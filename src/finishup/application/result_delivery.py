"""Lossless, handle-bound presentation of already privacy-projected results (#1139, #1244).

A continuation is a short handle (``delivery_handle``) naming the page set's source, frontier,
next offset and content digest prefix, sealed by a check segment over every other character so an
edited or mistyped handle is refused rather than served from another offset. The delivered page set is kept in service memory only
(``DeliveryPageStore``; never disk, never the ledger) so later pages come from the very copy the
first page was cut from. A miss, such as after a service restart, rebuilds the set from the
ledger at the handle's frontier. Every continuation goes through disclosure again; only a
recorded redaction or a changed disclosure policy refuses one, and the refusal names which.
"""

from __future__ import annotations

import base64
import hashlib
import re
import uuid
from collections import OrderedDict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final, Literal, cast

from finishup.domain.result_delivery import HOST_RESULT_BUDGET_BYTES, mcp_delivery_bytes
from finishup.protocol.canonical import (
    JsonValue,
    canonical_digest,
    canonical_encode,
)
from finishup.protocol.errors import PublicErrorCode, PublicOperationError

_ATOM_BYTES: Final = 1_400
# Each page carries its read's whole privacy projection beside the items. Past this canonical
# size its omitted pointers coalesce to containing fields (ADR-009's rule past the 512-pointer
# bound), so a long omission list still leaves room for full-size atoms.
_PROJECTION_BYTES: Final = 1_024
# The widest frontier a ``ledger_moved_since`` notice can name (a 20-digit sequence).
_WIDEST_FRONTIER: Final[Mapping[str, JsonValue]] = {
    "sequence": "9" * 20,
    "head_digest": "sha256:" + "f" * 64,
}
_REQUIRED_NEXT_STEP: Final = (
    "Until actionable_complete=true, call status view=compact delivery_cursor=next_cursor with "
    "the same session_id/writer_id. Rebuild containers and fragments (path, offsets, digest) "
    "before acting; then follow agent_next and inventory_read. Pages after actionable_complete "
    "hold provenance. AI-powered review is advisory, not proof."
)
_ACTION_KEYS: Final = (
    "finding_id",
    "kind",
    "origin",
    "priority",
    "summary",
    "detail",
    "subject_refs",
    "subject_frontier",
    "policy_id",
    "policy_version",
    "coverage",
    "challenge",
    "resolved",
    "disposition",
    "todo_state",
    "next_actions",
    "finding_frontier",
    "closure_class",
    "closure_basis",
    "reason",
    "review_rounds",
    "duplicate_of_finding_id",
    "response_event_id",
    "waiver_scope",
    "waiver_expiry",
)

# --- Short continuation handles (#1244, D12) -----------------------------------------------------
#
#   <kind><source request id, 22 base64url chars>.<frontier>.<offset>.<8 hex digest>[.<selector>]
#   .<6 base64url check>   (one line; wrapped here)
#
# ``kind`` is c (check), r (receipt) or s (status). The source id is the original request's UUID,
# so a recorded check or receipt is found again by its own operation. The selector segment lets a
# miss rebuild what the request named: a receipt's format, include and redaction profile; a status
# read's view, detail and limit, or ``x`` when the read named anything else (a filter, an
# inventory cursor or a selector id), which a miss cannot rebuild. A handle carries no secret and
# no signature: every read it names is one its own session and writer may already make, and the
# kept page set is bound to that session and writer.
#
# The check segment is the first 36 bits of a domain-separated SHA-256 over everything before it.
# It is an integrity check against an edited or mistyped handle, not authentication: an edited
# offset used to be served silently from another item, and an edited frontier or digest prefix
# silently restarted or rebuilt the set. It is unkeyed on purpose. A per-service key would expire
# every handle on restart, which D12 forbids (a restarted service rebuilds the set); a key that
# survives restarts would be a new persistent secret guarding nothing a caller could not already
# read. Anyone may recompute the check, and that only buys a read the caller may already make.
_KINDS: Final[Mapping[str, Literal["check", "receipt", "status"]]] = {
    "c": "check",
    "r": "receipt",
    "s": "status",
}
_KIND_OF: Final[Mapping[str, str]] = {value: key for key, value in _KINDS.items()}
_HANDLE: Final = re.compile(
    r"^(([crs])([A-Za-z0-9_-]{22})\.(0|[1-9][0-9]{0,19})\.(0|[1-9][0-9]{0,9})\.([0-9a-f]{8})"
    r"(?:\.([a-z0-9]{1,8}))?)\.([A-Za-z0-9_-]{6})$",
    re.ASCII,
)
_HANDLE_CHECK_DOMAIN: Final = b"finishup.delivery-handle.check.v1\x00"
_VIEW_CODES: Final[Mapping[str, str]] = {
    "advice": "a",
    "assignment": "g",
    "candidate_findings": "n",
    "coverage": "v",
    "compact": "c",
    "evidence": "e",
    "findings": "f",
    "history": "h",
    "obligations": "o",
    "operation": "p",
    "lineage": "l",
    "project": "j",
    "results": "r",
    "versions": "s",
}
_CODE_VIEWS: Final[Mapping[str, str]] = {value: key for key, value in _VIEW_CODES.items()}
_DETAIL_CODES: Final[Mapping[str | None, str]] = {"brief": "b", "full": "f", None: "n"}
_CODE_DETAILS: Final[Mapping[str, str | None]] = {v: k for k, v in _DETAIL_CODES.items()}
_FORMAT_CODES: Final[Mapping[str, str]] = {"json": "j", "markdown": "m", "text": "t"}
_INCLUDE_CODES: Final[Mapping[str, str]] = {"summary": "s", "standard": "d", "full": "f"}
_REDACTION_CODES: Final[Mapping[str, str]] = {
    "full_local": "l",
    "default_local_export": "e",
    "redacted_share": "r",
}
# Status selector keys a status handle can carry; any other key makes the set unrebuildable.
_STATUS_HANDLE_KEYS: Final = frozenset({"request_id", "view", "limit", "detail", "at_frontier"})
_STATUS_UNREBUILDABLE: Final = "x"

DeliveryRefusal = Literal[
    "delivery_cursor_invalid",
    "delivery_cursor_expired",
    "delivery_redaction_recorded",
    "delivery_disclosure_changed",
]
_REFUSAL_MESSAGES: Final[Mapping[str, str]] = {
    "delivery_cursor_invalid": (
        "Result continuation is invalid or was edited: copy next_cursor exactly, every "
        "character, from the last page and pass it unchanged as delivery_cursor; a handle "
        "cannot be edited to skip or repeat a page. If that page is gone, read current status; "
        "do not act on an incomplete finding or replay a completed check as a new review."
    ),
    "delivery_cursor_expired": (
        "Result continuation expired: the service restarted and this status read named a filter, "
        "cursor or selector its handle cannot carry. Repeat the original status read; do not act "
        "on an incomplete finding."
    ),
    "delivery_redaction_recorded": (
        "Result continuation refused: a redaction was recorded after this page set's frontier, "
        "so its earlier copy may hold redacted content. Read current status instead."
    ),
    "delivery_disclosure_changed": (
        "Result continuation refused: the disclosure policy or sink changed since the first "
        "page. Read current status instead; its pages follow the current policy."
    ),
}


@dataclass(frozen=True, slots=True)
class DeliveryHandle:
    """One parsed continuation handle; ``set_key`` names its page set in service memory."""

    method: Literal["check", "receipt", "status"]
    source_request_id: str
    frontier: int
    position: int
    digest_prefix: str
    selector_code: str | None

    @property
    def set_key(self) -> str:
        return f"{_KIND_OF[self.method]}{_compact_id(self.source_request_id)}.{self.frontier}"


@dataclass(frozen=True, slots=True, repr=False)
class DeliverySource:
    """A continuation's fresh source read plus what the projection step needs to page it."""

    result: Any
    method: str
    selector: dict[str, JsonValue]
    handle: DeliveryHandle
    request_id: str
    session_id: str
    writer_id: str
    # The ledger head when this continuation was read, and whether a redaction was recorded
    # after the page set's frontier (that alone refuses the continuation).
    head_frontier: dict[str, JsonValue]
    redacted_since: bool


def invalid_cursor(reason: DeliveryRefusal = "delivery_cursor_invalid") -> PublicOperationError:
    return PublicOperationError(
        PublicErrorCode.INVALID_REQUEST,
        _REFUSAL_MESSAGES[reason],
        False,
        safe_details={"reason_code": reason},
    )


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _compact_id(request_id: str) -> str:
    return _b64(uuid.UUID(request_id[4:]).bytes)


def _expand_id(compact: str) -> str:
    return "req_" + str(uuid.UUID(bytes=base64.urlsafe_b64decode(compact + "==")))


def _digest_prefix(digest: str) -> str:
    return digest.removeprefix("sha256:")[:8]


def handle_check(body: str) -> str:
    """The check segment sealing a handle body: typo and edit detection, not authentication."""

    return _b64(hashlib.sha256(_HANDLE_CHECK_DOMAIN + body.encode("ascii")).digest()[:6])[:6]


def status_selector_code(selector: Mapping[str, JsonValue]) -> str:
    """The status segment of a handle: view, detail and limit, or ``x`` when it names more."""

    view = selector.get("view")
    limit = selector.get("limit", "20")
    detail = selector.get("detail")
    if (
        set(selector) - _STATUS_HANDLE_KEYS - {"delivery"}
        or type(view) is not str
        or view not in _VIEW_CODES
        or type(limit) is not str
        or not limit.isdigit()
        or len(limit) > 3
        or detail not in _DETAIL_CODES
    ):
        return _STATUS_UNREBUILDABLE
    return _VIEW_CODES[view] + _DETAIL_CODES[detail] + limit


def check_selector_code(selector: Mapping[str, JsonValue]) -> str | None:
    """A check handle's segment: ``b`` for a brief reply, none for a full one."""

    return "b" if selector.get("detail") == "brief" else None


def receipt_selector_code(selector: Mapping[str, JsonValue]) -> str:
    try:
        return (
            _FORMAT_CODES[cast(str, selector["format"])]
            + _INCLUDE_CODES[cast(str, selector["include"])]
            + _REDACTION_CODES[cast(str, selector["redaction_profile"])]
        )
    except (KeyError, TypeError):
        return _STATUS_UNREBUILDABLE


def status_selector_from_code(code: str | None, handle: DeliveryHandle) -> dict[str, JsonValue]:
    """Rebuild a status selector from a handle after a miss, or refuse it as expired."""

    if (
        code is None
        or len(code) < 3
        or code[0] not in _CODE_VIEWS
        or code[1] not in _CODE_DETAILS
        or not code[2:].isdigit()
    ):
        raise invalid_cursor("delivery_cursor_expired")
    selector: dict[str, JsonValue] = {
        "request_id": handle.source_request_id,
        "view": _CODE_VIEWS[code[0]],
        "limit": code[2:],
        "at_frontier": str(handle.frontier),
        "delivery": "paged",
    }
    detail = _CODE_DETAILS[code[1]]
    if detail is not None:
        selector["detail"] = detail
    return selector


def receipt_selector_from_code(code: str | None) -> dict[str, JsonValue]:
    reverse = (
        {v: k for k, v in _FORMAT_CODES.items()},
        {v: k for k, v in _INCLUDE_CODES.items()},
        {v: k for k, v in _REDACTION_CODES.items()},
    )
    if (
        code is None
        or len(code) != 3
        or any(c not in m for c, m in zip(code, reverse, strict=True))
    ):
        raise invalid_cursor("delivery_cursor_expired")
    return {
        "format": reverse[0][code[0]],
        "include": reverse[1][code[1]],
        "redaction_profile": reverse[2][code[2]],
    }


def encode_handle(
    method: str,
    source_request_id: str,
    frontier: int,
    position: int,
    digest: str,
    selector_code: str | None = None,
) -> str:
    handle = (
        f"{_KIND_OF[method]}{_compact_id(source_request_id)}.{frontier}.{position}."
        f"{_digest_prefix(digest)}"
    )
    if selector_code is not None:
        handle += "." + selector_code
    handle += "." + handle_check(handle)
    if _HANDLE.fullmatch(handle) is None:
        raise ValueError("result_delivery_handle_invalid")
    return handle


def decode_handle(cursor: str) -> DeliveryHandle:
    match = _HANDLE.fullmatch(cursor)
    if match is None:
        raise invalid_cursor()
    body, kind, compact, frontier, position, digest, code, check = match.groups()
    # Every other field is covered: an edited offset, frontier, digest prefix, id or selector
    # is refused here instead of being served from another item or rebuilt as another set.
    if check != handle_check(body):
        raise invalid_cursor()
    try:
        source_request_id = _expand_id(compact)
    except ValueError as exc:
        raise invalid_cursor() from exc
    if _compact_id(source_request_id) != compact or int(position) < 1:
        raise invalid_cursor()
    return DeliveryHandle(
        _KINDS[kind], source_request_id, int(frontier), int(position), digest, code
    )


def content_digest(source: Mapping[str, JsonValue]) -> str:
    """The page set's content identity: everything but this read's own disclosure fields."""

    return canonical_digest(
        {k: v for k, v in source.items() if k not in {"privacy_projection", "review_delivery"}}
    )


def disclosure_identity(source: Mapping[str, JsonValue]) -> tuple[JsonValue, ...]:
    """What a changed disclosure decision would change: the sink and the policy it applied."""

    projection = cast(Mapping[str, JsonValue], source["privacy_projection"])
    return tuple(
        projection.get(key) for key in ("sink", "policy_id", "policy_version", "policy_digest")
    )


def brief_check_body(source: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
    """A complete check reply with each finding reduced to who and what to answer (#1244, D13).

    Only omission: ``CHECK_BRIEF_FINDING_KEYS`` stay, so every finding can still be named,
    answered or questioned; ``status view=findings`` carries its detail, coverage and provenance.
    ``closure_readiness`` gives way to the ``closure_state`` subset a brief status carries.
    """
    from finishup.protocol.models import CHECK_BRIEF_FINDING_KEYS

    body = {k: v for k, v in source.items() if k != "closure_readiness"}
    body["detail"] = "brief"
    readiness = source.get("closure_readiness")
    if isinstance(readiness, Mapping):
        # The subset a brief status carries (#1084, #1209); status view=compact has the rest.
        body["closure_state"] = {
            key: cast(Mapping[str, JsonValue], readiness)[key]
            for key in ("blocking_conditions", "state", "agent_actionable", "fix_or_decline")
            if key in readiness
        }
    rows = source.get("findings")
    if not isinstance(rows, (list, tuple)):
        return body
    return {
        **body,
        "findings": [
            {k: row[k] for k in CHECK_BRIEF_FINDING_KEYS if k in row}
            if isinstance(row, Mapping)
            else row
            for row in cast(Sequence[JsonValue], rows)
        ],
    }


@dataclass(frozen=True, slots=True, repr=False)
class DeliveryPageSet:
    """One delivered page set kept in service memory: the projected source pages are cut from."""

    session_id: str
    writer_id: str
    sink: str
    method: str
    selector: dict[str, JsonValue]
    source: dict[str, JsonValue]
    digest: str
    selector_code: str | None
    size: int


class DeliveryPageStore:
    """Process-memory copies of delivered page sets (#1244, D12), least recently used first out.

    Never written to disk or the ledger, so a restart drops every set and a continuation then
    rebuilds from the ledger. Bounded by count and by canonical size.
    """

    __slots__ = ("_bytes", "_max_bytes", "_max_sets", "_sets")

    def __init__(self, *, max_sets: int = 256, max_bytes: int = 64 * 1_048_576) -> None:
        self._sets: OrderedDict[str, DeliveryPageSet] = OrderedDict()
        self._max_sets = max_sets
        self._max_bytes = max_bytes
        self._bytes = 0

    def get(self, key: str, session_id: str, writer_id: str) -> DeliveryPageSet | None:
        entry = self._sets.get(key)
        if entry is None or entry.session_id != session_id or entry.writer_id != writer_id:
            return None
        self._sets.move_to_end(key)
        return entry

    def put(self, key: str, entry: DeliveryPageSet) -> None:
        previous = self._sets.pop(key, None)
        if previous is not None:
            self._bytes -= previous.size
        if entry.size > self._max_bytes:
            return
        self._sets[key] = entry
        self._bytes += entry.size
        while len(self._sets) > self._max_sets or self._bytes > self._max_bytes:
            _, evicted = self._sets.popitem(last=False)
            self._bytes -= evicted.size

    def clear(self) -> None:
        self._sets.clear()
        self._bytes = 0

    def __len__(self) -> int:
        return len(self._sets)


def _pointer(key: str) -> str:
    return key.replace("~", "~0").replace("/", "~1")


def _atoms(path: str, value: JsonValue, limit: int = _ATOM_BYTES) -> list[dict[str, JsonValue]]:
    """Prefer whole values. Oversized containers split only at explicit field boundaries.

    An individually oversized scalar is a *labelled fragment*, never a preview: offsets,
    length and digest make reconstruction mandatory and verifiable before use.
    """
    if (
        len(canonical_encode(value)) <= limit
        or value is None
        or value == ""
        or type(value) in {bool, int}
    ):
        return [{"path": path, "value": value}]
    if isinstance(value, Mapping):
        marker: dict[str, JsonValue] = {"path": path, "value": None, "container": "object"}
        return [marker] + [
            atom
            for k in sorted(value, key=str.encode)
            for atom in _atoms(path + "/" + _pointer(k), value[k], limit)
        ]
    if isinstance(value, (list, tuple)):
        marker = {"path": path, "value": None, "container": "array"}
        return [marker] + [
            atom for i, v in enumerate(value) for atom in _atoms(f"{path}/{i}", v, limit)
        ]
    if isinstance(value, str):
        atoms: list[dict[str, JsonValue]] = []
        start = 0
        digest = canonical_digest(value)
        while start < len(value):
            low, high = start + 1, min(len(value), start + limit)
            while low < high:
                mid = (low + high + 1) // 2
                if len(canonical_encode(value[start:mid])) <= limit:
                    low = mid
                else:
                    high = mid - 1
            atoms.append(
                {
                    "path": path,
                    "value": value[start:low],
                    "fragment": {
                        "unit": "unicode_scalar",
                        "offset": start,
                        "end": low,
                        "length": len(value),
                        "digest": digest,
                        "complete": low == len(value),
                    },
                }
            )
            start = low
        return atoms
    raise ValueError("result_delivery_atom_invalid")


def _page_projection(projection: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
    """This read's disclosure receipt, whole; only an over-long pointer list coalesces."""
    from finishup.application.receipt_projection import bounded_omitted_pointers

    pointers = tuple(cast(Sequence[str], projection["omitted_pointers"]))
    carried = dict(projection)
    count = len(pointers)
    while len(canonical_encode(carried)) > _PROJECTION_BYTES and count > 1:
        count //= 2
        carried["omitted_pointers"] = list(bounded_omitted_pointers(pointers, limit=count))
    return carried


# A readiness field at most this size is a decision field (state, counts, the ledger line).
_DECISION_FIELD_BYTES: Final = 512


def _small_fields_first(
    path: str, value: Mapping[str, JsonValue], limit: int
) -> list[dict[str, JsonValue]]:
    """An oversized object's small fields before its large ones (#1139), each group in key order.

    Object members reassemble in any order after the container marker; the order depends only on
    content, so the page partition stays independent of mapping insertion order.
    """

    atoms = _atoms(path, value, limit)
    if len(atoms) == 1:
        return atoms
    keys = sorted(value, key=str.encode)
    ordered = sorted(
        keys, key=lambda k: len(canonical_encode(value[k])) > _DECISION_FIELD_BYTES
    )  # stable: key order within each group
    return [atoms[0]] + [
        atom for k in ordered for atom in _atoms(path + "/" + _pointer(k), value[k], limit)
    ]


def _delivery_groups(
    source: Mapping[str, JsonValue], limit: int = _ATOM_BYTES, *, top: bool = True
) -> tuple[list[dict[str, JsonValue]], int]:
    """Action and counterinterpretation precede every excerpt and provenance inventory.

    The top-level privacy projection is never an item: each page carries its own read's copy.
    """
    primary: list[dict[str, JsonValue]] = []
    bulk: list[dict[str, JsonValue]] = []

    def atoms(path: str, value: JsonValue) -> list[dict[str, JsonValue]]:
        return _atoms(path, value, limit)

    for key in (
        "verdict",
        "conclusion",
        "semantic_status",
        "semantic_reason",
        "agent_next",
        # #1139: the counted ledger line, readiness and totals are what the agent decides on, so
        # they precede reviewer prose. The small ones lead; readiness's large lists (64 obligations
        # with every acceptance-risk reason can pass a page) follow, still actionable.
        "agent_status_line",
        "overall_next",
        "review_guidance",
        "closure_state",
        "totals",
        "closure_readiness",
        # #1162 tracked advice: the advisory identities respond answers are actionable.
        "correctness_advisories",
        "review_summary",
        "missing_for_assessment",
        "human_text",
        "coverage",
        "gaps",
        "finding_checklist",
        "suppressed_count",
        "suppressed_finding_count",
        "semantic_withheld_items",
        "semantic_redacted_values",
    ):
        if key not in source:
            continue
        value = source[key]
        if key == "closure_readiness" and isinstance(value, Mapping):
            primary.extend(_small_fields_first("/" + key, value, limit))
        else:
            primary.extend(atoms("/" + key, value))
    handled = {atom["path"].split("/")[1] for atom in primary if isinstance(atom["path"], str)}
    for key in sorted(source, key=str.encode):
        value = source[key]
        if key in handled or key == "review_delivery" or (top and key == "privacy_projection"):
            continue
        path = "/" + _pointer(key)
        if key == "document" and isinstance(value, Mapping):
            primary.append({"path": path, "value": None, "container": "object"})
            nested, count = _delivery_groups(value, limit, top=False)
            for atom in nested:
                atom["path"] = path + cast(str, atom["path"])
            primary.extend(nested[:count])
            bulk.extend(nested[count:])
            continue
        rows: object = value
        rows_path = path
        if key == "page" and isinstance(value, Mapping):
            rows = value.get("items")
            rows_path += "/items"
        if key in {"findings", "page"} and isinstance(rows, (list, tuple)):
            if key == "page":
                primary.append({"path": path, "value": None, "container": "object"})
            primary.append({"path": rows_path, "value": None, "container": "array"})
            for i, row in enumerate(cast(Sequence[JsonValue], rows)):
                if not isinstance(row, Mapping) or "finding_id" not in row:
                    primary.extend(atoms(f"{rows_path}/{i}", row))
                    continue
                action = {k: row[k] for k in _ACTION_KEYS if k in row}
                primary.append({"path": f"{rows_path}/{i}", "value": None, "container": "object"})
                challenge = action.get("challenge")
                if isinstance(challenge, Mapping):
                    action["challenge"] = {k: v for k, v in challenge.items() if k != "snippet"}
                for field, field_value in action.items():
                    if field == "challenge" and isinstance(field_value, Mapping):
                        primary.append(
                            {
                                "path": f"{rows_path}/{i}/challenge",
                                "value": None,
                                "container": "object",
                            }
                        )
                        for name in sorted(field_value, key=str.encode):
                            text = field_value[name]
                            primary.extend(
                                atoms(f"{rows_path}/{i}/challenge/{_pointer(name)}", text)
                            )
                    else:
                        primary.extend(atoms(f"{rows_path}/{i}/{_pointer(field)}", field_value))
                for k in sorted(row, key=str.encode):
                    v = row[k]
                    if k not in action:
                        bulk.extend(atoms(f"{rows_path}/{i}/{_pointer(k)}", v))
                if isinstance(challenge, Mapping) and "snippet" in challenge:
                    bulk.extend(atoms(f"{rows_path}/{i}/challenge/snippet", challenge["snippet"]))
            if key == "page" and isinstance(value, Mapping):
                for k in sorted(value, key=str.encode):
                    v = value[k]
                    if k != "items":
                        bulk.extend(atoms(f"/page/{_pointer(k)}", v))
        else:
            bulk.extend(atoms(path, value))
    return primary + bulk, len(primary)


def delivery_items(source: Mapping[str, JsonValue]) -> list[dict[str, JsonValue]]:
    return _delivery_groups(source)[0]


def page_result(
    source: Mapping[str, JsonValue],
    *,
    method: str,
    selector: Mapping[str, JsonValue],
    writer_id: str,
    sink: str,
    position: int = 0,
    request_id: str | None = None,
    selector_code: str | None = None,
    ledger_moved_since: Mapping[str, JsonValue] | None = None,
    page_set_restarted: bool = False,
) -> dict[str, JsonValue]:
    """Page a result after disclosure; the original operation remains complete and unchanged.

    ``ledger_moved_since`` names the ledger head when this page comes from the kept copy of a
    page set whose source has since changed; ``page_set_restarted`` marks the first page of a set
    rebuilt after a miss whose content differs from the one the handle named (#1244, D12).
    """
    del sink  # the projection step checks the sink; a page carries its read's own projection
    digest = content_digest(source)
    frontier = int(cast(str, cast(Mapping[str, JsonValue], source["result_frontier"])["sequence"]))
    source_request_id = cast(str, source["request_id"])

    def handle_at(next_position: int) -> str:
        return encode_handle(
            method, source_request_id, frontier, next_position, digest, selector_code
        )

    # Field order is the order Codex shows a model (ADR-043): the handle leads the page.
    page: dict[str, JsonValue] = {
        "next_cursor": None,
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "ok": True,
        "state": "delivery_page",
        "request_id": request_id or source_request_id,
        "source_request_id": source_request_id,
        "source_operation": method,
        "task_id": source["task_id"],
        "session_id": source["session_id"],
        "writer_id": writer_id,
        "result_frontier": source["result_frontier"],
        "source_digest": digest,
        "offset": position,
        "total_items": 1,
        "truncated": True,
        "complete": False,
        "actionable_complete": False,
        "budget_bytes": HOST_RESULT_BUDGET_BYTES,
        "required_next_step": _REQUIRED_NEXT_STEP,
        "inventory_read": (
            {
                "view": "findings",
                "limit": "20",
                "detail": "full",
                "filter": {"include_resolved": False},
                "at_frontier": cast(Mapping[str, JsonValue], source["result_frontier"])["sequence"],
            }
            if method in {"check", "receipt"}
            else None
        ),
        "items": [],
        "privacy_projection": _page_projection(
            cast(Mapping[str, JsonValue], source["privacy_projection"])
        ),
    }
    if ledger_moved_since is not None:
        page["ledger_moved_since"] = dict(ledger_moved_since)
    if page_set_restarted:
        page["page_set_restarted"] = True
    source_page = source.get("page")
    if method == "status" and isinstance(source_page, Mapping) and source_page.get("next_cursor"):
        page["inventory_read"] = {
            **{
                k: v
                for k, v in selector.items()
                if k
                in {
                    "view",
                    "limit",
                    "detail",
                    "filter",
                    "at_frontier",
                    "project_id",
                    "task_id",
                    "correlation_id",
                }
            },
            "cursor": source_page["next_cursor"],
        }
    # Admit individual atoms against the worst envelope, including both inventory cursors.
    # The handle's length depends only on the offset's digits, so the last offset bounds it.
    limit = _ATOM_BYTES
    empty_item_bytes = mcp_delivery_bytes({"items": []})
    while True:
        items, actionable_count = _delivery_groups(source, limit)
        last = len(items)
        longest_cursor = handle_at(last)
        # The notices a later page of this set may carry are measured on every page, so a
        # notice never changes the partition and offsets stay valid across the set.
        envelope_bytes = mcp_delivery_bytes(
            {
                **page,
                "items": [],
                "next_cursor": longest_cursor,
                "offset": last,
                "total_items": last,
                "ledger_moved_since": _WIDEST_FRONTIER,
                "page_set_restarted": True,
            }
        )
        largest_item_bytes = max(
            mcp_delivery_bytes({"items": [item]}) - empty_item_bytes for item in items
        )
        if envelope_bytes + largest_item_bytes <= HOST_RESULT_BUDGET_BYTES:
            break
        if limit == 1:
            raise ValueError("result_delivery_page_capacity")
        limit = max(1, limit // 2)
    if not 0 <= position < len(items):
        raise invalid_cursor()
    page["total_items"] = len(items)
    selected: list[JsonValue] = []
    stop = actionable_count if position < actionable_count else len(items)
    for end in range(position + 1, stop + 1):
        cursor = None if end == len(items) else handle_at(end)
        candidate: dict[str, JsonValue] = {
            **page,
            "items": [*selected, cast(JsonValue, items[end - 1])],
            "next_cursor": cursor,
            "complete": cursor is None,
            "actionable_complete": end >= actionable_count,
        }
        if mcp_delivery_bytes(candidate) > HOST_RESULT_BUDGET_BYTES:
            break
        selected.append(items[end - 1])
        page = candidate
    if not selected:
        raise ValueError("result_delivery_page_capacity")
    return page
