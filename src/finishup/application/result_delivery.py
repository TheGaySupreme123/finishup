"""Lossless, cursor-bound presentation of already privacy-projected results (#1139).

No response cache or new durable state: cursors select a recorded operation, or a status
read pinned to its original frontier. Every continuation goes through disclosure again.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import zlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final, cast

from finishup.domain.result_delivery import HOST_RESULT_BUDGET_BYTES, mcp_delivery_bytes
from finishup.protocol.canonical import (
    JsonValue,
    canonical_digest,
    canonical_encode,
    strict_json_parse,
)
from finishup.protocol.errors import PublicErrorCode, PublicOperationError

_CURSOR_DOMAIN: Final = b"finishup.result-delivery/1\0"
_ATOM_BYTES: Final = 1_400
# Each page carries its read's whole privacy projection beside the items. Past this canonical
# size its omitted pointers coalesce to containing fields (ADR-009's rule past the 512-pointer
# bound), so a long omission list still leaves room for full-size atoms.
_PROJECTION_BYTES: Final = 1_024
# Live status fields a later page read would see change; the cursor freezes the first read's,
# presence included: a brief body omits each one at its default, and an append can reveal it.
_STATUS_LIVE_FIELDS: Final = (
    "head_frontier",
    "projection_lag",
    "projection_version",
    "rebuild_state",
    "import_status",
    "credential_heuristic",
    "review_mode",
)
_REQUIRED_NEXT_STEP: Final = (
    "Until actionable_complete=true, call status view=compact delivery_cursor=next_cursor with "
    "the same session_id/writer_id. Rebuild containers and fragments (path, offsets, digest) "
    "before acting; then follow agent_next and inventory_read. Later pages are optional "
    "provenance. AI-powered review is advisory, not proof."
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


@dataclass(frozen=True, slots=True, repr=False)
class DeliverySource:
    result: Any
    method: str
    selector: dict[str, JsonValue]
    position: int
    digest: str
    request_id: str
    writer_id: str
    sink: str


def invalid_cursor() -> PublicOperationError:
    return PublicOperationError(
        PublicErrorCode.INVALID_REQUEST,
        "Result continuation is invalid or its authorized content changed. Read current status; "
        "do not act on an incomplete finding or replay a completed check as a new review.",
        False,
    )


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _cursor_mac(key: bytes, data: bytes, position: bytes, session_id: str, writer_id: str) -> bytes:
    # The held session and writer are bound by the signature, not repeated in the cursor body.
    bound = b"\0".join((data, position, session_id.encode("ascii"), writer_id.encode("ascii")))
    return hmac.new(key, _CURSOR_DOMAIN + bound, hashlib.sha256).digest()


def encode_cursor(key: bytes, body: Mapping[str, JsonValue]) -> str:
    position = str(body["position"]).encode("ascii")
    data = zlib.compress(
        canonical_encode(
            {k: v for k, v in body.items() if k not in {"position", "session_id", "writer_id"}}
        )
    )
    signature = _cursor_mac(
        key, data, position, cast(str, body["session_id"]), cast(str, body["writer_id"])
    )
    result = _b64(data) + "." + position.decode() + "." + _b64(signature)
    if len(key) < 32 or len(result) > 4096:
        raise ValueError("result_delivery_cursor_capacity")
    return result


def decode_cursor(key: bytes, cursor: str, session_id: str, writer_id: str) -> dict[str, Any]:
    try:
        body, position, signature = cursor.split(".")
        if (
            len(position) > 20
            or not position.isascii()
            or not position.isdigit()
            or str(int(position)) != position
        ):
            raise ValueError("position")
        data = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
        signed = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
        if len(key) < 32 or not hmac.compare_digest(
            signed, _cursor_mac(key, data, position.encode(), session_id, writer_id)
        ):
            raise ValueError("signature")
        decoder = zlib.decompressobj()
        decoded = decoder.decompress(data, 16_384)
        if not decoder.eof or decoder.unconsumed_tail or decoder.unused_data:
            raise ValueError("cursor_capacity")
        value = strict_json_parse(decoded)
        if not isinstance(value, dict):
            raise ValueError("shape")
        value["position"] = int(position)
        if (
            value.get("v") != "1"
            or "session_id" in value
            or "writer_id" in value
            or value.get("method") not in {"check", "receipt", "status"}
            or type(value.get("position")) is not int
            or value["position"] < 1
            or not isinstance(value.get("selector"), dict)
        ):
            raise ValueError("binding")
        value["session_id"], value["writer_id"] = session_id, writer_id
        return value
    except (KeyError, TypeError, ValueError, zlib.error) as exc:
        raise invalid_cursor() from exc


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
        "overall_next",
        "review_summary",
        "missing_for_assessment",
        "human_text",
        "coverage",
        "gaps",
        "closure_readiness",
        "closure_state",
        "finding_checklist",
        "suppressed_count",
        "suppressed_finding_count",
        "semantic_withheld_items",
        "semantic_redacted_values",
    ):
        if key in source:
            primary.extend(atoms("/" + key, source[key]))
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
    key: bytes,
    method: str,
    selector: dict[str, JsonValue],
    writer_id: str,
    sink: str,
    position: int = 0,
    expected_digest: str | None = None,
    request_id: str | None = None,
) -> dict[str, JsonValue]:
    """Page a result after disclosure; the original operation remains complete and unchanged."""
    if method in {"status", "check"}:
        live_fields = _STATUS_LIVE_FIELDS if method == "status" else ("observations_awaited",)
        snapshot = selector.get("_delivery_snapshot")
        if snapshot is None:
            selector = {
                **selector,
                "_delivery_snapshot": {k: source[k] for k in live_fields if k in source},
            }
        elif isinstance(snapshot, Mapping):
            # Freeze call-local wait facts as well as status watermarks, including absence.
            # A continuation neither replaces the first call's values nor adds omitted ones.
            frozen = cast(Mapping[str, JsonValue], snapshot)
            source = {k: v for k, v in source.items() if k not in live_fields}
            source.update({k: frozen[k] for k in live_fields if k in frozen})
        else:
            raise invalid_cursor()
    # Each read attaches a fresh local disclosure receipt to its own page, outside the items and
    # the content identity.
    content = {
        k: v for k, v in source.items() if k not in {"privacy_projection", "review_delivery"}
    }
    digest = canonical_digest(content)
    if expected_digest is not None and expected_digest != digest:
        raise invalid_cursor()
    cursor_body: dict[str, JsonValue] = {
        "v": "1",
        "method": method,
        "selector": selector,
        "digest": digest,
        "session_id": source["session_id"],
        "writer_id": writer_id,
        "sink": sink,
    }
    page: dict[str, JsonValue] = {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "ok": True,
        "state": "delivery_page",
        "request_id": request_id or source["request_id"],
        "source_request_id": source["request_id"],
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
        "next_cursor": None,
        "privacy_projection": _page_projection(
            cast(Mapping[str, JsonValue], source["privacy_projection"])
        ),
    }
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
    # A position-independent compressed cursor body makes that envelope's bound exact.
    limit = _ATOM_BYTES
    empty_item_bytes = mcp_delivery_bytes({"items": []})
    while True:
        items, actionable_count = _delivery_groups(source, limit)
        last = len(items)
        longest_cursor = encode_cursor(key, {**cursor_body, "position": last})
        envelope_bytes = mcp_delivery_bytes(
            {
                **page,
                "items": [],
                "next_cursor": longest_cursor,
                "offset": last,
                "total_items": last,
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
        cursor = None if end == len(items) else encode_cursor(key, {**cursor_body, "position": end})
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
