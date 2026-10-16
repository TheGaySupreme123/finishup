"""Server-filled ``publish_work`` boilerplate (issue #1084).

An agent used to hand-write every envelope value the service could derive itself: a fresh
``request_id``, one ``event_id`` per draft, ``occurred_at`` from ``date -u``, empty
``causal_parents``/``artifact_refs`` lists, an exact copy of the payload's ``evidence_refs`` and an
ASCII-sorted, duplicate-free order for every reference set. Across the 62 N6 trials that clerical
load cost more output tokens than any other FinishUP activity.

This module owns the pure, deterministic half of that derivation, so the MCP bridge, the CLI and
the service compute the same values from the same body:

* ``request_id`` (when absent) is a digest of the caller's canonical request body. Resending the
  same body after a lost response is the idempotent retry; any corrected body gets a new identity.
* a draft's ``event_id`` (when absent) is minted from the request identity, the draft position and
  whether the call is a dry run, so a dry-run preview never mints the ids its commit records.
* envelope mirrors (``evidence_refs``, ``artifact_refs``) are copied from the payload, and
  ``causal_parents`` defaults to an empty set.
* reference sets are sorted and de-duplicated instead of refused.

The time-dependent half -- ``occurred_at`` from the service clock and the ``latest`` frontier mode --
belongs to the service at append time. Every filled value is named in the result's
``server_filled`` record, which is also stored with the operation, so a filled value is never
presented as a caller assertion.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Final, cast

from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.protocol.errors import ProtocolValueError

__all__ = [
    "FILLABLE_DRAFT_FIELDS",
    "FILLABLE_REQUEST_FIELDS",
    "ServerFilled",
    "ServerFilledDraft",
    "canonicalize_publish_sets",
    "complete_draft_envelope",
    "derive_publish_request_id",
    "derived_publish_request_id",
    "drop_ignored_decision_ids",
    "mint_draft_event_id",
    "normalize_publish_drafts",
    "server_filled_from_json",
]

# Request-level values the service may fill, in canonical (ASCII) order.
FILLABLE_REQUEST_FIELDS: Final[tuple[str, ...]] = ("expected_frontier", "request_id")
# Draft-envelope values the service may fill, in canonical (ASCII) order.
FILLABLE_DRAFT_FIELDS: Final[tuple[str, ...]] = (
    "artifact_refs",
    "causal_parents",
    "event_id",
    "evidence_refs",
    "occurred_at",
)

_REQUEST_ID_DOMAIN: Final = b"finishup/publish_work/request_id/v1\x00"
_EVENT_ID_DOMAIN: Final = b"finishup/publish_work/event_id/v1\x00"

# A reference set member: any typed ledger identifier a draft may name. Free text never matches,
# so a list of labels or prose (``attempted_items``, ``alternatives``) is never reordered.
_REFERENCE: Final[re.Pattern[str]] = re.compile(
    r"\A(?:act|clm|evd|evt|fnd|obj|obl|res)_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}"
    r"-[0-9a-f]{12}\Z",
    re.ASCII,
)
_ENVELOPE_SETS: Final[tuple[str, ...]] = ("artifact_refs", "causal_parents", "evidence_refs")
# Families an agent publishes whose top-level id arrays are all canonical sets (ASCII-sorted and
# unique, enforced by the domain decoders). Lineage, coordination and service-only families keep
# their exact refusal: their arrays are either not caller-authored or not plain sets.
_SET_CANONICAL_FAMILIES: Final[frozenset[str]] = frozenset(
    {
        "action_recorded",
        "assignment_recorded",
        "claim_recorded",
        "decision_recorded",
        "evidence_recorded",
        "obligation_published",
        "plan_published",
        "plan_revised",
        "result_recorded",
    }
)
# Payload field whose value the envelope ``evidence_refs`` must mirror, by family.
_EVIDENCE_MIRROR_FAMILIES: Final[frozenset[str]] = frozenset(
    {"coordination_disposition_recorded", "result_recorded", "response_recorded"}
)


def _uuid4_shaped(prefix: str, digest: bytes) -> str:
    material = bytearray(digest[:16])
    material[6] = (material[6] & 0x0F) | 0x40
    material[8] = (material[8] & 0x3F) | 0x80
    return prefix + str(uuid.UUID(bytes=bytes(material)))


def derive_publish_request_id(identity_body: JsonValue) -> str:
    """Return the ``req_`` id of one caller body that omitted ``request_id``.

    ``identity_body`` is the caller's canonical request body without ``request_id`` (after the
    model's meaning-preserving normalization: ignored ``decision_id`` keys dropped and reference
    sets canonicalized). Equal bodies always derive the same id, so a resend after a lost
    response replays the stored outcome instead of appending twice.
    """

    if isinstance(identity_body, Mapping) and "request_id" in identity_body:
        raise ProtocolValueError("invalid_event_value_type")
    digest = hashlib.sha256(_REQUEST_ID_DOMAIN + canonical_encode(identity_body)).digest()
    return _uuid4_shaped("req_", digest)


def mint_draft_event_id(request_id: str, index: int, *, dry_run: bool) -> str:
    """Mint the ``evt_`` id of draft ``index`` in one request.

    The dry-run flag is part of the seed: a preview's ids are never the ids its commit records,
    even when the caller reuses one explicit ``request_id`` for both.
    """

    if type(request_id) is not str or type(index) is not int or index < 0:
        raise ProtocolValueError("invalid_event_value_type")
    seed = b"%s\x00%d\x00%s" % (
        request_id.encode("ascii"),
        index,
        b"dry_run" if dry_run else b"commit",
    )
    return _uuid4_shaped("evt_", hashlib.sha256(_EVENT_ID_DOMAIN + seed).digest())


_IGNORED_DECISION_ID_KEY: Final = "decision_id"


def drop_ignored_decision_ids(drafts: object) -> object:
    """Drop ``decision_id`` from every ``decision_recorded`` draft payload (tb4n4, #1049).

    ``decision_recorded`` is the one ordinary family without an id of its own (a decision is
    addressed by its ``event_id``), and ten tb4n4 attempts sent a ``decision_id`` by analogy with
    ``action_id``, ``claim_id`` and the rest. The key has no meaning in any spelling, so it is
    accepted and ignored: dropped here, before the schema check and before anything prepares,
    commits or hashes the drafts. A retry with or without it is therefore the same request (one
    request digest), and the recorded event never holds it. Every other unknown key, in this and
    every other family, keeps its ``extra_forbidden`` refusal.
    """

    if not isinstance(drafts, list | tuple):
        return drafts
    sequence = cast(Sequence[object], drafts)
    adapted: list[object] = []
    changed = False
    for draft in sequence:
        replacement: object = draft
        if isinstance(draft, Mapping):
            source = cast(Mapping[object, object], draft)
            schema: object = source.get("schema")
            payload: object = source.get("payload")
            if (
                isinstance(schema, Mapping)
                and cast(Mapping[object, object], schema).get("name") == "decision_recorded"
                and isinstance(payload, Mapping)
                and _IGNORED_DECISION_ID_KEY in cast(Mapping[object, object], payload)
            ):
                kept: dict[object, object] = {
                    key: value
                    for key, value in cast(Mapping[object, object], payload).items()
                    if key != _IGNORED_DECISION_ID_KEY
                }
                rebuilt: dict[object, object] = dict(source)
                rebuilt["payload"] = kept
                replacement = rebuilt
                changed = True
        adapted.append(replacement)
    if not changed:
        return sequence
    return adapted if isinstance(sequence, list) else tuple(adapted)


def normalize_publish_drafts(drafts: object) -> object:
    """Apply every meaning-preserving draft normalization, in the order the request model does.

    ``decision_id`` keys are dropped (#1049) and reference sets canonicalized (#1084). The same
    object is returned when nothing changes.
    """

    return canonicalize_publish_sets(drop_ignored_decision_ids(drafts))


def derived_publish_request_id(arguments: object) -> str | None:
    """The ``request_id`` the service derives for a raw publish body, or ``None``.

    ``None`` when the body names its own ``request_id`` or is not a JSON object. For a body the
    request model accepts, this is exactly the id the model derives (strict wire values are
    never coerced, so the model's serialization equals the normalized body); a host hook can
    therefore track a sparse write's identity without importing the request model.
    """

    if not isinstance(arguments, Mapping):
        return None
    source = cast(Mapping[object, object], arguments)
    if "request_id" in source or any(type(key) is not str for key in source):
        return None
    body: dict[str, object] = {cast(str, key): value for key, value in source.items()}
    if "event_drafts" in body:
        body["event_drafts"] = normalize_publish_drafts(body["event_drafts"])
    try:
        return derive_publish_request_id(cast(JsonValue, body))
    except ProtocolValueError, TypeError, ValueError, RecursionError:
        return None


def _canonical_reference_set(value: object) -> object:
    """Sort and de-duplicate one array of typed references; anything else is returned as is."""

    if not isinstance(value, list | tuple):
        return value
    members = cast(Sequence[object], value)
    if not members or not all(
        type(member) is str and _REFERENCE.fullmatch(member) is not None for member in members
    ):
        return cast(object, value)
    canonical = sorted(set(cast(Sequence[str], members)), key=lambda member: member.encode("ascii"))
    if list(members) == canonical:
        return cast(object, value)
    return canonical


def _canonical_draft_sets(draft: Mapping[object, object]) -> Mapping[object, object]:
    replacement: dict[object, object] | None = None
    for key in _ENVELOPE_SETS:
        if key not in draft:
            continue
        canonical = _canonical_reference_set(draft[key])
        if canonical is not draft[key]:
            replacement = dict(draft) if replacement is None else replacement
            replacement[key] = canonical
    schema: object = draft.get("schema")
    payload: object = draft.get("payload")
    family = (
        cast(Mapping[object, object], schema).get("name") if isinstance(schema, Mapping) else None
    )
    if family in _SET_CANONICAL_FAMILIES and isinstance(payload, Mapping):
        source = cast(Mapping[object, object], payload)
        rebuilt: dict[object, object] | None = None
        for key, member in source.items():
            canonical = _canonical_reference_set(member)
            if canonical is not member:
                rebuilt = dict(source) if rebuilt is None else rebuilt
                rebuilt[key] = canonical
        if rebuilt is not None:
            replacement = dict(draft) if replacement is None else replacement
            replacement["payload"] = rebuilt
    return draft if replacement is None else replacement


def canonicalize_publish_sets(drafts: object) -> object:
    """Return ``drafts`` with every reference set in canonical order (issue #1084).

    A reference set has no order and no multiplicity, so sorting it and dropping repeats never
    changes what the caller asserted; it only removes the ``unsorted_set_field`` and
    ``duplicate_set_member`` rejections that used to cost a whole resend. Envelope sets and the
    top-level id arrays of ordinary agent families are canonicalized; free-text arrays never are.
    The same object is returned when nothing changes.
    """

    if not isinstance(drafts, list | tuple):
        return drafts
    sequence = cast(Sequence[object], drafts)
    adapted: list[object] = []
    changed = False
    for draft in sequence:
        replacement = draft
        if isinstance(draft, Mapping):
            replacement = _canonical_draft_sets(cast(Mapping[object, object], draft))
            changed = changed or replacement is not draft
        adapted.append(replacement)
    if not changed:
        return cast(object, drafts)
    return adapted if isinstance(drafts, list) else tuple(adapted)


def _payload_mirrors(
    family: object, payload: object
) -> tuple[tuple[JsonValue, ...], tuple[JsonValue, ...]]:
    """Return the ``(artifact_refs, evidence_refs)`` a draft envelope must mirror."""

    if not isinstance(payload, Mapping):
        return (), ()
    source = cast(Mapping[str, JsonValue], payload)
    evidence: tuple[JsonValue, ...] = ()
    artifacts: tuple[JsonValue, ...] = ()
    if family in _EVIDENCE_MIRROR_FAMILIES:
        refs = source.get("evidence_refs")
        if isinstance(refs, list | tuple):
            evidence = tuple(cast(Sequence[JsonValue], refs))
    elif family == "evidence_recorded":
        captured = source.get("captured_object_id")
        if captured is not None:
            artifacts = (captured,)
    elif family == "redaction_recorded":
        targets = source.get("target_object_ids")
        if isinstance(targets, list | tuple):
            artifacts = tuple(cast(Sequence[JsonValue], targets))
    elif family == "receipt_recorded":
        receipt = source.get("receipt_object_id")
        if receipt is not None:
            artifacts = (receipt,)
    return artifacts, evidence


def complete_draft_envelope(
    draft: Mapping[str, JsonValue],
    *,
    request_id: str,
    index: int,
    dry_run: bool,
    occurred_at: str,
) -> tuple[Mapping[str, JsonValue], tuple[str, ...]]:
    """Fill the envelope values one draft omitted and name each filled field.

    A present value is never replaced, so an old client's complete draft is returned unchanged
    (the same object) and a present-but-inconsistent mirror still fails its exact validation. The
    returned names are in canonical order.
    """

    missing = tuple(field for field in FILLABLE_DRAFT_FIELDS if field not in draft)
    if not missing:
        return draft, ()
    schema: object = draft.get("schema")
    family = (
        cast(Mapping[object, object], schema).get("name") if isinstance(schema, Mapping) else None
    )
    artifacts, evidence = _payload_mirrors(family, draft.get("payload"))
    completed: dict[str, JsonValue] = dict(draft)
    for field in missing:
        if field == "event_id":
            completed[field] = mint_draft_event_id(request_id, index, dry_run=dry_run)
        elif field == "occurred_at":
            completed[field] = occurred_at
        elif field == "causal_parents":
            completed[field] = ()
        elif field == "artifact_refs":
            completed[field] = artifacts
        else:
            completed[field] = evidence
    return completed, missing


@dataclass(frozen=True, slots=True)
class ServerFilledDraft:
    """The envelope fields the service filled for one draft, by its batch position."""

    index: int
    fields: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.index) is not int or not 0 <= self.index < 100:
            raise ProtocolValueError("invalid_event_value_type")
        _validate_names(self.fields, FILLABLE_DRAFT_FIELDS)


@dataclass(frozen=True, slots=True)
class ServerFilled:
    """Which request and draft values the service supplied for one publication.

    Field names only: no caller content ever enters this record, so it may be stored in the
    operation's structural result and returned verbatim on replay.
    """

    request: tuple[str, ...]
    drafts: tuple[ServerFilledDraft, ...]

    def __post_init__(self) -> None:
        _validate_names(self.request, FILLABLE_REQUEST_FIELDS)
        if type(self.drafts) is not tuple or any(
            type(item) is not ServerFilledDraft for item in self.drafts
        ):
            raise ProtocolValueError("invalid_event_value_type")
        indexes = [item.index for item in self.drafts]
        if indexes != sorted(set(indexes)) or any(not item.fields for item in self.drafts):
            raise ProtocolValueError("invalid_event_value_type")

    @property
    def empty(self) -> bool:
        return not self.request and not self.drafts

    def as_json(self) -> dict[str, JsonValue]:
        """Group drafts that share one filled-field set, so a uniform batch costs one row.

        ``drafts`` holds ``{"fields": [...], "indexes": [...]}`` groups ordered by their first
        batch index; every index appears in exactly one group. In the N6 trials a per-draft row
        would have added about 110 tokens to an ordinary four-draft publish result.
        """

        groups: dict[tuple[str, ...], list[str]] = {}
        for item in self.drafts:
            groups.setdefault(item.fields, []).append(str(item.index))
        return {
            "request": self.request,
            "drafts": tuple(
                {"fields": fields, "indexes": tuple(indexes)} for fields, indexes in groups.items()
            ),
        }


def _validate_names(names: object, admitted: tuple[str, ...]) -> None:
    if type(names) is not tuple:
        raise ProtocolValueError("invalid_event_value_type")
    members = cast(tuple[object, ...], names)
    if any(type(name) is not str or name not in admitted for name in members):
        raise ProtocolValueError("invalid_event_value_type")
    if list(members) != sorted(set(cast(tuple[str, ...], members)), key=str.encode):
        raise ProtocolValueError("invalid_event_value_type")


def server_filled_from_json(value: object) -> ServerFilled:
    """Decode one stored or wire ``server_filled`` record, refusing any other shape."""

    if not isinstance(value, Mapping):
        raise ProtocolValueError("invalid_event_value_type")
    source = cast(Mapping[object, object], value)
    if frozenset(source) != frozenset({"request", "drafts"}):
        raise ProtocolValueError("invalid_event_value_type")
    request = source["request"]
    drafts = source["drafts"]
    if not isinstance(request, list | tuple) or not isinstance(drafts, list | tuple):
        raise ProtocolValueError("invalid_event_value_type")
    decoded: list[ServerFilledDraft] = []
    seen_fields: set[tuple[str, ...]] = set()
    first_indexes: list[int] = []
    for item in cast(Sequence[object], drafts):
        if not isinstance(item, Mapping):
            raise ProtocolValueError("invalid_event_value_type")
        entry = cast(Mapping[object, object], item)
        if frozenset(entry) != frozenset({"fields", "indexes"}):
            raise ProtocolValueError("invalid_event_value_type")
        fields = entry["fields"]
        indexes = entry["indexes"]
        if (
            not isinstance(fields, list | tuple)
            or not isinstance(indexes, list | tuple)
            or not indexes
        ):
            raise ProtocolValueError("invalid_event_value_type")
        names = tuple(cast(Sequence[str], fields))
        if names in seen_fields:
            raise ProtocolValueError("invalid_event_value_type")
        seen_fields.add(names)
        positions: list[int] = []
        for index in cast(Sequence[object], indexes):
            if (
                type(index) is not str
                or not index.isdigit()
                or (len(index) > 1 and index.startswith("0"))
            ):
                raise ProtocolValueError("invalid_event_value_type")
            positions.append(int(index))
        if positions != sorted(set(positions)):
            raise ProtocolValueError("invalid_event_value_type")
        first_indexes.append(positions[0])
        decoded.extend(ServerFilledDraft(position, names) for position in positions)
    if first_indexes != sorted(first_indexes):
        raise ProtocolValueError("invalid_event_value_type")
    decoded.sort(key=lambda item: item.index)
    return ServerFilled(tuple(cast(Sequence[str], request)), tuple(decoded))
