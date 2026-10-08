"""Prepare and atomically publish one strict batch of work events."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Final, Literal, Protocol, cast

from yoetz.application.ledger_snapshot import replay_off_loop, trusted_projection_at
from yoetz.application.unit_of_work import (
    PreparedMutation,
    PreSubmissionCancelled,
    abandon_preappend_objects,
    run_prepared_append,
)
from yoetz.domain.events import (
    LINEAGE_SERVICE_STAMPED_FAMILIES,
    PAYLOAD_TYPES,
    AcceptedEvent,
    ActionRecordedPayload,
    AssignmentRecordedPayload,
    CheckRecordedPayload,
    ClaimKind,
    ClaimRecordedPayload,
    ClaimRecordedPayloadV1_1,
    ClaimRevisionMismatch,
    DecisionRecordedPayload,
    EventDraft,
    EventPayload,
    EventSchema,
    EvidenceDigestProvenance,
    EvidenceRecordedPayload,
    FindingRecordedPayload,
    LedgerChain,
    LedgerRecord,
    NoObligationsReasonMismatch,
    ObligationPublishedPayload,
    ObligationResolutionMismatch,
    PayloadRef,
    PlanPublishedPayload,
    PlanRevisedPayload,
    ProjectionLocator,
    RedactionRecordedPayload,
    RedactionState,
    ResponseRecordedPayload,
    ResultRecordedPayload,
    UnknownEvent,
    WriterChain,
    decode_payload,
    encode_payload,
    is_observation_authored,
    is_observation_authorship,
    media_type_for,
    public_error_for_claim_revision_mismatch,
    public_error_for_no_obligations_reason_mismatch,
    public_error_for_obligation_resolution_mismatch,
)
from yoetz.domain.values import (
    Actor,
    ActorType,
    EventId,
    Frontier,
    ObjectId,
    actor_id,
    event_id,
    evidence_id,
    freeze_json,
    frontier_from_json,
    object_id,
    request_id,
    result_id,
    session_id,
    task_id,
    timestamp_from_datetime,
    timestamp_from_string,
    writer_id,
)
from yoetz.domain.values import (
    JsonValue as DomainJsonValue,
)
from yoetz.kernel.completion_scope import with_completion_scope_coverage
from yoetz.kernel.projections import PROJECTION_VERSION, ProjectionState
from yoetz.kernel.reducers import replay_extension
from yoetz.kernel.task_facts import blocker_publication_notices
from yoetz.ports.clock import ClockPort
from yoetz.ports.diagnostics import RuntimeCapability
from yoetz.ports.ledger import (
    AcceptedEventSummary,
    AppendCommand,
    AppendEntry,
    AppendResult,
    AppendWarning,
    OperationKind,
    OperationRecord,
    OperationState,
    ProjectionView,
)
from yoetz.ports.objects import ObjectKind, ObjectMetadata, ObjectRef, ObjectSource, StagedObject
from yoetz.ports.runtime import (
    BundleRuntimePort,
    RouteAccess,
    RouteCommand,
    TaskRuntime,
)
from yoetz.protocol.canonical import (
    JsonValue,
    canonical_digest,
    canonical_encode,
    entry_digest,
    request_digest,
    strict_json_parse,
)
from yoetz.protocol.coverage import (
    AuthorshipAssurance,
    Coverage,
    LedgerFreshness,
    PublicationChannel,
    coverage_for_channel,
    coverage_to_json,
)
from yoetz.protocol.errors import (
    PROTOCOL_REASON_CODES,
    REASON_CODE_CONTINUATIONS,
    ProtocolValueError,
    PublicErrorCode,
    PublicOperationError,
)
from yoetz.protocol.models import (
    MAX_CANONICAL_REQUEST_BYTES,
    MAX_EVENTS_PER_BATCH,
    PUBLISH_BLOCKER_NOTICE_TEXTS,
    CoverageModel,
    FrontierModel,
    PublishWorkAcceptedEventModel,
    PublishWorkBlockerNoticeModel,
    PublishWorkDryRunModel,
    PublishWorkDryRunPreviewEventModel,
    PublishWorkRequestModel,
    PublishWorkResult,
    PublishWorkResultModel,
    PublishWorkVersionSliceModel,
    RecordedVersionSlicePackWire,
)
from yoetz.protocol.policy_packs import (
    RESEARCH_EVIDENCE_POLICY_ID,
    WORK_INTEGRITY_POLICY_ID,
    current_policy_pack,
)

__all__ = [
    "Application",
    "PreparedPublication",
    "PublishWorkInternalResult",
    "build_accepted_projection_unavailable_result",
    "execute_publish_work",
    "prepare_publication",
]

_ORDINARY_FAMILIES = frozenset(
    {
        "plan_published",
        "obligation_published",
        "assignment_recorded",
        "decision_recorded",
        "action_recorded",
        "result_recorded",
        "evidence_recorded",
        "claim_recorded",
        "plan_revised",
        "coordination_obligation_declared",
        "coordination_disposition_recorded",
        # Lineage lifecycle actions are ordinary parent/child publications.  The remaining
        # service-only families stay outside this set and are admitted exclusively by their
        # coordinator writer path below.
        "delegation_cancelled",
        "child_accepted",
        "child_rejected",
        "child_written_off",
        "work_closed",
        "work_cancelled",
        "work_written_off",
    }
)
_IMPORT_FAMILIES = frozenset(
    {
        "action_recorded",
        "result_recorded",
        "evidence_recorded",
    }
)
_STATE_SENSITIVE_FAMILIES = frozenset(
    {
        "plan_published",
        "obligation_published",
        "assignment_recorded",
        "decision_recorded",
        "result_recorded",
        "claim_recorded",
        "plan_revised",
        "coordination_obligation_declared",
        "delegation_cancelled",
        "child_accepted",
        "child_rejected",
        "child_written_off",
        "work_closed",
        "work_cancelled",
        "work_written_off",
        "coordination_disposition_recorded",
    }
)
_UNKNOWN_GAP = "unknown_event_schema_preserved"
_POLICY_PACKS = cast(
    tuple[RecordedVersionSlicePackWire, ...],
    (
        current_policy_pack(RESEARCH_EVIDENCE_POLICY_ID),
        current_policy_pack(WORK_INTEGRITY_POLICY_ID),
    ),
)


class Application(Protocol):
    """Least surface required from the ready application composition."""

    runtime: BundleRuntimePort
    clock: ClockPort

    def authorizes_import_publication(self, request: PublishWorkRequestModel) -> bool:
        """Return a trusted service fact, never a caller assertion."""
        ...


@dataclass(frozen=True, slots=True)
class _PreparedDraft:
    draft: EventDraft
    payload_bytes: bytes
    projection_status: Literal["projected", "unknown_unprojected"]


@dataclass(frozen=True, slots=True)
class PreparedPublication:
    """Validated batch precursor; it owns no random or durable object identity."""

    channel: PublicationChannel
    author: Actor
    coverage: Coverage
    drafts: tuple[_PreparedDraft, ...]


@dataclass(frozen=True, slots=True)
class PublishWorkInternalResult:
    """Closed structural publication success before client-specific projection."""

    protocol_version: Literal["0.1"]
    schema_version: Literal["1.0.0"]
    request_id: str
    request_digest: str
    ok: Literal[True]
    outcome: Literal["accepted", "replayed"]
    task_id: str
    session_id: str
    writer_id: str
    subject_frontier: Frontier
    result_frontier: Frontier
    accepted_events: tuple[PublishWorkAcceptedEventModel, ...]
    warning_codes: tuple[str, ...]
    coverage: Coverage
    gaps: tuple[str, ...]
    versions: PublishWorkVersionSliceModel
    # Issue #985: fixed publish-time notices for yoetz-blocker lines; empty means absent.
    blocker_notices: tuple[PublishWorkBlockerNoticeModel, ...] = ()

    def as_json(self) -> dict[str, JsonValue]:
        """Serialize the closed internal result without materializing absent optional leaves."""

        body: dict[str, JsonValue] = {
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "request_id": self.request_id,
            "ok": self.ok,
            "outcome": self.outcome,
            "task_id": self.task_id,
            "session_id": self.session_id,
            "writer_id": self.writer_id,
            "subject_frontier": dict(self.subject_frontier.as_wire().items()),
            "result_frontier": dict(self.result_frontier.as_wire().items()),
            # An unpopulated optional field (today: every accepted event's ``summary``) must be
            # absent from the internal body, never an explicit null. The wire contract requires
            # total omission when unset (``optional_non_null_fields``); a materialized null leaf
            # is classified as content, survives disclosure whenever the policy includes its
            # category, and is then rejected by the closed success model — turning a durable
            # publish into ``response_projection_failed``. Same precedent as respond's internal
            # body, which already excludes nulls at this exact boundary.
            "accepted_events": tuple(
                cast(JsonValue, event.model_dump(mode="json", exclude_none=True))
                for event in self.accepted_events
            ),
            "warning_codes": self.warning_codes,
            "coverage": coverage_to_json(self.coverage),
            "gaps": self.gaps,
            "versions": cast(JsonValue, self.versions.model_dump(mode="json")),
        }
        if self.blocker_notices:
            # Absent when the batch carried no yoetz-blocker line (never an empty list, #985).
            body["blocker_notices"] = tuple(
                cast(JsonValue, item.model_dump(mode="json")) for item in self.blocker_notices
            )
        return body


def _error(
    code: PublicErrorCode,
    message: str,
    *,
    retryable: bool = False,
    reason_code: str | None = None,
) -> PublicOperationError:
    details = None if reason_code is None else {"reason_code": reason_code}
    return PublicOperationError(code, message, retryable, safe_details=details)


# The event-draft envelope fields, which are frozen schema names rather than caller-chosen keys.
# Only these may appear after the draft ordinal in a public error location.
_LOCATABLE_DRAFT_SUBFIELDS: Final = frozenset(
    {
        "artifact_refs",
        "causal_parents",
        "event_id",
        "evidence_refs",
        "occurred_at",
        "payload",
        "schema",
    }
)


# The payload fields that own a canonical set, which are frozen schema names declared by
# `yoetz.domain.events`. `/event_drafts/N/payload` alone cannot be acted on: a rejected batch left
# an agent guessing which of several reference lists broke the canonical set form.
_LOCATABLE_PAYLOAD_FIELDS: Final = frozenset(
    {
        "affected_obligation_ids",
        "disputes_refs",
        "evidence_refs",
        "limitation_refs",
        "obligation_ids",
        "obligation_refs",
        "redaction_target_event_ids",
        "redaction_target_object_ids",
        "replacement_obligation_ids",
        "resolution_evidence_refs",
        "returned_finding_ids",
        "scope",
        "source_refs",
        "supporting_refs",
        "supersedes_claim_refs",
        "target_event_ids",
        "target_object_ids",
    }
)


def _draft_pointer(
    event_index: int, subfield: str | None, payload_field: str | None = None
) -> str | None:
    """Locate one rejected draft without ever naming caller-supplied keys or values.

    Every segment is a frozen schema name plus the draft's ordinal, which is bounded by
    ``MAX_EVENTS_PER_BATCH``. Nothing here is derived from the submitted payload: a payload field
    is admitted only when it is already registered in ``_LOCATABLE_PAYLOAD_FIELDS``.
    """

    if type(event_index) is not int or not 0 <= event_index < MAX_EVENTS_PER_BATCH:
        return None
    if subfield is None:
        return f"/event_drafts/{event_index}"
    if subfield not in _LOCATABLE_DRAFT_SUBFIELDS:
        return None
    pointer = f"/event_drafts/{event_index}/{subfield}"
    # Only the payload has opaque interior structure worth naming one level deeper.
    if subfield == "payload" and payload_field in _LOCATABLE_PAYLOAD_FIELDS:
        return f"{pointer}/{payload_field}"
    return pointer


def _payload_field_of(exc: BaseException) -> str | None:
    """Read the owning payload field a protocol rejection carried, if it named one."""

    field = getattr(exc, "field", None)
    return field if type(field) is str else None


def _draft_subfield_of(exc: BaseException) -> str | None:
    """Read the owning draft envelope field a protocol rejection carried, if it named one.

    ``ProtocolValueError.field`` documents that consumers must re-check it against their own
    allowlist, so anything that is not a frozen draft envelope name is discarded here rather than
    handed to ``_draft_pointer``, which would drop the draft ordinal along with it.
    """

    field = getattr(exc, "field", None)
    return field if type(field) is str and field in _LOCATABLE_DRAFT_SUBFIELDS else None


_REGISTERED_EVENT_FAMILIES: Final = frozenset(schema.name for schema in PAYLOAD_TYPES)
_INPUT_CORRECTION_CONTINUATION: Final = "input_correction_new_identity"


def _declared_schema_name(value: JsonValue) -> str | None:
    """Return the draft's declared family, but only when it is a registered frozen name.

    The rule that repairs a reference-mirror rejection differs per family, so the message needs to
    know which one was declared. A caller-supplied string is never carried: an unregistered name
    returns None and the generic message stands.
    """

    if not isinstance(value, Mapping):
        return None
    schema = cast(Mapping[str, JsonValue], value).get("schema")
    if not isinstance(schema, Mapping):
        return None
    name = cast(Mapping[str, JsonValue], schema).get("name")
    return name if type(name) is str and name in _REGISTERED_EVENT_FAMILIES else None


# Corrective sentences for reason codes whose repair is an exact rule the caller cannot infer from
# the generic "correct the payload" message. Keyed by reason code and, where the rule differs per
# event family, by the frozen family name. Every character is checked in here: no caller value, no
# submitted identifier, and no count derived from the rejected request reaches these strings.
_SET_ORDER_RULE: Final = (
    "The event batch is invalid. Every set-valued list is admitted only when its members are "
    "unique and already in ascending ASCII order. JSON Schema uniqueItems does not express "
    "order. Sort the named field and retry; a one-element dry_run subset cannot demonstrate "
    "this rule."
)
_SET_ORDER_CORRECTIONS: Final[Mapping[str, str]] = MappingProxyType(
    {
        "duplicate_set_member": (
            "The event batch is invalid. Every set-valued list is admitted only when its "
            "members are unique and already in ascending ASCII order. Remove the duplicate "
            "from the named field and retry."
        ),
        "unsorted_set_field": _SET_ORDER_RULE,
    }
)
_REF_MIRROR_EVIDENCE_RULE: Final = (
    "The event batch is invalid. The draft envelope evidence_refs must repeat the payload "
    "evidence_refs exactly: the same ids in the same ascending order, or both empty. See "
    "yoetz://guidance/publication-policy.md section reference mirrors. Correct the event payload "
    "before retrying."
)
_REF_MIRROR_CORRECTIONS: Final[Mapping[str, Mapping[str, str]]] = MappingProxyType(
    {
        "ref_mirror_mismatch": MappingProxyType(
            {
                "result_recorded": _REF_MIRROR_EVIDENCE_RULE,
                "response_recorded": _REF_MIRROR_EVIDENCE_RULE,
                "evidence_recorded": (
                    "The event batch is invalid. The draft envelope artifact_refs must be exactly "
                    "the payload captured_object_id, or empty when the payload declares no "
                    "captured object. See yoetz://guidance/publication-policy.md section "
                    "reference mirrors. Correct the event payload before retrying."
                ),
                "receipt_recorded": (
                    "The event batch is invalid. The draft envelope artifact_refs must be exactly "
                    "the payload receipt_object_id. See yoetz://guidance/publication-policy.md "
                    "section reference mirrors. Correct the event payload before retrying."
                ),
                "redaction_recorded": (
                    "The event batch is invalid. The draft envelope artifact_refs must repeat the "
                    "payload target_object_ids exactly: the same ids in the same ascending order, "
                    "or both empty. See yoetz://guidance/publication-policy.md section reference "
                    "mirrors. Correct the event payload before retrying."
                ),
            }
        ),
        # #997: the obligation version is a pure function of the payload.
        "invalid_event_schema": MappingProxyType(
            {
                "obligation_published": (
                    "The event batch is invalid. obligation_published/1.1.0 is only for status "
                    "acknowledged_not_done with an acknowledged_not_done_reason; publish an open "
                    "or resolved obligation, including reopening an acknowledged one, on "
                    "obligation_published/1.0.0 with the same meaning fields."
                ),
            }
        ),
    }
)


def _corrective_message(reason_code: str, schema_name: str | None) -> str | None:
    """Return the checked-in corrective message for one reason code and family, if registered."""

    set_order = _SET_ORDER_CORRECTIONS.get(reason_code)
    if set_order is not None:
        return set_order
    families = _REF_MIRROR_CORRECTIONS.get(reason_code)
    if families is None or type(schema_name) is not str:
        return None
    # The family must be one the domain already registers; an unregistered name falls through to
    # the generic message rather than reaching the caller or raising.
    if schema_name not in _REGISTERED_EVENT_FAMILIES:
        return None
    return families.get(schema_name)


def _event_invalid(
    reason_code: str = "invalid_event_value_type",
    *,
    retryable: bool = False,
    event_index: int | None = None,
    subfield: str | None = None,
    payload_field: str | None = None,
    schema_name: str | None = None,
) -> PublicOperationError:
    # Only a stale frontier is fixed by rereading status; every other reason needs the event
    # payload corrected first, and retrying it unchanged would fail the same way.
    if reason_code == "expected_frontier_required":
        message = (
            "The event batch is invalid. State-sensitive event families require "
            "expected_frontier. Call status to read the current frontier, then retry "
            "idempotently with the same request_id and expected_frontier set."
        )
    elif reason_code == "frontier_changed":
        message = (
            "The event batch is invalid. Call status to read the current frontier, then retry "
            "idempotently with the same request_id."
        )
    else:
        # An EVENT_INVALID reaches MCP through the success branch of the dispatcher, so the bridge
        # cannot append a hint the way it does for INVALID_REQUEST. Stating the rule here is what
        # keeps the CLI and MCP surfaces identical and the failure repairable in one retry.
        message = _corrective_message(reason_code, schema_name) or (
            "The event batch is invalid. Correct the event payload before retrying."
        )
    details: dict[str, str] = {"reason_code": reason_code}
    if event_index is not None:
        pointer = _draft_pointer(event_index, subfield, payload_field)
        if pointer is not None:
            # Which draft failed is the difference between a one-line fix and re-deriving the
            # whole batch; a batch may carry up to MAX_EVENTS_PER_BATCH drafts.
            details["field"] = pointer
    if not retryable and reason_code not in REASON_CODE_CONTINUATIONS:
        # This producer is the one place that knows a non-retryable EVENT_INVALID rejected the
        # caller's drafts before any append (ADR-030). The reason code alone cannot say so -- the
        # same validation reasons also name corrupt stored records elsewhere -- so the correction
        # directive is classified here rather than mapped from the reason. A reason with its own
        # directive (set order, frontier) keeps it through the construction-time attachment.
        details["continuation"] = _INPUT_CORRECTION_CONTINUATION
    return PublicOperationError(
        PublicErrorCode.EVENT_INVALID, message, retryable, safe_details=details
    )


def _mapping(value: JsonValue) -> Mapping[str, JsonValue]:
    if not isinstance(value, Mapping):
        raise ProtocolValueError("invalid_event_value_type")
    source = cast(Mapping[object, object], value)
    if any(type(key) is not str for key in source):
        raise ProtocolValueError("invalid_event_value_type")
    return cast(Mapping[str, JsonValue], source)


def _field(source: Mapping[str, JsonValue], key: str) -> JsonValue:
    try:
        return source[key]
    except Exception as exc:
        raise ProtocolValueError("missing_payload_field") from exc


def _tuple_field(source: Mapping[str, JsonValue], key: str) -> tuple[JsonValue, ...]:
    value = _field(source, key)
    if type(value) is not tuple and type(value) is not list:
        raise ProtocolValueError("invalid_event_value_type")
    return tuple(cast(tuple[JsonValue, ...] | list[JsonValue], value))


def _channel_for(request: PublishWorkRequestModel) -> PublicationChannel:
    try:
        return PublicationChannel(request.client.integration.value)
    except ValueError as exc:
        raise _event_invalid("event_family_not_admitted") from exc


def _coverage_for(channel: PublicationChannel, *, has_unknown: bool) -> Coverage:
    baseline = coverage_for_channel(channel)
    if channel is PublicationChannel.CODEX_JSONL_IMPORT:
        baseline = replace(
            baseline,
            authorship_assurance=AuthorshipAssurance.HARNESS_OBSERVED,
        )
    if not has_unknown:
        return baseline
    return replace(
        baseline,
        ledger_freshness=LedgerFreshness.PARTIAL,
        known_gaps=tuple(sorted((*baseline.known_gaps, _UNKNOWN_GAP), key=str.encode)),
    )


def _reason_code_of(exc: BaseException, fallback: str = "invalid_event_value_type") -> str:
    reason = exc.args[0] if exc.args and type(exc.args[0]) is str else fallback
    return reason if reason in PROTOCOL_REASON_CODES else fallback


def _decode_draft(value: JsonValue, event_index: int) -> _PreparedDraft:
    """Decode one draft, attributing any rejection to that draft and its owning field."""

    source = _mapping(value)

    def _locate[T](subfield: str, decode: Callable[[], T]) -> T:
        try:
            return decode()
        except PublicOperationError:
            raise
        except (TypeError, ValueError) as exc:
            raise _event_invalid(
                _reason_code_of(exc),
                event_index=event_index,
                subfield=subfield,
                payload_field=_payload_field_of(exc),
            ) from exc

    schema_source = _locate("schema", lambda: _mapping(_field(source, "schema")))
    schema = _locate(
        "schema",
        lambda: EventSchema(
            cast(str, _field(schema_source, "name")),
            cast(str, _field(schema_source, "version")),
        ),
    )
    raw_payload = _locate("payload", lambda: freeze_json(_field(source, "payload")))
    if schema in PAYLOAD_TYPES:
        payload: EventPayload | DomainJsonValue = _locate(
            "payload", lambda: decode_payload(schema, raw_payload)
        )
        payload_json = _locate("payload", lambda: encode_payload(payload))
        projection_status = "projected"
    else:
        payload = raw_payload
        payload_json = cast(JsonValue, raw_payload)
        projection_status = "unknown_unprojected"
    draft = EventDraft(
        _locate("event_id", lambda: event_id(_field(source, "event_id"))),
        schema,
        _locate("occurred_at", lambda: timestamp_from_string(_field(source, "occurred_at"))),
        _locate(
            "causal_parents",
            lambda: tuple(event_id(item) for item in _tuple_field(source, "causal_parents")),
        ),
        payload,
        _locate(
            "artifact_refs",
            lambda: tuple(object_id(item) for item in _tuple_field(source, "artifact_refs")),
        ),
        _locate(
            "evidence_refs",
            lambda: tuple(
                evidence_id(item)
                if type(item) is str and item.startswith("evd_")
                else result_id(item)
                for item in _tuple_field(source, "evidence_refs")
            ),
        ),
    )
    return _PreparedDraft(draft, canonical_encode(payload_json), projection_status)


def _validate_admission(
    app: Application,
    request: PublishWorkRequestModel,
    channel: PublicationChannel,
    drafts: tuple[_PreparedDraft, ...],
) -> None:
    trusted_import = channel is PublicationChannel.CODEX_JSONL_IMPORT
    if trusted_import and not app.authorizes_import_publication(request):
        raise _event_invalid("event_family_not_admitted")
    admitted = _IMPORT_FAMILIES if trusted_import else _ORDINARY_FAMILIES
    for index, item in enumerate(drafts):
        known = item.draft.schema in PAYLOAD_TYPES
        # These event families carry service-authored relationship/lifecycle facts.  Even if a
        # future admission profile adds a broader family set, a caller must never self-award a
        # delegation declaration, frozen dependency manifest, or abandonment stamp.
        if (
            known
            and item.draft.schema.name in LINEAGE_SERVICE_STAMPED_FAMILIES
            and item.draft.schema.name != "coordination_obligation_declared"
        ):
            raise _event_invalid("event_family_not_admitted", event_index=index, subfield="schema")
        if (known and item.draft.schema.name not in admitted) or (not known and not trusted_import):
            raise _event_invalid("event_family_not_admitted", event_index=index, subfield="schema")
        payload = item.draft.payload
        if type(payload) is EvidenceRecordedPayload and payload.digest_binding is not None:
            provenance = payload.digest_binding.provenance
            if not trusted_import and provenance is not EvidenceDigestProvenance.CALLER_ASSERTED:
                raise _event_invalid(
                    "evidence_digest_provenance_invalid",
                    event_index=index,
                    subfield="payload",
                    payload_field="digest_binding",
                )
            if trusted_import and provenance not in {
                EvidenceDigestProvenance.CALLER_ASSERTED,
                EvidenceDigestProvenance.IMPORT_OBSERVED,
            }:
                raise _event_invalid(
                    "evidence_digest_provenance_invalid",
                    event_index=index,
                    subfield="payload",
                    payload_field="digest_binding",
                )
    if request.expected_frontier is None and any(
        item.draft.schema in PAYLOAD_TYPES and item.draft.schema.name in _STATE_SENSITIVE_FAMILIES
        for item in drafts
    ):
        raise _event_invalid("expected_frontier_required", retryable=True)


def _validate_order(drafts: tuple[_PreparedDraft, ...]) -> None:
    event_ids = tuple(item.draft.event_id for item in drafts)
    if len(event_ids) != len(set(event_ids)):
        seen: set[EventId] = set()
        duplicate_at = 0
        for index, value in enumerate(event_ids):
            if value in seen:
                duplicate_at = index
                break
            seen.add(value)
        raise _event_invalid("duplicate_set_member", event_index=duplicate_at, subfield="event_id")
    position = {event_id: index for index, event_id in enumerate(event_ids)}
    for index, item in enumerate(drafts):
        if any(position.get(parent, -1) >= index for parent in item.draft.causal_parents):
            raise _event_invalid(
                "invalid_event_value_type", event_index=index, subfield="causal_parents"
            )


def prepare_publication(
    request: PublishWorkRequestModel,
    *,
    channel: PublicationChannel,
    app: Application,
) -> PreparedPublication:
    """Decode, normalize, authorize, and cross-check one bounded batch."""

    if not 1 <= len(request.event_drafts) <= MAX_EVENTS_PER_BATCH:
        raise _error(PublicErrorCode.INVALID_REQUEST, "The event batch size is invalid.")
    decoded: list[_PreparedDraft] = []
    for index, value in enumerate(request.event_drafts):
        try:
            decoded.append(_decode_draft(value, index))
        except PublicOperationError:
            raise
        except (TypeError, ValueError) as exc:
            # Anything not already attributed to a field still names its draft, so the caller
            # never has to re-derive which member of the batch was rejected. Envelope-level
            # invariants such as the reference mirrors fail while the draft itself is being
            # constructed, outside any `_locate` wrapper, so the owning field is read here.
            raise _event_invalid(
                _reason_code_of(exc),
                event_index=index,
                subfield=_draft_subfield_of(exc),
                schema_name=_declared_schema_name(value),
            ) from exc
    drafts = tuple(decoded)
    try:
        _validate_order(drafts)
        _validate_admission(app, request, channel, drafts)
    except PublicOperationError:
        raise
    except (TypeError, ValueError) as exc:
        raise _event_invalid(_reason_code_of(exc)) from exc

    has_unknown = any(item.projection_status == "unknown_unprojected" for item in drafts)
    coverage = _coverage_for(channel, has_unknown=has_unknown)
    author = Actor(
        actor_id(request.actor.actor_id),
        ActorType(request.actor.actor_type.value),
        coverage.authorship_assurance,
    )
    return PreparedPublication(channel, author, coverage, drafts)


def _request_identity(
    request: PublishWorkRequestModel,
    prepared: PreparedPublication,
    commitments: tuple[str, ...],
) -> JsonValue:
    expected = (
        None
        if request.expected_frontier is None
        else request.expected_frontier.model_dump(mode="json")
    )
    return {
        "protocol": "yoetz",
        "protocol_version": request.protocol_version,
        "schema_version": request.schema_version,
        "request_id": request.request_id,
        "session_id": request.session_id,
        "writer_id": request.writer_id,
        "expected_frontier": expected,
        "actor": {
            "actor_id": prepared.author.actor_id,
            "actor_type": prepared.author.actor_type.value,
        },
        "client": {
            "integration": request.client.integration.value,
            "kind": request.client.kind.value,
            "version": request.client.version,
        },
        "event_drafts": tuple(
            {
                "event_id": item.draft.event_id,
                "schema": {
                    "name": item.draft.schema.name,
                    "version": item.draft.schema.version,
                },
                "occurred_at": item.draft.occurred_at.wire,
                "causal_parents": item.draft.causal_parents,
                "artifact_refs": item.draft.artifact_refs,
                "evidence_refs": item.draft.evidence_refs,
                "payload_commitment": commitment,
            }
            for item, commitment in zip(prepared.drafts, commitments, strict=True)
        ),
    }


def _decode_stored_append_result(data: bytes) -> AppendResult:
    try:
        source = _mapping(strict_json_parse(data))
        if frozenset(source) != frozenset(
            {"accepted", "subject_frontier", "result_frontier", "warnings"}
        ):
            raise ProtocolValueError("stored_result_shape_invalid")
        accepted = tuple(
            AcceptedEventSummary(
                cast(str, _field(item, "event_id")),
                int(cast(str, _field(item, "ingestion_sequence"))),
                int(cast(str, _field(item, "writer_sequence"))),
                cast(str, _field(item, "entry_digest")),
                cast(
                    Literal["projected", "unknown_unprojected"],
                    _field(item, "projection_status"),
                ),
            )
            for item in (_mapping(value) for value in _tuple_field(source, "accepted"))
        )
        warnings = tuple(
            sorted(
                (AppendWarning(cast(str, value)) for value in _tuple_field(source, "warnings")),
                key=lambda item: item.value.encode("ascii"),
            )
        )
        return AppendResult(
            "replayed",
            accepted,
            frontier_from_json(_field(source, "subject_frontier")),
            frontier_from_json(_field(source, "result_frontier")),
            warnings,
        )
    except (TypeError, ValueError) as exc:
        raise _error(
            PublicErrorCode.STORAGE_CORRUPT,
            "The stored operation result is invalid.",
        ) from exc


def _request_identity_conflict(result: AppendResult) -> PublicOperationError:
    """Return a non-destructive conflict when a request_id is reused with a different body.

    Carries the frontier and accepted-event count from the already-committed operation so the
    caller can continue without reconstructing the original body. Full accepted-event identity
    is available via ``status view=operation``.
    """

    return PublicOperationError(
        PublicErrorCode.REQUEST_IDENTITY_CONFLICT,
        (
            "The request ID was already used with a different request body. "
            "Read status view=operation for the stored result of that request_id."
        ),
        False,
        safe_details={
            "reason_code": "request_identity_conflict",
            "sequence": result.result_frontier.sequence,
            "head_digest": result.result_frontier.head_digest,
            "count": len(result.accepted),
        },
    )


async def _resolve_existing_operation(
    runtime: TaskRuntime,
    request: PublishWorkRequestModel,
) -> OperationRecord | None:
    """Resolve a prior publish operation before any body validation or append.

    Replay is keyed only on ``(writer_id, request_id)``. The body is not consulted here; digest
    matching happens after the caller has prepared the submission, and a body that cannot be
    prepared while an operation already exists becomes ``REQUEST_IDENTITY_CONFLICT``.
    """

    operation = await runtime.ledger.lookup_operation(request.writer_id, request.request_id)
    if operation is None:
        return None
    if operation.operation_kind is not OperationKind.PUBLISH_WORK:
        raise _error(
            PublicErrorCode.IDEMPOTENCY_CONFLICT,
            "The request ID was already used.",
        )
    if operation.state is OperationState.COMPLETE:
        return operation
    if operation.state is OperationState.QUARANTINED:
        raise _error(
            PublicErrorCode.STORAGE_CORRUPT,
            "The stored operation is quarantined.",
        )
    raise _error(
        PublicErrorCode.OPERATION_PENDING,
        "The operation is still pending.",
        retryable=True,
    )


async def _commitments_and_digest(
    runtime: TaskRuntime,
    request: PublishWorkRequestModel,
    prepared: PreparedPublication,
) -> tuple[tuple[str, ...], str]:
    commitments = tuple(
        [
            await runtime.objects.commitment_for(item.payload_bytes, ObjectKind.EVENT_PAYLOAD)
            for item in prepared.drafts
        ]
    )
    digest = request_digest(_request_identity(request, prepared, commitments))
    return commitments, digest


async def _load_accepted_records(
    runtime: TaskRuntime,
    result: AppendResult,
) -> tuple[LedgerRecord, ...]:
    first = min(item.ingestion_sequence for item in result.accepted)
    last = max(item.ingestion_sequence for item in result.accepted)
    records = tuple(
        [
            record
            async for record in runtime.ledger.load_events(
                runtime.session_id,
                after=first - 1,
                through=last,
            )
        ]
    )
    summaries = {item.event_id: item for item in result.accepted}
    matching = tuple(record for record in records if record.event_id in summaries)
    if len(matching) != len(result.accepted):
        raise _error(PublicErrorCode.STORAGE_CORRUPT, "The accepted event range is invalid.")
    by_id = {str(record.event_id): record for record in matching}
    ordered = tuple(by_id[item.event_id] for item in result.accepted)
    for record, summary in zip(ordered, result.accepted, strict=True):
        if (
            record.ledger.ingestion_sequence != summary.ingestion_sequence
            or record.writer.sequence != summary.writer_sequence
            or record.entry_digest != summary.entry_digest
            or ("unknown_unprojected" if type(record) is UnknownEvent else "projected")
            != summary.projection_status
        ):
            raise _error(PublicErrorCode.STORAGE_CORRUPT, "The accepted event range is invalid.")
    return ordered


async def _projection_at_result_frontier(
    runtime: TaskRuntime,
    result: AppendResult,
) -> ProjectionState:
    """Read the adapter's validated projection and replay only on a frontier mismatch.

    Both ledger adapters already replay and retain the exact projection as part of an accepted
    append. Replaying the task-global history here duplicated that O(n) work on every successful
    publish. A replayed operation or a concurrent suffix can point at an older frontier; in those
    cases the cached projection cannot answer the requested historical result and the exact prefix
    replay remains the conservative fallback.
    """

    stored = await runtime.ledger.load_projection(
        runtime.session_id,
        ProjectionView.CANDIDATE_FINDINGS,
    )
    if (
        stored is not None
        and stored.frontier == result.result_frontier
        and stored.lag == 0
        and not stored.rebuild_required
        and stored.projection_version == PROJECTION_VERSION
        and type(stored.state) is ProjectionState
        and stored.state.frontier == stored.frontier.sequence
        and stored.state.head_digest == stored.frontier.head_digest
    ):
        return stored.state
    prefix = tuple(
        [
            row
            async for row in runtime.ledger.load_events(
                runtime.session_id, through=result.result_frontier.sequence
            )
        ]
    )
    return await replay_off_loop(prefix)


def _accepted_model(record: LedgerRecord) -> PublishWorkAcceptedEventModel:
    return PublishWorkAcceptedEventModel(
        event_id=record.event_id,
        schema_name=record.schema.name,
        schema_version=record.schema.version,
        writer_sequence=str(record.writer.sequence),
        ingestion_sequence=str(record.ledger.ingestion_sequence),
        accepted_at=record.ledger.accepted_at.wire,
        predecessor_digest=record.ledger.previous_entry_digest,
        entry_digest=record.entry_digest,
        projection_status=("unknown_unprojected" if type(record) is UnknownEvent else "projected"),
    )


async def _internal_result(
    request: PublishWorkRequestModel,
    runtime: TaskRuntime,
    prepared: PreparedPublication,
    result: AppendResult,
    digest: str,
) -> PublishWorkInternalResult:
    expected_ids = tuple(item.draft.event_id for item in prepared.drafts)
    if tuple(item.event_id for item in result.accepted) != expected_ids:
        raise _error(PublicErrorCode.STORAGE_CORRUPT, "The accepted event set is invalid.")
    expected_warnings = (
        (AppendWarning.UNKNOWN_EVENT_SCHEMA_PRESERVED,)
        if any(item.projection_status == "unknown_unprojected" for item in prepared.drafts)
        else ()
    )
    if result.warnings != expected_warnings:
        raise _error(PublicErrorCode.STORAGE_CORRUPT, "The accepted warnings are invalid.")
    records = await _load_accepted_records(runtime, result)
    projection = await _projection_at_result_frontier(runtime, result)
    coverage = with_completion_scope_coverage(prepared.coverage, projection)
    notices = _blocker_notices(projection, prepared)
    return PublishWorkInternalResult(
        protocol_version="0.1",
        schema_version="1.0.0",
        request_id=request.request_id,
        request_digest=digest,
        ok=True,
        outcome=result.outcome,
        task_id=runtime.task_id,
        session_id=runtime.session_id,
        writer_id=cast(str, runtime.writer_id),
        subject_frontier=result.subject_frontier,
        result_frontier=result.result_frontier,
        accepted_events=tuple(_accepted_model(record) for record in records),
        warning_codes=tuple(item.value for item in result.warnings),
        coverage=coverage,
        gaps=coverage.known_gaps,
        versions=PublishWorkVersionSliceModel(
            protocol_version="0.1",
            engine_version=runtime.engine_version,
            projection_version=runtime.projection_version,
            policy_packs=_POLICY_PACKS,
        ),
        blocker_notices=notices,
    )


def _blocker_notices(
    projection: ProjectionState, prepared: PreparedPublication
) -> tuple[PublishWorkBlockerNoticeModel, ...]:
    """Publish-time challenge and no-effect notices for the batch's yoetz-blocker lines (#985).

    ``projection`` already includes the batch (the accepted frontier, or a dry run's provisional
    fold). Notices are closed codes with fixed text, so a replay returns the same body.
    """

    decisions = tuple(
        (item.draft.event_id, item.draft.payload)
        for item in prepared.drafts
        if type(item.draft.payload) is DecisionRecordedPayload
    )
    if not decisions:
        return ()
    return tuple(
        PublishWorkBlockerNoticeModel(
            obligation_id=notice.obligation_id,
            blocker_kind=cast(
                Literal["authority", "consent", "credential", "dependency_unavailable"],
                notice.kind,
            ),
            notice=cast(
                Literal["blocker_claimed", "blocker_confirmed", "blocker_without_effect"],
                notice.notice,
            ),
            text=PUBLISH_BLOCKER_NOTICE_TEXTS[notice.notice],
        )
        for notice in blocker_publication_notices(projection, decisions)[:64]
    )


def build_accepted_projection_unavailable_result(
    *,
    request_id: str,
    outcome: Literal["accepted", "replayed"],
    task_id: str,
    session_id: str,
    writer_id: str,
    subject_frontier: Frontier,
    result_frontier: Frontier,
    accepted: tuple[AcceptedEventSummary, ...] | tuple[PublishWorkAcceptedEventModel, ...],
    correlation_id: str,
) -> PublishWorkResult:
    """Build the reduced total-acceptance envelope from ledger facts alone.

    Constructible by construction from ``AppendResult`` or the closed internal result — never from
    privacy projection or event payload content. A committed publish must always be able to emit
    this shape; if it cannot, that is a genuine internal defect rather than a reported failure of
    the write itself.
    """

    events = tuple(
        {
            "event_id": item.event_id,
            "entry_digest": item.entry_digest,
            "ingestion_sequence": (
                item.ingestion_sequence
                if type(item.ingestion_sequence) is str
                else str(item.ingestion_sequence)
            ),
        }
        for item in accepted
    )
    body = {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": request_id,
        "ok": True,
        "response_completeness": "accepted_projection_unavailable",
        "reason_code": "response_projection_failed",
        "correlation_id": correlation_id,
        "outcome": outcome,
        "task_id": task_id,
        "session_id": session_id,
        "writer_id": writer_id,
        "subject_frontier": dict(subject_frontier.as_wire().items()),
        "result_frontier": dict(result_frontier.as_wire().items()),
        "accepted_events": events,
    }
    return PublishWorkResultModel.model_validate(body)


def accepted_projection_unavailable_from_internal(
    internal: PublishWorkInternalResult,
    *,
    correlation_id: str,
) -> PublishWorkResult:
    """Reduce a closed internal publication success to the total-acceptance envelope."""

    return build_accepted_projection_unavailable_result(
        request_id=internal.request_id,
        outcome=internal.outcome,
        task_id=internal.task_id,
        session_id=internal.session_id,
        writer_id=internal.writer_id,
        subject_frontier=internal.subject_frontier,
        result_frontier=internal.result_frontier,
        accepted=internal.accepted_events,
        correlation_id=correlation_id,
    )


def accepted_projection_unavailable_from_append(
    request: PublishWorkRequestModel,
    runtime: TaskRuntime,
    result: AppendResult,
    *,
    correlation_id: str,
) -> PublishWorkResult:
    """Reduce a committed append to the total-acceptance envelope without reloading events."""

    return build_accepted_projection_unavailable_result(
        request_id=request.request_id,
        outcome=result.outcome,
        task_id=runtime.task_id,
        session_id=runtime.session_id,
        writer_id=cast(str, runtime.writer_id),
        subject_frontier=result.subject_frontier,
        result_frontier=result.result_frontier,
        accepted=result.accepted,
        correlation_id=correlation_id,
    )


def _logical_key_for_payload(payload: EventPayload, draft_event_id: str) -> str | None:
    if type(payload) in {PlanPublishedPayload, PlanRevisedPayload}:
        return str(cast(PlanPublishedPayload | PlanRevisedPayload, payload).plan_version)
    if type(payload) is ObligationPublishedPayload:
        return payload.obligation_id
    if type(payload) in {AssignmentRecordedPayload, DecisionRecordedPayload, CheckRecordedPayload}:
        return draft_event_id
    if type(payload) is ActionRecordedPayload:
        return payload.action_id
    if type(payload) is ResultRecordedPayload:
        return payload.result_id
    if type(payload) is EvidenceRecordedPayload:
        return payload.evidence_id
    if type(payload) is ClaimRecordedPayloadV1_1:
        return payload.claim_id
    if type(payload) is ClaimRecordedPayload:
        return payload.claim_id
    if type(payload) is FindingRecordedPayload:
        return payload.finding_id
    if type(payload) is ResponseRecordedPayload:
        return payload.finding_id
    return None


def _redaction_targets_for_payload(
    payload: EventPayload,
) -> tuple[tuple[EventId, ...], tuple[ObjectId, ...]]:
    if type(payload) is RedactionRecordedPayload:
        return payload.target_event_ids, payload.target_object_ids
    return (), ()


def _provisional_record_for_dry_run(
    *,
    item: _PreparedDraft,
    author: Actor,
    channel: PublicationChannel,
    coverage: Coverage,
    runtime: TaskRuntime,
    operation: str,
    offset: int,
    ingestion_sequence: int,
    writer_sequence: int,
    previous_ledger_digest: str,
    previous_writer_digest: str,
    accepted_at: datetime,
) -> LedgerRecord:
    """Build one non-durable ledger preimage for read-only projection preflight."""

    draft = item.draft
    known_payload = item.projection_status == "projected"
    payload_json: JsonValue = (
        encode_payload(cast(EventPayload, draft.payload))
        if known_payload
        else cast(JsonValue, draft.payload)
    )
    payload_digest = canonical_digest(payload_json)
    logical_key: str | None = None
    target_events: tuple[EventId, ...] = ()
    target_objects: tuple[ObjectId, ...] = ()
    if known_payload:
        typed_payload = cast(EventPayload, draft.payload)
        logical_key = _logical_key_for_payload(typed_payload, draft.event_id)
        target_events, target_objects = _redaction_targets_for_payload(typed_payload)
    locator = ProjectionLocator(
        draft.schema,
        logical_key,
        payload_digest,
        target_events,
        target_objects,
    )
    # Synthetic object identity: dry-run never stages; digests stay chain-local to preflight.
    synthetic_object = f"obj_00000000-0000-4000-8000-{offset + 900_000:012d}"
    media_type = media_type_for(draft.schema.name)
    # Commitments are hmac-sha256; reuse the payload digest hex under that prefix for shape only.
    commitment = f"hmac-sha256:{payload_digest.removeprefix('sha256:')}"
    payload_ref = PayloadRef(
        object_id(synthetic_object),
        media_type,
        len(item.payload_bytes),
        commitment,
    )
    timestamp = timestamp_from_datetime(accepted_at)
    preimage = {
        "protocol": "yoetz.event",
        "protocol_version": "0.1",
        "event_id": draft.event_id,
        "task_id": runtime.task_id,
        "session_id": runtime.session_id,
        "schema": {"name": draft.schema.name, "version": draft.schema.version},
        "author": {
            "actor_id": author.actor_id,
            "actor_type": author.actor_type.value,
            "assurance": author.assurance.value,
        },
        "writer": {
            "writer_id": cast(str, runtime.writer_id),
            "sequence": str(writer_sequence),
            "previous_entry_digest": previous_writer_digest,
        },
        "ledger": {
            "ingestion_sequence": str(ingestion_sequence),
            "previous_entry_digest": previous_ledger_digest,
            "accepted_at": timestamp.wire,
        },
        "operation_id": operation,
        "occurred_at": draft.occurred_at.wire,
        "causal_parents": draft.causal_parents,
        "publication_channel": channel.value,
        "coverage": coverage_to_json(coverage),
        "payload_ref": {
            "object_id": synthetic_object,
            "media_type": media_type,
            "plaintext_size": len(item.payload_bytes),
            "commitment": commitment,
            "encryption_format": "yoetz-object/1",
        },
        "redaction": "present",
        "artifact_refs": draft.artifact_refs,
        "evidence_refs": draft.evidence_refs,
    }
    digest = entry_digest(preimage)
    writer = WriterChain(
        writer_id(cast(str, runtime.writer_id)),
        writer_sequence,
        previous_writer_digest,
    )
    ledger = LedgerChain(ingestion_sequence, previous_ledger_digest, timestamp)
    if known_payload:
        return AcceptedEvent(
            event_id=draft.event_id,
            task_id=task_id(runtime.task_id),
            session_id=session_id(runtime.session_id),
            schema=draft.schema,
            author=author,
            writer=writer,
            ledger=ledger,
            operation_id=request_id(operation),
            occurred_at=draft.occurred_at,
            causal_parents=draft.causal_parents,
            publication_channel=channel,
            coverage=coverage,
            payload_ref=payload_ref,
            redaction=RedactionState.PRESENT,
            artifact_refs=draft.artifact_refs,
            evidence_refs=draft.evidence_refs,
            entry_digest=digest,
            payload=cast(EventPayload, draft.payload),
            projection_locator=locator,
        )
    return UnknownEvent(
        event_id=draft.event_id,
        task_id=task_id(runtime.task_id),
        session_id=session_id(runtime.session_id),
        schema=draft.schema,
        author=author,
        writer=writer,
        ledger=ledger,
        operation_id=request_id(operation),
        occurred_at=draft.occurred_at,
        causal_parents=draft.causal_parents,
        publication_channel=channel,
        coverage=coverage,
        payload_ref=payload_ref,
        redaction=RedactionState.PRESENT,
        artifact_refs=draft.artifact_refs,
        evidence_refs=draft.evidence_refs,
        entry_digest=digest,
        payload=cast(DomainJsonValue, draft.payload),
        projection_locator=locator,
        canonical_payload_digest=payload_digest,
    )


async def _preflight_dry_run_feasibility(
    runtime: TaskRuntime,
    request: PublishWorkRequestModel,
    prepared: PreparedPublication,
) -> tuple[Frontier, Coverage, ProjectionState]:
    """Reject batches the real append path would reject before reporting would_accept.

    Matches ``append_batch`` acceptance for frontier sequence, event-id uniqueness, causal
    parents, and projection replay — without staging objects or mutating durable state.
    """

    current = await runtime.ledger.load_frontier()
    if is_observation_authorship(prepared.author, prepared.channel) and (
        await runtime.ledger.has_active_frozen_case(runtime.session_id)
    ):
        raise PublicOperationError(
            PublicErrorCode.OPERATION_PENDING,
            "An active check is holding this session frontier.",
            True,
        )
    existing_records: list[LedgerRecord] = []
    seen: set[str] = set()
    writer_sequence = 1
    previous_writer_digest = "genesis"
    async for record in runtime.ledger.load_events(runtime.session_id):
        existing_records.append(record)
        seen.add(str(record.event_id))
        if str(record.writer.writer_id) == cast(str, runtime.writer_id):
            writer_sequence = int(record.writer.sequence) + 1
            previous_writer_digest = record.entry_digest

    # Ordinary publish passes only the integer sequence into AppendCommand; digest is not a gate.
    if request.expected_frontier is not None:
        expected_sequence = int(request.expected_frontier.sequence)
        observation_only_advance = expected_sequence < current.sequence and all(
            is_observation_authored(record)
            for record in existing_records
            if record.ledger.ingestion_sequence > expected_sequence
        )
        if expected_sequence != current.sequence and not observation_only_advance:
            raise PublicOperationError(
                PublicErrorCode.FRONTIER_CONFLICT,
                (
                    "The event batch is invalid. Call status to read the current frontier, then "
                    "retry idempotently with the same request_id."
                ),
                True,
                safe_details={"reason_code": "frontier_changed"},
            )

    prior_batch: set[str] = set()
    for index, item in enumerate(prepared.drafts):
        event_key = str(item.draft.event_id)
        if event_key in seen or event_key in prior_batch:
            raise _event_invalid("duplicate_set_member", event_index=index, subfield="event_id")
        if any(
            parent not in seen and parent not in prior_batch for parent in item.draft.causal_parents
        ):
            raise _event_invalid(
                "invalid_event_value_type", event_index=index, subfield="causal_parents"
            )
        prior_batch.add(event_key)

    # Fixed synthetic accepted_at for chain continuity only; dry-run is not evidential.
    accepted_at_dt = datetime(2026, 1, 1, tzinfo=UTC)
    previous_ledger = current.head_digest
    provisional: list[LedgerRecord] = []
    try:
        for offset, item in enumerate(prepared.drafts):
            record = _provisional_record_for_dry_run(
                item=item,
                author=prepared.author,
                channel=prepared.channel,
                coverage=prepared.coverage,
                runtime=runtime,
                operation=request.request_id,
                offset=offset,
                ingestion_sequence=current.sequence + offset + 1,
                writer_sequence=writer_sequence + offset,
                previous_ledger_digest=previous_ledger,
                previous_writer_digest=(
                    previous_writer_digest if offset == 0 else provisional[offset - 1].entry_digest
                ),
                accepted_at=accepted_at_dt,
            )
            provisional.append(record)
            previous_ledger = record.entry_digest
        prior_records = tuple(existing_records)
        prior_projection = (
            None
            if not prior_records
            else await trusted_projection_at(
                runtime.ledger,
                runtime.session_id,
                Frontier(
                    prior_records[-1].ledger.ingestion_sequence, prior_records[-1].entry_digest
                ),
            )
        )
        if prior_projection is None:
            projected = await replay_off_loop((*prior_records, *provisional))
        else:
            # Fold only the provisional drafts onto the adapter-owned projection; the extension
            # still re-authenticates the whole prefix into a fresh reverse index (issue #886).
            trusted_prior = prior_projection
            appended = tuple(provisional)
            projected = await asyncio.to_thread(
                replay_extension, trusted_prior, prior_records, appended
            )
    except ObligationResolutionMismatch as exc:
        draft_index: int | None = None
        if exc.event_id is not None:
            for index, item in enumerate(prepared.drafts):
                if item.draft.event_id == exc.event_id:
                    draft_index = index
                    break
        raise public_error_for_obligation_resolution_mismatch(
            exc, event_index=draft_index
        ) from None
    except NoObligationsReasonMismatch as exc:
        draft_index = None
        if exc.event_id is not None:
            for index, item in enumerate(prepared.drafts):
                if item.draft.event_id == exc.event_id:
                    draft_index = index
                    break
        raise public_error_for_no_obligations_reason_mismatch(
            exc, event_index=draft_index
        ) from None
    except ClaimRevisionMismatch as exc:
        draft_index = None
        if exc.event_id is not None:
            for index, item in enumerate(prepared.drafts):
                if item.draft.event_id == exc.event_id:
                    draft_index = index
                    break
        raise public_error_for_claim_revision_mismatch(exc, event_index=draft_index) from None
    except (
        ValueError,
        TypeError,
    ):
        raise _event_invalid("invalid_event_value_type") from None
    return current, with_completion_scope_coverage(prepared.coverage, projected), projected


def _validate_new_completion_scope(
    request: PublishWorkRequestModel, prepared: PreparedPublication
) -> None:
    """Guard new v1.1 authoring without invalidating historical replay or write recovery.

    An explicit empty array remains a bounded assertion, never inferred task-wide completion.
    Obligation support alongside an empty scope is almost certainly a misplaced scope reference;
    require the author to decide its meaning instead of silently moving those ids.
    """

    for index, item in enumerate(prepared.drafts):
        payload = item.draft.payload
        if type(payload) is not ClaimRecordedPayloadV1_1:
            continue
        if payload.claim_kind is not ClaimKind.COMPLETION:
            continue
        raw = _mapping(_field(_mapping(request.event_drafts[index]), "payload"))
        invariant = None
        if "obligation_refs" not in raw:
            invariant = "completion_scope_must_be_explicit"
        elif not payload.obligation_refs and any(
            ref.startswith("obl_") for ref in payload.supporting_refs
        ):
            invariant = "empty_scope_must_not_support_obligations"
        if invariant is not None:
            raise public_error_for_claim_revision_mismatch(
                ClaimRevisionMismatch("obligation_refs", invariant, item.draft.event_id),
                event_index=index,
            )


async def _execute_dry_run(
    app: Application,
    request: PublishWorkRequestModel,
    channel: PublicationChannel,
    runtime: TaskRuntime,
) -> PublishWorkResult:
    """Validate a batch and return a non-evidential preview without any durable side effects."""

    # Intentionally skip operation lookup: dry_run must not consume or conflict on request_id.
    prepared = prepare_publication(request, channel=channel, app=app)
    _validate_new_completion_scope(request, prepared)
    current, coverage, projected = await _preflight_dry_run_feasibility(runtime, request, prepared)
    notices = _blocker_notices(projected, prepared)
    frontier = FrontierModel.model_validate(dict(current.as_wire()))
    preview = tuple(
        PublishWorkDryRunPreviewEventModel(
            event_id=item.draft.event_id,
            schema_name=item.draft.schema.name,
            schema_version=item.draft.schema.version,
            causal_parents=item.draft.causal_parents,
            artifact_refs=item.draft.artifact_refs,
            evidence_refs=tuple(str(ref) for ref in item.draft.evidence_refs),
        )
        for item in prepared.drafts
    )
    body = PublishWorkDryRunModel(
        protocol_version="0.1",
        schema_version="1.0.0",
        request_id=request.request_id,
        ok=True,
        outcome="dry_run",
        evidential=False,
        task_id=runtime.task_id,
        session_id=runtime.session_id,
        writer_id=cast(str, runtime.writer_id),
        subject_frontier=frontier,
        result_frontier=frontier,
        would_accept=preview,
        coverage=CoverageModel.model_validate(coverage_to_json(coverage)),
        gaps=coverage.known_gaps,
        **({"blocker_notices": notices} if notices else {}),
    )
    return PublishWorkResultModel.model_validate(
        body.model_dump(mode="json", by_alias=True, exclude_unset=True)
    )


async def execute_publish_work(
    app: Application,
    request: PublishWorkRequestModel,
) -> PublishWorkInternalResult | PublishWorkResult:
    """Publish one all-or-nothing batch behind the ready application facade.

    Operation identity is resolved before body preparation and before
    ``expected_frontier`` evaluation. A completed operation with a matching body digest returns
    the stored result without re-appending. A completed operation with a different body returns
    ``REQUEST_IDENTITY_CONFLICT`` with the stored frontier — never ``INVALID_REQUEST`` and never
    a second append.

    ``dry_run: true`` validates the full batch and returns a non-evidential preview without
    appending, recording an operation, consuming ``request_id``, or moving the frontier.
    """

    request_bytes = canonical_encode(
        cast(
            JsonValue,
            request.model_dump(mode="json", by_alias=True, exclude_none=False),
        )
    )
    if len(request_bytes) > MAX_CANONICAL_REQUEST_BYTES:
        raise _error(PublicErrorCode.LIMIT_EXCEEDED, "The request is too large.")

    channel = _channel_for(request)
    runtime = await app.runtime.route(
        RouteCommand(
            request.session_id,
            request.writer_id,
            RouteAccess.WRITE,
            frozenset({RuntimeCapability.WRITE}),
        )
    )
    try:
        if runtime.session_id != request.session_id or runtime.writer_id != request.writer_id:
            raise _error(PublicErrorCode.SESSION_CONFLICT, "The writer route is inconsistent.")

        if request.dry_run is True:
            return await _execute_dry_run(app, request, channel, runtime)

        # Resolve replay before prepare_publication and before expected_frontier so recovery is
        # never blocked by body validation or a stale pre-append frontier.
        existing = await _resolve_existing_operation(runtime, request)
        if existing is not None:
            # COMPLETE without a result body is storage corruption, not a programming assert:
            # under -O a bare assert would skip and later raise TypeError on decode.
            if existing.result_canonical is None:
                raise _error(
                    PublicErrorCode.STORAGE_CORRUPT,
                    "The stored operation result is invalid.",
                )
            stored = _decode_stored_append_result(existing.result_canonical)
            try:
                prepared = prepare_publication(request, channel=channel, app=app)
                commitments, digest = await _commitments_and_digest(runtime, request, prepared)
            except PublicOperationError:
                # Body cannot be prepared; the operation still stands. Surface the committed
                # frontier rather than the body-validation failure that made recovery unreachable.
                raise _request_identity_conflict(stored) from None
            del commitments
            if existing.request_digest != digest:
                raise _request_identity_conflict(stored)
            # Digest matches: return the stored result. expected_frontier is intentionally not
            # re-evaluated — a correct replay carries the pre-append frontier by definition.
            try:
                return await _internal_result(request, runtime, prepared, stored, digest)
            except PublicOperationError:
                raise
            except (asyncio.CancelledError, Exception) as exc:
                from yoetz.observability.logging import record_unexpected_exception_without_raising

                correlation_id = record_unexpected_exception_without_raising(
                    exc,
                    component="application.publish_work",
                    operation="publish_work_internal_result_failed",
                    request_id=request.request_id,
                )
                try:
                    return accepted_projection_unavailable_from_append(
                        request,
                        runtime,
                        stored,
                        correlation_id=correlation_id,
                    )
                except (asyncio.CancelledError, Exception) as envelope_exc:
                    record_unexpected_exception_without_raising(
                        envelope_exc,
                        component="application.publish_work",
                        operation="publish_work_accepted_envelope_failed",
                        request_id=request.request_id,
                    )
                    raise _error(
                        PublicErrorCode.OPERATION_PENDING,
                        (
                            "The event batch was accepted, but its response could not be "
                            "assembled. Retry with the same request_id to load the stored "
                            "result, or read status view=operation."
                        ),
                        retryable=True,
                        reason_code="response_projection_failed",
                    ) from envelope_exc

        # No prior operation: ordinary publish path. Body validation and expected_frontier apply.
        prepared = prepare_publication(request, channel=channel, app=app)
        _validate_new_completion_scope(request, prepared)
        commitments, digest = await _commitments_and_digest(runtime, request, prepared)
        refs: list[ObjectRef] = []
        entries: list[AppendEntry] = []
        staged_objects: list[StagedObject] = []
        try:
            for item, commitment in zip(prepared.drafts, commitments, strict=True):
                metadata = ObjectMetadata(
                    ObjectKind.EVENT_PAYLOAD,
                    media_type_for(item.draft.schema.name),
                    runtime.task_id,
                    app.clock.now_utc(),
                )
                staged = await runtime.objects.stage(
                    ObjectSource(data=item.payload_bytes, declared_size=len(item.payload_bytes)),
                    metadata,
                )
                staged_objects.append(staged)
                if staged.commitment != commitment:
                    raise _error(
                        PublicErrorCode.STORAGE_CORRUPT,
                        "The staged object commitment is inconsistent.",
                    )
                ref = await runtime.objects.finalize(staged)
                refs.append(ref)
                entries.append(
                    AppendEntry(
                        item.draft,
                        prepared.author,
                        ref,
                        commitment,
                        metadata.media_type,
                        ref.plaintext_size,
                        prepared.channel,
                        prepared.coverage,
                        item.projection_status,
                    )
                )
            expected_frontier = (
                None
                if request.expected_frontier is None
                else int(request.expected_frontier.sequence)
            )
            command = AppendCommand(
                runtime.task_id,
                runtime.session_id,
                cast(str, runtime.writer_id),
                request.request_id,
                OperationKind.PUBLISH_WORK,
                digest,
                expected_frontier,
                tuple(entries),
            )
            mutation = PreparedMutation(
                command.writer_id,
                command.operation_id,
                command.request_digest,
                command.expected_frontier,
                tuple(refs),
                command,
            )
        except BaseException:
            await abandon_preappend_objects(
                runtime.objects,
                tuple(staged_objects),
                component="application.publish_work",
                operation="publish_work_object_abandon_failed",
                request_id=request.request_id,
            )
            raise
        try:
            append_result = await run_prepared_append(runtime.ledger, mutation)
        except PreSubmissionCancelled:
            await abandon_preappend_objects(
                runtime.objects,
                tuple(staged_objects),
                component="application.publish_work",
                operation="publish_work_object_abandon_failed",
                request_id=request.request_id,
            )
            raise
        # The batch is durable from here on. Bounded PublicOperationError values (STORAGE_CORRUPT
        # and friends) stay exactly as raised because they already describe the stored state
        # truthfully. Only an unexpected failure falls back to the reduced total-acceptance
        # envelope so assembling the full closed model can never present an accepted write as a
        # failure.
        try:
            return await _internal_result(request, runtime, prepared, append_result, digest)
        except PublicOperationError:
            raise
        except (asyncio.CancelledError, Exception) as exc:
            # CancelledError is BaseException, not Exception. Cancellation after a durable append
            # must not surface as request_cancelled — the write already landed.
            from yoetz.observability.logging import record_unexpected_exception_without_raising

            correlation_id = record_unexpected_exception_without_raising(
                exc,
                component="application.publish_work",
                operation="publish_work_internal_result_failed",
                request_id=request.request_id,
            )
            try:
                return accepted_projection_unavailable_from_append(
                    request,
                    runtime,
                    append_result,
                    correlation_id=correlation_id,
                )
            except (asyncio.CancelledError, Exception) as envelope_exc:
                # Genuinely impossible for a committed AppendResult: every accepted summary already
                # carries the three structural fields the reduced envelope needs. Keep the legacy
                # retryable reason only if even that construction fails.
                record_unexpected_exception_without_raising(
                    envelope_exc,
                    component="application.publish_work",
                    operation="publish_work_accepted_envelope_failed",
                    request_id=request.request_id,
                )
                raise _error(
                    PublicErrorCode.OPERATION_PENDING,
                    (
                        "The event batch was accepted, but its response could not be assembled. "
                        "Retry with the same request_id to load the stored result, or read "
                        "status view=operation."
                    ),
                    retryable=True,
                    reason_code="response_projection_failed",
                ) from envelope_exc
    finally:
        await app.runtime.release(runtime)
