"""Record an attributable response to one immutable finding version."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, Literal, Protocol, cast

from yoetz.application.ledger_snapshot import projection_for_records
from yoetz.application.unit_of_work import PreparedMutation, run_prepared_append
from yoetz.domain.events import (
    RESPONSE_EVENT_SCHEMA_VERSION,
    CheckRecordedPayload,
    EventDraft,
    EventSchema,
    LedgerRecord,
    ResponseRecordedPayload,
    encode_payload,
    media_type_for,
)
from yoetz.domain.findings import (
    TERMINAL_RESPONSE_DISPOSITIONS,
    Finding,
    FindingKind,
    FindingOrigin,
    ResponseDisposition,
    WaiverScope,
)
from yoetz.domain.values import (
    Actor,
    ActorType,
    Frontier,
    actor_id,
    event_id,
    evidence_id,
    finding_id,
    frontier_from_json,
    result_id,
    timestamp_from_datetime,
    timestamp_from_string,
)
from yoetz.kernel.finding_todo import TERMINAL_TODO_STATES, finding_todo_state
from yoetz.kernel.projections import FindingProjectionRecord, ProjectionState
from yoetz.kernel.self_verification import FINDING_NOT_RECHECKED, self_verification_refusal
from yoetz.ports.clock import ClockPort
from yoetz.ports.diagnostics import RuntimeCapability
from yoetz.ports.ids import IdPort
from yoetz.ports.ledger import (
    AcceptedEventSummary,
    AppendCommand,
    AppendEntry,
    AppendResult,
    AppendWarning,
    OperationKind,
    OperationState,
)
from yoetz.ports.objects import ObjectKind, ObjectMetadata, ObjectSource
from yoetz.ports.runtime import BundleRuntimePort, RouteAccess, RouteCommand, TaskRuntime
from yoetz.protocol.canonical import (
    JsonValue,
    canonical_encode,
    request_digest,
    strict_json_parse,
)
from yoetz.protocol.coverage import (
    Coverage,
    PublicationChannel,
    coverage_for_channel,
    coverage_to_json,
)
from yoetz.protocol.errors import ProtocolValueError, PublicErrorCode, PublicOperationError
from yoetz.protocol.ids import IdKind
from yoetz.protocol.models import (
    RespondAcceptedEventModel,
    RespondEvidenceSummaryModel,
    RespondRequest,
    RespondResponseModel,
    SemanticReason,
    SemanticStatus,
)
from yoetz.protocol.policy_packs import (
    RESEARCH_EVIDENCE_POLICY_ID,
    WORK_INTEGRITY_POLICY_ID,
    current_policy_pack,
)

__all__ = ["Application", "RespondInternalResult", "execute_respond"]

_POLICY_PACKS = (
    current_policy_pack(RESEARCH_EVIDENCE_POLICY_ID),
    current_policy_pack(WORK_INTEGRITY_POLICY_ID),
)


class Application(Protocol):
    runtime: BundleRuntimePort
    clock: ClockPort
    ids: IdPort
    waiver_policy_digest: str

    def authorizes_waiver(self, request: RespondRequest) -> bool: ...


@dataclass(frozen=True, slots=True)
class RespondInternalResult:
    protocol_version: Literal["0.1"]
    schema_version: Literal["1.0.0"]
    request_id: str
    ok: Literal[True]
    task_id: str
    session_id: str
    writer_id: str
    subject_frontier: Frontier
    result_frontier: Frontier
    accepted_event: RespondAcceptedEventModel
    response: RespondResponseModel
    coverage: Coverage
    warning_codes: tuple[Literal["waiver_expired_at_recording"], ...]
    engine_version: str
    projection_version: str

    def as_json(self) -> dict[str, JsonValue]:
        return {
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "request_id": self.request_id,
            "ok": self.ok,
            "task_id": self.task_id,
            "session_id": self.session_id,
            "writer_id": self.writer_id,
            "subject_frontier": dict(self.subject_frontier.as_wire().items()),
            "result_frontier": dict(self.result_frontier.as_wire().items()),
            "accepted_event": cast(JsonValue, self.accepted_event.model_dump(mode="json")),
            # ``RespondResponseModel.optional_non_null_fields`` (reason/waiver_scope/waiver_expiry)
            # must be entirely omitted from the wire when absent, never present as an explicit
            # null; ``_ClosedModel`` rejects a reflexive re-validation otherwise (for example
            # when this internal JSON is later projected for an ordinary client).
            "response": cast(JsonValue, self.response.model_dump(mode="json", exclude_none=True)),
            "coverage": coverage_to_json(self.coverage),
            "warning_codes": self.warning_codes,
            "versions": {
                "protocol_version": "0.1",
                "engine_version": self.engine_version,
                "projection_version": self.projection_version,
                "policy_packs": _POLICY_PACKS,
            },
        }


def _error(
    code: PublicErrorCode,
    message: str,
    *,
    retryable: bool = False,
    reason_code: str | None = None,
    field: str | None = None,
) -> PublicOperationError:
    details: dict[str, str] = {}
    if reason_code is not None:
        details["reason_code"] = reason_code
    if field is not None:
        details["field"] = field
    return PublicOperationError(code, message, retryable, safe_details=details or None)


def _mapping(value: JsonValue) -> Mapping[str, JsonValue]:
    if not isinstance(value, Mapping):
        raise ProtocolValueError("stored_result_shape_invalid")
    source = cast(Mapping[object, object], value)
    if any(type(key) is not str for key in source):
        raise ProtocolValueError("stored_result_shape_invalid")
    return cast(Mapping[str, JsonValue], source)


def _decode_append_result(data: bytes) -> AppendResult:
    try:
        source = _mapping(strict_json_parse(data))
        if frozenset(source) != frozenset(
            {"accepted", "subject_frontier", "result_frontier", "warnings"}
        ):
            raise ProtocolValueError("stored_result_shape_invalid")
        accepted_raw = source["accepted"]
        warnings_raw = source["warnings"]
        if type(accepted_raw) not in {tuple, list} or type(warnings_raw) not in {tuple, list}:
            raise ProtocolValueError("stored_result_shape_invalid")
        accepted = tuple(
            AcceptedEventSummary(
                cast(str, item["event_id"]),
                int(cast(str, item["ingestion_sequence"])),
                int(cast(str, item["writer_sequence"])),
                cast(str, item["entry_digest"]),
                cast(Literal["projected", "unknown_unprojected"], item["projection_status"]),
            )
            for item in (
                _mapping(value)
                for value in cast(tuple[JsonValue, ...] | list[JsonValue], accepted_raw)
            )
        )
        warnings = tuple(
            sorted(
                (
                    AppendWarning(cast(str, value))
                    for value in cast(tuple[JsonValue, ...] | list[JsonValue], warnings_raw)
                ),
                key=lambda item: item.value.encode("ascii"),
            )
        )
        return AppendResult(
            "replayed",
            accepted,
            frontier_from_json(source["subject_frontier"]),
            frontier_from_json(source["result_frontier"]),
            warnings,
        )
    except (TypeError, ValueError) as exc:
        raise _error(PublicErrorCode.STORAGE_CORRUPT, "The stored response is invalid.") from exc


def _channel(request: RespondRequest) -> PublicationChannel:
    try:
        return PublicationChannel(request.client.integration.value)
    except ValueError as exc:
        raise _error(PublicErrorCode.INVALID_REQUEST, "The response channel is invalid.") from exc


def _identity(request: RespondRequest, *, policy_digest: str) -> JsonValue:
    return cast(
        JsonValue,
        {
            "protocol_version": request.protocol_version,
            "schema_version": request.schema_version,
            "request_id": request.request_id,
            "session_id": request.session_id,
            "writer_id": request.writer_id,
            "expected_frontier": request.expected_frontier.model_dump(mode="json"),
            "finding_id": request.finding_id,
            "finding_frontier": request.finding_frontier.model_dump(mode="json"),
            "disposition": request.disposition,
            "reason": request.reason,
            "waiver_scope": request.waiver_scope,
            "waiver_expiry": request.waiver_expiry,
            "evidence_refs": () if request.evidence_refs is None else request.evidence_refs,
            "actor": {
                "actor_id": request.actor.actor_id,
                "actor_type": request.actor.actor_type.value,
            },
            "client": {
                "integration": request.client.integration.value,
                "kind": request.client.kind.value,
                "version": request.client.version,
            },
            "waiver_policy_digest": policy_digest,
        },
    )


async def _preflight(
    runtime: TaskRuntime, request: RespondRequest, digest: str
) -> AppendResult | None:
    operation = await runtime.ledger.lookup_operation(request.writer_id, request.request_id)
    if operation is None:
        return None
    if operation.request_digest != digest or operation.operation_kind is not OperationKind.RESPOND:
        raise _error(PublicErrorCode.IDEMPOTENCY_CONFLICT, "The request ID was already used.")
    if operation.state is OperationState.COMPLETE:
        assert operation.result_canonical is not None
        return _decode_append_result(operation.result_canonical)
    if operation.state is OperationState.QUARANTINED:
        raise _error(PublicErrorCode.STORAGE_CORRUPT, "The response operation is quarantined.")
    raise _error(
        PublicErrorCode.OPERATION_PENDING,
        "The response operation is pending.",
        retryable=True,
    )


# Yoetz's own check and finding records (issue #906, open design question 3). A reviewer finding
# whose every subject is one of these is about Yoetz's process state, never about the work itself.
# ``response_recorded`` is deliberately absent: an agent's answer to a finding is the agent's own
# content, and a finding about its substance keeps the resolution-attempt gate.
_PROCESS_RECORD_SCHEMAS: Final = frozenset({"check_recorded", "finding_recorded"})
# The only finding kind that describes the state of the record rather than the work, and the only
# one that never blocks a receipt (``FINDING_KIND_TRAITS`` marks it non-actionable). A reviewer can
# cite an earlier check row while challenging what that check established about the work, so the
# cited rows alone never make a finding process-only: the kind has to say so too.
_PROCESS_FINDING_KINDS: Final = frozenset({FindingKind.LEDGER_STALE_OR_INCOMPLETE})


def _process_finding_answered_by_completed_review(
    records: tuple[LedgerRecord, ...], finding: FindingProjectionRecord
) -> bool:
    """Whether a completed later review is the resolution of a finding about Yoetz process state.

    A finding that asks for the review that already ran, or that is about check or finding
    records, has nothing to repair: requiring a fresh resolution attempt before
    ``acknowledged`` only produced a filler publish round (issue #906). The exception is structural
    and deliberately narrow. The finding's kind must describe record state
    (``_PROCESS_FINDING_KINDS``), every subject must be an event whose recorded schema is a Yoetz
    process record, and an AI-powered review that completed must be recorded after the finding.
    Citing a check row is not enough on its own: a work kind such as ``diff_does_not_match_account``
    that cites only a check still challenges the work. A cited finding record counts only when that
    earlier finding is itself, transitively, of a process kind and about process records alone: a
    restatement of a finding about the work is about the work, so it can never be easier to
    acknowledge than the finding it restates. A finding naming any obligation, claim, or work
    record keeps the ``resolution_attempt_required`` gate, because structure alone cannot tell an
    obligation to obtain a review from a work obligation.
    """

    payload = finding.payload
    if payload is None or payload.kind not in _PROCESS_FINDING_KINDS or not payload.subject_refs:
        return False
    by_event = {str(record.event_id): record for record in records}
    pending = [str(ref) for ref in payload.subject_refs]
    seen: set[str] = set()
    while pending:
        ref = pending.pop()
        if ref in seen:
            continue
        seen.add(ref)
        subject = by_event.get(ref) if ref.startswith("evt_") else None
        if subject is None or subject.schema.name not in _PROCESS_RECORD_SCHEMAS:
            return False
        if subject.schema.name == "finding_recorded":
            # An unreadable, redacted or unknown-version finding record cannot prove its subject.
            cited = subject.payload
            if (
                type(cited) is not Finding
                or cited.kind not in _PROCESS_FINDING_KINDS
                or not cited.subject_refs
            ):
                return False
            pending.extend(str(item) for item in cited.subject_refs)
    return any(
        type(record.payload) is CheckRecordedPayload
        and record.payload.semantic_status is SemanticStatus.SUCCEEDED
        and record.payload.semantic_reason is SemanticReason.SEMANTIC_COMPLETED
        and record.ledger.ingestion_sequence > finding.source_frontier
        for record in records
    )


def _admit_self_verification(
    request: RespondRequest,
    projection: ProjectionState,
    records: tuple[LedgerRecord, ...],
) -> None:
    """Admit a ``self_verified`` answer only for a rechecked, proof-limited finding (issue #984).

    The agent says how it verified the repair (``reason``) and cites its own recorded evidence
    (``evidence_refs``, checked as recorded ids by the caller). Eligibility is
    ``kernel/self_verification.py``'s replay-derived predicate over recorded checks; this never
    reads response prose and never resolves the finding.
    """

    if request.reason is None or not request.reason.strip():
        raise _error(
            PublicErrorCode.INVALID_REQUEST,
            "self_verified requires a non-empty reason: say how you verified the repair.",
            reason_code="response_fields_invalid",
            field="/reason",
        )
    if not request.evidence_refs:
        raise _error(
            PublicErrorCode.INVALID_REQUEST,
            (
                "self_verified requires at least one evidence_refs id: record the evidence of "
                "your own verification with publish_work first, then cite its evd_ or res_ id."
            ),
            reason_code="response_fields_invalid",
            field="/evidence_refs",
        )
    refusal = self_verification_refusal(projection, finding_id(request.finding_id), records)
    if refusal == FINDING_NOT_RECHECKED:
        raise _error(
            PublicErrorCode.INVALID_REQUEST,
            (
                "No check has tested this finding since it was recorded. Repair it first, then "
                "run check; respond self_verified only if that check still cannot prove the "
                "repair because of a Yoetz limit."
            ),
            reason_code=FINDING_NOT_RECHECKED,
            field="/finding_id",
        )
    if refusal is not None:
        raise _error(
            PublicErrorCode.INVALID_REQUEST,
            (
                "Yoetz's newest check of this finding still sees it or names work you can do "
                "(the rule fired again, a review without a packet limit ruled it still present, "
                "nothing changed since the finding, or the check did not cover it), so this is "
                "not a Yoetz limit. Repair it and check again; respond rejected with a reason if "
                "the finding is wrong; respond acknowledged_not_done only if you truly will not "
                "or cannot do it. status view=findings shows the unmet requirements."
            ),
            reason_code=refusal,
            field="/finding_id",
        )


async def _records_through(
    runtime: TaskRuntime, frontier: Frontier
) -> tuple[tuple[LedgerRecord, ...], ProjectionState]:
    records = tuple(
        [
            record
            async for record in runtime.ledger.load_events(
                runtime.session_id, through=frontier.sequence
            )
        ]
    )
    try:
        projection = await projection_for_records(
            runtime.ledger, runtime.session_id, frontier, records
        )
    except ValueError as exc:
        # Replay is genesis-anchored; a chain it rejects is a storage fact, not an engine bug, so
        # it leaves here as a bounded public error rather than an unbounded internal one.
        raise _error(PublicErrorCode.STORAGE_CORRUPT, "The task ledger is unreadable.") from exc
    if Frontier(projection.frontier, projection.head_digest) != frontier:
        raise _error(PublicErrorCode.FRONTIER_CONFLICT, "The response frontier is not current.")
    return records, projection


def _finding_from_current_prefix(
    current_records: tuple[LedgerRecord, ...],
    current_projection: ProjectionState,
    finding_frontier: Frontier,
    raw_finding_id: str,
) -> FindingProjectionRecord | None:
    """Read the finding at ``finding_frontier`` from the current projection without a replay.

    ``current_records`` is the hash-chained prefix the current projection was authenticated
    against. When the record at ``finding_frontier.sequence`` carries exactly that head digest,
    the finding frontier is an in-chain prefix of the current one. A finding whose source event is
    at or before that prefix, and whose payload is still present, is the same immutable payload
    the prefix replay would yield. Anything else (a later re-record, redaction, or a foreign
    frontier) returns ``None`` so the caller keeps the genesis-replay path (issue #886).
    """

    sequence = finding_frontier.sequence
    if not 0 < sequence <= len(current_records):
        return None
    anchor = current_records[sequence - 1]
    if (
        anchor.ledger.ingestion_sequence != sequence
        or anchor.entry_digest != finding_frontier.head_digest
    ):
        return None
    try:
        record = current_projection.findings.get(finding_id(raw_finding_id))
    except ValueError:
        return None
    if record is None or record.payload is None or record.source_frontier > sequence:
        return None
    return record


async def _accepted_record(runtime: TaskRuntime, result: AppendResult) -> LedgerRecord:
    if len(result.accepted) != 1:
        raise _error(PublicErrorCode.STORAGE_CORRUPT, "The response event range is invalid.")
    summary = result.accepted[0]
    records = tuple(
        [
            record
            async for record in runtime.ledger.load_events(
                runtime.session_id,
                after=summary.ingestion_sequence - 1,
                through=summary.ingestion_sequence,
            )
        ]
    )
    if len(records) != 1:
        raise _error(PublicErrorCode.STORAGE_CORRUPT, "The response event range is invalid.")
    record = records[0]
    if (
        str(record.event_id) != summary.event_id
        or record.writer.sequence != summary.writer_sequence
        or record.entry_digest != summary.entry_digest
        or record.schema.name != "response_recorded"
        or type(record.payload) is not ResponseRecordedPayload
    ):
        raise _error(PublicErrorCode.STORAGE_CORRUPT, "The response event range is invalid.")
    return record


async def _public_result(
    request: RespondRequest,
    runtime: TaskRuntime,
    result: AppendResult,
) -> RespondInternalResult:
    record = await _accepted_record(runtime, result)
    payload = cast(ResponseRecordedPayload, record.payload)
    evidence = tuple(RespondEvidenceSummaryModel(reference_id=ref) for ref in payload.evidence_refs)
    response_wire: dict[str, object] = {
        "response_event_id": record.event_id,
        "finding_id": payload.finding_id,
        "finding_frontier": dict(payload.finding_frontier.as_wire().items()),
        "disposition": payload.disposition.value,
        "evidence": evidence,
    }
    if payload.reason is not None:
        response_wire["reason"] = payload.reason
    if payload.waiver_scope is not None:
        response_wire["waiver_scope"] = payload.waiver_scope.value
    if payload.waiver_expiry is not None:
        response_wire["waiver_expiry"] = payload.waiver_expiry.wire
    response = RespondResponseModel.model_validate(response_wire)
    warning_codes: tuple[Literal["waiver_expired_at_recording"], ...] = ()
    if (
        payload.waiver_expiry is not None
        and payload.waiver_expiry.wire < record.ledger.accepted_at.wire
    ):
        warning_codes = ("waiver_expired_at_recording",)
    return RespondInternalResult(
        "0.1",
        "1.0.0",
        request.request_id,
        True,
        runtime.task_id,
        runtime.session_id,
        cast(str, runtime.writer_id),
        result.subject_frontier,
        result.result_frontier,
        RespondAcceptedEventModel(
            event_id=record.event_id,
            writer_sequence=str(record.writer.sequence),
            ingestion_sequence=str(record.ledger.ingestion_sequence),
            accepted_at=record.ledger.accepted_at.wire,
            entry_digest=record.entry_digest,
        ),
        response,
        record.coverage,
        warning_codes,
        runtime.engine_version,
        runtime.projection_version,
    )


async def execute_respond(app: Application, request: RespondRequest) -> RespondInternalResult:
    """Validate, object-publish, and atomically append one ``response_recorded`` event."""

    runtime = await app.runtime.route(
        RouteCommand(
            request.session_id,
            request.writer_id,
            RouteAccess.WRITE,
            frozenset({RuntimeCapability.WRITE, RuntimeCapability.PAYLOAD_READ}),
        )
    )
    try:
        if runtime.session_id != request.session_id or runtime.writer_id != request.writer_id:
            raise _error(PublicErrorCode.SESSION_CONFLICT, "The writer route is inconsistent.")
        if request.disposition == "waived" and (
            request.client.integration.value != "local_cli"
            or request.actor.actor_type.value != "human"
            or not app.authorizes_waiver(request)
        ):
            raise _error(PublicErrorCode.INVALID_REQUEST, "The waiver is not authorized.")
        digest = request_digest(_identity(request, policy_digest=app.waiver_policy_digest))
        result = await _preflight(runtime, request, digest)
        if result is None:
            finding_frontier = Frontier(
                int(request.finding_frontier.sequence), request.finding_frontier.head_digest
            )
            current = Frontier(
                int(request.expected_frontier.sequence), request.expected_frontier.head_digest
            )
            current_records, current_projection = await _records_through(runtime, current)
            finding_record = _finding_from_current_prefix(
                current_records, current_projection, finding_frontier, request.finding_id
            )
            if finding_record is None:
                _finding_records, finding_projection = await _records_through(
                    runtime, finding_frontier
                )
                finding_record = finding_projection.findings.get(finding_id(request.finding_id))
            if finding_record is None or finding_record.payload is None:
                raise _error(
                    PublicErrorCode.INVALID_REQUEST,
                    (
                        "The finding is unavailable at the supplied frontier. finding_frontier may "
                        "be any frontier at or after the finding's own record: the finding's "
                        "finding_frontier from status view=findings when present, or the current "
                        "status frontier. No historical frontier search is needed. The finding's "
                        "subject_frontier precedes its record and is rejected."
                    ),
                    reason_code="finding_not_in_prefix",
                    field="finding_frontier",
                )
            todo = finding_todo_state(current_projection, finding_id(request.finding_id))
            if todo in TERMINAL_TODO_STATES:
                # Issue #905: a terminal item is final. Nothing is recorded, so a repeat is an
                # idempotent no-op; new evidence about the same problem becomes a new finding.
                raise _error(
                    PublicErrorCode.INVALID_REQUEST,
                    (
                        f"The finding is already {todo.value}; that state is final and nothing "
                        "was recorded. New evidence about the same problem is raised by a later "
                        "check as a new finding."
                    ),
                    reason_code="finding_terminal",
                    field="/finding_id",
                )
            if request.disposition == "acknowledged_not_done" and (
                request.reason is None or not request.reason.strip()
            ):
                raise _error(
                    PublicErrorCode.INVALID_REQUEST,
                    "acknowledged_not_done requires a non-empty reason.",
                    reason_code="response_fields_invalid",
                    field="/reason",
                )
            if request.disposition == "self_verified":
                _admit_self_verification(request, current_projection, current_records)
            reviewer_finding = finding_record.payload.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED
            reasoned = request.reason is not None and bool(request.reason.strip())
            if request.disposition == "acknowledged" and reviewer_finding and not reasoned:
                # Issue #976: the next review carries this answer to the reviewer. A bare
                # acknowledgement gave it nothing to evaluate (352 of 365 TB4 answers).
                raise _error(
                    PublicErrorCode.INVALID_REQUEST,
                    (
                        "Acknowledging an AI-powered review finding requires a non-empty reason: "
                        "say what you changed or verified, or answer the reviewer's question. "
                        "The next review reads it."
                    ),
                    reason_code="response_fields_invalid",
                    field="/reason",
                )
            question = (
                reviewer_finding
                and finding_record.payload.challenge is not None
                and finding_record.payload.challenge.requested_next_step == "answer_question"
            )
            attempted = False
            for ref in () if request.evidence_refs is None else request.evidence_refs:
                present = (
                    current_projection.evidence.get(evidence_id(ref))
                    if ref.startswith("evd_")
                    else current_projection.results.get(result_id(ref))
                )
                if present is None or present.payload is None:
                    raise _error(
                        PublicErrorCode.INVALID_REQUEST, "A response reference is invalid."
                    )
                # "After the finding" means after the finding's own record, not after whichever
                # in-chain frontier the caller chose to name it by: any frontier at or after the
                # record is accepted, including the current status frontier (issue #911).
                attempted = attempted or present.source_frontier > finding_record.source_frontier
            if (
                request.disposition == "acknowledged"
                and reviewer_finding
                and not question
                and not attempted
                and not _process_finding_answered_by_completed_review(
                    current_records, finding_record
                )
            ):
                # Issue #885: accepting a reviewer finding (including as an unresolved limitation)
                # needs one recorded concrete resolution attempt after the finding. A recorded
                # failed or blocked result naming an authority blocker also counts. Disputes keep
                # their own dispositions; acknowledgement still never resolves the finding.
                raise _error(
                    PublicErrorCode.INVALID_REQUEST,
                    (
                        "Acknowledging an AI-powered review finding requires one concrete "
                        "resolution attempt recorded after the finding. Publish the repair, "
                        "requested evidence, or verification result (a failed or blocked result "
                        "naming the exact authority blocker also counts), then cite it in "
                        "evidence_refs. Use rejected or provenance_disputed to dispute it."
                    ),
                    reason_code="resolution_attempt_required",
                    field="/evidence_refs",
                )
            coverage = coverage_for_channel(_channel(request))
            payload = ResponseRecordedPayload(
                finding_id(request.finding_id),
                finding_frontier,
                ResponseDisposition(request.disposition),
                request.reason,
                None if request.waiver_scope is None else WaiverScope(request.waiver_scope),
                None
                if request.waiver_expiry is None
                else timestamp_from_string(request.waiver_expiry),
                tuple(
                    evidence_id(ref) if ref.startswith("evd_") else result_id(ref)
                    for ref in (() if request.evidence_refs is None else request.evidence_refs)
                ),
            )
            now = app.clock.now_utc()
            draft = EventDraft(
                event_id(app.ids.new(IdKind.EVENT)),
                EventSchema(
                    "response_recorded",
                    RESPONSE_EVENT_SCHEMA_VERSION
                    if payload.disposition in TERMINAL_RESPONSE_DISPOSITIONS
                    else "1.0.0",
                ),
                timestamp_from_datetime(now),
                (finding_record.source_event_id,),
                payload,
                (),
                payload.evidence_refs,
            )
            payload_bytes = canonical_encode(encode_payload(payload))
            metadata = ObjectMetadata(
                ObjectKind.EVENT_PAYLOAD,
                media_type_for("response_recorded"),
                runtime.task_id,
                now,
            )
            staged = await runtime.objects.stage(
                ObjectSource(data=payload_bytes, declared_size=len(payload_bytes)), metadata
            )
            ref = await runtime.objects.finalize(staged)
            author = Actor(
                actor_id(request.actor.actor_id),
                ActorType(request.actor.actor_type.value),
                coverage.authorship_assurance,
            )
            command = AppendCommand(
                runtime.task_id,
                runtime.session_id,
                cast(str, runtime.writer_id),
                request.request_id,
                OperationKind.RESPOND,
                digest,
                current.sequence,
                (
                    AppendEntry(
                        draft,
                        author,
                        ref,
                        ref.commitment,
                        metadata.media_type,
                        ref.plaintext_size,
                        _channel(request),
                        coverage,
                        "projected",
                    ),
                ),
            )
            result = await run_prepared_append(
                runtime.ledger,
                PreparedMutation(
                    cast(str, runtime.writer_id),
                    request.request_id,
                    digest,
                    current.sequence,
                    (ref,),
                    command,
                ),
            )
        return await _public_result(request, runtime, result)
    except ProtocolValueError as exc:
        raise _error(PublicErrorCode.INVALID_REQUEST, "The response request is invalid.") from exc
    finally:
        await app.runtime.release(runtime)
