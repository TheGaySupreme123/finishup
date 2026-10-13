"""Record an attributable response to one immutable finding version."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
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
    RESPONSE_V1_1_DISPOSITIONS,
    Finding,
    FindingKind,
    FindingOrigin,
    ResponseDisposition,
    WaiverScope,
    is_limitation_request,
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
from yoetz.kernel.finding_resolution import next_standing_position
from yoetz.kernel.finding_todo import (
    ABSOLUTELY_FINAL_TODO_STATES,
    REOPENABLE_TODO_STATES,
    FindingTodoState,
    duplicate_link_target,
    finding_todo_state,
)
from yoetz.kernel.limitation import limitation_standing
from yoetz.kernel.projections import FindingProjectionRecord, ProjectionRecord, ProjectionState
from yoetz.kernel.self_verification import (
    FINDING_NOT_RECHECKED,
    self_verification_blocking_reasons,
    self_verification_refusal,
)
from yoetz.kernel.task_fact_scope import (
    COMMAND_ATTEMPT_MISMATCH_GAP,
    CommandMismatch,
    command_mismatches,
    command_mismatches_for_finding,
)
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
    canonical_digest,
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
    RespondClosureAfterModel,
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
    # tb4n3 RC-7: where the finding stands once this answer is recorded (``None`` on an
    # idempotent replay, which recomputes nothing).
    closure_after: RespondClosureAfterModel | None = None

    def as_json(self) -> dict[str, JsonValue]:
        document: dict[str, JsonValue] = {
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
        if self.closure_after is not None:
            document["closure_after"] = cast(
                JsonValue, self.closure_after.model_dump(mode="json", exclude_none=True)
            )
        return document


def _error(
    code: PublicErrorCode,
    message: str,
    *,
    retryable: bool = False,
    reason_code: str | None = None,
    field: str | None = None,
    blocking_reasons: tuple[str, ...] = (),
) -> PublicOperationError:
    details: dict[str, str | tuple[str, ...]] = {}
    if reason_code is not None:
        details["reason_code"] = reason_code
    if field is not None:
        details["field"] = field
    if blocking_reasons:
        details["blocking_reasons"] = blocking_reasons
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
    identity: dict[str, object] = {
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
    }
    # Issue #996: present only when set, so every earlier request keeps its exact digest.
    if request.duplicate_of_finding_id is not None:
        identity["duplicate_of_finding_id"] = request.duplicate_of_finding_id
    return cast(JsonValue, identity)


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


_MAX_NAMED_EARLY_REFS: Final = 8


def _resolution_attempt_required_message(
    finding_sequence: int, cited_before: tuple[str, ...]
) -> str:
    """Say which citation is missing for an acknowledgement, naming only structural ids.

    tb4n1: 14 acknowledgements were refused with one fixed sentence. Most cited nothing in
    evidence_refs (the repair was described in ``reason`` or named there by id); others cited only
    evidence recorded before the finding. The two need different repairs, so the message names the
    finding's ledger sequence and, when present, the cited ids that predate it. ``reason`` is never
    echoed.
    """

    if cited_before:
        named = ", ".join(cited_before[:_MAX_NAMED_EARLY_REFS])
        more = len(cited_before) - _MAX_NAMED_EARLY_REFS
        suffix = f" and {more} more" if more > 0 else ""
        lead = (
            "Acknowledging an AI-powered review finding requires one concrete resolution attempt "
            f"recorded after the finding (ledger sequence {finding_sequence}). Every cited "
            f"evidence_refs id was recorded at or before it: {named}{suffix}."
        )
    else:
        lead = (
            "Acknowledging an AI-powered review finding requires one concrete resolution attempt "
            f"recorded after the finding (ledger sequence {finding_sequence}), cited in "
            "evidence_refs; ids named only in reason do not count."
        )
    return (
        f"{lead} Publish the repair, requested evidence, or verification result (a failed or "
        "blocked result naming the exact authority blocker also counts) with publish_work, then "
        "retry with its evd_ or res_ id in evidence_refs and a new request_id. Use rejected or "
        "provenance_disputed to dispute it."
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
        blocking = self_verification_blocking_reasons(
            projection, finding_id(request.finding_id), records
        )
        # tb4n5 (#1049): a mismatch refusal names the obligation, the requested item and the run
        # it is linked to, so the link the continuation asks for can be published without a hunt.
        mismatches = (
            command_mismatches_for_finding(
                projection,
                finding_id(request.finding_id),
                command_mismatches(projection, records),
            )
            if _MISMATCH_BLOCKING_REASON in blocking
            else ()
        )
        raise _error(
            PublicErrorCode.INVALID_REQUEST,
            self_verification_refusal_message(blocking, command_mismatches=mismatches),
            reason_code=refusal,
            field="/finding_id",
            blocking_reasons=blocking[:_MAX_NAMED_BLOCKING_REASONS],
        )


# tb4n2 R5 (issue #1023): a refusal names what disqualified the finding and the way out. The
# tokens are recorded resolution reasons (closed vocabulary), never response or finding prose.
_MAX_NAMED_BLOCKING_REASONS: Final = 32
_MAX_MESSAGE_REASONS: Final = 8
_BLOCKING_HINTS: Final[tuple[tuple[frozenset[str], str], ...]] = (
    (
        frozenset(
            {
                "issue_returned_again",
                "reviewer_verdict_still_present",
                "reviewer_verdict_answered_not_fixed",
            }
        ),
        "the check still sees the issue: repair it, then check",
    ),
    (
        frozenset({"no_material_change_since_finding"}),
        "nothing changed since the finding: repair it, then check",
    ),
    (
        frozenset(
            {
                "finding_not_in_checked_frontier",
                "matching_policy_not_completed",
                "subject_outside_checked_scope",
                "findings_suppressed",
                "check_unreadable",
                "returned_findings_unreadable",
                "semantic_review_not_completed",
            }
        ),
        "the check did not fully cover it: run a full check again",
    ),
    (
        frozenset({"coverage:completion_plan_not_claimed"}),
        "the completion claim must name every plan obligation not acknowledged as not done:"
        " finish and resolve the open ones before claiming them, and acknowledge the ones you"
        " will not do and leave those out of the claim",
    ),
    (
        frozenset(
            {
                "coverage:edited_after_last_verification",
                "coverage:planned_verification_stale",
                "coverage:planned_verification_not_observed",
                "coverage:planned_verification_failed",
            }
        ),
        "re-run your planned verification after your last edit, then check",
    ),
    (
        frozenset({"coverage:declared_output_emptied", "coverage:declared_output_removed"}),
        # ADR-045: the fact keys on the file, so acknowledging or republishing the obligation does
        # not clear it; `status` (readiness) says why it fired, with the earlier size it saw.
        "a declared deliverable that held content is empty, truncated or gone: restore it (status"
        " readiness says which and why), then check",
    ),
    (
        # tb4n4 kv (#1049): the agent looped on this code with only the generic coverage hint.
        frozenset({"coverage:command_attempt_mismatch"}),
        "a requested command item is linked to an observed run of another command: if a script"
        " or client ran the requested command, publish an action_recorded of kind"
        " command with that exact value in attempted_items and the run's action event id in"
        " causal_parents (disclosed as your equivalence), otherwise run it as recorded, then"
        " check; a command item is a shell command, so a message sent to the program under test"
        " belongs in the obligation's description or acceptance_criteria",
    ),
)


_MISMATCH_BLOCKING_REASON: Final = "coverage:" + COMMAND_ATTEMPT_MISMATCH_GAP
_MAX_NAMED_MISMATCHES: Final = 3
_MAX_NAMED_MISMATCH_IDS: Final = 2


def _mismatch_sentence(mismatches: tuple[CommandMismatch, ...]) -> str:
    """Which requested command item is mismatched, and the ids the repair link needs.

    Only ledger ids and item indexes are named, never the command text (which is the agent's).
    """

    if not mismatches:
        return ""
    rows: list[str] = []
    for row in mismatches[:_MAX_NAMED_MISMATCHES]:
        runs = ", ".join(row.observed_event_ids[:_MAX_NAMED_MISMATCH_IDS]) or "none"
        asserted = ", ".join(row.asserted_action_ids[:_MAX_NAMED_MISMATCH_IDS]) or "none"
        rows.append(
            f"{row.obligation_id} requested item {row.item_index} (asserted by {asserted};"
            f" linked observed run event {runs})"
        )
    hidden = len(mismatches) - _MAX_NAMED_MISMATCHES
    more = f" and {hidden} more (status view=obligations command_attempts)" if hidden > 0 else ""
    return (
        f" Mismatched: {'; '.join(rows)}{more}. The link needs three things: an action_recorded"
        " with action_kind command, attempted_items holding that item's exact value, and"
        " causal_parents naming the observed run event of the command that ran; or cite the"
        " result of an observed run of exactly that command in the obligation's"
        " resolution_evidence_refs."
    )


def self_verification_refusal_message(
    blocking: tuple[str, ...], *, command_mismatches: tuple[CommandMismatch, ...] = ()
) -> str:
    """The ``finding_not_proof_limited`` message: the disqualifying tokens and the exits.

    ``command_mismatches`` are the mismatched requested command items the finding bears on (only
    when ``coverage:command_attempt_mismatch`` refused it); they are named by id and index.
    """

    named = ", ".join(blocking[:_MAX_MESSAGE_REASONS])
    if len(blocking) > _MAX_MESSAGE_REASONS:
        named += f" and {len(blocking) - _MAX_MESSAGE_REASONS} more (safe_details.blocking_reasons)"
    hints = [
        hint for tokens, hint in _BLOCKING_HINTS if any(reason in tokens for reason in blocking)
    ]
    if any(reason.startswith("coverage:") for reason in blocking) and not any(
        reason in tokens for tokens, _hint in _BLOCKING_HINTS[3:] for reason in blocking
    ):
        hints.append("a listed coverage code is work you can do: clear it, then check")
    reasons_text = (
        f"Not a Yoetz limit: the newest check of this finding still lists {named}"
        if named
        else "Not a Yoetz limit: the newest check of this finding names no Yoetz limit"
    )
    hint_text = f" Next: {'; '.join(hints)}." if hints else ""
    mismatch_text = (
        _mismatch_sentence(command_mismatches) if _MISMATCH_BLOCKING_REASON in blocking else ""
    )
    return (
        f"{reasons_text}.{hint_text}{mismatch_text} If the finding asks for something you"
        " inherently cannot run (a hidden verifier, a private reference), that is not a Yoetz"
        " limit either: finish"
        " the work and disclose it with a decision line yoetz-verification-limit:<obligation id>."
        " When the reviewer's finding asks you to state that limit (a limitation request), that"
        " decision or one acknowledged response with a reason settles it as a verification limit"
        " (the requirement may be met but cannot be verified here): do not withdraw or empty"
        " working work over it. Respond rejected if the finding is wrong; acknowledged_not_done"
        " only if you truly will not or cannot do the work, and on a limitation request only when"
        " you know the requirement is not met (the receipt then keeps unresolved_findings_remain)."
        " Do not retry self_verified until a later check changes these reasons."
    )


# Issue #996 typed refusals of a ``duplicate_of`` answer.
DUPLICATE_TARGET_SAME_FINDING: Final = "duplicate_target_same_finding"
DUPLICATE_TARGET_UNKNOWN: Final = "duplicate_target_unknown"
DUPLICATE_TARGET_NOT_EARLIER: Final = "duplicate_target_not_earlier"
DUPLICATE_TARGET_IS_DUPLICATE: Final = "duplicate_target_is_duplicate"
DUPLICATE_LINK_BROKEN: Final = "duplicate_link_broken"
DUPLICATE_TARGET_DIFFERENT_ISSUE: Final = "duplicate_target_different_issue"
DUPLICATE_HAS_DUPLICATES: Final = "duplicate_has_duplicates"


def _admit_duplicate_link(
    request: RespondRequest,
    finding_record: FindingProjectionRecord,
    projection: ProjectionState,
) -> None:
    """Admit a ``duplicate_of`` link only for a genuine restatement (issue #996).

    The target must be a readable finding of this task, recorded earlier, with the same origin
    and kind (the same issue; a different kind is a different issue), and not itself linked; the
    refusal names the finding to link to instead. A finding that other findings already link to
    cannot become a duplicate itself, so no chain forms through a later link. A finding whose
    earlier link a later check broke needs its own answer and cannot be re-linked.
    """

    duplicate = finding_id(request.finding_id)
    finding_record = projection.findings.get(duplicate) or finding_record
    raw_target = request.duplicate_of_finding_id
    if raw_target is None:
        raise _error(
            PublicErrorCode.INVALID_REQUEST,
            "duplicate_of requires duplicate_of_finding_id: the earlier finding this one repeats.",
            reason_code="response_fields_invalid",
            field="/duplicate_of_finding_id",
        )
    target = finding_id(raw_target)
    if target == duplicate:
        raise _error(
            PublicErrorCode.INVALID_REQUEST,
            "A finding cannot be a duplicate of itself; name the earlier finding it repeats.",
            reason_code=DUPLICATE_TARGET_SAME_FINDING,
            field="/duplicate_of_finding_id",
        )
    if finding_record.duplicate_link_broken_by_check_event_ids:
        raise _error(
            PublicErrorCode.INVALID_REQUEST,
            (
                "A later check raised this finding's issue again after it was linked as a "
                "duplicate, so the link no longer applies and it cannot be linked again. Repair "
                "it and check, or answer it with another disposition."
            ),
            reason_code=DUPLICATE_LINK_BROKEN,
            field="/finding_id",
        )
    target_record = projection.findings.get(target)
    if target_record is None or target_record.payload is None:
        raise _error(
            PublicErrorCode.INVALID_REQUEST,
            (
                "The duplicate_of_finding_id is not a readable finding of this task. Name an "
                "earlier finding from status view=findings."
            ),
            reason_code=DUPLICATE_TARGET_UNKNOWN,
            field="/duplicate_of_finding_id",
        )
    if target_record.source_frontier >= finding_record.source_frontier:
        raise _error(
            PublicErrorCode.INVALID_REQUEST,
            (
                "The duplicate_of_finding_id was recorded after this finding. A duplicate link "
                "points back to the earlier finding; answer the later one as the duplicate."
            ),
            reason_code=DUPLICATE_TARGET_NOT_EARLIER,
            field="/duplicate_of_finding_id",
        )
    if (
        target_record.payload.origin is not cast(Finding, finding_record.payload).origin
        or target_record.payload.kind is not cast(Finding, finding_record.payload).kind
    ):
        raise _error(
            PublicErrorCode.INVALID_REQUEST,
            (
                "duplicate_of links only a restatement of the same issue: the earlier finding "
                "must have the same origin and kind. Answer this finding on its own."
            ),
            reason_code=DUPLICATE_TARGET_DIFFERENT_ISSUE,
            field="/duplicate_of_finding_id",
        )
    if any(
        other != duplicate and duplicate_link_target(projection, other) == duplicate
        for other in projection.findings
    ):
        raise _error(
            PublicErrorCode.INVALID_REQUEST,
            (
                "Other findings are linked as duplicates of this one, so it answers for them and "
                "cannot become a duplicate itself. Answer it on its own."
            ),
            reason_code=DUPLICATE_HAS_DUPLICATES,
            field="/finding_id",
        )
    root = duplicate_link_target(projection, target)
    if root is not None:
        raise _error(
            PublicErrorCode.INVALID_REQUEST,
            (
                "The duplicate_of_finding_id is itself linked as a duplicate of "
                f"{root}. Link to the finding that answers for it instead."
            ),
            reason_code=DUPLICATE_TARGET_IS_DUPLICATE,
            field="/duplicate_of_finding_id",
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


def _closure_after(
    projection: ProjectionState, payload: ResponseRecordedPayload, record: LedgerRecord
) -> RespondClosureAfterModel | None:
    """Where the finding stands once *payload* is recorded, from the same pure rules (RC-7).

    The pre-answer projection plus the new answer, folded with the reducer's own functions, so
    the answer and the next status can never disagree. Never raises: a committed answer is not
    failed over a diagnostic.
    """

    try:
        finding = projection.findings.get(payload.finding_id)
        if finding is None or finding.payload is None:
            return None
        sequence = record.ledger.ingestion_sequence
        answer = ProjectionRecord(
            payload=payload,
            payload_digest=canonical_digest(encode_payload(payload)),
            redacted=False,
            source_event_id=record.event_id,
            source_frontier=sequence,
        )
        updated = replace(
            finding,
            standing_position=next_standing_position(finding.standing_position, payload, sequence),
        )
        simulated = replace(
            projection,
            frontier=sequence,
            head_digest=record.entry_digest,
            findings={**projection.findings, payload.finding_id: updated},
            responses={**projection.responses, payload.finding_id: answer},
        )
        todo = finding_todo_state(simulated, payload.finding_id)
        limitation = limitation_standing(simulated, payload.finding_id)
        # ``limitation`` is an optional non-null field: absent, never an explicit null.
        if limitation is None:
            return RespondClosureAfterModel(todo_state=todo.value)
        return RespondClosureAfterModel(todo_state=todo.value, limitation=limitation.state)
    except TypeError, ValueError:
        return None


async def _public_result(
    request: RespondRequest,
    runtime: TaskRuntime,
    result: AppendResult,
    projection: ProjectionState | None = None,
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
    if payload.duplicate_of_finding_id is not None:
        response_wire["duplicate_of_finding_id"] = payload.duplicate_of_finding_id
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
        None if projection is None else _closure_after(projection, payload, record),
    )


def _admit_todo_state(disposition: str, todo: FindingTodoState) -> None:
    """Refuse an answer the finding's to-do state does not take (issue #905; tb4n3 RC-7, #1030).

    ``verified_resolved``, ``rejection_accepted`` and ``disputed_after_rebuttal`` are absolutely
    final. ``acknowledged_not_done`` takes exactly one answer, ``reopened``; ``self_verified``
    takes none, but a later qualifying check upgrades it. ``reopened`` is refused on any other
    state: there is nothing to take back. Every refusal says what actually happened and the way
    out, never "answer it there" on an item respond refuses.
    """

    if disposition == "reopened":
        if todo in REOPENABLE_TODO_STATES:
            return
        raise _error(
            PublicErrorCode.INVALID_REQUEST,
            (
                f"The finding is {todo.value}; reopened takes back an acknowledged_not_done "
                "answer and there is nothing to reopen here. Nothing was recorded."
            ),
            reason_code="response_fields_invalid",
            field="/disposition",
        )
    if todo is FindingTodoState.OPEN:
        return
    if todo is FindingTodoState.ACKNOWLEDGED_NOT_DONE:
        raise _error(
            PublicErrorCode.INVALID_REQUEST,
            (
                "The finding is acknowledged_not_done and nothing was recorded. To do the work "
                "after all, respond reopened with a reason; or just repair it and run check: a "
                "qualifying check that tests the work after your answer proves it absent and "
                "resolves the finding."
            ),
            reason_code="finding_terminal",
            field="/finding_id",
        )
    if todo is FindingTodoState.SELF_VERIFIED:
        raise _error(
            PublicErrorCode.INVALID_REQUEST,
            (
                "The finding is self_verified and nothing was recorded. It stays disclosed until "
                "a qualifying check that tests the work after your answer proves the issue "
                "absent, which resolves it; run check after your next change."
            ),
            reason_code="finding_terminal",
            field="/finding_id",
        )
    assert todo in ABSOLUTELY_FINAL_TODO_STATES
    if todo is FindingTodoState.VERIFIED_RESOLVED:
        # tb4n5: four of seven ``finding_terminal`` refusals were an ``acknowledged`` sent after a
        # recheck had already proved the finding absent. Nothing is wrong and nothing is owed.
        message = (
            "The finding is already verified_resolved: a later check proved the issue absent, so "
            "it needs no answer and nothing was recorded. Do not retry; answer only findings "
            "that are still open (status view=findings). A new problem is raised by a later "
            "check as a new finding."
        )
    elif todo is FindingTodoState.DISPUTED_AFTER_REBUTTAL:
        message = (
            "The finding is already disputed_after_rebuttal: the reviewer kept it open over your "
            "reasoned answer without citing anything newer. That state is final, needs no "
            "answer and is not agent work; nothing was recorded. The receipt lists it as a "
            "standing disagreement; new evidence about the same problem is raised by a later "
            "check as a new finding."
        )
    else:
        message = (
            f"The finding is already {todo.value}; that state is final and nothing was "
            "recorded. New evidence about the same problem is raised by a later check as a new "
            "finding."
        )
    raise _error(
        PublicErrorCode.INVALID_REQUEST,
        message,
        reason_code="finding_terminal",
        field="/finding_id",
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
        answered_from: ProjectionState | None = None
        if result is None:
            finding_frontier = Frontier(
                int(request.finding_frontier.sequence), request.finding_frontier.head_digest
            )
            current = Frontier(
                int(request.expected_frontier.sequence), request.expected_frontier.head_digest
            )
            current_records, current_projection = await _records_through(runtime, current)
            answered_from = current_projection
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
            _admit_todo_state(request.disposition, todo)
            if request.disposition == "acknowledged_not_done" and (
                request.reason is None or not request.reason.strip()
            ):
                raise _error(
                    PublicErrorCode.INVALID_REQUEST,
                    "acknowledged_not_done requires a non-empty reason.",
                    reason_code="response_fields_invalid",
                    field="/reason",
                )
            if request.disposition == "reopened" and (
                request.reason is None or not request.reason.strip()
            ):
                raise _error(
                    PublicErrorCode.INVALID_REQUEST,
                    "reopened requires a non-empty reason: say what changed and that you will do "
                    "the work.",
                    reason_code="response_fields_invalid",
                    field="/reason",
                )
            if request.disposition == "self_verified":
                _admit_self_verification(request, current_projection, current_records)
            if request.disposition == "duplicate_of":
                _admit_duplicate_link(request, finding_record, current_projection)
            elif request.duplicate_of_finding_id is not None:
                raise _error(
                    PublicErrorCode.INVALID_REQUEST,
                    "duplicate_of_finding_id is accepted only with disposition duplicate_of.",
                    reason_code="response_fields_invalid",
                    field="/duplicate_of_finding_id",
                )
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
            # tb4n3 RC-1 (Q4): a reviewer's limitation request asks for a disclosure, not for a
            # repair, so acknowledging it needs no recorded resolution attempt.
            limitation = reviewer_finding and is_limitation_request(finding_record.payload)
            attempted = False
            # Structural ids the caller cited that exist but predate the finding; named in the
            # rejection so the caller knows the citation, not the shape, is the problem.
            cited_before: list[str] = []
            for ref in () if request.evidence_refs is None else request.evidence_refs:
                present = (
                    current_projection.evidence.get(evidence_id(ref))
                    if ref.startswith("evd_")
                    else current_projection.results.get(result_id(ref))
                )
                if present is None or present.payload is None:
                    raise _error(
                        PublicErrorCode.INVALID_REQUEST,
                        "A response reference is invalid.",
                        reason_code="response_fields_invalid",
                        field="/evidence_refs",
                    )
                # "After the finding" means after the finding's own record, not after whichever
                # in-chain frontier the caller chose to name it by: any frontier at or after the
                # record is accepted, including the current status frontier (issue #911).
                after = present.source_frontier > finding_record.source_frontier
                attempted = attempted or after
                if not after:
                    cited_before.append(str(ref))
            if request.disposition == "self_verified" and not attempted:
                # Issue #984: the agent's own verification is evidence recorded after the finding;
                # evidence from before the repair cannot show that the repair was verified.
                raise _error(
                    PublicErrorCode.INVALID_REQUEST,
                    (
                        "self_verified needs at least one evidence_refs id recorded after the "
                        "finding: publish the evidence of your own verification of the repair, "
                        "then cite its evd_ or res_ id."
                    ),
                    reason_code="response_fields_invalid",
                    field="/evidence_refs",
                )
            if (
                request.disposition == "acknowledged"
                and reviewer_finding
                and not question
                and not limitation
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
                    _resolution_attempt_required_message(
                        finding_record.source_frontier, tuple(cited_before)
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
                None
                if request.duplicate_of_finding_id is None
                else finding_id(request.duplicate_of_finding_id),
            )
            now = app.clock.now_utc()
            draft = EventDraft(
                event_id(app.ids.new(IdKind.EVENT)),
                EventSchema(
                    "response_recorded",
                    RESPONSE_EVENT_SCHEMA_VERSION
                    if payload.disposition in RESPONSE_V1_1_DISPOSITIONS
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
        return await _public_result(request, runtime, result, answered_from)
    except ProtocolValueError as exc:
        raise _error(PublicErrorCode.INVALID_REQUEST, "The response request is invalid.") from exc
    finally:
        await app.runtime.release(runtime)
