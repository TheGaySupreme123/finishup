"""Deterministic in-memory reference implementation of the ledger boundary."""

from __future__ import annotations

import asyncio
import hashlib
from bisect import bisect_right
from collections.abc import AsyncIterator, Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Final, Literal, cast

from yoetz.domain.events import (
    CHECK_EVENT_SCHEMA_VERSION,
    FINDING_EVENT_SCHEMA_VERSION,
    FINDING_SNIPPET_EVENT_SCHEMA_VERSION,
    REVIEW_CHECK_EVENT_SCHEMA_VERSION,
    SEMANTIC_EVENT_SCHEMA_VERSION,
    AcceptedEvent,
    ActionRecordedPayload,
    AssignmentRecordedPayload,
    CheckChangeShownFiles,
    CheckMode,
    CheckRecordedPayload,
    ClaimRecordedPayload,
    ClaimRecordedPayloadV1_1,
    ClaimRevisionMismatch,
    DecisionRecordedPayload,
    DeliverableState,
    EventDraft,
    EventPayload,
    EventSchema,
    EvidenceRecordedPayload,
    FindingRecordedPayload,
    LedgerChain,
    LedgerRecord,
    MissingForAssessmentItem,
    NoObligationsReasonMismatch,
    ObligationPublishedPayload,
    ObligationResolutionMismatch,
    PayloadRef,
    PlanPublishedPayload,
    PlanRevisedPayload,
    PolicyVersion,
    ProjectionLocator,
    RedactionRecordedPayload,
    RedactionState,
    ResponseRecordedPayload,
    ResultRecordedPayload,
    SessionOpenedPayload,
    UnknownEvent,
    WriterChain,
    encode_payload,
    is_observation_authored,
    is_observation_authorship,
    media_type_for,
    public_error_for_claim_revision_mismatch,
    public_error_for_no_obligations_reason_mismatch,
    public_error_for_obligation_resolution_mismatch,
)
from yoetz.domain.findings import (
    FindingKind,
    PriorFindingVerdictRecord,
    RankedFindings,
    RuntimeTokenUsage,
    SemanticProvenance,
    rank_key,
    semantic_provenance_to_json,
)
from yoetz.domain.privacy import DisclosureProvenance, SourceAuthorship, authorship_provenance
from yoetz.domain.receipts import CHECK_CURRENT_AS_OF_EARLIER_FRONTIER_GAP
from yoetz.domain.values import (
    Actor,
    ActorType,
    EventId,
    Frontier,
    JsonObject,
    JsonValue,
    ObjectId,
    action_id,
    actor_id,
    event_id,
    finding_id,
    object_id,
    occurred_at_consistency,
    parse_rfc3339_millis,
    request_id,
    session_id,
    task_id,
    timestamp_from_datetime,
    writer_id,
)
from yoetz.kernel.check_totals import build_check_totals
from yoetz.kernel.closure_readiness import ClosureReadinessFacts, closure_readiness_facts
from yoetz.kernel.command_attempts import attempted_items_for_obligation, command_attempts
from yoetz.kernel.completion_scope import completion_scope_codes, with_completion_scope_coverage
from yoetz.kernel.deterministic_checks import (
    CaseAvailabilityFacts,
    DeterministicCase,
    UnavailableCapturedObject,
    build_deterministic_case,
    deterministic_case_from_json,
    deterministic_case_to_json,
)
from yoetz.kernel.finding_resolution import (
    append_resolution_explanation,
    finding_is_resolved,
    finding_resolution_explanation,
)
from yoetz.kernel.finding_todo import duplicate_link_target, finding_todo_state
from yoetz.kernel.observed_failures import (
    observed_event_ids_from_records,
    observed_run_facts,
)
from yoetz.kernel.plan_drift import plan_drift_signals
from yoetz.kernel.plan_scope import current_plan_scope
from yoetz.kernel.projections import (
    PROJECTION_VERSION,
    EvidenceProjectionRecord,
    ProjectionState,
    empty_projection_state,
    observation_limitation_finding_ids,
    projection_digest,
    unanswered_finding_ids,
)
from yoetz.kernel.receipt_capacity import (
    ReceiptCoverageCapacityExceeded,
    _validate_receipt_coverage_capacity_validated,  # pyright: ignore[reportPrivateUsage]
    receipt_blocking_finding_count,
)
from yoetz.kernel.reducers import (
    invalidates_recorded_check,
    is_material_event_family,
    replay,
    replay_extension,
    replay_extension_with_index,
    replay_with_index,
)
from yoetz.kernel.task_facts import task_fact_signals
from yoetz.observability.logging import record_unexpected_exception_without_raising
from yoetz.ports.change_capture import TASK_CHANGE_BASE_MEDIA_TYPE
from yoetz.ports.clock import ClockPort
from yoetz.ports.ids import IdPort
from yoetz.ports.ledger import (
    CHECK_ACQUISITION_RESERVATION_SECONDS,
    CHECK_ADMISSION_RETRY_AFTER_MS,
    AcceptedEventSummary,
    AppendCommand,
    AppendEntry,
    AppendResult,
    AppendWarning,
    AssignmentProjectionFilter,
    AttemptOutcome,
    CheckAdmissionRecord,
    CheckAdmissionStage,
    CheckCommitResult,
    CheckPhase,
    CheckPolicyExecution,
    CheckSuspensionKind,
    CheckVersionSlice,
    EvidenceProjectionFilter,
    FindingProjectionPosition,
    FindingsProjectionFilter,
    FrozenCase,
    HistoryProjectionFilter,
    HistoryProjectionPosition,
    IdProjectionPosition,
    ObligationsProjectionFilter,
    OperationKind,
    OperationLease,
    OperationQuarantineCode,
    OperationRecord,
    OperationState,
    PendingVerdict,
    PendingVerdictKind,
    ProjectionItem,
    ProjectionPage,
    ProjectionQuery,
    ProjectionView,
    SelectedAttempt,
    SemanticAttemptHandle,
    SemanticAttemptRecord,
    SemanticDisclosureWait,
    SemanticJobRecord,
    SemanticProgressRecord,
    StoredProjection,
    check_admission_refused,
    check_admission_stage,
)
from yoetz.ports.objects import (
    ObjectKind,
    ObjectMetadata,
    ObjectRef,
    ObjectSource,
    ObjectStorePort,
)
from yoetz.ports.runtime import OwnershipFence
from yoetz.protocol.canonical import (
    canonical_digest,
    canonical_encode,
    entry_digest,
    strict_json_parse,
)
from yoetz.protocol.coverage import (
    AuthorshipAssurance,
    Coverage,
    LedgerFreshness,
    PublicationChannel,
    coverage_for_channel,
    coverage_to_json,
    weakest,
)
from yoetz.protocol.errors import PublicErrorCode, PublicOperationError
from yoetz.protocol.ids import IdKind
from yoetz.protocol.models import (
    SEMANTIC_PROGRESS_PHASE_RANK,
    CheckPolicyExecutionModel,
    CheckScopeModel,
    CheckTestEditTotalsModel,
    CoverageModel,
    FreshnessWire,
    FrontierModel,
    RecordedPolicyVersionWire,
    ReviewInputManifestModel,
    SemanticProgressPhase,
    SemanticReason,
    SemanticStatus,
    StatusAssignmentItemModel,
    StatusCompactFindingModel,
    StatusCompactItemModel,
    StatusCompactObligationModel,
    StatusEvidenceItemModel,
    StatusFindingItemModel,
    StatusHistoryItemModel,
    StatusHistoryItemV14Model,
    StatusLatestCheckTestEditsModel,
    StatusObligationItemModel,
    StatusObservedRunModel,
    StatusResultItemModel,
    StatusStructuralSubjectStateModel,
    StatusVersionSliceModel,
)
from yoetz.protocol.redacted_values import SemanticRedactedValue
from yoetz.version import build_status_version_slice_facts

__all__ = ["MemoryLedgerAdapter", "MemoryLedgerState", "compact_status_coverage"]

_GENESIS: Final = Frontier.genesis()
_REPLAY_SAFE_IMMATERIAL_FAMILIES: Final = frozenset({"receipt_recorded"})
type _SummaryCode = Literal[
    "action_recorded",
    "assignment_recorded",
    "check_recorded",
    "child_accepted",
    "child_dependencies_recorded",
    "child_rejected",
    "child_written_off",
    "claim_recorded",
    "coordination_context_recorded",
    "coordination_disposition_recorded",
    "coordination_obligation_declared",
    "decision_recorded",
    "delegation_cancelled",
    "delegation_declared",
    "evidence_recorded",
    "finding_recorded",
    "obligation_published",
    "opaque_unknown",
    "plan_published",
    "plan_revised",
    "receipt_recorded",
    "redaction_recorded",
    "response_recorded",
    "result_recorded",
    "session_opened",
    "session_resumed",
    "work_abandoned",
    "work_cancelled",
    "work_closed",
    "work_written_off",
]


class _ErrorComponent(StrEnum):
    RECEIPT_COVERAGE = "receipt_coverage"


def _error(
    code: PublicErrorCode,
    *,
    retryable: bool = False,
    reason_code: str | None = None,
    quarantine_code: str | None = None,
    sequence: int | None = None,
    head_digest: str | None = None,
    component: _ErrorComponent | None = None,
    count: int | None = None,
    limit: int | None = None,
) -> PublicOperationError:
    details: dict[str, str | int] = {}
    if reason_code is not None:
        details["reason_code"] = reason_code
    if quarantine_code is not None:
        details["quarantine_code"] = quarantine_code
    if sequence is not None:
        details["sequence"] = sequence
    if head_digest is not None:
        details["head_digest"] = head_digest
    if component is not None:
        details["component"] = component
    if count is not None:
        details["count"] = count
    if limit is not None:
        details["limit"] = limit
    return PublicOperationError(code, code.value.lower(), retryable, safe_details=details)


def _frontier_conflict(head: Frontier) -> PublicOperationError:
    """Stale optimistic guard: surface the current head so callers can retry without a status trip."""

    return _error(
        PublicErrorCode.FRONTIER_CONFLICT,
        retryable=True,
        reason_code="frontier_changed",
        sequence=head.sequence,
        head_digest=head.head_digest,
    )


async def _run_blocking_joined[ResultT](call: Callable[[], ResultT]) -> ResultT:
    """Run a pure local calculation off-loop and join it before cancellation returns.

    The worker only receives immutable records/projections. ``asyncio.wait`` deliberately leaves
    the thread task alive when the caller is cancelled; the repeated wait below prevents the
    ledger lock from being released while that worker can still compute a result.
    """

    worker = asyncio.create_task(asyncio.to_thread(call))
    try:
        await asyncio.wait((worker,))
        return worker.result()
    except asyncio.CancelledError:
        while not worker.done():
            try:
                await asyncio.wait((worker,))
            except asyncio.CancelledError:
                # A second cancellation must not abandon the worker or release the ledger lock.
                continue
        if not worker.cancelled():
            # Observe a late worker exception before preserving the caller's cancellation.
            try:
                worker.result()
            except BaseException as worker_error:
                if not isinstance(worker_error, asyncio.CancelledError):
                    record_unexpected_exception_without_raising(
                        worker_error,
                        component="adapters.memory.ledger",
                        operation="append_validation_worker_failed",
                    )
        raise


@dataclass(frozen=True, slots=True)
class _WriterState:
    task_id: str
    session_id: str
    next_sequence: int = 1
    head_digest: str = "genesis"


@dataclass(frozen=True, slots=True)
class _AttemptState:
    handle: SemanticAttemptHandle
    state: str
    result_object_ref: ObjectRef | None = None
    terminal_code: SemanticReason | None = None
    started_at: datetime | None = None
    token_usage: RuntimeTokenUsage | None = None


@dataclass(frozen=True, slots=True)
class _CheckReservation:
    session_id: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class _CheckAdmissionRefusal:
    """One exact check key's recent pre-admission refusals; transient and structural only."""

    stage: CheckAdmissionStage
    first_refused_at: datetime
    last_refused_at: datetime
    refusal_count: int


_TRUSTED_PROJECTION_HISTORY_LIMIT: Final = 16
_CASE_DEPENDENCY_DIGEST_LIMIT: Final = 8


class TrustedProjectionHistory:
    """Bounded, process-local projections this adapter itself produced by replay or extension.

    Issue #886: a caller pinned one or a few appends behind the live head (hook observation
    drains between agent calls) used to force a full genesis replay. Each entry is keyed by the
    exact ``(sequence, head_digest)`` frontier and retains the record tuple it was folded from, so
    a lookup is honoured only while the current chain still carries those exact record objects as
    its prefix. Recovery, a rolled-back SQLite sync, or any replacement of a record (for example a
    payload purge after redaction) therefore invalidates the entry by identity instead of by
    trusting the hash chain alone. Nothing is persisted, so a restart falls back to replay.
    """

    __slots__ = ("_entries",)

    def __init__(self) -> None:
        self._entries: dict[tuple[int, str], tuple[ProjectionState, tuple[LedgerRecord, ...]]] = {}

    def remember(
        self,
        projection: ProjectionState,
        records: tuple[LedgerRecord, ...],
        appended: tuple[LedgerRecord, ...] = (),
    ) -> None:
        # A redaction must also hide content from every pinned historical read, so it drops
        # every older snapshot rather than letting one outlive the redaction.
        if any(row.schema.name == "redaction_recorded" for row in appended):
            self._entries.clear()
        if type(projection) is not ProjectionState or len(records) != projection.frontier:
            return
        key = (projection.frontier, projection.head_digest)
        self._entries.pop(key, None)
        while len(self._entries) >= _TRUSTED_PROJECTION_HISTORY_LIMIT:
            del self._entries[next(iter(self._entries))]
        self._entries[key] = (projection, records)

    def lookup(
        self, frontier: Frontier, current: tuple[LedgerRecord, ...]
    ) -> ProjectionState | None:
        entry = self._entries.get((frontier.sequence, frontier.head_digest))
        if entry is None:
            return None
        projection, records = entry
        if len(records) > len(current) or not (
            records is current
            or (
                (len(records) == 0 or records[-1] is current[len(records) - 1])
                and all(old is new for old, new in zip(records, current, strict=False))
            )
        ):
            return None
        return projection

    def vouches_for(self, projection: ProjectionState, current: tuple[LedgerRecord, ...]) -> bool:
        return (
            self.lookup(Frontier(projection.frontier, projection.head_digest), current)
            is projection
        )


@dataclass(slots=True)
class MemoryLedgerState:
    """Copy-on-write task state shared by the reference adapters."""

    records: tuple[LedgerRecord, ...] = ()
    operations: dict[tuple[str, str], tuple[OperationRecord, AppendResult | None]] = field(
        default_factory=lambda: {}
    )
    writers: dict[str, _WriterState] = field(default_factory=lambda: {})
    projection: ProjectionState = field(default_factory=empty_projection_state)
    frozen_cases: dict[tuple[str, str], DeterministicCase] = field(default_factory=lambda: {})
    check_results: dict[tuple[str, str], CheckCommitResult] = field(default_factory=lambda: {})
    check_errors: dict[tuple[str, str], PublicOperationError] = field(default_factory=lambda: {})
    jobs: dict[str, SemanticJobRecord] = field(default_factory=lambda: {})
    job_by_case: dict[tuple[str, str, str], str] = field(default_factory=lambda: {})
    attempts: dict[str, _AttemptState] = field(default_factory=lambda: {})
    # Keyed by job_id: at most one disclosure wait per AI-powered review job.
    disclosure_waits: dict[str, SemanticDisclosureWait] = field(default_factory=lambda: {})
    object_refs: dict[str, ObjectRef] = field(default_factory=lambda: {})
    # The task-start base object of the check-time change (ADR-031); kept once per task.
    task_change_base: ObjectRef | None = None
    # Keyed by job_id: the last non-terminal structural progress row (issue #571 A2). The
    # terminal phase is derived from the job row itself, never stored here.
    semantic_progress: dict[str, SemanticProgressRecord] = field(default_factory=lambda: {})
    # Transient freeze-acquisition holds: never persisted; a crash mid-freeze must drop them.
    check_reservations: dict[tuple[str, str], _CheckReservation] = field(default_factory=lambda: {})
    # Transient, bounded pre-admission refusals keyed by exact (writer, request) (issue #838).
    # Never persisted, cloned, or adopted: only the outermost ledger layer that answered the
    # caller records here, and admission of the key clears its entry.
    check_admissions: dict[tuple[str, str], _CheckAdmissionRefusal] = field(
        default_factory=lambda: {}
    )

    # Transient, bounded projections at recent exact frontiers. Clones share the same history:
    # every lookup is fenced by record identity, so an entry from a discarded clone never matches.
    trusted_projections: TrustedProjectionHistory = field(default_factory=TrustedProjectionHistory)
    # Transient memo of each frozen case's dependency digest (a canonical digest of its whole
    # projection), recomputed on every lease renewal otherwise. Identity-fenced on the case object.
    case_dependency_digests: dict[tuple[str, str], tuple[DeterministicCase, str]] = field(
        default_factory=lambda: {}
    )
    # Transient, bounded exact-snapshot row indexes; never persisted or shared across clones.
    # Evidence rows are built per page (``_evidence_page_rows``), so their entry holds ``None``.
    query_records: tuple[LedgerRecord, ...] = ()
    query_cache: dict[
        tuple[Frontier, str, str], tuple[ProjectionState, tuple[ProjectionItem, ...] | None]
    ] = field(default_factory=lambda: {})

    def restore_writer(
        self,
        writer: str,
        task: str,
        session: str,
        next_sequence: int,
        head_digest: str,
    ) -> None:
        self.writers[writer] = _WriterState(task, session, next_sequence, head_digest)


def _case_dependency_digest(case: DeterministicCase) -> str:
    return canonical_digest(
        {
            "availability": {
                "captured": tuple(
                    (item.source_event_id, item.object_id)
                    for item in case.availability.unavailable_captured_objects
                ),
                "events": case.availability.unavailable_event_ids,
            },
            "projection": projection_digest(case.projection),
        }
    )


_OPERATION_LEASE_SECONDS: Final = 60
_SEMANTIC_EXECUTION_CLEANUP_GRACE_SECONDS: Final = 5
_SEMANTIC_EXECUTION_MAX_SECONDS: Final = 7200


async def _open_exact_object(objects: ObjectStorePort, expected: ObjectRef) -> bytes:
    resolved = await objects.resolve_verified(expected.object_id, expected.envelope_digest)
    if resolved != expected:
        raise ValueError("resume_object_descriptor_invalid")
    return b"".join([chunk async for chunk in objects.open_verified(resolved)])


def _strict_mapping(value: object, *, reason: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(reason)
    mapping = cast(Mapping[object, object], value)
    if any(type(key) is not str for key in mapping):
        raise ValueError(reason)
    return cast(Mapping[str, object], value)


def _plain_mapping_for_model(value: JsonValue, *, reason: str) -> Mapping[str, object]:
    """Thaw a frozen JSON object before handing it to a Pydantic model.

    Ledger payloads use ``JsonObject`` recursively so event values cannot be mutated after
    acceptance.  Pydantic's mapping validation accepts the outer frozen object, but rejects its
    nested ``JsonObject`` values as model inputs.  A canonical round trip preserves the recorded
    bytes while restoring ordinary dict/list containers at this model boundary.
    """

    return _strict_mapping(strict_json_parse(canonical_encode(value)), reason=reason)


async def _semantic_execution_lease_bound(
    objects: ObjectStorePort,
    job: SemanticJobRecord,
    *,
    task: str,
    now: datetime,
) -> datetime | None:
    """Return the authenticated AI-powered review execution expiry plus cleanup grace.

    The execution deadline is part of the frozen ``semantic-case/2`` object. Reading it through
    the exact object reference keeps lease renewal tied to the case that was prepared for this
    job; callers cannot extend a provider operation by supplying a new deadline. Legacy
    ``semantic-case/1`` objects predate durable endpoint execution metadata and are handled by
    the legacy coordinator path, so they retain the ordinary operation lease behavior here.
    """

    ref = job.case_object_ref
    if ref.metadata.kind is not ObjectKind.SEMANTIC_CASE or ref.metadata.task_id != task:
        raise ValueError("semantic_case_object_binding_invalid")
    raw = await _open_exact_object(objects, ref)
    parsed = strict_json_parse(raw)
    if canonical_encode(parsed) != raw:
        raise ValueError("semantic_case_object_noncanonical")
    source = _strict_mapping(parsed, reason="semantic_case_object_shape_invalid")
    if source.get("case_digest") != job.case_digest:
        raise ValueError("semantic_case_object_binding_invalid")
    schema = source.get("schema")
    if schema == "yoetz.semantic-case/1":
        return None
    if schema != "yoetz.semantic-case/2":
        raise ValueError("semantic_case_object_schema_invalid")
    execution = _strict_mapping(
        source.get("execution"), reason="semantic_case_execution_shape_invalid"
    )
    primary_expires_at = parse_rfc3339_millis(execution.get("primary_expires_at"))
    expires_at = parse_rfc3339_millis(execution.get("expires_at"))
    if primary_expires_at > expires_at:
        raise ValueError("semantic_case_execution_deadline_invalid")
    if expires_at > now + timedelta(seconds=_SEMANTIC_EXECUTION_MAX_SECONDS):
        raise ValueError("semantic_case_execution_deadline_invalid")
    return expires_at + timedelta(seconds=_SEMANTIC_EXECUTION_CLEANUP_GRACE_SECONDS)


async def load_frozen_case_from_resume(
    objects: ObjectStorePort,
    record: OperationRecord,
    *,
    task: str,
    session: str,
) -> DeterministicCase:
    """Verified-decode the case reachable from the row's sole current pointer."""

    current = record.resume_object_ref
    if current is None or current.metadata.task_id != task:
        raise ValueError("resume_object_binding_invalid")
    raw = await _open_exact_object(objects, current)
    parsed = strict_json_parse(raw)
    if canonical_encode(parsed) != raw:
        raise ValueError("resume_object_noncanonical")
    source = _strict_mapping(parsed, reason="resume_object_shape_invalid")

    if current.metadata.kind is ObjectKind.DETERMINISTIC_RESULT:
        deterministic_result_keys = frozenset(
            {
                "schema_version",
                "request_id",
                "request_digest",
                "task_id",
                "session_id",
                "writer_id",
                "subject_frontier",
                "dependency_digest",
                "text_contract_digest",
                "prior_resume",
                "policy_executions",
                "assessments",
            }
        )
        # A checkpoint without the text-contract stamp predates issue #340. Its case pointer and
        # bindings are still authoritative for reopening the frozen case; only the application's
        # finding-text replay treats the missing stamp as superseded.
        if frozenset(source) not in {
            deterministic_result_keys,
            deterministic_result_keys - {"text_contract_digest"},
        }:
            raise ValueError("deterministic_result_shape_invalid")
        if "text_contract_digest" in source and type(source["text_contract_digest"]) is not str:
            raise ValueError("deterministic_result_shape_invalid")
        if (
            source["schema_version"] != "1.0.0"
            or source["request_id"] != record.operation_id
            or source["request_digest"] != record.request_digest
            or source["task_id"] != task
            or source["session_id"] != session
            or source["writer_id"] != record.writer_id
        ):
            raise ValueError("deterministic_result_binding_invalid")
        pointer = _strict_mapping(
            source["prior_resume"], reason="deterministic_result_pointer_invalid"
        )
        if frozenset(pointer) != frozenset({"object_id", "envelope_digest", "commitment"}) or any(
            type(pointer[key]) is not str for key in pointer
        ):
            raise ValueError("deterministic_result_pointer_invalid")
        prior = await objects.resolve_verified(
            cast(str, pointer["object_id"]), cast(str, pointer["envelope_digest"])
        )
        if (
            prior.metadata.kind is not ObjectKind.CHECK_RESUME
            or prior.metadata.task_id != task
            or prior.commitment != pointer["commitment"]
        ):
            raise ValueError("deterministic_result_pointer_invalid")
        raw = await _open_exact_object(objects, prior)
        parsed = strict_json_parse(raw)
        if canonical_encode(parsed) != raw:
            raise ValueError("resume_object_noncanonical")
        resume_source = _strict_mapping(parsed, reason="resume_object_shape_invalid")
        expected_frontier = source["subject_frontier"]
        expected_dependency = source["dependency_digest"]
    elif current.metadata.kind is ObjectKind.CHECK_RESUME:
        resume_source = source
        expected_frontier = None
        expected_dependency = None
    else:
        raise ValueError("resume_object_kind_invalid")

    if frozenset(resume_source) != frozenset(
        {
            "schema_version",
            "task_id",
            "session_id",
            "writer_id",
            "request_id",
            "request_digest",
            "frontier",
            "dependency_digest",
            "case_digest",
            "case",
        }
    ):
        raise ValueError("resume_object_shape_invalid")
    if (
        resume_source["schema_version"] != "1.0.0"
        or resume_source["task_id"] != task
        or resume_source["session_id"] != session
        or resume_source["writer_id"] != record.writer_id
        or resume_source["request_id"] != record.operation_id
        or resume_source["request_digest"] != record.request_digest
    ):
        raise ValueError("resume_object_binding_invalid")
    case = deterministic_case_from_json(cast(JsonValue, resume_source["case"]))
    case_json = deterministic_case_to_json(case)
    dependency = _case_dependency_digest(case)
    if (
        resume_source["case_digest"] != canonical_digest(case_json)
        or resume_source["frontier"] != case.frontier.as_wire()
        or resume_source["dependency_digest"] != dependency
        or (expected_frontier is not None and expected_frontier != case.frontier.as_wire())
        or (expected_dependency is not None and expected_dependency != dependency)
    ):
        raise ValueError("resume_object_binding_invalid")
    return case


def quarantine_resume_object_invalid(
    record: OperationRecord, *, now: datetime
) -> tuple[OperationRecord, PublicOperationError]:
    """Terminalize one pending check whose durable resume pointer cannot be rehydrated.

    The verdict belongs to this operation id, not the ledger: recovery keeps the event
    chain, projection, and every other operation live, and same-request replay raises
    the stored error instead of latching bundle ``STORAGE_CORRUPT``.
    """

    error = _error(
        PublicErrorCode.STORAGE_CORRUPT,
        quarantine_code=OperationQuarantineCode.OPERATION_RESUME_OBJECT_INVALID.value,
    )
    canonical = canonical_encode(
        {
            "code": error.code.value,
            "message": str(error),
            "retryable": error.retryable,
            "safe_details": dict(error.safe_details),
        }
    )
    quarantined = replace(
        record,
        state=OperationState.QUARANTINED,
        phase=CheckPhase.TERMINAL,
        owner_generation=None,
        lease_owner_id=None,
        lease_generation=None,
        lease_expires_at=None,
        resume_object_ref=None,
        result_canonical=canonical,
        result_digest=f"sha256:{hashlib.sha256(canonical).hexdigest()}",
        result_locator=None,
        quarantine_code=OperationQuarantineCode.OPERATION_RESUME_OBJECT_INVALID,
        terminal_at=now,
        suspension_kind=None,
    )
    return quarantined, error


_CHECK_ADMISSION_JOURNAL_LIMIT: Final = 64
_CHECK_ADMISSION_JOURNAL_TTL: Final = timedelta(minutes=15)
_CHECK_ADMISSION_MAX_REFUSALS: Final = 2**53 - 1


def _prune_check_admissions(state: MemoryLedgerState, now: datetime) -> None:
    journal = state.check_admissions
    for key in tuple(journal):
        if now - journal[key].last_refused_at > _CHECK_ADMISSION_JOURNAL_TTL:
            del journal[key]


def note_check_admission_refusal(
    state: MemoryLedgerState,
    key: tuple[str, str],
    stage: CheckAdmissionStage,
    now: datetime,
) -> None:
    """Remember one pre-admission refusal for an exact check key (issue #838).

    The journal is what lets ``status view=operation`` tell a refused admission apart from a
    request this service never saw. It is bounded by entry count and age, holds only closed
    stage tokens and service timestamps, and is never persisted.
    """

    _prune_check_admissions(state, now)
    journal = state.check_admissions
    prior = journal.pop(key, None)
    journal[key] = (
        _CheckAdmissionRefusal(stage, now, now, 1)
        if prior is None
        else _CheckAdmissionRefusal(
            stage,
            prior.first_refused_at,
            max(now, prior.last_refused_at),
            min(prior.refusal_count + 1, _CHECK_ADMISSION_MAX_REFUSALS),
        )
    )
    while len(journal) > _CHECK_ADMISSION_JOURNAL_LIMIT:
        del journal[next(iter(journal))]


def check_admission_record(
    state: MemoryLedgerState, key: tuple[str, str], now: datetime
) -> CheckAdmissionRecord | None:
    """Project the live reservation and recent refusals for one key; ``None`` once admitted."""

    if key in state.operations:
        return None
    _prune_check_admissions(state, now)
    refusal = state.check_admissions.get(key)
    reservation = cast(object | None, state.check_reservations.get(key))
    expires_at = getattr(reservation, "expires_at", None)
    if type(expires_at) is datetime and expires_at > now:
        armed_at = min(now, expires_at - timedelta(seconds=CHECK_ACQUISITION_RESERVATION_SECONDS))
        first = armed_at if refusal is None else min(armed_at, refusal.first_refused_at)
        return CheckAdmissionRecord(
            key[0],
            key[1],
            CheckAdmissionStage.ACQUIRING,
            0 if refusal is None else refusal.refusal_count,
            first,
            now,
            CHECK_ADMISSION_RETRY_AFTER_MS[CheckAdmissionStage.ACQUIRING],
        )
    if refusal is None:
        return None
    return CheckAdmissionRecord(
        key[0],
        key[1],
        refusal.stage,
        refusal.refusal_count,
        refusal.first_refused_at,
        refusal.last_refused_at,
        CHECK_ADMISSION_RETRY_AFTER_MS[refusal.stage],
    )


def _now(clock: ClockPort | None) -> datetime:
    value = datetime.now(UTC) if clock is None else clock.now_utc()
    if value.tzinfo is None or value.utcoffset() != datetime.now(UTC).utcoffset():
        raise ValueError("clock_value_invalid")
    return value


def _logical_key(payload: EventPayload, event_id: str) -> str | None:
    if type(payload) in {PlanPublishedPayload, PlanRevisedPayload}:
        return str(cast(PlanPublishedPayload | PlanRevisedPayload, payload).plan_version)
    if type(payload) is ObligationPublishedPayload:
        return payload.obligation_id
    if type(payload) in {AssignmentRecordedPayload, DecisionRecordedPayload, CheckRecordedPayload}:
        return event_id
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


def _redaction_targets(
    payload: EventPayload,
) -> tuple[tuple[EventId, ...], tuple[ObjectId, ...]]:
    if type(payload) is RedactionRecordedPayload:
        return payload.target_event_ids, payload.target_object_ids
    return (), ()


def _record_preimage(
    command: AppendCommand,
    index: int,
    *,
    ingestion_sequence: int,
    writer_sequence: int,
    previous_ledger_digest: str,
    previous_writer_digest: str,
    accepted_at: datetime,
) -> LedgerRecord:
    item = command.entries[index]
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
        logical_key = _logical_key(typed_payload, draft.event_id)
        target_events, target_objects = _redaction_targets(typed_payload)
    locator = ProjectionLocator(
        draft.schema,
        logical_key,
        payload_digest,
        target_events,
        target_objects,
    )
    timestamp = timestamp_from_datetime(accepted_at)
    task = task_id(command.task_id)
    session = session_id(command.session_id)
    writer = WriterChain(writer_id(command.writer_id), writer_sequence, previous_writer_digest)
    ledger = LedgerChain(ingestion_sequence, previous_ledger_digest, timestamp)
    operation = request_id(command.operation_id)
    payload_ref = PayloadRef(
        object_id(item.payload_object.object_id),
        item.media_type,
        item.plaintext_size,
        item.payload_commitment,
        item.payload_object.encryption_format,
    )
    # The digest preimage has exactly the structural fields serialized by the
    # domain record, so construct once with a temporary mapping rather than a
    # record carrying an invalid placeholder digest.
    from yoetz.protocol.coverage import coverage_to_json

    preimage = {
        "protocol": "yoetz.event",
        "protocol_version": "0.1",
        "event_id": draft.event_id,
        "task_id": command.task_id,
        "session_id": command.session_id,
        "schema": {"name": draft.schema.name, "version": draft.schema.version},
        "author": {
            "actor_id": item.author.actor_id,
            "actor_type": item.author.actor_type.value,
            "assurance": item.author.assurance.value,
        },
        "writer": {
            "writer_id": command.writer_id,
            "sequence": str(writer_sequence),
            "previous_entry_digest": previous_writer_digest,
        },
        "ledger": {
            "ingestion_sequence": str(ingestion_sequence),
            "previous_entry_digest": previous_ledger_digest,
            "accepted_at": timestamp.wire,
        },
        "operation_id": command.operation_id,
        "occurred_at": draft.occurred_at.wire,
        "causal_parents": draft.causal_parents,
        "publication_channel": item.publication_channel.value,
        "coverage": coverage_to_json(item.coverage),
        "payload_ref": {
            "object_id": item.payload_object.object_id,
            "media_type": item.media_type,
            "plaintext_size": item.plaintext_size,
            "commitment": item.payload_commitment,
            "encryption_format": item.payload_object.encryption_format,
        },
        "redaction": "present",
        "artifact_refs": draft.artifact_refs,
        "evidence_refs": draft.evidence_refs,
    }
    digest = entry_digest(preimage)
    if item.projection_status == "projected":
        record: LedgerRecord = AcceptedEvent(
            event_id=draft.event_id,
            task_id=task,
            session_id=session,
            schema=draft.schema,
            author=item.author,
            writer=writer,
            ledger=ledger,
            operation_id=operation,
            occurred_at=draft.occurred_at,
            causal_parents=draft.causal_parents,
            publication_channel=item.publication_channel,
            coverage=item.coverage,
            payload_ref=payload_ref,
            redaction=RedactionState.PRESENT,
            artifact_refs=draft.artifact_refs,
            evidence_refs=draft.evidence_refs,
            entry_digest=digest,
            payload=cast(EventPayload, draft.payload),
            projection_locator=locator,
        )
    else:
        record = UnknownEvent(
            event_id=draft.event_id,
            task_id=task,
            session_id=session,
            schema=draft.schema,
            author=item.author,
            writer=writer,
            ledger=ledger,
            operation_id=operation,
            occurred_at=draft.occurred_at,
            causal_parents=draft.causal_parents,
            publication_channel=item.publication_channel,
            coverage=item.coverage,
            payload_ref=payload_ref,
            redaction=RedactionState.PRESENT,
            artifact_refs=draft.artifact_refs,
            evidence_refs=draft.evidence_refs,
            entry_digest=digest,
            payload=cast(JsonValue, draft.payload),
            projection_locator=locator,
            canonical_payload_digest=payload_digest,
        )
    return record


def _result_bytes(result: AppendResult) -> bytes:
    value = {
        "accepted": tuple(
            {
                "entry_digest": row.entry_digest,
                "event_id": row.event_id,
                "ingestion_sequence": str(row.ingestion_sequence),
                "projection_status": row.projection_status,
                "writer_sequence": str(row.writer_sequence),
            }
            for row in result.accepted
        ),
        "result_frontier": result.result_frontier.as_wire(),
        "subject_frontier": result.subject_frontier.as_wire(),
        "warnings": tuple(item.value for item in result.warnings),
    }
    return canonical_encode(value)


def build_append_operation_record(
    command: AppendCommand, result: AppendResult, now: datetime
) -> OperationRecord:
    canonical = _result_bytes(result)
    first = result.accepted[0].ingestion_sequence
    last = result.accepted[-1].ingestion_sequence
    from yoetz.ports.ledger import OperationResultLocator

    return OperationRecord(
        writer_id=command.writer_id,
        operation_id=command.operation_id,
        operation_kind=command.operation_kind,
        request_digest=command.request_digest,
        state=OperationState.COMPLETE,
        phase=CheckPhase.TERMINAL,
        owner_generation=None,
        lease_owner_id=None,
        lease_generation=None,
        lease_expires_at=None,
        resume_object_ref=None,
        result_canonical=canonical,
        result_digest=f"sha256:{hashlib.sha256(canonical).hexdigest()}",
        result_locator=OperationResultLocator(
            first,
            last,
            command.result_object_ref,
            tuple(sorted((row.event_id for row in result.accepted), key=str.encode)),
        ),
        quarantine_code=None,
        terminal_at=now,
    )


def _finding_position(finding: FindingRecordedPayload) -> FindingProjectionPosition:
    key = rank_key(finding)
    return FindingProjectionPosition(
        key[0],
        key[1] == -1,
        -key[2],
        -key[3],
        -key[4],
        -key[5],
        key[6] == -1,
        key[7],
        key[8],
        finding.finding_id,
    )


def _finding_position_key(value: FindingProjectionPosition) -> tuple[object, ...]:
    return (
        value.priority,
        -int(value.actionable),
        -value.artifact_ordinal,
        -value.immutability_ordinal,
        -value.freshness_ordinal,
        -value.authorship_ordinal,
        -int(value.real_check_present),
        value.known_gap_count,
        value.origin_ordinal,
        value.finding_id.encode("ascii"),
    )


def _status_gap_codes(markers: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(sorted({marker.split(":", 1)[0] for marker in markers}, key=str.encode))


def compact_status_coverage(
    records: tuple[LedgerRecord, ...], projection: ProjectionState
) -> Coverage:
    """Fold the applicable check's coverage into the compact-status baseline.

    The newest record's envelope (often an engine-derived ``receipt_recorded``) hardcodes
    ``check_types=(none,)`` even immediately after a rich check; the check's real coverage
    lives in its payload. The receipt applicability rule decides whether the projected latest
    check still covers this state: it does unless cooperative material work or an observation
    finding superseded it.

    Shared by the memory status view and the durable SQLite ``p1_projection_state`` mirror so
    a restart cannot disagree with the in-process projection about what was checked, and it uses
    the same predicate as the receipt so status and receipts cannot disagree either.
    """

    baseline = with_completion_scope_coverage(records[-1].coverage, projection)
    latest = projection.latest_tested_state
    if latest is None:
        return baseline
    check_record = next(
        (record for record in records if record.event_id == latest.source_check_event_id),
        None,
    )
    if check_record is None or type(check_record.payload) is not CheckRecordedPayload:
        return baseline
    limitations = observation_limitation_finding_ids(projection, records)
    if any(
        invalidates_recorded_check(
            record,
            check_record.ledger.ingestion_sequence,
            latest.returned_finding_ids,
            limitation_finding_ids=limitations,
        )
        for record in records
    ):
        return baseline
    coverage = weakest(baseline, check_record.payload.coverage)
    if any(
        is_material_event_family(record.schema.name)
        and record.ledger.ingestion_sequence > check_record.ledger.ingestion_sequence
        for record in records
    ):
        # The same attributable suffix that the receipt builder discloses still leaves the check
        # useful, but only as of its tested subject frontier. Keep the current observation
        # records visible in status and add the bounded qualification instead of manufacturing
        # ``check_not_applicable`` or stale-after-material-change.
        gaps = tuple(
            sorted(
                set(coverage.known_gaps) | {CHECK_CURRENT_AS_OF_EARLIER_FRONTIER_GAP},
                key=str.encode,
            )
        )
        freshness = coverage.ledger_freshness
        if freshness is LedgerFreshness.CURRENT:
            freshness = LedgerFreshness.PARTIAL
        coverage = replace(coverage, ledger_freshness=freshness, known_gaps=gaps)
    return coverage


def _latest_check_test_edits(
    records: tuple[LedgerRecord, ...], projection: ProjectionState
) -> StatusLatestCheckTestEditsModel | None:
    """Expose only the latest check's persisted structural test-edit counters."""

    latest = projection.latest_tested_state
    if latest is None:
        return None
    check_record = next(
        (record for record in records if record.event_id == latest.source_check_event_id),
        None,
    )
    if check_record is None or type(check_record.payload) is not CheckRecordedPayload:
        return None
    totals = check_record.payload.totals
    if totals is None:
        return None
    try:
        counters = CheckTestEditTotalsModel.model_validate(totals["test_edits"])
    except KeyError, TypeError, ValueError:
        # Legacy check events have no totals group. Status must keep that absence explicit rather
        # than manufacture zero counts for an unexamined capture.
        return None
    read_availability = (
        "unavailable"
        if counters.examined == "0"
        else "unknown"
        if counters.baseline_known == "0" or counters.unknown != "0"
        else "available"
    )
    return StatusLatestCheckTestEditsModel(
        checked_frontier=FrontierModel(
            sequence=str(latest.subject_frontier.sequence),
            head_digest=latest.subject_frontier.head_digest,
        ),
        read_availability=read_availability,
        examined=counters.examined,
        baseline_known=counters.baseline_known,
        modified=counters.modified,
        renamed=counters.renamed,
        deleted=counters.deleted,
        skipped=counters.skipped,
        unjustified=counters.unjustified,
        unknown=counters.unknown,
    )


def _obligation_item(
    obligation: str,
    record: object,
    assigned_actor_ids: tuple[str, ...],
    attempted_items: frozenset[str],
) -> StatusObligationItemModel:
    from yoetz.kernel.projections import ObligationProjectionRecord

    typed = cast(ObligationProjectionRecord, record)
    assert typed.payload is not None
    requested_items = tuple(
        {"item_kind": item.item_kind.value, "value": item.value}
        if item.role is None
        else {"item_kind": item.item_kind.value, "value": item.value, "role": item.role.value}
        for item in typed.payload.requested_items
    )
    unattempted_items = tuple(
        item for item in requested_items if item["value"] not in attempted_items
    )
    values = dict(
        obligation_id=obligation,
        # Issue #997/#1002: the row is the not-done marker: ``acknowledged_not_done`` with the
        # agent's reason (status-result 1.4.0). Closure readiness counts it once, as not done.
        status=typed.payload.status.value,
        description=typed.payload.description,
        evidence_expectation=typed.payload.evidence_expectation,
        source_refs=typed.payload.source_refs,
        assigned_actor_ids=assigned_actor_ids,
        evidence_refs=typed.payload.resolution_evidence_refs,
        requested_items=requested_items,
        unattempted_items=unattempted_items,
        revision_event_id=None,
    )
    if typed.payload.acceptance_criteria is not None:
        values["acceptance_criteria"] = typed.payload.acceptance_criteria
    if typed.payload.acknowledged_not_done_reason is not None:
        values["acknowledged_not_done_reason"] = typed.payload.acknowledged_not_done_reason
    return StatusObligationItemModel.model_validate(values)


def _compact_obligation_item(obligation: str, record: object) -> StatusCompactObligationModel:
    from yoetz.kernel.projections import ObligationProjectionRecord

    typed = cast(ObligationProjectionRecord, record)
    assert typed.payload is not None
    values = dict(
        obligation_id=obligation,
        description=typed.payload.description,
        evidence_expectation=typed.payload.evidence_expectation,
    )
    if typed.payload.acceptance_criteria is not None:
        values["acceptance_criteria"] = typed.payload.acceptance_criteria
    return StatusCompactObligationModel.model_validate(values)


def _indexed_source_row(
    record: EvidenceProjectionRecord, records: tuple[LedgerRecord, ...]
) -> LedgerRecord | None:
    """Return an evidence row's source event by its ``source_frontier`` index, if it is there.

    Replay admits only a contiguous chain whose ingestion sequences start at 1, so the index
    normally names the source event directly; ``None`` sends the caller to one full scan.
    """

    index = record.source_frontier - 1
    if 0 <= index < len(records) and records[index].event_id == record.source_event_id:
        return records[index]
    return None


def _scanned_source_rows(
    projection: ProjectionState, records: tuple[LedgerRecord, ...]
) -> dict[str, LedgerRecord]:
    """Locate every readable evidence row's source event in one scan of the frozen prefix."""

    wanted = {
        record.source_event_id: evidence
        for evidence, record in projection.evidence.items()
        if record.payload is not None
    }
    return {wanted[row.event_id]: row for row in records if row.event_id in wanted}


def _evidence_rows(
    projection: ProjectionState,
    records: tuple[LedgerRecord, ...],
    *,
    after: str | None = None,
) -> Iterator[tuple[str, EvidenceProjectionRecord, LedgerRecord]]:
    """Yield readable evidence rows with their source events, in wire order, one at a time.

    Rows are ordered by the UTF-8 bytes of their ids (the ``IdProjectionPosition`` order) and
    start strictly after ``after``, so a page reaches its cursor without visiting earlier rows.
    Nothing is built here: the caller constructs only the rows it keeps.
    """

    ordered = sorted(
        (key for key, record in projection.evidence.items() if record.payload is not None),
        key=str.encode,
    )
    start = 0 if after is None else bisect_right(ordered, after.encode(), key=str.encode)
    scanned: dict[str, LedgerRecord] | None = None
    for evidence in ordered[start:]:
        record = projection.evidence[evidence]
        source = _indexed_source_row(record, records)
        if source is None:
            if scanned is None:
                scanned = _scanned_source_rows(projection, records)
            source = scanned.get(evidence)
        if source is None:
            raise _error(PublicErrorCode.STORAGE_CORRUPT)
        yield evidence, record, source


def _evidence_freshness(
    projection: ProjectionState, record: EvidenceProjectionRecord
) -> FreshnessWire:
    freshness = projection.freshness.value
    if not record.object_available and freshness == "current":
        return "redacted_gap"
    return freshness


def _evidence_item(
    evidence: str,
    record: EvidenceProjectionRecord,
    source: LedgerRecord,
    freshness: FreshnessWire,
) -> StatusEvidenceItemModel:
    payload = record.payload
    assert payload is not None
    state = payload.subject_state
    subject_state = None
    if state is not None and (state.tree_digest is not None or state.diff_digest is not None):
        # Optional non-null digests must be omitted when unset, never passed as null —
        # ``StatusStructuralSubjectStateModel`` rejects explicit null leaves.
        subject_state_values: dict[str, object] = {}
        if state.tree_digest is not None:
            subject_state_values["tree_digest"] = state.tree_digest
        if state.diff_digest is not None:
            subject_state_values["diff_digest"] = state.diff_digest
        subject_state = StatusStructuralSubjectStateModel.model_validate(subject_state_values)
    return StatusEvidenceItemModel(
        evidence_id=evidence,
        publication_channel=source.publication_channel.value,
        strength=payload.strength.value,
        freshness=freshness,
        available=record.object_available,
        description=payload.description,
        reference=payload.reference,
        captured_object_id=payload.captured_object_id,
        content_digest=payload.content_digest,
        subject_state=subject_state,
    )


def _evidence_page_rows(
    projection: ProjectionState,
    records: tuple[LedgerRecord, ...],
    query: ProjectionQuery,
    frontier: Frontier,
    sources: dict[str, LedgerRecord],
) -> Iterator[StatusEvidenceItemModel]:
    """Yield the rows of one evidence page lazily, building only rows that pass the filter.

    The filter is decided on the projection record and its source event (every filtered field
    is a direct copy of one of them), so a row that a filter drops is never constructed, and the
    page loop stops after ``limit + 1`` kept rows. ``sources`` receives each yielded row's source
    event for the page's authorship facts.
    """

    evidence_filter = query.filter if type(query.filter) is EvidenceProjectionFilter else None
    after = query.position.last_id if type(query.position) is IdProjectionPosition else None
    for evidence, record, source in _evidence_rows(projection, records, after=after):
        payload = record.payload
        assert payload is not None
        freshness = _evidence_freshness(projection, record)
        if evidence_filter is not None and not (
            (evidence_filter.strength is None or payload.strength.value == evidence_filter.strength)
            and (evidence_filter.freshness is None or freshness == evidence_filter.freshness)
            and (evidence_filter.include_unavailable is True or record.object_available)
            and (
                evidence_filter.author is None
                or _authored_by_requester(_source_authorship(source), query, frontier)
            )
        ):
            continue
        sources[evidence] = source
        yield _evidence_item(evidence, record, source, freshness)


def _source_authorship(row: LedgerRecord | None) -> SourceAuthorship | None:
    """Read one source event's authorship from its accepted envelope.

    Writer chain, session and sequence are service-assigned; the channel is the ledger-recorded
    one (a cooperative writer records only ``cooperative_mcp`` or ``local_cli``); the observation
    stamp cannot be asserted by a cooperative writer.
    """

    if row is None:
        return None
    return SourceAuthorship(
        row.writer.writer_id,
        row.session_id,
        row.ledger.ingestion_sequence,
        row.publication_channel,
        is_observation_authored(row),
    )


def _later_redaction_targets(
    suffix: tuple[LedgerRecord, ...],
) -> tuple[frozenset[str], frozenset[str]]:
    """Collect the event and object targets of every redaction after a pinned frontier.

    An object target redacts the event whose payload object it names, exactly as replay resolves
    it, so a row can be withdrawn by either identity. The suffix is empty for a head read.
    """

    events: set[str] = set()
    objects: set[str] = set()
    for row in suffix:
        if row.schema.name != "redaction_recorded":
            continue
        events.update(row.projection_locator.redaction_target_event_ids)
        objects.update(row.projection_locator.redaction_target_object_ids)
    return frozenset(events), frozenset(objects)


def _authored_by_requester(
    source: SourceAuthorship | None, query: ProjectionQuery, frontier: Frontier
) -> bool:
    """Apply the ``DisclosureProvenance`` self-authorship rule for ``author=mine``."""

    return (
        source is not None
        and query.writer_id is not None
        and authorship_provenance(
            (source,),
            writer_id=query.writer_id,
            session_id=query.session_id,
            frontier_sequence=frontier.sequence,
        )
        is DisclosureProvenance.SELF_AUTHORED
    )


def _record_frontier(records: tuple[LedgerRecord, ...], sequence: int) -> Frontier | None:
    """Return the frontier that ends at one ingestion sequence (#917).

    Its head digest is that record's own entry digest, which is exactly what
    ``respond`` authenticates for a supplied ``finding_frontier``.
    """

    if 0 < sequence <= len(records):
        anchor = records[sequence - 1]
        if anchor.ledger.ingestion_sequence == sequence:
            return Frontier(sequence, anchor.entry_digest)
    for anchor in records:
        if anchor.ledger.ingestion_sequence == sequence:
            return Frontier(sequence, anchor.entry_digest)
    return None


def _projection_items(
    view: ProjectionView,
    projection: ProjectionState,
    records: tuple[LedgerRecord, ...],
    *,
    task: str,
    session: str,
) -> tuple[ProjectionItem, ...]:
    """Project one immutable state into the exact bounded public row types."""

    if view is ProjectionView.CANDIDATE_FINDINGS:
        return ()
    if view is ProjectionView.HISTORY:
        result_history: list[StatusHistoryItemModel | StatusHistoryItemV14Model] = []
        for row in records:
            if row.session_id != session:
                continue
            manifest = (
                None
                if type(row.payload) is not CheckRecordedPayload
                else row.payload.review_input_manifest
            )
            manifest_model = (
                None
                if manifest is None
                else ReviewInputManifestModel.model_validate(
                    _plain_mapping_for_model(
                        cast(JsonValue, manifest), reason="review_input_manifest_shape_invalid"
                    )
                )
            )
            history_type = (
                StatusHistoryItemV14Model if manifest_model is not None else StatusHistoryItemModel
            )
            result_history.append(
                history_type(
                    event_id=row.event_id,
                    schema_name=row.schema.name,
                    schema_version=row.schema.version,
                    actor_id=row.author.actor_id,
                    publication_channel=row.publication_channel.value,
                    ingestion_sequence=str(row.ledger.ingestion_sequence),
                    occurred_at=row.occurred_at.wire,
                    accepted_at=row.ledger.accepted_at.wire,
                    occurred_at_consistency=occurred_at_consistency(
                        row.occurred_at, row.ledger.accepted_at
                    ),
                    projection_status=(
                        "unknown_unprojected" if type(row) is UnknownEvent else "projected"
                    ),
                    summary_code=cast(
                        _SummaryCode,
                        "opaque_unknown" if type(row) is UnknownEvent else row.schema.name,
                    ),
                    **(
                        {"review_input_manifest": manifest_model}
                        if manifest_model is not None
                        else {}
                    ),
                )
            )
        return tuple(result_history)
    if view is ProjectionView.ASSIGNMENT:
        handed_off = {
            payload.handoff_of
            for record in projection.assignments.values()
            if (payload := record.payload) is not None and payload.handoff_of is not None
        }
        result: list[ProjectionItem] = []
        for event, record in sorted(
            projection.assignments.items(), key=lambda item: item[0].encode()
        ):
            payload = record.payload
            if payload is None:
                continue
            obligations_resolved = all(
                (target := projection.obligations.get(obligation)) is not None
                and target.payload is not None
                and target.payload.status.value == "resolved"
                for obligation in payload.obligation_ids
            )
            result.append(
                StatusAssignmentItemModel(
                    assignment_event_id=event,
                    actor_id=payload.assignee_actor_id,
                    obligation_ids=payload.obligation_ids,
                    scope_refs=payload.obligation_ids,
                    resolved=event in handed_off or obligations_resolved,
                )
            )
        return tuple(result)
    if view is ProjectionView.OBLIGATIONS:
        actors: dict[str, set[str]] = {}
        for assignment in projection.assignments.values():
            if assignment.payload is None:
                continue
            for obligation in assignment.payload.obligation_ids:
                actors.setdefault(obligation, set()).add(assignment.payload.assignee_actor_id)
        return tuple(
            _obligation_item(
                obligation,
                record,
                tuple(sorted(actors.get(obligation, ()), key=str.encode)),
                attempted_items_for_obligation(projection, obligation),
            ).model_copy(
                update={"command_attempts": command_attempts(projection, records, obligation)}
            )
            for obligation, record in sorted(
                projection.obligations.items(), key=lambda item: item[0].encode()
            )
            if record.payload is not None
        )
    if view is ProjectionView.RESULTS:
        # Structural run facts let an agent name the right observed result in limitation_refs
        # without any command text (#909); cooperative results carry none.
        observed_runs = observed_run_facts(projection, observed_event_ids_from_records(records))
        result_items: list[ProjectionItem] = []
        for result_ref, record in sorted(
            projection.results.items(), key=lambda item: item[0].encode()
        ):
            fields: dict[str, object] = {
                "result_id": result_ref,
                "source_event_id": record.source_event_id,
                "payload_available": record.payload is not None,
                "outcome": None if record.payload is None else record.payload.outcome.value,
                "action_id": None if record.payload is None else record.payload.action_id,
                "evidence_refs": () if record.payload is None else record.payload.evidence_refs,
            }
            run = observed_runs.get(result_ref)
            if run is not None:
                run_fields: dict[str, object] = {"occurrence": str(run.occurrence)}
                if run.tool_name is not None:
                    run_fields["tool_name"] = run.tool_name
                if run.command_commitment is not None:
                    run_fields["command_commitment"] = run.command_commitment
                if run.exit_status is not None:
                    run_fields["exit_status"] = run.exit_status
                fields["observed_run"] = StatusObservedRunModel.model_validate(run_fields)
            result_items.append(StatusResultItemModel.model_validate(fields))
        return tuple(result_items)
    if view is ProjectionView.EVIDENCE:
        return tuple(
            _evidence_item(evidence, record, source, _evidence_freshness(projection, record))
            for evidence, record, source in _evidence_rows(projection, records)
        )
    if view is ProjectionView.FINDINGS:
        finding_items: list[ProjectionItem] = []
        proof_state_cache: dict[tuple[int, int, str], ProjectionState | None] = {}
        source_frontiers = {
            record.payload.finding_id: record.source_frontier
            for record in projection.findings.values()
            if record.payload is not None
        }
        ordered = sorted(
            (
                record.payload
                for record in projection.findings.values()
                if record.payload is not None
            ),
            key=rank_key,
        )
        for finding in ordered:
            response_record = projection.responses.get(finding.finding_id)
            response = None if response_record is None else response_record.payload
            finding_frontier = _record_frontier(records, source_frontiers[finding.finding_id])
            finding_fields: dict[str, Any] = {
                "finding_id": finding.finding_id,
                "kind": finding.kind.value,
                "origin": finding.origin.value,
                "priority": finding.priority,
                "summary": finding.summary,
                "detail": append_resolution_explanation(
                    finding.detail,
                    finding_resolution_explanation(
                        projection,
                        finding.finding_id,
                        records,
                        proof_state_cache=proof_state_cache,
                    ),
                ),
                "subject_refs": finding.subject_refs,
                "policy_id": cast(
                    Literal["research-evidence", "work-integrity"], finding.policy_id
                ),
                "policy_version": cast(RecordedPolicyVersionWire, finding.policy_version),
                "subject_frontier": FrontierModel.model_validate(
                    dict(finding.subject_frontier.as_wire())
                ),
                "coverage": CoverageModel.model_validate(coverage_to_json(finding.coverage)),
                "provenance": (
                    None
                    if finding.provenance is None
                    else semantic_provenance_to_json(finding.provenance)
                ),
                "disposition": "none" if response is None else response.disposition.value,
                "resolved": finding_is_resolved(projection, finding.finding_id),
                "response_event_id": (
                    None if response_record is None else response_record.source_event_id
                ),
                "reason": None if response is None else response.reason,
                "waiver_scope": (
                    None
                    if response is None or response.waiver_scope is None
                    else response.waiver_scope.value
                ),
                "waiver_expiry": (
                    None
                    if response is None or response.waiver_expiry is None
                    else response.waiver_expiry.wire
                ),
                "todo_state": finding_todo_state(projection, finding.finding_id).value,
                "review_rounds": str(projection.findings[finding.finding_id].review_rounds),
                "finding_frontier": (
                    None
                    if finding_frontier is None
                    else FrontierModel.model_validate(dict(finding_frontier.as_wire()))
                ),
            }
            # Issue #996: present exactly while a ``duplicate_of`` link holds.
            duplicate_of = duplicate_link_target(projection, finding.finding_id)
            if duplicate_of is not None:
                finding_fields["duplicate_of_finding_id"] = duplicate_of
            if finding.challenge is not None:
                finding_fields["challenge"] = {
                    "alternative_interpretation": finding.challenge.alternative_interpretation,
                    "discrepancy": finding.challenge.discrepancy,
                    "requested_next_step": finding.challenge.requested_next_step,
                    "uncertainty": finding.challenge.uncertainty,
                    **(
                        {}
                        if finding.challenge.snippet is None
                        else {"snippet": finding.challenge.snippet}
                    ),
                }
            finding_items.append(StatusFindingItemModel(**finding_fields))
        return tuple(finding_items)
    if view is ProjectionView.COMPACT:
        opened = next(
            (
                row.payload
                for row in records
                if type(row) is AcceptedEvent and type(row.payload) is SessionOpenedPayload
            ),
            None,
        )
        if opened is None:
            return ()
        scope = current_plan_scope(projection.plans, projection.coverage_gaps)
        scope_refs = scope.effective_obligation_refs
        open_obligations = (
            ()
            if scope_refs is None
            else tuple(
                _compact_obligation_item(key, record)
                for key in scope_refs
                if (record := projection.obligations.get(key)) is not None
                and record.payload is not None
                # acknowledged_not_done (#997) is listed by closure readiness, never as open.
                and record.payload.status.value == "open"
            )
        )
        proof_state_cache: dict[tuple[int, int, str], ProjectionState | None] = {}
        # Observation-authored, non-actionable rows are disclosed limitations, not response work
        # (issue #911): they stay in view=findings and on the receipt but leave this preview and
        # its counter, which is also what closure_readiness reads for findings_unanswered.
        unanswered_ids = unanswered_finding_ids(projection, records)
        unanswered_findings = tuple(
            StatusCompactFindingModel(
                finding_id=finding.finding_id,
                kind=finding.kind.value,
                priority=finding.priority,
                summary=finding.summary,
                detail=append_resolution_explanation(
                    finding.detail,
                    finding_resolution_explanation(
                        projection,
                        finding.finding_id,
                        records,
                        proof_state_cache=proof_state_cache,
                    ),
                ),
            )
            for finding in sorted(
                (
                    value.payload
                    for key, value in projection.findings.items()
                    if value.payload is not None and key in unanswered_ids
                ),
                key=rank_key,
            )
        )
        unanswered_count = len(unanswered_ids)
        receipt_blocking_count = receipt_blocking_finding_count(projection)
        declared_count = (
            None
            if scope_refs is None
            else (0 if not scope.has_plan else scope.declared_obligation_count)
        )
        open_count = (
            None
            if scope_refs is None
            else sum(
                (record := projection.obligations.get(obligation)) is None
                or record.payload is None
                # acknowledged_not_done (#997) is counted once, as not done, never as open.
                or record.payload.status.value == "open"
                for obligation in scope_refs
            )
        )
        item_coverage = compact_status_coverage(records, projection)
        # The scalar and the coverage beside it are two derivations of one fact: the projection
        # folds events, the coverage re-folds the applicable check over the newest record's
        # envelope. An import-channel envelope reads `partial` where the projection reads
        # `current`, so reporting the projection scalar raw lets the headline read cleaner than
        # the coverage it summarizes. Report the weaker of the two (issue #307).
        item_freshness = min(projection.freshness, item_coverage.ledger_freshness)
        item_gaps = tuple(
            sorted(
                set(_status_gap_codes(projection.coverage_gaps))
                | set(completion_scope_codes(projection))
                | set(item_coverage.known_gaps),
                key=str.encode,
            )
        )
        item_gaps = tuple(
            sorted(
                set(item_gaps) | set(plan_drift_signals(projection, records).codes),
                key=str.encode,
            )
        )
        compact_item_fields: dict[str, object] = {
            "task_id": task,
            "session_id": session,
            "task_title": opened.task_title,
            "current_plan_event_id": scope.current_plan_event_id,
            "declared_obligation_count": (None if declared_count is None else str(declared_count)),
            "no_obligations_reason": (
                None if scope.no_obligations_reason is None else scope.no_obligations_reason.value
            ),
            "open_obligation_count": None if open_count is None else str(open_count),
            "unanswered_finding_count": str(unanswered_count),
            "receipt_blocking_finding_count": str(receipt_blocking_count),
            "open_obligations": open_obligations[:10],
            "unanswered_findings": unanswered_findings[:10],
            "freshness": item_freshness.value,
            "coverage": CoverageModel.model_validate(coverage_to_json(item_coverage)),
            "gaps": item_gaps,
        }
        latest_check_test_edits = _latest_check_test_edits(records, projection)
        if latest_check_test_edits is not None:
            compact_item_fields["latest_check_test_edits"] = latest_check_test_edits
        return (StatusCompactItemModel.model_validate(compact_item_fields),)
    if view is ProjectionView.VERSIONS:
        facts = build_status_version_slice_facts()
        return (
            StatusVersionSliceModel.model_validate(
                {
                    "protocol_version": facts.protocol_version,
                    "engine_version": facts.engine_version,
                    "projection_version": facts.projection_version,
                    "object_format": facts.object_format,
                    "storage_schema": facts.storage_schema,
                    "python_version": facts.python_version,
                    "apsw_version": facts.apsw_version,
                    "sqlite_version": facts.sqlite_version,
                    "sqlite_source_id": facts.sqlite_source_id,
                    "policy_packs": list(facts.policy_packs),
                    "provider_profiles": list(facts.provider_profiles),
                }
            ),
        )
    raise _error(PublicErrorCode.INVALID_REQUEST)


class MemoryLedgerAdapter:
    """The deterministic conformance oracle for task-ledger operations."""

    def __init__(
        self,
        *,
        task_id: str,
        ownership_fence: OwnershipFence,
        state: MemoryLedgerState,
        import_state: object,
        transaction_lock: asyncio.Lock,
        clock: ClockPort | None = None,
        ids: IdPort | None = None,
        objects: ObjectStorePort | None = None,
    ) -> None:
        if (
            type(ownership_fence) is not OwnershipFence
            or type(state) is not MemoryLedgerState
            or type(transaction_lock) is not asyncio.Lock
        ):
            raise TypeError("memory_ledger_construction_invalid")
        if ids is None or objects is None:
            raise TypeError("memory_ledger_dependencies_required")
        self._task_id = task_id
        self._fence = ownership_fence
        self._state = state
        self._import_state = import_state
        self._lock = transaction_lock
        self._clock = clock
        self._ids = ids
        self._objects = objects

    def _pending_import(self, session_id: str) -> bool:
        method = getattr(self._import_state, "has_pending_import", None)
        if callable(method):
            return bool(method(session_id))
        pending = cast(tuple[str, ...], getattr(self._import_state, "pending_session_ids", ()))
        return session_id in pending

    def _reservation_valid(self, command: AppendCommand) -> bool:
        method = getattr(self._import_state, "publication_reservation", None)
        if callable(method):
            reservation = method(command.writer_id, command.operation_id)
            if reservation is None:
                return False
            source = getattr(reservation, "source_identity_digest", None)
            ordinal = getattr(reservation, "publication_ordinal", None)
            jobs = cast(Mapping[str, object], getattr(self._import_state, "jobs", {}))
            job = jobs.get(cast(str, source))
            if job is None:
                # The SQLite preparation shim deliberately exposes only the
                # already-verified permanent reservation.
                return type(reservation).__name__ == "_Reservation"
            if (
                getattr(job, "session_id", None) != command.session_id
                or getattr(job, "publishing_writer_id", None) != command.writer_id
            ):
                return False
            event_ids = tuple(item.draft.event_id for item in command.entries)
            batches = cast(
                Mapping[tuple[str, int], object], getattr(self._import_state, "batches", {})
            )
            batch = batches.get((cast(str, source), cast(int, ordinal)))
            if batch is not None:
                return (
                    getattr(batch, "request_id", None) == command.operation_id
                    and getattr(batch, "event_ids", None) == event_ids
                    and getattr(batch, "result", None) is None
                )
            return (
                getattr(job, "report_request_id", None) == command.operation_id
                and len(event_ids) == 1
                and getattr(job, "report_event_id", None) == event_ids[0]
            )
        reservations = getattr(self._import_state, "publication_requests", {})
        return (command.writer_id, command.operation_id) in cast(
            Mapping[tuple[str, str], object], reservations
        )

    def _lease_for(self, record: OperationRecord) -> OperationLease:
        key = (record.writer_id, record.operation_id)
        case = self._state.frozen_cases.get(key)
        if (
            case is None
            or record.owner_generation is None
            or record.lease_owner_id is None
            or record.lease_generation is None
            or record.lease_expires_at is None
        ):
            raise _error(PublicErrorCode.STORAGE_CORRUPT)
        return OperationLease(
            record.writer_id,
            record.operation_id,
            next(
                writer.session_id
                for writer_id, writer in self._state.writers.items()
                if writer_id == record.writer_id
            ),
            record.phase,
            record.owner_generation,
            record.lease_owner_id,
            record.lease_generation,
            record.lease_expires_at,
            case.frontier,
            self._dependency_digest_for(key, case),
        )

    def _dependency_digest_for(self, key: tuple[str, str], case: DeterministicCase) -> str:
        memo = self._state.case_dependency_digests.get(key)
        if memo is not None and memo[0] is case:
            return memo[1]
        digest = _case_dependency_digest(case)
        self._remember_dependency_digest(key, case, digest)
        return digest

    def _remember_dependency_digest(
        self, key: tuple[str, str], case: DeterministicCase, digest: str
    ) -> None:
        memo = self._state.case_dependency_digests
        memo.pop(key, None)
        while len(memo) >= _CASE_DEPENDENCY_DIGEST_LIMIT:
            del memo[next(iter(memo))]
        memo[key] = (case, digest)

    def _require_lease(self, lease: OperationLease) -> OperationRecord:
        row = self._state.operations.get((lease.writer_id, lease.operation_id))
        if row is None:
            raise _error(PublicErrorCode.OPERATION_PENDING, retryable=True)
        record = row[0]
        if (
            record.state is not OperationState.PENDING
            or self._lease_for(record) != lease
            or lease.owner_generation != str(self._fence.owner_generation)
            or lease.lease_owner_id != self._fence.service_instance_id
            or lease.lease_expires_at <= _now(self._clock)
        ):
            raise _error(PublicErrorCode.OPERATION_PENDING, retryable=True)
        return record

    def _has_active_frozen_case_unlocked(self, session_id: str) -> bool:
        """True when observation must defer because a check is actively frozen.

        A standing-grant park expires the lease and may never resume, so
        ``suspension_kind=repository_grant`` is not a barrier: observation
        continues and the same request re-acquires the barrier on replay.

        The same holds for any pending check whose lease is no longer live under this owner: an
        invocation that was abandoned (its caller went away, or a previous service generation
        died holding it) renews nothing and may never be replayed. Deferring observation behind
        it stranded the native capture handoffs that every new check on the task must wait for,
        so neither could ever proceed (issue #838). Commit already tolerates an
        observation-only suffix, and an exact replay re-installs the barrier when it reclaims.
        """

        now = _now(self._clock)
        if any(
            reservation.session_id == session_id and reservation.expires_at > now
            for reservation in self._state.check_reservations.values()
        ):
            return True
        owner_generation = str(self._fence.owner_generation)
        return any(
            (writer := self._state.writers.get(case_writer_id)) is not None
            and writer.session_id == session_id
            and (operation := self._state.operations.get((case_writer_id, operation_id)))
            is not None
            and operation[0].state is OperationState.PENDING
            and operation[0].suspension_kind
            not in {CheckSuspensionKind.REPOSITORY_GRANT, CheckSuspensionKind.REVIEW_INPUT}
            and operation[0].owner_generation == owner_generation
            and operation[0].lease_expires_at is not None
            and operation[0].lease_expires_at > now
            for case_writer_id, operation_id in self._state.frozen_cases
        )

    async def has_active_frozen_case(self, session_id: str) -> bool:
        async with self._lock:
            return self._has_active_frozen_case_unlocked(session_id)

    def _observation_only_since_unlocked(
        self, sequence: int, *, finding_free: bool = False
    ) -> bool:
        """True when every record past ``sequence`` is observation-authored.

        ``finding_free`` additionally rejects a suffix that materialized findings: a caller
        pinned to the older frontier would otherwise leave those findings silently uncovered.
        """

        return all(
            is_observation_authored(record)
            and not (finding_free and record.schema.name == "finding_recorded")
            for record in self._state.records
            if record.ledger.ingestion_sequence > sequence
        )

    def _receipt_prefix_suffix_safe_unlocked(
        self, sequence: int, *, finding_free: bool = False
    ) -> bool:
        """True when a pinned receipt prefix only gained immaterial records.

        A second rendering of one checked receipt may follow an engine-derived
        ``receipt_recorded`` event. That suffix changes the ledger frontier and receipt history,
        but it does not change the deterministic case. Observation records remain allowed under
        the existing observation rule; all other event families, including child manifests, are
        treated as material so a stale prefix cannot launder newer work.
        """

        return all(
            (
                is_observation_authored(record)
                or record.schema.name in _REPLAY_SAFE_IMMATERIAL_FAMILIES
            )
            and not (finding_free and record.schema.name == "finding_recorded")
            for record in self._state.records
            if record.ledger.ingestion_sequence > sequence
        )

    def _projection_anchored_unlocked(self, projection: ProjectionState) -> bool:
        """True when ``projection`` is the exact replay of this chain through its frontier."""

        # The live projection and projections this adapter produced for a still-identical prefix
        # are replay results by construction; only a foreign object needs re-deriving.
        if projection is self._state.projection or self._state.trusted_projections.vouches_for(
            projection, self._state.records
        ):
            return True
        records = tuple(
            row
            for row in self._state.records
            if row.ledger.ingestion_sequence <= projection.frontier
        )
        try:
            return replay(records) == projection
        except ValueError as exc:
            raise _error(PublicErrorCode.STORAGE_CORRUPT) from exc

    def _replace_pending_record(
        self,
        record: OperationRecord,
        *,
        phase: CheckPhase | None = None,
        resume_object_ref: ObjectRef | None = None,
        lease_expires_at: datetime | None = None,
        semantic_job_id: str | None = None,
    ) -> tuple[OperationRecord, OperationLease]:
        job: SemanticJobRecord | None = None
        if semantic_job_id is not None:
            job = self._state.jobs.get(semantic_job_id)
            if (
                job is None
                or job.writer_id != record.writer_id
                or job.operation_id != record.operation_id
                or job.state != "leased"
                or job.lease_owner_id != record.lease_owner_id
            ):
                raise _error(PublicErrorCode.STORAGE_CORRUPT)
        updated = replace(
            record,
            phase=record.phase if phase is None else phase,
            resume_object_ref=(
                record.resume_object_ref if resume_object_ref is None else resume_object_ref
            ),
            owner_generation=str(self._fence.owner_generation),
            lease_owner_id=self._fence.service_instance_id,
            lease_generation=cast(int, record.lease_generation) + 1,
            lease_expires_at=(
                _now(self._clock) + timedelta(seconds=_OPERATION_LEASE_SECONDS)
                if lease_expires_at is None
                else lease_expires_at
            ),
            suspension_kind=None,
        )
        key = (record.writer_id, record.operation_id)
        self._state.operations[key] = (updated, None)
        if job is not None:
            assert semantic_job_id is not None
            self._state.jobs[semantic_job_id] = replace(
                job,
                lease_owner_id=updated.lease_owner_id,
                lease_expires_at=updated.lease_expires_at,
            )
        return updated, self._lease_for(updated)

    async def append_batch(self, command: AppendCommand) -> AppendResult:
        if command.task_id != self._task_id:
            raise _error(PublicErrorCode.EVENT_INVALID)
        accepted_at = _now(self._clock)
        key = (command.writer_id, command.operation_id)
        importer_authored = any(
            entry.author.actor_type is ActorType.IMPORTER
            or entry.publication_channel is PublicationChannel.CODEX_JSONL_IMPORT
            for entry in command.entries
        )
        observation_authored = all(
            is_observation_authorship(entry.author, entry.publication_channel)
            for entry in command.entries
        )
        async with self._lock:
            prior = self._state.operations.get(key)
            if prior is not None:
                operation, prior_result = prior
                if operation.request_digest != command.request_digest:
                    raise _error(PublicErrorCode.IDEMPOTENCY_CONFLICT)
                if operation.state is OperationState.COMPLETE and prior_result is not None:
                    return replace(prior_result, outcome="replayed")
                raise _error(PublicErrorCode.OPERATION_PENDING, retryable=True)

            if observation_authored and self._has_active_frozen_case_unlocked(command.session_id):
                raise _error(PublicErrorCode.OPERATION_PENDING, retryable=True)

            if command.operation_kind is OperationKind.RECEIPT and self._pending_import(
                command.session_id
            ):
                raise _error(PublicErrorCode.OPERATION_PENDING, retryable=True)
            if importer_authored and not self._reservation_valid(command):
                raise _error(PublicErrorCode.STORAGE_CORRUPT)
            subject = Frontier(self._state.projection.frontier, self._state.projection.head_digest)
            # A receipt's case replays the prefix at its subject frontier, so a finding drained
            # past that frontier would be silently uncovered; receipt appends alone treat a
            # finding-bearing suffix as a real conflict.
            if (
                command.expected_frontier is not None
                and command.expected_frontier != subject.sequence
                and not (
                    command.expected_frontier < subject.sequence
                    and self._receipt_prefix_suffix_safe_unlocked(
                        command.expected_frontier,
                        finding_free=command.operation_kind is OperationKind.RECEIPT,
                    )
                )
            ):
                raise _frontier_conflict(subject)
            writer = self._state.writers.get(command.writer_id)
            if writer is None:
                writer = _WriterState(command.task_id, command.session_id)
            elif writer.task_id != command.task_id or writer.session_id != command.session_id:
                raise _error(PublicErrorCode.EVENT_INVALID)
            snapshot_records = self._state.records
            seen = {record.event_id for record in snapshot_records}
            prior_batch: set[str] = set()
            new_records: list[LedgerRecord] = []
            summaries: list[AcceptedEventSummary] = []
            previous_ledger = subject.head_digest
            previous_writer = writer.head_digest
            for offset, item in enumerate(command.entries):
                if item.draft.event_id in seen or item.draft.event_id in prior_batch:
                    raise _error(PublicErrorCode.EVENT_INVALID)
                if any(
                    parent not in seen and parent not in prior_batch
                    for parent in item.draft.causal_parents
                ):
                    raise _error(PublicErrorCode.EVENT_INVALID)
                ingestion = subject.sequence + offset + 1
                writer_sequence = writer.next_sequence + offset
                try:
                    record = _record_preimage(
                        command,
                        offset,
                        ingestion_sequence=ingestion,
                        writer_sequence=writer_sequence,
                        previous_ledger_digest=previous_ledger,
                        previous_writer_digest=previous_writer,
                        accepted_at=accepted_at,
                    )
                except ValueError as exc:
                    raise _error(PublicErrorCode.EVENT_INVALID) from exc
                new_records.append(record)
                summaries.append(
                    AcceptedEventSummary(
                        record.event_id,
                        ingestion,
                        writer_sequence,
                        record.entry_digest,
                        item.projection_status,
                    )
                )
                previous_ledger = record.entry_digest
                previous_writer = record.entry_digest
                prior_batch.add(record.event_id)
            appended_records = tuple(new_records)
            proposed = snapshot_records + appended_records
            prior_projection = self._state.projection
            try:
                # ``prior_projection`` is the adapter-owned replay of ``snapshot_records`` (set
                # only by recovery replay or a prior validated append under this lock), so folding
                # just the new records is equivalent to a genesis replay of ``proposed`` while the
                # extension still re-authenticates the whole prefix into a fresh reverse index.
                # A genesis replay here held the ledger lock for tens of seconds late in a
                # session (issue #886).
                if appended_records:
                    projection, replay_index = await _run_blocking_joined(
                        lambda: replay_extension_with_index(
                            prior_projection,
                            snapshot_records,
                            appended_records,
                        )
                    )
                else:
                    projection, replay_index = await _run_blocking_joined(
                        lambda: replay_with_index(proposed)
                    )
            except NoObligationsReasonMismatch as exc:
                draft_index: int | None = None
                if exc.event_id is not None:
                    for index, item in enumerate(command.entries):
                        if item.draft.event_id == exc.event_id:
                            draft_index = index
                            break
                raise public_error_for_no_obligations_reason_mismatch(
                    exc, event_index=draft_index
                ) from exc
            except ObligationResolutionMismatch as exc:
                draft_index = None
                if exc.event_id is not None:
                    for index, item in enumerate(command.entries):
                        if item.draft.event_id == exc.event_id:
                            draft_index = index
                            break
                raise public_error_for_obligation_resolution_mismatch(
                    exc, event_index=draft_index
                ) from exc
            except ClaimRevisionMismatch as exc:
                draft_index = None
                if exc.event_id is not None:
                    for index, item in enumerate(command.entries):
                        if item.draft.event_id == exc.event_id:
                            draft_index = index
                            break
                raise public_error_for_claim_revision_mismatch(
                    exc, event_index=draft_index
                ) from exc
            except ValueError as exc:
                raise _error(PublicErrorCode.EVENT_INVALID) from exc
            try:
                await _run_blocking_joined(
                    lambda: _validate_receipt_coverage_capacity_validated(
                        projection,
                        proposed,
                        replay_index=replay_index,
                    )
                )
            except ReceiptCoverageCapacityExceeded as exc:
                raise _error(
                    PublicErrorCode.LIMIT_EXCEEDED,
                    component=_ErrorComponent.RECEIPT_COVERAGE,
                    count=exc.count,
                    limit=exc.limit,
                ) from exc
            result_frontier = Frontier(projection.frontier, projection.head_digest)
            warnings = (
                (AppendWarning.UNKNOWN_EVENT_SCHEMA_PRESERVED,)
                if any(type(record) is UnknownEvent for record in new_records)
                else ()
            )
            result = AppendResult("accepted", tuple(summaries), subject, result_frontier, warnings)
            operation = build_append_operation_record(command, result, accepted_at)
            if command.operation_kind is OperationKind.RECEIPT and self._pending_import(
                command.session_id
            ):
                raise _error(PublicErrorCode.OPERATION_PENDING, retryable=True)
            if importer_authored and not self._reservation_valid(command):
                raise _error(PublicErrorCode.STORAGE_CORRUPT)
            self._state.records = proposed
            self._state.projection = projection
            self._state.trusted_projections.remember(projection, proposed, appended_records)
            self._state.object_refs = {
                **self._state.object_refs,
                **{
                    entry.payload_object.object_id: entry.payload_object
                    for entry in command.entries
                },
                **{
                    artifact_ref.object_id: artifact_ref
                    for artifact_ref in command.artifact_object_refs
                },
                **(
                    {}
                    if command.result_object_ref is None
                    else {command.result_object_ref.object_id: command.result_object_ref}
                ),
            }
            self._state.writers = {
                **self._state.writers,
                command.writer_id: _WriterState(
                    command.task_id,
                    command.session_id,
                    writer.next_sequence + len(new_records),
                    previous_writer,
                ),
            }
            self._state.operations = {**self._state.operations, key: (operation, result)}
            return result

    async def _iter_events(
        self, session_id: str, *, after: int, through: int | None
    ) -> AsyncIterator[LedgerRecord]:
        if (
            type(after) is not int
            or after < 0
            or (through is not None and (type(through) is not int or through < after))
        ):
            raise _error(PublicErrorCode.INVALID_REQUEST)
        async with self._lock:
            records = self._state.records
            # ``session_id`` is a membership check, not a row filter. The ingestion sequence and
            # the digest chain are task-global, so every session attached to this task reads the
            # whole task chain, exactly as ``load_projection`` and ``query_projection`` do.
            # Filtering rows by session would hand replay — which is genesis-anchored — a
            # mid-chain suffix as soon as a resumed session appended its own event.
            rows = (
                tuple(
                    record
                    for record in records
                    if record.ledger.ingestion_sequence > after
                    and (through is None or record.ledger.ingestion_sequence <= through)
                )
                if any(record.session_id == session_id for record in records)
                else ()
            )
        for record in rows:
            yield record

    def load_events(
        self, session_id: str, *, after: int = 0, through: int | None = None
    ) -> AsyncIterator[LedgerRecord]:
        return self._iter_events(session_id, after=after, through=through)

    async def load_trusted_projection(
        self, session_id: str, frontier: Frontier
    ) -> ProjectionState | None:
        """Return the adapter-owned projection at exactly ``frontier``, or ``None``.

        Only the live head or a retained entry whose record prefix is still identical qualifies;
        callers fall back to genesis replay otherwise. No replay runs here.
        """

        async with self._lock:
            records = self._state.records
            if not any(record.session_id == session_id for record in records):
                return None
            live = self._state.projection
            if Frontier(live.frontier, live.head_digest) == frontier:
                return live
            return self._state.trusted_projections.lookup(frontier, records)

    async def load_projection(
        self, session_id: str, view: ProjectionView
    ) -> StoredProjection | None:
        async with self._lock:
            records = self._state.records
            if not any(record.session_id == session_id for record in records):
                return None
            projection = self._state.projection
        frontier = Frontier(projection.frontier, projection.head_digest)
        if view is ProjectionView.CANDIDATE_FINDINGS:
            state: ProjectionState | tuple[ProjectionItem, ...] = projection
        else:
            state = _projection_items(
                view, projection, records, task=self._task_id, session=session_id
            )
        return StoredProjection(view, state, frontier, 0, PROJECTION_VERSION, False)

    async def load_frontier(self) -> Frontier:
        """Return the task-ledger frontier without requiring an existing session."""

        async with self._lock:
            return Frontier(self._state.projection.frontier, self._state.projection.head_digest)

    async def load_case_availability(
        self, session_id: str, frontier: Frontier, projection: ProjectionState
    ) -> CaseAvailabilityFacts:
        if (
            frontier.sequence != projection.frontier
            or frontier.head_digest != projection.head_digest
        ):
            raise _frontier_conflict(Frontier(projection.frontier, projection.head_digest))
        async with self._lock:
            live = Frontier(self._state.projection.frontier, self._state.projection.head_digest)
            if not any(row.session_id == session_id for row in self._state.records):
                raise _frontier_conflict(live)
            # A case pinned to a past frontier stays valid while the live chain only extends it
            # with observation-authored or receipt-only, finding-free records. Replaying and
            # comparing the exact prefix is required: its head digest authenticates the ledger
            # prefix, not an arbitrary caller-supplied ProjectionState that happens to repeat that
            # frontier. Anything else is a real conflict.
            if projection != self._state.projection and not (
                projection.frontier < live.sequence
                and self._projection_anchored_unlocked(projection)
                and self._receipt_prefix_suffix_safe_unlocked(
                    projection.frontier,
                    finding_free=True,
                )
            ):
                raise _frontier_conflict(live)
            by_event = {row.event_id: row for row in self._state.records}
            refs = dict(self._state.object_refs)
            current_records = tuple(
                record
                for collection in (
                    projection.plans,
                    projection.obligations,
                    projection.decisions,
                    projection.assignments,
                    projection.actions,
                    projection.results,
                    projection.evidence,
                    projection.claims,
                    projection.findings,
                    projection.responses,
                )
                for record in collection.values()
                if not record.redacted
            )
        assert self._objects is not None

        async def available(ref: ObjectRef | None) -> bool:
            if ref is None:
                return False
            try:
                async for _ in self._objects.open_verified(ref):
                    pass
            except KeyError, OSError, ValueError:
                return False
            return True

        unavailable_events: set[str] = set()
        for current in current_records:
            accepted = by_event.get(current.source_event_id)
            if accepted is None:
                raise _error(PublicErrorCode.STORAGE_CORRUPT)
            if not await available(refs.get(accepted.payload_ref.object_id)):
                unavailable_events.add(current.source_event_id)
        unavailable_captured: set[UnavailableCapturedObject] = set()
        for evidence in projection.evidence.values():
            payload = evidence.payload
            if (
                payload is None
                or payload.captured_object_id is None
                or not evidence.object_available
            ):
                continue
            if not await available(refs.get(payload.captured_object_id)):
                unavailable_captured.add(
                    UnavailableCapturedObject(evidence.source_event_id, payload.captured_object_id)
                )
        return CaseAvailabilityFacts(
            tuple(event_id(value) for value in sorted(unavailable_events, key=str.encode)),
            tuple(
                sorted(
                    unavailable_captured,
                    key=lambda item: (item.source_event_id.encode(), item.object_id.encode()),
                )
            ),
        )

    async def query_projection(self, query: ProjectionQuery) -> ProjectionPage:
        async with self._lock:
            state = self._state
            projection = state.projection
            head = Frontier(projection.frontier, projection.head_digest)
            records = state.records
            if state.query_records is not records:
                previous = state.query_records
                # A pinned page remains valid after an append-only extension. Redaction,
                # replacement, truncation or rebuilding the prefix invalidates every cache.
                unchanged_prefix = len(records) >= len(previous) and all(
                    old is new for old, new in zip(previous, records, strict=False)
                )
                redaction = any(
                    row.schema.name == "redaction_recorded" for row in records[len(previous) :]
                )
                if not unchanged_prefix or redaction:
                    state.query_cache.clear()
                state.query_records = records
            key = (query.requested_frontier, query.view, query.session_id)
            cached = state.query_cache.get(key)
            if cached is None:
                projection = next(
                    (
                        value[0]
                        for cached_key, value in state.query_cache.items()
                        if cached_key[0] == query.requested_frontier
                    ),
                    state.trusted_projections.lookup(query.requested_frontier, records)
                    or projection,
                )
        # Only immutable snapshots cross the thread boundary; no SQLite handle or mutable
        # ledger state enters the worker. Cancellation joins it before this read returns.
        page, effective, items = await _run_blocking_joined(
            lambda: self._query_snapshot(query, head, records, projection, cached)
        )
        async with self._lock:
            if state.records is records and state.query_records is records:
                if key not in state.query_cache and len(state.query_cache) >= 8:
                    del state.query_cache[next(iter(state.query_cache))]
                state.query_cache[key] = (effective, items)
        return page

    def _query_snapshot(
        self,
        query: ProjectionQuery,
        head: Frontier,
        records: tuple[LedgerRecord, ...],
        projection: ProjectionState,
        cached: tuple[ProjectionState, tuple[ProjectionItem, ...] | None] | None,
    ) -> tuple[ProjectionPage, ProjectionState, tuple[ProjectionItem, ...] | None]:
        if not any(row.session_id == query.session_id for row in records):
            raise _error(PublicErrorCode.SESSION_NOT_FOUND)
        if query.requested_frontier > head or (
            query.expected_projection_version is not None
            and query.expected_projection_version != PROJECTION_VERSION
        ):
            raise _error(PublicErrorCode.INVALID_REQUEST)
        prefix = tuple(
            row
            for row in records
            if row.ledger.ingestion_sequence <= query.requested_frontier.sequence
        )
        effective_projection = (
            cached[0]
            if cached is not None
            else projection
            if query.requested_frontier == Frontier(projection.frontier, projection.head_digest)
            else replay(prefix)
        )
        effective = Frontier(effective_projection.frontier, effective_projection.head_digest)
        if effective != query.requested_frontier:
            raise _error(PublicErrorCode.INVALID_REQUEST)
        view = ProjectionView(query.view)
        all_items: tuple[ProjectionItem, ...] | None = None
        # Evidence rows are built lazily from the cursor on and filtered before construction, so
        # a page builds at most ``limit + 1`` rows however long the task is. Ledger authorship is
        # read per query, never cached: ``author=mine`` and the disclosure provenance both depend
        # on the requesting writer and this exact prefix.
        evidence_sources: dict[str, LedgerRecord] = {}
        candidates: Iterable[ProjectionItem]
        if view is ProjectionView.EVIDENCE:
            candidates = _evidence_page_rows(
                effective_projection, prefix, query, effective, evidence_sources
            )
        else:
            all_items = (
                cached[1]
                if cached is not None and cached[1] is not None
                else _projection_items(
                    view,
                    effective_projection,
                    prefix,
                    task=self._task_id,
                    session=query.session_id,
                )
            )
            candidates = all_items
        filtered_items: list[ProjectionItem] = []
        for item in candidates:
            keep = True
            if type(query.filter) is AssignmentProjectionFilter:
                assert type(item) is StatusAssignmentItemModel
                keep = (
                    query.filter.actor_id is None or item.actor_id == query.filter.actor_id
                ) and (query.filter.include_resolved is True or not item.resolved)
            elif type(query.filter) is ObligationsProjectionFilter:
                assert type(item) is StatusObligationItemModel
                assigned = item.assigned_actor_ids
                keep = (
                    (query.filter.actor_id is None or query.filter.actor_id in assigned)
                    # acknowledged_not_done (#1002) is not resolved: it is listed, and matches
                    # the ``open`` filter, like an open obligation; its row shows its status.
                    and (query.filter.include_resolved is True or item.status != "resolved")
                    and (
                        query.filter.status is None
                        or (item.status == "resolved") == (query.filter.status == "resolved")
                    )
                )
            elif type(query.filter) is FindingsProjectionFilter:
                assert type(item) is StatusFindingItemModel
                keep = (
                    (query.filter.origin is None or item.origin == query.filter.origin)
                    and (query.filter.priority is None or item.priority == query.filter.priority)
                    and (
                        query.filter.disposition is None
                        or item.disposition == query.filter.disposition
                    )
                    and (query.filter.include_resolved is True or not item.resolved)
                )
            elif type(query.filter) is EvidenceProjectionFilter:
                # Already applied, before construction, by ``_evidence_page_rows``.
                assert type(item) is StatusEvidenceItemModel
            elif type(query.filter) is HistoryProjectionFilter:
                assert type(item) in {StatusHistoryItemModel, StatusHistoryItemV14Model}
                history_item = cast(StatusHistoryItemModel | StatusHistoryItemV14Model, item)
                keep = (
                    (
                        query.filter.schema_name is None
                        or history_item.schema_name == query.filter.schema_name
                    )
                    and (
                        query.filter.actor_id is None
                        or history_item.actor_id == query.filter.actor_id
                    )
                    and (
                        query.filter.after_sequence is None
                        or int(history_item.ingestion_sequence) > query.filter.after_sequence
                    )
                )
            if keep and type(query.position) is IdProjectionPosition:
                structural_id = (
                    item.assignment_event_id
                    if type(item) is StatusAssignmentItemModel
                    else item.obligation_id
                    if type(item) is StatusObligationItemModel
                    else item.evidence_id
                    if type(item) is StatusEvidenceItemModel
                    else item.result_id
                    if type(item) is StatusResultItemModel
                    else ""
                )
                keep = structural_id.encode() > query.position.last_id.encode()
            elif keep and type(query.position) is HistoryProjectionPosition:
                assert type(item) in {StatusHistoryItemModel, StatusHistoryItemV14Model}
                history_item = cast(StatusHistoryItemModel | StatusHistoryItemV14Model, item)
                keep = int(history_item.ingestion_sequence) > query.position.ingestion_sequence
            elif keep and type(query.position) is FindingProjectionPosition:
                assert type(item) is StatusFindingItemModel
                finding_record = effective_projection.findings[finding_id(item.finding_id)]
                assert finding_record.payload is not None
                keep = _finding_position_key(
                    _finding_position(finding_record.payload)
                ) > _finding_position_key(query.position)
            if keep:
                filtered_items.append(item)
                if len(filtered_items) > query.limit:
                    break
        selected = tuple(filtered_items[: query.limit])
        item_sources: tuple[tuple[SourceAuthorship, ...], ...] = ()
        if view is ProjectionView.EVIDENCE and selected:
            page_ids = tuple(
                item.evidence_id for item in selected if type(item) is StatusEvidenceItemModel
            )
            # A pinned read replays its own prefix, so a row redacted later (by its event or by
            # its payload object) still carries its prose there. The self-authorship exemption
            # must never re-disclose what the current ledger has redacted: such a row stays
            # unattributed and keeps the category ceiling.
            redacted_events, redacted_objects = _later_redaction_targets(records[len(prefix) :])
            item_sources = tuple(
                ()
                if (row := evidence_sources.get(evidence)) is None
                or row.event_id in redacted_events
                or row.payload_ref.object_id in redacted_objects
                else (cast(SourceAuthorship, _source_authorship(row)),)
                for evidence in page_ids
            )
        next_position = None
        if selected and len(filtered_items) > len(selected):
            last = selected[-1]
            if type(last) in {StatusHistoryItemModel, StatusHistoryItemV14Model}:
                history_item = cast(StatusHistoryItemModel | StatusHistoryItemV14Model, last)
                next_position = HistoryProjectionPosition(int(history_item.ingestion_sequence))
            elif type(last) is StatusFindingItemModel:
                finding_record = effective_projection.findings[finding_id(last.finding_id)]
                assert finding_record.payload is not None
                next_position = _finding_position(finding_record.payload)
            elif type(last) is StatusAssignmentItemModel:
                next_position = IdProjectionPosition(last.assignment_event_id)
            elif type(last) is StatusObligationItemModel:
                next_position = IdProjectionPosition(last.obligation_id)
            elif type(last) is StatusEvidenceItemModel:
                next_position = IdProjectionPosition(last.evidence_id)
            elif type(last) is StatusResultItemModel:
                next_position = IdProjectionPosition(last.result_id)
        status_gaps = tuple(
            sorted(
                set(_status_gap_codes(effective_projection.coverage_gaps))
                | set(completion_scope_codes(effective_projection)),
                key=str.encode,
            )
        )
        status_gaps = tuple(
            sorted(
                set(status_gaps)
                | set(plan_drift_signals(effective_projection, prefix).codes)
                | set(task_fact_signals(effective_projection, prefix).codes),
                key=str.encode,
            )
        )
        readiness_facts: ClosureReadinessFacts | None = None
        if view is ProjectionView.COMPACT:
            # Compact status exposes the same applicable-check fold as the item and as the
            # receipt. In particular, an observation-only suffix keeps the check attributable
            # while qualifying it at its earlier tested frontier; do not let the page-level
            # coverage silently drop that qualification.
            compact_coverage = compact_status_coverage(prefix, effective_projection)
            status_gaps = tuple(
                sorted(
                    set(status_gaps) | set(compact_coverage.known_gaps),
                    key=str.encode,
                )
            )
            coverage = replace(compact_coverage, known_gaps=status_gaps)
            # Derived for exactly this frontier on every request and never cached, so readiness
            # after a restart, a reattach or an upgrade is recomputed from the recorded prefix.
            readiness_facts = closure_readiness_facts(effective_projection, prefix)
        else:
            coverage = with_completion_scope_coverage(
                replace(prefix[-1].coverage, known_gaps=status_gaps), effective_projection
            )
        page = ProjectionPage(
            query.view,
            selected,
            query.requested_frontier,
            head,
            effective,
            head.sequence - effective.sequence,
            PROJECTION_VERSION,
            "current",
            coverage,
            status_gaps,
            next_position,
            item_sources,
            readiness_facts,
        )

        return page, effective_projection, all_items

    async def lookup_operation(self, writer_id: str, operation_id: str) -> OperationRecord | None:
        async with self._lock:
            row = self._state.operations.get((writer_id, operation_id))
        return None if row is None else row[0]

    async def projected_action_event(self, action: str) -> str | None:
        """Return the event that records one action in the current task projection.

        Task-wide and read-only. The observation coordinator uses it so the later
        phase of a paired host call links to the action its earlier phase already
        recorded instead of minting a second one (#917).
        """

        try:
            key = action_id(action)
        except ValueError:
            return None
        async with self._lock:
            record = self._state.projection.actions.get(key)
        return None if record is None else str(record.source_event_id)

    async def lookup_task_operation(
        self, writer_id: str, operation_id: str
    ) -> OperationRecord | None:
        async with self._lock:
            preferred = self._state.operations.get((writer_id, operation_id))
            if preferred is not None:
                return preferred[0]
            matches = [
                row[0]
                for key, row in self._state.operations.items()
                if key[0] != writer_id and key[1] == operation_id
            ]
        return matches[0] if len(matches) == 1 else None

    async def reclaim_operation(
        self, writer_id: str, operation_id: str, request_digest: str
    ) -> OperationLease | PendingVerdict:
        record = await self.lookup_operation(writer_id, operation_id)
        if record is None:
            return PendingVerdict(PendingVerdictKind.ABSENT, None, None)
        if record.request_digest != request_digest:
            raise _error(PublicErrorCode.IDEMPOTENCY_CONFLICT)
        if record.state is OperationState.COMPLETE:
            return PendingVerdict(PendingVerdictKind.TERMINAL, record, None)
        if record.state is OperationState.QUARANTINED:
            return PendingVerdict(PendingVerdictKind.QUARANTINED, record, None)
        assert record.lease_expires_at is not None
        now = _now(self._clock)
        if (
            record.owner_generation == str(self._fence.owner_generation)
            and record.lease_expires_at > now
        ):
            remaining = max(0, int((record.lease_expires_at - now).total_seconds() * 1000))
            return PendingVerdict(PendingVerdictKind.LIVE, record, remaining)
        writer = self._state.writers.get(writer_id)
        if writer is None:
            raise _error(PublicErrorCode.STORAGE_CORRUPT)
        assert self._objects is not None
        try:
            case = await load_frozen_case_from_resume(
                self._objects,
                record,
                task=self._task_id,
                session=writer.session_id,
            )
        except (KeyError, OSError, TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.STORAGE_CORRUPT) from exc
        async with self._lock:
            current = self._state.operations.get((writer_id, operation_id))
            if current is None or current[0] != record:
                raise _error(PublicErrorCode.OPERATION_PENDING, retryable=True)
            if self._pending_import(writer.session_id):
                raise _error(PublicErrorCode.OPERATION_PENDING, retryable=True)
            self._state.frozen_cases[(writer_id, operation_id)] = case
            _, lease = self._replace_pending_record(record)
            return lease

    async def freeze_case(
        self,
        session_id: str,
        writer_id: str,
        expected_frontier: int | None,
        request_id: str,
        request_digest: str,
    ) -> FrozenCase | CheckCommitResult:
        key = (writer_id, request_id)
        try:
            result = await self._freeze_case_unrecorded(
                session_id, writer_id, expected_frontier, request_id, request_digest
            )
        except PublicOperationError as exc:
            stage = check_admission_stage(exc)
            if stage is not None:
                # Synchronous on purpose: no await may separate the answer from its note, and a
                # cancelled lock wait must never discard an admission that already happened.
                note_check_admission_refusal(self._state, key, stage, _now(self._clock))
            raise
        self._state.check_admissions.pop(key, None)
        return result

    async def lookup_check_admission(
        self, writer_id: str, operation_id: str
    ) -> CheckAdmissionRecord | None:
        async with self._lock:
            return check_admission_record(self._state, (writer_id, operation_id), _now(self._clock))

    async def _refresh_review_input_case(
        self,
        prior_record: OperationRecord,
        *,
        session_id: str,
        writer_id: str,
        request_id: str,
    ) -> tuple[DeterministicCase, OperationLease]:
        """Rebuild a parked check after a same-session statement amendment.

        A review-input suspension releases the observation barrier so a matching plan amendment
        can append a statement-carrying event. Its original resume object therefore points at a
        deliberately older case. Reusing that object on exact check replay would silently discard
        the amended statement. Re-pin the case while retaining the check request identity, then
        re-enter the local phase so deterministic policies are recomputed from the new frontier.
        """

        if prior_record.suspension_kind is not CheckSuspensionKind.REVIEW_INPUT:
            raise ValueError("review_input_refresh_kind_invalid")
        if prior_record.resume_object_ref is None:
            raise _error(PublicErrorCode.STORAGE_CORRUPT)
        if prior_record.resume_object_ref.metadata.kind is not ObjectKind.DETERMINISTIC_RESULT:
            raise _error(PublicErrorCode.STORAGE_CORRUPT)

        old_result_raw = await _open_exact_object(self._objects, prior_record.resume_object_ref)
        old_result = _strict_mapping(
            strict_json_parse(old_result_raw), reason="deterministic_result_shape_invalid"
        )
        old_prior = _strict_mapping(
            old_result.get("prior_resume"), reason="deterministic_result_pointer_invalid"
        )
        if frozenset(old_prior) != frozenset({"object_id", "envelope_digest", "commitment"}):
            raise _error(PublicErrorCode.STORAGE_CORRUPT)

        async with self._lock:
            current = self._state.operations.get((writer_id, request_id))
            if current is None or current[0] != prior_record:
                raise _error(PublicErrorCode.OPERATION_PENDING, retryable=True)
            projection = self._state.projection
            records = self._state.records
            object_refs = dict(self._state.object_refs)
            frontier = Frontier(projection.frontier, projection.head_digest)
            writer = self._state.writers.get(writer_id)
            if writer is None or writer.session_id != session_id:
                raise _error(PublicErrorCode.SESSION_NOT_FOUND)
            if self._pending_import(session_id):
                raise _error(PublicErrorCode.OPERATION_PENDING, retryable=True)

        availability = await self.load_case_availability(session_id, frontier, projection)

        def build() -> tuple[DeterministicCase, str, bytes]:
            try:
                case = build_deterministic_case(
                    projection,
                    records,
                    availability,
                    _projection_validated=True,
                )
            except ValueError as exc:
                if str(exc) == "deterministic_case_invalid":
                    raise _error(PublicErrorCode.STORAGE_CORRUPT) from exc
                raise
            dependency = _case_dependency_digest(case)
            case_json = deterministic_case_to_json(case)
            encoded = canonical_encode(
                {
                    "schema_version": "1.0.0",
                    "task_id": self._task_id,
                    "case": case_json,
                    "case_digest": canonical_digest(case_json),
                    "dependency_digest": dependency,
                    "frontier": dict(case.frontier.as_wire().items()),
                    "request_digest": prior_record.request_digest,
                    "request_id": request_id,
                    "session_id": session_id,
                    "writer_id": writer_id,
                }
            )
            return case, dependency, encoded

        case, dependency, resume_bytes = await _run_blocking_joined(build)
        created_at = _now(self._clock)
        staged_resume = await self._objects.stage(
            ObjectSource(data=resume_bytes, declared_size=len(resume_bytes)),
            ObjectMetadata(
                ObjectKind.CHECK_RESUME,
                "application/vnd.yoetz.check-resume+json",
                self._task_id,
                created_at,
            ),
        )
        resume_ref = await self._objects.finalize(staged_resume)
        async with self._lock:
            current = self._state.operations.get((writer_id, request_id))
            live_frontier = Frontier(
                self._state.projection.frontier, self._state.projection.head_digest
            )
            if (
                current is None
                or current[0] != prior_record
                or live_frontier != frontier
                or self._state.object_refs != object_refs
                or self._pending_import(session_id)
            ):
                raise check_admission_refused(CheckAdmissionStage.ACQUISITION_CONTENDED)
            self._state.frozen_cases[(writer_id, request_id)] = case
            self._remember_dependency_digest((writer_id, request_id), case, dependency)
            _, renewed = self._replace_pending_record(
                prior_record,
                # Re-enter the local phase so execute_check_commit recomputes deterministic
                # assessments from the newly bound case before semantic admission. Repointing a
                # stale deterministic result at a newer frontier would preserve findings for
                # material events appended while the input suspension was open.
                phase=CheckPhase.RESERVED,
                resume_object_ref=resume_ref,
            )
            return case, renewed

    async def _freeze_case_unrecorded(
        self,
        session_id: str,
        writer_id: str,
        expected_frontier: int | None,
        request_id: str,
        request_digest: str,
    ) -> FrozenCase | CheckCommitResult:
        key = (writer_id, request_id)
        prior_record: OperationRecord | None = None
        projection: ProjectionState | None = None
        frontier: Frontier | None = None
        records: tuple[LedgerRecord, ...] | None = None
        object_refs: dict[str, ObjectRef] | None = None
        acquisition_reservation: _CheckReservation | None = None
        async with self._lock:
            prior = self._state.operations.get(key)
            if prior is not None:
                record = prior[0]
                if record.request_digest != request_digest:
                    raise _error(PublicErrorCode.IDEMPOTENCY_CONFLICT)
                if record.state is OperationState.COMPLETE:
                    result = self._state.check_results.get(key)
                    if result is not None:
                        return replace(result, outcome="replayed")
                    stored_error = self._state.check_errors.get(key)
                    if stored_error is not None:
                        raise stored_error
                    raise _error(PublicErrorCode.STORAGE_CORRUPT)
                if record.state is OperationState.QUARANTINED:
                    stored_error = self._state.check_errors.get(key)
                    if stored_error is not None:
                        raise stored_error
                    raise _error(
                        PublicErrorCode.STORAGE_CORRUPT,
                        quarantine_code=(
                            record.quarantine_code.value
                            if record.quarantine_code is not None
                            else None
                        ),
                    )
                writer = self._state.writers.get(writer_id)
                if writer is None or writer.session_id != session_id:
                    raise _error(PublicErrorCode.SESSION_NOT_FOUND)
                assert record.lease_expires_at is not None
                if record.lease_expires_at > _now(self._clock) and record.owner_generation == str(
                    self._fence.owner_generation
                ):
                    raise _error(PublicErrorCode.OPERATION_PENDING, retryable=True)
                if self._pending_import(session_id):
                    raise _error(PublicErrorCode.OPERATION_PENDING, retryable=True)
                prior_record = record
            else:
                if self._pending_import(session_id):
                    raise check_admission_refused(CheckAdmissionStage.IMPORT_PENDING)
                projection = self._state.projection
                frontier = Frontier(projection.frontier, projection.head_digest)
                # Observation-only motion past the caller's frontier is tolerated by freezing at
                # the real head: the case then covers the drained records instead of racing them.
                if (
                    expected_frontier is not None
                    and expected_frontier != frontier.sequence
                    and not (
                        expected_frontier < frontier.sequence
                        and self._observation_only_since_unlocked(expected_frontier)
                    )
                ):
                    raise _frontier_conflict(frontier)
                records = self._state.records
                object_refs = dict(self._state.object_refs)
                writer = self._state.writers.get(writer_id)
                if writer is None or writer.session_id != session_id:
                    raise _error(PublicErrorCode.SESSION_NOT_FOUND)
                # Arm the observation-append barrier before this lock is released, or the drain
                # that stayed active through acquisition would race the freeze it just tolerated.
                reservation = self._state.check_reservations.get(key)
                if reservation is not None and reservation.expires_at > _now(self._clock):
                    raise check_admission_refused(CheckAdmissionStage.ACQUIRING)
                acquisition_reservation = _CheckReservation(
                    session_id,
                    _now(self._clock) + timedelta(seconds=CHECK_ACQUISITION_RESERVATION_SECONDS),
                )
                self._state.check_reservations[key] = acquisition_reservation
        if prior_record is not None:
            assert self._objects is not None
            if prior_record.suspension_kind is CheckSuspensionKind.REVIEW_INPUT:
                case, renewed = await self._refresh_review_input_case(
                    prior_record,
                    session_id=session_id,
                    writer_id=writer_id,
                    request_id=request_id,
                )
                return FrozenCase(case, renewed)
            try:
                case = await load_frozen_case_from_resume(
                    self._objects,
                    prior_record,
                    task=self._task_id,
                    session=session_id,
                )
            except (KeyError, OSError, TypeError, ValueError) as exc:
                raise _error(PublicErrorCode.STORAGE_CORRUPT) from exc
            async with self._lock:
                current = self._state.operations.get(key)
                if current is None or current[0] != prior_record:
                    raise _error(PublicErrorCode.OPERATION_PENDING, retryable=True)
                if self._pending_import(session_id):
                    raise _error(PublicErrorCode.OPERATION_PENDING, retryable=True)
                self._state.frozen_cases[key] = case
                _, renewed = self._replace_pending_record(prior_record)
                return FrozenCase(case, renewed)
        assert projection is not None and frontier is not None and records is not None
        assert object_refs is not None
        try:
            availability = await self.load_case_availability(session_id, frontier, projection)
            frozen_projection = projection
            frozen_records = records
            frozen_frontier = frontier

            def freeze() -> tuple[DeterministicCase, str, bytes]:
                # ``projection`` and ``records`` were read together under the ledger lock, so the
                # projection is this adapter's replay of exactly these records; the case builder
                # still re-authenticates the chain and its frontier/digest (issue #886).
                try:
                    built = build_deterministic_case(
                        frozen_projection,
                        frozen_records,
                        availability,
                        _projection_validated=True,
                    )
                except ValueError as exc:
                    if str(exc) == "deterministic_case_invalid":
                        raise _error(PublicErrorCode.STORAGE_CORRUPT) from exc
                    raise
                digest = _case_dependency_digest(built)
                case_json = deterministic_case_to_json(built)
                encoded = canonical_encode(
                    {
                        "schema_version": "1.0.0",
                        "task_id": self._task_id,
                        "case": case_json,
                        "case_digest": canonical_digest(case_json),
                        "dependency_digest": digest,
                        "frontier": frozen_frontier.as_wire(),
                        "request_digest": request_digest,
                        "request_id": request_id,
                        "session_id": session_id,
                        "writer_id": writer_id,
                    }
                )
                return built, digest, encoded

            case, dependency, case_bytes = await _run_blocking_joined(freeze)
            self._remember_dependency_digest(key, case, dependency)
            assert self._objects is not None
            created_at = _now(self._clock)
            staged = await self._objects.stage(
                ObjectSource(data=case_bytes, declared_size=len(case_bytes)),
                ObjectMetadata(
                    ObjectKind.CHECK_RESUME,
                    "application/vnd.yoetz.check-resume+json",
                    self._task_id,
                    created_at,
                ),
            )
            resume_ref = await self._objects.finalize(staged)
            async with self._lock:
                if key in self._state.operations:
                    # Another invocation admitted this exact key after this one's reservation
                    # lapsed; the replay converges on that operation.
                    raise check_admission_refused(CheckAdmissionStage.ACQUIRING)
                current_reservation = self._state.check_reservations.get(key)
                if (
                    acquisition_reservation is not None
                    and current_reservation is not acquisition_reservation
                ):
                    # A successor may replace an expired reservation while this invocation is
                    # staging.  Its exact token owns the admission; this stale attempt must not
                    # overwrite the successor or win the race itself.
                    raise check_admission_refused(
                        CheckAdmissionStage.ACQUIRING
                        if current_reservation is not None
                        else CheckAdmissionStage.ACQUISITION_CONTENDED
                    )
                current = Frontier(
                    self._state.projection.frontier, self._state.projection.head_digest
                )
                if current != frontier or self._pending_import(session_id):
                    raise _frontier_conflict(current)
                if self._state.object_refs != object_refs:
                    # Case availability includes the object inventory.  A concurrent inventory
                    # refresh can change that input without moving the ledger frontier, so the
                    # staged case must be retried instead of admitting stale availability.
                    raise check_admission_refused(CheckAdmissionStage.ACQUISITION_CONTENDED)
                operation = OperationRecord(
                    writer_id,
                    request_id,
                    OperationKind.CHECK,
                    request_digest,
                    OperationState.PENDING,
                    CheckPhase.RESERVED,
                    str(self._fence.owner_generation),
                    self._fence.service_instance_id,
                    1,
                    _now(self._clock) + timedelta(seconds=60),
                    resume_ref,
                    None,
                    None,
                    None,
                    None,
                    None,
                )
                self._state.frozen_cases[key] = case
                self._state.operations[key] = (operation, None)
                return FrozenCase(case, self._lease_for(operation))
        finally:
            # The frozen case (registered above on success) carries the barrier from here on. An
            # expired acquisition may have been replaced under the same request key, so release
            # only the exact reservation this invocation installed.
            async with self._lock:
                if self._state.check_reservations.get(key) is acquisition_reservation:
                    self._state.check_reservations.pop(key, None)

    async def advance_check_phase(
        self,
        lease: OperationLease,
        expected_phase: CheckPhase,
        next_phase: CheckPhase,
        durable_object_ref: ObjectRef | None = None,
    ) -> OperationLease:
        edges = {
            (CheckPhase.RESERVED, CheckPhase.LOCAL_READY),
            (CheckPhase.LOCAL_READY, CheckPhase.SEMANTIC_WAIT),
            (CheckPhase.LOCAL_READY, CheckPhase.READY_TO_FINALIZE),
            (CheckPhase.SEMANTIC_WAIT, CheckPhase.READY_TO_FINALIZE),
        }
        if (expected_phase, next_phase) not in edges:
            raise _error(PublicErrorCode.INVALID_REQUEST)
        if expected_phase is CheckPhase.RESERVED:
            if (
                durable_object_ref is None
                or durable_object_ref.metadata.kind is not ObjectKind.DETERMINISTIC_RESULT
                or durable_object_ref.metadata.task_id != self._task_id
                or durable_object_ref.metadata.media_type
                != "application/vnd.yoetz.deterministic-result+json"
            ):
                raise _error(PublicErrorCode.INVALID_REQUEST)
            assert self._objects is not None
            try:
                resolved = await self._objects.resolve_verified(
                    durable_object_ref.object_id,
                    durable_object_ref.envelope_digest,
                )
            except (KeyError, OSError, TypeError, ValueError) as exc:
                raise _error(PublicErrorCode.INVALID_REQUEST) from exc
            if resolved != durable_object_ref:
                raise _error(PublicErrorCode.INVALID_REQUEST)
        elif durable_object_ref is not None:
            raise _error(PublicErrorCode.INVALID_REQUEST)
        async with self._lock:
            record = self._require_lease(lease)
            if record.phase is not expected_phase:
                raise _error(PublicErrorCode.OPERATION_PENDING, retryable=True)
            _, replacement = self._replace_pending_record(
                record,
                phase=next_phase,
                resume_object_ref=durable_object_ref,
            )
            return replacement

    async def enqueue_semantic_job(
        self, lease: OperationLease, case_digest: str, case_object_ref: ObjectRef
    ) -> SemanticJobRecord:
        async with self._lock:
            record = self._require_lease(lease)
            if record.phase is not CheckPhase.SEMANTIC_WAIT:
                raise _error(PublicErrorCode.INVALID_REQUEST)
            identity = (lease.writer_id, lease.operation_id, case_digest)
            existing_id = self._state.job_by_case.get(identity)
            if existing_id is not None:
                return self._state.jobs[existing_id]
            assert self._ids is not None
            job_id = self._ids.new(IdKind.SEMANTIC_JOB)
            job = SemanticJobRecord(
                job_id,
                lease.writer_id,
                lease.operation_id,
                case_digest,
                case_object_ref,
                "queued",
                0,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            )
            self._state.jobs[job_id] = job
            self._state.job_by_case[identity] = job_id
            return job

    async def suspend_check_for_repository_grant(self, lease: OperationLease) -> None:
        """Durably mark and expire the lease for a pre-job standing-grant suspension.

        The marker also releases the observation frozen-case barrier for this
        operation: the ceremony may never complete, and same-request replay
        re-installs the barrier when it reclaims the lease.
        """

        async with self._lock:
            record = self._require_lease(lease)
            if record.phase is not CheckPhase.SEMANTIC_WAIT or any(
                job.writer_id == lease.writer_id and job.operation_id == lease.operation_id
                for job in self._state.jobs.values()
            ):
                raise _error(PublicErrorCode.OPERATION_PENDING, retryable=True)
            suspended = replace(
                record,
                lease_expires_at=_now(self._clock),
                suspension_kind=CheckSuspensionKind.REPOSITORY_GRANT,
            )
            self._state.operations[(record.writer_id, record.operation_id)] = (suspended, None)

    async def suspend_check_for_review_input(self, lease: OperationLease) -> None:
        """Durably park a pre-dispatch check until its task statement is supplied."""

        async with self._lock:
            record = self._require_lease(lease)
            if record.phase is not CheckPhase.SEMANTIC_WAIT or any(
                job.writer_id == lease.writer_id and job.operation_id == lease.operation_id
                for job in self._state.jobs.values()
            ):
                raise _error(PublicErrorCode.OPERATION_PENDING, retryable=True)
            suspended = replace(
                record,
                lease_expires_at=_now(self._clock),
                suspension_kind=CheckSuspensionKind.REVIEW_INPUT,
            )
            self._state.operations[(record.writer_id, record.operation_id)] = (suspended, None)

    async def claim_semantic_job(self, lease: OperationLease, job_id: str) -> SemanticAttemptHandle:
        async with self._lock:
            operation = self._require_lease(lease)
            if operation.phase is not CheckPhase.SEMANTIC_WAIT:
                raise _error(PublicErrorCode.INVALID_REQUEST)
            job = self._state.jobs.get(job_id)
            if (
                job is None
                or job.writer_id != lease.writer_id
                or job.operation_id != lease.operation_id
            ):
                raise _error(PublicErrorCode.INVALID_REQUEST)
            now = _now(self._clock)
            # A live disclosure wait suspends the lease clock. The human may take longer than a
            # lease TTL to answer. Reclaim rebinds the started attempt rather than minting a new
            # provider request id, preserving the prepared bytes the human approved. The bound on
            # this wait is the proposal's own expiry, which the resume path checks before
            # dispatching anything.
            wait = self._state.disclosure_waits.get(job_id)
            if (
                wait is not None
                and wait.state == "awaiting"
                and job.active_attempt_id is not None
                and wait.attempt_id == job.active_attempt_id
            ):
                attempt = self._state.attempts.get(job.active_attempt_id)
                if attempt is not None and attempt.state in {"started", "response_durable"}:
                    return self._rebind_semantic_attempt(job, attempt, lease)
            if (
                job.state == "leased"
                and job.lease_expires_at is not None
                and job.lease_expires_at > now
            ):
                # Same owner still holding a live lease: resume the active started attempt.
                # Crash-before-authorization-consumption must not mint a new attempt identity.
                if job.lease_owner_id == lease.lease_owner_id and job.active_attempt_id is not None:
                    attempt = self._state.attempts.get(job.active_attempt_id)
                    if attempt is not None and attempt.state in {"started", "response_durable"}:
                        return self._rebind_semantic_attempt(job, attempt, lease)
                raise _error(PublicErrorCode.OPERATION_PENDING, retryable=True)
            if job.state not in {"queued", "leased"}:
                raise _error(PublicErrorCode.OPERATION_PENDING, retryable=True)
            # Expired or reclaimed lease: close the prior started attempt before a new ordinal.
            if (
                job.state == "leased"
                and job.active_attempt_id is not None
                and job.active_attempt_id in self._state.attempts
            ):
                prior = self._state.attempts[job.active_attempt_id]
                if prior.state in {"started", "response_durable"}:
                    # A provider may still be running after the old operation lease expires.
                    # Rebind that durable attempt to the freshly fenced lease so replay reports
                    # the same provider request instead of dispatching a duplicate. A durable
                    # response is included because a crash can occur between response
                    # publication and selection; replay must select it rather than dispatching
                    # a new request.
                    return self._rebind_semantic_attempt(job, prior, lease)
            ordinal = job.attempt_count + 1
            expiry = lease.lease_expires_at
            handle = SemanticAttemptHandle(
                job_id,
                self._ids.new(IdKind.SEMANTIC_ATTEMPT),
                ordinal,
                self._ids.new(IdKind.REQUEST),
                lease.writer_id,
                lease.operation_id,
                lease.owner_generation,
                lease.lease_owner_id,
                ordinal,
                expiry,
                lease.frontier,
                lease.dependency_digest,
            )
            self._state.attempts[handle.attempt_id] = _AttemptState(
                handle, "started", started_at=now
            )
            self._state.jobs[job_id] = replace(
                job,
                state="leased",
                attempt_count=ordinal,
                active_attempt_id=handle.attempt_id,
                lease_owner_id=lease.lease_owner_id,
                lease_generation=ordinal,
                lease_expires_at=expiry,
            )
            return handle

    def _rebind_semantic_attempt(
        self,
        job: SemanticJobRecord,
        attempt: _AttemptState,
        lease: OperationLease,
    ) -> SemanticAttemptHandle:
        if attempt.handle.job_id != job.job_id or attempt.state not in {
            "started",
            "response_durable",
        }:
            raise _error(PublicErrorCode.STORAGE_CORRUPT)
        rebound = replace(
            attempt.handle,
            owner_generation=lease.owner_generation,
            lease_owner_id=lease.lease_owner_id,
            lease_expires_at=lease.lease_expires_at,
            frontier=lease.frontier,
            dependency_digest=lease.dependency_digest,
        )
        self._state.attempts[attempt.handle.attempt_id] = replace(
            attempt,
            handle=rebound,
        )
        self._state.jobs[job.job_id] = replace(
            job,
            state="leased",
            lease_owner_id=lease.lease_owner_id,
            lease_expires_at=lease.lease_expires_at,
        )
        return rebound

    async def record_attempt_outcome(
        self,
        handle: SemanticAttemptHandle,
        outcome: AttemptOutcome,
        result_object_ref: ObjectRef | None = None,
        terminal_code: SemanticReason | None = None,
        token_usage: RuntimeTokenUsage | None = None,
    ) -> None:
        async with self._lock:
            attempt = self._state.attempts.get(handle.attempt_id)
            if attempt is None or attempt.handle != handle or attempt.state != "started":
                raise _error(PublicErrorCode.OPERATION_PENDING, retryable=True)
            job = self._state.jobs[handle.job_id]
            if outcome is AttemptOutcome.SELECTED:
                raise _error(PublicErrorCode.INVALID_REQUEST)
            if token_usage is not None and type(token_usage) is not RuntimeTokenUsage:
                raise _error(PublicErrorCode.INVALID_REQUEST)
            if outcome is AttemptOutcome.RESPONSE_DURABLE:
                if result_object_ref is None or terminal_code is not None:
                    raise _error(PublicErrorCode.INVALID_REQUEST)
                self._state.attempts[handle.attempt_id] = replace(
                    attempt,
                    state="response_durable",
                    result_object_ref=result_object_ref,
                    token_usage=token_usage,
                )
                return
            if terminal_code is None:
                raise _error(PublicErrorCode.INVALID_REQUEST)
            self._state.attempts[handle.attempt_id] = replace(
                attempt,
                state=outcome.value,
                result_object_ref=result_object_ref,
                terminal_code=terminal_code,
                token_usage=token_usage,
            )
            if outcome is AttemptOutcome.FAILED:
                self._state.jobs[handle.job_id] = replace(
                    job,
                    state="failed",
                    active_attempt_id=None,
                    lease_owner_id=None,
                    lease_generation=None,
                    lease_expires_at=None,
                    terminal_code=terminal_code,
                    terminal_at=_now(self._clock),
                )
            else:
                self._state.jobs[handle.job_id] = replace(
                    job,
                    state="queued",
                    active_attempt_id=None,
                    lease_owner_id=None,
                    lease_generation=None,
                    lease_expires_at=None,
                )

    async def fail_semantic_job(
        self,
        lease: OperationLease,
        job_id: str,
        terminal_code: SemanticReason,
    ) -> SemanticJobRecord:
        """Terminally fail a queued job when no physical attempt is active."""

        async with self._lock:
            operation = self._require_lease(lease)
            job = self._state.jobs.get(job_id)
            if (
                operation.phase is not CheckPhase.SEMANTIC_WAIT
                or job is None
                or job.writer_id != lease.writer_id
                or job.operation_id != lease.operation_id
                or job.state != "queued"
                or job.active_attempt_id is not None
                or terminal_code is SemanticReason.SEMANTIC_COMPLETED
            ):
                raise _error(PublicErrorCode.OPERATION_PENDING, retryable=True)
            failed = replace(
                job,
                state="failed",
                lease_owner_id=None,
                lease_generation=None,
                lease_expires_at=None,
                terminal_code=terminal_code,
                terminal_at=_now(self._clock),
            )
            self._state.jobs[job_id] = failed
            return failed

    async def select_attempt(
        self,
        lease: OperationLease,
        handle: SemanticAttemptHandle,
        selected_result_object_ref: ObjectRef,
    ) -> SelectedAttempt:
        async with self._lock:
            operation = self._require_lease(lease)
            attempt = self._state.attempts.get(handle.attempt_id)
            job = self._state.jobs.get(handle.job_id)
            if (
                operation.phase is not CheckPhase.SEMANTIC_WAIT
                or attempt is None
                or attempt.handle != handle
                or attempt.state != "response_durable"
                or attempt.result_object_ref != selected_result_object_ref
                or job is None
                or job.active_attempt_id != handle.attempt_id
            ):
                raise _error(PublicErrorCode.OPERATION_PENDING, retryable=True)
            selected_at = _now(self._clock)
            self._state.attempts[handle.attempt_id] = replace(
                attempt, state="selected", terminal_code=SemanticReason.SEMANTIC_COMPLETED
            )
            self._state.jobs[handle.job_id] = replace(
                job,
                state="succeeded",
                active_attempt_id=None,
                selected_attempt_id=handle.attempt_id,
                lease_owner_id=None,
                lease_generation=None,
                lease_expires_at=None,
                selected_result_object_ref=selected_result_object_ref,
                terminal_code=SemanticReason.SEMANTIC_COMPLETED,
                terminal_at=selected_at,
            )
            return SelectedAttempt(
                handle.job_id,
                handle.attempt_id,
                selected_result_object_ref,
                selected_at,
                lease.frontier,
                lease.dependency_digest,
            )

    async def record_task_change_base(self, ref: ObjectRef) -> bool:
        """Keep the first task-start base object (ADR-031) as an inventoried root."""

        if (
            type(ref) is not ObjectRef
            or ref.metadata.kind is not ObjectKind.CHANGE_CAPTURE
            or ref.metadata.media_type != TASK_CHANGE_BASE_MEDIA_TYPE
            or ref.metadata.task_id != self._task_id
        ):
            raise ValueError("task_change_base_invalid")
        async with self._lock:
            if self._state.task_change_base is not None:
                return False
            self._state.task_change_base = ref
            self._state.object_refs[ref.object_id] = ref
            return True

    async def load_task_change_base(self) -> ObjectRef | None:
        async with self._lock:
            return self._state.task_change_base

    async def load_semantic_job(
        self, writer_id: str, operation_id: str
    ) -> SemanticJobRecord | None:
        async with self._lock:
            matches = tuple(
                job
                for job in self._state.jobs.values()
                if job.writer_id == writer_id and job.operation_id == operation_id
            )
            if not matches:
                return None
            # One operation binds at most one durable AI-powered review job in practice; if multiple
            # case digests exist (should not), return the most recently enqueued by attempt_count.
            return max(matches, key=lambda item: (item.attempt_count, item.job_id))

    async def list_semantic_attempts(self, job_id: str) -> tuple[SemanticAttemptRecord, ...]:
        async with self._lock:
            if job_id not in self._state.jobs:
                return ()
            rows = [
                SemanticAttemptRecord(
                    attempt.handle.job_id,
                    attempt.handle.attempt_id,
                    attempt.handle.attempt_ordinal,
                    attempt.handle.provider_request_id,
                    cast(
                        Literal[
                            "started",
                            "response_durable",
                            "selected",
                            "failed",
                            "expired",
                            "late",
                        ],
                        attempt.state,
                    ),
                    attempt.terminal_code,
                    attempt.result_object_ref,
                    attempt.started_at,
                    attempt.token_usage,
                )
                for attempt in self._state.attempts.values()
                if attempt.handle.job_id == job_id
            ]
            rows.sort(key=lambda item: item.attempt_ordinal)
            return tuple(rows)

    async def record_disclosure_wait(
        self,
        handle: SemanticAttemptHandle,
        pending_id: str,
        pending_expires_at: datetime,
    ) -> SemanticDisclosureWait:
        async with self._lock:
            attempt = self._state.attempts.get(handle.attempt_id)
            if attempt is None or attempt.handle != handle or attempt.state != "started":
                raise _error(PublicErrorCode.OPERATION_PENDING, retryable=True)
            job = self._state.jobs.get(handle.job_id)
            if job is None or job.active_attempt_id != handle.attempt_id:
                raise _error(PublicErrorCode.OPERATION_PENDING, retryable=True)
            existing = self._state.disclosure_waits.get(handle.job_id)
            if existing is not None:
                # A second proposal on the same job means a fresh physical attempt asked for a
                # fresh decision. Re-recording over a live wait would let one decision authorize
                # bytes it never saw.
                if existing.state == "awaiting" and existing.attempt_id == handle.attempt_id:
                    return existing
                if existing.attempt_id == handle.attempt_id:
                    raise _error(PublicErrorCode.INVALID_REQUEST)
            wait = SemanticDisclosureWait(
                handle.job_id,
                handle.attempt_id,
                handle.writer_id,
                handle.operation_id,
                pending_id,
                pending_expires_at,
                "awaiting",
                None,
            )
            self._state.disclosure_waits[handle.job_id] = wait
            return wait

    async def load_disclosure_wait(
        self, writer_id: str, operation_id: str
    ) -> SemanticDisclosureWait | None:
        async with self._lock:
            matches = tuple(
                wait
                for wait in self._state.disclosure_waits.values()
                if wait.writer_id == writer_id and wait.operation_id == operation_id
            )
            if not matches:
                return None
            live = tuple(wait for wait in matches if wait.state == "awaiting")
            if live:
                return max(live, key=lambda item: item.job_id)
            return max(matches, key=lambda item: item.job_id)

    async def resolve_disclosure_wait(self, job_id: str) -> SemanticDisclosureWait:
        async with self._lock:
            wait = self._state.disclosure_waits.get(job_id)
            if wait is None:
                raise _error(PublicErrorCode.INVALID_REQUEST)
            # One-use. A denial or expiry resumes exactly once; a second attempt to consume the
            # same decision is a protocol error, not a silent replay.
            if wait.state != "awaiting":
                raise _error(PublicErrorCode.INVALID_REQUEST)
            resolved = replace(wait, state="resolved", resolved_at=_now(self._clock))
            self._state.disclosure_waits[job_id] = resolved
            return resolved

    async def begin_semantic_progress(
        self, job_id: str, queued_at: datetime, deadline_at: datetime
    ) -> None:
        progress = SemanticProgressRecord(
            job_id, 0, SemanticProgressPhase.QUEUED, queued_at, queued_at, deadline_at
        )
        async with self._lock:
            job = self._state.jobs.get(job_id)
            if (
                job is None
                or job.state not in {"queued", "leased"}
                or job_id in self._state.semantic_progress
            ):
                return
            self._state.semantic_progress[job_id] = progress

    async def advance_semantic_progress(
        self,
        handle: SemanticAttemptHandle,
        phase: SemanticProgressPhase,
        observed_at: datetime,
    ) -> bool:
        if (
            type(handle) is not SemanticAttemptHandle
            or type(phase) is not SemanticProgressPhase
            or phase is SemanticProgressPhase.TERMINAL
            or type(observed_at) is not datetime
        ):
            raise _error(PublicErrorCode.INVALID_REQUEST)
        async with self._lock:
            job = self._state.jobs.get(handle.job_id)
            current = self._state.semantic_progress.get(handle.job_id)
            if (
                job is None
                or current is None
                or job.state != "leased"
                or job.active_attempt_id != handle.attempt_id
            ):
                return False
            rank = SEMANTIC_PROGRESS_PHASE_RANK
            if (handle.attempt_ordinal, rank[phase]) <= (
                current.attempt_ordinal,
                rank[current.phase],
            ):
                return False
            self._state.semantic_progress[handle.job_id] = replace(
                current,
                attempt_ordinal=handle.attempt_ordinal,
                phase=phase,
                phase_entered_at=max(observed_at, current.phase_entered_at),
            )
            return True

    async def load_semantic_progress(
        self, writer_id: str, operation_id: str
    ) -> SemanticProgressRecord | None:
        async with self._lock:
            matches = tuple(
                job
                for job in self._state.jobs.values()
                if job.writer_id == writer_id and job.operation_id == operation_id
            )
            if not matches:
                return None
            job = max(matches, key=lambda item: (item.attempt_count, item.job_id))
            current = self._state.semantic_progress.get(job.job_id)
            if current is None:
                return None
            if job.state in {"queued", "leased"}:
                return current
            assert job.terminal_at is not None
            return replace(
                current,
                phase=SemanticProgressPhase.TERMINAL,
                phase_entered_at=max(job.terminal_at, current.phase_entered_at),
                terminal_outcome=cast(Literal["succeeded", "failed", "quarantined"], job.state),
                terminal_reason=job.terminal_code,
            )

    async def renew_leases(self, lease: OperationLease) -> OperationLease:
        async with self._lock:
            record = self._require_lease(lease)
            now = _now(self._clock)
            live_jobs = tuple(
                job
                for job in self._state.jobs.values()
                if job.writer_id == record.writer_id
                and job.operation_id == record.operation_id
                and job.state in {"queued", "leased"}
            )
            if len(live_jobs) > 1:
                raise _error(PublicErrorCode.STORAGE_CORRUPT)
            job = live_jobs[0] if live_jobs else None
            bound: datetime | None = None
            if job is not None:
                assert self._objects is not None
                try:
                    bound = await _semantic_execution_lease_bound(
                        self._objects,
                        job,
                        task=self._task_id,
                        now=now,
                    )
                except (KeyError, OSError, TypeError, ValueError) as exc:
                    raise _error(PublicErrorCode.STORAGE_CORRUPT) from exc
            if bound is None:
                assert record.lease_expires_at is not None
                expiry = max(
                    record.lease_expires_at,
                    now + timedelta(seconds=_OPERATION_LEASE_SECONDS),
                )
            else:
                expiry = bound
                if expiry <= now:
                    raise _error(PublicErrorCode.OPERATION_PENDING, retryable=True)
            active_job_id = (
                job.job_id
                if job is not None
                and job.state == "leased"
                and job.lease_owner_id == record.lease_owner_id
                else None
            )
            _, replacement = self._replace_pending_record(
                record,
                lease_expires_at=expiry,
                semantic_job_id=active_job_id,
            )
            return replacement

    async def commit_check_if_current(
        self,
        frozen: FrozenCase,
        findings: RankedFindings,
        policy_executions: tuple[CheckPolicyExecution, ...],
        semantic_status: SemanticStatus,
        semantic_reason: SemanticReason,
        semantic_provenance: SemanticProvenance | None,
        request_id: str,
        *,
        scope: CheckScopeModel | None = None,
        semantic_conclusion: str | None = None,
        review_summary: str | None = None,
        verified: tuple[JsonObject, ...] = (),
        prior_finding_verdicts: tuple[PriorFindingVerdictRecord, ...] = (),
        missing_for_assessment: tuple[MissingForAssessmentItem, ...] = (),
        check_change_files: CheckChangeShownFiles | None = None,
        semantic_included_refs: tuple[str, ...] | None = None,
        semantic_withheld_item_ids: tuple[str, ...] = (),
        review_input_manifest: JsonObject | None = None,
        totals: JsonObject | None = None,
        semantic_redacted_values: tuple[SemanticRedactedValue, ...] = (),
        semantic_route_required: bool | None = None,
        deliverable_states: tuple[DeliverableState, ...] = (),
    ) -> CheckCommitResult:
        key = (frozen.lease.writer_id, frozen.lease.operation_id)
        async with self._lock:
            prior_result = self._state.check_results.get(key)
            if prior_result is not None:
                return replace(prior_result, outcome="replayed")
            stored_error = self._state.check_errors.get(key)
            if stored_error is not None:
                raise stored_error
            record = self._require_lease(frozen.lease)
            if (
                record.phase is not CheckPhase.READY_TO_FINALIZE
                or request_id != record.operation_id
            ):
                raise _error(PublicErrorCode.OPERATION_PENDING, retryable=True)
            current = Frontier(self._state.projection.frontier, self._state.projection.head_digest)
            frozen_frontier = frozen.case.frontier
            observation_only_suffix = (
                current.sequence > frozen_frontier.sequence
                and self._observation_only_since_unlocked(frozen_frontier.sequence)
            )
            if (
                current != frozen_frontier and not observation_only_suffix
            ) or self._state.frozen_cases.get(key) != frozen.case:
                failure = _frontier_conflict(current)
                canonical = canonical_encode(
                    {
                        "code": failure.code.value,
                        "reason_code": "frontier_changed",
                        "sequence": current.sequence,
                        "head_digest": current.head_digest,
                    }
                )
                terminal = replace(
                    record,
                    state=OperationState.COMPLETE,
                    phase=CheckPhase.TERMINAL,
                    owner_generation=None,
                    lease_owner_id=None,
                    lease_generation=None,
                    lease_expires_at=None,
                    resume_object_ref=None,
                    result_canonical=canonical,
                    result_digest=f"sha256:{hashlib.sha256(canonical).hexdigest()}",
                    result_locator=None,
                    terminal_at=_now(self._clock),
                )
                self._state.operations[key] = (terminal, None)
                self._state.check_errors[key] = failure
                raise failure
            if self._pending_import(frozen.lease.session_id):
                raise _error(PublicErrorCode.OPERATION_PENDING, retryable=True)
            snapshot_records = self._state.records
            snapshot_projection = self._state.projection
            writer = self._state.writers.get(frozen.lease.writer_id)
            if writer is None:
                raise _error(PublicErrorCode.STORAGE_CORRUPT)
            request_digest_value = record.request_digest

        assert self._ids is not None and self._objects is not None
        # A finding that kept a previously recorded ID is already on the ledger; re-emitting it
        # would grow the record per re-check, so the check only cites it in returned_finding_ids.
        event_payloads: list[tuple[EventId, EventPayload]] = [
            (event_id(self._ids.new(IdKind.EVENT)), finding)
            for finding in findings.findings
            if (prior := snapshot_projection.findings.get(finding.finding_id)) is None
            or prior.payload is None
        ]
        check_payload = CheckRecordedPayload(
            mode=(
                CheckMode.DETERMINISTIC_ONLY
                if semantic_status is SemanticStatus.NOT_REQUESTED
                else CheckMode.SEMANTIC_IF_CONFIGURED
            ),
            policies=tuple(
                PolicyVersion(execution.policy_id, execution.policy_version)
                for execution in policy_executions
            ),
            # The normalized request scope is what a later reader needs to know which issues
            # this check could speak to (issue #458); omitted scope is the whole case.
            scope=CheckScopeModel(claim_ids=(), obligation_ids=()) if scope is None else scope,
            policy_executions=tuple(
                CheckPolicyExecutionModel.model_validate(
                    {
                        "policy_id": execution.policy_id,
                        "policy_version": execution.policy_version,
                        "outcome": execution.outcome,
                        "reason": execution.reason,
                    }
                )
                for execution in policy_executions
            ),
            subject_frontier=frozen.case.frontier,
            verdict=findings.verdict,
            # Ranking is by priority/actionability/coverage, not finding ID. The event field
            # is a canonical unique ASCII-ascending set; presentation order stays on the
            # check result's findings tuple.
            returned_finding_ids=tuple(
                sorted((item.finding_id for item in findings.findings), key=str.encode)
            ),
            suppressed_count=findings.suppressed_count,
            coverage=findings.coverage,
            semantic_status=semantic_status,
            semantic_reason=semantic_reason,
            engine_version="0.1.0",
            projection_version=PROJECTION_VERSION,
            semantic_provenance=semantic_provenance,
            semantic_conclusion=semantic_conclusion,
            review_summary=review_summary,
            verified=verified,
            missing_for_assessment=missing_for_assessment,
            prior_finding_verdicts=prior_finding_verdicts,
            check_change_files=check_change_files,
            semantic_included_refs=semantic_included_refs,
            semantic_withheld_item_ids=semantic_withheld_item_ids,
            semantic_redacted_values=semantic_redacted_values,
            semantic_route_required=semantic_route_required,
            deliverable_states=deliverable_states,
            review_input_manifest=review_input_manifest,
            totals=(
                build_check_totals(frozen.case, findings.findings, findings.suppressed_count)
                if totals is None
                else totals
            ),
        )
        event_payloads.append((event_id(self._ids.new(IdKind.EVENT)), check_payload))
        accepted_at = _now(self._clock)
        author = Actor(
            actor_id("yoetz.engine"),
            ActorType.YOETZ_ENGINE,
            AuthorshipAssurance.SERVICE_AUTHENTICATED,
        )
        entries: list[AppendEntry] = []
        for event, payload in event_payloads:
            payload_bytes = canonical_encode(encode_payload(payload))
            metadata = ObjectMetadata(
                ObjectKind.EVENT_PAYLOAD,
                media_type_for(
                    "finding_recorded"
                    if type(payload) is FindingRecordedPayload
                    else "check_recorded"
                ),
                self._task_id,
                accepted_at,
            )
            staged = await self._objects.stage(
                ObjectSource(data=payload_bytes, declared_size=len(payload_bytes)), metadata
            )
            payload_ref = await self._objects.finalize(staged)
            finding_schema_version = (
                FINDING_SNIPPET_EVENT_SCHEMA_VERSION
                if type(payload) is FindingRecordedPayload
                and (
                    payload.kind in {FindingKind.CODE_DEFECT, FindingKind.TASK_REQUIREMENT_UNMET}
                    or (payload.challenge is not None and payload.challenge.snippet is not None)
                )
                else FINDING_EVENT_SCHEMA_VERSION
            )
            schema = EventSchema(
                "finding_recorded" if type(payload) is FindingRecordedPayload else "check_recorded",
                finding_schema_version
                if type(payload) is FindingRecordedPayload
                else REVIEW_CHECK_EVENT_SCHEMA_VERSION
                if review_summary is not None or verified or check_payload.totals is not None
                else CHECK_EVENT_SCHEMA_VERSION
                if semantic_conclusion is not None
                else SEMANTIC_EVENT_SCHEMA_VERSION,
            )
            entries.append(
                AppendEntry(
                    EventDraft(
                        event,
                        schema,
                        timestamp_from_datetime(accepted_at),
                        (),
                        payload,
                        (),
                        (),
                    ),
                    author,
                    payload_ref,
                    payload_ref.commitment,
                    metadata.media_type,
                    payload_ref.plaintext_size,
                    PublicationChannel.ENGINE_DERIVED,
                    coverage_for_channel(PublicationChannel.ENGINE_DERIVED),
                    "projected",
                )
            )
        command = AppendCommand(
            self._task_id,
            frozen.lease.session_id,
            frozen.lease.writer_id,
            request_id,
            OperationKind.CHECK,
            request_digest_value,
            current.sequence,
            tuple(entries),
        )
        previous_ledger = current.head_digest
        previous_writer = writer.head_digest
        new_records: list[LedgerRecord] = []
        for offset in range(len(entries)):
            accepted = _record_preimage(
                command,
                offset,
                ingestion_sequence=current.sequence + offset + 1,
                writer_sequence=writer.next_sequence + offset,
                previous_ledger_digest=previous_ledger,
                previous_writer_digest=previous_writer,
                accepted_at=accepted_at,
            )
            new_records.append(accepted)
            previous_ledger = accepted.entry_digest
            previous_writer = accepted.entry_digest
        proposed_records = snapshot_records + tuple(new_records)
        appended_check_records = tuple(new_records)
        try:
            # The snapshot projection is the adapter-owned replay of ``snapshot_records``; the
            # commit below re-checks both under the lock before adopting this extension.
            proposed_projection = await _run_blocking_joined(
                lambda: replay_extension(
                    snapshot_projection, snapshot_records, appended_check_records
                )
            )
        except ValueError as exc:
            raise _error(PublicErrorCode.STORAGE_CORRUPT) from exc
        result_frontier = Frontier(proposed_projection.frontier, proposed_projection.head_digest)
        packs = tuple(
            f"{execution.policy_id}/{execution.policy_version}" for execution in policy_executions
        )
        result = CheckCommitResult(
            "committed",
            self._task_id,
            frozen.lease.session_id,
            frozen.lease.writer_id,
            request_id,
            frozen.case.frontier,
            result_frontier,
            findings.verdict,
            findings.findings,
            findings.suppressed_count,
            policy_executions,
            semantic_status,
            semantic_reason,
            semantic_provenance,
            findings.coverage,
            CheckVersionSlice("0.1", "0.1.0", PROJECTION_VERSION, packs),
            semantic_conclusion=check_payload.semantic_conclusion,
            review_summary=check_payload.review_summary,
            verified=check_payload.verified,
            missing_for_assessment=check_payload.missing_for_assessment,
            semantic_withheld_item_ids=check_payload.semantic_withheld_item_ids,
            review_input_manifest=check_payload.review_input_manifest,
            totals=check_payload.totals,
            semantic_redacted_values=check_payload.semantic_redacted_values,
            semantic_route_required=check_payload.semantic_route_required,
            deliverable_states=check_payload.deliverable_states,
        )
        canonical = canonical_encode(
            {
                "finding_ids": tuple(finding.finding_id for finding in findings.findings),
                "request_id": request_id,
                "result_frontier": result_frontier.as_wire(),
                "subject_frontier": frozen.case.frontier.as_wire(),
                "verdict": findings.verdict.value,
            }
        )
        from yoetz.ports.ledger import OperationResultLocator

        locator = OperationResultLocator(
            new_records[0].ledger.ingestion_sequence,
            new_records[-1].ledger.ingestion_sequence,
            None,
            tuple(sorted((row.event_id for row in new_records), key=str.encode)),
        )
        async with self._lock:
            current_record = self._require_lease(frozen.lease)
            current_head = Frontier(
                self._state.projection.frontier, self._state.projection.head_digest
            )
            if (
                current_record != record
                or current_head != current
                or self._state.records != snapshot_records
                or self._state.projection != snapshot_projection
                or self._pending_import(frozen.lease.session_id)
            ):
                raise _frontier_conflict(current_head)
            terminal = replace(
                current_record,
                state=OperationState.COMPLETE,
                phase=CheckPhase.TERMINAL,
                owner_generation=None,
                lease_owner_id=None,
                lease_generation=None,
                lease_expires_at=None,
                resume_object_ref=None,
                result_canonical=canonical,
                result_digest=f"sha256:{hashlib.sha256(canonical).hexdigest()}",
                result_locator=locator,
                terminal_at=accepted_at,
            )
            self._state.records = proposed_records
            self._state.projection = proposed_projection
            self._state.trusted_projections.remember(
                proposed_projection, proposed_records, appended_check_records
            )
            self._state.object_refs = {
                **self._state.object_refs,
                **{entry.payload_object.object_id: entry.payload_object for entry in entries},
            }
            self._state.writers = {
                **self._state.writers,
                frozen.lease.writer_id: _WriterState(
                    self._task_id,
                    frozen.lease.session_id,
                    writer.next_sequence + len(new_records),
                    previous_writer,
                ),
            }
            self._state.operations[key] = (terminal, None)
            self._state.check_results[key] = result
            return result

    async def fail_check_if_current(
        self, lease: OperationLease, failure: PublicOperationError
    ) -> None:
        """Terminalize an admitted check whose application pipeline failed unexpectedly.

        This is the last-resort durability path: it records no check event and advances no
        frontier, but it closes the exact operation so replay returns a stable terminal error
        instead of waiting forever on a lease that no worker can resume safely.
        """

        if failure.retryable:
            raise TypeError("retryable_check_failure_cannot_terminalize")
        canonical = canonical_encode(
            {
                "code": failure.code.value,
                "message": str(failure),
                "retryable": failure.retryable,
                "safe_details": dict(failure.safe_details),
            }
        )
        key = (lease.writer_id, lease.operation_id)
        async with self._lock:
            current = self._state.operations.get(key)
            if (
                current is not None
                and current[0].state is OperationState.COMPLETE
                and key in self._state.check_errors
            ):
                return
            record = self._require_lease(lease)
            terminal = replace(
                record,
                state=OperationState.COMPLETE,
                phase=CheckPhase.TERMINAL,
                owner_generation=None,
                lease_owner_id=None,
                lease_generation=None,
                lease_expires_at=None,
                resume_object_ref=None,
                result_canonical=canonical,
                result_digest=f"sha256:{hashlib.sha256(canonical).hexdigest()}",
                result_locator=None,
                terminal_at=_now(self._clock),
            )
            self._state.operations[key] = (terminal, None)
            self._state.check_errors[key] = failure
