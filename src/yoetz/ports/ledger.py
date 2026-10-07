"""Authoritative task-ledger boundary records and protocol."""

from __future__ import annotations

import hashlib
import re
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from types import MappingProxyType
from typing import Final, Literal, Protocol, cast

from yoetz.domain.coordination import (
    LineageAcceptance,
    LineageOrigin,
    SessionHealth,
    WorkState,
)
from yoetz.domain.events import (
    CheckChangeShownFiles,
    EventDraft,
    LedgerRecord,
    MissingForAssessmentItem,
)
from yoetz.domain.findings import (
    CheckVerdict,
    Finding,
    PriorFindingVerdictRecord,
    RankedFindings,
    RuntimeTokenUsage,
    SemanticProvenance,
)
from yoetz.domain.privacy import SourceAuthorship
from yoetz.domain.task_statement import SpecificationPreflight
from yoetz.domain.values import (
    Actor,
    Frontier,
    JsonObject,
    SemanticContinuation,
    format_rfc3339_millis,
    validate_commitment,
    validate_sha256_digest,
)
from yoetz.kernel.closure_readiness import ClosureReadinessFacts
from yoetz.kernel.deterministic_checks import CaseAvailabilityFacts, DeterministicCase
from yoetz.kernel.finding_todo import FindingTodoCounts
from yoetz.kernel.lineage import LineageRollupState
from yoetz.kernel.projections import ProjectionState
from yoetz.ports.objects import ObjectKind, ObjectRef
from yoetz.protocol.coverage import Coverage, PublicationChannel
from yoetz.protocol.errors import PublicErrorCode, PublicOperationError
from yoetz.protocol.ids import IdKind, validate_actor_id, validate_id, validate_opaque_item_id
from yoetz.protocol.models import (
    MAX_EVENTS_PER_BATCH,
    CheckScopeModel,
    SemanticProgressPhase,
    SemanticReason,
    SemanticStatus,
    StatusAssignmentItemModel,
    StatusCompactItemModel,
    StatusEvidenceItemModel,
    StatusFindingItemModel,
    StatusHistoryItemModel,
    StatusHistoryItemV14Model,
    StatusObligationItemModel,
    StatusResultItemModel,
    StatusVersionSliceModel,
    validate_semantic_outcome,
    validate_semantic_provenance_binding,
)
from yoetz.protocol.policy_packs import RECORDED_POLICY_PACKS

__all__ = [
    "CheckChecklistItem",
    "CheckFindingChecklist",
    "CheckOverallNext",
    "AcceptedEventSummary",
    "AppendCommand",
    "AppendEntry",
    "AppendResult",
    "AppendWarning",
    "AssignmentProjectionFilter",
    "AttemptOutcome",
    "CHECK_ACQUISITION_RESERVATION_SECONDS",
    "CHECK_ADMISSION_REASON_CODES",
    "CHECK_ADMISSION_RETRY_AFTER_MS",
    "CheckAdmissionRecord",
    "CheckAdmissionStage",
    "CheckAwaitingHuman",
    "CheckAdvisoryNote",
    "CheckChildPreviewItem",
    "CheckChildrenPreview",
    "CheckCommitResult",
    "CheckPhase",
    "CheckPolicyExecution",
    "CheckVersionSlice",
    "EvidenceProjectionFilter",
    "FindingProjectionPosition",
    "FindingsProjectionFilter",
    "FrozenCase",
    "HistoryProjectionFilter",
    "HistoryProjectionPosition",
    "IdProjectionPosition",
    "LedgerPort",
    "ObligationsProjectionFilter",
    "OperationKind",
    "OperationLease",
    "OperationQuarantineCode",
    "OperationRecord",
    "OperationResultLocator",
    "OperationState",
    "PendingVerdict",
    "PendingVerdictKind",
    "ProjectionFilter",
    "ProjectionItem",
    "ProjectionPage",
    "ProjectionPosition",
    "ProjectionQuery",
    "ProjectionView",
    "QueryableProjectionView",
    "SelectedAttempt",
    "SemanticAttemptHandle",
    "SemanticAttemptRecord",
    "SemanticContinuation",
    "SemanticDisclosureWait",
    "SemanticJobRecord",
    "SemanticProgressRecord",
    "StoredProjection",
    "check_admission_refused",
    "check_admission_stage",
]


class AppendWarning(str, Enum):  # noqa: UP042 - exact durable enum base
    UNKNOWN_EVENT_SCHEMA_PRESERVED = "unknown_event_schema_preserved"


class ProjectionView(str, Enum):  # noqa: UP042 - exact durable enum base
    COMPACT = "compact"
    ASSIGNMENT = "assignment"
    OBLIGATIONS = "obligations"
    FINDINGS = "findings"
    CANDIDATE_FINDINGS = "candidate_findings"
    EVIDENCE = "evidence"
    RESULTS = "results"
    HISTORY = "history"
    VERSIONS = "versions"


class OperationKind(str, Enum):  # noqa: UP042 - exact durable enum base
    START = "start"
    PUBLISH_WORK = "publish_work"
    CHECK = "check"
    RESPOND = "respond"
    RECEIPT = "receipt"


class OperationState(str, Enum):  # noqa: UP042 - exact durable enum base
    PENDING = "pending"
    COMPLETE = "complete"
    QUARANTINED = "quarantined"


class CheckPhase(str, Enum):  # noqa: UP042 - exact durable enum base
    RESERVED = "reserved"
    LOCAL_READY = "local_ready"
    SEMANTIC_WAIT = "semantic_wait"
    READY_TO_FINALIZE = "ready_to_finalize"
    TERMINAL = "terminal"


class CheckSuspensionKind(str, Enum):  # noqa: UP042 - exact durable enum base
    REPOSITORY_GRANT = "repository_grant"
    REVIEW_INPUT = "review_input"


class AttemptOutcome(str, Enum):  # noqa: UP042 - exact durable enum base
    RESPONSE_DURABLE = "response_durable"
    FAILED = "failed"
    EXPIRED = "expired"
    LATE = "late"
    SELECTED = "selected"


class OperationQuarantineCode(str, Enum):  # noqa: UP042 - exact durable enum base
    OPERATION_KIND_STATE_CONTRADICTION = "operation_kind_state_contradiction"
    OPERATION_RESULT_DIGEST_MISMATCH = "operation_result_digest_mismatch"
    OPERATION_EVENT_RANGE_MISMATCH = "operation_event_range_mismatch"
    OPERATION_RESUME_OBJECT_INVALID = "operation_resume_object_invalid"
    OPERATION_LEASE_SHAPE_INVALID = "operation_lease_shape_invalid"


class PendingVerdictKind(str, Enum):  # noqa: UP042 - exact durable enum base
    ABSENT = "absent"
    LIVE = "live"
    TERMINAL = "terminal"
    QUARANTINED = "quarantined"


# A new check arms a transient acquisition reservation for its exact (writer, request) key before
# it releases the ledger lock to stage its resume object. It is never persisted and lapses after
# this many seconds if acquisition stalls (ADR-022 decision 4).
CHECK_ACQUISITION_RESERVATION_SECONDS: Final = 60


class CheckAdmissionStage(str, Enum):  # noqa: UP042 - exact structural enum base
    """Why a check request has no operation record yet (issue #838).

    Each member names a transient condition met before admission. None of them records anything
    under the request identity, so replaying the exact same body and ``request_id`` is always
    safe and converges on the one operation that admission eventually creates.
    """

    # A live acquisition reservation already holds this exact request key.
    ACQUIRING = "acquiring"
    # A native capture handoff for this task is still outstanding; the frozen case must include it.
    CAPTURE_HANDOFF_PENDING = "capture_handoff_pending"
    # The acquisition lost a race with concurrent ledger motion and staged nothing durable.
    ACQUISITION_CONTENDED = "acquisition_contended"
    # A Codex import for this session is still being published.
    IMPORT_PENDING = "import_pending"


CHECK_ADMISSION_REASON_CODES: Final[Mapping[CheckAdmissionStage, str]] = MappingProxyType(
    {
        CheckAdmissionStage.ACQUIRING: "check_admission_in_progress",
        CheckAdmissionStage.CAPTURE_HANDOFF_PENDING: "check_admission_capture_pending",
        CheckAdmissionStage.ACQUISITION_CONTENDED: "check_admission_contended",
        CheckAdmissionStage.IMPORT_PENDING: "check_admission_import_pending",
    }
)
_CHECK_ADMISSION_STAGE_BY_REASON: Final[Mapping[str, CheckAdmissionStage]] = MappingProxyType(
    {reason: stage for stage, reason in CHECK_ADMISSION_REASON_CODES.items()}
)

# How long a caller should wait before replaying the exact request. A capture handoff drains on
# the service sweep that a refused admission wakes, so it gets the longest bounded wait.
CHECK_ADMISSION_RETRY_AFTER_MS: Final[Mapping[CheckAdmissionStage, int]] = MappingProxyType(
    {
        CheckAdmissionStage.ACQUIRING: 2_000,
        CheckAdmissionStage.CAPTURE_HANDOFF_PENDING: 5_000,
        CheckAdmissionStage.ACQUISITION_CONTENDED: 1_000,
        CheckAdmissionStage.IMPORT_PENDING: 5_000,
    }
)


def check_admission_refused(stage: CheckAdmissionStage) -> PublicOperationError:
    """Build the one retryable refusal every pre-admission branch raises.

    The typed reason code attaches the same-identity continuation at construction, so a caller
    can never receive a pre-admission ``OPERATION_PENDING`` that reads like a stranded operation.
    """

    if type(stage) is not CheckAdmissionStage:
        raise TypeError("check_admission_stage_invalid")
    return PublicOperationError(
        PublicErrorCode.OPERATION_PENDING,
        "The check has not been admitted yet.",
        True,
        safe_details={
            "reason_code": CHECK_ADMISSION_REASON_CODES[stage],
            "retry_after_ms": CHECK_ADMISSION_RETRY_AFTER_MS[stage],
        },
    )


def check_admission_stage(error: BaseException) -> CheckAdmissionStage | None:
    """Return the pre-admission stage a refusal names, or ``None`` for any other failure."""

    if (
        type(error) is not PublicOperationError
        or error.code is not PublicErrorCode.OPERATION_PENDING
        or not error.retryable
    ):
        return None
    reason = error.safe_details.get("reason_code")
    if type(reason) is not str:
        return None
    return _CHECK_ADMISSION_STAGE_BY_REASON.get(reason)


type QueryableProjectionView = Literal[
    "compact",
    "assignment",
    "obligations",
    "findings",
    "evidence",
    "results",
    "history",
    "versions",
]

_MAX_SAFE_INTEGER: Final = 2**53 - 1
_MAX_SQLITE_SIGNED_INTEGER: Final = 2**63 - 1
_IDENTITY_PATTERN: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}$", re.ASCII)
# A replayed check reports the pack versions it recorded, which may predate the current ones.
_POLICY_IDS: Final = RECORDED_POLICY_PACKS


def _invalid() -> ValueError:
    return ValueError("invalid_ledger_port_value")


def _id(kind: IdKind, value: object) -> str:
    try:
        return validate_id(kind, value)
    except ValueError as exc:
        raise _invalid() from exc


def _valid_opaque_item_id(value: object) -> bool:
    try:
        validate_opaque_item_id(value)
    except ValueError:
        return False
    return True


def _uint(value: object, *, positive: bool = False, sqlite: bool = False) -> int:
    maximum = _MAX_SQLITE_SIGNED_INTEGER if sqlite else _MAX_SAFE_INTEGER
    minimum = 1 if positive else 0
    if type(value) is not int or not minimum <= value <= maximum:
        raise _invalid()
    return value


def _utc(value: object) -> datetime:
    if type(value) is not datetime:
        raise _invalid()
    try:
        format_rfc3339_millis(value)
    except ValueError as exc:
        raise _invalid() from exc
    return value


def _digest(value: object) -> str:
    if type(value) is not str:
        raise _invalid()
    try:
        return validate_sha256_digest(value)
    except ValueError as exc:
        raise _invalid() from exc


def _commitment(value: object) -> str:
    if type(value) is not str:
        raise _invalid()
    try:
        return validate_commitment(value)
    except ValueError as exc:
        raise _invalid() from exc


def _identity(value: object) -> str:
    if type(value) is not str or _IDENTITY_PATTERN.fullmatch(value) is None:
        raise _invalid()
    return value


def _sorted_unique_strings(value: object, *, maximum: int = 64) -> tuple[str, ...]:
    if type(value) is not tuple:
        raise _invalid()
    raw = cast(tuple[object, ...], value)
    if len(raw) > maximum or any(type(item) is not str for item in raw):
        raise _invalid()
    strings = cast(tuple[str, ...], raw)
    try:
        expected = tuple(sorted(set(strings), key=str.encode))
    except UnicodeEncodeError as exc:
        raise _invalid() from exc
    if strings != expected:
        raise _invalid()
    return strings


def _validate_policy_executions(value: object) -> tuple[CheckPolicyExecution, ...]:
    if type(value) is not tuple:
        raise _invalid()
    raw = cast(tuple[object, ...], value)
    if any(type(item) is not CheckPolicyExecution for item in raw):
        raise _invalid()
    executions = cast(tuple[CheckPolicyExecution, ...], raw)
    keys = tuple(item.policy_id.encode("ascii") for item in executions)
    if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
        raise _invalid()
    return executions


@dataclass(frozen=True, slots=True)
class AppendEntry:
    draft: EventDraft
    author: Actor
    payload_object: ObjectRef
    payload_commitment: str
    media_type: str
    plaintext_size: int
    publication_channel: PublicationChannel
    coverage: Coverage
    projection_status: Literal["projected", "unknown_unprojected"]

    def __post_init__(self) -> None:
        if (
            type(self.draft) is not EventDraft
            or type(self.author) is not Actor
            or type(self.payload_object) is not ObjectRef
            or self.payload_object.metadata.kind is not ObjectKind.EVENT_PAYLOAD
        ):
            raise _invalid()
        _commitment(self.payload_commitment)
        if (
            self.payload_commitment != self.payload_object.commitment
            or type(self.media_type) is not str
            or self.media_type != self.payload_object.metadata.media_type
        ):
            raise _invalid()
        _uint(self.plaintext_size, sqlite=True)
        if self.plaintext_size != self.payload_object.plaintext_size:
            raise _invalid()
        if (
            type(self.publication_channel) is not PublicationChannel
            or type(self.coverage) is not Coverage
        ):
            raise _invalid()
        if type(self.projection_status) is not str or self.projection_status not in {
            "projected",
            "unknown_unprojected",
        }:
            raise _invalid()


@dataclass(frozen=True, slots=True)
class AppendCommand:
    task_id: str
    session_id: str
    writer_id: str
    operation_id: str
    operation_kind: OperationKind
    request_digest: str
    expected_frontier: int | None
    entries: tuple[AppendEntry, ...]
    result_object_ref: ObjectRef | None = None
    # Object descriptors for non-payload artifacts that are already
    # authenticated by the owning object store.  Native observation content
    # is staged before the ledger append, so the ledger must receive the exact
    # descriptor in order to retain it across a restart/replay.
    artifact_object_refs: tuple[ObjectRef, ...] = ()

    def __post_init__(self) -> None:
        _id(IdKind.TASK, self.task_id)
        _id(IdKind.SESSION, self.session_id)
        _id(IdKind.WRITER, self.writer_id)
        _id(IdKind.REQUEST, self.operation_id)
        if type(self.operation_kind) is not OperationKind:
            raise _invalid()
        _digest(self.request_digest)
        if self.expected_frontier is not None:
            _uint(self.expected_frontier, sqlite=True)
        if (
            type(self.entries) is not tuple
            or not 1 <= len(self.entries) <= MAX_EVENTS_PER_BATCH
            or any(type(entry) is not AppendEntry for entry in self.entries)
        ):
            raise _invalid()
        event_ids = tuple(entry.draft.event_id for entry in self.entries)
        if len(event_ids) != len(set(event_ids)):
            raise _invalid()
        if any(entry.payload_object.metadata.task_id != self.task_id for entry in self.entries):
            raise _invalid()
        if self.operation_kind is OperationKind.RECEIPT:
            if (
                type(self.result_object_ref) is not ObjectRef
                or self.result_object_ref.metadata.kind is not ObjectKind.RECEIPT
                or self.result_object_ref.metadata.task_id != self.task_id
            ):
                raise _invalid()
        elif self.result_object_ref is not None:
            raise _invalid()
        if type(self.artifact_object_refs) is not tuple:
            raise _invalid()
        artifact_ids = {
            artifact_ref for entry in self.entries for artifact_ref in entry.draft.artifact_refs
        }
        refs = self.artifact_object_refs
        if (
            len(refs) > MAX_EVENTS_PER_BATCH * 64
            or any(type(ref) is not ObjectRef for ref in refs)
            or tuple(ref.object_id for ref in refs)
            != tuple(sorted({ref.object_id for ref in refs}, key=str.encode))
            or any(
                ref.metadata.task_id != self.task_id or ref.object_id not in artifact_ids
                for ref in refs
            )
        ):
            raise _invalid()


@dataclass(frozen=True, slots=True)
class AcceptedEventSummary:
    event_id: str
    ingestion_sequence: int
    writer_sequence: int
    entry_digest: str
    projection_status: Literal["projected", "unknown_unprojected"]

    def __post_init__(self) -> None:
        _id(IdKind.EVENT, self.event_id)
        _uint(self.ingestion_sequence, positive=True, sqlite=True)
        _uint(self.writer_sequence, positive=True, sqlite=True)
        _digest(self.entry_digest)
        if type(self.projection_status) is not str or self.projection_status not in {
            "projected",
            "unknown_unprojected",
        }:
            raise _invalid()


@dataclass(frozen=True, slots=True)
class AppendResult:
    outcome: Literal["accepted", "replayed"]
    accepted: tuple[AcceptedEventSummary, ...]
    subject_frontier: Frontier
    result_frontier: Frontier
    warnings: tuple[AppendWarning, ...]

    def __post_init__(self) -> None:
        if type(self.outcome) is not str or self.outcome not in {"accepted", "replayed"}:
            raise _invalid()
        if (
            type(self.accepted) is not tuple
            or not 1 <= len(self.accepted) <= MAX_EVENTS_PER_BATCH
            or any(type(item) is not AcceptedEventSummary for item in self.accepted)
            or len({item.event_id for item in self.accepted}) != len(self.accepted)
        ):
            raise _invalid()
        if (
            type(self.subject_frontier) is not Frontier
            or type(self.result_frontier) is not Frontier
        ):
            raise _invalid()
        if self.result_frontier < self.subject_frontier:
            raise _invalid()
        if type(self.warnings) is not tuple or any(
            type(item) is not AppendWarning for item in self.warnings
        ):
            raise _invalid()
        expected = tuple(sorted(set(self.warnings), key=lambda item: item.value.encode("ascii")))
        if self.warnings != expected:
            raise _invalid()


@dataclass(frozen=True, slots=True)
class OperationLease:
    writer_id: str
    operation_id: str
    session_id: str
    phase: CheckPhase
    owner_generation: str
    lease_owner_id: str
    lease_generation: int
    lease_expires_at: datetime
    frontier: Frontier
    dependency_digest: str

    def __post_init__(self) -> None:
        _id(IdKind.WRITER, self.writer_id)
        _id(IdKind.REQUEST, self.operation_id)
        _id(IdKind.SESSION, self.session_id)
        if type(self.phase) is not CheckPhase or self.phase is CheckPhase.TERMINAL:
            raise _invalid()
        _identity(self.owner_generation)
        _identity(self.lease_owner_id)
        _uint(self.lease_generation, positive=True)
        _utc(self.lease_expires_at)
        if type(self.frontier) is not Frontier:
            raise _invalid()
        _digest(self.dependency_digest)


@dataclass(frozen=True, slots=True)
class FrozenCase:
    case: DeterministicCase
    lease: OperationLease

    def __post_init__(self) -> None:
        if (
            type(self.case) is not DeterministicCase
            or type(self.lease) is not OperationLease
            or self.case.frontier != self.lease.frontier
        ):
            raise _invalid()


@dataclass(frozen=True, slots=True)
class CheckPolicyExecution:
    policy_id: str
    policy_version: str
    outcome: Literal["run", "skipped", "failed"]
    reason: Literal[
        "completed",
        "material_unavailable",
        "not_applicable",
        "policy_failure",
        "scope_excluded",
    ]

    def __post_init__(self) -> None:
        _identity(self.policy_id)
        _identity(self.policy_version)
        legal = {
            ("run", "completed"),
            ("skipped", "material_unavailable"),
            ("skipped", "not_applicable"),
            ("skipped", "scope_excluded"),
            ("failed", "policy_failure"),
        }
        if (
            type(self.outcome) is not str
            or type(self.reason) is not str
            or (
                self.outcome,
                self.reason,
            )
            not in legal
        ):
            raise _invalid()


@dataclass(frozen=True, slots=True)
class CheckVersionSlice:
    protocol_version: Literal["0.1"]
    engine_version: str
    projection_version: str
    policy_packs: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.protocol_version != "0.1":
            raise _invalid()
        _identity(self.engine_version)
        _identity(self.projection_version)
        packs = _sorted_unique_strings(self.policy_packs, maximum=3)
        if not packs or any(pack not in _POLICY_IDS for pack in packs):
            raise _invalid()


@dataclass(frozen=True, slots=True)
class CheckChildPreviewItem:
    """One bounded child projection attached to a completed check result.

    The preview is derived from the parent ledger's recorded manifest by the application layer;
    it never holds live child state.  ``blocking_conditions`` contains evaluator tokens only and
    is deliberately separate from the check's finding list.
    """

    child_task_id: str
    origin: LineageOrigin
    acceptance: LineageAcceptance
    work_state: WorkState
    session_health: SessionHealth
    rollup_state: LineageRollupState
    blocking_conditions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _id(IdKind.TASK, self.child_task_id)
        if (
            type(self.origin) is not LineageOrigin
            or type(self.acceptance) is not LineageAcceptance
            or type(self.work_state) is not WorkState
            or type(self.session_health) is not SessionHealth
            or type(self.rollup_state) is not LineageRollupState
        ):
            raise _invalid()
        _sorted_unique_strings(self.blocking_conditions)


@dataclass(frozen=True, slots=True)
class CheckChildrenPreview:
    """The check-result child section, with a recorded/preview freshness label."""

    label: Literal["recorded", "preview"]
    items: tuple[CheckChildPreviewItem, ...]
    tested_manifest_frontier: Frontier | None = None

    def __post_init__(self) -> None:
        if self.label not in {"recorded", "preview"} or type(self.items) is not tuple:
            raise _invalid()
        if len(self.items) > 64 or any(
            type(item) is not CheckChildPreviewItem for item in self.items
        ):
            raise _invalid()
        ids = tuple(item.child_task_id for item in self.items)
        if ids != tuple(sorted(set(ids), key=str.encode)):
            raise _invalid()
        if (
            self.tested_manifest_frontier is not None
            and type(self.tested_manifest_frontier) is not Frontier
        ):
            raise _invalid()


@dataclass(frozen=True, slots=True)
class CheckAdvisoryNote:
    """A bounded project coordination hint carried beside, never inside, findings."""

    kind: Literal["live_member_present", "duplicate_finding"]
    project_id: str
    task_ids: tuple[str, ...]
    count: int

    def __post_init__(self) -> None:
        if self.kind not in {"live_member_present", "duplicate_finding"}:
            raise _invalid()
        _id(IdKind.PROJECT, self.project_id)
        if type(self.task_ids) is not tuple or not 1 <= len(self.task_ids) <= 64:
            raise _invalid()
        tasks = tuple(_id(IdKind.TASK, value) for value in self.task_ids)
        if tasks != tuple(sorted(set(tasks), key=str.encode)):
            raise _invalid()
        if self.kind == "duplicate_finding" and len(tasks) < 2:
            raise _invalid()
        if type(self.count) is not int or not 1 <= self.count <= _MAX_SAFE_INTEGER:
            raise _invalid()
        if self.count < len(tasks):
            raise _invalid()
        object.__setattr__(self, "task_ids", tasks)


FindingTodoStateWire = Literal[
    "acknowledged_not_done", "open", "rejection_accepted", "self_verified", "verified_resolved"
]
_TODO_STATES: Final = frozenset(
    {"acknowledged_not_done", "open", "rejection_accepted", "self_verified", "verified_resolved"}
)
# The closed "next:" tokens of the finding checklist (issue #905).
ChecklistNext = Literal["decide_at_budget", "request_receipt", "work_open_findings"]
_CHECKLIST_NEXT: Final = frozenset({"decide_at_budget", "request_receipt", "work_open_findings"})
MAX_CHECKLIST_ITEMS: Final = 100

OverallNextAction = Literal[
    "supply_missing_input",
    "work_open_findings",
    "review_recorded_work",
    "request_receipt",
]
OverallNextStatus = Literal["action_required", "ready_with_limitations", "ready"]
_OVERALL_NEXT_ACTIONS: Final = frozenset(
    {
        "supply_missing_input",
        "work_open_findings",
        "review_recorded_work",
        "request_receipt",
    }
)
_OVERALL_NEXT_STATUSES: Final = frozenset({"action_required", "ready_with_limitations", "ready"})


@dataclass(frozen=True, slots=True)
class CheckChecklistItem:
    """One finding on the converging to-do list, structural only."""

    finding_id: str
    todo_state: FindingTodoStateWire
    review_rounds: int

    def __post_init__(self) -> None:
        _id(IdKind.FINDING, self.finding_id)
        if type(self.todo_state) is not str or self.todo_state not in _TODO_STATES:
            raise _invalid()
        _uint(self.review_rounds)


@dataclass(frozen=True, slots=True)
class CheckFindingChecklist:
    """The task's findings as a to-do list after this check (issue #905).

    Current projection context attached beside the frozen check, like advisory notes: it never
    changes the recorded check event or its verdict.
    """

    attempt_budget: int
    items: tuple[CheckChecklistItem, ...]
    next: ChecklistNext
    # Counted over every current actionable item, not only the listed ones.
    counts: FindingTodoCounts

    def __post_init__(self) -> None:
        if type(self.attempt_budget) is not int or not 1 <= self.attempt_budget <= 50:
            raise _invalid()
        if type(self.counts) is not FindingTodoCounts:
            raise _invalid()
        for value in (
            self.counts.open,
            self.counts.verified_resolved,
            self.counts.acknowledged_not_done,
            self.counts.rejection_accepted,
            self.counts.budget_reached,
            self.counts.self_verified,
        ):
            _uint(value)
        total = (
            self.counts.open
            + self.counts.verified_resolved
            + self.counts.acknowledged_not_done
            + self.counts.rejection_accepted
            + self.counts.self_verified
        )
        if total < len(self.items) or self.counts.budget_reached > self.counts.open:
            raise _invalid()
        if type(self.items) is not tuple or len(self.items) > MAX_CHECKLIST_ITEMS:
            raise _invalid()
        if any(type(item) is not CheckChecklistItem for item in self.items):
            raise _invalid()
        if len({item.finding_id for item in self.items}) != len(self.items):
            raise _invalid()
        if type(self.next) is not str or self.next not in _CHECKLIST_NEXT:
            raise _invalid()


@dataclass(frozen=True, slots=True)
class CheckOverallNext:
    """The authoritative continuation beside the finding-only checklist (#963).

    ``finding_checklist.next`` describes only the finding to-do list.  This projection names the
    task-level continuation and its safe structural targets.  A coverage-limited result keeps the
    ordinary receipt endpoint available so an agent can acknowledge the limitation without
    turning it into a clean review.
    """

    status: OverallNextStatus
    action: OverallNextAction
    target_refs: tuple[str, ...] = ()
    acknowledged_incomplete_endpoint: Literal["receipt"] | None = None

    def __post_init__(self) -> None:
        if type(self.status) is not str or self.status not in _OVERALL_NEXT_STATUSES:
            raise _invalid()
        if type(self.action) is not str or self.action not in _OVERALL_NEXT_ACTIONS:
            raise _invalid()
        if type(self.target_refs) is not tuple or len(self.target_refs) > 64:
            raise _invalid()
        if any(
            type(item) is not str or _IDENTITY_PATTERN.fullmatch(item) is None
            for item in self.target_refs
        ):
            raise _invalid()
        if self.target_refs != tuple(sorted(set(self.target_refs), key=str.encode)):
            raise _invalid()
        if self.acknowledged_incomplete_endpoint not in {None, "receipt"}:
            raise _invalid()
        if (
            self.action
            in {
                "supply_missing_input",
                "work_open_findings",
                "review_recorded_work",
            }
            and self.status != "action_required"
        ):
            raise _invalid()
        if self.action in {"work_open_findings", "review_recorded_work"} and not self.target_refs:
            raise _invalid()
        if self.acknowledged_incomplete_endpoint is not None and (
            self.action != "request_receipt" or self.status != "ready_with_limitations"
        ):
            raise _invalid()


@dataclass(frozen=True, slots=True)
class CheckCommitResult:
    outcome: Literal["committed", "replayed"]
    task_id: str
    session_id: str
    writer_id: str
    request_id: str
    subject_frontier: Frontier
    result_frontier: Frontier
    verdict: CheckVerdict
    findings: tuple[Finding, ...]
    suppressed_count: int
    policy_executions: tuple[CheckPolicyExecution, ...]
    semantic_status: SemanticStatus
    semantic_reason: SemanticReason
    semantic_provenance: SemanticProvenance | None
    coverage: Coverage
    versions: CheckVersionSlice
    semantic_conclusion: str | None = None
    review_summary: str | None = None
    verified: tuple[JsonObject, ...] = ()
    children: CheckChildrenPreview | None = None
    advisory_notes: tuple[CheckAdvisoryNote, ...] = ()
    # Structural record of what an ``insufficient_packet`` review named as missing (issue #907).
    missing_for_assessment: tuple[MissingForAssessmentItem, ...] = ()
    finding_checklist: CheckFindingChecklist | None = None
    # Task-level continuation; ``finding_checklist.next`` remains finding-only (issue #963).
    overall_next: CheckOverallNext | None = None
    # Opaque case item identities withheld by the never-send heuristic. The check result keeps
    # these bounded references so recovery and every presentation surface can name the omitted
    # context without exposing matched bytes.
    semantic_withheld_item_ids: tuple[str, ...] = ()
    review_input_manifest: JsonObject | None = None
    totals: JsonObject | None = None

    def __post_init__(self) -> None:
        if type(self.outcome) is not str or self.outcome not in {"committed", "replayed"}:
            raise _invalid()
        _id(IdKind.TASK, self.task_id)
        _id(IdKind.SESSION, self.session_id)
        _id(IdKind.WRITER, self.writer_id)
        _id(IdKind.REQUEST, self.request_id)
        if (
            type(self.subject_frontier) is not Frontier
            or type(self.result_frontier) is not Frontier
        ):
            raise _invalid()
        if self.result_frontier < self.subject_frontier or type(self.verdict) is not CheckVerdict:
            raise _invalid()
        if type(self.findings) is not tuple or any(
            type(item) is not Finding for item in self.findings
        ):
            raise _invalid()
        if len({finding.finding_id for finding in self.findings}) != len(self.findings):
            raise _invalid()
        _uint(self.suppressed_count)
        _validate_policy_executions(self.policy_executions)
        try:
            validate_semantic_outcome(self.semantic_status, self.semantic_reason)
            validate_semantic_provenance_binding(
                self.semantic_status,
                self.semantic_reason,
                None if self.semantic_provenance is None else self.semantic_provenance.status,
                None if self.semantic_provenance is None else self.semantic_provenance.reason,
            )
        except ValueError as exc:
            raise _invalid() from exc
        if (
            self.semantic_provenance is not None
            and type(self.semantic_provenance) is not SemanticProvenance
        ):
            raise _invalid()
        if type(self.coverage) is not Coverage or type(self.versions) is not CheckVersionSlice:
            raise _invalid()
        if self.semantic_conclusion is not None and (
            type(self.semantic_conclusion) is not str
            or self.semantic_conclusion
            not in {"no_material_discrepancy", "challenges_returned", "insufficient_packet"}
            or self.semantic_status is not SemanticStatus.SUCCEEDED
        ):
            raise _invalid()
        if self.review_summary is not None and (
            type(self.review_summary) is not str or not self.review_summary
        ):
            raise _invalid()
        if type(self.verified) is not tuple or len(self.verified) > 64:
            raise _invalid()
        if any(type(item) is not JsonObject for item in self.verified):
            raise _invalid()
        if self.children is not None and type(self.children) is not CheckChildrenPreview:
            raise _invalid()
        if (
            self.finding_checklist is not None
            and type(self.finding_checklist) is not CheckFindingChecklist
        ):
            raise _invalid()
        if self.overall_next is not None and type(self.overall_next) is not CheckOverallNext:
            raise _invalid()
        if self.totals is not None:
            from yoetz.domain.check_totals import validate_check_totals

            object.__setattr__(self, "totals", validate_check_totals(self.totals))
        if (
            type(self.semantic_withheld_item_ids) is not tuple
            or len(self.semantic_withheld_item_ids) > 64
            or any(
                not _valid_opaque_item_id(item_id) for item_id in self.semantic_withheld_item_ids
            )
            or self.semantic_withheld_item_ids
            != tuple(sorted(set(self.semantic_withheld_item_ids), key=str.encode))
        ):
            raise _invalid()
        if (
            self.review_input_manifest is not None
            and type(self.review_input_manifest) is not JsonObject
        ):
            raise _invalid()
        if type(self.advisory_notes) is not tuple or len(self.advisory_notes) > 64:
            raise _invalid()
        if any(type(item) is not CheckAdvisoryNote for item in self.advisory_notes):
            raise _invalid()
        note_keys = tuple(
            (item.kind, item.project_id, item.task_ids) for item in self.advisory_notes
        )
        if len(note_keys) != len(set(note_keys)):
            raise _invalid()
        if type(self.missing_for_assessment) is not tuple or any(
            type(item) is not MissingForAssessmentItem for item in self.missing_for_assessment
        ):
            raise _invalid()


@dataclass(frozen=True, slots=True)
class CheckAwaitingHuman:
    """One check suspended on a local disclosure decision. Nothing was committed.

    This is deliberately not a ``CheckCommitResult``: there is no verdict, no findings, and no
    coverage, because no provider was reached and the case was never sent. Returning a commit
    result here is what made an approved decision useless — the operation was already closed.
    """

    task_id: str
    session_id: str
    writer_id: str
    request_id: str
    subject_frontier: Frontier
    result_frontier: Frontier
    continuation: SemanticContinuation
    versions: CheckVersionSlice
    specification_preflight: SpecificationPreflight | None = None
    state: Literal["awaiting_human", "awaiting_input"] = "awaiting_human"

    def __post_init__(self) -> None:
        _id(IdKind.TASK, self.task_id)
        _id(IdKind.SESSION, self.session_id)
        _id(IdKind.WRITER, self.writer_id)
        _id(IdKind.REQUEST, self.request_id)
        if (
            type(self.subject_frontier) is not Frontier
            or type(self.result_frontier) is not Frontier
        ):
            raise _invalid()
        if self.result_frontier < self.subject_frontier:
            raise _invalid()
        if type(self.continuation) is not SemanticContinuation:
            raise _invalid()
        # The continuation must name the request the caller has to replay, not some other one.
        if self.continuation.request_id != self.request_id:
            raise _invalid()
        if type(self.versions) is not CheckVersionSlice:
            raise _invalid()
        if (
            self.specification_preflight is not None
            and type(self.specification_preflight) is not SpecificationPreflight
        ):
            raise _invalid()
        expected_state = (
            "awaiting_input"
            if self.continuation.kind == "review_input_required"
            else "awaiting_human"
        )
        if self.state != expected_state:
            raise _invalid()


@dataclass(frozen=True, slots=True)
class OperationResultLocator:
    first_ingestion_sequence: int | None
    last_ingestion_sequence: int | None
    result_object_ref: ObjectRef | None
    structural_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if (self.first_ingestion_sequence is None) != (self.last_ingestion_sequence is None):
            raise _invalid()
        if self.first_ingestion_sequence is not None:
            first = _uint(self.first_ingestion_sequence, positive=True, sqlite=True)
            last = _uint(self.last_ingestion_sequence, positive=True, sqlite=True)
            if last < first:
                raise _invalid()
        if self.result_object_ref is not None and type(self.result_object_ref) is not ObjectRef:
            raise _invalid()
        ids = _sorted_unique_strings(self.structural_ids, maximum=MAX_EVENTS_PER_BATCH + 1)
        for value in ids:
            _validate_any_structural_id(value)


def _validate_any_structural_id(value: object) -> str:
    if type(value) is not str:
        raise _invalid()
    by_prefix = {
        "act_": IdKind.ACTION,
        "att_": IdKind.SEMANTIC_ATTEMPT,
        "clm_": IdKind.CLAIM,
        "evd_": IdKind.EVIDENCE,
        "evt_": IdKind.EVENT,
        "fnd_": IdKind.FINDING,
        "job_": IdKind.SEMANTIC_JOB,
        "obj_": IdKind.OBJECT,
        "obl_": IdKind.OBLIGATION,
        "rcp_": IdKind.RECEIPT,
        "req_": IdKind.REQUEST,
        "res_": IdKind.RESULT,
        "ses_": IdKind.SESSION,
        "tsk_": IdKind.TASK,
        "wri_": IdKind.WRITER,
    }
    kind = by_prefix.get(value[:4])
    if kind is None:
        raise _invalid()
    return _id(kind, value)


@dataclass(frozen=True, slots=True)
class OperationRecord:
    writer_id: str
    operation_id: str
    operation_kind: OperationKind
    request_digest: str
    state: OperationState
    phase: CheckPhase
    owner_generation: str | None
    lease_owner_id: str | None
    lease_generation: int | None
    lease_expires_at: datetime | None
    resume_object_ref: ObjectRef | None
    result_canonical: bytes | None
    result_digest: str | None
    result_locator: OperationResultLocator | None
    quarantine_code: OperationQuarantineCode | None
    terminal_at: datetime | None
    suspension_kind: CheckSuspensionKind | None = None

    def __post_init__(self) -> None:
        _id(IdKind.WRITER, self.writer_id)
        _id(IdKind.REQUEST, self.operation_id)
        if type(self.operation_kind) is not OperationKind or type(self.state) is not OperationState:
            raise _invalid()
        _digest(self.request_digest)
        if type(self.phase) is not CheckPhase:
            raise _invalid()
        if self.suspension_kind is not None and (
            type(self.suspension_kind) is not CheckSuspensionKind
            or self.state is not OperationState.PENDING
            or self.operation_kind is not OperationKind.CHECK
            or self.phase is not CheckPhase.SEMANTIC_WAIT
        ):
            raise _invalid()
        if self.resume_object_ref is not None:
            if type(self.resume_object_ref) is not ObjectRef:
                raise _invalid()
            expected_resume_kind = (
                ObjectKind.CHECK_RESUME
                if self.phase is CheckPhase.RESERVED
                else ObjectKind.DETERMINISTIC_RESULT
            )
            if self.phase is CheckPhase.TERMINAL or (
                self.resume_object_ref.metadata.kind is not expected_resume_kind
            ):
                raise _invalid()
        if (
            self.result_locator is not None
            and type(self.result_locator) is not OperationResultLocator
        ):
            raise _invalid()
        lease_values = (
            self.owner_generation,
            self.lease_owner_id,
            self.lease_generation,
            self.lease_expires_at,
        )
        if self.state is OperationState.PENDING:
            if (
                self.operation_kind is not OperationKind.CHECK
                or self.phase is CheckPhase.TERMINAL
                or any(value is None for value in lease_values)
                or self.resume_object_ref is None
                or self.result_canonical is not None
                or self.result_digest is not None
                or self.result_locator is not None
                or self.quarantine_code is not None
                or self.terminal_at is not None
            ):
                raise _invalid()
            _identity(self.owner_generation)
            _identity(self.lease_owner_id)
            _uint(self.lease_generation, positive=True)
            _utc(self.lease_expires_at)
            return
        if (
            self.phase is not CheckPhase.TERMINAL
            or self.suspension_kind is not None
            or any(value is not None for value in lease_values)
            or type(self.result_canonical) is not bytes
            or self.result_digest is None
            or self.terminal_at is None
        ):
            raise _invalid()
        _utc(self.terminal_at)
        expected = f"sha256:{hashlib.sha256(self.result_canonical).hexdigest()}"
        if self.result_digest != expected:
            raise _invalid()
        if self.state is OperationState.COMPLETE:
            if self.quarantine_code is not None:
                raise _invalid()
        elif type(self.quarantine_code) is not OperationQuarantineCode:
            raise _invalid()


@dataclass(frozen=True, slots=True)
class SemanticJobRecord:
    job_id: str
    writer_id: str
    operation_id: str
    case_digest: str
    case_object_ref: ObjectRef
    state: Literal["queued", "leased", "succeeded", "failed", "quarantined"]
    attempt_count: int
    active_attempt_id: str | None
    selected_attempt_id: str | None
    lease_owner_id: str | None
    lease_generation: int | None
    lease_expires_at: datetime | None
    selected_result_object_ref: ObjectRef | None
    terminal_code: SemanticReason | None
    terminal_at: datetime | None

    def __post_init__(self) -> None:
        _id(IdKind.SEMANTIC_JOB, self.job_id)
        _id(IdKind.WRITER, self.writer_id)
        _id(IdKind.REQUEST, self.operation_id)
        _digest(self.case_digest)
        if (
            type(self.case_object_ref) is not ObjectRef
            or self.case_object_ref.metadata.kind is not ObjectKind.SEMANTIC_CASE
        ):
            raise _invalid()
        if type(self.state) is not str or self.state not in {
            "queued",
            "leased",
            "succeeded",
            "failed",
            "quarantined",
        }:
            raise _invalid()
        _uint(self.attempt_count)
        if self.active_attempt_id is not None:
            _id(IdKind.SEMANTIC_ATTEMPT, self.active_attempt_id)
        if self.selected_attempt_id is not None:
            _id(IdKind.SEMANTIC_ATTEMPT, self.selected_attempt_id)
        lease = (self.lease_owner_id, self.lease_generation, self.lease_expires_at)
        if self.selected_result_object_ref is not None and (
            type(self.selected_result_object_ref) is not ObjectRef
            or self.selected_result_object_ref.metadata.kind is not ObjectKind.SEMANTIC_RESPONSE
        ):
            raise _invalid()
        if self.state == "queued":
            if any(
                value is not None
                for value in (
                    self.active_attempt_id,
                    self.selected_attempt_id,
                    *lease,
                    self.selected_result_object_ref,
                    self.terminal_code,
                    self.terminal_at,
                )
            ):
                raise _invalid()
        elif self.state == "leased":
            if (
                self.active_attempt_id is None
                or any(value is None for value in lease)
                or any(
                    value is not None
                    for value in (
                        self.selected_attempt_id,
                        self.selected_result_object_ref,
                        self.terminal_code,
                        self.terminal_at,
                    )
                )
            ):
                raise _invalid()
            _identity(self.lease_owner_id)
            _uint(self.lease_generation, positive=True)
            _utc(self.lease_expires_at)
        elif self.state == "succeeded":
            if (
                self.active_attempt_id is not None
                or any(value is not None for value in lease)
                or self.selected_attempt_id is None
                or self.selected_result_object_ref is None
                or type(self.terminal_code) is not SemanticReason
                or self.terminal_at is None
            ):
                raise _invalid()
            _utc(self.terminal_at)
        elif (
            any(
                value is not None
                for value in (
                    self.active_attempt_id,
                    self.selected_attempt_id,
                    *lease,
                    self.selected_result_object_ref,
                )
            )
            or type(self.terminal_code) is not SemanticReason
            or self.terminal_at is None
        ):
            raise _invalid()
        else:
            _utc(self.terminal_at)


@dataclass(frozen=True, slots=True)
class SemanticAttemptHandle:
    job_id: str
    attempt_id: str
    attempt_ordinal: int
    provider_request_id: str
    writer_id: str
    operation_id: str
    owner_generation: str
    lease_owner_id: str
    lease_generation: int
    lease_expires_at: datetime
    frontier: Frontier
    dependency_digest: str

    def __post_init__(self) -> None:
        _id(IdKind.SEMANTIC_JOB, self.job_id)
        _id(IdKind.SEMANTIC_ATTEMPT, self.attempt_id)
        _uint(self.attempt_ordinal, positive=True)
        _identity(self.provider_request_id)
        _id(IdKind.WRITER, self.writer_id)
        _id(IdKind.REQUEST, self.operation_id)
        _identity(self.owner_generation)
        _identity(self.lease_owner_id)
        _uint(self.lease_generation, positive=True)
        _utc(self.lease_expires_at)
        if type(self.frontier) is not Frontier:
            raise _invalid()
        _digest(self.dependency_digest)


@dataclass(frozen=True, slots=True)
class SelectedAttempt:
    job_id: str
    attempt_id: str
    result_object_ref: ObjectRef
    selected_at: datetime
    frontier: Frontier
    dependency_digest: str

    def __post_init__(self) -> None:
        _id(IdKind.SEMANTIC_JOB, self.job_id)
        _id(IdKind.SEMANTIC_ATTEMPT, self.attempt_id)
        if (
            type(self.result_object_ref) is not ObjectRef
            or self.result_object_ref.metadata.kind is not ObjectKind.SEMANTIC_RESPONSE
        ):
            raise _invalid()
        _utc(self.selected_at)
        if type(self.frontier) is not Frontier:
            raise _invalid()
        _digest(self.dependency_digest)


@dataclass(frozen=True, slots=True)
class SemanticAttemptRecord:
    """Bounded durable facts for one physical AI-powered review dispatch attempt.

    No raw provider text, prompt, secret, path, or user-controlled diagnostic prose.
    """

    job_id: str
    attempt_id: str
    attempt_ordinal: int
    provider_request_id: str
    state: Literal["started", "response_durable", "selected", "failed", "expired", "late"]
    terminal_code: SemanticReason | None
    result_object_ref: ObjectRef | None
    started_at: datetime | None = None
    token_usage: RuntimeTokenUsage | None = None

    def __post_init__(self) -> None:
        if self.started_at is not None:
            _utc(self.started_at)
        _id(IdKind.SEMANTIC_JOB, self.job_id)
        _id(IdKind.SEMANTIC_ATTEMPT, self.attempt_id)
        _uint(self.attempt_ordinal, positive=True)
        _identity(self.provider_request_id)
        if type(self.state) is not str or self.state not in {
            "started",
            "response_durable",
            "selected",
            "failed",
            "expired",
            "late",
        }:
            raise _invalid()
        if self.terminal_code is not None and type(self.terminal_code) is not SemanticReason:
            raise _invalid()
        if self.result_object_ref is not None and (
            type(self.result_object_ref) is not ObjectRef
            or self.result_object_ref.metadata.kind is not ObjectKind.SEMANTIC_RESPONSE
        ):
            raise _invalid()
        if self.token_usage is not None and type(self.token_usage) is not RuntimeTokenUsage:
            raise _invalid()
        if self.state == "started":
            if (
                self.terminal_code is not None
                or self.result_object_ref is not None
                or self.token_usage is not None
            ):
                raise _invalid()
        elif self.state == "response_durable":
            if self.terminal_code is not None or self.result_object_ref is None:
                raise _invalid()
        elif self.state == "selected":
            if self.terminal_code is None or self.result_object_ref is None:
                raise _invalid()
        elif self.state == "expired":
            # A retryable non-success may carry a durable response object solely for bounded
            # privacy omission metadata. It remains unselected and claimable, but terminal replay
            # can recover the same metadata if the frozen deadline closes the job before retry.
            if self.terminal_code is None:
                raise _invalid()
        elif self.state == "late":
            if self.terminal_code is None or self.result_object_ref is None:
                raise _invalid()
        elif self.terminal_code is None:
            raise _invalid()


@dataclass(frozen=True, slots=True)
class SemanticProgressRecord:
    """Durable structural progress of one AI-powered review job (issue #571 item A2).

    ``attempt_ordinal`` is 0 until the first attempt is claimed. ``queued_at`` and
    ``deadline_at`` are written once when progress begins; ``deadline_at`` is the job's frozen
    total execution expiry, never a caller wait. A terminal record is derived from the terminal
    job row, so ``phase`` is ``terminal`` exactly when ``terminal_outcome`` is present.
    """

    job_id: str
    attempt_ordinal: int
    phase: SemanticProgressPhase
    phase_entered_at: datetime
    queued_at: datetime
    deadline_at: datetime
    terminal_outcome: Literal["succeeded", "failed", "quarantined"] | None = None
    terminal_reason: SemanticReason | None = None

    def __post_init__(self) -> None:
        _id(IdKind.SEMANTIC_JOB, self.job_id)
        _uint(self.attempt_ordinal)
        if type(self.phase) is not SemanticProgressPhase:
            raise _invalid()
        _utc(self.phase_entered_at)
        _utc(self.queued_at)
        _utc(self.deadline_at)
        terminal = self.phase is SemanticProgressPhase.TERMINAL
        if terminal:
            if (
                type(self.terminal_outcome) is not str
                or self.terminal_outcome not in {"succeeded", "failed", "quarantined"}
                or type(self.terminal_reason) is not SemanticReason
            ):
                raise _invalid()
        elif self.terminal_outcome is not None or self.terminal_reason is not None:
            raise _invalid()
        elif self.attempt_ordinal == 0 and self.phase is not SemanticProgressPhase.QUEUED:
            raise _invalid()


@dataclass(frozen=True, slots=True)
class CheckAdmissionRecord:
    """Transient structural admission state of one check request id (issue #838).

    Read only while no operation record exists for the key. ``refusal_count`` counts the refused
    admissions this service observed for the exact (writer, request) key; it is 0 when the only
    fact is a live acquisition reservation. Nothing here is persisted, carries payload, or names
    another request: a service restart or runtime eviction forgets it, and the page then reads as
    plainly absent again.
    """

    writer_id: str
    operation_id: str
    stage: CheckAdmissionStage
    refusal_count: int
    first_observed_at: datetime
    last_observed_at: datetime
    retry_after_ms: int

    def __post_init__(self) -> None:
        _id(IdKind.WRITER, self.writer_id)
        _id(IdKind.REQUEST, self.operation_id)
        if type(self.stage) is not CheckAdmissionStage:
            raise _invalid()
        _uint(self.refusal_count)
        _uint(self.retry_after_ms)
        _utc(self.first_observed_at)
        _utc(self.last_observed_at)
        if self.last_observed_at < self.first_observed_at:
            raise _invalid()
        if self.refusal_count == 0 and self.stage is not CheckAdmissionStage.ACQUIRING:
            raise _invalid()


@dataclass(frozen=True, slots=True)
class SemanticDisclosureWait:
    """One suspended AI-powered review attempt awaiting a local disclosure decision.

    Structural only: an opaque proposal identifier and its expiry. No proposal content,
    prepared bytes, destination, or credential material is durable here.
    """

    job_id: str
    attempt_id: str
    writer_id: str
    operation_id: str
    pending_id: str
    pending_expires_at: datetime
    state: Literal["awaiting", "resolved"]
    resolved_at: datetime | None

    def __post_init__(self) -> None:
        _id(IdKind.SEMANTIC_JOB, self.job_id)
        _id(IdKind.SEMANTIC_ATTEMPT, self.attempt_id)
        _id(IdKind.WRITER, self.writer_id)
        _id(IdKind.REQUEST, self.operation_id)
        _id(IdKind.PRIVACY_PROPOSAL, self.pending_id)
        _utc(self.pending_expires_at)
        if type(self.state) is not str or self.state not in {"awaiting", "resolved"}:
            raise _invalid()
        # One-use: a resolved wait carries its consumption time so a second resume cannot
        # replay the same decision.
        if self.state == "awaiting":
            if self.resolved_at is not None:
                raise _invalid()
        elif self.resolved_at is None:
            raise _invalid()
        else:
            _utc(self.resolved_at)


@dataclass(frozen=True, slots=True)
class PendingVerdict:
    kind: PendingVerdictKind
    operation: OperationRecord | None
    retry_after_ms: int | None

    def __post_init__(self) -> None:
        if type(self.kind) is not PendingVerdictKind:
            raise _invalid()
        if self.operation is not None and type(self.operation) is not OperationRecord:
            raise _invalid()
        if self.kind is PendingVerdictKind.ABSENT:
            if self.operation is not None or self.retry_after_ms is not None:
                raise _invalid()
        elif self.kind is PendingVerdictKind.LIVE:
            if (
                self.operation is None
                or self.operation.state is not OperationState.PENDING
                or self.retry_after_ms is None
            ):
                raise _invalid()
            _uint(self.retry_after_ms)
        elif self.retry_after_ms is not None or self.operation is None:
            raise _invalid()
        elif (
            self.kind is PendingVerdictKind.TERMINAL
            and self.operation.state is not OperationState.COMPLETE
        ):
            raise _invalid()
        elif (
            self.kind is PendingVerdictKind.QUARANTINED
            and self.operation.state is not OperationState.QUARANTINED
        ):
            raise _invalid()


@dataclass(frozen=True, slots=True)
class StoredProjection:
    view: ProjectionView
    state: ProjectionState | tuple[ProjectionItem, ...]
    frontier: Frontier
    lag: int
    projection_version: str
    rebuild_required: bool

    def __post_init__(self) -> None:
        if type(self.view) is not ProjectionView:
            raise _invalid()
        if type(self.state) is not ProjectionState and (
            type(self.state) is not tuple
            or any(not _is_projection_item(item) for item in self.state)
        ):
            raise _invalid()
        if type(self.frontier) is not Frontier:
            raise _invalid()
        _uint(self.lag, sqlite=True)
        _identity(self.projection_version)
        if type(self.rebuild_required) is not bool:
            raise _invalid()


@dataclass(frozen=True, slots=True)
class AssignmentProjectionFilter:
    actor_id: str | None
    include_resolved: bool | None

    def __post_init__(self) -> None:
        if self.actor_id is not None:
            try:
                validate_actor_id(self.actor_id)
            except ValueError as exc:
                raise _invalid() from exc
        if self.include_resolved is not None and type(self.include_resolved) is not bool:
            raise _invalid()


@dataclass(frozen=True, slots=True)
class ObligationsProjectionFilter:
    actor_id: str | None
    include_resolved: bool | None
    status: Literal["open", "resolved"] | None

    def __post_init__(self) -> None:
        AssignmentProjectionFilter(self.actor_id, self.include_resolved)
        if self.status is not None and (
            type(self.status) is not str or self.status not in {"open", "resolved"}
        ):
            raise _invalid()


@dataclass(frozen=True, slots=True)
class FindingsProjectionFilter:
    origin: Literal["deterministic", "semantic_model_derived"] | None
    priority: int | None
    disposition: (
        Literal[
            "none",
            "acknowledged",
            "acknowledged_not_done",
            "duplicate_of",
            "provenance_disputed",
            "rejected",
            "self_verified",
            "waived",
        ]
        | None
    )
    include_resolved: bool | None

    def __post_init__(self) -> None:
        if self.origin is not None and (
            type(self.origin) is not str
            or self.origin not in {"deterministic", "semantic_model_derived"}
        ):
            raise _invalid()
        if self.priority is not None and (
            type(self.priority) is not int or not 1 <= self.priority <= 3
        ):
            raise _invalid()
        if self.disposition is not None and (
            type(self.disposition) is not str
            or self.disposition
            not in {
                "none",
                "acknowledged",
                "acknowledged_not_done",
                "duplicate_of",
                "provenance_disputed",
                "rejected",
                "self_verified",
                "waived",
            }
        ):
            raise _invalid()
        if self.include_resolved is not None and type(self.include_resolved) is not bool:
            raise _invalid()


@dataclass(frozen=True, slots=True)
class EvidenceProjectionFilter:
    strength: (
        Literal[
            "mutable_reference",
            "metadata_only",
            "content_digest",
            "immutable_snapshot",
            "independently_reproduced",
        ]
        | None
    )
    freshness: (
        Literal["current", "partial", "redacted_gap", "stale_after_material_change", "unknown"]
        | None
    )
    include_unavailable: bool | None
    # ``mine``: only rows whose source event the querying writer published in its own session,
    # decided from ledger authorship (``ProjectionQuery.writer_id``), never from caller input.
    author: Literal["mine"] | None = None

    def __post_init__(self) -> None:
        if self.strength is not None and (
            type(self.strength) is not str
            or self.strength
            not in {
                "mutable_reference",
                "metadata_only",
                "content_digest",
                "immutable_snapshot",
                "independently_reproduced",
            }
        ):
            raise _invalid()
        if self.author is not None and (type(self.author) is not str or self.author != "mine"):
            raise _invalid()
        if self.freshness is not None and (
            type(self.freshness) is not str
            or self.freshness
            not in {
                "current",
                "partial",
                "redacted_gap",
                "stale_after_material_change",
                "unknown",
            }
        ):
            raise _invalid()
        if self.include_unavailable is not None and type(self.include_unavailable) is not bool:
            raise _invalid()


@dataclass(frozen=True, slots=True)
class HistoryProjectionFilter:
    schema_name: str | None
    actor_id: str | None
    after_sequence: int | None

    def __post_init__(self) -> None:
        if self.schema_name is not None:
            _identity(self.schema_name)
        if self.actor_id is not None:
            try:
                validate_actor_id(self.actor_id)
            except ValueError as exc:
                raise _invalid() from exc
        if self.after_sequence is not None:
            _uint(self.after_sequence, sqlite=True)


type ProjectionFilter = (
    AssignmentProjectionFilter
    | ObligationsProjectionFilter
    | FindingsProjectionFilter
    | EvidenceProjectionFilter
    | HistoryProjectionFilter
)


@dataclass(frozen=True, slots=True)
class IdProjectionPosition:
    last_id: str

    def __post_init__(self) -> None:
        _validate_any_structural_id(self.last_id)
        if not self.last_id.startswith(("evt_", "obl_", "evd_", "res_")):
            raise _invalid()


@dataclass(frozen=True, slots=True)
class FindingProjectionPosition:
    priority: int
    actionable: bool
    artifact_ordinal: int
    immutability_ordinal: int
    freshness_ordinal: int
    authorship_ordinal: int
    real_check_present: bool
    known_gap_count: int
    origin_ordinal: int
    finding_id: str

    def __post_init__(self) -> None:
        if type(self.priority) is not int or not 1 <= self.priority <= 3:
            raise _invalid()
        if type(self.actionable) is not bool or type(self.real_check_present) is not bool:
            raise _invalid()
        for value in (
            self.artifact_ordinal,
            self.immutability_ordinal,
            self.freshness_ordinal,
            self.authorship_ordinal,
            self.known_gap_count,
        ):
            _uint(value)
        if type(self.origin_ordinal) is not int or self.origin_ordinal not in {0, 1}:
            raise _invalid()
        _id(IdKind.FINDING, self.finding_id)


@dataclass(frozen=True, slots=True)
class HistoryProjectionPosition:
    ingestion_sequence: int

    def __post_init__(self) -> None:
        _uint(self.ingestion_sequence, positive=True, sqlite=True)


type ProjectionPosition = (
    IdProjectionPosition | FindingProjectionPosition | HistoryProjectionPosition
)


@dataclass(frozen=True, slots=True)
class ProjectionQuery:
    session_id: str
    view: QueryableProjectionView
    filter: ProjectionFilter | None
    requested_frontier: Frontier
    limit: int
    position: ProjectionPosition | None
    expected_projection_version: str | None
    # The authenticated requesting writer; required only by writer-relative filters.
    writer_id: str | None = None

    def __post_init__(self) -> None:
        _id(IdKind.SESSION, self.session_id)
        if self.writer_id is not None:
            _id(IdKind.WRITER, self.writer_id)
        if (
            type(self.filter) is EvidenceProjectionFilter
            and self.filter.author is not None
            and self.writer_id is None
        ):
            raise _invalid()
        if type(self.view) is not str or self.view not in {
            "compact",
            "assignment",
            "obligations",
            "findings",
            "evidence",
            "results",
            "history",
            "versions",
        }:
            raise _invalid()
        if type(self.requested_frontier) is not Frontier:
            raise _invalid()
        if type(self.limit) is not int or not 1 <= self.limit <= 100:
            raise _invalid()
        if self.expected_projection_version is not None:
            _identity(self.expected_projection_version)
        filter_types: dict[str, type[object] | None] = {
            "compact": None,
            "assignment": AssignmentProjectionFilter,
            "obligations": ObligationsProjectionFilter,
            "findings": FindingsProjectionFilter,
            "evidence": EvidenceProjectionFilter,
            "results": None,
            "history": HistoryProjectionFilter,
            "versions": None,
        }
        position_types: dict[str, type[object] | None] = {
            "compact": None,
            "assignment": IdProjectionPosition,
            "obligations": IdProjectionPosition,
            "findings": FindingProjectionPosition,
            "evidence": IdProjectionPosition,
            "results": IdProjectionPosition,
            "history": HistoryProjectionPosition,
            "versions": None,
        }
        expected_filter = filter_types[self.view]
        expected_position = position_types[self.view]
        if (expected_filter is None and self.filter is not None) or (
            expected_filter is not None
            and self.filter is not None
            and type(self.filter) is not expected_filter
        ):
            raise _invalid()
        if (expected_position is None and self.position is not None) or (
            expected_position is not None
            and self.position is not None
            and type(self.position) is not expected_position
        ):
            raise _invalid()
        if type(self.position) is IdProjectionPosition:
            prefixes = {
                "assignment": "evt_",
                "obligations": "obl_",
                "evidence": "evd_",
                "results": "res_",
            }
            if not self.position.last_id.startswith(prefixes[self.view]):
                raise _invalid()


type ProjectionItem = (
    StatusAssignmentItemModel
    | StatusCompactItemModel
    | StatusEvidenceItemModel
    | StatusFindingItemModel
    | StatusHistoryItemModel
    | StatusHistoryItemV14Model
    | StatusObligationItemModel
    | StatusResultItemModel
    | StatusVersionSliceModel
)


def _is_projection_item(value: object) -> bool:
    return type(value) in {
        StatusAssignmentItemModel,
        StatusCompactItemModel,
        StatusEvidenceItemModel,
        StatusFindingItemModel,
        StatusHistoryItemModel,
        StatusHistoryItemV14Model,
        StatusObligationItemModel,
        StatusResultItemModel,
        StatusVersionSliceModel,
    }


@dataclass(frozen=True, slots=True)
class ProjectionPage:
    view: QueryableProjectionView
    items: tuple[ProjectionItem, ...]
    requested_frontier: Frontier
    head_frontier: Frontier
    effective_frontier: Frontier
    lag: int
    projection_version: str
    rebuild_state: Literal["current", "rebuild_required", "rebuilding"]
    coverage: Coverage
    gaps: tuple[str, ...]
    next_position: ProjectionPosition | None
    # Evidence pages only: the service-read ledger authorship of each returned row, parallel to
    # ``items``, taken from the same frozen frontier. It is a trusted structural fact for the
    # disclosure boundary and never becomes wire content. An empty member means the row's source
    # could not be attributed, which the boundary treats as ambiguous.
    item_sources: tuple[tuple[SourceAuthorship, ...], ...] = ()
    # Internal, compact-only: the per-request closure-readiness facts the status application
    # cannot read off the compact row (ADR-032). Never part of a wire page and never cached
    # across frontiers; an adapter that cannot derive them leaves ``None``.
    readiness_facts: ClosureReadinessFacts | None = None

    def __post_init__(self) -> None:
        if type(self.view) is not str or self.view not in {
            "compact",
            "assignment",
            "obligations",
            "findings",
            "evidence",
            "results",
            "history",
            "versions",
        }:
            raise _invalid()
        if (
            type(self.items) is not tuple
            or len(self.items) > 100
            or any(not _is_projection_item(item) for item in self.items)
        ):
            raise _invalid()
        if type(self.item_sources) is not tuple or (
            self.item_sources
            and (
                self.view != "evidence"
                or len(self.item_sources) != len(self.items)
                or any(
                    type(sources) is not tuple
                    or any(type(source) is not SourceAuthorship for source in sources)
                    for sources in self.item_sources
                )
            )
        ):
            raise _invalid()
        item_type_by_view = {
            "assignment": StatusAssignmentItemModel,
            "compact": StatusCompactItemModel,
            "evidence": StatusEvidenceItemModel,
            "findings": StatusFindingItemModel,
            "history": StatusHistoryItemModel,
            "obligations": StatusObligationItemModel,
            "results": StatusResultItemModel,
            "versions": StatusVersionSliceModel,
        }
        expected_item_type = item_type_by_view[self.view]
        if self.view == "history":
            if any(
                type(item) not in {StatusHistoryItemModel, StatusHistoryItemV14Model}
                for item in self.items
            ):
                raise _invalid()
        elif any(type(item) is not expected_item_type for item in self.items):
            raise _invalid()
        if self.view in {"compact", "versions"} and (
            len(self.items) > 1 or self.next_position is not None
        ):
            raise _invalid()
        for frontier in (self.requested_frontier, self.head_frontier, self.effective_frontier):
            if type(frontier) is not Frontier:
                raise _invalid()
        if self.effective_frontier > self.head_frontier:
            raise _invalid()
        _uint(self.lag, sqlite=True)
        if self.lag != self.head_frontier.sequence - self.effective_frontier.sequence:
            raise _invalid()
        _identity(self.projection_version)
        if type(self.rebuild_state) is not str or self.rebuild_state not in {
            "current",
            "rebuild_required",
            "rebuilding",
        }:
            raise _invalid()
        if type(self.coverage) is not Coverage:
            raise _invalid()
        _sorted_unique_strings(self.gaps)
        if self.gaps != self.coverage.known_gaps:
            raise _invalid()
        if self.readiness_facts is not None and (
            self.view != "compact" or type(self.readiness_facts) is not ClosureReadinessFacts
        ):
            raise _invalid()
        expected_position = {
            "assignment": IdProjectionPosition,
            "compact": None,
            "evidence": IdProjectionPosition,
            "findings": FindingProjectionPosition,
            "history": HistoryProjectionPosition,
            "obligations": IdProjectionPosition,
            "results": IdProjectionPosition,
            "versions": None,
        }[self.view]
        if (expected_position is None and self.next_position is not None) or (
            expected_position is not None
            and self.next_position is not None
            and type(self.next_position) is not expected_position
        ):
            raise _invalid()
        if type(self.next_position) is IdProjectionPosition:
            prefixes = {
                "assignment": "evt_",
                "evidence": "evd_",
                "obligations": "obl_",
                "results": "res_",
            }
            if not self.next_position.last_id.startswith(prefixes[self.view]):
                raise _invalid()


class LedgerPort(Protocol):
    async def append_batch(self, command: AppendCommand) -> AppendResult: ...

    async def load_frontier(self) -> Frontier: ...

    async def has_active_frozen_case(self, session_id: str) -> bool: ...

    def load_events(
        self,
        session_id: str,
        *,
        after: int = 0,
        through: int | None = None,
    ) -> AsyncIterator[LedgerRecord]: ...

    async def load_projection(
        self, session_id: str, view: ProjectionView
    ) -> StoredProjection | None: ...

    async def load_case_availability(
        self,
        session_id: str,
        frontier: Frontier,
        projection: ProjectionState,
    ) -> CaseAvailabilityFacts: ...

    async def query_projection(self, query: ProjectionQuery) -> ProjectionPage: ...

    async def freeze_case(
        self,
        session_id: str,
        writer_id: str,
        expected_frontier: int | None,
        request_id: str,
        request_digest: str,
    ) -> FrozenCase | CheckCommitResult: ...

    async def advance_check_phase(
        self,
        lease: OperationLease,
        expected_phase: CheckPhase,
        next_phase: CheckPhase,
        durable_object_ref: ObjectRef | None = None,
    ) -> OperationLease: ...

    async def suspend_check_for_repository_grant(self, lease: OperationLease) -> None: ...

    async def suspend_check_for_review_input(self, lease: OperationLease) -> None: ...

    async def enqueue_semantic_job(
        self,
        lease: OperationLease,
        case_digest: str,
        case_object_ref: ObjectRef,
    ) -> SemanticJobRecord: ...

    async def claim_semantic_job(
        self, lease: OperationLease, job_id: str
    ) -> SemanticAttemptHandle: ...

    async def record_attempt_outcome(
        self,
        handle: SemanticAttemptHandle,
        outcome: AttemptOutcome,
        result_object_ref: ObjectRef | None = None,
        terminal_code: SemanticReason | None = None,
        token_usage: RuntimeTokenUsage | None = None,
    ) -> None: ...

    async def fail_semantic_job(
        self,
        lease: OperationLease,
        job_id: str,
        terminal_code: SemanticReason,
    ) -> SemanticJobRecord: ...

    async def select_attempt(
        self,
        lease: OperationLease,
        handle: SemanticAttemptHandle,
        selected_result_object_ref: ObjectRef,
    ) -> SelectedAttempt: ...

    async def load_semantic_job(
        self, writer_id: str, operation_id: str
    ) -> SemanticJobRecord | None: ...

    async def list_semantic_attempts(self, job_id: str) -> tuple[SemanticAttemptRecord, ...]: ...

    async def record_disclosure_wait(
        self,
        handle: SemanticAttemptHandle,
        pending_id: str,
        pending_expires_at: datetime,
    ) -> SemanticDisclosureWait: ...

    async def load_disclosure_wait(
        self, writer_id: str, operation_id: str
    ) -> SemanticDisclosureWait | None: ...

    async def resolve_disclosure_wait(self, job_id: str) -> SemanticDisclosureWait: ...

    async def begin_semantic_progress(
        self, job_id: str, queued_at: datetime, deadline_at: datetime
    ) -> None:
        """Create the ``queued`` progress row for a non-terminal job once; later calls no-op."""

        ...

    async def advance_semantic_progress(
        self,
        handle: SemanticAttemptHandle,
        phase: SemanticProgressPhase,
        observed_at: datetime,
    ) -> bool:
        """Move progress forward for the job's active attempt; return whether it advanced.

        A write that would not move ``(attempt_ordinal, phase)`` strictly forward, names an
        attempt that is no longer active, or targets a terminal job is ignored.
        """

        ...

    async def load_semantic_progress(
        self, writer_id: str, operation_id: str
    ) -> SemanticProgressRecord | None: ...

    async def renew_leases(self, lease: OperationLease) -> OperationLease:
        """Return a replacement lease under the operation's authenticated lifetime policy.

        For a queued or leased ``semantic-case/2`` job, the ledger reads the frozen case object
        named by that job and caps the operation and active-job lease at its persisted execution
        expiry plus the fixed cleanup grace. The caller supplies no deadline authority. Claiming
        a job inherits the replacement operation expiry, including after a same-task recovery
        rebind of an existing started attempt.
        """

        ...

    async def reclaim_operation(
        self, writer_id: str, operation_id: str, request_digest: str
    ) -> OperationLease | PendingVerdict: ...

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
    ) -> CheckCommitResult: ...

    async def fail_check_if_current(
        self, lease: OperationLease, failure: PublicOperationError
    ) -> None: ...

    async def lookup_operation(
        self, writer_id: str, operation_id: str
    ) -> OperationRecord | None: ...

    async def lookup_task_operation(
        self, writer_id: str, operation_id: str
    ) -> OperationRecord | None: ...

    async def lookup_check_admission(
        self, writer_id: str, operation_id: str
    ) -> CheckAdmissionRecord | None:
        """Report why an exact check request has no operation record yet (issue #838).

        ``None`` once an operation record exists, and whenever this service has neither a live
        acquisition reservation nor a recent pre-admission refusal for the exact key.
        """

        ...
