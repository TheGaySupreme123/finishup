"""Service-owned task lineage, delegation recovery, and admission policy.

Lineage crosses the catalog and task bundles, so it belongs beside the application use cases.  The
module deliberately keeps the policy independent from SQLite: the concrete catalog may implement
the :class:`LineageStore` protocol, while :class:`MemoryLineageStore` gives the conformance suite
an executable reference.  User supplied titles, prompts, and labels never enter these values; only
validated task/session identities and bounded structural snapshots are retained.

The coordinator separates four facts which are easy to accidentally conflate:

* work lifecycle (``open`` through one terminal state),
* session health (``active``, ``contact_lost``, or ``ended``),
* relationship origin, and
* parent acceptance.

That separation is what lets a lost session remain recoverable without making a receipt close work,
and what prevents a parent from rejecting an accepted child after a finding appears.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import secrets
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from enum import Enum
from types import MappingProxyType
from typing import Final, Protocol, TypeVar, cast

from finishup.domain.coordination import (
    SESSION_LEASE_SECONDS,
    LineageAcceptance,
    LineageOrigin,
    SessionHealth,
    WorkState,
)
from finishup.domain.events import MAX_DECLARED_QUIET_SECONDS
from finishup.domain.values import (
    Frontier,
    Timestamp,
    format_rfc3339_millis,
    timestamp_from_datetime,
    validate_commitment,
)
from finishup.ports.clock import ClockPort
from finishup.ports.host_lineage import HostLineageRegistryPort
from finishup.ports.ids import IdPort
from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.ids import IdKind, new_id, validate_id

__all__ = [
    "AdmissionDecision",
    "AdmissionRequest",
    "AdmissionResult",
    "AttachHandle",
    "DelegationOperation",
    "DelegationOperationState",
    "DelegationPhase",
    "DelegationRequest",
    "DelegationResult",
    "DependencyManifest",
    "LineageAcceptance",
    "LineageCatalogPort",
    "LineageConfig",
    "LineageCoordinator",
    "LineageOrigin",
    "LineageSnapshot",
    "LineageStatus",
    "LineageStore",
    "ABANDONMENT_REASONS",
    "MAX_TOP_LEVEL_CONTACT_LOST_HORIZON_SECONDS",
    "REVERSIBLE_ABANDONMENT_REASON",
    "LineageProjectAdmission",
    "LineageProjectAdmissionResolver",
    "HostSessionCommitmentLookup",
    "HostLineageAnnotationMerger",
    "MemoryLineageStore",
    "SessionHealth",
    "WorkState",
]


_MAX_SAFE_INTEGER: Final = 2**53 - 1
_MAX_HANDLE_BYTES: Final = 256
# D6 (#1239): the configurable horizon after which a quiet top-level task is abandoned, at most a
# week, so the recovery sweep's set of long-lived ``contact_lost`` tasks stays bounded.
MAX_TOP_LEVEL_CONTACT_LOST_HORIZON_SECONDS: Final = 604_800
# Why open work was, or will be, abandoned (``LineageSnapshot.abandonment_reason``). Only a
# ``contact_lost`` abandonment is reversible, by the same session's ``work_closed`` (D6).
ABANDONMENT_REASONS: Final = frozenset({"contact_lost", "session_ended", "attach_handle_expired"})
REVERSIBLE_ABANDONMENT_REASON: Final = "contact_lost"
_HANDLE_DOMAIN: Final = b"yoetz/lineage-attach-handle/v1\x00"

# Host adapters own the source-specific annotation store.  The callback receives only validated
# structural identities; prompts, paths, transcripts, and result content never cross this seam.
HostLineageAnnotationMerger = Callable[[Mapping[str, JsonValue]], Awaitable[None]]
# Increment-B cross-repository lineage is admitted by the ready service's project/grant
# authority.  The child task does not exist yet at this boundary, so the callback receives only
# the authenticated parent task and the child's trusted repository commitment.  ``None`` is a
# bounded refusal; a successful result freezes the project and membership generation used by the
# admission check.  Later C9 reads perform their own current-generation check.
LineageProjectAdmissionResolver = Callable[[str, str], Awaitable["LineageProjectAdmission | None"]]
HostSessionCommitmentLookup = Callable[[str, str], Awaitable[str | None]]
_AttachOperationResult = TypeVar("_AttachOperationResult")


class DelegationPhase(str, Enum):  # noqa: UP042 - durable operation phases
    LINEAGE_RESERVED = "lineage_reserved"
    CHILD_BUNDLE_READY = "child_bundle_ready"
    PARENT_EVENT_COMMITTED = "parent_event_committed"
    HANDLE_PUBLISHED = "handle_published"
    TERMINAL = "terminal"


class DelegationOperationState(str, Enum):  # noqa: UP042 - durable operation state
    PENDING = "pending"
    COMPLETE = "complete"
    QUARANTINED = "quarantined"


class AdmissionDecision(str, Enum):  # noqa: UP042 - application vocabulary
    CREATE = "create"
    RESUME = "resume"
    ATTACH = "attach"
    DELEGATE = "delegate"
    SELF_REGISTER = "self_register"


@dataclass(frozen=True, slots=True)
class LineageProjectAdmission:
    """The generation-bound project authority that admitted a cross-repository child."""

    project_id: str
    membership_generation: int

    def __post_init__(self) -> None:
        _id(IdKind.PROJECT, self.project_id)
        _bounded_int(self.membership_generation, minimum=1)


def _invalid() -> ValueError:
    return ValueError("invalid_lineage_value")


def _id(kind: IdKind, value: object) -> str:
    try:
        return validate_id(kind, value)
    except (TypeError, ValueError) as exc:
        raise _invalid() from exc


def _optional_id(kind: IdKind, value: object) -> str | None:
    if value is None:
        return None
    return _id(kind, value)


def _bounded_int(value: object, *, minimum: int = 0, maximum: int = _MAX_SAFE_INTEGER) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise _invalid()
    return value


def _timestamp(value: object) -> datetime:
    if type(value) is not datetime:
        raise _invalid()
    try:
        format_rfc3339_millis(value)
    except ValueError as exc:
        raise _invalid() from exc
    return value


def _commitment(value: object, *, optional: bool = True) -> str | None:
    if value is None and optional:
        return None
    try:
        return validate_commitment(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise _invalid() from exc


def _digest(value: object) -> str:
    if type(value) is not str or len(value) != 71 or not value.startswith("sha256:"):
        raise _invalid()
    if any(char not in "0123456789abcdef" for char in value.removeprefix("sha256:")):
        raise _invalid()
    return value


def _safe_handle(value: object) -> str:
    if type(value) is not str:
        raise _invalid()
    try:
        encoded = value.encode("ascii", "strict")
    except UnicodeEncodeError as exc:
        raise _invalid() from exc
    if not 32 <= len(encoded) <= _MAX_HANDLE_BYTES or any(byte <= 0x20 for byte in encoded):
        raise _invalid()
    return value


def _json_structural(value: object) -> JsonValue:
    """Copy a bounded structural mapping into canonical immutable JSON.

    Manifest facts are service-produced structural values.  Rejecting arbitrary objects here is
    useful because it keeps a caller from smuggling titles, prompts, or model output into catalog
    fields by accident.
    """

    if value is None or type(value) in {str, int, bool}:
        if type(value) is int and not 0 <= value <= _MAX_SAFE_INTEGER:
            raise _invalid()
        return cast(JsonValue, value)
    if isinstance(value, Mapping):
        mapping = cast(Mapping[object, object], value)
        if len(mapping) > 64:
            raise _invalid()
        result: dict[str, JsonValue] = {}
        for key, item in mapping.items():
            if type(key) is not str or not key or len(key.encode("utf-8")) > 128:
                raise _invalid()
            result[key] = _json_structural(item)
        return cast(JsonValue, result)
    if type(value) in {list, tuple}:
        items = cast(Sequence[object], value)
        if len(items) > 64:
            raise _invalid()
        return tuple(_json_structural(item) for item in items)
    raise _invalid()


def _error(
    code: PublicErrorCode,
    message: str,
    *,
    reason: str | None = None,
    retryable: bool = False,
    count: int | None = None,
) -> PublicOperationError:
    details: dict[str, object] = {}
    if reason is not None:
        details["reason_code"] = reason
    if count is not None:
        details["count"] = count
    return PublicOperationError(code, message, retryable, safe_details=details)


def _reversible(snapshot: LineageSnapshot, target: WorkState) -> bool:
    """Whether ``target`` may follow ``snapshot``'s terminal work state (D6, #1239).

    Only a ``contact_lost`` abandonment is reversible, and only by ``work_closed``: silence was
    never evidence the agent stopped, so its own close supersedes the service's guess. Both events
    stay in the ledger.
    """

    return (
        target is WorkState.CLOSED
        and snapshot.work_state is WorkState.ABANDONED
        and snapshot.abandonment_reason == REVERSIBLE_ABANDONMENT_REASON
    )


def _pending_reason(snapshot: LineageSnapshot) -> str | None:
    """The reason to keep when contact returns: none pending on open work, history otherwise."""

    return None if snapshot.work_state is WorkState.OPEN else snapshot.abandonment_reason


def _quiet_end(snapshot: LineageSnapshot) -> datetime | None:
    """The later end of the declared and the implied quiet period, or ``None`` (#1239, D6)."""

    declared, implied = snapshot.quiet_until, snapshot.implied_quiet_until
    if declared is None or implied is None:
        return declared if implied is None else implied
    return max(declared, implied)


def _quiet_deadline(snapshot: LineageSnapshot, lost_at: datetime, window: timedelta) -> datetime:
    """When open work out of contact since ``lost_at`` is abandoned (#1239, D6).

    A quiet period, declared by the task or implied by a tool call its host announced, counts as
    contact until it ends, so the window runs from whichever is later: the loss of contact or the
    end of the quiet period.
    """

    quiet = _quiet_end(snapshot)
    return (lost_at if quiet is None or quiet <= lost_at else quiet) + window


def _work_terminal_refusal(snapshot: LineageSnapshot) -> PublicOperationError:
    """A refusal that names the terminal state, when it began and what to do next (#1239)."""

    state = snapshot.work_state.value
    if snapshot.work_state is WorkState.ABANDONED:
        cause = snapshot.abandonment_reason or "recorded by the service"
        when = (
            ""
            if snapshot.abandonment_deadline is None
            else f" at {format_rfc3339_millis(snapshot.abandonment_deadline)}"
        )
        message = (
            f"This task's work was abandoned ({cause}){when}; only a contact_lost abandonment "
            "can be closed, by the same session. Keep this session for status, checks and "
            "receipts; start a successor task for new work."
        )
    else:
        message = (
            f"This task's work is already {state}; it has no further lifecycle transition. Keep "
            "this session for status, checks and receipts; start a successor task for new work."
        )
    return _error(PublicErrorCode.SESSION_CONFLICT, message, reason="lineage_work_transition")


@dataclass(frozen=True, slots=True)
class LineageConfig:
    """Bounded service policy for delegation and recovery timing."""

    start_lease_seconds: int = 60
    attach_handle_ttl_seconds: int = 300
    # How long a child whose parent is waiting may stay out of contact (D7, #1239), and the grace
    # after a delivered ``SessionEnd`` before its open work is abandoned.
    contact_lost_recovery_seconds: int = 300
    # How long any other task may stay out of contact (D6, #1239): a quiet top-level task with no
    # parent waiting is never abandoned for silence sooner. It shows ``contact_lost`` meanwhile.
    top_level_contact_lost_horizon_seconds: int = 86_400
    # The longest declared quiet period that takes effect (D6, #1239), and the longest a tool call
    # the host announced with its own timeout implies; 0 records a declaration without effect and
    # implies nothing.
    max_declared_quiet_seconds: int = 3_600
    max_depth: int = 8
    max_fanout: int = 32
    # Upper bound on how long one host-declared child operation (a native subagent observed
    # starting but not yet stopping) keeps its parent session in contact.  It bounds how late a
    # host that dies mid-operation is noticed; it is service policy, not user configuration.
    native_operation_hold_seconds: int = 3_600

    def __post_init__(self) -> None:
        for value in (
            self.start_lease_seconds,
            self.attach_handle_ttl_seconds,
            self.contact_lost_recovery_seconds,
            self.native_operation_hold_seconds,
        ):
            _bounded_int(value, minimum=1, maximum=86_400)
        _bounded_int(
            self.top_level_contact_lost_horizon_seconds,
            minimum=self.contact_lost_recovery_seconds,
            maximum=MAX_TOP_LEVEL_CONTACT_LOST_HORIZON_SECONDS,
        )
        _bounded_int(self.max_declared_quiet_seconds, minimum=0, maximum=MAX_DECLARED_QUIET_SECONDS)
        _bounded_int(self.max_depth, minimum=0, maximum=64)
        # Child snapshots, check previews, and receipt child sections all carry one
        # canonical bounded tuple.  Keep admission at that wire limit so a legal
        # configuration can never produce a state that a downstream surface cannot
        # represent without truncation.
        _bounded_int(self.max_fanout, minimum=1, maximum=64)


@dataclass(frozen=True, slots=True, repr=False)
class AttachHandle:
    """One opaque child-attachment bearer value.

    The value is intentionally hidden from ``repr`` and from all structural snapshot methods.  A
    catalog uses ``digest`` for capability lookup and retains the service-owned replay value so
    an interrupted delegation returns the same handle after restart. The SQLite adapter currently
    stores that replay value in its private catalog; this type does not promise encryption at rest.
    """

    value: str = field(repr=False)
    digest: str
    task_id: str
    expires_at: datetime
    consumed_session_id: str | None = None
    revoked: bool = False

    def __post_init__(self) -> None:
        _safe_handle(self.value)
        _digest(self.digest)
        _id(IdKind.TASK, self.task_id)
        _timestamp(self.expires_at)
        _optional_id(IdKind.SESSION, self.consumed_session_id)
        if type(self.revoked) is not bool:
            raise _invalid()


@dataclass(frozen=True, slots=True, repr=False)
class LineageSnapshot:
    """One task's service-owned lineage and lifecycle state."""

    task_id: str
    parent_task_id: str | None
    depth: int
    origin: LineageOrigin | None
    acceptance: LineageAcceptance | None
    work_state: WorkState
    session_health: SessionHealth
    active_session_id: str | None
    repository_commitment: str | None = field(default=None, repr=False)
    contact_lost_at: datetime | None = None
    abandonment_deadline: datetime | None = None
    lineage_authority_revision: int = 1
    # #1239: why open work will be abandoned at ``abandonment_deadline``, or why terminal work was
    # (one of ``ABANDONMENT_REASONS``); kept after a reversed ``contact_lost`` abandonment so the
    # closed work still says it was once abandoned.
    abandonment_reason: str | None = None
    # #1239: until when the task's own session declared it expects no contact, already clamped by
    # ``LineageConfig.max_declared_quiet_seconds``. Open work out of contact keeps its window from
    # this time; contact does not clear it, it simply passes.
    quiet_until: datetime | None = None
    # #1239: until when a tool call the host announced on the task's own active session, with the
    # call's own timeout, implies the session expects no contact; clamped by the same setting.
    # Kept apart from ``quiet_until`` so a declaration, or its replay, never shortens a running
    # call's period, and the call never revives a replaced declaration. It also simply passes.
    implied_quiet_until: datetime | None = None

    def __post_init__(self) -> None:
        _id(IdKind.TASK, self.task_id)
        _optional_id(IdKind.TASK, self.parent_task_id)
        _bounded_int(self.depth)
        if type(self.origin) not in {LineageOrigin, type(None)}:
            raise _invalid()
        if type(self.acceptance) not in {LineageAcceptance, type(None)}:
            raise _invalid()
        if type(self.work_state) is not WorkState or type(self.session_health) is not SessionHealth:
            raise _invalid()
        _optional_id(IdKind.SESSION, self.active_session_id)
        _commitment(self.repository_commitment)
        if self.contact_lost_at is not None:
            _timestamp(self.contact_lost_at)
        if self.abandonment_deadline is not None:
            _timestamp(self.abandonment_deadline)
        _bounded_int(self.lineage_authority_revision, minimum=1)
        if self.quiet_until is not None:
            _timestamp(self.quiet_until)
        if self.implied_quiet_until is not None:
            _timestamp(self.implied_quiet_until)
        if self.abandonment_reason is not None and self.abandonment_reason not in (
            ABANDONMENT_REASONS
        ):
            raise _invalid()
        if self.parent_task_id is None:
            if self.depth != 0 or self.origin is not None or self.acceptance is not None:
                raise _invalid()
        elif self.depth == 0 or self.origin is None or self.acceptance is None:
            raise _invalid()
        if self.session_health is SessionHealth.ACTIVE and self.active_session_id is None:
            raise _invalid()

    def as_wire(self) -> dict[str, JsonValue]:
        """Return only the closed structural fields allowed in status projections."""

        return {
            "acceptance": None if self.acceptance is None else self.acceptance.value,
            "active_session_id": self.active_session_id,
            "contact_lost_at": (
                None
                if self.contact_lost_at is None
                else format_rfc3339_millis(self.contact_lost_at)
            ),
            "depth": self.depth,
            "lineage_authority_revision": self.lineage_authority_revision,
            "origin": None if self.origin is None else self.origin.value,
            "parent_task_id": self.parent_task_id,
            "session_health": self.session_health.value,
            "task_id": self.task_id,
            "work_state": self.work_state.value,
        }


@dataclass(frozen=True, slots=True, repr=False)
class DependencyManifest:
    """Frozen child facts recorded in the parent ledger before rollup."""

    parent_task_id: str
    child_task_id: str
    origin: LineageOrigin
    acceptance: LineageAcceptance
    child_frontier: Frontier
    child_check_id: str | None
    child_receipt_id: str | None
    coverage: Mapping[str, JsonValue]
    findings_state: Mapping[str, JsonValue]
    lineage_authority_revision: int
    membership_generation: int | None = None
    manifest_digest: str = field(init=False)

    def __post_init__(self) -> None:
        parent = _id(IdKind.TASK, self.parent_task_id)
        child = _id(IdKind.TASK, self.child_task_id)
        if parent == child:
            raise _invalid()
        if type(self.origin) is not LineageOrigin or type(self.acceptance) is not LineageAcceptance:
            raise _invalid()
        if type(self.child_frontier) is not Frontier:
            raise _invalid()
        # Check identifiers share the event identifier grammar in this protocol revision; the
        # public IdKind enum intentionally has no separate CHECK member.
        _optional_id(IdKind.EVENT, self.child_check_id)
        _optional_id(IdKind.RECEIPT, self.child_receipt_id)
        coverage = _json_structural(self.coverage)
        findings = _json_structural(self.findings_state)
        if not isinstance(coverage, Mapping) or not isinstance(findings, Mapping):
            raise _invalid()
        _bounded_int(self.lineage_authority_revision, minimum=1)
        _bounded_int(self.membership_generation, minimum=1) if self.membership_generation else None
        encoded = canonical_encode(
            {
                "acceptance": self.acceptance.value,
                "child_check_id": self.child_check_id,
                "child_frontier": self.child_frontier.as_wire(),
                "child_receipt_id": self.child_receipt_id,
                "child_task_id": child,
                "coverage": coverage,
                "findings_state": findings,
                "lineage_authority_revision": self.lineage_authority_revision,
                "membership_generation": self.membership_generation,
                "origin": self.origin.value,
                "parent_task_id": parent,
            }
        )
        object.__setattr__(self, "manifest_digest", f"sha256:{hashlib.sha256(encoded).hexdigest()}")
        object.__setattr__(
            self, "coverage", MappingProxyType(dict(cast(Mapping[str, JsonValue], coverage)))
        )
        object.__setattr__(
            self,
            "findings_state",
            MappingProxyType(dict(cast(Mapping[str, JsonValue], findings))),
        )

    def as_wire(self) -> dict[str, JsonValue]:
        """Return the frozen manifest identity and bounded structural facts."""

        return {
            "acceptance": self.acceptance.value,
            "child_check_id": self.child_check_id,
            "child_frontier": cast(JsonValue, self.child_frontier.as_wire()),
            "child_receipt_id": self.child_receipt_id,
            "child_task_id": self.child_task_id,
            "coverage": cast(JsonValue, dict(self.coverage)),
            "findings_state": cast(JsonValue, dict(self.findings_state)),
            "lineage_authority_revision": self.lineage_authority_revision,
            "manifest_digest": self.manifest_digest,
            "membership_generation": self.membership_generation,
            "origin": self.origin.value,
            "parent_task_id": self.parent_task_id,
        }


@dataclass(frozen=True, slots=True, repr=False)
class DelegationRequest:
    operation_id: str
    request_digest: str
    parent_task_id: str
    parent_session_id: str
    repository_commitment: str | None = field(default=None, repr=False)
    workspace_commitment: str | None = field(default=None, repr=False)
    external_commitment: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        _id(IdKind.REQUEST, self.operation_id)
        _digest(self.request_digest)
        _id(IdKind.TASK, self.parent_task_id)
        _id(IdKind.SESSION, self.parent_session_id)
        _commitment(self.repository_commitment)
        _commitment(self.workspace_commitment)
        _commitment(self.external_commitment)
        if (self.workspace_commitment is None) != (self.external_commitment is None):
            raise _invalid()


@dataclass(frozen=True, slots=True, repr=False)
class DelegationOperation:
    operation_id: str
    request_digest: str
    parent_task_id: str
    parent_session_id: str
    child_task_id: str
    depth: int
    phase: DelegationPhase
    state: DelegationOperationState
    handle_digest: str
    owner_generation: int
    lease_expires_at: datetime
    terminal_at: datetime | None = None
    # Cross-repository admission is bound to the exact project membership generation that
    # authorized the operation.  These values are optional for same-repository and legacy
    # operations, but must always be stored as a pair so replay cannot lose the authority fact.
    project_id: str | None = None
    membership_generation: int | None = None

    def __post_init__(self) -> None:
        _id(IdKind.REQUEST, self.operation_id)
        _digest(self.request_digest)
        _id(IdKind.TASK, self.parent_task_id)
        _id(IdKind.SESSION, self.parent_session_id)
        _id(IdKind.TASK, self.child_task_id)
        _bounded_int(self.depth)
        if (
            type(self.phase) is not DelegationPhase
            or type(self.state) is not DelegationOperationState
        ):
            raise _invalid()
        _digest(self.handle_digest)
        _bounded_int(self.owner_generation, minimum=1)
        _timestamp(self.lease_expires_at)
        if self.terminal_at is not None:
            _timestamp(self.terminal_at)
        _optional_id(IdKind.PROJECT, self.project_id)
        if self.membership_generation is not None:
            _bounded_int(self.membership_generation, minimum=1)
        if (self.project_id is None) != (self.membership_generation is None):
            raise _invalid()
        if (
            self.state is DelegationOperationState.COMPLETE
            and self.phase is not DelegationPhase.TERMINAL
        ):
            raise _invalid()
        if (
            self.state is DelegationOperationState.PENDING
            and self.phase is DelegationPhase.TERMINAL
        ):
            raise _invalid()


@dataclass(frozen=True, slots=True, repr=False)
class DelegationResult:
    operation: DelegationOperation
    task_id: str
    attach_handle: AttachHandle = field(repr=False)
    depth: int
    origin: LineageOrigin
    acceptance: LineageAcceptance

    def __post_init__(self) -> None:
        _id(IdKind.TASK, self.task_id)
        if self.operation.child_task_id != self.task_id:
            raise _invalid()
        if (
            type(self.attach_handle) is not AttachHandle
            or self.attach_handle.task_id != self.task_id
        ):
            raise _invalid()
        _bounded_int(self.depth)
        if type(self.origin) is not LineageOrigin or type(self.acceptance) is not LineageAcceptance:
            raise _invalid()


@dataclass(frozen=True, slots=True, repr=False)
class AdmissionRequest:
    """Inputs to the automatic create-versus-resume decision table.

    Candidate ids are supplied by the trusted lifecycle binding/catalog.  The coordinator never
    discovers a task from a repository or workspace commitment alone.
    """

    same_pair_task_id: str | None = None
    predecessor_task_ids: tuple[str, ...] = ()
    attach_handle_present: bool = False
    parent_session_present: bool = False
    auto_grouping: bool = True
    live_task_count: int = 0
    repository_commitment: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        _optional_id(IdKind.TASK, self.same_pair_task_id)
        if type(self.predecessor_task_ids) is not tuple:
            raise _invalid()
        for task in self.predecessor_task_ids:
            _id(IdKind.TASK, task)
        if len(set(self.predecessor_task_ids)) != len(self.predecessor_task_ids):
            raise _invalid()
        if (
            type(self.attach_handle_present) is not bool
            or type(self.parent_session_present) is not bool
        ):
            raise _invalid()
        if type(self.auto_grouping) is not bool:
            raise _invalid()
        _bounded_int(self.live_task_count)
        _commitment(self.repository_commitment)


@dataclass(frozen=True, slots=True)
class AdmissionResult:
    decision: AdmissionDecision
    task_id: str | None
    project_should_exist: bool
    predecessor_resumed: bool = False
    candidate_count: int = 0

    def __post_init__(self) -> None:
        if type(self.decision) is not AdmissionDecision:
            raise _invalid()
        _optional_id(IdKind.TASK, self.task_id)
        if (
            type(self.project_should_exist) is not bool
            or type(self.predecessor_resumed) is not bool
        ):
            raise _invalid()
        _bounded_int(self.candidate_count)

    def as_wire(self) -> dict[str, JsonValue]:
        return {
            "candidate_count": self.candidate_count,
            "decision": self.decision.value,
            "predecessor_resumed": self.predecessor_resumed,
            "project_should_exist": self.project_should_exist,
            "task_id": self.task_id,
        }


@dataclass(frozen=True, slots=True)
class LineageStatus:
    """One-level status projection; child content is never included."""

    task_id: str
    parent: LineageSnapshot | None
    children: tuple[LineageSnapshot, ...]

    def __post_init__(self) -> None:
        _id(IdKind.TASK, self.task_id)
        if self.parent is not None and type(self.parent) is not LineageSnapshot:
            raise _invalid()
        if type(self.children) is not tuple or any(
            type(item) is not LineageSnapshot for item in self.children
        ):
            raise _invalid()

    def as_wire(self) -> dict[str, JsonValue]:
        return {
            "children": [item.as_wire() for item in self.children],
            "parent": None if self.parent is None else self.parent.as_wire(),
            "task_id": self.task_id,
        }


class LineageStore(Protocol):
    """Durable catalog contract consumed by :class:`LineageCoordinator`.

    Implementations must make each method idempotent under the supplied operation/request digest.
    A SQLite implementation should commit each phase and preserve the operation row on process
    crash.  The memory implementation below follows the same semantics and is deliberately strict.
    """

    async def get_task(self, task_id: str) -> LineageSnapshot | None: ...

    async def list_children(self, parent_task_id: str) -> tuple[LineageSnapshot, ...]: ...

    async def list_tasks(self) -> tuple[LineageSnapshot, ...]: ...

    async def get_session_task(self, session_id: str) -> str | None: ...

    async def save_task(self, snapshot: LineageSnapshot) -> None: ...

    async def get_operation(self, operation_id: str) -> DelegationOperation | None: ...

    async def save_operation(self, operation: DelegationOperation) -> None: ...

    async def save_self_registration(
        self,
        operation: DelegationOperation,
        child: LineageSnapshot,
        *,
        workspace_commitment: str | None = None,
        external_commitment: str | None = None,
    ) -> None: ...

    async def get_handle(self, digest: str) -> AttachHandle | None: ...

    async def save_handle(self, handle: AttachHandle) -> None: ...

    async def revoke_handles(self, task_id: str) -> None: ...

    async def save_reservation(
        self,
        operation: DelegationOperation,
        child: LineageSnapshot,
        handle: AttachHandle,
        *,
        workspace_commitment: str | None = None,
        external_commitment: str | None = None,
    ) -> None: ...

    async def get_manifest(
        self, parent_task_id: str, child_task_id: str
    ) -> DependencyManifest | None: ...

    async def save_manifest(self, manifest: DependencyManifest) -> None: ...


# A narrower alias is useful to the service composition code and allows storage to expose only the
# manifest/status operations when delegation is not enabled in an older catalog.
LineageCatalogPort = LineageStore


@dataclass(slots=True)
class MemoryLineageStore:
    """Reference durable-like store for unit/conformance tests."""

    tasks: dict[str, LineageSnapshot] = field(default_factory=lambda: dict[str, LineageSnapshot]())
    sessions: dict[str, str] = field(default_factory=lambda: dict[str, str]())
    operations: dict[str, DelegationOperation] = field(
        default_factory=lambda: dict[str, DelegationOperation]()
    )
    handles: dict[str, AttachHandle] = field(default_factory=lambda: dict[str, AttachHandle]())
    manifests: dict[tuple[str, str], DependencyManifest] = field(
        default_factory=lambda: dict[tuple[str, str], DependencyManifest]()
    )

    async def get_task(self, task_id: str) -> LineageSnapshot | None:
        return self.tasks.get(_id(IdKind.TASK, task_id))

    async def list_children(self, parent_task_id: str) -> tuple[LineageSnapshot, ...]:
        parent = _id(IdKind.TASK, parent_task_id)
        return tuple(
            sorted(
                (task for task in self.tasks.values() if task.parent_task_id == parent),
                key=lambda x: x.task_id,
            )
        )

    async def list_tasks(self) -> tuple[LineageSnapshot, ...]:
        return tuple(sorted(self.tasks.values(), key=lambda item: item.task_id))

    async def get_session_task(self, session_id: str) -> str | None:
        return self.sessions.get(_id(IdKind.SESSION, session_id))

    async def save_task(self, snapshot: LineageSnapshot) -> None:
        if type(snapshot) is not LineageSnapshot:
            raise _invalid()
        existing = self.tasks.get(snapshot.task_id)
        if existing is not None:
            # Parentage, origin, depth, and repository binding are immutable.  Session and work
            # facts intentionally move through this method as the service records lifecycle
            # transitions.
            if (
                existing.parent_task_id != snapshot.parent_task_id
                or existing.depth != snapshot.depth
                or existing.origin != snapshot.origin
                or existing.repository_commitment != snapshot.repository_commitment
            ):
                raise _error(
                    PublicErrorCode.STORAGE_CORRUPT,
                    "The lineage state is inconsistent.",
                    reason="lineage_task_conflict",
                )
        self.tasks[snapshot.task_id] = snapshot
        if snapshot.active_session_id is not None:
            bound = self.sessions.get(snapshot.active_session_id)
            if bound is not None and bound != snapshot.task_id:
                raise _error(
                    PublicErrorCode.STORAGE_CORRUPT,
                    "The lineage state is inconsistent.",
                    reason="lineage_session_conflict",
                )
            self.sessions[snapshot.active_session_id] = snapshot.task_id
        if snapshot.work_state in {
            WorkState.ABANDONED,
            WorkState.CANCELLED,
            WorkState.WRITTEN_OFF,
        }:
            for digest, handle in tuple(self.handles.items()):
                if handle.task_id == snapshot.task_id and not handle.revoked:
                    self.handles[digest] = replace(handle, revoked=True)

    async def get_operation(self, operation_id: str) -> DelegationOperation | None:
        return self.operations.get(_id(IdKind.REQUEST, operation_id))

    async def save_operation(self, operation: DelegationOperation) -> None:
        if type(operation) is not DelegationOperation:
            raise _invalid()
        existing = self.operations.get(operation.operation_id)
        if existing is not None:
            if (
                existing.request_digest != operation.request_digest
                or existing.parent_task_id != operation.parent_task_id
                or existing.parent_session_id != operation.parent_session_id
                or existing.child_task_id != operation.child_task_id
                or existing.handle_digest != operation.handle_digest
                or existing.project_id != operation.project_id
                or existing.membership_generation != operation.membership_generation
            ):
                raise _error(
                    PublicErrorCode.STORAGE_CORRUPT,
                    "The lineage operation is inconsistent.",
                    reason="lineage_operation_conflict",
                )
        self.operations[operation.operation_id] = operation

    async def save_self_registration(
        self,
        operation: DelegationOperation,
        child: LineageSnapshot,
        *,
        workspace_commitment: str | None = None,
        external_commitment: str | None = None,
    ) -> None:
        """Install a pending self-registration's child and terminal operation together."""

        if (
            type(operation) is not DelegationOperation
            or type(child) is not LineageSnapshot
            or operation.child_task_id != child.task_id
        ):
            raise _invalid()
        _commitment(workspace_commitment)
        _commitment(external_commitment)
        if (workspace_commitment is None) != (external_commitment is None):
            raise _invalid()
        existing = self.operations.get(operation.operation_id)
        if existing is not None:
            if existing != operation:
                raise _error(
                    PublicErrorCode.STORAGE_CORRUPT,
                    "The lineage operation is inconsistent.",
                    reason="lineage_operation_conflict",
                )
            return
        if child.task_id in self.tasks:
            raise _error(
                PublicErrorCode.STORAGE_CORRUPT,
                "The self-registration child already exists.",
                reason="lineage_task_conflict",
            )
        # Validate the child and operation before assigning either map.  The reference store has
        # no transaction primitive, so this ordering keeps malformed input from leaving a partial
        # self-registration behind.
        await self.save_task(child)
        try:
            await self.save_operation(operation)
        except BaseException:
            self.tasks.pop(child.task_id, None)
            if child.active_session_id is not None:
                self.sessions.pop(child.active_session_id, None)
            raise

    async def get_handle(self, digest: str) -> AttachHandle | None:
        return self.handles.get(_digest(digest))

    async def save_handle(self, handle: AttachHandle) -> None:
        if type(handle) is not AttachHandle:
            raise _invalid()
        existing = self.handles.get(handle.digest)
        if existing is not None:
            if (
                existing.task_id != handle.task_id
                or existing.value != handle.value
                or existing.expires_at != handle.expires_at
            ):
                raise _error(
                    PublicErrorCode.STORAGE_CORRUPT,
                    "The attach handle is inconsistent.",
                    reason="lineage_handle_conflict",
                )
            if (
                existing.consumed_session_id is not None
                and existing.consumed_session_id != handle.consumed_session_id
            ):
                raise _error(
                    PublicErrorCode.SESSION_CONFLICT,
                    "The attach handle was already used.",
                    reason="attach_handle_reused",
                )
            if existing.revoked and not handle.revoked:
                raise _error(
                    PublicErrorCode.SESSION_CONFLICT,
                    "The attach handle has been revoked.",
                    reason="attach_handle_revoked",
                )
        self.handles[handle.digest] = handle

    async def revoke_handles(self, task_id: str) -> None:
        task = _id(IdKind.TASK, task_id)
        for digest, handle in tuple(self.handles.items()):
            if handle.task_id == task and not handle.revoked:
                self.handles[digest] = replace(handle, revoked=True)

    async def save_reservation(
        self,
        operation: DelegationOperation,
        child: LineageSnapshot,
        handle: AttachHandle,
        *,
        workspace_commitment: str | None = None,
        external_commitment: str | None = None,
    ) -> None:
        """Install the reservation's three rows as one reference-store mutation."""

        if (
            type(operation) is not DelegationOperation
            or type(child) is not LineageSnapshot
            or type(handle) is not AttachHandle
            or operation.child_task_id != child.task_id
            or operation.handle_digest != handle.digest
        ):
            raise _invalid()
        _commitment(workspace_commitment)
        _commitment(external_commitment)
        if (workspace_commitment is None) != (external_commitment is None):
            raise _invalid()
        existing = self.operations.get(operation.operation_id)
        if existing is not None:
            if existing != operation:
                raise _error(
                    PublicErrorCode.STORAGE_CORRUPT,
                    "The lineage operation is inconsistent.",
                    reason="lineage_operation_conflict",
                )
            return
        if child.task_id in self.tasks or handle.digest in self.handles:
            raise _error(
                PublicErrorCode.STORAGE_CORRUPT,
                "The lineage reservation is inconsistent.",
                reason="lineage_reservation_conflict",
            )
        # Validate all writes before assigning any map so a malformed child cannot leave a partial
        # reservation that a later retry would mistake for a durable operation.
        await self.save_operation(operation)
        await self.save_task(child)
        await self.save_handle(handle)

    async def get_manifest(
        self, parent_task_id: str, child_task_id: str
    ) -> DependencyManifest | None:
        return self.manifests.get(
            (_id(IdKind.TASK, parent_task_id), _id(IdKind.TASK, child_task_id))
        )

    async def save_manifest(self, manifest: DependencyManifest) -> None:
        if type(manifest) is not DependencyManifest:
            raise _invalid()
        key = (manifest.parent_task_id, manifest.child_task_id)
        existing = self.manifests.get(key)
        if existing is not None and existing.manifest_digest != manifest.manifest_digest:
            # A child fact can change only by recording a new authority revision.  Replacing the
            # old snapshot in a parent projection would break deterministic replay.
            if manifest.lineage_authority_revision <= existing.lineage_authority_revision:
                raise _error(
                    PublicErrorCode.SESSION_CONFLICT,
                    "The child dependency revision is stale.",
                    reason="lineage_manifest_stale",
                )
        self.manifests[key] = manifest


class LineageCoordinator:
    """Coordinate delegation and lifecycle transitions through a catalog port.

    All public methods are safe to call repeatedly.  The coordinator serializes policy decisions
    within one service process; a durable catalog remains the authority across process restarts.
    """

    def __init__(
        self,
        *,
        store: LineageStore,
        clock: ClockPort,
        ids: IdPort | None = None,
        config: LineageConfig = LineageConfig(),
        handle_key: bytes | None = None,
        handle_mac: Callable[[str], str] | None = None,
        owner_generation: int = 1,
        parent_event_committer: Callable[[DelegationOperation], Awaitable[None]] | None = None,
        bundle_provisioner: Callable[[str, int], Awaitable[None]] | None = None,
        host_annotation_merger: HostLineageAnnotationMerger | None = None,
        host_lineage_registry: HostLineageRegistryPort | None = None,
        host_session_commitment_lookup: HostSessionCommitmentLookup | None = None,
        project_admission_resolver: LineageProjectAdmissionResolver | None = None,
    ) -> None:
        # Runtime-checkable protocols are intentionally avoided; duck typing here permits the
        # SQLite adapter to implement the contract without inheriting a marker class.
        required = (
            "get_task",
            "list_children",
            "get_session_task",
            "save_task",
            "get_operation",
            "save_operation",
            "get_handle",
            "save_handle",
            "get_manifest",
            "save_manifest",
        )
        if any(not callable(getattr(store, name, None)) for name in required):
            raise TypeError("lineage_store_invalid")
        if not callable(getattr(clock, "now_utc", None)):
            raise TypeError("lineage_clock_invalid")
        _bounded_int(owner_generation, minimum=1)
        # A fixed module constant would make every installation share a bearer-token key.  The
        # production composition passes ``handle_mac`` backed by an installation-owned vault
        # handle; byte keys remain available only when a caller explicitly injects one (tests and
        # isolated harnesses).  Requiring one at construction also prevents an accidentally
        # unkeyed capability from being minted during a partially configured READY build.
        if handle_mac is None and (
            type(handle_key) is not bytes or not 16 <= len(handle_key) <= 128
        ):
            raise ValueError("lineage_handle_key_required")
        if handle_mac is not None and not callable(handle_mac):
            raise TypeError("lineage_handle_mac_invalid")
        if host_annotation_merger is not None and not callable(host_annotation_merger):
            raise TypeError("lineage_host_annotation_merger_invalid")
        if project_admission_resolver is not None and not callable(project_admission_resolver):
            raise TypeError("lineage_project_admission_resolver_invalid")
        if host_session_commitment_lookup is not None and not callable(
            host_session_commitment_lookup
        ):
            raise TypeError("lineage_host_session_commitment_lookup_invalid")
        if host_lineage_registry is not None and any(
            not callable(getattr(host_lineage_registry, name, None))
            for name in (
                "record_host_lineage_observation",
                "list_provisional_annotations",
                "bind_provisional_annotation",
                "bind_host_lineage_identity",
            )
        ):
            raise TypeError("lineage_host_lineage_registry_invalid")
        self._store = store
        self._clock = clock
        self._ids = ids
        self._config = config
        self._handle_key = b"" if handle_key is None else bytes(handle_key)
        self._handle_mac = handle_mac
        self._owner_generation = owner_generation
        self._parent_event_committer = parent_event_committer
        self._bundle_provisioner = bundle_provisioner
        self._host_annotation_merger = host_annotation_merger
        self._host_lineage_registry = host_lineage_registry
        self._host_session_commitment_lookup = host_session_commitment_lookup
        self._project_admission_resolver = project_admission_resolver
        self._host_session_commitments: dict[tuple[str, str], str] = {}
        self._lock = asyncio.Lock()

    @property
    def store(self) -> LineageStore:
        """Expose the catalog boundary to status/rollup applications.

        The returned value is the service-owned adapter, never a raw database connection.  This
        accessor lets the status and receipt lanes share the exact same lineage snapshot source.
        """

        return self._store

    @property
    def config(self) -> LineageConfig:
        return self._config

    @property
    def host_lineage_registry(self) -> HostLineageRegistryPort | None:
        """Expose the narrow host annotation view to status without widening ``LineageStore``."""

        return self._host_lineage_registry

    def _new(self, kind: IdKind) -> str:
        candidate = self._ids.new(kind) if self._ids is not None else new_id(kind)
        return _id(kind, candidate)

    def _now(self) -> datetime:
        return _timestamp(self._clock.now_utc())

    async def _cross_repository_admission(
        self,
        *,
        parent_task_id: str,
        parent_repository_commitment: str | None,
        child_repository_commitment: str | None,
    ) -> LineageProjectAdmission | None:
        """Resolve the current generation-bound grant for a repository mismatch."""

        if (
            parent_repository_commitment is None
            or child_repository_commitment is None
            or parent_repository_commitment == child_repository_commitment
        ):
            return None
        resolver = self._project_admission_resolver
        if resolver is None:
            return None
        try:
            result = await resolver(parent_task_id, child_repository_commitment)
        except Exception:
            return None
        return result if type(result) is LineageProjectAdmission else None

    def handle_digest(self, handle: str) -> str:
        value = _safe_handle(handle)
        if self._handle_mac is not None:
            try:
                derived = self._handle_mac(value)
            except Exception as exc:
                raise _error(
                    PublicErrorCode.STORAGE_UNSAFE,
                    "The lineage capability is temporarily unavailable.",
                    reason="lineage_handle_key_unavailable",
                    retryable=True,
                ) from exc
            if type(derived) is not str or not derived.startswith("hmac-sha256:"):
                raise _error(
                    PublicErrorCode.STORAGE_CORRUPT,
                    "The lineage capability key is invalid.",
                    reason="lineage_handle_key_invalid",
                )
            return "sha256:" + hashlib.sha256(derived.encode("ascii")).hexdigest()
        key = self._handle_key
        return (
            "sha256:"
            + hmac.new(key, _HANDLE_DOMAIN + value.encode("ascii"), hashlib.sha256).hexdigest()
        )

    def _mint_handle(self, task_id: str, now: datetime) -> AttachHandle:
        # ``token_urlsafe`` may begin with ``_`` or ``-``.  The public opaque-handle
        # contract deliberately requires an alphanumeric first byte so the value remains
        # safe in every structured transport and CLI argument position.
        value = "h_" + secrets.token_urlsafe(48)
        digest = self.handle_digest(value)
        return AttachHandle(
            value=value,
            digest=digest,
            task_id=task_id,
            expires_at=now + timedelta(seconds=self._config.attach_handle_ttl_seconds),
        )

    async def register_root(
        self,
        *,
        task_id: str,
        session_id: str,
        repository_commitment: str | None = None,
    ) -> LineageSnapshot:
        """Register an existing root route without rewriting its lifecycle facts."""

        snapshot = LineageSnapshot(
            task_id=_id(IdKind.TASK, task_id),
            parent_task_id=None,
            depth=0,
            origin=None,
            acceptance=None,
            work_state=WorkState.OPEN,
            session_health=SessionHealth.ACTIVE,
            active_session_id=_id(IdKind.SESSION, session_id),
            repository_commitment=_commitment(repository_commitment),
        )
        async with self._lock:
            existing = await self._store.get_task(snapshot.task_id)
            if existing is not None:
                if existing != snapshot:
                    raise _error(
                        PublicErrorCode.SESSION_CONFLICT,
                        "The task is already bound to a different lineage.",
                        reason="lineage_root_conflict",
                    )
                return existing
            await self._store.save_task(snapshot)
            return snapshot

    async def bind_session(self, *, task_id: str, session_id: str) -> LineageSnapshot:
        """Rotate an existing task route to a new active session.

        Route rotation belongs to the start catalog; this helper mirrors the resulting session
        binding into the lineage projection.  Parentage, origin, acceptance, and repository facts
        remain immutable.
        """

        task = _id(IdKind.TASK, task_id)
        session = _id(IdKind.SESSION, session_id)
        async with self._lock:
            snapshot = await self._store.get_task(task)
            if snapshot is None:
                raise _error(
                    PublicErrorCode.SESSION_NOT_FOUND,
                    "The task was not found.",
                    reason="lineage_task_not_found",
                )
            if snapshot.work_state is not WorkState.OPEN:
                if snapshot.active_session_id == session:
                    # Replaying a start whose route already names this session has nothing to
                    # mirror.  Returning the recorded binding keeps that exact start replayable
                    # after its work became terminal without touching health or work state.
                    return snapshot
                raise _error(
                    PublicErrorCode.SESSION_CONFLICT,
                    "The task is no longer open.",
                    reason="lineage_work_terminal",
                )
            updated = replace(
                snapshot,
                active_session_id=session,
                session_health=SessionHealth.ACTIVE,
                contact_lost_at=None,
                abandonment_deadline=None,
                abandonment_reason=None,
                lineage_authority_revision=snapshot.lineage_authority_revision + 1,
            )
            await self._store.save_task(updated)
            return updated

    async def reserve_delegation(self, request: DelegationRequest) -> DelegationResult:
        """Reserve a child and opaque handle at ``lineage_reserved``.

        Replaying the same operation id with a different request digest is rejected before any
        lookup can select a different child.  Replaying the same digest returns the original child
        and handle, including after a process restarted with a persistent store.
        """

        if type(request) is not DelegationRequest:
            raise _error(PublicErrorCode.INVALID_REQUEST, "The delegation request is invalid.")
        now = self._now()
        async with self._lock:
            existing = await self._store.get_operation(request.operation_id)
            if existing is not None:
                if existing.state is DelegationOperationState.QUARANTINED:
                    raise _error(
                        PublicErrorCode.STORAGE_CORRUPT,
                        "The delegation operation is quarantined.",
                        reason="lineage_operation_quarantined",
                    )
                if not hmac.compare_digest(existing.request_digest, request.request_digest):
                    raise _error(
                        PublicErrorCode.REQUEST_IDENTITY_CONFLICT,
                        "The request identity conflicts with an earlier delegation.",
                        reason="lineage_request_identity_conflict",
                    )
                if existing.state is DelegationOperationState.PENDING and (
                    existing.owner_generation != self._owner_generation
                    or existing.lease_expires_at <= now
                ):
                    # A retry is the recovery trigger for a stranded operation.  Reclaim its
                    # existing lease before returning the same child; no new task or handle is
                    # minted and every following phase remains request-digest bound.
                    existing = replace(
                        existing,
                        owner_generation=self._owner_generation,
                        lease_expires_at=now + timedelta(seconds=self._config.start_lease_seconds),
                    )
                    await self._store.save_operation(existing)
                handle = await self._store.get_handle(existing.handle_digest)
                if handle is None:
                    raise _error(
                        PublicErrorCode.STORAGE_CORRUPT,
                        "The delegation state is inconsistent.",
                        reason="lineage_handle_missing",
                    )
                return DelegationResult(
                    existing,
                    existing.child_task_id,
                    handle,
                    existing.depth,
                    LineageOrigin.PARENT_MINTED,
                    LineageAcceptance.ACCEPTED,
                )

            parent = await self._store.get_task(request.parent_task_id)
            if parent is None:
                raise _error(
                    PublicErrorCode.SESSION_NOT_FOUND,
                    "The parent task was not found.",
                    reason="lineage_parent_not_found",
                )
            if parent.work_state is not WorkState.OPEN:
                # Terminal work is never reopened by later activity; the parent continues new
                # delegation from a successor task instead (#837).
                raise _error(
                    PublicErrorCode.SESSION_CONFLICT,
                    "The parent task's work is terminal and cannot start new child work.",
                    reason="lineage_parent_work_terminal",
                )
            if (
                parent.session_health is not SessionHealth.ACTIVE
                or parent.active_session_id != request.parent_session_id
            ):
                raise _error(
                    PublicErrorCode.SESSION_CONFLICT,
                    "The parent session is not active for new child work.",
                    reason="lineage_parent_session_invalid",
                )
            if (
                request.repository_commitment is None
                and parent.repository_commitment is not None
                or request.repository_commitment is not None
                and parent.repository_commitment is None
            ):
                raise _error(
                    PublicErrorCode.SESSION_CONFLICT,
                    "The parent repository binding conflicts.",
                    reason="lineage_repository_mismatch",
                )
            if (
                request.repository_commitment is not None
                and parent.repository_commitment is not None
                and parent.repository_commitment != request.repository_commitment
                and (request.workspace_commitment is None or request.external_commitment is None)
            ):
                raise _error(
                    PublicErrorCode.SESSION_CONFLICT,
                    "The child source identity is incomplete.",
                    reason="lineage_repository_mismatch",
                )
            project_admission: LineageProjectAdmission | None = None
            if (
                request.repository_commitment is not None
                and parent.repository_commitment is not None
                and parent.repository_commitment != request.repository_commitment
            ):
                project_admission = await self._cross_repository_admission(
                    parent_task_id=parent.task_id,
                    parent_repository_commitment=parent.repository_commitment,
                    child_repository_commitment=request.repository_commitment,
                )
            if (
                request.repository_commitment is not None
                and parent.repository_commitment is not None
                and parent.repository_commitment != request.repository_commitment
                and project_admission is None
            ):
                raise _error(
                    PublicErrorCode.SESSION_CONFLICT,
                    "Cross-repository parent links require a current project grant.",
                    reason="cross_repository_lineage_requires_grant",
                )
            children = await self._store.list_children(parent.task_id)
            if len(children) >= self._config.max_fanout:
                raise _error(
                    PublicErrorCode.LIMIT_EXCEEDED,
                    "The parent fan-out limit was reached.",
                    reason="lineage_fanout_limit",
                    count=len(children),
                )
            depth = parent.depth + 1
            if depth > self._config.max_depth:
                raise _error(
                    PublicErrorCode.LIMIT_EXCEEDED,
                    "The delegation depth limit was reached.",
                    reason="lineage_depth_limit",
                    count=depth,
                )

            child_task_id = self._new(IdKind.TASK)
            handle = self._mint_handle(child_task_id, now)
            child = LineageSnapshot(
                task_id=child_task_id,
                parent_task_id=parent.task_id,
                depth=depth,
                origin=LineageOrigin.PARENT_MINTED,
                acceptance=LineageAcceptance.ACCEPTED,
                work_state=WorkState.OPEN,
                session_health=SessionHealth.ENDED,
                active_session_id=None,
                # A cross-repository grant admits the child under its actual trusted source
                # repository.  Same-repository and unbound children retain the parent's value.
                repository_commitment=(
                    request.repository_commitment
                    if request.repository_commitment is not None
                    else parent.repository_commitment
                ),
                lineage_authority_revision=1,
            )
            operation = DelegationOperation(
                operation_id=request.operation_id,
                request_digest=request.request_digest,
                parent_task_id=parent.task_id,
                parent_session_id=request.parent_session_id,
                child_task_id=child_task_id,
                depth=depth,
                phase=DelegationPhase.LINEAGE_RESERVED,
                state=DelegationOperationState.PENDING,
                handle_digest=handle.digest,
                owner_generation=self._owner_generation,
                lease_expires_at=now + timedelta(seconds=self._config.start_lease_seconds),
                project_id=(None if project_admission is None else project_admission.project_id),
                membership_generation=(
                    None if project_admission is None else project_admission.membership_generation
                ),
            )
            # A catalog with a transaction-aware implementation installs all three rows in one
            # commit.  The fallback preserves compatibility with small test doubles; the
            # coordinator lock still makes that reference path single-writer.
            save_reservation = getattr(self._store, "save_reservation", None)
            if callable(save_reservation):
                await cast(
                    Callable[..., Awaitable[None]],
                    save_reservation,
                )(
                    operation,
                    child,
                    handle,
                    workspace_commitment=request.workspace_commitment,
                    external_commitment=request.external_commitment,
                )
            else:
                await self._store.save_operation(operation)
                await self._store.save_task(child)
                await self._store.save_handle(handle)
            return DelegationResult(
                operation,
                child_task_id,
                handle,
                depth,
                LineageOrigin.PARENT_MINTED,
                LineageAcceptance.ACCEPTED,
            )

    async def mark_child_bundle_ready(
        self, operation_id: str, request_digest: str
    ) -> DelegationOperation:
        return await self._advance_operation(
            operation_id, request_digest, DelegationPhase.CHILD_BUNDLE_READY
        )

    async def mark_parent_event_committed(
        self, operation_id: str, request_digest: str
    ) -> DelegationOperation:
        operation = await self._advance_operation(
            operation_id, request_digest, DelegationPhase.PARENT_EVENT_COMMITTED
        )
        if self._parent_event_committer is not None:
            await self._parent_event_committer(operation)
        return operation

    async def publish_attach_handle(
        self, operation_id: str, request_digest: str
    ) -> DelegationResult:
        operation = await self._advance_operation(
            operation_id, request_digest, DelegationPhase.HANDLE_PUBLISHED
        )
        handle = await self._store.get_handle(operation.handle_digest)
        if handle is None:
            raise _error(
                PublicErrorCode.STORAGE_CORRUPT,
                "The delegation handle is missing.",
                reason="lineage_handle_missing",
            )
        return DelegationResult(
            operation,
            operation.child_task_id,
            handle,
            operation.depth,
            LineageOrigin.PARENT_MINTED,
            LineageAcceptance.ACCEPTED,
        )

    async def complete_delegation(self, operation_id: str, request_digest: str) -> DelegationResult:
        if type(operation_id) is not str or type(request_digest) is not str:
            raise _error(PublicErrorCode.INVALID_REQUEST, "The delegation operation is invalid.")
        async with self._lock:
            operation = await self._require_operation(operation_id, request_digest)
            if operation.state is DelegationOperationState.COMPLETE:
                handle = await self._store.get_handle(operation.handle_digest)
                if handle is None:
                    raise _error(
                        PublicErrorCode.STORAGE_CORRUPT,
                        "The delegation handle is missing.",
                        reason="lineage_handle_missing",
                    )
                return DelegationResult(
                    operation,
                    operation.child_task_id,
                    handle,
                    operation.depth,
                    LineageOrigin.PARENT_MINTED,
                    LineageAcceptance.ACCEPTED,
                )
            if operation.state is DelegationOperationState.QUARANTINED:
                raise _error(
                    PublicErrorCode.STORAGE_CORRUPT,
                    "The delegation operation is quarantined.",
                    reason="lineage_operation_quarantined",
                )
            self._require_owned_lease(operation)
            if operation.phase is not DelegationPhase.HANDLE_PUBLISHED:
                raise _error(
                    PublicErrorCode.OPERATION_PENDING,
                    "The delegation operation is not ready to complete.",
                    reason="lineage_operation_phase",
                )
            terminal = replace(
                operation,
                phase=DelegationPhase.TERMINAL,
                state=DelegationOperationState.COMPLETE,
                terminal_at=self._now(),
            )
            await self._store.save_operation(terminal)
            handle = await self._store.get_handle(operation.handle_digest)
            if handle is None:
                raise _error(
                    PublicErrorCode.STORAGE_CORRUPT,
                    "The delegation handle is missing.",
                    reason="lineage_handle_missing",
                )
            return DelegationResult(
                terminal,
                terminal.child_task_id,
                handle,
                terminal.depth,
                LineageOrigin.PARENT_MINTED,
                LineageAcceptance.ACCEPTED,
            )

    async def recover_delegations(self) -> tuple[DelegationOperation, ...]:
        """Reclaim expired operation leases without minting replacement children.

        Stores may implement a richer indexed operation scan; the reference store exposes its
        operation rows.  Recovery returns the rows that still need finishing so the service can run
        the missing external boundary and then call the phase transition again.
        """

        now = self._now()
        async with self._lock:
            list_operations = getattr(self._store, "list_operations", None)
            if callable(list_operations):
                rows_value = await cast(
                    Callable[[], Awaitable[tuple[DelegationOperation, ...]]], list_operations
                )()
                rows: Mapping[str, DelegationOperation] = {
                    operation.operation_id: operation for operation in rows_value
                }
            else:
                rows_value = getattr(self._store, "operations", None)
                if not isinstance(rows_value, Mapping):
                    return ()
                rows = cast(Mapping[str, DelegationOperation], rows_value)
            recovered: list[DelegationOperation] = []
            for operation in rows.values():
                if (
                    type(operation) is not DelegationOperation
                    or operation.state is not DelegationOperationState.PENDING
                ):
                    continue
                # A new READY generation supersedes the previous owner immediately.  Waiting for
                # the old wall-clock lease after a process crash would leave a stranded child and
                # its opaque handle unavailable for up to the full lease window.
                if (
                    operation.owner_generation == self._owner_generation
                    and operation.lease_expires_at > now
                ):
                    continue
                recovered.append(
                    replace(
                        operation,
                        owner_generation=self._owner_generation,
                        lease_expires_at=now + timedelta(seconds=self._config.start_lease_seconds),
                    )
                )
            for operation in recovered:
                await self._store.save_operation(operation)
            return tuple(recovered)

    async def attach(
        self,
        *,
        handle_value: str,
        session_id: str,
        repository_commitment: str | None = None,
        request_id: str | None = None,
        request_digest: str | None = None,
    ) -> LineageSnapshot:
        """Consume one handle and bind a child session.

        Consumption is a compare-and-set operation.  Replaying with the same session is
        idempotent; another session receives a typed reuse refusal.  Identity and repository checks
        happen before consumption, so an incompatible request cannot burn a valid handle.
        """

        value = _safe_handle(handle_value)
        session = _id(IdKind.SESSION, session_id)
        if request_id is not None:
            _id(IdKind.REQUEST, request_id)
        if request_digest is not None:
            _digest(request_digest)
        commitment = _commitment(repository_commitment)
        digest = self.handle_digest(value)
        async with self._lock:
            return await self._attach_locked(
                handle_value=value,
                session_id=session,
                repository_commitment=commitment,
                digest=digest,
            )

    async def attach_with_operation(
        self,
        *,
        handle_value: str,
        repository_commitment: str | None = None,
        request_id: str | None = None,
        request_digest: str | None = None,
        replay_check: Callable[[AttachHandle], Awaitable[bool]] | None = None,
        operation: Callable[[AttachHandle], Awaitable[_AttachOperationResult]],
    ) -> tuple[_AttachOperationResult, LineageSnapshot]:
        """Run a child start and consume its handle under one lineage lock.

        A public handle attach has two durable boundaries: the child start operation and the
        single-use capability.  Running them as separate calls lets two concurrent attachers each
        rotate the child route before either one consumes the handle.  This method keeps the
        service-side compare-and-set around the full callback.  The callback must use the supplied
        handle's route and a stable request id; if it has already committed and a process crashes
        before consumption, retrying the same request replays that start and then consumes the
        existing handle.

        The callback receives the current handle row and its result must expose the session that
        was actually reserved by the child start. No user content crosses this boundary; only the
        result's structural ``session_id`` and ``task_id`` are inspected.
        """

        value = _safe_handle(handle_value)
        if request_id is not None:
            _id(IdKind.REQUEST, request_id)
        if request_digest is not None:
            _digest(request_digest)
        commitment = _commitment(repository_commitment)
        digest = self.handle_digest(value)
        if not callable(operation):
            raise _error(PublicErrorCode.INVALID_REQUEST, "The attach operation is invalid.")
        if replay_check is not None and not callable(replay_check):
            raise _error(PublicErrorCode.INVALID_REQUEST, "The attach replay check is invalid.")
        async with self._lock:
            # Validate the capability before invoking the callback.  _attach_locked repeats the
            # checks after the callback because the callback may cross a process/restart boundary
            # and because the same-session replay path must remain idempotent.
            handle = await self._validate_attach_locked(
                digest, commitment, replay_check=replay_check
            )
            if handle.consumed_session_id is not None:
                # A used capability may replay only the exact child-start operation that consumed
                # it.  A fresh request id must fail before invoking the callback; otherwise the
                # callback could rotate the child route and only then discover that the handle was
                # already consumed, stranding the newly-created session.
                if replay_check is None or not await replay_check(handle):
                    raise _error(
                        PublicErrorCode.SESSION_CONFLICT,
                        "The attach handle was already used.",
                        reason="attach_handle_reused",
                    )
            result = await operation(handle)
            result_task_id = getattr(result, "task_id", None)
            result_session_id = getattr(result, "session_id", None)
            if type(result_task_id) is not str or type(result_session_id) is not str:
                raise _error(
                    PublicErrorCode.STORAGE_CORRUPT,
                    "The child attach result is inconsistent.",
                    reason="attach_result_invalid",
                )
            if result_task_id != handle.task_id:
                raise _error(
                    PublicErrorCode.STORAGE_CORRUPT,
                    "The child attach result is inconsistent.",
                    reason="attach_result_invalid",
                )
            try:
                session = _id(IdKind.SESSION, result_session_id)
            except ValueError as exc:
                raise _error(
                    PublicErrorCode.STORAGE_CORRUPT,
                    "The child attach result is inconsistent.",
                    reason="attach_result_invalid",
                ) from exc
            attached = await self._attach_locked(
                handle_value=value,
                session_id=session,
                repository_commitment=commitment,
                digest=digest,
                admitted_operation=True,
            )
            return result, attached

    async def _validate_attach_locked(
        self,
        digest: str,
        commitment: str | None,
        *,
        replay_check: Callable[[AttachHandle], Awaitable[bool]] | None = None,
        admitted_operation: bool = False,
    ) -> AttachHandle:
        """Validate a capability or recover an already committed exact start operation."""

        handle = await self._store.get_handle(digest)
        if handle is None:
            raise _error(
                PublicErrorCode.SESSION_NOT_FOUND,
                "The attach handle was not found.",
                reason="attach_handle_invalid",
            )
        if handle.revoked:
            raise _error(
                PublicErrorCode.SESSION_CONFLICT,
                "The attach handle has been revoked.",
                reason="attach_handle_revoked",
            )
        if (
            handle.consumed_session_id is None
            and self._now() >= handle.expires_at
            and not admitted_operation
            and (replay_check is None or not await replay_check(handle))
        ):
            raise _error(
                PublicErrorCode.SESSION_CONFLICT,
                "The attach handle has expired.",
                reason="attach_handle_expired",
            )
        snapshot = await self._store.get_task(handle.task_id)
        if snapshot is None:
            raise _error(
                PublicErrorCode.STORAGE_CORRUPT,
                "The child task is missing.",
                reason="lineage_child_missing",
            )
        if commitment is not None and snapshot.repository_commitment != commitment:
            raise _error(
                PublicErrorCode.SESSION_CONFLICT,
                "The attach identity conflicts.",
                reason="selector_conflict",
            )
        if snapshot.work_state is not WorkState.OPEN:
            raise _error(
                PublicErrorCode.SESSION_CONFLICT,
                "The child work is no longer attachable.",
                reason="lineage_work_terminal",
            )
        return handle

    async def _attach_locked(
        self,
        *,
        handle_value: str,
        session_id: str,
        repository_commitment: str | None,
        digest: str | None = None,
        admitted_operation: bool = False,
    ) -> LineageSnapshot:
        """Consume a validated handle while ``self._lock`` is held."""

        value = _safe_handle(handle_value)
        session = _id(IdKind.SESSION, session_id)
        commitment = _commitment(repository_commitment)
        handle_digest = self.handle_digest(value) if digest is None else _digest(digest)
        handle = await self._validate_attach_locked(
            handle_digest, commitment, admitted_operation=admitted_operation
        )
        snapshot = await self._store.get_task(handle.task_id)
        if snapshot is None:  # guarded by _validate_attach_locked; keep the invariant explicit
            raise _error(
                PublicErrorCode.STORAGE_CORRUPT,
                "The child task is missing.",
                reason="lineage_child_missing",
            )
        if handle.consumed_session_id is not None:
            if handle.consumed_session_id == session:
                if (
                    snapshot.active_session_id != session
                    or snapshot.session_health is not SessionHealth.ACTIVE
                ):
                    snapshot = replace(
                        snapshot,
                        active_session_id=session,
                        session_health=SessionHealth.ACTIVE,
                        contact_lost_at=None,
                        abandonment_deadline=None,
                        abandonment_reason=_pending_reason(snapshot),
                        lineage_authority_revision=snapshot.lineage_authority_revision + 1,
                    )
                    await self._store.save_task(snapshot)
                return snapshot
            raise _error(
                PublicErrorCode.SESSION_CONFLICT,
                "The attach handle was already used.",
                reason="attach_handle_reused",
            )
        consumed = replace(handle, consumed_session_id=session)
        attached = replace(
            snapshot,
            active_session_id=session,
            session_health=SessionHealth.ACTIVE,
            contact_lost_at=None,
            abandonment_deadline=None,
            abandonment_reason=_pending_reason(snapshot),
            lineage_authority_revision=snapshot.lineage_authority_revision + 1,
        )
        await self._store.save_handle(consumed)
        await self._store.save_task(attached)
        return attached

    async def validate_attach(
        self,
        *,
        handle_value: str,
        repository_commitment: str | None = None,
        replay_check: Callable[[AttachHandle], Awaitable[bool]] | None = None,
    ) -> AttachHandle:
        """Validate before route mutation, allowing exact committed-operation recovery.

        Expiry refuses new starts. An existing completed start may still finish interrupted
        capability consumption; its catalog replay must validate the full request digest.
        """

        value = _safe_handle(handle_value)
        commitment = _commitment(repository_commitment)
        digest = self.handle_digest(value)
        async with self._lock:
            return await self._validate_attach_locked(digest, commitment, replay_check=replay_check)

    async def self_register(
        self,
        *,
        operation_id: str,
        request_digest: str,
        parent_session_id: str,
        repository_commitment: str | None = None,
        workspace_commitment: str | None = None,
        external_commitment: str | None = None,
    ) -> LineageSnapshot:
        """Create a pending self-registered child from an active parent session."""

        _id(IdKind.REQUEST, operation_id)
        _digest(request_digest)
        parent_session = _id(IdKind.SESSION, parent_session_id)
        commitment = _commitment(repository_commitment)
        workspace = _commitment(workspace_commitment)
        external = _commitment(external_commitment)
        if (workspace is None) != (external is None):
            raise _error(PublicErrorCode.INVALID_REQUEST, "The child source identity is invalid.")
        now = self._now()
        async with self._lock:
            existing_operation = await self._store.get_operation(operation_id)
            if existing_operation is not None:
                if existing_operation.request_digest != request_digest:
                    raise _error(
                        PublicErrorCode.REQUEST_IDENTITY_CONFLICT,
                        "The request identity conflicts with an earlier registration.",
                        reason="lineage_request_identity_conflict",
                    )
                existing = await self._store.get_task(existing_operation.child_task_id)
                if existing is None:
                    raise _error(
                        PublicErrorCode.STORAGE_CORRUPT,
                        "The self-registration child is missing.",
                        reason="lineage_child_missing",
                    )
                return existing
            parent_task_id = await self._store.get_session_task(parent_session)
            if parent_task_id is None:
                raise _error(
                    PublicErrorCode.SESSION_NOT_FOUND,
                    "The parent session was not found.",
                    reason="lineage_parent_not_found",
                )
            parent = await self._store.get_task(parent_task_id)
            if parent is not None and parent.work_state is not WorkState.OPEN:
                raise _error(
                    PublicErrorCode.SESSION_CONFLICT,
                    "The parent task's work is terminal and cannot start new child work.",
                    reason="lineage_parent_work_terminal",
                )
            if (
                parent is None
                or parent.session_health is not SessionHealth.ACTIVE
                or parent.active_session_id != parent_session
            ):
                raise _error(
                    PublicErrorCode.SESSION_CONFLICT,
                    "The parent session is not active for new child work.",
                    reason="lineage_parent_session_invalid",
                )
            if (
                commitment is None
                and parent.repository_commitment is not None
                or commitment is not None
                and parent.repository_commitment is None
            ):
                raise _error(
                    PublicErrorCode.SESSION_CONFLICT,
                    "The parent repository binding conflicts.",
                    reason="lineage_repository_mismatch",
                )
            if (
                commitment is not None
                and parent.repository_commitment is not None
                and parent.repository_commitment != commitment
                and (workspace is None or external is None)
            ):
                raise _error(
                    PublicErrorCode.SESSION_CONFLICT,
                    "The child source identity is incomplete.",
                    reason="lineage_repository_mismatch",
                )
            project_admission: LineageProjectAdmission | None = None
            if (
                commitment is not None
                and parent.repository_commitment is not None
                and parent.repository_commitment != commitment
            ):
                project_admission = await self._cross_repository_admission(
                    parent_task_id=parent.task_id,
                    parent_repository_commitment=parent.repository_commitment,
                    child_repository_commitment=commitment,
                )
            if (
                commitment is not None
                and parent.repository_commitment is not None
                and parent.repository_commitment != commitment
                and project_admission is None
            ):
                raise _error(
                    PublicErrorCode.SESSION_CONFLICT,
                    "Cross-repository parent links require a current project grant.",
                    reason="cross_repository_lineage_requires_grant",
                )
            children = await self._store.list_children(parent.task_id)
            if len(children) >= self._config.max_fanout:
                raise _error(
                    PublicErrorCode.LIMIT_EXCEEDED,
                    "The parent fan-out limit was reached.",
                    reason="lineage_fanout_limit",
                    count=len(children),
                )
            depth = parent.depth + 1
            if depth > self._config.max_depth:
                raise _error(
                    PublicErrorCode.LIMIT_EXCEEDED,
                    "The delegation depth limit was reached.",
                    reason="lineage_depth_limit",
                    count=depth,
                )
            child_task_id = self._new(IdKind.TASK)
            child_session_id = self._new(IdKind.SESSION)
            child = LineageSnapshot(
                task_id=child_task_id,
                parent_task_id=parent.task_id,
                depth=depth,
                origin=LineageOrigin.SELF_REGISTERED,
                acceptance=LineageAcceptance.PENDING,
                work_state=WorkState.OPEN,
                session_health=SessionHealth.ACTIVE,
                active_session_id=child_session_id,
                repository_commitment=(
                    commitment if commitment is not None else parent.repository_commitment
                ),
            )
            operation = DelegationOperation(
                operation_id=operation_id,
                request_digest=request_digest,
                parent_task_id=parent.task_id,
                parent_session_id=parent_session,
                child_task_id=child_task_id,
                depth=depth,
                phase=DelegationPhase.TERMINAL,
                state=DelegationOperationState.COMPLETE,
                handle_digest=self.handle_digest(secrets.token_urlsafe(48)),
                owner_generation=self._owner_generation,
                lease_expires_at=now,
                terminal_at=now,
                project_id=(None if project_admission is None else project_admission.project_id),
                membership_generation=(
                    None if project_admission is None else project_admission.membership_generation
                ),
            )
            save_registration = getattr(self._store, "save_self_registration")
            await cast(Callable[..., Awaitable[None]], save_registration)(
                operation,
                child,
                workspace_commitment=workspace,
                external_commitment=external,
            )
            return child

    async def merge_host_annotation(
        self,
        *,
        parent_task_id: str,
        child_task_id: str,
        parent_session_id: str,
        host: str | None = None,
        subagent_id: str | None = None,
        parent_tool_call_id: str | None = None,
        correlation_id: str | None = None,
        phase: str = "start",
        validate_only: bool = False,
    ) -> None:
        """Forward a validated host correlation to the host-owned annotation registry.

        Host observations remain provisional ``host_observed``/``pending`` facts.  This seam is
        intentionally separate from task creation: a host can merge a late stop signal into the
        same annotation after a cooperative self-registration or handle attach without changing
        the immutable task origin.  A composition that has no host registry simply records no
        annotation; lineage correctness does not depend on a host-specific adapter being loaded.
        """

        parent = _id(IdKind.TASK, parent_task_id)
        child = _id(IdKind.TASK, child_task_id)
        session = _id(IdKind.SESSION, parent_session_id)
        if parent == child:
            raise _error(
                PublicErrorCode.SESSION_CONFLICT,
                "The host lineage relationship is invalid.",
                reason="lineage_cycle",
            )
        for value in (host, subagent_id, parent_tool_call_id, correlation_id):
            if value is not None and (
                type(value) is not str
                or not 1 <= len(value.encode("utf-8")) <= 256
                or any(char in value for char in "\x00\r\n")
            ):
                raise _error(
                    PublicErrorCode.INVALID_REQUEST,
                    "The host lineage annotation is invalid.",
                    reason="host_lineage_annotation_invalid",
                )
        if phase not in {"start", "stop"}:
            raise _error(
                PublicErrorCode.INVALID_REQUEST,
                "The host lineage annotation is invalid.",
                reason="host_lineage_annotation_invalid",
            )
        if subagent_id is None and parent_tool_call_id is None and correlation_id is None:
            return
        async with self._lock:
            parent_snapshot = await self._store.get_task(parent)
            child_snapshot = await self._store.get_task(child)
            bound_parent = await self._store.get_session_task(session)
            if (
                parent_snapshot is None
                or child_snapshot is None
                or child_snapshot.parent_task_id != parent
                or bound_parent != parent
            ):
                raise _error(
                    PublicErrorCode.SESSION_NOT_FOUND,
                    "The host lineage relationship was not found.",
                    reason="lineage_child_not_found",
                )
            merger = self._host_annotation_merger
            if merger is None:
                return
            values: dict[str, JsonValue] = {
                "acceptance": (
                    None if child_snapshot.acceptance is None else child_snapshot.acceptance.value
                ),
                "child_task_id": child,
                "correlation_id": correlation_id,
                "host": host,
                "origin": (None if child_snapshot.origin is None else child_snapshot.origin.value),
                "parent_task_id": parent,
                "parent_session_id": session,
                "parent_tool_call_id": parent_tool_call_id,
                "phase": phase,
                "subagent_id": subagent_id,
                "validate_only": validate_only,
            }
            await merger(MappingProxyType(values))

    async def accept_child(self, *, parent_session_id: str, child_task_id: str) -> LineageSnapshot:
        return await self._transition_acceptance(
            parent_session_id, child_task_id, LineageAcceptance.ACCEPTED
        )

    async def validate_acceptance_transition(
        self,
        *,
        parent_session_id: str,
        child_task_id: str,
        target: LineageAcceptance,
    ) -> None:
        """Check a parent acceptance transition without changing catalog state.

        ``publish_work`` uses this preflight before appending the public lifecycle event.  Keeping
        the check in the same coordinator as the mutating transition prevents an invalid
        accepted-to-rejected request from leaving a ledger event behind with no matching catalog
        state.  The expected-frontier check on the ledger still serializes concurrent writers.
        """

        parent_session = _id(IdKind.SESSION, parent_session_id)
        child_id = _id(IdKind.TASK, child_task_id)
        if type(target) is not LineageAcceptance:
            raise _error(
                PublicErrorCode.INVALID_REQUEST,
                "The child acceptance transition is invalid.",
                reason="lineage_acceptance_transition",
            )
        async with self._lock:
            parent_id = await self._store.get_session_task(parent_session)
            parent = None if parent_id is None else await self._store.get_task(parent_id)
            child = await self._store.get_task(child_id)
            if (
                parent is None
                or parent.session_health is not SessionHealth.ACTIVE
                or parent.active_session_id != parent_session
                or child is None
                or child.parent_task_id != parent_id
            ):
                raise _error(
                    PublicErrorCode.SESSION_NOT_FOUND,
                    "The child relationship was not found.",
                    reason="lineage_child_not_found",
                )
            if child.acceptance is target:
                return
            if child.acceptance is not LineageAcceptance.PENDING:
                raise _error(
                    PublicErrorCode.SESSION_CONFLICT,
                    "The child acceptance transition is invalid.",
                    reason="lineage_acceptance_transition",
                )

    async def validate_child_work_transition(
        self,
        *,
        parent_session_id: str,
        child_task_id: str,
        target: WorkState,
    ) -> None:
        """Check a parent-owned child work transition without mutating it."""

        parent_session = _id(IdKind.SESSION, parent_session_id)
        child_id = _id(IdKind.TASK, child_task_id)
        if target not in {WorkState.CANCELLED, WorkState.WRITTEN_OFF}:
            raise _error(
                PublicErrorCode.INVALID_REQUEST,
                "The child work transition is invalid.",
                reason="lineage_work_transition",
            )
        async with self._lock:
            parent_id = await self._store.get_session_task(parent_session)
            parent = None if parent_id is None else await self._store.get_task(parent_id)
            child = await self._store.get_task(child_id)
            if (
                parent is None
                or parent.session_health is not SessionHealth.ACTIVE
                or parent.active_session_id != parent_session
                or child is None
                or child.parent_task_id != parent_id
            ):
                raise _error(
                    PublicErrorCode.SESSION_NOT_FOUND,
                    "The child relationship was not found.",
                    reason="lineage_child_not_found",
                )
            if child.work_state is target:
                return
            if child.work_state is not WorkState.OPEN:
                raise _error(
                    PublicErrorCode.SESSION_CONFLICT,
                    "The work lifecycle transition is invalid.",
                    reason="lineage_work_transition",
                )

    async def validate_owned_work_transition(
        self,
        *,
        session_id: str,
        target: WorkState,
    ) -> None:
        """Check an agent-owned lifecycle transition before its ledger append."""

        session = _id(IdKind.SESSION, session_id)
        if target not in {
            WorkState.CLOSED,
            WorkState.CANCELLED,
            WorkState.WRITTEN_OFF,
        }:
            raise _error(
                PublicErrorCode.INVALID_REQUEST,
                "The work lifecycle transition is invalid.",
                reason="lineage_work_transition",
            )
        async with self._lock:
            task_id = await self._store.get_session_task(session)
            snapshot = None if task_id is None else await self._store.get_task(task_id)
            if (
                snapshot is None
                or snapshot.session_health is not SessionHealth.ACTIVE
                or snapshot.active_session_id != session
            ):
                raise _error(
                    PublicErrorCode.SESSION_CONFLICT,
                    "The task session is not active.",
                    reason="lineage_session_not_active",
                )
            if snapshot.work_state is target:
                return
            if snapshot.work_state is not WorkState.OPEN and not _reversible(snapshot, target):
                raise _work_terminal_refusal(snapshot)

    async def reject_child(self, *, parent_session_id: str, child_task_id: str) -> LineageSnapshot:
        return await self._transition_acceptance(
            parent_session_id, child_task_id, LineageAcceptance.REJECTED
        )

    async def _transition_acceptance(
        self, parent_session_id: str, child_task_id: str, target: LineageAcceptance
    ) -> LineageSnapshot:
        parent_session = _id(IdKind.SESSION, parent_session_id)
        child_id = _id(IdKind.TASK, child_task_id)
        async with self._lock:
            parent_id = await self._store.get_session_task(parent_session)
            parent = None if parent_id is None else await self._store.get_task(parent_id)
            child = await self._store.get_task(child_id)
            if (
                parent is None
                or parent.session_health is not SessionHealth.ACTIVE
                or parent.active_session_id != parent_session
                or child is None
                or child.parent_task_id != parent_id
            ):
                raise _error(
                    PublicErrorCode.SESSION_NOT_FOUND,
                    "The child relationship was not found.",
                    reason="lineage_child_not_found",
                )
            if child.acceptance is not LineageAcceptance.PENDING:
                if child.acceptance is target:
                    return child
                raise _error(
                    PublicErrorCode.SESSION_CONFLICT,
                    "The child acceptance transition is invalid.",
                    reason="lineage_acceptance_transition",
                )
            updated = replace(
                child,
                acceptance=target,
                lineage_authority_revision=child.lineage_authority_revision + 1,
            )
            await self._store.save_task(updated)
            return updated

    async def cancel_child(self, *, parent_session_id: str, child_task_id: str) -> LineageSnapshot:
        return await self._transition_work(
            parent_session_id, child_task_id, WorkState.CANCELLED, parent_required=True
        )

    async def write_off_child(
        self, *, parent_session_id: str, child_task_id: str
    ) -> LineageSnapshot:
        return await self._transition_work(
            parent_session_id, child_task_id, WorkState.WRITTEN_OFF, parent_required=True
        )

    async def cancel_work(self, *, session_id: str, task_id: str | None = None) -> LineageSnapshot:
        """Cancel the task owned by an active session, preserving its lineage relationship."""

        return await self._transition_owned_work(session_id, task_id, WorkState.CANCELLED)

    async def write_off_work(
        self, *, session_id: str, task_id: str | None = None
    ) -> LineageSnapshot:
        """Write off the task owned by an active session, preserving dependency history."""

        return await self._transition_owned_work(session_id, task_id, WorkState.WRITTEN_OFF)

    async def close_work(self, *, session_id: str, task_id: str | None = None) -> LineageSnapshot:
        return await self._transition_owned_work(session_id, task_id, WorkState.CLOSED)

    async def reconcile_child_acceptance(
        self,
        *,
        parent_task_id: str,
        child_task_id: str,
        target: LineageAcceptance,
    ) -> LineageSnapshot:
        """Reconcile a durable parent lifecycle event after a process crash.

        The ordinary public transition is session-authorized and therefore intentionally requires
        a live parent session.  A restart may discover the ledger event after that session's lease
        has expired, though.  Recovery already authenticated the event through the task ledger, so
        this idempotent repair applies the same immutable parent/child check without pretending
        that the old session is live again.
        """

        parent = _id(IdKind.TASK, parent_task_id)
        child_id = _id(IdKind.TASK, child_task_id)
        if type(target) is not LineageAcceptance:
            raise _error(
                PublicErrorCode.INVALID_REQUEST,
                "The child acceptance transition is invalid.",
                reason="lineage_acceptance_transition",
            )
        async with self._lock:
            parent_snapshot = await self._store.get_task(parent)
            child = await self._store.get_task(child_id)
            if parent_snapshot is None or child is None or child.parent_task_id != parent:
                raise _error(
                    PublicErrorCode.STORAGE_CORRUPT,
                    "The child relationship is inconsistent.",
                    reason="lineage_child_not_found",
                )
            if child.acceptance is target:
                return child
            if child.acceptance is not LineageAcceptance.PENDING:
                raise _error(
                    PublicErrorCode.STORAGE_CORRUPT,
                    "The child acceptance transition conflicts with the ledger.",
                    reason="lineage_acceptance_transition",
                )
            updated = replace(
                child,
                acceptance=target,
                lineage_authority_revision=child.lineage_authority_revision + 1,
            )
            await self._store.save_task(updated)
            return updated

    async def reconcile_child_work(
        self,
        *,
        parent_task_id: str,
        child_task_id: str,
        target: WorkState,
    ) -> LineageSnapshot:
        """Reconcile a parent-owned child work event without reviving its actor session."""

        parent = _id(IdKind.TASK, parent_task_id)
        child_id = _id(IdKind.TASK, child_task_id)
        if target not in {WorkState.CANCELLED, WorkState.WRITTEN_OFF}:
            raise _error(
                PublicErrorCode.INVALID_REQUEST,
                "The child work transition is invalid.",
                reason="lineage_work_transition",
            )
        async with self._lock:
            parent_snapshot = await self._store.get_task(parent)
            child = await self._store.get_task(child_id)
            if parent_snapshot is None or child is None or child.parent_task_id != parent:
                raise _error(
                    PublicErrorCode.STORAGE_CORRUPT,
                    "The child relationship is inconsistent.",
                    reason="lineage_child_not_found",
                )
            return await self._reconcile_work_locked(child, target)

    async def reconcile_owned_work(
        self, *, task_id: str, target: WorkState, reason: str | None = None
    ) -> LineageSnapshot:
        """Reconcile an agent-owned lifecycle event after append-before-catalog interruption.

        ``reason`` is a replayed ``work_abandoned`` event's ``reason_code``.
        """

        task = _id(IdKind.TASK, task_id)
        if target not in {
            WorkState.CLOSED,
            WorkState.CANCELLED,
            WorkState.WRITTEN_OFF,
            WorkState.ABANDONED,
        }:
            raise _error(
                PublicErrorCode.INVALID_REQUEST,
                "The work lifecycle transition is invalid.",
                reason="lineage_work_transition",
            )
        async with self._lock:
            snapshot = await self._store.get_task(task)
            if snapshot is None:
                raise _error(
                    PublicErrorCode.STORAGE_CORRUPT,
                    "The task lineage is inconsistent.",
                    reason="lineage_task_not_found",
                )
            return await self._reconcile_work_locked(snapshot, target, reason=reason)

    async def _reconcile_work_locked(
        self, snapshot: LineageSnapshot, target: WorkState, *, reason: str | None = None
    ) -> LineageSnapshot:
        """Apply one already-authenticated work event while the coordinator lock is held.

        ``reason`` is an abandonment's recorded reason; ``[work_abandoned(contact_lost),
        work_closed]`` replays to ``closed`` (D6, #1239).
        """

        if snapshot.work_state is target:
            if (
                target is WorkState.ABANDONED
                and snapshot.abandonment_reason is None
                and reason in ABANDONMENT_REASONS
            ):
                # A row abandoned before catalog migration 6 recorded no reason. Its ledger event
                # names it, so a contact_lost abandonment from before the upgrade is reversible
                # by its own session's close like any later one (#1239).
                named = replace(
                    snapshot,
                    abandonment_reason=reason,
                    lineage_authority_revision=snapshot.lineage_authority_revision + 1,
                )
                await self._store.save_task(named)
                return named
            return snapshot
        if (
            snapshot.work_state is WorkState.CLOSED
            and target is WorkState.ABANDONED
            and reason == REVERSIBLE_ABANDONMENT_REASON
        ):
            # The close already superseded this abandonment: it was accepted while only the
            # ledger held the service event (append before catalog sync). Keep it as history.
            if snapshot.abandonment_reason == reason:
                return snapshot
            history = replace(
                snapshot,
                abandonment_reason=reason,
                lineage_authority_revision=snapshot.lineage_authority_revision + 1,
            )
            await self._store.save_task(history)
            return history
        if snapshot.work_state is not WorkState.OPEN and not _reversible(snapshot, target):
            raise _error(
                PublicErrorCode.STORAGE_CORRUPT,
                "The work lifecycle transition conflicts with the ledger.",
                reason="lineage_work_transition",
            )
        updated = replace(
            snapshot,
            work_state=target,
            abandonment_reason=(
                (reason if reason in ABANDONMENT_REASONS else None)
                if target is WorkState.ABANDONED
                else snapshot.abandonment_reason
            ),
            lineage_authority_revision=snapshot.lineage_authority_revision + 1,
        )
        await self._store.save_task(updated)
        if target in {WorkState.CANCELLED, WorkState.WRITTEN_OFF, WorkState.ABANDONED}:
            await self._store.revoke_handles(snapshot.task_id)
        return updated

    async def _transition_work(
        self, actor_session_id: str, child_task_id: str, target: WorkState, *, parent_required: bool
    ) -> LineageSnapshot:
        session = _id(IdKind.SESSION, actor_session_id)
        child_id = _id(IdKind.TASK, child_task_id)
        async with self._lock:
            actor_task = await self._store.get_session_task(session)
            actor = None if actor_task is None else await self._store.get_task(actor_task)
            child = await self._store.get_task(child_id)
            if (
                actor is None
                or actor.session_health is not SessionHealth.ACTIVE
                or actor.active_session_id != session
                or child is None
                or (parent_required and child.parent_task_id != actor_task)
            ):
                raise _error(
                    PublicErrorCode.SESSION_NOT_FOUND,
                    "The child relationship was not found.",
                    reason="lineage_child_not_found",
                )
            return await self._transition_work_locked(
                child_id, target, session, parent_required=parent_required
            )

    async def _transition_owned_work(
        self,
        session_id: str,
        task_id: str | None,
        target: WorkState,
    ) -> LineageSnapshot:
        session = _id(IdKind.SESSION, session_id)
        requested_task = None if task_id is None else _id(IdKind.TASK, task_id)
        async with self._lock:
            owned_task = await self._store.get_session_task(session)
            snapshot = None if owned_task is None else await self._store.get_task(owned_task)
            if (
                snapshot is None
                or snapshot.session_health is not SessionHealth.ACTIVE
                or snapshot.active_session_id != session
                or (requested_task is not None and requested_task != owned_task)
            ):
                raise _error(
                    PublicErrorCode.SESSION_CONFLICT,
                    "The task session is not active.",
                    reason="lineage_session_not_active",
                )
            return await self._transition_work_locked(
                cast(str, owned_task), target, session, parent_required=False
            )

    async def _transition_work_locked(
        self, task_id: str, target: WorkState, actor_session_id: str, *, parent_required: bool
    ) -> LineageSnapshot:
        snapshot = await self._store.get_task(task_id)
        if snapshot is None:
            raise _error(
                PublicErrorCode.SESSION_NOT_FOUND,
                "The task was not found.",
                reason="lineage_task_not_found",
            )
        if target is WorkState.CLOSED and snapshot.active_session_id != actor_session_id:
            raise _error(
                PublicErrorCode.SESSION_CONFLICT,
                "Only the active task session may close work.",
                reason="lineage_close_authority",
            )
        if snapshot.work_state is target:
            return snapshot
        if snapshot.work_state is not WorkState.OPEN and not _reversible(snapshot, target):
            raise _work_terminal_refusal(snapshot)
        updated = replace(
            snapshot,
            work_state=target,
            lineage_authority_revision=snapshot.lineage_authority_revision + 1,
        )
        await self._store.save_task(updated)
        if target in {WorkState.CANCELLED, WorkState.WRITTEN_OFF, WorkState.ABANDONED}:
            await self._store.revoke_handles(task_id)
        return updated

    async def renew_observed_activity(
        self,
        *,
        task_id: str,
        session_id: str,
        renew_lease: Callable[[datetime], Awaitable[bool | None]],
        observed_at: datetime | None = None,
    ) -> bool:
        """Apply one piece of authenticated host contact at its own time.

        ``observed_at`` is when the admitted host event was received; the adapter may deliver it
        much later (a queued or retried row).  That evidence holds contact until ``observed_at``
        plus the session lease, never from its delivery time:

        * while that lease end is still ahead, the session is active until then and any earlier
          contact-loss deadline is cleared (``renew_lease`` receives the lease end);
        * once it has passed, the evidence cannot make the session active after the fact.  It
          can only move a recorded contact loss that began before the evidence ran out to the
          point where it did, and the abandonment deadline with it.

        Renewal is monotonic and idempotent, so a duplicate delivery or evidence older than the
        recorded contact changes nothing.  Explicitly ended sessions remain ended and terminal
        work is never reopened.  Returns whether the evidence applied to the current session.
        """

        task = _id(IdKind.TASK, task_id)
        session = _id(IdKind.SESSION, session_id)
        now = self._now()
        observed = now if observed_at is None else _timestamp(observed_at)
        if observed > now:
            return False
        evidence_until = observed + timedelta(seconds=SESSION_LEASE_SECONDS)
        async with self._lock:
            # The lineage lock may be queued behind a slow recovery or publication.  The
            # evidence decision is made at the commit boundary, not at call entry: a lease can
            # expire while this coroutine waits for the lock.
            now = self._now()
            if observed > now:
                return False
            snapshot = await self._store.get_task(task)
            # The store read is awaited too.  A queued read must not let evidence cross its
            # lease boundary and then take the active-state branch using the earlier clock.
            now = self._now()
            if (
                snapshot is None
                or snapshot.active_session_id != session
                or snapshot.session_health is SessionHealth.ENDED
            ):
                return False
            if evidence_until > now:
                lease_offered = await renew_lease(evidence_until)
                if lease_offered is False:
                    return False
                now = self._now()
                if evidence_until <= now:
                    # The catalog offer may have waited long enough for this evidence to run out.
                    # Fall through to the delayed-evidence rule rather than reviving contact.
                    pass
                elif (
                    snapshot.session_health is SessionHealth.ACTIVE
                    and snapshot.contact_lost_at is None
                    and (
                        snapshot.abandonment_deadline is None
                        or snapshot.work_state is not WorkState.OPEN
                    )
                ):
                    return True
                else:
                    await self._store.save_task(
                        replace(
                            snapshot,
                            session_health=SessionHealth.ACTIVE,
                            contact_lost_at=None,
                            # Terminal work keeps when and why it was abandoned (#1239).
                            abandonment_deadline=(
                                None
                                if snapshot.work_state is WorkState.OPEN
                                else snapshot.abandonment_deadline
                            ),
                            abandonment_reason=_pending_reason(snapshot),
                            lineage_authority_revision=snapshot.lineage_authority_revision + 1,
                        )
                    )
                    return True
            lost_at = snapshot.contact_lost_at
            if (
                snapshot.session_health is not SessionHealth.CONTACT_LOST
                or lost_at is None
                or lost_at >= evidence_until
            ):
                return False
            deadline = _quiet_deadline(
                snapshot,
                evidence_until,
                timedelta(seconds=await self._contact_window_seconds(snapshot)),
            )
            if snapshot.abandonment_deadline is not None:
                deadline = max(deadline, snapshot.abandonment_deadline)
            if snapshot.work_state is not WorkState.OPEN:
                deadline = snapshot.abandonment_deadline
            await self._store.save_task(
                replace(
                    snapshot,
                    contact_lost_at=evidence_until,
                    abandonment_deadline=deadline,
                    abandonment_reason=(
                        REVERSIBLE_ABANDONMENT_REASON
                        if snapshot.work_state is WorkState.OPEN
                        else snapshot.abandonment_reason
                    ),
                    lineage_authority_revision=snapshot.lineage_authority_revision + 1,
                )
            )
            return True

    async def bind_host_session_commitment(
        self, *, task_id: str, session_id: str, session_commitment: str
    ) -> None:
        """Record the exact host session currently bound to a live FinishUP route.

        Host observations are admitted only after the routing layer has checked the active route.
        Recovery uses this process-local binding as a second fence, so an open annotation from a
        predecessor host session cannot renew a reattached task.  Missing binding deliberately
        fails closed; a later admitted event re-establishes it.
        """

        task = _id(IdKind.TASK, task_id)
        session = _id(IdKind.SESSION, session_id)
        commitment = _commitment(session_commitment, optional=False)
        assert commitment is not None
        async with self._lock:
            self._host_session_commitments[(task, session)] = commitment

    async def hold_in_flight_contact(
        self,
        renew_lease: Callable[[str, str, datetime], Awaitable[bool | None]],
    ) -> tuple[str, ...]:
        """Keep contact for open work whose host declared an operation that has not ended.

        A native subagent observed starting (and not yet stopping) under a parent session is
        authenticated host evidence that the parent is waiting on it: hosts emit no event from
        the parent for the whole run.  The recovery sweep therefore renews one ordinary lease for
        such a session instead of expiring it, until the host reports the stop or the start is
        older than ``native_operation_hold_seconds``.  No event is published, terminal or ended
        work is untouched, and a session whose host never reports the stop is released by the
        bound.  Returns the held task ids.
        """

        registry = self._host_lineage_registry
        latest_open = getattr(registry, "latest_open_host_operation", None)
        if registry is None or not callable(latest_open):
            return ()
        lookup = cast(Callable[..., Awaitable[Timestamp | None]], latest_open)
        held: list[str] = []
        async with self._lock:
            for snapshot in await self._store.list_tasks():
                session = snapshot.active_session_id
                if (
                    snapshot.work_state is not WorkState.OPEN
                    or session is None
                    or snapshot.session_health is not SessionHealth.CONTACT_LOST
                ):
                    continue
                session_commitment = self._host_session_commitments.get((snapshot.task_id, session))
                if self._host_session_commitment_lookup is not None:
                    try:
                        persisted_commitment = await self._host_session_commitment_lookup(
                            snapshot.task_id, session
                        )
                        persisted_commitment = _commitment(persisted_commitment, optional=True)
                    except Exception:
                        # Durable bootstrap is advisory evidence.  An unavailable route cannot
                        # replace a binding already established by admitted ingress; without a
                        # cached binding, the hold still fails closed below.
                        persisted_commitment = None
                    if persisted_commitment is not None:
                        session_commitment = persisted_commitment
                        self._host_session_commitments[(snapshot.task_id, session)] = (
                            persisted_commitment
                        )
                if session_commitment is None:
                    continue
                now = self._now()
                current_not_before = timestamp_from_datetime(
                    now - timedelta(seconds=self._config.native_operation_hold_seconds)
                )
                started = await lookup(
                    snapshot.task_id,
                    not_before=current_not_before,
                    session_commitment=session_commitment,
                )
                now = self._now()
                if started is None or started.as_datetime() < now - timedelta(
                    seconds=self._config.native_operation_hold_seconds
                ):
                    continue
                lease_until = now + timedelta(seconds=SESSION_LEASE_SECONDS)
                lease_offered = await renew_lease(snapshot.task_id, session, lease_until)
                if lease_offered is False:
                    continue
                if lease_until <= self._now():
                    continue
                await self._store.save_task(
                    replace(
                        snapshot,
                        session_health=SessionHealth.ACTIVE,
                        contact_lost_at=None,
                        abandonment_deadline=None,
                        abandonment_reason=None,
                        lineage_authority_revision=snapshot.lineage_authority_revision + 1,
                    )
                )
                held.append(snapshot.task_id)
        return tuple(held)

    async def _contact_window_seconds(
        self,
        snapshot: LineageSnapshot,
        tasks: Mapping[str, LineageSnapshot] | None = None,
    ) -> int:
        """How long ``snapshot`` may stay out of contact before its open work is abandoned.

        D7 (#1239): a child whose parent is waiting on it (the parent's work is open, its session
        has not ended, and it has not rejected the child) keeps the short window, so a parent never
        waits long on a dead child. D6: every other task, top-level or orphaned, gets the long
        horizon and shows ``contact_lost`` meanwhile. ``tasks`` is a sweep's snapshot of the store.
        """

        parent_id = snapshot.parent_task_id
        if parent_id is not None:
            parent = (
                tasks.get(parent_id) if tasks is not None else await self._store.get_task(parent_id)
            )
            if (
                parent is not None
                and parent.work_state is WorkState.OPEN
                and parent.session_health is not SessionHealth.ENDED
                and snapshot.acceptance is not LineageAcceptance.REJECTED
            ):
                return self._config.contact_lost_recovery_seconds
        return self._config.top_level_contact_lost_horizon_seconds

    async def mark_contact_lost(self, *, session_id: str) -> LineageSnapshot:
        session = _id(IdKind.SESSION, session_id)
        now = self._now()
        async with self._lock:
            task_id = await self._store.get_session_task(session)
            if task_id is None:
                raise _error(
                    PublicErrorCode.SESSION_NOT_FOUND,
                    "The task session was not found.",
                    reason="lineage_session_not_found",
                )
            snapshot = await self._store.get_task(task_id)
            if snapshot is None:
                raise _error(
                    PublicErrorCode.STORAGE_CORRUPT,
                    "The task lineage is inconsistent.",
                    reason="lineage_task_missing",
                )
            # D6/D7 (#1239): the window follows whether a parent is waiting on this task.
            window = timedelta(seconds=await self._contact_window_seconds(snapshot))
            if snapshot.session_health is SessionHealth.CONTACT_LOST:
                # A durable session sweep may have moved the per-session row before the lineage
                # metadata row was updated (with the short default window).  Complete that
                # metadata transition here so recovery has one stable deadline across restarts;
                # the deadline is a function of the loss time, so repeated calls are idempotent.
                lost_at = snapshot.contact_lost_at or now
                # Terminal work keeps when it was abandoned; only open work has a deadline ahead.
                deadline = (
                    _quiet_deadline(snapshot, lost_at, window)
                    if snapshot.work_state is WorkState.OPEN
                    else snapshot.abandonment_deadline
                )
                reason = (
                    REVERSIBLE_ABANDONMENT_REASON
                    if snapshot.work_state is WorkState.OPEN
                    else snapshot.abandonment_reason
                )
                if (
                    snapshot.contact_lost_at == lost_at
                    and snapshot.abandonment_deadline == deadline
                    and snapshot.abandonment_reason == reason
                ):
                    return snapshot
                updated = replace(
                    snapshot,
                    contact_lost_at=lost_at,
                    abandonment_deadline=deadline,
                    abandonment_reason=reason,
                    lineage_authority_revision=snapshot.lineage_authority_revision + 1,
                )
                await self._store.save_task(updated)
                return updated
            if (
                snapshot.active_session_id != session
                or snapshot.session_health is not SessionHealth.ACTIVE
            ):
                raise _error(
                    PublicErrorCode.SESSION_CONFLICT,
                    "The task session is not active.",
                    reason="lineage_session_not_active",
                )
            updated = replace(
                snapshot,
                session_health=SessionHealth.CONTACT_LOST,
                contact_lost_at=now,
                abandonment_deadline=(
                    _quiet_deadline(snapshot, now, window)
                    if snapshot.work_state is WorkState.OPEN
                    else snapshot.abandonment_deadline
                ),
                abandonment_reason=(
                    REVERSIBLE_ABANDONMENT_REASON
                    if snapshot.work_state is WorkState.OPEN
                    else snapshot.abandonment_reason
                ),
                lineage_authority_revision=snapshot.lineage_authority_revision + 1,
            )
            await self._store.save_task(updated)
            return updated

    async def end_session(self, *, session_id: str) -> LineageSnapshot:
        session = _id(IdKind.SESSION, session_id)
        async with self._lock:
            task_id = await self._store.get_session_task(session)
            if task_id is None:
                raise _error(
                    PublicErrorCode.SESSION_NOT_FOUND,
                    "The task session was not found.",
                    reason="lineage_session_not_found",
                )
            snapshot = await self._store.get_task(task_id)
            if snapshot is None:
                raise _error(
                    PublicErrorCode.STORAGE_CORRUPT,
                    "The task lineage is inconsistent.",
                    reason="lineage_task_missing",
                )
            if snapshot.session_health is SessionHealth.ENDED:
                return snapshot
            if snapshot.active_session_id not in {None, session}:
                # Re-checked under the lock: a route rotated to a successor after the caller
                # looked, so a predecessor's late end must not end the successor (#1239).
                return snapshot
            # D6 (#1239): a delivered ``SessionEnd`` ends the session, and its open work is
            # abandoned (``session_ended``) after the short grace, so a host that clears and
            # resumes the same task reattaches instead of losing it.
            pending = snapshot.work_state is WorkState.OPEN
            updated = replace(
                snapshot,
                session_health=SessionHealth.ENDED,
                active_session_id=None,
                contact_lost_at=None,
                abandonment_deadline=(
                    self._now() + timedelta(seconds=self._config.contact_lost_recovery_seconds)
                    if pending
                    else snapshot.abandonment_deadline
                ),
                abandonment_reason="session_ended" if pending else snapshot.abandonment_reason,
                lineage_authority_revision=snapshot.lineage_authority_revision + 1,
            )
            await self._store.save_task(updated)
            return updated

    async def recover_abandoned(
        self,
        record_abandonment: Callable[[LineageSnapshot, str, datetime], Awaitable[None]],
    ) -> tuple[LineageSnapshot, ...]:
        """Commit service evidence before projecting a terminal recovery outcome.

        An unused expired capability abandons its reservation without inventing a lost session.
        Attached work instead receives the full contact-loss recovery window. The callback must
        durably and idempotently append the service event; failure leaves work recoverable.
        """

        now = self._now()
        async with self._lock:
            list_operations = getattr(self._store, "list_operations", None)
            if callable(list_operations):
                operations = await cast(
                    Callable[[], Awaitable[tuple[DelegationOperation, ...]]], list_operations
                )()
            else:
                rows = cast(
                    Mapping[str, DelegationOperation], getattr(self._store, "operations", {})
                )
                operations = tuple(rows.values())
            unclaimed: dict[str, datetime] = {}
            for operation in operations:
                if operation.phase is not DelegationPhase.TERMINAL:
                    continue
                handle = await self._store.get_handle(operation.handle_digest)
                if handle is not None and handle.consumed_session_id is None and not handle.revoked:
                    unclaimed[operation.child_task_id] = handle.expires_at
            values = await self._store.list_tasks()
            by_id = {item.task_id: item for item in values}
            recovered: list[LineageSnapshot] = []
            retryable_failure: Exception | None = None
            for snapshot in values:
                if snapshot.work_state is not WorkState.OPEN:
                    continue
                deadline = snapshot.abandonment_deadline
                reason = REVERSIBLE_ABANDONMENT_REASON
                if snapshot.active_session_id is None and snapshot.task_id in unclaimed:
                    deadline = unclaimed[snapshot.task_id]
                    reason = "attach_handle_expired"
                elif (
                    snapshot.session_health is SessionHealth.ENDED
                    and snapshot.abandonment_reason == "session_ended"
                ):
                    reason = "session_ended"
                elif snapshot.session_health is not SessionHealth.CONTACT_LOST:
                    continue
                elif snapshot.contact_lost_at is not None:
                    # D6/D7 (#1239): judged at sweep time, so a child whose parent stopped waiting
                    # moves to the long horizon. Delayed evidence already moved the loss time.
                    window = await self._contact_window_seconds(snapshot, by_id)
                    deadline = _quiet_deadline(
                        snapshot, snapshot.contact_lost_at, timedelta(seconds=window)
                    )
                if deadline is None or deadline > now:
                    continue
                try:
                    await record_abandonment(snapshot, reason, deadline)
                except PublicOperationError as exc:
                    if not exc.retryable:
                        raise
                    retryable_failure = retryable_failure or exc
                    continue
                except (OSError, TimeoutError) as exc:
                    retryable_failure = retryable_failure or exc
                    continue
                recovered.append(
                    await self._reconcile_work_locked(
                        replace(snapshot, abandonment_deadline=deadline),
                        WorkState.ABANDONED,
                        reason=reason,
                    )
                )
            if retryable_failure is not None:
                # Complete independent tasks but retain the daemon's failure diagnostic. The
                # failed task remains open and its next sweep retries the same event identity.
                raise retryable_failure
            return tuple(recovered)

    async def record_child_dependencies(
        self,
        *,
        parent_task_id: str,
        child_task_id: str,
        child_frontier: Frontier,
        child_check_id: str | None,
        child_receipt_id: str | None,
        coverage: Mapping[str, JsonValue],
        findings_state: Mapping[str, JsonValue],
        membership_generation: int | None = None,
    ) -> DependencyManifest:
        """Build and durably store a frozen manifest for a direct child."""

        parent = _id(IdKind.TASK, parent_task_id)
        child_id = _id(IdKind.TASK, child_task_id)
        async with self._lock:
            parent_snapshot = await self._store.get_task(parent)
            child_snapshot = await self._store.get_task(child_id)
            if (
                parent_snapshot is None
                or child_snapshot is None
                or child_snapshot.parent_task_id != parent
            ):
                raise _error(
                    PublicErrorCode.SESSION_NOT_FOUND,
                    "The child relationship was not found.",
                    reason="lineage_child_not_found",
                )
            if child_snapshot.origin is None or child_snapshot.acceptance is None:
                raise _error(
                    PublicErrorCode.SESSION_CONFLICT,
                    "A root task cannot be a child dependency.",
                    reason="lineage_root_dependency",
                )
            manifest = DependencyManifest(
                parent_task_id=parent,
                child_task_id=child_id,
                origin=child_snapshot.origin,
                acceptance=child_snapshot.acceptance,
                child_frontier=child_frontier,
                child_check_id=child_check_id,
                child_receipt_id=child_receipt_id,
                coverage=coverage,
                findings_state=findings_state,
                lineage_authority_revision=child_snapshot.lineage_authority_revision,
                membership_generation=membership_generation,
            )
            await self._store.save_manifest(manifest)
            return manifest

    def _quiet_until(self, declared_at: datetime, expected_quiet_seconds: int) -> datetime | None:
        """The clamped end of a declared or implied quiet period, or ``None`` when the cap is 0."""

        seconds = _bounded_int(
            expected_quiet_seconds, minimum=1, maximum=MAX_DECLARED_QUIET_SECONDS
        )
        effective = min(seconds, self._config.max_declared_quiet_seconds)
        return None if effective == 0 else declared_at + timedelta(seconds=effective)

    async def _apply_quiet_locked(
        self, snapshot: LineageSnapshot, updated: LineageSnapshot
    ) -> LineageSnapshot:
        """Store ``updated``'s quiet periods and re-judge open work's pending deadline.

        ``updated`` is ``snapshot`` with ``quiet_until`` or ``implied_quiet_until`` replaced.
        """

        if (
            updated.work_state is WorkState.OPEN
            and updated.session_health is SessionHealth.CONTACT_LOST
            and updated.contact_lost_at is not None
        ):
            window = timedelta(seconds=await self._contact_window_seconds(updated))
            updated = replace(
                updated,
                abandonment_deadline=_quiet_deadline(updated, updated.contact_lost_at, window),
            )
        if updated == snapshot:
            return snapshot
        updated = replace(
            updated, lineage_authority_revision=snapshot.lineage_authority_revision + 1
        )
        await self._store.save_task(updated)
        return updated

    async def declare_quiet_period(
        self,
        *,
        session_id: str,
        expected_quiet_seconds: int,
        declared_at: datetime | None = None,
    ) -> LineageSnapshot:
        """Record the task's own declared quiet period (#1239, D6) from its active session.

        The effective period is clamped by ``max_declared_quiet_seconds`` (0 records nothing that
        takes effect) and runs from ``declared_at``, the declaration's accepted time (now when
        unknown), so reconcile later computes the same end. A later declaration replaces an
        earlier one, shorter or longer; contact does not clear it.
        """

        session = _id(IdKind.SESSION, session_id)
        start = self._now() if declared_at is None else _timestamp(declared_at)
        quiet_until = self._quiet_until(start, expected_quiet_seconds)
        async with self._lock:
            snapshot = await self._declaring_task_locked(session)
            return await self._apply_quiet_locked(
                snapshot, replace(snapshot, quiet_until=quiet_until)
            )

    async def imply_quiet_period(
        self,
        *,
        task_id: str,
        session_id: str,
        started_at: datetime,
        expected_quiet_seconds: int,
    ) -> bool:
        """Hold open work's window while a tool call its host announced runs (#1239, D6).

        A pre-tool hook that the observation route bound to the task's own active session, and
        that names the call's own timeout, implies that session expects no contact until the
        call ends: ``started_at`` (the hook's receipt time) plus the timeout, clamped by
        ``max_declared_quiet_seconds`` like a declaration (0 implies nothing). Another session,
        an ended one, or terminal work records nothing. Overlapping calls keep the latest end, so
        a later shorter call never cuts a running one short. A declaration never replaces it and
        the finishing hook never clears it; it simply passes. A duplicate delivery writes
        nothing. Returns whether the call holds the task's period.
        """

        task = _id(IdKind.TASK, task_id)
        session = _id(IdKind.SESSION, session_id)
        implied_until = self._quiet_until(_timestamp(started_at), expected_quiet_seconds)
        if implied_until is None:
            return False
        async with self._lock:
            snapshot = await self._store.get_task(task)
            if (
                snapshot is None
                or snapshot.active_session_id != session
                or snapshot.session_health is SessionHealth.ENDED
                or snapshot.work_state is not WorkState.OPEN
            ):
                return False
            current = snapshot.implied_quiet_until
            if current is None or current < implied_until:
                await self._apply_quiet_locked(
                    snapshot, replace(snapshot, implied_quiet_until=implied_until)
                )
            return True

    async def validate_quiet_declaration(self, *, session_id: str) -> None:
        """Refuse, before append, a declaration from a session that is not the task's own."""

        session = _id(IdKind.SESSION, session_id)
        async with self._lock:
            await self._declaring_task_locked(session)

    async def _declaring_task_locked(self, session: str) -> LineageSnapshot:
        task_id = await self._store.get_session_task(session)
        snapshot = None if task_id is None else await self._store.get_task(task_id)
        if (
            snapshot is None
            or snapshot.active_session_id != session
            or snapshot.session_health is SessionHealth.ENDED
        ):
            raise _error(
                PublicErrorCode.SESSION_CONFLICT,
                "The task session is not active.",
                reason="lineage_session_not_active",
            )
        return snapshot

    async def reconcile_quiet_period(
        self, *, task_id: str, expected_quiet_seconds: int, declared_at: datetime
    ) -> LineageSnapshot:
        """Mirror the task's latest declared quiet period from its ledger after a restart.

        Idempotent: the period runs from the declaration's accepted time, so a repeated sweep
        writes nothing once the catalog agrees. It replaces only the declared period; an implied
        one is catalog state from a host hook, never in the ledger, and is left as it is.
        """

        task = _id(IdKind.TASK, task_id)
        quiet_until = self._quiet_until(_timestamp(declared_at), expected_quiet_seconds)
        async with self._lock:
            snapshot = await self._store.get_task(task)
            if snapshot is None:
                raise _error(
                    PublicErrorCode.SESSION_NOT_FOUND,
                    "The task was not found.",
                    reason="lineage_task_not_found",
                )
            return await self._apply_quiet_locked(
                snapshot, replace(snapshot, quiet_until=quiet_until)
            )

    async def own_lifecycle(self, task_id: str) -> LineageSnapshot | None:
        """The task's own lifecycle for status and receipts (#1239), or ``None`` if unknown.

        A read without the coordinator lock (one store read, like status): open work out of
        contact carries the deadline the recovery sweep will apply, judged by the same window.
        Its ``quiet_until`` is the later end of the declared and the implied quiet period, the
        one period status names; ``implied_quiet_until`` is folded into it.
        """

        snapshot = await self._store.get_task(_id(IdKind.TASK, task_id))
        if snapshot is None:
            return None
        # A quiet period that has passed, or that no open work can use, is history for status.
        # The deadline below still runs from it, as the recovery sweep's does.
        quiet_until = _quiet_end(snapshot)
        if quiet_until is not None and (
            snapshot.work_state is not WorkState.OPEN or quiet_until <= self._now()
        ):
            quiet_until = None
        if (
            snapshot.work_state is not WorkState.OPEN
            or snapshot.session_health is not SessionHealth.CONTACT_LOST
            or snapshot.contact_lost_at is None
        ):
            return replace(snapshot, quiet_until=quiet_until, implied_quiet_until=None)
        window = await self._contact_window_seconds(snapshot)
        return replace(
            snapshot,
            abandonment_deadline=_quiet_deadline(
                snapshot, snapshot.contact_lost_at, timedelta(seconds=window)
            ),
            abandonment_reason=REVERSIBLE_ABANDONMENT_REASON,
            quiet_until=quiet_until,
            implied_quiet_until=None,
        )

    async def status(self, task_id: str) -> LineageStatus:
        task = _id(IdKind.TASK, task_id)
        async with self._lock:
            snapshot = await self._store.get_task(task)
            if snapshot is None:
                raise _error(
                    PublicErrorCode.SESSION_NOT_FOUND,
                    "The task was not found.",
                    reason="lineage_task_not_found",
                )
            parent = None
            if snapshot.parent_task_id is not None:
                parent = await self._store.get_task(snapshot.parent_task_id)
            return LineageStatus(
                snapshot.task_id, parent, await self._store.list_children(snapshot.task_id)
            )

    @staticmethod
    def decide_admission(request: AdmissionRequest) -> AdmissionResult:
        """Evaluate the #497 table without allowing membership to select a task."""

        if type(request) is not AdmissionRequest:
            raise _error(PublicErrorCode.INVALID_REQUEST, "The admission request is invalid.")
        if request.attach_handle_present and request.parent_session_present:
            raise _error(
                PublicErrorCode.SESSION_CONFLICT,
                "The delegation selectors conflict.",
                reason="selector_conflict",
            )
        if request.attach_handle_present:
            return AdmissionResult(AdmissionDecision.ATTACH, None, False)
        if request.parent_session_present:
            return AdmissionResult(AdmissionDecision.SELF_REGISTER, None, False)
        predecessor_count = len(request.predecessor_task_ids)
        if predecessor_count > 1:
            # Only disclose the count; never return or put a task/session binding in the error.
            raise _error(
                PublicErrorCode.SESSION_CONFLICT,
                "Multiple resumable task bindings were found.",
                reason="ambiguous_binding",
                count=predecessor_count,
            )
        if request.same_pair_task_id is not None:
            return AdmissionResult(
                AdmissionDecision.RESUME, request.same_pair_task_id, False, candidate_count=1
            )
        if predecessor_count == 1:
            return AdmissionResult(
                AdmissionDecision.ATTACH,
                request.predecessor_task_ids[0],
                False,
                predecessor_resumed=True,
                candidate_count=1,
            )
        project = request.auto_grouping and request.live_task_count >= 1
        return AdmissionResult(AdmissionDecision.CREATE, None, project)

    async def _require_operation(
        self, operation_id: str, request_digest: str
    ) -> DelegationOperation:
        operation = await self._store.get_operation(_id(IdKind.REQUEST, operation_id))
        if operation is None:
            raise _error(
                PublicErrorCode.SESSION_NOT_FOUND,
                "The delegation operation was not found.",
                reason="lineage_operation_not_found",
            )
        _digest(request_digest)
        if not hmac.compare_digest(operation.request_digest, request_digest):
            raise _error(
                PublicErrorCode.REQUEST_IDENTITY_CONFLICT,
                "The request identity conflicts with an earlier delegation.",
                reason="lineage_request_identity_conflict",
            )
        return operation

    async def _advance_operation(
        self, operation_id: str, request_digest: str, phase: DelegationPhase
    ) -> DelegationOperation:
        if type(phase) is not DelegationPhase:
            raise _error(PublicErrorCode.INVALID_REQUEST, "The delegation phase is invalid.")
        async with self._lock:
            operation = await self._require_operation(operation_id, request_digest)
            if operation.state is DelegationOperationState.COMPLETE:
                return operation
            self._require_owned_lease(operation)
            if operation.phase is phase:
                return operation
            successor = {
                DelegationPhase.LINEAGE_RESERVED: DelegationPhase.CHILD_BUNDLE_READY,
                DelegationPhase.CHILD_BUNDLE_READY: DelegationPhase.PARENT_EVENT_COMMITTED,
                DelegationPhase.PARENT_EVENT_COMMITTED: DelegationPhase.HANDLE_PUBLISHED,
            }.get(operation.phase)
            if successor is not phase:
                raise _error(
                    PublicErrorCode.INTERNAL_ERROR,
                    "The delegation phase transition is invalid.",
                    reason="lineage_phase_transition",
                )
            if phase is DelegationPhase.CHILD_BUNDLE_READY and self._bundle_provisioner is not None:
                await self._bundle_provisioner(operation.child_task_id, operation.depth)
            updated = replace(
                operation,
                phase=phase,
                lease_expires_at=self._now() + timedelta(seconds=self._config.start_lease_seconds),
            )
            await self._store.save_operation(updated)
            return updated

    def _require_owned_lease(self, operation: DelegationOperation) -> None:
        """Reject phase writes from an expired or superseded service generation."""

        if operation.state is not DelegationOperationState.PENDING:
            return
        if (
            operation.owner_generation != self._owner_generation
            or operation.lease_expires_at <= self._now()
        ):
            raise _error(
                PublicErrorCode.OPERATION_PENDING,
                "The delegation operation lease must be recovered before it can continue.",
                reason="lineage_operation_lease_expired",
                retryable=True,
            )
