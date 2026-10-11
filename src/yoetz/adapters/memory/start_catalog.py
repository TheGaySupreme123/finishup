"""In-memory reference implementation of the pre-writer start catalog."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from enum import Enum
from types import TracebackType
from typing import Final, Protocol

from yoetz.domain.coordination import (
    CoordinationGrant,
    GrantState,
    LineageAcceptance,
    LineageOrigin,
    MemberKind,
    ProjectDescriptor,
    ProjectKind,
    ProjectMembership,
    ProjectTextRef,
    SessionHealth,
    WorkState,
    general_link_conflicts,
    provenance_spans_general_projects,
)
from yoetz.domain.privacy import LocalDisclosureSink
from yoetz.domain.values import format_rfc3339_millis, validate_commitment, validate_sha256_digest
from yoetz.ports.clock import ClockPort
from yoetz.ports.ids import IdPort
from yoetz.ports.keys import MacKeyHandle
from yoetz.ports.publish_response_catalog import PublishResponseKey, StoredPublishResponse
from yoetz.ports.runtime import StartCompletionEvidence, StartMilestone
from yoetz.ports.start_catalog import (
    EXTERNAL_REF_DOMAIN,
    START_TITLE_DOMAIN,
    WORKSPACE_REF_DOMAIN,
    EncryptedResultRef,
    SafeReason,
    SessionBinding,
    SessionState,
    StartAllocation,
    StartCommand,
    StartIdentityCommitments,
    StartIdentityInput,
    StartMode,
    StartOperationLease,
    StartPhase,
    TaskLineage,
    TaskRoute,
    TaskRouteState,
    TaskSourceProvenance,
)
from yoetz.protocol.canonical import JsonValue, canonical_digest, canonical_encode
from yoetz.protocol.errors import PublicErrorCode, PublicOperationError
from yoetz.protocol.ids import IdKind, validate_actor_id, validate_id
from yoetz.protocol.recovery import REASON_REMEDIES

__all__ = [
    "MemoryStartCatalogAdapter",
    "MemoryStartCatalogPolicy",
    "MemoryStartCatalogState",
]

_PHASE_SUCCESSOR: Final = {
    StartPhase.ROUTE_RESERVED: StartPhase.BUNDLE_READY,
    StartPhase.BUNDLE_READY: StartPhase.LIFECYCLE_COMMITTED,
    StartPhase.LIFECYCLE_COMMITTED: StartPhase.RESULT_PUBLISHED,
}


class _AsyncLock(Protocol):
    async def __aenter__(self) -> object: ...

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None: ...


@dataclass(frozen=True, slots=True, repr=False)
class _RouteRecord:
    task_id: str
    workspace_ref_commitment: str | None
    external_ref_commitment: str | None
    active_session_id: str
    bundle_relpath: str
    route_generation: int
    route_identity_digest: str
    state: TaskRouteState
    quarantine_code: str | None
    created_at: datetime
    updated_at: datetime
    repository_privacy_commitment: str | None = None
    parent_task_id: str | None = None
    depth: int = 0
    lineage_digest: str | None = None
    origin: LineageOrigin | None = None
    acceptance: LineageAcceptance | None = None
    work_state: WorkState = WorkState.OPEN

    def __repr__(self) -> str:
        return "_RouteRecord(<redacted>)"


class _OperationState(str, Enum):  # noqa: UP042 - mirrors the durable text vocabulary
    PENDING = "pending"
    COMPLETE = "complete"
    QUARANTINED = "quarantined"


@dataclass(frozen=True, slots=True, repr=False)
class _OperationRecord:
    installation_id: str
    operation_id: str
    request_digest: str
    requested_mode: StartMode
    route_action: str
    state: _OperationState
    phase: StartPhase
    task_id: str
    session_id: str
    writer_id: str
    lifecycle_event_id: str
    route_generation: int
    route_identity_digest: str
    owner_generation: int | None
    lease_owner_id: str | None
    lease_generation: int | None
    lease_expires_at: datetime | None
    response_object_id: str | None
    response_envelope_digest: str | None
    terminal_result_canonical: bytes | None
    terminal_result_digest: str | None
    quarantine_code: str | None
    terminal_at: datetime | None
    created_at: datetime
    updated_at: datetime

    def __repr__(self) -> str:
        return "_OperationRecord(<redacted>)"


@dataclass(slots=True, repr=False)
class MemoryStartCatalogState:
    """Process-local structural catalog state shared by reference adapters."""

    owner_generation: int = 1
    revision: int = 0
    routes: dict[str, _RouteRecord] = field(default_factory=lambda: {})
    operations: dict[tuple[str, str], _OperationRecord] = field(default_factory=lambda: {})
    session_index: dict[str, str] = field(default_factory=lambda: {})
    historical_session_index: dict[str, str] = field(default_factory=lambda: {})
    attachment_index: dict[tuple[str, str], str] = field(default_factory=lambda: {})
    session_states: dict[str, SessionState] = field(default_factory=lambda: {})
    projects: dict[str, ProjectDescriptor] = field(default_factory=lambda: {})
    repository_grouping_preferences: dict[str, bool] = field(default_factory=lambda: {})
    memberships: dict[tuple[str, int, MemberKind, str], ProjectMembership] = field(
        default_factory=lambda: {}
    )
    grants: dict[tuple[str, int], CoordinationGrant] = field(default_factory=lambda: {})
    publish_responses: dict[tuple[str, str, LocalDisclosureSink], StoredPublishResponse] = field(
        default_factory=lambda: {}
    )

    def __post_init__(self) -> None:
        if type(self.owner_generation) is not int or self.owner_generation <= 0:
            raise ValueError("catalog_owner_generation_invalid")
        if type(self.revision) is not int or self.revision < 0:
            raise ValueError("catalog_revision_invalid")

    def __repr__(self) -> str:
        return "MemoryStartCatalogState(<redacted>)"


@dataclass(frozen=True, slots=True)
class MemoryStartCatalogPolicy:
    lease_seconds: int = 60

    def __post_init__(self) -> None:
        if self.lease_seconds != 60:
            raise ValueError("start_lease_policy_invalid")


def _error(
    code: PublicErrorCode,
    *,
    retryable: bool = False,
    message: str | None = None,
    safe_details: object | None = None,
) -> PublicOperationError:
    messages = {
        PublicErrorCode.INVALID_REQUEST: "The start request is invalid.",
        PublicErrorCode.IDEMPOTENCY_CONFLICT: "The request ID was already used.",
        PublicErrorCode.OPERATION_PENDING: "The start operation is still pending.",
        PublicErrorCode.SESSION_CONFLICT: "The requested task attachment conflicts.",
        PublicErrorCode.SESSION_NOT_FOUND: "The requested task attachment was not found.",
        PublicErrorCode.BUNDLE_BUSY: "The task is temporarily busy.",
        PublicErrorCode.STORAGE_CORRUPT: "The local catalog is inconsistent.",
        PublicErrorCode.INTERNAL_ERROR: (
            "The start state is inconsistent. " + REASON_REMEDIES["start_state_inconsistent"]
        ),
    }
    if code is PublicErrorCode.INTERNAL_ERROR and safe_details is None:
        # An inconsistent start state is a typed stage, never a bare internal error (tb4n3 RC-2).
        safe_details = {"reason_code": "start_state_inconsistent"}
    return PublicOperationError(
        code,
        messages[code] if message is None else message,
        retryable,
        safe_details=safe_details,
    )


def _commitment(lookup: MacKeyHandle, domain: bytes, value: str) -> str:
    result = lookup.mac(domain, canonical_encode(value))
    if type(result) is not str:
        raise _error(PublicErrorCode.INVALID_REQUEST)
    return result


def _route_value(record: _RouteRecord) -> TaskRoute:
    try:
        return TaskRoute(
            task_id=record.task_id,
            session_id=record.active_session_id,
            bundle_relpath=record.bundle_relpath,
            route_generation=record.route_generation,
            state=record.state,
            route_identity_digest=record.route_identity_digest,
            repository_privacy_commitment=record.repository_privacy_commitment,
            parent_task_id=record.parent_task_id,
            depth=record.depth,
            lineage_digest=record.lineage_digest,
            origin=record.origin,
            acceptance=record.acceptance,
            work_state=record.work_state,
        )
    except (TypeError, ValueError) as exc:
        raise _error(PublicErrorCode.STORAGE_CORRUPT) from exc


def _lineage_from_record(record: _RouteRecord) -> TaskLineage:
    try:
        return TaskLineage(
            task_id=record.task_id,
            parent_task_id=record.parent_task_id,
            depth=record.depth,
            lineage_digest=record.lineage_digest or record.route_identity_digest,
            origin=record.origin,
            acceptance=record.acceptance,
            work_state=record.work_state,
        )
    except (TypeError, ValueError) as exc:
        raise _error(PublicErrorCode.STORAGE_CORRUPT) from exc


def _source_from_record(record: _RouteRecord) -> TaskSourceProvenance:
    try:
        return TaskSourceProvenance(
            task_id=record.task_id,
            workspace_ref_commitment=record.workspace_ref_commitment,
            external_ref_commitment=record.external_ref_commitment,
            repository_privacy_commitment=record.repository_privacy_commitment,
            route_generation=record.route_generation,
            route_identity_digest=record.route_identity_digest,
        )
    except (TypeError, ValueError) as exc:
        raise _error(PublicErrorCode.STORAGE_CORRUPT) from exc


def _lease(record: _OperationRecord) -> StartOperationLease | None:
    if record.state is not _OperationState.PENDING:
        return None
    if (
        record.owner_generation is None
        or record.lease_owner_id is None
        or record.lease_generation is None
        or record.lease_expires_at is None
    ):
        raise _error(PublicErrorCode.STORAGE_CORRUPT)
    try:
        return StartOperationLease(
            owner_generation=record.owner_generation,
            lease_owner_id=record.lease_owner_id,
            lease_generation=record.lease_generation,
            lease_expires_at=record.lease_expires_at,
        )
    except (TypeError, ValueError) as exc:
        raise _error(PublicErrorCode.STORAGE_CORRUPT) from exc


def _allocation(record: _OperationRecord, outcome: str) -> StartAllocation:
    replayed = record.terminal_result_canonical if outcome == "replayed" else None
    expose_response = record.state is _OperationState.COMPLETE or (
        record.state is _OperationState.PENDING and record.phase is StartPhase.RESULT_PUBLISHED
    )
    try:
        return StartAllocation(
            outcome=outcome,  # type: ignore[arg-type]
            route_action=record.route_action,  # type: ignore[arg-type]
            task_id=record.task_id,
            session_id=record.session_id,
            writer_id=record.writer_id,
            lifecycle_event_id=record.lifecycle_event_id,
            bundle_relpath=f"tasks/{record.task_id}",
            route_generation=record.route_generation,
            route_identity_digest=record.route_identity_digest,
            phase=record.phase,
            response_object_id=record.response_object_id if expose_response else None,
            response_envelope_digest=(record.response_envelope_digest if expose_response else None),
            response_result_canonical=(
                record.terminal_result_canonical if expose_response else None
            ),
            response_result_digest=record.terminal_result_digest if expose_response else None,
            lease=_lease(record),
            replayed_result=replayed,
        )
    except (TypeError, ValueError) as exc:
        raise _error(PublicErrorCode.STORAGE_CORRUPT) from exc


def _same_allocation(record: _OperationRecord, allocation: StartAllocation) -> bool:
    return (
        record.task_id == allocation.task_id
        and record.session_id == allocation.session_id
        and record.writer_id == allocation.writer_id
        and record.lifecycle_event_id == allocation.lifecycle_event_id
        and record.route_generation == allocation.route_generation
        and hmac.compare_digest(record.route_identity_digest, allocation.route_identity_digest)
        and record.response_object_id == allocation.response_object_id
        and record.response_envelope_digest == allocation.response_envelope_digest
        and record.terminal_result_canonical == allocation.response_result_canonical
        and record.terminal_result_digest == allocation.response_result_digest
    )


def _evidence_value(evidence: StartCompletionEvidence) -> dict[str, JsonValue]:
    frontier: JsonValue = None
    if evidence.lifecycle_frontier is not None:
        frontier = dict(evidence.lifecycle_frontier.as_wire())
    return {
        "lifecycle_event_id": evidence.lifecycle_event_id,
        "lifecycle_frontier": frontier,
        "milestone": evidence.milestone.value,
        "owner_generation": evidence.owner_generation,
        "response_object_id": evidence.response_object_id,
        "response_envelope_digest": evidence.response_envelope_digest,
        "result_digest": evidence.result_digest,
        "route_generation": evidence.route_generation,
        "route_identity_digest": evidence.route_identity_digest,
        "session_id": evidence.session_id,
        "task_id": evidence.task_id,
        "writer_id": evidence.writer_id,
    }


def _validate_completion_evidence(
    record: _OperationRecord,
    result: EncryptedResultRef,
    evidence: StartCompletionEvidence,
) -> None:
    if (
        evidence.milestone is not StartMilestone.RESULT_PUBLISHED
        or evidence.owner_generation != record.owner_generation
        or evidence.task_id != record.task_id
        or evidence.session_id != record.session_id
        or evidence.writer_id != record.writer_id
        or evidence.lifecycle_event_id != record.lifecycle_event_id
        or evidence.route_generation != record.route_generation
        or not hmac.compare_digest(evidence.route_identity_digest, record.route_identity_digest)
        or evidence.response_object_id != result.response_object_id
        or evidence.response_envelope_digest != result.envelope_digest
        or evidence.result_digest != result.result_digest
        or not hmac.compare_digest(
            evidence.evidence_digest, canonical_digest(_evidence_value(evidence))
        )
    ):
        raise _error(PublicErrorCode.INTERNAL_ERROR)


def _quarantine_envelope(record: _OperationRecord, reason: SafeReason) -> bytes:
    return canonical_encode(
        {
            "lifecycle_event_id": record.lifecycle_event_id,
            "quarantine_code": reason.code,
            "route_identity_digest": record.route_identity_digest,
            "session_id": record.session_id,
            "task_id": record.task_id,
            "writer_id": record.writer_id,
        }
    )


class MemoryStartCatalogAdapter:
    """Executable reference state machine for ``StartCatalogPort``."""

    def __init__(
        self,
        *,
        installation_id: str,
        lookup: MacKeyHandle,
        state: MemoryStartCatalogState,
        transaction_lock: _AsyncLock,
        clock: ClockPort,
        ids: IdPort,
        policy: MemoryStartCatalogPolicy = MemoryStartCatalogPolicy(),
    ) -> None:
        self._installation_id = validate_id(IdKind.INSTALLATION, installation_id)
        self._lookup = lookup
        self._state = state
        self._lock = transaction_lock
        self._clock = clock
        self._ids = ids
        self._policy = policy
        self._lease_owner_id = ids.new(IdKind.SERVICE_INSTANCE)
        validate_id(IdKind.SERVICE_INSTANCE, self._lease_owner_id)

    async def commit_identity(self, value: StartIdentityInput) -> StartIdentityCommitments:
        if type(value) is not StartIdentityInput:
            raise _error(PublicErrorCode.INVALID_REQUEST)
        title = _commitment(self._lookup, START_TITLE_DOMAIN, value.task_title)
        workspace = None
        external = None
        if value.workspace_ref is not None and value.external_ref is not None:
            workspace = _commitment(self._lookup, WORKSPACE_REF_DOMAIN, value.workspace_ref)
            external = _commitment(self._lookup, EXTERNAL_REF_DOMAIN, value.external_ref)
        return StartIdentityCommitments(title, workspace, external)

    async def resolve_route(self, session_id: str) -> TaskRoute | None:
        try:
            session = validate_id(IdKind.SESSION, session_id)
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        async with self._lock:
            task_id = self._state.session_index.get(session)
            if task_id is None:
                return None
            record = self._state.routes.get(task_id)
            if record is None or record.active_session_id != session:
                raise _error(PublicErrorCode.STORAGE_CORRUPT)
        return _route_value(record)

    async def recovery_routes(self) -> tuple[TaskRoute, ...]:
        """Return the complete bounded route inventory for ready recovery."""

        async with self._lock:
            records = tuple(sorted(self._state.routes.values(), key=lambda item: item.task_id))
        return tuple(_route_value(record) for record in records)

    async def session_binding(self, session_id: str) -> SessionBinding | None:
        try:
            session = validate_id(IdKind.SESSION, session_id)
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        async with self._lock:
            task_id = self._state.session_index.get(session)
            if task_id is None:
                task_id = self._state.historical_session_index.get(session)
            if task_id is None:
                task_id = self._task_id_for_operation_session(session)
            if task_id is None:
                return None
            return self._binding_for_task(task_id)

    async def list_workspace_task_ids(self, workspace_ref_commitment: str) -> tuple[str, ...]:
        try:
            validate_commitment(workspace_ref_commitment)
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        async with self._lock:
            task_ids = sorted(
                record.task_id
                for record in self._state.routes.values()
                if record.workspace_ref_commitment == workspace_ref_commitment
                and record.state is not TaskRouteState.QUARANTINED
            )
        return tuple(task_ids)

    async def list_project_task_ids(self, project_id: str) -> tuple[str, ...]:
        try:
            project = validate_id(IdKind.PROJECT, project_id)
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        async with self._lock:
            descriptor = self._state.projects.get(project)
            if descriptor is None or descriptor.dissolved_at is not None:
                return ()
            task_ids = {
                key[3]
                for key, membership in self._state.memberships.items()
                if key[0] == project
                and key[2] is MemberKind.TASK
                and membership.unbound_at is None
                and key[3] in self._state.routes
                and self._state.routes[key[3]].state is not TaskRouteState.QUARANTINED
            }
            if (
                descriptor.kind is ProjectKind.REPOSITORY
                and descriptor.repository_commitment is not None
                and descriptor.dissolved_at is None
                and descriptor.auto_grouping
            ):
                task_ids.update(
                    record.task_id
                    for record in self._state.routes.values()
                    if record.repository_privacy_commitment == descriptor.repository_commitment
                    and record.state is not TaskRouteState.QUARANTINED
                )
            elif descriptor.kind is ProjectKind.GENERAL:
                repository_bindings = {
                    key[3]
                    for key, membership in self._state.memberships.items()
                    if key[0] == project
                    and key[2] is MemberKind.REPOSITORY
                    and membership.unbound_at is None
                }
                workspace_bindings = {
                    key[3]
                    for key, membership in self._state.memberships.items()
                    if key[0] == project
                    and key[2] is MemberKind.WORKSPACE
                    and membership.unbound_at is None
                }
                task_ids.update(
                    record.task_id
                    for record in self._state.routes.values()
                    if record.state is not TaskRouteState.QUARANTINED
                    and (
                        record.repository_privacy_commitment in repository_bindings
                        or record.workspace_ref_commitment in workspace_bindings
                    )
                )
        return tuple(sorted(task_ids))

    async def list_repository_task_ids(self, repository_privacy_commitment: str) -> tuple[str, ...]:
        try:
            validate_commitment(repository_privacy_commitment)
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        async with self._lock:
            task_ids = sorted(
                record.task_id
                for record in self._state.routes.values()
                if record.repository_privacy_commitment == repository_privacy_commitment
                and record.state is not TaskRouteState.QUARANTINED
            )
        return tuple(task_ids)

    async def task_lineage(self, task_id: str) -> TaskLineage | None:
        try:
            task = validate_id(IdKind.TASK, task_id)
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        async with self._lock:
            record = self._state.routes.get(task)
            if record is None:
                return None
            return _lineage_from_record(record)

    async def task_source_provenance(self, task_id: str) -> TaskSourceProvenance | None:
        try:
            task = validate_id(IdKind.TASK, task_id)
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        async with self._lock:
            record = self._state.routes.get(task)
            if record is None:
                return None
            return _source_from_record(record)

    async def task_route_generation(self, task_id: str) -> int:
        try:
            task = validate_id(IdKind.TASK, task_id)
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        async with self._lock:
            record = self._state.routes.get(task)
            if record is None:
                raise _error(PublicErrorCode.SESSION_NOT_FOUND)
            return record.route_generation

    async def task_work_state(self, task_id: str) -> WorkState:
        try:
            task = validate_id(IdKind.TASK, task_id)
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        async with self._lock:
            record = self._state.routes.get(task)
            if record is None:
                raise _error(PublicErrorCode.SESSION_NOT_FOUND)
            return record.work_state

    async def task_session_state(self, session_id: str) -> SessionState | None:
        try:
            session = validate_id(IdKind.SESSION, session_id)
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        async with self._lock:
            state = self._state.session_states.get(session)
            if state is None:
                return None
            now = self._clock.now_utc()
            if state.health is SessionHealth.ACTIVE and (
                state.lease_expires_at is None or state.lease_expires_at <= now
            ):
                # Status reads remain read-only; the service sweep owns durable lease transition.
                return replace(
                    state,
                    health=SessionHealth.CONTACT_LOST,
                    changed_at=now,
                    lease_expires_at=None,
                )
            return state

    async def task_session_states(self, task_id: str) -> tuple[SessionState, ...]:
        try:
            task = validate_id(IdKind.TASK, task_id)
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        async with self._lock:
            sessions = sorted(
                state.session_id
                for state in self._state.session_states.values()
                if state.task_id == task
            )
        result: list[SessionState] = []
        for session in sessions:
            state = await self.task_session_state(session)
            if state is None:
                raise _error(PublicErrorCode.STORAGE_CORRUPT)
            result.append(state)
        return tuple(result)

    async def list_child_task_ids(self, parent_task_id: str) -> tuple[str, ...]:
        try:
            parent = validate_id(IdKind.TASK, parent_task_id)
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        async with self._lock:
            return tuple(
                sorted(
                    record.task_id
                    for record in self._state.routes.values()
                    if record.parent_task_id == parent
                    and record.state is not TaskRouteState.QUARANTINED
                )
            )

    async def list_task_project_ids(self, task_id: str) -> tuple[str, ...]:
        return await self._list_task_project_ids(task_id, include_quarantined=False)

    async def list_task_project_ids_for_consent_invalidation(self, task_id: str) -> tuple[str, ...]:
        return await self._list_task_project_ids(task_id, include_quarantined=True)

    async def _list_task_project_ids(
        self, task_id: str, *, include_quarantined: bool
    ) -> tuple[str, ...]:
        try:
            task = validate_id(IdKind.TASK, task_id)
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        async with self._lock:
            project_ids = {
                key[0]
                for key, membership in self._state.memberships.items()
                if key[2] is MemberKind.TASK
                and key[3] == task
                and membership.unbound_at is None
                and self._state.projects.get(key[0]) is not None
                and self._state.projects[key[0]].dissolved_at is None
            }
            route = self._state.routes.get(task)
            if route is not None and (
                include_quarantined or route.state is not TaskRouteState.QUARANTINED
            ):
                project_ids.update(
                    project.project_id
                    for project in self._state.projects.values()
                    if project.kind is ProjectKind.GENERAL
                    and project.dissolved_at is None
                    and any(
                        membership.unbound_at is None
                        and (
                            membership.member_kind is MemberKind.REPOSITORY
                            and membership.member_commitment_or_id
                            == route.repository_privacy_commitment
                            or membership.member_kind is MemberKind.WORKSPACE
                            and membership.member_commitment_or_id == route.workspace_ref_commitment
                        )
                        for key, membership in self._state.memberships.items()
                        if key[0] == project.project_id
                    )
                )
            if (
                route is not None
                and (include_quarantined or route.state is not TaskRouteState.QUARANTINED)
                and route.repository_privacy_commitment is not None
            ):
                project_ids.update(
                    project.project_id
                    for project in self._state.projects.values()
                    if project.kind is ProjectKind.REPOSITORY
                    and project.repository_commitment == route.repository_privacy_commitment
                    and project.auto_grouping
                    and project.dissolved_at is None
                )
            return tuple(sorted(project_ids))

    async def task_route(self, task_id: str) -> TaskRoute | None:
        try:
            task = validate_id(IdKind.TASK, task_id)
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        async with self._lock:
            record = self._state.routes.get(task)
            return None if record is None else _route_value(record)

    async def repository_state(self, repository_commitment: str) -> ProjectDescriptor | None:
        try:
            validate_commitment(repository_commitment)
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        async with self._lock:
            matches = [
                project
                for project in self._state.projects.values()
                if project.kind is ProjectKind.REPOSITORY
                and project.repository_commitment == repository_commitment
            ]
            if len(matches) > 1:
                raise _error(PublicErrorCode.STORAGE_CORRUPT)
            return None if not matches else matches[0]

    async def repository_auto_grouping_enabled(self, repository_commitment: str) -> bool:
        try:
            validate_commitment(repository_commitment)
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        async with self._lock:
            preference = self._state.repository_grouping_preferences.get(repository_commitment)
            matches = [
                project
                for project in self._state.projects.values()
                if project.kind is ProjectKind.REPOSITORY
                and project.repository_commitment == repository_commitment
            ]
            if len(matches) > 1:
                raise _error(PublicErrorCode.STORAGE_CORRUPT)
            project = None if not matches else matches[0].auto_grouping
            if preference is not None and project is not None and preference is not project:
                raise _error(PublicErrorCode.STORAGE_CORRUPT)
            if preference is not None:
                return preference
            return True if project is None else project

    async def project_state(self, project_id: str) -> ProjectDescriptor | None:
        try:
            project = validate_id(IdKind.PROJECT, project_id)
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        async with self._lock:
            return self._state.projects.get(project)

    async def project_memberships(self, project_id: str) -> tuple[ProjectMembership, ...]:
        try:
            project = validate_id(IdKind.PROJECT, project_id)
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        async with self._lock:
            return tuple(
                membership
                for key, membership in sorted(
                    self._state.memberships.items(),
                    key=lambda item: (item[0][1], item[0][2].value, item[0][3]),
                )
                if key[0] == project
            )

    async def coordination_grant(
        self, project_id: str, membership_generation: int
    ) -> CoordinationGrant | None:
        try:
            project = validate_id(IdKind.PROJECT, project_id)
            if type(membership_generation) is not int or membership_generation <= 0:
                raise ValueError("membership_generation_invalid")
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        async with self._lock:
            return self._state.grants.get((project, membership_generation))

    async def record_task_lineage(
        self,
        task_id: str,
        *,
        parent_task_id: str | None,
        depth: int,
        lineage_digest: str,
        origin: LineageOrigin | None,
        acceptance: LineageAcceptance | None,
    ) -> TaskLineage:
        try:
            task = validate_id(IdKind.TASK, task_id)
            parent = None if parent_task_id is None else validate_id(IdKind.TASK, parent_task_id)
            validate_sha256_digest(lineage_digest)
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        async with self._lock:
            record = self._state.routes.get(task)
            if record is None:
                raise _error(PublicErrorCode.SESSION_NOT_FOUND)
            if parent is not None:
                parent_record = self._state.routes.get(parent)
                if parent_record is None:
                    raise _error(PublicErrorCode.SESSION_NOT_FOUND)
                if parent_record.state is TaskRouteState.QUARANTINED:
                    raise _error(PublicErrorCode.SESSION_CONFLICT)
                if parent_record.depth + 1 != depth:
                    raise _error(PublicErrorCode.SESSION_CONFLICT)
                if (
                    record.repository_privacy_commitment is not None
                    and parent_record.repository_privacy_commitment is not None
                    and not hmac.compare_digest(
                        record.repository_privacy_commitment,
                        parent_record.repository_privacy_commitment,
                    )
                ):
                    raise _error(PublicErrorCode.SESSION_CONFLICT)
            desired = TaskLineage(
                task_id=task,
                parent_task_id=parent,
                depth=depth,
                lineage_digest=lineage_digest,
                origin=origin,
                acceptance=acceptance,
                work_state=record.work_state,
            )
            current = _lineage_from_record(record)
            if current == desired:
                return current
            if (
                record.parent_task_id is not None
                or record.origin is not None
                or record.acceptance is not None
                or record.depth != 0
            ):
                raise _error(PublicErrorCode.SESSION_CONFLICT)
            updated = replace(
                record,
                parent_task_id=parent,
                depth=depth,
                lineage_digest=lineage_digest,
                origin=origin,
                acceptance=acceptance,
                updated_at=self._clock.now_utc(),
            )
            self._state.routes[task] = updated
            self._state.revision += 1
            return _lineage_from_record(updated)

    @staticmethod
    def _work_state_transition_allowed(current: WorkState, requested: WorkState) -> bool:
        return current is requested or (
            current is WorkState.OPEN
            and requested
            in {
                WorkState.CLOSED,
                WorkState.CANCELLED,
                WorkState.ABANDONED,
                WorkState.WRITTEN_OFF,
            }
        )

    async def set_task_work_state(self, task_id: str, state: WorkState) -> TaskLineage:
        try:
            task = validate_id(IdKind.TASK, task_id)
            if type(state) is not WorkState:
                raise ValueError("work_state_invalid")
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        async with self._lock:
            record = self._state.routes.get(task)
            if record is None:
                raise _error(PublicErrorCode.SESSION_NOT_FOUND)
            if not self._work_state_transition_allowed(record.work_state, state):
                raise _error(PublicErrorCode.SESSION_CONFLICT)
            if record.work_state is not state:
                record = replace(record, work_state=state, updated_at=self._clock.now_utc())
                self._state.routes[task] = record
                self._state.revision += 1
            return _lineage_from_record(record)

    async def record_session_state(
        self,
        task_id: str,
        session_id: str,
        *,
        health: SessionHealth,
        changed_at: datetime,
        lease_expires_at: datetime | None = None,
        actor_id: str | None = None,
    ) -> SessionState:
        try:
            task = validate_id(IdKind.TASK, task_id)
            session = validate_id(IdKind.SESSION, session_id)
            if type(health) is not SessionHealth:
                raise ValueError("session_health_invalid")
            format_rfc3339_millis(changed_at)
            if lease_expires_at is not None:
                format_rfc3339_millis(lease_expires_at)
                if health is SessionHealth.ACTIVE and lease_expires_at <= changed_at:
                    raise ValueError("session_lease_expired")
            if actor_id is not None:
                validate_actor_id(actor_id)
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        async with self._lock:
            if task not in self._state.routes:
                raise _error(PublicErrorCode.SESSION_NOT_FOUND)
            current = self._state.session_states.get(session)
            if current is not None and current.task_id != task:
                raise _error(PublicErrorCode.SESSION_CONFLICT)
            if health is SessionHealth.ACTIVE and lease_expires_at is None:
                lease_expires_at = changed_at + timedelta(seconds=self._policy.lease_seconds)
            if current is not None and current.health is not health:
                if current.health is SessionHealth.ENDED or (
                    current.health is SessionHealth.CONTACT_LOST
                    and health not in {SessionHealth.ACTIVE, SessionHealth.ENDED}
                ):
                    raise _error(PublicErrorCode.SESSION_CONFLICT)
            effective_actor_id = (
                actor_id if actor_id is not None else (current.actor_id if current else None)
            )
            state = SessionState(
                task_id=task,
                session_id=session,
                health=health,
                changed_at=changed_at,
                lease_expires_at=lease_expires_at if health is SessionHealth.ACTIVE else None,
                actor_id=effective_actor_id,
            )
            if current != state:
                self._state.session_states[session] = state
                self._state.revision += 1
            return state

    async def extend_session_lease(
        self,
        task_id: str,
        session_id: str,
        *,
        changed_at: datetime,
        lease_expires_at: datetime,
    ) -> SessionState:
        """Atomically offer a later lease without overwriting newer catalog state."""

        try:
            task = validate_id(IdKind.TASK, task_id)
            session = validate_id(IdKind.SESSION, session_id)
            format_rfc3339_millis(changed_at)
            format_rfc3339_millis(lease_expires_at)
            if lease_expires_at <= changed_at:
                raise ValueError("session_lease_expired")
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        async with self._lock:
            if task not in self._state.routes:
                raise _error(PublicErrorCode.SESSION_NOT_FOUND)
            current = self._state.session_states.get(session)
            if current is None:
                raise _error(PublicErrorCode.SESSION_NOT_FOUND)
            if current.task_id != task:
                raise _error(PublicErrorCode.SESSION_CONFLICT)
            if current.health is SessionHealth.ENDED:
                return current
            if current.changed_at > changed_at or (
                current.lease_expires_at is not None
                and current.lease_expires_at >= lease_expires_at
            ):
                return current
            updated = replace(
                current,
                health=SessionHealth.ACTIVE,
                changed_at=changed_at,
                lease_expires_at=lease_expires_at,
            )
            self._state.session_states[session] = updated
            self._state.revision += 1
            return updated

    async def expire_session_leases(
        self, now: datetime | None = None, *, limit: int = 256
    ) -> tuple[SessionState, ...]:
        """Persist contact loss for expired leases from an explicit bounded service sweep."""

        effective_now = self._clock.now_utc() if now is None else now
        try:
            format_rfc3339_millis(effective_now)
            if type(limit) is not int or not 1 <= limit <= 256:
                raise ValueError("session_expiry_limit_invalid")
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        async with self._lock:
            expired: list[SessionState] = []
            # Scan all sessions in deterministic order and stop after the bounded number of
            # actual expirations.  Slicing the first ``limit`` rows can starve expired sessions
            # when those rows happen to be active leases that have not yet elapsed.
            for session_id in sorted(self._state.session_states):
                current = self._state.session_states[session_id]
                if current.health is not SessionHealth.ACTIVE or (
                    current.lease_expires_at is not None
                    and current.lease_expires_at > effective_now
                ):
                    continue
                updated = replace(
                    current,
                    health=SessionHealth.CONTACT_LOST,
                    changed_at=effective_now,
                    lease_expires_at=None,
                )
                self._state.session_states[session_id] = updated
                expired.append(updated)
                if len(expired) >= limit:
                    break
            if expired:
                self._state.revision += 1
            return tuple(expired)

    async def accept_task_lineage(self, task_id: str) -> TaskLineage:
        return await self._set_lineage_acceptance(task_id, LineageAcceptance.ACCEPTED)

    async def reject_task_lineage(self, task_id: str) -> TaskLineage:
        return await self._set_lineage_acceptance(task_id, LineageAcceptance.REJECTED)

    async def _set_lineage_acceptance(
        self, task_id: str, acceptance: LineageAcceptance
    ) -> TaskLineage:
        try:
            task = validate_id(IdKind.TASK, task_id)
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        async with self._lock:
            record = self._state.routes.get(task)
            if record is None:
                raise _error(PublicErrorCode.SESSION_NOT_FOUND)
            if record.parent_task_id is None:
                raise _error(PublicErrorCode.SESSION_CONFLICT)
            if record.acceptance is acceptance:
                return _lineage_from_record(record)
            if record.acceptance is not LineageAcceptance.PENDING:
                raise _error(PublicErrorCode.SESSION_CONFLICT)
            updated = replace(record, acceptance=acceptance, updated_at=self._clock.now_utc())
            self._state.routes[task] = updated
            self._state.revision += 1
            return _lineage_from_record(updated)

    def _ensure_repository_project_locked(
        self, repository_commitment: str, *, only_if_auto_grouping: bool
    ) -> ProjectDescriptor | None:
        matches = [
            project
            for project in self._state.projects.values()
            if project.kind is ProjectKind.REPOSITORY
            and project.repository_commitment == repository_commitment
        ]
        if len(matches) > 1:
            raise _error(PublicErrorCode.STORAGE_CORRUPT)
        if matches:
            current = matches[0]
            if current.dissolved_at is not None:
                raise _error(PublicErrorCode.SESSION_CONFLICT)
            if only_if_auto_grouping and not current.auto_grouping:
                return None
            return current
        auto_grouping = self._state.repository_grouping_preferences.get(repository_commitment, True)
        if only_if_auto_grouping and not auto_grouping:
            return None
        project_id = self._ids.new(IdKind.PROJECT)
        validate_id(IdKind.PROJECT, project_id)
        now = self._clock.now_utc()
        project = ProjectDescriptor(
            project_id=project_id,
            kind=ProjectKind.REPOSITORY,
            repository_commitment=repository_commitment,
            auto_grouping=auto_grouping,
            membership_generation=1,
            title_ref=None,
            description_ref=None,
            created_at=now,
        )
        membership = ProjectMembership(
            project_id=project_id,
            membership_generation=1,
            member_kind=MemberKind.REPOSITORY,
            member_commitment_or_id=repository_commitment,
            bound_at=now,
        )
        self._state.projects[project_id] = project
        self._state.memberships[(project_id, 1, MemberKind.REPOSITORY, repository_commitment)] = (
            membership
        )
        self._state.revision += 1
        return project

    async def ensure_repository_project(self, repository_commitment: str) -> ProjectDescriptor:
        try:
            validate_commitment(repository_commitment)
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        async with self._lock:
            project = self._ensure_repository_project_locked(
                repository_commitment, only_if_auto_grouping=False
            )
            assert project is not None
            return project

    async def ensure_repository_project_if_auto_grouping_enabled(
        self, repository_commitment: str
    ) -> ProjectDescriptor | None:
        try:
            validate_commitment(repository_commitment)
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        async with self._lock:
            return self._ensure_repository_project_locked(
                repository_commitment, only_if_auto_grouping=True
            )

    async def create_general_project(
        self, project_id: str, *, auto_grouping: bool = True
    ) -> ProjectDescriptor:
        try:
            project = validate_id(IdKind.PROJECT, project_id)
            if type(auto_grouping) is not bool:
                raise ValueError("auto_grouping_invalid")
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        async with self._lock:
            if project in self._state.projects:
                raise _error(PublicErrorCode.SESSION_CONFLICT)
            descriptor = ProjectDescriptor(
                project_id=project,
                kind=ProjectKind.GENERAL,
                repository_commitment=None,
                auto_grouping=auto_grouping,
                membership_generation=1,
                title_ref=None,
                description_ref=None,
                created_at=self._clock.now_utc(),
            )
            self._state.projects[project] = descriptor
            self._state.revision += 1
            return descriptor

    @staticmethod
    def _validate_membership_identity(
        member_kind: MemberKind, member_commitment_or_id: str
    ) -> tuple[MemberKind, str]:
        if type(member_kind) is not MemberKind or type(member_commitment_or_id) is not str:
            raise ValueError("membership_identity_invalid")
        if member_kind is MemberKind.TASK:
            return member_kind, validate_id(IdKind.TASK, member_commitment_or_id)
        validate_commitment(member_commitment_or_id)
        return member_kind, member_commitment_or_id

    def _active_general_memberships(self) -> list[tuple[str, MemberKind, str]]:
        facts: list[tuple[str, MemberKind, str]] = []
        for key, membership in self._state.memberships.items():
            project = self._state.projects.get(key[0])
            if (
                membership.unbound_at is None
                and project is not None
                and project.kind is ProjectKind.GENERAL
                and project.dissolved_at is None
            ):
                facts.append((key[0], key[2], key[3]))
        return facts

    def _route_provenance(self) -> list[tuple[str, str | None, str | None]]:
        return [
            (
                route.task_id,
                route.repository_privacy_commitment,
                route.workspace_ref_commitment,
            )
            for route in self._state.routes.values()
            if route.state is not TaskRouteState.QUARANTINED
        ]

    def _general_link_conflicts(self, project: str, kind: MemberKind, member: str) -> bool:
        return general_link_conflicts(
            target_project_id=project,
            member_kind=kind,
            member=member,
            other_memberships=[
                item for item in self._active_general_memberships() if item[0] != project
            ],
            provenance=self._route_provenance(),
        )

    def _provenance_spans_general_projects(
        self,
        task_id: str,
        repository_commitment: str | None,
        workspace_commitment: str | None,
    ) -> bool:
        return provenance_spans_general_projects(
            task_id=task_id,
            repository_commitment=repository_commitment,
            workspace_commitment=workspace_commitment,
            memberships=self._active_general_memberships(),
        )

    async def record_project_membership(
        self,
        project_id: str,
        *,
        member_kind: MemberKind,
        member_commitment_or_id: str,
    ) -> ProjectMembership:
        try:
            project = validate_id(IdKind.PROJECT, project_id)
            kind, member = self._validate_membership_identity(member_kind, member_commitment_or_id)
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        async with self._lock:
            descriptor = self._state.projects.get(project)
            if descriptor is None:
                raise _error(PublicErrorCode.SESSION_NOT_FOUND)
            if descriptor.dissolved_at is not None:
                raise _error(PublicErrorCode.SESSION_CONFLICT)
            active = [
                membership
                for key, membership in self._state.memberships.items()
                if key[0] == project
                and key[2] is kind
                and key[3] == member
                and membership.unbound_at is None
            ]
            if len(active) > 1:
                raise _error(PublicErrorCode.STORAGE_CORRUPT)
            if active:
                return active[0]
            if descriptor.kind is ProjectKind.GENERAL and self._general_link_conflicts(
                project, kind, member
            ):
                raise _error(
                    PublicErrorCode.SESSION_CONFLICT,
                    safe_details={"reason_code": "general_project_membership_conflict"},
                )
            generation = (
                max(
                    [descriptor.membership_generation]
                    + [key[1] for key in self._state.memberships if key[0] == project]
                )
                + 1
            )
            now = self._clock.now_utc()
            membership = ProjectMembership(
                project_id=project,
                membership_generation=generation,
                member_kind=kind,
                member_commitment_or_id=member,
                bound_at=now,
            )
            self._state.memberships[(project, generation, kind, member)] = membership
            self._state.projects[project] = replace(descriptor, membership_generation=generation)
            self._state.revision += 1
            return membership

    async def unbind_project_membership(
        self,
        project_id: str,
        membership_generation: int,
        *,
        member_kind: MemberKind | None = None,
        member_commitment_or_id: str | None = None,
    ) -> ProjectMembership:
        try:
            project = validate_id(IdKind.PROJECT, project_id)
            if type(membership_generation) is not int or membership_generation <= 0:
                raise ValueError("membership_generation_invalid")
            if (member_kind is None) != (member_commitment_or_id is None):
                raise ValueError("membership_selector_invalid")
            if member_kind is not None and member_commitment_or_id is not None:
                member_kind, member_commitment_or_id = self._validate_membership_identity(
                    member_kind, member_commitment_or_id
                )
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        async with self._lock:
            matches = [
                membership
                for key, membership in self._state.memberships.items()
                if key[0] == project
                and key[1] == membership_generation
                and membership.unbound_at is None
                and (member_kind is None or key[2] is member_kind)
                and (member_commitment_or_id is None or key[3] == member_commitment_or_id)
            ]
            if not matches:
                raise _error(PublicErrorCode.SESSION_NOT_FOUND)
            if len(matches) != 1:
                raise _error(PublicErrorCode.SESSION_CONFLICT)
            current = matches[0]
            now = self._clock.now_utc()
            updated = replace(current, unbound_at=now)
            key = (
                project,
                current.membership_generation,
                current.member_kind,
                current.member_commitment_or_id,
            )
            self._state.memberships[key] = updated
            descriptor = self._state.projects.get(project)
            if descriptor is None:
                raise _error(PublicErrorCode.STORAGE_CORRUPT)
            self._state.projects[project] = replace(
                descriptor,
                membership_generation=max(descriptor.membership_generation, membership_generation)
                + 1,
            )
            self._state.revision += 1
            return updated

    async def record_coordination_grant(
        self,
        project_id: str,
        membership_generation: int,
        *,
        grant_state: GrantState,
        audit_ref: str,
    ) -> CoordinationGrant:
        try:
            project = validate_id(IdKind.PROJECT, project_id)
            if type(membership_generation) is not int or membership_generation <= 0:
                raise ValueError("membership_generation_invalid")
            if type(grant_state) is not GrantState:
                raise ValueError("grant_state_invalid")
            if type(audit_ref) is not str or not 1 <= len(audit_ref) <= 128:
                raise ValueError("grant_audit_ref_invalid")
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        async with self._lock:
            descriptor = self._state.projects.get(project)
            if descriptor is None:
                raise _error(PublicErrorCode.SESSION_NOT_FOUND)
            if (
                descriptor.dissolved_at is not None
                or membership_generation > descriptor.membership_generation
            ):
                raise _error(PublicErrorCode.SESSION_CONFLICT)
            key = (project, membership_generation)
            current = self._state.grants.get(key)
            now = self._clock.now_utc()
            if current is not None:
                if current.audit_record_id != audit_ref:
                    raise _error(PublicErrorCode.SESSION_CONFLICT)
                if current.state is grant_state:
                    return current
                if current.state is GrantState.REVOKED or grant_state is not GrantState.REVOKED:
                    raise _error(PublicErrorCode.SESSION_CONFLICT)
                updated = replace(current, state=GrantState.REVOKED, revoked_at=now)
                self._state.grants[key] = updated
                self._state.revision += 1
                return updated
            grant = CoordinationGrant(
                project_id=project,
                membership_generation=membership_generation,
                state=grant_state,
                audit_record_id=audit_ref,
                granted_at=now,
                revoked_at=now if grant_state is GrantState.REVOKED else None,
            )
            self._state.grants[key] = grant
            self._state.revision += 1
            return grant

    async def dissolve_project(self, project_id: str) -> ProjectDescriptor:
        try:
            project = validate_id(IdKind.PROJECT, project_id)
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        async with self._lock:
            descriptor = self._state.projects.get(project)
            if descriptor is None:
                raise _error(PublicErrorCode.SESSION_NOT_FOUND)
            if descriptor.dissolved_at is not None:
                return descriptor
            now = self._clock.now_utc()
            for key, membership in tuple(self._state.memberships.items()):
                if key[0] == project and membership.unbound_at is None:
                    self._state.memberships[key] = replace(membership, unbound_at=now)
            updated = replace(
                descriptor,
                membership_generation=descriptor.membership_generation + 1,
                dissolved_at=now,
            )
            self._state.projects[project] = updated
            self._state.revision += 1
            return updated

    async def advance_project_generation(
        self, project_id: str, *, reason: str, expected_generation: int | None = None
    ) -> ProjectDescriptor:
        try:
            project = validate_id(IdKind.PROJECT, project_id)
            if type(reason) is not str or not 1 <= len(reason) <= 128:
                raise ValueError("project_generation_reason_invalid")
            if any(
                character
                not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-"
                for character in reason
            ):
                raise ValueError("project_generation_reason_invalid")
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        async with self._lock:
            descriptor = self._state.projects.get(project)
            if descriptor is None:
                raise _error(PublicErrorCode.SESSION_NOT_FOUND)
            if expected_generation is not None:
                if type(expected_generation) is not int or expected_generation < 1:
                    raise _error(PublicErrorCode.INVALID_REQUEST)
                if descriptor.membership_generation < expected_generation:
                    raise _error(PublicErrorCode.SESSION_CONFLICT)
                if descriptor.membership_generation > expected_generation:
                    return descriptor
            updated = replace(
                descriptor,
                membership_generation=descriptor.membership_generation + 1,
            )
            self._state.projects[project] = updated
            self._state.revision += 1
            return updated

    async def set_project_auto_grouping(
        self, repository_commitment: str, *, enabled: bool
    ) -> ProjectDescriptor | None:
        try:
            validate_commitment(repository_commitment)
            if type(enabled) is not bool:
                raise ValueError("project_auto_grouping_invalid")
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        async with self._lock:
            matches = [
                project
                for project in self._state.projects.values()
                if project.kind is ProjectKind.REPOSITORY
                and project.repository_commitment == repository_commitment
            ]
            if len(matches) > 1:
                raise _error(PublicErrorCode.STORAGE_CORRUPT)
            if not matches:
                self._state.repository_grouping_preferences[repository_commitment] = enabled
                self._state.revision += 1
                return None
            current = matches[0]
            if current.dissolved_at is not None:
                raise _error(PublicErrorCode.SESSION_CONFLICT)
            self._state.repository_grouping_preferences[repository_commitment] = enabled
            if current.auto_grouping is enabled:
                return current
            updated = replace(
                current,
                auto_grouping=enabled,
                membership_generation=current.membership_generation + 1,
            )
            self._state.projects[current.project_id] = updated
            self._state.revision += 1
            return updated

    async def record_project_text_refs(
        self,
        project_id: str,
        *,
        title_ref: ProjectTextRef | None,
        description_ref: ProjectTextRef | None,
    ) -> ProjectDescriptor:
        try:
            project = validate_id(IdKind.PROJECT, project_id)
            if title_ref is not None and type(title_ref) is not ProjectTextRef:
                raise ValueError("project_title_ref_invalid")
            if description_ref is not None and type(description_ref) is not ProjectTextRef:
                raise ValueError("project_description_ref_invalid")
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        async with self._lock:
            current = self._state.projects.get(project)
            if current is None:
                raise _error(PublicErrorCode.SESSION_NOT_FOUND)
            updated = replace(current, title_ref=title_ref, description_ref=description_ref)
            self._state.projects[project] = updated
            self._state.revision += 1
            return updated

    async def amend_project(
        self,
        project_id: str,
        *,
        title_ref: ProjectTextRef | None,
        description_ref: ProjectTextRef | None,
    ) -> ProjectDescriptor:
        return await self.record_project_text_refs(
            project_id, title_ref=title_ref, description_ref=description_ref
        )

    async def bind_repository_privacy(
        self,
        task_id: str,
        route_identity_digest: str,
        repository_privacy_commitment: str,
    ) -> TaskRoute:
        try:
            task = validate_id(IdKind.TASK, task_id)
            validate_sha256_digest(route_identity_digest)
            validate_commitment(repository_privacy_commitment)
        except (TypeError, ValueError) as exc:
            raise _error(PublicErrorCode.INVALID_REQUEST) from exc
        async with self._lock:
            record = self._state.routes.get(task)
            if record is None:
                raise _error(PublicErrorCode.SESSION_NOT_FOUND)
            if record.route_identity_digest != route_identity_digest:
                raise _error(PublicErrorCode.SESSION_CONFLICT)
            if record.repository_privacy_commitment not in {
                None,
                repository_privacy_commitment,
            }:
                raise _error(PublicErrorCode.SESSION_CONFLICT)
            if record.repository_privacy_commitment is None:
                if self._provenance_spans_general_projects(
                    task,
                    repository_privacy_commitment,
                    record.workspace_ref_commitment,
                ):
                    raise _error(
                        PublicErrorCode.SESSION_CONFLICT,
                        safe_details={"reason_code": "general_project_membership_conflict"},
                    )
                record = replace(
                    record,
                    repository_privacy_commitment=repository_privacy_commitment,
                    updated_at=self._clock.now_utc(),
                )
                self._state.routes[task] = record
                self._state.revision += 1
        return _route_value(record)

    async def lookup(self, key: PublishResponseKey) -> StoredPublishResponse | None:
        if type(key) is not PublishResponseKey:
            raise _error(PublicErrorCode.INVALID_REQUEST)
        identity = (key.writer_id, key.request_id, key.sink)
        async with self._lock:
            existing = self._state.publish_responses.get(identity)
            if existing is None:
                return None
            if type(existing) is not StoredPublishResponse or existing.key != key:
                raise _error(PublicErrorCode.STORAGE_CORRUPT)
            return existing

    async def put_if_absent(self, value: StoredPublishResponse) -> StoredPublishResponse:
        if type(value) is not StoredPublishResponse:
            raise _error(PublicErrorCode.INVALID_REQUEST)
        key = value.key
        identity = (key.writer_id, key.request_id, key.sink)
        async with self._lock:
            existing = self._state.publish_responses.get(identity)
            if existing is None:
                self._state.publish_responses[identity] = value
                self._state.revision += 1
                return value
            if type(existing) is not StoredPublishResponse or existing.key != key:
                raise _error(PublicErrorCode.STORAGE_CORRUPT)
            return existing

    async def reserve_or_resume(self, request: StartCommand) -> StartAllocation:
        if type(request) is not StartCommand:
            raise _error(PublicErrorCode.INVALID_REQUEST)
        recomputed = await self.commit_identity(request.identity_input)
        if not self._commitments_match(recomputed, request.identity_commitments):
            raise _error(PublicErrorCode.INVALID_REQUEST)
        now = self._clock.now_utc()
        format_rfc3339_millis(now)
        proposed = {
            IdKind.TASK: self._ids.new(IdKind.TASK),
            IdKind.SESSION: self._ids.new(IdKind.SESSION),
            IdKind.WRITER: self._ids.new(IdKind.WRITER),
            IdKind.EVENT: self._ids.new(IdKind.EVENT),
        }
        for kind, candidate in proposed.items():
            validate_id(kind, candidate)
        async with self._lock:
            key = (self._installation_id, request.operation_id)
            existing = self._state.operations.get(key)
            if existing is not None:
                return self._resume_existing(existing, request, now)

            route = self._resolve_requested_route(request)
            if route is not None and route.state is TaskRouteState.QUARANTINED:
                raise _error(PublicErrorCode.STORAGE_CORRUPT)
            if request.mode is StartMode.CREATE and route is not None:
                raise _error(
                    PublicErrorCode.SESSION_CONFLICT,
                    safe_details={
                        "reason_code": (
                            "workspace_task_exists"
                            if request.identity_commitments.workspace_ref_commitment is not None
                            and request.identity_commitments.external_ref_commitment is not None
                            else "selector_conflict"
                        )
                    },
                )
            if request.mode is StartMode.ATTACH and route is None:
                raise _error(PublicErrorCode.SESSION_NOT_FOUND)
            if route is not None and route.work_state is not WorkState.OPEN:
                # Mirrors the SQLite catalog: terminal work is refused before any reservation.
                raise _error(
                    PublicErrorCode.SESSION_CONFLICT,
                    safe_details={"reason_code": "lineage_resume_work_terminal"},
                )
            if route is not None:
                expected = route.repository_privacy_commitment
                actual = request.repository_privacy_commitment
                if expected is not None and (
                    actual is None or not hmac.compare_digest(expected, actual)
                ):
                    raise _error(
                        PublicErrorCode.SESSION_CONFLICT,
                        safe_details={
                            "reason_code": (
                                "repository_identity_required"
                                if actual is None
                                else "repository_identity_mismatch"
                            )
                        },
                    )
                if expected is None and actual is not None:
                    if self._provenance_spans_general_projects(
                        route.task_id,
                        actual,
                        route.workspace_ref_commitment,
                    ):
                        raise _error(
                            PublicErrorCode.SESSION_CONFLICT,
                            safe_details={"reason_code": "general_project_membership_conflict"},
                        )
                    route = replace(
                        route,
                        repository_privacy_commitment=actual,
                        updated_at=now,
                    )
                    self._state.routes[route.task_id] = route
                    self._state.revision += 1

            created = route is None
            if created:
                task_id = proposed[IdKind.TASK]
                session_id = proposed[IdKind.SESSION]
                bundle_relpath = f"tasks/{task_id}"
                route_digest = canonical_digest(
                    {
                        "bundle_relpath": bundle_relpath,
                        "route_generation": 1,
                        "task_id": task_id,
                    }
                )
                route = _RouteRecord(
                    task_id=task_id,
                    workspace_ref_commitment=request.identity_commitments.workspace_ref_commitment,
                    external_ref_commitment=request.identity_commitments.external_ref_commitment,
                    active_session_id=session_id,
                    bundle_relpath=bundle_relpath,
                    route_generation=1,
                    route_identity_digest=route_digest,
                    state=TaskRouteState.INITIALIZING,
                    quarantine_code=None,
                    created_at=now,
                    updated_at=now,
                    repository_privacy_commitment=request.repository_privacy_commitment,
                )
                if self._provenance_spans_general_projects(
                    route.task_id,
                    route.repository_privacy_commitment,
                    route.workspace_ref_commitment,
                ):
                    raise _error(
                        PublicErrorCode.SESSION_CONFLICT,
                        safe_details={"reason_code": "general_project_membership_conflict"},
                    )
                self._install_route(route)
                self._state.session_states[session_id] = SessionState(
                    task_id=task_id,
                    session_id=session_id,
                    health=SessionHealth.ACTIVE,
                    changed_at=now,
                    lease_expires_at=now + timedelta(seconds=self._policy.lease_seconds),
                )
            else:
                session_id = proposed[IdKind.SESSION]
                self._state.session_states[session_id] = SessionState(
                    task_id=route.task_id,
                    session_id=session_id,
                    health=SessionHealth.ACTIVE,
                    changed_at=now,
                    lease_expires_at=now + timedelta(seconds=self._policy.lease_seconds),
                )

            expires = now + timedelta(seconds=self._policy.lease_seconds)
            record = _OperationRecord(
                installation_id=self._installation_id,
                operation_id=request.operation_id,
                request_digest=request.request_digest,
                requested_mode=request.mode,
                route_action="created" if created else "attached",
                state=_OperationState.PENDING,
                phase=StartPhase.ROUTE_RESERVED,
                task_id=route.task_id,
                session_id=session_id,
                writer_id=proposed[IdKind.WRITER],
                lifecycle_event_id=proposed[IdKind.EVENT],
                route_generation=route.route_generation,
                route_identity_digest=route.route_identity_digest,
                owner_generation=self._state.owner_generation,
                lease_owner_id=self._lease_owner_id,
                lease_generation=1,
                lease_expires_at=expires,
                response_object_id=None,
                response_envelope_digest=None,
                terminal_result_canonical=None,
                terminal_result_digest=None,
                quarantine_code=None,
                terminal_at=None,
                created_at=now,
                updated_at=now,
            )
            self._state.operations[key] = record
            self._state.revision += 1
            return _allocation(record, "reserved")

    async def yield_lease(self, allocation: StartAllocation) -> None:
        if type(allocation) is not StartAllocation:
            raise _error(PublicErrorCode.INVALID_REQUEST)
        now = self._clock.now_utc()
        # Validate the same timestamp representation the SQLite adapter persists.
        format_rfc3339_millis(now)
        async with self._lock:
            key, record = self._operation_for(allocation)
            self._require_lease(record, allocation, now)
            self._state.operations[key] = replace(record, lease_expires_at=now, updated_at=now)
            self._state.revision += 1

    async def advance_phase(
        self,
        allocation: StartAllocation,
        phase: StartPhase,
        result: EncryptedResultRef | None = None,
    ) -> StartAllocation:
        if type(allocation) is not StartAllocation or type(phase) is not StartPhase:
            raise _error(PublicErrorCode.INVALID_REQUEST)
        if phase is StartPhase.RESULT_PUBLISHED:
            if type(result) is not EncryptedResultRef:
                raise _error(PublicErrorCode.INTERNAL_ERROR)
        elif result is not None:
            raise _error(PublicErrorCode.INTERNAL_ERROR)
        now = self._clock.now_utc()
        format_rfc3339_millis(now)
        async with self._lock:
            key, record = self._operation_for(allocation)
            self._require_lease(record, allocation, now)
            if record.phase is phase:
                if result is not None and (
                    record.response_object_id != result.response_object_id
                    or record.response_envelope_digest != result.envelope_digest
                    or record.terminal_result_canonical != result.result_canonical
                    or record.terminal_result_digest != result.result_digest
                ):
                    raise _error(PublicErrorCode.INTERNAL_ERROR)
                return _allocation(record, allocation.outcome)
            if _PHASE_SUCCESSOR.get(record.phase) is not phase:
                raise _error(PublicErrorCode.INTERNAL_ERROR)
            updated = replace(
                record,
                phase=phase,
                response_object_id=(result.response_object_id if result is not None else None),
                response_envelope_digest=(result.envelope_digest if result is not None else None),
                terminal_result_canonical=(result.result_canonical if result is not None else None),
                terminal_result_digest=(result.result_digest if result is not None else None),
                updated_at=now,
            )
            self._state.operations[key] = updated
            self._state.revision += 1
            return _allocation(updated, allocation.outcome)

    async def complete(
        self,
        allocation: StartAllocation,
        result: EncryptedResultRef,
        evidence: StartCompletionEvidence,
    ) -> None:
        if (
            type(allocation) is not StartAllocation
            or type(result) is not EncryptedResultRef
            or type(evidence) is not StartCompletionEvidence
        ):
            raise _error(PublicErrorCode.INVALID_REQUEST)
        now = self._clock.now_utc()
        format_rfc3339_millis(now)
        async with self._lock:
            key, record = self._operation_for(allocation)
            self._require_lease(record, allocation, now)
            if record.phase is not StartPhase.RESULT_PUBLISHED:
                raise _error(PublicErrorCode.INTERNAL_ERROR)
            if (
                record.response_object_id != result.response_object_id
                or record.response_envelope_digest != result.envelope_digest
                or record.terminal_result_canonical != result.result_canonical
                or record.terminal_result_digest != result.result_digest
            ):
                raise _error(PublicErrorCode.INTERNAL_ERROR)
            _validate_completion_evidence(record, result, evidence)
            route = self._require_current_route(record)
            completed = replace(
                record,
                state=_OperationState.COMPLETE,
                phase=StartPhase.TERMINAL,
                owner_generation=None,
                lease_owner_id=None,
                lease_generation=None,
                lease_expires_at=None,
                terminal_result_canonical=result.result_canonical,
                terminal_result_digest=result.result_digest,
                terminal_at=now,
                updated_at=now,
            )
            self._state.operations[key] = completed
            self._activate_route(route, record.session_id, now)
            self._state.revision += 1

    async def quarantine(self, allocation: StartAllocation, reason: SafeReason) -> None:
        if type(allocation) is not StartAllocation or type(reason) is not SafeReason:
            raise _error(PublicErrorCode.INVALID_REQUEST)
        now = self._clock.now_utc()
        format_rfc3339_millis(now)
        async with self._lock:
            key, record = self._operation_for(allocation)
            self._require_lease(record, allocation, now)
            route = self._require_current_route(record)
            terminal = _quarantine_envelope(record, reason)
            quarantined = replace(
                record,
                state=_OperationState.QUARANTINED,
                phase=StartPhase.TERMINAL,
                owner_generation=None,
                lease_owner_id=None,
                lease_generation=None,
                lease_expires_at=None,
                terminal_result_canonical=terminal,
                terminal_result_digest=f"sha256:{hashlib.sha256(terminal).hexdigest()}",
                quarantine_code=reason.code,
                terminal_at=now,
                updated_at=now,
            )
            self._state.operations[key] = quarantined
            if record.route_action == "created" and route.state is TaskRouteState.INITIALIZING:
                self._state.routes[route.task_id] = replace(
                    route,
                    state=TaskRouteState.QUARANTINED,
                    quarantine_code=reason.code,
                    updated_at=now,
                )
            self._state.revision += 1

    @staticmethod
    def _commitments_match(
        actual: StartIdentityCommitments,
        expected: StartIdentityCommitments,
    ) -> bool:
        pairs = (
            (actual.title_commitment, expected.title_commitment),
            (actual.workspace_ref_commitment, expected.workspace_ref_commitment),
            (actual.external_ref_commitment, expected.external_ref_commitment),
        )
        return all(
            left is None
            and right is None
            or left is not None
            and right is not None
            and hmac.compare_digest(left, right)
            for left, right in pairs
        )

    def _resolve_requested_route(self, request: StartCommand) -> _RouteRecord | None:
        # The lineage coordinator supplies this selector only after validating a handle or parent
        # relationship.  Pair/workspace membership must never discover a route on that path.
        if request.target_task_id is not None:
            target = validate_id(IdKind.TASK, request.target_task_id)
            route = self._state.routes.get(target)
            if route is None:
                raise _error(PublicErrorCode.SESSION_NOT_FOUND)
            if request.session_id is not None and route.active_session_id != request.session_id:
                raise _error(
                    PublicErrorCode.SESSION_CONFLICT,
                    safe_details={"reason_code": "selector_conflict"},
                )
            return route
        by_commitment: _RouteRecord | None = None
        workspace = request.identity_commitments.workspace_ref_commitment
        external = request.identity_commitments.external_ref_commitment
        if workspace is not None and external is not None:
            task_id = self._state.attachment_index.get((workspace, external))
            if task_id is not None:
                by_commitment = self._state.routes.get(task_id)
                if by_commitment is None:
                    raise _error(PublicErrorCode.STORAGE_CORRUPT)
        by_session: _RouteRecord | None = None
        if request.session_id is not None:
            task_id = self._state.session_index.get(request.session_id)
            if task_id is None:
                task_id = self._state.historical_session_index.get(request.session_id)
            if task_id is None:
                task_id = self._task_id_for_operation_session(request.session_id)
            if task_id is not None:
                by_session = self._state.routes.get(task_id)
                if by_session is None:
                    raise _error(PublicErrorCode.STORAGE_CORRUPT)
        if by_commitment is not None and by_session is not None:
            if by_commitment.task_id != by_session.task_id:
                raise _error(
                    PublicErrorCode.SESSION_CONFLICT,
                    safe_details={"reason_code": "selector_conflict"},
                )
            return by_commitment
        if by_session is not None and workspace is not None and by_commitment is None:
            workspace_routes = tuple(
                route
                for route in self._state.routes.values()
                if route.workspace_ref_commitment == workspace
                and route.parent_task_id is None
                and route.state is not TaskRouteState.QUARANTINED
            )
            if (
                request.mode is not StartMode.ATTACH
                or request.session_id != by_session.active_session_id
                or by_session.state is TaskRouteState.QUARANTINED
                or by_session.workspace_ref_commitment is None
                or not hmac.compare_digest(by_session.workspace_ref_commitment, workspace)
                or not any(route.task_id == by_session.task_id for route in workspace_routes)
            ):
                raise _error(
                    PublicErrorCode.SESSION_CONFLICT,
                    safe_details={"reason_code": "selector_conflict"},
                )
            if any(
                operation.task_id == by_session.task_id
                and operation.state is _OperationState.PENDING
                for operation in self._state.operations.values()
            ):
                # One route rotation at a time. The pending operation owns recovery
                # through its own request id and lease; a second rotation must not
                # reserve against the same predecessor session. Scoped to this
                # recovery admission so an abandoned pending operation never wedges
                # the ordinary same-pair attach that still self-heals the route.
                raise _error(PublicErrorCode.OPERATION_PENDING, retryable=True)
            return by_session
        if request.session_id is not None and (by_session is None and by_commitment is not None):
            raise _error(
                PublicErrorCode.SESSION_CONFLICT,
                safe_details={"reason_code": "selector_conflict"},
            )
        return by_commitment or by_session

    def _resume_existing(
        self,
        record: _OperationRecord,
        request: StartCommand,
        now: datetime,
    ) -> StartAllocation:
        if not hmac.compare_digest(record.request_digest, request.request_digest):
            raise _error(PublicErrorCode.IDEMPOTENCY_CONFLICT)
        if record.state is not _OperationState.PENDING:
            if record.terminal_result_canonical is None:
                raise _error(PublicErrorCode.STORAGE_CORRUPT)
            return _allocation(record, "replayed")
        if (
            record.owner_generation == self._state.owner_generation
            and record.lease_expires_at is not None
            and record.lease_expires_at > now
        ):
            raise _error(
                PublicErrorCode.OPERATION_PENDING,
                retryable=True,
                safe_details={"reason_code": "start_lease_pending"},
            )
        if record.lease_generation is None:
            raise _error(PublicErrorCode.STORAGE_CORRUPT)
        reclaimed = replace(
            record,
            owner_generation=self._state.owner_generation,
            lease_owner_id=self._lease_owner_id,
            lease_generation=record.lease_generation + 1,
            lease_expires_at=now + timedelta(seconds=self._policy.lease_seconds),
            updated_at=now,
        )
        self._state.operations[(record.installation_id, record.operation_id)] = reclaimed
        self._state.revision += 1
        return _allocation(reclaimed, "resumed")

    def _install_route(self, route: _RouteRecord) -> None:
        if (
            route.task_id in self._state.routes
            or route.active_session_id in self._state.session_index
        ):
            raise _error(PublicErrorCode.STORAGE_CORRUPT)
        pair: tuple[str, str] | None = None
        if route.workspace_ref_commitment is not None and route.external_ref_commitment is not None:
            pair = (route.workspace_ref_commitment, route.external_ref_commitment)
            if pair in self._state.attachment_index:
                raise _error(PublicErrorCode.SESSION_CONFLICT)
        self._state.routes[route.task_id] = route
        self._state.session_index[route.active_session_id] = route.task_id
        if pair is not None:
            self._state.attachment_index[pair] = route.task_id

    def _operation_for(
        self, allocation: StartAllocation
    ) -> tuple[tuple[str, str], _OperationRecord]:
        matches = [
            (key, record)
            for key, record in self._state.operations.items()
            if _same_allocation(record, allocation)
        ]
        if len(matches) != 1:
            raise _error(PublicErrorCode.STORAGE_CORRUPT)
        return matches[0]

    def _require_lease(
        self,
        record: _OperationRecord,
        allocation: StartAllocation,
        now: datetime,
    ) -> None:
        supplied = allocation.lease
        if (
            record.state is not _OperationState.PENDING
            or supplied is None
            or record.owner_generation != self._state.owner_generation
            or record.owner_generation != supplied.owner_generation
            or record.lease_owner_id != supplied.lease_owner_id
            or record.lease_generation != supplied.lease_generation
            or record.lease_expires_at != supplied.lease_expires_at
            or record.lease_expires_at is None
            or record.lease_expires_at <= now
        ):
            raise _error(PublicErrorCode.OPERATION_PENDING, retryable=True)

    def _require_current_route(self, record: _OperationRecord) -> _RouteRecord:
        route = self._state.routes.get(record.task_id)
        if (
            route is None
            or route.route_generation != record.route_generation
            or not hmac.compare_digest(route.route_identity_digest, record.route_identity_digest)
            or route.bundle_relpath != f"tasks/{record.task_id}"
        ):
            raise _error(PublicErrorCode.STORAGE_CORRUPT)
        return route

    def _activate_route(self, route: _RouteRecord, session_id: str, now: datetime) -> None:
        old_session = route.active_session_id
        existing = self._state.session_index.get(session_id)
        if existing is not None and existing != route.task_id:
            raise _error(PublicErrorCode.STORAGE_CORRUPT)
        if self._state.session_index.get(old_session) != route.task_id:
            raise _error(PublicErrorCode.STORAGE_CORRUPT)
        if old_session != session_id:
            del self._state.session_index[old_session]
            self._state.historical_session_index[old_session] = route.task_id
        self._state.session_index[session_id] = route.task_id
        self._state.routes[route.task_id] = replace(
            route,
            active_session_id=session_id,
            state=TaskRouteState.ACTIVE,
            quarantine_code=None,
            updated_at=now,
        )
        for state_id, state in tuple(self._state.session_states.items()):
            if (
                state.task_id == route.task_id
                and state_id != session_id
                and state.health is not SessionHealth.ENDED
            ):
                self._state.session_states[state_id] = replace(
                    state,
                    health=SessionHealth.ENDED,
                    changed_at=now,
                    lease_expires_at=None,
                )
        current = self._state.session_states.get(session_id)
        if current is None:
            self._state.session_states[session_id] = SessionState(
                task_id=route.task_id,
                session_id=session_id,
                health=SessionHealth.ACTIVE,
                changed_at=now,
                lease_expires_at=now + timedelta(seconds=self._policy.lease_seconds),
            )
        else:
            self._state.session_states[session_id] = replace(
                current,
                health=SessionHealth.ACTIVE,
                changed_at=now,
                lease_expires_at=now + timedelta(seconds=self._policy.lease_seconds),
            )

    def _task_id_for_operation_session(self, session_id: str) -> str | None:
        matches = [
            record.task_id
            for record in self._state.operations.values()
            if record.session_id == session_id
        ]
        if len(matches) > 1:
            raise _error(PublicErrorCode.STORAGE_CORRUPT)
        return None if not matches else matches[0]

    def _writer_for_session(self, session_id: str) -> str | None:
        matches = [
            record.writer_id
            for record in self._state.operations.values()
            if record.session_id == session_id
        ]
        if len(matches) > 1:
            raise _error(PublicErrorCode.STORAGE_CORRUPT)
        return None if not matches else matches[0]

    def _binding_for_task(self, task_id: str) -> SessionBinding | None:
        route = self._state.routes.get(task_id)
        if route is None or route.state is TaskRouteState.QUARANTINED:
            return None
        writer_id = self._writer_for_session(route.active_session_id)
        if writer_id is None:
            return None
        try:
            return SessionBinding(route.task_id, route.active_session_id, writer_id)
        except ValueError as exc:
            raise _error(PublicErrorCode.STORAGE_CORRUPT) from exc
