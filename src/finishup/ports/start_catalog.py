"""Pre-writer start allocation, routing, and idempotency boundary."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Final, Literal, Protocol

from finishup.domain.coordination import (
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
)
from finishup.domain.values import (
    format_rfc3339_millis,
    validate_commitment,
    validate_sha256_digest,
)
from finishup.ports.runtime import StartCompletionEvidence
from finishup.protocol.canonical import canonical_digest, ensure_canonical_value
from finishup.protocol.ids import IdKind, validate_actor_id, validate_id

__all__ = [
    "EXTERNAL_REF_DOMAIN",
    "START_TITLE_DOMAIN",
    "WORKSPACE_REF_DOMAIN",
    "EncryptedResultRef",
    "CoordinationGrant",
    "CoordinationGrantState",
    "LineageAcceptance",
    "LineageOrigin",
    "MemberKind",
    "ProjectDescriptor",
    "ProjectKind",
    "ProjectMembership",
    "ProjectTextRef",
    "ProjectMemberKind",
    "ProjectState",
    "SafeReason",
    "SessionHealth",
    "SessionBinding",
    "SessionState",
    "StartAllocation",
    "StartCatalogPort",
    "StartCommand",
    "StartIdentityCommitments",
    "StartIdentityInput",
    "StartMode",
    "StartOperationLease",
    "StartPhase",
    "TaskRoute",
    "TaskLineage",
    "TaskSourceProvenance",
    "TaskRouteState",
    "WorkState",
]

# Compatibility spellings used by the lifecycle and coordination application lanes.  The domain
# module owns the durable enum vocabulary; the aliases keep this port's contract independent of
# the wire/Pydantic enum definitions.
ProjectState = ProjectDescriptor
ProjectMemberKind = MemberKind
CoordinationGrantState = GrantState

START_TITLE_DOMAIN: Final = b"yoetz/start-title/v1\x00"
WORKSPACE_REF_DOMAIN: Final = b"yoetz/workspace-ref/v1\x00"
EXTERNAL_REF_DOMAIN: Final = b"yoetz/external-task-ref/v1\x00"

_MAX_SAFE_INTEGER: Final = 2**53 - 1
_SAFE_TOKEN_PATTERN: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", re.ASCII)
_START_QUARANTINE_CODES: Final = frozenset(
    {
        "start_allocation_ambiguous",
        "start_bundle_invalid",
        "start_catalog_integrity",
        "start_lifecycle_contradiction",
        "start_result_object_missing",
        "start_route_contradiction",
    }
)


class TaskRouteState(str, Enum):  # noqa: UP042 - exact durable enum base
    INITIALIZING = "initializing"
    ACTIVE = "active"
    QUARANTINED = "quarantined"


class StartPhase(str, Enum):  # noqa: UP042 - exact durable enum base
    ROUTE_RESERVED = "route_reserved"
    BUNDLE_READY = "bundle_ready"
    LIFECYCLE_COMMITTED = "lifecycle_committed"
    RESULT_PUBLISHED = "result_published"
    TERMINAL = "terminal"


class StartMode(str, Enum):  # noqa: UP042 - exact request enum base
    CREATE = "create"
    ATTACH = "attach"
    CREATE_OR_ATTACH = "create_or_attach"
    DELEGATE = "delegate"


def _invalid() -> ValueError:
    return ValueError("invalid_start_catalog_value")


def _id(kind: IdKind, value: object) -> str:
    try:
        return validate_id(kind, value)
    except ValueError as exc:
        raise _invalid() from exc


def _safe_token(value: object) -> str:
    if type(value) is not str or _SAFE_TOKEN_PATTERN.fullmatch(value) is None:
        raise _invalid()
    return value


def _optional_identity(value: object) -> str | None:
    if value is None:
        return None
    if type(value) is not str or not 1 <= len(value.encode("utf-8")) <= 8_192:
        raise _invalid()
    try:
        ensure_canonical_value(value)
    except ValueError as exc:
        raise _invalid() from exc
    return value


@dataclass(frozen=True, slots=True, repr=False)
class StartIdentityInput:
    task_title: str = field(repr=False)
    workspace_ref: str | None = field(default=None, repr=False)
    external_ref: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        title = _optional_identity(self.task_title)
        if title is None:
            raise _invalid()
        workspace = _optional_identity(self.workspace_ref)
        external = _optional_identity(self.external_ref)
        if (workspace is None) != (external is None):
            raise _invalid()

    def __repr__(self) -> str:
        return "StartIdentityInput(<redacted>)"


@dataclass(frozen=True, slots=True)
class StartIdentityCommitments:
    title_commitment: str
    workspace_ref_commitment: str | None
    external_ref_commitment: str | None

    def __post_init__(self) -> None:
        try:
            validate_commitment(self.title_commitment)
            if self.workspace_ref_commitment is not None:
                validate_commitment(self.workspace_ref_commitment)
            if self.external_ref_commitment is not None:
                validate_commitment(self.external_ref_commitment)
        except ValueError as exc:
            raise _invalid() from exc
        if (self.workspace_ref_commitment is None) != (self.external_ref_commitment is None):
            raise _invalid()


@dataclass(frozen=True, slots=True)
class StartCommand:
    operation_id: str
    request_digest: str
    mode: StartMode
    identity_input: StartIdentityInput
    identity_commitments: StartIdentityCommitments
    session_id: str | None = None
    repository_privacy_commitment: str | None = None
    parent_session_id: str | None = None
    attach_handle: str | None = None
    # Internal, service-derived route selector used after a lineage capability has been
    # authenticated.  It never crosses the public start request boundary and is not part of
    # request identity; the catalog still checks the operation digest before using it.
    target_task_id: str | None = None

    def __post_init__(self) -> None:
        _id(IdKind.REQUEST, self.operation_id)
        try:
            validate_sha256_digest(self.request_digest)
        except ValueError as exc:
            raise _invalid() from exc
        if (
            type(self.mode) is not StartMode
            or type(self.identity_input) is not StartIdentityInput
            or type(self.identity_commitments) is not StartIdentityCommitments
        ):
            raise _invalid()
        if self.session_id is not None:
            _id(IdKind.SESSION, self.session_id)
        if self.parent_session_id is not None:
            _id(IdKind.SESSION, self.parent_session_id)
        if self.attach_handle is not None:
            _safe_token(self.attach_handle)
        if self.target_task_id is not None:
            _id(IdKind.TASK, self.target_task_id)
        if self.repository_privacy_commitment is not None:
            try:
                validate_commitment(self.repository_privacy_commitment)
            except ValueError as exc:
                raise _invalid() from exc
        input_has_refs = self.identity_input.workspace_ref is not None
        commitments_have_refs = self.identity_commitments.workspace_ref_commitment is not None
        if input_has_refs != commitments_have_refs:
            raise _invalid()
        if self.mode is StartMode.ATTACH and not input_has_refs and self.session_id is None:
            raise _invalid()
        if self.mode is StartMode.DELEGATE and self.parent_session_id is None:
            raise _invalid()
        if self.attach_handle is not None and self.mode is not StartMode.ATTACH:
            raise _invalid()
        if self.target_task_id is not None and self.mode is not StartMode.ATTACH:
            raise _invalid()


@dataclass(frozen=True, slots=True, repr=False)
class TaskLineage:
    """Catalog-owned lineage and work facts for one task.

    A route remains the owner of its bundle and routing identity. This value carries only the
    structural relationship and lifecycle facts needed to coordinate tasks; it contains no title,
    description, path, or ledger prose.
    """

    task_id: str
    parent_task_id: str | None
    depth: int
    lineage_digest: str
    origin: LineageOrigin | None
    acceptance: LineageAcceptance | None
    work_state: WorkState

    def __post_init__(self) -> None:
        task = _id(IdKind.TASK, self.task_id)
        if self.parent_task_id is None:
            if self.depth != 0 or self.origin is not None or self.acceptance is not None:
                raise _invalid()
        else:
            parent = _id(IdKind.TASK, self.parent_task_id)
            if (
                parent == task
                or type(self.depth) is not int
                or not 1 <= self.depth <= _MAX_SAFE_INTEGER
            ):
                raise _invalid()
            if (
                type(self.origin) is not LineageOrigin
                or type(self.acceptance) is not LineageAcceptance
            ):
                raise _invalid()
        if type(self.depth) is not int or not 0 <= self.depth <= _MAX_SAFE_INTEGER:
            raise _invalid()
        try:
            validate_sha256_digest(self.lineage_digest)
        except ValueError as exc:
            raise _invalid() from exc
        if type(self.work_state) is not WorkState:
            raise _invalid()

    def __repr__(self) -> str:
        return "TaskLineage(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class TaskSourceProvenance:
    """Structural source and route facts used when a task is selected for a read."""

    task_id: str
    workspace_ref_commitment: str | None
    external_ref_commitment: str | None
    repository_privacy_commitment: str | None
    route_generation: int
    route_identity_digest: str

    def __post_init__(self) -> None:
        _id(IdKind.TASK, self.task_id)
        if (self.workspace_ref_commitment is None) != (self.external_ref_commitment is None):
            raise _invalid()
        try:
            if self.workspace_ref_commitment is not None:
                validate_commitment(self.workspace_ref_commitment)
            if self.external_ref_commitment is not None:
                validate_commitment(self.external_ref_commitment)
            if self.repository_privacy_commitment is not None:
                validate_commitment(self.repository_privacy_commitment)
            validate_sha256_digest(self.route_identity_digest)
        except ValueError as exc:
            raise _invalid() from exc
        if (
            type(self.route_generation) is not int
            or not 1 <= self.route_generation <= _MAX_SAFE_INTEGER
        ):
            raise _invalid()

    def __repr__(self) -> str:
        return "TaskSourceProvenance(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class SessionState:
    """Per-session liveness fact, kept separate from route and work state."""

    task_id: str
    session_id: str
    health: SessionHealth
    changed_at: datetime
    lease_expires_at: datetime | None = None
    actor_id: str | None = None

    def __post_init__(self) -> None:
        _id(IdKind.TASK, self.task_id)
        _id(IdKind.SESSION, self.session_id)
        if type(self.health) is not SessionHealth:
            raise _invalid()
        try:
            format_rfc3339_millis(self.changed_at)
            if self.lease_expires_at is not None:
                format_rfc3339_millis(self.lease_expires_at)
        except ValueError as exc:
            raise _invalid() from exc
        if self.health is SessionHealth.ACTIVE and self.lease_expires_at is not None:
            if self.lease_expires_at <= self.changed_at:
                raise _invalid()
        if self.actor_id is not None:
            try:
                validate_actor_id(self.actor_id)
            except (TypeError, ValueError) as exc:
                raise _invalid() from exc

    @property
    def updated_at(self) -> datetime:
        """Compatibility alias for callers that use the catalog column spelling."""

        return self.changed_at

    def __repr__(self) -> str:
        return "SessionState(<redacted>)"


@dataclass(frozen=True, slots=True)
class TaskRoute:
    task_id: str
    session_id: str
    bundle_relpath: str
    route_generation: int
    state: TaskRouteState
    route_identity_digest: str
    repository_privacy_commitment: str | None = None
    parent_task_id: str | None = None
    depth: int = 0
    lineage_digest: str | None = None
    origin: LineageOrigin | None = None
    acceptance: LineageAcceptance | None = None
    work_state: WorkState = WorkState.OPEN

    def __post_init__(self) -> None:
        task = _id(IdKind.TASK, self.task_id)
        _id(IdKind.SESSION, self.session_id)
        if type(self.bundle_relpath) is not str or self.bundle_relpath != f"tasks/{task}":
            raise _invalid()
        if (
            type(self.route_generation) is not int
            or not 1 <= self.route_generation <= _MAX_SAFE_INTEGER
        ):
            raise _invalid()
        if type(self.state) is not TaskRouteState:
            raise _invalid()
        expected = canonical_digest(
            {
                "task_id": task,
                "bundle_relpath": self.bundle_relpath,
                "route_generation": self.route_generation,
            }
        )
        if self.route_identity_digest != expected:
            raise _invalid()
        if self.parent_task_id is None:
            if self.depth != 0 or self.origin is not None or self.acceptance is not None:
                raise _invalid()
        else:
            parent = _id(IdKind.TASK, self.parent_task_id)
            if (
                parent == task
                or type(self.depth) is not int
                or not 1 <= self.depth <= _MAX_SAFE_INTEGER
            ):
                raise _invalid()
            if (
                type(self.origin) is not LineageOrigin
                or type(self.acceptance) is not LineageAcceptance
            ):
                raise _invalid()
        if type(self.depth) is not int or not 0 <= self.depth <= _MAX_SAFE_INTEGER:
            raise _invalid()
        lineage = self.lineage_digest
        if lineage is None:
            lineage = self.route_identity_digest
            object.__setattr__(self, "lineage_digest", lineage)
        try:
            validate_sha256_digest(lineage)
        except ValueError as exc:
            raise _invalid() from exc
        if type(self.work_state) is not WorkState:
            raise _invalid()
        if self.repository_privacy_commitment is not None:
            try:
                validate_commitment(self.repository_privacy_commitment)
            except ValueError as exc:
                raise _invalid() from exc


@dataclass(frozen=True, slots=True)
class SessionBinding:
    """Active session/writer binding for one task, used as an attach repair selector."""

    task_id: str
    session_id: str
    writer_id: str

    def __post_init__(self) -> None:
        _id(IdKind.TASK, self.task_id)
        _id(IdKind.SESSION, self.session_id)
        _id(IdKind.WRITER, self.writer_id)


@dataclass(frozen=True, slots=True)
class StartOperationLease:
    """Catalog-start lease; distinct from the check-specific ledger lease."""

    owner_generation: int
    lease_owner_id: str
    lease_generation: int
    lease_expires_at: datetime

    def __post_init__(self) -> None:
        if (
            type(self.owner_generation) is not int
            or not 1 <= self.owner_generation <= _MAX_SAFE_INTEGER
        ):
            raise _invalid()
        _safe_token(self.lease_owner_id)
        if (
            type(self.lease_generation) is not int
            or not 1 <= self.lease_generation <= _MAX_SAFE_INTEGER
        ):
            raise _invalid()
        try:
            format_rfc3339_millis(self.lease_expires_at)
        except ValueError as exc:
            raise _invalid() from exc


@dataclass(frozen=True, slots=True)
class StartAllocation:
    outcome: Literal["reserved", "resumed", "replayed"]
    route_action: Literal["created", "attached"]
    task_id: str
    session_id: str
    writer_id: str
    lifecycle_event_id: str
    bundle_relpath: str
    route_generation: int
    route_identity_digest: str
    phase: StartPhase
    response_object_id: str | None
    response_envelope_digest: str | None
    response_result_canonical: bytes | None
    response_result_digest: str | None
    lease: StartOperationLease | None
    replayed_result: bytes | None
    attach_handle: str | None = None

    def __post_init__(self) -> None:
        if self.outcome not in {"reserved", "resumed", "replayed"}:
            raise _invalid()
        if self.route_action not in {"created", "attached"}:
            raise _invalid()
        task = _id(IdKind.TASK, self.task_id)
        _id(IdKind.SESSION, self.session_id)
        _id(IdKind.WRITER, self.writer_id)
        _id(IdKind.EVENT, self.lifecycle_event_id)
        if type(self.bundle_relpath) is not str or self.bundle_relpath != f"tasks/{task}":
            raise _invalid()
        if (
            type(self.route_generation) is not int
            or not 1 <= self.route_generation <= _MAX_SAFE_INTEGER
        ):
            raise _invalid()
        try:
            validate_sha256_digest(self.route_identity_digest)
        except ValueError as exc:
            raise _invalid() from exc
        expected = canonical_digest(
            {
                "task_id": task,
                "bundle_relpath": self.bundle_relpath,
                "route_generation": self.route_generation,
            }
        )
        if self.route_identity_digest != expected or type(self.phase) is not StartPhase:
            raise _invalid()
        if self.response_object_id is not None:
            _id(IdKind.OBJECT, self.response_object_id)
        try:
            if self.response_envelope_digest is not None:
                validate_sha256_digest(self.response_envelope_digest)
            if self.response_result_digest is not None:
                validate_sha256_digest(self.response_result_digest)
        except ValueError as exc:
            raise _invalid() from exc
        if self.response_result_canonical is not None:
            if type(self.response_result_canonical) is not bytes:
                raise _invalid()
            expected_result_digest = (
                f"sha256:{hashlib.sha256(self.response_result_canonical).hexdigest()}"
            )
            if self.response_result_digest != expected_result_digest:
                raise _invalid()
        response_identity = (
            self.response_object_id,
            self.response_envelope_digest,
            self.response_result_canonical,
            self.response_result_digest,
        )
        response_identity_complete = all(value is not None for value in response_identity)
        response_identity_absent = all(value is None for value in response_identity)
        if not (response_identity_complete or response_identity_absent):
            raise _invalid()
        if self.attach_handle is not None:
            _safe_token(self.attach_handle)
        if self.outcome == "replayed":
            if (
                self.phase is not StartPhase.TERMINAL
                or self.lease is not None
                or type(self.replayed_result) is not bytes
            ):
                raise _invalid()
        elif (
            self.phase is StartPhase.TERMINAL
            or type(self.lease) is not StartOperationLease
            or self.replayed_result is not None
        ):
            raise _invalid()
        if self.phase is StartPhase.RESULT_PUBLISHED:
            if not response_identity_complete:
                raise _invalid()
        elif self.outcome != "replayed" and not response_identity_absent:
            raise _invalid()


@dataclass(frozen=True, slots=True)
class EncryptedResultRef:
    response_object_id: str
    envelope_digest: str
    result_canonical: bytes
    result_digest: str

    def __post_init__(self) -> None:
        _id(IdKind.OBJECT, self.response_object_id)
        try:
            validate_sha256_digest(self.envelope_digest)
        except ValueError as exc:
            raise _invalid() from exc
        if type(self.result_canonical) is not bytes:
            raise _invalid()
        expected = f"sha256:{hashlib.sha256(self.result_canonical).hexdigest()}"
        if self.result_digest != expected:
            raise _invalid()


@dataclass(frozen=True, slots=True)
class SafeReason:
    code: str

    def __post_init__(self) -> None:
        if type(self.code) is not str or self.code not in _START_QUARANTINE_CODES:
            raise _invalid()


class StartCatalogPort(Protocol):
    async def commit_identity(self, value: StartIdentityInput) -> StartIdentityCommitments: ...

    async def recovery_routes(self) -> tuple[TaskRoute, ...]: ...

    async def resolve_route(self, session_id: str) -> TaskRoute | None: ...

    async def session_binding(self, session_id: str) -> SessionBinding | None: ...

    async def list_workspace_task_ids(self, workspace_ref_commitment: str) -> tuple[str, ...]: ...

    async def list_project_task_ids(self, project_id: str) -> tuple[str, ...]: ...

    async def list_repository_task_ids(
        self, repository_privacy_commitment: str
    ) -> tuple[str, ...]: ...

    async def task_lineage(self, task_id: str) -> TaskLineage | None: ...

    async def task_source_provenance(self, task_id: str) -> TaskSourceProvenance | None: ...

    async def task_route_generation(self, task_id: str) -> int: ...

    async def task_work_state(self, task_id: str) -> WorkState: ...

    async def task_session_state(self, session_id: str) -> SessionState | None: ...

    async def task_session_states(self, task_id: str) -> tuple[SessionState, ...]: ...

    async def list_child_task_ids(self, parent_task_id: str) -> tuple[str, ...]: ...

    async def list_task_project_ids(self, task_id: str) -> tuple[str, ...]: ...

    async def list_task_project_ids_for_consent_invalidation(
        self, task_id: str
    ) -> tuple[str, ...]: ...

    async def task_route(self, task_id: str) -> TaskRoute | None: ...

    async def project_state(self, project_id: str) -> ProjectState | None: ...

    async def repository_state(self, repository_commitment: str) -> ProjectState | None: ...

    async def repository_auto_grouping_enabled(self, repository_commitment: str) -> bool: ...

    async def ensure_repository_project_if_auto_grouping_enabled(
        self, repository_commitment: str
    ) -> ProjectState | None: ...

    async def project_memberships(self, project_id: str) -> tuple[ProjectMembership, ...]: ...

    async def coordination_grant(
        self, project_id: str, membership_generation: int
    ) -> CoordinationGrant | None: ...

    async def record_task_lineage(
        self,
        task_id: str,
        *,
        parent_task_id: str | None,
        depth: int,
        lineage_digest: str,
        origin: LineageOrigin | None,
        acceptance: LineageAcceptance | None,
    ) -> TaskLineage: ...

    async def set_task_work_state(self, task_id: str, state: WorkState) -> TaskLineage: ...

    async def record_session_state(
        self,
        task_id: str,
        session_id: str,
        *,
        health: SessionHealth,
        changed_at: datetime,
        lease_expires_at: datetime | None = None,
        actor_id: str | None = None,
    ) -> SessionState: ...

    async def extend_session_lease(
        self,
        task_id: str,
        session_id: str,
        *,
        changed_at: datetime,
        lease_expires_at: datetime,
    ) -> SessionState: ...

    async def expire_session_leases(
        self, now: datetime | None = None, *, limit: int = 256
    ) -> tuple[SessionState, ...]: ...

    async def accept_task_lineage(self, task_id: str) -> TaskLineage: ...

    async def reject_task_lineage(self, task_id: str) -> TaskLineage: ...

    async def ensure_repository_project(self, repository_commitment: str) -> ProjectState: ...

    async def create_general_project(
        self, project_id: str, *, auto_grouping: bool = True
    ) -> ProjectState: ...

    async def record_project_membership(
        self,
        project_id: str,
        *,
        member_kind: ProjectMemberKind,
        member_commitment_or_id: str,
    ) -> ProjectMembership: ...

    async def unbind_project_membership(
        self,
        project_id: str,
        membership_generation: int,
        *,
        member_kind: ProjectMemberKind | None = None,
        member_commitment_or_id: str | None = None,
    ) -> ProjectMembership: ...

    async def record_coordination_grant(
        self,
        project_id: str,
        membership_generation: int,
        *,
        grant_state: CoordinationGrantState,
        audit_ref: str,
    ) -> CoordinationGrant: ...

    async def dissolve_project(self, project_id: str) -> ProjectState: ...

    async def advance_project_generation(
        self,
        project_id: str,
        *,
        reason: str,
        expected_generation: int | None = None,
    ) -> ProjectState: ...

    async def set_project_auto_grouping(
        self, repository_commitment: str, *, enabled: bool
    ) -> ProjectState | None: ...

    async def record_project_text_refs(
        self,
        project_id: str,
        *,
        title_ref: ProjectTextRef | None,
        description_ref: ProjectTextRef | None,
    ) -> ProjectState: ...

    async def amend_project(
        self,
        project_id: str,
        *,
        title_ref: ProjectTextRef | None,
        description_ref: ProjectTextRef | None,
    ) -> ProjectState: ...

    async def bind_repository_privacy(
        self,
        task_id: str,
        route_identity_digest: str,
        repository_privacy_commitment: str,
    ) -> TaskRoute: ...

    async def reserve_or_resume(self, request: StartCommand) -> StartAllocation: ...

    async def yield_lease(self, allocation: StartAllocation) -> None:
        """Expire only the held pending lease; preserve identity, phase and durable results."""
        ...

    async def complete(
        self,
        allocation: StartAllocation,
        result: EncryptedResultRef,
        evidence: StartCompletionEvidence,
    ) -> None: ...

    async def quarantine(self, allocation: StartAllocation, reason: SafeReason) -> None: ...

    async def advance_phase(
        self,
        allocation: StartAllocation,
        phase: StartPhase,
        result: EncryptedResultRef | None = None,
    ) -> StartAllocation: ...
