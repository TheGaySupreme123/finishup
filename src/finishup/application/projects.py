"""Project lifecycle and consent application services.

The catalog owns project and membership rows.  This module owns the invariants around those rows:
membership is append-only, a task has at most one general project, every generation change fences
queued coordination, and repository/workspace consent is evaluated per source workspace.  The
service intentionally receives small protocols instead of opening SQLite itself; production
composition can therefore bind the catalog migration while tests use the reference adapter.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal, Protocol, cast

if TYPE_CHECKING:
    from finishup.application.coordination import (
        CoordinationAdvice,
        CoordinationDetailReader,
        CoordinationParticipant,
        CoordinationResourceProjection,
    )
    from finishup.application.lineage import LineageProjectAdmission

from finishup.domain.coordination import (
    CoordinationAdmission,
    CoordinationCoverage,
    CoordinationDetection,
    CoordinationError,
    CoordinationErrorCode,
    CoordinationGrant,
    CoordinationObligationState,
    GrantState,
    MemberKind,
    ProjectDescriptor,
    ProjectKind,
    ProjectMembership,
    ProjectTextRef,
    ProjectTextStore,
    SessionHealth,
    WorkState,
    canonical_resource_identity,
    coordination_generation_is_current,
    general_link_conflicts,
    project_id,
    relative_resource_identity,
)
from finishup.domain.privacy import LocalDisclosureSink
from finishup.domain.values import (
    JsonObject,
    JsonValue,
    parse_rfc3339_millis,
    validate_commitment,
    validate_sha256_digest,
)
from finishup.ports.clock import ClockPort
from finishup.ports.diagnostics import RuntimeCapability
from finishup.ports.ids import IdPort
from finishup.ports.objects import (
    ObjectKind,
    ObjectMetadata,
    ObjectRef,
    ObjectSource,
    ObjectStorePort,
)
from finishup.ports.project_operations import (
    ProjectOperationConflict,
    ProjectOperationDigest,
    ProjectOperationJournalPort,
    ProjectOperationName,
    ProjectOperationRecord,
)
from finishup.ports.runtime import BundleRuntimePort, RouteAccess, RouteCommand, TaskRuntime
from finishup.ports.start_catalog import (
    SessionBinding,
    SessionState,
    TaskLineage,
    TaskRoute,
    TaskRouteState,
    TaskSourceProvenance,
)
from finishup.protocol.canonical import canonical_encode, strict_json_parse
from finishup.protocol.errors import PublicOperationError
from finishup.protocol.ids import IdKind, validate_id

__all__ = [
    "CreateProjectCommand",
    "InMemoryProjectCatalog",
    "LinkProjectCommand",
    "ProjectApplication",
    "ProjectCatalogPort",
    "ProjectCommandError",
    "ProjectDissolveCommand",
    "ProjectGrantCommand",
    "ProjectMembershipView",
    "ProjectObjectStoreResolver",
    "ProjectObjectStoreLease",
    "ProjectOptCommand",
    "ProjectRevokeCommand",
    "ProjectStatus",
    "ProjectTextStore",
    "SourceConsentRevocationPlan",
    "ProjectUnlinkCommand",
    "ProjectAmendCommand",
    "RoutedEncryptedProjectTextStore",
    "CoordinationGrantAuthorizer",
    "ProjectCoordinationSourceAuthorizer",
    "ProjectTextDisclosureAuthorizer",
    "CoordinationResourceDisclosureAuthorizer",
    "build_routed_project_text_store",
    "ProjectDetectionPort",
    "EncryptedProjectTextStore",
    "build_project_support_handler",
    "build_project_support_handlers",
    "project_request_from_json",
    "ProjectOperationJournalPort",
]


type _AwaitableValue[T] = T | Awaitable[T]


@dataclass(frozen=True, slots=True)
class ProjectObjectStoreLease:
    """A routed object store and its generation-bound runtime release callback.

    ``BundleRuntimePort.route`` returns a lease whose lifetime must cover every object read.  The
    project text adapter carries that lifetime explicitly instead of returning a bare object
    store that could outlive the authenticated route.
    """

    store: ObjectStorePort
    release: Callable[[], _AwaitableValue[None]]

    def __post_init__(self) -> None:
        if not callable(getattr(self.store, "resolve_verified", None)):
            raise TypeError("project_object_store_invalid")
        if not callable(self.release):
            raise TypeError("project_object_store_release_invalid")


type ProjectObjectStoreResolver = Callable[
    [str, int], _AwaitableValue[ObjectStorePort | ProjectObjectStoreLease | None]
]


type ProjectTextDisclosureAuthorizer = Callable[
    [str, str, Literal["title", "description"], LocalDisclosureSink, str],
    _AwaitableValue[bool],
]

type CoordinationResourceDisclosureAuthorizer = Callable[
    [str, str, LocalDisclosureSink, str],
    _AwaitableValue[bool],
]

# Coordination is a local cross-task disclosure boundary.  The catalog proves the task and
# workspace binding; READY supplies the effective source-task policy check.  Keep the project
# selector in the typed seam even though the current policy lattice has no project scope kind: it
# prevents a future composition from accidentally reusing this authority for an unrelated sink.
type ProjectCoordinationSourceAuthorizer = Callable[
    [str, str, str],
    _AwaitableValue[bool],
]

# The catalog commitment identifies the task's source workspace, while the observation store
# deliberately uses a separate key/domain for the local path commitment.  Production composition
# must prove that mapping from the task's authenticated route and encrypted source locator.  Keep
# the legacy one-argument callback for small application doubles, but give ready composition an
# explicit task-bound seam so it cannot translate arbitrary caller-supplied digests.
type ProjectWorkspaceConsentForSource = Callable[[str, str], _AwaitableValue[bool]]


def _default_project_text_disclosure_authorizer(
    owner_task_id: str,
    owner_workspace_commitment: str,
    field: Literal["title", "description"],
    sink: LocalDisclosureSink,
    purpose: str,
) -> bool:
    """Deny source text when the ready service has not bound privacy authorization.

    Every production sink, including the local-human view, must bind the privacy coordinator
    through ``text_disclosure_authorizer``.  A missing composition dependency therefore cannot
    turn a generic requester projection into source-owner authorization.
    """

    del owner_task_id, owner_workspace_commitment, field, purpose
    del sink
    return False


def _default_project_coordination_source_authorizer(
    source_task_id: str,
    source_workspace_commitment: str,
    project_id_value: str,
) -> bool:
    """Deny coordination when READY has not bound the source policy authority."""

    del source_task_id, source_workspace_commitment, project_id_value
    return False


def _now(clock: ClockPort | None) -> datetime:
    if clock is None:
        return datetime.now(UTC).replace(microsecond=0)
    return clock.now_utc()


def _awaitable[T](value: _AwaitableValue[T]) -> Awaitable[T]:
    if inspect.isawaitable(value):
        return cast(Awaitable[T], value)

    async def immediate() -> T:
        return value

    return immediate()


def _bounded_text(value: object, *, required: bool) -> str | None:
    if value is None:
        if required:
            raise ProjectCommandError(CoordinationErrorCode.INVALID)
        return None
    if type(value) is not str:
        raise ProjectCommandError(CoordinationErrorCode.INVALID)
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ProjectCommandError(CoordinationErrorCode.INVALID) from exc
    if not 1 <= len(encoded) <= 65_536:
        raise ProjectCommandError(CoordinationErrorCode.INVALID)
    if any(
        ord(character) in {0, 0x7F} or ord(character) < 0x20 and character not in "\n\t"
        for character in value
    ):
        raise ProjectCommandError(CoordinationErrorCode.INVALID)
    return value


def _commitment(value: object) -> str:
    if type(value) is not str:
        raise ProjectCommandError(CoordinationErrorCode.INVALID)
    try:
        return validate_commitment(value)
    except (TypeError, ValueError) as exc:
        raise ProjectCommandError(CoordinationErrorCode.INVALID) from exc


def _id(kind: IdKind, value: object) -> str:
    try:
        return validate_id(kind, value)
    except (TypeError, ValueError) as exc:
        raise ProjectCommandError(CoordinationErrorCode.INVALID) from exc


def _project(value: object) -> str:
    try:
        return project_id(value)
    except ValueError as exc:
        raise ProjectCommandError(CoordinationErrorCode.INVALID) from exc


def _member_kind(value: object) -> MemberKind:
    if type(value) is MemberKind:
        return value
    try:
        return MemberKind(cast(str, value))
    except (TypeError, ValueError) as exc:
        raise ProjectCommandError(CoordinationErrorCode.INVALID) from exc


def _project_id_from_ids(ids: IdPort) -> str:
    return _project(ids.new(IdKind.PROJECT))


def _audit_id(ids: IdPort) -> str:
    return ids.new(IdKind.EVENT)


def _project_operation_identity(operation: ProjectOperationName, **values: object) -> JsonObject:
    """Build the authenticated identity tree for one project mutation.

    The tree is hashed before it reaches the journal.  It may contain title/description values in
    process memory while the request is being authenticated, but the journal receives only the
    resulting digest and never this tree.
    """

    result: dict[str, JsonValue] = {
        "schema_version": "1.0.0",
        "operation": operation,
    }
    for key, value in values.items():
        if value is None:
            result[key] = None
        elif type(value) is bool or type(value) is int or type(value) is str:
            result[key] = value
        else:
            raise ProjectCommandError(CoordinationErrorCode.INVALID)
    return JsonObject(result)


def _operation_response_mapping(value: bytes) -> Mapping[str, JsonValue]:
    try:
        parsed = strict_json_parse(value)
        if not isinstance(parsed, Mapping) or canonical_encode(parsed) != value:
            raise ValueError("project_operation_response_invalid")
        return cast(Mapping[str, JsonValue], parsed)
    except (TypeError, ValueError) as exc:
        raise ProjectCommandError(CoordinationErrorCode.INVALID) from exc


def _text_ref_from_wire(value: object) -> ProjectTextRef | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise ProjectCommandError(CoordinationErrorCode.INVALID)
    source = cast(Mapping[str, object], value)
    required = {
        "object_id",
        "content_digest",
        "plaintext_size",
        "owner_task_id",
        "route_generation",
    }
    if set(source) not in (required, required | {"envelope_digest"}):
        raise ProjectCommandError(CoordinationErrorCode.INVALID)
    generation = source.get("route_generation")
    if type(generation) is not str:
        raise ProjectCommandError(CoordinationErrorCode.INVALID)
    try:
        parsed_generation = int(generation, 10)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ProjectCommandError(CoordinationErrorCode.INVALID) from exc
    if str(parsed_generation) != generation:
        raise ProjectCommandError(CoordinationErrorCode.INVALID)
    try:
        return ProjectTextRef(
            cast(str, source["object_id"]),
            cast(str, source["content_digest"]),
            cast(int, source["plaintext_size"]),
            cast(str, source["owner_task_id"]),
            parsed_generation,
            cast(str | None, source.get("envelope_digest")),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ProjectCommandError(CoordinationErrorCode.INVALID) from exc


def _descriptor_from_wire(value: bytes | Mapping[str, JsonValue]) -> ProjectDescriptor:
    source: Mapping[str, JsonValue]
    if isinstance(value, bytes):
        source = _operation_response_mapping(value)
    else:
        source = value
    try:
        generation = source["membership_generation"]
        if type(generation) is not str:
            raise ValueError("project_generation_wire_invalid")
        parsed_generation = int(generation, 10)
        if str(parsed_generation) != generation:
            raise ValueError("project_generation_wire_invalid")
        dissolved = source.get("dissolved_at")
        return ProjectDescriptor(
            cast(str, source["project_id"]),
            ProjectKind(cast(str, source["kind"])),
            cast(str | None, source.get("repository_commitment")),
            cast(bool, source["auto_grouping"]),
            parsed_generation,
            _text_ref_from_wire(source.get("title_ref")),
            _text_ref_from_wire(source.get("description_ref")),
            parse_rfc3339_millis(source["created_at"]),
            None if dissolved is None else parse_rfc3339_millis(dissolved),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ProjectCommandError(CoordinationErrorCode.INVALID) from exc


def _membership_from_wire(value: bytes | Mapping[str, JsonValue]) -> ProjectMembership:
    source: Mapping[str, JsonValue]
    if isinstance(value, bytes):
        source = _operation_response_mapping(value)
    else:
        source = value
    try:
        generation = source["membership_generation"]
        if type(generation) is not str:
            raise ValueError("membership_generation_wire_invalid")
        parsed_generation = int(generation, 10)
        if str(parsed_generation) != generation:
            raise ValueError("membership_generation_wire_invalid")
        unbound = source.get("unbound_at")
        return ProjectMembership(
            cast(str, source["project_id"]),
            parsed_generation,
            MemberKind(cast(str, source["member_kind"])),
            cast(str, source["member_commitment_or_id"]),
            parse_rfc3339_millis(source["bound_at"]),
            None if unbound is None else parse_rfc3339_millis(unbound),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ProjectCommandError(CoordinationErrorCode.INVALID) from exc


def _grant_from_wire(value: bytes | Mapping[str, JsonValue]) -> CoordinationGrant:
    source: Mapping[str, JsonValue]
    if isinstance(value, bytes):
        source = _operation_response_mapping(value)
    else:
        source = value
    try:
        generation = source["membership_generation"]
        if type(generation) is not str:
            raise ValueError("grant_generation_wire_invalid")
        parsed_generation = int(generation, 10)
        if str(parsed_generation) != generation:
            raise ValueError("grant_generation_wire_invalid")
        revoked = source.get("revoked_at")
        return CoordinationGrant(
            cast(str, source["project_id"]),
            parsed_generation,
            GrantState(cast(str, source["state"])),
            cast(str, source["audit_record_id"]),
            parse_rfc3339_millis(source["granted_at"]),
            None if revoked is None else parse_rfc3339_millis(revoked),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ProjectCommandError(CoordinationErrorCode.INVALID) from exc


def _auto_grouping_wire(
    repository: str, enabled: bool, result: ProjectDescriptor | None
) -> JsonObject:
    if result is None:
        return JsonObject(
            {
                "schema_version": "1.0.0",
                "repository_commitment": repository,
                "auto_grouping": enabled,
                "project_id": None,
            }
        )
    return result.as_wire()


def _auto_grouping_from_wire(value: bytes) -> ProjectDescriptor | None:
    source = _operation_response_mapping(value)
    if source.get("project_id") is None:
        return None
    return _descriptor_from_wire(value)


class ProjectCommandError(CoordinationError):
    """Alias used by command parsers and control adapters."""


@dataclass(frozen=True, slots=True)
class CreateProjectCommand:
    title: str
    description: str | None = None
    auto_grouping: bool = False
    owner_task_id: str | None = None
    owner_route_generation: int | None = None

    def __post_init__(self) -> None:
        _bounded_text(self.title, required=True)
        _bounded_text(self.description, required=False)
        if type(self.auto_grouping) is not bool:
            raise ProjectCommandError(CoordinationErrorCode.INVALID)
        if self.owner_task_id is None:
            raise ProjectCommandError(CoordinationErrorCode.INVALID)
        _id(IdKind.TASK, self.owner_task_id)
        if self.owner_route_generation is not None and (
            type(self.owner_route_generation) is not int or self.owner_route_generation < 1
        ):
            raise ProjectCommandError(CoordinationErrorCode.INVALID)


@dataclass(frozen=True, slots=True)
class LinkProjectCommand:
    project_id: str
    member_kind: MemberKind
    member_commitment_or_id: str
    source_workspace_commitment: str | None = None
    member_repository_commitment: str | None = None
    expected_generation: int | None = None

    def __post_init__(self) -> None:
        _project(self.project_id)
        kind = _member_kind(self.member_kind)
        value = self.member_commitment_or_id
        if type(value) is not str or not value:
            raise ProjectCommandError(CoordinationErrorCode.INVALID)
        if kind is MemberKind.TASK:
            _id(IdKind.TASK, value)
        else:
            _commitment(value)
        if self.source_workspace_commitment is not None:
            _commitment(self.source_workspace_commitment)
        if self.member_repository_commitment is not None:
            _commitment(self.member_repository_commitment)
        if self.expected_generation is not None and (
            type(self.expected_generation) is not int or self.expected_generation < 1
        ):
            raise ProjectCommandError(CoordinationErrorCode.INVALID)


@dataclass(frozen=True, slots=True)
class ProjectUnlinkCommand:
    project_id: str
    member_kind: MemberKind
    member_commitment_or_id: str
    expected_generation: int | None = None

    def __post_init__(self) -> None:
        LinkProjectCommand(
            self.project_id,
            self.member_kind,
            self.member_commitment_or_id,
            expected_generation=self.expected_generation,
        )


@dataclass(frozen=True, slots=True)
class ProjectAmendCommand:
    project_id: str
    title: str | None = None
    description: str | None = None
    owner_task_id: str | None = None
    owner_route_generation: int | None = None

    def __post_init__(self) -> None:
        _project(self.project_id)
        if self.title is None and self.description is None:
            raise ProjectCommandError(CoordinationErrorCode.INVALID)
        _bounded_text(self.title, required=False)
        _bounded_text(self.description, required=False)
        if self.owner_task_id is None:
            raise ProjectCommandError(CoordinationErrorCode.INVALID)
        _id(IdKind.TASK, self.owner_task_id)
        if self.owner_route_generation is not None and (
            type(self.owner_route_generation) is not int or self.owner_route_generation < 1
        ):
            raise ProjectCommandError(CoordinationErrorCode.INVALID)


@dataclass(frozen=True, slots=True)
class ProjectDissolveCommand:
    project_id: str
    expected_generation: int | None = None

    def __post_init__(self) -> None:
        _project(self.project_id)
        if self.expected_generation is not None and (
            type(self.expected_generation) is not int or self.expected_generation < 1
        ):
            raise ProjectCommandError(CoordinationErrorCode.INVALID)


@dataclass(frozen=True, slots=True)
class ProjectOptCommand:
    repository_commitment: str

    def __post_init__(self) -> None:
        _commitment(self.repository_commitment)


@dataclass(frozen=True, slots=True)
class ProjectGrantCommand:
    project_id: str
    membership_generation: int
    audit_record_id: str | None = None

    def __post_init__(self) -> None:
        _project(self.project_id)
        if type(self.membership_generation) is not int or self.membership_generation < 1:
            raise ProjectCommandError(CoordinationErrorCode.INVALID)
        if self.audit_record_id is not None and (
            type(self.audit_record_id) is not str or not self.audit_record_id
        ):
            raise ProjectCommandError(CoordinationErrorCode.INVALID)


@dataclass(frozen=True, slots=True)
class ProjectRevokeCommand:
    project_id: str
    membership_generation: int
    audit_record_id: str | None = None

    def __post_init__(self) -> None:
        ProjectGrantCommand(
            self.project_id,
            self.membership_generation,
            self.audit_record_id,
        )


@dataclass(frozen=True, slots=True)
class ProjectMembershipView:
    membership: ProjectMembership
    task_id: str | None = None
    work_state: str | None = None
    session_health: str | None = None
    actor_id: str | None = None
    parent_task_id: str | None = None

    def as_wire(self) -> JsonObject:
        values = dict(self.membership.as_wire())
        if self.task_id is not None:
            values["task_id"] = self.task_id
        if self.work_state is not None:
            values["work_state"] = self.work_state
        if self.session_health is not None:
            values["session_health"] = self.session_health
        if self.actor_id is not None:
            values["actor_id"] = self.actor_id
        if self.parent_task_id is not None:
            values["parent_task_id"] = self.parent_task_id
        return JsonObject(values)


@dataclass(frozen=True, slots=True, repr=False)
class ProjectStatus:
    project: ProjectDescriptor
    memberships: tuple[ProjectMembershipView, ...]
    grant: CoordinationGrant | None
    detections: tuple[JsonObject, ...] = ()
    authorized_task_id: str | None = None
    coverage: tuple[JsonObject, ...] = ()

    def __post_init__(self) -> None:
        if (
            type(self.memberships) is not tuple
            or type(self.detections) is not tuple
            or type(self.coverage) is not tuple
        ):
            raise ProjectCommandError(CoordinationErrorCode.INVALID)

    def as_wire(self) -> JsonObject:
        values: dict[str, JsonValue] = {
            "schema_version": "1.0.0",
            "project": self.project.as_wire(),
            "memberships": cast(JsonValue, [item.as_wire() for item in self.memberships]),
            "detections": cast(JsonValue, list(self.detections)),
            "coverage": cast(JsonValue, list(self.coverage)),
        }
        if self.grant is not None:
            values["grant"] = self.grant.as_wire()
        if self.authorized_task_id is not None:
            values["authorized_task_id"] = self.authorized_task_id
        return JsonObject(values)


@dataclass(frozen=True, slots=True)
class SourceConsentRevocationPlan:
    """Durable generation snapshot for one source-workspace consent withdrawal."""

    revocation_token: str
    project_generations: tuple[tuple[str, int], ...]

    def __post_init__(self) -> None:
        try:
            validate_sha256_digest(self.revocation_token)
        except (TypeError, ValueError) as exc:
            raise ProjectCommandError(CoordinationErrorCode.INVALID) from exc
        if type(self.project_generations) is not tuple or len(self.project_generations) > 256:
            raise ProjectCommandError(CoordinationErrorCode.INVALID)
        normalized: list[tuple[str, int]] = []
        for item in self.project_generations:
            if type(item) is not tuple or len(item) != 2:
                raise ProjectCommandError(CoordinationErrorCode.INVALID)
            project, generation = item
            normalized.append((_project(project), generation))
            if type(generation) is not int or isinstance(generation, bool) or generation < 1:
                raise ProjectCommandError(CoordinationErrorCode.INVALID)
        if tuple(normalized) != tuple(sorted(set(normalized), key=lambda item: item[0].encode())):
            raise ProjectCommandError(CoordinationErrorCode.INVALID)


class ProjectDetectionPort(Protocol):
    """Read-only detector projection used by the authenticated project status view."""

    async def list_detections(self, project_id: str) -> tuple[CoordinationDetection, ...]: ...

    async def obligation(
        self, detection_id: str, task_id: str
    ) -> CoordinationObligationState | None: ...

    async def coverage_for(
        self, project_id: str, membership_generation: int
    ) -> tuple[CoordinationCoverage, ...]: ...


async def inspect_obligation_states(
    store: ProjectDetectionPort,
    detection_id: str,
    task_ids: tuple[str, str],
) -> tuple[CoordinationObligationState, ...]:
    """Read the per-task obligation rows without widening the project status view."""

    states: list[CoordinationObligationState] = []
    for task_id in task_ids:
        state = await store.obligation(detection_id, task_id)
        if state is not None:
            states.append(state)
    return tuple(states)


class ProjectCatalogPort(Protocol):
    """The explicit catalog contract used by project coordination.

    These names intentionally match the durable catalog port in
    ``src/finishup/ports/start_catalog.py`` and the shared trust-boundary names in
    ``docs/INTERFACES.md``.  Project application code must not probe alternate spellings: a
    missing method means the service composition is incomplete.
    """

    async def project_state(self, project_id: str) -> ProjectDescriptor | None: ...

    async def list_project_ids(self) -> tuple[str, ...]: ...

    async def repository_state(self, repository_commitment: str) -> ProjectDescriptor | None: ...

    async def repository_auto_grouping_enabled(self, repository_commitment: str) -> bool: ...

    async def ensure_repository_project_if_auto_grouping_enabled(
        self, repository_commitment: str
    ) -> ProjectDescriptor | None: ...

    async def project_memberships(self, project_id: str) -> tuple[ProjectMembership, ...]: ...

    async def list_project_task_ids(self, project_id: str) -> tuple[str, ...]: ...

    async def list_repository_task_ids(
        self, repository_privacy_commitment: str
    ) -> tuple[str, ...]: ...

    async def list_workspace_task_ids(self, workspace_ref_commitment: str) -> tuple[str, ...]: ...

    async def list_task_project_ids(self, task_id: str) -> tuple[str, ...]: ...

    async def list_task_project_ids_for_consent_invalidation(
        self, task_id: str
    ) -> tuple[str, ...]: ...

    async def task_lineage(self, task_id: str) -> TaskLineage | None: ...

    async def task_source_provenance(self, task_id: str) -> TaskSourceProvenance | None: ...

    async def task_work_state(self, task_id: str) -> WorkState: ...

    async def task_session_states(self, task_id: str) -> tuple[SessionState, ...]: ...

    async def task_route_generation(self, task_id: str) -> int: ...

    async def task_route(self, task_id: str) -> TaskRoute | None: ...

    async def session_binding(self, session_id: str) -> SessionBinding | None: ...

    async def ensure_repository_project(self, repository_commitment: str) -> ProjectDescriptor: ...

    async def create_general_project(
        self, project_id: str, *, auto_grouping: bool = True
    ) -> ProjectDescriptor: ...

    async def record_project_membership(
        self,
        project_id: str,
        *,
        member_kind: MemberKind,
        member_commitment_or_id: str,
    ) -> ProjectMembership: ...

    async def unbind_project_membership(
        self,
        project_id: str,
        membership_generation: int,
        *,
        member_kind: MemberKind | None = None,
        member_commitment_or_id: str | None = None,
    ) -> ProjectMembership: ...

    async def coordination_grant(
        self, project_id: str, membership_generation: int
    ) -> CoordinationGrant | None: ...

    async def record_coordination_grant(
        self,
        project_id: str,
        membership_generation: int,
        *,
        grant_state: GrantState,
        audit_ref: str,
    ) -> CoordinationGrant: ...

    async def advance_project_generation(
        self, project_id: str, *, reason: str, expected_generation: int | None = None
    ) -> ProjectDescriptor: ...

    async def set_project_auto_grouping(
        self, repository_commitment: str, *, enabled: bool
    ) -> ProjectDescriptor | None: ...

    async def amend_project(
        self,
        project_id: str,
        *,
        title_ref: ProjectTextRef | None,
        description_ref: ProjectTextRef | None,
        expected_current_refs: tuple[ProjectTextRef | None, ProjectTextRef | None] | None = None,
    ) -> ProjectDescriptor: ...

    async def record_project_text_refs(
        self,
        project_id: str,
        *,
        title_ref: ProjectTextRef | None,
        description_ref: ProjectTextRef | None,
        expected_current_refs: tuple[ProjectTextRef | None, ProjectTextRef | None] | None = None,
    ) -> ProjectDescriptor: ...

    async def dissolve_project(self, project_id: str) -> ProjectDescriptor: ...


@dataclass(slots=True)
class _MemoryProjectRecord:
    descriptor: ProjectDescriptor
    memberships: list[ProjectMembership] = field(default_factory=lambda: list[ProjectMembership]())
    grants: list[CoordinationGrant] = field(default_factory=lambda: list[CoordinationGrant]())


class InMemoryProjectCatalog:
    """Reference catalog used by unit/conformance tests and lightweight compositions."""

    def __init__(self) -> None:
        self.projects: dict[str, _MemoryProjectRecord] = {}
        self.repository_grouping_preferences: dict[str, bool] = {}
        self.provenance: dict[str, TaskSourceProvenance] = {}

    async def project_state(self, project_id: str) -> ProjectDescriptor | None:
        record = self.projects.get(project_id)
        return None if record is None else record.descriptor

    async def list_project_ids(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                (
                    identifier
                    for identifier, record in self.projects.items()
                    if record.descriptor.dissolved_at is None
                ),
                key=str.encode,
            )
        )

    async def repository_state(self, repository_commitment: str) -> ProjectDescriptor | None:
        for record in self.projects.values():
            if (
                record.descriptor.kind is ProjectKind.REPOSITORY
                and record.descriptor.repository_commitment == repository_commitment
            ):
                return record.descriptor
        return None

    async def repository_auto_grouping_enabled(self, repository_commitment: str) -> bool:
        try:
            validate_commitment(repository_commitment)
        except (TypeError, ValueError) as exc:
            raise ProjectCommandError(CoordinationErrorCode.INVALID) from exc
        preference = self.repository_grouping_preferences.get(repository_commitment)
        if preference is not None:
            return preference
        descriptor = await self.repository_state(repository_commitment)
        return True if descriptor is None else descriptor.auto_grouping

    async def ensure_repository_project_if_auto_grouping_enabled(
        self, repository_commitment: str
    ) -> ProjectDescriptor | None:
        try:
            validate_commitment(repository_commitment)
        except (TypeError, ValueError) as exc:
            raise ProjectCommandError(CoordinationErrorCode.INVALID) from exc
        # Keep this decision and the birth in one catalog operation.  The ordinary ensure method
        # intentionally retains its explicit-call semantics and may materialize a disabled row.
        preference = self.repository_grouping_preferences.get(repository_commitment)
        if preference is False:
            return None
        descriptor = await self.repository_state(repository_commitment)
        if descriptor is not None:
            return None if not descriptor.auto_grouping else descriptor
        return await self.ensure_repository_project(repository_commitment)

    async def ensure_repository_project(self, repository_commitment: str) -> ProjectDescriptor:
        existing = await self.repository_state(repository_commitment)
        if existing is not None:
            return existing
        identifier = f"prj_{repository_commitment[-36:]}"
        # A repository commitment is a sha256 token and therefore cannot itself be a UUID.  The
        # deterministic test catalog uses a counter-shaped UUID suffix while production receives
        # ids from IdPort in the SQLite adapter.
        identifier = "prj_00000000-0000-4000-8000-" + repository_commitment[-12:]
        now = datetime.now(UTC).replace(microsecond=0)
        descriptor = ProjectDescriptor(
            identifier,
            ProjectKind.REPOSITORY,
            repository_commitment,
            self.repository_grouping_preferences.get(repository_commitment, True),
            1,
            None,
            None,
            now,
        )
        self.projects[identifier] = _MemoryProjectRecord(descriptor)
        self.projects[identifier].memberships.append(
            ProjectMembership(identifier, 1, MemberKind.REPOSITORY, repository_commitment, now)
        )
        return descriptor

    async def create_general_project(
        self, project_id: str, *, auto_grouping: bool = True
    ) -> ProjectDescriptor:
        if project_id in self.projects:
            raise ProjectCommandError(CoordinationErrorCode.SELECTOR_CONFLICT)
        descriptor = ProjectDescriptor(
            project_id,
            ProjectKind.GENERAL,
            None,
            auto_grouping,
            1,
            None,
            None,
            datetime.now(UTC).replace(microsecond=0),
        )
        self.projects[project_id] = _MemoryProjectRecord(descriptor)
        return descriptor

    async def project_memberships(self, project_id: str) -> tuple[ProjectMembership, ...]:
        record = self.projects.get(project_id)
        if record is None:
            raise ProjectCommandError(CoordinationErrorCode.PROJECT_NOT_FOUND)
        return tuple(record.memberships)

    async def list_project_task_ids(self, project_id: str) -> tuple[str, ...]:
        record = self.projects.get(project_id)
        if record is None or record.descriptor.dissolved_at is not None:
            return ()
        task_ids = {
            item.member_commitment_or_id
            for item in record.memberships
            if item.active and item.member_kind is MemberKind.TASK
        }
        if record.descriptor.kind is ProjectKind.REPOSITORY and record.descriptor.auto_grouping:
            repository = record.descriptor.repository_commitment
            if repository is not None:
                task_ids.update(
                    task_id
                    for task_id, provenance in self.provenance.items()
                    if provenance.repository_privacy_commitment == repository
                )
        elif record.descriptor.kind is ProjectKind.GENERAL:
            repository_bindings = {
                item.member_commitment_or_id
                for item in record.memberships
                if item.active and item.member_kind is MemberKind.REPOSITORY
            }
            workspace_bindings = {
                item.member_commitment_or_id
                for item in record.memberships
                if item.active and item.member_kind is MemberKind.WORKSPACE
            }
            task_ids.update(
                task_id
                for task_id, provenance in self.provenance.items()
                if provenance.repository_privacy_commitment in repository_bindings
                or provenance.workspace_ref_commitment in workspace_bindings
            )
        return tuple(sorted(task_ids))

    async def list_repository_task_ids(self, repository_privacy_commitment: str) -> tuple[str, ...]:
        return tuple(
            sorted(
                task_id
                for task_id, value in self.provenance.items()
                if value.repository_privacy_commitment == repository_privacy_commitment
            )
        )

    async def list_workspace_task_ids(self, workspace_ref_commitment: str) -> tuple[str, ...]:
        return tuple(
            sorted(
                task_id
                for task_id, value in self.provenance.items()
                if value.workspace_ref_commitment == workspace_ref_commitment
            )
        )

    async def list_task_project_ids(self, task_id: str) -> tuple[str, ...]:
        source = self.provenance.get(task_id)
        project_ids: set[str] = set()
        for record in self.projects.values():
            if record.descriptor.dissolved_at is not None:
                continue
            for item in record.memberships:
                if not item.active:
                    continue
                if item.member_kind is MemberKind.TASK and item.member_commitment_or_id == task_id:
                    project_ids.add(record.descriptor.project_id)
                elif (
                    source is not None
                    and record.descriptor.kind is ProjectKind.REPOSITORY
                    and record.descriptor.auto_grouping
                    and record.descriptor.repository_commitment
                    == source.repository_privacy_commitment
                ):
                    project_ids.add(record.descriptor.project_id)
                elif source is not None and record.descriptor.kind is ProjectKind.GENERAL:
                    if item.member_kind is MemberKind.REPOSITORY and (
                        item.member_commitment_or_id == source.repository_privacy_commitment
                    ):
                        project_ids.add(record.descriptor.project_id)
                    elif item.member_kind is MemberKind.WORKSPACE and (
                        item.member_commitment_or_id == source.workspace_ref_commitment
                    ):
                        project_ids.add(record.descriptor.project_id)
        return tuple(sorted(project_ids))

    def _general_link_conflicts(
        self, project_id: str, member_kind: MemberKind, member_commitment_or_id: str
    ) -> bool:
        other: list[tuple[str, MemberKind, str]] = []
        provenance: list[tuple[str, str | None, str | None]] = []
        for record in self.projects.values():
            descriptor = record.descriptor
            if (
                descriptor.project_id == project_id
                or descriptor.kind is not ProjectKind.GENERAL
                or descriptor.dissolved_at is not None
            ):
                continue
            for item in record.memberships:
                if item.active:
                    other.append(
                        (descriptor.project_id, item.member_kind, item.member_commitment_or_id)
                    )
        for task_id, source in self.provenance.items():
            provenance.append(
                (
                    task_id,
                    source.repository_privacy_commitment,
                    source.workspace_ref_commitment,
                )
            )
        return general_link_conflicts(
            target_project_id=project_id,
            member_kind=member_kind,
            member=member_commitment_or_id,
            other_memberships=other,
            provenance=provenance,
        )

    async def record_project_membership(
        self,
        project_id: str,
        *,
        member_kind: MemberKind,
        member_commitment_or_id: str,
    ) -> ProjectMembership:
        record = self.projects.get(project_id)
        if record is None:
            raise ProjectCommandError(CoordinationErrorCode.PROJECT_NOT_FOUND)
        if record.descriptor.dissolved_at is not None:
            raise ProjectCommandError(CoordinationErrorCode.PROJECT_DISSOLVED)
        existing = next(
            (
                item
                for item in record.memberships
                if item.active
                and item.member_kind is member_kind
                and item.member_commitment_or_id == member_commitment_or_id
            ),
            None,
        )
        if existing is not None:
            return existing
        if record.descriptor.kind is ProjectKind.GENERAL and self._general_link_conflicts(
            project_id, member_kind, member_commitment_or_id
        ):
            raise ProjectCommandError(CoordinationErrorCode.GENERAL_MEMBERSHIP_CONFLICT)
        generation = record.descriptor.membership_generation + 1
        now = datetime.now(UTC).replace(microsecond=0)
        membership = ProjectMembership(
            project_id, generation, member_kind, member_commitment_or_id, now
        )
        record.memberships.append(membership)
        prior = record.descriptor
        record.descriptor = ProjectDescriptor(
            prior.project_id,
            prior.kind,
            prior.repository_commitment,
            prior.auto_grouping,
            generation,
            prior.title_ref,
            prior.description_ref,
            prior.created_at,
            prior.dissolved_at,
        )
        return membership

    async def unbind_project_membership(
        self,
        project_id: str,
        membership_generation: int,
        *,
        member_kind: MemberKind | None = None,
        member_commitment_or_id: str | None = None,
    ) -> ProjectMembership:
        record = self.projects.get(project_id)
        if record is None:
            raise ProjectCommandError(CoordinationErrorCode.PROJECT_NOT_FOUND)
        candidates = [
            (index, item)
            for index, item in enumerate(record.memberships)
            if item.active
            and item.membership_generation == membership_generation
            and (member_kind is None or item.member_kind is member_kind)
            and (
                member_commitment_or_id is None
                or item.member_commitment_or_id == member_commitment_or_id
            )
        ]
        if len(candidates) != 1:
            raise ProjectCommandError(
                CoordinationErrorCode.MEMBER_NOT_FOUND
                if not candidates
                else CoordinationErrorCode.SELECTOR_CONFLICT
            )
        index, item = candidates[0]
        unbound = ProjectMembership(
            item.project_id,
            item.membership_generation,
            item.member_kind,
            item.member_commitment_or_id,
            item.bound_at,
            datetime.now(UTC).replace(microsecond=0),
        )
        record.memberships[index] = unbound
        await self.advance_project_generation(project_id, reason="unlink")
        return unbound

    async def coordination_grant(
        self, project_id: str, membership_generation: int
    ) -> CoordinationGrant | None:
        record = self.projects.get(project_id)
        if record is None:
            raise ProjectCommandError(CoordinationErrorCode.PROJECT_NOT_FOUND)
        return next(
            (
                item
                for item in reversed(record.grants)
                if item.membership_generation == membership_generation
            ),
            None,
        )

    async def record_coordination_grant(
        self,
        project_id: str,
        membership_generation: int,
        *,
        grant_state: GrantState,
        audit_ref: str,
    ) -> CoordinationGrant:
        record = self.projects.get(project_id)
        if record is None:
            raise ProjectCommandError(CoordinationErrorCode.PROJECT_NOT_FOUND)
        now = datetime.now(UTC).replace(microsecond=0)
        prior = await self.coordination_grant(project_id, membership_generation)
        if prior is not None and prior.state is GrantState.REVOKED:
            return prior
        grant = CoordinationGrant(
            project_id,
            membership_generation,
            grant_state,
            audit_ref,
            prior.granted_at if prior is not None else now,
            now if grant_state is GrantState.REVOKED else None,
        )
        record.grants.append(grant)
        return grant

    async def advance_project_generation(
        self, project_id: str, *, reason: str, expected_generation: int | None = None
    ) -> ProjectDescriptor:
        del reason
        record = self.projects.get(project_id)
        if record is None:
            raise ProjectCommandError(CoordinationErrorCode.PROJECT_NOT_FOUND)
        prior = record.descriptor
        if expected_generation is not None:
            if type(expected_generation) is not int or expected_generation < 1:
                raise ProjectCommandError(CoordinationErrorCode.INVALID)
            if prior.membership_generation < expected_generation:
                raise ProjectCommandError(CoordinationErrorCode.GENERATION_MISMATCH)
            if prior.membership_generation > expected_generation:
                return prior
        record.descriptor = ProjectDescriptor(
            prior.project_id,
            prior.kind,
            prior.repository_commitment,
            prior.auto_grouping,
            prior.membership_generation + 1,
            prior.title_ref,
            prior.description_ref,
            prior.created_at,
            prior.dissolved_at,
        )
        return record.descriptor

    async def set_project_auto_grouping(
        self, repository_commitment: str, *, enabled: bool
    ) -> ProjectDescriptor | None:
        descriptor = await self.repository_state(repository_commitment)
        if descriptor is None:
            self.repository_grouping_preferences[repository_commitment] = enabled
            return None
        self.repository_grouping_preferences[repository_commitment] = enabled
        if descriptor.auto_grouping is enabled:
            return descriptor
        record = self.projects[descriptor.project_id]
        record.descriptor = ProjectDescriptor(
            descriptor.project_id,
            descriptor.kind,
            descriptor.repository_commitment,
            enabled,
            descriptor.membership_generation + 1,
            descriptor.title_ref,
            descriptor.description_ref,
            descriptor.created_at,
            descriptor.dissolved_at,
        )
        return record.descriptor

    async def record_project_text_refs(
        self,
        project_id: str,
        *,
        title_ref: ProjectTextRef | None,
        description_ref: ProjectTextRef | None,
        expected_current_refs: tuple[ProjectTextRef | None, ProjectTextRef | None] | None = None,
    ) -> ProjectDescriptor:
        record = self.projects.get(project_id)
        if record is None:
            raise ProjectCommandError(CoordinationErrorCode.PROJECT_NOT_FOUND)
        prior = record.descriptor
        if expected_current_refs is not None and (
            type(expected_current_refs) is not tuple
            or len(expected_current_refs) != 2
            or prior.title_ref != expected_current_refs[0]
            or prior.description_ref != expected_current_refs[1]
        ):
            raise ProjectCommandError(CoordinationErrorCode.SELECTOR_CONFLICT)
        record.descriptor = ProjectDescriptor(
            prior.project_id,
            prior.kind,
            prior.repository_commitment,
            prior.auto_grouping,
            prior.membership_generation,
            title_ref,
            description_ref,
            prior.created_at,
            prior.dissolved_at,
        )
        return record.descriptor

    async def amend_project(
        self,
        project_id: str,
        *,
        title_ref: ProjectTextRef | None,
        description_ref: ProjectTextRef | None,
        expected_current_refs: tuple[ProjectTextRef | None, ProjectTextRef | None] | None = None,
    ) -> ProjectDescriptor:
        return await self.record_project_text_refs(
            project_id,
            title_ref=title_ref,
            description_ref=description_ref,
            expected_current_refs=expected_current_refs,
        )

    async def dissolve_project(self, project_id: str) -> ProjectDescriptor:
        record = self.projects.get(project_id)
        if record is None:
            raise ProjectCommandError(CoordinationErrorCode.PROJECT_NOT_FOUND)
        prior = record.descriptor
        if prior.dissolved_at is not None:
            return prior
        record.descriptor = ProjectDescriptor(
            prior.project_id,
            prior.kind,
            prior.repository_commitment,
            prior.auto_grouping,
            prior.membership_generation + 1,
            prior.title_ref,
            prior.description_ref,
            prior.created_at,
            datetime.now(UTC).replace(microsecond=0),
        )
        return record.descriptor

    async def task_lineage(self, task_id: str) -> TaskLineage | None:
        del task_id
        return None

    async def task_source_provenance(self, task_id: str) -> TaskSourceProvenance | None:
        return self.provenance.get(task_id)

    async def list_task_project_ids_for_consent_invalidation(self, task_id: str) -> tuple[str, ...]:
        return await self.list_task_project_ids(task_id)

    async def task_work_state(self, task_id: str) -> WorkState:
        del task_id
        return WorkState.OPEN

    async def task_session_states(self, task_id: str) -> tuple[SessionState, ...]:
        del task_id
        return ()

    async def task_route_generation(self, task_id: str) -> int:
        del task_id
        return 1

    async def task_route(self, task_id: str) -> TaskRoute | None:
        # The reference catalog intentionally has no bundle/session table.  Tests that exercise
        # production routing provide a catalog double with this method; returning no route here
        # keeps the in-memory catalog fail-closed instead of fabricating a filesystem location.
        _id(IdKind.TASK, task_id)
        return None

    async def session_binding(self, session_id: str) -> SessionBinding | None:
        del session_id
        return None


class EncryptedProjectTextStore:
    """Store project text in the owning task bundle's encrypted object store.

    The catalog keeps only :class:`ProjectTextRef`, including the owner task and route generation.
    This adapter deliberately has no in-memory plaintext cache: object staging/finalization is
    delegated to the existing vault-backed ``ObjectStorePort`` and reads verify the exact object
    envelope before decoding UTF-8 text.  Catalog retention/backup code can therefore root the
    object by the pointer's owner and generation.
    """

    def __init__(self, objects: ObjectStorePort, *, clock: ClockPort | None = None) -> None:
        self.objects = objects
        self.clock = clock

    async def put(
        self,
        project_id: str,
        field: Literal["title", "description"],
        plaintext: str,
        *,
        owner_task_id: str,
        route_generation: int,
        reserved_object_id: str | None = None,
    ) -> ProjectTextRef:
        _project(project_id)
        if field not in {"title", "description"}:
            raise ProjectCommandError(CoordinationErrorCode.INVALID)
        _id(IdKind.TASK, owner_task_id)
        if type(route_generation) is not int or route_generation < 1:
            raise ProjectCommandError(CoordinationErrorCode.INVALID)
        if type(plaintext) is not str:
            raise ProjectCommandError(CoordinationErrorCode.INVALID)
        try:
            data = plaintext.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ProjectCommandError(CoordinationErrorCode.INVALID) from exc
        metadata = ObjectMetadata(
            ObjectKind.PROJECT_TEXT,
            "text/plain",
            owner_task_id,
            _now(self.clock),
        )
        if reserved_object_id is not None:
            _id(IdKind.OBJECT, reserved_object_id)
        staged = await self.objects.stage(
            ObjectSource(data=data), metadata, object_id=reserved_object_id
        )
        try:
            reference = await self.objects.finalize(staged)
        except BaseException:
            await self.objects.abandon(staged)
            raise
        return ProjectTextRef(
            reference.object_id,
            "sha256:" + hashlib.sha256(data).hexdigest(),
            len(data),
            owner_task_id,
            route_generation,
            reference.envelope_digest,
        )

    async def read(self, reference: ProjectTextRef) -> str:
        if type(reference) is not ProjectTextRef or reference.envelope_digest is None:
            raise ProjectCommandError(CoordinationErrorCode.INVALID)
        resolved = await self.objects.resolve_verified(
            reference.object_id, reference.envelope_digest
        )
        if (
            type(resolved) is not ObjectRef
            or resolved.metadata.kind is not ObjectKind.PROJECT_TEXT
            or resolved.metadata.task_id != reference.owner_task_id
            or resolved.plaintext_size != reference.plaintext_size
        ):
            raise ProjectCommandError(CoordinationErrorCode.INVALID)
        data = bytearray()
        async for chunk in self.objects.open_verified(resolved):
            if type(chunk) is not bytes:
                raise ProjectCommandError(CoordinationErrorCode.INVALID)
            data.extend(chunk)
        payload = bytes(data)
        if "sha256:" + hashlib.sha256(payload).hexdigest() != reference.content_digest:
            raise ProjectCommandError(CoordinationErrorCode.INVALID)
        try:
            return payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ProjectCommandError(CoordinationErrorCode.INVALID) from exc


class RoutedEncryptedProjectTextStore:
    """Route encrypted project text to the task bundle named by each object reference.

    Project metadata is catalog-owned, while its text remains owned by the task bundle that
    supplied it.  The resolver is the service composition's authenticated route boundary; this
    adapter never guesses a filesystem path or falls back to the current caller's bundle.
    """

    def __init__(
        self,
        resolver: ProjectObjectStoreResolver,
        *,
        clock: ClockPort | None = None,
    ) -> None:
        if not callable(resolver):
            raise TypeError("project_object_store_resolver_invalid")
        self.resolver = resolver
        self.clock = clock

    async def _store(
        self, task_id: str, route_generation: int
    ) -> tuple[ObjectStorePort, Callable[[], Awaitable[None]]]:
        _id(IdKind.TASK, task_id)
        if type(route_generation) is not int or route_generation < 1:
            raise ProjectCommandError(CoordinationErrorCode.INVALID)
        resolved = await _awaitable(self.resolver(task_id, route_generation))
        if resolved is None:
            raise ProjectCommandError(CoordinationErrorCode.INVALID)
        if isinstance(resolved, ProjectObjectStoreLease):
            return resolved.store, lambda: _awaitable(resolved.release())
        if not callable(getattr(resolved, "resolve_verified", None)):
            raise ProjectCommandError(CoordinationErrorCode.INVALID)

        async def release() -> None:
            return None

        return resolved, release

    async def put(
        self,
        project_id: str,
        field: Literal["title", "description"],
        plaintext: str,
        *,
        owner_task_id: str,
        route_generation: int,
        reserved_object_id: str | None = None,
    ) -> ProjectTextRef:
        store, release = await self._store(owner_task_id, route_generation)
        try:
            return await EncryptedProjectTextStore(store, clock=self.clock).put(
                project_id,
                field,
                plaintext,
                owner_task_id=owner_task_id,
                route_generation=route_generation,
                reserved_object_id=reserved_object_id,
            )
        finally:
            await release()

    async def read(self, reference: ProjectTextRef) -> str:
        if type(reference) is not ProjectTextRef:
            raise ProjectCommandError(CoordinationErrorCode.INVALID)
        store, release = await self._store(reference.owner_task_id, reference.route_generation)
        try:
            return await EncryptedProjectTextStore(store, clock=self.clock).read(reference)
        finally:
            await release()


def build_routed_project_text_store(
    *,
    runtime: BundleRuntimePort,
    catalog: ProjectCatalogPort,
    clock: ClockPort | None = None,
) -> RoutedEncryptedProjectTextStore:
    """Bind project text to the ready runtime's authenticated payload route.

    The resolver checks the catalog's current task route and exact generation before acquiring a
    ``PAYLOAD_READ`` lease.  The lease is released by ``RoutedEncryptedProjectTextStore`` after
    staging/finalizing or reading the object, including failure paths.
    """

    if not callable(getattr(runtime, "route", None)) or not callable(
        getattr(runtime, "release", None)
    ):
        raise TypeError("project_runtime_invalid")
    if not callable(getattr(catalog, "task_route", None)) or not callable(
        getattr(catalog, "session_binding", None)
    ):
        raise TypeError("project_catalog_route_invalid")

    async def resolve(task_id: str, route_generation: int) -> ProjectObjectStoreLease:
        task = _id(IdKind.TASK, task_id)
        if type(route_generation) is not int or route_generation < 1:
            raise ProjectCommandError(CoordinationErrorCode.INVALID)
        route = await catalog.task_route(task)
        if (
            type(route) is not TaskRoute
            or route.task_id != task
            or route.route_generation != route_generation
            or route.state is not TaskRouteState.ACTIVE
        ):
            raise ProjectCommandError(CoordinationErrorCode.GENERATION_MISMATCH)
        binding = await catalog.session_binding(route.session_id)
        if (
            type(binding) is not SessionBinding
            or binding.task_id != task
            or binding.session_id != route.session_id
        ):
            raise ProjectCommandError(CoordinationErrorCode.INVALID)
        lease = await runtime.route(
            RouteCommand(
                route.session_id,
                binding.writer_id,
                RouteAccess.WRITE,
                frozenset({RuntimeCapability.WRITE}),
            )
        )
        if (
            type(lease) is not TaskRuntime
            or lease.task_id != task
            or lease.session_id != route.session_id
            or lease.writer_id != binding.writer_id
            or RuntimeCapability.WRITE not in lease.capabilities
        ):
            if type(lease) is TaskRuntime:
                await runtime.release(lease)
            raise ProjectCommandError(CoordinationErrorCode.INVALID)

        async def release() -> None:
            await runtime.release(lease)

        return ProjectObjectStoreLease(lease.objects, release)

    return RoutedEncryptedProjectTextStore(resolve, clock=clock)


class CoordinationGrantAuthorizer(Protocol):
    """Authenticated local consent path for a project grant or revoke.

    The body of a CLI/control request cannot carry this capability.  The service composition must
    bind this protocol to the existing trusted-local consent ceremony, where the exact project,
    generation, action, and audit record are approved together.
    """

    async def authorize(
        self,
        project_id: str,
        membership_generation: int,
        action: Literal["grant", "revoke"],
        audit_record_id: str,
    ) -> bool: ...

    async def consume(
        self,
        project_id: str,
        membership_generation: int,
        action: Literal["grant", "revoke"],
        audit_record_id: str,
    ) -> None: ...


class ProjectApplication:
    """Use-case facade for project writes, consent, and status projection."""

    def __init__(
        self,
        catalog: ProjectCatalogPort,
        *,
        ids: IdPort,
        clock: ClockPort | None = None,
        text_store: ProjectTextStore | None = None,
        workspace_consent: Callable[[str], _AwaitableValue[bool]] | None = None,
        workspace_consent_for_source: ProjectWorkspaceConsentForSource | None = None,
        grant_authorizer: CoordinationGrantAuthorizer | None = None,
        detection_store: ProjectDetectionPort | None = None,
        text_disclosure_authorizer: ProjectTextDisclosureAuthorizer | None = None,
        coordination_resource_disclosure_authorizer: CoordinationResourceDisclosureAuthorizer
        | None = None,
        coordination_source_authorizer: ProjectCoordinationSourceAuthorizer | None = None,
        operation_journal: ProjectOperationJournalPort | None = None,
        operation_digest: ProjectOperationDigest | None = None,
    ) -> None:
        # Keep composition failures at construction time.  The service has one catalog contract;
        # probing alternate method names would allow a partially upgraded adapter to look ready.
        if not callable(getattr(catalog, "project_state", None)):
            raise TypeError("project_catalog_invalid")
        self.catalog = catalog
        self.ids = ids
        self.clock = clock
        self.text_store = text_store
        # Consent is a source-workspace gate.  A missing production binder must therefore deny
        # admission rather than silently treating an unbound composition as consented.
        self.workspace_consent: Callable[[str], _AwaitableValue[bool]] = (
            workspace_consent if workspace_consent is not None else (lambda _workspace: False)
        )
        self.workspace_consent_for_source = workspace_consent_for_source
        self.grant_authorizer = grant_authorizer
        self.detection_store = detection_store
        # Coordination facts are source-owned even when the recipient is consented.  A missing
        # production binder must therefore deny admission rather than treating the source as
        # policy-authorized by default.
        self.coordination_source_authorizer: ProjectCoordinationSourceAuthorizer = (
            coordination_source_authorizer
            if coordination_source_authorizer is not None
            else _default_project_coordination_source_authorizer
        )
        # Source-owner authorization is deliberately separate from requester admission.  The
        # default keeps the existing local-human CLI path usable, while agent-context and model
        # sinks require the ready service to bind the privacy coordinator explicitly.
        self.text_disclosure_authorizer: ProjectTextDisclosureAuthorizer = (
            text_disclosure_authorizer
            if text_disclosure_authorizer is not None
            else _default_project_text_disclosure_authorizer
        )
        self._source_consent_invalidation_lock = asyncio.Lock()
        self.coordination_resource_disclosure_authorizer = (
            coordination_resource_disclosure_authorizer
        )
        self.coordination_detail_reader: CoordinationDetailReader | None = None
        self.operation_journal = operation_journal
        self.operation_digest = operation_digest

    def _project_operation_digest(self, identity: JsonValue) -> str:
        """Return the installation-keyed commitment for one request identity.

        Project titles and descriptions are part of the authenticated command, so hashing their
        canonical bytes directly would leave a low-entropy dictionary oracle in the durable
        journal.  READY binds this callback to an installation-owned MAC handle; unbound durable
        composition fails closed instead of falling back to a public hash.
        """

        digestor = self.operation_digest
        if digestor is None:
            raise ProjectCommandError(CoordinationErrorCode.INVALID)
        try:
            return validate_commitment(digestor(identity))
        except Exception as exc:
            raise ProjectCommandError(CoordinationErrorCode.INVALID) from exc

    async def _run_project_operation[T](
        self,
        *,
        operation: ProjectOperationName,
        request_id: str | None,
        identity: JsonValue,
        reserve: Mapping[str, object],
        execute: Callable[[ProjectOperationRecord | None], Awaitable[T]],
        encode: Callable[[T], JsonObject],
        decode: Callable[[bytes], T],
    ) -> T:
        """Run one mutation through the durable request journal when requested.

        Direct application callers from the pre-journal API may omit ``request_id`` and retain
        their existing behavior.  Control requests always carry one once READY binds a journal;
        this keeps the compatibility seam explicit instead of pretending an in-memory fallback
        is durable.
        """

        if request_id is None:
            return await execute(None)
        request = _id(IdKind.REQUEST, request_id)
        journal = self.operation_journal
        if journal is None:
            raise ProjectCommandError(CoordinationErrorCode.INVALID)
        try:
            digest = self._project_operation_digest(identity)
            record = await journal.reserve(
                request,
                digest,
                operation,
                **cast(Any, dict(reserve)),
            )
            if record.completed:
                if record.result_canonical is None:
                    raise ProjectCommandError(CoordinationErrorCode.INVALID)
                return decode(record.result_canonical)
            result = await execute(record)
            response = encode(result)
            await journal.complete(request, digest, canonical_encode(response))
            return result
        except ProjectOperationConflict as exc:
            raise ProjectCommandError(CoordinationErrorCode.SELECTOR_CONFLICT) from exc

    async def _replay_completed_project_operation[T](
        self,
        *,
        operation: ProjectOperationName,
        request_id: str | None,
        identity: JsonValue,
        decode: Callable[[bytes], T],
    ) -> T | None:
        """Replay a completed request before checking mutable route state.

        A completed request is already authenticated by its durable request digest and its
        structural response is immutable.  Looking it up first lets a response-loss retry remain
        valid after the source task has rotated its route generation; re-running the old command
        through current-route admission would turn a committed request into a spurious stale
        refusal.  Incomplete requests still go through ``_run_project_operation`` so recovery can
        validate the current fence and finish the recorded effect.
        """

        if request_id is None:
            return None
        journal = self.operation_journal
        if journal is None:
            return None
        request = _id(IdKind.REQUEST, request_id)
        digest = self._project_operation_digest(identity)
        try:
            record = await journal.get(request, digest)
        except ProjectOperationConflict as exc:
            raise ProjectCommandError(CoordinationErrorCode.SELECTOR_CONFLICT) from exc
        if record is None:
            return None
        if record.operation != operation:
            raise ProjectCommandError(CoordinationErrorCode.SELECTOR_CONFLICT)
        if not record.completed:
            return None
        if record.result_canonical is None:
            raise ProjectCommandError(CoordinationErrorCode.INVALID)
        return decode(record.result_canonical)

    async def _advance_project_operation(
        self,
        record: ProjectOperationRecord,
        *,
        phase: Literal["text_ready", "effect_pending"],
        title_ref: ProjectTextRef | None = None,
        description_ref: ProjectTextRef | None = None,
        project_id: str | None = None,
        member_kind: MemberKind | None = None,
        member_commitment_or_id: str | None = None,
        effect_generation: int | None = None,
        audit_record_id: str | None = None,
    ) -> ProjectOperationRecord:
        journal = self.operation_journal
        if journal is None:
            raise ProjectCommandError(CoordinationErrorCode.INVALID)
        try:
            return await journal.advance(
                record.request_id,
                record.request_digest,
                phase=phase,
                project_id=project_id,
                member_kind=member_kind,
                member_commitment_or_id=member_commitment_or_id,
                effect_generation=effect_generation,
                audit_record_id=audit_record_id,
                title_ref=title_ref,
                description_ref=description_ref,
            )
        except ProjectOperationConflict as exc:
            raise ProjectCommandError(CoordinationErrorCode.SELECTOR_CONFLICT) from exc

    @staticmethod
    def _validate_recorded_text_route(
        record: ProjectOperationRecord,
        *,
        owner_task_id: str,
        route_generation: int,
    ) -> None:
        """Reject an incomplete retry whose staged text belongs to an old route.

        Completed rows replay their immutable structural response before this check.  A
        non-completed row must finish through the exact route generation that created its staged
        object refs; otherwise retrying it could associate old ciphertext with a newly rotated
        task route.
        """

        for reference in (record.title_ref, record.description_ref):
            if reference is None:
                continue
            if (
                reference.owner_task_id != owner_task_id
                or reference.route_generation != route_generation
            ):
                raise ProjectCommandError(CoordinationErrorCode.GENERATION_MISMATCH)

    @staticmethod
    def _recorded_text_route(
        record: ProjectOperationRecord,
        *,
        owner_task_id: str,
    ) -> tuple[str, int]:
        """Recover the reservation-time text route for an incomplete create/amend.

        The route is captured before any object is finalized.  Rows written by an older journal
        that predate this fence may still recover after text staging, where the exact refs carry
        the same owner and generation; a row with no refs has no safe way to identify the route
        that owns a possibly finalized reserved object and therefore fails closed.
        """

        recorded_task = record.owner_task_id
        recorded_generation = record.owner_route_generation
        if recorded_task is not None or recorded_generation is not None:
            if (
                recorded_task is None
                or recorded_generation is None
                or recorded_task != owner_task_id
            ):
                raise ProjectCommandError(CoordinationErrorCode.GENERATION_MISMATCH)
            return recorded_task, recorded_generation
        references = tuple(
            reference
            for reference in (record.title_ref, record.description_ref)
            if reference is not None
        )
        if not references:
            raise ProjectCommandError(CoordinationErrorCode.GENERATION_MISMATCH)
        first = references[0]
        if first.owner_task_id != owner_task_id or any(
            reference.owner_task_id != first.owner_task_id
            or reference.route_generation != first.route_generation
            for reference in references[1:]
        ):
            raise ProjectCommandError(CoordinationErrorCode.GENERATION_MISMATCH)
        return first.owner_task_id, first.route_generation

    async def _source_workspace_consent(self, task_id: str, workspace: str) -> bool:
        checker = self.workspace_consent_for_source
        if checker is not None:
            return await _awaitable(checker(task_id, workspace))
        # Application-level test doubles may only know the already-authenticated commitment.
        # Ready composition always supplies the task-bound checker above.
        return await _awaitable(self.workspace_consent(workspace))

    async def plan_source_workspace_consent_invalidation(
        self, task_ids: Iterable[str], revocation_token: str
    ) -> SourceConsentRevocationPlan:
        """Snapshot active project generations affected by a source consent withdrawal.

        The caller persists this plan beside the local revoke token before applying it.  Task and
        project identities remain internal structural data; the public revoke result reports only
        the observation lifecycle.
        """

        try:
            validate_sha256_digest(revocation_token)
        except (TypeError, ValueError) as exc:
            raise ProjectCommandError(CoordinationErrorCode.INVALID) from exc
        normalized_tasks = tuple(
            sorted({_id(IdKind.TASK, value) for value in task_ids}, key=str.encode)
        )
        project_ids: set[str] = set()
        for task_id in normalized_tasks:
            project_ids.update(
                await self.catalog.list_task_project_ids_for_consent_invalidation(task_id)
            )
        generations: list[tuple[str, int]] = []
        for project_id_value in sorted(project_ids, key=str.encode):
            descriptor = await self.catalog.project_state(project_id_value)
            if descriptor is None or descriptor.dissolved_at is not None:
                continue
            generations.append((descriptor.project_id, descriptor.membership_generation))
        return SourceConsentRevocationPlan(revocation_token, tuple(generations))

    async def apply_source_workspace_consent_invalidation(
        self, plan: SourceConsentRevocationPlan
    ) -> SourceConsentRevocationPlan:
        """Advance each planned project once, tolerating replay after a crash.

        SQLite performs each generation advance in its own transaction.  The application lock
        serializes in-process revocations, while the expected-generation comparison makes a
        replay safe across service restarts or another process that already fenced the row.
        """

        if type(plan) is not SourceConsentRevocationPlan:
            raise ProjectCommandError(CoordinationErrorCode.INVALID)
        async with self._source_consent_invalidation_lock:
            for project_id_value, expected_generation in plan.project_generations:
                descriptor = await self.catalog.project_state(project_id_value)
                if descriptor is None or descriptor.dissolved_at is not None:
                    continue
                if descriptor.membership_generation < expected_generation:
                    raise ProjectCommandError(CoordinationErrorCode.GENERATION_MISMATCH)
                if descriptor.membership_generation == expected_generation:
                    await self.catalog.advance_project_generation(
                        project_id_value,
                        reason="consent-revoked",
                        expected_generation=expected_generation,
                    )
        return plan

    async def invalidate_source_workspace_consent(
        self,
        task_ids: Iterable[str],
        revocation_token: str,
        *,
        plan: SourceConsentRevocationPlan | None = None,
    ) -> SourceConsentRevocationPlan:
        """Prepare and apply one source consent fence, with an idempotent replay path."""

        selected = plan
        if selected is None:
            selected = await self.plan_source_workspace_consent_invalidation(
                task_ids, revocation_token
            )
        if selected.revocation_token != revocation_token:
            raise ProjectCommandError(CoordinationErrorCode.SELECTOR_CONFLICT)
        return await self.apply_source_workspace_consent_invalidation(selected)

    async def _coordination_source_allowed(
        self,
        task_id: str,
        workspace: str,
        project: str,
    ) -> bool:
        """Evaluate the live source-task policy for project coordination.

        The caller never supplies a policy result.  ``admit`` has already proved that ``workspace``
        is the task's current catalog provenance; this callback is only the READY-bound effective
        policy/scope authority.  Exceptions and non-boolean results are bounded denials.
        """

        try:
            return (
                await _awaitable(self.coordination_source_authorizer(task_id, workspace, project))
            ) is True
        except Exception:
            return False

    async def _text_owner_source(
        self,
        owner_task_id: str,
        route_generation: int,
    ) -> TaskSourceProvenance:
        """Resolve the owner provenance bound to an exact current text route."""

        owner = _id(IdKind.TASK, owner_task_id)
        if type(route_generation) is not int or route_generation < 1:
            raise ProjectCommandError(CoordinationErrorCode.INVALID)
        current_route = await self.catalog.task_route_generation(owner)
        if current_route != route_generation:
            raise ProjectCommandError(CoordinationErrorCode.GENERATION_MISMATCH)
        provenance = await self.catalog.task_source_provenance(owner)
        if provenance is None or provenance.workspace_ref_commitment is None:
            raise ProjectCommandError(CoordinationErrorCode.CONSENT_REQUIRED)
        if provenance.route_generation != route_generation:
            raise ProjectCommandError(CoordinationErrorCode.GENERATION_MISMATCH)
        return provenance

    async def _authorize_text_owner(
        self,
        descriptor: ProjectDescriptor,
        *,
        owner_task_id: str,
        route_generation: int,
        initial_general_project: bool = False,
    ) -> TaskSourceProvenance:
        """Bind project text ownership to the current task source and project authority.

        A newly-created general project is the one deliberate chicken-and-egg exception: its
        maintainer creates the project before a membership row and generation grant can exist.
        Every later general-project amendment/read requires ordinary admission.  Repository
        projects instead bind text ownership to the trusted repository identity.
        """

        provenance = await self._text_owner_source(owner_task_id, route_generation)
        if descriptor.kind is ProjectKind.REPOSITORY:
            if provenance.repository_privacy_commitment != descriptor.repository_commitment:
                raise ProjectCommandError(CoordinationErrorCode.CONSENT_REQUIRED)
            return provenance
        if descriptor.kind is not ProjectKind.GENERAL:
            raise ProjectCommandError(CoordinationErrorCode.INVALID)
        if initial_general_project:
            return provenance
        await self.admit(
            source_task_id=owner_task_id,
            source_workspace_commitment=cast(str, provenance.workspace_ref_commitment),
            project=descriptor.project_id,
            expected_generation=descriptor.membership_generation,
        )
        return provenance

    async def _authorize_grant(
        self,
        project_id_value: str,
        generation: int,
        action: Literal["grant", "revoke"],
        audit_record_id: str,
    ) -> bool:
        authorizer = self.grant_authorizer
        if authorizer is None:
            return False
        return (
            await authorizer.authorize(project_id_value, generation, action, audit_record_id)
            is True
        )

    async def _consume_grant_handoff(
        self,
        project_id_value: str,
        generation: int,
        audit_record_id: str,
    ) -> None:
        """Reconcile a committed grant's owner-only consent handoff when supported."""

        authorizer = self.grant_authorizer
        consume = None if authorizer is None else getattr(authorizer, "consume", None)
        if callable(consume):
            await cast(Callable[[str, int, Literal["grant"], str], Awaitable[object]], consume)(
                project_id_value, generation, "grant", audit_record_id
            )

    async def _text_ref(
        self,
        project: str,
        kind: Literal["title", "description"],
        plaintext: str | None,
        *,
        owner_task_id: str,
        route_generation: int,
        reserved_object_id: str | None = None,
    ) -> ProjectTextRef | None:
        if plaintext is None:
            return None
        if self.text_store is None:
            raise ProjectCommandError(CoordinationErrorCode.INVALID)
        kwargs: dict[str, object] = {
            "owner_task_id": owner_task_id,
            "route_generation": route_generation,
        }
        if reserved_object_id is not None:
            kwargs["reserved_object_id"] = reserved_object_id
        try:
            return await cast(Callable[..., Awaitable[ProjectTextRef]], self.text_store.put)(
                project,
                kind,
                plaintext,
                **kwargs,
            )
        except TypeError as exc:
            # Small pre-journal test doubles may implement the old text-store signature.  They
            # remain valid for unjournaled calls, while a durable operation must fail closed when
            # its store cannot honor the reserved-object fence.
            if reserved_object_id is None:
                raise
            raise ProjectCommandError(CoordinationErrorCode.INVALID) from exc

    async def _project_or_error(self, value: str) -> ProjectDescriptor:
        result = await self.catalog.project_state(value)
        if result is None:
            raise ProjectCommandError(CoordinationErrorCode.PROJECT_NOT_FOUND)
        if type(result) is not ProjectDescriptor:
            raise ProjectCommandError(CoordinationErrorCode.INVALID)
        return result

    async def create(
        self,
        command: CreateProjectCommand | None = None,
        *,
        title: str | None = None,
        description: str | None = None,
        auto_grouping: bool = False,
        owner_task_id: str | None = None,
        owner_route_generation: int | None = None,
        request_id: str | None = None,
    ) -> ProjectDescriptor:
        if command is None:
            if title is None:
                raise ProjectCommandError(CoordinationErrorCode.INVALID)
            command = CreateProjectCommand(
                title,
                description,
                auto_grouping,
                owner_task_id,
                owner_route_generation,
            )
        if type(command) is not CreateProjectCommand:
            raise ProjectCommandError(CoordinationErrorCode.INVALID)
        assert command.owner_task_id is not None
        owner_task = command.owner_task_id
        replayed = await self._replay_completed_project_operation(
            operation="create",
            request_id=request_id,
            identity=_project_operation_identity(
                "create",
                title=command.title,
                description=command.description,
                auto_grouping=command.auto_grouping,
                owner_task_id=owner_task,
                owner_route_generation=command.owner_route_generation,
            ),
            decode=_descriptor_from_wire,
        )
        if replayed is not None:
            return replayed
        current_route_generation = await self.catalog.task_route_generation(command.owner_task_id)
        owner_route_generation = (
            current_route_generation
            if command.owner_route_generation is None
            else command.owner_route_generation
        )
        if current_route_generation != owner_route_generation:
            raise ProjectCommandError(CoordinationErrorCode.GENERATION_MISMATCH)
        # The initial general-project write is the sole pre-membership exception.  Resolve the
        # authenticated source now so an arbitrary task id cannot become the durable text owner;
        # membership and grant authority are established by the subsequent explicit link flow.
        await self._text_owner_source(owner_task, owner_route_generation)

        reserved_project_id = _project_id_from_ids(self.ids) if request_id is not None else None
        reserved_title_object_id = (
            _id(IdKind.OBJECT, self.ids.new(IdKind.OBJECT)) if request_id is not None else None
        )
        reserved_description_object_id = (
            _id(IdKind.OBJECT, self.ids.new(IdKind.OBJECT))
            if request_id is not None and command.description is not None
            else None
        )

        async def execute(record: ProjectOperationRecord | None) -> ProjectDescriptor:
            identifier = (
                _project_id_from_ids(self.ids) if record is None else record.reserved_project_id
            )
            if identifier is None:
                raise ProjectCommandError(CoordinationErrorCode.INVALID)
            effective_owner_task = owner_task
            effective_route_generation = owner_route_generation
            if record is not None:
                effective_owner_task, effective_route_generation = self._recorded_text_route(
                    record,
                    owner_task_id=owner_task,
                )
                self._validate_recorded_text_route(
                    record,
                    owner_task_id=effective_owner_task,
                    route_generation=effective_route_generation,
                )
                # A reserved row may have no refs even though its object was finalized before a
                # crash.  Revalidate the reservation fence before reusing that object id.
                await self._text_owner_source(effective_owner_task, effective_route_generation)
            title_ref = None if record is None else record.title_ref
            if title_ref is None:
                title_ref = await self._text_ref(
                    identifier,
                    "title",
                    command.title,
                    owner_task_id=effective_owner_task,
                    route_generation=effective_route_generation,
                    reserved_object_id=(
                        None if record is None else record.reserved_title_object_id
                    ),
                )
            description_ref = None if record is None else record.description_ref
            if command.description is not None and description_ref is None:
                description_ref = await self._text_ref(
                    identifier,
                    "description",
                    command.description,
                    owner_task_id=effective_owner_task,
                    route_generation=effective_route_generation,
                    reserved_object_id=(
                        None if record is None else record.reserved_description_object_id
                    ),
                )
            if record is not None:
                record = await self._advance_project_operation(
                    record,
                    phase="text_ready",
                    title_ref=title_ref,
                    description_ref=description_ref,
                )
                await self._text_owner_source(effective_owner_task, effective_route_generation)
            created = await self.catalog.project_state(identifier)
            if created is None:
                created = await self.catalog.create_general_project(
                    identifier, auto_grouping=command.auto_grouping
                )
            if type(created) is not ProjectDescriptor:
                raise ProjectCommandError(CoordinationErrorCode.INVALID)
            if created.kind is not ProjectKind.GENERAL or created.dissolved_at is not None:
                raise ProjectCommandError(CoordinationErrorCode.SELECTOR_CONFLICT)
            # Keep the explicit initial general-project exception visible at the project boundary.
            await self._authorize_text_owner(
                created,
                owner_task_id=effective_owner_task,
                route_generation=effective_route_generation,
                initial_general_project=True,
            )
            if record is not None:
                await self._advance_project_operation(record, phase="effect_pending")
            if created.title_ref is not None or created.description_ref is not None:
                if created.title_ref != title_ref or created.description_ref != description_ref:
                    raise ProjectCommandError(CoordinationErrorCode.SELECTOR_CONFLICT)
                return created
            return await self.catalog.record_project_text_refs(
                identifier,
                title_ref=title_ref,
                description_ref=description_ref,
                expected_current_refs=((created.title_ref, created.description_ref)),
            )

        return await self._run_project_operation(
            operation="create",
            request_id=request_id,
            identity=_project_operation_identity(
                "create",
                title=command.title,
                description=command.description,
                auto_grouping=command.auto_grouping,
                owner_task_id=owner_task,
                owner_route_generation=command.owner_route_generation,
            ),
            reserve={
                "owner_task_id": owner_task,
                "owner_route_generation": owner_route_generation,
                "reserved_project_id": reserved_project_id,
                "reserved_title_object_id": reserved_title_object_id,
                "reserved_description_object_id": reserved_description_object_id,
            },
            execute=execute,
            encode=lambda result: result.as_wire(),
            decode=_descriptor_from_wire,
        )

    async def _general_membership_conflict(
        self, descriptor: ProjectDescriptor, command: LinkProjectCommand
    ) -> bool:
        if descriptor.kind is not ProjectKind.GENERAL:
            return False
        project_ids = await self.catalog.list_project_ids()
        other: list[tuple[str, MemberKind, str]] = []
        provenance: dict[str, tuple[str, str | None, str | None]] = {}

        async def remember(task_id: str) -> None:
            if task_id in provenance:
                return
            source = await self.catalog.task_source_provenance(task_id)
            if source is None:
                provenance[task_id] = (task_id, None, None)
                return
            provenance[task_id] = (
                task_id,
                source.repository_privacy_commitment,
                source.workspace_ref_commitment,
            )

        if command.member_kind is MemberKind.TASK:
            await remember(command.member_commitment_or_id)
        elif command.member_kind is MemberKind.REPOSITORY:
            for task_id in await self.catalog.list_repository_task_ids(
                command.member_commitment_or_id
            ):
                await remember(task_id)
        else:
            for task_id in await self.catalog.list_workspace_task_ids(
                command.member_commitment_or_id
            ):
                await remember(task_id)
        for other_project_id in project_ids:
            if other_project_id == descriptor.project_id:
                continue
            other_project = await self.catalog.project_state(other_project_id)
            if (
                other_project is None
                or other_project.kind is not ProjectKind.GENERAL
                or other_project.dissolved_at is not None
            ):
                continue
            for item in await self.catalog.project_memberships(other_project_id):
                if not item.active:
                    continue
                other.append((other_project_id, item.member_kind, item.member_commitment_or_id))
                if item.member_kind is MemberKind.TASK:
                    await remember(item.member_commitment_or_id)
                elif item.member_kind is MemberKind.REPOSITORY:
                    for task_id in await self.catalog.list_repository_task_ids(
                        item.member_commitment_or_id
                    ):
                        await remember(task_id)
                else:
                    for task_id in await self.catalog.list_workspace_task_ids(
                        item.member_commitment_or_id
                    ):
                        await remember(task_id)
        return general_link_conflicts(
            target_project_id=descriptor.project_id,
            member_kind=command.member_kind,
            member=command.member_commitment_or_id,
            other_memberships=other,
            provenance=provenance.values(),
        )

    async def link(
        self,
        command: LinkProjectCommand | None = None,
        *,
        request_id: str | None = None,
        **kwargs: object,
    ) -> ProjectMembership:
        if command is None:
            try:
                command = LinkProjectCommand(
                    cast(str, kwargs["project_id"]),
                    cast(MemberKind, kwargs["member_kind"]),
                    cast(str, kwargs["member_commitment_or_id"]),
                    cast(str | None, kwargs.get("source_workspace_commitment")),
                    cast(str | None, kwargs.get("member_repository_commitment")),
                    cast(int | None, kwargs.get("expected_generation")),
                )
            except KeyError as exc:
                raise ProjectCommandError(CoordinationErrorCode.INVALID) from exc
        if type(command) is not LinkProjectCommand:
            raise ProjectCommandError(CoordinationErrorCode.INVALID)

        async def execute(record: ProjectOperationRecord | None) -> ProjectMembership:
            # A response can be lost after the catalog transaction commits.  Resolve the exact
            # active membership before re-running consent/grant checks; those checks may have
            # changed while the caller was retrying, but the same request must replay its effect.
            if record is not None and record.effect_generation is not None:
                current_members = await self.catalog.project_memberships(command.project_id)
                existing = [
                    item
                    for item in current_members
                    if item.membership_generation == record.effect_generation
                    and item.member_kind is command.member_kind
                    and item.member_commitment_or_id == command.member_commitment_or_id
                ]
                if len(existing) == 1:
                    return existing[0]
            descriptor = await self._project_or_error(command.project_id)
            if descriptor.dissolved_at is not None:
                raise ProjectCommandError(CoordinationErrorCode.PROJECT_DISSOLVED)
            if descriptor.kind is not ProjectKind.GENERAL:
                raise ProjectCommandError(CoordinationErrorCode.INVALID)
            if (
                command.expected_generation is not None
                and command.expected_generation != descriptor.membership_generation
            ):
                raise ProjectCommandError(CoordinationErrorCode.GENERATION_MISMATCH)
            # A general project is a cross-source coordination surface even before its first
            # member is attached.  The local-human grant is checked against the generation being
            # mutated; record_project_membership then advances the generation and fences future
            # deliveries.
            await self.require_grant(descriptor.project_id, descriptor.membership_generation)
            if await self._general_membership_conflict(descriptor, command):
                raise ProjectCommandError(CoordinationErrorCode.GENERAL_MEMBERSHIP_CONFLICT)
            if command.member_kind is MemberKind.REPOSITORY:
                target_repository = (
                    command.member_repository_commitment or command.member_commitment_or_id
                )
                current_members = await self.catalog.project_memberships(descriptor.project_id)
                has_other_repository = any(
                    item.active
                    and item.member_kind is MemberKind.REPOSITORY
                    and item.member_commitment_or_id != target_repository
                    for item in current_members
                )
                if has_other_repository:
                    await self.require_grant(
                        descriptor.project_id, descriptor.membership_generation
                    )
            if (
                command.member_kind is MemberKind.TASK
                and command.source_workspace_commitment is None
            ):
                raise ProjectCommandError(CoordinationErrorCode.CONSENT_REQUIRED)
            if command.member_kind is MemberKind.TASK:
                assert command.source_workspace_commitment is not None
                provenance = await self.catalog.task_source_provenance(
                    command.member_commitment_or_id
                )
                if (
                    provenance is None
                    or provenance.workspace_ref_commitment != command.source_workspace_commitment
                ):
                    raise ProjectCommandError(CoordinationErrorCode.CONSENT_REQUIRED)
            if command.source_workspace_commitment is not None:
                consent = await self._source_workspace_consent(
                    command.member_commitment_or_id,
                    command.source_workspace_commitment,
                )
                if consent is not True:
                    raise ProjectCommandError(CoordinationErrorCode.CONSENT_REQUIRED)
            membership = ProjectMembership(
                descriptor.project_id,
                descriptor.membership_generation,
                command.member_kind,
                command.member_commitment_or_id,
                _now(self.clock),
            )
            if record is not None:
                await self._advance_project_operation(
                    record,
                    phase="effect_pending",
                    # Membership rows use the next project generation.  Persist that expected
                    # post-effect generation before the catalog write so a crash between the
                    # catalog commit and the journal update can still identify the exact row.
                    effect_generation=descriptor.membership_generation + 1,
                )
            try:
                membership = await self.catalog.record_project_membership(
                    descriptor.project_id,
                    member_kind=membership.member_kind,
                    member_commitment_or_id=membership.member_commitment_or_id,
                )
            except PublicOperationError as exc:
                if (
                    exc.safe_details.get("reason_code")
                    == CoordinationErrorCode.GENERAL_MEMBERSHIP_CONFLICT.value
                ):
                    raise ProjectCommandError(
                        CoordinationErrorCode.GENERAL_MEMBERSHIP_CONFLICT
                    ) from exc
                raise
            if (
                record is not None
                and membership.membership_generation != descriptor.membership_generation + 1
            ):
                await self._advance_project_operation(
                    record,
                    phase="effect_pending",
                    effect_generation=membership.membership_generation,
                )
            return membership

        return await self._run_project_operation(
            operation="link",
            request_id=request_id,
            identity=_project_operation_identity(
                "link",
                project_id=command.project_id,
                member_kind=command.member_kind.value,
                member_commitment_or_id=command.member_commitment_or_id,
                source_workspace_commitment=command.source_workspace_commitment,
                member_repository_commitment=command.member_repository_commitment,
                expected_generation=command.expected_generation,
            ),
            reserve={
                "project_id": command.project_id,
                "member_kind": command.member_kind,
                "member_commitment_or_id": command.member_commitment_or_id,
            },
            execute=execute,
            encode=lambda result: result.as_wire(),
            decode=_membership_from_wire,
        )

    async def unlink(
        self,
        command: ProjectUnlinkCommand | None = None,
        *,
        request_id: str | None = None,
        **kwargs: object,
    ) -> ProjectMembership:
        if command is None:
            try:
                command = ProjectUnlinkCommand(
                    cast(str, kwargs["project_id"]),
                    cast(MemberKind, kwargs["member_kind"]),
                    cast(str, kwargs["member_commitment_or_id"]),
                    cast(int | None, kwargs.get("expected_generation")),
                )
            except KeyError as exc:
                raise ProjectCommandError(CoordinationErrorCode.INVALID) from exc
        if type(command) is not ProjectUnlinkCommand:
            raise ProjectCommandError(CoordinationErrorCode.INVALID)

        async def execute(record: ProjectOperationRecord | None) -> ProjectMembership:
            memberships = await self.catalog.project_memberships(command.project_id)
            if record is not None and record.effect_generation is not None:
                prior = [
                    item
                    for item in memberships
                    if not item.active
                    and item.membership_generation == record.effect_generation
                    and item.member_kind is command.member_kind
                    and item.member_commitment_or_id == command.member_commitment_or_id
                ]
                if len(prior) == 1:
                    return prior[0]
            descriptor = await self._project_or_error(command.project_id)
            if descriptor.dissolved_at is not None:
                raise ProjectCommandError(CoordinationErrorCode.PROJECT_DISSOLVED)
            if (
                command.expected_generation is not None
                and command.expected_generation != descriptor.membership_generation
            ):
                raise ProjectCommandError(CoordinationErrorCode.GENERATION_MISMATCH)
            selected = [
                item
                for item in memberships
                if item.active
                and item.member_kind is command.member_kind
                and item.member_commitment_or_id == command.member_commitment_or_id
            ]
            if len(selected) != 1:
                raise ProjectCommandError(CoordinationErrorCode.MEMBER_NOT_FOUND)
            if record is not None:
                await self._advance_project_operation(
                    record,
                    phase="effect_pending",
                    effect_generation=selected[0].membership_generation,
                )
            # The selector is part of the same catalog transaction where supported.  It prevents
            # a reused binding generation from unbinding a different member during recovery.
            unbind = cast(
                Callable[..., Awaitable[ProjectMembership]], self.catalog.unbind_project_membership
            )
            try:
                return await unbind(
                    command.project_id,
                    selected[0].membership_generation,
                    member_kind=command.member_kind,
                    member_commitment_or_id=command.member_commitment_or_id,
                )
            except TypeError:
                return await unbind(command.project_id, selected[0].membership_generation)

        return await self._run_project_operation(
            operation="unlink",
            request_id=request_id,
            identity=_project_operation_identity(
                "unlink",
                project_id=command.project_id,
                member_kind=command.member_kind.value,
                member_commitment_or_id=command.member_commitment_or_id,
                expected_generation=command.expected_generation,
            ),
            reserve={
                "project_id": command.project_id,
                "member_kind": command.member_kind,
                "member_commitment_or_id": command.member_commitment_or_id,
            },
            execute=execute,
            encode=lambda result: result.as_wire(),
            decode=_membership_from_wire,
        )

    async def amend(
        self,
        command: ProjectAmendCommand | None = None,
        *,
        request_id: str | None = None,
        **kwargs: object,
    ) -> ProjectDescriptor:
        if command is None:
            try:
                command = ProjectAmendCommand(
                    cast(str, kwargs["project_id"]),
                    cast(str | None, kwargs.get("title")),
                    cast(str | None, kwargs.get("description")),
                    cast(str | None, kwargs.get("owner_task_id")),
                    cast(int | None, kwargs.get("owner_route_generation")),
                )
            except KeyError as exc:
                raise ProjectCommandError(CoordinationErrorCode.INVALID) from exc
        if type(command) is not ProjectAmendCommand:
            raise ProjectCommandError(CoordinationErrorCode.INVALID)
        assert command.owner_task_id is not None
        owner_task = command.owner_task_id
        replayed = await self._replay_completed_project_operation(
            operation="amend",
            request_id=request_id,
            identity=_project_operation_identity(
                "amend",
                project_id=command.project_id,
                title=command.title,
                description=command.description,
                owner_task_id=owner_task,
                owner_route_generation=command.owner_route_generation,
            ),
            decode=_descriptor_from_wire,
        )
        if replayed is not None:
            return replayed
        current_route_generation = await self.catalog.task_route_generation(owner_task)
        owner_route_generation = (
            current_route_generation
            if command.owner_route_generation is None
            else command.owner_route_generation
        )
        if current_route_generation != owner_route_generation:
            raise ProjectCommandError(CoordinationErrorCode.GENERATION_MISMATCH)
        baseline_descriptor = await self._project_or_error(command.project_id)
        reserved_title_object_id = (
            _id(IdKind.OBJECT, self.ids.new(IdKind.OBJECT))
            if request_id is not None and command.title is not None
            else None
        )
        reserved_description_object_id = (
            _id(IdKind.OBJECT, self.ids.new(IdKind.OBJECT))
            if request_id is not None and command.description is not None
            else None
        )

        async def execute(record: ProjectOperationRecord | None) -> ProjectDescriptor:
            descriptor = await self._project_or_error(command.project_id)
            effective_owner_task = owner_task
            effective_route_generation = owner_route_generation
            if record is not None:
                effective_owner_task, effective_route_generation = self._recorded_text_route(
                    record,
                    owner_task_id=owner_task,
                )
                self._validate_recorded_text_route(
                    record,
                    owner_task_id=effective_owner_task,
                    route_generation=effective_route_generation,
                )
            await self._authorize_text_owner(
                descriptor,
                owner_task_id=effective_owner_task,
                route_generation=effective_route_generation,
            )
            if record is not None:
                changed_states: list[str] = []
                if command.title is not None:
                    if record.title_ref is not None and descriptor.title_ref == record.title_ref:
                        changed_states.append("new")
                    elif descriptor.title_ref == record.prior_title_ref:
                        changed_states.append("prior")
                    else:
                        changed_states.append("conflict")
                if command.description is not None:
                    if (
                        record.description_ref is not None
                        and descriptor.description_ref == record.description_ref
                    ):
                        changed_states.append("new")
                    elif descriptor.description_ref == record.prior_description_ref:
                        changed_states.append("prior")
                    else:
                        changed_states.append("conflict")
                if any(state == "conflict" for state in changed_states) or (
                    any(state == "new" for state in changed_states)
                    and not all(state == "new" for state in changed_states)
                ):
                    raise ProjectCommandError(CoordinationErrorCode.SELECTOR_CONFLICT)
                if changed_states and all(state == "new" for state in changed_states):
                    return descriptor
            title_ref = (
                descriptor.title_ref
                if command.title is None
                else (None if record is None or record.title_ref is None else record.title_ref)
            )
            description_ref = (
                descriptor.description_ref
                if command.description is None
                else (
                    None
                    if record is None or record.description_ref is None
                    else record.description_ref
                )
            )
            if command.title is not None and title_ref is None:
                title_ref = await self._text_ref(
                    command.project_id,
                    "title",
                    command.title,
                    owner_task_id=effective_owner_task,
                    route_generation=effective_route_generation,
                    reserved_object_id=(
                        None if record is None else record.reserved_title_object_id
                    ),
                )
            if command.description is not None and description_ref is None:
                description_ref = await self._text_ref(
                    command.project_id,
                    "description",
                    command.description,
                    owner_task_id=effective_owner_task,
                    route_generation=effective_route_generation,
                    reserved_object_id=(
                        None if record is None else record.reserved_description_object_id
                    ),
                )
            if record is not None:
                await self._advance_project_operation(
                    record,
                    phase="text_ready",
                    title_ref=title_ref if command.title is not None else None,
                    description_ref=description_ref if command.description is not None else None,
                )
                await self._text_owner_source(effective_owner_task, effective_route_generation)
                await self._advance_project_operation(record, phase="effect_pending")
            # On recovery the catalog may already contain the exact references.  Returning it is
            # safe only after checking both pointers; a different request must not be mistaken
            # for this request's committed effect.
            if descriptor.title_ref == title_ref and descriptor.description_ref == description_ref:
                return descriptor
            return await self.catalog.amend_project(
                command.project_id,
                title_ref=title_ref,
                description_ref=description_ref,
                expected_current_refs=(descriptor.title_ref, descriptor.description_ref),
            )

        return await self._run_project_operation(
            operation="amend",
            request_id=request_id,
            identity=_project_operation_identity(
                "amend",
                project_id=command.project_id,
                title=command.title,
                description=command.description,
                owner_task_id=owner_task,
                owner_route_generation=command.owner_route_generation,
            ),
            reserve={
                "project_id": command.project_id,
                "owner_task_id": owner_task,
                "owner_route_generation": owner_route_generation,
                "reserved_title_object_id": reserved_title_object_id,
                "reserved_description_object_id": reserved_description_object_id,
                "prior_title_ref": (
                    baseline_descriptor.title_ref if command.title is not None else None
                ),
                "prior_description_ref": (
                    baseline_descriptor.description_ref if command.description is not None else None
                ),
            },
            execute=execute,
            encode=lambda result: result.as_wire(),
            decode=_descriptor_from_wire,
        )

    async def dissolve(
        self,
        command: ProjectDissolveCommand | None = None,
        *,
        request_id: str | None = None,
        **kwargs: object,
    ) -> ProjectDescriptor:
        if command is None:
            try:
                command = ProjectDissolveCommand(
                    cast(str, kwargs["project_id"]),
                    cast(int | None, kwargs.get("expected_generation")),
                )
            except KeyError as exc:
                raise ProjectCommandError(CoordinationErrorCode.INVALID) from exc
        if type(command) is not ProjectDissolveCommand:
            raise ProjectCommandError(CoordinationErrorCode.INVALID)

        async def execute(record: ProjectOperationRecord | None) -> ProjectDescriptor:
            descriptor = await self._project_or_error(command.project_id)
            if descriptor.kind is ProjectKind.REPOSITORY:
                # Repository grouping persists once born. Its reversible control is opt-out/opt-in;
                # dissolving it would leave a tombstone blocking later implicit project admission.
                raise ProjectCommandError(CoordinationErrorCode.IMPLICIT_PROJECT_REQUIRES_OPT_OUT)
            if descriptor.dissolved_at is not None:
                return descriptor
            if (
                command.expected_generation is not None
                and command.expected_generation != descriptor.membership_generation
            ):
                raise ProjectCommandError(CoordinationErrorCode.GENERATION_MISMATCH)
            if record is not None:
                await self._advance_project_operation(
                    record,
                    phase="effect_pending",
                    effect_generation=descriptor.membership_generation,
                )
            return await self.catalog.dissolve_project(command.project_id)

        return await self._run_project_operation(
            operation="dissolve",
            request_id=request_id,
            identity=_project_operation_identity(
                "dissolve",
                project_id=command.project_id,
                expected_generation=command.expected_generation,
            ),
            reserve={"project_id": command.project_id},
            execute=execute,
            encode=lambda result: result.as_wire(),
            decode=_descriptor_from_wire,
        )

    async def set_auto_grouping(
        self,
        repository_commitment: str,
        enabled: bool,
        *,
        request_id: str | None = None,
    ) -> ProjectDescriptor | None:
        repository = _commitment(repository_commitment)
        if type(enabled) is not bool:
            raise ProjectCommandError(CoordinationErrorCode.INVALID)
        operation: ProjectOperationName = "opt_in" if enabled else "opt_out"

        async def execute(_record: ProjectOperationRecord | None) -> ProjectDescriptor | None:
            descriptor = await self.catalog.repository_state(repository)
            if descriptor is not None and descriptor.kind is not ProjectKind.REPOSITORY:
                raise ProjectCommandError(CoordinationErrorCode.INVALID)
            # A pre-birth opt-out does not materialize an implicit project merely to save the
            # preference; the next birth reads this durable setting.
            return await self.catalog.set_project_auto_grouping(repository, enabled=enabled)

        return await self._run_project_operation(
            operation=operation,
            request_id=request_id,
            identity=_project_operation_identity(
                operation,
                repository_commitment=repository,
                enabled=enabled,
            ),
            reserve={},
            execute=execute,
            encode=lambda result: _auto_grouping_wire(repository, enabled, result),
            decode=_auto_grouping_from_wire,
        )

    async def opt_out(
        self,
        command: ProjectOptCommand | str | None = None,
        *,
        request_id: str | None = None,
        **kwargs: object,
    ) -> ProjectDescriptor | None:
        if command is None:
            try:
                command = ProjectOptCommand(cast(str, kwargs["repository_commitment"]))
            except KeyError as exc:
                raise ProjectCommandError(CoordinationErrorCode.INVALID) from exc
        if type(command) is str:
            command = ProjectOptCommand(command)
        if type(command) is not ProjectOptCommand:
            raise ProjectCommandError(CoordinationErrorCode.INVALID)
        return await self.set_auto_grouping(
            command.repository_commitment, False, request_id=request_id
        )

    async def opt_in(
        self,
        command: ProjectOptCommand | str | None = None,
        *,
        request_id: str | None = None,
        **kwargs: object,
    ) -> ProjectDescriptor | None:
        if command is None:
            try:
                command = ProjectOptCommand(cast(str, kwargs["repository_commitment"]))
            except KeyError as exc:
                raise ProjectCommandError(CoordinationErrorCode.INVALID) from exc
        if type(command) is str:
            command = ProjectOptCommand(command)
        if type(command) is not ProjectOptCommand:
            raise ProjectCommandError(CoordinationErrorCode.INVALID)
        return await self.set_auto_grouping(
            command.repository_commitment, True, request_id=request_id
        )

    async def grant(
        self,
        command: ProjectGrantCommand | None = None,
        *,
        request_id: str | None = None,
        **kwargs: object,
    ) -> CoordinationGrant:
        if command is None:
            try:
                command = ProjectGrantCommand(
                    cast(str, kwargs["project_id"]),
                    cast(int, kwargs["membership_generation"]),
                    cast(str | None, kwargs.get("audit_record_id")),
                )
            except KeyError as exc:
                raise ProjectCommandError(CoordinationErrorCode.INVALID) from exc
        if type(command) is not ProjectGrantCommand:
            raise ProjectCommandError(CoordinationErrorCode.INVALID)
        audit_record_id = command.audit_record_id
        if audit_record_id is None:
            descriptor_for_audit = await self._project_or_error(command.project_id)
            resolver = (
                None
                if self.grant_authorizer is None
                else getattr(self.grant_authorizer, "recover_audit_record_id", None)
            )
            recovered_audit = None
            if callable(resolver):
                candidate = await cast(Callable[[str, int], Awaitable[object]], resolver)(
                    descriptor_for_audit.project_id, command.membership_generation
                )
                if type(candidate) is str and candidate:
                    recovered_audit = candidate
            audit_record_id = recovered_audit or _audit_id(self.ids)

        async def execute(record: ProjectOperationRecord | None) -> CoordinationGrant:
            descriptor = await self._project_or_error(command.project_id)
            if command.membership_generation != descriptor.membership_generation:
                raise ProjectCommandError(CoordinationErrorCode.GENERATION_MISMATCH)
            resolved_audit = audit_record_id
            effective_audit = (
                resolved_audit
                if record is None or record.audit_record_id is None
                else record.audit_record_id
            )
            assert effective_audit is not None
            # A successful grant is idempotent for the same live generation. Check the durable
            # catalog before consuming a one-use consent handoff so a response-loss retry does not
            # demand a second approval.
            existing = await self.catalog.coordination_grant(
                descriptor.project_id, descriptor.membership_generation
            )
            if existing is not None:
                if existing.active:
                    await self._consume_grant_handoff(
                        descriptor.project_id, descriptor.membership_generation, effective_audit
                    )
                    return existing
                raise ProjectCommandError(CoordinationErrorCode.GRANT_REVOKED)
            if not await self._authorize_grant(
                descriptor.project_id,
                descriptor.membership_generation,
                "grant",
                effective_audit,
            ):
                raise ProjectCommandError(CoordinationErrorCode.GRANT_REQUIRED)
            if record is not None:
                await self._advance_project_operation(
                    record,
                    phase="effect_pending",
                    effect_generation=descriptor.membership_generation,
                    audit_record_id=effective_audit,
                )
            grant = await self.catalog.record_coordination_grant(
                descriptor.project_id,
                descriptor.membership_generation,
                grant_state=GrantState.ACTIVE,
                audit_ref=effective_audit,
            )
            await self._consume_grant_handoff(
                descriptor.project_id, descriptor.membership_generation, effective_audit
            )
            return grant

        return await self._run_project_operation(
            operation="grant",
            request_id=request_id,
            identity=_project_operation_identity(
                "grant",
                project_id=command.project_id,
                membership_generation=command.membership_generation,
                audit_record_id=command.audit_record_id,
            ),
            reserve={
                "project_id": command.project_id,
                "effect_generation": command.membership_generation,
                "audit_record_id": audit_record_id,
            },
            execute=execute,
            encode=lambda result: result.as_wire(),
            decode=_grant_from_wire,
        )

    async def revoke(
        self,
        command: ProjectRevokeCommand | None = None,
        *,
        request_id: str | None = None,
        **kwargs: object,
    ) -> CoordinationGrant:
        if command is None:
            try:
                command = ProjectRevokeCommand(
                    cast(str, kwargs["project_id"]),
                    cast(int, kwargs["membership_generation"]),
                    cast(str | None, kwargs.get("audit_record_id")),
                )
            except KeyError as exc:
                raise ProjectCommandError(CoordinationErrorCode.INVALID) from exc
        if type(command) is not ProjectRevokeCommand:
            raise ProjectCommandError(CoordinationErrorCode.INVALID)

        async def execute(record: ProjectOperationRecord | None) -> CoordinationGrant:
            descriptor = await self._project_or_error(command.project_id)
            existing = await self.catalog.coordination_grant(
                command.project_id, command.membership_generation
            )
            # Reconcile a crash after the grant row changed but before the generation fence.  A
            # completed revoke must remain replayable even though the project descriptor has
            # already advanced beyond the request's original generation.
            if record is not None and existing is not None and not existing.active:
                if descriptor.membership_generation == command.membership_generation:
                    await self.catalog.advance_project_generation(
                        descriptor.project_id,
                        reason="revoke",
                        expected_generation=command.membership_generation,
                    )
                elif descriptor.membership_generation < command.membership_generation:
                    raise ProjectCommandError(CoordinationErrorCode.GENERATION_MISMATCH)
                return existing
            if command.membership_generation != descriptor.membership_generation:
                raise ProjectCommandError(CoordinationErrorCode.GENERATION_MISMATCH)
            if existing is None or not existing.active:
                raise ProjectCommandError(CoordinationErrorCode.GRANT_REQUIRED)
            # A revoke tightens the existing grant in place. The catalog row is keyed by the
            # original grant audit identity so a repeat cannot replace it while changing state.
            audit_record_id = existing.audit_record_id
            if record is not None:
                await self._advance_project_operation(
                    record,
                    phase="effect_pending",
                    effect_generation=descriptor.membership_generation,
                    audit_record_id=audit_record_id,
                )
            grant = await self.catalog.record_coordination_grant(
                descriptor.project_id,
                descriptor.membership_generation,
                grant_state=GrantState.REVOKED,
                audit_ref=audit_record_id,
            )
            await self.catalog.advance_project_generation(
                descriptor.project_id,
                reason="revoke",
                expected_generation=descriptor.membership_generation,
            )
            return grant

        return await self._run_project_operation(
            operation="revoke",
            request_id=request_id,
            identity=_project_operation_identity(
                "revoke",
                project_id=command.project_id,
                membership_generation=command.membership_generation,
                audit_record_id=command.audit_record_id,
            ),
            reserve={
                "project_id": command.project_id,
                "effect_generation": command.membership_generation,
                "audit_record_id": command.audit_record_id,
            },
            execute=execute,
            encode=lambda result: result.as_wire(),
            decode=_grant_from_wire,
        )

    async def require_grant(self, project: str, generation: int) -> CoordinationGrant:
        descriptor = await self._project_or_error(project)
        grant = await self.catalog.coordination_grant(project, generation)
        if grant is None or not coordination_generation_is_current(
            generation, descriptor.membership_generation, grant_active=grant.active
        ):
            raise ProjectCommandError(CoordinationErrorCode.GRANT_REQUIRED)
        return grant

    async def current_generation(self, project: str) -> int:
        """Read the current project generation for bounded delivery diagnostics."""

        return (await self._project_or_error(project)).membership_generation

    async def admit_cross_repository_child(
        self,
        parent_task_id: str,
        child_repository_commitment: str,
    ) -> LineageProjectAdmission:
        """Authorize a cross-repository parent reference before the child task exists.

        Delegation reserves the child before its task route and workspace provenance are written,
        so the project must be selected from the parent's trusted provenance and prelinked
        repository memberships.  A current general-project grant is the only authority that can
        cross this boundary; caller supplied project ids, repository aliases, or a boolean consent
        flag are never accepted.  The child workspace consent is checked later, when its route
        binds the child provenance, before any child facts can be read.
        """

        parent = _id(IdKind.TASK, parent_task_id)
        child_repository = _commitment(child_repository_commitment)
        provenance = await self.catalog.task_source_provenance(parent)
        if (
            provenance is None
            or provenance.repository_privacy_commitment is None
            or provenance.workspace_ref_commitment is None
            or provenance.repository_privacy_commitment == child_repository
            or await self._source_workspace_consent(parent, provenance.workspace_ref_commitment)
            is not True
        ):
            raise ProjectCommandError(CoordinationErrorCode.CROSS_REPOSITORY_LINEAGE)

        list_projects = getattr(self.catalog, "list_project_ids", None)
        if not callable(list_projects):
            raise ProjectCommandError(CoordinationErrorCode.CROSS_REPOSITORY_LINEAGE)
        try:
            project_ids = await cast(Callable[[], Awaitable[tuple[str, ...]]], list_projects)()
        except Exception as exc:
            raise ProjectCommandError(CoordinationErrorCode.CROSS_REPOSITORY_LINEAGE) from exc

        for project_value in sorted(set(project_ids), key=str.encode):
            descriptor = await self.catalog.project_state(project_value)
            if (
                descriptor is None
                or descriptor.kind is not ProjectKind.GENERAL
                or descriptor.dissolved_at is not None
            ):
                continue
            memberships = await self.catalog.project_memberships(project_value)
            repositories = {
                item.member_commitment_or_id
                for item in memberships
                if item.active and item.member_kind is MemberKind.REPOSITORY
            }
            if (
                provenance.repository_privacy_commitment not in repositories
                or child_repository not in repositories
            ):
                continue
            grant = await self.catalog.coordination_grant(
                project_value, descriptor.membership_generation
            )
            if grant is None or not coordination_generation_is_current(
                descriptor.membership_generation,
                descriptor.membership_generation,
                grant_active=grant.active,
            ):
                continue
            # The shared result type is owned by the lineage coordinator.  Resolve it lazily to
            # keep this application module independent from the coordinator implementation while
            # still returning a closed, typed authority object in READY.
            from finishup.application.lineage import LineageProjectAdmission

            return LineageProjectAdmission(project_value, descriptor.membership_generation)
        raise ProjectCommandError(CoordinationErrorCode.CROSS_REPOSITORY_LINEAGE)

    async def current_route_generation(self, task: str) -> int:
        """Return the task route generation used to bind encrypted coordination details."""

        return await self.catalog.task_route_generation(_id(IdKind.TASK, task))

    async def _coordination_participants_for(
        self, detection_id: str
    ) -> tuple[CoordinationParticipant, CoordinationParticipant] | None:
        """Load the durable source snapshots that authenticate a detection projection."""

        store = self.detection_store
        loader = None if store is None else getattr(store, "participants", None)
        if not callable(loader):
            return None
        try:
            participants = await cast(Callable[[str], Awaitable[object | None]], loader)(
                detection_id
            )
        except (CoordinationError, ProjectCommandError):
            return None
        from finishup.application.coordination import CoordinationParticipant

        if type(participants) is not tuple:
            return None
        typed_participants = cast(
            tuple[CoordinationParticipant, CoordinationParticipant], participants
        )
        if (
            len(typed_participants) != 2
            or any(type(item) is not CoordinationParticipant for item in typed_participants)
            or typed_participants[0].task_id == typed_participants[1].task_id
        ):
            return None
        return typed_participants

    async def project_detections_for(
        self,
        project: str,
        *,
        visible_task_ids: Iterable[str],
        expected_generation: int,
    ) -> tuple[CoordinationDetection, ...]:
        """Return current detections whose two admitted tasks are visible to the requester."""

        project_id_value = _project(project)
        if type(expected_generation) is not int or expected_generation < 1:
            raise ProjectCommandError(CoordinationErrorCode.INVALID)
        generation = expected_generation
        store = self.detection_store
        if store is None:
            return ()
        visible = {_id(IdKind.TASK, value) for value in visible_task_ids}
        detections = await store.list_detections(project_id_value)
        admitted: list[CoordinationDetection] = []
        for item in detections:
            if (
                type(item) is not CoordinationDetection
                or item.project_id != project_id_value
                or item.membership_generation != generation
                or not item.generation_valid
                or item.left_task_id not in visible
                or item.right_task_id not in visible
            ):
                continue
            participant_rows = await self._coordination_participants_for(item.detection_id)
            if participant_rows is None:
                continue
            participant_by_task = {entry.task_id: entry for entry in participant_rows}
            if set(participant_by_task) != {item.left_task_id, item.right_task_id} or any(
                entry.project_id != project_id_value for entry in participant_rows
            ):
                continue
            left_snapshot = participant_by_task[item.left_task_id]
            right_snapshot = participant_by_task[item.right_task_id]
            left = await self.catalog.task_source_provenance(item.left_task_id)
            right = await self.catalog.task_source_provenance(item.right_task_id)
            if (
                left is None
                or right is None
                or left.workspace_ref_commitment is None
                or right.workspace_ref_commitment is None
                or left.workspace_ref_commitment != left_snapshot.workspace_commitment
                or right.workspace_ref_commitment != right_snapshot.workspace_commitment
                or left.repository_privacy_commitment != left_snapshot.repository_commitment
                or right.repository_privacy_commitment != right_snapshot.repository_commitment
            ):
                continue
            cross_repository = (
                left.repository_privacy_commitment != right.repository_privacy_commitment
            )
            try:
                await self.admit(
                    source_task_id=item.left_task_id,
                    source_workspace_commitment=left.workspace_ref_commitment,
                    project=project_id_value,
                    expected_generation=generation,
                    expected_route_generation=left_snapshot.route_generation,
                    expected_repository_commitment=left_snapshot.repository_commitment,
                    cross_repository=cross_repository,
                )
                await self.admit(
                    source_task_id=item.right_task_id,
                    source_workspace_commitment=right.workspace_ref_commitment,
                    project=project_id_value,
                    expected_generation=generation,
                    expected_route_generation=right_snapshot.route_generation,
                    expected_repository_commitment=right_snapshot.repository_commitment,
                    cross_repository=cross_repository,
                )
            except CoordinationError:
                # A status projection cannot turn a stale grant or withdrawn source consent into
                # a partially visible detection.  The durable row remains available for audit.
                continue
            admitted.append(item)
        current: list[CoordinationDetection] = []
        for item in admitted:
            participant_rows = await self._coordination_participants_for(item.detection_id)
            if participant_rows is None:
                continue
            participant_by_task = {entry.task_id: entry for entry in participant_rows}
            if set(participant_by_task) != {item.left_task_id, item.right_task_id}:
                continue
            left_snapshot = participant_by_task[item.left_task_id]
            right_snapshot = participant_by_task[item.right_task_id]
            left = await self.catalog.task_source_provenance(item.left_task_id)
            right = await self.catalog.task_source_provenance(item.right_task_id)
            cross_repository = bool(
                left is not None
                and right is not None
                and left.repository_privacy_commitment != right.repository_privacy_commitment
            )
            if await self._sources_current_at_generation(
                (item.left_task_id, item.right_task_id),
                project=project_id_value,
                generation=generation,
                cross_repository=cross_repository,
                expected_route_generations={
                    item.left_task_id: left_snapshot.route_generation,
                    item.right_task_id: right_snapshot.route_generation,
                },
                expected_repository_commitments={
                    item.left_task_id: left_snapshot.repository_commitment,
                    item.right_task_id: right_snapshot.repository_commitment,
                },
            ):
                current.append(item)
        return tuple(sorted(current, key=lambda item: item.detection_id.encode()))

    async def coordination_advice_for(
        self,
        requester_task_id: str,
        *,
        project: str,
        expected_generation: int | None = None,
    ) -> tuple[CoordinationAdvice, ...]:
        """Return only the two currently admitted advice deliveries for a project.

        Durable detection rows are a count/status projection.  Advice is consumable only when
        both source and recipient are still admitted at the same generation, and both target
        delivery rows exist.  Rechecking each task here makes consent withdrawal and grant
        revocation take effect before a status or hook consumer receives a counterpart identity.
        """

        # Keep the application modules acyclic at import time; the concrete advice type is only
        # needed while a composed coordination runtime is serving this read.
        from finishup.application.coordination import CoordinationAdvice as _CoordinationAdvice

        requester = _id(IdKind.TASK, requester_task_id)
        project_id_value = _project(project)
        descriptor = await self._project_or_error(project_id_value)
        generation = descriptor.membership_generation
        if expected_generation is not None and expected_generation != generation:
            raise ProjectCommandError(CoordinationErrorCode.GRANT_REVOKED)
        requester_provenance = await self.catalog.task_source_provenance(requester)
        if requester_provenance is None or requester_provenance.workspace_ref_commitment is None:
            raise ProjectCommandError(CoordinationErrorCode.CONSENT_REQUIRED)
        requester_route_generation = requester_provenance.route_generation
        try:
            await self.admit(
                source_task_id=requester,
                source_workspace_commitment=requester_provenance.workspace_ref_commitment,
                project=project_id_value,
                expected_generation=generation,
                expected_route_generation=requester_route_generation,
                expected_repository_commitment=requester_provenance.repository_privacy_commitment,
            )
        except ProjectCommandError as error:
            # Advice is a read of currently deliverable rows.  A withdrawn source consent or
            # revoked/missing generation therefore yields an empty page, so callers cannot
            # mistake a stale delivery for actionable current advice.
            if error.code in {
                CoordinationErrorCode.CONSENT_REQUIRED,
                CoordinationErrorCode.GRANT_REQUIRED,
                CoordinationErrorCode.GRANT_REVOKED,
                CoordinationErrorCode.GENERATION_MISMATCH,
            }:
                return ()
            raise
        store = self.detection_store
        list_detections = None if store is None else getattr(store, "list_detections", None)
        deliveries_for = None if store is None else getattr(store, "deliveries", None)
        advice_for = None if store is None else getattr(store, "advice_for", None)
        if not all(callable(item) for item in (list_detections, deliveries_for, advice_for)):
            return ()
        detections = await cast(
            Callable[[str], Awaitable[tuple[CoordinationDetection, ...]]], list_detections
        )(project_id_value)
        advice_rows: list[CoordinationAdvice] = []
        for detection in detections:
            if (
                type(detection) is not CoordinationDetection
                or detection.project_id != project_id_value
                or detection.membership_generation != generation
                or not detection.generation_valid
            ):
                continue
            participant_rows = await self._coordination_participants_for(detection.detection_id)
            if participant_rows is None:
                continue
            participant_by_task = {entry.task_id: entry for entry in participant_rows}
            if set(participant_by_task) != {
                detection.left_task_id,
                detection.right_task_id,
            } or any(entry.project_id != project_id_value for entry in participant_rows):
                continue
            left_snapshot = participant_by_task[detection.left_task_id]
            right_snapshot = participant_by_task[detection.right_task_id]
            deliveries = await cast(Callable[[str], Awaitable[tuple[object, ...]]], deliveries_for)(
                detection.detection_id
            )
            if (
                len(deliveries) != 2
                or {getattr(item, "target_task_id", None) for item in deliveries}
                != {detection.left_task_id, detection.right_task_id}
                or any(
                    getattr(item, "outcome", None) not in {"delivered", "duplicate"}
                    for item in deliveries
                )
            ):
                continue
            left = await self.catalog.task_source_provenance(detection.left_task_id)
            right = await self.catalog.task_source_provenance(detection.right_task_id)
            if (
                left is None
                or right is None
                or left.workspace_ref_commitment is None
                or right.workspace_ref_commitment is None
                or left.workspace_ref_commitment != left_snapshot.workspace_commitment
                or right.workspace_ref_commitment != right_snapshot.workspace_commitment
                or left.repository_privacy_commitment != left_snapshot.repository_commitment
                or right.repository_privacy_commitment != right_snapshot.repository_commitment
            ):
                continue
            cross_repository = (
                left.repository_privacy_commitment != right.repository_privacy_commitment
            )
            try:
                await self.admit(
                    source_task_id=left.task_id,
                    source_workspace_commitment=left.workspace_ref_commitment,
                    project=project_id_value,
                    expected_generation=generation,
                    expected_route_generation=left_snapshot.route_generation,
                    expected_repository_commitment=left_snapshot.repository_commitment,
                    cross_repository=cross_repository,
                )
                await self.admit(
                    source_task_id=right.task_id,
                    source_workspace_commitment=right.workspace_ref_commitment,
                    project=project_id_value,
                    expected_generation=generation,
                    expected_route_generation=right_snapshot.route_generation,
                    expected_repository_commitment=right_snapshot.repository_commitment,
                    cross_repository=cross_repository,
                )
                left_advice = await cast(
                    Callable[[str, str], Awaitable[object | None]], advice_for
                )(detection.detection_id, detection.left_task_id)
                right_advice = await cast(
                    Callable[[str, str], Awaitable[object | None]], advice_for
                )(detection.detection_id, detection.right_task_id)
                if not await self._sources_current_at_generation(
                    (detection.left_task_id, detection.right_task_id),
                    project=project_id_value,
                    generation=generation,
                    cross_repository=cross_repository,
                    expected_route_generations={
                        detection.left_task_id: left_snapshot.route_generation,
                        detection.right_task_id: right_snapshot.route_generation,
                    },
                    expected_repository_commitments={
                        detection.left_task_id: left_snapshot.repository_commitment,
                        detection.right_task_id: right_snapshot.repository_commitment,
                    },
                ):
                    continue
            except ProjectCommandError:
                continue
            if (
                type(left_advice) is not _CoordinationAdvice
                or type(right_advice) is not _CoordinationAdvice
            ):
                continue
            if (
                getattr(left_advice, "project_id", None) != project_id_value
                or getattr(right_advice, "project_id", None) != project_id_value
                or getattr(left_advice, "membership_generation", None) != generation
                or getattr(right_advice, "membership_generation", None) != generation
            ):
                continue
            advice_rows.extend((left_advice, right_advice))
        if not await self._source_current_at_generation(
            requester,
            project=project_id_value,
            generation=generation,
            expected_route_generation=requester_route_generation,
            expected_repository_commitment=requester_provenance.repository_privacy_commitment,
        ):
            return ()
        if advice_rows and not await self._sources_current_at_generation(
            {item.target_task_id for item in advice_rows},
            project=project_id_value,
            generation=generation,
        ):
            return ()
        latest = await self._project_or_error(project_id_value)
        if latest.dissolved_at is not None or latest.membership_generation != generation:
            raise ProjectCommandError(CoordinationErrorCode.GRANT_REVOKED)
        return tuple(
            sorted(
                advice_rows,
                key=lambda item: (item.detection_id.encode(), item.target_task_id.encode()),
            )
        )

    async def coordination_resource_detail_for(
        self,
        requester_task_id: str,
        *,
        project: str,
        detection_id: str,
        sink: LocalDisclosureSink,
        expected_generation: int | None = None,
    ) -> CoordinationResourceProjection | None:
        """Hydrate one detection's relative resources after both-side admission.

        Detection rows contain only repository-bound digests.  The raw declarations live in the
        source-owned encrypted detail object and are read only for a participant that is itself
        currently admitted.  The source-owner policy callback is deliberately separate from the
        recipient projection: the latter still classifies every returned path and may omit it
        when the recipient sink does not permit ``repository_excerpt``.
        """

        from finishup.application.coordination import (
            CoordinationDetection,
            CoordinationResourceProjection,
        )

        requester = _id(IdKind.TASK, requester_task_id)
        project_id_value = _project(project)
        if type(sink) is not LocalDisclosureSink:
            raise ProjectCommandError(CoordinationErrorCode.INVALID)
        descriptor = await self._project_or_error(project_id_value)
        generation = descriptor.membership_generation
        if expected_generation is not None and expected_generation != generation:
            raise ProjectCommandError(CoordinationErrorCode.GRANT_REVOKED)
        store = self.detection_store
        loader = None if store is None else getattr(store, "get_detection", None)
        if not callable(loader):
            return None
        try:
            detection = await cast(Callable[[str], Awaitable[object | None]], loader)(detection_id)
        except (CoordinationError, ProjectCommandError):
            return None
        if (
            type(detection) is not CoordinationDetection
            or detection.project_id != project_id_value
            or detection.membership_generation != generation
            or detection.left_task_id == detection.right_task_id
            or requester not in {detection.left_task_id, detection.right_task_id}
            or not detection.generation_valid
            or detection.detail_ref is None
        ):
            return None
        counterpart = (
            detection.right_task_id
            if requester == detection.left_task_id
            else detection.left_task_id
        )
        participants = (requester, counterpart)
        participant_rows = await self._coordination_participants_for(detection.detection_id)
        if participant_rows is None:
            return CoordinationResourceProjection(
                detection.detection_id,
                project_id_value,
                generation,
                counterpart,
                None,
                False,
            )
        participant_by_task = {entry.task_id: entry for entry in participant_rows}
        if set(participant_by_task) != set(participants) or any(
            entry.project_id != project_id_value for entry in participant_rows
        ):
            return CoordinationResourceProjection(
                detection.detection_id,
                project_id_value,
                generation,
                counterpart,
                None,
                False,
            )
        provenance_values: list[TaskSourceProvenance | None] = []
        for participant in participants:
            provenance_values.append(await self.catalog.task_source_provenance(participant))
        provenances = tuple(provenance_values)
        if any(item is None or item.workspace_ref_commitment is None for item in provenances):
            return CoordinationResourceProjection(
                detection.detection_id,
                project_id_value,
                generation,
                counterpart,
                None,
                False,
            )
        if any(
            provenance.repository_privacy_commitment
            != participant_by_task[participant].repository_commitment
            or provenance.workspace_ref_commitment
            != participant_by_task[participant].workspace_commitment
            for participant, provenance in zip(participants, provenances, strict=True)
            if provenance is not None
        ):
            return CoordinationResourceProjection(
                detection.detection_id,
                project_id_value,
                generation,
                counterpart,
                None,
                False,
            )
        typed_provenances = tuple(
            cast(TaskSourceProvenance, provenance) for provenance in provenances
        )
        cross_repository = (
            typed_provenances[0].repository_privacy_commitment
            != typed_provenances[1].repository_privacy_commitment
        )
        for participant, provenance in zip(participants, typed_provenances, strict=True):
            try:
                await self.admit(
                    source_task_id=participant,
                    source_workspace_commitment=cast(str, provenance.workspace_ref_commitment),
                    project=project_id_value,
                    expected_generation=generation,
                    expected_route_generation=participant_by_task[participant].route_generation,
                    expected_repository_commitment=participant_by_task[
                        participant
                    ].repository_commitment,
                    cross_repository=cross_repository,
                )
            except ProjectCommandError:
                return CoordinationResourceProjection(
                    detection.detection_id,
                    project_id_value,
                    generation,
                    counterpart,
                    None,
                    False,
                )
        reference = detection.detail_ref
        assert reference is not None
        owner = reference.owner_task_id
        if owner not in participants:
            return CoordinationResourceProjection(
                detection.detection_id,
                project_id_value,
                generation,
                counterpart,
                None,
                False,
            )
        owner_index = participants.index(owner)
        owner_provenance = typed_provenances[owner_index]
        owner_snapshot = participant_by_task[owner]
        if (
            owner_provenance.workspace_ref_commitment is None
            or owner_provenance.route_generation != reference.route_generation
            or owner_snapshot.route_generation != reference.route_generation
            or await self.catalog.task_route_generation(owner) != reference.route_generation
        ):
            return CoordinationResourceProjection(
                detection.detection_id,
                project_id_value,
                generation,
                counterpart,
                None,
                False,
            )

        async def resource_policy_allowed() -> bool:
            authorizer = self.coordination_resource_disclosure_authorizer
            try:
                if authorizer is None:
                    # The local human renderer has the established source-text callback.
                    # Agent/model sinks fail closed until READY binds the category-aware source
                    # policy.
                    if sink is not LocalDisclosureSink.LOCAL_HUMAN_VIEW:
                        return False
                    allowed = True
                    for participant, provenance in zip(
                        participants,
                        typed_provenances,
                        strict=True,
                    ):
                        workspace = provenance.workspace_ref_commitment
                        if workspace is None:
                            allowed = False
                            continue
                        if (
                            await _awaitable(
                                self.text_disclosure_authorizer(
                                    participant,
                                    workspace,
                                    "description",
                                    sink,
                                    "coordination-resource",
                                )
                            )
                            is not True
                        ):
                            allowed = False
                    return allowed
                # The detail object contains both participants' declared resources.  The source
                # policy therefore has to authorize both workspaces; checking only the encrypted
                # object's owner would let one permissive source carry another source's paths.
                allowed = True
                for participant, provenance in zip(
                    participants,
                    typed_provenances,
                    strict=True,
                ):
                    workspace = provenance.workspace_ref_commitment
                    if workspace is None:
                        allowed = False
                        continue
                    if (
                        await _awaitable(
                            authorizer(
                                participant,
                                workspace,
                                sink,
                                "coordination-resource",
                            )
                        )
                        is not True
                    ):
                        allowed = False
                return allowed
            except Exception:
                return False

        allowed = await resource_policy_allowed()
        if allowed is not True:
            return CoordinationResourceProjection(
                detection.detection_id,
                project_id_value,
                generation,
                counterpart,
                None,
                False,
            )
        reader = self.coordination_detail_reader
        if reader is None:
            return CoordinationResourceProjection(
                detection.detection_id,
                project_id_value,
                generation,
                counterpart,
                None,
                False,
            )
        try:
            details = await reader.read_details(reference)
            left_values = details.get("left_resources")
            right_values = details.get("right_resources")
            if type(left_values) is not tuple or type(right_values) is not tuple:
                raise ValueError("coordination_detail_resources_invalid")
            left_resources = tuple(
                relative_resource_identity(item) for item in left_values if type(item) is str
            )
            right_resources = tuple(
                relative_resource_identity(item) for item in right_values if type(item) is str
            )
            if len(left_resources) != len(left_values) or len(right_resources) != len(right_values):
                raise ValueError("coordination_detail_resources_invalid")
            case_sensitive_value = details.get("case_sensitive", True)
            if type(case_sensitive_value) is not bool:
                raise ValueError("coordination_detail_case_mode_invalid")
            if case_sensitive_value:
                overlap = tuple(sorted(set(left_resources) & set(right_resources), key=str.encode))
            else:
                left_by_folded = {item.casefold(): item for item in left_resources}
                overlap = tuple(
                    sorted(
                        (
                            left_by_folded[item]
                            for item in {value.casefold() for value in right_resources}
                            if item in left_by_folded
                        ),
                        key=str.encode,
                    )
                )
            if not overlap:
                raise ValueError("coordination_detail_overlap_missing")
            repository = typed_provenances[0].repository_privacy_commitment
            if repository != typed_provenances[1].repository_privacy_commitment:
                raise ValueError("coordination_detail_cross_repository")
            resource_ids = {
                canonical_resource_identity(
                    item,
                    repository_commitment=cast(str, repository),
                    case_sensitive=case_sensitive_value,
                )
                for item in overlap
            }
            if not resource_ids <= set(detection.resource_identities):
                raise ValueError("coordination_detail_identity_mismatch")
        except (CoordinationError, ProjectCommandError, TypeError, ValueError):
            return CoordinationResourceProjection(
                detection.detection_id,
                project_id_value,
                generation,
                counterpart,
                None,
                False,
            )
        # The object read may yield across a policy or consent transition.  Re-run the exact
        # source category gate after decryption before returning any relative path.
        if not await resource_policy_allowed():
            return CoordinationResourceProjection(
                detection.detection_id,
                project_id_value,
                generation,
                counterpart,
                None,
                False,
            )
        for participant, provenance in zip(participants, typed_provenances, strict=True):
            try:
                await self.admit(
                    source_task_id=participant,
                    source_workspace_commitment=cast(str, provenance.workspace_ref_commitment),
                    project=project_id_value,
                    expected_generation=generation,
                    expected_route_generation=participant_by_task[participant].route_generation,
                    expected_repository_commitment=participant_by_task[
                        participant
                    ].repository_commitment,
                    cross_repository=cross_repository,
                )
            except ProjectCommandError:
                return CoordinationResourceProjection(
                    detection.detection_id,
                    project_id_value,
                    generation,
                    counterpart,
                    None,
                    False,
                )
        owner_provenance_after = await self.catalog.task_source_provenance(owner)
        owner_route_after = await self.catalog.task_route_generation(owner)
        if (
            owner_provenance_after is None
            or owner_provenance_after.route_generation != reference.route_generation
            or owner_provenance_after.workspace_ref_commitment
            != owner_provenance.workspace_ref_commitment
            or owner_route_after != reference.route_generation
        ):
            return CoordinationResourceProjection(
                detection.detection_id,
                project_id_value,
                generation,
                counterpart,
                None,
                False,
            )
        latest = await self._project_or_error(project_id_value)
        if latest.dissolved_at is not None or latest.membership_generation != generation:
            return CoordinationResourceProjection(
                detection.detection_id,
                project_id_value,
                generation,
                counterpart,
                None,
                False,
            )
        return CoordinationResourceProjection(
            detection.detection_id,
            project_id_value,
            generation,
            counterpart,
            overlap,
            True,
        )

    async def coordination_coverage_for(
        self,
        requester_task_id: str,
        *,
        project: str,
        expected_generation: int | None = None,
    ) -> tuple[CoordinationCoverage, ...]:
        """Return current per-task coordination coverage after source admission.

        ``unobservable`` rows describe only a consented task's inability to reveal attributable
        paths.  They are not detections and therefore never expose a counterpart or resource
        identity.  Re-admitting every row's source before returning it keeps a revoked or
        dissolved project inert on the public status path.
        """

        from finishup.application.coordination import CoordinationCoverage as _CoordinationCoverage

        requester = _id(IdKind.TASK, requester_task_id)
        project_id_value = _project(project)
        descriptor = await self._project_or_error(project_id_value)
        generation = descriptor.membership_generation
        if expected_generation is not None and expected_generation != generation:
            raise ProjectCommandError(CoordinationErrorCode.GRANT_REVOKED)
        requester_provenance = await self.catalog.task_source_provenance(requester)
        if requester_provenance is None or requester_provenance.workspace_ref_commitment is None:
            raise ProjectCommandError(CoordinationErrorCode.CONSENT_REQUIRED)
        requester_route_generation = requester_provenance.route_generation
        try:
            await self.admit(
                source_task_id=requester,
                source_workspace_commitment=requester_provenance.workspace_ref_commitment,
                project=project_id_value,
                expected_generation=generation,
                expected_route_generation=requester_route_generation,
                expected_repository_commitment=requester_provenance.repository_privacy_commitment,
            )
        except ProjectCommandError:
            return ()
        store = self.detection_store
        coverage_for = None if store is None else getattr(store, "coverage_for", None)
        if not callable(coverage_for):
            return ()
        rows = await cast(Callable[[str, int], Awaitable[tuple[object, ...]]], coverage_for)(
            project_id_value, generation
        )
        visible: list[CoordinationCoverage] = []
        expected_route_generations = {requester: requester_route_generation}
        expected_repository_commitments: dict[str, str] = {}
        if requester_provenance.repository_privacy_commitment is not None:
            expected_repository_commitments[requester] = (
                requester_provenance.repository_privacy_commitment
            )
        for row in rows:
            if (
                type(row) is not _CoordinationCoverage
                or row.project_id != project_id_value
                or row.membership_generation != generation
            ):
                continue
            provenance = await self.catalog.task_source_provenance(row.task_id)
            if provenance is None or provenance.workspace_ref_commitment is None:
                continue
            try:
                await self.admit(
                    source_task_id=row.task_id,
                    source_workspace_commitment=provenance.workspace_ref_commitment,
                    project=project_id_value,
                    expected_generation=generation,
                    expected_route_generation=provenance.route_generation,
                    expected_repository_commitment=provenance.repository_privacy_commitment,
                )
            except ProjectCommandError:
                continue
            visible.append(row)
            expected_route_generations[row.task_id] = provenance.route_generation
            if provenance.repository_privacy_commitment is not None:
                expected_repository_commitments[row.task_id] = (
                    provenance.repository_privacy_commitment
                )
        if not await self._source_current_at_generation(
            requester,
            project=project_id_value,
            generation=generation,
            expected_route_generation=requester_route_generation,
            expected_repository_commitment=requester_provenance.repository_privacy_commitment,
        ):
            return ()
        if not await self._sources_current_at_generation(
            (requester, *(row.task_id for row in visible)),
            project=project_id_value,
            generation=generation,
            expected_route_generations=expected_route_generations,
            expected_repository_commitments=expected_repository_commitments,
        ):
            return ()
        latest = await self._project_or_error(project_id_value)
        if latest.dissolved_at is not None or latest.membership_generation != generation:
            return ()
        return tuple(sorted(visible, key=lambda item: item.task_id.encode()))

    async def _admit_text_source(
        self,
        reference: ProjectTextRef,
        *,
        project: str,
        field: Literal["title", "description"],
        expected_generation: int,
    ) -> str:
        """Authorize the owner workspace and route for a project text reference.

        Repository text owners must remain in the repository identified by the project and on the
        exact route that wrote the reference.  A general-project owner must also be a currently
        admitted member under the live generation grant; unlinking the owner therefore closes the
        source path even if the encrypted object is retained for audit/recovery.
        """

        if type(reference) is not ProjectTextRef:
            raise ProjectCommandError(CoordinationErrorCode.INVALID)
        owner = _id(IdKind.TASK, reference.owner_task_id)
        descriptor = await self._project_or_error(project)
        provenance = await self._authorize_text_owner(
            descriptor,
            owner_task_id=owner,
            route_generation=reference.route_generation,
        )
        workspace = cast(str, provenance.workspace_ref_commitment)
        consent = await self._source_workspace_consent(owner, workspace)
        if consent is not True:
            raise ProjectCommandError(CoordinationErrorCode.CONSENT_REQUIRED)
        if descriptor.membership_generation != expected_generation:
            raise ProjectCommandError(CoordinationErrorCode.GRANT_REVOKED)
        current_ref = descriptor.title_ref if field == "title" else descriptor.description_ref
        if current_ref != reference:
            # Amendments retain the project generation, so generation alone cannot fence a stale
            # text cursor.  Bind the read to the exact catalog pointer before opening the object.
            raise ProjectCommandError(CoordinationErrorCode.GENERATION_MISMATCH)
        return workspace

    async def project_text_for_sink(
        self,
        requester_task_id: str,
        *,
        project: str,
        field: Literal["title", "description"],
        sink: LocalDisclosureSink,
        purpose: str = "project-source-text",
        expected_generation: int | None = None,
        expected_reference: ProjectTextRef | None = None,
    ) -> str | None:
        """Read project text only after requester and source-owner disclosure gates.

        ``text_disclosure_authorizer`` is called with the source owner, workspace commitment,
        field, resolved sink, and purpose.  A generic requester projection is never accepted as
        that source-owner decision; the ready service should bind this callback to
        ``PrivacyCoordinator.prepare_local_disclosure`` (or an equivalent owner-scoped policy
        adapter) so ``TASK_DESCRIPTION`` is checked under the owner's effective policy.
        """

        requester = _id(IdKind.TASK, requester_task_id)
        project_id_value = _project(project)
        if field not in {"title", "description"} or type(sink) is not LocalDisclosureSink:
            raise ProjectCommandError(CoordinationErrorCode.INVALID)
        _bounded_text(purpose, required=True)
        descriptor = await self._project_or_error(project_id_value)
        generation = descriptor.membership_generation
        if expected_generation is not None and expected_generation != generation:
            raise ProjectCommandError(CoordinationErrorCode.GRANT_REVOKED)
        requester_provenance = await self.catalog.task_source_provenance(requester)
        if requester_provenance is None or requester_provenance.workspace_ref_commitment is None:
            raise ProjectCommandError(CoordinationErrorCode.CONSENT_REQUIRED)
        await self.admit(
            source_task_id=requester,
            source_workspace_commitment=requester_provenance.workspace_ref_commitment,
            project=project_id_value,
            expected_generation=generation,
        )
        reference = descriptor.title_ref if field == "title" else descriptor.description_ref
        if expected_reference is not None and reference != expected_reference:
            raise ProjectCommandError(CoordinationErrorCode.GENERATION_MISMATCH)
        if reference is None:
            return None
        owner_workspace = await self._admit_text_source(
            reference,
            project=project_id_value,
            field=field,
            expected_generation=generation,
        )
        authorized = await _awaitable(
            self.text_disclosure_authorizer(
                reference.owner_task_id,
                owner_workspace,
                field,
                sink,
                purpose,
            )
        )
        if authorized is not True:
            raise ProjectCommandError(CoordinationErrorCode.CONSENT_REQUIRED)
        if self.text_store is None:
            raise ProjectCommandError(CoordinationErrorCode.INVALID)
        value = await self.text_store.read(reference)
        latest = await self._project_or_error(project_id_value)
        latest_ref = latest.title_ref if field == "title" else latest.description_ref
        owner_route_after = await self.catalog.task_route_generation(reference.owner_task_id)
        if (
            latest.membership_generation != generation
            or latest_ref != reference
            or (expected_reference is not None and latest_ref != expected_reference)
            or owner_route_after != reference.route_generation
        ):
            raise ProjectCommandError(CoordinationErrorCode.GRANT_REVOKED)
        return value

    async def read_authorized_project_text(
        self,
        requester_task_id: str,
        *,
        project: str,
        field: Literal["title", "description"],
        sink: LocalDisclosureSink,
        purpose: str = "project-source-text",
        expected_generation: int | None = None,
        expected_reference: ProjectTextRef | None = None,
    ) -> str | None:
        """Compatibility name for the source-authorized project text read seam."""

        return await self.project_text_for_sink(
            requester_task_id,
            project=project,
            field=field,
            sink=sink,
            purpose=purpose,
            expected_generation=expected_generation,
            expected_reference=expected_reference,
        )

    async def project_text_for(
        self,
        requester_task_id: str,
        *,
        project: str,
        field: Literal["title", "description"],
        expected_generation: int | None = None,
        expected_reference: ProjectTextRef | None = None,
    ) -> str | None:
        """Read one project text value for the authenticated local-human view."""

        return await self.project_text_for_sink(
            requester_task_id,
            project=project,
            field=field,
            sink=LocalDisclosureSink.LOCAL_HUMAN_VIEW,
            purpose="project-status",
            expected_generation=expected_generation,
            expected_reference=expected_reference,
        )

    async def admit(
        self,
        *,
        source_task_id: str,
        source_workspace_commitment: str,
        project: str,
        expected_generation: int | None = None,
        expected_route_generation: int | None = None,
        expected_route_identity_digest: str | None = None,
        expected_repository_commitment: str | None = None,
        cross_repository: bool = False,
    ) -> CoordinationAdmission:
        task = _id(IdKind.TASK, source_task_id)
        workspace = _commitment(source_workspace_commitment)
        if expected_route_generation is not None and (
            type(expected_route_generation) is not int or expected_route_generation < 1
        ):
            raise ProjectCommandError(CoordinationErrorCode.INVALID)
        if expected_route_identity_digest is not None:
            try:
                validate_sha256_digest(expected_route_identity_digest)
            except (TypeError, ValueError) as exc:
                raise ProjectCommandError(CoordinationErrorCode.INVALID) from exc
        expected_repository = (
            None
            if expected_repository_commitment is None
            else _commitment(expected_repository_commitment)
        )
        descriptor = await self._project_or_error(project)
        if descriptor.dissolved_at is not None:
            raise ProjectCommandError(CoordinationErrorCode.PROJECT_DISSOLVED)
        generation = descriptor.membership_generation
        if expected_generation is not None and expected_generation != generation:
            raise ProjectCommandError(CoordinationErrorCode.GRANT_REVOKED)
        provenance = await self.catalog.task_source_provenance(task)
        if (
            provenance is None
            or provenance.workspace_ref_commitment is None
            or provenance.workspace_ref_commitment != workspace
        ):
            # A caller-provided workspace commitment is only a selector.  It becomes authority
            # for this task after the catalog proves that it is the task's current provenance.
            raise ProjectCommandError(CoordinationErrorCode.CONSENT_REQUIRED)
        # A queued coordination item carries the source snapshot captured at detection time.
        # Rechecking both catalog route generation and provenance keeps a route rotation from
        # reusing a stale participant row, even when project membership has not advanced.
        if expected_route_generation is not None:
            if provenance.route_generation != expected_route_generation:
                raise ProjectCommandError(CoordinationErrorCode.GENERATION_MISMATCH)
            current_route_generation = await self.catalog.task_route_generation(task)
            if (
                type(current_route_generation) is not int
                or current_route_generation != expected_route_generation
            ):
                raise ProjectCommandError(CoordinationErrorCode.GENERATION_MISMATCH)
        if (
            expected_route_identity_digest is not None
            and provenance.route_identity_digest != expected_route_identity_digest
        ):
            raise ProjectCommandError(CoordinationErrorCode.GENERATION_MISMATCH)
        if (
            expected_repository is not None
            and provenance.repository_privacy_commitment != expected_repository
        ):
            raise ProjectCommandError(CoordinationErrorCode.GENERATION_MISMATCH)
        own_consent = await self._source_workspace_consent(task, workspace)
        if own_consent is not True:
            raise ProjectCommandError(CoordinationErrorCode.CONSENT_REQUIRED)
        if not await self._coordination_source_allowed(task, workspace, descriptor.project_id):
            raise ProjectCommandError(CoordinationErrorCode.SOURCE_POLICY_DENIED)
        direct_memberships = await self.catalog.list_task_project_ids(task)
        member = project in direct_memberships
        if not member:
            memberships = await self.catalog.project_memberships(project)
            if descriptor.kind is ProjectKind.REPOSITORY and descriptor.auto_grouping:
                member = (
                    provenance.repository_privacy_commitment == descriptor.repository_commitment
                )
            elif descriptor.kind is ProjectKind.GENERAL:
                member = any(
                    item.active
                    and (
                        item.member_kind is MemberKind.REPOSITORY
                        and item.member_commitment_or_id == provenance.repository_privacy_commitment
                        or item.member_kind is MemberKind.WORKSPACE
                        and item.member_commitment_or_id == provenance.workspace_ref_commitment
                    )
                    for item in memberships
                )
        if not member:
            raise ProjectCommandError(CoordinationErrorCode.PROJECT_NOT_FOUND)
        grant_required = cross_repository or descriptor.kind is ProjectKind.GENERAL
        grant = None
        if grant_required:
            grant = await self.catalog.coordination_grant(project, generation)
        allowed = coordination_generation_is_current(
            generation,
            descriptor.membership_generation,
            grant_active=(not grant_required if grant is None else grant.active),
        )
        if not allowed:
            raise ProjectCommandError(
                CoordinationErrorCode.GRANT_REVOKED
                if expected_generation is not None
                else CoordinationErrorCode.GRANT_REQUIRED
            )
        return CoordinationAdmission(
            task,
            workspace,
            descriptor.project_id,
            generation,
            True,
            grant_required,
            not grant_required if grant is None else grant.active,
            cross_repository,
        )

    async def _source_current_at_generation(
        self,
        task_id: str,
        *,
        project: str,
        generation: int,
        cross_repository: bool = False,
        expected_route_generation: int | None = None,
        expected_route_identity_digest: str | None = None,
        expected_repository_commitment: str | None = None,
    ) -> bool:
        """Re-admit one source immediately before publishing its derived identity.

        Project reads await catalog, session, ledger, and delivery adapters after their initial
        admission.  The second admission is the source-and-grant fence for that read window; a
        membership generation check alone cannot detect a consent withdrawal or grant transition
        that occurred while those adapters were awaited.
        """

        task = _id(IdKind.TASK, task_id)
        provenance = await self.catalog.task_source_provenance(task)
        if provenance is None or provenance.workspace_ref_commitment is None:
            return False
        try:
            admission = await self.admit(
                source_task_id=task,
                source_workspace_commitment=provenance.workspace_ref_commitment,
                project=project,
                expected_generation=generation,
                expected_route_generation=expected_route_generation,
                expected_route_identity_digest=expected_route_identity_digest,
                expected_repository_commitment=expected_repository_commitment,
                cross_repository=cross_repository,
            )
        except ProjectCommandError:
            return False
        return admission.membership_generation == generation

    async def _sources_current_at_generation(
        self,
        task_ids: Iterable[str],
        *,
        project: str,
        generation: int,
        cross_repository: bool = False,
        expected_route_generations: Mapping[str, int] | None = None,
        expected_repository_commitments: Mapping[str, str] | None = None,
    ) -> bool:
        """Fence every source in a multi-task projection at one exact generation."""

        descriptor = await self._project_or_error(project)
        if descriptor.dissolved_at is not None or descriptor.membership_generation != generation:
            return False
        for task_id in sorted(set(task_ids), key=str.encode):
            if not await self._source_current_at_generation(
                task_id,
                project=project,
                generation=generation,
                cross_repository=cross_repository,
                expected_route_generation=(
                    None
                    if expected_route_generations is None
                    else expected_route_generations.get(task_id)
                ),
                expected_repository_commitment=(
                    None
                    if expected_repository_commitments is None
                    else expected_repository_commitments.get(task_id)
                ),
            ):
                return False
        latest = await self._project_or_error(project)
        return latest.dissolved_at is None and latest.membership_generation == generation

    async def status(self, project: str) -> ProjectStatus:
        descriptor = await self._project_or_error(project)
        memberships = await self.catalog.project_memberships(project)
        grant = await self.catalog.coordination_grant(project, descriptor.membership_generation)
        return ProjectStatus(
            descriptor,
            tuple(ProjectMembershipView(item) for item in memberships),
            grant,
        )

    async def _authorized_member_views(
        self,
        descriptor: ProjectDescriptor,
        memberships: tuple[ProjectMembership, ...],
        *,
        expected_generation: int,
    ) -> tuple[ProjectMembershipView, ...]:
        """Project one member at a time under that member's source consent.

        Membership rows are structural and durable, but a project view is a disclosure.  A task
        source that cannot be admitted at the current generation is omitted rather than exposing
        its identity or health to another task.  The generation is checked again by the caller
        after all awaits complete.
        """

        # A project membership may be a task, workspace, or repository binding.  Status must
        # expose only admitted task identities, so expand the latter two through the catalog and
        # run the same source-workspace gate for every resulting task.  The membership row itself
        # stays structural and is retained only as the provenance of the expanded view.
        candidates: list[tuple[ProjectMembership, str]] = []
        for membership in memberships:
            if not membership.active:
                continue
            if membership.member_kind is MemberKind.TASK:
                candidates.append((membership, membership.member_commitment_or_id))
            elif membership.member_kind is MemberKind.REPOSITORY:
                task_ids = await self.catalog.list_repository_task_ids(
                    membership.member_commitment_or_id
                )
                candidates.extend((membership, task_id) for task_id in task_ids)
            elif membership.member_kind is MemberKind.WORKSPACE:
                task_ids = await self.catalog.list_workspace_task_ids(
                    membership.member_commitment_or_id
                )
                candidates.extend((membership, task_id) for task_id in task_ids)

        views: list[ProjectMembershipView] = []
        seen_tasks: set[str] = set()
        for membership, task_id in sorted(
            candidates, key=lambda item: (item[1].encode(), item[0].membership_generation)
        ):
            if task_id in seen_tasks:
                continue
            seen_tasks.add(task_id)
            provenance = await self.catalog.task_source_provenance(task_id)
            if provenance is None or provenance.workspace_ref_commitment is None:
                continue
            try:
                await self.admit(
                    source_task_id=task_id,
                    source_workspace_commitment=provenance.workspace_ref_commitment,
                    project=descriptor.project_id,
                    expected_generation=expected_generation,
                    expected_route_generation=provenance.route_generation,
                    expected_repository_commitment=provenance.repository_privacy_commitment,
                )
            except ProjectCommandError:
                continue
            work_state = await self.catalog.task_work_state(task_id)
            sessions = await self.catalog.task_session_states(task_id)
            health: SessionHealth | None = None
            actor_id: str | None = None
            if sessions:
                active = [item for item in sessions if item.health is SessionHealth.ACTIVE]
                contact_lost = [
                    item for item in sessions if item.health is SessionHealth.CONTACT_LOST
                ]
                ended = [item for item in sessions if item.health is SessionHealth.ENDED]
                selected_session = next(
                    iter(sorted(active, key=lambda item: item.session_id.encode())),
                    next(
                        iter(sorted(contact_lost, key=lambda item: item.session_id.encode())),
                        next(iter(sorted(ended, key=lambda item: item.session_id.encode())), None),
                    ),
                )
                health = selected_session.health if selected_session is not None else None
                actor_id = None if selected_session is None else selected_session.actor_id
            lineage = await self.catalog.task_lineage(task_id)
            if not await self._source_current_at_generation(
                task_id,
                project=descriptor.project_id,
                generation=expected_generation,
                expected_route_generation=provenance.route_generation,
                expected_repository_commitment=provenance.repository_privacy_commitment,
            ):
                continue
            views.append(
                ProjectMembershipView(
                    membership,
                    task_id=task_id,
                    work_state=work_state.value,
                    session_health=None if health is None else health.value,
                    actor_id=actor_id,
                    parent_task_id=None if lineage is None else lineage.parent_task_id,
                )
            )
        return tuple(views)

    async def _resolve_project_for_task(self, task: str) -> str | None:
        """Resolve the only implicit/general project a task may use without a selector.

        A general project wins over the implicit repository project.  Multiple general projects
        are a durable selector conflict, even if an older adapter failed to enforce Q3.
        """

        project_ids = await self.catalog.list_task_project_ids(task)
        descriptors = [
            descriptor
            for identifier in project_ids
            if (descriptor := await self.catalog.project_state(identifier)) is not None
            and descriptor.dissolved_at is None
        ]
        general = [item.project_id for item in descriptors if item.kind is ProjectKind.GENERAL]
        if len(general) > 1:
            raise ProjectCommandError(CoordinationErrorCode.SELECTOR_CONFLICT)
        if general:
            return general[0]
        if len(descriptors) == 1:
            return descriptors[0].project_id
        if len(descriptors) > 1:
            raise ProjectCommandError(CoordinationErrorCode.SELECTOR_CONFLICT)
        provenance = await self.catalog.task_source_provenance(task)
        if provenance is None or provenance.repository_privacy_commitment is None:
            return None
        repository = await self.catalog.repository_state(provenance.repository_privacy_commitment)
        if (
            repository is None
            or repository.dissolved_at is not None
            or not repository.auto_grouping
        ):
            return None
        return repository.project_id

    async def project_view_for(
        self,
        requester_task_id: str,
        *,
        selected_task_id: str | None = None,
        project: str | None = None,
        expected_generation: int | None = None,
    ) -> ProjectStatus | TaskLineage:
        """Build the authenticated project status view for a requester task.

        ``selected_task_id`` is a presentation selector only.  It can narrow the view to a
        currently admitted member, but it never opens or resumes that task's runtime.
        """

        requester = _id(IdKind.TASK, requester_task_id)
        selected = requester if selected_task_id is None else _id(IdKind.TASK, selected_task_id)
        project_id_value = (
            await self._resolve_project_for_task(requester)
            if project is None
            else _project(project)
        )
        if project_id_value is None:
            lineage = await self.catalog.task_lineage(requester)
            if lineage is None:
                raise ProjectCommandError(CoordinationErrorCode.PROJECT_NOT_FOUND)
            return lineage
        requester_provenance = await self.catalog.task_source_provenance(requester)
        if requester_provenance is None or requester_provenance.workspace_ref_commitment is None:
            raise ProjectCommandError(CoordinationErrorCode.CONSENT_REQUIRED)
        admission = await self.admit(
            source_task_id=requester,
            source_workspace_commitment=requester_provenance.workspace_ref_commitment,
            project=project_id_value,
            expected_generation=expected_generation,
            expected_route_generation=requester_provenance.route_generation,
            expected_repository_commitment=requester_provenance.repository_privacy_commitment,
        )
        if selected != requester:
            selected_provenance = await self.catalog.task_source_provenance(selected)
            if selected_provenance is None or selected_provenance.workspace_ref_commitment is None:
                raise ProjectCommandError(CoordinationErrorCode.CONSENT_REQUIRED)
            await self.admit(
                source_task_id=selected,
                source_workspace_commitment=selected_provenance.workspace_ref_commitment,
                project=project_id_value,
                expected_generation=admission.membership_generation,
                expected_route_generation=selected_provenance.route_generation,
                expected_repository_commitment=selected_provenance.repository_privacy_commitment,
            )
        descriptor = await self._project_or_error(project_id_value)
        memberships = await self.catalog.project_memberships(project_id_value)
        views = await self._authorized_member_views(
            descriptor, memberships, expected_generation=admission.membership_generation
        )
        if selected != requester:
            views = tuple(item for item in views if item.task_id == selected)
            if not views:
                raise ProjectCommandError(CoordinationErrorCode.CONSENT_REQUIRED)
        visible_task_ids = tuple(item.task_id for item in views if item.task_id is not None)
        typed_detections = await self.project_detections_for(
            project_id_value,
            visible_task_ids=visible_task_ids,
            expected_generation=admission.membership_generation,
        )
        detection_wires: list[JsonObject] = []
        for detection in typed_detections:
            open_state = detection.finding_eligible
            if self.detection_store is not None:
                obligation_states = await inspect_obligation_states(
                    self.detection_store,
                    detection.detection_id,
                    (detection.left_task_id, detection.right_task_id),
                )
                open_state = any(
                    detection.finding_eligible_for(state) for state in obligation_states
                )
            detection_wire: dict[str, JsonValue] = {
                "detection_id": detection.detection_id,
                "task_ids": tuple(
                    sorted(
                        (detection.left_task_id, detection.right_task_id),
                        key=str.encode,
                    )
                ),
                "resource_count": len(detection.resource_identities),
                "open": open_state,
            }
            # Keep a bounded omission marker in the internal snapshot.  The final client
            # projection rehydrates only after it knows the recipient sink and source-owner
            # policy, so raw paths never enter a structural catalog row or MCP summary.
            if detection.detail_ref is not None:
                detection_wire["resource_paths"] = JsonObject(
                    {
                        "omitted": True,
                        "category": "repository_excerpt",
                        "reason": "local_disclosure_not_authorized",
                    }
                )
            detection_wires.append(JsonObject(detection_wire))
        latest = await self._project_or_error(project_id_value)
        if latest.membership_generation != admission.membership_generation:
            raise ProjectCommandError(CoordinationErrorCode.GRANT_REVOKED)
        grant = await self.catalog.coordination_grant(
            project_id_value, admission.membership_generation
        )
        coverage_rows = await self.coordination_coverage_for(
            requester,
            project=project_id_value,
            expected_generation=admission.membership_generation,
        )
        if not await self._sources_current_at_generation(
            visible_task_ids,
            project=project_id_value,
            generation=admission.membership_generation,
            expected_route_generations={
                requester: requester_provenance.route_generation,
            },
            expected_repository_commitments=(
                {
                    requester: requester_provenance.repository_privacy_commitment,
                }
                if requester_provenance.repository_privacy_commitment is not None
                else {}
            ),
        ):
            raise ProjectCommandError(CoordinationErrorCode.GRANT_REVOKED)
        return ProjectStatus(
            latest,
            views,
            grant,
            tuple(detection_wires),
            requester,
            tuple(item.as_wire() for item in coverage_rows if item.task_id in visible_task_ids),
        )

    async def status_for_task(
        self,
        requester_task_id: str,
        *,
        project: str | None = None,
        expected_generation: int | None = None,
    ) -> ProjectStatus | TaskLineage:
        """Return a requester-authorized project view or lineage-only state.

        A task selector is an authenticated source identity.  With no project selector, callers
        receive lineage only and cannot enumerate project membership.  With a project selector,
        the task must be a current member (or an auto-grouped repository task), its source
        workspace consent is checked, and the current generation/grant is admitted immediately
        before the view is assembled.
        """

        return await self.project_view_for(
            requester_task_id,
            project=project,
            expected_generation=expected_generation,
        )

    async def live_admitted_member_task_ids(
        self,
        requester_task_id: str,
        *,
        project: str,
        expected_generation: int | None = None,
    ) -> tuple[str, ...]:
        """Return other live task identities admitted to the current project generation.

        This is the identity-only read used by check advisory notes.  It expands durable project
        membership through the same source-consent and grant gates as the project view, then
        retains only tasks with open work and an active session.  No project text, ledger payload,
        path, or finding detail crosses this boundary, and the final generation check closes the
        revoke race after the per-member awaits.
        """

        requester = _id(IdKind.TASK, requester_task_id)
        project_id_value = _project(project)
        descriptor = await self._project_or_error(project_id_value)
        generation = descriptor.membership_generation
        if expected_generation is not None and expected_generation != generation:
            raise ProjectCommandError(CoordinationErrorCode.GRANT_REVOKED)
        requester_provenance = await self.catalog.task_source_provenance(requester)
        if requester_provenance is None or requester_provenance.workspace_ref_commitment is None:
            raise ProjectCommandError(CoordinationErrorCode.CONSENT_REQUIRED)
        admission = await self.admit(
            source_task_id=requester,
            source_workspace_commitment=requester_provenance.workspace_ref_commitment,
            project=project_id_value,
            expected_generation=generation,
            expected_route_generation=requester_provenance.route_generation,
            expected_repository_commitment=requester_provenance.repository_privacy_commitment,
        )
        memberships = await self.catalog.project_memberships(project_id_value)
        views = await self._authorized_member_views(
            descriptor,
            memberships,
            expected_generation=admission.membership_generation,
        )
        if not await self._source_current_at_generation(
            requester,
            project=project_id_value,
            generation=admission.membership_generation,
            expected_route_generation=requester_provenance.route_generation,
            expected_repository_commitment=requester_provenance.repository_privacy_commitment,
        ):
            return ()
        candidates = {
            item.task_id
            for item in views
            if item.task_id is not None
            and item.task_id != requester
            and item.work_state == WorkState.OPEN.value
            and item.session_health == SessionHealth.ACTIVE.value
        }
        if not await self._sources_current_at_generation(
            (requester, *candidates),
            project=project_id_value,
            generation=admission.membership_generation,
            expected_route_generations={
                requester: requester_provenance.route_generation,
            },
            expected_repository_commitments=(
                {
                    requester: requester_provenance.repository_privacy_commitment,
                }
                if requester_provenance.repository_privacy_commitment is not None
                else {}
            ),
        ):
            return ()
        latest = await self._project_or_error(project_id_value)
        if (
            latest.dissolved_at is not None
            or latest.membership_generation != admission.membership_generation
        ):
            return ()
        return tuple(sorted(candidates, key=str.encode))


def project_request_from_json(value: object) -> JsonObject:
    """Validate one CLI/control body and return a canonical, structural-only request object."""

    if not isinstance(value, Mapping):
        raise ProjectCommandError(CoordinationErrorCode.INVALID)
    source = cast(Mapping[str, object], value)
    operation = source.get("operation")
    if type(operation) is not str or operation not in {
        "create",
        "link",
        "unlink",
        "amend",
        "dissolve",
        "opt_out",
        "opt_in",
        "grant",
        "revoke",
        "status",
    }:
        raise ProjectCommandError(CoordinationErrorCode.INVALID)
    # Text values are accepted only by the encrypted-object application path.  This parser is a
    # structural request helper and never echoes them into a response or error.
    result: dict[str, JsonValue] = {"schema_version": "1.0.0", "operation": operation}
    for key in (
        "request_id",
        "project_id",
        "member_kind",
        "member_commitment_or_id",
        "source_workspace_commitment",
        "member_repository_commitment",
        "repository_commitment",
        "owner_task_id",
        "audit_record_id",
    ):
        item = source.get(key)
        if item is not None:
            if type(item) is not str:
                raise ProjectCommandError(CoordinationErrorCode.INVALID)
            if key == "request_id":
                item = _id(IdKind.REQUEST, item)
            result[key] = item
    for key in ("auto_grouping",):
        item = source.get(key)
        if item is not None:
            if type(item) is not bool:
                raise ProjectCommandError(CoordinationErrorCode.INVALID)
            result[key] = item
    generation = source.get("membership_generation", source.get("expected_generation"))
    if generation is not None:
        if type(generation) is not int or generation < 1:
            raise ProjectCommandError(CoordinationErrorCode.INVALID)
        result["membership_generation"] = str(generation)
    owner_generation = source.get("owner_route_generation")
    if owner_generation is not None:
        if type(owner_generation) is not int or owner_generation < 1:
            raise ProjectCommandError(CoordinationErrorCode.INVALID)
        result["owner_route_generation"] = str(owner_generation)
    # ``authority`` is intentionally rejected.  A caller-controlled label cannot authorize a
    # cross-source grant; the service supplies an exact, authenticated consent capability.
    if "authority" in source:
        raise ProjectCommandError(CoordinationErrorCode.GRANT_REQUIRED)
    return JsonObject(result)


def _control_error(error: ProjectCommandError) -> Exception:
    # Import lazily to keep the CLI/application modules light.  The coordination enum is the
    # closed, validated reason vocabulary; forwarding only its value preserves typed refusals
    # without carrying user-controlled titles, descriptions, paths, or exception text.
    try:
        from finishup.ports.control import ControlError

        return ControlError(error.code.value)
    except ImportError:
        return error


def build_project_support_handler(
    application: ProjectApplication,
) -> Callable[..., Awaitable[JsonObject]]:
    """Build the one service-control handler used by the CLI project command group.

    Project management remains CLI-only.  The service composition owns the concrete
    ``ControlMethod`` key and passes it to :func:`build_project_support_handlers`; this module
    does not probe the enum or silently expose additional methods.
    """

    async def invoke(request: object, **_context: object) -> JsonObject:
        try:
            if not isinstance(request, Mapping):
                raise ProjectCommandError(CoordinationErrorCode.INVALID)
            body = cast(Mapping[str, object], request)
            parsed = project_request_from_json(body)
            operation = cast(str, parsed["operation"])
            durable_journal = getattr(application, "operation_journal", None)
            request_id_value = body.get("request_id")
            if durable_journal is not None:
                if request_id_value is None:
                    raise ProjectCommandError(CoordinationErrorCode.INVALID)
                request_id = _id(IdKind.REQUEST, request_id_value)
            else:
                request_id = None
            operation_kwargs: dict[str, Any] = (
                {} if request_id is None else {"request_id": request_id}
            )
            if operation == "create":
                title = _bounded_text(body.get("title"), required=True)
                description = _bounded_text(body.get("description"), required=False)
                result = await application.create(
                    title=cast(str, title),
                    description=description,
                    auto_grouping=body.get("auto_grouping", False) is True,
                    owner_task_id=cast(str | None, body.get("owner_task_id")),
                    owner_route_generation=cast(int | None, body.get("owner_route_generation")),
                    **operation_kwargs,
                )
                return result.as_wire()
            if operation == "link":
                result = await application.link(
                    project_id=cast(str, body.get("project_id")),
                    member_kind=_member_kind(body.get("member_kind")),
                    member_commitment_or_id=cast(str, body.get("member_commitment_or_id")),
                    source_workspace_commitment=cast(
                        str | None, body.get("source_workspace_commitment")
                    ),
                    member_repository_commitment=cast(
                        str | None, body.get("member_repository_commitment")
                    ),
                    expected_generation=cast(int | None, body.get("expected_generation")),
                    **operation_kwargs,
                )
                return result.as_wire()
            if operation == "unlink":
                result = await application.unlink(
                    project_id=cast(str, body.get("project_id")),
                    member_kind=_member_kind(body.get("member_kind")),
                    member_commitment_or_id=cast(str, body.get("member_commitment_or_id")),
                    expected_generation=cast(int | None, body.get("expected_generation")),
                    **operation_kwargs,
                )
                return result.as_wire()
            if operation == "amend":
                result = await application.amend(
                    project_id=cast(str, body.get("project_id")),
                    title=cast(str | None, body.get("title")),
                    description=cast(str | None, body.get("description")),
                    owner_task_id=cast(str | None, body.get("owner_task_id")),
                    owner_route_generation=cast(int | None, body.get("owner_route_generation")),
                    **operation_kwargs,
                )
                return result.as_wire()
            if operation == "dissolve":
                result = await application.dissolve(
                    project_id=cast(str, body.get("project_id")),
                    expected_generation=cast(int | None, body.get("expected_generation")),
                    **operation_kwargs,
                )
                return result.as_wire()
            if operation in {"opt_out", "opt_in"}:
                result = await application.set_auto_grouping(
                    cast(str, body.get("repository_commitment")),
                    operation == "opt_in",
                    **operation_kwargs,
                )
                if result is None:
                    return JsonObject(
                        {
                            "schema_version": "1.0.0",
                            "repository_commitment": cast(str, body.get("repository_commitment")),
                            "auto_grouping": operation == "opt_in",
                            "project_id": None,
                        }
                    )
                return result.as_wire()
            if operation == "grant":
                result = await application.grant(
                    project_id=cast(str, body.get("project_id")),
                    membership_generation=cast(int, body.get("membership_generation")),
                    audit_record_id=cast(str | None, body.get("audit_record_id")),
                    **operation_kwargs,
                )
                return result.as_wire()
            if operation == "revoke":
                result = await application.revoke(
                    project_id=cast(str, body.get("project_id")),
                    membership_generation=cast(int, body.get("membership_generation")),
                    audit_record_id=cast(str | None, body.get("audit_record_id")),
                    **operation_kwargs,
                )
                return result.as_wire()
            # Project status is deliberately not a second control result shape.  Callers must use
            # the ordinary STATUS RPC, which binds the exact authenticated session and writer.
            # Falling through keeps the unreleased PROJECT surface lifecycle-only.
            raise ProjectCommandError(CoordinationErrorCode.INVALID)
        except ProjectCommandError as error:
            raise _control_error(error) from error

    return invoke


def build_project_support_handlers(
    application: ProjectApplication,
    *,
    control_method: object,
) -> Mapping[object, Callable[..., Awaitable[JsonObject]]]:
    """Bind the explicitly selected CLI-only project control method."""

    if control_method is None:
        raise TypeError("project_control_method_required")
    return {control_method: build_project_support_handler(application)}
