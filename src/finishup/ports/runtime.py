"""Service-owned, generation-fenced exact task routing boundary."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Protocol, cast

from finishup.domain.coordination import LineageAcceptance, LineageOrigin, WorkState
from finishup.domain.values import (
    Frontier,
    JsonObject,
    JsonValue,
    event_id,
    format_rfc3339_millis,
    freeze_json,
    object_id,
    session_id,
    task_id,
    validate_commitment,
    validate_sha256_digest,
    writer_id,
)
from finishup.ports.diagnostics import RuntimeCapability
from finishup.ports.importer import ImporterPort
from finishup.ports.ledger import LedgerPort
from finishup.ports.objects import ObjectStorePort
from finishup.ports.observation import TaskObservationPort
from finishup.protocol.ids import IdKind, validate_id

__all__ = [
    "BundleProvisionCommand",
    "BundleProvisionMode",
    "BundleRuntimePort",
    "OwnershipFence",
    "RouteAccess",
    "RouteCommand",
    "ServiceRuntimeContext",
    "StartCompletionEvidence",
    "StartMilestone",
    "StartMilestoneExpectation",
    "TaskRuntime",
]

_MAX_SQLITE_SIGNED_INTEGER = 2**63 - 1
_VERSION_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+/-]{0,127}$", re.ASCII)
_NONCE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{16,128}$", re.ASCII)
_START_PHASES = frozenset(
    {"route_reserved", "bundle_ready", "lifecycle_committed", "result_published", "terminal"}
)


def _invalid() -> ValueError:
    return ValueError("invalid_runtime_port_value")


def _positive_int(value: object) -> int:
    if type(value) is not int or not 1 <= value <= _MAX_SQLITE_SIGNED_INTEGER:
        raise _invalid()
    return value


def _validated_service_instance_id(value: object) -> str:
    try:
        return str(validate_id(IdKind.SERVICE_INSTANCE, value))
    except (TypeError, ValueError) as exc:
        raise _invalid() from exc


def _validated_version(value: object) -> str:
    if (
        type(value) is not str
        or _VERSION_PATTERN.fullmatch(value) is None
        or "//" in value
        or "/../" in value
    ):
        raise _invalid()
    return value


def _validated_capabilities(value: object) -> frozenset[RuntimeCapability]:
    if type(value) is not frozenset:
        raise _invalid()
    items = cast(frozenset[object], value)
    if any(type(item) is not RuntimeCapability for item in items):
        raise _invalid()
    return cast(frozenset[RuntimeCapability], value)


def _validated_id(factory: Callable[[object], str], value: object) -> str:
    try:
        return str(factory(value))
    except (TypeError, ValueError) as exc:
        raise _invalid() from exc


def _validate_route_identity(
    task: object,
    session: object,
    writer: object,
    route_generation: object,
    route_identity_digest: object,
) -> tuple[str, str, str, int, str]:
    normalized_task = _validated_id(task_id, task)
    normalized_session = _validated_id(session_id, session)
    normalized_writer = _validated_id(writer_id, writer)
    generation = _positive_int(route_generation)
    try:
        digest = validate_sha256_digest(cast(str, route_identity_digest))
    except (TypeError, ValueError) as exc:
        raise _invalid() from exc
    return normalized_task, normalized_session, normalized_writer, generation, digest


def _validated_optional_object_id(value: object) -> str | None:
    if value is None:
        return None
    return _validated_id(object_id, value)


def _validated_optional_digest(value: object) -> str | None:
    if value is None:
        return None
    try:
        return validate_sha256_digest(cast(str, value))
    except (TypeError, ValueError) as exc:
        raise _invalid() from exc


def _validated_optional_commitment(value: object) -> str | None:
    if value is None:
        return None
    try:
        return validate_commitment(cast(str, value))
    except (TypeError, ValueError) as exc:
        raise _invalid() from exc


def _validated_optional_task_id(value: object) -> str | None:
    if value is None:
        return None
    return _validated_id(task_id, value)


def _validate_route_metadata(
    *,
    task: str,
    repository_privacy_commitment: object,
    parent_task_id: object,
    depth: object,
    lineage_digest: object,
    origin: object,
    acceptance: object,
    work_state: object,
) -> tuple[
    str | None,
    str | None,
    int,
    str | None,
    LineageOrigin | None,
    LineageAcceptance | None,
    WorkState,
]:
    repository = _validated_optional_commitment(repository_privacy_commitment)
    parent = _validated_optional_task_id(parent_task_id)
    if parent is None:
        if depth != 0 or origin is not None or acceptance is not None:
            raise _invalid()
    else:
        if parent == task:
            raise _invalid()
        if type(depth) is not int or not 1 <= depth <= _MAX_SQLITE_SIGNED_INTEGER:
            raise _invalid()
        if type(origin) is not LineageOrigin or type(acceptance) is not LineageAcceptance:
            raise _invalid()
    if type(depth) is not int or not 0 <= depth <= _MAX_SQLITE_SIGNED_INTEGER:
        raise _invalid()
    lineage = _validated_optional_digest(lineage_digest)
    if type(work_state) is not WorkState:
        raise _invalid()
    return repository, parent, depth, lineage, origin, acceptance, work_state


def _validate_milestone_presence(
    milestone: StartMilestone,
    *,
    lifecycle_frontier: Frontier | None,
    response_object_id: str | None,
    response_envelope_digest: str | None,
    result_digest: str | None,
) -> None:
    if milestone is StartMilestone.BUNDLE_READY:
        if (
            lifecycle_frontier is not None
            or response_object_id is not None
            or response_envelope_digest is not None
            or result_digest is not None
        ):
            raise _invalid()
    elif milestone is StartMilestone.LIFECYCLE_COMMITTED:
        if (
            type(lifecycle_frontier) is not Frontier
            or lifecycle_frontier.sequence == 0
            or response_object_id is not None
            or response_envelope_digest is not None
            or result_digest is not None
        ):
            raise _invalid()
    elif (
        type(lifecycle_frontier) is not Frontier
        or lifecycle_frontier.sequence == 0
        or response_object_id is None
        or response_envelope_digest is None
        or result_digest is None
    ):
        raise _invalid()


class RouteAccess(str, Enum):  # noqa: UP042 - exact internal vocabulary is required
    STRUCTURAL_READ = "structural_read"
    PAYLOAD_READ = "payload_read"
    WRITE = "write"
    IMPORT_REVIEW = "import_review"
    MAINTENANCE = "maintenance"


class BundleProvisionMode(str, Enum):  # noqa: UP042 - exact internal vocabulary is required
    CREATED = "created"
    ATTACHED = "attached"


class StartMilestone(str, Enum):  # noqa: UP042 - exact internal vocabulary is required
    BUNDLE_READY = "bundle_ready"
    LIFECYCLE_COMMITTED = "lifecycle_committed"
    RESULT_PUBLISHED = "result_published"


@dataclass(frozen=True, slots=True, repr=False)
class ServiceRuntimeContext:
    service_instance_id: str
    service_generation: int
    vault_generation: int
    catalog_generation: int
    capabilities: frozenset[RuntimeCapability]
    version_manifest: Mapping[str, JsonValue]
    shutdown_token: object

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "service_instance_id", _validated_service_instance_id(self.service_instance_id)
        )
        _positive_int(self.service_generation)
        _positive_int(self.vault_generation)
        _positive_int(self.catalog_generation)
        object.__setattr__(self, "capabilities", _validated_capabilities(self.capabilities))
        try:
            frozen_manifest = freeze_json(self.version_manifest)
        except (TypeError, ValueError) as exc:
            raise _invalid() from exc
        if type(frozen_manifest) is not JsonObject or not frozen_manifest:
            raise _invalid()
        object.__setattr__(self, "version_manifest", frozen_manifest)
        if self.shutdown_token is None or type(self.shutdown_token) in {
            bool,
            int,
            str,
            tuple,
            list,
            dict,
            JsonObject,
        }:
            raise _invalid()

    def __repr__(self) -> str:
        return "ServiceRuntimeContext(<redacted>)"

    def __reduce__(self) -> str | tuple[object, ...]:
        raise TypeError("service_runtime_context_not_serializable")


@dataclass(frozen=True, slots=True)
class RouteCommand:
    session_id: str
    writer_id: str | None
    access: RouteAccess
    required_capabilities: frozenset[RuntimeCapability]

    def __post_init__(self) -> None:
        object.__setattr__(self, "session_id", _validated_id(session_id, self.session_id))
        if self.writer_id is not None:
            object.__setattr__(self, "writer_id", _validated_id(writer_id, self.writer_id))
        if type(self.access) is not RouteAccess:
            raise _invalid()
        required = _validated_capabilities(self.required_capabilities)
        object.__setattr__(self, "required_capabilities", required)

        minimum = {
            RouteAccess.STRUCTURAL_READ: RuntimeCapability.STRUCTURAL_READ,
            RouteAccess.PAYLOAD_READ: RuntimeCapability.PAYLOAD_READ,
            RouteAccess.WRITE: RuntimeCapability.WRITE,
            RouteAccess.IMPORT_REVIEW: RuntimeCapability.WRITE,
            RouteAccess.MAINTENANCE: RuntimeCapability.WRITE,
        }[self.access]
        if minimum not in required:
            raise _invalid()
        if (
            self.access
            in {
                RouteAccess.WRITE,
                RouteAccess.IMPORT_REVIEW,
                RouteAccess.MAINTENANCE,
            }
            and self.writer_id is None
        ):
            raise _invalid()


@dataclass(frozen=True, slots=True)
class BundleProvisionCommand:
    mode: BundleProvisionMode
    task_id: str
    session_id: str
    writer_id: str
    lifecycle_event_id: str
    bundle_relpath: str
    route_generation: int
    route_identity_digest: str
    phase: str
    response_object_id: str | None
    owner_generation: int
    lease_owner_id: str
    lease_generation: int
    lease_expires_at: datetime
    protocol_version: str
    engine_version: str
    projection_version: str
    bundle_schema_version: str
    # Route metadata is supplied by the authoritative catalog snapshot.  Bundle inspection can
    # prove the generated bundle identity, but cannot recreate mutable lineage/work facts.
    repository_privacy_commitment: str | None = None
    parent_task_id: str | None = None
    depth: int = 0
    lineage_digest: str | None = None
    origin: LineageOrigin | None = None
    acceptance: LineageAcceptance | None = None
    work_state: WorkState = WorkState.OPEN

    def __post_init__(self) -> None:
        if type(self.mode) is not BundleProvisionMode:
            raise _invalid()
        task, session, writer, generation, route_digest = _validate_route_identity(
            self.task_id,
            self.session_id,
            self.writer_id,
            self.route_generation,
            self.route_identity_digest,
        )
        object.__setattr__(self, "task_id", task)
        object.__setattr__(self, "session_id", session)
        object.__setattr__(self, "writer_id", writer)
        object.__setattr__(self, "route_generation", generation)
        object.__setattr__(self, "route_identity_digest", route_digest)
        (
            repository,
            parent,
            depth,
            lineage,
            origin,
            acceptance,
            work_state,
        ) = _validate_route_metadata(
            task=task,
            repository_privacy_commitment=self.repository_privacy_commitment,
            parent_task_id=self.parent_task_id,
            depth=self.depth,
            lineage_digest=self.lineage_digest,
            origin=self.origin,
            acceptance=self.acceptance,
            work_state=self.work_state,
        )
        object.__setattr__(self, "repository_privacy_commitment", repository)
        object.__setattr__(self, "parent_task_id", parent)
        object.__setattr__(self, "depth", depth)
        object.__setattr__(self, "lineage_digest", lineage)
        object.__setattr__(self, "origin", origin)
        object.__setattr__(self, "acceptance", acceptance)
        object.__setattr__(self, "work_state", work_state)
        object.__setattr__(
            self, "lifecycle_event_id", _validated_id(event_id, self.lifecycle_event_id)
        )
        if type(self.bundle_relpath) is not str or self.bundle_relpath != f"tasks/{task}":
            raise _invalid()
        if type(self.phase) is not str or self.phase not in _START_PHASES:
            raise _invalid()
        response_object_id = _validated_optional_object_id(self.response_object_id)
        object.__setattr__(self, "response_object_id", response_object_id)
        if (self.phase in {"result_published", "terminal"}) != (response_object_id is not None):
            raise _invalid()
        _positive_int(self.owner_generation)
        object.__setattr__(
            self, "lease_owner_id", _validated_service_instance_id(self.lease_owner_id)
        )
        _positive_int(self.lease_generation)
        try:
            format_rfc3339_millis(self.lease_expires_at)
        except (TypeError, ValueError) as exc:
            raise _invalid() from exc
        object.__setattr__(self, "protocol_version", _validated_version(self.protocol_version))
        object.__setattr__(self, "engine_version", _validated_version(self.engine_version))
        object.__setattr__(self, "projection_version", _validated_version(self.projection_version))
        object.__setattr__(
            self, "bundle_schema_version", _validated_version(self.bundle_schema_version)
        )


@dataclass(frozen=True, slots=True, repr=False)
class OwnershipFence:
    service_instance_id: str
    service_generation: int
    owner_generation: int
    nonce: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "service_instance_id", _validated_service_instance_id(self.service_instance_id)
        )
        _positive_int(self.service_generation)
        _positive_int(self.owner_generation)
        if type(self.nonce) is not str or _NONCE_PATTERN.fullmatch(self.nonce) is None:
            raise _invalid()

    def __repr__(self) -> str:
        return "OwnershipFence(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class TaskRuntime:
    task_id: str
    session_id: str
    writer_id: str | None
    capabilities: frozenset[RuntimeCapability]
    ledger: LedgerPort
    objects: ObjectStorePort
    importer: ImporterPort
    projection_version: str
    engine_version: str
    protocol_version: str
    bundle_schema_version: str
    fence: OwnershipFence
    observation: TaskObservationPort | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "task_id", _validated_id(task_id, self.task_id))
        object.__setattr__(self, "session_id", _validated_id(session_id, self.session_id))
        if self.writer_id is not None:
            object.__setattr__(self, "writer_id", _validated_id(writer_id, self.writer_id))
        capabilities = _validated_capabilities(self.capabilities)
        object.__setattr__(self, "capabilities", capabilities)
        if RuntimeCapability.WRITE in capabilities and self.writer_id is None:
            raise _invalid()
        if self.observation is not None and RuntimeCapability.WRITE not in capabilities:
            # A durable observation seam is only ever handed to WRITE-capable routes.
            raise _invalid()
        task_ports = (
            cast(object, self.ledger),
            cast(object, self.objects),
            cast(object, self.importer),
        )
        if any(port is None for port in task_ports):
            raise _invalid()
        object.__setattr__(self, "projection_version", _validated_version(self.projection_version))
        object.__setattr__(self, "engine_version", _validated_version(self.engine_version))
        object.__setattr__(self, "protocol_version", _validated_version(self.protocol_version))
        object.__setattr__(
            self, "bundle_schema_version", _validated_version(self.bundle_schema_version)
        )
        if type(self.fence) is not OwnershipFence:
            raise _invalid()

    def __repr__(self) -> str:
        return "TaskRuntime(<redacted>)"


@dataclass(frozen=True, slots=True)
class StartMilestoneExpectation:
    milestone: StartMilestone
    task_id: str
    session_id: str
    writer_id: str
    lifecycle_event_id: str
    route_generation: int
    route_identity_digest: str
    response_object_id: str | None = None
    response_envelope_digest: str | None = None
    result_digest: str | None = None

    def __post_init__(self) -> None:
        if type(self.milestone) is not StartMilestone:
            raise _invalid()
        task, session, writer, generation, route_digest = _validate_route_identity(
            self.task_id,
            self.session_id,
            self.writer_id,
            self.route_generation,
            self.route_identity_digest,
        )
        object.__setattr__(self, "task_id", task)
        object.__setattr__(self, "session_id", session)
        object.__setattr__(self, "writer_id", writer)
        object.__setattr__(self, "route_generation", generation)
        object.__setattr__(self, "route_identity_digest", route_digest)
        object.__setattr__(
            self, "lifecycle_event_id", _validated_id(event_id, self.lifecycle_event_id)
        )
        response_object_id = _validated_optional_object_id(self.response_object_id)
        response_envelope_digest = _validated_optional_digest(self.response_envelope_digest)
        result_digest = _validated_optional_digest(self.result_digest)
        object.__setattr__(self, "response_object_id", response_object_id)
        object.__setattr__(self, "response_envelope_digest", response_envelope_digest)
        object.__setattr__(self, "result_digest", result_digest)
        if self.milestone is StartMilestone.RESULT_PUBLISHED:
            if (
                response_object_id is None
                or response_envelope_digest is None
                or result_digest is None
            ):
                raise _invalid()
        elif (
            response_object_id is not None
            or response_envelope_digest is not None
            or result_digest is not None
        ):
            raise _invalid()


@dataclass(frozen=True, slots=True)
class StartCompletionEvidence:
    milestone: StartMilestone
    task_id: str
    session_id: str
    writer_id: str
    lifecycle_event_id: str
    route_generation: int
    route_identity_digest: str
    owner_generation: int
    lifecycle_frontier: Frontier | None
    response_object_id: str | None
    response_envelope_digest: str | None
    result_digest: str | None
    evidence_digest: str

    def __post_init__(self) -> None:
        if type(self.milestone) is not StartMilestone:
            raise _invalid()
        task, session, writer, generation, route_digest = _validate_route_identity(
            self.task_id,
            self.session_id,
            self.writer_id,
            self.route_generation,
            self.route_identity_digest,
        )
        object.__setattr__(self, "task_id", task)
        object.__setattr__(self, "session_id", session)
        object.__setattr__(self, "writer_id", writer)
        object.__setattr__(self, "route_generation", generation)
        object.__setattr__(self, "route_identity_digest", route_digest)
        object.__setattr__(
            self, "lifecycle_event_id", _validated_id(event_id, self.lifecycle_event_id)
        )
        _positive_int(self.owner_generation)
        if self.lifecycle_frontier is not None and type(self.lifecycle_frontier) is not Frontier:
            raise _invalid()
        response_object_id = _validated_optional_object_id(self.response_object_id)
        response_envelope_digest = _validated_optional_digest(self.response_envelope_digest)
        result_digest = _validated_optional_digest(self.result_digest)
        object.__setattr__(self, "response_object_id", response_object_id)
        object.__setattr__(self, "response_envelope_digest", response_envelope_digest)
        object.__setattr__(self, "result_digest", result_digest)
        _validate_milestone_presence(
            self.milestone,
            lifecycle_frontier=self.lifecycle_frontier,
            response_object_id=response_object_id,
            response_envelope_digest=response_envelope_digest,
            result_digest=result_digest,
        )
        try:
            evidence_digest = validate_sha256_digest(self.evidence_digest)
        except (TypeError, ValueError) as exc:
            raise _invalid() from exc
        object.__setattr__(self, "evidence_digest", evidence_digest)


class BundleRuntimePort(Protocol):
    """Provision and route least-authority task runtimes inside the ready service."""

    async def provision_start(self, command: BundleProvisionCommand) -> TaskRuntime: ...

    async def route(self, command: RouteCommand) -> TaskRuntime: ...

    async def verify_start(
        self,
        runtime: TaskRuntime,
        expectation: StartMilestoneExpectation,
    ) -> StartCompletionEvidence: ...

    async def release(self, runtime: TaskRuntime) -> None: ...

    async def close(self) -> None: ...
