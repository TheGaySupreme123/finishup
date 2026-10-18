"""Ready-service composition for generation-fenced local task bundles.

Concrete storage selection is deliberately absent from this module.  The daemon supplies one
fully explicit :class:`RuntimeAdapterFactories` value after its startup gate has verified the
installed adapter cell.
"""

from __future__ import annotations

import asyncio
from collections import OrderedDict
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field, replace
from typing import Protocol, cast

from finishup.domain.values import Frontier
from finishup.observability.logging import record_bounded_counts_without_raising
from finishup.ports.diagnostics import DiagnosticsPort, RuntimeCapability
from finishup.ports.importer import ImporterPort, ImportStatusSnapshot
from finishup.ports.keys import BundleKeys, KeyStoreError, KeyStoreReason
from finishup.ports.ledger import (
    CaseAvailabilityFacts,
    CheckAdmissionRecord,
    CheckCommitResult,
    LedgerPort,
    LedgerRecord,
    OperationRecord,
    ProjectionPage,
    ProjectionQuery,
    ProjectionState,
    ProjectionView,
    SemanticDisclosureWait,
    SemanticProgressRecord,
    StoredProjection,
)
from finishup.ports.objects import ObjectRef, ObjectStorePort
from finishup.ports.observation import TaskObservationPort
from finishup.ports.runtime import (
    BundleProvisionCommand,
    BundleProvisionMode,
    BundleRuntimePort,
    OwnershipFence,
    RouteAccess,
    RouteCommand,
    ServiceRuntimeContext,
    StartCompletionEvidence,
    StartMilestoneExpectation,
    TaskRuntime,
)
from finishup.ports.start_catalog import SessionBinding, TaskRoute, TaskRouteState
from finishup.protocol.errors import PublicErrorCode, PublicOperationError

__all__ = [
    "LocalBundleRuntime",
    "RuntimeAdapterFactories",
    "RuntimeCachePolicy",
    "RuntimeScope",
    "open_local_bundle_runtime",
]


class _VaultService(Protocol):
    @property
    def generation(self) -> int: ...

    @property
    def ready(self) -> bool: ...

    async def load_bundle_keys(self, bundle_id: str) -> BundleKeys: ...

    async def create_bundle_keys(self, bundle_id: str) -> BundleKeys: ...


class _GenerationCatalog(Protocol):
    @property
    def generation(self) -> int: ...

    async def resolve_route(self, session_id: str) -> TaskRoute | None: ...

    async def session_binding(self, session_id: str) -> SessionBinding | None: ...


class _RouteInspection(Protocol):
    """Private structural result of exact path/schema/recovery inspection."""

    @property
    def route(self) -> TaskRoute: ...

    @property
    def admitted_writer_ids(self) -> frozenset[str]: ...

    @property
    def fresh_allocation(self) -> bool: ...


type CurrentGeneration = Callable[[], int]
type InspectRoute = Callable[[TaskRoute, RouteAccess], Awaitable[object]]
type InspectProvision = Callable[[BundleProvisionCommand], Awaitable[object]]
type ScopeForRoute = Callable[[TaskRoute], object | None]
type AcquireFence = Callable[[object, bool], Awaitable[OwnershipFence]]
type ValidateFence = Callable[[object, OwnershipFence], Awaitable[None]]
type OpenObjects = Callable[
    [object, BundleKeys | None, OwnershipFence, RouteAccess],
    Awaitable[ObjectStorePort],
]
type OpenLedger = Callable[
    [object, ObjectStorePort, OwnershipFence, RouteAccess],
    Awaitable[LedgerPort],
]
type OpenImporter = Callable[
    [object, ObjectStorePort, LedgerPort, OwnershipFence, RouteAccess],
    Awaitable[ImporterPort],
]
type VerifyStart = Callable[
    [object, TaskRuntime, StartMilestoneExpectation],
    Awaitable[StartCompletionEvidence],
]
type CloseEntry = Callable[
    [
        object,
        ObjectStorePort | None,
        LedgerPort | None,
        ImporterPort | None,
        OwnershipFence | None,
    ],
    Awaitable[None],
]


@dataclass(frozen=True, slots=True)
class RuntimeAdapterFactories:
    """One verified, explicit adapter composition selected by the ready daemon."""

    current_service_generation: CurrentGeneration
    inspect_route: InspectRoute
    inspect_provision: InspectProvision
    acquire_fence: AcquireFence
    validate_fence: ValidateFence
    open_objects: OpenObjects
    open_ledger: OpenLedger
    open_importer: OpenImporter
    verify_start: VerifyStart
    close_entry: CloseEntry
    scope_for_route: ScopeForRoute | None = None

    def __post_init__(self) -> None:
        values = (
            self.current_service_generation,
            self.inspect_route,
            self.inspect_provision,
            self.acquire_fence,
            self.validate_fence,
            self.open_objects,
            self.open_ledger,
            self.open_importer,
            self.verify_start,
            self.close_entry,
        )
        if any(not callable(value) for value in values):
            raise TypeError("runtime_factory_invalid")
        if self.scope_for_route is not None and not callable(self.scope_for_route):
            raise TypeError("runtime_scope_factory_invalid")


@dataclass(frozen=True, slots=True)
class RuntimeScope:
    """Repository/project admission scope supplied by the ready catalog composition.

    Scope identity is an opaque commitment or catalog identity. It is retained only in the
    in-process runtime cache and never placed in a task runtime or user-facing error. A project
    is optional because repository-local tasks can exist before project membership is created.
    """

    repository: str
    project: str | None = None

    def __post_init__(self) -> None:
        for value in (self.repository, self.project):
            if value is not None and (type(value) is not str or not value):
                raise ValueError("runtime_scope_invalid")


@dataclass(frozen=True, slots=True)
class RuntimeCachePolicy:
    max_idle_tasks: int = 8
    max_opening_tasks: int = 4
    # This explicit total keeps the historical 8 idle + 4 opening envelope while making the
    # admission ceiling visible to callers that compose multiple live task runtimes.
    max_open_bundle_tasks: int = 12
    max_writer_connections: int = 12
    max_pending_leases_per_task: int = 64
    # Scope limits use the corresponding global limit when a RuntimeScope is supplied. ``None``
    # leaves room for a composition to select a stricter measured project policy.
    max_live_tasks_per_repository: int | None = None
    max_opening_tasks_per_repository: int | None = None
    max_writer_connections_per_repository: int | None = None
    max_live_tasks_per_project: int | None = None
    max_opening_tasks_per_project: int | None = None
    max_writer_connections_per_project: int | None = None

    def __post_init__(self) -> None:
        if (
            type(self.max_idle_tasks) is not int
            or not 1 <= self.max_idle_tasks <= 64
            or type(self.max_opening_tasks) is not int
            or not 1 <= self.max_opening_tasks <= 16
            or type(self.max_open_bundle_tasks) is not int
            or not self.max_opening_tasks <= self.max_open_bundle_tasks <= 256
            or type(self.max_writer_connections) is not int
            or not 1 <= self.max_writer_connections <= self.max_open_bundle_tasks
            or type(self.max_pending_leases_per_task) is not int
            or not 1 <= self.max_pending_leases_per_task <= 256
        ):
            raise ValueError("runtime_cache_policy_invalid")
        scoped = (
            self.max_live_tasks_per_repository,
            self.max_opening_tasks_per_repository,
            self.max_writer_connections_per_repository,
            self.max_live_tasks_per_project,
            self.max_opening_tasks_per_project,
            self.max_writer_connections_per_project,
        )
        if any(
            value is not None
            and (type(value) is not int or not 1 <= value <= self.max_open_bundle_tasks)
            for value in scoped
        ):
            raise ValueError("runtime_cache_policy_invalid")


@dataclass(slots=True, repr=False)
class _Entry:
    inspection: _RouteInspection
    keys: BundleKeys | None
    fence: OwnershipFence
    objects: ObjectStorePort
    ledger: LedgerPort
    importer: ImporterPort
    authority: frozenset[RuntimeCapability]
    scope: RuntimeScope | None = None
    usages: int = 0
    # Leases claimed by _entry_for but not yet counted in usages (validate_fence window).
    pending: int = 0
    rebind_waiters: int = 0
    # Background owners can cooperatively yield work when an explicit start needs to rebind this
    # bundle. Callbacks are process-local and never cross the public runtime boundary.
    rebind_callbacks: dict[int, Callable[[], None]] = field(
        default_factory=dict[int, Callable[[], None]]
    )
    poisoned: bool = False
    closed: bool = False


class _ObservationCapableLedger(Protocol):
    def open_observation_store(self) -> TaskObservationPort: ...


def _observation_for(ledger: LedgerPort) -> TaskObservationPort | None:
    """Expose the durable observation seam for WRITE-capable concrete ledgers.

    Read facades and ledger adapters without the public accessor simply have no
    observation seam; production ingest treats that as an unavailable store.
    """

    opener = getattr(ledger, "open_observation_store", None)
    if opener is None:
        return None
    return cast(_ObservationCapableLedger, ledger).open_observation_store()


class _StructuralLedger:
    """A keyless read facade: record envelopes without their decoded payloads.

    ``STRUCTURAL_READ`` never loads bundle keys when it opens a task, so it has no authority over
    encrypted payload content.  A warm entry opened earlier for payload or write access does hold
    decoded payloads, and before this facade a structural lease on such an entry saw them anyway.
    Code built on that saw payloads only while some other caller kept the entry warm, and it
    failed once the entry was evicted, restarted, or relocked (#839).  This facade removes the
    payload, which is exactly the record a keyless decode produces, and it omits every
    payload-derived projection read.  Warm or cold, a structural lease never sees payload content.
    """

    __slots__ = ("_value",)

    def __init__(self, value: LedgerPort) -> None:
        self._value = value

    async def _structural_events(
        self, session_id: str, after: int, through: int | None
    ) -> AsyncIterator[LedgerRecord]:
        async for record in self._value.load_events(session_id, after=after, through=through):
            yield record if record.payload is None else replace(record, payload=None)

    def load_events(
        self, session_id: str, *, after: int = 0, through: int | None = None
    ) -> AsyncIterator[LedgerRecord]:
        return self._structural_events(session_id, after, through)

    async def load_frontier(self) -> Frontier:
        return await self._value.load_frontier()


class _ReadLedger:
    """A payload read facade with no mutator attributes."""

    __slots__ = ("_value",)

    def __init__(self, value: LedgerPort) -> None:
        self._value = value

    def load_events(
        self, session_id: str, *, after: int = 0, through: int | None = None
    ) -> AsyncIterator[LedgerRecord]:
        return self._value.load_events(session_id, after=after, through=through)

    async def load_frontier(self) -> Frontier:
        return await self._value.load_frontier()

    async def verify_recovery_objects(self) -> int:
        verifier = getattr(self._value, "verify_recovery_objects", None)
        if not callable(verifier):
            raise TypeError("recovery_object_verifier_unavailable")
        return await cast(Callable[[], Awaitable[int]], verifier)()

    async def load_projection(
        self, session_id: str, view: ProjectionView
    ) -> StoredProjection | None:
        return await self._value.load_projection(session_id, view)

    async def load_trusted_projection(
        self, session_id: str, frontier: Frontier
    ) -> ProjectionState | None:
        loader = getattr(self._value, "load_trusted_projection", None)
        if not callable(loader):
            return None
        return await cast(Callable[[str, Frontier], Awaitable[ProjectionState | None]], loader)(
            session_id, frontier
        )

    async def load_case_availability(
        self,
        session_id: str,
        frontier: object,
        projection: ProjectionState,
    ) -> CaseAvailabilityFacts:
        return await self._value.load_case_availability(
            session_id, cast(Frontier, frontier), projection
        )

    async def query_projection(self, query: ProjectionQuery) -> ProjectionPage:
        return await self._value.query_projection(query)

    async def lookup_operation(self, writer_id: str, operation_id: str) -> OperationRecord | None:
        """Read one operation record by request id.

        Omitting this made ``status(view=operation)`` fail for every caller, every time: the view
        exists so an agent that got OPERATION_PENDING can find out what is pending, and it is
        routed read-only, so it received this facade and raised AttributeError before touching
        the ledger. Recovery was unavailable exactly when it was needed.

        It belongs here on the same grounds as the other four: it reads one already-committed
        record and cannot mutate anything.
        """

        return await self._value.lookup_operation(writer_id, operation_id)

    async def lookup_task_operation(
        self, writer_id: str, operation_id: str
    ) -> OperationRecord | None:
        return await self._value.lookup_task_operation(writer_id, operation_id)

    async def load_check_result(
        self, writer_id: str, operation_id: str
    ) -> CheckCommitResult | None:
        """Read one completed check's stored result for its operation page (W6)."""

        return await self._value.load_check_result(writer_id, operation_id)

    async def load_disclosure_wait(
        self, writer_id: str, operation_id: str
    ) -> SemanticDisclosureWait | None:
        """Read the structural continuation for one suspended AI-powered review attempt."""

        return await self._value.load_disclosure_wait(writer_id, operation_id)

    async def load_semantic_progress(
        self, writer_id: str, operation_id: str
    ) -> SemanticProgressRecord | None:
        """Read the structural progress of one check's AI-powered review job (issue #571 A2)."""

        return await self._value.load_semantic_progress(writer_id, operation_id)

    async def has_active_frozen_case(self, session_id: str) -> bool:
        """Read whether a check holds this session's frontier (closure readiness, #913)."""

        return await self._value.has_active_frozen_case(session_id)

    async def lookup_check_admission(
        self, writer_id: str, operation_id: str
    ) -> CheckAdmissionRecord | None:
        """Read why a check request id has no operation record yet (issue #838).

        Operation recovery reads through this facade, and a pre-admission refusal leaves nothing
        else to read: without it an agent told to replay sees only a bare ``absent`` page.
        """

        return await self._value.lookup_check_admission(writer_id, operation_id)


class _PayloadObjects:
    __slots__ = ("_value",)

    def __init__(self, value: ObjectStorePort) -> None:
        self._value = value

    def open_verified(self, ref: ObjectRef) -> AsyncIterator[bytes]:
        return self._value.open_verified(ref)


class _StructuralObjects:
    __slots__ = ()


class _StatusImporter:
    __slots__ = ("_value",)

    def __init__(self, value: ImporterPort) -> None:
        self._value = value

    async def status(self, session_id: str) -> ImportStatusSnapshot:
        return await self._value.status(session_id)


def _error(
    code: PublicErrorCode,
    message: str,
    *,
    retryable: bool,
    safe_details: object | None = None,
) -> PublicOperationError:
    return PublicOperationError(code, message, retryable, safe_details=safe_details)


_STALE = "The ready service generation changed."
_BUSY = "The task is temporarily busy."
_START_REBIND_WAIT_SECONDS = 5.0


class LocalBundleRuntime(BundleRuntimePort):
    """One ready service's lazy task-runtime cache and writer authority."""

    def __init__(
        self,
        context: ServiceRuntimeContext,
        catalog: _GenerationCatalog,
        vault: _VaultService,
        factories: RuntimeAdapterFactories,
        diagnostics: DiagnosticsPort,
        cache_policy: RuntimeCachePolicy,
    ) -> None:
        self._context = context
        self._catalog = catalog
        self._vault = vault
        self._factories = factories
        self._diagnostics = diagnostics
        self._policy = cache_policy
        self._entries: OrderedDict[str, _Entry] = OrderedDict()
        self._opening: dict[str, asyncio.Task[_Entry]] = {}
        self._opening_access: dict[str, RouteAccess] = {}
        self._opening_scopes: dict[str, RuntimeScope | None] = {}
        self._opening_writers: set[str] = set()
        self._usages: dict[int, _Entry] = {}
        self._lock = asyncio.Lock()
        self._idle = asyncio.Condition(self._lock)
        self._opening_limit = asyncio.Semaphore(cache_policy.max_opening_tasks)
        self._closed = False
        self._require_ready()
        self._versions()

    def _require_ready(self) -> None:
        current_service = self._factories.current_service_generation()
        if (
            self._closed
            or type(current_service) is not int
            or current_service != self._context.service_generation
        ):
            raise _error(PublicErrorCode.SERVICE_UNAVAILABLE, _STALE, retryable=True)
        if not self._vault.ready:
            raise _error(
                PublicErrorCode.VAULT_LOCKED,
                "The service vault is locked.",
                retryable=True,
            )
        if self._vault.generation != self._context.vault_generation:
            raise _error(PublicErrorCode.SERVICE_UNAVAILABLE, _STALE, retryable=True)
        if self._catalog.generation != self._context.catalog_generation:
            raise _error(PublicErrorCode.STORAGE_UNSAFE, _STALE, retryable=True)

    def _require_capabilities(self, required: frozenset[RuntimeCapability]) -> None:
        if not required.issubset(self._context.capabilities):
            raise _error(
                PublicErrorCode.STORAGE_UNSAFE,
                "The requested task capability is unavailable.",
                retryable=False,
            )

    async def route(self, command: RouteCommand) -> TaskRuntime:
        if type(command) is not RouteCommand:
            raise _error(PublicErrorCode.INVALID_REQUEST, "The route is invalid.", retryable=False)
        self._require_ready()
        self._require_capabilities(
            command.required_capabilities | self._authority_for(command.access)
        )
        route = await self._catalog.resolve_route(command.session_id)
        if route is None:
            binding = await self._catalog.session_binding(command.session_id)
            if binding is not None and binding.session_id != command.session_id:
                raise _error(
                    PublicErrorCode.SESSION_NOT_FOUND,
                    (
                        "The requested session was replaced. Continue with session_id "
                        f"{binding.session_id} and writer_id {binding.writer_id}."
                    ),
                    retryable=False,
                    safe_details={
                        "reason_code": "session_superseded",
                        "task_id": binding.task_id,
                        "session_id": binding.session_id,
                        "writer_id": binding.writer_id,
                    },
                )
            raise _error(
                PublicErrorCode.SESSION_NOT_FOUND,
                "The requested task attachment was not found.",
                retryable=False,
            )
        if route.session_id != command.session_id or route.state is not TaskRouteState.ACTIVE:
            raise _error(
                PublicErrorCode.SESSION_CONFLICT,
                "The requested task attachment conflicts.",
                retryable=False,
            )
        inspection = cast(
            _RouteInspection, await self._factories.inspect_route(route, command.access)
        )
        self._validate_inspection(route, inspection, command.writer_id)
        entry = await self._entry_for(inspection, command.access)
        return await self._lease(
            entry, command.required_capabilities, command.access, command.writer_id
        )

    async def provision_start(self, command: BundleProvisionCommand) -> TaskRuntime:
        if type(command) is not BundleProvisionCommand:
            raise _error(
                PublicErrorCode.INVALID_REQUEST, "The start route is invalid.", retryable=False
            )
        self._require_ready()
        required = frozenset(
            {
                RuntimeCapability.STRUCTURAL_READ,
                RuntimeCapability.PAYLOAD_READ,
                RuntimeCapability.WRITE,
            }
        )
        self._require_capabilities(required)
        inspection = cast(_RouteInspection, await self._factories.inspect_provision(command))
        try:
            route = inspection.route
        except (AttributeError, TypeError) as exc:
            raise _error(
                PublicErrorCode.STORAGE_CORRUPT,
                "The start inspection is invalid.",
                retryable=False,
            ) from exc
        if (
            route.task_id != command.task_id
            or route.session_id != command.session_id
            or route.bundle_relpath != command.bundle_relpath
            or route.route_generation != command.route_generation
            or route.route_identity_digest != command.route_identity_digest
        ):
            raise _error(
                PublicErrorCode.STORAGE_CORRUPT,
                "The start route identity is inconsistent.",
                retryable=False,
            )
        # Provision inspection can prove only the immutable bundle identity.  The route metadata
        # in ``command`` is the catalog authority and must survive even when bundle inspection
        # cannot reproduce mutable lineage/work facts.
        self._validate_inspection(
            route,
            inspection,
            command.writer_id,
            require_catalog_metadata=False,
        )
        entry = await self._entry_for(
            inspection,
            RouteAccess.WRITE,
            provision_mode=command.mode,
        )
        return await self._lease(entry, required, RouteAccess.WRITE, command.writer_id)

    def _validate_inspection(
        self,
        expected: TaskRoute,
        inspection: _RouteInspection,
        writer_id: str | None,
        *,
        require_catalog_metadata: bool = True,
    ) -> None:
        try:
            inspected_route = inspection.route
            writers = inspection.admitted_writer_ids
            fresh = inspection.fresh_allocation
        except (AttributeError, TypeError) as exc:
            raise _error(
                PublicErrorCode.STORAGE_CORRUPT,
                "The task inspection is invalid.",
                retryable=False,
            ) from exc
        if type(inspected_route) is not TaskRoute or not self._same_bundle_identity(
            inspected_route, expected
        ):
            raise _error(
                PublicErrorCode.STORAGE_CORRUPT,
                "The task route identity is inconsistent.",
                retryable=False,
            )
        if inspected_route.session_id != expected.session_id or (
            require_catalog_metadata and inspected_route != expected
        ):
            raise _error(
                PublicErrorCode.STORAGE_CORRUPT,
                "The task route identity is inconsistent.",
                retryable=False,
            )
        if type(writers) is not frozenset or any(type(item) is not str for item in writers):
            raise _error(
                PublicErrorCode.STORAGE_CORRUPT, "The writer set is invalid.", retryable=False
            )
        if type(fresh) is not bool:
            raise _error(
                PublicErrorCode.STORAGE_CORRUPT,
                "The task allocation state is invalid.",
                retryable=False,
            )
        if writer_id is not None and writer_id not in writers:
            raise _error(
                PublicErrorCode.SESSION_CONFLICT,
                "The requested writer is not attached.",
                retryable=False,
            )

    def _scope_for_route(self, route: TaskRoute) -> RuntimeScope | None:
        provider = self._factories.scope_for_route
        candidate: object | None
        if provider is None:
            # Existing routes carry the repository privacy commitment when one is available. It
            # is a safe, stable fallback scope until the catalog composition supplies an explicit
            # repository/project resolver.
            candidate = getattr(route, "repository_privacy_commitment", None)
        else:
            try:
                candidate = provider(route)
            except Exception as exc:
                raise _error(
                    PublicErrorCode.STORAGE_UNSAFE,
                    "The runtime admission scope is unavailable.",
                    retryable=False,
                ) from exc
        if candidate is None:
            return None
        if isinstance(candidate, RuntimeScope):
            return candidate
        if type(candidate) is str:
            try:
                return RuntimeScope(candidate)
            except ValueError as exc:
                raise _error(
                    PublicErrorCode.STORAGE_CORRUPT,
                    "The runtime admission scope is invalid.",
                    retryable=False,
                ) from exc
        raise _error(
            PublicErrorCode.STORAGE_CORRUPT,
            "The runtime admission scope is invalid.",
            retryable=False,
        )

    @staticmethod
    def _capacity_error(capacity: str, current: int, limit: int) -> PublicOperationError:
        return _error(
            PublicErrorCode.BUNDLE_BUSY,
            f"The runtime {capacity.replace('_', ' ')} capacity is temporarily exhausted; "
            "release a task and retry.",
            retryable=True,
            safe_details={
                # The public error contract intentionally admits only its frozen safe-detail
                # vocabulary.  ``operation`` carries the precise capacity name in the bounded
                # message; ``count``/``limit`` make remediation machine-actionable without
                # smuggling an unregistered key onto the wire.
                "reason_code": "ownership_contended",
                "operation": capacity,
                "count": current,
                "limit": limit,
            },
        )

    def _scope_capacity(
        self,
        scope: RuntimeScope | None,
        *,
        needs_writer: bool,
    ) -> None:
        if scope is None:
            return
        live = sum(entry.scope == scope for entry in self._entries.values()) + sum(
            opening_scope == scope for opening_scope in self._opening_scopes.values()
        )
        repository_limit = self._policy.max_live_tasks_per_repository
        if repository_limit is None:
            repository_limit = self._policy.max_open_bundle_tasks
        if live >= repository_limit:
            raise self._capacity_error("repository_live_tasks", live, repository_limit)
        opening = sum(opening_scope == scope for opening_scope in self._opening_scopes.values())
        opening_limit = self._policy.max_opening_tasks_per_repository
        if opening_limit is None:
            opening_limit = self._policy.max_opening_tasks
        if opening >= opening_limit:
            raise self._capacity_error("repository_opening_tasks", opening, opening_limit)
        if needs_writer:
            writers = sum(
                RuntimeCapability.WRITE in entry.authority
                for entry in self._entries.values()
                if entry.scope == scope
            ) + sum(
                task_id in self._opening_writers
                for task_id, opening_scope in self._opening_scopes.items()
                if opening_scope == scope
            )
            writer_limit = self._policy.max_writer_connections_per_repository
            if writer_limit is None:
                writer_limit = self._policy.max_writer_connections
            if writers >= writer_limit:
                raise self._capacity_error("repository_writer_connections", writers, writer_limit)
        if scope.project is None:
            return
        project_live = sum(
            entry.scope is not None and entry.scope.project == scope.project
            for entry in self._entries.values()
        ) + sum(
            opening_scope is not None and opening_scope.project == scope.project
            for opening_scope in self._opening_scopes.values()
        )
        project_opening = sum(
            opening_scope is not None and opening_scope.project == scope.project
            for opening_scope in self._opening_scopes.values()
        )
        project_live_limit = self._policy.max_live_tasks_per_project
        if project_live_limit is not None and project_live >= project_live_limit:
            raise self._capacity_error("project_live_tasks", project_live, project_live_limit)
        project_opening_limit = self._policy.max_opening_tasks_per_project
        if project_opening_limit is not None and project_opening >= project_opening_limit:
            raise self._capacity_error(
                "project_opening_tasks", project_opening, project_opening_limit
            )
        if needs_writer:
            project_writers = sum(
                RuntimeCapability.WRITE in entry.authority
                for entry in self._entries.values()
                if entry.scope is not None and entry.scope.project == scope.project
            ) + sum(
                task_id in self._opening_writers
                for task_id, opening_scope in self._opening_scopes.items()
                if opening_scope is not None and opening_scope.project == scope.project
            )
            project_writer_limit = self._policy.max_writer_connections_per_project
            if project_writer_limit is not None and project_writers >= project_writer_limit:
                raise self._capacity_error(
                    "project_writer_connections", project_writers, project_writer_limit
                )

    def _schedule_opening_adoption(self, task_id: str, opening: asyncio.Task[_Entry]) -> None:
        """Retain or discard an opening when every waiting route caller cancels.

        ``_entry_for`` shields the shared opener so one cancelled client cannot interrupt a
        sibling.  If that client is the only waiter, no caller remains to publish the completed
        entry or remove a failed task from ``_opening``.  The done callback closes that gap while
        checking task identity so it cannot race a normal waiter that already published it.
        """

        def _done(completed: asyncio.Task[_Entry]) -> None:
            asyncio.create_task(
                self._adopt_finished_opening(task_id, completed),
                name="runtime-opening-adoption",
            )

        opening.add_done_callback(_done)

    async def _adopt_finished_opening(self, task_id: str, opening: asyncio.Task[_Entry]) -> None:
        try:
            opened = opening.result()
        except BaseException:
            async with self._lock:
                if self._opening.get(task_id) is opening:
                    self._opening.pop(task_id, None)
                    self._opening_access.pop(task_id, None)
                    self._opening_scopes.pop(task_id, None)
                    self._opening_writers.discard(task_id)
            return

        ready = True
        try:
            self._require_ready()
        except PublicOperationError:
            ready = False
        evictions: list[_Entry] = []
        async with self._lock:
            if self._opening.get(task_id) is not opening:
                return
            self._opening.pop(task_id, None)
            self._opening_access.pop(task_id, None)
            self._opening_scopes.pop(task_id, None)
            self._opening_writers.discard(task_id)
            if self._closed or not ready:
                opened.poisoned = True
            else:
                self._entries[task_id] = opened
                self._entries.move_to_end(task_id)
                idle = [
                    candidate
                    for candidate in self._entries.values()
                    if candidate.usages == 0
                    and candidate.pending == 0
                    and not candidate.rebind_waiters
                ]
                while len(idle) > self._policy.max_idle_tasks:
                    candidate = idle.pop(0)
                    candidate.poisoned = True
                    self._entries.pop(candidate.inspection.route.task_id, None)
                    evictions.append(candidate)
        for entry in evictions:
            await self._close_entry(entry)
        if opened.poisoned:
            await self._close_entry(opened)

    async def _entry_for(
        self,
        inspection: _RouteInspection,
        access: RouteAccess,
        *,
        provision_mode: BundleProvisionMode | None = None,
    ) -> _Entry:
        task_id = inspection.route.task_id
        required_authority = self._authority_for(access)
        scope = self._scope_for_route(inspection.route)
        needs_writer = RuntimeCapability.WRITE in required_authority
        rebind_deadline = asyncio.get_running_loop().time() + _START_REBIND_WAIT_SECONDS
        while True:
            self._require_ready()
            close_before_open: _Entry | None = None
            rebind_entry: _Entry | None = None
            async with self._lock:
                entry = self._entries.get(task_id)
                if entry is not None and not entry.poisoned:
                    if (
                        self._same_route(entry.inspection.route, inspection.route)
                        and entry.scope == scope
                        and required_authority.issubset(entry.authority)
                    ):
                        # An admitted start gets a chance to drain the old session. Otherwise
                        # repeated background reads could keep rebinding busy indefinitely.
                        if entry.rebind_waiters and provision_mode is None:
                            raise _error(
                                PublicErrorCode.BUNDLE_BUSY,
                                _BUSY,
                                retryable=True,
                                safe_details={"reason_code": "runtime_rebind_busy"},
                            )
                        # Claim a pending lease before release so rebind cannot race the
                        # validate_fence window in _lease where usages is still zero.
                        if entry.pending >= self._policy.max_pending_leases_per_task:
                            raise self._capacity_error(
                                "task_pending_leases",
                                entry.pending,
                                self._policy.max_pending_leases_per_task,
                            )
                        entry.pending += 1
                        self._entries.move_to_end(task_id)
                        return entry
                    # Same-bundle session rebind: attach keeps task/route generation/identity and
                    # only changes session/writer. Reuse the open ports and fence instead of
                    # poison-close-reopen, which would destroy the only writable handle on failure.
                    # Block rebind while any lease is live or still validating (pending > 0).
                    if (
                        self._same_bundle_route(entry.inspection.route, inspection.route)
                        and entry.scope == scope
                        and entry.usages == 0
                        and entry.pending == 0
                        and required_authority.issubset(entry.authority)
                    ):
                        entry.inspection = inspection
                        entry.pending += 1
                        self._entries.move_to_end(task_id)
                        rebind_entry = entry
                    elif entry.usages or entry.pending:
                        if (
                            provision_mode is not None
                            and self._same_bundle_route(entry.inspection.route, inspection.route)
                            and entry.scope == scope
                            and required_authority.issubset(entry.authority)
                        ):
                            if entry.rebind_waiters >= self._policy.max_pending_leases_per_task:
                                raise self._capacity_error(
                                    "task_pending_leases",
                                    entry.rebind_waiters,
                                    self._policy.max_pending_leases_per_task,
                                )
                            entry.rebind_waiters += 1
                            waiting_entry = entry
                            for callback in tuple(entry.rebind_callbacks.values()):
                                try:
                                    callback()
                                except Exception:
                                    # A cooperative background owner cannot make the foreground
                                    # start fail closed. Its lease remains counted until the owner
                                    # retires normally, and the bounded wait still applies.
                                    continue
                            try:
                                # Condition.wait releases the cache lock used by release and
                                # pending-lease cleanup. Cancellation removes only this waiter.
                                async with asyncio.timeout_at(rebind_deadline):
                                    await self._idle.wait_for(
                                        lambda: (
                                            self._closed
                                            or waiting_entry.poisoned
                                            or (
                                                waiting_entry.usages == 0
                                                and waiting_entry.pending == 0
                                            )
                                        )
                                    )
                            except TimeoutError as exc:
                                for operation, count in (
                                    ("runtime_rebind_timeout_usages", waiting_entry.usages),
                                    ("runtime_rebind_timeout_pending", waiting_entry.pending),
                                    (
                                        "runtime_rebind_timeout_callbacks",
                                        len(waiting_entry.rebind_callbacks),
                                    ),
                                ):
                                    record_bounded_counts_without_raising(
                                        component="service.runtime",
                                        operation=operation,
                                        outcome="runtime_rebind_busy",
                                        counts={"operation_count": count},
                                    )
                                raise _error(
                                    PublicErrorCode.BUNDLE_BUSY,
                                    _BUSY,
                                    retryable=True,
                                    safe_details={"reason_code": "runtime_rebind_busy"},
                                ) from exc
                            finally:
                                entry.rebind_waiters -= 1
                            continue
                        raise _error(PublicErrorCode.BUNDLE_BUSY, _BUSY, retryable=True)
                    else:
                        entry.poisoned = True
                        self._entries.pop(task_id, None)
                        close_before_open = entry
                if rebind_entry is None:
                    opening = self._opening.get(task_id)
                    if opening is None:
                        total = len(self._entries) + len(self._opening)
                        if total >= self._policy.max_open_bundle_tasks:
                            raise self._capacity_error(
                                "open_bundle_tasks", total, self._policy.max_open_bundle_tasks
                            )
                        if needs_writer:
                            writers = sum(
                                RuntimeCapability.WRITE in candidate.authority
                                for candidate in self._entries.values()
                            ) + len(self._opening_writers)
                            if writers >= self._policy.max_writer_connections:
                                raise self._capacity_error(
                                    "writer_connections",
                                    writers,
                                    self._policy.max_writer_connections,
                                )
                        self._scope_capacity(scope, needs_writer=needs_writer)
                        opening = asyncio.create_task(
                            self._open_entry(
                                inspection,
                                access,
                                scope=scope,
                                provision_mode=provision_mode,
                            )
                        )
                        self._opening[task_id] = opening
                        self._opening_access[task_id] = access
                        self._opening_scopes[task_id] = scope
                        if needs_writer:
                            self._opening_writers.add(task_id)
                        self._schedule_opening_adoption(task_id, opening)
                    elif not required_authority.issubset(
                        self._authority_for(self._opening_access[task_id])
                    ):
                        # Do not let a read-only opening be handed out as a write-capable runtime.
                        # The caller can retry after the existing opener is published and evicted.
                        raise _error(
                            PublicErrorCode.BUNDLE_BUSY,
                            "The task runtime is opening with insufficient authority; retry.",
                            retryable=True,
                            safe_details={
                                "reason_code": "runtime_opening_authority",
                                "action": "retry_after_open",
                            },
                        )
                else:
                    opening = None
            if rebind_entry is not None:
                try:
                    await self._factories.validate_fence(
                        rebind_entry.inspection, rebind_entry.fence
                    )
                    rebind_session = getattr(rebind_entry.importer, "rebind_session", None)
                    if callable(rebind_session):
                        rebind_session(rebind_entry.inspection.route.session_id)
                except BaseException:
                    async with self._lock:
                        rebind_entry.pending = max(0, rebind_entry.pending - 1)
                        if self._entries.get(task_id) is rebind_entry:
                            rebind_entry.poisoned = True
                            self._entries.pop(task_id, None)
                        self._idle.notify_all()
                    await self._close_entry(rebind_entry)
                    raise
                return rebind_entry
            if close_before_open is not None:
                await self._close_entry(close_before_open)
            assert opening is not None
            try:
                opened = await asyncio.shield(opening)
            except asyncio.CancelledError:
                # The opener continues so another follower can observe its durable outcome.
                raise
            except BaseException:
                async with self._lock:
                    if opening.done() and self._opening.get(task_id) is opening:
                        self._opening.pop(task_id, None)
                        self._opening_access.pop(task_id, None)
                        self._opening_scopes.pop(task_id, None)
                        self._opening_writers.discard(task_id)
                raise
            ready = True
            try:
                self._require_ready()
            except PublicOperationError:
                ready = False
            async with self._lock:
                if self._opening.get(task_id) is not opening:
                    continue
                self._opening.pop(task_id, None)
                self._opening_access.pop(task_id, None)
                self._opening_scopes.pop(task_id, None)
                self._opening_writers.discard(task_id)
                if self._closed or not ready:
                    opened.poisoned = True
                else:
                    opened.pending += 1
                    self._entries[task_id] = opened
                    self._entries.move_to_end(task_id)
                    return opened
            await self._close_entry(opened)
            raise _error(PublicErrorCode.SERVICE_UNAVAILABLE, _STALE, retryable=True)

    async def _open_entry(
        self,
        inspection: _RouteInspection,
        access: RouteAccess,
        *,
        scope: RuntimeScope | None,
        provision_mode: BundleProvisionMode | None,
    ) -> _Entry:
        async with self._opening_limit:
            self._require_ready()
            keys: BundleKeys | None = None
            fence: OwnershipFence | None = None
            objects: ObjectStorePort | None = None
            ledger: LedgerPort | None = None
            importer: ImporterPort | None = None
            try:
                if access is not RouteAccess.STRUCTURAL_READ:
                    try:
                        keys = await self._vault.load_bundle_keys(inspection.route.task_id)
                    except KeyStoreError as exc:
                        if (
                            provision_mode is BundleProvisionMode.CREATED
                            and inspection.fresh_allocation
                            and exc.reason is KeyStoreReason.KEY_MISSING
                        ):
                            keys = await self._vault.create_bundle_keys(inspection.route.task_id)
                        else:
                            raise
                fence = await self._factories.acquire_fence(
                    inspection,
                    access
                    in {RouteAccess.WRITE, RouteAccess.IMPORT_REVIEW, RouteAccess.MAINTENANCE},
                )
                if (
                    type(fence) is not OwnershipFence
                    or fence.service_instance_id != self._context.service_instance_id
                    or fence.service_generation != self._context.service_generation
                ):
                    raise _error(
                        PublicErrorCode.STORAGE_UNSAFE,
                        "The task ownership fence is invalid.",
                        retryable=False,
                    )
                objects = await self._factories.open_objects(inspection, keys, fence, access)
                ledger = await self._factories.open_ledger(inspection, objects, fence, access)
                importer = await self._factories.open_importer(
                    inspection, objects, ledger, fence, access
                )
                self._require_ready()
                return _Entry(
                    inspection,
                    keys,
                    fence,
                    objects,
                    ledger,
                    importer,
                    self._authority_for(access),
                    scope,
                )
            except KeyStoreError as exc:
                if (
                    objects is not None
                    or ledger is not None
                    or importer is not None
                    or fence is not None
                ):
                    await self._factories.close_entry(inspection, objects, ledger, importer, fence)
                code = (
                    PublicErrorCode.VAULT_LOCKED
                    if exc.reason is KeyStoreReason.VAULT_LOCKED
                    else PublicErrorCode.STORAGE_CORRUPT
                )
                raise _error(
                    code,
                    "The bundle key is unavailable.",
                    retryable=code is PublicErrorCode.VAULT_LOCKED,
                ) from exc
            except BaseException:
                if (
                    objects is not None
                    or ledger is not None
                    or importer is not None
                    or fence is not None
                ):
                    await self._factories.close_entry(inspection, objects, ledger, importer, fence)
                raise

    @staticmethod
    def _same_bundle_identity(left: TaskRoute, right: TaskRoute) -> bool:
        return (
            left.task_id == right.task_id
            and left.bundle_relpath == right.bundle_relpath
            and left.route_generation == right.route_generation
            and left.route_identity_digest == right.route_identity_digest
        )

    @staticmethod
    def _same_bundle_route(left: TaskRoute, right: TaskRoute) -> bool:
        return (
            LocalBundleRuntime._same_bundle_identity(left, right)
            and left.repository_privacy_commitment == right.repository_privacy_commitment
        )

    @staticmethod
    def _same_route(left: TaskRoute, right: TaskRoute) -> bool:
        return (
            LocalBundleRuntime._same_bundle_route(left, right)
            and left.session_id == right.session_id
        )

    @staticmethod
    def _authority_for(access: RouteAccess) -> frozenset[RuntimeCapability]:
        if access is RouteAccess.STRUCTURAL_READ:
            return frozenset({RuntimeCapability.STRUCTURAL_READ})
        if access is RouteAccess.PAYLOAD_READ:
            return frozenset({RuntimeCapability.STRUCTURAL_READ, RuntimeCapability.PAYLOAD_READ})
        return frozenset(
            {
                RuntimeCapability.STRUCTURAL_READ,
                RuntimeCapability.PAYLOAD_READ,
                RuntimeCapability.WRITE,
            }
        )

    async def _lease(
        self,
        entry: _Entry,
        admitted: frozenset[RuntimeCapability],
        access: RouteAccess,
        writer_id: str | None,
    ) -> TaskRuntime:
        # pending was claimed in _entry_for; release it on every exit path so rebind cannot
        # observe a zero-usages window while validate_fence is still in flight.
        try:
            self._require_ready()
            await self._factories.validate_fence(entry.inspection, entry.fence)
            self._require_ready()
            route = entry.inspection.route
            ledger: LedgerPort
            objects: ObjectStorePort
            importer: ImporterPort
            observation: TaskObservationPort | None = None
            if access in {RouteAccess.WRITE, RouteAccess.IMPORT_REVIEW, RouteAccess.MAINTENANCE}:
                ledger = entry.ledger
                objects = entry.objects
                importer = entry.importer
                if RuntimeCapability.WRITE in admitted:
                    observation = _observation_for(entry.ledger)
            else:
                ledger = cast(
                    LedgerPort,
                    _ReadLedger(entry.ledger)
                    if access is RouteAccess.PAYLOAD_READ
                    else _StructuralLedger(entry.ledger),
                )
                objects = cast(
                    ObjectStorePort,
                    _PayloadObjects(entry.objects)
                    if access is RouteAccess.PAYLOAD_READ
                    else _StructuralObjects(),
                )
                importer = cast(ImporterPort, _StatusImporter(entry.importer))
            versions = self._versions()
            runtime = TaskRuntime(
                task_id=route.task_id,
                session_id=route.session_id,
                writer_id=writer_id,
                capabilities=admitted,
                ledger=ledger,
                objects=objects,
                importer=importer,
                projection_version=versions["projection_version"],
                engine_version=versions["engine_version"],
                protocol_version=versions["protocol_version"],
                bundle_schema_version=versions["bundle_schema_version"],
                fence=entry.fence,
                observation=observation,
            )
            async with self._lock:
                if entry.poisoned or self._closed:
                    raise _error(PublicErrorCode.SERVICE_UNAVAILABLE, _STALE, retryable=True)
                entry.usages += 1
                entry.pending = max(0, entry.pending - 1)
                self._usages[id(runtime)] = entry
                self._idle.notify_all()
            return runtime
        except BaseException:
            async with self._lock:
                entry.pending = max(0, entry.pending - 1)
                self._idle.notify_all()
            raise

    def _versions(self) -> dict[str, str]:
        names = (
            "projection_version",
            "engine_version",
            "protocol_version",
            "bundle_schema_version",
        )
        result: dict[str, str] = {}
        for name in names:
            value = self._context.version_manifest.get(name)
            if type(value) is not str:
                raise _error(
                    PublicErrorCode.STORAGE_UNSAFE,
                    "The runtime version manifest is incomplete.",
                    retryable=False,
                )
            result[name] = value
        return result

    async def verify_start(
        self,
        runtime: TaskRuntime,
        expectation: StartMilestoneExpectation,
    ) -> StartCompletionEvidence:
        if type(runtime) is not TaskRuntime or type(expectation) is not StartMilestoneExpectation:
            raise _error(
                PublicErrorCode.INVALID_REQUEST, "The start proof is invalid.", retryable=False
            )
        self._require_ready()
        async with self._lock:
            entry = self._usages.get(id(runtime))
            if entry is None or entry.poisoned or runtime.fence != entry.fence:
                raise _error(PublicErrorCode.STORAGE_UNSAFE, _STALE, retryable=True)
        if (
            runtime.task_id != expectation.task_id
            or runtime.session_id != expectation.session_id
            or runtime.writer_id != expectation.writer_id
            or entry.inspection.route.route_generation != expectation.route_generation
            or entry.inspection.route.route_identity_digest != expectation.route_identity_digest
        ):
            raise _error(
                PublicErrorCode.SESSION_CONFLICT,
                "The start proof identity conflicts.",
                retryable=False,
            )
        evidence = await asyncio.shield(
            self._factories.verify_start(entry.inspection, runtime, expectation)
        )
        await self._factories.validate_fence(entry.inspection, entry.fence)
        self._require_ready()
        # evidence.owner_generation is the start-lease / service generation; bundle fence
        # rotation is already caught by validate_fence against fence.owner_generation + nonce.
        if evidence.owner_generation != entry.fence.service_generation:
            raise _error(PublicErrorCode.STORAGE_UNSAFE, _STALE, retryable=True)
        return evidence

    async def release(self, runtime: TaskRuntime) -> None:
        if type(runtime) is not TaskRuntime:
            return
        evictions: list[_Entry] = []
        async with self._lock:
            entry = self._usages.pop(id(runtime), None)
            if entry is None:
                return
            entry.usages -= 1
            entry.rebind_callbacks.pop(id(runtime), None)
            self._idle.notify_all()
            idle = [
                candidate
                for candidate in self._entries.values()
                if candidate.usages == 0 and candidate.pending == 0 and not candidate.rebind_waiters
            ]
            while len(idle) > self._policy.max_idle_tasks:
                candidate = idle.pop(0)
                candidate.poisoned = True
                self._entries.pop(candidate.inspection.route.task_id, None)
                evictions.append(candidate)
        for entry in evictions:
            await self._close_entry(entry)

    def register_rebind_callback(self, runtime: TaskRuntime, callback: Callable[[], None]) -> bool:
        """Register a process-local callback for foreground rebind admission.

        Background owners use this to yield an in-flight, cancellable operation when an explicit
        start is waiting for the same bundle. The callback is advisory: the runtime keeps the
        usage counted until the owner releases it, and no callback data is persisted or exposed.
        """

        if type(runtime) is not TaskRuntime or not callable(callback):
            return False
        # Registration is a synchronous service-loop lifecycle operation. The runtime cache
        # lock is never awaited here, so _entry_for cannot interleave with this lookup or map
        # update on the owning loop.
        entry = self._usages.get(id(runtime))
        if entry is None or entry.poisoned or entry.closed:
            return False
        token = id(runtime)
        entry.rebind_callbacks[token] = callback
        if entry.rebind_waiters:
            try:
                callback()
            except Exception:
                entry.rebind_callbacks.pop(token, None)
                return False
        return True

    def unregister_rebind_callback(
        self, runtime: TaskRuntime, callback: Callable[[], None]
    ) -> None:
        """Remove one process-local foreground-rebind callback."""

        if type(runtime) is not TaskRuntime:
            return
        entry = self._usages.get(id(runtime))
        if entry is None:
            return
        if entry.rebind_callbacks.get(id(runtime)) is callback:
            entry.rebind_callbacks.pop(id(runtime), None)

    async def _close_entry(self, entry: _Entry) -> None:
        if entry.closed:
            return
        entry.closed = True
        entry.rebind_callbacks.clear()
        try:
            await asyncio.shield(
                self._factories.close_entry(
                    entry.inspection,
                    entry.objects,
                    entry.ledger,
                    entry.importer,
                    entry.fence,
                )
            )
        except Exception:
            # Close is best-effort here; lifecycle decides whether inability to prove drain is fatal.
            return

    async def close(self) -> None:
        async with self._lock:
            if self._closed:
                return
            self._closed = True
            self._idle.notify_all()
            entries = list(self._entries.values())
            openings = list(self._opening.values())
            self._entries.clear()
            self._usages.clear()
            self._opening.clear()
            self._opening_access.clear()
            self._opening_scopes.clear()
            self._opening_writers.clear()
            for entry in entries:
                entry.poisoned = True
        if openings:
            results = await asyncio.gather(
                *(asyncio.shield(task) for task in openings), return_exceptions=True
            )
            entries.extend(result for result in results if type(result) is _Entry)
        for entry in entries:
            await self._close_entry(entry)


async def open_local_bundle_runtime(
    context: ServiceRuntimeContext,
    catalog: _GenerationCatalog,
    vault: _VaultService,
    factories: RuntimeAdapterFactories,
    diagnostics: DiagnosticsPort,
    versions: object,
    cache_policy: RuntimeCachePolicy = RuntimeCachePolicy(),
) -> LocalBundleRuntime:
    """Validate the ready composition without opening a task bundle."""

    del versions  # Context carries the immutable version manifest; no ambient lookup is allowed.
    if (
        type(context) is not ServiceRuntimeContext
        or type(factories) is not RuntimeAdapterFactories
        or type(cache_policy) is not RuntimeCachePolicy
        or not hasattr(catalog, "resolve_route")
        or not hasattr(catalog, "generation")
        or not hasattr(vault, "load_bundle_keys")
        or not hasattr(vault, "generation")
        or not hasattr(diagnostics, "record")
    ):
        raise TypeError("local_bundle_runtime_construction_invalid")
    return LocalBundleRuntime(context, catalog, vault, factories, diagnostics, cache_policy)
