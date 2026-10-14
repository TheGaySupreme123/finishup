"""Ready-service runtime generation, capability, and facade tests."""

from __future__ import annotations

import asyncio
import hashlib
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
from typing import cast

import pytest

import finishup.adapters.runtime as runtime_module
from finishup.adapters.runtime import (
    LocalBundleRuntime,
    RuntimeAdapterFactories,
    RuntimeCachePolicy,
    open_local_bundle_runtime,
)
from finishup.adapters.session_events import (
    LinuxLogin1Backend,
    SessionEventMonitor,
)
from finishup.ports.diagnostics import RuntimeCapability, StartupCheckResult
from finishup.ports.importer import ImporterPort
from finishup.ports.keys import BundleKeys
from finishup.ports.ledger import LedgerPort
from finishup.ports.objects import ObjectStorePort
from finishup.ports.runtime import (
    BundleProvisionMode,
    OwnershipFence,
    RouteAccess,
    RouteCommand,
    ServiceRuntimeContext,
    StartCompletionEvidence,
    StartMilestoneExpectation,
    TaskRuntime,
)
from finishup.ports.start_catalog import SessionBinding, TaskRoute, TaskRouteState
from finishup.protocol.canonical import canonical_digest
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.ids import PREFIX_BY_KIND, IdKind
from finishup.service.lifecycle import SessionSecurityEvent


@pytest.mark.anyio
async def test_start_waits_for_pending_fence_validation_and_wakes_on_cancellation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    route, writer = _route()
    harness = _Harness(1, route, writer)
    runtime = await open_local_bundle_runtime(
        _context(frozenset(RuntimeCapability)),
        _Catalog(route),
        _Vault(),
        harness.factories(),
        _Diagnostics(),
        object(),
    )
    assert isinstance(runtime, LocalBundleRuntime)
    command = RouteCommand(
        route.session_id, writer, RouteAccess.WRITE, frozenset({RuntimeCapability.WRITE})
    )
    held = await runtime.route(command)
    await runtime.release(held)
    validating = asyncio.Event()
    waiting = asyncio.Event()
    gate = asyncio.Event()
    factories = runtime._factories  # pyright: ignore[reportPrivateUsage]

    async def validate(inspection: object, fence: OwnershipFence) -> None:
        if cast(_Inspection, inspection).route.session_id == route.session_id:
            validating.set()
            await gate.wait()
        await factories.validate_fence(inspection, fence)

    monkeypatch.setattr(runtime, "_factories", replace(factories, validate_fence=validate))
    condition = runtime._idle  # pyright: ignore[reportPrivateUsage]
    original_wait = condition.wait_for

    async def wait(predicate: Callable[[], bool]) -> bool:
        waiting.set()
        return await original_wait(predicate)

    monkeypatch.setattr(condition, "wait_for", wait)
    old_attempt = asyncio.create_task(runtime.route(command))
    await asyncio.wait_for(validating.wait(), 5)
    entry = runtime._entries[route.task_id]  # pyright: ignore[reportPrivateUsage]
    assert entry.usages == 0 and entry.pending == 1
    new_route = replace(route, session_id=_id(IdKind.SESSION, 745))
    attach = asyncio.create_task(
        runtime._entry_for(  # pyright: ignore[reportPrivateUsage]
            _Inspection(new_route, frozenset({writer})),
            RouteAccess.WRITE,
            provision_mode=BundleProvisionMode.ATTACHED,
        )
    )
    await asyncio.wait_for(waiting.wait(), 5)
    old_attempt.cancel()
    with pytest.raises(asyncio.CancelledError):
        await old_attempt
    rebound = await asyncio.wait_for(attach, 5)
    assert rebound is entry and entry.rebind_waiters == 0
    assert entry.pending == 1 and entry.inspection.route.session_id == new_route.session_id
    leased = await runtime._lease(  # pyright: ignore[reportPrivateUsage]
        entry, frozenset({RuntimeCapability.WRITE}), RouteAccess.WRITE, writer
    )
    await runtime.release(leased)
    await runtime.close()


@pytest.mark.anyio
@pytest.mark.parametrize("boundary", ["cancel", "generation", "close"])
async def test_start_rebind_wait_cancellation_generation_and_shutdown(
    boundary: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    route, writer = _route()
    harness = _Harness(1, route, writer)
    runtime = await open_local_bundle_runtime(
        _context(frozenset(RuntimeCapability)),
        _Catalog(route),
        _Vault(),
        harness.factories(),
        _Diagnostics(),
        object(),
    )
    assert isinstance(runtime, LocalBundleRuntime)
    command = RouteCommand(
        route.session_id, writer, RouteAccess.WRITE, frozenset({RuntimeCapability.WRITE})
    )
    held = await runtime.route(command)
    new_route = replace(route, session_id=_id(IdKind.SESSION, 744))
    entered = asyncio.Event()
    condition = runtime._idle  # pyright: ignore[reportPrivateUsage]
    wait = condition.wait_for

    async def observed_wait(predicate: Callable[[], bool]) -> bool:
        entered.set()
        return await wait(predicate)

    monkeypatch.setattr(condition, "wait_for", observed_wait)
    attempt = asyncio.create_task(
        runtime._entry_for(  # pyright: ignore[reportPrivateUsage]
            _Inspection(new_route, frozenset({writer})),
            RouteAccess.WRITE,
            provision_mode=BundleProvisionMode.ATTACHED,
        )
    )
    await asyncio.wait_for(entered.wait(), 5)
    entry = runtime._entries[route.task_id]  # pyright: ignore[reportPrivateUsage]
    assert entry.rebind_waiters == 1
    # An ongoing background producer cannot starve the waiting start with fresh leases.
    with pytest.raises(PublicOperationError) as busy:
        await runtime.route(command)
    assert busy.value.code is PublicErrorCode.BUNDLE_BUSY
    if boundary == "cancel":
        attempt.cancel()
        with pytest.raises(asyncio.CancelledError):
            await attempt
    else:
        if boundary == "generation":
            harness.service_generation = 2
            await runtime.release(held)
        else:
            await runtime.close()
        with pytest.raises(PublicOperationError) as stale:
            await asyncio.wait_for(attempt, 5)
        assert stale.value.code is PublicErrorCode.SERVICE_UNAVAILABLE
    assert entry.rebind_waiters == 0
    assert entry.inspection.route.session_id == route.session_id
    await runtime.release(held)
    await runtime.close()


@pytest.mark.anyio
async def test_start_rebind_notifies_background_owner_before_waiting() -> None:
    """A foreground attach gives a cooperative background owner a chance to release its lease."""

    route, writer = _route()
    harness = _Harness(1, route, writer)
    runtime = await open_local_bundle_runtime(
        _context(frozenset(RuntimeCapability)),
        _Catalog(route),
        _Vault(),
        harness.factories(),
        _Diagnostics(),
        object(),
    )
    assert isinstance(runtime, LocalBundleRuntime)
    command = RouteCommand(
        route.session_id, writer, RouteAccess.WRITE, frozenset({RuntimeCapability.WRITE})
    )
    held = await runtime.route(command)
    callback_called = asyncio.Event()

    def yield_background_owner() -> None:
        callback_called.set()
        asyncio.create_task(runtime.release(held))

    assert runtime.register_rebind_callback(held, yield_background_owner)
    new_route = replace(route, session_id=_id(IdKind.SESSION, 746))
    attach = asyncio.create_task(
        runtime._entry_for(  # pyright: ignore[reportPrivateUsage]
            _Inspection(new_route, frozenset({writer})),
            RouteAccess.WRITE,
            provision_mode=BundleProvisionMode.ATTACHED,
        )
    )
    await asyncio.wait_for(callback_called.wait(), 5)
    entry = await asyncio.wait_for(attach, 5)
    assert entry.inspection.route.session_id == new_route.session_id
    assert entry.rebind_waiters == 0
    rebound = await runtime._lease(  # pyright: ignore[reportPrivateUsage]
        entry, frozenset({RuntimeCapability.WRITE}), RouteAccess.WRITE, writer
    )
    await runtime.release(rebound)
    await runtime.close()


@pytest.mark.anyio
async def test_rebind_timeout_records_remaining_owner_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A timeout exposes the remaining lease count without exposing owner payloads."""

    route, writer = _route()
    harness = _Harness(1, route, writer)
    runtime = await open_local_bundle_runtime(
        _context(frozenset(RuntimeCapability)),
        _Catalog(route),
        _Vault(),
        harness.factories(),
        _Diagnostics(),
        object(),
    )
    assert isinstance(runtime, LocalBundleRuntime)
    command = RouteCommand(
        route.session_id, writer, RouteAccess.WRITE, frozenset({RuntimeCapability.WRITE})
    )
    held = await runtime.route(command)
    recorded: list[dict[str, object]] = []

    def record(**fields: object) -> None:
        recorded.append(fields)

    monkeypatch.setattr(runtime_module, "_START_REBIND_WAIT_SECONDS", 0.02)
    monkeypatch.setattr(runtime_module, "record_bounded_counts_without_raising", record)
    new_route = replace(route, session_id=_id(IdKind.SESSION, 748))
    with pytest.raises(PublicOperationError) as busy:
        await runtime._entry_for(  # pyright: ignore[reportPrivateUsage]
            _Inspection(new_route, frozenset({writer})),
            RouteAccess.WRITE,
            provision_mode=BundleProvisionMode.ATTACHED,
        )
    assert busy.value.code is PublicErrorCode.BUNDLE_BUSY
    assert [item["operation"] for item in recorded] == [
        "runtime_rebind_timeout_usages",
        "runtime_rebind_timeout_pending",
        "runtime_rebind_timeout_callbacks",
    ]
    assert all(item["component"] == "service.runtime" for item in recorded)
    assert [item["counts"] for item in recorded] == [
        {"operation_count": 1},
        {"operation_count": 0},
        {"operation_count": 0},
    ]
    await runtime.release(held)
    await runtime.close()


@pytest.mark.anyio
async def test_rebind_callback_lifetime_is_scoped_to_each_runtime_lease() -> None:
    """Releasing one shared entry user cannot erase another owner's yield callback."""

    route, writer = _route()
    harness = _Harness(1, route, writer)
    runtime = await open_local_bundle_runtime(
        _context(frozenset(RuntimeCapability)),
        _Catalog(route),
        _Vault(),
        harness.factories(),
        _Diagnostics(),
        object(),
    )
    assert isinstance(runtime, LocalBundleRuntime)
    command = RouteCommand(
        route.session_id, writer, RouteAccess.WRITE, frozenset({RuntimeCapability.WRITE})
    )
    first = await runtime.route(command)
    second = await runtime.route(command)
    first_called = asyncio.Event()
    second_called = asyncio.Event()

    def first_callback() -> None:
        first_called.set()

    def second_callback() -> None:
        second_called.set()
        asyncio.create_task(runtime.release(second))

    assert runtime.register_rebind_callback(first, first_callback)
    assert runtime.register_rebind_callback(second, second_callback)
    await runtime.release(first)

    new_route = replace(route, session_id=_id(IdKind.SESSION, 747))
    attach = asyncio.create_task(
        runtime._entry_for(  # pyright: ignore[reportPrivateUsage]
            _Inspection(new_route, frozenset({writer})),
            RouteAccess.WRITE,
            provision_mode=BundleProvisionMode.ATTACHED,
        )
    )
    await asyncio.wait_for(second_called.wait(), 5)
    rebound = await asyncio.wait_for(attach, 5)
    assert not first_called.is_set()
    leased = await runtime._lease(  # pyright: ignore[reportPrivateUsage]
        rebound, frozenset({RuntimeCapability.WRITE}), RouteAccess.WRITE, writer
    )
    await runtime.release(leased)
    await runtime.close()


def _id(kind: IdKind, value: int) -> str:
    raw = bytearray(value.to_bytes(16, "big"))
    raw[6] = (raw[6] & 0x0F) | 0x40
    raw[8] = (raw[8] & 0x3F) | 0x80
    return PREFIX_BY_KIND[kind] + str(uuid.UUID(bytes=bytes(raw)))


@dataclass(frozen=True, slots=True)
class _Inspection:
    route: TaskRoute
    admitted_writer_ids: frozenset[str]
    fresh_allocation: bool = False


class _Catalog:
    def __init__(self, route: TaskRoute, binding: SessionBinding | None = None) -> None:
        self.generation = 3
        self.route_value = route
        self.binding = binding
        self.lookups = 0

    async def resolve_route(self, session_id: str) -> TaskRoute | None:
        self.lookups += 1
        return self.route_value if session_id == self.route_value.session_id else None

    async def session_binding(self, session_id: str) -> SessionBinding | None:
        if self.binding is None or session_id == self.route_value.session_id:
            return None
        return self.binding


class _Vault:
    def __init__(self) -> None:
        self.generation = 2
        self.ready = True
        self.loads = 0

    async def load_bundle_keys(self, bundle_id: str) -> BundleKeys:
        del bundle_id
        self.loads += 1
        return cast(BundleKeys, object())

    async def create_bundle_keys(self, bundle_id: str) -> BundleKeys:
        del bundle_id
        raise AssertionError("route_must_not_create_keys")


class _Diagnostics:
    def record(self, result: StartupCheckResult) -> None:
        del result


class _Port:
    pass


@dataclass(slots=True)
class _Harness:
    service_generation: int
    route: TaskRoute
    writer_id: str
    opens: int = 0
    closes: int = 0
    inspections: int = 0

    def factories(self) -> RuntimeAdapterFactories:
        async def inspect(route: TaskRoute, access: RouteAccess) -> _Inspection:
            del access
            self.inspections += 1
            return _Inspection(route, frozenset({self.writer_id}))

        async def inspect_provision(command: object) -> _Inspection:
            del command
            return _Inspection(self.route, frozenset({self.writer_id}), True)

        async def acquire(value: object, writer: bool) -> OwnershipFence:
            del value, writer
            self.opens += 1
            return OwnershipFence(
                _id(IdKind.SERVICE_INSTANCE, 11), self.service_generation, 4, "nonce_value_123456"
            )

        async def validate(value: object, fence: OwnershipFence) -> None:
            del value
            assert fence.owner_generation == 4

        async def objects(
            value: object,
            keys: BundleKeys | None,
            fence: OwnershipFence,
            access: RouteAccess,
        ) -> ObjectStorePort:
            del value, keys, fence, access
            return cast(ObjectStorePort, _Port())

        async def ledger(
            value: object,
            objects: ObjectStorePort,
            fence: OwnershipFence,
            access: RouteAccess,
        ) -> LedgerPort:
            del value, objects, fence, access
            return cast(LedgerPort, _Port())

        async def importer(
            value: object,
            objects: ObjectStorePort,
            ledger: LedgerPort,
            fence: OwnershipFence,
            access: RouteAccess,
        ) -> ImporterPort:
            del value, objects, ledger, fence, access
            return cast(ImporterPort, _Port())

        async def verify(
            value: object,
            runtime: TaskRuntime,
            expectation: StartMilestoneExpectation,
        ) -> StartCompletionEvidence:
            del value, runtime, expectation
            raise AssertionError("not_used")

        async def close(*args: object) -> None:
            del args
            self.closes += 1

        return RuntimeAdapterFactories(
            current_service_generation=lambda: self.service_generation,
            inspect_route=inspect,
            inspect_provision=inspect_provision,
            acquire_fence=acquire,
            validate_fence=validate,
            open_objects=objects,
            open_ledger=ledger,
            open_importer=importer,
            verify_start=verify,
            close_entry=close,
        )


def _route() -> tuple[TaskRoute, str]:
    task = _id(IdKind.TASK, 1)
    session = _id(IdKind.SESSION, 2)
    writer = _id(IdKind.WRITER, 3)
    generation = 1
    return (
        TaskRoute(
            task,
            session,
            f"tasks/{task}",
            generation,
            TaskRouteState.ACTIVE,
            canonical_digest(
                {
                    "task_id": task,
                    "bundle_relpath": f"tasks/{task}",
                    "route_generation": generation,
                }
            ),
        ),
        writer,
    )


def _context(capabilities: frozenset[RuntimeCapability]) -> ServiceRuntimeContext:
    return ServiceRuntimeContext(
        service_instance_id=_id(IdKind.SERVICE_INSTANCE, 11),
        service_generation=1,
        vault_generation=2,
        catalog_generation=3,
        capabilities=capabilities,
        version_manifest={
            "bundle_schema_version": "2",
            "engine_version": "0.1.0",
            "projection_version": "1",
            "protocol_version": "0.1",
        },
        shutdown_token=object(),
    )


@pytest.mark.anyio
async def test_stale_service_rejects_before_catalog_route_io() -> None:
    route, writer = _route()
    catalog = _Catalog(route)
    vault = _Vault()
    harness = _Harness(1, route, writer)
    runtime = await open_local_bundle_runtime(
        _context(frozenset(RuntimeCapability)),
        catalog,
        vault,
        harness.factories(),
        _Diagnostics(),
        object(),
    )
    harness.service_generation = 2
    with pytest.raises(PublicOperationError) as caught:
        await runtime.route(
            RouteCommand(
                route.session_id,
                None,
                RouteAccess.STRUCTURAL_READ,
                frozenset({RuntimeCapability.STRUCTURAL_READ}),
            )
        )
    assert caught.value.code is PublicErrorCode.SERVICE_UNAVAILABLE
    assert catalog.lookups == 0


@pytest.mark.anyio
async def test_superseded_session_returns_current_bounded_binding() -> None:
    route, writer = _route()
    retired_session = _id(IdKind.SESSION, 4)
    binding = SessionBinding(route.task_id, route.session_id, writer)
    catalog = _Catalog(route, binding)
    runtime = await open_local_bundle_runtime(
        _context(frozenset({RuntimeCapability.STRUCTURAL_READ})),
        catalog,
        _Vault(),
        _Harness(1, route, writer).factories(),
        _Diagnostics(),
        object(),
    )

    with pytest.raises(PublicOperationError) as caught:
        await runtime.route(
            RouteCommand(
                retired_session,
                None,
                RouteAccess.STRUCTURAL_READ,
                frozenset({RuntimeCapability.STRUCTURAL_READ}),
            )
        )

    assert caught.value.code is PublicErrorCode.SESSION_NOT_FOUND
    assert caught.value.retryable is False
    assert caught.value.safe_details == {
        "continuation": "session_rebind_required",
        "reason_code": "session_superseded",
        "task_id": route.task_id,
        "session_id": route.session_id,
        "writer_id": writer,
    }
    await runtime.close()


@pytest.mark.anyio
async def test_capability_ceiling_and_writer_membership_fail_closed() -> None:
    route, writer = _route()
    catalog = _Catalog(route)
    vault = _Vault()
    harness = _Harness(1, route, writer)
    runtime = await open_local_bundle_runtime(
        _context(frozenset({RuntimeCapability.STRUCTURAL_READ, RuntimeCapability.WRITE})),
        catalog,
        vault,
        harness.factories(),
        _Diagnostics(),
        object(),
    )
    with pytest.raises(PublicOperationError) as unavailable:
        await runtime.route(
            RouteCommand(
                route.session_id,
                None,
                RouteAccess.PAYLOAD_READ,
                frozenset({RuntimeCapability.PAYLOAD_READ}),
            )
        )
    assert unavailable.value.code is PublicErrorCode.STORAGE_UNSAFE
    assert catalog.lookups == 0
    await runtime.close()

    foreign_writer = _id(IdKind.WRITER, 99)
    runtime = await open_local_bundle_runtime(
        _context(
            frozenset(
                {
                    RuntimeCapability.STRUCTURAL_READ,
                    RuntimeCapability.PAYLOAD_READ,
                    RuntimeCapability.WRITE,
                }
            )
        ),
        catalog,
        vault,
        harness.factories(),
        _Diagnostics(),
        object(),
    )
    with pytest.raises(PublicOperationError) as conflict:
        await runtime.route(
            RouteCommand(
                route.session_id,
                foreign_writer,
                RouteAccess.WRITE,
                frozenset({RuntimeCapability.WRITE}),
            )
        )
    assert conflict.value.code is PublicErrorCode.SESSION_CONFLICT
    assert harness.opens == 0


@pytest.mark.anyio
async def test_read_facade_has_no_mutators_and_close_poisons_handle() -> None:
    route, writer = _route()
    catalog = _Catalog(route)
    vault = _Vault()
    harness = _Harness(1, route, writer)
    runtime = await open_local_bundle_runtime(
        _context(frozenset({RuntimeCapability.STRUCTURAL_READ})),
        catalog,
        vault,
        harness.factories(),
        _Diagnostics(),
        object(),
        RuntimeCachePolicy(max_idle_tasks=1, max_opening_tasks=1),
    )
    task_runtime = await runtime.route(
        RouteCommand(
            route.session_id,
            None,
            RouteAccess.STRUCTURAL_READ,
            frozenset({RuntimeCapability.STRUCTURAL_READ}),
        )
    )
    assert not hasattr(task_runtime.ledger, "append_batch")
    assert not hasattr(task_runtime.objects, "stage")
    assert not hasattr(task_runtime.importer, "capture")
    assert vault.loads == 0
    await runtime.close()
    assert harness.closes == 1
    with pytest.raises(PublicOperationError) as closed:
        await runtime.route(
            RouteCommand(
                route.session_id,
                None,
                RouteAccess.STRUCTURAL_READ,
                frozenset({RuntimeCapability.STRUCTURAL_READ}),
            )
        )
    assert closed.value.code is PublicErrorCode.SERVICE_UNAVAILABLE


@pytest.mark.anyio
async def test_runtime_scope_ceiling_keeps_three_task_openings_isolated() -> None:
    """A repository scope rejects only its third task with a typed capacity result."""

    repo = "hmac-sha256:" + "e" * 64
    routes: list[TaskRoute] = []
    for offset in range(3):
        task = _id(IdKind.TASK, 100 + offset)
        session = _id(IdKind.SESSION, 200 + offset)
        generation = 1
        routes.append(
            TaskRoute(
                task,
                session,
                f"tasks/{task}",
                generation,
                TaskRouteState.ACTIVE,
                canonical_digest(
                    {
                        "task_id": task,
                        "bundle_relpath": f"tasks/{task}",
                        "route_generation": generation,
                    }
                ),
                repository_privacy_commitment=repo,
            )
        )

    class _MultiCatalog:
        generation = 3

        async def resolve_route(self, session_id: str) -> TaskRoute | None:
            return next((route for route in routes if route.session_id == session_id), None)

        async def session_binding(self, session_id: str) -> SessionBinding | None:
            del session_id
            return None

    first_route, writer = _route()
    harness = _Harness(1, first_route, writer)
    runtime = await open_local_bundle_runtime(
        _context(frozenset(RuntimeCapability)),
        _MultiCatalog(),
        _Vault(),
        harness.factories(),
        _Diagnostics(),
        object(),
        RuntimeCachePolicy(
            max_idle_tasks=3,
            max_opening_tasks=3,
            max_open_bundle_tasks=3,
            max_writer_connections=3,
            max_live_tasks_per_repository=2,
            max_opening_tasks_per_repository=2,
        ),
    )
    held: list[TaskRuntime] = []
    for route in routes[:2]:
        held.append(
            await runtime.route(
                RouteCommand(
                    route.session_id,
                    writer,
                    RouteAccess.WRITE,
                    frozenset({RuntimeCapability.WRITE}),
                )
            )
        )
    with pytest.raises(PublicOperationError) as busy:
        await runtime.route(
            RouteCommand(
                routes[2].session_id,
                writer,
                RouteAccess.WRITE,
                frozenset({RuntimeCapability.WRITE}),
            )
        )
    assert busy.value.code is PublicErrorCode.BUNDLE_BUSY
    assert busy.value.retryable is True
    assert busy.value.safe_details == {
        "reason_code": "ownership_contended",
        "count": 2,
        "limit": 2,
    }
    await runtime.release(held[0])
    await runtime.release(held[1])
    await runtime.close()


@pytest.mark.anyio
async def test_runtime_writer_connection_ceiling_is_explicit_and_actionable() -> None:
    """Writer-capacity refusal is independent from the open-bundle cache bound."""

    routes: list[TaskRoute] = []
    for offset in range(3):
        task = _id(IdKind.TASK, 300 + offset)
        session = _id(IdKind.SESSION, 400 + offset)
        routes.append(
            TaskRoute(
                task,
                session,
                f"tasks/{task}",
                1,
                TaskRouteState.ACTIVE,
                canonical_digest(
                    {
                        "task_id": task,
                        "bundle_relpath": f"tasks/{task}",
                        "route_generation": 1,
                    }
                ),
            )
        )

    class _MultiCatalog:
        generation = 3

        async def resolve_route(self, session_id: str) -> TaskRoute | None:
            return next((route for route in routes if route.session_id == session_id), None)

        async def session_binding(self, session_id: str) -> SessionBinding | None:
            del session_id
            return None

    _first_route, writer = _route()
    harness = _Harness(1, _first_route, writer)
    runtime = await open_local_bundle_runtime(
        _context(frozenset(RuntimeCapability)),
        _MultiCatalog(),
        _Vault(),
        harness.factories(),
        _Diagnostics(),
        object(),
        RuntimeCachePolicy(
            max_idle_tasks=3,
            max_opening_tasks=3,
            max_open_bundle_tasks=3,
            max_writer_connections=2,
        ),
    )
    held = [
        await runtime.route(
            RouteCommand(
                route.session_id,
                writer,
                RouteAccess.WRITE,
                frozenset({RuntimeCapability.WRITE}),
            )
        )
        for route in routes[:2]
    ]
    with pytest.raises(PublicOperationError) as busy:
        await runtime.route(
            RouteCommand(
                routes[2].session_id,
                writer,
                RouteAccess.WRITE,
                frozenset({RuntimeCapability.WRITE}),
            )
        )
    assert busy.value.safe_details == {
        "reason_code": "ownership_contended",
        "count": 2,
        "limit": 2,
    }
    for task_runtime in held:
        await runtime.release(task_runtime)
    await runtime.close()


def test_context_is_constant_redacted_and_not_serializable() -> None:
    context = _context(frozenset({RuntimeCapability.STRUCTURAL_READ}))
    assert repr(context) == "ServiceRuntimeContext(<redacted>)"
    with pytest.raises(TypeError, match="not_serializable"):
        context.__reduce__()
    assert "path" not in context.version_manifest
    assert hashlib.sha256(repr(context).encode()).digest()


@pytest.mark.anyio
async def test_session_monitor_normalizes_duplicates_and_never_unlocks_itself() -> None:
    sink: Callable[[SessionSecurityEvent], Awaitable[None]] | None = None
    unsubscribed = 0

    async def subscribe(
        value: Callable[[SessionSecurityEvent], Awaitable[None]],
    ) -> Callable[[], Awaitable[None]]:
        nonlocal sink
        sink = value
        await value(SessionSecurityEvent.USER_SESSION_LOCKED)

        async def unsubscribe() -> None:
            nonlocal unsubscribed
            unsubscribed += 1

        return unsubscribe

    events: list[SessionSecurityEvent] = []

    async def lifecycle(event: SessionSecurityEvent) -> None:
        events.append(event)

    monitor = SessionEventMonitor(LinuxLogin1Backend(subscribe))
    await monitor.start(lifecycle)
    assert monitor.capability.active
    assert callable(sink)
    emit = sink
    await emit(SessionSecurityEvent.USER_SESSION_LOCKED)
    await emit(SessionSecurityEvent.USER_SESSION_UNLOCKED)
    await emit(SessionSecurityEvent.SYSTEM_SUSPEND)
    await emit(SessionSecurityEvent.SYSTEM_RESUME)
    assert events == [
        SessionSecurityEvent.USER_SESSION_LOCKED,
        SessionSecurityEvent.USER_SESSION_UNLOCKED,
        SessionSecurityEvent.SYSTEM_SUSPEND,
        SessionSecurityEvent.SYSTEM_RESUME,
    ]
    await emit(SessionSecurityEvent.MONITOR_LOST)
    assert events[-1] is SessionSecurityEvent.MONITOR_LOST
    assert not monitor.capability.active
    await monitor.close()
    assert unsubscribed == 1
