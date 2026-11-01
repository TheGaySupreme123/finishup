"""Concurrent logical clients share one service-owned task writer runtime."""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass
from typing import cast

import pytest

from finishup.adapters.runtime import RuntimeAdapterFactories, open_local_bundle_runtime
from finishup.ports.diagnostics import RuntimeCapability, StartupCheckResult
from finishup.ports.importer import ImporterPort
from finishup.ports.keys import BundleKeys
from finishup.ports.ledger import LedgerPort
from finishup.ports.objects import ObjectStorePort
from finishup.ports.runtime import (
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
from finishup.protocol.ids import PREFIX_BY_KIND, IdKind


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
    generation = 1

    def __init__(self, route: TaskRoute) -> None:
        self.route = route

    async def resolve_route(self, session_id: str) -> TaskRoute | None:
        await asyncio.sleep(0)
        return self.route if session_id == self.route.session_id else None

    async def session_binding(self, session_id: str) -> SessionBinding | None:
        del session_id
        return None


class _Vault:
    generation = 1
    ready = True

    def __init__(self) -> None:
        self.loads = 0

    async def load_bundle_keys(self, bundle_id: str) -> BundleKeys:
        del bundle_id
        self.loads += 1
        return cast(BundleKeys, object())

    async def create_bundle_keys(self, bundle_id: str) -> BundleKeys:
        del bundle_id
        raise AssertionError("not_a_provisioning_test")


class _Diagnostics:
    def record(self, result: StartupCheckResult) -> None:
        del result


class _SharedWriter:
    pass


@pytest.mark.anyio
async def test_concurrent_clients_coalesce_on_one_writer_and_key_context() -> None:
    task = _id(IdKind.TASK, 1)
    session = _id(IdKind.SESSION, 2)
    writer = _id(IdKind.WRITER, 3)
    route = TaskRoute(
        task,
        session,
        f"tasks/{task}",
        1,
        TaskRouteState.ACTIVE,
        canonical_digest(
            {"task_id": task, "bundle_relpath": f"tasks/{task}", "route_generation": 1}
        ),
    )
    catalog = _Catalog(route)
    vault = _Vault()
    service_generation = 1
    opens = 0
    closes = 0
    open_started = asyncio.Event()
    continue_open = asyncio.Event()
    shared_objects = cast(ObjectStorePort, _SharedWriter())
    shared_ledger = cast(LedgerPort, _SharedWriter())
    shared_importer = cast(ImporterPort, _SharedWriter())

    async def inspect(value: TaskRoute, access: RouteAccess) -> _Inspection:
        del access
        return _Inspection(value, frozenset({writer}))

    async def inspect_provision(command: object) -> _Inspection:
        del command
        return _Inspection(route, frozenset({writer}), True)

    async def acquire(value: object, writable: bool) -> OwnershipFence:
        nonlocal opens
        del value
        assert writable
        opens += 1
        open_started.set()
        await continue_open.wait()
        return OwnershipFence(_id(IdKind.SERVICE_INSTANCE, 4), 1, 1, "writer_nonce_123456")

    async def validate(value: object, fence: OwnershipFence) -> None:
        del value
        assert fence.owner_generation == 1

    async def objects(*args: object) -> ObjectStorePort:
        del args
        return shared_objects

    async def ledger(*args: object) -> LedgerPort:
        del args
        return shared_ledger

    async def importer(*args: object) -> ImporterPort:
        del args
        return shared_importer

    async def verify(
        value: object,
        runtime_value: TaskRuntime,
        expectation: StartMilestoneExpectation,
    ) -> StartCompletionEvidence:
        del value, runtime_value, expectation
        raise AssertionError("not_used")

    async def close(*args: object) -> None:
        nonlocal closes
        del args
        closes += 1

    factories = RuntimeAdapterFactories(
        current_service_generation=lambda: service_generation,
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
    context = ServiceRuntimeContext(
        _id(IdKind.SERVICE_INSTANCE, 4),
        1,
        1,
        1,
        frozenset(
            {
                RuntimeCapability.STRUCTURAL_READ,
                RuntimeCapability.PAYLOAD_READ,
                RuntimeCapability.WRITE,
            }
        ),
        {
            "bundle_schema_version": "2",
            "engine_version": "0.1.0",
            "projection_version": "1",
            "protocol_version": "0.1",
        },
        object(),
    )
    runtime = await open_local_bundle_runtime(
        context, catalog, vault, factories, _Diagnostics(), object()
    )
    command = RouteCommand(
        session,
        writer,
        RouteAccess.WRITE,
        frozenset({RuntimeCapability.WRITE}),
    )
    cancelled_client = asyncio.create_task(runtime.route(command))
    await open_started.wait()
    cancelled_client.cancel()
    with pytest.raises(asyncio.CancelledError):
        await cancelled_client
    pending_clients = [asyncio.create_task(runtime.route(command)) for _ in range(32)]
    continue_open.set()
    clients = await asyncio.gather(*pending_clients)
    assert opens == 1
    assert vault.loads == 1
    assert all(client.ledger is shared_ledger for client in clients)
    assert all(client.fence == clients[0].fence for client in clients)
    assert len({id(client) for client in clients}) == 32

    await asyncio.gather(*(runtime.release(client) for client in clients))
    assert closes == 0
    await runtime.close()
    assert closes == 1
