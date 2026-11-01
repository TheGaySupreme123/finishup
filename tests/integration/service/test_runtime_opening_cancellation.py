"""Production runtime opening joins cancelled writer work before teardown."""

from __future__ import annotations

import asyncio
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest

import finishup.adapters.sqlite.connection as connection_module
import finishup.adapters.sqlite.recovery as recovery_module
import finishup.service.ready_composition as ready_composition_module
from finishup.adapters.runtime import open_local_bundle_runtime
from finishup.ports.diagnostics import RuntimeCapability, StartupCheckResult
from finishup.ports.keys import BundleKeys
from finishup.ports.runtime import OwnershipFence, RouteAccess, RouteCommand, ServiceRuntimeContext
from finishup.ports.start_catalog import TaskRoute, TaskRouteState
from finishup.protocol.canonical import canonical_digest
from finishup.protocol.ids import IdKind, new_id
from finishup.service.ready_composition import IdPort

_SERVICE_INSTANCE_ID = "svc_00000000-0000-4000-8000-000000000001"


class _Paths:
    def __init__(self, bundle: Path) -> None:
        self._bundle = bundle

    @property
    def bundle(self) -> Path:
        return self._bundle

    @property
    def state(self) -> Path:
        return self._bundle / "state"


class _Clock:
    def now_utc(self) -> datetime:
        return datetime(2026, 9, 6, tzinfo=UTC)

    def monotonic_seconds(self) -> float:
        return 1.0


class _Catalog:
    generation = 1

    def __init__(self, route: TaskRoute) -> None:
        self._route = route

    async def resolve_route(self, session_id: str) -> TaskRoute | None:
        return self._route if session_id == self._route.session_id else None

    async def session_binding(self, session_id: str) -> None:
        del session_id
        return None


class _Vault:
    generation = 1
    ready = True

    async def load_bundle_keys(self, bundle_id: str) -> BundleKeys:
        del bundle_id
        return cast(BundleKeys, object())

    async def create_bundle_keys(self, bundle_id: str) -> BundleKeys:
        del bundle_id
        raise AssertionError("route_open_must_not_create_keys")


class _Diagnostics:
    def record(self, result: StartupCheckResult) -> None:
        del result


class _Connection:
    def __init__(self, label: str) -> None:
        self.label = label
        self.closed = threading.Event()

    def close(self, *, force: bool = False) -> None:
        assert force
        self.closed.set()


class _Writer:
    def __init__(self, closed: threading.Event) -> None:
        self._closed = closed

    def close(self) -> None:
        self._closed.set()

    @property
    def closed(self) -> bool:
        return self._closed.is_set()


class _Objects:
    def __init__(self, **kwargs: object) -> None:
        del kwargs


class _Ledger:
    def __init__(self, **kwargs: object) -> None:
        del kwargs


class _Importer:
    def __init__(self, **kwargs: object) -> None:
        del kwargs


class _Plans:
    def __init__(self, **kwargs: object) -> None:
        del kwargs

    def prepare(self, *args: object, **kwargs: object) -> object:
        del args, kwargs
        return object()

    def read(self, *args: object, **kwargs: object) -> object:
        del args, kwargs
        return object()


class _Backend:
    def verify_fence(self, state: object, fence: OwnershipFence) -> None:
        del state, fence


async def _wait_thread_event(event: threading.Event) -> None:
    assert await asyncio.to_thread(event.wait, 5.0)


def _route() -> tuple[TaskRoute, str]:
    task_id = new_id(IdKind.TASK)
    session_id = new_id(IdKind.SESSION)
    writer_id = new_id(IdKind.WRITER)
    bundle_relpath = f"tasks/{task_id}"
    route = TaskRoute(
        task_id=task_id,
        session_id=session_id,
        bundle_relpath=bundle_relpath,
        route_generation=1,
        state=TaskRouteState.ACTIVE,
        route_identity_digest=canonical_digest(
            {"task_id": task_id, "bundle_relpath": bundle_relpath, "route_generation": 1}
        ),
    )
    return route, writer_id


@pytest.mark.anyio
@pytest.mark.parametrize("blocked_stage", ("open_writer", "writer_thread"))
async def test_cancelled_production_opening_is_joined_and_all_resources_close(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    blocked_stage: str,
) -> None:
    """A cancelled route cannot leave a production factory resource behind after close."""

    route, writer_id = _route()
    opening_started = threading.Event()
    opening_release = threading.Event()
    resources: dict[str, _Connection | _Writer] = {}

    inspection = ready_composition_module._BundleInspection(  # pyright: ignore[reportPrivateUsage]
        route,
        tmp_path / "tasks" / route.task_id,
        tmp_path / "tasks" / route.task_id / "ledger.sqlite3",
        tmp_path / "catalog.sqlite3",
        frozenset({writer_id}),
        False,
        object(),
        object(),
    )

    def inspect_common(**kwargs: object) -> object:
        del kwargs
        return inspection

    def admitted_writers(*args: object) -> frozenset[str]:
        del args
        return frozenset({writer_id})

    monkeypatch.setattr(ready_composition_module, "_inspect_common", inspect_common)
    monkeypatch.setattr(
        ready_composition_module,
        "_admitted_writers_for_session_from_path",
        admitted_writers,
    )

    def open_read_only(_path: Path) -> _Connection:
        connection = _Connection("objects")
        resources["objects"] = connection
        return connection

    def open_writer(_path: Path) -> _Connection:
        if blocked_stage == "open_writer":
            opening_started.set()
            assert opening_release.wait(5.0)
        connection = _Connection("ledger")
        resources["ledger"] = connection
        return connection

    def writer_thread(_path: Path) -> _Writer:
        if blocked_stage == "writer_thread":
            opening_started.set()
            assert opening_release.wait(5.0)
        writer = _Writer(threading.Event())
        resources["writer"] = writer
        return writer

    def acquire_ownership(
        state: object,
        verdict: object,
        *,
        service_instance_id: str,
        service_generation: int,
        owner_nonce: str,
        now: datetime,
    ) -> OwnershipFence:
        del state, verdict, owner_nonce, now
        return OwnershipFence(service_instance_id, service_generation, 1, "nonce_value_123456")

    monkeypatch.setattr(ready_composition_module, "open_read_only", open_read_only)
    monkeypatch.setattr(ready_composition_module, "open_writer", open_writer)
    monkeypatch.setattr(ready_composition_module, "SqliteWriterThread", writer_thread)
    monkeypatch.setattr(ready_composition_module, "EncryptedFilesObjectStore", _Objects)
    monkeypatch.setattr(ready_composition_module, "SqliteLedger", _Ledger)
    monkeypatch.setattr(ready_composition_module, "SqliteImporter", _Importer)
    monkeypatch.setattr(ready_composition_module, "CodexImportPlans", _Plans)
    monkeypatch.setattr(recovery_module, "acquire_bundle_ownership", acquire_ownership)
    monkeypatch.setattr(recovery_module, "_backend", lambda: _Backend())

    def clear_active_fence(*args: object) -> None:
        del args

    monkeypatch.setattr(connection_module, "_clear_active_fence", clear_active_fence)

    factories = ready_composition_module.build_runtime_adapter_factories(
        paths=_Paths(tmp_path),
        service_instance_id=_SERVICE_INSTANCE_ID,
        service_generation=1,
        clock=_Clock(),
        ids=IdPort(),
        secret_memory=object(),
    )
    context = ServiceRuntimeContext(
        service_instance_id=_SERVICE_INSTANCE_ID,
        service_generation=1,
        vault_generation=1,
        catalog_generation=1,
        capabilities=frozenset(
            {
                RuntimeCapability.STRUCTURAL_READ,
                RuntimeCapability.PAYLOAD_READ,
                RuntimeCapability.WRITE,
            }
        ),
        version_manifest={
            "bundle_schema_version": "10",
            "engine_version": "0.1.0",
            "projection_version": "1",
            "protocol_version": "0.1",
        },
        shutdown_token=object(),
    )
    runtime = await open_local_bundle_runtime(
        context,
        _Catalog(route),
        _Vault(),
        factories,
        _Diagnostics(),
        object(),
    )
    command = RouteCommand(
        session_id=route.session_id,
        writer_id=writer_id,
        access=RouteAccess.WRITE,
        required_capabilities=frozenset({RuntimeCapability.WRITE}),
    )

    route_task = asyncio.create_task(runtime.route(command))
    await _wait_thread_event(opening_started)
    route_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await route_task

    opening_task = cast(
        asyncio.Task[object],
        runtime._opening[route.task_id],  # pyright: ignore[reportPrivateUsage]
    )
    opening_release.set()
    # The route cancellation releases only its waiter.  The production opening remains owned by
    # the runtime and must finish before teardown can close the resources it created.
    await opening_task
    await runtime.close()
    assert opening_task.done()

    assert cast(_Connection, resources["objects"]).closed.is_set()
    assert cast(_Connection, resources["ledger"]).closed.is_set()
    assert cast(_Writer, resources["writer"]).closed
