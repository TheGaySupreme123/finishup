"""Real reserved start, runtime/catalog contention, and MCP recovery delivery (#744).

These isolated production-composition fixtures are not native host acceptance evidence.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from typing import cast
from unittest.mock import patch

import apsw
import pytest

import finishup.mcp.server as bridge
from finishup.adapters.runtime import LocalBundleRuntime
from finishup.adapters.sqlite.start_catalog import SqliteStartCatalog
from finishup.application.service import Application
from finishup.cli import elevated
from finishup.ports.diagnostics import RuntimeCapability
from finishup.ports.runtime import RouteAccess, RouteCommand
from finishup.ports.start_catalog import EncryptedResultRef, StartAllocation, StartPhase
from finishup.protocol.canonical import JsonValue
from finishup.service.elevated_bootstrap import load_pending
from integration.service.test_consent_vault_initialize_composition import (
    _approve_attestation,  # pyright: ignore[reportPrivateUsage]
    _approved_store,  # pyright: ignore[reportPrivateUsage]
    _MemoryKeyring,  # pyright: ignore[reportPrivateUsage]
    _production_daemon,  # pyright: ignore[reportPrivateUsage]
    runtime_directory,  # noqa: F401  # pyright: ignore[reportUnusedImport]
)

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
async def ready(
    tmp_path: Path,
    runtime_directory: Path,  # noqa: F811
) -> AsyncIterator[tuple[Application, bridge.BridgeRuntime]]:
    tmp_path.chmod(0o700)
    consent = tmp_path / "consent"
    consent.mkdir(mode=0o700)
    store = _approved_store(tmp_path / "data", _MemoryKeyring())
    daemon = await _production_daemon(tmp_path, pristine=True)
    await daemon.start()
    serving = asyncio.create_task(daemon.serve())
    runtime = bridge.build_bridge_runtime()
    try:
        with (
            patch("finishup.service.elevated_bootstrap.state_dir", return_value=consent),
            patch("finishup.cli.elevated._auto_unlock_store", return_value=store),
        ):
            elevated.prepare_elevated("vault_initialize")
            pending = load_pending(_state=consent)
            assert pending is not None
            await elevated.authorize_elevated(_approve_attestation(pending))
        application = daemon._application  # pyright: ignore[reportPrivateUsage]
        assert isinstance(application, Application)
        yield application, runtime
    finally:
        await bridge.close_bridge_runtime(runtime)
        await daemon.stop()
        await asyncio.wait_for(serving, 10)


def _body(seed: int, session_id: str | None = None) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": f"req_00000000-0000-4000-8000-{seed:012d}",
        "actor": {"actor_id": "harness:contention-744", "actor_type": "harness"},
        "client": {
            "kind": "cooperative_agent",
            "version": "0.1.0",
            "integration": "cooperative_mcp",
        },
        "mode": "create" if session_id is None else "attach",
        "task_title": "Synthetic start contention",
        "requested_view": "compact",
    }
    if session_id is not None:
        result["session_id"] = session_id
    return result


def _structured(result: object) -> dict[str, object]:
    return cast(dict[str, object], getattr(result, "structuredContent"))


def _text(result: object) -> str:
    return " ".join(str(getattr(item, "text", "")) for item in getattr(result, "content"))


def _logical_result(result: dict[str, object]) -> dict[str, object]:
    # Start result replay reprojects disclosure, which creates its own privacy receipt.
    return {key: value for key, value in result.items() if key != "privacy_projection"}


async def test_reserved_attach_drains_runtime_usage_and_replays_one_mcp_outcome(
    ready: tuple[Application, bridge.BridgeRuntime], monkeypatch: pytest.MonkeyPatch
) -> None:
    app, transport = ready
    created = _structured(await bridge.dispatch_start(_body(7440), transport))
    runtime = app.runtime
    assert isinstance(runtime, LocalBundleRuntime)
    command = RouteCommand(
        cast(str, created["session_id"]),
        cast(str, created["writer_id"]),
        RouteAccess.WRITE,
        frozenset({RuntimeCapability.WRITE}),
    )
    held = await runtime.route(command)
    monkeypatch.setattr(
        runtime,
        "_policy",
        replace(runtime._policy, max_idle_tasks=1),  # pyright: ignore[reportPrivateUsage]
    )
    assert _structured(await bridge.dispatch_start(_body(7449), transport))["ok"] is True
    entered = asyncio.Event()
    condition = runtime._idle  # pyright: ignore[reportPrivateUsage]
    original = condition.wait_for

    async def observed_wait(predicate: Callable[[], bool]) -> bool:
        entered.set()
        return await original(predicate)

    monkeypatch.setattr(condition, "wait_for", observed_wait)
    request = _body(7441, held.session_id)
    attempt = asyncio.create_task(bridge.dispatch_start(request, transport))
    try:
        await asyncio.wait_for(entered.wait(), 5)
        catalog = cast(SqliteStartCatalog, app.start_catalog)
        row = catalog._db.execute(  # pyright: ignore[reportPrivateUsage]
            "SELECT phase, state FROM start_operations WHERE operation_id = ?",
            (cast(str, request["request_id"]),),
        ).fetchone()
        assert row == ("route_reserved", "pending")
        assert not attempt.done()
        await runtime.release(held)
        result = await asyncio.wait_for(attempt, 5)
        wire = _structured(result)
        assert wire["ok"] is True and wire["task_id"] == created["task_id"]
        assert wire["session_id"] != created["session_id"]
        assert runtime._entries[held.task_id].fence == held.fence  # pyright: ignore[reportPrivateUsage]
        assert cast(str, wire["session_id"]) in _text(result)
        assert _logical_result(
            _structured(await bridge.dispatch_start(request, transport))
        ) == _logical_result(wire)
        assert cast(dict[str, str], wire["frontier"])["sequence"] == "2"
        changed = dict(request, task_title="Changed identity")
        conflict = _structured(await bridge.dispatch_start(changed, transport))
        assert cast(dict[str, object], conflict["error"])["code"] == "IDEMPOTENCY_CONFLICT"
    finally:
        await runtime.release(held)
        if not attempt.done():
            attempt.cancel()
        await asyncio.gather(attempt, return_exceptions=True)


async def test_runtime_wait_bound_yields_reserved_start_and_mcp_exact_replay_completes(
    ready: tuple[Application, bridge.BridgeRuntime], monkeypatch: pytest.MonkeyPatch
) -> None:
    app, transport = ready
    created = _structured(await bridge.dispatch_start(_body(7442), transport))
    held = await app.runtime.route(
        RouteCommand(
            cast(str, created["session_id"]),
            cast(str, created["writer_id"]),
            RouteAccess.WRITE,
            frozenset({RuntimeCapability.WRITE}),
        )
    )
    # Expire the wait budget deterministically; success is established after explicit release.
    monkeypatch.setattr("finishup.adapters.runtime._START_REBIND_WAIT_SECONDS", 0.0)
    request = _body(7443, held.session_id)
    try:
        result = await bridge.dispatch_start(request, transport)
        error = cast(dict[str, object], _structured(result)["error"])
        assert error["code"] == "BUNDLE_BUSY" and error["retryable"] is True
        assert error["safe_details"] == {
            "reason_code": "start_runtime_rebind_retry_ready",
            "continuation": "start_busy_same_identity",
        }
        assert "start_runtime_rebind_retry_ready" in _text(result)
    finally:
        await app.runtime.release(held)
    recovered = _structured(await bridge.dispatch_start(request, transport))
    assert recovered["ok"] is True and recovered["task_id"] == created["task_id"]
    assert cast(dict[str, str], recovered["frontier"])["sequence"] == "2"


async def test_real_catalog_busy_after_reservation_yields_and_recovers_through_mcp(
    ready: tuple[Application, bridge.BridgeRuntime], monkeypatch: pytest.MonkeyPatch
) -> None:
    app, transport = ready
    catalog = app.start_catalog
    assert isinstance(catalog, SqliteStartCatalog)
    db = catalog._db  # pyright: ignore[reportPrivateUsage]
    blocker = apsw.Connection(db.filename)
    advance = catalog.advance_phase
    attempted = False

    async def contended_advance(
        allocation: StartAllocation, phase: StartPhase, result: EncryptedResultRef | None = None
    ) -> StartAllocation:
        nonlocal attempted
        if attempted:
            return await advance(allocation, phase, result)
        attempted = True
        assert allocation.phase is StartPhase.ROUTE_RESERVED
        blocker.execute("BEGIN IMMEDIATE")
        try:
            return await advance(allocation, phase, result)
        finally:
            blocker.execute("ROLLBACK")

    monkeypatch.setattr(catalog, "advance_phase", contended_advance)
    request = _body(7444)
    try:
        result = await bridge.dispatch_start(request, transport)
        error = cast(dict[str, object], _structured(result)["error"])
        assert error["code"] == "BUNDLE_BUSY"
        assert error["safe_details"] == {
            "reason_code": "start_catalog_retry_ready",
            "continuation": "start_busy_same_identity",
        }
        assert "start_catalog_retry_ready" in _text(result)
        recovered = _structured(await bridge.dispatch_start(request, transport))
        assert recovered["ok"] is True
        assert cast(dict[str, str], recovered["frontier"])["sequence"] == "1"
        assert _logical_result(
            _structured(await bridge.dispatch_start(request, transport))
        ) == _logical_result(recovered)
    finally:
        blocker.close()


async def test_catalog_lock_preserves_pending_when_lease_yield_cannot_commit(
    ready: tuple[Application, bridge.BridgeRuntime], monkeypatch: pytest.MonkeyPatch
) -> None:
    app, transport = ready
    catalog = app.start_catalog
    assert isinstance(catalog, SqliteStartCatalog)
    db = catalog._db  # pyright: ignore[reportPrivateUsage]
    blocker = apsw.Connection(db.filename)
    advance = catalog.advance_phase

    async def blocked_advance(
        allocation: StartAllocation, phase: StartPhase, result: EncryptedResultRef | None = None
    ) -> StartAllocation:
        blocker.execute("BEGIN IMMEDIATE")
        return await advance(allocation, phase, result)

    monkeypatch.setattr(catalog, "advance_phase", blocked_advance)
    request = _body(7445)
    try:
        failed = await bridge.dispatch_start(request, transport)
        error = cast(dict[str, object], _structured(failed)["error"])
        assert error["code"] == "BUNDLE_BUSY"
        assert error["safe_details"] == {"reason_code": "catalog_busy"}
        blocker.execute("ROLLBACK")
        pending_result = await bridge.dispatch_start(request, transport)
        pending = cast(dict[str, object], _structured(pending_result)["error"])
        assert pending["code"] == "OPERATION_PENDING"
        assert pending["safe_details"] == {
            "reason_code": "start_lease_pending",
            "continuation": "start_pending_same_identity",
        }
        assert "start_lease_pending" in _text(pending_result)
        # Only a clock advance, never deletion or a fresh request, enables reclaim.
        clock = catalog._clock  # pyright: ignore[reportPrivateUsage]
        now = clock.now_utc() + timedelta(seconds=61)
        monkeypatch.setattr(clock, "now_utc", lambda: now)
        monkeypatch.setattr(catalog, "advance_phase", advance)
        recovered = _structured(await bridge.dispatch_start(request, transport))
        assert recovered["ok"] is True
        assert cast(dict[str, str], recovered["frontier"])["sequence"] == "1"
    finally:
        if not blocker.get_autocommit():
            blocker.execute("ROLLBACK")
        blocker.close()
