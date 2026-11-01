"""Cursor's workspace preflight and binding retirement under one call deadline (review of #1226).

Round 3 of the PR #1227 review: a discovery running outside the slot lock could publish a client
for a Cursor binding retired meanwhile and send the pending RPC on it, and the whole-call budget
started after Cursor's roots exchange and binding-lock wait. Events drive the interleavings; a
fake clock stands in for elapsed time where a stage would otherwise take seconds.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from mcp import types

import finishup.mcp.server as server
from unit.mcp.test_call_deadline_budget import (
    _COMPLETE_PAGE,
    _Client,
    _Clock,
    _RecoveringClient,
    _respond_body,
)
from unit.mcp.test_cursor_workspace_binding import (
    _LAUNCHER,
    _directory,
    _raw_roots,
    _write_project_registration,
)

_REQUEST = "req_80d0cc7a-150f-4d7b-9aa3-a50312db0078"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _status_body() -> dict[str, object]:
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": _REQUEST,
        "actor": {"actor_id": "harness:mcp", "actor_type": "harness"},
        "client": {
            "kind": "cooperative_agent",
            "version": "0.1.0",
            "integration": "cooperative_mcp",
        },
        "session_id": "ses_00000000-0000-4000-8000-000000000001",
        "writer_id": "wri_00000000-0000-4000-8000-000000000001",
        "view": "compact",
    }


def _call(name: str, arguments: dict[str, object]) -> types.CallToolRequest:
    return types.CallToolRequest(params=types.CallToolRequestParams(name=name, arguments=arguments))


class _Roots:
    """Cursor's roots/list answer; each exchange may cost fake time."""

    def __init__(self, project: Path, clock: _Clock | None = None, cost_ms: int = 0) -> None:
        self.project = project
        self.clock = clock
        self.cost_ms = cost_ms

    async def send_request(self, _request: object, _result_type: object) -> object:
        if self.clock is not None:
            self.clock.advance_ms(self.cost_ms)
        return _raw_roots(self.project)

    async def list_roots(self) -> types.ListRootsResult:
        raise AssertionError("the raw Cursor request path should be used")


class _RecordingClient:
    def __init__(self) -> None:
        self.rpcs: list[str] = []
        self.closed = False

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        self.closed = True

    def __getattr__(self, method: str) -> Any:
        async def call(*_args: object, **_kwargs: object) -> Any:
            self.rpcs.append(method)
            raise AssertionError("no RPC may be sent for a retired binding")

        return call


def _cursor_runtime(tmp_path: Path) -> tuple[server.BridgeRuntime, Path]:
    project = _directory(tmp_path / "project")
    _write_project_registration(project)
    runtime = server.build_bridge_runtime(
        host_profile="cursor", project_root=project, launcher=_LAUNCHER
    )
    return runtime, project


def _error(response: types.ServerResult) -> dict[str, Any]:
    result = response.root
    assert isinstance(result, types.CallToolResult) and result.isError is True
    return cast(dict[str, Any], cast(dict[str, Any], result.structuredContent)["error"])


@pytest.mark.anyio
async def test_a_binding_retired_during_discovery_never_gets_a_client_or_an_rpc(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime, project = _cursor_runtime(tmp_path)
    entered, release = asyncio.Event(), asyncio.Event()
    discovered = _RecordingClient()

    async def parked(
        _kind: object, *, workspace_locator: object = None, timeout_seconds: float = 30.0
    ) -> object:
        del workspace_locator, timeout_seconds
        entered.set()
        await release.wait()
        return discovered

    monkeypatch.setattr(server, "connect_service_on_demand", parked)
    call = asyncio.create_task(
        server._handle_call_tool_request(
            _call("status", _status_body()), runtime, session=_Roots(project)
        )
    )
    await entered.wait()
    # The host reports changed roots while discovery is parked outside the slot lock.
    await server._invalidate_cursor_workspace_binding(runtime)
    release.set()
    response = await call

    error = _error(response)
    assert error["safe_details"].get("reason_code") != "request_timeout"
    assert discovered.rpcs == [] and discovered.closed is True
    slot = runtime._slot
    assert slot.client is None and slot.workspace_binding_state == "failed"
    assert slot.attempting is False and slot.attempt_owner is None


@pytest.mark.anyio
async def test_slow_roots_and_a_slow_rpc_end_by_the_status_ceiling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime, project = _cursor_runtime(tmp_path)
    clock = _Clock()
    client = _Client(clock)

    async def on_demand(
        _kind: object, *, workspace_locator: object = None, timeout_seconds: float = 30.0
    ) -> object:
        del workspace_locator, timeout_seconds
        return client

    monkeypatch.setattr(server, "time", SimpleNamespace(monotonic=clock.monotonic))
    monkeypatch.setattr(server, "connect_service_on_demand", on_demand)
    monkeypatch.setenv("FINISHUP_MCP_DEADLINE_MS_STATUS", "999999")
    started = clock.now

    response = await server._handle_call_tool_request(
        _call("status", _status_body()),
        runtime,
        session=_Roots(project, clock, cost_ms=4_000),
    )

    ceiling = server._HOST_CEILING_MS["status"] - server._HOST_CEILING_MARGIN_MS
    # The 4 s roots exchange came out of the same budget: the read got 53 s, not a fresh 57 s.
    assert client.deadlines == [ceiling - 4_000]
    assert (clock.now - started) * 1_000 <= ceiling + 100
    error = _error(response)
    assert error["safe_details"]["reason_code"] == "request_timeout"
    await server.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_a_contended_binding_lock_answers_with_the_typed_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime, project = _cursor_runtime(tmp_path)
    session = _Roots(project)
    assert await server._ensure_cursor_workspace_binding(runtime, session, None, "status") is None

    def short_budget(_tool: str) -> int:
        return 150

    monkeypatch.setattr(server, "_call_budget_ms", short_budget)
    slot = runtime._slot

    await slot.workspace_binding_lock.acquire()
    try:
        started = time.monotonic()
        response = await server._handle_call_tool_request(
            _call("status", _status_body()), runtime, session=session
        )
        waited = time.monotonic() - started
    finally:
        slot.workspace_binding_lock.release()

    error = _error(response)
    assert error["safe_details"]["reason_code"] == "request_timeout"
    assert waited < 1.0
    # Running out of budget is not a binding failure.
    assert slot.workspace_binding_state == "bound"


@pytest.mark.anyio
@pytest.mark.parametrize("override", [None, "999999"], ids=("default", "max_override"))
async def test_cursor_write_recovery_after_slow_roots_stays_under_the_ceiling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, override: str | None
) -> None:
    runtime, project = _cursor_runtime(tmp_path)
    clock = _Clock()
    client = _RecoveringClient(clock)

    async def on_demand(
        _kind: object, *, workspace_locator: object = None, timeout_seconds: float = 30.0
    ) -> object:
        del workspace_locator, timeout_seconds
        return client

    original = server.public_model_to_wire

    def to_wire(model: object) -> dict[str, Any]:
        if model is _COMPLETE_PAGE:
            return {"ok": True, "page": {"state": "complete"}}
        return original(model)

    monkeypatch.setattr(server, "time", SimpleNamespace(monotonic=clock.monotonic))
    monkeypatch.setattr(server, "connect_service_on_demand", on_demand)
    monkeypatch.setattr(server, "public_model_to_wire", to_wire)
    for prefix in ("FINISHUP_", "YOETZ_"):
        monkeypatch.delenv(f"{prefix}MCP_DEADLINE_MS_RESPOND", raising=False)
    if override is not None:
        monkeypatch.setenv("FINISHUP_MCP_DEADLINE_MS_RESPOND", override)
    started = clock.now

    response = await server._handle_call_tool_request(
        _call("respond", _respond_body()),
        runtime,
        session=_Roots(project, clock, cost_ms=4_000),
    )

    ceiling = server._HOST_CEILING_MS["respond"]
    elapsed_ms = (clock.now - started) * 1_000
    assert elapsed_ms <= ceiling - server._HOST_CEILING_MARGIN_MS + 100 < ceiling
    assert _error(response)["safe_details"]["replay_request_id"] == _REQUEST
    await server.close_bridge_runtime(runtime)
