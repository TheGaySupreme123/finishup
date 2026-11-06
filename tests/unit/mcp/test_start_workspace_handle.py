"""The MCP bridge sends a claim-bound connection's handle in place of a start's workspace path."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import cast

import pytest

import finishup.mcp.server as bridge
from finishup.ports.control import ControlError
from finishup.protocol.canonical import JsonValue
from finishup.protocol.models import StartRequest, StartResult

_REQUEST = "req_00000000-0000-4000-8000-000000000051"
_HANDLE = "client:0123456789abcdef"
_PATH = "/srv/dev/private-project"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _start_body() -> dict[str, JsonValue]:
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
        "mode": "create",
        "task_title": "Remote task",
        "requested_view": "compact",
        "workspace_ref": _PATH,
        "external_ref": "host-session:1",
    }


class _Client:
    """Records the request it was sent, then answers with a non-retryable control error."""

    def __init__(self, binding: str, handle: str | None) -> None:
        self.workspace_binding = binding
        self.workspace_handle = handle
        self.sent: list[StartRequest] = []

    async def connect(self) -> None:
        return None

    async def start(self, request: StartRequest, *, deadline_ms: int | None = None) -> StartResult:
        del deadline_ms
        self.sent.append(request)
        raise ControlError("invalid_request")

    async def close(self) -> None:
        return None


def _wire(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, client: _Client) -> None:
    import finishup.observability.diagnostics as diagnostics

    monkeypatch.setattr(diagnostics, "log_dir", lambda: tmp_path)

    async def on_demand(_kind: object, **_kwargs: object) -> object:
        return client

    monkeypatch.setattr(
        bridge,
        "connect_service_on_demand",
        cast(Callable[[object], Awaitable[object]], on_demand),
    )


@pytest.mark.anyio
async def test_a_claim_bound_start_sends_the_handle(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    client = _Client("client_claim", _HANDLE)
    _wire(monkeypatch, tmp_path, client)
    await bridge.dispatch_start(_start_body(), bridge.build_bridge_runtime())
    (sent,) = client.sent
    assert sent.workspace_ref == _HANDLE
    assert sent.request_id == _REQUEST


@pytest.mark.anyio
async def test_a_local_start_is_sent_as_written(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    client = _Client("local_path", None)
    _wire(monkeypatch, tmp_path, client)
    await bridge.dispatch_start(_start_body(), bridge.build_bridge_runtime())
    (sent,) = client.sent
    assert sent.workspace_ref == _PATH


@pytest.mark.anyio
async def test_without_a_handle_nothing_is_sent_and_the_locked_server_is_named(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A claim the server could not key at hello (its vault was locked) is ``vault_locked``.

    Nothing is sent, the stale connection is discarded so a fresh hello binds the claim once the
    vault is unlocked, and the agent is never told to set a handle it cannot see.
    """

    import finishup.observability.diagnostics as diagnostics

    monkeypatch.setattr(diagnostics, "log_dir", lambda: tmp_path)
    clients: list[_Client] = []

    async def on_demand(_kind: object, **_kwargs: object) -> object:
        clients.append(_Client("client_claim", None))
        return clients[-1]

    monkeypatch.setattr(
        bridge,
        "connect_service_on_demand",
        cast(Callable[[object], Awaitable[object]], on_demand),
    )
    runtime = bridge.build_bridge_runtime()
    result = await bridge.dispatch_start(_start_body(), runtime)
    assert clients and all(client.sent == [] for client in clients)
    assert getattr(result, "isError") is True
    structured = cast(dict[str, object], getattr(result, "structuredContent"))
    error = cast(dict[str, object], structured["error"])
    assert error["code"] == "VAULT_LOCKED"
    assert "workspace_ref_not_portable" not in repr(result)
    assert "workspace_handle_required" not in repr(result)
    assert "private-project" not in repr(result)

    # Once the server is unlocked, the next start reconnects and its hello binds the claim.
    async def unlocked(_kind: object, **_kwargs: object) -> object:
        clients.append(_Client("client_claim", _HANDLE))
        return clients[-1]

    monkeypatch.setattr(
        bridge,
        "connect_service_on_demand",
        cast(Callable[[object], Awaitable[object]], unlocked),
    )
    await bridge.dispatch_start(_start_body(), runtime)
    (sent,) = clients[-1].sent
    assert sent.workspace_ref == _HANDLE


@pytest.mark.anyio
async def test_a_locked_remote_vault_is_named_as_such_and_nothing_is_sent(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A locked server binds no handle; the agent is told to have its vault unlocked there."""

    import finishup.client.targets as targets

    client = _Client("client_claim", None)
    _wire(monkeypatch, tmp_path, client)
    monkeypatch.setattr(targets, "active_target_is_remote", lambda: True)
    result = await bridge.dispatch_start(_start_body(), bridge.build_bridge_runtime())
    assert client.sent == []
    assert getattr(result, "isError") is True
    structured = cast(dict[str, object], getattr(result, "structuredContent"))
    error = cast(dict[str, object], structured["error"])
    assert error["code"] == "VAULT_LOCKED"
    details = cast(dict[str, object], error["safe_details"])
    assert details["continuation"] == "remote_vault_unlock_required"
    assert "private-project" not in repr(result)
