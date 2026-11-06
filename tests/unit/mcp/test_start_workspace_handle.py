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
_PATH = "/home/dev/private-project"


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
async def test_without_a_handle_nothing_is_sent_and_the_agent_gets_the_typed_refusal(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    client = _Client("client_claim", None)
    _wire(monkeypatch, tmp_path, client)
    result = await bridge.dispatch_start(_start_body(), bridge.build_bridge_runtime())
    assert client.sent == []
    assert getattr(result, "isError") is True
    structured = cast(dict[str, object], getattr(result, "structuredContent"))
    error = cast(dict[str, object], structured["error"])
    assert error["code"] == "INVALID_REQUEST"
    assert error["retryable"] is False
    details = cast(dict[str, object], error["safe_details"])
    assert details["reason_code"] == "workspace_ref_not_portable"
    assert details["continuation"] == "workspace_handle_required"
    assert "private-project" not in repr(result)


@pytest.mark.anyio
async def test_a_locked_remote_vault_is_named_as_such_and_nothing_is_sent(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A locked server binds no handle; the agent is told to have its vault unlocked there."""

    import finishup.client.targets as targets
    from finishup.ports.control import ServiceState, ServiceStatus

    client = _Client("client_claim", None)
    client.hello_service_status = ServiceStatus(  # pyright: ignore[reportAttributeAccessIssue]
        protocol_version="1.0",
        service_version="0.3.0",
        service_instance_id="svc_00000000-0000-4000-8000-000000000071",
        service_generation="2",
        state=ServiceState.LOCKED,
        state_reason="passphrase_required",
        vault_mode="passphrase",
        capabilities=("confidential_ingress",),
        session_monitor="unavailable",
    )
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
