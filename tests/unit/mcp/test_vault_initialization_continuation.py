"""An uninitialized vault turns start-first ``VAULT_LOCKED`` into a typed continuation.

Issue #512: installed guidance requires `start` before substantive work and treats every
non-retryable error as terminal, yet a pristine install answered that first `start` with a bare
non-retryable ``VAULT_LOCKED`` whose prose told the agent to keep going. The bridge now performs
one bounded fresh-handshake probe after such a failure; when the hello-result proves the vault is
uninitialized, the error carries the ``vault_initialization_required`` continuation (exact
repository-literal commands, the pending TTL, and the replay request id) instead of a dead end.
A hard-locked, recovering, or unreadable service keeps the existing unlock/recovery answer.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import cast

import pytest

import finishup.mcp.server as bridge
from finishup.ports.control import ControlError, ServiceState, ServiceStatus, WorkspaceLocator
from finishup.protocol.canonical import JsonValue
from finishup.protocol.models import StartRequest, StartResult

_REQUEST = "req_00000000-0000-4000-8000-000000000021"
_CORRELATION = "err_00000000-0000-4000-8000-000000000022"


def _start_body(request_id: str = _REQUEST) -> dict[str, JsonValue]:
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": request_id,
        "actor": {"actor_id": "harness:mcp", "actor_type": "harness"},
        "client": {
            "kind": "cooperative_agent",
            "version": "0.1.0",
            "integration": "cooperative_mcp",
        },
        "mode": "create",
        "task_title": "First task",
        "requested_view": "compact",
    }


def _status(state: ServiceState, state_reason: str, vault_mode: str) -> ServiceStatus:
    return ServiceStatus(
        protocol_version="1.0",
        service_version="0.1.0",
        service_instance_id="svc_00000000-0000-4000-8000-000000000031",
        service_generation="1",
        state=state,
        state_reason=state_reason,
        vault_mode=vault_mode,
        capabilities=(),
        session_monitor="unavailable",
    )


def _uninitialized() -> ServiceStatus:
    return _status(ServiceState.LOCKED, "vault_uninitialized", "uninitialized")


class _LockedClient:
    """First connection: every workflow call fails ``vault_locked``."""

    def __init__(self, *, retryable: bool) -> None:
        self.retryable = retryable
        self.closed = False

    async def connect(self) -> None:
        return None

    async def start(self, request: StartRequest, *, deadline_ms: int | None = None) -> StartResult:
        del request, deadline_ms
        raise ControlError("vault_locked", retryable=self.retryable, correlation_id=_CORRELATION)

    async def close(self) -> None:
        self.closed = True


class _ProbeClient:
    """Reconnect after the discard: only the hello-status snapshot is consulted."""

    def __init__(self, status: ServiceStatus | None) -> None:
        self._status = status
        self.closed = False

    @property
    def hello_service_status(self) -> ServiceStatus | None:
        return self._status

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        self.closed = True


def _wire(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, connections: list[object]) -> list[str]:
    import finishup.observability.diagnostics as diagnostics

    monkeypatch.setattr(diagnostics, "log_dir", lambda: tmp_path)
    attempts: list[str] = []

    async def on_demand(
        _kind: object, *, workspace_locator: object = None, timeout_seconds: float = 30.0
    ) -> object:
        del workspace_locator, timeout_seconds
        attempts.append("connect")
        if not connections:
            raise ControlError("service_unavailable", retryable=True)
        return connections.pop(0)

    monkeypatch.setattr(
        bridge,
        "connect_service_on_demand",
        cast(Callable[[object], Awaitable[object]], on_demand),
    )
    return attempts


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _error(result: object) -> dict[str, object]:
    structured = cast(dict[str, object], getattr(result, "structuredContent"))
    assert getattr(result, "isError") is True
    return cast(dict[str, object], structured["error"])


@pytest.mark.anyio
async def test_uninitialized_vault_start_carries_the_typed_continuation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    attempts = _wire(
        monkeypatch,
        tmp_path,
        [_LockedClient(retryable=False), _ProbeClient(_uninitialized())],
    )
    runtime = bridge.build_bridge_runtime()

    error = _error(await bridge.dispatch_start(_start_body(), runtime))

    assert error["code"] == "VAULT_LOCKED"
    assert error["retryable"] is False
    assert error["correlation_id"] == _CORRELATION
    assert attempts == ["connect", "connect"]
    details = cast(dict[str, object], error["safe_details"])
    assert details == {
        "authorize_command": "finishup consent authorize",
        "continuation": "vault_initialization_required",
        "pending_ttl_seconds": 900,
        "prepare_command": "finishup consent prepare vault_initialize",
        "replay_request_id": _REQUEST,
        "review_command": "finishup consent review",
    }
    message = cast(str, error["message"])
    assert "uninitialized" in message
    assert "bounded initialization-required continuation" in message
    assert "finishup consent prepare vault_initialize" in message
    assert "replay this exact request_id and body once" in message
    assert "never request, receive, or transmit a secret" in message
    assert "allowlisted first-party attestation client" in message


@pytest.mark.anyio
async def test_cursor_profile_receives_only_the_trusted_local_continuation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _wire(monkeypatch, tmp_path, [_LockedClient(retryable=False), _ProbeClient(_uninitialized())])
    runtime = bridge.build_bridge_runtime(
        host_profile="cursor", workspace_locator=WorkspaceLocator(str(tmp_path))
    )

    error = _error(await bridge.dispatch_start(_start_body(), runtime))

    details = cast(dict[str, object], error["safe_details"])
    assert "authorize_command" not in details
    assert details["continuation"] == "vault_initialization_required"
    assert details["review_command"] == "finishup consent review"
    message = cast(str, error["message"])
    assert "finishup consent authorize" not in message
    assert "finishup consent review" in message


@pytest.mark.anyio
async def test_hard_locked_initialized_vault_keeps_the_unlock_and_recovery_answer(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    status = _status(ServiceState.LOCKED, "passphrase_required", "passphrase")
    _wire(monkeypatch, tmp_path, [_LockedClient(retryable=False), _ProbeClient(status)])
    runtime = bridge.build_bridge_runtime()

    error = _error(await bridge.dispatch_start(_start_body(), runtime))

    assert error["code"] == "VAULT_LOCKED"
    assert error["retryable"] is False
    assert "safe_details" not in error
    assert "hard lock or missing setup" in cast(str, error["message"])


@pytest.mark.anyio
async def test_probe_failure_degrades_to_the_plain_hard_lock_answer(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # The reconnect probe finds no service: never assert an initialization state that was not
    # read. The plain non-retryable message still names `finishup setup` for a human.
    attempts = _wire(monkeypatch, tmp_path, [_LockedClient(retryable=False)])
    runtime = bridge.build_bridge_runtime()

    error = _error(await bridge.dispatch_start(_start_body(), runtime))

    assert error["code"] == "VAULT_LOCKED"
    assert "safe_details" not in error
    assert attempts == ["connect", "connect"]
    assert "hard lock or missing setup" in cast(str, error["message"])


@pytest.mark.anyio
async def test_soft_locked_vault_never_probes_and_keeps_the_retry_answer(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    attempts = _wire(monkeypatch, tmp_path, [_LockedClient(retryable=True)])
    runtime = bridge.build_bridge_runtime()

    error = _error(await bridge.dispatch_start(_start_body(), runtime))

    assert error["code"] == "VAULT_LOCKED"
    assert error["retryable"] is True
    assert "safe_details" not in error
    assert attempts == ["connect"]
    assert "Retry this operation" in cast(str, error["message"])


@pytest.mark.anyio
async def test_vault_initialized_between_failure_and_probe_drops_the_continuation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # The probe reads current state: a vault that became ready between the failing call and the
    # reconnect must not be described as uninitialized.
    ready = _status(ServiceState.READY, "none", "os_keyring")
    _wire(monkeypatch, tmp_path, [_LockedClient(retryable=False), _ProbeClient(ready)])
    runtime = bridge.build_bridge_runtime()

    error = _error(await bridge.dispatch_start(_start_body(), runtime))

    assert error["code"] == "VAULT_LOCKED"
    assert "safe_details" not in error
