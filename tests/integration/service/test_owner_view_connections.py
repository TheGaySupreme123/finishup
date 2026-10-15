"""R3-F1: an owner-view grant belongs to one service-admitted control connection.

These drive the daemon's real control-connection loop (``_serve_control_connection``) over
in-memory streams. The hello nonce is chosen by the client, so every case below uses the same
nonce on more than one connection: the attack is a second connection that claims the owner's
nonce. Only the daemon's dispatch is recorded, to observe the owner-view decision it made.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any

import pytest

import yoetz.service.control_protocol as control_protocol
from integration.service.test_daemon_clients import (
    _connected_control_pair,
    _daemon,
    _request,
)
from yoetz.ports.control import ControlClientKind, ControlError, ControlMethod
from yoetz.protocol.models import ReceiptRequest
from yoetz.service.control_protocol import (
    client_handshake,
    parse_control_result,
    read_control_frame,
    write_control_frame,
)
from yoetz.service.owner_view import (
    control_connection_digest,
    owner_receipt_view_target,
    owner_receipt_view_target_digest,
)

pytestmark = pytest.mark.anyio

_NONCE = "e" * 64
_BODY = ReceiptRequest.model_validate(
    {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": "req_00000000-0000-4000-8000-0000000000d1",
        "actor": {"actor_id": "harness:owner", "actor_type": "harness"},
        "client": {"kind": "yoetz_cli", "version": "0.3.0", "integration": "local_cli"},
        "task_id": "tsk_00000000-0000-4000-8000-0000000000d2",
        "session_id": "ses_00000000-0000-4000-8000-0000000000d3",
        "writer_id": "wri_00000000-0000-4000-8000-0000000000d4",
        "expected_frontier": {"sequence": "3", "head_digest": "sha256:" + "1" * 64},
        "format": "markdown",
        "include": "full",
        "redaction_profile": "full_local",
    }
)
_TARGET_DIGEST = owner_receipt_view_target_digest(owner_receipt_view_target(_BODY, _NONCE))


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class _Connection:
    def __init__(self, daemon: Any, nonce: str, monkeypatch: pytest.MonkeyPatch) -> None:
        self.daemon = daemon
        self.nonce = nonce
        self.monkeypatch = monkeypatch
        self.client: Any = None
        self.session: Any = None
        self.task: asyncio.Task[None] | None = None

    async def open(self) -> None:
        self.client, server = _connected_control_pair()
        self.task = asyncio.create_task(self.daemon._serve_control_connection(server))
        # The client picks its hello nonce; an attacker can pick the owner's.
        self.monkeypatch.setattr(
            control_protocol, "secrets", SimpleNamespace(token_hex=lambda _n=32: self.nonce)
        )
        self.session = await client_handshake(self.client, ControlClientKind.CLI, "0.3.0")

    async def receipt(self) -> bool:
        request = _request(self.daemon, ControlMethod.RECEIPT, _BODY)
        self.session.admit(request)
        await write_control_frame(self.client, request)
        result = parse_control_result(await read_control_frame(self.client))
        self.session.correlate(result)
        return self.daemon.owner_views.pop(request.rpc_id)

    async def close(self) -> None:
        assert self.task is not None
        self.task.cancel()
        await asyncio.gather(self.task, return_exceptions=True)


async def _started(monkeypatch: pytest.MonkeyPatch) -> Any:
    built, _application, _vault, _listener = _daemon()
    daemon: Any = built
    await daemon.start()
    daemon.owner_views = {}

    async def dispatch(_kind: object, request: Any, *, projection_context: Any, **_: object):
        daemon.owner_views[request.rpc_id] = projection_context.owner_view
        return daemon._error_result(
            request, ControlError("privacy_projection_blocked", retryable=False)
        )

    monkeypatch.setattr(daemon, "dispatch", dispatch)
    return daemon


async def test_a_second_connection_claiming_the_owner_nonce_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon = await _started(monkeypatch)
    owner = _Connection(daemon, _NONCE, monkeypatch)
    await owner.open()
    impostor = _Connection(daemon, _NONCE, monkeypatch)
    await impostor.open()
    # The daemon admitted the hello frame but refused the duplicate nonce: its loop ended
    # before serving a single call, so the impostor can never present a receipt call.
    assert impostor.task is not None
    await asyncio.wait_for(asyncio.shield(impostor.task), timeout=5)
    grants = daemon.composition.owner_view_grants
    grants.issue(_TARGET_DIGEST, control_connection_digest(_NONCE))
    assert await owner.receipt() is True
    # Single use on the owner's own connection too.
    assert await owner.receipt() is False
    await owner.close()
    await daemon.close()


async def test_another_connection_cannot_consume_the_owner_grant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Concurrent consumption: a different connection racing the owner gets nothing."""

    daemon = await _started(monkeypatch)
    owner = _Connection(daemon, _NONCE, monkeypatch)
    await owner.open()
    other = _Connection(daemon, "f" * 64, monkeypatch)
    await other.open()
    daemon.composition.owner_view_grants.issue(_TARGET_DIGEST, control_connection_digest(_NONCE))
    other_view, owner_view = await asyncio.gather(other.receipt(), owner.receipt())
    assert (other_view, owner_view) == (False, True)
    await other.close()
    await owner.close()
    await daemon.close()


async def test_disconnect_revokes_and_reconnecting_never_adopts_the_grant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon = await _started(monkeypatch)
    grants = daemon.composition.owner_view_grants
    owner = _Connection(daemon, _NONCE, monkeypatch)
    await owner.open()
    grants.issue(_TARGET_DIGEST, control_connection_digest(_NONCE))
    await owner.close()
    # Revoked with the connection, and the closed connection can no longer be granted.
    with pytest.raises(LookupError):
        grants.issue(_TARGET_DIGEST, control_connection_digest(_NONCE))
    # A new socket claiming the same nonce is refused outright ...
    again = _Connection(daemon, _NONCE, monkeypatch)
    await again.open()
    assert again.task is not None
    await asyncio.wait_for(asyncio.shield(again.task), timeout=5)
    # ... and a new socket with a fresh nonce starts with no grant at all.
    fresh = _Connection(daemon, "c" * 64, monkeypatch)
    await fresh.open()
    assert await fresh.receipt() is False
    await fresh.close()
    await daemon.close()
