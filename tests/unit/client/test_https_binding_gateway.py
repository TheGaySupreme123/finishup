"""The direct-dial HTTPS client against the real gateway (ADR-051, approach B).

Approach B's ``HttpsTransport`` speaks HTTPS binding v1 to the same ``finishup service gateway``
approach A uses. These tests run the client against that real gateway application (in process,
``httpx.ASGITransport``, a real key in a real key file): the binding's names and bounds agree,
``GET /v1/server`` is checked, a key the gateway refuses or revokes is ``remote_auth_failed``, a
call outside the key's scope is the gateway's synthesized ``method_forbidden``, and a session the
gateway expired is a retryable failure the caller's reconnect recovers from.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest

from builders.direct_dial import (
    StaticCredential,
    https_target,
    memory_pair,
    real_gateway,
    service_status,
)
from builders.server_targets import ambient_home
from finishup import __version__
from finishup.client import https_binding
from finishup.client.https_binding import fetch_server_info
from finishup.client.transports import HttpsTransport, TransportError
from finishup.gateway.keys import revoke_key
from finishup.ports.control import (
    ControlClientKind,
    ControlError,
    ControlMethod,
    ControlResult,
    ProjectionRenderMode,
)
from finishup.protocol import rest_binding
from finishup.protocol.schemas import schema_manifest_digest
from finishup.service import client as client_module
from finishup.service.control_protocol import (
    ControlStream,
    parse_control_request,
    read_control_frame,
    server_handshake,
    write_control_frame,
)


@pytest.fixture
def keys(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as home:
        yield home / "gateway"


async def _status_server(stream: ControlStream) -> None:
    """A service that answers every call with its status."""

    session = await server_handshake(stream, stream.peer_identity, service_status())
    while True:
        try:
            frame = await read_control_frame(stream, eof_reason="session_closed")
        except Exception:
            return
        request = parse_control_request(frame)
        await write_control_frame(
            stream,
            ControlResult(
                protocol_version="1.0",
                rpc_id=request.rpc_id,
                service_instance_id=session.service_instance_id,
                service_generation=session.service_generation,
                method=ControlMethod.SERVICE_STATUS,
                outcome="ok",
                body=service_status(),
            ),
        )


async def _upstream() -> ControlStream:
    gateway_end, server_end = memory_pair()
    asyncio.get_running_loop().create_task(_status_server(server_end))
    return gateway_end


def _transport(gateway: object, key: str) -> HttpsTransport:
    return HttpsTransport(
        https_target(),
        Path("/nonexistent"),
        credential=StaticCredential(key),
        http_transport=httpx.ASGITransport(app=gateway),  # type: ignore[arg-type]
    )


async def _connect(transport: HttpsTransport) -> client_module.ServiceClient:
    return await client_module._connect_service_attempt(  # pyright: ignore[reportPrivateUsage]
        ControlClientKind.CLI,
        workspace_locator=None,
        projection_render_mode=ProjectionRenderMode.MACHINE_READABLE,
        output_is_controlling_tty=False,
        timeout_seconds=5.0,
        transport=transport,
    )


def test_the_client_and_the_gateway_share_the_binding_names_and_bounds() -> None:
    assert https_binding.BINDING_HEADER == rest_binding.BINDING_HEADER
    assert https_binding.BINDING_VERSION == rest_binding.BINDING_VERSION
    assert https_binding.LONG_POLL_WAIT_MS == rest_binding.MAX_WAIT_MS
    assert https_binding.CALL_WAIT_MS <= rest_binding.MAX_WAIT_MS
    assert https_binding.SESSION_ID_PATTERN.pattern == rest_binding.SESSION_ID_PATTERN.pattern
    # A session idle this long is checked before a call, well inside the gateway's expiry.
    assert https_binding.SESSION_IDLE_CHECK_SECONDS < rest_binding.SESSION_IDLE_SECONDS
    # A live agent session begins its next frames long-poll well inside the gateway's grace.
    from finishup.gateway.sessions import AGENT_POLL_GRACE_SECONDS

    assert https_binding.LONG_POLL_WAIT_MS / 1_000 + 10.0 <= AGENT_POLL_GRACE_SECONDS


def test_server_info_from_the_real_gateway_is_this_release(keys: Path) -> None:
    gateway = real_gateway(keys, _upstream)

    async def info() -> https_binding.ServerInfo:
        return await fetch_server_info(
            https_target(), gateway.key, http_transport=httpx.ASGITransport(app=gateway)
        )

    reported = asyncio.run(info())
    assert reported == https_binding.ServerInfo(__version__, schema_manifest_digest())
    assert gateway.requests[-1][:2] == ("GET", "/base/v1/server")


def test_a_key_the_gateway_does_not_know_or_revoked_is_an_auth_failure(keys: Path) -> None:
    gateway = real_gateway(keys, _upstream)
    other = "fuk_" + "0" * 12 + "_" + "A" * 43

    async def info(key: str) -> object:
        return await fetch_server_info(
            https_target(), key, http_transport=httpx.ASGITransport(app=gateway)
        )

    with pytest.raises(TransportError) as raised:
        asyncio.run(info(other))
    assert raised.value.phase == "remote_auth_failed"

    key_id = gateway.key.split("_")[1]
    revoke_key(keys, key_id)
    gateway.state.keys.refresh()
    with pytest.raises(TransportError) as raised:
        asyncio.run(info(gateway.key))
    assert raised.value.phase == "remote_auth_failed"

    async def dial() -> ControlError:
        with pytest.raises(ControlError) as failed:
            await _connect(_transport(gateway, gateway.key))
        return failed.value

    error = asyncio.run(dial())
    assert (error.reason, error.retryable, error.phase) == (
        "service_unavailable",
        True,
        "remote_auth_failed",
    )


def test_a_call_outside_the_keys_scope_is_the_gateways_method_forbidden(keys: Path) -> None:
    gateway = real_gateway(keys, _upstream, scope="agent")

    async def exercise() -> tuple[str, str]:
        client = await _connect(_transport(gateway, gateway.key))
        try:
            status = await client.service_status()
            with pytest.raises(ControlError) as refused:
                # ``service_stop`` is never reachable over HTTPS, whatever the scope.
                await client.stop()
        finally:
            await client.close()
        await gateway.state.sessions.close_all()
        return status.service_instance_id, refused.value.reason

    assert asyncio.run(exercise()) == (service_status().service_instance_id, "method_forbidden")


def test_a_session_the_gateway_expired_is_retryable_and_a_new_connection_works(
    keys: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Every session counts as idle at the gateway's next sweep, and the client checks its session
    # before every call (in production: idle 120 s at the gateway, checked after 90 s here).
    gateway = real_gateway(keys, _upstream, idle_seconds=0.0)
    monkeypatch.setattr(https_binding, "SESSION_IDLE_CHECK_SECONDS", 0.0)

    async def exercise() -> tuple[ControlError, str]:
        transport = _transport(gateway, gateway.key)
        client = await _connect(transport)
        await client.service_status()
        await gateway.state.sweep()
        with pytest.raises(ControlError) as expired:
            await client.service_status()
        await client.close()
        again = await _connect(transport)
        try:
            status = await again.service_status()
        finally:
            await again.close()
        await gateway.state.sessions.close_all()
        return expired.value, status.service_instance_id

    error, served = asyncio.run(exercise())
    # The call was never posted into the expired session, so the caller's reconnect-once replays
    # it safely on a new one.
    assert (error.reason, error.retryable) == ("service_unavailable", True)
    assert served == service_status().service_instance_id
