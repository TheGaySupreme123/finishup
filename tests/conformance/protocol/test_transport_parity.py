"""One scripted control session carries identical bytes over every approach-A transport (ADR-051).

The same session — a hello with a workspace claim and an agent offer, one call per agent-scope
method, the server's ``workspace_call`` and the client's ``workspace_reply``, and a cancel — runs
over four transports:

1. an in-memory stream pair (today's test seam);
2. a real AF_UNIX ``socketpair`` with peer-UID authentication;
3. the connector's SSH relay: an OpenSSH stand-in master forwarding ``run/upstream.sock`` to the
   daemon's socket, and the connector's unparsed byte pump;
4. the connector's HTTPS relay to the in-process gateway (``httpx.ASGITransport``), which maps
   the session onto the binding's routes and one upstream control connection.

Every frame the client receives is byte-identical across all four, and so is every frame the
daemon receives (the hello exactly, in order; the rest as a multiset, because the HTTPS relay
posts a call and its cancel on separate requests).
"""

from __future__ import annotations

import asyncio
import socket
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

import httpx
import pytest

from builders.control_relay import (
    ScriptedDaemon,
    memory_pair,
    run_scripted_session,
    serve_unix,
    write_fake_ssh,
)
from builders.server_targets import ambient_home
from finishup.adapters.control.unix_socket import AuthenticatedUnixStream, authenticate_peer
from finishup.client import targets
from finishup.client.connector import Connector
from finishup.config.paths import selection_override
from finishup.gateway.app import build_gateway_app
from finishup.gateway.keys import create_key
from finishup.protocol.canonical import JsonValue


class _Audit:
    def __init__(self) -> None:
        self.records: list[dict[str, JsonValue]] = []

    def write(self, record: dict[str, JsonValue]) -> None:
        self.records.append(record)


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as root:
        yield root


def _socketpair() -> tuple[AuthenticatedUnixStream, AuthenticatedUnixStream]:
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    return (
        AuthenticatedUnixStream(left, authenticate_peer(left)),
        AuthenticatedUnixStream(right, authenticate_peer(right)),
    )


async def _over_memory(daemon: ScriptedDaemon) -> list[bytes]:
    client, server = memory_pair()
    served = asyncio.create_task(daemon.serve(server))
    received = await run_scripted_session(client)
    await client.aclose()
    await served
    return received


async def _over_socketpair(daemon: ScriptedDaemon) -> list[bytes]:
    client, server = _socketpair()
    served = asyncio.create_task(daemon.serve(server))
    received = await run_scripted_session(client)
    await client.shutdown_write()
    await served
    await client.aclose()
    return received


async def _relay(connector: Connector) -> list[bytes]:
    client, local = _socketpair()
    relay = asyncio.create_task(connector._serve_local(local))  # pyright: ignore[reportPrivateUsage]
    received = await run_scripted_session(client)
    await client.shutdown_write()
    async with asyncio.timeout(10):
        await relay
    await client.aclose()
    return received


def _remote(
    name: str, kind: targets.TargetKind, **fields: object
) -> tuple[targets.ServerTarget, Path]:
    with targets.registry_lock():
        return targets.new_remote_target(name, kind, **fields)  # type: ignore[arg-type]


async def _over_ssh_relay(daemon: ScriptedDaemon, home: Path) -> list[bytes]:
    record, root = _remote(
        "lab", "ssh", host="lab.example", port=22, remote_launcher="/opt/finishup/bin/finishup"
    )
    endpoint = home / "d.sock"
    record = replace(record, remote_endpoint=str(endpoint))
    server = await serve_unix(endpoint, daemon)
    ssh = write_fake_ssh(home / "bin")
    connector = Connector(root, record, ssh=str(ssh))
    try:
        with selection_override(root):
            return await _relay(connector)
    finally:
        await connector._ssh.close()  # pyright: ignore[reportPrivateUsage,reportOptionalMemberAccess]
        server.cancel()
        await asyncio.gather(server, return_exceptions=True)


async def _over_https_gateway(daemon: ScriptedDaemon, home: Path) -> list[bytes]:
    record, root = _remote("gw", "https", base_url="https://gw.example")
    keys = home / "gateway"
    _key_record, key = create_key(keys, label="parity", scope="agent")
    served: list[asyncio.Task[None]] = []

    async def connect_upstream() -> object:
        client, server = memory_pair()
        served.append(asyncio.create_task(daemon.serve(server)))
        return client

    _state, app = build_gateway_app(
        keys_directory=keys,
        connect_upstream=connect_upstream,  # type: ignore[arg-type]
        audit=_Audit(),
    )
    connector = Connector(
        root,
        record,
        https_transport=httpx.ASGITransport(app=app),
        credential=lambda: key,
    )
    with selection_override(root):
        received = await _relay(connector)
    async with asyncio.timeout(10):
        await asyncio.gather(*served)
    return received


def test_one_session_is_byte_identical_over_every_transport(home: Path) -> None:
    async def exercise() -> None:
        daemons = [ScriptedDaemon() for _ in range(4)]
        received = [
            await _over_memory(daemons[0]),
            await _over_socketpair(daemons[1]),
            await _over_ssh_relay(daemons[2], home),
            await _over_https_gateway(daemons[3], home),
        ]
        for transport in received[1:]:
            assert transport == received[0]
        # hello-result, seven results, one workspace call, the cancelled call's result
        assert len(received[0]) == 10
        reference = daemons[0].received()
        assert len(reference) == 11  # hello, seven calls, the reply, the slow call, its cancel
        for daemon in daemons:
            frames = daemon.received()
            assert frames[0] == reference[0]
            assert sorted(frames[1:]) == sorted(reference[1:])
            assert [reply["outcome"] for reply in daemon.replies] == ["unavailable"]
            assert daemon.connections == 1

    asyncio.run(exercise())
