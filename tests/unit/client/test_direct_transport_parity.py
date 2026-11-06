"""One control session is byte-identical on every direct-dial transport (ADR-051, approach B).

The same scripted session — a claim-bound hello that declares a workspace agent, a call, a call
cancelled while in flight, and a server operation that sends a ``workspace_call`` and answers only
after the client's ``workspace_reply`` — runs over:

* an in-memory stream pair (the baseline);
* a real ``AuthenticatedUnixStream`` pair over ``socket.socketpair`` (the local Unix transport);
* ``SshTransport`` with its production argv, where a stand-in for ``ssh`` honours ``-W`` by
  relaying to a real Unix socket;
* ``HttpsTransport`` through HTTPS binding v1 against the real gateway (``finishup service
  gateway``, in process over ``httpx.ASGITransport``, with a real key and mounted under the
  target's base path), including the ``202`` → results long-poll for the cancelled call and the
  frames long-poll that carries the ``workspace_call``.

A wire tap on each side records every byte; the frames each side sent and received must be
identical to the baseline, so server-to-client and client-to-server frames both flow end to end
through every transport.
"""

from __future__ import annotations

import asyncio
import os
import socket
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest

from builders.direct_dial import (
    RELAY_SOURCE,
    WORKSPACE_REPLY,
    RecordingGateway,
    ServerTranscript,
    StaticCredential,
    TapStream,
    frames,
    https_target,
    memory_pair,
    pinned_nonce,
    real_gateway,
    scripted_client,
    scripted_server,
    ssh_target,
)
from builders.server_targets import ambient_home
from finishup.adapters.control.unix_socket import AuthenticatedUnixStream, authenticate_peer
from finishup.client.transports import HttpsTransport, SshTransport, ssh_stdio_argv
from finishup.service.control_protocol import ControlStream


@dataclass(frozen=True)
class _Observation:
    client_sent: tuple[bytes, ...]
    client_received: tuple[bytes, ...]
    server_sent: tuple[bytes, ...]
    server_received: tuple[bytes, ...]
    client_kinds: tuple[str, ...]
    server_kinds: tuple[str, ...]
    handle: str | None
    reply_matches: bool


def _observe(
    client: TapStream, server: TapStream, kinds: list[str], transcript: ServerTranscript
) -> _Observation:
    return _Observation(
        tuple(frames(bytes(client.sent))),
        tuple(frames(bytes(client.received))),
        tuple(frames(bytes(server.sent))),
        tuple(frames(bytes(server.received))),
        tuple(kinds),
        tuple(transcript.kinds),
        transcript.handle,
        transcript.reply == WORKSPACE_REPLY,
    )


async def _run(client_stream: ControlStream, server_stream: ControlStream) -> _Observation:
    client = TapStream(client_stream)
    server = TapStream(server_stream)
    serving = asyncio.create_task(scripted_server(server, server.peer_identity))
    kinds = await scripted_client(client)
    await client.aclose()
    transcript = await asyncio.wait_for(serving, 5)
    await server.aclose()
    return _observe(client, server, kinds, transcript)


async def _over_memory() -> _Observation:
    client, server = memory_pair()
    return await _run(client, server)


async def _over_socketpair() -> _Observation:
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    client = AuthenticatedUnixStream(left, authenticate_peer(left))
    server = AuthenticatedUnixStream(right, authenticate_peer(right))
    return await _run(client, server)


async def _over_ssh_relay(directory: Path) -> tuple[_Observation, list[str]]:
    relay = directory / "relay.py"
    relay.write_text(RELAY_SOURCE, encoding="utf-8")
    endpoint = directory / "c.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(os.fspath(endpoint))
    listener.listen(1)
    listener.setblocking(False)
    target = ssh_target(endpoint=os.fspath(endpoint))
    transport = SshTransport(target, directory, program=(sys.executable, "-I", os.fspath(relay)))
    try:
        accepting = asyncio.ensure_future(asyncio.get_running_loop().sock_accept(listener))
        client = await transport.connect()
        connection, _address = await asyncio.wait_for(accepting, 10)
        server = AuthenticatedUnixStream(connection, authenticate_peer(connection))
        observation = await _run(client, server)
    finally:
        listener.close()
    logged = (directory / "relay.log").read_text(encoding="utf-8").splitlines()
    return observation, logged


async def _over_https(keys: Path) -> tuple[_Observation, RecordingGateway]:
    servers: list[tuple[TapStream, asyncio.Task[ServerTranscript]]] = []

    async def upstream() -> ControlStream:
        gateway_end, server_end = memory_pair()
        tap = TapStream(server_end)
        servers.append((tap, asyncio.create_task(scripted_server(tap, tap.peer_identity))))
        return gateway_end

    gateway = real_gateway(keys, upstream)
    transport = HttpsTransport(
        https_target(),
        Path("/nonexistent"),
        credential=StaticCredential(gateway.key),
        http_transport=httpx.ASGITransport(app=gateway),
    )
    client = TapStream(await transport.connect())
    kinds = await scripted_client(client)
    await client.aclose()
    ((server, serving),) = servers
    transcript = await asyncio.wait_for(serving, 5)
    await gateway.state.sessions.close_all()
    return _observe(client, server, kinds, transcript), gateway


def test_one_session_is_byte_identical_over_every_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pinned_nonce(monkeypatch), tempfile.TemporaryDirectory(prefix="fu-") as raw:
        directory = Path(raw)
        monkeypatch.setenv("FU_RELAY_LOG", os.fspath(directory / "relay.log"))
        baseline = asyncio.run(_over_memory())
        assert baseline.client_kinds == (
            "result:rpc_00000000-0000-4000-8000-000000000001",
            "result:rpc_00000000-0000-4000-8000-000000000002",
            "workspace_call",
            "result:rpc_00000000-0000-4000-8000-000000000004",
        )
        assert baseline.server_kinds == ("call", "call", "cancel", "call", "workspace_reply")
        assert baseline.handle == "client:" + "1" * 16
        assert baseline.reply_matches

        assert asyncio.run(_over_socketpair()) == baseline

        over_ssh, logged = asyncio.run(_over_ssh_relay(directory))
        assert over_ssh == baseline
        # The stand-in ran with exactly the production argv after the program.
        expected = ssh_stdio_argv(
            ssh_target(endpoint=os.fspath(directory / "c.sock")), directory, program=()
        )
        assert logged == [" ".join(expected)]

        with ambient_home(monkeypatch) as home:
            over_https, gateway = asyncio.run(_over_https(home / "gateway"))
        assert over_https == baseline

    paths = [(method, path) for method, path, _headers in gateway.requests]
    session = paths[0]
    assert session == ("POST", "/base/v1/sessions")
    sid_path = next(path for method, path in paths if method == "POST" and path.endswith("/calls"))
    prefix = sid_path.removesuffix("/calls")
    # The cancelled call took the 202 path and its result arrived through the results long-poll;
    # the workspace call arrived through the frames long-poll and the reply was posted back.
    assert ("GET", f"{prefix}/results/rpc_00000000-0000-4000-8000-000000000002") in paths
    assert ("POST", f"{prefix}/cancel") in paths
    assert ("GET", f"{prefix}/frames") in paths
    assert ("POST", f"{prefix}/frames") in paths
    assert ("DELETE", prefix) in paths
    calls = [path for method, path in paths if method == "POST" and path.endswith("/calls")]
    assert len(calls) == 3  # never re-posted
    for _method, _path, headers in gateway.requests:
        assert {"authorization", "finishup-binding"} <= headers
        assert "origin" not in headers
