"""Streams, a scripted daemon and a scripted client session for relay tests (ADR-051, approach A).

* ``MemoryStream``/``memory_pair`` — an in-memory ``ControlStream`` pair; closing one end ends
  the other end's reads.
* ``ScriptedDaemon`` — serves control connections the way the daemon's control loop does, with
  fixed answers: ``service_status`` succeeds, every other call gets a ``vault_locked`` error
  result, a call to ``SLOW_METHOD`` waits until it is cancelled (then ``request_cancelled``), and
  a session whose hello declared a workspace agent receives one ``workspace_call`` after its
  first call and must answer it. Every frame it reads and writes is recorded as exact payload
  bytes.
* ``run_scripted_session`` — drives one fixed session over any stream: a hello with a fixed
  nonce, one call per agent-scope method, a cancel, the workspace call and its reply. It returns
  the payload bytes the client received, so every transport can be compared byte for byte.
* ``write_fake_ssh`` — an ``ssh`` stand-in on ``PATH``: ``-M … -L LOCAL:REMOTE`` binds the local
  socket (mode 0600) and pumps each connection to the remote socket; ``-O exit|check`` talks to
  its control socket, and an exiting master leaves its forwarded socket behind as OpenSSH does;
  any other invocation runs the remote command locally.
"""

from __future__ import annotations

import asyncio
import contextlib
import struct
import sys
from collections.abc import Buffer
from pathlib import Path
from typing import Final, cast

from finishup.domain.values import JsonObject
from finishup.ports.control import (
    ControlCallRequest,
    ControlError,
    ControlMethod,
    ControlResult,
    ServiceState,
    ServiceStatus,
    WorkspaceCall,
)
from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.protocol.schemas import load_schema_catalog
from finishup.service.control_protocol import (
    ControlProtocolError,
    ControlStream,
    encode_control_frame,
    parse_control_request,
    read_control_frame,
    server_handshake,
    workspace_call_frame,
)

__all__ = [
    "AGENT_METHODS",
    "call_request",
    "serve_unix",
    "split_frames",
    "CLAIM_DIGEST",
    "SERVICE_ID",
    "SLOW_METHOD",
    "MemoryStream",
    "ScriptedDaemon",
    "memory_pair",
    "rpc_id",
    "run_scripted_session",
    "service_status",
    "write_fake_ssh",
]

SERVICE_ID: Final = "svc_00000000-0000-4000-8000-0000000000a1"
CLAIM_DIGEST: Final = "sha256:" + "c1a1" * 16
# The agent scope's methods, each called once by the scripted session (ADR-051 decision 9).
AGENT_METHODS: Final = (
    ControlMethod.START,
    ControlMethod.PUBLISH_WORK,
    ControlMethod.CHECK,
    ControlMethod.RESPOND,
    ControlMethod.STATUS,
    ControlMethod.RECEIPT,
    ControlMethod.SERVICE_STATUS,
)
SLOW_METHOD: Final = ControlMethod.STATUS
_CALL_ID: Final = "rpc_00000000-0000-4000-8000-00000000c0de"


def rpc_id(sequence: int) -> str:
    return f"rpc_00000000-0000-4000-8000-{sequence:012x}"


def service_status() -> ServiceStatus:
    return ServiceStatus(
        protocol_version="1.0",
        service_version="0.1.0",
        service_instance_id=SERVICE_ID,
        service_generation="1",
        state=ServiceState.LOCKED,
        state_reason="human_authority_unavailable",
        vault_mode="uninitialized",
        capabilities=(),
        session_monitor="unavailable",
    )


class MemoryStream:
    """One end of an in-memory byte stream; ``aclose`` ends the peer's reads."""

    def __init__(self, peer_identity: object) -> None:
        self.peer_identity = peer_identity
        self.other: MemoryStream | None = None
        self.closed = False
        self._chunks: asyncio.Queue[bytes] = asyncio.Queue()
        self._buffer = bytearray()
        self._ended = False

    async def receive(self, max_bytes: int) -> bytes:
        while not self._buffer:
            if self._ended:
                return b""
            chunk = await self._chunks.get()
            if not chunk:
                self._ended = True
                return b""
            self._buffer.extend(chunk)
        chunk = bytes(self._buffer[:max_bytes])
        del self._buffer[:max_bytes]
        return chunk

    async def send_all(self, data: Buffer) -> None:
        if self.closed or self.other is None:
            raise ConnectionError("memory_stream_closed")
        payload = bytes(data)
        if payload:
            self.other._chunks.put_nowait(payload)

    async def aclose(self) -> None:
        if self.closed:
            return
        self.closed = True
        if self.other is not None:
            self.other._chunks.put_nowait(b"")


def memory_pair() -> tuple[MemoryStream, MemoryStream]:
    """``(client end, server end)``; each end's ``peer_identity`` names the other side."""

    client_peer = object()
    server_peer = object()
    client = MemoryStream(server_peer)
    server = MemoryStream(client_peer)
    client.other = server
    server.other = client
    return client, server


def _payload(frame: object) -> bytes:
    return encode_control_frame(frame)[4:]


class _Tap:
    """A stream that records every byte read from it."""

    def __init__(self, inner: ControlStream, sink: bytearray) -> None:
        self._inner = inner
        self._sink = sink

    @property
    def peer_identity(self) -> object:
        return self._inner.peer_identity

    async def receive(self, max_bytes: int) -> bytes:
        data = await self._inner.receive(max_bytes)
        self._sink.extend(data)
        return data

    async def send_all(self, data: Buffer) -> None:
        await self._inner.send_all(data)

    async def aclose(self) -> None:
        await self._inner.aclose()


def split_frames(data: bytes) -> list[bytes]:
    """The payloads of a byte stream of length-prefixed frames (a trailing partial is dropped)."""

    payloads: list[bytes] = []
    offset = 0
    while offset + 4 <= len(data):
        (length,) = struct.unpack(">I", data[offset : offset + 4])
        if offset + 4 + length > len(data):
            break
        payloads.append(data[offset + 4 : offset + 4 + length])
        offset += 4 + length
    return payloads


class ScriptedDaemon:
    """Serves connections with fixed answers and records every frame's payload bytes."""

    def __init__(self) -> None:
        self.inbound: list[bytearray] = []
        self.sent: list[bytes] = []
        self.connections = 0
        self.replies: list[JsonObject] = []

    def received(self, connection: int = -1) -> list[bytes]:
        """Every frame payload one connection sent the daemon, its hello first."""

        return split_frames(bytes(self.inbound[connection]))

    async def _send(self, stream: ControlStream, frame: object) -> None:
        encoded = encode_control_frame(frame)
        self.sent.append(encoded[4:])
        await stream.send_all(encoded)

    async def serve(self, stream: ControlStream) -> None:
        """Serve one connection until its peer ends it."""

        self.connections += 1
        sink = bytearray()
        self.inbound.append(sink)
        stream = _Tap(stream, sink)
        write_lock = asyncio.Lock()
        slow: dict[str, asyncio.Event] = {}
        tasks: set[asyncio.Task[None]] = set()
        workspace_called = False
        try:
            session = await server_handshake(stream, stream.peer_identity, service_status())
            while True:
                try:
                    frame = await read_control_frame(stream)
                except ControlProtocolError:
                    return
                if frame.get("kind") == "workspace_reply":
                    self.replies.append(frame)
                    continue
                request = parse_control_request(frame)
                if not isinstance(request, ControlCallRequest):
                    # A cancel may overtake its call on a transport with concurrent requests.
                    slow.setdefault(request.target_rpc_id, asyncio.Event()).set()
                    continue
                if request.method is SLOW_METHOD and request.rpc_id.endswith("51f0"):
                    event = slow.setdefault(request.rpc_id, asyncio.Event())

                    async def answer_after_cancel(
                        call: ControlCallRequest = request, done: asyncio.Event = event
                    ) -> None:
                        await done.wait()
                        async with write_lock:
                            await self._send(
                                stream, _result(call, ControlError("request_cancelled"))
                            )

                    task = asyncio.create_task(answer_after_cancel())
                    tasks.add(task)
                    continue
                async with write_lock:
                    await self._send(stream, _answer(request))
                    if session.workspace_agent is not None and not workspace_called:
                        workspace_called = True
                        await self._send(
                            stream,
                            workspace_call_frame(
                                WorkspaceCall(
                                    kind="workspace_call",
                                    protocol_version="1.0",
                                    call_id=_CALL_ID,
                                    service_instance_id=SERVICE_ID,
                                    service_generation="1",
                                    operation="read_task_base",
                                    arguments=JsonObject({"workspace": "client:0123456789abcdef"}),
                                    deadline_ms=5_000,
                                )
                            ),
                        )
        except ControlProtocolError:
            return
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            with contextlib.suppress(Exception):
                await stream.aclose()


def _result(request: ControlCallRequest, body: ControlError | ServiceStatus) -> ControlResult:
    return ControlResult(
        protocol_version="1.0",
        rpc_id=request.rpc_id,
        service_instance_id=request.service_instance_id,
        service_generation=request.service_generation,
        method=request.method,
        outcome="error" if isinstance(body, ControlError) else "ok",
        body=body,
    )


def _answer(request: ControlCallRequest) -> ControlResult:
    if request.method is ControlMethod.SERVICE_STATUS:
        return _result(request, service_status())
    return _result(request, ControlError("vault_locked"))


def _hello(*, agent: bool) -> dict[str, JsonValue]:
    hello: dict[str, JsonValue] = {
        "protocol_version": "1.0",
        "client_kind": "cli",
        "client_version": "0.1.0",
        "connection_nonce": "1f" * 32,
        "schema_manifest_digest": load_schema_catalog().manifest_digest,
        "presentation_context": {
            "render_mode": "machine_readable",
            "output_is_controlling_tty": False,
        },
    }
    if agent:
        hello["workspace_claim"] = {
            "schema_version": "1.0.0",
            "identity_kind": "git_common_root",
            "digest": CLAIM_DIGEST,
        }
        hello["workspace_agent"] = {
            "schema_version": "1.0.0",
            "operations": ["read_task_base"],
            "max_reply_bytes": 1_048_576,
        }
    return hello


_ACTOR: Final[dict[str, JsonValue]] = {"actor_id": "harness:test", "actor_type": "harness"}
_CLIENT: Final[dict[str, JsonValue]] = {
    "kind": "test_client",
    "version": "0.1.0",
    "integration": "local_cli",
}
_GENESIS: Final[dict[str, JsonValue]] = {"sequence": "0", "head_digest": "genesis"}


def _envelope(sequence: int) -> dict[str, JsonValue]:
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": f"req_00000000-0000-4000-8000-{sequence:012x}",
        "actor": _ACTOR,
        "client": _CLIENT,
    }


def _session(sequence: int) -> dict[str, JsonValue]:
    return {
        "session_id": f"ses_00000000-0000-4000-8000-{sequence:012x}",
        "writer_id": f"wri_00000000-0000-4000-8000-{sequence:012x}",
    }


def _body(sequence: int, method: ControlMethod) -> object:
    """A schema-valid request body for one agent-scope method (its content is never acted on)."""

    from finishup.protocol.models import (
        CheckRequest,
        PublishWorkRequest,
        ReceiptRequest,
        RespondRequest,
        StartRequest,
        StatusRequest,
    )

    base = _envelope(sequence)
    if method is ControlMethod.START:
        return StartRequest.model_validate(
            {**base, "mode": "create", "task_title": "parity", "requested_view": "compact"}
        )
    if method is ControlMethod.PUBLISH_WORK:
        draft: dict[str, JsonValue] = {
            "event_id": f"evt_00000000-0000-4000-8000-{sequence:012x}",
            "schema": {"name": "plan_published", "version": "1.0.0"},
            "occurred_at": "2026-01-01T00:00:00.000Z",
            "causal_parents": [],
            "payload": {"plan_version": 1, "summary": "Plan", "obligation_refs": []},
            "artifact_refs": [],
            "evidence_refs": [],
        }
        return PublishWorkRequest.model_validate(
            {
                **base,
                **_session(sequence),
                "expected_frontier": _GENESIS,
                "event_drafts": [draft],
            }
        )
    if method is ControlMethod.CHECK:
        return CheckRequest.model_validate(
            {
                **base,
                **_session(sequence),
                "expected_frontier": _GENESIS,
                "mode": "deterministic_only",
            }
        )
    if method is ControlMethod.RESPOND:
        return RespondRequest.model_validate(
            {
                **base,
                **_session(sequence),
                "expected_frontier": _GENESIS,
                "finding_id": f"fnd_00000000-0000-4000-8000-{sequence:012x}",
                "finding_frontier": _GENESIS,
                "disposition": "acknowledged",
            }
        )
    if method is ControlMethod.STATUS:
        return StatusRequest.model_validate(
            {**base, **_session(sequence), "view": "compact", "limit": "10"}
        )
    if method is ControlMethod.RECEIPT:
        return ReceiptRequest.model_validate(
            {
                **base,
                **_session(sequence),
                "task_id": f"tsk_00000000-0000-4000-8000-{sequence:012x}",
                "expected_frontier": _GENESIS,
                "format": "json",
                "include": "standard",
                "redaction_profile": "full_local",
            }
        )
    return JsonObject({})


def call_request(sequence: int, method: ControlMethod) -> ControlCallRequest:
    """One schema-valid call frame of the scripted session."""

    return ControlCallRequest(
        kind="call",
        protocol_version="1.0",
        rpc_id=rpc_id(sequence),
        service_instance_id=SERVICE_ID,
        service_generation="1",
        method=method,
        body=_body(sequence, method),  # pyright: ignore[reportArgumentType]
    )


async def _read_payload(stream: ControlStream) -> bytes:
    return _payload(await read_control_frame(stream, eof_reason="handshake_rejected"))


async def run_scripted_session(stream: ControlStream, *, agent: bool = True) -> list[bytes]:
    """Drive the fixed session over ``stream``; return every payload the client received.

    Bodies are empty objects: the scripted daemon answers by method alone, so no workflow body
    shape is involved and only framing, routing and correlation are under test.
    """

    received: list[bytes] = []
    await stream.send_all(encode_control_frame(_hello(agent=agent)))
    received.append(await _read_payload(stream))
    for index, method in enumerate(AGENT_METHODS):
        await stream.send_all(encode_control_frame(call_request(0x5100 + index, method)))
        if agent and index == 0:
            # The result and the server's workspace call may arrive in either order on a
            # transport that relays them on separate requests; record them result first.
            first, second = await _read_payload(stream), await _read_payload(stream)
            received.extend(
                sorted((first, second), key=lambda payload: b"workspace_call" in payload)
            )
            reply: dict[str, JsonValue] = {
                "kind": "workspace_reply",
                "protocol_version": "1.0",
                "call_id": _CALL_ID,
                "outcome": "unavailable",
                "result": None,
                "reason": "not_git",
            }
            await stream.send_all(encode_control_frame(reply))
        else:
            received.append(await _read_payload(stream))
    slow = call_request(0x51F0, SLOW_METHOD)
    await stream.send_all(encode_control_frame(slow))
    cancel: dict[str, JsonValue] = {
        "kind": "cancel",
        "protocol_version": "1.0",
        "rpc_id": rpc_id(0x5200),
        "service_instance_id": SERVICE_ID,
        "service_generation": "1",
        "target_rpc_id": rpc_id(0x51F0),
    }
    await asyncio.sleep(0)
    await stream.send_all(encode_control_frame(cancel))
    received.append(await _read_payload(stream))
    return received


_FAKE_SSH: Final = r"""
import os, socket, subprocess, sys, threading

def pump(a, b):
    try:
        while True:
            data = a.recv(65536)
            if not data:
                break
            b.sendall(data)
    except OSError:
        pass
    finally:
        try:
            b.shutdown(socket.SHUT_WR)
        except OSError:
            pass

def option(args, flag):
    return args[args.index(flag) + 1] if flag in args else None

args = sys.argv[1:]
control = option(args, "-S")
log = os.environ.get("FAKE_SSH_LOG")
if log:
    with open(log, "a") as handle:
        handle.write(" ".join(args) + "\n")
if "-O" in args:
    command = option(args, "-O")
    try:
        client = socket.socket(socket.AF_UNIX)
        client.connect(control)
        client.sendall(command.encode())
        client.close()
    except OSError:
        sys.exit(255)
    sys.exit(0)
if "-M" in args:
    local, remote = option(args, "-L").split(":", 1)
    os.umask(0o177)
    for path in (local, control):
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
    listener = socket.socket(socket.AF_UNIX)
    listener.bind(local)
    listener.listen(16)
    master = socket.socket(socket.AF_UNIX)
    master.bind(control)
    master.listen(4)

    def serve_control():
        while True:
            conn, _ = master.accept()
            if conn.recv(16) == b"exit":
                # Like OpenSSH: the control socket is removed, the -L forward is left behind.
                try:
                    os.unlink(control)
                except FileNotFoundError:
                    pass
                os._exit(0)
            conn.close()

    threading.Thread(target=serve_control, daemon=True).start()
    while True:
        conn, _ = listener.accept()
        upstream = socket.socket(socket.AF_UNIX)
        try:
            upstream.connect(remote)
        except OSError:
            conn.close()
            continue
        threading.Thread(target=pump, args=(conn, upstream), daemon=True).start()
        threading.Thread(target=pump, args=(upstream, conn), daemon=True).start()
command = args[-1]
sys.exit(subprocess.call(["/bin/sh", "-c", command]))
"""


async def serve_unix(path: Path, daemon: ScriptedDaemon) -> asyncio.Task[None]:
    """Serve ``daemon`` on an owner-only Unix socket at ``path`` (until the task is cancelled)."""

    import os
    import socket

    from finishup.adapters.control.unix_socket import AuthenticatedUnixStream, authenticate_peer

    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    previous = os.umask(0o177)
    try:
        listener.bind(str(path))
    finally:
        os.umask(previous)
    listener.listen(16)
    listener.setblocking(False)
    loop = asyncio.get_running_loop()
    connections: set[asyncio.Task[None]] = set()

    async def accept() -> None:
        try:
            while True:
                accepted, _address = await loop.sock_accept(listener)
                stream = AuthenticatedUnixStream(accepted, authenticate_peer(accepted))
                task = asyncio.create_task(daemon.serve(stream))
                connections.add(task)
                task.add_done_callback(connections.discard)
        finally:
            for task in tuple(connections):
                task.cancel()
            await asyncio.gather(*connections, return_exceptions=True)
            listener.close()
            with contextlib.suppress(FileNotFoundError):
                path.unlink()

    return asyncio.create_task(accept())


def write_fake_ssh(directory: Path) -> Path:
    """Write the ``ssh`` stand-in into ``directory`` (put it first on ``PATH``)."""

    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = directory / "ssh"
    path.write_text(f"#!{sys.executable}\n{_FAKE_SSH}", encoding="utf-8")
    path.chmod(0o700)
    return path


def frame_bytes(payload: bytes) -> bytes:
    """A payload with its 4-byte big-endian length prefix."""

    return struct.pack(">I", len(payload)) + payload


def as_json(payload: bytes) -> dict[str, JsonValue]:
    import json

    return cast(dict[str, JsonValue], json.loads(payload))


def canonical(value: dict[str, JsonValue]) -> bytes:
    return canonical_encode(value)
