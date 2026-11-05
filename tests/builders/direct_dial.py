"""Test doubles for the direct-dial transports (ADR-051, approach B).

* ``memory_pair`` — two in-memory ``ControlStream`` ends.
* ``TapStream`` — wraps a stream and records every byte it sends and receives (the wire tap the
  parity tests compare across transports).
* ``scripted_server`` / ``scripted_client`` — one deterministic control session: a claim-bound
  hello that declares a workspace agent, two calls, a cancel, and a server operation that sends a
  ``workspace_call`` and waits for its ``workspace_reply`` before answering. With the hello nonce
  pinned (``pinned_nonce``) every frame is byte-identical on every transport.
* ``FakeBindingGateway`` — an in-test ASGI app speaking HTTPS binding v1 exactly as
  ``docs/INTERFACES.md`` specifies it, relaying each session to one upstream ``ControlStream``
  (as the real gateway relays to the daemon's Unix socket). Waits are capped so the ``202`` and
  long-poll paths run in milliseconds.
* ``RELAY_SOURCE`` — a stand-in for ``ssh`` that honours ``-W <unix socket>`` by relaying its
  standard input and output to that socket, so ``SshTransport`` runs its real argv against a
  local endpoint.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import struct
from collections.abc import Awaitable, Buffer, Callable, Generator, MutableMapping
from dataclasses import dataclass, field
from typing import Any, Final, cast
from urllib.parse import parse_qs

import pytest

from finishup import __version__
from finishup.client.targets import ServerTarget
from finishup.domain.values import JsonObject
from finishup.ports.control import (
    ControlCallRequest,
    ControlCancelRequest,
    ControlClientKind,
    ControlMethod,
    ControlResult,
    RepositoryPrivacyContext,
    ServiceState,
    ServiceStatus,
    WorkspaceAgentDeclaration,
    WorkspaceCall,
    WorkspaceClaim,
    WorkspaceReply,
)
from finishup.protocol.schemas import schema_manifest_digest
from finishup.service import control_protocol
from finishup.service.control_protocol import (
    ControlStream,
    client_handshake,
    is_workspace_call_frame,
    parse_workspace_reply,
    read_control_frame,
    server_handshake,
    write_control_frame,
    write_workspace_call,
    write_workspace_reply,
)

SERVICE_ID: Final = "svc_00000000-0000-4000-8000-0000000000b1"
CALL_ID: Final = "rpc_00000000-0000-4000-8000-0000000000c1"
COMMITMENT: Final = "hmac-sha256:" + "1" * 64
HANDLE: Final = "client:" + "1" * 16
CLAIM: Final = WorkspaceClaim(identity_kind="git_common_root", digest="sha256:" + "2" * 64)
AGENT: Final = WorkspaceAgentDeclaration(("list_beneath", "read_task_base"), 1_048_576)
API_KEY: Final = "fuk_0123456789ab_" + "B" * 43
BASE_URL: Final = "https://gateway.test/base"


def rpc_id(sequence: int) -> str:
    return f"rpc_00000000-0000-4000-8000-{sequence:012x}"


def service_status() -> ServiceStatus:
    return ServiceStatus(
        protocol_version="1.0",
        service_version=__version__,
        service_instance_id=SERVICE_ID,
        service_generation="1",
        state=ServiceState.LOCKED,
        state_reason="human_authority_unavailable",
        vault_mode="uninitialized",
        capabilities=(),
        session_monitor="unavailable",
    )


def https_target(*, kind: str = "https", tls_pin: str | None = None) -> ServerTarget:
    return ServerTarget(
        "t_0b0b0b0b",
        "gw",
        "https" if kind == "https" else "local_port",
        "2026-11-05T00:00:00.000Z",
        base_url=BASE_URL if kind == "https" else "https://127.0.0.1:9443",
        tls_pin=tls_pin,
        credential="file",
        claim_salt=base64.b64encode(b"\x07" * 32).decode("ascii"),
        authorized_at="2026-11-05T00:00:00.000Z",
        disclosure_version=1,
    )


def ssh_target(*, endpoint: str = "/srv/fu/run/control.sock") -> ServerTarget:
    return ServerTarget(
        "t_0c0c0c0c",
        "lab",
        "ssh",
        "2026-11-05T00:00:00.000Z",
        user="owner",
        host="lab.example",
        port=2222,
        remote_root="/srv/fu",
        remote_endpoint=endpoint,
        remote_launcher="/opt/fu/bin/finishup",
        claim_salt=base64.b64encode(b"\x07" * 32).decode("ascii"),
        authorized_at="2026-11-05T00:00:00.000Z",
        disclosure_version=1,
    )


class StaticCredential:
    """A ``CredentialSource`` holding one key in memory."""

    def __init__(self, secret: str | None = API_KEY) -> None:
        self._secret = secret

    @property
    def target_id(self) -> str:
        return "t_0b0b0b0b"

    def location(self) -> None:
        return None

    def read(self) -> str:
        from finishup.client.credentials import CredentialError

        if self._secret is None:
            raise CredentialError("credential_unavailable")
        return self._secret

    def store(self, secret: str) -> Any:
        raise AssertionError("not stored in tests")

    def delete(self) -> bool:
        return False


class MemoryStream:
    """One end of an in-memory byte stream pair."""

    def __init__(self, peer_identity: object) -> None:
        self.peer_identity = peer_identity
        self.other: MemoryStream | None = None
        self.closed = False
        self._chunks: asyncio.Queue[bytes] = asyncio.Queue()
        self._buffer = bytearray()

    async def receive(self, max_bytes: int = 65_536) -> bytes:
        while not self._buffer:
            chunk = await self._chunks.get()
            if not chunk:
                self._chunks.put_nowait(b"")
                return b""
            self._buffer.extend(chunk)
        chunk = bytes(self._buffer[:max_bytes])
        del self._buffer[:max_bytes]
        return chunk

    async def send_all(self, data: Buffer) -> None:
        if self.closed or self.other is None or self.other.closed:
            raise ConnectionResetError("closed")
        self.other._chunks.put_nowait(bytes(data))

    async def aclose(self) -> None:
        if self.closed:
            return
        self.closed = True
        if self.other is not None:
            self.other._chunks.put_nowait(b"")
        self._chunks.put_nowait(b"")


def memory_pair() -> tuple[MemoryStream, MemoryStream]:
    """``(client end, server end)``; each end's ``peer_identity`` stands for the other side."""

    client = MemoryStream(object())
    server = MemoryStream(object())
    client.other = server
    server.other = client
    return client, server


@dataclass
class TapStream:
    """A pass-through stream that records the exact bytes in each direction."""

    inner: ControlStream
    sent: bytearray = field(default_factory=bytearray)
    received: bytearray = field(default_factory=bytearray)

    @property
    def peer_identity(self) -> object:
        return self.inner.peer_identity

    async def receive(self, max_bytes: int) -> bytes:
        chunk = await self.inner.receive(max_bytes)
        self.received.extend(chunk)
        return chunk

    async def send_all(self, data: Buffer) -> None:
        self.sent.extend(bytes(data))
        await self.inner.send_all(data)

    async def aclose(self) -> None:
        await self.inner.aclose()


@contextlib.contextmanager
def pinned_nonce(monkeypatch: pytest.MonkeyPatch) -> Generator[None]:
    """Pin the hello's connection nonce so a session's bytes are reproducible."""

    class _Secrets:
        @staticmethod
        def token_hex(_size: int) -> str:
            return "ab" * 32

    monkeypatch.setattr(control_protocol, "secrets", _Secrets)
    yield


def _status_call(sequence: int) -> ControlCallRequest:
    return ControlCallRequest(
        kind="call",
        protocol_version="1.0",
        rpc_id=rpc_id(sequence),
        service_instance_id=SERVICE_ID,
        service_generation="1",
        method=ControlMethod.SERVICE_STATUS,
        body=JsonObject({}),
    )


def _status_result(sequence: int) -> ControlResult:
    return ControlResult(
        protocol_version="1.0",
        rpc_id=rpc_id(sequence),
        service_instance_id=SERVICE_ID,
        service_generation="1",
        method=ControlMethod.SERVICE_STATUS,
        outcome="ok",
        body=service_status(),
    )


WORKSPACE_CALL: Final = WorkspaceCall(
    kind="workspace_call",
    protocol_version="1.0",
    call_id=CALL_ID,
    service_instance_id=SERVICE_ID,
    service_generation="1",
    operation="read_task_base",
    arguments=JsonObject({"workspace": HANDLE}),
    deadline_ms=5_000,
)
WORKSPACE_REPLY: Final = WorkspaceReply(
    kind="workspace_reply",
    protocol_version="1.0",
    call_id=CALL_ID,
    outcome="unavailable",
    result=None,
    reason="workspace_unavailable",
)


@dataclass
class ServerTranscript:
    """What the scripted server observed: frames in arrival order, and the reply it got."""

    kinds: list[str] = field(default_factory=list[str])
    reply: WorkspaceReply | None = None
    handle: str | None = None


async def scripted_server(stream: ControlStream, peer: object) -> ServerTranscript:
    """Serve the scripted session: answer calls 1, 2 (after its cancel) and 4 (after the reply)."""

    async def resolve(_claim: WorkspaceClaim) -> RepositoryPrivacyContext:
        return RepositoryPrivacyContext(COMMITMENT, "client_claim")

    transcript = ServerTranscript()
    session = await server_handshake(stream, peer, service_status(), claim_context_resolver=resolve)
    transcript.handle = session.workspace_handle
    while True:
        try:
            frame = await read_control_frame(stream, eof_reason="session_closed")
        except control_protocol.ControlProtocolError:
            return transcript
        kind = cast(str, frame["kind"])
        transcript.kinds.append(kind)
        if kind == "workspace_reply":
            transcript.reply = parse_workspace_reply(frame)
            await write_control_frame(stream, _status_result(4))
            continue
        request = control_protocol.parse_control_request(frame)
        if isinstance(request, ControlCancelRequest):
            await write_control_frame(stream, _status_result(2))
            continue
        if request.rpc_id == rpc_id(1):
            await write_control_frame(stream, _status_result(1))
        elif request.rpc_id == rpc_id(4):
            await write_workspace_call(stream, WORKSPACE_CALL)


async def scripted_client(stream: ControlStream) -> list[str]:
    """Drive the scripted session; returns the kinds of the frames it read, in order."""

    session = await client_handshake(
        stream, ControlClientKind.CLI, __version__, workspace_claim=CLAIM, workspace_agent=AGENT
    )
    assert session.workspace_handle == HANDLE
    seen: list[str] = []

    async def read() -> str:
        frame = await read_control_frame(stream)
        kind = "workspace_call" if is_workspace_call_frame(frame) else f"result:{frame['rpc_id']}"
        seen.append(kind)
        return kind

    await write_control_frame(stream, _status_call(1))
    assert await read() == f"result:{rpc_id(1)}"
    await write_control_frame(stream, _status_call(2))
    await write_control_frame(
        stream,
        ControlCancelRequest(
            kind="cancel",
            protocol_version="1.0",
            rpc_id=rpc_id(3),
            service_instance_id=SERVICE_ID,
            service_generation="1",
            target_rpc_id=rpc_id(2),
        ),
    )
    assert await read() == f"result:{rpc_id(2)}"
    await write_control_frame(stream, _status_call(4))
    assert await read() == "workspace_call"
    await write_workspace_reply(stream, WORKSPACE_REPLY)
    assert await read() == f"result:{rpc_id(4)}"
    return seen


def frames(data: bytes) -> list[bytes]:
    """Split a recorded byte stream into its frame payloads (length prefixes removed)."""

    payloads: list[bytes] = []
    offset = 0
    while offset < len(data):
        (size,) = struct.unpack(">I", data[offset : offset + 4])
        payloads.append(bytes(data[offset + 4 : offset + 4 + size]))
        offset += 4 + size
    return payloads


# -- the in-test HTTPS binding v1 gateway ------------------------------------------------------


async def _read_frame_payload(stream: ControlStream) -> bytes:
    prefix = bytearray()
    while len(prefix) < 4:
        chunk = await stream.receive(4 - len(prefix))
        if not chunk:
            raise EOFError
        prefix.extend(chunk)
    (size,) = struct.unpack(">I", bytes(prefix))
    payload = bytearray()
    while len(payload) < size:
        chunk = await stream.receive(min(65_536, size - len(payload)))
        if not chunk:
            raise EOFError
        payload.extend(chunk)
    return bytes(payload)


type _Send = Callable[[MutableMapping[str, Any]], Awaitable[None]]


@dataclass
class _Session:
    upstream: ControlStream
    results: dict[str, bytes] = field(default_factory=dict[str, bytes])
    arrived: asyncio.Condition = field(default_factory=asyncio.Condition)
    frames: asyncio.Queue[bytes] = field(default_factory=asyncio.Queue[bytes])
    reader: asyncio.Task[None] | None = None
    closed: bool = False


@dataclass
class FakeBindingGateway:
    """HTTPS binding v1 over upstream control streams, as an ASGI app for ``httpx``."""

    upstream: Callable[[], Awaitable[ControlStream]]
    key: str = API_KEY
    base_path: str = "/base"
    wait_cap_ms: int = 100
    statuses: dict[str, int] = field(default_factory=dict[str, int])
    requests: list[tuple[str, str, frozenset[str]]] = field(
        default_factory=list[tuple[str, str, frozenset[str]]]
    )
    sessions: dict[str, _Session] = field(default_factory=dict[str, _Session])
    digest: str = field(default_factory=schema_manifest_digest)

    async def _reply(
        self,
        send: _Send,
        status: int,
        body: bytes = b"",
        headers: tuple[tuple[bytes, bytes], ...] = (),
    ) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [(b"content-type", b"application/json"), *headers],
            }
        )
        await send({"type": "http.response.body", "body": body})

    async def _error(self, send: _Send, status: int, reason: str) -> None:
        body = json.dumps({"reason": reason, "schema_version": "1.0.0"}, separators=(",", ":"))
        await self._reply(send, status, body.encode("ascii"))

    async def _route_upstream(self, session: _Session) -> None:
        try:
            while True:
                payload = await _read_frame_payload(session.upstream)
                frame = json.loads(payload)
                if frame.get("kind") == "workspace_call":
                    await session.frames.put(payload)
                else:
                    async with session.arrived:
                        session.results[frame["rpc_id"]] = payload
                        session.arrived.notify_all()
        except (EOFError, OSError, ConnectionError):
            # The daemon closed this session's connection: the session ends, and every later
            # request on it is ``404 session_unknown``.
            session.closed = True
            session.frames.put_nowait(b"")
            async with session.arrived:
                session.arrived.notify_all()

    async def _wait_result(self, session: _Session, rpc: str, wait_ms: int) -> bytes | None:
        seconds = min(wait_ms, self.wait_cap_ms) / 1_000
        try:
            async with asyncio.timeout(seconds):
                async with session.arrived:
                    await session.arrived.wait_for(lambda: rpc in session.results or session.closed)
        except TimeoutError:
            return None
        if rpc not in session.results:
            return None
        # Kept after delivery, as the binding requires: a client whose response was lost asks
        # for the same result again instead of posting the call twice.
        return session.results[rpc]

    async def __call__(
        self,
        scope: MutableMapping[str, Any],
        receive: Callable[[], Awaitable[MutableMapping[str, Any]]],
        send: _Send,
    ) -> None:
        assert scope["type"] == "http"
        method = cast(str, scope["method"])
        path = cast(str, scope["path"])
        headers = {
            bytes(name).decode("latin-1").lower(): bytes(value).decode("latin-1")
            for name, value in scope["headers"]
        }
        self.requests.append((method, path, frozenset(headers)))
        body = b""
        while True:
            message = await receive()
            body += message.get("body", b"")
            if not message.get("more_body"):
                break
        query = parse_qs(cast(bytes, scope.get("query_string", b"")).decode("ascii"))
        wait_ms = int(query.get("wait_ms", ["0"])[0])
        if "origin" in headers:
            return await self._error(send, 403, "origin_forbidden")
        if headers.get("authorization") != f"Bearer {self.key}":
            return await self._error(send, 401, "api_key_invalid")
        if headers.get("finishup-binding") != "1.0" or not path.startswith(self.base_path):
            return await self._error(send, 400, "frame_invalid")
        route = path[len(self.base_path) :]
        parts = route.split("/")
        # ``statuses`` answers one request per entry with that status instead of serving it,
        # keyed by method and route name: ``POST sessions``, ``POST calls``, ``GET results``,
        # ``POST cancel``, ``POST frames``, ``GET frames``, ``GET server``.
        name = parts[-2] if len(parts) == 6 else parts[-1]
        override = self.statuses.pop(f"{method} {name}", None)
        if override is not None:
            reason = {401: "api_key_invalid", 404: "session_unknown"}.get(
                override, "service_unavailable"
            )
            return await self._error(send, override, reason)
        if (method, route) == ("GET", "/v1/server"):
            info = {
                "release": __version__,
                "schema_manifest_digest": self.digest,
                "schema_version": "1.0.0",
            }
            return await self._reply(send, 200, json.dumps(info).encode("ascii"))
        if (method, route) == ("POST", "/v1/sessions"):
            if b"workspace_locator" in body:
                return await self._error(send, 403, "workspace_locator_forbidden")
            upstream = await self.upstream()
            await upstream.send_all(struct.pack(">I", len(body)) + body)
            hello_result = await _read_frame_payload(upstream)
            sid = f"s{len(self.sessions):031d}"
            session = _Session(upstream)
            session.reader = asyncio.create_task(self._route_upstream(session))
            self.sessions[sid] = session
            location = f"{self.base_path}/v1/sessions/{sid}".encode("ascii")
            return await self._reply(send, 201, hello_result, ((b"location", location),))
        if len(parts) < 4 or parts[1:3] != ["v1", "sessions"] or parts[3] not in self.sessions:
            return await self._error(send, 404, "session_unknown")
        session = self.sessions[parts[3]]
        tail = parts[4:]
        if session.closed and method != "DELETE":
            return await self._error(send, 404, "session_unknown")
        if method == "DELETE" and not tail:
            del self.sessions[parts[3]]
            await session.upstream.aclose()
            if session.reader is not None:
                session.reader.cancel()
            return await self._reply(send, 204)
        if method == "POST" and tail == ["calls"]:
            await session.upstream.send_all(struct.pack(">I", len(body)) + body)
            result = await self._wait_result(session, json.loads(body)["rpc_id"], wait_ms)
            return await self._reply(send, 202 if result is None else 200, result or b"")
        if method == "GET" and len(tail) == 2 and tail[0] == "results":
            result = await self._wait_result(session, tail[1], wait_ms)
            return await self._reply(send, 202 if result is None else 200, result or b"")
        if method == "POST" and tail in (["cancel"], ["frames"]):
            await session.upstream.send_all(struct.pack(">I", len(body)) + body)
            return await self._reply(send, 202)
        if method == "GET" and tail == ["frames"]:
            try:
                async with asyncio.timeout(min(wait_ms, self.wait_cap_ms) / 1_000):
                    frame = await session.frames.get()
            except TimeoutError:
                return await self._reply(send, 204)
            if not frame:
                return await self._error(send, 404, "session_unknown")
            return await self._reply(send, 200, frame)
        return await self._error(send, 404, "session_unknown")


# -- a stand-in for ssh: relay standard input and output to the -W unix socket ----------------

RELAY_SOURCE: Final = """\
import os, socket, sys, threading
arguments = sys.argv[1:]
with open(os.environ["FU_RELAY_LOG"], "a", encoding="utf-8") as log:
    log.write(" ".join(arguments) + "\\n")
path = arguments[arguments.index("-W") + 1]
connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    connection.connect(path)
except OSError:
    sys.stderr.write("channel 0: open failed: connect failed\\n")
    sys.stderr.write("Stdio forwarding request failed: Session open refused by peer\\n")
    sys.exit(255)

def pump_in():
    while True:
        data = os.read(0, 65536)
        if not data:
            connection.shutdown(socket.SHUT_WR)
            return
        connection.sendall(data)

threading.Thread(target=pump_in, daemon=True).start()
while True:
    data = connection.recv(65536)
    if not data:
        break
    os.write(1, data)
"""


__all__ = [
    "AGENT",
    "API_KEY",
    "BASE_URL",
    "CALL_ID",
    "CLAIM",
    "COMMITMENT",
    "HANDLE",
    "RELAY_SOURCE",
    "SERVICE_ID",
    "WORKSPACE_CALL",
    "WORKSPACE_REPLY",
    "FakeBindingGateway",
    "MemoryStream",
    "ServerTranscript",
    "StaticCredential",
    "TapStream",
    "frames",
    "https_target",
    "memory_pair",
    "pinned_nonce",
    "rpc_id",
    "scripted_client",
    "scripted_server",
    "service_status",
    "ssh_target",
]
