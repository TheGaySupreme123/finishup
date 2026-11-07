"""The ordinary client serves workspace calls only on a claim-bound connection that declared an agent.

Without an agent the client is unchanged: a ``workspace_call`` frame is still a protocol fault.
With one, each call is answered in a bounded set of daemon worker threads and written back under
the write lock, beside the connection's own calls and results (ADR-051).
"""

from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import Buffer, Callable
from pathlib import Path
from typing import cast

import pytest

from finishup.adapters.control.unix_socket import AuthenticatedUnixStream
from finishup.domain.values import JsonObject
from finishup.ports.control import (
    ControlClientKind,
    ControlError,
    ControlMethod,
    ControlResult,
    ServiceState,
    ServiceStatus,
    WorkspaceAgentDeclaration,
    WorkspaceCall,
    WorkspaceClaim,
    WorkspaceLocator,
    WorkspaceReply,
)
from finishup.protocol.ids import IdKind, new_id
from finishup.service import client as client_module
from finishup.service.client import (
    ClientWorkspaceBinding,
    ServiceClient,
    connect_service,
    connect_service_on_demand,
)
from finishup.service.control_protocol import (
    ControlSession,
    decode_control_frame,
    encode_control_frame,
    parse_workspace_reply,
    workspace_call_frame,
)

_SERVICE_ID = "svc_00000000-0000-4000-8000-000000000001"
_HANDLE = "client:0123456789abcdef"
_CLAIM = WorkspaceClaim(
    identity_kind="git_common_root", digest="sha256:" + "ab" * 32, worktree="sha256:" + "cd" * 32
)
_WAIT_SECONDS = 10.0


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class _FakeStream:
    def __init__(self) -> None:
        self.peer_identity = object()
        self.sent: list[bytes] = []
        self._incoming = bytearray()
        self._ready = asyncio.Condition()
        self.closed = False

    async def receive(self, max_bytes: int) -> bytes:
        async with self._ready:
            await self._ready.wait_for(lambda: bool(self._incoming) or self.closed)
            if not self._incoming:
                return b""
            size = min(max_bytes, len(self._incoming))
            result = bytes(self._incoming[:size])
            del self._incoming[:size]
            return result

    async def send_all(self, data: Buffer) -> None:
        self.sent.append(bytes(data))

    async def aclose(self) -> None:
        async with self._ready:
            self.closed = True
            self._ready.notify_all()

    async def feed(self, data: bytes) -> None:
        async with self._ready:
            self._incoming.extend(data)
            self._ready.notify_all()


class _Agent:
    """A stand-in handler: records what it was asked and answers from ``reply``."""

    def __init__(
        self,
        *,
        max_reply_bytes: int = 6_291_456,
        gate: threading.Event | None = None,
        reply: Callable[[WorkspaceCall], WorkspaceReply] | None = None,
    ) -> None:
        self.declaration = WorkspaceAgentDeclaration(("capture", "read_task_base"), max_reply_bytes)
        self.gate = gate
        self.reply = reply
        self.calls: list[tuple[str, str | None]] = []
        self.finished = 0
        self._guard = threading.Lock()

    def answer(self, call: WorkspaceCall, *, workspace_handle: str | None) -> WorkspaceReply:
        with self._guard:
            self.calls.append((call.call_id, workspace_handle))
        try:
            if self.gate is not None and not self.gate.wait(timeout=_WAIT_SECONDS):
                raise RuntimeError("test_gate_never_opened")
            if self.reply is not None:
                return self.reply(call)
            return WorkspaceReply("workspace_reply", "1.0", call.call_id, "ok", {"n": 1}, None)
        finally:
            with self._guard:
                self.finished += 1


def _session(
    stream: _FakeStream,
    *,
    agent: _Agent | None = None,
    claim_bound: bool = True,
) -> ControlSession:
    return ControlSession(
        protocol_version="1.0",
        client_kind=ControlClientKind.CLI,
        service_instance_id=_SERVICE_ID,
        service_generation="1",
        allowed_methods=tuple(sorted(ControlMethod, key=lambda method: method.value.encode())),
        peer_identity=stream.peer_identity,
        connection_nonce="0" * 64,
        workspace_binding="client_claim" if claim_bound else "none",
        workspace_handle=_HANDLE if claim_bound else None,
        workspace_agent=None if agent is None else agent.declaration,
    )


def _client(
    stream: _FakeStream, agent: _Agent | None, *, claim_bound: bool = True
) -> ServiceClient:
    factory = client_module._connected_client  # pyright: ignore[reportPrivateUsage]
    return factory(
        cast(AuthenticatedUnixStream, stream),
        _session(stream, agent=agent, claim_bound=claim_bound),
        ControlClientKind.CLI,
        agent,
    )


def _call(
    *, deadline_ms: int = 30_000, generation: str = "1", call_id: str | None = None
) -> WorkspaceCall:
    return WorkspaceCall(
        kind="workspace_call",
        protocol_version="1.0",
        call_id=call_id or new_id(IdKind.CONTROL_RPC),
        service_instance_id=_SERVICE_ID,
        service_generation=generation,
        operation="read_task_base",
        arguments=JsonObject({"workspace": _HANDLE}),
        deadline_ms=deadline_ms,
    )


async def _feed_call(stream: _FakeStream, call: WorkspaceCall) -> None:
    await stream.feed(encode_control_frame(workspace_call_frame(call)))


async def _until(condition: Callable[[], bool]) -> None:
    """A bounded wait on observed state: fails at the deadline, never infers from elapsed time."""

    deadline = time.monotonic() + _WAIT_SECONDS
    while not condition():
        if time.monotonic() > deadline:
            raise AssertionError("condition_not_reached")
        await asyncio.sleep(0.001)


def _replies(stream: _FakeStream) -> list[WorkspaceReply]:
    return [
        parse_workspace_reply(frame)
        for frame in (decode_control_frame(item) for item in stream.sent)
        if frame.get("kind") == "workspace_reply"
    ]


async def _status_round_trip(stream: _FakeStream, client: ServiceClient) -> None:
    sent = len(stream.sent)
    task = asyncio.create_task(client.service_status())
    await _until(lambda: len(stream.sent) > sent)
    request = decode_control_frame(stream.sent[-1])
    await stream.feed(
        encode_control_frame(
            ControlResult(
                protocol_version="1.0",
                rpc_id=cast(str, request["rpc_id"]),
                service_instance_id=_SERVICE_ID,
                service_generation="1",
                method=ControlMethod.SERVICE_STATUS,
                outcome="ok",
                body=ServiceStatus(
                    protocol_version="1.0",
                    service_version="0.1.0",
                    service_instance_id=_SERVICE_ID,
                    service_generation="1",
                    state=ServiceState.LOCKED,
                    state_reason="human_authority_unavailable",
                    vault_mode="uninitialized",
                    capabilities=(),
                    session_monitor="unavailable",
                ),
            )
        )
    )
    status = await task
    assert status.service_instance_id == _SERVICE_ID


@pytest.mark.anyio
async def test_without_an_agent_a_workspace_call_is_still_a_protocol_fault() -> None:
    stream = _FakeStream()
    client = _client(stream, None, claim_bound=False)
    pending = asyncio.create_task(client.service_status())
    await _until(lambda: len(stream.sent) == 1)
    await _feed_call(stream, _call())
    with pytest.raises(ControlError) as raised:
        await pending
    assert raised.value.reason == "frame_invalid"
    assert len(stream.sent) == 1  # nothing was answered
    assert client.workspace_binding == "none" and client.workspace_handle is None


@pytest.mark.anyio
async def test_a_declared_agent_answers_beside_ordinary_results() -> None:
    stream = _FakeStream()
    agent = _Agent()
    client = _client(stream, agent)
    assert client.workspace_binding == "client_claim"
    assert client.workspace_handle == _HANDLE

    call = _call()
    await _feed_call(stream, call)
    await _until(lambda: len(_replies(stream)) == 1)
    (reply,) = _replies(stream)
    assert (reply.call_id, reply.outcome, reply.reason, reply.result) == (
        call.call_id,
        "ok",
        None,
        {"n": 1},
    )
    assert agent.calls == [(call.call_id, _HANDLE)]
    # The connection keeps serving its own calls afterwards.
    await _status_round_trip(stream, client)
    await client.close()


@pytest.mark.anyio
async def test_a_call_from_another_generation_fails_the_connection() -> None:
    stream = _FakeStream()
    agent = _Agent()
    client = _client(stream, agent)
    pending = asyncio.create_task(client.service_status())
    await _until(lambda: len(stream.sent) == 1)
    await _feed_call(stream, _call(generation="2"))
    with pytest.raises(ControlError) as raised:
        await pending
    assert raised.value.reason == "service_unavailable" and raised.value.retryable
    assert agent.calls == []


@pytest.mark.anyio
async def test_a_repeated_call_id_in_flight_fails_the_connection() -> None:
    stream = _FakeStream()
    gate = threading.Event()
    agent = _Agent(gate=gate)
    client = _client(stream, agent)
    call = _call()
    pending = asyncio.create_task(client.service_status())
    await _until(lambda: len(stream.sent) == 1)
    await _feed_call(stream, call)
    await _until(lambda: len(agent.calls) == 1)
    await _feed_call(stream, call)
    with pytest.raises(ControlError) as raised:
        await pending
    assert raised.value.reason == "frame_invalid"
    gate.set()
    await _until(lambda: agent.finished == 1)
    assert _replies(stream) == []  # a closed connection answers nothing


@pytest.mark.anyio
async def test_calls_beyond_the_bound_are_answered_busy_at_once() -> None:
    stream = _FakeStream()
    gate = threading.Event()
    agent = _Agent(gate=gate)
    client = _client(stream, agent)
    held = [_call() for _ in range(4)]
    for call in held:
        await _feed_call(stream, call)
    await _until(lambda: len(agent.calls) == 4)
    extra = _call()
    await _feed_call(stream, extra)
    await _until(lambda: len(_replies(stream)) == 1)
    (busy,) = _replies(stream)
    assert (busy.call_id, busy.outcome, busy.reason) == (extra.call_id, "unavailable", "agent_busy")
    gate.set()
    await _until(lambda: len(_replies(stream)) == 5)
    assert {reply.call_id for reply in _replies(stream)[1:]} == {call.call_id for call in held}
    assert all(reply.outcome == "ok" for reply in _replies(stream)[1:])
    await client.close()


@pytest.mark.anyio
async def test_a_call_past_its_deadline_is_answered_once_and_keeps_its_slot() -> None:
    stream = _FakeStream()
    gate = threading.Event()
    agent = _Agent(gate=gate)
    client = _client(stream, agent)
    late = _call(deadline_ms=20)
    await _feed_call(stream, late)
    await _until(lambda: len(_replies(stream)) == 1)
    (reply,) = _replies(stream)
    assert (reply.call_id, reply.outcome, reply.reason) == (
        late.call_id,
        "unavailable",
        "deadline_exceeded",
    )
    # The worker still runs: its slot is taken until it finishes, then freed.
    assert client._agent_busy == 1  # pyright: ignore[reportPrivateUsage]
    gate.set()
    await _until(lambda: client._agent_busy == 0)  # pyright: ignore[reportPrivateUsage]
    assert len(_replies(stream)) == 1  # no second answer for the same call
    await client.close()


@pytest.mark.anyio
async def test_a_raising_agent_is_one_closed_failure() -> None:
    def explode(_call: WorkspaceCall) -> WorkspaceReply:
        raise RuntimeError("cannot read /srv/dev/secret.txt")

    stream = _FakeStream()
    client = _client(stream, _Agent(reply=explode))
    call = _call()
    await _feed_call(stream, call)
    await _until(lambda: len(_replies(stream)) == 1)
    (reply,) = _replies(stream)
    assert (reply.outcome, reply.reason, reply.result) == ("failed", "internal_error", None)
    assert b"secret" not in b"".join(stream.sent)
    await client.close()


@pytest.mark.anyio
async def test_a_reply_for_another_call_is_a_closed_failure() -> None:
    def misaddressed(_call: WorkspaceCall) -> WorkspaceReply:
        return WorkspaceReply(
            "workspace_reply", "1.0", new_id(IdKind.CONTROL_RPC), "ok", None, None
        )

    stream = _FakeStream()
    client = _client(stream, _Agent(reply=misaddressed))
    call = _call()
    await _feed_call(stream, call)
    await _until(lambda: len(_replies(stream)) == 1)
    (reply,) = _replies(stream)
    assert (reply.call_id, reply.outcome, reply.reason) == (
        call.call_id,
        "failed",
        "internal_error",
    )
    await client.close()


@pytest.mark.anyio
async def test_a_reply_above_the_declared_bound_becomes_result_too_large() -> None:
    def large(call: WorkspaceCall) -> WorkspaceReply:
        return WorkspaceReply("workspace_reply", "1.0", call.call_id, "ok", "x" * 4_096, None)

    stream = _FakeStream()
    client = _client(stream, _Agent(max_reply_bytes=1_024, reply=large))
    call = _call()
    await _feed_call(stream, call)
    await _until(lambda: len(_replies(stream)) == 1)
    (reply,) = _replies(stream)
    assert (reply.outcome, reply.reason) == ("unavailable", "result_too_large")
    await client.close()


@pytest.mark.anyio
async def test_closing_drops_unanswered_calls_without_a_reply() -> None:
    stream = _FakeStream()
    gate = threading.Event()
    agent = _Agent(gate=gate)
    client = _client(stream, agent)
    await _feed_call(stream, _call())
    await _until(lambda: len(agent.calls) == 1)
    await client.close()
    gate.set()
    await _until(lambda: agent.finished == 1)
    assert _replies(stream) == []


def test_an_agent_needs_the_claim_bound_session_that_declared_it() -> None:
    stream = _FakeStream()
    agent = _Agent()
    factory = client_module._connected_client  # pyright: ignore[reportPrivateUsage]
    for session in (
        _session(stream, agent=None),
        _session(stream, agent=None, claim_bound=False),
        _session(stream, agent=_Agent(max_reply_bytes=1)),
    ):
        with pytest.raises(ValueError, match="workspace_agent_invalid"):
            factory(cast(AuthenticatedUnixStream, stream), session, ControlClientKind.CLI, agent)


def test_a_binding_holds_a_claim_and_optionally_an_agent() -> None:
    assert ClientWorkspaceBinding(_CLAIM).agent is None
    with pytest.raises(TypeError, match="workspace_claim_invalid"):
        ClientWorkspaceBinding(cast(WorkspaceClaim, "sha256:" + "ab" * 32))
    broken = _Agent()
    broken.declaration = cast(WorkspaceAgentDeclaration, object())
    with pytest.raises(TypeError, match="workspace_agent_invalid"):
        ClientWorkspaceBinding(_CLAIM, broken)


@pytest.mark.anyio
async def test_a_hello_names_a_path_or_a_claim_never_both() -> None:
    binding = ClientWorkspaceBinding(_CLAIM)
    locator = WorkspaceLocator("/srv/dev/project")
    for connect in (connect_service, connect_service_on_demand):
        with pytest.raises(ValueError, match="workspace_binding_conflict"):
            await connect(
                ControlClientKind.CLI, workspace_locator=locator, workspace_binding=binding
            )
        with pytest.raises(TypeError, match="workspace_binding_invalid"):
            await connect(
                ControlClientKind.CLI,
                workspace_binding=cast(ClientWorkspaceBinding, _CLAIM),
            )


@pytest.mark.anyio
async def test_the_attempt_sends_the_claim_and_declares_the_agent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stream = _FakeStream()
    agent = _Agent()
    seen: list[dict[str, object]] = []

    async def connect() -> AuthenticatedUnixStream:
        return cast(AuthenticatedUnixStream, stream)

    async def handshake(*_args: object, **kwargs: object) -> ControlSession:
        seen.append(kwargs)
        return _session(stream, agent=agent if kwargs["workspace_agent"] is not None else None)

    monkeypatch.setattr(client_module, "connect_control", connect)
    monkeypatch.setattr(client_module, "client_handshake", handshake)

    bound = await connect_service(
        ControlClientKind.CLI, workspace_binding=ClientWorkspaceBinding(_CLAIM, agent)
    )
    assert seen[-1]["workspace_locator"] is None
    assert seen[-1]["workspace_claim"] is _CLAIM
    assert seen[-1]["workspace_agent"] == agent.declaration
    call = _call()
    await _feed_call(stream, call)
    await _until(lambda: len(_replies(stream)) == 1)
    await bound.close()

    plain = await connect_service(
        ControlClientKind.CLI, workspace_binding=ClientWorkspaceBinding(_CLAIM)
    )
    assert seen[-1]["workspace_claim"] is _CLAIM and seen[-1]["workspace_agent"] is None
    await plain.close()

    legacy = await connect_service(ControlClientKind.CLI)
    assert seen[-1]["workspace_claim"] is None and seen[-1]["workspace_agent"] is None
    await legacy.close()


@pytest.mark.anyio
async def test_on_demand_connections_carry_the_binding_on_every_attempt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = ClientWorkspaceBinding(_CLAIM)
    attempts: list[object] = []
    expected = object()

    async def attempt(_kind: ControlClientKind, **kwargs: object) -> object:
        attempts.append(kwargs["workspace_binding"])
        return expected

    monkeypatch.setattr(client_module, "_connect_service_attempt", attempt)
    connected = await connect_service_on_demand(
        ControlClientKind.CLI, workspace_binding=binding, supersede_incompatible=False
    )
    assert connected is expected
    assert attempts == [binding]


@pytest.mark.anyio
async def test_agent_work_runs_in_daemon_threads() -> None:
    """A worker never keeps a finished process open: it is a daemon thread (ADR-051)."""

    seen: list[bool] = []

    def record(call: WorkspaceCall) -> WorkspaceReply:
        seen.append(threading.current_thread().daemon)
        return WorkspaceReply("workspace_reply", "1.0", call.call_id, "ok", {"n": 1}, None)

    stream = _FakeStream()
    client = _client(stream, _Agent(reply=record))
    await _feed_call(stream, _call())
    await _until(lambda: len(_replies(stream)) == 1)
    assert seen == [True]
    await client.close()


# A CLI-shaped process: its connection carries an agent, a long workspace call arrives, the command
# ends and closes the connection. The process must exit then, not when the call's work finishes.
_SHORT_LIVED_CLI = """
import asyncio, sys, threading, time
from typing import cast
from finishup.adapters.control.unix_socket import AuthenticatedUnixStream
from finishup.domain.values import JsonObject
from finishup.ports.control import (
    ControlClientKind, ControlMethod, WorkspaceAgentDeclaration, WorkspaceCall, WorkspaceReply,
)
from finishup.protocol.ids import IdKind, new_id
from finishup.service import client as client_module
from finishup.service.control_protocol import (
    ControlSession, encode_control_frame, workspace_call_frame,
)

HANDLE = "client:0123456789abcdef"
SERVICE = "svc_00000000-0000-4000-8000-000000000001"
started = threading.Event()

class Stream:
    peer_identity = object()
    def __init__(self):
        self.buffer = bytearray()
        self.closed = False
        self.ready = asyncio.Event()
    def feed(self, data):
        self.buffer.extend(data)
        self.ready.set()
    async def receive(self, max_bytes):
        while not self.buffer and not self.closed:
            self.ready.clear()
            await self.ready.wait()
        chunk = bytes(self.buffer[:max_bytes])
        del self.buffer[:max_bytes]
        return chunk
    async def send_all(self, data):
        return None
    async def aclose(self):
        self.closed = True
        self.ready.set()

class Agent:
    declaration = WorkspaceAgentDeclaration(("read_task_base",), 6_291_456)
    def answer(self, call, *, workspace_handle):
        started.set()
        threading.Event().wait(120)  # a long approved check or capture
        return WorkspaceReply("workspace_reply", "1.0", call.call_id, "ok", {}, None)

async def main():
    stream = Stream()
    agent = Agent()
    session = ControlSession(
        protocol_version="1.0", client_kind=ControlClientKind.CLI, service_instance_id=SERVICE,
        service_generation="1",
        allowed_methods=tuple(sorted(ControlMethod, key=lambda m: m.value.encode())),
        peer_identity=stream.peer_identity, connection_nonce="0" * 64,
        workspace_binding="client_claim", workspace_handle=HANDLE,
        workspace_agent=agent.declaration,
    )
    client = client_module._connected_client(
        cast(AuthenticatedUnixStream, stream), session, ControlClientKind.CLI, agent
    )
    call = WorkspaceCall(
        kind="workspace_call", protocol_version="1.0", call_id=new_id(IdKind.CONTROL_RPC),
        service_instance_id=SERVICE, service_generation="1", operation="read_task_base",
        arguments=JsonObject({"workspace": HANDLE}), deadline_ms=300_000,
    )
    stream.feed(encode_control_frame(workspace_call_frame(call)))
    while not started.is_set():
        await asyncio.sleep(0.005)
    await client.close()

asyncio.run(main())
print("closed", flush=True)
"""


def test_a_short_lived_cli_exits_without_waiting_for_agent_work(tmp_path: Path) -> None:
    import subprocess
    import sys

    script = tmp_path / "short_lived_cli.py"
    script.write_text(_SHORT_LIVED_CLI, encoding="utf-8")
    started = time.monotonic()
    completed = subprocess.run(  # noqa: S603 - fixed interpreter and a test-owned script
        (sys.executable, "-I", str(script)),
        capture_output=True,
        timeout=60,  # far below the 120 s the agent's work would take
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == b"closed\n"
    assert time.monotonic() - started < 60
