"""The pull-based workspace agent (``finishup agent run``, ADR-051 server-native approach).

A ``workspace_call`` the service's hub sends reaches the agent through ``GET
/v1/agents/{id}/work``, the agent answers it with the workspace's handler in a worker thread, and
the ``workspace_reply`` comes back through ``POST /v1/agents/{id}/replies`` to the hub — all
through the real ``NetworkApi`` in process. The agent's singleton, its idle exit, the reverse of
a noted workspace, and its stop by stamped pid are covered too.
"""

from __future__ import annotations

import asyncio
import fcntl
import os
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from builders.network_api import FakeHub, FakeService, claim, context_for, key_store, make_api
from builders.server_targets import ambient_home
from finishup.client import agent as agent_module
from finishup.client import targets
from finishup.client.agent import (
    AGENT_LOCK_NAME,
    AGENT_STOP_NAME,
    WorkspaceAgentLoop,
    agent_pid,
    ensure_agent,
    note_workspace,
    run_workspace_agent,
    stop_agent,
)
from finishup.client.targets import ServerTarget
from finishup.domain.values import JsonObject
from finishup.ports.control import (
    WorkspaceAgentDeclaration,
    WorkspaceCall,
    WorkspaceClaim,
    WorkspaceLocator,
    WorkspaceReply,
)
from finishup.ports.workspace_agent import WORKSPACE_OPERATION_NAMES
from finishup.service.network_protocol import claim_principal_digest

_WORKSPACE = WorkspaceLocator("/srv/me/repo")


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def remote(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[ServerTarget, Path]]:
    with ambient_home(monkeypatch):
        with targets.registry_lock():
            record, root = targets.new_remote_target("lab", "https", base_url="https://lab.example")
        yield record, root


class _Handler:
    """Answers every call with the operation's name, from a worker thread."""

    def __init__(self) -> None:
        self.threads: set[int] = set()
        self.handles: list[str | None] = []

    @property
    def declaration(self) -> WorkspaceAgentDeclaration:
        return WorkspaceAgentDeclaration(
            tuple(sorted(WORKSPACE_OPERATION_NAMES, key=str.encode)), 65_536
        )

    def answer(self, call: WorkspaceCall, *, workspace_handle: str | None) -> WorkspaceReply:
        self.threads.add(threading.get_ident())
        self.handles.append(workspace_handle)
        return WorkspaceReply(
            kind="workspace_reply",
            protocol_version="1.0",
            call_id=call.call_id,
            outcome="ok",
            result=JsonObject({"answered": call.operation}),
            reason=None,
        )


def _loop(
    root: Path,
    record: ServerTarget,
    http: Any,
    token: str,
    *,
    workspace: WorkspaceClaim | None,
    handler: _Handler | None,
    **options: Any,
) -> WorkspaceAgentLoop:
    async def claim_for(_record: ServerTarget, locator: WorkspaceLocator) -> WorkspaceClaim | None:
        assert locator == _WORKSPACE
        return workspace

    return WorkspaceAgentLoop(
        root,
        record,
        http=http,
        headers={"authorization": f"Bearer {token}"},
        claim_factory=claim_for,
        handler_factory=lambda _locator, _root: handler,
        scan_seconds=0.02,
        **options,
    )


@pytest.mark.anyio
async def test_a_workspace_call_flows_to_the_agent_and_its_reply_back_to_the_hub(
    remote: tuple[ServerTarget, Path],
) -> None:
    record, root = remote
    keys = key_store(root.parent.parent)
    key, token = keys.create("laptop", "agent")
    hub = FakeHub()
    service = FakeService()
    api = make_api(service, keys, hub=hub)
    workspace = claim("repo")
    handle = context_for(claim_principal_digest(workspace, key.principal)).workspace_handle
    assert handle is not None
    note_workspace(root, _WORKSPACE)
    handler = _Handler()
    http = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=api.asgi("https")),  # type: ignore[arg-type]
        base_url="https://lab.example",
    )
    delivered: list[tuple[Path, WorkspaceLocator, WorkspaceClaim]] = []
    closed: list[bool] = []

    class _Delivery:
        async def deliver(self) -> None:
            await asyncio.sleep(0)

        async def close(self) -> None:
            closed.append(True)

    def delivery(
        _record: ServerTarget, at: Path, locator: WorkspaceLocator, value: WorkspaceClaim
    ) -> _Delivery:
        delivered.append((at, locator, value))
        return _Delivery()

    loop = _loop(
        root, record, http, token, workspace=workspace, handler=handler, delivery_factory=delivery
    )
    running = asyncio.create_task(loop.run())
    try:
        inline = await hub.call(handle, "capture", {"workspace": handle})
        background = await hub.call(handle, "inspect", {"workspace": handle})
    finally:
        loop.stop()
        assert await asyncio.wait_for(running, 5) == 0
    assert inline.result == JsonObject({"answered": "capture"})
    assert background.result == JsonObject({"answered": "inspect"})
    # The handler ran off the event loop and answered for the handle the server named.
    assert handler.handles == [handle, handle]
    assert threading.get_ident() not in handler.threads
    # While it serves a workspace, the agent delivers what this client captured in the background,
    # for that one workspace under its claim, and ends the delivery when the workspace ends.
    assert delivered == [(root, _WORKSPACE, workspace)]
    assert closed == [True]
    # Stopping ended the registration: the hub's channel closed and the idle hold released.
    assert all(channel.closed for channel in hub.channels)
    assert service.active == 0
    await api.close()


@pytest.mark.anyio
async def test_background_delivery_backs_off_while_it_makes_no_progress(
    remote: tuple[ServerTarget, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    # Found in the real-environment run: with the server down, a key revoked, or one row the
    # server kept answering ``mapping_missing``, every agent sent a pass every 2 s, forever.
    import types

    from finishup.application.observation_drain import ObservationDrainSummary
    from finishup.client.observation_outbox import ClientDrainSummary

    record, root = remote
    stuck = ClientDrainSummary(0, ObservationDrainSummary(1, 0, 1, 0, ()))
    settled = ClientDrainSummary(0, ObservationDrainSummary(1, 1, 0, 0, ()))
    nothing_due = ClientDrainSummary(0, ObservationDrainSummary(0, 0, 0, 0, ()))
    stopped = ClientDrainSummary(0, None, "service_unavailable")
    passes: list[object] = [None, stopped, stuck, stuck, stuck, stuck, stuck, settled]
    passes += [nothing_due, stuck]
    loop = WorkspaceAgentLoop(root, record, http=object(), headers={}, scan_seconds=2.0)
    waits: list[float] = []

    class _Timeout:
        def __init__(self, delay: float) -> None:
            waits.append(delay)

        async def __aenter__(self) -> None:
            raise TimeoutError

        async def __aexit__(self, *_exc: object) -> bool:
            return False

    namespace = types.SimpleNamespace(**vars(asyncio))
    namespace.timeout = _Timeout
    monkeypatch.setattr(agent_module, "asyncio", namespace)

    class _Delivery:
        async def deliver(self) -> object:
            value = passes.pop(0)
            if not passes:
                loop.stop()
            return value

        async def close(self) -> None:
            return None

    await loop._deliver(_Delivery())  # pyright: ignore[reportPrivateUsage]
    assert waits == [4.0, 8.0, 16.0, 32.0, 60.0, 60.0, 60.0, 2.0, 2.0, 4.0]


@pytest.mark.anyio
async def test_a_fresh_note_ends_a_registration_retry_wait_at_once(
    remote: tuple[ServerTarget, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    # Found in the real-environment run: after an SSH client restarted an idle-stopped server,
    # the agent was still waiting out its retry delay, so the next start and check found no
    # agent. A client process that reaches the server notes the workspace again; the agent then
    # retries at once instead of after the delay.
    record, root = remote
    monkeypatch.setattr(agent_module, "_RETRY_SECONDS", (60.0,))
    attempts: list[float] = []
    attempted = asyncio.Event()

    def refuse(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/agents":
            attempts.append(time.monotonic())
            attempted.set()
        raise httpx.ConnectError("unreachable", request=request)

    note_workspace(root, _WORKSPACE)
    http = httpx.AsyncClient(transport=httpx.MockTransport(refuse), base_url="https://lab.example")
    loop = _loop(root, record, http, "unused", workspace=claim("repo"), handler=_Handler())
    running = asyncio.create_task(loop.run())
    try:
        await asyncio.wait_for(attempted.wait(), 10)
        attempted.clear()
        note_workspace(root, _WORKSPACE)
        # Without the nudge the next attempt would come 60 s later.
        await asyncio.wait_for(attempted.wait(), 10)
    finally:
        loop.stop()
        assert await asyncio.wait_for(running, 10) == 0
    assert len(attempts) == 2


@pytest.mark.anyio
async def test_a_request_lost_on_the_transport_brings_the_transport_back(
    remote: tuple[ServerTarget, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    # An SSH target's master that died while the user was idle is restored by the agent itself,
    # not only when a foreground client happens to connect; a refusal the server answered is not
    # a transport failure and restores nothing.
    record, root = remote
    monkeypatch.setattr(agent_module, "_RETRY_SECONDS", (0.01,))
    restored: list[tuple[ServerTarget, Path]] = []
    refusals: list[str] = []
    both = asyncio.Event()

    async def restorer(at_record: ServerTarget, at_root: Path) -> None:
        restored.append((at_record, at_root))

    def answer(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/agents":
            refusals.append("connect" if len(refusals) % 2 == 0 else "refused")
            if len(refusals) >= 4:
                both.set()
            if refusals[-1] == "connect":
                raise httpx.ConnectError("forward gone", request=request)
            return httpx.Response(401, content=b'{"reason":"api_key_invalid"}')
        raise httpx.ConnectError("unused", request=request)

    note_workspace(root, _WORKSPACE)
    http = httpx.AsyncClient(transport=httpx.MockTransport(answer), base_url="https://lab.example")
    loop = _loop(
        root,
        record,
        http,
        "unused",
        workspace=claim("repo"),
        handler=_Handler(),
        transport_restorer=restorer,
    )
    running = asyncio.create_task(loop.run())
    try:
        await asyncio.wait_for(both.wait(), 10)
    finally:
        loop.stop()
        assert await asyncio.wait_for(running, 10) == 0
    connects = refusals.count("connect")
    assert restored and all(item == (record, root) for item in restored)
    assert 2 <= len(restored) <= connects


@pytest.mark.anyio
async def test_without_a_claim_or_handler_nothing_registers(
    remote: tuple[ServerTarget, Path],
) -> None:
    record, root = remote
    keys = key_store(root.parent.parent)
    _key, token = keys.create("laptop", "agent")
    hub = FakeHub()
    api = make_api(FakeService(), keys, hub=hub)
    note_workspace(root, _WORKSPACE)
    http = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=api.asgi("https")),  # type: ignore[arg-type]
        base_url="https://lab.example",
    )
    for workspace, handler in ((None, _Handler()), (claim(), None)):
        loop = _loop(root, record, http, token, workspace=workspace, handler=handler)
        running = asyncio.create_task(loop.run())
        await asyncio.sleep(0.1)
        loop.stop()
        assert await asyncio.wait_for(running, 5) == 0
        http = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=api.asgi("https")),  # type: ignore[arg-type]
            base_url="https://lab.example",
        )
    assert hub.channels == []


@pytest.mark.anyio
async def test_the_agent_exits_when_idle_and_drops_idle_workspaces(
    remote: tuple[ServerTarget, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    record, root = remote
    keys = key_store(root.parent.parent)
    _key, token = keys.create("laptop", "agent")
    hub = FakeHub()
    api = make_api(FakeService(), keys, hub=hub)
    note_workspace(root, _WORKSPACE)
    (noted,) = (root / "state" / "agent-workspaces").iterdir()
    stale = time.time() - agent_module.WORKSPACE_IDLE_SECONDS - 5
    os.utime(noted, (stale, stale))
    http = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=api.asgi("https")),  # type: ignore[arg-type]
        base_url="https://lab.example",
    )
    loop = _loop(
        root, record, http, token, workspace=claim(), handler=_Handler(), idle_exit_seconds=0.1
    )
    assert await asyncio.wait_for(loop.run(), 5) == 0
    assert not noted.exists()
    assert hub.channels == []


def test_noting_a_workspace_keeps_its_path_local_and_owner_only(
    remote: tuple[ServerTarget, Path],
) -> None:
    _record, root = remote
    note_workspace(root, _WORKSPACE)
    note_workspace(root, _WORKSPACE)
    (noted,) = (root / "state" / "agent-workspaces").iterdir()
    assert noted.stat().st_mode & 0o777 == 0o600
    assert noted.read_bytes() == b'{"path":"/srv/me/repo","schema":"yoetz.agent-workspace/1"}\n'
    assert "repo" not in noted.name


def test_the_agent_is_a_singleton_started_and_asked_to_stop_without_a_signal(
    remote: tuple[ServerTarget, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    _record, root = remote
    launched: list[tuple[tuple[str, ...], dict[str, str]]] = []
    real_popen = subprocess.Popen

    def popen(argv: tuple[str, ...], **options: Any) -> object:
        launched.append((argv, options["env"]))
        return object()

    monkeypatch.setenv("FINISHUP_ISOLATED_ROOT", "/somewhere/else")
    monkeypatch.setattr(agent_module.subprocess, "Popen", popen)
    assert agent_pid(root) is None
    assert ensure_agent(root) is True
    ((argv, env),) = launched
    assert argv == (sys.executable, "-m", "finishup", "agent", "run", "--root", os.fspath(root))
    assert "FINISHUP_ISOLATED_ROOT" not in env

    # A running agent holds the lock exclusively and stamps its pid; nothing starts beside it.
    holder = real_popen([sys.executable, "-c", "import time; time.sleep(30)"])  # noqa: S603
    descriptor = os.open(root / "state" / AGENT_LOCK_NAME, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        os.pwrite(descriptor, f"{holder.pid}\n".encode(), 0)
        assert agent_pid(root) == holder.pid
        assert ensure_agent(root) is False
        # Stopping asks through the request file; the stamped pid is never signalled (it may be
        # a stale stamp whose pid another process now has).
        assert stop_agent(root, wait_seconds=0.0) is True
        assert (root / "state" / AGENT_STOP_NAME).exists()
        assert holder.poll() is None
    finally:
        os.close(descriptor)
        holder.kill()
        holder.wait(5)
    assert agent_pid(root) is None
    assert stop_agent(root) is False
    assert len(launched) == 1


def test_a_probe_is_never_taken_for_a_running_agent(remote: tuple[ServerTarget, Path]) -> None:
    # A probe (``ensure_agent``'s, another ``stop_agent``'s) holds the lock shared for a moment.
    # It must not read as an agent, or a stale stamp from an agent that was killed would be used.
    _record, root = remote
    (root / "state").mkdir(mode=0o700, exist_ok=True)
    descriptor = os.open(root / "state" / AGENT_LOCK_NAME, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        os.pwrite(descriptor, b"999999\n", 0)  # a stamp left by an agent that was killed
        fcntl.flock(descriptor, fcntl.LOCK_SH)
        assert agent_pid(root) is None
        assert stop_agent(root, wait_seconds=0.0) is False
        assert not (root / "state" / AGENT_STOP_NAME).exists()
    finally:
        os.close(descriptor)


@pytest.mark.anyio
async def test_a_stop_request_ends_the_agent_loop(
    remote: tuple[ServerTarget, Path],
) -> None:
    record, root = remote
    note_workspace(root, _WORKSPACE)
    (root / "state" / AGENT_STOP_NAME).touch(mode=0o600)
    loop = WorkspaceAgentLoop(
        root,
        record,
        http=httpx.AsyncClient(base_url="https://lab.example"),
        headers={},
        claim_factory=lambda _record, _locator: _no_claim(),
        scan_seconds=0.02,
    )
    assert await asyncio.wait_for(loop.run(), 10) == 0


async def _no_claim() -> WorkspaceClaim | None:
    return None


def test_the_agent_refuses_a_root_that_is_not_a_remote_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with ambient_home(monkeypatch):
        with targets.registry_lock():
            _record, root = targets.new_local_target("work")
        assert run_workspace_agent(root) == 2


def _call(deadline_ms: int = 5_000) -> WorkspaceCall:
    from finishup.protocol.ids import IdKind, new_id

    return WorkspaceCall(
        kind="workspace_call",
        protocol_version="1.0",
        call_id=new_id(IdKind.CONTROL_RPC),
        service_instance_id="svc_00000000-0000-4000-8000-000000000001",
        service_generation="7",
        operation="read_task_base",
        arguments=JsonObject({}),
        deadline_ms=deadline_ms,
    )


@pytest.mark.anyio
async def test_a_reply_lost_on_the_way_is_sent_again_within_the_calls_deadline(
    remote: tuple[ServerTarget, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    # With every pooled connection taken by long-polls, a reply POST timed out waiting for one
    # and was dropped, so the server's call ended without its answer.
    record, root = remote
    monkeypatch.setattr(agent_module, "_REPLY_RETRY_FIRST_SECONDS", 0.01)
    recorded: list[tuple[str, str]] = []

    def record_event(operation: str, reason: str) -> None:
        recorded.append((operation, reason))

    monkeypatch.setattr(agent_module, "_record", record_event)

    class _Api:
        def __init__(self, failures: int) -> None:
            self.failures = failures
            self.sent: list[bytes] = []

        async def reply(self, agent_id: str, body: bytes) -> bool:
            del agent_id
            if self.failures:
                self.failures -= 1
                raise httpx.PoolTimeout("no connection free")
            self.sent.append(body)
            return True

    loop = WorkspaceAgentLoop(root, record, http=object(), headers={})
    flaky = _Api(failures=2)
    await loop._answer(flaky, "agt_x", "client:0123456789abcdef", _Handler(), _call())  # type: ignore[arg-type]  # pyright: ignore[reportPrivateUsage]
    assert len(flaky.sent) == 1 and recorded == []
    # Past the call's deadline it gives up, records why, and never raises out of the task.
    lost = _Api(failures=10_000)
    await loop._answer(lost, "agt_x", "client:0123456789abcdef", _Handler(), _call(50))  # type: ignore[arg-type]  # pyright: ignore[reportPrivateUsage]
    assert lost.sent == [] and recorded == [("workspace_agent_reply", "reply_failed")]


def test_the_pinned_pool_has_room_for_every_agent_poll_and_its_replies() -> None:
    from finishup.client.rest_client import (
        _PinMismatch,  # pyright: ignore[reportPrivateUsage]
        _PinnedTransport,  # pyright: ignore[reportPrivateUsage]
    )
    from finishup.service.http_api import MAX_AGENTS_PER_KEY

    transport = _PinnedTransport("sha256:" + "0" * 64, _PinMismatch())
    pool = transport._pool  # pyright: ignore[reportPrivateUsage]
    # One long-poll per registered workspace, the four calls the agent answers at once, and its
    # registrations, with room to spare: the size httpx gives every unpinned client.
    assert pool._max_connections >= MAX_AGENTS_PER_KEY + agent_module._MAX_CONCURRENT_CALLS + 1  # pyright: ignore[reportPrivateUsage]
    assert pool._max_connections == 100  # pyright: ignore[reportPrivateUsage]
