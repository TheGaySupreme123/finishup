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
import signal
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
from finishup.ports.workspace_agent import (
    WORKSPACE_OPERATION_NAMES,
    workspace_handle_for_commitment,
)
from finishup.service.network_protocol import claim_principal_digest

_WORKSPACE = WorkspaceLocator("/home/me/repo")


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
        handler_factory=lambda _locator: handler,
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
    handle = workspace_handle_for_commitment(
        context_for(claim_principal_digest(workspace, key.principal)).commitment
    )
    note_workspace(root, _WORKSPACE)
    handler = _Handler()
    http = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=api.asgi("https")),  # type: ignore[arg-type]
        base_url="https://lab.example",
    )
    loop = _loop(root, record, http, token, workspace=workspace, handler=handler)
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
    # Stopping ended the registration: the hub's channel closed and the idle hold released.
    assert all(channel.closed for channel in hub.channels)
    assert service.active == 0
    await api.close()


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
    assert noted.read_bytes() == b'{"path":"/home/me/repo","schema":"yoetz.agent-workspace/1"}\n'
    assert "repo" not in noted.name


def test_the_agent_is_a_singleton_started_and_stopped_by_its_stamped_pid(
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

    # A running agent holds the lock and stamps its pid; nothing new is started beside it.
    holder = real_popen([sys.executable, "-c", "import time; time.sleep(30)"])  # noqa: S603
    descriptor = os.open(root / "state" / AGENT_LOCK_NAME, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        os.pwrite(descriptor, f"{holder.pid}\n".encode(), 0)
        assert agent_pid(root) == holder.pid
        assert ensure_agent(root) is False
        assert stop_agent(root) is True
        assert holder.wait(5) == -signal.SIGTERM
    finally:
        os.close(descriptor)
        if holder.poll() is None:
            holder.kill()
    assert agent_pid(root) is None
    assert stop_agent(root) is False
    assert len(launched) == 1


def test_the_agent_refuses_a_root_that_is_not_a_remote_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with ambient_home(monkeypatch):
        with targets.registry_lock():
            _record, root = targets.new_local_target("work")
        assert run_workspace_agent(root) == 2
