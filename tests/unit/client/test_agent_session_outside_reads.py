"""Direct-dial workspace agents read outside the project as the owner chose at server add.

ADR-051 decision 5 (D2b), approach B (direct dial). Two paths of this approach build the agents
that answer the server's work while no call of the owner's runs: the MCP bridge's background agent
connection (``BridgeBackgroundWork``) and ``finishup server connect NAME --agent``
(``run_foreground_agent``). Each builds its agent through the real binding
(``service.client.serving_workspace_binding``) and honours the target's outside-read mode exactly
as an agent served on the client's own connection does: the same two modes for every remote kind,
``listed`` while none was chosen, a change of mode from the agent's next read, the target it was
built for whatever root the process resolves at a read, and never a prompt on any console once
set up. Only the dial is a stand-in; nothing reaches a server.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Literal, NoReturn

import pytest

from builders.server_targets import ambient_home
from finishup.cli import trusted_console
from finishup.client import targets
from finishup.client.agent_session import BridgeBackgroundWork, run_foreground_agent
from finishup.client.server_folders import OutsideReadMode, OutsideReads, set_mode
from finishup.client.workspace_agent import WorkspaceAgentHandler
from finishup.config.paths import active_root, reset_selection_memo, selection_override
from finishup.domain.values import JsonObject
from finishup.ports.control import WorkspaceCall, WorkspaceLocator
from finishup.ports.workspace_agent import (
    ReadTextBeneathArguments,
    WorkspaceOperation,
    operation_spec,
)
from finishup.protocol.ids import IdKind, new_id
from finishup.service.client import ClientWorkspaceBinding

type _Path = Literal["bridge", "foreground"]

_HANDLE = "client:0123456789abcdef"


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as root:
        yield root


@pytest.fixture
def no_console(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Fail on any trusted-console prompt, and record it even where a caller swallows the error.

    The guard sits beneath the class, so it holds whatever name a caller bound the class to when
    it was imported (``cli.elevated``, ``cli.unlock``'s subclass, the Linux presence adapter):
    ``TrustedForegroundConsole`` builds its terminal adapter through the module's
    ``_new_adapter`` when it is constructed, and each adapter opens the terminal in ``open``.
    """

    asked: list[str] = []

    def _refuse(*_arguments: object, **_options: object) -> NoReturn:
        asked.append("trusted_console")
        raise AssertionError("asked on the trusted console after setup")

    monkeypatch.setattr(trusted_console, "_new_adapter", _refuse)
    for adapter in ("_PosixConsoleAdapter", "_WindowsConsoleAdapter"):
        monkeypatch.setattr(f"{trusted_console.__name__}.{adapter}.open", _refuse)
    return asked


class _Connection:
    """The stand-in for the dialled connection: open until the owner closes it."""

    def __init__(self) -> None:
        self.workspace_handle = _HANDLE
        self._ended = asyncio.Event()

    @property
    def closed(self) -> bool:
        return self._ended.is_set()

    async def wait_closed(self) -> None:
        await self._ended.wait()

    async def close(self) -> None:
        self._ended.set()


def _remote(kind: str) -> tuple[targets.ServerTarget, Path]:
    with targets.registry_lock():
        if kind == "ssh":
            return targets.new_remote_target("lab", "ssh", host="lab.example", port=22)
        if kind == "local_port":
            return targets.new_remote_target(
                "port", "local_port", base_url="https://127.0.0.1:8443"
            )
        return targets.new_remote_target("web", "https", base_url="https://finishup.example")


def _outside_read(agent: WorkspaceAgentHandler, folder: Path) -> tuple[str, str | None]:
    spec = operation_spec(WorkspaceOperation.READ_TEXT_BENEATH)
    assert spec is not None
    call = WorkspaceCall(
        "workspace_call",
        "1.0",
        new_id(IdKind.CONTROL_RPC),
        "svc_00000000-0000-4000-8000-000000000001",
        "1",
        WorkspaceOperation.READ_TEXT_BENEATH.value,
        JsonObject(spec.encode_arguments(ReadTextBeneathArguments(os.fspath(folder), "spec.md"))),
        10_000,
    )
    reply = agent.answer(call, workspace_handle=_HANDLE)
    return reply.outcome, reply.reason


def _outside_read_elsewhere(agent: WorkspaceAgentHandler, folder: Path) -> tuple[str, str | None]:
    """The same read while this process resolves its everyday installation, not the target.

    ``selection_override`` sets a process-wide answer, so the agent's read in this thread sees
    it: only an agent that fixed its target when it was built still reads that target's record.
    """

    with selection_override(None):
        assert active_root() is None
        return _outside_read(agent, folder)


def _expected(mode: OutsideReadMode | None) -> tuple[str, str | None]:
    return ("ok", None) if mode == "local" else ("refused", "root_not_admitted")


async def _check_agent(
    binding: ClientWorkspaceBinding,
    record: targets.ServerTarget,
    root: Path,
    mode: OutsideReadMode | None,
    outside: Path,
) -> None:
    """The agent the path built reads outside as chosen, and follows a change of mode.

    Each read is made twice: as the path serves, and while this process resolves another root,
    so the answer is the target's whatever root the process uses at the time of the read.
    """

    handler = binding.agent
    assert type(handler) is WorkspaceAgentHandler
    expected = OutsideReads(mode or "listed", (), "owner" if mode else "not_chosen")
    assert await asyncio.to_thread(handler._outside) == expected  # pyright: ignore[reportPrivateUsage]
    assert await asyncio.to_thread(_outside_read, handler, outside) == _expected(mode)
    assert await asyncio.to_thread(_outside_read_elsewhere, handler, outside) == _expected(mode)
    # A change of mode applies from the agent's next read, with no prompt and no reconnect.
    other: OutsideReadMode = "listed" if mode == "local" else "local"
    with targets.registry_lock():
        set_mode(root, record.target_id, other)
    assert await asyncio.to_thread(_outside_read, handler, outside) == _expected(other)
    assert await asyncio.to_thread(_outside_read_elsewhere, handler, outside) == _expected(other)


async def _bridge_binding(workspace: WorkspaceLocator) -> tuple[ClientWorkspaceBinding, object]:
    """The binding the bridge's background agent connection is dialled with, and its holder."""

    bindings: list[ClientWorkspaceBinding] = []

    async def dial(binding: ClientWorkspaceBinding) -> _Connection:
        bindings.append(binding)
        return _Connection()

    work = BridgeBackgroundWork(connect=dial, pending=lambda _workspace: False)
    work.note_activity(workspace)
    passed = await work.run_pass()
    assert passed.connected and len(bindings) == 1
    return bindings[0], work


@pytest.mark.parametrize("path", ["bridge", "foreground"])
@pytest.mark.parametrize("kind", ["ssh", "local_port", "https"])
@pytest.mark.parametrize("mode", ["local", "listed", None], ids=["local", "listed", "unchosen"])
def test_a_direct_dial_agent_reads_outside_as_the_owner_chose(
    home: Path,
    tmp_path: Path,
    no_console: list[str],
    path: _Path,
    kind: str,
    mode: OutsideReadMode | None,
) -> None:
    del home
    workspace_dir = (tmp_path / "workspace").resolve()
    workspace_dir.mkdir()
    workspace = WorkspaceLocator(os.fspath(workspace_dir))
    outside = (tmp_path / "outside").resolve()
    outside.mkdir()
    (outside / "spec.md").write_text("SPEC\n", encoding="utf-8")
    record, root = _remote(kind)
    if mode is not None:
        with targets.registry_lock():
            set_mode(root, record.target_id, mode)
    if path == "bridge":
        # The bridge's process uses the selected target as its root.
        with targets.registry_lock():
            targets.write_selection(record)
    reset_selection_memo()

    async def bridge() -> None:
        binding, work = await _bridge_binding(workspace)
        assert type(work) is BridgeBackgroundWork
        try:
            await _check_agent(binding, record, root, mode, outside)
        finally:
            await work.aclose()

    async def foreground() -> None:
        # ``server connect NAME --agent`` names the target. No selection names it: the process
        # resolves it as its root only while ``run_foreground_agent`` serves, through
        # ``selection_override``; ``_check_agent`` also reads while the process resolves none.
        bindings: list[ClientWorkspaceBinding] = []
        dialled = asyncio.Event()

        async def dial(binding: ClientWorkspaceBinding) -> _Connection:
            bindings.append(binding)
            dialled.set()
            return _Connection()

        serving = asyncio.create_task(run_foreground_agent(root, workspace, connect=dial))
        try:
            async with asyncio.timeout(30.0):
                await dialled.wait()
            assert len(bindings) == 1
            await _check_agent(bindings[0], record, root, mode, outside)
        finally:
            serving.cancel()
            await asyncio.gather(serving, return_exceptions=True)

    asyncio.run(bridge() if path == "bridge" else foreground())
    assert no_console == []
