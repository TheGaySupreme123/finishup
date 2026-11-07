"""``finishup agent run --root ROOT`` reads outside the project as the owner chose at server add.

ADR-051 decision 5 (D2b), approach C (server-native). The server reaches the client's projects
through the pull-based workspace agent, ``finishup agent run --root ROOT``, which builds one
handler per noted workspace with ``client.remote_workspace.handler_for_workspace``. That agent
honours ROOT's target's outside-read mode exactly as the other approaches' agents do: the same two
modes for every remote kind, ``listed`` while none was chosen, a change of mode from its next
read, and never a prompt on any console once set up.

The command runs in process with its own defaults; only the network under it is replaced: the
agent's HTTP client reaches the real ``NetworkApi`` in the same event loop, whose hub stands in
for the server's and sends the agent a ``read_text_beneath`` call outside the project.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from typer.testing import CliRunner

from builders.network_api import FakeHub, FakeService, key_store, make_api
from builders.server_targets import ambient_home
from finishup.cli import app as cli
from finishup.cli import trusted_console
from finishup.client import agent as agent_module
from finishup.client import targets
from finishup.client.agent import WorkspaceAgentLoop, note_workspace
from finishup.client.server_folders import OutsideReadMode, set_mode
from finishup.ports.control import WorkspaceLocator
from finishup.ports.workspace_agent import (
    ReadTextBeneathArguments,
    WorkspaceOperation,
    operation_spec,
)

_RUNNER = CliRunner()
# Waits observe real state (the hub's registrations) and fail on this deadline.
_DEADLINE_SECONDS = 30.0
_ADMITTED = ("ok", None)
_REFUSED = ("refused", "root_not_admitted")


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as root:
        yield root


class _NoConsole:
    def __init__(self, *_arguments: object, **_options: object) -> None:
        raise AssertionError("asked on the trusted console after setup")


def _remote(kind: str) -> tuple[targets.ServerTarget, Path]:
    with targets.registry_lock():
        if kind == "ssh":
            return targets.new_remote_target("lab", "ssh", host="lab.example", port=22)
        if kind == "local_port":
            return targets.new_remote_target(
                "port", "local_port", base_url="https://127.0.0.1:8443"
            )
        return targets.new_remote_target("web", "https", base_url="https://finishup.example")


def _repository(path: Path) -> WorkspaceLocator:
    path.mkdir(parents=True, mode=0o700)
    subprocess.run(("git", "init", "-q", "-b", "main"), cwd=path, check=True)
    return WorkspaceLocator(os.fspath(path.resolve()))


def _outside_arguments(folder: Path) -> dict[str, Any]:
    spec = operation_spec(WorkspaceOperation.READ_TEXT_BENEATH)
    assert spec is not None
    return dict(spec.encode_arguments(ReadTextBeneathArguments(os.fspath(folder), "spec.md")))


class _NoDelivery:
    """Captured-observation delivery is not under test; it never leaves this process here."""

    def __init__(self, *_arguments: object) -> None:
        return None

    async def deliver(self) -> None:
        return None

    async def close(self) -> None:
        return None


@pytest.mark.parametrize("kind", ["ssh", "local_port", "https"])
@pytest.mark.parametrize("mode", ["local", "listed", None], ids=["local", "listed", "none"])
def test_agent_run_reads_outside_as_the_owner_chose(
    home: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
    mode: OutsideReadMode | None,
) -> None:
    del home
    workspace = _repository(tmp_path / "workspace")
    outside = (tmp_path / "outside").resolve()
    outside.mkdir()
    (outside / "spec.md").write_text("SPEC\n", encoding="utf-8")
    record, root = _remote(kind)
    if mode is not None:
        # What ``server add`` recorded for the owner's answer (or ``--outside-reads``).
        with targets.registry_lock():
            set_mode(root, record.target_id, mode)
    # A client process worked in the project, so the agent serves it.
    note_workspace(root, workspace)
    monkeypatch.setattr(trusted_console, "TrustedForegroundConsole", _NoConsole)

    keys = key_store(root.parent.parent)
    _key, token = keys.create("laptop", "agent")
    hub = FakeHub()
    api = make_api(FakeService(), keys, hub=hub)
    answers: list[tuple[str, str | None]] = []
    other: OutsideReadMode = "listed" if mode == "local" else "local"

    async def drive(loop: WorkspaceAgentLoop) -> None:
        """The server's side: read outside the project, change the mode, read again."""

        try:
            deadline = time.monotonic() + _DEADLINE_SECONDS
            while not [channel for channel in hub.channels if not channel.closed]:
                assert time.monotonic() < deadline, "the agent never registered"
                await asyncio.sleep(0.01)
            handle = hub.channels[0].handle
            reply = await hub.call(handle, "read_text_beneath", _outside_arguments(outside))
            answers.append((reply.outcome, reply.reason))
            # A change of mode applies from the agent's next read, with no prompt and no restart.
            with targets.registry_lock():
                set_mode(root, record.target_id, other)
            reply = await hub.call(handle, "read_text_beneath", _outside_arguments(outside))
            answers.append((reply.outcome, reply.reason))
            assert len(hub.channels) == 1
        finally:
            loop.stop()

    class _Loop(WorkspaceAgentLoop):
        """``agent run``'s own loop over the in-process API; its handler is the default."""

        def __init__(self, at: Path, served: targets.ServerTarget, **options: Any) -> None:
            # ``run_workspace_agent`` builds its loop from the root and record alone, so the
            # claim and handler are the command's own (``handler_for_workspace``).
            assert not options
            http = httpx.AsyncClient(
                transport=httpx.ASGITransport(app=api.asgi("https")),  # type: ignore[arg-type]
                base_url="https://agent.test",
            )
            super().__init__(
                at,
                served,
                http=http,
                headers={"authorization": f"Bearer {token}"},
                delivery_factory=_NoDelivery,
                scan_seconds=0.02,
            )

        async def run(self) -> int:
            driver = asyncio.create_task(drive(self))
            try:
                return await super().run()
            finally:
                await asyncio.wait_for(driver, _DEADLINE_SECONDS)

    monkeypatch.setattr(agent_module, "WorkspaceAgentLoop", _Loop)

    result = _RUNNER.invoke(cli.app, ["agent", "run", "--root", os.fspath(root)])

    assert result.exception is None, result.exception
    assert result.exit_code == 0, result.output
    first = _ADMITTED if mode == "local" else _REFUSED
    flipped = _ADMITTED if other == "local" else _REFUSED
    assert answers == [first, flipped]
    # The agent ended its registration when it stopped.
    assert all(channel.closed for channel in hub.channels)
