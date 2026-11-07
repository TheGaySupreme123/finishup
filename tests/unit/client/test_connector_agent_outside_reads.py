"""The connector's background workspace agents read outside the project as the owner chose.

ADR-051 decision 5 (D2b), approach A (edge relay). Work the server keeps doing after the call
that started it (the review loop, observation verification) reaches the client through the
target's connector, which holds one background agent per claimed workspace
(``finishup.client.connector_agent``). That agent honours the target's outside-read mode exactly
as an agent served on the client's own connection does: the same two modes for every remote
kind, ``listed`` while none was chosen, and never a prompt on any console once set up.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from builders.server_targets import ambient_home
from finishup.adapters.control.unix_socket import AuthenticatedUnixStream
from finishup.cli import trusted_console
from finishup.client import targets
from finishup.client.claimed_workspaces import record_claimed_workspace
from finishup.client.connector_agent import open_connector_agent
from finishup.client.remote_binding import binding_for_active_root
from finishup.client.server_folders import OutsideReadMode, OutsideReads, set_mode
from finishup.client.workspace_agent import WorkspaceAgentHandler
from finishup.config.paths import selection_override
from finishup.domain.values import JsonObject
from finishup.ports.control import WorkspaceCall, WorkspaceLocator
from finishup.ports.workspace_agent import (
    ReadTextBeneathArguments,
    WorkspaceOperation,
    operation_spec,
)
from finishup.protocol.ids import IdKind, new_id


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as root:
        yield root


class _NoConsole:
    def __init__(self) -> None:
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
    reply = agent.answer(call, workspace_handle="client:0123456789abcdef")
    return reply.outcome, reply.reason


@pytest.mark.anyio
@pytest.mark.parametrize("kind", ["ssh", "local_port", "https"])
@pytest.mark.parametrize("mode", ["local", "listed", None], ids=["local", "listed", "none"])
async def test_a_background_agent_reads_outside_as_the_owner_chose(
    home: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
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
    # A client process claimed the workspace over the connector and recorded the claim.
    with selection_override(root):
        claimed = await binding_for_active_root(workspace, serve_workspace=False)
    assert claimed is not None
    assert record_claimed_workspace(root, claimed.claim, workspace) is True
    monkeypatch.setattr(trusted_console, "TrustedForegroundConsole", _NoConsole)
    never = asyncio.Event()

    async def dial() -> AuthenticatedUnixStream:
        await never.wait()  # the server is not reached here; only the agent's answers matter
        raise OSError("unreachable")

    # The connector serves its root under that root's selection.
    with selection_override(root):
        agent = await open_connector_agent(root, claimed.claim, dial)
    assert agent is not None
    try:
        handler = agent._binding.agent  # pyright: ignore[reportPrivateUsage]
        assert type(handler) is WorkspaceAgentHandler
        expected = OutsideReads(mode or "listed", (), "owner" if mode else "not_chosen")
        assert handler._outside() == expected  # pyright: ignore[reportPrivateUsage]
        answer = ("ok", None) if mode == "local" else ("refused", "root_not_admitted")
        assert _outside_read(handler, outside) == answer
        # A change of mode applies from the background agent's next read, with no prompt.
        other: OutsideReadMode = "listed" if mode == "local" else "local"
        with targets.registry_lock():
            set_mode(root, record.target_id, other)
        flipped = ("ok", None) if other == "local" else ("refused", "root_not_admitted")
        assert _outside_read(handler, outside) == flipped
    finally:
        await agent.aclose()
