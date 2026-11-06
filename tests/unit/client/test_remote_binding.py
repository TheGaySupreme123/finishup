"""The one helper every approach calls to bind a connection from this process's root (ADR-051).

A local root — the everyday installation, an isolated root that is not a target, a named local
server — gets no binding and sends its locator exactly as before. A remote root (``local_port``,
``ssh``, ``https``) claims the workspace under its own target's salt, with the workspace agent
when asked, and never sends a path. A root or record that cannot be read fails closed.
"""

from __future__ import annotations

import base64
import os
from collections.abc import Iterator
from pathlib import Path
from typing import cast

import pytest

from builders.server_targets import ambient_home
from finishup.client import targets
from finishup.client.remote_binding import binding_for_active_root, is_remote_active_root
from finishup.client.targets import ServerTarget, TargetError
from finishup.client.workspace_agent import WorkspaceAgentHandler
from finishup.client.workspace_claim import workspace_claim
from finishup.config import paths
from finishup.ports.control import WorkspaceLocator


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as root:
        yield root


@pytest.fixture
def workspace(tmp_path: Path) -> WorkspaceLocator:
    directory = tmp_path / "workspace"
    directory.mkdir()
    return WorkspaceLocator(os.fspath(directory.resolve(strict=True)))


def _remote(kind: targets.TargetKind) -> ServerTarget:
    with targets.registry_lock():
        if kind == "ssh":
            record, _root = targets.new_remote_target(
                "lab", "ssh", user="owner", host="lab.example", port=2222
            )
        elif kind == "local_port":
            record, _root = targets.new_remote_target(
                "port", "local_port", base_url="https://127.0.0.1:8443"
            )
        else:
            record, _root = targets.new_remote_target(
                "web", "https", base_url="https://finishup.example"
            )
    return record


def _select(record: ServerTarget) -> None:
    targets.write_selection(record)


@pytest.mark.anyio
async def test_the_everyday_installation_sends_its_locator(
    home: Path, workspace: WorkspaceLocator
) -> None:
    assert is_remote_active_root() is False
    assert await binding_for_active_root(workspace, serve_workspace=True) is None


@pytest.mark.anyio
async def test_a_named_local_server_sends_its_locator(
    home: Path, workspace: WorkspaceLocator
) -> None:
    with targets.registry_lock():
        record, _root = targets.new_local_target("work")
    _select(record)
    assert paths.isolation_binding() == "selection"
    assert is_remote_active_root() is False
    assert await binding_for_active_root(workspace, serve_workspace=True) is None


@pytest.mark.anyio
@pytest.mark.parametrize("kind", ["ssh", "https", "local_port"])
async def test_a_remote_root_claims_under_its_own_salt_with_its_agent(
    home: Path, workspace: WorkspaceLocator, kind: targets.TargetKind
) -> None:
    record = _remote(kind)
    _select(record)
    assert is_remote_active_root() is True
    binding = await binding_for_active_root(workspace, serve_workspace=True)
    assert binding is not None
    salt = base64.b64decode(record.claim_salt or "", validate=True)
    assert binding.claim == await workspace_claim(workspace, salt)
    assert type(binding.agent) is WorkspaceAgentHandler
    # The agent never reads the everyday installation, though this process's own directories now
    # resolve beneath the selected target's root.
    assert paths.state_dir().is_relative_to(targets.target_root(record.target_id))
    protected = binding.agent._protected  # pyright: ignore[reportPrivateUsage]
    for directory in paths.ambient_installation_dirs():
        assert os.fspath(directory) in protected


@pytest.mark.anyio
async def test_every_agent_of_a_target_keys_its_opened_workspaces_alike(
    home: Path, workspace: WorkspaceLocator
) -> None:
    """Any agent of the client for one worktree answers a handle another one opened."""

    import subprocess

    from finishup.client.remote_binding import remote_workspace_binding
    from finishup.domain.values import JsonObject
    from finishup.ports.control import WorkspaceCall
    from finishup.ports.workspace_agent import (
        OpenWorkspaceArguments,
        WorkspaceOperation,
        operation_spec,
    )
    from finishup.protocol.ids import IdKind, new_id

    del home
    subprocess.run(
        ("git", "init", "-q", workspace.path),
        check=True,
        env={"PATH": os.defpath, "HOME": workspace.path, "GIT_CONFIG_NOSYSTEM": "1"},
    )
    salt = bytes(range(32))
    first = await remote_workspace_binding(workspace, salt, protected=("/nonexistent",))
    second = await remote_workspace_binding(workspace, salt, protected=("/nonexistent",))
    other_target = await remote_workspace_binding(
        workspace, bytes(range(32, 64)), protected=("/nonexistent",)
    )
    spec = operation_spec(WorkspaceOperation.OPEN_WORKSPACE)
    assert spec is not None
    handle = "client:0123456789abcdef"

    def opened(binding: object) -> object:
        agent = cast(WorkspaceAgentHandler, getattr(binding, "agent"))
        call = WorkspaceCall(
            "workspace_call",
            "1.0",
            new_id(IdKind.CONTROL_RPC),
            "svc_00000000-0000-4000-8000-000000000001",
            "1",
            "open_workspace",
            JsonObject(spec.encode_arguments(OpenWorkspaceArguments(handle))),
            10_000,
        )
        return agent.answer(call, workspace_handle=handle).result

    assert opened(first) == opened(second) != opened(other_target)


@pytest.mark.anyio
async def test_an_agent_reads_the_folders_of_its_own_target_whatever_is_selected_later(
    home: Path, workspace: WorkspaceLocator, tmp_path: Path
) -> None:
    """ADR-051 decision 5: the record is bound to the target the connection's claim was made for,
    never to the process-wide selection, which ``server use`` or another target's probe
    (``selection_override``) may change while the agent runs."""

    from finishup.client.remote_binding import remote_workspace_binding
    from finishup.client.server_folders import OutsideReads, add_folder

    del home
    first, second = _remote("ssh"), _remote("https")
    mine, theirs = (tmp_path / "mine").resolve(), (tmp_path / "theirs").resolve()
    for record, folder in ((first, mine), (second, theirs)):
        folder.mkdir()
        add_folder(targets.target_root(record.target_id), record.target_id, os.fspath(folder))
    _select(first)
    binding = await binding_for_active_root(workspace, serve_workspace=True)
    assert binding is not None and type(binding.agent) is WorkspaceAgentHandler
    agent = binding.agent

    def admitted() -> OutsideReads:
        return agent._outside()  # pyright: ignore[reportPrivateUsage]

    # The SSH target's own record: its kind's default mode, 'local', and its own folder.
    own = OutsideReads("local", (os.fspath(mine),), "kind_default")
    assert admitted() == own
    _select(second)
    assert admitted() == own
    with paths.selection_override(targets.target_root(second.target_id)):
        assert admitted() == own
    _select(first)
    # A claim made under another target's salt than the target in use reads no folder outside,
    # and never takes the 'local' default of the target in use.
    other = await remote_workspace_binding(
        workspace, base64.b64decode(second.claim_salt or "", validate=True)
    )
    assert type(other.agent) is WorkspaceAgentHandler
    assert other.agent._outside() == OutsideReads(  # pyright: ignore[reportPrivateUsage]
        "listed", (), "unreadable"
    )


@pytest.mark.anyio
async def test_a_claim_only_binding_loads_no_agent(home: Path, workspace: WorkspaceLocator) -> None:
    _select(_remote("ssh"))
    binding = await binding_for_active_root(workspace, serve_workspace=False)
    assert binding is not None
    assert binding.agent is None


@pytest.mark.anyio
async def test_two_targets_claim_one_workspace_differently(
    home: Path, workspace: WorkspaceLocator
) -> None:
    first = _remote("ssh")
    second = _remote("https")
    _select(first)
    one = await binding_for_active_root(workspace, serve_workspace=False)
    _select(second)
    other = await binding_for_active_root(workspace, serve_workspace=False)
    assert one is not None and other is not None
    assert one.claim.digest != other.claim.digest


@pytest.mark.anyio
async def test_a_remote_root_without_a_workspace_sends_neither(home: Path) -> None:
    _select(_remote("ssh"))
    assert is_remote_active_root() is True
    assert await binding_for_active_root(None, serve_workspace=True) is None


@pytest.mark.anyio
async def test_a_tampered_remote_record_fails_closed(
    home: Path, workspace: WorkspaceLocator
) -> None:
    record = _remote("ssh")
    _select(record)
    record_path = targets.target_root(record.target_id) / "target.json"
    record_path.write_bytes(record_path.read_bytes().replace(b'"ssh"', b'"sshx"'))
    with pytest.raises(TargetError) as refused:
        is_remote_active_root()
    assert refused.value.reason == "target_record_invalid"
    with pytest.raises(TargetError):
        await binding_for_active_root(workspace, serve_workspace=True)


def _release_with_a_newer_disclosure(monkeypatch: pytest.MonkeyPatch) -> None:
    """This release shows disclosure 2; targets confirmed under 1 need a fresh confirmation."""

    monkeypatch.setattr(targets, "DISCLOSURE_VERSION", targets.DISCLOSURE_VERSION + 1)


@pytest.mark.anyio
@pytest.mark.parametrize("with_workspace", [True, False])
async def test_a_target_confirmed_under_an_older_disclosure_is_refused_before_any_hop(
    home: Path, workspace: WorkspaceLocator, with_workspace: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ADR-051 section 8: a new disclosure version needs a fresh confirmation before use."""

    stale = _remote("ssh")
    _select(stale)
    _release_with_a_newer_disclosure(monkeypatch)
    assert stale.needs_reauthorization
    with pytest.raises(TargetError) as refused:
        is_remote_active_root()
    assert refused.value.reason == "target_reauthorization_required"
    with pytest.raises(TargetError) as refused:
        await binding_for_active_root(workspace if with_workspace else None, serve_workspace=True)
    assert refused.value.reason == "target_reauthorization_required"

    # The owner's fresh confirmation (``server use NAME``) is the way back.
    renewed = targets.reauthorized(stale)
    targets.write_target(targets.target_root(stale.target_id), renewed)
    assert is_remote_active_root() is True


def test_a_local_or_absent_record_needs_no_authorization(home: Path) -> None:
    targets.require_current_authorization(None)
    with targets.registry_lock():
        record, _root = targets.new_local_target("work")
    targets.require_current_authorization(record)
