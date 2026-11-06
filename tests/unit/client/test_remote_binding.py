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
