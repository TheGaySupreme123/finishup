"""The owner-only index of which local workspace each claim of a remote root stands for."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from finishup.client.claimed_workspaces import (
    CLAIMED_WORKSPACES_DIRECTORY,
    claimed_workspace,
    record_claimed_workspace,
)
from finishup.ports.control import WorkspaceClaim, WorkspaceLocator

_CLAIM = WorkspaceClaim("git_common_root", "sha256:" + "ab" * 32)


@pytest.fixture
def root(tmp_path: Path) -> Path:
    target = tmp_path / "t_0123abcd"
    (target / "state").mkdir(parents=True, mode=0o700)
    target.chmod(0o700)
    return target


def test_a_recorded_claim_reads_back_as_its_workspace(root: Path, tmp_path: Path) -> None:
    workspace = WorkspaceLocator(str(tmp_path / "repo"))
    assert claimed_workspace(root, _CLAIM) is None
    assert record_claimed_workspace(root, _CLAIM, workspace) is True
    assert claimed_workspace(root, _CLAIM) == workspace
    record = root / "state" / CLAIMED_WORKSPACES_DIRECTORY / f"{'ab' * 32}.json"
    assert record.stat().st_mode & 0o777 == 0o600
    assert record.parent.stat().st_mode & 0o777 == 0o700
    # Idempotent: an identical record is not rewritten.
    before = record.stat().st_ino
    assert record_claimed_workspace(root, _CLAIM, workspace) is True
    assert record.stat().st_ino == before
    # Another kind under the same digest is not this claim.
    assert claimed_workspace(root, WorkspaceClaim("directory", _CLAIM.digest)) is None


def test_a_tampered_or_unsafe_record_is_never_read(root: Path, tmp_path: Path) -> None:
    workspace = WorkspaceLocator(str(tmp_path / "repo"))
    record_claimed_workspace(root, _CLAIM, workspace)
    record = root / "state" / CLAIMED_WORKSPACES_DIRECTORY / f"{'ab' * 32}.json"
    original = record.read_bytes()
    record.write_bytes(original.replace(b'"workspace"', b'"workspace" '))
    assert claimed_workspace(root, _CLAIM) is None
    record.write_bytes(original)
    record.chmod(0o644)
    assert claimed_workspace(root, _CLAIM) is None
    record.chmod(0o600)
    assert claimed_workspace(root, _CLAIM) == workspace
    record.unlink()
    os.symlink(tmp_path / "elsewhere.json", record)
    assert claimed_workspace(root, _CLAIM) is None


def test_an_unsafe_state_folder_leaves_the_index_untouched(root: Path, tmp_path: Path) -> None:
    (root / "state").chmod(0o755)
    assert record_claimed_workspace(root, _CLAIM, WorkspaceLocator(str(tmp_path))) is False
    assert not (root / "state" / CLAIMED_WORKSPACES_DIRECTORY).exists()


def test_the_index_never_appears_in_a_representation(root: Path, tmp_path: Path) -> None:
    secret = str(tmp_path / "private-project")
    record_claimed_workspace(root, _CLAIM, WorkspaceLocator(secret))
    assert secret not in repr(claimed_workspace(root, _CLAIM))
    assert _CLAIM.digest not in repr(_CLAIM)
