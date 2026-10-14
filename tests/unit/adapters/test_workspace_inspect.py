"""Unit tests for descriptor-safe workspace inspection."""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from finishup.adapters import workspace_inspect as workspace_inspect_module
from finishup.adapters.workspace_inspect import (
    LocalWorkspaceInspectAdapter,
    open_inspect_workspace,
)
from finishup.ports.subject_state import LocalWorkspaceHandle
from finishup.ports.workspace_inspect import (
    WorkspaceInspectCommand,
    WorkspaceInspectLimitation,
    WorkspaceInspectStatus,
)


def test_inspect_relative_file_returns_digest_and_excerpt(tmp_path: Path) -> None:
    target = tmp_path / "src"
    target.mkdir()
    file_path = target / "note.txt"
    file_path.write_text("hello-advice\n", encoding="utf-8")
    handle = open_inspect_workspace(tmp_path)
    result = LocalWorkspaceInspectAdapter().inspect(
        WorkspaceInspectCommand(handle, ("src/note.txt",))
    )
    assert result.status is WorkspaceInspectStatus.INSPECTED
    assert result.selection_digest is not None
    assert result.artifacts[0].relative_path == "src/note.txt"
    assert b"hello-advice" in result.artifacts[0].excerpt
    assert str(tmp_path) not in result.artifacts[0].relative_path


def test_inspect_rejects_path_escape(tmp_path: Path) -> None:
    handle = open_inspect_workspace(tmp_path)
    with pytest.raises(Exception):
        WorkspaceInspectCommand(handle, ("../outside.txt",))


def test_inspect_rejects_symlink_escape(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside-secret.txt"
    outside.write_text("SECRET=super\n", encoding="utf-8")
    link = tmp_path / "link.txt"
    link.symlink_to(outside)
    handle = open_inspect_workspace(tmp_path)
    result = LocalWorkspaceInspectAdapter().inspect(WorkspaceInspectCommand(handle, ("link.txt",)))
    assert result.status is WorkspaceInspectStatus.REJECTED
    assert WorkspaceInspectLimitation.SYMLINK_ESCAPE in result.limitations
    assert result.artifacts == ()


def test_inspect_never_returns_absolute_paths(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x=1\n", encoding="utf-8")
    handle = open_inspect_workspace(tmp_path)
    result = LocalWorkspaceInspectAdapter().inspect(WorkspaceInspectCommand(handle, ("a.py",)))
    payload = repr(result)
    assert str(tmp_path) not in payload
    assert "/workspace" not in result.artifacts[0].relative_path


def test_root_replacement_after_open_cannot_redirect_reads(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "note.txt").write_text("consented-content\n", encoding="utf-8")
    handle = open_inspect_workspace(workspace)

    aside = tmp_path / "workspace-aside"
    os.rename(workspace, aside)
    replacement = tmp_path / "workspace"
    replacement.mkdir()
    (replacement / "note.txt").write_text("SECRET=should-not-leak\n", encoding="utf-8")

    result = LocalWorkspaceInspectAdapter().inspect(WorkspaceInspectCommand(handle, ("note.txt",)))
    assert result.status is WorkspaceInspectStatus.INSPECTED
    assert result.artifacts[0].excerpt == b"consented-content\n"
    payload = repr(result)
    assert "SECRET=" not in payload
    assert b"SECRET=" not in result.artifacts[0].excerpt


def test_intermediate_directory_symlink_cannot_escape_the_root(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "note.txt").write_text("SECRET=via-dir-link\n", encoding="utf-8")
    (workspace / "srclink").symlink_to(outside, target_is_directory=True)

    handle = open_inspect_workspace(workspace)
    result = LocalWorkspaceInspectAdapter().inspect(
        WorkspaceInspectCommand(handle, ("srclink/note.txt",))
    )
    assert result.status is WorkspaceInspectStatus.REJECTED
    assert WorkspaceInspectLimitation.SYMLINK_ESCAPE in result.limitations
    assert result.artifacts == ()
    assert "SECRET=" not in repr(result)


def test_in_root_symlink_is_still_inspected(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    src = workspace / "src"
    src.mkdir(parents=True)
    (src / "note.txt").write_text("in-root-target\n", encoding="utf-8")
    (workspace / "link.txt").symlink_to("src/note.txt")
    (workspace / "hop1").symlink_to("link.txt")
    (workspace / "via").mkdir()
    (workspace / "via" / "dirlink").symlink_to("../src", target_is_directory=True)

    handle = open_inspect_workspace(workspace)
    adapter = LocalWorkspaceInspectAdapter()

    direct = adapter.inspect(WorkspaceInspectCommand(handle, ("link.txt",)))
    assert direct.status is WorkspaceInspectStatus.INSPECTED
    assert direct.artifacts[0].excerpt == b"in-root-target\n"

    two_hop = adapter.inspect(WorkspaceInspectCommand(handle, ("hop1",)))
    assert two_hop.status is WorkspaceInspectStatus.INSPECTED
    assert two_hop.artifacts[0].excerpt == b"in-root-target\n"

    via_dir = adapter.inspect(WorkspaceInspectCommand(handle, ("via/dirlink/note.txt",)))
    assert via_dir.status is WorkspaceInspectStatus.INSPECTED
    assert via_dir.artifacts[0].excerpt == b"in-root-target\n"


def test_symlink_chain_depth_is_bounded(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "leaf.txt").write_text("deep-target\n", encoding="utf-8")
    previous = "leaf.txt"
    # One more hop than the adapter will resolve.
    for index in range(workspace_inspect_module._MAX_SYMLINK_DEPTH + 1):  # pyright: ignore[reportPrivateUsage]
        name = f"link{index}.txt"
        (workspace / name).symlink_to(previous)
        previous = name

    handle = open_inspect_workspace(workspace)
    result = LocalWorkspaceInspectAdapter().inspect(WorkspaceInspectCommand(handle, (previous,)))
    assert result.status is WorkspaceInspectStatus.REJECTED
    assert WorkspaceInspectLimitation.SYMLINK_ESCAPE in result.limitations
    assert result.artifacts == ()


def test_absolute_symlink_target_is_refused(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target = workspace / "note.txt"
    target.write_text("absolute-target\n", encoding="utf-8")
    (workspace / "abs-link.txt").symlink_to(target.resolve())

    handle = open_inspect_workspace(workspace)
    result = LocalWorkspaceInspectAdapter().inspect(
        WorkspaceInspectCommand(handle, ("abs-link.txt",))
    )
    assert result.status is WorkspaceInspectStatus.REJECTED
    assert WorkspaceInspectLimitation.SYMLINK_ESCAPE in result.limitations
    assert result.artifacts == ()


def test_content_changing_read_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target = workspace / "note.txt"
    original = b"stable-bytes-0123456789\n"
    target.write_bytes(original)

    real_read = workspace_inspect_module.os.read
    mutated = {"done": False}

    def flaky_read(fd: int, n: int) -> bytes:
        if not mutated["done"]:
            mutated["done"] = True
            # Same-inode rewrite so the open descriptor's fstat changes mid-read.
            # (os.replace would swap the directory entry while leaving this fd on
            # the original inode, which would not exercise the change check.)
            with open(target, "wb") as handle:
                handle.write(b"MUTATED-SECRET-should-not-appear\n")
                handle.flush()
                os.fsync(handle.fileno())
        return real_read(fd, n)

    monkeypatch.setattr(workspace_inspect_module.os, "read", flaky_read)
    handle = open_inspect_workspace(workspace)
    result = LocalWorkspaceInspectAdapter().inspect(WorkspaceInspectCommand(handle, ("note.txt",)))
    assert result.status is WorkspaceInspectStatus.REJECTED
    assert WorkspaceInspectLimitation.READ_FAILED in result.limitations
    assert result.artifacts == ()
    assert "MUTATED-SECRET" not in repr(result)


def test_unusable_workspace_payload_is_refused(tmp_path: Path) -> None:
    payload = SimpleNamespace(root=tmp_path)
    handle = LocalWorkspaceHandle._from_validated_descriptor(  # pyright: ignore[reportPrivateUsage]
        payload
    )
    result = LocalWorkspaceInspectAdapter().inspect(WorkspaceInspectCommand(handle, ("note.txt",)))
    assert result.status is WorkspaceInspectStatus.REJECTED
    assert result.limitations == (WorkspaceInspectLimitation.UNSAFE_ROOT,)
    assert result.artifacts == ()
    assert result.selection_digest is None
