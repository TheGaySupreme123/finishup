from __future__ import annotations

import hashlib
import hmac
import os
import subprocess
from pathlib import Path

import pytest

from finishup.adapters.repository_identity import (
    RepositoryIdentityError,
    resolve_repository_privacy_context,
)
from finishup.ports.control import WorkspaceLocator


class _MacKey:
    def mac(self, domain: bytes, message: bytes) -> str:
        digest = hmac.new(b"installation-test-key", domain + message, hashlib.sha256).hexdigest()
        return f"hmac-sha256:{digest}"


def _git(*arguments: str) -> None:
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=FinishUP Test",
            "-c",
            "user.email=test@finishup.invalid",
            *arguments,
        ],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={"PATH": os.defpath, "LANG": "C", "LC_ALL": "C"},
    )


def _repository(path: Path) -> None:
    path.mkdir()
    _git("-C", os.fspath(path), "init")
    (path / "tracked.txt").write_text("tracked\n", encoding="utf-8")
    _git("-C", os.fspath(path), "add", "tracked.txt")
    _git("-C", os.fspath(path), "commit", "-m", "initial")


@pytest.mark.anyio
async def test_git_branches_linked_worktrees_and_symlinks_share_identity(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    linked = tmp_path / "linked"
    alias = tmp_path / "alias"
    _repository(repository)
    _git("-C", os.fspath(repository), "branch", "other")
    _git("-C", os.fspath(repository), "worktree", "add", os.fspath(linked), "other")
    alias.symlink_to(repository, target_is_directory=True)

    key = _MacKey()
    root = await resolve_repository_privacy_context(WorkspaceLocator(os.fspath(repository)), key)
    nested = await resolve_repository_privacy_context(WorkspaceLocator(os.fspath(repository)), key)
    linked_context = await resolve_repository_privacy_context(
        WorkspaceLocator(os.fspath(linked)), key
    )
    alias_context = await resolve_repository_privacy_context(
        WorkspaceLocator(os.fspath(alias)), key
    )

    assert root.identity_kind == "git_common_root"
    assert root == nested == linked_context == alias_context


@pytest.mark.anyio
async def test_independent_clone_has_a_distinct_identity(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    clone = tmp_path / "clone"
    _repository(repository)
    _git("clone", os.fspath(repository), os.fspath(clone))

    original = await resolve_repository_privacy_context(
        WorkspaceLocator(os.fspath(repository)), _MacKey()
    )
    independent = await resolve_repository_privacy_context(
        WorkspaceLocator(os.fspath(clone)), _MacKey()
    )

    assert original.identity_kind == independent.identity_kind == "git_common_root"
    assert original.commitment != independent.commitment


@pytest.mark.anyio
async def test_non_git_directory_uses_resolved_directory_identity(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    alias = tmp_path / "alias"
    first.mkdir()
    second.mkdir()
    alias.symlink_to(first, target_is_directory=True)

    first_context = await resolve_repository_privacy_context(
        WorkspaceLocator(os.fspath(first)), _MacKey()
    )
    repeated = await resolve_repository_privacy_context(
        WorkspaceLocator(os.fspath(first)), _MacKey()
    )
    alias_context = await resolve_repository_privacy_context(
        WorkspaceLocator(os.fspath(alias)), _MacKey()
    )
    second_context = await resolve_repository_privacy_context(
        WorkspaceLocator(os.fspath(second)), _MacKey()
    )

    assert first_context.identity_kind == "directory"
    assert first_context == repeated == alias_context
    assert first_context.commitment != second_context.commitment


@pytest.mark.anyio
async def test_locator_failures_are_bounded_and_do_not_echo_path(tmp_path: Path) -> None:
    missing = tmp_path / "private-secret-name"
    with pytest.raises(RepositoryIdentityError) as caught:
        await resolve_repository_privacy_context(WorkspaceLocator(os.fspath(missing)), _MacKey())

    assert caught.value.reason == "repository_locator_unavailable"
    assert os.fspath(missing) not in repr(caught.value)
    assert os.fspath(missing) not in str(caught.value)


def test_workspace_locator_is_absolute_bounded_and_hides_path_from_repr() -> None:
    locator = WorkspaceLocator("/private/repository-name")
    assert "repository-name" not in repr(locator)
    with pytest.raises(ValueError, match="workspace_locator_path_invalid"):
        WorkspaceLocator("relative")
    with pytest.raises(ValueError, match="workspace_locator_path_invalid"):
        WorkspaceLocator("/private/bad\npath")
