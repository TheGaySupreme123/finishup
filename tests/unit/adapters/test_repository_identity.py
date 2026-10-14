from __future__ import annotations

import hashlib
import hmac
import os
import subprocess
from pathlib import Path

import pytest

from yoetz.adapters.repository_identity import (
    RepositoryIdentityError,
    resolve_repository_privacy_context,
)
from yoetz.ports.control import WorkspaceLocator


class _MacKey:
    def mac(self, domain: bytes, message: bytes) -> str:
        digest = hmac.new(b"installation-test-key", domain + message, hashlib.sha256).hexdigest()
        return f"hmac-sha256:{digest}"


def _git(*arguments: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=Yoetz Test", "-c", "user.email=test@yoetz.invalid", *arguments],
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


# --- A checkout root owns, served to a non-root user (ADR-007, 2026-10-14) -----------------
#
# An image built as root keeps /app and /app/.git root-owned and runs the agent as a non-root
# USER. Git refuses another owner's checkout ("dubious ownership"), so before, every service
# handshake for that workspace failed with repository_identity_unavailable. The real-ownership
# tests need root to chown; the simulated one runs anywhere and proves Git is never run.

_ROOT_PLAYED_BY = 41004
_ANOTHER_USER = 41005
_needs_root = pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() != 0, reason="chown needs root"
)


def _chown_tree(path: Path, uid: int) -> None:
    for directory, _subdirectories, files in os.walk(path):
        os.chown(directory, uid, uid)
        for name in files:
            os.chown(os.path.join(directory, name), uid, uid)


def _directory_commitment(path: Path) -> str:
    from yoetz.ports.keys import REPOSITORY_PRIVACY_MAC_DOMAIN

    return _MacKey().mac(
        REPOSITORY_PRIVACY_MAC_DOMAIN, b"directory\x00" + os.fsencode(path.resolve())
    )


@_needs_root
@pytest.mark.anyio
@pytest.mark.parametrize("layout", ["root_checkout", "user_git_init_in_sticky_root"])
async def test_a_checkout_root_owns_keeps_the_plain_directory_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, layout: str
) -> None:
    from yoetz.config import foreign_write

    # The runner is the non-root user; uid _ROOT_PLAYED_BY plays root. Git sees the same
    # mismatch it sees in the container (owner != euid) and refuses.
    monkeypatch.setattr(foreign_write, "_SUPERUSER_UID", _ROOT_PLAYED_BY)
    app = tmp_path.resolve() / "app"
    _repository(app)
    if layout == "root_checkout":
        _chown_tree(app, _ROOT_PLAYED_BY)
        app.chmod(0o755)
    else:
        os.chown(app, _ROOT_PLAYED_BY, _ROOT_PLAYED_BY)
        app.chmod(0o1777)

    context = await resolve_repository_privacy_context(WorkspaceLocator(os.fspath(app)), _MacKey())

    assert context.identity_kind == "directory"
    assert context.commitment == _directory_commitment(app)


@_needs_root
@pytest.mark.anyio
@pytest.mark.parametrize("layout", ["another_users_checkout", "hard_linked_root_marker"])
async def test_a_checkout_another_account_controls_is_still_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, layout: str
) -> None:
    from yoetz.config import foreign_write

    monkeypatch.setattr(foreign_write, "_SUPERUSER_UID", _ROOT_PLAYED_BY)
    if layout == "another_users_checkout":
        app = tmp_path.resolve() / "app"
        _repository(app)
        _chown_tree(app, _ANOTHER_USER)
        app.chmod(0o755)
    else:
        # A sticky shared directory: another account plants a hard link to a root-owned gitfile.
        repository = tmp_path.resolve() / "repository"
        _repository(repository)
        app = tmp_path.resolve() / "shared" / "app"
        app.parent.mkdir()
        app.mkdir()
        gitfile = tmp_path.resolve() / "root-gitfile"
        gitfile.write_text(f"gitdir: {repository / '.git'}\n", encoding="utf-8")
        os.link(gitfile, app / ".git")
        os.chown(gitfile, _ROOT_PLAYED_BY, _ROOT_PLAYED_BY)
        os.chown(app, _ROOT_PLAYED_BY, _ROOT_PLAYED_BY)
        app.chmod(0o1777)
        assert (app / ".git").stat().st_nlink == 2

    with pytest.raises(RepositoryIdentityError) as refused:
        await resolve_repository_privacy_context(WorkspaceLocator(os.fspath(app)), _MacKey())
    assert refused.value.reason == "repository_identity_unavailable"


@pytest.mark.anyio
async def test_a_checkout_root_owns_is_never_handed_to_git(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Simulated ownership (any runner): the identity is decided before Git would run."""

    import shutil

    from tests.builders.ownership import SUPERUSER, present_owners

    app = tmp_path.resolve() / "app"
    _repository(app)
    app.chmod(0o755)
    present_owners(monkeypatch, {app: SUPERUSER, app / ".git": SUPERUSER})

    def no_git(*_args: object, **_kwargs: object) -> str | None:
        raise AssertionError("Git ran against another owner's checkout")

    monkeypatch.setattr(shutil, "which", no_git)
    context = await resolve_repository_privacy_context(WorkspaceLocator(os.fspath(app)), _MacKey())
    assert context.identity_kind == "directory"
