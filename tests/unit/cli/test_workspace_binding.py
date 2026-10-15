"""Focused tests for host workspace-root selection and Git normalization."""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

import pytest

from finishup.cli.workspace_binding import canonical_workspace_locator, resolve_workspace_locator


def _env(home: Path, **values: str) -> dict[str, str]:
    return {"HOME": os.fspath(home), **values}


def _git(root: Path, *, worktree_file: bool = False) -> None:
    root.mkdir(parents=True, exist_ok=True)
    marker = root / ".git"
    if worktree_file:
        marker.write_text("gitdir: /private/git/worktree\n", encoding="utf-8")
    else:
        marker.mkdir()


def test_single_host_root_precedes_environment_and_explicit(tmp_path: Path) -> None:
    home = tmp_path / "home"
    host_root = tmp_path / "host"
    env_root = tmp_path / "env"
    explicit = tmp_path / "explicit"
    for root in (host_root, env_root, explicit):
        root.mkdir()

    actual = resolve_workspace_locator(
        explicit=os.fspath(explicit),
        payload={"workspace_roots": [os.fspath(host_root)]},
        env=_env(home, CURSOR_PROJECT_DIR=os.fspath(env_root)),
    )

    assert actual == os.fspath(host_root)


def test_multi_root_chooses_deepest_root_containing_cursor_project(tmp_path: Path) -> None:
    home = tmp_path / "home"
    outer = tmp_path / "repo"
    nested = outer / "packages" / "app"
    cursor_dir = nested / "src"
    cursor_dir.mkdir(parents=True)

    actual = resolve_workspace_locator(
        explicit=os.fspath(tmp_path / "explicit"),
        payload={
            "workspace_roots": [os.fspath(outer), os.fspath(nested)],
        },
        env=_env(home, CURSOR_PROJECT_DIR=os.fspath(cursor_dir)),
    )

    assert actual == os.fspath(nested)


def test_multi_root_without_cursor_ancestor_refuses_without_fallback(tmp_path: Path) -> None:
    home = tmp_path / "home"
    first = tmp_path / "first"
    second = tmp_path / "second"
    cursor_dir = tmp_path / "elsewhere"
    explicit = tmp_path / "explicit"
    for root in (first, second, cursor_dir, explicit):
        root.mkdir()

    assert (
        resolve_workspace_locator(
            explicit=os.fspath(explicit),
            payload={"workspace_roots": [os.fspath(first), os.fspath(second)]},
            env=_env(home, CURSOR_PROJECT_DIR=os.fspath(cursor_dir)),
        )
        is None
    )


def test_environment_precedes_explicit_and_normalizes_git_toplevel(tmp_path: Path) -> None:
    home = tmp_path / "home"
    repository = tmp_path / "repo"
    nested = repository / "src" / "module"
    nested.mkdir(parents=True)
    _git(repository)

    actual = resolve_workspace_locator(
        explicit=os.fspath(tmp_path / "explicit"),
        payload={},
        env=_env(home, CURSOR_PROJECT_DIR=os.fspath(nested)),
    )

    assert actual == os.fspath(repository)


def test_explicit_locator_is_non_git_fallback(tmp_path: Path) -> None:
    home = tmp_path / "home"
    explicit = tmp_path / "non-git"
    explicit.mkdir()

    assert resolve_workspace_locator(explicit=explicit, payload={}, env=_env(home)) == os.fspath(
        explicit
    )


def test_explicit_canonical_locator_ignores_cursor_environment_and_uses_git_root(
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    repository = tmp_path / "repo"
    nested = repository / "packages/app"
    unrelated = tmp_path / "cursor-environment"
    nested.mkdir(parents=True)
    unrelated.mkdir()
    _git(repository)

    assert canonical_workspace_locator(
        nested,
        env=_env(home, CURSOR_PROJECT_DIR=os.fspath(unrelated)),
    ) == os.fspath(repository)


def test_explicit_canonical_locator_preserves_exact_non_git_workspace(tmp_path: Path) -> None:
    home = tmp_path / "home"
    workspace = tmp_path / "non-git"
    workspace.mkdir()

    assert canonical_workspace_locator(workspace, env=_env(home)) == os.fspath(workspace)


def test_nearest_nested_git_root_wins(tmp_path: Path) -> None:
    home = tmp_path / "home"
    outer = tmp_path / "repo"
    nested = outer / "nested"
    current = nested / "src"
    current.mkdir(parents=True)
    _git(outer)
    _git(nested)

    assert resolve_workspace_locator(
        explicit=os.fspath(current), payload={}, env=_env(home)
    ) == os.fspath(nested)


def test_worktree_git_file_is_a_toplevel_marker(tmp_path: Path) -> None:
    home = tmp_path / "home"
    worktree = tmp_path / "worktree"
    current = worktree / "src"
    current.mkdir(parents=True)
    _git(worktree, worktree_file=True)

    assert resolve_workspace_locator(
        explicit=os.fspath(current), payload={}, env=_env(home)
    ) == os.fspath(worktree)


def test_symlinked_git_marker_is_refused(tmp_path: Path) -> None:
    home = tmp_path / "home"
    outer = tmp_path / "outer"
    nested = outer / "nested"
    current = nested / "src"
    current.mkdir(parents=True)
    _git(outer)
    nested_git = tmp_path / "nested-git"
    nested_git.mkdir()
    (nested / ".git").symlink_to(nested_git, target_is_directory=True)

    assert (
        resolve_workspace_locator(explicit=os.fspath(current), payload={}, env=_env(home)) is None
    )


def test_group_writable_git_marker_is_refused(tmp_path: Path) -> None:
    home = tmp_path / "home"
    repository = tmp_path / "repo"
    current = repository / "src"
    current.mkdir(parents=True)
    _git(repository)
    (repository / ".git").chmod(0o777)

    assert (
        resolve_workspace_locator(explicit=os.fspath(current), payload={}, env=_env(home)) is None
    )


def test_symlinked_ancestor_is_refused(tmp_path: Path) -> None:
    home = tmp_path / "home"
    real = tmp_path / "real"
    linked = tmp_path / "linked"
    real_repo = real / "repo"
    real_repo.mkdir(parents=True)
    linked.symlink_to(real, target_is_directory=True)

    assert (
        resolve_workspace_locator(explicit=os.fspath(linked / "repo"), payload={}, env=_env(home))
        is None
    )


def test_home_is_a_walk_boundary(tmp_path: Path) -> None:
    home = tmp_path / "home"
    project = home / "project"
    project.mkdir(parents=True)
    _git(home)

    # A marker at HOME is never crossed or used as a repository identity.
    assert resolve_workspace_locator(
        explicit=os.fspath(project), payload={}, env=_env(home)
    ) == os.fspath(project)


def test_root_and_home_are_not_workspace_locators(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()

    assert resolve_workspace_locator(explicit=os.fspath(home), payload={}, env=_env(home)) is None
    assert (
        resolve_workspace_locator(explicit=os.path.abspath(os.sep), payload={}, env=_env(home))
        is None
    )


def test_path_text_preserves_exact_filesystem_spelling_and_is_bounded(tmp_path: Path) -> None:
    home = tmp_path / "home"
    raw = os.fspath(tmp_path / ("e\u0301"))
    Path(raw).mkdir()

    assert resolve_workspace_locator(explicit=raw, payload={}, env=_env(home)) == raw
    assert (
        resolve_workspace_locator(
            explicit="x" * 8_193,
            payload={},
            env=_env(home),
        )
        is None
    )
    assert resolve_workspace_locator(explicit="bad\npath", payload={}, env=_env(home)) is None


def test_no_locator_returns_none(tmp_path: Path) -> None:
    assert resolve_workspace_locator(payload={}, env=_env(tmp_path / "home")) is None


def test_invalid_or_oversized_workspace_roots_refuse_without_fallback(tmp_path: Path) -> None:
    home = tmp_path / "home"
    explicit = tmp_path / "explicit"
    explicit.mkdir()
    environment = _env(home, CURSOR_PROJECT_DIR=os.fspath(explicit))

    assert (
        resolve_workspace_locator(
            explicit=explicit,
            payload={"workspace_roots": "not-a-list"},
            env=environment,
        )
        is None
    )
    assert (
        resolve_workspace_locator(
            explicit=explicit,
            payload={"workspace_roots": [os.fspath(explicit)] * 33},
            env=environment,
        )
        is None
    )


def test_group_writable_workspace_is_refused(tmp_path: Path) -> None:
    home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    workspace.mkdir(mode=0o777)
    workspace.chmod(0o777)

    assert resolve_workspace_locator(explicit=workspace, payload={}, env=_env(home)) is None


def test_umask_0002_workspace_of_a_user_private_group_is_accepted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from finishup.config import foreign_write

    home = tmp_path / "home"
    repository = tmp_path / "repo"
    current = repository / "src"
    previous = os.umask(0o002)
    try:
        current.mkdir(parents=True)
        _git(repository)
    finally:
        os.umask(previous)
    for path in (repository, repository / ".git", current):
        path.chmod(0o775)
    monkeypatch.setattr(foreign_write, "owner_private_group", _private_group_is(True))
    assert resolve_workspace_locator(
        explicit=os.fspath(current), payload={}, env=_env(home)
    ) == os.fspath(repository)
    foreign_write.clear_cache()
    monkeypatch.setattr(foreign_write, "owner_private_group", _private_group_is(False))
    assert (
        resolve_workspace_locator(explicit=os.fspath(current), payload={}, env=_env(home)) is None
    )


def _private_group_is(value: bool) -> Callable[[int, int], bool]:
    def answer(_uid: int, _gid: int) -> bool:
        return value

    return answer


def _as_other_user_under_superuser(monkeypatch: pytest.MonkeyPatch) -> None:
    """Run as another account while the test runner's own uid plays the superuser (``/app``)."""
    from finishup.config import foreign_write

    real = os.geteuid()
    monkeypatch.setattr(foreign_write, "_SUPERUSER_UID", real)
    monkeypatch.setattr(os, "geteuid", lambda: real + 1)


@pytest.mark.skipif(not hasattr(os, "geteuid"), reason="POSIX ownership")
@pytest.mark.parametrize(("mode", "admitted"), [(0o755, True), (0o1777, True), (0o777, False)])
def test_superuser_owned_workspace_is_a_non_root_users_project(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: int, admitted: bool
) -> None:
    # A container image keeps /app root-owned (0755, or sticky 1777) and runs the agent as a
    # non-root USER; the workspace is still that user's project unless others can replace it.
    home = tmp_path / "home"
    workspace = tmp_path / "app"
    workspace.mkdir()
    workspace.chmod(mode)
    _as_other_user_under_superuser(monkeypatch)

    expected = os.fspath(workspace) if admitted else None
    assert resolve_workspace_locator(explicit=workspace, payload={}, env=_env(home)) == expected
    assert canonical_workspace_locator(workspace, env=_env(home)) == expected


@pytest.mark.skipif(not hasattr(os, "geteuid"), reason="POSIX ownership")
def test_another_non_root_users_workspace_stays_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from finishup.config import foreign_write

    home = tmp_path / "home"
    workspace = tmp_path / "theirs"
    workspace.mkdir(mode=0o755)
    real = os.geteuid()
    monkeypatch.setattr(foreign_write, "_SUPERUSER_UID", real + 7)
    monkeypatch.setattr(os, "geteuid", lambda: real + 1)

    assert resolve_workspace_locator(explicit=workspace, payload={}, env=_env(home)) is None
    assert canonical_workspace_locator(workspace, env=_env(home)) is None


@pytest.mark.skipif(not hasattr(os, "geteuid"), reason="POSIX ownership")
@pytest.mark.parametrize("worktree_file", [False, True], ids=["git_dir", "git_file"])
def test_superuser_owned_checkout_is_a_non_root_users_plain_project(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, worktree_file: bool
) -> None:
    """An image built as root (``COPY . /app`` or ``git clone``) with ``USER agent``.

    Before, the root-owned ``.git`` failed the locator closed, so ``setup run`` reported
    internal_error (workspace_locator_invalid) and hooks and MCP bound no workspace. The checkout
    is the project, used as a plain directory, from the root or any directory beneath it.
    """

    from finishup.cli.setup import _canonical_setup_workspace  # pyright: ignore[reportPrivateUsage]

    home = tmp_path / "home"
    app = tmp_path.resolve() / "app"
    _git(app, worktree_file=worktree_file)
    (app / "src").mkdir()
    app.chmod(0o755)
    _as_other_user_under_superuser(monkeypatch)

    for selected in (app, app / "src"):
        assert canonical_workspace_locator(selected, env=_env(home)) == os.fspath(app)
        assert resolve_workspace_locator(
            explicit=selected, payload={}, env=_env(home)
        ) == os.fspath(app)
        assert resolve_workspace_locator(
            payload={"workspace_roots": [os.fspath(selected)]}, env=_env(home)
        ) == os.fspath(app)
    assert _canonical_setup_workspace(app / "src") == app


@pytest.mark.skipif(not hasattr(os, "geteuid"), reason="POSIX ownership")
@pytest.mark.parametrize("marker_owner", ["other_user", "superuser_shared"])
def test_a_checkout_marker_another_account_controls_still_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, marker_owner: str
) -> None:
    from finishup.config import foreign_write

    home = tmp_path / "home"
    app = tmp_path.resolve() / "app"
    _git(app)
    app.chmod(0o755)
    real = os.geteuid()
    if marker_owner == "superuser_shared":
        (app / ".git").chmod(0o777)
        monkeypatch.setattr(foreign_write, "_SUPERUSER_UID", real)
    else:
        # The runner's uid plays a second non-root account that owns the checkout.
        monkeypatch.setattr(foreign_write, "_SUPERUSER_UID", real + 7)
    monkeypatch.setattr(os, "geteuid", lambda: real + 1)

    assert canonical_workspace_locator(app, env=_env(home)) is None
    assert resolve_workspace_locator(explicit=app, payload={}, env=_env(home)) is None


@pytest.mark.skipif(not hasattr(os, "geteuid"), reason="POSIX ownership")
@pytest.mark.parametrize(
    ("links", "admitted"), [(1, True), (2, False)], ids=["single", "hard_link"]
)
def test_a_root_owned_gitfile_counts_only_when_nobody_could_have_linked_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, links: int, admitted: bool
) -> None:
    """In a sticky shared directory anyone can plant a hard link to a root-owned file; such a
    ``.git`` proves nothing about who made the checkout and must not move the locator."""

    from tests.builders.ownership import SUPERUSER, present_owners

    home = tmp_path / "home"
    app = tmp_path.resolve() / "app"
    app.mkdir()
    gitfile = app / ".git"
    gitfile.write_text("gitdir: /private/git/worktree\n", encoding="utf-8")
    if links == 2:
        os.link(gitfile, tmp_path.resolve() / "elsewhere")
    app.chmod(0o1777)
    present_owners(monkeypatch, {app: SUPERUSER, gitfile: SUPERUSER})

    expected = os.fspath(app) if admitted else None
    assert canonical_workspace_locator(app, env=_env(home)) == expected
    assert resolve_workspace_locator(explicit=app, payload={}, env=_env(home)) == expected
