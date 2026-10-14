"""Focused tests for host workspace-root selection and Git normalization."""

from __future__ import annotations

import os
from pathlib import Path

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
