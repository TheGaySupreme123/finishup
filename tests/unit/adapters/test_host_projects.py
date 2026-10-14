"""The connected-projects record shared by the host adapters (#1058)."""

from __future__ import annotations

import os
import threading
from pathlib import Path

import pytest

from yoetz.adapters.integrations import host_projects
from yoetz.adapters.integrations.host_projects import (
    CONNECTED_PROJECTS_FILE,
    HostProjectsError,
    host_config_lock,
    load_connected_projects,
    write_connected_projects,
)


def _root(tmp_path: Path) -> Path:
    root = tmp_path / "config"
    root.mkdir(mode=0o700)
    return root


def test_unknown_members_round_trip_and_survive_an_empty_project_set(tmp_path: Path) -> None:
    root = _root(tmp_path)
    write_connected_projects(load_connected_projects(root), ("/work/a",), unknown_members=True)
    snapshot = load_connected_projects(root)
    assert snapshot.projects == ("/work/a",) and snapshot.unknown_members is True

    # The last recorded project leaves, but unknown members may still use the shared pieces.
    write_connected_projects(snapshot, (), unknown_members=True)
    after = load_connected_projects(root)
    assert after.raw is not None and after.projects == () and after.unknown_members is True

    write_connected_projects(after, ())
    assert not (root / CONNECTED_PROJECTS_FILE).exists()


@pytest.mark.parametrize("mode", [0o640, 0o604, 0o644])
def test_record_readable_by_others_is_refused(tmp_path: Path, mode: int) -> None:
    root = _root(tmp_path)
    record = root / CONNECTED_PROJECTS_FILE
    record.write_text('{"projects":[]}\n')
    record.chmod(mode)

    with pytest.raises(HostProjectsError):
        load_connected_projects(root)


def test_publication_and_removal_sync_the_parent_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _root(tmp_path)
    synced: list[Path] = []
    real = host_projects._sync_directory  # pyright: ignore[reportPrivateUsage]

    def record(directory: Path) -> None:
        synced.append(directory)
        real(directory)

    monkeypatch.setattr(host_projects, "_sync_directory", record)
    write_connected_projects(load_connected_projects(root), ("/work/a",))
    write_connected_projects(load_connected_projects(root), ())
    # The record's own directory is synced after the publication and after the removal; the
    # membership witness syncs its own (private) directory.
    assert [directory for directory in synced if directory == root] == [root, root]
    witness_directory = host_projects.witness_path_for(root).parent
    assert set(synced) <= {root, witness_directory}


def test_the_witness_remembers_members_after_the_record_is_deleted(tmp_path: Path) -> None:
    """#1058 review P2-4: a deleted record does not make this installation forget members."""

    root = _root(tmp_path)
    write_connected_projects(load_connected_projects(root), ("/work/a",))
    write_connected_projects(load_connected_projects(root), ("/work/a", "/work/b"))
    witness = host_projects.witness_path_for(root)
    assert witness.stat().st_mode & 0o777 == 0o600
    (root / CONNECTED_PROJECTS_FILE).unlink()
    assert host_projects.recorded_members(root) == ("/work/a", "/work/b")

    # A rewrite after the loss keeps the unrecorded member; a departure removes only that one.
    write_connected_projects(load_connected_projects(root), ("/work/c",), departed=("/work/a",))
    assert host_projects.recorded_members(root) == ("/work/b", "/work/c")
    # Removing the shared pieces forgets everyone.
    write_connected_projects(load_connected_projects(root), (), shared_removed=True)
    assert host_projects.recorded_members(root) == ()
    assert not witness.exists()


def test_host_config_lock_excludes_a_second_holder(tmp_path: Path) -> None:
    root = _root(tmp_path)
    inside = threading.Event()
    release = threading.Event()
    order: list[str] = []

    def first() -> None:
        with host_config_lock(root):
            order.append("first-in")
            inside.set()
            release.wait(timeout=30)
            order.append("first-out")

    thread = threading.Thread(target=first)
    thread.start()
    assert inside.wait(timeout=30)
    # The second holder must not get in while the first holds the lock.
    import fcntl

    descriptor = os.open(host_projects.lock_path_for(root), os.O_RDWR)
    try:
        with pytest.raises(BlockingIOError):
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        os.close(descriptor)
    release.set()
    thread.join(timeout=30)
    with host_config_lock(root):
        order.append("second")
    assert order == ["first-in", "first-out", "second"]


def test_lock_needs_no_part_of_an_absent_nested_config_root(tmp_path: Path) -> None:
    """CHECK_MULTIPROJ_R2 P2-R2-2: a first setup into a root whose parents do not exist yet."""

    root = tmp_path / "new-profile" / "nested" / "config"
    with host_config_lock(root):
        pass
    assert not (tmp_path / "new-profile").exists()
    lock = host_projects.lock_path_for(root)
    assert lock.stat().st_mode & 0o777 == 0o600


def test_unrelated_roots_with_one_parent_do_not_share_a_lock(tmp_path: Path) -> None:
    import fcntl

    first, second = tmp_path / ".codex", tmp_path / ".cursor"
    assert host_projects.lock_path_for(first) != host_projects.lock_path_for(second)
    with host_config_lock(first):
        with host_config_lock(second):
            pass
        descriptor = os.open(host_projects.lock_path_for(first), os.O_RDWR)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(descriptor)


def test_a_filesystem_that_cannot_lock_is_a_specific_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import errno
    import fcntl

    def refuse(_descriptor: int, _operation: int) -> None:
        raise OSError(errno.ENOLCK, "no locks")

    monkeypatch.setattr(fcntl, "flock", refuse)
    with pytest.raises(HostProjectsError) as caught:
        with host_config_lock(tmp_path / "config"):
            raise AssertionError("must not run unlocked")
    assert caught.value.reason == "lock_unavailable"


def test_record_file_name_is_a_frozen_legacy_literal(tmp_path: Path) -> None:
    """An upgraded install keeps the records earlier builds wrote (#1058, ADR-048 rename).

    The name must not follow the MCP server key: a renamed key would otherwise make every
    existing record invisible, and a missing record turns known members into unknown ones.
    """

    import ast

    assert CONNECTED_PROJECTS_FILE == ".yoetz-connected-projects.json"
    source = Path(host_projects.__file__).read_text(encoding="utf-8")
    values = [
        node.value
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.AnnAssign)
        and isinstance(node.target, ast.Name)
        and node.target.id == "CONNECTED_PROJECTS_FILE"
    ]
    assert len(values) == 1 and isinstance(values[0], ast.Constant)
    # A record an earlier build wrote under that exact name is read as is.
    root = _root(tmp_path)
    record = root / ".yoetz-connected-projects.json"
    record.write_bytes(b'{"projects":["/work/a"]}\n')
    record.chmod(0o600)
    assert load_connected_projects(root).projects == ("/work/a",)


def test_case_and_unicode_spellings_of_one_root_share_a_lock(tmp_path: Path) -> None:
    """A case-insensitive or normalising filesystem (macOS) names one root several ways.

    Every spelling must reach the same lock; distinct roots that differ only in case merely
    serialise against each other, which is harmless.
    """

    import unicodedata

    assert host_projects.lock_path_for(tmp_path / ".Cursor") == host_projects.lock_path_for(
        tmp_path / ".cursor"
    )
    composed = unicodedata.normalize("NFC", "café")
    decomposed = unicodedata.normalize("NFD", composed)
    assert composed != decomposed
    assert host_projects.lock_path_for(tmp_path / composed) == host_projects.lock_path_for(
        tmp_path / decomposed
    )


def test_losing_the_race_to_create_the_lock_directory_still_locks(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Two first setups may both find the lock directory missing; the loser must not fail."""

    from yoetz.config import paths

    real = paths.ensure_owner_only_dir
    calls: list[Path] = []

    def racing(path: Path) -> None:
        calls.append(path)
        if len(calls) == 1:
            # Another setup created the directory between the existence check and mkdir.
            path.mkdir(mode=0o700, parents=True)
            raise paths.PathSafetyError("permissions_too_broad")
        real(path)

    monkeypatch.setattr(paths, "ensure_owner_only_dir", racing)
    with host_config_lock(tmp_path / "config"):
        pass
    assert len(calls) == 2
