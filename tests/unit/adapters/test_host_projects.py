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
    assert synced == [root, root]


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

    descriptor = os.open(root.parent, os.O_RDONLY)
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
