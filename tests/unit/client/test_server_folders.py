"""The folders a remote target's server may read here: this client's own record (ADR-051).

``finishup server folders add`` records them under the target's root; the workspace agent reads
the active target's record on every outside read and admits nothing when it cannot. The record
is owner-only canonical JSON bound to its target, and a folder that holds the home directory, or
lies in its private trees, is never admitted.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Iterator
from pathlib import Path

import pytest

from builders.server_targets import ambient_home
from finishup.client import targets
from finishup.client.server_folders import (
    FOLDERS_SCHEMA,
    MAX_FOLDERS,
    FolderError,
    active_target_folders,
    add_folder,
    clear_folders,
    folder_covers,
    folder_holds_home,
    folders_path,
    read_folders,
    remove_folder,
)
from finishup.config.paths import reset_selection_memo


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as root:
        yield root


@pytest.fixture
def remote(home: Path) -> tuple[targets.ServerTarget, Path]:
    del home
    with targets.registry_lock():
        return targets.new_remote_target("lab", "https", base_url="https://lab.example")


@pytest.fixture
def folder(tmp_path: Path) -> str:
    shared = (tmp_path / "shared").resolve()
    shared.mkdir()
    return os.fspath(shared)


def test_no_record_admits_nothing(remote: tuple[targets.ServerTarget, Path]) -> None:
    record, root = remote
    assert read_folders(root, record.target_id) == ()
    assert not folders_path(root).exists()


def test_a_folder_is_recorded_owner_only_canonical_and_bound_to_its_target(
    remote: tuple[targets.ServerTarget, Path], folder: str, tmp_path: Path
) -> None:
    record, root = remote
    other = (tmp_path / "another").resolve()
    other.mkdir()
    assert add_folder(root, record.target_id, folder) is True
    assert add_folder(root, record.target_id, folder) is False  # already admitted
    assert add_folder(root, record.target_id, os.fspath(other)) is True
    path = folders_path(root)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    expected = sorted((folder, os.fspath(other)), key=str.encode)
    assert read_folders(root, record.target_id) == tuple(expected)
    body = path.read_bytes()
    assert body == (
        b'{"folders":['
        + b",".join(b'"' + item.encode() + b'"' for item in expected)
        + b'],"schema":"'
        + FOLDERS_SCHEMA.encode()
        + b'","target_id":"'
        + record.target_id.encode()
        + b'"}\n'
    )
    # Another target's record is never taken for this one's.
    with pytest.raises(FolderError, match="folders_record_invalid"):
        read_folders(root, "t_00000000")


def test_remove_and_clear_are_the_way_out(
    remote: tuple[targets.ServerTarget, Path], folder: str
) -> None:
    record, root = remote
    add_folder(root, record.target_id, folder)
    assert remove_folder(root, record.target_id, folder + "/") is True  # compared in normal form
    assert read_folders(root, record.target_id) == ()
    assert remove_folder(root, record.target_id, folder) is False
    add_folder(root, record.target_id, folder)
    assert clear_folders(root) is True
    assert clear_folders(root) is False
    assert read_folders(root, record.target_id) == ()


@pytest.mark.parametrize(
    "damage",
    ["mode", "link", "json", "unsorted", "extra_field", "bad_folder"],
)
def test_a_damaged_record_fails_closed_and_clear_removes_it(
    remote: tuple[targets.ServerTarget, Path], folder: str, tmp_path: Path, damage: str
) -> None:
    record, root = remote
    add_folder(root, record.target_id, folder)
    path = folders_path(root)
    text = path.read_text()
    if damage == "mode":
        path.chmod(0o644)
    elif damage == "link":
        target = tmp_path / "elsewhere.json"
        target.write_text(text)
        target.chmod(0o600)
        path.unlink()
        path.symlink_to(target)
    elif damage == "json":
        path.write_text("{not json\n")
    elif damage == "unsorted":
        path.write_text(text.replace(f'["{folder}"]', f'["{folder}/z","{folder}"]'))
    elif damage == "extra_field":
        path.write_text(text.replace('{"folders"', '{"extra":1,"folders"'))
    else:
        path.write_text(text.replace(f'"{folder}"', '"/etc"'))
    reason = "folders_record_unsafe" if damage in {"mode", "link"} else "folders_record_invalid"
    with pytest.raises(FolderError, match=reason):
        read_folders(root, record.target_id)
    # Adding to a damaged record never replaces it; clearing it is the way back.
    with pytest.raises(FolderError):
        add_folder(root, record.target_id, folder)
    assert clear_folders(root) is True
    assert read_folders(root, record.target_id) == ()
    if damage == "link":
        assert (tmp_path / "elsewhere.json").exists()  # the link went, never its target


def test_a_folder_that_holds_home_or_lies_in_its_private_trees_is_never_admitted(
    remote: tuple[targets.ServerTarget, Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record, root = remote
    user_home = (tmp_path / "users" / "me").resolve()
    (user_home / "Library" / "Mail").mkdir(parents=True)
    (user_home / "projects").mkdir()
    monkeypatch.setenv("HOME", os.fspath(user_home))
    alias = tmp_path / "home-alias"
    alias.symlink_to(user_home)
    for refused in (
        os.fspath(user_home),
        os.fspath(user_home.parent),
        os.fspath(user_home / "Library" / "Mail"),
        os.fspath(alias),  # the home directory under another spelling, by identity
        "relative/folder",
        "/etc",
        os.fspath(tmp_path / ".hidden"),
        os.fspath(tmp_path / "missing"),
    ):
        with pytest.raises(FolderError, match="folder_invalid"):
            add_folder(root, record.target_id, refused)
    assert add_folder(root, record.target_id, os.fspath(user_home / "projects")) is True
    assert folder_holds_home(os.fspath(user_home.parent))
    assert not folder_holds_home(os.fspath(user_home / "projects"))


def test_at_most_the_bound_is_admitted(
    remote: tuple[targets.ServerTarget, Path], tmp_path: Path
) -> None:
    record, root = remote
    for index in range(MAX_FOLDERS):
        folder = tmp_path / f"f{index:02d}"
        folder.mkdir()
        add_folder(root, record.target_id, os.fspath(folder.resolve()))
    extra = tmp_path / "extra"
    extra.mkdir()
    with pytest.raises(FolderError, match="folder_limit"):
        add_folder(root, record.target_id, os.fspath(extra.resolve()))


def test_covering_is_by_exact_spelling_at_or_beneath_a_folder() -> None:
    folders = ("/srv/shared",)
    assert folder_covers("/srv/shared", folders)
    assert folder_covers("/srv/shared/data/rows.csv", folders)
    assert not folder_covers("/srv/shared-other/rows.csv", folders)
    assert not folder_covers("/srv/SHARED/rows.csv", folders)
    assert not folder_covers("/srv", folders)


def test_the_active_target_record_admits_and_fails_closed(
    remote: tuple[targets.ServerTarget, Path], folder: str, home: Path
) -> None:
    record, root = remote
    add_folder(root, record.target_id, folder)
    # Not selected: this process uses the everyday installation, which admits nothing here.
    assert active_target_folders() == ()
    with targets.registry_lock():
        targets.write_selection(record)
    reset_selection_memo()
    assert active_target_folders() == (folder,)
    folders_path(root).chmod(0o644)  # an unreadable record admits nothing
    assert active_target_folders() == ()
    folders_path(root).chmod(0o600)
    # A named local server reads with its own service: no folder record applies to it.
    with targets.registry_lock():
        local, _local_root = targets.new_local_target("bench")
        targets.write_selection(local)
    reset_selection_memo()
    assert active_target_folders() == ()
    del home
