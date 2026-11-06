"""What a remote target's server may read here outside a project: this client's own record
(ADR-051 decision 5).

Each target has an outside-read mode: ``local`` (as a FinishUP service on this computer would
read) or ``listed`` (only beneath the folders ``finishup server folders add`` records under the
target's root), the same two for every remote kind. There is no default per kind: with no mode
recorded a target is ``listed``, except an official FinishUP endpoint, which is ``local``. A
workspace agent is bound to its own target's record when it
is built, reads it on every outside read, and reads ``listed`` with no folder when it cannot. The
record is owner-only canonical JSON bound to its target, and a folder that holds the home
directory, or lies in its private trees, is never admitted.
"""

from __future__ import annotations

import base64
import os
import stat
from collections.abc import Iterator
from pathlib import Path
from typing import cast

import pytest

from builders.server_targets import ambient_home
from finishup.client import server_folders, targets
from finishup.client.server_folders import (
    FOLDERS_SCHEMA,
    MAX_FOLDERS,
    OFFICIAL_ENDPOINT_HOSTS,
    FolderError,
    FolderRecord,
    OutsideReadMode,
    OutsideReads,
    OutsideReadSource,
    add_folder,
    clear_folders,
    folder_admissible,
    folder_covers,
    folder_holds_home,
    folders_path,
    official_address,
    official_endpoint,
    outside_reads_of,
    outside_reads_reader,
    read_folders,
    read_record,
    remove_folder,
    set_mode,
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


_NOTHING: OutsideReads = OutsideReads("listed", (), "unreadable")


def _listed(*folders: str) -> OutsideReads:
    """What a target with no mode chosen reads: ``listed``, whatever its kind."""

    return OutsideReads("listed", folders, "not_chosen")


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
    assert clear_folders(root, record.target_id) == "cleared"
    assert clear_folders(root, record.target_id) == "absent"
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
    # Adding to a damaged record, or setting its mode, never replaces it; clearing it is the way
    # back, to the 'listed' state with no folder that a damaged record already stood for.
    with pytest.raises(FolderError):
        add_folder(root, record.target_id, folder)
    with pytest.raises(FolderError):
        set_mode(root, record.target_id, "local")
    assert outside_reads_of(root, record) == _NOTHING
    assert clear_folders(root, record.target_id) == "reset_to_listed"
    assert read_record(root, record.target_id) == FolderRecord((), "listed")
    assert not folders_path(root).is_symlink()
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
    salt = base64.b64decode(record.claim_salt or "", validate=True)
    add_folder(root, record.target_id, folder)
    # Not selected: this process uses the everyday installation, which admits nothing here.
    assert outside_reads_reader(claim_salt=salt)() == _NOTHING
    with targets.registry_lock():
        targets.write_selection(record)
    reset_selection_memo()
    assert outside_reads_reader(claim_salt=salt)() == _listed(folder)
    folders_path(root).chmod(0o644)  # an unreadable record admits nothing
    assert outside_reads_reader(claim_salt=salt)() == _NOTHING
    folders_path(root).chmod(0o600)
    # A named local server reads with its own service: no folder record applies to it.
    with targets.registry_lock():
        local, _local_root = targets.new_local_target("bench")
        targets.write_selection(local)
    reset_selection_memo()
    assert outside_reads_reader(claim_salt=salt)() == _NOTHING
    del home


def test_the_selection_alone_never_binds_a_reader(
    remote: tuple[targets.ServerTarget, Path], folder: str, home: Path
) -> None:
    """An agent may serve another server than the one this process selects (a background agent
    for one target, started by a process whose selection names another): with neither the
    target's root nor the claim's salt there is no telling which record is its own, so the reader
    admits nothing, even while the selected target admits a folder."""

    del home
    record, root = remote
    add_folder(root, record.target_id, folder)
    with targets.registry_lock():
        targets.write_selection(record)
    reset_selection_memo()
    assert outside_reads_reader(root)() == _listed(folder)
    assert outside_reads_reader()() == _NOTHING


def test_a_reader_is_bound_to_one_target_and_reads_its_record_on_every_call(
    remote: tuple[targets.ServerTarget, Path], folder: str, home: Path
) -> None:
    del home
    record, root = remote
    with targets.registry_lock():
        targets.write_selection(record)
    reset_selection_memo()
    by_root = outside_reads_reader(root)
    salt = base64.b64decode(record.claim_salt or "", validate=True)
    by_salt = outside_reads_reader(claim_salt=salt)
    assert by_root() == by_salt() == _listed()
    add_folder(root, record.target_id, folder)  # read at the next call, never cached
    assert by_root() == by_salt() == _listed(folder) == outside_reads_of(root, record)
    # Bound when built: another selection later changes nothing for these readers.
    with targets.registry_lock():
        other, other_root = targets.new_remote_target(
            "bench", "https", base_url="https://b.example"
        )
        targets.write_selection(other)
    reset_selection_memo()
    assert by_root() == by_salt() == _listed(folder)
    # A salt that is not the selected target's, a local root and a missing root admit nothing.
    assert outside_reads_reader(claim_salt=salt)() == _NOTHING
    assert outside_reads_reader(other_root, claim_salt=salt)() == _NOTHING
    assert outside_reads_reader(root, claim_salt=b"x" * 32)() == _NOTHING
    assert outside_reads_reader(root.parent / "t_00000000")() == _NOTHING
    # A record that cannot be read admits nothing, and a removal takes effect at once.
    folders_path(root).chmod(0o644)
    assert by_root() == _NOTHING == outside_reads_of(root, record)
    folders_path(root).chmod(0o600)
    remove_folder(root, record.target_id, folder)
    assert by_root() == _listed()
    # So does a change of mode, both ways.
    set_mode(root, record.target_id, "local")
    assert by_root() == by_salt() == OutsideReads("local", (), "owner")
    set_mode(root, record.target_id, "listed")
    assert by_root() == OutsideReads("listed", (), "owner")


def test_admissibility_is_the_rule_add_applies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    user_home = (tmp_path / "users" / "me").resolve()
    (user_home / "Library" / "Mail").mkdir(parents=True)
    (user_home / "projects").mkdir()
    monkeypatch.setenv("HOME", os.fspath(user_home))
    for refused in (
        os.fspath(user_home),
        os.fspath(user_home.parent),
        os.fspath(user_home / "Library" / "Mail"),
        "relative/folder",
        "/etc",
        os.fspath(tmp_path / "missing"),
    ):
        assert folder_admissible(refused) is False, refused
    assert folder_admissible(os.fspath(user_home / "projects")) is True


# --- the outside-read mode -------------------------------------------------------------------


def _remote(kind: str, name: str, **fields: object) -> tuple[targets.ServerTarget, Path]:
    with targets.registry_lock():
        if kind == "ssh":
            return targets.new_remote_target(name, "ssh", host="devbox.example", port=22)
        if kind == "local_port":
            return targets.new_remote_target(name, "local_port", base_url="https://127.0.0.1:8443")
        return targets.new_remote_target(
            name,
            "https",
            base_url=cast(str, fields.get("base_url", "https://lab.example")),
            ca_file=cast("str | None", fields.get("ca_file")),
            tls_pin=cast("str | None", fields.get("tls_pin")),
        )


def test_every_remote_kind_is_listed_until_its_owner_chooses(home: Path) -> None:
    """D2b: no default per kind. Local port, SSH and web servers alike read only listed folders
    until the owner chooses, and the same two modes are open to each."""

    del home
    for kind in ("ssh", "local_port", "https"):
        record, root = _remote(kind, kind.replace("_", "-"))
        assert outside_reads_of(root, record) == OutsideReads("listed", (), "not_chosen"), kind
        for mode in ("local", "listed"):
            set_mode(root, record.target_id, mode)
            assert outside_reads_of(root, record) == OutsideReads(mode, (), "owner"), kind
    assert not hasattr(server_folders, "DEFAULT_OUTSIDE_READ_MODE")


def test_a_record_with_no_mode_reads_as_listed(home: Path, folder: str) -> None:
    del home
    record, root = _remote("ssh", "devbox")
    add_folder(root, record.target_id, folder)
    assert b'"mode"' not in folders_path(root).read_bytes()
    assert read_record(root, record.target_id) == FolderRecord((folder,), None)
    assert outside_reads_of(root, record) == OutsideReads("listed", (folder,), "not_chosen")


def test_the_mode_switches_both_ways_and_folder_changes_keep_it(
    remote: tuple[targets.ServerTarget, Path], folder: str
) -> None:
    record, root = remote
    assert set_mode(root, record.target_id, "local") is True
    assert set_mode(root, record.target_id, "local") is False  # already recorded
    body = folders_path(root).read_bytes()
    assert body == (
        b'{"folders":[],"mode":"local","schema":"'
        + FOLDERS_SCHEMA.encode()
        + b'","target_id":"'
        + record.target_id.encode()
        + b'"}\n'
    )
    assert outside_reads_of(root, record) == OutsideReads("local", (), "owner")
    # Listing or removing a folder keeps the mode the owner chose, and so does clearing them.
    add_folder(root, record.target_id, folder)
    assert read_record(root, record.target_id) == FolderRecord((folder,), "local")
    assert outside_reads_of(root, record) == OutsideReads("local", (folder,), "owner")
    remove_folder(root, record.target_id, folder)
    add_folder(root, record.target_id, folder)
    assert clear_folders(root, record.target_id) == "cleared"
    assert read_record(root, record.target_id) == FolderRecord((), "local")
    # And back: the listed folders are kept across the switch.
    add_folder(root, record.target_id, folder)
    assert set_mode(root, record.target_id, "listed") is True
    assert outside_reads_of(root, record) == OutsideReads("listed", (folder,), "owner")
    # A mode the owner set is recorded even where it equals what no choice reads as.
    assert read_record(root, record.target_id).mode == "listed"
    with pytest.raises(FolderError, match="outside_read_mode_invalid"):
        set_mode(root, record.target_id, cast("OutsideReadMode", "open"))


@pytest.mark.parametrize("value", ['"open"', "null", '""', '"LOCAL"'])
def test_a_record_with_an_unknown_mode_fails_closed(home: Path, folder: str, value: str) -> None:
    """Even where the owner chose ``local``: a damaged record is ``listed``, no folder."""

    del home
    record, root = _remote("ssh", "devbox")
    add_folder(root, record.target_id, folder)
    set_mode(root, record.target_id, "local")
    path = folders_path(root)
    path.write_bytes(path.read_bytes().replace(b'"local"', value.encode()))
    with pytest.raises(FolderError, match="folders_record_invalid"):
        read_record(root, record.target_id)
    assert outside_reads_of(root, record) == _NOTHING


@pytest.mark.parametrize("damage", ["mode", "json"])
def test_an_unreadable_record_fails_closed_to_listed_where_the_owner_chose_local(
    home: Path, folder: str, damage: str
) -> None:
    del home
    record, root = _remote("ssh", "devbox")
    set_mode(root, record.target_id, "local")
    assert outside_reads_of(root, record).mode == "local"
    add_folder(root, record.target_id, folder)
    if damage == "mode":
        folders_path(root).chmod(0o644)
    else:
        folders_path(root).write_text("{damaged\n")
        folders_path(root).chmod(0o600)
    assert outside_reads_of(root, record) == _NOTHING
    assert outside_reads_reader(root)() == _NOTHING
    # Clearing it never widens it back to the 'local' the damaged record may have held.
    assert clear_folders(root, record.target_id) == "reset_to_listed"
    assert outside_reads_of(root, record) == OutsideReads("listed", (), "owner")


def test_no_official_endpoint_is_named_yet() -> None:
    """The reviewed constant is empty until an official hosted FinishUP endpoint exists."""

    assert OFFICIAL_ENDPOINT_HOSTS == frozenset()


def test_an_official_endpoint_is_local_by_exact_host_and_system_trust(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    del home
    monkeypatch.setattr(server_folders, "OFFICIAL_ENDPOINT_HOSTS", frozenset({"fu.example"}))
    pin = "sha256:" + "a" * 64
    cases: tuple[tuple[str, dict[str, str], OutsideReadMode], ...] = (
        ("official", {"base_url": "https://fu.example"}, "local"),
        ("official-port", {"base_url": "https://fu.example:8443/api"}, "local"),
        ("sub", {"base_url": "https://api.fu.example"}, "listed"),
        ("suffix", {"base_url": "https://fu.example.evil"}, "listed"),
        ("prefix", {"base_url": "https://notfu.example"}, "listed"),
        ("ca-file", {"base_url": "https://fu.example", "ca_file": "/etc/fu-ca.pem"}, "listed"),
        ("pinned", {"base_url": "https://fu.example", "tls_pin": pin}, "listed"),
    )
    for name, fields, mode in cases:
        record, root = _remote("https", name, **fields)
        assert official_endpoint(record) is (mode == "local"), name
        # The same answer before the target exists, as 'server add' asks it.
        assert official_address(
            "https",
            fields["base_url"],
            ca_file=fields.get("ca_file"),
            tls_pin=fields.get("tls_pin"),
        ) is (mode == "local"), name
        source: OutsideReadSource = "official_endpoint" if mode == "local" else "not_chosen"
        assert outside_reads_of(root, record) == OutsideReads(mode, (), source), name
    # The owner's own choice still wins over the official default.
    record, root = _remote("https", "chosen", base_url="https://fu.example")
    set_mode(root, record.target_id, "listed")
    assert outside_reads_of(root, record) == OutsideReads("listed", (), "owner")
    # Neither kind but HTTPS counts, whatever its host.
    ssh, _root = _remote("ssh", "devbox")
    assert official_endpoint(ssh) is False
    for kind in ("ssh", "local_port", "local"):
        assert official_address(kind, "https://fu.example", ca_file=None, tls_pin=None) is False
