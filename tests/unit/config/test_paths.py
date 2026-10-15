from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest
from platformdirs import PlatformDirs

from finishup.config.paths import (
    PathSafetyError,
    _PathProbe,  # pyright: ignore[reportPrivateUsage]
    ensure_owner_only_dir,
    existing_owner_only_dir,
    service_generation_path,
    unlock_throttle_path,
    verify_private_local_bundle,
)


def _probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    effective_uid: int | None = None,
    mount_table: str = "rootfs / ext4 rw 0 0",
) -> _PathProbe:  # pyright: ignore[reportPrivateUsage]
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    private_temp = tmp_path / "private-temp"
    private_temp.mkdir(mode=0o700, exist_ok=True)
    return _PathProbe(  # pyright: ignore[reportPrivateUsage]
        platform="linux",
        effective_uid=os.geteuid() if effective_uid is None else effective_uid,
        home=tmp_path,
        shared_temp=private_temp,
        fixed_shared_temps=(),
        platform_dirs=PlatformDirs(appname="finishup", appauthor=False, roaming=False),
        mount_table=lambda: mount_table,
        macos_fstype=lambda _path: None,
        diagnostic=lambda _reason: None,
    )


def test_owner_only_creation_and_fixed_locked_state_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "nested" / "bundle"
    ensure_owner_only_dir(target)
    assert stat.S_IMODE(target.stat().st_mode) == 0o700
    assert stat.S_IMODE(target.parent.stat().st_mode) == 0o700

    probe = _probe(tmp_path, monkeypatch)
    generation = service_generation_path(_probe=probe)
    throttle = unlock_throttle_path(_probe=probe)
    assert generation.name == "service-generation.json"
    assert throttle.name == "unlock-throttle.json"
    assert generation.parent == throttle.parent
    assert stat.S_IMODE(generation.parent.stat().st_mode) == 0o700


def test_existing_owner_only_dir_verifies_without_creating(tmp_path: Path) -> None:
    absent = tmp_path / "nested" / "observation"
    assert existing_owner_only_dir(absent) is False
    assert list(tmp_path.iterdir()) == []

    ensure_owner_only_dir(absent)
    assert existing_owner_only_dir(absent) is True

    absent.chmod(0o755)
    with pytest.raises(PathSafetyError, match="permissions_too_broad"):
        existing_owner_only_dir(absent)
    absent.chmod(0o700)

    linked = tmp_path / "linked"
    linked.symlink_to(absent.parent, target_is_directory=True)
    with pytest.raises(PathSafetyError, match="path_contains_symlink"):
        existing_owner_only_dir(linked / "observation")


def test_ordered_symlink_permission_repository_sync_and_network_reasons(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    probe = _probe(tmp_path, monkeypatch)

    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    linked = tmp_path / "linked"
    linked.symlink_to(real, target_is_directory=True)
    with pytest.raises(PathSafetyError) as symlink:
        verify_private_local_bundle(linked, _probe=probe)
    assert symlink.value.reason_code == "path_contains_symlink"

    broad = tmp_path / "broad"
    broad.mkdir(mode=0o750)
    with pytest.raises(PathSafetyError) as permissions:
        verify_private_local_bundle(broad, _probe=probe)
    assert permissions.value.reason_code == "permissions_too_broad"

    repository = tmp_path / "repository"
    repository.mkdir(mode=0o700)
    (repository / ".git").mkdir()
    bundle = repository / "bundle"
    bundle.mkdir(mode=0o700)
    with pytest.raises(PathSafetyError) as repo:
        verify_private_local_bundle(bundle, _probe=probe)
    assert repo.value.reason_code == "path_in_repository"

    synced = tmp_path / "Dropbox" / "bundle"
    synced.mkdir(mode=0o700, parents=True)
    with pytest.raises(PathSafetyError) as sync:
        verify_private_local_bundle(synced, _probe=probe)
    assert sync.value.reason_code == "path_in_sync_folder"

    network = tmp_path / "network"
    network.mkdir(mode=0o700)
    escaped = str(tmp_path).replace(" ", "\\040")
    network_probe = _probe(
        tmp_path,
        monkeypatch,
        mount_table=f"server {escaped} nfs rw 0 0\nrootfs / ext4 rw 0 0",
    )
    with pytest.raises(PathSafetyError) as network_error:
        verify_private_local_bundle(network, _probe=network_probe)
    assert network_error.value.reason_code == "path_on_network_filesystem"


def test_explicit_owner_mismatch_precedes_later_classifiers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "owned"
    repository.mkdir(mode=0o700)
    (repository / ".git").mkdir()
    wrong_owner = _probe(tmp_path, monkeypatch, effective_uid=os.geteuid() + 1)
    with pytest.raises(PathSafetyError) as caught:
        verify_private_local_bundle(repository, _probe=wrong_owner)
    assert caught.value.reason_code == "path_not_owned"


@pytest.mark.parametrize("fstype", ["9p", "drvfs", "virtiofs"])
def test_windows_drive_and_vm_share_transports_are_refused_like_a_network_share(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fstype: str
) -> None:
    """WSL 1 (drvfs), WSL 2 (9p), and virtiofs shares proxy locks across a VM boundary (#723)."""

    shared = tmp_path / "mnt" / "c" / "finishup"
    shared.mkdir(mode=0o700, parents=True)
    escaped = str(tmp_path / "mnt" / "c").replace(" ", "\\040")
    probe = _probe(
        tmp_path,
        monkeypatch,
        mount_table=f"C:\\134 {escaped} {fstype} rw 0 0\nrootfs / ext4 rw 0 0",
    )

    with pytest.raises(PathSafetyError) as error:
        verify_private_local_bundle(shared, _probe=probe)
    assert error.value.reason_code == "path_on_network_filesystem"

    local = tmp_path / "home" / "finishup"
    local.mkdir(mode=0o700, parents=True)
    verify_private_local_bundle(local, _probe=probe)
