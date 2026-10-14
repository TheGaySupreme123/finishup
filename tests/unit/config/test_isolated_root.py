"""Exact-target isolation-root contract for every identity root (issue #518).

``FINISHUP_ISOLATED_ROOT`` must rebase config, storage bundle, state (service lock/generation),
runtime endpoints, cache, and logs onto one validated private root — and must fail closed rather
than fall back to the ambient platform directories when the root is set but unusable. These are
the locks that keep a dogfood/test runtime from ever reaching the live singleton.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from platformdirs import PlatformDirs

from finishup.adapters.control import unix_socket
from finishup.config import paths as paths_module
from finishup.config.paths import (
    ISOLATED_ROOT_ENV,
    PathSafetyError,
    _PathProbe,  # pyright: ignore[reportPrivateUsage]
    bundle_root,
    cache_dir,
    config_file_path,
    isolated_root,
    log_dir,
    runtime_dir,
    service_generation_path,
    state_dir,
)


def _probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    fixed_shared_temps: tuple[Path, ...] = (),
) -> _PathProbe:  # pyright: ignore[reportPrivateUsage]
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg-data"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg-config"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg-cache"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg-state"))
    private_temp = tmp_path / "private-temp"
    private_temp.mkdir(mode=0o700, exist_ok=True)
    return _PathProbe(  # pyright: ignore[reportPrivateUsage]
        platform="linux",
        effective_uid=os.geteuid(),
        home=tmp_path,
        shared_temp=private_temp,
        fixed_shared_temps=fixed_shared_temps,
        platform_dirs=PlatformDirs(appname="finishup", appauthor=False, roaming=False),
        mount_table=lambda: "rootfs / ext4 rw 0 0",
        macos_fstype=lambda _path: None,
        diagnostic=lambda _reason: None,
    )


def _isolation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "iso"
    root.mkdir(mode=0o700)
    monkeypatch.setenv(ISOLATED_ROOT_ENV, str(root))
    return root


def test_ambient_mode_is_unchanged_when_the_variable_is_unset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(ISOLATED_ROOT_ENV, raising=False)
    probe = _probe(tmp_path, monkeypatch)

    assert isolated_root(_probe=probe) is None
    assert state_dir(_probe=probe) == Path(probe.platform_dirs.user_state_dir)
    assert cache_dir(_probe=probe) == Path(probe.platform_dirs.user_cache_dir)
    assert log_dir(_probe=probe) == Path(probe.platform_dirs.user_log_dir)
    assert runtime_dir(_probe=probe) == Path(probe.platform_dirs.user_runtime_path)
    assert bundle_root(_probe=probe) == Path(probe.platform_dirs.user_data_dir)
    assert config_file_path(_probe=probe) == (
        Path(probe.platform_dirs.user_config_dir) / "config.toml"
    )


def test_one_isolated_root_derives_every_identity_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _isolation(tmp_path, monkeypatch)
    probe = _probe(tmp_path, monkeypatch)

    assert isolated_root(_probe=probe) == root
    assert state_dir(_probe=probe) == root / "state"
    assert cache_dir(_probe=probe) == root / "cache"
    assert log_dir(_probe=probe) == root / "log"
    assert runtime_dir(_probe=probe) == root / "run"
    assert bundle_root(_probe=probe) == root / "data"
    assert config_file_path(_probe=probe) == root / "config" / "config.toml"

    # The service singleton (lock, generation) derives from the isolated state directory: the
    # locked-state metadata lands beneath the root, so an isolated service can never contend
    # for — or accidentally supersede — the ambient install's singleton.
    generation = service_generation_path(_probe=probe)
    assert generation == root / "state" / "service-generation.json"
    assert generation.parent.is_dir()


def test_explicit_data_dir_override_still_wins_over_the_isolated_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _isolation(tmp_path, monkeypatch)
    probe = _probe(tmp_path, monkeypatch)
    explicit = tmp_path / "explicit-bundle"
    explicit.mkdir(mode=0o700)

    assert bundle_root(_data_dir=explicit, _probe=probe) == explicit


@pytest.mark.parametrize("raw", ["", "relative/root"])
def test_empty_or_relative_root_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, raw: str
) -> None:
    monkeypatch.setenv(ISOLATED_ROOT_ENV, raw)
    probe = _probe(tmp_path, monkeypatch)

    with pytest.raises(PathSafetyError) as caught:
        state_dir(_probe=probe)
    assert caught.value.reason_code == "isolation_root_invalid"


def test_missing_root_and_nondirectory_root_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    probe = _probe(tmp_path, monkeypatch)

    monkeypatch.setenv(ISOLATED_ROOT_ENV, str(tmp_path / "never-created"))
    with pytest.raises(PathSafetyError) as missing:
        isolated_root(_probe=probe)
    assert missing.value.reason_code == "isolation_root_invalid"

    plain_file = tmp_path / "a-file"
    plain_file.touch()
    os.chmod(plain_file, 0o600)
    monkeypatch.setenv(ISOLATED_ROOT_ENV, str(plain_file))
    with pytest.raises(PathSafetyError) as nondir:
        isolated_root(_probe=probe)
    assert nondir.value.reason_code == "isolation_root_invalid"


def test_unsafe_roots_keep_their_precise_bounded_reasons(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    probe = _probe(tmp_path, monkeypatch)

    broad = tmp_path / "broad"
    broad.mkdir(mode=0o750)
    monkeypatch.setenv(ISOLATED_ROOT_ENV, str(broad))
    with pytest.raises(PathSafetyError) as permissions:
        runtime_dir(_probe=probe)
    assert permissions.value.reason_code == "permissions_too_broad"

    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    linked = tmp_path / "linked"
    linked.symlink_to(real, target_is_directory=True)
    monkeypatch.setenv(ISOLATED_ROOT_ENV, str(linked))
    with pytest.raises(PathSafetyError) as symlink:
        state_dir(_probe=probe)
    assert symlink.value.reason_code == "path_contains_symlink"

    repo = tmp_path / "checkout" / "root"
    repo.mkdir(parents=True, mode=0o700)
    (repo.parent / ".git").mkdir(mode=0o700)
    monkeypatch.setenv(ISOLATED_ROOT_ENV, str(repo))
    with pytest.raises(PathSafetyError) as repository:
        bundle_root(_probe=probe)
    assert repository.value.reason_code == "path_in_repository"


def test_shared_temp_root_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    shared = tmp_path / "shared-temp"
    shared.mkdir(mode=0o700)
    root = shared / "root"
    root.mkdir(mode=0o700)
    probe = _probe(tmp_path, monkeypatch, fixed_shared_temps=(shared,))
    monkeypatch.setenv(ISOLATED_ROOT_ENV, str(root))

    with pytest.raises(PathSafetyError) as caught:
        config_file_path(_probe=probe)
    assert caught.value.reason_code == "path_shared_temp"


def test_endpoint_layer_fails_closed_as_the_bounded_transport_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(ISOLATED_ROOT_ENV, "")

    with pytest.raises(unix_socket.LocalControlTransportError) as caught:
        unix_socket._runtime_directory()  # pyright: ignore[reportPrivateUsage]
    assert caught.value.reason == "runtime_directory_unsafe"


def test_endpoint_layer_binds_beneath_the_isolated_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _isolation(tmp_path, monkeypatch)
    probe = _probe(tmp_path, monkeypatch)
    monkeypatch.setattr(paths_module, "_default_probe", lambda: probe)

    assert unix_socket._runtime_directory() == root / "run"  # pyright: ignore[reportPrivateUsage]
