"""In-place adoption of a Yoetz-era installation and the isolation-root spellings (ADR-048).

One application name is chosen for every ambient platform root: a legacy anchor with no FinishUP
anchor keeps the legacy ``yoetz`` directories in place; a FinishUP anchor or none selects
``finishup``; anchors under both names fail closed. Isolated roots ignore the choice. Every case
runs against XDG roots under ``tmp_path``; nothing reads or writes a real user directory.
"""

from __future__ import annotations

import dataclasses
import os
from pathlib import Path

import pytest

from finishup.config import paths as paths_module
from finishup.config.paths import (
    ISOLATED_ROOT_ENV,
    LEGACY_ISOLATED_ROOT_ENV,
    PathSafetyError,
    _PathProbe,  # pyright: ignore[reportPrivateUsage]
    bundle_root,
    cache_dir,
    config_file_path,
    installation_naming,
    isolated_root,
    isolated_root_variable,
    isolation_binding,
    log_dir,
    runtime_dir,
    state_dir,
)

_ANCHORS = (
    ("data", "catalog.sqlite3"),
    ("data", "vault"),
    ("config", "config.toml"),
    ("state", "service.lock"),
)


def _xdg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    base = tmp_path / "xdg"
    for name in ("data", "config", "cache", "state", "runtime"):
        (base / name).mkdir(mode=0o700, parents=True)
    monkeypatch.setenv("XDG_DATA_HOME", str(base / "data"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(base / "config"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(base / "cache"))
    monkeypatch.setenv("XDG_STATE_HOME", str(base / "state"))
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(base / "runtime"))
    monkeypatch.delenv(ISOLATED_ROOT_ENV, raising=False)
    monkeypatch.delenv(LEGACY_ISOLATED_ROOT_ENV, raising=False)
    return base


def _anchor(base: Path, app_name: str, root: str, name: str) -> Path:
    directory = base / root / app_name
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = directory / name
    if name == "vault":
        path.mkdir(mode=0o700)
    else:
        path.write_bytes(b"")
    return path


def _probe(tmp_path: Path) -> _PathProbe:  # pyright: ignore[reportPrivateUsage]
    """The production selection, with temp classification pointed at a private directory."""

    private_temp = tmp_path / "private-temp"
    private_temp.mkdir(mode=0o700, exist_ok=True)
    return dataclasses.replace(
        paths_module._default_probe(),  # pyright: ignore[reportPrivateUsage]
        platform="linux",
        effective_uid=os.geteuid(),
        home=tmp_path,
        shared_temp=private_temp,
        fixed_shared_temps=(),
        mount_table=lambda: "rootfs / ext4 rw 0 0",
    )


def _app_names(probe: _PathProbe) -> set[str]:  # pyright: ignore[reportPrivateUsage]
    """The application names the six ambient roots resolve beneath."""

    roots = (
        bundle_root(_probe=probe),
        config_file_path(_probe=probe).parent,
        cache_dir(_probe=probe),
        state_dir(_probe=probe),
        log_dir(_probe=probe),
        runtime_dir(_probe=probe),
    )
    return {name for root in roots for name in root.parts if name in {"finishup", "yoetz"}}


def test_no_installation_selects_finishup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _xdg(tmp_path, monkeypatch)
    probe = _probe(tmp_path)

    assert installation_naming(_probe=probe) == "finishup"
    assert _app_names(probe) == {"finishup"}


def test_a_finishup_installation_stays_finishup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base = _xdg(tmp_path, monkeypatch)
    _anchor(base, "finishup", "data", "catalog.sqlite3")
    probe = _probe(tmp_path)

    assert installation_naming(_probe=probe) == "finishup"
    assert _app_names(probe) == {"finishup"}


@pytest.mark.parametrize(("root", "name"), _ANCHORS)
def test_any_legacy_anchor_adopts_every_legacy_root_in_place(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, root: str, name: str
) -> None:
    base = _xdg(tmp_path, monkeypatch)
    anchor = _anchor(base, "yoetz", root, name)
    probe = _probe(tmp_path)

    assert installation_naming(_probe=probe) == "legacy_yoetz"
    # One choice for all six roots, never per directory.
    assert _app_names(probe) == {"yoetz"}
    assert state_dir(_probe=probe) == base / "state" / "yoetz"
    assert bundle_root(_probe=probe) == base / "data" / "yoetz"
    assert config_file_path(_probe=probe) == base / "config" / "yoetz" / "config.toml"
    # Adoption is in place: nothing is created, moved, or linked under the new name.
    assert anchor.exists()
    assert not any((base / part / "finishup").exists() for part in ("data", "config", "state"))


def test_a_legacy_only_cache_or_log_does_not_anchor_an_installation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base = _xdg(tmp_path, monkeypatch)
    (base / "cache" / "yoetz").mkdir(mode=0o700)
    (base / "state" / "yoetz").mkdir(mode=0o700)
    probe = _probe(tmp_path)

    assert installation_naming(_probe=probe) == "finishup"


def test_installations_under_both_names_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base = _xdg(tmp_path, monkeypatch)
    _anchor(base, "yoetz", "data", "catalog.sqlite3")
    _anchor(base, "finishup", "config", "config.toml")
    probe = _probe(tmp_path)

    with pytest.raises(PathSafetyError) as caught:
        installation_naming(_probe=probe)
    assert caught.value.reason_code == "installation_root_ambiguous"
    for accessor in (bundle_root, cache_dir, state_dir, log_dir, runtime_dir, config_file_path):
        with pytest.raises(PathSafetyError, match="installation_root_ambiguous"):
            accessor(_probe=probe)


def test_an_isolated_root_is_unaffected_by_an_ambiguous_ambient_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base = _xdg(tmp_path, monkeypatch)
    _anchor(base, "yoetz", "data", "catalog.sqlite3")
    _anchor(base, "finishup", "data", "catalog.sqlite3")
    root = tmp_path / "iso"
    root.mkdir(mode=0o700)
    monkeypatch.setenv(ISOLATED_ROOT_ENV, str(root))
    probe = _probe(tmp_path)

    assert state_dir(_probe=probe) == root / "state"
    assert bundle_root(_probe=probe) == root / "data"
    assert config_file_path(_probe=probe) == root / "config" / "config.toml"


@pytest.mark.parametrize(
    "names",
    [
        (ISOLATED_ROOT_ENV,),
        (LEGACY_ISOLATED_ROOT_ENV,),
        (ISOLATED_ROOT_ENV, LEGACY_ISOLATED_ROOT_ENV),
    ],
)
def test_either_isolation_root_spelling_isolates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, names: tuple[str, ...]
) -> None:
    _xdg(tmp_path, monkeypatch)
    root = tmp_path / "iso"
    root.mkdir(mode=0o700)
    for name in names:
        monkeypatch.setenv(name, str(root))
    probe = _probe(tmp_path)

    assert isolated_root_variable() == str(root)
    assert isolated_root(_probe=probe) == root
    assert isolation_binding(_probe=probe) == "environment"
    assert state_dir(_probe=probe) == root / "state"


def test_isolation_root_spellings_that_disagree_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _xdg(tmp_path, monkeypatch)
    first = tmp_path / "iso-new"
    second = tmp_path / "iso-old"
    first.mkdir(mode=0o700)
    second.mkdir(mode=0o700)
    monkeypatch.setenv(ISOLATED_ROOT_ENV, str(first))
    monkeypatch.setenv(LEGACY_ISOLATED_ROOT_ENV, str(second))
    probe = _probe(tmp_path)

    for operation in (
        isolated_root_variable,
        lambda: isolated_root(_probe=probe),
        lambda: isolation_binding(_probe=probe),
        lambda: state_dir(_probe=probe),
    ):
        with pytest.raises(PathSafetyError) as caught:
            operation()
        assert caught.value.reason_code == "isolation_root_env_conflict"
