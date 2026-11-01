"""Remedies for the isolation-root and two-name folder refusals name the right next step (ADR-048).

Each refusal token can come from more than one source; the remedy must give an action that works
for every source it covers, and never names a path. Every case builds its roots under
``tmp_path``; nothing reads a real user directory and no service is started.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

import pytest
from platformdirs import PlatformDirs

from finishup.cli.exits import UPGRADING_FROM_YOETZ_GUIDE, remediation_message
from finishup.cli.service_installation import installation_folders, path_refusal_failure
from finishup.config.installation import new_instance_identity, write_runtime_pin
from finishup.config.paths import (
    ISOLATED_ROOT_ENV,
    LEGACY_ISOLATED_ROOT_ENV,
    PathSafetyError,
    _PathProbe,  # pyright: ignore[reportPrivateUsage]
    isolated_root,
)


def _probe(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, prefix: Path) -> _PathProbe:  # pyright: ignore[reportPrivateUsage]
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
        fixed_shared_temps=(),
        platform_dirs=PlatformDirs(appname="finishup", appauthor=False, roaming=False),
        mount_table=lambda: "rootfs / ext4 rw 0 0",
        macos_fstype=lambda _path: None,
        diagnostic=lambda _reason: None,
        runtime_prefix=prefix,
    )


def _pinned_prefix(tmp_path: Path, root: Path) -> Path:
    prefix = tmp_path / "venv"
    prefix.mkdir(mode=0o755)
    identity = new_instance_identity(
        "disposable",
        now=datetime(2026, 9, 5, 15, 0, 0, tzinfo=UTC),
        package_version="0.1.0",
        runtime_prefix=prefix,
        source_ref="c3d553611c998df32a72c64337d1e8231560a37d",
        source_state="clean",
        package_digest="sha256:" + "ab" * 32,
    )
    write_runtime_pin(prefix, root, identity.installation_id)
    return prefix


def _refusal_text(reason: str) -> str:
    errors: list[str] = []
    code = path_refusal_failure(
        reason, json_output=False, stderr_writer=errors.append, stdout_writer=lambda _v: None
    )
    assert code == 20
    assert len(errors) == 1
    return errors[0]


def test_only_the_older_variable_against_a_pin_is_named_in_the_conflict_remedy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # An older launcher or host registration exports only YOETZ_ISOLATED_ROOT into a FinishUP
    # runtime pinned to a different root: the remedy must name the variable that is set.
    pinned = tmp_path / "pinned"
    pinned.mkdir(mode=0o700)
    other = tmp_path / "other"
    other.mkdir(mode=0o700)
    prefix = _pinned_prefix(tmp_path, pinned)
    monkeypatch.delenv(ISOLATED_ROOT_ENV, raising=False)
    monkeypatch.setenv(LEGACY_ISOLATED_ROOT_ENV, str(other))
    probe = _probe(tmp_path, monkeypatch, prefix=prefix)

    with pytest.raises(PathSafetyError) as caught:
        isolated_root(_probe=probe)
    assert caught.value.reason_code == "isolation_root_conflict"

    text = _refusal_text("isolation_root_conflict")
    first = text.splitlines()[0]
    assert first.startswith(
        "isolation_root_conflict: FINISHUP_ISOLATED_ROOT (or the older YOETZ_ISOLATED_ROOT) "
        "names a different root than this runtime's pin"
    )
    assert "unset it to use the pinned root" in first
    assert str(tmp_path) not in text
    assert "Continuation: instance_identity_repair" in text


def test_a_pin_naming_a_root_that_is_gone_gets_an_action_for_a_pinned_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Neither variable is set: the token comes from the pin. "Unset the variable" alone would
    # be advice the user cannot follow, and a pinned runtime never falls back to the everyday
    # installation (#604).
    prefix = _pinned_prefix(tmp_path, tmp_path / "gone")
    monkeypatch.delenv(ISOLATED_ROOT_ENV, raising=False)
    monkeypatch.delenv(LEGACY_ISOLATED_ROOT_ENV, raising=False)
    probe = _probe(tmp_path, monkeypatch, prefix=prefix)

    with pytest.raises(PathSafetyError) as caught:
        isolated_root(_probe=probe)
    assert caught.value.reason_code == "isolation_root_invalid"

    remedy = remediation_message("isolation_root_invalid")
    assert remedy is not None
    # The variable source keeps its own action...
    assert "If FINISHUP_ISOLATED_ROOT (or the older YOETZ_ISOLATED_ROOT) is set" in remedy
    assert "unset it to use this runtime's pinned instance root" in remedy
    assert "(the everyday installation when the runtime is not pinned)" in remedy
    # ...and the pinned source gets one that works without any variable.
    assert "If neither is set, this runtime is pinned to an instance root that is gone" in remedy
    assert "will not fall back to the everyday installation" in remedy
    assert "recreate the instance" in remedy
    assert "'finishup instance dispose --root <root>' with the root given when" in remedy
    assert "provisioned to remove the stale pin" in remedy
    text = _refusal_text("isolation_root_invalid")
    assert text.startswith(f"isolation_root_invalid: {remedy}")
    assert str(tmp_path) not in text


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


@pytest.mark.parametrize(
    ("yoetz_anchor", "finishup_anchor"),
    [
        # Two real installations: a vault or catalog under each name.
        (("data", "catalog.sqlite3"), ("data", "catalog.sqlite3")),
        (("data", "catalog.sqlite3"), ("data", "vault")),
        # A stopped older service left its lock under the Yoetz name.
        (("state", "service.lock"), ("data", "catalog.sqlite3")),
    ],
)
def test_the_ambiguity_remedy_keeps_a_way_out_when_both_names_hold_data(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    yoetz_anchor: tuple[str, str],
    finishup_anchor: tuple[str, str],
) -> None:
    base = _xdg(tmp_path, monkeypatch)
    for app_name, (kind, leaf) in (("yoetz", yoetz_anchor), ("finishup", finishup_anchor)):
        directory = base / kind / app_name
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        (directory / leaf).write_bytes(b"")

    with pytest.raises(PathSafetyError) as caught:
        installation_folders()
    assert caught.value.reason_code == "installation_root_ambiguous"

    text = _refusal_text("installation_root_ambiguous")
    first = text.splitlines()[0]
    # The settings-file sentence stays, and now points at concrete folders.
    assert "If the other name holds only a settings file (config.toml)" in first
    assert "move that file into the folders that hold the vault and catalog" in first
    # The general fallback for two real installations and a leftover lock is back.
    assert (
        "If both names hold a vault or catalog, keep the installation you use and move the "
        "other name's folders aside without deleting them" in first
    )
    assert "a leftover service.lock from a stopped older service can be moved aside" in first
    assert first.endswith(UPGRADING_FROM_YOETZ_GUIDE)
    assert str(tmp_path) not in text
    assert "Continuation: local_state_repair" in text
