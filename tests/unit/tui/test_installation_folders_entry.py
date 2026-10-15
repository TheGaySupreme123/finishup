"""The doctor names which folders hold this installation's data (ADR-048).

Every case runs against XDG roots under ``tmp_path``; nothing reads a real user directory.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from finishup.cli.exits import UPGRADING_FROM_YOETZ_GUIDE
from finishup.tui.models import LayerState
from finishup.tui.runtime import (
    _installation_folders_entry,  # pyright: ignore[reportPrivateUsage]
)


def _xdg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *app_names: str) -> None:
    base = tmp_path / "xdg"
    for name in ("data", "config", "cache", "state", "runtime"):
        (base / name).mkdir(mode=0o700, parents=True)
    for app_name in app_names:
        (base / "config" / app_name).mkdir(mode=0o700)
        (base / "config" / app_name / "config.toml").write_bytes(b"")
    monkeypatch.setenv("XDG_DATA_HOME", str(base / "data"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(base / "config"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(base / "cache"))
    monkeypatch.setenv("XDG_STATE_HOME", str(base / "state"))
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(base / "runtime"))
    monkeypatch.delenv("FINISHUP_ISOLATED_ROOT", raising=False)
    monkeypatch.delenv("YOETZ_ISOLATED_ROOT", raising=False)


def test_finishup_folders_are_verified_without_a_next_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _xdg(tmp_path, monkeypatch, "finishup")

    entry = _installation_folders_entry()

    assert entry.key == "installation_folders"
    assert entry.state is LayerState.VERIFIED
    assert entry.detail == "FinishUP folders"
    assert entry.remediation == ""


def test_yoetz_era_folders_are_named_as_in_place_and_to_be_kept(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _xdg(tmp_path, monkeypatch, "yoetz")

    entry = _installation_folders_entry()

    assert entry.state is LayerState.VERIFIED
    assert entry.detail == "Yoetz-era folders, used in place"
    assert "nothing was moved" in entry.remediation
    assert "keep them" in entry.remediation
    assert entry.remediation.endswith(UPGRADING_FROM_YOETZ_GUIDE)
    assert str(tmp_path) not in entry.remediation


def test_folders_under_both_names_block_with_the_bounded_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _xdg(tmp_path, monkeypatch, "finishup", "yoetz")

    entry = _installation_folders_entry()

    assert entry.state is LayerState.BLOCKED
    assert entry.detail == "installation_root_ambiguous"
    assert "will not choose between them" in entry.remediation
    assert str(tmp_path) not in entry.remediation


def test_an_isolated_root_is_named_without_reading_the_ambient_folders(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _xdg(tmp_path, monkeypatch, "finishup", "yoetz")
    root = tmp_path / "iso"
    root.mkdir(mode=0o700)
    monkeypatch.setenv("FINISHUP_ISOLATED_ROOT", str(root))

    entry = _installation_folders_entry()

    assert entry.state is LayerState.VERIFIED
    assert entry.detail == "isolated root"


def _anchor_catalog(tmp_path: Path, app_name: str) -> None:
    data = tmp_path / "xdg" / "data" / app_name
    data.mkdir(mode=0o700)
    (data / "catalog.sqlite3").write_bytes(b"")


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_doctor_reports_ambiguous_folders_instead_of_failing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The reviewed failure: a catalog under one name and a settings file under the other. The
    # real doctor must return the blocked entry; nothing that reads configuration may run.
    from finishup.tui import runtime as runtime_module
    from finishup.tui.runtime import FinishUpRuntime

    _xdg(tmp_path, monkeypatch, "finishup")
    _anchor_catalog(tmp_path, "yoetz")
    monkeypatch.setattr(runtime_module, "_host_entries", lambda: ())

    async def unreachable(_self: object, **_kwargs: object) -> object:
        raise AssertionError("no configuration read once the folders are ambiguous")

    monkeypatch.setattr(FinishUpRuntime, "package_update_advisory", unreachable)
    project = tmp_path / "project"
    project.mkdir()

    report = await FinishUpRuntime(cwd=project).doctor()

    by_key = {entry.key: entry for entry in report.entries}
    assert list(by_key) == ["runtime", "package", "installation_folders"]
    folders = by_key["installation_folders"]
    assert folders.state is LayerState.BLOCKED
    assert folders.detail == "installation_root_ambiguous"
    assert "vault and catalog" in folders.remediation
    assert str(tmp_path) not in folders.remediation
    created = sorted(path.name for path in (tmp_path / "xdg" / "state").iterdir())
    assert created == []


@pytest.mark.anyio
async def test_doctor_names_a_folder_refusal_raised_while_reading_readiness(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from finishup.config.paths import PathSafetyError
    from finishup.tui import runtime as runtime_module
    from finishup.tui.runtime import FinishUpRuntime

    _xdg(tmp_path, monkeypatch, "finishup")
    monkeypatch.setattr(runtime_module, "_host_entries", lambda: ())

    async def no_advisory(_self: object, **_kwargs: object) -> None:
        return None

    async def refused(_self: object) -> object:
        raise PathSafetyError("permissions_too_broad")

    monkeypatch.setattr(FinishUpRuntime, "package_update_advisory", no_advisory)
    monkeypatch.setattr(FinishUpRuntime, "status_snapshot", refused)

    report = await FinishUpRuntime(cwd=tmp_path).doctor()

    folders = [entry for entry in report.entries if entry.key == "installation_folders"]
    assert len(folders) == 1
    last = report.entries[-1]
    assert last is folders[0]
    assert last.state is LayerState.BLOCKED
    assert last.detail == "permissions_too_broad"
    assert "owner-only" in last.remediation


def test_a_two_spelling_isolation_root_blocks_with_its_own_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _xdg(tmp_path, monkeypatch, "finishup")
    for name, leaf in (("FINISHUP_ISOLATED_ROOT", "new"), ("YOETZ_ISOLATED_ROOT", "old")):
        (tmp_path / leaf).mkdir(mode=0o700)
        monkeypatch.setenv(name, str(tmp_path / leaf))

    entry = _installation_folders_entry()

    assert entry.state is LayerState.BLOCKED
    assert entry.detail == "isolation_root_env_conflict"
    assert "unset YOETZ_ISOLATED_ROOT" in entry.remediation
    assert "dispose" not in entry.remediation.replace("No instance needs to be disposed", "")
