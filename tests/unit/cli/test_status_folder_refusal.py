"""Plain ``setup status`` and ``provider status`` name a folder refusal (ADR-048).

When FinishUP's local folders cannot be used safely -- here, data under both product names --
neither command may report a merely unreachable service or ``internal_error``. Both name the
bounded token, its remedy and its continuation on stderr and exit 20. ``setup status`` keeps its
released stdout report (setup status 2.0.0 has no field for this). Every case runs against XDG
roots under ``tmp_path``; nothing reads or writes a real user data directory and no service is
started or reached: the refusal happens before any endpoint is resolved.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from finishup.cli import provider_status, setup
from finishup.config.paths import ISOLATED_ROOT_ENV, LEGACY_ISOLATED_ROOT_ENV, PathSafetyError
from finishup.protocol.canonical import JsonValue
from finishup.protocol.errors import PublicErrorCode
from finishup.protocol.schemas import validate_schema_instance


@pytest.fixture
def ambiguous_install(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
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
    for app_name in ("yoetz", "finishup"):
        directory = base / "data" / app_name
        directory.mkdir(mode=0o700)
        (directory / "catalog.sqlite3").write_bytes(b"")
    return base


def _created_files(base: Path) -> set[Path]:
    return {path for path in base.rglob("*") if path.is_file()}


@pytest.mark.anyio
async def test_the_service_probe_names_the_folder_refusal_on_stderr(
    ambiguous_install: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    before = _created_files(ambiguous_install)

    service, refusal = await setup._service_reachability_observed()  # pyright: ignore[reportPrivateUsage]
    assert service == {"reachable": False, "state": None, "vault_mode": None}
    assert refusal == "installation_root_ambiguous"
    # The observed variant only reports the token; it prints nothing itself.
    assert capsys.readouterr().err == ""

    assert await setup._service_reachability() == service  # pyright: ignore[reportPrivateUsage]
    captured = capsys.readouterr()
    assert captured.out == ""
    lines = captured.err.splitlines()
    assert lines[0].startswith("installation_root_ambiguous: FinishUP found its folders")
    assert "Continuation: local_state_repair" in lines
    assert str(ambiguous_install) not in captured.err
    assert _created_files(ambiguous_install) == before


@pytest.mark.anyio
@pytest.mark.parametrize("json_output", [True, False])
async def test_plain_setup_status_keeps_its_report_and_names_the_refusal(
    ambiguous_install: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    json_output: bool,
) -> None:
    from finishup.cli import host_connection

    def empty_installation_rows(_project: Path | None = None) -> list[JsonValue]:
        return []

    monkeypatch.setattr(setup, "discover_codex_binaries", lambda: ())
    monkeypatch.setattr(setup, "setup_marker_present", lambda: False)
    monkeypatch.setattr(host_connection, "installation_rows", empty_installation_rows)

    assert await setup.setup_status(json_output=json_output) == 20

    captured = capsys.readouterr()
    if json_output:
        # stdout is exactly the released report: no refusal payload and no new field.
        report = json.loads(captured.out)
        validate_schema_instance("setup-status", "2.0.0", report)
        assert report["service"] == {"reachable": False, "state": None, "vault_mode": None}
        assert "installation_root_ambiguous" not in captured.out
    err = captured.err.splitlines()
    assert sum(line.startswith("installation_root_ambiguous: ") for line in err) == 1
    assert "Continuation: local_state_repair" in err
    assert "service_unavailable" not in captured.err
    assert str(ambiguous_install) not in captured.err


@pytest.mark.anyio
async def test_setup_status_without_a_refusal_still_exits_zero(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from finishup.cli import host_connection

    async def unreachable(
        *, start_if_absent: bool = False
    ) -> tuple[dict[str, JsonValue], str | None]:
        del start_if_absent
        return {"reachable": False, "state": None, "vault_mode": None}, None

    def empty_installation_rows(_project: Path | None = None) -> list[JsonValue]:
        return []

    monkeypatch.setattr(setup, "_service_reachability_observed", unreachable)
    monkeypatch.setattr(setup, "discover_codex_binaries", lambda: ())
    monkeypatch.setattr(setup, "setup_marker_present", lambda: False)
    monkeypatch.setattr(host_connection, "installation_rows", empty_installation_rows)

    assert await setup.setup_status(json_output=True) == 0
    assert capsys.readouterr().err == ""


@pytest.mark.anyio
@pytest.mark.parametrize("json_output", [True, False])
async def test_provider_status_names_the_refusal_instead_of_internal_error(
    ambiguous_install: Path,
    capsys: pytest.CaptureFixture[str],
    json_output: bool,
) -> None:
    before = _created_files(ambiguous_install)

    assert await provider_status.run_provider_status(json_output=json_output) == 20

    captured = capsys.readouterr()
    err = captured.err.splitlines()
    assert err[0].startswith("installation_root_ambiguous: FinishUP found its folders")
    assert "Continuation: local_state_repair" in err
    assert "internal_error" not in captured.err
    assert str(ambiguous_install) not in captured.err + captured.out
    if json_output:
        payload = json.loads(captured.out)
        assert payload["ok"] is False
        assert payload["public_code"] == PublicErrorCode.STORAGE_UNSAFE.value
        assert payload["reason"] == "installation_root_ambiguous"
        assert payload["retryable"] is False
        assert payload["recovery"]["continuation"] == "local_state_repair"
    else:
        assert captured.out == ""
    assert _created_files(ambiguous_install) == before


@pytest.mark.anyio
async def test_provider_status_names_a_refusal_raised_while_reading_the_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The folders resolve, but a later config or bundle read refuses (for example a symlinked
    # folder): the same bounded report, never exit 70.
    from finishup.cli import service_installation

    async def refused(**_kwargs: object) -> dict[str, JsonValue]:
        raise PathSafetyError("path_contains_symlink")

    monkeypatch.setattr(service_installation, "installation_folders", lambda: "finishup")
    monkeypatch.setattr(provider_status, "provider_status_report", refused)

    assert await provider_status.run_provider_status(json_output=False) == 20

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("path_contains_symlink: ")
    assert str(tmp_path) not in captured.err
