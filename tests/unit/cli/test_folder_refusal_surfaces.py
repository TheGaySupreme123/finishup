"""The folder refusal and the adopted-in-place note reach every CLI connect surface (ADR-048).

A connection refused because FinishUP's local folders cannot be used safely carries a closed
path-safety token. These tests hold that the CLI names that token and its remedy instead of an
absent service, and that ``service status`` names a Yoetz-era install used in place on stderr
while stdout stays byte-identical. Every case runs against private XDG roots; no service starts.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from finishup.adapters.control.unix_socket import LocalControlTransportError
from finishup.cli import bootstrap
from finishup.cli.service_installation import LEGACY_FOLDERS_NOTE
from finishup.ports.control import ControlError
from finishup.protocol.canonical import JsonValue
from finishup.service import client as client_module


def _refused(reason: str) -> ControlError:
    return client_module._transport_error(  # pyright: ignore[reportPrivateUsage]
        LocalControlTransportError("runtime_directory_unsafe", path_reason=reason)
    )


def _xdg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    base = tmp_path / "xdg"
    for name in ("data", "config", "cache", "state", "runtime"):
        (base / name).mkdir(mode=0o700, parents=True)
    for variable, name in (
        ("XDG_DATA_HOME", "data"),
        ("XDG_CONFIG_HOME", "config"),
        ("XDG_CACHE_HOME", "cache"),
        ("XDG_STATE_HOME", "state"),
        ("XDG_RUNTIME_DIR", "runtime"),
    ):
        monkeypatch.setenv(variable, str(base / name))
    monkeypatch.delenv("FINISHUP_ISOLATED_ROOT", raising=False)
    monkeypatch.delenv("YOETZ_ISOLATED_ROOT", raising=False)
    return base


def _legacy_install(base: Path) -> None:
    (base / "data" / "yoetz").mkdir(mode=0o700)
    (base / "data" / "yoetz" / "catalog.sqlite3").write_bytes(b"")


@pytest.mark.parametrize("json_output", [False, True])
def test_control_failure_names_the_folder_token_not_an_absent_service(json_output: bool) -> None:
    errors: list[str] = []
    payloads: list[JsonValue] = []

    code = bootstrap.control_failure(
        _refused("installation_root_ambiguous"),
        json_output=json_output,
        stderr_writer=errors.append,
        stdout_writer=payloads.append,
    )

    assert code == 20
    assert errors[0].startswith("installation_root_ambiguous: ")
    assert "service_unavailable" not in errors[0]
    assert "service run" not in errors[0]
    assert "Continuation: local_state_repair" in errors[0]
    if json_output:
        payload = payloads[0]
        assert isinstance(payload, dict)
        assert payload["public_code"] == "STORAGE_UNSAFE"
        assert payload["reason"] == "installation_root_ambiguous"
        assert payload["retryable"] is False
    else:
        assert payloads == []


def test_an_ordinary_unsafe_endpoint_keeps_its_own_rendering() -> None:
    errors: list[str] = []

    bootstrap.control_failure(
        ControlError("endpoint_unsafe"),
        stderr_writer=errors.append,
        stdout_writer=lambda _value: None,
    )

    assert not errors[0].startswith("installation_root_ambiguous")


class _StatusClient:
    async def service_status(self) -> object:
        return {"state": "ready"}

    async def close(self) -> None:
        return None


@pytest.mark.parametrize("legacy", [False, True])
def test_service_status_fast_path_names_a_yoetz_era_install_on_stderr_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
    legacy: bool,
) -> None:
    from finishup.cli import entry

    base = _xdg(tmp_path, monkeypatch)
    if legacy:
        _legacy_install(base)

    async def connect(*_args: object, **_kwargs: object) -> _StatusClient:
        return _StatusClient()

    monkeypatch.setattr(bootstrap, "connect_cli_service", connect)

    human = entry._service_status_fast_path([])  # pyright: ignore[reportPrivateUsage]
    human_out = capfd.readouterr()
    machine = entry._service_status_fast_path(["--json"])  # pyright: ignore[reportPrivateUsage]
    machine_out = capfd.readouterr()

    assert human == machine == 0
    assert json.loads(human_out.out) == json.loads(machine_out.out) == {"state": "ready"}
    assert (LEGACY_FOLDERS_NOTE in human_out.err) is legacy
    assert machine_out.err == ""


@pytest.mark.anyio
@pytest.mark.parametrize("anyio_backend", ["asyncio"])
async def test_service_status_command_names_a_yoetz_era_install_on_stderr(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
    anyio_backend: str,
) -> None:
    del anyio_backend
    from finishup.cli import app

    _legacy_install(_xdg(tmp_path, monkeypatch))

    async def build(*_args: object, **_kwargs: object) -> _StatusClient:
        return _StatusClient()

    monkeypatch.setattr(app, "build_service_client", build)

    def quiet(*_args: object, **_kwargs: object) -> None:
        return None

    monkeypatch.setattr(app, "_human_or_json", quiet)

    assert await app._service_call("service_status", False) == 0  # pyright: ignore[reportPrivateUsage]
    assert LEGACY_FOLDERS_NOTE in capfd.readouterr().err
    assert await app._service_call("service_status", True) == 0  # pyright: ignore[reportPrivateUsage]
    assert capfd.readouterr().err == ""

    async def refused(*_args: object, **_kwargs: object) -> object:
        raise _refused("isolation_root_env_conflict")

    monkeypatch.setattr(app, "build_service_client", refused)
    assert await app._service_call("service_status", False) == 20  # pyright: ignore[reportPrivateUsage]
    err = capfd.readouterr().err
    assert err.startswith("isolation_root_env_conflict: ")
    assert LEGACY_FOLDERS_NOTE not in err
