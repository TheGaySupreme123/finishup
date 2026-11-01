"""All Codex status paths must inspect the same selected installation."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from typer.testing import CliRunner

from finishup.adapters.integrations import codex_mcp
from finishup.adapters.integrations.codex_marketplace import ActivationInspection, ActivationState
from finishup.adapters.integrations.codex_session_stream import resolve_codex_home
from finishup.cli import codex_plugin, provider_status, setup
from finishup.cli.app import app
from finishup.ports.harness_mcp import HarnessBinary
from finishup.ports.integrations import HarnessId


@pytest.mark.parametrize("selection", ["explicit", "environment", "testing", "default"])
def test_plugin_status_home_precedence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    selection: str,
) -> None:
    homes = {name: tmp_path / name for name in ("explicit", "environment", "testing", "default")}
    for home in homes.values():
        home.mkdir(mode=0o700)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    homes["default"] = tmp_path / ".codex"
    homes["default"].mkdir()
    monkeypatch.delenv("CODEX_HOME", raising=False)
    monkeypatch.delenv("CODEX_TESTING_HOME", raising=False)
    if selection in {"explicit", "environment"}:
        monkeypatch.setenv("CODEX_HOME", str(homes["environment"]))
    if selection != "default":
        monkeypatch.setenv("CODEX_TESTING_HOME", str(homes["testing"]))
    binary = HarnessBinary(HarnessId.CODEX, "/test/codex", "0.150.1", "untested")
    monkeypatch.setattr(codex_plugin, "discover_codex_binaries", lambda: (binary,))

    def inspect(*_args: object, codex_home: Path, **_kwargs: object) -> ActivationInspection:
        assert codex_home == homes[selection]
        return ActivationInspection(True, True, ActivationState.ACTIVE)

    monkeypatch.setattr(codex_plugin, "inspect_activation", inspect)

    def skill_state(_target: object) -> str:
        return "absent"

    monkeypatch.setattr(codex_plugin, "skill_tree_state", skill_state)
    args = ["integrate", "codex", "plugin", "status", "--json"]
    if selection == "explicit":
        args.extend(("--codex-home", str(homes[selection])))
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["inspected_codex_home"] == str(homes[selection])


@pytest.mark.anyio
async def test_mcp_and_provider_probes_bind_explicit_home(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    chosen = tmp_path / "chosen"
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "foreign"))
    monkeypatch.setenv("CODEX_TESTING_HOME", str(tmp_path / "other"))
    binary = HarnessBinary(HarnessId.CODEX, "/test/codex", "0.150.1", "untested")
    monkeypatch.setattr(setup, "discover_codex_binaries", lambda: (binary,))
    monkeypatch.setattr(
        "finishup.adapters.integrations.codex_discovery.discover_codex_binaries", lambda: (binary,)
    )
    seen: list[Path | None] = []

    def runner(
        _argv: tuple[str, ...], *, codex_home: Path | None = None
    ) -> codex_mcp.CommandOutput:
        seen.append(codex_home)
        return codex_mcp.CommandOutput(1, b"")

    monkeypatch.setattr(codex_mcp, "_default_runner", runner)
    monkeypatch.setattr(codex_mcp, "isolated_root", lambda: None)
    monkeypatch.setattr(codex_mcp, "installed_launcher", lambda: None)

    def emit(*_args: object, **_kwargs: object) -> None:
        pass

    monkeypatch.setattr(setup, "_emit", emit)
    await setup.integrate_mcp(
        "status",
        "codex",
        codex_path=None,
        codex_home=chosen,
        accept=False,
        preview_digest=None,
        json_output=True,
        _state=tmp_path,
    )
    await provider_status.mcp_route_observation(tmp_path, codex_home=chosen, _state=tmp_path)
    assert len(seen) >= 2
    assert set(seen) == {chosen}


@pytest.mark.anyio
async def test_provider_probe_binds_testing_home_when_no_home_is_passed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    testing = tmp_path / "testing"
    testing.mkdir(mode=0o700)
    monkeypatch.delenv("CODEX_HOME", raising=False)
    monkeypatch.setenv("CODEX_TESTING_HOME", str(testing))
    binary = HarnessBinary(HarnessId.CODEX, "/test/codex", "0.150.1", "untested")
    monkeypatch.setattr(
        "finishup.adapters.integrations.codex_discovery.discover_codex_binaries", lambda: (binary,)
    )
    seen: list[Path | None] = []

    def runner(
        _argv: tuple[str, ...], *, codex_home: Path | None = None
    ) -> codex_mcp.CommandOutput:
        seen.append(codex_home)
        return codex_mcp.CommandOutput(1, b"")

    monkeypatch.setattr(codex_mcp, "_default_runner", runner)
    monkeypatch.setattr(codex_mcp, "isolated_root", lambda: None)
    monkeypatch.setattr(codex_mcp, "installed_launcher", lambda: None)

    route = await provider_status.mcp_route_observation(tmp_path, _state=tmp_path)

    assert route["observed"] is False
    assert seen
    assert set(seen) == {testing}


def test_bound_runner_overrides_both_ambient_homes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("CODEX_HOME", "/foreign")
    monkeypatch.setenv("CODEX_TESTING_HOME", "/also-foreign")

    def run(_argv: object, **kwargs: Any) -> SimpleNamespace:
        assert kwargs["env"]["CODEX_HOME"] == str(tmp_path)
        assert kwargs["env"]["CODEX_TESTING_HOME"] == str(tmp_path)
        assert kwargs["shell"] is False
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(codex_mcp.subprocess, "run", run)
    codex_mcp._default_runner(("/test/codex", "mcp", "list"), codex_home=tmp_path)  # pyright: ignore[reportPrivateUsage]
    assert resolve_codex_home(tmp_path) == tmp_path


def test_discovery_and_connection_honor_testing_home_before_default(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from finishup.adapters.integrations.codex_discovery import default_codex_home
    from finishup.adapters.integrations.host_discovery import host_config_root

    default = tmp_path / ".codex"
    testing = tmp_path / "testing"
    default.mkdir()
    testing.mkdir()
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    env = {"CODEX_TESTING_HOME": str(testing)}
    assert default_codex_home(env) == testing
    assert host_config_root("codex", environ=env) == testing
    assert resolve_codex_home(env=env) == testing


def test_setup_disconnect_accepts_the_selected_codex_home(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    captured: dict[str, object] = {}

    def disconnect(**kwargs: object) -> int:
        captured.update(kwargs)
        return 0

    monkeypatch.setattr("finishup.cli.host_connection.run_host_connection", disconnect)
    home = tmp_path / "selected-home"
    result = CliRunner().invoke(
        app,
        [
            "setup",
            "disconnect",
            "--host",
            "codex",
            "--codex-home",
            str(home),
            "--project",
            str(tmp_path),
            "--non-interactive",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    assert captured["host"] == "codex"
    assert captured["config_root"] == home
    assert captured["executable"] is None
