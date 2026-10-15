"""The terminal UI must be invisible to everything that is not a human terminal.

Adding a full-screen interface is only safe if scripts, CI, pipes, JSON output,
and the protocol bridges keep their exact previous behaviour. These tests assert
that from the CLI boundary rather than from inside the UI.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path

import pytest
from typer.testing import CliRunner

import finishup.cli.app as cli
import finishup.cli.menu as menu
import finishup.tui as tui

_RUNNER = CliRunner()


def _gate(answer: bool) -> Callable[[Mapping[str, str] | None], bool]:
    """A stand-in availability gate with the real signature."""

    def gate(environment: Mapping[str, str] | None = None) -> bool:
        return answer

    return gate


@pytest.fixture
def quiet_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """A completed first run with no reachable service and no Codex on PATH."""

    import finishup.adapters.integrations.codex_discovery as discovery_module
    import finishup.cli.setup as setup_module
    from finishup.ports.control import ControlError
    from finishup.ports.harness_mcp import HarnessBinary

    marker = tmp_path / "setup-wizard.json"
    marker.write_text('{"outcome":"registered","schema":"yoetz.setup-wizard-marker/1"}')

    def no_binaries(*, _probe: object = None) -> tuple[HarnessBinary, ...]:
        return ()

    async def unreachable() -> object:
        raise ControlError("service_unavailable")

    monkeypatch.setattr(discovery_module, "discover_codex_binaries", no_binaries)
    monkeypatch.setattr(setup_module, "setup_marker_path", lambda: marker)
    monkeypatch.setattr(cli, "build_service_client", unreachable)
    return marker


def test_a_bare_non_tty_invocation_still_prints_help(quiet_environment: Path) -> None:
    # CliRunner streams are not TTYs, which is exactly the automation case.
    result = _RUNNER.invoke(cli.app, [])
    assert result.exit_code == 0
    assert "Local-first evidence ledger and review engine." in result.output
    assert "Type / for FinishUP commands" not in result.output


def test_help_output_is_untouched_by_the_terminal_ui() -> None:
    result = _RUNNER.invoke(cli.app, ["--help"])
    assert result.exit_code == 0
    assert "Local-first evidence ledger and review engine." in result.output
    for command in ("mcp", "status", "receipt", "check", "privacy", "service"):
        assert command in result.output


def test_version_output_is_a_bare_version_string() -> None:
    from finishup import __version__

    result = _RUNNER.invoke(cli.app, ["--version"])
    assert result.exit_code == 0
    assert result.output.strip() == __version__


def test_the_gate_is_consulted_before_the_interface_is_ever_built(
    quiet_environment: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A refused gate must not import, construct, or run the application."""

    opened: list[bool] = []

    def never(*, first_run: bool = False, cwd: object = None) -> int:
        opened.append(True)
        return 0

    monkeypatch.setattr(tui, "run_tui", never)
    monkeypatch.setattr(tui, "tui_available", _gate(False))
    result = _RUNNER.invoke(cli.app, [])
    assert result.exit_code == 0
    assert opened == []


def test_an_interactive_terminal_opens_the_interface_instead_of_the_menu(
    quiet_environment: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[bool] = []

    def fake_run(*, first_run: bool = False, cwd: object = None) -> int:
        calls.append(first_run)
        return 0

    monkeypatch.setattr(tui, "tui_available", _gate(True))
    monkeypatch.setattr(tui, "tui_supported", lambda: True)
    monkeypatch.setattr(tui, "run_tui", fake_run)

    def refuse_menu() -> int:
        pytest.fail("the prompt menu must not open")

    monkeypatch.setattr(menu, "run_menu", refuse_menu)
    result = _RUNNER.invoke(cli.app, [])
    assert result.exit_code == 0
    assert calls == [False]


def test_a_first_run_terminal_folds_setup_into_the_interface(
    quiet_environment: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import finishup.cli.setup as setup_module

    calls: list[bool] = []
    monkeypatch.setattr(setup_module, "should_offer_first_run", lambda: True)
    monkeypatch.setattr(tui, "tui_available", _gate(True))
    monkeypatch.setattr(tui, "tui_supported", lambda: True)

    def record(*, first_run: bool = False, cwd: object = None) -> int:
        calls.append(first_run)
        return 0

    monkeypatch.setattr(tui, "run_tui", record)
    result = _RUNNER.invoke(cli.app, [])
    assert result.exit_code == 0
    assert calls == [True]


def test_an_installation_without_the_renderer_falls_back_to_the_prompt_menu(
    quiet_environment: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The interface is a presentation choice, never a hard requirement."""

    monkeypatch.setattr(tui, "tui_available", _gate(True))
    monkeypatch.setattr(tui, "tui_supported", lambda: False)
    monkeypatch.setattr(menu, "menu_available", lambda: True)
    result = _RUNNER.invoke(cli.app, [], input="q\n")
    assert result.exit_code == 0
    assert "Refresh status" in result.output


def test_menu_without_a_terminal_remains_a_usage_failure() -> None:
    result = _RUNNER.invoke(cli.app, ["menu"])
    assert result.exit_code == 2
    assert "invalid_request" in result.output


def test_named_subcommands_never_open_the_interface(
    quiet_environment: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tui, "tui_available", _gate(True))
    monkeypatch.setattr(tui, "tui_supported", lambda: True)

    def refuse(*, first_run: bool = False, cwd: object = None) -> int:
        pytest.fail("a named command must not open the UI")

    monkeypatch.setattr(tui, "run_tui", refuse)
    for argv in (["--help"], ["version"], ["setup", "--help"], ["mcp", "--help"]):
        result = _RUNNER.invoke(cli.app, argv)
        assert result.exit_code == 0, argv


def test_setup_status_json_stays_canonical(
    quiet_environment: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The wizard's machine output must not gain terminal-UI wording."""

    import json

    import finishup.adapters.integrations.codex_discovery as discovery_module
    from finishup.ports.harness_mcp import HarnessBinary

    def no_binaries(*, _probe: object = None) -> tuple[HarnessBinary, ...]:
        return ()

    monkeypatch.setattr(discovery_module, "discover_codex_binaries", no_binaries)
    result = _RUNNER.invoke(cli.app, ["setup", "status", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["schema"] == "yoetz.setup-status/2"
    assert set(payload) >= {"discovered", "integration", "marker_present", "schema", "service"}
