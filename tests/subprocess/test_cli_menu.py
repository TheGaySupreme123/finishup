"""Interactive menu: TTY gating, bare-invocation dispatch, and navigation."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

import finishup.cli.app as cli
import finishup.cli.menu as menu
from finishup.ports.control import ControlError
from finishup.ports.harness_mcp import HarnessBinary
from finishup.ports.integrations import HarnessId

_RUNNER = CliRunner()


@pytest.fixture
def menu_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Fake TTY probes, discovery, marker path, and an unreachable service client."""

    import finishup.adapters.integrations.codex_discovery as discovery_module
    import finishup.cli.setup as setup_module

    marker = tmp_path / "setup-wizard.json"
    marker.write_text('{"outcome":"registered","schema":"yoetz.setup-wizard-marker/1"}')

    def fake_discover(*, _probe: object = None) -> tuple[HarnessBinary, ...]:
        return (
            HarnessBinary(
                harness_id=HarnessId.CODEX,
                executable_path="/opt/harness/bin/codex",
                reported_version="0.144.5",
                compatibility="untested",
            ),
        )

    async def unreachable_client() -> object:
        raise ControlError("service_unavailable")

    monkeypatch.setattr(menu, "menu_available", lambda: True)
    monkeypatch.setattr(discovery_module, "discover_codex_binaries", fake_discover)
    monkeypatch.setattr(setup_module, "setup_marker_path", lambda: marker)
    monkeypatch.setattr(cli, "build_service_client", unreachable_client)
    return marker


def test_menu_without_tty_is_usage_failure() -> None:
    result = _RUNNER.invoke(cli.app, ["menu"])
    assert result.exit_code == 2
    assert "invalid_request" in result.output
    assert "Select" not in result.output


def test_menu_home_renders_overview_and_quits(menu_env: Path) -> None:
    result = _RUNNER.invoke(cli.app, ["menu"], input="q\n")
    assert result.exit_code == 0
    assert "finishup service run" in result.output
    assert "codex (0.144.5)" in result.output
    assert "First-run  complete" in result.output
    for section in ("Setup wizard", "Harness connection", "LLM provider", "Privacy", "Service"):
        assert section in result.output


def test_menu_sections_navigate_back_to_home(menu_env: Path) -> None:
    result = _RUNNER.invoke(cli.app, ["menu"], input="4\nb\n5\nb\n6\nb\nq\n")
    assert result.exit_code == 0
    assert "Replace API key for the configured provider" in result.output
    assert "Show effective policy" in result.output
    assert "Unlock vault" in result.output
    # Returning from each section re-renders the home screen before quitting.
    assert result.output.count("1  Refresh status") >= 4


def test_bare_tty_invocation_with_marker_opens_menu(
    menu_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import finishup.cli.setup as setup_module

    monkeypatch.setattr(setup_module, "should_offer_first_run", lambda: False)
    result = _RUNNER.invoke(cli.app, [], input="q\n")
    assert result.exit_code == 0
    assert "Refresh status" in result.output


def test_bare_invocation_without_tty_still_prints_help(
    menu_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(menu, "menu_available", lambda: False)
    result = _RUNNER.invoke(cli.app, [])
    assert result.exit_code == 0
    assert "Usage" in result.output
    assert "Refresh status" not in result.output


def test_bare_tty_first_run_without_the_full_screen_ui_reaches_the_wizard(
    menu_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``FINISHUP_TUI=0`` (or no Textual) on a first run must open the prompt wizard, not die
    with ``internal_error`` because the fallback call forgot a required argument (#766)."""

    import finishup.cli.setup as setup_module

    received: dict[str, object] = {}

    async def fake_wizard(**kwargs: object) -> int:
        received.update(kwargs)
        return 0

    monkeypatch.setenv("FINISHUP_TUI", "0")
    monkeypatch.setattr(setup_module, "should_offer_first_run", lambda: True)
    monkeypatch.setattr(setup_module, "run_setup_wizard", fake_wizard)
    result = _RUNNER.invoke(cli.app, [], input="q\n")
    assert result.exit_code == 0, result.output
    assert "internal_error" not in result.output
    assert received == {
        "non_interactive": False,
        "codex_path": None,
        "codex_home": None,
        "accept": False,
        "json_output": False,
    }
