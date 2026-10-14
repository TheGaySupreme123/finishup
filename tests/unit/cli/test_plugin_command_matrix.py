"""Per-host plugin command matrix: help never advertises a dead command (#465)."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest
from typer.testing import CliRunner

from finishup.cli import app as app_module
from finishup.cli.app import app, plugin_commands_for_host
from finishup.cli.codex_plugin import CODEX_PLUGIN_COMMANDS
from finishup.cli.cursor_integration import CURSOR_PLUGIN_COMMANDS

_RUNNER = CliRunner()
_ALL_COMMANDS = ("preview", "install", "update", "enable", "disable", "status", "remove", "export")
_EXPECTED: dict[str, tuple[str, ...]] = {
    "claude": _ALL_COMMANDS,
    "codex": ("preview", "status", "remove"),
    "cursor": ("preview", "install", "status", "remove"),
}


def _host_options(harness: str, tmp_path: Path) -> list[str]:
    if harness == "codex":
        return ["--codex-home", str(tmp_path)]
    if harness == "cursor":
        return ["--cursor-config-root", str(tmp_path)]
    return [
        "--claude-path",
        str(tmp_path / "claude"),
        "--claude-config-root",
        str(tmp_path),
        "--cache-root",
        str(tmp_path),
        "--marketplace-root",
        str(tmp_path),
        "--project-root",
        str(tmp_path),
        "--output-root",
        str(tmp_path / "export-root"),
    ]


def _install_recorders(monkeypatch: pytest.MonkeyPatch, calls: list[tuple[str, str]]) -> None:
    """Replace every dispatcher with a recorder so the CLI gate is the unit under test."""

    import finishup.cli.claude_code_integration as claude_module
    import finishup.cli.codex_plugin as codex_module
    import finishup.cli.cursor_integration as cursor_module

    def recorder(host: str) -> Callable[..., int]:
        def run(command: str, **_kwargs: object) -> int:
            calls.append((host, command))
            return 0

        return run

    def export(**_kwargs: object) -> int:
        calls.append(("claude", "export"))
        return 0

    monkeypatch.setattr(codex_module, "run_codex_plugin_command", recorder("codex"))
    monkeypatch.setattr(cursor_module, "run_cursor_plugin_command", recorder("cursor"))
    monkeypatch.setattr(claude_module, "run_claude_code_plugin_command", recorder("claude"))
    monkeypatch.setattr(claude_module, "run_claude_code_plugin_export", export)

    def forbidden_discovery(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("binary discovery must never run for a refused command")

    monkeypatch.setattr(codex_module, "discover_codex_binaries", forbidden_discovery)


def test_matrix_matches_each_dispatcher_and_registered_commands() -> None:
    assert tuple(app_module._PLUGIN_COMMAND_HOSTS) == _ALL_COMMANDS  # pyright: ignore[reportPrivateUsage]
    for harness, expected in _EXPECTED.items():
        assert plugin_commands_for_host(harness) == expected
    assert CODEX_PLUGIN_COMMANDS == _EXPECTED["codex"]
    assert CURSOR_PLUGIN_COMMANDS == _EXPECTED["cursor"]


@pytest.mark.parametrize("harness", sorted(_EXPECTED))
@pytest.mark.parametrize("command", _ALL_COMMANDS)
def test_cli_gate_dispatches_supported_and_refuses_unsupported_before_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, harness: str, command: str
) -> None:
    calls: list[tuple[str, str]] = []
    _install_recorders(monkeypatch, calls)

    result = _RUNNER.invoke(
        app, ["integrate", harness, "plugin", command, *_host_options(harness, tmp_path)]
    )

    if command in _EXPECTED[harness]:
        assert result.exit_code == 0, result.output
        assert calls == [(harness, command)]
        return
    assert result.exit_code == 2, result.output
    assert calls == []
    supported = ",".join(_EXPECTED[harness])
    assert f"{harness}_plugin_command_unsupported:{command} supported={supported}" in result.stderr


@pytest.mark.parametrize("command", ("install", "update", "enable", "disable", "export"))
def test_codex_dispatcher_refuses_generic_lifecycle_without_binary_discovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Defense in depth: the dispatcher itself names the supported actions and never discovers."""

    import finishup.cli.codex_plugin as module

    def forbidden_discovery(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("binary discovery must never run for a refused command")

    monkeypatch.setattr(module, "discover_codex_binaries", forbidden_discovery)
    code = module.run_codex_plugin_command(
        command,
        harness="codex",
        project_root=None,
        codex_path=None,
        codex_home=tmp_path,
        purge_cache=False,
        preview_digest=None,
        accept=False,
        json_output=False,
    )
    assert code == 2
    assert capsys.readouterr().err == (
        f"codex_plugin_command_unsupported:{command} supported=preview,status,remove\n"
    )


@pytest.mark.parametrize("command", ("update", "enable", "disable", "export"))
def test_cursor_dispatcher_refuses_generic_lifecycle_by_name(
    tmp_path: Path, command: str, capsys: pytest.CaptureFixture[str]
) -> None:
    import finishup.cli.cursor_integration as module

    code = module.run_cursor_plugin_command(
        command,
        harness="cursor",
        cursor_config_root=tmp_path,
        project_root=None,
        format_name="portable",
        ownership_name="external-registration",
        route_profile=None,
        requested_action=None,
        request_value=None,
        preview_digest=None,
        accept=False,
        json_output=False,
    )
    assert code == 2
    assert capsys.readouterr().err == (
        f"cursor_plugin_command_unsupported:{command} supported=preview,install,status,remove\n"
    )


def test_wrong_harness_at_the_dispatcher_stays_the_closed_invalid_token(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    import finishup.cli.codex_plugin as module

    code = module.run_codex_plugin_command(
        "preview",
        harness="cursor",
        project_root=None,
        codex_path=None,
        codex_home=tmp_path,
        purge_cache=False,
        preview_digest=None,
        accept=False,
        json_output=False,
    )
    assert code == 2
    assert capsys.readouterr().err == "codex_plugin_command_invalid\n"


def _flatten_help(output: str) -> str:
    """Collapse rich's wrapped, box-drawn help into one whitespace-normalized line."""

    return " ".join(output.replace("│", " ").replace("╭", " ").replace("╰", " ").split())


def test_plugin_help_marks_every_command_with_its_hosts() -> None:
    result = _RUNNER.invoke(
        app, ["integrate", "codex", "plugin", "--help"], env={"COLUMNS": "300", "TERM": "dumb"}
    )
    assert result.exit_code == 0, result.output
    text = _flatten_help(result.output)
    assert "Codex supports only preview, status, and remove" in text
    for command in ("install", "update", "enable", "disable", "export"):
        assert f"{command} " in text
        assert "Not supported for Codex" in text
    assert (
        "Render the exact plan and digest for a plugin change (Claude Code, Codex, Cursor)." in text
    )
    assert (
        "Apply a previewed plugin install (Claude Code, Cursor). Not supported for Codex." in text
    )

    action_help = _RUNNER.invoke(
        app,
        ["integrate", "codex", "plugin", "preview", "--help"],
        env={"COLUMNS": "300", "TERM": "dumb"},
    )
    assert "Not used for Codex (removal only)" in _flatten_help(action_help.output)
