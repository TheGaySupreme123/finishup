"""Native observation selection is reachable through the public artifact lifecycle."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from finishup.adapters.integrations.cursor_integration import render_cursor_plugin
from finishup.cli.app import app
from finishup.cli.cursor_integration import plugin_artifact as cursor_artifact
from finishup.ports.plugin_artifacts import PluginFormatProfile


def test_claude_export_selects_ordinary_without_granting_content(tmp_path: Path) -> None:
    root = tmp_path / "ordinary"
    result = CliRunner().invoke(
        app,
        [
            "integrate",
            "claude",
            "plugin",
            "export",
            "--output-root",
            str(root),
            "--development-enabled",
            "--observation-profile",
            "ordinary",
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    body = json.loads(result.stdout)
    assert body["observation_profile"] == "claude-code-ordinary-observation-v1"
    hooks = json.loads((root / "hooks/hooks.json").read_text())["hooks"]
    assert "PreToolUse" in hooks
    assert hooks["PostToolUse"][0]["matcher"] == ".*"
    assert (
        "--observation-profile claude-code-ordinary-observation-v1"
        in hooks["PreToolUse"][0]["hooks"][0]["command"]
    )
    # Export does not invoke observation consent or need a host configuration.
    assert sorted(p.name for p in tmp_path.iterdir()) == ["ordinary"]


def test_cursor_profile_selection_changes_artifact_and_reverses() -> None:
    structural = cursor_artifact("native", "external-registration", None)
    ordinary = cursor_artifact(
        "native", "external-registration", None, observation_profile="ordinary"
    )
    restored = cursor_artifact(
        "native", "external-registration", None, observation_profile="structural"
    )
    assert ordinary.artifact_digest != structural.artifact_digest
    assert restored.artifact_digest == structural.artifact_digest
    hooks = json.loads(ordinary.members["hooks/hooks.json"])["hooks"]
    assert "preToolUse" in hooks and "afterFileEdit" not in hooks
    assert ordinary.plan.host_extension_profile == "cursor-ordinary-observation-v1"


@pytest.mark.parametrize("host,format_name", [("cursor", "portable"), ("codex", "native")])
def test_ordinary_profile_rejects_unsupported_carriers(host: str, format_name: str) -> None:
    result = CliRunner().invoke(
        app,
        [
            "integrate",
            host,
            "plugin",
            "status",
            "--format",
            format_name,
            "--observation-profile",
            "ordinary",
        ],
    )
    assert result.exit_code == 2
    assert "ordinary observation requires native Claude or Cursor" in result.output


def test_cursor_portable_api_rejects_ordinary_profile() -> None:
    with pytest.raises(ValueError, match="cursor_observation_profile_unsupported"):
        cursor_artifact("portable", "external-registration", None, observation_profile="ordinary")


def test_cursor_portable_renderer_rejects_ordinary_profile() -> None:
    with pytest.raises(ValueError, match="cursor_observation_profile_unsupported"):
        render_cursor_plugin(PluginFormatProfile.AGENT_PLUGINS_1, observation_profile="ordinary")


def test_cursor_cli_preview_binds_ordinary_profile_without_installing(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    config = tmp_path / "cursor" / ".cursor"
    args = [
        "integrate",
        "cursor",
        "plugin",
        "preview",
        "--cursor-config-root",
        str(config),
        "--project-root",
        str(project),
        "--format",
        "native",
        "--json",
    ]
    structural = CliRunner().invoke(app, args)
    ordinary = CliRunner().invoke(app, [*args, "--observation-profile", "ordinary"])
    assert structural.exit_code == 0, structural.output
    assert ordinary.exit_code == 0, ordinary.output
    assert (
        json.loads(structural.stdout)["artifact_digest"]
        != json.loads(ordinary.stdout)["artifact_digest"]
    )
    assert json.loads(ordinary.stdout)["observation_profile"] == "cursor-ordinary-observation-v1"
    status_args = args.copy()
    status_args[3] = "status"
    status = CliRunner().invoke(app, [*status_args, "--observation-profile", "ordinary"])
    assert status.exit_code == 0, status.output
    body = json.loads(status.stdout)
    assert body["requested_observation_profile"] == "cursor-ordinary-observation-v1"
    assert body["installed_observation_profile"] is None
    assert not (config / "plugins").exists()
