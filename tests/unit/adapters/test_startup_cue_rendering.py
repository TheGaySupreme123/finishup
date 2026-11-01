"""Startup instructions must not depend on consented observation executing."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from finishup.adapters.integrations.claude_code_integration import render_claude_code_plugin
from finishup.adapters.integrations.cursor_integration import render_cursor_plugin
from finishup.ports.plugin_artifacts import PluginFormatProfile


@pytest.mark.parametrize("profile", ["structural", "ordinary"])
@pytest.mark.parametrize("host", ["claude", "cursor"])
def test_native_startup_has_an_independent_cue(tmp_path: Path, host: str, profile: str) -> None:
    launcher = tmp_path / "finishup"
    launcher.write_text("#!/bin/sh\nexit 0\n")
    launcher.chmod(0o700)
    assert profile in {"structural", "ordinary"}
    if host == "claude":
        artifact = render_claude_code_plugin(
            finishup_launcher=launcher,
            observation_profile="ordinary" if profile == "ordinary" else "structural",
        )
        groups = json.loads(artifact.members["hooks/hooks.json"])["hooks"]["SessionStart"]
        commands = [hook for group in groups for hook in group["hooks"]]
    else:
        artifact = render_cursor_plugin(
            PluginFormatProfile.CURSOR_PLUGIN_NATIVE,
            finishup_launcher=launcher,
            observation_profile="ordinary" if profile == "ordinary" else "structural",
        )
        commands = json.loads(artifact.members["hooks/hooks.json"])["hooks"]["sessionStart"]
    cue, observation = commands
    assert cue["command"] == f"{launcher} hooks startup-context --host {host}"
    assert cue["timeout"] == 2
    assert f"hooks {host}-observe" in observation["command"]
    assert observation["timeout"] == 10


@pytest.mark.parametrize("host", ["claude", "cursor"])
def test_required_is_explicit_and_optional_removes_every_gate(tmp_path: Path, host: str) -> None:
    launcher = tmp_path / "finishup"
    launcher.write_text("#!/bin/sh\nexit 0\n")
    launcher.chmod(0o700)
    if host == "claude":
        required = render_claude_code_plugin(finishup_launcher=launcher, startup_mode="required")
        optional = render_claude_code_plugin(finishup_launcher=launcher, startup_mode="optional")
        hooks = json.loads(required.members["hooks/hooks.json"])["hooks"]
        for event in (
            "SessionStart",
            "UserPromptSubmit",
            "PreToolUse",
            "PostToolUse",
            "PostToolUseFailure",
            "SessionEnd",
        ):
            assert (
                f"startup-gate --host claude --event {event}"
                in hooks[event][0]["hooks"][0]["command"]
            )
    else:
        required = render_cursor_plugin(
            PluginFormatProfile.CURSOR_PLUGIN_NATIVE,
            finishup_launcher=launcher,
            startup_mode="required",
            observation_profile="ordinary",
        )
        optional = render_cursor_plugin(
            PluginFormatProfile.CURSOR_PLUGIN_NATIVE,
            finishup_launcher=launcher,
            startup_mode="optional",
            observation_profile="ordinary",
        )
        hooks = json.loads(required.members["hooks/hooks.json"])["hooks"]
        for event in (
            "sessionStart",
            "beforeSubmitPrompt",
            "preToolUse",
            "beforeMCPExecution",
            "afterMCPExecution",
            "sessionEnd",
        ):
            assert f"startup-gate --host cursor --event {event}" in hooks[event][0]["command"]
        assert len(hooks["preToolUse"]) == 2
        assert "cursor-observe" in hooks["preToolUse"][1]["command"]
        assert "cursor-observe" in hooks["postToolUse"][0]["command"]
        with pytest.raises(ValueError, match="startup_mode_unsupported"):
            render_cursor_plugin(PluginFormatProfile.AGENT_PLUGINS_1, startup_mode="required")
    assert b"startup-gate" not in optional.members["hooks/hooks.json"]
    assert required.artifact_digest != optional.artifact_digest
