"""Claude activation cues: MCP mode and SessionStart cue from file observation (issue #789)."""

from __future__ import annotations

import json
from pathlib import Path

from finishup.adapters.integrations.claude_code_integration import (
    ClaudeCodeMcpSource,
    observe_claude_code_activation_cues,
)


def _launcher(tmp_path: Path) -> tuple[str, ...]:
    exe = tmp_path / "bin" / "finishup"
    exe.parent.mkdir()
    exe.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    exe.chmod(0o700)
    return (str(exe),)


def _mcp_entry(command: str, args: list[str]) -> dict[str, object]:
    return {"mcpServers": {"finishup": {"args": args, "command": command, "type": "stdio"}}}


def _session_start_hook(command: str) -> dict[str, object]:
    return {
        "hooks": {
            "SessionStart": [
                {
                    "hooks": [{"command": command, "timeout": 10, "type": "command"}],
                    "matcher": "startup|resume|clear|compact|fork",
                }
            ]
        }
    }


def _roots(tmp_path: Path) -> tuple[Path, Path]:
    config = tmp_path / "config"
    project = tmp_path / "project"
    config.mkdir()
    project.mkdir()
    return config, project


def test_a_bare_mcp_entry_in_the_user_config_has_no_session_start_cue(tmp_path: Path) -> None:
    launcher = _launcher(tmp_path)
    config, project = _roots(tmp_path)
    (config / ".claude.json").write_text(
        json.dumps(_mcp_entry(launcher[0], ["mcp", "serve", "--host", "claude"])),
        encoding="utf-8",
    )
    cues = observe_claude_code_activation_cues(
        project_root=project, claude_config_root=config, finishup_launcher=launcher
    )
    assert cues.mcp_mode == "bare_mcp"
    assert cues.mcp_source is ClaudeCodeMcpSource.USER
    assert cues.route_profile == "policy"
    assert cues.host_profile == "claude"
    assert cues.session_start_cue == "absent"
    assert cues.cue_sources == ()
    assert cues.as_json() == {
        "cue_sources": [],
        "mcp_mode": "bare_mcp",
        "mcp_source": "user",
        "notes": [
            "cue_presence_does_not_prove_hook_ran",
            "file_observation_only",
            "plugin_hooks_require_enabled_plugin",
        ],
        "host_profile": "claude",
        "route_profile": "policy",
        "session_start_cue": "absent",
    }
    # Without the exact launcher, a launcher-bound entry is not a route this installation owns.
    assert (
        observe_claude_code_activation_cues(
            project_root=project, claude_config_root=config
        ).mcp_mode
        == "foreign"
    )


def test_the_user_config_file_is_located_the_way_claude_code_locates_it(tmp_path: Path) -> None:
    # Claude Code keeps `~/.claude.json` beside the default `~/.claude` root and inside
    # `CLAUDE_CONFIG_DIR` when that variable names the root. A stray in-root file beside the
    # default root (this maintainer's machine has one) must not hide the real registration.
    config = tmp_path / ".claude"
    project = tmp_path / "project"
    config.mkdir()
    project.mkdir()
    (tmp_path / ".claude.json").write_text(
        json.dumps(_mcp_entry("finishup", ["mcp", "serve"])), encoding="utf-8"
    )
    (config / ".claude.json").write_text(json.dumps({"mcpServers": {}}), encoding="utf-8")
    default_root = observe_claude_code_activation_cues(
        project_root=project, claude_config_root=config, home=tmp_path, environ={}
    )
    assert default_root.mcp_mode == "bare_mcp"
    assert default_root.mcp_source is ClaudeCodeMcpSource.USER
    assert default_root.host_profile == "generic"
    configured_root = observe_claude_code_activation_cues(
        project_root=project,
        claude_config_root=config,
        home=tmp_path,
        environ={"CLAUDE_CONFIG_DIR": str(config)},
    )
    assert configured_root.mcp_mode == "absent"
    custom = tmp_path / "custom"
    custom.mkdir()
    (custom / ".claude.json").write_text(
        json.dumps(_mcp_entry("finishup", ["mcp", "serve", "--semantic", "off"])), encoding="utf-8"
    )
    explicit_root = observe_claude_code_activation_cues(
        project_root=project, claude_config_root=custom, home=tmp_path, environ={}
    )
    assert explicit_root.mcp_mode == "bare_mcp"
    assert explicit_root.route_profile == "strict"
    assert explicit_root.host_profile == "generic"


def test_a_legacy_bare_route_reports_the_generic_initialize_body(tmp_path: Path) -> None:
    config, project = _roots(tmp_path)
    (config / ".claude.json").write_text(
        json.dumps(_mcp_entry("finishup", ["mcp", "serve"])), encoding="utf-8"
    )
    cues = observe_claude_code_activation_cues(project_root=project, claude_config_root=config)
    assert cues.mcp_mode == "bare_mcp"
    assert cues.route_profile == "policy"
    assert cues.host_profile == "generic"
    assert cues.as_json()["host_profile"] == "generic"


def test_a_plugin_managed_registration_carries_the_rendered_session_start_hook(
    tmp_path: Path,
) -> None:
    launcher = _launcher(tmp_path)
    config, project = _roots(tmp_path)
    plugin_root = config / "plugins" / "marketplaces" / "finishup-local" / "plugins" / "finishup"
    (plugin_root / "hooks").mkdir(parents=True)
    (plugin_root / ".mcp.json").write_text(
        json.dumps(
            _mcp_entry(launcher[0], ["mcp", "serve", "--host", "claude", "--semantic", "off"])
        ),
        encoding="utf-8",
    )
    (plugin_root / "hooks" / "hooks.json").write_text(
        json.dumps(
            _session_start_hook(
                f'{launcher[0]} hooks claude-observe --workspace "${{CLAUDE_PROJECT_DIR}}"'
            )
        ),
        encoding="utf-8",
    )
    cues = observe_claude_code_activation_cues(
        project_root=project, claude_config_root=config, finishup_launcher=launcher
    )
    assert cues.mcp_mode == "plugin_managed"
    assert cues.mcp_source is ClaudeCodeMcpSource.PLUGIN
    assert cues.route_profile == "strict"
    assert cues.host_profile == "claude"
    assert cues.session_start_cue == "installed"
    assert cues.cue_sources == ("plugin_hooks",)
    # A bare entry beside the plugin entry is the dual state the runbook already documents.
    (project / ".mcp.json").write_text(
        json.dumps(_mcp_entry("finishup", ["mcp", "serve"])), encoding="utf-8"
    )
    dual = observe_claude_code_activation_cues(
        project_root=project, claude_config_root=config, finishup_launcher=launcher
    )
    assert dual.mcp_mode == "dual"
    assert dual.session_start_cue == "installed"


def test_settings_hooks_count_as_cues_and_unreadable_files_are_reported(tmp_path: Path) -> None:
    config, project = _roots(tmp_path)
    assert observe_claude_code_activation_cues(
        project_root=project, claude_config_root=config
    ).as_json() == {
        "cue_sources": [],
        "mcp_mode": "absent",
        "mcp_source": None,
        "notes": [
            "cue_presence_does_not_prove_hook_ran",
            "file_observation_only",
            "plugin_hooks_require_enabled_plugin",
        ],
        "host_profile": None,
        "route_profile": None,
        "session_start_cue": "absent",
    }
    (config / "settings.json").write_text(
        json.dumps(_session_start_hook("/opt/finishup/bin/finishup hooks claude-observe")),
        encoding="utf-8",
    )
    (project / ".claude").mkdir()
    (project / ".claude" / "settings.json").write_text(
        json.dumps(_session_start_hook("echo unrelated")), encoding="utf-8"
    )
    (project / ".claude" / "settings.local.json").write_text(
        json.dumps(_session_start_hook("/opt/finishup/bin/finishup hooks claude-observe")),
        encoding="utf-8",
    )
    cues = observe_claude_code_activation_cues(project_root=project, claude_config_root=config)
    assert cues.mcp_mode == "absent"
    assert cues.session_start_cue == "installed"
    assert cues.cue_sources == ("user_settings", "project_local_settings")

    (config / "settings.json").write_text("not json", encoding="utf-8")
    (project / ".claude" / "settings.local.json").unlink()
    unobserved = observe_claude_code_activation_cues(
        project_root=project, claude_config_root=config
    )
    assert unobserved.session_start_cue == "unobserved"
    assert unobserved.cue_sources == ()


def test_a_foreign_project_entry_is_named_not_counted(tmp_path: Path) -> None:
    config, project = _roots(tmp_path)
    (project / ".mcp.json").write_text(
        json.dumps(
            {"mcpServers": {"finishup": {"args": ["-c", "x"], "command": "sh", "type": "stdio"}}}
        ),
        encoding="utf-8",
    )
    cues = observe_claude_code_activation_cues(project_root=project, claude_config_root=config)
    assert cues.mcp_mode == "foreign"
    assert cues.route_profile is None
    assert cues.session_start_cue == "absent"
