"""`setup status` host rows name the Claude activation posture (issue #789)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from finishup.adapters.integrations.host_discovery import HostInstallation
from finishup.cli import host_connection as cli


def _bare_entry() -> dict[str, object]:
    return {
        "mcpServers": {
            "finishup": {
                "args": ["mcp", "serve", "--host", "claude"],
                "command": "finishup",
                "type": "stdio",
            }
        }
    }


def test_installation_rows_name_the_claude_mcp_mode_and_session_start_cue(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = tmp_path / "claude-config"
    config.mkdir()
    (config / ".claude.json").write_text(json.dumps(_bare_entry()), encoding="utf-8")
    project = tmp_path / "project"
    project.mkdir()
    claude = HostInstallation("claude", Path("/opt/claude"), "2.1.261", config, "Claude Code")
    cursor = HostInstallation(
        "cursor-ide", Path("/opt/cursor"), "2.6.0", tmp_path / ".cursor", "Cursor IDE"
    )
    monkeypatch.setattr(cli, "discover_hosts", lambda: (claude, cursor))
    monkeypatch.setattr(cli, "invoking_launcher", lambda: None)
    rows = cli.installation_rows(project)
    assert [row["host"] for row in rows] == ["claude", "cursor-ide"]  # type: ignore[index]
    claude_row = rows[0]
    assert isinstance(claude_row, dict)
    assert claude_row["connection_observed"] is False
    assert claude_row["activation_cues"] == {
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
    cursor_row = rows[1]
    assert isinstance(cursor_row, dict)
    assert cursor_row["activation_cues"] is None


@pytest.mark.parametrize("failure", [OSError("unreadable"), RuntimeError("home unavailable")])
def test_an_unreadable_claude_posture_is_none_not_a_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failure: Exception
) -> None:
    claude = HostInstallation(
        "claude", Path("/opt/claude"), "2.1.261", tmp_path / "missing", "Claude Code"
    )
    monkeypatch.setattr(cli, "discover_hosts", lambda: (claude,))
    monkeypatch.setattr(cli, "invoking_launcher", lambda: None)

    def broken(**_kwargs: object) -> object:
        raise failure

    import finishup.adapters.integrations.claude_code_integration as adapter

    monkeypatch.setattr(adapter, "observe_claude_code_activation_cues", broken)
    rows = cli.installation_rows(tmp_path)
    row = rows[0]
    assert isinstance(row, dict)
    assert row["activation_cues"] is None
