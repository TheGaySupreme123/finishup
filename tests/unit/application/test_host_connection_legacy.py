"""Guided Cursor connection over a pre-rename install (ADR-048), against isolated real state.

A Yoetz-era connection left a marker-valid ``plugins/local/yoetz`` tree and a project entry
under the ``yoetz`` key that launches the old installation's launcher; only the legacy marker
proves that launcher is FinishUP's. One reviewed connect migrates both, one reviewed disconnect
removes both, and neither ever needs the old launcher to exist.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any, cast

import pytest

from finishup.adapters.integrations.cursor_integration import (
    CursorPluginTarget,
    apply_cursor_plugin,
    preview_cursor_plugin,
    render_cursor_plugin,
)
from finishup.adapters.integrations.host_discovery import HostInstallation, SetupHost
from finishup.application.host_connection import (
    ConnectionAction,
    ConnectionPlan,
    apply_connection,
    prepare_connection,
)
from finishup.domain.values import request_id
from finishup.ports.plugin_artifacts import (
    ArtifactAuthority,
    McpOwnership,
    PluginArtifactAction,
    PluginFormatProfile,
)
from finishup.protocol.canonical import JsonValue, canonical_digest, canonical_encode

OLD_LAUNCHER = "/opt/yoetz-old/bin/yoetz"


class _Review:
    def consume_artifact_review(self, authority: ArtifactAuthority, preview_digest: str) -> None:
        assert authority.target_digest == preview_digest

    def consume_setup_authority(self, authority: ArtifactAuthority, preview_digest: str) -> None:
        assert authority.target_digest == preview_digest


def _legacy_connection(tmp_path: Path, launcher: Path) -> tuple[Path, Path]:
    """Lay out what a 0.2 guided connection left: legacy tree, legacy-key project entry."""

    project = tmp_path / "project"
    config = tmp_path / "cursor"
    project.mkdir(mode=0o700)
    config.mkdir(mode=0o700)
    artifact = render_cursor_plugin(
        PluginFormatProfile.CURSOR_PLUGIN_NATIVE,
        mcp_ownership=McpOwnership.EXTERNAL_REGISTRATION,
        finishup_launcher=launcher,
    )
    target = CursorPluginTarget(str(config))
    request = request_id("req_50000000-0000-4000-8000-000000000001")
    preview = preview_cursor_plugin(request, target, PluginArtifactAction.INSTALL, artifact)
    apply_cursor_plugin(
        request,
        target,
        PluginArtifactAction.INSTALL,
        artifact,
        accepted_preview_digest=preview.preview_digest,
        authority=ArtifactAuthority("setup_composition", preview.preview_digest),
        review=_Review(),
    )
    local = config / "plugins" / "local"
    (local / "finishup").rename(local / "yoetz")
    # The old installation recorded its own launcher; keep the marker self-consistent.
    marker_path = local / "yoetz" / ".yoetz-cursor-plugin-install.json"
    marker = json.loads(marker_path.read_bytes())
    body = {key: value for key, value in marker.items() if key != "marker_digest"}
    body["yoetz_launcher"] = [OLD_LAUNCHER]
    marker_path.write_bytes(
        canonical_encode(cast(JsonValue, {**body, "marker_digest": canonical_digest(body)}))
    )
    entry = {
        "type": "stdio",
        "command": OLD_LAUNCHER,
        "args": [
            "mcp",
            "serve",
            "--host",
            "cursor",
            "--project-root",
            "${workspaceFolder}",
            "--semantic",
            "off",
        ],
    }
    (project / ".cursor").mkdir(mode=0o700)
    (project / ".cursor" / "mcp.json").write_text(
        json.dumps({"mcpServers": {"yoetz": entry}}), encoding="utf-8"
    )
    return project, config


def _connection(
    installation: HostInstallation,
    project: Path,
    launcher: Path,
    action: ConnectionAction,
    number: int,
) -> tuple[ConnectionPlan, dict[str, JsonValue]]:
    request = request_id(f"req_50000000-0000-4000-8000-{number:012d}")

    def prepare() -> ConnectionPlan:
        return prepare_connection(
            request, installation, project, action=action, route="strict", launcher=(str(launcher),)
        )

    plan = prepare()
    return plan, apply_connection(
        plan,
        accepted_digest=plan.digest,
        refresh=prepare,
        authority=ArtifactAuthority("review_only", plan.digest, "test"),
        review=_Review(),
    )


def test_one_reviewed_connect_migrates_and_one_disconnect_removes(tmp_path: Path) -> None:
    launcher = tmp_path / "bin" / "finishup"
    launcher.parent.mkdir()
    launcher.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    launcher.chmod(0o700)
    project, config = _legacy_connection(tmp_path, launcher)
    installation = HostInstallation("cursor-ide", launcher, "3.17.8", config, "Cursor")

    plan, status = _connection(installation, project, launcher, "connect", 2)
    assert plan.body["changes"] == [
        "migrate_legacy_plugin",
        "install_plugin",
        "register_project_mcp",
    ]
    mcp_preview = cast(dict[str, Any], plan.body["mcp_preview"])
    assert mcp_preview["state_before"] == "yoetz_owned"
    assert mcp_preview["legacy_registration"] == "legacy_only"
    assert status["configured"] is True
    assert status["legacy_installation"] == "none"
    assert not (config / "plugins" / "local" / "yoetz").exists()
    servers = json.loads((project / ".cursor" / "mcp.json").read_bytes())["mcpServers"]
    assert set(servers) == {"finishup"}
    assert servers["finishup"]["command"] == str(launcher)

    # Put the legacy connection back alone, then disconnect it.
    _connection(installation, project, launcher, "disconnect", 3)
    shutil.rmtree(project)
    shutil.rmtree(config)
    project, config = _legacy_connection(tmp_path, launcher)
    plan, status = _connection(installation, project, launcher, "disconnect", 4)
    assert plan.body["changes"] == ["remove_legacy_plugin", "remove_project_mcp"]
    assert status["configured"] is False
    assert status["legacy_installation"] == "none"
    assert not (config / "plugins" / "local" / "yoetz").exists()
    assert json.loads((project / ".cursor" / "mcp.json").read_bytes())["mcpServers"] == {}


@pytest.mark.parametrize("host", ["cursor-ide", "cursor-cli"])
def test_reviewed_disconnect_preserves_foreign_current_mcp_entry(
    tmp_path: Path, host: SetupHost
) -> None:
    launcher = tmp_path / "bin" / "finishup"
    launcher.parent.mkdir()
    launcher.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    launcher.chmod(0o700)
    project, config = _legacy_connection(tmp_path, launcher)
    path = project / ".cursor" / "mcp.json"
    document = json.loads(path.read_bytes())
    foreign = {"command": "other-server", "args": ["private-value"]}
    document["mcpServers"]["finishup"] = foreign
    path.write_text(json.dumps(document), encoding="utf-8")
    installation = HostInstallation(host, launcher, "3.17.8", config, "Cursor")

    plan, status = _connection(installation, project, launcher, "disconnect", 5)
    assert plan.body["changes"] == ["remove_legacy_plugin", "remove_project_mcp"]
    mcp_preview = cast(dict[str, Any], plan.body["mcp_preview"])
    assert mcp_preview["action"] == "unregister"
    assert mcp_preview["legacy_registration"] == "legacy_only"
    assert "foreign_entry_present" in mcp_preview["warnings"]
    assert status["configured"] is False
    assert status["legacy_installation"] == "none"
    assert cast(dict[str, Any], status["project_mcp"])["state"] == "foreign_present"
    assert not (config / "plugins" / "local" / "yoetz").exists()
    assert json.loads(path.read_bytes())["mcpServers"] == {"finishup": foreign}
