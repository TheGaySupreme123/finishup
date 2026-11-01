"""Guided Cursor connection over a pre-rename install (ADR-048), against isolated real state.

A Yoetz-era connection left a marker-valid ``plugins/local/yoetz`` tree and a project entry
under the ``yoetz`` key that launches the old installation's launcher; only the legacy marker
proves that launcher is FinishUP's. One reviewed connect migrates both, and neither step ever
needs the old launcher to exist. Yoetz 0.2 connected several projects to one Cursor config root
and kept no record of them, so the Yoetz-era user tree is a shared piece found without a record:
membership is unknown (ADR-012), an ordinary disconnect keeps the tree, and only
``--remove-shared`` removes it.
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
from finishup.adapters.integrations.host_projects import load_connected_projects
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


def _legacy_connection(
    tmp_path: Path, launcher: Path, *, name: str = "project"
) -> tuple[Path, Path]:
    """Lay out what a 0.2 guided connection left: legacy tree, legacy-key project entry."""

    project = tmp_path / name
    config = tmp_path / "cursor"
    project.mkdir(mode=0o700)
    config.mkdir(mode=0o700)
    _legacy_tree(config, launcher)
    _legacy_project_entry(project)
    return project, config


def _legacy_tree(config: Path, launcher: Path) -> None:
    """The marker-valid ``plugins/local/yoetz`` tree a 0.2 connection left in ``config``."""

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


def _legacy_project_entry(project: Path) -> None:
    """The project MCP entry a 0.2 connection wrote under the ``yoetz`` key."""

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


def _connection(
    installation: HostInstallation,
    project: Path,
    launcher: Path,
    action: ConnectionAction,
    number: int,
    *,
    remove_shared: bool = False,
) -> tuple[ConnectionPlan, dict[str, JsonValue]]:
    request = request_id(f"req_50000000-0000-4000-8000-{number:012d}")

    def prepare() -> ConnectionPlan:
        return prepare_connection(
            request,
            installation,
            project,
            action=action,
            route="strict",
            launcher=(str(launcher),),
            remove_shared=remove_shared,
        )

    plan = prepare()
    return plan, apply_connection(
        plan,
        accepted_digest=plan.digest,
        refresh=prepare,
        authority=ArtifactAuthority("review_only", plan.digest, "test"),
        review=_Review(),
    )


def _launcher(tmp_path: Path) -> Path:
    launcher = tmp_path / "bin" / "finishup"
    launcher.parent.mkdir()
    launcher.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    launcher.chmod(0o700)
    return launcher


def _servers(project: Path) -> dict[str, Any]:
    return json.loads((project / ".cursor" / "mcp.json").read_bytes())["mcpServers"]


def test_one_reviewed_connect_migrates_and_remove_shared_removes(tmp_path: Path) -> None:
    launcher = _launcher(tmp_path)
    project, config = _legacy_connection(tmp_path, launcher)
    installation = HostInstallation("cursor-ide", launcher, "3.17.8", config, "Cursor")

    plan, status = _connection(installation, project, launcher, "connect", 2)
    # The connect also records the project for the shared user plugin (#1058).
    assert plan.body["changes"] == [
        "migrate_legacy_plugin",
        "install_plugin",
        "register_project_mcp",
        "record_connected_project",
    ]
    # A Yoetz-era tree found without a record may serve projects no record names (ADR-012).
    assert plan.disclosure["membership_unknown"] is True
    mcp_preview = cast(dict[str, Any], plan.body["mcp_preview"])
    assert mcp_preview["state_before"] == "yoetz_owned"
    assert mcp_preview["legacy_registration"] == "legacy_only"
    assert status["configured"] is True
    assert status["legacy_installation"] == "none"
    assert status["membership_unknown"] is True
    record = load_connected_projects(config)
    assert record.projects == (str(project),) and record.unknown_members
    assert not (config / "plugins" / "local" / "yoetz").exists()
    servers = _servers(project)
    assert set(servers) == {"finishup"}
    assert servers["finishup"]["command"] == str(launcher)

    # Put the legacy connection back alone, with no record: an ordinary disconnect removes only
    # the project's entry and keeps the Yoetz-era tree, since other projects may still load it.
    shutil.rmtree(project)
    shutil.rmtree(config)
    project, config = _legacy_connection(tmp_path, launcher)
    plan, status = _connection(installation, project, launcher, "disconnect", 4)
    assert plan.body["changes"] == ["remove_project_mcp"]
    assert plan.body["plugin_preview_digest"] is None
    assert plan.disclosure["membership_unknown"] is True
    assert status["configured"] is False
    assert status["legacy_installation"] == "legacy_only"
    assert status["membership_unknown"] is True
    assert (config / "plugins" / "local" / "yoetz").is_dir()
    assert _servers(project) == {}

    # That disconnect kept the uncertainty in a record that names no project yet.
    record = load_connected_projects(config)
    assert record.projects == () and record.unknown_members
    # The explicit home-wide disconnect removes the tree and that record.
    plan, status = _connection(installation, project, launcher, "disconnect", 5, remove_shared=True)
    assert plan.body["changes"] == ["remove_legacy_plugin", "forget_connected_project"]
    assert plan.disclosure["remove_shared"] is True
    assert status["legacy_installation"] == "none"
    assert "membership_unknown" not in status
    assert not (config / "plugins" / "local" / "yoetz").exists()
    assert load_connected_projects(config).raw is None


def test_disconnecting_one_of_two_yoetz_era_projects_keeps_the_shared_tree(
    tmp_path: Path,
) -> None:
    """ADR-048 x #1058: Yoetz 0.2 connected A and B to one Cursor config root; the first
    disconnect after the upgrade must not take the user plugin B still loads."""

    launcher = _launcher(tmp_path)
    a, config = _legacy_connection(tmp_path, launcher, name="a")
    b = tmp_path / "b"
    b.mkdir(mode=0o700)
    _legacy_project_entry(b)
    b_entry = (b / ".cursor" / "mcp.json").read_bytes()
    installation = HostInstallation("cursor-ide", launcher, "3.17.8", config, "Cursor")

    plan, status = _connection(installation, a, launcher, "disconnect", 6)

    assert plan.body["changes"] == ["remove_project_mcp"]
    assert plan.disclosure["membership_unknown"] is True
    assert status["membership_unknown"] is True
    assert (config / "plugins" / "local" / "yoetz").is_dir()
    assert _servers(a) == {}
    assert (b / ".cursor" / "mcp.json").read_bytes() == b_entry


def test_a_migrating_connect_keeps_unknown_membership_for_other_yoetz_era_projects(
    tmp_path: Path,
) -> None:
    """A's connect migrates the shared Yoetz-era tree; B, connected by Yoetz 0.2, is in no
    record, so the record says membership is unknown, that survives a later connect, and A's
    later disconnect keeps the FinishUP plugin B now loads."""

    launcher = _launcher(tmp_path)
    a, config = _legacy_connection(tmp_path, launcher, name="a")
    b = tmp_path / "b"
    b.mkdir(mode=0o700)
    _legacy_project_entry(b)
    installation = HostInstallation("cursor-ide", launcher, "3.17.8", config, "Cursor")

    plan, _status = _connection(installation, a, launcher, "connect", 7)
    assert plan.disclosure["membership_unknown"] is True
    assert load_connected_projects(config).unknown_members
    # A later connect (here a repeat) keeps the uncertainty.
    _connection(installation, a, launcher, "connect", 8)
    assert load_connected_projects(config).unknown_members

    plan, status = _connection(installation, a, launcher, "disconnect", 9)

    assert plan.body["changes"] == ["remove_project_mcp", "forget_connected_project"]
    assert plan.disclosure["membership_unknown"] is True
    assert status["membership_unknown"] is True
    assert (config / "plugins" / "local" / "finishup").is_dir()
    assert "yoetz" in _servers(b)


def test_a_duplicate_yoetz_era_tree_stays_with_the_shared_plugin_until_the_last_disconnect(
    tmp_path: Path,
) -> None:
    """Both trees (``duplicate``) are shared pieces: kept while another recorded project
    remains, removed together by the last disconnect."""

    launcher = _launcher(tmp_path)
    config = tmp_path / "cursor"
    config.mkdir(mode=0o700)
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir(mode=0o700)
    b.mkdir(mode=0o700)
    installation = HostInstallation("cursor-ide", launcher, "3.17.8", config, "Cursor")
    _connection(installation, a, launcher, "connect", 10)
    _connection(installation, b, launcher, "connect", 11)
    scratch = tmp_path / "scratch"
    scratch.mkdir(mode=0o700)
    _legacy_tree(scratch, launcher)
    local = config / "plugins" / "local"
    shutil.copytree(scratch / "plugins" / "local" / "yoetz", local / "yoetz")

    plan, status = _connection(installation, a, launcher, "disconnect", 12)
    assert plan.body["changes"] == ["remove_project_mcp", "forget_connected_project"]
    assert plan.disclosure["shared_with"] == [str(b)]
    assert status["legacy_installation"] == "duplicate"
    assert (local / "finishup").is_dir() and (local / "yoetz").is_dir()

    plan, status = _connection(installation, b, launcher, "disconnect", 13)
    assert plan.body["changes"] == [
        "remove_legacy_plugin",
        "remove_plugin",
        "remove_project_mcp",
        "forget_connected_project",
    ]
    assert status["legacy_installation"] == "none"
    assert not (local / "finishup").exists() and not (local / "yoetz").exists()


@pytest.mark.parametrize("host", ["cursor-ide", "cursor-cli"])
def test_reviewed_disconnect_preserves_foreign_current_mcp_entry(
    tmp_path: Path, host: SetupHost
) -> None:
    launcher = _launcher(tmp_path)
    project, config = _legacy_connection(tmp_path, launcher)
    path = project / ".cursor" / "mcp.json"
    document = json.loads(path.read_bytes())
    foreign = {"command": "other-server", "args": ["private-value"]}
    document["mcpServers"]["finishup"] = foreign
    path.write_text(json.dumps(document), encoding="utf-8")
    installation = HostInstallation(host, launcher, "3.17.8", config, "Cursor")

    # Home-wide, so the Yoetz-era tree (found without a record) goes in the same plan.
    plan, status = _connection(installation, project, launcher, "disconnect", 5, remove_shared=True)
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
