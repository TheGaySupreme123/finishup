"""Cursor project MCP registrations written before the rename (ADR-048).

A Yoetz-era project entry sits under the ``yoetz`` key, launches the ``yoetz`` console script, and
may carry only ``YOETZ_ISOLATED_ROOT``. Status reads an owned one as owned but outdated, install
migrates it in the same preview, remove takes both keys, and a legacy entry FinishUP cannot prove
is its own is reported and never touched.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from finishup.adapters.integrations.cursor_project_mcp import (
    CursorProjectMcpError,
    CursorProjectMcpTarget,
    apply_cursor_project_mcp,
    inspect_project_mcp_registration,
    preview_cursor_project_mcp,
    recorded_cursor_launchers,
    status_cursor_project_mcp,
)
from finishup.protocol.canonical import canonical_digest

LAUNCHER = ("/opt/finishup-test/bin/finishup",)
# The deprecated alias the same installation ships beside ``finishup``.
ALIAS = ("/opt/finishup-test/bin/yoetz",)
# A pre-rename installation's launcher, provable only through a marker that recorded it.
OLD_LAUNCHER = ("/opt/yoetz-old/bin/yoetz",)


def _secure_directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)
    return path


def _target(tmp_path: Path) -> CursorProjectMcpTarget:
    return CursorProjectMcpTarget(
        _secure_directory(tmp_path / "project"),
        _secure_directory(tmp_path / "cursor-config"),
    )


def _write_json(path: Path, document: object) -> None:
    _secure_directory(path.parent)
    path.write_text(json.dumps(document) + "\n", encoding="utf-8")
    path.chmod(0o600)


def _servers(target: CursorProjectMcpTarget) -> dict[str, Any]:
    path = target.project_root / ".cursor" / "mcp.json"
    return json.loads(path.read_text(encoding="utf-8"))["mcpServers"]


def _entry(
    launcher: tuple[str, ...] = LAUNCHER,
    *,
    project_root: Path | None = None,
    environment: dict[str, str] | None = None,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "type": "stdio",
        "command": launcher[0],
        "args": [
            *launcher[1:],
            "mcp",
            "serve",
            "--host",
            "cursor",
            "--project-root",
            "${workspaceFolder}" if project_root is None else str(project_root),
        ],
    }
    if environment is not None:
        entry["env"] = environment
    return entry


def _write_servers(target: CursorProjectMcpTarget, servers: dict[str, Any]) -> None:
    _write_json(target.project_root / ".cursor" / "mcp.json", {"mcpServers": servers})


def _status(target: CursorProjectMcpTarget, root: str | None = None) -> dict[str, Any]:
    return dict(status_cursor_project_mcp(target, launcher=LAUNCHER, isolation_root=root))


def _apply(
    target: CursorProjectMcpTarget,
    action: str,
    root: str | None = None,
    known: tuple[tuple[str, ...], ...] = (),
) -> tuple[dict[str, Any], dict[str, Any]]:
    preview = preview_cursor_project_mcp(
        target,
        action=action,
        launcher=LAUNCHER,
        route_profile=None,
        isolation_root=root,
        known_launchers=known,
    )
    applied = apply_cursor_project_mcp(
        target,
        action=action,
        launcher=LAUNCHER,
        route_profile=None,
        isolation_root=root,
        preview_digest=str(preview["preview_digest"]),
        accept=True,
        known_launchers=known,
    )
    return dict(preview), dict(applied)


def _write_plugin_marker(target: CursorProjectMcpTarget, directory: str, launcher: object) -> None:
    body: dict[str, Any] = {"schema": "yoetz.cursor-plugin-install/3", "yoetz_launcher": launcher}
    marker = {**body, "marker_digest": canonical_digest(body)}
    path = target.cursor_config_root / "plugins" / "local" / directory
    _write_json(path / ".yoetz-cursor-plugin-install.json", marker)


def test_legacy_only_entry_reads_owned_and_install_migrates_it(tmp_path: Path) -> None:
    target = _target(tmp_path)
    root = str(_secure_directory(tmp_path / "isolated"))
    legacy = _entry(environment={"YOETZ_ISOLATED_ROOT": root})
    _write_servers(target, {"yoetz": legacy, "other": {"command": "keep"}})

    status = _status(target, root)
    assert status["state"] == "yoetz_owned"
    assert status["source"] == "project"
    assert status["route_profile"] == "policy"
    assert status["legacy_registration"] == "legacy_only"

    preview, applied = _apply(target, "install", root)
    assert preview["action"] == "reregister"
    assert preview["state_before"] == "yoetz_owned"
    assert preview["legacy_registration"] == "legacy_only"
    assert "legacy_registration_owned" in preview["warnings"]
    assert applied["state_after"] == "yoetz_owned"
    servers = _servers(target)
    assert set(servers) == {"finishup", "other"}
    assert servers["finishup"] == _entry(
        project_root=target.project_root,
        environment={"FINISHUP_ISOLATED_ROOT": root, "YOETZ_ISOLATED_ROOT": root},
    )
    assert _status(target, root)["legacy_registration"] == "none"


def test_new_only_entry_has_no_legacy_state(tmp_path: Path) -> None:
    target = _target(tmp_path)
    _write_servers(target, {"finishup": _entry(project_root=target.project_root)})

    status = _status(target)
    assert (status["state"], status["legacy_registration"]) == ("yoetz_owned", "none")
    preview, _applied = _apply(target, "install")
    assert preview["action"] == "noop"
    assert "legacy_registration_owned" not in preview["warnings"]


def test_duplicate_entries_migrate_on_install_and_remove_takes_both(tmp_path: Path) -> None:
    target = _target(tmp_path)
    current = _entry(project_root=target.project_root)
    _write_servers(target, {"finishup": current, "yoetz": _entry(ALIAS)})

    assert _status(target)["legacy_registration"] == "duplicate"
    preview, _applied = _apply(target, "install")
    # The current entry is already exact; dropping the legacy key is still a change.
    assert preview["action"] == "reregister"
    assert _servers(target) == {"finishup": current}

    _write_servers(target, {"finishup": current, "yoetz": _entry(ALIAS)})
    preview, applied = _apply(target, "remove")
    assert preview["action"] == "unregister"
    assert applied["state_after"] == "absent"
    assert _servers(target) == {}


def test_remove_takes_a_legacy_only_entry(tmp_path: Path) -> None:
    target = _target(tmp_path)
    _write_servers(target, {"yoetz": _entry(ALIAS)})

    preview, applied = _apply(target, "remove")
    assert (preview["action"], applied["state_after"]) == ("unregister", "absent")
    assert _servers(target) == {}


def test_remove_owned_legacy_entry_preserves_foreign_current_entry(tmp_path: Path) -> None:
    target = _target(tmp_path)
    foreign = {"type": "stdio", "command": "/usr/bin/other-tool", "args": ["private-value"]}
    other = {"command": "keep"}
    _write_servers(target, {"finishup": foreign, "yoetz": _entry(ALIAS), "other": other})
    assert _status(target)["state"] == "foreign_present"

    # Install would overwrite the foreign current key, so it still refuses.
    with pytest.raises(CursorProjectMcpError) as caught:
        _apply(target, "install")
    assert caught.value.reason == "cursor_project_mcp_foreign_present"

    preview, applied = _apply(target, "remove")
    assert preview["action"] == "unregister"
    assert preview["legacy_registration"] == "legacy_only"
    assert "foreign_entry_present" in preview["warnings"]
    assert applied["state_after"] == "foreign_present"
    assert _servers(target) == {"finishup": foreign, "other": other}
    assert _status(target)["legacy_registration"] == "none"


def test_remove_owned_legacy_entry_beside_foreign_current_refuses_stale_preview(
    tmp_path: Path,
) -> None:
    target = _target(tmp_path)
    foreign = {"command": "other-tool"}
    _write_servers(target, {"finishup": foreign, "yoetz": _entry(ALIAS)})
    preview = preview_cursor_project_mcp(
        target,
        action="remove",
        launcher=LAUNCHER,
        route_profile=None,
        isolation_root=None,
    )
    changed = _entry(ALIAS, project_root=target.project_root)
    _write_servers(target, {"finishup": foreign, "yoetz": changed})
    with pytest.raises(CursorProjectMcpError) as caught:
        apply_cursor_project_mcp(
            target,
            action="remove",
            launcher=LAUNCHER,
            route_profile=None,
            isolation_root=None,
            preview_digest=str(preview["preview_digest"]),
            accept=True,
        )
    assert caught.value.reason == "cursor_project_mcp_preview_stale"
    assert _servers(target) == {"finishup": foreign, "yoetz": changed}


def test_foreign_legacy_entry_is_reported_and_never_touched(tmp_path: Path) -> None:
    target = _target(tmp_path)
    foreign = {"type": "stdio", "command": "/usr/bin/other-tool", "args": ["serve"]}
    _write_servers(target, {"yoetz": foreign})

    status = _status(target)
    assert (status["state"], status["legacy_registration"]) == ("absent", "foreign")
    preview, applied = _apply(target, "install")
    assert preview["action"] == "register"
    assert "legacy_registration_foreign" in preview["warnings"]
    assert applied["state_after"] == "yoetz_owned"
    servers = _servers(target)
    assert servers["yoetz"] == foreign
    assert set(servers) == {"finishup", "yoetz"}

    preview, _applied = _apply(target, "remove")
    assert _servers(target) == {"yoetz": foreign}


@pytest.mark.parametrize(
    ("environment", "owned"),
    [
        ({"FINISHUP_ISOLATED_ROOT": "ROOT"}, True),
        ({"YOETZ_ISOLATED_ROOT": "ROOT"}, True),
        ({"FINISHUP_ISOLATED_ROOT": "ROOT", "YOETZ_ISOLATED_ROOT": "ROOT"}, True),
        ({"FINISHUP_ISOLATED_ROOT": "ROOT", "YOETZ_ISOLATED_ROOT": "OTHER"}, False),
        ({"FINISHUP_ISOLATED_ROOT": "ROOT", "PATH": "/bin"}, False),
    ],
)
def test_isolation_root_spellings(tmp_path: Path, environment: dict[str, str], owned: bool) -> None:
    target = _target(tmp_path)
    root = str(_secure_directory(tmp_path / "isolated"))
    other = str(_secure_directory(tmp_path / "other"))
    resolved = {
        name: root if value == "ROOT" else other if value == "OTHER" else value
        for name, value in environment.items()
    }
    _write_servers(target, {"finishup": _entry(environment=resolved)})

    assert _status(target, root)["state"] == ("yoetz_owned" if owned else "foreign_present")


def test_deprecated_alias_of_this_installation_is_owned(tmp_path: Path) -> None:
    target = _target(tmp_path)
    _write_servers(target, {"yoetz": _entry(ALIAS)})

    assert _status(target)["legacy_registration"] == "legacy_only"


def test_old_installation_launcher_needs_a_recording_marker(tmp_path: Path) -> None:
    target = _target(tmp_path)
    _write_servers(target, {"yoetz": _entry(OLD_LAUNCHER)})
    assert _status(target)["legacy_registration"] == "foreign"

    # A self-consistent legacy plugin marker that recorded that launcher proves ownership.
    _write_plugin_marker(target, "yoetz", list(OLD_LAUNCHER))
    assert recorded_cursor_launchers(target.cursor_config_root) == (OLD_LAUNCHER,)
    assert _status(target)["legacy_registration"] == "legacy_only"


def test_marker_proof_needs_a_consistent_marker_naming_a_finishup_launcher(
    tmp_path: Path,
) -> None:
    target = _target(tmp_path)
    _write_plugin_marker(target, "yoetz", ["/opt/elsewhere/bin/some-tool"])
    assert recorded_cursor_launchers(target.cursor_config_root) == ()

    path = target.cursor_config_root / "plugins" / "local" / "finishup"
    body = {"schema": "yoetz.cursor-plugin-install/3", "yoetz_launcher": list(OLD_LAUNCHER)}
    _write_json(
        path / ".yoetz-cursor-plugin-install.json", {**body, "marker_digest": "sha256:" + "0" * 64}
    )
    assert recorded_cursor_launchers(target.cursor_config_root) == ()


def test_captured_launchers_keep_the_plan_stable_after_the_marker_is_migrated(
    tmp_path: Path,
) -> None:
    target = _target(tmp_path)
    _write_servers(target, {"yoetz": _entry(OLD_LAUNCHER)})
    _write_plugin_marker(target, "yoetz", list(OLD_LAUNCHER))
    known = recorded_cursor_launchers(target.cursor_config_root)
    preview = preview_cursor_project_mcp(
        target,
        action="install",
        launcher=LAUNCHER,
        route_profile=None,
        isolation_root=None,
        known_launchers=known,
    )

    # A guided connection's plugin step migrates the legacy tree, marker included.
    marker = target.cursor_config_root / "plugins" / "local" / "yoetz"
    for child in marker.iterdir():
        child.unlink()
    marker.rmdir()

    applied = apply_cursor_project_mcp(
        target,
        action="install",
        launcher=LAUNCHER,
        route_profile=None,
        isolation_root=None,
        preview_digest=str(preview["preview_digest"]),
        accept=True,
        known_launchers=known,
    )
    assert applied["state_after"] == "yoetz_owned"
    assert set(_servers(target)) == {"finishup"}


def test_live_bridge_accepts_the_legacy_key_and_spelling_that_launched_it(
    tmp_path: Path,
) -> None:
    target = _target(tmp_path)
    root = str(_secure_directory(tmp_path / "isolated"))
    _write_servers(target, {"yoetz": _entry(ALIAS, environment={"YOETZ_ISOLATED_ROOT": root})})

    inspect_project_mcp_registration(
        target.project_root, launcher=LAUNCHER, route_profile="policy", isolation_root=root
    )
    with pytest.raises(CursorProjectMcpError, match="foreign_present"):
        inspect_project_mcp_registration(
            target.project_root, launcher=LAUNCHER, route_profile="strict", isolation_root=root
        )


def _plugin_route(launcher: tuple[str, ...]) -> dict[str, Any]:
    """The plugin-managed route shape a Yoetz-era native Cursor plugin rendered."""

    return {
        "type": "stdio",
        "command": launcher[0],
        "args": [*launcher[1:], "mcp", "serve", "--host", "cursor"],
    }


def test_unmigrated_legacy_plugin_server_is_an_external_source(tmp_path: Path) -> None:
    # A 0.2 plugin-managed install still serves FinishUP from ``plugins/local/yoetz``. Adding a
    # project entry beside it would run two FinishUP servers, so install refuses as before.
    target = _target(tmp_path)
    plugin = target.cursor_config_root / "plugins" / "local" / "yoetz"
    _write_json(plugin / "mcp.json", {"mcpServers": {"yoetz": _plugin_route(OLD_LAUNCHER)}})
    _write_plugin_marker(target, "yoetz", list(OLD_LAUNCHER))

    status = _status(target)
    assert (status["state"], status["source"]) == ("external_source", "plugin")
    assert status["legacy_registration"] == "legacy_only"
    with pytest.raises(CursorProjectMcpError, match="external_source"):
        preview_cursor_project_mcp(
            target, action="install", launcher=LAUNCHER, route_profile=None, isolation_root=None
        )
    assert not (target.project_root / ".cursor" / "mcp.json").exists()


def test_legacy_plugin_server_beside_a_project_entry_is_multiple_sources(tmp_path: Path) -> None:
    target = _target(tmp_path)
    current = _entry(project_root=target.project_root)
    _write_servers(target, {"finishup": current})
    plugin = target.cursor_config_root / "plugins" / "local" / "yoetz"
    _write_json(plugin / "mcp.json", {"mcpServers": {"yoetz": _plugin_route(("yoetz",))}})

    status = _status(target)
    assert (status["state"], status["legacy_registration"]) == ("multiple_sources", "duplicate")
    with pytest.raises(CursorProjectMcpError, match="multiple_sources"):
        _apply(target, "remove")
    assert _servers(target) == {"finishup": current}


def test_owned_user_level_legacy_entry_is_an_external_source(tmp_path: Path) -> None:
    target = _target(tmp_path)
    _write_json(
        target.cursor_config_root / "mcp.json", {"mcpServers": {"yoetz": _entry(("yoetz",))}}
    )

    status = _status(target)
    assert (status["state"], status["source"]) == ("external_source", "user")
    assert status["legacy_registration"] == "legacy_only"
    with pytest.raises(CursorProjectMcpError, match="external_source"):
        _apply(target, "install")
    assert not (target.project_root / ".cursor" / "mcp.json").exists()


def test_foreign_user_level_legacy_entry_is_reported_and_not_a_conflict(tmp_path: Path) -> None:
    target = _target(tmp_path)
    foreign = {"mcpServers": {"yoetz": {"type": "stdio", "command": "/usr/bin/other-tool"}}}
    _write_json(target.cursor_config_root / "mcp.json", foreign)

    status = _status(target)
    assert (status["state"], status["legacy_registration"]) == ("absent", "foreign")
    preview, applied = _apply(target, "install")
    assert "legacy_registration_foreign" in preview["warnings"]
    assert applied["state_after"] == "yoetz_owned"
    user = json.loads((target.cursor_config_root / "mcp.json").read_text(encoding="utf-8"))
    assert user == foreign


def test_owned_project_and_user_legacy_entries_are_multiple_sources(tmp_path: Path) -> None:
    # The layout Yoetz 0.2 could leave: an owned ``yoetz`` entry in the project file and another
    # in ``~/.cursor/mcp.json``. The project file is a source too, exactly as before the rename.
    target = _target(tmp_path)
    project_entry = _entry(ALIAS)
    _write_servers(target, {"yoetz": project_entry})
    _write_json(
        target.cursor_config_root / "mcp.json", {"mcpServers": {"yoetz": _entry(("yoetz",))}}
    )

    status = _status(target)
    assert (status["state"], status["source"]) == ("multiple_sources", "none")
    assert status["legacy_registration"] == "legacy_only"
    for action in ("install", "remove"):
        with pytest.raises(CursorProjectMcpError, match="multiple_sources"):
            _apply(target, action)
    assert _servers(target) == {"yoetz": project_entry}


def test_foreign_project_legacy_entry_is_not_a_project_source(tmp_path: Path) -> None:
    target = _target(tmp_path)
    foreign = {"type": "stdio", "command": "/usr/bin/other-tool"}
    _write_servers(target, {"yoetz": foreign})
    _write_json(
        target.cursor_config_root / "mcp.json", {"mcpServers": {"finishup": _entry(LAUNCHER)}}
    )

    status = _status(target)
    assert (status["state"], status["source"]) == ("external_source", "user")
    assert status["legacy_registration"] == "foreign"
