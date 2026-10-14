"""One Claude Code config root serves several Yoetz-connected projects (issue #1058).

Observed on Claude Code 2.1.299 with a scratch ``CLAUDE_CONFIG_DIR``: ``claude plugin list
--json`` lists one ``yoetz@yoetz-local`` project-scope row per project that installed it, from
any working directory, and ``claude plugin marketplace remove`` (not project-scoped) uninstalls
every project's copy. Before #1058 a second project's install made both rows unprovable and
disconnecting the first project removed the shared marketplace source the second still used.
"""

from __future__ import annotations

import json
import shutil
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path
from typing import cast

from tests.unit.adapters.test_claude_code_integration import (
    _REQUEST,  # pyright: ignore[reportPrivateUsage]
    _authority,  # pyright: ignore[reportPrivateUsage]
    _Review,  # pyright: ignore[reportPrivateUsage]
    _target,  # pyright: ignore[reportPrivateUsage]
)

from yoetz.adapters.integrations.claude_code_integration import (
    ClaudeCodeCommandResult,
    ClaudeCodePluginAction,
    ClaudeCodePluginArtifact,
    ClaudeCodePluginTarget,
    apply_claude_code_plugin,
    claude_code_other_projects,
    preview_claude_code_plugin,
    render_claude_code_plugin,
    status_claude_code_plugin,
)
from yoetz.ports.plugin_artifacts import (
    McpOwnership,
    PluginArtifactState,
    PluginOperationState,
)
from yoetz.protocol.canonical import JsonValue, canonical_encode


class _SharedClaude:
    """Per-project install rows over one config root, as Claude Code 2.1.299 reports them."""

    def __init__(self, artifact: ClaudeCodePluginArtifact) -> None:
        self.artifact = artifact
        self.rows: dict[str, bool] = {}
        self.calls: list[tuple[str, tuple[str, ...]]] = []

    def _cache(self, target: ClaudeCodePluginTarget) -> Path:
        return Path(target.cache_root) / "yoetz-local" / "yoetz" / self.artifact.plan.version

    def _settings(self, target: ClaudeCodePluginTarget, *, registered: bool) -> None:
        path = Path(target.project_root) / ".claude" / "settings.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        value: dict[str, object] = {
            "enabledPlugins": {"yoetz@yoetz-local": self.rows.get(target.project_root, False)}
        }
        if registered:
            value["extraKnownMarketplaces"] = {
                "yoetz-local": {"source": {"source": "directory", "path": target.marketplace_root}}
            }
        path.write_text(json.dumps(value), encoding="utf-8")
        known = Path(target.claude_config_root) / "plugins" / "known_marketplaces.json"
        known.parent.mkdir(parents=True, exist_ok=True)
        known.write_text(
            json.dumps(
                {
                    "yoetz-local": {
                        "installLocation": target.marketplace_root,
                        "source": {"source": "directory", "path": target.marketplace_root},
                    }
                }
                if registered
                else {}
            ),
            encoding="utf-8",
        )

    def run(
        self, target: ClaudeCodePluginTarget, arguments: Sequence[str]
    ) -> ClaudeCodeCommandResult:
        args = tuple(arguments)
        self.calls.append((target.project_root, args))
        if args == ("plugin", "list", "--json"):
            rows = [
                {
                    "enabled": enabled,
                    "id": "yoetz@yoetz-local",
                    "installPath": str(self._cache(target)),
                    "projectPath": project,
                    "scope": "project",
                    "version": self.artifact.plan.version,
                }
                for project, enabled in sorted(self.rows.items())
            ]
            return ClaudeCodeCommandResult(0, canonical_encode(cast(JsonValue, rows)), b"")
        if args[:4] == ("plugin", "marketplace", "add", "--scope"):
            self._settings(target, registered=True)
            return ClaudeCodeCommandResult(0, b"ok", b"")
        if args[:2] == ("plugin", "install"):
            cache = self._cache(target)
            if not cache.exists():
                cache.parent.mkdir(parents=True, exist_ok=True)
                shutil.copytree(Path(target.marketplace_root) / "plugins" / "yoetz", cache)
            self.rows[target.project_root] = False
            self._settings(target, registered=True)
            return ClaudeCodeCommandResult(0, b"ok", b"")
        if args[:2] == ("plugin", "enable"):
            self.rows[target.project_root] = True
            self._settings(target, registered=True)
            return ClaudeCodeCommandResult(0, b"ok", b"")
        if args[:2] == ("plugin", "uninstall"):
            self.rows.pop(target.project_root, None)
            if not self.rows and self._cache(target).exists():
                shutil.rmtree(self._cache(target))
            self._settings(target, registered=True)
            return ClaudeCodeCommandResult(0, b"ok", b"")
        if args[:3] == ("plugin", "marketplace", "remove"):
            # Not project-scoped: every project's install goes with the marketplace.
            self.rows.clear()
            self._settings(target, registered=False)
            return ClaudeCodeCommandResult(0, b"ok", b"")
        return ClaudeCodeCommandResult(1, b"", b"unexpected")


def _pair(tmp_path: Path) -> tuple[ClaudeCodePluginTarget, ClaudeCodePluginTarget]:
    first = _target(tmp_path)
    second_root = tmp_path / "project-b"
    second_root.mkdir()
    return first, replace(first, project_root=str(second_root))


def _apply(
    target: ClaudeCodePluginTarget,
    action: ClaudeCodePluginAction,
    commands: _SharedClaude,
) -> PluginOperationState:
    preview = preview_claude_code_plugin(
        _REQUEST, target, action, commands.artifact, commands=commands
    )
    result = apply_claude_code_plugin(
        _REQUEST,
        target,
        action,
        commands.artifact,
        accepted_preview_digest=preview.preview_digest,
        authority=_authority(preview.preview_digest),
        review=_Review(),
        commands=commands,
    )
    return result.operation_state


def _state(target: ClaudeCodePluginTarget, commands: _SharedClaude) -> PluginArtifactState:
    return status_claude_code_plugin(target, commands.artifact, commands=commands).state


def test_second_project_connects_and_both_read_connected(tmp_path: Path) -> None:
    project_a, project_b = _pair(tmp_path)
    commands = _SharedClaude(
        render_claude_code_plugin(mcp_ownership=McpOwnership.PLUGIN_MANAGED, route_profile="strict")
    )
    assert _apply(project_a, ClaudeCodePluginAction.CONNECT, commands) is (
        PluginOperationState.COMPLETED
    )

    assert _apply(project_b, ClaudeCodePluginAction.CONNECT, commands) is (
        PluginOperationState.COMPLETED
    )

    assert _state(project_a, commands) is PluginArtifactState.NATIVE_MANAGED
    assert _state(project_b, commands) is PluginArtifactState.NATIVE_MANAGED
    assert claude_code_other_projects(project_a, commands=commands) == (project_b.project_root,)


def test_disconnecting_one_project_keeps_the_shared_marketplace_for_the_other(
    tmp_path: Path,
) -> None:
    project_a, project_b = _pair(tmp_path)
    commands = _SharedClaude(
        render_claude_code_plugin(mcp_ownership=McpOwnership.PLUGIN_MANAGED, route_profile="strict")
    )
    _apply(project_a, ClaudeCodePluginAction.CONNECT, commands)
    _apply(project_b, ClaudeCodePluginAction.CONNECT, commands)

    assert _apply(project_a, ClaudeCodePluginAction.REMOVE, commands) is (
        PluginOperationState.COMPLETED
    )

    assert not any(args[:3] == ("plugin", "marketplace", "remove") for _, args in commands.calls)
    assert Path(project_b.marketplace_root).is_dir()
    assert _state(project_b, commands) is PluginArtifactState.NATIVE_MANAGED
    assert claude_code_other_projects(project_b, commands=commands) == ()

    # The last project's disconnect removes the shared marketplace and its source.
    assert _apply(project_b, ClaudeCodePluginAction.REMOVE, commands) is (
        PluginOperationState.COMPLETED
    )
    assert any(args[:3] == ("plugin", "marketplace", "remove") for _, args in commands.calls)
    assert not Path(project_b.marketplace_root).exists()
    assert _state(project_b, commands) is PluginArtifactState.ABSENT


def _declaration(target: ClaudeCodePluginTarget) -> object:
    path = Path(target.project_root) / ".claude" / "settings.json"
    if not path.exists():
        return None
    return json.loads(path.read_text()).get("extraKnownMarketplaces", {}).get("yoetz-local")


class _RealisticClaude(_SharedClaude):
    """Uninstall keeps the project's declaration, as Claude Code 2.1.299 does."""

    def run(
        self, target: ClaudeCodePluginTarget, arguments: Sequence[str]
    ) -> ClaudeCodeCommandResult:
        args = tuple(arguments)
        if args[:2] == ("plugin", "uninstall"):
            self.calls.append((target.project_root, args))
            self.rows.pop(target.project_root, None)
            path = Path(target.project_root) / ".claude" / "settings.json"
            document = json.loads(path.read_text())
            document["enabledPlugins"] = {}
            path.write_text(json.dumps(document))
            return ClaudeCodeCommandResult(0, b"ok", b"")
        return super().run(target, arguments)


def test_first_detached_project_reconnects_after_the_last_disconnect_either_order(
    tmp_path: Path,
) -> None:
    """CHECK_MULTIPROJ_R1 P2-4: a scoped detach removes this project's own declaration."""

    for first_name in ("a", "b"):
        base = tmp_path / first_name
        base.mkdir()
        project_a, project_b = _pair(base)
        commands = _RealisticClaude(
            render_claude_code_plugin(
                mcp_ownership=McpOwnership.PLUGIN_MANAGED, route_profile="strict"
            )
        )
        _apply(project_a, ClaudeCodePluginAction.CONNECT, commands)
        _apply(project_b, ClaudeCodePluginAction.CONNECT, commands)
        first, last = (project_a, project_b) if first_name == "a" else (project_b, project_a)

        assert _apply(first, ClaudeCodePluginAction.REMOVE, commands) is (
            PluginOperationState.COMPLETED
        )
        assert _declaration(first) is None
        assert _state(last, commands) is PluginArtifactState.NATIVE_MANAGED
        assert _apply(last, ClaudeCodePluginAction.REMOVE, commands) is (
            PluginOperationState.COMPLETED
        )

        assert _apply(first, ClaudeCodePluginAction.CONNECT, commands) is (
            PluginOperationState.COMPLETED
        )
        assert _state(first, commands) is PluginArtifactState.NATIVE_MANAGED


def test_declaration_left_by_an_earlier_detach_is_repairable_but_an_edited_one_is_not(
    tmp_path: Path,
) -> None:
    from yoetz.adapters.integrations.claude_code_integration import ClaudeCodeIntegrationError

    project_a, project_b = _pair(tmp_path)
    commands = _RealisticClaude(
        render_claude_code_plugin(mcp_ownership=McpOwnership.PLUGIN_MANAGED, route_profile="strict")
    )
    _apply(project_a, ClaudeCodePluginAction.CONNECT, commands)
    _apply(project_b, ClaudeCodePluginAction.CONNECT, commands)
    settings = Path(project_a.project_root) / ".claude" / "settings.json"
    kept = settings.read_text()
    _apply(project_a, ClaudeCodePluginAction.REMOVE, commands)
    _apply(project_b, ClaudeCodePluginAction.REMOVE, commands)
    # The state an earlier release left: A still declares the now-absent shared source.
    document = json.loads(kept)
    document["enabledPlugins"] = {}
    settings.write_text(json.dumps(document))

    assert _apply(project_a, ClaudeCodePluginAction.CONNECT, commands) is (
        PluginOperationState.COMPLETED
    )
    _apply(project_a, ClaudeCodePluginAction.REMOVE, commands)

    # An edited declaration stays the owner's and still refuses.
    document["extraKnownMarketplaces"]["yoetz-local"]["note"] = "mine"
    settings.write_text(json.dumps(document))
    try:
        preview_claude_code_plugin(
            _REQUEST,
            project_a,
            ClaudeCodePluginAction.CONNECT,
            commands.artifact,
            commands=commands,
        )
    except ClaudeCodeIntegrationError as error:
        assert error.reason.value == "destination_conflict"
    else:
        raise AssertionError("edited declaration was not protected")


class _StrictUninstallClaude(_RealisticClaude):
    """`plugin uninstall --scope project` fails when this project has no install (2.1.300)."""

    def run(
        self, target: ClaudeCodePluginTarget, arguments: Sequence[str]
    ) -> ClaudeCodeCommandResult:
        args = tuple(arguments)
        if args[:2] == ("plugin", "uninstall") and target.project_root not in self.rows:
            self.calls.append((target.project_root, args))
            return ClaudeCodeCommandResult(1, b"", b"not installed")
        return super().run(target, arguments)


def test_a_deleted_projects_row_does_not_keep_the_shared_marketplace(tmp_path: Path) -> None:
    """#1058 review P2-1: apply counts other projects exactly as the preview did (live ones).

    Claude Code keeps a deleted project's row; it held the marketplace open after a preview
    that promised to remove it, and every later disconnect then failed.
    """

    project_a, project_b = _pair(tmp_path)
    commands = _StrictUninstallClaude(
        render_claude_code_plugin(mcp_ownership=McpOwnership.PLUGIN_MANAGED, route_profile="strict")
    )
    _apply(project_a, ClaudeCodePluginAction.CONNECT, commands)
    _apply(project_b, ClaudeCodePluginAction.CONNECT, commands)
    shutil.rmtree(project_a.project_root)
    assert project_a.project_root in commands.rows  # Claude still lists the deleted project

    assert _apply(project_b, ClaudeCodePluginAction.REMOVE, commands) is (
        PluginOperationState.COMPLETED
    )
    assert any(args[:3] == ("plugin", "marketplace", "remove") for _, args in commands.calls)
    assert not Path(project_b.marketplace_root).exists()
    assert commands.rows == {}
    assert _state(project_b, commands) is PluginArtifactState.ABSENT


def test_shared_pieces_left_behind_by_an_earlier_disconnect_can_still_be_removed(
    tmp_path: Path,
) -> None:
    """#1058 review P2-1: this project's install is gone but the shared marketplace stayed
    (kept for a project that was since deleted): the disconnect removes only what remains."""

    project_a, project_b = _pair(tmp_path)
    commands = _StrictUninstallClaude(
        render_claude_code_plugin(mcp_ownership=McpOwnership.PLUGIN_MANAGED, route_profile="strict")
    )
    _apply(project_a, ClaudeCodePluginAction.CONNECT, commands)
    _apply(project_b, ClaudeCodePluginAction.CONNECT, commands)
    shutil.rmtree(project_a.project_root)
    # The state an earlier build left: B's own row uninstalled, the shared source kept.
    commands.rows.pop(project_b.project_root)

    assert _apply(project_b, ClaudeCodePluginAction.REMOVE, commands) is (
        PluginOperationState.COMPLETED
    )
    assert not any(
        root == project_b.project_root and args[:2] == ("plugin", "uninstall")
        for root, args in commands.calls[-6:]
    )
    assert not Path(project_b.marketplace_root).exists()
    assert _state(project_b, commands) is PluginArtifactState.ABSENT


def test_installed_route_profile_reads_the_shared_source(tmp_path: Path) -> None:
    """#1058 review P2-3: the shared source's review mode, which every project's install uses."""

    from yoetz.adapters.integrations.claude_code_integration import installed_claude_route_profile

    project_a, _project_b = _pair(tmp_path)
    assert installed_claude_route_profile(project_a) is None
    commands = _SharedClaude(
        render_claude_code_plugin(mcp_ownership=McpOwnership.PLUGIN_MANAGED, route_profile="strict")
    )
    _apply(project_a, ClaudeCodePluginAction.CONNECT, commands)
    assert installed_claude_route_profile(project_a) == "strict"
