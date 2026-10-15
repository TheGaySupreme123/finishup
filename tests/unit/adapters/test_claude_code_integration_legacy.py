"""Claude Code state written before the rename (ADR-048).

A Yoetz-era project install registered the private ``yoetz-local`` marketplace and the
``yoetz@yoetz-local`` plugin, wrote a marker-valid tree, and owner-written MCP entries may still
sit under the ``yoetz`` key. Status reports each; connect, install, and update migrate an owned
legacy marketplace in the same approval; remove takes it too; anything FinishUP cannot prove is
its own is reported and never touched.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from collections.abc import Sequence
from pathlib import Path
from typing import cast

import pytest

from finishup.adapters.integrations.claude_code_integration import (
    ClaudeCodeCapabilityIdentity,
    ClaudeCodeCommandResult,
    ClaudeCodeMcpSource,
    ClaudeCodePluginAction,
    ClaudeCodePluginArtifact,
    ClaudeCodePluginTarget,
    apply_claude_code_plugin,
    installed_claude_startup_mode,
    observe_claude_code_activation_cues,
    observe_claude_code_mcp,
    preview_claude_code_plugin,
    render_claude_code_plugin,
    status_claude_code_plugin,
)
from finishup.domain.values import RequestId, request_id
from finishup.ports.plugin_artifacts import (
    ArtifactAuthority,
    McpOwnershipState,
    PluginArtifactState,
    PluginOperationState,
)
from finishup.protocol.canonical import JsonValue, canonical_digest, canonical_encode

_NEW = ("finishup-local", "finishup@finishup-local", "finishup")
_OLD = ("yoetz-local", "yoetz@yoetz-local", "yoetz")
# A pre-rename installation's launcher; only the legacy marker that recorded it proves it.
_OLD_LAUNCHER = ("/opt/yoetz-old/bin/yoetz",)


def _request(number: int) -> RequestId:
    return request_id(f"req_30000000-0000-4000-8000-{number:012d}")


class _Review:
    def consume_setup_authority(self, authority: ArtifactAuthority, preview_digest: str) -> None:
        assert authority.target_digest == preview_digest

    def consume_artifact_review(self, authority: ArtifactAuthority, preview_digest: str) -> None:
        assert authority.target_digest == preview_digest


def _launcher(tmp_path: Path) -> Path:
    exe = tmp_path / "bin" / "finishup"
    exe.parent.mkdir(exist_ok=True)
    exe.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    exe.chmod(0o700)
    return exe


def _target(tmp_path: Path, marketplace: Path | None = None) -> ClaudeCodePluginTarget:
    project = tmp_path / "project"
    config = tmp_path / "config"
    executable = tmp_path / "claude"
    project.mkdir(exist_ok=True)
    config.mkdir(exist_ok=True)
    executable.write_bytes(b"claude-test-executable")
    executable.chmod(0o700)
    root = config / "plugins" / "marketplaces" / _NEW[0] if marketplace is None else marketplace
    return ClaudeCodePluginTarget(
        str(project),
        str(config),
        str(config / "plugins" / "cache"),
        str(root),
        str(executable),
        ClaudeCodeCapabilityIdentity(
            "2.1.241",
            f"sha256:{hashlib.sha256(executable.read_bytes()).hexdigest()}",
            "darwin",
            "arm64",
        ),
    )


def _legacy_root(target: ClaudeCodePluginTarget) -> Path:
    return Path(target.claude_config_root) / "plugins" / "marketplaces" / _OLD[0]


def _write_legacy_tree(
    tmp_path: Path, root: Path, *, launcher: tuple[str, ...], startup: str = "optional"
) -> None:
    """Write a marker-valid ``yoetz-local`` tree laid out as a 0.2 install did.

    The members come from a 0.2.5 render; the marker records ``launcher``, which need not exist.
    """

    artifact = render_claude_code_plugin(
        version="0.2.5",
        finishup_launcher=_launcher(tmp_path),
        startup_mode="required" if startup == "required" else "optional",
    )
    files: dict[str, bytes] = {
        ".claude-plugin/marketplace.json": canonical_encode(
            cast(
                JsonValue,
                {
                    "name": _OLD[0],
                    "plugins": [{"name": _OLD[2], "source": "./plugins/yoetz", "strict": True}],
                },
            )
        )
    }
    files.update({f"plugins/yoetz/{path}": data for path, data in artifact.members.items()})
    body: dict[str, JsonValue] = {
        "artifact_digest": artifact.artifact_digest,
        "managed_files": [
            {
                "relative_path": path,
                "sha256": f"sha256:{hashlib.sha256(data).hexdigest()}",
                "size": len(data),
            }
            for path, data in sorted(files.items())
        ],
        "marketplace_name": _OLD[0],
        "schema": "yoetz.claude-code-marketplace-install/2",
        "yoetz_launcher": list(launcher),
        "yoetz_version": "0.2.5",
    }
    files[".yoetz-claude-marketplace-install.json"] = canonical_encode(
        {**body, "marker_digest": canonical_digest(body)}
    )
    for path, data in files.items():
        destination = root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)


def _load(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def _store(path: Path, document: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


class _Claude:
    """Claude's plugin CLI over both the renamed and the legacy plugin ids.

    Settings live in the files, as Claude keeps them: ``--scope project`` writes this project's
    ``.claude/settings.json``, and ``known_marketplaces.json`` is shared by every project of the
    config root. An unscoped ``plugin marketplace remove`` does what Claude's does: it drops the
    user-level registration and this project's declaration, deletes the marketplace directory
    under ``plugins/marketplaces``, and uninstalls the marketplace's plugins (``_Projects``
    extends that to every project).
    """

    def __init__(self, artifact: ClaudeCodePluginArtifact, target: ClaudeCodePluginTarget) -> None:
        self.artifact = artifact
        self.calls: list[tuple[str, ...]] = []
        self.installed = {_NEW[1]: False, _OLD[1]: False}
        self.enabled = {_NEW[1]: False, _OLD[1]: False}
        self.target = target

    @property
    def settings(self) -> Path:
        return Path(self.target.project_root) / ".claude" / "settings.json"

    @property
    def known(self) -> Path:
        return Path(self.target.claude_config_root) / "plugins" / "known_marketplaces.json"

    @property
    def registered(self) -> dict[str, str]:
        sources = cast(
            dict[str, dict[str, dict[str, str]]],
            _load(self.settings).get("extraKnownMarketplaces", {}),
        )
        return {name: entry["source"]["path"] for name, entry in sources.items()}

    def register(self, name: str, root: Path) -> None:
        source = {"source": "directory", "path": str(root)}
        settings = _load(self.settings)
        sources = cast(dict[str, object], settings.setdefault("extraKnownMarketplaces", {}))
        sources[name] = {"source": source}
        _store(self.settings, settings)
        known = _load(self.known)
        known[name] = {"source": source, "installLocation": str(root)}
        _store(self.known, known)

    def unregister(self, name: str) -> None:
        """Claude's unscoped ``plugin marketplace remove`` for this project."""

        settings = _load(self.settings)
        for container in ("extraKnownMarketplaces", "enabledPlugins"):
            entries = cast(dict[str, object], settings.get(container, {}))
            for key in [key for key in entries if key == name or key.endswith(f"@{name}")]:
                del entries[key]
        _store(self.settings, settings)
        known = _load(self.known)
        known.pop(name, None)
        _store(self.known, known)
        shutil.rmtree(
            Path(self.target.claude_config_root) / "plugins" / "marketplaces" / name,
            ignore_errors=True,
        )
        self.drop_installs(name)

    def drop_installs(self, marketplace: str) -> None:
        for plugin_id in self.installed:
            if plugin_id.endswith(f"@{marketplace}"):
                self.installed[plugin_id] = False
                self.enabled[plugin_id] = False

    def set_enabled(self, plugin_id: str, value: bool | None) -> None:
        if value is not None:
            self.enabled[plugin_id] = value
        settings = _load(self.settings)
        entries = cast(dict[str, object], settings.setdefault("enabledPlugins", {}))
        if value is None:
            entries.pop(plugin_id, None)
        else:
            entries[plugin_id] = value
        _store(self.settings, settings)

    def _cache(self, plugin_id: str) -> Path:
        name, marketplace = plugin_id.split("@")
        return Path(self.target.cache_root) / marketplace / name / self.artifact.plan.version

    def run(
        self, target: ClaudeCodePluginTarget, arguments: Sequence[str]
    ) -> ClaudeCodeCommandResult:
        args = tuple(arguments)
        self.calls.append(args)
        ok = ClaudeCodeCommandResult(0, b"ok", b"")
        if args == ("plugin", "list", "--json"):
            rows = [
                {
                    "enabled": self.enabled[plugin_id],
                    "id": plugin_id,
                    "installPath": str(self._cache(plugin_id)),
                    "projectPath": target.project_root,
                    "scope": "project",
                    "version": self.artifact.plan.version,
                }
                for plugin_id, installed in self.installed.items()
                if installed
            ]
            return ClaudeCodeCommandResult(0, canonical_encode(cast(JsonValue, rows)), b"")
        if args[:4] == ("plugin", "marketplace", "add", "--scope"):
            self.register(_NEW[0], Path(args[5]))
            return ok
        if args[:3] == ("plugin", "marketplace", "remove") and len(args) == 4:
            self.unregister(args[3])
            return ok
        if args[:3] == ("plugin", "marketplace", "update"):
            return ok
        if args[:2] in {("plugin", "install"), ("plugin", "update")} and args[2] == _NEW[1]:
            cache = self._cache(_NEW[1])
            if cache.exists():
                shutil.rmtree(cache)
            cache.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(Path(target.marketplace_root) / "plugins" / "finishup", cache)
            self.installed[_NEW[1]] = True
            return ok
        if args[:2] == ("plugin", "enable"):
            self.set_enabled(args[2], True)
            return ok
        if args[:2] == ("plugin", "uninstall") and args[3:5] == ("--scope", "project"):
            # A project-scoped uninstall touches this project's install and enablement only.
            self.installed[args[2]] = False
            self.enabled[args[2]] = False
            self.set_enabled(args[2], None)
            return ok
        return ClaudeCodeCommandResult(1, b"", b"unexpected")


def _legacy_install(
    tmp_path: Path, *, marketplace: Path | None = None
) -> tuple[ClaudeCodePluginTarget, ClaudeCodePluginArtifact, _Claude]:
    target = _target(tmp_path, marketplace)
    artifact = render_claude_code_plugin(finishup_launcher=_launcher(tmp_path))
    legacy = _legacy_root(target)
    _write_legacy_tree(tmp_path, legacy, launcher=artifact.finishup_launcher)
    claude = _Claude(artifact, target)
    claude.register(_OLD[0], legacy)
    claude.installed[_OLD[1]] = True
    claude.set_enabled(_OLD[1], True)
    return target, artifact, claude


def _apply(
    target: ClaudeCodePluginTarget,
    action: ClaudeCodePluginAction,
    artifact: ClaudeCodePluginArtifact,
    claude: _Claude,
    number: int,
) -> object:
    request = _request(number)
    preview = preview_claude_code_plugin(request, target, action, artifact, commands=claude)
    return apply_claude_code_plugin(
        request,
        target,
        action,
        artifact,
        accepted_preview_digest=preview.preview_digest,
        authority=ArtifactAuthority("review_only", preview.preview_digest, "a" * 64),
        review=_Review(),
        commands=claude,
    )


def test_legacy_only_install_is_reported_and_connect_migrates_it(tmp_path: Path) -> None:
    target, artifact, claude = _legacy_install(tmp_path)

    status = status_claude_code_plugin(target, artifact, commands=claude)
    assert status.state is PluginArtifactState.ABSENT
    assert status.legacy_installation == "legacy_only"
    preview = preview_claude_code_plugin(
        _request(1), target, ClaudeCodePluginAction.CONNECT, artifact, commands=claude
    )
    assert preview.action is ClaudeCodePluginAction.CONNECT
    assert preview.legacy_installation == "legacy_only"
    assert {
        "legacy_installation_owned",
        "legacy_marketplace_retained",
        "legacy_project_registration_removed",
    } <= set(preview.warnings)
    assert "legacy_marketplace_replaced" not in preview.warnings

    claude.calls.clear()
    result = _apply(target, ClaudeCodePluginAction.CONNECT, artifact, claude, 2)
    assert getattr(result, "operation_state") is PluginOperationState.COMPLETED
    mutations = [call for call in claude.calls if call != ("plugin", "list", "--json")]
    # The legacy plugin is retired for this project before any renamed source or registration is
    # written, and Claude's unscoped marketplace remove is never run.
    assert mutations[0] == ("plugin", "uninstall", _OLD[1], "--scope", "project", "--keep-data")
    assert not any(call[:3] == ("plugin", "marketplace", "remove") for call in mutations)
    # This project's own declaration is gone; the shared legacy tree and Claude's user-level
    # registration stay for any other project of this config root, and nothing in the tree is
    # reported as changed.
    settings = _load(claude.settings)
    assert _OLD[0] not in cast(dict[str, object], settings["extraKnownMarketplaces"])
    assert _OLD[1] not in cast(dict[str, object], settings["enabledPlugins"])
    assert _OLD[0] in _load(claude.known)
    assert _legacy_root(target).is_dir()
    assert not any(path.startswith("yoetz-local/") for path in getattr(result, "changed_files"))
    after = status_claude_code_plugin(target, artifact, commands=claude)
    assert after.state is PluginArtifactState.NATIVE_MANAGED
    assert after.enabled is True
    assert after.legacy_installation == "none"
    assert "legacy_marketplace_retained" in after.notes


def test_update_over_the_legacy_directory_itself_migrates_in_place(tmp_path: Path) -> None:
    # An owner who passed the old ``yoetz-local`` path as the marketplace root (the upgrade
    # plan's explicit update) keeps that directory; it now holds the renamed tree.
    config = tmp_path / "config"
    legacy_root = config / "plugins" / "marketplaces" / _OLD[0]
    target, artifact, claude = _legacy_install(tmp_path, marketplace=legacy_root)
    assert status_claude_code_plugin(target, artifact, commands=claude).legacy_installation == (
        "duplicate"
    )

    preview = preview_claude_code_plugin(
        _request(3), target, ClaudeCodePluginAction.UPDATE, artifact, commands=claude
    )
    # The approval names that the directory and Claude's registration of it are replaced.
    assert "legacy_marketplace_replaced" in preview.warnings
    assert "legacy_marketplace_retained" not in preview.warnings
    claude.calls.clear()
    result = _apply(target, ClaudeCodePluginAction.UPDATE, artifact, claude, 3)
    assert getattr(result, "operation_state") is PluginOperationState.COMPLETED
    assert ("plugin", "marketplace", "remove", _OLD[0]) in claude.calls
    after = status_claude_code_plugin(target, artifact, commands=claude)
    assert after.state is PluginArtifactState.NATIVE_MANAGED
    # The legacy plugin was enabled, so the migrated one is too.
    assert after.enabled is True
    assert after.legacy_installation == "none"
    assert (legacy_root / "plugins" / "finishup").is_dir()
    assert not (legacy_root / "plugins" / "yoetz").exists()


def test_duplicate_install_makes_connect_a_migration(tmp_path: Path) -> None:
    target, artifact, claude = _legacy_install(tmp_path)
    claude.installed[_OLD[1]] = False
    _apply(target, ClaudeCodePluginAction.CONNECT, artifact, claude, 4)
    _write_legacy_tree(tmp_path, _legacy_root(target), launcher=artifact.finishup_launcher)
    claude.register(_OLD[0], _legacy_root(target))

    assert status_claude_code_plugin(target, artifact, commands=claude).legacy_installation == (
        "duplicate"
    )
    preview = preview_claude_code_plugin(
        _request(5), target, ClaudeCodePluginAction.CONNECT, artifact, commands=claude
    )
    assert preview.action is ClaudeCodePluginAction.CONNECT
    _apply(target, ClaudeCodePluginAction.CONNECT, artifact, claude, 6)
    assert status_claude_code_plugin(target, artifact, commands=claude).legacy_installation == (
        "none"
    )


def test_remove_takes_a_legacy_only_install(tmp_path: Path) -> None:
    target, artifact, claude = _legacy_install(tmp_path)

    result = _apply(target, ClaudeCodePluginAction.REMOVE, artifact, claude, 7)
    assert getattr(result, "operation_state") is PluginOperationState.COMPLETED
    assert getattr(result, "state_after") is PluginArtifactState.ABSENT
    assert _legacy_root(target).is_dir()
    assert ("plugin", "uninstall", _OLD[1], "--scope", "project", "--keep-data") in claude.calls
    assert not any(call[:3] == ("plugin", "uninstall", _NEW[1]) for call in claude.calls)
    assert status_claude_code_plugin(target, artifact, commands=claude).legacy_installation == (
        "none"
    )


def test_unproven_legacy_registration_is_reported_and_never_touched(tmp_path: Path) -> None:
    target = _target(tmp_path)
    artifact = render_claude_code_plugin(finishup_launcher=_launcher(tmp_path))
    claude = _Claude(artifact, target)
    claude.register(_OLD[0], _legacy_root(target))
    claude.installed[_OLD[1]] = True

    status = status_claude_code_plugin(target, artifact, commands=claude)
    assert status.legacy_installation == "foreign"
    preview = preview_claude_code_plugin(
        _request(8), target, ClaudeCodePluginAction.CONNECT, artifact, commands=claude
    )
    assert "legacy_installation_foreign" in preview.warnings
    claude.calls.clear()
    _apply(target, ClaudeCodePluginAction.CONNECT, artifact, claude, 9)
    assert not any(_OLD[1] in call or _OLD[0] in call for call in claude.calls)
    assert claude.installed[_OLD[1]] is True


def test_a_legacy_tree_changed_after_preview_is_stale(tmp_path: Path) -> None:
    target, artifact, claude = _legacy_install(tmp_path)
    request = _request(10)
    preview = preview_claude_code_plugin(
        request, target, ClaudeCodePluginAction.CONNECT, artifact, commands=claude
    )
    (_legacy_root(target) / "notes.txt").write_text("changed", encoding="utf-8")

    from finishup.adapters.integrations.claude_code_integration import ClaudeCodeIntegrationError

    with pytest.raises(ClaudeCodeIntegrationError):
        apply_claude_code_plugin(
            request,
            target,
            ClaudeCodePluginAction.CONNECT,
            artifact,
            accepted_preview_digest=preview.preview_digest,
            authority=ArtifactAuthority("review_only", preview.preview_digest, "a" * 64),
            review=_Review(),
            commands=claude,
        )
    assert (_legacy_root(target) / "notes.txt").exists()
    assert claude.installed[_OLD[1]] is True


def test_startup_mode_survives_migration_from_the_legacy_tree(tmp_path: Path) -> None:
    target = _target(tmp_path)
    launcher = _launcher(tmp_path)
    _write_legacy_tree(
        tmp_path, _legacy_root(target), launcher=(str(launcher),), startup="required"
    )

    assert installed_claude_startup_mode(target) == "required"


def _mcp(path: Path, servers: dict[str, object]) -> None:
    path.write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")


def _route(command: str, *args: str) -> dict[str, object]:
    return {
        "args": ["mcp", "serve", "--host", "claude", *args],
        "command": command,
        "type": "stdio",
    }


def _observe(tmp_path: Path, **kwargs: object) -> object:
    project = tmp_path / "project"
    config = tmp_path / "config"
    project.mkdir(exist_ok=True)
    config.mkdir(exist_ok=True)
    return observe_claude_code_mcp(
        plugin_root=tmp_path / "plugin",
        project_root=project,
        claude_config_root=config,
        **kwargs,  # type: ignore[arg-type]
    )


def test_legacy_key_alone_is_the_registration_but_maps_to_no_admission_name(
    tmp_path: Path,
) -> None:
    (tmp_path / "project").mkdir()
    _mcp(tmp_path / "project" / ".mcp.json", {"yoetz": _route("yoetz")})

    observation = _observe(tmp_path)
    assert getattr(observation, "ownership_state") is McpOwnershipState.EXTERNAL
    assert getattr(observation, "winning_source") is ClaudeCodeMcpSource.PROJECT
    assert getattr(observation, "legacy_registration") == "legacy_only"
    assert getattr(observation, "host_admission_supported") is False


def test_both_keys_in_one_source_are_duplicate_not_unreadable(tmp_path: Path) -> None:
    (tmp_path / "project").mkdir()
    _mcp(
        tmp_path / "project" / ".mcp.json",
        {"finishup": _route("finishup", "--semantic", "off"), "yoetz": _route("yoetz")},
    )

    observation = _observe(tmp_path)
    # The source is readable; its two owned entries are two live FinishUP servers.
    assert getattr(observation, "observed") is True
    assert getattr(observation, "ownership_state") is McpOwnershipState.AMBIGUOUS
    assert getattr(observation, "present_sources") == (ClaudeCodeMcpSource.PROJECT,)
    assert getattr(observation, "legacy_registration") == "duplicate"
    assert getattr(observation, "host_admission_supported") is False


def test_plugin_route_beside_an_owned_legacy_external_entry_is_dual(tmp_path: Path) -> None:
    (tmp_path / "project").mkdir()
    (tmp_path / "plugin").mkdir()
    _mcp(tmp_path / "plugin" / ".mcp.json", {"finishup": _route("finishup")})
    _mcp(tmp_path / "project" / ".mcp.json", {"yoetz": _route("yoetz")})

    observation = _observe(tmp_path)
    # Exactly what the same pair under one name reads: refused, never one admissible route.
    assert getattr(observation, "ownership_state") is McpOwnershipState.DUAL
    assert getattr(observation, "legacy_registration") == "duplicate"
    assert getattr(observation, "host_admission_supported") is False


def test_foreign_legacy_key_is_reported_but_not_a_conflict(tmp_path: Path) -> None:
    (tmp_path / "project").mkdir()
    _mcp(tmp_path / "project" / ".mcp.json", {"yoetz": _route("/usr/bin/elsewhere")})

    observation = _observe(tmp_path)
    assert getattr(observation, "ownership_state") is McpOwnershipState.ABSENT
    assert getattr(observation, "legacy_registration") == "foreign"


def test_marker_recorded_old_launcher_proves_a_legacy_registration(tmp_path: Path) -> None:
    (tmp_path / "project").mkdir()
    _mcp(tmp_path / "project" / ".mcp.json", {"yoetz": _route(_OLD_LAUNCHER[0])})
    assert getattr(_observe(tmp_path), "legacy_registration") == "foreign"
    assert (
        getattr(_observe(tmp_path, known_launchers=(_OLD_LAUNCHER,)), "legacy_registration")
        == "legacy_only"
    )

    # Status reads the proof from the owned legacy marker itself.
    target = _target(tmp_path)
    artifact = render_claude_code_plugin(finishup_launcher=_launcher(tmp_path))
    _write_legacy_tree(tmp_path, _legacy_root(target), launcher=_OLD_LAUNCHER)
    claude = _Claude(artifact, target)
    claude.register(_OLD[0], _legacy_root(target))
    status = status_claude_code_plugin(target, artifact, commands=claude)
    assert status.legacy_installation == "legacy_only"
    assert status.mcp_observation.legacy_registration == "legacy_only"
    assert status.mcp_observation.ownership_state is McpOwnershipState.EXTERNAL


def test_activation_cues_read_a_not_yet_migrated_legacy_marketplace(tmp_path: Path) -> None:
    target = _target(tmp_path)
    launcher = _launcher(tmp_path)
    _write_legacy_tree(tmp_path, _legacy_root(target), launcher=(str(launcher),))

    cues = observe_claude_code_activation_cues(
        project_root=Path(target.project_root),
        claude_config_root=Path(target.claude_config_root),
        finishup_launcher=(str(launcher),),
        home=tmp_path / "home",
        environ={},
    )
    assert "plugin_hooks" in cues.cue_sources
    assert cues.session_start_cue == "installed"


def test_guided_connection_migrates_and_disconnect_removes_a_legacy_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from finishup.adapters.integrations import claude_code_integration as module
    from finishup.adapters.integrations.host_discovery import HostInstallation
    from finishup.application.host_connection import (
        ConnectionAction,
        ConnectionPlan,
        apply_connection,
        prepare_connection,
    )

    target, artifact, claude = _legacy_install(tmp_path)

    def discover(_executable: Path) -> ClaudeCodeCapabilityIdentity:
        return target.identity

    monkeypatch.setattr(module, "discover_claude_code", discover)
    monkeypatch.setattr(module, "SubprocessClaudeCodeCommands", lambda: claude)
    installation = HostInstallation(
        "claude",
        Path(target.executable),
        target.identity.version,
        Path(target.claude_config_root),
        "Claude Code",
    )

    def connection(action: ConnectionAction, number: int) -> dict[str, JsonValue]:
        def prepare() -> ConnectionPlan:
            return prepare_connection(
                _request(number),
                installation,
                Path(target.project_root),
                action=action,
                route="policy",
                launcher=artifact.finishup_launcher,
            )

        plan = prepare()
        expected = "migrate_legacy_plugin" if action == "connect" else "remove_legacy_plugin"
        assert plan.body["changes"] == (
            [expected, "install_plugin", "enable_plugin", "plugin_mcp"]
            if action == "connect"
            else [expected]
        )
        return apply_connection(
            plan,
            accepted_digest=plan.digest,
            refresh=prepare,
            authority=ArtifactAuthority("review_only", plan.digest, "test"),
            review=_Review(),
        )

    connected = connection("connect", 20)
    assert (connected["installed"], connected["enabled"]) == (True, True)
    assert connected["legacy_installation"] == "none"
    assert _legacy_root(target).is_dir()

    # Leave only a legacy install: the renamed one is removed out of band.
    module._remove_source(Path(target.marketplace_root))  # pyright: ignore[reportPrivateUsage]
    claude.installed[_NEW[1]] = False
    settings = _load(claude.settings)
    del cast(dict[str, object], settings["extraKnownMarketplaces"])[_NEW[0]]
    _store(claude.settings, settings)
    _write_legacy_tree(tmp_path, _legacy_root(target), launcher=artifact.finishup_launcher)
    claude.register(_OLD[0], _legacy_root(target))
    claude.installed[_OLD[1]] = True

    disconnected = connection("disconnect", 21)
    assert disconnected["legacy_installation"] == "none"
    assert _legacy_root(target).is_dir()
    assert claude.installed[_OLD[1]] is False
    assert _OLD[0] not in claude.registered


class _Projects:
    """One Claude config root seen from several projects: ``plugin list`` reports them all."""

    def __init__(self, *claudes: _Claude) -> None:
        self.claudes = {claude.target.project_root: claude for claude in claudes}

    def run(
        self, target: ClaudeCodePluginTarget, arguments: Sequence[str]
    ) -> ClaudeCodeCommandResult:
        if tuple(arguments)[:3] == ("plugin", "marketplace", "remove"):
            # Claude's unscoped remove uninstalls the marketplace's plugins for every project.
            for claude in self.claudes.values():
                claude.drop_installs(arguments[3])
        if tuple(arguments) != ("plugin", "list", "--json"):
            return self.claudes[target.project_root].run(target, arguments)
        rows: list[object] = []
        for claude in self.claudes.values():
            rows.extend(json.loads(claude.run(claude.target, arguments).stdout))
        return ClaudeCodeCommandResult(0, canonical_encode(cast(JsonValue, rows)), b"")


def _second_project(
    tmp_path: Path, first: ClaudeCodePluginTarget, artifact: ClaudeCodePluginArtifact
) -> tuple[ClaudeCodePluginTarget, _Claude]:
    project = tmp_path / "project-b"
    project.mkdir()
    target = ClaudeCodePluginTarget(
        str(project),
        first.claude_config_root,
        first.cache_root,
        first.marketplace_root,
        first.executable,
        first.identity,
    )
    claude = _Claude(artifact, target)
    claude.register(_OLD[0], _legacy_root(target))
    claude.installed[_OLD[1]] = True
    claude.set_enabled(_OLD[1], True)
    return target, claude


def test_reviewed_remove_keeps_foreign_mcp_and_shared_legacy_marketplace(tmp_path: Path) -> None:
    target, artifact, first_claude = _legacy_install(tmp_path)
    second, second_claude = _second_project(tmp_path, target, artifact)
    claude = _Projects(first_claude, second_claude)
    mcp_path = Path(target.project_root) / ".mcp.json"
    _mcp(mcp_path, {"finishup": {"command": "other-server", "args": ["private-value"]}})
    mcp_before = mcp_path.read_bytes()
    known_before = first_claude.known.read_bytes()
    second_settings_before = second_claude.settings.read_bytes()
    root = _legacy_root(target)
    tree_before = {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }
    before = status_claude_code_plugin(target, artifact, commands=claude)
    assert before.legacy_installation == "legacy_only"
    assert before.mcp_observation.ownership_state is McpOwnershipState.FOREIGN

    request = _request(65)
    preview = preview_claude_code_plugin(
        request, target, ClaudeCodePluginAction.REMOVE, artifact, commands=claude
    )
    assert preview.action is ClaudeCodePluginAction.REMOVE
    assert preview.legacy_installation == "legacy_only"
    assert {
        "legacy_installation_owned",
        "legacy_project_registration_removed",
        "legacy_marketplace_retained",
    } <= set(preview.warnings)
    first_claude.calls.clear()
    second_claude.calls.clear()
    result = apply_claude_code_plugin(
        request,
        target,
        ClaudeCodePluginAction.REMOVE,
        artifact,
        accepted_preview_digest=preview.preview_digest,
        authority=ArtifactAuthority("review_only", preview.preview_digest, "a" * 64),
        review=_Review(),
        commands=claude,
    )
    assert result.operation_state is PluginOperationState.COMPLETED
    assert result.state_after is PluginArtifactState.ABSENT
    assert first_claude.installed[_OLD[1]] is False
    assert first_claude.enabled[_OLD[1]] is False
    settings = _load(first_claude.settings)
    assert _OLD[0] not in cast(dict[str, object], settings.get("extraKnownMarketplaces", {}))
    assert _OLD[1] not in cast(dict[str, object], settings.get("enabledPlugins", {}))
    mutations = [call for call in first_claude.calls if call != ("plugin", "list", "--json")]
    assert mutations == [("plugin", "uninstall", _OLD[1], "--scope", "project", "--keep-data")]
    assert all(call == ("plugin", "list", "--json") for call in second_claude.calls)
    assert mcp_path.read_bytes() == mcp_before
    assert first_claude.known.read_bytes() == known_before
    assert second_claude.settings.read_bytes() == second_settings_before
    assert {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    } == tree_before
    assert second_claude.installed[_OLD[1]] is True
    assert second_claude.enabled[_OLD[1]] is True
    after = status_claude_code_plugin(target, artifact, commands=claude)
    assert after.legacy_installation == "none"
    assert after.mcp_observation.ownership_state is McpOwnershipState.FOREIGN
    assert status_claude_code_plugin(second, artifact, commands=claude).legacy_installation == (
        "legacy_only"
    )


def test_migrating_one_project_keeps_the_shared_tree_for_the_next(tmp_path: Path) -> None:
    first, artifact, first_claude = _legacy_install(tmp_path)
    second, second_claude = _second_project(tmp_path, first, artifact)
    claude = _Projects(first_claude, second_claude)
    assert status_claude_code_plugin(second, artifact, commands=claude).legacy_installation == (
        "legacy_only"
    )

    request = _request(40)
    preview = preview_claude_code_plugin(
        request, first, ClaudeCodePluginAction.CONNECT, artifact, commands=claude
    )
    assert "legacy_marketplace_retained" in preview.warnings
    result = apply_claude_code_plugin(
        request,
        first,
        ClaudeCodePluginAction.CONNECT,
        artifact,
        accepted_preview_digest=preview.preview_digest,
        authority=ArtifactAuthority("review_only", preview.preview_digest, "a" * 64),
        review=_Review(),
        commands=claude,
    )
    assert getattr(result, "operation_state") is PluginOperationState.COMPLETED
    # The second project still loads the legacy plugin from the untouched shared tree, so it
    # still reads as its own owned install and its own connect can retire it.
    assert _legacy_root(first).is_dir()
    assert second_claude.installed[_OLD[1]] is True
    assert not any(call[:3] == ("plugin", "marketplace", "remove") for call in first_claude.calls)
    # Claude's user-level registration and the second project's declaration are untouched.
    assert _load(first_claude.known)[_OLD[0]] == {
        "installLocation": str(_legacy_root(first)),
        "source": {"path": str(_legacy_root(first)), "source": "directory"},
    }
    assert second_claude.registered[_OLD[0]] == str(_legacy_root(first))
    assert cast(dict[str, object], _load(second_claude.settings)["enabledPlugins"])[_OLD[1]]
    # The renamed marketplace tree is shared too, so beside it the legacy install reads duplicate.
    before = status_claude_code_plugin(second, artifact, commands=claude)
    assert before.legacy_installation == "duplicate"

    request = _request(41)
    preview = preview_claude_code_plugin(
        request, second, ClaudeCodePluginAction.CONNECT, artifact, commands=claude
    )
    assert "legacy_installation_owned" in preview.warnings
    apply_claude_code_plugin(
        request,
        second,
        ClaudeCodePluginAction.CONNECT,
        artifact,
        accepted_preview_digest=preview.preview_digest,
        authority=ArtifactAuthority("review_only", preview.preview_digest, "a" * 64),
        review=_Review(),
        commands=claude,
    )
    assert second_claude.installed[_OLD[1]] is False
    for target in (first, second):
        after = status_claude_code_plugin(target, artifact, commands=claude)
        assert after.legacy_installation == "none"
        assert "legacy_marketplace_retained" in after.notes
    assert _legacy_root(first).is_dir()


def test_an_unreferenced_legacy_tree_is_retained_not_this_projects(tmp_path: Path) -> None:
    target = _target(tmp_path)
    artifact = render_claude_code_plugin(finishup_launcher=_launcher(tmp_path))
    _write_legacy_tree(tmp_path, _legacy_root(target), launcher=artifact.finishup_launcher)
    claude = _Claude(artifact, target)

    status = status_claude_code_plugin(target, artifact, commands=claude)
    assert status.legacy_installation == "none"
    assert "legacy_marketplace_retained" in status.notes
    claude.calls.clear()
    _apply(target, ClaudeCodePluginAction.CONNECT, artifact, claude, 42)
    assert not any(_OLD[0] in call or _OLD[1] in call for call in claude.calls)
    assert _legacy_root(target).is_dir()


def test_in_place_update_over_a_shared_legacy_directory_is_refused(tmp_path: Path) -> None:
    from finishup.adapters.integrations.claude_code_integration import ClaudeCodeIntegrationError

    legacy_root = tmp_path / "config" / "plugins" / "marketplaces" / _OLD[0]
    first, artifact, first_claude = _legacy_install(tmp_path, marketplace=legacy_root)
    _second, second_claude = _second_project(tmp_path, first, artifact)
    claude = _Projects(first_claude, second_claude)
    before = {path: path.read_bytes() for path in legacy_root.rglob("*") if path.is_file()}

    with pytest.raises(ClaudeCodeIntegrationError) as raised:
        preview_claude_code_plugin(
            _request(43), first, ClaudeCodePluginAction.UPDATE, artifact, commands=claude
        )
    assert raised.value.safe_details == {"legacy_marketplace_shared": True}
    assert {path: path.read_bytes() for path in legacy_root.rglob("*") if path.is_file()} == before


def test_registration_naming_another_directory_is_foreign_and_untouched(tmp_path: Path) -> None:
    target, artifact, claude = _legacy_install(tmp_path)
    elsewhere = tmp_path / "elsewhere" / _OLD[0]
    _write_legacy_tree(tmp_path, elsewhere, launcher=artifact.finishup_launcher)
    claude.register(_OLD[0], elsewhere)

    status = status_claude_code_plugin(target, artifact, commands=claude)
    assert status.legacy_installation == "foreign"
    claude.calls.clear()
    _apply(target, ClaudeCodePluginAction.CONNECT, artifact, claude, 44)
    assert not any(_OLD[0] in call or _OLD[1] in call for call in claude.calls)
    assert elsewhere.is_dir() and _legacy_root(target).is_dir()


def test_repository_settings_cannot_supply_a_legacy_tree_or_launcher(tmp_path: Path) -> None:
    # A cloned repository commits ``.claude/settings.json`` naming an in-repository
    # ``yoetz-local`` with a self-consistent forged marker that records the repository's own
    # binary, plus a project MCP entry launching that binary. None of it is FinishUP's.
    target = _target(tmp_path)
    artifact = render_claude_code_plugin(finishup_launcher=_launcher(tmp_path))
    project = Path(target.project_root)
    forged_root = project / "vendor" / _OLD[0]
    forged_launcher = str(project / "vendor" / "bin" / "yoetz")
    _write_legacy_tree(tmp_path, forged_root, launcher=(forged_launcher,))
    settings = project / ".claude" / "settings.json"
    settings.parent.mkdir(parents=True)
    settings.write_text(
        json.dumps(
            {
                "extraKnownMarketplaces": {
                    _OLD[0]: {"source": {"source": "directory", "path": str(forged_root)}}
                }
            }
        ),
        encoding="utf-8",
    )
    _mcp(project / ".mcp.json", {"finishup": _route(forged_launcher)})
    claude = _Claude(artifact, target)

    status = status_claude_code_plugin(target, artifact, commands=claude)
    assert status.legacy_installation == "foreign"
    assert status.mcp_observation.ownership_state is McpOwnershipState.FOREIGN
    assert status.mcp_observation.host_admission_supported is False
    claude.calls.clear()
    from finishup.adapters.integrations.claude_code_integration import ClaudeCodeIntegrationError

    # Nothing here is FinishUP's to remove, and nothing in the repository is ever touched.
    with pytest.raises(ClaudeCodeIntegrationError):
        _apply(target, ClaudeCodePluginAction.REMOVE, artifact, claude, 46)
    assert not any(_OLD[0] in call or _OLD[1] in call for call in claude.calls)
    assert (forged_root / ".yoetz-claude-marketplace-install.json").is_file()
    assert json.loads(settings.read_text(encoding="utf-8"))["extraKnownMarketplaces"]


def test_migration_keeps_every_other_project_setting(tmp_path: Path) -> None:
    target, artifact, claude = _legacy_install(tmp_path)
    settings = _load(claude.settings)
    document: dict[str, object] = {
        "permissions": {"allow": ["Bash(ls:*)"]},
        "enabledPlugins": {
            "other@elsewhere": True,
            **cast(dict[str, object], settings["enabledPlugins"]),
        },
        "extraKnownMarketplaces": {
            "elsewhere": {"source": {"source": "github", "repo": "owner/elsewhere"}},
            **cast(dict[str, object], settings["extraKnownMarketplaces"]),
        },
        "model": "opus",
    }
    _store(claude.settings, document)
    claude.settings.chmod(0o644)

    result = _apply(target, ClaudeCodePluginAction.REMOVE, artifact, claude, 50)
    assert getattr(result, "operation_state") is PluginOperationState.COMPLETED
    after = _load(claude.settings)
    # Only the legacy declaration went; every other key keeps its value and position.
    assert list(after) == ["permissions", "enabledPlugins", "extraKnownMarketplaces", "model"]
    assert after["permissions"] == {"allow": ["Bash(ls:*)"]}
    assert after["enabledPlugins"] == {"other@elsewhere": True}
    assert after["extraKnownMarketplaces"] == {
        "elsewhere": {"source": {"source": "github", "repo": "owner/elsewhere"}}
    }
    assert claude.settings.stat().st_mode & 0o777 == 0o644
    assert not any(
        path.name.startswith(".finishup-claude-settings-")
        for path in claude.settings.parent.iterdir()
    )


def test_a_declaration_changed_during_migration_is_left_alone(tmp_path: Path) -> None:
    target, artifact, claude = _legacy_install(tmp_path)
    moved = tmp_path / "moved" / _OLD[0]
    run = claude.run

    def racing(
        command_target: ClaudeCodePluginTarget, arguments: Sequence[str]
    ) -> ClaudeCodeCommandResult:
        result = run(command_target, arguments)
        if tuple(arguments[:2]) == ("plugin", "uninstall"):
            # Another writer re-points this project's legacy registration mid-migration.
            settings = _load(claude.settings)
            sources = cast(dict[str, object], settings["extraKnownMarketplaces"])
            sources[_OLD[0]] = {"source": {"source": "directory", "path": str(moved)}}
            _store(claude.settings, settings)
        return result

    claude.run = racing  # type: ignore[method-assign]
    result = _apply(target, ClaudeCodePluginAction.CONNECT, artifact, claude, 51)
    # Not the entry the owner approved removing: FinishUP stops and leaves the file as found.
    assert getattr(result, "operation_state") is PluginOperationState.OUTCOME_UNKNOWN
    assert claude.registered[_OLD[0]] == str(moved)
    assert not any(call[:3] == ("plugin", "marketplace", "add") for call in claude.calls)
    assert _legacy_root(target).is_dir()


def test_a_symlinked_project_claude_directory_reads_foreign_and_uninstalls_nothing(
    tmp_path: Path,
) -> None:
    # FinishUP never edits settings through a symlinked ``.claude``: status reads the legacy
    # install as foreign, and the preview refuses the directory before any command runs (the
    # project-settings ownership rule, ADR-007), so no connect uninstalls the legacy plugin.
    from finishup.adapters.integrations.claude_code_integration import ClaudeCodeIntegrationError
    from finishup.ports.plugin_artifacts import PluginArtifactReason

    target, artifact, claude = _legacy_install(tmp_path)
    claude_dir = Path(target.project_root) / ".claude"
    shared = tmp_path / "shared-claude"
    claude_dir.rename(shared)
    claude_dir.symlink_to(shared, target_is_directory=True)

    status = status_claude_code_plugin(target, artifact, commands=claude)
    assert status.legacy_installation == "foreign"
    settings_before = (shared / "settings.json").read_bytes()
    claude.calls.clear()
    with pytest.raises(ClaudeCodeIntegrationError) as raised:
        preview_claude_code_plugin(
            _request(60), target, ClaudeCodePluginAction.CONNECT, artifact, commands=claude
        )
    assert raised.value.reason is PluginArtifactReason.TARGET_UNSAFE
    assert [call for call in claude.calls if call != ("plugin", "list", "--json")] == []
    assert claude.installed[_OLD[1]] is True
    assert (shared / "settings.json").read_bytes() == settings_before
    assert _legacy_root(target).is_dir()


def _drop_project_marketplace_declaration(claude: _Claude) -> None:
    settings = _load(claude.settings)
    del settings["extraKnownMarketplaces"]
    _store(claude.settings, settings)


def test_in_place_update_without_a_project_declaration_unregisters_the_user_level_entry(
    tmp_path: Path,
) -> None:
    # Claude lists the legacy plugin for this project and its user-level file registers the
    # directory, but this project's settings do not declare it: the approval still names the
    # registration's removal, and the remove runs, so nothing points at the replaced folder.
    legacy_root = tmp_path / "config" / "plugins" / "marketplaces" / _OLD[0]
    target, artifact, claude = _legacy_install(tmp_path, marketplace=legacy_root)
    _drop_project_marketplace_declaration(claude)

    preview = preview_claude_code_plugin(
        _request(62), target, ClaudeCodePluginAction.UPDATE, artifact, commands=claude
    )
    assert "legacy_installation_owned" in preview.warnings
    assert "legacy_marketplace_replaced" in preview.warnings
    claude.calls.clear()
    result = _apply(target, ClaudeCodePluginAction.UPDATE, artifact, claude, 62)
    assert getattr(result, "operation_state") is PluginOperationState.COMPLETED
    assert ("plugin", "marketplace", "remove", _OLD[0]) in claude.calls
    known = _load(claude.known)
    assert _OLD[0] not in known
    assert _NEW[0] in known
    assert (legacy_root / "plugins" / "finishup").is_dir()


def test_in_place_update_with_no_registration_left_neither_warns_nor_unregisters(
    tmp_path: Path,
) -> None:
    # Nothing registers the directory any more, so no remove runs and none is announced.
    legacy_root = tmp_path / "config" / "plugins" / "marketplaces" / _OLD[0]
    target, artifact, claude = _legacy_install(tmp_path, marketplace=legacy_root)
    _drop_project_marketplace_declaration(claude)
    known = _load(claude.known)
    del known[_OLD[0]]
    _store(claude.known, known)

    preview = preview_claude_code_plugin(
        _request(63), target, ClaudeCodePluginAction.UPDATE, artifact, commands=claude
    )
    assert "legacy_installation_owned" in preview.warnings
    assert "legacy_marketplace_replaced" not in preview.warnings
    claude.calls.clear()
    result = _apply(target, ClaudeCodePluginAction.UPDATE, artifact, claude, 63)
    assert getattr(result, "operation_state") is PluginOperationState.COMPLETED
    assert not any(call[:3] == ("plugin", "marketplace", "remove") for call in claude.calls)
    assert _OLD[0] not in _load(claude.known)


def test_a_user_level_registration_appearing_after_preview_is_stale(tmp_path: Path) -> None:
    # Whether the in-place migration unregisters the legacy marketplace is bound to the preview.
    from finishup.adapters.integrations.claude_code_integration import ClaudeCodeIntegrationError

    legacy_root = tmp_path / "config" / "plugins" / "marketplaces" / _OLD[0]
    target, artifact, claude = _legacy_install(tmp_path, marketplace=legacy_root)
    _drop_project_marketplace_declaration(claude)
    registered = _load(claude.known)
    unregistered = {name: entry for name, entry in registered.items() if name != _OLD[0]}
    _store(claude.known, unregistered)
    preview = preview_claude_code_plugin(
        _request(64), target, ClaudeCodePluginAction.UPDATE, artifact, commands=claude
    )
    _store(claude.known, registered)
    claude.calls.clear()
    with pytest.raises(ClaudeCodeIntegrationError):
        apply_claude_code_plugin(
            _request(64),
            target,
            ClaudeCodePluginAction.UPDATE,
            artifact,
            accepted_preview_digest=preview.preview_digest,
            authority=ArtifactAuthority("review_only", preview.preview_digest, "a" * 64),
            review=_Review(),
            commands=claude,
        )
    assert not any(call[:2] != ("plugin", "list") for call in claude.calls)
