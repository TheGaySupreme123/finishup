from __future__ import annotations

import hashlib
import json
import shlex
import shutil
from collections.abc import Sequence
from pathlib import Path
from typing import cast

import pytest

from yoetz.adapters.integrations.claude_code_integration import (
    CLAUDE_CODE_HARNESS_PROFILE,
    CLAUDE_CODE_HOOK_EVENTS,
    ClaudeCodeCapabilityIdentity,
    ClaudeCodeCommandResult,
    ClaudeCodeIntegrationError,
    ClaudeCodeMcpSource,
    ClaudeCodePluginAction,
    ClaudeCodePluginArtifact,
    ClaudeCodePluginTarget,
    apply_claude_code_plugin,
    installed_claude_startup_mode,
    observe_claude_code_mcp,
    observe_claude_code_session_init,
    preview_claude_code_plugin,
    render_claude_code_plugin,
    status_claude_code_plugin,
)
from yoetz.domain.values import JsonObject, request_id
from yoetz.ports.plugin_artifacts import (
    ArtifactAuthority,
    McpOwnership,
    McpOwnershipState,
    PluginArtifactError,
    PluginArtifactReason,
    PluginArtifactState,
    PluginFormatProfile,
    PluginOperationState,
    PluginProofFacet,
)
from yoetz.protocol.canonical import JsonValue, canonical_encode
from yoetz.protocol.guidance_uris import FOCUSED_GUIDANCE_URIS, GUIDANCE_DOCUMENT_URIS
from yoetz.version import read_verified_resource

_REQUEST = request_id("req_10000000-0000-4000-8000-000000000001")
_GUIDANCE_NAMES = tuple(
    uri.removeprefix("yoetz://guidance/")
    for uri in (*GUIDANCE_DOCUMENT_URIS, *FOCUSED_GUIDANCE_URIS)
)


def test_required_startup_install_inspect_and_reverse(tmp_path: Path) -> None:
    target = _target(tmp_path)
    required = render_claude_code_plugin(startup_mode="required")
    commands = _ClaudeFixture(required)
    for index, artifact in enumerate((required, render_claude_code_plugin())):
        commands.artifact = artifact
        action = ClaudeCodePluginAction.INSTALL if index == 0 else ClaudeCodePluginAction.UPDATE
        preview = preview_claude_code_plugin(_REQUEST, target, action, artifact, commands=commands)
        apply_claude_code_plugin(
            _REQUEST,
            target,
            action,
            artifact,
            accepted_preview_digest=preview.preview_digest,
            authority=_authority(preview.preview_digest),
            review=_Review(),
            commands=commands,
        )
        assert installed_claude_startup_mode(target) == ("required" if index == 0 else "optional")
        assert status_claude_code_plugin(target, artifact, commands=commands).marker_valid


class _Review:
    def __init__(self) -> None:
        self.consumed: list[str] = []

    def consume_setup_authority(self, authority: ArtifactAuthority, preview_digest: str) -> None:
        assert authority.target_digest == preview_digest
        self.consumed.append(preview_digest)

    def consume_artifact_review(self, authority: ArtifactAuthority, preview_digest: str) -> None:
        assert authority.target_digest == preview_digest
        self.consumed.append(preview_digest)


def _authority(digest: str) -> ArtifactAuthority:
    return ArtifactAuthority("review_only", digest, "a" * 64)


def _target(tmp_path: Path) -> ClaudeCodePluginTarget:
    project = tmp_path / "project"
    config = tmp_path / "config"
    marketplace = tmp_path / "marketplace"
    executable = tmp_path / "claude"
    project.mkdir()
    config.mkdir()
    executable.write_bytes(b"claude-test-executable")
    executable.chmod(0o700)
    executable_digest = f"sha256:{hashlib.sha256(executable.read_bytes()).hexdigest()}"
    return ClaudeCodePluginTarget(
        str(project),
        str(config),
        str(config / "plugins" / "cache"),
        str(marketplace),
        str(executable),
        ClaudeCodeCapabilityIdentity(
            "2.1.241",
            executable_digest,
            "darwin",
            "arm64",
        ),
    )


class _ClaudeFixture:
    def __init__(
        self, artifact: ClaudeCodePluginArtifact, *, removes_marketplace_source: bool = False
    ) -> None:
        self.artifact = artifact
        self.removes_marketplace_source = removes_marketplace_source
        self.installed = False
        self.enabled = False
        self.calls: list[tuple[str, ...]] = []

    def settings(self, target: ClaudeCodePluginTarget, registered: bool) -> None:
        path = Path(target.project_root) / ".claude" / "settings.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        value: dict[str, object] = {"enabledPlugins": {"yoetz@yoetz-local": self.enabled}}
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
                        "source": {
                            "source": "directory",
                            "path": target.marketplace_root,
                        },
                    }
                }
                if registered
                else {}
            ),
            encoding="utf-8",
        )

    def _cache(self, target: ClaudeCodePluginTarget) -> Path:
        return Path(target.cache_root) / "yoetz-local" / "yoetz" / self.artifact.plan.version

    def run(
        self, target: ClaudeCodePluginTarget, arguments: Sequence[str]
    ) -> ClaudeCodeCommandResult:
        args = tuple(arguments)
        self.calls.append(args)
        if args == ("plugin", "list", "--json"):
            rows: list[dict[str, object]] = []
            if self.installed:
                rows.append(
                    {
                        "enabled": self.enabled,
                        "id": "yoetz@yoetz-local",
                        "installPath": str(self._cache(target)),
                        "projectPath": target.project_root,
                        "scope": "project",
                        "version": self.artifact.plan.version,
                    }
                )
            return ClaudeCodeCommandResult(0, canonical_encode(cast(JsonValue, rows)), b"")
        if args[:4] == ("plugin", "marketplace", "add", "--scope"):
            self.settings(target, True)
            return ClaudeCodeCommandResult(0, b"ok", b"")
        if args[:2] == ("plugin", "install"):
            cache = self._cache(target)
            cache.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(Path(target.marketplace_root) / "plugins" / "yoetz", cache)
            self.installed = True
            self.enabled = False
            self.settings(target, True)
            return ClaudeCodeCommandResult(0, b"ok", b"")
        if args[:2] == ("plugin", "enable"):
            self.enabled = True
            self.settings(target, True)
            return ClaudeCodeCommandResult(0, b"ok", b"")
        if args[:2] == ("plugin", "disable"):
            self.enabled = False
            self.settings(target, True)
            return ClaudeCodeCommandResult(0, b"ok", b"")
        if args[:3] == ("plugin", "marketplace", "update"):
            return ClaudeCodeCommandResult(0, b"ok", b"")
        if args[:2] == ("plugin", "update"):
            cache = self._cache(target)
            if cache.exists():
                shutil.rmtree(cache)
            shutil.copytree(Path(target.marketplace_root) / "plugins" / "yoetz", cache)
            return ClaudeCodeCommandResult(0, b"ok", b"")
        if args[:2] == ("plugin", "uninstall"):
            cache = self._cache(target)
            if cache.exists():
                shutil.rmtree(cache)
            self.installed = False
            self.enabled = False
            self.settings(target, True)
            return ClaudeCodeCommandResult(0, b"ok", b"")
        if args[:3] == ("plugin", "marketplace", "remove"):
            self.settings(target, False)
            if self.removes_marketplace_source:
                shutil.rmtree(Path(target.marketplace_root))
            return ClaudeCodeCommandResult(0, b"ok", b"")
        return ClaudeCodeCommandResult(1, b"", b"unexpected")


def test_connect_installs_and_enables_with_one_review_and_replays_without_review(
    tmp_path: Path,
) -> None:
    target = _target(tmp_path)
    artifact = render_claude_code_plugin(
        mcp_ownership=McpOwnership.PLUGIN_MANAGED, route_profile="strict"
    )
    commands = _ClaudeFixture(artifact)
    review = _Review()
    preview = preview_claude_code_plugin(
        _REQUEST, target, ClaudeCodePluginAction.CONNECT, artifact, commands=commands
    )
    result = apply_claude_code_plugin(
        _REQUEST,
        target,
        ClaudeCodePluginAction.CONNECT,
        artifact,
        accepted_preview_digest=preview.preview_digest,
        authority=_authority(preview.preview_digest),
        review=review,
        commands=commands,
    )
    assert result.operation_state is PluginOperationState.COMPLETED
    assert result.enabled is True
    assert review.consumed == [preview.preview_digest]
    replay = preview_claude_code_plugin(
        _REQUEST, target, ClaudeCodePluginAction.CONNECT, artifact, commands=commands
    )
    assert replay.action is ClaudeCodePluginAction.NOOP
    apply_claude_code_plugin(
        _REQUEST,
        target,
        ClaudeCodePluginAction.CONNECT,
        artifact,
        accepted_preview_digest=replay.preview_digest,
        authority=None,
        review=review,
        commands=commands,
    )
    assert review.consumed == [preview.preview_digest]


def test_connect_resumes_installed_disabled_without_reinstall(tmp_path: Path) -> None:
    target = _target(tmp_path)
    artifact = render_claude_code_plugin(
        mcp_ownership=McpOwnership.PLUGIN_MANAGED, route_profile="strict"
    )
    commands = _ClaudeFixture(artifact)
    preview = preview_claude_code_plugin(
        _REQUEST, target, ClaudeCodePluginAction.INSTALL, artifact, commands=commands
    )
    apply_claude_code_plugin(
        _REQUEST,
        target,
        ClaudeCodePluginAction.INSTALL,
        artifact,
        accepted_preview_digest=preview.preview_digest,
        authority=_authority(preview.preview_digest),
        review=_Review(),
        commands=commands,
    )
    commands.calls.clear()
    preview = preview_claude_code_plugin(
        _REQUEST, target, ClaudeCodePluginAction.CONNECT, artifact, commands=commands
    )
    result = apply_claude_code_plugin(
        _REQUEST,
        target,
        ClaudeCodePluginAction.CONNECT,
        artifact,
        accepted_preview_digest=preview.preview_digest,
        authority=_authority(preview.preview_digest),
        review=_Review(),
        commands=commands,
    )
    assert result.enabled is True
    assert not any(call[:2] == ("plugin", "install") for call in commands.calls)


def test_native_projection_uses_claude_skill_and_shared_guidance_components() -> None:
    external = render_claude_code_plugin()
    managed = render_claude_code_plugin(
        mcp_ownership=McpOwnership.PLUGIN_MANAGED,
        route_profile="strict",
    )

    assert CLAUDE_CODE_HARNESS_PROFILE.harness_id.value == "claude"
    assert CLAUDE_CODE_HARNESS_PROFILE.capability_profile_ids == (
        "claude-code-cli-local-project-2.1.241",
    )
    fixture = json.loads(
        read_verified_resource(
            "fixtures/agent-plugins/claude-code-cli-native-project-2.1.241.case.json"
        )
    )
    assert fixture["case_id"] == "claude-code-cli-native-project-2.1.241-macos-arm64"
    assert fixture["format_profile"] == "claude_code_plugin_native"
    hook = next(iter(CLAUDE_CODE_HARNESS_PROFILE.hooks_by_capability_profile.values()))
    assert hook is not None
    # The artifact renders all five candidate hooks, but the evidence case
    # recorded observation_evidence: not_observed, so the capability hook cell
    # stays unpopulated until accepted-observation evidence exists per event.
    assert hook.observation_events == ()
    assert fixture["observation_evidence"] == "not_observed"
    assert managed.plan.format_profile is PluginFormatProfile.CLAUDE_CODE_PLUGIN_NATIVE
    assert external.members["skills/yoetz/SKILL.md"] == managed.members["skills/yoetz/SKILL.md"]
    assert external.members["skills/yoetz/SKILL.md"] == read_verified_resource(
        "skills/claude-code/yoetz/SKILL.md"
    )
    for name in _GUIDANCE_NAMES:
        assert external.members[f"skills/yoetz/references/{name}"] == read_verified_resource(
            f"guidance/{name}"
        )
        assert f"guidance/{name}" in external.plan.source_refs
    assert ".mcp.json" not in external.members
    # The plugin-owned MCP entry and every hook launch the exact bound installation, never a
    # bare PATH lookup: the 2026-08-27 dogfood's bridge/service split-brain came from PATH.
    launcher = managed.yoetz_launcher
    assert len(launcher) == 1 and Path(launcher[0]).is_absolute()
    assert json.loads(managed.members[".mcp.json"])["mcpServers"]["yoetz"] == {
        "args": ["mcp", "serve", "--host", "claude", "--semantic", "off"],
        "command": launcher[0],
        "type": "stdio",
    }
    assert managed.development is False
    assert set(managed.members) == {
        ".claude-plugin/plugin.json",
        ".mcp.json",
        "hooks/hooks.json",
        "skills/yoetz/SKILL.md",
        *{f"skills/yoetz/references/{name}" for name in _GUIDANCE_NAMES},
    }
    manifest = json.loads(managed.members[".claude-plugin/plugin.json"])
    marketplace = json.loads(managed.marketplace_manifest)
    hooks = json.loads(managed.members["hooks/hooks.json"])["hooks"]
    assert manifest["defaultEnabled"] is False
    assert manifest["name"] == "yoetz"
    assert marketplace["plugins"] == [
        {"name": "yoetz", "source": "./plugins/yoetz", "strict": True}
    ]
    assert tuple(sorted(hooks)) == CLAUDE_CODE_HOOK_EVENTS
    assert "PermissionRequest" not in hooks
    # The denial hook is scoped to the one tool a host reviewer holds (issue #467); it fires
    # after the denial and can allow nothing.
    assert hooks["PermissionDenied"][0]["matcher"] == ("^mcp__(yoetz|plugin_yoetz_yoetz)__check$")
    assert hooks["PostToolUse"][0]["matcher"] == (
        "^mcp__plugin_yoetz_yoetz__(start|publish_work|check|respond|status|receipt|read_guidance)$"
    )
    assert hooks["PostToolUseFailure"][0]["matcher"] == hooks["PostToolUse"][0]["matcher"]
    assert all("CLAUDE_PROJECT_DIR" in row[0]["hooks"][-1]["command"] for row in hooks.values())
    assert all(
        row[0]["hooks"][-1]["command"].startswith(
            f"{shlex.quote(launcher[0])} hooks claude-observe "
        )
        for row in hooks.values()
    )


def test_installed_neighbor_fixture_keeps_native_child_proof_bounded() -> None:
    from fixture_loader import build_fixture_loader

    fixture = cast(
        dict[str, object],
        build_fixture_loader().load_json(
            "agent-plugins/claude-code-cli-native-project-2.1.261.case.json"
        ),
    )
    assert fixture["capability_status"] == "native_child_hooks_bounded_proven"
    assert fixture["model_use"] == "loopback_synthetic_only"
    assert fixture["observation_evidence"] == "native_hook_payload_only"
    limits = cast(list[object], fixture["proof_limits"])
    assert "production_auth_unavailable_in_isolated_home" in limits
    child = cast(dict[str, object], fixture["native_child_probe"])
    assert child["child_lifecycle"] == "started_completed"
    assert child["parent_tool_identifier"] == "absent_from_native_payload"


def test_native_hook_timeouts_leave_room_for_local_capture_and_service_drain() -> None:
    artifact = render_claude_code_plugin(observation_profile="ordinary")
    hooks = json.loads(artifact.members["hooks/hooks.json"])["hooks"]

    assert {
        event: definition[0]["hooks"][-1]["timeout"] for event, definition in hooks.items()
    } == {
        "PermissionDenied": 5,
        "PermissionRequest": 5,
        "PreToolUse": 5,
        "PostToolUse": 5,
        "PostToolUseFailure": 5,
        "SessionEnd": 3,
        "SessionStart": 10,
        "Stop": 10,
        "StopFailure": 5,
    }


def test_launcher_binding_uses_the_invoking_installation_and_marks_the_marker(
    tmp_path: Path,
) -> None:
    interpreter = tmp_path / "bin" / "python3"
    interpreter.parent.mkdir()
    interpreter.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    interpreter.chmod(0o700)
    artifact = render_claude_code_plugin(
        mcp_ownership=McpOwnership.PLUGIN_MANAGED,
        route_profile="policy",
        yoetz_launcher=(str(interpreter), "-m", "yoetz"),
    )
    assert artifact.yoetz_launcher == (str(interpreter.resolve()), "-m", "yoetz")
    entry = json.loads(artifact.members[".mcp.json"])["mcpServers"]["yoetz"]
    assert entry == {
        "args": ["-m", "yoetz", "mcp", "serve", "--host", "claude"],
        "command": str(interpreter.resolve()),
        "type": "stdio",
    }
    hook = json.loads(artifact.members["hooks/hooks.json"])["hooks"]["SessionStart"][0]
    assert hook["hooks"][-1]["command"].startswith(
        f"{shlex.quote(str(interpreter.resolve()))} -m yoetz hooks claude-observe "
    )
    # Two installations render two distinct artifacts; the digest binds the launcher.
    other = tmp_path / "bin" / "other"
    other.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    other.chmod(0o700)
    assert (
        render_claude_code_plugin(
            mcp_ownership=McpOwnership.PLUGIN_MANAGED,
            route_profile="policy",
            yoetz_launcher=other,
        ).artifact_digest
        != artifact.artifact_digest
    )
    with pytest.raises(ValueError, match="yoetz_executable_unavailable"):
        render_claude_code_plugin(yoetz_launcher=tmp_path / "missing")

    target = _target(tmp_path)
    commands = _ClaudeFixture(artifact)
    preview = preview_claude_code_plugin(
        _REQUEST, target, ClaudeCodePluginAction.INSTALL, artifact, commands=commands
    )
    apply_claude_code_plugin(
        _REQUEST,
        target,
        ClaudeCodePluginAction.INSTALL,
        artifact,
        accepted_preview_digest=preview.preview_digest,
        authority=_authority(preview.preview_digest),
        review=_Review(),
        commands=commands,
    )
    marker = json.loads(
        (Path(target.marketplace_root) / ".yoetz-claude-marketplace-install.json").read_bytes()
    )
    assert marker["schema"] == "yoetz.claude-code-marketplace-install/2"
    assert marker["yoetz_launcher"] == [str(interpreter.resolve()), "-m", "yoetz"]
    status = status_claude_code_plugin(target, artifact, commands=commands)
    assert status.state is PluginArtifactState.NATIVE_MANAGED
    assert status.marker_valid is True
    # The launcher-bound plugin entry is still recognized as the one exact Yoetz route.
    assert status.mcp_observation.ownership_state is McpOwnershipState.PLUGIN
    assert status.mcp_observation.route_profile == "policy"


def test_legacy_marker_without_launcher_stays_readable_but_is_never_written(
    tmp_path: Path,
) -> None:
    target = _target(tmp_path)
    artifact = render_claude_code_plugin()
    commands = _ClaudeFixture(artifact)
    preview = preview_claude_code_plugin(
        _REQUEST, target, ClaudeCodePluginAction.INSTALL, artifact, commands=commands
    )
    apply_claude_code_plugin(
        _REQUEST,
        target,
        ClaudeCodePluginAction.INSTALL,
        artifact,
        accepted_preview_digest=preview.preview_digest,
        authority=_authority(preview.preview_digest),
        review=_Review(),
        commands=commands,
    )
    marker_path = Path(target.marketplace_root) / ".yoetz-claude-marketplace-install.json"
    marker = json.loads(marker_path.read_bytes())
    body = {key: value for key, value in marker.items() if key != "marker_digest"}
    body["schema"] = "yoetz.claude-code-marketplace-install/1"
    del body["yoetz_launcher"]
    from yoetz.protocol.canonical import canonical_digest

    marker_path.write_bytes(canonical_encode({**body, "marker_digest": canonical_digest(body)}))
    status = status_claude_code_plugin(target, artifact, commands=commands)
    assert status.marker_valid is True
    assert status.state is PluginArtifactState.NATIVE_MANAGED
    # The current renderer's bytes differ from a v1 source only by the marker, which the
    # source digest reports as drift rather than as a modified/unmanaged tree.
    assert status.installed_digest == artifact.artifact_digest


def test_mcp_route_detection_accepts_bare_and_exact_launcher_but_not_other_binaries(
    tmp_path: Path,
) -> None:
    exe = tmp_path / "bin" / "yoetz"
    exe.parent.mkdir()
    exe.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    exe.chmod(0o700)
    artifact = render_claude_code_plugin(yoetz_launcher=exe)
    launcher = artifact.yoetz_launcher
    project = tmp_path / "project"
    config = tmp_path / "config"
    plugin = tmp_path / "plugin"
    for path in (project, config, plugin):
        path.mkdir()

    def observe() -> McpOwnershipState:
        return observe_claude_code_mcp(
            plugin_root=plugin,
            project_root=project,
            claude_config_root=config,
            yoetz_launcher=launcher,
        ).ownership_state

    def write(command: str, args: list[str]) -> None:
        (project / ".mcp.json").write_text(
            json.dumps(
                {"mcpServers": {"yoetz": {"args": args, "command": command, "type": "stdio"}}}
            ),
            encoding="utf-8",
        )

    write("yoetz", ["mcp", "serve"])
    assert observe() is McpOwnershipState.EXTERNAL
    write(launcher[0], ["mcp", "serve", "--semantic", "off"])
    assert observe() is McpOwnershipState.EXTERNAL
    write(str(tmp_path / "bin" / "elsewhere"), ["mcp", "serve"])
    assert observe() is McpOwnershipState.FOREIGN
    write(launcher[0], ["mcp", "serve", "--host", "cursor"])
    assert observe() is McpOwnershipState.FOREIGN


def test_export_writes_the_exact_development_root_and_preview_refuses_it(
    tmp_path: Path,
) -> None:
    from yoetz.adapters.integrations.claude_code_integration import export_claude_code_plugin

    development = render_claude_code_plugin(
        mcp_ownership=McpOwnership.PLUGIN_MANAGED,
        route_profile="strict",
        development_enabled=True,
    )
    production = render_claude_code_plugin(
        mcp_ownership=McpOwnership.PLUGIN_MANAGED, route_profile="strict"
    )
    assert development.development is True
    assert json.loads(development.members[".claude-plugin/plugin.json"])["defaultEnabled"] is True
    assert json.loads(production.members[".claude-plugin/plugin.json"])["defaultEnabled"] is False
    assert development.artifact_digest != production.artifact_digest
    for name in development.members:
        if name != ".claude-plugin/plugin.json":
            assert development.members[name] == production.members[name]

    output = tmp_path / "exports" / "yoetz-dev"
    written = export_claude_code_plugin(development, output)
    assert ".yoetz-claude-plugin-export.json" in written
    assert set(written) == {*development.members, ".yoetz-claude-plugin-export.json"}
    for name, data in development.members.items():
        assert (output / name).read_bytes() == data
    marker = json.loads((output / ".yoetz-claude-plugin-export.json").read_bytes())
    assert marker["schema"] == "yoetz.claude-code-plugin-export/1"
    assert marker["development"] is True
    assert marker["artifact_digest"] == development.artifact_digest
    assert marker["yoetz_launcher"] == list(development.yoetz_launcher)
    assert (output / ".claude-plugin" / "marketplace.json").exists() is False
    with pytest.raises(ClaudeCodeIntegrationError) as conflict:
        export_claude_code_plugin(development, output)
    assert conflict.value.reason is PluginArtifactReason.DESTINATION_CONFLICT

    target = _target(tmp_path)
    with pytest.raises(ClaudeCodeIntegrationError) as refused:
        preview_claude_code_plugin(
            _REQUEST,
            target,
            ClaudeCodePluginAction.INSTALL,
            development,
            commands=_ClaudeFixture(development),
        )
    assert refused.value.reason is PluginArtifactReason.SOURCE_INVALID


@pytest.mark.parametrize("removes_marketplace_source", [False, True])
def test_project_marketplace_install_enable_disable_and_remove_are_separate_states(
    tmp_path: Path,
    removes_marketplace_source: bool,
) -> None:
    target = _target(tmp_path)
    artifact = render_claude_code_plugin(
        mcp_ownership=McpOwnership.PLUGIN_MANAGED,
        route_profile="strict",
    )
    commands = _ClaudeFixture(artifact, removes_marketplace_source=removes_marketplace_source)
    review = _Review()

    before = status_claude_code_plugin(target, artifact, commands=commands)
    assert before.state is PluginArtifactState.ABSENT
    install_preview = preview_claude_code_plugin(
        _REQUEST, target, ClaudeCodePluginAction.INSTALL, artifact, commands=commands
    )
    installed = apply_claude_code_plugin(
        _REQUEST,
        target,
        ClaudeCodePluginAction.INSTALL,
        artifact,
        accepted_preview_digest=install_preview.preview_digest,
        authority=_authority(install_preview.preview_digest),
        review=review,
        commands=commands,
    )
    assert installed.operation_state is PluginOperationState.COMPLETED
    assert installed.state_after is PluginArtifactState.NATIVE_MANAGED
    assert installed.enabled is False
    status = status_claude_code_plugin(target, artifact, commands=commands)
    assert status.marketplace_registered is True
    assert status.discovered is True
    assert status.enabled is False
    assert status.loaded_root_digest is None
    assert status.mcp_observation.ownership_state is McpOwnershipState.PLUGIN
    assert status.mcp_observation.winning_source is ClaudeCodeMcpSource.PLUGIN
    proof = {item.facet: item.status for item in status.proof}
    assert proof[PluginProofFacet.INSTALLED_BYTES] == "proven"
    assert proof[PluginProofFacet.HOST_DISCOVERY] == "proven"
    assert proof[PluginProofFacet.HOST_ACTIVATION] == "not_observed"
    assert proof[PluginProofFacet.MODEL_USE] == "not_observed"

    plugin_root = Path(target.marketplace_root) / "plugins" / "yoetz"
    session = observe_claude_code_session_init(
        JsonObject(
            {
                "claude_code_version": "2.1.241",
                "cwd": target.project_root,
                "mcp_servers": [{"name": "plugin:yoetz:yoetz", "status": "connected"}],
                "plugins": [
                    {
                        "name": "yoetz",
                        "path": str(plugin_root),
                        "source": "yoetz@yoetz-local",
                        "version": artifact.plan.version,
                    }
                ],
                "session_id": "session-activation-1",
                "skills": ["yoetz:yoetz"],
                "subtype": "init",
                "tools": [
                    f"mcp__plugin_yoetz_yoetz__{name}"
                    for name in (
                        "check",
                        "publish_work",
                        "read_guidance",
                        "receipt",
                        "respond",
                        "start",
                        "status",
                    )
                ],
                "type": "system",
            }
        ),
        target=target,
        artifact=artifact,
    )
    # A session observation alone never proves marketplace activation: the
    # same init event can come from a development --plugin-dir run, so the
    # independent installed/discovered/registered/enabled facts are required.
    unactivated = status_claude_code_plugin(
        target, artifact, commands=commands, session_observation=session
    )
    unactivated_proof = {item.facet: item.status for item in unactivated.proof}
    assert unactivated.loaded_root_digest == artifact.artifact_digest
    assert unactivated_proof[PluginProofFacet.HOST_ACTIVATION] == "not_observed"

    enable_request = request_id("req_10000000-0000-4000-8000-000000000002")
    enable_preview = preview_claude_code_plugin(
        enable_request,
        target,
        ClaudeCodePluginAction.ENABLE,
        artifact,
        commands=commands,
    )
    enabled = apply_claude_code_plugin(
        enable_request,
        target,
        ClaudeCodePluginAction.ENABLE,
        artifact,
        accepted_preview_digest=enable_preview.preview_digest,
        authority=_authority(enable_preview.preview_digest),
        review=review,
        commands=commands,
    )
    assert enabled.enabled is True
    assert enabled.operation_state is PluginOperationState.COMPLETED

    activated = status_claude_code_plugin(
        target, artifact, commands=commands, session_observation=session
    )
    activated_proof = {item.facet: item.status for item in activated.proof}
    assert activated.loaded_root_digest == artifact.artifact_digest
    assert activated_proof[PluginProofFacet.HOST_ACTIVATION] == "proven"
    assert activated_proof[PluginProofFacet.SKILL_DELIVERY] == "proven"
    assert activated_proof[PluginProofFacet.MCP_BINDING] == "proven"
    assert activated_proof[PluginProofFacet.MCP_RUNTIME] == "proven"
    assert activated_proof[PluginProofFacet.MODEL_USE] == "not_observed"

    disable_request = request_id("req_10000000-0000-4000-8000-000000000003")
    disable_preview = preview_claude_code_plugin(
        disable_request,
        target,
        ClaudeCodePluginAction.DISABLE,
        artifact,
        commands=commands,
    )
    disabled = apply_claude_code_plugin(
        disable_request,
        target,
        ClaudeCodePluginAction.DISABLE,
        artifact,
        accepted_preview_digest=disable_preview.preview_digest,
        authority=_authority(disable_preview.preview_digest),
        review=review,
        commands=commands,
    )
    assert disabled.enabled is False

    remove_request = request_id("req_10000000-0000-4000-8000-000000000004")
    remove_preview = preview_claude_code_plugin(
        remove_request,
        target,
        ClaudeCodePluginAction.REMOVE,
        artifact,
        commands=commands,
    )
    removed = apply_claude_code_plugin(
        remove_request,
        target,
        ClaudeCodePluginAction.REMOVE,
        artifact,
        accepted_preview_digest=remove_preview.preview_digest,
        authority=_authority(remove_preview.preview_digest),
        review=review,
        commands=commands,
    )
    assert removed.operation_state is PluginOperationState.COMPLETED
    assert removed.state_after is PluginArtifactState.ABSENT
    assert not Path(target.marketplace_root).exists()
    assert len(review.consumed) == 4


def test_mutation_requires_exact_review_and_rejects_legacy_claude(tmp_path: Path) -> None:
    target = _target(tmp_path)
    artifact = render_claude_code_plugin()
    commands = _ClaudeFixture(artifact)
    preview = preview_claude_code_plugin(
        _REQUEST, target, ClaudeCodePluginAction.INSTALL, artifact, commands=commands
    )

    with pytest.raises(ClaudeCodeIntegrationError) as no_authority:
        apply_claude_code_plugin(
            _REQUEST,
            target,
            ClaudeCodePluginAction.INSTALL,
            artifact,
            accepted_preview_digest=preview.preview_digest,
            authority=None,
            commands=commands,
        )
    assert no_authority.value.reason is PluginArtifactReason.AUTHORITY_REQUIRED
    assert not Path(target.marketplace_root).exists()

    legacy = ClaudeCodePluginTarget(
        target.project_root,
        target.claude_config_root,
        target.cache_root,
        target.marketplace_root,
        target.executable,
        ClaudeCodeCapabilityIdentity(
            "2.1.211", target.identity.executable_digest, "darwin", "arm64"
        ),
    )
    with pytest.raises(ClaudeCodeIntegrationError) as unsupported:
        preview_claude_code_plugin(
            _REQUEST,
            legacy,
            ClaudeCodePluginAction.INSTALL,
            artifact,
            commands=commands,
        )
    assert unsupported.value.reason is PluginArtifactReason.FORMAT_UNSUPPORTED


def test_update_replaces_only_marker_valid_source_and_rechecks_same_version_cache(
    tmp_path: Path,
) -> None:
    target = _target(tmp_path)
    strict = render_claude_code_plugin(
        mcp_ownership=McpOwnership.PLUGIN_MANAGED,
        route_profile="strict",
    )
    commands = _ClaudeFixture(strict)
    review = _Review()
    install = preview_claude_code_plugin(
        _REQUEST, target, ClaudeCodePluginAction.INSTALL, strict, commands=commands
    )
    apply_claude_code_plugin(
        _REQUEST,
        target,
        ClaudeCodePluginAction.INSTALL,
        strict,
        accepted_preview_digest=install.preview_digest,
        authority=_authority(install.preview_digest),
        review=review,
        commands=commands,
    )

    policy = render_claude_code_plugin(
        mcp_ownership=McpOwnership.PLUGIN_MANAGED,
        route_profile="policy",
    )
    commands.artifact = policy
    update_request = request_id("req_10000000-0000-4000-8000-000000000030")
    update = preview_claude_code_plugin(
        update_request,
        target,
        ClaudeCodePluginAction.UPDATE,
        policy,
        commands=commands,
    )
    result = apply_claude_code_plugin(
        update_request,
        target,
        ClaudeCodePluginAction.UPDATE,
        policy,
        accepted_preview_digest=update.preview_digest,
        authority=_authority(update.preview_digest),
        review=review,
        commands=commands,
    )
    assert result.operation_state is PluginOperationState.COMPLETED
    assert result.installed_digest == policy.artifact_digest
    assert status_claude_code_plugin(
        target, policy, commands=commands
    ).mcp_observation.route_profile == ("policy")

    source_skill = (
        Path(target.marketplace_root) / "plugins" / "yoetz" / "skills" / "yoetz" / "SKILL.md"
    )
    source_skill.write_text("modified\n", encoding="utf-8")
    with pytest.raises(ClaudeCodeIntegrationError) as modified:
        preview_claude_code_plugin(
            request_id("req_10000000-0000-4000-8000-000000000031"),
            target,
            ClaudeCodePluginAction.UPDATE,
            policy,
            commands=commands,
        )
    assert modified.value.reason is PluginArtifactReason.DESTINATION_CONFLICT
    assert source_skill.read_text("utf-8") == "modified\n"


def test_stale_enable_preview_and_lost_cli_outcome_fail_closed(tmp_path: Path) -> None:
    target = _target(tmp_path)
    artifact = render_claude_code_plugin()
    commands = _ClaudeFixture(artifact)
    review = _Review()
    install = preview_claude_code_plugin(
        _REQUEST, target, ClaudeCodePluginAction.INSTALL, artifact, commands=commands
    )
    apply_claude_code_plugin(
        _REQUEST,
        target,
        ClaudeCodePluginAction.INSTALL,
        artifact,
        accepted_preview_digest=install.preview_digest,
        authority=_authority(install.preview_digest),
        review=review,
        commands=commands,
    )
    enable_request = request_id("req_10000000-0000-4000-8000-000000000032")
    enable = preview_claude_code_plugin(
        enable_request,
        target,
        ClaudeCodePluginAction.ENABLE,
        artifact,
        commands=commands,
    )
    commands.enabled = True
    commands.settings(target, True)
    with pytest.raises(ClaudeCodeIntegrationError) as stale:
        apply_claude_code_plugin(
            enable_request,
            target,
            ClaudeCodePluginAction.ENABLE,
            artifact,
            accepted_preview_digest=enable.preview_digest,
            authority=_authority(enable.preview_digest),
            review=review,
            commands=commands,
        )
    assert stale.value.reason is PluginArtifactReason.PREVIEW_STALE

    commands.enabled = False
    commands.settings(target, True)
    retry_request = request_id("req_10000000-0000-4000-8000-000000000033")
    retry = preview_claude_code_plugin(
        retry_request,
        target,
        ClaudeCodePluginAction.ENABLE,
        artifact,
        commands=commands,
    )
    original_run = commands.run

    def fail_enable(
        target_value: ClaudeCodePluginTarget, arguments: Sequence[str]
    ) -> ClaudeCodeCommandResult:
        if tuple(arguments)[:2] == ("plugin", "enable"):
            return ClaudeCodeCommandResult(1, b"", b"lost")
        return original_run(target_value, arguments)

    commands.run = fail_enable  # type: ignore[method-assign]
    outcome = apply_claude_code_plugin(
        retry_request,
        target,
        ClaudeCodePluginAction.ENABLE,
        artifact,
        accepted_preview_digest=retry.preview_digest,
        authority=_authority(retry.preview_digest),
        review=review,
        commands=commands,
    )
    assert outcome.operation_state is PluginOperationState.OUTCOME_UNKNOWN
    assert outcome.enabled is False


def test_mcp_sources_preserve_precedence_and_report_dual_foreign_and_ambiguous(
    tmp_path: Path,
) -> None:
    plugin = tmp_path / "plugin"
    project = tmp_path / "project"
    config = tmp_path / "config"
    plugin.mkdir()
    project.mkdir()
    config.mkdir()
    exact = {
        "mcpServers": {
            "yoetz": {
                "args": ["mcp", "serve"],
                "command": "yoetz",
                "type": "stdio",
            }
        }
    }
    (plugin / ".mcp.json").write_text(json.dumps(exact), encoding="utf-8")
    plugin_only = observe_claude_code_mcp(
        plugin_root=plugin,
        project_root=project,
        claude_config_root=config,
    )
    assert plugin_only.ownership_state is McpOwnershipState.PLUGIN
    assert plugin_only.host_admission_supported is True

    (project / ".mcp.json").write_text(json.dumps(exact), encoding="utf-8")
    dual = observe_claude_code_mcp(
        plugin_root=plugin,
        project_root=project,
        claude_config_root=config,
    )
    assert dual.ownership_state is McpOwnershipState.DUAL
    assert dual.winning_source is ClaudeCodeMcpSource.PROJECT
    assert dual.route_profile is None
    assert dual.host_admission_supported is False

    foreign = JsonObject({"args": ["-c", "foreign"], "command": "sh", "type": "stdio"})
    observed = observe_claude_code_mcp(
        plugin_root=plugin,
        project_root=project,
        claude_config_root=config,
        connector_entry=foreign,
    )
    assert observed.ownership_state is McpOwnershipState.FOREIGN

    (config / ".claude.json").write_text("not json", encoding="utf-8")
    ambiguous = observe_claude_code_mcp(
        plugin_root=plugin,
        project_root=project,
        claude_config_root=config,
    )
    assert ambiguous.ownership_state is McpOwnershipState.AMBIGUOUS
    assert ambiguous.observed is False


def test_mcp_ownership_detects_an_exact_yoetz_route_under_an_alias(tmp_path: Path) -> None:
    plugin = tmp_path / "plugin"
    project = tmp_path / "project"
    config = tmp_path / "config"
    plugin.mkdir()
    project.mkdir()
    config.mkdir()
    (project / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "team-ledger": {
                        "args": ["mcp", "serve", "--semantic", "off"],
                        "command": "yoetz",
                        "type": "stdio",
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    observed = observe_claude_code_mcp(
        plugin_root=plugin,
        project_root=project,
        claude_config_root=config,
    )

    assert observed.ownership_state is McpOwnershipState.EXTERNAL
    assert observed.winning_source is ClaudeCodeMcpSource.PROJECT
    assert observed.route_profile == "strict"
    assert observed.host_admission_supported is False


def test_exact_yoetz_strict_route_stays_admission_supported(tmp_path: Path) -> None:
    """Name-mappability is independent of profile: grant still refuses `route_not_policy`."""

    plugin = tmp_path / "plugin"
    project = tmp_path / "project"
    config = tmp_path / "config"
    plugin.mkdir()
    project.mkdir()
    config.mkdir()
    (project / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "yoetz": {
                        "args": ["mcp", "serve", "--semantic", "off"],
                        "command": "yoetz",
                        "type": "stdio",
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    observed = observe_claude_code_mcp(
        plugin_root=plugin,
        project_root=project,
        claude_config_root=config,
    )

    assert observed.ownership_state is McpOwnershipState.EXTERNAL
    assert observed.route_profile == "strict"
    assert observed.host_admission_supported is True


def test_recovery_material_surfaces_in_status_and_refuses_preview(tmp_path: Path) -> None:
    from yoetz.adapters.integrations import claude_code_integration as module

    target = _target(tmp_path)
    artifact = render_claude_code_plugin()
    commands = _ClaudeFixture(artifact)
    parent = Path(target.marketplace_root).parent
    rollback = parent / module._ROLLBACK_NAME  # pyright: ignore[reportPrivateUsage]
    rollback.mkdir(parents=True)

    status = status_claude_code_plugin(target, artifact, commands=commands)
    assert status.state is PluginArtifactState.RECOVERY_REQUIRED
    assert status.operation_state is PluginOperationState.OUTCOME_UNKNOWN
    with pytest.raises(ClaudeCodeIntegrationError) as refused:
        preview_claude_code_plugin(
            _REQUEST, target, ClaudeCodePluginAction.INSTALL, artifact, commands=commands
        )
    assert refused.value.reason is PluginArtifactReason.RECOVERY_REQUIRED

    rollback.rmdir()
    stage = parent / f"{module._STAGE_PREFIX}abandoned"  # pyright: ignore[reportPrivateUsage]
    stage.mkdir()
    staged = status_claude_code_plugin(target, artifact, commands=commands)
    assert staged.state is PluginArtifactState.RECOVERY_REQUIRED
    assert staged.operation_state is PluginOperationState.OUTCOME_UNKNOWN


def test_destructive_paths_revalidate_the_displaced_tree_before_deleting(
    tmp_path: Path,
) -> None:
    from yoetz.adapters.integrations import claude_code_integration as module

    target = _target(tmp_path)
    artifact = render_claude_code_plugin()
    root = Path(target.marketplace_root)
    root.mkdir(parents=True)
    victim = root / "user-notes.txt"
    victim.write_text("irreplaceable", encoding="utf-8")

    with pytest.raises(ClaudeCodeIntegrationError) as removal:
        module._remove_source(target)  # pyright: ignore[reportPrivateUsage]
    assert removal.value.reason is PluginArtifactReason.DESTINATION_CONFLICT
    assert victim.read_text(encoding="utf-8") == "irreplaceable"
    assert not (root.parent / module._ROLLBACK_NAME).exists()  # pyright: ignore[reportPrivateUsage]

    with pytest.raises(ClaudeCodeIntegrationError) as replacement:
        module._write_source(target, artifact, _REQUEST)  # pyright: ignore[reportPrivateUsage]
    assert replacement.value.reason is PluginArtifactReason.DESTINATION_CONFLICT
    assert victim.read_text(encoding="utf-8") == "irreplaceable"
    assert not (root.parent / module._ROLLBACK_NAME).exists()  # pyright: ignore[reportPrivateUsage]
    assert not any(
        item.name.startswith(module._STAGE_PREFIX)  # pyright: ignore[reportPrivateUsage]
        for item in root.parent.iterdir()
    )


def test_completed_host_command_with_missed_readback_is_outcome_unknown(
    tmp_path: Path,
) -> None:
    target = _target(tmp_path)
    artifact = render_claude_code_plugin()

    class _EnableClaimsSuccess(_ClaudeFixture):
        def run(
            self, target: ClaudeCodePluginTarget, arguments: Sequence[str]
        ) -> ClaudeCodeCommandResult:
            args = tuple(arguments)
            if args[:2] == ("plugin", "enable"):
                # The host command exits 0 but the mutation never lands.
                self.calls.append(args)
                return ClaudeCodeCommandResult(0, b"ok", b"")
            return super().run(target, arguments)

    commands = _EnableClaimsSuccess(artifact)
    review = _Review()
    install_preview = preview_claude_code_plugin(
        _REQUEST, target, ClaudeCodePluginAction.INSTALL, artifact, commands=commands
    )
    installed = apply_claude_code_plugin(
        _REQUEST,
        target,
        ClaudeCodePluginAction.INSTALL,
        artifact,
        accepted_preview_digest=install_preview.preview_digest,
        authority=_authority(install_preview.preview_digest),
        review=review,
        commands=commands,
    )
    assert installed.operation_state is PluginOperationState.COMPLETED

    enable_request = request_id("req_10000000-0000-4000-8000-000000000005")
    enable_preview = preview_claude_code_plugin(
        enable_request, target, ClaudeCodePluginAction.ENABLE, artifact, commands=commands
    )
    result = apply_claude_code_plugin(
        enable_request,
        target,
        ClaudeCodePluginAction.ENABLE,
        artifact,
        accepted_preview_digest=enable_preview.preview_digest,
        authority=_authority(enable_preview.preview_digest),
        review=review,
        commands=commands,
    )
    # The mutation already crossed its boundary; an unreached post-mutation
    # state is outcome_unknown, never a safe pre-mutation refusal.
    assert result.operation_state is PluginOperationState.OUTCOME_UNKNOWN
    assert result.enabled is False


# --- compatibility floor admission (#656) -----------------------------------------------------


def test_version_provenance_separates_certification_from_admission() -> None:
    from yoetz.adapters.integrations.claude_code_integration import (
        CLAUDE_CODE_MINIMUM_VERSION,
        claude_code_version_provenance,
    )

    assert CLAUDE_CODE_MINIMUM_VERSION == "2.1.233"
    assert claude_code_version_provenance("2.1.241") == "tested"
    # Neighbours and later releases are admitted but never promoted to a proven cell.
    for version in ("2.1.233", "2.1.240", "2.1.242", "2.2.0", "3.0.0"):
        assert claude_code_version_provenance(version) == "untested", version
    for version in ("2.1.232", "2.1.211", "1.9.9", "2.1", "2.1.241-beta", "", "x"):
        assert claude_code_version_provenance(version) is None, version


def test_compatible_untested_version_is_admitted_with_provenance(tmp_path: Path) -> None:
    """A release above the floor previews and applies; the preview and status carry
    ``untested`` provenance instead of an unearned proven cell. Below the floor stays refused."""

    target = _target(tmp_path)
    artifact = render_claude_code_plugin()
    commands = _ClaudeFixture(artifact)

    def _with_version(version: str) -> ClaudeCodePluginTarget:
        return ClaudeCodePluginTarget(
            target.project_root,
            target.claude_config_root,
            target.cache_root,
            target.marketplace_root,
            target.executable,
            ClaudeCodeCapabilityIdentity(
                version, target.identity.executable_digest, "darwin", "arm64"
            ),
        )

    tested = preview_claude_code_plugin(
        _REQUEST, target, ClaudeCodePluginAction.INSTALL, artifact, commands=commands
    )
    assert tested.version_provenance == "tested"
    assert (
        status_claude_code_plugin(target, artifact, commands=commands).version_provenance
        == "tested"
    )

    newer = _with_version("2.1.250")
    untested = preview_claude_code_plugin(
        _REQUEST, newer, ClaudeCodePluginAction.INSTALL, artifact, commands=commands
    )
    assert untested.version_provenance == "untested"
    assert untested.action is ClaudeCodePluginAction.INSTALL
    assert (
        status_claude_code_plugin(newer, artifact, commands=commands).version_provenance
        == "untested"
    )
    # Provenance is not a second admission gate: the digest is bound to the exact host version.
    assert untested.preview_digest != tested.preview_digest

    below = _with_version("2.1.232")
    with pytest.raises(ClaudeCodeIntegrationError) as refused:
        preview_claude_code_plugin(
            _REQUEST, below, ClaudeCodePluginAction.INSTALL, artifact, commands=commands
        )
    assert refused.value.reason is PluginArtifactReason.FORMAT_UNSUPPORTED
    assert refused.value.safe_details == {
        "minimum_version": "2.1.233",
        "version_unsupported": "2.1.232",
    }
    assert status_claude_code_plugin(below, artifact, commands=commands).version_provenance is None


def test_refused_presence_surfaces_as_claude_error_before_any_mutation(tmp_path: Path) -> None:
    interpreter = tmp_path / "bin" / "python3"
    interpreter.parent.mkdir()
    interpreter.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    interpreter.chmod(0o700)
    artifact = render_claude_code_plugin(
        mcp_ownership=McpOwnership.PLUGIN_MANAGED,
        route_profile="policy",
        yoetz_launcher=(str(interpreter), "-m", "yoetz"),
    )
    target = _target(tmp_path)
    commands = _ClaudeFixture(artifact)
    preview = preview_claude_code_plugin(
        _REQUEST, target, ClaudeCodePluginAction.INSTALL, artifact, commands=commands
    )

    class _RefusingReview:
        def consume_setup_authority(
            self, authority: ArtifactAuthority, preview_digest: str
        ) -> None:
            raise AssertionError("setup authority is not the review lane")

        def consume_artifact_review(
            self, authority: ArtifactAuthority, preview_digest: str
        ) -> None:
            raise PluginArtifactError(PluginArtifactReason.HUMAN_AUTHORITY_UNAVAILABLE, {})

    # The shared review port's neutral error must reach the Claude surface as the host error
    # type with the port's reason, never escape the CLI as a traceback.
    with pytest.raises(ClaudeCodeIntegrationError) as caught:
        apply_claude_code_plugin(
            _REQUEST,
            target,
            ClaudeCodePluginAction.INSTALL,
            artifact,
            accepted_preview_digest=preview.preview_digest,
            authority=_authority(preview.preview_digest),
            review=_RefusingReview(),
            commands=commands,
        )
    assert caught.value.reason is PluginArtifactReason.HUMAN_AUTHORITY_UNAVAILABLE
    assert isinstance(caught.value.__cause__, PluginArtifactError)
    # Preview and status only list; no marketplace, install, or enable command may run.
    assert all(call[:2] == ("plugin", "list") for call in commands.calls)
    assert not Path(target.marketplace_root).exists()
