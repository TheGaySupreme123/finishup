from __future__ import annotations

import hashlib
import json
import plistlib
import shlex
import shutil
import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest

from yoetz.adapters.integrations.cursor_integration import (
    CURSOR_HARNESS_PROFILE,
    CURSOR_HOOK_EVENTS,
    CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
    CursorIntegrationError,
    CursorMcpSource,
    CursorPluginTarget,
    CursorSdkBinding,
    apply_cursor_plugin,
    build_cursor_sdk_profile,
    discover_cursor_cli,
    discover_cursor_ide,
    discover_cursor_sdk,
    installed_cursor_startup_mode,
    observe_cursor_mcp,
    preview_cursor_plugin,
    remove_cursor_plugin,
    render_cursor_plugin,
    status_cursor_plugin,
)
from yoetz.domain.values import JsonObject, request_id
from yoetz.ports.plugin_artifacts import (
    ArtifactAuthority,
    McpOwnership,
    McpOwnershipState,
    PluginArtifactAction,
    PluginArtifactReason,
    PluginArtifactState,
    PluginFormatProfile,
    PluginOperationState,
    PluginProofFacet,
)
from yoetz.protocol.canonical import JsonValue, canonical_digest, canonical_encode
from yoetz.protocol.guidance_uris import FOCUSED_GUIDANCE_URIS, GUIDANCE_DOCUMENT_URIS
from yoetz.version import read_verified_resource

_REQUEST = request_id("req_10000000-0000-4000-8000-000000000001")
_REVIEW_ID = "a" * 64
_GUIDANCE_NAMES = tuple(
    uri.removeprefix("yoetz://guidance/")
    for uri in (*GUIDANCE_DOCUMENT_URIS, *FOCUSED_GUIDANCE_URIS)
)


def test_required_startup_install_inspect_and_reverse(tmp_path: Path) -> None:
    launcher = _fake_yoetz(tmp_path / "bin" / "yoetz")
    target = CursorPluginTarget(str(tmp_path / ".cursor"))
    for index, mode in enumerate(("required", "optional")):
        artifact = render_cursor_plugin(
            PluginFormatProfile.CURSOR_PLUGIN_NATIVE,
            yoetz_launcher=launcher,
            startup_mode="required" if mode == "required" else "optional",
        )
        action = PluginArtifactAction.INSTALL if index == 0 else PluginArtifactAction.REPLACE
        preview = preview_cursor_plugin(_REQUEST, target, action, artifact)
        apply_cursor_plugin(
            _REQUEST,
            target,
            action,
            artifact,
            accepted_preview_digest=preview.preview_digest,
            authority=_authority(preview.preview_digest),
            review=_AcceptingReview(),
        )
        assert installed_cursor_startup_mode(target) == mode
        assert status_cursor_plugin(target, artifact).marker_valid


class _AcceptingReview:
    """Stand in for one already-approved single-shot trusted review."""

    def __init__(self) -> None:
        self.artifact_reviews: list[tuple[ArtifactAuthority, str]] = []
        self.setup_authorities: list[tuple[ArtifactAuthority, str]] = []

    def consume_setup_authority(self, authority: ArtifactAuthority, preview_digest: str) -> None:
        self.setup_authorities.append((authority, preview_digest))

    def consume_artifact_review(self, authority: ArtifactAuthority, preview_digest: str) -> None:
        self.artifact_reviews.append((authority, preview_digest))


def _authority(preview_digest: str) -> ArtifactAuthority:
    return ArtifactAuthority("review_only", preview_digest, _REVIEW_ID)


def test_cursor_profile_exposes_only_supported_ide_and_cli_cells() -> None:
    assert CURSOR_HARNESS_PROFILE.harness_id.value == "cursor"
    assert CURSOR_HARNESS_PROFILE.capability_profile_ids == (
        "cursor-cli-2026.07.09-a3815c0",
        "cursor-ide-3.17.8",
    )
    assert CURSOR_HARNESS_PROFILE.supported_versions == (
        "2026.07.09-a3815c0",
        "3.17.8",
    )
    assert not any(
        profile_id.startswith("cursor-sdk-")
        for profile_id in CURSOR_HARNESS_PROFILE.capability_profile_ids
    )
    assert not {"1.0.23", "1.0.24"}.intersection(CURSOR_HARNESS_PROFILE.supported_versions)
    hooks = dict(CURSOR_HARNESS_PROFILE.hooks_by_capability_profile)
    assert hooks["cursor-cli-2026.07.09-a3815c0"] is None
    native_hooks = hooks["cursor-ide-3.17.8"]
    assert native_hooks is not None
    assert native_hooks.observation_events == CURSOR_HOOK_EVENTS
    assert native_hooks.evidence_case_ids == ("cursor-ide-native-3.17.8-macos-arm64",)
    for name in (
        "cursor-cli-portable-2026.07.09.case.json",
        "cursor-ide-native-3.17.8.case.json",
        "cursor-sdk-python-1.0.24.case.json",
        "cursor-sdk-typescript-1.0.23.case.json",
        "cursor-stale-shared-mcp-runtime.case.json",
    ):
        fixture = json.loads(read_verified_resource(f"fixtures/agent-plugins/{name}"))
        assert fixture["schema"].startswith("yoetz.cursor-")
        if name.startswith("cursor-sdk-"):
            assert fixture["proof_limits"] == ["metadata_only", "not_a_support_claim"]


def test_portable_and_native_use_distinct_skill_entries_and_shared_guidance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # This fixture models a legacy ambient install. Keep the process isolated
    # while mocking only the adapter's binding lookup.
    monkeypatch.setattr(
        "yoetz.adapters.integrations.cursor_integration.isolated_root", lambda: None
    )
    executable = tmp_path / "bin" / "yoetz"
    executable.parent.mkdir()
    executable.write_text("#!/bin/sh\nprintf '%s\\n' \"$@\"\n", encoding="utf-8")
    executable.chmod(0o755)

    def find_executable(command: str) -> str | None:
        return str(executable) if command == "yoetz" else None

    monkeypatch.setattr(
        "yoetz.adapters.integrations.cursor_integration.shutil.which", find_executable
    )
    portable = render_cursor_plugin(PluginFormatProfile.AGENT_PLUGINS_1)
    native = render_cursor_plugin(PluginFormatProfile.CURSOR_PLUGIN_NATIVE)

    assert portable.members["skills/yoetz/SKILL.md"] == read_verified_resource(
        "skills/cursor/yoetz/SKILL.md"
    )
    assert native.members["skills/yoetz/SKILL.md"] == read_verified_resource(
        "skills/cursor/yoetz/SKILL.md"
    )
    for name in _GUIDANCE_NAMES:
        assert (
            portable.members[f"skills/yoetz/references/{name}"]
            == native.members[f"skills/yoetz/references/{name}"]
            == read_verified_resource(f"guidance/{name}")
        )
        assert f"guidance/{name}" in portable.plan.source_refs
        assert f"guidance/{name}" in native.plan.source_refs
    assert "plugin.json" in portable.members
    assert "hooks/hooks.json" not in portable.members
    assert ".cursor-plugin/plugin.json" not in portable.members
    assert ".cursor-plugin/plugin.json" in native.members
    assert "plugin.json" not in native.members
    assert "hooks/hooks.json" in native.members
    assert native.plan.host_extension_profile == "cursor-native-3.17"

    manifest = json.loads(native.members[".cursor-plugin/plugin.json"])
    hooks = json.loads(native.members["hooks/hooks.json"])
    assert manifest["hooks"] == "hooks/hooks.json"
    assert tuple(sorted(hooks["hooks"])) == CURSOR_HOOK_EVENTS
    assert "afterAgentThought" not in hooks["hooks"]
    resolved = str(executable.resolve())
    assert native.yoetz_launcher == (resolved,)
    assert all(
        definition[-1]["command"].startswith(f"{shlex.quote(resolved)} hooks cursor-observe ")
        for definition in hooks["hooks"].values()
    )
    assert {event: definition[-1]["timeout"] for event, definition in hooks["hooks"].items()} == {
        "afterFileEdit": 5,
        "afterMCPExecution": 5,
        "sessionEnd": 3,
        "sessionStart": 10,
        "stop": 10,
    }
    command = hooks["hooks"]["sessionStart"][-1]["command"]
    completed = subprocess.run(
        shlex.split(command),
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    assert completed.returncode == 0
    assert completed.stdout.splitlines() == [
        "hooks",
        "cursor-observe",
        "--workspace",
        ".",
        "--event",
        "sessionStart",
    ]


def test_plugin_managed_native_route_is_exact_and_external_omits_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The scripted route is the pre-isolation ambient form.
    monkeypatch.setattr(
        "yoetz.adapters.integrations.cursor_integration.isolated_root", lambda: None
    )
    external = render_cursor_plugin(PluginFormatProfile.CURSOR_PLUGIN_NATIVE)
    managed = render_cursor_plugin(
        PluginFormatProfile.CURSOR_PLUGIN_NATIVE,
        mcp_ownership=McpOwnership.PLUGIN_MANAGED,
        route_profile="strict",
    )

    assert "mcp.json" not in external.members
    assert managed.yoetz_launcher is not None
    launcher = managed.yoetz_launcher
    # Issue #468: the plugin-owned entry names the exact launcher the hooks use, never a bare
    # ``yoetz`` that Cursor's sanitized desktop PATH may resolve to another installation.
    route = json.loads(managed.members["mcp.json"])["mcpServers"]["yoetz"]
    assert route == {
        "args": [*launcher[1:], "mcp", "serve", "--host", "cursor", "--semantic", "off"],
        "command": launcher[0],
        "type": "stdio",
    }
    assert Path(launcher[0]).is_absolute()
    hooks = json.loads(managed.members["hooks/hooks.json"])
    assert all(
        definition[-1]["command"].startswith(f"{shlex.quote(launcher[0])} ")
        for definition in hooks["hooks"].values()
    )

    policy = render_cursor_plugin(
        PluginFormatProfile.CURSOR_PLUGIN_NATIVE,
        mcp_ownership=McpOwnership.PLUGIN_MANAGED,
        route_profile="policy",
    )
    assert json.loads(policy.members["mcp.json"])["mcpServers"]["yoetz"] == {
        "args": [*launcher[1:], "mcp", "serve", "--host", "cursor"],
        "command": launcher[0],
        "type": "stdio",
    }


def test_isolated_native_artifact_binds_root_in_mcp_and_hook_commands(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    isolated_root = tmp_path / "isolated root with 'quotes'"
    executable = _fake_yoetz(tmp_path / "runtime" / "yoetz")
    executable.write_text("#!/bin/sh\nprintf '%s' \"$YOETZ_ISOLATED_ROOT\"\n", encoding="utf-8")
    executable.chmod(0o755)
    monkeypatch.setattr(
        "yoetz.adapters.integrations.cursor_integration.isolated_root",
        lambda: isolated_root,
    )

    artifact = render_cursor_plugin(
        PluginFormatProfile.CURSOR_PLUGIN_NATIVE,
        mcp_ownership=McpOwnership.PLUGIN_MANAGED,
        route_profile="policy",
        yoetz_launcher=executable,
    )

    assert artifact.isolation_root == str(isolated_root)
    route = json.loads(artifact.members["mcp.json"])["mcpServers"]["yoetz"]
    assert route["env"] == {"YOETZ_ISOLATED_ROOT": str(isolated_root)}
    assert set(route) == {"args", "command", "env", "type"}

    hooks = json.loads(artifact.members["hooks/hooks.json"])["hooks"]
    for definition in hooks.values():
        command = definition[-1]["command"]
        assert command.startswith(f"YOETZ_ISOLATED_ROOT={shlex.quote(str(isolated_root))} ")
        # Cursor executes command hooks as shell strings.  This also proves a path containing
        # spaces and a quote cannot escape the assignment.
        completed = subprocess.run(
            ["/bin/sh", "-c", command],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        assert completed.returncode == 0
        assert completed.stderr == ""
        assert completed.stdout == str(isolated_root)


def test_isolated_root_route_recognition_is_closed_and_drift_readable(tmp_path: Path) -> None:
    from yoetz.adapters.integrations.cursor_integration import (
        _route_profile,  # pyright: ignore[reportPrivateUsage]
    )

    launcher = (str(tmp_path / "bin" / "yoetz"),)
    serve = ["mcp", "serve", "--host", "cursor"]
    isolated = str(tmp_path / "isolated")
    exact = _entry(
        launcher[0],
        serve,
        env={"YOETZ_ISOLATED_ROOT": isolated},  # type: ignore[arg-type]
    )
    assert _route_profile(exact, (launcher,)) == "policy"
    assert _route_profile(exact, (launcher,), expected_isolation_root=isolated) == "policy"

    # Route shape remains classifiable without an expected binding, but the lifecycle ownership
    # check rejects a different root. Arbitrary, malformed, and empty environments remain foreign.
    different = _entry(
        launcher[0],
        serve,
        env={"YOETZ_ISOLATED_ROOT": str(tmp_path / "other")},  # type: ignore[arg-type]
    )
    assert _route_profile(different, (launcher,)) == "policy"
    assert _route_profile(different, (launcher,), expected_isolation_root=isolated) is None
    assert (
        _route_profile(
            _entry(launcher[0], serve, env={"YOETZ_TOKEN": "secret"}),  # type: ignore[arg-type]
            (launcher,),
        )
        is None
    )
    assert (
        _route_profile(
            _entry(launcher[0], serve, env={"YOETZ_ISOLATED_ROOT": "relative"}),  # type: ignore[arg-type]
            (launcher,),
        )
        is None
    )
    assert (
        _route_profile(
            _entry(launcher[0], serve, env={}),  # type: ignore[arg-type]
            (launcher,),
        )
        is None
    )


def _no_path_lookup(_name: str) -> str | None:
    return None


def _entry(command: str, args: list[str], **extra: str) -> Mapping[str, JsonValue]:
    return cast(
        Mapping[str, JsonValue],
        {"args": list(args), "command": command, "type": "stdio", **extra},
    )


def _fake_yoetz(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def test_plugin_mcp_ignores_sanitized_path_and_foreign_older_yoetz(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Negative controls for issue #468: PATH must not choose the MCP runtime."""

    # The fixture asserts the legacy ambient route shape; only the adapter
    # lookup is mocked so YOETZ_ISOLATED_ROOT remains set for the test process.
    monkeypatch.setattr(
        "yoetz.adapters.integrations.cursor_integration.isolated_root", lambda: None
    )

    invoking = _fake_yoetz(tmp_path / "current" / "bin" / "yoetz")
    older = _fake_yoetz(tmp_path / "older-channel" / "bin" / "yoetz")

    # A sanitized desktop PATH that cannot find any ``yoetz``.
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    monkeypatch.setattr(
        "yoetz.adapters.integrations.cursor_integration.shutil.which", _no_path_lookup
    )
    sanitized = render_cursor_plugin(
        PluginFormatProfile.CURSOR_PLUGIN_NATIVE,
        mcp_ownership=McpOwnership.PLUGIN_MANAGED,
        route_profile="policy",
        yoetz_launcher=invoking,
    )
    entry = json.loads(sanitized.members["mcp.json"])["mcpServers"]["yoetz"]
    assert entry["command"] == str(invoking.resolve())
    assert entry["args"] == ["mcp", "serve", "--host", "cursor"]

    # A foreign, older ``yoetz`` earlier on PATH than the invoking installation.
    monkeypatch.setenv("PATH", f"{older.parent}:{invoking.parent}")

    def find_older(_name: str) -> str | None:
        return str(older)

    monkeypatch.setattr("yoetz.adapters.integrations.cursor_integration.shutil.which", find_older)
    shadowed = render_cursor_plugin(
        PluginFormatProfile.CURSOR_PLUGIN_NATIVE,
        mcp_ownership=McpOwnership.PLUGIN_MANAGED,
        route_profile="policy",
        yoetz_launcher=invoking,
    )
    entry = json.loads(shadowed.members["mcp.json"])["mcpServers"]["yoetz"]
    assert entry["command"] == str(invoking.resolve())
    assert str(older) not in json.dumps(json.loads(shadowed.members["mcp.json"]))
    hooks = json.loads(shadowed.members["hooks/hooks.json"])
    assert all(
        definition[-1]["command"].startswith(f"{shlex.quote(str(invoking.resolve()))} ")
        for definition in hooks["hooks"].values()
    )
    # Hooks and MCP bind the same launcher by construction.
    assert shadowed.yoetz_launcher == (str(invoking.resolve()),)


def test_module_entrypoint_launcher_binds_plugin_mcp_arguments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "yoetz.adapters.integrations.cursor_integration.isolated_root", lambda: None
    )
    interpreter = _fake_yoetz(tmp_path / "venv" / "bin" / "python")

    def refuse_path_lookup(_name: str) -> str | None:
        pytest.fail("module entrypoint launcher must not consult PATH")

    monkeypatch.setattr(
        "yoetz.adapters.integrations.cursor_integration.shutil.which", refuse_path_lookup
    )
    artifact = render_cursor_plugin(
        PluginFormatProfile.CURSOR_PLUGIN_NATIVE,
        mcp_ownership=McpOwnership.PLUGIN_MANAGED,
        route_profile="strict",
        yoetz_launcher=(str(interpreter), "-m", "yoetz"),
    )
    entry = json.loads(artifact.members["mcp.json"])["mcpServers"]["yoetz"]
    assert entry == {
        "args": ["-m", "yoetz", "mcp", "serve", "--host", "cursor", "--semantic", "off"],
        "command": str(interpreter.resolve()),
        "type": "stdio",
    }


def test_mcp_route_recognition_accepts_bare_and_exact_launchers_only(tmp_path: Path) -> None:
    from yoetz.adapters.integrations.cursor_integration import (
        _route_profile,  # pyright: ignore[reportPrivateUsage]
    )

    console = (str(tmp_path / "current" / "bin" / "yoetz"),)
    module = (str(tmp_path / "venv" / "bin" / "python"), "-m", "yoetz")
    launchers = (console, module)
    serve = ["mcp", "serve", "--host", "cursor"]

    assert _route_profile(_entry("yoetz", serve)) == "policy"
    assert _route_profile(_entry(console[0], serve), launchers) == "policy"
    assert (
        _route_profile(_entry(module[0], ["-m", "yoetz", *serve, "--semantic", "off"]), launchers)
        == "strict"
    )
    # Unknown launcher, missing module arguments, wrong prefix order, or extra keys stay foreign.
    assert _route_profile(_entry(console[0], serve)) is None
    assert _route_profile(_entry(str(tmp_path / "other" / "yoetz"), serve), launchers) is None
    assert _route_profile(_entry(module[0], serve), launchers) is None
    assert _route_profile(_entry(console[0], serve, cwd="/x"), launchers) is None


def _install_native(
    tmp_path: Path, artifact: object, request: object = _REQUEST
) -> CursorPluginTarget:
    from yoetz.adapters.integrations.cursor_integration import CursorPluginArtifact

    assert isinstance(artifact, CursorPluginArtifact)
    target = CursorPluginTarget(str(tmp_path / ".cursor"))
    preview = preview_cursor_plugin(
        request,  # type: ignore[arg-type]
        target,
        PluginArtifactAction.INSTALL,
        artifact,
    )
    apply_cursor_plugin(
        request,  # type: ignore[arg-type]
        target,
        PluginArtifactAction.INSTALL,
        artifact,
        accepted_preview_digest=preview.preview_digest,
        authority=_authority(preview.preview_digest),
        review=_AcceptingReview(),
    )
    return target


def test_status_verifies_launcher_binding_identity_and_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Issue #468: status reports executable drift, missing launchers, and MCP binding."""

    from yoetz.adapters.integrations.launcher_probe import FixedLauncherProbe
    from yoetz.version import build_version_manifest

    monkeypatch.setattr(
        "yoetz.adapters.integrations.cursor_integration.shutil.which", _no_path_lookup
    )
    current = _fake_yoetz(tmp_path / "current" / "bin" / "yoetz")
    artifact = render_cursor_plugin(
        PluginFormatProfile.CURSOR_PLUGIN_NATIVE,
        mcp_ownership=McpOwnership.PLUGIN_MANAGED,
        route_profile="policy",
        yoetz_launcher=current,
    )
    target = _install_native(tmp_path, artifact)
    own = build_version_manifest()
    same_identity = cast(
        Mapping[str, JsonValue],
        {
            "package_version": own.package_version,
            "request_result_schema_versions": dict(own.request_result_schema_versions),
            "resource_manifest_digest": own.resource_manifest_digest,
        },
    )

    status = status_cursor_plugin(
        target, artifact, launcher_probe=FixedLauncherProbe(same_identity)
    )
    assert status.state is PluginArtifactState.NATIVE_MANAGED
    assert status.mcp_observation.ownership_state is McpOwnershipState.PLUGIN
    assert status.mcp_observation.route_profile == "policy"
    assert status.launcher.executable == "matched"
    assert status.launcher.mcp_binding == "exact_launcher"
    assert status.launcher.installed_launcher == artifact.yoetz_launcher
    assert status.launcher.identity.observed is True
    assert status.launcher.identity.matched is True

    # The installed plugin binds another channel than the runtime reading status.
    older = _fake_yoetz(tmp_path / "older" / "bin" / "yoetz")
    older_runtime = render_cursor_plugin(
        PluginFormatProfile.CURSOR_PLUGIN_NATIVE,
        mcp_ownership=McpOwnership.PLUGIN_MANAGED,
        route_profile="policy",
        yoetz_launcher=older,
    )
    other_identity = cast(Mapping[str, JsonValue], {**same_identity, "package_version": "0.0.9"})
    drift = status_cursor_plugin(
        target, older_runtime, launcher_probe=FixedLauncherProbe(other_identity)
    )
    # An installed tree bound to another installation is managed-but-modified against the
    # desired artifact of the runtime reading status; the marker itself stays valid.
    assert drift.state is PluginArtifactState.MODIFIED
    assert drift.marker_valid is True
    assert drift.installed_digest != older_runtime.artifact_digest
    assert drift.mcp_observation.ownership_state is McpOwnershipState.PLUGIN
    assert drift.launcher.executable == "drifted"
    assert drift.launcher.installed_launcher == artifact.yoetz_launcher
    assert drift.launcher.artifact_launcher == older_runtime.yoetz_launcher
    assert drift.launcher.identity.matched is False
    assert drift.launcher.identity.package_version == "0.0.9"

    # A probe that cannot answer never invents identity.
    unprobed = status_cursor_plugin(target, artifact, launcher_probe=FixedLauncherProbe(None))
    assert unprobed.launcher.identity.observed is False
    assert unprobed.launcher.identity.matched is None

    # The bound executable disappears: the marker is still exact, the launcher is missing.
    current.unlink()
    missing = status_cursor_plugin(
        target, artifact, launcher_probe=FixedLauncherProbe(same_identity)
    )
    assert missing.launcher.executable == "missing"
    assert missing.launcher.identity.observed is False


def test_status_reports_legacy_bare_plugin_mcp_as_ambient_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A marker-valid tree rendered before #468 still launches whatever PATH resolves."""

    monkeypatch.setattr(
        "yoetz.adapters.integrations.cursor_integration.isolated_root", lambda: None
    )

    from yoetz.adapters.integrations.launcher_probe import FixedLauncherProbe

    monkeypatch.setattr(
        "yoetz.adapters.integrations.cursor_integration.shutil.which", _no_path_lookup
    )
    current = _fake_yoetz(tmp_path / "current" / "bin" / "yoetz")
    artifact = render_cursor_plugin(
        PluginFormatProfile.CURSOR_PLUGIN_NATIVE,
        mcp_ownership=McpOwnership.PLUGIN_MANAGED,
        route_profile="policy",
        yoetz_launcher=current,
    )
    target = _install_native(tmp_path, artifact)
    destination = tmp_path / ".cursor" / "plugins" / "local" / "yoetz"
    legacy_entry = canonical_encode(
        {
            "mcpServers": {
                "yoetz": {
                    "args": ["mcp", "serve", "--host", "cursor"],
                    "command": "yoetz",
                    "type": "stdio",
                }
            }
        }
    )
    (destination / "mcp.json").write_bytes(legacy_entry)
    marker_path = destination / ".yoetz-cursor-plugin-install.json"
    marker = json.loads(marker_path.read_bytes())
    for row in marker["managed_files"]:
        if row["relative_path"] == "mcp.json":
            row["size"] = len(legacy_entry)
            row["sha256"] = f"sha256:{hashlib.sha256(legacy_entry).hexdigest()}"
    body = {key: value for key, value in marker.items() if key != "marker_digest"}
    marker["marker_digest"] = canonical_digest(body)
    marker_path.write_bytes(canonical_encode(marker))

    status = status_cursor_plugin(target, artifact, launcher_probe=FixedLauncherProbe(None))
    assert status.marker_valid is True
    assert status.state is PluginArtifactState.MODIFIED
    assert status.installed_digest == artifact.artifact_digest
    assert status.mcp_observation.ownership_state is McpOwnershipState.PLUGIN
    assert status.launcher.executable == "matched"
    assert status.launcher.mcp_binding == "ambient_path"


def test_native_render_fails_closed_when_yoetz_console_is_not_discoverable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def find_executable(_name: str) -> str | None:
        return None

    monkeypatch.setattr(
        "yoetz.adapters.integrations.cursor_integration.shutil.which", find_executable
    )
    with pytest.raises(ValueError, match="^yoetz_executable_unavailable$"):
        render_cursor_plugin(PluginFormatProfile.CURSOR_PLUGIN_NATIVE)


def test_native_render_prefers_explicit_invoking_executable_over_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "yoetz.adapters.integrations.cursor_integration.isolated_root", lambda: None
    )
    invoking = tmp_path / "invoking" / "yoetz"
    invoking.parent.mkdir()
    invoking.write_text("#!/bin/sh\n", encoding="utf-8")
    invoking.chmod(0o755)
    ambient = tmp_path / "ambient" / "yoetz"
    ambient.parent.mkdir()
    ambient.write_text("#!/bin/sh\n", encoding="utf-8")
    ambient.chmod(0o755)

    def find_ambient(_name: str) -> str | None:
        return str(ambient)

    monkeypatch.setattr(
        "yoetz.adapters.integrations.cursor_integration.shutil.which",
        find_ambient,
    )

    artifact = render_cursor_plugin(
        PluginFormatProfile.CURSOR_PLUGIN_NATIVE,
        yoetz_launcher=invoking,
    )

    resolved = str(invoking.resolve())
    assert artifact.yoetz_launcher == (resolved,)
    hooks = json.loads(artifact.members["hooks/hooks.json"])
    assert all(
        definition[-1]["command"].startswith(f"{shlex.quote(resolved)} hooks cursor-observe ")
        for definition in hooks["hooks"].values()
    )


def test_native_render_preserves_module_entrypoint_launcher(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "yoetz.adapters.integrations.cursor_integration.isolated_root", lambda: None
    )
    interpreter = tmp_path / "venv" / "bin" / "python"
    interpreter.parent.mkdir(parents=True)
    interpreter.write_text("#!/bin/sh\n", encoding="utf-8")
    interpreter.chmod(0o755)

    def refuse_path_lookup(_name: str) -> str | None:
        raise AssertionError("module entrypoint launcher must not consult PATH")

    monkeypatch.setattr(
        "yoetz.adapters.integrations.cursor_integration.shutil.which",
        refuse_path_lookup,
    )

    artifact = render_cursor_plugin(
        PluginFormatProfile.CURSOR_PLUGIN_NATIVE,
        yoetz_launcher=(str(interpreter), "-m", "yoetz"),
    )

    resolved = str(interpreter.resolve())
    assert artifact.yoetz_launcher == (resolved, "-m", "yoetz")
    hooks = json.loads(artifact.members["hooks/hooks.json"])
    prefix = f"{shlex.quote(resolved)} -m yoetz hooks cursor-observe "
    assert all(
        definition[-1]["command"].startswith(prefix) for definition in hooks["hooks"].values()
    )


@pytest.mark.parametrize(
    ("candidate", "relative_target"),
    [
        ("./yoetz", "work/yoetz"),
        ("bin/yoetz", "work/bin/yoetz"),
        ("../bin/yoetz", "bin/yoetz"),
        (Path("yoetz"), "work/yoetz"),
    ],
)
def test_native_render_preserves_explicit_relative_executable_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    candidate: str | Path,
    relative_target: str,
) -> None:
    work = tmp_path / "work"
    work.mkdir()
    invoking = tmp_path / relative_target
    invoking.parent.mkdir(parents=True, exist_ok=True)
    invoking.write_text("#!/bin/sh\n", encoding="utf-8")
    invoking.chmod(0o755)
    monkeypatch.chdir(work)

    def refuse_path_lookup(_name: str) -> str | None:
        raise AssertionError("explicit executable path must not consult PATH")

    monkeypatch.setattr(
        "yoetz.adapters.integrations.cursor_integration.shutil.which",
        refuse_path_lookup,
    )

    artifact = render_cursor_plugin(
        PluginFormatProfile.CURSOR_PLUGIN_NATIVE,
        yoetz_launcher=candidate,
    )

    assert artifact.yoetz_launcher == (str(invoking.resolve()),)


def test_portable_render_never_resolves_a_host_executable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def refuse_path_lookup(_name: str) -> str | None:
        raise AssertionError("portable rendering must stay host-resolver-free")

    monkeypatch.setattr(
        "yoetz.adapters.integrations.cursor_integration.shutil.which",
        refuse_path_lookup,
    )

    artifact = render_cursor_plugin(
        PluginFormatProfile.AGENT_PLUGINS_1,
        yoetz_launcher="./yoetz",
    )

    assert artifact.yoetz_launcher is None


def test_safe_cursor_lifecycle_is_preview_bound_atomic_and_reversible(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "yoetz.adapters.integrations.cursor_integration.isolated_root", lambda: None
    )
    target = CursorPluginTarget(str(tmp_path / ".cursor"))
    artifact = render_cursor_plugin(PluginFormatProfile.CURSOR_PLUGIN_NATIVE)

    preview = preview_cursor_plugin(
        _REQUEST,
        target,
        PluginArtifactAction.INSTALL,
        artifact,
    )
    assert preview.state_before is PluginArtifactState.ABSENT
    result = apply_cursor_plugin(
        _REQUEST,
        target,
        PluginArtifactAction.INSTALL,
        artifact,
        accepted_preview_digest=preview.preview_digest,
        authority=_authority(preview.preview_digest),
        review=_AcceptingReview(),
    )
    assert result.state_after is PluginArtifactState.NATIVE_MANAGED
    marker = json.loads(
        (
            tmp_path
            / ".cursor"
            / "plugins"
            / "local"
            / "yoetz"
            / ".yoetz-cursor-plugin-install.json"
        ).read_text(encoding="utf-8")
    )
    assert artifact.yoetz_launcher is not None
    assert marker["yoetz_launcher"] == list(artifact.yoetz_launcher)
    assert marker["schema"] == "yoetz.cursor-plugin-install/3"
    assert marker["isolation_root"] is None
    assert marker["renderer_version"] == "cursor-plugin/0.3.0"

    status = status_cursor_plugin(target, artifact)
    assert status.state is PluginArtifactState.NATIVE_MANAGED
    assert status.marker_valid is True
    assert status.installed_digest == artifact.artifact_digest
    proof = {item.facet: item.status for item in status.proof}
    assert proof[PluginProofFacet.INSTALLED_BYTES] == "proven"
    assert proof[PluginProofFacet.HOST_ACTIVATION] == "not_observed"

    remove_preview = preview_cursor_plugin(
        request_id("req_10000000-0000-4000-8000-000000000002"),
        target,
        PluginArtifactAction.REMOVE,
        artifact,
    )
    removed = remove_cursor_plugin(
        remove_preview.request_id,
        target,
        artifact,
        accepted_preview_digest=remove_preview.preview_digest,
        authority=_authority(remove_preview.preview_digest),
        review=_AcceptingReview(),
    )
    assert removed.state_after is PluginArtifactState.ABSENT
    assert not (tmp_path / ".cursor" / "plugins" / "local" / "yoetz").exists()
    assert status_cursor_plugin(target, artifact).operation_state.value == "not_started"


def test_isolation_binding_reports_drift_and_unset_reverts_to_ambient(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first_root = tmp_path / "isolated-one"
    second_root = tmp_path / "isolated-two"
    executable = _fake_yoetz(tmp_path / "runtime" / "yoetz")

    monkeypatch.setattr(
        "yoetz.adapters.integrations.cursor_integration.isolated_root",
        lambda: first_root,
    )
    first = render_cursor_plugin(
        PluginFormatProfile.CURSOR_PLUGIN_NATIVE,
        mcp_ownership=McpOwnership.PLUGIN_MANAGED,
        route_profile="policy",
        yoetz_launcher=executable,
    )
    target = _install_native(tmp_path, first)
    installed = status_cursor_plugin(target, first)
    assert installed.state is PluginArtifactState.NATIVE_MANAGED
    assert installed.isolation_binding == "isolated_exact"

    # A managed tree whose route is changed to another valid root is modified, and the foreign
    # route cannot be admitted as the current artifact's owned MCP route.
    route_path = tmp_path / ".cursor" / "plugins" / "local" / "yoetz" / "mcp.json"
    route = json.loads(route_path.read_bytes())
    route["mcpServers"]["yoetz"]["env"]["YOETZ_ISOLATED_ROOT"] = str(second_root)
    route_path.write_text(json.dumps(route), encoding="utf-8")
    route_drift = status_cursor_plugin(target, first)
    assert route_drift.state is PluginArtifactState.MODIFIED
    assert route_drift.marker_valid is False
    assert route_drift.isolation_binding == "unobserved"
    assert route_drift.mcp_observation.ownership_state is McpOwnershipState.FOREIGN
    assert route_drift.launcher.mcp_binding == "unobserved"
    with pytest.raises(CursorIntegrationError) as route_conflict:
        preview_cursor_plugin(
            request_id("req_10000000-0000-4000-8000-000000000026"),
            target,
            PluginArtifactAction.REPLACE,
            first,
        )
    assert route_conflict.value.reason is PluginArtifactReason.DESTINATION_CONFLICT
    route_path.write_bytes(first.members["mcp.json"])

    monkeypatch.setattr(
        "yoetz.adapters.integrations.cursor_integration.isolated_root",
        lambda: second_root,
    )
    second = render_cursor_plugin(
        PluginFormatProfile.CURSOR_PLUGIN_NATIVE,
        mcp_ownership=McpOwnership.PLUGIN_MANAGED,
        route_profile="policy",
        yoetz_launcher=executable,
    )
    project = tmp_path / "project"
    (project / ".cursor").mkdir(parents=True)
    (project / ".cursor" / "mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "yoetz": {
                        "args": ["foreign"],
                        "command": "other-runtime",
                        "type": "stdio",
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    before_foreign_conflict = route_path.read_bytes()
    with pytest.raises(CursorIntegrationError) as foreign_conflict:
        preview_cursor_plugin(
            request_id("req_10000000-0000-4000-8000-000000000030"),
            target,
            PluginArtifactAction.REPLACE,
            second,
            project_root=project,
        )
    assert foreign_conflict.value.reason is PluginArtifactReason.MCP_OWNERSHIP_CONFLICT
    assert route_path.read_bytes() == before_foreign_conflict

    drifted = status_cursor_plugin(target, second)
    assert drifted.state is PluginArtifactState.MODIFIED
    assert drifted.marker_valid is True
    assert drifted.isolation_binding == "different"
    assert drifted.mcp_observation.ownership_state is McpOwnershipState.FOREIGN
    assert drifted.launcher.mcp_binding == "foreign"

    replace_request = request_id("req_10000000-0000-4000-8000-000000000027")
    replace_preview = preview_cursor_plugin(
        replace_request, target, PluginArtifactAction.REPLACE, second
    )
    assert replace_preview.mcp_ownership_state is McpOwnershipState.FOREIGN
    apply_cursor_plugin(
        replace_request,
        target,
        PluginArtifactAction.REPLACE,
        second,
        accepted_preview_digest=replace_preview.preview_digest,
        authority=_authority(replace_preview.preview_digest),
        review=_AcceptingReview(),
    )
    assert status_cursor_plugin(target, second).isolation_binding == "isolated_exact"

    # Unsetting the environment renders the ambient form and exposes the installed isolated form
    # as drift until the operator explicitly replaces it.
    monkeypatch.setattr(
        "yoetz.adapters.integrations.cursor_integration.isolated_root", lambda: None
    )
    ambient = render_cursor_plugin(
        PluginFormatProfile.CURSOR_PLUGIN_NATIVE,
        mcp_ownership=McpOwnership.PLUGIN_MANAGED,
        route_profile="policy",
        yoetz_launcher=executable,
    )
    assert ambient.isolation_root is None
    ambient_view = status_cursor_plugin(target, ambient)
    assert ambient_view.state is PluginArtifactState.MODIFIED
    assert ambient_view.isolation_binding == "different"

    ambient_request = request_id("req_10000000-0000-4000-8000-000000000028")
    ambient_preview = preview_cursor_plugin(
        ambient_request, target, PluginArtifactAction.REPLACE, ambient
    )
    apply_cursor_plugin(
        ambient_request,
        target,
        PluginArtifactAction.REPLACE,
        ambient,
        accepted_preview_digest=ambient_preview.preview_digest,
        authority=_authority(ambient_preview.preview_digest),
        review=_AcceptingReview(),
    )
    final = status_cursor_plugin(target, ambient)
    assert final.state is PluginArtifactState.NATIVE_MANAGED
    assert final.isolation_binding == "ambient"
    route = json.loads(
        (tmp_path / ".cursor" / "plugins" / "local" / "yoetz" / "mcp.json").read_bytes()
    )["mcpServers"]["yoetz"]
    assert "env" not in route
    hooks = json.loads(
        (tmp_path / ".cursor" / "plugins" / "local" / "yoetz" / "hooks" / "hooks.json").read_bytes()
    )["hooks"]
    assert all(
        "YOETZ_ISOLATED_ROOT=" not in definition[-1]["command"] for definition in hooks.values()
    )


def test_ordinary_isolation_binding_checks_ordinary_hook_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    isolated_root = tmp_path / "isolated"
    drifted_root = tmp_path / "drifted"
    executable = _fake_yoetz(tmp_path / "runtime" / "yoetz")
    monkeypatch.setattr(
        "yoetz.adapters.integrations.cursor_integration.isolated_root",
        lambda: isolated_root,
    )
    artifact = render_cursor_plugin(
        PluginFormatProfile.CURSOR_PLUGIN_NATIVE,
        mcp_ownership=McpOwnership.PLUGIN_MANAGED,
        route_profile="policy",
        yoetz_launcher=executable,
        observation_profile="ordinary",
    )
    assert artifact.plan.host_extension_profile == CURSOR_ORDINARY_OBSERVATION_PROFILE_ID
    target = _install_native(tmp_path, artifact)
    exact = status_cursor_plugin(target, artifact)
    assert exact.isolation_binding == "isolated_exact"

    destination = tmp_path / ".cursor" / "plugins" / "local" / "yoetz"
    hooks_path = destination / "hooks" / "hooks.json"
    hooks = json.loads(hooks_path.read_bytes())
    ordinary_command = hooks["hooks"]["postToolUse"][0]["command"]
    hooks["hooks"]["postToolUse"][0]["command"] = ordinary_command.replace(
        f"YOETZ_ISOLATED_ROOT={shlex.quote(str(isolated_root))}",
        f"YOETZ_ISOLATED_ROOT={shlex.quote(str(drifted_root))}",
        1,
    )
    hooks_bytes = canonical_encode(cast(JsonValue, hooks))
    hooks_path.write_bytes(hooks_bytes)

    # Keep the marker self-consistent so status reaches the root-bearing surface comparison
    # instead of classifying the whole tree as an invalid marker.
    marker_path = destination / ".yoetz-cursor-plugin-install.json"
    marker = json.loads(marker_path.read_bytes())
    for row in marker["managed_files"]:
        if row["relative_path"] == "hooks/hooks.json":
            row["size"] = len(hooks_bytes)
            row["sha256"] = "sha256:" + hashlib.sha256(hooks_bytes).hexdigest()
            break
    else:  # pragma: no cover - the installed artifact always owns hooks.json
        raise AssertionError("marker did not inventory hooks.json")
    marker["marker_digest"] = canonical_digest(
        {key: value for key, value in marker.items() if key != "marker_digest"}
    )
    marker_path.write_bytes(canonical_encode(cast(JsonValue, marker)))

    drifted = status_cursor_plugin(target, artifact)
    assert drifted.marker_valid is True
    assert drifted.state is PluginArtifactState.MODIFIED
    assert drifted.mcp_observation.ownership_state is McpOwnershipState.PLUGIN
    assert drifted.launcher.mcp_binding == "exact_launcher"
    assert drifted.isolation_binding == "different"


def test_isolated_legacy_marker_without_root_reports_missing_and_replaces(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "isolated"
    executable = _fake_yoetz(tmp_path / "runtime" / "yoetz")
    monkeypatch.setattr(
        "yoetz.adapters.integrations.cursor_integration.isolated_root", lambda: root
    )
    artifact = render_cursor_plugin(
        PluginFormatProfile.CURSOR_PLUGIN_NATIVE,
        mcp_ownership=McpOwnership.PLUGIN_MANAGED,
        route_profile="policy",
        yoetz_launcher=executable,
    )
    target = _install_native(tmp_path, artifact)
    destination = tmp_path / ".cursor" / "plugins" / "local" / "yoetz"
    marker_path = destination / ".yoetz-cursor-plugin-install.json"
    marker = json.loads(marker_path.read_bytes())
    marker.pop("isolation_root")
    marker["schema"] = "yoetz.cursor-plugin-install/2"
    body = {key: value for key, value in marker.items() if key != "marker_digest"}
    marker["marker_digest"] = canonical_digest(body)
    marker_path.write_bytes(canonical_encode(marker))

    status = status_cursor_plugin(target, artifact)
    assert status.state is PluginArtifactState.MODIFIED
    assert status.marker_valid is True
    assert status.isolation_binding == "missing"

    replacement = preview_cursor_plugin(
        request_id("req_10000000-0000-4000-8000-000000000029"),
        target,
        PluginArtifactAction.REPLACE,
        artifact,
    )
    replaced = apply_cursor_plugin(
        replacement.request_id,
        target,
        PluginArtifactAction.REPLACE,
        artifact,
        accepted_preview_digest=replacement.preview_digest,
        authority=_authority(replacement.preview_digest),
        review=_AcceptingReview(),
    )
    assert replaced.state_after is PluginArtifactState.NATIVE_MANAGED
    assert status_cursor_plugin(target, artifact).isolation_binding == "isolated_exact"


def _rewrite_native_marker_as_legacy_v1(destination: Path) -> None:
    marker_path = destination / ".yoetz-cursor-plugin-install.json"
    marker = json.loads(marker_path.read_bytes())
    marker.pop("yoetz_launcher")
    marker.pop("isolation_root", None)
    marker["schema"] = "yoetz.cursor-plugin-install/1"
    body = {key: value for key, value in marker.items() if key != "marker_digest"}
    marker["marker_digest"] = canonical_digest(body)
    marker_path.write_bytes(canonical_encode(marker))


def test_legacy_native_v1_marker_has_a_safe_replace_path(tmp_path: Path) -> None:
    target = CursorPluginTarget(str(tmp_path / ".cursor"))
    artifact = render_cursor_plugin(PluginFormatProfile.CURSOR_PLUGIN_NATIVE)
    installed = preview_cursor_plugin(_REQUEST, target, PluginArtifactAction.INSTALL, artifact)
    apply_cursor_plugin(
        _REQUEST,
        target,
        PluginArtifactAction.INSTALL,
        artifact,
        accepted_preview_digest=installed.preview_digest,
        authority=_authority(installed.preview_digest),
        review=_AcceptingReview(),
    )
    destination = tmp_path / ".cursor" / "plugins" / "local" / "yoetz"
    _rewrite_native_marker_as_legacy_v1(destination)

    status = status_cursor_plugin(target, artifact)
    assert status.state is PluginArtifactState.MODIFIED
    assert status.marker_valid is True
    replacement = preview_cursor_plugin(
        request_id("req_10000000-0000-4000-8000-000000000025"),
        target,
        PluginArtifactAction.REPLACE,
        artifact,
    )
    replaced = apply_cursor_plugin(
        replacement.request_id,
        target,
        PluginArtifactAction.REPLACE,
        artifact,
        accepted_preview_digest=replacement.preview_digest,
        authority=_authority(replacement.preview_digest),
        review=_AcceptingReview(),
    )
    assert replaced.state_after is PluginArtifactState.NATIVE_MANAGED
    marker = json.loads((destination / ".yoetz-cursor-plugin-install.json").read_bytes())
    assert marker["schema"] == "yoetz.cursor-plugin-install/3"


def test_portable_v1_marker_remains_exact_and_removable(tmp_path: Path) -> None:
    target = CursorPluginTarget(str(tmp_path / ".cursor"))
    artifact = render_cursor_plugin(PluginFormatProfile.AGENT_PLUGINS_1)
    installed = preview_cursor_plugin(_REQUEST, target, PluginArtifactAction.INSTALL, artifact)
    apply_cursor_plugin(
        _REQUEST,
        target,
        PluginArtifactAction.INSTALL,
        artifact,
        accepted_preview_digest=installed.preview_digest,
        authority=_authority(installed.preview_digest),
        review=_AcceptingReview(),
    )
    destination = tmp_path / ".cursor" / "plugins" / "local" / "yoetz"
    marker = json.loads((destination / ".yoetz-cursor-plugin-install.json").read_bytes())
    assert marker["schema"] == "yoetz.cursor-plugin-install/1"
    status = status_cursor_plugin(target, artifact)
    assert status.state is PluginArtifactState.PORTABLE_EXACT
    assert status.marker_valid is True
    preview_cursor_plugin(
        request_id("req_10000000-0000-4000-8000-000000000026"),
        target,
        PluginArtifactAction.REMOVE,
        artifact,
    )


def test_native_executable_drift_is_modified_and_replaceable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = tmp_path / "first" / "yoetz"
    second = tmp_path / "second" / "yoetz"
    for executable in (first, second):
        executable.parent.mkdir()
        executable.write_text("#!/bin/sh\n", encoding="utf-8")
        executable.chmod(0o755)

    def find_first(_command: str) -> str | None:
        return str(first)

    monkeypatch.setattr("yoetz.adapters.integrations.cursor_integration.shutil.which", find_first)
    installed_artifact = render_cursor_plugin(PluginFormatProfile.CURSOR_PLUGIN_NATIVE)
    target = CursorPluginTarget(str(tmp_path / ".cursor"))
    installed = preview_cursor_plugin(
        _REQUEST, target, PluginArtifactAction.INSTALL, installed_artifact
    )
    apply_cursor_plugin(
        _REQUEST,
        target,
        PluginArtifactAction.INSTALL,
        installed_artifact,
        accepted_preview_digest=installed.preview_digest,
        authority=_authority(installed.preview_digest),
        review=_AcceptingReview(),
    )

    def find_second(_command: str) -> str | None:
        return str(second)

    monkeypatch.setattr("yoetz.adapters.integrations.cursor_integration.shutil.which", find_second)
    desired = render_cursor_plugin(PluginFormatProfile.CURSOR_PLUGIN_NATIVE)
    status = status_cursor_plugin(target, desired)
    assert status.state is PluginArtifactState.MODIFIED
    assert status.marker_valid is True
    replacement = preview_cursor_plugin(
        request_id("req_10000000-0000-4000-8000-000000000027"),
        target,
        PluginArtifactAction.REPLACE,
        desired,
    )
    assert replacement.state_before is PluginArtifactState.MODIFIED
    replaced = apply_cursor_plugin(
        replacement.request_id,
        target,
        PluginArtifactAction.REPLACE,
        desired,
        accepted_preview_digest=replacement.preview_digest,
        authority=_authority(replacement.preview_digest),
        review=_AcceptingReview(),
    )
    assert replaced.state_after is PluginArtifactState.NATIVE_MANAGED
    marker_path = (
        tmp_path / ".cursor" / "plugins" / "local" / "yoetz" / ".yoetz-cursor-plugin-install.json"
    )
    assert json.loads(marker_path.read_bytes())["yoetz_launcher"] == [str(second.resolve())]


def test_remove_preserves_separately_registered_mcp_route(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "yoetz.adapters.integrations.cursor_integration.isolated_root", lambda: None
    )
    target = CursorPluginTarget(str(tmp_path / ".cursor"))
    artifact = render_cursor_plugin(
        PluginFormatProfile.CURSOR_PLUGIN_NATIVE,
        mcp_ownership=McpOwnership.PLUGIN_MANAGED,
        route_profile="strict",
    )
    preview = preview_cursor_plugin(_REQUEST, target, PluginArtifactAction.INSTALL, artifact)
    apply_cursor_plugin(
        _REQUEST,
        target,
        PluginArtifactAction.INSTALL,
        artifact,
        accepted_preview_digest=preview.preview_digest,
        authority=_authority(preview.preview_digest),
        review=_AcceptingReview(),
    )
    (tmp_path / ".cursor" / "mcp.json").write_text(
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

    remove_preview = preview_cursor_plugin(
        request_id("req_10000000-0000-4000-8000-000000000004"),
        target,
        PluginArtifactAction.REMOVE,
        artifact,
    )
    remove_cursor_plugin(
        remove_preview.request_id,
        target,
        artifact,
        accepted_preview_digest=remove_preview.preview_digest,
        authority=_authority(remove_preview.preview_digest),
        review=_AcceptingReview(),
    )

    assert (tmp_path / ".cursor" / "mcp.json").is_file()
    assert status_cursor_plugin(target, artifact).mcp_observation.ownership_state is (
        McpOwnershipState.EXTERNAL
    )


def test_post_commit_cleanup_failure_preserves_new_and_old_trees_for_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = CursorPluginTarget(str(tmp_path / ".cursor"))
    portable = render_cursor_plugin(PluginFormatProfile.AGENT_PLUGINS_1)
    native = render_cursor_plugin(PluginFormatProfile.CURSOR_PLUGIN_NATIVE)
    installed = preview_cursor_plugin(_REQUEST, target, PluginArtifactAction.INSTALL, portable)
    apply_cursor_plugin(
        _REQUEST,
        target,
        PluginArtifactAction.INSTALL,
        portable,
        accepted_preview_digest=installed.preview_digest,
        authority=_authority(installed.preview_digest),
        review=_AcceptingReview(),
    )
    replacement = preview_cursor_plugin(
        request_id("req_10000000-0000-4000-8000-000000000005"),
        target,
        PluginArtifactAction.REPLACE,
        native,
    )
    real_rmtree = shutil.rmtree

    def fail_rollback_cleanup(path: str | Path, *args: object, **kwargs: object) -> None:
        if Path(path).name == ".yoetz-cursor-plugin-rollback":
            raise OSError("cleanup failed")
        assert not args and not kwargs
        real_rmtree(path)

    monkeypatch.setattr(
        "yoetz.adapters.integrations.cursor_integration.shutil.rmtree",
        fail_rollback_cleanup,
    )
    with pytest.raises(CursorIntegrationError) as raised:
        apply_cursor_plugin(
            replacement.request_id,
            target,
            PluginArtifactAction.REPLACE,
            native,
            accepted_preview_digest=replacement.preview_digest,
            authority=_authority(replacement.preview_digest),
            review=_AcceptingReview(),
        )

    assert raised.value.reason is PluginArtifactReason.WRITE_FAILED
    destination = tmp_path / ".cursor" / "plugins" / "local" / "yoetz"
    assert (destination / ".cursor-plugin" / "plugin.json").is_file()
    assert (destination.parent / ".yoetz-cursor-plugin-rollback" / "plugin.json").is_file()
    assert status_cursor_plugin(target, native).state is PluginArtifactState.RECOVERY_REQUIRED


def test_modified_managed_copy_is_preserved_and_remove_refused(tmp_path: Path) -> None:
    target = CursorPluginTarget(str(tmp_path / ".cursor"))
    artifact = render_cursor_plugin(PluginFormatProfile.AGENT_PLUGINS_1)
    preview = preview_cursor_plugin(_REQUEST, target, PluginArtifactAction.INSTALL, artifact)
    apply_cursor_plugin(
        _REQUEST,
        target,
        PluginArtifactAction.INSTALL,
        artifact,
        accepted_preview_digest=preview.preview_digest,
        authority=_authority(preview.preview_digest),
        review=_AcceptingReview(),
    )
    skill = tmp_path / ".cursor" / "plugins" / "local" / "yoetz" / "skills" / "yoetz" / "SKILL.md"
    skill.write_text("locally modified\n", encoding="utf-8")

    assert status_cursor_plugin(target, artifact).state is PluginArtifactState.MODIFIED
    with pytest.raises(CursorIntegrationError) as raised:
        preview_cursor_plugin(
            request_id("req_10000000-0000-4000-8000-000000000003"),
            target,
            PluginArtifactAction.REMOVE,
            artifact,
        )
    assert raised.value.reason is PluginArtifactReason.REMOVE_REFUSED
    assert skill.read_text("utf-8") == "locally modified\n"


def test_mcp_precedence_negative_controls_never_create_false_plugin_pass(tmp_path: Path) -> None:
    plugin = tmp_path / "plugin"
    project = tmp_path / "project"
    user = tmp_path / "user"
    plugin.mkdir()
    (project / ".cursor").mkdir(parents=True)
    user.mkdir()
    exact = {
        "mcpServers": {"yoetz": {"args": ["mcp", "serve"], "command": "yoetz", "type": "stdio"}}
    }
    (plugin / "mcp.json").write_text(json.dumps(exact), encoding="utf-8")

    plugin_only = observe_cursor_mcp(
        plugin_root=plugin,
        project_root=project,
        user_config_root=user,
    )
    assert plugin_only.ownership_state is McpOwnershipState.PLUGIN
    assert plugin_only.winning_source is CursorMcpSource.PLUGIN

    cursor_exact = {
        "mcpServers": {
            "yoetz": {
                "args": ["mcp", "serve", "--host", "cursor"],
                "command": "yoetz",
                "type": "stdio",
            }
        }
    }
    (plugin / "mcp.json").write_text(json.dumps(cursor_exact), encoding="utf-8")
    cursor_plugin_only = observe_cursor_mcp(
        plugin_root=plugin,
        project_root=project,
        user_config_root=user,
    )
    assert cursor_plugin_only.ownership_state is McpOwnershipState.PLUGIN
    assert cursor_plugin_only.route_profile == "policy"

    inline = JsonObject(
        {"yoetz": JsonObject({"args": ["mcp", "serve"], "command": "yoetz", "type": "stdio"})}
    )
    dual = observe_cursor_mcp(
        plugin_root=plugin,
        project_root=project,
        user_config_root=user,
        inline_send=inline,
    )
    assert dual.ownership_state is McpOwnershipState.DUAL
    assert dual.winning_source is CursorMcpSource.INLINE_SEND

    foreign = {
        "mcpServers": {"yoetz": {"args": ["-c", "foreign"], "command": "sh", "type": "stdio"}}
    }
    (project / ".cursor" / "mcp.json").write_text(json.dumps(foreign), encoding="utf-8")
    observed = observe_cursor_mcp(
        plugin_root=plugin,
        project_root=project,
        user_config_root=user,
    )
    assert observed.ownership_state is McpOwnershipState.FOREIGN
    assert observed.winning_source is CursorMcpSource.PROJECT


def test_cursor_cli_discovery_uses_first_nonempty_complete_utf8_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "cursor-agent"
    executable.write_bytes(b"binary")
    executable.chmod(0o755)
    output = b"\n\n2026.07.09-a3815c0\n"

    def fake_run(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess((str(executable), "--version"), 0, output, b"")

    monkeypatch.setattr(
        "yoetz.adapters.integrations.cursor_integration.subprocess.run",
        fake_run,
    )

    identity = discover_cursor_cli(executable)

    assert identity.version == "2026.07.09-a3815c0"


@pytest.mark.parametrize("stdout", [b"", b"\xff", b"version\n" + b"x" * 4_096])
def test_cursor_cli_discovery_normalizes_empty_and_invalid_utf8_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stdout: bytes,
) -> None:
    executable = tmp_path / "cursor-agent"
    executable.write_bytes(b"binary")
    executable.chmod(0o755)

    def fake_run(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess((str(executable), "--version"), 0, stdout, b"")

    monkeypatch.setattr(
        "yoetz.adapters.integrations.cursor_integration.subprocess.run",
        fake_run,
    )

    with pytest.raises(ValueError, match="^cursor_cli_identity_invalid$"):
        discover_cursor_cli(executable)


def test_cursor_ide_discovery_names_unavailable_layouts(tmp_path: Path) -> None:

    install_root = tmp_path / "cursor"
    install_root.mkdir()

    with pytest.raises(ValueError, match="^cursor_ide_layout_unsupported$"):
        discover_cursor_ide(install_root, system="Linux")
    with pytest.raises(ValueError, match="^cursor_ide_platform_unsupported$"):
        discover_cursor_ide(install_root, system="Windows")
    with pytest.raises(ValueError, match="^cursor_ide_unavailable$"):
        discover_cursor_ide(install_root, system="Darwin")


def _linux_cursor_package(tmp_path: Path) -> Path:
    root = tmp_path / "usr" / "share" / "cursor"
    metadata = root / "resources" / "app"
    metadata.mkdir(parents=True)
    (root / "cursor").write_bytes(
        b"\x7fELF\x02\x01" + b"\x00" * 10 + b"\x03\x00" + b"\x3e\x00native-binary"
    )
    (root / "cursor").chmod(0o755)
    (metadata / "package.json").write_text('{"name":"Cursor","version":"3.21.16"}')
    (metadata / "product.json").write_text(
        json.dumps({"applicationName": "cursor", "commit": "8" * 40})
    )
    return root


@pytest.mark.parametrize("selection", ["root", "binary", "symlink"])
def test_linux_cursor_identity_reads_package_without_launching(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, selection: str
) -> None:
    root = _linux_cursor_package(tmp_path)
    selected = root if selection == "root" else root / "cursor"
    if selection == "symlink":
        selected = tmp_path / "cursor-link"
        selected.symlink_to(root / "cursor")
    monkeypatch.setattr(
        "yoetz.adapters.integrations.cursor_integration.platform.machine", lambda: "x86_64"
    )

    def refuse_execution(*args: object, **kwargs: object) -> None:
        pytest.fail("Identity discovery must not launch the IDE")

    monkeypatch.setattr(
        "yoetz.adapters.integrations.cursor_integration.subprocess.run", refuse_execution
    )
    identity = discover_cursor_ide(selected, system="Linux")
    assert identity.surface == "cursor_ide"
    assert identity.version == "3.21.16"
    assert identity.build == "8" * 40
    assert identity.os_name == "linux"
    assert identity.architecture == "x86_64"
    assert (
        identity.artifact_digest
        == "sha256:" + hashlib.sha256((root / "cursor").read_bytes()).hexdigest()
    )


@pytest.mark.parametrize(
    "content",
    [
        b"not json",
        b"\xff",
        b"[]",
        b'{"version":null}',
        b'{"version":""}',
        b'{"version":"a","version":"b"}',
        b" " * (1024 * 1024 + 1),
    ],
)
def test_linux_cursor_identity_rejects_malformed_metadata(tmp_path: Path, content: bytes) -> None:
    root = _linux_cursor_package(tmp_path)
    (root / "resources" / "app" / "package.json").write_bytes(content)
    with pytest.raises(ValueError, match="^cursor_ide_identity_invalid$"):
        discover_cursor_ide(root, system="Linux")


@pytest.mark.parametrize("elf_type", [0, 1, 4])
def test_linux_cursor_identity_rejects_non_loadable_elf_types(
    tmp_path: Path, elf_type: int
) -> None:
    root = _linux_cursor_package(tmp_path)
    executable = root / "cursor"
    content = executable.read_bytes()
    executable.write_bytes(content[:16] + elf_type.to_bytes(2, "little") + content[18:])
    with pytest.raises(ValueError, match="^cursor_ide_identity_invalid$"):
        discover_cursor_ide(root, system="Linux")


@pytest.mark.parametrize("elf_type", [2, 3])
def test_linux_cursor_identity_accepts_loadable_elf_types(tmp_path: Path, elf_type: int) -> None:
    root = _linux_cursor_package(tmp_path)
    executable = root / "cursor"
    content = executable.read_bytes()
    executable.write_bytes(content[:16] + elf_type.to_bytes(2, "little") + content[18:])
    assert discover_cursor_ide(root, system="Linux").surface == "cursor_ide"


@pytest.mark.parametrize("field", ["version", "commit"])
def test_linux_cursor_identity_rejects_control_characters(tmp_path: Path, field: str) -> None:
    root = _linux_cursor_package(tmp_path)
    metadata_path = (
        root / "resources" / "app" / ("package.json" if field == "version" else "product.json")
    )
    metadata = json.loads(metadata_path.read_text())
    metadata[field] = "3.21.16\nunsafe" if field == "version" else "8" * 20 + "\x7f"
    metadata_path.write_text(json.dumps(metadata))
    with pytest.raises(ValueError, match="^cursor_ide_identity_invalid$"):
        discover_cursor_ide(root, system="Linux")


@pytest.mark.parametrize(
    "member", ["cursor", "resources", "resources/app", "resources/app/product.json"]
)
def test_linux_cursor_identity_rejects_linked_package_members(tmp_path: Path, member: str) -> None:
    root = _linux_cursor_package(tmp_path)
    target = root / member
    outside = tmp_path / "outside"
    target.rename(outside)
    target.symlink_to(outside)
    with pytest.raises(ValueError, match="^cursor_ide_identity_invalid$"):
        discover_cursor_ide(root, system="Linux")


def test_linux_cursor_identity_rejects_foreign_product_and_windows_executable(
    tmp_path: Path,
) -> None:
    root = _linux_cursor_package(tmp_path)
    product = root / "resources" / "app" / "product.json"
    original = product.read_bytes()
    product.write_text('{"applicationName":"code","commit":"foreign"}')
    with pytest.raises(ValueError, match="^cursor_ide_identity_invalid$"):
        discover_cursor_ide(root, system="Linux")
    product.write_bytes(original)
    (root / "cursor").write_bytes(b"MZWindows executable")
    with pytest.raises(ValueError, match="^cursor_ide_identity_invalid$"):
        discover_cursor_ide(root, system="Linux")


def test_linux_cursor_identity_requires_executable_and_available_root(tmp_path: Path) -> None:
    root = _linux_cursor_package(tmp_path)
    (root / "cursor").chmod(0o644)
    with pytest.raises(ValueError, match="^cursor_ide_unavailable$"):
        discover_cursor_ide(root, system="Linux")
    with pytest.raises(ValueError, match="^cursor_ide_unavailable$"):
        discover_cursor_ide(tmp_path / "missing", system="Linux")


@pytest.mark.parametrize("machine,expected", [(62, "x86_64"), (183, "aarch64")])
def test_linux_cursor_identity_uses_artifact_architecture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, machine: int, expected: str
) -> None:
    root = _linux_cursor_package(tmp_path)
    executable = root / "cursor"
    content = executable.read_bytes()
    executable.write_bytes(content[:18] + machine.to_bytes(2, "little") + content[20:])
    monkeypatch.setattr(
        "yoetz.adapters.integrations.cursor_integration.platform.machine", lambda: "other"
    )
    assert discover_cursor_ide(root, system="Linux").architecture == expected


def test_linux_cursor_identity_does_not_substitute_a_nearby_executable(tmp_path: Path) -> None:
    root = _linux_cursor_package(tmp_path)
    selected = root / "Cursor.exe"
    selected.write_bytes(b"MZforeign binary")
    with pytest.raises(ValueError, match="^cursor_ide_layout_unsupported$"):
        discover_cursor_ide(selected, system="Linux")


def test_macos_cursor_identity_keeps_bundle_version_build_and_digest(tmp_path: Path) -> None:
    root = tmp_path / "Cursor.app"
    executable = root / "Contents" / "MacOS" / "Cursor"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"macos executable")
    (root / "Contents" / "Info.plist").write_bytes(
        plistlib.dumps(
            {
                "CFBundleExecutable": "Cursor",
                "CFBundleShortVersionString": "3.17.8",
                "CFBundleVersion": "build-id",
            }
        )
    )
    identity = discover_cursor_ide(root, system="Darwin")
    assert identity.version == "3.17.8"
    assert identity.build == "build-id"
    assert (
        identity.artifact_digest == "sha256:" + hashlib.sha256(executable.read_bytes()).hexdigest()
    )


def test_unreadable_mcp_configuration_is_ambiguous_not_absent(tmp_path: Path) -> None:
    plugin = tmp_path / "plugin"
    project = tmp_path / "project"
    user = tmp_path / "user"
    plugin.mkdir()
    project.mkdir()
    user.mkdir()
    (user / "mcp.json").write_text("not json", encoding="utf-8")

    observed = observe_cursor_mcp(
        plugin_root=plugin,
        project_root=project,
        user_config_root=user,
    )

    assert observed.ownership_state is McpOwnershipState.AMBIGUOUS
    assert observed.observed is False
    assert observed.winning_source is None
    assert observed.present_sources == (CursorMcpSource.USER,)


def test_sdk_profiles_require_explicit_sources_and_pin_bridge_protocol(tmp_path: Path) -> None:
    package_json = tmp_path / "package.json"
    package_json.write_text('{"name":"@cursor/sdk","version":"1.0.23"}', encoding="utf-8")
    identity = discover_cursor_sdk(
        CursorSdkBinding.TYPESCRIPT,
        package_metadata=package_json,
    )
    profile = build_cursor_sdk_profile(
        identity,
        setting_sources=("plugins", "project"),
        mcp_ownership=McpOwnership.PLUGIN_MANAGED,
        sandbox_enabled=True,
        approval_mode="allowlist",
    )
    assert profile.identity.package_version == "1.0.23"
    assert profile.identity.bridge_protocol == "sdk.v1"
    assert profile.identity.proof_limits == ("metadata_only", "not_a_support_claim")
    assert profile.proof_limits == ("metadata_only", "not_a_support_claim")
    assert profile.metadata_only is True
    assert profile.support_claim is False
    assert profile.mcp_precedence[0] is CursorMcpSource.INLINE_SEND

    with pytest.raises(ValueError, match="cursor_sdk_plugin_source_required"):
        build_cursor_sdk_profile(
            identity,
            setting_sources=("project",),
            mcp_ownership=McpOwnership.PLUGIN_MANAGED,
            sandbox_enabled=True,
            approval_mode="default",
        )


def test_cursor_mutation_requires_a_consumed_review_and_accept_alone_is_not_authority(
    tmp_path: Path,
) -> None:
    target = CursorPluginTarget(str(tmp_path / ".cursor"))
    artifact = render_cursor_plugin(PluginFormatProfile.CURSOR_PLUGIN_NATIVE)
    preview = preview_cursor_plugin(_REQUEST, target, PluginArtifactAction.INSTALL, artifact)
    destination = tmp_path / ".cursor" / "plugins" / "local" / "yoetz"

    with pytest.raises(CursorIntegrationError) as no_authority:
        apply_cursor_plugin(
            _REQUEST,
            target,
            PluginArtifactAction.INSTALL,
            artifact,
            accepted_preview_digest=preview.preview_digest,
            authority=None,
        )
    assert no_authority.value.reason is PluginArtifactReason.AUTHORITY_REQUIRED
    assert not destination.exists()

    # An unwired caller cannot self-authorize by constructing the discriminator itself.
    with pytest.raises(CursorIntegrationError) as unwired:
        apply_cursor_plugin(
            _REQUEST,
            target,
            PluginArtifactAction.INSTALL,
            artifact,
            accepted_preview_digest=preview.preview_digest,
            authority=_authority(preview.preview_digest),
        )
    assert unwired.value.reason is PluginArtifactReason.HUMAN_AUTHORITY_UNAVAILABLE
    assert not destination.exists()

    # An authority bound to a different digest never authorizes this preview.
    other = preview_cursor_plugin(
        request_id("req_10000000-0000-4000-8000-000000000021"),
        target,
        PluginArtifactAction.INSTALL,
        artifact,
    )
    with pytest.raises(CursorIntegrationError) as mismatched:
        apply_cursor_plugin(
            _REQUEST,
            target,
            PluginArtifactAction.INSTALL,
            artifact,
            accepted_preview_digest=preview.preview_digest,
            authority=_authority(other.preview_digest),
            review=_AcceptingReview(),
        )
    assert mismatched.value.reason is PluginArtifactReason.AUTHORITY_REQUIRED
    assert not destination.exists()

    review = _AcceptingReview()
    result = apply_cursor_plugin(
        _REQUEST,
        target,
        PluginArtifactAction.INSTALL,
        artifact,
        accepted_preview_digest=preview.preview_digest,
        authority=_authority(preview.preview_digest),
        review=review,
    )
    assert result.state_after is PluginArtifactState.NATIVE_MANAGED
    assert [digest for _authority_value, digest in review.artifact_reviews] == [
        preview.preview_digest
    ]
    assert review.setup_authorities == []


def test_wedged_install_replay_reconciles_without_conflict_or_a_second_review(
    tmp_path: Path,
) -> None:
    target = CursorPluginTarget(str(tmp_path / ".cursor"))
    artifact = render_cursor_plugin(PluginFormatProfile.CURSOR_PLUGIN_NATIVE)
    preview = preview_cursor_plugin(_REQUEST, target, PluginArtifactAction.INSTALL, artifact)
    committed = apply_cursor_plugin(
        _REQUEST,
        target,
        PluginArtifactAction.INSTALL,
        artifact,
        accepted_preview_digest=preview.preview_digest,
        authority=_authority(preview.preview_digest),
        review=_AcceptingReview(),
    )
    assert committed.operation_state is PluginOperationState.COMPLETED

    # The commit succeeded but its result was lost. The same request and digest must reconcile at
    # the selected state, and must not need a second single-shot review to do it.
    replay = apply_cursor_plugin(
        _REQUEST,
        target,
        PluginArtifactAction.INSTALL,
        artifact,
        accepted_preview_digest=preview.preview_digest,
        authority=None,
    )
    assert replay.action is PluginArtifactAction.NOOP
    assert replay.operation_state is PluginOperationState.COMPLETED
    assert replay.state_before is PluginArtifactState.NATIVE_MANAGED
    assert replay.state_after is PluginArtifactState.NATIVE_MANAGED
    assert replay.installed_digest == artifact.artifact_digest
    assert replay.changed_files == ()

    # A foreign request replaying somebody else's accepted digest still fails closed, because
    # the request ID is part of the digest it would have to match.
    with pytest.raises(CursorIntegrationError) as borrowed_digest:
        apply_cursor_plugin(
            request_id("req_10000000-0000-4000-8000-000000000022"),
            target,
            PluginArtifactAction.INSTALL,
            artifact,
            accepted_preview_digest=preview.preview_digest,
            authority=None,
        )
    assert borrowed_digest.value.reason is PluginArtifactReason.DESTINATION_CONFLICT

    # Recognition is stateless, not request-bound, and this pins that honestly: the preview
    # digest is a pure function of its inputs, so a request that never committed anything can
    # recompute one and reach the same reconciled result. That is a read-only equivalent of
    # ``status`` -- no bytes move, no review is consumed -- so it is admitted, not a bypass.
    from yoetz.adapters.integrations.cursor_integration import (
        _ABSENT_STATE_DIGEST,  # pyright: ignore[reportPrivateUsage]
        _admissible_owner_states,  # pyright: ignore[reportPrivateUsage]
        _preview_digest,  # pyright: ignore[reportPrivateUsage]
    )

    never_committed = request_id("req_10000000-0000-4000-8000-000000000024")
    recomputed = _preview_digest(
        never_committed,
        PluginArtifactAction.INSTALL,
        artifact,
        current_state_digest=_ABSENT_STATE_DIGEST,
        mcp_ownership_state=preview.mcp_ownership_state,
        target_identity=preview.target_identity,
    )
    assert preview.mcp_ownership_state in _admissible_owner_states(artifact)
    installed_bytes = {
        path.relative_to(tmp_path).as_posix(): path.read_bytes()
        for path in (tmp_path / ".cursor").rglob("*")
        if path.is_file()
    }
    review = _AcceptingReview()
    foreign = apply_cursor_plugin(
        never_committed,
        target,
        PluginArtifactAction.INSTALL,
        artifact,
        accepted_preview_digest=recomputed,
        authority=None,
        review=review,
    )
    assert foreign.action is PluginArtifactAction.NOOP
    assert foreign.operation_state is PluginOperationState.COMPLETED
    assert foreign.changed_files == ()
    assert review.artifact_reviews == []
    assert review.setup_authorities == []
    assert {
        path.relative_to(tmp_path).as_posix(): path.read_bytes()
        for path in (tmp_path / ".cursor").rglob("*")
        if path.is_file()
    } == installed_bytes

    # What the reconcile cannot do is claim a state that is not on disk.
    portable = render_cursor_plugin(PluginFormatProfile.AGENT_PLUGINS_1)
    with pytest.raises(CursorIntegrationError) as other_artifact:
        apply_cursor_plugin(
            _REQUEST,
            target,
            PluginArtifactAction.INSTALL,
            portable,
            accepted_preview_digest=preview.preview_digest,
            authority=None,
        )
    assert other_artifact.value.reason is PluginArtifactReason.DESTINATION_CONFLICT


def test_wedged_remove_replay_reconciles_at_absent_instead_of_remove_refused(
    tmp_path: Path,
) -> None:
    target = CursorPluginTarget(str(tmp_path / ".cursor"))
    artifact = render_cursor_plugin(PluginFormatProfile.CURSOR_PLUGIN_NATIVE)
    install_preview = preview_cursor_plugin(
        _REQUEST, target, PluginArtifactAction.INSTALL, artifact
    )
    apply_cursor_plugin(
        _REQUEST,
        target,
        PluginArtifactAction.INSTALL,
        artifact,
        accepted_preview_digest=install_preview.preview_digest,
        authority=_authority(install_preview.preview_digest),
        review=_AcceptingReview(),
    )
    remove_request = request_id("req_10000000-0000-4000-8000-000000000023")
    remove_preview = preview_cursor_plugin(
        remove_request, target, PluginArtifactAction.REMOVE, artifact
    )
    removed = remove_cursor_plugin(
        remove_request,
        target,
        artifact,
        accepted_preview_digest=remove_preview.preview_digest,
        authority=_authority(remove_preview.preview_digest),
        review=_AcceptingReview(),
    )
    assert removed.state_after is PluginArtifactState.ABSENT

    replay = remove_cursor_plugin(
        remove_request,
        target,
        artifact,
        accepted_preview_digest=remove_preview.preview_digest,
        authority=None,
    )
    assert replay.action is PluginArtifactAction.NOOP
    assert replay.operation_state is PluginOperationState.COMPLETED
    assert replay.state_before is PluginArtifactState.ABSENT
    assert replay.state_after is PluginArtifactState.ABSENT
    assert replay.installed_digest is None
    assert replay.changed_files == ()


@pytest.mark.parametrize("extra_key", ["cwd", "env"])
def test_same_name_entry_with_any_extra_key_is_foreign_not_a_recognized_route(
    tmp_path: Path, extra_key: str
) -> None:
    plugin = tmp_path / "plugin"
    user = tmp_path / "user"
    plugin.mkdir()
    user.mkdir()
    entry: dict[str, object] = {
        "args": ["mcp", "serve", "--host", "cursor"],
        "command": "yoetz",
        "type": "stdio",
        extra_key: {"YOETZ_TOKEN": "leak"} if extra_key == "env" else "/tmp",
    }
    (user / "mcp.json").write_text(json.dumps({"mcpServers": {"yoetz": entry}}), encoding="utf-8")

    observation = observe_cursor_mcp(plugin_root=plugin, project_root=None, user_config_root=user)

    assert observation.ownership_state is McpOwnershipState.FOREIGN
    assert observation.route_profile is None
    assert observation.winning_source is CursorMcpSource.USER
