"""Cursor plugin and MCP state written before the rename (ADR-048).

A Yoetz-era native install lives in ``plugins/local/yoetz`` under the same frozen marker. Status
reports it, install and replace migrate it in the same approval, remove takes it too, and a
legacy directory FinishUP cannot prove is its own is reported and never touched. MCP entries
under the legacy ``yoetz`` key and either isolation-root spelling stay recognizable.
"""

from __future__ import annotations

import json
import shlex
import shutil
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest

from finishup.adapters.integrations.cursor_integration import (
    CursorIntegrationError,
    CursorMcpSource,
    CursorPluginArtifact,
    CursorPluginTarget,
    apply_cursor_plugin,
    installed_cursor_startup_mode,
    observe_cursor_mcp,
    preview_cursor_plugin,
    remove_cursor_plugin,
    render_cursor_plugin,
    status_cursor_plugin,
)
from finishup.domain.values import RequestId, request_id
from finishup.ports.plugin_artifacts import (
    ArtifactAuthority,
    McpOwnership,
    McpOwnershipState,
    PluginArtifactAction,
    PluginArtifactReason,
    PluginArtifactState,
    PluginFormatProfile,
    PluginOperationState,
)
from finishup.protocol.canonical import JsonValue

_REVIEW_ID = "b" * 64


def _request(number: int) -> RequestId:
    return request_id(f"req_20000000-0000-4000-8000-{number:012d}")


class _AcceptingReview:
    def consume_setup_authority(self, authority: ArtifactAuthority, preview_digest: str) -> None:
        del authority, preview_digest

    def consume_artifact_review(self, authority: ArtifactAuthority, preview_digest: str) -> None:
        del authority, preview_digest


def _fake_launcher(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def _artifact(tmp_path: Path, *, startup_mode: str = "optional") -> CursorPluginArtifact:
    return render_cursor_plugin(
        PluginFormatProfile.CURSOR_PLUGIN_NATIVE,
        finishup_launcher=_fake_launcher(tmp_path / "bin" / "finishup"),
        startup_mode="required" if startup_mode == "required" else "optional",
    )


def _apply(
    target: CursorPluginTarget,
    action: PluginArtifactAction,
    artifact: CursorPluginArtifact,
    number: int,
) -> object:
    request = _request(number)
    preview = preview_cursor_plugin(request, target, action, artifact)
    authority = ArtifactAuthority("review_only", preview.preview_digest, _REVIEW_ID)
    if action is PluginArtifactAction.REMOVE:
        return remove_cursor_plugin(
            request,
            target,
            artifact,
            accepted_preview_digest=preview.preview_digest,
            authority=authority,
            review=_AcceptingReview(),
        )
    return apply_cursor_plugin(
        request,
        target,
        action,
        artifact,
        accepted_preview_digest=preview.preview_digest,
        authority=authority,
        review=_AcceptingReview(),
    )


def _legacy_install(tmp_path: Path, artifact: CursorPluginArtifact) -> CursorPluginTarget:
    """Install, then move the marker-valid tree to the legacy name a 0.2 install used."""

    target = CursorPluginTarget(str(tmp_path / ".cursor"))
    _apply(target, PluginArtifactAction.INSTALL, artifact, 1)
    local = tmp_path / ".cursor" / "plugins" / "local"
    (local / "finishup").rename(local / "yoetz")
    return target


def test_legacy_only_tree_is_reported_and_install_migrates_it(tmp_path: Path) -> None:
    artifact = _artifact(tmp_path)
    target = _legacy_install(tmp_path, artifact)
    local = tmp_path / ".cursor" / "plugins" / "local"

    status = status_cursor_plugin(target, artifact)
    assert status.state is PluginArtifactState.ABSENT
    assert status.legacy_installation == "legacy_only"
    preview = preview_cursor_plugin(_request(2), target, PluginArtifactAction.INSTALL, artifact)
    assert preview.action is PluginArtifactAction.INSTALL
    assert preview.legacy_installation == "legacy_only"
    assert "legacy_installation_owned" in preview.warnings

    result = _apply(target, PluginArtifactAction.INSTALL, artifact, 3)
    assert getattr(result, "operation_state") is PluginOperationState.COMPLETED
    assert any(path.startswith("plugins/local/yoetz/") for path in getattr(result, "changed_files"))
    assert not (local / "yoetz").exists()
    after = status_cursor_plugin(target, artifact)
    assert after.state is PluginArtifactState.NATIVE_MANAGED
    assert after.legacy_installation == "none"


def test_duplicate_tree_makes_an_exact_replace_a_migration(tmp_path: Path) -> None:
    artifact = _artifact(tmp_path)
    target = _legacy_install(tmp_path, artifact)
    _apply(target, PluginArtifactAction.INSTALL, artifact, 4)
    shutil.copytree(
        tmp_path / ".cursor" / "plugins" / "local" / "finishup",
        tmp_path / ".cursor" / "plugins" / "local" / "yoetz",
    )

    assert status_cursor_plugin(target, artifact).legacy_installation == "duplicate"
    preview = preview_cursor_plugin(_request(5), target, PluginArtifactAction.REPLACE, artifact)
    assert preview.action is PluginArtifactAction.REPLACE
    _apply(target, PluginArtifactAction.REPLACE, artifact, 6)
    assert status_cursor_plugin(target, artifact).legacy_installation == "none"
    assert (
        preview_cursor_plugin(_request(7), target, PluginArtifactAction.REPLACE, artifact).action
        is PluginArtifactAction.NOOP
    )


def test_remove_takes_a_legacy_only_tree(tmp_path: Path) -> None:
    artifact = _artifact(tmp_path)
    target = _legacy_install(tmp_path, artifact)

    result = _apply(target, PluginArtifactAction.REMOVE, artifact, 8)
    assert getattr(result, "state_after") is PluginArtifactState.ABSENT
    assert not (tmp_path / ".cursor" / "plugins" / "local" / "yoetz").exists()
    assert status_cursor_plugin(target, artifact).legacy_installation == "none"


def test_foreign_legacy_directory_is_reported_and_never_touched(tmp_path: Path) -> None:
    artifact = _artifact(tmp_path)
    target = CursorPluginTarget(str(tmp_path / ".cursor"))
    foreign = tmp_path / ".cursor" / "plugins" / "local" / "yoetz"
    foreign.mkdir(parents=True)
    (foreign / "notes.txt").write_text("mine", encoding="utf-8")

    assert status_cursor_plugin(target, artifact).legacy_installation == "foreign"
    preview = preview_cursor_plugin(_request(9), target, PluginArtifactAction.INSTALL, artifact)
    assert "legacy_installation_foreign" in preview.warnings
    _apply(target, PluginArtifactAction.INSTALL, artifact, 10)
    assert (foreign / "notes.txt").read_text(encoding="utf-8") == "mine"
    with pytest.raises(CursorIntegrationError) as refused:
        preview_cursor_plugin(
            _request(11),
            CursorPluginTarget(str(tmp_path / "empty")),
            PluginArtifactAction.REMOVE,
            artifact,
        )
    assert refused.value.reason is PluginArtifactReason.REMOVE_REFUSED


def test_a_legacy_tree_changed_after_preview_is_stale(tmp_path: Path) -> None:
    artifact = _artifact(tmp_path)
    target = _legacy_install(tmp_path, artifact)
    request = _request(12)
    preview = preview_cursor_plugin(request, target, PluginArtifactAction.INSTALL, artifact)
    extra = tmp_path / ".cursor" / "plugins" / "local" / "yoetz" / "extra.txt"
    extra.write_text("changed", encoding="utf-8")

    with pytest.raises(CursorIntegrationError) as stale:
        apply_cursor_plugin(
            request,
            target,
            PluginArtifactAction.INSTALL,
            artifact,
            accepted_preview_digest=preview.preview_digest,
            authority=ArtifactAuthority("review_only", preview.preview_digest, _REVIEW_ID),
            review=_AcceptingReview(),
        )
    assert stale.value.reason is PluginArtifactReason.PREVIEW_STALE
    assert extra.exists()


def test_startup_mode_survives_migration_from_a_legacy_tree(tmp_path: Path) -> None:
    artifact = _artifact(tmp_path, startup_mode="required")
    target = _legacy_install(tmp_path, artifact)

    assert installed_cursor_startup_mode(target) == "required"


def _entry(command: str, args: list[str], **extra: object) -> Mapping[str, JsonValue]:
    return cast(
        Mapping[str, JsonValue],
        {"args": list(args), "command": command, "type": "stdio", **extra},
    )


def _observe(tmp_path: Path, servers: dict[str, object]) -> object:
    user = tmp_path / "user"
    user.mkdir(exist_ok=True)
    (user / "mcp.json").write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")
    return observe_cursor_mcp(
        plugin_root=tmp_path / "plugin",
        project_root=None,
        user_config_root=user,
    )


@pytest.mark.parametrize("command", ["finishup", "yoetz"])
def test_legacy_key_entry_stands_in_when_alone(tmp_path: Path, command: str) -> None:
    observation = _observe(tmp_path, {"yoetz": _entry(command, ["mcp", "serve"])})

    assert getattr(observation, "ownership_state") is McpOwnershipState.EXTERNAL
    assert getattr(observation, "winning_source") is CursorMcpSource.USER
    assert getattr(observation, "legacy_registration") == "legacy_only"


def test_both_keys_owned_read_as_duplicate_and_two_servers(tmp_path: Path) -> None:
    # Two owned entries are two live FinishUP servers, whichever key each sits under.
    observation = _observe(
        tmp_path,
        {
            "finishup": _entry("finishup", ["mcp", "serve", "--semantic", "off"]),
            "yoetz": _entry("yoetz", ["mcp", "serve"]),
        },
    )

    assert getattr(observation, "ownership_state") is McpOwnershipState.AMBIGUOUS
    assert getattr(observation, "route_profile") is None
    assert getattr(observation, "present_sources") == (CursorMcpSource.USER,)
    assert getattr(observation, "legacy_registration") == "duplicate"


def test_plugin_route_beside_an_owned_legacy_external_entry_is_dual(tmp_path: Path) -> None:
    plugin = tmp_path / "plugin"
    plugin.mkdir()
    (plugin / "mcp.json").write_text(
        json.dumps({"mcpServers": {"finishup": _entry("finishup", ["mcp", "serve"])}}),
        encoding="utf-8",
    )
    observation = _observe(tmp_path, {"yoetz": _entry("yoetz", ["mcp", "serve"])})

    # The same pair under one name reads dual; the legacy key does not make it admissible.
    assert getattr(observation, "ownership_state") is McpOwnershipState.DUAL
    assert getattr(observation, "present_sources") == (CursorMcpSource.PLUGIN, CursorMcpSource.USER)
    assert getattr(observation, "legacy_registration") == "duplicate"


def test_foreign_legacy_key_is_reported_but_not_a_conflict(tmp_path: Path) -> None:
    observation = _observe(tmp_path, {"yoetz": _entry("/usr/bin/other", ["serve"])})

    assert getattr(observation, "ownership_state") is McpOwnershipState.ABSENT
    assert getattr(observation, "legacy_registration") == "foreign"


@pytest.mark.parametrize(
    ("environment", "owned"),
    [
        ({"FINISHUP_ISOLATED_ROOT": "/r"}, True),
        ({"YOETZ_ISOLATED_ROOT": "/r"}, True),
        ({"FINISHUP_ISOLATED_ROOT": "/r", "YOETZ_ISOLATED_ROOT": "/r"}, True),
        ({"FINISHUP_ISOLATED_ROOT": "/r", "YOETZ_ISOLATED_ROOT": "/s"}, False),
        ({}, False),
    ],
)
def test_route_isolation_root_spellings(environment: dict[str, str], owned: bool) -> None:
    from finishup.adapters.integrations.cursor_integration import (
        _route_profile,  # pyright: ignore[reportPrivateUsage]
    )

    entry = _entry("finishup", ["mcp", "serve"], env=environment)
    assert (_route_profile(entry, expected_isolation_root="/r") == "policy") is owned


@pytest.mark.parametrize("spelling", ["both", "new", "legacy"])
def test_hook_prefix_classifier_accepts_each_spelling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, spelling: str
) -> None:
    from finishup.adapters.integrations import cursor_integration as module

    root = tmp_path / "isolated"
    monkeypatch.setattr(module, "isolated_root", lambda: root)
    artifact = render_cursor_plugin(
        PluginFormatProfile.CURSOR_PLUGIN_NATIVE,
        mcp_ownership=McpOwnership.EXTERNAL_REGISTRATION,
        finishup_launcher=_fake_launcher(tmp_path / "bin" / "finishup"),
    )
    target = CursorPluginTarget(str(tmp_path / ".cursor"))
    _apply(target, PluginArtifactAction.INSTALL, artifact, 13)
    hooks_path = tmp_path / ".cursor" / "plugins" / "local" / "finishup" / "hooks" / "hooks.json"
    quoted = shlex.quote(str(root))
    both = f"FINISHUP_ISOLATED_ROOT={quoted} YOETZ_ISOLATED_ROOT={quoted} "
    replacement = {
        "both": both,
        "new": f"FINISHUP_ISOLATED_ROOT={quoted} ",
        "legacy": f"YOETZ_ISOLATED_ROOT={quoted} ",
    }[spelling]
    hooks_path.write_text(
        hooks_path.read_text(encoding="utf-8").replace(both, replacement), encoding="utf-8"
    )

    inspection = module._inspect(target, artifact)  # pyright: ignore[reportPrivateUsage]
    assert module._root_binding_surfaces_match(  # pyright: ignore[reportPrivateUsage]
        artifact, inspection
    )
