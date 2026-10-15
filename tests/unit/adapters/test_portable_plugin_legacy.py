"""Portable plugin trees written before the rename (ADR-048).

A Yoetz-era portable tree lives in ``.agents/plugins/yoetz`` under the same frozen marker, and a
plugin-managed one keys its route ``yoetz`` and launches the bare ``yoetz`` alias. Status reports
it, install and replace migrate it in the same approval, remove takes it too, and a legacy tree
this lane cannot prove is its own is reported and never touched.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Literal

import pytest

from finishup.adapters.integrations import portable_plugin as portable_mod
from finishup.adapters.integrations.portable_plugin import (
    AGENT_PLUGIN_ROOT,
    LEGACY_AGENT_PLUGIN_ROOT,
    PortablePluginArtifactAdapter,
    build_portable_plugin_plan,
    observe_plugin_managed_mcp,
)
from finishup.domain.values import RequestId, request_id
from finishup.ports.plugin_artifacts import (
    ArtifactAuthority,
    ArtifactTarget,
    McpOwnership,
    McpOwnershipState,
    PluginArtifactAction,
    PluginArtifactApplyCommand,
    PluginArtifactError,
    PluginArtifactReason,
    PluginArtifactState,
    PluginArtifactStatusCommand,
    PluginOperationState,
)


def _request(number: int) -> RequestId:
    return request_id(f"req_40000000-0000-4000-8000-{number:012d}")


class _SetupAuthority:
    def consume_setup_authority(self, authority: ArtifactAuthority, preview_digest: str) -> None:
        assert authority.target_digest == preview_digest

    def consume_artifact_review(self, authority: ArtifactAuthority, preview_digest: str) -> None:
        raise AssertionError("setup composition only")


def _target(tmp_path: Path) -> ArtifactTarget:
    tmp_path.chmod(0o700)
    return ArtifactTarget(str(tmp_path))


def _write_tree(
    root: Path,
    *,
    route: Literal["strict", "policy"] | None = None,
    legacy_route: bool = False,
) -> None:
    """Write one marker-valid portable tree; ``legacy_route`` uses the pre-rename route bytes."""

    rendered = build_portable_plugin_plan(
        mcp_ownership=McpOwnership.EXTERNAL_REGISTRATION
        if route is None
        else McpOwnership.PLUGIN_MANAGED,
        mcp_route_profile=route,
    )
    members = dict(rendered.members)
    if route is not None and legacy_route:
        members["mcp.json"] = portable_mod._mcp_json(  # pyright: ignore[reportPrivateUsage]
            route, legacy=True
        )
        inventory = portable_mod._inventory(members)  # pyright: ignore[reportPrivateUsage]
        rendered = replace(rendered, plan=replace(rendered.plan, inventory=inventory))
    for path, data in {
        **members,
        ".yoetz-plugin-install.json": portable_mod._marker(  # pyright: ignore[reportPrivateUsage]
            rendered
        ),
    }.items():
        destination = root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)


async def _apply(
    adapter: PortablePluginArtifactAdapter,
    target: ArtifactTarget,
    action: PluginArtifactAction,
    number: int,
) -> object:
    request = request_id(_request(number))
    preview = await adapter.preview_artifact(request, target, action)
    command = PluginArtifactApplyCommand(
        request,
        target,
        action,
        preview.preview_digest,
        ArtifactAuthority("setup_composition", preview.preview_digest),
    )
    if action is PluginArtifactAction.REMOVE:
        return await adapter.remove_artifact(command)
    return await adapter.install_artifact(command)


@pytest.mark.anyio
async def test_legacy_only_tree_is_reported_and_install_migrates_it(tmp_path: Path) -> None:
    target = _target(tmp_path)
    _write_tree(tmp_path / LEGACY_AGENT_PLUGIN_ROOT)
    adapter = PortablePluginArtifactAdapter(review=_SetupAuthority())

    status = await adapter.status_artifact(PluginArtifactStatusCommand(target))
    assert status.state is PluginArtifactState.ABSENT
    assert status.legacy_installation == "legacy_only"
    preview = await adapter.preview_artifact(
        request_id(_request(1)), target, PluginArtifactAction.INSTALL
    )
    assert preview.action is PluginArtifactAction.INSTALL
    assert "legacy_installation_owned" in preview.warnings

    result = await _apply(adapter, target, PluginArtifactAction.INSTALL, 2)
    assert getattr(result, "operation_state") is PluginOperationState.COMPLETED
    assert any(
        path.startswith(f"{LEGACY_AGENT_PLUGIN_ROOT}/") for path in getattr(result, "changed_files")
    )
    assert not (tmp_path / LEGACY_AGENT_PLUGIN_ROOT).exists()
    after = await adapter.status_artifact(PluginArtifactStatusCommand(target))
    assert after.state is PluginArtifactState.PORTABLE_EXACT
    assert after.legacy_installation == "none"


@pytest.mark.anyio
async def test_duplicate_exact_tree_is_not_a_noop_until_migrated(tmp_path: Path) -> None:
    target = _target(tmp_path)
    _write_tree(tmp_path / AGENT_PLUGIN_ROOT)
    _write_tree(tmp_path / LEGACY_AGENT_PLUGIN_ROOT)
    adapter = PortablePluginArtifactAdapter(review=_SetupAuthority())

    status = await adapter.status_artifact(PluginArtifactStatusCommand(target))
    assert (status.state, status.legacy_installation) == (
        PluginArtifactState.PORTABLE_EXACT,
        "duplicate",
    )
    preview = await adapter.preview_artifact(
        request_id(_request(3)), target, PluginArtifactAction.REPLACE
    )
    assert preview.action is PluginArtifactAction.REPLACE
    await _apply(adapter, target, PluginArtifactAction.REPLACE, 4)
    preview = await adapter.preview_artifact(
        request_id(_request(5)), target, PluginArtifactAction.REPLACE
    )
    assert preview.action is PluginArtifactAction.NOOP


@pytest.mark.anyio
async def test_remove_takes_a_legacy_only_tree(tmp_path: Path) -> None:
    target = _target(tmp_path)
    _write_tree(tmp_path / LEGACY_AGENT_PLUGIN_ROOT)
    adapter = PortablePluginArtifactAdapter(review=_SetupAuthority())

    result = await _apply(adapter, target, PluginArtifactAction.REMOVE, 6)
    assert getattr(result, "state_after") is PluginArtifactState.ABSENT
    assert not (tmp_path / LEGACY_AGENT_PLUGIN_ROOT).exists()


@pytest.mark.anyio
async def test_foreign_legacy_tree_is_reported_and_never_touched(tmp_path: Path) -> None:
    target = _target(tmp_path)
    foreign = tmp_path / LEGACY_AGENT_PLUGIN_ROOT
    foreign.mkdir(parents=True)
    (foreign / "notes.txt").write_text("mine", encoding="utf-8")
    adapter = PortablePluginArtifactAdapter(review=_SetupAuthority())

    status = await adapter.status_artifact(PluginArtifactStatusCommand(target))
    assert status.legacy_installation == "foreign"
    await _apply(adapter, target, PluginArtifactAction.INSTALL, 7)
    assert (foreign / "notes.txt").read_text(encoding="utf-8") == "mine"
    await _apply(adapter, target, PluginArtifactAction.REMOVE, 8)
    assert (foreign / "notes.txt").read_text(encoding="utf-8") == "mine"
    with pytest.raises(PluginArtifactError) as refused:
        await adapter.preview_artifact(request_id(_request(9)), target, PluginArtifactAction.REMOVE)
    assert refused.value.reason is PluginArtifactReason.REMOVE_REFUSED


@pytest.mark.anyio
async def test_a_legacy_tree_changed_after_preview_is_stale(tmp_path: Path) -> None:
    target = _target(tmp_path)
    _write_tree(tmp_path / LEGACY_AGENT_PLUGIN_ROOT)
    adapter = PortablePluginArtifactAdapter(review=_SetupAuthority())
    request = request_id(_request(10))
    preview = await adapter.preview_artifact(request, target, PluginArtifactAction.INSTALL)
    (tmp_path / LEGACY_AGENT_PLUGIN_ROOT / "plugin.json").write_text("{}", encoding="utf-8")

    with pytest.raises(PluginArtifactError) as stale:
        await adapter.install_artifact(
            PluginArtifactApplyCommand(
                request,
                target,
                PluginArtifactAction.INSTALL,
                preview.preview_digest,
                ArtifactAuthority("setup_composition", preview.preview_digest),
            )
        )
    assert stale.value.reason is PluginArtifactReason.PREVIEW_STALE
    assert not (tmp_path / AGENT_PLUGIN_ROOT).exists()


@pytest.mark.parametrize("route", ["policy", "strict"])
def test_legacy_plugin_managed_route_is_observed_when_alone(
    tmp_path: Path, route: Literal["strict", "policy"]
) -> None:
    _target(tmp_path)
    _write_tree(tmp_path / LEGACY_AGENT_PLUGIN_ROOT, route=route, legacy_route=True)

    observation = observe_plugin_managed_mcp(tmp_path)
    assert (observation.ownership_state, observation.route_profile) == (
        McpOwnershipState.PLUGIN,
        route,
    )


def test_owned_routes_in_both_trees_are_ambiguous(tmp_path: Path) -> None:
    _target(tmp_path)
    _write_tree(tmp_path / AGENT_PLUGIN_ROOT, route="policy")
    _write_tree(tmp_path / LEGACY_AGENT_PLUGIN_ROOT, route="policy", legacy_route=True)

    observation = observe_plugin_managed_mcp(tmp_path)
    assert observation.ownership_state is McpOwnershipState.AMBIGUOUS
    assert observation.observed is True


def test_new_tree_route_wins_over_an_unowned_legacy_directory(tmp_path: Path) -> None:
    _target(tmp_path)
    _write_tree(tmp_path / AGENT_PLUGIN_ROOT, route="strict")
    foreign = tmp_path / LEGACY_AGENT_PLUGIN_ROOT
    foreign.mkdir(parents=True)
    (foreign / "mcp.json").write_text('{"mcpServers": {}}', encoding="utf-8")

    observation = observe_plugin_managed_mcp(tmp_path)
    assert (observation.ownership_state, observation.route_profile) == (
        McpOwnershipState.PLUGIN,
        "strict",
    )
