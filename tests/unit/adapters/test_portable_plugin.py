"""Portable Agent Plugins renderer and whole-directory lifecycle contract."""

from __future__ import annotations

import hashlib
import shutil
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, cast

import pytest

from yoetz.adapters.integrations import portable_plugin as portable_mod
from yoetz.adapters.integrations.codex_plugin import install_plugin
from yoetz.adapters.integrations.portable_plugin import (
    AGENT_PLUGIN_ROOT,
    ElevatedPortableArtifactReview,
    PortablePluginArtifactAdapter,
    build_portable_plugin_plan,
    combine_mcp_ownership_states,
    observe_plugin_managed_mcp,
    prepare_portable_artifact_review,
    render_portable_plugin_tree,
    validate_agent_plugin_manifest,
    validate_agent_plugin_mcp,
    validate_portable_plugin_tree,
    validate_portable_skill,
)
from yoetz.domain.values import request_id
from yoetz.ports.integrations import IntegrationScope, IntegrationTarget
from yoetz.ports.plugin_artifacts import (
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
    PluginFormatProfile,
    PluginOperationState,
    PluginProofFacet,
)
from yoetz.protocol.canonical import (
    JsonValue,
    canonical_digest,
    canonical_encode,
    strict_json_parse,
)
from yoetz.protocol.guidance_uris import FOCUSED_GUIDANCE_URIS, GUIDANCE_DOCUMENT_URIS
from yoetz.service.elevated_bootstrap import catalog_payload, load_pending
from yoetz.version import read_verified_resource

_GUIDANCE_NAMES = tuple(
    uri.removeprefix("yoetz://guidance/")
    for uri in (*GUIDANCE_DOCUMENT_URIS, *FOCUSED_GUIDANCE_URIS)
)


def _request(number: int) -> str:
    return f"req_00000000-0000-4000-8000-{number:012d}"


def _target(tmp_path: Path) -> ArtifactTarget:
    tmp_path.chmod(0o700)
    return ArtifactTarget(str(tmp_path))


def _setup_authority(preview_digest: str) -> ArtifactAuthority:
    return ArtifactAuthority("setup_composition", preview_digest)


def _tree_digest(members: Mapping[str, bytes]) -> str:
    return canonical_digest(
        {
            "files": [
                {
                    "relative_path": path,
                    "sha256": f"sha256:{hashlib.sha256(data).hexdigest()}",
                    "size": len(data),
                }
                for path, data in sorted(members.items(), key=lambda item: item[0].encode("ascii"))
            ]
        }
    )


def _make_native_tree_self_consistent_but_noncanonical(
    root: Path,
    mutation: str,
) -> None:
    marker_path = root / ".yoetz-plugin-install.json"
    parsed = strict_json_parse(marker_path.read_bytes())
    assert isinstance(parsed, Mapping)
    marker = dict(cast(Mapping[str, Any], parsed))
    if mutation == "member":
        member_path = root / "hooks/hooks.json"
        changed = member_path.read_bytes() + b"\n"
        member_path.write_bytes(changed)
        raw_rows = marker["managed_files"]
        assert type(raw_rows) is list
        rows: list[dict[str, Any]] = []
        for raw_row in cast(list[object], raw_rows):
            assert isinstance(raw_row, Mapping)
            row = dict(cast(Mapping[str, Any], raw_row))
            if row["relative_path"] == "hooks/hooks.json":
                row["sha256"] = f"sha256:{hashlib.sha256(changed).hexdigest()}"
                row["size"] = len(changed)
            rows.append(row)
        marker["managed_files"] = rows
    elif mutation == "renderer":
        marker["adapter_version"] = "codex-plugin/noncanonical"
    else:
        raise AssertionError("unknown mutation")
    body = {name: value for name, value in marker.items() if name != "marker_digest"}
    body["marker_digest"] = canonical_digest(cast(JsonValue, body))
    marker_path.write_bytes(canonical_encode(cast(JsonValue, body)) + b"\n")


class _Presence:
    def __init__(self, *, allowed: bool = True) -> None:
        self.allowed = allowed
        self.calls = 0
        self.seen: ArtifactAuthority | None = None

    def verify_artifact_review(self, authority: ArtifactAuthority) -> None:
        self.calls += 1
        self.seen = authority
        if not self.allowed:
            raise RuntimeError("presence unavailable")


class _SetupAuthority:
    def consume_setup_authority(self, authority: ArtifactAuthority, preview_digest: str) -> None:
        assert authority.channel == "setup_composition"
        assert authority.target_digest == preview_digest

    def consume_artifact_review(self, authority: ArtifactAuthority, preview_digest: str) -> None:
        del authority, preview_digest
        raise AssertionError("review-only authority was not expected")


class _MutatingSetupAuthority(_SetupAuthority):
    def __init__(self, mutation: Callable[[], None]) -> None:
        self._mutation = mutation

    def consume_setup_authority(self, authority: ArtifactAuthority, preview_digest: str) -> None:
        super().consume_setup_authority(authority, preview_digest)
        self._mutation()


class _Resources:
    def __init__(self, overrides: Mapping[str, bytes | None]) -> None:
        self.overrides = overrides

    def read_bytes(self, package_path: str) -> bytes:
        if package_path in self.overrides:
            value = self.overrides[package_path]
            if value is None:
                raise FileNotFoundError(package_path)
            return value
        return read_verified_resource(package_path)


def test_vendored_agent_plugin_schemas_match_the_accepted_pins() -> None:
    plugin = read_verified_resource("support/agent-plugins/1.0.0/plugin.schema.json")
    mcp = read_verified_resource("support/agent-plugins/1.0.0/mcp.schema.json")
    assert hashlib.sha256(plugin).hexdigest() == (
        "0a4aad95ce337878ad38802ebf0daa3fde76abe3f65400c86bcbb1ec0b3ab883"
    )
    assert hashlib.sha256(mcp).hexdigest() == (
        "6539175bfcdf43085855183e86da40ea94b166547a72b47ae9a0a390516d3acb"
    )


def test_codex_portable_root_and_scope_are_fixture_registered() -> None:
    fixture = strict_json_parse(
        read_verified_resource("fixtures/agent-plugins/codex-project-root.case.json")
    )
    assert isinstance(fixture, Mapping)
    assert fixture["host_surface"] == "codex_cli"
    assert fixture["format_profile"] == "agent_plugins_1"
    assert fixture["scope"] == "trusted_project"
    assert fixture["plugin_root"] == AGENT_PLUGIN_ROOT
    assert fixture["mcp_ownership"] == "external_registration"
    expected_members = fixture["expected_members"]
    assert type(expected_members) is list
    assert expected_members == sorted(render_portable_plugin_tree(), key=str.encode)


def test_plugin_managed_route_variants_match_the_registered_fixture() -> None:
    fixture = strict_json_parse(
        read_verified_resource("fixtures/agent-plugins/codex-project-plugin-managed-mcp.case.json")
    )
    assert isinstance(fixture, Mapping)
    routes = fixture["routes"]
    assert isinstance(routes, Mapping)
    server_name = fixture["expected_server_name"]
    assert type(server_name) is str
    for profile in ("policy", "strict"):
        rendered = render_portable_plugin_tree(
            mcp_ownership=McpOwnership.PLUGIN_MANAGED,
            mcp_route_profile=profile,
        )
        mcp = strict_json_parse(rendered["mcp.json"])
        assert isinstance(mcp, Mapping)
        servers = mcp["mcpServers"]
        assert isinstance(servers, Mapping)
        assert servers[server_name] == routes[profile]


def test_portable_tree_is_skills_only_and_guidance_is_byte_identical() -> None:
    rendered = build_portable_plugin_plan()
    tree = dict(rendered.members)
    assert tuple(sorted(tree, key=str.encode)) == tuple(
        item.relative_path for item in rendered.plan.inventory
    )
    assert "plugin.json" in tree
    assert "skills/yoetz/SKILL.md" in tree
    assert "mcp.json" not in tree
    assert "skills/yoetz/manifest.json" not in tree
    assert rendered.plan.format_profile is PluginFormatProfile.AGENT_PLUGINS_1
    assert rendered.plan.mcp_ownership is McpOwnership.EXTERNAL_REGISTRATION
    assert rendered.plan.mcp_route_profile is None
    skill = tree["skills/yoetz/SKILL.md"].decode("utf-8")
    assert "The first workflow operation is `start`." in skill
    assert "Carrier has no authority." in skill
    for name in _GUIDANCE_NAMES:
        assert tree[f"skills/yoetz/references/{name}"] == read_verified_resource(f"guidance/{name}")
        assert f"guidance/{name}" in rendered.plan.source_refs


def test_portable_builder_defaults_to_the_neutral_skill() -> None:
    default = build_portable_plugin_plan()
    explicit = build_portable_plugin_plan(skill_host="portable")

    assert default.members == explicit.members
    assert default.plan.source_refs == explicit.plan.source_refs
    assert default.artifact_digest == explicit.artifact_digest


@pytest.mark.parametrize("skill_host", ["claude", "codex", "", None, 1])
def test_portable_builder_rejects_unknown_skill_host(skill_host: object) -> None:
    with pytest.raises(PluginArtifactError) as caught:
        build_portable_plugin_plan(skill_host=cast(Any, skill_host))
    assert caught.value.reason is PluginArtifactReason.SOURCE_INVALID


@pytest.mark.parametrize(
    ("route_profile", "expected_args"),
    [
        ("policy", ["mcp", "serve"]),
        ("strict", ["mcp", "serve", "--semantic", "off"]),
    ],
)
def test_plugin_managed_mcp_variants_are_exact_and_offline_valid(
    route_profile: str, expected_args: list[str]
) -> None:
    rendered = build_portable_plugin_plan(
        mcp_ownership=McpOwnership.PLUGIN_MANAGED,
        mcp_route_profile=cast(Any, route_profile),
    )
    mcp_raw = rendered.members["mcp.json"]
    # The condensed skill defers setup to the carried consent topic, which states ownership.
    consent = " ".join(
        rendered.members["skills/yoetz/references/consent.md"].decode("utf-8").split()
    )
    assert "`plugin_managed` includes the selected `mcp.json` route" in consent
    assert "this plugin is the sole owner" in consent
    mcp = strict_json_parse(mcp_raw)
    assert mcp == {
        "$schema": "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json",
        "mcpServers": {"yoetz": {"args": expected_args, "command": "yoetz", "type": "stdio"}},
    }
    assert b"env" not in mcp_raw
    assert rendered.plan.mcp_ownership is McpOwnership.PLUGIN_MANAGED
    assert rendered.plan.mcp_route_profile == route_profile
    validated = validate_agent_plugin_mcp(
        mcp_raw,
        schema_bytes=read_verified_resource("support/agent-plugins/1.0.0/mcp.schema.json"),
    )
    assert validated.top_level_valid is True
    assert validated.loaded_server_count == 1
    assert validated.skipped_server_count == 0


def test_mcp_failure_boundaries_preserve_skill_and_other_servers() -> None:
    plugin = render_portable_plugin_tree()
    schema = read_verified_resource("support/agent-plugins/1.0.0/plugin.schema.json")
    mcp_schema = read_verified_resource("support/agent-plugins/1.0.0/mcp.schema.json")
    plugin["mcp.json"] = canonical_encode(
        {
            "$schema": "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json",
            "mcpServers": {
                "bad": {"type": "stdio", "command": "yoetz", "unknown": True},
                "good": {"type": "stdio", "command": "yoetz", "args": ["mcp", "serve"]},
                "other": {"type": "stdio", "command": "other-server"},
                "remote": {"type": "streamable-http", "url": "https://example.com/mcp"},
            },
        }
    )
    result = validate_portable_plugin_tree(
        plugin,
        schema_bytes=schema,
        mcp_schema_bytes=mcp_schema,
        mcp_connection_failures={"good": "handshake"},
    )
    assert "skills/yoetz" in result.loaded_components
    assert result.loaded_components == ("manifest", "skills/yoetz", "mcp")
    assert result.skipped_components == ("mcp_server",)
    assert result.diagnostics == (
        "mcp_server_invalid",
        "mcp_handshake_failed",
        "mcp_transport_unsupported",
    )


@pytest.mark.parametrize(
    "server",
    [
        {"type": "stdio", "command": "../yoetz"},
        {"type": "stdio", "command": "yoetz", "cwd": "data"},
        {"type": "stdio", "command": "yoetz", "env": {"PLUGIN_ROOT": "override"}},
    ],
)
def test_mcp_path_and_reserved_variable_escapes_skip_only_that_server(
    server: dict[str, JsonValue],
) -> None:
    raw = canonical_encode(
        {
            "$schema": "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json",
            "mcpServers": {
                "invalid": server,
                "yoetz": {"type": "stdio", "command": "yoetz", "args": ["mcp", "serve"]},
            },
        }
    )
    result = validate_agent_plugin_mcp(
        raw,
        schema_bytes=read_verified_resource("support/agent-plugins/1.0.0/mcp.schema.json"),
    )
    assert result.loaded_server_count == 1
    assert result.skipped_server_count == 1
    assert result.diagnostics == ("mcp_server_invalid",)


@pytest.mark.parametrize(
    "mcp_raw",
    [
        b"not-json",
        canonical_encode(
            {
                "$schema": "https://agent-plugins.org/schemas/9.9.9/mcp.schema.json",
                "mcpServers": {},
            }
        ),
        canonical_encode(
            {
                "$schema": "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json",
                "mcpServers": {},
                "unknown": True,
            }
        ),
    ],
)
def test_invalid_top_level_mcp_disables_only_mcp(mcp_raw: bytes) -> None:
    plugin = render_portable_plugin_tree()
    plugin["mcp.json"] = mcp_raw
    result = validate_portable_plugin_tree(
        plugin,
        schema_bytes=read_verified_resource("support/agent-plugins/1.0.0/plugin.schema.json"),
        mcp_schema_bytes=read_verified_resource("support/agent-plugins/1.0.0/mcp.schema.json"),
    )
    assert result.loaded_components == ("manifest", "skills/yoetz")
    assert result.skipped_components == ("mcp",)
    assert result.diagnostics == ("mcp_config_invalid",)


@pytest.mark.parametrize("failure", ["executable", "start", "connect", "auth", "handshake"])
def test_mcp_runtime_failure_skips_only_the_failed_server(failure: str) -> None:
    raw = render_portable_plugin_tree(
        mcp_ownership=McpOwnership.PLUGIN_MANAGED,
        mcp_route_profile="policy",
    )["mcp.json"]
    result = validate_agent_plugin_mcp(
        raw,
        schema_bytes=read_verified_resource("support/agent-plugins/1.0.0/mcp.schema.json"),
        connection_failures={"yoetz": cast(Any, failure)},
    )
    assert result.top_level_valid is True
    assert result.loaded_server_count == 0
    assert result.skipped_server_count == 1


def test_manifest_unknown_fields_are_reported_and_ignored() -> None:
    schema = read_verified_resource("support/agent-plugins/1.0.0/plugin.schema.json")
    valid = strict_json_parse(render_portable_plugin_tree()["plugin.json"])
    assert isinstance(valid, Mapping)
    with_unknown: dict[str, JsonValue] = {**valid, "futureField": {"opaque": True}}
    result = validate_agent_plugin_manifest(canonical_encode(with_unknown), schema_bytes=schema)
    assert result.accepted is True
    assert result.unknown_fields == ("futureField",)
    assert result.fatal_field is None


@pytest.mark.parametrize(
    ("change", "fatal_field"),
    [
        ({"name": "Not Allowed"}, "name"),
        ({"$schema": "https://invalid.example/schema"}, "$schema"),
        ({"name": ""}, "name"),
    ],
)
def test_manifest_fatal_violation_names_the_exact_field(
    change: Mapping[str, JsonValue], fatal_field: str
) -> None:
    schema = read_verified_resource("support/agent-plugins/1.0.0/plugin.schema.json")
    valid = strict_json_parse(render_portable_plugin_tree()["plugin.json"])
    assert isinstance(valid, Mapping)
    result = validate_agent_plugin_manifest(
        canonical_encode({**valid, **change}),
        schema_bytes=schema,
    )
    assert result.accepted is False
    assert result.fatal_field == fatal_field


def test_portable_skill_rejects_host_only_frontmatter_without_touching_manifest() -> None:
    manifest_before = render_portable_plugin_tree()["plugin.json"]
    invalid_skill = b"---\nname: yoetz\ndescription: test\nmetadata:\n  host: codex\n---\n"
    validation = validate_portable_plugin_tree(
        {"plugin.json": manifest_before, "skills/yoetz/SKILL.md": invalid_skill},
        schema_bytes=read_verified_resource("support/agent-plugins/1.0.0/plugin.schema.json"),
    )
    assert validation.manifest.accepted is True
    assert validation.loaded_components == ("manifest",)
    assert validation.skipped_components == ("skills/yoetz",)
    assert validation.diagnostics == ("skill_frontmatter_invalid",)
    with pytest.raises(PluginArtifactError) as caught:
        validate_portable_skill(invalid_skill)
    assert caught.value.reason is PluginArtifactReason.SOURCE_INVALID
    assert render_portable_plugin_tree()["plugin.json"] == manifest_before


@pytest.mark.parametrize(
    "overrides",
    [
        {"guidance/workflow.md": None},
        {"skills/portable/yoetz/SKILL.md": b"x" * 262_145},
    ],
)
def test_missing_or_oversized_source_member_fails_closed(
    overrides: Mapping[str, bytes | None],
) -> None:
    with pytest.raises(PluginArtifactError) as caught:
        build_portable_plugin_plan(resource_source=_Resources(overrides))
    assert caught.value.reason is PluginArtifactReason.SOURCE_INVALID


def test_consent_catalog_registers_exact_review_only_artifact_operation() -> None:
    catalog = catalog_payload()
    raw_operations = catalog["operations"]
    assert type(raw_operations) is list
    operations: dict[str, Mapping[str, JsonValue]] = {}
    for raw_item in raw_operations:
        assert isinstance(raw_item, Mapping)
        item = cast(Mapping[str, JsonValue], raw_item)
        name = item["operation"]
        assert type(name) is str
        operations[name] = item
    operation = operations["plugin_artifact_apply"]
    assert operation["risk_class"] == "review_only"
    assert operation["implemented"] is True
    assert operation["requires_target_digest_arg"] is True
    assert operation["agent_chat_authorize_allowed"] is False


@pytest.mark.anyio
async def test_install_is_preview_bound_verified_and_replay_safe(tmp_path: Path) -> None:
    target = _target(tmp_path)
    adapter = PortablePluginArtifactAdapter(
        review=_SetupAuthority(), mcp_owner_state=McpOwnershipState.EXTERNAL
    )
    preview = await adapter.preview_artifact(
        request_id(_request(1)), target, PluginArtifactAction.INSTALL
    )
    command = PluginArtifactApplyCommand(
        request_id(_request(1)),
        target,
        PluginArtifactAction.INSTALL,
        preview.preview_digest,
        _setup_authority(preview.preview_digest),
    )
    result = await adapter.install_artifact(command)
    replay = await adapter.install_artifact(command)
    assert replay == result
    assert result.operation_state is PluginOperationState.COMPLETED
    assert result.state_after is PluginArtifactState.PORTABLE_EXACT
    assert not (tmp_path / AGENT_PLUGIN_ROOT / "mcp.json").exists()
    status = await adapter.status_artifact(PluginArtifactStatusCommand(target, command.request_id))
    assert status.state is PluginArtifactState.PORTABLE_EXACT
    assert status.operation_state is PluginOperationState.COMPLETED
    assert status.mcp_ownership_state is McpOwnershipState.EXTERNAL
    proof = {item.facet: item.status for item in status.proof}
    assert proof[PluginProofFacet.INSTALLED_BYTES] == "proven"
    assert proof[PluginProofFacet.HOST_ACTIVATION] == "not_observed"
    assert proof[PluginProofFacet.OBSERVATION_EVIDENCE] == "not_observed"


@pytest.mark.anyio
async def test_plugin_managed_install_is_exclusive_and_owner_state_is_preview_bound(
    tmp_path: Path,
) -> None:
    target = _target(tmp_path)
    owner = [McpOwnershipState.ABSENT]
    adapter = PortablePluginArtifactAdapter(
        review=_SetupAuthority(),
        mcp_ownership=McpOwnership.PLUGIN_MANAGED,
        mcp_route_profile="strict",
        mcp_owner_state=McpOwnershipState.ABSENT,
        mcp_owner_observer=lambda: owner[0],
    )
    preview = await adapter.preview_artifact(
        request_id(_request(12)), target, PluginArtifactAction.INSTALL
    )
    assert preview.mcp_ownership_state is McpOwnershipState.ABSENT
    owner[0] = McpOwnershipState.EXTERNAL
    with pytest.raises(PluginArtifactError) as caught:
        await adapter.install_artifact(
            PluginArtifactApplyCommand(
                request_id(_request(12)),
                target,
                PluginArtifactAction.INSTALL,
                preview.preview_digest,
                _setup_authority(preview.preview_digest),
            )
        )
    assert caught.value.reason is PluginArtifactReason.MCP_OWNERSHIP_CONFLICT
    assert not (tmp_path / ".agents").exists()


@pytest.mark.anyio
async def test_allowed_owner_transition_after_preview_is_stale(tmp_path: Path) -> None:
    target = _target(tmp_path)
    owner = [McpOwnershipState.ABSENT]
    adapter = PortablePluginArtifactAdapter(
        review=_SetupAuthority(),
        mcp_ownership=McpOwnership.PLUGIN_MANAGED,
        mcp_route_profile="strict",
        mcp_owner_state=McpOwnershipState.ABSENT,
        mcp_owner_observer=lambda: owner[0],
    )
    preview = await adapter.preview_artifact(
        request_id(_request(15)), target, PluginArtifactAction.INSTALL
    )
    owner[0] = McpOwnershipState.PLUGIN
    with pytest.raises(PluginArtifactError) as caught:
        await adapter.install_artifact(
            PluginArtifactApplyCommand(
                request_id(_request(15)),
                target,
                PluginArtifactAction.INSTALL,
                preview.preview_digest,
                _setup_authority(preview.preview_digest),
            )
        )
    assert caught.value.reason is PluginArtifactReason.PREVIEW_STALE
    assert not (tmp_path / ".agents").exists()


@pytest.mark.anyio
async def test_route_change_after_preview_is_stale(tmp_path: Path) -> None:
    target = _target(tmp_path)
    strict = PortablePluginArtifactAdapter(
        mcp_ownership=McpOwnership.PLUGIN_MANAGED,
        mcp_route_profile="strict",
        mcp_owner_state=McpOwnershipState.ABSENT,
    )
    preview = await strict.preview_artifact(
        request_id(_request(16)), target, PluginArtifactAction.INSTALL
    )
    policy = PortablePluginArtifactAdapter(
        review=_SetupAuthority(),
        mcp_ownership=McpOwnership.PLUGIN_MANAGED,
        mcp_route_profile="policy",
        mcp_owner_state=McpOwnershipState.ABSENT,
    )
    with pytest.raises(PluginArtifactError) as caught:
        await policy.install_artifact(
            PluginArtifactApplyCommand(
                request_id(_request(16)),
                target,
                PluginArtifactAction.INSTALL,
                preview.preview_digest,
                _setup_authority(preview.preview_digest),
            )
        )
    assert caught.value.reason is PluginArtifactReason.PREVIEW_STALE
    assert not (tmp_path / ".agents").exists()


@pytest.mark.anyio
async def test_plugin_managed_install_is_observed_from_exact_marker_and_route(
    tmp_path: Path,
) -> None:
    target = _target(tmp_path)

    def _combined_owner() -> McpOwnershipState:
        plugin = observe_plugin_managed_mcp(tmp_path).ownership_state
        return combine_mcp_ownership_states(McpOwnershipState.ABSENT, plugin)

    adapter = PortablePluginArtifactAdapter(
        review=_SetupAuthority(),
        mcp_ownership=McpOwnership.PLUGIN_MANAGED,
        mcp_route_profile="policy",
        mcp_owner_observer=_combined_owner,
    )
    preview = await adapter.preview_artifact(
        request_id(_request(14)), target, PluginArtifactAction.INSTALL
    )
    await adapter.install_artifact(
        PluginArtifactApplyCommand(
            request_id(_request(14)),
            target,
            PluginArtifactAction.INSTALL,
            preview.preview_digest,
            _setup_authority(preview.preview_digest),
        )
    )

    observation = observe_plugin_managed_mcp(tmp_path)

    assert observation.observed is True
    assert observation.ownership_state is McpOwnershipState.PLUGIN
    assert observation.route_profile == "policy"
    status = await adapter.status_artifact(PluginArtifactStatusCommand(target))
    assert status.mcp_ownership_state is McpOwnershipState.PLUGIN
    assert status.mcp_route_profile == "policy"


@pytest.mark.anyio
async def test_default_plugin_managed_adapter_refuses_uncomposed_ownership(
    tmp_path: Path,
) -> None:
    adapter = PortablePluginArtifactAdapter(
        mcp_ownership=McpOwnership.PLUGIN_MANAGED,
        mcp_route_profile="policy",
    )
    with pytest.raises(PluginArtifactError) as caught:
        await adapter.preview_artifact(
            request_id(_request(17)), _target(tmp_path), PluginArtifactAction.INSTALL
        )
    assert caught.value.reason is PluginArtifactReason.MCP_OWNERSHIP_CONFLICT
    assert caught.value.safe_details == {"mcp_ownership_state": "ambiguous"}


@pytest.mark.parametrize(
    ("external", "plugin", "combined"),
    [
        (McpOwnershipState.ABSENT, McpOwnershipState.ABSENT, McpOwnershipState.ABSENT),
        (McpOwnershipState.EXTERNAL, McpOwnershipState.ABSENT, McpOwnershipState.EXTERNAL),
        (McpOwnershipState.ABSENT, McpOwnershipState.PLUGIN, McpOwnershipState.PLUGIN),
        (McpOwnershipState.EXTERNAL, McpOwnershipState.PLUGIN, McpOwnershipState.DUAL),
        (McpOwnershipState.AMBIGUOUS, McpOwnershipState.ABSENT, McpOwnershipState.AMBIGUOUS),
        (McpOwnershipState.ABSENT, McpOwnershipState.FOREIGN, McpOwnershipState.FOREIGN),
    ],
)
def test_composed_ownership_never_collapses_external_or_unknown_sources(
    external: McpOwnershipState,
    plugin: McpOwnershipState,
    combined: McpOwnershipState,
) -> None:
    assert combine_mcp_ownership_states(external, plugin) is combined


@pytest.mark.anyio
@pytest.mark.parametrize(
    "owner_state",
    [
        McpOwnershipState.EXTERNAL,
        McpOwnershipState.DUAL,
        McpOwnershipState.FOREIGN,
        McpOwnershipState.AMBIGUOUS,
    ],
)
async def test_plugin_managed_preview_preserves_and_reports_conflicting_owner_states(
    tmp_path: Path, owner_state: McpOwnershipState
) -> None:
    adapter = PortablePluginArtifactAdapter(
        mcp_ownership=McpOwnership.PLUGIN_MANAGED,
        mcp_route_profile="policy",
        mcp_owner_state=owner_state,
    )
    with pytest.raises(PluginArtifactError) as caught:
        await adapter.preview_artifact(
            request_id(_request(13)), _target(tmp_path), PluginArtifactAction.INSTALL
        )
    assert caught.value.reason is PluginArtifactReason.MCP_OWNERSHIP_CONFLICT
    assert caught.value.safe_details == {"mcp_ownership_state": owner_state.value}


@pytest.mark.anyio
async def test_stale_preview_rejects_before_mutation(tmp_path: Path) -> None:
    target = _target(tmp_path)
    adapter = PortablePluginArtifactAdapter()
    preview = await adapter.preview_artifact(
        request_id(_request(2)), target, PluginArtifactAction.INSTALL
    )
    plugin_root = tmp_path / AGENT_PLUGIN_ROOT
    plugin_root.mkdir(parents=True)
    (plugin_root / "foreign.txt").write_text("foreign", encoding="utf-8")
    command = PluginArtifactApplyCommand(
        request_id(_request(2)),
        target,
        PluginArtifactAction.INSTALL,
        preview.preview_digest,
        _setup_authority(preview.preview_digest),
    )
    with pytest.raises(PluginArtifactError) as caught:
        await adapter.install_artifact(command)
    assert caught.value.reason in {
        PluginArtifactReason.DESTINATION_CONFLICT,
        PluginArtifactReason.PREVIEW_STALE,
    }
    assert (plugin_root / "foreign.txt").read_text(encoding="utf-8") == "foreign"


@pytest.mark.anyio
async def test_standalone_review_fails_closed_without_presence_adapter(tmp_path: Path) -> None:
    target = _target(tmp_path)
    adapter = PortablePluginArtifactAdapter()
    preview = await adapter.preview_artifact(
        request_id(_request(3)), target, PluginArtifactAction.INSTALL
    )
    command = PluginArtifactApplyCommand(
        request_id(_request(3)),
        target,
        PluginArtifactAction.INSTALL,
        preview.preview_digest,
        ArtifactAuthority("review_only", preview.preview_digest, "pending-review"),
    )
    with pytest.raises(PluginArtifactError) as caught:
        await adapter.install_artifact(command)
    assert caught.value.reason is PluginArtifactReason.HUMAN_AUTHORITY_UNAVAILABLE
    assert not (tmp_path / ".agents").exists()


@pytest.mark.anyio
async def test_fabricated_setup_channel_fails_closed_without_composition_authority(
    tmp_path: Path,
) -> None:
    target = _target(tmp_path)
    adapter = PortablePluginArtifactAdapter()
    preview = await adapter.preview_artifact(
        request_id(_request(10)), target, PluginArtifactAction.INSTALL
    )
    command = PluginArtifactApplyCommand(
        request_id(_request(10)),
        target,
        PluginArtifactAction.INSTALL,
        preview.preview_digest,
        _setup_authority(preview.preview_digest),
    )
    with pytest.raises(PluginArtifactError) as caught:
        await adapter.install_artifact(command)
    assert caught.value.reason is PluginArtifactReason.AUTHORITY_REQUIRED
    assert not (tmp_path / ".agents").exists()


@pytest.mark.anyio
async def test_review_only_prepare_and_consume_is_exact_and_single_shot(
    tmp_path: Path,
) -> None:
    target = _target(tmp_path)
    state = tmp_path / "private-state"
    presence = _Presence()
    review = ElevatedPortableArtifactReview(presence, _state=state)
    adapter = PortablePluginArtifactAdapter(review=review)
    preview = await adapter.preview_artifact(
        request_id(_request(9)), target, PluginArtifactAction.INSTALL
    )
    authority = prepare_portable_artifact_review(preview.preview_digest, _state=state)
    pending = load_pending(_state=state)
    assert pending is not None
    assert pending.operation == "plugin_artifact_apply"
    result = await adapter.install_artifact(
        PluginArtifactApplyCommand(
            request_id(_request(9)),
            target,
            PluginArtifactAction.INSTALL,
            preview.preview_digest,
            authority,
        )
    )
    assert result.state_after is PluginArtifactState.PORTABLE_EXACT
    assert presence.seen == authority
    assert presence.calls == 1
    assert load_pending(_state=state) is None

    with pytest.raises(PluginArtifactError) as reused:
        review.consume_artifact_review(authority, preview.preview_digest)
    assert reused.value.reason is PluginArtifactReason.AUTHORITY_REQUIRED
    assert presence.calls == 1


@pytest.mark.anyio
async def test_codex_native_tree_migrates_as_one_directory_and_remove_rolls_back(
    tmp_path: Path,
) -> None:
    target = _target(tmp_path)
    install_plugin(
        IntegrationTarget(IntegrationScope.TRUSTED_PROJECT, str(tmp_path)),
        allow_untested=True,
    )
    native_before = {
        path.relative_to(tmp_path / AGENT_PLUGIN_ROOT).as_posix(): path.read_bytes()
        for path in (tmp_path / AGENT_PLUGIN_ROOT).rglob("*")
        if path.is_file()
    }
    adapter = PortablePluginArtifactAdapter(review=_SetupAuthority())
    replace_preview = await adapter.preview_artifact(
        request_id(_request(4)), target, PluginArtifactAction.REPLACE
    )
    assert replace_preview.state_before is PluginArtifactState.NATIVE_MANAGED
    assert replace_preview.rollback_digest == _tree_digest(native_before)
    await adapter.install_artifact(
        PluginArtifactApplyCommand(
            request_id(_request(4)),
            target,
            PluginArtifactAction.REPLACE,
            replace_preview.preview_digest,
            _setup_authority(replace_preview.preview_digest),
        )
    )
    remove_preview = await adapter.preview_artifact(
        request_id(_request(5)), target, PluginArtifactAction.REMOVE
    )
    assert remove_preview.rollback_digest == replace_preview.rollback_digest
    removed = await adapter.remove_artifact(
        PluginArtifactApplyCommand(
            request_id(_request(5)),
            target,
            PluginArtifactAction.REMOVE,
            remove_preview.preview_digest,
            _setup_authority(remove_preview.preview_digest),
        )
    )
    assert removed.state_after is PluginArtifactState.NATIVE_MANAGED
    native_after = {
        path.relative_to(tmp_path / AGENT_PLUGIN_ROOT).as_posix(): path.read_bytes()
        for path in (tmp_path / AGENT_PLUGIN_ROOT).rglob("*")
        if path.is_file()
    }
    assert native_after == native_before


@pytest.mark.anyio
@pytest.mark.parametrize("mutation", ["member", "renderer"])
async def test_self_consistent_noncanonical_native_tree_is_not_a_rollback_candidate(
    tmp_path: Path,
    mutation: str,
) -> None:
    target = _target(tmp_path)
    install_plugin(
        IntegrationTarget(IntegrationScope.TRUSTED_PROJECT, str(tmp_path)),
        allow_untested=True,
    )
    _make_native_tree_self_consistent_but_noncanonical(
        tmp_path / AGENT_PLUGIN_ROOT,
        mutation,
    )
    adapter = PortablePluginArtifactAdapter(review=_SetupAuthority())

    status = await adapter.status_artifact(PluginArtifactStatusCommand(target))
    assert status.state is PluginArtifactState.MODIFIED
    with pytest.raises(PluginArtifactError) as caught:
        await adapter.preview_artifact(
            request_id(_request(18)), target, PluginArtifactAction.REPLACE
        )
    assert caught.value.reason is PluginArtifactReason.DESTINATION_CONFLICT
    assert (tmp_path / AGENT_PLUGIN_ROOT).is_dir()


@pytest.mark.anyio
async def test_replace_rechecks_native_rollback_bytes_after_authority(tmp_path: Path) -> None:
    target = _target(tmp_path)
    install_plugin(
        IntegrationTarget(IntegrationScope.TRUSTED_PROJECT, str(tmp_path)),
        allow_untested=True,
    )
    native_root = tmp_path / AGENT_PLUGIN_ROOT
    adapter = PortablePluginArtifactAdapter(
        review=_MutatingSetupAuthority(
            lambda: _make_native_tree_self_consistent_but_noncanonical(native_root, "member")
        )
    )
    preview = await adapter.preview_artifact(
        request_id(_request(23)), target, PluginArtifactAction.REPLACE
    )

    with pytest.raises(PluginArtifactError) as caught:
        await adapter.install_artifact(
            PluginArtifactApplyCommand(
                request_id(_request(23)),
                target,
                PluginArtifactAction.REPLACE,
                preview.preview_digest,
                _setup_authority(preview.preview_digest),
            )
        )
    assert caught.value.reason is PluginArtifactReason.DESTINATION_CONFLICT
    assert native_root.is_dir()
    assert not (tmp_path / ".agents/plugins/.yoetz.plugin-native-rollback").exists()


@pytest.mark.anyio
@pytest.mark.parametrize("mutation", ["member", "renderer"])
async def test_self_consistent_noncanonical_rollback_is_preserved_and_refused(
    tmp_path: Path,
    mutation: str,
) -> None:
    target = _target(tmp_path)
    install_plugin(
        IntegrationTarget(IntegrationScope.TRUSTED_PROJECT, str(tmp_path)),
        allow_untested=True,
    )
    adapter = PortablePluginArtifactAdapter(review=_SetupAuthority())
    replace_preview = await adapter.preview_artifact(
        request_id(_request(19)), target, PluginArtifactAction.REPLACE
    )
    await adapter.install_artifact(
        PluginArtifactApplyCommand(
            request_id(_request(19)),
            target,
            PluginArtifactAction.REPLACE,
            replace_preview.preview_digest,
            _setup_authority(replace_preview.preview_digest),
        )
    )
    rollback = tmp_path / ".agents/plugins/.yoetz.plugin-native-rollback"
    remove_adapter = PortablePluginArtifactAdapter(
        review=_MutatingSetupAuthority(
            lambda: _make_native_tree_self_consistent_but_noncanonical(rollback, mutation)
        )
    )
    remove_preview = await remove_adapter.preview_artifact(
        request_id(_request(20)), target, PluginArtifactAction.REMOVE
    )

    with pytest.raises(PluginArtifactError) as caught:
        await remove_adapter.remove_artifact(
            PluginArtifactApplyCommand(
                request_id(_request(20)),
                target,
                PluginArtifactAction.REMOVE,
                remove_preview.preview_digest,
                _setup_authority(remove_preview.preview_digest),
            )
        )
    assert caught.value.reason is PluginArtifactReason.RECOVERY_REQUIRED
    status = await remove_adapter.status_artifact(PluginArtifactStatusCommand(target))
    assert status.state is PluginArtifactState.RECOVERY_REQUIRED
    assert status.rollback_available is False
    assert rollback.is_dir()
    assert (tmp_path / AGENT_PLUGIN_ROOT / "plugin.json").is_file()


@pytest.mark.anyio
async def test_remove_rejects_missing_previewed_rollback_before_mutation(tmp_path: Path) -> None:
    target = _target(tmp_path)
    install_plugin(
        IntegrationTarget(IntegrationScope.TRUSTED_PROJECT, str(tmp_path)),
        allow_untested=True,
    )
    adapter = PortablePluginArtifactAdapter(review=_SetupAuthority())
    replace_preview = await adapter.preview_artifact(
        request_id(_request(21)), target, PluginArtifactAction.REPLACE
    )
    await adapter.install_artifact(
        PluginArtifactApplyCommand(
            request_id(_request(21)),
            target,
            PluginArtifactAction.REPLACE,
            replace_preview.preview_digest,
            _setup_authority(replace_preview.preview_digest),
        )
    )
    remove_preview = await adapter.preview_artifact(
        request_id(_request(22)), target, PluginArtifactAction.REMOVE
    )
    rollback = tmp_path / ".agents/plugins/.yoetz.plugin-native-rollback"
    shutil.rmtree(rollback)

    with pytest.raises(PluginArtifactError) as caught:
        await adapter.remove_artifact(
            PluginArtifactApplyCommand(
                request_id(_request(22)),
                target,
                PluginArtifactAction.REMOVE,
                remove_preview.preview_digest,
                _setup_authority(remove_preview.preview_digest),
            )
        )
    assert caught.value.reason is PluginArtifactReason.PREVIEW_STALE
    assert (tmp_path / AGENT_PLUGIN_ROOT / "plugin.json").is_file()


@pytest.mark.anyio
async def test_symlinked_parent_is_refused_without_escape(tmp_path: Path) -> None:
    target = _target(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    (tmp_path / ".agents").symlink_to(outside, target_is_directory=True)
    adapter = PortablePluginArtifactAdapter(review=_SetupAuthority())
    with pytest.raises(PluginArtifactError) as caught:
        await adapter.preview_artifact(
            request_id(_request(6)), target, PluginArtifactAction.INSTALL
        )
    assert caught.value.reason is PluginArtifactReason.TARGET_UNSAFE
    assert not (outside / "plugins").exists()


@pytest.mark.anyio
async def test_interrupted_swap_is_reported_and_never_auto_repaired(
    tmp_path: Path,
) -> None:
    target = _target(tmp_path)
    parent = tmp_path / ".agents/plugins"
    parent.mkdir(parents=True, mode=0o700)
    (tmp_path / ".agents").chmod(0o700)
    parent.chmod(0o700)
    (parent / f".yoetz.plugin-stage-{_request(7)}").mkdir()
    adapter = PortablePluginArtifactAdapter()
    status = await adapter.status_artifact(PluginArtifactStatusCommand(target))
    assert status.state is PluginArtifactState.RECOVERY_REQUIRED
    assert (parent / f".yoetz.plugin-stage-{_request(7)}").is_dir()


@pytest.mark.anyio
async def test_ambiguous_rollback_is_preserved_and_blocks_preview(tmp_path: Path) -> None:
    target = _target(tmp_path)
    parent = tmp_path / ".agents/plugins"
    parent.mkdir(parents=True, mode=0o700)
    (tmp_path / ".agents").chmod(0o700)
    parent.chmod(0o700)
    outside = tmp_path / "ambiguous"
    outside.mkdir(mode=0o700)
    rollback = parent / ".yoetz.plugin-native-rollback"
    rollback.symlink_to(outside, target_is_directory=True)
    adapter = PortablePluginArtifactAdapter()
    status = await adapter.status_artifact(PluginArtifactStatusCommand(target))
    assert status.state is PluginArtifactState.RECOVERY_REQUIRED
    with pytest.raises(PluginArtifactError) as caught:
        await adapter.preview_artifact(
            request_id(_request(11)), target, PluginArtifactAction.INSTALL
        )
    assert caught.value.reason is PluginArtifactReason.RECOVERY_REQUIRED
    assert rollback.is_symlink()


@pytest.mark.anyio
async def test_mid_swap_failure_restores_native_and_records_unknown_outcome(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = _target(tmp_path)
    install_plugin(
        IntegrationTarget(IntegrationScope.TRUSTED_PROJECT, str(tmp_path)),
        allow_untested=True,
    )
    native_marker = (tmp_path / AGENT_PLUGIN_ROOT / ".yoetz-plugin-install.json").read_bytes()
    adapter = PortablePluginArtifactAdapter(review=_SetupAuthority())
    preview = await adapter.preview_artifact(
        request_id(_request(8)), target, PluginArtifactAction.REPLACE
    )
    real_replace = portable_mod.os.replace

    def _fail_stage(source: Path, destination: Path) -> None:
        if source.name.startswith(".yoetz.plugin-stage-") and destination.name == "yoetz":
            raise OSError("injected")
        real_replace(source, destination)

    monkeypatch.setattr(portable_mod.os, "replace", _fail_stage)
    command = PluginArtifactApplyCommand(
        request_id(_request(8)),
        target,
        PluginArtifactAction.REPLACE,
        preview.preview_digest,
        _setup_authority(preview.preview_digest),
    )
    with pytest.raises(PluginArtifactError) as caught:
        await adapter.install_artifact(command)
    assert caught.value.reason is PluginArtifactReason.WRITE_FAILED
    assert (
        tmp_path / AGENT_PLUGIN_ROOT / ".yoetz-plugin-install.json"
    ).read_bytes() == native_marker
    status = await adapter.status_artifact(PluginArtifactStatusCommand(target, command.request_id))
    assert status.operation_state is PluginOperationState.OUTCOME_UNKNOWN
