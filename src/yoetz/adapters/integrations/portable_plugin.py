"""Skills-only Agent Plugins 1.0.0 renderer and safe artifact lifecycle."""

from __future__ import annotations

import hashlib
import os
import shutil
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any, Final, Literal, Protocol, cast

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from yoetz import __version__
from yoetz.adapters.integrations.codex_plugin import render_plugin_install_tree
from yoetz.domain.values import RequestId
from yoetz.domain.values import request_id as validate_request_id
from yoetz.ports.plugin_artifacts import (
    ArtifactAuthority,
    ArtifactTarget,
    ManagedPluginFile,
    McpOwnership,
    McpOwnershipState,
    PluginArtifactAction,
    PluginArtifactApplyCommand,
    PluginArtifactError,
    PluginArtifactPort,
    PluginArtifactPreview,
    PluginArtifactReason,
    PluginArtifactResult,
    PluginArtifactState,
    PluginArtifactStatus,
    PluginArtifactStatusCommand,
    PluginFormatProfile,
    PluginMutationReviewPort,
    PluginOperationState,
    PluginProofFacet,
    PluginProofStatus,
    PortablePluginPlan,
)
from yoetz.protocol.canonical import (
    JsonValue,
    canonical_digest,
    canonical_encode,
    strict_json_parse,
)
from yoetz.protocol.errors import ProtocolValueError
from yoetz.protocol.guidance_uris import FOCUSED_GUIDANCE_URIS, GUIDANCE_DOCUMENT_URIS

__all__ = [
    "AGENT_PLUGIN_ROOT",
    "ArtifactUserPresencePort",
    "ManifestValidation",
    "McpConfigValidation",
    "PluginManagedMcpObservation",
    "PackagedPortableResources",
    "ElevatedPortableArtifactReview",
    "PortablePluginArtifactAdapter",
    "PortableTreeValidation",
    "RenderedPortablePlugin",
    "build_portable_plugin_plan",
    "combine_mcp_ownership_states",
    "render_portable_plugin_tree",
    "prepare_portable_artifact_review",
    "observe_plugin_managed_mcp",
    "validate_agent_plugin_manifest",
    "validate_agent_plugin_mcp",
    "validate_portable_skill",
    "validate_portable_plugin_tree",
]

AGENT_PLUGIN_ROOT: Final = ".agents/plugins/yoetz"
_PLUGIN_SCHEMA_PATH: Final = "support/agent-plugins/1.0.0/plugin.schema.json"
_MCP_SCHEMA_PATH: Final = "support/agent-plugins/1.0.0/mcp.schema.json"
_SKILL_PATH: Final = "skills/portable/yoetz/SKILL.md"
_SKILL_PATH_BY_HOST: Final[Mapping[str, str]] = {
    "portable": _SKILL_PATH,
    "cursor": "skills/cursor/yoetz/SKILL.md",
}
_GUIDANCE_URI_PREFIX: Final = "yoetz://guidance/"
_GUIDANCE_NAMES: Final = tuple(
    uri.removeprefix(_GUIDANCE_URI_PREFIX)
    for uri in (*GUIDANCE_DOCUMENT_URIS, *FOCUSED_GUIDANCE_URIS)
)
_SCHEMA_ID: Final = "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json"
_MCP_SCHEMA_ID: Final = "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json"
_PLUGIN_SCHEMA_SHA: Final = (
    "sha256:0a4aad95ce337878ad38802ebf0daa3fde76abe3f65400c86bcbb1ec0b3ab883"
)
_MCP_SCHEMA_SHA: Final = "sha256:6539175bfcdf43085855183e86da40ea94b166547a72b47ae9a0a390516d3acb"
_RENDERER_VERSION: Final = "portable-plugin/0.1.0"
_MARKER_NAME: Final = ".yoetz-plugin-install.json"
_MARKER_SCHEMA: Final = "yoetz.portable-plugin-install/1"
_NATIVE_MARKER_SCHEMA: Final = "yoetz.codex-plugin-install/1"
_STAGE_PREFIX: Final = ".yoetz.plugin-stage-"
_REMOVE_PREFIX: Final = ".yoetz.plugin-remove-"
_NATIVE_ROLLBACK_NAME: Final = ".yoetz.plugin-native-rollback"
_MAX_FILE_BYTES: Final = 262_144
_MAX_TREE_FILES: Final = 64
_PLUGIN_ALLOWED_FIELDS: Final = frozenset(
    {
        "$schema",
        "author",
        "description",
        "extensions",
        "homepage",
        "keywords",
        "license",
        "name",
        "repository",
        "version",
    }
)


class PortableResourceSource(Protocol):
    def read_bytes(self, package_path: str) -> bytes: ...


class _JsonSchemaValidator(Protocol):
    def iter_errors(self, instance: object) -> Iterable[ValidationError]: ...


class ArtifactUserPresencePort(Protocol):
    def verify_artifact_review(self, authority: ArtifactAuthority) -> None: ...


class PackagedPortableResources:
    """Read only the packaged resource tree; callers cannot select ambient files."""

    def read_bytes(self, package_path: str) -> bytes:
        node = resources.files("yoetz.resources")
        for part in package_path.split("/"):
            node = node.joinpath(part)
        return node.read_bytes()


@dataclass(frozen=True, slots=True)
class ManifestValidation:
    accepted: bool
    unknown_fields: tuple[str, ...]
    fatal_field: str | None


@dataclass(frozen=True, slots=True)
class McpConfigValidation:
    top_level_valid: bool
    loaded_server_count: int
    skipped_server_count: int
    diagnostics: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PluginManagedMcpObservation:
    ownership_state: McpOwnershipState
    route_profile: Literal["strict", "policy"] | None
    observed: bool


def combine_mcp_ownership_states(
    external: McpOwnershipState,
    plugin: McpOwnershipState,
) -> McpOwnershipState:
    """Combine separately observed sources without treating an unobserved source as absent."""

    if type(external) is not McpOwnershipState or type(plugin) is not McpOwnershipState:
        return McpOwnershipState.AMBIGUOUS
    if external is McpOwnershipState.AMBIGUOUS or plugin is McpOwnershipState.AMBIGUOUS:
        return McpOwnershipState.AMBIGUOUS
    if external is McpOwnershipState.FOREIGN or plugin is McpOwnershipState.FOREIGN:
        return McpOwnershipState.FOREIGN
    if external is McpOwnershipState.EXTERNAL and plugin is McpOwnershipState.PLUGIN:
        return McpOwnershipState.DUAL
    if external is McpOwnershipState.EXTERNAL and plugin is McpOwnershipState.ABSENT:
        return McpOwnershipState.EXTERNAL
    if external is McpOwnershipState.ABSENT and plugin is McpOwnershipState.PLUGIN:
        return McpOwnershipState.PLUGIN
    if external is McpOwnershipState.ABSENT and plugin is McpOwnershipState.ABSENT:
        return McpOwnershipState.ABSENT
    return McpOwnershipState.AMBIGUOUS


@dataclass(frozen=True, slots=True)
class RenderedPortablePlugin:
    plan: PortablePluginPlan
    members: Mapping[str, bytes]
    artifact_digest: str


@dataclass(frozen=True, slots=True)
class PortableTreeValidation:
    manifest: ManifestValidation
    loaded_components: tuple[str, ...]
    skipped_components: tuple[str, ...]
    diagnostics: tuple[str, ...]


@dataclass(frozen=True, slots=True, repr=False)
class _Inspection:
    root: Path
    parent: Path
    destination: Path
    state: PluginArtifactState
    target_identity: str
    current_state_digest: str
    installed_digest: str | None
    marker_valid: bool
    rollback_digest: str | None

    @property
    def rollback_available(self) -> bool:
        return self.rollback_digest is not None

    def __repr__(self) -> str:
        return (
            "_Inspection("
            f"state={self.state.value!r}, installed_digest={self.installed_digest!r}, "
            f"marker_valid={self.marker_valid!r}, rollback_available={self.rollback_available!r}, "
            "target=<redacted>)"
        )


def _error(
    reason: PluginArtifactReason,
    details: Mapping[str, JsonValue] | None = None,
) -> PluginArtifactError:
    return PluginArtifactError(reason, {} if details is None else details)


def _sha(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _load_json(raw: bytes, reason: PluginArtifactReason) -> Mapping[str, JsonValue]:
    if len(raw) > _MAX_FILE_BYTES:
        raise _error(reason)
    try:
        parsed = strict_json_parse(raw)
    except (ProtocolValueError, UnicodeError) as exc:
        raise _error(reason) from exc
    if not isinstance(parsed, Mapping):
        raise _error(reason)
    return cast(Mapping[str, JsonValue], parsed)


def _field_from_jsonschema_path(path: Sequence[str | int]) -> str:
    parts = tuple(path)
    if not parts:
        return "manifest"
    first = parts[0]
    return first if type(first) is str and first in _PLUGIN_ALLOWED_FIELDS else "manifest"


def validate_agent_plugin_manifest(
    raw: bytes,
    *,
    schema_bytes: bytes,
) -> ManifestValidation:
    """Validate fatal known fields while reporting and ignoring unknown top-level fields."""

    try:
        manifest = _load_json(raw, PluginArtifactReason.MANIFEST_INVALID)
        schema = _load_json(schema_bytes, PluginArtifactReason.SOURCE_INVALID)
    except PluginArtifactError:
        return ManifestValidation(False, (), "manifest")
    unknown = tuple(sorted(set(manifest) - _PLUGIN_ALLOWED_FIELDS, key=str.encode))
    known = {key: value for key, value in manifest.items() if key in _PLUGIN_ALLOWED_FIELDS}
    validator = cast(_JsonSchemaValidator, Draft202012Validator(cast(Any, schema)))
    errors: list[ValidationError] = sorted(
        validator.iter_errors(known),
        key=lambda item: (tuple(str(part) for part in item.absolute_path), item.message),
    )
    if errors:
        return ManifestValidation(
            False,
            unknown,
            _field_from_jsonschema_path(errors[0].absolute_path),
        )
    return ManifestValidation(True, unknown, None)


def validate_agent_plugin_mcp(
    raw: bytes,
    *,
    schema_bytes: bytes,
    supported_transports: tuple[str, ...] = ("stdio",),
    connection_failures: Mapping[
        str, Literal["executable", "start", "connect", "auth", "handshake"]
    ]
    | None = None,
) -> McpConfigValidation:
    """Validate MCP with Agent Plugins' top-level and per-server failure boundaries."""

    failures: Mapping[str, Literal["executable", "start", "connect", "auth", "handshake"]] = (
        {} if connection_failures is None else connection_failures
    )
    try:
        document = _load_json(raw, PluginArtifactReason.SOURCE_INVALID)
        schema = _load_json(schema_bytes, PluginArtifactReason.SOURCE_INVALID)
    except PluginArtifactError:
        return McpConfigValidation(False, 0, 0, ("mcp_config_invalid",))
    if set(document) != {"$schema", "mcpServers"} or document.get("$schema") != _MCP_SCHEMA_ID:
        return McpConfigValidation(False, 0, 0, ("mcp_config_invalid",))
    servers = document.get("mcpServers")
    if not isinstance(servers, Mapping):
        return McpConfigValidation(False, 0, 0, ("mcp_config_invalid",))
    validator = cast(_JsonSchemaValidator, Draft202012Validator(cast(Any, schema)))
    loaded_count = 0
    skipped_count = 0
    diagnostics: list[str] = []
    for raw_name, raw_server in sorted(servers.items(), key=lambda item: str(item[0]).encode()):
        if type(raw_name) is not str:
            return McpConfigValidation(False, 0, 0, ("mcp_config_invalid",))
        candidate = {"$schema": _MCP_SCHEMA_ID, "mcpServers": {raw_name: raw_server}}
        if next(iter(validator.iter_errors(candidate)), None) is not None:
            skipped_count += 1
            diagnostics.append("mcp_server_invalid")
            continue
        server = cast(Mapping[str, object], raw_server)
        transport = server.get("type")
        if transport == "stdio" and not _stdio_server_paths_valid(server):
            skipped_count += 1
            diagnostics.append("mcp_server_invalid")
            continue
        if type(transport) is not str or transport not in supported_transports:
            skipped_count += 1
            diagnostics.append("mcp_transport_unsupported")
            continue
        failure = failures.get(raw_name)
        if failure is not None:
            skipped_count += 1
            diagnostics.append(
                "mcp_executable_missing" if failure == "executable" else f"mcp_{failure}_failed"
            )
            continue
        loaded_count += 1
    return McpConfigValidation(
        True,
        loaded_count,
        skipped_count,
        tuple(diagnostics),
    )


def _contained_relative(value: str, prefix: str) -> bool:
    if value == prefix.removesuffix("/"):
        return True
    if not value.startswith(prefix):
        return False
    parts = value.removeprefix(prefix).split("/")
    return bool(parts) and all(part not in {"", ".", ".."} for part in parts)


def _stdio_server_paths_valid(server: Mapping[str, object]) -> bool:
    command = server.get("command")
    if type(command) is not str:
        return False
    if command.startswith("./"):
        if not _contained_relative(command, "./"):
            return False
    elif not command or "/" in command or "\\" in command or "${" in command:
        return False
    cwd = server.get("cwd")
    if cwd is not None:
        if type(cwd) is not str or not any(
            _contained_relative(cwd, prefix)
            for prefix in ("./", "${PLUGIN_ROOT}/", "${PLUGIN_DATA}/")
        ):
            return False
    env = server.get("env")
    if isinstance(env, Mapping):
        env_map = cast(Mapping[str, object], env)
        if {"PLUGIN_ROOT", "PLUGIN_DATA"}.intersection(env_map):
            return False
    return True


def validate_portable_skill(raw: bytes) -> None:
    """Validate the portable Agent Skills subset used by the immediate-child skill."""

    if len(raw) > _MAX_FILE_BYTES or not raw.endswith(b"\n") or b"\r" in raw:
        raise _error(PluginArtifactReason.SOURCE_INVALID)
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise _error(PluginArtifactReason.SOURCE_INVALID) from exc
    if not text.startswith("---\n") or "\n---\n" not in text[4:]:
        raise _error(PluginArtifactReason.SOURCE_INVALID)
    header = text[4 : text.index("\n---\n", 4)]
    lines = header.splitlines()
    fields = tuple(line.split(":", 1)[0] for line in lines if line and not line.startswith(" "))
    if set(fields) != {"name", "description"} or len(fields) != 2:
        raise _error(PluginArtifactReason.SOURCE_INVALID)
    if "name: yoetz" not in lines or not any(line.startswith("description: ") for line in lines):
        raise _error(PluginArtifactReason.SOURCE_INVALID)
    forbidden = ("allowed-tools:", "compatibility:", "metadata:")
    if any(line.startswith(forbidden) for line in lines):
        raise _error(PluginArtifactReason.SOURCE_INVALID)


def validate_portable_plugin_tree(
    members: Mapping[str, bytes],
    *,
    schema_bytes: bytes,
    mcp_schema_bytes: bytes | None = None,
    supported_mcp_transports: tuple[str, ...] = ("stdio",),
    mcp_connection_failures: Mapping[
        str, Literal["executable", "start", "connect", "auth", "handshake"]
    ]
    | None = None,
) -> PortableTreeValidation:
    """Apply Agent Plugins component boundaries without upgrading them to activation proof."""

    manifest_raw = members.get("plugin.json")
    if manifest_raw is None:
        manifest = ManifestValidation(False, (), "manifest")
        return PortableTreeValidation(manifest, (), (), ("manifest_missing",))
    manifest = validate_agent_plugin_manifest(manifest_raw, schema_bytes=schema_bytes)
    if not manifest.accepted:
        return PortableTreeValidation(manifest, (), (), ("manifest_invalid",))
    skill = members.get("skills/yoetz/SKILL.md")
    if skill is None:
        return PortableTreeValidation(
            manifest,
            ("manifest",),
            ("skills/yoetz",),
            ("skill_missing",),
        )
    try:
        validate_portable_skill(skill)
    except PluginArtifactError:
        return PortableTreeValidation(
            manifest,
            ("manifest",),
            ("skills/yoetz",),
            ("skill_frontmatter_invalid",),
        )
    loaded = ["manifest", "skills/yoetz"]
    skipped: list[str] = []
    diagnostics: list[str] = []
    mcp_raw = members.get("mcp.json")
    if mcp_raw is not None:
        if mcp_schema_bytes is None:
            skipped.append("mcp")
            diagnostics.append("mcp_schema_unavailable")
        else:
            mcp = validate_agent_plugin_mcp(
                mcp_raw,
                schema_bytes=mcp_schema_bytes,
                supported_transports=supported_mcp_transports,
                connection_failures=mcp_connection_failures,
            )
            if not mcp.top_level_valid:
                skipped.append("mcp")
            else:
                if mcp.loaded_server_count:
                    loaded.append("mcp")
                if mcp.skipped_server_count:
                    skipped.append("mcp_server")
            diagnostics.extend(mcp.diagnostics)
    return PortableTreeValidation(
        manifest,
        tuple(loaded),
        tuple(skipped),
        tuple(diagnostics),
    )


def _source(source: PortableResourceSource | None) -> PortableResourceSource:
    return PackagedPortableResources() if source is None else source


def _read_verified_source(source: PortableResourceSource, path: str) -> bytes:
    try:
        data = source.read_bytes(path)
    except (FileNotFoundError, ModuleNotFoundError, OSError) as exc:
        raise _error(PluginArtifactReason.SOURCE_INVALID) from exc
    if len(data) > _MAX_FILE_BYTES:
        raise _error(PluginArtifactReason.SOURCE_INVALID)
    return data


def _plugin_json() -> bytes:
    body: dict[str, JsonValue] = {
        "$schema": _SCHEMA_ID,
        "author": {
            "name": "Yoetz contributors",
            "url": "https://github.com/TheGaySupreme123/yoetz",
        },
        "description": (
            "Yoetz cooperative work-ledger guidance. Artifact validation or installation does "
            "not establish host activation, observation, provider dispatch, or completion."
        ),
        "homepage": "https://github.com/TheGaySupreme123/yoetz",
        "license": "Apache-2.0",
        "name": "yoetz",
        "repository": "https://github.com/TheGaySupreme123/yoetz",
        "version": __version__,
    }
    return canonical_encode(body) + b"\n"


def _mcp_json(route_profile: Literal["strict", "policy"]) -> bytes:
    args = ["mcp", "serve"]
    if route_profile == "strict":
        args.extend(("--semantic", "off"))
    body = cast(
        dict[str, JsonValue],
        {
            "$schema": _MCP_SCHEMA_ID,
            "mcpServers": {
                "yoetz": {
                    "args": args,
                    "command": "yoetz",
                    "type": "stdio",
                }
            },
        },
    )
    return canonical_encode(body) + b"\n"


def _inventory(members: Mapping[str, bytes]) -> tuple[ManagedPluginFile, ...]:
    return tuple(
        ManagedPluginFile(path, len(data), _sha(data))
        for path, data in sorted(members.items(), key=lambda item: item[0].encode("ascii"))
    )


def _artifact_digest(
    inventory: tuple[ManagedPluginFile, ...],
    *,
    mcp_ownership: McpOwnership,
    mcp_route_profile: Literal["strict", "policy"] | None,
) -> str:
    return canonical_digest(
        {
            "format_profile": PluginFormatProfile.AGENT_PLUGINS_1.value,
            "inventory": [
                {
                    "relative_path": item.relative_path,
                    "sha256": item.sha256,
                    "size": item.size,
                }
                for item in inventory
            ],
            "mcp_ownership": mcp_ownership.value,
            "mcp_route_profile": mcp_route_profile,
            "renderer_version": _RENDERER_VERSION,
            "schema_version": "1.0.0",
        }
    )


def build_portable_plugin_plan(
    *,
    resource_source: PortableResourceSource | None = None,
    mcp_ownership: McpOwnership = McpOwnership.EXTERNAL_REGISTRATION,
    mcp_route_profile: Literal["strict", "policy"] | None = None,
    skill_host: Literal["portable", "cursor"] = "portable",
) -> RenderedPortablePlugin:
    if type(skill_host) is not str or skill_host not in _SKILL_PATH_BY_HOST:
        raise _error(PluginArtifactReason.SOURCE_INVALID)
    if type(mcp_ownership) is not McpOwnership or (
        mcp_ownership is McpOwnership.PLUGIN_MANAGED
    ) != (mcp_route_profile in {"strict", "policy"}):
        raise _error(PluginArtifactReason.SOURCE_INVALID)
    source = _source(resource_source)
    schema = _read_verified_source(source, _PLUGIN_SCHEMA_PATH)
    mcp_schema = _read_verified_source(source, _MCP_SCHEMA_PATH)
    if _sha(schema) != _PLUGIN_SCHEMA_SHA or _sha(mcp_schema) != _MCP_SCHEMA_SHA:
        raise _error(PluginArtifactReason.SOURCE_INVALID)
    skill_path = _SKILL_PATH_BY_HOST[skill_host]
    skill = _read_verified_source(source, skill_path)
    validate_portable_skill(skill)
    members: dict[str, bytes] = {
        "plugin.json": _plugin_json(),
        "skills/yoetz/SKILL.md": skill,
    }
    if mcp_ownership is McpOwnership.PLUGIN_MANAGED:
        assert mcp_route_profile in {"strict", "policy"}
        members["mcp.json"] = _mcp_json(mcp_route_profile)
    for name in _GUIDANCE_NAMES:
        data = _read_verified_source(source, f"guidance/{name}")
        if not data.endswith(b"\n") or b"\r" in data:
            raise _error(PluginArtifactReason.SOURCE_INVALID)
        members[f"skills/yoetz/references/{name}"] = data
    validation = validate_portable_plugin_tree(
        members,
        schema_bytes=schema,
        mcp_schema_bytes=mcp_schema,
    )
    if (
        not validation.manifest.accepted
        or validation.manifest.unknown_fields
        or validation.skipped_components
    ):
        raise _error(
            PluginArtifactReason.MANIFEST_INVALID,
            {"fatal_field": validation.manifest.fatal_field or "manifest"},
        )
    inventory = _inventory(members)
    plan = PortablePluginPlan(
        name="yoetz",
        version=__version__,
        description=(
            "Yoetz cooperative work-ledger guidance carrier; no host activation or authority claim."
        ),
        format_profile=PluginFormatProfile.AGENT_PLUGINS_1,
        mcp_ownership=mcp_ownership,
        mcp_route_profile=mcp_route_profile,
        host_extension_profile=None,
        specification_version="1.0.0",
        renderer_version=_RENDERER_VERSION,
        source_refs=tuple(
            sorted(
                {
                    _MCP_SCHEMA_PATH,
                    _PLUGIN_SCHEMA_PATH,
                    skill_path,
                    *(f"guidance/{name}" for name in _GUIDANCE_NAMES),
                },
                key=str.encode,
            )
        ),
        inventory=inventory,
    )
    return RenderedPortablePlugin(
        plan,
        members,
        _artifact_digest(
            inventory,
            mcp_ownership=mcp_ownership,
            mcp_route_profile=mcp_route_profile,
        ),
    )


def render_portable_plugin_tree(
    *,
    resource_source: PortableResourceSource | None = None,
    mcp_ownership: McpOwnership = McpOwnership.EXTERNAL_REGISTRATION,
    mcp_route_profile: Literal["strict", "policy"] | None = None,
) -> dict[str, bytes]:
    return dict(
        build_portable_plugin_plan(
            resource_source=resource_source,
            mcp_ownership=mcp_ownership,
            mcp_route_profile=mcp_route_profile,
        ).members
    )


def _marker(rendered: RenderedPortablePlugin) -> bytes:
    body: dict[str, JsonValue] = {
        "artifact_digest": rendered.artifact_digest,
        "format_profile": rendered.plan.format_profile.value,
        "managed_files": [
            {
                "relative_path": item.relative_path,
                "sha256": item.sha256,
                "size": item.size,
            }
            for item in rendered.plan.inventory
        ],
        "mcp_ownership": rendered.plan.mcp_ownership.value,
        "mcp_route_profile": rendered.plan.mcp_route_profile,
        "renderer_version": rendered.plan.renderer_version,
        "schema": _MARKER_SCHEMA,
        "schema_version": rendered.plan.specification_version,
        "yoetz_version": rendered.plan.version,
    }
    body["marker_digest"] = canonical_digest(body)
    return canonical_encode(body) + b"\n"


def _validate_project(target: ArtifactTarget) -> tuple[Path, str]:
    if type(target) is not ArtifactTarget:
        raise _error(PluginArtifactReason.TARGET_UNTRUSTED)
    root = Path(target.project_root)
    if not root.is_absolute():
        root = Path.cwd() / root
    if root == Path(root.anchor) or root == Path.home() or root.is_symlink() or not root.is_dir():
        raise _error(PluginArtifactReason.TARGET_UNTRUSTED)
    current = Path(root.anchor)
    for part in root.parts[1:]:
        current /= part
        if current.is_symlink():
            raise _error(PluginArtifactReason.TARGET_UNSAFE)
    try:
        facts = root.stat()
    except OSError as exc:
        raise _error(PluginArtifactReason.TARGET_UNSAFE) from exc
    if hasattr(os, "geteuid") and facts.st_uid != os.geteuid():
        raise _error(PluginArtifactReason.TARGET_UNSAFE)
    if facts.st_mode & 0o022:
        raise _error(PluginArtifactReason.TARGET_UNSAFE)
    return root, canonical_digest(
        {"device": facts.st_dev, "inode": facts.st_ino, "mode": facts.st_mode & 0o777}
    )


def _plugin_parent(root: Path, *, create: bool) -> Path:
    current = root
    for component in (".agents", "plugins"):
        candidate = current / component
        if not candidate.exists() and not candidate.is_symlink():
            if not create:
                return root / ".agents" / "plugins"
            try:
                candidate.mkdir(mode=0o700)
            except OSError as exc:
                raise _error(PluginArtifactReason.WRITE_FAILED) from exc
        if candidate.is_symlink() or not candidate.is_dir():
            raise _error(PluginArtifactReason.TARGET_UNSAFE)
        facts = candidate.stat()
        if (hasattr(os, "geteuid") and facts.st_uid != os.geteuid()) or facts.st_mode & 0o022:
            raise _error(PluginArtifactReason.TARGET_UNSAFE)
        current = candidate
    return current


def _safe_tree_files(root: Path) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix().encode("utf-8")):
        if path.is_symlink():
            raise _error(PluginArtifactReason.TARGET_UNSAFE)
        if path.is_dir():
            continue
        if not path.is_file() or path.stat().st_nlink != 1 or path.stat().st_size > _MAX_FILE_BYTES:
            raise _error(PluginArtifactReason.TARGET_UNSAFE)
        relative = path.relative_to(root).as_posix()
        if len(files) >= _MAX_TREE_FILES:
            raise _error(PluginArtifactReason.TARGET_UNSAFE)
        files[relative] = path.read_bytes()
    return files


def _tree_digest(files: Mapping[str, bytes]) -> str:
    return canonical_digest(
        {
            "files": [
                {"relative_path": path, "sha256": _sha(data), "size": len(data)}
                for path, data in sorted(files.items(), key=lambda item: item[0].encode("ascii"))
            ]
        }
    )


def _parsed_marker(files: Mapping[str, bytes]) -> Mapping[str, JsonValue] | None:
    raw = files.get(_MARKER_NAME)
    if raw is None:
        return None
    try:
        return _load_json(raw, PluginArtifactReason.SOURCE_INVALID)
    except PluginArtifactError:
        return None


def observe_plugin_managed_mcp(project_root: Path) -> PluginManagedMcpObservation:
    """Observe a managed portable route without inferring activation or runtime success."""

    try:
        root, _identity = _validate_project(ArtifactTarget(str(project_root)))
        destination = _plugin_parent(root, create=False) / "yoetz"
        if not destination.exists():
            return PluginManagedMcpObservation(McpOwnershipState.ABSENT, None, True)
        if destination.is_symlink() or not destination.is_dir():
            return PluginManagedMcpObservation(McpOwnershipState.AMBIGUOUS, None, False)
        files = _safe_tree_files(destination)
    except OSError, PluginArtifactError, ValueError:
        return PluginManagedMcpObservation(McpOwnershipState.AMBIGUOUS, None, False)
    mcp_raw = files.get("mcp.json")
    if mcp_raw is None:
        return PluginManagedMcpObservation(McpOwnershipState.ABSENT, None, True)
    marker = _parsed_marker(files)
    if marker is None or not _marker_self_valid(marker):
        return PluginManagedMcpObservation(McpOwnershipState.FOREIGN, None, True)
    route = marker.get("mcp_route_profile")
    if (
        marker.get("schema") != _MARKER_SCHEMA
        or marker.get("mcp_ownership") != McpOwnership.PLUGIN_MANAGED.value
        or route not in {"strict", "policy"}
        or mcp_raw != _mcp_json(cast(Literal["strict", "policy"], route))
    ):
        return PluginManagedMcpObservation(McpOwnershipState.AMBIGUOUS, None, True)
    recorded_valid, _artifact = _recorded_tree_valid(files, marker)
    if not recorded_valid:
        return PluginManagedMcpObservation(McpOwnershipState.AMBIGUOUS, None, True)
    return PluginManagedMcpObservation(
        McpOwnershipState.PLUGIN,
        cast(Literal["strict", "policy"], route),
        True,
    )


def _marker_self_valid(marker: Mapping[str, JsonValue]) -> bool:
    digest = marker.get("marker_digest")
    if type(digest) is not str:
        return False
    body = {key: value for key, value in marker.items() if key != "marker_digest"}
    return digest == canonical_digest(body)


def _recorded_tree_valid(
    files: Mapping[str, bytes], marker: Mapping[str, JsonValue]
) -> tuple[bool, str | None]:
    rows = marker.get("managed_files")
    if type(rows) is not list:
        return False, None
    recorded: dict[str, tuple[int, str]] = {}
    for raw in rows:
        if not isinstance(raw, Mapping):
            return False, None
        path = raw.get("relative_path")
        size = raw.get("size")
        digest = raw.get("sha256")
        if (
            type(path) is not str
            or type(size) is not int
            or type(digest) is not str
            or path in recorded
        ):
            return False, None
        recorded[path] = (size, digest)
    content = {path: data for path, data in files.items() if path != _MARKER_NAME}
    if set(recorded) != set(content):
        return False, None
    for path, data in content.items():
        if recorded[path] != (len(data), _sha(data)):
            return False, None
    artifact = marker.get("artifact_digest")
    return True, artifact if type(artifact) is str else _tree_digest(content)


def _canonical_native_tree_digest(
    path: Path,
    canonical_members: Mapping[str, bytes],
) -> str | None:
    if path.is_symlink() or not path.is_dir():
        return None
    try:
        files = _safe_tree_files(path)
    except OSError, PluginArtifactError:
        return None
    if files != canonical_members:
        return None
    return _tree_digest(files)


def _inspect(
    target: ArtifactTarget,
    rendered: RenderedPortablePlugin,
    resource_source: PortableResourceSource | None,
) -> _Inspection:
    canonical_native_members: Mapping[str, bytes] | None = None

    def _canonical_native_members() -> Mapping[str, bytes]:
        nonlocal canonical_native_members
        if canonical_native_members is None:
            canonical_native_members = render_plugin_install_tree(resource_source=resource_source)
        return canonical_native_members

    root, target_identity = _validate_project(target)
    parent = _plugin_parent(root, create=False)
    destination = parent / "yoetz"
    rollback = parent / _NATIVE_ROLLBACK_NAME
    rollback_present = rollback.exists() or rollback.is_symlink()
    rollback_digest = (
        _canonical_native_tree_digest(rollback, _canonical_native_members())
        if rollback_present
        else None
    )
    if rollback_present and rollback_digest is None:
        return _Inspection(
            root,
            parent,
            destination,
            PluginArtifactState.RECOVERY_REQUIRED,
            target_identity,
            canonical_digest({"state": "rollback_ambiguous"}),
            None,
            False,
            None,
        )
    if parent.exists():
        interrupted = any(
            path.name.startswith((_STAGE_PREFIX, _REMOVE_PREFIX)) for path in parent.iterdir()
        )
        if interrupted:
            return _Inspection(
                root,
                parent,
                destination,
                PluginArtifactState.RECOVERY_REQUIRED,
                target_identity,
                canonical_digest({"state": "recovery_required"}),
                None,
                False,
                rollback_digest,
            )
    if not destination.exists():
        if rollback_digest is not None:
            return _Inspection(
                root,
                parent,
                destination,
                PluginArtifactState.RECOVERY_REQUIRED,
                target_identity,
                canonical_digest({"state": "rollback_without_destination"}),
                None,
                False,
                rollback_digest,
            )
        return _Inspection(
            root,
            parent,
            destination,
            PluginArtifactState.ABSENT,
            target_identity,
            canonical_digest({"state": "absent"}),
            None,
            False,
            None,
        )
    if destination.is_symlink() or not destination.is_dir():
        raise _error(PluginArtifactReason.TARGET_UNSAFE)
    files = _safe_tree_files(destination)
    current_digest = _tree_digest(files)
    marker = _parsed_marker(files)
    if marker is None or not _marker_self_valid(marker):
        return _Inspection(
            root,
            parent,
            destination,
            PluginArtifactState.UNMANAGED,
            target_identity,
            current_digest,
            None,
            False,
            rollback_digest,
        )
    recorded_valid, installed_digest = _recorded_tree_valid(files, marker)
    if not recorded_valid:
        return _Inspection(
            root,
            parent,
            destination,
            PluginArtifactState.MODIFIED,
            target_identity,
            current_digest,
            installed_digest,
            False,
            rollback_digest,
        )
    schema = marker.get("schema")
    if schema == _NATIVE_MARKER_SCHEMA:
        state = (
            PluginArtifactState.NATIVE_MANAGED
            if files == _canonical_native_members()
            else PluginArtifactState.MODIFIED
        )
    elif schema == _MARKER_SCHEMA:
        state = (
            PluginArtifactState.PORTABLE_EXACT
            if files == {**rendered.members, _MARKER_NAME: _marker(rendered)}
            else PluginArtifactState.PORTABLE_MANAGED
        )
    else:
        state = PluginArtifactState.UNMANAGED
    return _Inspection(
        root,
        parent,
        destination,
        state,
        target_identity,
        current_digest,
        installed_digest,
        state is not PluginArtifactState.UNMANAGED,
        rollback_digest,
    )


def _preview(
    request: RequestId,
    action: PluginArtifactAction,
    inspection: _Inspection,
    rendered: RenderedPortablePlugin,
    mcp_owner_state: McpOwnershipState,
) -> PluginArtifactPreview:
    if inspection.state is PluginArtifactState.RECOVERY_REQUIRED:
        raise _error(PluginArtifactReason.RECOVERY_REQUIRED)
    if inspection.state is PluginArtifactState.UNSAFE:
        raise _error(PluginArtifactReason.TARGET_UNSAFE)
    if (
        action is PluginArtifactAction.INSTALL
        and inspection.state is not PluginArtifactState.ABSENT
    ):
        raise _error(PluginArtifactReason.DESTINATION_CONFLICT)
    if action is PluginArtifactAction.REPLACE and inspection.state not in {
        PluginArtifactState.NATIVE_MANAGED,
        PluginArtifactState.PORTABLE_EXACT,
        PluginArtifactState.PORTABLE_MANAGED,
    }:
        raise _error(PluginArtifactReason.DESTINATION_CONFLICT)
    if action is PluginArtifactAction.REMOVE and inspection.state not in {
        PluginArtifactState.PORTABLE_EXACT,
        PluginArtifactState.PORTABLE_MANAGED,
    }:
        raise _error(PluginArtifactReason.REMOVE_REFUSED)
    if inspection.rollback_available and inspection.state is PluginArtifactState.NATIVE_MANAGED:
        raise _error(PluginArtifactReason.RECOVERY_REQUIRED)
    allowed_owner_states = (
        {McpOwnershipState.EXTERNAL}
        if rendered.plan.mcp_ownership is McpOwnership.EXTERNAL_REGISTRATION
        else {McpOwnershipState.ABSENT, McpOwnershipState.PLUGIN}
    )
    if mcp_owner_state not in allowed_owner_states:
        raise _error(
            PluginArtifactReason.MCP_OWNERSHIP_CONFLICT,
            {"mcp_ownership_state": mcp_owner_state.value},
        )
    effective = (
        PluginArtifactAction.NOOP
        if inspection.state is PluginArtifactState.PORTABLE_EXACT
        and action in {PluginArtifactAction.INSTALL, PluginArtifactAction.REPLACE}
        else action
    )
    warnings = tuple(
        sorted(
            {
                "format_validation_does_not_prove_activation",
                "mcp_runtime_not_observed",
                (
                    "mcp_ownership_remains_external_registration"
                    if rendered.plan.mcp_ownership is McpOwnership.EXTERNAL_REGISTRATION
                    else "plugin_activation_is_not_disclosure_consent"
                ),
            },
            key=str.encode,
        )
    )
    rollback_digest = (
        inspection.current_state_digest
        if inspection.state is PluginArtifactState.NATIVE_MANAGED
        else inspection.rollback_digest
    )
    preview_digest = canonical_digest(
        {
            "action": effective.value,
            "artifact_digest": rendered.artifact_digest,
            "current_state_digest": inspection.current_state_digest,
            "format_profile": rendered.plan.format_profile.value,
            "inventory": [
                {
                    "relative_path": item.relative_path,
                    "sha256": item.sha256,
                    "size": item.size,
                }
                for item in rendered.plan.inventory
            ],
            "mcp_ownership": rendered.plan.mcp_ownership.value,
            "mcp_ownership_state": mcp_owner_state.value,
            "mcp_route_profile": rendered.plan.mcp_route_profile,
            "renderer_version": rendered.plan.renderer_version,
            "request_id": request,
            "rollback_digest": rollback_digest,
            "schema_version": rendered.plan.specification_version,
            "state_before": inspection.state.value,
            "target_identity": inspection.target_identity,
        }
    )
    return PluginArtifactPreview(
        request_id=request,
        action=effective,
        state_before=inspection.state,
        mcp_ownership_state=mcp_owner_state,
        target_identity=inspection.target_identity,
        current_state_digest=inspection.current_state_digest,
        artifact_digest=rendered.artifact_digest,
        rollback_digest=rollback_digest,
        preview_digest=preview_digest,
        plan=rendered.plan,
        warnings=warnings,
    )


def _fsync_dir(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_tree(stage: Path, rendered: RenderedPortablePlugin) -> None:
    stage.mkdir(mode=0o700)
    for relative_path, data in rendered.members.items():
        if len(data) > _MAX_FILE_BYTES:
            raise _error(PluginArtifactReason.SOURCE_INVALID)
        destination = stage / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            offset = 0
            while offset < len(data):
                offset += os.write(descriptor, data[offset:])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    marker_path = stage / _MARKER_NAME
    marker_path.write_bytes(_marker(rendered))
    with marker_path.open("rb") as handle:
        os.fsync(handle.fileno())
    _fsync_dir(stage)


class _DenyStandaloneReview:
    def consume_setup_authority(self, authority: ArtifactAuthority, preview_digest: str) -> None:
        del authority, preview_digest
        raise _error(PluginArtifactReason.AUTHORITY_REQUIRED)

    def consume_artifact_review(self, authority: ArtifactAuthority, preview_digest: str) -> None:
        del authority, preview_digest
        raise _error(PluginArtifactReason.HUMAN_AUTHORITY_UNAVAILABLE)


def prepare_portable_artifact_review(
    preview_digest: str,
    *,
    _state: Path | None = None,
) -> ArtifactAuthority:
    """Prepare one review-only pending bound to the exact artifact preview digest."""

    from yoetz.service.elevated_bootstrap import prepare_pending

    pending = prepare_pending(
        "plugin_artifact_apply",
        target_digest=preview_digest,
        _state=_state,
    )
    return ArtifactAuthority("review_only", pending.target_digest, pending.pending_id)


class ElevatedPortableArtifactReview:
    """Consume one exact review-only pending after action-bound presence proof."""

    __slots__ = ("_presence", "_state")

    def __init__(
        self,
        presence: ArtifactUserPresencePort,
        *,
        _state: Path | None = None,
    ) -> None:
        self._presence = presence
        self._state = _state

    def consume_artifact_review(
        self,
        authority: ArtifactAuthority,
        preview_digest: str,
    ) -> None:
        from yoetz.service.elevated_bootstrap import (
            ElevatedBootstrapError,
            claim_pending_for_review,
            complete_review,
            load_pending,
        )

        if (
            type(authority) is not ArtifactAuthority
            or authority.channel != "review_only"
            or authority.target_digest != preview_digest
        ):
            raise _error(PluginArtifactReason.AUTHORITY_REQUIRED)
        pending = load_pending(_state=self._state)
        if (
            pending is None
            or pending.operation != "plugin_artifact_apply"
            or pending.pending_id != authority.review_id
            or pending.target_digest != preview_digest
        ):
            raise _error(PluginArtifactReason.AUTHORITY_REQUIRED)
        try:
            self._presence.verify_artifact_review(authority)
        except Exception as exc:
            raise _error(PluginArtifactReason.HUMAN_AUTHORITY_UNAVAILABLE) from exc
        claimed = None
        try:
            claimed = claim_pending_for_review(_state=self._state)
            if claimed != pending:
                raise ElevatedBootstrapError("pending_tampered")
            complete_review(claimed, outcome="approved", _state=self._state)
        except ElevatedBootstrapError as exc:
            if claimed is not None:
                try:
                    complete_review(claimed, outcome="failed", _state=self._state)
                except ElevatedBootstrapError:
                    pass
            raise _error(PluginArtifactReason.AUTHORITY_REQUIRED) from exc

    def consume_setup_authority(self, authority: ArtifactAuthority, preview_digest: str) -> None:
        del authority, preview_digest
        raise _error(PluginArtifactReason.AUTHORITY_REQUIRED)


class PortablePluginArtifactAdapter(PluginArtifactPort):
    """Codex-root portable projection with replay and conservative reconciliation."""

    __slots__ = (
        "_mcp_owner_state",
        "_mcp_owner_observer",
        "_mcp_ownership",
        "_mcp_route_profile",
        "_operations",
        "_resource_source",
        "_review",
    )

    def __init__(
        self,
        resource_source: PortableResourceSource | None = None,
        *,
        review: PluginMutationReviewPort | None = None,
        mcp_owner_state: McpOwnershipState | None = None,
        mcp_owner_observer: Callable[[], McpOwnershipState] | None = None,
        mcp_ownership: McpOwnership = McpOwnership.EXTERNAL_REGISTRATION,
        mcp_route_profile: Literal["strict", "policy"] | None = None,
    ) -> None:
        if (
            (mcp_owner_state is not None and type(mcp_owner_state) is not McpOwnershipState)
            or type(mcp_ownership) is not McpOwnership
            or (mcp_ownership is McpOwnership.PLUGIN_MANAGED)
            != (mcp_route_profile in {"strict", "policy"})
        ):
            raise ValueError("plugin_mcp_owner_invalid")
        self._resource_source = resource_source
        self._review = _DenyStandaloneReview() if review is None else review
        self._mcp_owner_state = mcp_owner_state
        self._mcp_owner_observer = mcp_owner_observer
        self._mcp_ownership = mcp_ownership
        self._mcp_route_profile: Literal["strict", "policy"] | None = mcp_route_profile
        self._operations: dict[str, tuple[str, PluginArtifactResult]] = {}

    def _owner_state(self, target: ArtifactTarget) -> McpOwnershipState:
        if self._mcp_owner_observer is not None:
            value = self._mcp_owner_observer()
        elif self._mcp_owner_state is not None:
            value = self._mcp_owner_state
        elif self._mcp_ownership is McpOwnership.PLUGIN_MANAGED:
            # The artifact adapter cannot synchronously prove the host/global registration source.
            # A caller must inject one combined observation; plugin-tree absence alone is not
            # exclusive absence and must fail closed.
            value = McpOwnershipState.AMBIGUOUS
        else:
            value = McpOwnershipState.EXTERNAL
        if type(value) is not McpOwnershipState:
            raise _error(PluginArtifactReason.MCP_OWNERSHIP_CONFLICT)
        return value

    def _rendered(self) -> RenderedPortablePlugin:
        return build_portable_plugin_plan(
            resource_source=self._resource_source,
            mcp_ownership=self._mcp_ownership,
            mcp_route_profile=self._mcp_route_profile,
        )

    def _authorize(self, command: PluginArtifactApplyCommand) -> None:
        if command.authority.target_digest != command.accepted_preview_digest:
            raise _error(PluginArtifactReason.AUTHORITY_REQUIRED)
        if command.authority.channel == "review_only":
            self._review.consume_artifact_review(
                command.authority,
                command.accepted_preview_digest,
            )
        else:
            self._review.consume_setup_authority(
                command.authority,
                command.accepted_preview_digest,
            )

    async def preview_artifact(
        self,
        request_id: RequestId,
        target: ArtifactTarget,
        action: PluginArtifactAction,
    ) -> PluginArtifactPreview:
        normalized = validate_request_id(request_id)
        if type(target) is not ArtifactTarget or type(action) is not PluginArtifactAction:
            raise _error(PluginArtifactReason.SOURCE_INVALID)
        rendered = self._rendered()
        return _preview(
            normalized,
            action,
            _inspect(target, rendered, self._resource_source),
            rendered,
            self._owner_state(target),
        )

    def _replay(self, command: PluginArtifactApplyCommand) -> PluginArtifactResult | None:
        identity = canonical_digest(
            {
                "action": command.action.value,
                "authority_channel": command.authority.channel,
                "preview_digest": command.accepted_preview_digest,
            }
        )
        previous = self._operations.get(command.request_id)
        if previous is None:
            return None
        if previous[0] != identity:
            raise _error(PluginArtifactReason.REQUEST_IDENTITY_CONFLICT)
        return previous[1]

    def _store(
        self,
        command: PluginArtifactApplyCommand,
        result: PluginArtifactResult,
    ) -> PluginArtifactResult:
        identity = canonical_digest(
            {
                "action": command.action.value,
                "authority_channel": command.authority.channel,
                "preview_digest": command.accepted_preview_digest,
            }
        )
        self._operations[command.request_id] = (identity, result)
        return result

    async def status_artifact(self, command: PluginArtifactStatusCommand) -> PluginArtifactStatus:
        if type(command) is not PluginArtifactStatusCommand:
            raise _error(PluginArtifactReason.SOURCE_INVALID)
        rendered = self._rendered()
        inspection = _inspect(command.target, rendered, self._resource_source)
        operation_state = PluginOperationState.NOT_STARTED
        if command.request_id is not None and command.request_id in self._operations:
            operation_state = self._operations[command.request_id][1].operation_state
        format_profile = (
            PluginFormatProfile.AGENT_PLUGINS_1
            if inspection.state
            in {PluginArtifactState.PORTABLE_EXACT, PluginArtifactState.PORTABLE_MANAGED}
            else PluginFormatProfile.CODEX_PLUGIN_NATIVE
            if inspection.state is PluginArtifactState.NATIVE_MANAGED
            else None
        )
        proof = tuple(
            PluginProofStatus(
                facet,
                "proven"
                if facet in {PluginProofFacet.SOURCE, PluginProofFacet.RENDERED_ARTIFACT}
                or (
                    facet is PluginProofFacet.INSTALLED_BYTES
                    and inspection.state is PluginArtifactState.PORTABLE_EXACT
                )
                else "not_observed",
            )
            for facet in PluginProofFacet
        )
        return PluginArtifactStatus(
            inspection.state,
            operation_state,
            format_profile,
            inspection.installed_digest,
            rendered.artifact_digest,
            rendered.plan.mcp_ownership,
            self._owner_state(command.target),
            rendered.plan.mcp_route_profile,
            inspection.marker_valid,
            inspection.rollback_available,
            proof,
        )

    async def install_artifact(self, command: PluginArtifactApplyCommand) -> PluginArtifactResult:
        if type(command) is not PluginArtifactApplyCommand or command.action not in {
            PluginArtifactAction.INSTALL,
            PluginArtifactAction.REPLACE,
        }:
            raise _error(PluginArtifactReason.DESTINATION_CONFLICT)
        replay = self._replay(command)
        if replay is not None:
            return replay
        rendered = self._rendered()
        inspection = _inspect(command.target, rendered, self._resource_source)
        preview = _preview(
            command.request_id,
            command.action,
            inspection,
            rendered,
            self._owner_state(command.target),
        )
        if preview.preview_digest != command.accepted_preview_digest:
            raise _error(PluginArtifactReason.PREVIEW_STALE)
        self._authorize(command)
        inspection = _inspect(command.target, rendered, self._resource_source)
        preview = _preview(
            command.request_id,
            command.action,
            inspection,
            rendered,
            self._owner_state(command.target),
        )
        if preview.preview_digest != command.accepted_preview_digest:
            raise _error(PluginArtifactReason.PREVIEW_STALE)
        if preview.action is PluginArtifactAction.NOOP:
            return self._store(
                command,
                PluginArtifactResult(
                    command.request_id,
                    PluginArtifactAction.NOOP,
                    PluginOperationState.COMPLETED,
                    inspection.state,
                    inspection.state,
                    preview.preview_digest,
                    rendered.artifact_digest,
                    inspection.installed_digest,
                    (),
                ),
            )
        parent = _plugin_parent(inspection.root, create=True)
        destination = parent / "yoetz"
        stage = parent / f"{_STAGE_PREFIX}{command.request_id}"
        rollback = parent / _NATIVE_ROLLBACK_NAME
        if stage.exists() or (
            inspection.state is PluginArtifactState.NATIVE_MANAGED and rollback.exists()
        ):
            raise _error(PluginArtifactReason.RECOVERY_REQUIRED)
        native_moved = False
        portable_moved: Path | None = None
        try:
            _write_tree(stage, rendered)
            if inspection.state is PluginArtifactState.NATIVE_MANAGED:
                os.replace(destination, rollback)
                native_moved = True
                _fsync_dir(parent)
            elif inspection.state is PluginArtifactState.PORTABLE_MANAGED:
                portable_moved = parent / f"{_REMOVE_PREFIX}{command.request_id}"
                os.replace(destination, portable_moved)
                _fsync_dir(parent)
            os.replace(stage, destination)
            _fsync_dir(parent)
            final = _inspect(command.target, rendered, self._resource_source)
            if final.state is not PluginArtifactState.PORTABLE_EXACT:
                raise OSError("installed_verification_failed")
            if portable_moved is not None and portable_moved.exists():
                shutil.rmtree(portable_moved)
                _fsync_dir(parent)
        except (OSError, PluginArtifactError) as exc:
            try:
                if native_moved and rollback.exists() and not destination.exists():
                    os.replace(rollback, destination)
                    _fsync_dir(parent)
                elif (
                    portable_moved is not None
                    and portable_moved.exists()
                    and not destination.exists()
                ):
                    os.replace(portable_moved, destination)
                    _fsync_dir(parent)
            except OSError:
                pass
            if stage.exists():
                shutil.rmtree(stage, ignore_errors=True)
            result = PluginArtifactResult(
                command.request_id,
                command.action,
                PluginOperationState.OUTCOME_UNKNOWN,
                inspection.state,
                PluginArtifactState.RECOVERY_REQUIRED,
                preview.preview_digest,
                rendered.artifact_digest,
                None,
                (),
            )
            self._store(command, result)
            if isinstance(exc, PluginArtifactError):
                raise
            raise _error(
                PluginArtifactReason.WRITE_FAILED,
                {"operation_state": PluginOperationState.OUTCOME_UNKNOWN.value},
            ) from exc
        changed = tuple(sorted((*rendered.members, _MARKER_NAME), key=str.encode))
        return self._store(
            command,
            PluginArtifactResult(
                command.request_id,
                command.action,
                PluginOperationState.COMPLETED,
                inspection.state,
                PluginArtifactState.PORTABLE_EXACT,
                preview.preview_digest,
                rendered.artifact_digest,
                rendered.artifact_digest,
                changed,
            ),
        )

    async def remove_artifact(self, command: PluginArtifactApplyCommand) -> PluginArtifactResult:
        if (
            type(command) is not PluginArtifactApplyCommand
            or command.action is not PluginArtifactAction.REMOVE
        ):
            raise _error(PluginArtifactReason.REMOVE_REFUSED)
        replay = self._replay(command)
        if replay is not None:
            return replay
        rendered = self._rendered()
        inspection = _inspect(command.target, rendered, self._resource_source)
        preview = _preview(
            command.request_id,
            command.action,
            inspection,
            rendered,
            self._owner_state(command.target),
        )
        if preview.preview_digest != command.accepted_preview_digest:
            raise _error(PluginArtifactReason.PREVIEW_STALE)
        self._authorize(command)
        inspection = _inspect(command.target, rendered, self._resource_source)
        preview = _preview(
            command.request_id,
            command.action,
            inspection,
            rendered,
            self._owner_state(command.target),
        )
        if preview.preview_digest != command.accepted_preview_digest:
            raise _error(PluginArtifactReason.PREVIEW_STALE)
        parent = inspection.parent
        destination = inspection.destination
        removal = parent / f"{_REMOVE_PREFIX}{command.request_id}"
        rollback = parent / _NATIVE_ROLLBACK_NAME
        if removal.exists():
            raise _error(PluginArtifactReason.RECOVERY_REQUIRED)
        try:
            os.replace(destination, removal)
            _fsync_dir(parent)
            restored = False
            if rollback.exists():
                if rollback.is_symlink() or not rollback.is_dir():
                    raise OSError("rollback_unsafe")
                os.replace(rollback, destination)
                restored = True
                _fsync_dir(parent)
            shutil.rmtree(removal)
            _fsync_dir(parent)
        except OSError as exc:
            result = PluginArtifactResult(
                command.request_id,
                command.action,
                PluginOperationState.OUTCOME_UNKNOWN,
                inspection.state,
                PluginArtifactState.RECOVERY_REQUIRED,
                preview.preview_digest,
                rendered.artifact_digest,
                None,
                (),
            )
            self._store(command, result)
            raise _error(
                PluginArtifactReason.WRITE_FAILED,
                {"operation_state": PluginOperationState.OUTCOME_UNKNOWN.value},
            ) from exc
        final = _inspect(command.target, rendered, self._resource_source)
        expected = PluginArtifactState.NATIVE_MANAGED if restored else PluginArtifactState.ABSENT
        if final.state is not expected:
            raise _error(PluginArtifactReason.WRITE_FAILED)
        changed = tuple(sorted((*rendered.members, _MARKER_NAME), key=str.encode))
        return self._store(
            command,
            PluginArtifactResult(
                command.request_id,
                PluginArtifactAction.REMOVE,
                PluginOperationState.COMPLETED,
                inspection.state,
                final.state,
                preview.preview_digest,
                rendered.artifact_digest,
                final.installed_digest,
                changed,
            ),
        )
