"""First-party local Cursor plugin, MCP, SDK, and capability integration.

The adapter deliberately keeps portable/native format, installed bytes, activation,
MCP ownership, SDK source precedence, and observation proof as separate facts.  It
never reads Cursor caches and every mutation is bound to an explicit user-scoped
configuration root and an exact preview digest.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import platform
import plistlib
import shlex
import shutil
import subprocess
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Final, Literal, cast

from yoetz import __version__
from yoetz.adapters.integrations.cursor_mcp_runtime import (
    CursorMcpProcessPort,
    CursorMcpRuntimeObservation,
    OsCursorMcpProcesses,
    observe_cursor_mcp_runtime,
)
from yoetz.adapters.integrations.launcher import resolve_yoetz_launcher, valid_launcher
from yoetz.adapters.integrations.launcher_probe import (
    UNOBSERVED_LAUNCHER_IDENTITY,
    LauncherIdentity,
    LauncherProbePort,
    OsLauncherProbe,
    compare_launcher_identity,
)
from yoetz.adapters.integrations.portable_plugin import (
    PackagedPortableResources,
    RenderedPortablePlugin,
    build_portable_plugin_plan,
)
from yoetz.config.paths import ISOLATED_ROOT_ENV, isolated_root
from yoetz.domain.observation_profiles import (
    CURSOR_ORDINARY_HOOK_MAPPING_VERSION,
    CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
)
from yoetz.domain.values import JsonObject, RequestId
from yoetz.domain.values import request_id as validate_request_id
from yoetz.ports.integrations import HarnessHookProfile, HarnessId, HarnessProfile
from yoetz.ports.plugin_artifacts import (
    ArtifactAuthority,
    ManagedPluginFile,
    McpOwnership,
    McpOwnershipState,
    PluginArtifactAction,
    PluginArtifactError,
    PluginArtifactReason,
    PluginArtifactState,
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
    "CURSOR_HOOK_EVENTS",
    "CURSOR_HARNESS_PROFILE",
    "CURSOR_NATIVE_PROFILE_ID",
    "CURSOR_ORDINARY_HOOK_MAPPING_VERSION",
    "CURSOR_ORDINARY_OBSERVATION_PROFILE_ID",
    "CURSOR_ORDINARY_HOOK_EVENTS",
    "CURSOR_PLUGIN_RELATIVE_ROOT",
    "CURSOR_SDK_PROOF_LIMITS",
    "CursorArtifactIdentity",
    "CursorCapabilityIdentity",
    "CursorIntegrationError",
    "CursorIsolationBindingState",
    "CursorMcpObservation",
    "CursorMcpProcessPort",
    "CursorMcpRuntimeObservation",
    "CursorMcpSource",
    "CursorPluginArtifact",
    "CursorPluginPreview",
    "CursorPluginResult",
    "CursorLauncherStatus",
    "CursorPluginStatus",
    "CursorPluginTarget",
    "CursorSdkBinding",
    "CursorSdkProfile",
    "apply_cursor_plugin",
    "build_cursor_sdk_profile",
    "discover_cursor_cli",
    "discover_cursor_ide",
    "discover_cursor_sdk",
    "observe_cursor_mcp",
    "preview_cursor_plugin",
    "remove_cursor_plugin",
    "render_cursor_plugin",
    "status_cursor_plugin",
]

CURSOR_PLUGIN_RELATIVE_ROOT: Final = "plugins/local/yoetz"
CURSOR_NATIVE_PROFILE_ID: Final = "cursor-native-3.17"
CURSOR_HOOK_MAPPING_VERSION: Final = "cursor-hooks-3.17-v1"
CURSOR_SDK_BRIDGE_PROTOCOL: Final = "sdk.v1"
CURSOR_SDK_PROOF_LIMITS: Final = ("metadata_only", "not_a_support_claim")
CURSOR_HOOK_EVENTS: Final = (
    "afterFileEdit",
    "afterMCPExecution",
    "sessionEnd",
    "sessionStart",
    "stop",
)
CURSOR_ORDINARY_HOOK_EVENTS: Final = (
    "afterMCPExecution",
    "postToolUse",
    "postToolUseFailure",
    "preToolUse",
    "sessionEnd",
    "sessionStart",
    "stop",
)
_CURSOR_CAPABILITY_PROFILE_IDS: Final = (
    "cursor-cli-2026.07.09-a3815c0",
    "cursor-ide-3.17.8",
)
_CURSOR_HOOK_PROFILE: Final = HarnessHookProfile(
    trigger_event="sessionStart",
    trigger_payload_profile_id="cursor-hooks-common-3.17-v1",
    evidence_case_ids=("cursor-ide-native-3.17.8-macos-arm64",),
    observation_events=CURSOR_HOOK_EVENTS,
    pairing_mode="post_only",
    correlation_kind="generation_id",
)
CURSOR_HARNESS_PROFILE: Final = HarnessProfile(
    harness_id=HarnessId.CURSOR,
    skill_root="plugins/local/yoetz/skills/",
    frontmatter_profile="agent-skills-1",
    capability_profile_ids=_CURSOR_CAPABILITY_PROFILE_IDS,
    supported_versions=("2026.07.09-a3815c0", "3.17.8"),
    hooks_by_capability_profile={
        "cursor-cli-2026.07.09-a3815c0": None,
        "cursor-ide-3.17.8": _CURSOR_HOOK_PROFILE,
    },
)

_MARKER_NAME: Final = ".yoetz-cursor-plugin-install.json"
_MARKER_SCHEMA_V1: Final = "yoetz.cursor-plugin-install/1"
_MARKER_SCHEMA_V2: Final = "yoetz.cursor-plugin-install/2"
_MARKER_SCHEMA_V3: Final = "yoetz.cursor-plugin-install/3"
_RENDERER_VERSION: Final = "cursor-plugin/0.3.0"
_ROLLBACK_NAME: Final = ".yoetz-cursor-plugin-rollback"
_STAGE_PREFIX: Final = ".yoetz-cursor-plugin-stage-"
_MAX_FILE_BYTES: Final = 262_144
_MAX_FILES: Final = 64
_MAX_PATH: Final = 4_096
_MAX_CURSOR_IDENTITY_BYTES: Final = 4_096
_MAX_CURSOR_IDENTITY_METADATA_BYTES: Final = 1_048_576
_GUIDANCE_URI_PREFIX: Final = "yoetz://guidance/"
_GUIDANCE_NAMES: Final = tuple(
    uri.removeprefix(_GUIDANCE_URI_PREFIX)
    for uri in (*GUIDANCE_DOCUMENT_URIS, *FOCUSED_GUIDANCE_URIS)
)
_SKILL_PATH: Final = "skills/cursor/yoetz/SKILL.md"
_DESCRIPTION: Final = (
    "Records material work in a local Yoetz ledger and checks completion claims "
    "against that record."
)

type CursorIsolationBindingState = Literal[
    "ambient", "isolated_exact", "missing", "different", "unobserved"
]


class CursorSdkBinding(str, Enum):  # noqa: UP042 - exact public token
    TYPESCRIPT = "typescript"
    PYTHON = "python"


class CursorMcpSource(str, Enum):  # noqa: UP042 - exact public token
    INLINE_SEND = "inline_send"
    INLINE_CREATE = "inline_create"
    PLUGIN = "plugin"
    PROJECT = "project"
    USER = "user"


@dataclass(frozen=True, slots=True, repr=False)
class CursorCapabilityIdentity:
    surface: Literal["cursor_ide", "cursor_cli"]
    version: str
    build: str
    artifact_digest: str
    os_name: str
    architecture: str

    def __post_init__(self) -> None:
        if self.surface not in {"cursor_ide", "cursor_cli"}:
            raise ValueError("cursor_surface_invalid")
        for value in (self.version, self.build, self.os_name, self.architecture):
            if type(value) is not str or not value or len(value) > 128:
                raise ValueError("cursor_identity_invalid")
        _validate_digest(self.artifact_digest)

    def __repr__(self) -> str:
        return (
            "CursorCapabilityIdentity("
            f"surface={self.surface!r}, version={self.version!r}, build={self.build!r}, "
            f"artifact_digest={self.artifact_digest!r}, os_name={self.os_name!r}, "
            f"architecture={self.architecture!r})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class CursorArtifactIdentity:
    """Metadata-only SDK identity; it never establishes a supported SDK cell."""

    binding: CursorSdkBinding
    package_version: str
    package_digest: str
    bridge_protocol: Literal["sdk.v1"] = CURSOR_SDK_BRIDGE_PROTOCOL
    bridge_digest: str | None = None

    def __post_init__(self) -> None:
        if type(self.binding) is not CursorSdkBinding:
            raise ValueError("cursor_sdk_binding_invalid")
        if type(self.package_version) is not str or not self.package_version:
            raise ValueError("cursor_sdk_version_invalid")
        _validate_digest(self.package_digest)
        if self.bridge_protocol != CURSOR_SDK_BRIDGE_PROTOCOL:
            raise ValueError("cursor_sdk_bridge_invalid")
        if self.bridge_digest is not None:
            _validate_digest(self.bridge_digest)

    def __repr__(self) -> str:
        return (
            "CursorArtifactIdentity("
            f"binding={self.binding.value!r}, package_version={self.package_version!r}, "
            f"package_digest={self.package_digest!r}, bridge_protocol={self.bridge_protocol!r}, "
            f"bridge_digest={self.bridge_digest!r})"
        )

    @property
    def proof_limits(self) -> tuple[str, str]:
        return CURSOR_SDK_PROOF_LIMITS

    @property
    def metadata_only(self) -> bool:
        return True

    @property
    def support_claim(self) -> bool:
        return False


@dataclass(frozen=True, slots=True)
class CursorSdkProfile:
    """Metadata-only SDK precedence profile; it never establishes SDK support."""

    identity: CursorArtifactIdentity
    setting_sources: tuple[Literal["plugins", "project", "user"], ...]
    mcp_precedence: tuple[CursorMcpSource, ...]
    mcp_ownership: McpOwnership
    sandbox_enabled: bool
    approval_mode: Literal["default", "allowlist", "full"]

    def __post_init__(self) -> None:
        if type(self.identity) is not CursorArtifactIdentity:
            raise ValueError("cursor_sdk_identity_invalid")
        allowed = {"plugins", "project", "user"}
        if (
            type(self.setting_sources) is not tuple
            or len(set(self.setting_sources)) != len(self.setting_sources)
            or any(item not in allowed for item in self.setting_sources)
        ):
            raise ValueError("cursor_sdk_setting_sources_invalid")
        expected = (
            CursorMcpSource.INLINE_SEND,
            CursorMcpSource.INLINE_CREATE,
            CursorMcpSource.PLUGIN,
            CursorMcpSource.PROJECT,
            CursorMcpSource.USER,
        )
        if self.mcp_precedence != expected:
            raise ValueError("cursor_sdk_precedence_invalid")
        if type(self.mcp_ownership) is not McpOwnership or type(self.sandbox_enabled) is not bool:
            raise ValueError("cursor_sdk_profile_invalid")
        if self.approval_mode not in {"default", "allowlist", "full"}:
            raise ValueError("cursor_sdk_profile_invalid")
        if (
            self.mcp_ownership is McpOwnership.PLUGIN_MANAGED
            and "plugins" not in self.setting_sources
        ):
            raise ValueError("cursor_sdk_plugin_source_required")
        if self.mcp_ownership is McpOwnership.EXTERNAL_REGISTRATION and not {
            "project",
            "user",
        }.intersection(self.setting_sources):
            raise ValueError("cursor_sdk_external_source_required")

    @property
    def proof_limits(self) -> tuple[str, str]:
        return CURSOR_SDK_PROOF_LIMITS

    @property
    def metadata_only(self) -> bool:
        return True

    @property
    def support_claim(self) -> bool:
        return False


@dataclass(frozen=True, slots=True, repr=False)
class CursorPluginTarget:
    cursor_config_root: str
    scope: Literal["user"] = "user"

    def __post_init__(self) -> None:
        if (
            type(self.cursor_config_root) is not str
            or not 1 <= len(self.cursor_config_root) <= _MAX_PATH
            or not Path(self.cursor_config_root).is_absolute()
            or any(ord(char) < 32 or ord(char) == 127 for char in self.cursor_config_root)
            or self.scope != "user"
        ):
            raise ValueError("cursor_target_invalid")

    def __repr__(self) -> str:
        return "CursorPluginTarget(cursor_config_root=<redacted>, scope='user')"


def _valid_isolation_root_text(value: object) -> bool:
    if type(value) is not str:
        return False
    return (
        1 <= len(value) <= _MAX_PATH
        and Path(value).is_absolute()
        and not any(ord(char) < 32 or ord(char) == 127 for char in value)
    )


def _render_isolation_root() -> str | None:
    """Resolve the one exact isolation binding for a native artifact.

    ``isolated_root`` owns the path-safety contract.  The adapter only adds the bounded text
    validation needed before a path is copied into a host-owned command/configuration artifact.
    """

    root = isolated_root()
    if root is None:
        return None
    value = str(root)
    if not _valid_isolation_root_text(value):
        raise ValueError("cursor_isolation_root_invalid")
    return value


@dataclass(frozen=True, slots=True)
class CursorPluginArtifact:
    plan: PortablePluginPlan
    members: Mapping[str, bytes]
    artifact_digest: str
    yoetz_launcher: tuple[str, ...] | None = field(default=None, repr=False)
    isolation_root: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if type(self.plan) is not PortablePluginPlan:
            raise ValueError("cursor_artifact_invalid")
        if self.plan.format_profile not in {
            PluginFormatProfile.AGENT_PLUGINS_1,
            PluginFormatProfile.CURSOR_PLUGIN_NATIVE,
        }:
            raise ValueError("cursor_artifact_invalid")
        if self.plan.format_profile is PluginFormatProfile.CURSOR_PLUGIN_NATIVE:
            if not _valid_launcher(self.yoetz_launcher):
                raise ValueError("cursor_artifact_invalid")
            if self.isolation_root is not None and not _valid_isolation_root_text(
                self.isolation_root
            ):
                raise ValueError("cursor_artifact_invalid")
        elif self.yoetz_launcher is not None:
            raise ValueError("cursor_artifact_invalid")
        elif self.isolation_root is not None:
            raise ValueError("cursor_artifact_invalid")
        _validate_digest(self.artifact_digest)
        expected = tuple(item.relative_path for item in self.plan.inventory)
        if tuple(sorted(self.members, key=str.encode)) != expected:
            raise ValueError("cursor_artifact_inventory_invalid")


@dataclass(frozen=True, slots=True)
class CursorMcpObservation:
    ownership_state: McpOwnershipState
    winning_source: CursorMcpSource | None
    route_profile: Literal["strict", "policy"] | None
    present_sources: tuple[CursorMcpSource, ...]
    observed: bool

    def __post_init__(self) -> None:
        if type(self.ownership_state) is not McpOwnershipState:
            raise ValueError("cursor_mcp_observation_invalid")
        if self.winning_source is not None and type(self.winning_source) is not CursorMcpSource:
            raise ValueError("cursor_mcp_observation_invalid")
        if self.route_profile not in {None, "strict", "policy"}:
            raise ValueError("cursor_mcp_observation_invalid")
        if type(self.observed) is not bool:
            raise ValueError("cursor_mcp_observation_invalid")
        if type(self.present_sources) is not tuple or any(
            type(item) is not CursorMcpSource for item in self.present_sources
        ):
            raise ValueError("cursor_mcp_observation_invalid")


@dataclass(frozen=True, slots=True)
class CursorPluginPreview:
    request_id: RequestId
    action: PluginArtifactAction
    state_before: PluginArtifactState
    format_profile: PluginFormatProfile
    target_identity: str
    current_state_digest: str
    artifact_digest: str
    preview_digest: str
    mcp_ownership: McpOwnership
    mcp_ownership_state: McpOwnershipState
    mcp_route_profile: Literal["strict", "policy"] | None
    isolation_root: str | None = field(repr=False)
    warnings: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "request_id", validate_request_id(self.request_id))
        if type(self.action) is not PluginArtifactAction:
            raise ValueError("cursor_preview_invalid")
        if type(self.state_before) is not PluginArtifactState:
            raise ValueError("cursor_preview_invalid")
        if type(self.format_profile) is not PluginFormatProfile:
            raise ValueError("cursor_preview_invalid")
        for value in (
            self.target_identity,
            self.current_state_digest,
            self.artifact_digest,
            self.preview_digest,
        ):
            _validate_digest(value)
        if self.isolation_root is not None and not _valid_isolation_root_text(self.isolation_root):
            raise ValueError("cursor_preview_invalid")


type CursorLauncherExecutableState = Literal[
    "matched", "drifted", "missing", "unbound", "unobserved"
]
type CursorMcpBindingState = Literal[
    "exact_launcher", "ambient_path", "absent", "foreign", "unobserved"
]


@dataclass(frozen=True, slots=True)
class CursorLauncherStatus:
    """Status of the exact launcher an installed native plugin binds (issue #468).

    ``executable`` compares the installed marker's launcher with this runtime's: ``matched``
    (same executable, present and executable), ``drifted`` (the installed tree binds another
    installation), ``missing`` (the bound executable no longer exists), ``unbound`` (portable or
    legacy ``/1`` native marker without a launcher), or ``unobserved`` (no marker-valid tree).
    ``mcp_binding`` says what the installed plugin-owned ``mcp.json`` actually launches:
    ``exact_launcher``, a bare ``ambient_path`` command, ``absent`` (external registration),
    ``foreign``, or ``unobserved``. ``identity`` is the bounded runtime identity probed from the
    installed launcher, compared with this runtime's package version, control result schema, and
    resource-manifest digest.
    """

    artifact_launcher: tuple[str, ...] | None
    installed_launcher: tuple[str, ...] | None
    executable: CursorLauncherExecutableState
    mcp_binding: CursorMcpBindingState
    identity: LauncherIdentity

    def __post_init__(self) -> None:
        for launcher in (self.artifact_launcher, self.installed_launcher):
            if launcher is not None and not _valid_launcher(launcher):
                raise ValueError("cursor_launcher_status_invalid")
        if self.executable not in {"matched", "drifted", "missing", "unbound", "unobserved"}:
            raise ValueError("cursor_launcher_status_invalid")
        if self.mcp_binding not in {
            "exact_launcher",
            "ambient_path",
            "absent",
            "foreign",
            "unobserved",
        }:
            raise ValueError("cursor_launcher_status_invalid")
        if type(self.identity) is not LauncherIdentity:
            raise ValueError("cursor_launcher_status_invalid")
        if self.installed_launcher is None and self.executable in {"matched", "drifted", "missing"}:
            raise ValueError("cursor_launcher_status_invalid")
        if self.installed_launcher is None and self.identity.observed:
            raise ValueError("cursor_launcher_status_invalid")


@dataclass(frozen=True, slots=True)
class CursorPluginStatus:
    state: PluginArtifactState
    operation_state: PluginOperationState
    format_profile: PluginFormatProfile | None
    artifact_digest: str
    installed_digest: str | None
    marker_valid: bool
    rollback_available: bool
    mcp_observation: CursorMcpObservation
    runtime: CursorMcpRuntimeObservation
    proof: tuple[PluginProofStatus, ...]
    launcher: CursorLauncherStatus = field(
        default_factory=lambda: CursorLauncherStatus(
            None, None, "unobserved", "unobserved", UNOBSERVED_LAUNCHER_IDENTITY
        )
    )
    isolation_binding: CursorIsolationBindingState = "unobserved"

    def __post_init__(self) -> None:
        if type(self.launcher) is not CursorLauncherStatus:
            raise ValueError("cursor_status_invalid")
        if (
            type(self.state) is not PluginArtifactState
            or type(self.operation_state) is not PluginOperationState
        ):
            raise ValueError("cursor_status_invalid")
        if self.format_profile is not None and type(self.format_profile) is not PluginFormatProfile:
            raise ValueError("cursor_status_invalid")
        _validate_digest(self.artifact_digest)
        if self.installed_digest is not None:
            _validate_digest(self.installed_digest)
        if type(self.marker_valid) is not bool or type(self.rollback_available) is not bool:
            raise ValueError("cursor_status_invalid")
        if (
            type(self.mcp_observation) is not CursorMcpObservation
            or type(self.runtime) is not CursorMcpRuntimeObservation
            or type(self.proof) is not tuple
        ):
            raise ValueError("cursor_status_invalid")
        if any(type(item) is not PluginProofStatus for item in self.proof):
            raise ValueError("cursor_status_invalid")
        if self.isolation_binding not in {
            "ambient",
            "isolated_exact",
            "missing",
            "different",
            "unobserved",
        }:
            raise ValueError("cursor_status_invalid")


@dataclass(frozen=True, slots=True)
class CursorPluginResult:
    request_id: RequestId
    action: PluginArtifactAction
    operation_state: PluginOperationState
    state_before: PluginArtifactState
    state_after: PluginArtifactState
    format_profile: PluginFormatProfile
    preview_digest: str
    artifact_digest: str
    installed_digest: str | None
    changed_files: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "request_id", validate_request_id(self.request_id))
        if (
            type(self.action) is not PluginArtifactAction
            or type(self.operation_state) is not PluginOperationState
            or type(self.state_before) is not PluginArtifactState
            or type(self.state_after) is not PluginArtifactState
            or type(self.format_profile) is not PluginFormatProfile
        ):
            raise ValueError("cursor_result_invalid")
        _validate_digest(self.preview_digest)
        _validate_digest(self.artifact_digest)
        if self.installed_digest is not None:
            _validate_digest(self.installed_digest)
        if type(self.changed_files) is not tuple or any(
            type(path) is not str or not path or len(path) > _MAX_PATH
            for path in self.changed_files
        ):
            raise ValueError("cursor_result_invalid")


@dataclass(frozen=True, slots=True)
class CursorIntegrationError(Exception):
    reason: PluginArtifactReason
    safe_details: Mapping[str, JsonValue]

    def __post_init__(self) -> None:
        if type(self.reason) is not PluginArtifactReason:
            raise ValueError("cursor_error_invalid")
        try:
            details = JsonObject(self.safe_details)
        except ProtocolValueError as exc:
            raise ValueError("cursor_error_invalid") from exc
        if (
            len(details) > 16
            or len(canonical_encode(details)) > 4_096
            or any(key not in {"mcp_ownership_state"} for key in details)
        ):
            raise ValueError("cursor_error_invalid")
        object.__setattr__(self, "safe_details", details)
        Exception.__init__(self, self.reason.value)


@dataclass(frozen=True, slots=True, repr=False)
class _Inspection:
    root: Path
    destination: Path
    state: PluginArtifactState
    format_profile: PluginFormatProfile | None
    target_identity: str
    current_state_digest: str
    installed_digest: str | None
    marker_valid: bool
    rollback_available: bool
    installed_launcher: tuple[str, ...] | None = None
    installed_isolation_root: str | None = None


def _error(
    reason: PluginArtifactReason, details: Mapping[str, JsonValue] | None = None
) -> CursorIntegrationError:
    return CursorIntegrationError(reason, {} if details is None else details)


def _sha(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _validate_digest(value: object) -> str:
    if (
        type(value) is not str
        or len(value) != 71
        or not value.startswith("sha256:")
        or any(char not in "0123456789abcdef" for char in value[7:])
    ):
        raise ValueError("cursor_digest_invalid")
    return value


def _valid_cursor_identity_text(value: object) -> bool:
    """Accept bounded printable ASCII metadata for structural identity fields."""

    return (
        type(value) is str
        and bool(value)
        and len(value) <= 128
        and all(0x20 <= ord(character) <= 0x7E for character in value)
    )


def _inventory(members: Mapping[str, bytes]) -> tuple[ManagedPluginFile, ...]:
    return tuple(
        ManagedPluginFile(path, len(data), _sha(data))
        for path, data in sorted(members.items(), key=lambda item: item[0].encode("ascii"))
    )


_MCP_SERVE_ARGS: Final = ("mcp", "serve", "--host", "cursor")
_MCP_SERVE_STRICT_ARGS: Final = (*_MCP_SERVE_ARGS, "--semantic", "off")


def _mcp_json(
    route_profile: Literal["strict", "policy"],
    yoetz_launcher: tuple[str, ...],
    isolation_root: str | None,
) -> bytes:
    """Render the plugin-owned MCP entry bound to the exact launcher the hooks use.

    Cursor resolves a bare ``command`` through the desktop app's PATH, which is sanitized and
    can name an older ambient Yoetz while the hooks run this installation (issue #468). The entry
    therefore names the absolute executable (plus the fixed ``-m yoetz`` arguments for the
    module entrypoint); Cursor's MCP reference admits a full path in ``command``.
    """

    serve = _MCP_SERVE_STRICT_ARGS if route_profile == "strict" else _MCP_SERVE_ARGS
    args = cast(list[JsonValue], [*yoetz_launcher[1:], *serve])
    entry: dict[str, JsonValue] = {
        "args": args,
        "command": yoetz_launcher[0],
        "type": "stdio",
    }
    if isolation_root is not None:
        entry["env"] = {ISOLATED_ROOT_ENV: isolation_root}
    return canonical_encode(
        cast(
            JsonValue,
            {"mcpServers": {"yoetz": entry}},
        )
    )


def _valid_launcher(launcher: object) -> bool:
    """Validate one rendered launcher (shared with every native carrier)."""

    return valid_launcher(launcher)


def _resolve_yoetz_launcher(candidate: Path | str | Sequence[str] | None = None) -> tuple[str, ...]:
    """Resolve the exact launcher command used by rendered native Cursor hooks."""

    return resolve_yoetz_launcher(candidate)


def _native_members(
    *,
    source: PackagedPortableResources,
    mcp_ownership: McpOwnership,
    route_profile: Literal["strict", "policy"] | None,
    yoetz_launcher: tuple[str, ...],
    isolation_root: str | None,
    observation_profile: Literal["structural", "ordinary"],
    startup_mode: Literal["optional", "required"] = "optional",
) -> dict[str, bytes]:
    manifest: dict[str, JsonValue] = {
        "author": {"name": "Yoetz contributors"},
        "description": _DESCRIPTION,
        "hooks": "hooks/hooks.json",
        "name": "yoetz",
        "skills": "skills",
        "version": __version__,
    }
    if mcp_ownership is McpOwnership.PLUGIN_MANAGED:
        if route_profile not in {"strict", "policy"}:
            raise ValueError("cursor_mcp_route_required")
        manifest["mcpServers"] = "mcp.json"
    elif route_profile is not None:
        raise ValueError("cursor_mcp_route_forbidden")
    launcher = " ".join(shlex.quote(part) for part in yoetz_launcher)
    isolation_prefix = (
        "" if isolation_root is None else f"{ISOLATED_ROOT_ENV}={shlex.quote(isolation_root)} "
    )
    hook_command = f"{isolation_prefix}{launcher} hooks cursor-observe --workspace ."
    hook_events = CURSOR_HOOK_EVENTS
    if observation_profile == "ordinary":
        hook_command = (
            f"{hook_command} --observation-profile "
            f"{shlex.quote(CURSOR_ORDINARY_OBSERVATION_PROFILE_ID)}"
        )
        hook_events = CURSOR_ORDINARY_HOOK_EVENTS
    hook_timeouts = {
        "afterFileEdit": 5,
        "afterMCPExecution": 5,
        "postToolUse": 5,
        "postToolUseFailure": 5,
        "preToolUse": 5,
        "sessionEnd": 3,
        "sessionStart": 10,
        "stop": 10,
    }
    hooks = {
        event: [{"command": f"{hook_command} --event {event}", "timeout": hook_timeouts[event]}]
        for event in hook_events
    }
    hooks["sessionStart"].insert(
        0,
        {
            "command": f"{isolation_prefix}{launcher} hooks startup-context --host cursor",
            "timeout": 2,
        },
    )
    if startup_mode == "required":
        # MCP ownership is available only on the specific before/after hooks.
        for event in (
            "sessionStart",
            "beforeSubmitPrompt",
            "preToolUse",
            "beforeMCPExecution",
            "afterMCPExecution",
            "sessionEnd",
        ):
            hooks.setdefault(event, []).insert(
                0,
                {
                    "command": f"{isolation_prefix}{launcher} hooks startup-gate --host cursor --event {event}",
                    "timeout": 3,
                    **(
                        {"failClosed": True}
                        if event in {"preToolUse", "beforeMCPExecution"}
                        else {}
                    ),
                },
            )
    members: dict[str, bytes] = {
        ".cursor-plugin/plugin.json": canonical_encode(manifest),
        "hooks/hooks.json": canonical_encode(cast(JsonValue, {"hooks": hooks, "version": 1})),
        "skills/yoetz/SKILL.md": source.read_bytes(_SKILL_PATH),
    }
    for name in _GUIDANCE_NAMES:
        members[f"skills/yoetz/references/{name}"] = source.read_bytes(f"guidance/{name}")
    if mcp_ownership is McpOwnership.PLUGIN_MANAGED:
        assert route_profile is not None
        members["mcp.json"] = _mcp_json(route_profile, yoetz_launcher, isolation_root)
    return members


def installed_cursor_startup_mode(
    target: CursorPluginTarget,
) -> Literal["optional", "required"] | None:
    """Inspect marker-verified installed bytes without assuming this version's digest."""
    base, _identity = _target_path(target)
    root = base / CURSOR_PLUGIN_RELATIVE_ROOT
    if root.is_symlink():
        return None
    if not root.exists():
        return "optional"
    files = _safe_tree(root)
    if not _valid_marker(files)[0]:
        return None
    hooks = files.get("hooks/hooks.json", b"")
    return "required" if b" hooks startup-gate --host cursor " in hooks else "optional"


def render_cursor_plugin(
    format_profile: PluginFormatProfile,
    *,
    mcp_ownership: McpOwnership = McpOwnership.EXTERNAL_REGISTRATION,
    route_profile: Literal["strict", "policy"] | None = None,
    source: PackagedPortableResources | None = None,
    yoetz_launcher: Path | str | Sequence[str] | None = None,
    observation_profile: Literal["structural", "ordinary"] = "structural",
    startup_mode: Literal["optional", "required"] = "optional",
) -> CursorPluginArtifact:
    """Render one Cursor artifact from canonical packaged guidance bytes."""

    if type(format_profile) is not PluginFormatProfile or format_profile not in {
        PluginFormatProfile.AGENT_PLUGINS_1,
        PluginFormatProfile.CURSOR_PLUGIN_NATIVE,
    }:
        raise ValueError("cursor_format_invalid")
    if type(mcp_ownership) is not McpOwnership:
        raise ValueError("cursor_mcp_ownership_invalid")
    if observation_profile not in {"structural", "ordinary"}:
        raise ValueError("cursor_observation_profile_invalid")
    if startup_mode not in {"optional", "required"}:
        raise ValueError("startup_mode_invalid")
    if (
        startup_mode == "required"
        and format_profile is not PluginFormatProfile.CURSOR_PLUGIN_NATIVE
    ):
        raise ValueError("startup_mode_unsupported")
    resources = PackagedPortableResources() if source is None else source
    if (
        observation_profile == "ordinary"
        and format_profile is not PluginFormatProfile.CURSOR_PLUGIN_NATIVE
    ):
        raise ValueError("cursor_observation_profile_unsupported")
    if format_profile is PluginFormatProfile.AGENT_PLUGINS_1:
        rendered: RenderedPortablePlugin = build_portable_plugin_plan(
            mcp_ownership=mcp_ownership,
            mcp_route_profile=route_profile,
            resource_source=resources,
            skill_host="cursor",
        )
        return CursorPluginArtifact(rendered.plan, dict(rendered.members), rendered.artifact_digest)
    resolved_yoetz_launcher = _resolve_yoetz_launcher(yoetz_launcher)
    resolved_isolation_root = _render_isolation_root()
    members = _native_members(
        source=resources,
        mcp_ownership=mcp_ownership,
        route_profile=route_profile,
        yoetz_launcher=resolved_yoetz_launcher,
        isolation_root=resolved_isolation_root,
        observation_profile=observation_profile,
        startup_mode=startup_mode,
    )
    plan = PortablePluginPlan(
        name="yoetz",
        version=__version__,
        description=_DESCRIPTION,
        format_profile=PluginFormatProfile.CURSOR_PLUGIN_NATIVE,
        mcp_ownership=mcp_ownership,
        mcp_route_profile=route_profile,
        host_extension_profile=(
            CURSOR_ORDINARY_OBSERVATION_PROFILE_ID
            if observation_profile == "ordinary"
            else CURSOR_NATIVE_PROFILE_ID
        ),
        specification_version="1.0.0",
        renderer_version=_RENDERER_VERSION,
        source_refs=tuple(
            sorted(
                {*(f"guidance/{name}" for name in _GUIDANCE_NAMES), _SKILL_PATH},
                key=str.encode,
            )
        ),
        inventory=_inventory(members),
    )
    digest = canonical_digest(
        {
            "files": [
                {"relative_path": item.relative_path, "sha256": item.sha256, "size": item.size}
                for item in plan.inventory
            ],
            "format_profile": format_profile.value,
            "renderer_version": _RENDERER_VERSION,
        }
    )
    return CursorPluginArtifact(
        plan, members, digest, resolved_yoetz_launcher, resolved_isolation_root
    )


def _safe_existing_ancestor(path: Path) -> Path:
    current = path
    missing: list[Path] = []
    while not current.exists():
        missing.append(current)
        if current.parent == current:
            raise _error(PluginArtifactReason.TARGET_UNSAFE)
        current = current.parent
    if current.is_symlink() or not current.is_dir():
        raise _error(PluginArtifactReason.TARGET_UNSAFE)
    if hasattr(os, "geteuid") and current.stat().st_uid != os.geteuid():
        raise _error(PluginArtifactReason.TARGET_UNTRUSTED)
    if current.stat().st_mode & 0o022:
        raise _error(PluginArtifactReason.TARGET_UNSAFE)
    for candidate in reversed(missing):
        if candidate.name in {"", ".", ".."}:
            raise _error(PluginArtifactReason.TARGET_UNSAFE)
    return current


def _target_path(target: CursorPluginTarget) -> tuple[Path, str]:
    if type(target) is not CursorPluginTarget:
        raise _error(PluginArtifactReason.TARGET_UNTRUSTED)
    root = Path(target.cursor_config_root)
    _safe_existing_ancestor(root)
    for candidate in (root, *root.parents):
        if candidate.exists() and candidate.is_symlink():
            raise _error(PluginArtifactReason.TARGET_UNSAFE)
        if candidate.parent == candidate:
            break
    identity = canonical_digest({"cursor_config_root": str(root), "scope": target.scope})
    return root, identity


def _ensure_private_path(path: Path) -> None:
    existing = _safe_existing_ancestor(path)
    relative = path.relative_to(existing)
    current = existing
    for part in relative.parts:
        current = current / part
        try:
            current.mkdir(mode=0o700)
        except FileExistsError:
            pass
        if current.is_symlink() or not current.is_dir():
            raise _error(PluginArtifactReason.TARGET_UNSAFE)
        facts = current.stat()
        if (hasattr(os, "geteuid") and facts.st_uid != os.geteuid()) or facts.st_mode & 0o022:
            raise _error(PluginArtifactReason.TARGET_UNSAFE)


def _safe_tree(root: Path) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    for path in sorted(root.rglob("*"), key=lambda value: value.as_posix().encode("utf-8")):
        if path.is_symlink():
            raise _error(PluginArtifactReason.TARGET_UNSAFE)
        if path.is_dir():
            continue
        if (
            not path.is_file()
            or path.stat().st_nlink != 1
            or path.stat().st_size > _MAX_FILE_BYTES
            or len(result) >= _MAX_FILES
        ):
            raise _error(PluginArtifactReason.TARGET_UNSAFE)
        result[path.relative_to(root).as_posix()] = path.read_bytes()
    return result


def _tree_digest(files: Mapping[str, bytes]) -> str:
    return canonical_digest(
        {
            "files": [
                {"relative_path": path, "sha256": _sha(data), "size": len(data)}
                for path, data in sorted(files.items(), key=lambda item: item[0].encode("ascii"))
            ]
        }
    )


def _load_object(data: bytes) -> Mapping[str, JsonValue] | None:
    try:
        value = strict_json_parse(data)
    except ProtocolValueError, UnicodeError:
        return None
    return cast(Mapping[str, JsonValue], value) if isinstance(value, Mapping) else None


def _hook_mapping_version_for_artifact(artifact: CursorPluginArtifact) -> str | None:
    """Return the exact mapping bound into a native artifact, if any."""

    if artifact.plan.format_profile is not PluginFormatProfile.CURSOR_PLUGIN_NATIVE:
        return None
    return (
        CURSOR_ORDINARY_HOOK_MAPPING_VERSION
        if artifact.plan.host_extension_profile == CURSOR_ORDINARY_OBSERVATION_PROFILE_ID
        else CURSOR_HOOK_MAPPING_VERSION
    )


def _marker(artifact: CursorPluginArtifact) -> bytes:
    body: dict[str, JsonValue] = {
        "artifact_digest": artifact.artifact_digest,
        "format_profile": artifact.plan.format_profile.value,
        "hook_mapping_version": _hook_mapping_version_for_artifact(artifact),
        "managed_files": [
            {"relative_path": item.relative_path, "sha256": item.sha256, "size": item.size}
            for item in artifact.plan.inventory
        ],
        "mcp_ownership": artifact.plan.mcp_ownership.value,
        "mcp_route_profile": artifact.plan.mcp_route_profile,
        "renderer_version": artifact.plan.renderer_version,
        "schema": (
            _MARKER_SCHEMA_V3
            if artifact.plan.format_profile is PluginFormatProfile.CURSOR_PLUGIN_NATIVE
            else _MARKER_SCHEMA_V1
        ),
        "yoetz_version": artifact.plan.version,
    }
    if artifact.plan.format_profile is PluginFormatProfile.CURSOR_PLUGIN_NATIVE:
        assert artifact.yoetz_launcher is not None
        body["yoetz_launcher"] = list(artifact.yoetz_launcher)
        body["isolation_root"] = artifact.isolation_root
    return canonical_encode({**body, "marker_digest": canonical_digest(body)})


def _valid_marker(
    files: Mapping[str, bytes],
) -> tuple[bool, PluginFormatProfile | None, str | None]:
    raw = files.get(_MARKER_NAME)
    marker = None if raw is None else _load_object(raw)
    if marker is None or marker.get("schema") not in {
        _MARKER_SCHEMA_V1,
        _MARKER_SCHEMA_V2,
        _MARKER_SCHEMA_V3,
    }:
        return False, None, None
    schema = cast(str, marker["schema"])
    digest = marker.get("marker_digest")
    body = {key: value for key, value in marker.items() if key != "marker_digest"}
    if type(digest) is not str or digest != canonical_digest(body):
        return False, None, None
    try:
        format_profile = PluginFormatProfile(cast(str, marker.get("format_profile")))
    except TypeError, ValueError:
        return False, None, None
    if format_profile not in {
        PluginFormatProfile.AGENT_PLUGINS_1,
        PluginFormatProfile.CURSOR_PLUGIN_NATIVE,
    }:
        return False, None, None
    launcher = marker.get("yoetz_launcher")
    isolation_root = marker.get("isolation_root")
    if schema in {_MARKER_SCHEMA_V2, _MARKER_SCHEMA_V3}:
        if (
            format_profile is not PluginFormatProfile.CURSOR_PLUGIN_NATIVE
            or type(launcher) is not list
            or not _valid_launcher(tuple(cast(list[object], launcher)))
        ):
            return False, format_profile, cast(str | None, marker.get("artifact_digest"))
        if schema == _MARKER_SCHEMA_V3 and (
            "isolation_root" not in marker
            or (isolation_root is not None and not _valid_isolation_root_text(isolation_root))
        ):
            return False, format_profile, cast(str | None, marker.get("artifact_digest"))
        if schema == _MARKER_SCHEMA_V2 and isolation_root is not None:
            return False, format_profile, cast(str | None, marker.get("artifact_digest"))
    elif launcher is not None or isolation_root is not None:
        return False, format_profile, cast(str | None, marker.get("artifact_digest"))
    rows = marker.get("managed_files")
    if type(rows) is not list:
        return False, None, None
    expected: dict[str, tuple[int, str]] = {}
    for row in rows:
        if not isinstance(row, Mapping):
            return False, None, None
        path = row.get("relative_path")
        size = row.get("size")
        sha = row.get("sha256")
        if (
            type(path) is not str
            or type(size) is not int
            or type(sha) is not str
            or path in expected
        ):
            return False, None, None
        expected[path] = (size, sha)
    content = {path: data for path, data in files.items() if path != _MARKER_NAME}
    if set(content) != set(expected) or any(
        expected[path] != (len(data), _sha(data)) for path, data in content.items()
    ):
        return False, format_profile, cast(str | None, marker.get("artifact_digest"))
    artifact_digest = marker.get("artifact_digest")
    return True, format_profile, artifact_digest if type(artifact_digest) is str else None


def _inspect(target: CursorPluginTarget, artifact: CursorPluginArtifact) -> _Inspection:
    root, target_identity = _target_path(target)
    destination = root / CURSOR_PLUGIN_RELATIVE_ROOT
    rollback = destination.parent / _ROLLBACK_NAME
    rollback_available = rollback.exists() and rollback.is_dir() and not rollback.is_symlink()
    if rollback.exists() or rollback.is_symlink():
        return _Inspection(
            root,
            destination,
            PluginArtifactState.RECOVERY_REQUIRED,
            None,
            target_identity,
            canonical_digest({"state": "rollback_present"}),
            None,
            False,
            rollback_available,
        )
    parent = destination.parent
    if parent.exists() and any(item.name.startswith(_STAGE_PREFIX) for item in parent.iterdir()):
        return _Inspection(
            root,
            destination,
            PluginArtifactState.RECOVERY_REQUIRED,
            None,
            target_identity,
            canonical_digest({"state": "stage_present"}),
            None,
            False,
            False,
        )
    if not destination.exists():
        return _Inspection(
            root,
            destination,
            PluginArtifactState.ABSENT,
            None,
            target_identity,
            canonical_digest({"state": "absent"}),
            None,
            False,
            False,
        )
    if destination.is_symlink() or not destination.is_dir():
        raise _error(PluginArtifactReason.TARGET_UNSAFE)
    files = _safe_tree(destination)
    current_digest = _tree_digest(files)
    valid, format_profile, installed_digest = _valid_marker(files)
    installed_launcher = _marker_launcher(files) if valid else None
    installed_isolation_root = _marker_isolation_root(files) if valid else None
    if not valid:
        state = (
            PluginArtifactState.MODIFIED
            if format_profile is not None
            else PluginArtifactState.UNMANAGED
        )
        return _Inspection(
            root,
            destination,
            state,
            format_profile,
            target_identity,
            current_digest,
            installed_digest,
            False,
            False,
        )
    expected = {**artifact.members, _MARKER_NAME: _marker(artifact)}
    same_format = format_profile is artifact.plan.format_profile
    state = (
        PluginArtifactState.MODIFIED
        if same_format
        and format_profile is PluginFormatProfile.CURSOR_PLUGIN_NATIVE
        and files != expected
        else PluginArtifactState.PORTABLE_EXACT
        if format_profile is PluginFormatProfile.AGENT_PLUGINS_1 and files == expected
        else PluginArtifactState.PORTABLE_MANAGED
        if format_profile is PluginFormatProfile.AGENT_PLUGINS_1
        else PluginArtifactState.NATIVE_MANAGED
    )
    return _Inspection(
        root,
        destination,
        state,
        format_profile,
        target_identity,
        current_digest,
        installed_digest,
        True,
        False,
        installed_launcher,
        installed_isolation_root,
    )


def _marker_launcher(files: Mapping[str, bytes]) -> tuple[str, ...] | None:
    """Return the exact launcher a marker-valid native tree binds, else ``None``."""

    raw = files.get(_MARKER_NAME)
    marker = None if raw is None else _load_object(raw)
    if marker is None or marker.get("schema") not in {_MARKER_SCHEMA_V2, _MARKER_SCHEMA_V3}:
        return None
    launcher = marker.get("yoetz_launcher")
    if type(launcher) is not list:
        return None
    candidate = tuple(cast(list[object], launcher))
    if not _valid_launcher(candidate):
        return None
    return cast(tuple[str, ...], candidate)


def _marker_isolation_root(files: Mapping[str, bytes]) -> str | None:
    """Return the root recorded by a marker-valid native tree, or ``None`` for legacy/ambient."""

    raw = files.get(_MARKER_NAME)
    marker = None if raw is None else _load_object(raw)
    if marker is None or marker.get("schema") != _MARKER_SCHEMA_V3:
        return None
    value = marker.get("isolation_root")
    if type(value) is not str or not _valid_isolation_root_text(value):
        return None
    return value


_ABSENT_STATE_DIGEST: Final = canonical_digest({"state": "absent"})

_PREVIEW_WARNINGS: Final = (
    "activation_not_inferred_from_installation",
    "cursor_cloud_not_supported",
    "cursor_sdk_support_deferred",
    "mcp_handshake_does_not_prove_model_use",
    "observation_requires_separate_consent",
    "reload_window_does_not_replace_mcp_runtime",
)


def _admissible_owner_states(artifact: CursorPluginArtifact) -> set[McpOwnershipState]:
    """Return the MCP ownership states an install or replace may legitimately observe."""

    if artifact.plan.mcp_ownership is McpOwnership.EXTERNAL_REGISTRATION:
        # Replacement may be the operation that installs plugin-managed MCP.  The
        # currently installed exact external artifact legitimately observes absent.
        return {McpOwnershipState.EXTERNAL, McpOwnershipState.ABSENT}
    return {McpOwnershipState.ABSENT, McpOwnershipState.PLUGIN}


def _isolation_drift_is_replaceable(
    action: PluginArtifactAction,
    inspection: _Inspection,
    artifact: CursorPluginArtifact,
    mcp_observation: CursorMcpObservation,
) -> bool:
    """Allow replacement of only the plugin-owned root binding drift."""

    return (
        action is PluginArtifactAction.REPLACE
        and inspection.marker_valid
        and inspection.format_profile is PluginFormatProfile.CURSOR_PLUGIN_NATIVE
        and artifact.plan.format_profile is PluginFormatProfile.CURSOR_PLUGIN_NATIVE
        and artifact.plan.mcp_ownership is McpOwnership.PLUGIN_MANAGED
        and inspection.installed_isolation_root != artifact.isolation_root
        and mcp_observation.observed
        and mcp_observation.ownership_state is McpOwnershipState.FOREIGN
        and mcp_observation.winning_source is CursorMcpSource.PLUGIN
        and mcp_observation.present_sources == (CursorMcpSource.PLUGIN,)
    )


def _preview_digest(
    request: RequestId,
    effective: PluginArtifactAction,
    artifact: CursorPluginArtifact,
    *,
    current_state_digest: str,
    mcp_ownership_state: McpOwnershipState,
    target_identity: str,
) -> str:
    return canonical_digest(
        {
            "action": effective.value,
            "artifact_digest": artifact.artifact_digest,
            "current_state_digest": current_state_digest,
            "format_profile": artifact.plan.format_profile.value,
            "mcp_ownership": artifact.plan.mcp_ownership.value,
            "mcp_ownership_state": mcp_ownership_state.value,
            "mcp_route_profile": artifact.plan.mcp_route_profile,
            "isolation_root": artifact.isolation_root,
            "request_id": request,
            "target_identity": target_identity,
        }
    )


def _preview_from_inspection(
    request: RequestId,
    action: PluginArtifactAction,
    inspection: _Inspection,
    artifact: CursorPluginArtifact,
    mcp_observation: CursorMcpObservation,
) -> CursorPluginPreview:
    if inspection.state is PluginArtifactState.RECOVERY_REQUIRED:
        raise _error(PluginArtifactReason.RECOVERY_REQUIRED)
    if (
        action is PluginArtifactAction.INSTALL
        and inspection.state is not PluginArtifactState.ABSENT
    ):
        raise _error(PluginArtifactReason.DESTINATION_CONFLICT)
    replace_allowed = inspection.state in {
        PluginArtifactState.PORTABLE_EXACT,
        PluginArtifactState.PORTABLE_MANAGED,
        PluginArtifactState.NATIVE_MANAGED,
    } or (inspection.state is PluginArtifactState.MODIFIED and inspection.marker_valid)
    if action is PluginArtifactAction.REPLACE and not replace_allowed:
        raise _error(PluginArtifactReason.DESTINATION_CONFLICT)
    if action is PluginArtifactAction.REMOVE and (
        inspection.state
        not in {
            PluginArtifactState.PORTABLE_EXACT,
            PluginArtifactState.PORTABLE_MANAGED,
            PluginArtifactState.NATIVE_MANAGED,
            PluginArtifactState.MODIFIED,
        }
        or not inspection.marker_valid
    ):
        raise _error(PluginArtifactReason.REMOVE_REFUSED)
    if action is not PluginArtifactAction.REMOVE:
        allowed = _admissible_owner_states(artifact)
        if mcp_observation.ownership_state not in allowed and not _isolation_drift_is_replaceable(
            action, inspection, artifact, mcp_observation
        ):
            raise _error(
                PluginArtifactReason.MCP_OWNERSHIP_CONFLICT,
                {"mcp_ownership_state": mcp_observation.ownership_state.value},
            )
    exact = (
        inspection.marker_valid
        and inspection.state is not PluginArtifactState.MODIFIED
        and inspection.format_profile is artifact.plan.format_profile
        and inspection.installed_digest == artifact.artifact_digest
    )
    effective = (
        PluginArtifactAction.NOOP
        if exact and action in {PluginArtifactAction.INSTALL, PluginArtifactAction.REPLACE}
        else action
    )
    warnings = tuple(sorted(set(_PREVIEW_WARNINGS), key=str.encode))
    preview_digest = _preview_digest(
        request,
        effective,
        artifact,
        current_state_digest=inspection.current_state_digest,
        mcp_ownership_state=mcp_observation.ownership_state,
        target_identity=inspection.target_identity,
    )
    return CursorPluginPreview(
        request,
        effective,
        inspection.state,
        artifact.plan.format_profile,
        inspection.target_identity,
        inspection.current_state_digest,
        artifact.artifact_digest,
        preview_digest,
        artifact.plan.mcp_ownership,
        mcp_observation.ownership_state,
        artifact.plan.mcp_route_profile,
        artifact.isolation_root,
        warnings,
    )


def preview_cursor_plugin(
    request: RequestId,
    target: CursorPluginTarget,
    action: PluginArtifactAction,
    artifact: CursorPluginArtifact,
    *,
    project_root: Path | None = None,
    inline_create: Mapping[str, JsonValue] | None = None,
    inline_send: Mapping[str, JsonValue] | None = None,
) -> CursorPluginPreview:
    request = validate_request_id(request)
    if type(action) is not PluginArtifactAction or action is PluginArtifactAction.NOOP:
        raise _error(PluginArtifactReason.SOURCE_INVALID)
    inspection = _inspect(target, artifact)
    observation = observe_cursor_mcp(
        plugin_root=inspection.destination,
        project_root=project_root,
        user_config_root=inspection.root,
        inline_create=inline_create,
        inline_send=inline_send,
        yoetz_launchers=_known_launchers(artifact, inspection),
        expected_isolation_root=artifact.isolation_root,
    )
    return _preview_from_inspection(request, action, inspection, artifact, observation)


def _known_launchers(
    artifact: CursorPluginArtifact, inspection: _Inspection
) -> tuple[tuple[str, ...], ...]:
    """Launchers an exact Yoetz MCP entry may name: this artifact's and the installed tree's."""

    known: list[tuple[str, ...]] = []
    for launcher in (artifact.yoetz_launcher, inspection.installed_launcher):
        if launcher is not None and launcher not in known:
            known.append(launcher)
    return tuple(known)


def _write_file(path: Path, data: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short_write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_dir(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _stage(parent: Path, artifact: CursorPluginArtifact, request: RequestId) -> Path:
    stage = parent / f"{_STAGE_PREFIX}{request.removeprefix('req_')}"
    if stage.exists() or stage.is_symlink():
        raise _error(PluginArtifactReason.RECOVERY_REQUIRED)
    stage.mkdir(mode=0o700)
    try:
        members = {**artifact.members, _MARKER_NAME: _marker(artifact)}
        for relative, data in sorted(members.items(), key=lambda item: item[0].encode("ascii")):
            destination = stage / relative
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if destination.parent.is_symlink():
                raise _error(PluginArtifactReason.TARGET_UNSAFE)
            _write_file(destination, data)
        for directory in sorted(
            (path for path in stage.rglob("*") if path.is_dir()),
            key=lambda item: len(item.parts),
            reverse=True,
        ):
            _fsync_dir(directory)
        _fsync_dir(stage)
        return stage
    except BaseException:
        shutil.rmtree(stage, ignore_errors=True)
        raise


class _DenyStandaloneCursorReview:
    """Default authority port: an unwired caller can prove no consent at all.

    ADR-016/ADR-023 are explicit that a TTY confirmation, ``--accept``, or a same-UID process is
    not ``UserPresencePort`` authority, so the default here refuses instead of trusting the
    ``ArtifactAuthority`` discriminator that the caller itself constructed.
    """

    def consume_setup_authority(self, authority: ArtifactAuthority, preview_digest: str) -> None:
        del authority, preview_digest
        raise _error(PluginArtifactReason.AUTHORITY_REQUIRED)

    def consume_artifact_review(self, authority: ArtifactAuthority, preview_digest: str) -> None:
        del authority, preview_digest
        raise _error(PluginArtifactReason.HUMAN_AUTHORITY_UNAVAILABLE)


def _consume_authority(
    review: PluginMutationReviewPort | None,
    authority: ArtifactAuthority | None,
    accepted_preview_digest: str,
) -> None:
    """Consume exactly one injected authority bound to the accepted preview digest."""

    if type(authority) is not ArtifactAuthority:
        raise _error(PluginArtifactReason.AUTHORITY_REQUIRED)
    if authority.target_digest != accepted_preview_digest:
        raise _error(PluginArtifactReason.AUTHORITY_REQUIRED)
    port: PluginMutationReviewPort = _DenyStandaloneCursorReview() if review is None else review
    try:
        if authority.channel == "review_only":
            port.consume_artifact_review(authority, accepted_preview_digest)
        else:
            port.consume_setup_authority(authority, accepted_preview_digest)
    except PluginArtifactError as exc:
        # The shared elevated-bootstrap review port raises the neutral artifact error. Keep one
        # error type on the Cursor surface without inventing a reason the port did not choose.
        raise _error(exc.reason) from exc


def _reconciled_install(
    request: RequestId,
    action: PluginArtifactAction,
    inspection: _Inspection,
    artifact: CursorPluginArtifact,
    accepted_preview_digest: str,
) -> CursorPluginResult | None:
    """Recognize a committed install whose result was lost, without touching any bytes.

    A replay of an install that already committed reconciles at the selected state rather than
    refusing with ``destination_conflict``. The destination must be marker-valid at the accepted
    artifact digest and format, and the accepted preview digest must equal the digest an
    ``absent`` preview would produce for that artifact and target at one of the MCP ownership
    states preview already admits.

    Recognition is stateless, so it is not request-bound and must not be read as one. The preview
    digest is a pure function of request ID, action, artifact digest, the ``absent`` state digest,
    owner state, and target identity, so any caller can recompute an accepted digest for a request
    ID that never committed anything and reach this result. That is deliberate rather than a
    bypass: this branch is a read-only equivalent of ``status``. It mutates nothing, consumes no
    authority, spends no review, and reports only the state already on disk. What it cannot do is
    claim a state that is not there -- a different artifact, format, target, or an unmarked,
    modified, or absent destination still fails closed.
    """

    if action is not PluginArtifactAction.INSTALL:
        return None
    if (
        not inspection.marker_valid
        or inspection.format_profile is not artifact.plan.format_profile
        or inspection.installed_digest != artifact.artifact_digest
    ):
        return None
    committed = {
        _preview_digest(
            request,
            PluginArtifactAction.INSTALL,
            artifact,
            current_state_digest=_ABSENT_STATE_DIGEST,
            mcp_ownership_state=owner_state,
            target_identity=inspection.target_identity,
        )
        for owner_state in _admissible_owner_states(artifact)
    }
    if accepted_preview_digest not in committed:
        return None
    return CursorPluginResult(
        request,
        PluginArtifactAction.NOOP,
        PluginOperationState.COMPLETED,
        inspection.state,
        inspection.state,
        artifact.plan.format_profile,
        accepted_preview_digest,
        artifact.artifact_digest,
        inspection.installed_digest,
        (),
    )


def _reconciled_remove(
    request: RequestId,
    inspection: _Inspection,
    artifact: CursorPluginArtifact,
    accepted_preview_digest: str,
) -> CursorPluginResult | None:
    """Recognize a committed remove whose result was lost.

    Removal's entire effect is that the managed destination is absent, and that is exactly what
    is observed here, so the replay reports the reconciled no-op instead of ``remove_refused``.
    The pre-commit tree digest that the accepted preview bound is gone with the tree, so this
    path deliberately cannot re-prove that binding; it also mutates nothing, spends no review,
    and never reports removal of bytes that are still present -- every other ``remove_refused``
    state (modified, unmanaged, native/portable managed) still refuses.
    """

    if inspection.state is not PluginArtifactState.ABSENT:
        return None
    return CursorPluginResult(
        request,
        PluginArtifactAction.NOOP,
        PluginOperationState.COMPLETED,
        PluginArtifactState.ABSENT,
        PluginArtifactState.ABSENT,
        artifact.plan.format_profile,
        accepted_preview_digest,
        artifact.artifact_digest,
        None,
        (),
    )


def apply_cursor_plugin(
    request: RequestId,
    target: CursorPluginTarget,
    action: PluginArtifactAction,
    artifact: CursorPluginArtifact,
    *,
    accepted_preview_digest: str,
    authority: ArtifactAuthority | None,
    review: PluginMutationReviewPort | None = None,
    project_root: Path | None = None,
) -> CursorPluginResult:
    _validate_digest(accepted_preview_digest)
    request = validate_request_id(request)
    try:
        preview = preview_cursor_plugin(
            request,
            target,
            action,
            artifact,
            project_root=project_root,
        )
    except CursorIntegrationError as exc:
        if exc.reason is not PluginArtifactReason.DESTINATION_CONFLICT:
            raise
        # Reconcile before authority: an already-committed state must not require a second
        # single-shot review, and this branch mutates nothing.
        reconciled = _reconciled_install(
            request,
            action,
            _inspect(target, artifact),
            artifact,
            accepted_preview_digest,
        )
        if reconciled is None:
            raise
        return reconciled
    if preview.preview_digest != accepted_preview_digest:
        raise _error(PluginArtifactReason.PREVIEW_STALE)
    _consume_authority(review, authority, accepted_preview_digest)
    if preview.action is PluginArtifactAction.NOOP:
        return CursorPluginResult(
            preview.request_id,
            preview.action,
            PluginOperationState.COMPLETED,
            preview.state_before,
            preview.state_before,
            preview.format_profile,
            preview.preview_digest,
            preview.artifact_digest,
            preview.artifact_digest,
            (),
        )
    root, _identity = _target_path(target)
    _ensure_private_path(root / "plugins" / "local")
    destination = root / CURSOR_PLUGIN_RELATIVE_ROOT
    parent = destination.parent
    rollback = parent / _ROLLBACK_NAME
    stage = _stage(parent, artifact, preview.request_id)
    moved_existing = False
    try:
        if destination.exists():
            os.replace(destination, rollback)
            moved_existing = True
            _fsync_dir(parent)
        os.replace(stage, destination)
        _fsync_dir(parent)
        installed = _safe_tree(destination)
        if installed != {**artifact.members, _MARKER_NAME: _marker(artifact)}:
            raise OSError("installed_bytes_mismatch")
    except BaseException as exc:
        with contextlib.suppress(OSError):
            if destination.exists():
                failed = parent / f"{_STAGE_PREFIX}failed"
                os.replace(destination, failed)
            if moved_existing and rollback.exists() and not destination.exists():
                os.replace(rollback, destination)
                _fsync_dir(parent)
        raise _error(PluginArtifactReason.WRITE_FAILED) from exc
    # The new bytes are committed once the exact post-swap verification passes.
    # Cleanup failure must never enter the pre-commit rollback branch: the old
    # tree may already be partially removed.  Preserve both trees and report a
    # recovery-required state instead of guessing which outcome won.
    if moved_existing:
        try:
            shutil.rmtree(rollback)
            _fsync_dir(parent)
        except OSError as exc:
            raise _error(PluginArtifactReason.WRITE_FAILED) from exc
    after = (
        PluginArtifactState.PORTABLE_EXACT
        if artifact.plan.format_profile is PluginFormatProfile.AGENT_PLUGINS_1
        else PluginArtifactState.NATIVE_MANAGED
    )
    return CursorPluginResult(
        preview.request_id,
        preview.action,
        PluginOperationState.COMPLETED,
        preview.state_before,
        after,
        preview.format_profile,
        preview.preview_digest,
        preview.artifact_digest,
        preview.artifact_digest,
        tuple(sorted({*artifact.members, _MARKER_NAME}, key=str.encode)),
    )


def remove_cursor_plugin(
    request: RequestId,
    target: CursorPluginTarget,
    artifact: CursorPluginArtifact,
    *,
    accepted_preview_digest: str,
    authority: ArtifactAuthority | None,
    review: PluginMutationReviewPort | None = None,
    project_root: Path | None = None,
) -> CursorPluginResult:
    _validate_digest(accepted_preview_digest)
    request = validate_request_id(request)
    try:
        preview = preview_cursor_plugin(
            request,
            target,
            PluginArtifactAction.REMOVE,
            artifact,
            project_root=project_root,
        )
    except CursorIntegrationError as exc:
        if exc.reason is not PluginArtifactReason.REMOVE_REFUSED:
            raise
        # Reconcile before authority: see _reconciled_remove.
        reconciled = _reconciled_remove(
            request,
            _inspect(target, artifact),
            artifact,
            accepted_preview_digest,
        )
        if reconciled is None:
            raise
        return reconciled
    if preview.preview_digest != accepted_preview_digest:
        raise _error(PluginArtifactReason.PREVIEW_STALE)
    _consume_authority(review, authority, accepted_preview_digest)
    root, _identity = _target_path(target)
    destination = root / CURSOR_PLUGIN_RELATIVE_ROOT
    rollback = destination.parent / _ROLLBACK_NAME
    files = tuple(sorted(_safe_tree(destination), key=str.encode))
    try:
        os.replace(destination, rollback)
        _fsync_dir(destination.parent)
        shutil.rmtree(rollback)
        _fsync_dir(destination.parent)
    except OSError as exc:
        raise _error(PluginArtifactReason.WRITE_FAILED) from exc
    return CursorPluginResult(
        preview.request_id,
        PluginArtifactAction.REMOVE,
        PluginOperationState.COMPLETED,
        preview.state_before,
        PluginArtifactState.ABSENT,
        preview.format_profile,
        preview.preview_digest,
        preview.artifact_digest,
        None,
        files,
    )


def _proof(state: PluginArtifactState) -> tuple[PluginProofStatus, ...]:
    installed = state in {
        PluginArtifactState.PORTABLE_EXACT,
        PluginArtifactState.PORTABLE_MANAGED,
        PluginArtifactState.NATIVE_MANAGED,
    }
    return tuple(
        PluginProofStatus(
            facet,
            (
                "proven"
                if facet in {PluginProofFacet.SOURCE, PluginProofFacet.RENDERED_ARTIFACT}
                or (installed and facet is PluginProofFacet.INSTALLED_BYTES)
                else "not_observed"
            ),
        )
        for facet in PluginProofFacet
    )


def status_cursor_plugin(
    target: CursorPluginTarget,
    artifact: CursorPluginArtifact,
    *,
    project_root: Path | None = None,
    processes: CursorMcpProcessPort | None = None,
    launcher_probe: LauncherProbePort | None = None,
) -> CursorPluginStatus:
    inspection = _inspect(target, artifact)
    observation = observe_cursor_mcp(
        plugin_root=inspection.destination,
        project_root=project_root,
        user_config_root=inspection.root,
        yoetz_launchers=_known_launchers(artifact, inspection),
        expected_isolation_root=artifact.isolation_root,
    )
    runtime = observe_cursor_mcp_runtime(
        installed_route=observation.route_profile,
        processes=(
            OsCursorMcpProcesses(inspection.installed_launcher) if processes is None else processes
        ),
    )
    launcher = _launcher_status(
        artifact,
        inspection,
        OsLauncherProbe() if launcher_probe is None else launcher_probe,
    )
    isolation_binding = _isolation_binding(artifact, inspection)
    return CursorPluginStatus(
        inspection.state,
        (
            PluginOperationState.IN_PROGRESS
            if inspection.state is PluginArtifactState.RECOVERY_REQUIRED
            else PluginOperationState.NOT_STARTED
            if inspection.state is PluginArtifactState.ABSENT
            else PluginOperationState.COMPLETED
        ),
        inspection.format_profile,
        artifact.artifact_digest,
        inspection.installed_digest,
        inspection.marker_valid,
        inspection.rollback_available,
        observation,
        runtime,
        _proof(inspection.state),
        launcher,
        isolation_binding,
    )


def _isolation_binding(
    artifact: CursorPluginArtifact, inspection: _Inspection
) -> CursorIsolationBindingState:
    """Classify the native artifact's exact state-root binding without exposing the path.

    The marker is necessary but not sufficient: the root-bearing MCP and hook members must also
    still carry the expected binding before status reports ``ambient`` or ``isolated_exact``.
    """

    if artifact.plan.format_profile is not PluginFormatProfile.CURSOR_PLUGIN_NATIVE:
        return "unobserved"
    if not inspection.marker_valid:
        return "unobserved"
    installed = inspection.installed_isolation_root
    expected = artifact.isolation_root
    if expected is None:
        if installed is not None:
            return "different"
        return "ambient" if _root_binding_surfaces_match(artifact, inspection) else "different"
    if installed == expected:
        return (
            "isolated_exact" if _root_binding_surfaces_match(artifact, inspection) else "different"
        )
    return "missing" if installed is None else "different"


def _safe_json_object(path: Path) -> Mapping[str, JsonValue] | None:
    """Read one regular JSON file without following a host-owned symlink."""

    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > _MAX_FILE_BYTES:
            return None
        return _load_object(path.read_bytes())
    except OSError:
        return None


def _route_isolation_binding(
    entry: Mapping[str, JsonValue] | None,
) -> tuple[Literal["ambient", "isolated", "invalid", "missing"], str | None]:
    """Return only the isolation binding represented by a parsed MCP entry."""

    if entry is None:
        return "missing", None
    keys = set(entry)
    if keys == {"args", "command", "type"}:
        return "ambient", None
    if keys == {"args", "command", "type", "env"}:
        valid, root = _entry_isolation_root(entry)
        return ("isolated", root) if valid else ("invalid", None)
    return "invalid", None


def _mcp_entry_from_object(
    document: Mapping[str, JsonValue] | None,
) -> Mapping[str, JsonValue] | None:
    if document is None:
        return None
    servers = document.get("mcpServers")
    if not isinstance(servers, Mapping):
        return None
    entry = servers.get("yoetz")
    return cast(Mapping[str, JsonValue], entry) if isinstance(entry, Mapping) else None


def _root_binding_surfaces_match(artifact: CursorPluginArtifact, inspection: _Inspection) -> bool:
    """Check root-bearing MCP and hook members before reporting an exact binding."""

    expected_hooks = _load_object(artifact.members.get("hooks/hooks.json", b""))
    current_hooks = _safe_json_object(inspection.destination / "hooks" / "hooks.json")
    if expected_hooks is None or current_hooks is None:
        return False
    expected_hook_map = expected_hooks.get("hooks")
    current_hook_map = current_hooks.get("hooks")
    if not isinstance(expected_hook_map, Mapping) or not isinstance(current_hook_map, Mapping):
        return False
    expected_prefix = (
        ""
        if artifact.isolation_root is None
        else f"{ISOLATED_ROOT_ENV}={shlex.quote(artifact.isolation_root)} "
    )
    hook_events = (
        CURSOR_ORDINARY_HOOK_EVENTS
        if artifact.plan.host_extension_profile == CURSOR_ORDINARY_OBSERVATION_PROFILE_ID
        else CURSOR_HOOK_EVENTS
    )
    for event in hook_events:
        expected_definition = expected_hook_map.get(event)
        current_definition = current_hook_map.get(event)
        if not isinstance(expected_definition, list) or not expected_definition:
            return False
        if not isinstance(current_definition, list) or not current_definition:
            return False
        expected_first = expected_definition[0]
        current_first = current_definition[0]
        if not isinstance(expected_first, Mapping) or not isinstance(current_first, Mapping):
            return False
        expected_command = expected_first.get("command")
        current_command = current_first.get("command")
        if not isinstance(expected_command, str) or not isinstance(current_command, str):
            return False
        if artifact.isolation_root is None:
            if f"{ISOLATED_ROOT_ENV}=" in current_command:
                return False
        elif not current_command.startswith(expected_prefix):
            return False

    if "mcp.json" not in artifact.members:
        return True
    expected_mcp = _mcp_entry_from_object(_load_object(artifact.members["mcp.json"]))
    current_mcp = _mcp_entry_from_object(_safe_json_object(inspection.destination / "mcp.json"))
    expected_kind, expected_root = _route_isolation_binding(expected_mcp)
    current_kind, current_root = _route_isolation_binding(current_mcp)
    return (current_kind, current_root) == (expected_kind, expected_root)


def _installed_mcp_binding(
    inspection: _Inspection,
    installed_launcher: tuple[str, ...] | None,
    expected_isolation_root: str | None,
) -> CursorMcpBindingState:
    """Say what the installed plugin-owned ``mcp.json`` would make Cursor spawn."""

    if not inspection.marker_valid:
        return "unobserved"
    entry, observed = _config_entry(inspection.destination / "mcp.json")
    if not observed:
        return "unobserved"
    if entry is None:
        return "absent"
    command = entry.get("command")
    if (
        command == "yoetz"
        and _route_profile(entry, expected_isolation_root=expected_isolation_root) is not None
    ):
        return "ambient_path"
    if (
        installed_launcher is not None
        and command == installed_launcher[0]
        and _route_profile(
            entry,
            (installed_launcher,),
            expected_isolation_root=expected_isolation_root,
        )
        is not None
    ):
        return "exact_launcher"
    return "foreign"


def _launcher_status(
    artifact: CursorPluginArtifact,
    inspection: _Inspection,
    launcher_probe: LauncherProbePort,
) -> CursorLauncherStatus:
    installed = inspection.installed_launcher
    binding = _installed_mcp_binding(inspection, installed, artifact.isolation_root)
    if not inspection.marker_valid:
        return CursorLauncherStatus(
            artifact.yoetz_launcher, None, "unobserved", binding, UNOBSERVED_LAUNCHER_IDENTITY
        )
    if installed is None:
        return CursorLauncherStatus(
            artifact.yoetz_launcher, None, "unbound", binding, UNOBSERVED_LAUNCHER_IDENTITY
        )
    executable_path = Path(installed[0])
    executable: CursorLauncherExecutableState
    try:
        present = executable_path.is_file() and os.access(executable_path, os.X_OK)
    except OSError:
        present = False
    if not present:
        executable = "missing"
    elif installed != artifact.yoetz_launcher:
        executable = "drifted"
    else:
        executable = "matched"
    identity = UNOBSERVED_LAUNCHER_IDENTITY
    if present:
        identity = _probe_launcher_identity(installed, launcher_probe)
    return CursorLauncherStatus(artifact.yoetz_launcher, installed, executable, binding, identity)


def _probe_launcher_identity(
    launcher: tuple[str, ...], launcher_probe: LauncherProbePort
) -> LauncherIdentity:
    from yoetz.version import build_version_manifest

    try:
        document = launcher_probe.probe(launcher)
    except Exception:
        return UNOBSERVED_LAUNCHER_IDENTITY
    if document is None:
        return UNOBSERVED_LAUNCHER_IDENTITY
    try:
        own = build_version_manifest()
    except Exception:
        return UNOBSERVED_LAUNCHER_IDENTITY
    control_schema_version = dict(own.request_result_schema_versions).get("control-result")
    if control_schema_version is None:
        return UNOBSERVED_LAUNCHER_IDENTITY
    return compare_launcher_identity(
        document,
        package_version=own.package_version,
        control_schema_version=control_schema_version,
        resource_manifest_digest=own.resource_manifest_digest,
    )


def _config_entry(path: Path) -> tuple[Mapping[str, JsonValue] | None, bool]:
    if not path.exists() and not path.is_symlink():
        return None, True
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > _MAX_FILE_BYTES:
            return None, False
        parsed = strict_json_parse(path.read_bytes())
    except OSError, ProtocolValueError, UnicodeError:
        return None, False
    if not isinstance(parsed, Mapping):
        return None, False
    servers = parsed.get("mcpServers")
    if not isinstance(servers, Mapping):
        return None, "mcpServers" not in parsed
    entry = servers.get("yoetz")
    if entry is None:
        return None, True
    if not isinstance(entry, Mapping):
        return None, False
    return cast(Mapping[str, JsonValue], entry), True


_POLICY_ROUTE_ARGS: Final = frozenset({("mcp", "serve"), _MCP_SERVE_ARGS})
_STRICT_ROUTE_ARGS: Final = frozenset(
    {("mcp", "serve", "--semantic", "off"), _MCP_SERVE_STRICT_ARGS}
)
_UNSET_ISOLATION_ROOT: Final = object()


def _route_profile(
    entry: Mapping[str, JsonValue] | None,
    yoetz_launchers: tuple[tuple[str, ...], ...] = (),
    *,
    expected_isolation_root: str | None | object = _UNSET_ISOLATION_ROOT,
    expected_project_root: Path | None = None,
) -> Literal["strict", "policy"] | None:
    """Classify one MCP entry as an exact Yoetz route, else ``None``.

    An exact route launches either a bare ``yoetz`` console script (an external registration
    the owner wrote by hand) or one of ``yoetz_launchers`` — this artifact's exact bound
    launcher, or the launcher the installed marker recorded — followed by the exact ``mcp
    serve`` arguments. When ``expected_isolation_root`` is supplied, the route must carry that
    exact root (or no environment in ambient mode); omission keeps this helper's route-shape
    classification independent from lifecycle ownership.
    """

    if entry is None:
        return None
    # Any non-exact same-name entry is foreign, so recognition is key-set exact and not merely
    # value-compatible. The one exception is the exact isolated-root environment binding owned
    # by this adapter. Route-shape callers may omit ``expected_isolation_root`` to classify a
    # structurally valid isolated route; lifecycle ownership callers pass the artifact's exact
    # expected root so a different root cannot count as owned or admitted. Arbitrary environment
    # keys remain foreign and are never overwritten.
    registered_isolation_root: str | None = None
    keys = set(entry)
    if keys == {"args", "command", "type"}:
        pass
    elif keys == {"args", "command", "type", "env"}:
        readable, registered_isolation_root = _entry_isolation_root(entry)
        if not readable:
            return None
    else:
        return None
    if (
        expected_isolation_root is not _UNSET_ISOLATION_ROOT
        and registered_isolation_root != expected_isolation_root
    ):
        return None
    if entry.get("type") != "stdio":
        return None
    raw_args = entry.get("args")
    if not isinstance(raw_args, list | tuple):
        return None
    args = tuple(cast(Sequence[object], raw_args))
    command = entry.get("command")
    prefix: tuple[str, ...] | None = None
    if command == "yoetz":
        prefix = ()
    else:
        for launcher in yoetz_launchers:
            if _valid_launcher(launcher) and command == launcher[0]:
                prefix = launcher[1:]
                break
    if prefix is None or args[: len(prefix)] != prefix:
        return None
    rest = args[len(prefix) :]
    if expected_project_root is not None:
        for selector in (str(expected_project_root), "${workspaceFolder}"):
            project_prefix = (*_MCP_SERVE_ARGS, "--project-root", selector)
            for binding in ((), ("--project-binding", "registered-project")):
                if selector == "${workspaceFolder}" and binding:
                    continue
                if rest == (*project_prefix, *binding):
                    return "policy"
                if rest == (*project_prefix, *binding, "--semantic", "off"):
                    return "strict"
    if rest in _POLICY_ROUTE_ARGS:
        return "policy"
    if rest in _STRICT_ROUTE_ARGS:
        return "strict"
    return None


def _entry_isolation_root(entry: Mapping[str, JsonValue]) -> tuple[bool, str | None]:
    """Read the only environment binding a Cursor route may carry."""

    environment = entry.get("env")
    if not isinstance(environment, Mapping):
        return False, None
    values = cast(Mapping[object, object], environment)
    if set(values) != {ISOLATED_ROOT_ENV}:
        return False, None
    raw = values.get(ISOLATED_ROOT_ENV)
    if not _valid_isolation_root_text(raw):
        return False, None
    return True, cast(str, raw)


def observe_cursor_mcp(
    *,
    plugin_root: Path,
    project_root: Path | None,
    user_config_root: Path,
    inline_create: Mapping[str, JsonValue] | None = None,
    inline_send: Mapping[str, JsonValue] | None = None,
    yoetz_launchers: tuple[tuple[str, ...], ...] = (),
    expected_isolation_root: str | None = None,
) -> CursorMcpObservation:
    """Classify exact same-name sources using Cursor SDK precedence.

    A successful route-shaped entry is not silently attributed to the plugin.
    Duplicate exact sources remain ambiguous (or dual for plugin+external), and
    any same-name foreign entry remains foreign. ``yoetz_launchers`` are the exact
    bound launchers (this artifact's and the installed marker's) that an exact route
    may name beside a bare ``yoetz``. The expected isolation root defaults to ambient mode;
    callers rendering an isolated artifact pass its exact root explicitly. Route-shape-only
    classification remains available through the private ``_route_profile`` helper.
    """

    candidates: list[tuple[CursorMcpSource, Mapping[str, JsonValue] | None]] = []
    uncertain: list[CursorMcpSource] = []
    for source, raw in (
        (CursorMcpSource.INLINE_SEND, inline_send),
        (CursorMcpSource.INLINE_CREATE, inline_create),
    ):
        if raw is not None:
            entry = raw.get("yoetz") if isinstance(raw.get("yoetz"), Mapping) else raw
            candidates.append((source, cast(Mapping[str, JsonValue], entry)))
    plugin_entry, plugin_observed = _config_entry(plugin_root / "mcp.json")
    if not plugin_observed:
        uncertain.append(CursorMcpSource.PLUGIN)
    if plugin_entry is not None:
        candidates.append((CursorMcpSource.PLUGIN, plugin_entry))
    if project_root is not None:
        project_entry, project_observed = _config_entry(project_root / ".cursor" / "mcp.json")
        if not project_observed:
            uncertain.append(CursorMcpSource.PROJECT)
        if project_entry is not None:
            candidates.append((CursorMcpSource.PROJECT, project_entry))
    user_entry, user_observed = _config_entry(user_config_root / "mcp.json")
    if not user_observed:
        uncertain.append(CursorMcpSource.USER)
    if user_entry is not None:
        candidates.append((CursorMcpSource.USER, user_entry))
    if uncertain:
        present = tuple(source for source, _entry in candidates)
        return CursorMcpObservation(
            McpOwnershipState.AMBIGUOUS,
            None,
            None,
            tuple(dict.fromkeys((*present, *uncertain))),
            False,
        )
    if not candidates:
        return CursorMcpObservation(McpOwnershipState.ABSENT, None, None, (), True)
    profiles = [
        (
            source,
            _route_profile(
                entry,
                yoetz_launchers,
                expected_isolation_root=expected_isolation_root,
                expected_project_root=project_root if source is CursorMcpSource.PROJECT else None,
            ),
        )
        for source, entry in candidates
    ]
    present = tuple(source for source, _profile in profiles)
    if any(profile is None for _source, profile in profiles):
        foreign_source = next(source for source, profile in profiles if profile is None)
        return CursorMcpObservation(McpOwnershipState.FOREIGN, foreign_source, None, present, True)
    plugin_profiles = [profile for source, profile in profiles if source is CursorMcpSource.PLUGIN]
    external_profiles = [
        profile for source, profile in profiles if source is not CursorMcpSource.PLUGIN
    ]
    if plugin_profiles and external_profiles:
        return CursorMcpObservation(McpOwnershipState.DUAL, present[0], None, present, True)
    if len(profiles) > 1:
        return CursorMcpObservation(McpOwnershipState.AMBIGUOUS, present[0], None, present, True)
    source, profile = profiles[0]
    assert profile is not None
    return CursorMcpObservation(
        McpOwnershipState.PLUGIN
        if source is CursorMcpSource.PLUGIN
        else McpOwnershipState.EXTERNAL,
        source,
        cast(Literal["strict", "policy"], profile),
        present,
        True,
    )


def _digest_file(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError("cursor_artifact_unavailable")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def discover_cursor_ide(app_path: Path, *, system: str | None = None) -> CursorCapabilityIdentity:
    """Read an IDE installation identity without executing it or certifying a host cell."""

    resolved_system = platform.system() if system is None else system
    if resolved_system == "Linux":
        return _discover_linux_cursor_ide(app_path)

    info_path = app_path / "Contents" / "Info.plist"
    executable_root = app_path / "Contents" / "MacOS"
    if app_path.is_symlink() or not info_path.is_file() or info_path.is_symlink():
        if resolved_system != "Darwin" and not info_path.exists():
            raise ValueError("cursor_ide_platform_unsupported")
        raise ValueError("cursor_ide_unavailable")
    try:
        info = plistlib.loads(info_path.read_bytes())
    except (OSError, plistlib.InvalidFileException) as exc:
        raise ValueError("cursor_ide_identity_invalid") from exc
    executable_name = info.get("CFBundleExecutable")
    version = info.get("CFBundleShortVersionString")
    build = info.get("CFBundleVersion")
    if not all(type(item) is str and item for item in (executable_name, version, build)):
        raise ValueError("cursor_ide_identity_invalid")
    executable = executable_root / cast(str, executable_name)
    return CursorCapabilityIdentity(
        "cursor_ide",
        cast(str, version),
        cast(str, build),
        _digest_file(executable),
        platform.system().lower(),
        platform.machine().lower(),
    )


def _discover_linux_cursor_ide(app_path: Path) -> CursorCapabilityIdentity:
    """Inspect the installed package root (also inside an extracted AppImage).

    Accept an explicit root or a symlink to its native executable. Never run an AppImage,
    CLI shell wrapper, or Windows launcher to infer a Linux IDE identity.
    """

    try:
        selected = app_path.resolve(strict=True)
        root = selected if selected.is_dir() else selected.parent
        executable = root / "cursor"
        if selected != root and selected != executable:
            raise ValueError("cursor_ide_layout_unsupported")
        metadata_root = root / "resources" / "app"
        # Package members must stay in this installation. The selected installation itself
        # may be reached through the package manager's ordinary executable symlink.
        members = (root / "resources", metadata_root, executable)
        if any(member.is_symlink() for member in members):
            raise ValueError("cursor_ide_identity_invalid")
        if not metadata_root.is_dir():
            raise ValueError("cursor_ide_layout_unsupported")
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise ValueError("cursor_ide_unavailable")
        with executable.open("rb") as stream:
            header = stream.read(20)
            if (
                len(header) != 20
                or header[:6] != b"\x7fELF\x02\x01"
                or int.from_bytes(header[16:18], "little") not in {2, 3}
            ):
                raise ValueError("cursor_ide_identity_invalid")
        architecture = {62: "x86_64", 183: "aarch64"}.get(int.from_bytes(header[18:20], "little"))
        if architecture is None:
            raise ValueError("cursor_ide_identity_invalid")
        metadata: list[Mapping[str, JsonValue]] = []
        for name in ("package.json", "product.json"):
            path = metadata_root / name
            if path.is_symlink() or not path.is_file():
                raise ValueError("cursor_ide_identity_invalid")
            with path.open("rb") as stream:
                content = stream.read(_MAX_CURSOR_IDENTITY_METADATA_BYTES + 1)
            if len(content) > _MAX_CURSOR_IDENTITY_METADATA_BYTES:
                raise ValueError("cursor_ide_identity_invalid")
            value = strict_json_parse(content)
            if not isinstance(value, Mapping):
                raise ValueError("cursor_ide_identity_invalid")
            metadata.append(value)
        package, product = metadata
        version = package.get("version")
        build = product.get("commit")
        if product.get("applicationName") != "cursor" or not all(
            _valid_cursor_identity_text(value) for value in (version, build)
        ):
            raise ValueError("cursor_ide_identity_invalid")
        return CursorCapabilityIdentity(
            "cursor_ide",
            cast(str, version),
            cast(str, build),
            _digest_file(executable),
            "linux",
            architecture,
        )
    except (OSError, RuntimeError) as exc:
        raise ValueError("cursor_ide_unavailable") from exc
    except ProtocolValueError as exc:
        raise ValueError("cursor_ide_identity_invalid") from exc


def discover_cursor_cli(executable: Path) -> CursorCapabilityIdentity:
    if executable.is_symlink():
        resolved = executable.resolve(strict=True)
    else:
        resolved = executable
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise ValueError("cursor_cli_unavailable")
    try:
        with tempfile.TemporaryDirectory(prefix="yoetz-cursor-discovery-") as temporary:
            environment = dict(os.environ)
            environment.update(
                {
                    "CURSOR_CONFIG_DIR": str(Path(temporary) / "config"),
                    "CURSOR_DATA_DIR": str(Path(temporary) / "data"),
                    "HOME": temporary,
                    "XDG_CACHE_HOME": str(Path(temporary) / "cache"),
                    "XDG_CONFIG_HOME": str(Path(temporary) / "xdg-config"),
                    "XDG_DATA_HOME": str(Path(temporary) / "xdg-data"),
                }
            )
            completed = subprocess.run(
                (str(executable), "--version"),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                check=False,
                shell=False,
                timeout=5,
                env=environment,
            )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError("cursor_cli_unavailable") from exc
    if completed.returncode != 0:
        raise ValueError("cursor_cli_unavailable")
    if len(completed.stdout) > _MAX_CURSOR_IDENTITY_BYTES:
        raise ValueError("cursor_cli_identity_invalid")
    try:
        output = completed.stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("cursor_cli_identity_invalid") from exc
    version = next((line.strip() for line in output.splitlines() if line.strip()), "")
    if not version or len(version) > 128:
        raise ValueError("cursor_cli_identity_invalid")
    return CursorCapabilityIdentity(
        "cursor_cli",
        version,
        version,
        _digest_file(resolved),
        platform.system().lower(),
        platform.machine().lower(),
    )


def discover_cursor_sdk(
    binding: CursorSdkBinding,
    *,
    package_metadata: Path,
    bridge_path: Path | None = None,
) -> CursorArtifactIdentity:
    if type(binding) is not CursorSdkBinding:
        raise ValueError("cursor_sdk_binding_invalid")
    if package_metadata.is_symlink() or not package_metadata.is_file():
        raise ValueError("cursor_sdk_unavailable")
    package_digest = _digest_file(package_metadata)
    try:
        metadata = strict_json_parse(package_metadata.read_bytes())
    except ProtocolValueError, UnicodeError:
        metadata = None
    version: object = None
    if isinstance(metadata, Mapping):
        version = metadata.get("version")
    if version is None and binding is CursorSdkBinding.PYTHON:
        # A wheel METADATA file is deliberately parsed without importing the package.
        for line in package_metadata.read_text("utf-8").splitlines():
            if line.startswith("Version: "):
                version = line.removeprefix("Version: ").strip()
                break
    if type(version) is not str or not version or len(version) > 128:
        raise ValueError("cursor_sdk_version_invalid")
    bridge_digest = None if bridge_path is None else _digest_file(bridge_path)
    return CursorArtifactIdentity(binding, version, package_digest, bridge_digest=bridge_digest)


def build_cursor_sdk_profile(
    identity: CursorArtifactIdentity,
    *,
    setting_sources: Sequence[Literal["plugins", "project", "user"]],
    mcp_ownership: McpOwnership,
    sandbox_enabled: bool,
    approval_mode: Literal["default", "allowlist", "full"],
) -> CursorSdkProfile:
    return CursorSdkProfile(
        identity,
        tuple(setting_sources),
        (
            CursorMcpSource.INLINE_SEND,
            CursorMcpSource.INLINE_CREATE,
            CursorMcpSource.PLUGIN,
            CursorMcpSource.PROJECT,
            CursorMcpSource.USER,
        ),
        mcp_ownership,
        sandbox_enabled,
        approval_mode,
    )
