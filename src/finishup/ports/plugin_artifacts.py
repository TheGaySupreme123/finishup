"""Neutral portable-plugin artifact lifecycle boundary (ADR-023)."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Final, Literal, Protocol, cast

from finishup.domain.values import JsonObject, RequestId, request_id, validate_sha256_digest
from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.protocol.errors import ProtocolValueError

__all__ = [
    "ArtifactAuthority",
    "ArtifactTarget",
    "LEGACY_INSTALLATIONS",
    "HostSurface",
    "LegacyInstallation",
    "ManagedPluginFile",
    "McpOwnership",
    "McpOwnershipState",
    "PluginArtifactAction",
    "PluginArtifactApplyCommand",
    "PluginArtifactError",
    "PluginArtifactPort",
    "PluginArtifactPreview",
    "PluginArtifactReason",
    "PluginArtifactResult",
    "PluginArtifactState",
    "PluginArtifactStatus",
    "PluginArtifactStatusCommand",
    "PluginFormatProfile",
    "PluginMutationReviewPort",
    "PluginOperationState",
    "PluginProofFacet",
    "PluginProofStatus",
    "PortablePluginPlan",
]

_PATH_RE = re.compile(r"^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$", re.ASCII)
_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+/-]{0,127}$", re.ASCII)
_MAX_FILES = 64
_MAX_ROOT = 4_096

# What a host holds under the pre-rename ``yoetz`` plugin name (ADR-048): ``none`` (nothing),
# ``legacy_only`` (the only FinishUP-owned install still uses the old name: owned but outdated),
# ``duplicate`` (owned installs under both names), or ``foreign`` (an old-name install FinishUP
# cannot prove is its own; it is reported and never touched). The same tokens name a legacy MCP
# registration key in ``finishup.ports.harness_mcp``.
type LegacyInstallation = Literal["none", "legacy_only", "duplicate", "foreign"]
LEGACY_INSTALLATIONS: Final[frozenset[str]] = frozenset(
    {"none", "legacy_only", "duplicate", "foreign"}
)


class PluginFormatProfile(str, Enum):  # noqa: UP042 - exact public enum
    AGENT_PLUGINS_1 = "agent_plugins_1"
    CLAUDE_CODE_PLUGIN_NATIVE = "claude_code_plugin_native"
    CODEX_PLUGIN_NATIVE = "codex_plugin_native"
    CURSOR_PLUGIN_NATIVE = "cursor_plugin_native"


class McpOwnership(str, Enum):  # noqa: UP042 - exact public enum
    EXTERNAL_REGISTRATION = "external_registration"
    PLUGIN_MANAGED = "plugin_managed"


class McpOwnershipState(str, Enum):  # noqa: UP042 - exact public enum
    ABSENT = "absent"
    EXTERNAL = "external"
    PLUGIN = "plugin"
    DUAL = "dual"
    FOREIGN = "foreign"
    AMBIGUOUS = "ambiguous"


class HostSurface(str, Enum):  # noqa: UP042 - exact public enum
    CODEX_CLI = "codex_cli"
    CHATGPT_DESKTOP = "chatgpt_desktop"
    CURSOR_IDE = "cursor_ide"
    CURSOR_CLI = "cursor_cli"
    CURSOR_SDK_LOCAL = "cursor_sdk_local"
    CURSOR_CLOUD = "cursor_cloud"
    CLAUDE_CODE = "claude_code"


class PluginOperationState(str, Enum):  # noqa: UP042 - exact public enum
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    REFUSED = "refused"
    OUTCOME_UNKNOWN = "outcome_unknown"


class PluginProofFacet(str, Enum):  # noqa: UP042 - exact public enum
    SOURCE = "source"
    RENDERED_ARTIFACT = "rendered_artifact"
    INSTALLED_BYTES = "installed_bytes"
    HOST_DISCOVERY = "host_discovery"
    HOST_ACTIVATION = "host_activation"
    SKILL_DELIVERY = "skill_delivery"
    MCP_OWNER = "mcp_owner"
    MCP_BINDING = "mcp_binding"
    MCP_RUNTIME = "mcp_runtime"
    MODEL_USE = "model_use"
    TRIGGER_CAPABILITY = "trigger_capability"
    OBSERVATION_CONSENT = "observation_consent"
    OBSERVATION_EVIDENCE = "observation_evidence"
    SERVICE_READINESS = "service_readiness"
    SEMANTIC_READINESS = "semantic_readiness"
    PROVIDER_DISPATCH = "provider_dispatch"
    PRIVACY_RECEIPT = "privacy_receipt"
    WORKFLOW_RECEIPT = "workflow_receipt"


class PluginArtifactAction(str, Enum):  # noqa: UP042 - exact structural enum
    INSTALL = "install"
    REPLACE = "replace"
    REMOVE = "remove"
    NOOP = "noop"


class PluginArtifactState(str, Enum):  # noqa: UP042 - exact structural enum
    ABSENT = "absent"
    PORTABLE_EXACT = "portable_exact"
    PORTABLE_MANAGED = "portable_managed"
    NATIVE_MANAGED = "native_managed"
    MODIFIED = "modified"
    PARTIAL = "partial"
    UNMANAGED = "unmanaged"
    UNSAFE = "unsafe"
    RECOVERY_REQUIRED = "recovery_required"


class PluginArtifactReason(str, Enum):  # noqa: UP042 - exact structural enum
    AUTHORITY_REQUIRED = "authority_required"
    DESTINATION_CONFLICT = "destination_conflict"
    FORMAT_UNSUPPORTED = "format_unsupported"
    HUMAN_AUTHORITY_UNAVAILABLE = "human_authority_unavailable"
    MANIFEST_INVALID = "manifest_invalid"
    MCP_OWNERSHIP_CONFLICT = "mcp_ownership_conflict"
    MODIFIED_COPY = "modified_copy"
    OPERATION_CONFLICT = "operation_conflict"
    PREVIEW_STALE = "preview_stale"
    RECOVERY_REQUIRED = "recovery_required"
    REMOVE_REFUSED = "remove_refused"
    REQUEST_IDENTITY_CONFLICT = "request_identity_conflict"
    SOURCE_INVALID = "source_invalid"
    TARGET_UNSAFE = "target_unsafe"
    TARGET_UNTRUSTED = "target_untrusted"
    WRITE_FAILED = "write_failed"


def _path(value: object) -> str:
    if type(value) is not str or _PATH_RE.fullmatch(value) is None:
        raise ValueError("plugin_path_invalid")
    if value.startswith("/") or any(part in {"", ".", ".."} for part in value.split("/")):
        raise ValueError("plugin_path_invalid")
    return value


def _token(value: object) -> str:
    if type(value) is not str or _TOKEN_RE.fullmatch(value) is None:
        raise ValueError("plugin_value_invalid")
    return value


def _sorted_files(value: object) -> tuple[ManagedPluginFile, ...]:
    if type(value) is not tuple:
        raise ValueError("plugin_inventory_invalid")
    raw_files = cast(tuple[object, ...], value)
    if not 1 <= len(raw_files) <= _MAX_FILES:
        raise ValueError("plugin_inventory_invalid")
    files: list[ManagedPluginFile] = []
    previous: str | None = None
    for item in raw_files:
        if type(item) is not ManagedPluginFile:
            raise ValueError("plugin_inventory_invalid")
        if previous is not None and item.relative_path.encode("ascii") <= previous.encode("ascii"):
            raise ValueError("plugin_inventory_invalid")
        files.append(item)
        previous = item.relative_path
    return tuple(files)


@dataclass(frozen=True, slots=True)
class ManagedPluginFile:
    relative_path: str
    size: int
    sha256: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "relative_path", _path(self.relative_path))
        if type(self.size) is not int or not 0 <= self.size <= 9_007_199_254_740_991:
            raise ValueError("plugin_inventory_invalid")
        validate_sha256_digest(self.sha256)


@dataclass(frozen=True, slots=True)
class PortablePluginPlan:
    name: Literal["finishup"]
    version: str
    description: str
    format_profile: PluginFormatProfile
    mcp_ownership: McpOwnership
    mcp_route_profile: Literal["strict", "policy"] | None
    host_extension_profile: str | None
    specification_version: Literal["1.0.0"]
    renderer_version: str
    source_refs: tuple[str, ...]
    inventory: tuple[ManagedPluginFile, ...]

    def __post_init__(self) -> None:
        if (
            self.name != "finishup"
            or type(self.description) is not str
            or not 1 <= len(self.description) <= 1_024
            or any(ord(char) < 32 or ord(char) == 127 for char in self.description)
        ):
            raise ValueError("plugin_plan_invalid")
        object.__setattr__(self, "version", _token(self.version))
        if type(self.format_profile) is not PluginFormatProfile:
            raise ValueError("plugin_plan_invalid")
        if type(self.mcp_ownership) is not McpOwnership:
            raise ValueError("plugin_plan_invalid")
        if (self.mcp_ownership is McpOwnership.PLUGIN_MANAGED) != (
            self.mcp_route_profile in {"strict", "policy"}
        ):
            raise ValueError("plugin_plan_invalid")
        if self.host_extension_profile is not None:
            _token(self.host_extension_profile)
        if self.specification_version != "1.0.0":
            raise ValueError("plugin_plan_invalid")
        object.__setattr__(self, "renderer_version", _token(self.renderer_version))
        if type(self.source_refs) is not tuple or not self.source_refs:
            raise ValueError("plugin_plan_invalid")
        refs = tuple(_path(item) for item in self.source_refs)
        if refs != tuple(sorted(set(refs), key=str.encode)):
            raise ValueError("plugin_plan_invalid")
        object.__setattr__(self, "source_refs", refs)
        object.__setattr__(self, "inventory", _sorted_files(self.inventory))


@dataclass(frozen=True, slots=True, repr=False)
class ArtifactTarget:
    project_root: str

    def __post_init__(self) -> None:
        if (
            type(self.project_root) is not str
            or not 1 <= len(self.project_root) <= _MAX_ROOT
            or any(ord(char) < 32 or ord(char) == 127 for char in self.project_root)
        ):
            raise ValueError("plugin_target_invalid")

    def __repr__(self) -> str:
        return "ArtifactTarget(project_root=<redacted>)"


@dataclass(frozen=True, slots=True)
class ArtifactAuthority:
    channel: Literal["setup_composition", "review_only"]
    target_digest: str
    review_id: str | None = None

    def __post_init__(self) -> None:
        validate_sha256_digest(self.target_digest)
        if self.channel == "review_only":
            if type(self.review_id) is not str or not self.review_id:
                raise ValueError("plugin_authority_invalid")
            object.__setattr__(self, "review_id", _token(self.review_id))
        elif self.channel == "setup_composition":
            if self.review_id is not None:
                raise ValueError("plugin_authority_invalid")
        else:
            raise ValueError("plugin_authority_invalid")


@dataclass(frozen=True, slots=True)
class PluginArtifactApplyCommand:
    request_id: RequestId
    target: ArtifactTarget
    action: PluginArtifactAction
    accepted_preview_digest: str
    authority: ArtifactAuthority

    def __post_init__(self) -> None:
        object.__setattr__(self, "request_id", request_id(self.request_id))
        if type(self.target) is not ArtifactTarget:
            raise ValueError("plugin_target_invalid")
        if (
            type(self.action) is not PluginArtifactAction
            or self.action is PluginArtifactAction.NOOP
        ):
            raise ValueError("plugin_action_invalid")
        validate_sha256_digest(self.accepted_preview_digest)
        if type(self.authority) is not ArtifactAuthority:
            raise ValueError("plugin_authority_invalid")


@dataclass(frozen=True, slots=True)
class PluginArtifactStatusCommand:
    target: ArtifactTarget
    request_id: RequestId | None = None

    def __post_init__(self) -> None:
        if type(self.target) is not ArtifactTarget:
            raise ValueError("plugin_target_invalid")
        if self.request_id is not None:
            object.__setattr__(self, "request_id", request_id(self.request_id))


@dataclass(frozen=True, slots=True)
class PluginProofStatus:
    facet: PluginProofFacet
    status: Literal["proven", "not_observed", "not_applicable", "unknown"]

    def __post_init__(self) -> None:
        if type(self.facet) is not PluginProofFacet:
            raise ValueError("plugin_proof_invalid")
        if self.status not in {"proven", "not_observed", "not_applicable", "unknown"}:
            raise ValueError("plugin_proof_invalid")


@dataclass(frozen=True, slots=True)
class PluginArtifactPreview:
    request_id: RequestId
    action: PluginArtifactAction
    state_before: PluginArtifactState
    mcp_ownership_state: McpOwnershipState
    target_identity: str
    current_state_digest: str
    artifact_digest: str
    rollback_digest: str | None
    preview_digest: str
    plan: PortablePluginPlan
    warnings: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "request_id", request_id(self.request_id))
        if type(self.action) is not PluginArtifactAction:
            raise ValueError("plugin_action_invalid")
        if (
            type(self.state_before) is not PluginArtifactState
            or type(self.mcp_ownership_state) is not McpOwnershipState
            or type(self.plan) is not PortablePluginPlan
        ):
            raise ValueError("plugin_preview_invalid")
        for digest in (
            self.target_identity,
            self.current_state_digest,
            self.artifact_digest,
            self.preview_digest,
        ):
            validate_sha256_digest(digest)
        if self.rollback_digest is not None:
            validate_sha256_digest(self.rollback_digest)
        warnings = tuple(_token(item) for item in self.warnings)
        if warnings != tuple(sorted(set(warnings), key=str.encode)):
            raise ValueError("plugin_preview_invalid")
        object.__setattr__(self, "warnings", warnings)


@dataclass(frozen=True, slots=True)
class PluginArtifactStatus:
    state: PluginArtifactState
    operation_state: PluginOperationState
    format_profile: PluginFormatProfile | None
    installed_digest: str | None
    artifact_digest: str
    mcp_ownership: McpOwnership
    mcp_ownership_state: McpOwnershipState
    mcp_route_profile: Literal["strict", "policy"] | None
    managed_marker_valid: bool
    rollback_available: bool
    proof: tuple[PluginProofStatus, ...]
    legacy_installation: LegacyInstallation = "none"

    def __post_init__(self) -> None:
        if type(self.state) is not PluginArtifactState:
            raise ValueError("plugin_status_invalid")
        if self.legacy_installation not in LEGACY_INSTALLATIONS:
            raise ValueError("plugin_status_invalid")
        if type(self.operation_state) is not PluginOperationState:
            raise ValueError("plugin_status_invalid")
        if self.format_profile is not None and type(self.format_profile) is not PluginFormatProfile:
            raise ValueError("plugin_status_invalid")
        if self.installed_digest is not None:
            validate_sha256_digest(self.installed_digest)
        validate_sha256_digest(self.artifact_digest)
        if (
            type(self.mcp_ownership) is not McpOwnership
            or type(self.mcp_ownership_state) is not McpOwnershipState
        ):
            raise ValueError("plugin_status_invalid")
        if (self.mcp_ownership is McpOwnership.PLUGIN_MANAGED) != (
            self.mcp_route_profile in {"strict", "policy"}
        ):
            raise ValueError("plugin_status_invalid")
        if type(self.managed_marker_valid) is not bool or type(self.rollback_available) is not bool:
            raise ValueError("plugin_status_invalid")
        if type(self.proof) is not tuple or any(
            type(item) is not PluginProofStatus for item in self.proof
        ):
            raise ValueError("plugin_status_invalid")
        if tuple(item.facet for item in self.proof) != tuple(PluginProofFacet):
            raise ValueError("plugin_status_invalid")


@dataclass(frozen=True, slots=True)
class PluginArtifactResult:
    request_id: RequestId
    action: PluginArtifactAction
    operation_state: PluginOperationState
    state_before: PluginArtifactState
    state_after: PluginArtifactState
    preview_digest: str
    artifact_digest: str
    installed_digest: str | None
    changed_files: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "request_id", request_id(self.request_id))
        if type(self.action) is not PluginArtifactAction:
            raise ValueError("plugin_result_invalid")
        if type(self.operation_state) is not PluginOperationState:
            raise ValueError("plugin_result_invalid")
        if (
            type(self.state_before) is not PluginArtifactState
            or type(self.state_after) is not PluginArtifactState
        ):
            raise ValueError("plugin_result_invalid")
        validate_sha256_digest(self.preview_digest)
        validate_sha256_digest(self.artifact_digest)
        if self.installed_digest is not None:
            validate_sha256_digest(self.installed_digest)
        files = tuple(_path(item) for item in self.changed_files)
        if files != tuple(sorted(set(files), key=str.encode)):
            raise ValueError("plugin_result_invalid")
        object.__setattr__(self, "changed_files", files)


@dataclass(frozen=True, slots=True)
class PluginArtifactError(Exception):
    reason: PluginArtifactReason
    safe_details: Mapping[str, JsonValue]

    def __post_init__(self) -> None:
        if type(self.reason) is not PluginArtifactReason:
            raise ValueError("plugin_error_invalid")
        try:
            details = JsonObject(self.safe_details)
        except ProtocolValueError as exc:
            raise ValueError("plugin_error_invalid") from exc
        if (
            len(details) > 16
            or len(canonical_encode(details)) > 4_096
            or any(_TOKEN_RE.fullmatch(key) is None for key in details)
        ):
            raise ValueError("plugin_error_invalid")
        object.__setattr__(self, "safe_details", details)
        Exception.__init__(self, self.reason.value)


class PluginMutationReviewPort(Protocol):
    def consume_setup_authority(
        self, authority: ArtifactAuthority, preview_digest: str
    ) -> None: ...

    def consume_artifact_review(
        self, authority: ArtifactAuthority, preview_digest: str
    ) -> None: ...


class PluginArtifactPort(Protocol):
    async def preview_artifact(
        self,
        request_id: RequestId,
        target: ArtifactTarget,
        action: PluginArtifactAction,
    ) -> PluginArtifactPreview: ...

    async def install_artifact(
        self, command: PluginArtifactApplyCommand
    ) -> PluginArtifactResult: ...

    async def status_artifact(
        self, command: PluginArtifactStatusCommand
    ) -> PluginArtifactStatus: ...

    async def remove_artifact(
        self, command: PluginArtifactApplyCommand
    ) -> PluginArtifactResult: ...
