"""Claude Code native project-plugin integration (issue #154).

Claude Code does not consume the Agent Plugins carrier.  This adapter renders a
Claude-native projection from the same packaged skill bytes, exposes one exact
CLI/local/project/private-marketplace capability cell, and keeps source,
marketplace registration, cache installation, enablement, loaded-session
activation, MCP ownership, hooks, observation, model use, and receipts separate.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Final, Literal, Protocol, cast

from finishup import __version__
from finishup.adapters.integrations.launcher import resolve_finishup_launcher, valid_launcher
from finishup.adapters.integrations.legacy_launchers import launcher_aliases, recorded_launcher
from finishup.adapters.integrations.portable_plugin import PackagedPortableResources
from finishup.config.foreign_write import writable_by_others
from finishup.domain.observation_profiles import (
    CLAUDE_CODE_ORDINARY_HOOK_MAPPING_VERSION,
    CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
)
from finishup.domain.values import JsonObject, RequestId
from finishup.domain.values import request_id as validate_request_id
from finishup.legacy_names import LAUNCHER_NAMES, LEGACY_MCP_SERVER_NAME, MCP_SERVER_NAME
from finishup.ports.integrations import (
    FINISHUP_WORKFLOW_TOOL_NAMES,
    HarnessHookProfile,
    HarnessId,
    HarnessProfile,
)
from finishup.ports.plugin_artifacts import (
    LEGACY_INSTALLATIONS,
    ArtifactAuthority,
    LegacyInstallation,
    ManagedPluginFile,
    McpOwnership,
    McpOwnershipState,
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
from finishup.protocol.canonical import (
    JsonValue,
    canonical_digest,
    canonical_encode,
    strict_json_parse,
)
from finishup.protocol.errors import ProtocolValueError
from finishup.protocol.guidance_uris import FOCUSED_GUIDANCE_URIS, GUIDANCE_DOCUMENT_URIS

__all__ = [
    "CLAUDE_CODE_HARNESS_PROFILE",
    "CLAUDE_CODE_HOOK_EVENTS",
    "CLAUDE_CODE_MINIMUM_VERSION",
    "CLAUDE_CODE_NATIVE_PROFILE_ID",
    "CLAUDE_CODE_ORDINARY_HOOK_MAPPING_VERSION",
    "CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID",
    "CLAUDE_CODE_ORDINARY_HOOK_EVENTS",
    "ClaudeCodeCapabilityIdentity",
    "ClaudeCodeCommandPort",
    "ClaudeCodeCommandResult",
    "ClaudeCodeIntegrationError",
    "ClaudeCodeMcpObservation",
    "ClaudeCodeMcpSource",
    "ClaudeCodePluginAction",
    "ClaudeCodePluginArtifact",
    "ClaudeCodePluginPreview",
    "ClaudeCodePluginResult",
    "ClaudeCodeSessionObservation",
    "ClaudeCodePluginStatus",
    "ClaudeCodePluginTarget",
    "SubprocessClaudeCodeCommands",
    "apply_claude_code_plugin",
    "discover_claude_code",
    "export_claude_code_plugin",
    "observe_claude_code_mcp",
    "observe_claude_code_session_init",
    "claude_code_version_provenance",
    "preview_claude_code_plugin",
    "render_claude_code_plugin",
    "status_claude_code_plugin",
]

# Hooks/plugin surfaces this integration relies on exist from 2.1.233. Plugin
# preview/apply admits any parseable version at or above this floor (issue #656);
# the exactly proven versions in CLAUDE_CODE_HARNESS_PROFILE.supported_versions
# are certification provenance (``tested``), never the admission gate. A version
# at or above the floor that was not proven is admitted as ``untested``.
CLAUDE_CODE_MINIMUM_VERSION: Final = "2.1.233"
type ClaudeCodeVersionProvenance = Literal["tested", "untested"]
CLAUDE_CODE_NATIVE_PROFILE_ID: Final = "claude-code-cli-local-project-2.1.241"
CLAUDE_CODE_HOOK_MAPPING_VERSION: Final = "claude-code-hooks-2.1.241-v1"
CLAUDE_CODE_HOOK_EVENTS: Final = (
    "PermissionDenied",
    "PostToolUse",
    "PostToolUseFailure",
    "SessionEnd",
    "SessionStart",
    "Stop",
    "SubagentStart",
    "SubagentStop",
)
CLAUDE_CODE_ORDINARY_HOOK_EVENTS: Final = (
    "PermissionDenied",
    "PermissionRequest",
    "PostToolUse",
    "PostToolUseFailure",
    "PreToolUse",
    "SessionEnd",
    "SessionStart",
    "Stop",
    "StopFailure",
)
_CLAUDE_HOOK_PROFILE: Final = HarnessHookProfile(
    trigger_event="SessionStart",
    trigger_payload_profile_id=CLAUDE_CODE_HOOK_MAPPING_VERSION,
    evidence_case_ids=("claude-code-cli-native-project-2.1.241-macos-arm64",),
    # The rendered artifact carries the lifecycle, scoped MCP, and native child
    # hook candidates, but the recorded
    # evidence case observed no accepted observation for any of them
    # (observation_evidence: not_observed). The capability hook cell stays
    # unpopulated until each event has installed-host delivery, privacy, and
    # accepted-observation evidence.
    observation_events=(),
    pairing_mode="post_only",
    correlation_kind="tool_call_id",
)
CLAUDE_CODE_HARNESS_PROFILE: Final = HarnessProfile(
    harness_id=HarnessId.CLAUDE,
    skill_root="skills/",
    frontmatter_profile="agent-skills-1",
    capability_profile_ids=(CLAUDE_CODE_NATIVE_PROFILE_ID,),
    supported_versions=("2.1.241",),
    hooks_by_capability_profile={CLAUDE_CODE_NATIVE_PROFILE_ID: _CLAUDE_HOOK_PROFILE},
)

_MARKETPLACE_NAME: Final = "finishup-local"
_PLUGIN_ID: Final = f"finishup@{_MARKETPLACE_NAME}"
# The private marketplace and plugin Yoetz 0.1-0.2 installs registered with Claude Code
# (ADR-048). The legacy tree is looked for only beside the owner-named managed root -- the
# guided connection's ``<config>/plugins/marketplaces/yoetz-local`` -- never at a path a project
# file names. A project that references it there, over a marker-valid tree, holds an owned legacy
# install: connect, install, and update retire it in the same approval and remove takes it too.
# The tree and Claude's user-level registration of it are shared by every project of the Claude
# config root, so retiring one project's install uninstalls the plugin for that project and drops
# that project's own declaration, never the shared tree or registration. Anything else under these
# names is reported and never touched.
_LEGACY_MARKETPLACE_NAME: Final = "yoetz-local"
_LEGACY_PLUGIN_NAME: Final = "yoetz"
_LEGACY_PLUGIN_ID: Final = f"{_LEGACY_PLUGIN_NAME}@{_LEGACY_MARKETPLACE_NAME}"
# The entries a Yoetz-era ``--scope project`` marketplace add and plugin install/enable left in the
# project's ``.claude/settings.json``: this project's declaration of the legacy install (ADR-048).
_LEGACY_DECLARATION: Final = (
    ("enabledPlugins", _LEGACY_PLUGIN_ID),
    ("extraKnownMarketplaces", _LEGACY_MARKETPLACE_NAME),
)
_SETTINGS_STAGE_PREFIX: Final = ".finishup-claude-settings-"
# Frozen legacy identifier (ADR-048): status and remove find ownership through these exact marker
# names and schemas, written unchanged in both the renamed and the legacy marketplace directory.
_MARKER_NAME: Final = ".yoetz-claude-marketplace-install.json"
_MARKER_SCHEMA: Final = "yoetz.claude-code-marketplace-install/2"
# Version 1 markers predate launcher binding; they remain readable (status/remove) but are
# never written again.
_LEGACY_MARKER_SCHEMAS: Final = frozenset({"yoetz.claude-code-marketplace-install/1"})
_EXPORT_MARKER_NAME: Final = ".yoetz-claude-plugin-export.json"
_EXPORT_MARKER_SCHEMA: Final = "yoetz.claude-code-plugin-export/1"
_RENDERER_VERSION: Final = "claude-code-plugin/0.4.0"
# Frozen legacy identifier (ADR-048): crash-recovery residue the next run finds by name/prefix.
_STAGE_PREFIX: Final = ".yoetz-claude-marketplace-stage-"
_ROLLBACK_NAME: Final = ".yoetz-claude-marketplace-rollback"
_MAX_FILE_BYTES: Final = 262_144
_MAX_FILES: Final = 64
_MAX_PATH: Final = 4_096
_MAX_COMMAND_OUTPUT: Final = 1_048_576
_DESCRIPTION: Final = (
    "Records material work in a local FinishUP ledger and checks completion claims "
    "against that record."
)
_GUIDANCE_URI_PREFIX: Final = "finishup://guidance/"
_GUIDANCE_NAMES: Final = tuple(
    uri.removeprefix(_GUIDANCE_URI_PREFIX)
    for uri in (*GUIDANCE_DOCUMENT_URIS, *FOCUSED_GUIDANCE_URIS)
)
_SKILL_PATH: Final = "skills/claude-code/finishup/SKILL.md"
_FINISHUP_SCOPED_TOOL_MATCHER: Final = (
    "^mcp__plugin_finishup_finishup__(" + "|".join(FINISHUP_WORKFLOW_TOOL_NAMES) + ")$"
)
# Only the AI-powered ``check`` is routed through a host's automatic reviewer (issue #467); the
# denial hook is scoped to its external and plugin-owned callable names so a held check is the only
# thing it can ever report. An owner-written registration still under the legacy ``yoetz`` key
# exposes ``mcp__yoetz__check`` until the owner renames it (ADR-048).
_FINISHUP_CHECK_TOOL_MATCHER: Final = "^mcp__(finishup|yoetz|plugin_finishup_finishup)__check$"
_VERSION_RE: Final = re.compile(r"^(\d+)\.(\d+)\.(\d+)$", re.ASCII)


class ClaudeCodePluginAction(str, Enum):  # noqa: UP042 - exact public token
    CONNECT = "connect"
    INSTALL = "install"
    UPDATE = "update"
    ENABLE = "enable"
    DISABLE = "disable"
    REMOVE = "remove"
    NOOP = "noop"


class ClaudeCodeMcpSource(str, Enum):  # noqa: UP042 - exact public token
    LOCAL = "local"
    PROJECT = "project"
    USER = "user"
    PLUGIN = "plugin"
    CLAUDE_AI_CONNECTOR = "claude_ai_connector"


@dataclass(frozen=True, slots=True, repr=False)
class ClaudeCodeCapabilityIdentity:
    version: str
    executable_digest: str
    os_name: str
    architecture: str

    def __post_init__(self) -> None:
        _version_tuple(self.version)
        _validate_digest(self.executable_digest)
        for value in (self.os_name, self.architecture):
            if type(value) is not str or not value or len(value) > 128:
                raise ValueError("claude_code_identity_invalid")

    def __repr__(self) -> str:
        return (
            "ClaudeCodeCapabilityIdentity("
            f"version={self.version!r}, executable_digest={self.executable_digest!r}, "
            f"os_name={self.os_name!r}, architecture={self.architecture!r})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class ClaudeCodePluginTarget:
    project_root: str
    claude_config_root: str
    cache_root: str
    marketplace_root: str
    executable: str
    identity: ClaudeCodeCapabilityIdentity
    scope: Literal["project"] = "project"
    marketplace_name: Literal["finishup-local"] = _MARKETPLACE_NAME

    def __post_init__(self) -> None:
        for value in (
            self.project_root,
            self.claude_config_root,
            self.cache_root,
            self.marketplace_root,
            self.executable,
        ):
            if (
                type(value) is not str
                or not 1 <= len(value) <= _MAX_PATH
                or not Path(value).is_absolute()
                or any(ord(char) < 32 or ord(char) == 127 for char in value)
            ):
                raise ValueError("claude_code_target_invalid")
        if type(self.identity) is not ClaudeCodeCapabilityIdentity:
            raise ValueError("claude_code_target_invalid")
        if self.scope != "project" or self.marketplace_name != _MARKETPLACE_NAME:
            raise ValueError("claude_code_target_invalid")
        if Path(self.cache_root) != Path(self.claude_config_root) / "plugins" / "cache":
            raise ValueError("claude_code_cache_root_invalid")

    def __repr__(self) -> str:
        return (
            "ClaudeCodePluginTarget(project_root=<redacted>, claude_config_root=<redacted>, "
            "cache_root=<redacted>, marketplace_root=<redacted>, executable=<redacted>, "
            f"identity={self.identity!r}, scope={self.scope!r}, "
            f"marketplace_name={self.marketplace_name!r})"
        )


@dataclass(frozen=True, slots=True)
class ClaudeCodePluginArtifact:
    plan: PortablePluginPlan
    members: Mapping[str, bytes]
    marketplace_manifest: bytes
    artifact_digest: str
    marketplace_digest: str
    # The exact installation the rendered hooks and plugin-owned MCP entry launch
    # (absolute executable plus fixed arguments); never a bare PATH lookup.
    finishup_launcher: tuple[str, ...] = ()
    # A development carrier ships ``defaultEnabled:true`` for ``claude --plugin-dir`` runs. It
    # is exported only, never previewed/installed, and earns no marketplace proof.
    development: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.plan) is not PortablePluginPlan
            or self.plan.format_profile is not PluginFormatProfile.CLAUDE_CODE_PLUGIN_NATIVE
        ):
            raise ValueError("claude_code_artifact_invalid")
        if not valid_launcher(self.finishup_launcher) or type(self.development) is not bool:
            raise ValueError("claude_code_artifact_invalid")
        _validate_digest(self.artifact_digest)
        _validate_digest(self.marketplace_digest)
        expected = tuple(item.relative_path for item in self.plan.inventory)
        if tuple(sorted(self.members, key=str.encode)) != expected:
            raise ValueError("claude_code_artifact_inventory_invalid")
        for item in self.plan.inventory:
            data = self.members[item.relative_path]
            if type(data) is not bytes or len(data) != item.size or _sha(data) != item.sha256:
                raise ValueError("claude_code_artifact_inventory_invalid")
        if (
            type(self.marketplace_manifest) is not bytes
            or _sha(self.marketplace_manifest) != self.marketplace_digest
        ):
            raise ValueError("claude_code_artifact_invalid")


@dataclass(frozen=True, slots=True)
class ClaudeCodeMcpObservation:
    ownership_state: McpOwnershipState
    winning_source: ClaudeCodeMcpSource | None
    route_profile: Literal["strict", "policy"] | None
    present_sources: tuple[ClaudeCodeMcpSource, ...]
    observed: bool
    host_admission_supported: bool
    # Which initialize body the winning route serves. A legacy bare ``mcp serve`` route is still
    # policy/strict for admission, but has no host identity and therefore receives the generic
    # guidance body rather than Claude's compact body.
    host_profile: Literal["generic", "claude"] | None = None
    # What the legacy ``yoetz`` registration key holds across the observed sources (ADR-048).
    legacy_registration: LegacyInstallation = "none"

    def __post_init__(self) -> None:
        if type(self.ownership_state) is not McpOwnershipState:
            raise ValueError("claude_code_mcp_observation_invalid")
        if self.legacy_registration not in LEGACY_INSTALLATIONS:
            raise ValueError("claude_code_mcp_observation_invalid")
        if self.winning_source is not None and type(self.winning_source) is not ClaudeCodeMcpSource:
            raise ValueError("claude_code_mcp_observation_invalid")
        if (
            self.route_profile not in {None, "strict", "policy"}
            or type(self.observed) is not bool
            or type(self.host_admission_supported) is not bool
            or self.host_profile not in {None, "generic", "claude"}
        ):
            raise ValueError("claude_code_mcp_observation_invalid")
        if type(self.present_sources) is not tuple or any(
            type(item) is not ClaudeCodeMcpSource for item in self.present_sources
        ):
            raise ValueError("claude_code_mcp_observation_invalid")
        order = {source: index for index, source in enumerate(ClaudeCodeMcpSource)}
        if (
            tuple(sorted(set(self.present_sources), key=lambda item: order[item]))
            != self.present_sources
        ):
            raise ValueError("claude_code_mcp_observation_invalid")
        if (
            self.ownership_state not in {McpOwnershipState.EXTERNAL, McpOwnershipState.PLUGIN}
            and self.route_profile is not None
        ):
            raise ValueError("claude_code_mcp_observation_invalid")
        if self.route_profile is None and self.host_profile is not None:
            raise ValueError("claude_code_mcp_observation_invalid")
        if self.host_admission_supported and (
            not self.observed
            or self.ownership_state not in {McpOwnershipState.EXTERNAL, McpOwnershipState.PLUGIN}
            or self.route_profile is None
        ):
            raise ValueError("claude_code_mcp_observation_invalid")


@dataclass(frozen=True, slots=True)
class ClaudeCodePluginStatus:
    state: PluginArtifactState
    operation_state: PluginOperationState
    artifact_digest: str
    marketplace_digest: str
    host_state_digest: str
    source_digest: str | None
    installed_digest: str | None
    installed_version: str | None
    marketplace_registered: bool | None
    discovered: bool
    enabled: bool | None
    loaded_root_digest: str | None
    marker_valid: bool
    mcp_observation: ClaudeCodeMcpObservation
    proof: tuple[PluginProofStatus, ...]
    notes: tuple[str, ...]
    # Whether the target host version is an exactly proven cell (``tested``) or a compatible
    # release admitted on the floor alone (``untested``); ``None`` when below the floor (#656).
    version_provenance: ClaudeCodeVersionProvenance | None = None
    # What the legacy ``yoetz-local`` marketplace holds for this project (ADR-048).
    legacy_installation: LegacyInstallation = "none"

    def __post_init__(self) -> None:
        if (
            type(self.state) is not PluginArtifactState
            or type(self.operation_state) is not PluginOperationState
        ):
            raise ValueError("claude_code_status_invalid")
        if self.legacy_installation not in LEGACY_INSTALLATIONS:
            raise ValueError("claude_code_status_invalid")
        if self.version_provenance not in {None, "tested", "untested"}:
            raise ValueError("claude_code_status_invalid")
        for value in (self.artifact_digest, self.marketplace_digest, self.host_state_digest):
            _validate_digest(value)
        for value in (self.source_digest, self.installed_digest, self.loaded_root_digest):
            if value is not None:
                _validate_digest(value)
        if self.installed_version is not None:
            _version_tuple(self.installed_version)
        if (
            self.marketplace_registered is not None
            and type(self.marketplace_registered) is not bool
        ):
            raise ValueError("claude_code_status_invalid")
        if type(self.discovered) is not bool or (
            self.enabled is not None and type(self.enabled) is not bool
        ):
            raise ValueError("claude_code_status_invalid")
        if (
            type(self.marker_valid) is not bool
            or type(self.mcp_observation) is not ClaudeCodeMcpObservation
        ):
            raise ValueError("claude_code_status_invalid")
        if type(self.proof) is not tuple or tuple(item.facet for item in self.proof) != tuple(
            PluginProofFacet
        ):
            raise ValueError("claude_code_status_invalid")
        if self.notes != tuple(sorted(set(self.notes), key=str.encode)):
            raise ValueError("claude_code_status_invalid")


@dataclass(frozen=True, slots=True)
class ClaudeCodePluginPreview:
    request_id: RequestId
    action: ClaudeCodePluginAction
    state_before: PluginArtifactState
    target_identity: str
    current_state_digest: str
    artifact_digest: str
    marketplace_digest: str
    preview_digest: str
    mcp_ownership: McpOwnership
    mcp_ownership_state: McpOwnershipState
    mcp_route_profile: Literal["strict", "policy"] | None
    warnings: tuple[str, ...]
    # Admission provenance of the previewed host version (#656). A preview never exists for a
    # version below the floor, so this is never ``None`` on a constructed preview.
    version_provenance: ClaudeCodeVersionProvenance = "untested"
    # The legacy ``yoetz-local`` marketplace this action migrates or removes (ADR-048).
    legacy_installation: LegacyInstallation = "none"

    def __post_init__(self) -> None:
        object.__setattr__(self, "request_id", validate_request_id(self.request_id))
        if (
            type(self.action) is not ClaudeCodePluginAction
            or type(self.state_before) is not PluginArtifactState
        ):
            raise ValueError("claude_code_preview_invalid")
        if self.legacy_installation not in LEGACY_INSTALLATIONS:
            raise ValueError("claude_code_preview_invalid")
        if self.version_provenance not in {"tested", "untested"}:
            raise ValueError("claude_code_preview_invalid")
        for value in (
            self.target_identity,
            self.current_state_digest,
            self.artifact_digest,
            self.marketplace_digest,
            self.preview_digest,
        ):
            _validate_digest(value)
        if (
            type(self.mcp_ownership) is not McpOwnership
            or type(self.mcp_ownership_state) is not McpOwnershipState
        ):
            raise ValueError("claude_code_preview_invalid")
        if self.mcp_route_profile not in {None, "strict", "policy"}:
            raise ValueError("claude_code_preview_invalid")
        if self.warnings != tuple(sorted(set(self.warnings), key=str.encode)):
            raise ValueError("claude_code_preview_invalid")


@dataclass(frozen=True, slots=True)
class ClaudeCodePluginResult:
    request_id: RequestId
    action: ClaudeCodePluginAction
    operation_state: PluginOperationState
    state_before: PluginArtifactState
    state_after: PluginArtifactState
    preview_digest: str
    artifact_digest: str
    installed_digest: str | None
    enabled: bool | None
    changed_files: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "request_id", validate_request_id(self.request_id))
        if (
            type(self.action) is not ClaudeCodePluginAction
            or type(self.operation_state) is not PluginOperationState
        ):
            raise ValueError("claude_code_result_invalid")
        if (
            type(self.state_before) is not PluginArtifactState
            or type(self.state_after) is not PluginArtifactState
        ):
            raise ValueError("claude_code_result_invalid")
        for value in (self.preview_digest, self.artifact_digest):
            _validate_digest(value)
        if self.installed_digest is not None:
            _validate_digest(self.installed_digest)
        if self.enabled is not None and type(self.enabled) is not bool:
            raise ValueError("claude_code_result_invalid")
        if self.changed_files != tuple(sorted(set(self.changed_files), key=str.encode)):
            raise ValueError("claude_code_result_invalid")


@dataclass(frozen=True, slots=True)
class ClaudeCodeSessionObservation:
    session_boundary_digest: str
    loaded_root_digest: str
    skill_registered: bool
    mcp_connected: bool
    scoped_workflow_tools_visible: bool

    def __post_init__(self) -> None:
        _validate_digest(self.session_boundary_digest)
        _validate_digest(self.loaded_root_digest)
        if any(
            type(value) is not bool
            for value in (
                self.skill_registered,
                self.mcp_connected,
                self.scoped_workflow_tools_visible,
            )
        ):
            raise ValueError("claude_code_session_observation_invalid")


@dataclass(frozen=True, slots=True)
class ClaudeCodeIntegrationError(Exception):
    reason: PluginArtifactReason
    safe_details: Mapping[str, JsonValue]

    def __post_init__(self) -> None:
        if type(self.reason) is not PluginArtifactReason:
            raise ValueError("claude_code_error_invalid")
        details = JsonObject(self.safe_details)
        if len(details) > 16 or len(canonical_encode(details)) > 4_096:
            raise ValueError("claude_code_error_invalid")
        object.__setattr__(self, "safe_details", details)
        Exception.__init__(self, self.reason.value)


@dataclass(frozen=True, slots=True)
class ClaudeCodeCommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes

    def __post_init__(self) -> None:
        if (
            type(self.returncode) is not int
            or type(self.stdout) is not bytes
            or type(self.stderr) is not bytes
        ):
            raise ValueError("claude_code_command_result_invalid")
        if len(self.stdout) > _MAX_COMMAND_OUTPUT or len(self.stderr) > _MAX_COMMAND_OUTPUT:
            raise ValueError("claude_code_command_result_invalid")


class ClaudeCodeCommandPort(Protocol):
    def run(
        self, target: ClaudeCodePluginTarget, arguments: Sequence[str]
    ) -> ClaudeCodeCommandResult: ...


class SubprocessClaudeCodeCommands:
    """Run one absolute Claude executable with an explicit config root and project cwd."""

    def run(
        self, target: ClaudeCodePluginTarget, arguments: Sequence[str]
    ) -> ClaudeCodeCommandResult:
        environment = dict(os.environ)
        environment["CLAUDE_CONFIG_DIR"] = target.claude_config_root
        try:
            completed = subprocess.run(
                (target.executable, *arguments),
                cwd=target.project_root,
                env=environment,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                check=False,
                shell=False,
                timeout=30,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise _error(PluginArtifactReason.WRITE_FAILED) from exc
        if (
            len(completed.stdout) > _MAX_COMMAND_OUTPUT
            or len(completed.stderr) > _MAX_COMMAND_OUTPUT
        ):
            raise _error(PluginArtifactReason.WRITE_FAILED)
        return ClaudeCodeCommandResult(completed.returncode, completed.stdout, completed.stderr)


@dataclass(frozen=True, slots=True, repr=False)
class _SourceInspection:
    state: PluginArtifactState
    digest: str | None
    marker_valid: bool
    current_state_digest: str


def _error(
    reason: PluginArtifactReason, details: Mapping[str, JsonValue] | None = None
) -> ClaudeCodeIntegrationError:
    return ClaudeCodeIntegrationError(reason, {} if details is None else details)


def _sha(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _validate_digest(value: object) -> str:
    if (
        type(value) is not str
        or len(value) != 71
        or not value.startswith("sha256:")
        or any(char not in "0123456789abcdef" for char in value[7:])
    ):
        raise ValueError("claude_code_digest_invalid")
    return value


def _version_tuple(value: object) -> tuple[int, int, int]:
    if type(value) is not str:
        raise ValueError("claude_code_version_invalid")
    matched = _VERSION_RE.fullmatch(value)
    if matched is None:
        raise ValueError("claude_code_version_invalid")
    major, minor, patch = matched.groups()
    return int(major), int(minor), int(patch)


def claude_code_version_provenance(version: str) -> ClaudeCodeVersionProvenance | None:
    """Classify a host version for plugin admission (issue #656).

    ``tested`` names an exactly proven cell in ``CLAUDE_CODE_HARNESS_PROFILE.supported_versions``;
    ``untested`` is a parseable version at or above ``CLAUDE_CODE_MINIMUM_VERSION`` whose native
    contract was never proven — admitted because the surfaces it relies on exist, but never
    promoted to a proven cell; ``None`` is below the floor or unparseable and is refused.
    """

    try:
        parsed = _version_tuple(version)
    except ValueError:
        return None
    if parsed < _version_tuple(CLAUDE_CODE_MINIMUM_VERSION):
        return None
    if version in CLAUDE_CODE_HARNESS_PROFILE.supported_versions:
        return "tested"
    return "untested"


def _digest_file(path: Path) -> str:
    if path.is_symlink():
        path = path.resolve(strict=True)
    if not path.is_file():
        raise ValueError("claude_code_executable_unavailable")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def discover_claude_code(executable: Path) -> ClaudeCodeCapabilityIdentity:
    """Discover version and executable identity without reading ambient Claude state."""

    resolved = executable.resolve(strict=True)
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise ValueError("claude_code_executable_unavailable")
    with tempfile.TemporaryDirectory(prefix="finishup-claude-discovery-") as temporary:
        environment = dict(os.environ)
        environment["CLAUDE_CONFIG_DIR"] = str(Path(temporary) / "config")
        try:
            completed = subprocess.run(
                (str(resolved), "--version"),
                cwd=temporary,
                env=environment,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                check=False,
                shell=False,
                timeout=5,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ValueError("claude_code_executable_unavailable") from exc
    if completed.returncode != 0 or len(completed.stdout) > 4_096:
        raise ValueError("claude_code_identity_invalid")
    try:
        first = completed.stdout.decode("utf-8", errors="strict").split()[0]
    except (UnicodeDecodeError, IndexError) as exc:
        raise ValueError("claude_code_identity_invalid") from exc
    _version_tuple(first)
    return ClaudeCodeCapabilityIdentity(
        first,
        _digest_file(resolved),
        platform.system().lower(),
        platform.machine().lower(),
    )


def _inventory(members: Mapping[str, bytes]) -> tuple[ManagedPluginFile, ...]:
    return tuple(
        ManagedPluginFile(path, len(data), _sha(data))
        for path, data in sorted(members.items(), key=lambda item: item[0].encode("ascii"))
    )


def _mcp_json(
    route_profile: Literal["strict", "policy"], finishup_launcher: tuple[str, ...]
) -> bytes:
    args = [*finishup_launcher[1:], "mcp", "serve", "--host", "claude"]
    if route_profile == "strict":
        args.extend(("--semantic", "off"))
    return canonical_encode(
        cast(
            JsonValue,
            {
                "mcpServers": {
                    "finishup": {"args": args, "command": finishup_launcher[0], "type": "stdio"}
                }
            },
        )
    )


def _hooks_json(
    finishup_launcher: tuple[str, ...],
    *,
    observation_profile: Literal["structural", "ordinary"],
    startup_mode: Literal["optional", "required"] = "optional",
) -> bytes:
    launcher = " ".join(shlex.quote(part) for part in finishup_launcher)
    command = f'{launcher} hooks claude-observe --workspace "${{CLAUDE_PROJECT_DIR}}"'
    startup_cue: dict[str, JsonValue] = {
        "command": f"{launcher} hooks startup-context --host claude",
        "timeout": 2,
        "type": "command",
    }

    def hook(event: str) -> dict[str, JsonValue]:
        # The hook entrypoint has a small import path, but a fresh process can
        # still spend time on local state hydration and one bounded service
        # drain. Keep ordinary events above that base budget while giving
        # lifecycle attach/advice events enough room for their documented
        # service work. SessionEnd is intentionally local-first and remains
        # within Claude's three-second teardown window (#616).
        timeout = 3 if event == "SessionEnd" else 10 if event in {"SessionStart", "Stop"} else 5
        return {"command": f"{command} --event {event}", "timeout": timeout, "type": "command"}

    if observation_profile == "ordinary":
        command = (
            f"{command} --observation-profile "
            f"{shlex.quote(CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID)}"
        )
        hooks: dict[str, JsonValue] = {
            "PermissionDenied": [{"hooks": [hook("PermissionDenied")]}],
            "PermissionRequest": [{"hooks": [hook("PermissionRequest")]}],
            "PreToolUse": [{"hooks": [hook("PreToolUse")], "matcher": ".*"}],
            "PostToolUse": [{"hooks": [hook("PostToolUse")], "matcher": ".*"}],
            "PostToolUseFailure": [{"hooks": [hook("PostToolUseFailure")], "matcher": ".*"}],
            "SessionEnd": [{"hooks": [hook("SessionEnd")]}],
            "SessionStart": [
                {
                    "hooks": [startup_cue, hook("SessionStart")],
                    "matcher": "startup|resume|clear|compact|fork",
                }
            ],
            "Stop": [{"hooks": [hook("Stop")]}],
            "StopFailure": [{"hooks": [hook("StopFailure")]}],
        }
        return canonical_encode(
            cast(
                JsonValue,
                {
                    "hooks": _required_startup_hooks(hooks, launcher)
                    if startup_mode == "required"
                    else hooks
                },
            )
        )

    hooks: dict[str, JsonValue] = {
        # Fires when auto mode (or a rule or another hook) denies the call, after the denial;
        # it cannot allow anything. FinishUP records one payload-free typed diagnostic so
        # ``observe status`` can say the host held a check (issue #467).
        "PermissionDenied": [
            {"hooks": [hook("PermissionDenied")], "matcher": _FINISHUP_CHECK_TOOL_MATCHER}
        ],
        "PostToolUse": [{"hooks": [hook("PostToolUse")], "matcher": _FINISHUP_SCOPED_TOOL_MATCHER}],
        "PostToolUseFailure": [
            {"hooks": [hook("PostToolUseFailure")], "matcher": _FINISHUP_SCOPED_TOOL_MATCHER}
        ],
        "SessionEnd": [{"hooks": [hook("SessionEnd")]}],
        "SessionStart": [
            {
                "hooks": [startup_cue, hook("SessionStart")],
                "matcher": "startup|resume|clear|compact|fork",
            }
        ],
        "Stop": [{"hooks": [hook("Stop")]}],
        # Claude Code 2.1.261's native Agent tool delivers child identity through
        # these hooks.  The ingress retains only the structural child id; parent
        # tool context remains optional and service-stamped.
        "SubagentStart": [{"hooks": [hook("SubagentStart")]}],
        "SubagentStop": [{"hooks": [hook("SubagentStop")]}],
    }
    return canonical_encode(
        cast(
            JsonValue,
            {
                "hooks": _required_startup_hooks(hooks, launcher)
                if startup_mode == "required"
                else hooks
            },
        )
    )


def _required_startup_hooks(hooks: dict[str, JsonValue], launcher: str) -> dict[str, JsonValue]:
    for event in (
        "SessionStart",
        "UserPromptSubmit",
        "PreToolUse",
        "PostToolUse",
        "PostToolUseFailure",
        "SessionEnd",
    ):
        gate: dict[str, JsonValue] = {
            "hooks": [
                {
                    "type": "command",
                    "timeout": 3,
                    "command": f"{launcher} hooks startup-gate --host claude --event {event}",
                }
            ]
        }
        if event == "SessionStart":
            gate["matcher"] = "startup|resume|clear|compact|fork"
        if event in {"PreToolUse", "PostToolUse", "PostToolUseFailure"}:
            gate["matcher"] = ".*"
        existing = hooks.get(event, [])
        assert isinstance(existing, list)
        hooks[event] = [gate, *existing]
    return hooks


def installed_claude_startup_mode(
    target: ClaudeCodePluginTarget,
) -> Literal["optional", "required"] | None:
    """Inspect marker-verified source bytes, including older owned versions.

    Without a managed tree, a marker-valid legacy ``yoetz-local`` tree at the accepted location
    supplies the mode so a migration keeps the startup mode the owner chose (ADR-048).
    """
    _validate_target(target)
    root = Path(target.marketplace_root)
    if not root.exists():
        legacy_root = _legacy_location(target)
        if _legacy_tree(legacy_root)[0] != "legacy":
            return "optional"
        root = legacy_root
    files = _safe_tree(root)
    if not _valid_source_marker(files)[0]:
        return None
    hooks = files.get("plugins/finishup/hooks/hooks.json") or files.get(
        f"plugins/{_LEGACY_PLUGIN_NAME}/hooks/hooks.json", b""
    )
    return "required" if b" hooks startup-gate --host claude " in hooks else "optional"


def render_claude_code_plugin(
    *,
    mcp_ownership: McpOwnership = McpOwnership.EXTERNAL_REGISTRATION,
    route_profile: Literal["strict", "policy"] | None = None,
    source: PackagedPortableResources | None = None,
    version: str = __version__,
    finishup_launcher: Path | str | Sequence[str] | None = None,
    development_enabled: bool = False,
    observation_profile: Literal["structural", "ordinary"] = "structural",
    startup_mode: Literal["optional", "required"] = "optional",
) -> ClaudeCodePluginArtifact:
    """Render Claude-native bytes from canonical packaged guidance.

    ``finishup_launcher`` binds hooks and the plugin-owned MCP entry to one exact installation
    (the invoking console script or ``python -m finishup``); ``None`` resolves ``finishup`` on PATH
    to its absolute executable. ``development_enabled`` renders the ``claude --plugin-dir``
    development carrier (``defaultEnabled:true``), which export writes and preview refuses.
    """

    _version_tuple(version)
    if startup_mode not in {"optional", "required"}:
        raise ValueError("startup_mode_invalid")
    if type(mcp_ownership) is not McpOwnership:
        raise ValueError("claude_code_mcp_ownership_invalid")
    if type(development_enabled) is not bool:
        raise ValueError("claude_code_artifact_invalid")
    if observation_profile not in {"structural", "ordinary"}:
        raise ValueError("claude_code_observation_profile_invalid")
    resolved_launcher = resolve_finishup_launcher(finishup_launcher)
    if (mcp_ownership is McpOwnership.PLUGIN_MANAGED) != (route_profile in {"strict", "policy"}):
        raise ValueError(
            "claude_code_mcp_route_required"
            if mcp_ownership is McpOwnership.PLUGIN_MANAGED
            else "claude_code_mcp_route_forbidden"
        )
    resources = PackagedPortableResources() if source is None else source
    manifest: dict[str, JsonValue] = {
        "$schema": "https://json.schemastore.org/claude-code-plugin-manifest.json",
        "author": {"name": "FinishUP contributors"},
        "defaultEnabled": development_enabled,
        "description": _DESCRIPTION,
        "displayName": "FinishUP",
        "license": "Apache-2.0",
        "name": "finishup",
        "repository": "https://github.com/TheGaySupreme123/finishup",
        "version": version,
    }
    members: dict[str, bytes] = {
        ".claude-plugin/plugin.json": canonical_encode(manifest),
        "hooks/hooks.json": _hooks_json(
            resolved_launcher, observation_profile=observation_profile, startup_mode=startup_mode
        ),
        "skills/finishup/SKILL.md": resources.read_bytes(_SKILL_PATH),
    }
    for name in _GUIDANCE_NAMES:
        members[f"skills/finishup/references/{name}"] = resources.read_bytes(f"guidance/{name}")
    if mcp_ownership is McpOwnership.PLUGIN_MANAGED:
        assert route_profile is not None
        members[".mcp.json"] = _mcp_json(route_profile, resolved_launcher)
    plan = PortablePluginPlan(
        name="finishup",
        version=version,
        description=_DESCRIPTION,
        format_profile=PluginFormatProfile.CLAUDE_CODE_PLUGIN_NATIVE,
        mcp_ownership=mcp_ownership,
        mcp_route_profile=route_profile,
        host_extension_profile=(
            CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID
            if observation_profile == "ordinary"
            else CLAUDE_CODE_NATIVE_PROFILE_ID
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
    artifact_digest = canonical_digest(
        {
            "files": [
                {"relative_path": item.relative_path, "sha256": item.sha256, "size": item.size}
                for item in plan.inventory
            ],
            "format_profile": plan.format_profile.value,
            "renderer_version": plan.renderer_version,
        }
    )
    marketplace_manifest = canonical_encode(
        cast(
            JsonValue,
            {
                "description": "Private local FinishUP marketplace",
                "name": _MARKETPLACE_NAME,
                "owner": {"name": "FinishUP contributors"},
                "plugins": [{"name": "finishup", "source": "./plugins/finishup", "strict": True}],
            },
        )
    )
    return ClaudeCodePluginArtifact(
        plan,
        members,
        marketplace_manifest,
        artifact_digest,
        _sha(marketplace_manifest),
        resolved_launcher,
        development_enabled,
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
    facts = current.stat()
    if (hasattr(os, "geteuid") and facts.st_uid != os.geteuid()) or writable_by_others(facts):
        raise _error(PluginArtifactReason.TARGET_UNSAFE)
    if any(item.name in {"", ".", ".."} for item in missing):
        raise _error(PluginArtifactReason.TARGET_UNSAFE)
    return current


def _validate_target(target: ClaudeCodePluginTarget) -> str:
    if type(target) is not ClaudeCodePluginTarget:
        raise _error(PluginArtifactReason.TARGET_UNTRUSTED)
    for raw in (
        target.project_root,
        target.claude_config_root,
        target.cache_root,
        target.marketplace_root,
    ):
        path = Path(raw)
        _safe_existing_ancestor(path)
        for candidate in (path, *path.parents):
            if candidate.exists() and candidate.is_symlink():
                raise _error(PluginArtifactReason.TARGET_UNSAFE)
            if candidate.parent == candidate:
                break
    executable = Path(target.executable)
    if executable.is_symlink() or not executable.is_file() or not os.access(executable, os.X_OK):
        raise _error(PluginArtifactReason.TARGET_UNSAFE)
    facts = executable.stat()
    if (hasattr(os, "geteuid") and facts.st_uid != os.geteuid()) or writable_by_others(facts):
        raise _error(PluginArtifactReason.TARGET_UNSAFE)
    if _digest_file(executable) != target.identity.executable_digest:
        raise _error(PluginArtifactReason.PREVIEW_STALE)
    return canonical_digest(
        {
            "architecture": target.identity.architecture,
            "cache_root": target.cache_root,
            "claude_config_root": target.claude_config_root,
            "executable_digest": target.identity.executable_digest,
            "marketplace_name": target.marketplace_name,
            "marketplace_root": target.marketplace_root,
            "os_name": target.identity.os_name,
            "project_root": target.project_root,
            "scope": target.scope,
            "version": target.identity.version,
        }
    )


def _safe_tree(root: Path) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix().encode("utf-8")):
        if path.is_symlink():
            raise _error(PluginArtifactReason.TARGET_UNSAFE)
        if path.is_dir():
            continue
        facts = path.stat()
        if (
            not path.is_file()
            or facts.st_nlink != 1
            or facts.st_size > _MAX_FILE_BYTES
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


def _source_members(artifact: ClaudeCodePluginArtifact) -> dict[str, bytes]:
    members = {".claude-plugin/marketplace.json": artifact.marketplace_manifest}
    members.update({f"plugins/finishup/{path}": data for path, data in artifact.members.items()})
    return members


def _hook_mapping_version_for_artifact(artifact: ClaudeCodePluginArtifact) -> str:
    """Return the mapping bound into this artifact's rendered hook command."""

    return (
        CLAUDE_CODE_ORDINARY_HOOK_MAPPING_VERSION
        if artifact.plan.host_extension_profile == CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID
        else CLAUDE_CODE_HOOK_MAPPING_VERSION
    )


def _marker(artifact: ClaudeCodePluginArtifact) -> bytes:
    source = _source_members(artifact)
    body: dict[str, JsonValue] = {
        "artifact_digest": artifact.artifact_digest,
        "format_profile": artifact.plan.format_profile.value,
        "hook_mapping_version": _hook_mapping_version_for_artifact(artifact),
        "managed_files": [
            {"relative_path": path, "sha256": _sha(data), "size": len(data)}
            for path, data in sorted(source.items(), key=lambda item: item[0].encode("ascii"))
        ],
        "marketplace_digest": artifact.marketplace_digest,
        "marketplace_name": _MARKETPLACE_NAME,
        "mcp_ownership": artifact.plan.mcp_ownership.value,
        "mcp_route_profile": artifact.plan.mcp_route_profile,
        "renderer_version": artifact.plan.renderer_version,
        "schema": _MARKER_SCHEMA,
        # Frozen legacy identifier (ADR-048): marker keys every release reads by name.
        "yoetz_launcher": list(artifact.finishup_launcher),
        "yoetz_version": artifact.plan.version,
    }
    return canonical_encode({**body, "marker_digest": canonical_digest(body)})


def _load_object(data: bytes) -> Mapping[str, JsonValue] | None:
    try:
        parsed = strict_json_parse(data)
    except ProtocolValueError, UnicodeError:
        return None
    return cast(Mapping[str, JsonValue], parsed) if isinstance(parsed, Mapping) else None


def _valid_source_marker(files: Mapping[str, bytes]) -> tuple[bool, str | None]:
    raw = files.get(_MARKER_NAME)
    marker = None if raw is None else _load_object(raw)
    if marker is None or (
        marker.get("schema") != _MARKER_SCHEMA
        and marker.get("schema") not in _LEGACY_MARKER_SCHEMAS
    ):
        return False, None
    digest = marker.get("marker_digest")
    body = {key: value for key, value in marker.items() if key != "marker_digest"}
    if type(digest) is not str or digest != canonical_digest(body):
        return False, None
    # Frozen legacy identifier (ADR-048): the marker's launcher key.
    launcher = marker.get("yoetz_launcher")
    if marker.get("schema") == _MARKER_SCHEMA and (
        type(launcher) is not list or not valid_launcher(tuple(cast(list[object], launcher)))
    ):
        return False, None
    rows = marker.get("managed_files")
    if type(rows) is not list:
        return False, None
    expected: dict[str, tuple[int, str]] = {}
    for raw_row in rows:
        if not isinstance(raw_row, Mapping):
            return False, None
        path = raw_row.get("relative_path")
        size = raw_row.get("size")
        sha = raw_row.get("sha256")
        if (
            type(path) is not str
            or type(size) is not int
            or type(sha) is not str
            or path in expected
        ):
            return False, None
        expected[path] = (size, sha)
    content = {path: data for path, data in files.items() if path != _MARKER_NAME}
    if set(content) != set(expected) or any(
        expected[path] != (len(data), _sha(data)) for path, data in content.items()
    ):
        value = marker.get("artifact_digest")
        return False, value if type(value) is str else None
    value = marker.get("artifact_digest")
    return True, value if type(value) is str else None


def _inspect_source(
    target: ClaudeCodePluginTarget, artifact: ClaudeCodePluginArtifact
) -> _SourceInspection:
    root = Path(target.marketplace_root)
    parent = root.parent
    rollback = parent / _ROLLBACK_NAME
    if rollback.exists() or rollback.is_symlink():
        # An interrupted replacement or removal left recovery material behind.
        # Reporting absent/managed here would let a later operation consume
        # authority before discovering it; surface the recovery state instead.
        return _SourceInspection(
            PluginArtifactState.RECOVERY_REQUIRED,
            None,
            False,
            canonical_digest({"state": "rollback_present"}),
        )
    if parent.exists() and any(item.name.startswith(_STAGE_PREFIX) for item in parent.iterdir()):
        return _SourceInspection(
            PluginArtifactState.RECOVERY_REQUIRED,
            None,
            False,
            canonical_digest({"state": "stage_present"}),
        )
    if not root.exists():
        return _SourceInspection(
            PluginArtifactState.ABSENT,
            None,
            False,
            canonical_digest({"state": "absent"}),
        )
    if root.is_symlink() or not root.is_dir():
        raise _error(PluginArtifactReason.TARGET_UNSAFE)
    files = _safe_tree(root)
    digest = _tree_digest(files)
    valid, installed_digest = _valid_source_marker(files)
    if not valid:
        return _SourceInspection(
            PluginArtifactState.MODIFIED
            if installed_digest is not None
            else PluginArtifactState.UNMANAGED,
            installed_digest,
            False,
            digest,
        )
    expected = {**_source_members(artifact), _MARKER_NAME: _marker(artifact)}
    return _SourceInspection(
        PluginArtifactState.NATIVE_MANAGED,
        installed_digest,
        True,
        digest if files != expected else _tree_digest(expected),
    )


def _json_file(path: Path) -> tuple[Mapping[str, JsonValue] | None, bool]:
    if not path.exists() and not path.is_symlink():
        return None, True
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > _MAX_FILE_BYTES:
            return None, False
        parsed = strict_json_parse(path.read_bytes())
    except OSError, ProtocolValueError, UnicodeError:
        return None, False
    return (
        (cast(Mapping[str, JsonValue], parsed), True)
        if isinstance(parsed, Mapping)
        else (None, False)
    )


def _host_state_digest(target: ClaudeCodePluginTarget) -> str:
    rows: list[dict[str, JsonValue]] = []
    for name, path in (
        ("claude_json", Path(target.claude_config_root) / ".claude.json"),
        (
            "installed_plugins",
            Path(target.claude_config_root) / "plugins" / "installed_plugins.json",
        ),
        (
            "known_marketplaces",
            Path(target.claude_config_root) / "plugins" / "known_marketplaces.json",
        ),
        ("project_settings", Path(target.project_root) / ".claude" / "settings.json"),
    ):
        if not path.exists() and not path.is_symlink():
            rows.append({"name": name, "state": "absent"})
            continue
        if path.is_symlink() or not path.is_file() or path.stat().st_size > _MAX_FILE_BYTES:
            rows.append({"name": name, "state": "unsafe"})
            continue
        data = path.read_bytes()
        rows.append({"name": name, "sha256": _sha(data), "size": len(data), "state": "present"})
    return canonical_digest(cast(JsonValue, {"files": rows}))


@dataclass(frozen=True, slots=True)
class _ConfigEntries:
    """One configuration source's FinishUP-relevant MCP entries (ADR-048 splits the legacy key).

    ``current`` is the ``finishup`` entry or the one other-named exact route; ``legacy`` is an
    exact route under the legacy ``yoetz`` key, and ``legacy_foreign`` records a legacy-key entry
    FinishUP cannot prove is its own. ``observed`` is False when the source is unreadable.
    """

    current: tuple[str, Mapping[str, JsonValue]] | None = None
    legacy: tuple[str, Mapping[str, JsonValue]] | None = None
    legacy_foreign: bool = False
    observed: bool = True


_UNREADABLE: Final = _ConfigEntries(observed=False)


def _config_entries(raw: object, launchers: tuple[tuple[str, ...], ...] = ()) -> _ConfigEntries:
    if raw is None:
        return _ConfigEntries()
    if not isinstance(raw, Mapping):
        return _UNREADABLE
    config = cast(Mapping[str, JsonValue], raw)
    servers = config.get("mcpServers")
    if servers is None:
        return _ConfigEntries()
    if not isinstance(servers, Mapping):
        return _UNREADABLE
    typed_servers = cast(Mapping[str, JsonValue], servers)
    relevant: list[tuple[str, Mapping[str, JsonValue]]] = []
    legacy: tuple[str, Mapping[str, JsonValue]] | None = None
    legacy_foreign = False
    for name, raw_entry in typed_servers.items():
        if name == MCP_SERVER_NAME:
            if not isinstance(raw_entry, Mapping):
                return _UNREADABLE
            relevant.append((name, cast(Mapping[str, JsonValue], raw_entry)))
        elif name == LEGACY_MCP_SERVER_NAME:
            # The pre-rename key (ADR-048): an exact route there is FinishUP's own but outdated;
            # anything else no longer shares FinishUP's name and is only reported.
            if (
                isinstance(raw_entry, Mapping)
                and _route_profile(cast(Mapping[str, JsonValue], raw_entry), launchers) is not None
            ):
                legacy = (name, cast(Mapping[str, JsonValue], raw_entry))
            else:
                legacy_foreign = True
        elif (
            isinstance(raw_entry, Mapping)
            and _route_profile(cast(Mapping[str, JsonValue], raw_entry), launchers) is not None
        ):
            relevant.append((name, cast(Mapping[str, JsonValue], raw_entry)))
    if len(relevant) > 1:
        return _UNREADABLE
    return _ConfigEntries(relevant[0] if relevant else None, legacy, legacy_foreign)


def _launcher_prefix(
    command: object, launchers: tuple[tuple[str, ...], ...]
) -> tuple[str, ...] | None:
    """The fixed arguments of the launcher ``command`` names, or ``None`` when it names none.

    A bare console script under either spelling (the deprecated ``yoetz`` alias, ADR-048) takes
    no fixed arguments; an absolute command must be one of ``launchers`` exactly.
    """

    if command in LAUNCHER_NAMES:
        return ()
    for launcher in launchers:
        if command == launcher[0]:
            return launcher[1:]
    return None


def _route_profile(
    entry: Mapping[str, JsonValue] | None, launchers: tuple[tuple[str, ...], ...] = ()
) -> Literal["strict", "policy"] | None:
    """Classify one MCP entry as an exact FinishUP route, else ``None``.

    An exact route launches either a bare ``finishup`` console script (external registrations
    the owner wrote by hand) or one of ``launchers`` — this artifact's exact bound launcher, its
    deprecated ``yoetz`` alias, or a launcher a managed marker recorded — followed by the exact
    Claude ``mcp serve`` arguments. The pre-host-identity bare forms remain readable for an
    upgrade/remove transition but are never emitted by the renderer.
    """

    if entry is None or set(entry) != {"args", "command", "type"}:
        return None
    if entry.get("type") != "stdio":
        return None
    raw_args = entry.get("args")
    if not isinstance(raw_args, (list, tuple)):
        return None
    args = tuple(cast(Sequence[object], raw_args))
    prefix = _launcher_prefix(entry.get("command"), launchers)
    if prefix is None or args[: len(prefix)] != prefix:
        return None
    rest = args[len(prefix) :]
    if rest in {
        ("mcp", "serve", "--host", "claude"),
        ("mcp", "serve"),
    }:
        return "policy"
    if rest in {
        ("mcp", "serve", "--host", "claude", "--semantic", "off"),
        ("mcp", "serve", "--semantic", "off"),
    }:
        return "strict"
    return None


def _initialize_host_profile(
    entry: Mapping[str, JsonValue], launchers: tuple[tuple[str, ...], ...] = ()
) -> Literal["generic", "claude"]:
    """Classify the initialize body for an already recognized FinishUP route.

    The route profile answers the semantic question (policy versus strict). The host profile is a
    separate fact: only the explicit ``--host claude`` argv selects the compact Claude body. Old
    owner-written ``mcp serve`` entries remain valid routes, but they cannot safely be assumed to
    have been launched by Claude and therefore use the generic body.
    """

    raw_args = entry.get("args")
    if not isinstance(raw_args, (list, tuple)):
        raise ValueError("claude_code_mcp_observation_invalid")
    args = tuple(cast(Sequence[object], raw_args))
    prefix = _launcher_prefix(entry.get("command"), launchers)
    if prefix is None or args[: len(prefix)] != prefix:
        raise ValueError("claude_code_mcp_observation_invalid")
    rest = args[len(prefix) :]
    if tuple(rest[:4]) == ("mcp", "serve", "--host", "claude"):
        return "claude"
    return "generic"


def _route_launchers(
    finishup_launcher: tuple[str, ...] | None, known_launchers: Sequence[tuple[str, ...]]
) -> tuple[tuple[str, ...], ...]:
    """The bound launcher, its deprecated alias, and marker-recorded launchers (ADR-048)."""

    candidates: list[tuple[str, ...]] = []
    if finishup_launcher is not None:
        candidates.extend(
            launcher_aliases(finishup_launcher)
            if valid_launcher(finishup_launcher)
            else (finishup_launcher,)
        )
    candidates.extend(known_launchers)
    return tuple(dict.fromkeys(candidates))


def observe_claude_code_mcp(
    *,
    plugin_root: Path,
    project_root: Path,
    claude_config_root: Path,
    connector_entry: Mapping[str, JsonValue] | None = None,
    finishup_launcher: tuple[str, ...] | None = None,
    claude_json: Path | None = None,
    known_launchers: Sequence[tuple[str, ...]] = (),
) -> ClaudeCodeMcpObservation:
    """Observe all reachable sources without treating Claude precedence as ownership.

    ``finishup_launcher`` is the artifact's exact bound launcher; entries that launch it (or its
    deprecated ``yoetz`` alias) with the exact ``mcp serve`` arguments are FinishUP routes just
    like a bare ``finishup`` console script. ``known_launchers`` adds launchers a managed marker
    recorded, such as a pre-rename installation's (ADR-048). ``claude_json`` names the user
    configuration file when it does not sit inside ``claude_config_root``; the default keeps the
    plugin status path's exact location.

    Entries under the legacy ``yoetz`` key are reported through ``legacy_registration``
    (ADR-048). An owned one is a live FinishUP route: alone it stands in for the registration,
    and beside a current entry the pair reads ``DUAL`` or ``AMBIGUOUS``.
    """

    launchers = _route_launchers(finishup_launcher, known_launchers)
    candidates: list[tuple[ClaudeCodeMcpSource, str | None, Mapping[str, JsonValue]]] = []
    legacy_candidates: list[tuple[ClaudeCodeMcpSource, str, Mapping[str, JsonValue]]] = []
    legacy_foreign = False
    uncertain: list[ClaudeCodeMcpSource] = []

    def collect(source: ClaudeCodeMcpSource, entries: _ConfigEntries) -> None:
        nonlocal legacy_foreign
        if not entries.observed:
            uncertain.append(source)
            return
        if entries.current is not None:
            candidates.append((source, *entries.current))
        if entries.legacy is not None:
            legacy_candidates.append((source, *entries.legacy))
        legacy_foreign = legacy_foreign or entries.legacy_foreign

    config, config_observed = _json_file(
        claude_config_root / ".claude.json" if claude_json is None else claude_json
    )
    if not config_observed:
        uncertain.extend((ClaudeCodeMcpSource.LOCAL, ClaudeCodeMcpSource.USER))
    elif config is not None:
        projects = config.get("projects")
        local_raw = projects.get(str(project_root)) if isinstance(projects, Mapping) else None
        collect(ClaudeCodeMcpSource.LOCAL, _config_entries(local_raw, launchers))
        collect(ClaudeCodeMcpSource.USER, _config_entries(config, launchers))
    project, project_observed = _json_file(project_root / ".mcp.json")
    collect(
        ClaudeCodeMcpSource.PROJECT,
        _config_entries(project, launchers) if project_observed else _UNREADABLE,
    )
    plugin, plugin_observed = _json_file(plugin_root / ".mcp.json")
    collect(
        ClaudeCodeMcpSource.PLUGIN,
        _config_entries(plugin, launchers) if plugin_observed else _UNREADABLE,
    )
    if connector_entry is not None:
        candidates.append((ClaudeCodeMcpSource.CLAUDE_AI_CONNECTOR, None, connector_entry))
    order = {source: index for index, source in enumerate(ClaudeCodeMcpSource)}
    candidates.sort(key=lambda item: order[item[0]])
    legacy_candidates.sort(key=lambda item: order[item[0]])
    if uncertain:
        present = tuple(source for source, _name, _entry in candidates)
        combined = tuple(
            sorted(
                set((*present, *uncertain)),
                key=lambda source: order[source],
            )
        )
        return ClaudeCodeMcpObservation(
            McpOwnershipState.AMBIGUOUS,
            None,
            None,
            combined,
            False,
            False,
        )
    profiles = [
        (source, name, entry, _route_profile(entry, launchers))
        for source, name, entry in candidates
    ]
    legacy: LegacyInstallation = (
        "none"
        if not legacy_candidates and not legacy_foreign
        else "foreign"
        if not legacy_candidates
        else "duplicate"
        if profiles and all(profile is not None for *_rest, profile in profiles)
        else "legacy_only"
    )
    if not profiles and not legacy_candidates:
        return ClaudeCodeMcpObservation(
            McpOwnershipState.ABSENT, None, None, (), True, False, legacy_registration=legacy
        )
    # An owned legacy-key route is a live FinishUP server: alone it is the registration, owned
    # but outdated; beside a current entry the pair reads dual or ambiguous exactly as the same
    # pair under one name would, never as one admissible route.
    profiles = sorted(
        (
            *profiles,
            *(
                (source, name, entry, _route_profile(entry, launchers))
                for source, name, entry in legacy_candidates
            ),
        ),
        key=lambda item: order[item[0]],
    )
    present = tuple(dict.fromkeys(source for source, _name, _entry, _profile in profiles))
    if any(profile is None for _source, _name, _entry, profile in profiles):
        source = next(source for source, _name, _entry, profile in profiles if profile is None)
        return ClaudeCodeMcpObservation(
            McpOwnershipState.FOREIGN,
            source,
            None,
            present,
            True,
            False,
            legacy_registration=legacy,
        )
    plugin_profiles = [
        profile
        for source, _name, _entry, profile in profiles
        if source is ClaudeCodeMcpSource.PLUGIN
    ]
    external_profiles = [
        profile
        for source, _name, _entry, profile in profiles
        if source is not ClaudeCodeMcpSource.PLUGIN
    ]
    if plugin_profiles and external_profiles:
        return ClaudeCodeMcpObservation(
            McpOwnershipState.DUAL,
            present[0],
            None,
            present,
            True,
            False,
            legacy_registration=legacy,
        )
    if len(profiles) > 1:
        return ClaudeCodeMcpObservation(
            McpOwnershipState.AMBIGUOUS,
            present[0],
            None,
            present,
            True,
            False,
            legacy_registration=legacy,
        )
    source, name, entry, profile = profiles[0]
    assert profile is not None
    return ClaudeCodeMcpObservation(
        McpOwnershipState.PLUGIN
        if source is ClaudeCodeMcpSource.PLUGIN
        else McpOwnershipState.EXTERNAL,
        source,
        cast(Literal["strict", "policy"], profile),
        present,
        True,
        # Name-mappability only, deliberately independent of the route profile: it says whether
        # the observed server key maps to the fixed permission-rule names admission can write
        # (docs/INTERFACES.md). The policy-route requirement is enforced separately at grant,
        # which refuses `route_not_policy` for any non-policy route (host_admission.py). A
        # legacy-key route maps to no admission rule name (ADR-048).
        name == MCP_SERVER_NAME and source is not ClaudeCodeMcpSource.CLAUDE_AI_CONNECTOR,
        _initialize_host_profile(entry, launchers),
        legacy,
    )


def _list_plugins(
    target: ClaudeCodePluginTarget, commands: ClaudeCodeCommandPort
) -> tuple[list[Mapping[str, JsonValue]], bool]:
    result = commands.run(target, ("plugin", "list", "--json"))
    if result.returncode != 0:
        return [], False
    try:
        parsed = strict_json_parse(result.stdout)
    except ProtocolValueError, UnicodeError:
        return [], False
    if type(parsed) is not list or any(not isinstance(item, Mapping) for item in parsed):
        return [], False
    return [cast(Mapping[str, JsonValue], item) for item in parsed], True


def _exact_plugin_entry(
    target: ClaudeCodePluginTarget, rows: Sequence[Mapping[str, JsonValue]]
) -> Mapping[str, JsonValue] | None:
    matches = [row for row in rows if row.get("id") == _PLUGIN_ID]
    if len(matches) != 1:
        return None
    row = matches[0]
    if row.get("scope") != "project" or row.get("projectPath") != target.project_root:
        return None
    return row


def _marketplace_registered(target: ClaudeCodePluginTarget) -> bool | None:
    settings, observed = _json_file(Path(target.project_root) / ".claude" / "settings.json")
    if not observed:
        return None
    if settings is None:
        return False
    marketplaces = settings.get("extraKnownMarketplaces")
    if marketplaces is None:
        return False
    if not isinstance(marketplaces, Mapping):
        return None
    entry = marketplaces.get(_MARKETPLACE_NAME)
    if entry is None:
        return False
    if not isinstance(entry, Mapping):
        return None
    source = entry.get("source")
    if not isinstance(source, Mapping):
        return None
    if source != {"source": "directory", "path": target.marketplace_root}:
        return None
    known, known_observed = _json_file(
        Path(target.claude_config_root) / "plugins" / "known_marketplaces.json"
    )
    if not known_observed or known is None:
        return None
    known_entry = known.get(_MARKETPLACE_NAME)
    if not isinstance(known_entry, Mapping):
        return None
    known_source = known_entry.get("source")
    if not isinstance(known_source, Mapping):
        return None
    return (
        True
        if known_source == {"source": "directory", "path": target.marketplace_root}
        and known_entry.get("installLocation") == target.marketplace_root
        else None
    )


def _cache_digest(
    target: ClaudeCodePluginTarget,
    artifact: ClaudeCodePluginArtifact,
    row: Mapping[str, JsonValue] | None,
) -> tuple[str | None, str | None, bool]:
    if row is None:
        return None, None, True
    version = row.get("version")
    install_path = row.get("installPath")
    if type(version) is not str or type(install_path) is not str:
        return None, None, False
    path = Path(install_path)
    expected_parent = Path(target.cache_root) / _MARKETPLACE_NAME / "finishup"
    try:
        path.relative_to(expected_parent)
    except ValueError:
        return None, version, False
    if path != expected_parent / version or path.is_symlink() or not path.is_dir():
        return None, version, False
    files = _safe_tree(path)
    exact = files == dict(artifact.members)
    return artifact.artifact_digest if exact else _tree_digest(files), version, exact


def _proof(
    *,
    installed_exact: bool,
    discovered: bool,
    registered: bool | None,
    enabled: bool | None,
    mcp: ClaudeCodeMcpObservation,
    session: ClaudeCodeSessionObservation | None,
) -> tuple[PluginProofStatus, ...]:
    # Activation proof claims the marketplace-installed delivery profile, so a
    # session observation alone is insufficient: a development --plugin-dir run
    # can produce the same init event from the source root. Require the
    # independent installed/discovered/registered/enabled facts alongside it.
    activated = (
        session is not None
        and installed_exact
        and discovered
        and registered is True
        and enabled is True
    )
    return tuple(
        PluginProofStatus(
            facet,
            (
                "proven"
                if facet in {PluginProofFacet.SOURCE, PluginProofFacet.RENDERED_ARTIFACT}
                or (installed_exact and facet is PluginProofFacet.INSTALLED_BYTES)
                or (discovered and facet is PluginProofFacet.HOST_DISCOVERY)
                or (activated and facet is PluginProofFacet.HOST_ACTIVATION)
                or (
                    session is not None
                    and session.skill_registered
                    and facet is PluginProofFacet.SKILL_DELIVERY
                )
                or (
                    session is not None
                    and session.scoped_workflow_tools_visible
                    and facet is PluginProofFacet.MCP_BINDING
                )
                or (
                    session is not None
                    and session.mcp_connected
                    and facet is PluginProofFacet.MCP_RUNTIME
                )
                or (
                    mcp.observed
                    and mcp.ownership_state
                    in {McpOwnershipState.EXTERNAL, McpOwnershipState.PLUGIN}
                    and facet is PluginProofFacet.MCP_OWNER
                )
                else "not_observed"
            ),
        )
        for facet in PluginProofFacet
    )


@dataclass(frozen=True, slots=True, repr=False)
class _LegacyMarketplace:
    """The Yoetz-era ``yoetz-local`` marketplace for this project (ADR-048).

    ``owned`` requires a marker-valid tree that names the legacy marketplace; its digest, the
    host registration, discovery, and enablement are what a preview binds and a migration undoes.
    """

    state: Literal["absent", "owned", "foreign"]
    root: Path | None = None
    # This project's own settings register the legacy marketplace.
    registered: bool = False
    discovered: bool = False
    enabled: bool | None = None
    digest: str | None = None
    launcher: tuple[str, ...] | None = None
    # A marker-valid legacy tree stays beside the managed root whatever this project does: other
    # projects of the same Claude config root may still load it, so FinishUP never deletes it or
    # Claude's user-level registration of it.
    retained: bool = False
    # Claude lists the legacy plugin for another project or scope too.
    shared: bool = False
    # This project's own declaration entries (settings key, entry digest) that a migration drops.
    declaration: tuple[tuple[str, str], ...] = ()
    # Claude's user-level ``known_marketplaces.json`` registers the legacy marketplace.
    known: bool = False

    def installation(self, current: PluginArtifactState) -> LegacyInstallation:
        if self.state == "absent":
            return "none"
        if self.state == "foreign":
            return "foreign"
        return "legacy_only" if current is PluginArtifactState.ABSENT else "duplicate"

    def binding(self) -> dict[str, JsonValue]:
        return {
            "digest": self.digest,
            "discovered": self.discovered,
            "enabled": self.enabled,
            "registered": self.registered,
            "retained": self.retained,
            "declaration": dict(self.declaration),
            "known": self.known,
            "root": None if self.root is None else str(self.root),
            "shared": self.shared,
            "state": self.state,
        }


_NO_LEGACY: Final = _LegacyMarketplace("absent")


def _directory_source(entry: object) -> Path | None:
    """The absolute directory a marketplace registration names, else ``None``."""

    if not isinstance(entry, Mapping):
        return None
    source = cast(Mapping[str, JsonValue], entry).get("source")
    if not isinstance(source, Mapping):
        return None
    path = cast(Mapping[str, JsonValue], source).get("path")
    if source.get("source") != "directory" or type(path) is not str:
        return None
    candidate = Path(path)
    if not candidate.is_absolute() or any(ord(char) < 32 or ord(char) == 127 for char in path):
        return None
    return candidate


def _legacy_location(target: ClaudeCodePluginTarget) -> Path:
    """The one directory FinishUP accepts as the legacy marketplace (ADR-048).

    Yoetz's guided connection wrote ``<config>/plugins/marketplaces/yoetz-local``, the sibling of
    the managed ``finishup-local`` root FinishUP's connection names; an explicit command names
    its managed root, or the old directory itself. Both come from the owner, never from a file a
    repository can commit, so a project setting can only confirm this location, never move it.
    """

    managed = Path(target.marketplace_root)
    if managed.name == _LEGACY_MARKETPLACE_NAME:
        return managed
    return managed.parent / _LEGACY_MARKETPLACE_NAME


def _legacy_registration(
    target: ClaudeCodePluginTarget, location: Path
) -> tuple[bool, bool, bool, bool]:
    """Return ``(registered here, readable, elsewhere, known)`` for the legacy marketplace.

    ``registered here`` is this project's ``extraKnownMarketplaces`` entry and ``known`` Claude's
    user-level ``known_marketplaces.json`` entry. ``elsewhere`` is set when either names any
    directory but ``location``: that marketplace is not one FinishUP wrote.
    """

    registered = False
    readable = True
    elsewhere = False
    known = False
    for path, key in (
        (Path(target.project_root) / ".claude" / "settings.json", "extraKnownMarketplaces"),
        (Path(target.claude_config_root) / "plugins" / "known_marketplaces.json", None),
    ):
        document, observed = _json_file(path)
        if not observed:
            readable = False
            continue
        if document is None:
            continue
        container = document.get(key) if key is not None else document
        if container is None:
            continue
        if not isinstance(container, Mapping):
            readable = False
            continue
        entry = cast(Mapping[str, JsonValue], container).get(_LEGACY_MARKETPLACE_NAME)
        if entry is None:
            continue
        if key is not None:
            registered = True
        else:
            known = True
        directory = _directory_source(entry)
        if directory is None:
            readable = False
        elif directory != location:
            elsewhere = True
    return registered, readable, elsewhere, known


def _legacy_declaration(target: ClaudeCodePluginTarget) -> tuple[tuple[str, str], ...] | None:
    """This project's legacy declaration entries and their digests, or ``None`` when unreadable.

    A symlinked ``.claude`` directory reads as unreadable: the migration's settings edit refuses
    it (``_drop_legacy_declaration``), so a preview must never promise that edit over it.
    """

    settings = Path(target.project_root) / ".claude" / "settings.json"
    try:
        if settings.parent.is_symlink():
            return None
    except OSError:
        return None
    document, observed = _json_file(settings)
    if not observed:
        return None
    found: list[tuple[str, str]] = []
    for container_key, key in _LEGACY_DECLARATION:
        container = None if document is None else document.get(container_key)
        if container is None:
            continue
        if not isinstance(container, Mapping):
            return None
        entries = cast(Mapping[str, JsonValue], container)
        if key in entries:
            found.append((container_key, canonical_digest(entries[key])))
    return tuple(found)


def _legacy_tree(
    root: Path,
) -> tuple[Literal["missing", "legacy", "current", "other"], str | None, tuple[str, ...] | None]:
    """Classify one marketplace directory by its marker's marketplace name (ADR-048)."""

    if not root.exists() and not root.is_symlink():
        return "missing", None, None
    try:
        _safe_existing_ancestor(root)
        if any(item.is_symlink() for item in (root, *root.parents)) or not root.is_dir():
            return "other", None, None
        if any(item.name.startswith(_STAGE_PREFIX) for item in root.parent.iterdir()) or (
            (root.parent / _ROLLBACK_NAME).exists()
        ):
            # Interrupted residue beside it: never classify it as safe to remove.
            return "other", None, None
        files = _safe_tree(root)
    except ClaudeCodeIntegrationError, OSError:
        return "other", None, None
    if not _valid_source_marker(files)[0]:
        return "other", None, None
    marker = _load_object(files[_MARKER_NAME])
    assert marker is not None
    name = marker.get("marketplace_name")
    if name == _MARKETPLACE_NAME:
        return "current", None, None
    if name != _LEGACY_MARKETPLACE_NAME:
        return "other", None, None
    # Frozen legacy identifier (ADR-048): the marker's launcher key.
    return "legacy", _tree_digest(files), recorded_launcher(marker.get("yoetz_launcher"))


def _inspect_legacy(
    target: ClaudeCodePluginTarget,
    rows: Sequence[Mapping[str, JsonValue]] | None,
) -> _LegacyMarketplace:
    """Classify this project's Yoetz-era install against the one accepted location (ADR-048).

    ``rows`` is the observed ``plugin list`` output, or ``None`` when it was not read; status
    treats an unreadable list as unproven ownership. The install is this project's only when its
    settings register the legacy marketplace or Claude lists the legacy plugin for it; a legacy
    tree no project here references is only reported as retained.
    """

    location = _legacy_location(target)
    registered, readable, elsewhere, known = _legacy_registration(target, location)
    discovered = False
    enabled: bool | None = None
    shared = False
    if rows is not None:
        matches = [row for row in rows if row.get("id") == _LEGACY_PLUGIN_ID]
        exact = [
            row
            for row in matches
            if row.get("scope") == "project" and row.get("projectPath") == target.project_root
        ]
        shared = len(exact) != len(matches)
        if len(exact) > 1:
            readable = False
        elif exact:
            discovered = True
            value = exact[0].get("enabled")
            enabled = value if type(value) is bool else None
    tree, digest, launcher = _legacy_tree(location)
    retained = tree == "legacy" and location != Path(target.marketplace_root)
    if not registered and not discovered:
        # Nothing in this project uses the legacy marketplace. A tree there belongs to other
        # projects of this config root (or to none any more) and is left where it is.
        return _LegacyMarketplace("absent", retained=retained, shared=shared)
    declaration = _legacy_declaration(target)
    if tree != "legacy" or not readable or elsewhere or declaration is None:
        # Registered or listed here, but not over a tree FinishUP wrote at the accepted location:
        # never trusted, never touched.
        return _LegacyMarketplace(
            "foreign", None, registered, discovered, enabled, retained=retained, shared=shared
        )
    return _LegacyMarketplace(
        "owned",
        location,
        registered,
        discovered,
        enabled,
        digest,
        launcher,
        retained=retained,
        shared=shared,
        declaration=declaration,
        known=known,
    )


def _unregisters_legacy_marketplace(
    target: ClaudeCodePluginTarget, legacy: _LegacyMarketplace
) -> bool:
    """Whether a migration runs Claude's unscoped ``plugin marketplace remove yoetz-local``.

    Only an in-place migration, whose managed root is the owned legacy directory itself, runs it,
    and only while this project or Claude's user-level file still registers that directory. The
    preview's ``legacy_marketplace_replaced`` warning and ``_remove_legacy`` share this one fact.
    """

    return (
        legacy.state == "owned"
        and legacy.root == Path(target.marketplace_root)
        and (legacy.registered or legacy.known)
    )


def status_claude_code_plugin(
    target: ClaudeCodePluginTarget,
    artifact: ClaudeCodePluginArtifact,
    *,
    commands: ClaudeCodeCommandPort | None = None,
    connector_entry: Mapping[str, JsonValue] | None = None,
    session_observation: ClaudeCodeSessionObservation | None = None,
) -> ClaudeCodePluginStatus:
    return _status_with_legacy(
        target,
        artifact,
        commands=commands,
        connector_entry=connector_entry,
        session_observation=session_observation,
    )[0]


def _status_with_legacy(
    target: ClaudeCodePluginTarget,
    artifact: ClaudeCodePluginArtifact,
    *,
    commands: ClaudeCodeCommandPort | None = None,
    connector_entry: Mapping[str, JsonValue] | None = None,
    session_observation: ClaudeCodeSessionObservation | None = None,
) -> tuple[ClaudeCodePluginStatus, _LegacyMarketplace]:
    _validate_target(target)
    source = _inspect_source(target, artifact)
    command_port = SubprocessClaudeCodeCommands() if commands is None else commands
    rows, list_observed = _list_plugins(target, command_port)
    legacy = _inspect_legacy(target, rows if list_observed else None)
    if not list_observed and legacy.state == "owned":
        legacy = _LegacyMarketplace(
            "foreign", None, legacy.registered, retained=legacy.retained, shared=legacy.shared
        )
    row = _exact_plugin_entry(target, rows) if list_observed else None
    installed_digest, installed_version, cache_observed = _cache_digest(target, artifact, row)
    installed_exact = (
        cache_observed
        and installed_digest == artifact.artifact_digest
        and installed_version == artifact.plan.version
    )
    registered = _marketplace_registered(target)
    enabled_raw = None if row is None else row.get("enabled")
    enabled = enabled_raw if type(enabled_raw) is bool else None
    discovered = row is not None
    plugin_root = Path(target.marketplace_root) / "plugins" / "finishup"
    mcp = observe_claude_code_mcp(
        plugin_root=plugin_root,
        project_root=Path(target.project_root),
        claude_config_root=Path(target.claude_config_root),
        finishup_launcher=artifact.finishup_launcher,
        connector_entry=connector_entry,
        # A registration an earlier install wrote names the launcher its marker recorded.
        known_launchers=() if legacy.launcher is None else (legacy.launcher,),
    )
    if source.state is PluginArtifactState.RECOVERY_REQUIRED:
        state = PluginArtifactState.RECOVERY_REQUIRED
    elif (
        source.state in {PluginArtifactState.MODIFIED, PluginArtifactState.UNMANAGED}
        or not cache_observed
    ):
        state = PluginArtifactState.MODIFIED
    elif source.state is PluginArtifactState.ABSENT and row is None and registered is False:
        state = PluginArtifactState.ABSENT
    elif source.marker_valid and installed_exact and registered is True:
        state = PluginArtifactState.NATIVE_MANAGED
    else:
        state = PluginArtifactState.PARTIAL
    operation = (
        PluginOperationState.NOT_STARTED
        if state is PluginArtifactState.ABSENT
        else PluginOperationState.COMPLETED
        if state is PluginArtifactState.NATIVE_MANAGED
        else PluginOperationState.OUTCOME_UNKNOWN
    )
    notes = tuple(
        sorted(
            {
                "agent_plugins_not_claimed",
                "cache_install_does_not_prove_loaded_session",
                "enabled_state_does_not_prove_loaded_session",
                "marketplace_project_scope_only",
                "model_use_not_observed",
                *(("legacy_marketplace_retained",) if legacy.retained else ()),
            },
            key=str.encode,
        )
    )
    status = ClaudeCodePluginStatus(
        state,
        operation,
        artifact.artifact_digest,
        artifact.marketplace_digest,
        _host_state_digest(target),
        source.digest,
        installed_digest,
        installed_version,
        registered,
        discovered,
        enabled,
        None if session_observation is None else session_observation.loaded_root_digest,
        source.marker_valid,
        mcp,
        _proof(
            installed_exact=installed_exact,
            discovered=discovered,
            registered=registered,
            enabled=enabled,
            mcp=mcp,
            session=session_observation,
        ),
        notes,
        claude_code_version_provenance(target.identity.version),
        legacy.installation(state),
    )
    return status, legacy


def observe_claude_code_session_init(
    payload: Mapping[str, JsonValue],
    *,
    target: ClaudeCodePluginTarget,
    artifact: ClaudeCodePluginArtifact,
) -> ClaudeCodeSessionObservation:
    """Reduce one Claude stream-json init event to bounded activation evidence.

    Raw cwd, plugin paths, session ID, memory paths, tool payloads, and model output
    are used only for exact local validation and never returned.
    """

    if payload.get("type") != "system" or payload.get("subtype") != "init":
        raise ValueError("claude_code_session_init_invalid")
    if payload.get("claude_code_version") != target.identity.version:
        raise ValueError("claude_code_session_init_invalid")
    if payload.get("cwd") != target.project_root:
        raise ValueError("claude_code_session_init_invalid")
    session_id = payload.get("session_id")
    if type(session_id) is not str or not session_id or len(session_id) > 128:
        raise ValueError("claude_code_session_init_invalid")
    plugins: object = payload.get("plugins")
    if not isinstance(plugins, (list, tuple)):
        raise ValueError("claude_code_session_init_invalid")
    matches: list[Mapping[str, JsonValue]] = []
    for raw in cast(Sequence[object], plugins):
        if isinstance(raw, Mapping):
            row = cast(Mapping[str, JsonValue], raw)
            if row.get("name") == "finishup" and row.get("source") == _PLUGIN_ID:
                matches.append(row)
    if len(matches) != 1 or matches[0].get("version") != artifact.plan.version:
        raise ValueError("claude_code_session_init_invalid")
    loaded_path = matches[0].get("path")
    if type(loaded_path) is not str or not Path(loaded_path).is_absolute():
        raise ValueError("claude_code_session_init_invalid")
    root = Path(loaded_path)
    allowed_roots = {
        Path(target.marketplace_root) / "plugins" / "finishup",
        Path(target.cache_root) / _MARKETPLACE_NAME / "finishup" / artifact.plan.version,
    }
    if root not in allowed_roots or root.is_symlink() or not root.is_dir():
        raise ValueError("claude_code_session_init_invalid")
    if _safe_tree(root) != dict(artifact.members):
        raise ValueError("claude_code_session_init_invalid")
    skills: object = payload.get("skills")
    tools: object = payload.get("tools")
    servers: object = payload.get("mcp_servers")
    skill_registered = isinstance(skills, (list, tuple)) and "finishup:finishup" in skills
    required_tools = {
        f"mcp__plugin_finishup_finishup__{name}" for name in FINISHUP_WORKFLOW_TOOL_NAMES
    }
    visible_tools: set[str] = set()
    if isinstance(tools, (list, tuple)):
        visible_tools = {item for item in cast(Sequence[object], tools) if type(item) is str}
    mcp_connected = False
    if isinstance(servers, (list, tuple)):
        for raw in cast(Sequence[object], servers):
            if isinstance(raw, Mapping):
                server = cast(Mapping[str, JsonValue], raw)
                if (
                    server.get("name") == "plugin:finishup:finishup"
                    and server.get("status") == "connected"
                ):
                    mcp_connected = True
                    break
    return ClaudeCodeSessionObservation(
        canonical_digest(
            {
                "artifact_digest": artifact.artifact_digest,
                "session_id": session_id,
                "version": target.identity.version,
            }
        ),
        artifact.artifact_digest,
        skill_registered,
        mcp_connected,
        required_tools.issubset(visible_tools),
    )


# Actions that never retire a legacy install, even beside an owned one (ADR-048).
_NON_MIGRATING_ACTIONS: Final = frozenset(
    {ClaudeCodePluginAction.ENABLE, ClaudeCodePluginAction.DISABLE, ClaudeCodePluginAction.NOOP}
)


def _admissible_owner_states(artifact: ClaudeCodePluginArtifact) -> set[McpOwnershipState]:
    if artifact.plan.mcp_ownership is McpOwnership.PLUGIN_MANAGED:
        return {McpOwnershipState.ABSENT, McpOwnershipState.PLUGIN}
    return {McpOwnershipState.ABSENT, McpOwnershipState.EXTERNAL}


def preview_claude_code_plugin(
    request: RequestId,
    target: ClaudeCodePluginTarget,
    action: ClaudeCodePluginAction,
    artifact: ClaudeCodePluginArtifact,
    *,
    commands: ClaudeCodeCommandPort | None = None,
    connector_entry: Mapping[str, JsonValue] | None = None,
) -> ClaudeCodePluginPreview:
    return _preview_with_legacy(
        request, target, action, artifact, commands=commands, connector_entry=connector_entry
    )[0]


def _preview_with_legacy(
    request: RequestId,
    target: ClaudeCodePluginTarget,
    action: ClaudeCodePluginAction,
    artifact: ClaudeCodePluginArtifact,
    *,
    commands: ClaudeCodeCommandPort | None = None,
    connector_entry: Mapping[str, JsonValue] | None = None,
) -> tuple[ClaudeCodePluginPreview, ClaudeCodePluginStatus, _LegacyMarketplace]:
    request = validate_request_id(request)
    if type(action) is not ClaudeCodePluginAction or action is ClaudeCodePluginAction.NOOP:
        raise _error(PluginArtifactReason.SOURCE_INVALID)
    if artifact.development:
        # The development carrier exists only for ``claude --plugin-dir`` runs; it never
        # enters the marketplace lane or consumes review authority.
        raise _error(PluginArtifactReason.SOURCE_INVALID, {"development_carrier": True})
    version_provenance = claude_code_version_provenance(target.identity.version)
    if version_provenance is None:
        # Below the compatibility floor the plugin/hook surfaces do not exist.
        # At or above it a version is admitted; whether it is an exactly proven
        # cell is reported as provenance, never inferred from proximity (#656).
        raise _error(
            PluginArtifactReason.FORMAT_UNSUPPORTED,
            {
                "version_unsupported": target.identity.version,
                "minimum_version": CLAUDE_CODE_MINIMUM_VERSION,
            },
        )
    target_identity = _validate_target(target)
    status, legacy = _status_with_legacy(
        target, artifact, commands=commands, connector_entry=connector_entry
    )
    if status.state is PluginArtifactState.RECOVERY_REQUIRED:
        # Interrupted stage/rollback material must be resolved before any new
        # mutation may even be previewed, let alone consume authority.
        raise _error(PluginArtifactReason.RECOVERY_REQUIRED)
    # An owned legacy marketplace is migrated by every installing action and removed by remove,
    # in the same approval, so its presence is never a no-op (ADR-048).
    legacy_owned = legacy.state == "owned"
    in_place = legacy_owned and legacy.root == Path(target.marketplace_root)
    if action is ClaudeCodePluginAction.CONNECT:
        if status.state is not PluginArtifactState.ABSENT:
            if not status.marker_valid or status.state not in {
                PluginArtifactState.NATIVE_MANAGED,
                PluginArtifactState.PARTIAL,
            }:
                raise _error(PluginArtifactReason.DESTINATION_CONFLICT)
            if (
                status.installed_digest == artifact.artifact_digest
                and status.enabled is True
                and not legacy_owned
            ):
                action = ClaudeCodePluginAction.NOOP
    elif (
        action is ClaudeCodePluginAction.INSTALL and status.state is not PluginArtifactState.ABSENT
    ):
        if (
            status.state is PluginArtifactState.NATIVE_MANAGED
            and status.installed_digest == artifact.artifact_digest
            and not legacy_owned
        ):
            action = ClaudeCodePluginAction.NOOP
        else:
            raise _error(PluginArtifactReason.DESTINATION_CONFLICT)
    elif action is ClaudeCodePluginAction.UPDATE and (
        # Updating a legacy-only install migrates it; a present renamed tree must still be ours.
        (
            not status.marker_valid
            and not (legacy_owned and status.state is PluginArtifactState.ABSENT)
        )
        or (not status.discovered and not legacy_owned)
    ):
        raise _error(PluginArtifactReason.DESTINATION_CONFLICT)
    elif action is ClaudeCodePluginAction.ENABLE and status.enabled is not False:
        if status.enabled is True:
            action = ClaudeCodePluginAction.NOOP
        else:
            raise _error(PluginArtifactReason.DESTINATION_CONFLICT)
    elif action is ClaudeCodePluginAction.DISABLE and status.enabled is not True:
        if status.enabled is False:
            action = ClaudeCodePluginAction.NOOP
        else:
            raise _error(PluginArtifactReason.DESTINATION_CONFLICT)
    elif (
        action is ClaudeCodePluginAction.REMOVE
        and (not status.marker_valid or status.state is PluginArtifactState.ABSENT)
        # An owned legacy marketplace alone is still FinishUP's to remove (ADR-048).
        and not (legacy_owned and status.state is PluginArtifactState.ABSENT)
    ):
        raise _error(PluginArtifactReason.REMOVE_REFUSED)
    if (
        in_place
        and legacy.shared
        and action
        not in {
            ClaudeCodePluginAction.ENABLE,
            ClaudeCodePluginAction.DISABLE,
            ClaudeCodePluginAction.NOOP,
        }
    ):
        # The managed root named is the shared legacy directory itself, and Claude still lists
        # the legacy plugin elsewhere: rewriting or deleting it would break those installs.
        raise _error(PluginArtifactReason.DESTINATION_CONFLICT, {"legacy_marketplace_shared": True})
    if action not in {
        ClaudeCodePluginAction.REMOVE,
        ClaudeCodePluginAction.DISABLE,
        ClaudeCodePluginAction.NOOP,
    } and status.mcp_observation.ownership_state not in _admissible_owner_states(artifact):
        raise _error(
            PluginArtifactReason.MCP_OWNERSHIP_CONFLICT,
            {
                "mcp_ownership_state": status.mcp_observation.ownership_state.value,
                **(
                    {}
                    if status.mcp_observation.legacy_registration == "none"
                    else {"legacy_registration": status.mcp_observation.legacy_registration}
                ),
            },
        )
    current_state: dict[str, JsonValue] = {
        "discovered": status.discovered,
        "enabled": status.enabled,
        "installed_digest": status.installed_digest,
        "installed_version": status.installed_version,
        "marketplace_registered": status.marketplace_registered,
        "mcp_ownership_state": status.mcp_observation.ownership_state.value,
        "observed_host_state_digest": status.host_state_digest,
        "source_digest": status.source_digest,
        "state": status.state.value,
    }
    if legacy.state != "absent":
        # Bind the exact legacy marketplace this approval migrates or removes (ADR-048).
        current_state["legacy_marketplace"] = legacy.binding()
    current_state_digest = canonical_digest(current_state)
    preview_digest = canonical_digest(
        {
            "action": action.value,
            "artifact_digest": artifact.artifact_digest,
            "current_state_digest": current_state_digest,
            "host_identity": {
                "architecture": target.identity.architecture,
                "executable_digest": target.identity.executable_digest,
                "os_name": target.identity.os_name,
                "version": target.identity.version,
            },
            "marketplace_digest": artifact.marketplace_digest,
            "marketplace_name": target.marketplace_name,
            "mcp_ownership": artifact.plan.mcp_ownership.value,
            "mcp_ownership_state": status.mcp_observation.ownership_state.value,
            "mcp_route_profile": artifact.plan.mcp_route_profile,
            "request_id": request,
            "scope": target.scope,
            "target_identity": target_identity,
        }
    )
    warnings = tuple(
        sorted(
            {
                "activation_requires_new_session_or_reload",
                "agent_plugins_compatibility_not_claimed",
                "claude_desktop_cloud_sdk_not_covered",
                "observation_requires_separate_consent",
                "plugin_data_does_not_hold_finishup_state",
                *(
                    ("legacy_installation_owned",)
                    if legacy_owned
                    else ("legacy_installation_foreign",)
                    if legacy.state == "foreign"
                    else ()
                ),
                *(("legacy_marketplace_retained",) if legacy.retained else ()),
                # Exactly what retiring this project's legacy install takes (ADR-048).
                *(
                    (
                        *(("legacy_project_registration_removed",) if legacy.declaration else ()),
                        *(
                            ("legacy_marketplace_replaced",)
                            if _unregisters_legacy_marketplace(target, legacy)
                            else ()
                        ),
                    )
                    if legacy_owned and action not in _NON_MIGRATING_ACTIONS
                    else ()
                ),
            },
            key=str.encode,
        )
    )
    preview = ClaudeCodePluginPreview(
        request,
        action,
        status.state,
        target_identity,
        current_state_digest,
        artifact.artifact_digest,
        artifact.marketplace_digest,
        preview_digest,
        artifact.plan.mcp_ownership,
        status.mcp_observation.ownership_state,
        artifact.plan.mcp_route_profile,
        warnings,
        version_provenance,
        status.legacy_installation,
    )
    return preview, status, legacy


def _ensure_private_parent(path: Path) -> None:
    existing = _safe_existing_ancestor(path)
    current = existing
    for part in path.relative_to(existing).parts:
        current = current / part
        current.mkdir(mode=0o700, exist_ok=True)
        facts = current.stat()
        if current.is_symlink() or not current.is_dir() or writable_by_others(facts):
            raise _error(PluginArtifactReason.TARGET_UNSAFE)


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


def _write_source(
    target: ClaudeCodePluginTarget,
    artifact: ClaudeCodePluginArtifact,
    request: RequestId,
) -> tuple[str, ...]:
    destination = Path(target.marketplace_root)
    parent = destination.parent
    _ensure_private_parent(parent)
    stage = parent / f"{_STAGE_PREFIX}{request.removeprefix('req_')}"
    rollback = parent / _ROLLBACK_NAME
    if stage.exists() or stage.is_symlink() or rollback.exists() or rollback.is_symlink():
        raise _error(PluginArtifactReason.RECOVERY_REQUIRED)
    stage.mkdir(mode=0o700)
    members = {**_source_members(artifact), _MARKER_NAME: _marker(artifact)}
    try:
        for relative, data in sorted(members.items(), key=lambda item: item[0].encode("ascii")):
            path = stage / relative
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            _write_file(path, data)
        _fsync_dir(stage)
        moved = destination.exists() or destination.is_symlink()
        if moved:
            os.replace(destination, rollback)
            _fsync_dir(parent)
            # Revalidate the displaced tree after the rename, when nothing can
            # swap it any more: only a marker-valid managed tree may be
            # destroyed. Content created or modified during the authority or
            # host-command window is restored untouched and the mutation is
            # refused (the failure handler below performs the restore).
            if (
                rollback.is_symlink()
                or not rollback.is_dir()
                or not _valid_source_marker(_safe_tree(rollback))[0]
            ):
                raise _error(PluginArtifactReason.DESTINATION_CONFLICT)
        os.replace(stage, destination)
        _fsync_dir(parent)
        if _safe_tree(destination) != members:
            raise OSError("claude_source_bytes_mismatch")
        if moved:
            shutil.rmtree(rollback)
            _fsync_dir(parent)
    except BaseException as exc:
        with contextlib.suppress(OSError):
            if stage.exists():
                shutil.rmtree(stage)
            if rollback.exists() and not destination.exists():
                os.replace(rollback, destination)
                _fsync_dir(parent)
        if isinstance(exc, ClaudeCodeIntegrationError):
            raise
        raise _error(PluginArtifactReason.WRITE_FAILED) from exc
    return tuple(sorted(members, key=str.encode))


def _export_marker(artifact: ClaudeCodePluginArtifact) -> bytes:
    body: dict[str, JsonValue] = {
        "artifact_digest": artifact.artifact_digest,
        "development": artifact.development,
        "format_profile": artifact.plan.format_profile.value,
        "hook_mapping_version": _hook_mapping_version_for_artifact(artifact),
        "managed_files": [
            {"relative_path": path, "sha256": _sha(data), "size": len(data)}
            for path, data in sorted(
                artifact.members.items(), key=lambda item: item[0].encode("ascii")
            )
        ],
        "mcp_ownership": artifact.plan.mcp_ownership.value,
        "mcp_route_profile": artifact.plan.mcp_route_profile,
        "renderer_version": artifact.plan.renderer_version,
        "schema": _EXPORT_MARKER_SCHEMA,
        # Frozen legacy identifier (ADR-048): marker keys every release reads by name.
        "yoetz_launcher": list(artifact.finishup_launcher),
        "yoetz_version": artifact.plan.version,
    }
    return canonical_encode({**body, "marker_digest": canonical_digest(body)})


def export_claude_code_plugin(
    artifact: ClaudeCodePluginArtifact, output_root: Path
) -> tuple[str, ...]:
    """Write the exact plugin root for a ``claude --plugin-dir`` session; no host state moves.

    This is the supported development/test activation path: it writes only into the caller's
    chosen, not-yet-existing directory (owner-only, no symlinks, safe ancestors), touches no
    Claude settings, marketplace, or cache, and consumes no review authority. The written tree
    carries an export marker naming its digest, launcher, and development flag, so a later
    status/proof reader can never mistake it for the marketplace-installed delivery cell.
    """

    destination = Path(os.fspath(output_root)).expanduser().absolute()
    if destination.exists() or destination.is_symlink():
        raise _error(PluginArtifactReason.DESTINATION_CONFLICT)
    _ensure_private_parent(destination.parent)
    members = {**dict(artifact.members), _EXPORT_MARKER_NAME: _export_marker(artifact)}
    try:
        destination.mkdir(mode=0o700)
        for relative, data in sorted(members.items(), key=lambda item: item[0].encode("ascii")):
            path = destination / relative
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            _write_file(path, data)
        _fsync_dir(destination)
        if _safe_tree(destination) != members:
            raise OSError("claude_export_bytes_mismatch")
    except BaseException as exc:
        with contextlib.suppress(OSError):
            shutil.rmtree(destination)
        if isinstance(exc, ClaudeCodeIntegrationError):
            raise
        raise _error(PluginArtifactReason.WRITE_FAILED) from exc
    return tuple(sorted(members, key=str.encode))


class _DenyStandaloneClaudeReview:
    def consume_setup_authority(self, _authority: ArtifactAuthority, _preview_digest: str) -> None:
        raise _error(PluginArtifactReason.HUMAN_AUTHORITY_UNAVAILABLE)

    def consume_artifact_review(self, _authority: ArtifactAuthority, _preview_digest: str) -> None:
        raise _error(PluginArtifactReason.HUMAN_AUTHORITY_UNAVAILABLE)


def _consume_authority(
    review: PluginMutationReviewPort | None,
    authority: ArtifactAuthority | None,
    preview_digest: str,
) -> None:
    if authority is None or authority.target_digest != preview_digest:
        raise _error(PluginArtifactReason.AUTHORITY_REQUIRED)
    port = _DenyStandaloneClaudeReview() if review is None else review
    try:
        if authority.channel == "setup_composition":
            port.consume_setup_authority(authority, preview_digest)
        else:
            port.consume_artifact_review(authority, preview_digest)
    except PluginArtifactError as exc:
        # The shared elevated-bootstrap review port raises the neutral artifact error. Keep one
        # error type on the Claude Code surface without inventing a reason the port did not
        # choose, so a cancelled or unavailable presence prompt is reported, not raised through
        # the CLI as a traceback.
        raise _error(exc.reason) from exc


def _run_mutation(
    target: ClaudeCodePluginTarget,
    commands: ClaudeCodeCommandPort,
    arguments: Sequence[str],
) -> bool:
    return commands.run(target, arguments).returncode == 0


def _remove_source(root: Path, expected_digest: str | None = None) -> tuple[str, ...]:
    """Remove one marker-valid marketplace tree; ``expected_digest`` pins the exact bytes."""

    rollback = root.parent / _ROLLBACK_NAME
    if rollback.exists() or rollback.is_symlink():
        raise _error(PluginArtifactReason.RECOVERY_REQUIRED)
    # Claude's marketplace removal may already delete its source directory.
    # Missing source is a successful removal; dangling symlinks still require
    # the ownership checks below.
    if not root.exists() and not root.is_symlink():
        return ()
    try:
        os.replace(root, rollback)
        _fsync_dir(root.parent)
    except OSError as exc:
        raise _error(PluginArtifactReason.WRITE_FAILED) from exc
    try:
        # Revalidate the displaced tree after the rename, when nothing can swap
        # it any more: only a marker-valid managed tree may be deleted. Content
        # created or modified during the authority or host-command window is
        # restored untouched and the removal is refused.
        if rollback.is_symlink() or not rollback.is_dir():
            raise _error(PluginArtifactReason.DESTINATION_CONFLICT)
        displaced = _safe_tree(rollback)
        if not _valid_source_marker(displaced)[0] or (
            expected_digest is not None and _tree_digest(displaced) != expected_digest
        ):
            raise _error(PluginArtifactReason.DESTINATION_CONFLICT)
        files = tuple(sorted(displaced, key=str.encode))
        shutil.rmtree(rollback)
        _fsync_dir(root.parent)
    except ClaudeCodeIntegrationError:
        with contextlib.suppress(OSError):
            if (rollback.exists() or rollback.is_symlink()) and not root.exists():
                os.replace(rollback, root)
                _fsync_dir(root.parent)
        raise
    except OSError as exc:
        raise _error(PluginArtifactReason.WRITE_FAILED) from exc
    return files


def _drop_legacy_declaration(
    target: ClaudeCodePluginTarget, declaration: tuple[tuple[str, str], ...]
) -> bool:
    """Drop this project's legacy declaration entries from its ``.claude/settings.json``.

    Only the entries the preview bound are removed, and only while each still holds the bound
    value; an entry already gone (Claude's project-scoped uninstall drops ``enabledPlugins``) is
    not an error. Every other key keeps its value and position. The file is re-read immediately
    before an atomic replacement and left alone if it changed; this narrows, but cannot close,
    the window against a non-cooperating writer.
    """

    path = Path(target.project_root) / ".claude" / "settings.json"
    bound = dict(declaration)
    try:
        if path.parent.is_symlink() or path.is_symlink():
            return False
        if not path.exists():
            return True
        facts = path.stat()
        if not path.is_file() or facts.st_size > _MAX_FILE_BYTES:
            return False
        raw = path.read_bytes()
        parsed = strict_json_parse(raw)
    except OSError, ProtocolValueError, UnicodeError:
        return False
    if not isinstance(parsed, Mapping):
        return False
    document = dict(cast(Mapping[str, JsonValue], parsed))
    changed = False
    for container_key, key in _LEGACY_DECLARATION:
        container = document.get(container_key)
        if container is None:
            continue
        if not isinstance(container, Mapping):
            return False
        entries = cast(Mapping[str, JsonValue], container)
        if key not in entries:
            continue
        if canonical_digest(entries[key]) != bound.get(container_key):
            # Not the entry the owner approved removing: leave the file untouched.
            return False
        remaining = {name: value for name, value in entries.items() if name != key}
        if remaining:
            document[container_key] = remaining
        else:
            del document[container_key]
        changed = True
    if not changed:
        return True
    replacement = (json.dumps(document, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    temporary = path.parent / f"{_SETTINGS_STAGE_PREFIX}{os.urandom(8).hex()}"
    try:
        _write_file(temporary, replacement)
        os.chmod(temporary, facts.st_mode & 0o777)
        if path.is_symlink() or path.read_bytes() != raw:
            return False
        os.replace(temporary, path)
        _fsync_dir(path.parent)
    except OSError:
        return False
    finally:
        with contextlib.suppress(OSError):
            temporary.unlink(missing_ok=True)
    return True


def _remove_legacy(
    target: ClaudeCodePluginTarget,
    legacy: _LegacyMarketplace,
    commands: ClaudeCodeCommandPort,
) -> bool:
    """Retire this project's legacy install: its plugin and its own declaration (ADR-048).

    Each step runs only for what the preview observed. Claude's unscoped ``plugin marketplace
    remove`` would also delete the shared tree, Claude's user-level registration, and every other
    project's ``yoetz@yoetz-local`` install, so it is never run for a tree beside the managed root:
    that tree and registration stay for the projects still loading them. Only an owner-named
    in-place update, whose directory the renamed tree replaces anyway and which the preview
    refuses while Claude lists the legacy plugin elsewhere, unregisters it first.
    """

    ok = True
    if legacy.discovered:
        ok = _run_mutation(
            target,
            commands,
            ("plugin", "uninstall", _LEGACY_PLUGIN_ID, "--scope", "project", "--keep-data"),
        )
    if ok and _unregisters_legacy_marketplace(target, legacy):
        ok = _run_mutation(
            target, commands, ("plugin", "marketplace", "remove", _LEGACY_MARKETPLACE_NAME)
        )
    if ok and legacy.declaration:
        ok = _drop_legacy_declaration(target, legacy.declaration)
    return ok


def apply_claude_code_plugin(
    request: RequestId,
    target: ClaudeCodePluginTarget,
    action: ClaudeCodePluginAction,
    artifact: ClaudeCodePluginArtifact,
    *,
    accepted_preview_digest: str,
    authority: ArtifactAuthority | None,
    review: PluginMutationReviewPort | None = None,
    commands: ClaudeCodeCommandPort | None = None,
) -> ClaudeCodePluginResult:
    """Apply one exact Claude lifecycle mutation and reconcile by read-back."""

    _validate_digest(accepted_preview_digest)
    command_port = SubprocessClaudeCodeCommands() if commands is None else commands
    preview, status_before, legacy = _preview_with_legacy(
        request, target, action, artifact, commands=command_port
    )
    if preview.preview_digest != accepted_preview_digest:
        raise _error(PluginArtifactReason.PREVIEW_STALE)
    if preview.action is ClaudeCodePluginAction.NOOP:
        unchanged = status_claude_code_plugin(target, artifact, commands=command_port)
        return ClaudeCodePluginResult(
            preview.request_id,
            preview.action,
            PluginOperationState.COMPLETED,
            preview.state_before,
            preview.state_before,
            preview.preview_digest,
            preview.artifact_digest,
            unchanged.installed_digest,
            unchanged.enabled,
            (),
        )
    _consume_authority(review, authority, accepted_preview_digest)
    changed: tuple[str, ...] = ()
    command_ok = True
    migrate = legacy.state == "owned" and action not in {
        ClaudeCodePluginAction.ENABLE,
        ClaudeCodePluginAction.DISABLE,
    }
    if migrate:
        # Retire this project's legacy plugin and registration first, before any renamed source
        # is written over a legacy tree at the managed root itself (ADR-048).
        command_ok = _remove_legacy(target, legacy, command_port)
    if not command_ok:
        # A failed legacy step stops here; read-back below reports the unknown outcome and the
        # remaining legacy state stays visible for a fresh preview.
        pass
    elif action is ClaudeCodePluginAction.CONNECT or (
        action is ClaudeCodePluginAction.UPDATE and migrate and not status_before.discovered
    ):
        # One reviewed operation covers source, marketplace, installation and enablement.
        # Read-back determines the remaining stages after an interrupted connection.
        before = status_claude_code_plugin(target, artifact, commands=command_port)
        # A legacy tree at the managed root itself always gives way to the renamed layout.
        in_place = migrate and legacy.root == Path(target.marketplace_root)
        if before.source_digest != artifact.artifact_digest or in_place:
            changed = (*changed, *_write_source(target, artifact, preview.request_id))
        if before.marketplace_registered is not True:
            command_ok = _run_mutation(
                target,
                command_port,
                ("plugin", "marketplace", "add", "--scope", "project", target.marketplace_root),
            )
        if command_ok and before.installed_digest != artifact.artifact_digest:
            command_ok = _run_mutation(
                target,
                command_port,
                (
                    "plugin",
                    "update" if before.discovered else "install",
                    _PLUGIN_ID,
                    "--scope",
                    "project",
                ),
            )
        # Updating a legacy-only install keeps its enablement; connect always enables.
        wants_enabled = action is ClaudeCodePluginAction.CONNECT or legacy.enabled is True
        if command_ok and wants_enabled and before.enabled is not True:
            command_ok = _run_mutation(
                target, command_port, ("plugin", "enable", _PLUGIN_ID, "--scope", "project")
            )
    elif action is ClaudeCodePluginAction.INSTALL:
        changed = (*changed, *_write_source(target, artifact, preview.request_id))
        command_ok = _run_mutation(
            target,
            command_port,
            ("plugin", "marketplace", "add", "--scope", "project", target.marketplace_root),
        )
        if command_ok:
            command_ok = _run_mutation(
                target,
                command_port,
                ("plugin", "install", _PLUGIN_ID, "--scope", "project"),
            )
    elif action is ClaudeCodePluginAction.UPDATE:
        changed = (*changed, *_write_source(target, artifact, preview.request_id))
        command_ok = _run_mutation(
            target, command_port, ("plugin", "marketplace", "update", _MARKETPLACE_NAME)
        )
        if command_ok:
            command_ok = _run_mutation(
                target,
                command_port,
                ("plugin", "update", _PLUGIN_ID, "--scope", "project"),
            )
    elif action is ClaudeCodePluginAction.ENABLE:
        command_ok = _run_mutation(
            target, command_port, ("plugin", "enable", _PLUGIN_ID, "--scope", "project")
        )
    elif action is ClaudeCodePluginAction.DISABLE:
        command_ok = _run_mutation(
            target, command_port, ("plugin", "disable", _PLUGIN_ID, "--scope", "project")
        )
    elif action is ClaudeCodePluginAction.REMOVE and (
        # A legacy-only removal has no renamed plugin to uninstall (ADR-048).
        status_before.state is not PluginArtifactState.ABSENT
    ):
        if not migrate or status_before.discovered:
            command_ok = _run_mutation(
                target,
                command_port,
                ("plugin", "uninstall", _PLUGIN_ID, "--scope", "project", "--keep-data"),
            )
        if command_ok and (not migrate or status_before.marketplace_registered is not False):
            command_ok = _run_mutation(
                target,
                command_port,
                ("plugin", "marketplace", "remove", _MARKETPLACE_NAME),
            )
        if command_ok:
            changed = (*changed, *_remove_source(Path(target.marketplace_root)))
    after, legacy_after = _status_with_legacy(target, artifact, commands=command_port)
    changed = tuple(sorted(set(changed), key=str.encode))
    reached = (
        after.state is PluginArtifactState.NATIVE_MANAGED
        and after.installed_digest == artifact.artifact_digest
        and after.enabled is True
        if action is ClaudeCodePluginAction.CONNECT
        else after.state is PluginArtifactState.NATIVE_MANAGED
        and after.installed_digest == artifact.artifact_digest
        and after.enabled is False
        if action is ClaudeCodePluginAction.INSTALL
        else after.state is PluginArtifactState.NATIVE_MANAGED
        and after.installed_digest == artifact.artifact_digest
        if action is ClaudeCodePluginAction.UPDATE
        else after.enabled is True
        if action is ClaudeCodePluginAction.ENABLE
        else after.enabled is False
        if action is ClaudeCodePluginAction.DISABLE
        else after.state is PluginArtifactState.ABSENT
    ) and (not migrate or legacy_after.state == "absent")
    # Every branch above has already crossed a mutation boundary (source write,
    # host command, or removal). REFUSED describes a safe pre-mutation
    # rejection only, so any unreached post-mutation state is OUTCOME_UNKNOWN
    # regardless of the subprocess exit code.
    operation = PluginOperationState.COMPLETED if reached else PluginOperationState.OUTCOME_UNKNOWN
    return ClaudeCodePluginResult(
        preview.request_id,
        action,
        operation,
        preview.state_before,
        after.state,
        preview.preview_digest,
        preview.artifact_digest,
        after.installed_digest,
        after.enabled,
        changed,
    )


# Activation cues (issue #789). A Claude Code session receives FinishUP's "call `start` first" cue
# through two channels: the MCP initialize instructions (any registration) and the plugin's
# SessionStart hook (plugin-managed registrations only). A bare `finishup mcp serve` entry the owner
# wrote into Claude's own MCP configuration carries no hook, so it has no SessionStart cue; this
# observation names that fact instead of leaving the owner to infer it from a session transcript.
type ClaudeCodeMcpMode = Literal[
    "plugin_managed", "bare_mcp", "dual", "absent", "foreign", "ambiguous"
]
type ClaudeCodeSessionStartCue = Literal["installed", "absent", "unobserved"]

_MCP_MODE_BY_OWNERSHIP: Final[Mapping[McpOwnershipState, ClaudeCodeMcpMode]] = {
    McpOwnershipState.PLUGIN: "plugin_managed",
    McpOwnershipState.EXTERNAL: "bare_mcp",
    McpOwnershipState.DUAL: "dual",
    McpOwnershipState.ABSENT: "absent",
    McpOwnershipState.FOREIGN: "foreign",
    McpOwnershipState.AMBIGUOUS: "ambiguous",
}
# The rendered hook command (`_hooks_json`) and any owner-written settings hook that reaches the
# same ingress both name this subcommand; matching on it keeps the cue check free of launcher
# path comparisons.
_SESSION_START_CUE_COMMAND: Final = "hooks claude-observe"
_ACTIVATION_CUE_NOTES: Final = (
    "cue_presence_does_not_prove_hook_ran",
    "file_observation_only",
    "plugin_hooks_require_enabled_plugin",
)


@dataclass(frozen=True, slots=True)
class ClaudeCodeActivationCues:
    """Which activation cues one Claude Code installation carries for one project.

    Derived from file observation only. ``mcp_mode`` says which registration Claude would launch:
    the plugin-owned ``.mcp.json`` (``plugin_managed``), a bare ``mcp serve`` entry the owner wrote
    (``bare_mcp``), both (``dual``), none, a non-FinishUP entry (``foreign``), or an unreadable source
    (``ambiguous``). ``host_profile`` says whether the winning route explicitly requests Claude's
    compact initialize body or remains a legacy generic route. ``session_start_cue`` says whether
    any installed hook file can deliver the session-start context. Neither establishes that Claude
    loaded the plugin, that a hook ran, or that the agent called ``start``; plugin hooks
    additionally need the plugin enabled, which ``status_claude_code_plugin`` reports separately.
    """

    mcp_mode: ClaudeCodeMcpMode
    mcp_source: ClaudeCodeMcpSource | None
    route_profile: Literal["strict", "policy"] | None
    session_start_cue: ClaudeCodeSessionStartCue
    cue_sources: tuple[str, ...]
    host_profile: Literal["generic", "claude"] | None = None

    def as_json(self) -> dict[str, JsonValue]:
        return {
            "cue_sources": list(self.cue_sources),
            "mcp_mode": self.mcp_mode,
            "mcp_source": None if self.mcp_source is None else self.mcp_source.value,
            "notes": list(_ACTIVATION_CUE_NOTES),
            "host_profile": self.host_profile,
            "route_profile": self.route_profile,
            "session_start_cue": self.session_start_cue,
        }


def _user_config_file(
    claude_config_root: Path,
    *,
    home: Path | None = None,
    environ: Mapping[str, str] | None = None,
) -> Path:
    """Locate Claude's user configuration file the way Claude Code itself does.

    Claude Code keeps `.claude.json` inside `CLAUDE_CONFIG_DIR` when that variable names the
    config root, and beside the default `~/.claude` directory (`~/.claude.json`) otherwise. Any
    other explicit root reads its own in-root file. This mirrors `host_config_root`, which is
    where `discover_hosts` takes the root from.
    """

    environment = os.environ if environ is None else environ
    configured = environment.get("CLAUDE_CONFIG_DIR")
    root = claude_config_root.expanduser().absolute()
    if configured and Path(configured).expanduser().absolute() == root:
        return claude_config_root / ".claude.json"
    base = Path.home() if home is None else home
    if root == (base / ".claude").expanduser().absolute():
        return base / ".claude.json"
    return claude_config_root / ".claude.json"


def _session_start_cue_present(config: Mapping[str, JsonValue]) -> bool:
    hooks = config.get("hooks")
    if not isinstance(hooks, Mapping):
        return False
    entries = cast(Mapping[str, JsonValue], hooks).get("SessionStart")
    if not isinstance(entries, list):
        return False
    for entry in cast(list[JsonValue], entries):
        if not isinstance(entry, Mapping):
            continue
        inner = cast(Mapping[str, JsonValue], entry).get("hooks")
        if not isinstance(inner, list):
            continue
        for hook in cast(list[JsonValue], inner):
            if not isinstance(hook, Mapping):
                continue
            command = cast(Mapping[str, JsonValue], hook).get("command")
            if isinstance(command, str) and _SESSION_START_CUE_COMMAND in command:
                return True
    return False


def observe_claude_code_activation_cues(
    *,
    project_root: Path,
    claude_config_root: Path,
    marketplace_root: Path | None = None,
    finishup_launcher: tuple[str, ...] | None = None,
    home: Path | None = None,
    environ: Mapping[str, str] | None = None,
) -> ClaudeCodeActivationCues:
    """Observe the activation cues one Claude Code installation carries for ``project_root``.

    ``marketplace_root`` defaults to the managed ``finishup-local`` marketplace under the config
    root, the same location the guided connection renders into; when only the legacy
    ``yoetz-local`` marketplace exists there, its plugin is read instead (ADR-048).
    ``finishup_launcher`` is the exact
    launcher that classifies a launcher-bound external registration as a FinishUP route; without it,
    only a bare ``finishup`` console-script entry is recognized and a launcher-bound entry reads as
    ``foreign``. ``home`` and ``environ`` locate Claude's user configuration file exactly as
    Claude does (`~/.claude.json` beside the default root, in-root under ``CLAUDE_CONFIG_DIR``).
    """

    root = (
        claude_config_root / "plugins" / "marketplaces" / _MARKETPLACE_NAME
        if marketplace_root is None
        else marketplace_root
    )
    plugin_root = root / "plugins" / "finishup"
    known_launchers: tuple[tuple[str, ...], ...] = ()
    legacy_root = root.parent / _LEGACY_MARKETPLACE_NAME
    if marketplace_root is None and not root.exists():
        tree, _digest, legacy_launcher = _legacy_tree(legacy_root)
        if tree == "legacy":
            # An installation not yet migrated still carries its cues in the legacy
            # ``yoetz-local`` marketplace (ADR-048).
            plugin_root = legacy_root / "plugins" / _LEGACY_PLUGIN_NAME
            known_launchers = () if legacy_launcher is None else (legacy_launcher,)
    mcp = observe_claude_code_mcp(
        plugin_root=plugin_root,
        project_root=project_root,
        claude_config_root=claude_config_root,
        finishup_launcher=finishup_launcher,
        claude_json=_user_config_file(claude_config_root, home=home, environ=environ),
        known_launchers=known_launchers,
    )
    sources: list[str] = []
    unobserved = False
    for name, path in (
        ("plugin_hooks", plugin_root / "hooks" / "hooks.json"),
        ("user_settings", claude_config_root / "settings.json"),
        ("project_settings", project_root / ".claude" / "settings.json"),
        ("project_local_settings", project_root / ".claude" / "settings.local.json"),
    ):
        config, observed = _json_file(path)
        if not observed:
            unobserved = True
        elif config is not None and _session_start_cue_present(config):
            sources.append(name)
    cue: ClaudeCodeSessionStartCue = (
        "installed" if sources else "unobserved" if unobserved else "absent"
    )
    return ClaudeCodeActivationCues(
        _MCP_MODE_BY_OWNERSHIP[mcp.ownership_state],
        mcp.winning_source,
        mcp.route_profile,
        cue,
        tuple(sources),
        mcp.host_profile,
    )
