"""Explicit Claude Code project-plugin lifecycle commands."""

from __future__ import annotations

import shlex
import sys
from pathlib import Path
from typing import Final, Literal, cast

from finishup.adapters.integrations.artifact_presence import (
    describe_artifact_presence,
    select_artifact_user_presence,
)
from finishup.adapters.integrations.claude_code_integration import (
    ClaudeCodeIntegrationError,
    ClaudeCodePluginAction,
    ClaudeCodePluginArtifact,
    ClaudeCodePluginStatus,
    ClaudeCodePluginTarget,
    apply_claude_code_plugin,
    discover_claude_code,
    export_claude_code_plugin,
    installed_claude_startup_mode,
    preview_claude_code_plugin,
    render_claude_code_plugin,
    status_claude_code_plugin,
)
from finishup.adapters.integrations.launcher import invoking_launcher
from finishup.adapters.integrations.portable_plugin import (
    ArtifactUserPresencePort,
    ElevatedPortableArtifactReview,
)
from finishup.cli.host_admission import admission_cleanup_preview, reverse_sweep
from finishup.domain.values import RequestId, request_id
from finishup.ports.plugin_artifacts import (
    ArtifactAuthority,
    McpOwnership,
    PluginMutationReviewPort,
    PluginOperationState,
)
from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.protocol.ids import IdKind, new_id

__all__ = [
    "plugin_artifact",
    "run_claude_code_plugin_command",
    "run_claude_code_plugin_export",
]


def _artifact_authority(
    accepted_preview_digest: str, *, state: Path | None
) -> ArtifactAuthority | None:
    from finishup.service.elevated_bootstrap import ElevatedBootstrapError, load_pending

    try:
        pending = load_pending(_state=state)
    except ElevatedBootstrapError:
        return None
    if (
        pending is None
        or pending.operation != "plugin_artifact_apply"
        or pending.target_digest != accepted_preview_digest
    ):
        return None
    return ArtifactAuthority("review_only", accepted_preview_digest, pending.pending_id)


def _emit(value: dict[str, object], *, json_output: bool) -> None:
    if json_output:
        sys.stdout.buffer.write(canonical_encode(cast(JsonValue, value)) + b"\n")
        return
    for key, item in value.items():
        rendered = (
            canonical_encode(cast(JsonValue, item)).decode("utf-8")
            if isinstance(item, (dict, list, tuple))
            else str(item)
        )
        sys.stdout.write(f"{key}: {rendered}\n")


def _request(value: str | None) -> RequestId:
    return request_id(new_id(IdKind.REQUEST) if value is None else value)


def _operation_exit_code(state: PluginOperationState) -> int:
    if state is PluginOperationState.COMPLETED:
        return 0
    if state is PluginOperationState.OUTCOME_UNKNOWN:
        return 4
    return 1


def plugin_artifact(
    ownership_name: str,
    route_name: str | None,
    *,
    development_enabled: bool = False,
    observation_profile: str = "structural",
    startup_mode: str = "optional",
) -> ClaudeCodePluginArtifact:
    ownerships = {
        "external-registration": McpOwnership.EXTERNAL_REGISTRATION,
        "plugin-managed": McpOwnership.PLUGIN_MANAGED,
    }
    try:
        ownership = ownerships[ownership_name]
    except KeyError as exc:
        raise ValueError("claude_code_plugin_option_invalid") from exc
    route: Literal["strict", "policy"] | None
    if route_name is None:
        route = None
    elif route_name in {"strict", "policy"}:
        route = cast(Literal["strict", "policy"], route_name)
    else:
        raise ValueError("claude_code_mcp_route_invalid")
    if startup_mode not in {"optional", "required"}:
        raise ValueError("startup_mode_invalid")
    if observation_profile not in {"structural", "ordinary"}:
        raise ValueError("claude_code_observation_profile_invalid")
    return render_claude_code_plugin(
        mcp_ownership=ownership,
        route_profile=route,
        finishup_launcher=invoking_launcher(),
        development_enabled=development_enabled,
        observation_profile=cast(Literal["structural", "ordinary"], observation_profile),
        startup_mode=cast(Literal["optional", "required"], startup_mode),
    )


def run_claude_code_plugin_export(
    *,
    output_root: Path,
    ownership_name: str,
    route_profile: str | None,
    development_enabled: bool,
    json_output: bool,
    observation_profile: str = "structural",
    startup_mode: str = "optional",
) -> int:
    """Write the exact Claude plugin root for a ``claude --plugin-dir`` session.

    No Claude settings, marketplace, cache, or review authority is involved: the tree lands only
    in the caller's not-yet-existing directory. ``development_enabled`` renders
    ``defaultEnabled:true`` so the directory loads without an install record; that carrier is
    marked as development and is refused by every marketplace lifecycle command.
    """

    try:
        artifact = plugin_artifact(
            ownership_name,
            route_profile,
            development_enabled=development_enabled,
            observation_profile=observation_profile,
            startup_mode=startup_mode,
        )
        written = export_claude_code_plugin(artifact, output_root)
        _emit(
            {
                "artifact_digest": artifact.artifact_digest,
                "default_enabled": development_enabled,
                "development": artifact.development,
                "files": list(written),
                "startup_mode": startup_mode,
                "observation_profile": artifact.plan.host_extension_profile,
                "mcp_ownership": artifact.plan.mcp_ownership.value,
                "mcp_route_profile": artifact.plan.mcp_route_profile,
                "next_step": (
                    f"claude --plugin-dir {shlex.quote(str(output_root))}"
                    if development_enabled
                    else "install through the private marketplace lane; a disabled carrier "
                    "does not load under --plugin-dir"
                ),
                "output_root": str(output_root),
                "proof": "development_export_not_marketplace_activation",
                # Frozen legacy identifier (ADR-048): a released output key scripts read.
                "yoetz_launcher": list(artifact.finishup_launcher),
            },
            json_output=json_output,
        )
        return 0
    except (ClaudeCodeIntegrationError, ValueError, OSError) as error:
        reason = error.reason.value if isinstance(error, ClaudeCodeIntegrationError) else str(error)
        sys.stderr.write(f"{reason}\n")
        return 1


def _status_body(status: ClaudeCodePluginStatus) -> dict[str, object]:
    return {
        "artifact_digest": status.artifact_digest,
        "discovered": status.discovered,
        "enabled": status.enabled,
        "installed_digest": status.installed_digest,
        "installed_version": status.installed_version,
        "host_state_digest": status.host_state_digest,
        "loaded_root_digest": status.loaded_root_digest,
        "host_version_provenance": status.version_provenance,
        # What the legacy ``yoetz-local`` marketplace holds for this project (ADR-048).
        "legacy_installation": status.legacy_installation,
        "marketplace_digest": status.marketplace_digest,
        "marketplace_registered": status.marketplace_registered,
        "marker_valid": status.marker_valid,
        "mcp": {
            "host_admission_supported": status.mcp_observation.host_admission_supported,
            "legacy_registration": status.mcp_observation.legacy_registration,
            "observed": status.mcp_observation.observed,
            "ownership_state": status.mcp_observation.ownership_state.value,
            "present_sources": [item.value for item in status.mcp_observation.present_sources],
            "route_profile": status.mcp_observation.route_profile,
            "winning_source": (
                None
                if status.mcp_observation.winning_source is None
                else status.mcp_observation.winning_source.value
            ),
        },
        "notes": list(status.notes),
        "operation_state": status.operation_state.value,
        "proof": {item.facet.value: item.status for item in status.proof},
        "scope": "project",
        "state": status.state.value,
    }


# Actions that leave Claude Code launching this runtime; disable, remove and status never ask.
_CONNECT_ACTIONS: Final = frozenset(
    action.value
    for action in (
        ClaudeCodePluginAction.CONNECT,
        ClaudeCodePluginAction.INSTALL,
        ClaudeCodePluginAction.UPDATE,
        ClaudeCodePluginAction.ENABLE,
    )
)


def _connect_refused() -> int | None:
    """``<token>: <next step>`` and exit 20 when this runtime cannot serve the running account."""

    from finishup.cli.runtime_refusal import connect_refusal

    refusal = connect_refusal()
    if refusal is None:
        return None
    sys.stderr.write(f"{refusal[0]}: {refusal[1]}\n")
    return 20


def run_claude_code_plugin_command(
    command: str,
    *,
    harness: str,
    claude_path: Path,
    claude_config_root: Path,
    cache_root: Path,
    marketplace_root: Path,
    project_root: Path,
    format_name: str,
    ownership_name: str,
    route_profile: str | None,
    requested_action: str | None,
    request_value: str | None,
    preview_digest: str | None,
    accept: bool,
    json_output: bool,
    observation_profile: str = "structural",
    startup_mode: str | None = None,
    _state: Path | None = None,
    _presence: ArtifactUserPresencePort | None = None,
) -> int:
    """Run one explicit Claude Code CLI/local/project marketplace operation."""

    if (
        harness != "claude"
        or format_name != "native"
        or command
        not in {
            "preview",
            "install",
            "update",
            "enable",
            "disable",
            "status",
            "remove",
        }
    ):
        sys.stderr.write("claude_code_plugin_command_invalid\n")
        return 2
    requested = (requested_action if command == "preview" else command) or "install"
    if command != "status" and requested in _CONNECT_ACTIONS:
        refused = _connect_refused()
        if refused is not None:
            return refused
    try:
        executable = claude_path.expanduser().resolve(strict=True)
        identity = discover_claude_code(executable)
        target = ClaudeCodePluginTarget(
            str(project_root.expanduser().absolute()),
            str(claude_config_root.expanduser().absolute()),
            str(cache_root.expanduser().absolute()),
            str(marketplace_root.expanduser().absolute()),
            str(executable),
            identity,
        )
        installed_mode = installed_claude_startup_mode(target)
        startup_mode = startup_mode or installed_mode or "optional"
        artifact = plugin_artifact(
            ownership_name,
            route_profile,
            observation_profile=observation_profile,
            startup_mode=startup_mode,
        )
        status = status_claude_code_plugin(target, artifact)
        if command == "status":
            _emit(
                {
                    **_status_body(status),
                    "startup_mode": startup_mode,
                    "installed_startup_mode": installed_mode
                    if status.installed_digest is not None
                    else None,
                    "requested_observation_profile": artifact.plan.host_extension_profile,
                    "installed_observation_profile": (
                        artifact.plan.host_extension_profile
                        if status.marker_valid
                        and status.installed_digest == artifact.artifact_digest
                        else None
                    ),
                },
                json_output=json_output,
            )
            return 0
        action_name = requested_action if command == "preview" else command
        if action_name is None:
            action_name = "install"
        if command != "preview" and requested_action is not None:
            raise ValueError("claude_code_plugin_action_invalid")
        try:
            action = ClaudeCodePluginAction(action_name)
        except ValueError as exc:
            raise ValueError("claude_code_plugin_action_invalid") from exc
        request = _request(request_value)
        preview = preview_claude_code_plugin(request, target, action, artifact)
        # A host uninstall and a re-render onto the strict route are reverse transitions for
        # the project's host-admission entry (issue #467): the sweep is disclosed in the
        # preview and reported in the result, and removes only the exact entry FinishUP wrote.
        reverse_admission = action is ClaudeCodePluginAction.REMOVE or (
            action in {ClaudeCodePluginAction.INSTALL, ClaudeCodePluginAction.UPDATE}
            and artifact.plan.mcp_route_profile == "strict"
        )
        project = Path(target.project_root)
        if command == "preview":
            _emit(
                {
                    "action": preview.action.value,
                    "admission_cleanup": (
                        admission_cleanup_preview("claude", project) if reverse_admission else None
                    ),
                    "artifact_digest": preview.artifact_digest,
                    "startup_mode": startup_mode,
                    "observation_profile": artifact.plan.host_extension_profile,
                    "authorization": {
                        "operation": "plugin_artifact_apply",
                        "prepare_command": [
                            "finishup",
                            "consent",
                            "prepare",
                            "plugin_artifact_apply",
                            "--target-digest",
                            preview.preview_digest,
                        ],
                        "human_presence": describe_artifact_presence(),
                        "requires_os_authenticated_prompt": True,
                    },
                    "host": {
                        "architecture": identity.architecture,
                        "executable_digest": identity.executable_digest,
                        "os": identity.os_name,
                        "version": identity.version,
                        "version_provenance": preview.version_provenance,
                    },
                    "legacy_installation": preview.legacy_installation,
                    "marketplace_digest": preview.marketplace_digest,
                    "marketplace_name": "finishup-local",
                    "mcp_ownership": preview.mcp_ownership.value,
                    "mcp_ownership_state": preview.mcp_ownership_state.value,
                    "mcp_route_profile": preview.mcp_route_profile,
                    "preview_digest": preview.preview_digest,
                    "request_id": preview.request_id,
                    "scope": "project",
                    "state_before": preview.state_before.value,
                    "warnings": list(preview.warnings),
                },
                json_output=json_output,
            )
            return 0
        if not accept or preview_digest is None:
            sys.stderr.write("claude_code_plugin_exact_preview_acceptance_required\n")
            return 3
        review: PluginMutationReviewPort = ElevatedPortableArtifactReview(
            select_artifact_user_presence() if _presence is None else _presence,
            _state=_state,
        )
        result = apply_claude_code_plugin(
            request,
            target,
            action,
            artifact,
            accepted_preview_digest=preview_digest,
            authority=_artifact_authority(preview_digest, state=_state),
            review=review,
        )
        _emit(
            {
                "action": result.action.value,
                "admission_cleanup": (
                    reverse_sweep("claude", project)
                    if reverse_admission
                    and result.operation_state is PluginOperationState.COMPLETED
                    else None
                ),
                "artifact_digest": result.artifact_digest,
                "startup_mode": startup_mode,
                "installed_startup_mode": installed_claude_startup_mode(target)
                if result.installed_digest is not None
                else None,
                "requested_observation_profile": artifact.plan.host_extension_profile,
                "changed_files": list(result.changed_files),
                "enabled": result.enabled,
                "installed_digest": result.installed_digest,
                "operation_state": result.operation_state.value,
                "preview_digest": result.preview_digest,
                "request_id": result.request_id,
                "scope": "project",
                "state_after": result.state_after.value,
                "state_before": result.state_before.value,
            },
            json_output=json_output,
        )
        return _operation_exit_code(result.operation_state)
    except (ClaudeCodeIntegrationError, ValueError, OSError) as error:
        reason = error.reason.value if isinstance(error, ClaudeCodeIntegrationError) else str(error)
        sys.stderr.write(f"{reason}\n")
        return 1
