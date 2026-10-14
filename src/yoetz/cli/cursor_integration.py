"""Explicit local Cursor plugin lifecycle commands."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Final, Literal, cast

from yoetz.adapters.integrations.artifact_presence import (
    describe_artifact_presence,
    select_artifact_user_presence,
)
from yoetz.adapters.integrations.cursor_integration import (
    CursorIntegrationError,
    CursorPluginArtifact,
    CursorPluginStatus,
    CursorPluginTarget,
    apply_cursor_plugin,
    installed_cursor_startup_mode,
    preview_cursor_plugin,
    remove_cursor_plugin,
    render_cursor_plugin,
    status_cursor_plugin,
)
from yoetz.adapters.integrations.launcher import invoking_launcher
from yoetz.adapters.integrations.portable_plugin import (
    ArtifactUserPresencePort,
    ElevatedPortableArtifactReview,
)
from yoetz.cli.host_admission import admission_cleanup_preview, reverse_sweep
from yoetz.config.paths import PathSafetyError
from yoetz.domain.values import RequestId, request_id
from yoetz.ports.plugin_artifacts import (
    ArtifactAuthority,
    McpOwnership,
    PluginArtifactAction,
    PluginFormatProfile,
    PluginMutationReviewPort,
    PluginOperationState,
)
from yoetz.protocol.canonical import JsonValue, canonical_encode
from yoetz.protocol.ids import IdKind, new_id

__all__ = ["CURSOR_PLUGIN_COMMANDS", "plugin_artifact", "run_cursor_plugin_command"]

# Cursor's portable artifact has no update/enable/disable states and no
# development export carrier (issue #465).
CURSOR_PLUGIN_COMMANDS: Final = ("preview", "install", "status", "remove")
_UNSUPPORTED_GENERIC_COMMANDS: Final = frozenset({"update", "enable", "disable", "export"})


def _artifact_authority(
    accepted_preview_digest: str, *, state: Path | None
) -> ArtifactAuthority | None:
    """Bind the exact ``plugin_artifact_apply`` pending review to the accepted preview digest.

    Returning ``None`` when no matching pending exists keeps the refusal inside the adapter,
    which reconciles an already-committed replay before it asks for authority at all.
    """

    from yoetz.service.elevated_bootstrap import ElevatedBootstrapError, load_pending

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


def plugin_artifact(
    format_name: str,
    ownership_name: str,
    route_name: str | None,
    *,
    observation_profile: str = "structural",
    startup_mode: str = "optional",
) -> CursorPluginArtifact:
    formats = {
        "native": PluginFormatProfile.CURSOR_PLUGIN_NATIVE,
        "portable": PluginFormatProfile.AGENT_PLUGINS_1,
    }
    ownerships = {
        "external-registration": McpOwnership.EXTERNAL_REGISTRATION,
        "plugin-managed": McpOwnership.PLUGIN_MANAGED,
    }
    try:
        format_profile = formats[format_name]
        ownership = ownerships[ownership_name]
    except KeyError as exc:
        raise ValueError("cursor_plugin_option_invalid") from exc
    route: Literal["strict", "policy"] | None
    if route_name is None:
        route = None
    elif route_name in {"strict", "policy"}:
        route = cast(Literal["strict", "policy"], route_name)
    else:
        raise ValueError("cursor_mcp_route_invalid")
    if (ownership is McpOwnership.PLUGIN_MANAGED) != (route is not None):
        raise ValueError(
            "cursor_mcp_route_required"
            if ownership is McpOwnership.PLUGIN_MANAGED
            else "cursor_mcp_route_forbidden"
        )
    if startup_mode not in {"optional", "required"}:
        raise ValueError("startup_mode_invalid")
    if observation_profile not in {"structural", "ordinary"}:
        raise ValueError("cursor_observation_profile_invalid")
    if (
        observation_profile == "ordinary"
        and format_profile is not PluginFormatProfile.CURSOR_PLUGIN_NATIVE
    ):
        raise ValueError("cursor_observation_profile_unsupported")
    return render_cursor_plugin(
        format_profile,
        mcp_ownership=ownership,
        route_profile=route,
        yoetz_launcher=_invoking_launcher(),
        observation_profile=cast(Literal["structural", "ordinary"], observation_profile),
        startup_mode=cast(Literal["optional", "required"], startup_mode),
    )


def _invoking_launcher() -> str | tuple[str, ...] | None:
    """Preserve the exact invocation that produced this process (shared launcher helper)."""

    return invoking_launcher()


def _request(value: str | None) -> RequestId:
    return request_id(new_id(IdKind.REQUEST) if value is None else value)


def _status_body(status: CursorPluginStatus) -> dict[str, object]:
    return {
        "artifact_digest": status.artifact_digest,
        "format_profile": None if status.format_profile is None else status.format_profile.value,
        "installed_digest": status.installed_digest,
        "isolation_binding": status.isolation_binding,
        "launcher": {
            "artifact": (
                None
                if status.launcher.artifact_launcher is None
                else list(status.launcher.artifact_launcher)
            ),
            "executable": status.launcher.executable,
            "identity": {
                "control_schema_version": status.launcher.identity.control_schema_version,
                "matched": status.launcher.identity.matched,
                "observed": status.launcher.identity.observed,
                "package_version": status.launcher.identity.package_version,
                "resource_manifest_digest": status.launcher.identity.resource_manifest_digest,
            },
            "installed": (
                None
                if status.launcher.installed_launcher is None
                else list(status.launcher.installed_launcher)
            ),
            "mcp_binding": status.launcher.mcp_binding,
        },
        "marker_valid": status.marker_valid,
        "mcp": {
            "observed": status.mcp_observation.observed,
            "ownership_state": status.mcp_observation.ownership_state.value,
            "present_sources": [item.value for item in status.mcp_observation.present_sources],
            "route_profile": status.mcp_observation.route_profile,
            "runtime": {
                "activation": status.runtime.activation,
                "executable_activation": status.runtime.executable_activation,
                "foreign_process_count": status.runtime.foreign_process_count,
                "live_route_profile": status.runtime.live_route_profile,
                "observed": status.runtime.observed,
                "policy_process_count": status.runtime.policy_process_count,
                "strict_process_count": status.runtime.strict_process_count,
            },
            "winning_source": (
                None
                if status.mcp_observation.winning_source is None
                else status.mcp_observation.winning_source.value
            ),
        },
        "operation_state": status.operation_state.value,
        "proof": {item.facet.value: item.status for item in status.proof},
        "rollback_available": status.rollback_available,
        "scope": "user",
        "state": status.state.value,
    }


def run_cursor_plugin_command(
    command: str,
    *,
    harness: str,
    cursor_config_root: Path,
    project_root: Path | None,
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
    """Run one path-explicit Cursor operation without reading ambient Cursor state."""

    if harness == "cursor" and command in _UNSUPPORTED_GENERIC_COMMANDS:
        sys.stderr.write(
            f"cursor_plugin_command_unsupported:{command} "
            f"supported={','.join(CURSOR_PLUGIN_COMMANDS)}\n"
        )
        return 2
    if harness != "cursor" or command not in CURSOR_PLUGIN_COMMANDS:
        sys.stderr.write("cursor_plugin_command_invalid\n")
        return 2
    if command == "install" or (
        command == "preview" and requested_action != PluginArtifactAction.REMOVE.value
    ):
        from yoetz.cli.runtime_refusal import connect_refusal

        refusal = connect_refusal()
        if refusal is not None:
            # Cursor would launch this runtime for MCP and every hook, and each launch would be
            # refused. Removal, its preview and status never ask.
            sys.stderr.write(f"{refusal[0]}: {refusal[1]}\n")
            return 20
    try:
        target = CursorPluginTarget(str(cursor_config_root.expanduser().absolute()))
        installed_mode = installed_cursor_startup_mode(target)
        startup_mode = startup_mode or installed_mode or "optional"
        artifact = plugin_artifact(
            format_name,
            ownership_name,
            route_profile,
            observation_profile=observation_profile,
            startup_mode=startup_mode,
        )
        project = None if project_root is None else project_root.expanduser().absolute()
        status = status_cursor_plugin(target, artifact, project_root=project)
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

        request = _request(request_value)
        if command == "remove":
            action = PluginArtifactAction.REMOVE
        elif requested_action is None:
            action = (
                PluginArtifactAction.INSTALL
                if status.state.value == "absent"
                else PluginArtifactAction.REPLACE
            )
        else:
            allowed_action_values = {
                PluginArtifactAction.INSTALL.value,
                PluginArtifactAction.REPLACE.value,
                *((PluginArtifactAction.REMOVE.value,) if command == "preview" else ()),
            }
            if requested_action not in allowed_action_values:
                raise ValueError("cursor_plugin_action_invalid")
            action = PluginArtifactAction(requested_action)
        # A removal and an install/replace onto the strict route are reverse transitions for
        # the project's host-admission entry (issue #467); with no explicit project root there
        # is no project file to sweep, and status/drift reporting remains the way to see it.
        reverse_admission = project is not None and (
            action is PluginArtifactAction.REMOVE or artifact.plan.mcp_route_profile == "strict"
        )
        if command == "preview":
            # Only the preview command renders a plan. Computing one here for install/remove
            # would also refuse an already-committed replay before the adapter can reconcile it.
            preview = preview_cursor_plugin(request, target, action, artifact, project_root=project)
            _emit(
                {
                    "action": preview.action.value,
                    "admission_cleanup": (
                        admission_cleanup_preview("cursor", project)
                        if reverse_admission and project is not None
                        else None
                    ),
                    "artifact_digest": preview.artifact_digest,
                    "startup_mode": startup_mode,
                    "observation_profile": artifact.plan.host_extension_profile,
                    "authorization": {
                        "operation": "plugin_artifact_apply",
                        "prepare_command": [
                            "yoetz",
                            "consent",
                            "prepare",
                            "plugin_artifact_apply",
                            "--target-digest",
                            preview.preview_digest,
                        ],
                        "human_presence": describe_artifact_presence(),
                        "requires_os_authenticated_prompt": True,
                    },
                    "format_profile": preview.format_profile.value,
                    "mcp_ownership": preview.mcp_ownership.value,
                    "mcp_ownership_state": preview.mcp_ownership_state.value,
                    "mcp_route_profile": preview.mcp_route_profile,
                    "isolation_root": preview.isolation_root,
                    "preview_digest": preview.preview_digest,
                    "request_id": preview.request_id,
                    "scope": "user",
                    "state_before": preview.state_before.value,
                    "warnings": list(preview.warnings),
                },
                json_output=json_output,
            )
            return 0
        if not accept or preview_digest is None:
            sys.stderr.write("cursor_plugin_exact_preview_acceptance_required\n")
            return 3
        # ``--accept`` only proves the operator typed the exact preview digest. The mutation
        # itself consumes the ADR-016 ``review_only`` single-shot trusted review prepared for
        # this exact digest; the adapter refuses when that authority is absent or unproven.
        review: PluginMutationReviewPort = ElevatedPortableArtifactReview(
            select_artifact_user_presence() if _presence is None else _presence,
            _state=_state,
        )
        authority = _artifact_authority(preview_digest, state=_state)
        result = (
            remove_cursor_plugin(
                request,
                target,
                artifact,
                accepted_preview_digest=preview_digest,
                authority=authority,
                review=review,
                project_root=project,
            )
            if command == "remove"
            else apply_cursor_plugin(
                request,
                target,
                action,
                artifact,
                accepted_preview_digest=preview_digest,
                authority=authority,
                review=review,
                project_root=project,
            )
        )
        _emit(
            {
                "action": result.action.value,
                "admission_cleanup": (
                    reverse_sweep("cursor", project)
                    if reverse_admission
                    and project is not None
                    and result.operation_state is PluginOperationState.COMPLETED
                    else None
                ),
                "artifact_digest": result.artifact_digest,
                "startup_mode": startup_mode,
                "installed_startup_mode": installed_cursor_startup_mode(target)
                if result.installed_digest is not None
                else None,
                "requested_observation_profile": artifact.plan.host_extension_profile,
                "changed_files": list(result.changed_files),
                "format_profile": result.format_profile.value,
                "installed_digest": result.installed_digest,
                "operation_state": result.operation_state.value,
                "preview_digest": result.preview_digest,
                "request_id": result.request_id,
                "scope": "user",
                "state_after": result.state_after.value,
                "state_before": result.state_before.value,
            },
            json_output=json_output,
        )
        return 0
    except PathSafetyError as error:
        sys.stderr.write(f"cursor_isolation_root_invalid:{error.reason_code}\n")
        return 1
    except (CursorIntegrationError, ValueError) as error:
        reason = error.reason.value if isinstance(error, CursorIntegrationError) else str(error)
        sys.stderr.write(f"{reason}\n")
        return 1
