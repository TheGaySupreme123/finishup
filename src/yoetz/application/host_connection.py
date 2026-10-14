"""Shared, exact-plan host connection lifecycle for human and agent setup."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, cast

from yoetz.adapters.integrations import claude_code_integration as claude
from yoetz.adapters.integrations import cursor_integration as cursor
from yoetz.adapters.integrations import cursor_project_mcp as mcp
from yoetz.adapters.integrations.host_admission import (
    HostAdmissionError,
    HostAdmissionHost,
    HostAdmissionState,
    observe_host_admission,
    sweep_host_admission,
)
from yoetz.adapters.integrations.host_discovery import HostInstallation
from yoetz.domain.values import RequestId
from yoetz.ports.plugin_artifacts import (
    ArtifactAuthority,
    McpOwnership,
    PluginArtifactAction,
    PluginArtifactState,
    PluginFormatProfile,
    PluginMutationReviewPort,
    PluginOperationState,
)
from yoetz.protocol.canonical import JsonValue, canonical_digest

type Route = Literal["strict", "policy"]
type ConnectionAction = Literal["connect", "disconnect"]


class ConnectionError(ValueError):
    """Closed setup failure; never include OS error text or host configuration."""

    def __init__(self, reason: str, *, status: dict[str, JsonValue] | None = None) -> None:
        super().__init__(reason)
        self.status = status


class _ReviewedStep:
    """One in-process child capability, minted only after the enclosing review consumed."""

    def __init__(self, digest: str) -> None:
        self._digest: str | None = digest

    def consume_setup_authority(self, authority: ArtifactAuthority, preview_digest: str) -> None:
        if (
            authority.channel != "setup_composition"
            or self._digest != preview_digest
            or authority.target_digest != preview_digest
        ):
            raise ConnectionError("connection_step_authority_invalid")
        self._digest = None

    def consume_artifact_review(self, authority: ArtifactAuthority, preview_digest: str) -> None:
        raise ConnectionError("connection_step_authority_invalid")


def admission_cleanup_plan(host: HostAdmissionHost, project: Path) -> dict[str, JsonValue]:
    """Disclose the project's host-admission entries a disconnect removes (issue #467 reverse).

    The returned body is part of the digest-bound connection plan: it carries each surface's
    observed file digest, so a grant or revoke between preview and apply makes the plan stale.
    """

    try:
        observation = observe_host_admission(host, project)
    except HostAdmissionError as error:
        return {"host": host, "state": "unknown", "reason": error.reason.value, "surfaces": []}
    return {
        "host": host,
        "state": observation.state.value,
        "surfaces": cast(
            list[JsonValue],
            [
                {
                    "surface": entry.surface,
                    "state": entry.state.value,
                    "file_digest": entry.file_digest,
                }
                for entry in sorted(observation.entries, key=lambda item: item.surface)
            ],
        ),
    }


def admission_cleanup_needed(plan: dict[str, JsonValue]) -> bool:
    """True when at least one surface carries an exact Yoetz entry the sweep removes."""

    surfaces = plan.get("surfaces")
    return isinstance(surfaces, list) and any(
        isinstance(item, dict) and item.get("state") == HostAdmissionState.PRESENT.value
        for item in surfaces
    )


def admission_revoke_arguments(host: HostAdmissionHost, project: Path) -> list[str]:
    """The exact manual repair a CLI renders through its pinned continuation."""

    return [
        "integrate",
        host,
        "admission",
        "preview",
        "--project-root",
        str(project),
        "--action",
        "revoke",
    ]


def sweep_project_admission(host: HostAdmissionHost, project: Path) -> dict[str, JsonValue]:
    """Remove exactly the Yoetz-written admission entries for ``host`` under ``project``.

    Runs before any registration removal: a Codex project table that outlives the user-level
    ``mcp_servers.yoetz`` transport makes Codex refuse to load configuration in that project.
    A sweep that cannot finish stops the disconnect before anything else changes.
    """

    (outcome,) = sweep_host_admission(project, (host,))
    report = outcome.as_json()
    if outcome.outcome in {"unknown", "write_failed"}:
        raise ConnectionError(
            "connection_admission_cleanup_failed",
            status={
                "admission_cleanup": report,
                "next_arguments": cast(
                    list[JsonValue], list(admission_revoke_arguments(host, project))
                ),
            },
        )
    return report


def plan_digest(body: dict[str, JsonValue], disclosure: dict[str, JsonValue]) -> str:
    """Digest the plan body plus any disclosure, keeping a disclosure-free digest unchanged."""

    return canonical_digest(body if not disclosure else {**body, "disclosure": disclosure})


class AdmissionCleanupStep:
    """One disconnect's project admission sweep: planned in preview, run first in apply."""

    def __init__(self, project: Path) -> None:
        self._project = project
        self._host: HostAdmissionHost | None = None
        self._report: dict[str, JsonValue] | None = None
        self.disclosure: dict[str, JsonValue] = {}

    def plan(
        self, body: dict[str, JsonValue], host: HostAdmissionHost, action: ConnectionAction
    ) -> bool:
        """Record the cleanup in ``body`` (digest-bound) and say whether apply must sweep."""

        if action != "disconnect":
            return False
        self._host = host
        cleanup = admission_cleanup_plan(host, self._project)
        self.disclosure["admission_cleanup"] = cleanup
        needed = admission_cleanup_needed(cleanup)
        if needed:
            cast(list[JsonValue], body["changes"]).append("remove_project_admission")
        return needed

    def apply(self, needed: bool) -> None:
        if needed and self._host is not None:
            self._report = sweep_project_admission(self._host, self._project)

    def status(self) -> dict[str, JsonValue]:
        if self._host is None:
            return {}
        return {
            "admission_cleanup": (
                self._report
                if self._report is not None
                else admission_cleanup_plan(self._host, self._project)
            )
        }


@dataclass(frozen=True, slots=True)
class ConnectionPlan:
    body: dict[str, JsonValue]
    status: Callable[[], dict[str, JsonValue]]
    _apply: Callable[[], None]
    # Preview facts outside the released `yoetz.host-connection-plan/1` body (for example the
    # project admission cleanup). They are bound into ``preview_digest`` all the same.
    disclosure: dict[str, JsonValue] = field(default_factory=dict[str, JsonValue])

    @property
    def digest(self) -> str:
        return str(self.body["preview_digest"])

    @property
    def unchanged(self) -> bool:
        return self.body["changes"] == []

    def apply_reviewed_steps(self) -> None:
        self._apply()


def prepare_connection(
    request: RequestId,
    installation: HostInstallation,
    project: Path,
    *,
    action: ConnectionAction,
    route: Route,
    launcher: tuple[str, ...],
    isolation_root: str | None = None,
) -> ConnectionPlan:
    """Read all participating preimages before any authorization or mutation."""
    body: dict[str, JsonValue] = {
        "schema": "yoetz.host-connection-plan/1",
        "request_id": request,
        "host": installation.host,
        "host_version": installation.version,
        "executable": str(installation.executable),
        "config_root": str(installation.config_root),
        "project_root": str(project),
        "action": action,
        "route_profile": route,
        "launcher": list(launcher),
        "isolation_root": isolation_root,
        "connection_observed": False,
        "warnings": [
            "fresh_host_session_required",
            "observation_consent_separate",
            "provider_and_disclosure_authority_separate",
        ],
    }
    admission = AdmissionCleanupStep(project)
    if installation.host == "claude":
        target = claude.ClaudeCodePluginTarget(
            str(project),
            str(installation.config_root),
            str(installation.config_root / "plugins" / "cache"),
            str(installation.config_root / "plugins" / "marketplaces" / "yoetz-local"),
            str(installation.executable),
            claude.discover_claude_code(installation.executable),
        )
        artifact = claude.render_claude_code_plugin(
            mcp_ownership=McpOwnership.PLUGIN_MANAGED,
            route_profile=route,
            yoetz_launcher=launcher,
            startup_mode=claude.installed_claude_startup_mode(target) or "optional",
        )
        before = claude.status_claude_code_plugin(target, artifact)
        operation = (
            claude.ClaudeCodePluginAction.CONNECT
            if action == "connect"
            else claude.ClaudeCodePluginAction.REMOVE
        )
        preview = (
            None
            if (action == "disconnect" and before.state is PluginArtifactState.ABSENT)
            else claude.preview_claude_code_plugin(request, target, operation, artifact)
        )
        noop = preview is None or preview.action is claude.ClaudeCodePluginAction.NOOP
        body["plugin_preview_digest"] = None if preview is None else preview.preview_digest
        body["marketplace_root"] = target.marketplace_root
        body["cache_root"] = target.cache_root
        body["state_before"] = before.state.value
        body["enabled_before"] = before.enabled
        body["changes"] = (
            []
            if noop
            else (
                ["install_plugin", "enable_plugin", "plugin_mcp"]
                if action == "connect"
                else ["uninstall_plugin", "remove_marketplace", "remove_plugin_mcp"]
            )
        )
        sweep_admission = admission.plan(body, "claude", action)

        def status() -> dict[str, JsonValue]:
            observed = claude.status_claude_code_plugin(target, artifact)
            return {
                "installed": observed.installed_digest == artifact.artifact_digest,
                "enabled": observed.enabled,
                "configured": observed.marketplace_registered,
                "state": observed.state.value,
                "connection_observed": False,
                "reload_required": action == "connect",
                **admission.status(),
            }

        def apply() -> None:
            admission.apply(sweep_admission)
            if noop or preview is None:
                return
            result = claude.apply_claude_code_plugin(
                request,
                target,
                operation,
                artifact,
                accepted_preview_digest=preview.preview_digest,
                authority=ArtifactAuthority("setup_composition", preview.preview_digest),
                review=_ReviewedStep(preview.preview_digest),
            )
            if result.operation_state is not PluginOperationState.COMPLETED:
                raise ConnectionError("connection_outcome_unknown")

    elif installation.host in {"cursor-ide", "cursor-cli"}:
        config_existed = installation.config_root.exists()
        project_identity = (project.stat().st_dev, project.stat().st_ino)
        cursor_target = cursor.CursorPluginTarget(str(installation.config_root))
        cursor_artifact = cursor.render_cursor_plugin(
            PluginFormatProfile.CURSOR_PLUGIN_NATIVE,
            mcp_ownership=McpOwnership.EXTERNAL_REGISTRATION,
            yoetz_launcher=launcher,
            startup_mode=cursor.installed_cursor_startup_mode(cursor_target) or "optional",
        )
        project_target = mcp.CursorProjectMcpTarget(
            project,
            installation.config_root,
            "registered-project" if installation.host == "cursor-cli" else "mcp-roots",
        )
        observed = cursor.status_cursor_plugin(cursor_target, cursor_artifact, project_root=project)
        if observed.state is PluginArtifactState.MODIFIED:
            raise ConnectionError("connection_modified_plugin")
        cursor_action = (
            PluginArtifactAction.REMOVE
            if action == "disconnect"
            else PluginArtifactAction.INSTALL
            if observed.state is PluginArtifactState.ABSENT
            else PluginArtifactAction.REPLACE
        )
        cursor_preview = (
            None
            if (action == "disconnect" and observed.state is PluginArtifactState.ABSENT)
            else cursor.preview_cursor_plugin(
                request, cursor_target, cursor_action, cursor_artifact, project_root=project
            )
        )
        mcp_action = "install" if action == "connect" else "remove"
        mcp_preview = mcp.preview_cursor_project_mcp(
            project_target,
            action=mcp_action,
            launcher=launcher,
            route_profile=route,
            isolation_root=isolation_root,
        )
        plugin_noop = cursor_preview is None or cursor_preview.action is PluginArtifactAction.NOOP
        changes: list[JsonValue] = []
        if not plugin_noop:
            changes.append("install_plugin" if action == "connect" else "remove_plugin")
        if mcp_preview["action"] != "noop":
            changes.append("register_project_mcp" if action == "connect" else "remove_project_mcp")
        body.update(
            {
                "create_config_root": not config_existed and action == "connect",
                "plugin_preview_digest": None
                if cursor_preview is None
                else cursor_preview.preview_digest,
                "mcp_preview": mcp_preview,
                "changes": changes,
                "state_before": observed.state.value,
                "project_binding": project_target.project_binding,
                "scope": "user_plugin_and_selected_project_mcp",
            }
        )
        sweep_admission = admission.plan(body, "cursor", action)

        def status() -> dict[str, JsonValue]:
            current = cursor.status_cursor_plugin(
                cursor_target, cursor_artifact, project_root=project
            )
            registration = mcp.status_cursor_project_mcp(
                project_target, launcher=launcher, isolation_root=isolation_root
            )
            return {
                "installed": current.installed_digest == cursor_artifact.artifact_digest,
                "enabled": None,
                "configured": registration["state"] == "yoetz_owned",
                "state": current.state.value,
                "connection_observed": False,
                "reload_required": action == "connect",
                "project_mcp": registration,
                **admission.status(),
            }

        def apply() -> None:
            admission.apply(sweep_admission)
            # External-registration artifacts do not change any MCP preimage. Removing or
            # installing that plugin first therefore preserves the approved MCP digest.
            if not plugin_noop and cursor_preview is not None:
                result = (
                    cursor.apply_cursor_plugin(
                        request,
                        cursor_target,
                        cursor_action,
                        cursor_artifact,
                        accepted_preview_digest=cursor_preview.preview_digest,
                        authority=ArtifactAuthority(
                            "setup_composition", cursor_preview.preview_digest
                        ),
                        review=_ReviewedStep(cursor_preview.preview_digest),
                        project_root=project,
                    )
                    if action == "connect"
                    else cursor.remove_cursor_plugin(
                        request,
                        cursor_target,
                        cursor_artifact,
                        accepted_preview_digest=cursor_preview.preview_digest,
                        authority=ArtifactAuthority(
                            "setup_composition", cursor_preview.preview_digest
                        ),
                        review=_ReviewedStep(cursor_preview.preview_digest),
                        project_root=project,
                    )
                )
                if result.operation_state is not PluginOperationState.COMPLETED:
                    raise ConnectionError("connection_outcome_unknown")
            accepted_mcp = str(mcp_preview["preview_digest"])
            if not config_existed and action == "connect":
                # The reviewed plugin step created its missing private config root. Only
                # that directory identity may differ; all config bytes, the project inode,
                # and the proposed MCP replacement must still match the complete preview.
                current_project = project.stat()
                if (current_project.st_dev, current_project.st_ino) != project_identity:
                    raise ConnectionError("connection_preview_stale")
                refreshed = mcp.preview_cursor_project_mcp(
                    project_target,
                    action=mcp_action,
                    launcher=launcher,
                    route_profile=route,
                    isolation_root=isolation_root,
                )
                omit = {"target_identity", "preview_digest"}
                if {key: value for key, value in refreshed.items() if key not in omit} != {
                    key: value for key, value in mcp_preview.items() if key not in omit
                }:
                    raise ConnectionError("connection_preview_stale")
                accepted_mcp = str(refreshed["preview_digest"])
            mcp.apply_cursor_project_mcp(
                project_target,
                action=mcp_action,
                launcher=launcher,
                route_profile=route,
                isolation_root=isolation_root,
                preview_digest=accepted_mcp,
                accept=True,
            )
    else:
        raise ConnectionError("connection_host_unsupported")
    body["preview_digest"] = plan_digest(body, admission.disclosure)
    return ConnectionPlan(body, status, apply, admission.disclosure)


def apply_connection(
    plan: ConnectionPlan,
    *,
    accepted_digest: str,
    refresh: Callable[[], ConnectionPlan],
    authority: ArtifactAuthority | None,
    review: PluginMutationReviewPort,
) -> dict[str, JsonValue]:
    """Revalidate the complete plan, consume one review, then run only its exact steps."""
    current = refresh()
    if current.digest != plan.digest or current.digest != accepted_digest:
        raise ConnectionError("connection_preview_stale")
    if not current.unchanged:
        if current.body.get("requires_os_presence") is not False:
            if authority is None or authority.target_digest != current.digest:
                raise ConnectionError("connection_authority_required")
            review.consume_artifact_review(authority, current.digest)
        current.apply_reviewed_steps()
    return current.status()
