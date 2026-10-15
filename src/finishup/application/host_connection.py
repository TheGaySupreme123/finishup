"""Shared, exact-plan host connection lifecycle for human and agent setup."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, Literal, cast

from finishup.adapters.integrations import claude_code_integration as claude
from finishup.adapters.integrations import cursor_integration as cursor
from finishup.adapters.integrations import cursor_project_mcp as mcp
from finishup.adapters.integrations.host_admission import (
    HostAdmissionError,
    HostAdmissionHost,
    HostAdmissionState,
    observe_host_admission,
    sweep_host_admission,
)
from finishup.adapters.integrations.host_discovery import HostInstallation
from finishup.adapters.integrations.host_projects import (
    ConnectedProjects,
    HostProjectsError,
    duplicate_of,
    host_config_lock,
    live_projects,
    load_connected_projects,
    same_directory,
    write_connected_projects,
)
from finishup.domain.values import RequestId
from finishup.ports.plugin_artifacts import (
    ArtifactAuthority,
    McpOwnership,
    PluginArtifactAction,
    PluginArtifactState,
    PluginFormatProfile,
    PluginMutationReviewPort,
    PluginOperationState,
)
from finishup.protocol.canonical import JsonValue, canonical_digest

type Route = Literal["strict", "policy"]
type ConnectionAction = Literal["connect", "disconnect"]

_CLAUDE_MARKETPLACE: Final = "finishup-local"
# Legacy installation states that a connection migrates or a disconnect removes (ADR-048).
_OWNED_LEGACY: Final = frozenset({"legacy_only", "duplicate"})


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
                    # Exact pre-rename ``yoetz`` entries the same sweep removes (ADR-048).
                    **(
                        {"legacy_entries": cast(list[JsonValue], list(entry.legacy_entries))}
                        if entry.legacy_entries
                        else {}
                    ),
                }
                for entry in sorted(observation.entries, key=lambda item: item.surface)
            ],
        ),
    }


def admission_cleanup_needed(plan: dict[str, JsonValue]) -> bool:
    """True when at least one surface carries an exact FinishUP entry the sweep removes.

    An exact legacy ``yoetz`` entry counts too, also on an otherwise absent surface: the sweep
    removes it, and a stale project entry must not outlive the registration (ADR-048).
    """

    surfaces = plan.get("surfaces")
    return isinstance(surfaces, list) and any(
        isinstance(item, dict)
        and (
            item.get("state") == HostAdmissionState.PRESENT.value
            or bool(item.get("legacy_entries"))
        )
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
    """Remove exactly the FinishUP-written admission entries for ``host`` under ``project``.

    Runs before any registration removal: a Codex project table that outlives the user-level
    ``mcp_servers.finishup`` transport makes Codex refuse to load configuration in that project.
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


def _refuse_unknown_admission(cleanup: dict[str, JsonValue]) -> None:
    """Stop a disconnect whose admission surfaces FinishUP cannot read or safely edit.

    A symlinked, oversized, or unparsable approval file may still hold an entry the host loads;
    removing the registration under it would leave the project unloadable, and FinishUP must not
    edit through it. Nothing has changed yet when this refuses.
    """

    surfaces = cleanup.get("surfaces")
    unknown = [
        str(item.get("surface"))
        for item in (surfaces if isinstance(surfaces, list) else [])
        if isinstance(item, dict) and item.get("state") == HostAdmissionState.UNKNOWN.value
    ]
    if cleanup.get("state") == HostAdmissionState.UNKNOWN.value or unknown:
        raise ConnectionError(
            "connection_admission_cleanup_failed",
            status={
                "admission_cleanup": cleanup,
                "admission_unreadable_surfaces": cast(list[JsonValue], sorted(unknown)),
            },
        )


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
        _refuse_unknown_admission(cleanup)
        self.disclosure["admission_cleanup"] = cleanup
        needed = admission_cleanup_needed(cleanup)
        if needed:
            cast(list[JsonValue], body["changes"]).append("remove_project_admission")
        return needed

    def apply(self, needed: bool) -> None:
        if self._host is None:
            return
        # Revalidate before anything is removed: a surface that became unreadable or unsafe
        # since preview must stop the disconnect, not be skipped (CHECK_DISCONNECT_R1 P2).
        _refuse_unknown_admission(admission_cleanup_plan(self._host, self._project))
        if needed:
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


class SharedProjectsStep:
    """The other projects that share one host config root's FinishUP pieces (#1058).

    ``observed`` names projects the host itself reports (Claude Code lists every project-scope
    install); otherwise the config root's connected-projects record is the source. Connect
    refuses a second path to an already connected directory and records the project; a
    disconnect keeps the shared pieces while another live project remains.
    """

    def __init__(
        self,
        config_root: Path,
        project: Path,
        action: ConnectionAction,
        *,
        observed: tuple[str, ...] | None = None,
        recorded: bool = True,
        remove_shared: bool = False,
        shared_present: bool = False,
    ) -> None:
        self._project = project
        self._recorded = recorded
        self._snapshot: ConnectedProjects | None = None
        if recorded and config_root.is_dir():
            try:
                self._snapshot = load_connected_projects(config_root)
            except HostProjectsError as error:
                raise ConnectionError("connection_projects_record_invalid") from error
        known = set(observed or ())
        if self._snapshot is not None:
            known.update(self._snapshot.projects)
        # Disconnecting under either path removes the alias entry too; only a second connect
        # through another path to the same directory is refused.
        if action == "connect" and duplicate_of(project, known) is not None:
            raise ConnectionError("project_connected_via_other_path")
        # Projects that keep the shared pieces; an explicit home-wide disconnect keeps none.
        self.affected: tuple[str, ...] = live_projects(known, excluding=project)
        self.remove_shared = remove_shared and action == "disconnect"
        self.others: tuple[str, ...] = () if self.remove_shared else self.affected
        # Shared pieces found without a record (an earlier release, or a lost record) may serve
        # projects no record names; that stays unknown through later connects (#1058 round 2).
        self.unknown_members = recorded and (
            (self._snapshot is not None and self._snapshot.unknown_members)
            or ((self._snapshot is None or self._snapshot.raw is None) and shared_present)
        )
        self.keeps_shared = not self.remove_shared and (bool(self.others) or self.unknown_members)
        self._shared_present = shared_present
        self._config_root = config_root

    def record_change(self, action: ConnectionAction) -> str | None:
        """The plan change naming a record-only update (an earlier release left no entry)."""

        if not self._recorded:
            return None
        listed = self._snapshot is not None and any(
            same_directory(Path(item), self._project) or item == str(self._project)
            for item in self._snapshot.projects
        )
        if action == "connect" and (
            not listed or (self.unknown_members and not self._snapshot_unknown())
        ):
            return "record_connected_project"
        if action == "disconnect" and (
            listed or (self.remove_shared and self._snapshot is not None and self._snapshot.raw)
        ):
            return "forget_connected_project"
        return None

    def _snapshot_unknown(self) -> bool:
        return self._snapshot is not None and self._snapshot.unknown_members

    def disclose(self, disclosure: dict[str, JsonValue]) -> None:
        if self.others:
            disclosure["shared_with"] = cast(list[JsonValue], list(self.others))
        if self.unknown_members:
            disclosure["membership_unknown"] = True
        if self.remove_shared:
            disclosure["remove_shared"] = True
            if self.affected:
                # These projects lose the shared pieces with this home-wide disconnect.
                disclosure["shared_removed_from"] = cast(list[JsonValue], list(self.affected))
        if self._snapshot is not None and self._snapshot.raw is not None:
            disclosure["connected_projects_record"] = canonical_digest(
                {"projects": list(self._snapshot.projects)}
            )

    def record(self, action: ConnectionAction) -> None:
        """Update the record after the host-side steps succeeded."""

        if not self._recorded:
            return
        snapshot = self._snapshot
        if snapshot is None:
            # The reviewed plugin step created the missing config root.
            try:
                snapshot = load_connected_projects(self._config_root)
            except HostProjectsError as error:
                raise ConnectionError("connection_outcome_unknown") from error
        unknown = self.unknown_members and not self.remove_shared
        if action == "connect":
            projects = snapshot.with_project(self._project)
        elif self.remove_shared:
            projects = ()
        else:
            projects = tuple(
                item
                for item in snapshot.without_project(self._project)
                if not same_directory(Path(item), self._project)
            )
        disconnect = action == "disconnect"
        try:
            write_connected_projects(
                snapshot,
                projects,
                unknown_members=unknown,
                departed=(str(self._project),) if disconnect else (),
                # The shared pieces went with this disconnect: nobody here is connected now.
                shared_removed=disconnect and not self.keeps_shared,
            )
        except HostProjectsError as error:
            raise ConnectionError(
                "connection_preview_stale"
                if error.reason == "registry_stale"
                else "connection_outcome_unknown"
            ) from error

    def status(self) -> dict[str, JsonValue]:
        try:
            current = (
                load_connected_projects(self._config_root).projects
                if self._recorded and self._config_root.is_dir()
                else ()
            )
        except HostProjectsError:
            return {}
        if not self._recorded:
            return {}
        return {
            "connected_projects": cast(list[JsonValue], list(current)),
            **({"membership_unknown": True} if self._current_unknown() else {}),
        }

    def _current_unknown(self) -> bool:
        # Before any record exists, shared pieces found without one are already unknown
        # membership (CHECK_MULTIPROJ_R2 P3); status must say so, not only a preview.
        try:
            current = load_connected_projects(self._config_root)
        except HostProjectsError:
            return False
        return current.unknown_members or (current.raw is None and self._shared_present)


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


def _cursor_observed_members(
    shared_status: dict[str, JsonValue],
    config_root: Path,
    selected: mcp.CursorProjectMcpTarget,
    launcher: tuple[str, ...],
    isolation_root: str | None,
    known_launchers: tuple[tuple[str, ...], ...] = (),
) -> dict[str, JsonValue]:
    """Recorded members whose own project MCP entry is still FinishUP's (P3, #1058 round 2).

    A recorded member without it keeps the shared plugin but is not observed connected; its
    reconciliation is ``setup disconnect`` for that project, which forgets it.
    """

    recorded = shared_status.get("connected_projects")
    if not isinstance(recorded, list):
        return {}
    observed: list[JsonValue] = []
    for item in recorded:
        try:
            state: JsonValue = mcp.status_cursor_project_mcp(
                mcp.CursorProjectMcpTarget(Path(str(item)), config_root, selected.project_binding),
                launcher=launcher,
                isolation_root=isolation_root,
                # Marker-recorded launchers keep a member's legacy entry provably ours (ADR-048).
                known_launchers=known_launchers,
            )["state"]
        except mcp.CursorProjectMcpError, OSError, ValueError:
            continue
        # Frozen legacy identifier (ADR-048): ``yoetz_owned`` is a released state value.
        if state == "yoetz_owned":
            observed.append(item)
    return {"connected_projects_observed": observed}


def prepare_connection(
    request: RequestId,
    installation: HostInstallation,
    project: Path,
    *,
    action: ConnectionAction,
    route: Route,
    launcher: tuple[str, ...],
    isolation_root: str | None = None,
    remove_shared: bool = False,
) -> ConnectionPlan:
    """Read all participating preimages before any authorization or mutation.

    ``remove_shared`` (disconnect only) also removes the pieces this config root shares with
    other connected projects; without it a disconnect keeps whatever they still use (#1058).
    """
    body: dict[str, JsonValue] = {
        # Frozen legacy identifier (ADR-048): a released schema tag (host-connection-1.0.0).
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
            str(installation.config_root / "plugins" / "marketplaces" / _CLAUDE_MARKETPLACE),
            str(installation.executable),
            claude.discover_claude_code(installation.executable),
        )
        artifact = claude.render_claude_code_plugin(
            mcp_ownership=McpOwnership.PLUGIN_MANAGED,
            route_profile=route,
            finishup_launcher=launcher,
            startup_mode=claude.installed_claude_startup_mode(target) or "optional",
        )
        before = claude.status_claude_code_plugin(target, artifact)
        # Claude Code lists every project's install, so the host itself names who shares the
        # config root's marketplace source; no FinishUP record is needed (#1058).
        shared = SharedProjectsStep(
            installation.config_root,
            project,
            action,
            observed=claude.claude_code_other_projects(target) or (),
            recorded=False,
            remove_shared=remove_shared,
        )
        operation = (
            claude.ClaudeCodePluginAction.CONNECT
            if action == "connect"
            else claude.ClaudeCodePluginAction.REMOVE
        )
        # An owned legacy ``yoetz-local`` install alone still needs the disconnect (ADR-048).
        legacy_owned = before.legacy_installation in _OWNED_LEGACY
        detached = action == "disconnect" and bool(shared.others) and not before.discovered
        preview = (
            None
            if action == "disconnect"
            and not legacy_owned
            and (before.state is PluginArtifactState.ABSENT or detached)
            else claude.preview_claude_code_plugin(request, target, operation, artifact)
        )
        noop = preview is None or preview.action is claude.ClaudeCodePluginAction.NOOP
        body["plugin_preview_digest"] = None if preview is None else preview.preview_digest
        body["marketplace_root"] = target.marketplace_root
        body["cache_root"] = target.cache_root
        body["state_before"] = before.state.value
        body["enabled_before"] = before.enabled
        changes: list[JsonValue] = []
        if not noop:
            if legacy_owned:
                changes.append(
                    "migrate_legacy_plugin" if action == "connect" else "remove_legacy_plugin"
                )
            if action == "connect":
                changes.extend(("install_plugin", "enable_plugin", "plugin_mcp"))
            elif before.state is not PluginArtifactState.ABSENT:
                if shared.others and not shared.remove_shared:
                    # Other projects keep the shared marketplace source and its plugin MCP.
                    changes.append("uninstall_plugin")
                else:
                    # This project's own install may already be gone (an earlier disconnect
                    # kept the shared pieces for a project since deleted): only they remain.
                    if before.discovered:
                        changes.append("uninstall_plugin")
                    changes.extend(("remove_marketplace", "remove_plugin_mcp"))
        body["changes"] = changes
        shared.disclose(admission.disclosure)
        route_before = (
            claude.installed_claude_route_profile(target)
            if action == "connect" and not noop and shared.others
            else None
        )
        if route_before is not None and route_before != route:
            # The shared source carries the plugin MCP server's review mode for every project's
            # install: re-rendering it changes theirs too (#1058 review P2-3).
            admission.disclosure["route_profile_before"] = route_before
            admission.disclosure["route_changes_for"] = cast(list[JsonValue], list(shared.others))
        sweep_admission = admission.plan(body, "claude", action)

        def status() -> dict[str, JsonValue]:
            observed = claude.status_claude_code_plugin(target, artifact)
            return {
                "installed": observed.installed_digest == artifact.artifact_digest,
                "enabled": observed.enabled,
                "configured": observed.marketplace_registered,
                "state": observed.state.value,
                "legacy_installation": observed.legacy_installation,
                "connection_observed": False,
                "reload_required": action == "connect",
                "connected_projects": cast(
                    list[JsonValue],
                    sorted(
                        {
                            *(claude.claude_code_other_projects(target) or ()),
                            *((str(project),) if observed.discovered else ()),
                        }
                    ),
                ),
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
                remove_shared=shared.remove_shared,
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
            finishup_launcher=launcher,
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
        # The user plugin (hooks, skill) serves every project under this config root; only the
        # project MCP entry is per project. The record names who still needs the plugin (#1058).
        shared = SharedProjectsStep(
            installation.config_root,
            project,
            action,
            remove_shared=remove_shared,
            shared_present=observed.state is not PluginArtifactState.ABSENT,
        )
        cursor_action = (
            PluginArtifactAction.REMOVE
            if action == "disconnect"
            else PluginArtifactAction.INSTALL
            if observed.state is PluginArtifactState.ABSENT
            else PluginArtifactAction.REPLACE
        )
        # An owned legacy ``plugins/local/yoetz`` tree alone still needs the disconnect (ADR-048).
        cursor_legacy_owned = observed.legacy_installation in _OWNED_LEGACY
        cursor_preview = (
            None
            if action == "disconnect"
            and (
                (observed.state is PluginArtifactState.ABSENT and not cursor_legacy_owned)
                # Other projects still use the user plugin; a Yoetz-era user tree is shared the
                # same way and stays with it until the last project leaves (ADR-048, #1058).
                or shared.keeps_shared
            )
            else cursor.preview_cursor_plugin(
                request, cursor_target, cursor_action, cursor_artifact, project_root=project
            )
        )
        mcp_action = "install" if action == "connect" else "remove"
        # Launchers the plugin markers recorded now, before any step can migrate them (ADR-048).
        recorded = mcp.recorded_cursor_launchers(installation.config_root)
        mcp_preview = mcp.preview_cursor_project_mcp(
            project_target,
            action=mcp_action,
            launcher=launcher,
            route_profile=route,
            isolation_root=isolation_root,
            known_launchers=recorded,
        )
        plugin_noop = cursor_preview is None or cursor_preview.action is PluginArtifactAction.NOOP
        changes: list[JsonValue] = []
        if not plugin_noop:
            if cursor_legacy_owned:
                changes.append(
                    "migrate_legacy_plugin" if action == "connect" else "remove_legacy_plugin"
                )
            if action == "connect" or observed.state is not PluginArtifactState.ABSENT:
                changes.append("install_plugin" if action == "connect" else "remove_plugin")
        if mcp_preview["action"] != "noop":
            changes.append("register_project_mcp" if action == "connect" else "remove_project_mcp")
        record_change = shared.record_change(action)
        if record_change is not None:
            changes.append(record_change)
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
        shared.disclose(admission.disclosure)
        sweep_admission = admission.plan(body, "cursor", action)

        def status() -> dict[str, JsonValue]:
            current = cursor.status_cursor_plugin(
                cursor_target, cursor_artifact, project_root=project
            )
            registration = mcp.status_cursor_project_mcp(
                project_target,
                launcher=launcher,
                isolation_root=isolation_root,
                known_launchers=recorded,
            )
            return {
                "installed": current.installed_digest == cursor_artifact.artifact_digest,
                "enabled": None,
                # Frozen legacy identifier (ADR-048): ``yoetz_owned`` is a released state value.
                "configured": registration["state"] == "yoetz_owned",
                "state": current.state.value,
                "legacy_installation": current.legacy_installation,
                "connection_observed": False,
                "reload_required": action == "connect",
                "project_mcp": registration,
                **shared.status(),
                **_cursor_observed_members(
                    shared.status(),
                    installation.config_root,
                    project_target,
                    launcher,
                    isolation_root,
                    recorded,
                ),
                **admission.status(),
            }

        def plugin_step() -> None:
            if plugin_noop or cursor_preview is None:
                return
            result = (
                cursor.apply_cursor_plugin(
                    request,
                    cursor_target,
                    cursor_action,
                    cursor_artifact,
                    accepted_preview_digest=cursor_preview.preview_digest,
                    authority=ArtifactAuthority("setup_composition", cursor_preview.preview_digest),
                    review=_ReviewedStep(cursor_preview.preview_digest),
                    project_root=project,
                )
                if action == "connect"
                else cursor.remove_cursor_plugin(
                    request,
                    cursor_target,
                    cursor_artifact,
                    accepted_preview_digest=cursor_preview.preview_digest,
                    authority=ArtifactAuthority("setup_composition", cursor_preview.preview_digest),
                    review=_ReviewedStep(cursor_preview.preview_digest),
                    project_root=project,
                )
            )
            if result.operation_state is not PluginOperationState.COMPLETED:
                raise ConnectionError("connection_outcome_unknown")

        def mcp_step() -> None:
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
                    known_launchers=recorded,
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
                known_launchers=recorded,
            )

        def apply() -> None:
            admission.apply(sweep_admission)
            # External-registration artifacts do not change any MCP preimage. Removing or
            # installing that plugin first therefore preserves the approved MCP digest; the
            # legacy launchers captured above keep a legacy project entry provably FinishUP's
            # after the plugin step migrates the legacy tree whose marker recorded it (ADR-048).
            plugin_step()
            mcp_step()
            shared.record(action)

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
    """Revalidate the complete plan, consume one review, then run only its exact steps.

    One lock per host configuration root is held from revalidation through the shared changes
    and the connected-projects update, so two setups for one root never both act on the same
    membership (#1058 round 2): the later one finds the earlier one's changes and is stale.
    """
    try:
        lock = host_config_lock(Path(str(plan.body["config_root"])))
        with lock:
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
    except HostProjectsError as error:
        raise ConnectionError(
            "connection_lock_unavailable"
            if error.reason == "lock_unavailable"
            else "connection_outcome_unknown"
        ) from error
