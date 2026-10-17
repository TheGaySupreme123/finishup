"""Adapt the existing Codex setup composition to the common connection report."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import asdict
from pathlib import Path
from typing import Literal, cast

import anyio

from finishup.adapters.integrations.codex_marketplace import (
    ActivationState,
    RemovalOutcome,
    apply_removal,
    connected_projects,
    inspect_activation,
    other_members,
    possible_projects,
    preview_removal,
    serving_projects,
    skill_tree_state,
)
from finishup.adapters.integrations.codex_mcp import (
    CodexMcpAdapter,
    codex_project_mcp_leftovers,
    home_project_candidates,
    legacy_registration_dependents,
    legacy_registration_shaped,
    probe_project_config_load,
    project_config_unreadable_reason,
    project_transport_dependence,
    read_bounded_toml,
)
from finishup.adapters.integrations.codex_skill import CodexSkillIntegration
from finishup.adapters.integrations.host_discovery import HostInstallation
from finishup.adapters.integrations.host_projects import live_projects, same_directory
from finishup.application.harness_mcp import (
    HarnessMcpService,
    McpRegistrationConfirmation,
    mcp_removal_report,
)
from finishup.application.host_connection import (
    AdmissionCleanupStep,
    ConnectionAction,
    ConnectionError,
    ConnectionPlan,
    admission_revoke_arguments,
    plan_digest,
)
from finishup.domain.values import request_id
from finishup.legacy_names import LEGACY_MCP_SERVER_NAME, MCP_SERVER_NAME
from finishup.ports.harness_mcp import (
    HarnessBinary,
    McpRegistrationError,
    McpRegistrationReason,
    McpRegistrationState,
)
from finishup.ports.integrations import (
    HarnessId,
    IntegrationAction,
    IntegrationError,
    IntegrationScope,
    IntegrationState,
    IntegrationTarget,
    SkillApplyCommand,
    SkillPreviewCommand,
)
from finishup.protocol.canonical import JsonValue
from finishup.tui.models import HarnessOption
from finishup.tui.runtime import FinishUpRuntime

# What the legacy ``yoetz`` MCP key holds when FinishUP owns the entry there (ADR-048).
_OWNED_LEGACY_REGISTRATIONS = frozenset({"legacy_only", "duplicate"})
# Yoetz-era project trees an approved connect deletes, keyed by the change token that names them.
# Frozen legacy directory names (ADR-048): Yoetz 0.1-0.2 wrote these exact paths.
_LEGACY_TREE_CHANGES = (
    ((".agents", "plugins", "yoetz"), "remove_legacy_plugin_sources"),
    ((".agents", "skills", "yoetz"), "remove_legacy_project_skill"),
)


def _legacy_tree_changes(project_root: str, managed_paths: tuple[str, ...]) -> list[str]:
    """Name each Yoetz-era tree the plan's bound skill and activation digests delete.

    The integration plan lists those trees among its managed paths exactly when the skill
    preview owns ``.agents/skills/yoetz`` and the activation preview plans deleting
    ``.agents/plugins/yoetz`` (ADR-048).
    """

    root = Path(project_root)
    managed = {Path(path) for path in managed_paths}
    return [change for parts, change in _LEGACY_TREE_CHANGES if root.joinpath(*parts) in managed]


def prepare_codex_connection(
    installation: HostInstallation,
    project: Path,
    *,
    action: ConnectionAction,
    route: Literal["policy", "strict"] | None,
    request_value: str,
    remove_shared: bool = False,
) -> ConnectionPlan:
    """Plan one Codex connect, status, or disconnect for ``project``.

    ``route=None`` means no explicit review mode: the home's registration is user-level and
    every project of the home shares it, so its current mode stays; a fresh home uses
    ``strict`` (local only) (#1058 review round 3).
    """

    runtime = FinishUpRuntime(cwd=project)
    option = HarnessOption(
        str(installation.executable), installation.version, installation.label, ""
    )
    binary = HarnessBinary(
        HarnessId.CODEX, str(installation.executable), installation.version, "untested"
    )
    if route is None:
        route = _current_route(binary, installation.config_root)
    service = HarnessMcpService(
        CodexMcpAdapter(route_profile=route, codex_home=installation.config_root)
    )
    admission = AdmissionCleanupStep(project)
    body: dict[str, JsonValue] = {
        "schema": "yoetz.host-connection-plan/1",
        "request_id": request_value,
        "host": "codex",
        "host_version": installation.version,
        "executable": str(installation.executable),
        "config_root": str(installation.config_root),
        "project_root": str(project),
        "action": action,
        "route_profile": route,
        "requires_os_presence": False,
        "connection_observed": False,
    }
    if action == "connect":

        async def preview():
            return await runtime.integration_plan(option, installation.config_root, route)

        legacy = anyio.run(preview)
        body["codex_plan"] = cast(JsonValue, asdict(legacy))
        body["changes"] = list(legacy.changes)
        # An owned ``yoetz`` entry that a project's Codex configuration still names without a
        # transport of its own stays beside ``finishup``: migrating it would stop Codex loading
        # there (#1073). The adapter decided it and bound it in the preview digest.
        legacy_kept = bool(legacy.legacy_registration_kept_for) or (
            legacy.legacy_registration_kept_unchecked
        )
        if legacy_kept:
            kept_status = legacy_kept_disclosure(
                legacy.legacy_registration_kept_for,
                legacy.legacy_registration_kept_unread,
                codex_home=installation.config_root,
                way_out=legacy_way_out(
                    str(installation.executable), installation.config_root, project, route
                ),
            )
            legacy_route = legacy.legacy_registration_route_profile
            if legacy_route is not None and legacy_route != route:
                # The kept entry serves every project of the home on its own review mode: a
                # different one here would leave both running side by side. Nothing changed;
                # either mode stays reachable (keep this one, or the explicit way out).
                raise ConnectionError(
                    "connection_legacy_registration_route_kept",
                    status={
                        "route_profile_before": legacy_route,
                        "route_profile": route,
                        **kept_status,
                        "keep_route_arguments": legacy_way_out(
                            str(installation.executable),
                            installation.config_root,
                            project,
                            legacy_route,
                        )["reconnect_arguments"],
                    },
                )
            admission.disclosure.update(kept_status)

        async def observe():
            return await service.observe(binary)

        observed = anyio.run(observe)
        home_status = home_projects_status(installation.config_root)
        listed = home_status.get("codex_home_projects")
        others: list[JsonValue] = [
            item
            for item in (cast(list[JsonValue], listed) if isinstance(listed, list) else [])
            if item != str(project)
        ]
        if others:
            admission.disclosure["shared_with"] = others
        possible = home_status.get("codex_home_possible_projects")
        admission.disclosure.update(
            possible_users_disclosure(
                tuple(str(item) for item in cast(list[JsonValue], possible))
                if isinstance(possible, list)
                else (),
                excluding=project,
            )
        )
        if legacy.route_profile_before is not None:
            # The user-level registration serves every project in the home: rewriting it on
            # another review mode changes theirs too, so the plan names them (#1058 review P2-3),
            # including projects that may use it without a verified connection.
            admission.disclosure.update(
                route_change_disclosure(
                    legacy.route_profile_before,
                    legacy.route_changes_for,
                    legacy.route_changes_possible_for,
                )
            )
        activation = inspect_activation(
            IntegrationTarget(IntegrationScope.TRUSTED_PROJECT, str(project)),
            executable_path=str(installation.executable),
            codex_home=installation.config_root,
        )
        # A Yoetz-era registration or activation is migrated by the same approved apply, so it
        # keeps the connection from reading as already complete (ADR-048).
        legacy_registration_owned = observed.legacy_registration in _OWNED_LEGACY_REGISTRATIONS
        legacy_trees = _legacy_tree_changes(legacy.project_root, legacy.managed_paths)
        if (
            activation.inventory_verified
            and activation.plugin_cached
            # The home's shared plugin is cached for every project; only a project that is
            # itself connected (anchor or recorded) is unchanged (#1058).
            and activation.state is ActivationState.ACTIVE
            and legacy.already_registered
            # Plugin activation and project-skill installation are independent. A
            # current cache must not hide a pristine older (or user-edited) skill.
            and skill_tree_state(IntegrationTarget(IntegrationScope.TRUSTED_PROJECT, str(project)))
            == IntegrationState.INSTALLED_EXACT.value
            and observed.route_profile == route
            and not (legacy_registration_owned and not legacy_kept)
            and not activation.legacy_activation
            and not legacy_trees
        ):
            body["changes"] = []
        if legacy_registration_owned and not legacy_kept:
            cast(list[JsonValue], body["changes"]).append("migrate_legacy_mcp_registration")
        if activation.legacy_activation:
            cast(list[JsonValue], body["changes"]).append("migrate_legacy_plugin")
        cast(list[JsonValue], body["changes"]).extend(legacy_trees)
        connect_warnings: list[JsonValue] = []
        if observed.legacy_registration == "foreign":
            connect_warnings.append("legacy_registration_foreign")
        if legacy_kept:
            connect_warnings.append("legacy_registration_kept")
        if connect_warnings:
            body["warnings"] = connect_warnings

        def apply() -> None:
            from finishup.cli.setup import apply_codex_integration

            async def execute():
                return await apply_codex_integration(
                    binary,
                    route_profile=route,
                    workspace=project,
                    approved_preview_digest=legacy.preview_digest,
                    approved_activation_mcp_command=legacy.activation_mcp_command,
                    approved_skill_preview_digest=legacy.skill_preview_digest,
                    approved_activation_digest=legacy.activation_preview_digest,
                    approved_policy_digest=legacy.policy_digest,
                    codex_home=installation.config_root,
                )

            report = anyio.run(execute)
            if report.get("outcome") not in {"registered", "reregistered", "already_registered"}:
                raise ConnectionError("connection_outcome_unknown", status=report)

        def status() -> dict[str, JsonValue]:
            current = inspect_activation(
                IntegrationTarget(IntegrationScope.TRUSTED_PROJECT, str(project)),
                executable_path=str(installation.executable),
                codex_home=installation.config_root,
            )
            registration = anyio.run(observe)
            # `active` only for a project connected to this home; the shared plugin and
            # registration alone serve every project in it (#1058). A detached or never-connected
            # project reports them as retained, not as its configuration, as the disconnect
            # status does (#1058 review round 3).
            connected = current.state is ActivationState.ACTIVE
            registered = registration.route_profile is not None
            return {
                "installed": current.plugin_cached,
                "enabled": current.plugin_enabled and connected,
                "activation_state": current.state.value,
                "configured": connected and registration.route_profile == route,
                **({"shared_registration_retained": True} if registered and not connected else {}),
                "legacy_activation": current.legacy_activation,
                "legacy_registration": registration.legacy_registration,
                "connection_observed": False,
                "reload_required": True,
                **home_projects_status(installation.config_root),
                **project_mcp_leftover_status(
                    installation.config_root,
                    project,
                    legacy_registration=registration.legacy_registration,
                ),
                **legacy_kept_status(
                    installation.config_root,
                    registration.legacy_registration,
                    way_out=legacy_way_out(
                        str(installation.executable), installation.config_root, project, route
                    ),
                ),
            }
    else:
        removal_report: dict[str, JsonValue] | None = None
        config_load: str | None = None
        target = IntegrationTarget(IntegrationScope.TRUSTED_PROJECT, str(project))
        removal = preview_removal(
            target,
            executable_path=str(installation.executable),
            codex_home=installation.config_root,
            remove_shared=remove_shared,
        )

        async def preview_mcp():
            return await service.preview_unregistration(binary)

        registration = anyio.run(preview_mcp)
        # Disconnect preserves the observed mode in its continuation.
        body["route_profile"] = registration.route_profile
        # Other connected projects keep the home's shared plugin and user-level MCP
        # registration; this disconnect removes only this project's pieces (#1058).
        detach = removal.outcome is RemovalOutcome.DETACH
        # Whatever this project's own state (already detached, never connected), the shared
        # registration stays while another project uses the home's shared pieces: a verified
        # member that still serves the manifest, or a possible user (#1058 review round 2 P1).
        # A project that is not (or no longer) a member never takes the shared pieces from a
        # recorded project, even one whose plugin files are absent right now (a branch switch,
        # `git clean`, an unmounted volume) (#1058 review round 3). Membership that cannot be
        # read keeps them too: unknown is never "nobody else".
        membership_unknown = False
        serving_others: tuple[str, ...] = ()
        possible_others: tuple[str, ...] = ()
        members: tuple[str, ...] = ()
        if os.path.lexists(installation.config_root):
            try:
                serving_others, possible_others = other_members(installation.config_root, project)
                members = connected_projects(installation.config_root)
            except IntegrationError:
                membership_unknown = True
        is_member = any(
            item == str(project) or same_directory(Path(item), project) for item in members
        )
        recorded_others = () if is_member else live_projects(members, excluding=project)
        # The removal plan's own decision comes first: it keeps the shared pieces for recorded
        # projects whose plugin files are absent right now too.
        shared_kept = not remove_shared and (
            removal.keeps_shared
            or bool(serving_others)
            or bool(possible_others)
            or bool(recorded_others)
            or membership_unknown
        )
        # The plan removes the shared plugin (no project can carry the binding) while the
        # user-level registration stays for the projects that still use it, such as a Yoetz-era
        # bound project: members whose plugin files are absent right now lose the plugin (#1073).
        plugin_removed = (
            shared_kept and removal.outcome is RemovalOutcome.REMOVE and not removal.keeps_shared
        )
        # Who the kept pieces are for: serving members, and recorded projects whose plugin
        # files are absent right now (they use them again once the files return) unless the
        # plugin itself goes.
        kept_for: tuple[str, ...] = (
            tuple(
                sorted(
                    {
                        *removal.shared_with,
                        *serving_others,
                        *(() if plugin_removed else removal.unserved_members),
                        *recorded_others,
                        *removal.missing_members,
                    }
                )
            )
            if shared_kept
            else ()
        )
        # The user-level keys an unregistration removes: an owned entry under the earlier
        # ``yoetz`` key goes with the ``finishup`` one, so tables that need either count (ADR-048).
        removed_names = (
            (MCP_SERVER_NAME, LEGACY_MCP_SERVER_NAME)
            if registration.legacy_registration in _OWNED_LEGACY_REGISTRATIONS
            else (MCP_SERVER_NAME,)
        )
        # Projects whose own Codex layer uses the user-level transport (an approval table
        # without a transport of its own) also keep it, connected through FinishUP or not.
        needing, enumeration = _other_projects_needing_transport(
            installation.config_root, project, removed_names
        )
        removes_transport = not shared_kept and registration.action.value != "noop"
        # An incomplete read is not proof that no other project needs the transport
        # (CHECK_MULTIPROJ_R1 P2-3): keep it on an ordinary disconnect, refuse it home-wide.
        unproven = bool(enumeration)
        if removes_transport and (needing or unproven) and remove_shared:
            # An explicit home-wide disconnect still never breaks Codex in another project.
            raise ConnectionError(
                "connection_other_projects_need_registration",
                status={
                    "admission_other_projects": needing,
                    **enumeration,
                    **(
                        {
                            "mcp_removal_preview_arguments": legacy_way_out(
                                str(installation.executable),
                                installation.config_root,
                                project,
                                None,
                            )["mcp_removal_preview_arguments"]
                        }
                        if enumeration.get("admission_other_projects_unread")
                        else {}
                    ),
                },
            )
        keep_transport = removes_transport and (bool(needing) or unproven)
        if removes_transport and not keep_transport:
            own = project_transport_dependence(project, after_sweep=True, names=removed_names)
            if own == "depends":
                # Tables FinishUP did not write (or that were edited) stay in this project's
                # .codex/config.toml after the sweep and still name the FinishUP server: removing
                # the registration would stop Codex loading here. Nothing has changed yet.
                raise ConnectionError(
                    "connection_project_mcp_tables_retained",
                    status={
                        "project_mcp_retained": str(project / ".codex" / "config.toml"),
                    },
                )
        skill = CodexSkillIntegration()
        skill_command = SkillPreviewCommand(
            request_id(request_value), target, IntegrationAction.REMOVE, False
        )

        async def preview_skill():
            return await skill.preview_skill(HarnessId.CODEX, skill_command)

        skill_preview = anyio.run(preview_skill)
        skill_owned_update = "owned_skill_update" in skill_preview.warnings
        if not skill_owned_update and skill_preview.state_before not in {
            IntegrationState.INSTALLED_EXACT,
            IntegrationState.ABSENT,
        }:
            raise ConnectionError("connection_modified_skill")
        # A marker-consistent Yoetz-era ``.agents/skills/yoetz`` goes with the same approved
        # removal, including when it is the only skill tree left (ADR-048).
        legacy_skill_owned = "legacy_skill_tree_owned" in skill_preview.warnings
        skill_remove_planned = (
            skill_preview.state_before is IntegrationState.INSTALLED_EXACT
            or skill_owned_update
            or legacy_skill_owned
        )
        body["skill_preview_digest"] = skill_preview.preview_digest
        body["plugin_preview_digest"] = removal.preview_digest
        unregister_planned = removes_transport and not keep_transport
        body["mcp_preview_digest"] = registration.preview_digest if unregister_planned else None
        warnings: list[JsonValue] = list(registration.warnings) if unregister_planned else []
        body["warnings"] = warnings
        body["retained"] = ["FinishUP data", "inactive project plugin sources"]
        # Kept-for projects whose directory is missing right now (the dangling binding's).
        missing_kept = tuple(item for item in kept_for if item in removal.missing_members)
        if shared_kept:
            cast(list[JsonValue], body["retained"]).append(
                # Only projects whose directory is missing right now: say so, not "other
                # connected projects" that are not there (#1058 triage).
                "shared Codex plugin and MCP registration, kept for a connected project whose "
                "directory is missing right now"
                if kept_for and len(missing_kept) == len(kept_for)
                else "shared Codex plugin and MCP registration used by other connected projects"
                if removal.keeps_shared or removal.outcome is not RemovalOutcome.REMOVE
                # The plan removes the shared plugin (no project can carry it); only the
                # user-level registration stays for the projects that still use it.
                else "FinishUP MCP registration used by other connected projects"
            )
            admission.disclosure["shared_with"] = cast(list[JsonValue], list(kept_for))
            if missing_kept:
                admission.disclosure["members_missing"] = cast(list[JsonValue], list(missing_kept))
        if membership_unknown:
            # Unreadable membership: an ordinary disconnect keeps the shared pieces, and a
            # home-wide one says it cannot name everyone it removes them from.
            admission.disclosure["membership_unknown"] = True
        if keep_transport:
            cast(list[JsonValue], body["retained"]).append(
                "FinishUP MCP registration used by other projects' Codex configuration"
                if needing
                else "FinishUP MCP registration, because not every project this home knows was checked"
            )
            if needing:
                admission.disclosure["admission_other_projects"] = needing
            warnings.append("mcp_registration_kept_for_other_projects")
        if removes_transport and enumeration:
            # Not every known project was read: absence from the list is not proof.
            admission.disclosure.update(enumeration)
            warnings.append("other_projects_partially_checked")
            if enumeration.get("admission_other_projects_unread"):
                # Kept because an input could not be read: name the explicit way out too.
                admission.disclosure["mcp_removal_preview_arguments"] = legacy_way_out(
                    str(installation.executable), installation.config_root, project, None
                )["mcp_removal_preview_arguments"]
        # Projects that may use the shared pieces though no record names them: an ordinary
        # disconnect keeps the pieces for them, --remove-shared removes them anyway.
        admission.disclosure.update(
            possible_users_disclosure(tuple(sorted({*removal.possible_users, *possible_others})))
        )
        if removal.rebind_to is not None:
            admission.disclosure["rebind_to"] = removal.rebind_to
        if removal.unserved_members and (not shared_kept or plugin_removed):
            # Connected projects whose plugin files are absent right now lose the shared pieces
            # with this removal too (#1058 review round 2), also when only the registration
            # stays for others (#1073).
            admission.disclosure["members_not_serving"] = cast(
                list[JsonValue], list(removal.unserved_members)
            )
        if plugin_removed:
            admission.disclosure["shared_plugin_removed"] = True
        if remove_shared:
            admission.disclosure["remove_shared"] = True
            if removal.outcome is not RemovalOutcome.ALREADY_ABSENT:
                # The verified projects that stop using FinishUP with this home-wide disconnect,
                # disclosed as Claude Code and Cursor do (#1058).
                affected = _other_connected_projects(installation.config_root, project)
                if affected:
                    admission.disclosure["shared_removed_from"] = cast(
                        list[JsonValue], list(affected)
                    )
        body["changes"] = (
            []
            if removal.outcome is RemovalOutcome.ALREADY_ABSENT
            else ["detach_project"]
            if detach
            else ["deactivate_plugin"]
        )
        if unregister_planned:
            cast(list[JsonValue], body["changes"]).append("remove_mcp_registration")
        # The legacy ``yoetz`` entry is user-level too: it goes with the unregistration, and
        # stays with the ``finishup`` one while other projects keep the shared pieces (#1058).
        if unregister_planned and registration.legacy_registration in _OWNED_LEGACY_REGISTRATIONS:
            cast(list[JsonValue], body["changes"]).append("remove_legacy_mcp_registration")
        if removal.legacy_removed_block or removal.legacy_cache_versions:
            cast(list[JsonValue], body["changes"]).append("deactivate_legacy_plugin")
        if skill_preview.state_before is IntegrationState.INSTALLED_EXACT or skill_owned_update:
            cast(list[JsonValue], body["changes"]).append("remove_project_skill")
        if legacy_skill_owned:
            cast(list[JsonValue], body["changes"]).append("remove_legacy_project_skill")
        # The project's admission table must go before the user-level transport does: a
        # trusted project's `[mcp_servers.finishup.tools.check]` without a transport makes
        # Codex refuse to load configuration there (exec, mcp list, plugin list).
        sweep_admission = admission.plan(body, "codex", action)

        def apply() -> None:
            nonlocal removal_report, config_load
            admission.apply(sweep_admission)
            apply_removal(
                target,
                approved_digest=removal.preview_digest,
                executable_path=str(installation.executable),
                codex_home=installation.config_root,
                remove_shared=remove_shared,
            )

            async def unregister():
                confirmation = McpRegistrationConfirmation(
                    registration.preview_digest, True, "noninteractive_flag"
                )
                try:
                    return await service.unregister(binary, confirmation)
                except McpRegistrationError as error:
                    if (
                        error.reason is not McpRegistrationReason.PREVIEW_STALE
                        or removal.outcome is not RemovalOutcome.REMOVE
                        or removal.keeps_shared
                    ):
                        raise
                    # Policy may be supplied solely by the activation cache. Removing
                    # that plugin already removed the approved registration. Only
                    # positive absence of BOTH names permits this no-op; a changed,
                    # foreign or present entry still fails closed as stale.
                    after_plugin = await service.preview_unregistration(binary)
                    if after_plugin.state_before is not McpRegistrationState.ABSENT:
                        raise error
                    return await service.unregister(
                        binary,
                        McpRegistrationConfirmation(
                            after_plugin.preview_digest, True, "noninteractive_flag"
                        ),
                    )

            try:
                if unregister_planned:
                    removal_report = mcp_removal_report(anyio.run(unregister))
            except McpRegistrationError as error:
                if error.reason is McpRegistrationReason.REGISTRATION_FAILED:
                    from finishup.cli.setup_readiness import continuation

                    raise ConnectionError(
                        "connection_outcome_unknown",
                        status={
                            "mcp_removal": mcp_removal_report(error),
                            "next_command": continuation(
                                [
                                    "integrate",
                                    "codex",
                                    "mcp",
                                    "status",
                                    "--codex-path",
                                    binary.executable_path,
                                    "--codex-home",
                                    str(installation.config_root),
                                    "--json",
                                ]
                            ),
                        },
                    ) from error
                raise
            if skill_remove_planned:

                async def remove_skill():
                    return await skill.remove_skill(
                        HarnessId.CODEX,
                        SkillApplyCommand(
                            request_id(request_value),
                            target,
                            IntegrationAction.REMOVE,
                            skill_preview.preview_digest,
                            True,
                            False,
                        ),
                    )

                anyio.run(remove_skill)
            config_load = probe_project_config_load(
                str(installation.executable), installation.config_root, project
            )
            if config_load == "fails":
                raise ConnectionError(
                    "connection_project_config_unloadable",
                    status={
                        **admission.status(),
                        "mcp_removal": removal_report,
                        "project_config_load": config_load,
                        **project_mcp_leftover_status(installation.config_root, project),
                    },
                )

        def status() -> dict[str, JsonValue]:
            current = preview_removal(
                target,
                executable_path=str(installation.executable),
                codex_home=installation.config_root,
            )
            observed = anyio.run(preview_mcp)
            # Only an owned entry (under either name) is FinishUP's registration; a foreign one
            # stays visible without counting as configuration (ADR-048).
            registered = observed.state_before is McpRegistrationState.FINISHUP_OWNED
            connected = current.outcome is not RemovalOutcome.ALREADY_ABSENT
            # Kept for other projects: their use of the shared pieces, or their own Codex
            # configuration (an approval table that needs the transport, or a scan that stopped at
            # its bound) (#1058).
            kept_for_others = shared_kept or keep_transport
            return {
                "installed": None,
                # A detached project still sees the home's shared plugin; it is not connected.
                "enabled": current.outcome is RemovalOutcome.REMOVE,
                # The registration other projects keep is not this project's configuration
                # (#1058 review round 2 P1: reporting it invited a re-run). One this disconnect
                # removes is, until it is gone, as it was before several projects shared a home.
                "configured": registered and (connected or unregister_planned),
                **(
                    {"shared_registration_retained": True}
                    if registered and not connected and kept_for_others
                    else {}
                ),
                # Kept for these projects (also when this disconnect changed nothing).
                **({"shared_with": cast(list[JsonValue], list(kept_for))} if kept_for else {}),
                **(
                    {"members_missing": cast(list[JsonValue], list(missing_kept))}
                    if shared_kept and missing_kept
                    else {}
                ),
                "legacy_registration": observed.legacy_registration,
                "connection_observed": False,
                "reload_required": True,
                "retained": body["retained"],
                "mcp_removal": removal_report,
                "project_config_load": config_load,
                **home_projects_status(installation.config_root),
                **admission.status(),
            }

    body["preview_digest"] = plan_digest(body, admission.disclosure)
    return ConnectionPlan(body, status, apply, admission.disclosure)


_OTHER_PROJECTS_LIMIT = 32


def legacy_kept_disclosure(
    roots: tuple[str, ...],
    unread: tuple[str, ...],
    *,
    codex_home: Path,
    way_out: Mapping[str, JsonValue] | None = None,
) -> dict[str, JsonValue]:
    """Who keeps the owned ``yoetz`` entry, why, and what releases it (#1073).

    An entry names the project and how its ``.codex/config.toml`` depends on the ``yoetz``
    transport: ``depends`` (it names the server without a transport of its own) or ``unknown``
    with the closed reason it could not be read safely (``unreadable``). Only a project whose
    dependence ends once its exact earlier-name approval tables are swept carries the revoke
    (``next_arguments``: ``integrate codex admission preview --action revoke`` removes exactly
    those); edited tables are the owner's to remove. ``unread`` names what of the home itself
    could not be read. ``way_out`` carries the explicit removal under both names and the connect
    that follows it (``legacy_way_out``).
    """

    entries: list[JsonValue] = []
    for root in roots:
        path = Path(root)
        dependence = project_transport_dependence(
            path, after_sweep=False, names=(LEGACY_MCP_SERVER_NAME,)
        )
        entry: dict[str, JsonValue] = {"project_root": root, "dependence": dependence}
        if dependence == "unknown":
            reason = project_config_unreadable_reason(path)
            if reason is not None:
                entry["unreadable"] = reason
        elif dependence == "depends" and (
            project_transport_dependence(path, after_sweep=True, names=(LEGACY_MCP_SERVER_NAME,))
            == "none"
        ):
            entry["next_arguments"] = cast(
                list[JsonValue], admission_revoke_arguments("codex", path)
            )
        entries.append(entry)
    disclosure: dict[str, JsonValue] = {
        "legacy_registration_kept_for": entries,
        "legacy_registration_codex_home": str(codex_home),
    }
    if unread:
        disclosure["legacy_registration_kept_unchecked"] = True
        disclosure["legacy_registration_kept_unread"] = cast(list[JsonValue], list(unread))
    if way_out:
        disclosure.update(way_out)
    return disclosure


def legacy_way_out(
    executable: str,
    codex_home: Path,
    project: Path | None,
    route: str | None,
    *,
    low_level: bool = False,
) -> dict[str, JsonValue]:
    """The explicit way past a kept ``yoetz`` entry, as structural continuations (#1073).

    ``mcp_removal_preview_arguments`` previews removing FinishUP's MCP registration from this
    Codex home under both names (the low-level ``integrate codex mcp preview-remove``; its
    ``remove`` form applies that preview's digest). ``reconnect_arguments`` is the connect that
    follows: ``setup run`` for the selected installation and project, or, for the low-level path,
    its own ``integrate codex mcp install``. Both carry the selected executable and Codex home.
    """

    low = ["--codex-path", executable, "--codex-home", str(codex_home)]
    reconnect: list[str] = (
        ["integrate", "codex", "mcp", "install", *low]
        if low_level
        else [
            "setup",
            "run",
            "--host",
            "codex",
            "--host-path",
            executable,
            "--host-config-root",
            str(codex_home),
            *(["--project", str(project)] if project is not None else []),
        ]
    )
    if route is not None:
        reconnect += ["--route-profile", route]
    return {
        "mcp_removal_preview_arguments": cast(
            list[JsonValue], ["integrate", "codex", "mcp", "preview-remove", *low]
        ),
        "reconnect_arguments": cast(list[JsonValue], reconnect),
    }


def legacy_kept_status(
    codex_home: Path,
    legacy_registration: str | None,
    *,
    way_out: Mapping[str, JsonValue] | None = None,
) -> dict[str, JsonValue]:
    """Status facts for an owned ``yoetz`` entry that stays because projects may still need it.

    Read now, so it names what still holds the migration back; empty once nothing does (the next
    connect then completes the migration, and the last disconnect removes both keys).
    """

    if legacy_registration not in _OWNED_LEGACY_REGISTRATIONS:
        return {}
    use = legacy_registration_dependents(codex_home)
    if not use.keeps:
        return {}
    return legacy_kept_disclosure(use.kept_for, use.unread, codex_home=codex_home, way_out=way_out)


def _current_route(binary: HarnessBinary, codex_home: Path) -> Literal["policy", "strict"]:
    """The review mode of the home's FinishUP-owned MCP registration; ``strict`` without one."""

    async def observe():
        return await HarnessMcpService(
            CodexMcpAdapter(route_profile="strict", codex_home=codex_home)
        ).observe(binary)

    try:
        observed = anyio.run(observe)
    except McpRegistrationError:
        # The later steps read the same configuration and report what is wrong with it.
        return "strict"
    return observed.route_profile or "strict"


def _other_projects_needing_transport(
    codex_home: Path, project: Path, names: tuple[str, ...] = (MCP_SERVER_NAME,)
) -> tuple[list[JsonValue], dict[str, JsonValue]]:
    """Projects, other than ``project``, whose Codex layer uses the user-level transport.

    Candidates are the projects this home knows: its ``[projects."<path>"]`` trust entries, the
    FinishUP marketplace binding, and the connected-projects record. A project whose
    ``.codex/config.toml`` declares ``mcp_servers.finishup`` without its own transport, or cannot be
    read safely, needs the registration kept; ``names`` adds the earlier ``yoetz`` key when the
    unregistration also removes an owned entry there (ADR-048). At most ``_OTHER_PROJECTS_LIMIT``
    candidates are read; the second value reports the bound so absence from the list is never
    read as proof.
    """

    candidates, unread = home_project_candidates(codex_home)
    # Missing directories and other paths to this same project are filtered before the bound,
    # so stale trust entries do not use up the read window.
    eligible = [
        candidate for candidate in candidates if not same_directory(Path(candidate), project)
    ]
    inspected = eligible[:_OTHER_PROJECTS_LIMIT]
    found: list[JsonValue] = []
    for candidate in inspected:
        root = Path(candidate)
        dependence = project_transport_dependence(root, after_sweep=False, names=names)
        if dependence == "none":
            continue
        entry: dict[str, JsonValue] = {"project_root": str(root), "dependence": dependence}
        if dependence == "depends" and (
            project_transport_dependence(root, after_sweep=True, names=names) == "none"
        ):
            # Only exact FinishUP approval tables: an admission revoke there removes them.
            entry["next_arguments"] = cast(
                list[JsonValue], admission_revoke_arguments("codex", root)
            )
        found.append(entry)
    enumeration: dict[str, JsonValue] = (
        {
            "admission_other_projects_inspected": len(inspected),
            "admission_other_projects_known": len(eligible),
        }
        if len(eligible) > len(inspected)
        else {}
    )
    if unread:
        # What could not be read is not proof that nobody needs the transport: the connect keeps
        # the earlier entry for the same reason (#1073 round 3).
        enumeration["admission_other_projects_unread"] = cast(list[JsonValue], list(unread))
    return found, enumeration


def _other_connected_projects(codex_home: Path, project: Path) -> tuple[str, ...]:
    """Verified members of the home other than ``project`` that still use its shared pieces."""

    try:
        listed = serving_projects(codex_home)
    except IntegrationError:
        return ()
    return live_projects(listed, excluding=project)


def route_change_disclosure(
    before: str | None, verified: tuple[str, ...], possible: tuple[str, ...]
) -> dict[str, JsonValue]:
    """Digest-bound preview facts for a shared review-mode change that reaches other projects."""

    if before is None or (not verified and not possible):
        return {}
    disclosure: dict[str, JsonValue] = {
        "route_profile_before": before,
        "route_changes_for": cast(list[JsonValue], list(verified)),
    }
    if possible:
        disclosure["route_changes_possible_for"] = cast(list[JsonValue], list(possible))
    return disclosure


def possible_users_disclosure(
    possible: tuple[str, ...], *, excluding: Path | None = None
) -> dict[str, JsonValue]:
    """Preview facts for unverified projects that may use the home's shared pieces (#1058).

    They are possible users, not connections: membership is unknown while they exist. The
    project being connected is excluded: the connect records it.
    """

    listed = [
        item
        for item in possible
        if excluding is None
        or (item != str(excluding) and not same_directory(Path(item), excluding))
    ]
    if not listed:
        return {}
    return {
        "membership_unknown": True,
        "possible_users": cast(list[JsonValue], listed),
    }


def home_projects_status(codex_home: Path) -> dict[str, JsonValue]:
    """Every project this Codex home's shared FinishUP pieces serve (#1058).

    Unreadable membership reports ``membership_unknown`` rather than nobody; a home that does
    not exist yet reports nothing.
    """

    if not os.path.lexists(codex_home):
        return {}
    try:
        # Verified members that still serve the manifest: a deleted anchor, or one whose
        # manifest is gone, is not reported as connected (#1058 review P2-2).
        projects = serving_projects(codex_home)
        possible = possible_projects(codex_home)
    except IntegrationError:
        return {"membership_unknown": True}
    status: dict[str, JsonValue] = {"codex_home_projects": cast(list[JsonValue], list(projects))}
    if possible:
        # Possible users, not verified connections: they keep the shared pieces, never anchor.
        status["codex_home_possible_projects"] = cast(list[JsonValue], list(possible))
        status["membership_unknown"] = True
    return status


def project_mcp_leftover_status(
    codex_home: Path, project: Path, *, legacy_registration: str | None = None
) -> dict[str, JsonValue]:
    """Explain a transport-less project ``mcp_servers`` table and name its exact repair.

    Both server keys are read: ``finishup`` and the earlier ``yoetz`` one, whose approval table
    a Yoetz 0.2.x disconnect left behind (ADR-048). Exact approval tables (``tools_only``) are
    revoked. Other retained tables (``retained_tables``) are the owner's to edit; under
    ``finishup`` alone, connecting again also restores the server, so the continuation is the
    reconnect, while a ``yoetz`` table has no FinishUP repair (only ``finishup`` is registered
    now), so the step names the file without a command. ``legacy_registration`` is the observed
    ``yoetz`` registration state when the caller has one; otherwise a FinishUP-shaped user-level
    ``yoetz`` entry counts as owned.
    """

    leftovers = codex_project_mcp_leftovers(codex_home, project)
    if not leftovers:
        legacy_owned = (
            legacy_registration in _OWNED_LEGACY_REGISTRATIONS
            if legacy_registration is not None
            else legacy_registration_shaped(read_bounded_toml(codex_home / "config.toml") or {})
        )
        names = (MCP_SERVER_NAME, LEGACY_MCP_SERVER_NAME) if legacy_owned else (MCP_SERVER_NAME,)
        if project_transport_dependence(project, after_sweep=True, names=names) == "depends":
            # Loads today, but a disconnect would refuse: the retained tables need the transport.
            return {"project_mcp_needs_registration": True}
        return {}
    retained = [name for name, kind in leftovers if kind == "retained_tables"]
    tools_only = [name for name, kind in leftovers if kind == "tools_only"]
    status: dict[str, JsonValue] = {
        "project_mcp_leftover": "retained_tables" if retained else "tools_only",
        "project_mcp_leftover_servers": cast(list[JsonValue], [name for name, _ in leftovers]),
        # Each key by kind, so a step never calls an exact FinishUP table one the owner edited.
        "project_mcp_leftover_retained_servers": cast(list[JsonValue], retained),
        "project_mcp_leftover_tools_only_servers": cast(list[JsonValue], tools_only),
    }
    if tools_only:
        # A ``tools_only`` key is one the revoke removes (its file is still FinishUP's to sweep),
        # also beside tables the owner edited under the other key.
        status["next_arguments"] = cast(
            list[JsonValue], admission_revoke_arguments("codex", project)
        )
    elif all(name == MCP_SERVER_NAME for name in retained):
        status["next_arguments"] = [
            "setup",
            "run",
            "--host",
            "codex",
            "--host-config-root",
            str(codex_home),
            "--project",
            str(project),
        ]
    return status
