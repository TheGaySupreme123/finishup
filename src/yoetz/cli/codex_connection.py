"""Adapt the existing Codex setup composition to the common connection report."""

from __future__ import annotations

import os
from dataclasses import asdict
from pathlib import Path
from typing import Literal, cast

import anyio

from yoetz.adapters.integrations.codex_marketplace import (
    ActivationState,
    RemovalOutcome,
    apply_removal,
    connected_projects,
    inspect_activation,
    other_members,
    possible_projects,
    preview_removal,
    serving_projects,
)
from yoetz.adapters.integrations.codex_mcp import (
    CodexMcpAdapter,
    codex_project_mcp_leftover,
    probe_project_config_load,
    project_transport_dependence,
    read_bounded_toml,
)
from yoetz.adapters.integrations.codex_skill import CodexSkillIntegration
from yoetz.adapters.integrations.host_discovery import HostInstallation
from yoetz.adapters.integrations.host_projects import live_projects, same_directory
from yoetz.application.harness_mcp import (
    HarnessMcpService,
    McpRegistrationConfirmation,
    mcp_removal_report,
)
from yoetz.application.host_connection import (
    AdmissionCleanupStep,
    ConnectionAction,
    ConnectionError,
    ConnectionPlan,
    admission_revoke_arguments,
    plan_digest,
)
from yoetz.domain.values import request_id
from yoetz.ports.harness_mcp import HarnessBinary, McpRegistrationError, McpRegistrationReason
from yoetz.ports.integrations import (
    HarnessId,
    IntegrationAction,
    IntegrationError,
    IntegrationScope,
    IntegrationState,
    IntegrationTarget,
    SkillApplyCommand,
    SkillPreviewCommand,
)
from yoetz.protocol.canonical import JsonValue
from yoetz.tui.models import HarnessOption
from yoetz.tui.runtime import YoetzRuntime


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

    runtime = YoetzRuntime(cwd=project)
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
        if (
            activation.inventory_verified
            and activation.plugin_cached
            # The home's shared plugin is cached for every project; only a project that is
            # itself connected (anchor or recorded) is unchanged (#1058).
            and activation.state is ActivationState.ACTIVE
            and legacy.already_registered
            and observed.route_profile == route
        ):
            body["changes"] = []

        def apply() -> None:
            from yoetz.cli.setup import apply_codex_integration

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
                "connection_observed": False,
                "reload_required": True,
                **home_projects_status(installation.config_root),
                **project_mcp_leftover_status(installation.config_root, project),
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
        # Who the kept pieces are for: serving members, and recorded projects whose plugin
        # files are absent right now (they use them again once the files return).
        kept_for: tuple[str, ...] = (
            tuple(
                sorted(
                    {
                        *removal.shared_with,
                        *serving_others,
                        *removal.unserved_members,
                        *recorded_others,
                        *removal.missing_members,
                    }
                )
            )
            if shared_kept
            else ()
        )
        # Projects whose own Codex layer uses the user-level transport (an approval table
        # without a transport of its own) also keep it, connected through Yoetz or not.
        needing, enumeration = _other_projects_needing_transport(installation.config_root, project)
        removes_transport = not shared_kept and registration.action.value != "noop"
        # An incomplete read is not proof that no other project needs the transport
        # (CHECK_MULTIPROJ_R1 P2-3): keep it on an ordinary disconnect, refuse it home-wide.
        unproven = bool(enumeration)
        if removes_transport and (needing or unproven) and remove_shared:
            # An explicit home-wide disconnect still never breaks Codex in another project.
            raise ConnectionError(
                "connection_other_projects_need_registration",
                status={"admission_other_projects": needing, **enumeration},
            )
        keep_transport = removes_transport and (bool(needing) or unproven)
        if removes_transport and not keep_transport:
            own = project_transport_dependence(project, after_sweep=True)
            if own == "depends":
                # Tables Yoetz did not write (or that were edited) stay in this project's
                # .codex/config.toml after the sweep and still name the Yoetz server: removing
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
        if skill_preview.state_before not in {
            IntegrationState.INSTALLED_EXACT,
            IntegrationState.ABSENT,
        }:
            raise ConnectionError("connection_modified_skill")
        body["skill_preview_digest"] = skill_preview.preview_digest
        body["plugin_preview_digest"] = removal.preview_digest
        unregister_planned = removes_transport and not keep_transport
        body["mcp_preview_digest"] = registration.preview_digest if unregister_planned else None
        warnings: list[JsonValue] = list(registration.warnings) if unregister_planned else []
        body["warnings"] = warnings
        body["retained"] = ["Yoetz data", "inactive project plugin sources"]
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
                else "Yoetz MCP registration used by other connected projects"
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
                "Yoetz MCP registration used by other projects' Codex configuration"
                if needing
                else "Yoetz MCP registration, because not every project this home knows was checked"
            )
            if needing:
                admission.disclosure["admission_other_projects"] = needing
            warnings.append("mcp_registration_kept_for_other_projects")
        if removes_transport and enumeration:
            # Not every known project was read: absence from the list is not proof.
            admission.disclosure.update(enumeration)
            warnings.append("other_projects_partially_checked")
        # Projects that may use the shared pieces though no record names them: an ordinary
        # disconnect keeps the pieces for them, --remove-shared removes them anyway.
        admission.disclosure.update(
            possible_users_disclosure(tuple(sorted({*removal.possible_users, *possible_others})))
        )
        if removal.rebind_to is not None:
            admission.disclosure["rebind_to"] = removal.rebind_to
        if removal.unserved_members and not shared_kept:
            # Connected projects whose plugin files are absent right now lose the shared pieces
            # with this removal too (#1058 review round 2).
            admission.disclosure["members_not_serving"] = cast(
                list[JsonValue], list(removal.unserved_members)
            )
        if remove_shared:
            admission.disclosure["remove_shared"] = True
            if removal.outcome is not RemovalOutcome.ALREADY_ABSENT:
                # The verified projects that stop using Yoetz with this home-wide disconnect,
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
        if skill_preview.state_before is IntegrationState.INSTALLED_EXACT:
            cast(list[JsonValue], body["changes"]).append("remove_project_skill")
        # The project's admission table must go before the user-level transport does: a
        # trusted project's `[mcp_servers.yoetz.tools.check]` without a transport makes
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
                return await service.unregister(
                    binary,
                    McpRegistrationConfirmation(
                        registration.preview_digest, True, "noninteractive_flag"
                    ),
                )

            try:
                if unregister_planned:
                    removal_report = mcp_removal_report(anyio.run(unregister))
            except McpRegistrationError as error:
                if error.reason is McpRegistrationReason.REGISTRATION_FAILED:
                    from yoetz.cli.setup_readiness import continuation

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
            if skill_preview.state_before is IntegrationState.INSTALLED_EXACT:

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
            registered = observed.action.value != "noop"
            connected = current.outcome is not RemovalOutcome.ALREADY_ABSENT
            return {
                "installed": None,
                # A detached project still sees the home's shared plugin; it is not connected.
                "enabled": current.outcome is RemovalOutcome.REMOVE,
                # The shared registration other projects keep is not this project's
                # configuration (#1058 review round 2 P1: reporting it invited a re-run).
                "configured": registered and connected,
                **(
                    {"shared_registration_retained": True}
                    if registered and not connected and shared_kept
                    else {}
                ),
                # Kept for these projects (also when this disconnect changed nothing).
                **({"shared_with": cast(list[JsonValue], list(kept_for))} if kept_for else {}),
                **(
                    {"members_missing": cast(list[JsonValue], list(missing_kept))}
                    if shared_kept and missing_kept
                    else {}
                ),
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


def _current_route(binary: HarnessBinary, codex_home: Path) -> Literal["policy", "strict"]:
    """The review mode of the home's Yoetz-owned MCP registration; ``strict`` without one."""

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
    codex_home: Path, project: Path
) -> tuple[list[JsonValue], dict[str, JsonValue]]:
    """Projects, other than ``project``, whose Codex layer uses the user-level transport.

    Candidates are the projects this home knows: its ``[projects."<path>"]`` trust entries, the
    Yoetz marketplace binding, and the connected-projects record. A project whose
    ``.codex/config.toml`` declares ``mcp_servers.yoetz`` without its own transport, or cannot be
    read safely, needs the registration kept. At most ``_OTHER_PROJECTS_LIMIT`` candidates are
    read; the second value reports the bound so absence from the list is never read as proof.
    """

    config = read_bounded_toml(codex_home / "config.toml") or {}
    candidates: set[str] = set()
    projects = config.get("projects")
    if isinstance(projects, dict):
        candidates.update(str(key) for key in cast(dict[str, object], projects))
    try:
        candidates.update(connected_projects(codex_home))
    except IntegrationError:
        pass
    # Missing directories and other paths to this same project are filtered before the bound,
    # so stale trust entries do not use up the read window.
    eligible = sorted(
        candidate
        for candidate in candidates
        if Path(candidate).is_absolute()
        and Path(candidate).is_dir()
        and not same_directory(Path(candidate), project)
    )
    inspected = eligible[:_OTHER_PROJECTS_LIMIT]
    found: list[JsonValue] = []
    for candidate in inspected:
        root = Path(candidate)
        dependence = project_transport_dependence(root, after_sweep=False)
        if dependence == "none":
            continue
        entry: dict[str, JsonValue] = {"project_root": str(root), "dependence": dependence}
        if dependence == "depends" and project_transport_dependence(root, after_sweep=True) == (
            "none"
        ):
            # Only exact Yoetz approval tables: an admission revoke there removes them.
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
    """Every project this Codex home's shared Yoetz pieces serve (#1058).

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


def project_mcp_leftover_status(codex_home: Path, project: Path) -> dict[str, JsonValue]:
    """Explain a transport-less project ``mcp_servers.yoetz`` table and name its exact repair.

    Exact Yoetz approval tables (``tools_only``) are revoked; other retained tables
    (``retained_tables``) are the owner's to edit, or the server is registered again by
    reconnecting, so the continuation is the reconnect and the step text names the file.
    """

    leftover = codex_project_mcp_leftover(codex_home, project)
    if leftover is None:
        if project_transport_dependence(project, after_sweep=True) == "depends":
            # Loads today, but a disconnect would refuse: the retained tables need the transport.
            return {"project_mcp_needs_registration": True}
        return {}
    arguments = (
        admission_revoke_arguments("codex", project)
        if leftover == "tools_only"
        else [
            "setup",
            "run",
            "--host",
            "codex",
            "--host-config-root",
            str(codex_home),
            "--project",
            str(project),
        ]
    )
    return {
        "project_mcp_leftover": leftover,
        "next_arguments": cast(list[JsonValue], arguments),
    }
