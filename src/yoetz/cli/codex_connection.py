"""Adapt the existing Codex setup composition to the common connection report."""

from __future__ import annotations

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
    possible_projects,
    preview_removal,
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
    route: Literal["policy", "strict"],
    request_value: str,
    remove_shared: bool = False,
) -> ConnectionPlan:
    runtime = YoetzRuntime(cwd=project)
    option = HarnessOption(
        str(installation.executable), installation.version, installation.label, ""
    )
    binary = HarnessBinary(
        HarnessId.CODEX, str(installation.executable), installation.version, "untested"
    )
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
            return {
                "installed": current.plugin_cached,
                "enabled": current.plugin_enabled,
                # `active` only for a project connected to this home; the shared plugin alone
                # is cached and enabled for every project in it (#1058).
                "activation_state": current.state.value,
                "configured": registration.route_profile == route,
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
        # Projects whose own Codex layer uses the user-level transport (an approval table
        # without a transport of its own) also keep it, connected through Yoetz or not.
        needing, enumeration = _other_projects_needing_transport(installation.config_root, project)
        removes_transport = not detach and registration.action.value != "noop"
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
        if detach:
            cast(list[JsonValue], body["retained"]).append(
                "shared Codex plugin and MCP registration used by other connected projects"
            )
            admission.disclosure["shared_with"] = cast(list[JsonValue], list(removal.shared_with))
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
        # Trusted checkouts that may use the shared pieces though no record names them: an
        # ordinary disconnect keeps the pieces for them, --remove-shared removes them anyway.
        admission.disclosure.update(possible_users_disclosure(removal.possible_users))
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
            return {
                "installed": None,
                # A detached project still sees the home's shared plugin; it is not connected.
                "enabled": current.outcome is RemovalOutcome.REMOVE,
                "configured": observed.action.value != "noop",
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
    """Verified members of the home other than ``project`` whose directories still exist."""

    try:
        listed = connected_projects(codex_home)
    except IntegrationError:
        return ()
    return live_projects(listed, excluding=project)


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
    """Every project this Codex home's shared Yoetz pieces serve (#1058); empty if unreadable."""

    try:
        projects = connected_projects(codex_home)
        possible = possible_projects(codex_home)
    except IntegrationError:
        return {}
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
