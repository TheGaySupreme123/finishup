"""Adapt the existing Codex setup composition to the common connection report."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Literal, cast

import anyio

from yoetz.adapters.integrations.codex_marketplace import (
    RemovalOutcome,
    apply_removal,
    inspect_activation,
    preview_removal,
)
from yoetz.adapters.integrations.codex_mcp import (
    CodexMcpAdapter,
    codex_project_mcp_leftover,
    probe_project_config_load,
    read_bounded_toml,
)
from yoetz.adapters.integrations.codex_skill import CodexSkillIntegration
from yoetz.adapters.integrations.host_discovery import HostInstallation
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
    admission_cleanup_needed,
    admission_cleanup_plan,
    admission_revoke_arguments,
    plan_digest,
)
from yoetz.domain.values import request_id
from yoetz.ports.harness_mcp import HarnessBinary, McpRegistrationError, McpRegistrationReason
from yoetz.ports.integrations import (
    HarnessId,
    IntegrationAction,
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
        activation = inspect_activation(
            IntegrationTarget(IntegrationScope.TRUSTED_PROJECT, str(project)),
            executable_path=str(installation.executable),
            codex_home=installation.config_root,
        )
        if (
            activation.inventory_verified
            and activation.plugin_cached
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
                "configured": registration.route_profile == route,
                "connection_observed": False,
                "reload_required": True,
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
        )

        async def preview_mcp():
            return await service.preview_unregistration(binary)

        registration = anyio.run(preview_mcp)
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
        body["mcp_preview_digest"] = registration.preview_digest
        warnings: list[JsonValue] = list(registration.warnings)
        body["warnings"] = warnings
        body["retained"] = ["Yoetz data", "inactive project plugin sources"]
        body["changes"] = (
            [] if removal.outcome is RemovalOutcome.ALREADY_ABSENT else ["deactivate_plugin"]
        )
        if registration.action.value != "noop":
            cast(list[JsonValue], body["changes"]).append("remove_mcp_registration")
        if skill_preview.state_before is IntegrationState.INSTALLED_EXACT:
            cast(list[JsonValue], body["changes"]).append("remove_project_skill")
        # The project's admission table must go before the user-level transport does: a
        # trusted project's `[mcp_servers.yoetz.tools.check]` without a transport makes
        # Codex refuse to load configuration there (exec, mcp list, plugin list).
        sweep_admission = admission.plan(body, "codex", action)
        other_projects = _other_project_admissions(installation.config_root, project)
        if other_projects:
            admission.disclosure["admission_other_projects"] = other_projects
            warnings.append("admission_present_in_other_projects")

        def apply() -> None:
            nonlocal removal_report, config_load
            admission.apply(sweep_admission)
            apply_removal(
                target,
                approved_digest=removal.preview_digest,
                executable_path=str(installation.executable),
                codex_home=installation.config_root,
            )

            async def unregister():
                return await service.unregister(
                    binary,
                    McpRegistrationConfirmation(
                        registration.preview_digest, True, "noninteractive_flag"
                    ),
                )

            try:
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
                        "project_mcp_leftover": codex_project_mcp_leftover(
                            installation.config_root, project
                        ),
                        "next_arguments": cast(
                            list[JsonValue], admission_revoke_arguments("codex", project)
                        ),
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
                "enabled": current.outcome is not RemovalOutcome.ALREADY_ABSENT,
                "configured": observed.action.value != "noop",
                "connection_observed": False,
                "reload_required": True,
                "retained": body["retained"],
                "mcp_removal": removal_report,
                "project_config_load": config_load,
                **admission.status(),
            }

    body["preview_digest"] = plan_digest(body, admission.disclosure)
    return ConnectionPlan(body, status, apply, admission.disclosure)


_OTHER_PROJECTS_LIMIT = 32


def _other_project_admissions(codex_home: Path, project: Path) -> list[JsonValue]:
    """Codex projects, other than ``project``, that still carry a Yoetz admission table.

    Removing the user-level registration leaves such a table without a transport, and Codex
    then refuses to start there. The candidates are the projects this Codex home knows:
    its ``[projects."<path>"]`` trust entries and the Yoetz marketplace source.
    """

    config = read_bounded_toml(codex_home / "config.toml") or {}
    candidates: set[str] = set()
    projects = config.get("projects")
    if isinstance(projects, dict):
        candidates.update(str(key) for key in cast(dict[str, object], projects))
    marketplaces = config.get("marketplaces")
    if isinstance(marketplaces, dict):
        yoetz_market = cast(dict[str, object], marketplaces).get("yoetz")
        if isinstance(yoetz_market, dict):
            source = cast(dict[str, object], yoetz_market).get("source")
            if isinstance(source, str):
                candidates.add(source)
    found: list[JsonValue] = []
    for candidate in sorted(candidates)[:_OTHER_PROJECTS_LIMIT]:
        root = Path(candidate)
        if not root.is_absolute() or root == project or not root.is_dir():
            continue
        cleanup = admission_cleanup_plan("codex", root)
        if admission_cleanup_needed(cleanup):
            found.append(
                {
                    "project_root": str(root),
                    "next_arguments": cast(
                        list[JsonValue], admission_revoke_arguments("codex", root)
                    ),
                }
            )
    return found


def project_mcp_leftover_status(codex_home: Path, project: Path) -> dict[str, JsonValue]:
    """Explain a transport-less project ``mcp_servers.yoetz`` table and name its exact repair."""

    leftover = codex_project_mcp_leftover(codex_home, project)
    if leftover is None:
        return {}
    return {
        "project_mcp_leftover": leftover,
        "next_arguments": cast(list[JsonValue], admission_revoke_arguments("codex", project)),
    }
