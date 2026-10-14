"""Adapt the existing Codex setup composition to the common connection report."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Literal, cast

import anyio

from finishup.adapters.integrations.codex_marketplace import (
    RemovalOutcome,
    apply_removal,
    inspect_activation,
    preview_removal,
)
from finishup.adapters.integrations.codex_mcp import CodexMcpAdapter
from finishup.adapters.integrations.codex_skill import CodexSkillIntegration
from finishup.adapters.integrations.host_discovery import HostInstallation
from finishup.application.harness_mcp import (
    HarnessMcpService,
    McpRegistrationConfirmation,
    mcp_removal_report,
)
from finishup.application.host_connection import ConnectionAction, ConnectionError, ConnectionPlan
from finishup.domain.values import request_id
from finishup.ports.harness_mcp import HarnessBinary, McpRegistrationError, McpRegistrationReason
from finishup.ports.integrations import (
    HarnessId,
    IntegrationAction,
    IntegrationScope,
    IntegrationState,
    IntegrationTarget,
    SkillApplyCommand,
    SkillPreviewCommand,
)
from finishup.protocol.canonical import JsonValue, canonical_digest
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
    route: Literal["policy", "strict"],
    request_value: str,
) -> ConnectionPlan:
    runtime = FinishUpRuntime(cwd=project)
    option = HarnessOption(
        str(installation.executable), installation.version, installation.label, ""
    )
    binary = HarnessBinary(
        HarnessId.CODEX, str(installation.executable), installation.version, "untested"
    )
    service = HarnessMcpService(
        CodexMcpAdapter(route_profile=route, codex_home=installation.config_root)
    )
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
        # A Yoetz-era registration or activation is migrated by the same approved apply, so it
        # keeps the connection from reading as already complete (ADR-048).
        legacy_registration_owned = observed.legacy_registration in _OWNED_LEGACY_REGISTRATIONS
        legacy_trees = _legacy_tree_changes(legacy.project_root, legacy.managed_paths)
        if (
            activation.inventory_verified
            and activation.plugin_cached
            and legacy.already_registered
            and observed.route_profile == route
            and not legacy_registration_owned
            and not activation.legacy_activation
            and not legacy_trees
        ):
            body["changes"] = []
        if legacy_registration_owned:
            cast(list[JsonValue], body["changes"]).append("migrate_legacy_mcp_registration")
        if activation.legacy_activation:
            cast(list[JsonValue], body["changes"]).append("migrate_legacy_plugin")
        cast(list[JsonValue], body["changes"]).extend(legacy_trees)
        if observed.legacy_registration == "foreign":
            body["warnings"] = ["legacy_registration_foreign"]

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
            return {
                "installed": current.plugin_cached,
                "enabled": current.plugin_enabled,
                "configured": registration.route_profile == route,
                "legacy_activation": current.legacy_activation,
                "legacy_registration": registration.legacy_registration,
                "connection_observed": False,
                "reload_required": True,
            }
    else:
        removal_report: dict[str, JsonValue] | None = None
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
        # A marker-consistent Yoetz-era ``.agents/skills/yoetz`` goes with the same approved
        # removal, including when it is the only skill tree left (ADR-048).
        legacy_skill_owned = "legacy_skill_tree_owned" in skill_preview.warnings
        skill_remove_planned = (
            skill_preview.state_before is IntegrationState.INSTALLED_EXACT or legacy_skill_owned
        )
        body["skill_preview_digest"] = skill_preview.preview_digest
        body["plugin_preview_digest"] = removal.preview_digest
        body["mcp_preview_digest"] = registration.preview_digest
        body["warnings"] = list(registration.warnings)
        body["retained"] = ["FinishUP data", "inactive project plugin sources"]
        body["changes"] = (
            [] if removal.outcome is RemovalOutcome.ALREADY_ABSENT else ["deactivate_plugin"]
        )
        if registration.action.value != "noop":
            cast(list[JsonValue], body["changes"]).append("remove_mcp_registration")
        if registration.legacy_registration in _OWNED_LEGACY_REGISTRATIONS:
            cast(list[JsonValue], body["changes"]).append("remove_legacy_mcp_registration")
        if removal.legacy_removed_block or removal.legacy_cache_versions:
            cast(list[JsonValue], body["changes"]).append("deactivate_legacy_plugin")
        if skill_preview.state_before is IntegrationState.INSTALLED_EXACT:
            cast(list[JsonValue], body["changes"]).append("remove_project_skill")
        if legacy_skill_owned:
            cast(list[JsonValue], body["changes"]).append("remove_legacy_project_skill")

        def apply() -> None:
            nonlocal removal_report
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
                "legacy_registration": observed.legacy_registration,
                "connection_observed": False,
                "reload_required": True,
                "retained": body["retained"],
                "mcp_removal": removal_report,
            }

    body["preview_digest"] = canonical_digest(body)
    return ConnectionPlan(body, status, apply)
