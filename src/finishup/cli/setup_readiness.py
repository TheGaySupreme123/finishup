"""Read-only, recipe-specific setup continuation for one selected installation."""

from __future__ import annotations

import shlex
import sys
from pathlib import Path
from typing import Literal, cast

import anyio
import typer

from finishup.adapters.integrations.launcher import invoking_launcher, resolve_finishup_launcher
from finishup.cli.privacy_setup import configured_bindings, get_privacy_setup_snapshot
from finishup.config.paths import isolated_root
from finishup.protocol.canonical import JsonValue
from finishup.protocol.setup_readiness import SetupReadiness, SetupReadinessReason

type SetupOperation = Literal["local", "review", "connection"]


def continuation(arguments: list[str], *, project: Path | None = None) -> str:
    """Pin the invoking runtime and process-tree isolation, and shell-quote every value."""
    invocation = invoking_launcher()
    # Keep a module invocation's venv interpreter spelling: resolving its symlink
    # to the base Python would discard the selected installed package and runtime pin.
    launcher = (
        invocation
        if isinstance(invocation, tuple)
        else resolve_finishup_launcher(invocation)
        if invocation is not None
        else (sys.executable, "-m", "finishup")
    )
    root = isolated_root()
    command = [*launcher, *arguments]
    if root is not None:
        command = ["env", f"FINISHUP_ISOLATED_ROOT={root}", *command]
    rendered = shlex.join(command)
    return rendered if project is None else "cd " + shlex.quote(str(project)) + " && " + rendered


async def installation_readiness(project: Path, operation: SetupOperation) -> dict[str, JsonValue]:
    from finishup.cli.setup import _service_reachability  # pyright: ignore[reportPrivateUsage]

    service = await _service_reachability()
    result: dict[str, JsonValue] = {"service": service}
    if service.get("reachable") is not True:
        result.update(reason="service_unavailable", arguments=["service", "restart"])
    elif service.get("state") in {"starting", "unlocking", "draining", "failed"}:
        result.update(reason="service_not_ready", arguments=["service", "status"])
    elif service.get("vault_mode") == "uninitialized":
        result.update(reason="vault_uninitialized", arguments=["setup", "vault"])
    elif service.get("state") != "ready":
        result.update(reason="vault_locked", arguments=["service", "unlock"])
    else:
        try:
            snapshot = await get_privacy_setup_snapshot(project)
            result["repository_grant"] = snapshot.grant_state
        except Exception:
            result.update(reason="repository_privacy_scope_unavailable", arguments=["--privacy"])
            return result
        # A private grant may be established first; a provider-backed grant cannot.
        if operation == "review":
            try:
                external, _local = configured_bindings()
            except OSError, ValueError:
                external = None
            if external is None:
                result.update(reason="provider_binding_required", arguments=["--set"])
                return result
        if snapshot.grant_state != "granted":
            result.update(reason="repository_grant_required", arguments=["--privacy"])
        elif operation == "review":
            from finishup.domain.privacy import EgressChannel

            if not any(
                channel.enabled
                for channel in snapshot.composed_policy.channel_policies
                if channel.channel is EgressChannel.LLM_INFERENCE
            ):
                result.update(reason="review_permission_required", arguments=["--privacy"])
    return result


def _background_advice() -> dict[str, JsonValue] | None:
    """The configured background-advice switch and reason; unreadable config reports nothing."""

    import os

    from finishup.cli.provider_status import background_advice_facts
    from finishup.config.load import load_config
    from finishup.config.models import ConfigError

    try:
        return background_advice_facts(load_config({}, os.environ, None))
    except ConfigError, OSError, ValueError:
        return None


def setup_next(
    *,
    operation: SetupOperation,
    host: str | None,
    executable: Path | None,
    config_root: Path | None,
    project: Path,
    route: Literal["strict", "policy"],
    json_output: bool,
) -> int:
    """Evaluate only the selected recipe; connection alone needs no service/provider login."""
    from finishup.cli.host_connection import (
        CONNECTION_ERRORS,
        prepare_selected,
        select_installation,
    )
    from finishup.protocol.ids import IdKind, new_id

    facts = (
        {} if operation == "connection" else anyio.run(installation_readiness, project, operation)
    )
    if operation != "connection":
        advice = _background_advice()
        if advice is not None:
            facts["background_advice"] = advice
    arguments = cast(list[str] | None, facts.pop("arguments", None))
    reason = cast(SetupReadinessReason, str(facts.pop("reason", "ready")))
    selected_home: str | None = None
    if host is not None:
        try:
            selected = select_installation(host, executable, config_root)
            selected_home = str(selected.config_root)
            if arguments is None:
                plan = prepare_selected(
                    selected,
                    project,
                    action="connect",
                    route=route,
                    request_value=new_id(IdKind.REQUEST),
                )
                status = plan.status()
                facts["connection"] = status
                if not plan.unchanged:
                    reason = (
                        "installed_not_activated"
                        if status.get("installed") is True and status.get("enabled") is not True
                        else "connection_required"
                    )
                    # Produces a new preview; this command grants no unseen activation authority.
                    arguments = [
                        "setup",
                        "run",
                        "--host",
                        selected.host,
                        "--host-path",
                        str(selected.executable),
                        "--host-config-root",
                        selected_home,
                        "--project",
                        str(project),
                        "--route-profile",
                        route,
                    ]
        except CONNECTION_ERRORS:
            if arguments is None:
                reason = "connection_unavailable"
                arguments = ["setup", "status", "--host", host, "--project", str(project)]
                if executable is not None:
                    arguments.extend(("--host-path", str(executable)))
                if config_root is not None:
                    arguments.extend(("--host-config-root", str(config_root)))
    elif operation == "connection":
        reason = "host_selection_required"
        arguments = ["setup", "status"]
    report = SetupReadiness(
        schema="yoetz.setup-readiness/1",
        operation=operation,
        reason=reason,
        project=str(project),
        inspected_config_root=selected_home,
        next_command=None if arguments is None else continuation(arguments, project=project),
        facts=facts,
    )
    from finishup.cli.provider_status import background_advice_human_line

    advice_line = background_advice_human_line(facts.get("background_advice"))
    typer.echo(
        report.model_dump_json(by_alias=True)
        if json_output
        else (
            reason.replace("_", " ")
            + ("" if advice_line is None else "\nBackground AI-powered advice: " + advice_line)
            + (
                "\nNext: " + report.next_command
                if report.next_command
                else "\nSetup prerequisites are ready; native session and provider dispatch remain unverified."
            )
        )
    )
    return 0
