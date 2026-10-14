"""Human and noninteractive entrypoints for the shared host connection plan."""

from __future__ import annotations

import json
import os
import shlex
from dataclasses import replace
from pathlib import Path
from typing import Literal, cast

import typer

from finishup.adapters.integrations.artifact_presence import select_artifact_user_presence
from finishup.adapters.integrations.claude_code_integration import ClaudeCodeIntegrationError
from finishup.adapters.integrations.cursor_integration import CursorIntegrationError
from finishup.adapters.integrations.host_discovery import (
    HostInstallation,
    SetupHost,
    discover_hosts,
    host_config_root,
    probe_version,
)
from finishup.adapters.integrations.launcher import invoking_launcher, resolve_finishup_launcher
from finishup.adapters.integrations.portable_plugin import ElevatedPortableArtifactReview
from finishup.application.host_connection import (
    ConnectionAction,
    ConnectionError,
    ConnectionPlan,
    apply_connection,
    prepare_connection,
)
from finishup.config.paths import ISOLATED_ROOT_ENV_NAMES, isolated_root
from finishup.domain.values import request_id
from finishup.ports.integrations import IntegrationError
from finishup.ports.plugin_artifacts import ArtifactAuthority, PluginArtifactError
from finishup.protocol.canonical import JsonValue
from finishup.protocol.ids import IdKind, new_id
from finishup.service.elevated_bootstrap import ElevatedBootstrapError
from finishup.tui.runtime import RuntimeError_

CONNECTION_ERRORS = (
    PluginArtifactError,
    ClaudeCodeIntegrationError,
    CursorIntegrationError,
    IntegrationError,
    ConnectionError,
    ElevatedBootstrapError,
    RuntimeError_,
    OSError,
    ValueError,
)
_POSTURE_ERRORS = (*CONNECTION_ERRORS, RuntimeError)


def installation_rows(project: Path | None = None) -> list[JsonValue]:
    rows: list[JsonValue] = []
    for item in discover_hosts():
        row: dict[str, JsonValue] = {
            "host": item.host,
            "label": item.label,
            "executable": str(item.executable),
            "version": item.version,
            "config_root": str(item.config_root),
            "support": item.support,
            "connection_observed": False,
            "activation_cues": None,
        }
        if item.host == "claude":
            row["activation_cues"] = claude_activation_cues(item, project)
        rows.append(row)
    return rows


def claude_activation_cues(
    installation: HostInstallation, project: Path | None = None
) -> dict[str, JsonValue] | None:
    """Read-only Claude activation posture for ``setup status`` (issue #789).

    Names whether the installation would launch FinishUP through the plugin or a bare MCP entry and
    whether any installed hook can deliver the SessionStart cue. A bare entry has no cue; the
    guided connection (``finishup setup run --host claude``) installs the plugin that carries one. ``None``
    means the posture could not be read, never that no registration exists.
    """

    from finishup.adapters.integrations.claude_code_integration import (
        observe_claude_code_activation_cues,
    )

    launcher: tuple[str, ...] | None = None
    invocation = invoking_launcher()
    if invocation is not None:
        try:
            launcher = resolve_finishup_launcher(invocation)
        except _POSTURE_ERRORS:
            launcher = None
    try:
        return observe_claude_code_activation_cues(
            project_root=(Path.cwd() if project is None else project).absolute(),
            claude_config_root=installation.config_root,
            finishup_launcher=launcher,
        ).as_json()
    except _POSTURE_ERRORS:
        return None


def select_installation(
    host: str, executable: Path | None = None, config_root: Path | None = None
) -> HostInstallation:
    if host == "cursor":
        matches = [item for item in discover_hosts() if item.host in {"cursor-ide", "cursor-cli"}]
        if len(matches) != 1:
            raise ConnectionError("choose_cursor_ide_or_cursor_cli")
        host = matches[0].host
    if host not in {"claude", "cursor-ide", "cursor-cli", "codex"}:
        raise ConnectionError(
            "choose_cursor_ide_or_cursor_cli" if host == "cursor" else "connection_host_invalid"
        )
    selected_host = cast(SetupHost, host)
    if executable is not None:
        candidate = executable.expanduser().resolve(strict=True)
        if not candidate.is_file() or not os.access(candidate, os.X_OK):
            raise ConnectionError("connection_executable_unavailable")
        version = probe_version(candidate)
        if version is None:
            raise ConnectionError("connection_version_unavailable")
        selected = HostInstallation(
            selected_host,
            candidate,
            version,
            host_config_root(selected_host),
            {
                "claude": "Claude Code",
                "cursor-ide": "Cursor IDE",
                "cursor-cli": "Cursor Agent CLI",
                "codex": "Codex",
            }[host],
        )
    else:
        matches = [item for item in discover_hosts() if item.host == host]
        if len(matches) != 1:
            raise ConnectionError("connection_executable_required")
        selected = matches[0]
    return (
        selected
        if config_root is None
        else replace(selected, config_root=config_root.expanduser().absolute())
    )


def connection_summary(plan: ConnectionPlan) -> tuple[str, ...]:
    body = plan.body
    warnings = body.get("warnings")
    removal_warning = (
        (
            "Keep other Codex configuration writers stopped during removal "
            "(host_remove_not_compare_and_swap).",
        )
        if isinstance(warnings, list) and "host_remove_not_compare_and_swap" in warnings
        else ()
    )
    return (
        f"Project: {body['project_root']}",
        f"Configuration: {body['config_root']}",
        "Review: "
        + (
            "local only"
            if body["route_profile"] == "strict"
            else "AI-powered review using your configured privacy policy"
        ),
        "Changes: "
        + ", ".join(str(item).replace("_", " ") for item in cast(list[JsonValue], body["changes"])),
        "Your host must open a fresh session to observe the connection.",
        "Observation and provider permissions are separate.",
        *removal_warning,
    )


def prepare_selected(
    installation: HostInstallation,
    project: Path,
    *,
    action: ConnectionAction,
    route: Literal["strict", "policy"],
    request_value: str,
) -> ConnectionPlan:
    if installation.host == "codex":
        from finishup.cli.codex_connection import prepare_codex_connection

        return prepare_codex_connection(
            installation, project, action=action, route=route, request_value=request_value
        )
    invocation = invoking_launcher()
    if invocation is None:
        raise ConnectionError("connection_launcher_unavailable")
    root = isolated_root()
    return prepare_connection(
        request_id(request_value),
        installation,
        project,
        action=action,
        route=route,
        launcher=resolve_finishup_launcher(invocation),
        isolation_root=None if root is None else str(root),
    )


def refuse_unservable_runtime() -> None:
    """Refuse a connect when this installation's runtime cannot serve the running account.

    Every host would launch this runtime and every launch would be refused (another account
    can write it, or another account owns the directory it runs from). Callers that render
    their own report name the token through ``cli.runtime_refusal.connect_refusal``.
    """

    from finishup.cli.runtime_refusal import connect_refusal

    if connect_refusal() is not None:
        raise ConnectionError("release_runtime_refused")


def apply_selected(plan: ConnectionPlan, refresh: object) -> dict[str, JsonValue]:
    """Prepare the one reviewed target only after exact integration acceptance.

    A connect is refused here too, whatever front end prepared it, when this installation's
    runtime cannot serve the running account; a disconnect is never refused for that.
    """
    from collections.abc import Callable

    from finishup.service.elevated_bootstrap import load_pending, prepare_pending

    if plan.body.get("action") == "connect":
        refuse_unservable_runtime()

    authority = None
    if not plan.unchanged and plan.body.get("requires_os_presence") is not False:
        pending = load_pending()
        if pending is None:
            pending = prepare_pending("plugin_artifact_apply", target_digest=plan.digest)
        if pending.operation != "plugin_artifact_apply" or pending.target_digest != plan.digest:
            raise ConnectionError("connection_other_approval_pending")
        authority = ArtifactAuthority("review_only", plan.digest, pending.pending_id)
    return apply_connection(
        plan,
        accepted_digest=plan.digest,
        refresh=cast(Callable[[], ConnectionPlan], refresh),
        authority=authority,
        review=ElevatedPortableArtifactReview(select_artifact_user_presence()),
    )


def run_host_connection(
    *,
    host: str,
    executable: Path | None,
    config_root: Path | None,
    project: Path,
    action: ConnectionAction = "connect",
    route: Literal["strict", "policy"] = "strict",
    accept: bool = False,
    interactive: bool = False,
    request_value: str | None = None,
    preview_digest: str | None = None,
    json_output: bool = False,
    status_only: bool = False,
) -> int:
    report: dict[str, JsonValue] = {
        "schema": "yoetz.host-connection-report/1",
        "host": host,
        "action": action,
        "connection_observed": False,
    }
    try:
        selected = select_installation(host, executable, config_root)
        report["host"] = selected.host
        if action == "connect" and not status_only:
            # The except branch below names the token and repair. Disconnect stays available.
            refuse_unservable_runtime()
        request = request_value or new_id(IdKind.REQUEST)

        def prepare() -> ConnectionPlan:
            return prepare_selected(
                selected, project, action=action, route=route, request_value=request
            )

        plan = prepare()
        report["plan"] = plan.body
        if status_only:
            report.update({"outcome": "status", "status": plan.status()})
            typer.echo(
                json.dumps(report, sort_keys=True)
                if json_output
                else f"{selected.label}: {report['status']}\nA fresh session is required to observe the connection."
            )
            return 0
        if preview_digest is not None and preview_digest != plan.digest:
            raise ConnectionError("connection_preview_stale")
        approved = accept and request_value is not None and preview_digest == plan.digest
        if interactive and not plan.unchanged:
            typer.echo(f"{'Connect' if action == 'connect' else 'Disconnect'} {selected.label}")
            for line in connection_summary(plan):
                typer.echo(line)
            approved = typer.confirm("Apply this connection plan?", default=False)
        if plan.unchanged:
            report.update({"outcome": "unchanged", "status": plan.status()})
            code = 0
        elif approved:
            report.update({"outcome": "completed", "status": apply_selected(plan, prepare)})
            code = 0
        else:
            report.update({"outcome": "preview", "next_step": connection_continuation(plan)})
            code = 3 if accept or interactive else 0
        if report["outcome"] in {"completed", "unchanged"}:
            launch = launch_details(selected, project)
            report["launch"] = launch
            report["next_step"] = (
                "Start a fresh session: " + str(launch["shell_command"])
                if action == "connect"
                else "Restart the selected host. FinishUP data was retained."
            )
    except CONNECTION_ERRORS as error:
        from finishup.adapters.integrations.cursor_project_mcp import CursorProjectMcpError

        reason = (
            error.reason.value
            if isinstance(
                error,
                (
                    PluginArtifactError,
                    ClaudeCodeIntegrationError,
                    CursorIntegrationError,
                    IntegrationError,
                ),
            )
            else error.reason
            if isinstance(error, (CursorProjectMcpError, ElevatedBootstrapError, RuntimeError_))
            else str(error)
            if isinstance(error, ConnectionError)
            else "connection_unavailable"
        )
        report.update(
            {
                "outcome": "incomplete",
                "reason": reason,
                "next_step": "Run the same setup command in a trusted local terminal; inspect status before retrying a partial connection.",
            }
        )
        if host == "codex" and reason in {"destination_conflict", "foreign_entry_present"}:
            report["next_step"] = (
                "The selected Codex home and foreign configuration were preserved. "
                "Create a fresh directory owned only by you (mode 0700), then rerun this "
                "setup command with --host-config-root pointing to that directory. "
                "For legacy Codex setup use --codex-home. If the conflict is in the "
                "project's marketplace, inspect that file first; a new home cannot repair it."
            )
        from finishup.cli.runtime_refusal import installed_runtime_refusal_text

        refusal = installed_runtime_refusal_text()
        if refusal is not None:
            # The launcher or runtime this host would run is writable by another account: a
            # host-specific symptom (launcher_unproven, target_unsafe) hides the one repair.
            report["reason"], text = refusal
            report["next_step"] = text.split(": ", 1)[1].rstrip("\n")
        if isinstance(error, ConnectionError) and error.status is not None:
            report["status"] = error.status
            next_command = error.status.get("next_command")
            if isinstance(next_command, str):
                report["next_step"] = (
                    "Inspect the selected registration before a fresh preview: " + next_command
                )
        code = 1
    if json_output:
        typer.echo(json.dumps(report, sort_keys=True))
    else:
        typer.echo(f"{host}: {report['outcome']}")
        status = report.get("status")
        if isinstance(status, dict):
            removal = status.get("mcp_removal")
            if isinstance(removal, dict):
                warnings = removal.get("warnings")
                if isinstance(warnings, list):
                    for warning in warnings:
                        typer.echo(str(warning))
        if "reason" in report:
            typer.echo(str(report["reason"]))
        if "next_step" in report:
            typer.echo(str(report["next_step"]))
    return code


def launch_details(installation: HostInstallation, project: Path) -> dict[str, JsonValue]:
    environment: dict[str, JsonValue] = {}
    invocation = invoking_launcher()
    if invocation is not None:
        # Canonical Codex hooks and agent-issued CLI commands use `finishup` on PATH.
        # Keep them on the same installation as the reviewed MCP registration.
        launcher = resolve_finishup_launcher(invocation)
        environment["PATH"] = (
            str(Path(launcher[0]).parent) + os.pathsep + os.environ.get("PATH", "")
        )
    command: list[JsonValue] = [str(installation.executable)]
    if installation.host == "codex":
        environment["CODEX_HOME"] = str(installation.config_root)
        environment["CODEX_TESTING_HOME"] = str(installation.config_root)
        command.extend(("--cd", str(project)))
    elif installation.host == "claude":
        environment["CLAUDE_CONFIG_DIR"] = str(installation.config_root)
    elif installation.host == "cursor-cli":
        environment["CURSOR_CONFIG_DIR"] = str(installation.config_root)
        command.extend(
            (
                "--workspace",
                str(project),
                "--plugin-dir",
                str(installation.config_root / "plugins/local/finishup"),
            )
        )
    else:
        command.extend(("--new-window", str(project)))
    root = isolated_root()
    if root is not None:
        # Both spellings with one value (ADR-048): a host that resolves an older ``yoetz``
        # launcher through PATH stays on this isolated root too (#604).
        for name in ISOLATED_ROOT_ENV_NAMES:
            environment[name] = str(root)
    arguments = [
        "env",
        *(f"{key}={value}" for key, value in environment.items()),
        *(str(item) for item in command),
    ]
    return {
        "command": command,
        "environment": environment,
        "cwd": str(project),
        "shell_command": "cd " + shlex.quote(str(project)) + " && " + shlex.join(arguments),
    }


def connection_continuation(plan: ConnectionPlan) -> str:
    """Retain the selected instance, host, project and exact approval on handover."""
    launcher = invoking_launcher()
    if launcher is None:
        raise ConnectionError("connection_launcher_unavailable")
    body = plan.body
    command = [
        *resolve_finishup_launcher(launcher),
        "setup",
        "run" if body["action"] == "connect" else "disconnect",
        "--host",
        str(body["host"]),
        "--host-path",
        str(body["executable"]),
        "--host-config-root",
        str(body["config_root"]),
        "--project",
        str(body["project_root"]),
        "--route-profile",
        str(body["route_profile"]),
        "--request-id",
        str(body["request_id"]),
        "--preview-digest",
        plan.digest,
        "--accept",
        "--non-interactive",
    ]
    return shlex.join(command)
