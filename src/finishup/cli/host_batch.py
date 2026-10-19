"""One exact approval over independently previewed host connections (#1119).

Single-host commands keep their released report and entrypoint. A batch never treats one
member's success as another's, and never carries approval across a partial apply.
"""

from __future__ import annotations

import json
import shlex
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast

import typer
from anyio.to_thread import run_sync

from finishup.adapters.integrations.host_discovery import HostInstallation
from finishup.application.host_connection import ConnectionAction, ConnectionError, ConnectionPlan
from finishup.cli import host_connection as single
from finishup.domain.values import request_id
from finishup.protocol.canonical import JsonValue, canonical_digest
from finishup.protocol.ids import IdKind, new_id

type Route = Literal["strict", "policy"]


async def on_host[T](installation: HostInstallation, operation: Callable[[], T]) -> T:
    # Codex's composition owns an AnyIO loop; PAM for the other hosts owns the main thread.
    return await run_sync(operation) if installation.host == "codex" else operation()


def select_batch_installation(
    host: str,
    executable: Path | None,
    config_root: Path | None,
) -> HostInstallation:
    if host == "codex" and executable is not None:
        return single.select_installation(
            host,
            executable,
            config_root,
            preserve_visible_name=True,
        )
    return single.select_installation(host, executable, config_root)


def select_installations(
    hosts: Sequence[str],
    executables: Sequence[Path] = (),
    config_roots: Sequence[Path] = (),
) -> tuple[HostInstallation, ...]:
    if "all" in hosts:
        if list(hosts) != ["all"] or executables or config_roots:
            raise ConnectionError("connection_batch_selection_invalid")
        selected = single.discover_hosts()
    else:
        if (executables and len(executables) != len(hosts)) or (
            config_roots and len(config_roots) != len(hosts)
        ):
            raise ConnectionError("connection_batch_selection_invalid")
        selected = tuple(
            select_batch_installation(
                host,
                executables[index] if executables else None,
                config_roots[index] if config_roots else None,
            )
            for index, host in enumerate(hosts)
        )
    if not selected:
        raise ConnectionError("connection_executable_required")
    # Discovery order, PATH order, and repeated flags cannot change the digest or apply order.
    unique = {(item.host, str(item.executable), str(item.config_root)): item for item in selected}
    return tuple(unique[key] for key in sorted(unique))


@dataclass(frozen=True, slots=True)
class BatchMember:
    installation: HostInstallation
    plan: ConnectionPlan
    refresh: Callable[[], ConnectionPlan]


class BatchPreparationError(ConnectionError):
    def __init__(self, reports: list[dict[str, JsonValue]], error: BaseException) -> None:
        super().__init__(error_reason(error))
        self.reports = reports


def batch_digest(members: Sequence[BatchMember]) -> str:
    rows: list[JsonValue] = [
        {
            "host": member.installation.host,
            "installation_path": str(member.installation.executable),
            "request_id": member.plan.body["request_id"],
            "preview_digest": member.plan.digest,
        }
        for member in sorted(
            members,
            key=lambda member: (
                member.installation.host,
                str(member.installation.executable),
                str(member.plan.body["request_id"]),
                member.plan.digest,
            ),
        )
    ]
    return canonical_digest(rows)


async def prepare_batch(
    installations: Sequence[HostInstallation],
    project: Path,
    *,
    action: ConnectionAction = "connect",
    route: Route | None = None,
    request_value: str,
    remove_shared: bool = False,
) -> tuple[BatchMember, ...]:
    members: list[BatchMember] = []
    for selected in installations:

        def prepare(selected: HostInstallation = selected) -> ConnectionPlan:
            return single.prepare_selected(
                selected,
                project,
                action=action,
                route=route,
                request_value=request_value,
                remove_shared=remove_shared,
            )

        try:
            members.append(BatchMember(selected, await on_host(selected, prepare), prepare))
        except single.CONNECTION_ERRORS as error:
            reports = [member_report(member, "not_attempted") for member in members]
            reports.append(unprepared_report(selected, action, "incomplete", error))
            reports.extend(
                unprepared_report(item, action, "not_attempted")
                for item in installations[len(members) + 1 :]
            )
            raise BatchPreparationError(reports, error) from error
    return tuple(members)


def batch_command(
    installations: Sequence[HostInstallation],
    project: Path,
    *,
    action: ConnectionAction,
    route: Route | None,
    remove_shared: bool = False,
    request_value: str | None = None,
    preview_digest: str | None = None,
    json_output: bool = False,
) -> str:
    launcher = single.invoking_launcher()
    if launcher is None:
        raise ConnectionError("connection_launcher_unavailable")
    command = [
        *single.resolve_finishup_launcher(launcher),
        "setup",
        "run" if action == "connect" else "disconnect",
    ]
    for selected in installations:
        command.extend(
            (
                "--host",
                selected.host,
                "--host-path",
                str(selected.executable),
                "--host-config-root",
                str(selected.config_root),
            )
        )
    command.extend(("--project", str(project)))
    if route is not None:
        command.extend(("--route-profile", route))
    if remove_shared:
        command.append("--remove-shared")
    if request_value is not None and preview_digest is not None:
        command.extend(
            ("--request-id", request_value, "--preview-digest", preview_digest, "--accept")
        )
    command.append("--non-interactive")
    if json_output:
        command.append("--json")
    command.append("--batch")
    return shlex.join(command)


def member_report(member: BatchMember, outcome: str) -> dict[str, JsonValue]:
    report: dict[str, JsonValue] = {
        "schema": "yoetz.host-connection-batch-member/1",
        "host": member.installation.host,
        "executable": str(member.installation.executable),
        "config_root": str(member.installation.config_root),
        "action": member.plan.body["action"],
        "connection_observed": False,
        "outcome": outcome,
        "plan": member.plan.body,
    }
    if member.plan.disclosure:
        report["status"] = single.rendered_status(member.plan.disclosure)
    return report


def unprepared_report(
    selected: HostInstallation,
    action: ConnectionAction,
    outcome: str,
    error: BaseException | None = None,
) -> dict[str, JsonValue]:
    row: dict[str, JsonValue] = {
        "schema": "yoetz.host-connection-batch-member/1",
        "host": selected.host,
        "executable": str(selected.executable),
        "config_root": str(selected.config_root),
        "action": action,
        "connection_observed": False,
        "outcome": outcome,
    }
    if error is not None:
        row["reason"] = error_reason(error)
        if isinstance(error, ConnectionError) and error.status is not None:
            row["status"] = single.rendered_status(error.status)
    return row


def error_reason(error: BaseException) -> str:
    # Only typed adapter reasons are public. OS exceptions and arbitrary text never become tokens.
    if isinstance(error, ConnectionError):
        return str(error)
    reason = getattr(error, "reason", None)
    if reason is not None:
        return str(getattr(reason, "value", reason))
    return "connection_unavailable"


async def apply_batch(members: Sequence[BatchMember]) -> list[dict[str, JsonValue]]:
    # Recompute *all* previews before the first mutation, including unchanged members.
    for index, member in enumerate(members):
        try:
            if (await on_host(member.installation, member.refresh)).digest != member.plan.digest:
                raise ConnectionError("connection_preview_stale")
        except single.CONNECTION_ERRORS as error:
            reports = [member_report(item, "not_attempted") for item in members]
            reports[index].update({"outcome": "incomplete", "reason": error_reason(error)})
            raise BatchPreparationError(reports, error) from error
    reports: list[dict[str, JsonValue]] = []
    failed = False
    for member in members:
        row = member_report(member, "not_attempted" if failed else "unchanged")
        reports.append(row)
        if failed:
            continue
        try:
            if member.plan.unchanged:
                # Another process may have changed this agent while an earlier member was being
                # applied; an unchanged preview is only true if it is still the same now.
                if (
                    await on_host(member.installation, member.refresh)
                ).digest != member.plan.digest:
                    raise ConnectionError("connection_preview_stale")
                status = await on_host(member.installation, member.plan.status)
            else:
                if member.plan.body.get("requires_os_presence") is not False:
                    typer.echo(
                        f"{member.installation.label}: operating-system authentication for this agent.",
                        err=True,
                    )
                status = await on_host(
                    member.installation, lambda: single.apply_selected(member.plan, member.refresh)
                )
                row["outcome"] = "completed"
            row["status"] = single.rendered_status(status)
            if member.plan.body["action"] == "connect":
                row["launch"] = single.launch_details(
                    member.installation, Path(str(member.plan.body["project_root"]))
                )
            steps = single.kept_pieces_steps(
                cast(ConnectionAction, member.plan.body["action"]),
                status,
                member.installation,
                Path(str(member.plan.body["project_root"])),
            )
            if steps:
                row["next_step"] = "\n".join(steps)
        except single.CONNECTION_ERRORS as error:
            row.update({"outcome": "incomplete", "reason": error_reason(error)})
            if isinstance(error, ConnectionError) and error.status is not None:
                row["status"] = single.rendered_status(error.status)
            row["next_step"] = (
                "Inspect status before retrying: this agent's connection may have changed partially."
            )
            failed = True
    return reports


def emit_batch(report: dict[str, JsonValue], *, json_output: bool) -> None:
    if json_output:
        typer.echo(json.dumps(report, sort_keys=True))
        return
    members = report.get("members")
    for row in members if isinstance(members, list) else []:
        if isinstance(row, dict):
            typer.echo(f"{row['host']}: {row['outcome']}")
            if "reason" in row:
                typer.echo(str(row["reason"]))
            launch = row.get("launch")
            if isinstance(launch, dict):
                typer.echo("Start a fresh session: " + str(launch["shell_command"]))
            if "next_step" in row:
                typer.echo(str(row["next_step"]))
    if "reason" in report:
        typer.echo(str(report["reason"]))
    if "next_step" in report:
        typer.echo(str(report["next_step"]))


async def run_host_batch(
    *,
    hosts: Sequence[str],
    project: Path,
    executables: Sequence[Path] = (),
    config_roots: Sequence[Path] = (),
    installations: Sequence[HostInstallation] | None = None,
    action: ConnectionAction = "connect",
    route: Route | None = None,
    accept: bool = False,
    interactive: bool = False,
    request_value: str | None = None,
    preview_digest: str | None = None,
    json_output: bool = False,
    status_only: bool = False,
    remove_shared: bool = False,
) -> int:
    report: dict[str, JsonValue] = {
        "schema": "yoetz.host-connection-batch-report/1",
        "action": action,
        "connection_observed": False,
        "members": [],
    }
    selected: tuple[HostInstallation, ...] = ()
    try:
        selected = (
            tuple(installations)
            if installations is not None
            else select_installations(hosts, executables, config_roots)
        )
        if action == "connect" and not status_only:
            single.refuse_unservable_runtime()
        request = request_value or new_id(IdKind.REQUEST)
        request_id(request)
        report["request_id"] = request
        if status_only:
            status_rows: list[dict[str, JsonValue]] = []
            failed = False
            for installation in selected:
                try:
                    (member,) = await prepare_batch(
                        (installation,),
                        project,
                        action=action,
                        route=route,
                        request_value=request,
                        remove_shared=remove_shared,
                    )
                    row = member_report(member, "status")
                    row["status"] = single.rendered_status(
                        await on_host(installation, member.plan.status)
                    )
                except single.CONNECTION_ERRORS as error:
                    row = unprepared_report(installation, action, "incomplete", error)
                    failed = True
                status_rows.append(row)
            report.update(
                {
                    "outcome": "incomplete" if failed else "status",
                    "members": cast(list[JsonValue], status_rows),
                }
            )
            emit_batch(report, json_output=json_output)
            return 1 if failed else 0
        members = await prepare_batch(
            selected,
            project,
            action=action,
            route=route,
            request_value=request,
            remove_shared=remove_shared,
        )
        digest = batch_digest(members)
        report["preview_digest"] = digest
        rows = [member_report(member, "preview") for member in members]
        report["members"] = cast(list[JsonValue], rows)
        report["outcome"] = "preview"
        report["next_step"] = batch_command(
            selected,
            project,
            action=action,
            route=route,
            remove_shared=remove_shared,
            request_value=request,
            preview_digest=digest,
            json_output=json_output,
        )
        if preview_digest is not None and preview_digest != digest:
            raise ConnectionError("connection_preview_stale")
        approved = accept and request_value is not None and preview_digest == digest
        if not json_output:
            for member in members:
                typer.echo(member.installation.label)
                for line in single.connection_summary(member.plan):
                    typer.echo(line)
                if member.installation.host == "codex" and "codex_plan" in member.plan.body:
                    from finishup.tui.models import IntegrationPlan
                    from finishup.tui.render import (
                        render_integration_preview,
                        render_integration_technical_details,
                    )

                    codex = IntegrationPlan(**cast(dict[str, Any], member.plan.body["codex_plan"]))
                    for line in (
                        *render_integration_preview(codex, 88),
                        *render_integration_technical_details(codex, 88),
                    ):
                        typer.echo(line)
        if interactive:
            approved = typer.confirm("Apply this combined connection plan?", default=False)
        if not approved:
            emit_batch(report, json_output=json_output)
            return 3 if accept or interactive else 0
        rows = await apply_batch(members)
        report["members"] = cast(list[JsonValue], rows)
        remaining = tuple(
            member.installation
            for member, row in zip(members, rows, strict=True)
            if row["outcome"] in {"incomplete", "not_attempted"}
        )
        if remaining:
            report["outcome"] = "incomplete"
            # A new preview, with no carried approval, covers just the failed/unattempted tail.
            report["next_step"] = batch_command(
                remaining,
                project,
                action=action,
                route=route,
                remove_shared=remove_shared,
                json_output=json_output,
            )
        else:
            report["outcome"] = "completed"
            report["next_step"] = (
                "Start a fresh session in each selected agent."
                if action == "connect"
                else "Restart the selected agents. FinishUP data was retained."
            )
        emit_batch(report, json_output=json_output)
        return 1 if remaining else 0
    except single.CONNECTION_ERRORS as error:
        report.update({"outcome": "incomplete", "reason": error_reason(error)})
        if isinstance(error, BatchPreparationError):
            report["members"] = cast(list[JsonValue], error.reports)
        if error_reason(error) == "connection_preview_stale":
            report["next_step"] = batch_command(
                selected,
                project,
                action=action,
                route=route,
                remove_shared=remove_shared,
                json_output=json_output,
            )
        if "next_step" not in report:
            report["next_step"] = (
                "Inspect setup status for the selected agents, resolve the reported reason, then request a fresh preview."
            )
        emit_batch(report, json_output=json_output)
        return 1
