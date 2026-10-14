"""Human-readable upgrade plan, with an explicitly accepted package-only action."""

from __future__ import annotations

import shlex
from collections.abc import Mapping, Sequence

import typer

from finishup.adapters.package_upgrade import execute_package_upgrade
from finishup.adapters.release_runtime import installation_prefix, prune_release_runtimes
from finishup.application.upgrade import HOSTS, build_upgrade_plan


def run_upgrade(
    *,
    hosts: Sequence[str] | None,
    options: Mapping[str, str],
    accept: bool,
    prune_runtimes: bool = False,
) -> int:
    if prune_runtimes:
        if accept:
            typer.echo("Choose either --accept or --prune-runtimes.", err=True)
            return 2
        try:
            removed, retained = prune_release_runtimes(installation_prefix())
        except OSError, ValueError:
            typer.echo(
                "Runtime cleanup could not safely complete; running sessions were not stopped.",
                err=True,
            )
            return 2
        typer.echo(f"Removed {removed} unused runtime copies; kept {retained} in use.")
        return 0
    try:
        steps = build_upgrade_plan(hosts or HOSTS, options)
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        return 2
    typer.echo("FinishUP upgrade — preserve existing configuration")
    for step in steps:
        typer.echo(f"\n{step.title}\n{step.detail}")
        if step.cwd:
            typer.echo(f"Working directory: {shlex.quote(step.cwd)}")
        for argv in step.commands:
            command = (
                ("env", *(f"{key}={value}" for key, value in step.environment), *argv)
                if step.environment
                else argv
            )
            typer.echo("  " + shlex.join(command))
    if not accept:
        typer.echo("\nPlan only. No package, host, service, data, or setting was changed.")
        return 0
    try:
        outcome = execute_package_upgrade()
    except OSError, ValueError:
        outcome = "runtime_identity_unavailable"
    typer.echo(f"\nPackage step: {outcome}")
    if outcome == "package_already_current":
        typer.echo("The fresh launcher reports the same version. No newer version was installed.")
        return 0
    if outcome == "refused_custom_uv_installation":
        typer.echo(
            "This installation has custom package sources, dependencies, or options. "
            "Update it through its original installation procedure to preserve those choices."
        )
        return 2
    if outcome != "package_command_succeeded":
        typer.echo("No full upgrade is claimed. Resolve the package step before continuing.")
        return 2
    typer.echo(
        "Open sessions keep working on the previous version; nothing needs to be stopped. When "
        "you next reopen your agent app (or start a new session), its first FinishUP call switches "
        "to the new version and retires the previous service automatically. A session left open "
        "from before may then ask to be reopened."
    )
    typer.echo(
        "Host refresh, migration and activation remain unverified. Re-run finishup upgrade with the "
        "same target options and follow the remaining stages. Do not repeat --accept merely to "
        "continue."
    )
    return 0
