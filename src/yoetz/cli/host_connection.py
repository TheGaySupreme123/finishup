"""Human and noninteractive entrypoints for the shared host connection plan."""

from __future__ import annotations

import json
import os
import shlex
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import Literal, cast

import typer

from yoetz.adapters.integrations.artifact_presence import select_artifact_user_presence
from yoetz.adapters.integrations.claude_code_integration import ClaudeCodeIntegrationError
from yoetz.adapters.integrations.cursor_integration import CursorIntegrationError
from yoetz.adapters.integrations.host_discovery import (
    HostInstallation,
    SetupHost,
    discover_hosts,
    host_config_root,
    probe_version,
)
from yoetz.adapters.integrations.launcher import invoking_launcher, resolve_yoetz_launcher
from yoetz.adapters.integrations.portable_plugin import ElevatedPortableArtifactReview
from yoetz.application.host_connection import (
    ConnectionAction,
    ConnectionError,
    ConnectionPlan,
    apply_connection,
    prepare_connection,
)
from yoetz.cli.setup_readiness import continuation
from yoetz.config.paths import isolated_root
from yoetz.domain.values import request_id
from yoetz.ports.harness_mcp import MCP_SERVER_NAME
from yoetz.ports.integrations import IntegrationError, IntegrationReason
from yoetz.ports.plugin_artifacts import ArtifactAuthority, PluginArtifactError
from yoetz.protocol.canonical import JsonValue
from yoetz.protocol.ids import IdKind, new_id
from yoetz.service.elevated_bootstrap import ElevatedBootstrapError
from yoetz.tui.runtime import RuntimeError_

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

    Names whether the installation would launch Yoetz through the plugin or a bare MCP entry and
    whether any installed hook can deliver the SessionStart cue. A bare entry has no cue; the
    guided connection (``yoetz setup run --host claude``) installs the plugin that carries one. ``None``
    means the posture could not be read, never that no registration exists.
    """

    from yoetz.adapters.integrations.claude_code_integration import (
        observe_claude_code_activation_cues,
    )

    launcher: tuple[str, ...] | None = None
    invocation = invoking_launcher()
    if invocation is not None:
        try:
            launcher = resolve_yoetz_launcher(invocation)
        except _POSTURE_ERRORS:
            launcher = None
    try:
        return observe_claude_code_activation_cues(
            project_root=(Path.cwd() if project is None else project).absolute(),
            claude_config_root=installation.config_root,
            yoetz_launcher=launcher,
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
    body = {**plan.body, **plan.disclosure}
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
        *_shared_summary(body),
        *_admission_summary(body),
    )


_REVIEW_MODES: dict[str, str] = {
    "strict": "local only",
    "policy": "AI-powered review using your configured privacy policy",
}


def _shared_summary(body: dict[str, JsonValue]) -> tuple[str, ...]:
    """Name the other projects that share this configuration's Yoetz pieces (#1058)."""

    lines: list[str] = []
    if body.get("remove_shared") is True:
        # A home-wide disconnect is the one consent that ends Yoetz for other projects: say so
        # and name them before the approval (#1058 review P2-7).
        removed = body.get("shared_removed_from")
        names = (
            ", ".join(str(item) for item in removed)
            if isinstance(removed, list) and removed
            else ""
        )
        lines.append(
            "Home-wide disconnect (--remove-shared): this removes Yoetz's shared pieces from this "
            "agent configuration for every project"
            + (f", so these connected projects stop using Yoetz too: {names}" if names else "")
            + ". Their own project files stay."
        )
    if body.get("membership_unknown") is True:
        lines.append(
            "Yoetz cannot confirm every project that uses its shared pieces here (they were set "
            "up before it recorded connected projects, its record was lost, or projects it "
            "connected are missing from the record), so an ordinary disconnect keeps them. Only "
            "--remove-shared removes them for every project."
        )
    possible = body.get("possible_users")
    if isinstance(possible, list) and possible:
        lines.append(
            "Projects that may use them (connected earlier by this installation of Yoetz, or "
            "trusted checkouts with Yoetz's plugin files; not verified connections): "
            + ", ".join(str(item) for item in possible)
        )
    unserved = body.get("members_not_serving")
    if isinstance(unserved, list) and unserved:
        lines.append(
            "Connected projects whose Yoetz plugin files are missing right now lose the shared "
            "pieces too (connect them again later to restore them): "
            + ", ".join(str(item) for item in unserved)
        )
    rebind = body.get("rebind_to")
    if isinstance(rebind, str):
        lines.append(f"The shared Codex marketplace binding moves to {rebind}.")
    others = body.get("shared_with")
    if isinstance(others, list) and others:
        names = ", ".join(str(item) for item in others)
        lines.append(
            "Other connected projects keep using the shared Yoetz pieces, so only this "
            f"project's pieces are removed: {names}"
            if body.get("action") == "disconnect"
            else "This configuration already serves other connected projects, which keep "
            f"working: {names}"
        )
    route_line = _route_change_line(body)
    if route_line is not None:
        lines.append(route_line)
    return tuple(lines)


def _route_change_line(body: dict[str, JsonValue]) -> str | None:
    """One sentence naming the other projects whose shared review mode this plan changes."""

    before = body.get("route_profile_before")
    after = body.get("route_profile")
    changed = body.get("route_changes_for")
    possible = body.get("route_changes_possible_for")
    named = [
        *(str(item) for item in (changed if isinstance(changed, list) else [])),
        *(f"{item} (may use Yoetz)" for item in (possible if isinstance(possible, list) else [])),
    ]
    if (
        not named
        or not isinstance(before, str)
        or not isinstance(after, str)
        or before not in _REVIEW_MODES
        or after not in _REVIEW_MODES
        or before == after
    ):
        return None
    return (
        "The review mode is shared by every project using this agent configuration: this "
        f"changes it from {_REVIEW_MODES[before]} to {_REVIEW_MODES[after]} for these "
        "projects too: " + ", ".join(named)
    )


def _admission_summary(body: dict[str, JsonValue]) -> tuple[str, ...]:
    lines: list[str] = []
    changes = body.get("changes")
    if isinstance(changes, list) and "remove_project_admission" in changes:
        lines.append(
            "This project's Yoetz tool-approval entry is removed first, so the host still "
            "loads its configuration here afterwards."
        )
    others = body.get("admission_other_projects")
    if isinstance(others, list) and others:
        lines.append(
            "The Yoetz MCP registration stays: these projects' Codex configuration names the "
            "Yoetz server without a transport of its own (or could not be read), and removing "
            "the registration could stop Codex loading there:"
        )
        for item in others:
            if not isinstance(item, dict):
                continue
            lines.append(f"  {item.get('project_root')}")
            if isinstance(item.get("next_arguments"), list):
                lines.append(
                    "    to release it, revoke that project's approval entry: "
                    + continuation([str(a) for a in cast(list[JsonValue], item["next_arguments"])])
                )
    inspected = body.get("admission_other_projects_inspected")
    if isinstance(inspected, int):
        lines.append(
            f"Only {inspected} of {body.get('admission_other_projects_known')} projects this "
            "Codex home knows were checked; others may also use the registration, so it stays."
        )
    return tuple(lines)


def _rendered_disclosure(disclosure: dict[str, JsonValue]) -> dict[str, JsonValue]:
    rendered = dict(disclosure)
    others = rendered.get("admission_other_projects")
    if isinstance(others, list):
        rendered["admission_other_projects"] = [
            _rendered_status(item) if isinstance(item, dict) else item for item in others
        ]
    return rendered


def _rendered_status(status: dict[str, JsonValue]) -> dict[str, JsonValue]:
    """Render structural ``next_arguments`` through the pinned launcher continuation."""

    arguments = status.get("next_arguments")
    if not isinstance(arguments, list):
        return status
    rendered = {key: value for key, value in status.items() if key != "next_arguments"}
    rendered["next_command"] = continuation([str(item) for item in arguments])
    return rendered


def _codex_leftover(config_root: Path | None, project: Path) -> dict[str, JsonValue]:
    from yoetz.cli.codex_connection import project_mcp_leftover_status

    try:
        selected = config_root.expanduser().absolute() if config_root is not None else None
        return _rendered_status(
            project_mcp_leftover_status(
                selected if selected is not None else host_config_root("codex"), project
            )
        )
    except OSError, ValueError:
        return {}


def _duplicate_step(host: str, config_root: Path | None, project: Path) -> str:
    arguments = ["setup", "disconnect", "--host", host]
    if config_root is not None:
        arguments += ["--host-config-root", str(config_root.expanduser().absolute())]
    return (
        "This host configuration already connects this project directory under a different "
        "path (a symlink, a different letter case, or the path it had before it moved). One "
        "directory is connected once per configuration, so a second entry was refused. To "
        "connect it under this path, disconnect it first (that also removes the entry under "
        "the other path), then rerun this command: "
        + continuation([*arguments, "--project", str(project)])
        + (
            " If that disconnect reports the project's Yoetz MCP entry as foreign, it still "
            "names the old path: remove the Yoetz entry from this project's .cursor/mcp.json "
            "first."
            if host.startswith("cursor")
            else ""
        )
    )


def _membership_status_step(
    status: dict[str, JsonValue], selected: HostInstallation, project: Path
) -> str | None:
    """Status-only explanation of unknown membership with the exact home-wide preview."""

    if status.get("membership_unknown") is not True:
        return None
    possible = status.get("codex_home_possible_projects")
    summary = " ".join(_shared_summary({"membership_unknown": True}))
    if isinstance(possible, list) and possible:
        summary += " Projects that may use them: " + ", ".join(str(item) for item in possible) + "."
    command = continuation(
        [
            "setup",
            "disconnect",
            "--host",
            selected.host,
            "--host-path",
            str(selected.executable),
            "--host-config-root",
            str(selected.config_root),
            "--project",
            str(project),
            "--remove-shared",
        ]
    )
    return (
        f"{summary} Connecting the projects you use records them; that alone does not show no "
        f"other project uses the shared pieces. To preview removing them for every project: {command}"
    )


def _registered_codex_route(home: Path) -> str | None:
    """The review mode of the home's Yoetz MCP registration, read from its config (or None)."""

    from yoetz.adapters.integrations.codex_mcp import read_bounded_toml

    try:
        config = read_bounded_toml(home / "config.toml") or {}
    except OSError, ValueError:
        return None
    servers = config.get("mcp_servers")
    entry = (
        cast(Mapping[str, object], servers).get(MCP_SERVER_NAME)
        if isinstance(servers, Mapping)
        else None
    )
    args = cast(Mapping[str, object], entry).get("args") if isinstance(entry, Mapping) else None
    if not isinstance(args, list):
        return None
    words = [str(item) for item in cast(list[object], args)]
    if "serve" not in words:
        return None
    return "strict" if words[-2:] == ["--semantic", "off"] else "policy"


def _codex_unverified_step(
    config_root: Path | None, project: Path, selected: HostInstallation | None = None
) -> str:
    """Continuation when only unverified projects might still use the shared pieces.

    The commands name the selected Codex executable and home (Codex may not be on PATH), and
    the reconnect keeps the home's current review mode, which every project shares.
    """

    from yoetz.adapters.integrations.codex_marketplace import possible_projects

    try:
        home = (
            selected.config_root
            if selected is not None
            else config_root.expanduser().absolute()
            if config_root is not None
            else host_config_root("codex")
        )
        possible = possible_projects(home)
    except OSError, ValueError, IntegrationError:
        home, possible = None, ()
    names = ", ".join(possible) if possible else "other projects"
    target = [
        *(["--host-path", str(selected.executable)] if selected is not None else []),
        *(["--host-config-root", str(home)] if home is not None else []),
    ]
    route = None if home is None else _registered_codex_route(home)
    keep_route = ["--route-profile", route] if route is not None else []
    return (
        "Nothing was changed. Yoetz's record of the projects connected to this Codex home does "
        "not name these projects, but this installation of Yoetz connected them earlier or they "
        "are trusted checkouts that carry Yoetz's plugin files, so they may still use its shared "
        f"pieces: {names}. None of them is a verified connection now, so Yoetz will not move the "
        "shared marketplace to one or remove what they use. If you use Yoetz in one of them, "
        "connect it again (this records it), then rerun this disconnect: "
        + continuation(
            [
                "setup",
                "run",
                "--host",
                "codex",
                *target,
                *keep_route,
                "--project",
                "<that project>",
            ]
        )
        + ". If none of them uses Yoetz, preview removing the shared pieces for every project: "
        + continuation(
            [
                "setup",
                "disconnect",
                "--host",
                "codex",
                *target,
                "--project",
                str(project),
                "--remove-shared",
            ]
        )
    )


def _selected_root(host: str, config_root: Path | None) -> Path | None:
    try:
        return (
            config_root.expanduser().absolute()
            if config_root is not None
            else host_config_root(cast(SetupHost, host))
        )
    except OSError, ValueError, RuntimeError:
        return None


def _lock_unavailable_step(host: str, config_root: Path | None) -> str:
    """The setup lock could not be taken; nothing was changed (#1058)."""

    from yoetz.adapters.integrations.host_projects import lock_path_for

    root = _selected_root(host, config_root)
    try:
        folder = None if root is None else str(lock_path_for(root).parent)
    except OSError, ValueError, RuntimeError:
        folder = None
    where = f" ({folder})" if folder is not None else ""
    return (
        "Nothing was changed. Yoetz could not take its private setup lock for this agent "
        f"configuration. The lock lives in Yoetz's own state folder{where}, which must be a "
        "local folder you own (mode 0700) with no symlinked parts, on a filesystem that supports "
        "file locks. Fix that, then rerun this command."
    )


def _record_unreadable(host: str, config_root: Path | None) -> bool:
    """Whether this host configuration's connected-projects record exists and is refused."""

    from yoetz.adapters.integrations.host_projects import (
        CONNECTED_PROJECTS_FILE,
        HostProjectsError,
        load_connected_projects,
    )

    if host not in {"codex", "cursor-ide", "cursor-cli"}:
        return False
    root = _selected_root(host, config_root)
    if root is None or not os.path.lexists(root / CONNECTED_PROJECTS_FILE):
        return False
    try:
        load_connected_projects(root)
    except HostProjectsError:
        return True
    return False


def _record_invalid_step(host: str, config_root: Path | None) -> str:
    """The connected-projects record cannot be trusted; nothing was changed (#1058)."""

    from yoetz.adapters.integrations.host_projects import CONNECTED_PROJECTS_FILE

    root = _selected_root(host, config_root)
    record = str(root / CONNECTED_PROJECTS_FILE) if root is not None else CONNECTED_PROJECTS_FILE
    common = (
        "Nothing was changed. Yoetz's record of the projects connected to this agent "
        f"configuration ({record}) is not a regular file that only you can read and write with "
        "valid content, so Yoetz cannot tell which other projects use the shared pieces. If only "
        f"its permissions changed, make it yours and owner-only again (chmod 600 {record}) and "
        "rerun this command. If you have a copy, restore it. "
    )
    if host == "codex":
        return common + (
            "If its content is damaged, remove it, then run setup again for every project that "
            "uses Yoetz with this Codex home, before you disconnect any of them: that records "
            "them. Until then a disconnect keeps the shared pieces for the projects this "
            "installation of Yoetz connected and for trusted checkouts that carry Yoetz's plugin "
            "files, and stops (membership_unverified) rather than remove what they may use. A "
            "project connected only through another Yoetz installation is not detected."
        )
    return common + (
        "If its content is damaged, remove it: Yoetz then treats the projects using this "
        "configuration as unknown and keeps the shared plugin on an ordinary disconnect, and "
        "running setup again for each project you use records it."
    )


def _codex_duplicate_step(config_root: Path | None, project: Path) -> str:
    """Name the path that already connects this directory, and the two ways forward (#1058)."""

    from yoetz.adapters.integrations.codex_marketplace import project_registered_elsewhere

    try:
        home = (
            config_root.expanduser().absolute()
            if config_root is not None
            else host_config_root("codex")
        )
        existing = project_registered_elsewhere(home, project)
    except OSError, ValueError:
        home, existing = None, None
    if existing is None or home is None:
        return (
            "This Codex home already connects this project directory under a different path "
            "(a symlink, a different letter case, or the path it had before it moved). One "
            "directory is connected once per Codex home: disconnect this project first (that "
            "also removes the other entry), then rerun this command."
        )
    disconnect = continuation(
        [
            "setup",
            "disconnect",
            "--host",
            "codex",
            "--host-config-root",
            str(home),
            "--project",
            str(project),
        ]
    )
    return (
        f"This Codex home already connects this project directory as {existing}, a different "
        "path to the same directory (a symlink, a different letter case, or the path it had "
        "before it moved). One directory is connected once per Codex home, so a second entry "
        "was refused. To connect it under this path, disconnect it first (that also removes "
        f"the entry under the other path), then rerun this command: {disconnect}"
    )


def _leftover_next_step(status: dict[str, JsonValue]) -> str | None:
    leftover = status.get("project_mcp_leftover")
    if leftover == "tools_only":
        return (
            "This project's .codex/config.toml keeps a Yoetz tool-approval table for a server "
            "that is no longer registered, so Codex cannot load its configuration here. Revoke "
            "it, then accept the shown digest: " + str(status.get("next_command"))
        )
    if leftover == "retained_tables":
        return (
            "This project's .codex/config.toml keeps [mcp_servers."
            + MCP_SERVER_NAME
            + "] tables that Yoetz did not write (or that were edited), for a server that is no "
            "longer registered, so Codex cannot load its configuration here. Yoetz does not "
            "edit them. Either remove those tables from that file yourself, or connect the "
            "project again so the server is registered: " + str(status.get("next_command"))
        )
    return None


def _refusal_step(reason: str, status: dict[str, JsonValue]) -> str | None:
    """Plain-language continuation for a disconnect that stopped before changing anything."""

    if reason == "connection_admission_cleanup_failed":
        surfaces = status.get("admission_unreadable_surfaces")
        named = (
            ", ".join(str(item) for item in surfaces)
            if isinstance(surfaces, list) and surfaces
            else "its tool-approval file"
        )
        return (
            f"Nothing was changed. This project's {named} could not be read safely (a symlink, "
            "an unreadable or oversized file, or invalid syntax), so Yoetz cannot remove its "
            "approval entry there, and removing the registration under it could stop the host "
            "loading this project. Make it a regular file you own with valid syntax (or remove "
            "the Yoetz entries from it yourself), then rerun this command."
        )
    if reason == "connection_project_mcp_tables_retained":
        return (
            "Nothing was changed. "
            + str(status.get("project_mcp_retained"))
            + " keeps [mcp_servers."
            + MCP_SERVER_NAME
            + "] tables that Yoetz did not write or that were edited (for example your own "
            "tools.* approval settings or comments inside the Yoetz table). They need the Yoetz "
            "MCP registration this disconnect would remove, and Codex would then refuse to load "
            "this project. Remove or move those tables yourself, then rerun this command; or "
            "keep Yoetz connected."
        )
    if reason == "connection_other_projects_need_registration":
        partial = isinstance(status.get("admission_other_projects_known"), int)
        return " ".join(
            part
            for part in (
                "Nothing was changed.",
                "Other projects' Codex configuration uses the Yoetz MCP registration (listed "
                "in status), so removing it for every project would stop Codex loading there. "
                "Revoke or remove their Yoetz approval tables first (status shows the command "
                "where Yoetz can do it), or disconnect without --remove-shared."
                if status.get("admission_other_projects")
                else "",
                f"Only {status.get('admission_other_projects_inspected')} of "
                f"{status.get('admission_other_projects_known')} projects this Codex home "
                "knows were checked, so removing the registration for every project cannot be "
                "shown safe. Remove trust entries for projects you no longer use from the "
                "Codex home's config.toml, or disconnect without --remove-shared."
                if partial
                else "",
            )
            if part
        )
    return None


def prepare_selected(
    installation: HostInstallation,
    project: Path,
    *,
    action: ConnectionAction,
    route: Literal["strict", "policy"],
    request_value: str,
    remove_shared: bool = False,
) -> ConnectionPlan:
    if installation.host == "codex":
        from yoetz.cli.codex_connection import prepare_codex_connection

        return prepare_codex_connection(
            installation,
            project,
            action=action,
            route=route,
            request_value=request_value,
            remove_shared=remove_shared,
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
        launcher=resolve_yoetz_launcher(invocation),
        isolation_root=None if root is None else str(root),
        remove_shared=remove_shared,
    )


def apply_selected(plan: ConnectionPlan, refresh: object) -> dict[str, JsonValue]:
    """Prepare the one reviewed target only after exact integration acceptance."""
    from collections.abc import Callable

    from yoetz.service.elevated_bootstrap import load_pending, prepare_pending

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
    remove_shared: bool = False,
) -> int:
    report: dict[str, JsonValue] = {
        "schema": "yoetz.host-connection-report/1",
        "host": host,
        "action": action,
        "connection_observed": False,
    }
    chosen: HostInstallation | None = None
    try:
        selected = select_installation(host, executable, config_root)
        chosen = selected
        report["host"] = selected.host
        if action == "connect" and not status_only:
            from yoetz.cli.runtime_refusal import installed_runtime_refusal_text

            if installed_runtime_refusal_text() is not None:
                # Every host would launch this runtime and every launch would be refused; the
                # except branch below names the token and repair. Disconnect stays available.
                raise ConnectionError("release_runtime_refused")
        request = request_value or new_id(IdKind.REQUEST)

        def prepare() -> ConnectionPlan:
            return prepare_selected(
                selected,
                project,
                action=action,
                route=route,
                request_value=request,
                remove_shared=remove_shared,
            )

        plan = prepare()
        report["plan"] = plan.body
        if status_only:
            report.update({"outcome": "status", "status": _rendered_status(plan.status())})
            leftover_step = _leftover_next_step(cast(dict[str, JsonValue], report["status"]))
            if leftover_step is not None:
                report["next_step"] = leftover_step
            membership_step = _membership_status_step(
                cast(dict[str, JsonValue], report["status"]), selected, project
            )
            if membership_step is not None:
                report["next_step"] = (
                    membership_step
                    if leftover_step is None
                    else f"{leftover_step}\n{membership_step}"
                )
            typer.echo(
                json.dumps(report, sort_keys=True)
                if json_output
                else f"{selected.label}: {report['status']}\nA fresh session is required to observe the connection."
                + (f"\n{report['next_step']}" if "next_step" in report else "")
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
            report.update(
                {"outcome": "completed", "status": _rendered_status(apply_selected(plan, prepare))}
            )
            code = 0
        else:
            report.update({"outcome": "preview", "next_step": connection_continuation(plan)})
            if plan.disclosure:
                # The released plan schema is closed; preview facts beyond it ride in `status`.
                report["status"] = _rendered_disclosure(plan.disclosure)
            code = 3 if accept or interactive else 0
        if report["outcome"] in {"completed", "unchanged"}:
            launch = launch_details(selected, project)
            report["launch"] = launch
            report["next_step"] = (
                "Start a fresh session: " + str(launch["shell_command"])
                if action == "connect"
                else "Restart the selected host. Yoetz data was retained."
            )
    except CONNECTION_ERRORS as error:
        from yoetz.adapters.integrations.cursor_project_mcp import CursorProjectMcpError

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
            # Another Yoetz-connected project in the same home is not a conflict (#1058): this
            # is Yoetz-named configuration that Yoetz did not write or that was edited since.
            name = MCP_SERVER_NAME
            report["next_step"] = (
                "The selected Codex home holds Yoetz-named configuration that Yoetz did not "
                f"write or that was edited since (its [marketplaces.{name}] or "
                f'[plugins."{name}@{name}"] table, its plugin cache, or its {name} MCP server), '
                "or this project's .agents/plugins/marketplace.json does; setup left it "
                "untouched. Review and remove that entry, then rerun this command. Other "
                "projects connected to the same home are not a conflict. To keep the entry, "
                "connect through a separate Codex home instead: create a directory owned only "
                "by you (mode 0700) and rerun with --host-config-root pointing to it."
            )
        if (
            host == "codex"
            and isinstance(error, IntegrationError)
            and error.safe_details.get("conflict") == "membership_unverified"
        ):
            report["reason"] = "membership_unverified"
            report["next_step"] = _codex_unverified_step(config_root, project, chosen)
        if reason == "connection_lock_unavailable":
            report["next_step"] = _lock_unavailable_step(str(report["host"]), config_root)
        if host == "codex" and reason == "target_untrusted":
            home = _selected_root("codex", config_root)
            if home is not None and not os.path.lexists(home):
                # Unlike Claude Code and Cursor, Codex setup needs its home to exist first.
                report["next_step"] = (
                    f"Nothing was changed. The selected Codex home {home} does not exist. Create "
                    f"it as a folder only you can use (mkdir -p -m 700 {home}) and rerun this "
                    "command."
                )
        if (
            reason == "connection_projects_record_invalid"
            or (
                isinstance(error, IntegrationError)
                and error.reason is IntegrationReason.SOURCE_INVALID
                and error.safe_details.get("conflict") == "connected_projects"
            )
            # `setup run` and `setup status` reach Codex through a wrapper that keeps only the
            # reason; ask the record itself (#1058 review P2-6).
            or (reason == "source_invalid" and _record_unreadable(str(report["host"]), config_root))
        ):
            # One name for every host and command (Codex adapters say source_invalid).
            report["reason"] = "connection_projects_record_invalid"
            report["next_step"] = _record_invalid_step(str(report["host"]), config_root)
        if reason == "project_connected_via_other_path":
            report["next_step"] = (
                _codex_duplicate_step(config_root, project)
                if host == "codex"
                else _duplicate_step(host, config_root, project)
            )
        from yoetz.cli.runtime_refusal import installed_runtime_refusal_text

        refusal = installed_runtime_refusal_text()
        if refusal is not None:
            # The launcher or runtime this host would run is writable by another account: a
            # host-specific symptom (launcher_unproven, target_unsafe) hides the one repair.
            report["reason"], text = refusal
            report["next_step"] = text.split(": ", 1)[1].rstrip("\n")
        if isinstance(error, ConnectionError) and error.status is not None:
            rendered_status = _rendered_status(error.status)
            others = rendered_status.get("admission_other_projects")
            if isinstance(others, list):
                rendered_status["admission_other_projects"] = [
                    _rendered_status(item) if isinstance(item, dict) else item for item in others
                ]
            report["status"] = rendered_status
            next_command = rendered_status.get("next_command")
            refusal = _refusal_step(reason, rendered_status) or _leftover_next_step(rendered_status)
            if refusal is not None:
                report["next_step"] = refusal
            elif isinstance(next_command, str):
                report["next_step"] = (
                    "Inspect the selected registration before a fresh preview: " + next_command
                )
        if host == "codex" and "status" not in report:
            leftover = _codex_leftover(config_root, project)
            if leftover:
                report["status"] = leftover
                report["next_step"] = _leftover_next_step(leftover)
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
        plan_body = report.get("plan")
        if report["outcome"] == "preview" and isinstance(plan_body, dict):
            # What this plan does to other projects is part of what is being approved.
            for line in _shared_summary(
                {**plan_body, **(status if isinstance(status, dict) else {})}
            ):
                typer.echo(line)
        if "reason" in report:
            typer.echo(str(report["reason"]))
        if "next_step" in report:
            typer.echo(str(report["next_step"]))
    return code


def launch_details(installation: HostInstallation, project: Path) -> dict[str, JsonValue]:
    environment: dict[str, JsonValue] = {}
    invocation = invoking_launcher()
    if invocation is not None:
        # Canonical Codex hooks and agent-issued CLI commands use `yoetz` on PATH.
        # Keep them on the same installation as the reviewed MCP registration.
        launcher = resolve_yoetz_launcher(invocation)
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
                str(installation.config_root / "plugins/local/yoetz"),
            )
        )
    else:
        command.extend(("--new-window", str(project)))
    root = isolated_root()
    if root is not None:
        environment["YOETZ_ISOLATED_ROOT"] = str(root)
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
        *resolve_yoetz_launcher(launcher),
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
        *(["--remove-shared"] if plan.disclosure.get("remove_shared") is True else []),
        "--accept",
        "--non-interactive",
    ]
    return shlex.join(command)
