"""Explicit project-local Cursor MCP registration without starting a service."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Literal, cast

from yoetz.adapters.integrations.cursor_project_mcp import (
    CursorProjectMcpError,
    CursorProjectMcpTarget,
    apply_cursor_project_mcp,
    preview_cursor_project_mcp,
    status_cursor_project_mcp,
)
from yoetz.adapters.integrations.launcher import invoking_launcher, resolve_yoetz_launcher
from yoetz.config.paths import isolated_root
from yoetz.protocol.canonical import JsonValue

__all__ = ["run_cursor_project_mcp_command"]


def _emit(body: dict[str, JsonValue], *, json_output: bool) -> None:
    if json_output:
        sys.stdout.write(json.dumps(body, sort_keys=True, separators=(",", ":")) + "\n")
        return
    for key, value in body.items():
        sys.stdout.write(f"{key}: {json.dumps(value, sort_keys=True)}\n")


def run_cursor_project_mcp_command(
    action: str,
    harness: str,
    *,
    project_root: Path,
    cursor_config_root: Path,
    route_profile: str | None,
    accept: bool,
    preview_digest: str | None,
    json_output: bool,
    project_binding: Literal["mcp-roots", "registered-project"] | None = None,
) -> int:
    """Use only explicit targets and the launcher that produced this CLI process."""

    if harness != "cursor" or action not in {
        "preview",
        "preview-remove",
        "install",
        "status",
        "remove",
    }:
        _emit(
            {"ok": False, "reason_code": "cursor_project_mcp_command_invalid"},
            json_output=json_output,
        )
        return 2
    if route_profile not in {None, "strict", "policy"}:
        _emit({"ok": False, "reason_code": "cursor_mcp_route_invalid"}, json_output=json_output)
        return 2
    if action in {"preview", "install"}:
        from yoetz.cli.runtime_refusal import connect_refusal

        refusal = connect_refusal()
        if refusal is not None:
            # Cursor would launch this runtime and every launch would be refused; removal and
            # status never ask.
            _emit(
                {"ok": False, "reason_code": refusal[0], "next_step": refusal[1]},
                json_output=json_output,
            )
            return 20
    try:
        invocation = invoking_launcher()
        if invocation is None:
            raise ValueError("yoetz_executable_unavailable")
        launcher = resolve_yoetz_launcher(invocation)
        root = isolated_root()
        isolation = None if root is None else str(root)
        target = CursorProjectMcpTarget(
            project_root.expanduser(), cursor_config_root.expanduser(), project_binding
        )
        route = cast(Literal["policy", "strict"] | None, route_profile)
        if action == "status":
            body = status_cursor_project_mcp(target, launcher=launcher, isolation_root=isolation)
        elif action in {"preview", "preview-remove"}:
            body = preview_cursor_project_mcp(
                target,
                action="remove" if action == "preview-remove" else "install",
                launcher=launcher,
                route_profile=route,
                isolation_root=isolation,
            )
            if action == "preview-remove" or body.get("route_profile") == "strict":
                from yoetz.cli.host_admission import admission_cleanup_preview

                body["admission_cleanup"] = admission_cleanup_preview("cursor", target.project_root)
        else:
            if not accept or preview_digest is None:
                _emit(
                    {"ok": False, "reason_code": "cursor_project_mcp_preview_required"},
                    json_output=json_output,
                )
                return 2
            body = apply_cursor_project_mcp(
                target,
                action="remove" if action == "remove" else "install",
                launcher=launcher,
                route_profile=route,
                isolation_root=isolation,
                preview_digest=preview_digest,
                accept=accept,
            )
            if action == "remove" or body.get("route_profile") == "strict":
                from yoetz.cli.host_admission import reverse_sweep

                body["admission_cleanup"] = reverse_sweep("cursor", target.project_root)
        _emit(body, json_output=json_output)
        return 0
    except CursorProjectMcpError as error:
        _emit({"ok": False, "reason_code": error.reason}, json_output=json_output)
        return 1
    except OSError, TypeError, ValueError:
        _emit({"ok": False, "reason_code": "cursor_project_mcp_invalid"}, json_output=json_output)
        return 2
