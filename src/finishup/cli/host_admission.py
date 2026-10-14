"""Explicit ``finishup integrate <host> admission`` commands (issue #467).

The commands compose three already-existing facts — the host's observed MCP route, the
repository's privacy grant as the running service reports it, and the host's own project-scoped
admission files — and hand exactly those facts to the admission adapter. Nothing here infers a
root from the ambient environment: every host root is an explicit option, as it is for the plugin
lifecycle commands, so a test cell can never bleed into the maintainer's real host configuration.
"""

from __future__ import annotations

import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from finishup.adapters.integrations.host_admission import (
    ADMISSION_HOSTS,
    HostAdmissionAction,
    HostAdmissionError,
    HostAdmissionHost,
    McpOwnerForm,
    apply_host_admission,
    observe_host_admission,
    preview_host_admission,
    sweep_host_admission,
)
from finishup.protocol.canonical import JsonValue, canonical_encode

__all__ = [
    "ADMISSION_COMMANDS",
    "AdmissionFacts",
    "admission_cleanup_preview",
    "gather_admission_facts",
    "reverse_sweep",
    "run_host_admission_command",
]

ADMISSION_COMMANDS: tuple[str, ...] = ("status", "preview", "grant", "revoke")


@dataclass(frozen=True, slots=True)
class AdmissionFacts:
    """Observed inputs the adapter gates on. ``None`` always means unread, never absent."""

    route_profile: str | None
    owner: McpOwnerForm | None
    route_observed: bool
    grant_state: str | None
    llm_inference_enabled: bool | None
    service_state: str | None

    @property
    def grant_permits(self) -> bool | None:
        if self.grant_state is None or self.llm_inference_enabled is None:
            return None
        return self.grant_state == "granted" and self.llm_inference_enabled is True

    def as_json(self) -> dict[str, JsonValue]:
        return {
            "grant": {
                "llm_inference_enabled": self.llm_inference_enabled,
                "permits_external_review": self.grant_permits,
                "repository_grant_state": self.grant_state,
                "service_state": self.service_state,
            },
            "route": {
                "observed": self.route_observed,
                "owner": self.owner,
                "route_profile": self.route_profile,
            },
        }


def _owner(ownership_state: object) -> McpOwnerForm | None:
    if ownership_state == "external":
        return "external"
    if ownership_state == "plugin":
        return "plugin"
    return None


def _emit(value: Mapping[str, JsonValue], *, json_output: bool) -> None:
    if json_output:
        sys.stdout.buffer.write(canonical_encode(dict(value)) + b"\n")
        sys.stdout.buffer.flush()
        return
    for key, item in value.items():
        rendered = (
            canonical_encode(item).decode("utf-8")
            if isinstance(item, (dict, list, tuple))
            else str(item)
        )
        sys.stdout.write(f"{key}: {rendered}\n")


def _claude_route(
    *,
    project_root: Path,
    claude_path: Path | None,
    claude_config_root: Path | None,
    cache_root: Path | None,
    marketplace_root: Path | None,
    ownership_name: str,
    route_name: str | None,
) -> tuple[str | None, McpOwnerForm | None, bool]:
    if any(
        value is None for value in (claude_path, claude_config_root, cache_root, marketplace_root)
    ):
        return None, None, False
    assert claude_path is not None
    assert claude_config_root is not None
    assert cache_root is not None
    assert marketplace_root is not None
    from finishup.adapters.integrations.claude_code_integration import (
        ClaudeCodePluginTarget,
        discover_claude_code,
        status_claude_code_plugin,
    )
    from finishup.cli.claude_code_integration import plugin_artifact as claude_artifact

    executable = claude_path.expanduser().resolve(strict=True)
    identity = discover_claude_code(executable)
    target = ClaudeCodePluginTarget(
        str(project_root),
        str(claude_config_root.expanduser().absolute()),
        str(cache_root.expanduser().absolute()),
        str(marketplace_root.expanduser().absolute()),
        str(executable),
        identity,
    )
    status = status_claude_code_plugin(target, claude_artifact(ownership_name, route_name))
    observation = status.mcp_observation
    return (
        observation.route_profile,
        _owner(observation.ownership_state.value) if observation.host_admission_supported else None,
        observation.observed,
    )


def _cursor_route(
    *,
    project_root: Path,
    cursor_config_root: Path | None,
    ownership_name: str,
    route_name: str | None,
) -> tuple[str | None, McpOwnerForm | None, bool]:
    if cursor_config_root is None:
        return None, None, False
    from finishup.adapters.integrations.cursor_integration import (
        CursorPluginTarget,
        status_cursor_plugin,
    )
    from finishup.cli.cursor_integration import plugin_artifact as cursor_artifact

    target = CursorPluginTarget(str(cursor_config_root.expanduser().absolute()))
    status = status_cursor_plugin(
        target,
        cursor_artifact("native", ownership_name, route_name),
        project_root=project_root,
    )
    observation = status.mcp_observation
    return (
        observation.route_profile,
        _owner(observation.ownership_state.value),
        observation.observed,
    )


async def gather_admission_facts(
    harness: HostAdmissionHost,
    project_root: Path,
    *,
    claude_path: Path | None = None,
    claude_config_root: Path | None = None,
    cache_root: Path | None = None,
    marketplace_root: Path | None = None,
    cursor_config_root: Path | None = None,
    ownership_name: str = "external-registration",
    route_name: str | None = None,
) -> AdmissionFacts:
    """Read the route and grant facts a grant preview must gate on, all fail-soft to unread."""

    from finishup.cli.provider_status import provider_status_report

    report = await provider_status_report(workspace_locator=project_root)
    grant_state = report.get("repository_grant_state")
    llm = report.get("llm_inference_enabled")
    service_state = report.get("service_state")
    route_profile: str | None = None
    owner: McpOwnerForm | None = None
    route_observed = False
    if harness == "codex":
        route = report.get("mcp_route")
        if isinstance(route, Mapping):
            route_map = cast(Mapping[str, object], route)
            route_observed = route_map.get("observed") is True
            if route_observed:
                registered = route_map.get("registered_profile")
                route_profile = registered if type(registered) is str else None
                owner = _owner(route_map.get("ownership_state"))
    elif harness == "claude":
        route_profile, owner, route_observed = _claude_route(
            project_root=project_root,
            claude_path=claude_path,
            claude_config_root=claude_config_root,
            cache_root=cache_root,
            marketplace_root=marketplace_root,
            ownership_name=ownership_name,
            route_name=route_name,
        )
    elif harness == "cursor":
        route_profile, owner, route_observed = _cursor_route(
            project_root=project_root,
            cursor_config_root=cursor_config_root,
            ownership_name=ownership_name,
            route_name=route_name,
        )
    return AdmissionFacts(
        route_profile,
        owner,
        route_observed,
        grant_state if type(grant_state) is str else None,
        llm if type(llm) is bool else None,
        service_state if type(service_state) is str else None,
    )


def admission_cleanup_preview(host: HostAdmissionHost, project_root: Path) -> dict[str, JsonValue]:
    """Disclose, before a reverse transition, what its admission sweep would touch."""

    try:
        observation = observe_host_admission(host, project_root.expanduser().absolute())
    except HostAdmissionError as error:
        return {"host": host, "state": "unknown", "reason": error.reason.value}
    return {
        "host": host,
        "state": observation.state.value,
        "surfaces": cast(
            list[JsonValue],
            sorted(
                entry.surface for entry in observation.entries if entry.state.value == "present"
            ),
        ),
    }


def reverse_sweep(host: HostAdmissionHost, project_root: Path) -> dict[str, JsonValue]:
    """Run one host's reverse transition (uninstall, strict re-registration, grant revoke).

    Removes exactly the entries FinishUP wrote for ``host`` under ``project_root`` and reports the
    outcome; foreign entries stay, an unreadable file is ``unknown``. The caller's own
    digest-bound mutation is the authority this rides on, and the sweep is reported in that
    command's result so the transition is never silent.
    """

    (outcome,) = sweep_host_admission(project_root.expanduser().absolute(), (host,))
    return outcome.as_json()


def _next_command(harness: str, action: HostAdmissionAction) -> str:
    verb = "grant" if action is HostAdmissionAction.GRANT else "revoke"
    return (
        f"finishup integrate {harness} admission {verb} --project-root <root> "
        "--accept --preview-digest <preview_digest>"
    )


async def run_host_admission_command(
    command: str,
    *,
    harness: str,
    project_root: Path,
    action_name: str | None,
    accept: bool,
    preview_digest: str | None,
    checkpoint: bool,
    json_output: bool,
    claude_path: Path | None = None,
    claude_config_root: Path | None = None,
    cache_root: Path | None = None,
    marketplace_root: Path | None = None,
    cursor_config_root: Path | None = None,
    ownership_name: str = "external-registration",
    route_name: str | None = None,
) -> int:
    """Run one path-explicit admission command and return a process exit code."""

    if harness not in ADMISSION_HOSTS or command not in ADMISSION_COMMANDS:
        sys.stderr.write("host_admission_command_invalid\n")
        return 2
    host: HostAdmissionHost = harness
    root = project_root.expanduser().absolute()
    if command == "status":
        action = HostAdmissionAction.NOOP
    elif command == "grant":
        action = HostAdmissionAction.GRANT
    elif command == "revoke":
        action = HostAdmissionAction.REVOKE
    elif action_name in {None, "grant"}:
        action = HostAdmissionAction.GRANT
    elif action_name == "revoke":
        action = HostAdmissionAction.REVOKE
    else:
        sys.stderr.write("host_admission_action_invalid\n")
        return 2
    if command != "preview" and action_name is not None:
        sys.stderr.write("host_admission_action_invalid\n")
        return 2
    try:
        facts = await gather_admission_facts(
            host,
            root,
            claude_path=claude_path,
            claude_config_root=claude_config_root,
            cache_root=cache_root,
            marketplace_root=marketplace_root,
            cursor_config_root=cursor_config_root,
            ownership_name=ownership_name,
            route_name=route_name,
        )
        if command == "status":
            observation = observe_host_admission(host, root, owner=facts.owner)
            body: dict[str, JsonValue] = {
                "admission": observation.as_json(),
                "host": host,
                "scope": "project",
                **facts.as_json(),
            }
            _emit(body, json_output=json_output)
            return 0
        preview = preview_host_admission(
            host,
            root,
            action,
            route_profile=facts.route_profile,
            grant_permits=facts.grant_permits,
            owner=facts.owner,
            checkpoint=checkpoint,
        )
        if command == "preview":
            body = {
                **preview.as_json(),
                **facts.as_json(),
                "next_command": _next_command(host, action),
                "scope": "project",
            }
            _emit(body, json_output=json_output)
            return 0
        if not accept or preview_digest is None:
            sys.stderr.write("host_admission_exact_preview_acceptance_required\n")
            return 3
        result = apply_host_admission(preview, root, accepted_preview_digest=preview_digest)
        _emit({**result.as_json(), "scope": "project"}, json_output=json_output)
        return 0
    except HostAdmissionError as error:
        sys.stderr.write(f"host_admission_{error.reason.value}\n")
        return 1
    except OSError:
        # Paths and raw OS errors are user-controlled content under the repository privacy rule.
        sys.stderr.write("host_admission_target_unsafe\n")
        return 1
    except ValueError:
        sys.stderr.write("host_admission_host_invalid\n")
        return 1
    except Exception:  # noqa: BLE001 - public CLI boundary must never reflect raw exception text
        sys.stderr.write("host_admission_host_invalid\n")
        return 1
