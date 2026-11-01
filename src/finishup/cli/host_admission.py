"""Explicit ``finishup integrate <host> admission`` commands (issue #467).

The commands compose three already-existing facts — the host's observed MCP route, the
repository's privacy grant as the running service reports it, and the host's own project-scoped
admission files — and hand exactly those facts to the admission adapter. Nothing here infers a
root from the ambient environment: every host root is an explicit option, as it is for the plugin
lifecycle commands, so a test cell can never bleed into the maintainer's real host configuration.
"""

from __future__ import annotations

import sys
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, cast

from finishup.adapters.integrations.host_admission import (
    ADMISSION_HOSTS,
    CODEX_LEGACY_PLUGIN_ADMISSION_HEADER,
    HostAdmissionAction,
    HostAdmissionEntry,
    HostAdmissionError,
    HostAdmissionHost,
    HostAdmissionObservation,
    HostAdmissionReason,
    LegacyNameUse,
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

# Frozen legacy identifier (ADR-048): the plugin id a Yoetz 0.1-0.2 Codex activation enabled.
_CODEX_LEGACY_PLUGIN_ID = "yoetz@yoetz"
_MAX_CODEX_CONFIG_BYTES = 1_048_576


@dataclass(frozen=True, slots=True)
class AdmissionFacts:
    """Observed inputs the adapter gates on. ``None`` always means unread, never absent."""

    route_profile: str | None
    owner: McpOwnerForm | None
    route_observed: bool
    grant_state: str | None
    llm_inference_enabled: bool | None
    service_state: str | None
    # What the host holds under the legacy ``yoetz`` MCP key, and (Claude, Cursor) what the
    # legacy plugin install holds: none | legacy_only | duplicate | foreign (ADR-048).
    legacy_registration: str | None = None
    legacy_installation: str | None = None
    # Codex only: whether a Yoetz-era ``[plugins."yoetz@yoetz"]`` activation may be enabled, which
    # the plugin-form legacy admission table serves; ``None`` when unread (ADR-048).
    legacy_plugin_activation: bool | None = None
    # Codex only: how the route was read when several Codex installations are discoverable
    # (``consistent``, ``inconsistent``, ``multiple`` = none readable, ``explicit_path_unresolved``)
    # and the reported version of the installation read. Never a path.
    codex_binary_selection: str | None = None
    codex_version: str | None = None

    @property
    def grant_permits(self) -> bool | None:
        if self.grant_state is None or self.llm_inference_enabled is None:
            return None
        return self.grant_state == "granted" and self.llm_inference_enabled is True

    @property
    def legacy_name(self) -> LegacyNameUse | None:
        """How FinishUP still uses the legacy ``yoetz`` server name; ``None`` when unread.

        Only a FinishUP-owned entry counts as use: a foreign ``yoetz`` registration is exactly
        what a stale legacy grant would wrongly admit (ADR-048).
        """

        if self.legacy_registration not in {"none", "legacy_only", "duplicate", "foreign"}:
            return None
        if self.legacy_registration == "legacy_only":
            return "serving"
        if self.legacy_registration == "duplicate" or self.legacy_installation in {
            "legacy_only",
            "duplicate",
        }:
            return "shared"
        return "unused"

    def legacy_name_for(self, entries: Sequence[HostAdmissionEntry]) -> LegacyNameUse | None:
        """``legacy_name``, narrowed by what the observed legacy entries would admit (ADR-048).

        The Codex plugin-form legacy table admits the Yoetz-era plugin's ``check``, which the
        legacy MCP key never shows. While that table remains it is unused only when no Yoetz-era
        plugin activation can be enabled; an enabled one keeps it, and an unread one leaves the
        use unread.
        """

        legacy_name = self.legacy_name
        if legacy_name != "unused" or not any(
            CODEX_LEGACY_PLUGIN_ADMISSION_HEADER in entry.legacy_entries for entry in entries
        ):
            return legacy_name
        if self.legacy_plugin_activation is None:
            return None
        return "shared" if self.legacy_plugin_activation else "unused"

    def as_json(self) -> dict[str, JsonValue]:
        route: dict[str, JsonValue] = {
            "observed": self.route_observed,
            "owner": self.owner,
            "route_profile": self.route_profile,
        }
        if self.codex_binary_selection is not None:
            route["codex_binary_selection"] = self.codex_binary_selection
        if self.codex_version is not None:
            route["codex_version"] = self.codex_version
        return {
            "grant": {
                "llm_inference_enabled": self.llm_inference_enabled,
                "permits_external_review": self.grant_permits,
                "repository_grant_state": self.grant_state,
                "service_state": self.service_state,
            },
            "route": {
                **route,
                "legacy_installation": self.legacy_installation,
                "legacy_plugin_activation": self.legacy_plugin_activation,
                "legacy_registration": self.legacy_registration,
            },
        }


def legacy_grant_state(observation: HostAdmissionObservation, facts: AdmissionFacts) -> str:
    """Classify exact legacy ``yoetz`` admission entries against the observed registration.

    ``absent``: none remain. ``in_use``: a FinishUP-owned registration or install still uses the
    old name. ``stale``: nothing FinishUP owns does, so the entry would only admit an unrelated
    server that takes the old name; a grant (or revoke) removes it. ``unverified``: the
    registration, or (for the Codex plugin-form table) the Yoetz-era plugin activation, was not
    read (ADR-048).
    """

    if not observation.legacy_entries_present:
        return "absent"
    legacy_name = facts.legacy_name_for(observation.entries)
    if legacy_name is None:
        return "unverified"
    return "stale" if legacy_name == "unused" else "in_use"


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


type _Route = tuple[str | None, McpOwnerForm | None, bool, str | None, str | None]


def _claude_route(
    *,
    project_root: Path,
    claude_path: Path | None,
    claude_config_root: Path | None,
    cache_root: Path | None,
    marketplace_root: Path | None,
    ownership_name: str,
    route_name: str | None,
) -> _Route:
    if any(
        value is None for value in (claude_path, claude_config_root, cache_root, marketplace_root)
    ):
        return None, None, False, None, None
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
        observation.legacy_registration if observation.observed else None,
        status.legacy_installation if observation.observed else None,
    )


def _cursor_route(
    *,
    project_root: Path,
    cursor_config_root: Path | None,
    ownership_name: str,
    route_name: str | None,
) -> _Route:
    if cursor_config_root is None:
        return None, None, False, None, None
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
        observation.legacy_registration if observation.observed else None,
        status.legacy_installation if observation.observed else None,
    )


async def _codex_legacy_registration() -> str | None:
    """Read what the Codex legacy ``yoetz`` MCP key holds; ``None`` when unread (ADR-048).

    Mirrors the provider-status route probe: exactly one discovered Codex and its default home.
    Fail-soft, like that probe, because an unread fact only keeps legacy entries in place.
    """

    try:
        from finishup.adapters.integrations.codex_discovery import discover_codex_binaries
        from finishup.adapters.integrations.codex_mcp import CodexMcpAdapter
        from finishup.adapters.integrations.codex_session_stream import resolve_codex_home

        binaries = discover_codex_binaries()
        if len(binaries) != 1:
            return None
        adapter = CodexMcpAdapter(codex_home=resolve_codex_home(None).absolute())
        observation = await adapter.observe_registration(binaries[0])
    except Exception:  # noqa: BLE001 - an unread fact is reported as unread, never raised
        return None
    return observation.legacy_registration


def _codex_config_enables_legacy_plugin(path: Path) -> bool | None:
    """Whether one Codex config may enable the Yoetz-era plugin; ``None`` when unreadable.

    ``enabled = true`` (what a Yoetz-era activation wrote) counts; ``enabled = false`` does not.
    Without an ``enabled`` key the table counts unless it holds only the ``mcp_servers`` subtable
    the plugin-form legacy admission entry implies (ADR-048).
    """

    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return False
    except OSError:
        return None
    if len(raw) > _MAX_CODEX_CONFIG_BYTES:
        return None
    try:
        parsed = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError):
        return None
    plugins = parsed.get("plugins")
    if plugins is None:
        return False
    if not isinstance(plugins, Mapping):
        return None
    plugin = cast(Mapping[str, object], plugins).get(_CODEX_LEGACY_PLUGIN_ID)
    if plugin is None:
        return False
    if not isinstance(plugin, Mapping):
        # Not a table Codex could read as an activation, nor one FinishUP can judge.
        return None
    table = cast(Mapping[str, object], plugin)
    enabled = table.get("enabled")
    if enabled is True:
        # Exactly what a Yoetz-era activation wrote.
        return True
    if enabled is False:
        return False
    # The plugin-form admission subtable ``[plugins."yoetz@yoetz".mcp_servers...]`` creates an
    # implicit ``yoetz@yoetz`` table holding only ``mcp_servers``; that is the table being judged,
    # not an activation. Any other shape without ``enabled = false`` may still enable the plugin.
    return set(table) != {"mcp_servers"}


def _codex_legacy_plugin_activation(project_root: Path) -> bool | None:
    """Whether a Yoetz-era Codex plugin activation may be enabled; ``None`` when unread.

    Reads the default Codex home's ``config.toml`` and the project's ``.codex/config.toml``
    without running Codex. Any project's legacy activation counts, since an enabled plugin is
    loaded in every project. Fail-soft: an unread fact keeps the plugin-form legacy admission
    table in place (ADR-048).
    """

    try:
        from finishup.adapters.integrations.codex_session_stream import resolve_codex_home

        configs = (
            resolve_codex_home(None).absolute() / "config.toml",
            project_root / ".codex" / "config.toml",
        )
    except Exception:  # noqa: BLE001 - an unread fact is reported as unread, never raised
        return None
    results = [_codex_config_enables_legacy_plugin(path) for path in configs]
    if True in results:
        return True
    if None in results:
        return None
    return False


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
    codex_path: Path | None = None,
    codex_home: Path | None = None,
) -> AdmissionFacts:
    """Read the route and grant facts a grant preview must gate on, all fail-soft to unread."""

    from finishup.cli.provider_status import provider_status_report

    report = (
        await provider_status_report(
            workspace_locator=project_root,
            codex_path=None if codex_path is None else str(codex_path.expanduser()),
            codex_home=None if codex_home is None else codex_home.expanduser(),
        )
        if harness == "codex" and (codex_path is not None or codex_home is not None)
        else await provider_status_report(workspace_locator=project_root)
    )
    grant_state = report.get("repository_grant_state")
    llm = report.get("llm_inference_enabled")
    service_state = report.get("service_state")
    route_profile: str | None = None
    owner: McpOwnerForm | None = None
    route_observed = False
    legacy_registration: str | None = None
    legacy_installation: str | None = None
    legacy_plugin_activation: bool | None = None
    binary_selection: str | None = None
    codex_version: str | None = None
    if harness == "codex":
        route = report.get("mcp_route")
        if isinstance(route, Mapping):
            route_map = cast(Mapping[str, object], route)
            route_observed = route_map.get("observed") is True
            selection = route_map.get("binary_selection")
            binary_selection = selection if type(selection) is str else None
            version = route_map.get("selected_codex_version")
            codex_version = version if type(version) is str else None
            if route_observed:
                registered = route_map.get("registered_profile")
                route_profile = registered if type(registered) is str else None
                owner = _owner(route_map.get("ownership_state"))
        legacy_registration = await _codex_legacy_registration()
        legacy_plugin_activation = _codex_legacy_plugin_activation(project_root)
    elif harness == "claude":
        route_profile, owner, route_observed, legacy_registration, legacy_installation = (
            _claude_route(
                project_root=project_root,
                claude_path=claude_path,
                claude_config_root=claude_config_root,
                cache_root=cache_root,
                marketplace_root=marketplace_root,
                ownership_name=ownership_name,
                route_name=route_name,
            )
        )
    elif harness == "cursor":
        route_profile, owner, route_observed, legacy_registration, legacy_installation = (
            _cursor_route(
                project_root=project_root,
                cursor_config_root=cursor_config_root,
                ownership_name=ownership_name,
                route_name=route_name,
            )
        )
    return AdmissionFacts(
        route_profile,
        owner,
        route_observed,
        grant_state if type(grant_state) is str else None,
        llm if type(llm) is bool else None,
        service_state if type(service_state) is str else None,
        legacy_registration,
        legacy_installation,
        legacy_plugin_activation,
        binary_selection,
        codex_version,
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
        # The sweep also takes exact legacy ``yoetz`` entries on an otherwise absent surface.
        "surfaces": cast(
            list[JsonValue],
            sorted(
                entry.surface
                for entry in observation.entries
                if entry.state.value == "present"
                or (entry.state.value == "absent" and entry.legacy_entries)
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


def _codex_selectors(codex_path: Path | None, codex_home: Path | None) -> str:
    selectors = ""
    if codex_path is not None:
        selectors += " --codex-path <codex-path>"
    if codex_home is not None:
        selectors += " --codex-home <codex-home>"
    return selectors


def _next_command(
    harness: str,
    action: HostAdmissionAction,
    *,
    codex_path: Path | None = None,
    codex_home: Path | None = None,
) -> str:
    verb = "grant" if action is HostAdmissionAction.GRANT else "revoke"
    return (
        f"finishup integrate {harness} admission {verb} --project-root <root>"
        f"{_codex_selectors(codex_path, codex_home)} "
        "--accept --preview-digest <preview_digest>"
    )


# Codex installation-selection states that leave the route unread or read it with a caveat.
_CODEX_SELECTION_CONTINUATION: Final = frozenset(
    {"multiple", "inconsistent", "explicit_path_unresolved"}
)


def _codex_selection_continuation(command: str, selection: str | None) -> str | None:
    """A path-free continuation naming the explicit Codex selector, when selection is the issue."""

    if selection not in _CODEX_SELECTION_CONTINUATION:
        return None
    return (
        f"next: finishup integrate codex admission {command} --project-root <root> "
        "--codex-path <exact-codex-executable> [--codex-home <codex-home>]"
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
    codex_path: Path | None = None,
    codex_home: Path | None = None,
) -> int:
    """Run one path-explicit admission command and return a process exit code."""

    if harness not in ADMISSION_HOSTS or command not in ADMISSION_COMMANDS:
        sys.stderr.write("host_admission_command_invalid\n")
        return 2
    if harness != "codex" and (codex_path is not None or codex_home is not None):
        sys.stderr.write("host_admission_codex_selector_invalid\n")
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
    facts: AdmissionFacts | None = None
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
            codex_path=codex_path,
            codex_home=codex_home,
        )
        observation = observe_host_admission(host, root, owner=facts.owner)
        if command == "status":
            body: dict[str, JsonValue] = {
                "admission": observation.as_json(),
                "host": host,
                # A legacy ``yoetz`` grant that no FinishUP registration needs reads ``stale``.
                "legacy_grant": legacy_grant_state(observation, facts),
                "scope": "project",
                **facts.as_json(),
            }
            _emit(body, json_output=json_output)
            return 0
        if action is HostAdmissionAction.GRANT and facts.codex_binary_selection == "inconsistent":
            raise HostAdmissionError(HostAdmissionReason.CODEX_BINARY_INCONSISTENT)
        legacy_name = facts.legacy_name_for(observation.entries)
        preview = preview_host_admission(
            host,
            root,
            action,
            route_profile=facts.route_profile,
            grant_permits=facts.grant_permits,
            owner=facts.owner,
            checkpoint=checkpoint,
            legacy_name=legacy_name,
        )
        if facts.legacy_name_for(preview.entries) != legacy_name:
            # The legacy entries changed between the two reads; the use was judged on others.
            raise HostAdmissionError(HostAdmissionReason.PREVIEW_STALE)
        if command == "preview":
            body = {
                **preview.as_json(),
                **facts.as_json(),
                "next_command": _next_command(
                    host, action, codex_path=codex_path, codex_home=codex_home
                ),
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
        continuation = (
            _codex_selection_continuation(command, facts.codex_binary_selection)
            if facts is not None and host == "codex"
            else None
        )
        if continuation is not None:
            sys.stderr.write(continuation + "\n")
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
