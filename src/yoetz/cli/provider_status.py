"""Read-only AI-powered review readiness report for operator surfaces.

Reports the installation-local conditions that must all hold before external AI-powered review can
dispatch, without claiming a live provider smoke or writing any state. It separately reports the
registered Codex MCP route, because a strict agent route cannot dispatch AI-powered review even
when every installation condition holds.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import stat
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Final, Literal, cast

from yoetz.config.load import load_config
from yoetz.config.models import (
    BackgroundAdviceSetting,
    ConfigError,
    ExternalRuntimeProfileConfig,
    ProviderProfileConfig,
    YoetzConfig,
    background_advice_setting,
    fallback_external_endpoint,
    primary_external_endpoint,
)
from yoetz.config.paths import PathSafetyError, bundle_root
from yoetz.domain.values import JsonObject
from yoetz.ports.control import ControlClientKind, ControlError, WorkspaceLocator
from yoetz.protocol.canonical import JsonValue, canonical_encode, strict_json_parse
from yoetz.protocol.ids import IdKind, validate_id
from yoetz.service.client import connect_service

__all__ = [
    "MachineScopeError",
    "BACKGROUND_ADVICE_ON_REASONS",
    "background_advice_facts",
    "background_advice_human_line",
    "credential_human_display",
    "host_admission_observation",
    "machine_scope_request",
    "mcp_route_observation",
    "provider_status_report",
    "run_provider_status",
]

_SCHEMA: Final = "yoetz.provider-status/1"
_CREDENTIAL_MASK: Final = "********"
# This report probes the persistent user service over the fixed endpoint only. It never starts
# one, unlike the MCP bridge's connect-on-demand path.
_PROBED_LIFECYCLE: Final = "user_service_no_autostart"
_INSTALLATION_MARKER_DOMAIN: Final = b"yoetz/installation-state/v1\x00"
_MAX_INSTALLATION_MARKER_BYTES: Final = 65_536
_INSTALLATION_MARKER_KEYS: Final = frozenset(
    {
        "schema_version",
        "installation_id",
        "vault_mode",
        "root_envelope_base64",
        "mode_binding_digest",
        "record_digest",
    }
)


def _stdout_json(value: JsonValue) -> None:
    sys.stdout.buffer.write(canonical_encode(value) + b"\n")
    sys.stdout.buffer.flush()


def _emit(value: Mapping[str, JsonValue], *, json_output: bool) -> None:
    if json_output or not sys.stdout.isatty():
        _stdout_json(dict(value))
        return
    print(f"schema: {value.get('schema')}")
    print(f"semantic_mode: {value.get('verification_semantic')}")
    print(f"endpoint_bound: {value.get('endpoint_bound')}")
    binding = value.get("endpoint")
    if isinstance(binding, Mapping):
        print(
            "  "
            f"provider_id={binding.get('provider_id')} "
            f"model={binding.get('model')} "
            f"profile={binding.get('endpoint_profile_id')}"
        )
    for key in ("endpoint", "fallback_endpoint"):
        budget_line = review_budget_human_line(value.get(key))
        if budget_line is not None:
            print(f"  {key} review budgets: {budget_line}")
    print(f"credential: {credential_human_display(value.get('credential_connected'))}")
    print(f"llm_inference_enabled: {value.get('llm_inference_enabled')}")
    print(f"repository_grant: {value.get('repository_grant_state')}")
    print(f"repository_migration: {value.get('repository_migration_state')}")
    print(f"semantic_ready: {value.get('semantic_ready')}")
    advice_line = background_advice_human_line(value.get("background_advice"))
    if advice_line is not None:
        print(f"background_advice: {advice_line}")
    route = value.get("mcp_route")
    if isinstance(route, Mapping):
        print(
            "mcp_route: "
            f"registered={route.get('registered_profile')} "
            f"configured={route.get('configured_profile')} "
            f"observed={route.get('observed')}"
        )
        # Issue #537 slice B: surface applied-vs-serving drift in the human
        # rendering using only closed profile tokens, never paths or config.
        try:
            _drift = route.get("drift_since_install") is True
            _applied = route.get("applied_profile")
            _serving = route.get("registered_profile")
            if _drift and _applied in {"policy", "strict"} and _serving in {"policy", "strict"}:
                print(f"registration drift: applied {_applied}, serving {_serving}")
            elif _drift:
                print("registration drift: applied route differs from serving route")
        except Exception:
            pass
    print(f"agent_route_semantic_ready: {value.get('agent_route_semantic_ready')}")
    admission = value.get("host_admission")
    if isinstance(admission, Mapping):
        print(
            "host_admission: "
            + " ".join(
                f"{host}={_admission_state(admission.get(host))}"
                for host in ("claude", "codex", "cursor")
            )
        )
    blockers = value.get("blockers")
    if isinstance(blockers, list | tuple) and blockers:
        print("blockers:")
        for item in blockers:
            if isinstance(item, Mapping):
                print(f"  - {item.get('condition')}: {item.get('next_command')}")
                if item.get("mcp_local_composition") == "starts_on_demand":
                    print(
                        "    (this check probes the running user service and never starts one; "
                        "the MCP bridge starts it on demand, but this check does not probe "
                        "that path)"
                    )
            else:
                print(f"  - {item}")
    next_steps = value.get("next_commands")
    if isinstance(next_steps, list | tuple) and next_steps:
        print("next commands:")
        for step in next_steps:
            print(f"  - {step}")


def review_budget_human_line(endpoint: object) -> str | None:
    """Render the per-profile effort and output limit using closed tokens and integers only."""

    if not isinstance(endpoint, Mapping):
        return None
    budgets = cast(Mapping[str, object], endpoint).get("review_budgets")
    if not isinstance(budgets, Mapping):
        return None
    parts: list[str] = []
    for name in ("routine", "final"):
        row = cast(Mapping[str, object], budgets).get(name)
        if not isinstance(row, Mapping):
            return None
        facts = cast(Mapping[str, object], row)
        source = facts.get("effort_source")
        suffix = " (legacy single effort)" if source == "legacy_single_effort" else ""
        parts.append(
            f"{name} effort={facts.get('reasoning_effort')}{suffix} "
            f"output_limit={facts.get('output_limit')} tokens"
        )
    return "; ".join(parts)


# Closed reason token -> plain explanation. Only these fixed strings are ever rendered (#888).
_BACKGROUND_ADVICE_TEXT: Final[Mapping[str, str]] = {
    "owner_enabled": "on (set in [observation] semantic_advice_enabled); runs only while a "
    "provider is usable",
    "default_enabled": "on by default where AI-powered review is configured; runs only while a "
    "provider is usable; set [observation] semantic_advice_enabled = false to turn it off",
    "owner_disabled": "off (set to false in [observation] semantic_advice_enabled); set it to "
    "true, or remove the line, to turn it on",
    "semantic_review_disabled": "off because [verification] semantic is disabled",
    "observation_disabled": "off because observation is disabled",
}


# The closed reasons that accompany an enabled switch; every other known reason means off.
BACKGROUND_ADVICE_ON_REASONS: Final[frozenset[str]] = frozenset(
    {"owner_enabled", "default_enabled"}
)


def background_advice_facts(config: YoetzConfig) -> dict[str, JsonValue]:
    """The effective background-advice switch and its closed reason, for status surfaces."""

    setting: BackgroundAdviceSetting = background_advice_setting(config)
    return {"enabled": setting.enabled, "reason": setting.reason}


def background_advice_human_line(value: object) -> str | None:
    """Render a ``background_advice`` fact with fixed text only; unknown shapes render nothing."""

    if not isinstance(value, Mapping):
        return None
    reason = cast(Mapping[str, object], value).get("reason")
    if type(reason) is not str:
        return None
    return _BACKGROUND_ADVICE_TEXT.get(reason)


def _admission_state(value: object) -> str:
    if isinstance(value, Mapping):
        state = cast(Mapping[str, object], value).get("state")
        if type(state) is str:
            return state
    return "unknown"


def credential_human_display(value: object) -> str:
    """Render credential presence without reflecting any property of the stored secret."""

    if value is True:
        return _CREDENTIAL_MASK
    if value is False:
        return "not stored"
    return "unknown"


def _endpoint_facts(
    endpoint: ProviderProfileConfig | ExternalRuntimeProfileConfig | None,
    *,
    role: str,
) -> dict[str, JsonValue] | None:
    """Nonsecret identity of one bound endpoint, or ``None`` when that slot is unbound."""

    if endpoint is None:
        return None
    if type(endpoint) is ExternalRuntimeProfileConfig:
        return {
            "role": role,
            "provider_id": endpoint.provider_id,
            "model": endpoint.model,
            "endpoint_profile_id": endpoint.endpoint_profile_id,
            "endpoint_profile_version": endpoint.endpoint_profile_version,
            "credential_authority": endpoint.credential_authority,
            "runtime_version": endpoint.runtime_version,
            "capability_profile": endpoint.capability_profile,
            "upstream_body_observability": "unavailable",
            "review_budgets": cast(JsonValue, endpoint.review_budget_facts()),
        }
    return {
        "role": role,
        "provider_id": endpoint.provider_id,
        "model": endpoint.model,
        "endpoint_profile_id": endpoint.endpoint_profile_id,
        "endpoint_profile_version": endpoint.endpoint_profile_version,
        "credential_authority": "yoetz_vault_api_credential",
    }


def _credential_command(
    endpoint: ProviderProfileConfig | ExternalRuntimeProfileConfig | None,
) -> str:
    if type(endpoint) is ExternalRuntimeProfileConfig:
        return "yoetz provider codex-subscription status"
    return "yoetz provider credential set"


def _channel_enabled(policy: Mapping[str, object], channel: str) -> bool | None:
    """Read one channel's enabled flag from the canonical effective policy.

    The canonical policy names this list ``channel_policies``; reading any other key silently
    reports every channel as unknown and makes readiness unreachable.
    """

    channels = policy.get("channel_policies")
    if not isinstance(channels, list | tuple):
        return None
    for item in cast("list[object] | tuple[object, ...]", channels):
        if not isinstance(item, Mapping):
            continue
        entry = cast(Mapping[str, object], item)
        if entry.get("channel") == channel:
            return entry.get("enabled") is True
    return None


def _mcp_local_composition(service_state: str | None, *, service_observed: bool) -> str:
    """Say what the MCP-local path would find, only from what this probe actually established.

    A service that answered is shared by both surfaces. An absent one is started on demand by the
    bridge. Every other refusal — an untrusted peer, a protocol mismatch — proves neither, so it
    stays `unknown` instead of asserting a lifecycle this check never observed.
    """

    if service_observed:
        return "shares_this_service"
    if service_state in {None, "service_unavailable"}:
        return "starts_on_demand"
    return "unknown"


def _codex_binary_selection_command(selected_home: Path) -> str:
    """Render a selector continuation that retains the inspected runtime and Codex home."""

    from yoetz.cli.setup_readiness import continuation

    return continuation(
        [
            "provider",
            "status",
            "--codex-path",
            "<exact-executable>",
            "--codex-home",
            str(selected_home),
        ]
    )


async def mcp_route_observation(
    workspace_locator: Path | None = None,
    *,
    _state: Path | None = None,
    codex_home: Path | None = None,
    codex_path: str | None = None,
) -> dict[str, JsonValue]:
    """Report exclusive external/plugin MCP ownership without inferring runtime success.

    A strict registration and a policy registration are both ``yoetz_owned``, so registration
    state alone cannot tell an operator whether the agent route can dispatch AI-powered review at
    all. This probe adds the missing fact.

    Fail-soft is deliberate and load-bearing: this report exists to stay readable when the
    installation is broken, so an absent Codex, an unreadable entry, or any registration error
    degrades to ``observed: false`` — the module's existing "unknown means unread" convention —
    rather than raising or moving the exit code.
    """

    # Imported here: `yoetz.cli.setup` imports this module lazily, and the discovery/adapter
    # stack is only needed on this one path.
    from yoetz.adapters.integrations.codex_discovery import discover_codex_binaries
    from yoetz.adapters.integrations.codex_mcp import CodexMcpAdapter
    from yoetz.adapters.integrations.portable_plugin import observe_plugin_managed_mcp
    from yoetz.application.harness_mcp import HarnessMcpService
    from yoetz.cli import setup as cli_setup
    from yoetz.ports.plugin_artifacts import McpOwnershipState

    try:
        # The registration-time authority stays owned by `setup`, so this reads it rather than
        # growing a second answer to the same question.
        configured: JsonValue = cli_setup.configured_mcp_route_profile()
    except Exception:
        configured = None
    external_state: str | None = None
    external_profile: str | None = None
    external_observed = False
    binary_selection: str | None = None
    try:
        from yoetz.adapters.integrations.codex_session_stream import resolve_codex_home

        binaries = discover_codex_binaries()
        if codex_path is not None:
            binary = cli_setup._explicit_binary(codex_path)  # pyright: ignore[reportPrivateUsage]
            if binary is None:
                binary_selection = "explicit_path_unresolved"
        elif len(binaries) == 1:
            binary = binaries[0]
        elif len(binaries) > 1:
            # A readiness report must never silently inspect an arbitrary installation when the
            # operator has not selected one. Keep the route unreadable and provide the exact
            # selector in the composed report below.
            binary = None
            binary_selection = "multiple"
        else:
            binary = None
        if binary is not None:
            observation = await HarnessMcpService(
                CodexMcpAdapter(codex_home=resolve_codex_home(codex_home).absolute())
            ).observe(binary)
            external_state = observation.state.value
            external_profile = observation.route_profile
            external_observed = True
    except Exception:
        pass
    root = Path.cwd() if workspace_locator is None else workspace_locator
    plugin = observe_plugin_managed_mcp(root)

    external_owned = external_state == "yoetz_owned"
    external_foreign = external_state == "foreign_present"
    plugin_owned = plugin.ownership_state is McpOwnershipState.PLUGIN
    plugin_foreign = plugin.ownership_state is McpOwnershipState.FOREIGN
    plugin_ambiguous = plugin.ownership_state is McpOwnershipState.AMBIGUOUS
    if not external_observed or not plugin.observed or plugin_ambiguous:
        ownership = McpOwnershipState.AMBIGUOUS
        source: JsonValue = None
        route_profile: JsonValue = None
        observed = False
    elif external_owned and plugin_owned:
        ownership = McpOwnershipState.DUAL
        source = "dual"
        route_profile = None
        observed = True
    elif external_foreign or plugin_foreign:
        ownership = McpOwnershipState.FOREIGN
        source = "foreign"
        route_profile = None
        observed = True
    elif external_owned:
        ownership = McpOwnershipState.EXTERNAL
        source = "external_registration"
        route_profile = external_profile
        observed = True
    elif plugin_owned:
        ownership = McpOwnershipState.PLUGIN
        source = "plugin_managed"
        route_profile = plugin.route_profile
        observed = True
    else:
        ownership = McpOwnershipState.ABSENT
        source = None
        route_profile = None
        observed = True

    # Issue #537 slice B: join the durable applied route against the live
    # host resolution above (never a cached preview). Fail-soft: an unreadable
    # record reads as no applied route and no drift; unread observations never
    # report drift. Strict both-in-set rule (review B1): drift is True iff a
    # record exists AND both profiles name a Yoetz route AND they differ, so
    # ABSENT/DUAL/FOREIGN (registered None) never report drift.
    try:
        from yoetz.application.applied_mcp_route import read_applied_route

        _applied_record = read_applied_route(_state=_state)
    except Exception:
        _applied_record = None
    _applied_profile: str | None = None
    if isinstance(_applied_record, dict):
        _candidate = _applied_record.get("applied_profile")
        if isinstance(_candidate, str) and _candidate in {"policy", "strict"}:
            _applied_profile = _candidate
    _drift_since_install = (
        _applied_record is not None
        and _applied_profile in {"policy", "strict"}
        and observed is True
        and route_profile in {"policy", "strict"}
        and route_profile != _applied_profile
    )

    result: dict[str, JsonValue] = {
        "registration_state": external_state,
        "registered_profile": route_profile,
        "configured_profile": configured,
        "observed": observed,
        "owner_source": source,
        "ownership_state": ownership.value,
        "external_registration_state": external_state,
        "plugin_managed_state": plugin.ownership_state.value,
        "applied_profile": _applied_profile,
        "drift_since_install": _drift_since_install,
    }
    if binary_selection is not None:
        result["binary_selection"] = binary_selection
    return result


def _admission_repository_root(workspace_locator: Path | None) -> Path:
    """Resolve the locator to the repository root that owns the host admission files.

    The hosts honor their project-scoped admission files at the repository root
    (``.claude/settings.local.json``, ``.codex/config.toml``, ``.cursor/*``), so an observation
    started in a subdirectory must walk up to that root or it reports ``absent`` for files it
    never looked at. The result is absolute — the adapter refuses a relative root as
    ``TARGET_UNSAFE`` — and the final symlink is deliberately not resolved: a symlinked root
    must keep reading as ``unknown`` rather than silently observing the symlink's target.
    """

    start = Path.cwd() if workspace_locator is None else workspace_locator.absolute()
    for candidate in (start, *start.parents):
        if (candidate / ".git").exists():
            return candidate
    return start


def host_admission_observation(
    workspace_locator: Path | None = None,
    *,
    codex_owner: str | None = None,
) -> dict[str, JsonValue]:
    """Report each host's project-scoped admission entry for ``check`` without inferring intent.

    Reads only the three hosts' own files under the repository root resolved from the workspace
    locator (issue #467). An unreadable file is ``unknown``, never ``absent``: the report must
    not tell an operator that a host holds no admission when it simply could not read the host's
    rule file.
    """

    from yoetz.adapters.integrations.host_admission import (
        ADMISSION_HOSTS,
        HostAdmissionError,
        observe_host_admission,
    )

    root = _admission_repository_root(workspace_locator)
    owner = codex_owner if codex_owner in {"external", "plugin"} else None
    report: dict[str, JsonValue] = {}
    for host in ADMISSION_HOSTS:
        try:
            observation = observe_host_admission(
                host,
                root,
                owner=cast('Literal["external", "plugin"] | None', owner)
                if host == "codex"
                else None,
            )
        except HostAdmissionError as error:
            report[host] = {
                "entries": [],
                "host": host,
                "observed": False,
                "reason": error.reason.value,
                "state": "unknown",
            }
            continue
        report[host] = observation.as_json()
    return report


# Closed remediation set: each machine-scope construction failure names exactly one trusted next
# command. Values are fixed strings — no paths, no marker content, no user-controlled text.
_MACHINE_SCOPE_REMEDIATIONS: Final[Mapping[str, str]] = {
    "installation_bundle_unavailable": (
        "the configured storage bundle could not be resolved; "
        "fix [storage].data_dir in config.toml, then retry"
    ),
    "installation_marker_invalid": (
        "the installation marker could not be read; "
        "run 'yoetz service recovery status' for the trusted repair path, then retry"
    ),
    "installation_marker_missing": (
        "this installation is not initialized; run 'yoetz setup', then retry"
    ),
}


class MachineScopeError(Exception):
    """A bounded local machine-scope construction failure; never a service result.

    Raised before any service request when this installation's identity cannot be resolved from
    the configured storage bundle. The reason set is closed so every caller renders one valid
    actionable diagnostic instead of constructing an error the control vocabulary does not admit
    (issue #517: an inadmissible ``ControlError`` reason surfaced as generic ``internal_error``).
    """

    __slots__ = ("reason",)

    reason: str

    def __init__(self, reason: str) -> None:
        if type(reason) is not str or reason not in _MACHINE_SCOPE_REMEDIATIONS:
            raise ValueError("machine_scope_reason_invalid")
        self.reason = reason
        super().__init__(reason)

    @property
    def remediation(self) -> str:
        """One fixed actionable next step for this reason; safe for human stderr output."""

        return _MACHINE_SCOPE_REMEDIATIONS[self.reason]


def machine_scope_request() -> JsonObject:
    """Build the ``privacy_get_effective`` body for this installation's machine scope.

    The installation marker lives in the configured storage bundle — the same root the service
    resolves via ``bundle_root(_data_dir=config.storage.data_dir)`` — not the fixed platform
    state directory, so an explicit ``storage.data_dir`` is honored here too (issue #517).
    ``scope`` is required by the frozen request schema, so a scope that cannot be constructed
    locally is reported as a bounded :class:`MachineScopeError` before any service request rather
    than sent as a body the service must reject.
    """

    try:
        config = load_config({}, os.environ, None)
        root = bundle_root(_data_dir=config.storage.data_dir)
    except (ConfigError, OSError, PathSafetyError) as exc:
        raise MachineScopeError("installation_bundle_unavailable") from exc
    marker = root / "installation-state.json"
    try:
        facts = marker.lstat()
        encoded = marker.read_bytes()
    except FileNotFoundError as exc:
        raise MachineScopeError("installation_marker_missing") from exc
    except OSError as exc:
        raise MachineScopeError("installation_marker_invalid") from exc
    try:
        if (
            not stat.S_ISREG(facts.st_mode)
            or stat.S_ISLNK(facts.st_mode)
            or facts.st_nlink != 1
            or len(encoded) > _MAX_INSTALLATION_MARKER_BYTES
            or not encoded.endswith(b"\n")
            or encoded.endswith(b"\n\n")
        ):
            raise ValueError
        if os.name == "posix" and stat.S_IMODE(facts.st_mode) & 0o077:
            raise ValueError
        state: object = strict_json_parse(encoded[:-1])
        if type(state) is not dict or canonical_encode(cast(JsonValue, state)) != encoded[:-1]:
            raise ValueError
        source = cast("dict[str, JsonValue]", state)
        if frozenset(source) != _INSTALLATION_MARKER_KEYS or source["schema_version"] != "1":
            raise ValueError
        body = dict(source)
        record_digest = body.pop("record_digest")
        if type(record_digest) is not str:
            raise ValueError
        expected = (
            "sha256:"
            + hashlib.sha256(_INSTALLATION_MARKER_DOMAIN + canonical_encode(body)).hexdigest()
        )
        if not hmac.compare_digest(record_digest, expected):
            raise ValueError
    except (TypeError, ValueError) as exc:
        raise MachineScopeError("installation_marker_invalid") from exc
    installation_id: object = source["installation_id"]
    if type(installation_id) is not str:
        raise MachineScopeError("installation_marker_invalid")
    try:
        validate_id(IdKind.INSTALLATION, installation_id)
    except (TypeError, ValueError) as exc:
        raise MachineScopeError("installation_marker_invalid") from exc
    body: dict[str, JsonValue] = {
        "schema_version": "1.0.0",
        "scope": {"kind": "machine", "installation_id": installation_id},
    }
    return JsonObject(body)


def external_runtime_fact(config: YoetzConfig) -> dict[str, JsonValue] | None:
    """Local structural state of the bound Codex subscription runtime, or ``None`` when unbound.

    Read from the binding, executable bytes, and dedicated home only: no Codex process, login
    probe, or credential read (#855). It names the exact repair when the service can only say the
    external credential is not connected.
    """

    runtime = config.external_runtime
    if runtime is None:
        return None
    from yoetz.adapters.providers.codex_evaluator_runtime import (
        host_codex_evaluator_cell,
        managed_runtime_path,
    )
    from yoetz.cli.codex_subscription import (
        binding_continuation,
        diagnose_bound_runtime,
        runtime_bundle,
    )

    diagnosis = diagnose_bound_runtime(runtime)
    pairing = config.semantic_fallback
    role = "fallback" if pairing is not None and pairing.primary == "api_provider" else "primary"
    next_command = binding_continuation(diagnosis.state)
    uses_managed: bool | None
    try:
        managed = managed_runtime_path(runtime_bundle(), host_codex_evaluator_cell())
    except ValueError:
        uses_managed = None
    else:
        uses_managed = runtime.executable_path == str(managed)
    if next_command is None and uses_managed is False:
        # Ready today, but bound to a host installation its package manager can replace.
        next_command = "yoetz provider codex-subscription repair"
    return {
        "role": role,
        "state": diagnosis.state,
        "capability": diagnosis.capability,
        "executable": diagnosis.executable,
        "code_mode_host": diagnosis.code_mode_host,
        "home": diagnosis.home,
        "uses_managed_runtime": uses_managed,
        "next_command": next_command,
    }


async def provider_status_report(
    *,
    workspace_locator: Path | None = None,
    _state: Path | None = None,
    codex_home: Path | None = None,
    codex_path: str | None = None,
) -> dict[str, JsonValue]:
    """Compose a nonsecret readiness snapshot from config, service, and policy."""

    config = load_config({}, os.environ, None)
    verification_semantic = config.verification.semantic
    semantic_enabled = verification_semantic != "disabled"
    endpoint_bound = config.provider is not None or config.external_runtime is not None
    primary_config = primary_external_endpoint(config)
    fallback_config = fallback_external_endpoint(config)
    endpoint = _endpoint_facts(primary_config, role="primary")
    # A declared pairing reports both endpoints; single-endpoint installs read as before with
    # ``fallback_endpoint`` absent rather than null-shaped (#582).
    fallback_endpoint = _endpoint_facts(fallback_config, role="fallback")
    runtime_fact = external_runtime_fact(config)
    runtime_unready = runtime_fact is not None and runtime_fact["state"] != "ready"
    runtime_next = None if runtime_fact is None else runtime_fact.get("next_command")

    def credential_command(
        endpoint_config: ProviderProfileConfig | ExternalRuntimeProfileConfig | None,
    ) -> str:
        # A structurally stranded runtime needs its exact repair, not a login status probe.
        if (
            type(endpoint_config) is ExternalRuntimeProfileConfig
            and runtime_unready
            and type(runtime_next) is str
        ):
            return runtime_next
        return _credential_command(endpoint_config)

    service_state: str | None = None
    service_state_reason: str | None = None
    credential_connected: bool | None = None
    fallback_credential_connected: bool | None = None
    llm_inference_enabled: bool | None = None
    policy_profile: str | None = None
    # ``disabled`` only when the composed policy turned the possible-credential filter off
    # (issue #982 owner opt-out); the default is never printed.
    credential_heuristic_disabled = False
    repository_grant_state: str | None = None
    repository_migration_state: str | None = None
    # Set only when a service actually answered, so presence is observed rather than inferred
    # from the shape of a refusal.
    service_observed = False

    try:
        client = await connect_service(
            ControlClientKind.CLI,
            workspace_locator=WorkspaceLocator(
                str(
                    (Path.cwd() if workspace_locator is None else workspace_locator).resolve(
                        strict=True
                    )
                )
            ),
        )
        try:
            status = await client.service_status()
            service_observed = True
            service_state = status.state.value
            service_state_reason = status.state_reason
            if status.state.value == "ready":
                credential_connected = "external_provider" in status.capabilities
                if fallback_config is not None:
                    fallback_credential_connected = "fallback_provider" in status.capabilities
                try:
                    effective = await client.privacy_get_setup(
                        JsonObject({"schema_version": "2.0.0"})
                    )
                except Exception:
                    effective = None
                if isinstance(effective, Mapping):
                    plain = cast(Mapping[str, object], dict(effective))
                    raw_grant = plain.get("grant_state")
                    raw_migration = plain.get("migration_state")
                    if raw_grant in {"granted", "missing"}:
                        repository_grant_state = cast(str, raw_grant)
                    if raw_migration in {
                        "not_applicable",
                        "legacy_route_available",
                        "first_repository_available",
                        "consumed",
                    }:
                        repository_migration_state = cast(str, raw_migration)
                    policy = plain.get("composed_policy")
                    if isinstance(policy, Mapping):
                        policy_map = cast(Mapping[str, object], policy)
                        profile = policy_map.get("profile")
                        if type(profile) is str:
                            policy_profile = profile
                        llm_inference_enabled = _channel_enabled(policy_map, "llm_inference")
                        credential_heuristic_disabled = (
                            policy_map.get("credential_heuristic") == "disabled"
                        )
            else:
                credential_connected = None
        finally:
            await client.close()
    except ControlError as error:
        service_state = error.reason
        service_state_reason = error.reason
        credential_connected = None
        llm_inference_enabled = None

    from yoetz.adapters.integrations.codex_session_stream import resolve_codex_home

    selected_home = resolve_codex_home(codex_home).absolute()
    # Keep the no-selector call shape for read-only integrations that override the route probe;
    # the probe itself resolves the same selected home before invoking Codex.
    mcp_route = (
        await mcp_route_observation(workspace_locator, _state=_state)
        if codex_home is None and codex_path is None
        else await mcp_route_observation(
            workspace_locator, _state=_state, codex_home=selected_home, codex_path=codex_path
        )
    )
    registered_profile = mcp_route.get("registered_profile")
    ownership_state = mcp_route.get("ownership_state")
    if ownership_state is None and mcp_route.get("registration_state") == "yoetz_owned":
        ownership_state = "external"
    route_observed = mcp_route.get("observed") is True
    host_admission = host_admission_observation(
        workspace_locator,
        codex_owner=ownership_state if type(ownership_state) is str else None,
    )
    # Admission is a repository fact derived from the grant; it drifts when the grant no
    # longer permits external review or (Codex) the registered route is strict, and a present
    # entry then admits a call Yoetz will refuse or hold anyway. Reported, never auto-removed
    # here: this surface is read-only.
    grant_permits_review = llm_inference_enabled is True and repository_grant_state == "granted"
    grant_known = llm_inference_enabled is not None and repository_grant_state is not None
    binary_selection_command = (
        _codex_binary_selection_command(selected_home)
        if mcp_route.get("binary_selection") in {"multiple", "explicit_path_unresolved"}
        else None
    )

    blockers: list[dict[str, JsonValue]] = []
    if service_state != "ready":
        if service_state_reason in {"auto_unlock_rejected", "auto_unlock_stale"}:
            service_command = "yoetz service auto-unlock repair"
        elif service_state_reason == "vault_uninitialized":
            service_command = "yoetz setup"
        elif service_state in {None, "service_unavailable"}:
            service_command = "yoetz service run"
        else:
            service_command = "yoetz service unlock"
        blockers.append(
            {
                "condition": "service_unlocked",
                "state": service_state or "service_unavailable",
                "reason": service_state_reason,
                "next_command": service_command,
                # This surface deliberately connects without starting anything, so an absent
                # service reads as unavailable here while the MCP bridge — which connects on
                # demand — starts the same service and succeeds. Naming the probed lifecycle
                # keeps the two reports from looking like a contradiction.
                "probed_lifecycle": _PROBED_LIFECYCLE,
                "mcp_local_composition": _mcp_local_composition(
                    service_state, service_observed=service_observed
                ),
            }
        )
    if not semantic_enabled:
        blockers.append(
            {
                "condition": "verification.semantic",
                "state": verification_semantic,
                "next_command": "set [verification].semantic to optional|required in config.toml",
            }
        )
    if not endpoint_bound:
        blockers.append(
            {
                "condition": "provider_endpoint",
                "state": "unbound",
                "next_command": (
                    "yoetz provider endpoint --provider <preset> --model <model> OR "
                    "yoetz provider codex-subscription setup"
                ),
            }
        )
    if credential_connected is None:
        blockers.append({"condition": "provider_credential", "state": "unknown"})
    elif credential_connected is False:
        blockers.append(
            {
                "condition": "provider_credential",
                "state": "not_connected",
                "next_command": credential_command(primary_config),
            }
        )
    # The fallback's credential is a blocker of the fallback only: the primary dispatches
    # without it, so it is reported under its own condition rather than folded into the
    # primary's readiness.
    if fallback_config is not None:
        if fallback_credential_connected is None:
            blockers.append({"condition": "fallback_provider_credential", "state": "unknown"})
        elif fallback_credential_connected is False:
            blockers.append(
                {
                    "condition": "fallback_provider_credential",
                    "state": "not_connected",
                    "next_command": credential_command(fallback_config),
                }
            )
    if runtime_fact is not None and runtime_unready:
        # Known without the service and before any login: the exact structural refusal.
        blockers.append(
            {
                "condition": "external_runtime_structure",
                "state": runtime_fact["state"],
                "role": runtime_fact["role"],
                **({} if type(runtime_next) is not str else {"next_command": runtime_next}),
            }
        )
    if llm_inference_enabled is None:
        blockers.append({"condition": "llm_inference_channel", "state": "unknown"})
    elif llm_inference_enabled is False:
        blockers.append(
            {
                "condition": "llm_inference_channel",
                "state": "disabled",
                "next_command": "yoetz --privacy",
            }
        )
    if repository_grant_state is None:
        blockers.append({"condition": "repository_privacy_grant", "state": "unknown"})
    elif repository_grant_state == "missing":
        blockers.append(
            {
                "condition": "repository_privacy_grant",
                "state": "missing",
                "next_command": "yoetz --privacy",
            }
        )
    if registered_profile == "strict":
        # Scoped to the agent route on purpose. ADR-018 decision 2 makes the route ceiling
        # process-local, so a strict Codex registration does not stop a CLI or terminal check
        # from dispatching AI-powered review — it is not an installation blocker.
        blockers.append(
            {
                "condition": "mcp_route_profile",
                "state": "strict",
                "scope": "agent_route",
                "next_command": "yoetz integrate codex mcp preview",
            }
        )
    if route_observed and ownership_state in {"dual", "foreign", "ambiguous"}:
        blockers.append(
            {
                "condition": "mcp_ownership_state",
                "state": ownership_state or "ambiguous",
                "scope": "agent_route",
            }
        )
    if mcp_route.get("binary_selection") == "multiple":
        blockers.append(
            {
                "condition": "codex_binary_selection",
                "state": "multiple",
                "scope": "agent_route",
                "next_command": binary_selection_command,
            }
        )
    elif mcp_route.get("binary_selection") == "explicit_path_unresolved":
        blockers.append(
            {
                "condition": "codex_binary_selection",
                "state": "not_found",
                "scope": "agent_route",
                "next_command": binary_selection_command,
            }
        )
    for host, admission in host_admission.items():
        state = admission.get("state") if isinstance(admission, Mapping) else None
        if state not in {"present", "partial"}:
            continue
        drifted = (grant_known and not grant_permits_review) or (
            host == "codex" and route_observed and registered_profile == "strict"
        )
        if drifted:
            blockers.append(
                {
                    "condition": "host_admission_drift",
                    "state": state,
                    "scope": "agent_route",
                    "host": host,
                    "next_command": (
                        f"yoetz integrate {host} admission preview --action revoke --project-root ."
                    ),
                }
            )

    readiness_determinable = (
        service_state == "ready"
        and credential_connected is not None
        and llm_inference_enabled is not None
        and repository_grant_state is not None
    )
    semantic_ready = (
        readiness_determinable
        and semantic_enabled
        and endpoint_bound
        and credential_connected is True
        and llm_inference_enabled is True
        and repository_grant_state == "granted"
        # A service composed before the runtime changed can still report the credential as
        # connected; the live structural fact is what the next dispatch will meet (#855).
        and not (runtime_unready and runtime_fact is not None and runtime_fact["role"] == "primary")
    )
    next_commands = tuple(
        dict.fromkeys(
            cast(str, item["next_command"])
            for item in blockers
            if type(item.get("next_command")) is str
        )
    )

    return {
        "schema": _SCHEMA,
        "inspected_codex_home": str(selected_home),
        "verification_semantic": verification_semantic,
        "semantic_enabled": semantic_enabled,
        "endpoint_bound": endpoint_bound,
        "endpoint": endpoint,
        "credential_connected": credential_connected,
        **({} if runtime_fact is None else {"external_runtime": runtime_fact}),
        **(
            {}
            if fallback_endpoint is None
            else {
                "fallback_endpoint": fallback_endpoint,
                "fallback_credential_connected": fallback_credential_connected,
            }
        ),
        "llm_inference_enabled": llm_inference_enabled,
        "privacy_profile": policy_profile,
        **({"credential_heuristic": "disabled"} if credential_heuristic_disabled else {}),
        "repository_grant_state": repository_grant_state,
        "repository_migration_state": repository_migration_state,
        "service_state": service_state,
        "service_state_reason": service_state_reason,
        "readiness_determinable": readiness_determinable,
        "semantic_ready": semantic_ready,
        "background_advice": background_advice_facts(config),
        "mcp_route": mcp_route,
        "host_admission": host_admission,
        "agent_route_semantic_ready": (
            semantic_ready
            and route_observed
            and ownership_state in {"external", "plugin"}
            and registered_profile == "policy"
        ),
        "blockers": tuple(blockers),
        "next_commands": next_commands,
        "notes": (
            "semantic_ready is structural readiness only; it does not prove live provider dispatch.",
            "background_advice is the effective [observation] semantic_advice_enabled switch; "
            "when on, the service still schedules it only while a provider is usable.",
            "credential_connected reports the configured provider's credential, not any provider.",
            "For external_runtime_oauth, READY credential presence is the exact binding, digest, "
            "and dedicated home; ChatGPT login and model availability are proven inside evaluate() "
            "or by 'yoetz provider codex-subscription status'. Yoetz never reads the credential.",
            "external_runtime is a local structural diagnosis of the bound Codex subscription "
            "runtime; it starts no Codex process and does not check sign-in.",
            "A credential for a different provider than the bound endpoint does not count.",
            "unknown means the service could not be read, not that the step is incomplete.",
            "agent_route_semantic_ready describes one exclusively observed Codex MCP owner; "
            "semantic_ready describes this repository-bound installation view. Neither "
            "substitutes for the other.",
            "A strict registered route does not make this installation not-ready: CLI and "
            "terminal checks still dispatch, only the strict agent route cannot.",
            "mcp_route.observed false means ownership was not read unambiguously, not that no "
            "route exists.",
            "host_admission reports each host's own project-scoped rule admitting the "
            "AI-powered check past its automatic reviewer; it is host tool-call authorization "
            "and proves neither dispatch nor a Yoetz decision. unknown means the host file "
            "could not be read.",
        ),
    }


async def run_provider_status(
    *, json_output: bool, codex_home: Path | None = None, codex_path: str | None = None
) -> int:
    """Emit the readiness report and return a process exit code."""

    report = await provider_status_report(codex_home=codex_home, codex_path=codex_path)
    _emit(report, json_output=json_output)
    return 0 if report.get("semantic_ready") is True else 20
