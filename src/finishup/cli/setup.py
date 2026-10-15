"""First-run setup wizard: harness, local service, and provider connection.

The wizard orchestrates only operations a human could already run by hand: it
discovers Codex binaries, previews and (after explicit confirmation) applies the
runbook's ``codex mcp get``/``codex mcp add`` sequence, checks whether the local
service is reachable, and—only on a local interactive terminal—runs the existing
vault and provider-credential ceremonies. Secret bytes remain inside the dedicated
hidden-input confidential helper and never enter wizard arguments, config, or MCP.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import shlex
import shutil
import sys
import tempfile
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final, Literal, cast

import anyio
import typer
from anyio.to_thread import run_sync
from click import IntRange

from finishup.adapters.integrations.codex_discovery import (
    default_codex_home,
    discover_codex_binaries,
)
from finishup.adapters.integrations.codex_marketplace import (
    ActivationPreview,
    ActivationState,
    apply_activation,
    inspect_activation,
    preview_activation,
    resolve_codex_home_for_binary,
)
from finishup.adapters.integrations.codex_mcp import CodexMcpAdapter
from finishup.adapters.integrations.codex_plugin import PluginHookPresence, inspect_plugin
from finishup.adapters.integrations.codex_skill import (
    CodexSkillIntegration,
    inspect_destination,
    load_packaged_skill_source,
)
from finishup.adapters.workspace_binding import canonical_workspace_locator
from finishup.application.applied_mcp_route import clear_applied_route, read_applied_route
from finishup.application.codex_plugin import CodexPluginService
from finishup.application.harness_mcp import (
    HarnessMcpService,
    McpRegistrationConfirmation,
    mcp_removal_report,
)
from finishup.application.observation_check_policy import (
    ObservationCheckPolicyAmbiguous,
    load_observation_check_policy,
)
from finishup.cli.agent_start import AGENT_START_HANDOFF
from finishup.config.load import load_config
from finishup.config.models import ConfigError
from finishup.config.paths import PathSafetyError, setup_marker_path
from finishup.domain.privacy import ConversationReview
from finishup.domain.values import RequestId, request_id
from finishup.ports.harness_mcp import (
    HarnessBinary,
    McpRegistrationAction,
    McpRegistrationError,
    McpRegistrationPreview,
    McpRegistrationReason,
    McpRegistrationState,
)
from finishup.ports.integrations import (
    HarnessId,
    IntegrationAction,
    IntegrationError,
    IntegrationPreview,
    IntegrationScope,
    IntegrationTarget,
    SkillApplyCommand,
    SkillPreviewCommand,
)
from finishup.protocol.canonical import JsonValue, canonical_digest, canonical_encode
from finishup.protocol.ids import IdKind, new_id

if TYPE_CHECKING:
    from finishup.adapters.integrations.host_discovery import HostInstallation

__all__ = [
    "SETUP_MARKER_SCHEMA",
    "codex_activation_preview",
    "apply_codex_integration",
    "check_policy_preview",
    "configured_mcp_route_profile",
    "integrate_mcp",
    "project_skill_preview",
    "run_provider_setup",
    "run_setup_wizard",
    "restart_service_for_semantic_composition",
    "setup_marker_present",
    "setup_status",
    "should_offer_first_run",
    "write_setup_marker",
]

# Frozen legacy identifier (ADR-048): stored marker and released report/status tags.
SETUP_MARKER_SCHEMA: Final = "yoetz.setup-wizard-marker/1"
_REPORT_SCHEMA: Final = "yoetz.setup-wizard-report/1"
_STATUS_SCHEMA: Final = "yoetz.setup-status/2"
_HARNESS_DISPLAY_NAMES: Final[dict[HarnessId, str]] = {HarnessId.CODEX: "Codex"}

_NEXT_SERVICE: Final = "run 'finishup service run' under your selected user supervisor"
_NEXT_UNLOCK: Final = "run 'finishup service unlock' from a local terminal if the vault is locked"
_NEXT_PRIVACY: Final = "run 'finishup --privacy' to review or change the privacy policy"
_NEXT_PROVIDER_TOML: Final = (
    "run 'finishup provider endpoint' for an API provider, or "
    "'finishup provider codex-subscription setup' for Codex-managed ChatGPT login (it offers "
    "the newest capability-checked Codex) — never put credentials in TOML"
)
_NEXT_CREDENTIAL: Final = (
    "run 'finishup provider credential set' from a local terminal to provision the "
    "provider credential through the confidential ceremony"
)
_NEXT_RESTART: Final = (
    "restart the FinishUP service so the configured AI-powered evaluator is composed"
)
_NEXT_AGENT_GUIDE: Final = AGENT_START_HANDOFF
_PROVIDER_SETUP_DIRECT_REASONS: Final = frozenset(
    {
        "cancelled",
        "confirmation_mismatch",
        "credential_setup_failed",
        "empty_input",
        "eof",
        "input_invalid",
        "interrupted",
        "model_selection_invalid",
        "preview_invalid",
        "provider_binding_invalid",
        "repository_privacy_scope_unavailable",
        "result_invalid",
        "service_not_ready",
        "stored_result_recovered",
        "trusted_console_required",
        "codex_runtime_not_found",
        "codex_runtime_unavailable",
        "codex_model_unavailable",
        "codex_reasoning_effort_unavailable",
        "codex_subscription_timeout",
        "codex_subscription_failed",
        # Evaluator-runtime selection and retention (#855): each names its own next step.
        "codex_runtime_capability_unsupported",
        "codex_evaluator_runtime_unavailable",
        "codex_evaluator_runtime_store_unsafe",
        "codex_evaluator_runtime_store_unavailable",
        "codex_evaluator_runtime_download_failed",
        "codex_evaluator_runtime_download_timeout",
        "codex_evaluator_runtime_package_manager_unavailable",
        # Capability admission (ADR-006, 2026-10-13): why a Codex release was not admitted.
        "codex_runtime_version_unsupported",
        "codex_runtime_version_unknown",
        "codex_runtime_code_mode_host_missing",
        "codex_runtime_protocol_incompatible",
        "codex_runtime_protocol_unavailable",
        "codex_app_server_predisclosure_event_forbidden",
        "codex_sandbox_unavailable_unreviewed_runtime",
        "codex_thread_isolation_unproven",
        "codex_capability_probe_cleanup_unconfirmed",
    }
)


def _sandbox_unavailable_reason(status: Mapping[str, object]) -> str | None:
    """The closed reason Codex gave for an unverified Linux sandbox (ADR-006, 2026-10-14)."""

    reason = status.get("codex_sandbox_unavailable_reason")
    if status.get("codex_sandbox_unavailable") is True and reason in {
        "user_namespaces_unavailable",
        "bubblewrap_missing",
    }:
        return cast(str, reason)
    return None


def _canonical_setup_workspace(workspace: Path | None = None) -> Path:
    canonical = canonical_workspace_locator(Path.cwd() if workspace is None else workspace)
    if canonical is None:
        raise ValueError("workspace_locator_invalid")
    return Path(canonical)


_NEXT_PROJECT: Final = (
    "Run 'finishup setup run' from inside the project folder you want to connect, or pass "
    "--project <folder>. Your home folder and the filesystem root cannot be connected."
)
_NEXT_PRIVACY_AFTER_PROVIDER: Final = (
    "Next: from the project folder, run 'finishup --privacy' to choose the disclosure policy for "
    "AI-powered review; the provider binding is kept."
)
_NEXT_CREDENTIAL_AFTER_PRIVACY: Final = (
    "No API key was stored: after that, rerun 'finishup --set' from the project folder, or run "
    "'finishup provider credential set' there."
)
_NEXT_PROVIDER_AFTER_SKIP: Final = (
    "Next: no provider was chosen. Rerun 'finishup --set' and choose one, or run 'finishup "
    "provider endpoint' (API key) or 'finishup provider codex-subscription setup' (Codex with a "
    "ChatGPT subscription)."
)
_PRIVACY_READY: Final = frozenset({"configured", "unchanged"})


def _emit_unconnectable_project(host: str, *, json_output: bool) -> int:
    """Report a project folder setup cannot connect, with the same words on every path."""

    if json_output:
        typer.echo(
            json.dumps(
                {
                    "schema": "yoetz.host-connection-report/1",
                    "host": host,
                    "action": "connect",
                    "connection_observed": False,
                    "outcome": "incomplete",
                    "reason": "workspace_locator_invalid",
                    "next_step": _NEXT_PROJECT,
                },
                sort_keys=True,
            )
        )
    else:
        typer.echo(f"{host}: incomplete")
        typer.echo("workspace_locator_invalid")
        typer.echo(_NEXT_PROJECT)
    return 1


def _resolve_setup_project(project: Path | None, *, interactive: bool) -> Path | None:
    """Return the canonical project to connect, asking once per attempt in a terminal.

    Setup used to discover an unusable folder (the home folder, ``/``, or a symlinked path) only
    after every question had been answered, and then failed as ``internal_error``. Now the
    folder is checked first; a terminal user may name another one, and an empty answer stops
    with a plain next step.
    """

    try:
        return _canonical_setup_workspace(project)
    except ValueError:
        pass
    if not interactive:
        return None
    typer.echo(
        "FinishUP connects an agent to one project folder. This folder cannot be connected "
        "(your home folder, the filesystem root, and symlinked paths are refused)."
    )
    while True:
        answer = typer.prompt(
            "Project folder to connect (Enter to stop)", default="", show_default=False
        ).strip()
        if not answer:
            return None
        try:
            return _canonical_setup_workspace(Path(answer).expanduser())
        except ValueError:
            typer.echo("That folder cannot be connected either; choose a project folder.")


_PROVIDER_SETUP_PRIVACY_REASONS: Final = frozenset(
    {
        "local_terminal_required",
        "privacy_authority_required",
        "privacy_decision_not_approved",
        "privacy_policy_stale",
        "privacy_proposal_stale",
        "privacy_setup_candidate_invalid",
        "privacy_setup_category_invalid",
        "privacy_setup_channel_unsupported",
        "privacy_setup_credential_probe_requires_provider",
        "privacy_setup_data_class_invalid",
        "privacy_setup_failed",
        "privacy_setup_grant_missing",
        "privacy_setup_incomplete",
        "privacy_setup_local_model_binding_required",
        "privacy_setup_proposal_invalid",
        "privacy_setup_provider_binding_required",
        "privacy_setup_recipe_invalid",
        "privacy_setup_router_route_unconstrained",
        "privacy_setup_snapshot_invalid",
    }
)
_PROVIDER_SETUP_CONFIG_REASONS: Final = frozenset(
    {
        "config_file_too_large",
        "config_file_unreadable",
        "config_preimage_mismatch",
        "config_schema_unsupported",
        "config_toml_invalid",
        "config_value_invalid",
        "durability_unsupported",
        "external_profile_forbids_local_model",
        "external_runtime_forbids_local_model",
        "external_runtime_forbids_provider",
        "external_runtime_required_for_semantic",
        "https_origin_invalid",
        "local_model_locator_forbidden",
        "max_findings_out_of_range",
        "owner_declared_endpoint_forbidden",
        "owner_declared_endpoint_required",
        "payload_logging_forbidden",
        "privacy_bootstrap_unsafe",
        "provider_required_for_semantic",
        "release_probe_not_a_user_profile",
        "secret_in_config",
        "strict_local_forbids_provider",
        "test_fake_forbids_local_model",
        "test_fake_forbids_provider",
        "unknown_config_key",
    }
)
_PROVIDER_SETUP_AUTO_UNLOCK_REASONS: Final = frozenset(
    {
        "ambiguous_write",
        "authority_mismatch",
        "bundle_parent_missing",
        "bundle_permission_denied",
        "bundle_unsafe",
        "correlation_mismatch",
        "entry_exists",
        "entry_invalid",
        "guard_unavailable",
        "human_authority_unavailable",
        "initialization_in_progress",
        "locked",
        "migration_not_proven",
        "missing",
        "readback_failed",
        "staged_entry_exists",
        "unsupported",
        "unverified",
    }
)
# Filesystem failures of the bundle-scoped initialization guard (issue #565); each is distinct
# from a genuinely unsupported keyring and never triggers the manual-passphrase fallback.
_BUNDLE_GUARD_REASONS: Final = frozenset(
    {"bundle_parent_missing", "bundle_permission_denied", "bundle_unsafe", "guard_unavailable"}
)
_PROVIDER_SETUP_CONFIDENTIAL_REASONS: Final = frozenset(
    {
        "ambiguous",
        "cancelled",
        "ceremony_busy",
        "ceremony_unsupported",
        "correlation_mismatch",
        "kind_forbidden",
        "peer_untrusted",
        "pending_not_actionable",
        "pending_unavailable",
        "protocol_error",
        "reauthentication_rate_limited",
        "response_bytes",
        "secret_rejected",
        "service_unavailable",
        "session_busy",
        "session_closed",
        "stale_generation",
        "state_forbidden",
        "timeout",
    }
)


def _allowlisted_provider_setup_reason(reason: object) -> str:
    """Return one reviewed nonsecret provider-setup reason, never caller text."""

    if type(reason) is not str:
        return "credential_setup_failed"
    if (
        reason in _PROVIDER_SETUP_DIRECT_REASONS
        or reason in _PROVIDER_SETUP_CONFIG_REASONS
        or reason in _PROVIDER_SETUP_PRIVACY_REASONS
    ):
        return reason
    if reason.startswith("credential_"):
        confidential_reason = reason.removeprefix("credential_")
        if confidential_reason in _PROVIDER_SETUP_CONFIDENTIAL_REASONS:
            return reason
    if reason.startswith("auto_unlock_"):
        auto_unlock_reason = reason.removeprefix("auto_unlock_")
        if auto_unlock_reason in _PROVIDER_SETUP_AUTO_UNLOCK_REASONS:
            return reason
    if reason.startswith("vault_result_"):
        # The suffix comes from a schema-validated VaultStateResult reason, never caller text;
        # the structural bound here keeps the allowlist self-contained.
        vault_reason = reason.removeprefix("vault_result_")
        if 0 < len(vault_reason) <= 64 and all(
            character in "abcdefghijklmnopqrstuvwxyz_" for character in vault_reason
        ):
            return reason
    return "credential_setup_failed"


def _provider_setup_result(
    service: dict[str, JsonValue],
    report: dict[str, JsonValue],
) -> tuple[dict[str, JsonValue], dict[str, JsonValue]]:
    """Finalize a provider component report through the public reason allowlist."""

    if "credential_reason" in report:
        report["credential_reason"] = _allowlisted_provider_setup_reason(
            report.get("credential_reason")
        )
    return service, report


def _provider_credential_ready(report: Mapping[str, object]) -> bool:
    return report.get("credential") in {"stored", "external_runtime_oauth"}


def _prompt_yes_no_before_credential(
    prompt: str,
    *,
    default: bool,
) -> bool:
    """Read one visible yes/no choice without ever reflecting an invalid response."""

    typer.echo("  This is a visible yes/no prompt. API-key entry has not started.")
    typer.echo("  Enter only yes or no. A separate heading will announce hidden secret input.")
    default_text = "Y" if default else "N"
    suffix = "Y/n" if default else "y/N"
    while True:
        raw = typer.prompt(
            f"{prompt} [{suffix}]",
            default=default_text,
            show_default=False,
        )
        answer = raw.strip().casefold()
        if answer in {"y", "yes"}:
            return True
        if answer in {"n", "no"}:
            return False
        typer.echo(
            "Not accepted: this was a yes/no consent prompt, not credential entry. "
            "No API key was read or stored; enter only yes or no.",
            err=True,
        )


def _prompt_credential_probe_authorization() -> bool:
    """Collect credential-probe consent before the separately labelled hidden ceremony."""

    typer.echo("")
    typer.echo("Privacy and credential-verification consent")
    return _prompt_yes_no_before_credential(
        "After storage, permit one fixed, content-free request to verify this API key?",
        default=True,
    )


def _emit_hidden_credential_transition() -> None:
    """Make the first confidential-input boundary unmistakable."""

    typer.echo("")
    typer.echo("Hidden credential ceremony begins now")
    typer.echo(
        "  Secret prompts from this point use the trusted local terminal with input echo disabled."
    )
    typer.echo(
        "  The ceremony may request vault reauthentication first. Enter the API key only at "
        "the hidden 'Provider credential:' prompt."
    )


def _append_next_step(next_steps: list[JsonValue], step: str) -> None:
    if step not in next_steps:
        next_steps.append(step)


_ADVICE_UNREADABLE_NOTE: Final = "background_advice_unreadable"
_ADVICE_READY_NOTE: Final = "configured_and_composed; live_provider_dispatch_not_tested"
_ADVICE_OFF_PREFIX: Final = "background_advice_off:"
_ADVICE_NOT_DEMONSTRATED: Final = "not demonstrated"
# Closed readiness note -> the fixed words the setup summary shows after "not demonstrated".
# A note absent from this map renders "not demonstrated" alone, never itself (#888).
_ADVICE_NOTE_REASON_TEXT: Final[Mapping[str, str]] = {
    "semantic_configuration_incomplete": "the AI-powered review provider is not ready",
    "deterministic_only_until_provider_ready": (
        "local checks only until an AI-powered review provider is ready"
    ),
    _ADVICE_UNREADABLE_NOTE: "the background-advice setting could not be read",
}


def _background_advice_off_text(reason: str) -> str | None:
    """Fixed text for a reason that says background advice is off; any other reason is ``None``."""

    from finishup.cli.provider_status import (
        BACKGROUND_ADVICE_ON_REASONS,
        background_advice_human_line,
    )

    # A reason for an on switch contradicts itself under "off".
    if reason in BACKGROUND_ADVICE_ON_REASONS:
        return None
    return background_advice_human_line({"reason": reason})


def _semantic_advice_readiness(status: Mapping[str, object]) -> tuple[bool, str]:
    """Background-advice readiness and its closed note from a provider status report.

    Background advice is its own switch, on by default where AI-powered review is configured and
    off when the owner sets it false (#888): a ready provider alone is not ready background
    advice. A provider that is not ready is the configuration-incomplete case whatever the advice
    fact says. Once it is ready, an absent, malformed or unrecognized advice fact, or a reason
    that contradicts ``enabled``, is unreadable, never a raw reason token.
    """

    from finishup.cli.provider_status import BACKGROUND_ADVICE_ON_REASONS

    if status.get("semantic_ready") is not True:
        return False, "semantic_configuration_incomplete"
    advice = status.get("background_advice")
    facts: Mapping[str, object] = (
        cast(Mapping[str, object], advice) if isinstance(advice, Mapping) else {}
    )
    enabled = facts.get("enabled")
    reason = facts.get("reason")
    if enabled is True and reason in BACKGROUND_ADVICE_ON_REASONS:
        return True, _ADVICE_READY_NOTE
    if enabled is False and type(reason) is str and _background_advice_off_text(reason):
        return False, _ADVICE_OFF_PREFIX + reason
    return False, _ADVICE_UNREADABLE_NOTE


def _advice_readiness_text(note: object) -> str:
    """Fixed words for a not-ready advice note; no note token ever renders raw (#888)."""

    if type(note) is str and note.startswith(_ADVICE_OFF_PREFIX):
        off_text = _background_advice_off_text(note.removeprefix(_ADVICE_OFF_PREFIX))
        if off_text is not None:
            return off_text
        note = _ADVICE_UNREADABLE_NOTE
    reason = _ADVICE_NOTE_REASON_TEXT.get(note) if type(note) is str else None
    return _ADVICE_NOT_DEMONSTRATED if reason is None else f"{_ADVICE_NOT_DEMONSTRATED} ({reason})"


def _semantic_status_next_steps(status: Mapping[str, object]) -> tuple[str, ...]:
    """Translate authoritative provider-status blockers into wizard recovery guidance."""

    steps: list[str] = []
    blockers = status.get("blockers")
    if isinstance(blockers, (list, tuple)):
        for blocker_value in cast(list[object] | tuple[object, ...], blockers):
            if not isinstance(blocker_value, Mapping):
                continue
            blocker = cast(Mapping[str, object], blocker_value)
            condition = blocker.get("condition")
            if condition == "provider_credential":
                if blocker.get("state") == "not_connected":
                    steps.append(_NEXT_CREDENTIAL)
            elif condition == "provider_endpoint":
                steps.append(_NEXT_PROVIDER_TOML)
            elif condition in {"llm_inference_channel", "repository_privacy_grant"}:
                if blocker.get("state") in {"disabled", "missing"}:
                    steps.append(_NEXT_PRIVACY)
            elif condition == "verification.semantic":
                command = blocker.get("next_command")
                if type(command) is str:
                    steps.append(command)
            elif condition == "mcp_route_profile":
                steps.append(
                    "run 'finishup integrate codex mcp preview' and explicitly accept "
                    "re-registration if you want the policy route to permit configured "
                    "AI-powered review"
                )
    else:
        if status.get("endpoint_bound") is False:
            steps.append(_NEXT_PROVIDER_TOML)
        if status.get("credential_connected") is False:
            steps.append(_NEXT_CREDENTIAL)
        if status.get("llm_inference_enabled") is False:
            steps.append(_NEXT_PRIVACY)
        if status.get("repository_grant_state") == "missing":
            steps.append(_NEXT_PRIVACY)
    return tuple(dict.fromkeys(steps))


def _stdout_json(value: JsonValue) -> None:
    sys.stdout.buffer.write(canonical_encode(value) + b"\n")
    sys.stdout.buffer.flush()


def _emit(value: JsonValue, *, json_output: bool) -> None:
    if json_output or not sys.stdout.isatty():
        _stdout_json(value)
    else:
        typer.echo(canonical_encode(value).decode("utf-8"))


def _usage_failure(message: str) -> int:
    typer.echo(f"invalid_request: {message}", err=True)
    return 2


class _UsageExit(Exception):
    """Internal control flow for a selection failure with an already-printed message."""

    def __init__(self, code: int) -> None:
        super().__init__(code)
        self.code = code


def setup_marker_present() -> bool:
    """Report whether the wizard completion marker exists, failing closed on unsafe paths."""

    try:
        return setup_marker_path().is_file()
    except PathSafetyError, OSError:
        # An unsafe or unreadable state directory must never trigger the wizard.
        return True


def should_offer_first_run() -> bool:
    """True only for an interactive terminal with no completion marker recorded."""

    try:
        interactive = sys.stdin.isatty() and sys.stdout.isatty()
    except OSError, ValueError:
        return False
    return interactive and not setup_marker_present()


def _integration_layers(workspace: Path | None = None) -> dict[str, JsonValue]:
    """Inspect skill, plugin, hook, and trust state without inferring activation.

    ``workspace`` is the project setup connected; the current directory when omitted.
    """

    root = str(Path.cwd() if workspace is None else workspace)
    source = None
    try:
        source = load_packaged_skill_source()
    except IntegrationError as error:
        tested_profiles: list[JsonValue] = []
        skill_source_state = error.reason.value
    else:
        tested_profiles = list(source.harness_tested_set)
        skill_source_state = "verified"
    skill_presence = "unknown"
    skill_digest: str | None = None
    skill_compatibility = "unsupported"
    if source is not None:
        try:
            skill_inspection = inspect_destination(
                IntegrationTarget(IntegrationScope.TRUSTED_PROJECT, root),
                source,
            )
        except IntegrationError:
            skill_presence = "unknown"
        else:
            skill_presence = skill_inspection.state.value
            skill_digest = skill_inspection.installed_digest
            skill_compatibility = "supported" if tested_profiles else "unsupported"
    try:
        inspection = inspect_plugin(IntegrationTarget(IntegrationScope.TRUSTED_PROJECT, root))
    except IntegrationError as error:
        return {
            "hooks": {
                "presence": "unknown",
                "trust_observable": False,
                "trust_state": "unknown",
            },
            "plugin": {
                "digest": None,
                "presence": "unknown",
                "reason": error.reason.value,
            },
            "skill": {
                "automatic_activation_tested": False,
                "compatibility": skill_compatibility,
                "installed_digest": skill_digest,
                "presence": skill_presence,
                "source_state": skill_source_state,
                "tested_profiles": tested_profiles,
            },
        }
    return {
        "hooks": {
            "presence": inspection.presence.value,
            "trust_observable": inspection.trust_observable,
            "trust_state": "observable" if inspection.trust_observable else "unknown",
        },
        "plugin": {
            "digest": inspection.installed_digest,
            "presence": inspection.presence.value,
        },
        "skill": {
            "automatic_activation_tested": bool(tested_profiles),
            "compatibility": skill_compatibility,
            "installed_digest": skill_digest,
            "presence": skill_presence,
            "source_state": skill_source_state,
            "tested_profiles": tested_profiles,
        },
    }


def _is_interactive_terminal() -> bool:
    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except OSError, ValueError:
        return False


type ReviewChoice = Literal["agent_opt_in", "local_only", "ai_powered"]

# The owner's three first-run answers (ADR-049). Each maps to the conversation setting the drafted
# privacy policy carries; all three register the ``policy`` MCP route, so the owner can widen
# later without re-registering, and the privacy policy alone decides what may be sent.
_REVIEW_CHOICES: Final[tuple[tuple[ReviewChoice, str], ...]] = (
    (
        "agent_opt_in",
        "FinishUP (recommended): local checks; your agent can turn on AI-powered review for a "
        "task when it helps",
    ),
    ("local_only", "FinishUP, local only (agents may not opt in)"),
    ("ai_powered", "AI-powered review on every task"),
)


def review_choice_conversation_setting(choice: ReviewChoice) -> ConversationReview:
    """The privacy-policy conversation setting one first-run answer stands for (ADR-049)."""

    return {
        "agent_opt_in": ConversationReview.LOCAL_AGENT_OPT_IN,
        "local_only": ConversationReview.LOCAL_ONLY,
        "ai_powered": ConversationReview.AI_POWERED,
    }[choice]


def _choose_review_mode() -> ReviewChoice:
    """Let first run choose how tasks use AI-powered review before registration (ADR-049).

    Every task starts with FinishUP's local checks unless the owner picks AI-powered review on
    every task. The recommended first answer is the owner's standing permission for an agent to
    turn on AI-powered review for one task when it helps; the second keeps every task local and
    refuses agent opt-in; the third reviews every task. The answer configures nothing on its own:
    reaching egress still needs the reviewer, its credential, and the separately reauthenticated
    privacy decision, and an answer that leads to AI-powered review is drafted into that policy.
    """

    typer.echo("")
    typer.echo("Choose how FinishUP should review work:")
    for number, (_choice, text) in enumerate(_REVIEW_CHOICES, 1):
        typer.echo(f"  {number}. {text}")
    typer.echo(
        "Local checks run on every task. AI-powered review sends work only within the privacy "
        "policy you approve next, and you can change this later with "
        "'finishup privacy conversations'."
    )
    while True:
        raw = typer.prompt("Review mode", default="1").strip()
        if raw in {"1", "2", "3"}:
            return _REVIEW_CHOICES[int(raw) - 1][0]
        typer.echo("Please enter 1, 2, or 3.")


def _write_setup_marker(outcome: str) -> bool:
    try:
        path = setup_marker_path()
        payload = canonical_encode({"outcome": outcome, "schema": SETUP_MARKER_SCHEMA}) + b"\n"
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(descriptor, payload)
        finally:
            os.close(descriptor)
    except PathSafetyError, OSError:
        return False
    return True


def _binary_row(binary: HarnessBinary) -> dict[str, JsonValue]:
    return {
        "compatibility": binary.compatibility,
        "executable_path": binary.executable_path,
        "harness": binary.harness_id.value,
        "reported_version": binary.reported_version,
    }


def _explicit_binary(codex_path: str) -> HarnessBinary | None:
    candidate = Path(os.path.abspath(codex_path))
    if not candidate.is_file() or not os.access(candidate, os.X_OK):
        return None
    return HarnessBinary(
        harness_id=HarnessId.CODEX,
        executable_path=str(candidate),
        reported_version=None,
        compatibility="untested",
    )


def _choose_harness(
    binaries: tuple[HarnessBinary, ...],
    *,
    codex_path: str | None,
    interactive: bool,
) -> HarnessId | None:
    """Choose one detected supported harness before selecting its installation."""

    if codex_path is not None:
        return HarnessId.CODEX
    if not binaries:
        return None
    if not interactive:
        return HarnessId.CODEX

    harness = HarnessId.CODEX
    count = len(binaries)
    suffix = "installation" if count == 1 else "installations"
    typer.echo("Automatically detected harnesses:")
    typer.echo(f"  1. {_HARNESS_DISPLAY_NAMES[harness]} ({count} {suffix})")
    raw = typer.prompt("Select a harness to connect to FinishUP", default="1")
    if raw != "1":
        raise _UsageExit(_usage_failure("the harness selection is not one of the listed numbers"))
    return harness


def _choose_binary(
    binaries: tuple[HarnessBinary, ...],
    *,
    codex_path: str | None,
    interactive: bool,
) -> HarnessBinary | None:
    """Return the selected binary or ``None`` when none exists; raise ``_UsageExit`` otherwise."""

    if codex_path is not None:
        explicit = _explicit_binary(codex_path)
        if explicit is None:
            raise _UsageExit(_usage_failure("the --codex-path executable was not found"))
        return explicit
    if not binaries:
        return None
    if len(binaries) == 1:
        return binaries[0]
    if not interactive:
        raise _UsageExit(
            _usage_failure("multiple codex executables found; select one with --codex-path")
        )
    typer.echo("Detected Codex installations:")
    for index, binary in enumerate(binaries, start=1):
        version = binary.reported_version or "unknown version"
        typer.echo(f"  {index}. {binary.executable_path} ({version})")
    default = _path_codex_choice([Path(binary.executable_path) for binary in binaries]) or 1
    raw = typer.prompt("Select the Codex installation to configure", default=str(default))
    if not raw.isdecimal() or not 1 <= int(raw) <= len(binaries):
        raise _UsageExit(_usage_failure("the harness selection is not one of the listed numbers"))
    return binaries[int(raw) - 1]


def _confirm_registration() -> bool:
    """Require an explicit capital-insensitive Y or N with no default answer."""

    while True:
        raw = typer.prompt("Apply this registration? [Y/N]", show_default=False)
        answer = raw.strip().upper()
        if answer == "Y":
            return True
        if answer == "N":
            return False
        typer.echo("Please enter Y or N.")


def _confirm_project_setup(
    *, include_observation: bool, include_activation: bool, policy_digest: str | None
) -> bool:
    """One confirmed operation covering MCP/plugin/guidance/hooks/observation consent."""

    typer.echo("This confirmation covers:")
    typer.echo("  - Project skill plus plugin / hook source installation in this trusted project")
    typer.echo("  - MCP registration")
    if include_activation:
        typer.echo("  - Enable the exact activation bytes shown above in the selected Codex home")
    if include_observation:
        typer.echo(
            "  - Observation consent for this workspace "
            "(structural Codex events only; never raw path logged)"
        )
        typer.echo("  - Advice readiness once observation evidence exists")
    if policy_digest is not None:
        typer.echo(f"  - Trust exact approved-check policy digest {policy_digest}")
    while True:
        raw = typer.prompt("Confirm Codex project setup? [Y/N]", show_default=False)
        answer = raw.strip().upper()
        if answer == "Y":
            return True
        if answer == "N":
            return False
        typer.echo("Please enter Y or N.")


def _grant_observation_consent(workspace: Path | None = None) -> dict[str, JsonValue]:
    """Record observation consent via private workspace commitment (never log raw path).

    Structural setup never names a content-profile set, so another host's already-approved
    native content arm and the unchanged content fence survive this step (issue #835). The
    report lists the arms left in force; only explicit content-disable or revoke removes one.
    """

    try:
        from finishup.adapters.integrations.observation_local import LocalObservationStore

        store = LocalObservationStore()
        root = _canonical_setup_workspace(workspace)
        commitment = store.workspace_commitment(str(root))
        grant = store.grant_consent(commitment)
        return {
            "outcome": "granted",
            "transition": grant.transition.value,
            "workspace_commitment": commitment,
            "content_capture_profiles": list(grant.consent.content_capture_profiles),
        }
    except Exception as error:
        return {
            "outcome": "failed",
            "reason": type(error).__name__,
            "workspace_commitment": None,
        }


# Fixed words for an ambiguous approved-check policy (ADR-048); no repository content is echoed.
_POLICY_AMBIGUOUS_TEXT: Final = (
    "both .finishup/checks.toml and the earlier .yoetz/checks.toml exist; neither is used "
    "until you remove one"
)


def _check_policy_preview(workspace: Path | None = None) -> dict[str, JsonValue]:
    """Return a path-free exact-byte policy preview; repository bytes grant no authority."""

    root = _canonical_setup_workspace(workspace)
    try:
        policy, _raw = load_observation_check_policy(root)
    except ObservationCheckPolicyAmbiguous:
        # Both `.finishup/checks.toml` and the legacy `.yoetz/checks.toml` exist (ADR-048).
        # Neither is proposed, and the owner is told why rather than shown "absent".
        return {
            "outcome": "ambiguous",
            "reason": "policy_ambiguous",
            "policy_digest": None,
            "check_ids": (),
        }
    except Exception:
        return {"outcome": "absent", "policy_digest": None, "check_ids": ()}
    return {
        "outcome": "proposed",
        "policy_digest": policy.raw_digest,
        "check_ids": tuple(item.approval_id for item in policy.checks),
    }


def _activate_check_policy_trust(
    workspace: Path | None,
    preview: dict[str, JsonValue],
    *,
    exact_digest_confirmed: bool,
) -> dict[str, JsonValue]:
    """Activate only the exact bytes shown to a trusted local human."""

    digest = preview.get("policy_digest")
    if type(digest) is not str:
        return preview
    if not exact_digest_confirmed:
        return {**preview, "outcome": "untrusted_confirmation_required"}
    try:
        from finishup.adapters.integrations.observation_local import LocalObservationStore

        root = _canonical_setup_workspace(workspace)
        policy, _raw = load_observation_check_policy(root)
        if policy.raw_digest != digest:
            return {**preview, "outcome": "untrusted_digest_changed"}
        store = LocalObservationStore()
        commitment = store.workspace_commitment(str(root))
        store.trust_policy_digest(commitment, digest)
        return {**preview, "outcome": "trusted"}
    except Exception:
        return {**preview, "outcome": "untrusted_activation_failed"}


def _shared_route_change_members(
    codex_home: Path | None,
    project: Path | None,
    before: str | None,
    after: str | None,
) -> tuple[tuple[str, ...], tuple[str, ...], bool]:
    """Other projects of the Codex home whose review mode this registration change rewrites.

    ``[mcp_servers.finishup]`` is user-level: every project in the home runs its review mode
    (#1058 review round 2). ``(verified serving members, possible users, unknown)``, the lists
    excluding ``project``; empty when the mode does not change. ``unknown`` is True when the
    membership cannot be read (a damaged record, an unsafe home): never "nobody else".
    """

    if before is None or after is None or before == after:
        return (), (), False
    from finishup.adapters.integrations.codex_marketplace import other_members
    from finishup.adapters.integrations.codex_session_stream import resolve_codex_home

    try:
        home = resolve_codex_home(codex_home).absolute()
        verified, possible = other_members(home, project)
    except OSError, ValueError, IntegrationError:
        return (), (), True
    return verified, possible, False


def _route_change_report(
    before: str | None,
    after: str | None,
    verified: tuple[str, ...],
    possible: tuple[str, ...],
    unknown: bool = False,
) -> dict[str, JsonValue]:
    """The disclosure keys every shared review-mode change carries (setup run, TUI, integrate)."""

    if before is None or after is None or before == after or not (verified or possible or unknown):
        return {}
    report: dict[str, JsonValue] = {
        "route_profile_before": before,
        "route_changes_for": cast(list[JsonValue], list(verified)),
    }
    if possible:
        report["route_changes_possible_for"] = cast(list[JsonValue], list(possible))
    if unknown:
        # The projects using this home cannot be read: the change may reach any of them.
        report["membership_unknown"] = True
    return report


async def _observed_route_before(
    service: HarnessMcpService, binary: HarnessBinary, preview: McpRegistrationPreview
) -> Literal["policy", "strict"] | None:
    """The review mode the home's FinishUP registration has now, read from the registration.

    Not inferred from the preview's action: a re-registration may change only the launcher or
    isolation root (a legacy bare `yoetz` entry) and keep the mode (#1058 review round 3).
    A failed read raises: the caller reports it rather than guessing the mode.
    """

    if preview.state_before is not McpRegistrationState.FINISHUP_OWNED:
        return None
    return (await service.observe(binary)).route_profile


def _route_change_sentence(report: Mapping[str, JsonValue], after: str | None) -> str | None:
    from finishup.cli.host_connection import (
        _route_change_line,  # pyright: ignore[reportPrivateUsage]
    )

    if not report or after is None:
        return None
    return _route_change_line({**report, "route_profile": after})


def _emit_registration_preview(
    binary: HarnessBinary,
    mcp_preview: object,
    policy_preview: dict[str, JsonValue] | None = None,
    skill_preview: IntegrationPreview | None = None,
    activation_preview: ActivationPreview | None = None,
    activation_target: Path | None = None,
    *,
    route_profile_before: str | None = None,
    route_change: Mapping[str, JsonValue] | None = None,
) -> None:
    typer.echo("Proposed change: complete FinishUP Codex project integration:")
    typer.echo("  1. Install discoverable guidance under .agents/skills/finishup")
    typer.echo("  2. Install structural plugin / hook sources under .agents/plugins/finishup")
    typer.echo("  3. Register the FinishUP MCP server with Codex")
    typer.echo("  MCP server name: finishup")
    _emit_legacy_registration(getattr(mcp_preview, "legacy_registration", "none"))
    serve_command = getattr(mcp_preview, "serve_command", ())
    typer.echo(f"  Command: {shlex.join(serve_command)}")
    isolated_root = getattr(mcp_preview, "isolated_root", None)
    typer.echo(
        "  MCP isolation root: " + (str(isolated_root) if isolated_root is not None else "ambient")
    )
    route_profile = getattr(mcp_preview, "route_profile", None)
    if type(route_profile) is str:
        if route_profile_before is not None and route_profile_before != route_profile:
            typer.echo(
                f"  MCP route profile change: {route_profile_before} -> {route_profile} "
                "(the existing finishup-owned registration will be rewritten)"
            )
            sentence = _route_change_sentence(route_change or {}, route_profile)
            if sentence is not None:
                typer.echo(f"  {sentence}")
        else:
            typer.echo(f"  MCP route profile: {route_profile}")
    typer.echo(f"  Codex executable: {binary.executable_path}")
    if binary.reported_version is not None:
        typer.echo(f"  Codex version: {binary.reported_version}")
    if skill_preview is not None:
        typer.echo(f"  Project skill state: {skill_preview.state_before.value}")
        typer.echo(f"  Project skill compatibility: {skill_preview.compatibility}")
        typer.echo(f"  Project skill preview digest: {skill_preview.preview_digest}")
    if activation_preview is not None:
        project = _canonical_setup_workspace(activation_target)
        marketplace_path = project / ".agents" / "plugins" / "marketplace.json"
        config_path = activation_preview.codex_home / "config.toml"
        typer.echo(f"  Codex activation state: {activation_preview.inspection.state.value}")
        typer.echo(
            "  Canonical installed inventory verified before approval: "
            f"{'yes' if activation_preview.inspection.inventory_verified else 'no'}"
        )
        typer.echo(f"  Repository marketplace target: {marketplace_path}")
        typer.echo(f"  Selected Codex home: {activation_preview.codex_home}")
        typer.echo(f"  Selected Codex config target: {config_path}")
        typer.echo("  Exact marketplace.json bytes:")
        for line in activation_preview.marketplace_bytes.decode("utf-8").splitlines():
            typer.echo(f"    {line}")
        typer.echo("  Exact config.toml block:")
        if activation_preview.config_toml_block:
            for line in activation_preview.config_toml_block.splitlines():
                typer.echo(f"    {line}")
        else:
            typer.echo("    (no byte change; already active)")
        _emit_legacy_activation(
            activation_preview.legacy_removed_block,
            activation_preview.legacy_cache_versions,
            plugin_tree_planned=activation_preview.legacy_plugin_tree_planned,
        )
        typer.echo(f"  Plugin source-tree digest: {activation_preview.plugin_source_digest}")
        typer.echo(f"  Selected activation executable: {activation_preview.executable_path}")
        typer.echo(f"  Activation executable digest: {activation_preview.executable_digest}")
        typer.echo(f"  Activation Codex version: {activation_preview.codex_version}")
        typer.echo(f"  Exact plugin install target: {activation_preview.plugin_install_path}")
        typer.echo(f"  Plugin install-tree digest: {activation_preview.plugin_install_digest}")
        typer.echo(
            f"  Marketplace preimage digest: {activation_preview.marketplace_preimage_digest}"
        )
        typer.echo(f"  Config preimage digest: {activation_preview.config_preimage_digest}")
        typer.echo(
            "  Plugin cache mutation planned: "
            f"{'yes' if activation_preview.cache_mutation_planned else 'no'}"
        )
        typer.echo("  Exact activation commands:")
        typer.echo(f"    version probe environment: {activation_preview.probe_environment}")
        typer.echo("    inventory/install environment:")
        for name, value in activation_preview.activation_environment:
            typer.echo(f"      {name}={value}")
        for command in (
            activation_preview.probe_command,
            activation_preview.inventory_command,
            activation_preview.install_command,
        ):
            typer.echo(f"    {activation_preview.executable_path} {' '.join(command)}")
        typer.echo(f"  Activation preview digest: {activation_preview.preview_digest}")
        typer.echo(
            "  Standing-trust warning: this enables the repository plugin for future Codex "
            "sessions using this exact Codex home until you disable or remove it."
        )
    digest = None if policy_preview is None else policy_preview.get("policy_digest")
    if policy_preview is not None and policy_preview.get("outcome") == "ambiguous":
        typer.echo(f"  Approved-check policy: ambiguous ({_POLICY_AMBIGUOUS_TEXT})")
    if type(digest) is str:
        typer.echo(f"  Approved-check policy digest: {digest}")
        check_ids = policy_preview.get("check_ids") if policy_preview is not None else None
        if isinstance(check_ids, tuple):
            typer.echo(f"  Proposed checks: {', '.join(str(item) for item in check_ids)}")
        typer.echo("  Repository policy bytes propose commands; this confirmation activates only")
        typer.echo("  the exact digest above. Any byte change suspends execution.")


def _emit_legacy_registration(legacy_registration: object) -> None:
    """Name what the approval does with an entry under the pre-rename key (ADR-048)."""

    if legacy_registration in {"legacy_only", "duplicate"}:
        typer.echo(
            "  Legacy MCP server name: yoetz (FinishUP-owned from an earlier install; "
            "this change removes it)"
        )
    elif legacy_registration == "foreign":
        typer.echo("  Legacy MCP server name: yoetz (not provably FinishUP's; left unchanged)")


def _emit_legacy_activation(
    removed_block: str, cache_versions: tuple[str, ...], *, plugin_tree_planned: bool = False
) -> None:
    """Show the exact Yoetz-era activation bytes an approval also removes (ADR-048)."""

    if not removed_block and not cache_versions and not plugin_tree_planned:
        return
    typer.echo("  Earlier Yoetz activation removed by this change:")
    for line in removed_block.splitlines():
        typer.echo(f"    {line}")
    if cache_versions:
        typer.echo(f"    plugin cache versions: {', '.join(cache_versions)}")
    if plugin_tree_planned:
        typer.echo(
            "    plugin source tree: .agents/plugins/yoetz (FinishUP-managed; deleted last, "
            "once nothing activated here reads it)"
        )


def _emit_legacy_plugin_tree(notes: tuple[str, ...], *, removal_planned: bool) -> None:
    """Say what happens to a Yoetz-era plugin tree beside the FinishUP one (ADR-048)."""

    if "legacy_plugin_tree_present" in notes and not removal_planned:
        typer.echo(
            "  Earlier Yoetz plugin sources (.agents/plugins/yoetz): kept; only an approved "
            "Codex plugin activation removes them"
        )
    elif "legacy_plugin_tree_retained" in notes:
        typer.echo(
            "  Earlier Yoetz plugin directory (.agents/plugins/yoetz): not provably "
            "FinishUP's; left unchanged"
        )


def _emit_unregistration_preview(mcp_preview: object) -> None:
    """Show every approval-relevant removal field before interactive consent."""

    typer.echo("Proposed change: remove the FinishUP-owned Codex MCP registration")
    legacy = getattr(mcp_preview, "legacy_registration", "none")
    if legacy == "legacy_only":
        typer.echo("  MCP server name: yoetz")
    elif legacy == "duplicate":
        typer.echo("  MCP server names: finishup, yoetz")
    else:
        typer.echo("  MCP server name: finishup")
    _emit_legacy_registration(legacy)
    if "foreign_entry_present" in getattr(mcp_preview, "warnings", ()):
        typer.echo("  Foreign MCP server finishup: retained; not provably FinishUP's")
    typer.echo(f"  Action: {getattr(mcp_preview, 'action').value}")
    typer.echo(f"  State before: {getattr(mcp_preview, 'state_before').value}")
    serve_command = getattr(mcp_preview, "serve_command", ())
    typer.echo(f"  Command: {shlex.join(serve_command)}")
    isolated_root = getattr(mcp_preview, "isolated_root", None)
    typer.echo(
        "  MCP isolation root: " + (str(isolated_root) if isolated_root is not None else "ambient")
    )
    route_profile = getattr(mcp_preview, "route_profile", None)
    if type(route_profile) is str:
        typer.echo(f"  MCP route profile: {route_profile}")
    for warning in getattr(mcp_preview, "warnings", ()):
        typer.echo(f"  Warning: {warning}")
    typer.echo(f"  Preview digest: {getattr(mcp_preview, 'preview_digest')}")


def _plugin_verified(presence: str | None) -> bool:
    return presence == PluginHookPresence.INSTALLED.value


async def _install_project_skill(
    target: IntegrationTarget,
    *,
    adapter: CodexSkillIntegration,
    operation_id: RequestId,
    accepted_preview: IntegrationPreview,
) -> dict[str, JsonValue]:
    """Install the project-scoped skill without claiming Codex capability support.

    Project skill discovery is a separate, native Codex surface from plugin loading.  Setup may
    explicitly install the reviewed bytes for an unprofiled Codex release after the enclosing
    project-integration preview is accepted, but the returned compatibility remains unsupported
    until an exact capability cell is frozen.
    """

    try:
        result = await adapter.install_skill(
            HarnessId.CODEX,
            SkillApplyCommand(
                operation_id,
                target,
                IntegrationAction.INSTALL,
                accepted_preview.preview_digest,
                True,
                False,
            ),
        )
    except IntegrationError as error:
        return {
            "compatibility": "unsupported",
            "outcome": "failed",
            "presence": None,
            "reason": error.reason.value,
        }
    return {
        "compatibility": accepted_preview.compatibility,
        "installed_digest": result.installed_digest,
        "outcome": "already_installed" if result.action is IntegrationAction.NOOP else "installed",
        "presence": result.state_after.value,
        "reason": None,
    }


@dataclass(frozen=True, slots=True)
class _ProjectSkillPlan:
    adapter: CodexSkillIntegration
    operation_id: RequestId
    preview: IntegrationPreview


async def _preview_project_skill(target: IntegrationTarget) -> _ProjectSkillPlan:
    """Create the exact project-skill plan before any setup acceptance is collected."""

    adapter = CodexSkillIntegration(allow_untested=True)
    operation_id = request_id(new_id(IdKind.REQUEST))
    preview = await adapter.preview_skill(
        HarnessId.CODEX,
        SkillPreviewCommand(
            operation_id,
            target,
            IntegrationAction.INSTALL,
            False,
        ),
    )
    return _ProjectSkillPlan(adapter, operation_id, preview)


async def project_skill_preview(workspace: Path | None = None) -> IntegrationPreview:
    """Return the exact setup skill preview for a non-prompt front end."""

    root = _canonical_setup_workspace(workspace)
    target = IntegrationTarget(IntegrationScope.TRUSTED_PROJECT, str(root))
    return (await _preview_project_skill(target)).preview


def _integration_target(workspace: Path | None = None) -> IntegrationTarget:
    root = _canonical_setup_workspace(workspace)
    return IntegrationTarget(IntegrationScope.TRUSTED_PROJECT, str(root))


def codex_activation_preview(
    binary: HarnessBinary,
    codex_home: Path,
    workspace: Path | None = None,
) -> ActivationPreview:
    """Preview activation against the exact home loaded by the selected Codex binary."""

    return preview_activation(
        _integration_target(workspace),
        executable_path=binary.executable_path,
        codex_home=codex_home,
    )


def _configured_mcp_route_profile() -> Literal["policy", "strict"]:
    """Choose the registration-time route posture from structural local configuration."""

    try:
        config = load_config({}, os.environ, None)
    except Exception:
        return "strict"
    if config.verification.semantic == "disabled":
        return "strict"
    return "strict" if config.provider is None and config.local_model is None else "policy"


def configured_mcp_route_profile() -> Literal["policy", "strict"]:
    """Public registration-time route posture for front ends with no answer of their own.

    A caller that has just asked the human which review posture they want passes that answer
    instead: the reply is the authority, and configuration is only the fallback for surfaces
    (post-setup ``/connect``, ``integrate codex mcp``) that ask nothing. Even then it applies
    only to a *fresh* registration: an existing finishup-owned registration keeps its observed
    route unless an explicit route input requests otherwise (#389 / ADR-018).
    """

    return _configured_mcp_route_profile()


def _mcp_adapter(
    route_profile: Literal["policy", "strict"] | None = None,
    *,
    codex_home: Path | None = None,
) -> CodexMcpAdapter:
    return CodexMcpAdapter(
        route_profile=_configured_mcp_route_profile() if route_profile is None else route_profile,
        codex_home=codex_home,
    )


def _installed_hooks_declare_workspace_binding(workspace: Path | None = None) -> bool:
    """True when the installed plugin hooks render ``--workspace .`` for observe."""

    root = _canonical_setup_workspace(workspace)
    hooks_path = root / ".agents" / "plugins" / "finishup" / "hooks" / "hooks.json"
    try:
        raw = hooks_path.read_bytes()
    except FileNotFoundError:
        # Frozen legacy identifier (ADR-048): a Yoetz-era plugin tree an upgrade has not yet
        # migrated still binds the workspace through the deprecated ``yoetz`` alias. Only a
        # missing FinishUP file falls back; an unreadable one never reads as bound.
        try:
            raw = (root / ".agents" / "plugins" / "yoetz" / "hooks" / "hooks.json").read_bytes()
        except OSError:
            return False
    except OSError:
        return False
    return b"--workspace ." in raw and (
        b"finishup hooks observe" in raw or b"yoetz hooks observe" in raw
    )


def _observation_hook_probe(*, workspace: Path | None = None) -> dict[str, JsonValue]:
    """Prove project binding + envelope enqueue without polluting the real store.

    The real store is read only to require existing workspace consent. The synthetic
    SessionStart, consent copy, lifecycle mapping, and outbox row all live in a fresh
    owner-private temporary state directory and are destroyed before returning.
    """

    from finishup.adapters.integrations.observation_local import LocalObservationStore
    from finishup.cli.observe_hooks import handle_observe
    from finishup.protocol.canonical import canonical_encode

    root = _canonical_setup_workspace(workspace)
    if not _installed_hooks_declare_workspace_binding(root):
        return {"ok": False, "reason": "hooks_missing_workspace_binding"}
    store = LocalObservationStore()
    commitment = store.workspace_commitment(str(root))
    consent = store.consent_for(commitment)
    if consent is None or not consent.active:
        return {"ok": False, "reason": "consent_inactive"}
    with tempfile.TemporaryDirectory(
        prefix=".finishup-setup-observation-probe-", dir=root.parent
    ) as temporary:
        probe_state = Path(temporary)
        probe_store = LocalObservationStore(_state=probe_state)
        probe_commitment = probe_store.workspace_commitment(str(root))
        probe_store.grant_consent(probe_commitment)
        probe_session = "finishup-setup-probe-session"
        payload = canonical_encode(
            {
                "session_id": probe_session,
                "hook_event_name": "SessionStart",
                "cwd": ".",
            }
        )
        with contextlib.redirect_stderr(io.StringIO()):
            code = handle_observe(
                event_name="SessionStart",
                stdin_bytes=payload,
                stdout=io.BytesIO(),
                workspace=str(root),
                skip_service=True,
                _state=probe_state,
            )
        if code != 0:
            return {"ok": False, "reason": "observe_exit_nonzero"}
        bound = probe_store.find_workspace_for_codex_session(probe_session)
        if bound != probe_commitment:
            return {"ok": False, "reason": "binding_missing"}
        pending = probe_store.list_pending_outbox(probe_commitment)
        if not pending:
            return {"ok": True, "reason": "bound_without_pending"}
        return {"ok": True, "reason": "envelope_enqueued"}


def _readiness_layers(
    *,
    binary: HarnessBinary | None,
    mcp_state: str | None,
    plugin_presence: str | None,
    skill_presence: str | None,
    hooks: dict[str, JsonValue],
    consent_outcome: str | None,
    service: dict[str, JsonValue],
    workspace: Path | None = None,
    codex_home: Path | None = None,
) -> dict[str, JsonValue]:
    consent_active = consent_outcome == "granted"
    service_routing = bool(service.get("reachable"))
    # Unobserved facts start as null (unknown), never as an asserted ``false``;
    # they become booleans only when an inspection actually ran (#390).
    activation: dict[str, JsonValue] = {
        "codex_home": None,
        "config_path": None,
        "legacy_activation": None,
        "marketplace_registered": None,
        "plugin_enabled": None,
        "state": "unknown",
    }
    if binary is not None and codex_home is not None:
        # The bound home is echoed even when inspection fails, so a failure can
        # never read as "no home was provided" (#390).
        activation["codex_home"] = str(codex_home)
        activation["config_path"] = str(codex_home / "config.toml")
        try:
            inspected = inspect_activation(
                _integration_target(workspace),
                executable_path=binary.executable_path,
                codex_home=codex_home,
            )
            activation["marketplace_registered"] = inspected.marketplace_registered
            activation["plugin_enabled"] = inspected.plugin_enabled
            activation["state"] = inspected.state.value
            # An owned Yoetz-era activation of this project is still present; integrate
            # migrates it and removal deactivates it (ADR-048).
            activation["legacy_activation"] = inspected.legacy_activation
        except IntegrationError as error:
            activation["reason"] = error.reason.value
        except (OSError, TypeError, ValueError) as error:
            activation["reason"] = type(error).__name__
    elif binary is not None:
        activation["reason"] = "codex_home_required"
    activation_active = activation.get("state") == ActivationState.ACTIVE.value
    probe: dict[str, JsonValue] = {"ok": False, "reason": "not_attempted"}
    if _plugin_verified(plugin_presence) and activation_active and consent_active:
        try:
            probe = _observation_hook_probe(workspace=workspace)
        except Exception as error:
            probe = {"ok": False, "reason": type(error).__name__}
    observation_ready = (
        _plugin_verified(plugin_presence)
        and activation_active
        and consent_active
        and service_routing
        and bool(probe.get("ok"))
    )
    return {
        "codex": None
        if binary is None
        else {
            "executable_path": binary.executable_path,
            "reported_version": binary.reported_version,
        },
        "mcp_registration": mcp_state,
        "plugin_installation": plugin_presence,
        "plugin_activation": activation,
        "project_skill_installation": skill_presence,
        "hooks": hooks,
        "consent": consent_outcome or "absent",
        "service_routing": {
            "reachable": service_routing,
            "state": service.get("state"),
        },
        "observation_hook_probe": probe,
        "observation_ready": observation_ready,
        "semantic_advice_ready": False,
        "semantic_advice_note": "deterministic_only_until_provider_ready",
    }


def _legacy_route_kept_step(preview: McpRegistrationPreview) -> str:
    """The way on when a kept ``yoetz`` entry serves another review mode (#1073)."""

    from finishup.cli.codex_connection import legacy_kept_disclosure
    from finishup.cli.host_connection import refusal_step

    return (
        refusal_step(
            "connection_legacy_registration_route_kept",
            {
                "route_profile_before": preview.legacy_route_profile,
                "route_profile": preview.route_profile,
                **legacy_kept_disclosure(preview.legacy_kept_for, preview.legacy_kept_unchecked),
            },
        )
        or ""
    )


async def _codex_integration_step(
    binary: HarnessBinary,
    *,
    interactive: bool,
    accept: bool,
    route_profile: Literal["policy", "strict"] | None = None,
    workspace: Path | None = None,
    approved_preview_digest: str | None = None,
    approved_activation_mcp_command: tuple[str, ...] | None = None,
    approved_skill_preview_digest: str | None = None,
    approved_activation_digest: str | None = None,
    approved_policy_digest: str | None = None,
    codex_home: Path | None = None,
    _state: Path | None = None,
) -> dict[str, JsonValue]:
    """Preview and apply one Codex integration: skill + plugin sources + MCP + consent.

    The three integration preview digests let a caller that has already shown a human the exact
    previews echo them back. They are a *stricter* gate than ``accept``, not a softer one: the
    step re-previews and refuses as stale if any digest moved since approval was shown,
    and only an explicitly echoed policy digest activates the policy trust.

    ``route_profile=None`` means "no explicit route input": an existing finishup-owned
    registration keeps its observed profile, and a fresh registration defaults to
    strict. No configuration derivation (or derivation-on-exception fallback) may
    silently rewrite a previously chosen route (#389 / ADR-018).
    """

    from finishup.cli.runtime_refusal import connect_refusal

    refusal = connect_refusal()
    if refusal is not None:
        # Codex would launch this runtime for MCP and every hook, and each launch would be
        # refused: register nothing, and say why and what to do (ADR-007, 2026-10-14).
        token, next_step = refusal
        return {
            "outcome": "failed",
            "reason": token,
            "next_step": next_step,
            "state": None,
            "plugin": {"outcome": "skipped", "presence": None},
            "plugin_activation": {"outcome": "skipped", "state": "unknown"},
            "skill": {"outcome": "skipped", "presence": None},
            "observation_consent": {"outcome": "absent", "workspace_commitment": None},
        }
    plugin_service = CodexPluginService()
    project = _integration_target(workspace)
    selected_codex_home: Path | None = None
    activation_plan: ActivationPreview | None = None
    activation_unavailable_reason = "codex_home_required"
    if codex_home is not None:
        try:
            selected_codex_home = resolve_codex_home_for_binary(
                binary.executable_path, codex_home=codex_home
            )
            activation_plan = preview_activation(
                project,
                executable_path=binary.executable_path,
                codex_home=selected_codex_home,
            )
        except IntegrationError as error:
            activation_unavailable_reason = error.reason.value
            # A caller echoing an activation digest explicitly requested that exact mutation.
            # Without a usable explicit home, fail closed instead of silently applying only the
            # other integration surfaces.
            if selected_codex_home is None or approved_activation_digest is not None:
                return {
                    "outcome": "failed",
                    "reason": "activation_preview_failed",
                    "state": None,
                    "plugin": {"outcome": "skipped", "presence": None},
                    "plugin_activation": {
                        "codex_home": str(
                            selected_codex_home if selected_codex_home is not None else codex_home
                        ),
                        "outcome": "failed",
                        "reason": activation_unavailable_reason,
                        "state": "unknown",
                    },
                    "skill": {"outcome": "skipped", "presence": None},
                    "observation_consent": {
                        "outcome": "absent",
                        "workspace_commitment": None,
                    },
                }
    activation_state_before = (
        activation_plan.inspection.state.value if activation_plan is not None else "unknown"
    )
    # The wizard's project-tree plugin steps always use the canonical render
    # (``codex_version=None``): the committed source deliberately carries the
    # async-free fallback form, and host-specific rendering belongs only to the
    # activation cache layer (#387).
    bound_home = selected_codex_home if selected_codex_home is not None else codex_home
    activation_unavailable: dict[str, JsonValue] = {
        "outcome": "skipped",
        "reason": activation_unavailable_reason,
        "state": activation_state_before,
    }
    if bound_home is not None:
        # An explicitly bound home is echoed even when the preview failed, so the
        # report never claims the home was missing when it was not (#390).
        activation_unavailable["codex_home"] = str(bound_home)
        activation_unavailable["config_path"] = str(bound_home / "config.toml")
    if activation_plan is None and approved_activation_digest is not None:
        return {
            "outcome": "failed",
            "reason": "activation_preview_failed",
            "state": None,
            "plugin": {"outcome": "skipped", "presence": None},
            "plugin_activation": {
                **activation_unavailable,
                "outcome": "failed",
            },
            "skill": {"outcome": "skipped", "presence": None},
            "observation_consent": {"outcome": "absent", "workspace_commitment": None},
        }
    mcp_service = HarnessMcpService(
        _mcp_adapter(
            "strict" if route_profile is None else route_profile,
            codex_home=bound_home,
        )
    )
    try:
        mcp_preview = await mcp_service.preview(binary)
    except McpRegistrationError as error:
        return {
            "outcome": "failed",
            "reason": error.reason.value,
            "detail": error.safe_details.get("detail"),
            "state": None,
            "plugin": {"outcome": "skipped", "presence": None},
            "plugin_activation": {"outcome": "skipped", "state": "unknown"},
            "skill": {"outcome": "skipped", "presence": None},
            "observation_consent": {"outcome": "absent", "workspace_commitment": None},
        }

    # The existing owned registration's mode is read from the registration itself: a
    # ``reregister`` may change only the launcher, isolation root, or legacy key and keep the
    # mode (#1058 review round 3, ADR-048).
    try:
        route_profile_before = await _observed_route_before(mcp_service, binary, mcp_preview)
    except McpRegistrationError as error:
        return {
            "outcome": "failed",
            "reason": error.reason.value,
            "detail": error.safe_details.get("detail"),
            "state": None,
            "plugin": {"outcome": "skipped", "presence": None},
            "plugin_activation": {"outcome": "skipped", "state": "unknown"},
            "skill": {"outcome": "skipped", "presence": None},
            "observation_consent": {"outcome": "absent", "workspace_commitment": None},
        }
    if (
        route_profile is None
        and route_profile_before is not None
        and route_profile_before != mcp_preview.route_profile
    ):
        # No explicit route input: preserve the observed profile of the existing
        # finishup-owned registration instead of rewriting it (#389).
        mcp_service = HarnessMcpService(_mcp_adapter(route_profile_before, codex_home=bound_home))
        try:
            mcp_preview = await mcp_service.preview(binary)
        except McpRegistrationError as error:
            return {
                "outcome": "failed",
                "reason": error.reason.value,
                "state": None,
                "plugin": {"outcome": "skipped", "presence": None},
                "plugin_activation": {"outcome": "skipped", "state": "unknown"},
                "skill": {"outcome": "skipped", "presence": None},
                "observation_consent": {"outcome": "absent", "workspace_commitment": None},
            }

    if "legacy_registration_route_kept" in mcp_preview.warnings:
        # An owned ``yoetz`` entry a project's Codex configuration still needs stays beside
        # ``finishup`` and serves the whole home on its own review mode; registering another
        # mode next to it would run both (#1073). Nothing has changed yet.
        return {
            "outcome": "failed",
            "reason": "connection_legacy_registration_route_kept",
            "next_step": _legacy_route_kept_step(mcp_preview),
            "state": None,
            "plugin": {"outcome": "skipped", "presence": None},
            "plugin_activation": {"outcome": "skipped", "state": "unknown"},
            "skill": {"outcome": "skipped", "presence": None},
            "observation_consent": {"outcome": "absent", "workspace_commitment": None},
        }

    plugin_preview = plugin_service.preview(project)
    check_policy = _check_policy_preview(workspace)
    already_registered = mcp_preview.action is McpRegistrationAction.NOOP
    foreign = mcp_preview.state_before is McpRegistrationState.FOREIGN_PRESENT
    # The registration is user-level: a review-mode change reaches every other project of the
    # home, so the preview names them and a bare --accept cannot apply it (#1058 review round 2).
    route_change = _route_change_report(
        route_profile_before,
        mcp_preview.route_profile,
        *_shared_route_change_members(
            bound_home,
            Path(project.project_root),
            route_profile_before,
            mcp_preview.route_profile,
        ),
    )

    if foreign:
        inspection = plugin_service.inspect(project)
        return {
            "outcome": "skipped",
            "reason": "foreign_entry_present",
            "next_step": "Foreign configuration was preserved. Create a new owner-private "
            "directory (mode 0700) and rerun setup with --codex-home <new-home>.",
            "state": mcp_preview.state_before.value,
            "plugin": {
                "outcome": "skipped",
                "presence": inspection.presence.value,
                "reason": "mcp_foreign_entry",
            },
            "plugin_activation": {
                "outcome": "skipped",
                "state": activation_state_before,
            },
            "skill": {"outcome": "skipped", "presence": None},
            "observation_consent": {"outcome": "absent", "workspace_commitment": None},
        }

    try:
        skill_plan = await _preview_project_skill(project)
    except IntegrationError as error:
        return {
            "outcome": "failed",
            "reason": "skill_preview_failed",
            "state": mcp_preview.state_before.value,
            "plugin": {"outcome": "skipped", "presence": plugin_preview.presence_before.value},
            "plugin_activation": {
                "outcome": "skipped",
                "state": activation_state_before,
            },
            "skill": {
                "outcome": "failed",
                "presence": None,
                "reason": error.reason.value,
            },
            "observation_consent": {"outcome": "absent", "workspace_commitment": None},
        }

    external_approval = (
        approved_preview_digest is not None
        or approved_skill_preview_digest is not None
        or approved_activation_digest is not None
    )
    if external_approval and (
        approved_preview_digest != mcp_preview.preview_digest
        or approved_skill_preview_digest != skill_plan.preview.preview_digest
        or (
            approved_activation_digest is not None
            and (
                activation_plan is None
                or approved_activation_digest != activation_plan.preview_digest
            )
        )
    ):
        return {
            "outcome": "failed",
            "reason": "preview_stale",
            "state": mcp_preview.state_before.value,
            "plugin": {"outcome": "skipped", "presence": plugin_preview.presence_before.value},
            "plugin_activation": {
                "outcome": "skipped",
                "reason": "preview_stale",
                "state": activation_state_before,
            },
            "skill": {
                "outcome": "skipped",
                "presence": skill_plan.preview.state_before.value,
                "reason": "preview_stale",
            },
            "observation_consent": {"outcome": "absent", "workspace_commitment": None},
        }

    if route_change and accept and not external_approval:
        from finishup.cli.setup_readiness import continuation

        return {
            "outcome": "failed",
            "reason": "route_change_affects_other_projects",
            **route_change,
            "next_step": (
                "Nothing was changed. This review mode change would also apply to the other "
                "projects using this Codex home, so it needs a preview you have seen: "
                + continuation(
                    [
                        "setup",
                        "run",
                        "--host",
                        "codex",
                        "--host-path",
                        binary.executable_path,
                        *(
                            ["--host-config-root", str(bound_home)]
                            if bound_home is not None
                            else []
                        ),
                        "--route-profile",
                        mcp_preview.route_profile,
                        "--project",
                        project.project_root,
                    ]
                )
                + f". To keep the current mode, rerun with --route-profile {route_profile_before}."
            ),
            "state": mcp_preview.state_before.value,
            "plugin": {"outcome": "skipped", "presence": plugin_preview.presence_before.value},
            "plugin_activation": {"outcome": "skipped", "state": activation_state_before},
            "skill": {
                "outcome": "skipped",
                "presence": skill_plan.preview.state_before.value,
            },
            "observation_consent": {"outcome": "absent", "workspace_commitment": None},
        }
    accepted = accept
    activation_approved = False
    policy_digest_confirmed = False
    if external_approval:
        # The caller displayed both exact previews and collected an explicit yes.
        accepted = True
        activation_approved = (
            activation_plan is not None
            and approved_activation_digest == activation_plan.preview_digest
        )
        shown = check_policy.get("policy_digest")
        policy_digest_confirmed = (
            approved_policy_digest is not None
            and isinstance(shown, str)
            and approved_policy_digest == shown
        )
    if interactive and not accepted:
        _emit_registration_preview(
            binary,
            mcp_preview,
            check_policy,
            skill_plan.preview,
            activation_plan,
            Path(project.project_root),
            route_profile_before=route_profile_before,
            route_change=route_change,
        )
        typer.echo(
            f"  Plugin presence before apply: {plugin_preview.presence_before.value} "
            f"({plugin_preview.planned_file_count} managed files)"
        )
        _emit_legacy_plugin_tree(
            plugin_preview.notes,
            removal_planned=activation_plan is not None
            and activation_plan.legacy_plugin_tree_planned,
        )
        if already_registered:
            typer.echo("  MCP is already registered; setup will still install/verify the plugin.")
        accepted = _confirm_project_setup(
            include_observation=True,
            include_activation=activation_plan is not None,
            policy_digest=cast(str | None, check_policy.get("policy_digest")),
        )
        activation_approved = accepted and activation_plan is not None
        policy_digest_confirmed = accepted and type(check_policy.get("policy_digest")) is str
    if not accepted:
        return {
            "outcome": "declined",
            "reason": None,
            **route_change,
            "state": mcp_preview.state_before.value,
            "plugin": {
                "outcome": "declined",
                "presence": plugin_preview.presence_before.value,
            },
            "plugin_activation": {
                "outcome": "declined",
                "state": activation_state_before,
            },
            "skill": {
                "outcome": "declined",
                "presence": skill_plan.preview.state_before.value,
            },
            "observation_consent": {"outcome": "absent", "workspace_commitment": None},
        }

    # 1) Install the project-scoped skill Codex actually discovers without a marketplace.
    skill_report = await _install_project_skill(
        project,
        adapter=skill_plan.adapter,
        operation_id=skill_plan.operation_id,
        accepted_preview=skill_plan.preview,
    )
    if skill_report.get("outcome") == "failed":
        return {
            "outcome": "failed",
            "reason": "skill_install_failed",
            "state": mcp_preview.state_before.value,
            "plugin": {"outcome": "skipped", "presence": plugin_preview.presence_before.value},
            "plugin_activation": {
                "outcome": "skipped",
                "state": activation_state_before,
            },
            "skill": skill_report,
            "observation_consent": {"outcome": "absent", "workspace_commitment": None},
        }

    # 2) Install and verify structural plugin/hook sources (even when MCP is registered).
    plugin_report: dict[str, JsonValue]
    try:
        inspection = plugin_service.install(
            project,
            allow_untested=True,
        )
        plugin_report = {
            "outcome": "installed",
            "presence": inspection.presence.value,
            "trust_observable": inspection.trust_observable,
            "digest": inspection.installed_digest,
        }
    except IntegrationError as error:
        plugin_report = {
            "outcome": "failed",
            "presence": plugin_preview.presence_before.value,
            "reason": error.reason.value,
        }
        return {
            "outcome": "failed",
            "reason": "plugin_install_failed",
            "state": mcp_preview.state_before.value,
            "plugin": plugin_report,
            "plugin_activation": {
                "outcome": "skipped",
                "state": activation_state_before,
            },
            "skill": skill_report,
            "observation_consent": {"outcome": "absent", "workspace_commitment": None},
        }

    plugin_ok = inspection.presence is PluginHookPresence.INSTALLED
    if not plugin_ok:
        plugin_report["outcome"] = "unverified"
        return {
            "outcome": "failed",
            "reason": "plugin_verification_failed",
            "state": mcp_preview.state_before.value,
            "plugin": plugin_report,
            "plugin_activation": {
                "outcome": "skipped",
                "state": activation_state_before,
            },
            "skill": skill_report,
            "observation_consent": {"outcome": "absent", "workspace_commitment": None},
        }

    # 3) Activation has its own preview-bound approval. Generic ``--accept`` never stands in
    # for bytes the owner was not shown; legacy setup actions may continue, but hooks stay inert.
    if activation_approved and activation_plan is not None and selected_codex_home is not None:
        try:
            activated = apply_activation(
                project,
                codex_home=selected_codex_home,
                executable_path=binary.executable_path,
                approved_digest=activation_plan.preview_digest,
            )
        except IntegrationError as error:
            return {
                "outcome": "failed",
                "reason": "plugin_activation_failed",
                "state": mcp_preview.state_before.value,
                "plugin": plugin_report,
                "plugin_activation": {
                    "codex_home": str(selected_codex_home),
                    "config_path": str(selected_codex_home / "config.toml"),
                    "outcome": "failed",
                    "reason": error.reason.value,
                    "state": activation_plan.inspection.state.value,
                },
                "skill": skill_report,
                "observation_consent": {"outcome": "absent", "workspace_commitment": None},
            }
        activation_report: dict[str, JsonValue] = {
            "codex_home": str(selected_codex_home),
            "config_path": str(selected_codex_home / "config.toml"),
            "legacy_activation": activated.legacy_activation,
            "marketplace_registered": activated.marketplace_registered,
            "outcome": "active",
            "plugin_enabled": activated.plugin_enabled,
            "preview_digest": activation_plan.preview_digest,
            "plugin_source_digest": activation_plan.plugin_source_digest,
            "state": activated.state.value,
        }
    elif activation_plan is not None and selected_codex_home is not None:
        from finishup.cli.setup_readiness import continuation

        activation_report = {
            "next_command": continuation(
                [
                    "recommend",
                    "accept",
                    "codex-plugin-activation",
                    "--codex-path",
                    binary.executable_path,
                    "--codex-home",
                    str(selected_codex_home),
                ],
                project=_canonical_setup_workspace(workspace),
            ),
            "codex_home": str(selected_codex_home),
            "config_path": str(selected_codex_home / "config.toml"),
            # A Yoetz-era activation stays live until this skipped step runs (ADR-048).
            "legacy_activation": activation_plan.inspection.legacy_activation,
            "marketplace_registered": activation_plan.inspection.marketplace_registered,
            "outcome": "skipped",
            "plugin_enabled": activation_plan.inspection.plugin_enabled,
            "reason": "activation_confirmation_required",
            "preview_digest": activation_plan.preview_digest,
            "plugin_source_digest": activation_plan.plugin_source_digest,
            "state": activation_plan.inspection.state.value,
        }
    else:
        activation_report = activation_unavailable

    # 4) Register and verify MCP (noop when already finishup-owned).
    mcp_outcome = (
        "already_registered"
        if already_registered
        else (
            "reregistered"
            if mcp_preview.action is McpRegistrationAction.REREGISTER
            else "registered"
        )
    )
    mcp_state = mcp_preview.state_before
    if already_registered and mcp_state is McpRegistrationState.FINISHUP_OWNED:
        # Nothing to write, but the host is on the route this step just accepted: keep the
        # applied record in agreement with it so no earlier entry reads as drift (#537).
        mcp_service.reconcile_applied_route(binary, mcp_preview, _state=_state)
    if not already_registered:
        try:
            try:
                result = await mcp_service.register(
                    binary,
                    McpRegistrationConfirmation(
                        mcp_preview.preview_digest,
                        True,
                        "interactive" if interactive else "noninteractive_flag",
                    ),
                    _state=_state,
                )
            except McpRegistrationError as changed:
                if (
                    changed.reason is McpRegistrationReason.PREVIEW_STALE
                    and approved_activation_mcp_command is not None
                    and mcp_preview.state_before is McpRegistrationState.ABSENT
                    and activation_report.get("outcome") == "active"
                ):
                    observed = await mcp_service.observe(binary)
                    if observed.serve_command != approved_activation_mcp_command:
                        raise
                    refreshed = await mcp_service.preview(binary)
                    if (
                        refreshed.state_before is not McpRegistrationState.FINISHUP_OWNED
                        or refreshed.serve_command != mcp_preview.serve_command
                        or refreshed.isolated_root != mcp_preview.isolated_root
                    ):
                        raise
                    result = await mcp_service.register(
                        binary,
                        McpRegistrationConfirmation(
                            refreshed.preview_digest, True, "noninteractive_flag"
                        ),
                        _state=_state,
                    )
                    mcp_preview = refreshed
                else:
                    raise
            # Legacy interactive flows can ask for another preview when they did not
            # approve the complete activation-generated transition up front.
        except McpRegistrationError as changed:
            try:
                if (
                    changed.reason is not McpRegistrationReason.PREVIEW_STALE
                    or not interactive
                    or activation_report.get("outcome") != "active"
                ):
                    raise
                # Plugin activation can make its bundled MCP entry visible. Never silently
                # reinterpret the approved absence as permission to replace that new entry.
                refreshed = await mcp_service.preview(binary)
                if refreshed.state_before is McpRegistrationState.FOREIGN_PRESENT:
                    raise McpRegistrationError(McpRegistrationReason.FOREIGN_ENTRY_PRESENT, {})
                typer.echo("Plugin activation changed the effective MCP entry. Updated preview:")
                typer.echo(f"  Selected Codex home: {bound_home}")
                typer.echo(f"  Codex executable: {binary.executable_path}")
                typer.echo(f"  Action: {refreshed.action.value}")
                typer.echo(f"  State before: {refreshed.state_before.value}")
                typer.echo(f"  Command: {' '.join(refreshed.serve_command)}")
                typer.echo(f"  Isolation root: {refreshed.isolated_root}")
                typer.echo(f"  Preview digest: {refreshed.preview_digest}")
                if not typer.confirm("Confirm updated MCP registration?", default=False):
                    raise McpRegistrationError(McpRegistrationReason.CONFIRMATION_REQUIRED, {})
                result = await mcp_service.register(
                    binary,
                    McpRegistrationConfirmation(refreshed.preview_digest, True, "interactive"),
                    _state=_state,
                )
                mcp_preview = refreshed
            except McpRegistrationError as error:
                return {
                    "outcome": "failed",
                    "reason": error.reason.value,
                    "state": mcp_preview.state_before.value,
                    "plugin": plugin_report,
                    "plugin_activation": activation_report,
                    "skill": skill_report,
                    "observation_consent": {"outcome": "absent", "workspace_commitment": None},
                }
        mcp_state = result.state_after
        mcp_outcome = (
            "reregistered" if result.action is McpRegistrationAction.REREGISTER else "registered"
        )
    else:
        try:
            mcp_state = await mcp_service.status(binary)
        except McpRegistrationError as error:
            return {
                "outcome": "failed",
                "reason": error.reason.value,
                "state": mcp_preview.state_before.value,
                "plugin": plugin_report,
                "plugin_activation": activation_report,
                "skill": skill_report,
                "observation_consent": {"outcome": "absent", "workspace_commitment": None},
            }

    mcp_ok = mcp_state is McpRegistrationState.FINISHUP_OWNED
    if not mcp_ok:
        return {
            "outcome": "failed",
            "reason": "mcp_verification_failed",
            "state": mcp_state.value,
            "plugin": plugin_report,
            "plugin_activation": activation_report,
            "skill": skill_report,
            "observation_consent": {"outcome": "absent", "workspace_commitment": None},
        }

    # 5) Consent is independent local authority after skill/plugin sources and MCP verification.
    # Observation readiness still requires activation to be active; a missing explicit Codex
    # home therefore leaves hooks inert without blocking these separately approved steps.
    observation = _grant_observation_consent(workspace)
    check_policy = _activate_check_policy_trust(
        workspace,
        check_policy,
        exact_digest_confirmed=policy_digest_confirmed,
    )
    return {
        "outcome": mcp_outcome,
        "reason": None,
        "route_profile": mcp_preview.route_profile,
        "route_profile_before": route_profile_before,
        "serve_command": list(mcp_preview.serve_command),
        "isolated_root": mcp_preview.isolated_root,
        "state": mcp_state.value,
        "plugin": plugin_report,
        "plugin_activation": activation_report,
        "skill": skill_report,
        "observation_consent": observation,
        "check_policy": check_policy,
    }


async def _register_step(
    binary: HarnessBinary,
    *,
    interactive: bool,
    accept: bool,
    route_profile: Literal["policy", "strict"] | None = None,
    codex_home: Path | None = None,
    workspace: Path | None = None,
    _state: Path | None = None,
) -> dict[str, JsonValue]:
    """Backward-compatible name for the complete Codex integration step."""

    return await _codex_integration_step(
        binary,
        interactive=interactive,
        accept=accept,
        route_profile=route_profile,
        workspace=workspace,
        codex_home=codex_home,
        _state=_state,
    )


async def apply_codex_integration(
    binary: HarnessBinary,
    *,
    route_profile: Literal["policy", "strict"] | None = None,
    workspace: Path | None = None,
    approved_preview_digest: str,
    approved_activation_mcp_command: tuple[str, ...] | None = None,
    approved_skill_preview_digest: str,
    approved_activation_digest: str,
    approved_policy_digest: str | None = None,
    codex_home: Path,
    _state: Path | None = None,
) -> dict[str, JsonValue]:
    """Apply the exact integration a caller already previewed and got approved.

    This exists so a non-prompt front end (the terminal UI) can reuse the whole
    skill → plugin sources → MCP → consent → policy-trust sequence with its gates
    intact instead
    of reassembling it. It never prompts, and it refuses rather than proceed when
    the preview it is handed no longer matches what the services would propose.

    ``route_profile`` must be the same one the approved preview was built from. The serve
    command is inside the preview digest, so a caller that previews on one route and applies
    on another is refused as stale -- correctly, but with a reason that describes the digest
    rather than the disagreement underneath it. Pass the route explicitly and the two halves
    cannot drift.
    """

    return await _codex_integration_step(
        binary,
        interactive=False,
        accept=False,
        route_profile=route_profile,
        workspace=workspace,
        approved_preview_digest=approved_preview_digest,
        approved_activation_mcp_command=approved_activation_mcp_command,
        approved_skill_preview_digest=approved_skill_preview_digest,
        approved_activation_digest=approved_activation_digest,
        approved_policy_digest=approved_policy_digest,
        codex_home=codex_home,
        _state=_state,
    )


def check_policy_preview(workspace: Path | None = None) -> dict[str, JsonValue]:
    """Public path-free approved-check policy preview for non-prompt front ends."""

    return _check_policy_preview(workspace)


def write_setup_marker(outcome: str) -> bool:
    """Record first-run completion; shared by the wizard and the terminal UI."""

    return _write_setup_marker(outcome)


def _credential_store_unavailable_line() -> str:
    """Name why the platform credential store cannot hold the vault root (issue #721)."""

    from finishup.adapters.keys.os_keyring import describe_vault_keyring_backend

    report = describe_vault_keyring_backend()
    if report.reason == "backend_not_approved":
        why = f"the loaded backend is not approved for the vault ({report.backend_id})"
    else:
        why = "no credential store is loaded"
    return (
        f"Platform credential store unavailable: {why}; FinishUP needs {report.requirement}. "
        "Choose a vault passphrase instead."
    )


def _report_folder_refusal(reason: str) -> int:
    """Name a folder refusal on stderr: token, remedy, and continuation (ADR-048).

    stdout is never written, so a ``--json`` report keeps its released shape. Returns the exit
    code the refusal carries (unsafe storage: 20).
    """

    from finishup.cli.service_installation import path_refusal_failure

    return path_refusal_failure(
        reason,
        json_output=False,
        stderr_writer=lambda text: typer.echo(text, err=True),
        stdout_writer=lambda _value: None,
    )


async def _service_reachability_observed(
    *, start_if_absent: bool = False
) -> tuple[dict[str, JsonValue], str | None]:
    """Probe the service; also return the folder-refusal token when the connect was refused.

    A refusal because FinishUP's local folders cannot be used safely (data under both product
    names, an unusable isolation root) happens before any endpoint is touched. It is not an
    absent service, so the token comes back for the caller to name instead of being folded into
    ``reachable: false``.
    """

    from finishup.cli.app import build_service_client
    from finishup.cli.bootstrap import spawned_startup_failure_line
    from finishup.ports.control import ControlClientKind, ControlError
    from finishup.service.client import connect_service_on_demand, path_refusal_reason

    unreachable: dict[str, JsonValue] = {"reachable": False, "state": None, "vault_mode": None}
    try:
        client = (
            await connect_service_on_demand(ControlClientKind.CLI)
            if start_if_absent
            else await build_service_client()
        )
        try:
            status = await client.service_status()
        finally:
            await client.close()
    except ControlError as error:
        refusal = path_refusal_reason(error)
        if refusal is not None:
            return unreachable, refusal
        # The service this command started exited while starting: name its stage and record
        # (#1040) before the caller reports the service as unreachable.
        startup_line = spawned_startup_failure_line(error)
        if startup_line is not None:
            typer.echo(startup_line, err=True)
        else:
            from finishup.cli.runtime_refusal import installed_runtime_refusal_text

            runtime_refusal = installed_runtime_refusal_text()
            if runtime_refusal is not None:
                typer.echo(runtime_refusal[1].rstrip("\n"), err=True)
        return unreachable, None
    vault_mode = getattr(status, "vault_mode", None)
    state = getattr(getattr(status, "state", None), "value", getattr(status, "state", None))
    return {
        "reachable": True,
        "state": state if type(state) is str else None,
        "vault_mode": vault_mode if type(vault_mode) is str else None,
    }, None


async def _service_reachability(*, start_if_absent: bool = False) -> dict[str, JsonValue]:
    """Probe the service; a folder refusal is named on stderr, never only as unreachable."""

    service, refusal = await _service_reachability_observed(start_if_absent=start_if_absent)
    if refusal is not None:
        _report_folder_refusal(refusal)
    return service


# A draining service unlinks its endpoints and releases singleton authority before the
# successor can bind, so a flat retry window reports an unreachable service that was only slow.
_RESTART_BACKOFF_SECONDS: Final = (0.05, 0.1, 0.2, 0.4, 0.8, 1.6, 3.2)


async def _restart_service_for_semantic_composition(
    *, report_startup_failure: bool = True
) -> dict[str, JsonValue]:
    """Restart after provider config changes, then verify the new singleton answered.

    A successor that exits while starting fails the same way on every spawn, so the first one
    ends the retries; ``report_startup_failure`` names its stage and record on stderr (#1040).
    The full-screen window passes False: it owns the terminal.
    """

    from finishup.cli.app import build_service_client
    from finishup.cli.bootstrap import spawned_startup_failure_line
    from finishup.ports.control import ControlClientKind, ControlError
    from finishup.service.client import connect_service_on_demand

    try:
        client = await build_service_client()
        try:
            await client.stop()
        finally:
            await client.close()
    except ControlError:
        return {"reachable": False, "state": None, "vault_mode": None}
    for delay in _RESTART_BACKOFF_SECONDS:
        await anyio.sleep(delay)
        try:
            client = await connect_service_on_demand(ControlClientKind.CLI)
            try:
                status = await client.service_status()
            finally:
                await client.close()
        except ControlError as error:
            startup_line = spawned_startup_failure_line(error)
            if startup_line is None:
                continue
            if report_startup_failure:
                typer.echo(startup_line, err=True)
            break
        state = getattr(getattr(status, "state", None), "value", getattr(status, "state", None))
        vault_mode = getattr(status, "vault_mode", None)
        return {
            "reachable": True,
            "state": state if type(state) is str else None,
            "vault_mode": vault_mode if type(vault_mode) is str else None,
        }
    return {"reachable": False, "state": None, "vault_mode": None}


async def restart_service_for_semantic_composition(
    *, report_startup_failure: bool = True
) -> dict[str, JsonValue]:
    """Recompose the singleton after an AI-powered evaluator binding changes."""

    return await _restart_service_for_semantic_composition(
        report_startup_failure=report_startup_failure
    )


def _privacy_block_reason(reason: object) -> str:
    """Name the exact privacy cause that blocked the credential step, never free text."""

    return reason if type(reason) is str and reason else "privacy_setup_incomplete"


async def _interactive_provider_setup(
    service: dict[str, JsonValue],
    *,
    provider_choice: str | None = None,
    model: str | None = None,
    before_credential: Callable[[], Awaitable[str | None]] | None = None,
    storage_only: bool = False,
    project: Path | None = None,
) -> tuple[dict[str, JsonValue], dict[str, JsonValue]]:
    """Run trusted local setup ceremonies while keeping secrets out of wizard state.

    ``project`` is the folder the credential's repository privacy commitment names (the current
    directory when omitted), the same folder the privacy step governs.
    """

    from finishup.adapters.keys.os_keyring import AutoUnlockPassphraseStore, OSKeyringError
    from finishup.cli.privacy_setup import get_privacy_setup_snapshot
    from finishup.cli.provider_binding import (
        ProviderEndpointChoice,
        apply_provider_endpoint_choice,
        prompt_provider_endpoint_binding,
        prompt_provider_model,
    )
    from finishup.cli.unlock import (
        HumanCeremonyCliError,
        initialize_passphrase_vault,
        set_provider_credential,
        unlock_vault,
    )
    from finishup.config.load import load_config
    from finishup.config.models import ConfigError
    from finishup.config.paths import bundle_root
    from finishup.config.write import provider_preset
    from finishup.ports.control import ControlError
    from finishup.service.confidential_client import ConfidentialClientError
    from finishup.service.confidential_protocol import ProviderCredentialTarget
    from finishup.service.vault import provider_credential_profile_binding

    provider_report: dict[str, JsonValue] = {
        "binding": "skipped",
        "credential": "skipped",
    }
    auto_passphrase: bytearray | None = None
    replacing_stored_credential = False

    def wipe_auto_passphrase() -> None:
        nonlocal auto_passphrase
        if auto_passphrase is not None:
            for index in range(len(auto_passphrase)):
                auto_passphrase[index] = 0
            auto_passphrase = None

    try:
        if service.get("reachable") and service.get("state") == "locked":
            if service.get("vault_mode") == "uninitialized":
                typer.echo("")
                current_config = load_config({}, os.environ, None)
                auto_store = AutoUnlockPassphraseStore(
                    bundle_root(_data_dir=current_config.storage.data_dir)
                )
                try:
                    # ADR-015 decision 5 / ADR-008: generate a fresh scoped secret for
                    # vault_initialize. Never adopt a pre-existing entry; the active slot stays
                    # fail-closed on entry_exists. The guard is held across stage, ceremony,
                    # and promote so no concurrent repair or retry can act on a stale status.
                    # A leftover staged-initialization entry from an earlier failed attempt is
                    # discarded only after a fresh service status, read under the guard, proves
                    # the vault is still uninitialized and idle (#511) — any other state keeps
                    # it for proof-based restart reconciliation.
                    with auto_store.staged_initialization_guard():
                        if auto_store.slot_report().get("staged_initialization") == "present":
                            fresh = await _service_reachability()
                            if (
                                fresh.get("state") == "locked"
                                and fresh.get("vault_mode") == "uninitialized"
                            ):
                                auto_store.discard_staged_initialization()
                        auto_passphrase = auto_store.stage_for_initialization()
                        typer.echo("Secure vault setup (platform credential store auto-unlock)")
                        init_result = await initialize_passphrase_vault(bytearray(auto_passphrase))
                        if init_result.state == "ready" and init_result.reason == "succeeded":
                            try:
                                auto_store.promote_staged_initialization()
                            except OSKeyringError:
                                # The vault committed and activated; the staged entry remains
                                # the proven candidate and restart reconciliation promotes it.
                                pass
                        else:
                            # Failure atomicity (#511): remove the same-attempt staged
                            # credential when the service proves no envelope was committed;
                            # otherwise keep it for proof-based restart reconciliation.
                            try:
                                fresh = await _service_reachability()
                                if (
                                    fresh.get("state") == "locked"
                                    and fresh.get("vault_mode") == "uninitialized"
                                ):
                                    auto_store.discard_staged_initialization()
                            except OSKeyringError:
                                pass
                            provider_report["credential_reason"] = (
                                f"vault_result_{init_result.reason}"
                            )
                            wipe_auto_passphrase()
                            return _provider_setup_result(service, provider_report)
                except OSKeyringError as error:
                    if error.reason != "unsupported":
                        provider_report["credential_reason"] = f"auto_unlock_{error.reason}"
                        if error.reason == "initialization_in_progress":
                            typer.echo(
                                "Another FinishUP vault initialization is already in progress. "
                                "Wait for it to finish, then rerun 'finishup setup'.",
                                err=True,
                            )
                        elif error.reason in _BUNDLE_GUARD_REASONS:
                            typer.echo(
                                "The FinishUP data directory could not be prepared for vault "
                                f"initialization ({error.reason}). Its parent directory must "
                                "exist, be owned by you, contain no symlinks, and be "
                                "writable. Fix that, then rerun 'finishup setup'.",
                                err=True,
                            )
                        elif error.reason == "staged_entry_exists":
                            typer.echo(
                                "A staged credential from an earlier vault-initialization "
                                "attempt is not yet reconciled. Restart the service "
                                "('finishup service restart') so it can resolve the entry by "
                                "proof, then rerun 'finishup setup'.",
                                err=True,
                            )
                        elif error.reason == "entry_exists":
                            entry_service, entry_account = auto_store.entry_identity
                            typer.echo(
                                "A pre-existing platform credential entry blocks vault "
                                "initialization, because adopting it would make an already "
                                "known value the vault root passphrase.",
                                err=True,
                            )
                            typer.echo(f"  Credential store service: {entry_service}", err=True)
                            typer.echo(f"  Account: {entry_account}", err=True)
                            typer.echo(
                                "Delete that entry (macOS: Keychain Access; Linux: your keyring "
                                "manager such as Seahorse or KWalletManager, or "
                                "'secret-tool clear service " + entry_service + "' from the "
                                "libsecret tools package), then rerun 'finishup setup'. Keep it "
                                "only if this install already has a vault, in which case setup "
                                "did not need to initialize one.",
                                err=True,
                            )
                        else:
                            typer.echo(
                                "Platform credential entry could not be verified; vault "
                                "initialization stopped to avoid a conflicting passphrase. "
                                "Restore credential-store access, then rerun 'finishup setup'.",
                                err=True,
                            )
                        return _provider_setup_result(service, provider_report)
                    typer.echo(_credential_store_unavailable_line())
                    typer.echo("Secure vault setup (hidden local-terminal input)")
                    await initialize_passphrase_vault()
            elif service.get("vault_mode") == "passphrase":
                typer.echo("")
                current_config = load_config({}, os.environ, None)
                auto_store = AutoUnlockPassphraseStore(
                    bundle_root(_data_dir=current_config.storage.data_dir)
                )
                auto_passphrase = auto_store.load()
                if auto_passphrase is None:
                    typer.echo(
                        "Unlock FinishUP to finish provider setup (hidden local-terminal input)"
                    )
                    await unlock_vault()
                else:
                    typer.echo("Unlocking FinishUP from the platform credential store")
                    await unlock_vault(bytearray(auto_passphrase))
            elif service.get("vault_mode") == "os_keyring" and storage_only:
                from finishup.cli.unlock import retry_keyring

                await retry_keyring()
            service = await _service_reachability()
    except HumanCeremonyCliError as error:
        provider_report["credential_reason"] = error.reason

    if storage_only:
        wipe_auto_passphrase()
        return _provider_setup_result(service, provider_report)

    if provider_choice is not None:
        selected_model = model
        try:
            preset = provider_preset(provider_choice)
            choice = cast(ProviderEndpointChoice, preset.choice)
            if selected_model is None:
                selected_model = prompt_provider_model(preset.choice)
            if not selected_model:
                provider_report["credential_reason"] = "model_selection_invalid"
                wipe_auto_passphrase()
                return _provider_setup_result(service, provider_report)
            written, _provider = apply_provider_endpoint_choice(choice, model=selected_model)
        except (ConfigError, OSError, ValueError) as error:
            provider_report["credential_reason"] = getattr(
                error, "reason_code", "provider_binding_invalid"
            )
            wipe_auto_passphrase()
            return _provider_setup_result(service, provider_report)
        typer.echo(f"{preset.provider_id} model: {selected_model}")
    else:
        written = prompt_provider_endpoint_binding(
            show_standalone_next_step=False,
        )
    if written == "codex_subscription":
        from finishup.cli.codex_subscription import prompt_codex_subscription_setup

        try:
            status = await prompt_codex_subscription_setup()
        except (OSError, TimeoutError, ValueError) as error:
            from finishup.cli.codex_subscription import subscription_failure_reason

            provider_report["binding"] = "failed"
            provider_report["credential"] = "external_runtime_oauth"
            provider_report["credential_reason"] = _allowlisted_provider_setup_reason(
                subscription_failure_reason(error)
            )
            wipe_auto_passphrase()
            return _provider_setup_result(service, provider_report)
        provider_report.update(
            {
                "binding": "configured",
                "credential": "external_runtime_oauth",
                "auth_mode": status.get("auth_mode"),
                "plan_type": status.get("plan_type"),
                "model_available": status.get("model_available"),
                "process_cleanup": status.get("process_cleanup"),
                "codex_sandbox_unavailable": status.get("codex_sandbox_unavailable") is True,
                "codex_sandbox_unavailable_reason": _sandbox_unavailable_reason(status),
                "login_reused": status.get("login_reused") is True,
                "model": status.get("model"),
                **(
                    {"model_fallback_from": status["model_fallback_from"]}
                    if type(status.get("model_fallback_from")) is str
                    else {}
                ),
            }
        )
        service = await _restart_service_for_semantic_composition()
        if before_credential is not None:
            blocked = await before_credential()
            if blocked is not None:
                provider_report["credential_reason"] = blocked
        wipe_auto_passphrase()
        return _provider_setup_result(service, provider_report)
    if written is None:
        wipe_auto_passphrase()
        return _provider_setup_result(service, provider_report)
    provider_report["binding"] = "configured"
    config = load_config({}, {}, written)
    provider = config.provider
    if provider is None or service.get("state") != "ready":
        provider_report.setdefault("credential_reason", "service_not_ready")
        wipe_auto_passphrase()
        return _provider_setup_result(service, provider_report)

    # The service snapshots its configured provider and credential capability at composition
    # time. Refresh it after writing the binding before deciding whether this exact profile
    # already has a credential. This also makes a repeated setup run idempotent: an existing
    # credential is shown as present and is never requested again.
    service = await _restart_service_for_semantic_composition()
    if before_credential is not None:
        # The privacy step reports its own bounded reason; keep it instead of flattening every
        # cause to privacy_setup_incomplete.
        blocked = await before_credential()
        if blocked is not None:
            provider_report["credential_reason"] = blocked
            wipe_auto_passphrase()
            return _provider_setup_result(service, provider_report)
    credential_before: bool | None = None
    if service.get("state") == "ready":
        from finishup.cli.provider_status import provider_status_report

        try:
            status_before = await provider_status_report()
        except OSError, ValueError:
            status_before = {}
        observed_before = status_before.get("credential_connected")
        credential_before = observed_before if type(observed_before) is bool else None
    if credential_before is True:
        from finishup.cli.provider_status import credential_human_display

        typer.echo(f"  Credential: {credential_human_display(True)} (already stored)")
        if _prompt_yes_no_before_credential(
            "Use the stored credential for this provider and model?",
            default=True,
        ):
            provider_report["credential"] = "stored"
            provider_report["credential_display"] = credential_human_display(True)
            wipe_auto_passphrase()
            return _provider_setup_result(service, provider_report)
        replacing_stored_credential = True
        typer.echo("Enter a new credential to replace the stored value.")

    # A Keychain-provisioned passphrase vault is already ready without the
    # human knowing its generated passphrase. Load that same scoped secret
    # only for the one provider-reauthentication ceremony, so setup asks for
    # the provider key but never unexpectedly asks the user for a passphrase.
    if auto_passphrase is None and service.get("vault_mode") == "passphrase":
        current_config = load_config({}, os.environ, None)
        auto_passphrase = AutoUnlockPassphraseStore(
            bundle_root(_data_dir=current_config.storage.data_dir)
        ).load()

    storage = provider_credential_profile_binding(
        provider.provider_id,
        provider.model,
        provider.endpoint_profile_id,
        provider.endpoint_profile_version,
    )
    try:
        repository_snapshot = await get_privacy_setup_snapshot(project)
        repository_commitment = repository_snapshot.bound_scope.get("workspace_ref_commitment")
    except ControlError, OSError, ValueError:
        repository_commitment = None
    if type(repository_commitment) is not str:
        provider_report["credential_reason"] = "repository_privacy_scope_unavailable"
        wipe_auto_passphrase()
        return _provider_setup_result(service, provider_report)
    target = ProviderCredentialTarget(
        action="set",
        provider_id=storage.provider_id,
        model_id=storage.model_id,
        endpoint_profile_id=storage.endpoint_profile_id,
        endpoint_profile_version=storage.endpoint_profile_version,
        purpose=storage.purpose,
        scope_digest=storage.authorization_scope_digest,
        purpose_digest=storage.purpose_digest,
        repository_privacy_commitment=repository_commitment,
    )
    _emit_hidden_credential_transition()
    try:
        result = await set_provider_credential(
            target,
            None,
            None if auto_passphrase is None else bytearray(auto_passphrase),
        )
    except HumanCeremonyCliError as error:
        provider_report["credential"] = "failed"
        provider_report["credential_reason"] = error.reason
    except ConfidentialClientError as error:
        # An initial vault write may have committed before the result/close frame was lost.
        # Recompose and inspect only the exact configured profile's presence bit; never retry with
        # a wiped buffer and never turn an unreadable state into a success claim.
        if replacing_stored_credential:
            # Presence was already true before the write, so it cannot distinguish the old value
            # from a committed replacement. Preserve that uncertainty instead of claiming success.
            provider_report["credential"] = "failed"
            provider_report["credential_reason"] = f"credential_{error.reason}"
            return _provider_setup_result(await _service_reachability(), provider_report)
        service = await _restart_service_for_semantic_composition()
        credential_after: bool | None = None
        if service.get("state") == "ready":
            from finishup.cli.provider_status import provider_status_report

            try:
                status_after = await provider_status_report()
            except OSError, ValueError:
                status_after = {}
            observed_after = status_after.get("credential_connected")
            credential_after = observed_after if type(observed_after) is bool else None
        if credential_after is True:
            from finishup.cli.provider_status import credential_human_display

            provider_report["credential"] = "stored"
            provider_report["credential_display"] = credential_human_display(True)
            provider_report["credential_reason"] = "stored_result_recovered"
        else:
            provider_report["credential"] = "failed"
            provider_report["credential_reason"] = f"credential_{error.reason}"
    else:
        provider_report["credential"] = result.activation_status
        if result.activation_status == "stored":
            from finishup.cli.provider_status import credential_human_display

            provider_report["credential_display"] = credential_human_display(True)
    finally:
        wipe_auto_passphrase()
    return _provider_setup_result(await _service_reachability(), provider_report)


def _semantic_openai_extra_state() -> str:
    """Report whether the optional ``semantic-openai`` import surface is present.

    Presence is a structural import fact only. It does not prove wire dispatch, auth, or a
    successful AI-powered review.
    """

    if importlib.util.find_spec("openai") is None:
        return "absent (not demonstrated)"
    return "present (importable; wire dispatch not demonstrated)"


def _emit_provider_setup_layer_report(*, privacy_outcome: str) -> None:
    """Honestly separate binding/credential storage from undemonstrated runtime layers."""

    typer.echo("Provider binding and vault credential storage succeeded; that layer is supported.")
    typer.echo("Other layers (ready vs not demonstrated by this path):")
    typer.echo(f"  SDK extra (semantic-openai): {_semantic_openai_extra_state()}")
    typer.echo(
        "  AI-powered evaluator: not composed "
        "(_semantic_not_configured in ready composition; not demonstrated)"
    )
    typer.echo(f"  Privacy policy: {privacy_outcome}")
    typer.echo("  Transport probe: not demonstrated")
    typer.echo("  Installed artifact evidence: not demonstrated")
    typer.echo(
        "Stored binding/credential is not proof of live provider dispatch or AI-powered review."
    )


def _emit_privacy_incomplete(
    *, reason: object, privacy_outcome: str, api_key_unstored: bool
) -> None:
    """Name a declined or failed privacy step after the provider binding, and what is left."""

    typer.echo(f"Reason: {_privacy_block_reason(reason)}")
    typer.echo(f"Privacy policy: {privacy_outcome}")
    typer.echo(_NEXT_PRIVACY_AFTER_PROVIDER)
    if api_key_unstored:
        typer.echo(_NEXT_CREDENTIAL_AFTER_PRIVACY)


def _emit_codex_subscription_layer_report(*, privacy_outcome: str) -> None:
    """The Codex-subscription route's own layers: no API key and no vault credential exist."""

    typer.echo(
        "Codex subscription binding written. Codex keeps the ChatGPT sign-in in the dedicated "
        "evaluator home; FinishUP never reads it."
    )
    typer.echo("Other layers (ready vs not demonstrated by this path):")
    typer.echo(f"  Privacy policy: {privacy_outcome}")
    typer.echo("  Live AI-powered review: not demonstrated")
    typer.echo("The binding and the sign-in are not proof that an AI-powered review ran.")


async def _run_local_only_privacy_setup(project: Path | None) -> int:
    """Record the owner's "local only; agents may not opt in" answer (ADR-049).

    The Private recipe with the explicit ``local_only`` conversation setting, through the same
    trusted questionnaire every privacy change uses. It narrows, so it applies without the
    widening ceremony. Without it a policy-route registration would keep the released check
    behaviour of an installation that never chose.
    """

    from finishup.cli.privacy_setup import run_privacy_setup
    from finishup.cli.unlock import HumanCeremonyCliError
    from finishup.ports.control import ControlError

    service = await _service_reachability(start_if_absent=True)
    if not service.get("reachable"):
        typer.echo("privacy_setup_failed: service_unavailable", err=True)
        return 20
    try:
        result = await run_privacy_setup(
            recipe_hint="private",
            workspace_locator=None if project is None else _canonical_setup_workspace(project),
            conversation_review=ConversationReview.LOCAL_ONLY,
        )
    except (ControlError, HumanCeremonyCliError, OSError, ValueError) as error:
        typer.echo(
            f"privacy_setup_failed: {_privacy_block_reason(getattr(error, 'reason', None))}",
            err=True,
        )
        return 20
    if result.outcome in {"configured", "unchanged"}:
        return 0
    typer.echo(f"privacy_setup_failed: {_privacy_block_reason(result.reason)}", err=True)
    return 20


async def run_provider_setup(
    *,
    fireworks: bool = False,
    grok: bool = False,
    provider: str | None = None,
    model: str | None = None,
    conversation_review: ConversationReview | None = None,
    project: Path | None = None,
) -> int:
    """Run only the simple local provider setup path used by ``finishup --set``.

    ``conversation_review`` is a first-run answer already taken (ADR-049): the drafted privacy
    policy carries it and the privacy step does not ask again. ``project`` is the folder the
    privacy step governs; the current directory when omitted.
    """

    if (fireworks or grok) and provider is not None:
        return _usage_failure("provider shortcuts and --provider are mutually exclusive")
    if fireworks and grok:
        return _usage_failure("--fireworks and --grok are mutually exclusive")
    provider_choice = "fireworks" if fireworks else ("grok" if grok else provider)
    if provider_choice is not None:
        from finishup.config.write import provider_preset

        try:
            provider_choice = provider_preset(provider_choice).choice
        except ConfigError, TypeError:
            return _usage_failure("--provider must name a reviewed provider preset")
    if not _is_interactive_terminal():
        return _usage_failure("--set requires a local terminal for hidden credential input")
    typer.echo("FinishUP AI-powered review setup")
    typer.echo(
        "Choose a provider next. An API key, when the provider needs one, is entered with hidden "
        "input and stored only in the local vault; Codex with a ChatGPT subscription needs none."
    )
    service = await _service_reachability(start_if_absent=True)
    if not service.get("reachable"):
        typer.echo("provider_setup_failed: service_unavailable", err=True)
        return 20
    # The disclosure policy this run chose: ``failed`` when the privacy step raised, and
    # ``not_attempted`` only when the provider step stopped before reaching it.
    privacy_outcome = "not_attempted"

    async def authorize_provider_channel() -> str | None:
        nonlocal privacy_outcome
        from finishup.cli.privacy_setup import adds_ai_review, run_privacy_setup
        from finishup.cli.unlock import HumanCeremonyCliError
        from finishup.ports.control import ControlError

        try:
            external_runtime_configured = (
                load_config({}, os.environ, None).external_runtime is not None
            )
        except ConfigError:
            # Same rule as the first-run wizard: an unreadable configuration keeps the API-key
            # prompt path, and the owning provider step reports the configuration error.
            external_runtime_configured = False
        typer.echo("")
        if external_runtime_configured:
            # Codex with a ChatGPT subscription has no API key, so no key-verification request
            # is offered; only the disclosure policy is chosen here.
            typer.echo("Choose the exact disclosure policy for AI-powered review.")
            credential_probe_authorized = False
        else:
            typer.echo("Choose the exact disclosure policy before the API key can be tested.")
            credential_probe_authorized = _prompt_credential_probe_authorization()
        # ADR-049 review round 1: an answer that adds AI-powered review lists the AI recipes
        # with their own recommendation, never the released Private recommendation.
        add_on = adds_ai_review(conversation_review)
        try:
            privacy_result = await run_privacy_setup(
                recipe_hint=None if add_on else "assisted_review",
                offer_recommended=not add_on,
                credential_probe_authorized=credential_probe_authorized,
                conversation_review=conversation_review,
                workspace_locator=project,
                ai_review_add_on=add_on,
            )
        except (ControlError, HumanCeremonyCliError, OSError, ValueError) as error:
            privacy_outcome = "failed"
            typer.echo(f"privacy_setup_failed: {type(error).__name__}", err=True)
            return _privacy_block_reason(getattr(error, "reason", None))
        outcome = getattr(privacy_result, "outcome", "failed")
        privacy_outcome = outcome if type(outcome) is str else "failed"
        if privacy_outcome in _PRIVACY_READY:
            return None
        return _privacy_block_reason(getattr(privacy_result, "reason", None))

    service, provider_report = await _interactive_provider_setup(
        service,
        provider_choice=provider_choice,
        model=model,
        before_credential=authorize_provider_channel,
        project=project,
    )
    service, provider_report = _provider_setup_result(service, provider_report)
    binding = provider_report.get("binding")
    credential = provider_report.get("credential")
    typer.echo("")
    typer.echo(f"Provider binding: {binding}")
    from finishup.cli.provider_status import credential_human_display

    if credential == "external_runtime_oauth":
        typer.echo("Credential: held by Codex's own ChatGPT sign-in; FinishUP stores none")
    else:
        typer.echo(
            "Credential: "
            + credential_human_display(
                True if credential == "stored" else (False if credential == "failed" else None)
            )
        )
    model_fallback_from = provider_report.get("model_fallback_from")
    if type(model_fallback_from) is str:
        typer.echo(
            f"Model: {provider_report.get('model')} (suggested {model_fallback_from} is not "
            "listed by this Codex)"
        )
    # A provider binding without the disclosure policy is not usable: on the API-key path the
    # credential step never ran, and a Codex sign-in is already held, so the privacy outcome
    # itself must gate success on every provider path.
    privacy_ready = privacy_outcome in _PRIVACY_READY
    if (
        binding != "configured"
        or not _provider_credential_ready(provider_report)
        or not privacy_ready
    ):
        privacy_attempted = privacy_outcome != "not_attempted"
        if binding == "configured" and not privacy_ready and privacy_attempted:
            _emit_privacy_incomplete(
                reason=provider_report.get("credential_reason"),
                privacy_outcome=privacy_outcome,
                api_key_unstored=credential != "external_runtime_oauth"
                and not _provider_credential_ready(provider_report),
            )
            return 20
        reason = provider_report.get("credential_reason")
        if type(reason) is not str and binding == "configured" and not privacy_ready:
            reason = "privacy_setup_incomplete"
        if type(reason) is str:
            typer.echo(f"Reason: {reason}")
            from finishup.cli.codex_subscription import subscription_remediation

            remediation = subscription_remediation(reason)
            if remediation is not None:
                typer.echo(f"Next: {remediation}")
        elif binding == "skipped":
            # No provider was chosen, so neither the privacy step nor a credential ran.
            typer.echo(_NEXT_PROVIDER_AFTER_SKIP)
        return 20
    if credential == "external_runtime_oauth":
        _emit_codex_subscription_layer_report(privacy_outcome=privacy_outcome)
    else:
        _emit_provider_setup_layer_report(privacy_outcome=privacy_outcome)
    typer.echo(
        "AI-powered review configuration changed: start a fresh agent session so it uses it."
    )
    return 0


def _registration_report(
    state: McpRegistrationState | None,
    *,
    outcome: str,
    reason: str | None = None,
) -> dict[str, JsonValue]:
    return {
        "outcome": outcome,
        "reason": reason,
        "state": None if state is None else state.value,
    }


async def _resolve_setup_package_update(
    *,
    interactive: bool,
) -> dict[str, JsonValue]:
    """Structural package-update advisory for setup reports (never auto-upgrades)."""

    from finishup.application.package_update import (
        package_update_report_fields,
        resolve_package_update_advisory,
    )

    network, enabled = await _effective_update_policy_bits()
    advisory = await resolve_package_update_advisory(
        network_egress_permitted=network,
        update_checks_enabled=enabled,
        allow_network=interactive,
    )
    fields = dict(package_update_report_fields(advisory))
    return cast(dict[str, JsonValue], fields)


async def _effective_update_policy_bits() -> tuple[bool | None, bool]:
    """Read only the two durable policy facts that authorize the PyPI channel."""

    try:
        from finishup.cli.app import build_service_client
        from finishup.cli.provider_status import machine_scope_request

        # Machine scope is a local construction; resolve it before connecting so a broken
        # installation marker fails soft here without any service request (issue #517).
        scoped = machine_scope_request()
        client = await build_service_client()
        try:
            raw = await client.privacy_get_effective(scoped)
        finally:
            await client.close()
        raw_map = cast(Mapping[str, object], raw)
        policy_obj = raw_map.get("policy")
        if not isinstance(policy_obj, Mapping):
            return None, False
        policy_map = cast(Mapping[str, object], policy_obj)
        network = policy_map.get("network_egress_permitted")
        enabled = False
        channels = policy_map.get("channel_policies")
        if isinstance(channels, (list, tuple)):
            for entry_obj in cast(tuple[object, ...] | list[object], channels):
                if not isinstance(entry_obj, Mapping):
                    continue
                row = cast(Mapping[str, object], entry_obj)
                if row.get("channel") == "update_checks" and row.get("enabled") is True:
                    enabled = True
                    break
        return network if type(network) is bool else None, enabled
    except Exception:
        return None, False


async def _refresh_setup_recommendations(
    *,
    binary: HarnessBinary | None,
    codex_home: Path | None,
    allow_network: bool,
    workspace: Path | None = None,
) -> dict[str, JsonValue]:
    """Refresh cached recommendations from current local and durable policy facts."""

    try:
        from finishup.application.recommendations import (
            evaluate_recommendation_context,
            refresh_pending,
        )

        config = load_config({}, os.environ, None)
        activation_state: str | None = None
        if binary is not None and codex_home is not None:
            activation_state = inspect_activation(
                _integration_target(workspace),
                executable_path=binary.executable_path,
                codex_home=codex_home,
            ).state.value
        network, updates = await _effective_update_policy_bits()
        context = await evaluate_recommendation_context(
            observation_enabled=config.observation.enabled,
            codex_activation_state=activation_state,
            network_egress_permitted=network,
            update_checks_enabled=updates,
            allow_network=allow_network,
        )
        state = await refresh_pending(context=context, force=True)
        return {"outcome": "refreshed", "pending": list(state.pending)}
    except Exception as error:
        return {"outcome": "failed", "reason": type(error).__name__, "pending": []}


def _path_codex_choice(executables: Sequence[Path | None]) -> int | None:
    """The 1-based position of the Codex a plain ``codex`` command runs, if it is listed."""

    on_path = shutil.which("codex")
    if on_path is None:
        return None
    selected = Path(os.path.abspath(on_path))
    for index, executable in enumerate(executables, 1):
        if executable is not None and Path(os.path.abspath(executable)) == selected:
            return index
    return None


def _default_installation_choice(installations: Sequence[HostInstallation]) -> int:
    """Offer the Codex a plain ``codex`` command runs, not merely the first path in sort order."""

    codex = [item.executable if item.host == "codex" else None for item in installations]
    return _path_codex_choice(codex) or 1


async def run_setup_wizard(
    *,
    non_interactive: bool,
    codex_path: str | None,
    codex_home: Path | None,
    accept: bool,
    json_output: bool,
    route_profile: Literal["policy", "strict"] | None = None,
    host: str | None = None,
    host_path: Path | None = None,
    host_config_root: Path | None = None,
    project: Path | None = None,
    request_value: str | None = None,
    preview_digest: str | None = None,
) -> int:
    """Run the guided first-run setup and report each step honestly.

    ``route_profile`` is the explicit MCP route input (``--route-profile``). When
    absent, an interactive run registers the ``policy`` route for every review answer
    (ADR-049: the answer is drafted into the privacy policy as its conversation setting,
    and the policy alone decides what may be sent), and a non-interactive run, which
    answers nothing, preserves the observed profile of an existing finishup-owned
    registration (strict only for a fresh registration) — ``--accept`` alone never
    changes an existing route (#389).
    """

    interactive = not non_interactive and _is_interactive_terminal()

    from finishup.adapters.integrations.host_discovery import discover_hosts
    from finishup.cli.host_connection import run_host_connection

    if host is None and codex_path is None:
        installations = discover_hosts()
        alternatives = [item for item in installations if item.host != "codex"]
        if alternatives and interactive:
            typer.echo(
                "Choose an agent to connect (one per run; run setup again to connect another):"
            )
            for index, item in enumerate(installations, 1):
                typer.echo(f"  {index}. {item.label} {item.version or ''} ({item.executable})")
            choice = int(
                typer.prompt(
                    "Agent",
                    type=IntRange(1, len(installations)),
                    default=_default_installation_choice(installations),
                )
            )
            selected = installations[choice - 1]
            host, host_path, host_config_root = (
                selected.host,
                selected.executable,
                selected.config_root,
            )
        elif alternatives and len(installations) == 1:
            selected = alternatives[0]
            host, host_path, host_config_root = (
                selected.host,
                selected.executable,
                selected.config_root,
            )
    if host is not None:
        connected_project = _resolve_setup_project(project, interactive=interactive)
        if connected_project is None:
            return _emit_unconnectable_project(host, json_output=json_output)
        # ADR-049: every interactive answer registers the policy route; the privacy policy, not
        # the route, decides what may be sent. Non-interactive without --route-profile: a Codex
        # home keeps its registered review mode (every project of the home shares it, #1058); a
        # fresh home and other hosts use strict.
        host_review: ReviewChoice | None = (
            _choose_review_mode() if interactive and route_profile is None else None
        )
        host_route: Literal["policy", "strict"] | None = route_profile or (
            "policy" if host_review is not None else None
        )

        def connect() -> int:
            return run_host_connection(
                host=host,
                executable=host_path,
                config_root=host_config_root,
                project=connected_project,
                route=host_route,
                accept=accept,
                interactive=interactive,
                request_value=request_value,
                preview_digest=preview_digest,
                json_output=json_output,
            )

        # PAM owns SIGALRM and the foreground console on the operator's main thread.
        # Codex's legacy composition owns an AnyIO loop and must stay off this loop.
        result = await run_sync(connect) if host == "codex" else connect()
        if result == 0 and interactive:
            # The privacy step governs the project just connected, which may be a folder the
            # owner typed rather than the current directory.
            if host_review == "local_only":
                result = await _run_local_only_privacy_setup(connected_project)
            elif host_route == "policy":
                result = await run_provider_setup(
                    conversation_review=(
                        None
                        if host_review is None
                        else review_choice_conversation_setting(host_review)
                    ),
                    project=connected_project,
                )
            if result == 0:
                _write_setup_marker("complete")
        return result

    # The Codex wizard needs the same project folder before its first question; it is carried
    # through registration, the privacy and provider steps, readiness and recommendations.
    codex_project = _resolve_setup_project(project, interactive=interactive)
    if codex_project is None:
        return _emit_unconnectable_project("codex", json_output=json_output)

    binaries = discover_codex_binaries()
    try:
        harness = _choose_harness(
            binaries,
            codex_path=codex_path,
            interactive=interactive,
        )
        chosen = (
            None
            if harness is None
            else _choose_binary(binaries, codex_path=codex_path, interactive=interactive)
        )
    except _UsageExit as failure:
        return failure.code

    if chosen is not None and codex_home is None:
        # Offer the home a person would otherwise have to type. Interactive runs confirm or
        # replace it; non-interactive runs bind it and report it, so an agent driving setup
        # never has to guess ``--codex-home`` (issue #766).
        suggested = default_codex_home()
        if interactive:
            codex_home = Path(
                typer.prompt(
                    f"Codex home used by {chosen.executable_path}",
                    default=None if suggested is None else str(suggested),
                )
            ).expanduser()
        else:
            codex_home = suggested

    review_choice: ReviewChoice | None = _choose_review_mode() if interactive else None
    # The released report vocabulary: ``semantic`` for an answer that sets up AI-powered review.
    review_mode: Literal["local_only", "semantic", "deferred"] = (
        "deferred"
        if review_choice is None
        else ("local_only" if review_choice == "local_only" else "semantic")
    )
    update_checks_choice = (
        typer.confirm(
            "Check PyPI for FinishUP updates (package name and version only)?",
            default=True,
        )
        if interactive
        else None
    )
    if chosen is None:
        registration = _registration_report(None, outcome="skipped", reason="codex_not_found")
    else:
        if route_profile is not None:
            selected_route = route_profile
        elif interactive:
            # ADR-049: all three answers register the policy route, so the owner can let an
            # agent opt in later without re-registering; the privacy policy decides egress.
            selected_route = "policy"
        else:
            # No explicit input and no human answer: the step preserves an
            # existing finishup-owned route and registers strict only when fresh.
            selected_route = None
        registration = await _register_step(
            chosen,
            interactive=interactive,
            accept=accept,
            route_profile=selected_route,
            codex_home=codex_home,
            workspace=codex_project,
        )

    service = await _service_reachability(start_if_absent=interactive)
    provider: dict[str, JsonValue] = {
        "binding": "skipped",
        "credential": "skipped",
    }
    # Choosing local-only review means no widening was requested; it does not observe what the
    # durable policy already is, so the report never names a profile it did not read.
    privacy: dict[str, JsonValue] = {
        "outcome": "deferred" if not interactive else "not_changed",
        "profile": "unknown",
        "grant_state": None,
        "migration_state": None,
        "reason": None,
    }
    semantic_status: dict[str, JsonValue] | None = None
    if interactive and review_mode == "semantic":

        async def authorize_provider_channel() -> str | None:
            nonlocal privacy
            from finishup.cli.privacy_setup import run_privacy_setup
            from finishup.cli.unlock import HumanCeremonyCliError
            from finishup.ports.control import ControlError

            try:
                external_runtime_configured = (
                    load_config({}, os.environ, None).external_runtime is not None
                )
            except ConfigError:
                # This optional read only decides whether an API-credential probe applies. Keep
                # the established prompt path when ambient configuration cannot be interpreted;
                # the owning provider/setup operation will still report that configuration error.
                external_runtime_configured = False
            credential_probe_authorized = (
                False if external_runtime_configured else _prompt_credential_probe_authorization()
            )
            # ADR-049 review round 1: both answers that set up AI-powered review list the AI
            # recipes with their own recommendation (Assisted review by default), never the
            # released Private recommendation a subscription reviewer would otherwise get.
            try:
                privacy_result = await run_privacy_setup(
                    credential_probe_authorized=credential_probe_authorized,
                    update_checks_override=update_checks_choice,
                    conversation_review=(
                        None
                        if review_choice is None
                        else review_choice_conversation_setting(review_choice)
                    ),
                    workspace_locator=codex_project,
                    ai_review_add_on=True,
                )
            except (ControlError, HumanCeremonyCliError, OSError, ValueError) as error:
                reason = getattr(error, "reason", None)
                if type(error) is ValueError:
                    value_error_reason = str(error)
                    reason = (
                        value_error_reason
                        if value_error_reason.startswith("privacy_setup_")
                        else "privacy_setup_failed"
                    )
                privacy = {
                    "outcome": "failed",
                    "profile": "unknown",
                    "grant_state": None,
                    "migration_state": None,
                    "reason": reason if type(reason) is str else "privacy_setup_failed",
                }
                return _privacy_block_reason(reason)
            privacy = {
                "outcome": privacy_result.outcome,
                "profile": privacy_result.profile,
                "proposal_id": privacy_result.proposal_id,
                "grant_state": getattr(privacy_result, "grant_state", None),
                "migration_state": getattr(privacy_result, "migration_state", None),
                "reason": privacy_result.reason,
            }
            if privacy_result.outcome in {"configured", "unchanged"}:
                return None
            return _privacy_block_reason(privacy_result.reason)

        service, provider = await _interactive_provider_setup(
            service,
            before_credential=authorize_provider_channel,
            project=codex_project,
        )
        service, provider = _provider_setup_result(service, provider)
        if service.get("state") == "ready" and provider.get("binding") == "configured":
            if provider.get("credential") == "stored":
                service = await _restart_service_for_semantic_composition()
            if service.get("state") == "ready":
                from finishup.cli.provider_status import provider_status_report
                from finishup.ports.control import ControlError

                # This is a read-only structural status read. It never probes the provider or
                # dispatches AI-powered review work, and it supplies authoritative blockers after a
                # credential ceremony fails or returns an ambiguous result.
                try:
                    semantic_status = await provider_status_report(workspace_locator=codex_project)
                except ControlError, OSError, ValueError:
                    semantic_status = None
    elif interactive and review_mode == "local_only":
        from finishup.cli.privacy_setup import run_privacy_setup
        from finishup.cli.unlock import HumanCeremonyCliError
        from finishup.ports.control import ControlError

        try:
            privacy_result = await run_privacy_setup(
                recipe_hint="private",
                update_checks_override=update_checks_choice,
                # ADR-049: the owner's explicit "local only; agents may not opt in".
                conversation_review=ConversationReview.LOCAL_ONLY,
                workspace_locator=codex_project,
            )
            privacy = {
                "outcome": privacy_result.outcome,
                "profile": privacy_result.profile,
                "proposal_id": privacy_result.proposal_id,
                "grant_state": getattr(privacy_result, "grant_state", None),
                "migration_state": getattr(privacy_result, "migration_state", None),
                "reason": privacy_result.reason,
            }
        except (ControlError, HumanCeremonyCliError, OSError, ValueError) as error:
            privacy = {
                "outcome": "failed",
                "profile": "unknown",
                "grant_state": None,
                "migration_state": None,
                "reason": _privacy_block_reason(getattr(error, "reason", None)),
            }

    # A package check can happen only after the interactive user explicitly answered the
    # update-check question and the trusted privacy ceremony had a chance to commit it.
    update_choice_committed = privacy.get("outcome") in {"configured", "unchanged"}
    package_update = await _resolve_setup_package_update(
        interactive=interactive and update_checks_choice is True and update_choice_committed
    )

    next_steps: list[JsonValue] = []
    registration_next = registration.get("next_step")
    if type(registration_next) is str:
        _append_next_step(next_steps, registration_next)
    if not interactive:
        _append_next_step(next_steps, _NEXT_AGENT_GUIDE)
    if not service.get("reachable"):
        _append_next_step(next_steps, _NEXT_SERVICE)
    if service.get("state") != "ready":
        _append_next_step(next_steps, _NEXT_UNLOCK)
    if review_mode == "semantic":
        status_steps = (
            _semantic_status_next_steps(cast(Mapping[str, object], semantic_status))
            if semantic_status is not None
            else ()
        )
        for step in status_steps:
            _append_next_step(next_steps, step)
        if semantic_status is None or (
            semantic_status.get("semantic_ready") is not True and not status_steps
        ):
            # Fall back only to component results that this run committed or directly observed.
            # A missing credential cannot be repaired by restarting a ready service, and a
            # successful privacy result must stay successful even when the next component fails.
            if privacy.get("outcome") not in {"configured", "unchanged", "not_changed"}:
                _append_next_step(next_steps, _NEXT_PRIVACY)
            if provider.get("binding") != "configured":
                _append_next_step(next_steps, _NEXT_PROVIDER_TOML)
            if not _provider_credential_ready(provider):
                _append_next_step(next_steps, _NEXT_CREDENTIAL)
            elif provider.get("binding") == "configured":
                _append_next_step(next_steps, _NEXT_RESTART)
    elif review_mode != "local_only":
        if privacy.get("outcome") not in {"configured", "unchanged", "not_changed"}:
            _append_next_step(next_steps, _NEXT_PRIVACY)
        if provider.get("binding") != "configured":
            _append_next_step(next_steps, _NEXT_PROVIDER_TOML)
        if not _provider_credential_ready(provider):
            _append_next_step(next_steps, _NEXT_CREDENTIAL)
    if (
        chosen is not None
        and provider.get("binding") == "configured"
        and registration.get("route_profile") == "strict"
    ):
        _append_next_step(
            next_steps,
            "run 'finishup integrate codex mcp preview' and explicitly accept re-registration "
            "if you want the policy route to permit configured AI-powered review",
        )

    mutating_run = interactive or accept
    # A privacy step this run attempted for AI-powered review and that was declined or failed
    # leaves setup incomplete, as on every provider path, even when an earlier policy keeps the
    # evaluator composable.
    privacy_incomplete = review_mode == "semantic" and privacy.get("outcome") not in {
        "configured",
        "unchanged",
        "not_changed",
        "deferred",
    }
    if privacy_incomplete and interactive:
        # The closing block names the privacy step and, when no API key was stored, the
        # credential step, in that order; the summary list leaves them out so each prints once.
        next_steps = [step for step in next_steps if step not in {_NEXT_PRIVACY, _NEXT_CREDENTIAL}]
    setup_complete = (
        not interactive
        or (review_mode == "local_only" and privacy.get("outcome") in {"configured", "unchanged"})
        or (
            semantic_status is not None
            and semantic_status.get("semantic_ready") is True
            and not privacy_incomplete
        )
    )
    marker_written = (
        _write_setup_marker(str(registration["outcome"]))
        if mutating_run and setup_complete
        else False
    )
    integration = _integration_layers(codex_project)
    consent: str | None = None
    observation = registration.get("observation_consent")
    if isinstance(observation, Mapping):
        raw_consent = observation.get("outcome")
        consent = raw_consent if type(raw_consent) is str else None
    plugin_block = registration.get("plugin")
    plugin_presence = None
    if isinstance(plugin_block, Mapping):
        raw_presence = plugin_block.get("presence")
        plugin_presence = raw_presence if type(raw_presence) is str else None
    else:
        plugin = integration.get("plugin")
        if isinstance(plugin, Mapping):
            raw_presence = plugin.get("presence")
            plugin_presence = raw_presence if type(raw_presence) is str else None
    skill_block = registration.get("skill")
    skill_presence = None
    if isinstance(skill_block, Mapping):
        raw_presence = skill_block.get("presence")
        skill_presence = raw_presence if type(raw_presence) is str else None
    else:
        skill = integration.get("skill")
        if isinstance(skill, Mapping):
            raw_presence = skill.get("presence")
            skill_presence = raw_presence if type(raw_presence) is str else None
    hooks_raw = integration.get("hooks")
    hooks = hooks_raw if isinstance(hooks_raw, dict) else {}
    activation_block = registration.get("plugin_activation")
    selected_codex_home: Path | None = None
    if isinstance(activation_block, Mapping):
        raw_codex_home = activation_block.get("codex_home")
        if type(raw_codex_home) is str:
            selected_codex_home = Path(raw_codex_home)
    if selected_codex_home is None and chosen is not None and codex_home is not None:
        # An explicitly provided home stays bound for readiness even when the
        # registration step failed before echoing it (#390).
        selected_codex_home = codex_home
    readiness = _readiness_layers(
        binary=chosen,
        mcp_state=cast(str | None, registration.get("state")),
        plugin_presence=plugin_presence,
        skill_presence=skill_presence,
        hooks=hooks,
        consent_outcome=consent,
        service=service,
        workspace=codex_project,
        codex_home=selected_codex_home,
    )
    if semantic_status is not None:
        advice_ready, advice_note = _semantic_advice_readiness(semantic_status)
        readiness["semantic_advice_ready"] = advice_ready
        readiness["semantic_advice_note"] = advice_note
    recommendations = await _refresh_setup_recommendations(
        binary=chosen,
        codex_home=selected_codex_home,
        allow_network=interactive and update_checks_choice is True and update_choice_committed,
        workspace=codex_project,
    )

    report: dict[str, JsonValue] = {
        "discovered": [_binary_row(binary) for binary in binaries],
        "integration": integration,
        "marker_written": marker_written,
        "next_steps": next_steps,
        "package_update": package_update,
        "privacy": privacy,
        "provider": provider,
        "readiness": readiness,
        "recommendations": recommendations,
        "registration": registration,
        "schema": _REPORT_SCHEMA,
        "selected": None if chosen is None else _binary_row(chosen),
        "semantic_status": semantic_status,
        "service": service,
        "review_mode": review_mode,
    }
    if interactive:
        _emit_human_report(report)
        if privacy_incomplete:
            typer.echo("")
            _emit_privacy_incomplete(
                reason=privacy.get("reason"),
                privacy_outcome=str(privacy.get("outcome")),
                api_key_unstored=provider.get("credential") != "external_runtime_oauth"
                and not _provider_credential_ready(provider),
            )
            return 20
        if (
            provider.get("binding") == "configured"
            and provider.get("credential") == "external_runtime_oauth"
            and privacy.get("outcome") in _PRIVACY_READY
        ):
            typer.echo("")
            _emit_codex_subscription_layer_report(privacy_outcome=str(privacy.get("outcome")))
    else:
        _emit(report, json_output=json_output)
    return 0


def _emit_human_report(report: dict[str, JsonValue]) -> None:
    registration = report["registration"]
    service = report["service"]
    provider = report["provider"]
    privacy = report.get("privacy")
    integration = report["integration"]
    readiness = report.get("readiness")
    typer.echo("Setup summary:")
    if isinstance(registration, dict):
        outcome = registration.get("outcome")
        reason = registration.get("reason")
        # MCP registration alone is not product readiness or plugin activation.
        if outcome in {"registered", "reregistered", "already_registered"}:
            line = f"  MCP registration: {outcome}"
        else:
            line = f"  MCP registration: {outcome}"
        if reason:
            line += f" ({reason})"
        typer.echo(line)
        route = registration.get("route_profile")
        if type(route) is str:
            route_line = f"  MCP route profile: {route}"
            route_before = registration.get("route_profile_before")
            if type(route_before) is str and route_before != route:
                route_line += f" (changed from {route_before})"
            typer.echo(route_line)
        plugin = registration.get("plugin")
        if isinstance(plugin, dict):
            typer.echo(
                "  Plugin source files: "
                f"{plugin.get('outcome') or 'unknown'} "
                f"(presence={plugin.get('presence') or 'absent'})"
            )
        activation = registration.get("plugin_activation")
        if isinstance(activation, dict):
            typer.echo(
                "  Codex plugin activation: "
                f"{activation.get('state') or 'unknown'} "
                f"(outcome={activation.get('outcome') or 'observed'})"
            )
            if activation.get("legacy_activation") is True:
                typer.echo(
                    "  Earlier Yoetz plugin activation: still present (integrate migrates it)"
                )
            if type(activation.get("next_command")) is str:
                typer.echo(f"  Next: {activation['next_command']}")
            config_path = activation.get("config_path")
            if type(config_path) is str:
                typer.echo(f"  Activated Codex config: {config_path}")
        skill = registration.get("skill")
        if isinstance(skill, dict):
            typer.echo(
                "  Project skill installation: "
                f"{skill.get('outcome') or 'unknown'} "
                f"(presence={skill.get('presence') or 'absent'}; "
                f"compatibility={skill.get('compatibility') or 'unsupported'})"
            )
    if isinstance(integration, dict):
        skill = integration.get("skill")
        hooks = integration.get("hooks")
        if isinstance(skill, dict) and skill.get("source_state") != "verified":
            typer.echo("  Skill support: packaged source invalid; automatic activation not tested")
        elif (
            isinstance(skill, dict)
            and isinstance(skill.get("tested_profiles"), list)
            and bool(skill.get("tested_profiles"))
        ):
            tested_profiles = cast(list[JsonValue], skill["tested_profiles"])
            profiles = ", ".join(str(item) for item in tested_profiles)
            typer.echo(f"  Skill support: tested profiles: {profiles}")
        else:
            typer.echo(
                "  Skill support: no tested capability profile; automatic activation not tested"
            )
        if isinstance(hooks, dict):
            typer.echo(
                "  Hook installation: "
                f"{hooks.get('presence') or 'absent'}; "
                f"trust {hooks.get('trust_state') or 'unknown'}"
            )
    if isinstance(registration, dict):
        observation = registration.get("observation_consent")
        if isinstance(observation, dict):
            outcome = observation.get("outcome")
            if outcome == "granted":
                typer.echo(
                    "  Observation consent: granted "
                    "(structural events only; coverage requires real evidence)"
                )
                kept = observation.get("content_capture_profiles")
                if isinstance(kept, list) and kept:
                    typer.echo(
                        "  Native content profiles kept: "
                        + ", ".join(str(profile) for profile in cast(list[JsonValue], kept))
                    )
            elif outcome is not None:
                typer.echo(f"  Observation consent: {outcome}")
        check_policy = registration.get("check_policy")
        if isinstance(check_policy, dict):
            policy_outcome = check_policy.get("outcome") or "absent"
            if policy_outcome == "ambiguous":
                typer.echo(f"  Approved-check policy: ambiguous ({_POLICY_AMBIGUOUS_TEXT})")
            else:
                typer.echo(f"  Approved-check policy: {policy_outcome}")
            digest = check_policy.get("policy_digest")
            if type(digest) is str:
                typer.echo(f"  Approved-check policy digest: {digest}")
    if isinstance(service, dict):
        reachable = service.get("reachable")
        typer.echo(f"  Local service reachable: {'yes' if reachable else 'no'}")
        typer.echo(f"  Local service state: {service.get('state') or 'unavailable'}")
    if isinstance(readiness, dict):
        typer.echo(
            "  Observation readiness: "
            + ("ready to observe" if readiness.get("observation_ready") else "not ready")
        )
        typer.echo(
            "  AI-powered advice readiness: "
            + (
                "ready"
                if readiness.get("semantic_advice_ready")
                else _advice_readiness_text(readiness.get("semantic_advice_note"))
            )
        )
    if isinstance(provider, dict):
        typer.echo(f"  Provider binding: {provider.get('binding')}")
        from finishup.cli.provider_status import credential_human_display

        credential = provider.get("credential")
        if credential == "external_runtime_oauth":
            typer.echo("  Credential authority: Codex-managed ChatGPT login")
            if provider.get("login_reused") is True:
                typer.echo("  Sign-in: reused the existing Codex login")
        else:
            typer.echo(
                "  Credential: "
                + credential_human_display(
                    True if credential == "stored" else (False if credential == "failed" else None)
                )
            )
        credential_reason = provider.get("credential_reason")
        if not _provider_credential_ready(provider) and type(credential_reason) is str:
            typer.echo(f"  Credential reason: {credential_reason}")
    if isinstance(privacy, dict):
        line = f"  Privacy: {privacy.get('outcome')} ({privacy.get('profile')})"
        grant_state = privacy.get("grant_state")
        if type(grant_state) is str:
            line += f"; repository grant: {grant_state}"
        if privacy.get("reason"):
            line += f"; reason: {privacy.get('reason')}"
        typer.echo(line)
    steps = report["next_steps"]
    if isinstance(steps, list) and steps:
        typer.echo("Next steps:")
        for step in steps:
            typer.echo(f"  - {step}")


async def run_vault_setup() -> int:
    """Reuse the protected storage ceremony without configuring a model provider."""
    if not _is_interactive_terminal():
        typer.echo(
            "trusted_console_required: run 'finishup setup vault' in your local terminal", err=True
        )
        return 2
    service = await _service_reachability(start_if_absent=True)
    service, result = await _interactive_provider_setup(service, storage_only=True)
    if service.get("state") != "ready" or result.get("credential_reason") is not None:
        typer.echo("Vault setup is incomplete. Inspect 'finishup setup status --next'.", err=True)
        return 20
    typer.echo("Vault ready. Provider configuration and privacy permissions were not changed.")
    return 0


async def setup_status(*, json_output: bool) -> int:
    """Read-only setup posture: discovery, registration state, service, marker."""

    from finishup.cli.host_connection import installation_rows

    binaries = discover_codex_binaries()
    service_port = _mcp_adapter()
    rows: list[JsonValue] = []
    for binary in binaries:
        row = _binary_row(binary)
        # This legacy status surface has no paired home input. It reports that omission rather
        # than guessing from the executable or ambient process state.
        row["plugin_activation"] = {
            "reason": "codex_home_required",
            "state": "unknown",
        }
        try:
            observation = await HarnessMcpService(service_port).observe(binary)
            row["registration_state"] = observation.state.value
            # A strict and a policy registration are both finishup_owned; only this distinguishes them.
            row["registered_route_profile"] = observation.route_profile
        except McpRegistrationError as error:
            row["registration_state"] = None
            row["registered_route_profile"] = None
            row["registration_error"] = error.reason.value
        rows.append(row)
    service, folder_refusal = await _service_reachability_observed()
    report: dict[str, JsonValue] = {
        "discovered": rows,
        "hosts": installation_rows(),
        "integration": _integration_layers(),
        "marker_present": setup_marker_present(),
        "platform": _platform_diagnostics(),
        "schema": _STATUS_SCHEMA,
        "service": service,
    }
    _emit(report, json_output=json_output)
    if folder_refusal is not None:
        # The released report (setup status 2.0.0) has no field for this, so stdout keeps its
        # shape and the refusal goes to stderr with the exit code it carries (ADR-048).
        return _report_folder_refusal(folder_refusal)
    return 0


def _platform_diagnostics() -> dict[str, JsonValue]:
    """Host facts named once: platform cell, check sandbox, credential store (#720, #721, #724).

    Each answer is a fixed reason token plus fixed remediation text; none echoes a path.
    """

    from finishup.adapters.check_sandbox import probe_check_sandbox
    from finishup.adapters.keys.os_keyring import describe_vault_keyring_backend
    from finishup.version import platform_cell

    return {
        "cell": cast(JsonValue, platform_cell().as_json()),
        "check_sandbox": cast(JsonValue, probe_check_sandbox().as_json()),
        "secure_storage": describe_vault_keyring_backend().as_json(),
    }


_MCP_EXIT_USAGE: Final = frozenset(
    {
        "confirmation_required",
        "preview_stale",
        "foreign_entry_present",
        "route_change_affects_other_projects",
    }
)


def _connect_refused() -> int | None:
    """Refuse a connect when this installation's runtime cannot serve the running account.

    Prints ``<token>: <next step>`` and returns exit 20, like the serving commands' own refusal;
    ``None`` lets the connect proceed. Status and removal never ask.
    """

    from finishup.cli.runtime_refusal import connect_refusal

    refusal = connect_refusal()
    if refusal is None:
        return None
    token, next_step = refusal
    typer.echo(f"{token}: {next_step}", err=True)
    return 20


def _sharing_clause(sharing: tuple[str, ...], maybe: tuple[str, ...], unknown: bool) -> str:
    """Name the other projects a shared-registration removal reaches."""

    named = [*sharing, *(f"{item} (may use FinishUP)" for item in maybe)]
    if unknown:
        return "and the projects using it could not be read" + (
            ("; known: " + ", ".join(named)) if named else ""
        )
    return "including: " + ", ".join(named)


def _mcp_error_exit(reason: str, *, preview_command: str | None = None) -> int:
    typer.echo(f"mcp_registration_{reason}", err=True)
    if reason == "foreign_entry_present":
        typer.echo(
            "Foreign configuration was preserved. Create a new owner-private Codex home "
            "(mode 0700), then preview again with --codex-home <new-home>.",
            err=True,
        )
    if reason == "route_change_affects_other_projects":
        typer.echo(
            "Nothing was changed. The FinishUP MCP registration is shared by every project using "
            "this Codex home, so this review mode change would apply to them too. Run "
            + (preview_command or "the preview with the same --route-profile")
            + ", check the projects it names, then install with the same --route-profile and "
            "its exact --preview-digest.",
            err=True,
        )
    return 2 if reason in _MCP_EXIT_USAGE else 20


async def integrate_mcp(
    action: str,
    harness: str,
    *,
    codex_path: str | None,
    codex_home: Path | None = None,
    accept: bool,
    preview_digest: str | None,
    json_output: bool,
    route_profile: Literal["policy", "strict"] | None = None,
    project_root: Path | None = None,
    _state: Path | None = None,
) -> int:
    """Client-local MCP status, registration, and unregistration commands.

    ``route_profile`` is the explicit route input. When absent, an existing
    finishup-owned registration keeps its observed profile (#389); only a fresh
    registration falls back to the structural configuration derivation.

    ``project_root`` names the trusted project whose Codex host-admission entry
    (issue #467) a strict registration or an unregistration also revokes. The
    registration is global and the admission is project-scoped, so without an
    explicit root nothing is swept and ``provider status`` reports the drift.
    """

    if harness != "codex" or action not in {
        "status",
        "preview",
        "preview-remove",
        "install",
        "remove",
    }:
        return _usage_failure("the harness or action is not supported")
    if action in {"preview", "install"}:
        refused = _connect_refused()
        if refused is not None:
            return refused
    interactive = _is_interactive_terminal()
    binaries = discover_codex_binaries()
    try:
        chosen = _choose_binary(binaries, codex_path=codex_path, interactive=False)
    except _UsageExit as failure:
        return failure.code
    if chosen is None:
        return _usage_failure("no codex executable was found on PATH")

    from finishup.adapters.integrations.codex_session_stream import resolve_codex_home

    selected_home = resolve_codex_home(codex_home).absolute()
    service = HarnessMcpService(_mcp_adapter(route_profile, codex_home=selected_home))
    try:
        if action == "status":
            observation = await service.observe(chosen)
            # Issue #537 slice B: join the durable applied route against the
            # host's own live resolution (never a cached preview). Fail-soft:
            # an unreadable record reads as no applied route and no drift.
            try:
                _applied_record = read_applied_route(_state=_state)
            except Exception:
                _applied_record = None
            _applied_profile: str | None = None
            if isinstance(_applied_record, dict):
                _candidate = _applied_record.get("applied_profile")
                if isinstance(_candidate, str) and _candidate in {"policy", "strict"}:
                    _applied_profile = _candidate
            _registered_profile = observation.route_profile
            # Strict both-in-set rule (issue #537 review B1): drift is True
            # iff a record exists AND both profiles name a FinishUP route AND
            # they differ. Unread/None/DUAL/FOREIGN/ABSENT (registered None)
            # never report drift; host observe stays the authority.
            _drift = (
                _applied_record is not None
                and _applied_profile in {"policy", "strict"}
                and _registered_profile in {"policy", "strict"}
                and _registered_profile != _applied_profile
            )
            _emit(
                {
                    "harness": harness,
                    "inspected_codex_home": str(selected_home),
                    "isolation_binding": observation.isolation_binding,
                    # ``legacy_only`` reads as owned but outdated; integrate migrates it (ADR-048).
                    "legacy_registration": observation.legacy_registration,
                    "route_profile": observation.route_profile,
                    "state": observation.state.value,
                    "registered_profile": _registered_profile,
                    "applied_profile": _applied_profile,
                    "drift_since_install": _drift,
                },
                json_output=json_output,
            )
            return 0
        if action in {"preview-remove", "remove"}:
            preview = await service.preview_unregistration(chosen)
            # The registration is user-level: removing it removes it for every project of the
            # home. This low-level command still may (`setup disconnect` keeps it while others
            # use it), but it names them and its digest binds them (#1058 review round 2).
            from finishup.adapters.integrations.codex_marketplace import other_members

            sharing: tuple[str, ...] = ()
            maybe: tuple[str, ...] = ()
            membership_unknown = False
            if preview.action is not McpRegistrationAction.NOOP:
                try:
                    sharing, maybe = other_members(
                        selected_home,
                        None if project_root is None else project_root.expanduser().resolve(),
                    )
                except IntegrationError:
                    # The projects using this home cannot be read: never "nobody else".
                    membership_unknown = True
            shared_report: dict[str, JsonValue] = {}
            if sharing or maybe or membership_unknown:
                shared_report = {
                    "shared_with": cast(list[JsonValue], list(sharing)),
                    "possible_users": cast(list[JsonValue], list(maybe)),
                }
                if membership_unknown:
                    shared_report["membership_unknown"] = True
            removal_digest = (
                preview.preview_digest
                if not shared_report
                else canonical_digest(
                    {"mcp_preview_digest": preview.preview_digest, "shared": shared_report}
                )
            )
            if action == "preview-remove":
                _emit(
                    {
                        "action": preview.action.value,
                        "admission_cleanup": _admission_cleanup_preview(project_root),
                        "harness": harness,
                        "inspected_codex_home": str(selected_home),
                        "isolated_root": preview.isolated_root,
                        "legacy_registration": preview.legacy_registration,
                        "preview_digest": removal_digest,
                        "route_profile": preview.route_profile,
                        "serve_command": list(preview.serve_command),
                        "state_before": preview.state_before.value,
                        "warnings": [
                            *preview.warnings,
                            *(
                                ["mcp_registration_shared_with_other_projects"]
                                if shared_report
                                else []
                            ),
                        ],
                        **shared_report,
                    },
                    json_output=json_output,
                )
                if shared_report and not json_output:
                    typer.echo(
                        "This removes the FinishUP MCP registration for every project using this "
                        "Codex home, "
                        + _sharing_clause(sharing, maybe, membership_unknown)
                        + ". To disconnect only one project, use `finishup setup disconnect`."
                    )
                return 0
            if preview_digest is not None and preview_digest != removal_digest:
                return _mcp_error_exit("preview_stale")
            if preview.state_before is McpRegistrationState.FOREIGN_PRESENT:
                return _mcp_error_exit("foreign_entry_present")
            if accept and preview_digest is None:
                return _mcp_error_exit("confirmation_required")
            accepted = accept
            if interactive and not accepted:
                _emit_unregistration_preview(preview)
                if shared_report:
                    typer.echo(
                        "  This removes it for every project using this Codex home, "
                        + _sharing_clause(sharing, maybe, membership_unknown)
                    )
                accepted = _confirm_registration()
            if not accepted:
                return _mcp_error_exit("confirmation_required")
            if preview.action is McpRegistrationAction.NOOP:
                # A NOOP remove against ABSENT means the host entry is already
                # gone (e.g. manually deleted): drop any stale applied record
                # fail-soft so later drift reads False, then emit the noop.
                if preview.state_before is McpRegistrationState.ABSENT:
                    try:
                        clear_applied_route(_state=_state)
                    except Exception:
                        pass
                _emit(
                    {
                        "action": "noop",
                        "admission_cleanup": _admission_reverse_sweep(project_root),
                        "harness": harness,
                        "inspected_codex_home": str(selected_home),
                        "state_after": preview.state_before.value,
                        "state_before": preview.state_before.value,
                    },
                    json_output=json_output,
                )
                return 0
            # Sweep the project admission first: once the user-level transport is gone, a
            # trusted project's leftover `mcp_servers.finishup` table stops Codex loading there.
            admission_cleanup = _admission_reverse_sweep(project_root)
            result = await service.unregister(
                chosen,
                McpRegistrationConfirmation(
                    preview.preview_digest,
                    True,
                    "interactive" if interactive else "noninteractive_flag",
                ),
                _state=_state,
            )
            _emit(
                {
                    "action": result.action.value,
                    "admission_cleanup": admission_cleanup,
                    "harness": harness,
                    "inspected_codex_home": str(selected_home),
                    "state_after": result.state_after.value,
                    "state_before": result.state_before.value,
                    "removal": mcp_removal_report(result),
                },
                json_output=json_output,
            )
            return 0
        preview = await service.preview(chosen)
        # Read the owned registration's mode from the registration: a ``reregister`` may change
        # only the launcher or isolation root and keep the mode (#1058 review round 3).
        route_profile_before = await _observed_route_before(service, chosen, preview)
        if (
            route_profile is None
            and route_profile_before is not None
            and route_profile_before != preview.route_profile
        ):
            # No explicit route input: preserve the existing finishup-owned route
            # rather than letting the configuration derivation rewrite it (#389).
            service = HarnessMcpService(
                _mcp_adapter(route_profile_before, codex_home=selected_home)
            )
            preview = await service.preview(chosen)
        # The registration is user-level: a review-mode change reaches every other project of
        # the home. The preview names them and its digest binds them; an install that would
        # change them needs that digest (#1058 review round 2).
        route_change = _route_change_report(
            route_profile_before,
            preview.route_profile,
            *_shared_route_change_members(
                selected_home,
                None if project_root is None else project_root.expanduser().resolve(),
                route_profile_before,
                preview.route_profile,
            ),
        )
        shown_digest = (
            preview.preview_digest
            if not route_change
            else canonical_digest(
                {"mcp_preview_digest": preview.preview_digest, "route_change": route_change}
            )
        )
        if action == "preview":
            _emit(
                {
                    "action": preview.action.value,
                    "admission_cleanup": (
                        _admission_cleanup_preview(project_root)
                        if preview.route_profile == "strict"
                        else None
                    ),
                    "harness": harness,
                    "inspected_codex_home": str(selected_home),
                    "isolated_root": preview.isolated_root,
                    "legacy_registration": preview.legacy_registration,
                    # An owned ``yoetz`` entry kept beside ``finishup`` for these projects (#1073).
                    **(
                        {
                            "legacy_registration_kept_for": list(preview.legacy_kept_for),
                            "legacy_registration_kept_unchecked": preview.legacy_kept_unchecked,
                        }
                        if preview.legacy_kept_for or preview.legacy_kept_unchecked
                        else {}
                    ),
                    "preview_digest": shown_digest,
                    "route_profile": preview.route_profile,
                    "route_profile_before": route_profile_before,
                    **{
                        key: value
                        for key, value in route_change.items()
                        if key != "route_profile_before"
                    },
                    "serve_command": list(preview.serve_command),
                    "state_before": preview.state_before.value,
                    "warnings": list(preview.warnings),
                },
                json_output=json_output,
            )
            sentence = _route_change_sentence(route_change, preview.route_profile)
            if sentence is not None and not json_output:
                typer.echo(sentence)
            return 0
        if preview_digest is not None and preview_digest != shown_digest:
            return _mcp_error_exit("preview_stale")
        if preview.state_before is McpRegistrationState.FOREIGN_PRESENT:
            return _mcp_error_exit("foreign_entry_present")
        if "legacy_registration_route_kept" in preview.warnings:
            # The kept ``yoetz`` entry would go on serving another review mode (#1073).
            typer.echo("mcp_registration_legacy_registration_route_kept", err=True)
            typer.echo(_legacy_route_kept_step(preview), err=True)
            return 2
        if route_change and accept and preview_digest is None:
            # Other projects' review mode would change: only the exact preview may approve it.
            from finishup.cli.setup_readiness import continuation

            return _mcp_error_exit(
                "route_change_affects_other_projects",
                preview_command=continuation(
                    [
                        "integrate",
                        "codex",
                        "mcp",
                        "preview",
                        "--codex-path",
                        chosen.executable_path,
                        "--codex-home",
                        str(selected_home),
                        "--route-profile",
                        preview.route_profile,
                        *(
                            ["--project-root", str(project_root)]
                            if project_root is not None
                            else []
                        ),
                    ]
                ),
            )
        accepted = accept
        if interactive and not accepted:
            _emit_registration_preview(
                chosen,
                preview,
                route_profile_before=route_profile_before,
                route_change=route_change,
            )
            accepted = _confirm_registration()
        if not accepted:
            return _mcp_error_exit("confirmation_required")
        if preview.action is McpRegistrationAction.NOOP:
            # The ceremony was accepted and the host is already on the previewed route, so
            # the applied record has to agree with it: an earlier entry left here would
            # report drift against a route the owner just re-accepted (issue #537).
            if preview.state_before is McpRegistrationState.FINISHUP_OWNED:
                service.reconcile_applied_route(chosen, preview, _state=_state)
            _emit(
                {
                    "action": "noop",
                    "admission_cleanup": (
                        _admission_reverse_sweep(project_root)
                        if preview.route_profile == "strict"
                        else None
                    ),
                    "harness": harness,
                    "inspected_codex_home": str(selected_home),
                    "state_after": preview.state_before.value,
                    "state_before": preview.state_before.value,
                },
                json_output=json_output,
            )
            return 0
        result = await service.register(
            chosen,
            McpRegistrationConfirmation(
                preview.preview_digest,
                True,
                "interactive" if interactive else "noninteractive_flag",
            ),
            _state=_state,
        )
    except McpRegistrationError as error:
        if action == "remove" and error.reason.value == "registration_failed":
            from finishup.cli.setup_readiness import continuation

            inspect_command = continuation(
                [
                    "integrate",
                    "codex",
                    "mcp",
                    "status",
                    "--codex-path",
                    chosen.executable_path,
                    "--codex-home",
                    str(selected_home),
                    "--json",
                ]
            )
            _emit(
                {"removal": mcp_removal_report(error), "next_command": inspect_command},
                json_output=json_output,
            )
            typer.echo(
                "Removal was attempted but absence is unverified. Inspect the selected "
                "registration before obtaining a fresh removal preview: " + inspect_command,
                err=True,
            )
        return _mcp_error_exit(error.reason.value)
    _emit(
        {
            "action": result.action.value,
            "admission_cleanup": (
                _admission_reverse_sweep(project_root)
                if preview.route_profile == "strict"
                else None
            ),
            "harness": harness,
            "inspected_codex_home": str(selected_home),
            "state_after": result.state_after.value,
            "state_before": result.state_before.value,
        },
        json_output=json_output,
    )
    return 0


def _admission_cleanup_preview(project_root: Path | None) -> JsonValue:
    if project_root is None:
        return None
    from finishup.cli.host_admission import admission_cleanup_preview

    return admission_cleanup_preview("codex", project_root)


def _admission_reverse_sweep(project_root: Path | None) -> JsonValue:
    if project_root is None:
        return None
    from finishup.cli.host_admission import reverse_sweep

    return reverse_sweep("codex", project_root)
