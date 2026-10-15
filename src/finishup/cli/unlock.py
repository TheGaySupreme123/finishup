"""Foreground-only confidential local-human ceremony helper."""

from __future__ import annotations

import hmac
import os
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal, Protocol, cast

from finishup.cli.trusted_console import TrustedConsoleError, TrustedForegroundConsole
from finishup.domain.privacy import PrivacyPolicyChange, PrivacyPolicyChangeValue
from finishup.ports.secret_memory import presence_confirmation_code
from finishup.protocol.canonical import canonical_digest
from finishup.service.confidential_client import (
    ConfidentialClientError,
    HumanControlClient,
    HumanControlSession,
)
from finishup.service.confidential_protocol import (
    AuthorizationRequiredPhase,
    ConfidentialProtocolError,
    ConfidentialSecretPurpose,
    DecisionAction,
    DecisionRequiredPhase,
    EmptyVaultTarget,
    HumanCeremonyKind,
    HumanOpenTarget,
    HumanPhase,
    HumanPreview,
    HumanResult,
    IdleRelockPolicyChangePreview,
    IdleRelockPolicyResult,
    IdleRelockPolicyTarget,
    InstallationRecoveryPreview,
    InstallationRecoveryResult,
    InstallationRecoveryTarget,
    KeyringRetryPhase,
    KeyringRetryPreview,
    KeyringRetryResult,
    OwnerReceiptViewPreview,
    OwnerReceiptViewResult,
    OwnerReceiptViewTarget,
    PortableRecoveryPreview,
    PortableRecoveryResult,
    PortableRecoveryTarget,
    PrivacyDecisionResult,
    PrivacyDisclosureDecisionPreview,
    PrivacyPendingTarget,
    PrivacyPolicyDecisionPreview,
    ProviderCredentialResult,
    ProviderCredentialRotatePreview,
    ProviderCredentialSetPreview,
    ProviderCredentialTarget,
    RetryAction,
    SecretRequiredPhase,
    SelectAuthorizationSourceAction,
    VaultInitializePreview,
    VaultPassphraseRotatePreview,
    VaultStateResult,
    VaultUnlockPreview,
    human_target_json,
    validate_passphrase_buffer,
    validate_provider_credential_buffer,
)

__all__ = [
    "DisabledIdleRelockCliPolicyValue",
    "FiniteIdleRelockCliPolicyValue",
    "HumanCeremonyCliError",
    "IdleRelockCliPolicyValue",
    "IdleRelockCliResult",
    "InstallationRecoveryImportResult",
    "authorize_owner_receipt_view",
    "change_idle_relock_policy",
    "export_installation_recovery_set",
    "initialize_passphrase_vault",
    "import_installation_recovery_set",
    "provision_installation_recovery",
    "revoke_installation_recovery",
    "restore_installation_recovery",
    "portable_recovery",
    "read_vault_passphrase_for_auto_unlock",
    "retry_keyring",
    "rotate_provider_credential",
    "rotate_vault_passphrase",
    "run_human_ceremony",
    "run_human_ceremony_on_terminal",
    "set_provider_credential",
    "unlock_vault",
    "overwrite_secret_buffer",
    "owner_view_confirmation_code",
    "vault_passphrase_held_by_credential_store",
]

_FIXED_ERROR_REASONS: Final = frozenset(
    {
        "cancelled",
        "confirmation_mismatch",
        "empty_input",
        "eof",
        "input_invalid",
        "interrupted",
        # Owner view (#1073): the vault's passphrase is kept in the platform credential store,
        # so its owner may never have seen it; it is used only when asked for explicitly.
        "passphrase_in_credential_store",
        # Owner view: the durable passphrase throttle (not the dialog backoff) refused.
        "passphrase_rate_limited",
        # Owner view with an explicit passphrase request on a vault without one.
        "passphrase_unavailable",
        "preview_invalid",
        "result_invalid",
        "trusted_console_required",
    }
)
_PASSPHRASE_PROMPT_SUFFIX: Final = " (16-1024 UTF-8 bytes; no control characters): "
_IGNORABLE_ROTATION_STAGE_REASONS: Final = frozenset({"missing", "unsupported"})


class HumanCeremonyCliError(Exception):
    """One bounded helper failure that never reflects preview or input bytes."""

    __slots__ = ("reason",)

    reason: str

    def __init__(self, reason: str) -> None:
        if type(reason) is not str or reason not in _FIXED_ERROR_REASONS:
            raise ValueError("human_ceremony_cli_reason_invalid")
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True, slots=True)
class FiniteIdleRelockCliPolicyValue:
    seconds: int
    mode: Literal["finite"] = "finite"

    def __post_init__(self) -> None:
        if (
            self.mode != "finite"
            or type(self.seconds) is not int
            or not 60 <= self.seconds <= 86_400
        ):
            raise ValueError("idle_relock_cli_policy_invalid")


@dataclass(frozen=True, slots=True)
class DisabledIdleRelockCliPolicyValue:
    mode: Literal["disabled"] = "disabled"

    def __post_init__(self) -> None:
        if self.mode != "disabled":
            raise ValueError("idle_relock_cli_policy_invalid")


type IdleRelockCliPolicyValue = FiniteIdleRelockCliPolicyValue | DisabledIdleRelockCliPolicyValue


@dataclass(frozen=True, slots=True)
class IdleRelockCliResult:
    outcome: Literal["applied", "denied"]
    previous: IdleRelockCliPolicyValue
    effective: IdleRelockCliPolicyValue
    scope: Literal["service_generation"]
    service_generation: int

    def __post_init__(self) -> None:
        if self.outcome not in {"applied", "denied"}:
            raise ValueError("idle_relock_cli_result_invalid")
        if type(self.previous) not in {
            FiniteIdleRelockCliPolicyValue,
            DisabledIdleRelockCliPolicyValue,
        } or type(self.effective) not in {
            FiniteIdleRelockCliPolicyValue,
            DisabledIdleRelockCliPolicyValue,
        }:
            raise ValueError("idle_relock_cli_result_invalid")
        if (
            self.scope != "service_generation"
            or type(self.service_generation) is not int
            or self.service_generation <= 0
        ):
            raise ValueError("idle_relock_cli_result_invalid")


@dataclass(frozen=True, slots=True)
class InstallationRecoveryImportResult:
    outcome: Literal["imported", "exported", "snapshot_installed"]
    recovery_generation: int
    set_mode: Literal["compact", "self_contained"]
    next_command: Literal[
        "finishup service recovery restore",
        "finishup service recovery status",
        "finishup service run",
    ]


def overwrite_secret_buffer(value: bytearray) -> None:
    for index in range(len(value)):
        value[index] = 0


class _ForegroundTerminal(TrustedForegroundConsole):
    """Compatibility facade that maps console failures into ceremony failures."""

    __slots__ = ()

    def __enter__(self) -> _ForegroundTerminal:
        try:
            super().__enter__()
        except TrustedConsoleError as exc:
            raise HumanCeremonyCliError(exc.reason) from exc
        return self

    def write(self, value: str) -> None:
        try:
            super().write(value)
        except TrustedConsoleError as exc:
            raise HumanCeremonyCliError(exc.reason) from exc

    def write_secret(self, value: bytearray) -> None:
        try:
            super().write_secret(value)
        except TrustedConsoleError as exc:
            raise HumanCeremonyCliError(exc.reason) from exc

    def read_choice(self, prompt: str, allowed: tuple[bytes, ...]) -> bytes:
        try:
            return super().read_choice(prompt, allowed)
        except TrustedConsoleError as exc:
            raise HumanCeremonyCliError(exc.reason) from exc

    def read_secret(self, prompt: str, maximum: int) -> bytearray:
        try:
            return super().read_secret(prompt, maximum)
        except TrustedConsoleError as exc:
            raise HumanCeremonyCliError(exc.reason) from exc

    def read_path(self, prompt: str, maximum: int = 4_096) -> Path:
        try:
            return super().read_path(prompt, maximum)
        except TrustedConsoleError as exc:
            raise HumanCeremonyCliError(exc.reason) from exc


class _CeremonyTerminal(Protocol):
    """Small terminal surface shared by prompted and fully supplied ceremonies."""

    def write(self, value: str) -> None: ...

    def write_secret(self, value: bytearray) -> None: ...

    def read_choice(self, prompt: str, allowed: tuple[bytes, ...]) -> bytes: ...

    def read_secret(self, prompt: str, maximum: int) -> bytearray: ...


@dataclass(slots=True)
class _AuthorizationChoice:
    """Which reauthentication source the ceremony asks for, and what the service offered.

    The CLI only names a source; the service decides. ``offered`` records the service's
    ``AuthorizationRequiredPhase`` so a caller can tell whether a passphrase was an option.
    """

    prefer: Literal["os_user_presence", "secret_reauthentication"] = "os_user_presence"
    offered: tuple[str, ...] = ()
    after_unavailable_dialog: bool = False
    # Use the passphrase and nothing else (the owner asked for it explicitly).
    passphrase_only: bool = False
    # Whether a passphrase prompt may be shown without an explicit request; None: always.
    passphrase_allowed: Callable[[], bool] | None = None
    # The source this ceremony asked the service for, once chosen.
    selected: str | None = None


class _RotationStore(Protocol):
    def stage_value_for_rotation(self, value: bytearray) -> None: ...

    def promote_staged_rotation(self) -> None: ...


class _SuppliedSecretTerminal:
    """Non-prompting facade used only when every possible secret was supplied."""

    __slots__ = ()

    def write(self, value: str) -> None:
        if type(value) is not str:
            raise TypeError("terminal_text_invalid")

    def write_secret(self, value: bytearray) -> None:
        if type(value) is not bytearray:
            raise TypeError("terminal_secret_invalid")

    def read_choice(self, prompt: str, allowed: tuple[bytes, ...]) -> bytes:
        del prompt, allowed
        raise HumanCeremonyCliError("input_invalid")

    def read_secret(self, prompt: str, maximum: int) -> bytearray:
        del prompt, maximum
        raise HumanCeremonyCliError("input_invalid")


def _verify_preview(
    kind: HumanCeremonyKind,
    target: HumanOpenTarget,
    session: HumanControlSession,
) -> HumanPreview:
    opened = session.opened
    preview = opened.preview
    expected_binding = (
        preview.confirmed_plan_digest
        if type(preview) is InstallationRecoveryPreview
        else canonical_digest(human_target_json(target))
    )
    if opened.binding.target_digest != expected_binding:
        raise HumanCeremonyCliError("preview_invalid")
    valid = False
    if kind is HumanCeremonyKind.VAULT_INITIALIZE:
        valid = type(preview) is VaultInitializePreview
    elif kind is HumanCeremonyKind.VAULT_PASSPHRASE_ROTATE:
        valid = type(preview) is VaultPassphraseRotatePreview
    elif kind is HumanCeremonyKind.VAULT_UNLOCK:
        valid = type(preview) is VaultUnlockPreview
    elif kind is HumanCeremonyKind.KEYRING_RETRY:
        valid = type(preview) is KeyringRetryPreview
    elif kind is HumanCeremonyKind.PORTABLE_RECOVERY:
        valid = (
            type(preview) is PortableRecoveryPreview
            and type(target) is PortableRecoveryTarget
            and preview.operation == target.operation
            and preview.request_id == target.request_id
            and preview.confirmed_plan_digest == target.confirmed_plan_digest
        )
    elif kind is HumanCeremonyKind.INSTALLATION_RECOVERY:
        valid = (
            type(preview) is InstallationRecoveryPreview
            and type(target) is InstallationRecoveryTarget
            and preview.operation == target.operation
            and preview.request_id == target.request_id
            # Both sides of the binding comparison are server-supplied, so it proves only
            # internal consistency.  Bind the plan to the digest this client computed for its
            # own target as well, or a server-chosen plan passes unnoticed.
            and preview.confirmed_plan_digest == target.confirmed_plan_digest
            and preview.confirmed_plan_digest == opened.binding.target_digest
            and preview.recovery_generation == target.recovery_generation
            and preview.set_mode == target.set_mode
            and preview.secret_kind == target.secret_kind
            and preview.target_envelope == target.target_envelope
        )
    elif kind is HumanCeremonyKind.PROVIDER_CREDENTIAL_SET:
        valid = (
            type(preview) is ProviderCredentialSetPreview
            and type(target) is ProviderCredentialTarget
            and preview.target == target
        )
    elif kind is HumanCeremonyKind.PROVIDER_CREDENTIAL_ROTATE:
        valid = (
            type(preview) is ProviderCredentialRotatePreview
            and type(target) is ProviderCredentialTarget
            and preview.target == target
        )
    elif kind is HumanCeremonyKind.PRIVACY_POLICY_DECISION:
        valid = (
            type(preview) is PrivacyPolicyDecisionPreview
            and type(target) is PrivacyPendingTarget
            and preview.pending_id == target.pending_id
        )
    elif kind is HumanCeremonyKind.PRIVACY_DISCLOSURE_DECISION:
        valid = (
            type(preview) is PrivacyDisclosureDecisionPreview
            and type(target) is PrivacyPendingTarget
            and preview.pending_id == target.pending_id
            and preview.authorization_change == "none"
        )
    elif kind is HumanCeremonyKind.IDLE_RELOCK_POLICY_CHANGE:
        proposed: object = (
            "disabled"
            if type(target) is IdleRelockPolicyTarget and target.operation == "disable"
            else getattr(target, "seconds", None)
        )
        valid = (
            type(preview) is IdleRelockPolicyChangePreview
            and type(target) is IdleRelockPolicyTarget
            and preview.proposed == proposed
            and preview.service_generation == opened.binding.service_generation
            and preview.target_digest == opened.binding.target_digest
        )
    elif kind is HumanCeremonyKind.OWNER_RECEIPT_VIEW:
        valid = (
            type(preview) is OwnerReceiptViewPreview
            and type(target) is OwnerReceiptViewTarget
            and preview.task_id == target.task_id
            and preview.format == target.format
            and preview.redaction_profile == target.redaction_profile
            and preview.target_digest == opened.binding.target_digest
        )
    if not valid:
        raise HumanCeremonyCliError("preview_invalid")
    return preview


# Every label below is fixed here, in the trusted client. The service sends structured
# ``(area, field, before, after)`` records and never explanatory prose, so nothing a proposal
# author writes can appear on this screen — only values drawn from the closed policy vocabulary.
# ASCII only, including the arrow: this is written straight to /dev/tty with no terminal
# capability negotiation, and a change a human cannot read is a change they cannot judge.
_ARROW: Final = " -> "

_CHANGE_GROUPS: Final[tuple[tuple[str, tuple[tuple[str, str], ...]], ...]] = (
    (
        "Destination",
        (
            ("global", "network_egress"),
            ("channel", "enabled"),
            ("channel", "provider"),
            ("channel", "fallback_provider"),
            ("channel", "purposes"),
        ),
    ),
    (
        "Information disclosed",
        (
            ("global", "credential_heuristic"),
            ("channel", "categories"),
            ("channel", "data_classes"),
            ("review", "sections"),
            ("review", "excerpt_kinds"),
            ("review", "relevance"),
            ("review", "include_finding_prose"),
            ("review", "include_exact_command_text"),
        ),
    ),
    (
        "Authorization",
        (
            ("channel", "preview_required"),
            ("channel", "scope_ceiling"),
            ("channel", "authorization_ttl_seconds"),
            ("global", "effective_scope"),
            ("global", "provider_data_use_evidence"),
        ),
    ),
    (
        "Limits",
        (
            ("channel", "max_bytes"),
            ("channel", "max_tokens"),
            ("review", "max_excerpts"),
            ("review", "max_excerpt_bytes"),
            ("review", "max_total_excerpt_bytes"),
            ("review", "max_timeline_items"),
            ("review", "max_assessments"),
            ("review", "max_change_observations"),
            ("review", "max_omissions"),
        ),
    ),
    (
        "Local visibility",
        (
            ("local_model", "enabled"),
            ("local_model", "binding"),
            ("local_model", "categories"),
            ("local_model", "data_classes"),
            ("agent_context", "categories"),
            ("agent_context", "data_classes"),
            ("human_control", "categories"),
            ("human_control", "data_classes"),
        ),
    ),
)

_CHANGE_LABELS: Final[dict[tuple[str, str], str]] = {
    ("global", "network_egress"): "Data leaving this computer",
    ("global", "effective_scope"): "Policy applies to",
    ("global", "provider_data_use_evidence"): "Current provider data-use evidence",
    ("global", "credential_heuristic"): "Possible-credential filter",
    ("channel", "enabled"): "Channel",
    ("channel", "provider"): "Provider and model",
    ("channel", "fallback_provider"): "Fallback provider and model",
    ("channel", "purposes"): "Purposes",
    ("channel", "categories"): "Information allowed",
    ("channel", "data_classes"): "Sensitivity allowed",
    ("channel", "scope_ceiling"): "Authorization ceiling",
    ("channel", "preview_required"): "Confirmation",
    ("channel", "max_bytes"): "Maximum bytes per case",
    ("channel", "max_tokens"): "Maximum tokens per case",
    ("channel", "authorization_ttl_seconds"): "Authorization lifetime (seconds)",
    ("local_model", "enabled"): "Local model processing",
    ("local_model", "binding"): "Local model",
    ("local_model", "categories"): "Information the local model may receive",
    ("local_model", "data_classes"): "Sensitivity the local model may receive",
    ("agent_context", "categories"): "Information released to the agent host",
    ("agent_context", "data_classes"): "Sensitivity released to the agent host",
    ("human_control", "categories"): "Information shown on your own terminal",
    ("human_control", "data_classes"): "Sensitivity shown on your own terminal",
    ("review", "sections"): "Review sections built",
    ("review", "excerpt_kinds"): "Excerpt kinds built",
    ("review", "relevance"): "Selection reach",
    ("review", "include_finding_prose"): "Reviewer sees finding prose",
    ("review", "include_exact_command_text"): "Reviewer sees exact command text",
    ("review", "max_timeline_items"): "Maximum timeline items",
    ("review", "max_assessments"): "Maximum assessments",
    ("review", "max_change_observations"): "Maximum change observations",
    ("review", "max_excerpts"): "Maximum excerpts",
    ("review", "max_omissions"): "Maximum omissions",
    ("review", "max_excerpt_bytes"): "Maximum bytes per excerpt",
    ("review", "max_total_excerpt_bytes"): "Maximum excerpt bytes per case",
}

_CHANNEL_LABELS: Final[dict[str, str]] = {
    "llm_inference": "External model review",
    "product_telemetry": "Product telemetry",
    "crash_diagnostics": "Crash diagnostics",
    "update_checks": "Update checks",
    "capability_testing": "Capability testing",
}

_FLAG_WORDS: Final[dict[tuple[str, str], tuple[str, str]]] = {
    ("global", "network_egress"): ("Allowed", "Not allowed"),
    ("global", "provider_data_use_evidence"): ("Required", "Not required"),
    (
        "global",
        "credential_heuristic",
    ): (
        "On: values that look like passwords or tokens are withheld",
        "Off: only known credential shapes, private keys and URL passwords are withheld",
    ),
    ("channel", "enabled"): ("On", "Off"),
    ("channel", "preview_required"): ("Ask before every request", "No confirmation"),
    ("local_model", "enabled"): ("On", "Off"),
}


def _change_line_label(change: PrivacyPolicyChange) -> str:
    base = _CHANGE_LABELS[(change.area, change.field)]
    if change.subject is None:
        return base
    channel = _CHANNEL_LABELS.get(change.subject, change.subject)
    return channel if change.field == "enabled" else f"{base} ({channel})"


def _binding_text(labels: tuple[str, ...]) -> str:
    parts = {name: value for name, _, value in (item.partition(":") for item in labels)}
    provider = parts.get("provider")
    model = parts.get("model")
    if provider is None or model is None:
        return ", ".join(labels)
    detail = ", ".join(
        value for value in (parts.get("endpoint"), parts.get("transport")) if value is not None
    )
    return f"{provider} / {model}" + (f" ({detail})" if detail else "")


def _scope_text(labels: tuple[str, ...]) -> str:
    parts = {name: value for name, _, value in (item.partition(":") for item in labels)}
    kind = parts.get("kind")
    if kind is None:
        return ", ".join(labels)
    narrower = ", ".join(
        f"{name} {parts[name]}" for name in ("workspace", "task", "request") if name in parts
    )
    return f"{kind}" + (f" ({narrower})" if narrower else "")


def _change_value_text(change: PrivacyPolicyChange, value: PrivacyPolicyChangeValue) -> str:
    if value.kind == "none":
        return "Not applicable"
    if value.kind == "flag":
        yes, no = _FLAG_WORDS.get((change.area, change.field), ("Yes", "No"))
        return yes if value.flag else no
    if value.kind == "count":
        return str(value.count)
    if not value.labels:
        return "None"
    if change.field in {"provider", "fallback_provider", "binding"}:
        return _binding_text(value.labels)
    if change.field == "effective_scope":
        return _scope_text(value.labels)
    return ", ".join(value.labels)


def _privacy_policy_change_text(preview: PrivacyPolicyDecisionPreview) -> str:
    if preview.members:
        compound = len(preview.members) == 2
        lines = [
            "Action: decide repository privacy authority widening",
            f"Pending: {preview.pending_id}",
            "",
            (
                "This single approval changes the installation ceiling and repository grant shown"
                if compound
                else "This approval inserts the repository grant shown"
            ),
            "below. The repository identity was bound by the trusted session and is not printed.",
        ]
        for member in preview.members:
            if member.authority == "machine_ceiling":
                lines.extend(
                    (
                        "",
                        "Installation-wide ceiling (replace)",
                        "  This is the maximum permission any repository grant may use.",
                    )
                )
                _append_privacy_change_lines(lines, member.changes)
            elif member.authority == "repository_grant" and member.action == "insert":
                lines.extend(
                    (
                        "",
                        "Repository grant (insert)",
                        "  (!) Before: no repository grant; external model review is off.",
                        "  (!) After: insert a repository grant bounded by the installation ceiling.",
                    )
                )
                _append_privacy_change_lines(lines, member.changes)
            elif member.authority == "repository_grant" and member.action == "replace":
                lines.extend(
                    (
                        "",
                        "Repository grant (replace)",
                        "  This replaces the exact existing grant for this repository.",
                    )
                )
                _append_privacy_change_lines(lines, member.changes)
            else:
                raise HumanCeremonyCliError("preview_invalid")
        lines.extend(
            (
                "",
                "The digest below identifies the exact compound proposal bytes. It is integrity",
                "evidence, not a description of the change; the lines above are the change.",
                f"Diff digest: {preview.diff_digest}",
                "",
            )
        )
        return "\n".join(lines)

    widening = tuple(change for change in preview.changes if change.widens)
    lines = [
        "Action: decide privacy policy widening",
        f"Pending: {preview.pending_id}",
        "",
        "Privacy will become less restrictive.",
        f"{len(widening)} of {len(preview.changes)} changes below make it less restrictive; "
        "they are marked (!).",
    ]
    _append_privacy_change_lines(lines, preview.changes)
    lines.extend(
        (
            "",
            "The digest below identifies the exact proposal bytes. It is integrity evidence,",
            "not a description of the change; the lines above are the change.",
            f"Diff digest: {preview.diff_digest}",
            "",
        )
    )
    return "\n".join(lines)


def _task_statement_change_note(
    change: PrivacyPolicyChange, changes: tuple[PrivacyPolicyChange, ...] = ()
) -> str | None:
    """Plain words for adding or removing the ``task_statement`` review section (issue #908).

    An approval given for the agent's plan never covers the user's own words, so the ceremony
    names this content explicitly instead of leaving it to one token in a section list. A change
    to the excerpt count gets its own plain words too (issue #907 Phase 1b); ``changes`` is the
    whole screen, so the words never claim the byte limits stay when another row raises them.
    """

    if (change.area, change.field) == ("review", "max_excerpts"):
        if not change.widens:
            return (
                f"max_excerpts: at most {change.after.count} excerpts will be sent in one review."
                if change.after.kind == "count"
                else "max_excerpts: fewer excerpts will be sent in one review."
            )
        bytes_widen = any(
            other.area == "review"
            and other.field in {"max_excerpt_bytes", "max_total_excerpt_bytes"}
            and other.widens
            for other in changes
        )
        if bytes_widen:
            return (
                "max_excerpts: more excerpts may be sent in one review; each stays within the "
                "per-excerpt and total byte limits shown on this screen."
            )
        return (
            "max_excerpts: more excerpts may be sent in one review; each stays within the "
            "per-excerpt and total byte limits, which this change does not raise."
        )
    if (change.area, change.field) != ("review", "sections"):
        return None
    before = "task_statement" in change.before.labels
    after = "task_statement" in change.after.labels
    if after and not before:
        return (
            "task_statement: the agent's transcription of the user's request (or the task "
            "title when none was supplied) will be sent to the reviewer. The host-captured "
            "user prompt is not used."
        )
    if before and not after:
        return (
            "task_statement: the agent's transcription of the user's request will stop being "
            "sent; it stays in the local task record."
        )
    return None


def _append_privacy_change_lines(
    lines: list[str], changes: tuple[PrivacyPolicyChange, ...]
) -> None:
    placed: set[tuple[str, str, str]] = set()
    for heading, members in _CHANGE_GROUPS:
        allowed = set(members)
        rows = [change for change in changes if (change.area, change.field) in allowed]
        if not rows:
            continue
        lines.extend(("", heading))
        for change in rows:
            placed.add(change.identity)
            marker = "(!)" if change.widens else "   "
            before = _change_value_text(change, change.before)
            after = _change_value_text(change, change.after)
            lines.append(f"  {marker} {_change_line_label(change)}: {before}{_ARROW}{after}")
            note = _task_statement_change_note(change, changes)
            if note is not None:
                lines.append(f"      {note}")
    if len(placed) != len(changes):
        # A field the service is allowed to send but this screen has no group for would be
        # silently dropped, which is the exact defect this renderer exists to close.
        raise HumanCeremonyCliError("preview_invalid")


def _render_preview(terminal: _CeremonyTerminal, preview: HumanPreview) -> None:
    terminal.write("FinishUP trusted foreground ceremony\n")
    if type(preview) is VaultInitializePreview:
        terminal.write("Action: initialize passphrase vault (irreversible mode selection)\n")
    elif type(preview) is VaultPassphraseRotatePreview:
        terminal.write("Action: rotate passphrase vault credentials\n")
    elif type(preview) is VaultUnlockPreview:
        terminal.write("Action: unlock passphrase vault\n")
    elif type(preview) is KeyringRetryPreview:
        terminal.write(f"Action: retry OS keyring ({preview.operation})\n")
    elif type(preview) is PortableRecoveryPreview:
        terminal.write(
            f"Action: portable recovery {preview.operation}\n"
            f"Request: {preview.request_id}\n"
            f"Plan digest: {preview.confirmed_plan_digest}\n"
            f"Location commitment: {preview.location_commitment}\n"
            f"Content commitment: {preview.content_commitment}\n"
            f"Items: {preview.item_count}; bytes: {preview.total_bytes}\n"
        )
    elif type(preview) is InstallationRecoveryPreview:
        terminal.write(
            f"Action: installation recovery {preview.operation}\n"
            f"Request: {preview.request_id}\n"
            f"Plan digest: {preview.confirmed_plan_digest}\n"
            f"Generation: {preview.recovery_generation}\n"
            f"Set: {preview.set_mode}; secret: {preview.secret_kind}\n"
            f"Target envelope: {preview.target_envelope}\n"
            f"Destination: "
            f"{'create-only local .yirs file; path stays in this helper' if preview.operation in {'provision', 'rotate'} else 'no export'}\n"
            f"Items: {preview.item_count}; bytes: {preview.total_bytes}\n"
        )
    elif type(preview) in {ProviderCredentialSetPreview, ProviderCredentialRotatePreview}:
        provider = cast(ProviderCredentialSetPreview | ProviderCredentialRotatePreview, preview)
        terminal.write(
            f"Action: provider credential {provider.target.action}\n"
            f"Provider: {provider.target.provider_id}\n"
            f"Model: {provider.target.model_id}\n"
            f"Endpoint profile: {provider.target.endpoint_profile_id}@"
            f"{provider.target.endpoint_profile_version}\n"
            f"Purpose: {provider.target.purpose}\n"
            f"Scope digest: {provider.target.scope_digest}\n"
        )
    elif type(preview) is PrivacyPolicyDecisionPreview:
        terminal.write(_privacy_policy_change_text(preview))
    elif type(preview) is PrivacyDisclosureDecisionPreview:
        terminal.write(
            f"Action: decide one disclosure (authorization change: none)\n"
            f"Pending: {preview.pending_id}\nCategory: {preview.category}\n"
            f"Destination commitment: {preview.destination_commitment}\n"
            f"Bytes: {preview.byte_count}; tokens: {preview.token_count}\n"
            f"Excerpt digest: {preview.excerpt_digest}\n"
            f"Preview:\n{preview.excerpt_preview}\n"
        )
    elif type(preview) is IdleRelockPolicyChangePreview:
        terminal.write(
            f"Action: change idle relock for service generation {preview.service_generation}\n"
            f"Current: {preview.current}; proposed: {preview.proposed}\n"
            "Restart restores the 3600-second default. Explicit lock, session lock, suspend, "
            "and monitor loss still relock the service.\n"
        )
    elif type(preview) is OwnerReceiptViewPreview:
        terminal.write(
            "Action: show you the full receipt, including repository file names your agents "
            "do not see\n"
            f"Task: {preview.task_id}\n"
            f"Format: {preview.format}; profile: {preview.redaction_profile}\n"
            f"Scope: this one receipt request, on this command's own connection, once, within "
            f"{preview.grant_seconds} seconds. No policy or standing access changes.\n"
        )
    else:
        raise HumanCeremonyCliError("preview_invalid")


def _validate_secret(source: bytearray, purpose: ConfidentialSecretPurpose) -> None:
    view = memoryview(source)
    try:
        if purpose is ConfidentialSecretPurpose.PROVIDER_CREDENTIAL:
            validate_provider_credential_buffer(view)
        else:
            validate_passphrase_buffer(view)
    except ConfidentialProtocolError as exc:
        raise HumanCeremonyCliError("input_invalid") from exc
    finally:
        view.release()


def _needs_confirmation(
    kind: HumanCeremonyKind,
    target: HumanOpenTarget,
    purpose: ConfidentialSecretPurpose,
) -> bool:
    return (
        purpose
        in {
            ConfidentialSecretPurpose.VAULT_INITIALIZE,
            ConfidentialSecretPurpose.VAULT_REWRAP,
        }
        or (
            kind is HumanCeremonyKind.PORTABLE_RECOVERY
            and type(target) is PortableRecoveryTarget
            and target.operation == "create"
        )
        or (
            kind is HumanCeremonyKind.INSTALLATION_RECOVERY
            and type(target) is InstallationRecoveryTarget
            and target.operation in {"provision", "rotate", "revoke"}
            and target.secret_kind == "argon2id_passphrase"
        )
    )


def _passphrase_prompt(stem: str) -> str:
    """Prompt stem plus the shared length/control-character contract suffix."""

    return f"{stem}{_PASSPHRASE_PROMPT_SUFFIX}"


def _raise_for_rotation_stage_error(exc: Exception) -> None:
    """Map a staged-keyring write failure without calling the user's input invalid.

    Missing or unsupported backends cannot hold a stage; other keyring failures are
    ceremony-result problems, not a malformed passphrase.
    """

    from finishup.adapters.keys.os_keyring import OSKeyringError

    if type(exc) is not OSKeyringError:
        raise HumanCeremonyCliError("result_invalid") from exc
    if exc.reason in _IGNORABLE_ROTATION_STAGE_REASONS:
        return
    raise HumanCeremonyCliError("result_invalid") from exc


def _read_secret(
    terminal: _CeremonyTerminal,
    kind: HumanCeremonyKind,
    target: HumanOpenTarget,
    purpose: ConfidentialSecretPurpose,
) -> bytearray:
    maximum = 8_192 if purpose is ConfidentialSecretPurpose.PROVIDER_CREDENTIAL else 1_024
    is_passphrase = purpose is not ConfidentialSecretPurpose.PROVIDER_CREDENTIAL
    label = (
        "Provider credential: "
        if purpose is ConfidentialSecretPurpose.PROVIDER_CREDENTIAL
        else _passphrase_prompt(
            "Recovery code or passphrase"
            if purpose is ConfidentialSecretPurpose.INSTALLATION_RECOVERY
            else "New vault passphrase"
            if purpose is ConfidentialSecretPurpose.VAULT_REWRAP
            else "Passphrase"
        )
    )
    while True:
        first = terminal.read_secret(label, maximum)
        accepted = False
        try:
            try:
                _validate_secret(first, purpose)
            except HumanCeremonyCliError:
                if not is_passphrase:
                    raise
                terminal.write(
                    "Passphrase must be 16-1024 UTF-8 bytes with no control characters. "
                    "Try again.\n"
                )
                continue
            if not _needs_confirmation(kind, target, purpose):
                accepted = True
                return first
            confirmation = terminal.read_secret(
                _passphrase_prompt(
                    "Confirm recovery passphrase"
                    if purpose is ConfidentialSecretPurpose.INSTALLATION_RECOVERY
                    else "Confirm passphrase"
                ),
                maximum,
            )
            try:
                try:
                    _validate_secret(confirmation, purpose)
                except HumanCeremonyCliError:
                    terminal.write(
                        "Passphrase must be 16-1024 UTF-8 bytes with no control characters. "
                        "Try again.\n"
                    )
                    continue
                if not hmac.compare_digest(first, confirmation):
                    terminal.write("Passphrases did not match. Try again.\n")
                    continue
                accepted = True
                return first
            finally:
                overwrite_secret_buffer(confirmation)
        finally:
            if not accepted:
                overwrite_secret_buffer(first)


async def _send_secret(
    session: HumanControlSession,
    phase: SecretRequiredPhase,
    source: bytearray,
) -> None:
    try:
        secret_client = session._secret_client()  # pyright: ignore[reportPrivateUsage]
        token = session._session_token()  # pyright: ignore[reportPrivateUsage]
        await secret_client.send_once(phase.binding, source, token)
    finally:
        overwrite_secret_buffer(source)


def _expected_result_type(kind: HumanCeremonyKind) -> type[HumanResult]:
    if kind in {
        HumanCeremonyKind.VAULT_INITIALIZE,
        HumanCeremonyKind.VAULT_PASSPHRASE_ROTATE,
        HumanCeremonyKind.VAULT_UNLOCK,
    }:
        return VaultStateResult
    if kind is HumanCeremonyKind.KEYRING_RETRY:
        return KeyringRetryResult
    if kind is HumanCeremonyKind.PORTABLE_RECOVERY:
        return PortableRecoveryResult
    if kind is HumanCeremonyKind.INSTALLATION_RECOVERY:
        return InstallationRecoveryResult
    if kind in {
        HumanCeremonyKind.PROVIDER_CREDENTIAL_SET,
        HumanCeremonyKind.PROVIDER_CREDENTIAL_ROTATE,
    }:
        return ProviderCredentialResult
    if kind in {
        HumanCeremonyKind.PRIVACY_POLICY_DECISION,
        HumanCeremonyKind.PRIVACY_DISCLOSURE_DECISION,
    }:
        return PrivacyDecisionResult
    if kind is HumanCeremonyKind.OWNER_RECEIPT_VIEW:
        return OwnerReceiptViewResult
    return IdleRelockPolicyResult


async def _cancel_quietly(session: HumanControlSession) -> None:
    try:
        await session.cancel()
    except ConfidentialClientError, OSError, RuntimeError:
        pass


async def _drive_session(
    session: HumanControlSession,
    terminal: _CeremonyTerminal,
    kind: HumanCeremonyKind,
    target: HumanOpenTarget,
    current: HumanPhase | HumanResult,
    provider_credential: bytearray | None = None,
    passphrase: bytearray | None = None,
    provider_reauthentication: bytearray | None = None,
    installation_recovery_secret: bytearray | None = None,
    vault_rewrap_secret: bytearray | None = None,
    authorization: _AuthorizationChoice | None = None,
) -> tuple[HumanResult, Literal["approve", "deny"] | None]:
    decision: Literal["approve", "deny"] | None = None
    rotation_store: _RotationStore | None = None
    rotation_staged = False
    for _ in range(8):
        if type(current) is _expected_result_type(kind):
            if rotation_staged:
                assert rotation_store is not None
                rotation_store.promote_staged_rotation()
            return cast(HumanResult, current), decision
        if type(current) is SecretRequiredPhase:
            purpose = current.binding.purpose
            supplied: bytearray | None = None
            if purpose is ConfidentialSecretPurpose.PROVIDER_CREDENTIAL:
                supplied = provider_credential
            elif purpose in {
                ConfidentialSecretPurpose.VAULT_INITIALIZE,
                ConfidentialSecretPurpose.VAULT_UNLOCK,
            }:
                supplied = passphrase
            elif purpose is ConfidentialSecretPurpose.INSTALLATION_RECOVERY:
                supplied = installation_recovery_secret
            elif purpose is ConfidentialSecretPurpose.VAULT_REWRAP:
                supplied = vault_rewrap_secret
            elif purpose in {
                ConfidentialSecretPurpose.PROVIDER_REAUTHENTICATION,
                ConfidentialSecretPurpose.PRIVACY_REAUTHENTICATION,
                ConfidentialSecretPurpose.SECURITY_REAUTHENTICATION,
            }:
                # Privacy/security widen ceremonies re-auth with the vault passphrase.
                supplied = (
                    provider_reauthentication
                    if purpose is ConfidentialSecretPurpose.PROVIDER_REAUTHENTICATION
                    else passphrase
                )
                if (
                    supplied is None
                    and purpose is ConfidentialSecretPurpose.SECURITY_REAUTHENTICATION
                    and type(target) is InstallationRecoveryTarget
                ):
                    supplied = _load_scoped_auto_unlock_passphrase()
            if supplied is not None:
                _validate_secret(supplied, purpose)
                secret_buffer = supplied
            elif (
                purpose is ConfidentialSecretPurpose.INSTALLATION_RECOVERY
                and type(target) is InstallationRecoveryTarget
                and target.operation in {"provision", "rotate", "revoke"}
                and target.secret_kind == "generated_code"
            ):
                from finishup.adapters.keys.installation_recovery import generate_recovery_code

                secret_buffer = generate_recovery_code()
                terminal.write(
                    "Write down this recovery code now. It is displayed once and is not copied "
                    "to the clipboard:\n"
                )
                terminal.write_secret(secret_buffer)
                terminal.write("\n")
            else:
                secret_buffer = _read_secret(terminal, kind, target, purpose)
            if (
                kind is HumanCeremonyKind.VAULT_PASSPHRASE_ROTATE
                and purpose is ConfidentialSecretPurpose.VAULT_REWRAP
                and supplied is None
            ):
                # Persist the exact user-selected replacement before the envelope switches.
                # If the ceremony becomes ambiguous, daemon restart tries active and staged
                # candidates and reconciles the one that authenticates the envelope.
                from finishup.adapters.keys.os_keyring import (
                    AutoUnlockPassphraseStore,
                    OSKeyringError,
                )
                from finishup.config.load import load_config
                from finishup.config.paths import bundle_root

                config = load_config({}, os.environ, None)
                store = AutoUnlockPassphraseStore(bundle_root(_data_dir=config.storage.data_dir))
                try:
                    store.stage_value_for_rotation(secret_buffer)
                except OSKeyringError as exc:
                    _raise_for_rotation_stage_error(exc)
                else:
                    rotation_store = store
                    rotation_staged = True
            await _send_secret(session, current, secret_buffer)
        elif type(current) is AuthorizationRequiredPhase:
            authorization_source: Literal["os_user_presence", "secret_reauthentication"]
            if authorization is not None:
                authorization.offered = tuple(current.available_sources)
            if (
                provider_reauthentication is not None or passphrase is not None
            ) and "secret_reauthentication" in current.available_sources:
                authorization_source = "secret_reauthentication"
            elif authorization is not None and authorization.passphrase_only:
                if "secret_reauthentication" not in current.available_sources:
                    raise HumanCeremonyCliError("passphrase_unavailable")
                authorization_source = "secret_reauthentication"
            elif authorization is not None and authorization.prefer in current.available_sources:
                authorization_source = authorization.prefer
            elif "os_user_presence" in current.available_sources:
                authorization_source = "os_user_presence"
            elif "secret_reauthentication" in current.available_sources:
                authorization_source = "secret_reauthentication"
            else:
                raise HumanCeremonyCliError("preview_invalid")
            if (
                authorization is not None
                and authorization_source == "secret_reauthentication"
                and not authorization.passphrase_only
                and authorization.passphrase_allowed is not None
                and not authorization.passphrase_allowed()
            ):
                # Never ask for a passphrase the owner may never have been shown.
                raise HumanCeremonyCliError("passphrase_in_credential_store")
            if authorization is not None:
                authorization.selected = authorization_source
            terminal.write(f"Authorization: {authorization_source}\n")
            if (
                authorization is not None
                and authorization.after_unavailable_dialog
                and authorization_source == "secret_reauthentication"
            ):
                terminal.write(
                    "No system confirmation dialog can be shown from here, so confirm with your "
                    "vault passphrase instead.\n"
                )
            if authorization_source == "os_user_presence":
                # The service, not this process, runs the check; the dialog shows the same code.
                code = presence_confirmation_code(session.opened.binding.target_digest)
                terminal.write(
                    "Confirm it is you in the system dialog (Touch ID or your login password). "
                    f"It shows confirmation code {code}; cancel it if the code differs.\n"
                )
            await session.send_action(SelectAuthorizationSourceAction(authorization_source))
        elif type(current) is KeyringRetryPhase:
            await session.send_action(RetryAction())
        elif type(current) is DecisionRequiredPhase:
            selected = terminal.read_choice(
                "Decision [approve/deny]: ",
                (b"approve", b"deny"),
            )
            decision = "approve" if selected == b"approve" else "deny"
            await session.send_action(DecisionAction(decision))
        else:
            raise HumanCeremonyCliError("result_invalid")
        current = await session.wait_phase_or_result()
    raise HumanCeremonyCliError("result_invalid")


async def _complete_human_ceremony(
    client: HumanControlClient,
    terminal: _CeremonyTerminal,
    kind: HumanCeremonyKind,
    target: HumanOpenTarget,
    provider_credential: bytearray | None,
    passphrase: bytearray | None,
    provider_reauthentication: bytearray | None,
    installation_recovery_secret: bytearray | None,
    vault_rewrap_secret: bytearray | None,
    authorization: _AuthorizationChoice | None = None,
) -> HumanResult:
    session = await client.open(kind, target)
    async with session:
        try:
            preview = _verify_preview(kind, target, session)
            _render_preview(terminal, preview)
            result, _decision = await _drive_session(
                session,
                terminal,
                kind,
                target,
                session.opened.phase,
                provider_credential,
                passphrase,
                provider_reauthentication,
                installation_recovery_secret,
                vault_rewrap_secret,
                authorization,
            )
            return result
        except BaseException:
            await _cancel_quietly(session)
            raise


def _validate_supplied_secrets(
    kind: HumanCeremonyKind,
    provider_credential: bytearray | None,
    passphrase: bytearray | None,
    provider_reauthentication: bytearray | None,
    installation_recovery_secret: bytearray | None,
    vault_rewrap_secret: bytearray | None,
) -> tuple[bool, bool, bool, bool]:
    if type(kind) is not HumanCeremonyKind:
        raise TypeError("human_ceremony_kind_invalid")
    provider_kind = kind in {
        HumanCeremonyKind.PROVIDER_CREDENTIAL_SET,
        HumanCeremonyKind.PROVIDER_CREDENTIAL_ROTATE,
    }
    passphrase_kind = kind in {
        HumanCeremonyKind.VAULT_INITIALIZE,
        HumanCeremonyKind.VAULT_UNLOCK,
    }
    passphrase_rotation_kind = kind is HumanCeremonyKind.VAULT_PASSPHRASE_ROTATE
    recovery_kind = kind is HumanCeremonyKind.INSTALLATION_RECOVERY
    if (
        (provider_credential is not None and not provider_kind)
        or (provider_reauthentication is not None and not provider_kind)
        or (passphrase is not None and not (passphrase_kind or passphrase_rotation_kind))
        or (installation_recovery_secret is not None and not recovery_kind)
        or (vault_rewrap_secret is not None and not (recovery_kind or passphrase_rotation_kind))
    ):
        for supplied in (
            provider_credential,
            passphrase,
            provider_reauthentication,
            installation_recovery_secret,
            vault_rewrap_secret,
        ):
            if supplied is not None:
                overwrite_secret_buffer(supplied)
        raise ValueError("provider_credential_target_invalid")
    return provider_kind, passphrase_kind, recovery_kind, passphrase_rotation_kind


async def run_human_ceremony(
    kind: HumanCeremonyKind,
    target: HumanOpenTarget,
    provider_credential: bytearray | None = None,
    passphrase: bytearray | None = None,
    provider_reauthentication: bytearray | None = None,
    installation_recovery_secret: bytearray | None = None,
    vault_rewrap_secret: bytearray | None = None,
    *,
    authorization: _AuthorizationChoice | None = None,
) -> HumanResult:
    """Run one exact foreground YZH1/YZS1 ceremony and return structural state only."""

    provider_kind, passphrase_kind, recovery_kind, passphrase_rotation_kind = (
        _validate_supplied_secrets(
            kind,
            provider_credential,
            passphrase,
            provider_reauthentication,
            installation_recovery_secret,
            vault_rewrap_secret,
        )
    )
    fully_supplied = (
        (passphrase_kind and passphrase is not None)
        or (passphrase_rotation_kind and passphrase is not None and vault_rewrap_secret is not None)
        or (
            recovery_kind
            and type(target) is InstallationRecoveryTarget
            and (
                target.operation == "provision"
                and installation_recovery_secret is not None
                or target.operation in {"rotate", "restore"}
                and installation_recovery_secret is not None
                and vault_rewrap_secret is not None
                or target.operation == "revoke"
                and vault_rewrap_secret is not None
            )
        )
        or (
            provider_kind
            and provider_credential is not None
            and provider_reauthentication is not None
        )
    )
    client = HumanControlClient()

    try:
        if fully_supplied:
            return await _complete_human_ceremony(
                client,
                _SuppliedSecretTerminal(),
                kind,
                target,
                provider_credential,
                passphrase,
                provider_reauthentication,
                installation_recovery_secret,
                vault_rewrap_secret,
            )
        with _ForegroundTerminal() as terminal:
            return await _complete_human_ceremony(
                client,
                terminal,
                kind,
                target,
                provider_credential,
                passphrase,
                provider_reauthentication,
                installation_recovery_secret,
                vault_rewrap_secret,
                authorization,
            )
    finally:
        await client.close()
        for supplied in (
            provider_credential,
            passphrase,
            provider_reauthentication,
            installation_recovery_secret,
            vault_rewrap_secret,
        ):
            if supplied is not None:
                overwrite_secret_buffer(supplied)


async def run_human_ceremony_on_terminal(
    terminal: _CeremonyTerminal,
    kind: HumanCeremonyKind,
    target: HumanOpenTarget,
    *,
    provider_credential: bytearray | None = None,
    passphrase: bytearray | None = None,
    provider_reauthentication: bytearray | None = None,
    installation_recovery_secret: bytearray | None = None,
    vault_rewrap_secret: bytearray | None = None,
) -> HumanResult:
    """Run a ceremony on an already verified console owned by the trusted helper."""

    _validate_supplied_secrets(
        kind,
        provider_credential,
        passphrase,
        provider_reauthentication,
        installation_recovery_secret,
        vault_rewrap_secret,
    )
    client = HumanControlClient()
    try:
        return await _complete_human_ceremony(
            client,
            terminal,
            kind,
            target,
            provider_credential,
            passphrase,
            provider_reauthentication,
            installation_recovery_secret,
            vault_rewrap_secret,
        )
    finally:
        await client.close()
        for supplied in (
            provider_credential,
            passphrase,
            provider_reauthentication,
            installation_recovery_secret,
            vault_rewrap_secret,
        ):
            if supplied is not None:
                overwrite_secret_buffer(supplied)


async def initialize_passphrase_vault(passphrase: bytearray | None = None) -> VaultStateResult:
    result = await run_human_ceremony(
        HumanCeremonyKind.VAULT_INITIALIZE,
        EmptyVaultTarget(expected_mode="uninitialized"),
        passphrase=passphrase,
    )
    return cast(VaultStateResult, result)


async def rotate_vault_passphrase(
    passphrase: bytearray | None = None,
    replacement: bytearray | None = None,
) -> VaultStateResult:
    """Reauthenticate and atomically rewrap the vault under a new passphrase."""

    result = await run_human_ceremony(
        HumanCeremonyKind.VAULT_PASSPHRASE_ROTATE,
        EmptyVaultTarget(expected_mode="passphrase"),
        passphrase=passphrase,
        vault_rewrap_secret=replacement,
    )
    return cast(VaultStateResult, result)


def _load_scoped_auto_unlock_passphrase() -> bytearray | None:
    """Load the bundle-scoped platform entry when present; never invent a secret."""

    import os

    from finishup.adapters.keys.os_keyring import AutoUnlockPassphraseStore
    from finishup.config.load import load_config
    from finishup.config.paths import bundle_root

    try:
        config = load_config({}, os.environ, None)
        return AutoUnlockPassphraseStore(bundle_root(_data_dir=config.storage.data_dir)).load()
    except Exception:
        # Convenience path must never block the interactive unlock ceremony.
        return None


def load_auto_unlock_reauthentication() -> bytearray | None:
    """Load the scoped auto-unlock secret for one provider ceremony, or None when absent.

    A Keychain-provisioned passphrase vault is ready without the human ever learning its
    generated passphrase. Supplying it as the reauthentication factor keeps the credential
    ceremony asking only for the provider key.
    """

    return _load_scoped_auto_unlock_passphrase()


async def _service_reports_unusable_auto_unlock() -> bool:
    """True when the daemon already knows the scoped entry cannot unlock this vault."""

    try:
        from finishup.ports.control import ControlClientKind
        from finishup.service.client import connect_service

        client = await connect_service(ControlClientKind.CLI)
        try:
            status = await client.service_status()
        finally:
            await client.close()
    except Exception:
        return False
    reason = getattr(status, "state_reason", None)
    return reason in {"auto_unlock_stale", "auto_unlock_rejected"}


async def unlock_vault(passphrase: bytearray | None = None) -> VaultStateResult:
    """Unlock the passphrase vault, preferring the scoped platform entry when available.

    Setup often provisions a generated passphrase the human never types. When that entry
    is present, submit it through the ordinary confidential ceremony with no TTY prompt.
    Only fall back to interactive entry when no usable entry exists or silent unlock fails.
    """

    target = EmptyVaultTarget(expected_mode="passphrase")
    if passphrase is not None:
        result = await run_human_ceremony(
            HumanCeremonyKind.VAULT_UNLOCK,
            target,
            passphrase=passphrase,
        )
        return cast(VaultStateResult, result)
    if not await _service_reports_unusable_auto_unlock():
        stored = _load_scoped_auto_unlock_passphrase()
        if stored is not None:
            try:
                result = cast(
                    VaultStateResult,
                    await run_human_ceremony(
                        HumanCeremonyKind.VAULT_UNLOCK,
                        target,
                        passphrase=stored,
                    ),
                )
                if getattr(result, "state", None) == "ready":
                    return result
            except HumanCeremonyCliError:
                pass
    result = await run_human_ceremony(HumanCeremonyKind.VAULT_UNLOCK, target)
    return cast(VaultStateResult, result)


def read_vault_passphrase_for_auto_unlock() -> bytearray:
    """Read one existing vault passphrase from the foreground TTY for a repair ceremony."""

    with _ForegroundTerminal() as terminal:
        return _read_secret(
            terminal,
            HumanCeremonyKind.VAULT_UNLOCK,
            EmptyVaultTarget(expected_mode="passphrase"),
            ConfidentialSecretPurpose.VAULT_UNLOCK,
        )


async def retry_keyring(
    expected_mode: Literal["uninitialized", "os_keyring"] = "os_keyring",
) -> KeyringRetryResult:
    result = await run_human_ceremony(
        HumanCeremonyKind.KEYRING_RETRY,
        EmptyVaultTarget(expected_mode=expected_mode),
    )
    return cast(KeyringRetryResult, result)


async def portable_recovery(target: PortableRecoveryTarget) -> PortableRecoveryResult:
    result = await run_human_ceremony(HumanCeremonyKind.PORTABLE_RECOVERY, target)
    return cast(PortableRecoveryResult, result)


async def provision_installation_recovery(
    target: InstallationRecoveryTarget,
) -> InstallationRecoveryResult:
    """Provision one set without ever accepting the recovery secret from argv or stdio."""

    if target.operation not in {"provision", "rotate"}:
        raise ValueError("installation_recovery_target_invalid")
    with _ForegroundTerminal() as terminal:
        destination = terminal.read_path("Recovery-set destination (.yirs): ")
        if destination.exists():
            raise HumanCeremonyCliError("input_invalid")
        result = await run_human_ceremony_on_terminal(
            terminal,
            HumanCeremonyKind.INSTALLATION_RECOVERY,
            target,
        )
        from finishup.config.load import load_config
        from finishup.config.paths import bundle_root
        from finishup.service.installation_recovery import InstallationRecoverySetStore

        config = load_config({}, os.environ, None)
        try:
            InstallationRecoverySetStore(
                bundle_root(_data_dir=config.storage.data_dir)
            ).export_generation(target.recovery_generation, destination)
        except BaseException:
            terminal.write(
                "The recovery generation is retained, but export did not complete. "
                "Run 'finishup service recovery export' and choose a new destination.\n"
            )
            raise
        terminal.write("Recovery set exported. Keep it separate from the recovery secret.\n")
    return cast(InstallationRecoveryResult, result)


async def export_installation_recovery_set(
    recovery_generation: int,
) -> InstallationRecoveryImportResult:
    """Export the active encrypted set through a create-only trusted-console path."""

    from finishup.config.load import load_config
    from finishup.config.paths import bundle_root
    from finishup.service.installation_recovery import InstallationRecoverySetStore

    with _ForegroundTerminal() as terminal:
        destination = terminal.read_path("Recovery-set destination (.yirs): ")
        if destination.exists():
            raise HumanCeremonyCliError("input_invalid")
        config = load_config({}, os.environ, None)
        store = InstallationRecoverySetStore(bundle_root(_data_dir=config.storage.data_dir))
        metadata = store.metadata(recovery_generation)
        store.export_generation(recovery_generation, destination)
        terminal.write("Recovery set exported. Keep it separate from the recovery secret.\n")
    return InstallationRecoveryImportResult(
        "exported",
        metadata.recovery_generation,
        metadata.mode.value,
        "finishup service recovery status",
    )


async def revoke_installation_recovery(
    target: InstallationRecoveryTarget,
) -> InstallationRecoveryResult:
    if target.operation != "revoke":
        raise ValueError("installation_recovery_target_invalid")
    result = await run_human_ceremony(HumanCeremonyKind.INSTALLATION_RECOVERY, target)
    return cast(InstallationRecoveryResult, result)


async def import_installation_recovery_set() -> InstallationRecoveryImportResult:
    """Import one set selected locally while holding the daemon's singleton exclusion."""

    from finishup.config.load import load_config
    from finishup.config.paths import bundle_root, state_dir
    from finishup.service.installation_recovery import (
        InstallationRecoverySetStore,
        OfflineInstallationRecoveryLease,
    )

    with _ForegroundTerminal() as terminal:
        source = terminal.read_path("Recovery-set archive (.yirs): ")
        config = load_config({}, os.environ, None)
        with OfflineInstallationRecoveryLease(state_dir() / "service.lock"):
            metadata = InstallationRecoverySetStore(
                bundle_root(_data_dir=config.storage.data_dir)
            ).import_archive(source)
        terminal.write(
            f"Recovery set generation {metadata.recovery_generation} imported and staged. "
            "It is not active yet: the archive is unauthenticated until the restore ceremony "
            "opens it with your recovery secret, so any generation already in force is "
            "untouched.\nRun 'finishup service recovery restore'.\n"
        )
    return InstallationRecoveryImportResult(
        "imported",
        metadata.recovery_generation,
        metadata.mode.value,
        "finishup service recovery restore",
    )


async def restore_installation_recovery(
    target: InstallationRecoveryTarget,
) -> InstallationRecoveryResult | InstallationRecoveryImportResult:
    """Restore through the trusted terminal; both secrets stay on confidential ingress.

    Installing a snapshot into a pristine profile is an *offline* step: it holds the daemon's
    singleton exclusion, so it can only run while the service is stopped.  The ceremony that
    follows needs a running daemon, and this helper never starts one.  The two phases are
    therefore two invocations of the same command rather than one that opens a socket nobody is
    listening on.  The second invocation finds the installed marker and goes straight to the
    ceremony, so resuming is just running `finishup service recovery restore` again.
    """

    if target.operation != "restore":
        raise ValueError("installation_recovery_target_invalid")
    from finishup.config.load import load_config
    from finishup.config.paths import bundle_root, state_dir
    from finishup.service.installation_recovery import (
        InstallationRecoverySetStore,
        OfflineInstallationRecoveryLease,
    )

    config = load_config({}, os.environ, None)
    bundle = bundle_root(_data_dir=config.storage.data_dir)
    if not (bundle / "installation-state.json").exists():
        if target.set_mode != "self_contained":
            raise HumanCeremonyCliError("input_invalid")
        with OfflineInstallationRecoveryLease(state_dir() / "service.lock"):
            InstallationRecoverySetStore(bundle).install_snapshot_into_pristine(
                target.recovery_generation
            )
        with _ForegroundTerminal() as terminal:
            terminal.write(
                "Encrypted state installed. It is still locked, and the imported set is not "
                "active yet.\nStart the service with 'finishup service run', then run "
                "'finishup service recovery restore' again to enter the recovery secret and a new "
                "vault passphrase.\n"
            )
        return InstallationRecoveryImportResult(
            "snapshot_installed",
            target.recovery_generation,
            target.set_mode,
            "finishup service run",
        )
    result = await run_human_ceremony(HumanCeremonyKind.INSTALLATION_RECOVERY, target)
    return cast(InstallationRecoveryResult, result)


async def set_provider_credential(
    target: ProviderCredentialTarget,
    provider_credential: bytearray | None = None,
    provider_reauthentication: bytearray | None = None,
) -> ProviderCredentialResult:
    if target.action != "set":
        raise ValueError("provider_credential_target_invalid")
    result = await run_human_ceremony(
        HumanCeremonyKind.PROVIDER_CREDENTIAL_SET,
        target,
        provider_credential,
        provider_reauthentication=provider_reauthentication,
    )
    return cast(ProviderCredentialResult, result)


async def rotate_provider_credential(
    target: ProviderCredentialTarget,
    provider_credential: bytearray | None = None,
    provider_reauthentication: bytearray | None = None,
) -> ProviderCredentialResult:
    if target.action != "rotate":
        raise ValueError("provider_credential_target_invalid")
    result = await run_human_ceremony(
        HumanCeremonyKind.PROVIDER_CREDENTIAL_ROTATE,
        target,
        provider_credential,
        provider_reauthentication=provider_reauthentication,
    )
    return cast(ProviderCredentialResult, result)


def _idle_cli_value(value: Literal["disabled"] | int) -> IdleRelockCliPolicyValue:
    if value == "disabled":
        return DisabledIdleRelockCliPolicyValue()
    return FiniteIdleRelockCliPolicyValue(value)


async def change_idle_relock_policy(
    target: int | Literal["disabled"],
) -> IdleRelockCliResult:
    if target == "disabled":
        wire_target = IdleRelockPolicyTarget("disable")
    elif type(target) is int and 60 <= target <= 86_400:
        wire_target = IdleRelockPolicyTarget("set", target)
    else:
        raise ValueError("idle_relock_cli_target_invalid")

    client = HumanControlClient()
    with _ForegroundTerminal() as terminal:
        try:
            session = await client.open(HumanCeremonyKind.IDLE_RELOCK_POLICY_CHANGE, wire_target)
            async with session:
                try:
                    preview = _verify_preview(
                        HumanCeremonyKind.IDLE_RELOCK_POLICY_CHANGE,
                        wire_target,
                        session,
                    )
                    _render_preview(terminal, preview)
                    expected_generation = session.opened.binding.service_generation
                    result, decision = await _drive_session(
                        session,
                        terminal,
                        HumanCeremonyKind.IDLE_RELOCK_POLICY_CHANGE,
                        wire_target,
                        session.opened.phase,
                    )
                except BaseException:
                    await _cancel_quietly(session)
                    raise
        finally:
            await client.close()
    typed = cast(IdleRelockPolicyResult, result)
    if decision not in {"approve", "deny"}:
        raise HumanCeremonyCliError("result_invalid")
    proposed: Literal["disabled"] | int = target
    if (
        typed.service_generation != expected_generation
        or (decision == "approve" and typed.effective != proposed)
        or (decision == "deny" and typed.effective != typed.previous)
    ):
        raise HumanCeremonyCliError("result_invalid")
    return IdleRelockCliResult(
        outcome="applied" if decision == "approve" else "denied",
        previous=_idle_cli_value(typed.previous),
        effective=_idle_cli_value(typed.effective),
        scope=typed.scope,
        service_generation=typed.service_generation,
    )


def _owner_view_target_digest(target: OwnerReceiptViewTarget) -> str:
    from finishup.service.owner_view import owner_receipt_view_target_digest

    return owner_receipt_view_target_digest(target)


def owner_view_confirmation_code(target: OwnerReceiptViewTarget) -> str:
    """The code a system dialog for exactly this request shows, derived on this side."""

    return presence_confirmation_code(_owner_view_target_digest(target))


def vault_passphrase_held_by_credential_store() -> bool:
    """True unless this installation's vault passphrase is known not to be in the credential store.

    Setup's system-keychain choice generates that passphrase and stores it there, so its owner
    was never shown it. Only a definite answer allows a prompt: the slot is absent, or no
    approved credential store exists here at all (so setup could not have stored one). A slot
    that is present, unreadable or refused, or a store that cannot be asked, answers True: the
    passphrase may be one its owner never saw, and ``--use-passphrase`` remains for an owner
    who chose it.
    """

    from finishup.adapters.keys.os_keyring import AutoUnlockPassphraseStore
    from finishup.config.load import load_config
    from finishup.config.paths import bundle_root

    try:
        config = load_config({}, os.environ, None)
        store = AutoUnlockPassphraseStore(bundle_root(_data_dir=config.storage.data_dir))
        value, reason = store.load_with_reason()
    except Exception:
        return True
    if value is not None:
        overwrite_secret_buffer(value)
        return True
    return reason not in {"auto_unlock_absent", "auto_unlock_backend_unavailable"}


async def authorize_owner_receipt_view(
    target: OwnerReceiptViewTarget, *, use_passphrase: bool = False
) -> OwnerReceiptViewResult:
    """Reauthenticate the owner for one exact receipt view on the foreground terminal.

    The ceremony asks for OS user presence (on macOS, Touch ID or the login password in a
    system dialog the service raises) or the vault passphrase, and never accepts a secret on the
    command line. Whoever holds the terminal can type into the prompt (a pseudo-terminal too),
    so the boundary is the service verifying a passphrase or presence an agent does not have,
    not who is typing. A passphrase kept in the platform credential store (setup's
    system-keychain choice) is asked for only when the owner requests it with
    ``use_passphrase``: its owner may never have seen it.
    """

    if type(target) is not OwnerReceiptViewTarget:
        raise TypeError("owner_receipt_view_target_invalid")

    async def ceremony(choice: _AuthorizationChoice) -> HumanResult:
        try:
            return await run_human_ceremony(
                HumanCeremonyKind.OWNER_RECEIPT_VIEW, target, authorization=choice
            )
        except ConfidentialClientError as error:
            # The same refusal code covers the dialog backoff and the durable passphrase
            # throttle; only the source this command chose tells them apart.
            if (
                error.reason == "reauthentication_rate_limited"
                and choice.selected == "secret_reauthentication"
            ):
                raise HumanCeremonyCliError("passphrase_rate_limited") from error
            raise

    if use_passphrase:
        result = await ceremony(
            _AuthorizationChoice(prefer="secret_reauthentication", passphrase_only=True)
        )
    else:
        if sys.platform == "darwin":
            # Before anything opens, so a dialog that is already on screen can be told apart.
            sys.stderr.write(
                f"Confirmation code for this request: {owner_view_confirmation_code(target)}\n"
            )
            sys.stderr.flush()
        choice = _AuthorizationChoice(
            passphrase_allowed=lambda: not vault_passphrase_held_by_credential_store()
        )
        try:
            result = await ceremony(choice)
        except (ConfidentialClientError, HumanCeremonyCliError) as error:
            # The service could not show an operating-system dialog (where the service runs
            # decides that, not where this command runs). When the vault also offered a
            # passphrase its owner typed, ask for that instead, once, in a fresh ceremony; a
            # cancelled, failed or unanswered dialog is not retried.
            if (
                error.reason != "presence_unavailable"
                or "secret_reauthentication" not in choice.offered
            ):
                raise
            result = await ceremony(
                _AuthorizationChoice(
                    prefer="secret_reauthentication",
                    after_unavailable_dialog=True,
                    passphrase_allowed=choice.passphrase_allowed,
                )
            )
    if type(result) is not OwnerReceiptViewResult:
        raise HumanCeremonyCliError("result_invalid")
    return result
