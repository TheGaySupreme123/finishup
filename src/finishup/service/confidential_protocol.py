"""Pure YZH1/YZS1 confidential wire contracts.

This module deliberately has no service, socket, terminal, vault, or provider
dependencies.  It is safe to import from the narrowly trusted foreground helper.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from enum import Enum, IntEnum
from typing import Final, Literal, cast

from finishup.domain.privacy import (
    PRIVACY_CHANGE_AREAS,
    PRIVACY_CHANGE_FIELDS,
    PrivacyPolicyChange,
    PrivacyPolicyChangeValue,
    validate_privacy_change_set,
)
from finishup.domain.values import validate_commitment, validate_sha256_digest
from finishup.protocol.canonical import (
    JsonValue,
    canonical_digest,
    canonical_encode,
    strict_json_parse,
)
from finishup.protocol.errors import ProtocolValueError
from finishup.protocol.ids import IdKind, validate_id

__all__ = [
    "CEREMONY_EXPIRY_SECONDS",
    "HUMAN_PROTOCOL_MAGIC",
    "HUMAN_PROTOCOL_VERSION",
    "MAX_HUMAN_CONTROL_FRAME_BYTES",
    "MAX_PRIVACY_PREVIEW_CHANGE_BYTES",
    "MAX_SECRET_BINDING_BYTES",
    "MAX_SECRET_BYTES",
    "PASSPHRASE_MAX_BYTES",
    "PASSPHRASE_MIN_BYTES",
    "PROVIDER_CREDENTIAL_MAX_BYTES",
    "SECRET_PROTOCOL_MAGIC",
    "SECRET_PROTOCOL_VERSION",
    "AuthorizationRequiredPhase",
    "CancelAction",
    "ClientActionEnvelope",
    "ClientCancelEnvelope",
    "ClientOpenEnvelope",
    "ConfidentialProtocolError",
    "ConfidentialSecretPurpose",
    "DecisionAction",
    "DecisionRequiredPhase",
    "EmptyVaultTarget",
    "HumanAction",
    "HumanCeremonyBinding",
    "HumanCeremonyKind",
    "HumanDecisionBinding",
    "HumanEnvelope",
    "HumanOpenTarget",
    "HumanPhase",
    "HumanPreview",
    "HumanResult",
    "IdleRelockPolicyChangePreview",
    "IdleRelockPolicyResult",
    "IdleRelockPolicyTarget",
    "InstallationRecoveryPreview",
    "InstallationRecoveryResult",
    "InstallationRecoveryTarget",
    "OWNER_RECEIPT_VIEW_GRANT_SECONDS",
    "OwnerReceiptViewPreview",
    "OwnerReceiptViewResult",
    "OwnerReceiptViewTarget",
    "KeyringRetryPhase",
    "KeyringRetryPreview",
    "KeyringRetryResult",
    "PortableRecoveryPreview",
    "PortableRecoveryResult",
    "PortableRecoveryTarget",
    "PrivacyDecisionResult",
    "PrivacyDisclosureDecisionPreview",
    "PrivacyPendingTarget",
    "PrivacyPolicyDecisionPreview",
    "PrivacyPolicyTransitionPreviewMember",
    "ProviderCredentialResult",
    "ProviderCredentialRotatePreview",
    "ProviderCredentialSetPreview",
    "ProviderCredentialTarget",
    "RetryAction",
    "SecretIngressBinding",
    "SecretRequiredPhase",
    "SelectAuthorizationSourceAction",
    "ServerCloseEnvelope",
    "ServerErrorEnvelope",
    "ServerOpenedEnvelope",
    "ServerPhaseEnvelope",
    "ServerResultEnvelope",
    "VaultInitializePreview",
    "VaultPassphraseRotatePreview",
    "VaultStateResult",
    "VaultUnlockPreview",
    "decode_human_frame",
    "decode_secret_header",
    "encode_human_frame",
    "encode_secret_header",
    "human_target_json",
    "monotonic_milliseconds",
    "new_binding_expiry_ms",
    "validate_passphrase_buffer",
    "validate_provider_credential_buffer",
]

# Frozen legacy identifier (ADR-048): an older running service and a newer client exchange these
# brand-derived frame magics, so both stay byte-identical across the rename.
HUMAN_PROTOCOL_MAGIC: Final = b"YZH1"
HUMAN_PROTOCOL_VERSION: Final = 1
MAX_HUMAN_CONTROL_FRAME_BYTES: Final = 65_536
SECRET_PROTOCOL_MAGIC: Final = b"YZS1"
SECRET_PROTOCOL_VERSION: Final = 1
MAX_SECRET_BYTES: Final = 16_384
MAX_SECRET_BINDING_BYTES: Final = 4_096
PASSPHRASE_MIN_BYTES: Final = 16
PASSPHRASE_MAX_BYTES: Final = 1_024
PROVIDER_CREDENTIAL_MAX_BYTES: Final = 8_192
# One ceremony's whole human span, not one keystroke's. Provisioning a provider credential means
# leaving the terminal, opening the provider console, minting a key, and coming back; a minute is
# not enough for that, and the failure it produced was a retry under time pressure rather than a
# refusal. The window is bounded by foreground-terminal presence, a one-shot challenge, and the
# service/vault generation binding, none of which this changes.
CEREMONY_EXPIRY_SECONDS: Final = 300
# Half the 64 KiB frame ceiling. A policy diff is bounded by the closed field vocabulary, so a
# preview anywhere near this is malformed rather than merely large, and refusing it here keeps
# the failure at the protocol boundary instead of at frame encoding.
MAX_PRIVACY_PREVIEW_CHANGE_BYTES: Final = 32_768
# How long an authorized owner receipt view waits for its one receipt call on the same control
# connection. The grant is one-use and in memory only, so this is a window, never a standing grant.
OWNER_RECEIPT_VIEW_GRANT_SECONDS: Final = 60

_HUMAN_HEADER = struct.Struct(">4sBBI")
_SECRET_HEADER = struct.Struct(">4sBBHI")
_MAX_SAFE_INTEGER: Final = 2**53 - 1
_HEX_64 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_TOKEN = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$", re.ASCII)
_IDENTITY = re.compile(r"^[a-z0-9][a-z0-9._/-]{0,127}$", re.ASCII)
_MODEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$", re.ASCII)
_VERSION = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+-]{0,127}$", re.ASCII)

_PROTOCOL_REASONS: Final = frozenset(
    {
        "protocol_mismatch",
        "invalid_frame",
        "frame_too_large",
        "binding_invalid",
        "purpose_forbidden",
        "secret_rejected",
    }
)


class ConfidentialProtocolError(Exception):
    """A bounded protocol failure that never reflects input bytes or values."""

    __slots__ = ("reason",)

    def __init__(self, reason: str) -> None:
        if type(reason) is not str or reason not in _PROTOCOL_REASONS:
            raise ValueError("confidential_protocol_reason_invalid")
        self.reason = reason
        super().__init__(reason)


class HumanCeremonyKind(str, Enum):  # noqa: UP042 - fixed wire strings
    VAULT_INITIALIZE = "vault_initialize"
    VAULT_PASSPHRASE_ROTATE = "vault_passphrase_rotate"
    VAULT_UNLOCK = "vault_unlock"
    KEYRING_RETRY = "keyring_retry"
    PORTABLE_RECOVERY = "portable_recovery"
    INSTALLATION_RECOVERY = "installation_recovery"
    PROVIDER_CREDENTIAL_SET = "provider_credential_set"
    PROVIDER_CREDENTIAL_ROTATE = "provider_credential_rotate"
    PRIVACY_POLICY_DECISION = "privacy_policy_decision"
    PRIVACY_DISCLOSURE_DECISION = "privacy_disclosure_decision"
    IDLE_RELOCK_POLICY_CHANGE = "idle_relock_policy_change"
    OWNER_RECEIPT_VIEW = "owner_receipt_view"


class ConfidentialSecretPurpose(IntEnum):
    VAULT_INITIALIZE = 1
    VAULT_UNLOCK = 2
    PORTABLE_RECOVERY = 3
    PROVIDER_REAUTHENTICATION = 4
    PROVIDER_CREDENTIAL = 5
    PRIVACY_REAUTHENTICATION = 6
    SECURITY_REAUTHENTICATION = 7
    INSTALLATION_RECOVERY = 8
    VAULT_REWRAP = 9


def _require_exact_type(value: object, expected: type[object], reason: str) -> None:
    if type(value) is not expected:
        raise ValueError(reason)


def _require_token(value: str, reason: str) -> None:
    if type(value) is not str or len(value) > 128 or _TOKEN.fullmatch(value) is None:
        raise ValueError(reason)


def _require_identity(value: str, reason: str) -> None:
    if type(value) is not str or _IDENTITY.fullmatch(value) is None:
        raise ValueError(reason)


def _require_positive(value: int, reason: str) -> None:
    if type(value) is not int or value <= 0 or value > _MAX_SAFE_INTEGER:
        raise ValueError(reason)


def _require_nonnegative(value: int, reason: str) -> None:
    if type(value) is not int or not 0 <= value <= _MAX_SAFE_INTEGER:
        raise ValueError(reason)


def _require_hex64(value: str, reason: str) -> None:
    if type(value) is not str or _HEX_64.fullmatch(value) is None:
        raise ValueError(reason)


def _require_digest(value: str, reason: str) -> None:
    try:
        validate_sha256_digest(value)
    except (ProtocolValueError, TypeError, ValueError) as exc:
        raise ValueError(reason) from exc


def _require_string_tuple(value: tuple[str, ...], *, allowed: frozenset[str], reason: str) -> None:
    if type(value) is not tuple or not value or len(value) != len(set(value)):
        raise ValueError(reason)
    if tuple(sorted(value)) != value or any(
        type(item) is not str or item not in allowed for item in value
    ):
        raise ValueError(reason)


@dataclass(frozen=True, slots=True)
class EmptyVaultTarget:
    kind: Literal["vault"] = "vault"
    expected_mode: Literal["uninitialized", "os_keyring", "passphrase"] = "uninitialized"

    def __post_init__(self) -> None:
        if self.kind != "vault" or self.expected_mode not in {
            "uninitialized",
            "os_keyring",
            "passphrase",
        }:
            raise ValueError("vault_target_invalid")


@dataclass(frozen=True, slots=True)
class PortableRecoveryTarget:
    operation: Literal["create", "restore"]
    request_id: str
    confirmed_plan_digest: str
    kind: Literal["portable_recovery"] = "portable_recovery"

    def __post_init__(self) -> None:
        if self.kind != "portable_recovery" or self.operation not in {"create", "restore"}:
            raise ValueError("portable_recovery_target_invalid")
        validate_id(IdKind.REQUEST, self.request_id)
        _require_digest(self.confirmed_plan_digest, "portable_recovery_target_invalid")


@dataclass(frozen=True, slots=True)
class InstallationRecoveryTarget:
    operation: Literal["provision", "rotate", "revoke", "restore"]
    request_id: str
    confirmed_plan_digest: str
    recovery_generation: int
    set_mode: Literal["compact", "self_contained"]
    secret_kind: Literal["generated_code", "argon2id_passphrase"]
    target_envelope: Literal["preserve", "passphrase", "platform_auto_unlock"]
    kind: Literal["installation_recovery"] = "installation_recovery"

    def __post_init__(self) -> None:
        if self.kind != "installation_recovery" or self.operation not in {
            "provision",
            "rotate",
            "revoke",
            "restore",
        }:
            raise ValueError("installation_recovery_target_invalid")
        validate_id(IdKind.REQUEST, self.request_id)
        _require_digest(self.confirmed_plan_digest, "installation_recovery_target_invalid")
        _require_positive(self.recovery_generation, "installation_recovery_target_invalid")
        if self.set_mode not in {"compact", "self_contained"} or self.secret_kind not in {
            "generated_code",
            "argon2id_passphrase",
        }:
            raise ValueError("installation_recovery_target_invalid")
        expected = (
            {"preserve"}
            if self.operation == "provision"
            else {"passphrase", "platform_auto_unlock"}
            if self.operation == "restore"
            else {"passphrase"}
        )
        if self.target_envelope not in expected:
            raise ValueError("installation_recovery_target_invalid")

    def plan_digest(self) -> str:
        """Bind the human preview to the exact nonsecret recovery choices."""

        return canonical_digest(
            {
                "operation": self.operation,
                "recovery_generation": self.recovery_generation,
                "request_id": self.request_id,
                "secret_kind": self.secret_kind,
                "set_mode": self.set_mode,
                "target_envelope": self.target_envelope,
            }
        )


@dataclass(frozen=True, slots=True)
class ProviderCredentialTarget:
    action: Literal["set", "rotate"]
    provider_id: str
    model_id: str
    endpoint_profile_id: str
    endpoint_profile_version: str
    purpose: str
    scope_digest: str
    purpose_digest: str
    repository_privacy_commitment: str | None = None
    kind: Literal["provider_credential"] = "provider_credential"

    def __post_init__(self) -> None:
        if self.kind != "provider_credential" or self.action not in {"set", "rotate"}:
            raise ValueError("provider_credential_target_invalid")
        _require_identity(self.provider_id, "provider_credential_target_invalid")
        if type(self.model_id) is not str or _MODEL.fullmatch(self.model_id) is None:
            raise ValueError("provider_credential_target_invalid")
        _require_identity(self.endpoint_profile_id, "provider_credential_target_invalid")
        if (
            type(self.endpoint_profile_version) is not str
            or _VERSION.fullmatch(self.endpoint_profile_version) is None
        ):
            raise ValueError("provider_credential_target_invalid")
        _require_token(self.purpose, "provider_credential_target_invalid")
        _require_digest(self.scope_digest, "provider_credential_target_invalid")
        _require_digest(self.purpose_digest, "provider_credential_target_invalid")
        if self.repository_privacy_commitment is not None:
            try:
                validate_commitment(self.repository_privacy_commitment)
            except (TypeError, ValueError) as exc:
                raise ValueError("provider_credential_target_invalid") from exc
        if self.purpose_digest != canonical_digest({"purpose": self.purpose}):
            raise ValueError("provider_credential_target_invalid")

    def target_digest(self) -> str:
        return canonical_digest(human_target_json(self))


@dataclass(frozen=True, slots=True)
class PrivacyPendingTarget:
    decision_kind: Literal["policy", "disclosure"]
    pending_id: str
    kind: Literal["privacy_pending"] = "privacy_pending"

    def __post_init__(self) -> None:
        if self.kind != "privacy_pending" or self.decision_kind not in {"policy", "disclosure"}:
            raise ValueError("privacy_pending_target_invalid")
        if type(self.pending_id) is not str or not 1 <= len(self.pending_id) <= 128:
            raise ValueError("privacy_pending_target_invalid")


@dataclass(frozen=True, slots=True)
class IdleRelockPolicyTarget:
    operation: Literal["set", "disable"]
    seconds: int | None = None
    kind: Literal["idle_relock_policy"] = "idle_relock_policy"

    def __post_init__(self) -> None:
        if self.kind != "idle_relock_policy" or self.operation not in {"set", "disable"}:
            raise ValueError("idle_relock_policy_target_invalid")
        if self.operation == "set":
            if type(self.seconds) is not int or not 60 <= self.seconds <= 86_400:
                raise ValueError("idle_relock_policy_target_invalid")
        elif self.seconds is not None:
            raise ValueError("idle_relock_policy_target_invalid")


@dataclass(frozen=True, slots=True)
class OwnerReceiptViewTarget:
    """One exact receipt request, on one control connection, that the owner asks to see whole.

    ``control_connection_digest`` binds the view to the ordinary control connection the owner's
    own command opened; the receipt call that consumes the grant must arrive on that connection
    with these exact request fields. Nothing here is authority until the ceremony's
    reauthentication succeeds.
    """

    task_id: str
    session_id: str
    receipt_request_id: str
    format: Literal["json", "markdown", "text"]
    include: Literal["summary", "standard", "full"]
    redaction_profile: Literal["full_local", "default_local_export", "redacted_share"]
    control_connection_digest: str
    kind: Literal["owner_receipt_view"] = "owner_receipt_view"

    def __post_init__(self) -> None:
        reason = "owner_receipt_view_target_invalid"
        if self.kind != "owner_receipt_view":
            raise ValueError(reason)
        try:
            validate_id(IdKind.TASK, self.task_id)
            validate_id(IdKind.SESSION, self.session_id)
            validate_id(IdKind.REQUEST, self.receipt_request_id)
        except (TypeError, ValueError) as exc:
            raise ValueError(reason) from exc
        if (
            self.format not in {"json", "markdown", "text"}
            or self.include not in {"summary", "standard", "full"}
            or self.redaction_profile
            not in {"full_local", "default_local_export", "redacted_share"}
        ):
            raise ValueError(reason)
        _require_digest(self.control_connection_digest, reason)


type HumanOpenTarget = (
    EmptyVaultTarget
    | PortableRecoveryTarget
    | InstallationRecoveryTarget
    | ProviderCredentialTarget
    | PrivacyPendingTarget
    | IdleRelockPolicyTarget
    | OwnerReceiptViewTarget
)


@dataclass(frozen=True, slots=True)
class HumanCeremonyBinding:
    binding_version: int
    ceremony_id: str
    connection_nonce: str
    ceremony_kind: HumanCeremonyKind
    service_instance_id: str
    service_generation: int
    vault_generation: int
    policy_generation: int | None
    target_digest: str
    expires_at_monotonic_ms: int

    def __post_init__(self) -> None:
        if self.binding_version != 1:
            raise ValueError("ceremony_binding_invalid")
        _require_hex64(self.ceremony_id, "ceremony_binding_invalid")
        _require_hex64(self.connection_nonce, "ceremony_binding_invalid")
        _require_exact_type(self.ceremony_kind, HumanCeremonyKind, "ceremony_binding_invalid")
        validate_id(IdKind.SERVICE_INSTANCE, self.service_instance_id)
        _require_positive(self.service_generation, "ceremony_binding_invalid")
        _require_nonnegative(self.vault_generation, "ceremony_binding_invalid")
        if self.policy_generation is not None:
            _require_positive(self.policy_generation, "ceremony_binding_invalid")
        _require_digest(self.target_digest, "ceremony_binding_invalid")
        _require_nonnegative(self.expires_at_monotonic_ms, "ceremony_binding_invalid")


@dataclass(frozen=True, slots=True)
class HumanDecisionBinding:
    binding_version: int
    ceremony_id: str
    step: int
    decision_digest: str
    service_instance_id: str
    service_generation: int
    vault_generation: int
    policy_generation: int | None
    target_digest: str
    expires_at_monotonic_ms: int

    def __post_init__(self) -> None:
        if self.binding_version != 1:
            raise ValueError("decision_binding_invalid")
        _require_hex64(self.ceremony_id, "decision_binding_invalid")
        _require_positive(self.step, "decision_binding_invalid")
        _require_digest(self.decision_digest, "decision_binding_invalid")
        validate_id(IdKind.SERVICE_INSTANCE, self.service_instance_id)
        _require_positive(self.service_generation, "decision_binding_invalid")
        _require_nonnegative(self.vault_generation, "decision_binding_invalid")
        if self.policy_generation is not None:
            _require_positive(self.policy_generation, "decision_binding_invalid")
        _require_digest(self.target_digest, "decision_binding_invalid")
        _require_nonnegative(self.expires_at_monotonic_ms, "decision_binding_invalid")


@dataclass(frozen=True, slots=True)
class SecretIngressBinding:
    binding_version: int
    ceremony_id: str
    secret_challenge: str
    purpose: ConfidentialSecretPurpose
    service_instance_id: str
    service_generation: int
    vault_generation: int
    policy_generation: int | None
    target_digest: str
    expires_at_monotonic_ms: int

    def __post_init__(self) -> None:
        if self.binding_version != 1:
            raise ValueError("secret_binding_invalid")
        _require_hex64(self.ceremony_id, "secret_binding_invalid")
        _require_hex64(self.secret_challenge, "secret_binding_invalid")
        _require_exact_type(self.purpose, ConfidentialSecretPurpose, "secret_binding_invalid")
        validate_id(IdKind.SERVICE_INSTANCE, self.service_instance_id)
        _require_positive(self.service_generation, "secret_binding_invalid")
        _require_nonnegative(self.vault_generation, "secret_binding_invalid")
        if self.policy_generation is not None:
            _require_positive(self.policy_generation, "secret_binding_invalid")
        _require_digest(self.target_digest, "secret_binding_invalid")
        _require_nonnegative(self.expires_at_monotonic_ms, "secret_binding_invalid")


@dataclass(frozen=True, slots=True)
class VaultInitializePreview:
    selected_mode: Literal["passphrase"] = "passphrase"
    irreversible: Literal[True] = True
    kind: Literal["vault_initialize"] = "vault_initialize"

    def __post_init__(self) -> None:
        if (
            self.selected_mode != "passphrase"
            or self.irreversible is not True
            or self.kind != "vault_initialize"
        ):
            raise ValueError("vault_initialize_preview_invalid")


@dataclass(frozen=True, slots=True)
class VaultPassphraseRotatePreview:
    current_mode: Literal["passphrase"] = "passphrase"
    kind: Literal["vault_passphrase_rotate"] = "vault_passphrase_rotate"

    def __post_init__(self) -> None:
        if self.current_mode != "passphrase" or self.kind != "vault_passphrase_rotate":
            raise ValueError("vault_passphrase_rotate_preview_invalid")


@dataclass(frozen=True, slots=True)
class VaultUnlockPreview:
    current_mode: Literal["passphrase"] = "passphrase"
    kind: Literal["vault_unlock"] = "vault_unlock"

    def __post_init__(self) -> None:
        if self.current_mode != "passphrase" or self.kind != "vault_unlock":
            raise ValueError("vault_unlock_preview_invalid")


@dataclass(frozen=True, slots=True)
class KeyringRetryPreview:
    operation: Literal["pristine_create", "existing_load"]
    kind: Literal["keyring_retry"] = "keyring_retry"

    def __post_init__(self) -> None:
        if self.operation not in {"pristine_create", "existing_load"}:
            raise ValueError("keyring_retry_preview_invalid")


@dataclass(frozen=True, slots=True)
class PortableRecoveryPreview:
    operation: Literal["create", "restore"]
    request_id: str
    confirmed_plan_digest: str
    location_commitment: str
    content_commitment: str
    item_count: int
    total_bytes: int
    kind: Literal["portable_recovery"] = "portable_recovery"

    def __post_init__(self) -> None:
        if self.operation not in {"create", "restore"}:
            raise ValueError("portable_recovery_preview_invalid")
        validate_id(IdKind.REQUEST, self.request_id)
        for value in (
            self.confirmed_plan_digest,
            self.location_commitment,
            self.content_commitment,
        ):
            _require_digest(value, "portable_recovery_preview_invalid")
        _require_nonnegative(self.item_count, "portable_recovery_preview_invalid")
        _require_nonnegative(self.total_bytes, "portable_recovery_preview_invalid")


@dataclass(frozen=True, slots=True)
class InstallationRecoveryPreview:
    operation: Literal["provision", "rotate", "revoke", "restore"]
    request_id: str
    confirmed_plan_digest: str
    recovery_generation: int
    set_mode: Literal["compact", "self_contained"]
    secret_kind: Literal["generated_code", "argon2id_passphrase"]
    target_envelope: Literal["preserve", "passphrase", "platform_auto_unlock"]
    item_count: int
    total_bytes: int
    native_prompt_available: bool
    kind: Literal["installation_recovery"] = "installation_recovery"

    def __post_init__(self) -> None:
        target = InstallationRecoveryTarget(
            self.operation,
            self.request_id,
            self.confirmed_plan_digest,
            self.recovery_generation,
            self.set_mode,
            self.secret_kind,
            self.target_envelope,
        )
        if target.kind != self.kind:
            raise ValueError("installation_recovery_preview_invalid")
        _require_nonnegative(self.item_count, "installation_recovery_preview_invalid")
        _require_nonnegative(self.total_bytes, "installation_recovery_preview_invalid")
        if type(self.native_prompt_available) is not bool:
            raise ValueError("installation_recovery_preview_invalid")


@dataclass(frozen=True, slots=True)
class ProviderCredentialSetPreview:
    target: ProviderCredentialTarget
    kind: Literal["provider_credential_set"] = "provider_credential_set"

    def __post_init__(self) -> None:
        if (
            type(self.target) is not ProviderCredentialTarget
            or self.target.action != "set"
            or self.kind != "provider_credential_set"
        ):
            raise ValueError("provider_credential_preview_invalid")


@dataclass(frozen=True, slots=True)
class ProviderCredentialRotatePreview:
    target: ProviderCredentialTarget
    kind: Literal["provider_credential_rotate"] = "provider_credential_rotate"

    def __post_init__(self) -> None:
        if (
            type(self.target) is not ProviderCredentialTarget
            or self.target.action != "rotate"
            or self.kind != "provider_credential_rotate"
        ):
            raise ValueError("provider_credential_preview_invalid")


@dataclass(frozen=True, slots=True)
class PrivacyPolicyTransitionPreviewMember:
    """One authority layer changed by a compound privacy decision.

    The wire names only the layer and operation. Repository identity is deliberately absent:
    the trusted control session already bound it, and neither a path nor its commitment helps a
    person understand the disclosure boundary they are approving.
    """

    authority: Literal["machine_ceiling", "repository_grant"]
    action: Literal["replace", "insert"]
    changes: tuple[PrivacyPolicyChange, ...]

    def __post_init__(self) -> None:
        if (
            self.authority not in {"machine_ceiling", "repository_grant"}
            or self.action not in {"replace", "insert"}
            or (self.authority == "machine_ceiling" and self.action != "replace")
            or (self.authority == "repository_grant" and self.action not in {"replace", "insert"})
        ):
            raise ValueError("privacy_policy_preview_member_invalid")
        try:
            validate_privacy_change_set(self.changes, require_widening=False)
        except (TypeError, ValueError) as exc:
            raise ValueError("privacy_policy_preview_member_invalid") from exc
        if self.action == "insert" and (
            not self.changes or not any(change.widens for change in self.changes)
        ):
            raise ValueError("privacy_policy_preview_member_invalid")


@dataclass(frozen=True, slots=True)
class PrivacyPolicyDecisionPreview:
    """The complete substantive policy diff a human approves a widening against.

    Legacy proposals carry their whole security-relevant ``before → after`` diff in ``changes``.
    Repository proposals carry ordered ``members`` so one approval cannot hide either an
    installation-ceiling replacement or repository-row insertion/replacement. An insertion is
    compared with an explicit Private/no-egress baseline and must carry every resulting field
    change. Every preview member must contain a widening field. ``diff_digest`` stays as integrity evidence binding
    the decision to exact bytes; it is not the human-readable description.
    """

    pending_id: str
    diff_digest: str
    changes: tuple[PrivacyPolicyChange, ...]
    members: tuple[PrivacyPolicyTransitionPreviewMember, ...] = ()
    kind: Literal["privacy_policy_decision"] = "privacy_policy_decision"

    def __post_init__(self) -> None:
        if type(self.pending_id) is not str or not self.pending_id:
            raise ValueError("privacy_policy_preview_invalid")
        _require_digest(self.diff_digest, "privacy_policy_preview_invalid")
        if type(self.members) is not tuple or any(
            type(member) is not PrivacyPolicyTransitionPreviewMember for member in self.members
        ):
            raise ValueError("privacy_policy_preview_invalid")
        try:
            if self.members:
                if self.changes or tuple(member.authority for member in self.members) not in {
                    ("repository_grant",),
                    ("machine_ceiling", "repository_grant"),
                }:
                    raise ValueError("privacy_policy_preview_invalid")
                if not any(
                    member.action == "insert" or any(change.widens for change in member.changes)
                    for member in self.members
                ):
                    raise ValueError("privacy_policy_preview_invalid")
                encoded_value: JsonValue = [
                    _privacy_preview_member_to_json(member) for member in self.members
                ]
            else:
                validate_privacy_change_set(self.changes, require_widening=True)
                encoded_value = [_change_to_json(c) for c in self.changes]
        except (TypeError, ValueError) as exc:
            raise ValueError("privacy_policy_preview_invalid") from exc
        encoded = canonical_encode(encoded_value)
        if len(encoded) > MAX_PRIVACY_PREVIEW_CHANGE_BYTES:
            raise ValueError("privacy_policy_preview_invalid")


@dataclass(frozen=True, slots=True)
class PrivacyDisclosureDecisionPreview:
    pending_id: str
    excerpt_preview: str
    excerpt_digest: str
    category: str
    destination_commitment: str
    byte_count: int
    token_count: int
    policy_digest: str
    authorization_change: Literal["none"] = "none"
    kind: Literal["privacy_disclosure_decision"] = "privacy_disclosure_decision"

    def __post_init__(self) -> None:
        if type(self.pending_id) is not str or not self.pending_id:
            raise ValueError("privacy_disclosure_preview_invalid")
        if (
            type(self.excerpt_preview) is not str
            or len(self.excerpt_preview.encode("utf-8")) > 4_096
        ):
            raise ValueError("privacy_disclosure_preview_invalid")
        _require_digest(self.excerpt_digest, "privacy_disclosure_preview_invalid")
        _require_token(self.category, "privacy_disclosure_preview_invalid")
        _require_digest(self.destination_commitment, "privacy_disclosure_preview_invalid")
        _require_nonnegative(self.byte_count, "privacy_disclosure_preview_invalid")
        _require_nonnegative(self.token_count, "privacy_disclosure_preview_invalid")
        _require_digest(self.policy_digest, "privacy_disclosure_preview_invalid")
        if self.authorization_change != "none":
            raise ValueError("privacy_disclosure_preview_invalid")


type IdlePolicyValue = Literal["disabled"] | int


def _validate_idle_policy_value(value: IdlePolicyValue) -> None:
    if value == "disabled":
        return
    if type(value) is not int or not 60 <= value <= 86_400:
        raise ValueError("idle_relock_policy_value_invalid")


@dataclass(frozen=True, slots=True)
class IdleRelockPolicyChangePreview:
    current: IdlePolicyValue
    proposed: IdlePolicyValue
    service_generation: int
    target_digest: str
    kind: Literal["idle_relock_policy_change"] = "idle_relock_policy_change"

    def __post_init__(self) -> None:
        _validate_idle_policy_value(self.current)
        _validate_idle_policy_value(self.proposed)
        _require_positive(self.service_generation, "idle_relock_policy_preview_invalid")
        _require_digest(self.target_digest, "idle_relock_policy_preview_invalid")


@dataclass(frozen=True, slots=True)
class OwnerReceiptViewPreview:
    """What the owner is about to see: one task's receipt, in this format and profile."""

    task_id: str
    format: Literal["json", "markdown", "text"]
    redaction_profile: Literal["full_local", "default_local_export", "redacted_share"]
    grant_seconds: int
    target_digest: str
    kind: Literal["owner_receipt_view"] = "owner_receipt_view"

    def __post_init__(self) -> None:
        reason = "owner_receipt_view_preview_invalid"
        try:
            validate_id(IdKind.TASK, self.task_id)
        except (TypeError, ValueError) as exc:
            raise ValueError(reason) from exc
        if self.format not in {"json", "markdown", "text"} or self.redaction_profile not in {
            "full_local",
            "default_local_export",
            "redacted_share",
        }:
            raise ValueError(reason)
        _require_positive(self.grant_seconds, reason)
        _require_digest(self.target_digest, reason)


type HumanPreview = (
    VaultInitializePreview
    | VaultPassphraseRotatePreview
    | VaultUnlockPreview
    | KeyringRetryPreview
    | PortableRecoveryPreview
    | InstallationRecoveryPreview
    | ProviderCredentialSetPreview
    | ProviderCredentialRotatePreview
    | PrivacyPolicyDecisionPreview
    | PrivacyDisclosureDecisionPreview
    | IdleRelockPolicyChangePreview
    | OwnerReceiptViewPreview
)


@dataclass(frozen=True, slots=True)
class RetryAction:
    kind: Literal["retry"] = "retry"

    def __post_init__(self) -> None:
        if self.kind != "retry":
            raise ValueError("retry_action_invalid")


@dataclass(frozen=True, slots=True)
class SelectAuthorizationSourceAction:
    source: Literal["os_user_presence", "secret_reauthentication"]
    kind: Literal["select_authorization_source"] = "select_authorization_source"

    def __post_init__(self) -> None:
        if self.source not in {"os_user_presence", "secret_reauthentication"}:
            raise ValueError("authorization_source_invalid")


@dataclass(frozen=True, slots=True)
class DecisionAction:
    decision: Literal["approve", "deny"]
    kind: Literal["decision"] = "decision"

    def __post_init__(self) -> None:
        if self.decision not in {"approve", "deny"}:
            raise ValueError("decision_invalid")


@dataclass(frozen=True, slots=True)
class CancelAction:
    kind: Literal["cancel"] = "cancel"

    def __post_init__(self) -> None:
        if self.kind != "cancel":
            raise ValueError("cancel_action_invalid")


type HumanAction = RetryAction | SelectAuthorizationSourceAction | DecisionAction | CancelAction


@dataclass(frozen=True, slots=True)
class SecretRequiredPhase:
    binding: SecretIngressBinding
    kind: Literal["secret_required"] = "secret_required"

    def __post_init__(self) -> None:
        if type(self.binding) is not SecretIngressBinding or self.kind != "secret_required":
            raise ValueError("secret_required_phase_invalid")


@dataclass(frozen=True, slots=True)
class AuthorizationRequiredPhase:
    available_sources: tuple[Literal["os_user_presence", "secret_reauthentication"], ...]
    kind: Literal["authorization_required"] = "authorization_required"

    def __post_init__(self) -> None:
        _require_string_tuple(
            cast(tuple[str, ...], self.available_sources),
            allowed=frozenset({"os_user_presence", "secret_reauthentication"}),
            reason="authorization_sources_invalid",
        )


@dataclass(frozen=True, slots=True)
class KeyringRetryPhase:
    kind: Literal["keyring_retry"] = "keyring_retry"

    def __post_init__(self) -> None:
        if self.kind != "keyring_retry":
            raise ValueError("keyring_retry_phase_invalid")


@dataclass(frozen=True, slots=True)
class DecisionRequiredPhase:
    allowed_decisions: tuple[Literal["approve", "deny"], ...] = ("approve", "deny")
    kind: Literal["decision_required"] = "decision_required"

    def __post_init__(self) -> None:
        _require_string_tuple(
            cast(tuple[str, ...], self.allowed_decisions),
            allowed=frozenset({"approve", "deny"}),
            reason="allowed_decisions_invalid",
        )


type HumanPhase = (
    SecretRequiredPhase | AuthorizationRequiredPhase | KeyringRetryPhase | DecisionRequiredPhase
)


@dataclass(frozen=True, slots=True)
class VaultStateResult:
    state: Literal["locked", "ready"]
    reason: str
    kind: Literal["vault_state"] = "vault_state"

    def __post_init__(self) -> None:
        if self.state not in {"locked", "ready"}:
            raise ValueError("vault_state_result_invalid")
        if type(self.reason) is not str or self.reason not in _VAULT_STATE_RESULT_REASONS:
            raise ValueError("vault_state_result_invalid")


@dataclass(frozen=True, slots=True)
class KeyringRetryResult:
    state: Literal["locked", "ready"]
    reason: str
    kind: Literal["keyring_retry"] = "keyring_retry"

    def __post_init__(self) -> None:
        if self.state not in {"locked", "ready"}:
            raise ValueError("keyring_retry_result_invalid")
        if type(self.reason) is not str or self.reason not in _VAULT_STATE_RESULT_REASONS:
            raise ValueError("keyring_retry_result_invalid")


@dataclass(frozen=True, slots=True)
class PortableRecoveryResult:
    operation: Literal["create", "restore"]
    status: Literal["completed", "failed"]
    result_commitment: str
    kind: Literal["portable_recovery"] = "portable_recovery"

    def __post_init__(self) -> None:
        if self.operation not in {"create", "restore"} or self.status not in {
            "completed",
            "failed",
        }:
            raise ValueError("portable_recovery_result_invalid")
        _require_digest(self.result_commitment, "portable_recovery_result_invalid")


@dataclass(frozen=True, slots=True)
class InstallationRecoveryResult:
    operation: Literal["provision", "rotate", "revoke", "restore"]
    status: Literal["completed", "failed"]
    recovery_generation: int
    result_commitment: str
    kind: Literal["installation_recovery"] = "installation_recovery"

    def __post_init__(self) -> None:
        if self.operation not in {
            "provision",
            "rotate",
            "revoke",
            "restore",
        } or self.status not in {
            "completed",
            "failed",
        }:
            raise ValueError("installation_recovery_result_invalid")
        _require_positive(self.recovery_generation, "installation_recovery_result_invalid")
        _require_digest(self.result_commitment, "installation_recovery_result_invalid")


@dataclass(frozen=True, slots=True)
class ProviderCredentialResult:
    action: Literal["set", "rotate"]
    stored_generation: int
    activation_status: Literal["active", "local_only", "stored"]
    kind: Literal["provider_credential"] = "provider_credential"

    def __post_init__(self) -> None:
        if self.action not in {"set", "rotate"} or self.activation_status not in {
            "active",
            "local_only",
            "stored",
        }:
            raise ValueError("provider_credential_result_invalid")
        _require_positive(self.stored_generation, "provider_credential_result_invalid")


@dataclass(frozen=True, slots=True)
class PrivacyDecisionResult:
    status: Literal["committed", "denied", "stale"]
    commitment: str
    kind: Literal["privacy_decision"] = "privacy_decision"

    def __post_init__(self) -> None:
        if self.status not in {"committed", "denied", "stale"}:
            raise ValueError("privacy_decision_result_invalid")
        _require_digest(self.commitment, "privacy_decision_result_invalid")


@dataclass(frozen=True, slots=True)
class IdleRelockPolicyResult:
    previous: IdlePolicyValue
    effective: IdlePolicyValue
    service_generation: int
    scope: Literal["service_generation"] = "service_generation"
    kind: Literal["idle_relock_policy"] = "idle_relock_policy"

    def __post_init__(self) -> None:
        _validate_idle_policy_value(self.previous)
        _validate_idle_policy_value(self.effective)
        _require_positive(self.service_generation, "idle_relock_policy_result_invalid")
        if self.scope != "service_generation":
            raise ValueError("idle_relock_policy_result_invalid")


@dataclass(frozen=True, slots=True)
class OwnerReceiptViewResult:
    """The one-use owner view is authorized for ``grant_seconds`` on the bound connection."""

    status: Literal["authorized"]
    target_digest: str
    grant_seconds: int
    kind: Literal["owner_receipt_view"] = "owner_receipt_view"

    def __post_init__(self) -> None:
        if self.status != "authorized":
            raise ValueError("owner_receipt_view_result_invalid")
        _require_digest(self.target_digest, "owner_receipt_view_result_invalid")
        _require_positive(self.grant_seconds, "owner_receipt_view_result_invalid")


type HumanResult = (
    VaultStateResult
    | KeyringRetryResult
    | PortableRecoveryResult
    | InstallationRecoveryResult
    | ProviderCredentialResult
    | PrivacyDecisionResult
    | IdleRelockPolicyResult
    | OwnerReceiptViewResult
)


@dataclass(frozen=True, slots=True)
class ClientOpenEnvelope:
    connection_nonce: str
    ceremony_kind: HumanCeremonyKind
    target: HumanOpenTarget
    protocol_version: int = HUMAN_PROTOCOL_VERSION

    def __post_init__(self) -> None:
        if self.protocol_version != HUMAN_PROTOCOL_VERSION:
            raise ValueError("protocol_version_invalid")
        _require_hex64(self.connection_nonce, "connection_nonce_invalid")
        _require_exact_type(self.ceremony_kind, HumanCeremonyKind, "ceremony_kind_invalid")
        _validate_open_combination(self.ceremony_kind, self.target)


@dataclass(frozen=True, slots=True)
class ServerOpenedEnvelope:
    ceremony_id: str
    step: int
    binding: HumanCeremonyBinding
    preview: HumanPreview
    phase: HumanPhase

    def __post_init__(self) -> None:
        _require_hex64(self.ceremony_id, "ceremony_id_invalid")
        _require_positive(self.step, "ceremony_step_invalid")
        if self.step != 1 or self.binding.ceremony_id != self.ceremony_id:
            raise ValueError("ceremony_binding_invalid")


@dataclass(frozen=True, slots=True)
class ClientActionEnvelope:
    ceremony_id: str
    step: int
    action: HumanAction

    def __post_init__(self) -> None:
        _require_hex64(self.ceremony_id, "ceremony_id_invalid")
        _require_positive(self.step, "ceremony_step_invalid")


@dataclass(frozen=True, slots=True)
class ServerPhaseEnvelope:
    ceremony_id: str
    step: int
    phase: HumanPhase

    def __post_init__(self) -> None:
        _require_hex64(self.ceremony_id, "ceremony_id_invalid")
        _require_positive(self.step, "ceremony_step_invalid")


@dataclass(frozen=True, slots=True)
class ServerResultEnvelope:
    ceremony_id: str
    step: int
    result: HumanResult

    def __post_init__(self) -> None:
        _require_hex64(self.ceremony_id, "ceremony_id_invalid")
        _require_positive(self.step, "ceremony_step_invalid")


_SERVER_ERROR_CODES: Final = frozenset(
    {
        "protocol_mismatch",
        "invalid_frame",
        "frame_too_large",
        "peer_untrusted",
        "kind_forbidden",
        # Another ceremony is already open on this service; nothing was opened (#1073).
        "ceremony_busy",
        # Too many recent failed confirmations (passphrase throttle, or OS presence prompts
        # that did not approve); wait and try again.
        "reauthentication_rate_limited",
        # Bounded structural outcomes for a disclosure decision that cannot proceed. They say
        # what the caller can do next without revealing proposal content or reflecting input:
        # the proposal is gone/expired, it is not in a decidable state, or this build cannot
        # run the ceremony at all.
        "pending_unavailable",
        "pending_not_actionable",
        "ceremony_unsupported",
        "target_invalid",
        "state_forbidden",
        "stale_generation",
        "binding_expired",
        "phase_invalid",
        "replay",
        "presence_unavailable",
        # The OS presence prompt was cancelled or did not authenticate the person, or nobody
        # answered it before its deadline (ADR-016 decision 4). Bounded; no OS text.
        "presence_refused",
        "presence_timeout",
        "reauthentication_unavailable",
        "reauthentication_required",
        "action_denied",
        "secret_rejected",
        "cancelled",
        "internal_error",
    }
)

# These are the exact structural reasons emitted by UnlockCoordinator plus
# HumanControlService's two explicit non-error summaries.  They remain local
# to the pure wire module so importing the protocol never imports service
# authority.
_VAULT_STATE_RESULT_REASONS: Final = frozenset(
    {
        "attempt_active",
        "binding_expired",
        "cancelled",
        "challenge_mismatch",
        "closed",
        "confidential_endpoint_unavailable",
        "credential_invalid",
        "human_authority_unavailable",
        "initialization_ambiguous",
        "initialization_forbidden",
        "invalid_state",
        "keyring_locked",
        "keyring_unavailable",
        "locked",
        "reauthentication_unavailable",
        "record_binding_mismatch",
        "record_missing",
        "secret_purpose_mismatch",
        "stale_generation",
        "succeeded",
        "throttle_persistence_failed",
        "throttle_repair_required",
        "throttle_record_exists",
        "throttle_record_missing",
        "throttle_record_tampered",
        "throttle_record_unsafe",
        "unlock_rate_limited",
        "unlock_failed",
        "unlock_wrong",
        "vault_locked",
        "vault_tampered",
        "vault_uninitialized",
        "already_ready",
    }
)


@dataclass(frozen=True, slots=True)
class ServerErrorEnvelope:
    code: str
    retryable: bool
    ceremony_id: str | None = None
    step: int | None = None

    def __post_init__(self) -> None:
        if type(self.code) is not str or self.code not in _SERVER_ERROR_CODES:
            raise ValueError("server_error_code_invalid")
        if type(self.retryable) is not bool:
            raise ValueError("server_error_retryable_invalid")
        if self.ceremony_id is None:
            if self.step is not None:
                raise ValueError("server_error_correlation_invalid")
        else:
            _require_hex64(self.ceremony_id, "server_error_correlation_invalid")
            if self.step is None:
                raise ValueError("server_error_correlation_invalid")
            _require_positive(self.step, "server_error_correlation_invalid")


@dataclass(frozen=True, slots=True)
class ClientCancelEnvelope:
    ceremony_id: str
    step: int

    def __post_init__(self) -> None:
        _require_hex64(self.ceremony_id, "ceremony_id_invalid")
        _require_positive(self.step, "ceremony_step_invalid")


@dataclass(frozen=True, slots=True)
class ServerCloseEnvelope:
    ceremony_id: str
    step: int
    outcome: Literal["completed", "cancelled", "failed"]

    def __post_init__(self) -> None:
        _require_hex64(self.ceremony_id, "ceremony_id_invalid")
        _require_positive(self.step, "ceremony_step_invalid")
        if self.outcome not in {"completed", "cancelled", "failed"}:
            raise ValueError("close_outcome_invalid")


type HumanEnvelope = (
    ClientOpenEnvelope
    | ServerOpenedEnvelope
    | ClientActionEnvelope
    | ServerPhaseEnvelope
    | ServerResultEnvelope
    | ServerErrorEnvelope
    | ClientCancelEnvelope
    | ServerCloseEnvelope
)


class _HumanFrameType(IntEnum):
    CLIENT_OPEN = 1
    SERVER_OPENED = 2
    CLIENT_ACTION = 3
    SERVER_PHASE = 4
    SERVER_RESULT = 5
    SERVER_ERROR = 6
    CLIENT_CANCEL = 7
    SERVER_CLOSE = 8


def _validate_open_combination(kind: HumanCeremonyKind, target: HumanOpenTarget) -> None:
    expected: type[object]
    if kind in {
        HumanCeremonyKind.VAULT_INITIALIZE,
        HumanCeremonyKind.VAULT_PASSPHRASE_ROTATE,
        HumanCeremonyKind.VAULT_UNLOCK,
        HumanCeremonyKind.KEYRING_RETRY,
    }:
        expected = EmptyVaultTarget
    elif kind is HumanCeremonyKind.PORTABLE_RECOVERY:
        expected = PortableRecoveryTarget
    elif kind is HumanCeremonyKind.INSTALLATION_RECOVERY:
        expected = InstallationRecoveryTarget
    elif kind in {
        HumanCeremonyKind.PROVIDER_CREDENTIAL_SET,
        HumanCeremonyKind.PROVIDER_CREDENTIAL_ROTATE,
    }:
        expected = ProviderCredentialTarget
    elif kind in {
        HumanCeremonyKind.PRIVACY_POLICY_DECISION,
        HumanCeremonyKind.PRIVACY_DISCLOSURE_DECISION,
    }:
        expected = PrivacyPendingTarget
    elif kind is HumanCeremonyKind.OWNER_RECEIPT_VIEW:
        expected = OwnerReceiptViewTarget
    else:
        expected = IdleRelockPolicyTarget
    if type(target) is not expected:
        raise ValueError("ceremony_target_mismatch")
    if type(target) is ProviderCredentialTarget:
        action = target.action
        expected_action = "set" if kind is HumanCeremonyKind.PROVIDER_CREDENTIAL_SET else "rotate"
        if action != expected_action:
            raise ValueError("ceremony_target_mismatch")
    if type(target) is PrivacyPendingTarget:
        decision_kind = target.decision_kind
        expected_decision = (
            "policy" if kind is HumanCeremonyKind.PRIVACY_POLICY_DECISION else "disclosure"
        )
        if decision_kind != expected_decision:
            raise ValueError("ceremony_target_mismatch")


def monotonic_milliseconds(seconds: float) -> int:
    """Floor one finite nonnegative monotonic sample into JSON-safe milliseconds."""

    if type(seconds) is not float:
        raise ValueError("monotonic_sample_invalid")
    if seconds < 0.0 or seconds != seconds or seconds in {float("inf"), float("-inf")}:
        raise ValueError("monotonic_sample_invalid")
    milliseconds = int(seconds * 1_000)
    if not 0 <= milliseconds <= _MAX_SAFE_INTEGER:
        raise ValueError("monotonic_sample_invalid")
    return milliseconds


def new_binding_expiry_ms(seconds: float) -> int:
    issue_ms = monotonic_milliseconds(seconds)
    expiry_ms = issue_ms + CEREMONY_EXPIRY_SECONDS * 1_000
    if expiry_ms > _MAX_SAFE_INTEGER:
        raise ValueError("monotonic_sample_invalid")
    return expiry_ms


def validate_passphrase_buffer(value: memoryview) -> None:
    """Validate exact passphrase bytes without decoding to an immutable string."""

    view = _byte_view(value)
    try:
        if not PASSPHRASE_MIN_BYTES <= len(view) <= PASSPHRASE_MAX_BYTES:
            raise ConfidentialProtocolError("secret_rejected")
        _validate_utf8(view, forbid_controls=True)
    finally:
        if view is not value:
            view.release()


def validate_provider_credential_buffer(value: memoryview) -> None:
    """Apply only the generic confidential transport/storage credential guard."""

    view = _byte_view(value)
    try:
        if not 1 <= len(view) <= PROVIDER_CREDENTIAL_MAX_BYTES:
            raise ConfidentialProtocolError("secret_rejected")
        if any(byte in {0, 10, 13} for byte in view):
            raise ConfidentialProtocolError("secret_rejected")
    finally:
        if view is not value:
            view.release()


def _byte_view(value: memoryview) -> memoryview:
    if type(value) is not memoryview or value.ndim != 1 or not value.contiguous:
        raise TypeError("secret_buffer_invalid")
    if value.format == "B":
        return value
    try:
        return value.cast("B")
    except (TypeError, ValueError) as exc:
        raise TypeError("secret_buffer_invalid") from exc


def _validate_utf8(view: memoryview, *, forbid_controls: bool) -> None:
    index = 0
    size = len(view)
    while index < size:
        first = view[index]
        if first <= 0x7F:
            if forbid_controls and first in {0, 10, 13}:
                raise ConfidentialProtocolError("secret_rejected")
            index += 1
            continue
        if 0xC2 <= first <= 0xDF:
            width, second_min, second_max = 2, 0x80, 0xBF
        elif first == 0xE0:
            width, second_min, second_max = 3, 0xA0, 0xBF
        elif 0xE1 <= first <= 0xEC or 0xEE <= first <= 0xEF:
            width, second_min, second_max = 3, 0x80, 0xBF
        elif first == 0xED:
            width, second_min, second_max = 3, 0x80, 0x9F
        elif first == 0xF0:
            width, second_min, second_max = 4, 0x90, 0xBF
        elif 0xF1 <= first <= 0xF3:
            width, second_min, second_max = 4, 0x80, 0xBF
        elif first == 0xF4:
            width, second_min, second_max = 4, 0x80, 0x8F
        else:
            raise ConfidentialProtocolError("secret_rejected")
        if index + width > size or not second_min <= view[index + 1] <= second_max:
            raise ConfidentialProtocolError("secret_rejected")
        if any(not 0x80 <= view[index + offset] <= 0xBF for offset in range(2, width)):
            raise ConfidentialProtocolError("secret_rejected")
        index += width


def encode_human_frame(envelope: HumanEnvelope) -> bytes:
    frame_type, payload = _human_to_json(envelope)
    encoded = canonical_encode(cast(JsonValue, payload))
    if len(encoded) > MAX_HUMAN_CONTROL_FRAME_BYTES:
        raise ConfidentialProtocolError("frame_too_large")
    return (
        _HUMAN_HEADER.pack(
            HUMAN_PROTOCOL_MAGIC,
            HUMAN_PROTOCOL_VERSION,
            int(frame_type),
            len(encoded),
        )
        + encoded
    )


def decode_human_frame(data: bytes | bytearray) -> HumanEnvelope:
    if type(data) not in {bytes, bytearray}:
        raise TypeError("human_frame_invalid")
    if len(data) < _HUMAN_HEADER.size:
        raise ConfidentialProtocolError("invalid_frame")
    magic, version, raw_type, payload_length = _HUMAN_HEADER.unpack_from(data)
    if magic != HUMAN_PROTOCOL_MAGIC or version != HUMAN_PROTOCOL_VERSION:
        raise ConfidentialProtocolError("protocol_mismatch")
    if payload_length > MAX_HUMAN_CONTROL_FRAME_BYTES:
        raise ConfidentialProtocolError("frame_too_large")
    if len(data) != _HUMAN_HEADER.size + payload_length:
        raise ConfidentialProtocolError("invalid_frame")
    try:
        frame_type = _HumanFrameType(raw_type)
    except ValueError as exc:
        raise ConfidentialProtocolError("invalid_frame") from exc
    payload_bytes = bytes(data[_HUMAN_HEADER.size :])
    try:
        parsed = strict_json_parse(payload_bytes)
        if canonical_encode(parsed) != payload_bytes or type(parsed) is not dict:
            raise ConfidentialProtocolError("invalid_frame")
        return _human_from_json(frame_type, cast(dict[str, JsonValue], parsed))
    except ConfidentialProtocolError:
        raise
    except (ProtocolValueError, TypeError, ValueError, KeyError) as exc:
        raise ConfidentialProtocolError("invalid_frame") from exc


def encode_secret_header(binding: SecretIngressBinding, secret_length: int) -> bytes:
    if type(binding) is not SecretIngressBinding:
        raise TypeError("secret_binding_invalid")
    if type(secret_length) is not int or not 1 <= secret_length <= MAX_SECRET_BYTES:
        raise ConfidentialProtocolError("secret_rejected")
    binding_bytes = canonical_encode(cast(JsonValue, _binding_to_json(binding)))
    if not 1 <= len(binding_bytes) <= MAX_SECRET_BINDING_BYTES:
        raise ConfidentialProtocolError("frame_too_large")
    return (
        _SECRET_HEADER.pack(
            SECRET_PROTOCOL_MAGIC,
            SECRET_PROTOCOL_VERSION,
            int(binding.purpose),
            len(binding_bytes),
            secret_length,
        )
        + binding_bytes
    )


def decode_secret_header(data: bytes | bytearray) -> tuple[SecretIngressBinding, int]:
    if type(data) not in {bytes, bytearray} or len(data) < _SECRET_HEADER.size:
        raise ConfidentialProtocolError("invalid_frame")
    magic, version, raw_purpose, binding_length, secret_length = _SECRET_HEADER.unpack_from(data)
    if magic != SECRET_PROTOCOL_MAGIC or version != SECRET_PROTOCOL_VERSION:
        raise ConfidentialProtocolError("protocol_mismatch")
    if not 1 <= binding_length <= MAX_SECRET_BINDING_BYTES:
        raise ConfidentialProtocolError("frame_too_large")
    if not 1 <= secret_length <= MAX_SECRET_BYTES:
        raise ConfidentialProtocolError("secret_rejected")
    if len(data) != _SECRET_HEADER.size + binding_length:
        raise ConfidentialProtocolError("invalid_frame")
    try:
        purpose = ConfidentialSecretPurpose(raw_purpose)
        raw = bytes(data[_SECRET_HEADER.size :])
        parsed = strict_json_parse(raw)
        if canonical_encode(parsed) != raw or type(parsed) is not dict:
            raise ConfidentialProtocolError("binding_invalid")
        binding = _binding_from_json(cast(dict[str, JsonValue], parsed))
        if binding.purpose is not purpose:
            raise ConfidentialProtocolError("binding_invalid")
        return binding, secret_length
    except ConfidentialProtocolError:
        raise
    except (ProtocolValueError, TypeError, ValueError, KeyError) as exc:
        raise ConfidentialProtocolError("binding_invalid") from exc


def human_target_json(target: HumanOpenTarget) -> dict[str, JsonValue]:
    """The one canonical JSON shape for a human ceremony target.

    The service session binding digest, the wire encoding, and the trusted client's preview
    verification must all hash exactly these bytes; a second hand-maintained copy of this
    serialization is how the client ends up rejecting its own valid preview.
    """
    if type(target) is EmptyVaultTarget:
        return {"expected_mode": target.expected_mode, "kind": target.kind}
    if type(target) is PortableRecoveryTarget:
        return {
            "confirmed_plan_digest": target.confirmed_plan_digest,
            "kind": target.kind,
            "operation": target.operation,
            "request_id": target.request_id,
        }
    if type(target) is InstallationRecoveryTarget:
        return {
            "confirmed_plan_digest": target.confirmed_plan_digest,
            "kind": target.kind,
            "operation": target.operation,
            "recovery_generation": target.recovery_generation,
            "request_id": target.request_id,
            "secret_kind": target.secret_kind,
            "set_mode": target.set_mode,
            "target_envelope": target.target_envelope,
        }
    if type(target) is ProviderCredentialTarget:
        return {
            "action": target.action,
            "endpoint_profile_id": target.endpoint_profile_id,
            "endpoint_profile_version": target.endpoint_profile_version,
            "kind": target.kind,
            "model_id": target.model_id,
            "provider_id": target.provider_id,
            "purpose": target.purpose,
            "purpose_digest": target.purpose_digest,
            "repository_privacy_commitment": target.repository_privacy_commitment,
            "scope_digest": target.scope_digest,
        }
    if type(target) is PrivacyPendingTarget:
        return {
            "decision_kind": target.decision_kind,
            "kind": target.kind,
            "pending_id": target.pending_id,
        }
    if type(target) is IdleRelockPolicyTarget:
        result: dict[str, JsonValue] = {"kind": target.kind, "operation": target.operation}
        if target.seconds is not None:
            result["seconds"] = target.seconds
        return result
    if type(target) is OwnerReceiptViewTarget:
        return {
            "control_connection_digest": target.control_connection_digest,
            "format": target.format,
            "include": target.include,
            "kind": target.kind,
            "receipt_request_id": target.receipt_request_id,
            "redaction_profile": target.redaction_profile,
            "session_id": target.session_id,
            "task_id": target.task_id,
        }
    raise TypeError("human_target_invalid")


def _target_from_json(value: JsonValue) -> HumanOpenTarget:
    source = _closed_object(value)
    kind = source.get("kind")
    if kind == "vault":
        _keys(source, {"expected_mode", "kind"})
        return EmptyVaultTarget(
            expected_mode=cast(
                Literal["uninitialized", "os_keyring", "passphrase"], source["expected_mode"]
            )
        )
    if kind == "portable_recovery":
        _keys(source, {"confirmed_plan_digest", "kind", "operation", "request_id"})
        return PortableRecoveryTarget(
            operation=cast(Literal["create", "restore"], source["operation"]),
            request_id=cast(str, source["request_id"]),
            confirmed_plan_digest=cast(str, source["confirmed_plan_digest"]),
        )
    if kind == "installation_recovery":
        _keys(
            source,
            {
                "confirmed_plan_digest",
                "kind",
                "operation",
                "recovery_generation",
                "request_id",
                "secret_kind",
                "set_mode",
                "target_envelope",
            },
        )
        return InstallationRecoveryTarget(
            operation=cast(
                Literal["provision", "rotate", "revoke", "restore"],
                source["operation"],
            ),
            request_id=cast(str, source["request_id"]),
            confirmed_plan_digest=cast(str, source["confirmed_plan_digest"]),
            recovery_generation=cast(int, source["recovery_generation"]),
            set_mode=cast(Literal["compact", "self_contained"], source["set_mode"]),
            secret_kind=cast(
                Literal["generated_code", "argon2id_passphrase"],
                source["secret_kind"],
            ),
            target_envelope=cast(
                Literal["preserve", "passphrase", "platform_auto_unlock"],
                source["target_envelope"],
            ),
        )
    if kind == "provider_credential":
        _keys(
            source,
            {
                "action",
                "endpoint_profile_id",
                "endpoint_profile_version",
                "kind",
                "model_id",
                "provider_id",
                "purpose",
                "purpose_digest",
                "repository_privacy_commitment",
                "scope_digest",
            },
        )
        return ProviderCredentialTarget(
            action=cast(Literal["set", "rotate"], source["action"]),
            provider_id=cast(str, source["provider_id"]),
            model_id=cast(str, source["model_id"]),
            endpoint_profile_id=cast(str, source["endpoint_profile_id"]),
            endpoint_profile_version=cast(str, source["endpoint_profile_version"]),
            purpose=cast(str, source["purpose"]),
            scope_digest=cast(str, source["scope_digest"]),
            purpose_digest=cast(str, source["purpose_digest"]),
            repository_privacy_commitment=cast(str | None, source["repository_privacy_commitment"]),
        )
    if kind == "privacy_pending":
        _keys(source, {"decision_kind", "kind", "pending_id"})
        return PrivacyPendingTarget(
            decision_kind=cast(Literal["policy", "disclosure"], source["decision_kind"]),
            pending_id=cast(str, source["pending_id"]),
        )
    if kind == "idle_relock_policy":
        operation = cast(Literal["set", "disable"], source.get("operation"))
        expected = {"kind", "operation", "seconds"} if operation == "set" else {"kind", "operation"}
        _keys(source, expected)
        return IdleRelockPolicyTarget(
            operation=operation, seconds=cast(int | None, source.get("seconds"))
        )
    if kind == "owner_receipt_view":
        _keys(
            source,
            {
                "control_connection_digest",
                "format",
                "include",
                "kind",
                "receipt_request_id",
                "redaction_profile",
                "session_id",
                "task_id",
            },
        )
        return OwnerReceiptViewTarget(
            task_id=cast(str, source["task_id"]),
            session_id=cast(str, source["session_id"]),
            receipt_request_id=cast(str, source["receipt_request_id"]),
            format=cast(Literal["json", "markdown", "text"], source["format"]),
            include=cast(Literal["summary", "standard", "full"], source["include"]),
            redaction_profile=cast(
                Literal["full_local", "default_local_export", "redacted_share"],
                source["redaction_profile"],
            ),
            control_connection_digest=cast(str, source["control_connection_digest"]),
        )
    raise ValueError("human_target_invalid")


def _binding_to_json(binding: SecretIngressBinding) -> dict[str, JsonValue]:
    return {
        "binding_version": binding.binding_version,
        "ceremony_id": binding.ceremony_id,
        "expires_at_monotonic_ms": binding.expires_at_monotonic_ms,
        "policy_generation": binding.policy_generation,
        "purpose": binding.purpose.name.lower(),
        "secret_challenge": binding.secret_challenge,
        "service_generation": binding.service_generation,
        "service_instance_id": binding.service_instance_id,
        "target_digest": binding.target_digest,
        "vault_generation": binding.vault_generation,
    }


def _binding_from_json(value: JsonValue) -> SecretIngressBinding:
    source = _closed_object(value)
    _keys(
        source,
        {
            "binding_version",
            "ceremony_id",
            "expires_at_monotonic_ms",
            "policy_generation",
            "purpose",
            "secret_challenge",
            "service_generation",
            "service_instance_id",
            "target_digest",
            "vault_generation",
        },
    )
    try:
        purpose = ConfidentialSecretPurpose[str(cast(str, source["purpose"])).upper()]
    except KeyError as exc:
        raise ValueError("secret_binding_invalid") from exc
    return SecretIngressBinding(
        binding_version=cast(int, source["binding_version"]),
        ceremony_id=cast(str, source["ceremony_id"]),
        secret_challenge=cast(str, source["secret_challenge"]),
        purpose=purpose,
        service_instance_id=cast(str, source["service_instance_id"]),
        service_generation=cast(int, source["service_generation"]),
        vault_generation=cast(int, source["vault_generation"]),
        policy_generation=cast(int | None, source["policy_generation"]),
        target_digest=cast(str, source["target_digest"]),
        expires_at_monotonic_ms=cast(int, source["expires_at_monotonic_ms"]),
    )


def _ceremony_binding_to_json(value: HumanCeremonyBinding) -> dict[str, JsonValue]:
    return {
        "binding_version": value.binding_version,
        "ceremony_id": value.ceremony_id,
        "ceremony_kind": value.ceremony_kind.value,
        "connection_nonce": value.connection_nonce,
        "expires_at_monotonic_ms": value.expires_at_monotonic_ms,
        "policy_generation": value.policy_generation,
        "service_generation": value.service_generation,
        "service_instance_id": value.service_instance_id,
        "target_digest": value.target_digest,
        "vault_generation": value.vault_generation,
    }


def _ceremony_binding_from_json(value: JsonValue) -> HumanCeremonyBinding:
    source = _closed_object(value)
    _keys(
        source,
        {
            "binding_version",
            "ceremony_id",
            "ceremony_kind",
            "connection_nonce",
            "expires_at_monotonic_ms",
            "policy_generation",
            "service_generation",
            "service_instance_id",
            "target_digest",
            "vault_generation",
        },
    )
    return HumanCeremonyBinding(
        binding_version=cast(int, source["binding_version"]),
        ceremony_id=cast(str, source["ceremony_id"]),
        connection_nonce=cast(str, source["connection_nonce"]),
        ceremony_kind=HumanCeremonyKind(cast(str, source["ceremony_kind"])),
        service_instance_id=cast(str, source["service_instance_id"]),
        service_generation=cast(int, source["service_generation"]),
        vault_generation=cast(int, source["vault_generation"]),
        policy_generation=cast(int | None, source["policy_generation"]),
        target_digest=cast(str, source["target_digest"]),
        expires_at_monotonic_ms=cast(int, source["expires_at_monotonic_ms"]),
    )


def _human_to_json(envelope: HumanEnvelope) -> tuple[_HumanFrameType, dict[str, JsonValue]]:
    if type(envelope) is ClientOpenEnvelope:
        return _HumanFrameType.CLIENT_OPEN, {
            "ceremony_kind": envelope.ceremony_kind.value,
            "connection_nonce": envelope.connection_nonce,
            "protocol_version": envelope.protocol_version,
            "target": human_target_json(envelope.target),
        }
    if type(envelope) is ServerOpenedEnvelope:
        return _HumanFrameType.SERVER_OPENED, {
            "binding": _ceremony_binding_to_json(envelope.binding),
            "ceremony_id": envelope.ceremony_id,
            "phase": _phase_to_json(envelope.phase),
            "preview": _preview_to_json(envelope.preview),
            "step": envelope.step,
        }
    if type(envelope) is ClientActionEnvelope:
        return _HumanFrameType.CLIENT_ACTION, {
            "action": _action_to_json(envelope.action),
            "ceremony_id": envelope.ceremony_id,
            "step": envelope.step,
        }
    if type(envelope) is ServerPhaseEnvelope:
        return _HumanFrameType.SERVER_PHASE, {
            "ceremony_id": envelope.ceremony_id,
            "phase": _phase_to_json(envelope.phase),
            "step": envelope.step,
        }
    if type(envelope) is ServerResultEnvelope:
        return _HumanFrameType.SERVER_RESULT, {
            "ceremony_id": envelope.ceremony_id,
            "result": _result_to_json(envelope.result),
            "step": envelope.step,
        }
    if type(envelope) is ServerErrorEnvelope:
        payload: dict[str, JsonValue] = {"code": envelope.code, "retryable": envelope.retryable}
        if envelope.ceremony_id is not None:
            payload["ceremony_id"] = envelope.ceremony_id
            payload["step"] = envelope.step
        return _HumanFrameType.SERVER_ERROR, payload
    if type(envelope) is ClientCancelEnvelope:
        return _HumanFrameType.CLIENT_CANCEL, {
            "ceremony_id": envelope.ceremony_id,
            "step": envelope.step,
        }
    if type(envelope) is ServerCloseEnvelope:
        return _HumanFrameType.SERVER_CLOSE, {
            "ceremony_id": envelope.ceremony_id,
            "outcome": envelope.outcome,
            "step": envelope.step,
        }
    raise TypeError("human_envelope_invalid")


def _human_from_json(frame_type: _HumanFrameType, source: dict[str, JsonValue]) -> HumanEnvelope:
    if frame_type is _HumanFrameType.CLIENT_OPEN:
        _keys(source, {"ceremony_kind", "connection_nonce", "protocol_version", "target"})
        return ClientOpenEnvelope(
            connection_nonce=cast(str, source["connection_nonce"]),
            ceremony_kind=HumanCeremonyKind(cast(str, source["ceremony_kind"])),
            target=_target_from_json(source["target"]),
            protocol_version=cast(int, source["protocol_version"]),
        )
    if frame_type is _HumanFrameType.SERVER_OPENED:
        _keys(source, {"binding", "ceremony_id", "phase", "preview", "step"})
        return ServerOpenedEnvelope(
            ceremony_id=cast(str, source["ceremony_id"]),
            step=cast(int, source["step"]),
            binding=_ceremony_binding_from_json(source["binding"]),
            preview=_preview_from_json(source["preview"]),
            phase=_phase_from_json(source["phase"]),
        )
    if frame_type is _HumanFrameType.CLIENT_ACTION:
        _keys(source, {"action", "ceremony_id", "step"})
        return ClientActionEnvelope(
            ceremony_id=cast(str, source["ceremony_id"]),
            step=cast(int, source["step"]),
            action=_action_from_json(source["action"]),
        )
    if frame_type is _HumanFrameType.SERVER_PHASE:
        _keys(source, {"ceremony_id", "phase", "step"})
        return ServerPhaseEnvelope(
            ceremony_id=cast(str, source["ceremony_id"]),
            step=cast(int, source["step"]),
            phase=_phase_from_json(source["phase"]),
        )
    if frame_type is _HumanFrameType.SERVER_RESULT:
        _keys(source, {"ceremony_id", "result", "step"})
        return ServerResultEnvelope(
            ceremony_id=cast(str, source["ceremony_id"]),
            step=cast(int, source["step"]),
            result=_result_from_json(source["result"]),
        )
    if frame_type is _HumanFrameType.SERVER_ERROR:
        if "ceremony_id" in source:
            _keys(source, {"ceremony_id", "code", "retryable", "step"})
        else:
            _keys(source, {"code", "retryable"})
        return ServerErrorEnvelope(
            code=cast(str, source["code"]),
            retryable=cast(bool, source["retryable"]),
            ceremony_id=cast(str | None, source.get("ceremony_id")),
            step=cast(int | None, source.get("step")),
        )
    if frame_type is _HumanFrameType.CLIENT_CANCEL:
        _keys(source, {"ceremony_id", "step"})
        return ClientCancelEnvelope(
            ceremony_id=cast(str, source["ceremony_id"]), step=cast(int, source["step"])
        )
    _keys(source, {"ceremony_id", "outcome", "step"})
    return ServerCloseEnvelope(
        ceremony_id=cast(str, source["ceremony_id"]),
        step=cast(int, source["step"]),
        outcome=cast(Literal["completed", "cancelled", "failed"], source["outcome"]),
    )


def _change_value_to_json(value: PrivacyPolicyChangeValue) -> dict[str, JsonValue]:
    return {
        "count": value.count,
        "flag": value.flag,
        "kind": value.kind,
        "labels": list(value.labels),
    }


def _change_value_from_json(value: JsonValue) -> PrivacyPolicyChangeValue:
    source = _closed_object(value)
    _keys(source, {"count", "flag", "kind", "labels"})
    labels = source["labels"]
    if type(labels) is not list:
        raise ValueError("privacy_policy_preview_invalid")
    try:
        return PrivacyPolicyChangeValue(
            kind=cast(Literal["none", "flag", "count", "labels"], source["kind"]),
            flag=cast(bool | None, source["flag"]),
            count=cast(int | None, source["count"]),
            labels=tuple(cast(list[str], labels)),
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("privacy_policy_preview_invalid") from exc


def _change_to_json(value: PrivacyPolicyChange) -> dict[str, JsonValue]:
    return {
        "after": _change_value_to_json(value.after),
        "area": value.area,
        "before": _change_value_to_json(value.before),
        "field": value.field,
        "subject": value.subject,
        "widens": value.widens,
    }


def _change_from_json(value: JsonValue) -> PrivacyPolicyChange:
    source = _closed_object(value)
    _keys(source, {"after", "area", "before", "field", "subject", "widens"})
    area = source["area"]
    field = source["field"]
    # Reject an unknown area or field before constructing, so a peer cannot smuggle a token the
    # trusted renderer has no fixed label for onto an approval screen.
    if type(area) is not str or area not in PRIVACY_CHANGE_AREAS:
        raise ValueError("privacy_policy_preview_invalid")
    if type(field) is not str or field not in PRIVACY_CHANGE_FIELDS[area]:
        raise ValueError("privacy_policy_preview_invalid")
    subject = source["subject"]
    if subject is not None and type(subject) is not str:
        raise ValueError("privacy_policy_preview_invalid")
    try:
        return PrivacyPolicyChange(
            area=cast(
                Literal[
                    "global", "review", "channel", "local_model", "agent_context", "human_control"
                ],
                area,
            ),
            field=field,
            subject=subject,
            before=_change_value_from_json(source["before"]),
            after=_change_value_from_json(source["after"]),
            widens=cast(bool, source["widens"]),
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("privacy_policy_preview_invalid") from exc


def _privacy_preview_member_to_json(
    value: PrivacyPolicyTransitionPreviewMember,
) -> dict[str, JsonValue]:
    return {
        "action": value.action,
        "authority": value.authority,
        "changes": [_change_to_json(change) for change in value.changes],
    }


def _privacy_preview_member_from_json(value: JsonValue) -> PrivacyPolicyTransitionPreviewMember:
    source = _closed_object(value)
    _keys(source, {"action", "authority", "changes"})
    raw_changes = source["changes"]
    if type(raw_changes) is not list:
        raise ValueError("privacy_policy_preview_invalid")
    try:
        return PrivacyPolicyTransitionPreviewMember(
            authority=cast(Literal["machine_ceiling", "repository_grant"], source["authority"]),
            action=cast(Literal["replace", "insert"], source["action"]),
            changes=tuple(_change_from_json(item) for item in cast(list[JsonValue], raw_changes)),
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("privacy_policy_preview_invalid") from exc


def _preview_to_json(value: HumanPreview) -> dict[str, JsonValue]:
    if type(value) is VaultInitializePreview:
        return {
            "irreversible": value.irreversible,
            "kind": value.kind,
            "selected_mode": value.selected_mode,
        }
    if type(value) is VaultPassphraseRotatePreview:
        return {"current_mode": value.current_mode, "kind": value.kind}
    if type(value) is VaultUnlockPreview:
        return {"current_mode": value.current_mode, "kind": value.kind}
    if type(value) is KeyringRetryPreview:
        return {"kind": value.kind, "operation": value.operation}
    if type(value) is PortableRecoveryPreview:
        return {
            "confirmed_plan_digest": value.confirmed_plan_digest,
            "content_commitment": value.content_commitment,
            "item_count": value.item_count,
            "kind": value.kind,
            "location_commitment": value.location_commitment,
            "operation": value.operation,
            "request_id": value.request_id,
            "total_bytes": value.total_bytes,
        }
    if type(value) is InstallationRecoveryPreview:
        return {
            "confirmed_plan_digest": value.confirmed_plan_digest,
            "item_count": value.item_count,
            "kind": value.kind,
            "native_prompt_available": value.native_prompt_available,
            "operation": value.operation,
            "recovery_generation": value.recovery_generation,
            "request_id": value.request_id,
            "secret_kind": value.secret_kind,
            "set_mode": value.set_mode,
            "target_envelope": value.target_envelope,
            "total_bytes": value.total_bytes,
        }
    if type(value) in {ProviderCredentialSetPreview, ProviderCredentialRotatePreview}:
        provider = cast(ProviderCredentialSetPreview | ProviderCredentialRotatePreview, value)
        return {"kind": provider.kind, "target": human_target_json(provider.target)}
    if type(value) is PrivacyPolicyDecisionPreview:
        encoded: dict[str, JsonValue] = {
            "diff_digest": value.diff_digest,
            "kind": value.kind,
            "pending_id": value.pending_id,
        }
        if value.members:
            encoded["members"] = [
                _privacy_preview_member_to_json(member) for member in value.members
            ]
        else:
            encoded["changes"] = [_change_to_json(change) for change in value.changes]
        return encoded
    if type(value) is PrivacyDisclosureDecisionPreview:
        return {
            "authorization_change": value.authorization_change,
            "byte_count": value.byte_count,
            "category": value.category,
            "destination_commitment": value.destination_commitment,
            "excerpt_digest": value.excerpt_digest,
            "excerpt_preview": value.excerpt_preview,
            "kind": value.kind,
            "pending_id": value.pending_id,
            "policy_digest": value.policy_digest,
            "token_count": value.token_count,
        }
    if type(value) is IdleRelockPolicyChangePreview:
        return {
            "current": value.current,
            "kind": value.kind,
            "proposed": value.proposed,
            "service_generation": value.service_generation,
            "target_digest": value.target_digest,
        }
    if type(value) is OwnerReceiptViewPreview:
        return {
            "format": value.format,
            "grant_seconds": value.grant_seconds,
            "kind": value.kind,
            "redaction_profile": value.redaction_profile,
            "target_digest": value.target_digest,
            "task_id": value.task_id,
        }
    raise TypeError("human_preview_invalid")


def _preview_from_json(value: JsonValue) -> HumanPreview:
    source = _closed_object(value)
    kind = source.get("kind")
    if kind == "vault_initialize":
        _keys(source, {"irreversible", "kind", "selected_mode"})
        return VaultInitializePreview(
            selected_mode=cast(Literal["passphrase"], source["selected_mode"]),
            irreversible=cast(Literal[True], source["irreversible"]),
        )
    if kind == "vault_passphrase_rotate":
        _keys(source, {"current_mode", "kind"})
        return VaultPassphraseRotatePreview(
            current_mode=cast(Literal["passphrase"], source["current_mode"]),
            kind=cast(Literal["vault_passphrase_rotate"], kind),
        )
    if kind == "vault_unlock":
        _keys(source, {"current_mode", "kind"})
        return VaultUnlockPreview(current_mode=cast(Literal["passphrase"], source["current_mode"]))
    if kind == "keyring_retry":
        _keys(source, {"kind", "operation"})
        return KeyringRetryPreview(
            operation=cast(Literal["pristine_create", "existing_load"], source["operation"])
        )
    if kind == "portable_recovery":
        _keys(
            source,
            {
                "confirmed_plan_digest",
                "content_commitment",
                "item_count",
                "kind",
                "location_commitment",
                "operation",
                "request_id",
                "total_bytes",
            },
        )
        return PortableRecoveryPreview(
            operation=cast(Literal["create", "restore"], source["operation"]),
            request_id=cast(str, source["request_id"]),
            confirmed_plan_digest=cast(str, source["confirmed_plan_digest"]),
            location_commitment=cast(str, source["location_commitment"]),
            content_commitment=cast(str, source["content_commitment"]),
            item_count=cast(int, source["item_count"]),
            total_bytes=cast(int, source["total_bytes"]),
        )
    if kind == "installation_recovery":
        _keys(
            source,
            {
                "confirmed_plan_digest",
                "item_count",
                "kind",
                "native_prompt_available",
                "operation",
                "recovery_generation",
                "request_id",
                "secret_kind",
                "set_mode",
                "target_envelope",
                "total_bytes",
            },
        )
        return InstallationRecoveryPreview(
            operation=cast(
                Literal["provision", "rotate", "revoke", "restore"],
                source["operation"],
            ),
            request_id=cast(str, source["request_id"]),
            confirmed_plan_digest=cast(str, source["confirmed_plan_digest"]),
            recovery_generation=cast(int, source["recovery_generation"]),
            set_mode=cast(Literal["compact", "self_contained"], source["set_mode"]),
            secret_kind=cast(
                Literal["generated_code", "argon2id_passphrase"],
                source["secret_kind"],
            ),
            target_envelope=cast(
                Literal["preserve", "passphrase", "platform_auto_unlock"],
                source["target_envelope"],
            ),
            item_count=cast(int, source["item_count"]),
            total_bytes=cast(int, source["total_bytes"]),
            native_prompt_available=cast(bool, source["native_prompt_available"]),
        )
    if kind in {"provider_credential_set", "provider_credential_rotate"}:
        _keys(source, {"kind", "target"})
        target = _target_from_json(source["target"])
        if type(target) is not ProviderCredentialTarget:
            raise ValueError("human_preview_invalid")
        return (
            ProviderCredentialSetPreview(target)
            if kind == "provider_credential_set"
            else ProviderCredentialRotatePreview(target)
        )
    if kind == "privacy_policy_decision":
        if "members" in source:
            _keys(source, {"diff_digest", "kind", "members", "pending_id"})
            raw_members = source["members"]
            if type(raw_members) is not list:
                raise ValueError("privacy_policy_preview_invalid")
            return PrivacyPolicyDecisionPreview(
                pending_id=cast(str, source["pending_id"]),
                diff_digest=cast(str, source["diff_digest"]),
                changes=(),
                members=tuple(
                    _privacy_preview_member_from_json(item)
                    for item in cast(list[JsonValue], raw_members)
                ),
            )
        _keys(source, {"changes", "diff_digest", "kind", "pending_id"})
        raw_changes = source["changes"]
        if type(raw_changes) is not list:
            raise ValueError("privacy_policy_preview_invalid")
        return PrivacyPolicyDecisionPreview(
            pending_id=cast(str, source["pending_id"]),
            diff_digest=cast(str, source["diff_digest"]),
            changes=tuple(_change_from_json(item) for item in cast(list[JsonValue], raw_changes)),
        )
    if kind == "privacy_disclosure_decision":
        _keys(
            source,
            {
                "authorization_change",
                "byte_count",
                "category",
                "destination_commitment",
                "excerpt_digest",
                "excerpt_preview",
                "kind",
                "pending_id",
                "policy_digest",
                "token_count",
            },
        )
        return PrivacyDisclosureDecisionPreview(
            pending_id=cast(str, source["pending_id"]),
            excerpt_preview=cast(str, source["excerpt_preview"]),
            excerpt_digest=cast(str, source["excerpt_digest"]),
            category=cast(str, source["category"]),
            destination_commitment=cast(str, source["destination_commitment"]),
            byte_count=cast(int, source["byte_count"]),
            token_count=cast(int, source["token_count"]),
            policy_digest=cast(str, source["policy_digest"]),
            authorization_change=cast(Literal["none"], source["authorization_change"]),
        )
    if kind == "idle_relock_policy_change":
        _keys(source, {"current", "kind", "proposed", "service_generation", "target_digest"})
        return IdleRelockPolicyChangePreview(
            current=cast(IdlePolicyValue, source["current"]),
            proposed=cast(IdlePolicyValue, source["proposed"]),
            service_generation=cast(int, source["service_generation"]),
            target_digest=cast(str, source["target_digest"]),
        )
    if kind == "owner_receipt_view":
        _keys(
            source,
            {"format", "grant_seconds", "kind", "redaction_profile", "target_digest", "task_id"},
        )
        return OwnerReceiptViewPreview(
            task_id=cast(str, source["task_id"]),
            format=cast(Literal["json", "markdown", "text"], source["format"]),
            redaction_profile=cast(
                Literal["full_local", "default_local_export", "redacted_share"],
                source["redaction_profile"],
            ),
            grant_seconds=cast(int, source["grant_seconds"]),
            target_digest=cast(str, source["target_digest"]),
        )
    raise ValueError("human_preview_invalid")


def _action_to_json(value: HumanAction) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {"kind": value.kind}
    if type(value) is SelectAuthorizationSourceAction:
        result["source"] = value.source
    elif type(value) is DecisionAction:
        result["decision"] = value.decision
    return result


def _action_from_json(value: JsonValue) -> HumanAction:
    source = _closed_object(value)
    kind = source.get("kind")
    if kind == "retry":
        _keys(source, {"kind"})
        return RetryAction()
    if kind == "select_authorization_source":
        _keys(source, {"kind", "source"})
        return SelectAuthorizationSourceAction(
            cast(Literal["os_user_presence", "secret_reauthentication"], source["source"])
        )
    if kind == "decision":
        _keys(source, {"decision", "kind"})
        return DecisionAction(cast(Literal["approve", "deny"], source["decision"]))
    if kind == "cancel":
        _keys(source, {"kind"})
        return CancelAction()
    raise ValueError("human_action_invalid")


def _phase_to_json(value: HumanPhase) -> dict[str, JsonValue]:
    if type(value) is SecretRequiredPhase:
        return {"binding": _binding_to_json(value.binding), "kind": value.kind}
    if type(value) is AuthorizationRequiredPhase:
        return {"available_sources": list(value.available_sources), "kind": value.kind}
    if type(value) is KeyringRetryPhase:
        return {"kind": value.kind}
    if type(value) is DecisionRequiredPhase:
        return {"allowed_decisions": list(value.allowed_decisions), "kind": value.kind}
    raise TypeError("human_phase_invalid")


def _phase_from_json(value: JsonValue) -> HumanPhase:
    source = _closed_object(value)
    kind = source.get("kind")
    if kind == "secret_required":
        _keys(source, {"binding", "kind"})
        return SecretRequiredPhase(_binding_from_json(source["binding"]))
    if kind == "authorization_required":
        _keys(source, {"available_sources", "kind"})
        return AuthorizationRequiredPhase(
            tuple(
                cast(
                    list[Literal["os_user_presence", "secret_reauthentication"]],
                    source["available_sources"],
                )
            )
        )
    if kind == "keyring_retry":
        _keys(source, {"kind"})
        return KeyringRetryPhase()
    if kind == "decision_required":
        _keys(source, {"allowed_decisions", "kind"})
        return DecisionRequiredPhase(
            tuple(cast(list[Literal["approve", "deny"]], source["allowed_decisions"]))
        )
    raise ValueError("human_phase_invalid")


def _result_to_json(value: HumanResult) -> dict[str, JsonValue]:
    if type(value) is VaultStateResult:
        return {"kind": value.kind, "reason": value.reason, "state": value.state}
    if type(value) is KeyringRetryResult:
        return {"kind": value.kind, "reason": value.reason, "state": value.state}
    if type(value) is PortableRecoveryResult:
        return {
            "kind": value.kind,
            "operation": value.operation,
            "result_commitment": value.result_commitment,
            "status": value.status,
        }
    if type(value) is InstallationRecoveryResult:
        return {
            "kind": value.kind,
            "operation": value.operation,
            "recovery_generation": value.recovery_generation,
            "result_commitment": value.result_commitment,
            "status": value.status,
        }
    if type(value) is ProviderCredentialResult:
        return {
            "action": value.action,
            "activation_status": value.activation_status,
            "kind": value.kind,
            "stored_generation": value.stored_generation,
        }
    if type(value) is PrivacyDecisionResult:
        return {"commitment": value.commitment, "kind": value.kind, "status": value.status}
    if type(value) is IdleRelockPolicyResult:
        return {
            "effective": value.effective,
            "kind": value.kind,
            "previous": value.previous,
            "scope": value.scope,
            "service_generation": value.service_generation,
        }
    if type(value) is OwnerReceiptViewResult:
        return {
            "grant_seconds": value.grant_seconds,
            "kind": value.kind,
            "status": value.status,
            "target_digest": value.target_digest,
        }
    raise TypeError("human_result_invalid")


def _result_from_json(value: JsonValue) -> HumanResult:
    source = _closed_object(value)
    kind = source.get("kind")
    if kind == "vault_state":
        _keys(source, {"kind", "reason", "state"})
        return VaultStateResult(
            cast(Literal["locked", "ready"], source["state"]), cast(str, source["reason"])
        )
    if kind == "keyring_retry":
        _keys(source, {"kind", "reason", "state"})
        return KeyringRetryResult(
            cast(Literal["locked", "ready"], source["state"]), cast(str, source["reason"])
        )
    if kind == "portable_recovery":
        _keys(source, {"kind", "operation", "result_commitment", "status"})
        return PortableRecoveryResult(
            cast(Literal["create", "restore"], source["operation"]),
            cast(Literal["completed", "failed"], source["status"]),
            cast(str, source["result_commitment"]),
        )
    if kind == "installation_recovery":
        _keys(
            source,
            {"kind", "operation", "recovery_generation", "result_commitment", "status"},
        )
        return InstallationRecoveryResult(
            cast(
                Literal["provision", "rotate", "revoke", "restore"],
                source["operation"],
            ),
            cast(Literal["completed", "failed"], source["status"]),
            cast(int, source["recovery_generation"]),
            cast(str, source["result_commitment"]),
        )
    if kind == "provider_credential":
        _keys(source, {"action", "activation_status", "kind", "stored_generation"})
        return ProviderCredentialResult(
            cast(Literal["set", "rotate"], source["action"]),
            cast(int, source["stored_generation"]),
            cast(Literal["active", "local_only", "stored"], source["activation_status"]),
        )
    if kind == "privacy_decision":
        _keys(source, {"commitment", "kind", "status"})
        return PrivacyDecisionResult(
            cast(Literal["committed", "denied", "stale"], source["status"]),
            cast(str, source["commitment"]),
        )
    if kind == "idle_relock_policy":
        _keys(source, {"effective", "kind", "previous", "scope", "service_generation"})
        return IdleRelockPolicyResult(
            cast(IdlePolicyValue, source["previous"]),
            cast(IdlePolicyValue, source["effective"]),
            cast(int, source["service_generation"]),
            cast(Literal["service_generation"], source["scope"]),
        )
    if kind == "owner_receipt_view":
        _keys(source, {"grant_seconds", "kind", "status", "target_digest"})
        return OwnerReceiptViewResult(
            cast(Literal["authorized"], source["status"]),
            cast(str, source["target_digest"]),
            cast(int, source["grant_seconds"]),
        )
    raise ValueError("human_result_invalid")


def _closed_object(value: JsonValue) -> dict[str, JsonValue]:
    if type(value) is not dict:
        raise ValueError("closed_object_invalid")
    return cast(dict[str, JsonValue], value)


def _keys(source: dict[str, JsonValue], expected: set[str]) -> None:
    if set(source) != expected:
        raise ValueError("closed_object_invalid")
