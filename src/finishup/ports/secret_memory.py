"""Protected-memory and opaque secret-handle boundary."""

from __future__ import annotations

import math
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from threading import Lock
from typing import Literal, Protocol, cast, runtime_checkable

from finishup.domain.values import validate_sha256_digest
from finishup.protocol.canonical import JsonValue, canonical_digest
from finishup.protocol.ids import IdKind, validate_id

__all__ = [
    "HumanAuthorizationProof",
    "ProviderAttemptAuthBinding",
    "ProviderAuthTransportCallback",
    "ProviderCredentialHandle",
    "SecretConsumer",
    "SecretHandle",
    "SecretMemoryCapability",
    "SecretMemoryError",
    "SecretMemoryPort",
    "SecretPurpose",
    "UserPresenceAttestation",
    "UserPresenceCapability",
    "UserPresenceChallenge",
    "UserPresencePort",
]

_IDENTITY_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$", re.ASCII)
_PROFILE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._/-]{0,127}$", re.ASCII)
_MODEL_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$", re.ASCII)
_VERSION_PATTERN = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+-]{0,127}$", re.ASCII)
_PURPOSE_PATTERN = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$", re.ASCII)


class SecretPurpose(str, Enum):  # noqa: UP042 - exact internal enum base
    VAULT_INITIALIZE = "vault_initialize"
    VAULT_UNLOCK = "vault_unlock"
    VAULT_ROOT_KEY = "vault_root_key"
    PORTABLE_RECOVERY = "portable_recovery"
    INSTALLATION_RECOVERY = "installation_recovery"
    VAULT_REWRAP = "vault_rewrap"
    OBJECT_PAYLOAD = "object_payload"
    PROVIDER_REAUTHENTICATION = "provider_reauthentication"
    PROVIDER_CREDENTIAL = "provider_credential"
    PRIVACY_REAUTHENTICATION = "privacy_reauthentication"
    SECURITY_REAUTHENTICATION = "security_reauthentication"


class SecretConsumer(str, Enum):  # noqa: UP042 - exact internal enum base
    VAULT_ROOT = "vault_root"
    RECOVERY_WRAPPER = "recovery_wrapper"
    INSTALLATION_RECOVERY = "installation_recovery"
    VAULT_REWRAPPER = "vault_rewrapper"
    OBJECT_CRYPTO = "object_crypto"
    PROVIDER_AUTHORIZER = "provider_authorizer"
    PRIVACY_AUTHORIZER = "privacy_authorizer"
    SECURITY_AUTHORIZER = "security_authorizer"


type SecretMemoryCapabilityState = Literal["supported", "active", "unavailable"]

_SECRET_MEMORY_CAPABILITY_STATES = frozenset({"supported", "active", "unavailable"})


@dataclass(frozen=True, slots=True)
class SecretMemoryCapability:
    bounded_mutable_allocation: SecretMemoryCapabilityState
    page_locking: SecretMemoryCapabilityState
    core_dump_suppression: SecretMemoryCapabilityState
    one_shot_consumption: SecretMemoryCapabilityState
    best_effort_overwrite: SecretMemoryCapabilityState

    def __post_init__(self) -> None:
        for value in (
            self.bounded_mutable_allocation,
            self.page_locking,
            self.core_dump_suppression,
            self.one_shot_consumption,
            self.best_effort_overwrite,
        ):
            if type(value) is not str or value not in _SECRET_MEMORY_CAPABILITY_STATES:
                raise ValueError("secret_memory_capability_state_invalid")


class SecretHandle(Protocol):
    """A nonserializable, one-shot protected allocation."""

    @property
    def purpose(self) -> SecretPurpose: ...

    def consume[T](
        self,
        consumer: SecretConsumer,
        fn: Callable[[memoryview], T],
    ) -> T: ...


class SecretMemoryPort(Protocol):
    def capability(self) -> SecretMemoryCapability: ...

    def capture(self, purpose: SecretPurpose, source: bytearray) -> SecretHandle: ...

    def allocate(self, purpose: SecretPurpose, size: int) -> SecretHandle: ...

    def close(self) -> None: ...


class ProviderAuthTransportCallback[T](Protocol):
    async def inject_and_start(self, credential_view: memoryview) -> T: ...


@dataclass(frozen=True, slots=True)
class ProviderAttemptAuthBinding:
    provider_id: str
    model_id: str
    endpoint_profile_id: str
    endpoint_profile_version: str
    purpose: str
    authorization_scope_digest: str
    purpose_digest: str
    dispatch_id: str
    request_body_digest: str
    service_generation: int
    monotonic_deadline: float

    def __post_init__(self) -> None:
        if (
            type(self.provider_id) is not str
            or _IDENTITY_PATTERN.fullmatch(self.provider_id) is None
        ):
            raise ValueError("provider_id_invalid")
        if type(self.model_id) is not str or _MODEL_PATTERN.fullmatch(self.model_id) is None:
            raise ValueError("model_id_invalid")
        if (
            type(self.endpoint_profile_id) is not str
            or _IDENTITY_PATTERN.fullmatch(self.endpoint_profile_id) is None
        ):
            raise ValueError("endpoint_profile_id_invalid")
        if (
            type(self.endpoint_profile_version) is not str
            or _VERSION_PATTERN.fullmatch(self.endpoint_profile_version) is None
        ):
            raise ValueError("endpoint_profile_version_invalid")
        if (
            type(self.purpose) is not str
            or len(self.purpose) > 128
            or _PURPOSE_PATTERN.fullmatch(self.purpose) is None
        ):
            raise ValueError("provider_purpose_invalid")
        validate_sha256_digest(self.authorization_scope_digest)
        validate_sha256_digest(self.purpose_digest)
        expected_purpose_digest = canonical_digest(cast(JsonValue, {"purpose": self.purpose}))
        if self.purpose_digest != expected_purpose_digest:
            raise ValueError("provider_purpose_digest_mismatch")
        validate_id(IdKind.EGRESS_DISPATCH, self.dispatch_id)
        validate_sha256_digest(self.request_body_digest)
        if type(self.service_generation) is not int or self.service_generation <= 0:
            raise ValueError("service_generation_invalid")
        if (
            type(self.monotonic_deadline) is not float
            or not math.isfinite(self.monotonic_deadline)
            or self.monotonic_deadline < 0.0
        ):
            raise ValueError("provider_deadline_invalid")


@runtime_checkable
class ProviderCredentialHandle(Protocol):
    async def authorize_attempt[T](
        self,
        binding: ProviderAttemptAuthBinding,
        inject_and_start: ProviderAuthTransportCallback[T],
    ) -> T: ...


@dataclass(frozen=True, slots=True)
class UserPresenceChallenge:
    purpose: str
    ceremony_digest: str
    target_digest: str
    display_summary_digest: str
    service_generation: int
    vault_generation: int
    policy_generation: int | None
    expires_at_monotonic: float

    def __post_init__(self) -> None:
        if type(self.purpose) is not str or not self.purpose:
            raise ValueError("authorization_purpose_invalid")
        validate_sha256_digest(self.ceremony_digest)
        validate_sha256_digest(self.target_digest)
        validate_sha256_digest(self.display_summary_digest)
        if type(self.service_generation) is not int or self.service_generation <= 0:
            raise ValueError("service_generation_invalid")
        if type(self.vault_generation) is not int or self.vault_generation <= 0:
            raise ValueError("vault_generation_invalid")
        if self.policy_generation is not None and (
            type(self.policy_generation) is not int or self.policy_generation <= 0
        ):
            raise ValueError("policy_generation_invalid")
        if (
            type(self.expires_at_monotonic) is not float
            or not math.isfinite(self.expires_at_monotonic)
            or self.expires_at_monotonic < 0.0
        ):
            raise ValueError("presence_challenge_expiry_invalid")


class UserPresenceAttestation(Protocol):
    """Opaque one-use adapter result; it carries no generic approval boolean."""


type UserPresenceState = Literal["active", "unavailable"]

_USER_PRESENCE_STATES = frozenset({"active", "unavailable"})


@dataclass(frozen=True, slots=True)
class UserPresenceCapability:
    candidate_artifact_digest: str
    release_cell: str
    adapter_id: str
    profile_id: str
    os_authentication_primitive: str
    os_authenticated_prompt: UserPresenceState
    trusted_action_binding: UserPresenceState
    one_use_attestation: UserPresenceState
    available: UserPresenceState
    capability_evidence_digest: str

    def __post_init__(self) -> None:
        validate_sha256_digest(self.candidate_artifact_digest)
        if type(self.release_cell) is not str or not self.release_cell:
            raise ValueError("presence_release_cell_invalid")
        for value in (self.adapter_id, self.profile_id):
            if type(value) is not str or _PROFILE_PATTERN.fullmatch(value) is None:
                raise ValueError("presence_adapter_profile_invalid")
        if (
            type(self.os_authentication_primitive) is not str
            or not self.os_authentication_primitive
        ):
            raise ValueError("os_authentication_primitive_invalid")
        for state in (
            self.os_authenticated_prompt,
            self.trusted_action_binding,
            self.one_use_attestation,
            self.available,
        ):
            if type(state) is not str or state not in _USER_PRESENCE_STATES:
                raise ValueError("user_presence_state_invalid")
        validate_sha256_digest(self.capability_evidence_digest)


class UserPresencePort(Protocol):
    def capability(self) -> UserPresenceCapability: ...

    async def assert_presence(
        self,
        challenge: UserPresenceChallenge,
    ) -> UserPresenceAttestation: ...

    def consume(
        self,
        attestation: UserPresenceAttestation,
        challenge: UserPresenceChallenge,
    ) -> None: ...

    def close(self) -> None: ...


_SECRET_MEMORY_REASONS = frozenset(
    {
        "size_invalid",
        "purpose_mismatch",
        "consumer_forbidden",
        "already_consumed",
        "memory_lock_failed",
        "closed",
        "provider_binding_mismatch",
        "provider_body_digest_mismatch",
        "provider_deadline_expired",
        "provider_transport_forbidden",
        "presence_capability_unverified",
        "proof_binding_mismatch",
        "proof_expired",
        "internal_error",
    }
)


class SecretMemoryError(Exception):
    """A bounded protected-memory failure with no secret-derived text."""

    __slots__ = ("reason",)

    reason: str

    def __init__(self, reason: str) -> None:
        if type(reason) is not str or reason not in _SECRET_MEMORY_REASONS:
            raise TypeError("secret_memory_reason_invalid")
        self.reason = reason
        super().__init__(reason)


@dataclass(slots=True)
class _ConsumeLatch:
    consumed: bool = False
    lock: Lock = field(default_factory=Lock, repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class HumanAuthorizationProof:
    proof_id: str
    purpose: str
    target_digest: str
    service_generation: int
    vault_generation: int
    policy_generation: int | None
    issued_at_monotonic: float
    expires_at_monotonic: float
    _consume_latch: _ConsumeLatch = field(
        default_factory=_ConsumeLatch,
        init=False,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        if type(self.proof_id) is not str or not self.proof_id:
            raise ValueError("authorization_proof_id_invalid")
        if type(self.purpose) is not str or not self.purpose:
            raise ValueError("authorization_purpose_invalid")
        validate_sha256_digest(self.target_digest)
        if type(self.service_generation) is not int or self.service_generation <= 0:
            raise ValueError("service_generation_invalid")
        if type(self.vault_generation) is not int or self.vault_generation <= 0:
            raise ValueError("vault_generation_invalid")
        if self.policy_generation is not None and (
            type(self.policy_generation) is not int or self.policy_generation <= 0
        ):
            raise ValueError("policy_generation_invalid")
        if (
            type(self.issued_at_monotonic) is not float
            or type(self.expires_at_monotonic) is not float
            or not math.isfinite(self.issued_at_monotonic)
            or not math.isfinite(self.expires_at_monotonic)
            or self.issued_at_monotonic < 0.0
            or self.expires_at_monotonic <= self.issued_at_monotonic
        ):
            raise ValueError("authorization_expiry_invalid")

    def __copy__(self) -> HumanAuthorizationProof:
        raise TypeError("human_authorization_proof_not_copyable")

    def __deepcopy__(self, memo: dict[int, object]) -> HumanAuthorizationProof:
        del memo
        raise TypeError("human_authorization_proof_not_copyable")

    def __reduce__(self) -> str | tuple[object, ...]:
        raise TypeError("human_authorization_proof_not_serializable")

    def consume(
        self,
        expected_purpose: str,
        expected_target_digest: str,
        service_generation: int,
        vault_generation: int,
        policy_generation: int | None,
        now_monotonic: float,
    ) -> None:
        with self._consume_latch.lock:
            if self._consume_latch.consumed:
                raise SecretMemoryError("already_consumed")
            if expected_purpose != self.purpose:
                raise SecretMemoryError("purpose_mismatch")
            if (
                expected_target_digest != self.target_digest
                or service_generation != self.service_generation
                or vault_generation != self.vault_generation
                or policy_generation != self.policy_generation
            ):
                raise SecretMemoryError("proof_binding_mismatch")
            if (
                type(now_monotonic) is not float
                or not math.isfinite(now_monotonic)
                or now_monotonic < self.issued_at_monotonic
                or now_monotonic >= self.expires_at_monotonic
            ):
                raise SecretMemoryError("proof_expired")
            self._consume_latch.consumed = True
