"""Service-internal opaque key, MAC, and recovery-operation boundary."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import Literal, Protocol

from finishup.domain.values import validate_sha256_digest
from finishup.ports.secret_memory import SecretConsumer, SecretHandle, SecretPurpose
from finishup.protocol.canonical import canonical_encode, strict_json_parse

REPOSITORY_PRIVACY_MAC_DOMAIN = b"yoetz/repository-privacy/v1\x00"
LINEAGE_ATTACH_MAC_DOMAIN = b"yoetz/lineage-attach/v1\x00"
PROJECT_OPERATION_MAC_DOMAIN = b"yoetz/project-operation/v1\x00"

__all__ = [
    "BundleKeys",
    "KeyStoreError",
    "KeyStorePort",
    "KeyStoreReason",
    "LINEAGE_ATTACH_MAC_DOMAIN",
    "MacKeyHandle",
    "MacKeyPurpose",
    "PROJECT_OPERATION_MAC_DOMAIN",
    "RecoveryArtifact",
    "RecoveryKeyMaterialHandle",
    "RecoverySecret",
    "REPOSITORY_PRIVACY_MAC_DOMAIN",
    "WrapKeyHandle",
    "WrappedDek",
]


class MacKeyPurpose(str, Enum):  # noqa: UP042 - exact internal enum base
    BUNDLE_COMMITMENT = "bundle_commitment"
    CATALOG_LOOKUP = "catalog_lookup"
    LINEAGE_ATTACH = "lineage_attach"
    LOG_CORRELATION = "log_correlation"
    PRIVACY_AUDIT = "privacy_audit"


class WrapKeyHandle(Protocol):
    def wrap_dek(self, dek: SecretHandle) -> WrappedDek: ...

    def unwrap_dek(self, wrapped: WrappedDek) -> SecretHandle: ...


class MacKeyHandle(Protocol):
    def mac(self, domain: bytes, message: bytes) -> str: ...


@dataclass(frozen=True, slots=True)
class BundleKeys:
    key_slot: str
    wrap_key: WrapKeyHandle
    commitment_key: MacKeyHandle

    def __post_init__(self) -> None:
        if type(self.key_slot) is not str or not self.key_slot:
            raise ValueError("key_slot_invalid")


@dataclass(frozen=True, slots=True)
class WrappedDek:
    algorithm: Literal["aes-256-kw-rfc3394"]
    wrapped: bytes

    def __post_init__(self) -> None:
        if self.algorithm != "aes-256-kw-rfc3394":
            raise ValueError("wrapped_dek_algorithm_invalid")
        if type(self.wrapped) is not bytes or len(self.wrapped) != 40:
            raise ValueError("wrapped_dek_invalid")


class RecoverySecret(Protocol):
    @property
    def purpose(self) -> Literal[SecretPurpose.PORTABLE_RECOVERY]: ...

    def consume[T](
        self,
        consumer: SecretConsumer,
        fn: Callable[[memoryview], T],
    ) -> T: ...


class RecoveryKeyMaterialHandle(Protocol):
    """One-shot opaque BMK view available only to the recovery wrapper."""

    def consume[T](self, fn: Callable[[memoryview], T]) -> T: ...


@dataclass(frozen=True, slots=True)
class RecoveryArtifact:
    canonical_bytes: bytes
    artifact_digest: str

    def __post_init__(self) -> None:
        if (
            type(self.canonical_bytes) is not bytes
            or not self.canonical_bytes
            or len(self.canonical_bytes) > 16_384
        ):
            raise ValueError("recovery_artifact_bytes_invalid")
        parsed = strict_json_parse(self.canonical_bytes)
        if canonical_encode(parsed) != self.canonical_bytes:
            raise ValueError("recovery_artifact_not_canonical")
        validate_sha256_digest(self.artifact_digest)
        expected_digest = f"sha256:{hashlib.sha256(self.canonical_bytes).hexdigest()}"
        if self.artifact_digest != expected_digest:
            raise ValueError("recovery_artifact_digest_mismatch")


class KeyStoreReason(str, Enum):  # noqa: UP042 - exact bounded reason base
    VAULT_LOCKED = "vault_locked"
    KEY_MISSING = "key_missing"
    KEY_ID_MISMATCH = "key_id_mismatch"
    UNSUPPORTED_BACKEND = "unsupported_backend"
    BACKEND_UNVERIFIED = "backend_unverified"
    RECOVERY_ARTIFACT_MISSING = "recovery_artifact_missing"
    RECOVERY_SECRET_WRONG = "recovery_secret_wrong"
    RECOVERY_ARTIFACT_TAMPERED = "recovery_artifact_tampered"
    RECOVERY_FORMAT_UNSUPPORTED = "recovery_format_unsupported"
    MACHINE_BOUND_KEY_MISSING = "machine_bound_key_missing"
    RECOVERED_KEY_CANNOT_DECRYPT = "recovered_key_cannot_decrypt"
    STALE_KEY_HANDLE = "stale_key_handle"
    MAC_PURPOSE_MISMATCH = "mac_purpose_mismatch"
    MAC_DOMAIN_FORBIDDEN = "mac_domain_forbidden"


class KeyStoreError(Exception):
    """A bounded key-store failure with no key- or secret-derived text."""

    __slots__ = ("reason",)

    reason: KeyStoreReason

    def __init__(self, reason: KeyStoreReason) -> None:
        if type(reason) is not KeyStoreReason:
            raise TypeError("key_store_reason_invalid")
        self.reason = reason
        super().__init__(reason.value)


class KeyStorePort(Protocol):
    async def load_bundle_keys(self, bundle_id: str) -> BundleKeys: ...

    async def create_bundle_keys(self, bundle_id: str) -> BundleKeys: ...

    async def wrap_recovery(
        self,
        bundle_id: str,
        recovery_secret: RecoverySecret,
    ) -> RecoveryArtifact: ...

    def installation_mac_handle(self, purpose: MacKeyPurpose) -> MacKeyHandle: ...
