"""Authenticated recovery artifacts for one installation vault root.

The artifact contains no path, installation identifier, provider binding, or plaintext key. The
caller proves the recovered IVK against the staged vault sentinel and encrypted recovery metadata
before it may switch authority.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import Enum
from threading import Lock
from typing import Final, Literal, Protocol, cast

from cryptography.hazmat.primitives import keywrap

from finishup.adapters.keys.vault_passphrase import (
    PASSPHRASE_KDF_MEMORY_KIB,
    PASSPHRASE_KDF_OUTPUT_BYTES,
    PASSPHRASE_KDF_PARALLELISM,
    PASSPHRASE_KDF_TIME_COST,
    PASSPHRASE_KDF_VERSION,
    PassphraseKdfParameters,
    VaultPassphraseError,
    derive_passphrase_subkeys,
    validate_passphrase_view,
)
from finishup.domain.values import validate_sha256_digest
from finishup.ports.secret_memory import SecretConsumer, SecretHandle, SecretPurpose
from finishup.protocol.canonical import JsonValue, canonical_encode, strict_json_parse
from finishup.protocol.errors import ProtocolValueError

__all__ = [
    "InstallationRecoveryArtifact",
    "InstallationRecoveryArtifactError",
    "InstallationRecoveryMaterial",
    "InstallationRecoveryMetadata",
    "InstallationRecoveryMode",
    "InstallationRecoverySecretKind",
    "create_installation_recovery_artifact",
    "generate_recovery_code",
    "unlock_installation_recovery_artifact",
    "validate_generated_recovery_code",
]


class InstallationRecoveryMode(str, Enum):  # noqa: UP042 - exact durable spelling
    COMPACT = "compact"
    SELF_CONTAINED = "self_contained"


class InstallationRecoverySecretKind(str, Enum):  # noqa: UP042 - exact durable spelling
    GENERATED_CODE = "generated_code"
    ARGON2ID_PASSPHRASE = "argon2id_passphrase"


_FORMAT: Final = "yoetz-installation-recovery/1"
_WRAP_INFO: Final = b"yoetz/installation-recovery-wrap/v1"
_AUTH_INFO: Final = b"yoetz/installation-recovery-auth/v1"
_AUTH_DOMAIN: Final = b"yoetz/installation-recovery-envelope/v1\x00"
_MAX_ARTIFACT_BYTES: Final = 16_384
_B64URL_PATTERN: Final = re.compile(r"^[A-Za-z0-9_-]+$", re.ASCII)
_GENERATED_CODE_PATTERN: Final = re.compile(rb"^YRK1-(?:[A-Z2-7]{4}-){8}[A-Z2-7]{4}$", re.ASCII)
_GENERATED_CODE_RANDOM_BYTES: Final = 20
_GENERATED_CODE_CHECKSUM_BYTES: Final = 2

_ERROR_REASONS: Final = frozenset(
    {
        "artifact_invalid",
        "artifact_too_large",
        "format_unsupported",
        "generation_invalid",
        "mode_invalid",
        "secret_invalid",
        "secret_or_artifact_invalid",
        "secret_purpose_mismatch",
        "snapshot_binding_invalid",
        "stale_handle",
        "vault_root_invalid",
    }
)


class InstallationRecoveryArtifactError(Exception):
    """Bounded artifact failure with no secret-, path-, or input-derived text."""

    __slots__ = ("reason",)

    reason: str

    def __init__(self, reason: str) -> None:
        if type(reason) is not str or reason not in _ERROR_REASONS:
            raise TypeError("installation_recovery_reason_invalid")
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True, slots=True, repr=False)
class InstallationRecoveryArtifact:
    canonical_bytes: bytes

    def __post_init__(self) -> None:
        _parse_artifact(self.canonical_bytes)

    @property
    def artifact_digest(self) -> str:
        return f"sha256:{hashlib.sha256(self.canonical_bytes).hexdigest()}"

    def __repr__(self) -> str:
        return "<InstallationRecoveryArtifact redacted>"


class InstallationRecoveryMaterial(Protocol):
    recovery_generation: int
    mode: InstallationRecoveryMode
    secret_kind: InstallationRecoverySecretKind
    snapshot_manifest_digest: str | None

    def consume_ivk[T](self, fn: Callable[[memoryview], T]) -> T: ...


@dataclass(frozen=True, slots=True)
class InstallationRecoveryMetadata:
    recovery_generation: int
    mode: InstallationRecoveryMode
    secret_kind: InstallationRecoverySecretKind
    artifact_digest: str
    snapshot_manifest_digest: str | None

    def __post_init__(self) -> None:
        _validate_public_binding(
            self.recovery_generation,
            self.mode,
            self.secret_kind,
            self.snapshot_manifest_digest,
        )
        try:
            validate_sha256_digest(self.artifact_digest)
        except (TypeError, ValueError) as exc:
            raise InstallationRecoveryArtifactError("artifact_invalid") from exc

    def canonical_bytes(self) -> bytes:
        return canonical_encode(
            {
                "artifact_digest": self.artifact_digest,
                "format": "yoetz-installation-recovery-metadata/1",
                "mode": self.mode.value,
                "recovery_generation": self.recovery_generation,
                "secret_kind": self.secret_kind.value,
                "snapshot_manifest_digest": self.snapshot_manifest_digest,
            }
        )

    @classmethod
    def parse(cls, data: bytes) -> InstallationRecoveryMetadata:
        try:
            value = strict_json_parse(data)
            if canonical_encode(value) != data or type(value) is not dict:
                raise InstallationRecoveryArtifactError("artifact_invalid")
            source = cast(dict[str, JsonValue], value)
            if (
                set(source)
                != {
                    "artifact_digest",
                    "format",
                    "mode",
                    "recovery_generation",
                    "secret_kind",
                    "snapshot_manifest_digest",
                }
                or source["format"] != "yoetz-installation-recovery-metadata/1"
            ):
                raise InstallationRecoveryArtifactError("artifact_invalid")
            return cls(
                recovery_generation=_positive_int(source["recovery_generation"]),
                mode=InstallationRecoveryMode(_required_str(source["mode"])),
                secret_kind=InstallationRecoverySecretKind(_required_str(source["secret_kind"])),
                artifact_digest=_required_str(source["artifact_digest"]),
                snapshot_manifest_digest=_optional_digest(source["snapshot_manifest_digest"]),
            )
        except InstallationRecoveryArtifactError:
            raise
        except (ProtocolValueError, TypeError, ValueError) as exc:
            raise InstallationRecoveryArtifactError("artifact_invalid") from exc


def generate_recovery_code() -> bytearray:
    """Return a 160-bit, checksummed code in a mutable buffer for protected display."""

    random_part = os.urandom(_GENERATED_CODE_RANDOM_BYTES)
    payload = base64.b32encode(random_part).rstrip(b"=")
    checksum = base64.b32encode(hashlib.sha256(random_part).digest()[:2]).rstrip(b"=")
    compact = payload + checksum
    groups = [compact[offset : offset + 4] for offset in range(0, len(compact), 4)]
    code = bytearray(b"YRK1-" + b"-".join(groups))
    validate_generated_recovery_code(memoryview(code))
    return code


def validate_generated_recovery_code(secret: memoryview) -> None:
    if secret.ndim != 1 or not secret.contiguous:
        raise InstallationRecoveryArtifactError("secret_invalid")
    raw = bytes(secret)
    if _GENERATED_CODE_PATTERN.fullmatch(raw) is None:
        raise InstallationRecoveryArtifactError("secret_invalid")
    compact = raw.removeprefix(b"YRK1-").replace(b"-", b"")
    if len(compact) != 36:
        raise InstallationRecoveryArtifactError("secret_invalid")
    try:
        payload = base64.b32decode(compact[:32], casefold=False)
    except binascii.Error as exc:
        raise InstallationRecoveryArtifactError("secret_invalid") from exc
    expected = base64.b32encode(hashlib.sha256(payload).digest()[:2]).rstrip(b"=")
    if not hmac.compare_digest(expected, compact[32:]):
        raise InstallationRecoveryArtifactError("secret_invalid")


def create_installation_recovery_artifact(
    ivk_handle: SecretHandle,
    recovery_secret: SecretHandle,
    *,
    recovery_generation: int,
    mode: InstallationRecoveryMode,
    secret_kind: InstallationRecoverySecretKind,
    snapshot_manifest_digest: str | None,
) -> InstallationRecoveryArtifact:
    """Consume one exact IVK and recovery secret to create a versioned artifact."""

    _validate_public_binding(recovery_generation, mode, secret_kind, snapshot_manifest_digest)
    if ivk_handle.purpose is not SecretPurpose.VAULT_ROOT_KEY:
        raise InstallationRecoveryArtifactError("secret_purpose_mismatch")
    if recovery_secret.purpose is not SecretPurpose.INSTALLATION_RECOVERY:
        raise InstallationRecoveryArtifactError("secret_purpose_mismatch")
    salt = os.urandom(32)

    def _with_ivk(ivk_view: memoryview) -> InstallationRecoveryArtifact:
        if ivk_view.nbytes != 32:
            raise InstallationRecoveryArtifactError("vault_root_invalid")

        def _with_secret(secret_view: memoryview) -> InstallationRecoveryArtifact:
            _validate_secret(secret_view, secret_kind)
            secret_copy = bytearray(secret_view)
            try:
                parameters = PassphraseKdfParameters(
                    algorithm="argon2id",
                    memory_kib=PASSPHRASE_KDF_MEMORY_KIB,
                    output_bytes=PASSPHRASE_KDF_OUTPUT_BYTES,
                    parallelism=PASSPHRASE_KDF_PARALLELISM,
                    salt=salt,
                    time_cost=PASSPHRASE_KDF_TIME_COST,
                    version=PASSPHRASE_KDF_VERSION,
                )
                wrap_key, auth_key = derive_passphrase_subkeys(
                    secret_copy, parameters, _WRAP_INFO, _AUTH_INFO
                )
                try:
                    body = _artifact_body(
                        recovery_generation=recovery_generation,
                        mode=mode,
                        secret_kind=secret_kind,
                        snapshot_manifest_digest=snapshot_manifest_digest,
                        parameters=parameters,
                        wrapped_ivk=keywrap.aes_key_wrap(bytes(wrap_key), bytes(ivk_view)),
                    )
                    tag = hmac.digest(auth_key, _AUTH_DOMAIN + canonical_encode(body), "sha256")
                    envelope = dict(body)
                    envelope["auth_algorithm"] = "hmac-sha256"
                    envelope["auth_tag"] = _b64url_encode(tag)
                    return InstallationRecoveryArtifact(canonical_encode(envelope))
                finally:
                    _overwrite(wrap_key)
                    _overwrite(auth_key)
            finally:
                _overwrite(secret_copy)

        return recovery_secret.consume(SecretConsumer.INSTALLATION_RECOVERY, _with_secret)

    return ivk_handle.consume(SecretConsumer.VAULT_ROOT, _with_ivk)


def unlock_installation_recovery_artifact(
    artifact: InstallationRecoveryArtifact,
    recovery_secret: SecretHandle,
) -> InstallationRecoveryMaterial:
    """Authenticate and unwrap one artifact into a one-shot opaque IVK handle."""

    if recovery_secret.purpose is not SecretPurpose.INSTALLATION_RECOVERY:
        raise InstallationRecoveryArtifactError("secret_purpose_mismatch")
    parsed = _parse_artifact(artifact.canonical_bytes)

    def _with_secret(secret_view: memoryview) -> InstallationRecoveryMaterial:
        _validate_secret(secret_view, parsed.secret_kind)
        secret_copy = bytearray(secret_view)
        try:
            wrap_key, auth_key = derive_passphrase_subkeys(
                secret_copy, parsed.parameters, _WRAP_INFO, _AUTH_INFO
            )
            try:
                expected = hmac.digest(auth_key, _AUTH_DOMAIN + parsed.body_bytes, "sha256")
                if not hmac.compare_digest(expected, parsed.auth_tag):
                    raise InstallationRecoveryArtifactError("secret_or_artifact_invalid")
                try:
                    ivk = keywrap.aes_key_unwrap(bytes(wrap_key), parsed.wrapped_ivk)
                except keywrap.InvalidUnwrap as exc:
                    raise InstallationRecoveryArtifactError("secret_or_artifact_invalid") from exc
                if len(ivk) != 32:
                    raise InstallationRecoveryArtifactError("secret_or_artifact_invalid")
                return _OneShotInstallationRecoveryMaterial(
                    bytearray(ivk),
                    parsed.recovery_generation,
                    parsed.mode,
                    parsed.secret_kind,
                    parsed.snapshot_manifest_digest,
                )
            finally:
                _overwrite(wrap_key)
                _overwrite(auth_key)
        finally:
            _overwrite(secret_copy)

    return recovery_secret.consume(SecretConsumer.INSTALLATION_RECOVERY, _with_secret)


@dataclass(frozen=True, slots=True)
class _ParsedArtifact:
    recovery_generation: int
    mode: InstallationRecoveryMode
    secret_kind: InstallationRecoverySecretKind
    snapshot_manifest_digest: str | None
    parameters: PassphraseKdfParameters
    wrapped_ivk: bytes = field(repr=False)
    auth_tag: bytes = field(repr=False)
    body_bytes: bytes = field(repr=False)


def _parse_artifact(data: bytes) -> _ParsedArtifact:
    if type(data) is not bytes or not data:
        raise InstallationRecoveryArtifactError("artifact_invalid")
    if len(data) > _MAX_ARTIFACT_BYTES:
        raise InstallationRecoveryArtifactError("artifact_too_large")
    try:
        value = strict_json_parse(data)
        if canonical_encode(value) != data or type(value) is not dict:
            raise InstallationRecoveryArtifactError("format_unsupported")
        source = cast(dict[str, JsonValue], value)
        if set(source) != {
            "auth_algorithm",
            "auth_tag",
            "binding",
            "format",
            "kdf",
            "wrap_algorithm",
            "wrapped_ivk",
        }:
            raise InstallationRecoveryArtifactError("format_unsupported")
        if (
            source["auth_algorithm"] != "hmac-sha256"
            or source["format"] != _FORMAT
            or source["wrap_algorithm"] != "aes-256-kw-rfc3394"
        ):
            raise InstallationRecoveryArtifactError("format_unsupported")
        binding = _exact_mapping(
            source["binding"],
            {"mode", "recovery_generation", "secret_kind", "snapshot_manifest_digest"},
        )
        recovery_generation = _positive_int(binding["recovery_generation"])
        mode = InstallationRecoveryMode(_required_str(binding["mode"]))
        secret_kind = InstallationRecoverySecretKind(_required_str(binding["secret_kind"]))
        snapshot = _optional_digest(binding["snapshot_manifest_digest"])
        _validate_public_binding(recovery_generation, mode, secret_kind, snapshot)
        kdf = _exact_mapping(
            source["kdf"],
            {
                "algorithm",
                "memory_kib",
                "output_bytes",
                "parallelism",
                "salt",
                "time_cost",
                "version",
            },
        )
        parameters = PassphraseKdfParameters(
            algorithm=_required_str(kdf["algorithm"]),
            memory_kib=_required_int(kdf["memory_kib"]),
            output_bytes=_required_int(kdf["output_bytes"]),
            parallelism=_required_int(kdf["parallelism"]),
            salt=_b64url_decode(kdf["salt"], 32),
            time_cost=_required_int(kdf["time_cost"]),
            version=_required_int(kdf["version"]),
        )
        wrapped_ivk = _b64url_decode(source["wrapped_ivk"], 40)
        auth_tag = _b64url_decode(source["auth_tag"], 32)
        body = _artifact_body(
            recovery_generation=recovery_generation,
            mode=mode,
            secret_kind=secret_kind,
            snapshot_manifest_digest=snapshot,
            parameters=parameters,
            wrapped_ivk=wrapped_ivk,
        )
        return _ParsedArtifact(
            recovery_generation,
            mode,
            secret_kind,
            snapshot,
            parameters,
            wrapped_ivk,
            auth_tag,
            canonical_encode(body),
        )
    except InstallationRecoveryArtifactError:
        raise
    except (ProtocolValueError, VaultPassphraseError, ValueError, TypeError) as exc:
        raise InstallationRecoveryArtifactError("format_unsupported") from exc


def _artifact_body(
    *,
    recovery_generation: int,
    mode: InstallationRecoveryMode,
    secret_kind: InstallationRecoverySecretKind,
    snapshot_manifest_digest: str | None,
    parameters: PassphraseKdfParameters,
    wrapped_ivk: bytes,
) -> dict[str, JsonValue]:
    return {
        "binding": {
            "mode": mode.value,
            "recovery_generation": recovery_generation,
            "secret_kind": secret_kind.value,
            "snapshot_manifest_digest": snapshot_manifest_digest,
        },
        "format": _FORMAT,
        "kdf": parameters.canonical_value(),
        "wrap_algorithm": "aes-256-kw-rfc3394",
        "wrapped_ivk": _b64url_encode(wrapped_ivk),
    }


def _validate_public_binding(
    recovery_generation: int,
    mode: InstallationRecoveryMode,
    secret_kind: InstallationRecoverySecretKind,
    snapshot_manifest_digest: str | None,
) -> None:
    if (
        type(recovery_generation) is not int
        or not 1 <= recovery_generation <= 9_007_199_254_740_991
    ):
        raise InstallationRecoveryArtifactError("generation_invalid")
    if type(mode) is not InstallationRecoveryMode:
        raise InstallationRecoveryArtifactError("mode_invalid")
    if type(secret_kind) is not InstallationRecoverySecretKind:
        raise InstallationRecoveryArtifactError("secret_invalid")
    if mode is InstallationRecoveryMode.COMPACT and snapshot_manifest_digest is not None:
        raise InstallationRecoveryArtifactError("snapshot_binding_invalid")
    if mode is InstallationRecoveryMode.SELF_CONTAINED and snapshot_manifest_digest is None:
        raise InstallationRecoveryArtifactError("snapshot_binding_invalid")
    if snapshot_manifest_digest is not None:
        try:
            validate_sha256_digest(snapshot_manifest_digest)
        except (TypeError, ValueError) as exc:
            raise InstallationRecoveryArtifactError("snapshot_binding_invalid") from exc


def _validate_secret(secret: memoryview, kind: InstallationRecoverySecretKind) -> None:
    try:
        if kind is InstallationRecoverySecretKind.GENERATED_CODE:
            validate_generated_recovery_code(secret)
        else:
            validate_passphrase_view(secret)
    except (InstallationRecoveryArtifactError, VaultPassphraseError) as exc:
        raise InstallationRecoveryArtifactError("secret_invalid") from exc


def _exact_mapping(value: JsonValue, keys: set[str]) -> dict[str, JsonValue]:
    if type(value) is not dict:
        raise InstallationRecoveryArtifactError("format_unsupported")
    source = cast(dict[str, JsonValue], value)
    if set(source) != keys:
        raise InstallationRecoveryArtifactError("format_unsupported")
    return source


def _required_str(value: JsonValue) -> str:
    if type(value) is not str:
        raise InstallationRecoveryArtifactError("format_unsupported")
    return value


def _required_int(value: JsonValue) -> int:
    if type(value) is not int:
        raise InstallationRecoveryArtifactError("format_unsupported")
    return value


def _positive_int(value: JsonValue) -> int:
    result = _required_int(value)
    if not 1 <= result <= 9_007_199_254_740_991:
        raise InstallationRecoveryArtifactError("generation_invalid")
    return result


def _optional_digest(value: JsonValue) -> str | None:
    if value is None:
        return None
    if type(value) is not str:
        raise InstallationRecoveryArtifactError("snapshot_binding_invalid")
    try:
        return validate_sha256_digest(value)
    except (TypeError, ValueError) as exc:
        raise InstallationRecoveryArtifactError("snapshot_binding_invalid") from exc


def _b64url_encode(value: bytes | bytearray) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: JsonValue, expected_length: int) -> bytes:
    if type(value) is not str or not value or _B64URL_PATTERN.fullmatch(value) is None:
        raise InstallationRecoveryArtifactError("format_unsupported")
    padding = "=" * (-len(value) % 4)
    try:
        decoded = base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise InstallationRecoveryArtifactError("format_unsupported") from exc
    if len(decoded) != expected_length or _b64url_encode(decoded) != value:
        raise InstallationRecoveryArtifactError("format_unsupported")
    return decoded


def _overwrite(value: bytearray) -> None:
    value[:] = b"\x00" * len(value)


@dataclass(slots=True)
class _OneShotInstallationRecoveryMaterial:
    _ivk: bytearray = field(repr=False)
    recovery_generation: int
    mode: InstallationRecoveryMode
    secret_kind: InstallationRecoverySecretKind
    snapshot_manifest_digest: str | None
    _consumed: bool = field(default=False, init=False, repr=False)
    _lock: Lock = field(default_factory=Lock, init=False, repr=False)

    def consume_ivk[T](self, fn: Callable[[memoryview], T]) -> T:
        with self._lock:
            if self._consumed:
                raise InstallationRecoveryArtifactError("stale_handle")
            self._consumed = True
            try:
                return fn(memoryview(self._ivk))
            finally:
                _overwrite(self._ivk)

    def __copy__(self) -> _OneShotInstallationRecoveryMaterial:
        raise TypeError("installation_recovery_material_not_copyable")

    def __deepcopy__(self, memo: Mapping[int, object]) -> _OneShotInstallationRecoveryMaterial:
        del memo
        raise TypeError("installation_recovery_material_not_copyable")

    def __reduce__(self) -> Literal["installation_recovery_material_not_serializable"]:
        raise TypeError("installation_recovery_material_not_serializable")
