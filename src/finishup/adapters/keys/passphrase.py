"""Portable passphrase recovery artifacts for one bundle BMK."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from threading import Lock
from typing import Final, cast

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
from finishup.ports.keys import (
    KeyStoreError,
    KeyStoreReason,
    RecoveryArtifact,
    RecoveryKeyMaterialHandle,
    RecoverySecret,
)
from finishup.ports.secret_memory import SecretConsumer, SecretPurpose
from finishup.protocol.canonical import JsonValue, canonical_encode, strict_json_parse
from finishup.protocol.errors import ProtocolValueError
from finishup.protocol.ids import IdKind, validate_id

__all__ = ["unlock_recovery_artifact", "wrap_recovery_artifact"]

_WRAP_INFO: Final = b"yoetz/recovery-wrap/v1"
_AUTH_INFO: Final = b"yoetz/recovery-auth/v1"
_AUTH_DOMAIN: Final = b"yoetz/portable-recovery-envelope/v1\x00"
_MAX_ARTIFACT_BYTES: Final = 16_384
_B64URL_PATTERN: Final = re.compile(r"^[A-Za-z0-9_-]+$", re.ASCII)


def wrap_recovery_artifact(
    key_material: RecoveryKeyMaterialHandle,
    recovery_secret: RecoverySecret,
    *,
    task_id: str,
    key_slot: str,
) -> RecoveryArtifact:
    """Consume one BMK handle and recovery secret to create a portable artifact."""

    _validate_binding(task_id, key_slot)
    if recovery_secret.purpose is not SecretPurpose.PORTABLE_RECOVERY:
        raise KeyStoreError(KeyStoreReason.RECOVERY_SECRET_WRONG)
    salt = os.urandom(32)

    def _with_bmk(bmk_view: memoryview) -> RecoveryArtifact:
        if bmk_view.nbytes != 32:
            raise KeyStoreError(KeyStoreReason.KEY_ID_MISMATCH)

        def _with_secret(secret_view: memoryview) -> RecoveryArtifact:
            try:
                validate_passphrase_view(secret_view)
            except VaultPassphraseError as exc:
                raise KeyStoreError(KeyStoreReason.RECOVERY_SECRET_WRONG) from exc
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
                    wrapped_bmk = keywrap.aes_key_wrap(bytes(wrap_key), bytes(bmk_view))
                    body: dict[str, JsonValue] = {
                        "binding": {"key_slot": key_slot, "task_id": task_id},
                        "format": "yoetz-portable-recovery/1",
                        "kdf": parameters.canonical_value(),
                        "wrap_algorithm": "aes-256-kw-rfc3394",
                        "wrapped_bmk": _b64url_encode(wrapped_bmk),
                    }
                    tag = hmac.digest(auth_key, _AUTH_DOMAIN + canonical_encode(body), "sha256")
                    envelope = dict(body)
                    envelope["auth_algorithm"] = "hmac-sha256"
                    envelope["auth_tag"] = _b64url_encode(tag)
                    canonical_bytes = canonical_encode(envelope)
                    return RecoveryArtifact(
                        canonical_bytes=canonical_bytes,
                        artifact_digest=f"sha256:{hashlib.sha256(canonical_bytes).hexdigest()}",
                    )
                finally:
                    _overwrite(wrap_key)
                    _overwrite(auth_key)
            finally:
                _overwrite(secret_copy)

        return recovery_secret.consume(SecretConsumer.RECOVERY_WRAPPER, _with_secret)

    return key_material.consume(_with_bmk)


def unlock_recovery_artifact(
    artifact: RecoveryArtifact,
    recovery_secret: RecoverySecret,
) -> RecoveryKeyMaterialHandle:
    """Authenticate and unwrap one portable artifact into an opaque BMK handle."""

    if recovery_secret.purpose is not SecretPurpose.PORTABLE_RECOVERY:
        raise KeyStoreError(KeyStoreReason.RECOVERY_SECRET_WRONG)
    parsed = _parse_artifact(artifact)

    def _with_secret(secret_view: memoryview) -> RecoveryKeyMaterialHandle:
        try:
            validate_passphrase_view(secret_view)
        except VaultPassphraseError as exc:
            raise KeyStoreError(KeyStoreReason.RECOVERY_SECRET_WRONG) from exc
        secret_copy = bytearray(secret_view)
        try:
            wrap_key, auth_key = derive_passphrase_subkeys(
                secret_copy,
                parsed.parameters,
                _WRAP_INFO,
                _AUTH_INFO,
            )
            try:
                expected = hmac.digest(auth_key, _AUTH_DOMAIN + parsed.body_bytes, "sha256")
                if not hmac.compare_digest(expected, parsed.auth_tag):
                    raise KeyStoreError(KeyStoreReason.RECOVERY_SECRET_WRONG)
                try:
                    bmk = keywrap.aes_key_unwrap(bytes(wrap_key), parsed.wrapped_bmk)
                except keywrap.InvalidUnwrap as exc:
                    raise KeyStoreError(KeyStoreReason.RECOVERY_ARTIFACT_TAMPERED) from exc
                if len(bmk) != 32:
                    raise KeyStoreError(KeyStoreReason.RECOVERY_ARTIFACT_TAMPERED)
                return _OneShotRecoveryKeyMaterial(bytearray(bmk))
            finally:
                _overwrite(wrap_key)
                _overwrite(auth_key)
        finally:
            _overwrite(secret_copy)

    return recovery_secret.consume(SecretConsumer.RECOVERY_WRAPPER, _with_secret)


@dataclass(frozen=True, slots=True)
class _ParsedArtifact:
    task_id: str
    key_slot: str
    parameters: PassphraseKdfParameters
    wrapped_bmk: bytes
    auth_tag: bytes
    body_bytes: bytes


def _parse_artifact(artifact: RecoveryArtifact) -> _ParsedArtifact:
    data = artifact.canonical_bytes
    if len(data) > _MAX_ARTIFACT_BYTES:
        raise KeyStoreError(KeyStoreReason.RECOVERY_FORMAT_UNSUPPORTED)
    try:
        value = strict_json_parse(data)
        if canonical_encode(value) != data or type(value) is not dict:
            raise KeyStoreError(KeyStoreReason.RECOVERY_FORMAT_UNSUPPORTED)
        source = cast(dict[str, JsonValue], value)
        if set(source) != {
            "auth_algorithm",
            "auth_tag",
            "binding",
            "format",
            "kdf",
            "wrap_algorithm",
            "wrapped_bmk",
        }:
            raise KeyStoreError(KeyStoreReason.RECOVERY_FORMAT_UNSUPPORTED)
        if (
            source["auth_algorithm"] != "hmac-sha256"
            or source["format"] != "yoetz-portable-recovery/1"
            or source["wrap_algorithm"] != "aes-256-kw-rfc3394"
        ):
            raise KeyStoreError(KeyStoreReason.RECOVERY_FORMAT_UNSUPPORTED)
        binding = _exact_mapping(source["binding"], {"key_slot", "task_id"})
        task_id = _required_str(binding["task_id"])
        key_slot = _required_str(binding["key_slot"])
        _validate_binding(task_id, key_slot)
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
        wrapped_bmk = _b64url_decode(source["wrapped_bmk"], 40)
        auth_tag = _b64url_decode(source["auth_tag"], 32)
        body: dict[str, JsonValue] = {
            "binding": binding,
            "format": "yoetz-portable-recovery/1",
            "kdf": kdf,
            "wrap_algorithm": "aes-256-kw-rfc3394",
            "wrapped_bmk": cast(str, source["wrapped_bmk"]),
        }
        return _ParsedArtifact(
            task_id,
            key_slot,
            parameters,
            wrapped_bmk,
            auth_tag,
            canonical_encode(body),
        )
    except KeyStoreError:
        raise
    except (ProtocolValueError, VaultPassphraseError, ValueError, TypeError) as exc:
        raise KeyStoreError(KeyStoreReason.RECOVERY_FORMAT_UNSUPPORTED) from exc


def _validate_binding(task_id: str, key_slot: str) -> None:
    try:
        validate_id(IdKind.TASK, task_id)
    except ProtocolValueError as exc:
        raise KeyStoreError(KeyStoreReason.KEY_ID_MISMATCH) from exc
    if (
        type(key_slot) is not str
        or not 1 <= len(key_slot) <= 128
        or not key_slot.isascii()
        or any(not (character.isalnum() or character in "._-") for character in key_slot)
    ):
        raise KeyStoreError(KeyStoreReason.KEY_ID_MISMATCH)


def _exact_mapping(value: JsonValue, keys: set[str]) -> dict[str, JsonValue]:
    if type(value) is not dict:
        raise KeyStoreError(KeyStoreReason.RECOVERY_FORMAT_UNSUPPORTED)
    result = cast(dict[str, JsonValue], value)
    if set(result) != keys:
        raise KeyStoreError(KeyStoreReason.RECOVERY_FORMAT_UNSUPPORTED)
    return result


def _required_str(value: JsonValue) -> str:
    if type(value) is not str:
        raise KeyStoreError(KeyStoreReason.RECOVERY_FORMAT_UNSUPPORTED)
    return value


def _required_int(value: JsonValue) -> int:
    if type(value) is not int:
        raise KeyStoreError(KeyStoreReason.RECOVERY_FORMAT_UNSUPPORTED)
    return value


def _b64url_encode(value: bytes | bytearray) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: JsonValue, expected_length: int) -> bytes:
    if type(value) is not str or not value or _B64URL_PATTERN.fullmatch(value) is None:
        raise KeyStoreError(KeyStoreReason.RECOVERY_FORMAT_UNSUPPORTED)
    padding = "=" * (-len(value) % 4)
    try:
        decoded = base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise KeyStoreError(KeyStoreReason.RECOVERY_FORMAT_UNSUPPORTED) from exc
    if len(decoded) != expected_length or _b64url_encode(decoded) != value:
        raise KeyStoreError(KeyStoreReason.RECOVERY_FORMAT_UNSUPPORTED)
    return decoded


def _overwrite(value: bytearray) -> None:
    value[:] = b"\x00" * len(value)


@dataclass(slots=True)
class _OneShotRecoveryKeyMaterial:
    _key: bytearray = field(repr=False)
    _consumed: bool = field(default=False, init=False, repr=False)
    _lock: Lock = field(default_factory=Lock, init=False, repr=False)

    def consume[T](self, fn: Callable[[memoryview], T]) -> T:
        with self._lock:
            if self._consumed:
                raise KeyStoreError(KeyStoreReason.STALE_KEY_HANDLE)
            self._consumed = True
            try:
                return fn(memoryview(self._key))
            finally:
                _overwrite(self._key)

    def __copy__(self) -> _OneShotRecoveryKeyMaterial:
        raise TypeError("recovery_key_material_not_copyable")

    def __deepcopy__(self, memo: Mapping[int, object]) -> _OneShotRecoveryKeyMaterial:
        del memo
        raise TypeError("recovery_key_material_not_copyable")

    def __reduce__(self) -> str | tuple[object, ...]:
        raise TypeError("recovery_key_material_not_serializable")
