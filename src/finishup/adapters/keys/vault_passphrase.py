"""Authenticated passphrase envelope for an installation vault key."""

from __future__ import annotations

import base64
import binascii
import codecs
import hashlib
import hmac
import os
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from threading import Lock
from typing import Final, cast

from cryptography.hazmat.primitives import hashes, keywrap
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from finishup.ports.secret_memory import SecretConsumer, SecretHandle, SecretPurpose
from finishup.protocol.canonical import JsonValue, canonical_encode, strict_json_parse
from finishup.protocol.errors import ProtocolValueError
from finishup.protocol.ids import IdKind, validate_id

__all__ = [
    "PASSPHRASE_KDF_MEMORY_KIB",
    "PASSPHRASE_KDF_OUTPUT_BYTES",
    "PASSPHRASE_KDF_PARALLELISM",
    "PASSPHRASE_KDF_TIME_COST",
    "PASSPHRASE_KDF_VERSION",
    "PassphraseKdfParameters",
    "VaultPassphraseError",
    "VaultRootEnvelope",
    "create_vault_root_envelope",
    "derive_passphrase_subkeys",
    "rewrap_vault_root_envelope",
    "unlock_vault_root_envelope",
    "validate_kdf_parameters",
    "validate_passphrase_view",
]

PASSPHRASE_KDF_VERSION: Final = 19
PASSPHRASE_KDF_TIME_COST: Final = 3
PASSPHRASE_KDF_MEMORY_KIB: Final = 262_144
PASSPHRASE_KDF_PARALLELISM: Final = 1
PASSPHRASE_KDF_OUTPUT_BYTES: Final = 32

_MIN_SECRET_BYTES: Final = 16
_MAX_SECRET_BYTES: Final = 1_024
_MAX_ENVELOPE_BYTES: Final = 16_384
_KDF_SALT_BYTES: Final = 32
_WRAPPED_KEY_BYTES: Final = 40
_AUTH_TAG_BYTES: Final = 32
_SUBKEY_SALT: Final = b"yoetz/passphrase-subkey-root/v1"
_WRAP_INFO: Final = b"yoetz/vault-root-wrap/v1"
_AUTH_INFO: Final = b"yoetz/vault-root-auth/v1"
_AUTH_DOMAIN: Final = b"yoetz/vault-root-envelope/v1\x00"
_B64URL_PATTERN: Final = re.compile(r"^[A-Za-z0-9_-]+$", re.ASCII)

_VAULT_ERROR_REASONS: Final = frozenset(
    {
        "envelope_too_large",
        "envelope_invalid",
        "noncanonical_envelope",
        "unknown_envelope_field",
        "noncanonical_base64url",
        "kdf_parameter_out_of_range",
        "kdf_output_length_invalid",
        "kdf_version_invalid",
        "kdf_salt_length_invalid",
        "secret_length_invalid",
        "secret_encoding_invalid",
        "secret_character_forbidden",
        "secret_purpose_mismatch",
        "initialization_forbidden",
        "secret_or_artifact_invalid",
    }
)


class VaultPassphraseError(Exception):
    """A bounded failure which never includes secret-dependent text."""

    __slots__ = ("reason",)

    reason: str

    def __init__(self, reason: str) -> None:
        if type(reason) is not str or reason not in _VAULT_ERROR_REASONS:
            raise TypeError("vault_passphrase_reason_invalid")
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True, slots=True)
class PassphraseKdfParameters:
    algorithm: str
    memory_kib: int
    output_bytes: int
    parallelism: int
    salt: bytes = field(repr=False)
    time_cost: int
    version: int

    def __post_init__(self) -> None:
        validate_kdf_parameters(self)

    def canonical_value(self) -> dict[str, JsonValue]:
        return {
            "algorithm": self.algorithm,
            "memory_kib": self.memory_kib,
            "output_bytes": self.output_bytes,
            "parallelism": self.parallelism,
            "salt": _b64url_encode(self.salt),
            "time_cost": self.time_cost,
            "version": self.version,
        }


@dataclass(frozen=True, slots=True)
class VaultRootEnvelope:
    canonical_bytes: bytes = field(repr=False)

    def __post_init__(self) -> None:
        _parse_envelope(self.canonical_bytes)

    @property
    def artifact_digest(self) -> str:
        return f"sha256:{hashlib.sha256(self.canonical_bytes).hexdigest()}"


def validate_kdf_parameters(parameters: PassphraseKdfParameters) -> None:
    if parameters.algorithm != "argon2id":
        raise VaultPassphraseError("envelope_invalid")
    if type(parameters.version) is not int or parameters.version != PASSPHRASE_KDF_VERSION:
        raise VaultPassphraseError("kdf_version_invalid")
    if type(parameters.output_bytes) is not int or parameters.output_bytes != 32:
        raise VaultPassphraseError("kdf_output_length_invalid")
    if type(parameters.time_cost) is not int or not 1 <= parameters.time_cost <= 10:
        raise VaultPassphraseError("kdf_parameter_out_of_range")
    if type(parameters.memory_kib) is not int or not 65_536 <= parameters.memory_kib <= 1_048_576:
        raise VaultPassphraseError("kdf_parameter_out_of_range")
    if type(parameters.parallelism) is not int or not 1 <= parameters.parallelism <= 8:
        raise VaultPassphraseError("kdf_parameter_out_of_range")
    if type(parameters.salt) is not bytes or len(parameters.salt) != _KDF_SALT_BYTES:
        raise VaultPassphraseError("kdf_salt_length_invalid")


def validate_passphrase_view(secret: memoryview) -> None:
    """Validate exact passphrase bytes without normalization or replacement."""

    if not _MIN_SECRET_BYTES <= secret.nbytes <= _MAX_SECRET_BYTES:
        raise VaultPassphraseError("secret_length_invalid")
    decoder = codecs.getincrementaldecoder("utf-8")("strict")
    try:
        for offset in range(0, secret.nbytes, 64):
            text = decoder.decode(secret[offset : offset + 64], final=False)
            if "\x00" in text or "\n" in text or "\r" in text:
                raise VaultPassphraseError("secret_character_forbidden")
        tail = decoder.decode(b"", final=True)
        if "\x00" in tail or "\n" in tail or "\r" in tail:
            raise VaultPassphraseError("secret_character_forbidden")
    except UnicodeDecodeError as exc:
        raise VaultPassphraseError("secret_encoding_invalid") from exc


def create_vault_root_envelope(
    ivk_handle: SecretHandle,
    initialize_handle: SecretHandle,
    *,
    installation_id: str,
) -> VaultRootEnvelope:
    """Consume one initialization secret and wrap one exact 32-byte IVK."""

    return _wrap_vault_root_envelope(
        ivk_handle,
        initialize_handle,
        installation_id=installation_id,
        expected_purpose=SecretPurpose.VAULT_INITIALIZE,
        consumer=SecretConsumer.VAULT_ROOT,
    )


def rewrap_vault_root_envelope(
    ivk_handle: SecretHandle,
    rewrap_handle: SecretHandle,
    *,
    installation_id: str,
) -> VaultRootEnvelope:
    """Wrap a recovered exact IVK in a newly authenticated passphrase envelope."""

    return _wrap_vault_root_envelope(
        ivk_handle,
        rewrap_handle,
        installation_id=installation_id,
        expected_purpose=SecretPurpose.VAULT_REWRAP,
        consumer=SecretConsumer.VAULT_REWRAPPER,
    )


def _wrap_vault_root_envelope(
    ivk_handle: SecretHandle,
    passphrase_handle: SecretHandle,
    *,
    installation_id: str,
    expected_purpose: SecretPurpose,
    consumer: SecretConsumer,
) -> VaultRootEnvelope:

    validate_id(IdKind.INSTALLATION, installation_id)
    if ivk_handle.purpose is not SecretPurpose.VAULT_ROOT_KEY:
        raise VaultPassphraseError("secret_purpose_mismatch")
    if passphrase_handle.purpose is not expected_purpose:
        raise VaultPassphraseError("secret_purpose_mismatch")
    salt = os.urandom(_KDF_SALT_BYTES)

    def _with_ivk(ivk_view: memoryview) -> VaultRootEnvelope:
        if ivk_view.nbytes != 32:
            raise VaultPassphraseError("initialization_forbidden")

        def _with_secret(secret_view: memoryview) -> VaultRootEnvelope:
            validate_passphrase_view(secret_view)
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
                    wrapped_ivk = keywrap.aes_key_wrap(bytes(wrap_key), bytes(ivk_view))
                    body: dict[str, JsonValue] = {
                        "binding": {
                            "installation_id": installation_id,
                            "vault_mode": "passphrase",
                        },
                        "format": "yoetz-vault-root/1",
                        "kdf": parameters.canonical_value(),
                        "wrap_algorithm": "aes-256-kw-rfc3394",
                        "wrapped_ivk": _b64url_encode(wrapped_ivk),
                    }
                    body_bytes = canonical_encode(body)
                    tag = hmac.digest(auth_key, _AUTH_DOMAIN + body_bytes, "sha256")
                    envelope = dict(body)
                    envelope["auth_algorithm"] = "hmac-sha256"
                    envelope["auth_tag"] = _b64url_encode(tag)
                    return VaultRootEnvelope(canonical_encode(envelope))
                finally:
                    _overwrite(wrap_key)
                    _overwrite(auth_key)
            finally:
                _overwrite(secret_copy)

        return passphrase_handle.consume(consumer, _with_secret)

    return ivk_handle.consume(SecretConsumer.VAULT_ROOT, _with_ivk)


def unlock_vault_root_envelope(
    envelope: VaultRootEnvelope,
    unlock_handle: SecretHandle,
) -> SecretHandle:
    """Consume one unlock secret and return an opaque one-shot vault-root handle."""

    if unlock_handle.purpose is not SecretPurpose.VAULT_UNLOCK:
        raise VaultPassphraseError("secret_purpose_mismatch")
    parsed = _parse_envelope(envelope.canonical_bytes)

    def _with_secret(secret_view: memoryview) -> SecretHandle:
        validate_passphrase_view(secret_view)
        secret_copy = bytearray(secret_view)
        try:
            wrap_key, auth_key = derive_passphrase_subkeys(
                secret_copy,
                parsed.parameters,
                _WRAP_INFO,
                _AUTH_INFO,
            )
            try:
                expected_tag = hmac.digest(auth_key, _AUTH_DOMAIN + parsed.body_bytes, "sha256")
                if not hmac.compare_digest(expected_tag, parsed.auth_tag):
                    raise VaultPassphraseError("secret_or_artifact_invalid")
                try:
                    ivk = keywrap.aes_key_unwrap(bytes(wrap_key), parsed.wrapped_ivk)
                except keywrap.InvalidUnwrap as exc:
                    raise VaultPassphraseError("secret_or_artifact_invalid") from exc
                if len(ivk) != 32:
                    raise VaultPassphraseError("secret_or_artifact_invalid")
                return _OneShotVaultRootHandle(bytearray(ivk))
            finally:
                _overwrite(wrap_key)
                _overwrite(auth_key)
        finally:
            _overwrite(secret_copy)

    return unlock_handle.consume(SecretConsumer.VAULT_ROOT, _with_secret)


@dataclass(frozen=True, slots=True)
class _ParsedEnvelope:
    installation_id: str
    parameters: PassphraseKdfParameters
    wrapped_ivk: bytes
    auth_tag: bytes
    body_bytes: bytes


def _parse_envelope(data: bytes) -> _ParsedEnvelope:
    if type(data) is not bytes or not data:
        raise VaultPassphraseError("envelope_invalid")
    if len(data) > _MAX_ENVELOPE_BYTES:
        raise VaultPassphraseError("envelope_too_large")
    try:
        value = strict_json_parse(data)
    except ProtocolValueError as exc:
        raise VaultPassphraseError("envelope_invalid") from exc
    if canonical_encode(value) != data:
        raise VaultPassphraseError("noncanonical_envelope")
    if type(value) is not dict:
        raise VaultPassphraseError("envelope_invalid")
    source = cast(dict[str, JsonValue], value)
    expected_keys = {
        "auth_algorithm",
        "auth_tag",
        "binding",
        "format",
        "kdf",
        "wrap_algorithm",
        "wrapped_ivk",
    }
    if set(source) != expected_keys:
        raise VaultPassphraseError("unknown_envelope_field")
    if (
        source["auth_algorithm"] != "hmac-sha256"
        or source["format"] != "yoetz-vault-root/1"
        or source["wrap_algorithm"] != "aes-256-kw-rfc3394"
    ):
        raise VaultPassphraseError("envelope_invalid")
    binding = _exact_mapping(source["binding"], {"installation_id", "vault_mode"})
    if binding["vault_mode"] != "passphrase" or type(binding["installation_id"]) is not str:
        raise VaultPassphraseError("envelope_invalid")
    try:
        installation_id = validate_id(IdKind.INSTALLATION, binding["installation_id"])
    except ProtocolValueError as exc:
        raise VaultPassphraseError("envelope_invalid") from exc
    kdf = _exact_mapping(
        source["kdf"],
        {"algorithm", "memory_kib", "output_bytes", "parallelism", "salt", "time_cost", "version"},
    )
    parameters = PassphraseKdfParameters(
        algorithm=_required_str(kdf["algorithm"]),
        memory_kib=_required_int(kdf["memory_kib"]),
        output_bytes=_required_int(kdf["output_bytes"]),
        parallelism=_required_int(kdf["parallelism"]),
        salt=_b64url_decode(kdf["salt"], _KDF_SALT_BYTES),
        time_cost=_required_int(kdf["time_cost"]),
        version=_required_int(kdf["version"]),
    )
    wrapped_ivk = _b64url_decode(source["wrapped_ivk"], _WRAPPED_KEY_BYTES)
    auth_tag = _b64url_decode(source["auth_tag"], _AUTH_TAG_BYTES)
    body: dict[str, JsonValue] = {
        "binding": binding,
        "format": "yoetz-vault-root/1",
        "kdf": kdf,
        "wrap_algorithm": "aes-256-kw-rfc3394",
        "wrapped_ivk": cast(str, source["wrapped_ivk"]),
    }
    return _ParsedEnvelope(
        installation_id, parameters, wrapped_ivk, auth_tag, canonical_encode(body)
    )


def derive_passphrase_subkeys(
    secret: bytearray,
    parameters: PassphraseKdfParameters,
    wrap_info: bytes,
    auth_info: bytes,
) -> tuple[bytearray, bytearray]:
    argon_root = bytearray(
        Argon2id(
            salt=parameters.salt,
            length=parameters.output_bytes,
            iterations=parameters.time_cost,
            lanes=parameters.parallelism,
            memory_cost=parameters.memory_kib,
        ).derive(bytes(secret))
    )
    try:
        return (
            bytearray(
                HKDF(
                    algorithm=hashes.SHA256(), length=32, salt=_SUBKEY_SALT, info=wrap_info
                ).derive(bytes(argon_root))
            ),
            bytearray(
                HKDF(
                    algorithm=hashes.SHA256(), length=32, salt=_SUBKEY_SALT, info=auth_info
                ).derive(bytes(argon_root))
            ),
        )
    finally:
        _overwrite(argon_root)


def _exact_mapping(value: JsonValue, keys: set[str]) -> dict[str, JsonValue]:
    if type(value) is not dict:
        raise VaultPassphraseError("envelope_invalid")
    result = cast(dict[str, JsonValue], value)
    if set(result) != keys:
        raise VaultPassphraseError("unknown_envelope_field")
    return result


def _required_str(value: JsonValue) -> str:
    if type(value) is not str:
        raise VaultPassphraseError("envelope_invalid")
    return value


def _required_int(value: JsonValue) -> int:
    if type(value) is not int:
        raise VaultPassphraseError("envelope_invalid")
    return value


def _b64url_encode(value: bytes | bytearray) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: JsonValue, expected_length: int) -> bytes:
    if type(value) is not str or not value or _B64URL_PATTERN.fullmatch(value) is None:
        raise VaultPassphraseError("noncanonical_base64url")
    padding = "=" * (-len(value) % 4)
    try:
        decoded = base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise VaultPassphraseError("noncanonical_base64url") from exc
    if len(decoded) != expected_length or _b64url_encode(decoded) != value:
        raise VaultPassphraseError("noncanonical_base64url")
    return decoded


def _overwrite(value: bytearray) -> None:
    value[:] = b"\x00" * len(value)


@dataclass(slots=True)
class _OneShotVaultRootHandle:
    _secret: bytearray = field(repr=False)
    _consumed: bool = field(default=False, init=False, repr=False)
    _lock: Lock = field(default_factory=Lock, init=False, repr=False)

    @property
    def purpose(self) -> SecretPurpose:
        return SecretPurpose.VAULT_ROOT_KEY

    def consume[T](self, consumer: SecretConsumer, fn: Callable[[memoryview], T]) -> T:
        if consumer is not SecretConsumer.VAULT_ROOT:
            raise VaultPassphraseError("secret_purpose_mismatch")
        with self._lock:
            if self._consumed:
                raise VaultPassphraseError("secret_or_artifact_invalid")
            self._consumed = True
            try:
                return fn(memoryview(self._secret))
            finally:
                _overwrite(self._secret)

    def __copy__(self) -> _OneShotVaultRootHandle:
        raise TypeError("vault_root_handle_not_copyable")

    def __deepcopy__(self, memo: Mapping[int, object]) -> _OneShotVaultRootHandle:
        del memo
        raise TypeError("vault_root_handle_not_copyable")

    def __reduce__(self) -> str | tuple[object, ...]:
        raise TypeError("vault_root_handle_not_serializable")
