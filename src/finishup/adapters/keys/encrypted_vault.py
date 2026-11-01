"""Authenticated, generation-CAS encrypted vault records."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import re
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from threading import Lock
from typing import Final, cast

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, keywrap
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from finishup.config.paths import ensure_owner_only_dir
from finishup.domain.values import validate_sha256_digest
from finishup.ports.secret_memory import SecretConsumer, SecretHandle, SecretPurpose
from finishup.protocol.canonical import JsonValue, canonical_encode, strict_json_parse
from finishup.protocol.errors import ProtocolValueError
from finishup.protocol.ids import IdKind, validate_id

__all__ = [
    "EncryptedVaultError",
    "EncryptedVaultStore",
    "PreparedVaultRootRotation",
    "VaultRecordKind",
]

_FRAME_MAGIC: Final = b"YZV1"
_FRAME_VERSION: Final = 1
_MAX_HEADER_BYTES: Final = 16_384
_MAX_RECORD_BYTES: Final = 8_388_608
_LOCATOR_SALT: Final = b"yoetz/vault-internal-root/v1"
_LOCATOR_INFO: Final = b"yoetz/vault-record-locator/v1"
_BINDING_DOMAIN: Final = b"yoetz/vault-record-binding/v1\x00"
_INDEX_DOMAIN: Final = b"yoetz/vault-record-index/v1\x00"
_INDEX_AUTH_SALT: Final = b"yoetz/vault-index-auth-root/v1"
_INDEX_AUTH_INFO: Final = b"yoetz/vault-index-auth/v1"
_ROOT_STATE_DOMAIN: Final = b"yoetz/vault-root-state/v1\x00"
_ROOT_STATE_NAME: Final = "vault-root-state.yzr"
_ROOT_STATE_FORMAT: Final = "yoetz-vault-root-state/1"
_MAX_ROOT_STATE_BYTES: Final = 16_384
_IDENTITY = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$", re.ASCII)
_MODEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$", re.ASCII)
_PURPOSE = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$", re.ASCII)
_KEY_SLOT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$", re.ASCII)
_RECORD_ID = re.compile(r"^vrec_[0-9a-f]{64}$", re.ASCII)

_ERROR_REASONS: Final = frozenset(
    {
        "closed",
        "not_initialized",
        "already_initialized",
        "record_exists",
        "record_missing",
        "record_immutable",
        "record_binding_invalid",
        "record_generation_mismatch",
        "record_tampered",
        "index_tampered",
        "index_cas_mismatch",
        "unsafe_permissions",
        "io_failure",
    }
)


class VaultRecordKind(str, Enum):  # noqa: UP042 - closed on-disk spelling
    VAULT_SENTINEL = "vault_sentinel"
    BUNDLE_KEY = "bundle_key"
    PROVIDER_CREDENTIAL = "provider_credential"
    RECOVERY_METADATA = "recovery_metadata"


class EncryptedVaultError(Exception):
    __slots__ = ("reason",)

    reason: str

    def __init__(self, reason: str) -> None:
        if type(reason) is not str or reason not in _ERROR_REASONS:
            raise TypeError("encrypted_vault_reason_invalid")
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True, slots=True)
class _IndexEntry:
    record_id: str
    generation: int
    envelope_digest: str

    def value(self) -> dict[str, JsonValue]:
        return {
            "envelope_digest": self.envelope_digest,
            "generation": self.generation,
            "record_id": self.record_id,
        }


@dataclass(frozen=True, slots=True)
class _DecodedRecord:
    record_id: str
    kind: VaultRecordKind
    generation: int
    binding_digest: str
    plaintext_size: int
    wrapped_dek: bytes
    nonce: bytes
    ciphertext_and_tag: bytes
    header_bytes: bytes


@dataclass(frozen=True, slots=True)
class PreparedVaultRootRotation:
    """One verified, quarantined vault encrypted by the next root."""

    recovery_generation: int
    root_epoch: int
    stage: Path

    def __post_init__(self) -> None:
        if type(self.recovery_generation) is not int or self.recovery_generation <= 0:
            raise ValueError("recovery_generation_invalid")
        if type(self.root_epoch) is not int or self.root_epoch <= 1:
            raise ValueError("vault_root_epoch_invalid")


class EncryptedVaultStore:
    """One owner-only encrypted record directory and authenticated current index."""

    def __init__(self, vault_dir: Path) -> None:
        self._vault_dir = vault_dir
        self._index_path = vault_dir / "vault-index.json"
        self._ivk: bytearray | None = None
        self._locator_key: bytearray | None = None
        self._index_key: bytearray | None = None
        self._installation_mac_root: bytearray | None = None
        self._root_epoch = 0
        self._index: dict[str, _IndexEntry] = {}
        self._lock = Lock()
        self._closed = False

    def initialize(self, ivk_handle: SecretHandle) -> None:
        if ivk_handle.purpose is not SecretPurpose.VAULT_ROOT_KEY:
            raise EncryptedVaultError("record_binding_invalid")
        with self._lock:
            self._require_open()
            if self._ivk is not None:
                raise EncryptedVaultError("already_initialized")
            ensure_owner_only_dir(self._vault_dir)

            def _capture(view: memoryview) -> bytearray:
                if view.nbytes != 32:
                    raise EncryptedVaultError("record_binding_invalid")
                return bytearray(view)

            ivk = ivk_handle.consume(SecretConsumer.VAULT_ROOT, _capture)
            root_state_path = self._vault_dir / _ROOT_STATE_NAME
            if root_state_path.exists():
                locator, mac_root, root_epoch = _read_root_state(root_state_path, ivk)
                index_key = _derive_index_key(ivk)
            else:
                locator = _derive_locator(ivk)
                # Pre-rotation vault-index/1 used the locator directly. The first root rotation
                # republishes the same index under a root-specific key, preserving backward read
                # while revoking an old artifact's ability to authenticate a new index.
                index_key = bytearray(locator)
                mac_root = bytearray(ivk)
                root_epoch = 1
            self._ivk = ivk
            self._locator_key = locator
            self._index_key = index_key
            self._installation_mac_root = mac_root
            self._root_epoch = root_epoch
            try:
                if self._index_path.exists():
                    self._index = self._read_index()
                else:
                    self._publish_index({}, expected_bytes=None)
                    self._index = {}
            except Exception:
                _overwrite(ivk)
                _overwrite(locator)
                _overwrite(index_key)
                _overwrite(mac_root)
                self._ivk = None
                self._locator_key = None
                self._index_key = None
                self._installation_mac_root = None
                self._root_epoch = 0
                raise

    def create_record(
        self,
        kind: VaultRecordKind,
        structural_binding: Mapping[str, str],
        payload: SecretHandle,
        *,
        generation: int = 1,
    ) -> str:
        binding = _validate_binding(kind, structural_binding)
        if type(generation) is not int or generation < 1:
            raise EncryptedVaultError("record_generation_mismatch")
        if kind is VaultRecordKind.BUNDLE_KEY and generation != 1:
            raise EncryptedVaultError("record_immutable")
        with self._lock:
            ivk, locator = self._ready_keys()
            binding_bytes, binding_digest, record_id = _record_identity(locator, kind, binding)
            del binding_bytes
            if record_id in self._index:
                raise EncryptedVaultError("record_exists")
            plaintext = _consume_payload(payload)
            try:
                frame = _encrypt_frame(
                    ivk,
                    kind,
                    record_id,
                    binding_digest,
                    generation,
                    plaintext,
                )
                digest = f"sha256:{hashlib.sha256(frame).hexdigest()}"
                self._publish_record(record_id, generation, frame)
                updated = dict(self._index)
                updated[record_id] = _IndexEntry(record_id, generation, digest)
                expected = self._index_path.read_bytes()
                self._publish_index(updated, expected_bytes=expected)
                self._index = updated
                return record_id
            finally:
                _overwrite(plaintext)

    def load_record(
        self,
        kind: VaultRecordKind,
        structural_binding: Mapping[str, str],
    ) -> SecretHandle:
        binding = _validate_binding(kind, structural_binding)
        with self._lock:
            ivk, locator = self._ready_keys()
            _, expected_binding_digest, record_id = _record_identity(locator, kind, binding)
            entry = self._index.get(record_id)
            if entry is None:
                raise EncryptedVaultError("record_missing")
            frame = self._read_record_frame(entry)
            decoded = _decode_frame(frame)
            if (
                decoded.record_id != record_id
                or decoded.kind is not kind
                or decoded.generation != entry.generation
                or decoded.binding_digest != expected_binding_digest
            ):
                raise EncryptedVaultError("record_tampered")
            plaintext = _decrypt_record(ivk, decoded)
            purpose = (
                SecretPurpose.PROVIDER_CREDENTIAL
                if kind is VaultRecordKind.PROVIDER_CREDENTIAL
                else SecretPurpose.VAULT_ROOT_KEY
            )
            return _OneShotVaultRecordHandle(plaintext, purpose)

    def replace_credential_record(
        self,
        structural_binding: Mapping[str, str],
        payload: SecretHandle,
        *,
        expected_generation: int,
    ) -> str:
        kind = VaultRecordKind.PROVIDER_CREDENTIAL
        binding = _validate_binding(kind, structural_binding)
        if type(expected_generation) is not int or expected_generation < 1:
            raise EncryptedVaultError("record_generation_mismatch")
        with self._lock:
            ivk, locator = self._ready_keys()
            _, binding_digest, record_id = _record_identity(locator, kind, binding)
            current = self._index.get(record_id)
            if current is None:
                raise EncryptedVaultError("record_missing")
            if current.generation != expected_generation:
                raise EncryptedVaultError("index_cas_mismatch")
            generation = expected_generation + 1
            plaintext = _consume_payload(payload)
            try:
                frame = _encrypt_frame(
                    ivk,
                    kind,
                    record_id,
                    binding_digest,
                    generation,
                    plaintext,
                )
                digest = f"sha256:{hashlib.sha256(frame).hexdigest()}"
                self._publish_record(record_id, generation, frame)
                updated = dict(self._index)
                updated[record_id] = _IndexEntry(record_id, generation, digest)
                expected = self._index_path.read_bytes()
                self._publish_index(updated, expected_bytes=expected)
                self._index = updated
                return record_id
            finally:
                _overwrite(plaintext)

    def record_generation(
        self,
        kind: VaultRecordKind,
        structural_binding: Mapping[str, str],
    ) -> int | None:
        """Return the authenticated index generation for one exact record binding."""

        binding = _validate_binding(kind, structural_binding)
        with self._lock:
            _, locator = self._ready_keys()
            _, _, record_id = _record_identity(locator, kind, binding)
            current = self._index.get(record_id)
            return None if current is None else current.generation

    def installation_recovery_root(self) -> SecretHandle:
        """Return one opaque IVK copy for the in-service recovery wrapper only."""

        with self._lock:
            ivk, _locator = self._ready_keys()
            return _OneShotVaultRecordHandle(bytearray(ivk), SecretPurpose.VAULT_ROOT_KEY)

    def installation_mac_root(self) -> SecretHandle:
        """Return the stable installation commitment root without exposing it publicly."""

        with self._lock:
            self._ready_keys()
            root = self._installation_mac_root
            if root is None:
                raise EncryptedVaultError("not_initialized")
            return _OneShotVaultRecordHandle(bytearray(root), SecretPurpose.VAULT_ROOT_KEY)

    def prepare_root_rotation(
        self,
        new_ivk_handle: SecretHandle,
        *,
        recovery_generation: int,
    ) -> PreparedVaultRootRotation:
        """Re-encrypt every current record into a verified sibling quarantine.

        Record locators and installation commitment roots stay stable so existing catalog rows do
        not need unavailable plaintext references.  Only the vault encryption root rotates: an
        older recovery artifact can still derive opaque historical commitments, but it cannot
        unwrap any record in this candidate vault.
        """

        if type(recovery_generation) is not int or recovery_generation <= 0:
            raise EncryptedVaultError("record_binding_invalid")
        if new_ivk_handle.purpose is not SecretPurpose.VAULT_ROOT_KEY:
            raise EncryptedVaultError("record_binding_invalid")
        with self._lock:
            old_ivk, locator = self._ready_keys()
            mac_root = self._installation_mac_root
            if mac_root is None or self._root_epoch <= 0:
                raise EncryptedVaultError("not_initialized")
            new_ivk = new_ivk_handle.consume(
                SecretConsumer.VAULT_ROOT, lambda view: bytearray(view)
            )
            if len(new_ivk) != 32 or hmac.compare_digest(new_ivk, old_ivk):
                _overwrite(new_ivk)
                raise EncryptedVaultError("record_binding_invalid")
            stage = self._vault_dir.parent / (
                f".{self._vault_dir.name}.root-{recovery_generation}.{os.urandom(16).hex()}.tmp"
            )
            candidate: EncryptedVaultStore | None = None
            try:
                ensure_owner_only_dir(stage)
                _write_private_exclusive(
                    stage / _ROOT_STATE_NAME,
                    _encode_root_state(
                        new_ivk,
                        locator,
                        mac_root,
                        root_epoch=self._root_epoch + 1,
                    ),
                )
                candidate = EncryptedVaultStore(stage)
                candidate.initialize(
                    _OneShotVaultRecordHandle(bytearray(new_ivk), SecretPurpose.VAULT_ROOT_KEY)
                )
                updated: dict[str, _IndexEntry] = {}
                for record_id in sorted(self._index):
                    entry = self._index[record_id]
                    decoded = _decode_frame(self._read_record_frame(entry))
                    plaintext = _decrypt_record(old_ivk, decoded)
                    try:
                        frame = _encrypt_frame(
                            new_ivk,
                            decoded.kind,
                            decoded.record_id,
                            decoded.binding_digest,
                            decoded.generation,
                            plaintext,
                        )
                    finally:
                        _overwrite(plaintext)
                    candidate._publish_record(  # pyright: ignore[reportPrivateUsage]
                        record_id, entry.generation, frame
                    )
                    updated[record_id] = _IndexEntry(
                        record_id,
                        entry.generation,
                        f"sha256:{hashlib.sha256(frame).hexdigest()}",
                    )
                expected = candidate._index_path.read_bytes()  # pyright: ignore[reportPrivateUsage]
                candidate._publish_index(  # pyright: ignore[reportPrivateUsage]
                    updated, expected_bytes=expected
                )
                candidate._index = updated  # pyright: ignore[reportPrivateUsage]
                observed = candidate._read_index()  # pyright: ignore[reportPrivateUsage]
                if observed != updated:
                    raise EncryptedVaultError("record_tampered")
                for entry in observed.values():
                    decoded = _decode_frame(
                        candidate._read_record_frame(entry)  # pyright: ignore[reportPrivateUsage]
                    )
                    plaintext = _decrypt_record(new_ivk, decoded)
                    _overwrite(plaintext)
                _fsync_dir(stage)
                return PreparedVaultRootRotation(
                    recovery_generation,
                    self._root_epoch + 1,
                    stage,
                )
            except BaseException:
                _remove_private_tree(stage)
                raise
            finally:
                if candidate is not None:
                    candidate.close()
                _overwrite(new_ivk)

    def verify_sentinel(self, structural_binding: Mapping[str, str]) -> None:
        handle = self.load_record(VaultRecordKind.VAULT_SENTINEL, structural_binding)
        handle.consume(SecretConsumer.VAULT_ROOT, lambda view: None)

    def delete_record(
        self,
        kind: VaultRecordKind,
        structural_binding: Mapping[str, str],
        *,
        expected_generation: int,
    ) -> None:
        """Remove one exact record under compare-and-set on its index generation.

        Used after a proven migration, and to withdraw a provider credential the provider
        itself refused, so a key that cannot work is never left behind as if it could.
        """

        binding = _validate_binding(kind, structural_binding)
        with self._lock:
            _, locator = self._ready_keys()
            _, _, record_id = _record_identity(locator, kind, binding)
            current = self._index.get(record_id)
            if current is None:
                raise EncryptedVaultError("record_missing")
            if current.generation != expected_generation:
                raise EncryptedVaultError("index_cas_mismatch")
            updated = dict(self._index)
            del updated[record_id]
            expected = self._index_path.read_bytes()
            self._publish_index(updated, expected_bytes=expected)
            self._index = updated
            try:
                (self._vault_dir / f"{record_id}.{expected_generation}.yzv").unlink()
                _fsync_dir(self._vault_dir)
            except OSError as exc:
                raise EncryptedVaultError("io_failure") from exc

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            if self._ivk is not None:
                _overwrite(self._ivk)
            if self._locator_key is not None:
                _overwrite(self._locator_key)
            if self._index_key is not None:
                _overwrite(self._index_key)
            if self._installation_mac_root is not None:
                _overwrite(self._installation_mac_root)
            self._ivk = None
            self._locator_key = None
            self._index_key = None
            self._installation_mac_root = None
            self._root_epoch = 0
            self._index = {}

    def _require_open(self) -> None:
        if self._closed:
            raise EncryptedVaultError("closed")

    def _ready_keys(self) -> tuple[bytearray, bytearray]:
        self._require_open()
        if (
            self._ivk is None
            or self._locator_key is None
            or self._index_key is None
            or self._installation_mac_root is None
            or self._root_epoch <= 0
        ):
            raise EncryptedVaultError("not_initialized")
        return self._ivk, self._locator_key

    def _ready_index_key(self) -> bytearray:
        self._ready_keys()
        if self._index_key is None:
            raise EncryptedVaultError("not_initialized")
        return self._index_key

    def _read_record_frame(self, entry: _IndexEntry) -> bytes:
        path = self._vault_dir / f"{entry.record_id}.{entry.generation}.yzv"
        _verify_private_file(path)
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise EncryptedVaultError("io_failure") from exc
        if len(data) > _MAX_RECORD_BYTES:
            raise EncryptedVaultError("record_tampered")
        if f"sha256:{hashlib.sha256(data).hexdigest()}" != entry.envelope_digest:
            raise EncryptedVaultError("record_tampered")
        return data

    def _publish_record(self, record_id: str, generation: int, frame: bytes) -> None:
        path = self._vault_dir / f"{record_id}.{generation}.yzv"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags, 0o600)
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                stream.write(frame)
                stream.flush()
                os.fsync(stream.fileno())
            _verify_private_file(path)
            if path.read_bytes() != frame:
                raise EncryptedVaultError("record_tampered")
            _fsync_dir(self._vault_dir)
        except FileExistsError as exc:
            raise EncryptedVaultError("record_exists") from exc
        except EncryptedVaultError:
            raise
        except OSError as exc:
            raise EncryptedVaultError("io_failure") from exc

    def _read_index(self) -> dict[str, _IndexEntry]:
        _verify_private_file(self._index_path)
        try:
            data = self._index_path.read_bytes()
            value = strict_json_parse(data)
        except (OSError, ProtocolValueError) as exc:
            raise EncryptedVaultError("index_tampered") from exc
        if canonical_encode(value) != data or type(value) is not dict:
            raise EncryptedVaultError("index_tampered")
        wrapper = cast(dict[str, JsonValue], value)
        if set(wrapper) != {"index", "index_mac"} or type(wrapper["index_mac"]) is not str:
            raise EncryptedVaultError("index_tampered")
        index_value = wrapper["index"]
        if type(index_value) is not dict:
            raise EncryptedVaultError("index_tampered")
        index = cast(dict[str, JsonValue], index_value)
        if set(index) != {"format", "records"} or index["format"] != "yoetz-vault-index/1":
            raise EncryptedVaultError("index_tampered")
        records = index["records"]
        if type(records) is not list:
            raise EncryptedVaultError("index_tampered")
        index_key = self._ready_index_key()
        expected_mac = (
            "hmac-sha256:"
            + hmac.digest(index_key, _INDEX_DOMAIN + canonical_encode(index), "sha256").hex()
        )
        if not hmac.compare_digest(wrapper["index_mac"], expected_mac):
            raise EncryptedVaultError("index_tampered")
        result: dict[str, _IndexEntry] = {}
        previous = ""
        for item in records:
            if type(item) is not dict:
                raise EncryptedVaultError("index_tampered")
            entry = cast(dict[str, JsonValue], item)
            if set(entry) != {"envelope_digest", "generation", "record_id"}:
                raise EncryptedVaultError("index_tampered")
            record_id = entry["record_id"]
            generation = entry["generation"]
            digest = entry["envelope_digest"]
            if (
                type(record_id) is not str
                or _RECORD_ID.fullmatch(record_id) is None
                or record_id <= previous
                or record_id in result
                or type(generation) is not int
                or generation < 1
                or type(digest) is not str
            ):
                raise EncryptedVaultError("index_tampered")
            try:
                validate_sha256_digest(digest)
            except ValueError as exc:
                raise EncryptedVaultError("index_tampered") from exc
            result[record_id] = _IndexEntry(record_id, generation, digest)
            previous = record_id
        for entry in result.values():
            self._read_record_frame(entry)
        return result

    def _publish_index(
        self,
        entries: Mapping[str, _IndexEntry],
        *,
        expected_bytes: bytes | None,
    ) -> None:
        index_key = self._ready_index_key()
        index_value: dict[str, JsonValue] = {
            "format": "yoetz-vault-index/1",
            "records": [entries[key].value() for key in sorted(entries)],
        }
        index_mac = (
            "hmac-sha256:"
            + hmac.digest(index_key, _INDEX_DOMAIN + canonical_encode(index_value), "sha256").hex()
        )
        data = canonical_encode({"index": index_value, "index_mac": index_mac})
        if expected_bytes is not None:
            try:
                current = self._index_path.read_bytes()
            except OSError as exc:
                raise EncryptedVaultError("index_cas_mismatch") from exc
            if current != expected_bytes:
                raise EncryptedVaultError("index_cas_mismatch")
        temp = self._vault_dir / f".vault-index.{os.urandom(16).hex()}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(temp, flags, 0o600)
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp, self._index_path)
            _fsync_dir(self._vault_dir)
            _verify_private_file(self._index_path)
        except OSError as exc:
            try:
                temp.unlink(missing_ok=True)
            except OSError:
                pass
            raise EncryptedVaultError("io_failure") from exc


def _record_identity(
    locator: bytes | bytearray,
    kind: VaultRecordKind,
    binding: Mapping[str, str],
) -> tuple[bytes, str, str]:
    binding_bytes = canonical_encode({"kind": kind.value, "structural_binding": dict(binding)})
    digest = hmac.digest(locator, _BINDING_DOMAIN + binding_bytes, "sha256").hex()
    return binding_bytes, f"hmac-sha256:{digest}", f"vrec_{digest}"


def _derive_locator(root: bytes | bytearray) -> bytearray:
    return bytearray(
        HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=_LOCATOR_SALT,
            info=_LOCATOR_INFO,
        ).derive(bytes(root))
    )


def _derive_index_key(root: bytes | bytearray) -> bytearray:
    return bytearray(
        HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=_INDEX_AUTH_SALT,
            info=_INDEX_AUTH_INFO,
        ).derive(bytes(root))
    )


def _encode_root_state(
    active_root: bytes | bytearray,
    locator_root: bytes | bytearray,
    installation_mac_root: bytes | bytearray,
    *,
    root_epoch: int,
) -> bytes:
    if (
        len(active_root) != 32
        or len(locator_root) != 32
        or len(installation_mac_root) != 32
        or type(root_epoch) is not int
        or root_epoch <= 1
    ):
        raise EncryptedVaultError("record_binding_invalid")
    plaintext = bytearray(
        canonical_encode(
            {
                "installation_mac_root": _b64url_encode(installation_mac_root),
                "locator_root": _b64url_encode(locator_root),
                "root_epoch": root_epoch,
            }
        )
    )
    nonce = os.urandom(12)
    try:
        ciphertext = AESGCM(bytes(active_root)).encrypt(
            nonce,
            bytes(plaintext),
            _ROOT_STATE_DOMAIN,
        )
    finally:
        _overwrite(plaintext)
    return canonical_encode(
        {
            "ciphertext": _b64url_encode(ciphertext),
            "format": _ROOT_STATE_FORMAT,
            "nonce": _b64url_encode(nonce),
        }
    )


def _read_root_state(
    path: Path, active_root: bytes | bytearray
) -> tuple[bytearray, bytearray, int]:
    try:
        _verify_private_file(path)
        encoded = path.read_bytes()
        if not 1 <= len(encoded) <= _MAX_ROOT_STATE_BYTES:
            raise ValueError
        value = strict_json_parse(encoded)
        if type(value) is not dict:
            raise ValueError
        source = cast(dict[str, JsonValue], value)
        if canonical_encode(source) != encoded:
            raise ValueError
        if set(source) != {"ciphertext", "format", "nonce"}:
            raise ValueError
        if source["format"] != _ROOT_STATE_FORMAT:
            raise ValueError
        nonce = _b64url_decode(source["nonce"], 12)
        ciphertext_value = source["ciphertext"]
        if type(ciphertext_value) is not str:
            raise ValueError
        ciphertext = _b64url_decode_bounded(ciphertext_value, _MAX_ROOT_STATE_BYTES)
        plaintext = bytearray(
            AESGCM(bytes(active_root)).decrypt(nonce, ciphertext, _ROOT_STATE_DOMAIN)
        )
        try:
            body = strict_json_parse(bytes(plaintext))
            if type(body) is not dict:
                raise ValueError
            state = cast(dict[str, JsonValue], body)
            if canonical_encode(state) != bytes(plaintext):
                raise ValueError
            if set(state) != {"installation_mac_root", "locator_root", "root_epoch"}:
                raise ValueError
            epoch = state["root_epoch"]
            if type(epoch) is not int or epoch <= 1:
                raise ValueError
            locator = bytearray(_b64url_decode(state["locator_root"], 32))
            mac_root = bytearray(_b64url_decode(state["installation_mac_root"], 32))
            return locator, mac_root, epoch
        finally:
            _overwrite(plaintext)
    except (InvalidTag, OSError, ProtocolValueError, TypeError, ValueError) as exc:
        raise EncryptedVaultError("record_tampered") from exc


def _write_private_exclusive(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        _verify_private_file(path)
    except EncryptedVaultError:
        raise
    except OSError as exc:
        raise EncryptedVaultError("io_failure") from exc


def _remove_private_tree(path: Path) -> None:
    if not path.exists():
        return
    for member in sorted(path.rglob("*"), key=lambda item: len(item.parts), reverse=True):
        try:
            if member.is_dir():
                member.rmdir()
            else:
                member.unlink()
        except FileNotFoundError:
            pass
    try:
        path.rmdir()
    except FileNotFoundError:
        pass


def _encrypt_frame(
    ivk: bytes | bytearray,
    kind: VaultRecordKind,
    record_id: str,
    binding_digest: str,
    generation: int,
    plaintext: bytearray,
) -> bytes:
    dek = bytearray(os.urandom(32))
    nonce = os.urandom(12)
    try:
        wrapped = keywrap.aes_key_wrap(bytes(ivk), bytes(dek))
        header: dict[str, JsonValue] = {
            "binding_digest": binding_digest,
            "format": "yoetz-vault-record/1",
            "generation": generation,
            "payload_algorithm": "aes-256-gcm",
            "plaintext_size": len(plaintext),
            "record_id": record_id,
            "record_kind": kind.value,
            "wrap_algorithm": "aes-256-kw-rfc3394",
            "wrapped_record_dek": _b64url_encode(wrapped),
        }
        header_bytes = canonical_encode(header)
        encrypted = AESGCM(bytes(dek)).encrypt(nonce, bytes(plaintext), header_bytes)
        return (
            _FRAME_MAGIC
            + bytes([_FRAME_VERSION])
            + len(header_bytes).to_bytes(4, "big")
            + header_bytes
            + nonce
            + encrypted
        )
    finally:
        _overwrite(dek)


def _decode_frame(frame: bytes) -> _DecodedRecord:
    if type(frame) is not bytes or len(frame) < 4 + 1 + 4 + 1 + 12 + 16:
        raise EncryptedVaultError("record_tampered")
    if frame[:4] != _FRAME_MAGIC or frame[4] != _FRAME_VERSION:
        raise EncryptedVaultError("record_tampered")
    header_length = int.from_bytes(frame[5:9], "big")
    if not 1 <= header_length <= _MAX_HEADER_BYTES:
        raise EncryptedVaultError("record_tampered")
    header_end = 9 + header_length
    if len(frame) < header_end + 12 + 16:
        raise EncryptedVaultError("record_tampered")
    header_bytes = frame[9:header_end]
    try:
        value = strict_json_parse(header_bytes)
    except ProtocolValueError as exc:
        raise EncryptedVaultError("record_tampered") from exc
    if canonical_encode(value) != header_bytes or type(value) is not dict:
        raise EncryptedVaultError("record_tampered")
    header = cast(dict[str, JsonValue], value)
    if set(header) != {
        "binding_digest",
        "format",
        "generation",
        "payload_algorithm",
        "plaintext_size",
        "record_id",
        "record_kind",
        "wrap_algorithm",
        "wrapped_record_dek",
    }:
        raise EncryptedVaultError("record_tampered")
    try:
        kind = VaultRecordKind(_required_str(header["record_kind"]))
        generation = _required_int(header["generation"])
        plaintext_size = _required_int(header["plaintext_size"])
        record_id = _required_str(header["record_id"])
        binding_digest = _required_str(header["binding_digest"])
        validate_sha256_digest(binding_digest.replace("hmac-sha256:", "sha256:", 1))
    except (ValueError, TypeError) as exc:
        raise EncryptedVaultError("record_tampered") from exc
    if (
        header["format"] != "yoetz-vault-record/1"
        or header["payload_algorithm"] != "aes-256-gcm"
        or header["wrap_algorithm"] != "aes-256-kw-rfc3394"
        or _RECORD_ID.fullmatch(record_id) is None
        or generation < 1
        or plaintext_size < 0
    ):
        raise EncryptedVaultError("record_tampered")
    wrapped = _b64url_decode(header["wrapped_record_dek"], 40)
    nonce = frame[header_end : header_end + 12]
    encrypted = frame[header_end + 12 :]
    if len(encrypted) != plaintext_size + 16:
        raise EncryptedVaultError("record_tampered")
    return _DecodedRecord(
        record_id,
        kind,
        generation,
        binding_digest,
        plaintext_size,
        wrapped,
        nonce,
        encrypted,
        header_bytes,
    )


def _decrypt_record(ivk: bytes | bytearray, record: _DecodedRecord) -> bytearray:
    try:
        dek = bytearray(keywrap.aes_key_unwrap(bytes(ivk), record.wrapped_dek))
    except keywrap.InvalidUnwrap as exc:
        raise EncryptedVaultError("record_tampered") from exc
    try:
        try:
            plaintext = AESGCM(bytes(dek)).decrypt(
                record.nonce, record.ciphertext_and_tag, record.header_bytes
            )
        except InvalidTag as exc:
            raise EncryptedVaultError("record_tampered") from exc
        if len(plaintext) != record.plaintext_size:
            raise EncryptedVaultError("record_tampered")
        return bytearray(plaintext)
    finally:
        _overwrite(dek)


def _validate_binding(kind: VaultRecordKind, binding: Mapping[str, str]) -> dict[str, str]:
    if type(kind) is not VaultRecordKind or type(binding) is not dict:
        raise EncryptedVaultError("record_binding_invalid")
    source = cast(dict[str, str], binding)
    expected: set[str]
    if kind is VaultRecordKind.VAULT_SENTINEL:
        expected = {"installation_id"}
    elif kind is VaultRecordKind.BUNDLE_KEY:
        expected = {"task_id", "key_slot"}
    elif kind is VaultRecordKind.PROVIDER_CREDENTIAL:
        expected = {
            "provider_id",
            "model_id",
            "endpoint_profile_id",
            "endpoint_profile_version",
            "purpose",
            "authorization_scope_digest",
            "purpose_digest",
        }
    else:
        expected = {"installation_id", "recovery_generation"}
    if set(source) != expected or any(type(value) is not str for value in source.values()):
        raise EncryptedVaultError("record_binding_invalid")
    try:
        if "installation_id" in source:
            validate_id(IdKind.INSTALLATION, source["installation_id"])
        if "task_id" in source:
            validate_id(IdKind.TASK, source["task_id"])
        if "key_slot" in source and _KEY_SLOT.fullmatch(source["key_slot"]) is None:
            raise ValueError
        if "recovery_generation" in source:
            generation = source["recovery_generation"]
            if (
                not generation.isascii()
                or not generation.isdecimal()
                or str(int(generation)) != generation
            ):
                raise ValueError
            if not 1 <= int(generation) <= 9_007_199_254_740_991:
                raise ValueError
        if "provider_id" in source and _IDENTITY.fullmatch(source["provider_id"]) is None:
            raise ValueError
        if "model_id" in source and _MODEL.fullmatch(source["model_id"]) is None:
            raise ValueError
        if (
            "endpoint_profile_id" in source
            and _IDENTITY.fullmatch(source["endpoint_profile_id"]) is None
        ):
            raise ValueError
        if (
            "endpoint_profile_version" in source
            and not 1 <= len(source["endpoint_profile_version"]) <= 128
        ):
            raise ValueError
        if "purpose" in source and _PURPOSE.fullmatch(source["purpose"]) is None:
            raise ValueError
        for field in ("authorization_scope_digest", "purpose_digest"):
            if field in source:
                validate_sha256_digest(source[field])
    except (ProtocolValueError, ValueError) as exc:
        raise EncryptedVaultError("record_binding_invalid") from exc
    return dict(source)


def _consume_payload(handle: SecretHandle) -> bytearray:
    return handle.consume(SecretConsumer.VAULT_ROOT, lambda view: bytearray(view))


def _verify_private_file(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise EncryptedVaultError("io_failure") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise EncryptedVaultError("unsafe_permissions")


def _fsync_dir(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _required_str(value: JsonValue) -> str:
    if type(value) is not str:
        raise EncryptedVaultError("record_tampered")
    return value


def _required_int(value: JsonValue) -> int:
    if type(value) is not int:
        raise EncryptedVaultError("record_tampered")
    return value


def _b64url_encode(value: bytes | bytearray) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: JsonValue, expected_length: int) -> bytes:
    if type(value) is not str or not value or "=" in value:
        raise EncryptedVaultError("record_tampered")
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise EncryptedVaultError("record_tampered") from exc
    if len(decoded) != expected_length or _b64url_encode(decoded) != value:
        raise EncryptedVaultError("record_tampered")
    return decoded


def _b64url_decode_bounded(value: str, maximum: int) -> bytes:
    if not value or len(value) > maximum * 2 or "=" in value:
        raise EncryptedVaultError("record_tampered")
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise EncryptedVaultError("record_tampered") from exc
    if not decoded or len(decoded) > maximum or _b64url_encode(decoded) != value:
        raise EncryptedVaultError("record_tampered")
    return decoded


def _overwrite(value: bytearray) -> None:
    value[:] = b"\x00" * len(value)


@dataclass(slots=True)
class _OneShotVaultRecordHandle:
    _secret: bytearray = field(repr=False)
    _purpose: SecretPurpose
    _consumed: bool = field(default=False, init=False, repr=False)
    _lock: Lock = field(default_factory=Lock, init=False, repr=False)

    @property
    def purpose(self) -> SecretPurpose:
        return self._purpose

    def consume[T](self, consumer: SecretConsumer, fn: Callable[[memoryview], T]) -> T:
        if consumer is not SecretConsumer.VAULT_ROOT:
            raise EncryptedVaultError("record_binding_invalid")
        with self._lock:
            if self._consumed:
                raise EncryptedVaultError("closed")
            self._consumed = True
            try:
                return fn(memoryview(self._secret))
            finally:
                _overwrite(self._secret)

    def __copy__(self) -> _OneShotVaultRecordHandle:
        raise TypeError("vault_record_handle_not_copyable")

    def __deepcopy__(self, memo: Mapping[int, object]) -> _OneShotVaultRecordHandle:
        del memo
        raise TypeError("vault_record_handle_not_copyable")

    def __reduce__(self) -> str | tuple[object, ...]:
        raise TypeError("vault_record_handle_not_serializable")
