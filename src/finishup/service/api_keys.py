"""The service's network API keys, hashed at rest (ADR-051, server-native approach).

Keys live in the service's own state, ``<state>/network/api-keys.json`` (``yoetz.api-keys/1``,
owner-only, canonical JSON). The file holds, per key: its id, an owner label, a scope (``agent``
or ``operator``), a principal, when it was created, when it expires and when it was revoked, a
random salt and ``sha256(salt ‖ secret)``. The key itself is shown once, when it is created, and
is never stored.

The owner manages keys on the server host with ``finishup service api-key create|list|revoke``,
which edit this file directly under an exclusive lock; no key is ever managed over the network.
The running service re-reads the file when it changes, so a revoked key fails its very next
request. A rotated key (``create --rotate KEY_ID``) keeps its predecessor's principal, so the
workspaces its client claimed stay reachable.

Every failure is an ``ApiKeyError`` with a closed reason; no error, log or listing carries a key.
Labels appear only in the owner's own ``list`` output on the server host.
"""

from __future__ import annotations

import base64
import binascii
import fcntl
import hashlib
import hmac
import os
import re
import secrets
import stat
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Final, cast

from finishup.config.installation import format_rfc3339_ms, parse_rfc3339_ms
from finishup.config.paths import PathSafetyError, ensure_owner_only_dir, state_dir
from finishup.protocol.canonical import JsonValue, canonical_encode, strict_json_parse
from finishup.service.network_protocol import (
    API_SCOPES,
    ApiKeyToken,
    ApiScope,
    mint_api_key,
    parse_api_key,
)

__all__ = [
    "API_KEYS_DIRECTORY",
    "API_KEYS_FILE_NAME",
    "API_KEYS_SCHEMA",
    "MAX_API_KEYS",
    "ApiKeyError",
    "ApiKeyRecord",
    "ApiKeyStore",
    "default_api_key_store",
    "validate_label",
]

API_KEYS_SCHEMA: Final = "yoetz.api-keys/1"
API_KEYS_DIRECTORY: Final = "network"
API_KEYS_FILE_NAME: Final = "api-keys.json"
MAX_API_KEYS: Final = 256
_MAX_FILE_BYTES: Final = 256 * 1024
_MAX_EXPIRY_DAYS: Final = 3_650
_SALT_BYTES: Final = 16
_LOCK_NAME: Final = ".api-keys.lock"
_LABEL: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,47}$", re.ASCII)
_KEY_ID: Final = re.compile(r"^[0-9a-f]{12}$", re.ASCII)
_PRINCIPAL: Final = re.compile(r"^p_[0-9a-f]{16}$", re.ASCII)
_HASH: Final = re.compile(r"^sha256:[0-9a-f]{64}$", re.ASCII)
_RECORD_KEYS: Final = frozenset(
    {
        "created_at",
        "expires_at",
        "hash",
        "key_id",
        "label",
        "principal",
        "revoked_at",
        "salt",
        "scope",
    }
)
_REASONS: Final = frozenset(
    {
        "api_key_invalid",
        "api_key_revoked",
        "api_key_expired",
        "api_key_unknown",
        "api_key_label_invalid",
        "api_key_scope_invalid",
        "api_key_expiry_invalid",
        "api_key_limit",
        "api_keys_unsafe",
        "api_keys_damaged",
    }
)


class ApiKeyError(Exception):
    """A bounded API-key failure; ``reason`` is a closed token and never holds a key."""

    reason: str

    def __init__(self, reason: str) -> None:
        if reason not in _REASONS:
            raise ValueError("api_key_reason_invalid")
        self.reason = reason
        super().__init__(reason)


def validate_label(label: str) -> str:
    if type(label) is not str or not _LABEL.fullmatch(label):
        raise ApiKeyError("api_key_label_invalid")
    return label


def _digest(salt: bytes, secret: bytes) -> str:
    return "sha256:" + hashlib.sha256(salt + secret).hexdigest()


@dataclass(frozen=True, slots=True)
class ApiKeyRecord:
    """One stored key: everything but the key itself."""

    key_id: str
    label: str
    scope: ApiScope
    principal: str
    created_at: str
    expires_at: str | None
    revoked_at: str | None
    salt: str
    hash: str

    def __post_init__(self) -> None:
        if type(self.key_id) is not str or not _KEY_ID.fullmatch(self.key_id):
            raise ApiKeyError("api_keys_damaged")
        try:
            validate_label(self.label)
        except ApiKeyError:
            raise ApiKeyError("api_keys_damaged") from None
        if self.scope not in API_SCOPES:
            raise ApiKeyError("api_keys_damaged")
        if type(self.principal) is not str or not _PRINCIPAL.fullmatch(self.principal):
            raise ApiKeyError("api_keys_damaged")
        try:
            parse_rfc3339_ms(self.created_at)
            for stamp in (self.expires_at, self.revoked_at):
                if stamp is not None:
                    parse_rfc3339_ms(stamp)
            salt = base64.b64decode(self.salt, validate=True)
        except (TypeError, ValueError, binascii.Error):
            raise ApiKeyError("api_keys_damaged") from None
        if len(salt) != _SALT_BYTES:
            raise ApiKeyError("api_keys_damaged")
        if type(self.hash) is not str or not _HASH.fullmatch(self.hash):
            raise ApiKeyError("api_keys_damaged")

    def __repr__(self) -> str:
        return f"ApiKeyRecord(key_id={self.key_id!r}, scope={self.scope!r}, <redacted>)"

    def state(self, now: datetime) -> str:
        """``active``, ``revoked`` or ``expired`` at ``now``."""

        if self.revoked_at is not None:
            return "revoked"
        if self.expires_at is not None and parse_rfc3339_ms(self.expires_at) <= now:
            return "expired"
        return "active"

    def matches(self, token: ApiKeyToken) -> bool:
        salt = base64.b64decode(self.salt, validate=True)
        return hmac.compare_digest(_digest(salt, token.secret), self.hash)

    def body(self) -> dict[str, JsonValue]:
        return {
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "hash": self.hash,
            "key_id": self.key_id,
            "label": self.label,
            "principal": self.principal,
            "revoked_at": self.revoked_at,
            "salt": self.salt,
            "scope": self.scope,
        }


def _decode(encoded: bytes) -> tuple[ApiKeyRecord, ...]:
    try:
        if not encoded.endswith(b"\n"):
            raise ValueError("trailer")
        value = strict_json_parse(encoded[:-1])
        if type(value) is not dict:
            raise ValueError("shape")
        document = cast(dict[str, JsonValue], value)
        if frozenset(document) != frozenset({"keys", "schema"}) or (
            document["schema"] != API_KEYS_SCHEMA
        ):
            raise ValueError("fields")
        if canonical_encode(document) != encoded[:-1]:
            raise ValueError("canonical")
        raw_keys = document["keys"]
        if type(raw_keys) is not list or len(raw_keys) > MAX_API_KEYS:
            raise ValueError("keys")
        records: list[ApiKeyRecord] = []
        for raw in raw_keys:
            if type(raw) is not dict:
                raise ValueError("record")
            item = cast(dict[str, JsonValue], raw)
            if frozenset(item) != _RECORD_KEYS:
                raise ValueError("record")
            records.append(
                ApiKeyRecord(
                    key_id=cast(str, item["key_id"]),
                    label=cast(str, item["label"]),
                    scope=cast(ApiScope, item["scope"]),
                    principal=cast(str, item["principal"]),
                    created_at=cast(str, item["created_at"]),
                    expires_at=cast(str | None, item["expires_at"]),
                    revoked_at=cast(str | None, item["revoked_at"]),
                    salt=cast(str, item["salt"]),
                    hash=cast(str, item["hash"]),
                )
            )
    except ApiKeyError:
        raise ApiKeyError("api_keys_damaged") from None
    except (KeyError, TypeError, ValueError):
        raise ApiKeyError("api_keys_damaged") from None
    if len({record.key_id for record in records}) != len(records):
        raise ApiKeyError("api_keys_damaged")
    return tuple(records)


def _encode(records: tuple[ApiKeyRecord, ...]) -> bytes:
    document: dict[str, JsonValue] = {
        "keys": [cast(JsonValue, record.body()) for record in records],
        "schema": API_KEYS_SCHEMA,
    }
    return canonical_encode(document) + b"\n"


type _Signature = tuple[int, int, int, int]


class ApiKeyStore:
    """The owner-only key file of one service root.

    ``authenticate`` is what the service calls per request; ``create``, ``revoke`` and ``list``
    are what the server-host CLI calls. Writers hold an exclusive lock and replace the file
    atomically; the service re-reads it whenever its identity, size or modification time moves.
    """

    __slots__ = ("_cached", "_directory", "_path", "_signature")

    def __init__(self, directory: Path) -> None:
        if not directory.is_absolute():
            raise ApiKeyError("api_keys_unsafe")
        self._directory = directory
        self._path = directory / API_KEYS_FILE_NAME
        self._signature: _Signature | None = None
        self._cached: tuple[ApiKeyRecord, ...] = ()

    @property
    def path(self) -> Path:
        return self._path

    def _facts(self) -> os.stat_result | None:
        try:
            facts = self._path.lstat()
        except FileNotFoundError:
            return None
        except OSError:
            raise ApiKeyError("api_keys_unsafe") from None
        if (
            not stat.S_ISREG(facts.st_mode)
            or facts.st_uid != os.geteuid()
            or stat.S_IMODE(facts.st_mode) & 0o077
            or facts.st_size > _MAX_FILE_BYTES
        ):
            raise ApiKeyError("api_keys_unsafe")
        return facts

    def _read(self) -> tuple[ApiKeyRecord, ...]:
        facts = self._facts()
        if facts is None:
            self._signature = None
            self._cached = ()
            return ()
        signature: _Signature = (facts.st_ino, facts.st_size, facts.st_mtime_ns, facts.st_ctime_ns)
        if signature == self._signature:
            return self._cached
        try:
            descriptor = os.open(self._path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except FileNotFoundError:
            self._signature = None
            self._cached = ()
            return ()
        except OSError:
            raise ApiKeyError("api_keys_unsafe") from None
        try:
            data = os.read(descriptor, _MAX_FILE_BYTES + 1)
        finally:
            os.close(descriptor)
        if len(data) > _MAX_FILE_BYTES:
            raise ApiKeyError("api_keys_unsafe")
        records = _decode(data)
        self._signature = signature
        self._cached = records
        return records

    def records(self) -> tuple[ApiKeyRecord, ...]:
        """Every stored key, oldest first."""

        return self._read()

    def authenticate(self, token: str, *, now: datetime | None = None) -> ApiKeyRecord:
        """The active key ``token`` names; ``api_key_invalid|revoked|expired`` otherwise."""

        parsed = parse_api_key(token)
        records = self._read()
        record = (
            None
            if parsed is None
            else next((item for item in records if item.key_id == parsed.key_id), None)
        )
        if parsed is None or record is None:
            # Spend a comparable hash so an unknown id does not answer faster than a wrong secret.
            hmac.compare_digest(_digest(b"\x00" * _SALT_BYTES, b""), "sha256:" + "0" * 64)
            raise ApiKeyError("api_key_invalid")
        if not record.matches(parsed):
            raise ApiKeyError("api_key_invalid")
        state = record.state(now or datetime.now(UTC))
        if state == "revoked":
            raise ApiKeyError("api_key_revoked")
        if state == "expired":
            raise ApiKeyError("api_key_expired")
        return record

    def is_active(self, key_id: str, *, now: datetime | None = None) -> bool:
        """Whether ``key_id`` names a key that is neither revoked nor expired now."""

        try:
            records = self._read()
        except ApiKeyError:
            return False
        record = next((item for item in records if item.key_id == key_id), None)
        return record is not None and record.state(now or datetime.now(UTC)) == "active"

    @contextmanager
    def _locked(self) -> Generator[None]:
        try:
            ensure_owner_only_dir(self._directory)
        except PathSafetyError:
            raise ApiKeyError("api_keys_unsafe") from None
        try:
            descriptor = os.open(
                self._directory / _LOCK_NAME,
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
            )
        except OSError:
            raise ApiKeyError("api_keys_unsafe") from None
        try:
            facts = os.fstat(descriptor)
            if not stat.S_ISREG(facts.st_mode) or facts.st_uid != os.geteuid():
                raise ApiKeyError("api_keys_unsafe")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            os.close(descriptor)

    def _write(self, records: tuple[ApiKeyRecord, ...]) -> None:
        encoded = _encode(records)
        temporary = self._directory / f".{API_KEYS_FILE_NAME}.{secrets.token_hex(6)}.tmp"
        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
            )
        except OSError:
            raise ApiKeyError("api_keys_unsafe") from None
        try:
            try:
                view = memoryview(encoded)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise OSError("short_write")
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.replace(temporary, self._path)
        except OSError:
            temporary.unlink(missing_ok=True)
            raise ApiKeyError("api_keys_unsafe") from None
        directory = os.open(self._directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        self._signature = None

    def create(
        self,
        label: str,
        scope: ApiScope,
        *,
        expires_in_days: int | None = None,
        rotate: str | None = None,
        now: datetime | None = None,
    ) -> tuple[ApiKeyRecord, str]:
        """Store a new key and return its record and the one-time key text.

        ``rotate`` names an existing key whose principal the new key keeps; the old key stays
        valid until the owner revokes it.
        """

        validate_label(label)
        if scope not in API_SCOPES:
            raise ApiKeyError("api_key_scope_invalid")
        if expires_in_days is not None and (
            type(expires_in_days) is not int or not 1 <= expires_in_days <= _MAX_EXPIRY_DAYS
        ):
            raise ApiKeyError("api_key_expiry_invalid")
        stamp = now or datetime.now(UTC)
        with self._locked():
            records = self._read()
            if len(records) >= MAX_API_KEYS:
                raise ApiKeyError("api_key_limit")
            principal = f"p_{secrets.token_hex(8)}"
            if rotate is not None:
                predecessor = next((item for item in records if item.key_id == rotate), None)
                if predecessor is None:
                    raise ApiKeyError("api_key_unknown")
                principal = predecessor.principal
            token, text = mint_api_key()
            while any(item.key_id == token.key_id for item in records):
                token, text = mint_api_key()
            salt = secrets.token_bytes(_SALT_BYTES)
            record = ApiKeyRecord(
                key_id=token.key_id,
                label=label,
                scope=scope,
                principal=principal,
                created_at=format_rfc3339_ms(stamp),
                expires_at=None
                if expires_in_days is None
                else format_rfc3339_ms(stamp + timedelta(days=expires_in_days)),
                revoked_at=None,
                salt=base64.b64encode(salt).decode("ascii"),
                hash=_digest(salt, token.secret),
            )
            self._write((*records, record))
        return record, text

    def revoke(self, key_id: str, *, now: datetime | None = None) -> bool:
        """Revoke ``key_id``; ``False`` when it was already revoked (``api_key_unknown`` if none)."""

        stamp = format_rfc3339_ms(now or datetime.now(UTC))
        with self._locked():
            records = self._read()
            record = next((item for item in records if item.key_id == key_id), None)
            if record is None:
                raise ApiKeyError("api_key_unknown")
            if record.revoked_at is not None:
                return False
            updated = tuple(
                replace(item, revoked_at=stamp) if item.key_id == key_id else item
                for item in records
            )
            self._write(updated)
        return True


def default_api_key_store() -> ApiKeyStore:
    """The key store of this process's service root (``<state>/network``)."""

    try:
        return ApiKeyStore(state_dir() / API_KEYS_DIRECTORY)
    except PathSafetyError:
        raise ApiKeyError("api_keys_unsafe") from None
