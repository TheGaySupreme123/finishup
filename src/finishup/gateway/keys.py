"""The gateway's API keys: ``<state dir>/gateway/keys.json`` (``yoetz.gateway-keys/1``).

A key is ``fuk_<12 hex key id>_<43 base64url secret>`` (256 random bits). The file never holds a
secret: each record keeps a random salt and ``sha256(salt ‖ secret)``, compared in constant time.
Records also carry the owner's label (shown only by ``key list`` on the server's console), the
scope (``agent`` or ``operator``), the principal (``owner``; v1 is single-owner, so every key
reaches the owner's claims), and ``created_at``, ``expires_at``, ``revoked_at`` and
``last_used_at``.

``finishup service gateway key create|list|revoke`` edit the file as its owner while holding
``gateway/keys.lock``; a running gateway re-reads it when it changes, so a revoked key fails its
next request and its sessions close. Every failure is a closed ``GatewayKeyError`` reason.
"""

from __future__ import annotations

import base64
import contextlib
import fcntl
import hashlib
import hmac
import os
import re
import secrets
import stat
from collections.abc import Generator
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Final, Literal, cast

from finishup.config.installation import format_rfc3339_ms, parse_rfc3339_ms
from finishup.config.paths import PathSafetyError, ensure_owner_only_dir
from finishup.protocol.canonical import JsonValue, canonical_encode, strict_json_parse
from finishup.protocol.rest_binding import KeyScope, parse_api_key

__all__ = [
    "GATEWAY_DIR_NAME",
    "KEYS_SCHEMA",
    "GatewayKey",
    "GatewayKeyError",
    "KeyRing",
    "create_key",
    "list_keys",
    "record_use",
    "revoke_key",
]

KEYS_SCHEMA: Final = "yoetz.gateway-keys/1"
GATEWAY_DIR_NAME: Final = "gateway"
_KEYS_NAME: Final = "keys.json"
_LOCK_NAME: Final = "keys.lock"
_MAX_KEYS_BYTES: Final = 1_048_576
_MAX_KEYS: Final = 256
_LABEL: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$", re.ASCII)
_KEY_ID: Final = re.compile(r"^[0-9a-f]{12}$", re.ASCII)
_DIGEST: Final = re.compile(r"^sha256:[0-9a-f]{64}$", re.ASCII)
_SALT_BYTES: Final = 16
_SECRET_BYTES: Final = 32
_MAX_EXPIRY_DAYS: Final = 3_650
_FIELDS: Final = frozenset(
    {
        "key_id",
        "label",
        "scope",
        "principal",
        "created_at",
        "expires_at",
        "revoked_at",
        "last_used_at",
        "salt",
        "digest",
    }
)
_REASONS: Final = frozenset(
    {
        "gateway_keys_invalid",
        "gateway_keys_unsafe",
        "gateway_key_unknown",
        "gateway_key_label_invalid",
        "gateway_key_scope_invalid",
        "gateway_key_expiry_invalid",
        "gateway_key_limit",
    }
)
# A digest of a fixed, unused secret: unknown key ids pay the same hash and compare.
_DECOY_SALT: Final = bytes(_SALT_BYTES)

type AuthenticationFailure = Literal["api_key_invalid", "api_key_revoked", "api_key_expired"]


class GatewayKeyError(Exception):
    """A bounded key-store failure; ``reason`` is closed and never holds a key or a label."""

    def __init__(self, reason: str) -> None:
        if reason not in _REASONS:
            raise ValueError("gateway_key_reason_invalid")
        self.reason = reason
        super().__init__(reason)


def _timestamp(value: object, *, optional: bool) -> None:
    if value is None and optional:
        return
    try:
        parse_rfc3339_ms(value)
    except ValueError:
        raise GatewayKeyError("gateway_keys_invalid") from None


@dataclass(frozen=True, slots=True)
class GatewayKey:
    """One validated key record (no secret)."""

    key_id: str
    label: str
    scope: KeyScope
    created_at: str
    salt: str
    digest: str
    principal: Literal["owner"] = "owner"
    expires_at: str | None = None
    revoked_at: str | None = None
    last_used_at: str | None = None

    def __post_init__(self) -> None:
        if not _KEY_ID.match(self.key_id) or not _DIGEST.match(self.digest):
            raise GatewayKeyError("gateway_keys_invalid")
        if type(self.label) is not str or not _LABEL.match(self.label):
            raise GatewayKeyError("gateway_key_label_invalid")
        if self.scope not in {"agent", "operator"} or self.principal != "owner":
            raise GatewayKeyError("gateway_keys_invalid")
        try:
            salt = base64.b64decode(self.salt, validate=True)
        except (TypeError, ValueError):
            raise GatewayKeyError("gateway_keys_invalid") from None
        if len(salt) != _SALT_BYTES:
            raise GatewayKeyError("gateway_keys_invalid")
        _timestamp(self.created_at, optional=False)
        for value in (self.expires_at, self.revoked_at, self.last_used_at):
            _timestamp(value, optional=True)

    def body(self) -> dict[str, JsonValue]:
        return {
            "key_id": self.key_id,
            "label": self.label,
            "scope": self.scope,
            "principal": self.principal,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "revoked_at": self.revoked_at,
            "last_used_at": self.last_used_at,
            "salt": self.salt,
            "digest": self.digest,
        }

    def matches(self, secret: str) -> bool:
        return hmac.compare_digest(self.digest, _digest(base64.b64decode(self.salt), secret))

    def failure(self, now: datetime) -> AuthenticationFailure | None:
        if self.revoked_at is not None:
            return "api_key_revoked"
        if self.expires_at is not None and now >= parse_rfc3339_ms(self.expires_at):
            return "api_key_expired"
        return None


def _digest(salt: bytes, secret: str) -> str:
    return "sha256:" + hashlib.sha256(salt + secret.encode("ascii")).hexdigest()


def _keys_path(directory: Path) -> Path:
    return directory / _KEYS_NAME


def _encode(keys: tuple[GatewayKey, ...]) -> bytes:
    document: dict[str, JsonValue] = {
        "schema": KEYS_SCHEMA,
        "keys": [cast(JsonValue, key.body()) for key in keys],
    }
    return canonical_encode(document) + b"\n"


def _decode(data: bytes) -> tuple[GatewayKey, ...]:
    try:
        if not data.endswith(b"\n"):
            raise ValueError("trailer")
        parsed = strict_json_parse(data[:-1])
        if type(parsed) is not dict:
            raise ValueError("shape")
        document = cast(dict[str, JsonValue], parsed)
        if set(document) != {"schema", "keys"} or document["schema"] != KEYS_SCHEMA:
            raise ValueError("schema")
        entries = document["keys"]
        if type(entries) is not tuple and type(entries) is not list:
            raise ValueError("keys")
        keys: list[GatewayKey] = []
        for entry in cast(list[JsonValue], entries):
            if type(entry) is not dict or frozenset(cast(dict[str, JsonValue], entry)) != _FIELDS:
                raise ValueError("entry")
            fields = cast(dict[str, object], entry)
            keys.append(
                GatewayKey(
                    key_id=cast(str, fields["key_id"]),
                    label=cast(str, fields["label"]),
                    scope=cast(KeyScope, fields["scope"]),
                    created_at=cast(str, fields["created_at"]),
                    salt=cast(str, fields["salt"]),
                    digest=cast(str, fields["digest"]),
                    principal=cast(Literal["owner"], fields["principal"]),
                    expires_at=cast(str | None, fields["expires_at"]),
                    revoked_at=cast(str | None, fields["revoked_at"]),
                    last_used_at=cast(str | None, fields["last_used_at"]),
                )
            )
    except GatewayKeyError:
        raise GatewayKeyError("gateway_keys_invalid") from None
    except (TypeError, ValueError):
        raise GatewayKeyError("gateway_keys_invalid") from None
    if len({key.key_id for key in keys}) != len(keys):
        raise GatewayKeyError("gateway_keys_invalid")
    result = tuple(keys)
    if _encode(result) != data:
        raise GatewayKeyError("gateway_keys_invalid")
    return result


def _file_identity(path: Path) -> tuple[int, int, int, int] | None:
    try:
        facts = path.lstat()
    except FileNotFoundError:
        return None
    except OSError:
        raise GatewayKeyError("gateway_keys_unsafe") from None
    if (
        not stat.S_ISREG(facts.st_mode)
        or facts.st_uid != os.geteuid()
        or stat.S_IMODE(facts.st_mode) & 0o077
        or facts.st_size > _MAX_KEYS_BYTES
    ):
        raise GatewayKeyError("gateway_keys_unsafe")
    return facts.st_dev, facts.st_ino, facts.st_size, facts.st_mtime_ns


def _read(directory: Path) -> tuple[GatewayKey, ...]:
    path = _keys_path(directory)
    if _file_identity(path) is None:
        return ()
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return ()
    except OSError:
        raise GatewayKeyError("gateway_keys_unsafe") from None
    try:
        data = os.read(descriptor, _MAX_KEYS_BYTES + 1)
    finally:
        os.close(descriptor)
    return _decode(data)


def _write(directory: Path, keys: tuple[GatewayKey, ...]) -> None:
    path = _keys_path(directory)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
    descriptor = os.open(
        temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600
    )
    try:
        try:
            view = memoryview(_encode(keys))
            while view:
                view = view[os.write(descriptor, view) :]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


@contextlib.contextmanager
def _locked(directory: Path) -> Generator[None]:
    try:
        ensure_owner_only_dir(directory)
    except PathSafetyError:
        raise GatewayKeyError("gateway_keys_unsafe") from None
    descriptor = os.open(
        directory / _LOCK_NAME, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600
    )
    try:
        facts = os.fstat(descriptor)
        if not stat.S_ISREG(facts.st_mode) or facts.st_uid != os.geteuid():
            raise GatewayKeyError("gateway_keys_unsafe")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


def _now() -> datetime:
    return datetime.now(UTC)


def list_keys(directory: Path) -> tuple[GatewayKey, ...]:
    """Every key record, ordered by creation then id."""

    return tuple(sorted(_read(directory), key=lambda key: (key.created_at, key.key_id)))


def create_key(
    directory: Path,
    *,
    label: str | None,
    scope: KeyScope | None,
    expires_in_days: int | None = None,
    rotate: str | None = None,
    now: datetime | None = None,
) -> tuple[GatewayKey, str]:
    """Create a key; return its record and the one-time ``fuk_…`` key text.

    ``rotate`` names an existing key whose label and scope the new key takes unless given; the old
    key stays valid until it is revoked, after the client logged in with the new one.
    """

    stamp = now or _now()
    if expires_in_days is not None and not 1 <= expires_in_days <= _MAX_EXPIRY_DAYS:
        raise GatewayKeyError("gateway_key_expiry_invalid")
    with _locked(directory):
        keys = _read(directory)
        if rotate is not None:
            previous = next((key for key in keys if key.key_id == rotate), None)
            if previous is None:
                raise GatewayKeyError("gateway_key_unknown")
            label = label or previous.label
            scope = scope or previous.scope
        if label is None or not _LABEL.match(label):
            raise GatewayKeyError("gateway_key_label_invalid")
        if scope not in {"agent", "operator"}:
            raise GatewayKeyError("gateway_key_scope_invalid")
        if len(keys) >= _MAX_KEYS:
            raise GatewayKeyError("gateway_key_limit")
        taken = {key.key_id for key in keys}
        key_id = secrets.token_hex(6)
        while key_id in taken:
            key_id = secrets.token_hex(6)
        secret = base64.urlsafe_b64encode(secrets.token_bytes(_SECRET_BYTES)).decode("ascii")
        secret = secret.rstrip("=")
        salt = secrets.token_bytes(_SALT_BYTES)
        record = GatewayKey(
            key_id=key_id,
            label=label,
            scope=scope,
            created_at=format_rfc3339_ms(stamp),
            salt=base64.b64encode(salt).decode("ascii"),
            digest=_digest(salt, secret),
            expires_at=(
                None
                if expires_in_days is None
                else format_rfc3339_ms(stamp + timedelta(days=expires_in_days))
            ),
        )
        _write(directory, (*keys, record))
    return record, f"fuk_{key_id}_{secret}"


def revoke_key(directory: Path, key_id: str, *, now: datetime | None = None) -> GatewayKey:
    """Mark ``key_id`` revoked (idempotent: an already revoked key keeps its first time)."""

    if type(key_id) is not str or not _KEY_ID.match(key_id):
        raise GatewayKeyError("gateway_key_unknown")
    with _locked(directory):
        keys = _read(directory)
        for index, key in enumerate(keys):
            if key.key_id != key_id:
                continue
            if key.revoked_at is not None:
                return key
            revoked = replace(key, revoked_at=format_rfc3339_ms(now or _now()))
            _write(directory, (*keys[:index], revoked, *keys[index + 1 :]))
            return revoked
    raise GatewayKeyError("gateway_key_unknown")


def record_use(directory: Path, key_id: str, *, now: datetime | None = None) -> None:
    """Record ``last_used_at`` for one key (the gateway throttles how often it calls this)."""

    with _locked(directory):
        keys = _read(directory)
        stamp = format_rfc3339_ms(now or _now())
        updated = tuple(
            replace(key, last_used_at=stamp) if key.key_id == key_id else key for key in keys
        )
        if updated != keys:
            _write(directory, updated)


class KeyRing:
    """The running gateway's view of the key file, re-read whenever the file changes."""

    def __init__(self, directory: Path) -> None:
        self._directory = directory
        self._identity: tuple[int, int, int, int] | None = None
        self._keys: dict[str, GatewayKey] = {}

    def refresh(self) -> None:
        """Re-read the file if it changed; an unreadable file fails closed (no key matches)."""

        try:
            identity = _file_identity(_keys_path(self._directory))
            if identity == self._identity and identity is not None:
                return
            keys = _read(self._directory)
        except GatewayKeyError:
            self._identity = None
            self._keys = {}
            return
        self._identity = identity
        self._keys = {key.key_id: key for key in keys}

    def revoked_ids(self, now: datetime | None = None) -> frozenset[str]:
        """Key ids that no longer authenticate (revoked, expired or removed)."""

        stamp = now or _now()
        return frozenset(
            key.key_id for key in self._keys.values() if key.failure(stamp) is not None
        )

    def known(self, key_id: str) -> bool:
        return key_id in self._keys

    def authenticate(
        self, bearer: str, now: datetime | None = None
    ) -> GatewayKey | AuthenticationFailure:
        """The key a bearer token names, or the closed reason it does not authenticate."""

        self.refresh()
        parsed = parse_api_key(bearer)
        if parsed is None:
            return "api_key_invalid"
        key_id, secret = parsed
        record = self._keys.get(key_id)
        if record is None:
            hmac.compare_digest(_digest(_DECOY_SALT, secret), _digest(_DECOY_SALT, ""))
            return "api_key_invalid"
        if not record.matches(secret):
            return "api_key_invalid"
        failure = record.failure(now or _now())
        return record if failure is None else failure
