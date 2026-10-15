"""Instance identity for independent FinishUP installations (issue #604).

An *instance* is one FinishUP runtime plus the state it owns. The everyday installation is the
``permanent`` instance: it carries no marker and resolves the ambient platform directories. A
``persistent`` development instance or a ``disposable`` test snapshot is an ADR-026 isolated root
whose state directory carries an owner-only, digest-sealed ``instance-identity.json`` naming its
lifecycle, exact source revision, package identity, and bounded lifetime. A snapshot's own virtual
environment may additionally carry a *runtime pin* that binds the executable to that root, so a
host, hook, or shell that drops ``FINISHUP_ISOLATED_ROOT`` still resolves the snapshot's state and
never the everyday singleton (``config/paths.py`` owns that resolution).

Nothing here connects to a service or opens a ledger. Every failure is a bounded reason token.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Final, Literal, cast

from finishup.config.paths import (
    RUNTIME_PIN_NAME,
    RUNTIME_PIN_SCHEMA,
    RuntimePin,
    ensure_owner_only_dir,
)
from finishup.protocol.canonical import JsonValue, canonical_encode, strict_json_parse
from finishup.protocol.ids import IdKind, new_id, validate_id

__all__ = [
    "INSTANCE_IDENTITY_NAME",
    "INSTANCE_IDENTITY_SCHEMA",
    "INSTANCE_LIFECYCLES",
    "REPORTED_LIFECYCLES",
    "InstanceIdentity",
    "InstanceIdentityError",
    "InstanceLifecycle",
    "ReportedLifecycle",
    "SourceState",
    "format_rfc3339_ms",
    "instance_identity_path",
    "is_expired",
    "new_instance_identity",
    "parse_rfc3339_ms",
    "read_instance_identity",
    "remove_runtime_pin",
    "runtime_prefix_digest",
    "validate_package_digest",
    "validate_source_ref",
    "verify_instance_binding",
    "write_instance_identity",
    "write_runtime_pin",
]

INSTANCE_IDENTITY_NAME: Final = "instance-identity.json"
# Frozen legacy identifier (ADR-048): sealed into existing instance markers and their digest.
INSTANCE_IDENTITY_SCHEMA: Final = "yoetz.instance-identity/1"
_INSTANCE_IDENTITY_DOMAIN: Final = b"yoetz/instance-identity/v1\x00"
_MAX_INSTANCE_IDENTITY_BYTES: Final = 8_192
# Bounded lifetime for a disposable instance: long enough for a CI job or an overnight soak, short
# enough that a forgotten snapshot cannot outlive the revision it was cut from by much.
MAX_DISPOSABLE_LIFETIME: Final = timedelta(days=30)

type InstanceLifecycle = Literal["persistent", "disposable"]
type ReportedLifecycle = Literal["permanent", "persistent", "disposable", "unlabeled"]
type SourceState = Literal["clean", "modified", "unknown"]

INSTANCE_LIFECYCLES: Final = frozenset({"persistent", "disposable"})
REPORTED_LIFECYCLES: Final = frozenset({"permanent", "persistent", "disposable", "unlabeled"})
_SOURCE_STATES: Final = frozenset({"clean", "modified", "unknown"})
_RFC3339_MS: Final = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$", re.ASCII)
_SOURCE_REF: Final = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$", re.ASCII)
_SHA256: Final = re.compile(r"^sha256:[0-9a-f]{64}$", re.ASCII)
_VERSION: Final = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+-]{0,127}$", re.ASCII)
_MARKER_FIELDS: Final = frozenset(
    {
        "schema",
        "installation_id",
        "lifecycle",
        "created_at",
        "expires_at",
        "source_ref",
        "source_state",
        "package_version",
        "package_digest",
        "runtime_prefix_digest",
        "record_digest",
    }
)
_REASONS: Final = frozenset(
    {
        "installation_identity_mismatch",
        "instance_absent",
        "instance_exists",
        "instance_expired",
        "instance_expiry_invalid",
        "instance_identity_invalid",
        "instance_lifecycle_requires_isolated_root",
        "instance_not_disposable",
        "instance_root_invalid",
        "instance_root_too_long",
        "instance_service_running",
        "runtime_pin_conflict",
        "runtime_pin_invalid",
        "runtime_pin_unwritable",
    }
)


class InstanceIdentityError(Exception):
    """A bounded instance-identity failure; ``reason`` is a closed token, never content."""

    reason: str

    def __init__(self, reason: str) -> None:
        if type(reason) is not str or reason not in _REASONS:
            raise ValueError("instance_identity_reason_invalid")
        self.reason = reason
        super().__init__(reason)


def format_rfc3339_ms(value: datetime) -> str:
    """Render a UTC-aware datetime as the RFC 3339 millisecond form FinishUP records everywhere."""

    if value.tzinfo is None:
        raise ValueError("timestamp_naive")
    utc = value.astimezone(UTC)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{utc.microsecond // 1000:03d}Z"


def parse_rfc3339_ms(value: object) -> datetime:
    if type(value) is not str or not _RFC3339_MS.match(value):
        raise ValueError("timestamp_invalid")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)


def validate_source_ref(value: object) -> str:
    """Accept only an exact 40- or 64-hex commit identity; anything else is not a revision."""

    if type(value) is not str or not _SOURCE_REF.match(value):
        raise ValueError("source_ref_invalid")
    return value


def validate_package_digest(value: object) -> str:
    if type(value) is not str or not _SHA256.match(value):
        raise ValueError("package_digest_invalid")
    return value


def runtime_prefix_digest(prefix: Path) -> str:
    """Digest over the canonical runtime prefix identity; the path itself is never recorded."""

    try:
        resolved = prefix.resolve(strict=False)
    except OSError:
        resolved = prefix
    return "sha256:" + hashlib.sha256(str(resolved).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class InstanceIdentity:
    installation_id: str
    lifecycle: InstanceLifecycle
    created_at: str
    expires_at: str | None
    source_ref: str | None
    source_state: SourceState
    package_version: str
    package_digest: str | None
    runtime_prefix_digest: str

    def __post_init__(self) -> None:
        validate_id(IdKind.INSTALLATION, self.installation_id)
        if self.lifecycle not in INSTANCE_LIFECYCLES:
            raise ValueError("instance_lifecycle_invalid")
        created = parse_rfc3339_ms(self.created_at)
        if self.expires_at is not None:
            if self.lifecycle != "disposable":
                raise ValueError("instance_expiry_invalid")
            expires = parse_rfc3339_ms(self.expires_at)
            if expires <= created or expires - created > MAX_DISPOSABLE_LIFETIME:
                raise ValueError("instance_expiry_invalid")
        if self.source_ref is not None:
            validate_source_ref(self.source_ref)
        if self.source_state not in _SOURCE_STATES:
            raise ValueError("source_state_invalid")
        if type(self.package_version) is not str or not _VERSION.match(self.package_version):
            raise ValueError("package_version_invalid")
        if self.package_digest is not None:
            validate_package_digest(self.package_digest)
        if type(self.runtime_prefix_digest) is not str or not _SHA256.match(
            self.runtime_prefix_digest
        ):
            raise ValueError("runtime_prefix_digest_invalid")

    def body(self) -> dict[str, JsonValue]:
        return {
            "schema": INSTANCE_IDENTITY_SCHEMA,
            "installation_id": self.installation_id,
            "lifecycle": self.lifecycle,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "source_ref": self.source_ref,
            "source_state": self.source_state,
            "package_version": self.package_version,
            "package_digest": self.package_digest,
            "runtime_prefix_digest": self.runtime_prefix_digest,
        }

    def encode(self) -> bytes:
        body = self.body()
        body["record_digest"] = _record_digest(body)
        return canonical_encode(cast(JsonValue, body)) + b"\n"


def _record_digest(body: dict[str, JsonValue]) -> str:
    return (
        "sha256:"
        + hashlib.sha256(
            _INSTANCE_IDENTITY_DOMAIN + canonical_encode(cast(JsonValue, body))
        ).hexdigest()
    )


def new_instance_identity(
    lifecycle: InstanceLifecycle,
    *,
    now: datetime,
    package_version: str,
    runtime_prefix: Path,
    expires_at: datetime | None = None,
    source_ref: str | None = None,
    source_state: SourceState = "unknown",
    package_digest: str | None = None,
) -> InstanceIdentity:
    """Mint a fresh installation identity for a new instance; ``now`` is the creation time."""

    try:
        return InstanceIdentity(
            new_id(IdKind.INSTALLATION),
            lifecycle,
            format_rfc3339_ms(now),
            None if expires_at is None else format_rfc3339_ms(expires_at),
            source_ref,
            source_state,
            package_version,
            package_digest,
            runtime_prefix_digest(runtime_prefix),
        )
    except ValueError as exc:
        if str(exc) == "instance_expiry_invalid":
            raise InstanceIdentityError("instance_expiry_invalid") from exc
        raise InstanceIdentityError("instance_identity_invalid") from exc


def is_expired(identity: InstanceIdentity, now: datetime) -> bool:
    if identity.expires_at is None:
        return False
    return now >= parse_rfc3339_ms(identity.expires_at)


def instance_identity_path(state_root: Path) -> Path:
    return state_root / INSTANCE_IDENTITY_NAME


def _read_private_file(path: Path, maximum: int) -> bytes:
    facts = path.lstat()
    if (
        not stat.S_ISREG(facts.st_mode)
        or facts.st_uid != os.geteuid()
        or stat.S_IMODE(facts.st_mode) & 0o077
        or facts.st_size > maximum
    ):
        raise InstanceIdentityError("instance_identity_invalid")
    with path.open("rb") as source:
        encoded = source.read(maximum + 1)
    if len(encoded) > maximum:
        raise InstanceIdentityError("instance_identity_invalid")
    return encoded


def read_instance_identity(state_root: Path) -> InstanceIdentity | None:
    """Return the sealed identity beneath ``state_root``, ``None`` when absent, or fail closed."""

    path = instance_identity_path(state_root)
    try:
        encoded = _read_private_file(path, _MAX_INSTANCE_IDENTITY_BYTES)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise InstanceIdentityError("instance_identity_invalid") from exc
    try:
        if not encoded.endswith(b"\n") or encoded.endswith(b"\n\n"):
            raise ValueError("trailer")
        value = strict_json_parse(encoded[:-1])
        if type(value) is not dict:
            raise ValueError("shape")
        source = cast(dict[str, JsonValue], value)
        if canonical_encode(cast(JsonValue, source)) != encoded[:-1]:
            raise ValueError("canonical")
        if frozenset(source) != _MARKER_FIELDS or source["schema"] != INSTANCE_IDENTITY_SCHEMA:
            raise ValueError("fields")
        body = dict(source)
        record = body.pop("record_digest")
        if type(record) is not str or not hmac.compare_digest(record, _record_digest(body)):
            raise ValueError("record_digest")
        lifecycle = source["lifecycle"]
        source_state = source["source_state"]
        if lifecycle not in INSTANCE_LIFECYCLES or source_state not in _SOURCE_STATES:
            raise ValueError("enum")
        for name in ("created_at", "package_version", "runtime_prefix_digest"):
            if type(source[name]) is not str:
                raise ValueError(name)
        for name in ("expires_at", "source_ref", "package_digest"):
            if source[name] is not None and type(source[name]) is not str:
                raise ValueError(name)
        return InstanceIdentity(
            cast(str, source["installation_id"]),
            cast(InstanceLifecycle, lifecycle),
            cast(str, source["created_at"]),
            cast(str | None, source["expires_at"]),
            cast(str | None, source["source_ref"]),
            cast(SourceState, source_state),
            cast(str, source["package_version"]),
            cast(str | None, source["package_digest"]),
            cast(str, source["runtime_prefix_digest"]),
        )
    except Exception as exc:
        raise InstanceIdentityError("instance_identity_invalid") from exc


def _write_temporary_then_replace(path: Path, encoded: bytes, *, sync_directory: bool) -> None:
    """Write ``encoded`` to a fresh owner-only temporary beside ``path`` and rename it into place.

    A failure at any step removes the temporary, so a refused write leaves nothing behind: the
    caller can unwind the directory it created, and a retry finds it as it was.
    """

    temporary = path.with_name(f".{path.name}.{os.urandom(12).hex()}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
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
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    if sync_directory:
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


def _write_private_atomic(path: Path, encoded: bytes) -> None:
    ensure_owner_only_dir(path.parent)
    _write_temporary_then_replace(path, encoded, sync_directory=True)


def write_instance_identity(state_root: Path, identity: InstanceIdentity) -> Path:
    """Seal ``identity`` beneath ``state_root``; an existing marker is never overwritten."""

    path = instance_identity_path(state_root)
    if path.exists() or path.is_symlink():
        raise InstanceIdentityError("instance_exists")
    _write_private_atomic(path, identity.encode())
    return path


def verify_instance_binding(
    identity: InstanceIdentity | None,
    *,
    isolated: bool,
    pin: RuntimePin | None,
    now: datetime,
) -> None:
    """Refuse a service start whose runtime, root, and identity do not agree.

    - A pin without a marker, or a pin naming another installation, is a re-pointed runtime:
      ``installation_identity_mismatch`` rather than a silently redirected service.
    - A marker outside an isolated root is a labeled instance in ambient state:
      ``instance_lifecycle_requires_isolated_root``.
    - A disposable instance past ``expires_at`` is ``instance_expired``; it can be disposed but
      never served.
    """

    if identity is None:
        if pin is not None:
            raise InstanceIdentityError("installation_identity_mismatch")
        return
    if not isolated:
        raise InstanceIdentityError("instance_lifecycle_requires_isolated_root")
    if pin is not None and pin.installation_id != identity.installation_id:
        raise InstanceIdentityError("installation_identity_mismatch")
    if is_expired(identity, now):
        raise InstanceIdentityError("instance_expired")


def _pinned_root(path: Path) -> str | None:
    """The root an existing pin file names, or ``None`` when it is malformed."""

    try:
        existing: object = json.loads(path.read_bytes())
    except OSError, ValueError:
        raise InstanceIdentityError("runtime_pin_invalid") from None
    if not isinstance(existing, dict):
        return None
    value = cast(dict[object, object], existing).get("isolated_root")
    return value if type(value) is str else None


def write_runtime_pin(prefix: Path, root: Path, installation_id: str) -> Path:
    """Bind the runtime at ``prefix`` to ``root``; an existing pin must name the same root.

    A prefix the current user cannot write (a runtime another account installed, a read-only
    image layer, a full disk) is ``runtime_pin_unwritable`` with no temporary file left behind.
    """

    validate_id(IdKind.INSTALLATION, installation_id)
    if not root.is_absolute() or not prefix.is_dir():
        raise InstanceIdentityError("runtime_pin_invalid")
    path = prefix / RUNTIME_PIN_NAME
    if path.is_symlink():
        raise InstanceIdentityError("runtime_pin_invalid")
    if path.exists() and _pinned_root(path) != str(root):
        raise InstanceIdentityError("runtime_pin_conflict")
    body: dict[str, JsonValue] = {
        "schema": RUNTIME_PIN_SCHEMA,
        "isolated_root": str(root),
        "installation_id": installation_id,
    }
    encoded = canonical_encode(cast(JsonValue, body)) + b"\n"
    try:
        _write_temporary_then_replace(path, encoded, sync_directory=False)
    except OSError:
        # Closed token only: the OS message names the prefix, a local path.
        raise InstanceIdentityError("runtime_pin_unwritable") from None
    return path


def remove_runtime_pin(prefix: Path, root: Path) -> bool:
    """Remove the pin at ``prefix`` only when it names ``root``; return whether it was removed."""

    path = prefix / RUNTIME_PIN_NAME
    if path.is_symlink() or not path.is_file():
        return False
    try:
        if _pinned_root(path) != str(root):
            return False
    except InstanceIdentityError:
        return False
    try:
        path.unlink()
    except FileNotFoundError:
        return False
    return True
