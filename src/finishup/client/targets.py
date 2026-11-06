"""Server targets: the FinishUP servers this client can use, and which one is selected (ADR-051).

A *target* is one root beneath ``<ambient state dir>/servers/t_<8 hex>/`` holding an owner-only
``target.json`` (``yoetz.server-target/1``) with an exact field set per kind:

* ``local`` — a named local server: an ADR-028 persistent instance root with its own vault,
  ledger, and service, started on demand like the everyday one.
* ``local_port`` — a FinishUP server reached over HTTPS on this machine's loopback
  (``https://127.0.0.1:<port>`` or ``https://[::1]:<port>``).
* ``ssh`` — a server on another machine reached over OpenSSH (``ssh://[user@]host[:port]``).
* ``https`` — a server reached over HTTPS (``https://host[:port][/base]``); plain HTTP is refused.

Non-local kinds also record a per-target ``claim_salt`` (32 random bytes) and the owner's
authorization (``authorized_at``, ``disclosure_version``). A remote root holds client state only.

The owner-only selection file ``<ambient config dir>/server-selection.json``
(``yoetz.server-selection/1``) names one target; absent, the everyday server is used exactly as
before. ``config.paths.active_root()`` reads it. Names match ``[a-z0-9][a-z0-9-]{0,15}``, ``local``
is reserved, and a name appears only in ``target.json`` and owner displays; everything else
names a target by its id. Every failure is a closed ``TargetError`` reason.

This module imports only the standard library and lean SHARED modules, so a hook may import it.
"""

from __future__ import annotations

import base64
import binascii
import fcntl
import ipaddress
import os
import re
import secrets
import shutil
import stat
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Literal, cast
from urllib.parse import urlsplit

from finishup.config.installation import (
    format_rfc3339_ms,
    instance_root_fits,
    parse_rfc3339_ms,
    socket_path_fits,
)
from finishup.config.paths import (
    SERVER_SELECTION_NAME,
    SERVER_SELECTION_SCHEMA,
    SERVER_TARGET_FILE_NAME,
    SERVERS_DIR_NAME,
    IsolationBinding,
    PathSafetyError,
    active_root,
    ambient_registry_dirs,
    ensure_owner_only_dir,
    isolation_binding,
    reset_selection_memo,
    verify_private_local_bundle,
)
from finishup.protocol.canonical import JsonValue, canonical_encode, strict_json_parse

__all__ = [
    "CLAIM_SALT_BYTES",
    "DISCLOSURE_VERSION",
    "REMOTE_KINDS",
    "RESERVED_NAMES",
    "TARGET_KINDS",
    "TARGET_SCHEMA",
    "CredentialLocation",
    "SelectionSource",
    "ServerTarget",
    "TargetError",
    "TargetKind",
    "TargetRecordUnreadable",
    "active_root_may_be_remote",
    "active_target_is_remote",
    "active_target_record",
    "clear_selection",
    "find_target",
    "list_targets",
    "new_local_target",
    "new_remote_target",
    "normalize_https_url",
    "parse_ssh_url",
    "read_selected_target_id",
    "read_target",
    "reauthorized",
    "registry_lock",
    "remove_target_root",
    "require_current_authorization",
    "selection_path",
    "selection_source",
    "servers_dir",
    "target_root",
    "validate_name",
    "write_selection",
    "write_target",
]

TARGET_SCHEMA: Final = "yoetz.server-target/1"
TARGET_KINDS: Final = ("local", "local_port", "ssh", "https")
REMOTE_KINDS: Final = frozenset({"local_port", "ssh", "https"})
RESERVED_NAMES: Final = frozenset({"local"})
# The versioned disclosure the owner confirmed for a remote target (design section 6). A new
# version forces the owner to confirm again before the target is used.
DISCLOSURE_VERSION: Final = 1
CLAIM_SALT_BYTES: Final = 32

type TargetKind = Literal["local", "local_port", "ssh", "https"]
type CredentialLocation = Literal["keyring", "file"]
# Which source decided this process's root (``config.paths.isolation_binding``).
type SelectionSource = IsolationBinding

_NAME: Final = re.compile(r"^[a-z0-9][a-z0-9-]{0,15}$", re.ASCII)
_TARGET_ID: Final = re.compile(r"^t_[0-9a-f]{8}$", re.ASCII)
_TLS_PIN: Final = re.compile(r"^sha256:[0-9a-f]{64}$", re.ASCII)
_SSH_USER: Final = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,31}$", re.ASCII)
_DNS_NAME: Final = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$",
    re.ASCII,
)
_URL_PATH: Final = re.compile(r"^(?:/[A-Za-z0-9._~-]+)*/?$", re.ASCII)
_MAX_RECORD_BYTES: Final = 8_192
_MAX_PATH_TEXT: Final = 1_024
# The sockets a client may bind beneath a remote target root, each with the temporary suffix it
# is bound under first. A remote root runs no service, so the service's endpoints (the instance
# bound a ``local`` root is held to) never apply to it. OpenSSH binds its ControlMaster ``run/m``
# at ``run/m.<16 random characters>`` and renames it into place, the longest of these; a relay or
# forwarded socket (``run/control.sock``, ``run/upstream.sock``, ``run/api.sock``, as the
# topology needs) binds directly. An HTTPS or ``local_port`` target may bind none.
_REMOTE_CLIENT_SOCKETS: Final = (
    (Path("run") / "m", 17),
    (Path("run") / "control.sock", 0),
    (Path("run") / "upstream.sock", 0),
    (Path("run") / "api.sock", 0),
)
_REGISTRY_LOCK_NAME: Final = ".registry.lock"
_COMMON_FIELDS: Final = frozenset({"schema", "target_id", "name", "kind", "created_at"})
_REMOTE_FIELDS: Final = frozenset({"claim_salt", "authorized_at", "disclosure_version"})
_HTTPS_FIELDS: Final = frozenset({"base_url", "ca_file", "tls_pin", "credential"})
_SSH_FIELDS: Final = frozenset(
    {"user", "host", "port", "remote_root", "remote_endpoint", "remote_launcher"}
)
_FIELDS_BY_KIND: Final[dict[str, frozenset[str]]] = {
    "local": _COMMON_FIELDS,
    "local_port": _COMMON_FIELDS | _HTTPS_FIELDS | _REMOTE_FIELDS,
    "https": _COMMON_FIELDS | _HTTPS_FIELDS | _REMOTE_FIELDS,
    "ssh": _COMMON_FIELDS | _SSH_FIELDS | _REMOTE_FIELDS,
}
_REASONS: Final = frozenset(
    {
        "selection_overridden",
        "target_name_invalid",
        "target_name_reserved",
        "target_name_taken",
        "target_unknown",
        "target_selected",
        "target_record_invalid",
        "target_reauthorization_required",
        "target_url_invalid",
        "target_tls_invalid",
        "target_path_invalid",
        "target_root_too_long",
        "target_root_unsafe",
        "selection_invalid",
    }
)


class TargetError(Exception):
    """A bounded target failure; ``reason`` is a closed token, never user text."""

    reason: str

    def __init__(self, reason: str) -> None:
        if reason not in _REASONS:
            raise ValueError("target_reason_invalid")
        self.reason = reason
        super().__init__(reason)


class TargetRecordUnreadable(TargetError):
    """The active root resolves, but the server target record it holds cannot be read.

    Its ``reason`` is the record's own closed refusal (``target_root_unsafe`` or
    ``target_record_invalid``). Whether such a root is this machine's server or a remote one is
    unknown, so a caller deciding where something may run fails closed on it, while a root that
    cannot be resolved at all stays a plain ``TargetError`` its own path reports. ``target_id`` is
    the root's generated ``t_<8 hex>`` folder name when it has one, never other folder text.
    """

    target_id: str | None

    def __init__(self, reason: str, target_id: str | None) -> None:
        super().__init__(reason)
        self.target_id = (
            target_id if target_id is not None and _TARGET_ID.match(target_id) else None
        )


def _absolute_text(value: str | None, *, required: bool = False) -> None:
    if value is None:
        if required:
            raise TargetError("target_path_invalid")
        return
    if (
        type(value) is not str
        or not value.startswith("/")
        or len(value) > _MAX_PATH_TEXT
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise TargetError("target_path_invalid")


def _port(value: object) -> int:
    if type(value) is not int or not 1 <= value <= 65_535:
        raise TargetError("target_url_invalid")
    return value


def _host(value: object) -> str:
    """A DNS name or an IP literal; never anything ``ssh`` or a URL parser could read as an option."""

    if type(value) is not str or not value:
        raise TargetError("target_url_invalid")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        if not _DNS_NAME.match(value):
            raise TargetError("target_url_invalid") from None
    return value


def validate_name(name: str) -> str:
    """Return ``name`` when it is a usable target name, else raise a closed reason."""

    if type(name) is not str or not _NAME.match(name):
        raise TargetError("target_name_invalid")
    if name in RESERVED_NAMES:
        raise TargetError("target_name_reserved")
    return name


def normalize_https_url(raw: str, *, loopback_only: bool = False) -> str:
    """Normalize ``https://host[:port][/base]``; refuse plain HTTP, userinfo, query, fragment.

    ``loopback_only`` additionally requires ``127.0.0.1`` or ``[::1]`` with an explicit port
    (the ``local_port`` kind).
    """

    if type(raw) is not str or len(raw) > 2_048 or any(ord(c) <= 0x20 for c in raw):
        raise TargetError("target_url_invalid")
    try:
        parts = urlsplit(raw)
        port = parts.port
    except ValueError:
        raise TargetError("target_url_invalid") from None
    if (
        parts.scheme.lower() != "https"
        or parts.username is not None
        or parts.password is not None
        or parts.query
        or parts.fragment
        or "@" in parts.netloc
        or parts.hostname is None
        or not _URL_PATH.match(parts.path)
    ):
        raise TargetError("target_url_invalid")
    host = parts.hostname.lower()
    if ":" in host:
        try:
            literal = ipaddress.IPv6Address(host)
        except ValueError:
            raise TargetError("target_url_invalid") from None
        authority = f"[{literal.compressed}]"
    else:
        authority = _host(host)
    if port is not None:
        _port(port)
    if loopback_only:
        if port is None or authority not in {"127.0.0.1", "[::1]"}:
            raise TargetError("target_url_invalid")
    path = parts.path.rstrip("/")
    return f"https://{authority}{'' if port is None else f':{port}'}{path}"


def parse_ssh_url(raw: str) -> tuple[str | None, str, int]:
    """Parse ``ssh://[user@]host[:port]`` into ``(user, host, port)``; nothing else is accepted."""

    if type(raw) is not str or len(raw) > 512 or any(ord(c) <= 0x20 for c in raw):
        raise TargetError("target_url_invalid")
    try:
        parts = urlsplit(raw)
        port = parts.port
    except ValueError:
        raise TargetError("target_url_invalid") from None
    if (
        parts.scheme != "ssh"
        or parts.password is not None
        or parts.path not in {"", "/"}
        or parts.query
        or parts.fragment
        or parts.hostname is None
    ):
        raise TargetError("target_url_invalid")
    user = parts.username
    if user is not None and not _SSH_USER.match(user):
        raise TargetError("target_url_invalid")
    host = parts.hostname
    if ":" in host:
        try:
            host = ipaddress.IPv6Address(host).compressed
        except ValueError:
            raise TargetError("target_url_invalid") from None
    else:
        host = _host(host)
    return user, host, 22 if port is None else _port(port)


@dataclass(frozen=True, slots=True)
class ServerTarget:
    """One validated ``yoetz.server-target/1`` record."""

    target_id: str
    name: str
    kind: TargetKind
    created_at: str
    base_url: str | None = None
    ca_file: str | None = None
    tls_pin: str | None = None
    credential: CredentialLocation | None = None
    user: str | None = None
    host: str | None = None
    port: int | None = None
    remote_root: str | None = None
    remote_endpoint: str | None = None
    remote_launcher: str | None = None
    claim_salt: str | None = None
    authorized_at: str | None = None
    disclosure_version: int | None = None

    def __post_init__(self) -> None:
        if type(self.target_id) is not str or not _TARGET_ID.match(self.target_id):
            raise TargetError("target_record_invalid")
        validate_name(self.name)
        if self.kind not in TARGET_KINDS:
            raise TargetError("target_record_invalid")
        try:
            parse_rfc3339_ms(self.created_at)
        except (TypeError, ValueError):
            raise TargetError("target_record_invalid") from None
        fields = _FIELDS_BY_KIND[self.kind]
        for name in ("base_url", "ca_file", "tls_pin", "credential", "user", "host", "port"):
            if name not in fields and getattr(self, name) is not None:
                raise TargetError("target_record_invalid")
        for name in ("remote_root", "remote_endpoint", "remote_launcher"):
            if name not in fields and getattr(self, name) is not None:
                raise TargetError("target_record_invalid")
        if self.kind == "local":
            if any(
                value is not None
                for value in (self.claim_salt, self.authorized_at, self.disclosure_version)
            ):
                raise TargetError("target_record_invalid")
            return
        self._validate_authorization()
        if self.kind == "ssh":
            if self.host is None or self.port is None:
                raise TargetError("target_record_invalid")
            if self.user is not None and (
                type(self.user) is not str or not _SSH_USER.match(self.user)
            ):
                raise TargetError("target_record_invalid")
            if ":" not in self.host:
                _host(self.host)
            else:
                try:
                    ipaddress.IPv6Address(self.host)
                except ValueError:
                    raise TargetError("target_record_invalid") from None
            _port(self.port)
            for value in (self.remote_root, self.remote_endpoint, self.remote_launcher):
                _absolute_text(value)
            return
        if self.base_url is None:
            raise TargetError("target_record_invalid")
        if normalize_https_url(self.base_url, loopback_only=self.kind == "local_port") != (
            self.base_url
        ):
            raise TargetError("target_record_invalid")
        if self.ca_file is not None and self.tls_pin is not None:
            raise TargetError("target_tls_invalid")
        _absolute_text(self.ca_file)
        if self.tls_pin is not None and (
            type(self.tls_pin) is not str or not _TLS_PIN.match(self.tls_pin)
        ):
            raise TargetError("target_tls_invalid")
        if self.credential not in {None, "keyring", "file"}:
            raise TargetError("target_record_invalid")

    def _validate_authorization(self) -> None:
        try:
            salt = base64.b64decode(cast(str, self.claim_salt), validate=True)
            parse_rfc3339_ms(self.authorized_at)
        except (TypeError, ValueError, binascii.Error):
            raise TargetError("target_record_invalid") from None
        if len(salt) != CLAIM_SALT_BYTES:
            raise TargetError("target_record_invalid")
        version = self.disclosure_version
        if type(version) is not int or version < 1:
            raise TargetError("target_record_invalid")

    @property
    def is_remote(self) -> bool:
        return self.kind in REMOTE_KINDS

    @property
    def needs_reauthorization(self) -> bool:
        """True when the owner confirmed an older disclosure than this release shows."""

        return self.is_remote and self.disclosure_version != DISCLOSURE_VERSION

    def body(self) -> dict[str, JsonValue]:
        """The exact ``target.json`` object for this kind."""

        values: dict[str, JsonValue] = {
            "schema": TARGET_SCHEMA,
            "target_id": self.target_id,
            "name": self.name,
            "kind": self.kind,
            "created_at": self.created_at,
            "base_url": self.base_url,
            "ca_file": self.ca_file,
            "tls_pin": self.tls_pin,
            "credential": self.credential,
            "user": self.user,
            "host": self.host,
            "port": self.port,
            "remote_root": self.remote_root,
            "remote_endpoint": self.remote_endpoint,
            "remote_launcher": self.remote_launcher,
            "claim_salt": self.claim_salt,
            "authorized_at": self.authorized_at,
            "disclosure_version": self.disclosure_version,
        }
        fields = _FIELDS_BY_KIND[self.kind]
        return {key: value for key, value in values.items() if key in fields}

    def encode(self) -> bytes:
        return canonical_encode(cast(JsonValue, self.body())) + b"\n"


def _decode_target(encoded: bytes) -> ServerTarget:
    try:
        if not encoded.endswith(b"\n"):
            raise ValueError("trailer")
        value = strict_json_parse(encoded[:-1])
        if type(value) is not dict:
            raise ValueError("shape")
        source = cast(dict[str, JsonValue], value)
        kind = source.get("kind")
        if type(kind) is not str or kind not in _FIELDS_BY_KIND:
            raise ValueError("kind")
        if frozenset(source) != _FIELDS_BY_KIND[kind] or source["schema"] != TARGET_SCHEMA:
            raise ValueError("fields")
        if canonical_encode(cast(JsonValue, source)) != encoded[:-1]:
            raise ValueError("canonical")
        for name in ("target_id", "name", "created_at"):
            if type(source[name]) is not str:
                raise ValueError(name)

        def text(name: str) -> str | None:
            value = source.get(name)
            if value is not None and type(value) is not str:
                raise ValueError(name)
            return value

        port = source.get("port")
        version = source.get("disclosure_version")
        if (port is not None and type(port) is not int) or (
            version is not None and type(version) is not int
        ):
            raise ValueError("integer")
        record = ServerTarget(
            cast(str, source["target_id"]),
            cast(str, source["name"]),
            cast(TargetKind, kind),
            cast(str, source["created_at"]),
            base_url=text("base_url"),
            ca_file=text("ca_file"),
            tls_pin=text("tls_pin"),
            credential=cast(CredentialLocation | None, text("credential")),
            user=text("user"),
            host=text("host"),
            port=port,
            remote_root=text("remote_root"),
            remote_endpoint=text("remote_endpoint"),
            remote_launcher=text("remote_launcher"),
            claim_salt=text("claim_salt"),
            authorized_at=text("authorized_at"),
            disclosure_version=version,
        )
    except TargetError:
        raise TargetError("target_record_invalid") from None
    except (TypeError, ValueError):
        raise TargetError("target_record_invalid") from None
    if record.encode() != encoded:
        raise TargetError("target_record_invalid")
    return record


def _read_owner_only(path: Path, maximum: int) -> bytes | None:
    """Read a regular, owner-owned, owner-only file; ``None`` when absent; fail closed otherwise."""

    try:
        facts = path.lstat()
    except (FileNotFoundError, NotADirectoryError):
        return None
    except OSError:
        raise TargetError("target_root_unsafe") from None
    if (
        not stat.S_ISREG(facts.st_mode)
        or facts.st_uid != os.geteuid()
        or stat.S_IMODE(facts.st_mode) & 0o077
        or facts.st_size > maximum
    ):
        raise TargetError("target_root_unsafe")
    # The file can still change between the check and the read (replaced by a link, removed,
    # made unreadable): that is the same unsafe record, never a raw ``OSError``.
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise TargetError("target_root_unsafe") from None
    try:
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining > 0:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    except OSError:
        raise TargetError("target_root_unsafe") from None
    finally:
        os.close(descriptor)
    data = b"".join(chunks)
    if len(data) > maximum:
        raise TargetError("target_root_unsafe")
    return data


def _write_owner_only(path: Path, encoded: bytes) -> None:
    """Atomically replace ``path`` with ``encoded`` (owner-only temp file, fsync, rename)."""

    temporary = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
    descriptor = os.open(
        temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600
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
        temporary.unlink(missing_ok=True)
        raise
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def servers_dir() -> Path:
    """``<ambient state dir>/servers``: where every target root lives."""

    _config, state = ambient_registry_dirs()
    return state / SERVERS_DIR_NAME


def selection_path() -> Path:
    """``<ambient config dir>/server-selection.json``."""

    config, _state = ambient_registry_dirs()
    return config / SERVER_SELECTION_NAME


def target_root(target_id: str) -> Path:
    if type(target_id) is not str or not _TARGET_ID.match(target_id):
        raise TargetError("target_unknown")
    return servers_dir() / target_id


def _check_root_length(root: Path, kind: TargetKind) -> None:
    """Refuse a root whose longest socket would not fit this platform's ``sun_path`` bound.

    A ``local`` root is an instance root, held to the service's own endpoints exactly as
    ``finishup instance create`` holds it (``instance_root_too_long``); a remote root only to the
    sockets a client binds there.
    """

    if kind in REMOTE_KINDS:
        fits = all(
            socket_path_fits(root / name, temporary_suffix_bytes=suffix)
            for name, suffix in _REMOTE_CLIENT_SOCKETS
        )
    else:
        fits = instance_root_fits(root)
    if not fits:
        raise TargetError("target_root_too_long")


def read_target(root: Path) -> ServerTarget | None:
    """Return the record in ``root``, ``None`` when it has none, or fail closed."""

    encoded = _read_owner_only(root / SERVER_TARGET_FILE_NAME, _MAX_RECORD_BYTES)
    if encoded is None:
        return None
    record = _decode_target(encoded)
    if record.target_id != root.name:
        raise TargetError("target_record_invalid")
    return record


def write_target(root: Path, record: ServerTarget) -> None:
    """Write ``record`` into its own root (owner-only, atomic)."""

    if record.target_id != root.name:
        raise TargetError("target_record_invalid")
    try:
        verify_private_local_bundle(root)
        ensure_owner_only_dir(root)
    except PathSafetyError:
        raise TargetError("target_root_unsafe") from None
    _write_owner_only(root / SERVER_TARGET_FILE_NAME, record.encode())


@contextmanager
def registry_lock() -> Generator[None]:
    """Serialize registry changes (add, remove, select) across processes on this machine."""

    directory = servers_dir()
    try:
        ensure_owner_only_dir(directory)
    except PathSafetyError:
        raise TargetError("target_root_unsafe") from None
    descriptor = os.open(
        directory / _REGISTRY_LOCK_NAME,
        os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
    )
    try:
        facts = os.fstat(descriptor)
        if not stat.S_ISREG(facts.st_mode) or facts.st_uid != os.geteuid():
            raise TargetError("target_root_unsafe")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


def list_targets() -> tuple[ServerTarget, ...]:
    """Every target, ordered by name; a damaged root fails closed instead of being skipped."""

    directory = servers_dir()
    try:
        entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
    except FileNotFoundError:
        return ()
    except OSError:
        raise TargetError("target_root_unsafe") from None
    records: list[ServerTarget] = []
    for entry in entries:
        if not _TARGET_ID.match(entry.name):
            continue
        if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
            raise TargetError("target_root_unsafe")
        record = read_target(Path(entry.path))
        if record is None:
            raise TargetError("target_record_invalid")
        records.append(record)
    return tuple(sorted(records, key=lambda record: record.name))


def find_target(name: str) -> ServerTarget:
    """The target named ``name``; ``target_unknown`` when there is none."""

    validate_name(name)
    for record in list_targets():
        if record.name == name:
            return record
    raise TargetError("target_unknown")


def _new_target_id(directory: Path) -> str:
    for _attempt in range(16):
        candidate = f"t_{secrets.token_hex(4)}"
        if not (directory / candidate).exists():
            return candidate
    raise TargetError("target_root_unsafe")


def _now() -> str:
    return format_rfc3339_ms(datetime.now(UTC))


def new_local_target(name: str, *, now: str | None = None) -> tuple[ServerTarget, Path]:
    """Create a named local server: a persistent instance root plus its ``target.json``.

    The instance root is made by ``finishup instance``'s own creation path, so it gets the same
    root-shape checks (including the socket path bound) and an instance identity a later
    ``remove`` can dispose of. Callers hold ``registry_lock()``.
    """

    from finishup.cli.instance import create_instance
    from finishup.config.installation import InstanceIdentityError

    validate_name(name)
    if any(record.name == name for record in list_targets()):
        raise TargetError("target_name_taken")
    directory = servers_dir()
    target_id = _new_target_id(directory)
    root = directory / target_id
    _check_root_length(root, "local")
    try:
        create_instance(root=root, lifecycle="persistent")
    except InstanceIdentityError as error:
        if error.reason == "instance_root_too_long":
            raise TargetError("target_root_too_long") from None
        raise TargetError("target_root_unsafe") from None
    except PathSafetyError:
        raise TargetError("target_root_unsafe") from None
    record = ServerTarget(target_id, name, "local", now or _now())
    try:
        write_target(root, record)
    except BaseException:
        shutil.rmtree(root, ignore_errors=True)
        raise
    return record, root


def new_remote_target(
    name: str,
    kind: TargetKind,
    *,
    base_url: str | None = None,
    ca_file: str | None = None,
    tls_pin: str | None = None,
    user: str | None = None,
    host: str | None = None,
    port: int | None = None,
    remote_root: str | None = None,
    remote_launcher: str | None = None,
    now: str | None = None,
) -> tuple[ServerTarget, Path]:
    """Create a remote target root (client state only) with a fresh claim salt.

    The caller has already obtained the owner's typed confirmation of the current disclosure on
    the trusted console; ``authorized_at`` records when. Callers hold ``registry_lock()``.
    """

    if kind not in REMOTE_KINDS:
        raise TargetError("target_record_invalid")
    validate_name(name)
    if any(record.name == name for record in list_targets()):
        raise TargetError("target_name_taken")
    stamp = now or _now()
    remote_endpoint = None if remote_root is None else f"{remote_root.rstrip('/')}/run/control.sock"
    directory = servers_dir()
    target_id = _new_target_id(directory)
    root = directory / target_id
    _check_root_length(root, kind)
    record = ServerTarget(
        target_id,
        name,
        kind,
        stamp,
        base_url=base_url,
        ca_file=ca_file,
        tls_pin=tls_pin,
        user=user,
        host=host,
        port=port,
        remote_root=remote_root,
        remote_endpoint=remote_endpoint,
        remote_launcher=remote_launcher,
        claim_salt=base64.b64encode(secrets.token_bytes(CLAIM_SALT_BYTES)).decode("ascii"),
        authorized_at=stamp,
        disclosure_version=DISCLOSURE_VERSION,
    )
    try:
        verify_private_local_bundle(directory)
        ensure_owner_only_dir(directory)
        root.mkdir(mode=0o700)
    except (PathSafetyError, OSError):
        # Nothing was made here (an existing root is never adopted or removed).
        raise TargetError("target_root_unsafe") from None
    try:
        for child in ("state", "config", "run", "log"):
            (root / child).mkdir(mode=0o700)
        write_target(root, record)
    except BaseException:
        shutil.rmtree(root, ignore_errors=True)
        raise
    return record, root


def reauthorized(record: ServerTarget, *, now: str | None = None) -> ServerTarget:
    """``record`` with a fresh authorization of the current disclosure version."""

    if not record.is_remote:
        raise TargetError("target_record_invalid")
    return replace(record, authorized_at=now or _now(), disclosure_version=DISCLOSURE_VERSION)


def require_current_authorization(record: ServerTarget | None) -> None:
    """Refuse a remote target the owner authorized under an older disclosure (ADR-051 section 8).

    A new disclosure version needs a fresh typed confirmation before anything is sent to that
    target: ``finishup server use NAME`` on the trusted console shows the current disclosure and
    records it (``reauthorized``). Raises ``target_reauthorization_required``; ``None`` and a local
    record pass. Every path that opens a connection to a remote target calls this; the display and
    reverse paths (``server status``, ``list``, ``test``, ``remove``, ``logout``) do not, so the
    owner can still see and remove a stale target.
    """

    if record is not None and record.needs_reauthorization:
        raise TargetError("target_reauthorization_required")


def remove_target_root(record: ServerTarget) -> None:
    """Delete a remote target's root; local roots go through ``dispose_instance`` instead."""

    root = target_root(record.target_id)
    if record.kind == "local":
        raise TargetError("target_record_invalid")
    if root.is_symlink() or not root.is_dir():
        raise TargetError("target_root_unsafe")
    shutil.rmtree(root)


def read_selected_target_id() -> str | None:
    """The target id the selection file names, ``None`` when there is none, or fail closed."""

    encoded = _read_owner_only(selection_path(), 1_024)
    if encoded is None:
        return None
    try:
        value = strict_json_parse(encoded.rstrip(b"\n"))
    except ValueError:
        raise TargetError("selection_invalid") from None
    if type(value) is not dict:
        raise TargetError("selection_invalid")
    source = cast(dict[str, JsonValue], value)
    target_id = source.get("target_id")
    if (
        set(source) != {"schema", "target_id"}
        or source.get("schema") != SERVER_SELECTION_SCHEMA
        or type(target_id) is not str
        or not _TARGET_ID.match(target_id)
    ):
        raise TargetError("selection_invalid")
    return target_id


def write_selection(record: ServerTarget) -> None:
    """Select ``record`` for every new client process (hooks at once; a bridge on restart)."""

    path = selection_path()
    try:
        ensure_owner_only_dir(path.parent)
    except PathSafetyError:
        raise TargetError("target_root_unsafe") from None
    body: dict[str, JsonValue] = {"schema": SERVER_SELECTION_SCHEMA, "target_id": record.target_id}
    _write_owner_only(path, canonical_encode(body) + b"\n")
    reset_selection_memo()


def clear_selection() -> bool:
    """Return to the everyday server; returns whether a selection was removed.

    A selection that cannot be read (damaged, foreign-mode, or a symlink, which the root
    resolution refuses) is removed too: this is the documented way back from it. Unlinking a
    symlink removes the link, never what it points to. Anything but a file or a link is refused.
    """

    path = selection_path()
    try:
        facts = path.lstat()
    except FileNotFoundError:
        reset_selection_memo()
        return False
    if not (stat.S_ISREG(facts.st_mode) or stat.S_ISLNK(facts.st_mode)):
        raise TargetError("selection_invalid")
    path.unlink()
    reset_selection_memo()
    return True


def selection_source() -> SelectionSource:
    """Which source decided this process's root: the variable, the pin, the selection, ambient."""

    return isolation_binding()


def active_target_is_remote() -> bool:
    """Whether the root this process uses is a remote target, for choosing a remedy's words.

    Never raises. A root that resolves but whose record cannot be read counts as remote, as in
    ``active_root_may_be_remote``: that record may name a server on another machine, and the
    connection paths refuse it there (``finishup.client.remote_binding.is_remote_active_root``),
    so the remedy never sends the owner to repair a local service that is not in use. A root
    that cannot be resolved at all answers False and keeps the remedy every local root gets.
    """

    try:
        record = active_target_record()
    except TargetRecordUnreadable:
        return True
    except TargetError:
        return False
    return record is not None and record.is_remote


def active_root_may_be_remote() -> bool:
    """Whether a connection from this process must claim its workspace instead of naming a path.

    True when the root's ``target.json`` names a remote kind, and also when the root resolves but
    its record cannot be read: that record may name a server on another machine, so a caller
    fails closed (it never sends a path there, and the connect seam then refuses on its own).
    False for the everyday installation, an isolated root that is not a target, a named local
    server, and a root that cannot be resolved at all, whose own path reports it exactly as
    before. Hook-safe: it reads only the target records.
    """

    try:
        record = active_target_record()
    except TargetRecordUnreadable:
        return True
    except TargetError:
        return False
    return record is not None and record.is_remote


def active_target_record() -> ServerTarget | None:
    """The target record of the root this process uses, or ``None`` for an ordinary local root.

    ``None`` covers the everyday server and an explicitly isolated root that is not a target.
    A path-safety refusal of the root is reported as ``target_root_unsafe``; a root that resolves
    but holds a record that cannot be read raises ``TargetRecordUnreadable``.
    """

    try:
        root = active_root()
    except PathSafetyError:
        raise TargetError("target_root_unsafe") from None
    if root is None:
        return None
    try:
        return read_target(root)
    except TargetError as error:
        raise TargetRecordUnreadable(error.reason, root.name) from None
