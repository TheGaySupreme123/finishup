"""The connector's owner-only records in a remote target root, and how clients start or stop it.

A remote target root (ADR-051, approach A) has no service of its own. Its ``run/control.sock`` is
served by one vault-less ``finishup connector`` process that relays each connection to the server.
Two owner-only records in ``<target root>/state`` describe that process to every client:

* ``connector.lock`` — the singleton flock, stamped with the holder's pid, package version and
  schema-manifest digest. A client stops or supersedes a connector only by this stamped pid,
  never by matching a process name or path.
* ``connector-status.json`` (``yoetz.connector-status/1``) — ``generation``, ``phase``,
  ``reason``, ``correlation_id``, ``pid`` and ``started_at``. Every field is a closed token, an
  integer, a minted id or a timestamp; no host, name, path or remote text is ever written. The
  generation increases on every change of phase or reason, so a client that latched an outage
  (the MCP bridge) sees the repair.

This module is light (standard library, path and target helpers, and the control error type),
so ``finishup.service.client`` can read the status on a failed connection without loading the
connector's transports.
"""

from __future__ import annotations

import contextlib
import errno
import fcntl
import os
import secrets
import signal
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Literal, cast

from finishup.config.installation import format_rfc3339_ms, parse_rfc3339_ms
from finishup.protocol.canonical import JsonValue, canonical_encode, strict_json_parse

__all__ = [
    "CONNECTOR_IDLE_SECONDS",
    "CONNECTOR_LOCK_NAME",
    "CONNECTOR_PHASES",
    "CONNECTOR_REASONS",
    "CONNECTOR_STATUS_NAME",
    "CONNECTOR_STATUS_SCHEMA",
    "ConnectorLock",
    "ConnectorLockBusy",
    "ConnectorPhase",
    "ConnectorStamp",
    "ConnectorStatus",
    "connector_environment",
    "connector_holder",
    "new_status",
    "now_stamp",
    "read_connector_status",
    "spawn_connector",
    "stop_connector",
    "write_connector_status",
]

CONNECTOR_STATUS_SCHEMA: Final = "yoetz.connector-status/1"
CONNECTOR_STATUS_NAME: Final = "connector-status.json"
CONNECTOR_LOCK_NAME: Final = "connector.lock"
# A connector with no local connection for this long exits; the next client starts a new one.
CONNECTOR_IDLE_SECONDS: Final = 900.0
CONNECTOR_PHASES: Final = frozenset({"starting", "ready", "unavailable", "stopped"})
# ``unavailable`` names one of the remote connection phases (``protocol.errors``); ``stopped``
# names why the process ended. ``zero_network_remote_selected`` is both: the connector refuses
# to relay while this computer last reported a zero-network policy, then stops for it (ADR-051
# decision 8).
_UNAVAILABLE_REASONS: Final = frozenset(
    {
        "remote_auth_failed",
        "remote_identity_changed",
        "remote_incompatible",
        "remote_service_not_running",
        "remote_unreachable",
        "zero_network_remote_selected",
    }
)
_STOPPED_REASONS: Final = frozenset(
    {"idle_timeout", "stop_requested", "connector_failed", "zero_network_remote_selected"}
)
CONNECTOR_REASONS: Final = _UNAVAILABLE_REASONS | _STOPPED_REASONS

type ConnectorPhase = Literal["starting", "ready", "unavailable", "stopped"]

_MAX_RECORD_BYTES: Final = 2_048
_CORRELATION: Final = "err_"
_STOP_POLL_SECONDS: Final = 0.05
# The connector's scrubbed environment: what OpenSSH and the interpreter need, nothing secret.
# ``SSH_AUTH_SOCK`` lets an SSH target use the owner's agent; the key itself stays in OpenSSH.
# ``DBUS_SESSION_BUS_ADDRESS`` (a bus address, not a secret) lets an HTTPS target read the key
# ``server login`` stored in the desktop's Secret Service: the Linux keyring backend finds the
# session bus only through it. The XDG base directories decide where this machine's server
# registry lives, so the connector resolves the same target root its client did.
_ENVIRONMENT_NAMES: Final = (
    "DBUS_SESSION_BUS_ADDRESS",
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LOGNAME",
    "PATH",
    "SSH_AUTH_SOCK",
    "TMPDIR",
    "USER",
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_RUNTIME_DIR",
    "XDG_STATE_HOME",
)


@dataclass(frozen=True, slots=True)
class ConnectorStatus:
    """One validated ``yoetz.connector-status/1`` record."""

    generation: int
    phase: ConnectorPhase
    reason: str | None
    correlation_id: str | None
    pid: int
    started_at: str

    def __post_init__(self) -> None:
        if type(self.generation) is not int or self.generation < 1:
            raise ValueError("connector_status_invalid")
        if self.phase not in CONNECTOR_PHASES:
            raise ValueError("connector_status_invalid")
        allowed = {
            "starting": frozenset[str](),
            "ready": frozenset[str](),
            "unavailable": _UNAVAILABLE_REASONS,
            "stopped": _STOPPED_REASONS,
        }[self.phase]
        if (self.reason is None) is bool(allowed) or (
            self.reason is not None and self.reason not in allowed
        ):
            raise ValueError("connector_status_invalid")
        if self.correlation_id is not None and (
            type(self.correlation_id) is not str
            or not self.correlation_id.startswith(_CORRELATION)
            or not 4 < len(self.correlation_id) <= 64
            or not self.correlation_id.isascii()
        ):
            raise ValueError("connector_status_invalid")
        if type(self.pid) is not int or not 1 <= self.pid < 2**31:
            raise ValueError("connector_status_invalid")
        parse_rfc3339_ms(self.started_at)

    def body(self) -> dict[str, JsonValue]:
        return {
            "schema": CONNECTOR_STATUS_SCHEMA,
            "generation": self.generation,
            "phase": self.phase,
            "reason": self.reason,
            "correlation_id": self.correlation_id,
            "pid": self.pid,
            "started_at": self.started_at,
        }

    def encode(self) -> bytes:
        return canonical_encode(cast(JsonValue, self.body())) + b"\n"


def _status_path(root: Path) -> Path:
    return root / "state" / CONNECTOR_STATUS_NAME


def _lock_path(root: Path) -> Path:
    return root / "state" / CONNECTOR_LOCK_NAME


def _read_owner_only(path: Path) -> bytes | None:
    """A regular, owner-owned, owner-only file's bytes; ``None`` when absent or unsafe."""

    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        facts = os.fstat(descriptor)
        if (
            not stat.S_ISREG(facts.st_mode)
            or facts.st_uid != os.geteuid()
            or stat.S_IMODE(facts.st_mode) & 0o077
            or facts.st_size > _MAX_RECORD_BYTES
        ):
            return None
        data = os.read(descriptor, _MAX_RECORD_BYTES + 1)
    except OSError:
        return None
    finally:
        os.close(descriptor)
    return data if len(data) <= _MAX_RECORD_BYTES else None


def read_connector_status(root: Path) -> ConnectorStatus | None:
    """The status in ``root``; ``None`` when absent, unsafe or malformed (never a guess)."""

    data = _read_owner_only(_status_path(root))
    if data is None or not data.endswith(b"\n"):
        return None
    try:
        parsed = strict_json_parse(data[:-1])
        if type(parsed) is not dict:
            return None
        source = cast(dict[str, JsonValue], parsed)
        if (
            set(source)
            != {
                "schema",
                "generation",
                "phase",
                "reason",
                "correlation_id",
                "pid",
                "started_at",
            }
            or source["schema"] != CONNECTOR_STATUS_SCHEMA
        ):
            return None
        status = ConnectorStatus(
            cast(int, source["generation"]),
            cast(ConnectorPhase, source["phase"]),
            cast(str | None, source["reason"]),
            cast(str | None, source["correlation_id"]),
            cast(int, source["pid"]),
            cast(str, source["started_at"]),
        )
    except (TypeError, ValueError):
        return None
    return status if status.encode() == data else None


def write_connector_status(root: Path, status: ConnectorStatus) -> None:
    """Atomically replace the status (owner-only temp file, fsync, rename)."""

    path = _status_path(root)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
    descriptor = os.open(
        temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600
    )
    try:
        try:
            view = memoryview(status.encode())
            while view:
                view = view[os.write(descriptor, view) :]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


@dataclass(frozen=True, slots=True)
class ConnectorStamp:
    """The advisory identity a live connector stamped into its lock file."""

    pid: int
    version: str
    schema_manifest_digest: str


class ConnectorLockBusy(Exception):
    """Another live connector holds this root's singleton lock."""


class ConnectorLock:
    """The connector singleton: an exclusive flock on ``state/connector.lock``, stamped."""

    __slots__ = ("_descriptor", "_path")

    def __init__(self, root: Path) -> None:
        self._path = _lock_path(root)
        self._descriptor: int | None = None

    def acquire(self, *, version: str, schema_manifest_digest: str) -> None:
        descriptor = os.open(
            self._path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600
        )
        try:
            facts = os.fstat(descriptor)
            if (
                not stat.S_ISREG(facts.st_mode)
                or facts.st_uid != os.geteuid()
                or stat.S_IMODE(facts.st_mode) & 0o077
            ):
                raise ConnectorLockBusy
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                if exc.errno in {errno.EWOULDBLOCK, errno.EAGAIN}:
                    raise ConnectorLockBusy from None
                raise
            stamp: dict[str, JsonValue] = {
                "pid": os.getpid(),
                "version": version,
                "schema_manifest_digest": schema_manifest_digest,
            }
            os.ftruncate(descriptor, 0)
            os.lseek(descriptor, 0, os.SEEK_SET)
            os.write(descriptor, canonical_encode(stamp) + b"\n")
        except BaseException:
            os.close(descriptor)
            raise
        self._descriptor = descriptor

    def assert_held(self) -> None:
        """For ``unix_socket.remove_stale_endpoint``: only the holder clears a stale endpoint."""

        if self._descriptor is None:
            raise RuntimeError("connector_lock_not_held")

    def release(self) -> None:
        descriptor = self._descriptor
        self._descriptor = None
        if descriptor is None:
            return
        try:
            with contextlib.suppress(OSError):
                os.ftruncate(descriptor, 0)
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _lock_held(path: Path) -> bool | None:
    """Whether some process holds the exclusive flock (``None``: cannot be inspected)."""

    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return False
    except OSError:
        return None
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except OSError as exc:
            return True if exc.errno in {errno.EWOULDBLOCK, errno.EAGAIN} else None
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        return False
    finally:
        os.close(descriptor)


def connector_holder(root: Path) -> ConnectorStamp | None:
    """The stamp of the live connector holding ``root``'s lock, or ``None``.

    The stamp alone is advisory: it is returned only while the flock is held and the stamped pid
    is alive.
    """

    path = _lock_path(root)
    data = _read_owner_only(path)
    if data is None or _lock_held(path) is not True:
        return None
    try:
        parsed = strict_json_parse(data.rstrip(b"\n"))
    except ValueError:
        return None
    if type(parsed) is not dict:
        return None
    stamp = cast(dict[str, JsonValue], parsed)
    pid = stamp.get("pid")
    version = stamp.get("version")
    digest = stamp.get("schema_manifest_digest")
    if (
        type(pid) is not int
        or not 1 <= pid < 2**31
        or type(version) is not str
        or not 0 < len(version) <= 128
        or type(digest) is not str
        or len(digest) != 71
    ):
        return None
    try:
        os.kill(pid, 0)
    except OSError:
        return None
    return ConnectorStamp(pid, version, digest)


def connector_environment(root: Path) -> dict[str, str]:
    """The scrubbed environment a connector runs with: no product variable, no secret.

    The target root travels as ``--root``; no isolation variable is set, so the connector's own
    children (OpenSSH) inherit nothing that could point a FinishUP process at another root.
    """

    del root
    return {name: os.environ[name] for name in _ENVIRONMENT_NAMES if name in os.environ}


def spawn_connector(root: Path) -> subprocess.Popen[bytes]:
    """Start one detached connector for ``root``; its stderr goes to ``log/connector.stderr``."""

    log = root / "log"
    log.mkdir(mode=0o700, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open(log / "connector.stderr", flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        return subprocess.Popen(  # noqa: S603 - fixed interpreter, module and arguments
            (sys.executable, "-m", "finishup", "connector", "run", "--root", str(root)),
            close_fds=True,
            env=connector_environment(root),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=descriptor,
            start_new_session=True,
        )
    finally:
        os.close(descriptor)


def stop_connector(root: Path, *, timeout_seconds: float = 5.0) -> bool:
    """Ask ``root``'s stamped connector to stop and wait for its lock; ``True`` once free.

    Only the pid stamped in the held lock is signalled (AGENTS.md: never by pattern). Returns
    ``True`` when no connector runs or it released the lock in time, ``False`` otherwise.
    """

    holder = connector_holder(root)
    if holder is None:
        return True
    try:
        os.kill(holder.pid, signal.SIGTERM)
    except ProcessLookupError:
        return True
    except OSError:
        return False
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if _lock_held(_lock_path(root)) is False:
            return True
        time.sleep(_STOP_POLL_SECONDS)
    return _lock_held(_lock_path(root)) is False


def new_status(
    previous: ConnectorStatus | None,
    phase: ConnectorPhase,
    reason: str | None,
    *,
    correlation_id: str | None = None,
    started_at: str,
) -> ConnectorStatus:
    """The next status: the generation moves only when the phase or the reason changes."""

    generation = 1 if previous is None else previous.generation
    if previous is not None and (previous.phase, previous.reason) != (phase, reason):
        generation += 1
    if previous is not None and previous.pid != os.getpid():
        # A new connector process continues the root's sequence, so a latch keyed on it moves.
        generation = previous.generation + 1
    return ConnectorStatus(generation, phase, reason, correlation_id, os.getpid(), started_at)


def now_stamp() -> str:
    return format_rfc3339_ms(datetime.now(UTC))
