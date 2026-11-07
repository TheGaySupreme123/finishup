"""What this computer's everyday FinishUP last reported about network use (ADR-051 decision 8).

Maintainer decision of 2026-11-07 ("remember"). This computer's zero-network state is its
everyday installation's effective machine-scope privacy policy, read from its running service.
While a FinishUP server on another machine, a port or the web is selected, that service is
usually stopped or locked, so the live answer cannot be had. Whenever the service does report the
policy to a client command on this computer (the zero-network check, ``privacy show``, and every
privacy change made here), the client records a small marker: whether the policy was zero-network,
and when. Surfaces read the live policy first and fall back to the marker, worded as "this
computer last reported"; the connection check reads only the marker, so no hook pays for a
service round trip.

The marker is ``<ambient state dir>/servers/everyday-policy.json`` (``SCHEMA``), an owner-only
regular file beside the server registry, outside the vault: client state of this computer's
everyday installation, independent of the selected server. It holds no path, name or policy
content, only ``zero_network`` (a boolean) and ``reported_at`` (an RFC 3339 UTC time in
milliseconds).

* Only the everyday installation keeps it. A process whose root an isolation variable or runtime
  pin decides reads and changes its own root's policy, so it neither records nor reads the
  marker.
* A marker that cannot be read (damaged, not owner-only, a link, too large) counts as no record:
  no surface claims the zero-network state from it and no connection is refused on it, and the
  next report replaces it. Nothing here ever raises: a marker that cannot be written leaves the
  previous one, or none.
* The way out: deleting FinishUP's per-user folders (uninstalling) removes it with the state
  folder, and the zero-network check removes it once the everyday installation no longer exists
  (its vault was never set up, or was removed).

This module imports only the standard library and lean SHARED modules, so a hook may import it.
"""

from __future__ import annotations

import os
import re
import secrets
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Literal

from finishup.config.installation import format_rfc3339_ms
from finishup.config.paths import (
    SERVERS_DIR_NAME,
    PathSafetyError,
    ambient_registry_dirs,
    ensure_owner_only_dir,
)
from finishup.protocol.canonical import JsonValue, canonical_encode, strict_json_parse

__all__ = [
    "MARKER_NAME",
    "SCHEMA",
    "ReportedPolicy",
    "last_reported_zero_network",
    "marker_path",
    "read_marker",
    "record_reported_policy",
    "remove_marker",
]

SCHEMA: Final = "yoetz.everyday-network-policy/1"
MARKER_NAME: Final = "everyday-policy.json"
_MAX_BYTES: Final = 512
_FIELDS: Final = frozenset({"schema", "zero_network", "reported_at"})
_TIMESTAMP: Final = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$"
)

type MarkerReading = ReportedPolicy | Literal["absent", "unreadable"]


@dataclass(frozen=True, slots=True)
class ReportedPolicy:
    """What this computer's everyday FinishUP last reported: zero-network or not, and when."""

    zero_network: bool
    reported_at: str


def _ambient_marker_path() -> Path:
    _config, state = ambient_registry_dirs()
    return state / SERVERS_DIR_NAME / MARKER_NAME


# Where the marker lives; the test suite points it at a private folder of its own.
_location = _ambient_marker_path


def marker_path() -> Path:
    """``<ambient state dir>/servers/everyday-policy.json``."""

    return _location()


def _everyday_scope() -> bool:
    """Whether this process's FinishUP is the everyday one (no isolation variable or pin).

    A variable or pin that cannot be used still decides: it fails closed on its own path, and the
    marker is left alone.
    """

    from finishup.config.paths import isolated_root_variable, read_runtime_pin

    try:
        return isolated_root_variable() is None and read_runtime_pin() is None
    except PathSafetyError:
        return False


def record_reported_policy(*, zero_network: bool, now: datetime | None = None) -> bool:
    """Record what this computer's everyday FinishUP just reported; whether it was written.

    Call it only with the everyday installation's own effective machine-scope policy, as its
    service answered a client command. Atomic (an owner-only temporary file, flushed, renamed
    over the marker, so a damaged file or a link in its place is replaced, never followed).
    Never raises.
    """

    if type(zero_network) is not bool or not _everyday_scope():
        return False
    stamp = format_rfc3339_ms((now or datetime.now(UTC)).astimezone(UTC))
    body: dict[str, JsonValue] = {
        "schema": SCHEMA,
        "reported_at": stamp,
        "zero_network": zero_network,
    }
    try:
        path = marker_path()
        ensure_owner_only_dir(path.parent)
        _write_owner_only(path, canonical_encode(body) + b"\n")
    except (OSError, PathSafetyError, ValueError):
        return False
    return True


def _write_owner_only(path: Path, encoded: bytes) -> None:
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


def read_marker() -> MarkerReading:
    """The marker: what was last reported, ``absent``, or ``unreadable``. Never raises.

    ``absent`` too in a process whose root an isolation variable or runtime pin decides.
    """

    if not _everyday_scope():
        return "absent"
    try:
        path = marker_path()
        facts = path.lstat()
    except FileNotFoundError:
        return "absent"
    except (OSError, PathSafetyError):
        return "unreadable"
    if (
        not stat.S_ISREG(facts.st_mode)
        or facts.st_uid != os.geteuid()
        or stat.S_IMODE(facts.st_mode) & 0o077
        or facts.st_size > _MAX_BYTES
    ):
        return "unreadable"
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            encoded = os.read(descriptor, _MAX_BYTES + 1)
        finally:
            os.close(descriptor)
        parsed = strict_json_parse(encoded)
    except (OSError, ValueError):
        return "unreadable"
    if not isinstance(parsed, dict):
        return "unreadable"
    fields = parsed
    zero_network = fields.get("zero_network")
    reported_at = fields.get("reported_at")
    if (
        frozenset(fields) != _FIELDS
        or fields.get("schema") != SCHEMA
        or type(zero_network) is not bool
        or type(reported_at) is not str
        or not _TIMESTAMP.match(reported_at)
    ):
        return "unreadable"
    return ReportedPolicy(zero_network, reported_at)


def last_reported_zero_network() -> ReportedPolicy | None:
    """The marker when it says this computer last reported zero-network; ``None`` otherwise.

    The connection check (``targets.require_current_authorization``) reads this: a file read
    only, never a service round trip. An absent or unreadable marker is ``None``.
    """

    reading = read_marker()
    if isinstance(reading, ReportedPolicy) and reading.zero_network:
        return reading
    return None


def remove_marker() -> bool:
    """Delete the marker; whether one was removed. A link is removed, never what it names.

    Anything but a file or a link is left in place. Never raises.
    """

    try:
        path = marker_path()
        facts = path.lstat()
    except (OSError, PathSafetyError):
        return False
    if not (stat.S_ISREG(facts.st_mode) or stat.S_ISLNK(facts.st_mode)):
        return False
    try:
        path.unlink()
    except OSError:
        return False
    return True
