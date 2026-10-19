"""The projects one host configuration root serves through its shared FinishUP pieces (#1058).

Codex, Claude Code, and Cursor each keep some FinishUP pieces once per host configuration root
(a plugin, its marketplace binding or source, the user-level MCP registration) and others once
per project (skills, project MCP entries, tool admission). Several projects may connect to the
same root one after another; the shared pieces then serve all of them, and only the last
project's disconnect may remove them.

This module keeps the one structural record of which projects connected through FinishUP setup:
``<config root>/.yoetz-connected-projects.json`` (a frozen name, see ``CONNECTED_PROJECTS_FILE``),
canonical JSON
``{"projects": [<absolute project roots>]}`` plus ``"unknown_members": true`` when the shared
pieces were found without a record (an earlier release, or a lost record), so other projects may
use them that no record names. The file is owner-only (a group- or world-readable or writable
record is refused), replaced by an atomic rename with the parent directory synced, and written
only while the caller holds ``host_config_lock`` (Codex: or the home's activation lock) and its
bytes, re-read just before the rename, still equal the snapshot the approved plan was built from
(a compare-then-rename: it narrows, but does not close, the window for a writer holding neither
lock). A project root is the canonical path setup resolved. Two entries naming one
directory through different paths are never admitted: the caller refuses with
``project_connected_via_other_path``.

Each installation also keeps a *membership witness* beside its setup lock
(``<state dir>/host-config-locks/<key>.members``): every project it recorded for that root and
has not seen disconnect. A record that disappears (deleted by hand, or lost) therefore does not
make this installation forget who connected: those projects stay possible users (#1058 review).
The witness is maintained best effort after each record write and never names a project the
record did not name at some point.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import unicodedata
from collections.abc import Generator, Iterable
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal, cast

from finishup.config.paths import PathSafetyError, state_dir

__all__ = [
    "CONNECTED_PROJECTS_FILE",
    "ConnectedProjects",
    "HostProjectsError",
    "duplicate_of",
    "encode_projects",
    "host_config_lock",
    "lock_path_for",
    "live_projects",
    "load_connected_projects",
    "recorded_members",
    "same_directory",
    "witness_path_for",
    "write_connected_projects",
]

# Frozen legacy identifier (ADR-048): the record keeps this exact name whatever the MCP server
# key becomes, so an upgraded install still finds the members earlier builds recorded; a missing
# record would turn every known member into an unknown one (#1058).
CONNECTED_PROJECTS_FILE: Final = ".yoetz-connected-projects.json"
_MAX_BYTES: Final = 262_144
_MAX_PROJECTS: Final = 256
_MAX_PATH_CHARS: Final = 4_096
_LOCK_DIRECTORY: Final = "host-config-locks"
_WITNESS_SUFFIX: Final = ".members"

type HostProjectsReason = Literal[
    "registry_invalid", "registry_stale", "write_failed", "lock_unavailable"
]


class HostProjectsError(Exception):
    """Closed failure; never carries file contents or OS error text."""

    def __init__(self, reason: HostProjectsReason) -> None:
        super().__init__(reason)
        self.reason: HostProjectsReason = reason


@dataclass(frozen=True, slots=True)
class ConnectedProjects:
    """One read of the record: its exact bytes (``None`` when absent) and the parsed roots."""

    path: Path
    raw: bytes | None
    projects: tuple[str, ...]
    # Other projects may use the shared pieces without being named here (#1058 round 2).
    unknown_members: bool = False

    def with_project(self, project: Path) -> tuple[str, ...]:
        return tuple(sorted({*self.projects, str(project)}))

    def without_project(self, project: Path) -> tuple[str, ...]:
        return tuple(item for item in self.projects if item != str(project))


def _valid_root(value: object) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= _MAX_PATH_CHARS
        and Path(value).is_absolute()
        and not any(ord(char) < 32 or ord(char) == 127 for char in value)
    )


def encode_projects(projects: Iterable[str], *, unknown_members: bool = False) -> bytes:
    """The canonical record bytes for ``projects`` (sorted, unique)."""

    document: dict[str, object] = {"projects": sorted(set(projects))}
    if unknown_members:
        document["unknown_members"] = True
    return (
        json.dumps(document, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
        + b"\n"
    )


def _read_bounded(path: Path) -> bytes | None:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise HostProjectsError("registry_invalid") from exc
    try:
        facts = os.fstat(descriptor)
        if (
            not stat.S_ISREG(facts.st_mode)
            or facts.st_size > _MAX_BYTES
            or facts.st_mode & 0o077
            or (hasattr(os, "geteuid") and facts.st_uid != os.geteuid())
        ):
            raise HostProjectsError("registry_invalid")
        chunks: list[bytes] = []
        remaining = _MAX_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > _MAX_BYTES:
            raise HostProjectsError("registry_invalid")
        return raw
    finally:
        os.close(descriptor)


def _parse_record(raw: bytes) -> tuple[tuple[str, ...], bool]:
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise HostProjectsError("registry_invalid") from exc
    document = cast(dict[str, object], parsed) if isinstance(parsed, dict) else None
    if document is None or not (
        set(document) == {"projects"}
        or (
            set(document) == {"projects", "unknown_members"} and document["unknown_members"] is True
        )
    ):
        raise HostProjectsError("registry_invalid")
    items = document["projects"]
    if type(items) is not list or len(cast(list[object], items)) > _MAX_PROJECTS:
        raise HostProjectsError("registry_invalid")
    values = cast(list[object], items)
    if not all(_valid_root(item) for item in values):
        raise HostProjectsError("registry_invalid")
    projects = cast(list[str], values)
    if len(set(projects)) != len(projects):
        raise HostProjectsError("registry_invalid")
    return tuple(sorted(projects)), document.get("unknown_members") is True


def load_connected_projects(config_root: Path) -> ConnectedProjects:
    """Read the record under ``config_root``; an absent record names no projects."""

    path = config_root / CONNECTED_PROJECTS_FILE
    raw = _read_bounded(path)
    if raw is None:
        return ConnectedProjects(path, None, ())
    projects, unknown = _parse_record(raw)
    return ConnectedProjects(path, raw, projects, unknown)


def same_directory(left: Path, right: Path) -> bool:
    """True when both paths name one existing directory (symlink, case, or mount alias)."""

    try:
        return os.path.samefile(left, right)
    except OSError:
        return False


def duplicate_of(project: Path, candidates: Iterable[str]) -> str | None:
    """A recorded root spelled differently from ``project`` that is the same directory."""

    for candidate in sorted(set(candidates)):
        if candidate != str(project) and same_directory(Path(candidate), project):
            return candidate
    return None


def live_projects(projects: Iterable[str], *, excluding: Path) -> tuple[str, ...]:
    """Recorded roots, other than ``excluding``, that still exist as the directory recorded.

    A deleted or replaced-by-symlink project no longer holds the shared pieces open.
    """

    live: list[str] = []
    for candidate in sorted(set(projects)):
        if candidate == str(excluding):
            continue
        root = Path(candidate)
        try:
            if root.is_symlink() or not root.is_dir() or root.resolve() != root:
                continue
        except OSError:
            continue
        if same_directory(root, excluding):
            continue
        live.append(candidate)
    return tuple(live)


def _sync_directory(directory: Path) -> None:
    try:
        descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError as exc:
        raise HostProjectsError("write_failed") from exc
    try:
        os.fsync(descriptor)
    except OSError as exc:
        raise HostProjectsError("write_failed") from exc
    finally:
        os.close(descriptor)


def lock_path_for(config_root: Path) -> Path:
    """The private lock file for one host configuration root (#1058 round 3).

    It lives under this FinishUP installation's own state directory, which exists before any host
    hierarchy does, keyed by the resolved target path, so a first setup into a configuration
    root that does not exist yet can lock, and unrelated roots never share a lock. The key is
    the resolved path in Unicode NFC and case-folded: a case-insensitive or normalising
    filesystem (macOS) reaches one root through several spellings, and each must find the same
    lock. Two distinct roots that differ only in case then serialise against each other, which
    costs a wait, never a lost update.
    """

    target = os.path.realpath(os.path.abspath(os.path.expanduser(config_root)))
    key = unicodedata.normalize("NFC", target).casefold()
    digest = hashlib.sha256(key.encode("utf-8", "surrogateescape")).hexdigest()
    return state_dir() / _LOCK_DIRECTORY / f"{digest}.lock"


def witness_path_for(config_root: Path) -> Path:
    """This installation's membership witness for one configuration root (beside its lock)."""

    return lock_path_for(config_root).with_suffix(_WITNESS_SUFFIX)


def recorded_members(config_root: Path) -> tuple[str, ...]:
    """Projects this installation recorded for ``config_root`` and has not seen disconnect.

    Read from the witness, not the record, so a record deleted by hand or lost still leaves
    them known. An absent or unreadable witness names none (the witness is a safety net).
    """

    try:
        raw = _read_bounded(witness_path_for(config_root))
        return () if raw is None else _parse_record(raw)[0]
    except (HostProjectsError, OSError):
        return ()


def _update_witness(
    config_root: Path, after: tuple[str, ...], departed: set[str], *, shared_removed: bool
) -> None:
    """Apply one record change to the witness: who left goes, who is recorded is added.

    ``shared_removed`` (the shared pieces went: the last project left, or a home-wide
    disconnect) forgets every project. Best effort: a failure leaves the previous witness, never
    a partial one, and never fails the setup whose record write already succeeded.
    """

    try:
        path = witness_path_for(config_root)
        if shared_removed:
            path.unlink(missing_ok=True)
            return
        members = (set(recorded_members(config_root)) - departed) | set(after)
        ordered = tuple(sorted(item for item in members if _valid_root(item)))[:_MAX_PROJECTS]
        _private_lock_directory(path.parent)
        _replace_private_file(path, encode_projects(ordered))
    except (HostProjectsError, OSError, ValueError, PathSafetyError):
        return


def _replace_private_file(path: Path, payload: bytes) -> None:
    """Write ``payload`` to ``path`` through an fsynced 0600 temporary and an atomic rename."""

    try:
        descriptor, temporary_name = tempfile.mkstemp(prefix=f"{path.name}.", dir=path.parent)
    except OSError as exc:
        raise HostProjectsError("write_failed") from exc
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    except OSError as exc:
        temporary.unlink(missing_ok=True)
        raise HostProjectsError("write_failed") from exc
    _sync_directory(path.parent)


def _private_lock_directory(directory: Path) -> None:
    from finishup.config import paths

    try:
        paths.ensure_owner_only_dir(directory)
    except PathSafetyError:
        # A concurrent first setup may have created the directory between the existence check
        # and ``mkdir``; check what is there now rather than failing the loser of that race. A
        # directory that really is unsafe fails the same check again.
        paths.ensure_owner_only_dir(directory)


@contextmanager
def host_config_lock(config_root: Path) -> Generator[None]:
    """Serialize every setup apply for one host configuration root (#1058 round 3).

    An exclusive ``flock`` on a 0600 lock file opened for writing (``lock_path_for``), held
    across plan revalidation, the shared host changes, and the record update. A filesystem that
    cannot lock reports ``lock_unavailable`` before anything changes; there is no unlocked
    fallback. The lock serialises setups run by this installation only (another installation
    has its own state directory); against a setup from another installation, or any other
    writer, only the record's compare-then-rename remains, which narrows the window for
    overwriting a newer record but does not close it. Lock files are never removed: unlinking
    one while another setup waits on it would split the lock.
    """

    import fcntl

    path = lock_path_for(config_root)
    try:
        _private_lock_directory(path.parent)
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(path, flags, 0o600)
    except (OSError, PathSafetyError) as exc:
        raise HostProjectsError("lock_unavailable") from exc
    try:
        try:
            facts = os.fstat(descriptor)
            if not stat.S_ISREG(facts.st_mode) or (
                hasattr(os, "geteuid") and facts.st_uid != os.geteuid()
            ):
                raise HostProjectsError("lock_unavailable")
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
        except OSError as exc:
            raise HostProjectsError("lock_unavailable") from exc
        yield
    finally:
        os.close(descriptor)


def write_connected_projects(
    snapshot: ConnectedProjects,
    projects: Iterable[str],
    *,
    unknown_members: bool = False,
    departed: Iterable[str] = (),
    shared_removed: bool = False,
) -> None:
    """Replace the record with ``projects`` only if it still holds ``snapshot.raw``.

    An empty set without unknown members removes the record. The caller holds
    ``host_config_lock`` (or, for Codex, the home's activation lock). The record is re-read and
    compared with the bytes the approved plan read immediately before an atomic rename, which
    refuses a record changed since the plan; it narrows, but cannot close, the window in which
    a writer that holds neither lock (another installation) changes it between the compare and
    the rename.

    ``departed`` names the projects this change disconnects (also when a lost record no longer
    lists them) and ``shared_removed`` says the shared pieces went; both keep the membership
    witness in step.
    """

    ordered = tuple(sorted(set(projects)))
    if not all(_valid_root(item) for item in ordered) or len(ordered) > _MAX_PROJECTS:
        raise HostProjectsError("registry_invalid")
    path = snapshot.path
    if _read_bounded(path) != snapshot.raw:
        raise HostProjectsError("registry_stale")
    if not ordered and not unknown_members:
        if snapshot.raw is not None:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise HostProjectsError("write_failed") from exc
            _sync_directory(path.parent)
    else:
        payload = encode_projects(ordered, unknown_members=unknown_members)
        if payload != snapshot.raw:
            _replace_private_file(path, payload)
    left = {*departed, *(set(snapshot.projects) - set(ordered))}
    _update_witness(path.parent, ordered, left, shared_removed=shared_removed)
