"""The projects one host configuration root serves through its shared Yoetz pieces (#1058).

Codex, Claude Code, and Cursor each keep some Yoetz pieces once per host configuration root
(a plugin, its marketplace binding or source, the user-level MCP registration) and others once
per project (skills, project MCP entries, tool admission). Several projects may connect to the
same root one after another; the shared pieces then serve all of them, and only the last
project's disconnect may remove them.

This module keeps the one structural record of which projects connected through Yoetz setup:
``<config root>/.<server name>-connected-projects.json``, canonical JSON
``{"projects": [<absolute project roots>]}`` plus ``"unknown_members": true`` when the shared
pieces were found without a record (an earlier release, or a lost record), so other projects may
use them that no record names. The file is owner-only (a group- or world-readable or writable
record is refused), replaced atomically with the parent directory synced, and written only while
the caller holds ``host_config_lock`` and its bytes still equal the snapshot the approved plan
was built from. A project root is the canonical path setup resolved. Two entries naming one
directory through different paths are never admitted: the caller refuses with
``project_connected_via_other_path``.
"""

from __future__ import annotations

import json
import os
import stat
import tempfile
from collections.abc import Generator, Iterable
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal, cast

from yoetz.config.paths import state_dir
from yoetz.ports.harness_mcp import MCP_SERVER_NAME

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
    "same_directory",
    "write_connected_projects",
]

CONNECTED_PROJECTS_FILE: Final = f".{MCP_SERVER_NAME}-connected-projects.json"
_MAX_BYTES: Final = 262_144
_MAX_PROJECTS: Final = 256
_MAX_PATH_CHARS: Final = 4_096
_LOCK_DIRECTORY: Final = "host-config-locks"

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


def load_connected_projects(config_root: Path) -> ConnectedProjects:
    """Read the record under ``config_root``; an absent record names no projects."""

    path = config_root / CONNECTED_PROJECTS_FILE
    raw = _read_bounded(path)
    if raw is None:
        return ConnectedProjects(path, None, ())
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
    return ConnectedProjects(
        path, raw, tuple(sorted(projects)), document.get("unknown_members") is True
    )


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

    It lives under this Yoetz installation's own state directory, which exists before any host
    hierarchy does, keyed by the resolved target path, so a first setup into a configuration
    root that does not exist yet can lock, and unrelated roots never share a lock.
    """

    import hashlib

    target = os.path.realpath(os.path.abspath(os.path.expanduser(config_root)))
    digest = hashlib.sha256(target.encode("utf-8", "surrogateescape")).hexdigest()
    return state_dir() / _LOCK_DIRECTORY / f"{digest}.lock"


@contextmanager
def host_config_lock(config_root: Path) -> Generator[None]:
    """Serialize every setup apply for one host configuration root (#1058 round 3).

    An exclusive ``flock`` on a 0600 lock file opened for writing (``lock_path_for``), held
    across plan revalidation, the shared host changes, and the record update. A filesystem that
    cannot lock reports ``lock_unavailable`` before anything changes; there is no unlocked
    fallback.
    """

    import fcntl

    from yoetz.config.paths import PathSafetyError, ensure_owner_only_dir

    path = lock_path_for(config_root)
    try:
        ensure_owner_only_dir(path.parent)
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
    snapshot: ConnectedProjects, projects: Iterable[str], *, unknown_members: bool = False
) -> None:
    """Replace the record with ``projects`` only if it still holds ``snapshot.raw``.

    An empty set without unknown members removes the record. The caller holds
    ``host_config_lock``; this compare-and-swap additionally refuses a record changed since the
    approved plan read it.
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
        return
    payload = encode_projects(ordered, unknown_members=unknown_members)
    if payload == snapshot.raw:
        return
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
