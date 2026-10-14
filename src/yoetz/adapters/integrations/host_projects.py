"""The projects one host configuration root serves through its shared Yoetz pieces (#1058).

Codex, Claude Code, and Cursor each keep some Yoetz pieces once per host configuration root
(a plugin, its marketplace binding or source, the user-level MCP registration) and others once
per project (skills, project MCP entries, tool admission). Several projects may connect to the
same root one after another; the shared pieces then serve all of them, and only the last
project's disconnect may remove them.

This module keeps the one structural record of which projects connected through Yoetz setup:
``<config root>/.<server name>-connected-projects.json``, canonical JSON
``{"projects": [<absolute project roots>]}``, owner-only, written atomically under the caller's
lock and only when its bytes still equal the snapshot the approved plan was built from. A project
root is the canonical path setup resolved. Two entries naming one directory through different
paths are never admitted: the caller refuses with ``project_connected_via_other_path``.
"""

from __future__ import annotations

import json
import os
import stat
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal, cast

from yoetz.ports.harness_mcp import MCP_SERVER_NAME

__all__ = [
    "CONNECTED_PROJECTS_FILE",
    "ConnectedProjects",
    "HostProjectsError",
    "duplicate_of",
    "encode_projects",
    "live_projects",
    "load_connected_projects",
    "same_directory",
    "write_connected_projects",
]

CONNECTED_PROJECTS_FILE: Final = f".{MCP_SERVER_NAME}-connected-projects.json"
_MAX_BYTES: Final = 262_144
_MAX_PROJECTS: Final = 256
_MAX_PATH_CHARS: Final = 4_096

type HostProjectsReason = Literal["registry_invalid", "registry_stale", "write_failed"]


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


def encode_projects(projects: Iterable[str]) -> bytes:
    """The canonical record bytes for ``projects`` (sorted, unique)."""

    ordered = sorted(set(projects))
    return (
        json.dumps({"projects": ordered}, ensure_ascii=False, separators=(",", ":")).encode()
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
            or facts.st_mode & 0o022
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
    if not isinstance(parsed, dict) or set(cast(dict[str, object], parsed)) != {"projects"}:
        raise HostProjectsError("registry_invalid")
    items = cast(dict[str, object], parsed)["projects"]
    if type(items) is not list or len(cast(list[object], items)) > _MAX_PROJECTS:
        raise HostProjectsError("registry_invalid")
    values = cast(list[object], items)
    if not all(_valid_root(item) for item in values):
        raise HostProjectsError("registry_invalid")
    projects = cast(list[str], values)
    if len(set(projects)) != len(projects):
        raise HostProjectsError("registry_invalid")
    return ConnectedProjects(path, raw, tuple(sorted(projects)))


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


def write_connected_projects(snapshot: ConnectedProjects, projects: Iterable[str]) -> None:
    """Replace the record with ``projects`` only if it still holds ``snapshot.raw``.

    An empty set removes the record. The caller holds its host's activation lock; this
    compare-and-swap additionally refuses a record changed since the approved plan read it.
    """

    ordered = tuple(sorted(set(projects)))
    if not all(_valid_root(item) for item in ordered) or len(ordered) > _MAX_PROJECTS:
        raise HostProjectsError("registry_invalid")
    path = snapshot.path
    if _read_bounded(path) != snapshot.raw:
        raise HostProjectsError("registry_stale")
    if not ordered:
        if snapshot.raw is not None:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise HostProjectsError("write_failed") from exc
        return
    payload = encode_projects(ordered)
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
