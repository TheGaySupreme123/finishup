"""Service-owned check-time change capture boundary (ADR-031).

When a check's AI-powered review selects diff excerpts, the service reads one bounded, read-only
view of the task's repository: the change from the commit recorded when the task started to the
working tree, plus untracked files Git does not ignore. The read uses only the repository root
that the check's own authenticated control connection supplied and that resolved to the task's
repository commitment. It never runs a shell, a hook, an external diff or a network transport.

The resulting text is one object. The service redacts it, stores it encrypted for the check's
durable AI-powered review job, and hands it to the pure case builder, which reserves packet room
for it. Nothing here widens a disclosure: the review recipe, never-send scanning and the privacy
gateway apply to it exactly as to every other case item.
"""

from __future__ import annotations

import re
from collections.abc import Generator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, Literal, Protocol, cast

from yoetz.domain.values import validate_commitment
from yoetz.ports.objects import ObjectRef
from yoetz.protocol.canonical import JsonValue, canonical_encode, strict_json_parse

__all__ = [
    "CHANGE_CAPTURE_UNAVAILABLE_REASONS",
    "CHECK_CHANGE_MEDIA_TYPE",
    "MAX_CHECK_CHANGE_TEXT_BYTES",
    "TASK_CHANGE_BASE_MEDIA_TYPE",
    "ChangeBaseKind",
    "ChangeCapturePort",
    "ChangeCaptureUnavailable",
    "CheckChangeCapture",
    "CheckChangeMetadata",
    "ChangeMetadataEntry",
    "CheckWorkspaceSource",
    "TaskChangeBase",
    "TaskChangeBaseStorePort",
    "check_workspace_source_scope",
    "current_check_workspace_source",
    "decode_check_change",
    "decode_task_change_base",
    "encode_check_change",
    "encode_task_change_base",
    "RequestedPathProbe",
]

TASK_CHANGE_BASE_MEDIA_TYPE: Final = "application/vnd.yoetz.task-change-base+json"
CHECK_CHANGE_MEDIA_TYPE: Final = "application/vnd.yoetz.check-change+json"
_TASK_CHANGE_BASE_SCHEMA: Final = "yoetz.task-change-base/1"
_CHECK_CHANGE_SCHEMA: Final = "yoetz.check-change/1"
# The stored capture is bounded well above what one review packet can carry, so the header's file
# list and a useful prefix of the diff survive, and far below the object-store plaintext bound.
MAX_CHECK_CHANGE_TEXT_BYTES: Final = 262_144
_MAX_FILE_COUNT: Final = 1_000_000
_HEX: Final = re.compile(r"^[0-9a-f]+$", re.ASCII)

# ``first_check``: the task recorded no start commit (created before ADR-031, or recording
# failed), so its first check pinned HEAD as the task's base for every later check.
type ChangeBaseKind = Literal["task_start", "first_check", "head", "empty"]
type TaskChangeBaseOrigin = Literal["task_start", "first_check"]
_BASE_KINDS: Final = frozenset({"task_start", "first_check", "head", "empty"})

# Closed diagnostic vocabulary. A capture that cannot run reports one of these tokens and never an
# exception message, path, or Git output.
CHANGE_CAPTURE_UNAVAILABLE_REASONS: Final = frozenset(
    {
        "git_unavailable",
        "not_git",
        "unsafe_root",
        "unsupported_repository",
        "git_failed",
        # The working tree kept moving while it was read: no coherent state could be captured.
        "changed_during_capture",
        "redaction_incomplete",
    }
)


class ChangeCaptureUnavailable(Exception):
    """The repository could not be read within the capture's safety and size bounds."""

    __slots__ = ("reason",)

    reason: str

    def __init__(self, reason: str) -> None:
        if reason not in CHANGE_CAPTURE_UNAVAILABLE_REASONS:
            raise ValueError("change_capture_reason_invalid")
        self.reason = reason
        super().__init__(reason)


def _invalid() -> ValueError:
    return ValueError("change_capture_value_invalid")


@dataclass(frozen=True, slots=True)
class TaskChangeBase:
    """The commit a task's check-time change starts from, fixed for the life of the task.

    ``task_start`` bases are HEAD when the task was created. A task without one gets a
    ``first_check`` base: HEAD when its first check ran, pinned so every later check of the task
    diffs from the same commit and commits made in between stay in the change.
    """

    object_format: Literal["sha1", "sha256"]
    commit: str = field(repr=False)
    origin: TaskChangeBaseOrigin = "task_start"

    def __post_init__(self) -> None:
        if self.object_format not in {"sha1", "sha256"}:
            raise _invalid()
        if self.origin not in {"task_start", "first_check"}:
            raise _invalid()
        length = 40 if self.object_format == "sha1" else 64
        if (
            type(self.commit) is not str
            or len(self.commit) != length
            or _HEX.fullmatch(self.commit) is None
        ):
            raise _invalid()


@dataclass(frozen=True, slots=True)
class CheckChangeCapture:
    """One bounded, rendered check-time change: a plain-text header followed by a unified diff.

    ``truncated`` is set whenever a changed file or any of its bytes is missing from ``text``; the
    header names each file that is not shown. ``redacted`` is set by the service after it replaced
    credential-like spans, never by the adapter. ``base_commit`` is the object id the change was
    taken against (the task-start commit, HEAD, or the empty tree); it keys the per-file
    commitments a completed review records, and is empty only for an object written before it
    existed.
    """

    base: ChangeBaseKind
    text: bytes = field(repr=False)
    tracked_files: int
    untracked_files: int
    omitted_files: int
    truncated: bool
    redacted: bool = False
    base_commit: str = field(default="", repr=False)

    def __post_init__(self) -> None:
        if self.base not in _BASE_KINDS:
            raise _invalid()
        if type(self.text) is not bytes or not 1 <= len(self.text) <= MAX_CHECK_CHANGE_TEXT_BYTES:
            raise _invalid()
        try:
            self.text.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise _invalid() from exc
        for count in (self.tracked_files, self.untracked_files, self.omitted_files):
            if type(count) is not int or not 0 <= count <= _MAX_FILE_COUNT:
                raise _invalid()
        if self.omitted_files > self.tracked_files + self.untracked_files:
            raise _invalid()
        if type(self.truncated) is not bool or type(self.redacted) is not bool:
            raise _invalid()
        if self.omitted_files and not self.truncated:
            raise _invalid()
        if type(self.base_commit) is not str or (
            self.base_commit
            and (len(self.base_commit) not in {40, 64} or _HEX.fullmatch(self.base_commit) is None)
        ):
            raise _invalid()


@dataclass(frozen=True, slots=True)
class ChangeMetadataEntry:
    """One changed path used only for local structural accounting.

    The metadata path deliberately carries no bytes or line counts.  Its path is reduced in
    process and never becomes a provider input or a durable check object.
    """

    status: str
    path: str = field(repr=False)
    untracked: bool = False
    original_path: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.status) is not str
            or not self.status
            or len(self.status) > 2
            or any(ord(char) < 0x20 or ord(char) > 0x7E for char in self.status)
        ):
            raise _invalid()
        if (
            type(self.path) is not str
            or not self.path
            or any(char in self.path for char in "\x00\r\n")
        ):
            raise _invalid()
        if type(self.untracked) is not bool:
            raise _invalid()
        if self.original_path is not None and (
            type(self.original_path) is not str
            or not self.original_path
            or any(char in self.original_path for char in "\x00\r\n")
        ):
            raise _invalid()
        if self.original_path is not None and self.status != "R":
            raise _invalid()


@dataclass(frozen=True, slots=True)
class CheckChangeMetadata:
    """Bounded path/status facts for local test-edit accounting.

    This is intentionally a separate result from :class:`CheckChangeCapture`: callers can inspect
    changed paths without invoking the content-returning capture.  ``content_available`` remains
    false for the metadata path, so skip markers are reported as unknown until a separately
    authorized semantic capture supplies them.
    """

    base: ChangeBaseKind
    entries: tuple[ChangeMetadataEntry, ...]
    tracked_files: int
    untracked_files: int
    omitted_files: int
    truncated: bool
    content_available: bool = False
    base_commit: str = field(default="", repr=False)

    def __post_init__(self) -> None:
        if self.base not in _BASE_KINDS:
            raise _invalid()
        if (
            type(self.entries) is not tuple
            or len(self.entries) > _MAX_FILE_COUNT
            or any(type(item) is not ChangeMetadataEntry for item in self.entries)
        ):
            raise _invalid()
        for count in (self.tracked_files, self.untracked_files, self.omitted_files):
            if type(count) is not int or not 0 <= count <= _MAX_FILE_COUNT:
                raise _invalid()
        if self.omitted_files > self.tracked_files + self.untracked_files:
            raise _invalid()
        if type(self.truncated) is not bool or type(self.content_available) is not bool:
            raise _invalid()
        if self.content_available:
            raise _invalid()
        if self.omitted_files and not self.truncated:
            raise _invalid()
        if type(self.base_commit) is not str or (
            self.base_commit
            and (len(self.base_commit) not in {40, 64} or _HEX.fullmatch(self.base_commit) is None)
        ):
            raise _invalid()


class ChangeCapturePort(Protocol):
    """Blocking, read-only Git access for one explicit local workspace directory."""

    def read_task_base(self, workspace: str) -> TaskChangeBase:
        """Return HEAD's commit, or the empty tree for a repository with no commit yet."""
        ...

    def capture(self, workspace: str, base: TaskChangeBase | None) -> CheckChangeCapture:
        """Render the change from ``base`` (or HEAD when ``None``) to the working tree."""
        ...

    def capture_metadata(self, workspace: str, base: TaskChangeBase | None) -> CheckChangeMetadata:
        """Return bounded changed-path facts without reading or returning file content."""
        ...


@dataclass(frozen=True, slots=True)
class RequestedPathProbe:
    """One requested file path located against the checked repository root (#977).

    ``location`` is ``inside`` or ``outside``. For an inside path, ``relative`` is its
    root-relative form (``.`` for the root itself; compared with the check-time change entries,
    never stored), ``exists`` is
    ``None`` when a link or non-directory blocked the walk, and ``ignored`` is Git's answer.
    """

    location: str
    relative: str | None = field(default=None, repr=False)
    exists: bool | None = None
    ignored: bool | None = None
    # For an ignored path, where the ignoring rule lives: ``info_exclude`` (``.git/info/exclude``),
    # ``repository_file`` (a ``.gitignore`` in the tree, named root-relative by ``ignore_file``),
    # or ``outside_repository`` (a configured or global excludes file).
    ignore_source: str | None = None
    ignore_file: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.location not in {"inside", "outside"}:
            raise _invalid()
        if self.ignore_source not in {
            None,
            "info_exclude",
            "repository_file",
            "outside_repository",
        }:
            raise _invalid()
        if (self.location == "inside") is (self.relative is None):
            raise _invalid()


class TaskChangeBaseStorePort(Protocol):
    """Optional task-ledger seam that keeps the task-start base object as a durable root."""

    async def record_task_change_base(self, ref: ObjectRef) -> bool:
        """Keep ``ref`` as this task's base unless one is already recorded; return if kept."""
        ...

    async def load_task_change_base(self) -> ObjectRef | None: ...


@dataclass(frozen=True, slots=True)
class CheckWorkspaceSource:
    """The repository root one check may read, bound by the service from its control session.

    ``workspace`` is the locator the authenticated connection supplied at handshake and
    ``repository_commitment`` the installation-keyed commitment the service derived from that same
    locator. The capture runs only when the commitment equals the task route's own, so a
    connection cannot point one task's review at another repository.
    """

    workspace: str = field(repr=False)
    repository_commitment: str

    def __post_init__(self) -> None:
        if type(self.workspace) is not str or not Path(self.workspace).is_absolute():
            raise _invalid()
        validate_commitment(self.repository_commitment)


_CHECK_WORKSPACE_SOURCE: ContextVar[CheckWorkspaceSource | None] = ContextVar(
    "check_workspace_source", default=None
)


@contextmanager
def check_workspace_source_scope(source: CheckWorkspaceSource | None) -> Generator[None]:
    """Expose one check's trusted workspace to its AI-powered review composition only."""

    if source is not None and type(source) is not CheckWorkspaceSource:
        raise TypeError("check_workspace_source_invalid")
    token = _CHECK_WORKSPACE_SOURCE.set(source)
    try:
        yield
    finally:
        _CHECK_WORKSPACE_SOURCE.reset(token)


def current_check_workspace_source() -> CheckWorkspaceSource | None:
    return _CHECK_WORKSPACE_SOURCE.get()


def encode_task_change_base(base: TaskChangeBase) -> bytes:
    if type(base) is not TaskChangeBase:
        raise _invalid()
    return canonical_encode(
        cast(
            JsonValue,
            {
                "commit": base.commit,
                "object_format": base.object_format,
                "origin": base.origin,
                "schema": _TASK_CHANGE_BASE_SCHEMA,
            },
        )
    )


def decode_task_change_base(data: bytes) -> TaskChangeBase:
    parsed = strict_json_parse(data)
    if canonical_encode(parsed) != data or type(parsed) is not dict:
        raise _invalid()
    source = cast(dict[str, object], parsed)
    if set(source) - {"origin"} != {"commit", "object_format", "schema"}:
        raise _invalid()
    if source["schema"] != _TASK_CHANGE_BASE_SCHEMA:
        raise _invalid()
    return TaskChangeBase(
        cast(Literal["sha1", "sha256"], source["object_format"]),
        cast(str, source["commit"]),
        cast(TaskChangeBaseOrigin, source.get("origin", "task_start")),
    )


def encode_check_change(capture: CheckChangeCapture) -> bytes:
    if type(capture) is not CheckChangeCapture:
        raise _invalid()
    return canonical_encode(
        cast(
            JsonValue,
            {
                "base": capture.base,
                "base_commit": capture.base_commit,
                "omitted_files": capture.omitted_files,
                "redacted": capture.redacted,
                "schema": _CHECK_CHANGE_SCHEMA,
                "text": capture.text.decode("utf-8"),
                "tracked_files": capture.tracked_files,
                "truncated": capture.truncated,
                "untracked_files": capture.untracked_files,
            },
        )
    )


def decode_check_change(data: bytes) -> CheckChangeCapture:
    parsed = strict_json_parse(data)
    if canonical_encode(parsed) != data or type(parsed) is not dict:
        raise _invalid()
    source = cast(dict[str, object], parsed)
    if set(source) - {"base_commit"} != {
        "base",
        "omitted_files",
        "redacted",
        "schema",
        "text",
        "tracked_files",
        "truncated",
        "untracked_files",
    }:
        raise _invalid()
    if source["schema"] != _CHECK_CHANGE_SCHEMA or type(source["text"]) is not str:
        raise _invalid()
    return CheckChangeCapture(
        base=cast(ChangeBaseKind, source["base"]),
        text=source["text"].encode("utf-8"),
        tracked_files=cast(int, source["tracked_files"]),
        untracked_files=cast(int, source["untracked_files"]),
        omitted_files=cast(int, source["omitted_files"]),
        truncated=cast(bool, source["truncated"]),
        redacted=cast(bool, source["redacted"]),
        base_commit=cast(str, source.get("base_commit", "")),
    )
