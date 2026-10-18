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
from collections.abc import Callable, Collection, Generator, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, Literal, Protocol, cast

from finishup.domain.values import validate_commitment
from finishup.ports.objects import ObjectRef
from finishup.protocol.canonical import JsonValue, canonical_encode, strict_json_parse

__all__ = [
    "CHANGE_CAPTURE_UNAVAILABLE_REASONS",
    "CHECK_CHANGE_MEDIA_TYPE",
    "MAX_CHECK_CHANGE_TEXT_BYTES",
    "MAX_PROBED_FILE_SIZE",
    "TASK_CHANGE_BASE_MEDIA_TYPE",
    "ChangeBaseKind",
    "ChangeCapturePort",
    "ChangeCaptureUnavailable",
    "CheckChangeCapture",
    "CheckChangeMetadata",
    "ChangeLineCount",
    "ChangeLineCounts",
    "ChangeMetadataEntry",
    "CheckWorkspaceSource",
    "TaskChangeBase",
    "TaskChangeBaseStorePort",
    "check_workspace_source_scope",
    "current_check_workspace_source",
    "decode_check_change",
    "decode_task_change_base",
    "drop_space_cut_words",
    "encode_check_change",
    "encode_task_change_base",
    "metadata_path_representable",
    "RequestedPathProbe",
    "MAX_BASELINE_UNTRACKED_FILES",
    "MAX_NESTED_REPOSITORIES",
    "MAX_TASK_INPUT_FILES",
    "MAX_TASK_INPUT_TEXT_BYTES",
    "NestedUntrackedBaseline",
    "TASK_INPUT_ORIGINS",
    "TaskInputFile",
    "TaskInputOrigin",
    "UntrackedBaselineFile",
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
# The task-start snapshot of untracked files (issue #1045): names and metadata only, bounded so a
# workspace full of generated files keeps a small base object. Past the bound the snapshot is
# incomplete and an untracked file it does not name is treated as new, exactly as before.
MAX_BASELINE_UNTRACKED_FILES: Final = 4_096
_MAX_BASELINE_PATH_BYTES: Final = 262_144
# Nested Git repositories whose own change a check renders (issue #1045), and whose HEAD the
# task-start snapshot records.
MAX_NESTED_REPOSITORIES: Final = 8
# Read-only task input files a check may carry (issue #1045): at most this many, each rendered to
# at most this many bytes (whole, or head and tail with the cut marked).
MAX_TASK_INPUT_FILES: Final = 4
MAX_TASK_INPUT_TEXT_BYTES: Final = 16_384
_MAX_TASK_INPUT_SIZE: Final = (1 << 53) - 1

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
        # The system Git is older than the documented minimum (2.25).
        "git_version_unsupported",
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


def _json_path(value: object) -> bool:
    """A root-relative path a canonical JSON object can hold: no NUL, CR, LF or lone surrogate."""

    if type(value) is not str or not value or any(char in value for char in "\x00\r\n"):
        return False
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        return False
    return not value.startswith("/") and all(
        part not in {"", ".", ".."} for part in value.split("/")
    )


def _commit_id(value: object) -> bool:
    return type(value) is str and len(value) in {40, 64} and _HEX.fullmatch(value) is not None


@dataclass(frozen=True, slots=True)
class UntrackedBaselineFile:
    """One untracked file as it stood when the task started (issue #1045).

    ``state`` is a digest of the link-free ``stat`` fields the capture compares (file type and
    permissions, inode, size, modification and change times); no content is read. A file whose
    fields still digest to ``state`` at check time predates the task and is unchanged, so it is
    baseline, never an addition.
    """

    path: str = field(repr=False)
    state: str = field(repr=False)

    def __post_init__(self) -> None:
        if not _json_path(self.path):
            raise _invalid()
        if (
            type(self.state) is not str
            or not self.state.startswith("sha256:")
            or len(self.state) != 71
            or _HEX.fullmatch(self.state[7:]) is None
        ):
            raise _invalid()


@dataclass(frozen=True, slots=True)
class NestedUntrackedBaseline:
    """One nested repository's untracked files as they stood when the task started (#1045).

    ``path`` is the repository's root-relative directory (one of the base's ``nested`` rows);
    ``files`` are its untracked files, relative to that directory, in path order, each with the
    same ``stat`` digest the outer listing keeps. ``complete`` is false when the listing could not
    be taken whole within the snapshot's bounds; such a row names no file, and none of the
    repository's untracked files can then be told apart from one that predates the task.
    """

    path: str = field(repr=False)
    complete: bool
    files: tuple[UntrackedBaselineFile, ...] = field(default=(), repr=False)

    def __post_init__(self) -> None:
        if not _json_path(self.path) or type(self.complete) is not bool:
            raise _invalid()
        if (
            type(self.files) is not tuple
            or any(type(item) is not UntrackedBaselineFile for item in self.files)
            or any(
                left.path >= right.path
                for left, right in zip(self.files, self.files[1:], strict=False)
            )
            or (self.files and not self.complete)
        ):
            raise _invalid()


@dataclass(frozen=True, slots=True)
class TaskChangeBase:
    """The commit a task's check-time change starts from, fixed for the life of the task.

    ``task_start`` bases are HEAD when the task was created. A task without one gets a
    ``first_check`` base: HEAD when its first check ran, pinned so every later check of the task
    diffs from the same commit and commits made in between stay in the change.

    A ``task_start`` base also records the working tree's untracked files at that moment
    (``untracked``, names and ``stat`` identity only; ``untracked_complete`` is false when the
    listing exceeded its bound or could not be read), the HEAD of each nested Git repository
    among them or tracked as a gitlink (``nested``: root-relative directory and commit), and the
    untracked files of each of those repositories (``nested_untracked``, in path order, sharing
    the outer listing's name and byte bounds), so files that predate the task are baseline and a
    nested repository's change starts where the task did (issue #1045).
    """

    object_format: Literal["sha1", "sha256"]
    commit: str = field(repr=False)
    origin: TaskChangeBaseOrigin = "task_start"
    untracked: tuple[UntrackedBaselineFile, ...] = field(default=(), repr=False)
    untracked_complete: bool = False
    nested: tuple[tuple[str, str], ...] = field(default=(), repr=False)
    nested_untracked: tuple[NestedUntrackedBaseline, ...] = field(default=(), repr=False)

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
        if (
            type(self.untracked) is not tuple
            or len(self.untracked) > MAX_BASELINE_UNTRACKED_FILES
            or any(type(item) is not UntrackedBaselineFile for item in self.untracked)
            or sum(len(item.path.encode("utf-8")) for item in self.untracked)
            > _MAX_BASELINE_PATH_BYTES
            or len({item.path for item in self.untracked}) != len(self.untracked)
        ):
            raise _invalid()
        if type(self.untracked_complete) is not bool:
            raise _invalid()
        if (
            type(self.nested) is not tuple
            or len(self.nested) > MAX_NESTED_REPOSITORIES
            or any(
                type(item) is not tuple
                or len(item) != 2
                or not _json_path(item[0])
                or not _commit_id(item[1])
                for item in self.nested
            )
            or len({item[0] for item in self.nested}) != len(self.nested)
        ):
            raise _invalid()
        recorded = {item[0] for item in self.nested}
        if (
            type(self.nested_untracked) is not tuple
            or any(type(item) is not NestedUntrackedBaseline for item in self.nested_untracked)
            or any(item.path not in recorded for item in self.nested_untracked)
            or any(
                left.path >= right.path
                for left, right in zip(
                    self.nested_untracked, self.nested_untracked[1:], strict=False
                )
            )
        ):
            raise _invalid()
        # The nested listings share the outer listing's bounds.
        files = [*self.untracked, *(item for row in self.nested_untracked for item in row.files)]
        if (
            len(files) > MAX_BASELINE_UNTRACKED_FILES
            or sum(len(item.path.encode("utf-8")) for item in files) > _MAX_BASELINE_PATH_BYTES
        ):
            raise _invalid()
        if self.origin != "task_start" and (
            self.untracked or self.untracked_complete or self.nested or self.nested_untracked
        ):
            # Only the task's own start can say what predates the task.
            raise _invalid()


type TaskInputOrigin = Literal["task", "verification", "outside_workspace", "task_directory"]
TASK_INPUT_ORIGINS: Final[frozenset[str]] = frozenset(
    {"task", "verification", "outside_workspace", "task_directory"}
)


def drop_space_cut_words(
    values: Sequence[str],
    names_something: Callable[[str], bool],
    space_cut: Collection[str],
) -> tuple[str, ...]:
    """``values`` without the words the spaces cut from a spaced value that names something.

    Issue #1102 (RC6d): a quoted span only the disk can tell apart (``"/app/test data"`` is a
    folder or prose, ``"/app/Terms and Conditions/terms.pdf"`` one path or two) is offered as a
    candidate ahead of its own words. A read asks ``names_something`` (a metadata look at that
    one value, inside what the read may look at) for each value holding a space; when it says
    yes, a value that is one of that value's space-cut words (``/app/test``) is no path the task
    named and is dropped, so an unrelated folder is never read under the task's name. Only a
    value in ``space_cut`` may be dropped: one that came only from splitting a quoted span
    (``space_cut_input_paths``). A value the task also named on its own (``Notes.md`` of
    ``Read "docs/My Notes.md" and Notes.md``), a ``role: input`` item or a verification operand
    is never in it and is always kept. A spaced value is never dropped. Order is kept.
    """

    cut: set[str] = set()
    for value in values:
        if " " in value and names_something(value):
            cut.update(word.rstrip("/") for word in value.split(" ") if word.rstrip("/"))
    if not cut:
        return tuple(values)
    return tuple(
        value
        for value in values
        if " " in value or value not in space_cut or value.rstrip("/") not in cut
    )


def _listing_path(value: str) -> bool:
    """A named directory's listing path (issue #1102): ``dir/``, or ``./`` for the root."""

    return value == "./" or (value.endswith("/") and _json_path(value[:-1]))


@dataclass(frozen=True, slots=True)
class TaskInputFile:
    """One read-only task input file the check carries for review (issue #1045).

    A file the task statement (or a ``role: input`` requested item) names, inside the checked
    repository and unchanged since the task started (a tracked one only against a ``task_start``
    base, and only when its bytes match the base commit), that Git does not ignore. ``text`` is
    the file whole, or its head and tail with the cut marked, at most ``MAX_TASK_INPUT_TEXT_BYTES``;
    ``size`` is the file's byte size; ``redacted`` is set by the service after it replaced
    credential-like spans.
    """

    path: str = field(repr=False)
    text: bytes = field(repr=False)
    size: int
    redacted: bool = False
    # Issue #1082: who named the file and where it was read. ``task``: the task statement or a
    # ``role: input`` item, inside the repository (the #1045 rule). ``verification``: a path
    # operand of a recorded verification command, under the same repository rule, so a test the
    # task ships reaches the reviewer as the oracle. ``outside_workspace``: named by the task and
    # read beneath a root the owner admitted in the repository's privacy grant.
    # ``task_directory`` (issue #1102): beneath a directory the task names inside the repository,
    # chosen by FinishUP by the identifiers it shares with the change, or else by its place
    # beside the changed files, under the ``task`` rule; never labelled as named by the task.
    origin: TaskInputOrigin = "task"
    # Issue #1082: ``text`` is FinishUP's own bounded summary of a binary or data file it never
    # sends whole (``finishup.adapters.input_summary``), not the file's bytes. Issue #1102: a
    # ``task`` summary whose path ends in ``/`` is FinishUP's own listing of the unchanged files
    # beneath a directory the task names (``./`` for the workspace root).
    summary: bool = False

    def __post_init__(self) -> None:
        if self.origin not in TASK_INPUT_ORIGINS or type(self.summary) is not bool:
            raise _invalid()
        if self.origin == "outside_workspace":
            if not self.path.startswith("/") or not _json_path(self.path.lstrip("/")):
                raise _invalid()
        elif not _json_path(self.path) and not (
            self.origin == "task" and self.summary and _listing_path(self.path)
        ):
            raise _invalid()
        if (
            type(self.text) is not bytes
            or not 1 <= len(self.text) <= MAX_TASK_INPUT_TEXT_BYTES + 256
        ):
            raise _invalid()
        try:
            self.text.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise _invalid() from exc
        if type(self.size) is not int or not 0 <= self.size <= _MAX_TASK_INPUT_SIZE:
            raise _invalid()
        if type(self.redacted) is not bool:
            raise _invalid()


@dataclass(frozen=True, slots=True)
class CheckChangeCapture:
    """One bounded, rendered check-time change: a plain-text header followed by a unified diff.

    ``truncated`` is set whenever a changed file or any of its bytes is missing from ``text``; the
    header names each file that is not shown. ``redacted`` is set by the service after it replaced
    credential-like spans in ``text`` or in a task input file, or withheld an input it could not
    redact, never by the adapter. ``base_commit`` is the object id the change was taken against (the
    task-start commit, HEAD, or the empty tree); it keys the per-file commitments a completed review
    records, and is empty only for an object written before it existed. ``inputs`` are the read-only
    task input files the same read carried (issue #1045); they are not part of the change and never
    enter ``text``. ``outside_inputs_not_admitted`` is the service's closed decision, taken when
    the read ran, that the task names an existing input outside the workspace that no root the
    owner admitted covers (issue #1102); it names no path.
    """

    base: ChangeBaseKind
    text: bytes = field(repr=False)
    tracked_files: int
    untracked_files: int
    omitted_files: int
    truncated: bool
    redacted: bool = False
    base_commit: str = field(default="", repr=False)
    inputs: tuple[TaskInputFile, ...] = field(default=(), repr=False)
    outside_inputs_not_admitted: bool = False

    def __post_init__(self) -> None:
        if self.base not in _BASE_KINDS:
            raise _invalid()
        if type(self.text) is not bytes or not 1 <= len(self.text) <= MAX_CHECK_CHANGE_TEXT_BYTES:
            raise _invalid()
        if (
            type(self.inputs) is not tuple
            or len(self.inputs) > MAX_TASK_INPUT_FILES
            or any(type(item) is not TaskInputFile for item in self.inputs)
            or len({item.path for item in self.inputs}) != len(self.inputs)
        ):
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
        if (
            type(self.truncated) is not bool
            or type(self.redacted) is not bool
            or type(self.outside_inputs_not_admitted) is not bool
        ):
            raise _invalid()
        if self.omitted_files and not self.truncated:
            raise _invalid()
        if type(self.base_commit) is not str or (
            self.base_commit
            and (len(self.base_commit) not in {40, 64} or _HEX.fullmatch(self.base_commit) is None)
        ):
            raise _invalid()


_UNREPRESENTABLE_PATH_CHARACTERS: Final = "\x00\r\n"


def metadata_path_representable(path: str) -> bool:
    """Whether *path* can be a :class:`ChangeMetadataEntry` path.

    Git allows a carriage return or line feed in a file name (NUL never reaches a ``-z`` field),
    but structural accounting is line-oriented and refuses such a path.  The capture skips that
    one entry and counts it instead of failing the whole check-time read (issue #1019).
    """

    return (
        type(path) is str
        and bool(path)
        and not any(char in path for char in _UNREPRESENTABLE_PATH_CHARACTERS)
    )


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
        if not metadata_path_representable(self.path):
            raise _invalid()
        if type(self.untracked) is not bool:
            raise _invalid()
        if self.original_path is not None and not metadata_path_representable(self.original_path):
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
    # Changed paths skipped because a CR or LF in the name cannot be an entry (issue #1019).
    # Each is also counted in ``omitted_files``, so the listing is truncated.
    unrepresentable_files: int = 0

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
        if (
            type(self.unrepresentable_files) is not int
            or isinstance(self.unrepresentable_files, bool)
            or not 0 <= self.unrepresentable_files <= self.omitted_files
        ):
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

    def capture(
        self,
        workspace: str,
        base: TaskChangeBase | None,
        *,
        priority_paths: tuple[str, ...] = (),
        input_paths: tuple[str, ...] = (),
        space_cut_paths: frozenset[str] = frozenset(),
    ) -> CheckChangeCapture:
        """Render the change from ``base`` (or HEAD when ``None``) to the working tree.

        ``priority_paths`` names the task's declared deliverables; their files are rendered ahead
        of every other file (tb4n2 R7). They order the change only, never widen what is read.
        ``input_paths`` names candidate read-only task input files (issue #1045); only those inside
        the repository, unchanged, not ignored and not credential-named are read, into ``inputs``.
        A candidate may name a directory inside the repository (issue #1102): its unchanged files
        are listed and the ones most related to the change read, within the same input bound.
        A candidate holding a space that names something there keeps the words its spaces cut
        out of the read (``drop_space_cut_words``); ``space_cut_paths`` are the candidates that
        are only such words, and no other candidate is ever dropped that way.
        """
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
    # For an existing directory only (#1002): whether a bounded, link-free metadata walk found any
    # entry that is not a directory beneath it. ``False`` means empty or only empty directories;
    # ``None`` means not a directory, or the walk was blocked or exceeded its bound.
    holds_file: bool | None = None
    # For an existing regular file only (tb4n2 R2): its size in bytes from the same link-free
    # ``stat``; no content is read. ``None`` for anything else or when the walk was blocked.
    size_bytes: int | None = None

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
        if self.holds_file is not None and self.exists is not True:
            raise _invalid()
        if self.size_bytes is not None and (
            self.exists is not True
            or type(self.size_bytes) is not int
            or not 0 <= self.size_bytes <= MAX_PROBED_FILE_SIZE
        ):
            raise _invalid()


_MAX_LINE_COUNT: Final = 1 << 40
# The largest file size a probe reports (the JSON-safe integer range); a larger one is unknown.
MAX_PROBED_FILE_SIZE: Final = (1 << 53) - 1


def _line_count(value: object) -> bool:
    return value is None or (type(value) is int and 0 <= value <= _MAX_LINE_COUNT)


@dataclass(frozen=True, slots=True)
class ChangeLineCount:
    """Line counts for one changed file in the check-time change (ADR-035).

    ``added``/``removed`` are Git's numstat counts for a tracked file, or the line count of an
    untracked file with ``removed=0``; ``None`` when the file is binary, too large, or could not be
    read safely. ``path`` is root-relative, compared in process only and never stored.
    """

    path: str = field(repr=False)
    added: int | None
    removed: int | None
    untracked: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.path) is not str
            or not self.path
            or any(char in self.path for char in "\x00\r\n")
        ):
            raise _invalid()
        if not _line_count(self.added) or not _line_count(self.removed):
            raise _invalid()
        if type(self.untracked) is not bool:
            raise _invalid()


@dataclass(frozen=True, slots=True)
class ChangeLineCounts:
    """A bounded, metadata-only line-count read of the check-time change (ADR-035).

    ``changed`` holds counts for the changed files that fit the read; ``truncated`` is true when
    some changed or untracked file was left out, so any total is a lower bound. ``base_lines``
    holds, in the order the caller named them, the line count of each requested path in the base
    (``None`` when absent from the base, binary, or unreadable). No content leaves the adapter.
    """

    changed: tuple[ChangeLineCount, ...]
    base_lines: tuple[int | None, ...]
    truncated: bool

    def __post_init__(self) -> None:
        if (
            type(self.changed) is not tuple
            or len(self.changed) > _MAX_FILE_COUNT
            or any(type(item) is not ChangeLineCount for item in self.changed)
        ):
            raise _invalid()
        if type(self.base_lines) is not tuple or not all(
            _line_count(item) for item in self.base_lines
        ):
            raise _invalid()
        if type(self.truncated) is not bool:
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
    body: dict[str, JsonValue] = {
        "commit": base.commit,
        "object_format": base.object_format,
        "origin": base.origin,
        "schema": _TASK_CHANGE_BASE_SCHEMA,
    }
    if base.untracked or base.untracked_complete or base.nested:
        # The task-start snapshot (issue #1045). A base without one (written before it existed, or
        # whose listing could not be read) has none of these keys and keeps its bytes; it reads as
        # an empty, incomplete snapshot, so every untracked file is new, as before.
        body["untracked"] = [[item.path, item.state] for item in base.untracked]
        body["untracked_complete"] = base.untracked_complete
        body["nested"] = [[path, commit] for path, commit in base.nested]
        if base.nested_untracked:
            # Only when recorded, so a base written before nested listings keeps its bytes.
            body["nested_untracked"] = [
                [row.path, row.complete, [[item.path, item.state] for item in row.files]]
                for row in base.nested_untracked
            ]
    return canonical_encode(cast(JsonValue, body))


def decode_task_change_base(data: bytes) -> TaskChangeBase:
    parsed = strict_json_parse(data)
    if canonical_encode(parsed) != data or type(parsed) is not dict:
        raise _invalid()
    source = cast(dict[str, object], parsed)
    if set(source) - {
        "origin",
        "untracked",
        "untracked_complete",
        "nested",
        "nested_untracked",
    } != {
        "commit",
        "object_format",
        "schema",
    }:
        raise _invalid()
    if source["schema"] != _TASK_CHANGE_BASE_SCHEMA:
        raise _invalid()
    # Only shapes the encoder writes are read: the snapshot's three keys together or not at all,
    # ``nested_untracked`` only beside them and never empty or null.
    snapshot = {"untracked", "untracked_complete", "nested"} & set(source)
    if snapshot not in (set(), {"untracked", "untracked_complete", "nested"}) or (
        "nested_untracked" in source and not snapshot
    ):
        raise _invalid()
    untracked_raw = source.get("untracked", [])
    nested_raw = source.get("nested", [])
    listings_raw = source.get("nested_untracked", [])
    if (
        type(untracked_raw) is not list
        or type(nested_raw) is not list
        or type(listings_raw) is not list
        or ("nested_untracked" in source and not listings_raw)
    ):
        raise _invalid()
    untracked = _baseline_files(cast(list[object], untracked_raw))
    listings: list[NestedUntrackedBaseline] = []
    for row in cast(list[object], listings_raw):
        if type(row) is not list or len(cast(list[object], row)) != 3:
            raise _invalid()
        path, complete, files = cast(list[object], row)
        listings.append(
            NestedUntrackedBaseline(cast(str, path), cast(bool, complete), _baseline_files(files))
        )
    nested: list[tuple[str, str]] = []
    for row in cast(list[object], nested_raw):
        if type(row) is not list or len(cast(list[object], row)) != 2:
            raise _invalid()
        path, commit = cast(list[object], row)
        nested.append((cast(str, path), cast(str, commit)))
    base = TaskChangeBase(
        cast(Literal["sha1", "sha256"], source["object_format"]),
        cast(str, source["commit"]),
        cast(TaskChangeBaseOrigin, source.get("origin", "task_start")),
        tuple(untracked),
        cast(bool, source.get("untracked_complete", False)),
        tuple(nested),
        tuple(listings),
    )
    if snapshot and not (base.untracked or base.untracked_complete or base.nested):
        # An empty snapshot is never written: its keys are left out.
        raise _invalid()
    return base


def _baseline_files(raw: object) -> tuple[UntrackedBaselineFile, ...]:
    """Decode ``[[path, state], ...]`` rows of a task-start snapshot strictly."""

    if type(raw) is not list:
        raise _invalid()
    files: list[UntrackedBaselineFile] = []
    for row in cast(list[object], raw):
        if type(row) is not list or len(cast(list[object], row)) != 2:
            raise _invalid()
        path, state = cast(list[object], row)
        files.append(UntrackedBaselineFile(cast(str, path), cast(str, state)))
    return tuple(files)


def encode_check_change(capture: CheckChangeCapture) -> bytes:
    if type(capture) is not CheckChangeCapture:
        raise _invalid()
    body: dict[str, JsonValue] = {
        "base": capture.base,
        "base_commit": capture.base_commit,
        "omitted_files": capture.omitted_files,
        "redacted": capture.redacted,
        "schema": _CHECK_CHANGE_SCHEMA,
        "text": capture.text.decode("utf-8"),
        "tracked_files": capture.tracked_files,
        "truncated": capture.truncated,
        "untracked_files": capture.untracked_files,
    }
    if capture.inputs:
        # Only present when the read carried task input files (issue #1045), so every object
        # written without them keeps its bytes.
        # ``origin`` and ``summary`` (issue #1082) are written only when not the default, so an
        # input read before they existed keeps its bytes.
        body["inputs"] = [
            {
                "path": item.path,
                "redacted": item.redacted,
                "size": item.size,
                "text": item.text.decode("utf-8"),
                **({"origin": item.origin} if item.origin != "task" else {}),
                **({"summary": True} if item.summary else {}),
            }
            for item in capture.inputs
        ]
    if capture.outside_inputs_not_admitted:
        # Issue #1102: written only when set, so every object without it keeps its bytes.
        body["outside_inputs_not_admitted"] = True
    return canonical_encode(cast(JsonValue, body))


def decode_check_change(data: bytes) -> CheckChangeCapture:
    parsed = strict_json_parse(data)
    if canonical_encode(parsed) != data or type(parsed) is not dict:
        raise _invalid()
    source = cast(dict[str, object], parsed)
    if set(source) - {"base_commit", "inputs", "outside_inputs_not_admitted"} != {
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
    if source.get("outside_inputs_not_admitted", True) is not True:
        # A default value is never written, so a present ``false`` is not canonical.
        raise _invalid()
    inputs_raw = source.get("inputs", [])
    if type(inputs_raw) is not list or ("inputs" in source and not inputs_raw):
        raise _invalid()
    inputs: list[TaskInputFile] = []
    for row in cast(list[object], inputs_raw):
        if type(row) is not dict:
            raise _invalid()
        fields = cast(dict[str, object], row)
        if (
            set(fields) - {"origin", "summary"} != {"path", "redacted", "size", "text"}
            or type(fields["text"]) is not str
            or fields.get("origin", "verification") == "task"
            or fields.get("summary", True) is not True
        ):
            # A default value is never written, so a present default is not canonical.
            raise _invalid()
        inputs.append(
            TaskInputFile(
                cast(str, fields["path"]),
                fields["text"].encode("utf-8"),
                cast(int, fields["size"]),
                cast(bool, fields["redacted"]),
                cast(TaskInputOrigin, fields.get("origin", "task")),
                fields.get("summary", False) is True,
            )
        )
    return CheckChangeCapture(
        base=cast(ChangeBaseKind, source["base"]),
        text=source["text"].encode("utf-8"),
        tracked_files=cast(int, source["tracked_files"]),
        untracked_files=cast(int, source["untracked_files"]),
        omitted_files=cast(int, source["omitted_files"]),
        truncated=cast(bool, source["truncated"]),
        redacted=cast(bool, source["redacted"]),
        base_commit=cast(str, source.get("base_commit", "")),
        inputs=tuple(inputs),
        outside_inputs_not_admitted=source.get("outside_inputs_not_admitted") is True,
    )
