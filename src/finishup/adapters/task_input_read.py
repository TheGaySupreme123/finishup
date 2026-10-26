"""Read-only task input files: bounded text or FinishUP's own summary (issues #1045 and #1082).

A task input is a file the task names that the reviewer needs beside the change: a
specification, a dataset, the source to port, a test the verification runs. This module turns the
bytes the service read into one bounded ``TaskInputFile``:

- text stays text, whole or as head and tail with the cut marked, a large text data file (a CSV,
  say) included (issue #1094 R2-N3);
- a binary file or an image becomes FinishUP's own bounded summary
  (``finishup.adapters.input_summary``), never its bytes;
- a file larger than the whole-read bound is read from its two ends only, without following a
  link: text keeps its head and tail, and a binary file is summarized from its head.

A recognized document or binary signature (an all-ASCII PDF has no NUL) is summarized like any
binary, and no cut ever splits a credential the shared scanner recognizes: a head or tail cut moves
clear of one before the text is cut (PR #1086 review R1-04, R1-08).

It also holds the one outside-workspace read path: files the task names beneath a directory the
owner admitted in the repository's privacy grant (``PrivacyPolicy.admitted_input_roots``). That
reader opens the admitted root one component at a time from ``/`` without following a link, then
walks beneath it the same way. Every directory on the way, the root's ancestors included, must be
owned by the service user or by root and writable by no other account (a sticky directory such as
``/tmp`` excepted), and must not be the workspace or another excluded directory, compared by
device and inode so a case-insensitive or otherwise different spelling cannot re-enter it. Hidden
components and credential-named files are refused, and only singly linked regular files owned by
the service user or by root that no other account may write are read; group write counts as
another account's unless the group is the owner's private group (``writable_by_others``). Nothing
here decides whether the content may leave: the review recipe, the redaction pass and the egress
gate still do.
"""

from __future__ import annotations

import os
import posixpath
import stat
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, replace
from itertools import islice
from pathlib import Path
from typing import Final, Literal

from finishup.adapters.home_project_reads import home_private_location, home_private_path
from finishup.adapters.input_summary import declared_binary_format, summarize_task_input
from finishup.config.foreign_write import writable_by_others
from finishup.domain.privacy import (
    SYSTEM_DIRECTORY_PREFIXES,
    admitted_input_root_valid,
    system_directory_path,
)
from finishup.domain.repository_excerpt import credential_named_bytes
from finishup.observability.privacy import scan_for_sensitive_content
from finishup.ports.change_capture import (
    MAX_TASK_INPUT_FILES,
    MAX_TASK_INPUT_TEXT_BYTES,
    TaskInputFile,
    TaskInputOrigin,
    drop_space_cut_words,
)

__all__ = [
    "MAX_TASK_INPUT_READ_BYTES",
    "ReadDeadline",
    "clear_cut",
    "list_beneath",
    "read_declared_test",
    "read_text_beneath",
    "read_ends_beneath",
    "read_outside_inputs",
    "OutsideSnapshotRead",
    "snapshot_outside_inputs",
    "task_input_from_bytes",
    "task_input_from_ends",
]

# A whole read of at most this many bytes; a larger file is read from its two ends only.
MAX_TASK_INPUT_READ_BYTES: Final = 1024 * 1024
_TAIL_BYTES: Final = 8 * 1024
_BINARY_PROBE_BYTES: Final = 8_000
_READ_CHUNK: Final = 65_536
_ELISION: Final = "\n[finishup: {elided} of {total} bytes elided here; head and tail kept]\n"
# Outside-workspace reads are bounded in count and time like the in-repository read.
_MAX_OUTSIDE_CANDIDATES: Final = 16
_OUTSIDE_READ_SECONDS: Final = 5.0
# A credential the shared scanner recognizes is at most this long (its own chunk overlap), so a
# window this wide on each side of a cut holds any match that straddles it. The tail is read with
# the same margin before it, so its cut can be moved clear of a credential too.
_CUT_SCAN_WINDOW: Final = 4_096
_DIRECTORY_FLAGS: Final = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_FILE_FLAGS: Final = (
    os.O_RDONLY
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_NONBLOCK", 0)
    | getattr(os, "O_CLOEXEC", 0)
)


def _decode(text: bytes) -> str:
    return text.decode("utf-8", errors="replace")


def _binary(content: bytes) -> bool:
    """Whether ``content`` is summarized rather than sent as text (PR #1086 review R1-08).

    A format whose signature the summarizer recognizes is summarized first, whether or not its
    bytes hold a NUL (an all-ASCII PDF holds none); the NUL sniff then catches every other binary.
    Text formats with no such signature (CSV, source code, FASTA, JSON) stay text.
    """

    return declared_binary_format(content) or b"\0" in content[:_BINARY_PROBE_BYTES]


def _summary(name: str, content: bytes, size: int, origin: TaskInputOrigin) -> TaskInputFile | None:
    """FinishUP's summary of a binary input; ``redacted`` when the summarizer withheld a value."""

    summary, withheld = summarize_task_input(name, content, size)
    text = summary.encode("utf-8")
    if len(text) > MAX_TASK_INPUT_TEXT_BYTES:
        # Whole lines only: a cut line could hold part of a quoted value.
        text = text[: text.rfind(b"\n", 0, MAX_TASK_INPUT_TEXT_BYTES) + 1]
    try:
        return TaskInputFile(name, text, size, redacted=withheld, origin=origin, summary=True)
    except ValueError:
        return None


def _cut_clear(data: bytes, cut: int, keep: Literal["head", "tail"]) -> int:
    """``cut`` moved so no credential the shared scanner recognizes straddles it (R1-04).

    A cut through a credential would leave a fragment too short for any later scan to recognize.
    Keeping the head, the cut moves back to the credential's start; keeping the tail, forward to
    its end, so the credential is wholly on the side that is dropped.
    """

    low = max(0, cut - _CUT_SCAN_WINDOW)
    spans = [
        (low + finding.start_offset, low + finding.end_offset)
        for finding in scan_for_sensitive_content(data[low : cut + _CUT_SCAN_WINDOW])
    ]
    moved = True
    while moved:
        moved = False
        for start, end in spans:
            if start < cut < end:
                cut = start if keep == "head" else end
                moved = True
    return cut


def _head_tail(head: bytes, tail: bytes, total: int) -> bytes:
    """Head and tail of a ``total``-byte text within ``MAX_TASK_INPUT_TEXT_BYTES``, cut marked.

    Each cut is moved clear of any recognized credential before the text is cut (R1-04); the
    redaction pass then sees every kept credential whole.
    """

    marker = _ELISION.format(elided="0" * len(str(total)), total=total)
    side = (MAX_TASK_INPUT_TEXT_BYTES - len(marker.encode("utf-8"))) // 2
    head_cut = _cut_clear(head, min(side, len(head)), "head")
    tail_cut = _cut_clear(tail, max(0, len(tail) - side), "tail")
    first = head[:head_cut].decode("utf-8", errors="ignore")
    last = tail[tail_cut:].decode("utf-8", errors="ignore")
    elided = total - len(first.encode("utf-8")) - len(last.encode("utf-8"))
    return (first + _ELISION.format(elided=elided, total=total) + last).encode("utf-8")


def task_input_from_bytes(
    name: str, content: bytes, *, origin: TaskInputOrigin = "task"
) -> TaskInputFile | None:
    """One task input from a whole read: text (head and tail when long) or a summary."""

    if not content:
        return None
    total = len(content)
    if _binary(content):
        return _summary(name, content, total, origin)
    if total <= MAX_TASK_INPUT_TEXT_BYTES:
        text = _decode(content).encode("utf-8")
    else:
        text = _head_tail(content, content, total)
    try:
        return TaskInputFile(name, text, total, origin=origin)
    except ValueError:
        return None


def task_input_from_ends(
    name: str, head: bytes, tail: bytes, size: int, *, origin: TaskInputOrigin = "task"
) -> TaskInputFile | None:
    """One task input from a file too large to read whole (issue #1082).

    A binary file is summarized from its head; text keeps its head and its tail with the cut
    marked, so the header row of a large data file and its last rows both reach the reviewer.
    """

    if not head:
        return None
    if _binary(head):
        return _summary(name, head, size, origin)
    try:
        return TaskInputFile(name, _head_tail(head, tail, size), size, origin=origin)
    except ValueError:
        return None


@dataclass(frozen=True, slots=True)
class _Trust:
    """What the outside read trusts (PR #1086 review R1-02, R1-03, R1-07).

    ``owners`` may own a directory on the way or the file read; ``excluded`` are the device and
    inode of directories never entered (the workspace, FinishUP's own directories), so another
    spelling of one (a case-insensitive alias, a bind mount) is refused like the path itself.
    """

    owners: frozenset[int]
    excluded: frozenset[tuple[int, int]]

    def directory(self, facts: os.stat_result) -> bool:
        """A directory of an owner, not excluded, that no other account can rename beneath.

        A directory another account may write is trusted only with the sticky bit (``/tmp``):
        then no other account can rename or replace an entry it does not own, and every entry
        read beneath it must itself belong to an owner.
        """

        return (
            stat.S_ISDIR(facts.st_mode)
            and facts.st_uid in self.owners
            and (facts.st_dev, facts.st_ino) not in self.excluded
            and (not writable_by_others(facts) or bool(facts.st_mode & stat.S_ISVTX))
        )

    def file(self, facts: os.stat_result) -> bool:
        """A singly linked regular file of an owner that no other account may write."""

        return (
            stat.S_ISREG(facts.st_mode)
            and facts.st_nlink == 1
            and facts.st_uid in self.owners
            and not writable_by_others(facts)
        )


def read_ends_beneath(
    root_descriptor: int,
    path: bytes,
    *,
    owners: frozenset[int],
    head_limit: int = MAX_TASK_INPUT_READ_BYTES,
) -> tuple[bytes, bytes, int] | None:
    """``(head, tail, size)`` of the regular file ``path`` beneath an open root, or ``None``.

    Each component is opened from the root descriptor without following a link. Only a singly
    linked regular file owned by one of ``owners`` that no other user may write is read: up to
    ``head_limit`` bytes from its start and, when it is larger, its last 8 KiB with 4 KiB before
    them, so the tail's cut can be moved clear of a credential. A file that changes while it is
    read is not returned.
    """

    return _read_ends(root_descriptor, path, owners=owners, head_limit=head_limit, trust=None)


def _read_ends(
    root_descriptor: int,
    path: bytes,
    *,
    owners: frozenset[int],
    head_limit: int,
    trust: _Trust | None,
    recorded: str | None = None,
    expired: Callable[[], bool] | None = None,
) -> tuple[bytes, bytes, int] | None:
    """``read_ends_beneath``; with ``trust``, every directory and the file must also pass it.

    ``recorded`` is the absolute path the read will be reported under; after the read it must
    still name the file read, so a renamed and replaced ancestor or root is refused too.
    ``expired`` is checked before each chunk; once true the read stops with ``ReadDeadline``.
    """

    parts = path.split(b"/")
    if not path or any(part in {b"", b".", b".."} for part in parts):
        return None
    opened: list[int] = []
    current = root_descriptor
    try:
        for part in parts[:-1]:
            current = os.open(part, _DIRECTORY_FLAGS, dir_fd=current)
            opened.append(current)
            if trust is not None and not trust.directory(os.fstat(current)):
                return None
        descriptor = os.open(parts[-1], _FILE_FLAGS, dir_fd=current)
        opened.append(descriptor)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid not in owners
            or before.st_mode & stat.S_IWOTH
            or (trust is not None and not trust.file(before))
        ):
            return None
        size = before.st_size
        chunks: list[bytes] = []
        read = 0
        while read < min(size, head_limit):
            if expired is not None and expired():
                raise ReadDeadline("reviewer_read_deadline")
            chunk = os.read(descriptor, min(_READ_CHUNK, head_limit - read))
            if not chunk:
                break
            chunks.append(chunk)
            read += len(chunk)
        head = b"".join(chunks)
        tail = b""
        if size > head_limit:
            span = _TAIL_BYTES + _CUT_SCAN_WINDOW
            tail = os.pread(descriptor, span, max(0, size - span))
        # Drift and identity (#1118 R6): the descriptor's facts are unchanged and the name still
        # leads to that same file, so an ordinary replacement or permission change mid-read is
        # refused rather than kept. Not a defence against a hostile process of the same user.
        after = os.fstat(descriptor)
        named = (
            os.stat(parts[-1], dir_fd=current, follow_symlinks=False)
            if recorded is None
            else os.stat(recorded, follow_symlinks=False)
        )
        if (
            _identity(before) != _identity(after)
            or (named.st_dev, named.st_ino) != (after.st_dev, after.st_ino)
            or read != min(size, head_limit)
        ):
            return None
        return head, tail, size
    except OSError:
        # A link on the way (ELOOP/ENOTDIR), a missing or unreadable file: nothing is read.
        return None
    finally:
        for descriptor in reversed(opened):
            os.close(descriptor)


def _identity(facts: os.stat_result) -> tuple[int, ...]:
    return (
        facts.st_dev,
        facts.st_ino,
        facts.st_size,
        facts.st_mtime_ns,
        facts.st_ctime_ns,
        facts.st_mode,
        facts.st_uid,
        facts.st_nlink,
    )


def _folded_inside(path: str, folded_directories: tuple[str, ...]) -> bool:
    """Whether ``path``, case-folded, is at or beneath one of the case-folded directories.

    The lexical twin of the identity test: it errs toward refusing (on a case-sensitive file
    system ``/shared/Repo`` is refused beside a workspace ``/shared/repo``), never toward reading.
    """

    folded = posixpath.normpath(path).casefold()
    return any(
        folded == directory or folded.startswith(directory.rstrip("/") + "/")
        for directory in folded_directories
    )


def _beneath(value: str, roots: tuple[str, ...]) -> tuple[str, bytes] | None:
    """``(root, relative path)`` for an absolute ``value`` lexically at or beneath one root.

    The relative path is empty for the root itself (a directory request for the whole root).
    """

    if not value.startswith("/") or "\x00" in value:
        return None
    path = posixpath.normpath(value)
    for root in roots:
        prefix = root.rstrip("/") + "/"
        if path == root:
            return root, b""
        if path.startswith(prefix) and len(path) > len(prefix):
            relative = path[len(prefix) :]
            if any(part.startswith(".") for part in relative.split("/")):
                # Hidden files and directories (.ssh, .env, .git) are never read.
                return None
            try:
                encoded = relative.encode("utf-8", errors="strict")
            except UnicodeEncodeError:
                return None
            if credential_named_bytes(encoded) or home_private_path(Path(root), encoded):
                return None
            return root, encoded
    return None


# A directory the task names beneath an admitted root offers its files, two levels deep at most,
# in name order, until the input bound is reached. Listing reads names only; each file is then
# read like a named one.
_MAX_LISTED_DEPTH: Final = 2
_MAX_LISTED_ENTRIES: Final = 256


def _listed_files(root_descriptor: int, directory: bytes, room: int, trust: _Trust) -> list[bytes]:
    """Up to ``room`` regular, visible, not credential-named files beneath ``directory``.

    Every directory opened or queued must pass ``trust``: one that is the workspace or another
    excluded directory, by identity, is never entered (R1-02).
    """

    found: list[bytes] = []
    pending: list[tuple[bytes, int]] = [(directory, 0)]
    while pending and len(found) < room:
        current, depth = pending.pop(0)
        opened: list[int] = []
        try:
            descriptor = root_descriptor
            for part in [part for part in current.split(b"/") if part]:
                descriptor = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
                opened.append(descriptor)
                if not trust.directory(os.fstat(descriptor)):
                    raise PermissionError("untrusted_directory")
            if descriptor == root_descriptor:
                descriptor = os.dup(root_descriptor)
                opened.append(descriptor)
            names = sorted(os.listdir(descriptor))[:_MAX_LISTED_ENTRIES]
            children: list[bytes] = []
            for name in names:
                if name.startswith("."):
                    continue
                try:
                    encoded = name.encode("utf-8", errors="strict")
                    facts = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                except (UnicodeEncodeError, OSError):
                    continue
                relative = encoded if not current else current + b"/" + encoded
                if stat.S_ISREG(facts.st_mode) and not credential_named_bytes(relative):
                    found.append(relative)
                    if len(found) >= room:
                        break
                elif (
                    stat.S_ISDIR(facts.st_mode)
                    and depth + 1 < _MAX_LISTED_DEPTH
                    and trust.directory(facts)
                ):
                    children.append(relative)
            pending.extend((child, depth + 1) for child in children)
        except OSError:
            continue
        finally:
            for item in reversed(opened):
                os.close(item)
    return found


def _excluded_identities(paths: tuple[str, ...]) -> frozenset[tuple[int, int]] | None:
    """The device and inode of each existing directory in ``paths``; ``None`` if one is unknown.

    A path that does not exist excludes nothing. One that exists but cannot be examined (a
    permission error) leaves the exclusion unprovable, so the caller reads nothing.
    """

    identities: set[tuple[int, int]] = set()
    for path in paths:
        try:
            facts = os.stat(path)
        except (FileNotFoundError, NotADirectoryError):
            continue
        except (OSError, ValueError):
            return None
        identities.add((facts.st_dev, facts.st_ino))
    return frozenset(identities)


def read_outside_inputs(
    roots: tuple[str, ...],
    values: tuple[str, ...],
    *,
    limit: int = MAX_TASK_INPUT_FILES,
    excluded: tuple[str, ...] = (),
    space_cut: frozenset[str] = frozenset(),
) -> tuple[TaskInputFile, ...]:
    """Read the files ``values`` names beneath admitted ``roots`` (issue #1082), bounded.

    ``values`` are the task's candidate input paths in order: the statement and ``role: input``
    files, never paths only a verification command named (``review_input_paths``). Only an
    absolute path lexically beneath an admitted root counts. A value ending in ``/``, or one whose
    last component is a trusted directory reached without a link (issue #1102), names a
    directory: its visible files, two levels deep at most, are offered in name order. Each root
    must still be exactly the directory the owner admitted: it is opened one component at a time
    from ``/`` without following a link, every directory on the way must pass the trust test, and
    the opened directory must still be what the root path names. ``excluded`` are absolute
    directories never read from (the workspace, FinishUP's own directories): refused by their
    case-folded path and by device and inode at every level, so neither an enumeration nor a
    differently spelled path re-enters them. At most ``limit`` files and 16 candidates are read
    within five seconds; a file that fails any test is skipped silently. ``space_cut`` are the
    values only the spaces of a quoted spaced value cut out (``space_cut_input_paths``): when
    that value names something beneath a root, they are not read (``drop_space_cut_words``).
    Each input keeps the root it was read beneath (``TaskInputFile.root``, #1118 unit 1).
    """

    inputs: list[TaskInputFile] = []
    for root, full, ends in _outside_files(
        roots,
        values,
        limit=limit,
        excluded=excluded,
        space_cut=space_cut,
        head_limit=MAX_TASK_INPUT_READ_BYTES,
        seconds=_OUTSIDE_READ_SECONDS,
    ):
        if ends is None:
            continue
        head, tail, size = ends
        item = (
            task_input_from_bytes(full, head, origin="outside_workspace")
            if size <= MAX_TASK_INPUT_READ_BYTES
            else task_input_from_ends(full, head, tail, size, origin="outside_workspace")
        )
        if item is not None:
            inputs.append(replace(item, root=root))
            if len(inputs) >= limit:
                break
    return tuple(inputs)


@dataclass(frozen=True, slots=True)
class OutsideSnapshotRead:
    """One snapshot candidate the outside read reached (#1118 unit 1).

    ``text`` is the whole file when it is UTF-8 text of at most ``max_bytes``; otherwise
    ``None`` and ``reason`` is the closed code for why no full original was kept.
    """

    root: str
    path: str
    size: int
    text: bytes | None
    reason: Literal["too_large", "not_text", "unreadable"] | None


def snapshot_outside_inputs(
    roots: tuple[str, ...],
    values: tuple[str, ...],
    *,
    limit: int,
    max_bytes: int,
    seconds: float,
    excluded: tuple[str, ...] = (),
) -> tuple[OutsideSnapshotRead, ...]:
    """Whole-file reads of task-named outside inputs for a snapshot (#1118 unit 1), bounded.

    The same trusted walk as ``read_outside_inputs``: the same roots, exclusions and file
    tests, at most ``limit`` candidates within ``seconds``. A file is kept whole only when it is text
    of at most ``max_bytes``; a larger, binary or undecodable file is reported with its reason
    and no bytes, so no partial read is ever kept as an original.
    """

    reads: list[OutsideSnapshotRead] = []
    # ``limit`` bounds the candidates attempted, readable or not, directory members included:
    # the walk is lazy, so stopping here stops it before the next member is opened.
    for root, full, ends in _outside_files(
        roots,
        values,
        limit=limit,
        excluded=excluded,
        space_cut=frozenset(),
        head_limit=max_bytes,
        seconds=seconds,
    ):
        reads.append(_snapshot_row(root, full, ends, max_bytes))
        if len(reads) >= limit:
            break
    return tuple(reads)


def _snapshot_row(
    root: str, full: str, ends: tuple[bytes, bytes, int] | None, max_bytes: int
) -> OutsideSnapshotRead:
    if ends is None:
        return OutsideSnapshotRead(root, full, 0, None, "unreadable")
    head, _tail, size = ends
    if size > max_bytes:
        return OutsideSnapshotRead(root, full, size, None, "too_large")
    try:
        head.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return OutsideSnapshotRead(root, full, size, None, "not_text")
    if _binary(head):
        return OutsideSnapshotRead(root, full, size, None, "not_text")
    return OutsideSnapshotRead(root, full, size, head, None)


def _outside_files(
    roots: tuple[str, ...],
    values: tuple[str, ...],
    *,
    limit: int,
    excluded: tuple[str, ...],
    space_cut: frozenset[str],
    head_limit: int,
    seconds: float,
) -> Iterator[tuple[str, str, tuple[bytes, bytes, int] | None]]:
    """``(root, path, ends)`` per file the trusted outside walk reaches; ``ends`` ``None`` when
    the file failed a test. At most ``limit`` files and 16 candidates, within ``seconds``."""

    usable = tuple(root for root in roots if admitted_input_root_valid(root))
    if not usable or not values or limit < 1:
        return
    identities = _excluded_identities(excluded)
    if identities is None:
        return
    folded = tuple(posixpath.normpath(path).casefold() for path in excluded if path.startswith("/"))
    deadline = time.monotonic() + seconds
    owners = frozenset({0, os.geteuid() if hasattr(os, "geteuid") else os.getuid()})
    trust = _Trust(owners, identities)
    descriptors: dict[str, int | None] = {}
    seen: set[str] = set()
    yielded = 0

    def located_open(value: str) -> tuple[str, bytes, int] | None:
        if _folded_inside(value, folded):
            return None
        located = _beneath(value, usable)
        if located is None:
            return None
        root, relative = located
        if root not in descriptors:
            descriptors[root] = None if _folded_inside(root, folded) else _open_root(root, trust)
        descriptor = descriptors[root]
        return None if descriptor is None else (root, relative, descriptor)

    def names_something(value: str) -> bool:
        opened = located_open(value)
        if opened is None or not opened[1]:
            return False
        entry = _entry_beneath(opened[2], opened[1], trust)
        return entry is not None and (stat.S_ISREG(entry.st_mode) or trust.directory(entry))

    try:
        # Issue #1102: a spaced value that names something beneath a root keeps its own words
        # out (``drop_space_cut_words``): ``/shared/legacy`` is never read for ``legacy app``.
        candidates = values[:_MAX_OUTSIDE_CANDIDATES]
        for value in drop_space_cut_words(candidates, names_something, space_cut):
            if yielded >= limit or time.monotonic() > deadline:
                break
            opened = located_open(value)
            if opened is None:
                continue
            root, relative, descriptor = opened
            # Issue #1102 (RC6d): a directory named without its trailing ``/`` ("the legacy app
            # in /shared/legacy_app") is listed like one named with it.
            files = (
                _listed_files(descriptor, relative, limit - yielded, trust)
                if value.endswith("/")
                or not relative
                or _is_directory_beneath(descriptor, relative, trust)
                else [relative]
            )
            for file in files:
                if yielded >= limit or time.monotonic() > deadline:
                    break
                full = posixpath.join(root, file.decode("utf-8"))
                if full in seen or _folded_inside(full, folded):
                    continue
                seen.add(full)
                ends = _read_ends(
                    descriptor,
                    file,
                    owners=owners,
                    head_limit=head_limit,
                    trust=trust,
                    recorded=full,
                )
                if ends is not None:
                    yielded += 1
                yield root, full, ends
    finally:
        for descriptor in descriptors.values():
            if descriptor is not None:
                os.close(descriptor)


class ReadDeadline(Exception):
    """A reviewer read ran past its local time budget (#1118); nothing it read is returned."""


clear_cut: Final = _cut_clear  # the reviewer broker's credential-safe cut (#1118)


def _reviewer_open(
    root: str, relative: str, excluded: tuple[str, ...]
) -> tuple[int, bytes, _Trust] | None:
    """The open root, checked path and trust of one reviewer read: the outside read's walk."""

    identities = _excluded_identities(excluded)
    folded = tuple(posixpath.normpath(path).casefold() for path in excluded if path.startswith("/"))
    full = posixpath.join(root, relative) if relative else root
    located = _beneath(full, (root,))
    if identities is None or located is None or _folded_inside(full, folded):
        return None
    owners = frozenset({0, os.geteuid() if hasattr(os, "geteuid") else os.getuid()})
    trust = _Trust(owners, identities)
    descriptor = _open_root(root, trust)
    return None if descriptor is None else (descriptor, located[1], trust)


def read_text_beneath(
    root: str, relative: str, *, excluded: tuple[str, ...], expired: Callable[[], bool]
) -> tuple[bytes, int] | None:
    """One trusted file and its size; withhold all bytes above 1 MiB.

    A physical head cut cannot prove that a credential crossing it remains recognizable. Return
    only the original size in that case, so the broker can disclose the limit without a fragment.
    """

    opened = _reviewer_open(root, relative, excluded)
    if opened is None:
        return None
    descriptor, path, trust = opened
    try:
        ends = _read_ends(
            descriptor,
            path,
            owners=trust.owners,
            head_limit=MAX_TASK_INPUT_READ_BYTES,
            trust=trust,
            expired=expired,
        )
    finally:
        os.close(descriptor)
    if ends is None:
        return None
    return (b"" if ends[2] > len(ends[0]) else ends[0], ends[2])


def _beneath_system_directory(path: str) -> bool:
    """Whether an ancestor of ``path`` is a system directory by device and inode (#1220 review).

    Ancestors are examined without following a link (a read never follows one beneath its root);
    the system directories are taken both as named and as their link targets. An ancestor that
    cannot be examined, other than one that does not exist, refuses the path.
    """

    refused: set[tuple[int, int]] = set()
    for prefix in SYSTEM_DIRECTORY_PREFIXES:
        for probe in (os.lstat, os.stat):
            try:
                facts = probe(prefix)
            except OSError:
                continue
            refused.add((facts.st_dev, facts.st_ino))
    parts = path.strip("/").split("/")
    current = ""
    for part in parts[:-1]:
        current += "/" + part
        try:
            facts = os.lstat(current)
        except FileNotFoundError:
            return False
        except OSError:
            return True
        if (facts.st_dev, facts.st_ino) in refused:
            return True
    return False


def read_declared_test(
    location: str, *, excluded: tuple[str, ...], expired: Callable[[], bool] = lambda: False
) -> bytes | None:
    """The bytes of one agent-declared test file (issue #1220), or ``None``; never raises.

    ``location`` is the absolute, normalized path ``kernel.declared_tests`` admitted by shape.
    The read is the outside read's walk with ``/`` plus the first component as its root: every
    directory on the way and the file pass the same trust test, hidden and credential-named
    components are refused, ``excluded`` (FinishUP's own directories) is never entered, and a
    file that changes while it is read is not returned. A first component that is a link root
    owns (``/tmp`` or ``/var`` on macOS) is replaced by its target first; no other link is
    followed. Beneath the home directory its private trees and files are refused too. Only UTF-8
    text of at most 1 MiB with no NUL byte is returned.
    """

    if (
        not location.startswith("/")
        or posixpath.normpath(location) != location
        or system_directory_path(location)
    ):
        return None
    first, _, rest = location[1:].partition("/")
    if not first or not rest:
        return None
    top = "/" + first
    try:
        facts = os.lstat(top)
        if stat.S_ISLNK(facts.st_mode):
            target = os.path.realpath(top)
            if facts.st_uid != 0 or target.count("/") > 2 or not os.path.isdir(target):
                return None
            top = target
    except OSError:
        return None
    resolved = f"{top}/{rest}"
    # By spelling (case-folded too) and by identity (#1220 review): on a case-insensitive volume
    # ``/ETC`` or ``/Users/ALICE/Library`` names the same directory as the refused spelling.
    if (
        system_directory_path(resolved)
        or system_directory_path(location.casefold())
        or system_directory_path(resolved.casefold())
        or _beneath_system_directory(resolved)
        or home_private_location(resolved)
    ):
        return None
    try:
        read = read_text_beneath(top, rest, excluded=excluded, expired=expired)
    except ReadDeadline:
        return None
    if read is None:
        return None
    data, size = read
    if not data or size != len(data) or b"\0" in data:
        return None
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return data


def list_beneath(
    root: str,
    relative: str,
    *,
    excluded: tuple[str, ...],
    expired: Callable[[], bool],
    inspect: int = 128,
) -> tuple[tuple[tuple[str, bool], ...], bool] | None:
    """Visible trusted children and whether native entries remain beyond ``inspect``.

    Hidden and refused entries spend the inspection budget too. One lookahead establishes
    exhaustion without inspecting or returning that entry; this is a sample, not a full listing.
    """

    opened_root = _reviewer_open(root, relative, excluded)
    if opened_root is None:
        return None
    descriptor, path, trust = opened_root
    opened = [descriptor]
    try:
        current = descriptor
        for part in [part for part in path.split(b"/") if part]:
            current = os.open(part, _DIRECTORY_FLAGS, dir_fd=current)
            opened.append(current)
            if not trust.directory(os.fstat(current)):
                return None
        entries: list[tuple[str, bool]] = []
        with os.scandir(current) as found:
            for entry in islice(found, inspect):
                if expired():
                    raise ReadDeadline("reviewer_read_deadline")
                try:
                    encoded = entry.name.encode("utf-8", errors="strict")
                    hidden = (
                        entry.name.startswith(".")
                        or credential_named_bytes(encoded)
                        or home_private_path(Path(root), path + b"/" + encoded if path else encoded)
                    )
                    facts = entry.stat(follow_symlinks=False)
                except (UnicodeEncodeError, OSError):
                    continue
                if not hidden and (trust.file(facts) or trust.directory(facts)):
                    entries.append((entry.name, stat.S_ISDIR(facts.st_mode)))
            if expired():
                raise ReadDeadline("reviewer_read_deadline")
            truncated = next(found, None) is not None
        return tuple(sorted(entries)), truncated
    except OSError:
        return None
    finally:
        for item in reversed(opened):
            os.close(item)


def _is_directory_beneath(root_descriptor: int, path: bytes, trust: _Trust) -> bool:
    """Whether ``path`` beneath the open root is a trusted directory, reached without a link."""

    entry = _entry_beneath(root_descriptor, path, trust)
    return entry is not None and trust.directory(entry)


def _entry_beneath(root_descriptor: int, path: bytes, trust: _Trust) -> os.stat_result | None:
    """The metadata of ``path`` beneath the open root, reached without a link; never content.

    Each parent component is opened from the root descriptor without following a link and must
    pass ``trust``; the last is examined without following a link, so a link is never what it
    points to. ``None`` on any error; what was opened is closed.
    """

    parts = path.split(b"/")
    if not path or any(part in {b"", b".", b".."} for part in parts):
        return None
    opened: list[int] = []
    current = root_descriptor
    try:
        for part in parts[:-1]:
            current = os.open(part, _DIRECTORY_FLAGS, dir_fd=current)
            opened.append(current)
            if not trust.directory(os.fstat(current)):
                return None
        return os.stat(parts[-1], dir_fd=current, follow_symlinks=False)
    except OSError:
        return None
    finally:
        for descriptor in reversed(opened):
            os.close(descriptor)


def _open_root(root: str, trust: _Trust) -> int | None:
    """An open descriptor of the admitted directory ``root``, reached without any link (R1-03).

    The walk starts at ``/`` and opens each component from the previous descriptor without
    following a link, so no ancestor can be swapped for a link between a check and the open: a
    component that is a link fails to open, and a directory already opened stays the one checked.
    Every directory on the way, ``/`` and the root included, must pass ``trust`` (an owner's,
    writable by no other account unless sticky, not excluded). Last, the path must still name the
    opened directory (same device and inode); a root renamed or replaced meanwhile admits nothing.
    """

    try:
        if os.path.realpath(root) != root:
            return None
        current = os.open("/", _DIRECTORY_FLAGS)
    except OSError:
        return None
    try:
        if not trust.directory(os.fstat(current)):
            raise PermissionError("untrusted_directory")
        for part in root.strip("/").split("/"):
            following = os.open(part, _DIRECTORY_FLAGS, dir_fd=current)
            os.close(current)
            current = following
            if not trust.directory(os.fstat(current)):
                raise PermissionError("untrusted_directory")
        named = os.stat(root, follow_symlinks=False)
        opened = os.fstat(current)
        if (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino):
            raise PermissionError("root_replaced")
    except OSError:
        os.close(current)
        return None
    return current
