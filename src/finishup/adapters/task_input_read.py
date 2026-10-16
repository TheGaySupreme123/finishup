"""Read-only task input files: bounded text or FinishUP's own summary (issues #1045 and #1082).

A task input is a file the task names that the reviewer needs beside the change: a
specification, a dataset, the source to port, a test the verification runs. This module turns the
bytes the service read into one bounded ``TaskInputFile``:

- text stays text, whole or as head and tail with the cut marked;
- a binary file, an image or a large data file becomes FinishUP's own bounded summary
  (``finishup.adapters.input_summary``), never its bytes;
- a file larger than the whole-read bound is summarized from its two ends, read without following
  a link.

It also holds the one outside-workspace read path: files the task names beneath a directory the
owner admitted in the repository's privacy grant (``PrivacyPolicy.admitted_input_roots``). That
reader opens the admitted root once, then walks one component at a time without following a link,
refuses hidden components and credential-named files, and reads only singly linked regular files
owned by the service user or by root that no other user may write. Nothing here decides whether
the content may leave: the review recipe, the redaction pass and the egress gate still do.
"""

from __future__ import annotations

import os
import posixpath
import stat
import time
from typing import Final

from finishup.adapters.input_summary import summarize_binary_input
from finishup.domain.privacy import admitted_input_root_valid
from finishup.domain.repository_excerpt import credential_named_bytes
from finishup.ports.change_capture import (
    MAX_TASK_INPUT_FILES,
    MAX_TASK_INPUT_TEXT_BYTES,
    TaskInputFile,
    TaskInputOrigin,
)

__all__ = [
    "MAX_TASK_INPUT_READ_BYTES",
    "read_ends_beneath",
    "read_outside_inputs",
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


def _decode(text: bytes) -> str:
    return text.decode("utf-8", errors="replace")


def _binary(content: bytes) -> bool:
    return b"\0" in content[:_BINARY_PROBE_BYTES]


def _summary(name: str, content: bytes, size: int, origin: TaskInputOrigin) -> TaskInputFile | None:
    text = summarize_binary_input(name, content, size).encode("utf-8")
    text = text[:MAX_TASK_INPUT_TEXT_BYTES].decode("utf-8", errors="ignore").encode("utf-8")
    try:
        return TaskInputFile(name, text, size, origin=origin, summary=True)
    except ValueError:
        return None


def _head_tail(head: bytes, tail: bytes, total: int) -> bytes:
    """Head and tail of a ``total``-byte text within ``MAX_TASK_INPUT_TEXT_BYTES``, cut marked."""

    marker = _ELISION.format(elided="0" * len(str(total)), total=total)
    side = (MAX_TASK_INPUT_TEXT_BYTES - len(marker.encode("utf-8"))) // 2
    first = head[:side].decode("utf-8", errors="ignore")
    last = tail[-side:].decode("utf-8", errors="ignore")
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
    ``head_limit`` bytes from its start and, when it is larger, its last 8 KiB. A file that
    changes while it is read is not returned.
    """

    parts = path.split(b"/")
    if not path or any(part in {b"", b".", b".."} for part in parts):
        return None
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    file_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    opened: list[int] = []
    current = root_descriptor
    try:
        for part in parts[:-1]:
            current = os.open(part, directory_flags, dir_fd=current)
            opened.append(current)
        descriptor = os.open(parts[-1], file_flags, dir_fd=current)
        opened.append(descriptor)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid not in owners
            or before.st_mode & stat.S_IWOTH
        ):
            return None
        size = before.st_size
        chunks: list[bytes] = []
        read = 0
        while read < min(size, head_limit):
            chunk = os.read(descriptor, min(_READ_CHUNK, head_limit - read))
            if not chunk:
                break
            chunks.append(chunk)
            read += len(chunk)
        head = b"".join(chunks)
        tail = b""
        if size > head_limit:
            tail = os.pread(descriptor, _TAIL_BYTES, max(0, size - _TAIL_BYTES))
        after = os.fstat(descriptor)
        if (before.st_size, before.st_mtime_ns, before.st_ino) != (
            after.st_size,
            after.st_mtime_ns,
            after.st_ino,
        ) or read != min(size, head_limit):
            return None
        return head, tail, size
    except OSError:
        # A link on the way (ELOOP/ENOTDIR), a missing or unreadable file: nothing is read.
        return None
    finally:
        for descriptor in reversed(opened):
            os.close(descriptor)


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
            if credential_named_bytes(encoded):
                return None
            return root, encoded
    return None


# A directory the task names beneath an admitted root offers its files, two levels deep at most,
# in name order, until the input bound is reached. Listing reads names only; each file is then
# read like a named one.
_MAX_LISTED_DEPTH: Final = 2
_MAX_LISTED_ENTRIES: Final = 256


def _listed_files(root_descriptor: int, directory: bytes, room: int) -> list[bytes]:
    """Up to ``room`` regular, visible, not credential-named files beneath ``directory``."""

    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    found: list[bytes] = []
    pending: list[tuple[bytes, int]] = [(directory, 0)]
    while pending and len(found) < room:
        current, depth = pending.pop(0)
        opened: list[int] = []
        try:
            descriptor = root_descriptor
            for part in [part for part in current.split(b"/") if part]:
                descriptor = os.open(part, directory_flags, dir_fd=descriptor)
                opened.append(descriptor)
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
                except UnicodeEncodeError, OSError:
                    continue
                relative = encoded if not current else current + b"/" + encoded
                if stat.S_ISREG(facts.st_mode) and not credential_named_bytes(relative):
                    found.append(relative)
                    if len(found) >= room:
                        break
                elif stat.S_ISDIR(facts.st_mode) and depth + 1 < _MAX_LISTED_DEPTH:
                    children.append(relative)
            pending.extend((child, depth + 1) for child in children)
        except OSError:
            continue
        finally:
            for item in reversed(opened):
                os.close(item)
    return found


def read_outside_inputs(
    roots: tuple[str, ...], values: tuple[str, ...], *, limit: int = MAX_TASK_INPUT_FILES
) -> tuple[TaskInputFile, ...]:
    """Read the files ``values`` names beneath admitted ``roots`` (issue #1082), bounded.

    ``values`` are the task's candidate input paths in order (``review_input_paths``); only an
    absolute path lexically beneath an admitted root counts. A value ending in ``/`` names a
    directory: its visible files, two levels deep at most, are offered in name order. Each root must still be exactly the
    directory the owner admitted: it is opened without following a link, and a root that is now
    a link or no longer a directory admits nothing. At most ``limit`` files and 16 candidates are
    read within five seconds; a file that fails any test is skipped silently.
    """

    usable = tuple(root for root in roots if admitted_input_root_valid(root))
    if not usable or not values or limit < 1:
        return ()
    deadline = time.monotonic() + _OUTSIDE_READ_SECONDS
    owners = frozenset({0, os.geteuid() if hasattr(os, "geteuid") else os.getuid()})
    descriptors: dict[str, int | None] = {}
    inputs: list[TaskInputFile] = []
    seen: set[str] = set()
    try:
        for value in values[:_MAX_OUTSIDE_CANDIDATES]:
            if len(inputs) >= limit or time.monotonic() > deadline:
                break
            located = _beneath(value, usable)
            if located is None:
                continue
            root, relative = located
            if root not in descriptors:
                descriptors[root] = _open_root(root)
            descriptor = descriptors[root]
            if descriptor is None:
                continue
            files = (
                _listed_files(descriptor, relative, limit - len(inputs))
                if value.endswith("/") or not relative
                else [relative]
            )
            for file in files:
                if len(inputs) >= limit or time.monotonic() > deadline:
                    break
                full = posixpath.join(root, file.decode("utf-8"))
                if full in seen:
                    continue
                seen.add(full)
                ends = read_ends_beneath(descriptor, file, owners=owners)
                if ends is None:
                    continue
                head, tail, size = ends
                item = (
                    task_input_from_bytes(full, head, origin="outside_workspace")
                    if size <= MAX_TASK_INPUT_READ_BYTES
                    else task_input_from_ends(full, head, tail, size, origin="outside_workspace")
                )
                if item is not None:
                    inputs.append(item)
    finally:
        for descriptor in descriptors.values():
            if descriptor is not None:
                os.close(descriptor)
    return tuple(inputs)


def _open_root(root: str) -> int | None:
    """An open descriptor of the admitted directory ``root``, reached without any link."""

    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        if os.path.realpath(root) != root:
            return None
        descriptor = os.open(root, flags)
    except OSError:
        return None
    facts = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(facts.st_mode)
        or facts.st_mode & stat.S_IWOTH
        and not (facts.st_mode & stat.S_ISVTX)
    ):
        # A world-writable directory without the sticky bit lets anyone swap a file in.
        os.close(descriptor)
        return None
    return descriptor
