"""Bounded, read-only check-time change capture from one validated Git workspace (ADR-031).

The service calls this adapter with the repository root its own authenticated control connection
supplied. Every Git call goes through the hardened runner of ``git_subject_state`` (no shell, no
global or system config, no hooks, fsmonitor, external diff, textconv or credential helper), with
Git transports disabled so a partial clone cannot fetch. Before and after every Git call the root
path must still name the directory that was validated, and its ``.git`` the validated one, so a
directory swapped in at the same path is never read. Untracked files are opened one path
component at a time relative to the validated root descriptor without following symlinks. A
tracked file whose working copy is a link, a special file or multiply linked is never shown, and
every Git object a shown diff reads must hash to its own name through an object store that holds
no link, so neither a link nor a hard link can make the capture read outside the workspace.

The capture is one coherent state: after assembling it, the adapter re-reads the file list, the
identity of every file it read, the untracked listing, HEAD and the index, and takes the whole
capture again (a bounded number of times) when anything moved; a tree that never holds still is
unavailable as ``changed_during_capture``.

The result is plain text: a short header naming the base, the file counts and every changed file,
then a unified diff. It is bounded to ``MAX_CHECK_CHANGE_TEXT_BYTES``. When the change is larger,
whole files are left out rather than cut mid-hunk, and the header names each file not shown.
"""

from __future__ import annotations

import errno
import hashlib
import os
import re
import shutil
import stat
import subprocess
import time
import zlib
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Final, Literal

from yoetz.adapters.git_rev_parse import absolute_rev_parse_path
from yoetz.adapters.git_subject_state import (
    GitOutputTruncated,
    discover_workspace_root,
    local_workspace_root,
    open_local_workspace,
    run_read_only_git,
)
from yoetz.adapters.git_version import GIT_VERSION_UNSUPPORTED, git_version, git_version_supported
from yoetz.observability.logging import record_unexpected_exception_without_raising
from yoetz.ports.change_capture import (
    MAX_BASELINE_UNTRACKED_FILES,
    MAX_CHECK_CHANGE_TEXT_BYTES,
    MAX_NESTED_REPOSITORIES,
    MAX_PROBED_FILE_SIZE,
    MAX_TASK_INPUT_FILES,
    MAX_TASK_INPUT_TEXT_BYTES,
    ChangeBaseKind,
    ChangeCaptureUnavailable,
    ChangeLineCount,
    ChangeLineCounts,
    ChangeMetadataEntry,
    CheckChangeCapture,
    CheckChangeMetadata,
    NestedUntrackedBaseline,
    RequestedPathProbe,
    TaskChangeBase,
    TaskInputFile,
    UntrackedBaselineFile,
    metadata_path_representable,
)
from yoetz.ports.subject_state import LocalWorkspaceHandle

__all__ = ["GitChangeCaptureAdapter"]

_EMPTY_TREES: Final = {
    "sha1": "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
    "sha256": "6ef19b41225c5369f1c104d45d8d85efa9b057b53b14b4b9b939dd74decc5321",
}
_CAPTURE_DEADLINE_SECONDS: Final = 20.0
_GIT_CALL_SECONDS: Final = 10.0
_GLOBAL_CONFIG_SECONDS: Final = 5.0
_LIST_LIMIT: Final = 8 * 1024 * 1024
_WHOLE_DIFF_LIMIT: Final = 8 * 1024 * 1024
_PER_FILE_DIFF_LIMIT: Final = 1024 * 1024
_MAX_PER_FILE_DIFFS: Final = 400
_MAX_UNTRACKED_FILES: Final = 500
_BINARY_PROBE_BYTES: Final = 8_000
_HEADER_BUDGET: Final = 24_576
# An untracked file is read up to the largest body the capture can carry at all (issue #983): a
# single new source file of a few hundred KiB is the deliverable, so naming it only would hide it
# from review. A larger file, or one the remaining body room cannot hold, is still left out whole.
_MAX_UNTRACKED_FILE_BYTES: Final = MAX_CHECK_CHANGE_TEXT_BYTES - _HEADER_BUDGET
_MAX_LISTED_FILES: Final = 100
_MAX_LISTED_PATH_BYTES: Final = 200
# Room kept for the header lines written after the file listing.
_HEADER_TRAILER_ROOM: Final = 512
_READ_CHUNK: Final = 65_536
# A capture whose working tree moved while it was read is taken again at most this many times.
_CAPTURE_ATTEMPTS: Final = 3
# The share of the deadline assembly may use; the rest is kept for the closing stability check.
_ASSEMBLY_SHARE: Final = 0.75
# Every Git object a shown diff reads is re-hashed; these bound that read.
_MAX_VERIFIED_OBJECT_BYTES: Final = 8 * 1024 * 1024
_MAX_TOTAL_VERIFIED_OBJECT_BYTES: Final = 64 * 1024 * 1024
_MAX_PACK_DIRECTORY_ENTRIES: Final = 4_096
_BLOB_MODES: Final = frozenset({"100644", "100755", "120000"})
# Transports are disabled outright: diffing a partial clone must fail, never fetch a blob.
# Replace refs are ignored so every object is read under its own name, which is what is verified.
# ``diff.relative=false`` overrides a repository's own ``diff.relative`` so every path stays
# root-relative. ``--no-relative`` said the same, but only Git 2.28 and later know it and an older
# Git refused every diff with it; there the setting does not exist and the key is inert.
_CAPTURE_CONFIG: Final = (
    "--no-replace-objects",
    "-c",
    "core.quotePath=true",
    "-c",
    "diff.relative=false",
    "-c",
    "protocol.allow=never",
)
_DIFF_OPTIONS: Final = (
    "--no-color",
    "--no-ext-diff",
    "--no-textconv",
    "--no-renames",
    "--submodule=short",
    "-O/dev/null",
    "--src-prefix=a/",
    "--dst-prefix=b/",
)
# ``--unified`` implies a patch, so it is added only where the patch itself is read.
_PATCH_OPTIONS: Final = (*_DIFF_OPTIONS, "--unified=3")
# ``git config --show-origin -z`` names a ``-c`` value's origin exactly so (Git 2.8 and later).
_COMMAND_LINE_ORIGIN: Final = b"command line:"
_DIFF_SECTION: Final = b"diff --git "
# Files with these names hold local credentials far more often than code, and the pattern scanner
# cannot recognise every provider's key format (``DB_PASS=...``, ``rk_live_...``). Tracked or
# untracked, they are listed by name only and their content is never shown (ADR-031). The list is a
# name heuristic: it catches common conventions, not every file that holds a secret.
_CREDENTIAL_NAMES: Final = frozenset(
    {
        b".env",
        b".envrc",
        b".git-credentials",
        b".htpasswd",
        b".netrc",
        b"_netrc",
        b".npmrc",
        b".pgpass",
        b".pypirc",
        b"credentials",
        b"credentials.json",
        b"id_dsa",
        b"id_ecdsa",
        b"id_ed25519",
        b"id_rsa",
    }
)
_CREDENTIAL_PREFIXES: Final = (b".env.",)
_CREDENTIAL_SUFFIXES: Final = (
    b".jks",
    b".kdbx",
    b".key",
    b".keystore",
    b".p12",
    b".pem",
    b".pfx",
    b".tfstate",
    b".tfvars",
)


def _credential_name(path: bytes) -> bool:
    name = path.rsplit(b"/", 1)[-1].lower()
    return (
        name in _CREDENTIAL_NAMES
        or name.startswith(_CREDENTIAL_PREFIXES)
        or name.endswith(_CREDENTIAL_SUFFIXES)
    )


type _OmitReason = Literal[
    "capture_limit",
    "too_large",
    "not_regular_file",
    "unreadable",
    "credential_name",
    "object_unverified",
    "nested_repository",
    "nested_untracked",
]
_OMIT_TEXT: Final[dict[_OmitReason, str]] = {
    "credential_name": "not shown: listed by name only, as for every file named like this",
    "capture_limit": "not shown: the capture reached its size, time or file limit",
    "too_large": "not shown: too large for this capture",
    "not_regular_file": "not shown: links, special files and multiply linked files are never read",
    "unreadable": "not shown: could not be read safely",
    "object_unverified": "not shown: a Git object its diff needs could not be verified",
    "nested_repository": "not shown: a nested Git repository whose own change was not read",
    "nested_untracked": (
        "not shown: untracked inside a nested repository whose untracked files the task-start "
        "record does not fully list, so it may predate the task"
    ),
}
# Omitted for what the file is, not its size: its line counts are not shown either.
_WITHHELD_COUNTS: Final[frozenset[_OmitReason]] = frozenset(
    {
        "not_regular_file",
        "unreadable",
        "object_unverified",
        "nested_repository",
        "nested_untracked",
    }
)
# The ``stat`` fields that say an untracked file is still the one the task started with (issue
# #1045): type and permission bits, inode, size, modification and change time. The change time
# moves on every content or metadata write and cannot be set back, so a file rewritten with its old
# modification time restored is still seen as changed. Device and link count are left out: a
# remount or a second name does not change the file's bytes.
_BASELINE_FIELDS: Final = (0, 2, 3, 4, 5)
# (mode, device, inode, size, mtime ns, ctime ns, link count, owner) of one path, never followed.
type _Identity = tuple[int, int, int, int, int, int, int, int]
# A path reachable only through a link or a non-directory component.
_BLOCKED: Final[_Identity] = (0, 0, 0, 0, 0, 0, 0, 0)


class _ChangedDuringCapture(Exception):
    """The working tree moved while one capture attempt read it."""


@dataclass(frozen=True, slots=True)
class _Workspace:
    """A validated workspace and the identity its root and ``.git`` had when validated."""

    handle: LocalWorkspaceHandle
    root: Path
    descriptor: int
    root_identity: tuple[int, int]
    git_identity: tuple[int, int]


@dataclass(frozen=True, slots=True)
class _RawEntry:
    status: str
    path: bytes
    src_mode: str
    dst_mode: str
    src_oid: str
    dst_oid: str


@dataclass(slots=True)
class _TrackedRead:
    raw: bytes
    sections: list[_Section]
    # Working copies and loose objects (with their fan-out directories), keyed by root-relative
    # path, taken before Git read any content and compared again after the whole capture.
    identities: dict[bytes, _Identity | None]
    # Metadata capture uses a name-status query; content capture keeps the raw query.
    arguments: tuple[str, ...] = ()
    # Changed gitlinks (submodules and embedded repositories Git tracks): path and the commit the
    # base tree records for it, ``None`` when the base held no gitlink there.
    gitlinks: tuple[tuple[bytes, str | None], ...] = ()


@dataclass(slots=True)
class _UntrackedRead:
    total: int
    sections: list[_Section]
    listing_truncated: bool
    listing: bytes | None
    config: tuple[str, ...]
    identities: dict[bytes, _Identity | None]
    # Untracked files that predate the task (issue #1045): those unchanged since are left out
    # (``kept``; their identities only join the stability check), the others changed since.
    kept: frozenset[bytes] = frozenset()
    preexisting: frozenset[bytes] = frozenset()
    # Embedded repositories the metadata read listed as their directory (issue #1045).
    directories: tuple[bytes, ...] = ()


@dataclass(slots=True)
class _Section:
    path: bytes
    status: str
    untracked: bool
    added: str
    deleted: str
    text: bytes | None
    omitted: _OmitReason | None
    # An untracked file that already existed when the task started and changed since (#1045).
    preexisting: bool = False


@dataclass(frozen=True, slots=True)
class _Baseline:
    """The task-start snapshot a capture applies (issue #1045); absent for any other base."""

    files: dict[bytes, str]
    complete: bool
    nested: dict[bytes, str]
    # Each nested repository's own untracked files at task start, relative to its directory;
    # ``None`` when its listing was incomplete. A repository absent here has no listing.
    nested_untracked: dict[bytes, dict[bytes, str] | None]


@dataclass(slots=True)
class _NestedRead:
    """One nested repository's own change, or why it could not be read (issue #1045)."""

    path: bytes
    base: ChangeBaseKind | None = None
    sections: list[_Section] | None = None
    tracked: int = 0
    untracked: int = 0
    unlisted_untracked: int = 0
    listing_truncated: bool = False
    reason: str | None = None
    # Its starting commit is the gitlink the outer base tree records, because the task-start
    # snapshot recorded no HEAD for it (a base recorded before the snapshot named gitlinked
    # repositories, or one it could not open): commits made in it before the task that the outer
    # repository does not record are part of its change, and the header says so.
    from_base_tree: bool = False
    # Why its untracked files are named only (no task-start listing of them, or an incomplete
    # one); ``None`` when the listing was complete and they are treated as at the outer level.
    untracked_unrecorded: Literal["absent", "incomplete"] | None = None
    # Its untracked files that the listing names with an unchanged digest: left out and counted.
    kept: int = 0


@dataclass(slots=True)
class _NestedMetadata:
    """One nested repository's metadata-only change (issue #1045); ``entries`` ``None``: unread."""

    path: bytes
    entries: list[ChangeMetadataEntry] | None = None
    tracked: int = 0
    untracked: int = 0
    omitted: int = 0
    unrepresentable: int = 0
    listing_truncated: bool = False


_BASELINE_DOMAIN: Final = b"yoetz/untracked-baseline/v1\x00"


def _baseline_state(identity: Sequence[int]) -> str:
    """The digest a task-start snapshot keeps for one untracked file's ``stat`` (issue #1045)."""

    fields = ",".join(str(identity[index]) for index in _BASELINE_FIELDS)
    return "sha256:" + hashlib.sha256(_BASELINE_DOMAIN + fields.encode("ascii")).hexdigest()


def _apply_baseline(
    pinned: _Workspace, paths: list[bytes], baseline: _Baseline | None
) -> tuple[list[bytes], dict[bytes, _Identity | None], set[bytes]]:
    """Split listed untracked paths by the task-start snapshot (issue #1045).

    Returns the paths still part of the change, the baseline paths left out (with the identity
    each still had, for the stability check), and the paths that predate the task but changed
    since. Without a snapshot every path stays and nothing is left out.
    """

    if baseline is None or not baseline.files:
        return list(paths), {}, set()
    remaining: list[bytes] = []
    kept: dict[bytes, _Identity | None] = {}
    preexisting: set[bytes] = set()
    for path in paths:
        recorded = baseline.files.get(path)
        if recorded is None:
            remaining.append(path)
            continue
        identity = _path_identity(pinned.descriptor, path)
        if identity is not None and identity != _BLOCKED and _baseline_state(identity) == recorded:
            kept[path] = identity
            continue
        preexisting.add(path)
        remaining.append(path)
    return remaining, kept, preexisting


def _baseline(base: TaskChangeBase | None) -> _Baseline | None:
    """The snapshot of a ``task_start`` base that recorded one; ``None`` otherwise."""

    if base is None or base.origin != "task_start":
        return None
    if not (base.untracked or base.untracked_complete or base.nested):
        return None
    return _Baseline(
        {os.fsencode(item.path): item.state for item in base.untracked},
        base.untracked_complete,
        {os.fsencode(path): commit for path, commit in base.nested},
        {
            os.fsencode(row.path): (
                {os.fsencode(item.path): item.state for item in row.files} if row.complete else None
            )
            for row in base.nested_untracked
        },
    )


def _nested_start_state(
    baseline: _Baseline | None, path: bytes, gitlink_commit: str | None
) -> tuple[str | None, bool, dict[bytes, str] | None, Literal["absent", "incomplete"] | None]:
    """Where one nested repository's change starts, and its task-start untracked listing (#1045).

    The HEAD the snapshot recorded comes first: the commit the outer base tree records for a
    gitlink (``gitlink_commit``) can be older than that HEAD, and every commit in between predates
    the task. Returns the starting commit (``None``: its HEAD now), whether it is the base tree's
    gitlink commit, the complete untracked listing (``None`` when there is none) and, without
    one, why: no listing was recorded, or it was incomplete.
    """

    recorded = None if baseline is None else baseline.nested.get(path)
    from_base_tree = recorded is None and gitlink_commit is not None
    if recorded is None:
        recorded = gitlink_commit
    if baseline is None or path not in baseline.nested_untracked:
        return recorded, from_base_tree, None, "absent"
    listing = baseline.nested_untracked[path]
    return recorded, from_base_tree, listing, None if listing is not None else "incomplete"


def _nested_base(
    object_format: Literal["sha1", "sha256"], recorded: str | None
) -> TaskChangeBase | None:
    if recorded is None or not recorded.strip("0"):
        return None
    try:
        return TaskChangeBase(object_format, recorded)
    except ValueError:
        return None


def _metadata_listing(
    tracked: Sequence[ChangeMetadataEntry],
    tracked_skipped: int,
    untracked: _UntrackedRead,
    *,
    prefix: bytes = b"",
    named_only: bool = False,
) -> tuple[list[ChangeMetadataEntry], int, int]:
    """One repository's metadata entries, unrepresentable count and omitted count.

    ``prefix`` is a nested repository's directory, carried by every path (issue #1045). With
    ``named_only`` its untracked files cannot be told apart from ones that predate the task, so
    none is an entry and each counts as omitted, as the full capture names them without showing
    them. A CR or LF in a name cannot be an entry: such a path is skipped and counted (#1019).
    """

    directory = os.fsdecode(prefix)
    entries: list[ChangeMetadataEntry] = []
    skipped = tracked_skipped
    for entry in tracked:
        if not prefix:
            entries.append(entry)
            continue
        name = directory + entry.path
        original = None if entry.original_path is None else directory + entry.original_path
        if not metadata_path_representable(name) or (
            original is not None and not metadata_path_representable(original)
        ):
            skipped += 1
            continue
        entries.append(replace(entry, path=name, original_path=original))
    if named_only:
        return entries, skipped, untracked.total + skipped
    # An untracked file that predates the task and changed since is a modification, not a new
    # file (issue #1045).
    paths = sorted(untracked.identities.keys() - untracked.kept, key=bytes)
    listed = [
        ChangeMetadataEntry("M", name)
        if path in untracked.preexisting
        else ChangeMetadataEntry("A", name, untracked=True)
        for path in paths
        if metadata_path_representable(name := os.fsdecode(prefix + path))
    ]
    unrepresentable = skipped + len(paths) - len(listed)
    return [*entries, *listed], unrepresentable, untracked.total - len(paths) + unrepresentable


def _patch_options(prefix: bytes) -> tuple[str, ...]:
    """Patch options whose ``a/``/``b/`` path prefixes also carry a nested repository's path."""

    if not prefix:
        return _PATCH_OPTIONS
    nested = os.fsdecode(prefix)
    return tuple(
        f"--src-prefix=a/{nested}"
        if option == "--src-prefix=a/"
        else f"--dst-prefix=b/{nested}"
        if option == "--dst-prefix=b/"
        else option
        for option in _PATCH_OPTIONS
    )


def _quote_path(path: bytes) -> str:
    """Quote one Git path the way ``core.quotePath=true`` does; ASCII-only output."""

    if not any(byte < 0x20 or byte >= 0x7F or byte in b'"\\' for byte in path):
        return path.decode("ascii")
    escapes = {7: "\\a", 8: "\\b", 9: "\\t", 10: "\\n", 11: "\\v", 12: "\\f", 13: "\\r"}
    rendered: list[str] = ['"']
    for byte in path:
        if byte in escapes:
            rendered.append(escapes[byte])
        elif byte in b'"\\':
            rendered.append("\\" + chr(byte))
        elif byte < 0x20 or byte >= 0x7F:
            rendered.append(f"\\{byte:03o}")
        else:
            rendered.append(chr(byte))
    rendered.append('"')
    return "".join(rendered)


def _prefixed(prefix: str, path: bytes) -> str:
    quoted = _quote_path(path)
    if quoted.startswith('"'):
        return '"' + prefix + quoted[1:]
    return prefix + quoted


def _nul_fields(payload: bytes) -> list[bytes]:
    if not payload:
        return []
    if not payload.endswith(b"\0"):
        raise ChangeCaptureUnavailable("git_failed")
    return payload[:-1].split(b"\0")


_MAX_REQUESTED_PATH_PROBES: Final = 64
# A requested directory "holds a file" when any non-directory entry lies beneath it (#1002). The
# walk is metadata only and bounded so a huge tree never stalls a check; past the bound the answer
# is unknown, which never reports the directory absent.
_MAX_DIRECTORY_WALK_ENTRIES: Final = 4_096
_MAX_DIRECTORY_WALK_OPEN: Final = 64
_ROOT_RELATIVE: Final = b"."
# The line-count read (ADR-035) opens each untracked file at most this large, and stops opening
# files once this many bytes were read in one call; what it skips makes the result a lower bound.
_MAX_LINE_COUNT_FILE_BYTES: Final = 8 * 1024 * 1024
_MAX_LINE_COUNT_TOTAL_BYTES: Final = 64 * 1024 * 1024
# The undeclared-reference read (tb4n2 R2, ADR-035 amendment) opens at most this many declared
# deliverables per check and reads at most this many bytes from the start of each; it compares
# one-line quoted string literals with at most this many created-file paths.
_MAX_REFERENCE_DELIVERABLES: Final = 16
_MAX_REFERENCE_FILE_BYTES: Final = 256 * 1024
_MAX_REFERENCE_CANDIDATES: Final = 1_024
# The (deliverable, referenced file) pairs one read returns (tb4n4, #1044).
_MAX_REFERENCE_PAIRS: Final = 64
# A basename shorter than this is too common (``a.py``, ``x``) to count as a reference by itself.
_MIN_REFERENCE_BASENAME: Final = 5
_SOURCE_SUFFIXES: Final = frozenset(
    {
        b".py",
        b".sh",
        b".bash",
        b".js",
        b".mjs",
        b".cjs",
        b".ts",
        b".rb",
        b".pl",
        b".r",
        b".R",
        b".jl",
        b".lua",
        b".php",
    }
)
_STRING_LITERAL: Final = re.compile(rb'"([^"\n]{1,1024})"|\'([^\'\n]{1,1024})\'|`([^`\n]{1,1024})`')


def _requested_relative_path(root: Path, value: str) -> bytes | None:
    """The root-relative form of one requested path, or ``None`` when it is not under the root.

    Lexical only: ``.``/``..`` segments are resolved textually and a result that leaves the root
    is outside. The root itself is ``.``. Links are never followed here; ``_path_identity``
    refuses them on the way down.
    """

    if type(value) is not str or not value or "\x00" in value:
        return None
    candidate = Path(value)
    if candidate.is_absolute():
        try:
            candidate = Path(os.path.normpath(candidate)).relative_to(root)
        except ValueError:
            return None
    normalized = os.path.normpath(os.fspath(candidate))
    encoded = os.fsencode(normalized)
    if encoded == _ROOT_RELATIVE:
        # The repository root itself (``/app`` for a checkout at ``/app``) is inside: it is the
        # whole workspace, not a path beyond it (tb4n1 E7).
        return _ROOT_RELATIVE
    if encoded == b"" or not _safe_relative(encoded) or encoded.startswith(b".git/"):
        return None
    return encoded


# A file whose rendered section is at most this large is ranked right after the declared
# deliverables (tb4n2 R7, P1-11): a 12-byte ``requirements.txt`` costs the packet almost nothing,
# so it is never clipped behind a large scratch file.
_SMALL_SECTION_BYTES: Final = 4_096


# How many untracked paths are stat-ed (metadata only) to rank small files ahead of the untracked
# file limit; paths past this bound keep path order after the ranked ones.
_MAX_UNTRACKED_ORDER_STATS: Final = 4_096
# The task-start snapshot's path bytes in all (issue #1045); the port enforces the same bound.
_MAX_BASELINE_PATH_BYTES: Final = 262_144


def _priority_paths(root: Path, values: tuple[str, ...]) -> tuple[bytes, ...]:
    """The root-relative forms of the declared deliverables under ``root``, in the given order.

    The caller lists ``role: output`` items before role-less ones and that order is kept: an
    earlier entry outranks a later one. Lexical, like ``_requested_relative_path``: nothing is
    opened or stat-ed. The root itself is dropped (a declared whole workspace orders nothing), as
    is any value outside the root; a duplicate keeps its first place.
    """

    if type(values) is not tuple:
        return ()
    located = (
        relative
        for value in values[:_MAX_REQUESTED_PATH_PROBES]
        if (relative := _requested_relative_path(root, value)) is not None
        and relative != _ROOT_RELATIVE
    )
    return tuple(dict.fromkeys(located))


def _priority_tier(path: bytes, priority: tuple[bytes, ...]) -> int | None:
    """The index of the first declared deliverable ``path`` is or lies under; else ``None``."""

    bare = path.rstrip(b"/")
    for index, item in enumerate(priority):
        if bare == item or bare.startswith(item + b"/"):
            return index
    return None


def _section_rank(section: _Section, priority: tuple[bytes, ...]) -> tuple[int, int, bytes]:
    """Order of a section in the rendered change: deliverables, small files, then the rest."""

    tier = _priority_tier(section.path, priority)
    if tier is not None:
        return (0, tier, section.path)
    if section.text is not None and len(section.text) <= _SMALL_SECTION_BYTES:
        return (1, 0, section.path)
    return (2, 0, section.path)


# A tracked file whose numstat line counts sum to at most this many is ranked as small before its
# diff text exists (the per-file read fallback, tb4n2 R7).
_SMALL_SECTION_LINES: Final = 64


def _tracked_read_rank(section: _Section, priority: tuple[bytes, ...]) -> tuple[int, int, bytes]:
    """Read order of a tracked file before its diff is loaded: deliverables, small, the rest."""

    tier = _priority_tier(section.path, priority)
    if tier is not None:
        return (0, tier, section.path)
    if (
        section.added.isdigit()
        and section.deleted.isdigit()
        and int(section.added) + int(section.deleted) <= _SMALL_SECTION_LINES
    ):
        return (1, 0, section.path)
    return (2, 0, section.path)


def _untracked_order(
    pinned: _Workspace, paths: list[bytes], priority: tuple[bytes, ...], deadline: float
) -> list[bytes]:
    """Untracked paths in read order: deliverables, then small files, then the rest (tb4n2 R7).

    The untracked file limit keeps the head of this order, so a 12-byte ``requirements.txt`` is
    never left unread behind hundreds of large scratch files. Sizes come from the link-free
    metadata walk of at most ``_MAX_UNTRACKED_ORDER_STATS`` paths (in path order) before the
    deadline; nothing is opened, and an unknown size ranks as large.
    """

    ordered = sorted(paths)
    sizes: dict[bytes, int] = {}
    for path in ordered[:_MAX_UNTRACKED_ORDER_STATS]:
        if _expired(deadline):
            break
        if path.endswith(b"/") or not _safe_relative(path) or _credential_name(path):
            continue
        identity = _path_identity(pinned.descriptor, path)
        if identity is not None and identity != _BLOCKED and stat.S_ISREG(identity[0]):
            sizes[path] = identity[3]

    def rank(path: bytes) -> tuple[int, int, bytes]:
        tier = _priority_tier(path, priority)
        if tier is not None:
            return (0, tier, path)
        size = sizes.get(path)
        return (1 if size is not None and size <= _SMALL_SECTION_BYTES else 2, 0, path)

    return sorted(ordered, key=rank)


def _nested_name(path: bytes) -> str | None:
    """A nested repository's directory as the task-start base can hold it, else ``None``."""

    try:
        name = path.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None
    return None if any(character in name for character in "\x00\r\n") else name


def _safe_relative(path: bytes) -> bool:
    return (
        bool(path)
        and not path.startswith(b"/")
        and all(part not in {b"", b".", b".."} for part in path.split(b"/"))
    )


def _decode(text: bytes) -> bytes:
    """Return valid UTF-8: undecodable bytes become U+FFFD, never raw bytes in the object."""

    return text.decode("utf-8", errors="replace").encode("utf-8")


def _section_path(section: bytes) -> bytes | None:
    """Return the destination path of one ``diff --git`` section.

    Git leaves ordinary spaces unquoted, so the header alone cannot be split at the last
    `` b/``: a path such as ``tests/foo b/test.js`` contains the same byte sequence. Prefer the
    exact ``+++``/``---`` operand and use an equal-operand header candidate for binary sections.
    """

    line = section.split(b"\n", 1)[0]
    rest = line[len(_DIFF_SECTION) :]

    def operand(token: bytes, prefix: bytes) -> bytes | None:
        if token == b"/dev/null":
            return None
        if token.startswith(prefix):
            return token[len(prefix) :]
        if not token.startswith(b'"') or not token.endswith(b'"'):
            return None
        raw = token[1:-1]
        out = bytearray()
        index = 0
        while index < len(raw):
            byte = raw[index]
            if byte != ord("\\"):
                out.append(byte)
                index += 1
                continue
            if index + 1 >= len(raw):
                return None
            following = raw[index + 1]
            escapes = {ord("a"): 7, ord("b"): 8, ord("t"): 9, ord("n"): 10}
            escapes.update({ord("v"): 11, ord("f"): 12, ord("r"): 13})
            if following in escapes:
                out.append(escapes[following])
                index += 2
            elif 0x30 <= following <= 0x37 and index + 3 < len(raw):
                out.append(int(raw[index + 1 : index + 4], 8) & 0xFF)
                index += 4
            else:
                out.append(following)
                index += 2
        if not out.startswith(prefix) or len(out) == len(prefix):
            return None
        return bytes(out[len(prefix) :])

    for diff_line in section.split(b"\n")[1:]:
        if diff_line.startswith(b"+++ "):
            token = diff_line[4:].split(b"\t", 1)[0]
            path = operand(token, b"b/")
            if path is not None:
                return path
        elif diff_line.startswith(b"--- "):
            token = diff_line[4:].split(b"\t", 1)[0]
            path = operand(token, b"a/")
            if path is not None and b"+++ /dev/null" in section:
                return path

    if rest.startswith(b'"'):
        tokens: list[bytes] = []
        index = 0
        while len(tokens) < 2 and index < len(rest):
            if rest[index] != ord('"'):
                return None
            start = index
            index += 1
            escaped = False
            while index < len(rest):
                byte = rest[index]
                index += 1
                if escaped:
                    escaped = False
                elif byte == ord("\\"):
                    escaped = True
                elif byte == ord('"'):
                    break
            else:
                return None
            tokens.append(rest[start:index])
            while index < len(rest) and rest[index] == ord(" "):
                index += 1
        if len(tokens) != 2:
            return None
        return operand(tokens[1], b"b/")
    # Unquoted: ``a/P b/Q``. Find a candidate whose decoded operands are equal, which distinguishes
    # the separator from `` b/`` inside an ordinary path.
    if not rest.startswith(b"a/"):
        return None
    candidates: list[tuple[bytes, bytes]] = []
    start = 0
    while True:
        separator = rest.find(b" b/", start)
        if separator < 0:
            break
        source, destination = rest[:separator], rest[separator + 1 :]
        if source.startswith(b"a/") and destination.startswith(b"b/"):
            source_path, destination_path = source[2:], destination[2:]
            if source_path == destination_path:
                candidates.append((source_path, destination_path))
        start = separator + 1
    return candidates[-1][1] if candidates else None


class GitChangeCaptureAdapter:
    """Read the task base and render one bounded check-time change for a local workspace."""

    def __init__(
        self,
        *,
        _deadline_seconds: float = _CAPTURE_DEADLINE_SECONDS,
        _max_text_bytes: int = MAX_CHECK_CHANGE_TEXT_BYTES,
    ) -> None:
        if not 0.0 < _deadline_seconds <= 120.0:
            raise ValueError("change_capture_deadline_invalid")
        if not _HEADER_BUDGET + 1_024 <= _max_text_bytes <= MAX_CHECK_CHANGE_TEXT_BYTES:
            raise ValueError("change_capture_limit_invalid")
        self._deadline_seconds = _deadline_seconds
        self._max_text_bytes = _max_text_bytes

    # --- public port -------------------------------------------------------------------------

    def read_task_base(self, workspace: str) -> TaskChangeBase:
        deadline = time.monotonic() + self._deadline_seconds
        pinned = self._open(workspace, deadline)
        object_format = self._object_format(pinned, deadline)
        head = self._rev(pinned, "HEAD^{commit}", deadline)
        # A repository with no commit yet starts from the empty tree, so every file the task adds
        # is still part of its change when HEAD later gains commits.
        commit = head or _EMPTY_TREES[object_format]
        try:
            untracked, complete, nested, listings = self._start_snapshot(pinned, deadline)
            return TaskChangeBase(
                object_format, commit, "task_start", untracked, complete, nested, listings
            )
        except ChangeCaptureUnavailable:
            # The commit is the base; a snapshot that cannot be taken only leaves every untracked
            # file to be shown as new, exactly as before the snapshot existed.
            return TaskChangeBase(object_format, commit)
        except ValueError as exc:
            # A snapshot the base object refuses is a defect, kept diagnosable; the task still
            # gets its commit base.
            record_unexpected_exception_without_raising(
                exc, component="start", operation="task_change_base_snapshot_dropped"
            )
            return TaskChangeBase(object_format, commit)

    def _start_snapshot(
        self, pinned: _Workspace, deadline: float
    ) -> tuple[
        tuple[UntrackedBaselineFile, ...],
        bool,
        tuple[tuple[str, str], ...],
        tuple[NestedUntrackedBaseline, ...],
    ]:
        """Untracked files and nested repository HEADs when the task starts (issue #1045).

        Metadata only: Git lists the untracked names (honouring the same ignore files as the
        capture) and each is ``stat``-ed beneath the validated root without following a link; no
        file is opened. A nested repository (listed as its directory, or a gitlink the index
        records whose directory holds its own ``.git`` directory) is opened with every fence the
        capture uses; its HEAD is read and its own untracked files are listed and ``stat``-ed the
        same way. Untracked repositories take the ``MAX_NESTED_REPOSITORIES`` places first, as a
        gitlink still has the commit the outer base tree records for it. Bounded: past
        ``MAX_BASELINE_UNTRACKED_FILES`` names (or 256 KiB of names) the outer snapshot is
        incomplete and a later untracked file it does not name is new; a nested repository's
        listing takes what the outer one left of the same bounds whole, in place order, or is
        recorded incomplete.
        """

        self._refuse_unsafe_config(pinned, deadline)
        excludes = self._repository_excludes_file(pinned, deadline)
        if excludes is None:
            excludes = _global_excludes_file(deadline)
        config = ("-c", f"core.excludesFile={excludes}") if excludes is not None else ()
        listing, truncated = self._untracked_listing(pinned, config, deadline)
        complete = not truncated
        files: list[UntrackedBaselineFile] = []
        directories: list[bytes] = []
        path_bytes = 0
        for path in sorted(_nul_fields(listing)):
            if not _safe_relative(path.rstrip(b"/")):
                raise ChangeCaptureUnavailable("unsafe_root")
            if path.endswith(b"/"):
                directories.append(path[:-1])
                continue
            if (
                len(files) >= MAX_BASELINE_UNTRACKED_FILES
                or path_bytes + len(path) > _MAX_BASELINE_PATH_BYTES
                or _expired(deadline)
            ):
                # Past a bound the snapshot no longer names every file, so it is incomplete.
                complete = False
                continue
            identity = _path_identity(pinned.descriptor, path)
            if identity is None:
                # Gone already: it cannot be a file this task started with.
                continue
            if identity == _BLOCKED:
                # Git never lists a path behind a link, so this is a failed or raced ``stat``: the
                # file may still be there, so the snapshot no longer names every file.
                complete = False
                continue
            try:
                item = UntrackedBaselineFile(
                    path.decode("utf-8", errors="strict"), _baseline_state(identity)
                )
            except ValueError:
                # A name the snapshot cannot hold: it is incomplete.
                complete = False
                continue
            path_bytes += len(path)
            files.append(item)

        def repositories() -> Iterator[bytes]:
            yield from directories
            # A gitlinked repository's HEAD can be ahead of the commit the outer repository
            # records for it (commits made in it and never added outside): the change in it
            # starts from that HEAD, so those earlier commits are never shown as the task's work.
            for path in self._gitlink_paths(pinned, deadline):
                git_entry = _path_identity(pinned.descriptor, path + b"/.git")
                # Only an embedded repository the check-time read would open: never an
                # uninitialised submodule, or a checkout whose ``.git`` is a file.
                if git_entry is not None and git_entry != _BLOCKED and stat.S_ISDIR(git_entry[0]):
                    yield path

        nested: list[tuple[str, str]] = []
        listings: list[NestedUntrackedBaseline] = []
        names_left = MAX_BASELINE_UNTRACKED_FILES - len(files)
        bytes_left = _MAX_BASELINE_PATH_BYTES - path_bytes
        for path in repositories():
            if len(nested) >= MAX_NESTED_REPOSITORIES or _expired(deadline):
                break
            name = _nested_name(path)
            if name is None or any(name == recorded for recorded, _ in nested):
                continue
            started = self._nested_start(pinned, path, deadline)
            if started is None:
                continue
            commit, found = started
            nested.append((name, commit))
            size = 0 if found is None else sum(len(item.path.encode("utf-8")) for item in found)
            if found is not None and len(found) <= names_left and size <= bytes_left:
                names_left -= len(found)
                bytes_left -= size
                listings.append(NestedUntrackedBaseline(name, True, found))
            else:
                # Whole or not at all: a partial listing could not tell its other files apart
                # from ones that predate the task.
                listings.append(NestedUntrackedBaseline(name, False))
        listings.sort(key=lambda row: row.path)
        return tuple(files), complete, tuple(nested), tuple(listings)

    def _gitlink_paths(self, pinned: _Workspace, deadline: float) -> list[bytes]:
        """The paths the index records as gitlinks, in path order (issue #1045). Metadata only.

        An index too large to list keeps the gitlinks among the names that fit; one Git cannot
        list records none. Either way a gitlink not recorded starts from the commit the outer
        base tree records for it, and the header says so.
        """

        try:
            _, listing = self._git(
                pinned,
                ("ls-files", "--stage", "-z"),
                deadline=deadline,
                limit=_LIST_LIMIT,
                keep_prefix_on_limit=True,
            )
        except GitOutputTruncated as exc:
            listing = exc.prefix[: exc.prefix.rfind(b"\0") + 1]
        except ValueError:
            return []
        except ChangeCaptureUnavailable as exc:
            if exc.reason != "git_failed":
                raise
            return []
        paths: set[bytes] = set()
        for record in _nul_fields(listing):
            meta, separator, path = record.partition(b"\t")
            if separator and meta.startswith(b"160000 ") and _safe_relative(path):
                paths.add(path)
        return sorted(paths)

    def _nested_start(
        self, pinned: _Workspace, relative: bytes, deadline: float
    ) -> tuple[str, tuple[UntrackedBaselineFile, ...] | None] | None:
        """HEAD and untracked files of the nested repository at ``relative``, or ``None``.

        After the open fence, the repository passes the object-store and effective-config fences
        its check-time read applies (``_nested_read``) before its HEAD is resolved, so a store
        borrowed through ``commondir`` or alternates never supplies the starting commit. ``None``
        records nothing: the capture then starts from its HEAD and says it may miss commits, or
        refuses it as it was refused here. Only with a HEAD are its untracked files listed (the
        same ignore files its check-time read honours) and ``stat``-ed beneath its own root
        without following a link; no file is opened. That listing is ``None`` when it is cut
        short, would exceed the snapshot's bounds on its own, holds a name the base cannot carry
        or cannot be taken in time.
        """

        try:
            nested = self._open_nested(pinned, relative, deadline)
            # Metadata only: a borrowed store is refused before the effective-config listing
            # follows its includes and before HEAD is resolved.
            self._refuse_unsafe_object_store(nested)
            self._refuse_unsafe_config(nested, deadline)
            commit = self._rev(nested, "HEAD^{commit}", deadline)
        except ChangeCaptureUnavailable:
            return None
        if commit is None:
            return None
        try:
            return commit, self._nested_untracked_baseline(nested, deadline)
        except ChangeCaptureUnavailable, ValueError:
            return commit, None

    def _nested_untracked_baseline(
        self, nested: _Workspace, deadline: float
    ) -> tuple[UntrackedBaselineFile, ...] | None:
        """The opened nested repository's untracked files in path order, or ``None``."""

        excludes = self._repository_excludes_file(nested, deadline)
        if excludes is None:
            excludes = _global_excludes_file(deadline)
        config = ("-c", f"core.excludesFile={excludes}") if excludes is not None else ()
        listing, truncated = self._untracked_listing(nested, config, deadline)
        if truncated:
            return None
        files: list[UntrackedBaselineFile] = []
        path_bytes = 0
        for path in sorted(_nul_fields(listing)):
            if path.endswith(b"/"):
                # A repository nested inside this one is never read; nothing to record.
                continue
            if (
                not _safe_relative(path)
                or len(files) >= MAX_BASELINE_UNTRACKED_FILES
                or path_bytes + len(path) > _MAX_BASELINE_PATH_BYTES
                or _expired(deadline)
            ):
                return None
            identity = _path_identity(nested.descriptor, path)
            if identity is None:
                # Gone already: it cannot be a file this task started with.
                continue
            if identity == _BLOCKED:
                # Git never lists a path behind a link, so this is a failed or raced ``stat`` of a
                # file that may still be there: the listing cannot be complete.
                return None
            files.append(
                UntrackedBaselineFile(
                    path.decode("utf-8", errors="strict"), _baseline_state(identity)
                )
            )
            path_bytes += len(path)
        return tuple(files)

    def _open_nested(self, pinned: _Workspace, relative: bytes, deadline: float) -> _Workspace:
        """Open the nested repository whose top level is ``relative`` under the pinned root.

        The nested root gets every fence of the outer one (``_open``) and must also be exactly the
        directory reached beneath the outer root descriptor without following a link, so a path
        swapped for a link to another repository is refused as ``unsafe_root``.
        """

        expected = _path_identity(pinned.descriptor, relative)
        if expected is None or expected == _BLOCKED or not stat.S_ISDIR(expected[0]):
            raise ChangeCaptureUnavailable("unsafe_root")
        git_entry = _path_identity(pinned.descriptor, relative + b"/.git")
        if git_entry is not None and git_entry != _BLOCKED and stat.S_ISREG(git_entry[0]):
            # A submodule checkout: its Git directory lives elsewhere, which is never read.
            raise ChangeCaptureUnavailable("unsupported_repository")
        location = pinned.root / os.fsdecode(relative)
        nested = self._open(os.fspath(location), deadline)
        if nested.root != location or nested.root_identity != (expected[1], expected[2]):
            raise ChangeCaptureUnavailable("unsafe_root")
        return nested

    def capture(
        self,
        workspace: str,
        base: TaskChangeBase | None,
        *,
        priority_paths: tuple[str, ...] = (),
        input_paths: tuple[str, ...] = (),
    ) -> CheckChangeCapture:
        """Render the change; ``priority_paths`` are the task's declared deliverables (tb4n2 R7).

        A file at or under one of them is read, budgeted and rendered ahead of every other file,
        then come small files, then the rest in path order, so a reviewer packet clipped for room
        never drops a deliverable behind scratch files. The paths only order the change: they
        never widen what is read, and a value outside the repository is ignored.

        Issue #1045: untracked files a ``task_start`` base's snapshot names and that are unchanged
        since are baseline and left out; a nested Git repository's own change is rendered under
        its directory; and ``input_paths`` (files the task statement names) that lie in the
        repository, are not part of the change, are not ignored and are not credential-named are
        read into ``inputs`` as read-only task input files.
        """

        # One deadline bounds the whole capture: every Git call gets at most what is left of it.
        # Assembly may use its first part; the rest is kept for the closing stability check.
        started = time.monotonic()
        deadline = started + self._deadline_seconds
        assembly = started + self._deadline_seconds * _ASSEMBLY_SHARE
        pinned = self._open(workspace, assembly)
        self._refuse_unsafe_config(pinned, assembly)
        self._refuse_unsafe_object_store(pinned)
        object_format = self._object_format(pinned, assembly)
        priority = _priority_paths(pinned.root, priority_paths)
        for _ in range(_CAPTURE_ATTEMPTS):
            try:
                return self._capture_once(
                    pinned, object_format, base, assembly, deadline, priority, input_paths
                )
            except _ChangedDuringCapture:
                if _expired(assembly):
                    break
        raise ChangeCaptureUnavailable("changed_during_capture")

    def probe_requested_paths(
        self, workspace: str, values: tuple[str, ...]
    ) -> tuple[RequestedPathProbe, ...]:
        """Locate requested file paths under the root; report existence and Git ignore state.

        Metadata only (#977): each path is reached from the validated root descriptor one
        component at a time without following a link and only ``stat``-ed; no file or blob
        content is read. A relative value is taken relative to the repository root, an absolute
        one must lie under it. Ignore state is Git's own answer (``git check-ignore``), which
        honours ``.gitignore``, ``.git/info/exclude``, a repository ``core.excludesFile`` and the
        owner's global ignore file, and never reports a tracked file. Paths are only ever passed
        as arguments after ``--`` to the hardened runner; none is returned or logged.
        """

        if len(values) > _MAX_REQUESTED_PATH_PROBES:
            raise ChangeCaptureUnavailable("unsupported_repository")
        deadline = time.monotonic() + self._deadline_seconds
        pinned = self._open(workspace, deadline)
        self._refuse_unsafe_config(pinned, deadline)
        located: list[tuple[str, bytes | None]] = []
        for value in values:
            relative = _requested_relative_path(pinned.root, value)
            located.append(("inside", relative) if relative is not None else ("outside", None))
        inside = sorted({path for _, path in located if path is not None})
        identities = {path: _path_identity(pinned.descriptor, path) for path in inside}
        ignored: set[bytes] = set()
        unknown: set[bytes] = set()
        sources: dict[bytes, bytes] = {}
        # The root is never ignored by Git, so it is not queried.
        queried = [
            path for path in inside if identities[path] != _BLOCKED and path != _ROOT_RELATIVE
        ]
        unknown.update(path for path in inside if identities[path] == _BLOCKED)
        if queried:
            excludes = self._repository_excludes_file(pinned, deadline)
            if excludes is None:
                excludes = _global_excludes_file(deadline)
            config = ("-c", f"core.excludesFile={excludes}") if excludes is not None else ()
            # One quiet query per path: its exit status is the whole answer (0 ignored, 1 not),
            # so no path ever has to be parsed back out of Git's quoted output. A path Git
            # refuses (beyond a link, say) stays unknown without failing the others.
            for path in queried:
                try:
                    code, _ = self._git(
                        pinned,
                        (*config, "check-ignore", "-q", "--", os.fsdecode(path)),
                        deadline=deadline,
                        limit=1_024,
                        accepted=frozenset({0, 1}),
                    )
                except ValueError, ChangeCaptureUnavailable:
                    unknown.add(path)
                    continue
                if code != 0:
                    continue
                ignored.add(path)
                # Which rule ignores it: a negated match also prints here, so this second call
                # runs only for a path the quiet query already proved ignored.
                try:
                    _, verbose = self._git(
                        pinned,
                        (*config, "check-ignore", "-v", "--", os.fsdecode(path)),
                        deadline=deadline,
                        limit=8_192,
                        accepted=frozenset({0, 1}),
                    )
                except ValueError, ChangeCaptureUnavailable:
                    verbose = b""
                sources[path] = verbose.split(b":", 1)[0] if b":" in verbose else b""
        info_exclude = os.fsencode(pinned.root / ".git" / "info" / "exclude")
        holds_file: dict[bytes, bool | None] = {}
        probes: list[RequestedPathProbe] = []
        for location, path in located:
            if path is None:
                probes.append(RequestedPathProbe(location))
                continue
            identity = identities[path]
            source = sources.get(path)
            if path not in holds_file:
                holds_file[path] = (
                    _directory_holds_file(pinned.descriptor, path)
                    if identity is not None and identity != _BLOCKED and stat.S_ISDIR(identity[0])
                    else None
                )
            probes.append(
                RequestedPathProbe(
                    location,
                    os.fsdecode(path),
                    None if identity == _BLOCKED else identity is not None,
                    None if path in unknown else path in ignored,
                    holds_file=holds_file[path],
                    size_bytes=(
                        identity[3]
                        if identity is not None
                        and identity != _BLOCKED
                        and stat.S_ISREG(identity[0])
                        and identity[3] <= MAX_PROBED_FILE_SIZE
                        else None
                    ),
                    ignore_source=(
                        None
                        if source is None
                        else "info_exclude"
                        if source in {b".git/info/exclude", info_exclude}
                        else "outside_repository"
                        if source.startswith(b"/") or not source
                        else "repository_file"
                    ),
                    ignore_file=(
                        os.fsdecode(source)
                        if source is not None and source and not source.startswith(b"/")
                        else None
                    ),
                )
            )
        return tuple(probes)

    def count_change_lines(
        self, workspace: str, base_commit: str, base_paths: tuple[str, ...]
    ) -> ChangeLineCounts:
        """Count added and removed lines per changed file, and base lines of named paths.

        The ADR-035 content-moved fact needs sizes the path/status metadata does not carry. This
        read returns numbers only: Git's ``--numstat`` for tracked changes from ``base_commit``
        (binary files count as unknown), and for each untracked file Git does not ignore its
        newline count, read one component at a time without following a link, bounded per file
        and per call, never for a credential-named file or a binary one. ``base_paths`` are
        root-relative paths whose line counts in ``base_commit`` are returned in order, passed to
        Git as literal pathspecs. No content or path leaves this process; nothing is stored.
        The counts are a point-in-time read, not re-verified for stability: they feed a
        non-blocking disclosure only.
        """

        if len(base_paths) > _MAX_REQUESTED_PATH_PROBES or any(
            type(path) is not str or not _safe_relative(os.fsencode(path)) for path in base_paths
        ):
            raise ChangeCaptureUnavailable("unsupported_repository")
        deadline = time.monotonic() + self._deadline_seconds
        pinned = self._open(workspace, deadline)
        self._refuse_unsafe_config(pinned, deadline)
        self._refuse_unsafe_object_store(pinned)
        object_format = self._object_format(pinned, deadline)
        if (
            type(base_commit) is not str
            or not base_commit
            or self._rev(pinned, base_commit + "^{tree}", deadline) is None
        ):
            raise ChangeCaptureUnavailable("unsupported_repository")
        try:
            _, numbers = self._git(
                pinned,
                ("diff", "--numstat", "-z", *_DIFF_OPTIONS, base_commit, "--"),
                deadline=deadline,
                limit=_LIST_LIMIT,
            )
        except ValueError:
            raise ChangeCaptureUnavailable("unsupported_repository") from None
        # A path Git allows but a line count cannot carry (CR or LF) is skipped, not fatal.
        changed = [
            ChangeLineCount(os.fsdecode(path), added, removed)
            for path, added, removed in _numstat_rows(numbers)
            if b"\r" not in path and b"\n" not in path
        ]
        excludes = self._repository_excludes_file(pinned, deadline)
        if excludes is None:
            excludes = _global_excludes_file(deadline)
        config = ("-c", f"core.excludesFile={excludes}") if excludes is not None else ()
        listing, truncated = self._untracked_listing(pinned, config, deadline)
        paths = sorted(_nul_fields(listing))
        budget = _MAX_LINE_COUNT_TOTAL_BYTES
        for index, path in enumerate(paths):
            if index >= _MAX_UNTRACKED_FILES or _expired(deadline):
                truncated = True
                break
            if budget <= 0:
                truncated = True
                break
            if path.endswith(b"/") or _credential_name(path) or b"\r" in path or b"\n" in path:
                continue
            if not _safe_relative(path):
                raise ChangeCaptureUnavailable("unsafe_root")
            lines: int | None = None
            try:
                outcome, content = _read_beneath(
                    pinned.descriptor,
                    path,
                    min(_MAX_LINE_COUNT_FILE_BYTES, budget),
                    _path_identity(pinned.descriptor, path),
                )
            except _ChangedDuringCapture:
                outcome, content = "unreadable", None
            if outcome in {"regular", "executable"} and content is not None:
                budget -= len(content)
                if b"\0" not in content[:_BINARY_PROBE_BYTES]:
                    lines = content.count(b"\n") + (
                        1 if content and not content.endswith(b"\n") else 0
                    )
            elif outcome == "too_large":
                truncated = True
            changed.append(
                ChangeLineCount(
                    os.fsdecode(path), lines, None if lines is None else 0, untracked=True
                )
            )
        base_lines: list[int | None] = [None] * len(base_paths)
        if base_paths:
            try:
                _, numbers = self._git(
                    pinned,
                    (
                        "diff",
                        "--numstat",
                        "-z",
                        *_DIFF_OPTIONS,
                        _EMPTY_TREES[object_format],
                        base_commit,
                        "--",
                        *(f":(literal){path}" for path in base_paths),
                    ),
                    deadline=deadline,
                    limit=_LIST_LIMIT,
                )
            except ValueError:
                raise ChangeCaptureUnavailable("unsupported_repository") from None
            in_base = {os.fsdecode(path): added for path, added, _ in _numstat_rows(numbers)}
            base_lines = [in_base.get(path) for path in base_paths]
        return ChangeLineCounts(tuple(changed), tuple(base_lines), truncated)

    def find_undeclared_references(
        self, workspace: str, deliverables: tuple[str, ...], candidates: tuple[str, ...]
    ) -> tuple[tuple[int, int], ...]:
        """Which declared deliverables name which created but undeclared files.

        tb4n2 R2 / tb4n4 (ADR-035 amendment, issue #1044): a delivered ``cracker.py`` loaded model
        files the agent created and never declared, so the graded deliverable failed.
        ``deliverables`` and ``candidates`` are root-relative paths. Each deliverable with a
        source-code suffix (or no suffix and a ``#!`` first line) is read from the start, at most
        ``_MAX_REFERENCE_FILE_BYTES``, one component at a time without following a link, never
        when credential-named, multiply linked or binary. A candidate is referenced when a one-line
        quoted string literal equals its path, ends with ``/`` and its path, or equals its basename
        of at least ``_MIN_REFERENCE_BASENAME`` bytes. Returns ``(deliverable index, candidate
        index)`` pairs into the caller's own tuples, sorted, at most ``_MAX_REFERENCE_PAIRS``: no
        path or content leaves this method, and nothing is logged.
        """

        if (
            type(deliverables) is not tuple
            or type(candidates) is not tuple
            or len(deliverables) > _MAX_REFERENCE_DELIVERABLES
            or len(candidates) > _MAX_REFERENCE_CANDIDATES
            or any(
                type(path) is not str or not _safe_relative(os.fsencode(path))
                for path in (*deliverables, *candidates)
            )
        ):
            raise ChangeCaptureUnavailable("unsupported_repository")
        if not deliverables or not candidates:
            return ()
        deadline = time.monotonic() + self._deadline_seconds
        pinned = self._open(workspace, deadline)
        paths: dict[bytes, list[int]] = {}
        names: dict[bytes, list[int]] = {}
        for index, candidate in enumerate(candidates):
            path = os.fsencode(candidate)
            paths.setdefault(path, []).append(index)
            name = path.rsplit(b"/", 1)[-1]
            if len(name) >= _MIN_REFERENCE_BASENAME:
                names.setdefault(name, []).append(index)
        found: set[tuple[int, int]] = set()
        for position, deliverable in enumerate(deliverables):
            if _expired(deadline):
                break
            path = os.fsencode(deliverable)
            name = path.rsplit(b"/", 1)[-1]
            suffix = os.path.splitext(name)[1]
            if _credential_name(path) or (suffix and suffix not in _SOURCE_SUFFIXES):
                continue
            content = _read_prefix_beneath(pinned.descriptor, path, _MAX_REFERENCE_FILE_BYTES)
            if content is None or b"\0" in content[:_BINARY_PROBE_BYTES]:
                continue
            if not suffix and not content.startswith(b"#!"):
                continue
            found.update((position, index) for index in _referenced(content, paths, names))
        return tuple(sorted(found))[:_MAX_REFERENCE_PAIRS]

    def capture_metadata(self, workspace: str, base: TaskChangeBase | None) -> CheckChangeMetadata:
        """Return changed-path facts without reading file or blob content.

        Structural test-edit accounting needs the changed paths, while ADR-031 content capture is
        authorized only by a semantic review recipe.  Keep this path on Git's raw/name metadata
        commands and never call the content-rendering capture or its redaction pipeline.
        """

        started = time.monotonic()
        deadline = started + self._deadline_seconds
        assembly = started + self._deadline_seconds * _ASSEMBLY_SHARE
        pinned = self._open(workspace, assembly)
        self._refuse_unsafe_config(pinned, assembly)
        object_format = self._object_format(pinned, assembly)
        for _ in range(_CAPTURE_ATTEMPTS):
            try:
                packs = self._refuse_unsafe_object_store(pinned)
                return self._capture_metadata_once(
                    pinned, object_format, base, assembly, deadline, packs
                )
            except _ChangedDuringCapture:
                if _expired(assembly):
                    break
        raise ChangeCaptureUnavailable("changed_during_capture")

    def _capture_metadata_once(
        self,
        pinned: _Workspace,
        object_format: Literal["sha1", "sha256"],
        base: TaskChangeBase | None,
        assembly: float,
        deadline: float,
        packs: tuple[tuple[bytes, _Identity], ...],
    ) -> CheckChangeMetadata:
        head = self._rev(pinned, "HEAD^{commit}", assembly)
        if (
            base is not None
            and base.object_format == object_format
            and self._rev(pinned, base.commit + "^{tree}", assembly) is not None
        ):
            base_kind, base_id = base.origin, base.commit
        elif head is not None:
            base_kind, base_id = "head", head
        else:
            base_kind, base_id = "empty", _EMPTY_TREES[object_format]

        tracked_raw, tracked_entries, tracked_identities, tracked_arguments, tracked_skipped = (
            self._tracked_metadata(pinned, base_id, assembly)
        )
        gitlinks = self._metadata_gitlinks(pinned, base_id, tracked_identities, assembly)
        index = _path_identity(pinned.descriptor, b".git/index")
        baseline = _baseline(base)
        untracked = self._untracked_metadata(pinned, assembly, baseline)
        tracked = _TrackedRead(tracked_raw, [], tracked_identities, tracked_arguments)
        self._verify_stable(
            pinned,
            base_id,
            tracked,
            untracked,
            head,
            index,
            packs,
            deadline,
        )
        entries, unrepresentable, omitted = _metadata_listing(
            tracked_entries, tracked_skipped, untracked
        )
        tracked_files = len(tracked_entries) + tracked_skipped
        untracked_files = untracked.total
        listing_truncated = untracked.listing_truncated
        # Nested repositories (issue #1045), read after the outer state proved stable, exactly
        # where the full capture reads them: an untracked repository's directory counts as one
        # omitted untracked entry until its own change replaces it, and a changed gitlink whose
        # repository is not read counts as omitted beside its entry.
        directories = set(untracked.directories)
        for read in self._nested_metadata(
            pinned, gitlinks, untracked.directories, baseline, assembly, deadline
        ):
            if read.entries is None:
                if read.path in gitlinks:
                    omitted += 1
                continue
            if read.path in directories and read.path not in gitlinks:
                untracked_files -= 1
                omitted -= 1
            entries.extend(read.entries)
            tracked_files += read.tracked
            untracked_files += read.untracked
            omitted += read.omitted
            unrepresentable += read.unrepresentable
            listing_truncated = listing_truncated or read.listing_truncated
        return CheckChangeMetadata(
            base=base_kind,
            entries=tuple(entries),
            tracked_files=tracked_files,
            untracked_files=untracked_files,
            omitted_files=omitted,
            truncated=omitted > 0 or listing_truncated,
            base_commit=base_id,
            unrepresentable_files=unrepresentable,
        )

    def _metadata_gitlinks(
        self,
        pinned: _Workspace,
        base_id: str,
        identities: Mapping[bytes, _Identity | None],
        deadline: float,
    ) -> dict[bytes, str | None]:
        """Changed gitlinks and the commit the base tree records for each, as the capture reads.

        Only when a changed path is a directory in the working tree (a tracked file never is) is
        the raw list read, which names modes and object ids but reads no content.
        """

        if not any(
            identity is not None and identity != _BLOCKED and stat.S_ISDIR(identity[0])
            for identity in identities.values()
        ):
            return {}
        try:
            _, raw = self._git(
                pinned, self._raw_arguments(base_id), deadline=deadline, limit=_LIST_LIMIT
            )
        except ValueError:
            raise ChangeCaptureUnavailable("unsupported_repository") from None
        return {
            entry.path: (
                entry.src_oid if entry.src_mode == "160000" and entry.src_oid.strip("0") else None
            )
            for entry in _raw_entries(raw)
            if entry.dst_mode == "160000" and entry.status != "D"
        }

    def _nested_metadata(
        self,
        pinned: _Workspace,
        gitlinks: Mapping[bytes, str | None],
        directories: Sequence[bytes],
        baseline: _Baseline | None,
        assembly: float,
        deadline: float,
    ) -> list[_NestedMetadata]:
        """Each nested repository's metadata-only change, as ``_nested_reads`` selects them."""

        candidates: dict[bytes, str | None] = dict(gitlinks)
        for path in directories:
            candidates.setdefault(path, None)
        reads: list[_NestedMetadata] = []
        for path in sorted(candidates):
            if len(reads) >= MAX_NESTED_REPOSITORIES or _expired(assembly):
                reads.append(_NestedMetadata(path))
                continue
            recorded, _, listing, _ = _nested_start_state(baseline, path, candidates[path])
            try:
                reads.append(
                    self._nested_metadata_read(pinned, path, recorded, listing, assembly, deadline)
                )
            except ChangeCaptureUnavailable:
                reads.append(_NestedMetadata(path))
        return reads

    def _nested_metadata_read(
        self,
        pinned: _Workspace,
        path: bytes,
        recorded: str | None,
        listing: dict[bytes, str] | None,
        assembly: float,
        deadline: float,
    ) -> _NestedMetadata:
        """One nested repository's change as metadata, with every fence of ``_nested_read``."""

        nested = self._open_nested(pinned, path, assembly)
        self._refuse_unsafe_config(nested, assembly)
        object_format = self._object_format(nested, assembly)
        for _ in range(_CAPTURE_ATTEMPTS):
            try:
                packs = self._refuse_unsafe_object_store(nested)
                head = self._rev(nested, "HEAD^{commit}", assembly)
                index = _path_identity(nested.descriptor, b".git/index")
                _, base_id = self._base(
                    nested, object_format, _nested_base(object_format, recorded), head, assembly
                )
                raw, entries, identities, arguments, skipped = self._tracked_metadata(
                    nested, base_id, assembly
                )
                untracked = self._untracked_metadata(
                    nested, assembly, None if listing is None else _Baseline(listing, True, {}, {})
                )
                self._verify_stable(
                    nested,
                    base_id,
                    _TrackedRead(raw, [], identities, arguments),
                    untracked,
                    head,
                    index,
                    packs,
                    deadline,
                )
            except _ChangedDuringCapture:
                if _expired(assembly):
                    break
                continue
            listed, unrepresentable, omitted = _metadata_listing(
                entries, skipped, untracked, prefix=path + b"/", named_only=listing is None
            )
            # A repository nested inside this one is never read: its changed gitlink (a changed
            # path that is a directory) counts as omitted, as the full capture marks it.
            omitted += sum(
                1
                for identity in identities.values()
                if identity is not None and identity != _BLOCKED and stat.S_ISDIR(identity[0])
            )
            return _NestedMetadata(
                path,
                listed,
                len(entries) + skipped,
                untracked.total,
                omitted,
                unrepresentable,
                untracked.listing_truncated,
            )
        raise ChangeCaptureUnavailable("changed_during_capture")

    def _capture_once(
        self,
        pinned: _Workspace,
        object_format: Literal["sha1", "sha256"],
        base: TaskChangeBase | None,
        assembly: float,
        deadline: float,
        priority: tuple[bytes, ...] = (),
        input_paths: tuple[str, ...] = (),
    ) -> CheckChangeCapture:
        packs = self._refuse_unsafe_object_store(pinned)
        head = self._rev(pinned, "HEAD^{commit}", assembly)
        index = _path_identity(pinned.descriptor, b".git/index")
        base_kind, base_id = self._base(pinned, object_format, base, head, assembly)
        baseline = _baseline(base)
        tracked = self._tracked_sections(pinned, object_format, base_id, assembly, priority)
        untracked = _UntrackedRead(0, [], True, None, (), {})
        if not _expired(assembly):
            try:
                untracked = self._untracked_sections(pinned, assembly, priority, baseline=baseline)
            except ChangeCaptureUnavailable as exc:
                if not _ran_out(exc, assembly):
                    raise
        # Past the deadline no untracked file is listed or read; the header says the untracked
        # count is a lower bound, and the tracked change above still stands.
        self._verify_stable(pinned, base_id, tracked, untracked, head, index, packs, deadline)
        sections = [*tracked.sections, *untracked.sections]
        # Nested repositories (issue #1045): each one's own change replaces the one-line entry
        # the outer change gives its directory. Read after the outer state proved stable; each is
        # its own coherent state, bounded by the same deadline.
        nested = self._nested_reads(
            pinned, tracked, untracked, baseline, priority, assembly, deadline
        )
        nested_tracked = nested_untracked = nested_unlisted = nested_kept = 0
        nested_truncated = False
        for read in nested:
            if read.sections is None:
                # Its directory keeps its one-line entry, and a changed gitlink its commit-id
                # lines; either way the repository's own change is not shown and counts so. The
                # header says why it was not read.
                for section in tracked.sections:
                    if section.path == read.path and section.omitted is None:
                        section.omitted = "nested_repository"
                continue
            placeholder = next(
                (
                    section
                    for section in untracked.sections
                    if section.path == read.path + b"/" and section.text is None
                ),
                None,
            )
            if placeholder is not None:
                # The directory's placeholder gives way to the files the repository changed.
                untracked.sections.remove(placeholder)
                sections.remove(placeholder)
                untracked.total -= 1
            sections.extend(read.sections)
            nested_tracked += read.tracked
            nested_untracked += read.untracked
            nested_unlisted += read.unlisted_untracked
            nested_kept += read.kept
            nested_truncated = nested_truncated or read.listing_truncated
        # Declared deliverables first, then small files, then the rest (tb4n2 R7, P1-11): the
        # body budget and every later packet cut keep the head of this order.
        sections.sort(key=lambda item: _section_rank(item, priority))
        inputs = self._task_inputs(
            pinned,
            input_paths,
            sections,
            nested,
            untracked.kept,
            deadline,
            base_kind=base_kind,
            base_id=base_id,
            object_format=object_format,
        )
        return self._render(
            base_kind,
            base_id,
            sections,
            tracked=len(tracked.sections) + nested_tracked,
            untracked=untracked.total + nested_untracked,
            unlisted_untracked=untracked.total - len(untracked.sections) + nested_unlisted,
            untracked_listing_truncated=untracked.listing_truncated or nested_truncated,
            baseline=baseline,
            baseline_unchanged=len(untracked.kept) + nested_kept,
            nested=nested,
            inputs=inputs,
        )

    def _base(
        self,
        pinned: _Workspace,
        object_format: Literal["sha1", "sha256"],
        base: TaskChangeBase | None,
        head: str | None,
        deadline: float,
    ) -> tuple[ChangeBaseKind, str]:
        """The recorded base when this repository still holds it, else HEAD, else the empty tree."""

        if (
            base is not None
            and base.object_format == object_format
            and self._rev(pinned, base.commit + "^{tree}", deadline) is not None
        ):
            return base.origin, base.commit
        if head is not None:
            return "head", head
        return "empty", _EMPTY_TREES[object_format]

    def _nested_reads(
        self,
        pinned: _Workspace,
        tracked: _TrackedRead,
        untracked: _UntrackedRead,
        baseline: _Baseline | None,
        priority: tuple[bytes, ...],
        assembly: float,
        deadline: float,
    ) -> list[_NestedRead]:
        """Read each nested repository's own change (issue #1045), bounded and in rank order.

        A nested repository is an untracked directory Git lists as its own repository, or a
        changed gitlink whose working directory is one. Its change starts from the HEAD the
        task-start snapshot recorded for it, else the commit the outer base tree records for the
        gitlink (the header then says commits made in it before the task that the outer
        repository does not record are included), else its HEAD now (disclosed in the header).
        Its untracked files are treated as at the outer level when the snapshot holds a complete
        listing of them; otherwise they are named, never read, since any may predate the task.
        Paths are shown under the directory's path. At most ``MAX_NESTED_REPOSITORIES`` are read;
        the rest keep their one-line entry.
        """

        candidates: dict[bytes, str | None] = {}
        for path, commit in tracked.gitlinks:
            # A gitlink the base tree does not hold (added during the task, or replacing a file)
            # has no recorded commit there.
            candidates.setdefault(path, commit if commit and commit.strip("0") else None)
        for section in untracked.sections:
            if section.path.endswith(b"/") and section.text is None:
                candidates.setdefault(section.path[:-1], None)

        def rank(path: bytes) -> tuple[int, int, bytes]:
            # A repository holding (or being) a declared deliverable is read first.
            tier = _priority_tier(path, priority)
            if tier is None:
                tier = next(
                    (index for index, item in enumerate(priority) if item.startswith(path + b"/")),
                    None,
                )
            return (1, 0, path) if tier is None else (0, tier, path)

        reads: list[_NestedRead] = []
        for path in sorted(candidates, key=rank):
            if len(reads) >= MAX_NESTED_REPOSITORIES:
                reads.append(_NestedRead(path, reason="nested_limit"))
                continue
            if _expired(assembly):
                reads.append(_NestedRead(path, reason="capture_limit"))
                continue
            recorded, from_base_tree, listing, unrecorded = _nested_start_state(
                baseline, path, candidates[path]
            )
            try:
                read = self._nested_read(
                    pinned, path, recorded, listing, priority, assembly, deadline
                )
                read.from_base_tree = from_base_tree and read.base == "task_start"
                read.untracked_unrecorded = unrecorded
                reads.append(read)
            except ChangeCaptureUnavailable as exc:
                reads.append(
                    _NestedRead(
                        path, reason="capture_limit" if _ran_out(exc, assembly) else exc.reason
                    )
                )
        return reads

    def _nested_read(
        self,
        pinned: _Workspace,
        path: bytes,
        recorded: str | None,
        listing: dict[bytes, str] | None,
        priority: tuple[bytes, ...],
        assembly: float,
        deadline: float,
    ) -> _NestedRead:
        """One nested repository's change; ``listing`` is its complete task-start untracked list.

        With ``listing`` its untracked files are split exactly as at the outer level: one it
        names with an unchanged digest is left out and counted, any other is read and shown.
        Without one they are named only.
        """

        nested = self._open_nested(pinned, path, assembly)
        self._refuse_unsafe_config(nested, assembly)
        object_format = self._object_format(nested, assembly)
        prefix = path + b"/"
        inner = tuple(item[len(prefix) :] for item in priority if item.startswith(prefix))
        for _ in range(_CAPTURE_ATTEMPTS):
            try:
                packs = self._refuse_unsafe_object_store(nested)
                head = self._rev(nested, "HEAD^{commit}", assembly)
                index = _path_identity(nested.descriptor, b".git/index")
                base_kind, base_id = self._base(
                    nested, object_format, _nested_base(object_format, recorded), head, assembly
                )
                tracked = self._tracked_sections(
                    nested, object_format, base_id, assembly, inner, prefix=prefix
                )
                if listing is None:
                    # No complete task-start listing of its untracked files: none of them can be
                    # told apart from one that predates the task, so they are named only.
                    untracked = self._untracked_sections(
                        nested, assembly, inner, prefix=prefix, read_files=False
                    )
                else:
                    untracked = self._untracked_sections(
                        nested,
                        assembly,
                        inner,
                        baseline=_Baseline(listing, True, {}, {}),
                        prefix=prefix,
                    )
                self._verify_stable(
                    nested, base_id, tracked, untracked, head, index, packs, deadline
                )
            except _ChangedDuringCapture:
                if _expired(assembly):
                    break
                continue
            # A repository nested inside this one is never read (issue #1045): its changed
            # gitlink keeps its commit-id lines and counts as not shown, as at the outer level.
            inner_gitlinks = {gitlink for gitlink, _ in tracked.gitlinks}
            for section in tracked.sections:
                if section.path in inner_gitlinks and section.omitted is None:
                    section.omitted = "nested_repository"
                section.path = prefix + section.path
            return _NestedRead(
                path,
                base_kind,
                [*tracked.sections, *untracked.sections],
                len(tracked.sections),
                untracked.total,
                untracked.total - len(untracked.sections),
                untracked.listing_truncated,
                kept=len(untracked.kept),
            )
        raise ChangeCaptureUnavailable("changed_during_capture")

    def _task_inputs(
        self,
        pinned: _Workspace,
        values: tuple[str, ...],
        sections: list[_Section],
        nested: list[_NestedRead],
        baseline_kept: frozenset[bytes],
        deadline: float,
        *,
        base_kind: ChangeBaseKind,
        base_id: str,
        object_format: Literal["sha1", "sha256"],
    ) -> tuple[TaskInputFile, ...]:
        """Read the read-only task input files ``values`` names (issue #1045), bounded.

        A value is read only when it lies inside the repository (lexically, like a requested
        path) and is unchanged since the task started: an untracked file the task-start snapshot
        names whose identity has not changed, or, when the change's base is the task's own start
        (``task_start``), a file Git tracks that this change does not touch, whose index entry is
        neither skip-worktree nor assume-unchanged (Git does not compare those with the working
        tree) and whose bytes hash to its blob in the base commit. So it is never the agent's
        work, never a file Git ignores (an ignored file is neither tracked nor listed untracked),
        never inside a nested repository and never credential-named; and it must be a regular,
        singly linked file of the service user reached without a link, holding no NUL byte in
        its head. At most ``MAX_TASK_INPUT_FILES`` are read, in the order given; each keeps at
        most ``MAX_TASK_INPUT_TEXT_BYTES``, whole or as head and tail with the cut marked. The
        read is point-in-time, after the change proved stable. A file that fails any test is
        skipped silently: nothing about it is returned.
        """

        if type(values) is not tuple or not values:
            return ()
        changed = {section.path.rstrip(b"/") for section in sections}
        nested_roots = {read.path for read in nested}
        inputs: list[TaskInputFile] = []
        seen: set[bytes] = set()
        for value in values[:_MAX_REQUESTED_PATH_PROBES]:
            if len(inputs) >= MAX_TASK_INPUT_FILES or _expired(deadline):
                break
            relative = _requested_relative_path(pinned.root, value)
            if relative is None or relative == _ROOT_RELATIVE or relative in seen:
                continue
            seen.add(relative)
            if (
                relative in changed
                or _credential_name(relative)
                or any(
                    relative == root or relative.startswith(root + b"/") for root in nested_roots
                )
            ):
                continue
            identity = _path_identity(pinned.descriptor, relative)
            if identity is None or identity == _BLOCKED or not stat.S_ISREG(identity[0]):
                continue
            blob: str | None = None
            if relative not in baseline_kept:
                if base_kind != "task_start":
                    # Absent from a change against a first-check pin or HEAD, a tracked file may
                    # still be the agent's committed work: it is not unchanged since the start.
                    continue
                blob = self._unchanged_tracked_blob(pinned, relative, base_id, deadline)
                if blob is None:
                    continue
            input_file = _task_input(pinned, relative, identity, object_format, blob)
            if input_file is not None:
                inputs.append(input_file)
        return tuple(inputs)

    def _unchanged_tracked_blob(
        self, pinned: _Workspace, relative: bytes, base_id: str, deadline: float
    ) -> str | None:
        """The base commit's blob id for a tracked task input Git compares, else ``None``.

        The file must be one ordinary index entry (``git ls-files -v`` tag ``H``): a
        skip-worktree (``S``) or assume-unchanged (lowercase) entry is never compared with the
        working tree, so its absence from the change says nothing about its bytes, and an
        untracked one (no entry) may be the agent's own. The caller reads the file only when its
        bytes hash to this blob (issue #1045).
        """

        try:
            name = relative.decode("utf-8", errors="strict")
            _, listed = self._git(
                pinned,
                ("ls-files", "-v", "-z", "--", ":(literal)" + name),
                deadline=deadline,
                limit=65_536,
            )
            if _nul_fields(listed) != [b"H " + relative]:
                return None
            return self._rev(pinned, f"{base_id}:{name}", deadline)
        except UnicodeDecodeError, ValueError, ChangeCaptureUnavailable:
            return None

    # --- Git access --------------------------------------------------------------------------

    @staticmethod
    def _open(workspace: str, deadline: float) -> _Workspace:
        executable = shutil.which("git", path=os.defpath)
        if executable is None:
            raise ChangeCaptureUnavailable("git_unavailable")
        if not git_version_supported(git_version(executable)):
            # Named rather than left to fail as ``git_failed`` on the first option it lacks.
            raise ChangeCaptureUnavailable(GIT_VERSION_UNSUPPORTED)
        try:
            root = discover_workspace_root(Path(workspace), timeout_seconds=_remaining(deadline))
            handle = open_local_workspace(root, timeout_seconds=_remaining(deadline))
            validated_root, descriptor = local_workspace_root(handle)
        except ValueError as exc:
            if time.monotonic() >= deadline:
                raise ChangeCaptureUnavailable("git_failed") from None
            reason = str(exc)
            if reason == "not_git":
                raise ChangeCaptureUnavailable("not_git") from None
            if reason in {"unsafe_root"}:
                raise ChangeCaptureUnavailable("unsafe_root") from None
            raise ChangeCaptureUnavailable("unsupported_repository") from None
        try:
            # The open descriptor is the validated directory; its identity pins the pathname
            # every Git call receives (Git itself can only be given a path).
            facts = os.fstat(descriptor)
            git_facts = os.stat(".git", dir_fd=descriptor, follow_symlinks=False)
        except OSError:
            raise ChangeCaptureUnavailable("unsafe_root") from None
        if not stat.S_ISDIR(git_facts.st_mode):
            raise ChangeCaptureUnavailable("unsafe_root")
        pinned = _Workspace(
            handle,
            validated_root,
            descriptor,
            (facts.st_dev, facts.st_ino),
            (git_facts.st_dev, git_facts.st_ino),
        )
        _verify_same_root(pinned)
        # Every capture call names the validated ``.git`` and working tree explicitly, so no
        # configuration can redirect it; confirm Git agrees before reading anything.
        try:
            _, located = GitChangeCaptureAdapter._git(
                pinned,
                # No ``--path-format=absolute``: Git before 2.31 echoes it as an extra output
                # line (#1040). Both queries print absolute paths on every supported Git; each
                # answer is still canonicalised against the root Git ran in.
                ("rev-parse", "--show-toplevel", "--absolute-git-dir"),
                deadline=deadline,
                limit=8_192,
            )
            located_paths = [
                absolute_rev_parse_path(line, validated_root)
                for line in located.rstrip(b"\n").split(b"\n")
            ]
        except ValueError:
            raise ChangeCaptureUnavailable("unsafe_root") from None
        if located_paths != [validated_root, validated_root / ".git"]:
            raise ChangeCaptureUnavailable("unsafe_root")
        return pinned

    @staticmethod
    def _git(
        pinned: _Workspace,
        arguments: Sequence[str],
        *,
        deadline: float,
        limit: int,
        accepted: frozenset[int] = frozenset({0}),
        keep_prefix_on_limit: bool = False,
    ) -> tuple[int, bytes]:
        # Git runs at the root's pathname. Before and after each call that pathname, and its
        # ``.git``, must still be the validated directories: a directory renamed away and replaced
        # at the same path fails closed rather than being read.
        _verify_same_root(pinned)
        try:
            result = run_read_only_git(
                pinned.handle,
                (
                    *_CAPTURE_CONFIG,
                    # Explicit, so neither ``core.worktree`` nor any other setting written at any
                    # level can point this call at another directory. The runner's environment is
                    # fixed, so no ``GIT_DIR``-style variable reaches Git either.
                    f"--git-dir={os.fspath(pinned.root / '.git')}",
                    f"--work-tree={os.fspath(pinned.root)}",
                    *arguments,
                ),
                stdout_limit=limit,
                timeout_seconds=_remaining(deadline),
                accepted_returncodes=accepted,
                keep_prefix_on_limit=keep_prefix_on_limit,
            )
        except ValueError as exc:
            _verify_same_root(pinned)
            if str(exc) == "git_output_limit":
                raise
            raise ChangeCaptureUnavailable("git_failed") from None
        _verify_same_root(pinned)
        return result

    def _object_format(self, pinned: _Workspace, deadline: float) -> Literal["sha1", "sha256"]:
        _, raw = self._git(
            pinned, ("rev-parse", "--show-object-format"), deadline=deadline, limit=32
        )
        value = raw.strip()
        if value == b"sha1":
            return "sha1"
        if value == b"sha256":
            return "sha256"
        raise ChangeCaptureUnavailable("unsupported_repository")

    def _rev(self, pinned: _Workspace, spec: str, deadline: float) -> str | None:
        # Every spec is a fixed spelling (``HEAD^{commit}``) or starts with a hexadecimal object
        # id, so none can be read as an option. ``--end-of-options`` would say so to Git, but
        # ``rev-parse`` learned it only in Git 2.30 and an older one drops it unread; the guard
        # below holds on every Git instead.
        if type(spec) is not str or not spec or spec.startswith("-"):
            raise ChangeCaptureUnavailable("git_failed")
        code, raw = self._git(
            pinned,
            ("rev-parse", "--verify", "--quiet", spec),
            deadline=deadline,
            limit=128,
            accepted=frozenset({0, 1, 128}),
        )
        if code != 0:
            return None
        value = raw.strip().decode("ascii", errors="replace")
        if not value or any(character not in "0123456789abcdef" for character in value):
            raise ChangeCaptureUnavailable("git_failed")
        return value

    def _refuse_unsafe_config(self, pinned: _Workspace, deadline: float) -> None:
        """Refuse any effective repository config that could run a command or fetch.

        The ADR-011 metadata fence reads ``.git/config`` lexically, so a filter driver defined in
        ``config.worktree`` (``extensions.worktreeConfig``), through an ``include`` there, or on a
        line that opens two sections (``[core][filter "x"]``) passes it, and ``git diff`` against
        the working tree then runs that driver's ``clean`` command. Git's own view of its
        effective config names every such key, whichever file or include it came from.
        ``--show-origin`` (Git 2.8) tells the runner's own ``-c`` values (``command line:``)
        apart from everything else; ``--show-scope`` said the same but needs Git 2.26. The
        runner reads no system or global configuration on any Git, so every other entry is the
        repository's own (``.git/config``, ``config.worktree`` or a file either includes).
        """

        try:
            _, listing = self._git(
                pinned,
                ("config", "--list", "--name-only", "--includes", "--show-origin", "-z"),
                deadline=deadline,
                limit=1_048_576,
            )
        except ValueError:
            raise ChangeCaptureUnavailable("unsupported_repository") from None
        fields = _nul_fields(listing)
        if len(fields) % 2:
            raise ChangeCaptureUnavailable("git_failed")
        for index in range(0, len(fields), 2):
            if fields[index] == _COMMAND_LINE_ORIGIN:
                # The hardened runner's own ``-c`` overrides.
                continue
            name = fields[index + 1].lower()
            if (
                name.startswith((b"filter.", b"include.", b"includeif."))
                or name in {b"extensions.partialclone", b"core.worktree"}
                or (
                    name.startswith(b"remote.")
                    and name.endswith((b".promisor", b".partialclonefilter"))
                )
            ):
                raise ChangeCaptureUnavailable("unsupported_repository")

    @staticmethod
    def _refuse_unsafe_object_store(pinned: _Workspace) -> tuple[tuple[bytes, _Identity], ...]:
        """Refuse an object store Git would reach through a link or another repository.

        Git follows links inside ``.git`` and trusts every object file it opens, so an object
        store, a pack or an index that is a link, or a ``commondir`` or ``alternates`` naming
        another repository's store, could hand the diff bytes from outside the workspace. Every
        pack-directory entry must be a regular file of the service user, not group- or
        world-writable. A second name (a local ``git clone`` hard-links its source's objects) is
        accepted: what makes a blob this repository's is that it hashes to the name the base tree
        or index gives it, which ``_verify_object`` proves for every blob a shown diff reads,
        whatever the file's link count. Returns a snapshot the
        closing stability check compares: the identity of every pack-directory entry and of the
        object directories themselves (``objects``, ``info``, ``pack`` and each fan-out
        directory), whose modification and change times move whenever an object file is created,
        renamed or removed in them. So a loose object swapped for a link and back while Git
        reads it is seen, even one outside the diff's own list (Git itself rejects a tree or
        commit whose bytes do not hash to its name; it does not re-hash a blob it streams into a
        diff). Loose blobs a shown diff reads are fenced one by one as well (``_verify_object``).
        """

        descriptor = pinned.descriptor
        expected_uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
        try:
            objects = os.stat(".git/objects", dir_fd=descriptor, follow_symlinks=False)
        except OSError:
            raise ChangeCaptureUnavailable("unsafe_root") from None
        if not stat.S_ISDIR(objects.st_mode) or objects.st_uid != expected_uid:
            raise ChangeCaptureUnavailable("unsafe_root")
        # Alternates are refused as ``unsafe_root`` exactly as the ADR-011 open fence refuses
        # them; a ``commondir`` (a borrowed store the open fence does not see) is unsupported.
        for name, reason in (
            (".git/objects/info/alternates", "unsafe_root"),
            (".git/objects/info/http-alternates", "unsafe_root"),
            (".git/commondir", "unsupported_repository"),
        ):
            try:
                os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                continue
            except OSError:
                raise ChangeCaptureUnavailable("unsafe_root") from None
            raise ChangeCaptureUnavailable(reason)
        for name in (".git/objects/info", ".git/objects/pack"):
            try:
                facts = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                continue
            except OSError:
                raise ChangeCaptureUnavailable("unsafe_root") from None
            if not stat.S_ISDIR(facts.st_mode) or facts.st_uid != expected_uid:
                raise ChangeCaptureUnavailable("unsafe_root")
        snapshot: list[tuple[bytes, _Identity]] = [(b".git/objects", _identity(objects))]
        for index in range(256):
            name = b".git/objects/%02x" % index
            identity = _path_identity(descriptor, name)
            if identity is not None:
                if not stat.S_ISDIR(identity[0]):
                    raise ChangeCaptureUnavailable("unsafe_root")
                snapshot.append((name, identity))
        for name in (b".git/objects/info", b".git/objects/pack"):
            identity = _path_identity(descriptor, name)
            if identity is not None:
                snapshot.append((name, identity))
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            pack = os.open(".git/objects/pack", flags, dir_fd=descriptor)
        except FileNotFoundError:
            return tuple(snapshot)
        except OSError:
            raise ChangeCaptureUnavailable("unsafe_root") from None
        try:
            with os.scandir(pack) as entries:
                for count, entry in enumerate(entries, start=1):
                    if count > _MAX_PACK_DIRECTORY_ENTRIES:
                        raise ChangeCaptureUnavailable("unsupported_repository")
                    facts = entry.stat(follow_symlinks=False)
                    if not stat.S_ISREG(facts.st_mode):
                        raise ChangeCaptureUnavailable("unsafe_root")
                    if not _owner_only(_identity(facts)):
                        raise ChangeCaptureUnavailable("unsafe_root")
                    snapshot.append(
                        (b".git/objects/pack/" + os.fsencode(entry.name), _identity(facts))
                    )
        except OSError:
            raise ChangeCaptureUnavailable("unsafe_root") from None
        finally:
            os.close(pack)
        return tuple(sorted(snapshot))

    @staticmethod
    def _raw_arguments(base_id: str) -> tuple[str, ...]:
        return ("diff", "--raw", "-z", "--no-abbrev", *_DIFF_OPTIONS, base_id, "--")

    def _tracked_metadata(
        self,
        pinned: _Workspace,
        base_id: str,
        deadline: float,
    ) -> tuple[
        bytes,
        list[ChangeMetadataEntry],
        dict[bytes, _Identity | None],
        tuple[str, ...],
        int,
    ]:
        """Read name/status metadata without numstat, patch or blob reads.

        The last value counts changed paths skipped because a CR or LF in a name cannot be an
        entry (issue #1019); their identities still take part in the stability check.
        """

        arguments = self._metadata_arguments(base_id)
        try:
            _, raw = self._git(pinned, arguments, deadline=deadline, limit=_LIST_LIMIT)
        except ValueError:
            raise ChangeCaptureUnavailable("unsupported_repository") from None
        fields = _nul_fields(raw)
        entries: list[ChangeMetadataEntry] = []
        paths: list[bytes] = []
        skipped = 0
        index = 0
        while index < len(fields):
            status = fields[index].decode("ascii", errors="replace")
            index += 1
            if status.startswith(("R", "C")):
                if index + 1 >= len(fields):
                    raise ChangeCaptureUnavailable("git_failed")
                old, new = fields[index], fields[index + 1]
                index += 2
                if not _safe_relative(old) or not _safe_relative(new):
                    raise ChangeCaptureUnavailable("unsafe_root")
                paths.extend((old, new))
                new_name = os.fsdecode(new)
                original = os.fsdecode(old) if status.startswith("R") else None
                if not metadata_path_representable(new_name) or (
                    original is not None and not metadata_path_representable(original)
                ):
                    skipped += 1
                    continue
                entries.append(ChangeMetadataEntry(status[:1], new_name, original_path=original))
                continue
            if index >= len(fields):
                raise ChangeCaptureUnavailable("git_failed")
            path = fields[index]
            index += 1
            if not _safe_relative(path):
                raise ChangeCaptureUnavailable("unsafe_root")
            paths.append(path)
            name = os.fsdecode(path)
            if not metadata_path_representable(name):
                skipped += 1
                continue
            entries.append(ChangeMetadataEntry(status[:1], name))
        identities = {path: _path_identity(pinned.descriptor, path) for path in paths}
        return raw, entries, identities, arguments, skipped

    @staticmethod
    def _metadata_arguments(base_id: str) -> tuple[str, ...]:
        options = tuple(option for option in _DIFF_OPTIONS if option != "--no-renames")
        return ("diff", "--name-status", "-z", "--find-renames=100%", *options, base_id, "--")

    def _untracked_metadata(
        self, pinned: _Workspace, deadline: float, baseline: _Baseline | None = None
    ) -> _UntrackedRead:
        """List untracked paths and stat them without opening their files.

        Files the task-start snapshot names with an unchanged identity are baseline (issue #1045):
        they are left out of the listing's entries and total, and their identities join the
        stability check so a write while the change is read retakes it.
        """

        excludes = self._repository_excludes_file(pinned, deadline)
        if excludes is None:
            excludes = _global_excludes_file(deadline)
        config = ("-c", f"core.excludesFile={excludes}") if excludes is not None else ()
        listing, listing_truncated = self._untracked_listing(pinned, config, deadline)
        paths, kept, preexisting = _apply_baseline(pinned, _nul_fields(listing), baseline)
        paths.sort()
        identities: dict[bytes, _Identity | None] = dict(kept)
        directories: list[bytes] = []
        for index, path in enumerate(paths):
            if index >= _MAX_UNTRACKED_FILES:
                break
            if path.endswith(b"/"):
                # An embedded repository is listed as its directory, never as a file of this
                # repository: it is no entry here, and its own change is read separately, as the
                # full capture reads it (issue #1045).
                if not _safe_relative(path[:-1]):
                    raise ChangeCaptureUnavailable("unsafe_root")
                directories.append(path[:-1])
                continue
            if not _safe_relative(path):
                raise ChangeCaptureUnavailable("unsafe_root")
            identities[path] = _path_identity(pinned.descriptor, path)
        return _UntrackedRead(
            len(paths),
            [],
            listing_truncated,
            listing,
            config,
            identities,
            frozenset(kept),
            frozenset(preexisting),
            tuple(directories),
        )

    def _tracked_sections(
        self,
        pinned: _Workspace,
        object_format: Literal["sha1", "sha256"],
        base_id: str,
        deadline: float,
        priority: tuple[bytes, ...] = (),
        *,
        prefix: bytes = b"",
    ) -> _TrackedRead:
        """Changed tracked files of one repository; ``prefix`` names a nested one's directory.

        A nested repository's diff carries its directory in every ``a/``/``b/`` path, so its
        sections read as paths of the outer working tree; its section paths stay relative to its
        own root here (every Git call and stability check needs them) and the caller prefixes
        them afterwards.
        """

        try:
            _, raw = self._git(
                pinned, self._raw_arguments(base_id), deadline=deadline, limit=_LIST_LIMIT
            )
        except ValueError:
            raise ChangeCaptureUnavailable("unsupported_repository") from None
        # The raw list reads trees and the index but no file or blob content; it is compared
        # again after the capture. Every content read below (counts, patch, verification) sits
        # between the identities taken here and the same identities taken by ``_verify_stable``:
        # each working copy, each loose object a diff may read and its fan-out directory (whose
        # times change when an object appears or disappears in it). The working-copy identity is
        # also the no-link fence.
        entries = _raw_entries(raw)
        rename_pairs = self._rename_pairs(pinned, base_id, deadline)
        if rename_pairs:
            entries, rename_targets = _fold_rename_pairs(entries, rename_pairs)
        else:
            rename_targets = {}
        identities: dict[bytes, _Identity | None] = {}
        for entry in entries:
            identities[entry.path] = _path_identity(pinned.descriptor, entry.path)
            for oid, mode in ((entry.src_oid, entry.src_mode), (entry.dst_oid, entry.dst_mode)):
                if mode in _BLOB_MODES and oid.strip("0"):
                    for path in _loose_paths(oid):
                        identities[path] = _path_identity(pinned.descriptor, path)
        try:
            _, numbers = self._git(
                pinned,
                ("diff", "--numstat", "-z", *_DIFF_OPTIONS, base_id, "--"),
                deadline=deadline,
                limit=_LIST_LIMIT,
            )
        except ValueError:
            raise ChangeCaptureUnavailable("unsupported_repository") from None
        counts: dict[bytes, tuple[str, str]] = {}
        for record in _nul_fields(numbers):
            parts = record.split(b"\t", 2)
            if len(parts) != 3:
                raise ChangeCaptureUnavailable("git_failed")
            counts[parts[2]] = (
                parts[0].decode("ascii", errors="replace"),
                parts[1].decode("ascii", errors="replace"),
            )
        sections: list[_Section] = []
        for entry in entries:
            section = _Section(
                entry.path,
                entry.status,
                False,
                *counts.get(entry.path, ("-", "-")),
                None,
                "credential_name" if _credential_name(entry.path) else None,
            )
            if section.omitted is None and not _worktree_side_safe(entry, identities[entry.path]):
                # A link, a special file or a second name for other bytes: Git would read what
                # it points at, so neither its content nor its line counts are shown.
                section.omitted = "not_regular_file"
                section.added = section.deleted = "-"
            sections.append(section)
        if rename_targets:
            sections = [
                replace(section, status="R") if section.path in rename_targets else section
                for section in sections
            ]
        read = _TrackedRead(
            raw,
            sections,
            identities,
            # Only a gitlink the base tree already held names a starting commit: one added during
            # the task (Git's null id) or replacing a file or link (a blob id) records none.
            gitlinks=tuple(
                (entry.path, entry.src_oid if entry.src_mode == "160000" else None)
                for entry in entries
                if entry.dst_mode == "160000" and entry.status != "D"
            ),
        )
        if not sections:
            return read
        by_path = {prefix + section.path: section for section in sections}
        try:
            _, whole = self._git(
                pinned,
                ("diff", *_patch_options(prefix), base_id, "--"),
                deadline=deadline,
                limit=_WHOLE_DIFF_LIMIT,
            )
        except ValueError:
            whole = None
        except ChangeCaptureUnavailable as exc:
            if not _ran_out(exc, deadline):
                raise
            # The deadline ran out inside the diff: every changed file is listed, none shown.
            for section in sections:
                if section.omitted is None:
                    section.omitted = "capture_limit"
            return read
        if whole is not None:
            for chunk in self._split_sections(whole):
                path = _section_path(chunk)
                section = by_path.get(path) if path is not None else None
                if section is not None and section.text is None and section.omitted is None:
                    section.text = _decode(chunk)
            for section in sections:
                if section.text is None and section.omitted is None:
                    section.omitted = "unreadable"
        else:
            # Declared deliverables take the per-file read budget first (tb4n2 R7).
            self._per_file_diffs(
                pinned,
                base_id,
                sorted(sections, key=lambda item: _tracked_read_rank(item, priority)),
                deadline,
                prefix,
            )
        self._verify_section_objects(
            pinned, object_format, entries, sections, identities, deadline, priority
        )
        return read

    def _rename_pairs(
        self, pinned: _Workspace, base_id: str, deadline: float
    ) -> tuple[tuple[bytes, bytes], ...]:
        """Read rename identity separately from the bounded no-renames content diff.

        Content capture keeps ``--no-renames`` for stable per-file sections.  This small metadata
        query lets the structural header distinguish a true Git rename from an unrelated delete
        plus add without inferring that relation from path names or bytes.
        """

        options = tuple(option for option in _DIFF_OPTIONS if option != "--no-renames")
        try:
            _, raw = self._git(
                pinned,
                ("diff", "--name-status", "-z", "--find-renames=50%", *options, base_id, "--"),
                deadline=deadline,
                limit=_LIST_LIMIT,
            )
        except ValueError:
            return ()
        except ChangeCaptureUnavailable as exc:
            if exc.reason in {"git_failed", "unsupported_repository"}:
                return ()
            raise
        fields = _nul_fields(raw)
        pairs: list[tuple[bytes, bytes]] = []
        index = 0
        while index < len(fields):
            status = fields[index]
            index += 1
            if not status.startswith(b"R"):
                if index >= len(fields):
                    break
                index += 1
                continue
            if index + 1 >= len(fields):
                raise ChangeCaptureUnavailable("git_failed")
            old, new = fields[index], fields[index + 1]
            index += 2
            if _safe_relative(old) and _safe_relative(new):
                pairs.append((old, new))
        return tuple(pairs)

    def _per_file_diffs(
        self,
        pinned: _Workspace,
        base_id: str,
        sections: list[_Section],
        deadline: float,
        prefix: bytes = b"",
    ) -> None:
        # The whole diff is larger than one bounded read. Fall back to one bounded read per file
        # so an oversized generated file cannot hide the rest of the change.
        count = 0
        for section in sections:
            if section.omitted is not None:
                continue
            if count >= _MAX_PER_FILE_DIFFS or _expired(deadline):
                section.omitted = "capture_limit"
                continue
            count += 1
            try:
                _, text = self._git(
                    pinned,
                    (
                        "diff",
                        *_patch_options(prefix),
                        base_id,
                        "--",
                        ":(literal)" + os.fsdecode(section.path),
                    ),
                    deadline=deadline,
                    limit=_PER_FILE_DIFF_LIMIT,
                )
            except ValueError:
                section.omitted = "too_large"
                continue
            except ChangeCaptureUnavailable as exc:
                if not _ran_out(exc, deadline):
                    raise
                # The deadline ran out inside this file's diff: it and the rest are not shown.
                section.omitted = "capture_limit"
                continue
            section.text = _decode(text) if text else None
            if section.text is None:
                section.omitted = "unreadable"

    def _verify_section_objects(
        self,
        pinned: _Workspace,
        object_format: Literal["sha1", "sha256"],
        entries: list[_RawEntry],
        sections: list[_Section],
        identities: dict[bytes, _Identity | None],
        deadline: float,
        priority: tuple[bytes, ...] = (),
    ) -> None:
        """Withhold every shown diff whose Git objects do not hash to their own names.

        Git trusts the object file it opens, so a loose object replaced by a link or a hard link to
        another repository's object, or a pack reached through a link, would show bytes from
        outside the workspace under a name the base tree commits to. Re-hashing each object a
        shown diff reads (the base side, and the index side Git uses for a file whose working
        copy it did not read) proves its bytes are the ones its name commits to.
        """

        verified: dict[str, _OmitReason | None] = {}
        budget = [_MAX_TOTAL_VERIFIED_OBJECT_BYTES]
        # Deliverables, then small files, take the verification budget first (tb4n2 R7): a
        # budget spent on large scratch blobs never withholds a declared output.
        for entry, section in sorted(
            zip(entries, sections, strict=True),
            key=lambda pair: _section_rank(pair[1], priority),
        ):
            if section.text is None:
                continue
            for oid, mode in ((entry.src_oid, entry.src_mode), (entry.dst_oid, entry.dst_mode)):
                if mode not in _BLOB_MODES or not oid.strip("0"):
                    continue
                if oid not in verified:
                    verified[oid] = self._verify_object(
                        pinned, object_format, oid, identities, deadline, budget
                    )
                reason = verified[oid]
                if reason is not None:
                    section.text = None
                    section.omitted = reason
                    if reason == "object_unverified":
                        section.added = section.deleted = "-"
                    break

    def _verify_object(
        self,
        pinned: _Workspace,
        object_format: Literal["sha1", "sha256"],
        oid: str,
        identities: dict[bytes, _Identity | None],
        deadline: float,
        budget: list[int],
    ) -> _OmitReason | None:
        """Prove one blob a shown diff read is the object its name commits to.

        A loose object must be a regular file of the service user, not group- or world-writable,
        reached without a link, still the file whose identity was taken before the diff read it
        (a hard-linked one, as a local clone makes, is fine: its bytes must still hash); it is
        inflated and hashed from that same open descriptor. The object is also read the way the
        diff read it (``git cat-file``, packs first) and hashed. Packs are fenced and pinned by
        ``_refuse_unsafe_object_store``.
        """

        fan_out, loose = _loose_paths(oid)
        fan_out_facts, loose_facts = identities.get(fan_out), identities.get(loose)
        if fan_out_facts is not None and not stat.S_ISDIR(fan_out_facts[0]):
            return "object_unverified"
        if fan_out_facts is not None and loose_facts is not None:
            if not stat.S_ISREG(loose_facts[0]) or not _owner_only(loose_facts):
                return "object_unverified"
            reason = _verify_loose_object(pinned.descriptor, loose, loose_facts, object_format, oid)
            if reason is not None:
                return reason
        if _expired(deadline):
            return "capture_limit"
        if budget[0] <= 0:
            return "capture_limit"
        limit = min(_MAX_VERIFIED_OBJECT_BYTES, budget[0])
        try:
            _, content = self._git(
                pinned, ("cat-file", "blob", oid), deadline=deadline, limit=limit
            )
        except ValueError:
            # Over its own bound the file is too large; over what is left of the total, the
            # capture reached its limit.
            return "too_large" if limit == _MAX_VERIFIED_OBJECT_BYTES else "capture_limit"
        except ChangeCaptureUnavailable as exc:
            if _ran_out(exc, deadline):
                return "capture_limit"
            if exc.reason != "git_failed":
                raise
            return "object_unverified"
        budget[0] -= len(content)
        hasher = hashlib.new(object_format)
        hasher.update(b"blob %d\0" % len(content))
        hasher.update(content)
        # ``content`` is an immutable ``bytes`` returned by the runner (which already overwrote
        # its own buffer); drop the reference so it is not kept beyond the hash.
        del content
        return None if hasher.hexdigest() == oid else "object_unverified"

    @staticmethod
    def _split_sections(diff: bytes) -> list[bytes]:
        if not diff:
            return []
        chunks: list[bytes] = []
        start = 0 if diff.startswith(_DIFF_SECTION) else diff.find(b"\n" + _DIFF_SECTION) + 1
        if start <= 0 and not diff.startswith(_DIFF_SECTION):
            return []
        while start < len(diff):
            following = diff.find(b"\n" + _DIFF_SECTION, start)
            end = len(diff) if following < 0 else following + 1
            chunks.append(diff[start:end])
            start = end
        return chunks

    def _untracked_listing(
        self, pinned: _Workspace, config: tuple[str, ...], deadline: float
    ) -> tuple[bytes, bool]:
        """Return the NUL-terminated untracked names that fit, and whether the listing was cut."""

        try:
            _, listing = self._git(
                pinned,
                (*config, "ls-files", "--others", "--exclude-standard", "-z"),
                deadline=deadline,
                limit=_LIST_LIMIT,
                keep_prefix_on_limit=True,
            )
        except GitOutputTruncated as exc:
            # Too many untracked paths to list: keep every whole path that fit and disclose the
            # rest as not listed, rather than losing the tracked change along with them.
            return exc.prefix[: exc.prefix.rfind(b"\0") + 1], True
        except ValueError:
            raise ChangeCaptureUnavailable("unsupported_repository") from None
        return listing, False

    def _untracked_sections(
        self,
        pinned: _Workspace,
        deadline: float,
        priority: tuple[bytes, ...] = (),
        *,
        baseline: _Baseline | None = None,
        prefix: bytes = b"",
        read_files: bool = True,
    ) -> _UntrackedRead:
        """Return the untracked total, their sections, and whether the listing was cut short.

        Declared deliverables (``priority``) are read first, so the untracked file limit and the
        deadline never skip one behind scratch files. Files the task-start snapshot (``baseline``)
        names with an unchanged identity are left out and counted (issue #1045); one that changed
        since is shown as a modification of a file that predates the task. ``prefix`` is a nested
        repository's directory, carried by every rendered path (issue #1045). Without
        ``read_files`` (a nested repository whose untracked files the snapshot does not fully
        list) every file is named as not shown and none is opened.
        """

        excludes = self._repository_excludes_file(pinned, deadline)
        if excludes is None:
            excludes = _global_excludes_file(deadline)
        config = ("-c", f"core.excludesFile={excludes}") if excludes is not None else ()
        listing, listing_truncated = self._untracked_listing(pinned, config, deadline)
        listed, kept, preexisting = _apply_baseline(pinned, _nul_fields(listing), baseline)
        paths = _untracked_order(pinned, listed, priority, deadline)
        sections: list[_Section] = []
        # Baseline files left out still join the stability check: one written while the change
        # is read takes the capture again.
        identities: dict[bytes, _Identity | None] = dict(kept)
        for index, path in enumerate(paths):
            if index >= _MAX_UNTRACKED_FILES:
                break
            shown = prefix + path
            status = "M" if path in preexisting else "A"
            if path.endswith(b"/"):
                # An embedded repository is listed as its directory; its files are not this
                # repository's change. Its own change is read separately (issue #1045), and this
                # entry stays only when that read could not be made.
                sections.append(_Section(shown, "A", True, "-", "-", None, "nested_repository"))
                continue
            if not _safe_relative(path):
                raise ChangeCaptureUnavailable("unsafe_root")
            if _credential_name(path):
                sections.append(
                    _Section(
                        shown, status, True, "-", "-", None, "credential_name", path in preexisting
                    )
                )
                continue
            if not read_files:
                sections.append(_Section(shown, status, True, "-", "-", None, "nested_untracked"))
                continue
            if _expired(deadline):
                sections.append(
                    _Section(
                        shown, status, True, "-", "-", None, "capture_limit", path in preexisting
                    )
                )
                continue
            identity = _path_identity(pinned.descriptor, path)
            outcome, content = _read_beneath(
                pinned.descriptor, path, _MAX_UNTRACKED_FILE_BYTES, identity
            )
            if outcome != "regular" and outcome != "executable":
                sections.append(
                    _Section(shown, status, True, "-", "-", None, outcome, path in preexisting)
                )
                continue
            assert content is not None
            identities[path] = identity
            text, added = _new_file_diff(shown, content, outcome == "executable")
            sections.append(
                _Section(shown, status, True, added, "0", text, None, path in preexisting)
            )
        return _UntrackedRead(
            len(paths),
            sections,
            listing_truncated,
            listing,
            config,
            identities,
            frozenset(kept),
            frozenset(preexisting),
        )

    def _verify_stable(
        self,
        pinned: _Workspace,
        base_id: str,
        tracked: _TrackedRead,
        untracked: _UntrackedRead,
        head: str | None,
        index: _Identity | None,
        packs: tuple[tuple[bytes, _Identity], ...],
        deadline: float,
    ) -> None:
        """Prove the capture is one state: nothing it read moved while it was assembled.

        The changed-file list, the identity (inode, size, modification and change times, link
        count) of every working copy, loose object and fan-out directory the diff could read and
        of every untracked file read, every pack-directory entry, the untracked listing, HEAD and
        the index are read again and must equal what the assembly saw. A write, a rename, a
        link swapped in and back out, or a commit in between changes one of them.
        """

        if self._refuse_unsafe_object_store(pinned) != packs:
            raise _ChangedDuringCapture
        try:
            arguments = tracked.arguments or self._raw_arguments(base_id)
            _, raw = self._git(pinned, arguments, deadline=deadline, limit=_LIST_LIMIT)
        except ValueError:
            raise _ChangedDuringCapture from None
        if raw != tracked.raw:
            raise _ChangedDuringCapture
        for identities in (tracked.identities, untracked.identities):
            for path, identity in identities.items():
                if _path_identity(pinned.descriptor, path) != identity:
                    raise _ChangedDuringCapture
        if untracked.listing is not None:
            listing, _ = self._untracked_listing(pinned, untracked.config, deadline)
            if listing != untracked.listing:
                raise _ChangedDuringCapture
        if self._rev(pinned, "HEAD^{commit}", deadline) != head:
            raise _ChangedDuringCapture
        if _path_identity(pinned.descriptor, b".git/index") != index:
            raise _ChangedDuringCapture

    def _repository_excludes_file(self, pinned: _Workspace, deadline: float) -> str | None:
        """Return a repository-level ``core.excludesFile``, which Git prefers over the global one.

        The hardened runner pins ``core.excludesFile`` on its command line, which would otherwise
        hide the repository's own setting and let files the owner ignores there be read.
        """

        code, raw = self._git(
            pinned,
            # ``--show-origin`` (Git 2.8), not ``--show-scope`` (2.26); see
            # ``_refuse_unsafe_config``.
            ("config", "--get-all", "--show-origin", "-z", "core.excludesFile"),
            deadline=deadline,
            limit=65_536,
            accepted=frozenset({0, 1}),
        )
        if code != 0:
            return None
        fields = _nul_fields(raw)
        if len(fields) % 2:
            raise ChangeCaptureUnavailable("git_failed")
        value: bytes | None = None
        for index in range(0, len(fields), 2):
            # Lowest precedence first; the runner's own command-line entry is last and skipped.
            # No system or global file is ever read, so every other entry is the repository's.
            if fields[index] != _COMMAND_LINE_ORIGIN:
                value = fields[index + 1]
        if not value:
            return None
        path = os.path.expanduser(os.fsdecode(value))
        return _existing_regular_file(
            path if os.path.isabs(path) else os.path.join(pinned.root, path)
        )

    # --- rendering ---------------------------------------------------------------------------

    def _render(
        self,
        base: ChangeBaseKind,
        base_id: str,
        sections: list[_Section],
        *,
        tracked: int,
        untracked: int,
        unlisted_untracked: int,
        untracked_listing_truncated: bool = False,
        baseline: _Baseline | None = None,
        baseline_unchanged: int = 0,
        nested: Sequence[_NestedRead] = (),
        inputs: tuple[TaskInputFile, ...] = (),
    ) -> CheckChangeCapture:
        body_budget = self._max_text_bytes - _HEADER_BUDGET
        body: list[bytes] = []
        used = 0
        for section in sections:
            if section.text is None:
                continue
            if used + len(section.text) > body_budget:
                section.text = None
                section.omitted = "capture_limit"
                continue
            body.append(section.text)
            used += len(section.text)
        omitted = sum(1 for section in sections if section.omitted is not None)
        omitted += unlisted_untracked
        header = _header(
            base,
            base_id,
            sections,
            tracked=tracked,
            untracked=untracked,
            omitted=omitted,
            unlisted_untracked=unlisted_untracked,
            untracked_listing_truncated=untracked_listing_truncated,
            baseline=baseline,
            baseline_unchanged=baseline_unchanged,
            nested=nested,
        )
        text = header + b"".join(body)
        return CheckChangeCapture(
            base=base,
            text=text,
            tracked_files=tracked,
            untracked_files=untracked,
            omitted_files=omitted,
            truncated=omitted > 0 or untracked_listing_truncated,
            base_commit=base_id,
            inputs=inputs,
        )


# Fixed sentences for a nested repository the header names (issue #1045); never Git output.
_NESTED_BASE_TEXT: Final[dict[ChangeBaseKind, str]] = {
    "task_start": "from the commit it held when the task started",
    "first_check": "from the commit it held when the task started",
    "head": (
        "from its HEAD when this check ran (no starting commit was recorded for it, or the "
        "recorded one is gone, so commits made in it during the task may be missing)"
    ),
    "empty": "from an empty tree (it had no commit when this check ran)",
}
# A gitlink whose HEAD at task start was not recorded starts from the commit the outer base tree
# records for it, which can be older than that HEAD (issue #1045).
_NESTED_BASE_TREE_TEXT: Final = (
    "from the commit the base above records for it (its own HEAD when the task started was not "
    "recorded, so any commits made in it before the task that the outer repository does not "
    "record are included too)"
)
_NESTED_UNTRACKED_TEXT: Final[dict[str, str]] = {
    "absent": (
        " Untracked files in it are named but not shown: the task-start record does not list "
        "them, so any of them may predate the task."
    ),
    "incomplete": (
        " Untracked files in it are named but not shown: the task-start list of them was "
        "incomplete, so any of them may predate the task."
    ),
}
_NESTED_REASON_TEXT: Final[dict[str, str]] = {
    "nested_limit": "more nested repositories than one check reads",
    "capture_limit": "the capture reached its time limit",
    "changed_during_capture": "it kept changing while it was read",
    "unsafe_root": "it failed a safety check",
    "unsupported_repository": "its Git configuration or layout is not supported",
    "not_git": "Git did not read it as a repository",
    "git_failed": "Git could not read it",
    "git_unavailable": "Git is not available",
    "redaction_incomplete": "it could not be redacted",
}


def _nested_lines(nested: Sequence[_NestedRead]) -> list[str]:
    lines: list[str] = []
    for read in nested:
        quoted = _quote_path(read.path + b"/")
        if len(quoted) > _MAX_LISTED_PATH_BYTES:
            quoted = quoted[: _MAX_LISTED_PATH_BYTES - 3] + "..."
        if read.sections is not None and read.base is not None:
            start = _NESTED_BASE_TREE_TEXT if read.from_base_tree else _NESTED_BASE_TEXT[read.base]
            untracked = (
                _NESTED_UNTRACKED_TEXT[read.untracked_unrecorded]
                if read.untracked_unrecorded is not None
                and (read.untracked or read.listing_truncated)
                else ""
            )
            lines.append(
                f"Nested repository {quoted}: its own change is shown under that directory, "
                f"{start}.{untracked}"
            )
        else:
            reason = _NESTED_REASON_TEXT.get(read.reason or "", "it could not be read")
            lines.append(f"Nested repository {quoted}: its own change is not shown ({reason}).")
    return lines


# A task input file larger than this is not read at all (issue #1045); one up to it keeps its head
# and tail within ``MAX_TASK_INPUT_TEXT_BYTES``.
_MAX_TASK_INPUT_READ_BYTES: Final = 1024 * 1024
_TASK_INPUT_ELISION: Final = (
    "\n[yoetz: {elided} of {total} bytes elided here; head and tail kept]\n"
)


def _task_input(
    pinned: _Workspace,
    relative: bytes,
    identity: _Identity,
    object_format: Literal["sha1", "sha256"],
    blob: str | None,
) -> TaskInputFile | None:
    """One read-only task input file, whole or head and tail (issue #1045); ``None`` to skip.

    ``blob`` is the base commit's blob for a tracked input: the bytes read must hash to it
    exactly (no filter or line-ending conversion applied), so content Git did not compare, or
    changed without Git noticing, is never carried as unchanged.
    """

    try:
        name = relative.decode("utf-8", errors="strict")
        outcome, content = _read_beneath(
            pinned.descriptor, relative, _MAX_TASK_INPUT_READ_BYTES, identity
        )
    except UnicodeDecodeError, _ChangedDuringCapture:
        return None
    if outcome not in {"regular", "executable"} or not content:
        return None
    if blob is not None:
        digest = hashlib.new(object_format, b"blob %d\0" % len(content))
        digest.update(content)
        if digest.hexdigest() != blob:
            return None
    if b"\0" in content[:_BINARY_PROBE_BYTES]:
        return None
    total = len(content)
    if total <= MAX_TASK_INPUT_TEXT_BYTES:
        text = _decode(content)
    else:
        marker = _TASK_INPUT_ELISION.format(elided="0" * len(str(total)), total=total)
        side = (MAX_TASK_INPUT_TEXT_BYTES - len(marker.encode("utf-8"))) // 2
        head = content[:side].decode("utf-8", errors="ignore")
        tail = content[total - side :].decode("utf-8", errors="ignore")
        elided = total - len(head.encode("utf-8")) - len(tail.encode("utf-8"))
        text = _decode(
            (head + _TASK_INPUT_ELISION.format(elided=elided, total=total) + tail).encode("utf-8")
        )
    try:
        return TaskInputFile(name, text, total)
    except ValueError:
        return None


def _header(
    base: ChangeBaseKind,
    base_id: str,
    sections: list[_Section],
    *,
    tracked: int,
    untracked: int,
    omitted: int,
    unlisted_untracked: int,
    untracked_listing_truncated: bool = False,
    baseline: _Baseline | None = None,
    baseline_unchanged: int = 0,
    nested: Sequence[_NestedRead] = (),
) -> bytes:
    lines = [
        "Yoetz check-time change: captured by the Yoetz service when this check ran; "
        "the agent did not supply it.",
        {
            "task_start": "Base: the commit HEAD named when this task started.",
            "first_check": (
                f"Base: {base_id[:12]}, the state at this task's first check (the commit at task "
                "start was not recorded). Work committed before that check is not part of this "
                "change."
            ),
            "head": (
                "Base: HEAD when this check ran. The commit at task start was not recorded or "
                "is no longer available, so commits made during the task may be missing from "
                "this change."
            ),
            "empty": "Base: an empty tree. The repository had no commit when this check ran.",
        }[base],
        (
            "Scope: committed and uncommitted changes to tracked files since the base, plus "
            "untracked files Git does not ignore. Uncommitted or untracked work that already "
            "existed when the base was named is included too."
        )
        if baseline is None
        else (
            "Scope: committed and uncommitted changes to tracked files since the base, plus "
            "untracked files Git does not ignore, except untracked files that already existed "
            "when the task started and have not changed since. Uncommitted work on tracked files "
            "that already existed when the base was named is included too."
        ),
    ]
    if baseline is not None:
        # Issue #1045: what predates the task is its starting state, not the agent's work.
        if baseline_unchanged:
            lines.append(
                f"Untracked files that already existed when the task started and are unchanged "
                f"since: {baseline_unchanged}. They are the task's starting state, not part of "
                "this change, and are not listed."
            )
        if not baseline.complete:
            lines.append(
                "The task-start list of untracked files was incomplete, so an untracked file "
                "listed below as added may predate the task."
            )
    lines.extend(_nested_lines(nested))
    if not tracked and not untracked and not untracked_listing_truncated:
        lines.append("Changed files: none. The working tree matches the base.")
    else:
        lines.append(
            f"Changed files: {tracked} tracked, {untracked} untracked. Not shown: {omitted}."
        )
        lines.append("Files:")
        # The body was fitted to ``_HEADER_BUDGET`` before this header existed, so the listing
        # stops early rather than letting long paths and notes overrun the object bound.
        used = sum(len(line) + 1 for line in lines) + _HEADER_TRAILER_ROOM
        listed = 0
        for section in sections[:_MAX_LISTED_FILES]:
            quoted = _quote_path(section.path)
            if len(quoted) > _MAX_LISTED_PATH_BYTES:
                quoted = quoted[: _MAX_LISTED_PATH_BYTES - 3] + "..."
            if section.added != "-":
                counts = f" (+{section.added} -{section.deleted})"
            elif (section.untracked and section.text is None) or (
                section.omitted in _WITHHELD_COUNTS
            ):
                counts = ""
            else:
                counts = " (binary)"
            notes = [
                note
                for note in (
                    "untracked" if section.untracked else "",
                    "existed when the task started; its earlier content was not recorded, so it "
                    "is shown whole"
                    if section.preexisting
                    else "",
                    "" if section.omitted is None else _OMIT_TEXT[section.omitted],
                )
                if note
            ]
            suffix = "" if not notes else " " + "; ".join(notes)
            line = f"  {section.status} {quoted}{counts}{suffix}"
            if used + len(line) + 1 > _HEADER_BUDGET:
                break
            lines.append(line)
            used += len(line) + 1
            listed += 1
        if len(sections) > listed:
            hidden = sum(1 for section in sections[listed:] if section.omitted)
            lines.append(
                f"  ... {len(sections) - listed} more changed files are not listed "
                f"({hidden} of them not shown)."
            )
        if unlisted_untracked:
            lines.append(
                f"  ... {unlisted_untracked} more untracked files are not listed or shown "
                "(untracked file limit)."
            )
        if untracked_listing_truncated:
            lines.append(
                "  ... further untracked files may exist but are not listed or shown: the "
                "untracked listing hit its size or time limit, so the untracked count above is a "
                "lower bound."
            )
    lines.append("End of header. The unified diff follows.")
    return ("\n".join(lines) + "\n").encode("ascii", errors="replace")


def _new_file_diff(path: bytes, content: bytes, executable: bool) -> tuple[bytes, str]:
    mode = "100755" if executable else "100644"
    head = [
        f"diff --git {_prefixed('a/', path)} {_prefixed('b/', path)}",
        f"new file mode {mode}",
    ]
    if not content:
        return ("\n".join(head) + "\n").encode("ascii"), "0"
    if b"\0" in content[:_BINARY_PROBE_BYTES]:
        head.append(f"Binary files /dev/null and {_prefixed('b/', path)} differ")
        return ("\n".join(head) + "\n").encode("ascii"), "-"
    lines = content.split(b"\n")
    trailing_newline = content.endswith(b"\n")
    if trailing_newline:
        lines = lines[:-1]
    head.append("--- /dev/null")
    head.append(f"+++ {_prefixed('b/', path)}")
    head.append(f"@@ -0,0 +1,{len(lines)} @@" if len(lines) != 1 else "@@ -0,0 +1 @@")
    rendered = ("\n".join(head) + "\n").encode("ascii") + b"".join(
        b"+" + line + b"\n" for line in lines
    )
    if not trailing_newline:
        rendered += b"\\ No newline at end of file\n"
    return _decode(rendered), str(len(lines))


def _numstat_rows(numbers: bytes) -> list[tuple[bytes, int | None, int | None]]:
    """``(path, added, removed)`` from ``git diff --numstat -z --no-renames``; ``-`` is ``None``."""

    rows: list[tuple[bytes, int | None, int | None]] = []
    for record in _nul_fields(numbers):
        parts = record.split(b"\t", 2)
        if len(parts) != 3 or not _safe_relative(parts[2]):
            raise ChangeCaptureUnavailable("git_failed")
        counts: list[int | None] = []
        for part in parts[:2]:
            if part == b"-":
                counts.append(None)
            elif part.isdigit() and len(part) <= 12:
                counts.append(int(part))
            else:
                raise ChangeCaptureUnavailable("git_failed")
        rows.append((parts[2], counts[0], counts[1]))
    return rows


def _read_beneath(
    root_descriptor: int, path: bytes, limit: int, expected: _Identity | None
) -> tuple[_OmitReason | Literal["regular", "executable"], bytes | None]:
    """Open ``path`` under the root one component at a time, never following a link.

    ``expected`` is the path's identity taken just before; a file that is not that file when
    opened, or that changed while it was read, raises ``_ChangedDuringCapture`` so the whole
    capture is taken again rather than keeping a mix of two versions.
    """

    parts = path.split(b"/")
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
        facts = os.fstat(descriptor)
        expected_uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
        if not stat.S_ISREG(facts.st_mode) or facts.st_uid != expected_uid:
            return "not_regular_file", None
        if facts.st_nlink != 1:
            # A second name can be a link to content outside the workspace.
            return "not_regular_file", None
        if _identity(facts) != expected:
            raise _ChangedDuringCapture
        if facts.st_size > limit:
            return "too_large", None
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(_READ_CHUNK, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                return "too_large", None
        if total != facts.st_size or _identity(os.fstat(descriptor)) != expected:
            raise _ChangedDuringCapture
        executable = bool(stat.S_IMODE(facts.st_mode) & 0o111)
        return ("executable" if executable else "regular"), b"".join(chunks)
    except OSError as exc:
        # ELOOP/ENOTDIR: a component is a link or not a directory. Anything else is unreadable.
        if exc.errno in {errno.ELOOP, errno.ENOTDIR, errno.ENXIO}:
            return "not_regular_file", None
        return "unreadable", None
    finally:
        for descriptor in reversed(opened):
            os.close(descriptor)


def _read_prefix_beneath(root_descriptor: int, path: bytes, limit: int) -> bytes | None:
    """Read at most ``limit`` bytes from the start of ``path`` under the root, or ``None``.

    Opened one component at a time from the validated root descriptor without following a link,
    like ``_read_beneath``; only a singly linked regular file the current user owns is read.
    """

    parts = path.split(b"/")
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
        facts = os.fstat(descriptor)
        expected_uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
        if not stat.S_ISREG(facts.st_mode) or facts.st_uid != expected_uid or facts.st_nlink != 1:
            return None
        chunks: list[bytes] = []
        total = 0
        while total < limit:
            chunk = os.read(descriptor, min(_READ_CHUNK, limit - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        return b"".join(chunks)
    except OSError:
        return None
    finally:
        for descriptor in reversed(opened):
            os.close(descriptor)


def _referenced(
    content: bytes, paths: Mapping[bytes, list[int]], names: Mapping[bytes, list[int]]
) -> set[int]:
    """The candidate indexes a one-line quoted literal in ``content`` names (see caller)."""

    found: set[int] = set()
    for match in _STRING_LITERAL.finditer(content):
        literal = match.group(1) or match.group(2) or match.group(3) or b""
        found.update(paths.get(literal, ()))
        found.update(names.get(literal, ()))
        start = literal.find(b"/")
        while start != -1:
            found.update(paths.get(literal[start + 1 :], ()))
            start = literal.find(b"/", start + 1)
    return found


def _identity(facts: os.stat_result) -> _Identity:
    return (
        facts.st_mode,
        facts.st_dev,
        facts.st_ino,
        facts.st_size,
        facts.st_mtime_ns,
        facts.st_ctime_ns,
        facts.st_nlink,
        facts.st_uid,
    )


def _path_identity(root_descriptor: int, path: bytes) -> _Identity | None:
    """The identity of ``path`` under the root, reached without following any link.

    ``None`` when it does not exist; ``_BLOCKED`` when a component on the way is a link or not a
    directory, which is never a regular file.
    """

    parts = path.split(b"/")
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    opened: list[int] = []
    current = root_descriptor
    try:
        for part in parts[:-1]:
            current = os.open(part, directory_flags, dir_fd=current)
            opened.append(current)
        return _identity(os.stat(parts[-1], dir_fd=current, follow_symlinks=False))
    except FileNotFoundError:
        return None
    except OSError:
        return _BLOCKED
    finally:
        for descriptor in reversed(opened):
            os.close(descriptor)


def _directory_holds_file(root_descriptor: int, path: bytes) -> bool | None:
    """Whether any non-directory entry lies beneath the directory ``path`` under the root (#1002).

    Metadata only: every directory is opened ``O_NOFOLLOW`` from its parent's descriptor and only
    listed; no entry is ``stat``-ed through a link and no file is opened or read. A link, socket or
    other non-directory entry counts as content, so only a directory that is empty or holds nothing
    but empty directories answers ``False``. ``None`` when a component cannot be opened or the walk
    exceeds its entry or open-descriptor bound.
    """

    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    pending: list[int] = []
    current = root_descriptor
    try:
        for part in path.split(b"/"):
            opened = os.open(part, directory_flags, dir_fd=current)
            if current != root_descriptor:
                os.close(current)
            current = opened
        pending.append(current)
        current = root_descriptor
        visited = 0
        while pending:
            directory = pending.pop()
            try:
                with os.scandir(directory) as entries:
                    for entry in entries:
                        visited += 1
                        if visited > _MAX_DIRECTORY_WALK_ENTRIES:
                            return None
                        if not entry.is_dir(follow_symlinks=False):
                            return True
                        if len(pending) >= _MAX_DIRECTORY_WALK_OPEN:
                            return None
                        pending.append(
                            os.open(os.fsencode(entry.name), directory_flags, dir_fd=directory)
                        )
            finally:
                os.close(directory)
        return False
    except OSError:
        return None
    finally:
        if current != root_descriptor:
            os.close(current)
        for descriptor in pending:
            os.close(descriptor)


def _loose_paths(oid: str) -> tuple[bytes, bytes]:
    """The fan-out directory and loose object path of ``oid``, relative to the root."""

    fan_out = b".git/objects/" + oid[:2].encode("ascii")
    return fan_out, fan_out + b"/" + oid[2:].encode("ascii")


def _owner_only(identity: _Identity) -> bool:
    """A file of the service user that no other user may write."""

    expected_uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
    mode, _, _, _, _, _, _, owner = identity
    return owner == expected_uid and not stat.S_IMODE(mode) & 0o022


def _verify_loose_object(
    root_descriptor: int,
    path: bytes,
    expected: _Identity,
    object_format: Literal["sha1", "sha256"],
    oid: str,
) -> _OmitReason | None:
    """Inflate and hash one loose object from a descriptor bound to its recorded identity."""

    if expected[3] > _MAX_VERIFIED_OBJECT_BYTES:
        return "too_large"
    parts = path.split(b"/")
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    file_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    opened: list[int] = []
    compressed = bytearray()
    inflated = bytearray()
    current = root_descriptor
    try:
        for part in parts[:-1]:
            current = os.open(part, directory_flags, dir_fd=current)
            opened.append(current)
        descriptor = os.open(parts[-1], file_flags, dir_fd=current)
        opened.append(descriptor)
        if _identity(os.fstat(descriptor)) != expected:
            raise _ChangedDuringCapture
        while len(compressed) <= expected[3]:
            chunk = os.read(descriptor, _READ_CHUNK)
            if not chunk:
                break
            compressed += chunk
        if len(compressed) != expected[3] or _identity(os.fstat(descriptor)) != expected:
            raise _ChangedDuringCapture
        inflater = zlib.decompressobj()
        inflated += inflater.decompress(compressed, _MAX_VERIFIED_OBJECT_BYTES + 64)
        if inflater.unconsumed_tail:
            return "too_large"
        if not inflater.eof:
            return "object_unverified"
        header_end = inflated.find(b"\0", 0, 64)
        if header_end < 0 or bytes(inflated[:header_end]) != b"blob %d" % (
            len(inflated) - header_end - 1
        ):
            return "object_unverified"
        hasher = hashlib.new(object_format)
        hasher.update(inflated)
        return None if hasher.hexdigest() == oid else "object_unverified"
    except OSError, zlib.error:
        return "object_unverified"
    finally:
        compressed[:] = bytes(len(compressed))
        inflated[:] = bytes(len(inflated))
        for descriptor in reversed(opened):
            os.close(descriptor)


def _worktree_side_safe(entry: _RawEntry, identity: _Identity | None) -> bool:
    """Whether Git reading this entry's working copy stays within the workspace.

    A deleted file has no working copy and a submodule shows only commit ids. Anything else must
    be a regular file of the service user with a single link, exactly as for untracked files.
    """

    if entry.dst_mode in {"000000", "160000"}:
        return True
    if identity is None:
        return False
    expected_uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
    mode, _, _, _, _, _, links, owner = identity
    return stat.S_ISREG(mode) and links == 1 and owner == expected_uid


def _raw_entries(raw: bytes) -> list[_RawEntry]:
    """Parse ``git diff --raw -z --no-abbrev`` (renames off): one entry per changed path."""

    fields = _nul_fields(raw)
    if len(fields) % 2:
        raise ChangeCaptureUnavailable("git_failed")
    entries: list[_RawEntry] = []
    for index in range(0, len(fields), 2):
        meta = fields[index].decode("ascii", errors="replace")
        path = fields[index + 1]
        parts = meta.split(" ")
        if len(parts) != 5 or not parts[0].startswith(":"):
            raise ChangeCaptureUnavailable("git_failed")
        src_mode, dst_mode, src_oid, dst_oid, status = parts[0][1:], *parts[1:]
        if any(
            not value or any(character not in "0123456789abcdef" for character in value)
            for value in (src_mode, dst_mode, src_oid, dst_oid)
        ):
            raise ChangeCaptureUnavailable("git_failed")
        if not _safe_relative(path):
            raise ChangeCaptureUnavailable("unsafe_root")
        entries.append(_RawEntry(status[:1] or "M", path, src_mode, dst_mode, src_oid, dst_oid))
    return entries


def _fold_rename_pairs(
    entries: list[_RawEntry], pairs: tuple[tuple[bytes, bytes], ...]
) -> tuple[list[_RawEntry], dict[bytes, bytes]]:
    """Fold Git's rename metadata into the no-renames raw entries."""

    by_path = {entry.path: entry for entry in entries}
    replacements: dict[bytes, _RawEntry] = {}
    renamed: dict[bytes, bytes] = {}
    for old, new in pairs:
        source = by_path.get(old)
        target = by_path.get(new)
        if source is None or target is None or old == new:
            continue
        replacements[new] = _RawEntry(
            "R",
            new,
            source.src_mode,
            target.dst_mode,
            source.src_oid,
            target.dst_oid,
        )
        renamed[new] = old
    if not replacements:
        return entries, {}
    folded: list[_RawEntry] = []
    old_paths = set(renamed.values())
    for entry in entries:
        if entry.path in renamed:
            folded.append(replacements[entry.path])
        elif entry.path in old_paths:
            continue
        else:
            folded.append(entry)
    return folded, renamed


def _verify_same_root(pinned: _Workspace) -> None:
    """The root pathname and its ``.git`` must still be the directories that were validated."""

    try:
        held = os.fstat(pinned.descriptor)
        current = os.lstat(pinned.root)
        git_current = os.lstat(pinned.root / ".git")
    except OSError:
        raise ChangeCaptureUnavailable("unsafe_root") from None
    if (
        (held.st_dev, held.st_ino) != pinned.root_identity
        or not stat.S_ISDIR(current.st_mode)
        or (current.st_dev, current.st_ino) != pinned.root_identity
        or not stat.S_ISDIR(git_current.st_mode)
        or (git_current.st_dev, git_current.st_ino) != pinned.git_identity
    ):
        raise ChangeCaptureUnavailable("unsafe_root")


def _remaining(deadline: float) -> float:
    """Time left for one Git call: at most ``_GIT_CALL_SECONDS`` and never past the deadline."""

    remaining = deadline - time.monotonic()
    if remaining <= 0.0:
        raise ChangeCaptureUnavailable("git_failed")
    return min(_GIT_CALL_SECONDS, remaining)


def _expired(deadline: float) -> bool:
    return time.monotonic() >= deadline


def _ran_out(exc: ChangeCaptureUnavailable, deadline: float) -> bool:
    """A Git call failed because the deadline ran out, never because the root was replaced."""

    return exc.reason == "git_failed" and _expired(deadline)


def _global_excludes_file(deadline: float) -> str | None:
    """Return the owner's own global Git ignore file, read without loading global config helpers.

    The hardened runner disables global config, which would otherwise make files the owner ignores
    everywhere (for example local secrets) look untracked. Only the ``core.excludesFile`` value is
    read here; no other global setting reaches the capture. The read shares the capture deadline,
    and a read that runs out of time makes the capture unavailable rather than guessing the file.
    """

    executable = shutil.which("git", path=os.defpath)
    home = os.environ.get("HOME") or os.path.expanduser("~")
    environment = {
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": home,
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.defpath,
    }
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        environment["XDG_CONFIG_HOME"] = xdg
    candidate: str | None = None
    if executable is not None:
        try:
            completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
                (
                    executable,
                    "config",
                    "--global",
                    "--includes",
                    "--path",
                    "--get",
                    "core.excludesFile",
                ),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=min(_GLOBAL_CONFIG_SECONDS, _remaining(deadline)),
                env=environment,
                cwd=home if os.path.isdir(home) else "/",
                check=False,
            )
            if completed.returncode == 0 and len(completed.stdout) <= 4_096:
                candidate = os.fsdecode(completed.stdout.rstrip(b"\n")) or None
        except subprocess.TimeoutExpired:
            raise ChangeCaptureUnavailable("git_failed") from None
        except OSError, subprocess.SubprocessError:
            candidate = None
    if candidate is None:
        base = xdg if xdg else os.path.join(home, ".config")
        candidate = os.path.join(base, "git", "ignore")
    return _existing_regular_file(candidate)


def _existing_regular_file(candidate: str) -> str | None:
    if not os.path.isabs(candidate) or any(marker in candidate for marker in "\0\n\r"):
        return None
    try:
        if not stat.S_ISREG(os.stat(candidate).st_mode):
            return None
    except OSError:
        return None
    return candidate
