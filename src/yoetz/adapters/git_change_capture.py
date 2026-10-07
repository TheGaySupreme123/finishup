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
import shutil
import stat
import subprocess
import time
import zlib
from collections.abc import Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Final, Literal

from yoetz.adapters.git_subject_state import (
    GitOutputTruncated,
    discover_workspace_root,
    local_workspace_root,
    open_local_workspace,
    run_read_only_git,
)
from yoetz.ports.change_capture import (
    MAX_CHECK_CHANGE_TEXT_BYTES,
    ChangeBaseKind,
    ChangeCaptureUnavailable,
    ChangeMetadataEntry,
    CheckChangeCapture,
    CheckChangeMetadata,
    RequestedPathProbe,
    TaskChangeBase,
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
_CAPTURE_CONFIG: Final = (
    "--no-replace-objects",
    "-c",
    "core.quotePath=true",
    "-c",
    "protocol.allow=never",
)
_DIFF_OPTIONS: Final = (
    "--no-color",
    "--no-ext-diff",
    "--no-textconv",
    "--no-renames",
    "--no-relative",
    "--submodule=short",
    "-O/dev/null",
    "--src-prefix=a/",
    "--dst-prefix=b/",
)
# ``--unified`` implies a patch, so it is added only where the patch itself is read.
_PATCH_OPTIONS: Final = (*_DIFF_OPTIONS, "--unified=3")
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
]
_OMIT_TEXT: Final[dict[_OmitReason, str]] = {
    "credential_name": "not shown: listed by name only, as for every file named like this",
    "capture_limit": "not shown: the capture reached its size, time or file limit",
    "too_large": "not shown: too large for this capture",
    "not_regular_file": "not shown: links, special files and multiply linked files are never read",
    "unreadable": "not shown: could not be read safely",
    "object_unverified": "not shown: a Git object its diff needs could not be verified",
}
# Omitted for what the file is, not its size: its line counts are not shown either.
_WITHHELD_COUNTS: Final[frozenset[_OmitReason]] = frozenset(
    {"not_regular_file", "unreadable", "object_unverified"}
)
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


@dataclass(slots=True)
class _UntrackedRead:
    total: int
    sections: list[_Section]
    listing_truncated: bool
    listing: bytes | None
    config: tuple[str, ...]
    identities: dict[bytes, _Identity | None]


@dataclass(slots=True)
class _Section:
    path: bytes
    status: str
    untracked: bool
    added: str
    deleted: str
    text: bytes | None
    omitted: _OmitReason | None


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


def _requested_relative_path(root: Path, value: str) -> bytes | None:
    """The root-relative form of one requested path, or ``None`` when it is not under the root.

    Lexical only: ``.``/``..`` segments are resolved textually and a result that leaves the root
    is outside. Links are never followed here; ``_path_identity`` refuses them on the way down.
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
    if encoded in {b".", b""} or not _safe_relative(encoded) or encoded.startswith(b".git/"):
        return None
    return encoded


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
        return TaskChangeBase(object_format, head or _EMPTY_TREES[object_format])

    def capture(self, workspace: str, base: TaskChangeBase | None) -> CheckChangeCapture:
        # One deadline bounds the whole capture: every Git call gets at most what is left of it.
        # Assembly may use its first part; the rest is kept for the closing stability check.
        started = time.monotonic()
        deadline = started + self._deadline_seconds
        assembly = started + self._deadline_seconds * _ASSEMBLY_SHARE
        pinned = self._open(workspace, assembly)
        self._refuse_unsafe_config(pinned, assembly)
        self._refuse_unsafe_object_store(pinned)
        object_format = self._object_format(pinned, assembly)
        for _ in range(_CAPTURE_ATTEMPTS):
            try:
                return self._capture_once(pinned, object_format, base, assembly, deadline)
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
        queried = [path for path in inside if identities[path] != _BLOCKED]
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
        probes: list[RequestedPathProbe] = []
        for location, path in located:
            if path is None:
                probes.append(RequestedPathProbe(location))
                continue
            identity = identities[path]
            source = sources.get(path)
            probes.append(
                RequestedPathProbe(
                    location,
                    os.fsdecode(path),
                    None if identity == _BLOCKED else identity is not None,
                    None if path in unknown else path in ignored,
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

        tracked_raw, tracked_entries, tracked_identities, tracked_arguments = (
            self._tracked_metadata(pinned, base_id, assembly)
        )
        index = _path_identity(pinned.descriptor, b".git/index")
        untracked = self._untracked_metadata(pinned, assembly)
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
        metadata_paths = tuple(sorted(untracked.identities, key=bytes))
        entries = tuple(
            [
                ChangeMetadataEntry(
                    entry.status,
                    entry.path,
                    original_path=entry.original_path,
                )
                for entry in tracked_entries
            ]
            + [
                ChangeMetadataEntry("A", os.fsdecode(path), untracked=True)
                for path in metadata_paths
            ]
        )
        omitted = untracked.total - len(metadata_paths)
        return CheckChangeMetadata(
            base=base_kind,
            entries=entries,
            tracked_files=len(tracked_entries),
            untracked_files=untracked.total,
            omitted_files=omitted,
            truncated=omitted > 0 or untracked.listing_truncated,
            base_commit=base_id,
        )

    def _capture_once(
        self,
        pinned: _Workspace,
        object_format: Literal["sha1", "sha256"],
        base: TaskChangeBase | None,
        assembly: float,
        deadline: float,
    ) -> CheckChangeCapture:
        packs = self._refuse_unsafe_object_store(pinned)
        head = self._rev(pinned, "HEAD^{commit}", assembly)
        index = _path_identity(pinned.descriptor, b".git/index")
        base_kind: ChangeBaseKind
        base_id: str | None = None
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
        tracked = self._tracked_sections(pinned, object_format, base_id, assembly)
        untracked = _UntrackedRead(0, [], True, None, (), {})
        if not _expired(assembly):
            try:
                untracked = self._untracked_sections(pinned, assembly)
            except ChangeCaptureUnavailable as exc:
                if not _ran_out(exc, assembly):
                    raise
        # Past the deadline no untracked file is listed or read; the header says the untracked
        # count is a lower bound, and the tracked change above still stands.
        self._verify_stable(pinned, base_id, tracked, untracked, head, index, packs, deadline)
        sections = [*tracked.sections, *untracked.sections]
        sections.sort(key=lambda item: item.path)
        return self._render(
            base_kind,
            base_id,
            sections,
            tracked=len(tracked.sections),
            untracked=untracked.total,
            unlisted_untracked=untracked.total - len(untracked.sections),
            untracked_listing_truncated=untracked.listing_truncated,
        )

    # --- Git access --------------------------------------------------------------------------

    @staticmethod
    def _open(workspace: str, deadline: float) -> _Workspace:
        if shutil.which("git", path=os.defpath) is None:
            raise ChangeCaptureUnavailable("git_unavailable")
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
                ("rev-parse", "--path-format=absolute", "--show-toplevel", "--git-dir"),
                deadline=deadline,
                limit=8_192,
            )
        except ValueError:
            raise ChangeCaptureUnavailable("unsafe_root") from None
        if located.rstrip(b"\n").split(b"\n") != [
            os.fsencode(validated_root),
            os.fsencode(validated_root / ".git"),
        ]:
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
        code, raw = self._git(
            pinned,
            ("rev-parse", "--verify", "--quiet", "--end-of-options", spec),
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
        ``--show-scope`` needs Git 2.26; an older Git rejects it, and the capture is then
        unavailable rather than taken without this check.
        """

        try:
            _, listing = self._git(
                pinned,
                ("config", "--list", "--name-only", "--includes", "--show-scope", "-z"),
                deadline=deadline,
                limit=1_048_576,
            )
        except ValueError:
            raise ChangeCaptureUnavailable("unsupported_repository") from None
        fields = _nul_fields(listing)
        if len(fields) % 2:
            raise ChangeCaptureUnavailable("git_failed")
        for index in range(0, len(fields), 2):
            if fields[index] == b"command":
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
    ]:
        """Read name/status metadata without numstat, patch or blob reads."""

        arguments = self._metadata_arguments(base_id)
        try:
            _, raw = self._git(pinned, arguments, deadline=deadline, limit=_LIST_LIMIT)
        except ValueError:
            raise ChangeCaptureUnavailable("unsupported_repository") from None
        fields = _nul_fields(raw)
        entries: list[ChangeMetadataEntry] = []
        paths: list[bytes] = []
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
                entries.append(
                    ChangeMetadataEntry(
                        status[:1],
                        os.fsdecode(new),
                        original_path=os.fsdecode(old) if status.startswith("R") else None,
                    )
                )
                continue
            if index >= len(fields):
                raise ChangeCaptureUnavailable("git_failed")
            path = fields[index]
            index += 1
            if not _safe_relative(path):
                raise ChangeCaptureUnavailable("unsafe_root")
            paths.append(path)
            entries.append(ChangeMetadataEntry(status[:1], os.fsdecode(path)))
        identities = {path: _path_identity(pinned.descriptor, path) for path in paths}
        return raw, entries, identities, arguments

    @staticmethod
    def _metadata_arguments(base_id: str) -> tuple[str, ...]:
        options = tuple(option for option in _DIFF_OPTIONS if option != "--no-renames")
        return ("diff", "--name-status", "-z", "--find-renames=100%", *options, base_id, "--")

    def _untracked_metadata(self, pinned: _Workspace, deadline: float) -> _UntrackedRead:
        """List untracked paths and stat them without opening their files."""

        excludes = self._repository_excludes_file(pinned, deadline)
        if excludes is None:
            excludes = _global_excludes_file(deadline)
        config = ("-c", f"core.excludesFile={excludes}") if excludes is not None else ()
        listing, listing_truncated = self._untracked_listing(pinned, config, deadline)
        paths = sorted(_nul_fields(listing))
        identities: dict[bytes, _Identity | None] = {}
        for index, path in enumerate(paths):
            if index >= _MAX_UNTRACKED_FILES:
                break
            if path.endswith(b"/") or not _safe_relative(path):
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
        )

    def _tracked_sections(
        self,
        pinned: _Workspace,
        object_format: Literal["sha1", "sha256"],
        base_id: str,
        deadline: float,
    ) -> _TrackedRead:
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
        read = _TrackedRead(raw, sections, identities)
        if not sections:
            return read
        by_path = {section.path: section for section in sections}
        try:
            _, whole = self._git(
                pinned,
                ("diff", *_PATCH_OPTIONS, base_id, "--"),
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
            self._per_file_diffs(pinned, base_id, sections, deadline)
        self._verify_section_objects(pinned, object_format, entries, sections, identities, deadline)
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
        self, pinned: _Workspace, base_id: str, sections: list[_Section], deadline: float
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
                        *_PATCH_OPTIONS,
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
        for entry, section in zip(entries, sections, strict=True):
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

    def _untracked_sections(self, pinned: _Workspace, deadline: float) -> _UntrackedRead:
        """Return the untracked total, their sections, and whether the listing was cut short."""

        excludes = self._repository_excludes_file(pinned, deadline)
        if excludes is None:
            excludes = _global_excludes_file(deadline)
        config = ("-c", f"core.excludesFile={excludes}") if excludes is not None else ()
        listing, listing_truncated = self._untracked_listing(pinned, config, deadline)
        paths = sorted(path for path in _nul_fields(listing))
        sections: list[_Section] = []
        identities: dict[bytes, _Identity | None] = {}
        for index, path in enumerate(paths):
            if index >= _MAX_UNTRACKED_FILES:
                break
            if path.endswith(b"/"):
                # An embedded repository is listed as its directory; its files are not this
                # repository's change.
                sections.append(_Section(path, "A", True, "-", "-", None, "not_regular_file"))
                continue
            if not _safe_relative(path):
                raise ChangeCaptureUnavailable("unsafe_root")
            if _credential_name(path):
                sections.append(_Section(path, "A", True, "-", "-", None, "credential_name"))
                continue
            if _expired(deadline):
                sections.append(_Section(path, "A", True, "-", "-", None, "capture_limit"))
                continue
            identity = _path_identity(pinned.descriptor, path)
            outcome, content = _read_beneath(
                pinned.descriptor, path, _MAX_UNTRACKED_FILE_BYTES, identity
            )
            if outcome != "regular" and outcome != "executable":
                sections.append(_Section(path, "A", True, "-", "-", None, outcome))
                continue
            assert content is not None
            identities[path] = identity
            text, added = _new_file_diff(path, content, outcome == "executable")
            sections.append(_Section(path, "A", True, added, "0", text, None))
        return _UntrackedRead(len(paths), sections, listing_truncated, listing, config, identities)

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
            ("config", "--get-all", "--show-scope", "-z", "core.excludesFile"),
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
            # Lowest precedence first; the runner's own ``command`` entry is last and skipped.
            if fields[index] in {b"local", b"worktree"}:
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
        )


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
        "Scope: committed and uncommitted changes to tracked files since the base, plus "
        "untracked files Git does not ignore. Uncommitted or untracked work that already existed "
        "when the base was named is included too.",
    ]
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
