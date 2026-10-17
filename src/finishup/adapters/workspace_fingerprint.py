"""Host-derived workspace fingerprints around one tool call (PR #1080, ADR-033 amendment).

Whether a command observed after the closing review is a new review input is decided by what the
command did to the project workspace, never by what its text looks like. Rounds 3 and 4 of PR
#1080 tried to recognize read-only command text (``date -u``, ``sed -n``, ``rg``, ``git status``,
the FinishUP CLI); each adversarial review found a spelling that wrote files while looking like a
read (a case-sensitive Git filter, a ``-C`` path, zsh glob qualifiers, ``nohup.out``). This
adapter replaces that judgment with an observation: the hook takes a snapshot of the workspace in
the host's ``PreToolUse`` (before the host runs the call) and another in its ``PostToolUse``, and
reports one closed token:

* ``unchanged`` - both snapshots were complete and no entry differs;
* ``changed`` - an entry was added, removed or modified, or the root itself was replaced;
* ``unavailable`` - FinishUP cannot vouch for the comparison: no pre-call snapshot, a workspace too
  large or slow to walk within the bound, an unreadable directory, a call the host reports as still
  running, or a damaged or foreign snapshot record. The kernel treats it like ``changed``.

**What the workspace covers.** Every directory entry beneath the hook's canonical workspace root:
tracked and untracked files alike, without consulting Git or any ignore file. Honouring ignore
rules would mean running Git in the hook (which executes repository-configured programs and
resolves through the agent's ``PATH``, the exact hazards of rounds 3 and 4) or re-implementing
ignore semantics, where any mistake would hide a real change; ignored paths can also hold graded
output, and many task workspaces are not repositories at all. Counting them is the conservative
direction. Three closed rules keep the cost bounded without hiding a deliverable (round 6
narrowed them; round 5 skipped whole directories by name):

* *VCS metadata* (``.git``, ``.hg``, ``.svn``) is walked, except its exact internal churn: the
  object store, reflogs, refs, LFS objects, submodule and worktree administration directories (and
  ``lost-found`` and Cursor's ``cursor`` checkpoint store) are recorded by identity only, and the
  index files in the metadata root, ``HEAD``-style pointer files, ``packed-refs``, lock files and the
  like are skipped (``domain.workspace_effect.VCS_OPAQUE_DIRECTORIES`` and
  ``vcs_bookkeeping_name``, which the kernel's ``path_beyond_workspace_fingerprint`` reads too). A
  commit, a fetch or an index refresh by ``git status`` is therefore not a workspace change, while a
  write to ``config``, ``hooks/``, ``info/attributes`` or any other file there is.
* *Dependency environments and tool caches* (``SHALLOW_DIRECTORY_NAMES``: ``node_modules``,
  ``.venv``, ``venv``, ``.tox``, ``.nox``, ``.pytest_cache``, ``.mypy_cache``, ``.ruff_cache``,
  ``.hypothesis``) are compared at their first level: a file directly inside one is compared like
  any other file, and each subdirectory by its identity (kind, mode, inode). A typical
  ``node_modules`` or virtual environment holds tens to hundreds of thousands of entries; walking it
  on every call would exceed the snapshot bound and make every call ``unavailable``. Package
  installs stay material through the ``install`` runtime fact, and a declared output below the
  first level makes the kernel withhold ``unchanged`` (``path_beyond_workspace_fingerprint``).
* *Bytecode caches* (``__pycache__``) are walked, but the interpreter's ``.pyc`` files and the
  directory's own creation are not changes; any other file inside one is compared.

FinishUP's own material is skipped as well: a saved receipt or export file (ADR-042) and FinishUP's
state or isolation root when it lies inside the workspace.

Paths are never followed through symbolic links; a link is compared by its target text. Effects
outside the root are out of scope for this signal, exactly as before: databases, ``/tmp``, the
network, other repositories, and a deliverable path outside the root that an obligation names. A
lexically visible write outside the root still records ``write outside_workspace`` and stays
material through the existing runtime fact.

**Comparison.** An entry is identical when its kind, permission bits, size, modification and change
times, inode and device all match. The change time cannot be set back by an unprivileged process,
so a write that restores the modification time is still seen. Content is hashed only for an entry
whose metadata moved since the last snapshot (``hashing only on change``): a later snapshot whose
metadata differs but whose bytes, kind and permission bits are equal is not a change (a formatter
that rewrote identical bytes, a ``touch``). An entry whose timestamps fall within two seconds of the
pre-call snapshot is *racy*: a coarse-timestamp filesystem could hide a same-second write, so its
bytes are hashed at the pre-call snapshot and compared again after the call. Directory timestamps
are not compared (their entries are).

**Bounds.** One snapshot walks at most ``MAX_ENTRIES`` entries and hashes at most
``HASH_FILE_BYTES`` per file and ``HASH_TOTAL_BYTES`` in all. ``SNAPSHOT_SECONDS`` (or the
caller's tighter deadline) bounds the whole pass, not just the walk: loading the cache, expiring
pending records, walking, hashing (checked before every read chunk) and storing. A pass that
overruns it is ``unavailable`` (``timeout``); exceeding a hashing byte bound leaves that entry's
bytes unknown, which can only make the token ``changed``. One blocking read of a chunk
(``_READ_CHUNK``) is the largest step that can run past the deadline before it is noticed.

**Quiescence** (round 6). A host's completion fact says the process it started ended, not that
nothing that process started is still writing. Before it walks, the post-call pass asks
``adapters.process_lifetime`` whether a process of this user that started during the call window is
still running with its working directory or a file open for writing inside the workspace; if so,
the token is ``unavailable`` (``call_incomplete``); when the process table cannot be read it is
``unavailable`` too (``process_table_unreadable``, diagnosed once in ``observe status``). After
it walks, the pass re-reads the modification time of every directory it walked: one that changed
during the walk means the workspace was still being written, and the token is ``unavailable`` as
well. VCS metadata and bytecode caches are exempt from that re-read, as they are from the walk.

**Host window** (round 6). A pre-call snapshot is published only when the whole capture finished
before the host could stop waiting for the hook; the completion time and the host deadline are
stored inside the authenticated record, and the post-call pass re-checks them. A late capture is
never published, so it cannot be consumed even when the pre-call process is killed before it could
withdraw anything.

**Storage.** Snapshots live in an owner-only directory beside the local observation store, keyed by
the workspace commitment: one pending snapshot per open call and one cache of the latest snapshot
(the content digests the next pre-call snapshot reuses). No path or content is stored: every path
and every content digest is a BLAKE2b value keyed by the installation's observation key, and each
file carries an HMAC so a damaged or foreign file reads as unavailable. Pending snapshots expire;
revoking observation for the workspace removes its directory.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import os
import shutil
import stat
import struct
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal

from finishup.adapters.process_lifetime import lingering_process, process_clock_ns
from finishup.config.paths import PathSafetyError, ensure_owner_only_dir
from finishup.domain.workspace_effect import (
    BYTECODE_CACHE_DIRECTORY,
    SHALLOW_DIRECTORY_NAMES,
    VCS_METADATA_DIRECTORIES,
    VCS_OPAQUE_DIRECTORIES,
    WORKSPACE_CHANGED,
    WORKSPACE_UNAVAILABLE,
    WORKSPACE_UNCHANGED,
    bytecode_artifact_name,
    saved_artifact_name,
    vcs_bookkeeping_name,
)

__all__ = [
    "FINGERPRINT_DIRECTORY",
    "HASH_FILE_BYTES",
    "HASH_TOTAL_BYTES",
    "MAX_ENTRIES",
    "SHALLOW_DIRECTORY_NAMES",
    "SNAPSHOT_SECONDS",
    "UnavailableReason",
    "WorkspaceEffectReading",
    "WorkspaceFingerprintStore",
    "workspace_fingerprint_dir",
]

FINGERPRINT_DIRECTORY: Final = "workspace-fingerprints"
MAX_ENTRIES: Final = 60_000
SNAPSHOT_SECONDS: Final = 0.75
HASH_FILE_BYTES: Final = 8 * 1024 * 1024
HASH_TOTAL_BYTES: Final = 64 * 1024 * 1024
MAX_DEPTH: Final = 64
RACY_WINDOW_NS: Final = 2_000_000_000
PENDING_TTL_SECONDS: Final = 24 * 3600
MAX_PENDING: Final = 256

# Walk modes of one directory: ordinary, inside VCS metadata, the first level of a dependency
# environment or tool cache, or inside a bytecode cache.
_MODE_NORMAL: Final = 0
_MODE_VCS: Final = 1
_MODE_SHALLOW: Final = 2
_MODE_BYTECODE: Final = 3
_MODE_VCS_ROOT: Final = 4

UnavailableReason = Literal[
    "no_pre_snapshot",
    "call_incomplete",
    "process_table_unreadable",
    "too_large",
    "timeout",
    "unreadable",
    "root_unusable",
    "store_unusable",
]

# Version 2 adds the call window start (process clock), the capture completion time and the host
# deadline (both monotonic, 0 when absent) to the authenticated header.
_MAGIC: Final = b"FUWF\x02"
_HEADER: Final = struct.Struct("<5sQQqqQQI")
_ENTRY: Final = struct.Struct("<16sBIQqqQQB16s")
_MAC_BYTES: Final = 32
_HAS_DIGEST: Final = 1
_RACY: Final = 2
# Small enough that one blocking read of a regular file is a short step past the deadline check.
_READ_CHUNK: Final = 256 * 1024
_KIND_FILE: Final = 1
_KIND_DIR: Final = 2
_KIND_LINK: Final = 3
_KIND_OPAQUE: Final = 4
_KIND_OTHER: Final = 5


# How long a workspace that exceeded a walk bound skips walking: a tree too large stays too large,
# while a timeout may have been a cold filesystem cache.
_BACKOFF_SECONDS: Final = {"too_large": 600.0, "timeout": 120.0}


def _write_small(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        os.write(descriptor, data)
    finally:
        os.close(descriptor)


def workspace_fingerprint_dir(observation_root: Path, workspace_commitment: str) -> Path | None:
    """The owner-only snapshot directory of one workspace commitment, or ``None``."""

    digest = workspace_commitment.removeprefix("hmac-sha256:")
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        return None
    return observation_root / FINGERPRINT_DIRECTORY / digest


@dataclass(frozen=True, slots=True)
class WorkspaceEffectReading:
    """The closed token one call produced, with the closed reason when it is unavailable.

    ``fresh`` is false when the reason repeats one already found for this call or workspace (a
    pre-call failure carried to the post-call half, or a recent walk-bound back-off), so a caller
    reports each underlying failure once.
    """

    effect: str
    reason: UnavailableReason | None = None
    fresh: bool = True


@dataclass(slots=True)
class _Entry:
    kind: int
    mode: int
    size: int
    mtime_ns: int
    ctime_ns: int
    ino: int
    dev: int
    digest: bytes | None = None
    racy: bool = False

    def same_metadata(self, other: _Entry) -> bool:
        if self.kind != other.kind or self.mode != other.mode:
            return False
        if self.kind == _KIND_DIR:
            return True
        if self.kind == _KIND_OPAQUE:
            return (self.ino, self.dev) == (other.ino, other.dev)
        return (self.size, self.mtime_ns, self.ctime_ns, self.ino, self.dev) == (
            other.size,
            other.mtime_ns,
            other.ctime_ns,
            other.ino,
            other.dev,
        )


@dataclass(slots=True)
class _Snapshot:
    root_dev: int
    root_ino: int
    started_ns: int
    entries: dict[bytes, _Entry]
    paths: dict[bytes, str]
    # The pre-call pass's start on ``process_lifetime.process_clock_ns`` (0 when unknown), when its
    # capture finished and the host deadline it had to meet (``time.monotonic`` nanoseconds, 0 when
    # absent). A post-call walk leaves them 0.
    window_ns: int = 0
    captured_ns: int = 0
    host_deadline_ns: int = 0
    # The directories this walk entered with the modification time it saw (post-call re-read).
    settle: tuple[tuple[str, int], ...] = ()


class _Unavailable(Exception):
    __slots__ = ("backoff", "reason")

    def __init__(self, reason: UnavailableReason, *, backoff: bool = True) -> None:
        self.reason: UnavailableReason = reason
        # A walk bound starts the back-off; a hashing or persistence overrun, or a missed host
        # window, says nothing about the next walk and does not.
        self.backoff = backoff
        super().__init__(reason)


def _kind(mode: int) -> int:
    if stat.S_ISREG(mode):
        return _KIND_FILE
    if stat.S_ISDIR(mode):
        return _KIND_DIR
    if stat.S_ISLNK(mode):
        return _KIND_LINK
    return _KIND_OTHER


def _past(deadline: float) -> bool:
    return time.monotonic() >= deadline


class _Hasher:
    """Bounded keyed content hashing shared by one snapshot.

    The deadline is checked before every read chunk; passing it raises ``timeout`` (no back-off),
    so a slow read can never let a pass report success after its budget.
    """

    __slots__ = ("_content_key", "_deadline", "_remaining")

    def __init__(self, content_key: bytes, deadline: float) -> None:
        self._content_key = content_key
        self._remaining = HASH_TOTAL_BYTES
        self._deadline = deadline

    def _check(self) -> None:
        if _past(self._deadline):
            raise _Unavailable("timeout", backoff=False)

    def digest(self, root: str, relative: str, entry: _Entry) -> bytes | None:
        """The keyed digest of one entry's bytes, or ``None`` when it cannot be read in bounds."""

        self._check()
        path = os.path.join(root, relative)
        hasher = hashlib.blake2b(key=self._content_key, digest_size=16, person=b"fu-wf-content")
        if entry.kind == _KIND_LINK:
            try:
                target = os.readlink(path)
            except OSError:
                return None
            hasher.update(b"L" + os.fsencode(target))
            return hasher.digest()
        if entry.kind != _KIND_FILE:
            return None
        if entry.size > HASH_FILE_BYTES or entry.size > self._remaining:
            return None
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NONBLOCK", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError:
            return None
        try:
            facts = os.fstat(descriptor)
            if (
                not stat.S_ISREG(facts.st_mode)
                or facts.st_ino != entry.ino
                or facts.st_dev != entry.dev
                or facts.st_size != entry.size
            ):
                return None
            hasher.update(b"F")
            read = 0
            while True:
                self._check()
                chunk = os.read(descriptor, _READ_CHUNK)
                if not chunk:
                    break
                read += len(chunk)
                if read > entry.size:
                    return None
                hasher.update(chunk)
            self._check()
            after = os.fstat(descriptor)
            if (after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (
                entry.size,
                entry.mtime_ns,
                entry.ctime_ns,
            ):
                # The file moved while it was read: these bytes are not that state.
                return None
        except OSError:
            return None
        finally:
            os.close(descriptor)
        self._remaining -= read
        return hasher.digest()


LingeringProbe = Callable[[int, str], "bool | None"]


class WorkspaceFingerprintStore:
    """Pre/post snapshots of one workspace, kept in an owner-only hook-local directory.

    ``observation_root`` is the local observation store's root; ``key_material`` its key. The
    store never raises to its caller: every failure becomes an ``unavailable`` reading.
    ``lingering`` answers whether a process started since a window start still runs in the
    workspace (``process_lifetime.lingering_process``; replaced only by tests).
    """

    __slots__ = ("_content_key", "_directory", "_lingering", "_mac_key", "_path_key")

    def __init__(
        self,
        directory: Path,
        key_material: bytes,
        *,
        lingering: LingeringProbe = lingering_process,
    ) -> None:
        self._directory = directory
        base = hmac.new(key_material, b"finishup/workspace-fingerprint/v1", "sha256").digest()
        self._path_key = hmac.new(base, b"path", "sha256").digest()
        self._content_key = hmac.new(base, b"content", "sha256").digest()
        self._mac_key = hmac.new(base, b"record", "sha256").digest()
        self._lingering = lingering

    # -- public surface -------------------------------------------------------------------------

    def call_key(self, call_identity: str) -> str:
        """The pending-snapshot name for one host call identity (keyed; never the identity)."""

        return hmac.new(self._mac_key, call_identity.encode("utf-8"), "sha256").hexdigest()[:40]

    def capture_before(
        self,
        root: str,
        call_identity: str,
        *,
        deadline: float,
        host_deadline: float | None = None,
        excluded: Iterable[str] = (),
    ) -> UnavailableReason | None:
        """Snapshot *root* for one call before the host runs it; the reason when it could not.

        ``deadline`` (monotonic) bounds the whole capture. ``host_deadline`` (monotonic) is when
        the host may stop waiting for this pass and run the call: a capture that has not finished
        by then may already hold the call's writes, so it is never published (``timeout``).
        """

        window = process_clock_ns() or 0
        try:
            self._prepare()
            self._expire_pending(deadline)
            bounded = self._recently_bounded()
            if bounded is not None:
                # The last walk of this workspace exceeded a bound moments ago: do not spend the
                # bound again on every call. The post-call half reports the same reason.
                self._mark_failed(call_identity, bounded)
                return bounded
            cache = self._load(self._cache_path(), delete=False)
            if _past(deadline):
                raise _Unavailable("timeout", backoff=False)
            snapshot = self._walk(root, deadline=deadline, excluded=excluded)
            hasher = _Hasher(self._content_key, deadline)
            for key, entry in snapshot.entries.items():
                cached = None if cache is None else cache.entries.get(key)
                if cached is not None and cached.same_metadata(entry) and not entry.racy:
                    entry.digest = cached.digest
                    continue
                if entry.kind not in {_KIND_FILE, _KIND_LINK}:
                    continue
                if entry.racy or cache is not None or entry.kind == _KIND_LINK:
                    # Moved since the last snapshot, new since it, or racy: hash now so a later
                    # metadata-only change can be told apart from a content change.
                    entry.digest = hasher.digest(root, snapshot.paths[key], entry)
            # Nothing is published unless the whole capture finished inside both bounds. A late
            # capture may hold the call's own writes; publishing it first and withdrawing it
            # afterwards would let a concurrent post-call pass consume it in between.
            finished = time.monotonic()
            if finished >= deadline:
                raise _Unavailable("timeout", backoff=False)
            if host_deadline is not None and finished > host_deadline:
                raise _Unavailable("timeout", backoff=False)
            snapshot.window_ns = window
            snapshot.captured_ns = max(1, int(finished * 1_000_000_000))
            snapshot.host_deadline_ns = (
                0 if host_deadline is None else max(1, int(host_deadline * 1_000_000_000))
            )
            pending = self._pending_path(call_identity)
            self._store(pending, snapshot)
            if _past(deadline):
                # Persisting took the pass past its budget. The stored bytes are still a pre-call
                # state (the capture finished in time), but the pass reports its overrun.
                with contextlib.suppress(OSError):
                    pending.unlink()
                raise _Unavailable("timeout", backoff=False)
            return None
        except _Unavailable as failure:
            with contextlib.suppress(OSError):
                self._pending_path(call_identity).unlink()
            with contextlib.suppress(OSError, PathSafetyError, ValueError):
                if failure.backoff and failure.reason in _BACKOFF_SECONDS:
                    _write_small(self._directory / "bounded", failure.reason.encode("ascii"))
                self._mark_failed(call_identity, failure.reason)
            return failure.reason
        except OSError, PathSafetyError, ValueError:
            return "store_unusable"

    def effect_after(
        self,
        root: str,
        call_identity: str,
        *,
        deadline: float,
        call_complete: bool,
        excluded: Iterable[str] = (),
    ) -> WorkspaceEffectReading:
        """Compare *root* now with the call's pre-call snapshot; consumes that snapshot."""

        try:
            failed = self._take_failed(call_identity)
            if failed is not None:
                with contextlib.suppress(OSError):
                    self._pending_path(call_identity).unlink()
                return WorkspaceEffectReading(WORKSPACE_UNAVAILABLE, failed, fresh=False)
            try:
                before = self._load(self._pending_path(call_identity), delete=True)
            except OSError, PathSafetyError, ValueError:
                before = None
            if before is None:
                return WorkspaceEffectReading(WORKSPACE_UNAVAILABLE, "no_pre_snapshot")
            if before.captured_ns <= 0 or (
                before.host_deadline_ns and before.captured_ns > before.host_deadline_ns
            ):
                # The authenticated record says its capture did not finish inside the host
                # window (or does not say when it finished): it may hold the call's writes.
                return WorkspaceEffectReading(WORKSPACE_UNAVAILABLE, "timeout")
            if not call_complete:
                # The host has not reported that the call ended (a background launch, a process
                # still running behind a session id): later writes would be missed.
                return WorkspaceEffectReading(WORKSPACE_UNAVAILABLE, "call_incomplete")
            if _past(deadline):
                raise _Unavailable("timeout", backoff=False)
            # The host's completion fact covers the process it started, not what that process
            # started. A process of this user begun in the call window and still running in the
            # workspace may write after this comparison; an unreadable process table cannot rule
            # that out.
            lingering = None if before.window_ns <= 0 else self._lingering(before.window_ns, root)
            if lingering is None:
                # This host or platform does not let the hook read the process table, so no
                # lingering writer can be ruled out. A standing condition: named once per
                # back-off period, unlike a lingering process (a per-call fact).
                return WorkspaceEffectReading(
                    WORKSPACE_UNAVAILABLE,
                    "process_table_unreadable",
                    fresh=self._note_standing("process-table-unreadable"),
                )
            if lingering:
                return WorkspaceEffectReading(WORKSPACE_UNAVAILABLE, "call_incomplete")
            after = self._walk(root, deadline=deadline, excluded=excluded)
            hasher = _Hasher(self._content_key, deadline)
            changed = (after.root_dev, after.root_ino) != (
                before.root_dev,
                before.root_ino,
            ) or bool(before.entries.keys() - after.entries.keys())
            for key, entry in after.entries.items():
                prior = before.entries.get(key)
                if prior is None:
                    changed = True
                    entry.digest = hasher.digest(root, after.paths[key], entry)
                    continue
                if prior.same_metadata(entry) and not prior.racy:
                    entry.digest = prior.digest
                    continue
                if entry.kind not in {_KIND_FILE, _KIND_LINK} or prior.kind != entry.kind:
                    changed = changed or not prior.same_metadata(entry)
                    continue
                entry.digest = hasher.digest(root, after.paths[key], entry)
                if (
                    prior.digest is None
                    or entry.digest is None
                    or prior.digest != entry.digest
                    or prior.mode != entry.mode
                ):
                    changed = True
            if not changed:
                if not self._settled(after.settle):
                    # A directory gained, lost or replaced an entry while it was being compared:
                    # the workspace was still being written, so this walk is not its final state.
                    return WorkspaceEffectReading(WORKSPACE_UNAVAILABLE, "call_incomplete")
                if _past(deadline):
                    raise _Unavailable("timeout", backoff=False)
            if not _past(deadline):
                with contextlib.suppress(OSError, PathSafetyError, ValueError):
                    self._store(self._cache_path(), after)
            return WorkspaceEffectReading(WORKSPACE_CHANGED if changed else WORKSPACE_UNCHANGED)
        except _Unavailable as failure:
            with contextlib.suppress(OSError, PathSafetyError, ValueError):
                if failure.backoff and failure.reason in _BACKOFF_SECONDS:
                    _write_small(self._directory / "bounded", failure.reason.encode("ascii"))
            return WorkspaceEffectReading(WORKSPACE_UNAVAILABLE, failure.reason)
        except OSError, PathSafetyError, ValueError:
            return WorkspaceEffectReading(WORKSPACE_UNAVAILABLE, "store_unusable")

    def invalidate(self, call_identity: str, reason: UnavailableReason) -> None:
        """Withdraw a stored pre-call snapshot (the post-call half then reports *reason*)."""

        with contextlib.suppress(OSError):
            self._pending_path(call_identity).unlink()
        with contextlib.suppress(OSError, PathSafetyError, ValueError):
            self._mark_failed(call_identity, reason)

    def discard(self) -> None:
        """Remove this workspace's snapshots (observation revoked)."""

        with contextlib.suppress(OSError):
            if self._directory.is_dir() and not self._directory.is_symlink():
                shutil.rmtree(self._directory)

    # -- walking ----------------------------------------------------------------------------------

    def _walk(self, root: str, *, deadline: float, excluded: Iterable[str]) -> _Snapshot:
        try:
            facts = os.stat(root)
        except OSError as exc:
            raise _Unavailable("root_unusable") from exc
        if not stat.S_ISDIR(facts.st_mode) or not os.path.isabs(root):
            raise _Unavailable("root_unusable")
        skipped = frozenset(part.strip("/") for part in excluded if part.strip("/"))
        started = time.time_ns()
        racy_from = started - RACY_WINDOW_NS
        entries: dict[bytes, _Entry] = {}
        paths: dict[bytes, str] = {}
        settle: list[tuple[str, int]] = [(root, facts.st_mtime_ns)]
        pending: list[tuple[str, str, int, int]] = [("", root, 0, _MODE_NORMAL)]
        count = 0
        while pending:
            relative_dir, directory, depth, mode = pending.pop()
            try:
                iterator = os.scandir(directory)
            except OSError as exc:
                raise _Unavailable("unreadable") from exc
            with iterator:
                for item in iterator:
                    count += 1
                    if count > MAX_ENTRIES:
                        raise _Unavailable("too_large")
                    if count & 0xFF == 0 and _past(deadline):
                        raise _Unavailable("timeout")
                    name = item.name
                    relative = name if not relative_dir else f"{relative_dir}/{name}"
                    if relative in skipped:
                        continue
                    try:
                        info = item.stat(follow_symlinks=False)
                    except FileNotFoundError:
                        # Removed between listing and stat: the pre/post comparison sees it.
                        continue
                    except OSError as exc:
                        raise _Unavailable("unreadable") from exc
                    kind = _kind(info.st_mode)
                    if kind == _KIND_FILE and saved_artifact_name(name):
                        continue
                    child_mode: int | None = None
                    opaque = False
                    record = True
                    if mode in {_MODE_VCS, _MODE_VCS_ROOT}:
                        if kind == _KIND_DIR and name in VCS_OPAQUE_DIRECTORIES:
                            opaque = True
                        elif kind != _KIND_DIR and vcs_bookkeeping_name(
                            name, in_root=mode == _MODE_VCS_ROOT
                        ):
                            continue
                        elif kind == _KIND_DIR:
                            child_mode = _MODE_VCS
                    elif mode == _MODE_SHALLOW:
                        opaque = kind == _KIND_DIR
                    elif mode == _MODE_BYTECODE:
                        if kind == _KIND_FILE and bytecode_artifact_name(name):
                            continue
                        if kind == _KIND_DIR:
                            child_mode = _MODE_BYTECODE
                    elif kind == _KIND_DIR:
                        if name in VCS_METADATA_DIRECTORIES:
                            child_mode = _MODE_VCS_ROOT
                        elif name in SHALLOW_DIRECTORY_NAMES:
                            child_mode = _MODE_SHALLOW
                        elif name == BYTECODE_CACHE_DIRECTORY:
                            # Its creation by an import is not a change; what it holds besides
                            # bytecode is.
                            child_mode = _MODE_BYTECODE
                            record = False
                        else:
                            child_mode = _MODE_NORMAL
                    if record:
                        entry = _Entry(
                            _KIND_OPAQUE if opaque else kind,
                            stat.S_IMODE(info.st_mode),
                            info.st_size if kind in {_KIND_FILE, _KIND_LINK} else 0,
                            info.st_mtime_ns,
                            info.st_ctime_ns,
                            info.st_ino,
                            info.st_dev,
                        )
                        entry.racy = kind in {_KIND_FILE, _KIND_LINK} and (
                            max(info.st_mtime_ns, info.st_ctime_ns) >= racy_from
                        )
                        key = self._key(relative)
                        entries[key] = entry
                        paths[key] = relative
                    if child_mode is not None and not opaque:
                        if depth + 1 > MAX_DEPTH:
                            raise _Unavailable("too_large")
                        if child_mode in {_MODE_NORMAL, _MODE_SHALLOW}:
                            settle.append((item.path, info.st_mtime_ns))
                        pending.append((relative, item.path, depth + 1, child_mode))
        if _past(deadline):
            raise _Unavailable("timeout")
        return _Snapshot(facts.st_dev, facts.st_ino, started, entries, paths, settle=tuple(settle))

    @staticmethod
    def _settled(directories: tuple[tuple[str, int], ...]) -> bool:
        """Whether every directory a walk entered still has the modification time it saw."""

        for path, mtime_ns in directories:
            try:
                if os.stat(path, follow_symlinks=False).st_mtime_ns != mtime_ns:
                    return False
            except OSError:
                return False
        return True

    def _key(self, relative: str) -> bytes:
        return hashlib.blake2b(
            relative.encode("utf-8", "surrogateescape"),
            key=self._path_key,
            digest_size=16,
            person=b"fu-wf-path",
        ).digest()

    # -- persistence ------------------------------------------------------------------------------

    def recently_bounded(self) -> UnavailableReason | None:
        """The walk bound this workspace exceeded moments ago, while its back-off lasts."""

        return self._recently_bounded()

    def _recently_bounded(self) -> UnavailableReason | None:
        marker = self._directory / "bounded"
        try:
            if marker.is_symlink():
                return None
            age = time.time() - marker.stat().st_mtime
            reason = marker.read_bytes()[:32].decode("ascii")
        except OSError, UnicodeDecodeError:
            return None
        if reason == "too_large" and 0 <= age < _BACKOFF_SECONDS["too_large"]:
            return "too_large"
        if reason == "timeout" and 0 <= age < _BACKOFF_SECONDS["timeout"]:
            return "timeout"
        return None

    def _note_standing(self, name: str) -> bool:
        """Whether a standing condition is new: true at most once per back-off period."""

        marker = self._directory / name
        try:
            if not marker.is_symlink():
                age = time.time() - marker.stat().st_mtime
                if 0 <= age < _BACKOFF_SECONDS["too_large"]:
                    return False
        except OSError:
            pass
        with contextlib.suppress(OSError, PathSafetyError, ValueError):
            ensure_owner_only_dir(self._directory)
            _write_small(marker, b"1")
        return True

    def _failed_path(self, call_identity: str) -> Path:
        return self._directory / "pending" / f"{self.call_key(call_identity)}.fail"

    def _mark_failed(self, call_identity: str, reason: UnavailableReason) -> None:
        _write_small(self._failed_path(call_identity), reason.encode("ascii"))

    def _take_failed(self, call_identity: str) -> UnavailableReason | None:
        path = self._failed_path(call_identity)
        try:
            if path.is_symlink():
                return None
            raw = path.read_bytes()[:32].decode("ascii")
        except OSError, UnicodeDecodeError:
            return None
        finally:
            with contextlib.suppress(OSError):
                path.unlink()
        reasons: dict[str, UnavailableReason] = {
            "too_large": "too_large",
            "timeout": "timeout",
            "unreadable": "unreadable",
            "root_unusable": "root_unusable",
        }
        return reasons.get(raw, "store_unusable")

    def _prepare(self) -> None:
        ensure_owner_only_dir(self._directory / "pending")

    def _cache_path(self) -> Path:
        return self._directory / "latest.bin"

    def _pending_path(self, call_identity: str) -> Path:
        return self._directory / "pending" / f"{self.call_key(call_identity)}.bin"

    def _expire_pending(self, deadline: float) -> None:
        directory = self._directory / "pending"
        try:
            names = os.listdir(directory)
        except OSError:
            return
        if len(names) < MAX_PENDING // 4:
            return
        now = time.time()
        aged: list[tuple[float, Path]] = []
        for index, name in enumerate(names):
            if index & 0x3F == 0 and _past(deadline):
                # Cleanup is part of the pass's budget; the rest waits for the next pass.
                return
            path = directory / name
            try:
                modified = path.lstat().st_mtime
            except OSError:
                continue
            if now - modified > PENDING_TTL_SECONDS:
                with contextlib.suppress(OSError):
                    path.unlink()
            else:
                aged.append((modified, path))
        aged.sort()
        for _modified, path in aged[: max(0, len(aged) - MAX_PENDING)]:
            with contextlib.suppress(OSError):
                path.unlink()

    def _store(self, path: Path, snapshot: _Snapshot) -> None:
        body = bytearray(
            _HEADER.pack(
                _MAGIC,
                snapshot.root_dev,
                snapshot.root_ino,
                snapshot.started_ns,
                snapshot.window_ns,
                snapshot.captured_ns,
                snapshot.host_deadline_ns,
                len(snapshot.entries),
            )
        )
        for key, entry in snapshot.entries.items():
            flags = (_HAS_DIGEST if entry.digest is not None else 0) | (_RACY if entry.racy else 0)
            body += _ENTRY.pack(
                key,
                entry.kind,
                entry.mode,
                entry.size,
                entry.mtime_ns,
                entry.ctime_ns,
                entry.ino,
                entry.dev,
                flags,
                entry.digest or b"\x00" * 16,
            )
        body += hmac.new(self._mac_key, bytes(body), "sha256").digest()
        ensure_owner_only_dir(path.parent)
        temporary = path.with_name(f".{path.name}.{os.urandom(6).hex()}.tmp")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(temporary, flags, 0o600)
        try:
            view = memoryview(body)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("short_write")
                view = view[written:]
        finally:
            os.close(descriptor)
        try:
            os.replace(temporary, path)
        except BaseException:
            with contextlib.suppress(OSError):
                temporary.unlink()
            raise

    def _load(self, path: Path, *, delete: bool) -> _Snapshot | None:
        try:
            if path.is_symlink() or not path.is_file():
                return None
            size = path.stat().st_size
            if size > _HEADER.size + _ENTRY.size * MAX_ENTRIES + _MAC_BYTES:
                return None
            data = path.read_bytes()
        except OSError:
            return None
        finally:
            if delete:
                with contextlib.suppress(OSError):
                    path.unlink()
        if len(data) < _HEADER.size + _MAC_BYTES:
            return None
        body, mac = data[:-_MAC_BYTES], data[-_MAC_BYTES:]
        if not hmac.compare_digest(mac, hmac.new(self._mac_key, body, "sha256").digest()):
            return None
        magic, root_dev, root_ino, started, window, captured, host_deadline, count = (
            _HEADER.unpack_from(body, 0)
        )
        if magic != _MAGIC or len(body) != _HEADER.size + count * _ENTRY.size:
            return None
        entries: dict[bytes, _Entry] = {}
        for offset in range(_HEADER.size, len(body), _ENTRY.size):
            key, kind, mode, size, mtime, ctime, ino, dev, flags, digest = _ENTRY.unpack_from(
                body, offset
            )
            entries[key] = _Entry(
                kind,
                mode,
                size,
                mtime,
                ctime,
                ino,
                dev,
                digest if flags & _HAS_DIGEST else None,
                bool(flags & _RACY),
            )
        return _Snapshot(
            root_dev,
            root_ino,
            started,
            entries,
            {},
            window_ns=window,
            captured_ns=captured,
            host_deadline_ns=host_deadline,
        )
