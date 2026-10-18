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
  large or slow to walk within the bound, an unreadable directory, a call the host has not reported
  as ended (``call_incomplete``) or that launched a background process (``background_launch``), a
  process still writing (``process_lingering``, ``workspace_unsettled``), or a damaged or foreign
  snapshot record. The kernel treats it like ``changed``.

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
the token is ``unavailable`` (``process_lingering``); when the process table cannot be read it is
``unavailable`` too (``process_table_unreadable``, diagnosed once in ``observe status``). After
it walks, the pass re-reads the modification time of every directory it walked: one that changed
during the walk means the workspace was still being written, and the token is ``unavailable``
(``workspace_unsettled``). VCS metadata and bytecode caches are exempt from that re-read, as they
are from the walk.

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
revoking observation for the workspace removes its directory (``remove_workspace_fingerprints``).
The hook checks consent once, outside any store lock, so a pass may race a revoke. Only two writes
may create the directory, the pre-call snapshot and the tally, and both take the store lock and ask
again (``admitted``) whether observation is still granted before they write; the pre-call snapshot
is published into the store it entered, never into a re-created one (the pass keeps the entered
store's lock file open across its walk and publishes only while that same file is at the store's
path). The other post-call writes
(the digest cache, a standing marker) go by path into a store that already exists. Revocation
saves the revoked consent, then takes the same lock and renames the directory away before removing
it, so a pass that raced the revoke records nothing and creates nothing after it.

**Reading tally** (n7 RC1). Beside the snapshots, ``readings.json`` counts every post-call reading
made while observation is granted (a pass without a resolvable or writable store excepted) by its
closed effect and reason (for all time, and for the current and previous clock hour) and
keeps the last ``READING_RING`` readings with their time and, when it is already a closed token,
the host's tool-call id. It holds no path, digest or command text and never exceeds
``READING_FILE_BYTES``; a writer that cannot take its lock within ``_LOCK_WAIT_SECONDS`` drops the
sample and counts the drop. A writer that takes the lock checks that the lock file it holds is
still the one at the store's path and that observation is still granted, so a tally cannot land in
a revoked or re-created tree. ``observe status`` reports it (``reading_tally_summary``), so a call
that stayed material can be attributed to its reason locally; nothing of it crosses the wire.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import os
import re
import shutil
import stat
import struct
import time
from collections.abc import Callable, Generator, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal, cast, get_args

from finishup.adapters.process_lifetime import lingering_process, process_clock_ns
from finishup.config.paths import PathSafetyError, ensure_owner_only_dir, existing_owner_only_dir
from finishup.domain.values import JsonObject, JsonValue
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
from finishup.domain.write_scope import WRITE_SCOPES, classify_write_path

try:
    import fcntl
except ImportError:  # pragma: no cover - supported hook hosts are POSIX
    fcntl = None  # type: ignore[assignment]

__all__ = [
    "FINGERPRINT_DIRECTORY",
    "HASH_FILE_BYTES",
    "HASH_TOTAL_BYTES",
    "MAX_ENTRIES",
    "READING_FILE_BYTES",
    "READING_RING",
    "SHALLOW_DIRECTORY_NAMES",
    "SNAPSHOT_SECONDS",
    "UnavailableReason",
    "WorkspaceEffectReading",
    "WorkspaceFingerprintStore",
    "reading_tally_summary",
    "remove_workspace_fingerprints",
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
    "background_launch",
    "process_lingering",
    "workspace_unsettled",
    "process_table_unreadable",
    "too_large",
    "timeout",
    "unreadable",
    "root_unusable",
    "store_unusable",
]

# Version 2 adds the call window start (process clock), the capture completion time and the host
# deadline (both monotonic, 0 when absent) to the authenticated header.
# Version 3 retains closed write-class bits per keyed entry, including deleted entries.
_MAGIC: Final = b"FUWF\x03"
_WRITE_CLASSES: Final[tuple[str, ...]] = tuple(sorted(WRITE_SCOPES))
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
    write_scopes: tuple[str, ...] | None = None


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
    write_class: str | None = None

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


def _left(deadline: float) -> float:
    return max(0.0, deadline - time.monotonic())


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
# Whether observation is still granted for the store's workspace (asked under the store lock).
Admission = Callable[[], bool]


class WorkspaceFingerprintStore:
    """Pre/post snapshots of one workspace, kept in an owner-only hook-local directory.

    ``observation_root`` is the local observation store's root; ``key_material`` its key. The
    store never raises to its caller: every failure becomes an ``unavailable`` reading.
    ``lingering`` answers whether a process started since a window start still runs in the
    workspace (``process_lifetime.lingering_process``; replaced only by tests).
    ``admitted`` answers whether observation is still granted for the workspace. The hook checks
    consent once, outside any store lock; the store asks again under the store lock before a write
    that may create the store (the pre-call snapshot, the tally), so a pass that raced a revoke
    neither re-creates the store nor records into it. Without it the store is never created by the
    tally, and the pre-call half creates it unchecked (its caller vouches for consent).
    """

    __slots__ = ("_admitted", "_content_key", "_directory", "_lingering", "_mac_key", "_path_key")

    def __init__(
        self,
        directory: Path,
        key_material: bytes,
        *,
        lingering: LingeringProbe = lingering_process,
        admitted: Admission | None = None,
    ) -> None:
        self._directory = directory
        self._admitted = admitted
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
        # The lock file of the store this pass entered, held open (not locked) across the walk:
        # the snapshot is published only while that same file is at the store's path.
        entered: int | None = None
        try:
            # The store is created (or entered) only under its lock with observation still
            # granted: a pass that read consent before a revoke records nothing after it.
            with _store_access(
                self._directory, create=True, admitted=self._admitted, wait=_left(deadline)
            ) as (access, lock):
                if access == "busy":
                    raise _Unavailable("timeout", backoff=False)
                if access == "withdrawn":
                    return None
                self._prepare()
                entered = _pin_lock(self._directory, lock)
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
            # Published under the store lock, into the store this pass entered, and only while
            # observation is still granted: a revoke during the walk renamed the store away (or
            # withdrew consent), and nothing is re-created or published after it, not even into
            # a store a re-grant re-created meanwhile (its lock file is not the pinned one).
            with _store_access(
                self._directory,
                create=False,
                admitted=self._admitted,
                wait=_left(deadline),
                entered=entered,
            ) as (access, _lock):
                if access == "busy":
                    raise _Unavailable("timeout", backoff=False)
                if access == "withdrawn":
                    return None
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
        finally:
            if entered is not None:
                with contextlib.suppress(OSError):
                    os.close(entered)

    def effect_after(
        self,
        root: str,
        call_identity: str,
        *,
        deadline: float,
        call_complete: bool,
        incomplete_reason: UnavailableReason = "call_incomplete",
        excluded: Iterable[str] = (),
    ) -> WorkspaceEffectReading:
        """Compare *root* now with the call's pre-call snapshot; consumes that snapshot.

        ``incomplete_reason`` is the reason an incomplete call reads as (``call_incomplete`` when
        the host stated no completion, ``background_launch`` for a background launch).
        """

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
                return WorkspaceEffectReading(WORKSPACE_UNAVAILABLE, incomplete_reason)
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
                return WorkspaceEffectReading(WORKSPACE_UNAVAILABLE, "process_lingering")
            after = self._walk(root, deadline=deadline, excluded=excluded)
            hasher = _Hasher(self._content_key, deadline)
            replaced_root = (after.root_dev, after.root_ino) != (
                before.root_dev,
                before.root_ino,
            )
            removed = before.entries.keys() - after.entries.keys()
            changed = replaced_root or bool(removed)
            scopes = {before.entries[key].write_class for key in removed}
            for key, entry in after.entries.items():
                prior = before.entries.get(key)
                if prior is None:
                    changed = True
                    scopes.add(entry.write_class)
                    entry.digest = hasher.digest(root, after.paths[key], entry)
                    continue
                if prior.same_metadata(entry) and not prior.racy:
                    entry.digest = prior.digest
                    continue
                if entry.kind not in {_KIND_FILE, _KIND_LINK} or prior.kind != entry.kind:
                    if not prior.same_metadata(entry):
                        changed = True
                        scopes.update((prior.write_class, entry.write_class))
                    continue
                entry.digest = hasher.digest(root, after.paths[key], entry)
                if (
                    prior.digest is None
                    or entry.digest is None
                    or prior.digest != entry.digest
                    or prior.mode != entry.mode
                ):
                    changed = True
                    scopes.update((prior.write_class, entry.write_class))
            if not changed:
                if not self._settled(after.settle):
                    # A directory gained, lost or replaced an entry while it was being compared:
                    # the workspace was still being written, so this walk is not its final state.
                    return WorkspaceEffectReading(WORKSPACE_UNAVAILABLE, "workspace_unsettled")
                if _past(deadline):
                    raise _Unavailable("timeout", backoff=False)
            if not _past(deadline):
                with contextlib.suppress(OSError, PathSafetyError, ValueError):
                    self._store(self._cache_path(), after)
            return WorkspaceEffectReading(
                WORKSPACE_CHANGED if changed else WORKSPACE_UNCHANGED,
                write_scopes=None
                if replaced_root
                else tuple(sorted(scope for scope in scopes if scope)),
            )
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

    def note_reading(self, reading: WorkspaceEffectReading, call_token: str | None) -> bool:
        """Count one post-call reading in this workspace's bounded tally. Never raises.

        ``call_token`` is kept in the recent-reading ring only when it is already a closed token
        (the pattern the envelope applies to a tool-call id); anything else is kept as ``null``.
        Returns whether the sample was recorded (``False`` when it was dropped).
        """

        return _note_reading(self._directory, reading, call_token, self._admitted)

    def discard(self) -> None:
        """Remove this workspace's snapshots and tally (observation revoked). Never raises."""

        remove_workspace_fingerprints(self._directory)

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
                        if kind != _KIND_DIR:
                            entry.write_class = classify_write_path(
                                relative, workspace=root, inside=True
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
            # Post-call only: a store revoked since the pre-call half is not re-created.
            if existing_owner_only_dir(self._directory):
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
        """Persist *snapshot* at *path*, only into a store that already exists.

        Only ``_store_access`` creates the store. The post-call digest cache is written by path:
        observation may have been revoked (and the store removed) since the pre-call half, and the
        cache must not re-create it.
        """

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
            if entry.write_class is not None:
                flags |= (_WRITE_CLASSES.index(entry.write_class) + 1) << 2
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
        if not existing_owner_only_dir(path.parent):
            raise OSError("store_absent")
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
            scope_code = int(flags) >> 2
            if scope_code > len(_WRITE_CLASSES):
                return None
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
                _WRITE_CLASSES[scope_code - 1] if scope_code else None,
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


# -- reading tally (n7 RC1) -----------------------------------------------------------------------

READING_RING: Final = 64
READING_FILE_BYTES: Final = 16 * 1024
_READING_FORMAT: Final = "finishup.workspace-effect-readings/1"
_READING_NAME: Final = "readings.json"
# Writers stage the next document here and rename it over the tally, so a reader never sees a
# partial document and never needs the lock.
_READING_STAGING: Final = ".readings.json.next"
_READING_LOCK: Final = ".readings.lock"
# One byte per sample dropped under lock contention, appended without the lock.
_READING_DROPS: Final = ".readings.dropped"
_MAX_DROP_BYTES: Final = 64 * 1024
_LOCK_WAIT_SECONDS: Final = 0.1
_LOCK_POLL_SECONDS: Final = 0.002
# Revocation waits longer than a tally writer: a writer holds the lock for one small rewrite or one
# pending-snapshot publish, and removal goes ahead (by renaming the directory away) even when the
# wait runs out.
_REVOKE_LOCK_WAIT_SECONDS: Final = 1.0
_REVOKED_INFIX: Final = ".revoked."
_REMOVE_PASSES: Final = 3
_HOUR_MS: Final = 3_600_000
_MAX_SAFE: Final = 2**53 - 1
_MAX_EPOCH_MS: Final = 253_402_300_799_999
_EFFECTS: Final = (WORKSPACE_UNCHANGED, WORKSPACE_CHANGED, WORKSPACE_UNAVAILABLE)
_REASONS: Final = frozenset(get_args(UnavailableReason))
# The tally's count keys: ``unchanged``, ``changed`` and ``unavailable:<reason>``.
_COUNT_KEYS: Final = frozenset(
    {WORKSPACE_UNCHANGED, WORKSPACE_CHANGED, *(f"{WORKSPACE_UNAVAILABLE}:{r}" for r in _REASONS)}
)
_CALL_TOKEN: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+/-]{0,127}")
_TALLY_KEYS: Final = frozenset({"format", "since_ms", "counts", "slots", "recent"})
_RECENT_KEYS: Final = frozenset({"at_ms", "effect", "reason", "call"})
_SLOT_KEYS: Final = frozenset({"hour", "counts"})


def _count_key(reading: WorkspaceEffectReading) -> str | None:
    if reading.effect == WORKSPACE_UNAVAILABLE:
        return None if reading.reason is None else f"{WORKSPACE_UNAVAILABLE}:{reading.reason}"
    return reading.effect if reading.effect in _COUNT_KEYS else None


def _is_count(value: object) -> bool:
    return type(value) is int and 0 <= value <= _MAX_SAFE


def _valid_counts(raw: object) -> bool:
    if type(raw) is not dict:
        return False
    counts = cast(dict[object, object], raw)
    return all(
        type(key) is str and key in _COUNT_KEYS and _is_count(value)
        for key, value in counts.items()
    )


def _valid_recent(raw: object) -> bool:
    if type(raw) is not dict or frozenset(cast(dict[str, object], raw)) != _RECENT_KEYS:
        return False
    item = cast(dict[str, object], raw)
    effect, reason, call, moment = item["effect"], item["reason"], item["call"], item["at_ms"]
    if type(effect) is not str or effect not in _EFFECTS:
        return False
    if not (type(moment) is int and 0 <= moment <= _MAX_EPOCH_MS):
        return False
    if effect == WORKSPACE_UNAVAILABLE:
        if type(reason) is not str or reason not in _REASONS:
            return False
    elif reason is not None:
        return False
    return call is None or (type(call) is str and _CALL_TOKEN.fullmatch(call) is not None)


def _valid_tally(raw: object) -> dict[str, object] | None:
    """The tally document when every field is in its closed vocabulary, else ``None``."""

    if type(raw) is not dict or frozenset(cast(dict[str, object], raw)) != _TALLY_KEYS:
        return None
    document = cast(dict[str, object], raw)
    since, slots, recent = document["since_ms"], document["slots"], document["recent"]
    if document["format"] != _READING_FORMAT or not (
        type(since) is int and 0 <= since <= _MAX_EPOCH_MS
    ):
        return None
    if not _valid_counts(document["counts"]) or type(slots) is not list or type(recent) is not list:
        return None
    slot_items = cast(list[object], slots)
    if len(slot_items) > 2:
        return None
    hours: list[int] = []
    for slot in slot_items:
        if type(slot) is not dict or frozenset(cast(dict[str, object], slot)) != _SLOT_KEYS:
            return None
        hour = cast(dict[str, object], slot)["hour"]
        if not _is_count(hour) or not _valid_counts(cast(dict[str, object], slot)["counts"]):
            return None
        hours.append(cast(int, hour))
    recent_items = cast(list[object], recent)
    if len(set(hours)) != len(hours) or len(recent_items) > READING_RING:
        return None
    if not all(_valid_recent(item) for item in recent_items):
        return None
    return document


def _read_tally(path: Path) -> tuple[str, dict[str, object] | None]:
    """``absent``, ``unreadable`` or ``retained`` plus the validated document."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return "absent", None
    except OSError:
        return "unreadable", None
    try:
        facts = os.fstat(descriptor)
        if (
            not stat.S_ISREG(facts.st_mode)
            or facts.st_uid != os.geteuid()
            or facts.st_mode & 0o077
            or facts.st_size > READING_FILE_BYTES
        ):
            return "unreadable", None
        raw = os.pread(descriptor, READING_FILE_BYTES + 1, 0)
    except OSError:
        return "unreadable", None
    finally:
        os.close(descriptor)
    try:
        document = _valid_tally(json.loads(raw))
    except UnicodeError, ValueError, RecursionError:
        document = None
    return ("retained", document) if document is not None else ("unreadable", None)


def _acquire_lock(descriptor: int, wait: float = _LOCK_WAIT_SECONDS) -> bool:
    if fcntl is None:
        return True
    deadline = time.monotonic() + wait
    while True:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except BlockingIOError:
            if time.monotonic() >= deadline:
                return False
            time.sleep(_LOCK_POLL_SECONDS)


def _count_drop(directory: Path) -> None:
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(
            directory / _READING_DROPS, flags | getattr(os, "O_NOFOLLOW", 0), 0o600
        )
    except OSError:
        return
    try:
        facts = os.fstat(descriptor)
        if (
            stat.S_ISREG(facts.st_mode)
            and facts.st_uid == os.geteuid()
            and facts.st_size < _MAX_DROP_BYTES
        ):
            os.write(descriptor, b".")
    except OSError:
        pass
    finally:
        os.close(descriptor)


def _drop_count(directory: Path) -> int:
    try:
        facts = os.lstat(directory / _READING_DROPS)
    except OSError:
        return 0
    if not stat.S_ISREG(facts.st_mode) or facts.st_uid != os.geteuid():
        return 0
    return min(facts.st_size, _MAX_DROP_BYTES)


def _bump(counts: dict[str, int], key: str) -> None:
    counts[key] = min(_MAX_SAFE, counts.get(key, 0) + 1)


def _folded_tally(
    document: dict[str, object] | None,
    key: str,
    reading: WorkspaceEffectReading,
    call: str | None,
    now_ms: int,
) -> bytes:
    """Fold one reading into *document* and encode it within ``READING_FILE_BYTES``."""

    if document is None:
        empty_counts: dict[str, int] = {}
        empty_slots: list[dict[str, object]] = []
        empty_recent: list[dict[str, object]] = []
        document = {
            "format": _READING_FORMAT,
            "since_ms": now_ms,
            "counts": empty_counts,
            "slots": empty_slots,
            "recent": empty_recent,
        }
    _bump(cast(dict[str, int], document["counts"]), key)
    hour = now_ms // _HOUR_MS
    # Only this clock hour and the one before it; a slot from the future (a clock stepped back)
    # is dropped rather than trusted.
    slots = [
        slot
        for slot in cast(list[dict[str, object]], document["slots"])
        if hour - 1 <= cast(int, slot["hour"]) <= hour
    ]
    current: dict[str, object] | None = next((slot for slot in slots if slot["hour"] == hour), None)
    if current is None:
        fresh_counts: dict[str, int] = {}
        current = {"hour": hour, "counts": fresh_counts}
        slots.append(current)
    _bump(cast(dict[str, int], current["counts"]), key)
    document["slots"] = sorted(slots, key=lambda slot: cast(int, slot["hour"]))
    recent = cast(list[dict[str, object]], document["recent"])
    recent.append(
        {
            "at_ms": now_ms,
            "effect": reading.effect,
            "reason": reading.reason if reading.effect == WORKSPACE_UNAVAILABLE else None,
            "call": call,
        }
    )
    del recent[: max(0, len(recent) - READING_RING)]
    while True:
        encoded = json.dumps(document, separators=(",", ":"), sort_keys=True).encode("ascii")
        if len(encoded) <= READING_FILE_BYTES or not recent:
            return encoded
        # Long call ids could push the ring past the byte bound: shed the oldest readings.
        del recent[0]


def _replace_tally(directory: Path, encoded: bytes) -> None:
    staging = directory / _READING_STAGING
    with contextlib.suppress(FileNotFoundError):
        os.unlink(staging)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(staging, flags | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        try:
            view = memoryview(encoded)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("short_write")
                view = view[written:]
        finally:
            os.close(descriptor)
        os.replace(staging, directory / _READING_NAME)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(staging)
        raise


def _note_reading(
    directory: Path,
    reading: WorkspaceEffectReading,
    call_token: str | None,
    admitted: Admission | None = None,
) -> bool:
    key = _count_key(reading)
    if key is None:
        return False
    call = (
        call_token
        if type(call_token) is str and _CALL_TOKEN.fullmatch(call_token) is not None
        else None
    )
    now_ms = min(_MAX_EPOCH_MS, max(0, time.time_ns() // 1_000_000))
    try:
        # The tally creates the store only when it can ask, under the store lock, whether
        # observation is still granted: a reading after a revoke is never recorded.
        with _store_access(
            directory, create=admitted is not None, admitted=admitted, wait=_LOCK_WAIT_SECONDS
        ) as (access, _lock):
            if access == "busy":
                _count_drop(directory)
                return False
            if access == "withdrawn":
                return False
            status, document = _read_tally(directory / _READING_NAME)
            if status == "unreadable":
                # A damaged or foreign tally restarts (with a new ``since``) rather than being
                # trusted; one this user does not own is never replaced.
                with contextlib.suppress(OSError):
                    facts = os.lstat(directory / _READING_NAME)
                    if facts.st_uid != os.geteuid() or not stat.S_ISREG(facts.st_mode):
                        return False
                with contextlib.suppress(OSError):
                    # The drop count belongs to the tally it restarts; never through a link.
                    os.close(
                        os.open(
                            directory / _READING_DROPS,
                            os.O_WRONLY
                            | os.O_TRUNC
                            | getattr(os, "O_CLOEXEC", 0)
                            | getattr(os, "O_NOFOLLOW", 0),
                        )
                    )
            _replace_tally(directory, _folded_tally(document, key, reading, call, now_ms))
    except OSError, PathSafetyError, ValueError:
        return False
    return True


_Access = Literal["write", "busy", "withdrawn"]


def _open_lock(directory: Path) -> int:
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    return os.open(directory / _READING_LOCK, flags, 0o600)


def _holds_lock_of(directory: Path, lock: int) -> bool:
    """Whether the lock file *lock* is still the one at *directory*'s path.

    Revocation renames the store away under this lock, so a writer that waited across a revoke
    finds no lock file, or another one, at the path. The comparison is by the lock file's own
    identity: the descriptor held open here keeps that inode allocated, so a file at the path with
    the same (device, inode) can only be this one, even if a re-created directory reused the old
    directory's inode number.
    """

    try:
        held = os.fstat(lock)
        current = os.lstat(directory / _READING_LOCK)
    except OSError:
        return False
    return (held.st_dev, held.st_ino) == (current.st_dev, current.st_ino)


def _same_file(first: int, second: int) -> bool:
    try:
        one, other = os.fstat(first), os.fstat(second)
    except OSError:
        return False
    return (one.st_dev, one.st_ino) == (other.st_dev, other.st_ino)


def _pin_lock(directory: Path, lock: int) -> int:
    """Open the held lock file *lock* again by path, as a pin of the store it belongs to.

    Called under the lock, where the file at the path is the held one. The pin is its own open
    file description, so it holds no lock and closing it releases none; it only keeps the lock
    file's inode allocated, so a store re-created at the path later never has a lock file with the
    same (device, inode). Raises ``OSError`` when the file at the path is not the held one.
    """

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    pin = os.open(directory / _READING_LOCK, flags)
    if not _same_file(pin, lock):
        os.close(pin)
        raise OSError("store_moved")
    return pin


def _still_admitted(admitted: Admission) -> bool:
    try:
        return admitted() is True
    except Exception:
        # An unanswerable consent check is not a grant.
        return False


@contextlib.contextmanager
def _store_access(
    directory: Path,
    *,
    create: bool,
    admitted: Admission | None,
    wait: float,
    entered: int | None = None,
) -> Generator[tuple[_Access, int]]:
    """Hold the store lock for one write into *directory* while observation is still granted.

    Yields the access and the held lock descriptor (``-1`` when none is held): ``write`` while
    the caller may write (the lock is held until the block ends), ``busy`` when the lock was not
    taken within *wait*, and ``withdrawn`` when there is no store to write into: none exists and
    *create* is false, revocation renamed it away while this writer waited, the store at the path
    is not the one *entered* pins (``_pin_lock``: a store re-created since), or *admitted* says
    observation is no longer granted. A store this call created for a withdrawn grant is removed
    again under the lock; an existing one is left to revocation (a pause keeps it). Raises
    ``OSError`` or ``PathSafetyError`` for an unusable store.
    """

    existed = existing_owner_only_dir(directory)
    if not existed:
        if not create:
            yield "withdrawn", -1
            return
        ensure_owner_only_dir(directory)
    lock = _open_lock(directory)
    try:
        if not _acquire_lock(lock, wait):
            yield "busy", -1
            return
        if not _holds_lock_of(directory, lock) or (
            entered is not None and not _same_file(lock, entered)
        ):
            yield "withdrawn", -1
            return
        if admitted is not None and not _still_admitted(admitted):
            if not existed:
                _remove_renamed(directory)
            yield "withdrawn", -1
            return
        yield "write", lock
    finally:
        os.close(lock)


def remove_workspace_fingerprints(directory: Path) -> None:
    """Remove one workspace's fingerprint store: snapshots, cache and tally. Never raises.

    Observation revoke calls this after it has saved the revoked consent. It takes the store lock
    first, so a write under that lock (a pre-call snapshot, a tally update) finishes before the
    store goes, and any later one re-checks consent and finds it revoked; then it renames the
    directory to a private sibling, so no later write by path (the digest cache, a marker) can
    land in the tree being removed, and a writer that waited on the lock finds its store gone. The
    lock wait is bounded: removal goes ahead without the lock rather than leave a revoked store
    behind. A sibling left by an interrupted earlier removal of the same store is removed too.
    """

    with contextlib.suppress(OSError):
        if stat.S_ISDIR(os.lstat(directory).st_mode):
            doomed = directory
            lock: int | None = None
            with contextlib.suppress(OSError):
                lock = _open_lock(directory)
            try:
                if lock is not None:
                    _acquire_lock(lock, _REVOKE_LOCK_WAIT_SECONDS)
                doomed = _renamed_away(directory)
            finally:
                if lock is not None:
                    # Once renamed, a writer that takes the lock finds another lock file (or
                    # none) at the store's path: the removal itself need not hold it.
                    os.close(lock)
            _remove_tree(doomed)
    with contextlib.suppress(OSError):
        prefix = f".{directory.name}{_REVOKED_INFIX}"
        for name in os.listdir(directory.parent):
            if name.startswith(prefix):
                _remove_tree(directory.parent / name)


def _renamed_away(directory: Path) -> Path:
    """Rename *directory* to a private sibling and return it (*directory* if the rename failed)."""

    renamed = directory.with_name(f".{directory.name}{_REVOKED_INFIX}{os.urandom(6).hex()}")
    try:
        os.rename(directory, renamed)
    except OSError:
        return directory
    return renamed


def _remove_renamed(directory: Path) -> None:
    _remove_tree(_renamed_away(directory))


def _remove_tree(path: Path) -> None:
    # A write already in flight when the directory was renamed can still add an entry after a
    # pass has listed it; another pass takes it.
    for _ in range(_REMOVE_PASSES):
        shutil.rmtree(path, ignore_errors=True)
        if not os.path.lexists(path):
            return


def _counts_json(counts: Mapping[str, int]) -> JsonObject:
    unavailable = {
        key.partition(":")[2]: value
        for key, value in sorted(counts.items())
        if key.startswith(f"{WORKSPACE_UNAVAILABLE}:")
    }
    return JsonObject(
        {
            WORKSPACE_UNCHANGED: counts.get(WORKSPACE_UNCHANGED, 0),
            WORKSPACE_CHANGED: counts.get(WORKSPACE_CHANGED, 0),
            WORKSPACE_UNAVAILABLE: sum(unavailable.values()),
            "unavailable_reasons": JsonObject(dict(unavailable)),
        }
    )


def _render_ms(epoch_ms: int) -> str:
    seconds, millis = divmod(epoch_ms, 1000)
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(seconds)) + f".{millis:03d}Z"


def reading_tally_summary(directory: Path | None) -> JsonObject:
    """The bounded reading tally of one workspace's fingerprint directory, for ``observe status``.

    A status read never creates the directory, the lock or the tally. Every value is a closed
    token, a count, a time or a host tool-call id that already matched the closed token pattern.
    """

    status = "absent"
    document: dict[str, object] | None = None
    dropped = 0
    if directory is not None:
        try:
            if existing_owner_only_dir(directory):
                status, document = _read_tally(directory / _READING_NAME)
                dropped = _drop_count(directory)
        except OSError, PathSafetyError:
            status, document = "unreadable", None
    counts: Mapping[str, int] = (
        {} if document is None else cast(Mapping[str, int], document["counts"])
    )
    hour = time.time_ns() // 1_000_000 // _HOUR_MS
    recent_counts: dict[str, int] = {}
    if document is not None:
        for slot in cast(list[dict[str, object]], document["slots"]):
            if hour - 1 <= cast(int, slot["hour"]) <= hour:
                for key, value in cast(dict[str, int], slot["counts"]).items():
                    recent_counts[key] = min(_MAX_SAFE, recent_counts.get(key, 0) + value)
    recent: list[JsonValue] = []
    if document is not None:
        for item in cast(list[dict[str, object]], document["recent"]):
            recent.append(
                JsonObject(
                    {
                        "at": _render_ms(cast(int, item["at_ms"])),
                        "effect": cast(str, item["effect"]),
                        "reason": cast(str | None, item["reason"]),
                        "call": cast(str | None, item["call"]),
                    }
                )
            )
    return JsonObject(
        {
            "status": status,
            "since": None if document is None else _render_ms(cast(int, document["since_ms"])),
            "all": _counts_json(counts),
            "recent_window": "current_and_previous_clock_hour",
            "recent_counts": _counts_json(recent_counts),
            "ring_capacity": READING_RING,
            "recent_readings": tuple(recent),
            # Readings that could not take the lock within the bounded wait: a lower bound.
            "dropped_sample_count": dropped,
        }
    )
