"""Whether a process a tool call started may still be running in the workspace (PR #1080 round 6).

A host reports a shell call ended when the process it started exited. That does not establish that
the workspace is quiescent: an ordinary program can start a child in a new session
(``subprocess.Popen(..., start_new_session=True)``), exit 0, and leave the child to write after the
post-call fingerprint. No command-text rule can see that. This adapter reads the process table
instead, at the start of the post-call pass, and answers one question: is a process of this user
that started during the call window still running *in the workspace*?

**Candidates.** A process of the effective user that

* started at or after the window start (the pre-call pass's start, less a small clock slack),
* is still running (not a zombie), and
* is not parented, directly or through its current ancestors, by this hook's own process chain or
  by the host that ran this hook. The host's other children (its parallel hooks, its other tool
  calls) are its own ongoing work and are judged by their own calls. A child a command left behind
  is reparented away from the host when its launcher exits (to ``init``/``launchd`` or a
  subreaper), so it is a candidate.

A candidate lingers in the workspace when its working directory, or a file it holds open for
writing, lies inside the canonical workspace root. Read-only descriptors do not count: an indexer
or a viewer reading a file is not a writer. A candidate whose working directory or descriptors
cannot be read counts as lingering (the conservative direction).

**Platforms.** macOS reads ``libproc`` (``proc_listpids``, ``proc_pidinfo``,
``proc_pidfdinfo``); Linux and WSL 2 read ``/proc``. Anywhere else, or when the process table
cannot be read, the answer is ``None``: FinishUP cannot establish that no writer lingers, and the
caller reports the comparison ``unavailable``.

**Limits** (documented in ADR-033). A process that changed its working directory away from the
workspace and holds no workspace file open, but later opens one by absolute path, is not seen. A
background job still parented by a long-lived process the host owns (a persistent terminal shell
the host started) is the host's descendant and is not a candidate; the background-operator text
rule still covers ``cmd &``. A process started before the call (a dev server from an earlier call)
is outside the window. A host that makes itself a subreaper keeps orphans as its own children.
Process start times are wall-clock on macOS and boot-clock ticks on Linux; the slack absorbs their
resolution. Nothing here kills, signals or attaches to any process.
"""

from __future__ import annotations

import contextlib
import ctypes
import os
import struct
import sys
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Final

__all__ = [
    "PROCESS_CLOCK_SLACK_NS",
    "lingering_process",
    "process_clock_ns",
]

# Processes started this long before the window start still count as started in it: the boot-clock
# tick on Linux is 10 ms, and a conservative window costs only an extra review.
PROCESS_CLOCK_SLACK_NS: Final = 50_000_000
# How many ancestors are followed before a chain is treated as unreadable (a cycle guard).
_MAX_CHAIN: Final = 256
# A candidate holding more descriptors than this is not read through; it counts as lingering.
_MAX_DESCRIPTORS: Final = 4096


@dataclass(frozen=True, slots=True)
class _Process:
    ppid: int
    started_ns: int
    zombie: bool


def process_clock_ns() -> int | None:
    """Now, on the clock this platform's process start times use, or ``None`` when unsupported."""

    if sys.platform == "darwin":
        return time.time_ns()
    if sys.platform.startswith("linux"):
        clock = getattr(time, "CLOCK_BOOTTIME", None)
        try:
            return time.clock_gettime_ns(clock if clock is not None else time.CLOCK_MONOTONIC)
        except OSError:
            return None
    return None


def _inside(path: str | None, root: str) -> bool:
    if not path:
        return False
    return path == root or path.startswith(root.rstrip("/") + "/")


# -- macOS ------------------------------------------------------------------------------------------

_PROC_UID_ONLY: Final = 4
_PROC_PIDLISTFDS: Final = 1
_PROC_PIDTBSDINFO: Final = 3
_PROC_PIDVNODEPATHINFO: Final = 9
_PROC_PIDFDVNODEPATHINFO: Final = 2
_PROX_FDTYPE_VNODE: Final = 1
_BSDINFO_SIZE: Final = 136
_VNODE_INFO_SIZE: Final = 152
_MAXPATHLEN: Final = 1024
_VNODEPATHINFO_SIZE: Final = 2 * (_VNODE_INFO_SIZE + _MAXPATHLEN)
_FDINFO_SIZE: Final = 8
_PROC_FILEINFO_SIZE: Final = 24
_FD_VNODEPATH_SIZE: Final = _PROC_FILEINFO_SIZE + _VNODE_INFO_SIZE + _MAXPATHLEN
_SZOMB: Final = 5
_FWRITE: Final = 0x0002


class _LibProc:
    """The few ``libproc`` calls this adapter makes, with fixed-size buffers."""

    def __init__(self) -> None:
        library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        self._listpids = library.proc_listpids
        self._listpids.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_int]
        self._listpids.restype = ctypes.c_int
        self._pidinfo = library.proc_pidinfo
        self._pidinfo.argtypes = [
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_uint64,
            ctypes.c_void_p,
            ctypes.c_int,
        ]
        self._pidinfo.restype = ctypes.c_int
        self._pidfdinfo = library.proc_pidfdinfo
        self._pidfdinfo.argtypes = [
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_int,
        ]
        self._pidfdinfo.restype = ctypes.c_int

    def pids(self, uid: int) -> tuple[int, ...] | None:
        needed = self._listpids(_PROC_UID_ONLY, uid, None, 0)
        if needed <= 0:
            return None
        capacity = needed // 4 + 256
        buffer = (ctypes.c_int * capacity)()
        filled = self._listpids(_PROC_UID_ONLY, uid, buffer, ctypes.sizeof(buffer))
        if filled <= 0:
            return None
        return tuple(pid for pid in buffer[: filled // 4] if pid > 0)

    def process(self, pid: int) -> _Process | None:
        buffer = ctypes.create_string_buffer(_BSDINFO_SIZE)
        if self._pidinfo(pid, _PROC_PIDTBSDINFO, 0, buffer, _BSDINFO_SIZE) != _BSDINFO_SIZE:
            return None
        raw = buffer.raw
        (status,) = struct.unpack_from("<I", raw, 4)
        (ppid,) = struct.unpack_from("<I", raw, 16)
        seconds, microseconds = struct.unpack_from("<QQ", raw, 120)
        return _Process(ppid, seconds * 1_000_000_000 + microseconds * 1_000, status == _SZOMB)

    def cwd(self, pid: int) -> str | None:
        buffer = ctypes.create_string_buffer(_VNODEPATHINFO_SIZE)
        if (
            self._pidinfo(pid, _PROC_PIDVNODEPATHINFO, 0, buffer, _VNODEPATHINFO_SIZE)
            != _VNODEPATHINFO_SIZE
        ):
            return None
        raw = buffer.raw[_VNODE_INFO_SIZE : _VNODE_INFO_SIZE + _MAXPATHLEN]
        return os.fsdecode(raw.split(b"\0", 1)[0]) or None

    def written_paths(self, pid: int) -> tuple[str, ...] | None:
        """The paths of the files *pid* holds open for writing."""

        needed = self._pidinfo(pid, _PROC_PIDLISTFDS, 0, None, 0)
        if needed <= 0 or needed // _FDINFO_SIZE > _MAX_DESCRIPTORS:
            return None
        count = needed // _FDINFO_SIZE + 16
        buffer = ctypes.create_string_buffer(count * _FDINFO_SIZE)
        filled = self._pidinfo(pid, _PROC_PIDLISTFDS, 0, buffer, count * _FDINFO_SIZE)
        if filled <= 0:
            return None
        paths: list[str] = []
        path_buffer = ctypes.create_string_buffer(_FD_VNODEPATH_SIZE)
        start = _PROC_FILEINFO_SIZE + _VNODE_INFO_SIZE
        for offset in range(0, filled - filled % _FDINFO_SIZE, _FDINFO_SIZE):
            descriptor, kind = struct.unpack_from("<iI", buffer.raw, offset)
            if kind != _PROX_FDTYPE_VNODE:
                continue
            if (
                self._pidfdinfo(
                    pid, descriptor, _PROC_PIDFDVNODEPATHINFO, path_buffer, _FD_VNODEPATH_SIZE
                )
                != _FD_VNODEPATH_SIZE
            ):
                continue
            (open_flags,) = struct.unpack_from("<I", path_buffer.raw, 0)
            if not open_flags & _FWRITE:
                continue
            raw = path_buffer.raw[start : start + _MAXPATHLEN]
            path = os.fsdecode(raw.split(b"\0", 1)[0])
            if path:
                paths.append(path)
        return tuple(paths)


_LIBPROC: list[_LibProc | None] = []


def _libproc() -> _LibProc | None:
    if not _LIBPROC:
        try:
            _LIBPROC.append(_LibProc())
        except (OSError, AttributeError):
            _LIBPROC.append(None)
    return _LIBPROC[0]


# -- Linux ------------------------------------------------------------------------------------------


def _parse_linux_stat(raw: bytes, tick_ns: float) -> _Process | None:
    """Parse ``/proc/<pid>/stat``: the command name may hold spaces and parentheses."""

    close = raw.rfind(b")")
    if close < 0:
        return None
    fields = raw[close + 2 :].split()
    if len(fields) < 20:
        return None
    try:
        state = fields[0]
        ppid = int(fields[1])
        started = int(fields[19])
    except ValueError:
        return None
    return _Process(ppid, int(started * tick_ns), state in {b"Z", b"X", b"x"})


def _linux_process(pid: int, tick_ns: float) -> _Process | None:
    try:
        with open(f"/proc/{pid}/stat", "rb") as handle:
            raw = handle.read(4096)
    except OSError:
        return None
    return _parse_linux_stat(raw, tick_ns)


def _linux_table(uid: int) -> tuple[dict[int, _Process], float] | None:
    try:
        tick_ns = 1_000_000_000 / os.sysconf("SC_CLK_TCK")
        names = os.listdir("/proc")
    except (OSError, ValueError, ZeroDivisionError):
        return None
    table: dict[int, _Process] = {}
    for name in names:
        if not name.isdigit():
            continue
        pid = int(name)
        try:
            if os.stat(f"/proc/{pid}").st_uid != uid:
                continue
        except OSError:
            continue
        process = _linux_process(pid, tick_ns)
        if process is not None:
            table[pid] = process
    return table, tick_ns


def _linux_cwd(pid: int) -> str | None:
    try:
        return os.readlink(f"/proc/{pid}/cwd")
    except OSError:
        return None


def _linux_written_paths(pid: int) -> tuple[str, ...] | None:
    """The paths of the files *pid* holds open for writing (``O_WRONLY`` or ``O_RDWR``)."""

    directory = f"/proc/{pid}/fd"
    try:
        names = os.listdir(directory)
    except OSError:
        return None
    if len(names) > _MAX_DESCRIPTORS:
        return None
    paths: list[str] = []
    for name in names:
        with contextlib.suppress(OSError, ValueError):
            target = os.readlink(f"{directory}/{name}")
            if not target.startswith("/"):
                continue
            with open(f"/proc/{pid}/fdinfo/{name}", "rb") as handle:
                info = handle.read(1024)
            flags = next(
                (
                    int(line.split(b":", 1)[1].strip(), 8)
                    for line in info.splitlines()
                    if line.startswith(b"flags:")
                ),
                None,
            )
            if flags is None or flags & 0o3:
                paths.append(target)
    return tuple(paths)


# -- shared decision --------------------------------------------------------------------------------


def _chain(pid: int, lookup: Mapping[int, _Process], fetch: object) -> list[tuple[int, _Process]]:
    """This process and its ancestors, nearest first (other users' ancestors are fetched)."""

    chain: list[tuple[int, _Process]] = []
    seen: set[int] = set()
    current = pid
    while current > 1 and current not in seen and len(chain) < _MAX_CHAIN:
        seen.add(current)
        process = lookup.get(current)
        if process is None and callable(fetch):
            fetched = fetch(current)
            process = fetched if isinstance(fetched, _Process) else None
        if process is None:
            break
        chain.append((current, process))
        current = process.ppid
    return chain


def _owned_roots(chain: list[tuple[int, _Process]], window_ns: int) -> frozenset[int]:
    """This hook's own chain up to and including the host that ran it.

    The chain members that started inside the window are this hook's launchers; the first member
    that started before it is the host (in a test, the test process itself). The window carries the
    same clock slack as the candidates: a launcher whose start time the platform rounded down (the
    10 ms Linux tick) is still a launcher, not the host (#1090 PL-1).
    """

    owned: set[int] = set()
    for pid, process in chain:
        owned.add(pid)
        if process.started_ns < window_ns - PROCESS_CLOCK_SLACK_NS:
            break
    owned.discard(1)
    owned.discard(0)
    return frozenset(owned)


def _descends_from(pid: int, owned: frozenset[int], lookup: Mapping[int, _Process]) -> bool:
    current = pid
    for _ in range(_MAX_CHAIN):
        if current in owned:
            return True
        process = lookup.get(current)
        if process is None or process.ppid <= 1:
            return False
        current = process.ppid
    return False


def _candidates(
    lookup: Mapping[int, _Process], window_ns: int, owned: frozenset[int]
) -> Iterable[int]:
    threshold = window_ns - PROCESS_CLOCK_SLACK_NS
    for pid, process in lookup.items():
        if process.zombie or process.started_ns < threshold:
            continue
        if _descends_from(pid, owned, lookup):
            continue
        yield pid


def lingering_process(window_ns: int, workspace_root: str) -> bool | None:
    """Whether a process started since *window_ns* still runs in *workspace_root*.

    ``window_ns`` is a ``process_clock_ns`` reading taken when the pre-call pass started.
    ``None`` means the process table could not be read here, so no answer can be established.
    Never raises.
    """

    try:
        root = os.path.realpath(workspace_root)
        uid = os.geteuid()
        if sys.platform == "darwin":
            library = _libproc()
            if library is None:
                return None
            pids = library.pids(uid)
            if pids is None:
                return None
            lookup: dict[int, _Process] = {}
            for pid in pids:
                process = library.process(pid)
                if process is not None:
                    lookup[pid] = process
            fetch: object = library.process
            cwd = library.cwd
            written_paths = library.written_paths
        elif sys.platform.startswith("linux"):
            table = _linux_table(uid)
            if table is None:
                return None
            lookup, tick_ns = table

            def fetch_linux(pid: int) -> _Process | None:
                return _linux_process(pid, tick_ns)

            fetch = fetch_linux
            cwd = _linux_cwd
            written_paths = _linux_written_paths
        else:
            return None
        chain = _chain(os.getpid(), lookup, fetch)
        if not chain:
            return None
        owned = _owned_roots(chain, window_ns)
        for pid in _candidates(lookup, window_ns, owned):
            directory = cwd(pid)
            if directory is None:
                still = fetch(pid) if callable(fetch) else None
                if not isinstance(still, _Process) or still.zombie:
                    continue  # it exited while it was read
                return True
            if _inside(os.path.realpath(directory), root) or _inside(directory, root):
                return True
            paths = written_paths(pid)
            if paths is None:
                still = fetch(pid) if callable(fetch) else None
                if not isinstance(still, _Process) or still.zombie:
                    continue
                return True
            if any(_inside(path, root) for path in paths):
                return True
        return False
    except Exception:
        return None
