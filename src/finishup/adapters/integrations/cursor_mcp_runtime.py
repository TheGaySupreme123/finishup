"""Live Cursor MCP process identity, classified without retaining argv bytes.

Installed plugin files name a desired route. Cursor can keep a shared ``mcp-process`` helper
alive across Reload Window, so file status alone cannot prove that model calls use that route.
This module classifies exact known ``finishup mcp serve`` argv suffixes and Cursor-helper parents
into counts and an activation token. When the installed marker binds an exact launcher, the
tokens before ``mcp serve`` are compared with that launcher so a helper child running a different
FinishUP executable (an ambient PATH install, another channel) is reported as an executable mismatch
(issue #468). Unmatched tokens are dropped and never logged.
"""

from __future__ import annotations

import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal, Protocol

from finishup.legacy_names import LAUNCHER_NAMES

__all__ = [
    "CursorMcpProcessPort",
    "CursorMcpProcessSnapshot",
    "CursorMcpRuntimeObservation",
    "FixedCursorMcpProcesses",
    "OsCursorMcpProcesses",
    "classify_cursor_semantic_ceiling",
    "classify_serve_argv",
    "launcher_precedes_serve_in_text",
    "observe_cursor_mcp_runtime",
]

_MAX_PROCESSES: Final = 64
_MAX_TOKENS: Final = 12
_MAX_COMM: Final = 32
_MAX_PROJECT_SELECTOR: Final = 8_192
_PS_EXECUTABLE: Final = "/bin/ps"
_POLICY_SUFFIXES: Final = frozenset(
    {
        ("mcp", "serve"),
        ("mcp", "serve", "--host", "cursor"),
    }
)
_STRICT_SUFFIXES: Final = frozenset(
    {
        ("mcp", "serve", "--semantic", "off"),
        ("mcp", "serve", "--host", "cursor", "--semantic", "off"),
    }
)
_CURSOR_COMM_PREFIXES: Final = ("Cursor", "Cursor Helper")
_CURSOR_COMM_EXACT: Final = frozenset({"Cursor", "mcp-process"})


type CursorRuntimeActivation = Literal["unobserved", "matched", "full_restart_required"]
type CursorLauncherMatch = Literal["matched", "different", "unresolved"]
type CursorExecutableActivation = Literal[
    "unobserved", "matched", "unproven", "executable_mismatch"
]
type CursorCeilingClass = Literal[
    "not_applicable",
    "genuine_route_ceiling",
    "activation_mismatch",
    "activation_unproven",
]


@dataclass(frozen=True, slots=True)
class CursorMcpProcessSnapshot:
    """One classified live process.

    ``route_profile`` is the exact known serve suffix class (``None`` for a foreign suffix).
    ``launcher`` compares the tokens before ``mcp serve`` with the expected bound launcher:
    ``matched`` (exact), ``different`` (another absolute executable), ``unresolved`` (a bare
    name that cannot be attributed), or ``None`` when no launcher was expected.
    """

    parent_kind: Literal["cursor_helper", "other"]
    route_profile: Literal["strict", "policy"] | None
    launcher: CursorLauncherMatch | None = None

    def __post_init__(self) -> None:
        if self.parent_kind not in {"cursor_helper", "other"}:
            raise ValueError("cursor_mcp_process_invalid")
        if self.route_profile not in {None, "strict", "policy"}:
            raise ValueError("cursor_mcp_process_invalid")
        if self.launcher not in {None, "matched", "different", "unresolved"}:
            raise ValueError("cursor_mcp_process_invalid")


@dataclass(frozen=True, slots=True)
class CursorMcpRuntimeObservation:
    observed: bool
    activation: CursorRuntimeActivation
    live_route_profile: Literal["strict", "policy"] | None
    policy_process_count: int
    strict_process_count: int
    foreign_process_count: int
    executable_activation: CursorExecutableActivation = "unobserved"

    def __post_init__(self) -> None:
        if type(self.observed) is not bool:
            raise ValueError("cursor_mcp_runtime_invalid")
        if self.activation not in {"unobserved", "matched", "full_restart_required"}:
            raise ValueError("cursor_mcp_runtime_invalid")
        if self.executable_activation not in {
            "unobserved",
            "matched",
            "unproven",
            "executable_mismatch",
        }:
            raise ValueError("cursor_mcp_runtime_invalid")
        if self.executable_activation == "executable_mismatch" and (
            self.activation != "full_restart_required"
        ):
            raise ValueError("cursor_mcp_runtime_invalid")
        if self.live_route_profile not in {None, "strict", "policy"}:
            raise ValueError("cursor_mcp_runtime_invalid")
        for count in (
            self.policy_process_count,
            self.strict_process_count,
            self.foreign_process_count,
        ):
            if type(count) is not int or count < 0 or count > _MAX_PROCESSES:
                raise ValueError("cursor_mcp_runtime_invalid")
        if self.activation == "unobserved" and self.live_route_profile is not None:
            raise ValueError("cursor_mcp_runtime_invalid")
        if self.activation == "matched" and self.live_route_profile not in {"strict", "policy"}:
            raise ValueError("cursor_mcp_runtime_invalid")


class CursorMcpProcessPort(Protocol):
    def snapshot(self) -> tuple[CursorMcpProcessSnapshot, ...] | None:
        """Return classified processes, or ``None`` when the scan itself is unavailable."""


@dataclass(frozen=True, slots=True)
class FixedCursorMcpProcesses:
    processes: tuple[CursorMcpProcessSnapshot, ...] | None

    def snapshot(self) -> tuple[CursorMcpProcessSnapshot, ...] | None:
        return self.processes


def _cursor_helper_comm(value: str) -> bool:
    if type(value) is not str or not value:
        return False
    value = value.rsplit("/", 1)[-1]
    if not value or len(value) > _MAX_COMM:
        return False
    if any(ord(char) < 32 or ord(char) > 126 for char in value):
        return False
    if value in _CURSOR_COMM_EXACT or value == "cursor":
        return True
    return (value.startswith(_CURSOR_COMM_PREFIXES) or value.startswith("cursor-helper")) and all(
        char.isalnum() or char in {" ", "(", ")", "-"} for char in value
    )


# Either launcher spelling (ADR-048): a Cursor helper keeps running the ``yoetz mcp serve`` child
# a pre-rename registration spawned until the host restarts it, and that child is still FinishUP.
_LAUNCHER_TOKENS: Final = frozenset({*LAUNCHER_NAMES, *(f"{name}.exe" for name in LAUNCHER_NAMES)})


def _finishup_launcher_token(value: str) -> bool:
    if type(value) is not str or not value or len(value) > 4_096:
        return False
    return value.replace("\\", "/").rsplit("/", 1)[-1] in _LAUNCHER_TOKENS


def classify_serve_suffix(
    tokens: Sequence[str],
) -> Literal["strict", "policy", "foreign"] | None:
    """Classify a serve suffix. Returns ``None`` when ``mcp serve`` is absent."""

    kind, _launcher = classify_serve_argv(tokens, None)
    return kind


def _valid_project_selector(value: str) -> bool:
    """Recognize Cursor's expanded workspace selector without retaining its path."""

    if type(value) is not str or not value:
        return False
    try:
        if len(value.encode("utf-8")) > _MAX_PROJECT_SELECTOR:
            return False
    except UnicodeEncodeError:
        return False
    if not value.startswith("/") or value.startswith("//"):
        return False
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        return False
    try:
        selector = Path(value)
    except OSError, ValueError:
        return False
    # Match the bridge's lexical authority checks without probing the filesystem here.  Runtime
    # classification identifies the argv shape only; existence, ownership, symlink safety, and
    # roots/list membership remain separate binding gates.
    return selector != Path(selector.anchor) and ".." not in selector.parts


def _classify_cursor_project_suffix(
    suffix: tuple[str, ...],
) -> Literal["strict", "policy"] | None:
    """Classify the exact project registration suffix with its expanded root argument."""

    prefix = ("mcp", "serve", "--host", "cursor", "--project-root")
    if len(suffix) < len(prefix) + 1 or suffix[: len(prefix)] != prefix:
        return None
    if not _valid_project_selector(suffix[len(prefix)]):
        return None
    tail = suffix[len(prefix) + 1 :]
    if not tail:
        return "policy"
    if tail == ("--semantic", "off"):
        return "strict"
    return None


def _launcher_match(
    tokens: Sequence[str], serve_index: int, expected_launcher: tuple[str, ...]
) -> CursorLauncherMatch:
    width = len(expected_launcher)
    if (
        serve_index >= width
        and tuple(tokens[serve_index - width : serve_index]) == expected_launcher
    ):
        return "matched"
    if width > 1 and serve_index >= width:
        # Module entrypoint shape (``<interpreter> -m finishup``): the fixed tail matched but the
        # interpreter is another explicit executable.
        head = tokens[serve_index - width]
        tail = tuple(tokens[serve_index - width + 1 : serve_index])
        if tail == expected_launcher[1:] and ("/" in head or "\\" in head):
            return "different"
    preceding = tokens[serve_index - 1]
    if "/" in preceding or "\\" in preceding:
        # An absolute (or explicit) executable that is not the bound launcher: another
        # installation answered the host's spawn.
        return "different"
    return "unresolved"


def launcher_precedes_serve_in_text(text: str, expected_launcher: tuple[str, ...]) -> bool:
    """True when the whitespace-joined launcher immediately precedes ``mcp serve`` in ``text``.

    Used for the macOS ``ps`` rendering, where argv is one string and a launcher path that
    contains whitespace cannot be recovered by splitting. The launcher must sit at the start of
    the text or after a space, so a longer path that merely ends with the same suffix does not
    match.
    """

    if type(text) is not str or not expected_launcher or len(text) > 8_192:
        return False
    if any(type(part) is not str or not part for part in expected_launcher):
        return False
    needle = " ".join(expected_launcher) + " mcp serve"
    padded = " " + text
    return (" " + needle + " " in padded + " ") or padded.endswith(" " + needle)


def classify_serve_argv(
    tokens: Sequence[str],
    expected_launcher: tuple[str, ...] | None,
) -> tuple[Literal["strict", "policy", "foreign"] | None, CursorLauncherMatch | None]:
    """Classify one argv as ``(serve suffix class, launcher match)``.

    The suffix class is ``None`` when ``mcp serve`` is absent. The launcher match is ``None``
    when no launcher was expected or the suffix is absent; otherwise it compares the tokens that
    precede ``mcp`` with ``expected_launcher`` exactly. A shebang console script shows up as
    ``<interpreter> <script> mcp serve …`` and a module entrypoint as
    ``<interpreter> -m finishup mcp serve …``; both compare on the exact bound tuple.
    """

    suffix: tuple[str, ...] | None = None
    serve_index: int | None = None
    for index, token in enumerate(tokens):
        if type(token) is not str:
            return None, None
        if (
            token == "mcp"
            and index > 0
            and _finishup_launcher_token(tokens[index - 1])
            and index + 1 < len(tokens)
            and tokens[index + 1] == "serve"
        ):
            rest = tuple(tokens[index:])
            if len(rest) > _MAX_TOKENS:
                return "foreign", None
            suffix = rest
            serve_index = index
    if suffix is None or serve_index is None:
        return None, None
    launcher: CursorLauncherMatch | None = None
    if expected_launcher is not None and expected_launcher:
        launcher = _launcher_match(tokens, serve_index, expected_launcher)
    project_kind = _classify_cursor_project_suffix(suffix)
    if project_kind is not None:
        return project_kind, launcher
    if suffix in _POLICY_SUFFIXES:
        return "policy", launcher
    if suffix in _STRICT_SUFFIXES:
        return "strict", launcher
    return "foreign", launcher


def observe_cursor_mcp_runtime(
    *,
    installed_route: Literal["strict", "policy"] | None,
    processes: CursorMcpProcessPort,
) -> CursorMcpRuntimeObservation:
    """Compare classified Cursor-helper children with the installed winning route.

    When snapshots carry a launcher comparison, a helper child whose executable differs from
    the bound launcher is an ``executable_mismatch``: the host is running another FinishUP
    installation behind marker-valid plugin bytes, and only a full application quit replaces
    that process. An unattributable bare launcher leaves the executable ``unproven``.
    """

    snapshot = processes.snapshot()
    if snapshot is None:
        return CursorMcpRuntimeObservation(False, "unobserved", None, 0, 0, 0)
    policy = 0
    strict = 0
    foreign = 0
    helper_routes: set[Literal["strict", "policy"]] = set()
    helper_foreign = False
    helper_launchers: set[CursorLauncherMatch] = set()
    scan_truncated = len(snapshot) > _MAX_PROCESSES
    for item in snapshot[:_MAX_PROCESSES]:
        if type(item) is not CursorMcpProcessSnapshot:
            continue
        if item.route_profile == "policy":
            policy += 1
            if item.parent_kind == "cursor_helper":
                helper_routes.add("policy")
        elif item.route_profile == "strict":
            strict += 1
            if item.parent_kind == "cursor_helper":
                helper_routes.add("strict")
        else:
            foreign += 1
            if item.parent_kind == "cursor_helper":
                helper_foreign = True
        if item.parent_kind == "cursor_helper" and item.launcher is not None:
            helper_launchers.add(item.launcher)
    if scan_truncated or (not helper_routes and not helper_foreign):
        return CursorMcpRuntimeObservation(True, "unobserved", None, policy, strict, foreign)
    live: Literal["strict", "policy"] | None
    if len(helper_routes) == 1 and not helper_foreign:
        live = next(iter(helper_routes))
    else:
        live = None
    executable: CursorExecutableActivation
    if not helper_launchers:
        executable = "unobserved"
    elif "different" in helper_launchers:
        executable = "executable_mismatch"
    elif helper_launchers == {"matched"}:
        executable = "matched"
    else:
        executable = "unproven"
    if live is not None and live == installed_route and executable != "executable_mismatch":
        activation: CursorRuntimeActivation = "matched"
    else:
        activation = "full_restart_required"
    return CursorMcpRuntimeObservation(True, activation, live, policy, strict, foreign, executable)


def classify_cursor_semantic_ceiling(
    *,
    semantic_status: str,
    semantic_reason: str,
    installed_route: Literal["strict", "policy"] | None,
    runtime: CursorMcpRuntimeObservation,
) -> CursorCeilingClass:
    """Distinguish a live strict ceiling from installed-policy vs stale-runtime mismatch."""

    if semantic_status != "blocked_by_policy" or semantic_reason != "route_semantic_ceiling":
        return "not_applicable"
    if installed_route == "strict" and runtime.activation != "full_restart_required":
        return "genuine_route_ceiling"
    if installed_route == "policy":
        if runtime.activation == "full_restart_required":
            return "activation_mismatch"
        if runtime.activation == "matched" and runtime.live_route_profile == "policy":
            return "activation_mismatch"
        return "activation_unproven"
    if runtime.activation == "full_restart_required":
        return "activation_mismatch"
    return "genuine_route_ceiling"


def _linux_snapshots(
    expected_launcher: tuple[str, ...] | None,
) -> tuple[CursorMcpProcessSnapshot, ...] | None:
    proc = Path("/proc")
    if not proc.is_dir():
        return None
    try:
        pid_dirs = tuple(path for path in proc.iterdir() if path.name.isdigit())
    except OSError:
        return None
    comm_by_pid: dict[int, str] = {}
    ppid_by_pid: dict[int, int] = {}
    classified: list[CursorMcpProcessSnapshot] = []
    for path in pid_dirs:
        try:
            pid = int(path.name)
        except ValueError:
            continue
        try:
            comm = path.joinpath("comm").read_text(encoding="ascii", errors="ignore").strip()
        except OSError:
            continue
        comm_by_pid[pid] = comm
        try:
            status_text = path.joinpath("status").read_text(encoding="ascii", errors="ignore")
            for line in status_text.splitlines():
                if line.startswith("PPid:"):
                    ppid_by_pid[pid] = int(line.split(":", 1)[1].strip())
                    break
        except OSError, ValueError:
            continue
    for path in pid_dirs:
        if len(classified) > _MAX_PROCESSES:
            break
        try:
            raw = path.joinpath("cmdline").read_bytes()
        except OSError:
            continue
        if not raw or len(raw) > 4096:
            continue
        tokens = tuple(part.decode("utf-8", errors="ignore") for part in raw.split(b"\0") if part)
        kind, launcher = classify_serve_argv(tokens, expected_launcher)
        if kind is None:
            continue
        try:
            pid = int(path.name)
        except ValueError:
            continue
        parent = ppid_by_pid.get(pid)
        parent_comm = comm_by_pid.get(parent, "") if parent is not None else ""
        grand = ppid_by_pid.get(parent, 0) if parent is not None else 0
        grand_comm = comm_by_pid.get(grand, "") if grand else ""
        helper = _cursor_helper_comm(parent_comm) or _cursor_helper_comm(grand_comm)
        classified.append(
            CursorMcpProcessSnapshot(
                "cursor_helper" if helper else "other",
                None if kind == "foreign" else kind,
                launcher,
            )
        )
    return tuple(classified)


def _parse_ps_table(payload: bytes) -> tuple[tuple[int, int, str], ...]:
    rows: list[tuple[int, int, str]] = []
    for raw_line in payload.splitlines()[: 8 * _MAX_PROCESSES]:
        line = raw_line.decode("utf-8", errors="ignore").strip()
        if not line:
            continue
        parts = line.split(None, 2)
        if len(parts) < 2:
            continue
        try:
            pid = int(parts[0])
            ppid = int(parts[1])
        except ValueError:
            continue
        rest = parts[2] if len(parts) == 3 else ""
        rows.append((pid, ppid, rest[:512]))
    return tuple(rows)


def _darwin_snapshots(
    expected_launcher: tuple[str, ...] | None,
) -> tuple[CursorMcpProcessSnapshot, ...] | None:
    try:
        comm_table = subprocess.run(
            [_PS_EXECUTABLE, "-ax", "-o", "pid=", "-o", "ppid=", "-o", "comm="],
            stdin=subprocess.DEVNULL,
            check=False,
            capture_output=True,
            env={"LANG": "C", "LC_ALL": "C"},
            shell=False,
            timeout=2,
        )
        arg_table = subprocess.run(
            [_PS_EXECUTABLE, "-axww", "-o", "pid=", "-o", "ppid=", "-o", "args="],
            stdin=subprocess.DEVNULL,
            check=False,
            capture_output=True,
            env={"LANG": "C", "LC_ALL": "C"},
            shell=False,
            timeout=2,
        )
    except OSError, ValueError, subprocess.SubprocessError:
        return None
    if comm_table.returncode != 0 or arg_table.returncode != 0:
        return None
    comm_by_pid = {pid: comm for pid, _ppid, comm in _parse_ps_table(comm_table.stdout)}
    ppid_by_pid = {pid: ppid for pid, ppid, _comm in _parse_ps_table(comm_table.stdout)}
    classified: list[CursorMcpProcessSnapshot] = []
    for pid, _ppid, args in _parse_ps_table(arg_table.stdout):
        if len(classified) > _MAX_PROCESSES:
            break
        tokens = tuple(args.split())
        kind, launcher = classify_serve_argv(tokens, expected_launcher)
        if kind is None:
            continue
        if (
            expected_launcher is not None
            and launcher != "matched"
            and launcher_precedes_serve_in_text(args, expected_launcher)
        ):
            # ``ps`` renders argv as one whitespace-joined string, so a bound path that itself
            # contains whitespace splits into fragments; the exact textual form settles it.
            launcher = "matched"
        parent = ppid_by_pid.get(pid)
        parent_comm = comm_by_pid.get(parent, "") if parent is not None else ""
        grand = ppid_by_pid.get(parent, 0) if parent is not None else 0
        grand_comm = comm_by_pid.get(grand, "") if grand else ""
        helper = _cursor_helper_comm(parent_comm) or _cursor_helper_comm(grand_comm)
        classified.append(
            CursorMcpProcessSnapshot(
                "cursor_helper" if helper else "other",
                None if kind == "foreign" else kind,
                launcher,
            )
        )
    return tuple(classified)


@dataclass(frozen=True, slots=True)
class OsCursorMcpProcesses:
    """Live OS scan. ``expected_launcher`` is the installed marker's exact bound launcher."""

    expected_launcher: tuple[str, ...] | None = None

    def snapshot(self) -> tuple[CursorMcpProcessSnapshot, ...] | None:
        try:
            linux = _linux_snapshots(self.expected_launcher)
            if linux is not None:
                return linux
            return _darwin_snapshots(self.expected_launcher)
        except OSError, ValueError, TimeoutError:
            return None
