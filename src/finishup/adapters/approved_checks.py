"""Approved-check runner: fixed argv, commitment-bound, enforcing sandbox when available."""

from __future__ import annotations

import ctypes
import functools
import hashlib
import os
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Final

from finishup.adapters.check_sandbox import default_check_sandbox
from finishup.observability.privacy import redact_high_confidence_content
from finishup.ports.check_sandbox import CheckSandboxPort, CheckSandboxStatus
from finishup.ports.subject_state import LocalWorkspaceHandle
from finishup.protocol.canonical import JsonValue, canonical_digest
from finishup.protocol.errors import ProtocolValueError

__all__ = [
    "APPROVED_CHECK_FORMAT",
    "ApprovedCheckApproval",
    "ApprovedCheckCommand",
    "ApprovedCheckOutcome",
    "ApprovedCheckResult",
    "ApprovedCheckRunner",
    "ApprovedCheckStatus",
    "approval_commitment",
]

APPROVED_CHECK_FORMAT: Final = "yoetz.approved-check/1"
_DEFAULT_TIMEOUT_SECONDS: Final = 30.0
_MAX_OUTPUT_BYTES: Final = 65_536
_MAX_ARGV: Final = 32
_MAX_ARG_BYTES: Final = 512
_TOKEN_CHARS: Final = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._/+-="
)
_REAP_DEADLINE_SECONDS: Final = 5.0
# Once the leader is reaped and no group member is waitable by us, the only way the group can
# still disappear is an external reaper (init/launchd). Give that a short grace window instead
# of burning the whole deadline against zombies we are structurally unable to reap.
_REAP_NO_PROGRESS_SECONDS: Final = 0.5
# Teardown bound for a check that returned on its own: the tree is normally already gone,
# so this only pays for stragglers the check left behind.
_COMPLETED_DRAIN_SECONDS: Final = 1.0
_PR_SET_CHILD_SUBREAPER: Final = 36


class ApprovedCheckStatus(str, Enum):  # noqa: UP042 - exact wire enum
    PASSED = "passed"
    FAILED = "failed"
    REJECTED = "rejected"
    TIMEOUT = "timeout"
    STALE = "stale"


class ApprovedCheckOutcome(str, Enum):  # noqa: UP042 - exact wire enum
    SUCCESS = "success"
    NONZERO_EXIT = "nonzero_exit"
    NOT_APPROVED = "not_approved"
    UNSAFE_ARGV = "unsafe_argv"
    NETWORK_DENIED = "network_denied"
    SANDBOX_UNAVAILABLE = "sandbox_unavailable"
    OUTPUT_TRUNCATED = "output_truncated"
    TIMEOUT = "timeout"
    EXEC_FAILED = "exec_failed"
    SUBJECT_STATE_MISMATCH = "subject_state_mismatch"


@dataclass(frozen=True, slots=True)
class ApprovedCheckApproval:
    """Commitment-backed approval for one exact argv under a workspace policy."""

    approval_id: str
    argv: tuple[str, ...]
    allow_network: bool
    timeout_seconds: float
    approval_commitment: str

    def __post_init__(self) -> None:
        if (
            type(self.approval_id) is not str
            or not self.approval_id
            or len(self.approval_id) > 128
            or type(self.argv) is not tuple
            or not 1 <= len(self.argv) <= _MAX_ARGV
            or type(self.allow_network) is not bool
            or type(self.timeout_seconds) is not float
            or not 0.1 <= self.timeout_seconds <= 300.0
            or type(self.approval_commitment) is not str
            or not self.approval_commitment.startswith("sha256:")
        ):
            raise ProtocolValueError("invalid_approved_check")
        for arg in self.argv:
            if (
                type(arg) is not str
                or not arg
                or len(arg.encode("utf-8")) > _MAX_ARG_BYTES
                or any(ch not in _TOKEN_CHARS and ch not in {":", "@"} for ch in arg)
            ):
                raise ProtocolValueError("invalid_approved_check")
        expected = approval_commitment(
            self.approval_id, self.argv, allow_network=self.allow_network
        )
        if self.approval_commitment != expected:
            raise ProtocolValueError("invalid_approved_check")


@dataclass(frozen=True, slots=True)
class ApprovedCheckCommand:
    workspace: LocalWorkspaceHandle
    approval: ApprovedCheckApproval
    subject_state_digest: str
    expected_subject_state_digest: str | None = None

    def __post_init__(self) -> None:
        if type(self.workspace) is not LocalWorkspaceHandle or not self.workspace.is_validated():
            raise ProtocolValueError("invalid_approved_check")
        if type(self.approval) is not ApprovedCheckApproval:
            raise ProtocolValueError("invalid_approved_check")
        for digest in (self.subject_state_digest, self.expected_subject_state_digest):
            if digest is None:
                continue
            if type(digest) is not str or not digest.startswith("sha256:") or len(digest) != 71:
                raise ProtocolValueError("invalid_approved_check")


@dataclass(frozen=True, slots=True)
class ApprovedCheckResult:
    status: ApprovedCheckStatus
    outcome: ApprovedCheckOutcome
    exit_status: int | None
    output_digest: str | None
    output_bytes: int
    subject_state_digest: str
    approval_commitment: str
    result_digest: str
    duration_ms: int

    def __post_init__(self) -> None:
        if type(self.status) is not ApprovedCheckStatus:
            raise ProtocolValueError("invalid_approved_check")
        if type(self.outcome) is not ApprovedCheckOutcome:
            raise ProtocolValueError("invalid_approved_check")
        if self.exit_status is not None and (
            type(self.exit_status) is not int or not 0 <= self.exit_status <= 255
        ):
            raise ProtocolValueError("invalid_approved_check")
        if self.output_digest is not None and (
            type(self.output_digest) is not str
            or not self.output_digest.startswith("sha256:")
            or len(self.output_digest) != 71
        ):
            raise ProtocolValueError("invalid_approved_check")
        if type(self.output_bytes) is not int or not 0 <= self.output_bytes <= _MAX_OUTPUT_BYTES:
            raise ProtocolValueError("invalid_approved_check")
        if (
            type(self.subject_state_digest) is not str
            or not self.subject_state_digest.startswith("sha256:")
            or type(self.approval_commitment) is not str
            or not self.approval_commitment.startswith("sha256:")
            or type(self.result_digest) is not str
            or not self.result_digest.startswith("sha256:")
            or type(self.duration_ms) is not int
            or self.duration_ms < 0
        ):
            raise ProtocolValueError("invalid_approved_check")


def approval_commitment(approval_id: str, argv: Sequence[str], *, allow_network: bool) -> str:
    """Return the commitment for one exact approved argv (not freeform shell)."""

    return canonical_digest(
        {
            "format": APPROVED_CHECK_FORMAT,
            "approval_id": approval_id,
            "argv": tuple(argv),
            "allow_network": allow_network,
        }
    )


def _owner_private_temp_dirs() -> tuple[Path, Path, tempfile.TemporaryDirectory[str]]:
    """Create owner-private HOME and TMPDIR replacements (never /dev/null)."""

    root = tempfile.TemporaryDirectory(prefix="finishup-check-")
    base = Path(root.name)
    home = base / "home"
    tmp = base / "tmp"
    home.mkdir(mode=0o700)
    tmp.mkdir(mode=0o700)
    os.chmod(home, stat.S_IRWXU)
    os.chmod(tmp, stat.S_IRWXU)
    return home, tmp, root


def _sanitized_env(*, home: Path, tmpdir: Path) -> dict[str, str]:
    return {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.defpath,
        "HOME": str(home),
        "TMPDIR": str(tmpdir),
        "PAGER": "cat",
        "TERM": "dumb",
    }


def _root_from_handle(workspace: LocalWorkspaceHandle) -> Path | None:
    try:
        descriptor = workspace._validated_descriptor()  # pyright: ignore[reportPrivateUsage]
    except ValueError:
        return None
    root = getattr(descriptor, "root", None)
    if isinstance(root, Path):
        return root
    return None


def _bounded_communicate(
    process: subprocess.Popen[bytes],
    *,
    stdout_limit: int,
    timeout_seconds: float,
) -> tuple[bytearray, bool]:
    assert process.stdout is not None
    assert process.stderr is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    selector.register(process.stderr, selectors.EVENT_READ)
    stdout = bytearray()
    truncated = False
    deadline = time.monotonic() + timeout_seconds
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            events = selector.select(timeout=remaining)
            if not events:
                continue
            for key, _ in events:
                chunk = os.read(key.fd, 8_192)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if key.fileobj is process.stdout:
                    room = stdout_limit - len(stdout)
                    if room <= 0:
                        truncated = True
                        continue
                    if len(chunk) > room:
                        stdout.extend(chunk[:room])
                        truncated = True
                    else:
                        stdout.extend(chunk)
                # stderr is discarded after consumption; never retained for advice/status.
        try:
            process.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            # End-of-file on both pipes is not exit: a check may close its own stdout/stderr
            # and keep running. ``TimeoutExpired`` is a ``SubprocessError``, so letting it
            # escape would skip the runner's timeout result *and* its group reaping, leaking
            # the whole tree. Translate it into the timeout contract the runner handles.
            raise TimeoutError from None
    finally:
        selector.close()
    return stdout, truncated


def _wait_process(process: subprocess.Popen[bytes], timeout_seconds: float) -> bool:
    try:
        process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        return False
    return True


def _posix_process_group_id(process: subprocess.Popen[bytes]) -> int | None:
    get_group = getattr(os, "getpgid", None)
    get_self_group = getattr(os, "getpgrp", None)
    if not callable(get_group) or not callable(get_self_group):
        return None
    try:
        group_id = get_group(process.pid)
        self_group = get_self_group()
    except OSError:
        return None
    if type(group_id) is not int or type(self_group) is not int:
        return None
    if group_id <= 1 or group_id == self_group:
        return None
    return group_id


def _signal_posix_group(group_id: int, sig: int) -> bool:
    kill_group = getattr(os, "killpg", None)
    if not callable(kill_group):
        return False
    try:
        kill_group(group_id, sig)
    except OSError:
        return False
    return True


def _posix_group_exists(group_id: int) -> bool:
    return _signal_posix_group(group_id, 0)


@functools.cache
def _enable_child_subreaper() -> bool:
    """Best-effort ``PR_SET_CHILD_SUBREAPER`` so orphaned check descendants stay waitable.

    Under a container PID 1 that never calls ``wait()``, a killed grandchild that outlived its
    parent reparents to PID 1 and stays ``<defunct>`` forever: the process group keeps existing,
    ``killpg(group, 0)`` keeps succeeding, and the reaper below would spin against zombies it
    cannot reap while PIDs leak. As a subreaper this process inherits those orphans instead, so
    ``waitpid(-group, ...)`` can actually clear them. Linux-only; ignored everywhere else.
    """

    if sys.platform != "linux":
        return False
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        prctl = libc.prctl
        prctl.argtypes = [
            ctypes.c_int,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
        ]
        prctl.restype = ctypes.c_int
        return prctl(_PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) == 0
    except (OSError, AttributeError, ValueError):
        # Best effort only: a missing libc symbol or a seccomp-blocked prctl must never fail
        # the check run; the reap loop below degrades to its bounded no-progress exit.
        return False


def _reap_posix_group_members(group_id: int) -> tuple[int, bool]:
    """Reap every waitable member of ``group_id``; return (reaped_count, waitable_remaining).

    ``waitpid(-group_id, WNOHANG)`` is scoped to the isolated check's own process group, so it
    can never steal an unrelated child of this runner. It may reap the leader out from under its
    ``Popen``; that is harmless because ``Popen`` treats ``ChildProcessError`` as "already
    exited" and the timeout result never reports an exit status.
    """

    if os.name == "nt" or not hasattr(os, "waitpid"):
        return 0, False
    reaped = 0
    while True:
        try:
            pid, _status = os.waitpid(-group_id, os.WNOHANG)
        except ChildProcessError:
            # No member of the group is a child of ours: nothing here is waitable.
            return reaped, False
        except OSError:
            return reaped, reaped > 0
        if pid == 0:
            # Live children remain but none has exited yet.
            return reaped, True
        reaped += 1


def _taskkill_tree(pid: int) -> bool:
    """Kill a Windows process *tree*; ``TerminateProcess`` alone spares grandchildren."""

    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell, output discarded
            ["taskkill", "/PID", str(pid), "/T", "/F"],
            capture_output=True,
            check=False,
            timeout=5.0,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    # A nonzero code (access denied, no such pid) means the tree is still standing: report the
    # failure so the caller falls back to ``kill`` now instead of after a five-second wait.
    return completed.returncode == 0


def _reap_windows_process_tree(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None and not _taskkill_tree(process.pid):
        process.kill()
    _wait_process(process, 5.0)
    if process.poll() is None:
        process.kill()
        _wait_process(process, 5.0)


def _drain_posix_group(
    process: subprocess.Popen[bytes],
    group_id: int,
    *,
    deadline_seconds: float,
) -> None:
    """Kill and reap every member of the check's process group until empty or the bound expires.

    Known limitation: a descendant that calls ``setsid`` leaves the group and is not covered
    here; containing that needs a PID namespace (follow-up: bwrap ``--unshare-pid``).
    """

    deadline = time.monotonic() + deadline_seconds
    last_progress = time.monotonic()
    while time.monotonic() < deadline:
        if not _posix_group_exists(group_id):
            break
        _signal_posix_group(group_id, signal.SIGKILL)
        reaped, waitable = _reap_posix_group_members(group_id)
        leader_reaped = process.poll() is not None or _wait_process(process, 0.05)
        if reaped:
            last_progress = time.monotonic()
            continue
        if (
            leader_reaped
            and not waitable
            and time.monotonic() - last_progress >= _REAP_NO_PROGRESS_SECONDS
        ):
            # Signals are delivered and nothing left in the group belongs to us: the remainder
            # are zombies owned by a parent that may never reap them. Stop instead of spending
            # the full deadline on every timed-out check.
            break
        time.sleep(0.01)


def _drain_completed_check_group(process: subprocess.Popen[bytes], group_id: int | None) -> None:
    """Tear the group down after a check returns on its own, not only after a timeout.

    A member the check leaves running would otherwise outlive its result -- and because this
    process is a child subreaper, such an orphan reparents here when its parent exits and stays
    ``<defunct>`` for the lifetime of a long-lived service. ``group_id`` is ``None`` on Windows
    and wherever the launch could not claim a group, where there is nothing to drain.
    """

    if group_id is None:
        return
    _drain_posix_group(process, group_id, deadline_seconds=_COMPLETED_DRAIN_SECONDS)


def _reap_approved_check_process(
    process: subprocess.Popen[bytes],
    *,
    process_group_id: int | None = None,
) -> None:
    """Terminate the isolated check tree, then wait until its members are reaped."""

    if os.name == "nt":
        _reap_windows_process_tree(process)
        return

    group_id = (
        process_group_id if process_group_id is not None else _posix_process_group_id(process)
    )
    if group_id is None:
        if process.poll() is None:
            process.kill()
        _wait_process(process, 5.0)
        return

    _signal_posix_group(group_id, signal.SIGTERM)
    if not _wait_process(process, 0.5) or _posix_group_exists(group_id):
        _signal_posix_group(group_id, signal.SIGKILL)
        _wait_process(process, 5.0)

    _drain_posix_group(process, group_id, deadline_seconds=_REAP_DEADLINE_SECONDS)

    if process.poll() is None:
        process.kill()
        _wait_process(process, 1.0)


class ApprovedCheckRunner:
    """Execute only commitment-approved argv under a consented workspace root."""

    def __init__(
        self,
        approvals: Mapping[str, ApprovedCheckApproval] | None = None,
        *,
        sandbox: CheckSandboxPort | None = None,
        output_sink: Callable[[bytes], None] | None = None,
    ) -> None:
        self._approvals = dict(approvals or {})
        self._sandbox = sandbox if sandbox is not None else default_check_sandbox()
        self._output_sink = output_sink

    def register(self, approval: ApprovedCheckApproval) -> None:
        self._approvals[approval.approval_commitment] = approval

    def run(self, command: ApprovedCheckCommand) -> ApprovedCheckResult:
        if type(command) is not ApprovedCheckCommand:
            raise ProtocolValueError("invalid_approved_check")
        approval = command.approval
        registered = self._approvals.get(approval.approval_commitment)
        if registered is None or registered != approval:
            return self._result(
                ApprovedCheckStatus.REJECTED,
                ApprovedCheckOutcome.NOT_APPROVED,
                None,
                None,
                0,
                command.subject_state_digest,
                approval.approval_commitment,
                0,
            )
        if (
            command.expected_subject_state_digest is not None
            and command.expected_subject_state_digest != command.subject_state_digest
        ):
            return self._result(
                ApprovedCheckStatus.STALE,
                ApprovedCheckOutcome.SUBJECT_STATE_MISMATCH,
                None,
                None,
                0,
                command.subject_state_digest,
                approval.approval_commitment,
                0,
            )
        if approval.allow_network:
            # Network requires an explicit separate authorization; default runner denies.
            return self._result(
                ApprovedCheckStatus.REJECTED,
                ApprovedCheckOutcome.NETWORK_DENIED,
                None,
                None,
                0,
                command.subject_state_digest,
                approval.approval_commitment,
                0,
            )
        root = _root_from_handle(command.workspace)
        if root is None or not root.is_dir():
            return self._result(
                ApprovedCheckStatus.REJECTED,
                ApprovedCheckOutcome.EXEC_FAILED,
                None,
                None,
                0,
                command.subject_state_digest,
                approval.approval_commitment,
                0,
            )
        home, tmpdir, temp_root = _owner_private_temp_dirs()
        started = time.monotonic()
        process: subprocess.Popen[bytes] | None = None
        process_group_id: int | None = None
        try:
            env = _sanitized_env(home=home, tmpdir=tmpdir)
            launch = self._sandbox.prepare(
                argv=approval.argv,
                cwd=root,
                env=env,
                deny_network=True,
            )
            if launch.status is CheckSandboxStatus.UNAVAILABLE or not launch.network_isolated:
                # Never claim network denial from an environment variable alone.
                return self._result(
                    ApprovedCheckStatus.REJECTED,
                    ApprovedCheckOutcome.SANDBOX_UNAVAILABLE,
                    None,
                    None,
                    0,
                    command.subject_state_digest,
                    approval.approval_commitment,
                    int((time.monotonic() - started) * 1000),
                )
            if os.name == "nt":
                process = subprocess.Popen(
                    list(launch.argv),
                    cwd=launch.cwd,
                    env=dict(launch.env),
                    shell=False,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    close_fds=True,
                    # Console-signal isolation, the Windows counterpart of ``start_new_session``:
                    # a Ctrl-C on our console must not race the reaper for this tree. Killing the
                    # tree does not go through the group (see ``_reap_windows_process_tree``).
                    creationflags=int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)),
                )
            else:
                # Adopt orphaned descendants (Linux) so the reaper can actually clear them.
                _enable_child_subreaper()
                process = subprocess.Popen(
                    list(launch.argv),
                    cwd=launch.cwd,
                    env=dict(launch.env),
                    shell=False,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    close_fds=True,
                    start_new_session=True,
                )
                # ``start_new_session`` makes the child's PID the new session and process-group
                # ID.  Capture that identity without a post-launch ``getpgid`` lookup: the group
                # can remain alive after a short-lived leader exits, and losing the leader must
                # not make its descendants unaddressable at timeout.
                process_group_id = process.pid
            stdout, truncated = _bounded_communicate(
                process,
                stdout_limit=_MAX_OUTPUT_BYTES,
                timeout_seconds=approval.timeout_seconds,
            )
            _drain_completed_check_group(process, process_group_id)
            duration_ms = int((time.monotonic() - started) * 1000)
            exit_status = int(process.returncode or 0)
            # Output goes to the encrypted store; heuristic-only matches are redacted at egress.
            safe_output, _redacted = redact_high_confidence_content(bytes(stdout))
            captured_len = len(safe_output)
            output_digest = "sha256:" + hashlib.sha256(safe_output).hexdigest()
            if self._output_sink is not None:
                # Ephemeral handoff to the ready-service encrypted object writer.
                # The sink receives only the redacted bounded buffer.
                self._output_sink(safe_output)
            stdout[:] = b"\x00" * len(stdout)
            del stdout
            if truncated:
                outcome = ApprovedCheckOutcome.OUTPUT_TRUNCATED
                status = ApprovedCheckStatus.FAILED
            elif exit_status == 0:
                outcome = ApprovedCheckOutcome.SUCCESS
                status = ApprovedCheckStatus.PASSED
            else:
                outcome = ApprovedCheckOutcome.NONZERO_EXIT
                status = ApprovedCheckStatus.FAILED
            return self._result(
                status,
                outcome,
                exit_status,
                output_digest,
                captured_len,
                command.subject_state_digest,
                approval.approval_commitment,
                duration_ms,
            )
        except TimeoutError:
            if process is not None:
                _reap_approved_check_process(process, process_group_id=process_group_id)
            return self._result(
                ApprovedCheckStatus.TIMEOUT,
                ApprovedCheckOutcome.TIMEOUT,
                None,
                None,
                0,
                command.subject_state_digest,
                approval.approval_commitment,
                int((time.monotonic() - started) * 1000),
            )
        except OSError:
            return self._result(
                ApprovedCheckStatus.REJECTED,
                ApprovedCheckOutcome.EXEC_FAILED,
                None,
                None,
                0,
                command.subject_state_digest,
                approval.approval_commitment,
                int((time.monotonic() - started) * 1000),
            )
        finally:
            if process is not None:
                if process.stdout is not None:
                    process.stdout.close()
                if process.stderr is not None:
                    process.stderr.close()
            temp_root.cleanup()

    def _result(
        self,
        status: ApprovedCheckStatus,
        outcome: ApprovedCheckOutcome,
        exit_status: int | None,
        output_digest: str | None,
        output_bytes: int,
        subject_state_digest: str,
        approval_commitment_value: str,
        duration_ms: int,
    ) -> ApprovedCheckResult:
        payload: dict[str, JsonValue] = {
            "format": APPROVED_CHECK_FORMAT,
            "status": status.value,
            "outcome": outcome.value,
            "exit_status": exit_status,
            "output_digest": output_digest,
            "output_bytes": output_bytes,
            "subject_state_digest": subject_state_digest,
            "approval_commitment": approval_commitment_value,
            "duration_ms": duration_ms,
        }
        return ApprovedCheckResult(
            status=status,
            outcome=outcome,
            exit_status=exit_status,
            output_digest=output_digest,
            output_bytes=output_bytes,
            subject_state_digest=subject_state_digest,
            approval_commitment=approval_commitment_value,
            result_digest=canonical_digest(payload),
            duration_ms=duration_ms,
        )
