"""Unit tests for commitment-bound approved check runner."""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast

import pytest

from finishup.adapters import approved_checks
from finishup.adapters.approved_checks import (
    ApprovedCheckApproval,
    ApprovedCheckCommand,
    ApprovedCheckOutcome,
    ApprovedCheckRunner,
    ApprovedCheckStatus,
    _reap_approved_check_process,  # pyright: ignore[reportPrivateUsage]
    _reap_posix_group_members,  # pyright: ignore[reportPrivateUsage]
    _taskkill_tree,  # pyright: ignore[reportPrivateUsage]
    approval_commitment,
)
from finishup.adapters.workspace_inspect import open_inspect_workspace
from finishup.ports.check_sandbox import CheckSandboxLaunch, CheckSandboxStatus

_TRUE = shutil.which("true") or "/usr/bin/true"


class _ReadyCheckSandbox:
    """Deterministic unit seam; platform-enforcement behavior has dedicated adapter tests."""

    def prepare(
        self,
        *,
        argv: Sequence[str],
        cwd: Path,
        env: Mapping[str, str],
        deny_network: bool,
    ) -> CheckSandboxLaunch:
        return CheckSandboxLaunch(
            argv=tuple(argv),
            env=dict(env),
            cwd=cwd,
            status=CheckSandboxStatus.READY,
            network_isolated=deny_network,
        )


def _approval(argv: tuple[str, ...], *, timeout_seconds: float = 10.0) -> ApprovedCheckApproval:
    commitment = approval_commitment("pytest-unit", argv, allow_network=False)
    return ApprovedCheckApproval(
        approval_id="pytest-unit",
        argv=argv,
        allow_network=False,
        timeout_seconds=timeout_seconds,
        approval_commitment=commitment,
    )


def test_approved_check_binds_to_subject_state_digest(tmp_path: Path) -> None:
    handle = open_inspect_workspace(tmp_path)
    argv = (_TRUE,)
    approval = _approval(argv)
    runner = ApprovedCheckRunner(
        {approval.approval_commitment: approval},
        sandbox=_ReadyCheckSandbox(),
    )
    digest_a = "sha256:" + "a" * 64
    digest_b = "sha256:" + "b" * 64
    ok = runner.run(
        ApprovedCheckCommand(
            workspace=handle,
            approval=approval,
            subject_state_digest=digest_a,
            expected_subject_state_digest=digest_a,
        )
    )
    assert ok.status is ApprovedCheckStatus.PASSED
    assert ok.subject_state_digest == digest_a
    stale = runner.run(
        ApprovedCheckCommand(
            workspace=handle,
            approval=approval,
            subject_state_digest=digest_b,
            expected_subject_state_digest=digest_a,
        )
    )
    assert stale.status is ApprovedCheckStatus.STALE
    assert stale.outcome is ApprovedCheckOutcome.SUBJECT_STATE_MISMATCH


def test_unapproved_argv_rejected(tmp_path: Path) -> None:
    handle = open_inspect_workspace(tmp_path)
    approval = _approval((_TRUE,))
    runner = ApprovedCheckRunner()  # nothing registered
    result = runner.run(
        ApprovedCheckCommand(
            workspace=handle,
            approval=approval,
            subject_state_digest="sha256:" + "c" * 64,
        )
    )
    assert result.status is ApprovedCheckStatus.REJECTED
    assert result.outcome is ApprovedCheckOutcome.NOT_APPROVED


def test_output_never_retained_as_secret_text(tmp_path: Path) -> None:
    handle = open_inspect_workspace(tmp_path)
    argv = ("/bin/echo", "SECRET=should-not-leak")
    # echo may not allow '=' in our argv validator — use a safer token.
    argv = ("/bin/echo", "secret-token-value")
    approval = _approval(argv)
    runner = ApprovedCheckRunner(
        {approval.approval_commitment: approval},
        sandbox=_ReadyCheckSandbox(),
    )
    result = runner.run(
        ApprovedCheckCommand(
            workspace=handle,
            approval=approval,
            subject_state_digest="sha256:" + "d" * 64,
        )
    )
    assert result.output_digest is not None
    assert "secret-token-value" not in repr(result)
    assert "SECRET" not in repr(result)


def test_nonforking_timeout_is_deterministic(tmp_path: Path) -> None:
    handle = open_inspect_workspace(tmp_path)
    sleep = shutil.which("sleep") or "/bin/sleep"
    approval = _approval((sleep, "8"), timeout_seconds=0.3)
    runner = ApprovedCheckRunner(
        {approval.approval_commitment: approval},
        sandbox=_ReadyCheckSandbox(),
    )
    started = time.monotonic()
    result = runner.run(
        ApprovedCheckCommand(
            workspace=handle,
            approval=approval,
            subject_state_digest="sha256:" + "e" * 64,
        )
    )
    elapsed = time.monotonic() - started
    assert result.status is ApprovedCheckStatus.TIMEOUT
    assert result.outcome is ApprovedCheckOutcome.TIMEOUT
    assert result.exit_status is None
    assert result.output_digest is None
    assert result.output_bytes == 0
    assert elapsed < 4.0


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX process-group reaping")
def test_timeout_reaps_forked_descendant_before_result(tmp_path: Path) -> None:
    handle = open_inspect_workspace(tmp_path)
    pid_path = tmp_path / "desc.pid"
    stop_path = tmp_path / "stop.flag"
    leak_path = tmp_path / "leaked.txt"
    script_path = tmp_path / "fork-check.sh"
    script_path.write_text(
        "#!/bin/sh\n"
        "pid_file=$1\n"
        "stop_file=$2\n"
        "leak_file=$3\n"
        "(\n"
        "  trap '' TERM\n"
        '  while [ ! -f "$stop_file" ]; do\n'
        "    sleep 0.05\n"
        "  done\n"
        '  echo leaked > "$leak_file"\n'
        ") &\n"
        'echo $! > "$pid_file"\n'
        # Exit the direct child while its descendant keeps the inherited output pipes open. This
        # proves the runner retains the launch-time group identity instead of relying on a later
        # lookup through a leader that may already be gone.
        "exit 0\n",
        encoding="ascii",
    )
    os.chmod(script_path, 0o700)
    approval = _approval(
        ("/bin/sh", str(script_path), str(pid_path), str(stop_path), str(leak_path)),
        timeout_seconds=0.5,
    )
    runner = ApprovedCheckRunner(
        {approval.approval_commitment: approval},
        sandbox=_ReadyCheckSandbox(),
    )
    result = runner.run(
        ApprovedCheckCommand(
            workspace=handle,
            approval=approval,
            subject_state_digest="sha256:" + "f" * 64,
        )
    )
    assert result.status is ApprovedCheckStatus.TIMEOUT
    assert result.outcome is ApprovedCheckOutcome.TIMEOUT
    assert pid_path.is_file()
    descendant_pid = int(pid_path.read_text(encoding="ascii").strip())
    with pytest.raises(ProcessLookupError):
        os.kill(descendant_pid, 0)
    stop_path.write_text("stop", encoding="ascii")
    time.sleep(0.3)
    assert not leak_path.exists()


class _FakeLeader:
    """Stand-in for the leader ``Popen`` in reaper unit tests."""

    def __init__(self, *, pid: int = 424_242, running: bool = False) -> None:
        self.pid = pid
        self.running = running
        self.kill_calls = 0
        self.events: list[str] = []

    def poll(self) -> int | None:
        return None if self.running else 0

    def kill(self) -> None:
        self.kill_calls += 1
        self.events.append("kill")
        self.running = False

    def wait(self, timeout: float | None = None) -> int:
        self.events.append(f"wait:{timeout}")
        if self.running:
            raise subprocess.TimeoutExpired(cmd="fake-check", timeout=timeout or 0.0)
        return 0


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX process-group reaping")
def test_closed_output_pipes_still_time_out_and_reap_group(tmp_path: Path) -> None:
    handle = open_inspect_workspace(tmp_path)
    leader_path = tmp_path / "leader.pid"
    child_path = tmp_path / "child.pid"
    script_path = tmp_path / "closed-fds-check.sh"
    script_path.write_text(
        "#!/bin/sh\n"
        'echo $$ > "$1"\n'
        # Closing both output pipes hands the runner EOF while the tree keeps running, so the
        # selector loop finishes early and only the final wait can observe the overrun. That
        # wait must not escape as ``subprocess.TimeoutExpired``: it would skip both the timeout
        # result and the group reaping, leaking the whole tree.
        "exec 1>&- 2>&-\n"
        "sleep 30 &\n"
        'echo $! > "$2"\n'
        "wait\n",
        encoding="ascii",
    )
    os.chmod(script_path, 0o700)
    approval = _approval(
        ("/bin/sh", str(script_path), str(leader_path), str(child_path)),
        timeout_seconds=0.5,
    )
    runner = ApprovedCheckRunner(
        {approval.approval_commitment: approval},
        sandbox=_ReadyCheckSandbox(),
    )
    started = time.monotonic()
    result = runner.run(
        ApprovedCheckCommand(
            workspace=handle,
            approval=approval,
            subject_state_digest="sha256:" + "1" * 64,
        )
    )
    elapsed = time.monotonic() - started
    assert result.status is ApprovedCheckStatus.TIMEOUT
    assert result.outcome is ApprovedCheckOutcome.TIMEOUT
    assert result.exit_status is None
    assert elapsed < 4.0
    group_id = int(leader_path.read_text(encoding="ascii").strip())
    descendant_pid = int(child_path.read_text(encoding="ascii").strip())
    with pytest.raises(ProcessLookupError):
        os.kill(descendant_pid, 0)
    with pytest.raises(ProcessLookupError):
        os.killpg(group_id, 0)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX process-group reaping")
def test_group_reaper_drains_exited_members() -> None:
    sleep = shutil.which("sleep") or "/bin/sleep"
    process = subprocess.Popen(
        [sleep, "30"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    group_id = process.pid
    try:
        os.killpg(group_id, signal.SIGKILL)
        reaped = 0
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and reaped == 0:
            reaped, _waitable = _reap_posix_group_members(group_id)
            if reaped == 0:
                time.sleep(0.01)
        assert reaped == 1
        # Drained: no member of the group is waitable by us any more.
        assert _reap_posix_group_members(group_id) == (0, False)
    finally:
        process.wait(timeout=5.0)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX process-group reaping")
def test_reaper_waits_on_the_group_and_returns_when_it_is_gone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    leader = _FakeLeader()
    alive = [True]
    waitpid_calls: list[tuple[int, int]] = []

    def _fake_signal(group_id: int, sig: int) -> bool:
        assert group_id == 7_777
        return alive[0]

    def _fake_waitpid(pid: int, options: int) -> tuple[int, int]:
        waitpid_calls.append((pid, options))
        if len(waitpid_calls) == 1:
            return (8_888, 0)
        alive[0] = False
        raise ChildProcessError

    monkeypatch.setattr(approved_checks, "_signal_posix_group", _fake_signal)
    monkeypatch.setattr(approved_checks.os, "waitpid", _fake_waitpid)
    started = time.monotonic()
    _reap_approved_check_process(cast("subprocess.Popen[bytes]", leader), process_group_id=7_777)
    elapsed = time.monotonic() - started
    assert waitpid_calls[0] == (-7_777, os.WNOHANG)
    assert elapsed < 1.0


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX process-group reaping")
def test_reaper_stops_early_when_group_members_are_unreapable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    leader = _FakeLeader()
    signals: list[int] = []

    def _fake_signal(group_id: int, sig: int) -> bool:
        assert group_id == 9_999
        signals.append(sig)
        # A non-reaping PID 1 keeps the killed members ``<defunct>``: the group never goes away.
        return True

    def _fake_waitpid(pid: int, options: int) -> tuple[int, int]:
        raise ChildProcessError

    monkeypatch.setattr(approved_checks, "_signal_posix_group", _fake_signal)
    monkeypatch.setattr(approved_checks.os, "waitpid", _fake_waitpid)
    started = time.monotonic()
    _reap_approved_check_process(cast("subprocess.Popen[bytes]", leader), process_group_id=9_999)
    elapsed = time.monotonic() - started
    assert signal.SIGKILL in signals
    # Bounded no-progress exit, not the full reap deadline burned on every timed-out check.
    assert elapsed < 2.0


def test_windows_reaper_kills_the_process_tree(monkeypatch: pytest.MonkeyPatch) -> None:
    leader = _FakeLeader(pid=4_321, running=True)
    killed: list[int] = []

    def _fake_taskkill(pid: int) -> bool:
        killed.append(pid)
        leader.running = False
        return True

    monkeypatch.setattr(approved_checks.os, "name", "nt")
    monkeypatch.setattr(approved_checks, "_taskkill_tree", _fake_taskkill)
    _reap_approved_check_process(cast("subprocess.Popen[bytes]", leader))
    # ``TerminateProcess`` on the direct child alone would spare its grandchildren.
    assert killed == [4_321]
    assert leader.kill_calls == 0


def test_windows_reaper_falls_back_to_kill_on_taskkill_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    leader = _FakeLeader(pid=4_321, running=True)
    commands: list[list[str]] = []

    def _fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        commands.append(argv)
        # taskkill reports access denied rather than raising; the tree is still standing.
        return subprocess.CompletedProcess(argv, 1, b"", b"ERROR: Access is denied.")

    monkeypatch.setattr(approved_checks.os, "name", "nt")
    monkeypatch.setattr(approved_checks.subprocess, "run", _fake_run)
    _reap_approved_check_process(cast("subprocess.Popen[bytes]", leader))
    assert commands == [["taskkill", "/PID", "4321", "/T", "/F"]]
    # The nonzero code must fall back immediately: kill before any wait, not five seconds later.
    assert leader.events[0] == "kill"
    assert leader.kill_calls == 1


def test_taskkill_tree_reports_the_exit_code(monkeypatch: pytest.MonkeyPatch) -> None:
    codes = [0, 1]

    def _fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(argv, codes.pop(0), b"", b"")

    monkeypatch.setattr(approved_checks.subprocess, "run", _fake_run)
    assert _taskkill_tree(4_321) is True
    assert _taskkill_tree(4_321) is False


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX process-group reaping")
def test_completed_check_tears_down_leftover_group_members(tmp_path: Path) -> None:
    handle = open_inspect_workspace(tmp_path)
    leader_path = tmp_path / "leader.pid"
    child_path = tmp_path / "child.pid"
    script_path = tmp_path / "orphan-check.sh"
    script_path.write_text(
        "#!/bin/sh\n"
        'echo $$ > "$1"\n'
        # The background member drops the inherited pipes so the check can return normally,
        # then outlives its parent. Without an unconditional teardown it survives the PASSED
        # result -- and where this process is a child subreaper it later reparents here and
        # becomes an unreapable zombie for the lifetime of a long-lived service.
        "sleep 30 >/dev/null 2>&1 &\n"
        'echo $! > "$2"\n'
        "exit 0\n",
        encoding="ascii",
    )
    os.chmod(script_path, 0o700)
    approval = _approval(
        ("/bin/sh", str(script_path), str(leader_path), str(child_path)),
        timeout_seconds=5.0,
    )
    runner = ApprovedCheckRunner(
        {approval.approval_commitment: approval},
        sandbox=_ReadyCheckSandbox(),
    )
    started = time.monotonic()
    result = runner.run(
        ApprovedCheckCommand(
            workspace=handle,
            approval=approval,
            subject_state_digest="sha256:" + "2" * 64,
        )
    )
    elapsed = time.monotonic() - started
    # The outcome contract is unchanged: the check itself succeeded.
    assert result.status is ApprovedCheckStatus.PASSED
    assert result.outcome is ApprovedCheckOutcome.SUCCESS
    assert result.exit_status == 0
    assert elapsed < 4.0
    group_id = int(leader_path.read_text(encoding="ascii").strip())
    descendant_pid = int(child_path.read_text(encoding="ascii").strip())
    with pytest.raises(ProcessLookupError):
        os.kill(descendant_pid, 0)
    with pytest.raises(ProcessLookupError):
        os.killpg(group_id, 0)
