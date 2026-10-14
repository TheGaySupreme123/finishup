"""Unit tests for CheckSandboxPort and approved-check sandbox integration."""

from __future__ import annotations

import platform
import shutil
from collections.abc import Sequence
from pathlib import Path

from finishup.adapters.approved_checks import (
    ApprovedCheckApproval,
    ApprovedCheckCommand,
    ApprovedCheckOutcome,
    ApprovedCheckRunner,
    ApprovedCheckStatus,
    approval_commitment,
)
from finishup.adapters.check_sandbox import (
    LinuxCheckSandbox,
    MacOSCheckSandbox,
    UnsupportedCheckSandbox,
    default_check_sandbox,
    probe_check_sandbox,
)
from finishup.adapters.workspace_inspect import open_inspect_workspace
from finishup.ports.check_sandbox import CheckSandboxStatus

_TRUE = shutil.which("true") or "/usr/bin/true"


def _approval(argv: tuple[str, ...]) -> ApprovedCheckApproval:
    commitment = approval_commitment("pytest-sandbox", argv, allow_network=False)
    return ApprovedCheckApproval(
        approval_id="pytest-sandbox",
        argv=argv,
        allow_network=False,
        timeout_seconds=10.0,
        approval_commitment=commitment,
    )


def test_default_sandbox_is_platform_specific() -> None:
    sandbox = default_check_sandbox()
    if platform.system() == "Darwin":
        assert isinstance(sandbox, MacOSCheckSandbox)
    launch = sandbox.prepare(
        argv=(_TRUE,),
        cwd=Path("/"),
        env={"HOME": "/tmp", "TMPDIR": "/tmp"},
        deny_network=True,
    )
    if platform.system() == "Darwin":
        assert launch.status is CheckSandboxStatus.READY
        assert launch.network_isolated is True
        assert launch.argv[0].endswith("sandbox-exec")


def test_unsupported_sandbox_never_claims_network_isolation() -> None:
    launch = UnsupportedCheckSandbox().prepare(
        argv=(_TRUE,),
        cwd=Path("/"),
        env={"FINISHUP_APPROVED_CHECK_NETWORK": "denied"},
        deny_network=True,
    )
    assert launch.status is CheckSandboxStatus.UNAVAILABLE
    assert launch.network_isolated is False


def test_approved_true_succeeds_inside_enforcing_sandbox(tmp_path: Path) -> None:
    if platform.system() != "Darwin":
        return
    handle = open_inspect_workspace(tmp_path)
    approval = _approval((_TRUE,))
    runner = ApprovedCheckRunner({approval.approval_commitment: approval})
    result = runner.run(
        ApprovedCheckCommand(
            workspace=handle,
            approval=approval,
            subject_state_digest="sha256:" + "a" * 64,
            expected_subject_state_digest="sha256:" + "a" * 64,
        )
    )
    assert result.status is ApprovedCheckStatus.PASSED
    assert result.outcome is ApprovedCheckOutcome.SUCCESS


def test_sandbox_unavailable_rejects_honestly(tmp_path: Path) -> None:
    handle = open_inspect_workspace(tmp_path)
    approval = _approval((_TRUE,))
    runner = ApprovedCheckRunner(
        {approval.approval_commitment: approval},
        sandbox=UnsupportedCheckSandbox(),
    )
    result = runner.run(
        ApprovedCheckCommand(
            workspace=handle,
            approval=approval,
            subject_state_digest="sha256:" + "b" * 64,
        )
    )
    assert result.status is ApprovedCheckStatus.REJECTED
    assert result.outcome is ApprovedCheckOutcome.SANDBOX_UNAVAILABLE


# ---------------------------------------------------------------------------
# Availability is decided once, with the dependency named (issue #720)
# ---------------------------------------------------------------------------


def _fake_bwrap(tmp_path: Path) -> str:
    bwrap = tmp_path / "bwrap"
    bwrap.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
    bwrap.chmod(0o755)
    return str(bwrap)


def test_linux_sandbox_names_a_missing_bubblewrap() -> None:
    sandbox = LinuxCheckSandbox(bwrap="/nonexistent/bwrap", _probe=lambda _argv: 0)

    availability = sandbox.availability()

    assert availability.status is CheckSandboxStatus.UNAVAILABLE
    assert availability.mechanism == "bubblewrap"
    assert availability.reason == "bwrap_missing"
    assert "apt install bubblewrap" in availability.remediation
    launch = sandbox.prepare(argv=(_TRUE,), cwd=Path("/"), env={}, deny_network=True)
    assert launch.status is CheckSandboxStatus.UNAVAILABLE
    assert launch.network_isolated is False


def test_linux_sandbox_probes_usability_not_presence(tmp_path: Path) -> None:
    """A bwrap that AppArmor blocks passes ``which`` and must still read as unavailable."""

    calls: list[tuple[str, ...]] = []

    def blocked(argv: Sequence[str]) -> int:
        calls.append(tuple(argv))
        return 1

    sandbox = LinuxCheckSandbox(bwrap=_fake_bwrap(tmp_path), _probe=blocked, _true=_TRUE)

    first = sandbox.availability()
    second = sandbox.availability()
    launch = sandbox.prepare(argv=(_TRUE,), cwd=tmp_path, env={}, deny_network=True)

    assert first.reason == "bwrap_unusable"
    assert first.status is CheckSandboxStatus.UNAVAILABLE
    assert "AppArmor" in first.remediation
    assert second is first
    assert len(calls) == 1, "one bounded probe per adapter, never per check"
    assert calls[0][1:] == (
        "--die-with-parent",
        "--unshare-net",
        "--bind",
        "/",
        "/",
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        "--",
        _TRUE,
    )
    assert launch.status is CheckSandboxStatus.UNAVAILABLE
    assert launch.argv == (_TRUE,)


def test_linux_sandbox_wraps_with_the_probed_launch_shape(tmp_path: Path) -> None:
    bwrap = _fake_bwrap(tmp_path)
    sandbox = LinuxCheckSandbox(bwrap=bwrap, _probe=lambda _argv: 0, _true=_TRUE)

    availability = sandbox.availability()
    launch = sandbox.prepare(
        argv=("pytest", "-q"), cwd=tmp_path, env={"HOME": str(tmp_path)}, deny_network=True
    )
    plain = sandbox.prepare(argv=("pytest",), cwd=tmp_path, env={}, deny_network=False)

    assert availability.status is CheckSandboxStatus.READY
    assert availability.reason == "ready"
    assert availability.remediation == ""
    assert launch.status is CheckSandboxStatus.READY
    assert launch.network_isolated is True
    # Whole-filesystem bind mirrors the macOS "allow default, deny network" profile; a
    # working-tree-only bind would leave the check without an interpreter to execute.
    assert launch.argv == (
        bwrap,
        "--die-with-parent",
        "--unshare-net",
        "--bind",
        "/",
        "/",
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        "--chdir",
        str(tmp_path),
        "--",
        "pytest",
        "-q",
    )
    assert launch.env == {"HOME": str(tmp_path)}
    assert plain.argv == ("pytest",)
    assert plain.network_isolated is False


def test_macos_sandbox_names_a_missing_sandbox_exec() -> None:
    availability = MacOSCheckSandbox(sandbox_exec="/nonexistent/sandbox-exec").availability()

    assert availability.status is CheckSandboxStatus.UNAVAILABLE
    assert availability.mechanism == "seatbelt"
    assert availability.reason == "sandbox_exec_missing"


def test_unsupported_sandbox_names_the_platform() -> None:
    availability = UnsupportedCheckSandbox().availability()

    assert availability.as_json() == {
        "mechanism": "none",
        "reason": "platform_unsupported",
        "remediation": availability.remediation,
        "status": "unavailable",
    }
    assert "macOS" in availability.remediation and "Linux" in availability.remediation


def test_default_availability_agrees_with_the_per_run_decision(tmp_path: Path) -> None:
    sandbox = default_check_sandbox()
    availability = probe_check_sandbox()
    launch = sandbox.prepare(argv=(_TRUE,), cwd=tmp_path, env={}, deny_network=True)

    assert availability.status is launch.status
    if platform.system() == "Darwin":
        assert availability.mechanism == "seatbelt"
        assert availability.status is CheckSandboxStatus.READY
