"""Platform CheckSandboxPort adapters (macOS seatbelt, Linux bwrap when present)."""

from __future__ import annotations

import platform
import shutil
import subprocess
import tempfile
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Final

from finishup.ports.check_sandbox import (
    CheckSandboxAvailability,
    CheckSandboxLaunch,
    CheckSandboxStatus,
)

__all__ = [
    "LinuxCheckSandbox",
    "MacOSCheckSandbox",
    "UnsupportedCheckSandbox",
    "default_check_sandbox",
    "probe_check_sandbox",
]

_SEATBELT_NO_NETWORK = """\
(version 1)
(allow default)
(deny network*)
"""

# Bounded, fixed remediation text: it names the dependency and the known host restriction, never
# a path or any output from the probe (issue #720).
_BWRAP_MISSING_REMEDIATION: Final = (
    "install bubblewrap (Debian, Ubuntu, and WSL 2: 'sudo apt install bubblewrap'; Fedora: "
    "'sudo dnf install bubblewrap'), then rerun this command"
)
_BWRAP_UNUSABLE_REMEDIATION: Final = (
    "bwrap is installed but could not create an unprivileged no-network namespace on this host; "
    "Ubuntu 24.04 and later restrict unprivileged user namespaces through AppArmor, so use the "
    "distribution bubblewrap package (it ships the AppArmor profile that permits bwrap) or relax "
    "the restriction with 'sudo sysctl kernel.apparmor_restrict_unprivileged_userns=0', then "
    "rerun this command"
)
_SANDBOX_EXEC_MISSING_REMEDIATION: Final = (
    "sandbox-exec ships with macOS; restore /usr/bin/sandbox-exec from the operating system, "
    "then rerun this command"
)
_PLATFORM_UNSUPPORTED_REMEDIATION: Final = (
    "network-denied approved checks run only on macOS (sandbox-exec) and Linux (bubblewrap); "
    "checks that do not require network denial are unaffected"
)
_PROBE_TIMEOUT_SECONDS: Final = 10.0


def _run_probe(argv: Sequence[str]) -> int:
    """Run one bounded, output-free probe and return its exit code (-1 when it cannot run)."""

    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv built from an absolute bwrap path
            list(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            shell=False,
            timeout=_PROBE_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        return -1
    return completed.returncode


def _passthrough(
    argv: Sequence[str], cwd: Path, env: Mapping[str, str], *, status: CheckSandboxStatus
) -> CheckSandboxLaunch:
    return CheckSandboxLaunch(
        argv=tuple(argv),
        env=dict(env),
        cwd=cwd,
        status=status,
        network_isolated=False,
    )


class UnsupportedCheckSandbox:
    """Honest unavailable sandbox — never claims network denial from env alone."""

    def availability(self) -> CheckSandboxAvailability:
        return CheckSandboxAvailability(
            status=CheckSandboxStatus.UNAVAILABLE,
            mechanism="none",
            reason="platform_unsupported",
            remediation=_PLATFORM_UNSUPPORTED_REMEDIATION,
        )

    def prepare(
        self,
        *,
        argv: Sequence[str],
        cwd: Path,
        env: Mapping[str, str],
        deny_network: bool,
    ) -> CheckSandboxLaunch:
        _ = deny_network
        return _passthrough(argv, cwd, env, status=CheckSandboxStatus.UNAVAILABLE)


class MacOSCheckSandbox:
    """Enforcing no-network Seatbelt profile via sandbox-exec when available."""

    def __init__(self, *, sandbox_exec: str | None = None) -> None:
        self._sandbox_exec = sandbox_exec or shutil.which("sandbox-exec")

    def availability(self) -> CheckSandboxAvailability:
        if self._sandbox_exec is None or not Path(self._sandbox_exec).is_file():
            return CheckSandboxAvailability(
                status=CheckSandboxStatus.UNAVAILABLE,
                mechanism="seatbelt",
                reason="sandbox_exec_missing",
                remediation=_SANDBOX_EXEC_MISSING_REMEDIATION,
            )
        return CheckSandboxAvailability(
            status=CheckSandboxStatus.READY,
            mechanism="seatbelt",
            reason="ready",
            remediation="",
        )

    def prepare(
        self,
        *,
        argv: Sequence[str],
        cwd: Path,
        env: Mapping[str, str],
        deny_network: bool,
    ) -> CheckSandboxLaunch:
        if not deny_network:
            return _passthrough(argv, cwd, env, status=CheckSandboxStatus.READY)
        if self._sandbox_exec is None or not Path(self._sandbox_exec).is_file():
            return _passthrough(argv, cwd, env, status=CheckSandboxStatus.UNAVAILABLE)
        home = env.get("HOME", "/tmp")
        tmpdir = env.get("TMPDIR", "/tmp")
        _ = home, tmpdir
        profile = _SEATBELT_NO_NETWORK
        profile_dir = Path(tempfile.mkdtemp(prefix="finishup-sb-"))
        profile_path = profile_dir / "no-network.sb"
        profile_path.write_text(profile, encoding="ascii")
        wrapped = (self._sandbox_exec, "-f", str(profile_path), *argv)
        return CheckSandboxLaunch(
            argv=wrapped,
            env=dict(env),
            cwd=cwd,
            status=CheckSandboxStatus.READY,
            network_isolated=True,
        )


class LinuxCheckSandbox:
    """Enforcing no-network sandbox via bubblewrap when present *and usable*.

    Presence is not usability: a ``bwrap`` that AppArmor forbids from creating an unprivileged
    user namespace passes ``shutil.which`` and then fails ``--unshare-net`` at run time. One
    bounded probe with the real launch shape decides once per adapter, so an unusable host is
    reported as unavailable before a check starts instead of as a failed check (issue #720).

    The launch mirrors the macOS profile — allow the filesystem, deny the network — by binding
    the host root read-write with fresh ``/dev`` and ``/proc`` and unsharing only the network
    namespace. Binding just the working tree would leave the check without an interpreter.
    """

    def __init__(
        self,
        *,
        bwrap: str | None = None,
        _probe: Callable[[Sequence[str]], int] | None = None,
        _true: str | None = None,
    ) -> None:
        self._bwrap = bwrap or shutil.which("bwrap")
        self._probe = _run_probe if _probe is None else _probe
        self._true = _true or shutil.which("true") or "/bin/true"
        self._availability: CheckSandboxAvailability | None = None

    def _wrapper_prefix(self) -> tuple[str, ...]:
        assert self._bwrap is not None
        return (
            self._bwrap,
            "--die-with-parent",
            "--unshare-net",
            "--bind",
            "/",
            "/",
            "--dev",
            "/dev",
            "--proc",
            "/proc",
        )

    def availability(self) -> CheckSandboxAvailability:
        if self._availability is not None:
            return self._availability
        if self._bwrap is None or not Path(self._bwrap).is_file():
            result = CheckSandboxAvailability(
                status=CheckSandboxStatus.UNAVAILABLE,
                mechanism="bubblewrap",
                reason="bwrap_missing",
                remediation=_BWRAP_MISSING_REMEDIATION,
            )
        elif self._probe((*self._wrapper_prefix(), "--", self._true)) != 0:
            result = CheckSandboxAvailability(
                status=CheckSandboxStatus.UNAVAILABLE,
                mechanism="bubblewrap",
                reason="bwrap_unusable",
                remediation=_BWRAP_UNUSABLE_REMEDIATION,
            )
        else:
            result = CheckSandboxAvailability(
                status=CheckSandboxStatus.READY,
                mechanism="bubblewrap",
                reason="ready",
                remediation="",
            )
        self._availability = result
        return result

    def prepare(
        self,
        *,
        argv: Sequence[str],
        cwd: Path,
        env: Mapping[str, str],
        deny_network: bool,
    ) -> CheckSandboxLaunch:
        if not deny_network:
            return _passthrough(argv, cwd, env, status=CheckSandboxStatus.READY)
        if self.availability().status is not CheckSandboxStatus.READY:
            return _passthrough(argv, cwd, env, status=CheckSandboxStatus.UNAVAILABLE)
        wrapped = (*self._wrapper_prefix(), "--chdir", str(cwd), "--", *argv)
        return CheckSandboxLaunch(
            argv=wrapped,
            env=dict(env),
            cwd=cwd,
            status=CheckSandboxStatus.READY,
            network_isolated=True,
        )


def default_check_sandbox() -> MacOSCheckSandbox | LinuxCheckSandbox | UnsupportedCheckSandbox:
    system = platform.system()
    if system == "Darwin":
        return MacOSCheckSandbox()
    if system == "Linux":
        return LinuxCheckSandbox()
    return UnsupportedCheckSandbox()


def probe_check_sandbox() -> CheckSandboxAvailability:
    """Report once whether this host can run a network-denied approved check, and why not."""

    return default_check_sandbox().availability()
