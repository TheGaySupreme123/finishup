"""OpenSSH for an ``ssh`` server target: the connector's one warm master and its fixed commands.

The connector (ADR-051, approach A) keeps one OpenSSH master per SSH target. The master forwards a
stream-local socket, ``<target root>/run/upstream.sock``, to the server's own control endpoint;
every local client connection becomes one channel of that master. sshd connects to the server's
endpoint as the owner, so the server's peer-UID check passes unchanged, and FinishUP stores no SSH
key and never asks for a password: keys, the agent and ``known_hosts`` stay with OpenSSH.

Every argv here is fixed and secret-free (design section 6). The remote commands are the server's
own ``finishup`` launcher (an absolute path recorded with the target) with fixed arguments; each
remote word is shell-quoted because sshd hands the command line to the remote login shell.

Failures are closed reasons: ``remote_unreachable``, ``remote_auth_failed`` and
``remote_identity_changed``. OpenSSH's own diagnostic text is matched against fixed phrases only to
choose between them; it is never stored, logged or shown.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import shlex
import shutil
import time
from collections import deque
from pathlib import Path
from typing import Final

from finishup.client.targets import ServerTarget

__all__ = [
    "MASTER_NAME",
    "UPSTREAM_NAME",
    "SshMaster",
    "UpstreamUnavailable",
    "classify_ssh_failure",
    "control_argv",
    "destination",
    "master_argv",
    "probe_argv",
    "remote_argv",
    "remote_command",
    "remote_command_line",
    "resolve_ssh",
    "ssh_root_fits",
]

MASTER_NAME: Final = "m"
UPSTREAM_NAME: Final = "upstream.sock"
# OpenSSH binds a ControlPath at ``<path>.<16 random characters>`` and renames it into place.
_OPENSSH_TEMPORARY_SUFFIX: Final = 17
# ``sun_path`` holds 104 bytes on macOS and 108 on Linux, each with a terminating NUL.
_MAX_SOCKET_PATH_BYTES: Final = 103
_MASTER_START_SECONDS: Final = 20.0
_REMOTE_COMMAND_SECONDS: Final = 30.0
_POLL_SECONDS: Final = 0.05
_STDERR_TAIL_BYTES: Final = 4_096
_UNREACHABLE: Final = "remote_unreachable"
# Fixed OpenSSH phrases, matched only to choose a closed reason.
_IDENTITY_PHRASES: Final = (
    b"Host key verification failed",
    b"REMOTE HOST IDENTIFICATION HAS CHANGED",
    b"No ED25519 host key is known",
    b"No RSA host key is known",
    b"No ECDSA host key is known",
)
_AUTH_PHRASES: Final = (b"Permission denied", b"Too many authentication failures")


class UpstreamUnavailable(Exception):
    """The server could not be reached; ``reason`` is one closed remote connection phase."""

    def __init__(self, reason: str) -> None:
        if reason not in {
            "remote_auth_failed",
            "remote_identity_changed",
            "remote_incompatible",
            "remote_service_not_running",
            "remote_unreachable",
        }:
            raise ValueError("upstream_reason_invalid")
        self.reason = reason
        super().__init__(reason)


def resolve_ssh() -> str:
    """The absolute ``ssh`` on ``PATH``; ``remote_unreachable`` when there is none."""

    found = shutil.which("ssh")
    if found is None or not os.path.isabs(found):
        raise UpstreamUnavailable(_UNREACHABLE)
    return found


def destination(record: ServerTarget) -> str:
    """``[user@]host`` for OpenSSH (``host`` and ``user`` were validated when recorded)."""

    if record.kind != "ssh" or record.host is None:
        raise ValueError("target_not_ssh")
    return record.host if record.user is None else f"{record.user}@{record.host}"


def _port(record: ServerTarget) -> str:
    if record.port is None:
        raise ValueError("target_not_ssh")
    return str(record.port)


def ssh_root_fits(root: Path) -> bool:
    """Whether the master's temporary bind path and the upstream socket fit ``sun_path``."""

    master = len(os.fsencode(root / "run" / MASTER_NAME)) + _OPENSSH_TEMPORARY_SUFFIX
    upstream = len(os.fsencode(root / "run" / UPSTREAM_NAME))
    return max(master, upstream) <= _MAX_SOCKET_PATH_BYTES


def _forward_path(text: str) -> str:
    # ``-L local:remote`` splits on ':'; a path that holds one, or whitespace, cannot be forwarded.
    if not text.startswith("/") or ":" in text or any(ord(c) <= 0x20 for c in text):
        raise UpstreamUnavailable(_UNREACHABLE)
    return text


def master_argv(ssh: str, root: Path, record: ServerTarget) -> tuple[str, ...]:
    """The master's exact argv (design section 6): one warm connection, one forward."""

    if record.remote_endpoint is None:
        raise UpstreamUnavailable(_UNREACHABLE)
    local = _forward_path(str(root / "run" / UPSTREAM_NAME))
    remote = _forward_path(record.remote_endpoint)
    return (
        ssh,
        "-M",
        "-S",
        str(root / "run" / MASTER_NAME),
        "-N",
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "ExitOnForwardFailure=yes",
        "-o",
        "StreamLocalBindMask=0177",
        "-o",
        "StreamLocalBindUnlink=yes",
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "ServerAliveCountMax=3",
        "-p",
        _port(record),
        "-L",
        f"{local}:{remote}",
        destination(record),
    )


def control_argv(ssh: str, root: Path, record: ServerTarget, operation: str) -> tuple[str, ...]:
    """``ssh -S <master> -O check|exit`` for this target's master (never by pattern)."""

    if operation not in {"check", "exit"}:
        raise ValueError("ssh_control_operation_invalid")
    return (
        ssh,
        "-S",
        str(root / "run" / MASTER_NAME),
        "-O",
        operation,
        "-p",
        _port(record),
        destination(record),
    )


def remote_command_line(launcher: str, remote_root: str | None, *arguments: str) -> str:
    """One quoted remote command line, pinned to ``remote_root`` when the target names one."""

    words = [launcher, *arguments]
    if remote_root is not None:
        words = ["env", f"FINISHUP_ISOLATED_ROOT={remote_root}", *words]
    return shlex.join(words)


def remote_command(record: ServerTarget, *arguments: str) -> str:
    """The quoted remote command line: the recorded launcher, pinned to the remote root."""

    launcher = record.remote_launcher
    if launcher is None or not launcher.startswith("/"):
        raise UpstreamUnavailable(_UNREACHABLE)
    return remote_command_line(launcher, record.remote_root, *arguments)


def remote_argv(ssh: str, root: Path, record: ServerTarget, *arguments: str) -> tuple[str, ...]:
    """A fixed remote command sent over this target's master, without a terminal."""

    return (
        ssh,
        "-S",
        str(root / "run" / MASTER_NAME),
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-T",
        "-p",
        _port(record),
        destination(record),
        remote_command(record, *arguments),
    )


def probe_argv(
    ssh: str,
    *,
    user: str | None,
    host: str,
    port: int,
    command: str,
) -> tuple[str, ...]:
    """The one interactive probe of ``server add``: OpenSSH itself asks to confirm a new host key.

    No master, no forward; the owner answers OpenSSH's own prompt on the trusted terminal.
    """

    target = host if user is None else f"{user}@{host}"
    return (
        ssh,
        "-o",
        "StrictHostKeyChecking=ask",
        "-o",
        "ControlMaster=no",
        "-T",
        "-p",
        str(port),
        target,
        command,
    )


def classify_ssh_failure(stderr_tail: bytes) -> str:
    """A closed reason for a failed OpenSSH run, chosen by fixed phrases only."""

    if any(phrase in stderr_tail for phrase in _IDENTITY_PHRASES):
        return "remote_identity_changed"
    if any(phrase in stderr_tail for phrase in _AUTH_PHRASES):
        return "remote_auth_failed"
    return _UNREACHABLE


class SshMaster:
    """The connector's OpenSSH master for one target, and the fixed commands it carries."""

    def __init__(self, root: Path, record: ServerTarget, *, ssh: str | None = None) -> None:
        if record.kind != "ssh":
            raise ValueError("target_not_ssh")
        self._root = root
        self._record = record
        self._ssh = ssh
        self._process: asyncio.subprocess.Process | None = None
        self._stderr: deque[bytes] = deque()
        self._stderr_task: asyncio.Task[None] | None = None
        self._lock = asyncio.Lock()

    @property
    def upstream_path(self) -> Path:
        return self._root / "run" / UPSTREAM_NAME

    def _executable(self) -> str:
        if self._ssh is None:
            self._ssh = resolve_ssh()
        return self._ssh

    def _alive(self) -> bool:
        return self._process is not None and self._process.returncode is None

    async def _drain_stderr(self, process: asyncio.subprocess.Process) -> None:
        stream = process.stderr
        if stream is None:
            return
        held = 0
        while chunk := await stream.read(1_024):
            self._stderr.append(chunk)
            held += len(chunk)
            while held > _STDERR_TAIL_BYTES and len(self._stderr) > 1:
                held -= len(self._stderr.popleft())

    async def ensure(self) -> None:
        """Start the master unless it runs; raise ``UpstreamUnavailable`` when it cannot."""

        async with self._lock:
            if self._alive() and self.upstream_path.exists():
                return
            await self._stop_process()
            if not ssh_root_fits(self._root):
                raise UpstreamUnavailable(_UNREACHABLE)
            argv = master_argv(self._executable(), self._root, self._record)
            self._stderr.clear()
            process = await asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )
            self._process = process
            self._stderr_task = asyncio.create_task(self._drain_stderr(process))
            deadline = time.monotonic() + _MASTER_START_SECONDS
            while time.monotonic() < deadline:
                if process.returncode is not None:
                    break
                if self.upstream_path.exists():
                    return
                await asyncio.sleep(_POLL_SECONDS)
            if process.returncode is None:
                await self._stop_process()
                raise UpstreamUnavailable(_UNREACHABLE)
            await asyncio.gather(self._stderr_task, return_exceptions=True)
            reason = classify_ssh_failure(b"".join(self._stderr))
            self._process = None
            raise UpstreamUnavailable(reason)

    async def run_remote(self, *arguments: str) -> int:
        """Run one fixed remote command over the master; its exit status (output discarded)."""

        await self.ensure()
        process = await asyncio.create_subprocess_exec(
            *remote_argv(self._executable(), self._root, self._record, *arguments),
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
            start_new_session=True,
        )
        try:
            async with asyncio.timeout(_REMOTE_COMMAND_SECONDS):
                return await process.wait()
        except TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                process.kill()
            await process.wait()
            return 255

    async def _stop_process(self) -> None:
        process = self._process
        self._process = None
        if process is not None and process.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                process.terminate()
            try:
                async with asyncio.timeout(2.0):
                    await process.wait()
            except TimeoutError:
                with contextlib.suppress(ProcessLookupError):
                    process.kill()
                await process.wait()
        task = self._stderr_task
        self._stderr_task = None
        if task is not None:
            await asyncio.gather(task, return_exceptions=True)

    async def close(self) -> None:
        """Ask the master to exit through its control socket, then reap the child we started."""

        if self._alive():
            exiting = await asyncio.create_subprocess_exec(
                *control_argv(self._executable(), self._root, self._record, "exit"),
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                async with asyncio.timeout(2.0):
                    await exiting.wait()
            except TimeoutError:
                with contextlib.suppress(ProcessLookupError):
                    exiting.kill()
                await exiting.wait()
        async with self._lock:
            await self._stop_process()
