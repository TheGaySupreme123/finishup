"""Direct-dial control transports: how one client process reaches its server (ADR-051, approach B).

Approach B ("client SDK, direct dial") runs no relay process on the client machine. Every client
process — a hook, the MCP bridge, the CLI, the terminal interface — opens its own control stream
to the server its active root names, and ``ServiceClient`` runs the unchanged control protocol
above that stream. ``transport_for_active_root()`` picks the transport from the root's
``target.json``:

* ``UnixTransport`` — the everyday server, an explicitly isolated root, and named local servers:
  today's owner-only endpoint under the active root, dialled by the caller's ``connect_control``.
* ``SshTransport`` — a server on another machine over OpenSSH. Each stream is one
  ``ssh -S <root>/run/m -o ControlMaster=auto -o ControlPersist=15m -o BatchMode=yes
  -o StrictHostKeyChecking=yes -p <port> -W <remote control.sock> <[user@]host>`` whose standard
  input and output carry the frames. The first stream leaves a master that persists for 15 idle
  minutes, so a later hook pays one channel open instead of a TCP and key exchange. sshd connects
  to the remote endpoint as the login user, so the service's peer-UID check passes unchanged.
* ``HttpsTransport`` — a server reached over HTTPS (``https`` and ``local_port`` targets), speaking
  HTTPS binding v1 to the server's gateway (``finishup.client.https_binding``). The binding is
  re-framed into the same length-prefixed byte stream, so nothing above the stream changes. The
  API key is read in this process from the target's credential store: the disclosed ADR-008
  amendment of this approach.

Remote roots never spawn or supersede a local service; that stays with ``service.client`` and
local roots. Nothing here loads a network client at import: the HTTPS binding (and ``httpx``) loads
inside ``HttpsTransport.connect`` only, so a hook that never dials an HTTPS target never imports
it. Every remote failure is a ``TransportError`` carrying one closed remote phase
(``protocol.errors.REMOTE_CONNECTION_PHASES``); no host, user, path, header, or server text appears
in an error, a log, or a representation.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import shlex
from collections.abc import Awaitable, Buffer, Callable, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Final, Literal, NoReturn, Protocol

from finishup.client.targets import ServerTarget, read_target
from finishup.config.env import canonical_env_name
from finishup.config.paths import ISOLATED_ROOT_ENV, PathSafetyError, active_root
from finishup.protocol.errors import REMOTE_CONNECTION_PHASES
from finishup.service.control_protocol import ControlStream

if TYPE_CHECKING:
    from finishup.client.credentials import CredentialSource

__all__ = [
    "SSH_CONTROL_PATH",
    "SSH_CONTROL_PERSIST",
    "ControlTransport",
    "HttpsTransport",
    "RemoteControlStream",
    "RemotePeerIdentity",
    "SshControlStream",
    "SshTransport",
    "TransportError",
    "TransportKind",
    "UnixTransport",
    "classify_ssh_failure",
    "ssh_control_argv",
    "ssh_destination",
    "ssh_environment",
    "ssh_master_argv",
    "ssh_remote_command_argv",
    "ssh_stdio_argv",
    "start_remote_service",
    "transport_for_active_root",
    "transport_for_target",
]

type TransportKind = Literal["unix", "ssh", "https"]

# The OpenSSH master's control socket beneath a remote target root. OpenSSH binds it under a
# 17-byte temporary suffix first, which stays inside the root's socket-path bound (the longest
# endpoint ``run/secret-ingress.sock`` is longer than ``run/m`` plus that suffix).
SSH_CONTROL_PATH: Final = Path("run") / "m"
SSH_CONTROL_PERSIST: Final = "15m"
# BatchMode never prompts (no password, no passphrase, no host-key question); a host key that is
# not already in known_hosts, or that changed, refuses the connection.
_SSH_TRUST_OPTIONS: Final = ("-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes")
_SSH_LIVENESS_OPTIONS: Final = ("-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3")
_SSH_STDERR_LIMIT: Final = 8_192
# A remote ``finishup service start`` spawns the service and waits for its first handshake.
_REMOTE_START_SECONDS: Final = 30.0
_SSH_EXIT_WAIT_SECONDS: Final = 1.0
_SSH_TERMINATE_WAIT_SECONDS: Final = 0.5
_MAX_RECEIVE_BYTES: Final = 65_536

# Fixed OpenSSH diagnostics, matched to classify a failed stream. They are read, never echoed:
# the stderr buffer stays in this process and no part of it reaches an error, log, or output.
_SSH_IDENTITY_MARKERS: Final = (
    b"Host key verification failed",
    b"REMOTE HOST IDENTIFICATION HAS CHANGED",
    b"host key is known",
)
_SSH_AUTH_MARKERS: Final = (
    b"Permission denied",
    b"Too many authentication failures",
    b"no mutual signature",
)
_SSH_NOT_RUNNING_MARKERS: Final = (
    b"Stdio forwarding request failed",
    b"open failed",
    b"Session open refused",
)


class TransportError(Exception):
    """A remote connection failed in one closed phase (``REMOTE_CONNECTION_PHASES``)."""

    __slots__ = ("phase",)

    phase: str

    def __init__(self, phase: str) -> None:
        if phase not in REMOTE_CONNECTION_PHASES:
            raise ValueError("transport_phase_invalid")
        self.phase = phase
        super().__init__(phase)


class RemotePeerIdentity:
    """Opaque, nonserializable peer of one remote stream; it names only the transport kind.

    The control session needs a non-primitive peer object; a remote stream's real peer is the
    login (SSH) or the API key (HTTPS) the server authenticated, which the client never holds.
    """

    __slots__ = ("_kind",)

    _kind: TransportKind

    def __init__(self, kind: TransportKind) -> None:
        self._kind = kind

    @property
    def kind(self) -> TransportKind:
        return self._kind

    def __repr__(self) -> str:
        return f"RemotePeerIdentity({self._kind})"

    def __reduce__(self) -> NoReturn:
        raise TypeError("remote_peer_identity_not_serializable")


class RemoteControlStream(ControlStream, Protocol):
    """A control stream to a remote server that can name why it ended."""

    async def failure_phase(self) -> str | None:
        """The closed remote phase that ended this stream, or ``None`` when it ended cleanly."""
        ...


class ControlTransport(Protocol):
    """How this process dials its server: one call, one fresh authenticated stream."""

    @property
    def kind(self) -> TransportKind: ...

    @property
    def target(self) -> ServerTarget | None:
        """The remote target record, or ``None`` for a local root."""
        ...

    async def connect(self) -> ControlStream: ...


class UnixTransport:
    """The owner-only Unix endpoint under the active root (local servers): today's path."""

    __slots__ = ("_dial",)

    _dial: Callable[[], Awaitable[ControlStream]]

    def __init__(self, dial: Callable[[], Awaitable[ControlStream]]) -> None:
        self._dial = dial

    @property
    def kind(self) -> TransportKind:
        return "unix"

    @property
    def target(self) -> ServerTarget | None:
        return None

    async def connect(self) -> ControlStream:
        return await self._dial()


def ssh_destination(target: ServerTarget) -> str:
    """``[user@]host`` of an SSH target; both parts were validated when the record was read."""

    if target.kind != "ssh" or target.host is None:
        raise ValueError("ssh_target_required")
    return target.host if target.user is None else f"{target.user}@{target.host}"


def _ssh_port(target: ServerTarget) -> str:
    if target.port is None:
        raise ValueError("ssh_target_required")
    return str(target.port)


def _control_path(root: Path) -> str:
    return os.fspath(root / SSH_CONTROL_PATH)


def ssh_stdio_argv(
    target: ServerTarget, root: Path, *, program: Sequence[str] = ("ssh",)
) -> tuple[str, ...]:
    """The exact argv of one stdio stream to the remote control endpoint (no secret, no shell).

    ``-W`` forwards standard input and output to the remote Unix socket over a channel of the
    shared master (it implies ``-N``, ``-T`` and ``ExitOnForwardFailure``). The host and user
    passed the target-record validation, so neither can start with ``-``.
    """

    endpoint = target.remote_endpoint
    if endpoint is None:
        raise TransportError("remote_unreachable")
    return (
        *program,
        "-S",
        _control_path(root),
        "-o",
        "ControlMaster=auto",
        "-o",
        f"ControlPersist={SSH_CONTROL_PERSIST}",
        *_SSH_TRUST_OPTIONS,
        *_SSH_LIVENESS_OPTIONS,
        "-p",
        _ssh_port(target),
        "-W",
        endpoint,
        ssh_destination(target),
    )


def ssh_master_argv(
    target: ServerTarget, root: Path, *, program: Sequence[str] = ("ssh",)
) -> tuple[str, ...]:
    """Start (or reuse) the persistent master in the background; it idles out after 15 minutes."""

    return (
        *program,
        "-f",
        "-N",
        "-S",
        _control_path(root),
        "-o",
        "ControlMaster=auto",
        "-o",
        f"ControlPersist={SSH_CONTROL_PERSIST}",
        *_SSH_TRUST_OPTIONS,
        *_SSH_LIVENESS_OPTIONS,
        "-p",
        _ssh_port(target),
        ssh_destination(target),
    )


def ssh_control_argv(
    target: ServerTarget,
    root: Path,
    operation: Literal["check", "exit"],
    *,
    program: Sequence[str] = ("ssh",),
) -> tuple[str, ...]:
    """Ask the master this root stamped by its control path; never a process found by pattern."""

    return (
        *program,
        "-S",
        _control_path(root),
        "-O",
        operation,
        "-p",
        _ssh_port(target),
        ssh_destination(target),
    )


def ssh_remote_command_argv(
    target: ServerTarget,
    root: Path | None,
    arguments: Sequence[str],
    *,
    program: Sequence[str] = ("ssh",),
) -> tuple[str, ...]:
    """Run one fixed FinishUP command on the server: ``[env ROOT=…] <launcher> <arguments>``.

    The remote side is a shell command line, so every word is quoted. The launcher is the
    recorded absolute path, never a bare ``finishup`` resolved through the remote ``PATH``; the
    recorded remote root pins the command to that isolated root. With ``root`` the command rides
    the target's master (starting one when none runs).
    """

    launcher = target.remote_launcher
    if launcher is None:
        raise TransportError("remote_service_not_running")
    words: list[str] = []
    if target.remote_root is not None:
        words.extend(("env", f"{ISOLATED_ROOT_ENV}={target.remote_root}"))
    words.append(launcher)
    words.extend(arguments)
    master: tuple[str, ...] = (
        ()
        if root is None
        else (
            "-S",
            _control_path(root),
            "-o",
            "ControlMaster=auto",
            "-o",
            f"ControlPersist={SSH_CONTROL_PERSIST}",
        )
    )
    return (
        *program,
        *master,
        *_SSH_TRUST_OPTIONS,
        "-T",
        "-p",
        _ssh_port(target),
        ssh_destination(target),
        "--",
        " ".join(shlex.quote(word) for word in words),
    )


def ssh_environment() -> dict[str, str]:
    """The environment an ``ssh`` child gets: this process's, without FinishUP's own variables.

    OpenSSH needs the agent socket and the user's home; a FinishUP root variable must never ride
    a ``SendEnv`` line to the server, where it would pick a root the owner did not record.
    """

    return {name: value for name, value in os.environ.items() if canonical_env_name(name) is None}


def classify_ssh_failure(returncode: int | None, stderr: bytes) -> str | None:
    """Name why an ``ssh`` stream ended, from its exit status and OpenSSH's fixed diagnostics.

    ``None`` means it ended cleanly: the remote endpoint closed the channel (the server itself
    answered or refused the hello), or this process closed it.
    """

    if any(marker in stderr for marker in _SSH_IDENTITY_MARKERS):
        return "remote_identity_changed"
    if any(marker in stderr for marker in _SSH_AUTH_MARKERS):
        return "remote_auth_failed"
    if any(marker in stderr for marker in _SSH_NOT_RUNNING_MARKERS):
        return "remote_service_not_running"
    if returncode is None or returncode == 0 or returncode < 0:
        return None
    return "remote_unreachable"


class SshControlStream:
    """One ``ssh -W`` child whose standard input and output carry the control frames."""

    __slots__ = ("_closed", "_peer", "_process", "_stderr", "_stderr_task")

    _closed: bool
    _peer: RemotePeerIdentity
    _process: asyncio.subprocess.Process
    _stderr: bytearray
    _stderr_task: asyncio.Task[None]

    def __init__(self, process: asyncio.subprocess.Process) -> None:
        self._process = process
        self._peer = RemotePeerIdentity("ssh")
        self._closed = False
        self._stderr = bytearray()
        self._stderr_task = asyncio.create_task(self._drain_stderr())

    @classmethod
    async def open(cls, argv: Sequence[str]) -> SshControlStream:
        try:
            process = await asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=ssh_environment(),
                close_fds=True,
            )
        except OSError:
            raise TransportError("remote_unreachable") from None
        return cls(process)

    @property
    def peer_identity(self) -> RemotePeerIdentity:
        return self._peer

    @property
    def pid(self) -> int:
        return self._process.pid

    async def _drain_stderr(self) -> None:
        reader = self._process.stderr
        if reader is None:
            return
        with contextlib.suppress(Exception):
            while chunk := await reader.read(4_096):
                room = _SSH_STDERR_LIMIT - len(self._stderr)
                if room > 0:
                    self._stderr.extend(chunk[:room])

    async def receive(self, max_bytes: int = _MAX_RECEIVE_BYTES) -> bytes:
        if type(max_bytes) is not int or not 1 <= max_bytes <= _MAX_RECEIVE_BYTES:
            raise ValueError("receive_size_invalid")
        reader = self._process.stdout
        if self._closed or reader is None:
            return b""
        try:
            return await reader.read(max_bytes)
        except (OSError, ValueError):
            return b""

    async def send_all(self, data: Buffer) -> None:
        writer = self._process.stdin
        if self._closed or writer is None:
            raise TransportError("remote_unreachable")
        view = memoryview(data)
        if view.ndim != 1 or not view.contiguous:
            raise TypeError("send_buffer_invalid")
        try:
            writer.write(view.tobytes())
            await writer.drain()
        except (OSError, RuntimeError):
            raise TransportError("remote_unreachable") from None

    async def _wait_exit(self, seconds: float) -> int | None:
        try:
            async with asyncio.timeout(seconds):
                return await self._process.wait()
        except TimeoutError:
            return None

    async def failure_phase(self) -> str | None:
        """Classify the end of this stream once ``ssh`` exited (bounded wait)."""

        returncode = self._process.returncode
        if returncode is None:
            returncode = await self._wait_exit(_SSH_EXIT_WAIT_SECONDS)
        with contextlib.suppress(TimeoutError):
            async with asyncio.timeout(_SSH_TERMINATE_WAIT_SECONDS):
                await asyncio.shield(self._stderr_task)
        return classify_ssh_failure(returncode, bytes(self._stderr))

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        writer = self._process.stdin
        if writer is not None:
            with contextlib.suppress(Exception):
                writer.close()
        if self._process.returncode is None:
            # Only the child this stream spawned is signalled, by its own pid (AGENTS.md hazard 2).
            # The shared master is a separate process and stays up for the next stream.
            with contextlib.suppress(ProcessLookupError):
                self._process.terminate()
            if await self._wait_exit(_SSH_TERMINATE_WAIT_SECONDS) is None:
                with contextlib.suppress(ProcessLookupError):
                    self._process.kill()
                await self._wait_exit(_SSH_TERMINATE_WAIT_SECONDS)


class SshTransport:
    """A server on another machine over OpenSSH, one ``-W`` channel per stream."""

    __slots__ = ("_program", "_root", "_target")

    _program: tuple[str, ...]
    _root: Path
    _target: ServerTarget

    def __init__(
        self, target: ServerTarget, root: Path, *, program: Sequence[str] = ("ssh",)
    ) -> None:
        """``program`` replaces ``ssh`` only in tests (a local relay that honours ``-W``)."""

        if target.kind != "ssh":
            raise ValueError("ssh_target_required")
        self._target = target
        self._root = root
        self._program = tuple(program)

    @property
    def kind(self) -> TransportKind:
        return "ssh"

    @property
    def target(self) -> ServerTarget:
        return self._target

    @property
    def root(self) -> Path:
        return self._root

    @property
    def program(self) -> tuple[str, ...]:
        return self._program

    def argv(self) -> tuple[str, ...]:
        return ssh_stdio_argv(self._target, self._root, program=self._program)

    async def connect(self) -> SshControlStream:
        return await SshControlStream.open(self.argv())


async def _run_ssh(argv: Sequence[str], seconds: float) -> int | None:
    """Run one fixed ``ssh`` argv to completion within ``seconds``; its output is discarded."""

    try:
        process = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
            env=ssh_environment(),
            close_fds=True,
        )
    except OSError:
        return None
    try:
        async with asyncio.timeout(seconds):
            return await process.wait()
    except BaseException:
        with contextlib.suppress(ProcessLookupError):
            process.kill()
        with contextlib.suppress(Exception):
            await asyncio.shield(process.wait())
        raise


async def start_remote_service(transport: ControlTransport, seconds: float) -> bool:
    """Start the remote service once through the target's recorded launcher; whether it started.

    Only an SSH target with a recorded launcher can: the command is the server's own idempotent
    ``finishup service start``, pinned to the recorded remote root, over the target's master. An
    HTTPS target's service is its operator's to start.
    """

    if not isinstance(transport, SshTransport) or transport.target.remote_launcher is None:
        return False
    if seconds <= 0:
        return False
    argv = ssh_remote_command_argv(
        transport.target,
        transport.root,
        ("service", "start", "--json"),
        program=transport.program,
    )
    try:
        code = await _run_ssh(argv, min(seconds, _REMOTE_START_SECONDS))
    except TimeoutError:
        return False
    return code == 0


class HttpsTransport:
    """A server over HTTPS binding v1 (``https`` and ``local_port`` targets)."""

    __slots__ = ("_credential", "_http_transport", "_root", "_target")

    _credential: CredentialSource | None
    _http_transport: object | None
    _root: Path
    _target: ServerTarget

    def __init__(
        self,
        target: ServerTarget,
        root: Path,
        *,
        credential: CredentialSource | None = None,
        http_transport: object | None = None,
    ) -> None:
        """``credential`` defaults to the target's own store; ``http_transport`` (an
        ``httpx.AsyncBaseTransport``) replaces the TLS transport only in tests."""

        if target.kind not in {"https", "local_port"}:
            raise ValueError("https_target_required")
        self._target = target
        self._root = root
        self._credential = credential
        self._http_transport = http_transport

    @property
    def kind(self) -> TransportKind:
        return "https"

    @property
    def target(self) -> ServerTarget:
        return self._target

    def credential_source(self) -> CredentialSource:
        if self._credential is not None:
            return self._credential
        from finishup.client.credentials import KeyringOrFileCredential

        return KeyringOrFileCredential(
            self._target.target_id, self._root, recorded=self._target.credential
        )

    async def connect(self) -> ControlStream:
        from finishup.client.https_binding import open_binding_stream

        return await open_binding_stream(
            self._target, self.credential_source(), http_transport=self._http_transport
        )


def transport_for_target(target: ServerTarget, root: Path) -> ControlTransport:
    """The transport of one remote target record (``local`` targets dial their Unix endpoint)."""

    if target.kind == "ssh":
        return SshTransport(target, root)
    if target.kind in {"https", "local_port"}:
        return HttpsTransport(target, root)
    raise ValueError("remote_target_required")


def transport_for_active_root(
    unix_dial: Callable[[], Awaitable[ControlStream]],
) -> ControlTransport:
    """The transport for this process's active root; ``unix_dial`` for every local root.

    Only a root whose ``target.json`` names a remote kind dials remotely. A root that cannot be
    resolved is left to ``unix_dial``, which reports that refusal exactly as before; a target
    record that cannot be read raises its closed ``TargetError``, so a damaged remote root never
    falls back to starting a local service in it.
    """

    try:
        root = active_root()
    except PathSafetyError:
        return UnixTransport(unix_dial)
    if root is None:
        return UnixTransport(unix_dial)
    record = read_target(root)
    if record is None or not record.is_remote:
        return UnixTransport(unix_dial)
    return transport_for_target(record, root)
