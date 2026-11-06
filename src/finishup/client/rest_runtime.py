"""Target runtimes of the server-native network API: ``https``, ``local_port`` and ``ssh`` (ADR-051).

``finishup server connect|disconnect|test|status`` reach a remote target through these.

* ``https`` and ``local_port`` need no local process: ``ensure_ready`` reads ``GET /v1/server``
  with the stored key, ``probe`` times ``service_status`` calls, and ``stop`` ends this client's
  workspace agent for the target.
* ``ssh`` keeps one OpenSSH master per target (``<target root>/run/m``) that forwards
  ``<target root>/run/api.sock`` to the server's owner-only API socket — a Unix socket to a Unix
  socket, so the server opens no TCP port for SSH clients. The master runs with
  ``BatchMode=yes`` and ``StrictHostKeyChecking=yes`` (OpenSSH keeps the keys and
  ``known_hosts``), binds the local socket owner-only, and stops after 15 idle minutes or on
  ``ssh -O exit``. A remote service that stopped while idle is started again with the recorded
  absolute launcher (``service start``), never a bare ``finishup`` from the remote ``PATH``.

Nothing here runs a shell on this machine or kills a process by name: the master is stopped
through its own control socket and the agent through its stamped pid. ssh's own output is read
only to choose a closed reason and is never shown or logged.
"""

from __future__ import annotations

import os
import re
import shlex
import stat
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Final, cast

from finishup.client.target_runtime import (
    PROBE_SAMPLES,
    ProbeOutcome,
    ProbeResult,
    TargetRuntimeError,
)
from finishup.client.targets import ServerTarget, read_target
from finishup.protocol.canonical import JsonValue, strict_json_parse
from finishup.service.network_protocol import API_SOCKET_NAME

__all__ = [
    "MASTER_SOCKET_NAME",
    "RestTargetRuntime",
    "SshEndpoint",
    "SshTargetRuntime",
    "discover_ssh_endpoint",
    "ssh_command_prefix",
    "ssh_master_argv",
]

MASTER_SOCKET_NAME: Final = "m"
_SSH: Final = "ssh"
_MASTER_IDLE_SECONDS: Final = 900
_SSH_START_SECONDS: Final = 30.0
_SSH_CONTROL_SECONDS: Final = 10.0
_DISCOVERY_SECONDS: Final = 30.0
_MAX_DISCOVERY_BYTES: Final = 65_536
_MAX_PATH_TEXT: Final = 1_024
# Where a FinishUP launcher is commonly installed when ``server add`` was given none. The first
# executable one answers; a bare ``finishup`` from the remote PATH is never used (issue #604).
_LAUNCHER_CANDIDATES: Final = (
    '"$HOME/.local/bin/finishup"',
    "/usr/local/bin/finishup",
    "/opt/homebrew/bin/finishup",
)
_AUTH_FAILURE: Final = re.compile(rb"Permission denied|Too many authentication failures")
_HOST_KEY_FAILURE: Final = re.compile(
    rb"Host key verification failed|REMOTE HOST IDENTIFICATION HAS CHANGED|No .* host key is known"
)


@dataclass(frozen=True, slots=True)
class SshEndpoint:
    """What ``server add`` learned from the server: its API socket and its launcher."""

    api_socket: str
    launcher: str


def _destination_of(user: str | None, host: str) -> str:
    return host if user is None else f"{user}@{host}"


def _destination(record: ServerTarget) -> str:
    if record.host is None or record.port is None:
        raise TargetRuntimeError("remote_unreachable", phase="target_incomplete")
    return _destination_of(record.user, record.host)


def _socket_path_text(value: object) -> str:
    """An absolute socket path that ``ssh -L local:remote`` can carry (no ``:``)."""

    if (
        type(value) is not str
        or not value.startswith("/")
        or len(value) > _MAX_PATH_TEXT
        or ":" in value
        or any(ord(character) < 0x21 or ord(character) == 0x7F for character in value)
    ):
        raise TargetRuntimeError("remote_incompatible", phase="api_socket_invalid")
    return value


def _launcher_text(value: object) -> str:
    """An absolute launcher path reported by the server (spaces allowed, no control bytes)."""

    if (
        type(value) is not str
        or not value.startswith("/")
        or len(value) > _MAX_PATH_TEXT
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise TargetRuntimeError("remote_incompatible", phase="launcher_invalid")
    return value


def ssh_command_prefix(record: ServerTarget, root: Path) -> list[str]:
    """``ssh`` options shared by every connection of one target, through its master if any."""

    return [
        _SSH,
        "-S",
        os.fspath(root / "run" / MASTER_SOCKET_NAME),
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-p",
        str(record.port),
    ]


def ssh_master_argv(record: ServerTarget, root: Path) -> list[str]:
    """The fixed, secret-free argv of one target's OpenSSH master and its socket forward."""

    if record.kind != "ssh":
        raise TargetRuntimeError("remote_unreachable", phase="target_incomplete")
    remote = _socket_path_text(record.remote_endpoint)
    local = os.fspath(root / "run" / API_SOCKET_NAME)
    if ":" in local:
        raise TargetRuntimeError("remote_unreachable", phase="target_root_unsupported")
    return [
        _SSH,
        "-f",
        "-N",
        "-M",
        "-S",
        os.fspath(root / "run" / MASTER_SOCKET_NAME),
        "-o",
        f"ControlPersist={_MASTER_IDLE_SECONDS}",
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
        str(record.port),
        "-L",
        f"{local}:{remote}",
        "--",
        _destination(record),
    ]


def _ssh_environment() -> dict[str, str]:
    """What ssh needs to find the owner's keys and agent, and nothing FinishUP-specific."""

    keep = ("HOME", "USER", "LOGNAME", "PATH", "SSH_AUTH_SOCK", "LANG", "LC_ALL", "TMPDIR")
    return {name: os.environ[name] for name in keep if name in os.environ}


def _ssh_failure(stderr: bytes) -> TargetRuntimeError:
    if _HOST_KEY_FAILURE.search(stderr):
        return TargetRuntimeError("remote_identity_changed", phase="ssh_host_key")
    if _AUTH_FAILURE.search(stderr):
        return TargetRuntimeError("remote_auth_failed", phase="ssh_authentication")
    return TargetRuntimeError("remote_unreachable", phase="ssh_connect")


def _run(
    argv: list[str], *, timeout: float, detaches: bool = False
) -> subprocess.CompletedProcess[bytes]:
    """Run ssh with a scrubbed environment; ``detaches`` for a master that backgrounds itself.

    A backgrounded master keeps its inherited output open for its whole life, so its stderr goes
    to an unnamed temporary file (read once, for a closed reason) instead of a pipe.
    """

    import tempfile

    try:
        if not detaches:
            return subprocess.run(  # noqa: S603 - fixed ssh argv; no shell on this machine
                argv,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                env=_ssh_environment(),
                timeout=timeout,
                check=False,
            )
        with tempfile.TemporaryFile() as stderr:
            completed = subprocess.run(  # noqa: S603 - fixed ssh argv; no shell on this machine
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=stderr,
                env=_ssh_environment(),
                timeout=timeout,
                check=False,
                start_new_session=True,
            )
            stderr.seek(0)
            return subprocess.CompletedProcess(
                argv, completed.returncode, b"", stderr.read(_MAX_DISCOVERY_BYTES)
            )
    except FileNotFoundError:
        raise TargetRuntimeError("remote_unreachable", phase="ssh_missing") from None
    except subprocess.TimeoutExpired:
        raise TargetRuntimeError("remote_unreachable", phase="ssh_timeout") from None
    except OSError:
        raise TargetRuntimeError("remote_unreachable", phase="ssh_connect") from None


def _remote_command(remote_root: str | None, launcher: str | None, *arguments: str) -> str:
    """One remote command: the absolute launcher (or the probe for one) and fixed arguments.

    ``remote_root`` pins the server's isolated root through ``env``, so the command acts on that
    service whatever the remote login environment holds. Every value is shell-quoted.
    """

    pin = "" if remote_root is None else f"env FINISHUP_ISOLATED_ROOT={shlex.quote(remote_root)} "
    tail = " ".join(shlex.quote(argument) for argument in arguments)
    if launcher is not None:
        return f"{pin}{shlex.quote(launcher)} {tail}"
    candidates = " ".join(_LAUNCHER_CANDIDATES)
    return (
        f'for p in {candidates}; do if [ -x "$p" ]; then printf "%s\\n" "$p"; '
        f'exec {pin}"$p" {tail}; fi; done; exit 127'
    )


def discover_ssh_endpoint(
    *,
    user: str | None,
    host: str,
    port: int,
    remote_root: str | None,
    remote_launcher: str | None,
) -> SshEndpoint:
    """Ask the server, over one batch-mode SSH command, where its API socket is.

    Runs ``<launcher> service endpoint --json`` there (``--remote-launcher``, or the first common
    install path that exists). The answer must name an owner-only API socket: a server without
    ``[network] api_socket = true`` is refused with ``remote_incompatible``. OpenSSH must already
    trust the host key (``StrictHostKeyChecking=yes``); nothing here prompts.
    """

    launcher = remote_launcher
    command = _remote_command(remote_root, launcher, "service", "endpoint", "--json")
    argv = [
        _SSH,
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-p",
        str(port),
        "--",
        _destination_of(user, host),
        command,
    ]
    completed = _run(argv, timeout=_DISCOVERY_SECONDS)
    if completed.returncode == 255:
        raise _ssh_failure(completed.stderr)
    if completed.returncode == 127:
        raise TargetRuntimeError("remote_incompatible", phase="launcher_not_found")
    if completed.returncode != 0 or len(completed.stdout) > _MAX_DISCOVERY_BYTES:
        raise TargetRuntimeError("remote_incompatible", phase="endpoint_report_invalid")
    output = completed.stdout
    if launcher is None:
        first, _newline, output = output.partition(b"\n")
        try:
            launcher = _launcher_text(first.decode("utf-8"))
        except UnicodeDecodeError:
            raise TargetRuntimeError("remote_incompatible", phase="launcher_invalid") from None
    try:
        report = strict_json_parse(output.rstrip(b"\n"))
    except ValueError:
        raise TargetRuntimeError("remote_incompatible", phase="endpoint_report_invalid") from None
    if type(report) is not dict:
        raise TargetRuntimeError("remote_incompatible", phase="endpoint_report_invalid")
    document = cast(dict[str, JsonValue], report)
    if document.get("schema") != "yoetz.service-endpoint/1":
        raise TargetRuntimeError("remote_incompatible", phase="endpoint_report_invalid")
    network = document.get("network")
    if type(network) is not dict:
        raise TargetRuntimeError("remote_incompatible", phase="api_socket_unconfigured")
    api_socket = cast(dict[str, JsonValue], network).get("api_socket")
    if api_socket is None:
        raise TargetRuntimeError("remote_incompatible", phase="api_socket_unconfigured")
    return SshEndpoint(_socket_path_text(api_socket), launcher)


def _p95(samples: list[float]) -> int:
    ordered = sorted(samples)
    index = max(0, -(-95 * len(ordered) // 100) - 1)
    return round(ordered[index] * 1000)


def _record(root: Path | None) -> ServerTarget:
    if root is None:
        raise TargetRuntimeError("remote_unreachable", phase="target_incomplete")
    from finishup.client.targets import TargetError

    try:
        record = read_target(root)
    except TargetError:
        raise TargetRuntimeError("remote_unreachable", phase="target_incomplete") from None
    if record is None or not record.is_remote:
        raise TargetRuntimeError("remote_unreachable", phase="target_incomplete")
    return record


def _runtime_error(error: BaseException) -> TargetRuntimeError:
    from finishup.ports.control import ControlError

    if isinstance(error, TargetRuntimeError):
        return error
    if isinstance(error, ControlError):
        phase = error.phase
        if (
            error.reason == "service_unavailable"
            and phase is not None
            and phase.startswith("remote_")
        ):
            return TargetRuntimeError(phase)
        return TargetRuntimeError(error.reason, phase=phase)
    return TargetRuntimeError("remote_unreachable", phase="timeout")


class RestTargetRuntime:
    """``https`` and ``local_port`` targets: nothing to start, a workspace agent to stop."""

    def ensure_ready(self, root: Path | None) -> None:
        record = _record(root)
        assert root is not None
        self._prepare(record, root)
        import anyio

        from finishup.client.rest_client import connect_rest_service
        from finishup.ports.control import ControlClientKind

        async def connect() -> None:
            with anyio.fail_after(_SSH_START_SECONDS):
                client = await connect_rest_service(ControlClientKind.CLI, record=record, root=root)
            await client.close()

        try:
            anyio.run(connect)
        except Exception as error:
            raise _runtime_error(error) from None

    def _prepare(self, record: ServerTarget, root: Path) -> None:
        """Make the transport usable before connecting (nothing for HTTPS)."""

        del record, root

    def stop(self, root: Path | None) -> None:
        record = _record(root)
        assert root is not None
        from finishup.client.agent import stop_agent

        stop_agent(root)
        self._teardown(record, root)

    def _teardown(self, record: ServerTarget, root: Path) -> None:
        del record, root

    def probe(self, root: Path | None) -> ProbeResult:
        try:
            record = _record(root)
            assert root is not None
            self._prepare(record, root)
        except TargetRuntimeError as error:
            return ProbeResult("unavailable", reason=error.reason, phase=error.phase)
        import anyio

        from finishup.client.rest_client import connect_rest_service
        from finishup.ports.control import ControlClientKind, ControlError, ServiceState

        async def probe() -> ProbeResult:
            try:
                with anyio.fail_after(_SSH_START_SECONDS):
                    client = await connect_rest_service(
                        ControlClientKind.CLI, record=record, root=root
                    )
            except (ControlError, TimeoutError) as error:
                failure = _runtime_error(error)
                outcome: ProbeOutcome = (
                    "not_running"
                    if failure.reason == "remote_service_not_running"
                    else "unavailable"
                )
                return ProbeResult(outcome, reason=failure.reason, phase=failure.phase)
            samples: list[float] = []
            try:
                # The first call also loads this process's protocol validators, which a local
                # connection loads during its hello; that is not a round trip, so it is not one
                # of the samples (it read about 0.2 s against a 20 ms round trip in a real run).
                status = await client.service_status()
                for _sample in range(PROBE_SAMPLES):
                    started = time.monotonic()
                    status = await client.service_status()
                    samples.append(time.monotonic() - started)
            except ControlError as error:
                failure = _runtime_error(error)
                return ProbeResult("unavailable", reason=failure.reason, phase=failure.phase)
            finally:
                await client.close()
            assert status is not None
            return ProbeResult(
                "ready" if status.state is ServiceState.READY else "reachable",
                service_version=status.service_version,
                service_instance_id=status.service_instance_id,
                service_state=status.state.value,
                vault_mode=status.vault_mode,
                round_trip_p95_ms=_p95(samples),
                samples=len(samples),
            )

        return anyio.run(probe)


class SshTargetRuntime(RestTargetRuntime):
    """``ssh`` targets: one OpenSSH master per target, forwarding the API socket."""

    def master_running(self, record: ServerTarget, root: Path) -> bool:
        argv = [*ssh_command_prefix(record, root), "-O", "check", "--", _destination(record)]
        if not (root / "run" / MASTER_SOCKET_NAME).exists():
            return False
        return _run(argv, timeout=_SSH_CONTROL_SECONDS).returncode == 0

    def _prepare(self, record: ServerTarget, root: Path) -> None:
        self.ensure_master(record, root)

    def ensure_master(self, record: ServerTarget, root: Path) -> None:
        """Start this target's master unless it is running with its forward in place."""

        if self.master_running(record, root) and (root / "run" / API_SOCKET_NAME).exists():
            return
        completed = _run(ssh_master_argv(record, root), timeout=_SSH_START_SECONDS, detaches=True)
        if completed.returncode != 0:
            raise _ssh_failure(completed.stderr)

    def start_remote_service(self, record: ServerTarget, root: Path) -> None:
        """Start an idle-stopped remote service once, through the master and its launcher."""

        if record.remote_launcher is None:
            raise TargetRuntimeError("remote_service_not_running", phase="launcher_unknown")
        argv = [
            *ssh_command_prefix(record, root),
            "--",
            _destination(record),
            _remote_command(record.remote_root, record.remote_launcher, "service", "start"),
        ]
        completed = _run(argv, timeout=_SSH_START_SECONDS)
        if completed.returncode == 255:
            raise _ssh_failure(completed.stderr)
        if completed.returncode != 0:
            raise TargetRuntimeError("remote_service_not_running", phase="service_start_failed")

    def _teardown(self, record: ServerTarget, root: Path) -> None:
        if (root / "run" / MASTER_SOCKET_NAME).exists():
            argv = [*ssh_command_prefix(record, root), "-O", "exit", "--", _destination(record)]
            _run(argv, timeout=_SSH_CONTROL_SECONDS)
        forwarded = root / "run" / API_SOCKET_NAME
        try:
            facts = forwarded.lstat()
        except FileNotFoundError:
            return
        if stat.S_ISSOCK(facts.st_mode) and facts.st_uid == os.geteuid():
            forwarded.unlink()
