"""Target runtimes and server checks of the direct-dial topology (ADR-051, approach B).

``finishup server connect|disconnect|test|status`` reach a remote target through these runtimes
(``client.target_runtime`` registers them for ``ssh``, ``https`` and ``local_port``):

* **SSH.** ``ensure_ready`` starts (or reuses) the target's OpenSSH master at
  ``<root>/run/m`` with ``ssh -fN`` and the same trust options every stream uses, then connects on
  demand, which starts an idle-stopped remote service through the recorded launcher.
  ``stop`` asks that master to exit by its control path (``ssh -O exit``); nothing is ever found
  or signalled by pattern. ``probe`` times status round trips over the real transport.
* **HTTPS and localhost ports.** ``ensure_ready`` asks the gateway who it is
  (``GET /v1/server``) with the stored key; there is no client-side process, so ``stop`` has
  nothing to stop (the gateway expires idle sessions). ``probe`` is the same timed status probe.

``discover_ssh_endpoint`` is what ``server add ssh://…`` runs once the owner has authorized the
target: the server's own ``finishup service endpoint --json``, over the same SSH trust options,
through the recorded launcher (or one found at a fixed list of install paths, never a bare
``finishup`` on the remote ``PATH``). It returns the remote control endpoint to record and checks
that the server runs this client's schema manifest.

Every failure is a ``TargetRuntimeError`` with closed tokens; OpenSSH's own diagnostics are
classified and dropped, never shown.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, cast

from finishup.client.target_runtime import ProbeResult, TargetRuntimeError, probe_service
from finishup.client.targets import ServerTarget, TargetError, read_target
from finishup.client.transports import (
    TransportError,
    classify_ssh_failure,
    ssh_control_argv,
    ssh_environment,
    ssh_master_argv,
)

__all__ = [
    "SSH_LAUNCHER_CANDIDATES",
    "HttpsTargetRuntime",
    "SshEndpoint",
    "SshTargetRuntime",
    "discover_ssh_endpoint",
]

type _Runner = Callable[..., subprocess.CompletedProcess[bytes]]

_MASTER_SECONDS: Final = 30.0
_CONTROL_SECONDS: Final = 10.0
_PROBE_SECONDS: Final = 30.0
_START_SECONDS: Final = 30.0
_MAX_ENDPOINT_REPORT_BYTES: Final = 16_384
_MAX_PATH_TEXT: Final = 1_024
# Where a FinishUP launcher is installed by the documented install paths (``uv tool``, ``pipx``,
# Homebrew, a system package). The probe is one fixed remote script; it prints the first
# executable candidate and nothing else.
SSH_LAUNCHER_CANDIDATES: Final = (
    "$HOME/.local/bin/finishup",
    "/opt/homebrew/bin/finishup",
    "/usr/local/bin/finishup",
    "/usr/bin/finishup",
)
_LAUNCHER_PROBE: Final = (
    "for candidate in "
    + " ".join(f'"{candidate}"' for candidate in SSH_LAUNCHER_CANDIDATES)
    + '; do if [ -x "$candidate" ]; then printf "%s\\n" "$candidate"; exit 0; fi; done; exit 3'
)
_ENDPOINT_SCHEMA: Final = "yoetz.service-endpoint/1"


def _remote_record(root: Path | None, kinds: frozenset[str]) -> tuple[ServerTarget, Path]:
    if root is None:
        raise TargetRuntimeError("target_record_invalid")
    try:
        record = read_target(root)
    except TargetError as error:
        raise TargetRuntimeError(error.reason) from None
    if record is None or record.kind not in kinds:
        raise TargetRuntimeError("target_record_invalid")
    return record, root


def _run(runner: _Runner, argv: Sequence[str], seconds: float) -> tuple[int | None, bytes, bytes]:
    """Run one fixed ``ssh`` argv; ``None`` as the code when it outlived its bound or failed."""

    try:
        completed = runner(
            list(argv),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            env=ssh_environment(),
            timeout=seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return None, b"", b""
    except OSError:
        return None, b"", b""
    return completed.returncode, completed.stdout, completed.stderr


def _ssh_phase(code: int | None, stderr: bytes) -> str:
    return classify_ssh_failure(code, stderr) or "remote_unreachable"


def _command_phase(code: int | None, stderr: bytes) -> str:
    """Why a remote command failed: ``ssh`` itself (255, or no exit) or the server's command.

    Any other exit status is the remote command's own: the connection worked and the server did
    not answer as this release's FinishUP does.
    """

    if code is None or code == 255:
        return _ssh_phase(code, stderr)
    return "remote_incompatible"


class SshTargetRuntime:
    """An SSH target: its persistent OpenSSH master, and the remote service behind it."""

    __slots__ = ("_program", "_runner")

    _program: tuple[str, ...]
    _runner: _Runner

    def __init__(
        self, *, program: Sequence[str] = ("ssh",), runner: _Runner = subprocess.run
    ) -> None:
        self._program = tuple(program)
        self._runner = runner

    def ensure_ready(self, root: Path | None) -> None:
        record, target_root = _remote_record(root, frozenset({"ssh"}))
        code, _stdout, stderr = _run(
            self._runner,
            ssh_master_argv(record, target_root, program=self._program),
            _MASTER_SECONDS,
        )
        if code != 0:
            raise TargetRuntimeError("service_unavailable", phase=_ssh_phase(code, stderr))
        _ensure_service(target_root)

    def stop(self, root: Path | None) -> None:
        record, target_root = _remote_record(root, frozenset({"ssh"}))
        if not (target_root / "run" / "m").exists():
            return
        code, _stdout, stderr = _run(
            self._runner,
            ssh_control_argv(record, target_root, "exit", program=self._program),
            _CONTROL_SECONDS,
        )
        if code != 0 and b"No such file" not in stderr and b"Connection refused" not in stderr:
            raise TargetRuntimeError("service_unavailable", phase=_ssh_phase(code, stderr))

    def probe(self, root: Path | None) -> ProbeResult:
        _remote_record(root, frozenset({"ssh"}))
        return probe_service(root)


class HttpsTargetRuntime:
    """An HTTPS or localhost-port target: the gateway answers; no client process runs."""

    __slots__ = ()

    def ensure_ready(self, root: Path | None) -> None:
        import anyio

        from finishup.client.credentials import CredentialError, KeyringOrFileCredential
        from finishup.client.https_binding import fetch_server_info

        record, target_root = _remote_record(root, frozenset({"https", "local_port"}))
        try:
            secret = KeyringOrFileCredential(
                record.target_id, target_root, recorded=record.credential
            ).read()
        except CredentialError:
            raise TargetRuntimeError("service_unavailable", phase="remote_auth_failed") from None

        async def check() -> None:
            await fetch_server_info(record, secret)

        try:
            anyio.run(check)
        except TransportError as error:
            raise TargetRuntimeError("service_unavailable", phase=error.phase) from None

    def stop(self, root: Path | None) -> None:
        # No client-side process holds anything for this target; the gateway closes a session's
        # upstream after 120 idle seconds.
        _remote_record(root, frozenset({"https", "local_port"}))

    def probe(self, root: Path | None) -> ProbeResult:
        _remote_record(root, frozenset({"https", "local_port"}))
        return probe_service(root)


def _ensure_service(root: Path) -> None:
    """Connect on demand under ``root``: an idle-stopped remote service is started once."""

    import anyio

    from finishup.config.paths import selection_override
    from finishup.ports.control import ControlClientKind, ControlError
    from finishup.service.client import connect_service_on_demand

    async def start() -> None:
        client = await connect_service_on_demand(
            ControlClientKind.CLI, workspace_locator=None, timeout_seconds=_START_SECONDS
        )
        await client.close()

    with selection_override(root):
        try:
            anyio.run(start)
        except ControlError as error:
            raise TargetRuntimeError(error.reason, phase=error.phase) from None


@dataclass(frozen=True, slots=True)
class SshEndpoint:
    """What ``server add ssh://…`` records: the remote endpoint and the launcher that found it.

    ``session_bound`` is true when the endpoint lives in a login session's runtime folder on an
    account without linger, so it disappears at the owner's last logout on the server.
    """

    endpoint: str
    launcher: str | None
    session_bound: bool


def _absolute(value: object) -> str | None:
    if (
        type(value) is not str
        or not value.startswith("/")
        or len(value) > _MAX_PATH_TEXT
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        return None
    return value


def _probe_argv(
    program: Sequence[str], user: str | None, host: str, port: int, command: str
) -> tuple[str, ...]:
    destination = host if user is None else f"{user}@{host}"
    return (
        *program,
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-T",
        "-p",
        str(port),
        destination,
        "--",
        command,
    )


def discover_ssh_endpoint(
    *,
    user: str | None,
    host: str,
    port: int,
    remote_root: str | None,
    remote_launcher: str | None,
    program: Sequence[str] = ("ssh",),
    runner: _Runner = subprocess.run,
) -> SshEndpoint:
    """Ask the server, over SSH, where its control endpoint is (after the owner authorized it).

    With a launcher (given or found at a fixed install path) the server's own
    ``service endpoint --json`` answers, pinned to ``remote_root`` when one is given; its manifest
    must be this client's (``remote_incompatible``). With no launcher but a remote root, the
    endpoint is ``<remote root>/run/control.sock`` and nothing runs remotely. With neither, the
    target cannot be reached: ``remote_service_not_running``.
    """

    import shlex

    from finishup.config.paths import ISOLATED_ROOT_ENV
    from finishup.protocol.schemas import schema_manifest_digest

    launcher = remote_launcher
    if launcher is None:
        code, stdout, stderr = _run(
            runner, _probe_argv(program, user, host, port, _LAUNCHER_PROBE), _PROBE_SECONDS
        )
        if code == 0:
            launcher = _absolute(stdout.decode("utf-8", "replace").strip())
        elif code != 3:
            raise TargetRuntimeError("service_unavailable", phase=_command_phase(code, stderr))
    if launcher is None:
        if remote_root is None:
            raise TargetRuntimeError("service_unavailable", phase="remote_service_not_running")
        return SshEndpoint(f"{remote_root.rstrip('/')}/run/control.sock", None, False)
    words = [launcher, "service", "endpoint", "--json"]
    if remote_root is not None:
        words = ["env", f"{ISOLATED_ROOT_ENV}={remote_root}", *words]
    command = " ".join(shlex.quote(word) for word in words)
    code, stdout, stderr = _run(
        runner, _probe_argv(program, user, host, port, command), _PROBE_SECONDS
    )
    if code != 0:
        # A launcher the remote shell cannot run (126, 127) is not this release's FinishUP.
        raise TargetRuntimeError("service_unavailable", phase=_command_phase(code, stderr))
    if len(stdout) > _MAX_ENDPOINT_REPORT_BYTES:
        raise TargetRuntimeError("service_unavailable", phase="remote_incompatible")
    try:
        parsed: object = json.loads(stdout)
    except ValueError:
        raise TargetRuntimeError("service_unavailable", phase="remote_incompatible") from None
    if not isinstance(parsed, dict):
        raise TargetRuntimeError("service_unavailable", phase="remote_incompatible")
    report = cast(dict[str, object], parsed)
    endpoint = _absolute(report.get("endpoint"))
    if report.get("schema") != _ENDPOINT_SCHEMA or endpoint is None:
        raise TargetRuntimeError("service_unavailable", phase="remote_incompatible")
    if report.get("schema_manifest_digest") != schema_manifest_digest():
        raise TargetRuntimeError("service_unavailable", phase="remote_incompatible")
    # The endpoint disappears at the owner's last logout unless the account lingers.
    session_bound = (
        report.get("runtime_dir_session_bound") is True and report.get("linger") != "enabled"
    )
    return SshEndpoint(endpoint, launcher, session_bound)
