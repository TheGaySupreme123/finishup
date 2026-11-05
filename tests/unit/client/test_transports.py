"""Direct-dial transports: exact OpenSSH argv, closed failure phases, and root-based selection.

ADR-051 approach B: every client process dials its own server. Local roots keep the owner-only
Unix endpoint; an SSH target runs one fixed, secret-free ``ssh -W`` per stream over a persistent
master; an HTTPS target speaks the binding. Failures are closed remote phases built from OpenSSH's
fixed diagnostics, which are never echoed; and nothing here loads a network client at import.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from builders.direct_dial import RELAY_SOURCE, https_target, ssh_target
from builders.server_targets import ambient_home
from finishup.client import targets
from finishup.client.targets import TargetError
from finishup.client.transports import (
    HttpsTransport,
    SshTransport,
    TransportError,
    UnixTransport,
    classify_ssh_failure,
    ssh_control_argv,
    ssh_environment,
    ssh_master_argv,
    ssh_remote_command_argv,
    ssh_stdio_argv,
    start_remote_service,
    transport_for_active_root,
)
from finishup.config.paths import reset_selection_memo, selection_override

_REPO_SRC = Path(__file__).resolve().parents[3] / "src"
_ROOT = Path("/home/owner/.local/state/finishup/servers/t_0c0c0c0c")
_TRUST = ("-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes")
_LIVENESS = ("-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3")
_MASTER = (
    "-S",
    f"{_ROOT}/run/m",
    "-o",
    "ControlMaster=auto",
    "-o",
    "ControlPersist=15m",
)


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as root:
        yield root


def test_the_stdio_stream_argv_is_fixed_and_secret_free() -> None:
    assert ssh_stdio_argv(ssh_target(), _ROOT) == (
        "ssh",
        *_MASTER,
        *_TRUST,
        *_LIVENESS,
        "-p",
        "2222",
        "-W",
        "/srv/fu/run/control.sock",
        "owner@lab.example",
    )


def test_the_master_and_control_argv_name_only_this_root() -> None:
    assert ssh_master_argv(ssh_target(), _ROOT) == (
        "ssh",
        "-f",
        "-N",
        *_MASTER,
        *_TRUST,
        *_LIVENESS,
        "-p",
        "2222",
        "owner@lab.example",
    )
    assert ssh_control_argv(ssh_target(), _ROOT, "exit") == (
        "ssh",
        "-S",
        f"{_ROOT}/run/m",
        "-O",
        "exit",
        "-p",
        "2222",
        "owner@lab.example",
    )


def test_a_remote_command_is_one_quoted_line_pinned_to_the_recorded_root() -> None:
    from dataclasses import replace

    odd = replace(ssh_target(), remote_root="/srv/my fu", remote_launcher="/opt/fu's/finishup")
    argv = ssh_remote_command_argv(odd, _ROOT, ("service", "start", "--json"))
    assert argv[:-1] == ("ssh", *_MASTER, *_TRUST, "-T", "-p", "2222", "owner@lab.example", "--")
    assert argv[-1] == (
        "env 'FINISHUP_ISOLATED_ROOT=/srv/my fu' '/opt/fu'\"'\"'s/finishup' service start --json"
    )
    without_master = ssh_remote_command_argv(ssh_target(), None, ("service", "endpoint"))
    assert "-S" not in without_master
    no_launcher = replace(ssh_target(), remote_launcher=None)
    with pytest.raises(TransportError) as raised:
        ssh_remote_command_argv(no_launcher, _ROOT, ("service", "start"))
    assert raised.value.phase == "remote_service_not_running"


def test_an_ssh_target_without_an_endpoint_cannot_be_dialled() -> None:
    from dataclasses import replace

    with pytest.raises(TransportError) as raised:
        ssh_stdio_argv(replace(ssh_target(), remote_endpoint=None, remote_root=None), _ROOT)
    assert raised.value.phase == "remote_unreachable"


@pytest.mark.parametrize(
    ("code", "stderr", "phase"),
    [
        (
            255,
            b"No ED25519 host key is known for [127.0.0.1]:2222 and you have requested strict "
            b"checking.\r\nHost key verification failed.\r\n",
            "remote_identity_changed",
        ),
        (
            255,
            b"@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@\r\n",
            "remote_identity_changed",
        ),
        (255, b"srv@127.0.0.1: Permission denied (publickey).\r\n", "remote_auth_failed"),
        (
            255,
            b"Stdio forwarding request failed: Session open refused by peer\r\n",
            "remote_service_not_running",
        ),
        (
            255,
            b"ssh: connect to host 127.0.0.1 port 2299: Connection refused\r\n",
            "remote_unreachable",
        ),
        (
            255,
            b"ssh: Could not resolve hostname x: Name or service not known\r\n",
            "remote_unreachable",
        ),
        (0, b"", None),
        (-15, b"", None),
        (None, b"", None),
    ],
)
def test_openssh_diagnostics_map_to_closed_phases(
    code: int | None, stderr: bytes, phase: str | None
) -> None:
    assert classify_ssh_failure(code, stderr) == phase


def test_ssh_children_never_inherit_a_finishup_variable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FINISHUP_ISOLATED_ROOT", "/somewhere")
    monkeypatch.setenv("YOETZ_ISOLATED_ROOT", "/elsewhere")
    monkeypatch.setenv("SSH_AUTH_SOCK", "/run/agent.sock")
    environment = ssh_environment()
    assert "FINISHUP_ISOLATED_ROOT" not in environment
    assert "YOETZ_ISOLATED_ROOT" not in environment
    assert environment["SSH_AUTH_SOCK"] == "/run/agent.sock"


async def _never() -> object:
    raise AssertionError("not dialled")


def test_every_local_root_dials_its_unix_endpoint(home: Path) -> None:
    assert isinstance(transport_for_active_root(_never), UnixTransport)  # type: ignore[arg-type]
    with targets.registry_lock():
        record, root = targets.new_local_target("work")
    with selection_override(root):
        transport = transport_for_active_root(_never)  # type: ignore[arg-type]
    assert isinstance(transport, UnixTransport) and transport.target is None
    assert record.kind == "local"


@pytest.mark.parametrize(
    ("kind", "arguments", "expected"),
    [
        (
            "ssh",
            {"user": "owner", "host": "lab.example", "port": 22, "remote_root": "/srv"},
            SshTransport,
        ),
        ("https", {"base_url": "https://fu.example"}, HttpsTransport),
        ("local_port", {"base_url": "https://127.0.0.1:9443"}, HttpsTransport),
    ],
)
def test_a_remote_target_root_dials_its_own_transport(
    home: Path, kind: str, arguments: dict[str, object], expected: type[object]
) -> None:
    with targets.registry_lock():
        record, root = targets.new_remote_target("lab", kind, **arguments)  # type: ignore[arg-type]
    with selection_override(root):
        transport = transport_for_active_root(_never)  # type: ignore[arg-type]
    assert isinstance(transport, expected)
    assert transport.target == record


def test_a_damaged_target_record_refuses_instead_of_dialling(home: Path) -> None:
    with targets.registry_lock():
        _record, root = targets.new_remote_target("lab", "https", base_url="https://fu.example")
    (root / "target.json").write_bytes(b"{}\n")
    with selection_override(root), pytest.raises(TargetError):
        transport_for_active_root(_never)  # type: ignore[arg-type]


def test_an_unusable_root_is_left_to_the_unix_dial(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from finishup.client import transports
    from finishup.config.paths import PathSafetyError

    def refuse() -> Path:
        raise PathSafetyError("isolation_root_invalid")

    monkeypatch.setattr(transports, "active_root", refuse)
    assert isinstance(transport_for_active_root(_never), UnixTransport)  # type: ignore[arg-type]
    reset_selection_memo()


def _fake_ssh(directory: Path, body: str) -> tuple[str, ...]:
    script = directory / "ssh.py"
    script.write_text(body, encoding="utf-8")
    return (sys.executable, "-I", os.fspath(script))


def test_a_failed_ssh_stream_names_its_phase_and_never_its_text() -> None:
    with tempfile.TemporaryDirectory(prefix="fu-") as raw:
        program = _fake_ssh(
            Path(raw),
            "import sys\n"
            "sys.stderr.write('owner@lab.example: Permission denied (publickey).\\n')\n"
            "sys.exit(255)\n",
        )

        async def exercise() -> str | None:
            stream = await SshTransport(ssh_target(), Path(raw), program=program).connect()
            assert await stream.receive(1024) == b""
            phase = await stream.failure_phase()
            await stream.aclose()
            return phase

        assert asyncio.run(exercise()) == "remote_auth_failed"


def test_a_missing_remote_socket_reads_as_a_service_not_running(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with tempfile.TemporaryDirectory(prefix="fu-") as raw:
        directory = Path(raw)
        (directory / "relay.py").write_text(RELAY_SOURCE, encoding="utf-8")
        monkeypatch.setenv("FU_RELAY_LOG", os.fspath(directory / "relay.log"))
        program = (sys.executable, "-I", os.fspath(directory / "relay.py"))
        target = ssh_target(endpoint=os.fspath(directory / "absent.sock"))

        async def exercise() -> str | None:
            stream = await SshTransport(target, directory, program=program).connect()
            assert await stream.receive(1024) == b""
            return await stream.failure_phase()

        assert asyncio.run(exercise()) == "remote_service_not_running"


def test_closing_an_ssh_stream_stops_only_its_own_child() -> None:
    with tempfile.TemporaryDirectory(prefix="fu-") as raw:
        program = _fake_ssh(Path(raw), "import time\ntime.sleep(60)\n")

        async def exercise() -> int:
            stream = await SshTransport(ssh_target(), Path(raw), program=program).connect()
            pid = stream.pid
            await stream.aclose()
            await stream.aclose()  # idempotent
            return pid

        pid = asyncio.run(exercise())
        with pytest.raises(ProcessLookupError):
            os.kill(pid, 0)


def test_only_an_ssh_target_with_a_launcher_starts_its_remote_service() -> None:
    from dataclasses import replace

    with tempfile.TemporaryDirectory(prefix="fu-") as raw:
        directory = Path(raw)
        log = directory / "argv.json"
        program = _fake_ssh(
            directory,
            f"import json, sys\nopen({os.fspath(log)!r}, 'w').write(json.dumps(sys.argv[1:]))\n",
        )
        ssh = SshTransport(ssh_target(), directory, program=program)
        assert asyncio.run(start_remote_service(ssh, 10.0)) is True
        assert json.loads(log.read_text(encoding="utf-8")) == list(
            ssh_remote_command_argv(
                ssh_target(), directory, ("service", "start", "--json"), program=()
            )
        )
        no_launcher = SshTransport(replace(ssh_target(), remote_launcher=None), directory)
        assert asyncio.run(start_remote_service(no_launcher, 10.0)) is False
        https = HttpsTransport(https_target(), directory)
        assert asyncio.run(start_remote_service(https, 10.0)) is False
        assert asyncio.run(start_remote_service(ssh, 0.0)) is False


def test_the_transport_module_loads_no_network_client() -> None:
    """``httpx``, ``keyring`` and the credential store load only inside an HTTPS dial."""

    source = (
        f"import sys; sys.path.insert(0, {os.fspath(_REPO_SRC)!r})\n"
        "import json, finishup.client.transports, finishup.client.agent_session\n"
        "print(json.dumps(sorted(sys.modules)))\n"
    )
    completed = subprocess.run(  # noqa: S603 - fixed interpreter and in-repository source
        [sys.executable, "-I", "-c", source], capture_output=True, check=True, timeout=60
    )
    loaded = set(json.loads(completed.stdout))
    for module in (
        "httpx",
        "httpcore",
        "keyring",
        "finishup.client.credentials",
        "finishup.client.https_binding",
    ):
        assert module not in loaded
