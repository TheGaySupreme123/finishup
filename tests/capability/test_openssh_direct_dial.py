"""Platform evidence: the direct-dial SSH transport against a real OpenSSH server.

A private ``sshd`` (its own host key, authorized key and port on 127.0.0.1) serves this user.
``SshTransport`` runs its production argv, with only ``-F <private client config>`` in front so
the test never reads or writes the owner's own ``~/.ssh``:

* ``ssh -W <unix socket>`` carries the scripted control session byte for byte (the same bytes an
  in-memory pair carries), so stream-local forwarding needs no ``attach-stdio`` helper;
* the first stream leaves a ``ControlPersist`` master that later streams reuse, and the runtime
  stops exactly that master by its control path;
* a missing remote socket, an unknown host key and a refused client key end as the closed phases
  ``remote_service_not_running``, ``remote_identity_changed`` and ``remote_auth_failed``.

Skipped where OpenSSH's client, server or key generator is not installed.
"""

from __future__ import annotations

import asyncio
import getpass
import os
import shutil
import socket
import subprocess
import time
from collections.abc import Iterator
from dataclasses import dataclass, replace
from pathlib import Path
from typing import cast

import pytest

from builders.direct_dial import (
    memory_pair,
    pinned_nonce,
    scripted_client,
    scripted_server,
    ssh_target,
)
from finishup.adapters.control.unix_socket import AuthenticatedUnixStream, authenticate_peer
from finishup.client.direct_runtime import SshTargetRuntime
from finishup.client.targets import ServerTarget, write_target
from finishup.client.transports import SshTransport, ssh_control_argv

_SSHD = shutil.which("sshd") or ("/usr/sbin/sshd" if Path("/usr/sbin/sshd").exists() else None)
pytestmark = pytest.mark.skipif(
    _SSHD is None or shutil.which("ssh") is None or shutil.which("ssh-keygen") is None,
    reason="OpenSSH client, server and ssh-keygen are required",
)


@dataclass(frozen=True)
class _Server:
    directory: Path
    port: int
    config: Path

    def program(self, config: Path | None = None) -> tuple[str, ...]:
        return ("ssh", "-F", os.fspath(config or self.config))

    def target(self, endpoint: Path) -> ServerTarget:
        return replace(
            ssh_target(endpoint=os.fspath(endpoint)),
            user=getpass.getuser(),
            host="127.0.0.1",
            port=self.port,
            remote_launcher=None,
        )


def _keygen(path: Path) -> None:
    subprocess.run(  # noqa: S603 - fixed ssh-keygen argv
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", os.fspath(path)],
        check=True,
        capture_output=True,
        timeout=30,
    )


def _client_config(directory: Path, name: str, key: Path, known_hosts: Path) -> Path:
    config = directory / name
    config.write_text(
        "Host *\n"
        f"  IdentityFile {key}\n"
        "  IdentitiesOnly yes\n"
        "  IdentityAgent none\n"
        f"  UserKnownHostsFile {known_hosts}\n"
        "  GlobalKnownHostsFile /dev/null\n"
        "  LogLevel ERROR\n",
        encoding="utf-8",
    )
    config.chmod(0o600)
    return config


@pytest.fixture
def server(tmp_path: Path) -> Iterator[_Server]:
    directory = tmp_path
    for name in ("host_key", "client_key", "other_key"):
        _keygen(directory / name)
    (directory / "authorized_keys").write_bytes((directory / "client_key.pub").read_bytes())
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    sshd_config = directory / "sshd_config"
    sshd_config.write_text(
        f"Port {port}\n"
        "ListenAddress 127.0.0.1\n"
        f"HostKey {directory / 'host_key'}\n"
        f"PidFile {directory / 'sshd.pid'}\n"
        f"AuthorizedKeysFile {directory / 'authorized_keys'}\n"
        "PasswordAuthentication no\n"
        "KbdInteractiveAuthentication no\n"
        "PubkeyAuthentication yes\n"
        "PermitRootLogin prohibit-password\n"
        "StrictModes no\n"
        "UsePAM no\n"
        "AllowStreamLocalForwarding yes\n"
        "LogLevel ERROR\n",
        encoding="utf-8",
    )
    host_key = (directory / "host_key.pub").read_text(encoding="ascii").split()
    known = directory / "known_hosts"
    known.write_text(f"[127.0.0.1]:{port} {host_key[0]} {host_key[1]}\n", encoding="ascii")
    config = _client_config(directory, "ssh_config", directory / "client_key", known)
    daemon = subprocess.Popen(  # noqa: S603 - the located sshd with a private configuration
        [cast(str, _SSHD), "-D", "-e", "-f", os.fspath(sshd_config)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        deadline = time.monotonic() + 10
        while True:
            if daemon.poll() is not None:
                pytest.skip("a private sshd cannot run here")
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                if time.monotonic() > deadline:
                    pytest.skip("a private sshd did not start")
                time.sleep(0.05)
        yield _Server(directory, port, config)
    finally:
        # Every master a test left (even a failing one), by its own control path; then only the
        # sshd this fixture spawned, by its own pid.
        for master in directory.glob("*/run/m"):
            subprocess.run(  # noqa: S603 - fixed ssh argv naming this test's own control path
                [
                    "ssh",
                    "-F",
                    os.fspath(config),
                    "-S",
                    os.fspath(master),
                    "-O",
                    "exit",
                    "-p",
                    str(port),
                    f"{getpass.getuser()}@127.0.0.1",
                ],
                capture_output=True,
                timeout=30,
                check=False,
            )
        daemon.terminate()
        try:
            daemon.wait(timeout=5)
        except subprocess.TimeoutExpired:
            daemon.kill()
            daemon.wait(timeout=5)
        if daemon.stderr is not None:
            daemon.stderr.close()


async def _session_over(transport: SshTransport, endpoint: Path) -> tuple[list[str], bytes]:
    from builders.direct_dial import TapStream

    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(os.fspath(endpoint))
    listener.listen(1)
    listener.setblocking(False)
    try:
        accepting = asyncio.ensure_future(asyncio.get_running_loop().sock_accept(listener))
        client = TapStream(await transport.connect())
        connection, _address = await asyncio.wait_for(accepting, 15)
        server = AuthenticatedUnixStream(connection, authenticate_peer(connection))
        serving = asyncio.create_task(scripted_server(server, server.peer_identity))
        kinds = await scripted_client(client)
        await client.aclose()
        await asyncio.wait_for(serving, 10)
        await server.aclose()
        return kinds, bytes(client.received)
    finally:
        listener.close()
        endpoint.unlink(missing_ok=True)


async def _baseline() -> bytes:
    from builders.direct_dial import TapStream

    client_end, server_end = memory_pair()
    client = TapStream(client_end)
    serving = asyncio.create_task(scripted_server(server_end, server_end.peer_identity))
    await scripted_client(client)
    await client.aclose()
    await serving
    return bytes(client.received)


def test_real_ssh_carries_the_session_over_a_persistent_master(
    server: _Server, monkeypatch: pytest.MonkeyPatch
) -> None:
    endpoint = server.directory / "c.sock"
    target = server.target(endpoint)
    # A real target root: named by the target id and holding its record, as ``server add`` makes.
    root = server.directory / target.target_id
    root.mkdir(mode=0o700)
    (root / "run").mkdir(mode=0o700)
    write_target(root, target)
    transport = SshTransport(target, root, program=server.program())
    with pinned_nonce(monkeypatch):
        baseline = asyncio.run(_baseline())
        kinds, received = asyncio.run(_session_over(transport, endpoint))
        assert received == baseline
        assert kinds[-1] == "result:rpc_00000000-0000-4000-8000-000000000004"

        check = ssh_control_argv(target, root, "check", program=server.program())
        assert subprocess.run(check, capture_output=True, timeout=30).returncode == 0  # noqa: S603

        started = time.monotonic()
        _kinds, again = asyncio.run(_session_over(transport, endpoint))
        reused_seconds = time.monotonic() - started
        assert again == baseline
        assert reused_seconds < 10

    SshTargetRuntime(program=server.program()).stop(root)
    assert subprocess.run(check, capture_output=True, timeout=30).returncode != 0  # noqa: S603


def _phase(transport: SshTransport) -> str | None:
    async def exercise() -> str | None:
        stream = await transport.connect()
        try:
            assert await asyncio.wait_for(stream.receive(1024), 30) == b""
            return await stream.failure_phase()
        finally:
            await stream.aclose()

    return asyncio.run(exercise())


def test_real_ssh_failures_are_closed_phases(server: _Server) -> None:
    directory = server.directory
    absent = server.target(directory / "absent.sock")
    no_master = directory / "solo"
    (no_master / "run").mkdir(parents=True, mode=0o700)

    assert (
        _phase(SshTransport(absent, no_master, program=server.program()))
        == "remote_service_not_running"
    )

    empty = directory / "empty_known_hosts"
    empty.write_text("", encoding="ascii")
    unknown_host = _client_config(directory, "unknown_host", directory / "client_key", empty)
    fresh = directory / "fresh"
    (fresh / "run").mkdir(parents=True, mode=0o700)
    assert (
        _phase(SshTransport(absent, fresh, program=server.program(unknown_host)))
        == "remote_identity_changed"
    )

    wrong_key = _client_config(
        directory, "wrong_key", directory / "other_key", directory / "known_hosts"
    )
    assert (
        _phase(SshTransport(absent, fresh, program=server.program(wrong_key)))
        == "remote_auth_failed"
    )
    # The authenticated attempt left a master behind; stop it by its own control path.
    exit_argv = ssh_control_argv(absent, no_master, "exit", program=server.program())
    subprocess.run(exit_argv, capture_output=True, timeout=30, check=False)  # noqa: S603
