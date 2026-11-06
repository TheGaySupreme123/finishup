"""Real OpenSSH carries the connector's SSH relay (ADR-051, approach A).

Starts a private ``sshd`` on a free loopback port (key-only, this user, a throwaway host key),
then runs the connector's own master argv through the real ``ssh`` client — ``BatchMode``,
``StrictHostKeyChecking=yes`` against a pinned ``known_hosts``, ``StreamLocalBindMask=0177`` and
the ``-L upstream.sock:<remote endpoint>`` forward — and drives the scripted session through the
connector to a scripted daemon on the "server" socket. The bytes match the in-memory transport.
Skipped where ``ssh``, ``sshd`` or ``ssh-keygen`` is missing, or ``sshd`` cannot start here.

The only stand-in is a two-line ``ssh`` wrapper on ``PATH`` that adds ``-F <test config>``
(identity and ``known_hosts``): OpenSSH reads ``~/.ssh`` from the password database, not
``$HOME``, so a test cannot point it elsewhere any other way.
"""

from __future__ import annotations

import asyncio
import os
import pwd
import shutil
import socket
import subprocess
import tempfile
import time
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

import pytest

from builders.control_relay import ScriptedDaemon, memory_pair, run_scripted_session, serve_unix
from builders.server_targets import ambient_home
from finishup.adapters.control.unix_socket import AuthenticatedUnixStream, authenticate_peer
from finishup.client import targets
from finishup.client.connector import Connector
from finishup.config.paths import selection_override

_TOOLS = ("ssh", "sshd", "ssh-keygen")
pytestmark = pytest.mark.skipif(
    any(shutil.which(tool, path="/usr/sbin:/usr/bin:/sbin:/bin") is None for tool in _TOOLS),
    reason="OpenSSH client, server or ssh-keygen not installed",
)


def _tool(name: str) -> str:
    found = shutil.which(name, path="/usr/sbin:/usr/bin:/sbin:/bin")
    assert found is not None
    return found


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


@pytest.fixture
def sshd(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[Path, int, str]]:
    """``(directory, port, user)`` of a running private sshd and an ssh wrapper on ``PATH``."""

    user = pwd.getpwuid(os.getuid()).pw_name
    real_home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    directory = Path(tempfile.mkdtemp(prefix=".yz-ssh-", dir=real_home))
    directory.chmod(0o700)
    keygen = _tool("ssh-keygen")
    for name in ("host_key", "client_key"):
        subprocess.run(  # noqa: S603 - fixed test argv
            (keygen, "-q", "-t", "ed25519", "-N", "", "-f", str(directory / name)),
            check=True,
        )
    (directory / "authorized_keys").write_bytes((directory / "client_key.pub").read_bytes())
    (directory / "authorized_keys").chmod(0o600)
    port = _free_port()
    (directory / "sshd_config").write_text(
        "\n".join(
            (
                f"Port {port}",
                "ListenAddress 127.0.0.1",
                f"HostKey {directory / 'host_key'}",
                f"AuthorizedKeysFile {directory / 'authorized_keys'}",
                f"PidFile {directory / 'sshd.pid'}",
                "PubkeyAuthentication yes",
                "PasswordAuthentication no",
                "KbdInteractiveAuthentication no",
                "UsePAM no",
                "StrictModes no",
                "PermitRootLogin prohibit-password",
                "AllowStreamLocalForwarding yes",
                "StreamLocalBindUnlink yes",
                "LogLevel ERROR",
                "",
            )
        ),
        encoding="utf-8",
    )
    server = subprocess.Popen(  # noqa: S603 - fixed test argv
        (_tool("sshd"), "-D", "-e", "-f", str(directory / "sshd_config")),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 10
        while True:
            if server.poll() is not None:
                pytest.skip("sshd cannot run in this environment")
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                if time.monotonic() > deadline:
                    pytest.skip("sshd did not start listening")
                time.sleep(0.05)
        host_key = (directory / "host_key.pub").read_text(encoding="utf-8").split()
        (directory / "known_hosts").write_text(
            f"[127.0.0.1]:{port} {host_key[0]} {host_key[1]}\n", encoding="utf-8"
        )
        (directory / "ssh_config").write_text(
            "\n".join(
                (
                    "Host *",
                    f"  IdentityFile {directory / 'client_key'}",
                    "  IdentitiesOnly yes",
                    f"  UserKnownHostsFile {directory / 'known_hosts'}",
                    "  GlobalKnownHostsFile /dev/null",
                    "",
                )
            ),
            encoding="utf-8",
        )
        bin_dir = directory / "bin"
        bin_dir.mkdir(mode=0o700)
        wrapper = bin_dir / "ssh"
        wrapper.write_text(
            f'#!/bin/sh\nexec {_tool("ssh")} -F {directory / "ssh_config"} "$@"\n',
            encoding="utf-8",
        )
        wrapper.chmod(0o700)
        yield directory, port, user
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()
        shutil.rmtree(directory, ignore_errors=True)


def test_real_openssh_forwards_the_connector_session_byte_for_byte(
    sshd: tuple[Path, int, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    directory, port, user = sshd

    async def reference() -> list[bytes]:
        daemon = ScriptedDaemon()
        client, server = memory_pair()
        served = asyncio.create_task(daemon.serve(server))
        received = await run_scripted_session(client)
        await client.aclose()
        await served
        return received

    expected = asyncio.run(reference())

    with ambient_home(monkeypatch):
        with targets.registry_lock():
            record, root = targets.new_remote_target(
                "lab",
                "ssh",
                user=user,
                host="127.0.0.1",
                port=port,
                remote_launcher="/bin/true",
            )
        endpoint = directory / "d.sock"
        record = replace(record, remote_endpoint=str(endpoint))

        async def exercise() -> list[bytes]:
            daemon = ScriptedDaemon()
            server = await serve_unix(endpoint, daemon)
            connector = Connector(root, record, ssh=str(directory / "bin" / "ssh"))
            left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
            client = AuthenticatedUnixStream(left, authenticate_peer(left))
            local = AuthenticatedUnixStream(right, authenticate_peer(right))
            relay = asyncio.create_task(connector._serve_local(local))  # pyright: ignore[reportPrivateUsage]
            try:
                async with asyncio.timeout(30):
                    received = await run_scripted_session(client)
                    await client.shutdown_write()
                    await relay
                upstream = root / "run" / "upstream.sock"
                assert upstream.stat().st_mode & 0o777 == 0o600
                assert daemon.replies and daemon.connections == 1
                return received
            finally:
                await client.aclose()
                await connector._ssh.close()  # pyright: ignore[reportPrivateUsage,reportOptionalMemberAccess]
                server.cancel()
                await asyncio.gather(server, return_exceptions=True)

        with selection_override(root):
            received = asyncio.run(exercise())
        assert received == expected
        assert not (root / "run" / "m").exists()
