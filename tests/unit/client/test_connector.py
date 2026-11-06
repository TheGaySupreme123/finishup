"""The connector process: refusals, the SSH restart-once path, status, claims, idle exit."""

from __future__ import annotations

import asyncio
import os
import socket
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

import pytest

from builders.control_relay import (
    CLAIM_DIGEST,
    ScriptedDaemon,
    run_scripted_session,
)
from builders.server_targets import ambient_home
from finishup.adapters.control.unix_socket import (
    AuthenticatedUnixStream,
    authenticate_peer,
    bind_control_listener,
    connect_control,
)
from finishup.client import targets
from finishup.client.connector import Connector, run_connector
from finishup.client.connector_status import read_connector_status
from finishup.client.ssh_upstream import UpstreamUnavailable
from finishup.config.paths import ISOLATED_ROOT_ENV_NAMES, selection_override
from finishup.ports.control import WorkspaceClaim
from finishup.protocol.canonical import JsonValue
from finishup.protocol.schemas import load_schema_catalog
from finishup.service.control_protocol import encode_control_frame


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as root:
        yield root


def _ssh_target(home: Path) -> tuple[targets.ServerTarget, Path]:
    with targets.registry_lock():
        record, root = targets.new_remote_target(
            "lab", "ssh", host="lab.example", port=22, remote_launcher="/opt/fu/bin/finishup"
        )
    return replace(record, remote_endpoint=str(home / "remote.sock")), root


def _pair() -> tuple[AuthenticatedUnixStream, AuthenticatedUnixStream]:
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    return (
        AuthenticatedUnixStream(left, authenticate_peer(left)),
        AuthenticatedUnixStream(right, authenticate_peer(right)),
    )


class _StubMaster:
    """Stands in for the OpenSSH master: the test serves ``run/upstream.sock`` itself."""

    def __init__(self, root: Path, *, restarts: list[str], start_ok: bool = True) -> None:
        self.upstream_path = root / "run" / "upstream.sock"
        self.restarts = restarts
        self.start_ok = start_ok
        self.failure: str | None = None

    async def ensure(self) -> None:
        if self.failure is not None:
            raise UpstreamUnavailable(self.failure)

    async def run_remote(self, *arguments: str) -> int:
        self.restarts.append(" ".join(arguments))
        return 0 if self.start_ok else 1

    async def close(self) -> None:
        return None


async def _serve_upstream(
    path: Path, daemon: ScriptedDaemon, started: list[bool]
) -> asyncio.Task[None]:
    """``upstream.sock`` as sshd would forward it: closed at once until the service started."""

    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    previous = os.umask(0o177)
    try:
        listener.bind(str(path))
    finally:
        os.umask(previous)
    listener.listen(8)
    listener.setblocking(False)
    loop = asyncio.get_running_loop()

    async def accept() -> None:
        tasks: set[asyncio.Task[None]] = set()
        try:
            while True:
                accepted, _ = await loop.sock_accept(listener)
                if not started[0]:
                    accepted.close()
                    continue
                stream = AuthenticatedUnixStream(accepted, authenticate_peer(accepted))
                task = asyncio.create_task(daemon.serve(stream))
                tasks.add(task)
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            listener.close()

    return asyncio.create_task(accept())


def _hello(**extra: JsonValue) -> bytes:
    hello: dict[str, JsonValue] = {
        "protocol_version": "1.0",
        "client_kind": "cli",
        "client_version": "0.1.0",
        "connection_nonce": "3d" * 32,
        "schema_manifest_digest": load_schema_catalog().manifest_digest,
        **extra,
    }
    return encode_control_frame(hello)


async def _closed_unanswered(stream: AuthenticatedUnixStream) -> bool:
    async with asyncio.timeout(5):
        return await stream.receive(65_536) == b""


def test_a_hello_naming_a_local_path_never_leaves_this_machine(home: Path) -> None:
    record, root = _ssh_target(home)

    async def exercise() -> None:
        connector = Connector(root, record)
        restarts: list[str] = []
        master = _StubMaster(root, restarts=restarts)
        master.failure = "remote_unreachable"  # any upstream contact would be recorded
        connector._ssh = master  # type: ignore[assignment]  # pyright: ignore[reportPrivateUsage]
        client, local = _pair()
        serving = asyncio.create_task(connector._serve_local(local))  # pyright: ignore[reportPrivateUsage]
        await client.send_all(
            _hello(workspace_locator={"schema_version": "1.0.0", "path": "/home/owner/repo"})
        )
        assert await _closed_unanswered(client)
        await serving
        assert read_connector_status(root) is None  # nothing was attempted upstream

    with selection_override(root):
        asyncio.run(exercise())


def test_ssh_restarts_an_idle_stopped_service_once_then_relays(home: Path) -> None:
    record, root = _ssh_target(home)

    async def exercise() -> None:
        daemon = ScriptedDaemon()
        started = [False]
        restarts: list[str] = []
        master = _StubMaster(root, restarts=restarts)

        async def start_service(*arguments: str) -> int:
            restarts.append(" ".join(arguments))
            started[0] = True
            return 0

        master.run_remote = start_service  # type: ignore[method-assign]
        upstream = await _serve_upstream(master.upstream_path, daemon, started)
        connector = Connector(root, record)
        connector._ssh = master  # type: ignore[assignment]  # pyright: ignore[reportPrivateUsage]
        client, local = _pair()
        serving = asyncio.create_task(connector._serve_local(local))  # pyright: ignore[reportPrivateUsage]
        received = await run_scripted_session(client, agent=False)
        await client.shutdown_write()
        async with asyncio.timeout(5):
            await serving
        upstream.cancel()
        await asyncio.gather(upstream, return_exceptions=True)
        assert restarts == ["service start"]
        assert len(received) == 9
        status = read_connector_status(root)
        assert status is not None and status.phase == "ready"

    with selection_override(root):
        asyncio.run(exercise())


def test_a_service_that_stays_down_is_named_and_the_client_can_read_why(home: Path) -> None:
    record, root = _ssh_target(home)

    async def exercise() -> None:
        restarts: list[str] = []
        master = _StubMaster(root, restarts=restarts, start_ok=False)
        upstream = await _serve_upstream(master.upstream_path, ScriptedDaemon(), [False])
        connector = Connector(root, record)
        connector._ssh = master  # type: ignore[assignment]  # pyright: ignore[reportPrivateUsage]
        client, local = _pair()
        serving = asyncio.create_task(connector._serve_local(local))  # pyright: ignore[reportPrivateUsage]
        await client.send_all(_hello())
        assert await _closed_unanswered(client)
        await serving
        upstream.cancel()
        await asyncio.gather(upstream, return_exceptions=True)
        assert restarts == ["service start"]
        status = read_connector_status(root)
        assert status is not None
        assert (status.phase, status.reason) == ("unavailable", "remote_service_not_running")
        assert status.correlation_id is not None and status.correlation_id.startswith("err_")

    with selection_override(root):
        asyncio.run(exercise())


def test_an_unreachable_server_is_recorded_with_a_closed_reason_only(home: Path) -> None:
    record, root = _ssh_target(home)

    async def exercise() -> None:
        master = _StubMaster(root, restarts=[])
        master.failure = "remote_auth_failed"
        connector = Connector(root, record)
        connector._ssh = master  # type: ignore[assignment]  # pyright: ignore[reportPrivateUsage]
        client, local = _pair()
        serving = asyncio.create_task(connector._serve_local(local))  # pyright: ignore[reportPrivateUsage]
        await client.send_all(_hello())
        assert await _closed_unanswered(client)
        await serving
        status_bytes = (root / "state" / "connector-status.json").read_bytes()
        assert b"lab.example" not in status_bytes and b"remote_auth_failed" in status_bytes

    with selection_override(root):
        asyncio.run(exercise())


def test_each_claimed_workspace_gets_one_background_agent_lease(home: Path) -> None:
    record, root = _ssh_target(home)
    opened: list[WorkspaceClaim] = []

    class _Agent:
        alive = True

        async def aclose(self) -> None:
            self.alive = False

    async def opener(_root: Path, claim: WorkspaceClaim) -> _Agent:
        opened.append(claim)
        return _Agent()

    async def exercise() -> None:
        connector = Connector(root, record, agent_opener=opener)
        claim = WorkspaceClaim(identity_kind="directory", digest=CLAIM_DIGEST)
        await connector._observe_claim(claim)  # pyright: ignore[reportPrivateUsage]
        await connector._observe_claim(claim)  # pyright: ignore[reportPrivateUsage]
        assert [item.digest for item in opened] == [CLAIM_DIGEST]
        lease = connector._claims[CLAIM_DIGEST]  # pyright: ignore[reportPrivateUsage]
        lease.last_seen -= 10_000
        await connector._expire_claims()  # pyright: ignore[reportPrivateUsage]
        assert connector._claims == {}  # pyright: ignore[reportPrivateUsage]

    with selection_override(root):
        asyncio.run(exercise())


def test_an_idle_connector_stops_and_removes_its_endpoint(home: Path) -> None:
    record, root = _ssh_target(home)
    drained: list[Path] = []

    async def drainer(target: Path) -> None:
        drained.append(target)

    async def exercise() -> None:
        listener = await bind_control_listener()
        connector = Connector(root, record, idle_seconds=0.3, drainer=drainer, drain_interval=0.05)
        master = _StubMaster(root, restarts=[])
        master.failure = "remote_unreachable"
        connector._ssh = master  # type: ignore[assignment]  # pyright: ignore[reportPrivateUsage]
        async with asyncio.timeout(10):
            reason = await connector.serve(listener)
        assert reason == "idle_timeout"
        assert not (root / "run" / "control.sock").exists()
        status = read_connector_status(root)
        assert status is not None and (status.phase, status.reason) == ("stopped", "idle_timeout")
        with pytest.raises(Exception):
            await connect_control()
        # The client-captured outbox is drained while it runs and once more as it stops.
        assert len(drained) >= 2 and set(drained) == {root}

    with selection_override(root):
        asyncio.run(exercise())


def test_the_connector_command_serves_only_a_remote_targets_own_root(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    record, root = _ssh_target(home)
    del record
    assert run_connector(Path("relative")) == 2
    assert run_connector(home) == 2  # not a target root
    with targets.registry_lock():
        _local, local_root = targets.new_local_target("work")
    assert run_connector(local_root) == 2  # a named local server has its own service
    other = home / "explicit"
    other.mkdir(mode=0o700)
    monkeypatch.setenv(ISOLATED_ROOT_ENV_NAMES[0], str(other))
    assert run_connector(root) == 2
