"""The connector process: refusals, the SSH restart-once path, status, claims, idle exit."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import os
import socket
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

import pytest

from builders.control_relay import (
    CLAIM_DIGEST,
    WORKTREE_DIGEST,
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
from finishup.ports.control import WorkspaceClaim, WorkspaceLocator
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
            _hello(workspace_locator={"schema_version": "1.0.0", "path": "/srv/owner/repo"})
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


def test_a_background_agent_never_starts_a_stopped_remote_service(home: Path) -> None:
    """The owner stopped the server's service; only a client's connection may start it again."""

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
        try:
            # The connector's own background agent reconnects: nothing is started.
            agent = await connector._dial_own()  # pyright: ignore[reportPrivateUsage]
            await agent.send_all(_hello())
            assert await _closed_unanswered(agent)
            await agent.aclose()
            assert restarts == []
            status = read_connector_status(root)
            assert status is not None
            assert (status.phase, status.reason) == ("unavailable", "remote_service_not_running")
            # A client's connection is demand: the service is started once and relayed.
            client, local = _pair()
            serving = asyncio.create_task(connector._serve_local(local))  # pyright: ignore[reportPrivateUsage]
            received = await run_scripted_session(client, agent=False)
            await client.shutdown_write()
            async with asyncio.timeout(5):
                await serving
            assert restarts == ["service start"]
            assert len(received) == 9
        finally:
            upstream.cancel()
            await asyncio.gather(upstream, return_exceptions=True)

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


class _Agent:
    """A background agent stand-in that records its drains and its close."""

    def __init__(self) -> None:
        self.alive = True
        self.drains = 0

    async def drain(self) -> None:
        self.drains += 1

    async def aclose(self) -> None:
        self.alive = False


def test_each_claimed_workspace_gets_one_background_agent_lease(home: Path) -> None:
    record, root = _ssh_target(home)
    opened: list[WorkspaceClaim] = []

    async def opener(_root: Path, claim: WorkspaceClaim, _dial: object) -> _Agent:
        opened.append(claim)
        return _Agent()

    async def exercise() -> None:
        connector = Connector(root, record, agent_opener=opener)
        claim = WorkspaceClaim(
            identity_kind="directory", digest=CLAIM_DIGEST, worktree=WORKTREE_DIGEST
        )
        await connector._observe_claim(claim)  # pyright: ignore[reportPrivateUsage]
        await connector._observe_claim(claim)  # pyright: ignore[reportPrivateUsage]
        assert [item.digest for item in opened] == [CLAIM_DIGEST]
        # A linked worktree of the same repository shares its digest and gets its own agent.
        linked = WorkspaceClaim(
            identity_kind="directory", digest=CLAIM_DIGEST, worktree="sha256:" + "0e" * 32
        )
        await connector._observe_claim(linked)  # pyright: ignore[reportPrivateUsage]
        assert opened == [claim, linked]
        connector._claims.pop(linked)  # pyright: ignore[reportPrivateUsage]
        lease = connector._claims[claim]  # pyright: ignore[reportPrivateUsage]
        lease.last_seen -= 10_000
        await connector._expire_claims()  # pyright: ignore[reportPrivateUsage]
        assert connector._claims == {}  # pyright: ignore[reportPrivateUsage]

    with selection_override(root):
        asyncio.run(exercise())


def test_an_idle_connector_stops_and_removes_its_endpoint(home: Path) -> None:
    record, root = _ssh_target(home)
    agent = _Agent()

    async def opener(_root: Path, _claim: WorkspaceClaim, _dial: object) -> _Agent:
        return agent

    async def exercise() -> None:
        listener = await bind_control_listener()
        connector = Connector(
            root, record, idle_seconds=0.3, agent_opener=opener, drain_interval=0.05
        )
        await connector._observe_claim(  # pyright: ignore[reportPrivateUsage]
            WorkspaceClaim(identity_kind="directory", digest=CLAIM_DIGEST, worktree=WORKTREE_DIGEST)
        )
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
        # Each leased workspace's captures are delivered while it runs and once more as it
        # stops, before its background agent is closed.
        assert agent.drains >= 2
        assert agent.alive is False

    with selection_override(root):
        asyncio.run(exercise())


def test_a_stop_is_not_held_up_by_a_slow_last_delivery(home: Path) -> None:
    """``server disconnect`` and ``server remove`` wait 5 seconds for the connector's lock; the
    last delivery over a degraded network must not outlast that."""

    import time

    record, root = _ssh_target(home)

    class _SlowAgent(_Agent):
        async def drain(self) -> None:
            self.drains += 1
            await asyncio.sleep(60)  # an ingest stuck on a degraded network

    agent = _SlowAgent()

    async def opener(_root: Path, _claim: WorkspaceClaim, _dial: object) -> _Agent:
        return agent

    async def exercise() -> float:
        listener = await bind_control_listener()
        connector = Connector(root, record, agent_opener=opener, drain_interval=3_600)
        await connector._observe_claim(  # pyright: ignore[reportPrivateUsage]
            WorkspaceClaim(identity_kind="directory", digest=CLAIM_DIGEST, worktree=WORKTREE_DIGEST)
        )
        master = _StubMaster(root, restarts=[])
        connector._ssh = master  # type: ignore[assignment]  # pyright: ignore[reportPrivateUsage]
        serving = asyncio.create_task(connector.serve(listener))
        await asyncio.sleep(0.1)
        started = time.monotonic()
        connector.request_stop()
        async with asyncio.timeout(10):
            assert await serving == "stop_requested"
        return time.monotonic() - started

    with selection_override(root):
        elapsed = asyncio.run(exercise())
    assert agent.drains == 1 and agent.alive is False
    assert elapsed < 4.0


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


def test_a_background_agent_still_opening_is_held_and_ended_when_the_connector_stops(
    home: Path,
) -> None:
    """A relayed claim opens its workspace's background agent beside the client's relay. The
    loop keeps only a weak reference to that task, so the connector holds it, and ``serve``
    cancels and awaits it as it stops instead of leaving it running."""

    record, root = _ssh_target(home)
    ended: list[str] = []

    async def exercise() -> None:
        opening = asyncio.Event()
        never = asyncio.Event()

        async def opener(_root: Path, _claim: WorkspaceClaim, _dial: object) -> _Agent:
            opening.set()
            try:
                await never.wait()  # a server slow to answer the agent's hello
            except asyncio.CancelledError:
                ended.append("cancelled")
                raise
            return _Agent()

        listener = await bind_control_listener()
        connector = Connector(root, record, agent_opener=opener)
        master = _StubMaster(root, restarts=[])
        master.failure = "remote_unreachable"
        connector._ssh = master  # type: ignore[assignment]  # pyright: ignore[reportPrivateUsage]
        serving = asyncio.create_task(connector.serve(listener))
        client = await connect_control()
        claim: dict[str, JsonValue] = {
            "schema_version": "1.0.0",
            "identity_kind": "directory",
            "digest": CLAIM_DIGEST,
            "worktree": WORKTREE_DIGEST,
        }
        await client.send_all(_hello(workspace_claim=claim))
        async with asyncio.timeout(5):
            await opening.wait()
        connector.request_stop()
        async with asyncio.timeout(10):
            assert await serving == "stop_requested"
        assert ended == ["cancelled"]
        await client.aclose()

    with selection_override(root):
        asyncio.run(exercise())


def test_a_background_agent_reads_the_folders_of_its_own_target(home: Path, tmp_path: Path) -> None:
    """ADR-051 decision 5: the agent the connector opens for a relayed claim admits the folders
    the owner recorded for the connector's own target, never another target's, and keeps that
    record when this process's selection later names another target."""

    from finishup.client.claimed_workspaces import record_claimed_workspace
    from finishup.client.connector import open_background_agent
    from finishup.client.connector_agent import ConnectorAgent
    from finishup.client.server_folders import add_folder
    from finishup.client.workspace_agent import WorkspaceAgentHandler
    from finishup.client.workspace_claim import workspace_claim

    record, root = _ssh_target(home)
    with targets.registry_lock():
        other, other_root = targets.new_remote_target("gw", "https", base_url="https://gw.example")
    admitted: list[str] = []
    for target, folder in ((record, tmp_path / "mine"), (other, tmp_path / "theirs")):
        folder.mkdir()
        admitted.append(os.fspath(folder.resolve(strict=True)))
        add_folder(targets.target_root(target.target_id), target.target_id, admitted[-1])
    (tmp_path / "workspace").mkdir()
    workspace = WorkspaceLocator(os.fspath((tmp_path / "workspace").resolve(strict=True)))

    async def exercise() -> None:
        salt = base64.b64decode(record.claim_salt or "", validate=True)
        claim = await workspace_claim(workspace, salt)
        assert record_claimed_workspace(root, claim, workspace) is True
        never = asyncio.Event()

        async def dial() -> AuthenticatedUnixStream:
            await never.wait()  # no server answers: the agent's handler is what is checked
            raise AssertionError("unreachable")

        agent = await open_background_agent(root, claim, dial)
        assert isinstance(agent, ConnectorAgent)
        try:
            handler = agent._binding.agent  # pyright: ignore[reportPrivateUsage]
            assert type(handler) is WorkspaceAgentHandler
            outside = handler._outside  # pyright: ignore[reportPrivateUsage]
            assert outside().folders == (admitted[0],)
            with selection_override(other_root):
                assert outside().folders == (admitted[0],)
        finally:
            await agent.aclose()

    with selection_override(root):
        asyncio.run(exercise())


# -- zero-network (ADR-051 decision 8, maintainer decision of 2026-11-07) ----------------------
#
# This computer's zero-network policy and a server elsewhere are never in force together. The
# connector is the last line of defence for everything already running: it reads the same record
# as every connection check and refuses, stops, and delivers nothing once it says zero-network.

_ZERO_NETWORK = "zero_network_remote_selected"


async def _refused(stream: AuthenticatedUnixStream) -> bool:
    """Closed with no byte answered: an end of stream, or a reset (the hello went unread)."""

    from finishup.adapters.control.unix_socket import LocalControlTransportError

    try:
        return await _closed_unanswered(stream)
    except LocalControlTransportError:
        return True


async def _until_ready(root: Path) -> None:
    async with asyncio.timeout(5):
        while (status := read_connector_status(root)) is None or status.phase != "ready":
            await asyncio.sleep(0.01)


def test_a_running_connector_stops_within_a_tick_once_this_computer_reports_zero_network(
    home: Path,
) -> None:
    from finishup.client import everyday_policy

    record, root = _ssh_target(home)
    agent = _Agent()

    async def opener(_root: Path, _claim: WorkspaceClaim, _dial: object) -> _Agent:
        return agent

    async def exercise() -> str:
        listener = await bind_control_listener()
        # No delivery is due while it runs: any delivery seen is the last one, made as it stops.
        connector = Connector(root, record, agent_opener=opener, drain_interval=3_600)
        await connector._observe_claim(  # pyright: ignore[reportPrivateUsage]
            WorkspaceClaim(identity_kind="directory", digest=CLAIM_DIGEST, worktree=WORKTREE_DIGEST)
        )
        connector._ssh = _StubMaster(root, restarts=[])  # type: ignore[assignment]  # pyright: ignore[reportPrivateUsage]
        serving = asyncio.create_task(connector.serve(listener))
        await _until_ready(root)
        assert everyday_policy.record_reported_policy(zero_network=True) is True
        # It stops on its own (the idle stop is 15 minutes away): within a tick, not a lease.
        async with asyncio.timeout(5):
            return await serving

    with selection_override(root):
        reason = asyncio.run(exercise())
    assert reason == _ZERO_NETWORK
    status = read_connector_status(root)
    assert status is not None and (status.phase, status.reason) == ("stopped", _ZERO_NETWORK)
    # Its background agent is closed, and nothing was delivered on the way out.
    assert agent.alive is False and agent.drains == 0
    assert not (root / "run" / "control.sock").exists()


def test_nothing_is_relayed_for_a_client_or_an_agent_while_zero_network(home: Path) -> None:
    from finishup.adapters.control.unix_socket import LocalControlTransportError
    from finishup.client import everyday_policy
    from finishup.service import client as service_client

    record, root = _ssh_target(home)
    assert everyday_policy.record_reported_policy(zero_network=True) is True

    async def exercise() -> ScriptedDaemon:
        daemon = ScriptedDaemon()
        master = _StubMaster(root, restarts=[])
        upstream = await _serve_upstream(master.upstream_path, daemon, [True])
        connector = Connector(root, record)
        connector._ssh = master  # type: ignore[assignment]  # pyright: ignore[reportPrivateUsage]
        try:
            # A background agent's own connection (it bypasses the endpoint)...
            agent = await connector._dial_own()  # pyright: ignore[reportPrivateUsage]
            with contextlib.suppress(LocalControlTransportError):
                await agent.send_all(_hello())
            assert await _refused(agent)
            await agent.aclose()
            # ...and a client's connection through the endpoint, as an older process would dial.
            local, theirs = _pair()
            serving = asyncio.create_task(
                connector._serve_local(theirs)  # pyright: ignore[reportPrivateUsage]
            )
            with contextlib.suppress(LocalControlTransportError):
                await local.send_all(_hello())
            assert await _refused(local)
            await serving
            await local.aclose()
            # The connector asked itself to stop for it.
            assert connector._stop.is_set()  # pyright: ignore[reportPrivateUsage]
            assert connector._stop_reason == _ZERO_NETWORK  # pyright: ignore[reportPrivateUsage]
        finally:
            upstream.cancel()
            await asyncio.gather(upstream, return_exceptions=True)
        return daemon

    with selection_override(root):
        daemon = asyncio.run(exercise())
        # The client whose connection closed unanswered names why, and the one remedy follows.
        failure = service_client._remote_failure(root)  # pyright: ignore[reportPrivateUsage]
    assert daemon.connections == 0
    assert (failure.reason, failure.phase, failure.retryable) == (
        "service_unavailable",
        _ZERO_NETWORK,
        True,
    )
    status = read_connector_status(root)
    assert status is not None and (status.phase, status.reason) == ("unavailable", _ZERO_NETWORK)


def test_a_stopped_connectors_zero_network_status_still_names_the_phase(home: Path) -> None:
    from finishup.client.connector_status import new_status, now_stamp, write_connector_status
    from finishup.service import client as service_client

    _record, root = _ssh_target(home)
    write_connector_status(root, new_status(None, "stopped", _ZERO_NETWORK, started_at=now_stamp()))
    with selection_override(root):
        failure = service_client._remote_failure(root)  # pyright: ignore[reportPrivateUsage]
    assert failure.phase == _ZERO_NETWORK
    # Any other stop names no phase: the client says the server could not be reached.
    write_connector_status(
        root, new_status(None, "stopped", "idle_timeout", started_at=now_stamp())
    )
    with selection_override(root):
        failure = service_client._remote_failure(root)  # pyright: ignore[reportPrivateUsage]
    assert failure.phase is None


def test_a_background_agent_opened_before_zero_network_never_reconnects_or_delivers(
    home: Path, tmp_path: Path
) -> None:
    """The agent asks the shared connection check before every dial: once this computer last
    reported zero-network it never connects again, even through a dial that bypasses the
    connector's own check, and it delivers nothing over a connection it still holds."""

    from finishup.adapters.control.unix_socket import connect_owner_only_endpoint
    from finishup.client import everyday_policy
    from finishup.client.claimed_workspaces import record_claimed_workspace
    from finishup.client.connector import open_background_agent
    from finishup.client.connector_agent import ConnectorAgent
    from finishup.client.workspace_claim import workspace_claim

    record, root = _ssh_target(home)
    (tmp_path / "workspace").mkdir()
    workspace = WorkspaceLocator(os.fspath((tmp_path / "workspace").resolve(strict=True)))

    class _Drain:
        def __init__(self) -> None:
            self.calls = 0

        async def drain(self, _client: object) -> None:
            self.calls += 1

        def close(self) -> None:
            return None

    async def exercise() -> tuple[int, int, int, int]:
        daemon = ScriptedDaemon()
        master = _StubMaster(root, restarts=[])
        upstream = await _serve_upstream(master.upstream_path, daemon, [True])

        async def dial() -> AuthenticatedUnixStream:
            # Straight to the server's endpoint: only the agent's own check can refuse.
            return await connect_owner_only_endpoint(master.upstream_path)

        salt = base64.b64decode(record.claim_salt or "", validate=True)
        claim = await workspace_claim(workspace, salt)
        assert record_claimed_workspace(root, claim, workspace) is True
        assert everyday_policy.record_reported_policy(zero_network=False) is True
        agent = await open_background_agent(root, claim, dial)
        assert isinstance(agent, ConnectorAgent)
        drain = _Drain()
        agent._drain = drain  # type: ignore[assignment]  # pyright: ignore[reportPrivateUsage]
        try:
            assert await agent.wait_connected(5.0)
            await agent.drain()
            delivered_before = drain.calls
            before = daemon.connections
            assert everyday_policy.record_reported_policy(zero_network=True) is True
            # Over the connection it still holds, nothing more is delivered.
            await agent.drain()
            delivered_after = drain.calls
            # The server ends the session (idle, restart, lost upstream): no new connection.
            client = agent._client  # pyright: ignore[reportPrivateUsage]
            assert client is not None
            await client.close()
            async with asyncio.timeout(5):
                while agent.alive:
                    await asyncio.sleep(0.01)
            assert not agent.connected
            return before, daemon.connections, delivered_before, delivered_after
        finally:
            await agent.aclose()
            upstream.cancel()
            await asyncio.gather(upstream, return_exceptions=True)

    with selection_override(root):
        before, after, delivered_before, delivered_after = asyncio.run(exercise())
    # One connection, made while network use was permitted; none after.
    assert (before, after) == (1, 1)
    # One delivery while permitted; none once zero-network was reported.
    assert (delivered_before, delivered_after) == (1, 1)
