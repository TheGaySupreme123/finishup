"""Where a direct-dial client serves its workspace when no call runs (ADR-051, approach B).

``run_foreground_agent`` (``finishup server connect NAME --agent``) keeps one agent connection to
the named target, opened with that target resolved as the root, and opens it again when the
server closes it. ``BridgeBackgroundWork`` is the MCP bridge's background agent connection and
drain: kept while its lease runs or captured rows wait, released afterwards, dialled again after
a back-off when the server is away, never by starting a service. Each uses injected connections
here; the end-to-end tests run them through the real transports.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from pathlib import Path

import pytest

from builders.server_targets import ambient_home
from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.client import agent_session, targets
from finishup.client.agent_session import (
    AgentSessionError,
    BackgroundPass,
    BridgeBackgroundWork,
    capture_pending,
    run_foreground_agent,
    start_remote_background_work,
)
from finishup.config.paths import active_root, reset_selection_memo
from finishup.ports.control import ControlError, WorkspaceClaim, WorkspaceLocator
from finishup.service.client import ClientWorkspaceBinding

_BINDING = ClientWorkspaceBinding(
    WorkspaceClaim("directory", "sha256:" + "2" * 64, "sha256:" + "3" * 64)
)
_HANDLE = "client:" + "1" * 16


class _Connection:
    """A connection double the server can close (``drop``) and the owner can close."""

    def __init__(self, handle: str | None = _HANDLE) -> None:
        self.workspace_handle = handle
        self._ended = asyncio.Event()
        self.closed_by_owner = False

    @property
    def closed(self) -> bool:
        return self._ended.is_set()

    def drop(self) -> None:
        self._ended.set()

    async def wait_closed(self) -> None:
        await self._ended.wait()

    async def close(self) -> None:
        self.closed_by_owner = True
        self._ended.set()


class _Clock:
    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def remote(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch):
        with targets.registry_lock():
            _record, root = targets.new_remote_target("lab", "https", base_url="https://fu.example")
        reset_selection_memo()
        yield root


# -- the foreground agent --------------------------------------------------------------------------


def test_the_foreground_agent_binds_the_named_target_and_reconnects_after_a_close(
    remote: Path,
) -> None:
    roots: list[Path | None] = []
    dialled: list[_Connection] = []

    async def bind(_workspace: WorkspaceLocator) -> ClientWorkspaceBinding:
        # The named target is this block's root even though nothing selected it.
        roots.append(active_root())
        return _BINDING

    async def dial(binding: ClientWorkspaceBinding) -> _Connection:
        assert binding is _BINDING
        connection = _Connection()
        dialled.append(connection)
        return connection

    async def exercise() -> None:
        serving = asyncio.create_task(
            run_foreground_agent(
                remote, WorkspaceLocator("/w/repo"), connect=dial, binding_for=bind
            )
        )
        while not dialled:
            await asyncio.sleep(0)
        dialled[0].drop()  # the server closed the connection (its idle bound, a restart)
        while len(dialled) < 2:
            await asyncio.sleep(0)
        serving.cancel()
        await asyncio.gather(serving, return_exceptions=True)

    asyncio.run(exercise())
    assert roots == [remote]
    assert all(connection.closed_by_owner for connection in dialled)
    assert active_root() is None  # the selection is the everyday install again


@pytest.mark.parametrize(
    ("binding", "handle", "error", "expected"),
    [
        (None, _HANDLE, None, ("agent_not_applicable", None)),
        (_BINDING, None, None, ("workspace_agent_unavailable", None)),
        (
            _BINDING,
            _HANDLE,
            ControlError("service_unavailable", retryable=True, phase="remote_auth_failed"),
            ("service_unavailable", "remote_auth_failed"),
        ),
    ],
)
def test_the_foreground_agent_refuses_with_closed_reasons(
    remote: Path,
    binding: ClientWorkspaceBinding | None,
    handle: str | None,
    error: ControlError | None,
    expected: tuple[str, str | None],
) -> None:
    async def bind(_workspace: WorkspaceLocator) -> ClientWorkspaceBinding | None:
        return binding

    async def dial(_binding: ClientWorkspaceBinding) -> _Connection:
        if error is not None:
            raise error
        return _Connection(handle)

    with pytest.raises(AgentSessionError) as raised:
        asyncio.run(
            run_foreground_agent(
                remote, WorkspaceLocator("/w/repo"), connect=dial, binding_for=bind
            )
        )
    assert (raised.value.reason, raised.value.phase) == expected
    assert "/w/repo" not in str(raised.value)


# -- the bridge's background work ------------------------------------------------------------------


def _work(
    clock: _Clock,
    *,
    pending: list[bool],
    dialled: list[_Connection],
    failures: list[ControlError] | None = None,
) -> BridgeBackgroundWork:
    async def bind(_workspace: WorkspaceLocator) -> ClientWorkspaceBinding:
        return _BINDING

    async def dial(_binding: ClientWorkspaceBinding) -> _Connection:
        if failures:
            raise failures.pop(0)
        connection = _Connection()
        dialled.append(connection)
        return connection

    return BridgeBackgroundWork(
        lease_seconds=60.0,
        drain_interval=30.0,
        connect=dial,
        binding_for=bind,
        pending=lambda _workspace: pending[0],
        clock=clock,
    )


def test_the_bridge_holds_an_agent_while_its_lease_runs_and_releases_it_after() -> None:
    clock = _Clock()
    dialled: list[_Connection] = []
    work = _work(clock, pending=[False], dialled=dialled)

    async def exercise() -> list[BackgroundPass]:
        passes = [await work.run_pass()]  # no workspace named yet: nothing to serve
        work.note_activity(WorkspaceLocator("/w/repo"))
        passes.append(await work.run_pass())
        passes.append(await work.run_pass())  # the same connection is kept
        dialled[0].drop()  # the server closed it within the lease: dialled again
        passes.append(await work.run_pass())
        clock.now += 61.0  # the lease ran out and nothing waits: released
        passes.append(await work.run_pass())
        await work.aclose()
        return passes

    passes = asyncio.run(exercise())
    assert [item.connected for item in passes] == [False, True, True, True, False]
    assert len(dialled) == 2
    assert dialled[1].closed_by_owner
    assert work.connection is None


def test_captured_rows_keep_or_bring_back_the_connection_after_the_lease(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    clock = _Clock()
    dialled: list[_Connection] = []
    work = _work(clock, pending=[True], dialled=dialled)
    drained: list[object] = []

    async def drain_over(
        _self: BridgeBackgroundWork, _workspace: WorkspaceLocator, connection: object
    ) -> object:
        drained.append(connection)
        from finishup.application.observation_drain import ObservationDrainSummary
        from finishup.client.observation_outbox import ClientDrainSummary

        return ClientDrainSummary(0, ObservationDrainSummary(1, 1, 0, 0, ()))

    monkeypatch.setattr(BridgeBackgroundWork, "_drain_over", drain_over)

    async def exercise() -> BackgroundPass:
        work.note_activity(WorkspaceLocator(str(tmp_path)))
        clock.now += 120.0  # past the lease, but rows wait
        delivered = await work.run_pass()
        # The delivered row renewed the lease: the server verifies it through this agent.
        later = await work.run_pass()
        assert later.connected
        await work.aclose()
        return delivered

    delivered = asyncio.run(exercise())
    assert delivered.connected and delivered.drained is not None
    assert drained == [dialled[0], dialled[0]]


def test_a_workspace_switch_releases_the_connection_that_claims_the_earlier_workspace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _Clock()
    dialled: list[_Connection] = []
    bound_for: dict[int, WorkspaceLocator] = {}
    drained: list[tuple[WorkspaceLocator, int]] = []
    first, second = WorkspaceLocator("/w/a"), WorkspaceLocator("/w/b")
    bindings = {
        first: ClientWorkspaceBinding(
            WorkspaceClaim("directory", "sha256:" + "a" * 64, "sha256:" + "c" * 64)
        ),
        second: ClientWorkspaceBinding(
            WorkspaceClaim("directory", "sha256:" + "b" * 64, "sha256:" + "d" * 64)
        ),
    }

    async def bind(workspace: WorkspaceLocator) -> ClientWorkspaceBinding:
        return bindings[workspace]

    async def dial(binding: ClientWorkspaceBinding) -> _Connection:
        connection = _Connection()
        bound_for[id(connection)] = next(key for key, item in bindings.items() if item is binding)
        dialled.append(connection)
        return connection

    async def drain_over(
        _self: BridgeBackgroundWork, workspace: WorkspaceLocator, connection: object
    ) -> object:
        drained.append((workspace, id(connection)))
        from finishup.client.observation_outbox import ClientDrainSummary

        return ClientDrainSummary(0, None)

    monkeypatch.setattr(BridgeBackgroundWork, "_drain_over", drain_over)
    work = BridgeBackgroundWork(
        lease_seconds=60.0,
        drain_interval=30.0,
        connect=dial,
        binding_for=bind,
        pending=lambda _workspace: True,
        clock=clock,
    )

    async def exercise() -> None:
        work.note_activity(first)
        assert (await work.run_pass()).connected
        work.note_activity(second)  # the bridge now serves another folder
        assert (await work.run_pass()).connected
        work.note_activity(second)  # the same folder again: the connection is kept
        assert (await work.run_pass()).connected
        await work.aclose()

    asyncio.run(exercise())
    assert len(dialled) == 2
    assert dialled[0].closed_by_owner  # the connection that claims the earlier workspace
    assert [bound_for[id(item)] for item in dialled] == [first, second]
    # Each workspace's rows went over the connection that claims that workspace.
    assert drained == [(first, id(dialled[0])), (second, id(dialled[1])), (second, id(dialled[1]))]


def test_a_server_that_is_away_is_dialled_again_only_after_a_back_off() -> None:
    clock = _Clock()
    dialled: list[_Connection] = []
    away = ControlError("service_unavailable", retryable=True, phase="remote_service_not_running")
    work = _work(clock, pending=[False], dialled=dialled, failures=[away, away])

    async def exercise() -> list[bool]:
        work.note_activity(WorkspaceLocator("/w/repo"))
        connected = [(await work.run_pass()).connected]
        connected.append((await work.run_pass()).connected)  # inside the back-off: no dial
        clock.now += 1.0
        connected.append((await work.run_pass()).connected)  # dialled: away again
        clock.now += 2.0
        connected.append((await work.run_pass()).connected)  # dialled: answers
        await work.aclose()
        return connected

    assert asyncio.run(exercise()) == [False, False, False, True]
    assert len(dialled) == 1


def test_only_a_remote_root_starts_the_bridges_background_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def started() -> bool:
        begun = start_remote_background_work()
        if begun is None:
            return False
        work, task = begun
        assert isinstance(work, BridgeBackgroundWork)
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        return True

    with ambient_home(monkeypatch):
        assert asyncio.run(started()) is False  # the everyday server
        with targets.registry_lock():
            local, _local_root = targets.new_local_target("work")
            targets.write_selection(local)
        reset_selection_memo()
        assert asyncio.run(started()) is False  # a named local server
        with targets.registry_lock():
            remote, _root = targets.new_remote_target("lab", "https", base_url="https://fu.example")
            targets.write_selection(remote)
        reset_selection_memo()
        assert asyncio.run(started()) is True


def test_nothing_is_pending_where_no_hook_ever_captured(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    assert capture_pending(WorkspaceLocator(str(tmp_path)), state) is False
    # The probe made no commitment for the workspace.
    store = LocalObservationStore(_state=state)
    assert store.existing_workspace_commitment(str(tmp_path)) is None


def test_background_bounds_are_validated() -> None:
    with pytest.raises(ValueError, match="background_work_bound_invalid"):
        BridgeBackgroundWork(lease_seconds=0.0)
    assert agent_session.AGENT_LEASE_SECONDS == 900.0
