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
import os
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
from finishup.client.server_folders import add_folder
from finishup.client.workspace_agent import WorkspaceAgentHandler
from finishup.config.paths import active_root, reset_selection_memo, selection_override
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


def _two_targets_with_folders(tmp_path: Path) -> tuple[tuple[Path, str], tuple[Path, str]]:
    """Two remote targets, each with one folder its owner admitted; the first is selected.

    Each pair is the target's root and the folder admitted for it alone (``server folders add``).
    """

    made: list[tuple[Path, str]] = []
    with targets.registry_lock():
        selected, selected_root = targets.new_remote_target(
            "selected", "https", base_url="https://selected.example"
        )
        other, other_root = targets.new_remote_target(
            "other", "ssh", user="owner", host="other.example", port=2222
        )
        targets.write_selection(selected)
    for record, root in ((selected, selected_root), (other, other_root)):
        folder = (tmp_path / f"folder-{record.name}").resolve()
        folder.mkdir()
        add_folder(root, record.target_id, os.fspath(folder))
        made.append((root, os.fspath(folder)))
    reset_selection_memo()
    return made[0], made[1]


def _workspace(tmp_path: Path) -> WorkspaceLocator:
    directory = tmp_path / "workspace"
    directory.mkdir()
    return WorkspaceLocator(os.fspath(directory.resolve(strict=True)))


def _admitted(binding: ClientWorkspaceBinding) -> tuple[str, ...]:
    """The folders outside the workspace the binding's agent admits, read now.

    The targets here have no outside-read mode chosen, so they are in ``listed`` mode, which
    reads only the folders listed for the target the agent serves (ADR-051 decision 5).
    """

    agent = binding.agent
    assert type(agent) is WorkspaceAgentHandler
    outside = agent._outside()  # pyright: ignore[reportPrivateUsage]
    assert outside.mode == "listed"
    return outside.folders


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


def test_the_foreground_agent_backs_off_while_connections_close_at_once(remote: Path) -> None:
    """A server that accepts and closes at once (draining, an idle stop) is not redialled in a
    tight loop: each brief connection waits the next back-off; a lasting one resets it."""

    clock = _Clock()
    waits: list[float] = []
    dialled: list[_Connection] = []
    lifetimes = iter((0.0, 0.0, 0.0, 60.0, 0.0))

    async def bind(_workspace: WorkspaceLocator) -> ClientWorkspaceBinding:
        return _BINDING

    class _Lived(_Connection):
        def __init__(self, lifetime: float) -> None:
            super().__init__()
            self.lifetime = lifetime

        async def wait_closed(self) -> None:
            clock.now += self.lifetime  # the server closes it after ``lifetime`` seconds
            self.drop()

    async def dial(_binding: ClientWorkspaceBinding) -> _Connection:
        lifetime = next(lifetimes, None)
        if lifetime is None:
            raise asyncio.CancelledError
        connection = _Lived(lifetime)
        dialled.append(connection)
        return connection

    async def sleep(seconds: float) -> None:
        waits.append(seconds)

    async def exercise() -> None:
        with pytest.raises(asyncio.CancelledError):
            await run_foreground_agent(
                remote,
                WorkspaceLocator("/w/repo"),
                connect=dial,
                binding_for=bind,
                clock=clock,
                sleep=sleep,
            )

    asyncio.run(exercise())
    # Three brief connections back off 1, 2, 5 s; the lasting one resets; the next brief one
    # starts again at 1 s.
    assert waits == [1.0, 2.0, 5.0, 1.0]
    assert len(dialled) == 5


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


def test_the_foreground_agent_admits_the_folders_of_the_target_it_serves(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """``server connect NAME --agent`` serves NAME while this process's selection names another
    target: its agent admits the folders the owner admitted for NAME alone, through the real
    binding (``serving_workspace_binding``), and keeps them after the selection is back (ADR-051
    decision 5)."""

    with ambient_home(monkeypatch):
        (selected_root, selected_folder), (served_root, served_folder) = _two_targets_with_folders(
            tmp_path
        )
        assert active_root() == selected_root
        workspace = _workspace(tmp_path)
        bindings: list[ClientWorkspaceBinding] = []

        async def exercise() -> tuple[str, ...]:
            dialled = asyncio.Event()

            async def dial(binding: ClientWorkspaceBinding) -> _Connection:
                bindings.append(binding)
                dialled.set()
                return _Connection()

            serving = asyncio.create_task(
                run_foreground_agent(served_root, workspace, connect=dial)
            )
            try:
                async with asyncio.timeout(30.0):
                    await dialled.wait()
                assert active_root() == served_root
                return _admitted(bindings[0])
            finally:
                serving.cancel()
                await asyncio.gather(serving, return_exceptions=True)

        while_serving = asyncio.run(exercise())
        assert while_serving == (served_folder,)
        assert selected_folder not in while_serving
        # The selection names the other target again; the agent's record is still its own.
        assert active_root() == selected_root
        assert _admitted(bindings[0]) == (served_folder,)


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


def test_the_bridges_background_agent_admits_the_folders_of_the_bridges_own_target(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The background agent connection is bound through the real binding to the bridge's own
    target: it admits that target's folders only, and still does while another target is probed
    (``selection_override``, as the terminal's /server status does) or selected later (ADR-051
    decision 5)."""

    with ambient_home(monkeypatch):
        (own_root, own_folder), (other_root, other_folder) = _two_targets_with_folders(tmp_path)
        workspace = _workspace(tmp_path)
        bindings: list[ClientWorkspaceBinding] = []

        async def dial(binding: ClientWorkspaceBinding) -> _Connection:
            bindings.append(binding)
            return _Connection()

        work = BridgeBackgroundWork(connect=dial, pending=lambda _workspace: False)

        async def exercise() -> BackgroundPass:
            work.note_activity(workspace)
            try:
                return await work.run_pass()
            finally:
                await work.aclose()

        assert asyncio.run(exercise()).connected
        assert active_root() == own_root
        assert len(bindings) == 1 and _admitted(bindings[0]) == (own_folder,)
        with selection_override(other_root):
            assert _admitted(bindings[0]) == (own_folder,)
        with targets.registry_lock():
            other = targets.read_target(other_root)
            assert other is not None
            targets.write_selection(other)
        reset_selection_memo()
        assert active_root() == other_root
        assert _admitted(bindings[0]) == (own_folder,)
        assert other_folder not in _admitted(bindings[0])


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
