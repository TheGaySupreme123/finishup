"""Where a direct-dial client answers its server's workspace calls (ADR-051, approach B).

In approach B the workspace agent runs inside the client processes themselves; there is no relay
or agent daemon on the client machine:

* **Per connection.** A process whose calls need the workspace while they run (a CLI workflow
  command, the terminal interface, the MCP bridge) connects with
  ``service.client.serving_workspace_binding``: its hello claims the workspace and offers the
  agent, and ``ServiceClient`` answers the server's ``workspace_call`` frames on that same
  connection. Short-lived processes (hooks) are claim-bound without an agent.
* **Background work.** Work that outlives a call (a semantic review after ``check`` returned,
  the verification of a row a hook delivered) needs an agent connection while no call runs. The
  MCP bridge, the long-lived client process of this approach, holds one
  (``BridgeBackgroundWork``): a claim-bound agent connection kept while the session is active
  and released ``AGENT_LEASE_SECONDS`` after its last activity, so the server's idle relock and
  idle stop still apply. Over that connection it delivers what hooks captured under the remote
  root and could not deliver themselves (the observation outbox and the legacy spool), with the
  shared ``ClientObservationDrain``.
* **CLI-only use.** ``finishup server connect NAME --agent`` keeps one agent connection to that
  target open in the foreground until interrupted (``run_foreground_agent``), for an owner who
  runs no MCP bridge.

The bridge's background connection never asks for a remote service to be started: it dials
without the on-demand start, so over SSH a stopped service stays stopped (an HTTPS gateway starts
its own service for any session it opens, as it does for every client). Failures are closed
reasons; no path, host or server text appears in an error or a log.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final, Protocol, cast

from finishup.ports.control import ControlClientKind, ControlError, WorkspaceLocator

if TYPE_CHECKING:
    from finishup.client.observation_outbox import (
        ClientDrainSummary,
        ClientObservationDrain,
        ObservationIngestClient,
    )
    from finishup.service.client import ClientWorkspaceBinding

__all__ = [
    "AGENT_LEASE_SECONDS",
    "DRAIN_INTERVAL_SECONDS",
    "AgentConnection",
    "AgentSessionError",
    "BackgroundPass",
    "BridgeBackgroundWork",
    "capture_pending",
    "run_foreground_agent",
    "start_remote_background_work",
]

# The bridge keeps its background agent connection this long after its last activity (a tool
# call, or rows its drain delivered): the lease approach A's connector keeps too.
AGENT_LEASE_SECONDS: Final = 900.0
# How often the bridge looks for captured rows to deliver while nothing wakes it sooner.
DRAIN_INTERVAL_SECONDS: Final = 30.0
# Waits between reconnect attempts of a background or foreground agent connection.
_RECONNECT_BACKOFF_SECONDS: Final = (1.0, 2.0, 5.0, 15.0, 30.0)
_COMPONENT: Final = "client.agent_session"


class AgentSessionError(Exception):
    """A foreground agent could not serve: one closed reason and an optional closed phase."""

    __slots__ = ("phase", "reason")

    reason: str
    phase: str | None

    def __init__(self, reason: str, *, phase: str | None = None) -> None:
        self.reason = reason
        self.phase = phase
        super().__init__(reason if phase is None else f"{reason}:{phase}")


class AgentConnection(Protocol):
    """What the agent loops need of a connection; ``ServiceClient`` is the production one."""

    @property
    def closed(self) -> bool: ...

    @property
    def workspace_handle(self) -> str | None: ...

    async def wait_closed(self) -> None: ...

    async def close(self) -> None: ...


type AgentConnector = Callable[[ClientWorkspaceBinding], Awaitable[AgentConnection]]
type BindingFactory = Callable[[WorkspaceLocator], Awaitable[ClientWorkspaceBinding | None]]
type PendingProbe = Callable[[WorkspaceLocator], bool]


def _backoff(attempt: int) -> float:
    return _RECONNECT_BACKOFF_SECONDS[min(attempt, len(_RECONNECT_BACKOFF_SECONDS) - 1)]


def _record(operation: str, reason: str) -> None:
    from finishup.observability.logging import record_bounded_event_without_raising

    record_bounded_event_without_raising(component=_COMPONENT, operation=operation, reason=reason)


async def _serving_binding(workspace: WorkspaceLocator) -> ClientWorkspaceBinding | None:
    from finishup.service.client import serving_workspace_binding

    return await serving_workspace_binding(workspace)


# -- the foreground agent (``finishup server connect NAME --agent``) ------------------------------


async def _connect_on_demand(binding: ClientWorkspaceBinding) -> AgentConnection:
    from finishup.service.client import connect_service_on_demand

    return await connect_service_on_demand(ControlClientKind.CLI, workspace_binding=binding)


async def run_foreground_agent(
    root: Path,
    workspace_locator: WorkspaceLocator,
    *,
    connect: AgentConnector | None = None,
    binding_for: BindingFactory | None = None,
) -> None:
    """Serve this workspace's calls on one connection to the target at ``root`` until cancelled.

    ``finishup server connect NAME --agent`` runs this in the foreground, for owners who drive a
    remote target from the CLI only (no MCP bridge holds a connection for background work). The
    target is resolved as ``root`` for this block, whatever this process's selection names. When
    the server closes the connection (its idle bound, a restart) it is opened again after a short
    back-off, so while this runs the server counts it as a connected client.

    Raises ``AgentSessionError``: ``agent_not_applicable`` for a root that is not a remote target,
    ``workspace_agent_unavailable`` when the server bound no workspace handle (its vault is
    locked, say), or a closed control reason and remote phase: any failure of the first
    connection, and a non-retryable failure of a later one.
    """

    from finishup.config.paths import selection_override

    dial = connect if connect is not None else _connect_on_demand
    bind = binding_for if binding_for is not None else _serving_binding
    with selection_override(root):
        try:
            binding = await bind(workspace_locator)
        except ControlError as error:
            raise AgentSessionError(error.reason, phase=error.phase) from None
        if binding is None:
            raise AgentSessionError("agent_not_applicable")
        attempt = 0
        served = False
        while True:
            try:
                connection = await dial(binding)
            except ControlError as error:
                if not served or not error.retryable:
                    raise AgentSessionError(error.reason, phase=error.phase) from None
                _record("foreground_agent", error.phase or error.reason)
                await asyncio.sleep(_backoff(attempt))
                attempt += 1
                continue
            try:
                if connection.workspace_handle is None:
                    # The server derived no handle (its vault is locked, say): no call names us.
                    raise AgentSessionError("workspace_agent_unavailable")
                served = True
                attempt = 0
                await connection.wait_closed()
            finally:
                await connection.close()
            _record("foreground_agent", "reconnecting")


# -- the bridge's background agent and drain ------------------------------------------------------


def capture_pending(workspace: WorkspaceLocator, state: Path | None = None) -> bool:
    """Whether hooks left rows or spooled records for ``workspace`` (a read-only probe).

    ``finishup.client.observation_outbox.capture_pending``; it creates nothing.
    """

    from finishup.client.observation_outbox import capture_pending as pending

    return pending(workspace, state=state)


async def _connect_running(binding: ClientWorkspaceBinding) -> AgentConnection:
    from finishup.service.client import connect_service

    # No on-demand start: background work never asks for a remote service to be started.
    return await connect_service(ControlClientKind.CLI, workspace_binding=binding)


@dataclass(frozen=True, slots=True)
class BackgroundPass:
    """What one background pass did: whether an agent connection is held, and any delivery."""

    connected: bool
    drained: ClientDrainSummary | None = None


class BridgeBackgroundWork:
    """The MCP bridge's background agent connection and observation drain for a remote root.

    ``note_activity`` (each tool call) names the bridge's workspace and renews the lease; ``run``
    is the loop the bridge runs for its lifetime. Each pass, woken by activity or every
    ``drain_interval`` seconds:

    * while the lease runs, or while captured rows wait, one agent connection is kept (dialled
      again if the server closed it, after a back-off; never with the on-demand start);
    * rows waiting for this workspace are delivered over that connection, and delivered rows
      renew the lease (the server verifies them through this agent);
    * once the lease has run out and nothing waits, the connection is closed.

    A connection claims the workspace it was opened for. When the bridge names another workspace
    (a Cursor folder change, say), the next pass closes the connection that claims the earlier
    one and opens one that claims the new workspace before it delivers that workspace's rows.
    """

    __slots__ = (
        "_attempt",
        "_binding_for",
        "_clock",
        "_connect",
        "_connection",
        "_connection_workspace",
        "_drain",
        "_drain_interval",
        "_last_activity",
        "_lease",
        "_pending",
        "_retry_at",
        "_wake",
        "_workspace",
    )

    def __init__(
        self,
        *,
        lease_seconds: float = AGENT_LEASE_SECONDS,
        drain_interval: float = DRAIN_INTERVAL_SECONDS,
        connect: AgentConnector | None = None,
        binding_for: BindingFactory | None = None,
        pending: PendingProbe | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        for bound in (lease_seconds, drain_interval):
            if type(bound) is not float or not 0.0 < bound <= 86_400.0:
                raise ValueError("background_work_bound_invalid")
        self._lease = lease_seconds
        self._drain_interval = drain_interval
        self._connect = connect if connect is not None else _connect_running
        self._binding_for = binding_for if binding_for is not None else _serving_binding
        self._pending = pending if pending is not None else capture_pending
        self._clock = clock
        self._wake = asyncio.Event()
        self._workspace: WorkspaceLocator | None = None
        self._last_activity = clock()
        self._connection: AgentConnection | None = None
        # The workspace ``_connection`` claims: a connection serves only the one it was opened for.
        self._connection_workspace: WorkspaceLocator | None = None
        self._drain: ClientObservationDrain | None = None
        self._attempt = 0
        self._retry_at = 0.0

    @property
    def connection(self) -> AgentConnection | None:
        """The live background agent connection, if one is held."""

        held = self._connection
        return None if held is None or held.closed else held

    def note_activity(self, workspace: WorkspaceLocator | None) -> None:
        """Renew the lease for ``workspace`` (the bridge's own) and wake the loop."""

        if type(workspace) is WorkspaceLocator and workspace != self._workspace:
            if self._workspace is not None:
                # The bridge now serves another workspace (a Cursor folder change, say).
                self._close_drain()
            self._workspace = workspace
        self._last_activity = self._clock()
        self._wake.set()

    async def run(self) -> None:
        """Run passes until cancelled; a failed pass is recorded by closed reason only."""

        try:
            while True:
                try:
                    await self.run_pass()
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    from finishup.observability.logging import (
                        record_unexpected_exception_without_raising,
                    )

                    record_unexpected_exception_without_raising(
                        exc, component=_COMPONENT, operation="background_pass_failed"
                    )
                with contextlib.suppress(TimeoutError):
                    async with asyncio.timeout(self._drain_interval):
                        await self._wake.wait()
                self._wake.clear()
        finally:
            await self.aclose()

    async def run_pass(self) -> BackgroundPass:
        """One pass: keep or release the agent connection, and deliver what waits."""

        workspace = self._workspace
        if workspace is None:
            return BackgroundPass(False)
        leased = self._clock() - self._last_activity < self._lease
        pending = await asyncio.to_thread(self._pending, workspace)
        if not leased and not pending:
            await self._release()
            return BackgroundPass(False)
        connection = await self._ensure_connection(workspace)
        if connection is None:
            return BackgroundPass(False)
        if not pending:
            return BackgroundPass(True)
        summary = await self._drain_over(workspace, connection)
        if summary.delivery is not None and summary.delivery.acknowledged:
            # The server verifies what it accepted through this agent: keep it for that.
            self._last_activity = self._clock()
        return BackgroundPass(True, summary)

    async def _ensure_connection(self, workspace: WorkspaceLocator) -> AgentConnection | None:
        live = self.connection
        if live is not None and self._connection_workspace == workspace:
            return live
        # Closed by the server, or claiming a workspace the bridge no longer serves: its claim
        # would attribute this workspace's rows and calls to the earlier one.
        await self._release()
        now = self._clock()
        if now < self._retry_at:
            return None
        try:
            binding = await self._binding_for(workspace)
            if binding is None:
                # The bridge's root is not a remote target any more; there is nothing to serve.
                return None
            connection = await self._connect(binding)
        except ControlError as error:
            self._retry_at = now + _backoff(self._attempt)
            self._attempt += 1
            _record("background_agent", error.phase or error.reason)
            return None
        self._attempt = 0
        self._retry_at = 0.0
        self._connection = connection
        self._connection_workspace = workspace
        return connection

    async def _drain_over(
        self, workspace: WorkspaceLocator, connection: AgentConnection
    ) -> ClientDrainSummary:
        from finishup.client.observation_outbox import ClientObservationDrain

        drain = self._drain
        if drain is None:
            drain = ClientObservationDrain(workspace)
            self._drain = drain
        # A ``ServiceClient``: the drain sends each row as ``observation_ingest`` on it.
        return await drain.drain(cast("ObservationIngestClient", connection))

    async def _release(self) -> None:
        connection, self._connection = self._connection, None
        self._connection_workspace = None
        if connection is not None:
            with contextlib.suppress(Exception):
                await connection.close()

    def _close_drain(self) -> None:
        drain, self._drain = self._drain, None
        if drain is not None:
            drain.close()

    async def aclose(self) -> None:
        """Close the background connection and the drain's worker pool."""

        await self._release()
        self._close_drain()


def start_remote_background_work() -> tuple[BridgeBackgroundWork, asyncio.Task[None]] | None:
    """Start the bridge's background work for a remote active root; ``None`` for a local root.

    A local root (the everyday server, an isolated root, a named local server) starts nothing,
    and a root whose record cannot be read starts nothing either: the bridge's own connection
    reports that refusal. The work serves no workspace until the bridge names it
    (``BridgeBackgroundWork.note_activity``).
    """

    from finishup.client.targets import TargetError, active_target_record

    try:
        record = active_target_record()
    except TargetError:
        return None
    if record is None or not record.is_remote:
        return None
    work = BridgeBackgroundWork()
    return work, asyncio.create_task(work.run())
