"""The connector's long-lived workspace agent for one claimed workspace (ADR-051, approach A).

A FinishUP server on another machine reads this client's workspace only through a workspace
agent. A client process answers the server's workspace calls on its own connection while that
connection is open; work the server keeps doing after the call that started it returned (the
AI-powered review loop, observation verification, recovered jobs) needs an agent that outlives
it. For a remote target that is the target's connector: it holds one ``ConnectorAgent`` per
workspace whose claim it relayed, for ``AGENT_LEASE_SECONDS`` after that workspace's last hello.

A ``ConnectorAgent`` keeps one claim-bound control connection that offers the real
``WorkspaceAgentHandler`` (``finishup.client.workspace_agent``) for its workspace, connecting
again whenever the service ends it (an idle session, a restart, a lost upstream). Over the same
connection it delivers what this client's hooks captured for that workspace
(``ClientObservationDrain``), each row attested by the client's own observation store. The
connection is served by the connector itself (``dial``), never through its endpoint, so it never
counts as client activity and never renews its own lease. Nothing here logs or raises a path.

Before every connection attempt the agent asks the shared connection check
(``targets.require_current_authorization`` for its target's record): while this computer last
reported a zero-network policy (ADR-051 decision 8, maintainer decision of 2026-11-07), or once
the target needs a fresh confirmation, it stops for good instead of connecting again, and it
delivers nothing while that record says zero-network.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Final

from finishup.adapters.control.unix_socket import AuthenticatedUnixStream
from finishup.adapters.workspace_root import RepositoryIdentityError
from finishup.client.claimed_workspaces import claimed_workspace
from finishup.client.everyday_policy import last_reported_zero_network
from finishup.client.observation_outbox import ClientObservationDrain
from finishup.client.remote_binding import binding_for_active_root
from finishup.client.targets import TargetError, read_target, require_current_authorization
from finishup.ports.control import ControlClientKind, WorkspaceClaim
from finishup.service.client import ClientWorkspaceBinding, ServiceClient, connect_service_stream

__all__ = ["ConnectorAgent", "Dial", "open_connector_agent"]

type Dial = Callable[[], Awaitable[AuthenticatedUnixStream]]

# Back-off between connection attempts: the first retry is quick (an idle session ended), and a
# server that stays unreachable is retried at most every half minute.
_RECONNECT_MIN_SECONDS: Final = 0.5
_RECONNECT_MAX_SECONDS: Final = 30.0


class ConnectorAgent:
    """One claimed workspace's agent connection, kept and reconnected until closed."""

    __slots__ = (
        "_binding",
        "_client",
        "_closing",
        "_connected",
        "_dial",
        "_drain",
        "_drain_lock",
        "_root",
        "_supervisor",
    )

    def __init__(
        self,
        binding: ClientWorkspaceBinding,
        drain: ClientObservationDrain,
        dial: Dial,
        *,
        root: Path,
    ) -> None:
        if type(binding) is not ClientWorkspaceBinding or binding.agent is None:
            raise TypeError("workspace_binding_invalid")
        if type(drain) is not ClientObservationDrain:
            raise TypeError("observation_drain_invalid")
        self._binding = binding
        self._drain = drain
        self._dial = dial
        self._root = root
        self._client: ServiceClient | None = None
        self._closing = False
        self._connected = asyncio.Event()
        self._drain_lock = asyncio.Lock()
        self._supervisor: asyncio.Task[None] | None = None

    def __repr__(self) -> str:
        return "ConnectorAgent(<redacted>)"

    @property
    def alive(self) -> bool:
        """Whether this agent still holds, or is still re-establishing, its connection."""

        return not self._closing and self._supervisor is not None and not self._supervisor.done()

    @property
    def connected(self) -> bool:
        client = self._client
        return client is not None and not client.closed

    def start(self) -> None:
        if self._supervisor is None:
            self._supervisor = asyncio.create_task(self._supervise())

    async def wait_connected(self, timeout_seconds: float) -> bool:
        """Wait up to ``timeout_seconds`` for a live connection; True when there is one."""

        try:
            async with asyncio.timeout(timeout_seconds):
                await self._connected.wait()
        except TimeoutError:
            return False
        return self.connected

    def _may_connect(self) -> bool:
        """Whether anything may be sent to this agent's target now (the shared check).

        A file read only. While this computer last reported a zero-network policy, or once the
        target's record needs a fresh confirmation or can no longer be read, nothing is.
        """

        try:
            require_current_authorization(read_target(self._root))
        except TargetError:
            return False
        return True

    async def _supervise(self) -> None:
        delay = _RECONNECT_MIN_SECONDS
        while not self._closing:
            if not await asyncio.to_thread(self._may_connect):
                # Never connect again: the connector's own check stops it, and a client that
                # may connect again later opens a new agent through the same check.
                return
            try:
                stream = await self._dial()
                client = await connect_service_stream(
                    stream,
                    ControlClientKind.CLI,
                    workspace_binding=self._binding,
                    transport="connector",
                )
            except Exception:
                # Unreachable, refused or mid-restart: try again later, quietly and bounded.
                await asyncio.sleep(delay)
                delay = min(delay * 2, _RECONNECT_MAX_SECONDS)
                continue
            delay = _RECONNECT_MIN_SECONDS
            self._client = client
            self._connected.set()
            try:
                await client.wait_closed()
            finally:
                self._connected.clear()
                self._client = None
                with contextlib.suppress(Exception):
                    await client.close()
            if not self._closing:
                await asyncio.sleep(_RECONNECT_MIN_SECONDS)

    async def drain(self) -> None:
        """Deliver this workspace's captured observations over the live connection, if any.

        Never raises: nothing to send, no connection, or a server that cannot take the rows
        now all leave the rows for the next pass (or the next hook).
        """

        client = self._client
        if client is None or client.closed:
            return
        if last_reported_zero_network() is not None:
            # Nothing leaves this computer while it last reported zero-network (ADR-051
            # decision 8); the rows wait in the outbox.
            return
        async with self._drain_lock:
            with contextlib.suppress(Exception):
                await self._drain.drain(client)

    async def aclose(self) -> None:
        self._closing = True
        supervisor, self._supervisor = self._supervisor, None
        if supervisor is not None:
            supervisor.cancel()
            await asyncio.gather(supervisor, return_exceptions=True)
        client, self._client = self._client, None
        if client is not None:
            with contextlib.suppress(Exception):
                await client.close()
        with contextlib.suppress(Exception):
            self._drain.close()


async def open_connector_agent(
    root: Path, claim: WorkspaceClaim, dial: Dial
) -> ConnectorAgent | None:
    """The background agent for ``claim`` in remote target ``root``; None when it cannot serve.

    The workspace comes from the root's claimed-workspace index, written by the client process
    that made the claim. The claim is derived again from that workspace with the target's own
    salt (``binding_for_active_root``, under the connector's selection of ``root``); a record
    that no longer yields this exact claim (a moved folder, an edited record) is never served.
    """

    workspace = await asyncio.to_thread(claimed_workspace, root, claim)
    if workspace is None:
        return None
    try:
        binding = await binding_for_active_root(workspace, serve_workspace=True)
    except (RepositoryIdentityError, TargetError):
        return None
    if binding is None or binding.claim != claim or binding.agent is None:
        return None
    agent = ConnectorAgent(binding, ClientObservationDrain(workspace), dial, root=root)
    agent.start()
    return agent
