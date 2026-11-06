"""Where a direct-dial client answers its server's workspace calls (ADR-051, approach B).

In approach B the workspace agent runs inside the client processes themselves; there is no relay
or agent daemon on the client machine:

* **Per connection.** Every connection a client process opens to a remote target claims the
  process's workspace and declares the agent, so the server can call back during that process's
  own operation (a CLI ``check``, a hook's observation). ``remote_workspace_binding`` decides the
  claim and the agent for one connection; ``service.client`` calls it for every remote dial.
* **Background work.** The MCP bridge keeps its connection for the whole agent session, so that
  same declaration lets the server reach the workspace for work that outlives a call (the detached
  semantic check, reviewer reads, observation verification).
* **CLI-only use.** ``finishup server connect NAME --agent`` keeps one agent connection open in the
  foreground (``run_foreground_agent``) for an owner who runs no MCP bridge.
* **Background drain.** The MCP bridge, the long-lived client process of this approach, also
  drains what hooks captured under a remote root (the observation outbox and the legacy spool) to
  the server between hook passes (``start_remote_background_work``).

``serve_workspace_calls`` is the frame loop of an agent-only connection: it reads
``workspace_call`` frames, answers each in a worker thread, and writes the ``workspace_reply``
under one write lock. It works over every transport, because every transport carries the same
frames.

Two pieces come from the shared foundation tracks and are wired here once they merge: the claim
(``finishup.client.workspace_claim``) and the handler that runs the eighteen operations against
the local adapters (``finishup.client.workspace_agent``). Until then ``remote_workspace_binding``
returns ``NO_BINDING``: a remote connection claims nothing, declares no agent, and never sends a
path, so the server binds it ``none``.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from finishup import __version__
from finishup.client.targets import ServerTarget
from finishup.client.transports import ControlTransport, transport_for_target
from finishup.ports.control import (
    ControlClientKind,
    WorkspaceAgentDeclaration,
    WorkspaceCall,
    WorkspaceClaim,
    WorkspaceLocator,
    WorkspaceReply,
)
from finishup.service.control_protocol import (
    ControlProtocolError,
    ControlSession,
    ControlStream,
    client_handshake,
    is_workspace_call_frame,
    parse_workspace_call,
    read_control_frame,
    write_workspace_reply,
)

__all__ = [
    "AGENT_CONCURRENCY",
    "NO_BINDING",
    "AgentSessionError",
    "RemoteWorkspaceBinding",
    "WorkspaceAnswer",
    "open_agent_session",
    "remote_workspace_binding",
    "remote_background_drain",
    "run_foreground_agent",
    "serve_workspace_calls",
    "start_remote_background_work",
]

# Calls one agent connection answers at once; the hub bounds its own side too.
AGENT_CONCURRENCY: Final = 4
_AGENT_HANDSHAKE_SECONDS: Final = 10.0

# ``answer(call, workspace_handle)``: run one call against the claimed workspace and return its
# reply; never raises for anything the call carried (``WorkspaceAgentHandler.answer``).
type WorkspaceAnswer = Callable[[WorkspaceCall, str | None], WorkspaceReply]


class AgentSessionError(Exception):
    """A foreground agent could not serve: one closed reason and an optional closed phase."""

    __slots__ = ("phase", "reason")

    reason: str
    phase: str | None

    def __init__(self, reason: str, *, phase: str | None = None) -> None:
        self.reason = reason
        self.phase = phase
        super().__init__(reason if phase is None else f"{reason}:{phase}")


@dataclass(frozen=True, slots=True)
class RemoteWorkspaceBinding:
    """How one connection to a remote target binds its workspace.

    ``claim`` replaces the locator on the hello (a keyed digest, never a path); ``agent`` is the
    declaration the hello offers; ``answer`` serves the calls the server then sends. All three are
    present together or all absent.
    """

    claim: WorkspaceClaim | None
    agent: WorkspaceAgentDeclaration | None
    answer: WorkspaceAnswer | None

    def __post_init__(self) -> None:
        present = (self.claim is not None, self.agent is not None, self.answer is not None)
        if any(present) and not all(present):
            raise ValueError("remote_workspace_binding_incomplete")

    @property
    def declares_agent(self) -> bool:
        return self.agent is not None


NO_BINDING: Final = RemoteWorkspaceBinding(None, None, None)


async def remote_workspace_binding(
    target: ServerTarget, workspace_locator: WorkspaceLocator | None
) -> RemoteWorkspaceBinding:
    """INTEGRATION POINT — wired after split/client and split/server merge.

    Decide the claim and the agent for one connection to the remote ``target`` from this
    process's workspace. ``service.client`` calls it for every remote dial (so every client
    process is the agent of its own connection, and the MCP bridge's long-lived connection is the
    agent for background work), and ``run_foreground_agent`` calls it for
    ``finishup server connect --agent``. After the merge it becomes::

        if workspace_locator is None or target.claim_salt is None:
            return NO_BINDING
        salt = base64.b64decode(target.claim_salt, validate=True)
        claim = await finishup.client.workspace_claim.workspace_claim(workspace_locator, salt)
        handler = finishup.client.workspace_agent.WorkspaceAgentHandler(workspace_locator)
        return RemoteWorkspaceBinding(
            claim,
            handler.declaration,
            lambda call, handle: handler.answer(call, workspace_handle=handle),
        )

    and ``service.client._connect_remote_attempt`` passes ``binding.answer`` to the
    ``ServiceClient`` it builds (split/client's agent-serving constructor argument). Until then
    no remote connection claims a workspace or declares an agent, and no path is sent.
    """

    del target, workspace_locator
    return NO_BINDING


async def serve_workspace_calls(
    stream: ControlStream,
    session: ControlSession,
    answer: WorkspaceAnswer,
    *,
    concurrency: int = AGENT_CONCURRENCY,
) -> None:
    """Answer ``workspace_call`` frames on an agent-only connection until the server closes it.

    The connection makes no calls of its own, so every frame it receives must be a workspace call
    of this session's service instance and generation; anything else ends the loop as
    ``frame_invalid``. Each call runs in a worker thread (the handler blocks on Git and the
    filesystem) and its reply is written under one lock, in completion order.
    """

    if type(concurrency) is not int or not 1 <= concurrency <= 32:
        raise ValueError("agent_concurrency_invalid")
    write_lock = asyncio.Lock()
    limiter = asyncio.Semaphore(concurrency)
    tasks: set[asyncio.Task[None]] = set()

    async def handle(call: WorkspaceCall) -> None:
        async with limiter:
            reply = await asyncio.to_thread(answer, call, session.workspace_handle)
        async with write_lock:
            await write_workspace_reply(stream, reply)

    try:
        while True:
            try:
                frame = await read_control_frame(stream, eof_reason="session_closed")
            except ControlProtocolError as error:
                if error.reason == "session_closed":
                    return
                raise
            if not is_workspace_call_frame(frame):
                raise ControlProtocolError("frame_invalid")
            call = parse_workspace_call(frame)
            if (
                call.service_instance_id != session.service_instance_id
                or call.service_generation != session.service_generation
            ):
                raise ControlProtocolError("frame_invalid")
            task = asyncio.create_task(handle(call))
            tasks.add(task)
            task.add_done_callback(tasks.discard)
    finally:
        pending = tuple(tasks)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)


async def open_agent_session(
    transport: ControlTransport,
    binding: RemoteWorkspaceBinding,
    *,
    client_kind: ControlClientKind = ControlClientKind.CLI,
    timeout_seconds: float = _AGENT_HANDSHAKE_SECONDS,
) -> tuple[ControlStream, ControlSession]:
    """Dial ``transport`` and handshake an agent connection that claims ``binding``'s workspace."""

    if binding.claim is None or binding.agent is None:
        raise AgentSessionError("workspace_agent_unavailable")
    stream: ControlStream | None = None
    try:
        async with asyncio.timeout(timeout_seconds):
            stream = await transport.connect()
            session = await client_handshake(
                stream,
                client_kind,
                __version__,
                workspace_claim=binding.claim,
                workspace_agent=binding.agent,
            )
    except BaseException:
        if stream is not None:
            with contextlib.suppress(Exception):
                await stream.aclose()
        raise
    return stream, session


async def run_foreground_agent(
    target: ServerTarget, root: Path, workspace_locator: WorkspaceLocator
) -> None:
    """INTEGRATION POINT (CLI) — serve this workspace's calls until the server closes the session.

    ``finishup server connect NAME --agent`` runs this in the foreground, for owners who drive a
    remote target from the CLI only (no MCP bridge holds a connection for background work). It
    needs ``remote_workspace_binding`` to produce a binding, so until split/client and
    split/server merge it refuses with ``workspace_agent_unavailable`` before dialling.
    """

    from finishup.client.transports import TransportError

    binding = await remote_workspace_binding(target, workspace_locator)
    if binding.answer is None:
        raise AgentSessionError("workspace_agent_unavailable")
    transport = transport_for_target(target, root)
    try:
        stream, session = await open_agent_session(transport, binding)
    except TransportError as error:
        raise AgentSessionError("service_unavailable", phase=error.phase) from None
    except (ControlProtocolError, TimeoutError):
        raise AgentSessionError("service_unavailable", phase="remote_unreachable") from None
    try:
        if session.workspace_handle is None:
            # The server derived no handle (its vault is locked, say): no call can name us.
            raise AgentSessionError("workspace_agent_unavailable")
        await serve_workspace_calls(stream, session, binding.answer)
    finally:
        with contextlib.suppress(Exception):
            await stream.aclose()


async def remote_background_drain(target: ServerTarget, root: Path) -> None:
    """INTEGRATION POINT — wired after split/client merges.

    The MCP bridge runs this for the life of its process when its active root is a remote target
    (``start_remote_background_work``), so what hooks captured under ``<root>/state`` (the
    observation outbox and the legacy spool) reaches the server between hook passes. After the
    merge it loops over split/client's drain helper on a ``connect_service`` connection, with a
    bounded pause between passes, until cancelled. Until then there is nothing to drain and it
    returns at once; hooks still drain their own pass.
    """

    del target, root


def start_remote_background_work() -> asyncio.Task[None] | None:
    """Start the bridge's background work for a remote active root; ``None`` for a local root.

    A local root (the everyday server, an isolated root, a named local server) starts nothing,
    and a root whose record cannot be read starts nothing either: the bridge's own connection
    reports that refusal.
    """

    from finishup.client.targets import TargetError, active_target_record, target_root

    try:
        record = active_target_record()
    except TargetError:
        return None
    if record is None or not record.is_remote:
        return None
    return asyncio.create_task(remote_background_drain(record, target_root(record.target_id)))
