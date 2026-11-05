"""The service's registry of client workspace agents and its bounded callback channel (ADR-051).

A client that works with this service from another machine claims its workspace instead of
naming a path, and may offer a workspace agent on the same control connection
(``workspace_agent`` in its hello). The daemon registers such a connection here under the
``client:`` handle it derived from the claim, and unregisters it when the connection closes.

``WorkspaceAgentHub.call`` sends one catalog operation (``finishup.ports.workspace_agent``) to an
agent that holds the handle, through that connection's own write lock, and awaits the correlated
``workspace_reply``. Every wait is bounded: for an agent to appear (5 s inside a live control call,
30 s for background work), for a call slot on the agent's connection, and for the reply. Every
failure is a typed ``WorkspaceAgentUnavailable`` with a closed reason; nothing here logs or raises
a path, an argument or anything the agent sent besides its closed reply reason.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import contextlib
import threading
from collections.abc import Awaitable, Callable, Generator
from contextvars import ContextVar
from typing import Any, Final

from finishup.domain.receipts import CLIENT_ATTESTED
from finishup.observability.logging import record_bounded_event_without_raising
from finishup.ports.control import WorkspaceAgentDeclaration, WorkspaceCall, WorkspaceReply
from finishup.ports.workspace_agent import (
    MAX_WORKSPACE_DEADLINE_MS,
    MAX_WORKSPACE_FRAME_BYTES,
    WorkspaceAgentUnavailable,
    WorkspaceCodecError,
    WorkspaceOperation,
    operation_spec,
    workspace_handle_valid,
)
from finishup.protocol.canonical import canonical_encode
from finishup.protocol.ids import IdKind, new_id

__all__ = [
    "BACKGROUND_AGENT_WAIT_SECONDS",
    "INLINE_AGENT_WAIT_SECONDS",
    "MAX_CALLS_PER_CHANNEL",
    "MAX_PENDING_ARGUMENT_BYTES_PER_CHANNEL",
    "WorkspaceAgentChannel",
    "WorkspaceAgentHub",
    "WorkspaceCallWriter",
    "in_live_call",
    "live_call_scope",
]

# How long a call waits for an agent connection for its workspace to appear.
INLINE_AGENT_WAIT_SECONDS: Final = 5.0
BACKGROUND_AGENT_WAIT_SECONDS: Final = 30.0
# Calls one agent connection serves at once, and the argument bytes they may hold in flight.
MAX_CALLS_PER_CHANNEL: Final = 4
MAX_PENDING_ARGUMENT_BYTES_PER_CHANNEL: Final = 2 * MAX_WORKSPACE_FRAME_BYTES
# Room past a call's own deadline for its reply frame to arrive and be read.
_REPLY_GRACE_SECONDS: Final = 1.0
_COMPONENT: Final = "service.workspace_hub"

# Whether the current work runs inside a live control call (the caller's connection is open and
# waiting), set by the daemon around each dispatched call. Background work (verification
# supervisors, sweeps, recovered jobs) runs outside it and waits longer for an agent.
_LIVE_CALL: ContextVar[bool] = ContextVar("finishup_workspace_live_call", default=False)

type WorkspaceCallWriter = Callable[[WorkspaceCall], Awaitable[None]]


@contextlib.contextmanager
def live_call_scope() -> Generator[None]:
    """Mark the work below as serving a live control call (the shorter agent wait)."""

    token = _LIVE_CALL.set(True)
    try:
        yield
    finally:
        _LIVE_CALL.reset(token)


def in_live_call() -> bool:
    return _LIVE_CALL.get()


def _record(operation: str, reason: str) -> None:
    record_bounded_event_without_raising(component=_COMPONENT, operation=operation, reason=reason)


class WorkspaceAgentChannel:
    """One agent-declaring control connection: its handle, its offer and its pending calls.

    ``writer`` writes one ``workspace_call`` frame under the connection's write lock. The channel
    holds no stream itself; the daemon owns the connection and closes the channel with it.
    """

    __slots__ = (
        "_bytes",
        "_changed",
        "_pending",
        "_pending_bytes",
        "closed",
        "declaration",
        "handle",
        "service_generation",
        "service_instance_id",
        "writer",
    )

    def __init__(
        self,
        *,
        handle: str,
        declaration: WorkspaceAgentDeclaration,
        service_instance_id: str,
        service_generation: str,
        writer: WorkspaceCallWriter,
    ) -> None:
        if not workspace_handle_valid(handle):
            raise ValueError("workspace_handle_invalid")
        if type(declaration) is not WorkspaceAgentDeclaration:
            raise TypeError("workspace_agent_invalid")
        if not callable(writer):
            raise TypeError("workspace_call_writer_invalid")
        self.handle = handle
        self.declaration = declaration
        self.service_instance_id = service_instance_id
        self.service_generation = service_generation
        self.writer = writer
        self.closed = False
        self._pending: dict[str, asyncio.Future[WorkspaceReply]] = {}
        self._pending_bytes: dict[str, int] = {}
        self._bytes = 0
        self._changed = asyncio.Condition()

    def __repr__(self) -> str:
        return "WorkspaceAgentChannel(<redacted>)"

    def declares(self, operation: WorkspaceOperation) -> bool:
        return operation.value in self.declaration.operations

    @property
    def pending_count(self) -> int:
        return len(self._pending)

    def _has_room(self, size: int) -> bool:
        if len(self._pending) >= MAX_CALLS_PER_CHANNEL:
            return False
        # One call alone may always use the whole bound; it was bounded by its own spec.
        return not self._pending or self._bytes + size <= MAX_PENDING_ARGUMENT_BYTES_PER_CHANNEL

    async def _reserve(self, call_id: str, size: int) -> asyncio.Future[WorkspaceReply]:
        async with self._changed:
            await self._changed.wait_for(lambda: self.closed or self._has_room(size))
            if self.closed:
                raise WorkspaceAgentUnavailable("agent_disconnected")
            future: asyncio.Future[WorkspaceReply] = asyncio.get_running_loop().create_future()
            self._pending[call_id] = future
            self._pending_bytes[call_id] = size
            self._bytes += size
            return future

    async def _release(self, call_id: str) -> None:
        async with self._changed:
            self._pending.pop(call_id, None)
            self._bytes -= self._pending_bytes.pop(call_id, 0)
            self._changed.notify_all()

    def deliver(self, reply: WorkspaceReply) -> bool:
        """Resolve the pending call ``reply`` answers; False for one nothing awaits."""

        future = self._pending.get(reply.call_id)
        if future is None or future.done():
            return False
        future.set_result(reply)
        return True

    async def close(self) -> None:
        """Fail every pending call and wake every waiter; idempotent."""

        async with self._changed:
            self.closed = True
            for future in self._pending.values():
                if not future.done():
                    future.set_exception(WorkspaceAgentUnavailable("agent_disconnected"))
            self._changed.notify_all()


class WorkspaceAgentHub:
    """Live agent channels keyed by workspace handle, and the one way to call them."""

    __slots__ = ("_background_wait", "_changed", "_channels", "_inline_wait", "_loop", "_lock")

    def __init__(
        self,
        *,
        inline_wait_seconds: float = INLINE_AGENT_WAIT_SECONDS,
        background_wait_seconds: float = BACKGROUND_AGENT_WAIT_SECONDS,
    ) -> None:
        for bound in (inline_wait_seconds, background_wait_seconds):
            if type(bound) is not float or not 0.0 <= bound <= 300.0:
                raise ValueError("workspace_agent_wait_invalid")
        self._inline_wait = inline_wait_seconds
        self._background_wait = background_wait_seconds
        self._channels: dict[str, list[WorkspaceAgentChannel]] = {}
        self._changed: asyncio.Condition | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._lock = threading.Lock()

    def __repr__(self) -> str:
        return "WorkspaceAgentHub(<redacted>)"

    # --- registration (event loop) -----------------------------------------------------------

    def bind_loop(self, loop: asyncio.AbstractEventLoop | None = None) -> None:
        """Bind the event loop blocking callers reach the hub through; the first binding wins."""

        current = loop if loop is not None else asyncio.get_running_loop()
        with self._lock:
            if self._loop is None or self._loop.is_closed():
                self._loop = current
                self._changed = None

    def _condition(self) -> asyncio.Condition:
        if self._changed is None:
            self._changed = asyncio.Condition()
        return self._changed

    async def register(
        self,
        *,
        handle: str,
        declaration: WorkspaceAgentDeclaration,
        service_instance_id: str,
        service_generation: str,
        writer: WorkspaceCallWriter,
    ) -> WorkspaceAgentChannel:
        """Admit one agent-declaring connection under its claim's handle."""

        self.bind_loop()
        channel = WorkspaceAgentChannel(
            handle=handle,
            declaration=declaration,
            service_instance_id=service_instance_id,
            service_generation=service_generation,
            writer=writer,
        )
        condition = self._condition()
        async with condition:
            self._channels.setdefault(handle, []).append(channel)
            condition.notify_all()
        _record("workspace_agent_registered", "registered")
        return channel

    async def unregister(self, channel: WorkspaceAgentChannel) -> None:
        """Remove a closed connection's channel and fail its pending calls; idempotent."""

        if type(channel) is not WorkspaceAgentChannel:
            raise TypeError("workspace_agent_channel_invalid")
        was_open = not channel.closed
        await channel.close()
        condition = self._condition()
        async with condition:
            live = self._channels.get(channel.handle)
            if live is not None:
                remaining = [item for item in live if item is not channel]
                if remaining:
                    self._channels[channel.handle] = remaining
                else:
                    self._channels.pop(channel.handle, None)
            condition.notify_all()
        if was_open:
            _record("workspace_agent_unregistered", "disconnected")

    def deliver(self, channel: WorkspaceAgentChannel, reply: WorkspaceReply) -> None:
        """Route one reply the channel's connection sent; a reply nothing awaits is dropped."""

        if type(reply) is not WorkspaceReply:
            raise TypeError("workspace_reply_invalid")
        if not channel.deliver(reply):
            # A reply after its call's deadline, or one for a call this service never sent.
            _record("workspace_reply", "unmatched")

    def has_agent(self, handle: str) -> bool:
        return any(not channel.closed for channel in self._channels.get(handle, ()))

    async def close(self) -> None:
        """Fail every pending call on every channel (service shutdown)."""

        for channels in tuple(self._channels.values()):
            for channel in tuple(channels):
                await self.unregister(channel)

    # --- calls ----------------------------------------------------------------------------------

    def _live_channel(
        self, handle: str, operation: WorkspaceOperation
    ) -> WorkspaceAgentChannel | None:
        live = [channel for channel in self._channels.get(handle, ()) if not channel.closed]
        declaring = [channel for channel in live if channel.declares(operation)]
        if declaring:
            # The newest connection is the agent most likely still in front of the workspace.
            return declaring[-1]
        if live:
            raise WorkspaceAgentUnavailable("operation_not_declared")
        return None

    async def _channel_for(
        self, handle: str, operation: WorkspaceOperation, wait_seconds: float
    ) -> WorkspaceAgentChannel:
        condition = self._condition()
        try:
            async with asyncio.timeout(max(0.0, wait_seconds)):
                async with condition:
                    while True:
                        channel = self._live_channel(handle, operation)
                        if channel is not None:
                            return channel
                        await condition.wait()
        except TimeoutError:
            raise WorkspaceAgentUnavailable("no_agent") from None

    async def call(
        self,
        handle: str,
        operation: WorkspaceOperation,
        arguments: object,
        *,
        timeout_seconds: float,
        background: bool | None = None,
    ) -> Any:  # noqa: ANN401 - the operation's own result type (``WorkspaceOperationSpec``)
        """Run one catalog operation on the client's agent for ``handle``; its decoded result.

        ``timeout_seconds`` bounds the agent's answer once the call is sent; the wait for an
        agent connection is bounded separately (``background`` picks the longer wait; by default
        it is decided by whether this work serves a live control call).
        """

        spec = operation_spec(operation)
        if spec is None or not workspace_handle_valid(handle):
            raise ValueError("workspace_call_invalid")
        if type(timeout_seconds) not in {int, float} or not 0 < timeout_seconds <= (
            MAX_WORKSPACE_DEADLINE_MS / 1000
        ):
            raise ValueError("workspace_call_timeout_invalid")
        self.bind_loop()
        try:
            wire = spec.encode_arguments(arguments)
        except WorkspaceCodecError:
            _record("workspace_call", "arguments_invalid")
            raise WorkspaceAgentUnavailable("arguments_invalid") from None
        size = len(canonical_encode(wire))
        if background is None:
            background = not in_live_call()
        wait = self._background_wait if background else self._inline_wait
        try:
            channel = await self._channel_for(handle, spec.operation, wait)
            reply = await self._exchange(channel, spec.operation, wire, size, timeout_seconds)
        except WorkspaceAgentUnavailable as exc:
            _record("workspace_call", exc.reason)
            raise
        if reply.outcome != "ok":
            reason = {
                "unavailable": "agent_unavailable",
                "refused": "agent_refused",
                "failed": "agent_failed",
            }[reply.outcome]
            _record("workspace_call", reason)
            raise WorkspaceAgentUnavailable(reason, reply.reason)
        try:
            decoded = spec.decode_result(reply.result)
        except WorkspaceCodecError:
            _record("workspace_call", "reply_invalid")
            raise WorkspaceAgentUnavailable("reply_invalid") from None
        # What the agent answered is the client's attestation, never a read of this machine.
        _record("workspace_evidence", CLIENT_ATTESTED)
        return decoded

    async def _exchange(
        self,
        channel: WorkspaceAgentChannel,
        operation: WorkspaceOperation,
        wire: dict[str, Any],
        size: int,
        timeout_seconds: float,
    ) -> WorkspaceReply:
        call_id = new_id(IdKind.CONTROL_RPC)
        deadline_ms = max(1, min(MAX_WORKSPACE_DEADLINE_MS, int(timeout_seconds * 1000)))
        reserved = False
        try:
            async with asyncio.timeout(timeout_seconds + _REPLY_GRACE_SECONDS):
                future = await channel._reserve(call_id, size)  # pyright: ignore[reportPrivateUsage]
                reserved = True
                call = WorkspaceCall(
                    kind="workspace_call",
                    protocol_version="1.0",
                    call_id=call_id,
                    service_instance_id=channel.service_instance_id,
                    service_generation=channel.service_generation,
                    operation=operation.value,
                    arguments=wire,  # pyright: ignore[reportArgumentType]
                    deadline_ms=deadline_ms,
                )
                try:
                    await channel.writer(call)
                except TimeoutError:
                    raise
                except Exception:
                    # The connection could not take the frame: the peer is gone.
                    raise WorkspaceAgentUnavailable("agent_disconnected") from None
                return await future
        except TimeoutError:
            raise WorkspaceAgentUnavailable(
                "deadline_exceeded" if reserved else "agent_busy"
            ) from None
        finally:
            if reserved:
                await channel._release(call_id)  # pyright: ignore[reportPrivateUsage]

    def call_blocking(
        self,
        handle: str,
        operation: WorkspaceOperation,
        arguments: object,
        *,
        timeout_seconds: float,
    ) -> Any:  # noqa: ANN401 - the operation's own result type
        """``call`` from a worker thread; never from the hub's own event loop thread.

        A synchronous adapter runs in a worker thread (``asyncio.to_thread``); it waits here for
        the loop to finish the call. The total wait is bounded by the agent wait, the call's
        deadline and a grace, after which the call is cancelled.
        """

        loop = self._loop
        if loop is None or loop.is_closed():
            _record("workspace_call", "hub_unavailable")
            raise WorkspaceAgentUnavailable("hub_unavailable")
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is loop:
            # Waiting here would block the very loop that must deliver the reply.
            _record("workspace_call", "hub_unavailable")
            raise WorkspaceAgentUnavailable("hub_unavailable")
        background = not in_live_call()
        wait = self._background_wait if background else self._inline_wait
        future = asyncio.run_coroutine_threadsafe(
            self.call(
                handle,
                operation,
                arguments,
                timeout_seconds=timeout_seconds,
                background=background,
            ),
            loop,
        )
        try:
            return future.result(wait + timeout_seconds + 2 * _REPLY_GRACE_SECONDS)
        except concurrent.futures.TimeoutError:
            future.cancel()
            _record("workspace_call", "deadline_exceeded")
            raise WorkspaceAgentUnavailable("deadline_exceeded") from None
        except concurrent.futures.CancelledError:
            raise WorkspaceAgentUnavailable("agent_disconnected") from None
