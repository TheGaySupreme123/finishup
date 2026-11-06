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

A handle names one worktree (the server derives it from the claim's commitment and its worktree
digest), so every channel under one handle serves the same tree. A channel whose claim names
another worktree is never admitted under a handle that already has a live one. A live control
call prefers the agent its own connection offered, when that connection offered one.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import contextlib
import re
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
# Operations that read and change nothing on the client: one whose connection dropped before it
# answered is sent once more to another live connection of the same claim. An approved check may
# already have run, so it is never sent twice.
_REPLAYABLE_OPERATIONS: Final = frozenset(
    operation
    for operation in WorkspaceOperation
    if operation is not WorkspaceOperation.RUN_APPROVED_CHECK
)
_COMPONENT: Final = "service.workspace_hub"
_WORKTREE_DIGEST: Final = re.compile(r"^sha256:[0-9a-f]{64}$", re.ASCII)

type WorkspaceCallWriter = Callable[[WorkspaceCall], Awaitable[None]]


class _CallScope:
    """What the work below serves, set by the daemon around each dispatched control call.

    ``live``: a live control call (the caller's connection is open and waiting), which waits the
    shorter bound for an agent; background work (verification supervisors, sweeps, recovered
    jobs) runs outside any scope and waits longer. ``channel``: the agent the serving connection
    itself offered, preferred for its own handle.
    """

    __slots__ = ("channel", "live")

    def __init__(self, *, live: bool, channel: WorkspaceAgentChannel | None) -> None:
        self.live = live
        self.channel = channel

    def __repr__(self) -> str:
        return "_CallScope(<redacted>)"


_SCOPE: ContextVar[_CallScope | None] = ContextVar("finishup_workspace_call_scope", default=None)


@contextlib.contextmanager
def live_call_scope(channel: WorkspaceAgentChannel | None = None) -> Generator[None]:
    """Mark the work below as serving a live control call (the shorter agent wait).

    ``channel`` is the agent the serving connection itself offered, if any: a call for its handle
    goes to it ahead of any other live channel for that handle.
    """

    if channel is not None and type(channel) is not WorkspaceAgentChannel:
        raise TypeError("workspace_agent_channel_invalid")
    token = _SCOPE.set(_CallScope(live=True, channel=channel))
    try:
        yield
    finally:
        _SCOPE.reset(token)


def in_live_call() -> bool:
    scope = _SCOPE.get()
    return scope is not None and scope.live


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
        "worktree",
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
        worktree: str | None = None,
    ) -> None:
        if not workspace_handle_valid(handle):
            raise ValueError("workspace_handle_invalid")
        if type(declaration) is not WorkspaceAgentDeclaration:
            raise TypeError("workspace_agent_invalid")
        if not callable(writer):
            raise TypeError("workspace_call_writer_invalid")
        if worktree is not None and (
            type(worktree) is not str or _WORKTREE_DIGEST.fullmatch(worktree) is None
        ):
            raise ValueError("workspace_worktree_invalid")
        self.handle = handle
        # The claim's keyed worktree digest, when the connection's hello carried one.
        self.worktree = worktree
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
        worktree: str | None = None,
    ) -> WorkspaceAgentChannel:
        """Admit one agent-declaring connection under its claim's handle.

        ``worktree`` is the claim's keyed worktree digest. A handle names one worktree, so a
        connection whose digest differs from a live channel's under the same handle is refused
        (``ValueError("workspace_agent_worktree_conflict")``; the daemon closes it) rather than
        ever answering another worktree's calls.
        """

        self.bind_loop()
        channel = WorkspaceAgentChannel(
            handle=handle,
            declaration=declaration,
            service_instance_id=service_instance_id,
            service_generation=service_generation,
            writer=writer,
            worktree=worktree,
        )
        condition = self._condition()
        async with condition:
            live = [item for item in self._channels.get(handle, ()) if not item.closed]
            if worktree is not None and any(
                item.worktree is not None and item.worktree != worktree for item in live
            ):
                _record("workspace_agent_registered", "worktree_conflict")
                raise ValueError("workspace_agent_worktree_conflict")
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
        self,
        handle: str,
        operation: WorkspaceOperation,
        preferred: WorkspaceAgentChannel | None = None,
    ) -> WorkspaceAgentChannel | None:
        if (
            preferred is not None
            and not preferred.closed
            and preferred.handle == handle
            and preferred.declares(operation)
            and any(channel is preferred for channel in self._channels.get(handle, ()))
        ):
            # The serving connection's own agent: the one in front of the caller's worktree.
            return preferred
        live = [channel for channel in self._channels.get(handle, ()) if not channel.closed]
        declaring = [channel for channel in live if channel.declares(operation)]
        if declaring:
            # Every channel under a handle serves its one worktree; the newest connection is the
            # agent most likely still in front of it.
            return declaring[-1]
        if live:
            raise WorkspaceAgentUnavailable("operation_not_declared")
        return None

    def _other_live_channel(
        self, handle: str, operation: WorkspaceOperation, previous: WorkspaceAgentChannel
    ) -> WorkspaceAgentChannel | None:
        """Another live connection that declares ``operation`` for ``handle``, right now."""

        live = [
            channel
            for channel in self._channels.get(handle, ())
            if channel is not previous and not channel.closed and channel.declares(operation)
        ]
        return live[-1] if live else None

    async def _channel_for(
        self,
        handle: str,
        operation: WorkspaceOperation,
        wait_seconds: float,
        preferred: WorkspaceAgentChannel | None = None,
    ) -> WorkspaceAgentChannel:
        condition = self._condition()
        try:
            async with asyncio.timeout(max(0.0, wait_seconds)):
                async with condition:
                    while True:
                        channel = self._live_channel(handle, operation, preferred)
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

        return await self._call(
            handle,
            operation,
            arguments,
            timeout_seconds=timeout_seconds,
            background=background,
            scope=_SCOPE.get(),
        )

    async def _call(
        self,
        handle: str,
        operation: WorkspaceOperation,
        arguments: object,
        *,
        timeout_seconds: float,
        background: bool | None,
        scope: _CallScope | None,
    ) -> Any:  # noqa: ANN401 - the operation's own result type
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
            background = scope is None or not scope.live
        wait = self._background_wait if background else self._inline_wait
        preferred = None if scope is None else scope.channel
        try:
            channel = await self._channel_for(handle, spec.operation, wait, preferred)
            try:
                reply = await self._exchange(channel, spec.operation, wire, size, timeout_seconds)
            except WorkspaceAgentUnavailable as exc:
                # Several connections of one client may serve a handle's one worktree (ADR-051):
                # when the one asked drops mid-call and another is live now, a read is asked
                # there once more.
                other = self._other_live_channel(handle, spec.operation, channel)
                if (
                    exc.reason != "agent_disconnected"
                    or spec.operation not in _REPLAYABLE_OPERATIONS
                    or other is None
                ):
                    raise
                reply = await self._exchange(other, spec.operation, wire, size, timeout_seconds)
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
        # The worker thread runs in a copy of its caller's context: what that call serves.
        scope = _SCOPE.get()
        background = scope is None or not scope.live
        wait = self._background_wait if background else self._inline_wait
        future = asyncio.run_coroutine_threadsafe(
            self._call(
                handle,
                operation,
                arguments,
                timeout_seconds=timeout_seconds,
                background=background,
                scope=scope,
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
