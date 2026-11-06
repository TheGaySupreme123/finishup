"""Gateway sessions: one REST session is one ordinary control connection to the daemon.

``POST /v1/sessions`` opens a session: the gateway connects to the daemon's owner-only control
endpoint as the same user, forwards the client's hello frame byte for byte, and keeps the
connection. Calls, cancels and ``workspace_reply`` frames are forwarded on it unchanged; a
reader task files every frame the daemon sends — a result by its ``rpc_id``, a server frame
(``workspace_call``) in the session's frame queue for the client's long-poll.

Delivery is at most once. A result is kept per ``(sid, rpc_id)`` until it is fetched, and stays
readable for a minute afterwards (bounded in bytes) so a client whose answer was lost in transit
polls it instead of posting again; a duplicate post of a pending or unfetched ``rpc_id`` is
answered from that slot and never sent to the daemon again, and a post of an ``rpc_id`` already
delivered is refused as ``frame_invalid``.

A cancel reaches the daemon only while its call runs there, in the order the client wrote them:
the daemon ends a connection whose cancel names a call it is not running (and every call on it
with it). A cancel for a call that already finished, or that the gateway answered itself (a scope
refusal), is dropped, since that result is final. A cancel and its call are separate HTTP requests
and may arrive in either order; one that arrives first is held (bounded, briefly) and forwarded
right after its call.

A session ends when its upstream closes, when its key no longer authenticates, after
``SESSION_IDLE_SECONDS`` without a request (closing the upstream so the daemon's idle relock and
idle stop still work), or on ``DELETE``. A session whose hello declared a workspace agent also
ends once no ``GET …/frames`` long-poll has begun for ``AGENT_POLL_GRACE_SECONDS``: its client
keeps one going while it lives, so a client that died without ``DELETE`` stops being the agent
the daemon routes workspace calls to well before the idle bound.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import secrets
import struct
import time
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Final

from finishup.protocol.rest_binding import (
    MAX_SESSIONS_PER_KEY,
    MAX_WAIT_MS,
    SESSION_IDLE_SECONDS,
    KeyScope,
)
from finishup.service.control_protocol import (
    MAX_ACTIVE_REQUESTS_PER_SESSION,
    ControlFrame,
    ControlProtocolError,
    ControlStream,
    encode_control_frame,
    read_control_frame,
)

__all__ = [
    "AGENT_POLL_GRACE_SECONDS",
    "GatewaySession",
    "SessionLimit",
    "SessionRegistry",
    "UpstreamStream",
]

_FRAME_QUEUE: Final = 64
_DELIVERED_MEMORY: Final = 1_024
# A delivered result stays readable this long, within this many bytes per session, so a client
# whose answer was lost in transit can fetch it by polling instead of posting the call again.
_RETAIN_SECONDS: Final = 60.0
_RETAIN_BYTES: Final = 8 * 1_048_576
# A live agent client begins a frames long-poll at least every ``MAX_WAIT_MS``; this adds room for
# a slow round trip and a fresh TLS connection.
AGENT_POLL_GRACE_SECONDS: Final = MAX_WAIT_MS / 1_000 + 15.0


type UpstreamStream = ControlStream


class SessionLimit(Exception):
    """The key already holds ``MAX_SESSIONS_PER_KEY`` sessions, or a session its call limit."""


def _new_sid() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")


@dataclass(eq=False)
class GatewaySession:
    """One REST session and its upstream control connection."""

    sid: str
    key_id: str
    scope: KeyScope
    claim_bound: bool
    agent: bool
    upstream: UpstreamStream
    service_instance_id: str
    service_generation: str
    last_seen: float = field(default_factory=time.monotonic)
    # When the latest ``GET …/frames`` long-poll began (the session's creation before the first).
    poll_started: float = field(default_factory=time.monotonic)
    closed: asyncio.Event = field(default_factory=asyncio.Event)
    _results: dict[str, asyncio.Future[bytes]] = field(
        default_factory=dict[str, "asyncio.Future[bytes]"]
    )
    _delivered: deque[str] = field(default_factory=deque[str])
    _retained: dict[str, tuple[bytes, float]] = field(
        default_factory=dict[str, tuple[bytes, float]]
    )
    # Cancels that arrived before their call: target rpc_id -> (payload, expiry).
    _early_cancels: dict[str, tuple[bytes, float]] = field(
        default_factory=dict[str, tuple[bytes, float]]
    )
    _frames: asyncio.Queue[bytes] = field(
        default_factory=lambda: asyncio.Queue[bytes](maxsize=_FRAME_QUEUE)
    )
    _write_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    _reader: asyncio.Task[None] | None = None

    def touch(self) -> None:
        self.last_seen = time.monotonic()

    def agent_lapsed(self, now: float, grace: float) -> bool:
        """Whether this agent session's client stopped polling for server frames (it died)."""

        return self.agent and now - self.poll_started >= grace

    def start(self) -> None:
        self._reader = asyncio.create_task(self._read_upstream())

    async def _read_upstream(self) -> None:
        try:
            while True:
                frame = await read_control_frame(self.upstream)
                payload = encode_control_frame(frame)[4:]
                if frame.get("kind") == "workspace_call":
                    if not self.agent:
                        return
                    await self._frames.put(payload)
                    continue
                rpc_id = frame.get("rpc_id")
                slot = self._results.get(rpc_id) if type(rpc_id) is str else None
                if slot is None or slot.done():
                    return
                slot.set_result(payload)
        except (ControlProtocolError, OSError, asyncio.CancelledError):
            return
        except Exception:
            return
        finally:
            self.closed.set()

    def delivered(self, rpc_id: str) -> bool:
        return rpc_id in self._delivered

    def slot(self, rpc_id: str) -> asyncio.Future[bytes] | None:
        return self._results.get(rpc_id)

    def known(self, rpc_id: str) -> bool:
        """Whether a result for ``rpc_id`` is pending, unfetched, or recently delivered."""

        self._expire_retained()
        return rpc_id in self._results or rpc_id in self._retained

    def _expire_retained(self) -> None:
        now = time.monotonic()
        for rpc_id, (_payload, expires) in tuple(self._retained.items()):
            if expires <= now:
                del self._retained[rpc_id]

    def _retain(self, rpc_id: str, payload: bytes) -> None:
        self._expire_retained()
        self._retained[rpc_id] = (payload, time.monotonic() + _RETAIN_SECONDS)
        while sum(len(held) for held, _expires in self._retained.values()) > _RETAIN_BYTES:
            del self._retained[next(iter(self._retained))]

    async def forward(self, payload: bytes) -> None:
        """Write one already-validated frame payload upstream, prefixed, under the write lock."""

        async with self._write_lock:
            await self._write(payload)

    async def _write(self, payload: bytes) -> None:
        await self.upstream.send_all(struct.pack(">I", len(payload)) + payload)

    async def forward_cancel(self, target_rpc_id: str, payload: bytes) -> None:
        """Forward one validated cancel only while its call runs upstream; see the module notes."""

        async with self._write_lock:
            slot = self._results.get(target_rpc_id)
            if slot is not None:
                if not slot.done():
                    await self._write(payload)
                return
            if target_rpc_id in self._delivered or target_rpc_id in self._retained:
                return
            now = time.monotonic()
            for held, (_payload, expires) in tuple(self._early_cancels.items()):
                if expires <= now:
                    del self._early_cancels[held]
            if len(self._early_cancels) < MAX_ACTIVE_REQUESTS_PER_SESSION:
                self._early_cancels[target_rpc_id] = (payload, now + _RETAIN_SECONDS)

    async def forward_call(self, rpc_id: str, payload: bytes) -> asyncio.Future[bytes]:
        """Forward one call once and return the slot its result lands in."""

        if len(self._results) >= MAX_ACTIVE_REQUESTS_PER_SESSION:
            raise SessionLimit
        slot: asyncio.Future[bytes] = asyncio.get_running_loop().create_future()
        self._results[rpc_id] = slot
        try:
            await self.forward(payload)
        except BaseException:
            self._results.pop(rpc_id, None)
            raise
        early = self._early_cancels.pop(rpc_id, None)
        if early is not None and early[1] > time.monotonic():
            # Its cancel overtook it on another request: send it now, after the call.
            await self.forward_cancel(rpc_id, early[0])
        return slot

    def take(self, rpc_id: str) -> bytes | None:
        """The finished result for ``rpc_id``, removed from its slot; ``None`` while pending."""

        slot = self._results.get(rpc_id)
        if slot is None:
            retained = self._retained.get(rpc_id)
            return None if retained is None else retained[0]
        if not slot.done() or slot.cancelled():
            return None
        del self._results[rpc_id]
        self._delivered.append(rpc_id)
        while len(self._delivered) > _DELIVERED_MEMORY:
            self._delivered.popleft()
        payload = slot.result()
        self._retain(rpc_id, payload)
        return payload

    async def wait_result(self, rpc_id: str, seconds: float) -> bytes | None:
        slot = self._results.get(rpc_id)
        if slot is None:
            return self.take(rpc_id)
        if not slot.done():
            closed = asyncio.ensure_future(self.closed.wait())
            try:
                await asyncio.wait(
                    (asyncio.shield(slot), closed),
                    timeout=seconds,
                    return_when=asyncio.FIRST_COMPLETED,
                )
            finally:
                closed.cancel()
        return self.take(rpc_id)

    async def next_frame(self, seconds: float) -> bytes | None:
        """The next server frame (``workspace_call``), or ``None`` after ``seconds``."""

        self.poll_started = time.monotonic()
        with contextlib.suppress(asyncio.QueueEmpty):
            return self._frames.get_nowait()
        getter = asyncio.ensure_future(self._frames.get())
        closed = asyncio.ensure_future(self.closed.wait())
        try:
            await asyncio.wait(
                (getter, closed), timeout=seconds, return_when=asyncio.FIRST_COMPLETED
            )
        finally:
            closed.cancel()
        if not getter.done():
            # A cancelled ``Queue.get`` leaves its item queued for the next poll.
            getter.cancel()
            await asyncio.gather(getter, return_exceptions=True)
        return None if getter.cancelled() else getter.result()

    async def close(self) -> None:
        self.closed.set()
        if self._reader is not None:
            self._reader.cancel()
            await asyncio.gather(self._reader, return_exceptions=True)
        for slot in self._results.values():
            if not slot.done():
                slot.cancel()
        with contextlib.suppress(Exception):
            await self.upstream.aclose()


type UpstreamConnector = Callable[[], Awaitable[UpstreamStream]]


@dataclass(frozen=True, slots=True)
class OpenedSession:
    """What opening a session produced: the HTTP status and body, and the live session."""

    status: int
    body: bytes
    session: GatewaySession | None


class SessionRegistry:
    """Every live session, bounded per key, expired after idle."""

    def __init__(
        self,
        connect_upstream: UpstreamConnector,
        *,
        idle_seconds: float = SESSION_IDLE_SECONDS,
        per_key: int = MAX_SESSIONS_PER_KEY,
        agent_poll_grace_seconds: float = AGENT_POLL_GRACE_SECONDS,
    ) -> None:
        self._connect = connect_upstream
        self._idle = idle_seconds
        self._per_key = per_key
        self._agent_grace = agent_poll_grace_seconds
        self._sessions: dict[str, GatewaySession] = {}
        # Sessions being opened, per key: they count against the bound from before the first
        # await, so concurrent opens of one key cannot all pass it.
        self._opening: dict[str, int] = {}

    def __len__(self) -> int:
        return len(self._sessions)

    def count_for(self, key_id: str) -> int:
        """Sessions of ``key_id``, open or being opened."""

        live = sum(1 for session in self._sessions.values() if session.key_id == key_id)
        return live + self._opening.get(key_id, 0)

    async def open(
        self,
        *,
        key_id: str,
        scope: KeyScope,
        hello: ControlFrame,
        hello_payload: bytes,
        manifest_digest: str,
    ) -> OpenedSession:
        """Forward the hello on a fresh upstream; register the session when it was admitted.

        ``201`` with the daemon's hello-result for an admitted session; ``409`` with the daemon's
        own hello-result when it answered a manifest mismatch (it then closes the connection).
        ``SessionLimit`` when the key holds its maximum; ``ControlProtocolError`` when the daemon
        closed without answering.
        """

        if self.count_for(key_id) >= self._per_key:
            raise SessionLimit
        self._opening[key_id] = self._opening.get(key_id, 0) + 1
        try:
            return await self._open(
                key_id=key_id,
                scope=scope,
                hello=hello,
                hello_payload=hello_payload,
                manifest_digest=manifest_digest,
            )
        finally:
            remaining = self._opening[key_id] - 1
            if remaining:
                self._opening[key_id] = remaining
            else:
                del self._opening[key_id]

    async def _open(
        self,
        *,
        key_id: str,
        scope: KeyScope,
        hello: ControlFrame,
        hello_payload: bytes,
        manifest_digest: str,
    ) -> OpenedSession:
        upstream = await self._connect()
        try:
            await upstream.send_all(struct.pack(">I", len(hello_payload)) + hello_payload)
            answer = await read_control_frame(upstream, eof_reason="handshake_rejected")
        except BaseException:
            with contextlib.suppress(Exception):
                await upstream.aclose()
            raise
        body = encode_control_frame(answer)[4:]
        if (
            answer.get("schema_manifest_digest") != hello.get("schema_manifest_digest")
            or answer.get("schema_manifest_digest") != manifest_digest
            or "workspace_binding" not in answer
        ):
            with contextlib.suppress(Exception):
                await upstream.aclose()
            return OpenedSession(409, body, None)
        session = GatewaySession(
            sid=_new_sid(),
            key_id=key_id,
            scope=scope,
            claim_bound=answer.get("workspace_binding") == "client_claim",
            agent=hello.get("workspace_agent") is not None,
            upstream=upstream,
            service_instance_id=str(answer["service_instance_id"]),
            service_generation=str(answer["service_generation"]),
        )
        self._sessions[session.sid] = session
        session.start()
        return OpenedSession(201, body, session)

    def get(self, sid: str, key_id: str) -> GatewaySession | None:
        """The live session ``sid`` of ``key_id``; a session of another key is not found."""

        session = self._sessions.get(sid)
        if session is None or session.key_id != key_id:
            return None
        if session.closed.is_set():
            asyncio.ensure_future(self.close(sid))
            return None
        return session

    async def close(self, sid: str) -> bool:
        session = self._sessions.pop(sid, None)
        if session is None:
            return False
        await session.close()
        return True

    async def close_keys(self, key_ids: frozenset[str]) -> int:
        """Close every session of keys that no longer authenticate; how many closed."""

        doomed = [sid for sid, session in self._sessions.items() if session.key_id in key_ids]
        for sid in doomed:
            await self.close(sid)
        return len(doomed)

    async def sweep(self) -> int:
        """Close sessions idle past the bound, whose upstream ended, or whose agent client stopped
        polling; how many closed."""

        now = time.monotonic()
        doomed = [
            sid
            for sid, session in self._sessions.items()
            if session.closed.is_set()
            or now - session.last_seen >= self._idle
            or session.agent_lapsed(now, self._agent_grace)
        ]
        for sid in doomed:
            await self.close(sid)
        return len(doomed)

    async def close_all(self) -> None:
        for sid in tuple(self._sessions):
            await self.close(sid)
