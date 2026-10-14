"""Fail-closed user-session lock and system-suspend event normalization."""

from __future__ import annotations

import asyncio
import sys
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
from enum import Enum
from typing import Protocol

from finishup.service.lifecycle import SessionSecurityEvent

__all__ = [
    "LinuxLogin1Backend",
    "MacOSSessionBackend",
    "SessionEventMonitor",
    "SessionMonitorCapability",
    "SessionMonitorError",
    "SessionMonitorReason",
]


class SessionMonitorReason(str, Enum):  # noqa: UP042 - bounded diagnostic vocabulary
    UNSUPPORTED_PLATFORM = "unsupported_platform"
    BACKEND_UNAVAILABLE = "backend_unavailable"
    SUBSCRIPTION_FAILED = "subscription_failed"
    MONITOR_LOST = "monitor_lost"
    CLOSED = "closed"


class SessionMonitorError(Exception):
    __slots__ = ("reason",)

    reason: SessionMonitorReason

    def __init__(self, reason: SessionMonitorReason) -> None:
        if type(reason) is not SessionMonitorReason:
            raise TypeError("session_monitor_reason_invalid")
        self.reason = reason
        super().__init__(reason.value)


@dataclass(frozen=True, slots=True)
class SessionMonitorCapability:
    platform: str
    backend: str
    active: bool
    lock_events: bool
    suspend_events: bool

    def __post_init__(self) -> None:
        if (
            self.platform not in {"darwin", "linux", "unsupported"}
            or self.backend not in {"macos_session", "linux_login1", "unsupported"}
            or type(self.active) is not bool
            or type(self.lock_events) is not bool
            or type(self.suspend_events) is not bool
        ):
            raise TypeError("session_monitor_capability_invalid")
        if self.active and not (self.lock_events and self.suspend_events):
            raise ValueError("session_monitor_capability_incomplete")


type EventSink = Callable[[SessionSecurityEvent], Awaitable[None]]
type Unsubscribe = Callable[[], Awaitable[None]]
type Subscribe = Callable[[EventSink], Awaitable[Unsubscribe]]
type LifecycleCallback = Callable[[SessionSecurityEvent], Awaitable[None]]


class _SessionBackend(Protocol):
    @property
    def capability(self) -> SessionMonitorCapability: ...

    async def start(self, sink: EventSink) -> None: ...

    async def close(self) -> None: ...


class _InjectedBackend:
    """Common subscription owner for release-tested platform API adapters."""

    __slots__ = ("_capability", "_closed", "_subscribe", "_unsubscribe")

    def __init__(self, capability: SessionMonitorCapability, subscribe: Subscribe | None) -> None:
        self._capability = capability
        self._subscribe = subscribe
        self._unsubscribe: Unsubscribe | None = None
        self._closed = False

    @property
    def capability(self) -> SessionMonitorCapability:
        return replace(self._capability, active=self._unsubscribe is not None and not self._closed)

    async def start(self, sink: EventSink) -> None:
        if self._closed:
            raise SessionMonitorError(SessionMonitorReason.CLOSED)
        if self._subscribe is None:
            raise SessionMonitorError(SessionMonitorReason.BACKEND_UNAVAILABLE)
        try:
            unsubscribe = await self._subscribe(sink)
        except SessionMonitorError:
            raise
        except Exception as exc:
            raise SessionMonitorError(SessionMonitorReason.SUBSCRIPTION_FAILED) from exc
        if not callable(unsubscribe):
            raise SessionMonitorError(SessionMonitorReason.SUBSCRIPTION_FAILED)
        self._unsubscribe = unsubscribe

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        unsubscribe, self._unsubscribe = self._unsubscribe, None
        if unsubscribe is not None:
            await unsubscribe()


class MacOSSessionBackend(_InjectedBackend):
    """macOS session-notification adapter selected only with a verified API binding."""

    def __init__(self, subscribe: Subscribe | None = None) -> None:
        super().__init__(
            SessionMonitorCapability("darwin", "macos_session", False, True, True), subscribe
        )


class LinuxLogin1Backend(_InjectedBackend):
    """Linux login1 D-Bus adapter selected only with a verified user-session binding."""

    def __init__(self, subscribe: Subscribe | None = None) -> None:
        super().__init__(
            SessionMonitorCapability("linux", "linux_login1", False, True, True), subscribe
        )


class _UnsupportedBackend:
    @property
    def capability(self) -> SessionMonitorCapability:
        return SessionMonitorCapability("unsupported", "unsupported", False, False, False)

    async def start(self, sink: EventSink) -> None:
        del sink
        raise SessionMonitorError(SessionMonitorReason.UNSUPPORTED_PLATFORM)

    async def close(self) -> None:
        return None


class SessionEventMonitor:
    """Normalize platform notifications and fail closed when the subscription is lost."""

    def __init__(self, backend: _SessionBackend | None = None) -> None:
        if backend is None:
            backend = (
                MacOSSessionBackend()
                if sys.platform == "darwin"
                else LinuxLogin1Backend()
                if sys.platform.startswith("linux")
                else _UnsupportedBackend()
            )
        self._backend = backend
        self._callback: LifecycleCallback | None = None
        self._starting = False
        self._started = False
        self._closed = False
        self._lock = asyncio.Lock()
        self._session_locked = False
        self._suspended = False
        self._lost = False

    @property
    def capability(self) -> SessionMonitorCapability:
        capability = self._backend.capability
        return replace(
            capability,
            active=(
                capability.active
                and self._started
                and not self._starting
                and not self._closed
                and not self._lost
            ),
        )

    async def start(self, callback: LifecycleCallback) -> None:
        if not callable(callback):
            raise TypeError("session_monitor_callback_invalid")
        async with self._lock:
            if self._closed:
                raise SessionMonitorError(SessionMonitorReason.CLOSED)
            if self._started:
                return
            if self._starting:
                raise SessionMonitorError(SessionMonitorReason.SUBSCRIPTION_FAILED)
            self._callback = callback
            self._starting = True
        try:
            await self._backend.start(self._receive)
            capability = self._backend.capability
            if not capability.active or not capability.lock_events or not capability.suspend_events:
                await self._backend.close()
                raise SessionMonitorError(SessionMonitorReason.SUBSCRIPTION_FAILED)
        except BaseException:
            async with self._lock:
                self._callback = None
                self._starting = False
            raise
        async with self._lock:
            if self._closed:
                self._starting = False
                self._callback = None
                await self._backend.close()
                raise SessionMonitorError(SessionMonitorReason.CLOSED)
            self._starting = False
            self._started = True

    async def _receive(self, kind: SessionSecurityEvent) -> None:
        if type(kind) is not SessionSecurityEvent:
            await self._emit_lost()
            return
        callback: LifecycleCallback | None = None
        event: SessionSecurityEvent | None = None
        async with self._lock:
            if not (self._started or self._starting) or self._closed or self._lost:
                return
            if kind is SessionSecurityEvent.MONITOR_LOST:
                self._lost = True
                event = kind
            elif kind is SessionSecurityEvent.USER_SESSION_LOCKED:
                if not self._session_locked:
                    self._session_locked = True
                    event = kind
            elif kind is SessionSecurityEvent.USER_SESSION_UNLOCKED:
                if self._session_locked:
                    self._session_locked = False
                    event = kind
            elif kind is SessionSecurityEvent.SYSTEM_SUSPEND:
                if not self._suspended:
                    self._suspended = True
                    event = kind
            elif kind is SessionSecurityEvent.SYSTEM_RESUME and self._suspended:
                self._suspended = False
                event = kind
            callback = self._callback
        if event is not None and callback is not None:
            await callback(event)

    async def _emit_lost(self) -> None:
        await self._receive(SessionSecurityEvent.MONITOR_LOST)

    async def close(self) -> None:
        async with self._lock:
            if self._closed:
                return
            self._closed = True
            self._callback = None
        await self._backend.close()
