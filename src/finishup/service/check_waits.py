"""Bounded service-owned check waits; durable recovery stays in the task ledger."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable

from finishup.ports.control import ControlError
from finishup.protocol.errors import PublicErrorCode, PublicOperationError

EXPLICIT_CONTROL_CANCEL = "explicit_control_cancel"


class CheckWaits:
    """Keep an admitted check alive when its client stops waiting, without caching results."""

    def __init__(self) -> None:
        self._tasks: dict[tuple[str, str], tuple[str, asyncio.Task[object]]] = {}
        self._closed = False

    async def run(
        self,
        key: tuple[str, str],
        digest: str,
        operation: Callable[[], Awaitable[object]],
        deadline_ms: int | None,
    ) -> object:
        if self._closed:
            raise ControlError("service_draining", retryable=True)
        prior = self._tasks.get(key)
        if prior is not None:
            if prior[0] != digest:
                raise PublicOperationError(
                    PublicErrorCode.IDEMPOTENCY_CONFLICT, "The request identity conflicts.", False
                )
            raise PublicOperationError(
                PublicErrorCode.OPERATION_PENDING,
                "The check is still running. Retry the same request_id to recover its result.",
                True,
            )
        if len(self._tasks) >= 8:
            raise ControlError("service_unavailable", retryable=True)

        async def execute() -> object:
            return await operation()

        task = asyncio.create_task(execute())
        self._tasks[key] = (digest, task)

        def completed(done: asyncio.Task[object]) -> None:
            if self._tasks.get(key) == (digest, done):
                self._tasks.pop(key)
            if not done.cancelled():
                # Retrieve detached exceptions; connected waiters still receive the original.
                done.exception()

        task.add_done_callback(completed)
        try:
            async with asyncio.timeout(None if deadline_ms is None else deadline_ms / 1000):
                # wait() leaves the owned task alive without installing shield's late-error
                # logger after the waiter is cancelled (Python 3.14). Our callback observes it.
                await asyncio.wait((task,))
                return task.result()
        except TimeoutError as exc:
            raise ControlError("request_timeout", retryable=True) from exc
        except asyncio.CancelledError as exc:
            if exc.args == (EXPLICIT_CONTROL_CANCEL,):
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            raise

    async def close(self) -> None:
        self._closed = True
        tasks = tuple(task for _, task in self._tasks.values())
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


class CheckReadWindow:
    """Admit bounded operation-status reads while a service-owned check holds the dispatch gates.

    A semantic check can hold the maintenance and observation gates for many minutes. Its live
    structural progress (issue #571 A2) is only useful if ``status view=operation`` can be read
    meanwhile. The window is open only while a detached check owns both gates, so maintenance,
    recovery, and observation sweeps are still excluded for as long as a reader runs: the owner
    closes the window and drains every admitted reader before it releases the gates. Every other
    request keeps waiting on the gates as before.
    """

    def __init__(self) -> None:
        self._open = False
        self._readers = 0
        self._drained = asyncio.Event()
        self._drained.set()

    @property
    def admits_readers(self) -> bool:
        return self._open

    def open(self) -> None:
        self._open = True

    async def close(self) -> None:
        self._open = False
        await self._drained.wait()

    def enter(self) -> None:
        if not self._open:
            raise RuntimeError("check_read_window_closed")
        self._readers += 1
        self._drained.clear()

    def leave(self) -> None:
        if self._readers <= 0:
            raise RuntimeError("check_read_window_unbalanced")
        self._readers -= 1
        if self._readers == 0:
            self._drained.set()
