"""Bounded service-owned check waits; durable recovery stays in the task ledger."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Final

from finishup.observability.logging import record_public_error_without_raising
from finishup.ports.control import ControlError
from finishup.protocol.errors import PublicErrorCode, PublicOperationError

EXPLICIT_CONTROL_CANCEL = "explicit_control_cancel"
# Checks the service keeps at once: running, waiting for the dispatch gates, or detached from a
# client that stopped waiting. Each holds an owned task until its operation finishes.
MAX_RETAINED_CHECKS: Final = 8
# A slot frees only when a retained check finishes, and checks that may use AI-powered review
# take the dispatch gates one at a time, so the replay hint is in seconds, not the 1 s of an
# admission race. The ``check_service_busy_same_identity`` directive names the same wait.
CAPACITY_RETRY_AFTER_MS: Final = 30_000
# The refusal is made from in-memory state alone, before the task ledger is read, so it cannot
# say whether anything is recorded under the request identity: a check that finished after its
# client stopped waiting is no longer retained here, yet its result is in the ledger (#746).
_CAPACITY_MESSAGE: Final = (
    f"The FinishUP service already has its limit of {MAX_RETAINED_CHECKS} checks in progress, so "
    "it did not look up or start this check. Wait, then replay the exact request; the replay is "
    "answered from anything already recorded under this request_id."
)


def _capacity_refusal(request_id: str) -> PublicOperationError:
    """Build the retryable refusal for a check over the service's capacity (issue #1309).

    ``BUNDLE_BUSY`` is the public code for a resource another owner holds, here the service's
    check slots. The refusal carries no admission ``reason_code``: those stages promise nothing
    is recorded under the identity, which this branch cannot know. Its own diagnostic operation
    is recorded here and bound, so the correlation id names the capacity refusal.
    """

    refusal = PublicOperationError(
        PublicErrorCode.BUNDLE_BUSY,
        _CAPACITY_MESSAGE,
        True,
        safe_details={
            "continuation": "check_service_busy_same_identity",
            "limit": MAX_RETAINED_CHECKS,
            "retry_after_ms": CAPACITY_RETRY_AFTER_MS,
        },
    )
    return refusal.bind_correlation_id(
        record_public_error_without_raising(
            component="service.check_waits",
            operation="check_service_busy",
            reason=PublicErrorCode.BUNDLE_BUSY.value.lower(),
            request_id=request_id,
        )
    )


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
        if len(self._tasks) >= MAX_RETAINED_CHECKS:
            # Issue #1309: this was a control-level ``service_unavailable``, a client-local reason
            # no control-result error body admits, so the daemon failed to frame its own answer
            # and the call went unanswered until the client's deadline. A workflow error travels
            # in the check result instead, and the connection keeps serving.
            raise _capacity_refusal(key[1])

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
