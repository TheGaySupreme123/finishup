"""Client wait cancellation cannot restart an admitted semantic operation."""

from __future__ import annotations

import asyncio

import pytest

from finishup.ports.control import ControlError
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.service.check_waits import EXPLICIT_CONTROL_CANCEL, CheckWaits


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_disconnect_preserves_work_and_replay_reports_pending() -> None:
    waits = CheckWaits()
    entered, release, finished = asyncio.Event(), asyncio.Event(), asyncio.Event()
    calls = 0

    async def work() -> object:
        nonlocal calls
        calls += 1
        entered.set()
        await release.wait()
        finished.set()
        return "complete"

    waiter = asyncio.create_task(waits.run(("writer", "request"), "digest", work, None))
    try:
        await entered.wait()
        waiter.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiter
        with pytest.raises(PublicOperationError) as pending:
            await waits.run(("writer", "request"), "digest", work, None)
        assert pending.value.code is PublicErrorCode.OPERATION_PENDING
        with pytest.raises(PublicOperationError) as conflict:
            await waits.run(("writer", "request"), "different", work, None)
        assert conflict.value.code is PublicErrorCode.IDEMPOTENCY_CONFLICT
        assert calls == 1 and not finished.is_set()
        release.set()
        await finished.wait()
    finally:
        release.set()
        await waits.close()


@pytest.mark.anyio
async def test_wait_deadline_preserves_work_until_shutdown_joins_it() -> None:
    waits = CheckWaits()
    entered, cancelled = asyncio.Event(), asyncio.Event()

    async def work() -> object:
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    try:
        with pytest.raises(ControlError) as timeout:
            await waits.run(("writer", "request"), "digest", work, 10)
        assert timeout.value.reason == "request_timeout"
        assert entered.is_set() and not cancelled.is_set()
    finally:
        await waits.close()
    assert cancelled.is_set()
    with pytest.raises(ControlError) as stopped:
        await waits.run(("writer", "next"), "digest", work, None)
    assert stopped.value.reason == "service_draining"


@pytest.mark.anyio
async def test_explicit_control_cancel_stops_attached_work() -> None:
    waits = CheckWaits()
    entered, cancelled = asyncio.Event(), asyncio.Event()

    async def work() -> object:
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    waiter = asyncio.create_task(waits.run(("writer", "request"), "digest", work, None))
    await entered.wait()
    waiter.cancel(EXPLICIT_CONTROL_CANCEL)
    with pytest.raises(asyncio.CancelledError):
        await waiter
    assert cancelled.is_set()
    await waits.close()


@pytest.mark.anyio
async def test_detached_failure_is_observed_without_retaining_a_result() -> None:
    waits = CheckWaits()
    entered, release, completed = asyncio.Event(), asyncio.Event(), asyncio.Event()

    async def work() -> object:
        entered.set()
        await release.wait()
        raise ValueError("synthetic_failure")

    waiter = asyncio.create_task(waits.run(("writer", "request"), "digest", work, None))
    await entered.wait()
    waiter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiter
    # A callback after the manager's callback establishes that failure collection completed.
    task = waits._tasks[("writer", "request")][1]  # pyright: ignore[reportPrivateUsage]
    task.add_done_callback(lambda _task: completed.set())
    release.set()
    await completed.wait()
    assert not waits._tasks  # pyright: ignore[reportPrivateUsage]
    await waits.close()


@pytest.mark.anyio
async def test_retained_waiters_have_a_fixed_capacity() -> None:
    waits = CheckWaits()
    entered = asyncio.Queue[None]()

    async def work() -> object:
        await entered.put(None)
        await asyncio.Event().wait()

    waiters = [
        asyncio.create_task(waits.run(("writer", str(index)), "digest", work, None))
        for index in range(8)
    ]
    try:
        for _ in waiters:
            await entered.get()
        with pytest.raises(ControlError) as busy:
            await waits.run(("writer", "overflow"), "digest", work, None)
        assert busy.value.reason == "service_unavailable"
    finally:
        await waits.close()
        await asyncio.gather(*waiters, return_exceptions=True)


@pytest.mark.anyio
async def test_read_window_admits_only_while_open_and_close_drains_readers() -> None:
    """Issue #571 A2: the gate owner cannot release its gates under an admitted reader."""

    from finishup.service.check_waits import CheckReadWindow

    window = CheckReadWindow()
    assert not window.admits_readers
    with pytest.raises(RuntimeError):
        window.enter()
    window.open()
    assert window.admits_readers
    window.enter()
    closing = asyncio.create_task(window.close())
    done, _pending = await asyncio.wait({closing}, timeout=0)
    # Closing stops new admissions at once but waits for the active reader.
    assert not window.admits_readers
    assert not done
    with pytest.raises(RuntimeError):
        window.enter()
    window.leave()
    await asyncio.wait_for(closing, timeout=1.0)
    with pytest.raises(RuntimeError):
        window.leave()
