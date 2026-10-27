"""A cold SQLite ledger replay is shared, bounded, and off the shared default pool (#1231).

A status read on a freshly opened task ledger waits for one full replay of every recorded event.
These tests park that replay and prove: concurrent reads share one replay instead of starting
their own; a read whose deadline expires leaves without cancelling, repeating, or queueing more
work behind it; and the replay and projection snapshots no longer depend on the event loop's
default executor, which every unrelated blocking hop in the service also uses.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable, Generator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from typing import cast

import apsw
import pytest

import finishup.adapters.memory.ledger as ledger_module
import finishup.adapters.sqlite.repository as repository_module
from builders.ledger_adapters import (
    FixedClock,
    FixedIds,
    MemoryObjects,
    append_command,
    ownership_fence,
)
from conformance.adapters.test_obligation_resolution_parity import (
    _append_payload,  # pyright: ignore[reportPrivateUsage]
)
from finishup.adapters.sqlite.migrations import initialize_bundle
from finishup.adapters.sqlite.repository import SqliteLedger
from finishup.domain.events import ObligationPublishedPayload, ObligationStatus
from finishup.domain.values import obligation_id
from finishup.kernel.projections import ProjectionState
from finishup.ports.ledger import ProjectionPage, ProjectionQuery, ProjectionView
from finishup.ports.objects import ObjectStorePort

pytestmark = pytest.mark.anyio

# Every bounded wait below fails on a deadline while observing real state; none infers success.
_BOUND_SECONDS = 10.0


def _obligation(index: int) -> ObligationPublishedPayload:
    return ObligationPublishedPayload(
        obligation_id=obligation_id(f"obl_00000000-0000-4000-8000-{900_000 + index:012d}"),
        description=f"Deliver item {index}.",
        evidence_expectation="A named test run at the claimed state.",
        status=ObligationStatus.OPEN,
    )


async def _recorded_ledger(events: int) -> tuple[SqliteLedger, Callable[[], SqliteLedger]]:
    """Record ``events`` appends, then return a factory for a cold ledger over the same bundle."""

    seed = append_command()
    db = apsw.Connection(":memory:")
    initialize_bundle(
        db, {"task_id": seed.task_id, "owner_generation": "1", "owner_nonce": "ledger-test-nonce"}
    )
    ids = FixedIds()
    objects = MemoryObjects(ids)
    warm = SqliteLedger(
        db=db,
        task_id=seed.task_id,
        ownership_fence=ownership_fence(),
        clock=FixedClock(),
        ids=ids,
        objects=objects,
    )
    for index in range(events):
        await _append_payload(
            warm, _obligation(index), request_tail=10_000 + index, event_tail=20_000 + index
        )

    def cold() -> SqliteLedger:
        return SqliteLedger(
            db=db,
            task_id=seed.task_id,
            ownership_fence=ownership_fence(),
            clock=FixedClock(),
            ids=ids,
            objects=cast(ObjectStorePort, objects),
        )

    return warm, cold


async def _compact(ledger: SqliteLedger) -> ProjectionPage:
    frontier = await ledger.load_frontier()
    return await ledger.query_projection(
        ProjectionQuery(
            append_command().session_id,
            ProjectionView.COMPACT.value,
            None,
            frontier,
            1,
            None,
            None,
        )
    )


@contextmanager
def _parked_replay(monkeypatch: pytest.MonkeyPatch) -> Generator[tuple[list[str], threading.Event]]:
    """Park every reducer replay the repository starts until the test releases it."""

    calls: list[str] = []
    release = threading.Event()
    original = repository_module.replay

    def parked(records: object) -> ProjectionState:
        calls.append(threading.current_thread().name)
        assert release.wait(_BOUND_SECONDS), "parked replay was never released"
        return original(records)  # pyright: ignore[reportArgumentType]

    monkeypatch.setattr(repository_module, "replay", parked)
    try:
        yield calls, release
    finally:
        release.set()


async def test_many_timed_out_reads_share_one_cold_replay_and_free_the_pool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _warm, cold = await _recorded_ledger(24)
    ledger = cold()
    with _parked_replay(monkeypatch) as (calls, release):

        async def bounded_read() -> str:
            try:
                async with asyncio.timeout(0.05):
                    await _compact(ledger)
            except TimeoutError:
                return "timed_out"
            return "served"

        outcomes = await asyncio.gather(*(bounded_read() for _ in range(12)))
        assert outcomes == ["timed_out"] * 12
        # Twelve expired readers started exactly one replay, which is still running.
        assert len(calls) == 1
        assert calls[0].startswith("finishup-ledger")
        # The expired readers left nothing queued: the pool still serves other work at once.
        assert (
            await asyncio.wait_for(ledger_module.run_ledger_work(lambda: "free"), _BOUND_SECONDS)
            == "free"
        )

        release.set()
        page = await asyncio.wait_for(_compact(ledger), _BOUND_SECONDS)
        assert page.head_frontier.sequence == 24
        assert len(calls) == 1


async def test_cold_replay_and_status_page_survive_a_saturated_default_executor() -> None:
    _warm, cold = await _recorded_ledger(16)
    ledger = cold()
    loop = asyncio.get_running_loop()
    starved = ThreadPoolExecutor(max_workers=2, thread_name_prefix="starved-default")
    parked = threading.Event()
    loop.set_default_executor(starved)
    blockers = [loop.run_in_executor(None, parked.wait, _BOUND_SECONDS) for _ in range(2)]
    try:
        # Every default-pool thread is parked by unrelated work, as when timed-out hops keep
        # running after their callers left. The cold replay and the page must not need one.
        page = await asyncio.wait_for(_compact(ledger), _BOUND_SECONDS)
        assert page.head_frontier.sequence == 16
    finally:
        parked.set()
        await asyncio.gather(*blockers)
        loop.set_default_executor(ThreadPoolExecutor())
        starved.shutdown(wait=True)


async def test_a_cancelled_read_drops_work_that_never_started() -> None:
    gate = threading.Event()
    started = [threading.Event() for _ in range(ledger_module.LEDGER_WORKERS)]
    ran: list[str] = []

    def occupy(index: int) -> None:
        started[index].set()
        assert gate.wait(_BOUND_SECONDS)

    pool = ledger_module.ledger_executor()
    occupants = [pool.submit(occupy, index) for index in range(ledger_module.LEDGER_WORKERS)]
    try:
        for flag in started:
            assert await asyncio.to_thread(flag.wait, _BOUND_SECONDS)
        queued = asyncio.create_task(ledger_module.run_ledger_work(lambda: ran.append("late")))
        await asyncio.sleep(0)
        queued.cancel()
        # Cancellation returns while every pool thread is still busy: nothing was joined.
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(queued, _BOUND_SECONDS)
    finally:
        gate.set()
        for occupant in occupants:
            occupant.result(_BOUND_SECONDS)
    assert await ledger_module.run_ledger_work(lambda: "drained") == "drained"
    assert ran == []
