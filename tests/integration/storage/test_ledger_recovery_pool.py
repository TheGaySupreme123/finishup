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
from finishup.adapters.memory.ledger import MemoryLedgerAdapter
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
        assert calls[0].startswith("finishup-ledger-recovery")
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
    started = [threading.Event() for _ in range(ledger_module.LEDGER_POOL_WORKERS["write"])]
    ran: list[str] = []

    def occupy(index: int) -> None:
        started[index].set()
        assert gate.wait(_BOUND_SECONDS)

    pool = ledger_module.ledger_executor("write")
    occupants = [
        pool.submit(occupy, index) for index in range(ledger_module.LEDGER_POOL_WORKERS["write"])
    ]
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


async def test_a_timed_out_read_detaches_an_already_running_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Codex review P1: a running snapshot must not hold a read past its deadline."""

    warm, _cold = await _recorded_ledger(8)
    await _compact(warm)
    started = threading.Event()
    release = threading.Event()
    original = MemoryLedgerAdapter._query_snapshot  # pyright: ignore[reportPrivateUsage]

    def slow_snapshot(self: MemoryLedgerAdapter, *args: object) -> object:
        started.set()
        assert release.wait(_BOUND_SECONDS), "parked snapshot was never released"
        return original(self, *args)  # pyright: ignore[reportArgumentType]

    monkeypatch.setattr(MemoryLedgerAdapter, "_query_snapshot", slow_snapshot)
    # A changed frontier forces a fresh snapshot instead of the cached page.
    await _append_payload(warm, _obligation(99), request_tail=19_999, event_tail=29_999)

    async def bounded_read() -> str:
        try:
            async with asyncio.timeout(0.05):
                await _compact(warm)
        except TimeoutError:
            return "timed_out"
        return "served"

    read = asyncio.create_task(bounded_read())
    try:
        assert await asyncio.to_thread(started.wait, _BOUND_SECONDS)
        # ``asyncio.wait`` observes without cancelling, so a joined worker cannot hang the test.
        done, _pending = await asyncio.wait((read,), timeout=_BOUND_SECONDS / 4)
        assert read in done, "the read waited for its running snapshot"
        assert read.result() == "timed_out"
        assert not release.is_set()
    finally:
        release.set()
        await asyncio.wait((read,), timeout=_BOUND_SECONDS)


async def test_cold_replays_of_many_tasks_cannot_starve_a_warm_append(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Codex review P2: background recoveries keep their own pool."""

    warm, _cold = await _recorded_ledger(4)
    colds = [cold() for _warm_unused, cold in [await _recorded_ledger(6) for _ in range(5)]]
    with _parked_replay(monkeypatch) as (calls, release):
        readers = [asyncio.create_task(_compact(ledger)) for ledger in colds]
        try:
            appended = asyncio.create_task(
                _append_payload(warm, _obligation(77), request_tail=18_777, event_tail=28_777)
            )
            done, _pending = await asyncio.wait((appended,), timeout=_BOUND_SECONDS / 4)
            assert appended in done, "a warm append queued behind cold replays"
            appended.result()
            assert calls and all(name.startswith("finishup-ledger-recovery") for name in calls)
        finally:
            release.set()
            await asyncio.wait_for(asyncio.gather(*readers), _BOUND_SECONDS)


async def test_genesis_replay_ignores_a_saturated_default_pool_and_drops_when_queued() -> None:
    """Independent review: status' fallback replay keeps the read's deadline (#1231)."""

    from builders.replay import replay_records
    from finishup.application.ledger_snapshot import replay_off_loop

    records = replay_records("all-event-families")
    loop = asyncio.get_running_loop()
    starved = ThreadPoolExecutor(max_workers=2, thread_name_prefix="starved-default")
    parked = threading.Event()
    loop.set_default_executor(starved)
    blockers = [loop.run_in_executor(None, parked.wait, _BOUND_SECONDS) for _ in range(2)]
    try:
        replay = asyncio.create_task(replay_off_loop(records))
        # ``asyncio.wait`` observes without cancelling, so a stuck replay cannot hang the test.
        done, _pending = await asyncio.wait((replay,), timeout=_BOUND_SECONDS / 4)
        assert replay in done, "the replay waited for the shared default pool"
        assert isinstance(replay.result(), ProjectionState)
    finally:
        parked.set()
        await asyncio.gather(*blockers)
        loop.set_default_executor(ThreadPoolExecutor())
        starved.shutdown(wait=True)

    gate = threading.Event()
    workers = ledger_module.LEDGER_POOL_WORKERS["read"]
    started = [threading.Event() for _ in range(workers)]

    def occupy(index: int) -> None:
        started[index].set()
        assert gate.wait(_BOUND_SECONDS)

    pool = ledger_module.ledger_executor("read")
    occupants = [pool.submit(occupy, index) for index in range(workers)]
    try:
        for flag in started:
            assert await asyncio.to_thread(flag.wait, _BOUND_SECONDS)

        async def bounded() -> str:
            try:
                async with asyncio.timeout(0.05):
                    await replay_off_loop(records)
            except TimeoutError:
                return "timed_out"
            return "served"

        queued = asyncio.create_task(bounded())
        done, _pending = await asyncio.wait((queued,), timeout=_BOUND_SECONDS / 4)
        assert queued in done, "a cancelled replay waited for a queued worker"
        assert queued.result() == "timed_out"
    finally:
        gate.set()
        for occupant in occupants:
            occupant.result(_BOUND_SECONDS)


def test_an_unbalanced_release_never_retires_pools(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ledger_module, "_ledger_pool_owners", 0)
    pool = ledger_module.ledger_executor("write")
    ledger_module.release_ledger_executors()
    assert ledger_module._ledger_pool_owners == 0  # pyright: ignore[reportPrivateUsage]
    assert ledger_module.ledger_executor("write") is pool
    assert pool.submit(lambda: "alive").result(_BOUND_SECONDS) == "alive"
