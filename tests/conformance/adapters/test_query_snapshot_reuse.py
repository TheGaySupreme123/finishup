"""Snapshot parity, bounded reuse and cancellation of off-loop status work."""

from __future__ import annotations

import asyncio
import threading
from dataclasses import replace

import apsw
import pytest

from builders.replay import replay_records
from finishup.adapters.memory import ledger as module
from finishup.application import ledger_snapshot
from finishup.domain.events import LedgerRecord
from finishup.domain.values import Frontier
from finishup.kernel.projections import ProjectionState
from finishup.ports.ledger import ProjectionItem, ProjectionQuery, ProjectionView
from integration.storage.test_append_and_replay import command_from_records, memory_for, sqlite_for


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
@pytest.mark.parametrize("backend", ["memory", "sqlite"])
async def test_pages_reuse_frontier_and_rows(backend: str, monkeypatch: pytest.MonkeyPatch) -> None:
    records = replay_records("all-event-families")
    command, objects = command_from_records(records, expected_frontier=0)
    db = None
    if backend == "memory":
        ledger = memory_for(command, objects)
    else:
        db = apsw.Connection(":memory:")
        ledger = sqlite_for(command, objects, db)
    try:
        await ledger.append_batch(command)
        accepted = tuple([row async for row in ledger.load_events(command.session_id)])
        head = Frontier(accepted[-1].ledger.ingestion_sequence, accepted[-1].entry_digest)
        original_replay, original_items = module.replay, module._projection_items  # pyright: ignore[reportPrivateUsage]
        counts = {"replays": 0, "rows": 0}

        def replay(prefix: tuple[LedgerRecord, ...]) -> ProjectionState:
            counts["replays"] += 1
            return original_replay(prefix)

        def items(
            view: ProjectionView,
            projection: ProjectionState,
            records: tuple[LedgerRecord, ...],
            *,
            task: str,
            session: str,
            service_clock_events: frozenset[str] = frozenset(),
        ) -> tuple[ProjectionItem, ...]:
            counts["rows"] += 1
            return original_items(
                view,
                projection,
                records,
                task=task,
                session=session,
                service_clock_events=service_clock_events,
            )

        monkeypatch.setattr(module, "replay", replay)
        monkeypatch.setattr(module, "_projection_items", items)
        query = ProjectionQuery(command.session_id, "history", None, head, 1, None, None)
        first = await ledger.query_projection(query)
        assert first.next_position is not None
        second = await ledger.query_projection(replace(query, position=first.next_position))
        assert first.items != second.items
        assert counts == {"replays": 0, "rows": 1}
        historical = Frontier(accepted[3].ledger.ingestion_sequence, accepted[3].entry_digest)
        historical_query = replace(query, requested_frontier=historical)
        page = await ledger.query_projection(historical_query)
        assert await ledger.query_projection(historical_query) == page
        await ledger.query_projection(replace(historical_query, view="obligations"))
        assert counts["replays"] == 1
        assert page.effective_frontier == historical
    finally:
        if db is not None:
            db.close()


@pytest.mark.anyio
async def test_historical_query_yields_and_detaches_cancelled_worker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A cancelled read returns at once; its running snapshot finishes detached (#1231).

    The snapshot holds no ledger lock and reads only immutable inputs, so the read does not
    wait for it. The detached worker's result is discarded: it never populates the page cache.
    """

    records = replay_records("all-event-families")
    command, objects = command_from_records(records, expected_frontier=0)
    ledger = memory_for(command, objects)
    await ledger.append_batch(command)
    accepted = tuple([row async for row in ledger.load_events(command.session_id)])
    frontier = Frontier(accepted[3].ledger.ingestion_sequence, accepted[3].entry_digest)
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    loop_thread = threading.get_ident()
    original = module.replay
    original_snapshot = module.MemoryLedgerAdapter._query_snapshot  # pyright: ignore[reportPrivateUsage]

    def replay(prefix: tuple[LedgerRecord, ...]) -> ProjectionState:
        assert threading.get_ident() != loop_thread
        entered.set()
        assert release.wait(10)
        return original(prefix)

    def tracked_snapshot(self: module.MemoryLedgerAdapter, *args: object) -> object:
        try:
            return original_snapshot(self, *args)  # pyright: ignore[reportArgumentType]
        finally:
            finished.set()

    monkeypatch.setattr(module, "replay", replay)
    monkeypatch.setattr(module.MemoryLedgerAdapter, "_query_snapshot", tracked_snapshot)
    query = ProjectionQuery(command.session_id, "history", None, frontier, 1, None, None)
    task = asyncio.create_task(ledger.query_projection(query))
    try:
        assert await asyncio.to_thread(entered.wait, 5)
        # An unrelated ledger read progresses while replay is deliberately held.
        assert await ledger.lookup_operation(command.writer_id, command.operation_id) is not None
        task.cancel()
        # Cancellation completes while the worker is still held: nothing joins it.
        done, _pending = await asyncio.wait((task,), timeout=5)
        assert task in done
        assert task.cancelled()
        assert not finished.is_set()
    finally:
        release.set()
    # Drain the detached worker explicitly, then prove its result was discarded.
    assert await asyncio.to_thread(finished.wait, 10)
    state = ledger._state  # pyright: ignore[reportPrivateUsage]
    assert all(key[0] != frontier for key in state.query_cache)


@pytest.mark.anyio
@pytest.mark.parametrize("backend", ["memory", "sqlite"])
async def test_append_retains_pinned_rows_without_replay(
    backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    records = replay_records("all-event-families")
    command, objects = command_from_records(records[:4], expected_frontier=0)
    db = None
    if backend == "memory":
        ledger = memory_for(command, objects)
    else:
        db = apsw.Connection(":memory:")
        ledger = sqlite_for(command, objects, db)
    try:
        accepted = await ledger.append_batch(command)
        query = ProjectionQuery(
            command.session_id, "history", None, accepted.result_frontier, 100, None, None
        )
        before = await ledger.query_projection(query)
        next_command, _ = command_from_records(
            records[4:5], expected_frontier=4, request_number=100, objects=objects
        )
        appended = await ledger.append_batch(next_command)
        after = await ledger.query_projection(
            replace(query, requested_frontier=appended.result_frontier)
        )
        assert len(before.items) == 4
        assert len(after.items) == 5

        def forbidden_replay(_records: tuple[LedgerRecord, ...]) -> ProjectionState:
            pytest.fail("unchanged pinned prefix must reuse its authenticated projection")

        monkeypatch.setattr(module, "replay", forbidden_replay)
        historical = await ledger.query_projection(query)
        assert historical.items == before.items
        assert historical.effective_frontier == before.effective_frontier
        assert historical.head_frontier == appended.result_frontier
    finally:
        if db is not None:
            db.close()


@pytest.mark.anyio
async def test_application_snapshot_reuses_current_and_replays_old_prefix_off_loop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    records = replay_records("all-event-families")
    command, objects = command_from_records(records, expected_frontier=0)
    ledger = memory_for(command, objects)
    await ledger.append_batch(command)
    accepted = tuple([row async for row in ledger.load_events(command.session_id)])
    head = await ledger.load_frontier()
    original = ledger_snapshot._replay_until_cancelled  # pyright: ignore[reportPrivateUsage]
    replay_threads: list[int] = []
    loop_thread = threading.get_ident()

    def replay(prefix: tuple[LedgerRecord, ...], cancelled: threading.Event) -> ProjectionState:
        replay_threads.append(threading.get_ident())
        return original(prefix, cancelled)

    monkeypatch.setattr(ledger_snapshot, "_replay_until_cancelled", replay)
    current = await ledger_snapshot.projection_for_records(
        ledger, command.session_id, head, accepted
    )
    assert Frontier(current.frontier, current.head_digest) == head
    assert replay_threads == []
    prefix = accepted[:4]
    past = Frontier(prefix[-1].ledger.ingestion_sequence, prefix[-1].entry_digest)
    historical = await ledger_snapshot.projection_for_records(
        ledger, command.session_id, past, prefix
    )
    assert Frontier(historical.frontier, historical.head_digest) == past
    assert len(replay_threads) == 1 and replay_threads[0] != loop_thread


@pytest.mark.anyio
@pytest.mark.parametrize("backend", ["memory", "sqlite"])
async def test_redaction_append_invalidates_pinned_page_cache(
    backend: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    records = replay_records("all-event-families")
    redaction_index = next(
        i for i, row in enumerate(records) if row.schema.name == "redaction_recorded"
    )
    command, objects = command_from_records(records[:redaction_index], expected_frontier=0)
    db = None
    if backend == "memory":
        ledger = memory_for(command, objects)
    else:
        db = apsw.Connection(":memory:")
        ledger = sqlite_for(command, objects, db)
    try:
        accepted = await ledger.append_batch(command)
        query = ProjectionQuery(
            command.session_id, "history", None, accepted.result_frontier, 100, None, None
        )
        await ledger.query_projection(query)
        appended, _ = command_from_records(
            records[redaction_index : redaction_index + 1],
            expected_frontier=redaction_index,
            request_number=100,
            objects=objects,
        )
        await ledger.append_batch(appended)
        calls: list[int] = []
        original = module.replay

        def counted(prefix: tuple[LedgerRecord, ...]) -> ProjectionState:
            calls.append(len(prefix))
            return original(prefix)

        monkeypatch.setattr(module, "replay", counted)
        await ledger.query_projection(query)
        assert calls == [redaction_index]
    finally:
        if db is not None:
            db.close()


def test_incremental_fold_matches_genesis_replay_and_still_validates_new_records() -> None:
    """Issue #886: trusted-prior folding is an optimisation only, never a trust widening."""

    from finishup.kernel.projections import derive_projection_state
    from finishup.kernel.reducers import (
        build_replay_index,
        replay,
        replay_extension,
        replay_with_index,
    )

    records = replay_records("all-event-families")
    full, full_index = replay_with_index(records)
    for split in range(len(records) + 1):
        prior = replay(records[:split])
        assert replay_extension(prior, records[:split], records[split:]) == full
    assert build_replay_index(records) == full_index

    collection, record_key, live_record = next(
        (name, key, row)
        for name in ("actions", "results", "claims", "obligations", "evidence")
        for key, row in getattr(full, name).items()
        if row.payload is not None
    )
    tampered = replace(live_record, payload_digest="sha256:" + "f" * 64)
    fields = {name: getattr(full, name) for name in ProjectionState.__slots__}
    # An unchanged record is carried by identity; a replaced one is re-validated in full.
    assert derive_projection_state(full, **fields) == full
    with pytest.raises(ValueError):
        derive_projection_state(
            full, **{**fields, collection: {**getattr(full, collection), record_key: tampered}}
        )
    # A prior at a later frontier than the new state is ignored rather than trusted.
    earlier = replay(records[:1])
    with pytest.raises(ValueError):
        derive_projection_state(
            full,
            **{
                **fields,
                "frontier": earlier.frontier,
                "head_digest": earlier.head_digest,
                collection: {record_key: tampered},
            },
        )


@pytest.mark.anyio
@pytest.mark.parametrize("backend", ["memory", "sqlite"])
async def test_trusted_frontier_history_is_exact_identity_fenced_and_redaction_cleared(
    backend: str,
) -> None:
    from finishup.kernel.reducers import replay

    records = replay_records("all-event-families")
    redaction_index = next(
        i for i, row in enumerate(records) if row.schema.name == "redaction_recorded"
    )
    first, objects = command_from_records(records[:4], expected_frontier=0)
    db = None
    if backend == "memory":
        ledger = memory_for(first, objects)
    else:
        db = apsw.Connection(":memory:")
        ledger = sqlite_for(first, objects, db)
    try:
        early = (await ledger.append_batch(first)).result_frontier
        middle, _ = command_from_records(
            records[4:redaction_index],
            expected_frontier=4,
            request_number=200,
            objects=objects,
        )
        before_redaction = (await ledger.append_batch(middle)).result_frontier
        accepted = tuple([row async for row in ledger.load_events(first.session_id)])
        retained = await ledger.load_trusted_projection(first.session_id, early)
        assert retained is not None and retained == replay(accepted[:4])
        # Wrong digest at a real sequence and an unknown session are never vouched for.
        forged = Frontier(early.sequence, "sha256:" + "0" * 64)
        assert await ledger.load_trusted_projection(first.session_id, forged) is None
        assert (
            await ledger.load_trusted_projection("ses_00000000-0000-4000-8000-00000000ffff", early)
            is None
        )
        redaction, _ = command_from_records(
            records[redaction_index : redaction_index + 1],
            expected_frontier=redaction_index,
            request_number=300,
            objects=objects,
        )
        await ledger.append_batch(redaction)
        # Redaction drops every retained historical snapshot; the live head is still served.
        assert await ledger.load_trusted_projection(first.session_id, early) is None
        assert await ledger.load_trusted_projection(first.session_id, before_redaction) is None
        head = await ledger.load_frontier()
        assert await ledger.load_trusted_projection(first.session_id, head) is not None
    finally:
        if db is not None:
            db.close()


def test_trusted_history_rejects_a_prefix_whose_record_objects_changed() -> None:
    from finishup.adapters.memory.ledger import TrustedProjectionHistory
    from finishup.kernel.reducers import replay

    records = replay_records("all-event-families")
    prefix = records[:3]
    projection = replay(prefix)
    history = TrustedProjectionHistory()
    history.remember(projection, prefix)
    frontier = Frontier(projection.frontier, projection.head_digest)
    assert history.lookup(frontier, records) is projection
    # Same values, different objects (for example a recovery re-decode): identity fence fails.
    rebuilt = tuple(replace(row) for row in records)
    assert history.lookup(frontier, rebuilt) is None
    assert history.lookup(frontier, records[:2]) is None


@pytest.mark.anyio
async def test_offloaded_replay_stops_when_the_caller_is_cancelled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    records = replay_records("all-event-families")
    original = ledger_snapshot.reduce_event
    folded: list[int] = []
    first_fold = threading.Event()
    release = threading.Event()

    def gated(state: ProjectionState, event: LedgerRecord, index: object) -> ProjectionState:
        folded.append(event.ledger.ingestion_sequence)
        first_fold.set()
        assert release.wait(timeout=5)
        return original(state, event, index)  # type: ignore[arg-type]

    monkeypatch.setattr(ledger_snapshot, "reduce_event", gated)
    task = asyncio.ensure_future(ledger_snapshot.replay_off_loop(records))
    assert await asyncio.to_thread(first_fold.wait, 5)
    task.cancel()
    # FIFO: the task handles its cancellation (arming the worker's stop flag) before this runs.
    asyncio.get_running_loop().call_soon(release.set)
    with pytest.raises(asyncio.CancelledError):
        await task
    # The worker was joined before cancellation propagated and stopped at the next record.
    assert folded == [records[0].ledger.ingestion_sequence]
