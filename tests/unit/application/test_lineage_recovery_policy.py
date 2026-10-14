"""Recovery ordering and authenticated native activity policy."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta

import pytest

from builders.ledger_adapters import FixedClock, FixedIds
from builders.multi_agent import ScenarioClock
from finishup.application.lineage import (
    DelegationRequest,
    LineageConfig,
    LineageCoordinator,
    LineageSnapshot,
    MemoryLineageStore,
)
from finishup.domain.coordination import SESSION_LEASE_SECONDS, SessionHealth, WorkState
from finishup.domain.values import Timestamp, timestamp_from_datetime
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.ids import IdKind

pytestmark = pytest.mark.anyio


async def test_retryable_abandonment_failure_does_not_starve_other_tasks() -> None:
    store = MemoryLineageStore()
    clock = FixedClock()
    ids = FixedIds()
    coordinator = LineageCoordinator(store=store, clock=clock, ids=ids, handle_key=b"k" * 32)
    tasks: list[str] = []
    for _ in range(2):
        task = ids.new(IdKind.TASK)
        tasks.append(task)
        snapshot = await coordinator.register_root(task_id=task, session_id=ids.new(IdKind.SESSION))
        await store.save_task(
            replace(
                snapshot,
                session_health=SessionHealth.CONTACT_LOST,
                contact_lost_at=clock.now_utc() - timedelta(seconds=301),
                abandonment_deadline=clock.now_utc() - timedelta(seconds=1),
            )
        )
    committed: list[str] = []
    blocked_task = min(tasks)

    async def append(snapshot: LineageSnapshot, _reason: str, _deadline: datetime) -> None:
        if snapshot.task_id == blocked_task:
            raise PublicOperationError(PublicErrorCode.BUNDLE_BUSY, "Retry later.", True)
        committed.append(snapshot.task_id)

    with pytest.raises(PublicOperationError) as failure:
        await coordinator.recover_abandoned(append)
    assert failure.value.retryable is True
    assert len(committed) == 1
    blocked = await store.get_task(blocked_task)
    completed = await store.get_task(committed[0])
    assert blocked is not None and blocked.work_state is WorkState.OPEN
    assert completed is not None and completed.work_state is WorkState.ABANDONED


async def test_native_activity_renews_contact_but_never_revives_ended_session_or_work() -> None:
    store = MemoryLineageStore()
    clock = FixedClock()
    ids = FixedIds()
    coordinator = LineageCoordinator(store=store, clock=clock, ids=ids, handle_key=b"k" * 32)
    task = ids.new(IdKind.TASK)
    session = ids.new(IdKind.SESSION)
    snapshot = await coordinator.register_root(task_id=task, session_id=session)
    await store.save_task(
        replace(
            snapshot,
            work_state=WorkState.ABANDONED,
            session_health=SessionHealth.CONTACT_LOST,
            contact_lost_at=clock.now_utc() - timedelta(seconds=301),
            abandonment_deadline=clock.now_utc() - timedelta(seconds=1),
        )
    )
    renewals: list[datetime] = []

    async def renew(lease_until: datetime) -> None:
        renewals.append(lease_until)

    assert await coordinator.renew_observed_activity(
        task_id=task, session_id=session, renew_lease=renew
    )
    renewed = await store.get_task(task)
    assert renewed is not None
    assert renewed.work_state is WorkState.ABANDONED
    assert renewed.session_health is SessionHealth.ACTIVE
    assert renewed.contact_lost_at is None and renewed.abandonment_deadline is None
    await coordinator.end_session(session_id=session)
    assert not await coordinator.renew_observed_activity(
        task_id=task, session_id=session, renew_lease=renew
    )
    ended = await store.get_task(task)
    assert ended is not None and ended.session_health is SessionHealth.ENDED
    assert renewals == [clock.now_utc() + timedelta(seconds=SESSION_LEASE_SECONDS)]


async def _lost_root(
    coordinator: LineageCoordinator,
    store: MemoryLineageStore,
    ids: FixedIds,
    *,
    lost_at: datetime,
    window: int = 300,
    work_state: WorkState = WorkState.OPEN,
) -> tuple[str, str]:
    task = ids.new(IdKind.TASK)
    session = ids.new(IdKind.SESSION)
    snapshot = await coordinator.register_root(task_id=task, session_id=session)
    await store.save_task(
        replace(
            snapshot,
            work_state=work_state,
            session_health=SessionHealth.CONTACT_LOST,
            contact_lost_at=lost_at,
            abandonment_deadline=lost_at + timedelta(seconds=window),
        )
    )
    return task, session


async def test_delayed_host_evidence_renews_from_its_own_time_not_its_delivery() -> None:
    """A swept row that proves contact after the recorded loss restores it until its own end."""

    store = MemoryLineageStore()
    clock = ScenarioClock()
    ids = FixedIds()
    coordinator = LineageCoordinator(store=store, clock=clock, ids=ids, handle_key=b"k" * 32)
    start = clock.now_utc()
    task, session = await _lost_root(coordinator, store, ids, lost_at=start + timedelta(seconds=61))
    clock.advance(seconds=66)
    renewals: list[datetime] = []

    async def renew(lease_until: datetime) -> None:
        renewals.append(lease_until)

    # Received at +30 while the lease still held, delivered at +66 after the sweep marked loss.
    assert await coordinator.renew_observed_activity(
        task_id=task,
        session_id=session,
        renew_lease=renew,
        observed_at=start + timedelta(seconds=30),
    )
    # The lease ends where the evidence ends (+90), never at delivery plus a lease (+126).
    assert renewals == [start + timedelta(seconds=90)]
    restored = await store.get_task(task)
    assert restored is not None and restored.session_health is SessionHealth.ACTIVE
    assert restored.contact_lost_at is None and restored.abandonment_deadline is None


async def test_expired_evidence_postpones_recorded_loss_but_never_revives_contact() -> None:
    store = MemoryLineageStore()
    clock = ScenarioClock()
    ids = FixedIds()
    coordinator = LineageCoordinator(store=store, clock=clock, ids=ids, handle_key=b"k" * 32)
    start = clock.now_utc()
    task, session = await _lost_root(coordinator, store, ids, lost_at=start + timedelta(seconds=61))
    clock.advance(seconds=300)
    renewals: list[datetime] = []

    async def renew(lease_until: datetime) -> None:
        renewals.append(lease_until)

    evidence = start + timedelta(seconds=100)
    assert await coordinator.renew_observed_activity(
        task_id=task, session_id=session, renew_lease=renew, observed_at=evidence
    )
    moved = await store.get_task(task)
    assert moved is not None
    # Contact provably held until +160, so loss starts there and the window restarts from it.
    assert moved.session_health is SessionHealth.CONTACT_LOST
    assert moved.contact_lost_at == start + timedelta(seconds=160)
    assert moved.abandonment_deadline == start + timedelta(seconds=460)
    # A duplicate delivery, older evidence, or a future receipt time changes nothing.
    for observed in (
        evidence,
        start + timedelta(seconds=50),
        clock.now_utc() + timedelta(seconds=1),
    ):
        assert not await coordinator.renew_observed_activity(
            task_id=task, session_id=session, renew_lease=renew, observed_at=observed
        )
    assert await store.get_task(task) == moved
    assert renewals == []


class _OpenOperations:
    """Registry double that reports one started, not yet stopped host child per parent."""

    def __init__(self, started: dict[str, datetime]) -> None:
        self.started = started
        self.queries: list[tuple[str, str]] = []
        self.session_commitments: dict[str, str] = {}

    async def latest_open_host_operation(
        self, parent_task_id: str, *, not_before: Timestamp, session_commitment: str
    ) -> Timestamp | None:
        self.queries.append((parent_task_id, not_before.wire))
        expected = self.session_commitments.get(parent_task_id)
        if expected is not None and expected != session_commitment:
            return None
        started = self.started.get(parent_task_id)
        if started is None or started < not_before.as_datetime():
            return None
        return timestamp_from_datetime(started)

    async def record_host_lineage_observation(self, *args: object, **kwargs: object) -> object:
        raise AssertionError("not used")

    async def list_provisional_annotations(self, *args: object, **kwargs: object) -> object:
        raise AssertionError("not used")

    async def bind_provisional_annotation(self, *args: object, **kwargs: object) -> object:
        raise AssertionError("not used")

    async def bind_host_lineage_identity(self, *args: object, **kwargs: object) -> object:
        raise AssertionError("not used")


async def test_open_host_child_operation_holds_only_open_lapsed_work_within_its_bound() -> None:
    store = MemoryLineageStore()
    clock = ScenarioClock()
    ids = FixedIds()
    start = clock.now_utc()
    registry = _OpenOperations({})
    coordinator = LineageCoordinator(
        store=store,
        clock=clock,
        ids=ids,
        handle_key=b"k" * 32,
        host_lineage_registry=registry,  # pyright: ignore[reportArgumentType]
        config=LineageConfig(native_operation_hold_seconds=3_600),
    )
    lost = start + timedelta(seconds=61)
    waiting, waiting_session = await _lost_root(coordinator, store, ids, lost_at=lost)
    silent, silent_session = await _lost_root(coordinator, store, ids, lost_at=lost)
    terminal, _ = await _lost_root(
        coordinator, store, ids, lost_at=lost, work_state=WorkState.ABANDONED
    )
    stale, stale_session = await _lost_root(coordinator, store, ids, lost_at=lost)
    for task_id, session_id in (
        (waiting, waiting_session),
        (silent, silent_session),
        (stale, stale_session),
    ):
        await coordinator.bind_host_session_commitment(
            task_id=task_id,
            session_id=session_id,
            session_commitment="hmac-sha256:" + "a" * 64,
        )
    live = ids.new(IdKind.TASK)
    await coordinator.register_root(task_id=live, session_id=ids.new(IdKind.SESSION))
    clock.advance(seconds=3_000)
    registry.started.update(
        {
            waiting: start + timedelta(seconds=5),
            terminal: start + timedelta(seconds=5),
            live: start + timedelta(seconds=5),
            # Started more than the bound before now: a host that never reports the stop.
            stale: clock.now_utc() - timedelta(seconds=3_601),
        }
    )
    held: list[tuple[str, str, datetime]] = []

    async def renew(task_id: str, session_id: str, lease_until: datetime) -> None:
        held.append((task_id, session_id, lease_until))

    assert await coordinator.hold_in_flight_contact(renew) == (waiting,)
    assert held == [
        (waiting, waiting_session, clock.now_utc() + timedelta(seconds=SESSION_LEASE_SECONDS))
    ]
    restored = await store.get_task(waiting)
    assert restored is not None and restored.session_health is SessionHealth.ACTIVE
    assert restored.contact_lost_at is None and restored.abandonment_deadline is None
    for untouched in (silent, stale):
        snapshot = await store.get_task(untouched)
        assert snapshot is not None and snapshot.session_health is SessionHealth.CONTACT_LOST
    abandoned = await store.get_task(terminal)
    assert abandoned is not None and abandoned.work_state is WorkState.ABANDONED
    assert abandoned.session_health is SessionHealth.CONTACT_LOST
    # Only open, lapsed work is looked up; the bound is expressed as the earliest start.
    assert {task for task, _ in registry.queries} == {waiting, silent, stale}
    assert {bound for _, bound in registry.queries} == {
        timestamp_from_datetime(clock.now_utc() - timedelta(seconds=3_600)).wire
    }


async def test_hold_without_a_host_lineage_registry_holds_nothing() -> None:
    store = MemoryLineageStore()
    clock = ScenarioClock()
    ids = FixedIds()
    coordinator = LineageCoordinator(store=store, clock=clock, ids=ids, handle_key=b"k" * 32)
    await _lost_root(coordinator, store, ids, lost_at=clock.now_utc())

    async def renew(task_id: str, session_id: str, lease_until: datetime) -> None:
        raise AssertionError((task_id, session_id, lease_until))

    assert await coordinator.hold_in_flight_contact(renew) == ()


async def test_in_flight_hold_requires_the_current_host_session_binding() -> None:
    """An unstopped predecessor operation cannot renew a reattached FinishUP session."""

    store = MemoryLineageStore()
    clock = ScenarioClock()
    ids = FixedIds()
    start = clock.now_utc()
    registry = _OpenOperations({})
    coordinator = LineageCoordinator(
        store=store,
        clock=clock,
        ids=ids,
        handle_key=b"k" * 32,
        host_lineage_registry=registry,  # pyright: ignore[reportArgumentType]
    )
    task, session_one = await _lost_root(coordinator, store, ids, lost_at=start, window=300)
    session_two = ids.new(IdKind.SESSION)
    await coordinator.bind_host_session_commitment(
        task_id=task,
        session_id=session_one,
        session_commitment="hmac-sha256:" + "a" * 64,
    )
    registry.started[task] = start + timedelta(seconds=5)
    registry.session_commitments[task] = "hmac-sha256:" + "a" * 64
    held: list[tuple[str, str, datetime]] = []

    async def renew(task_id: str, session_id: str, lease_until: datetime) -> None:
        held.append((task_id, session_id, lease_until))

    assert await coordinator.hold_in_flight_contact(renew) == (task,)
    rotated = await coordinator.bind_session(task_id=task, session_id=session_two)
    await store.save_task(
        replace(
            rotated,
            session_health=SessionHealth.CONTACT_LOST,
            contact_lost_at=clock.now_utc(),
            abandonment_deadline=clock.now_utc() + timedelta(seconds=300),
        )
    )
    held.clear()
    # No binding for session two exists; the open row is explicitly scoped to session one.
    assert await coordinator.hold_in_flight_contact(renew) == ()
    assert held == []


async def test_in_flight_hold_bootstraps_persisted_current_host_session_binding() -> None:
    """A restart can recover an exact durable session route without task membership inference."""

    store = MemoryLineageStore()
    clock = ScenarioClock()
    ids = FixedIds()
    start = clock.now_utc()
    registry = _OpenOperations({})
    commitment = "hmac-sha256:" + "b" * 64
    lookups: list[tuple[str, str]] = []

    async def persisted_binding(task_id: str, session_id: str) -> str | None:
        lookups.append((task_id, session_id))
        return commitment

    coordinator = LineageCoordinator(
        store=store,
        clock=clock,
        ids=ids,
        handle_key=b"k" * 32,
        host_lineage_registry=registry,  # pyright: ignore[reportArgumentType]
        host_session_commitment_lookup=persisted_binding,
    )
    task, session = await _lost_root(coordinator, store, ids, lost_at=start)
    registry.started[task] = start + timedelta(seconds=5)
    registry.session_commitments[task] = commitment
    held: list[tuple[str, str]] = []

    async def renew(task_id: str, session_id: str, _lease_until: datetime) -> None:
        held.append((task_id, session_id))

    assert await coordinator.hold_in_flight_contact(renew) == (task,)
    assert held == [(task, session)]
    assert lookups == [(task, session)]


async def test_in_flight_hold_rechecks_time_after_registry_waits() -> None:
    """A delayed host lookup renews from its completion time, not its stale entry clock."""

    store = MemoryLineageStore()
    clock = ScenarioClock()
    ids = FixedIds()
    start = clock.now_utc()
    commitment = "hmac-sha256:" + "c" * 64

    class DelayedOperations(_OpenOperations):
        async def latest_open_host_operation(
            self, parent_task_id: str, *, not_before: Timestamp, session_commitment: str
        ) -> Timestamp | None:
            result = await super().latest_open_host_operation(
                parent_task_id,
                not_before=not_before,
                session_commitment=session_commitment,
            )
            clock.advance(seconds=SESSION_LEASE_SECONDS + 1)
            return result

    registry = DelayedOperations({})
    coordinator = LineageCoordinator(
        store=store,
        clock=clock,
        ids=ids,
        handle_key=b"k" * 32,
        host_lineage_registry=registry,  # pyright: ignore[reportArgumentType]
    )
    task, session = await _lost_root(coordinator, store, ids, lost_at=start)
    await coordinator.bind_host_session_commitment(
        task_id=task,
        session_id=session,
        session_commitment=commitment,
    )
    registry.started[task] = start + timedelta(seconds=5)
    registry.session_commitments[task] = commitment
    renewals: list[datetime] = []

    async def renew(_task_id: str, _session_id: str, lease_until: datetime) -> None:
        renewals.append(lease_until)

    assert await coordinator.hold_in_flight_contact(renew) == (task,)
    assert renewals == [clock.now_utc() + timedelta(seconds=SESSION_LEASE_SECONDS)]


async def test_observed_activity_rechecks_time_after_lease_offer_waits() -> None:
    """A lease offer that outlives its evidence cannot revive contact."""

    store = MemoryLineageStore()
    clock = ScenarioClock()
    ids = FixedIds()
    start = clock.now_utc()
    coordinator = LineageCoordinator(store=store, clock=clock, ids=ids, handle_key=b"k" * 32)
    task, session = await _lost_root(coordinator, store, ids, lost_at=start)

    async def renew(_lease_until: datetime) -> None:
        # Model a catalog call that waits past the evidence-anchored 60-second lease.
        clock.advance(seconds=SESSION_LEASE_SECONDS + 1)

    assert await coordinator.renew_observed_activity(
        task_id=task,
        session_id=session,
        renew_lease=renew,
        observed_at=start,
    )
    snapshot = await store.get_task(task)
    assert snapshot is not None
    assert snapshot.session_health is SessionHealth.CONTACT_LOST
    assert snapshot.contact_lost_at == start + timedelta(seconds=SESSION_LEASE_SECONDS)


async def test_observed_activity_rechecks_time_after_lineage_store_waits() -> None:
    """A delayed lineage read cannot take the active-state branch after evidence expires."""

    clock = ScenarioClock()

    class DelayedStore(MemoryLineageStore):
        def __init__(self) -> None:
            super().__init__()
            self.delayed = True

        async def get_task(self, task_id: str) -> LineageSnapshot | None:
            snapshot = await super().get_task(task_id)
            if self.delayed:
                self.delayed = False
                clock.advance(seconds=SESSION_LEASE_SECONDS + 1)
            return snapshot

    store = DelayedStore()
    ids = FixedIds()
    start = clock.now_utc()
    coordinator = LineageCoordinator(store=store, clock=clock, ids=ids, handle_key=b"k" * 32)
    task, session = await _lost_root(coordinator, store, ids, lost_at=start)
    renewals: list[datetime] = []

    async def renew(lease_until: datetime) -> None:
        renewals.append(lease_until)

    assert await coordinator.renew_observed_activity(
        task_id=task, session_id=session, renew_lease=renew, observed_at=start
    )
    snapshot = await store.get_task(task)
    assert snapshot is not None
    assert snapshot.session_health is SessionHealth.CONTACT_LOST
    assert snapshot.contact_lost_at == start + timedelta(seconds=SESSION_LEASE_SECONDS)
    assert renewals == []


async def test_observed_activity_keeps_lineage_fence_when_catalog_rejects_lease() -> None:
    """A concurrent ended/rotated catalog row cannot be overwritten by lineage metadata."""

    store = MemoryLineageStore()
    clock = ScenarioClock()
    ids = FixedIds()
    coordinator = LineageCoordinator(store=store, clock=clock, ids=ids, handle_key=b"k" * 32)
    task = ids.new(IdKind.TASK)
    session = ids.new(IdKind.SESSION)
    initial = await coordinator.register_root(task_id=task, session_id=session)

    async def reject_lease(_lease_until: datetime) -> bool:
        return False

    assert not await coordinator.renew_observed_activity(
        task_id=task,
        session_id=session,
        renew_lease=reject_lease,
        observed_at=clock.now_utc(),
    )
    assert await store.get_task(task) == initial


@pytest.mark.parametrize(
    "state",
    [WorkState.ABANDONED, WorkState.CLOSED, WorkState.CANCELLED, WorkState.WRITTEN_OFF],
)
async def test_terminal_parent_is_refused_new_child_work_with_its_own_reason(
    state: WorkState,
) -> None:
    """A renewed session never makes terminal work a parent again (#837).

    The refusal names the parent's terminal work, not an unusable child capability, so the
    continuation points at a successor task instead of the child-attach review.
    """

    store = MemoryLineageStore()
    clock = FixedClock()
    ids = FixedIds()
    coordinator = LineageCoordinator(store=store, clock=clock, ids=ids, handle_key=b"k" * 32)
    parent = ids.new(IdKind.TASK)
    session = ids.new(IdKind.SESSION)
    snapshot = await coordinator.register_root(task_id=parent, session_id=session)
    # Late activity already restored the session; only the work outcome is terminal.
    await store.save_task(replace(snapshot, work_state=state))
    digest = "sha256:" + "5" * 64
    with pytest.raises(PublicOperationError) as delegated:
        await coordinator.reserve_delegation(
            DelegationRequest(
                operation_id=ids.new(IdKind.REQUEST),
                request_digest=digest,
                parent_task_id=parent,
                parent_session_id=session,
            )
        )
    with pytest.raises(PublicOperationError) as registered:
        await coordinator.self_register(
            operation_id=ids.new(IdKind.REQUEST),
            request_digest=digest,
            parent_session_id=session,
        )
    for refused in (delegated.value, registered.value):
        assert refused.code is PublicErrorCode.SESSION_CONFLICT
        assert refused.safe_details["reason_code"] == "lineage_parent_work_terminal"
        assert refused.safe_details["continuation"] == "lineage_successor_task"
    assert await store.list_children(parent) == ()
