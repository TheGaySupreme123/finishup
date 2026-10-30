"""Issue #1239: silence abandons only work someone waits on, and a guess can be taken back."""

from __future__ import annotations

import time
from dataclasses import replace
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest

from builders.ledger_adapters import FixedIds
from builders.multi_agent import ScenarioClock
from finishup.application.lineage import (
    LineageConfig,
    LineageCoordinator,
    LineageSnapshot,
    MemoryLineageStore,
)
from finishup.application.lineage_recovery import observed_session_end
from finishup.domain.coordination import (
    SESSION_LEASE_SECONDS,
    LineageAcceptance,
    LineageOrigin,
    SessionHealth,
    WorkState,
)
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.ids import IdKind

pytestmark = pytest.mark.anyio

_WINDOW = 300
_HORIZON = 86_400


def _coordinator(
    clock: ScenarioClock, store: MemoryLineageStore, ids: FixedIds, **config: int
) -> LineageCoordinator:
    return LineageCoordinator(
        store=store,
        clock=clock,
        ids=ids,
        handle_key=b"k" * 32,
        config=LineageConfig(**config),
    )


async def _root(coordinator: LineageCoordinator, ids: FixedIds) -> tuple[str, str]:
    task, session = ids.new(IdKind.TASK), ids.new(IdKind.SESSION)
    await coordinator.register_root(task_id=task, session_id=session)
    return task, session


async def _child(
    store: MemoryLineageStore,
    ids: FixedIds,
    parent: str,
    *,
    acceptance: LineageAcceptance = LineageAcceptance.PENDING,
) -> tuple[str, str]:
    task, session = ids.new(IdKind.TASK), ids.new(IdKind.SESSION)
    await store.save_task(
        LineageSnapshot(
            task_id=task,
            parent_task_id=parent,
            depth=1,
            origin=LineageOrigin.PARENT_MINTED,
            acceptance=acceptance,
            work_state=WorkState.OPEN,
            session_health=SessionHealth.ACTIVE,
            active_session_id=session,
        )
    )
    return task, session


class _Appends:
    def __init__(self) -> None:
        self.rows: list[tuple[str, str, datetime]] = []

    async def __call__(self, snapshot: LineageSnapshot, reason: str, deadline: datetime) -> None:
        self.rows.append((snapshot.task_id, reason, deadline))


async def test_a_quiet_top_level_task_keeps_open_work_until_the_long_horizon() -> None:
    clock, store, ids = ScenarioClock(), MemoryLineageStore(), FixedIds()
    coordinator = _coordinator(clock, store, ids)
    task, session = await _root(coordinator, ids)
    lost_at = clock.now_utc()
    lost = await coordinator.mark_contact_lost(session_id=session)
    assert lost.session_health is SessionHealth.CONTACT_LOST
    assert lost.abandonment_deadline == lost_at + timedelta(seconds=_HORIZON)
    assert lost.abandonment_reason == "contact_lost"
    appends = _Appends()
    # The six quiet minutes of the benchmark run, and then most of a day, abandon nothing.
    for seconds in (_WINDOW + 61, _HORIZON - _WINDOW - 62):
        clock.advance(seconds=seconds)
        assert await coordinator.recover_abandoned(appends) == ()
    assert appends.rows == []
    clock.advance(seconds=1)
    (abandoned,) = await coordinator.recover_abandoned(appends)
    assert abandoned.work_state is WorkState.ABANDONED
    assert abandoned.abandonment_reason == "contact_lost"
    assert appends.rows == [(task, "contact_lost", lost_at + timedelta(seconds=_HORIZON))]


async def test_a_child_whose_parent_waits_keeps_the_short_window() -> None:
    clock, store, ids = ScenarioClock(), MemoryLineageStore(), FixedIds()
    coordinator = _coordinator(clock, store, ids)
    parent, _ = await _root(coordinator, ids)
    child, child_session = await _child(store, ids, parent)
    lost_at = clock.now_utc()
    lost = await coordinator.mark_contact_lost(session_id=child_session)
    assert lost.abandonment_deadline == lost_at + timedelta(seconds=_WINDOW)
    clock.advance(seconds=_WINDOW)
    appends = _Appends()
    (abandoned,) = await coordinator.recover_abandoned(appends)
    assert abandoned.task_id == child and abandoned.work_state is WorkState.ABANDONED
    assert appends.rows == [(child, "contact_lost", lost_at + timedelta(seconds=_WINDOW))]


@pytest.mark.parametrize("parent_stopped_waiting", ("parent_closed", "parent_ended", "rejected"))
async def test_a_child_nobody_waits_on_moves_to_the_long_horizon(
    parent_stopped_waiting: str,
) -> None:
    """The window is judged at sweep time, so a parent that stops waiting frees the child."""

    clock, store, ids = ScenarioClock(), MemoryLineageStore(), FixedIds()
    coordinator = _coordinator(clock, store, ids)
    parent, parent_session = await _root(coordinator, ids)
    acceptance = (
        LineageAcceptance.REJECTED
        if parent_stopped_waiting == "rejected"
        else LineageAcceptance.PENDING
    )
    child, child_session = await _child(store, ids, parent, acceptance=acceptance)
    lost_at = clock.now_utc()
    await coordinator.mark_contact_lost(session_id=child_session)
    if parent_stopped_waiting == "parent_closed":
        await coordinator.close_work(session_id=parent_session)
    elif parent_stopped_waiting == "parent_ended":
        await coordinator.end_session(session_id=parent_session)
    clock.advance(seconds=_WINDOW + 1)
    appends = _Appends()
    recovered = await coordinator.recover_abandoned(appends)
    assert child not in {item.task_id for item in recovered}
    still = await store.get_task(child)
    assert still is not None and still.work_state is WorkState.OPEN
    effective = await coordinator.own_lifecycle(child)
    assert effective is not None
    assert effective.abandonment_deadline == lost_at + timedelta(seconds=_HORIZON)


async def test_the_same_session_closes_work_the_service_abandoned_for_silence() -> None:
    clock, store, ids = ScenarioClock(), MemoryLineageStore(), FixedIds()
    coordinator = _coordinator(clock, store, ids, top_level_contact_lost_horizon_seconds=_WINDOW)
    task, session = await _root(coordinator, ids)
    await coordinator.mark_contact_lost(session_id=session)
    clock.advance(seconds=_WINDOW)
    (abandoned,) = await coordinator.recover_abandoned(_Appends())
    assert abandoned.work_state is WorkState.ABANDONED
    deadline = abandoned.abandonment_deadline

    async def renew(_lease_until: datetime) -> None:
        return None

    # The agent was working all along: its next call restores contact and its close stands.
    assert await coordinator.renew_observed_activity(
        task_id=task, session_id=session, renew_lease=renew
    )
    revived = await store.get_task(task)
    assert revived is not None and revived.work_state is WorkState.ABANDONED
    assert revived.abandonment_reason == "contact_lost"
    assert revived.abandonment_deadline == deadline
    closed = await coordinator.close_work(session_id=session)
    assert closed.work_state is WorkState.CLOSED
    # The reason stays as history, so status and receipts can say the abandonment was reversed.
    assert closed.abandonment_reason == "contact_lost"
    with pytest.raises(PublicOperationError) as again:
        await coordinator.cancel_work(session_id=session)
    assert again.value.code is PublicErrorCode.SESSION_CONFLICT
    assert again.value.safe_details["reason_code"] == "lineage_work_transition"
    # Closed work is terminal: a later silence loses contact but never abandons it again, so one
    # abandonment identity per task stays enough (no second episode can exist).
    await coordinator.mark_contact_lost(session_id=session)
    clock.advance(seconds=_HORIZON + 1)
    appends = _Appends()
    assert await coordinator.recover_abandoned(appends) == ()
    assert appends.rows == []
    still = await store.get_task(task)
    assert still is not None and still.work_state is WorkState.CLOSED


@pytest.mark.parametrize("target", ("cancel", "write_off"))
async def test_only_a_close_reverses_a_contact_lost_abandonment(target: str) -> None:
    clock, store, ids = ScenarioClock(), MemoryLineageStore(), FixedIds()
    coordinator = _coordinator(clock, store, ids, top_level_contact_lost_horizon_seconds=_WINDOW)
    task, session = await _root(coordinator, ids)
    await coordinator.mark_contact_lost(session_id=session)
    clock.advance(seconds=_WINDOW)
    await coordinator.recover_abandoned(_Appends())

    async def renew(_lease_until: datetime) -> None:
        return None

    await coordinator.renew_observed_activity(task_id=task, session_id=session, renew_lease=renew)
    transition = coordinator.cancel_work if target == "cancel" else coordinator.write_off_work
    with pytest.raises(PublicOperationError) as refused:
        await transition(session_id=session)
    assert refused.value.safe_details["reason_code"] == "lineage_work_transition"
    # The refusal names the state, its time and what still works.
    assert "abandoned (contact_lost) at " in refused.value.message
    assert "same session" in refused.value.message
    assert "successor task" in refused.value.message


async def test_an_abandonment_for_another_reason_stays_final() -> None:
    clock, store, ids = ScenarioClock(), MemoryLineageStore(), FixedIds()
    coordinator = _coordinator(clock, store, ids)
    task, session = await _root(coordinator, ids)
    snapshot = await store.get_task(task)
    assert snapshot is not None
    await store.save_task(
        replace(
            snapshot,
            work_state=WorkState.ABANDONED,
            abandonment_deadline=clock.now_utc(),
            abandonment_reason="attach_handle_expired",
        )
    )
    with pytest.raises(PublicOperationError) as refused:
        await coordinator.close_work(session_id=session)
    assert refused.value.safe_details["reason_code"] == "lineage_work_transition"
    assert "(attach_handle_expired)" in refused.value.message


async def test_an_abandonment_from_before_the_upgrade_learns_its_reason_from_replay() -> None:
    """A row abandoned under catalog 5 has no reason; its ledger event names it on replay."""

    clock, store, ids = ScenarioClock(), MemoryLineageStore(), FixedIds()
    coordinator = _coordinator(clock, store, ids)
    task, session = await _root(coordinator, ids)
    snapshot = await store.get_task(task)
    assert snapshot is not None
    await store.save_task(replace(snapshot, work_state=WorkState.ABANDONED))
    with pytest.raises(PublicOperationError):
        await coordinator.close_work(session_id=session)
    named = await coordinator.reconcile_owned_work(
        task_id=task, target=WorkState.ABANDONED, reason="contact_lost"
    )
    assert named.abandonment_reason == "contact_lost"
    # A later sweep replays the same event and writes nothing.
    assert (
        await coordinator.reconcile_owned_work(
            task_id=task, target=WorkState.ABANDONED, reason="contact_lost"
        )
        == named
    )
    closed = await coordinator.close_work(session_id=session)
    assert closed.work_state is WorkState.CLOSED
    assert closed.abandonment_reason == "contact_lost"


async def test_a_delivered_session_end_abandons_open_work_after_the_grace() -> None:
    clock, store, ids = ScenarioClock(), MemoryLineageStore(), FixedIds()
    coordinator = _coordinator(clock, store, ids)
    task, session = await _root(coordinator, ids)
    ended_at = clock.now_utc()
    ended = await coordinator.end_session(session_id=session)
    assert ended.session_health is SessionHealth.ENDED
    assert ended.abandonment_reason == "session_ended"
    assert ended.abandonment_deadline == ended_at + timedelta(seconds=_WINDOW)
    appends = _Appends()
    clock.advance(seconds=_WINDOW - 1)
    assert await coordinator.recover_abandoned(appends) == ()
    clock.advance(seconds=1)
    (abandoned,) = await coordinator.recover_abandoned(appends)
    assert abandoned.work_state is WorkState.ABANDONED
    assert abandoned.abandonment_reason == "session_ended"
    assert appends.rows == [(task, "session_ended", ended_at + timedelta(seconds=_WINDOW))]


async def test_closed_work_takes_no_session_end_deadline() -> None:
    clock, store, ids = ScenarioClock(), MemoryLineageStore(), FixedIds()
    coordinator = _coordinator(clock, store, ids)
    task, session = await _root(coordinator, ids)
    await coordinator.close_work(session_id=session)
    ended = await coordinator.end_session(session_id=session)
    assert ended.work_state is WorkState.CLOSED
    assert ended.abandonment_deadline is None and ended.abandonment_reason is None
    clock.advance(seconds=_WINDOW * 2)
    assert await coordinator.recover_abandoned(_Appends()) == ()
    assert (await store.get_task(task)) == ended


async def test_returning_contact_clears_a_pending_abandonment() -> None:
    clock, store, ids = ScenarioClock(), MemoryLineageStore(), FixedIds()
    coordinator = _coordinator(clock, store, ids)
    task, session = await _root(coordinator, ids)
    await coordinator.mark_contact_lost(session_id=session)
    clock.advance(seconds=_WINDOW * 4)

    async def renew(_lease_until: datetime) -> None:
        return None

    assert await coordinator.renew_observed_activity(
        task_id=task, session_id=session, renew_lease=renew
    )
    restored = await store.get_task(task)
    assert restored is not None and restored.session_health is SessionHealth.ACTIVE
    assert restored.abandonment_deadline is None and restored.abandonment_reason is None
    assert await coordinator.own_lifecycle(task) == restored


class _CountingStore(MemoryLineageStore):
    """Counts single-task reads, so a sweep that re-reads each parent shows up."""

    reads = 0

    async def get_task(self, task_id: str) -> LineageSnapshot | None:
        type(self).reads += 1
        return await MemoryLineageStore.get_task(self, task_id)


async def test_one_sweep_judges_many_quiet_tasks_from_one_store_read() -> None:
    """A sweep over many quiet children judges each window from its listing, not per parent."""

    clock, store, ids = ScenarioClock(), _CountingStore(), FixedIds()
    coordinator = _coordinator(clock, store, ids)
    parents = [await _root(coordinator, ids) for _ in range(20)]
    children = [await _child(store, ids, parent) for parent, _ in parents for _ in range(10)]
    for _, child_session in children:
        await coordinator.mark_contact_lost(session_id=child_session)
    clock.advance(seconds=_WINDOW - 1)
    _CountingStore.reads = 0
    assert await coordinator.recover_abandoned(_Appends()) == ()
    assert _CountingStore.reads == 0
    clock.advance(seconds=1)
    recovered = await coordinator.recover_abandoned(_Appends())
    assert len(recovered) == len(children)


def test_the_horizon_is_never_shorter_than_the_recovery_window() -> None:
    with pytest.raises(ValueError):
        LineageConfig(contact_lost_recovery_seconds=600, top_level_contact_lost_horizon_seconds=599)
    with pytest.raises(ValueError):
        LineageConfig(top_level_contact_lost_horizon_seconds=604_801)
    assert LineageConfig(top_level_contact_lost_horizon_seconds=604_800)


class _StartCatalog:
    """The two start-catalog reads ``observed_session_end`` makes, with fixed answers."""

    def __init__(self, task: str, session: str, writer: str, lease: datetime | None) -> None:
        self.binding = SimpleNamespace(task_id=task, session_id=session, writer_id=writer)
        self.lease = lease

    async def session_binding(self, session_id: str) -> object:
        return self.binding if session_id == self.binding.session_id else None

    async def task_session_states(self, task_id: str) -> tuple[object, ...]:
        del task_id
        return (SimpleNamespace(session_id=self.binding.session_id, lease_expires_at=self.lease),)


@pytest.mark.parametrize("case", ("ends", "later_lease", "other_writer", "rotated"))
async def test_a_delivered_session_end_ends_only_the_current_session(case: str) -> None:
    clock, store, ids = ScenarioClock(), MemoryLineageStore(), FixedIds()
    coordinator = _coordinator(clock, store, ids)
    task, session = await _root(coordinator, ids)
    writer = ids.new(IdKind.WRITER)
    observed = clock.now_utc()
    lease = observed + timedelta(seconds=SESSION_LEASE_SECONDS)
    if case == "later_lease":
        # A resumed host renewed the lease past this end's own lease: the end is stale.
        lease += timedelta(seconds=1)
    catalog = _StartCatalog(task, session, writer, lease)
    if case == "rotated":
        snapshot = await store.get_task(task)
        assert snapshot is not None
        await store.save_task(replace(snapshot, active_session_id=ids.new(IdKind.SESSION)))
    hook = observed_session_end(catalog, coordinator)
    await hook(
        task, session, writer if case != "other_writer" else ids.new(IdKind.WRITER), observed
    )
    after = await store.get_task(task)
    assert after is not None
    if case == "ends":
        assert after.session_health is SessionHealth.ENDED
        assert after.abandonment_reason == "session_ended"
    else:
        assert after.session_health is SessionHealth.ACTIVE
        assert after.abandonment_reason is None


async def test_a_day_of_quiet_top_level_tasks_sweeps_well_inside_the_recovery_deadline() -> None:
    """The horizon keeps quiet tasks ``contact_lost`` for a day; the sweep stays linear.

    The daemon gives one recovery pass 30 seconds (``_LINEAGE_RECOVERY_DEADLINE_SECONDS``). The
    sweep reads the store once and judges every window from that listing, so thousands of
    long-lived quiet tasks cost one pass, not one read each.
    """

    clock, store, ids = ScenarioClock(), _CountingStore(), FixedIds()
    coordinator = _coordinator(clock, store, ids)
    sessions = [(await _root(coordinator, ids))[1] for _ in range(2_000)]
    for session in sessions:
        await coordinator.mark_contact_lost(session_id=session)
    clock.advance(seconds=_HORIZON // 2)
    _CountingStore.reads = 0
    started = time.monotonic()
    assert await coordinator.recover_abandoned(_Appends()) == ()

    async def renew(_task_id: str, _session_id: str, _lease_until: datetime) -> bool:
        return True

    assert await coordinator.hold_in_flight_contact(renew) == ()
    elapsed = time.monotonic() - started
    assert _CountingStore.reads == 0
    assert elapsed < 30, elapsed


async def test_a_declared_quiet_period_moves_a_waiting_parents_child_deadline() -> None:
    """D6: a child declaring a long build is not abandoned inside its declared quiet period."""

    clock, store, ids = ScenarioClock(), MemoryLineageStore(), FixedIds()
    coordinator = _coordinator(clock, store, ids)
    parent, _ = await _root(coordinator, ids)
    child, child_session = await _child(store, ids, parent)
    declared_at = clock.now_utc()
    declared = await coordinator.declare_quiet_period(
        session_id=child_session, expected_quiet_seconds=1_800
    )
    assert declared.quiet_until == declared_at + timedelta(seconds=1_800)
    clock.advance(seconds=61)
    lost = await coordinator.mark_contact_lost(session_id=child_session)
    # The window runs from the end of the quiet period, not from the loss of contact.
    assert lost.abandonment_deadline == declared_at + timedelta(seconds=1_800 + _WINDOW)
    appends = _Appends()
    clock.advance(seconds=1_800)
    assert await coordinator.recover_abandoned(appends) == ()
    clock.advance(seconds=_WINDOW)
    (abandoned,) = await coordinator.recover_abandoned(appends)
    assert abandoned.task_id == child
    assert appends.rows == [
        (child, "contact_lost", declared_at + timedelta(seconds=1_800 + _WINDOW))
    ]


@pytest.mark.parametrize(
    ("cap", "requested", "effective"),
    ((3_600, 86_400, 3_600), (3_600, 600, 600), (0, 1_800, None)),
)
async def test_the_config_clamps_or_disables_a_declared_quiet_period(
    cap: int, requested: int, effective: int | None
) -> None:
    clock, store, ids = ScenarioClock(), MemoryLineageStore(), FixedIds()
    coordinator = _coordinator(clock, store, ids, max_declared_quiet_seconds=cap)
    _, session = await _root(coordinator, ids)
    declared = await coordinator.declare_quiet_period(
        session_id=session, expected_quiet_seconds=requested
    )
    expected = None if effective is None else clock.now_utc() + timedelta(seconds=effective)
    assert declared.quiet_until == expected


async def test_a_later_declaration_replaces_and_contact_never_clears_one() -> None:
    clock, store, ids = ScenarioClock(), MemoryLineageStore(), FixedIds()
    coordinator = _coordinator(clock, store, ids)
    task, session = await _root(coordinator, ids)
    await coordinator.declare_quiet_period(session_id=session, expected_quiet_seconds=3_000)
    shorter = await coordinator.declare_quiet_period(session_id=session, expected_quiet_seconds=120)
    assert shorter.quiet_until == clock.now_utc() + timedelta(seconds=120)

    async def renew(_lease_until: datetime) -> None:
        return None

    clock.advance(seconds=30)
    # A hook firing as the long command starts is contact; the declaration stands.
    assert await coordinator.renew_observed_activity(
        task_id=task, session_id=session, renew_lease=renew
    )
    kept = await store.get_task(task)
    assert kept is not None and kept.quiet_until == shorter.quiet_until
    lifecycle = await coordinator.own_lifecycle(task)
    assert lifecycle is not None and lifecycle.quiet_until == shorter.quiet_until
    clock.advance(seconds=91)
    # Once it has passed, status no longer reports it.
    passed = await coordinator.own_lifecycle(task)
    assert passed is not None and passed.quiet_until is None


async def test_status_keeps_the_quiet_deadline_after_the_period_passes() -> None:
    """The deadline status reports is the sweep's own, also once the quiet period has passed."""

    clock, store, ids = ScenarioClock(), MemoryLineageStore(), FixedIds()
    coordinator = _coordinator(clock, store, ids)
    parent, _ = await _root(coordinator, ids)
    child, child_session = await _child(store, ids, parent)
    declared_at = clock.now_utc()
    await coordinator.declare_quiet_period(session_id=child_session, expected_quiet_seconds=1_800)
    clock.advance(seconds=61)
    await coordinator.mark_contact_lost(session_id=child_session)
    deadline = declared_at + timedelta(seconds=1_800 + _WINDOW)
    lifecycle = None
    for seconds in (1_000, 800):  # inside the period, then just after it ends
        clock.advance(seconds=seconds)
        lifecycle = await coordinator.own_lifecycle(child)
        assert lifecycle is not None and lifecycle.abandonment_deadline == deadline
    assert lifecycle is not None and lifecycle.quiet_until is None
    assert await coordinator.recover_abandoned(_Appends()) == ()


async def test_only_the_tasks_own_session_declares_and_replay_is_idempotent() -> None:
    clock, store, ids = ScenarioClock(), MemoryLineageStore(), FixedIds()
    coordinator = _coordinator(clock, store, ids)
    task, session = await _root(coordinator, ids)
    with pytest.raises(PublicOperationError) as refused:
        await coordinator.validate_quiet_declaration(session_id=ids.new(IdKind.SESSION))
    assert refused.value.safe_details["reason_code"] == "lineage_session_not_active"
    await coordinator.validate_quiet_declaration(session_id=session)
    declared_at = clock.now_utc() - timedelta(seconds=5)
    first = await coordinator.reconcile_quiet_period(
        task_id=task, expected_quiet_seconds=900, declared_at=declared_at
    )
    assert first.quiet_until == declared_at + timedelta(seconds=900)
    again = await coordinator.reconcile_quiet_period(
        task_id=task, expected_quiet_seconds=900, declared_at=declared_at
    )
    assert again == first  # no second write, no new revision
    # The catalog sync runs after the append; it starts the period at the accepted time, so the
    # reconcile of the same event later writes nothing either.
    accepted_at = clock.now_utc()
    clock.advance(seconds=2)
    live = await coordinator.declare_quiet_period(
        session_id=session, expected_quiet_seconds=900, declared_at=accepted_at
    )
    assert live.quiet_until == accepted_at + timedelta(seconds=900)
    assert (
        await coordinator.reconcile_quiet_period(
            task_id=task, expected_quiet_seconds=900, declared_at=accepted_at
        )
        == live
    )


@pytest.mark.parametrize(("cap", "effective"), ((3_600, 900), (600, 600)))
async def test_an_announced_call_keeps_a_waited_on_child_open_past_the_window(
    cap: int, effective: int
) -> None:
    """D6: a pre-tool hook naming a 900 s timeout holds the child for min(timeout, cap) + window.

    The child declares nothing. Without the implied period it would be abandoned at
    ``contact_lost_at + window``, while its own build was still running.
    """

    clock, store, ids = ScenarioClock(), MemoryLineageStore(), FixedIds()
    coordinator = _coordinator(clock, store, ids, max_declared_quiet_seconds=cap)
    parent, _ = await _root(coordinator, ids)
    child, child_session = await _child(store, ids, parent)
    started_at = clock.now_utc()
    assert await coordinator.imply_quiet_period(
        task_id=child,
        session_id=child_session,
        started_at=started_at,
        expected_quiet_seconds=900,
    )
    implied = await store.get_task(child)
    assert implied is not None
    assert implied.implied_quiet_until == started_at + timedelta(seconds=effective)
    assert implied.quiet_until is None  # never written into the declared period
    clock.advance(seconds=SESSION_LEASE_SECONDS + 1)
    lost = await coordinator.mark_contact_lost(session_id=child_session)
    deadline = started_at + timedelta(seconds=effective + _WINDOW)
    assert lost.abandonment_deadline == deadline
    # Status names the running call's period with the same field a declaration uses.
    lifecycle = await coordinator.own_lifecycle(child)
    assert lifecycle is not None
    assert lifecycle.quiet_until == started_at + timedelta(seconds=effective)
    assert lifecycle.abandonment_deadline == deadline
    appends = _Appends()
    # Past the ordinary deadline (contact_lost_at + window) the child is still open.
    clock.advance(seconds=_WINDOW + 1)
    assert await coordinator.recover_abandoned(appends) == ()
    clock.advance(seconds=int((deadline - clock.now_utc()).total_seconds()) - 1)
    assert await coordinator.recover_abandoned(appends) == ()
    clock.advance(seconds=1)
    (abandoned,) = await coordinator.recover_abandoned(appends)
    assert abandoned.task_id == child and abandoned.work_state is WorkState.ABANDONED
    assert appends.rows == [(child, "contact_lost", deadline)]


async def test_a_cap_of_zero_lets_an_announced_call_imply_nothing() -> None:
    clock, store, ids = ScenarioClock(), MemoryLineageStore(), FixedIds()
    coordinator = _coordinator(clock, store, ids, max_declared_quiet_seconds=0)
    parent, _ = await _root(coordinator, ids)
    child, child_session = await _child(store, ids, parent)
    before = await store.get_task(child)
    assert not await coordinator.imply_quiet_period(
        task_id=child,
        session_id=child_session,
        started_at=clock.now_utc(),
        expected_quiet_seconds=900,
    )
    assert await store.get_task(child) == before
    clock.advance(seconds=SESSION_LEASE_SECONDS + 1)
    lost_at = clock.now_utc()
    lost = await coordinator.mark_contact_lost(session_id=child_session)
    assert lost.abandonment_deadline == lost_at + timedelta(seconds=_WINDOW)


@pytest.mark.parametrize("caller", ("parent_session", "unknown_session", "ended", "rotated"))
async def test_a_call_bound_to_another_session_implies_nothing(caller: str) -> None:
    """Only the task's own active session's call counts; a declaration's rule does not weaken."""

    clock, store, ids = ScenarioClock(), MemoryLineageStore(), FixedIds()
    coordinator = _coordinator(clock, store, ids)
    parent, parent_session = await _root(coordinator, ids)
    child, child_session = await _child(store, ids, parent)
    session = {"parent_session": parent_session, "unknown_session": ids.new(IdKind.SESSION)}.get(
        caller, child_session
    )
    if caller == "ended":
        await coordinator.end_session(session_id=child_session)
    elif caller == "rotated":
        snapshot = await store.get_task(child)
        assert snapshot is not None
        await store.save_task(replace(snapshot, active_session_id=ids.new(IdKind.SESSION)))
    before = await store.get_task(child)
    parent_before = await store.get_task(parent)
    assert not await coordinator.imply_quiet_period(
        task_id=child,
        session_id=session,
        started_at=clock.now_utc(),
        expected_quiet_seconds=900,
    )
    assert await store.get_task(child) == before
    assert await store.get_task(parent) == parent_before


async def test_an_implied_period_survives_restart_reconcile_and_later_calls() -> None:
    """The implied period is catalog state: a restart keeps it and reconcile never erases it.

    Reconcile replays only the ledger's latest declaration into ``quiet_until``; it neither
    shortens a running call's period nor turns the call's period into a declared one. A later
    shorter call, a shorter declaration, contact and a duplicate delivery keep the latest end.
    """

    clock, store, ids = ScenarioClock(), MemoryLineageStore(), FixedIds()
    coordinator = _coordinator(clock, store, ids)
    parent, _ = await _root(coordinator, ids)
    child, child_session = await _child(store, ids, parent)
    declared_at = clock.now_utc()
    await coordinator.declare_quiet_period(
        session_id=child_session, expected_quiet_seconds=120, declared_at=declared_at
    )
    started_at = clock.now_utc()
    assert await coordinator.imply_quiet_period(
        task_id=child,
        session_id=child_session,
        started_at=started_at,
        expected_quiet_seconds=1_200,
    )
    implied_until = started_at + timedelta(seconds=1_200)
    held = await store.get_task(child)
    assert held is not None and held.implied_quiet_until == implied_until
    # A duplicate delivery and a later, shorter overlapping call write nothing.
    clock.advance(seconds=10)
    for start, seconds in ((started_at, 1_200), (clock.now_utc(), 60)):
        assert await coordinator.imply_quiet_period(
            task_id=child,
            session_id=child_session,
            started_at=start,
            expected_quiet_seconds=seconds,
        )
    assert await store.get_task(child) == held

    async def renew(_lease_until: datetime) -> None:
        return None

    # Contact (the finishing hook) and a shorter declaration leave the call's period running.
    assert await coordinator.renew_observed_activity(
        task_id=child, session_id=child_session, renew_lease=renew
    )
    shorter_at = clock.now_utc()
    shorter = await coordinator.declare_quiet_period(
        session_id=child_session, expected_quiet_seconds=30, declared_at=shorter_at
    )
    assert shorter.quiet_until == shorter_at + timedelta(seconds=30)
    assert shorter.implied_quiet_until == implied_until

    # A service restart: a fresh coordinator over the same catalog. Reconcile replays the
    # ledger's latest declaration, which the catalog already mirrors, so it writes nothing: the
    # call's period stays, and the declared period stays the declaration's own.
    restarted = _coordinator(clock, store, ids)
    replayed = await restarted.reconcile_quiet_period(
        task_id=child, expected_quiet_seconds=30, declared_at=shorter_at
    )
    assert replayed == shorter
    # A replay that still has to repair the declared period (an append-before-sync crash left
    # the earlier declaration in the catalog) replaces only that period.
    await store.save_task(replace(shorter, quiet_until=declared_at + timedelta(seconds=120)))
    repaired = await restarted.reconcile_quiet_period(
        task_id=child, expected_quiet_seconds=30, declared_at=shorter_at
    )
    assert repaired.quiet_until == shorter.quiet_until
    assert repaired.implied_quiet_until == implied_until
    clock.advance(seconds=SESSION_LEASE_SECONDS + 1)
    lost = await restarted.mark_contact_lost(session_id=child_session)
    deadline = implied_until + timedelta(seconds=_WINDOW)
    assert lost.abandonment_deadline == deadline
    clock.advance(seconds=int((deadline - clock.now_utc()).total_seconds()) - 1)
    assert await restarted.recover_abandoned(_Appends()) == ()
    clock.advance(seconds=1)
    (abandoned,) = await restarted.recover_abandoned(_Appends())
    assert abandoned.task_id == child


async def test_a_late_end_for_a_rotated_session_ends_nothing() -> None:
    """The coordinator re-checks the active session under its lock before ending it."""

    clock, store, ids = ScenarioClock(), MemoryLineageStore(), FixedIds()
    coordinator = _coordinator(clock, store, ids)
    task, session = await _root(coordinator, ids)
    snapshot = await store.get_task(task)
    assert snapshot is not None
    rotated = replace(snapshot, active_session_id=ids.new(IdKind.SESSION))
    await store.save_task(rotated)
    # The predecessor's mapping still resolves to the task, but it is no longer the active one.
    assert await coordinator.end_session(session_id=session) == rotated
    assert await store.get_task(task) == rotated
