"""Issue #836: a stranded capture handoff cannot hold shared admission closed.

A handoff (capture ticket plus central reservation) that no structural row can
consume any more used to stay ``pending`` while its authority was current. Its
age alone held oldest-age pressure at the hard limit with an empty queue. These
tests use the real start catalog, two real task bundles, the READY handoff
router, and the outbox sweeper. Handoffs are backdated rather than waited for,
so the pending-age gate itself is exercised unchanged.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.adapters.sqlite.observation import SqliteObservationStore
from finishup.application.observation_coordinator import ObservationCoordinator
from finishup.application.observation_drain import ObservationCaptureRecoveryOutcome
from finishup.application.observation_materialize import observation_content_identity
from finishup.application.semantic_content import resolve_captured_semantic_content
from finishup.cli.observe_hooks import map_hook_payload_to_envelope
from finishup.domain.observation import (
    OBSERVATION_CONTENT_CAPTURE_PENDING_REASON,
    CaptureHandoffRetirementReason,
    CaptureHandoffRetirementStage,
    ObservationCaptureBacklog,
    ObservationCaptureTicket,
    ObservationContentChunk,
    ObservationContentKind,
    ObservationCursor,
    ObservationEnvelope,
    ObservationGapCode,
    ObservationIngestRequest,
    ObservationSource,
    observation_capture_ticket_id,
)
from finishup.domain.observation_profiles import (
    CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
    CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
)
from finishup.domain.values import JsonObject, timestamp_from_datetime
from finishup.ports.ledger import FrozenCase
from finishup.ports.observation import TaskObservationPort
from finishup.ports.runtime import BundleRuntimePort, TaskRuntime
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.ids import IdKind
from integration.application import test_native_capture_pipeline as native
from integration.service import test_capture_inventory_recovery as inventory

_STRANDED_AGE_SECONDS = 61
_PROFILES: Mapping[str, str | None] = {
    "claude": CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
    "cursor": CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
    "codex": None,
}
_SOURCES: Mapping[str, ObservationSource] = {
    "claude": ObservationSource.CLAUDE_HOOK,
    "cursor": ObservationSource.CURSOR_HOOK,
    "codex": ObservationSource.CODEX_HOOK,
}


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class _ServiceClock:
    """The real service clock; tests never move it, they backdate handoffs."""

    def now_utc(self) -> datetime:
        now = datetime.now(UTC)
        return now.replace(microsecond=(now.microsecond // 1_000) * 1_000)

    def monotonic_seconds(self) -> float:
        return time.monotonic()


@dataclass
class _Handoff:
    world: inventory._World  # pyright: ignore[reportPrivateUsage]
    host: str

    @property
    def workspace(self) -> str:
        return self.world.workspace

    def status(self) -> Mapping[str, object]:
        return self.world.local.selection_runtime_status(self.workspace, self.world.session)

    def publish_inventory(self) -> None:
        """Publish a complete, identity-bound inventory for both task routes."""

        backlogs: dict[str, ObservationCaptureBacklog] = {}
        identities: dict[str, tuple[str, ...]] = {}
        for runtime, store in self.routes():
            backlogs[runtime.task_id] = store.capture_backlog(self.workspace)
            identities[runtime.task_id] = tuple(
                observation_capture_ticket_id(ticket)
                for ticket in store.list_pending_capture_tickets(runtime.task_id)
                if ticket.workspace_commitment == self.workspace
            )
        assert self.world.local.bootstrap_capture_reservations(
            self.workspace, backlogs, ticket_ids_by_task=identities
        )

    def routes(self) -> tuple[tuple[TaskRuntime, SqliteObservationStore], ...]:
        return (
            (self.world.runtime, self.world.observation),
            (self.world.sibling, self.world.sibling_observation),
        )

    def strand(
        self,
        identity: str,
        *,
        sibling: bool = False,
        generation: str | None = None,
        reserve: bool = True,
    ) -> ObservationCaptureTicket:
        """Record a staged handoff and its central reservation, 61 seconds old."""

        runtime, store = self.routes()[1 if sibling else 0]
        authority = self.world.local.content_capture_authority(self.workspace)
        assert authority is not None
        captured = datetime.now(UTC) - timedelta(seconds=_STRANDED_AGE_SECONDS)
        ticket = ObservationCaptureTicket(
            workspace_commitment=self.workspace,
            task_id=runtime.task_id,
            yoetz_session_id=runtime.session_id,
            session_commitment=self.world.session,
            source=_SOURCES[self.host],
            source_identity=identity,
            cursor=self.cursor(),
            logical_identity=f"stranded-{identity}",
            content_capture_profile=_PROFILES[self.host],
            authority_generation=generation or authority.generation,
            object_ids=(),
            captured_at=timestamp_from_datetime(
                captured.replace(microsecond=(captured.microsecond // 1_000) * 1_000)
            ),
        )
        store.record_capture_ticket(ticket)
        if reserve:
            # The reservation was taken when the handoff was staged.
            then = LocalObservationStore(
                _state=self.world.root / "state",
                _wall=lambda: time.time() - _STRANDED_AGE_SECONDS,
            )
            then.reserve_capture_ticket(
                self.workspace, observation_capture_ticket_id(ticket), runtime.task_id, 144
            )
        return ticket

    def cursor(self) -> ObservationCursor:
        return ObservationCursor(1, 0, 7, "hmac-sha256:" + "a" * 64, "native-obs-hook/1.0.0")

    def envelope(self, identity: str) -> ObservationEnvelope:
        return ObservationEnvelope(
            session_commitment=self.world.session,
            event_kind="PostToolUse",
            source_identity=identity,
            source=_SOURCES[self.host],
            cursor=self.cursor(),
            receipt_time=timestamp_from_datetime(_ServiceClock().now_utc()),
            structural_payload=JsonObject({"tool_name": "Bash", "exit_status": 1}),
            content_object_refs=(),
            gap_codes=(),
        )

    def load(self, ticket: ObservationCaptureTicket) -> ObservationCaptureTicket | None:
        store = (
            self.world.sibling_observation
            if ticket.task_id == self.world.sibling.task_id
            else self.world.observation
        )
        return store.load_capture_ticket(
            workspace=self.workspace, logical_identity=ticket.logical_identity
        )

    def retirements(self) -> tuple[Mapping[str, object], ...]:
        account = self.world.local.capture_handoff_retirements(self.workspace)
        return cast(tuple[Mapping[str, object], ...], account["recent"])


async def _handoff(tmp_path: Path, *, host: str = "claude") -> _Handoff:
    world = await inventory._world(tmp_path, host=host)  # pyright: ignore[reportPrivateUsage]
    world.coordinator.clock = _ServiceClock()
    world.wire()
    handoff = _Handoff(world, host)
    handoff.publish_inventory()
    return handoff


def _assert_aged_handoff(handoff: _Handoff) -> None:
    status = handoff.status()
    budget = cast(Mapping[str, object], status["effective_budget"])
    assert status["queue_count"] == 0
    assert cast(int, status["oldest_pending_age_ms"]) >= _STRANDED_AGE_SECONDS * 1_000
    assert status["pressure_state"] == "healthy"
    assert budget["limiting_dimension"] in {"bytes", "capture_backlog"}
    assert status["admission_allowed"] is True
    assert status["content_allowed"] is True


def _assert_admitting(handoff: _Handoff) -> None:
    status = handoff.status()
    # Hard admission follows current usage at once; optional detail still waits
    # for the unchanged low-water recovery dwell after a hard-limit episode.
    assert status["admission_allowed"] is True
    assert status["pressure_state"] in {"healthy", "high"}
    assert status["oldest_pending_age_ms"] == 0
    backlog = handoff.world.local.capture_backlog(handoff.workspace)
    assert (backlog["count"], backlog["reservation_count"]) == (0, 0)


@pytest.mark.anyio
@pytest.mark.parametrize("sibling", (False, True), ids=("mapped-task", "sibling-task"))
async def test_sweep_retires_a_handoff_whose_structural_row_is_gone(
    tmp_path: Path, sibling: bool
) -> None:
    """The native stall shape: one aged ticket, known inventory, empty queue."""

    handoff = await _handoff(tmp_path)
    ticket = handoff.strand("row-already-acknowledged", sibling=sibling)
    handoff.publish_inventory()
    backlog = handoff.world.local.capture_backlog(handoff.workspace)
    assert backlog["reservation_unknown"] is False
    _assert_aged_handoff(handoff)
    losses_before = handoff.world.local.selection_accounting(handoff.workspace)

    sweeper = handoff.world.sweep()
    try:
        summary = await sweeper.sweep()
        assert summary.attempted == 0
        assert summary.reasons == (("capture_handoff_retired", 1),)
        retired = handoff.load(ticket)
        assert retired is not None and retired.state == "revoked"
        _assert_admitting(handoff)
        # Retirement names its transition and records the honest content gap,
        # without touching structural loss accounting.
        (entry,) = handoff.retirements()
        assert entry["stage"] == "sweep"
        assert entry["reason"] == "structural_row_absent"
        assert entry["ticket_state"] == "staging"
        assert entry["task_id"] == ticket.task_id
        assert cast(int, entry["age_ms"]) >= _STRANDED_AGE_SECONDS * 1_000
        assert handoff.world.local.selection_accounting(handoff.workspace) == losses_before
        assert handoff.world.requests == []
        assert not handoff.world.routes.held
        # A healthy workspace does not keep scanning.
        calls = len(handoff.world.routes.calls)
        assert (await sweeper.sweep()).reasons == ()
        assert len(handoff.world.routes.calls) == calls
    finally:
        sweeper.close()
        handoff.world.coordinator.close()


@pytest.mark.anyio
async def test_retirement_account_failure_keeps_handoff_for_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed accounting write cannot discard the only recovery evidence."""

    handoff = await _handoff(tmp_path)
    ticket = handoff.strand("accounting-write-fails")
    handoff.publish_inventory()
    original = handoff.world.local.record_capture_handoff_retirement

    def unavailable(*_args: object, **_kwargs: object) -> None:
        raise OSError("synthetic-accounting-store-failure")

    monkeypatch.setattr(handoff.world.local, "record_capture_handoff_retirement", unavailable)
    try:
        assert (
            await handoff.world.coordinator.reconcile_task_capture_handoffs(handoff.world.runtime)
            == 0
        )
        kept = handoff.load(ticket)
        assert kept is not None and kept.state == "staging"
        assert handoff.world.local.capture_backlog(handoff.workspace)["reservation_count"] == 1
        assert handoff.retirements() == ()

        monkeypatch.setattr(handoff.world.local, "record_capture_handoff_retirement", original)
        assert (
            await handoff.world.coordinator.reconcile_task_capture_handoffs(handoff.world.runtime)
            == 1
        )
        retired = handoff.load(ticket)
        assert retired is not None and retired.state == "revoked"
        assert handoff.world.local.capture_backlog(handoff.workspace)["reservation_count"] == 0
        assert len(handoff.retirements()) == 1
    finally:
        handoff.world.coordinator.close()


@pytest.mark.anyio
async def test_retirement_replay_after_cancellation_does_not_duplicate_loss(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cancellation after accounting commits leaves an idempotent retry point."""

    handoff = await _handoff(tmp_path)
    ticket = handoff.strand("accounting-before-cancel")
    handoff.publish_inventory()
    original = handoff.world.coordinator._retire_capture_ticket  # pyright: ignore[reportPrivateUsage]
    cancelled = True

    async def cancel_once(
        workspace: str,
        runtime: TaskRuntime,
        store: TaskObservationPort,
        ticket: ObservationCaptureTicket,
        *,
        delete: bool = False,
    ) -> None:
        nonlocal cancelled
        if cancelled:
            cancelled = False
            raise asyncio.CancelledError
        await original(workspace, runtime, store, ticket, delete=delete)

    monkeypatch.setattr(handoff.world.coordinator, "_retire_capture_ticket", cancel_once)
    try:
        with pytest.raises(asyncio.CancelledError):
            await handoff.world.coordinator.reconcile_task_capture_handoffs(handoff.world.runtime)
        kept = handoff.load(ticket)
        assert kept is not None and kept.state == "staging"
        assert handoff.world.local.capture_backlog(handoff.workspace)["reservation_count"] == 1
        assert len(handoff.retirements()) == 1

        monkeypatch.setattr(handoff.world.coordinator, "_retire_capture_ticket", original)
        assert (
            await handoff.world.coordinator.reconcile_task_capture_handoffs(handoff.world.runtime)
            == 1
        )
        retired = handoff.load(ticket)
        assert retired is not None and retired.state == "revoked"
        assert handoff.world.local.capture_backlog(handoff.workspace)["reservation_count"] == 0
        assert len(handoff.retirements()) == 1
    finally:
        handoff.world.coordinator.close()


@pytest.mark.anyio
async def test_legacy_handoff_account_stays_retryable_past_512_other_retirements(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A legacy ticket without a reservation cannot lose its replay identity."""

    handoff = await _handoff(tmp_path)
    ticket = handoff.strand("legacy-no-reservation", reserve=False)
    handoff.publish_inventory()
    assert handoff.world.local.capture_backlog(handoff.workspace)["reservation_count"] == 0
    original = handoff.world.coordinator._retire_capture_ticket  # pyright: ignore[reportPrivateUsage]

    async def fail_retirement(
        _workspace: str,
        _runtime: TaskRuntime,
        _store: TaskObservationPort,
        _ticket: ObservationCaptureTicket,
        *,
        delete: bool = False,
    ) -> None:
        del delete
        raise OSError("synthetic-ticket-retirement-failure")

    monkeypatch.setattr(handoff.world.coordinator, "_retire_capture_ticket", fail_retirement)
    try:
        with pytest.raises(OSError):
            await handoff.world.coordinator.reconcile_task_capture_handoffs(handoff.world.runtime)
        ticket_id = observation_capture_ticket_id(ticket)
        with handoff.world.local._lock:  # pyright: ignore[reportPrivateUsage]
            state = handoff.world.local._load(handoff.workspace)  # pyright: ignore[reportPrivateUsage]
            assert state.capture_handoff_retirement_pending == {ticket_id: ticket.task_id}

        def account_and_confirm(ticket_id: str) -> None:
            handoff.world.local.record_capture_handoff_retirement(
                handoff.workspace,
                ticket_id=ticket_id,
                stage=CaptureHandoffRetirementStage.SWEEP,
                reason=CaptureHandoffRetirementReason.STRUCTURAL_ROW_ABSENT,
                ticket_state="pending",
                source=ticket.source,
                task_id=ticket.task_id,
                age_ms=61_000,
            )
            handoff.world.local.confirm_capture_handoff_retirement(
                handoff.workspace, ticket_id, ticket.task_id
            )

        for index in range(513):
            account_and_confirm("sha256:" + format(2_000 + index, "064x"))
        with handoff.world.local._lock:  # pyright: ignore[reportPrivateUsage]
            state = handoff.world.local._load(handoff.workspace)  # pyright: ignore[reportPrivateUsage]
            assert state.capture_handoff_retirement_pending == {ticket_id: ticket.task_id}
            assert ticket_id in state.capture_handoff_retirement_ids
            assert state.capture_handoff_retired_count == 514

        monkeypatch.setattr(handoff.world.coordinator, "_retire_capture_ticket", original)
        assert (
            await handoff.world.coordinator.reconcile_task_capture_handoffs(handoff.world.runtime)
            == 1
        )
        retired = handoff.load(ticket)
        assert retired is not None and retired.state == "revoked"
        assert handoff.world.local.capture_handoff_retirement_workspaces(ticket.task_id) == ()
        assert (
            handoff.world.local.capture_handoff_retirements(handoff.workspace)["retired_count"]
            == 514
        )
    finally:
        handoff.world.coordinator.close()


@pytest.mark.anyio
async def test_tombstone_before_confirmation_is_reconciled_after_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A confirmation failure after tombstoning is cleaned from durable pending state."""

    handoff = await _handoff(tmp_path)
    ticket = handoff.strand("tombstone-before-confirm", reserve=False)
    handoff.publish_inventory()

    def confirmation_unavailable(*_args: object, **_kwargs: object) -> None:
        raise OSError("synthetic-confirmation-failure")

    monkeypatch.setattr(
        handoff.world.local,
        "confirm_capture_handoff_retirement",
        confirmation_unavailable,
    )
    try:
        with pytest.raises(OSError):
            await handoff.world.coordinator.reconcile_task_capture_handoffs(handoff.world.runtime)
        retired = handoff.load(ticket)
        assert retired is not None and retired.state == "revoked"
        ticket_id = observation_capture_ticket_id(ticket)
        with handoff.world.local._lock:  # pyright: ignore[reportPrivateUsage]
            state = handoff.world.local._load(handoff.workspace)  # pyright: ignore[reportPrivateUsage]
            assert state.capture_handoff_retirement_pending == {ticket_id: ticket.task_id}

        world = handoff.world
        prior_coordinator = world.coordinator
        prior_coordinator.close()
        world.local = LocalObservationStore(_state=tmp_path / "state")
        world.coordinator = ObservationCoordinator(
            runtime=cast(BundleRuntimePort, world.routes),
            local=world.local,
            clock=_ServiceClock(),
            ids=prior_coordinator.ids,
            state_root=tmp_path / "state",
        )
        world.wire()
        assert world.local.capture_handoff_retirement_workspaces(ticket.task_id) == (
            handoff.workspace,
        )
        assert await world.coordinator.reconcile_task_capture_handoffs(world.runtime) == 0
        assert world.local.capture_handoff_retirement_workspaces(ticket.task_id) == ()
        assert world.local.capture_handoff_retirements(handoff.workspace)["retired_count"] == 1
    finally:
        handoff.world.coordinator.close()


@pytest.mark.anyio
async def test_schema_unavailable_preserves_pending_retirement_account(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unavailable capture-ticket schema cannot authorize pending cleanup."""

    handoff = await _handoff(tmp_path)
    ticket = handoff.strand("schema-unavailable", reserve=False)
    ticket_id = observation_capture_ticket_id(ticket)
    handoff.world.local.record_capture_handoff_retirement(
        handoff.workspace,
        ticket_id=ticket_id,
        stage=CaptureHandoffRetirementStage.SWEEP,
        reason=CaptureHandoffRetirementReason.STRUCTURAL_ROW_ABSENT,
        ticket_state=ticket.state,
        source=ticket.source,
        task_id=ticket.task_id,
        age_ms=61_000,
    )
    handoff.world.observation.tombstone_capture_ticket(ticket)
    monkeypatch.setattr(handoff.world.observation, "capture_ticket_schema_available", lambda: False)
    try:
        assert (
            await handoff.world.coordinator.reconcile_task_capture_handoffs(handoff.world.runtime)
            == 0
        )
        with handoff.world.local._lock:  # pyright: ignore[reportPrivateUsage]
            state = handoff.world.local._load(handoff.workspace)  # pyright: ignore[reportPrivateUsage]
            assert state.capture_handoff_retirement_pending == {ticket_id: ticket.task_id}
    finally:
        handoff.world.coordinator.close()


@pytest.mark.anyio
async def test_capped_ticket_listing_preserves_pending_retirement_account(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A capped task listing is not treated as proof that a pending ticket is absent."""

    handoff = await _handoff(tmp_path)
    ticket = handoff.strand("capped-listing", reserve=False)
    handoff.publish_inventory()
    pending_id = "sha256:" + "b" * 64
    handoff.world.local.record_capture_handoff_retirement(
        handoff.workspace,
        ticket_id=pending_id,
        stage=CaptureHandoffRetirementStage.SWEEP,
        reason=CaptureHandoffRetirementReason.STRUCTURAL_ROW_ABSENT,
        ticket_state="pending",
        source=ticket.source,
        task_id=ticket.task_id,
        age_ms=61_000,
    )
    assert (
        handoff.world.local.enqueue_outbox(
            handoff.workspace,
            handoff.world.host_session,
            handoff.envelope("capped-listing"),
        )
        is None
    )
    capped = tuple(ticket for _index in range(512))

    def capped_listing(_task_id: str) -> tuple[ObservationCaptureTicket, ...]:
        return capped

    monkeypatch.setattr(
        handoff.world.observation,
        "list_pending_capture_tickets",
        capped_listing,
    )
    try:
        assert (
            await handoff.world.coordinator.reconcile_task_capture_handoffs(handoff.world.runtime)
            == 0
        )
        with handoff.world.local._lock:  # pyright: ignore[reportPrivateUsage]
            state = handoff.world.local._load(handoff.workspace)  # pyright: ignore[reportPrivateUsage]
            assert state.capture_handoff_retirement_pending == {pending_id: ticket.task_id}
            assert state.capture_handoff_retired_count == 1
    finally:
        handoff.world.coordinator.close()


@pytest.mark.anyio
async def test_quarantined_structural_row_is_named_in_the_retirement(tmp_path: Path) -> None:
    handoff = await _handoff(tmp_path)
    ticket = handoff.strand("row-refused-terminally")
    handoff.publish_inventory()
    local = handoff.world.local
    assert (
        local.enqueue_outbox(
            handoff.workspace,
            handoff.world.host_session,
            handoff.envelope("row-refused-terminally"),
        )
        is None
    )
    (row,) = local.list_pending_outbox_rows(handoff.workspace)
    assert local.quarantine_outbox_row(
        handoff.workspace, row, ObservationGapCode.CONTENT_CAPTURE_PROFILE_MISMATCH.value
    )
    _assert_aged_handoff(handoff)
    try:
        outcome = await handoff.world.coordinator.recover_capture_inventory(handoff.workspace)
        assert outcome is ObservationCaptureRecoveryOutcome.HANDOFF_RETIRED
        retired = handoff.load(ticket)
        assert retired is not None and retired.state == "revoked"
        (entry,) = handoff.retirements()
        assert entry["reason"] == "structural_row_quarantined"
        assert entry["quarantine_reason"] == "content_capture_profile_mismatch"
        _assert_admitting(handoff)
    finally:
        handoff.world.coordinator.close()


@pytest.mark.anyio
async def test_a_genuinely_pending_handoff_is_preserved_without_age_refusal(tmp_path: Path) -> None:
    """Current authority plus a deliverable row: nothing is cleared or raised."""

    handoff = await _handoff(tmp_path)
    ticket = handoff.strand("row-still-queued")
    handoff.publish_inventory()
    assert (
        handoff.world.local.enqueue_outbox(
            handoff.workspace, handoff.world.host_session, handoff.envelope("row-still-queued")
        )
        is None
    )
    try:
        outcome = await handoff.world.coordinator.recover_capture_inventory(handoff.workspace)
        assert outcome is None
        kept = handoff.load(ticket)
        assert kept is not None and kept.state == "staging"
        assert handoff.retirements() == ()
        status = handoff.status()
        assert status["pressure_state"] == "healthy"
        assert status["admission_allowed"] is True
        backlog = handoff.world.local.capture_backlog(handoff.workspace)
        assert backlog["reservation_count"] == 1
        assert not handoff.world.routes.held
    finally:
        handoff.world.coordinator.close()


@pytest.mark.anyio
async def test_expired_authority_retires_a_queued_handoff(tmp_path: Path) -> None:
    """A stale authority generation can never be consumed, row or no row."""

    handoff = await _handoff(tmp_path)
    ticket = handoff.strand("row-under-old-authority", generation="sha256:" + "e" * 64)
    handoff.publish_inventory()
    assert (
        handoff.world.local.enqueue_outbox(
            handoff.workspace,
            handoff.world.host_session,
            handoff.envelope("row-under-old-authority"),
        )
        is None
    )
    try:
        outcome = await handoff.world.coordinator.recover_capture_inventory(handoff.workspace)
        assert outcome is ObservationCaptureRecoveryOutcome.HANDOFF_RETIRED
        retired = handoff.load(ticket)
        assert retired is not None and retired.state == "revoked"
        (entry,) = handoff.retirements()
        assert entry["reason"] == "authority_generation_changed"
        backlog = handoff.world.local.capture_backlog(handoff.workspace)
        assert backlog["reservation_count"] == 0
    finally:
        handoff.world.coordinator.close()


@pytest.mark.anyio
@pytest.mark.parametrize("finished", ("deleted", "tombstoned"))
async def test_reservation_outliving_its_ticket_is_released(tmp_path: Path, finished: str) -> None:
    """A completed or tombstoned ticket whose release was lost still clears."""

    handoff = await _handoff(tmp_path)
    ticket = handoff.strand("row-finished")
    handoff.publish_inventory()
    if finished == "tombstoned":
        handoff.world.observation.tombstone_capture_ticket(ticket)
    else:
        handoff.world.observation._db.execute(  # pyright: ignore[reportPrivateUsage]
            "DELETE FROM observation_capture_tickets WHERE ticket_id=?",
            (observation_capture_ticket_id(ticket),),
        )
    _assert_aged_handoff(handoff)
    try:
        outcome = await handoff.world.coordinator.recover_capture_inventory(handoff.workspace)
        # Nothing was retired: the durable ticket was already finished.
        assert outcome is None
        assert handoff.retirements() == ()
        _assert_admitting(handoff)
    finally:
        handoff.world.coordinator.close()


@pytest.mark.anyio
async def test_cold_restart_recovers_inventory_then_retires_in_one_turn(
    tmp_path: Path,
) -> None:
    handoff = await _handoff(tmp_path)
    ticket = handoff.strand("row-lost-across-restart")
    handoff.publish_inventory()
    world = handoff.world
    world.coordinator.close()
    # A new service generation: fresh local store and coordinator, and the
    # persisted inventory proof no longer counts until READY revalidates it.
    world.local = LocalObservationStore(_state=tmp_path / "state")
    world.local.set_capture_reservation_bootstrap_required(True)
    world.local.mark_capture_backlog_scope_unknown(world.workspace)
    world.coordinator = ObservationCoordinator(
        runtime=cast(BundleRuntimePort, world.routes),
        local=world.local,
        clock=_ServiceClock(),
        ids=world.coordinator.ids,
        state_root=tmp_path / "state",
    )
    world.wire()
    assert handoff.status()["admission_allowed"] is False
    sweeper = world.sweep()
    try:
        summary = await sweeper.sweep()
        assert summary.reasons == (
            ("capture_handoff_retired", 1),
            ("capture_inventory_recovered", 1),
        )
        retired = handoff.load(ticket)
        assert retired is not None and retired.state == "revoked"
        _assert_admitting(handoff)
        assert not world.routes.held
    finally:
        sweeper.close()
        world.coordinator.close()


@pytest.mark.anyio
async def test_unreadable_task_retries_on_the_next_sweep(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An exception while reconciling keeps the handoff; the next turn retires it."""

    handoff = await _handoff(tmp_path)
    ticket = handoff.strand("row-behind-a-busy-bundle", sibling=True)
    handoff.publish_inventory()
    original = handoff.world.sibling_observation.list_pending_capture_tickets

    def busy(task_id: str) -> tuple[ObservationCaptureTicket, ...]:
        raise OSError("synthetic-private-path-must-not-enter-diagnostics")

    monkeypatch.setattr(handoff.world.sibling_observation, "list_pending_capture_tickets", busy)
    sweeper = handoff.world.sweep()
    try:
        failed = await sweeper.sweep()
        assert failed.reasons == (("capture_handoff_unavailable", 1),)
        kept = handoff.load(ticket)
        assert kept is not None and kept.state == "staging"
        assert handoff.retirements() == ()
        assert not handoff.world.routes.held
        monkeypatch.setattr(
            handoff.world.sibling_observation, "list_pending_capture_tickets", original
        )
        recovered = await sweeper.sweep()
        assert recovered.reasons == (("capture_handoff_retired", 1),)
        _assert_admitting(handoff)
    finally:
        sweeper.close()
        handoff.world.coordinator.close()


@pytest.mark.anyio
async def test_busy_capture_lane_is_not_waited_for(tmp_path: Path) -> None:
    handoff = await _handoff(tmp_path)
    handoff.strand("row-while-capturing")
    handoff.publish_inventory()
    lock = handoff.world.coordinator._capture_lock  # pyright: ignore[reportPrivateUsage]
    await lock.acquire()
    try:
        async with asyncio.timeout(0.5):
            outcome = await handoff.world.coordinator.recover_capture_inventory(handoff.workspace)
        assert outcome is ObservationCaptureRecoveryOutcome.BUSY
        assert handoff.retirements() == ()
    finally:
        lock.release()
        handoff.world.coordinator.close()


@pytest.mark.anyio
async def test_check_preflight_retires_a_stranded_handoff_before_freeze(
    tmp_path: Path,
) -> None:
    """A new CHECK on the owning task is not blocked by an unconsumable ticket."""

    handoff = await _handoff(tmp_path)
    world = handoff.world
    # One real native command gives the task ledger its session and frontier.
    assert (
        await asyncio.to_thread(
            inventory._native_failed_command,  # pyright: ignore[reportPrivateUsage]
            world,
            "claude",
            "before-check",
            "check-primer",
        )
        == 0
    )
    ticket = handoff.strand("row-behind-check-barrier", reserve=False)
    runtime = world.runtime
    frontier = await runtime.ledger.load_frontier()
    with pytest.raises(PublicOperationError) as barrier:
        await runtime.ledger.freeze_case(
            runtime.session_id,
            cast(str, runtime.writer_id),
            frontier.sequence,
            native._ids(IdKind.REQUEST, 836),  # pyright: ignore[reportPrivateUsage]
            "sha256:" + "0" * 64,
        )
    assert barrier.value.code is PublicErrorCode.OPERATION_PENDING
    try:
        assert await world.coordinator.reconcile_task_capture_handoffs(runtime) == 1
        stored = handoff.load(ticket)
        assert stored is not None and stored.state == "revoked"
        (entry,) = handoff.retirements()
        assert entry["stage"] == "check_preflight"
        assert entry["reason"] == "structural_row_absent"
        frozen = await runtime.ledger.freeze_case(
            runtime.session_id,
            cast(str, runtime.writer_id),
            frontier.sequence,
            native._ids(IdKind.REQUEST, 837),  # pyright: ignore[reportPrivateUsage]
            "sha256:" + "0" * 64,
        )
        assert isinstance(frozen, FrozenCase)
    finally:
        world.coordinator.close()


@pytest.mark.anyio
async def test_check_preflight_does_not_wait_for_a_busy_capture_lane(tmp_path: Path) -> None:
    """While capture work holds the lock only the authority rules run."""

    handoff = await _handoff(tmp_path)
    ticket = handoff.strand("row-while-check-waits", reserve=False)
    lock = handoff.world.coordinator._capture_lock  # pyright: ignore[reportPrivateUsage]
    await lock.acquire()
    try:
        async with asyncio.timeout(0.5):
            retired = await handoff.world.coordinator.reconcile_task_capture_handoffs(
                handoff.world.runtime
            )
        assert retired == 0
        kept = handoff.load(ticket)
        assert kept is not None and kept.state == "staging"
    finally:
        lock.release()
        handoff.world.coordinator.close()


@pytest.mark.anyio
@pytest.mark.parametrize("host", ("claude", "codex", "cursor"))
async def test_native_input_is_captured_before_and_after_aged_handoff_recovery(
    tmp_path: Path, host: str
) -> None:
    """An empty queue is not success: real host input must be retained again."""

    handoff = await _handoff(tmp_path, host=host)
    world = handoff.world
    handoff.strand("row-that-stranded-admission")
    handoff.publish_inventory()
    sweeper = world.sweep()
    try:
        # A delayed handoff must not prevent unrelated authorized native capture.
        assert (
            await asyncio.to_thread(
                inventory._native_failed_command,  # pyright: ignore[reportPrivateUsage]
                world,
                host,
                "during-stall",
                "retained-during-delay",
            )
            == 0
        )
        assert any(request.capture_only for request in world.requests)
        stalled = world.local.selection_accounting(world.workspace)
        assert stalled["unrecoverable_input_count"] == 0

        assert (await sweeper.sweep()).reasons[:1] == (("capture_handoff_retired", 1),)
        await _drain_selection_losses(world)

        marker = f"{host}-admitted-after-836"
        assert (
            await asyncio.to_thread(
                inventory._native_failed_command,  # pyright: ignore[reportPrivateUsage]
                world,
                host,
                "after-recovery",
                marker,
            )
            == 0
        )
        assert any(request.capture_only for request in world.requests)
        async with asyncio.timeout(10):
            while world.local.pending_outbox_count(world.workspace) > 0:
                await sweeper.sweep()
        after = world.local.selection_accounting(world.workspace)
        assert after["unrecoverable_input_count"] == stalled["unrecoverable_input_count"]
        backlog = world.local.capture_backlog(world.workspace)
        assert (backlog["count"], backlog["reservation_count"]) == (0, 0)
        frontier = await world.runtime.ledger.load_frontier()
        frozen = await world.runtime.ledger.freeze_case(
            world.runtime.session_id,
            cast(str, world.runtime.writer_id),
            frontier.sequence,
            native._ids(IdKind.REQUEST, 838),  # pyright: ignore[reportPrivateUsage]
            "sha256:" + "0" * 64,
        )
        assert isinstance(frozen, FrozenCase)
        resolved = await resolve_captured_semantic_content(
            runtime=world.runtime,
            frozen=frozen,
            workspace_commitment=world.workspace,
            local_observation=world.local,
        )
        assert any(marker.encode() in item.content for item in resolved.content)
        assert any(b"retained-during-delay" in item.content for item in resolved.content)
        assert not world.routes.held
    finally:
        sweeper.close()
        world.coordinator.close()


async def _drain_selection_losses(
    world: inventory._World,  # pyright: ignore[reportPrivateUsage]
) -> None:
    """Let READY publish the stall's loss marker before new input is observed."""

    async with asyncio.timeout(10):
        while world.local.pending_selection_losses(world.workspace):
            await world.coordinator.recover_capture_inventory(world.workspace)


@pytest.mark.anyio
async def test_claude_drain_delivers_a_shared_workspace_codex_row_with_its_handoff(
    tmp_path: Path,
) -> None:
    """Concurrent Codex and Claude Code lanes share one workspace outbox.

    A Claude Code hook used to deliver a queued Codex row under its own content
    profile. The service refused that as a profile mismatch, which is terminal:
    the Codex row was quarantined and its staged handoff stranded, holding the
    shared workspace at the oldest-age hard limit.
    """

    handoff = await _handoff(tmp_path, host="claude")
    world = handoff.world
    worker_root = tmp_path / "codex"
    worker_root.mkdir(mode=0o700)
    worker = await native._pipeline(  # pyright: ignore[reportPrivateUsage]
        worker_root,
        codex_session_id="codex-shared",
        profile=None,
        identity=(
            world.sibling.task_id,
            world.sibling.session_id,
            cast(str, world.sibling.writer_id),
        ),
    )
    worker[7].close()  # One service coordinator owns both lanes.
    world.sibling = worker[6]
    world.sibling_observation = worker[4]
    world.routes.runtimes[world.sibling.session_id] = world.sibling
    codex_commitment = world.local.bind_codex_session(world.workspace, "codex-shared")
    native.store_mapping(
        native.LifecycleMapping(
            mapping_version=1,
            codex_session_id="codex-shared",
            yoetz_task_id=world.sibling.task_id,
            yoetz_session_id=world.sibling.session_id,
            yoetz_writer_id=cast(str, world.sibling.writer_id),
            last_frontier=None,
        ),
        _state=tmp_path / "state",
    )
    handoff.publish_inventory()

    marker = b"codex-row-drained-by-claude-836"
    envelope = map_hook_payload_to_envelope(
        "PostToolUse",
        {
            "hook_event_name": "PostToolUse",
            "session_id": "codex-shared",
            "tool_name": "Bash",
            "tool_use_id": "cross-host-codex-tool",
            "tool_response": marker.decode(),
        },
        session_commitment=codex_commitment,
        event_ordinal=1,
        key_material=world.local.key_material(),
        source=ObservationSource.CODEX_HOOK,
    )
    staged = await world.coordinator.ingest_request(
        ObservationIngestRequest(
            codex_session_id="codex-shared",
            envelope=envelope,
            content_chunks=(
                ObservationContentChunk(
                    content_kind=ObservationContentKind.TOOL_OUTPUT,
                    correlation_identity=f"{envelope.source_identity}:tool-output",
                    source_commitment=envelope.cursor.last_source_commitment,
                    media_type="text/plain",
                    part_index=0,
                    part_count=1,
                    content=marker,
                ),
            ),
            capture_only=True,
        )
    )
    assert staged.reason == OBSERVATION_CONTENT_CAPTURE_PENDING_REASON
    # The Codex hook's drain budget ran out after staging: its row stays queued.
    assert world.local.enqueue_outbox(world.workspace, "codex-shared", envelope) is None
    identity = observation_content_identity(envelope)
    pending = world.sibling_observation.load_capture_ticket(
        workspace=world.workspace, logical_identity=identity
    )
    assert pending is not None and pending.state == "pending"

    sweeper = world.sweep()
    try:
        assert (
            await asyncio.to_thread(
                inventory._native_failed_command,  # pyright: ignore[reportPrivateUsage]
                world,
                "claude",
                "cross-host-claude-tool",
                "cross-host-claude-marker",
            )
            == 0
        )
        async with asyncio.timeout(10):
            while world.local.pending_outbox_count(world.workspace) > 0:
                await sweeper.sweep()
        assert world.local.list_quarantine(world.workspace) == ()
        assert (
            world.sibling_observation.load_capture_ticket(
                workspace=world.workspace, logical_identity=identity
            )
            is None
        )
        assert handoff.retirements() == ()
        backlog = world.local.capture_backlog(world.workspace)
        assert (backlog["count"], backlog["reservation_count"]) == (0, 0)
        frontier = await world.sibling.ledger.load_frontier()
        frozen = await world.sibling.ledger.freeze_case(
            world.sibling.session_id,
            cast(str, world.sibling.writer_id),
            frontier.sequence,
            native._ids(IdKind.REQUEST, 839),  # pyright: ignore[reportPrivateUsage]
            "sha256:" + "0" * 64,
        )
        assert isinstance(frozen, FrozenCase)
        resolved = await resolve_captured_semantic_content(
            runtime=world.sibling,
            frozen=frozen,
            workspace_commitment=world.workspace,
            local_observation=world.local,
        )
        assert any(marker in item.content for item in resolved.content)
    finally:
        sweeper.close()
        world.coordinator.close()
