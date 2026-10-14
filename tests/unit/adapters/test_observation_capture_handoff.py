"""Aged native capture handoffs are maintenance demand, not admission policy (#836)."""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest

from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.domain.observation import (
    CAPTURE_HANDOFF_RECONCILE_AGE_MS,
    CaptureHandoffRetirementReason,
    CaptureHandoffRetirementStage,
    ObservationCaptureBacklog,
    ObservationCursor,
    ObservationEnvelope,
    ObservationGapCode,
    ObservationSource,
)
from finishup.domain.observation_budget import LARGEST_CAPACITY
from finishup.domain.observation_settings import ObservationDetailProfile, ObservationSelection
from finishup.domain.values import JsonObject, Timestamp, timestamp_from_datetime
from finishup.protocol.errors import ProtocolValueError, PublicErrorCode, PublicOperationError

# The oldest capture receipt in the issue's native run.
_START = datetime(2026, 9, 25, 7, 47, 6, 537_000, tzinfo=UTC)
_SESSION = "hmac-sha256:" + "1" * 64
_TASK = "tsk_10000000-0000-4000-8000-000000000836"
_OTHER_TASK = "tsk_20000000-0000-4000-8000-000000000836"
_TICKET = "sha256:" + "a" * 64


class _Wall:
    """Deterministic wall clock; monotonic time advances with it (one boot epoch)."""

    def __init__(self) -> None:
        self.seconds = _START.timestamp()

    def __call__(self) -> float:
        return self.seconds

    def monotonic(self) -> float:
        return self.seconds - _START.timestamp()

    def now(self) -> Timestamp:
        return timestamp_from_datetime(datetime.fromtimestamp(self.seconds, UTC))


def _store(tmp_path: Path, wall: _Wall) -> tuple[LocalObservationStore, str]:
    project = tmp_path / "project"
    project.mkdir(exist_ok=True)
    store = LocalObservationStore(_state=tmp_path / "state", _wall=wall, _monotonic=wall.monotonic)
    workspace = store.workspace_commitment(str(project.resolve()))
    store.grant_consent(workspace)
    return store, workspace


def _envelope(identity: str, *, receipt_time: Timestamp) -> ObservationEnvelope:
    return ObservationEnvelope(
        session_commitment=_SESSION,
        event_kind="PostToolUse",
        source_identity=identity,
        source=ObservationSource.CLAUDE_HOOK,
        cursor=ObservationCursor(1, 0, 1, "hmac-sha256:" + "c" * 64, "claude-obs-hook/1.0.0"),
        receipt_time=receipt_time,
        structural_payload=JsonObject({"tool_name": "Bash", "exit_status": 1}),
        content_object_refs=(),
        gap_codes=(),
    )


def _reserve_known(
    store: LocalObservationStore,
    workspace: str,
    wall: _Wall,
    inventory: Mapping[str, ObservationCaptureBacklog],
) -> None:
    """Reserve one 144-byte ticket, then publish a complete inventory naming it.

    The reconciled reservation is known (``reservation_unknown`` is false) and
    stays additive to the task aggregate, exactly as in the native run.
    """

    store.reserve_capture_ticket(workspace, _TICKET, _TASK, 144)
    assert store.bootstrap_capture_reservations(
        workspace,
        {**inventory, _TASK: ObservationCaptureBacklog(1, 144, wall.now())},
        ticket_ids_by_task={_TASK: (_TICKET,)},
    )


def test_one_aged_handoff_requests_maintenance_without_refusing_new_content(tmp_path: Path) -> None:
    """Age remains maintenance demand, not a capacity refusal."""

    wall = _Wall()
    store, workspace = _store(tmp_path, wall)
    store.set_workspace_selection(
        workspace,
        ObservationSelection(detail=ObservationDetailProfile.DETAILED, capacity=LARGEST_CAPACITY),
        set_at=wall.now(),
    )
    store.set_capture_reservation_bootstrap_required(True)
    assert store.bootstrap_capture_reservations(
        workspace, {_TASK: ObservationCaptureBacklog(0, 0, None)}
    )
    _reserve_known(store, workspace, wall, {})
    backlog = store.capture_backlog(workspace)
    # The issue's snapshot: capture 1 / 288 bytes, reservations 1 / 144 bytes.
    assert (backlog["count"], backlog["byte_count"]) == (1, 288)
    assert (backlog["reservation_count"], backlog["reserved_byte_count"]) == (1, 144)
    assert backlog["reservation_unknown"] is False
    assert backlog["capture_backlog_scope"] == "partial"

    fresh = store.selection_runtime_status(workspace, _SESSION)
    assert fresh["queue_count"] == 0
    assert fresh["pending_attempts"] == 0
    assert fresh["admission_allowed"] is True
    assert fresh["content_allowed"] is True

    wall.seconds += 61
    stalled = store.selection_runtime_status(workspace, _SESSION)
    budget = cast(Mapping[str, object], stalled["effective_budget"])
    assert stalled["queue_count"] == 0
    assert stalled["oldest_pending_age_ms"] == 61_000
    assert stalled["pressure_state"] == "healthy"
    assert stalled["effective_mode"] == "detailed"
    assert budget["limiting_dimension"] == "capture_backlog"
    assert stalled["admission_allowed"] is True
    assert stalled["content_allowed"] is True
    # The same aged reservation is durable maintenance demand, independent of
    # the admission booleans above and of an empty outbox.
    assert store.capture_handoff_candidates(workspace) == (_TASK,)
    assert workspace in store.pending_workspaces()


def test_only_aged_handoffs_become_candidates_oldest_first(tmp_path: Path) -> None:
    wall = _Wall()
    store, workspace = _store(tmp_path, wall)
    store.set_capture_reservation_bootstrap_required(True)
    inventory = {
        _TASK: ObservationCaptureBacklog(0, 0, None),
        _OTHER_TASK: ObservationCaptureBacklog(0, 0, None),
    }
    assert store.bootstrap_capture_reservations(workspace, inventory)
    _reserve_known(store, workspace, wall, inventory)
    assert store.capture_handoff_candidates(workspace) == ()
    assert workspace not in store.pending_workspaces()

    wall.seconds += 20
    # A task snapshot counts as well, so a legacy ticket without a central
    # reservation is still found.
    store.update_capture_backlog(workspace, 1, 9, wall.now(), wall.now(), route_id=_OTHER_TASK)
    wall.seconds += (CAPTURE_HANDOFF_RECONCILE_AGE_MS // 1_000) - 20
    assert store.capture_handoff_candidates(workspace) == (_TASK,)
    wall.seconds += 20
    assert store.capture_handoff_candidates(workspace) == (_TASK, _OTHER_TASK)
    assert store.capture_handoff_candidates(workspace, older_than_ms=10**9) == ()
    with pytest.raises(ProtocolValueError):
        store.capture_handoff_candidates(workspace, older_than_ms=-1)

    # A route report without an identity cannot be opened, so unknown scope is
    # left to inventory recovery rather than named as a handoff candidate.
    store.update_capture_backlog(workspace, 1, 1, _as_old(wall), wall.now())
    assert "_unknown" not in store.capture_handoff_candidates(workspace)


def _as_old(wall: _Wall) -> Timestamp:
    return timestamp_from_datetime(datetime.fromtimestamp(wall.seconds - 3_600, UTC))


def test_structural_state_names_pending_and_quarantined_rows(tmp_path: Path) -> None:
    wall = _Wall()
    store, workspace = _store(tmp_path, wall)
    session = "claude:structural-state"
    store.bind_codex_session(workspace, session)
    assert (
        store.enqueue_outbox(workspace, session, _envelope("pending-row", receipt_time=wall.now()))
        is None
    )
    assert (
        store.enqueue_outbox(workspace, session, _envelope("refused-row", receipt_time=wall.now()))
        is None
    )
    refused = next(
        row
        for row in store.list_pending_outbox_rows(workspace)
        if row.envelope.source_identity == "refused-row"
    )
    assert store.quarantine_outbox_row(
        workspace, refused, ObservationGapCode.CONTENT_CAPTURE_PROFILE_MISMATCH.value
    )

    state = store.capture_handoff_structural_state(workspace)
    source = ObservationSource.CLAUDE_HOOK.value
    assert state.pending == frozenset({(source, _SESSION, "pending-row")})
    assert dict(state.quarantined) == {
        (source, _SESSION, "refused-row"): ObservationGapCode.CONTENT_CAPTURE_PROFILE_MISMATCH.value
    }


def test_retirement_account_is_bounded_payload_free_and_durable(tmp_path: Path) -> None:
    wall = _Wall()
    store, workspace = _store(tmp_path, wall)
    assert store.capture_handoff_retirements(workspace) == {"retired_count": 0, "recent": ()}

    for index in range(20):
        ticket_id = "sha256:" + format(index, "064x")
        store.record_capture_handoff_retirement(
            workspace,
            ticket_id=ticket_id,
            stage=CaptureHandoffRetirementStage.SWEEP,
            reason=CaptureHandoffRetirementReason.STRUCTURAL_ROW_QUARANTINED,
            ticket_state="pending",
            source=ObservationSource.CODEX_HOOK,
            task_id=_TASK,
            age_ms=1_000 + index,
            quarantine_reason="content_capture_profile_mismatch",
        )

    account = store.capture_handoff_retirements(workspace)
    recent = cast(tuple[Mapping[str, object], ...], account["recent"])
    assert account["retired_count"] == 20
    assert len(recent) == 16
    assert recent[-1] == {
        "stage": "sweep",
        "reason": "structural_row_quarantined",
        "ticket_id": "sha256:" + format(19, "064x"),
        "ticket_state": "pending",
        "source": "codex_hook",
        "task_id": _TASK,
        "age_ms": 1_019,
        "quarantine_reason": "content_capture_profile_mismatch",
        "retired_at": wall.now().wire,
    }
    reopened = LocalObservationStore(
        _state=tmp_path / "state", _wall=wall, _monotonic=wall.monotonic
    )
    assert reopened.capture_handoff_retirements(workspace) == account

    for invalid in (
        {"ticket_state": "revoked"},
        {"age_ms": -1},
        {"task_id": "not a task"},
        {"quarantine_reason": "Not Closed"},
    ):
        arguments: dict[str, object] = {
            "ticket_id": _TICKET,
            "stage": CaptureHandoffRetirementStage.SWEEP,
            "reason": CaptureHandoffRetirementReason.STRUCTURAL_ROW_ABSENT,
            "ticket_state": "pending",
            "source": ObservationSource.CLAUDE_HOOK,
            "task_id": _TASK,
            "age_ms": 0,
        }
        arguments.update(invalid)
        with pytest.raises(ProtocolValueError):
            store.record_capture_handoff_retirement(workspace, **arguments)  # type: ignore[arg-type]


def test_malformed_persisted_retirements_are_dropped(tmp_path: Path) -> None:
    wall = _Wall()
    store, workspace = _store(tmp_path, wall)
    store.record_capture_handoff_retirement(
        workspace,
        ticket_id=_TICKET,
        stage=CaptureHandoffRetirementStage.CHECK_PREFLIGHT,
        reason=CaptureHandoffRetirementReason.STRUCTURAL_ROW_ABSENT,
        ticket_state="staging",
        source=ObservationSource.CURSOR_HOOK,
        task_id=_TASK,
        age_ms=30_000,
    )
    path = store._workspace_path(workspace)  # pyright: ignore[reportPrivateUsage]
    document = json.loads(path.read_text())
    document["capture_handoff_retirements"].append(
        {"stage": "invented", "reason": "structural_row_absent", "ticket_state": "pending"}
    )
    document["capture_handoff_retirements"].append("not an object")
    path.write_text(json.dumps(document))

    reopened = LocalObservationStore(
        _state=tmp_path / "state", _wall=wall, _monotonic=wall.monotonic
    )
    account = reopened.capture_handoff_retirements(workspace)
    assert account["retired_count"] == 1
    recent = cast(tuple[Mapping[str, object], ...], account["recent"])
    assert [entry["stage"] for entry in recent] == ["check_preflight"]


def test_recording_a_retirement_records_the_honest_content_gap(tmp_path: Path) -> None:
    wall = _Wall()
    store, workspace = _store(tmp_path, wall)
    store.record_capture_handoff_retirement(
        workspace,
        ticket_id=_TICKET,
        stage=CaptureHandoffRetirementStage.STRUCTURAL_COMMITTED,
        reason=CaptureHandoffRetirementReason.CONTENT_NOT_ADMITTED,
        ticket_state="pending",
        source=ObservationSource.CLAUDE_HOOK,
        task_id=_OTHER_TASK,
        age_ms=5,
    )
    with store._lock:  # pyright: ignore[reportPrivateUsage]
        state = store._load(workspace)  # pyright: ignore[reportPrivateUsage]
        assert state.gaps is not None
        assert ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value in state.gaps


def test_retirement_account_replay_is_idempotent_by_ticket(tmp_path: Path) -> None:
    wall = _Wall()
    store, workspace = _store(tmp_path, wall)

    def record(ticket_id: str, reason: CaptureHandoffRetirementReason) -> None:
        store.record_capture_handoff_retirement(
            workspace,
            ticket_id=ticket_id,
            stage=CaptureHandoffRetirementStage.SWEEP,
            reason=reason,
            ticket_state="pending",
            source=ObservationSource.CLAUDE_HOOK,
            task_id=_TASK,
            age_ms=30_000,
        )

    record(_TICKET, CaptureHandoffRetirementReason.STRUCTURAL_ROW_ABSENT)
    # A retry after the ticket mutation failed must not add a second loss or
    # increment the retirement count again.
    record(_TICKET, CaptureHandoffRetirementReason.TERMINAL_REFUSAL)
    account = store.capture_handoff_retirements(workspace)
    assert account["retired_count"] == 1
    assert len(cast(tuple[Mapping[str, object], ...], account["recent"])) == 1


def test_active_reservation_pins_retirement_replay_identity(tmp_path: Path) -> None:
    wall = _Wall()
    store, workspace = _store(tmp_path, wall)
    store.set_capture_reservation_bootstrap_required(True)
    assert store.bootstrap_capture_reservations(
        workspace, {_TASK: ObservationCaptureBacklog(0, 0, None)}
    )
    store.reserve_capture_ticket(workspace, _TICKET, _TASK, 144)

    def record(ticket_id: str) -> None:
        store.record_capture_handoff_retirement(
            workspace,
            ticket_id=ticket_id,
            stage=CaptureHandoffRetirementStage.SWEEP,
            reason=CaptureHandoffRetirementReason.STRUCTURAL_ROW_ABSENT,
            ticket_state="pending",
            source=ObservationSource.CLAUDE_HOOK,
            task_id=_TASK,
            age_ms=30_000,
        )

    record(_TICKET)
    for index in range(512):
        ticket_id = "sha256:" + format(index + 1, "064x")
        record(ticket_id)
        store.confirm_capture_handoff_retirement(workspace, ticket_id, _TASK)

    # The active reservation pins its accounted identity even after the
    # bounded history has received more than 512 other retirements.
    record(_TICKET)
    with store._lock:  # pyright: ignore[reportPrivateUsage]
        state = store._load(workspace)  # pyright: ignore[reportPrivateUsage]
        assert _TICKET in state.capture_handoff_retirement_ids
        assert len(state.capture_handoff_retirement_ids) <= 512
        assert state.capture_handoff_retired_count == 513


def test_full_active_reservation_set_drops_unpinned_ids_on_reload(tmp_path: Path) -> None:
    """A zero unpinned budget must not retain stale identities after reload."""

    wall = _Wall()
    store, workspace = _store(tmp_path, wall)

    def record(ticket_id: str) -> None:
        store.record_capture_handoff_retirement(
            workspace,
            ticket_id=ticket_id,
            stage=CaptureHandoffRetirementStage.SWEEP,
            reason=CaptureHandoffRetirementReason.STRUCTURAL_ROW_ABSENT,
            ticket_state="pending",
            source=ObservationSource.CLAUDE_HOOK,
            task_id=_TASK,
            age_ms=30_000,
        )

    historical_ids = tuple("sha256:" + format(1_000 + index, "064x") for index in range(8))
    for ticket_id in historical_ids:
        record(ticket_id)
        store.confirm_capture_handoff_retirement(workspace, ticket_id, _TASK)

    active_ids = tuple("sha256:" + format(index, "064x") for index in range(512))
    for index, ticket_id in enumerate(active_ids, start=1):
        store.reserve_capture_ticket(workspace, ticket_id, _TASK, 1)
        assert store.bootstrap_capture_reservations(
            workspace,
            {_TASK: ObservationCaptureBacklog(index, index, wall.now())},
            ticket_ids_by_task={_TASK: active_ids[:index]},
        )
    store.set_capture_reservation_bootstrap_required(True)
    for ticket_id in active_ids:
        record(ticket_id)

    overflow_id = "sha256:" + "f" * 64
    with pytest.raises(PublicOperationError) as overflow:
        record(overflow_id)
    assert overflow.value.code is PublicErrorCode.LIMIT_EXCEEDED

    with store._lock:  # pyright: ignore[reportPrivateUsage]
        state = store._load(workspace)  # pyright: ignore[reportPrivateUsage]
        assert set(state.capture_handoff_retirement_ids) == set(active_ids)
        assert len(state.capture_handoff_retirement_ids) == 512
        assert state.capture_handoff_retirement_pending is not None
        assert set(state.capture_handoff_retirement_pending) == set(active_ids)
        # Eight confirmed historical entries remain in the aggregate count;
        # the refused overflow must not add a ninth pending identity.
        assert state.capture_handoff_retired_count == 520

    reopened = LocalObservationStore(
        _state=tmp_path / "state", _wall=wall, _monotonic=wall.monotonic
    )
    with reopened._lock:  # pyright: ignore[reportPrivateUsage]
        state = reopened._load(workspace)  # pyright: ignore[reportPrivateUsage]
        assert set(state.capture_handoff_retirement_ids) == set(active_ids)
        assert len(state.capture_handoff_retirement_ids) == 512
        assert state.capture_handoff_retirement_pending is not None
        assert set(state.capture_handoff_retirement_pending) == set(active_ids)
