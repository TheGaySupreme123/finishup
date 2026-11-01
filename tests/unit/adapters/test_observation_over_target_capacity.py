"""#843: lowering capacity above the fallback byte ceiling keeps a finite drain.

Rows accepted under a larger selection stay durable after the selection is
lowered, admission stops, and the store must still record the refused input,
delivery attempts, and lifecycle transitions without widening the bound for
anything else.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

import finishup.adapters.integrations.observation_local as local_mod
from finishup.adapters.integrations.observation_local import (
    LocalObservationStore,
    ObservationOutboxRow,
)
from finishup.domain.observation import (
    ObservationCursor,
    ObservationEnvelope,
    ObservationGapCode,
    ObservationSource,
)
from finishup.domain.observation_budget import (
    LARGER_CAPACITY,
    LARGEST_CAPACITY,
    STANDARD_CAPACITY,
    BudgetLimits,
    ObservationCapacity,
)
from finishup.domain.observation_settings import ObservationDetailProfile, ObservationSelection
from finishup.domain.values import JsonObject, Timestamp
from finishup.protocol.canonical import canonical_encode

_NOW = Timestamp("2026-09-10T00:01:00.000Z")
_WALL_SECONDS = datetime(2026, 9, 10, 0, 1, tzinfo=UTC).timestamp()
_BACKLOG_SESSION = "hmac-sha256:" + "1" * 64
_BACKLOG_CODEX_ID = "codex-backlog"
_SIBLING_SESSIONS = tuple("hmac-sha256:" + digit * 64 for digit in "234")
_FALLBACK_BYTES = 1_048_576
_RESERVE = 128 * 1024
_STANDARD_QUEUE_BYTES = BudgetLimits.for_capacity(STANDARD_CAPACITY).queue_bytes


class _Clock:
    def __init__(self) -> None:
        self.monotonic = 0.0

    def mono(self) -> float:
        return self.monotonic

    def wall(self) -> float:
        # Wall minus monotonic stays constant, so the store sees one boot.
        return _WALL_SECONDS + self.monotonic


def _store(tmp_path: Path, clock: _Clock | None = None) -> tuple[LocalObservationStore, str]:
    clock = clock or _Clock()
    workspace_path = tmp_path / "workspace"
    workspace_path.mkdir()
    store = LocalObservationStore(
        _state=tmp_path / "state", _monotonic=clock.mono, _wall=clock.wall
    )
    workspace = store.workspace_commitment(str(workspace_path))
    store.grant_consent(workspace)
    return store, workspace


def _envelope(index: int, *, session: str = _BACKLOG_SESSION) -> ObservationEnvelope:
    return ObservationEnvelope(
        session_commitment=session,
        event_kind="PostToolUse",
        source_identity=f"backlog:{index}",
        source=ObservationSource.CODEX_HOOK,
        cursor=ObservationCursor(
            source_generation=1,
            byte_position=0,
            event_position=index + 1,
            last_source_commitment="hmac-sha256:" + "a" * 64,
            mapping_version="codex-obs-hook/1.0.0",
        ),
        receipt_time=_NOW,
        structural_payload=JsonObject({"tool_name": "shell", "exit_status": 1}),
        content_object_refs=(),
        gap_codes=(),
    )


def _selection(capacity: ObservationCapacity) -> ObservationSelection:
    return ObservationSelection(detail=ObservationDetailProfile.FOCUSED, capacity=capacity)


def _accept_backlog(
    store: LocalObservationStore,
    workspace: str,
    count: int,
    *,
    codex_session_id: str = _BACKLOG_CODEX_ID,
    session: str = _BACKLOG_SESSION,
) -> None:
    """Persist ``count`` rows as if admitted under the current larger selection.

    Admitting thousands of rows one hook at a time re-encodes the whole state
    for each; this writes the same accepted rows through one bounded save.
    """

    with store._lock:  # pyright: ignore[reportPrivateUsage]
        state = store._load(workspace)  # pyright: ignore[reportPrivateUsage]
        assert state.pending_outbox is not None
        state.pending_outbox.extend(
            ObservationOutboxRow(
                codex_session_id=codex_session_id,
                envelope=_envelope(index, session=session),
            )
            for index in range(count)
        )
        store._save(workspace, state)  # pyright: ignore[reportPrivateUsage]


def _file_size(store: LocalObservationStore, workspace: str) -> int:
    return store._workspace_path(workspace).stat().st_size  # pyright: ignore[reportPrivateUsage]


def _limit(store: LocalObservationStore, workspace: str, *, required: int | None = None) -> int:
    with store._lock:  # pyright: ignore[reportPrivateUsage]
        state = store._load(workspace)  # pyright: ignore[reportPrivateUsage]
        return store._state_byte_limit(  # pyright: ignore[reportPrivateUsage]
            workspace, state, required=required
        )


def _persisted_row_bytes(store: LocalObservationStore, workspace: str) -> int:
    return sum(
        len(canonical_encode(local_mod._outbox_row_to_json(row)))  # pyright: ignore[reportPrivateUsage]
        for row in store.list_pending_outbox_rows(workspace)
    )


def _lowered_above_fallback(tmp_path: Path, rows: int = 3_000) -> tuple[LocalObservationStore, str]:
    """Accept a backlog under Largest, then revoke to the 512-row fallback."""

    store, workspace = _store(tmp_path)
    store.set_workspace_selection(workspace, _selection(LARGEST_CAPACITY), set_at=_NOW)
    _accept_backlog(store, workspace, rows)
    assert _file_size(store, workspace) > _FALLBACK_BYTES
    store.clear_workspace_selection(workspace)
    return store, workspace


def test_lowering_above_the_fallback_still_accounts_refused_input(tmp_path: Path) -> None:
    store, workspace = _lowered_above_fallback(tmp_path)
    accepted_before = store.list_pending_outbox_rows(workspace)

    results = [
        store.enqueue_outbox(
            workspace, f"codex-sibling-{index}", _envelope(9_000 + index, session=s)
        )
        for index, s in enumerate(_SIBLING_SESSIONS)
    ]

    assert results == [ObservationGapCode.OUTBOX_OVERFLOW.value] * 3
    # Accepted rows are durable records, never room for the refusal.
    assert store.list_pending_outbox_rows(workspace) == accepted_before
    reopened = LocalObservationStore(_state=tmp_path / "state")
    state = reopened._load(workspace)  # pyright: ignore[reportPrivateUsage]
    assert state.gaps is not None and state.session_gaps is not None
    assert state.gaps["_local_outbox_overflow"].active
    for session in _SIBLING_SESSIONS:
        assert state.session_gaps[session] == {ObservationGapCode.OUTBOX_OVERFLOW.value}


def test_refused_selected_admission_records_bounded_loss(tmp_path: Path) -> None:
    store, workspace = _lowered_above_fallback(tmp_path)

    notices = [
        store.record_admission_loss(workspace, _envelope(9_100 + index, session=session))
        for index, session in enumerate(_SIBLING_SESSIONS)
    ]

    # One notice is requested for the burst; every lost input is accounted.
    assert notices == [True, False, False]

    reopened = LocalObservationStore(_state=tmp_path / "state")
    assert reopened.selection_accounting(workspace)["unrecoverable_input_count"] == 3
    state = reopened._load(workspace)  # pyright: ignore[reportPrivateUsage]
    assert {item["session"] for item in state.selection_loss_ranges} == set(_SIBLING_SESSIONS)
    assert len(reopened.list_pending_outbox_rows(workspace)) == 3_000


def test_drain_attempts_are_recorded_at_the_byte_boundary(tmp_path: Path) -> None:
    store, workspace = _lowered_above_fallback(tmp_path)
    first = store.list_pending_outbox_rows(workspace)[0]

    attempted = store.bump_outbox_row_attempt(workspace, first, reason="service_unavailable")

    assert attempted is not None and attempted.attempts == 1
    # A whole-session reason stamp grows every row it touches; the rows carry
    # their own bytes, so it lands too.
    assert (
        store.note_outbox_session_reason(workspace, _BACKLOG_CODEX_ID, "service_unavailable")
        == 2_999
    )
    rows = store.list_pending_outbox_rows(workspace)
    assert all(row.last_reason == "service_unavailable" for row in rows)


@pytest.mark.parametrize("lowering", ["revoke", "expiry", "session_end"])
def test_session_end_persists_after_a_session_override_is_lowered(
    tmp_path: Path, lowering: str
) -> None:
    clock = _Clock()
    store, workspace = _store(tmp_path, clock)
    session = store.bind_codex_session(workspace, _BACKLOG_CODEX_ID)
    expiry = Timestamp("2026-09-10T00:02:00.000Z") if lowering == "expiry" else None
    store.set_session_selection(
        workspace, session, _selection(LARGEST_CAPACITY), expires_at=expiry, set_at=_NOW
    )
    _accept_backlog(store, workspace, 3_000, session=session)
    assert _file_size(store, workspace) > _FALLBACK_BYTES
    if lowering == "revoke":
        store.clear_session_selection(workspace, session)
    elif lowering == "expiry":
        # The override lapses without any write; the end is the first save.
        clock.monotonic += 120.0

    store.note_session_end(workspace, session)

    reopened = LocalObservationStore(_state=tmp_path / "state", _wall=clock.wall)
    state = reopened._load(workspace)  # pyright: ignore[reportPrivateUsage]
    assert state.ended_sessions is not None and session in state.ended_sessions
    settings = reopened.selection_settings_for(workspace)
    assert settings.session(session) is None
    assert len(reopened.list_pending_outbox_rows(workspace)) == 3_000


def test_the_over_target_bound_is_exact_and_ends_with_the_transition(tmp_path: Path) -> None:
    store, workspace = _lowered_above_fallback(tmp_path)
    persisted = _persisted_row_bytes(store, workspace)
    size = _file_size(store, workspace)

    # A write that already fits keeps the ordinary occupancy bound.
    assert _limit(store, workspace) == size
    assert _limit(store, workspace, required=size) == size
    expected = _FALLBACK_BYTES + (persisted - _STANDARD_QUEUE_BYTES) + _RESERVE
    assert _limit(store, workspace, required=size + 1) == expected
    assert size < expected <= 16 * 1_048_576


def test_accounting_writes_cannot_raise_the_over_target_bound(tmp_path: Path) -> None:
    store, workspace = _lowered_above_fallback(tmp_path)
    bound = _limit(store, workspace, required=1 << 40)

    # 300 distinct refused lanes exceed every bounded accounting structure
    # (256 session gap maps, 64 loss ranges), all landing in one write.
    with store.batched(workspace):
        for index in range(300):
            session = f"hmac-sha256:{index:064x}"
            assert (
                store.enqueue_outbox(
                    workspace, f"codex-lane-{index}", _envelope(20_000 + index, session=session)
                )
                == ObservationGapCode.OUTBOX_OVERFLOW.value
            )
            store.record_admission_loss(workspace, _envelope(30_000 + index, session=session))
    assert _file_size(store, workspace) <= bound
    assert store.selection_accounting(workspace)["unrecoverable_input_count"] == 300

    # Only the accepted rows move the bound; the accounting did not, and a
    # later refusal still lands under it.
    assert _limit(store, workspace, required=1 << 40) == bound
    assert (
        store.enqueue_outbox(
            workspace, "codex-late", _envelope(31_000, session=_SIBLING_SESSIONS[0])
        )
        == ObservationGapCode.OUTBOX_OVERFLOW.value
    )
    assert _file_size(store, workspace) <= bound
    assert len(store.list_pending_outbox_rows(workspace)) == 3_000


def test_drain_shrinks_the_bound_and_reopens_selected_admission(tmp_path: Path) -> None:
    store, workspace = _lowered_above_fallback(tmp_path)
    sibling = _SIBLING_SESSIONS[0]
    assert (
        store.enqueue_outbox(workspace, "codex-sibling", _envelope(40_000, session=sibling))
        == ObservationGapCode.OUTBOX_OVERFLOW.value
    )
    bound_before = _limit(store, workspace, required=1 << 40)

    # Real acknowledgements at the byte boundary.
    for row in store.list_pending_outbox_rows(workspace)[:3]:
        assert store.acknowledge_outbox_row(workspace, row)
    bound_after = _limit(store, workspace, required=1 << 40)
    assert bound_after < bound_before

    # Most of the backlog drains; finish across the queue target with real
    # acknowledgements so the last transitions use the public drain path.
    with store._lock:  # pyright: ignore[reportPrivateUsage]
        state = store._load(workspace)  # pyright: ignore[reportPrivateUsage]
        assert state.pending_outbox is not None
        del state.pending_outbox[: len(state.pending_outbox) - 514]
        store._save(workspace, state)  # pyright: ignore[reportPrivateUsage]
    for row in store.list_pending_outbox_rows(workspace)[:3]:
        assert store.acknowledge_outbox_row(workspace, row)
    assert len(store.list_pending_outbox_rows(workspace)) == 511

    # Back inside the selected target: no allowance, the fallback bound, and
    # ordinary admission resumes for the lane that was refused.
    assert _file_size(store, workspace) <= _FALLBACK_BYTES
    assert _limit(store, workspace, required=1 << 40) == _FALLBACK_BYTES
    assert (
        store.enqueue_outbox(workspace, "codex-sibling", _envelope(40_001, session=sibling)) is None
    )
    assert len(store.list_pending_outbox_rows(workspace)) == 512
    assert (
        store.enqueue_outbox(workspace, "codex-sibling", _envelope(40_002, session=sibling))
        == ObservationGapCode.OUTBOX_OVERFLOW.value
    )


def test_an_ordinary_full_queue_keeps_the_standard_bound(tmp_path: Path) -> None:
    # No selection was lowered: a full standard queue never earns the
    # over-target allowance, so the standard retention ladder is unchanged.
    store, workspace = _store(tmp_path)
    _accept_backlog(store, workspace, 512)
    assert _limit(store, workspace, required=1 << 40) == _FALLBACK_BYTES


def test_the_standard_pressure_seam_still_governs_a_queue_within_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(local_mod, "_MAX_STATE_BYTES", 40_000)
    store, workspace = _store(tmp_path)
    _accept_backlog(store, workspace, 20)
    assert _limit(store, workspace, required=1 << 40) == 40_000


def test_six_hundred_rows_over_the_512_fallback_report_overflow(tmp_path: Path) -> None:
    # The #843 control: over-target backpressure itself is expected, and a
    # small file never needed the allowance.
    store, workspace = _store(tmp_path)
    store.set_workspace_selection(workspace, _selection(LARGER_CAPACITY), set_at=_NOW)
    _accept_backlog(store, workspace, 600)
    store.clear_workspace_selection(workspace)
    assert _file_size(store, workspace) < _FALLBACK_BYTES

    sibling = _SIBLING_SESSIONS[0]
    result = store.enqueue_outbox(workspace, "codex-sibling", _envelope(50_000, session=sibling))

    assert result == ObservationGapCode.OUTBOX_OVERFLOW.value
    assert len(store.list_pending_outbox_rows(workspace)) == 600
    state = LocalObservationStore(_state=tmp_path / "state")._load(workspace)  # pyright: ignore[reportPrivateUsage]
    assert state.gaps is not None and state.gaps["_local_outbox_overflow"].active
    assert state.session_gaps == {sibling: {ObservationGapCode.OUTBOX_OVERFLOW.value}}
    assert _limit(store, workspace, required=1 << 40) == _FALLBACK_BYTES + _RESERVE


def test_over_target_writes_never_heal_a_truncation_gap(tmp_path: Path) -> None:
    store, workspace = _lowered_above_fallback(tmp_path)
    with store._lock:  # pyright: ignore[reportPrivateUsage]
        state = store._load(workspace)  # pyright: ignore[reportPrivateUsage]
        store._note_gap_state(  # pyright: ignore[reportPrivateUsage]
            state, ObservationGapCode.TRUNCATED_PAYLOAD.value
        )
        store._save(workspace, state)  # pyright: ignore[reportPrivateUsage]

    assert (
        store.enqueue_outbox(
            workspace, "codex-sibling", _envelope(60_000, session=_SIBLING_SESSIONS[0])
        )
        == ObservationGapCode.OUTBOX_OVERFLOW.value
    )

    state = store._load(workspace)  # pyright: ignore[reportPrivateUsage]
    assert state.gaps is not None
    # The over-target allowance is room for accounting, not evidence that the
    # store stopped losing observations to its bound.
    assert state.gaps[ObservationGapCode.TRUNCATED_PAYLOAD.value].active


def test_an_accepted_buffered_input_still_transfers_over_target(tmp_path: Path) -> None:
    from finishup.adapters.integrations.observation_admission import (
        AdmissionBuffer,
        AdmissionPlan,
        BufferedInput,
    )

    store, workspace = _store(tmp_path)
    store.set_workspace_selection(workspace, _selection(LARGEST_CAPACITY), set_at=_NOW)
    buffered = replace(
        _envelope(70_000, session=_SIBLING_SESSIONS[0]), source_identity="buffered:accepted"
    )
    assert store.commit_selected_admission(
        workspace,
        AdmissionPlan(
            AdmissionBuffer((BufferedInput("lane", "sha256:" + "1" * 64, buffered, "pending", 0),)),
            (),
            True,
        ),
        incoming=buffered,
        newly_observed=True,
    )
    _accept_backlog(store, workspace, 3_000)
    store.clear_workspace_selection(workspace)

    # An input accepted before the lowering still drains into the outbox.
    transfer = AdmissionPlan(AdmissionBuffer(), (("codex-buffered", buffered),), False)
    assert store.commit_selected_admission(workspace, transfer)
    rows = store.list_pending_outbox_rows(workspace)
    assert len(rows) == 3_001
    assert rows[-1].envelope == buffered
    assert store.selection_accounting(workspace)["buffered_input_count"] == 0
