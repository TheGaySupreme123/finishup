from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest

import finishup.adapters.integrations.observation_local as local_mod
from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.domain.observation import (
    ObservationCursor,
    ObservationEnvelope,
    ObservationSource,
    ObservationStatusQuery,
)
from finishup.domain.observation_budget import (
    LARGEST_CAPACITY,
    STANDARD_CAPACITY,
    ObservationCapacity,
    ObservationMode,
    PressureState,
    no_cap_support,
)
from finishup.domain.observation_settings import (
    ObservationDetailProfile,
    ObservationSelection,
)
from finishup.domain.values import JsonObject, Timestamp

_NOW = Timestamp("2026-09-10T00:01:00.000Z")
_OLD = Timestamp("2026-09-10T00:00:00.000Z")
_WALL_SECONDS = datetime(2026, 9, 10, 0, 1, tzinfo=UTC).timestamp()
_SESSION = "hmac-sha256:" + "1" * 64
# A modification time no write can produce: 1970-01-01T00:00:01Z.
_PINNED_NS = 1_000_000_000


def _store(tmp_path: Path, monotonic: list[float]) -> tuple[LocalObservationStore, str]:
    workspace_path = tmp_path / "workspace"
    workspace_path.mkdir()
    store = LocalObservationStore(
        _state=tmp_path / "state",
        _monotonic=lambda: monotonic[0],
        # Keep wall-minus-monotonic stable so the store recognizes one boot
        # epoch while the test advances its deterministic monotonic clock.
        _wall=lambda: _WALL_SECONDS + monotonic[0],
    )
    return store, store.workspace_commitment(str(workspace_path))


def _select_detailed(store: LocalObservationStore, workspace: str) -> None:
    store.set_session_selection(
        workspace,
        _SESSION,
        ObservationSelection(
            detail=ObservationDetailProfile.DETAILED,
            capacity=STANDARD_CAPACITY,
        ),
        set_at=_NOW,
    )


def _pending_envelope(*, session: str, receipt_time: Timestamp) -> ObservationEnvelope:
    return ObservationEnvelope(
        session_commitment=session,
        event_kind="PostToolUse",
        source_identity="pending:oldest-age",
        source=ObservationSource.CODEX_HOOK,
        cursor=ObservationCursor(
            source_generation=1,
            byte_position=0,
            event_position=1,
            last_source_commitment="hmac-sha256:" + "a" * 64,
            mapping_version="codex-obs-hook/1.0.0",
        ),
        receipt_time=receipt_time,
        structural_payload=JsonObject({"tool_name": "shell", "exit_status": 1}),
        content_object_refs=(),
        gap_codes=(),
    )


def test_update_pressure_persists_selected_and_effective_state(tmp_path: Path) -> None:
    monotonic = [0.0]
    store, workspace = _store(tmp_path, monotonic)
    _select_detailed(store, workspace)
    store.update_capture_backlog(workspace, 450, 0, _NOW, _NOW, route_id="capture-a")

    first = store.update_selection_pressure(workspace, _SESSION)
    assert first.selected_mode is ObservationMode.DETAILED
    assert first.effective_mode is ObservationMode.FOCUSED
    assert first.state is PressureState.HIGH
    assert first.transition is not None
    assert first.transition.notice == "downgrade"
    assert workspace in store.pending_workspaces()

    reopened = LocalObservationStore(
        _state=tmp_path / "state",
        _monotonic=lambda: monotonic[0],
        _wall=lambda: _WALL_SECONDS,
    )
    status = reopened.selection_runtime_status(workspace, _SESSION)
    assert status["selected_mode"] == "detailed"
    assert status["effective_mode"] == "focused"
    assert status["pressure_state"] == "high"
    capture_status = cast(Mapping[str, object], status["capture_backlog"])
    assert capture_status["capture_backlog_scope"] == "partial"


def test_workspace_runtime_status_aggregates_active_child_pressure(tmp_path: Path) -> None:
    monotonic = [0.0]
    store, workspace = _store(tmp_path, monotonic)
    store.set_workspace_selection(
        workspace,
        ObservationSelection(
            detail=ObservationDetailProfile.DETAILED,
            capacity=STANDARD_CAPACITY,
        ),
        set_at=_NOW,
    )
    _select_detailed(store, workspace)
    store.update_capture_backlog(workspace, 450, 0, _NOW, _NOW, route_id="capture-a")
    store.update_selection_pressure(workspace, _SESSION)

    status = store.selection_runtime_status(workspace)
    assert status["selected_mode"] == "detailed"
    assert status["effective_mode"] == "focused"
    assert status["pressure_state"] == "high"
    status_wire = store.status(ObservationStatusQuery(workspace)).selection_runtime
    assert status_wire is not None
    assert status_wire.effective_mode is ObservationMode.FOCUSED
    assert status_wire.pressure_state is PressureState.HIGH


def test_runtime_status_does_not_advance_recovery_or_write(tmp_path: Path) -> None:
    monotonic = [0.0]
    store, workspace = _store(tmp_path, monotonic)
    _select_detailed(store, workspace)
    store.update_capture_backlog(workspace, 450, 0, _NOW, _NOW, route_id="capture-a")
    store.update_selection_pressure(workspace, _SESSION)
    state_path = store._workspace_path(workspace)  # pyright: ignore[reportPrivateUsage]

    # Detect a write by what it does to a modification time pinned in the past. Comparing two
    # real mtimes read back to back is a race against the filesystem clock: it ticks once per
    # jiffy (1 ms on the CI-equivalent box, 4 to 10 ms elsewhere), so two writes inside one tick
    # carry the same mtime and "was it written" cannot be told from "it was not".
    def pin_mtime() -> None:
        os.utime(state_path, ns=(_PINNED_NS, _PINNED_NS))

    def written() -> bool:
        return state_path.stat().st_mtime_ns != _PINNED_NS

    # A low read must not start the dwell timer or persist a snapshot.
    pin_mtime()
    store.update_capture_backlog(workspace, 0, 0, None, _NOW, route_id="capture-a")
    assert written(), "the low backlog read is itself recorded"
    at_rest = state_path.read_bytes()

    pin_mtime()
    status = store.selection_runtime_status(workspace, _SESSION)
    assert status["pressure_state"] == "high"
    assert status["effective_mode"] == "focused"
    assert not written(), "a status read must not write the state file"
    assert state_path.read_bytes() == at_rest


def test_low_pressure_dwell_recovers_and_emits_one_transition(tmp_path: Path) -> None:
    monotonic = [0.0]
    store, workspace = _store(tmp_path, monotonic)
    _select_detailed(store, workspace)
    store.update_capture_backlog(workspace, 450, 0, _NOW, _NOW, route_id="capture-a")
    high = store.update_selection_pressure(workspace, _SESSION)
    assert high.state is PressureState.HIGH

    store.update_capture_backlog(workspace, 0, 0, None, _NOW, route_id="capture-a")
    monotonic[0] = 1.0
    before_dwell = store.update_selection_pressure(workspace, _SESSION)
    assert before_dwell.state is PressureState.HIGH
    assert before_dwell.transition is None
    assert before_dwell.effective_mode is ObservationMode.FOCUSED

    monotonic[0] = 11.1
    recovered = store.update_selection_pressure(workspace, _SESSION)
    assert recovered.state is PressureState.HEALTHY
    assert recovered.effective_mode is ObservationMode.DETAILED
    assert recovered.transition is not None
    assert recovered.transition.notice == "recovery"

    monotonic[0] = 12.0
    repeated = store.update_selection_pressure(workspace, _SESSION)
    assert repeated.transition is None
    assert repeated.snapshot.transition_identity == recovered.snapshot.transition_identity


def test_retry_does_not_reset_oldest_pending_age(tmp_path: Path) -> None:
    monotonic = [0.0]
    store, workspace = _store(tmp_path, monotonic)
    envelope = _pending_envelope(session=_SESSION, receipt_time=_OLD)
    assert store.enqueue_outbox(workspace, "codex-session", envelope) is None

    before = store.selection_runtime_status(workspace, _SESSION)
    assert before["oldest_pending_age_ms"] == 60_000
    (row,) = store.list_pending_outbox_rows(workspace)
    retried = store.bump_outbox_row_attempt(
        workspace, row, reason="transport_unavailable", attempted_at=_NOW
    )
    assert retried is not None

    after = store.selection_runtime_status(workspace, _SESSION)
    assert after["oldest_pending_age_ms"] == before["oldest_pending_age_ms"]


def test_pressure_snapshot_cache_stays_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monotonic = [0.0]
    store, workspace = _store(tmp_path, monotonic)
    monkeypatch.setattr(local_mod, "_MAX_HOOK_SEQUENCES", 2)
    sessions = [_SESSION, "hmac-sha256:" + "2" * 64, "hmac-sha256:" + "3" * 64]
    for session in sessions:
        store.update_selection_pressure(workspace, session)

    with store._lock:  # pyright: ignore[reportPrivateUsage]
        state = store._load(workspace)  # pyright: ignore[reportPrivateUsage]
        assert state.pressure_snapshots is not None
        assert len(state.pressure_snapshots) == 2


@pytest.mark.parametrize(
    "source",
    [
        ObservationSource.CODEX_HOOK,
        ObservationSource.CLAUDE_HOOK,
        ObservationSource.CURSOR_HOOK,
        ObservationSource.CODEX_SESSION_STREAM,
    ],
)
def test_current_hard_pressure_blocks_new_input_but_allows_recovery(
    tmp_path: Path, source: ObservationSource
) -> None:
    monotonic = [0.0]
    store, workspace = _store(tmp_path, monotonic)
    old = replace(_pending_envelope(session=_SESSION, receipt_time=_OLD), source=source)
    assert store.enqueue_outbox(workspace, "session", old) is None
    store.update_capture_backlog(workspace, 512, 0, _NOW, _NOW, route_id="capture-a")
    assert not store.update_selection_pressure(workspace, _SESSION).admission_allowed
    fresh = replace(
        old,
        source_identity="new-input",
        receipt_time=_NOW,
        cursor=replace(old.cursor, event_position=2),
    )
    from finishup.adapters.integrations.observation_admission import AdmissionBuffer, AdmissionPlan

    plan = AdmissionPlan(buffer=AdmissionBuffer(), deliveries=(("session", fresh),), deferred=False)
    assert not store.commit_selected_admission(workspace, plan, incoming=fresh, newly_observed=True)
    (row,) = store.list_pending_outbox_rows(workspace)
    assert store.acknowledge_outbox_row(workspace, row)
    store.update_capture_backlog(workspace, 0, 0, None, _NOW, route_id="capture-a")
    status = store.update_selection_pressure(workspace, _SESSION)
    assert status.admission_allowed
    assert status.state is PressureState.HIGH
    assert not status.content_allowed
    assert store.commit_selected_admission(workspace, plan, incoming=fresh, newly_observed=True)
    assert [r.envelope.source_identity for r in store.list_pending_outbox_rows(workspace)] == [
        "new-input"
    ]


def test_session_end_clears_pressure_only_at_current_generation(tmp_path: Path) -> None:
    monotonic = [0.0]
    store, workspace = _store(tmp_path, monotonic)
    store.grant_consent(workspace)
    session = store.bind_codex_session(workspace, "session")
    old = _pending_envelope(session=session, receipt_time=_OLD)
    store.update_capture_backlog(workspace, 450, 0, _NOW, _NOW, route_id="capture-a")
    assert store.enqueue_outbox(workspace, "session", old) is None
    store.update_selection_pressure(workspace, session)
    store.update_capture_backlog(workspace, 0, 0, None, _NOW, route_id="capture-a")
    (row,) = store.list_pending_outbox_rows(workspace)
    assert store.acknowledge_outbox_row(workspace, row)
    store.note_session_end(workspace, session, generation=0)
    assert workspace in store.pending_workspaces()
    store.note_session_end(workspace, session, generation=1)
    store.maintain_selected_admission(workspace)
    assert workspace not in store.pending_workspaces()
    assert store.selection_runtime_status(workspace, session)["pressure_state"] == "healthy"
    reopened = LocalObservationStore(_state=tmp_path / "state")
    assert workspace not in reopened.pending_workspaces()


def test_accepted_buffer_transfer_drains_under_hard_pressure(tmp_path: Path) -> None:
    from finishup.adapters.integrations.observation_admission import (
        AdmissionBuffer,
        AdmissionPlan,
        BufferedInput,
    )

    monotonic = [0.0]
    store, workspace = _store(tmp_path, monotonic)
    envelope = _pending_envelope(session=_SESSION, receipt_time=_NOW)
    buffer = AdmissionBuffer(
        (BufferedInput("session", "sha256:" + "1" * 64, envelope, "pending", 0),)
    )
    assert store.commit_selected_admission(
        workspace, AdmissionPlan(buffer, (), True), incoming=envelope, newly_observed=True
    )
    store.update_capture_backlog(workspace, 512, 0, _NOW, _NOW, route_id="capture-a")
    assert not store.update_selection_pressure(workspace, _SESSION).admission_allowed
    transfer = AdmissionPlan(AdmissionBuffer(), (("session", envelope),), False)
    assert store.commit_selected_admission(workspace, transfer)
    (row,) = store.list_pending_outbox_rows(workspace)
    assert row.envelope == envelope
    assert store.selection_accounting(workspace)["buffered_input_count"] == 0


def test_buffer_only_plan_checks_aggregate_bytes_before_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from finishup.adapters.integrations.observation_admission import (
        AdmissionBuffer,
        AdmissionPlan,
        BufferedInput,
    )

    monotonic = [0.0]
    store, workspace = _store(tmp_path, monotonic)
    envelope = _pending_envelope(session=_SESSION, receipt_time=_NOW)
    state = store._load(workspace)  # pyright: ignore[reportPrivateUsage]
    initial_size = len(store._encode_state(workspace, state))  # pyright: ignore[reportPrivateUsage]

    def limit(workspace: str, state: object, *, required: int | None = None) -> int:
        return initial_size + 1_000

    monkeypatch.setattr(store, "_state_byte_limit", limit)
    buffer = AdmissionBuffer(
        tuple(
            BufferedInput(
                "session",
                "sha256:" + "1" * 64,
                replace(
                    envelope,
                    source_identity=f"input-{i}",
                    cursor=replace(envelope.cursor, event_position=i + 1),
                ),
                "pending",
                0,
            )
            for i in range(4)
        )
    )
    assert not store.commit_selected_admission(
        workspace,
        AdmissionPlan(buffer, (), True),
        incoming=envelope,
        newly_observed=True,
        replayable=True,
    )
    assert store.selection_accounting(workspace)["buffered_input_count"] == 0
    assert store.selection_accounting(workspace)["unrecoverable_input_count"] == 0
    assert store.list_pending_outbox_rows(workspace) == ()


# --- #828: custom capacity reaches the store's aggregate and state ladders ---


def _select_workspace_capacity(
    store: LocalObservationStore, workspace: str, capacity: ObservationCapacity
) -> None:
    store.set_workspace_selection(
        workspace,
        ObservationSelection(detail=ObservationDetailProfile.FOCUSED, capacity=capacity),
        set_at=_NOW,
    )


def _aggregate_outbox_limit(store: LocalObservationStore, workspace: str) -> int:
    with store._lock:  # pyright: ignore[reportPrivateUsage]
        state = store._load(workspace)  # pyright: ignore[reportPrivateUsage]
        return store._aggregate_outbox_limit(state)  # pyright: ignore[reportPrivateUsage]


def _state_byte_limit(store: LocalObservationStore, workspace: str) -> int:
    with store._lock:  # pyright: ignore[reportPrivateUsage]
        state = store._load(workspace)  # pyright: ignore[reportPrivateUsage]
        return store._state_byte_limit(workspace, state)  # pyright: ignore[reportPrivateUsage]


def test_state_ceiling_is_owned_by_the_budget_policy() -> None:
    assert local_mod._MAX_EXPANDED_STATE_BYTES == 16 * 1_048_576  # pyright: ignore[reportPrivateUsage]


@pytest.mark.parametrize(
    ("capacity", "outbox_limit"),
    [
        (ObservationCapacity(64), 64),
        (ObservationCapacity(1_024), 1_024),
        (LARGEST_CAPACITY, 8_192),
    ],
)
def test_custom_capacity_sets_the_aggregate_outbox_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capacity: ObservationCapacity,
    outbox_limit: int,
) -> None:
    # The standard compatibility seam must not leak into a non-standard
    # selection, while the standard selection still honors it.
    monkeypatch.setattr(local_mod, "_MAX_OUTBOX", 3)
    store, workspace = _store(tmp_path, [0.0])
    assert _aggregate_outbox_limit(store, workspace) == 3
    _select_workspace_capacity(store, workspace, capacity)
    assert _aggregate_outbox_limit(store, workspace) == outbox_limit
    _select_workspace_capacity(store, workspace, STANDARD_CAPACITY)
    assert _aggregate_outbox_limit(store, workspace) == 3


@pytest.mark.parametrize(
    ("capacity", "state_limit"),
    [
        (ObservationCapacity(64), 1_048_576),
        (ObservationCapacity(1_024), 2 * 1_048_576),
        (ObservationCapacity(3_000), 6_000 * 1_024),
        (LARGEST_CAPACITY, 16 * 1_048_576),
    ],
)
def test_custom_capacity_follows_the_state_byte_ladder(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capacity: ObservationCapacity,
    state_limit: int,
) -> None:
    monkeypatch.setattr(local_mod, "_MAX_STATE_BYTES", 12_345)
    store, workspace = _store(tmp_path, [0.0])
    assert _state_byte_limit(store, workspace) == 12_345
    _select_workspace_capacity(store, workspace, capacity)
    assert _state_byte_limit(store, workspace) == state_limit


def test_small_custom_capacity_admits_structural_rows(tmp_path: Path) -> None:
    store, workspace = _store(tmp_path, [0.0])
    _select_workspace_capacity(store, workspace, ObservationCapacity(64))
    envelope = _pending_envelope(session=_SESSION, receipt_time=_NOW)
    assert store.enqueue_outbox(workspace, "codex-session", envelope) is None
    assert len(store.list_pending_outbox_rows(workspace)) == 1


def test_runtime_status_reports_effective_budget_and_labels(tmp_path: Path) -> None:
    store, workspace = _store(tmp_path, [0.0])
    _select_workspace_capacity(store, workspace, STANDARD_CAPACITY)
    store.set_session_selection(
        workspace,
        _SESSION,
        ObservationSelection(
            detail=ObservationDetailProfile.FOCUSED, capacity=ObservationCapacity(1_024)
        ),
        set_at=_NOW,
    )

    session_status = store.selection_runtime_status(workspace, _SESSION)
    assert session_status["selected_capacity"] == 1_024
    assert session_status["effective_capacity"] == 1_024
    assert session_status["selected_capacity_label"] == "custom"
    assert session_status["effective_capacity_label"] == "custom"
    budget = cast(Mapping[str, object], session_status["effective_budget"])
    assert budget["schema"] == "yoetz.observation-effective-budget/1"
    assert budget["budget_policy_version"] == "observation-budget-v3-capacity"
    assert budget["validation_status"] == "not_validated"
    assert budget["scope"] == "session"
    assert budget["selected_queue_count"] == 1_024
    assert budget["effective_reason"] == "selected"
    assert budget["limiting_dimension"] in {"count", "bytes", "oldest_age", "capture_backlog"}
    assert type(budget["utilization_bps"]) is int
    assert budget["no_cap"] == no_cap_support()
    assert budget["limits"] == {
        "queue_count": 1_024,
        "queue_bytes": 1_048_576,
        "state_bytes": 2_097_152,
        "pending_attempts": 256,
        "capture_tickets": 512,
        "capture_bytes": 134_217_728,
        "protected_count": 256,
        "protected_bytes": 262_144,
        "session_fair_share": 256,
        "session_fair_share_bytes": 262_144,
        "max_pending_age_ms": 60_000,
        "state_document_ceiling_bytes": 16_777_216,
    }

    workspace_status = store.selection_runtime_status(workspace)
    assert workspace_status["selected_capacity_label"] == "standard"
    assert workspace_status["effective_capacity_label"] == "custom"
    workspace_budget = cast(Mapping[str, object], workspace_status["effective_budget"])
    assert workspace_budget["scope"] == "workspace"
    assert workspace_budget["selected_queue_count"] == 512
    assert workspace_budget["effective_queue_count"] == 1_024
    assert workspace_budget["effective_reason"] == "workspace_aggregate"

    typed = store.status(ObservationStatusQuery(workspace)).selection_runtime
    assert typed is not None
    assert typed.effective_capacity == ObservationCapacity(1_024)
    assert typed.effective_budget["scope"] == "workspace"


def _numbered_envelope(*, session: str, index: int) -> ObservationEnvelope:
    envelope = _pending_envelope(session=session, receipt_time=_NOW)
    return replace(
        envelope,
        source_identity=f"pending:sibling-{index}",
        cursor=replace(envelope.cursor, event_position=index + 1),
    )


def test_small_session_capacity_does_not_shrink_sibling_admission(tmp_path: Path) -> None:
    # A session-scoped count below the standard baseline lowers only that
    # session's own admission; the shared workspace queue stays at 512.
    store, workspace = _store(tmp_path, [0.0])
    sibling = "hmac-sha256:" + "2" * 64
    store.set_session_selection(
        workspace,
        _SESSION,
        ObservationSelection(
            detail=ObservationDetailProfile.FOCUSED, capacity=ObservationCapacity(64)
        ),
        set_at=_NOW,
    )
    assert _aggregate_outbox_limit(store, workspace) == 512

    sibling_results = [
        store.enqueue_outbox(
            workspace, "codex-sibling", _numbered_envelope(session=sibling, index=index)
        )
        for index in range(300)
    ]
    assert sibling_results == [None] * 300

    small_results = [
        store.enqueue_outbox(
            workspace, "codex-small", _numbered_envelope(session=_SESSION, index=1_000 + index)
        )
        for index in range(70)
    ]
    assert small_results[:64] == [None] * 64
    assert all(result is not None for result in small_results[64:])

    sibling_status = store.selection_runtime_status(workspace, sibling)
    assert sibling_status["selected_capacity"] == 512
    assert sibling_status["effective_capacity"] == 512
    small_status = store.selection_runtime_status(workspace, _SESSION)
    assert small_status["selected_capacity"] == 64
    assert small_status["effective_capacity"] == 512


@pytest.mark.parametrize("source", list(ObservationSource))
def test_aged_backlog_retains_new_inputs_across_restart(
    tmp_path: Path, source: ObservationSource
) -> None:
    from finishup.adapters.integrations.observation_admission import AdmissionBuffer, AdmissionPlan

    monotonic = [0.0]
    store, workspace = _store(tmp_path, monotonic)
    _select_detailed(store, workspace)
    old = replace(_pending_envelope(session=_SESSION, receipt_time=_OLD), source=source)
    assert store.enqueue_outbox(workspace, "session", old) is None
    # Twenty minutes of delayed delivery, observed with a controlled clock.
    monotonic[0] = 1_200.0
    for index in range(2, 22):
        fresh = replace(
            old, source_identity=f"input-{index}", cursor=replace(old.cursor, event_position=index)
        )
        plan = AdmissionPlan(AdmissionBuffer(), (("session", fresh),), False)
        assert store.commit_selected_admission(workspace, plan, incoming=fresh, newly_observed=True)
    assert store.selection_accounting(workspace)["unrecoverable_input_count"] == 0
    reopened = LocalObservationStore(
        _state=tmp_path / "state",
        _monotonic=lambda: monotonic[0],
        _wall=lambda: _WALL_SECONDS + monotonic[0],
    )
    status = reopened.selection_runtime_status(workspace, _SESSION)
    assert cast(int, status["oldest_pending_age_ms"]) >= 1_200_000
    assert status["admission_allowed"] is True
    assert status["content_allowed"] is True
    assert status["effective_mode"] == "detailed"
    rows = reopened.list_pending_outbox_rows(workspace)
    assert len(rows) == 21
    for row in rows:
        assert reopened.acknowledge_outbox_row(workspace, row)
    assert reopened.list_pending_outbox_rows(workspace) == ()
    assert reopened.selection_accounting(workspace)["unrecoverable_input_count"] == 0


def test_delivery_unit_bytes_match_the_encoded_unit() -> None:
    envelope = _pending_envelope(session=_SESSION, receipt_time=_OLD)
    for codex_session_id in ("", "session", 'é "\\', "019a-" * 12, "\U0001f600"):
        encoded = local_mod.canonical_encode(
            cast(
                local_mod.JsonValue,
                {
                    "codex_session_id": codex_session_id,
                    "envelope": local_mod._envelope_fragment(envelope),  # pyright: ignore[reportPrivateUsage]
                },
            )
        )
        assert local_mod._delivery_unit_bytes(codex_session_id, envelope) == len(encoded)  # pyright: ignore[reportPrivateUsage]


def test_admission_pressure_sampling_does_not_reencode_retained_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Hook admission cost must not re-encode each retained row (#887).

    With age no longer refusing input, a stalled backlog can reach the session fair share. The
    admission check then samples every pending row, so its encoder calls must not scale with it.
    """

    from finishup.adapters.integrations.observation_admission import AdmissionBuffer, AdmissionPlan

    monotonic = [0.0]
    store, workspace = _store(tmp_path, monotonic)
    _select_detailed(store, workspace)
    old = _pending_envelope(session=_SESSION, receipt_time=_OLD)

    def admit(index: int) -> bool:
        fresh = replace(
            old, source_identity=f"input-{index}", cursor=replace(old.cursor, event_position=index)
        )
        plan = AdmissionPlan(AdmissionBuffer(), (("session", fresh),), False)
        return store.commit_selected_admission(workspace, plan, incoming=fresh, newly_observed=True)

    for index in range(1, 101):
        assert admit(index)
    real_encode = local_mod.canonical_encode
    calls = 0

    def counting_encode(value: object) -> bytes:
        nonlocal calls
        calls += 1
        return real_encode(cast(local_mod.JsonValue, value))

    monkeypatch.setattr(local_mod, "canonical_encode", counting_encode)
    assert admit(101)
    # A handful of whole-document and new-row encodes, never one per retained row.
    assert calls < 20
    assert store.selection_accounting(workspace)["unrecoverable_input_count"] == 0


def test_backlog_probe_reports_only_unattempted_rows(tmp_path: Path) -> None:
    monotonic = [0.0]
    store, workspace = _store(tmp_path, monotonic)
    assert not store.has_unattempted_outbox_rows()
    envelope = _pending_envelope(session=_SESSION, receipt_time=_OLD)
    assert store.enqueue_outbox(workspace, "session", envelope) is None
    assert store.has_unattempted_outbox_rows()
    (row,) = store.list_pending_outbox_rows(workspace)
    assert store.bump_outbox_row_attempt(workspace, row, reason=None) is not None
    # A row that already failed an attempt keeps the ordinary retry cadence.
    assert not store.has_unattempted_outbox_rows()
