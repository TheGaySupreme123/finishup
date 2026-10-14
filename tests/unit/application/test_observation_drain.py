"""Focused routing and service-side observation outbox sweep tests."""

from __future__ import annotations

import asyncio
import contextlib
import threading
import time
from collections.abc import Generator
from pathlib import Path

import pytest

from finishup.adapters.integrations.codex_lifecycle import acquire_session_lock
from finishup.adapters.integrations.observation_local import (
    LocalObservationStore,
    ObservationOutboxRow,
)
from finishup.application.observation_drain import (
    ObservationDrainAction,
    ObservationOutboxSweeper,
    route_observation_ingest,
)
from finishup.domain.observation import (
    OBSERVATION_BACKPRESSURE_REASON,
    OBSERVATION_CONTENT_CAPTURE_PENDING_REASON,
    ObservationCursor,
    ObservationEnvelope,
    ObservationGapCode,
    ObservationIngestDisposition,
    ObservationIngestRequest,
    ObservationIngestResult,
    ObservationSource,
    ObservationStatusQuery,
)
from finishup.domain.values import JsonObject, Timestamp


def _envelope(session: str, identity: str, ordinal: int) -> ObservationEnvelope:
    return ObservationEnvelope(
        session_commitment=session,
        event_kind="PostToolUse",
        source_identity=identity,
        source=ObservationSource.CODEX_HOOK,
        cursor=ObservationCursor(
            1,
            0,
            ordinal,
            f"hmac-sha256:{'ab' * 32}",
            "codex-obs-hook/1.0.0",
        ),
        receipt_time=Timestamp("2026-01-01T00:00:00.000Z"),
        structural_payload=JsonObject(
            {"tool_name": "shell", "tool_call_id": identity, "exit_status": 0}
        ),
        content_object_refs=(),
        gap_codes=(),
    )


@pytest.mark.parametrize(
    ("result", "expected"),
    [
        (
            ObservationIngestResult(ObservationIngestDisposition.DUPLICATE, "duplicate", None),
            ObservationDrainAction.ACKNOWLEDGE,
        ),
        (
            ObservationIngestResult(
                ObservationIngestDisposition.REJECTED,
                ObservationGapCode.MAPPING_MISSING.value,
                None,
            ),
            ObservationDrainAction.RETRY,
        ),
        (
            ObservationIngestResult(
                ObservationIngestDisposition.REJECTED,
                ObservationGapCode.SESSION_SUPERSEDED.value,
                None,
            ),
            ObservationDrainAction.QUARANTINE,
        ),
        (
            ObservationIngestResult(
                ObservationIngestDisposition.REJECTED,
                "observation_disabled",
                None,
            ),
            ObservationDrainAction.RETRY,
        ),
        (
            ObservationIngestResult(
                ObservationIngestDisposition.REJECTED,
                ObservationGapCode.CONSENT_REVOKED.value,
                None,
            ),
            ObservationDrainAction.QUARANTINE,
        ),
        (
            ObservationIngestResult(
                ObservationIngestDisposition.REJECTED,
                ObservationGapCode.OBSERVATION_STORAGE_CORRUPT.value,
                None,
            ),
            ObservationDrainAction.QUARANTINE,
        ),
        (
            # A logical-identity claim conflict quarantines exactly one row
            # (issue #309); only observation_storage_corrupt retires a session.
            ObservationIngestResult(
                ObservationIngestDisposition.REJECTED,
                ObservationGapCode.DEDUP_CONFLICT.value,
                None,
            ),
            ObservationDrainAction.QUARANTINE,
        ),
    ],
)
def test_route_observation_ingest_is_pure(
    result: ObservationIngestResult, expected: ObservationDrainAction
) -> None:
    assert route_observation_ingest(result).action is expected


def test_route_unknown_rejection_reason_to_safe_retry_fallback() -> None:
    decision = route_observation_ingest(
        ObservationIngestResult(
            ObservationIngestDisposition.REJECTED,
            "customerapikey123",
            None,
        )
    )

    assert decision.action is ObservationDrainAction.RETRY
    assert decision.reason == ObservationGapCode.SERVICE_UNAVAILABLE.value


@pytest.mark.parametrize(
    "reason",
    [
        OBSERVATION_BACKPRESSURE_REASON,
        OBSERVATION_CONTENT_CAPTURE_PENDING_REASON,
        ObservationGapCode.VAULT_LOCKED.value,
        "paused",
        "observation_disabled",
    ],
)
def test_retry_ceiling_does_not_terminalize_designed_or_global_gates(reason: str) -> None:
    envelope = _envelope(f"hmac-sha256:{'cd' * 32}", "hook:barrier", 1)
    row = ObservationOutboxRow(
        "barrier",
        envelope,
        attempts=127,
        last_reason=reason,
        consecutive_reason_attempts=127,
    )

    decision = route_observation_ingest(
        ObservationIngestResult(
            ObservationIngestDisposition.REJECTED,
            reason,
            None,
        ),
        row=row,
    )

    assert decision.action is ObservationDrainAction.RETRY


def test_retry_ceiling_terminalizes_repeated_session_scoped_reason() -> None:
    reason = ObservationGapCode.MAPPING_MISSING.value
    row = ObservationOutboxRow(
        "mapping",
        _envelope(f"hmac-sha256:{'ce' * 32}", "hook:mapping", 1),
        attempts=127,
        last_reason=reason,
        consecutive_reason_attempts=127,
    )

    decision = route_observation_ingest(
        ObservationIngestResult(ObservationIngestDisposition.REJECTED, reason, None),
        row=row,
    )

    assert decision.action is ObservationDrainAction.QUARANTINE


@pytest.mark.anyio
async def test_workspace_global_retry_reason_stops_after_first_lane(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    outcomes: dict[str, ObservationIngestResult | Exception] = {}
    for session_id in ("locked-a", "locked-b"):
        session = store.bind_codex_session(workspace, session_id)
        envelope = _envelope(session, f"hook:{session_id}", 1)
        store.enqueue_outbox(workspace, session_id, envelope)
        outcomes[envelope.source_identity] = ObservationIngestResult(
            ObservationIngestDisposition.REJECTED,
            ObservationGapCode.VAULT_LOCKED.value,
            None,
        )
    coordinator = _Coordinator(outcomes)

    summary = await ObservationOutboxSweeper(store, coordinator).sweep()

    assert summary.attempted == 1
    assert summary.retry_pending == 1
    assert summary.reasons == ((ObservationGapCode.VAULT_LOCKED.value, 1),)
    assert len(coordinator.calls) == 1
    assert len(store.list_pending_outbox_rows(workspace)) == 2


def test_bulk_quarantine_records_terminal_reason_and_returns_rows_moved(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    corrupt = store.bind_codex_session(workspace, "corrupt")
    healthy = store.bind_codex_session(workspace, "healthy")
    for ordinal in (1, 2):
        store.enqueue_outbox(
            workspace,
            "corrupt",
            _envelope(corrupt, f"hook:corrupt:{ordinal}", ordinal),
        )
    store.enqueue_outbox(workspace, "healthy", _envelope(healthy, "hook:healthy", 1))

    moved = store.quarantine_outbox_session(
        workspace,
        "corrupt",
        ObservationGapCode.OBSERVATION_STORAGE_CORRUPT.value,
    )

    assert moved == 2
    assert (
        store.quarantine_outbox_session(
            workspace,
            "corrupt",
            ObservationGapCode.OBSERVATION_STORAGE_CORRUPT.value,
        )
        == 0
    )
    assert [row.codex_session_id for row in store.list_pending_outbox_rows(workspace)] == [
        "healthy"
    ]
    status = store.status(ObservationStatusQuery(workspace))
    assert ObservationGapCode.OBSERVATION_STORAGE_CORRUPT.value in status.gaps
    assert ObservationGapCode.OUTBOX_QUARANTINED.value in status.gaps


def test_successful_recovery_probe_heals_only_its_corrupt_session(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    first = store.bind_codex_session(workspace, "corrupt-first")
    second = store.bind_codex_session(workspace, "corrupt-second")
    store.enqueue_outbox(workspace, "corrupt-first", _envelope(first, "hook:first:1", 1))
    store.enqueue_outbox(workspace, "corrupt-second", _envelope(second, "hook:second:1", 1))
    reason = ObservationGapCode.OBSERVATION_STORAGE_CORRUPT.value
    assert store.quarantine_outbox_session(workspace, "corrupt-first", reason) == 1
    assert store.quarantine_outbox_session(workspace, "corrupt-second", reason) == 1

    assert store.ingest(_envelope(first, "hook:first:repaired", 2)).disposition is (
        ObservationIngestDisposition.ACCEPTED
    )
    assert reason in store.status(ObservationStatusQuery(workspace)).gaps

    assert store.ingest(_envelope(second, "hook:second:repaired", 2)).disposition is (
        ObservationIngestDisposition.ACCEPTED
    )
    healed = store.status(ObservationStatusQuery(workspace))
    assert reason not in healed.gaps
    assert ObservationGapCode.OUTBOX_QUARANTINED.value in healed.gaps


class _Coordinator:
    def __init__(self, outcomes: dict[str, ObservationIngestResult | Exception]) -> None:
        self.outcomes = outcomes
        self.calls: list[str] = []

    async def ingest_request(self, request: ObservationIngestRequest) -> ObservationIngestResult:
        identity = request.envelope.source_identity
        self.calls.append(request.codex_session_id)
        outcome = self.outcomes[identity]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


@pytest.mark.anyio
async def test_sweep_routes_rows_persists_attempts_and_marks_success(tmp_path: Path) -> None:
    store = LocalObservationStore(
        _state=tmp_path,
        _monotonic=lambda: 50.0,
        _wall=lambda: 1_767_225_600.0,
    )
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    # One session per outcome: a retryable rejection retires its whole session lane for the
    # pass (#272), so mixed routings can only all be observed across separate lanes.
    envelopes: dict[str, ObservationEnvelope] = {}
    for name in ("accepted", "retry", "permanent", "failed"):
        session = store.bind_codex_session(workspace, f"session-{name}")
        envelope = _envelope(session, f"hook:{name}", 1)
        envelopes[name] = envelope
        store.enqueue_outbox(workspace, f"session-{name}", envelope)

    coordinator = _Coordinator(
        {
            envelopes["accepted"].source_identity: ObservationIngestResult(
                ObservationIngestDisposition.DUPLICATE, "duplicate", None
            ),
            envelopes["retry"].source_identity: ObservationIngestResult(
                ObservationIngestDisposition.REJECTED,
                ObservationGapCode.MAPPING_MISSING.value,
                None,
            ),
            envelopes["permanent"].source_identity: ObservationIngestResult(
                ObservationIngestDisposition.REJECTED,
                ObservationGapCode.CONSENT_REVOKED.value,
                None,
            ),
            envelopes["failed"].source_identity: RuntimeError("transport detail must not persist"),
        }
    )
    summary = await ObservationOutboxSweeper(store, coordinator).sweep()

    assert summary.attempted == 4
    assert summary.acknowledged == 1
    assert summary.retry_pending == 2
    assert summary.quarantined == 1
    assert summary.reasons == (
        (ObservationGapCode.CONSENT_REVOKED.value, 1),
        (ObservationGapCode.MAPPING_MISSING.value, 1),
        (ObservationGapCode.SERVICE_UNAVAILABLE.value, 1),
    )
    assert store.last_successful_drain_mono(workspace) == 50.0
    assert store.quarantined_count(workspace) == 1
    pending = store.list_pending_outbox_rows(workspace)
    assert [row.envelope.source_identity for row in pending] == [
        envelopes["retry"].source_identity,
        envelopes["failed"].source_identity,
    ]
    assert [row.attempts for row in pending] == [1, 1]
    assert [row.last_reason for row in pending] == [
        ObservationGapCode.MAPPING_MISSING.value,
        ObservationGapCode.SERVICE_UNAVAILABLE.value,
    ]
    state_bytes = b"".join(path.read_bytes() for path in tmp_path.rglob("*.json"))
    assert b"transport detail must not persist" not in state_bytes


@pytest.mark.anyio
async def test_sweep_backpressure_deferral_never_projects_a_coverage_gap(tmp_path: Path) -> None:
    """#351: a check-barrier deferral keeps its row pending and annotated, but the
    workspace's current gaps never report the designed barrier as a condition."""

    from finishup.domain.observation import OBSERVATION_BACKPRESSURE_REASON

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.bind_codex_session(workspace, "session-deferred")
    envelope = _envelope(session, "hook:deferred", 1)
    store.enqueue_outbox(workspace, "session-deferred", envelope)

    coordinator = _Coordinator(
        {
            envelope.source_identity: ObservationIngestResult(
                ObservationIngestDisposition.REJECTED,
                OBSERVATION_BACKPRESSURE_REASON,
                None,
            ),
        }
    )
    summary = await ObservationOutboxSweeper(store, coordinator).sweep()

    assert summary.retry_pending == 1
    assert summary.reasons == ((OBSERVATION_BACKPRESSURE_REASON, 1),)
    pending = store.list_pending_outbox_rows(workspace)
    assert [row.last_reason for row in pending] == [OBSERVATION_BACKPRESSURE_REASON]
    status = store.status(ObservationStatusQuery(workspace))
    assert OBSERVATION_BACKPRESSURE_REASON not in status.gaps
    assert ObservationGapCode.SERVICE_UNAVAILABLE.value not in status.gaps

    # After the barrier clears, the retried row delivers and the outbox drains.
    coordinator.outcomes[envelope.source_identity] = ObservationIngestResult(
        ObservationIngestDisposition.ACCEPTED, None, envelope.cursor
    )
    converged = await ObservationOutboxSweeper(store, coordinator).sweep()
    assert converged.acknowledged == 1
    assert store.pending_outbox_count(workspace) == 0
    cleared = store.status(ObservationStatusQuery(workspace))
    assert OBSERVATION_BACKPRESSURE_REASON not in cleared.gaps


@pytest.mark.anyio
async def test_sweep_round_robins_pending_workspaces_under_limit(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    outcomes: dict[str, ObservationIngestResult | Exception] = {}
    expected_sessions: set[str] = set()
    for workspace_name in ("one", "two"):
        workspace = store.workspace_commitment(str((tmp_path / workspace_name).resolve()))
        store.grant_consent(workspace)
        codex_session = f"session-{workspace_name}"
        expected_sessions.add(codex_session)
        session = store.bind_codex_session(workspace, codex_session)
        for ordinal in (1, 2):
            envelope = _envelope(session, f"hook:{workspace_name}:{ordinal}", ordinal)
            store.enqueue_outbox(workspace, codex_session, envelope)
            outcomes[envelope.source_identity] = ObservationIngestResult(
                ObservationIngestDisposition.REJECTED,
                ObservationGapCode.MAPPING_MISSING.value,
                None,
            )

    coordinator = _Coordinator(outcomes)
    summary = await ObservationOutboxSweeper(store, coordinator, limit=2).sweep()

    assert summary.attempted == 2
    assert set(coordinator.calls) == expected_sessions
    assert len(store.pending_workspaces()) == 2


@pytest.mark.anyio
async def test_storage_corrupt_quarantines_session_backlog_and_keeps_healthy_lane(
    tmp_path: Path,
) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    corrupt_commitment = store.bind_codex_session(workspace, "corrupt-session")
    healthy_commitment = store.bind_codex_session(workspace, "healthy-session")
    outcomes: dict[str, ObservationIngestResult | Exception] = {}
    for ordinal in (1, 2, 3):
        envelope = _envelope(corrupt_commitment, f"hook:corrupt:{ordinal}", ordinal)
        store.enqueue_outbox(workspace, "corrupt-session", envelope)
        outcomes[envelope.source_identity] = ObservationIngestResult(
            ObservationIngestDisposition.REJECTED,
            ObservationGapCode.OBSERVATION_STORAGE_CORRUPT.value,
            None,
        )
    healthy = _envelope(healthy_commitment, "hook:healthy", 1)
    store.enqueue_outbox(workspace, "healthy-session", healthy)
    outcomes[healthy.source_identity] = ObservationIngestResult(
        ObservationIngestDisposition.ACCEPTED,
        None,
        healthy.cursor,
    )

    coordinator = _Coordinator(outcomes)
    summary = await ObservationOutboxSweeper(store, coordinator).sweep()

    assert coordinator.calls.count("corrupt-session") == 1
    assert coordinator.calls.count("healthy-session") == 1
    assert summary.attempted == 2
    assert summary.acknowledged == 1
    assert summary.quarantined == 3
    assert summary.reasons == ((ObservationGapCode.OBSERVATION_STORAGE_CORRUPT.value, 1),)
    assert store.pending_outbox_count(workspace) == 0
    assert store.quarantined_count(workspace) == 3
    status = store.status(ObservationStatusQuery(workspace))
    assert ObservationGapCode.OBSERVATION_STORAGE_CORRUPT.value in status.gaps
    assert ObservationGapCode.OUTBOX_QUARANTINED.value in status.gaps
    assert store.reclaim_quarantine(workspace) == 3


@pytest.mark.anyio
async def test_repeated_limit_one_sweeps_are_fair_across_sessions(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    outcomes: dict[str, ObservationIngestResult | Exception] = {}
    for session_name in ("a", "b"):
        codex_session = f"session-{session_name}"
        session = store.bind_codex_session(workspace, codex_session)
        envelope = _envelope(session, f"hook:{session_name}", 1)
        store.enqueue_outbox(workspace, codex_session, envelope)
        outcomes[envelope.source_identity] = ObservationIngestResult(
            ObservationIngestDisposition.REJECTED,
            ObservationGapCode.MAPPING_MISSING.value,
            None,
        )
    coordinator = _Coordinator(outcomes)
    sweeper = ObservationOutboxSweeper(store, coordinator, limit=1)

    await sweeper.sweep()
    await sweeper.sweep()

    assert coordinator.calls == ["session-a", "session-b"]


@pytest.mark.anyio
async def test_head_retry_retires_lane_and_stamps_backlog_with_shared_cause(
    tmp_path: Path,
) -> None:
    """A retryable head probes once per sweep; siblings are stamped, never stepped over (#272)."""

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.bind_codex_session(workspace, "long-session")
    outcomes: dict[str, ObservationIngestResult | Exception] = {}
    for ordinal in range(1, 66):
        identity = f"hook:long:{ordinal}"
        envelope = _envelope(session, identity, ordinal)
        store.enqueue_outbox(workspace, "long-session", envelope)
        outcomes[identity] = ObservationIngestResult(
            ObservationIngestDisposition.REJECTED,
            ObservationGapCode.MAPPING_MISSING.value,
            None,
        )
    coordinator = _Coordinator(outcomes)
    sweeper = ObservationOutboxSweeper(store, coordinator, limit=64)

    await sweeper.sweep()
    rows = store.list_pending_outbox_rows(workspace)
    assert [row.attempts for row in rows] == [1] + [0] * 64
    assert all(row.last_reason == ObservationGapCode.MAPPING_MISSING.value for row in rows)

    await sweeper.sweep()
    rows = store.list_pending_outbox_rows(workspace)
    assert [row.attempts for row in rows] == [2] + [0] * 64
    assert len(coordinator.calls) == 2


@pytest.mark.anyio
async def test_sweep_delivers_a_session_fifo_despite_attempt_skew(tmp_path: Path) -> None:
    """Recovered rows with high attempts must still go before newer rows of the same session.

    Sorting a lane by attempts once delivered a session's fresh rows first; the ingest cursor
    then advanced past the older rows and every one of them was destroyed as a terminal
    ``cursor_stale`` quarantine — the exact loss of issue #272.
    """

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.bind_codex_session(workspace, "recovered-session")
    outcomes: dict[str, ObservationIngestResult | Exception] = {}
    for ordinal in (1, 2, 3):
        envelope = _envelope(session, f"hook:recovered:{ordinal}", ordinal)
        store.enqueue_outbox(workspace, "recovered-session", envelope)
        outcomes[envelope.source_identity] = ObservationIngestResult(
            ObservationIngestDisposition.ACCEPTED, None, envelope.cursor
        )
    # The opening rows failed earlier passes (e.g. mapping_missing) and carry more attempts
    # than the youngest row, exactly the shape of a session that started before its mapping.
    for row in store.list_pending_outbox_rows(workspace)[:2]:
        assert (
            store.bump_outbox_row_attempt(
                workspace, row, reason=ObservationGapCode.MAPPING_MISSING.value
            )
            is not None
        )

    class _OrderRecorder:
        def __init__(self) -> None:
            self.positions: list[int] = []

        async def ingest_request(
            self, request: ObservationIngestRequest
        ) -> ObservationIngestResult:
            self.positions.append(request.envelope.cursor.event_position)
            return outcomes[request.envelope.source_identity]  # type: ignore[return-value]

    coordinator = _OrderRecorder()
    summary = await ObservationOutboxSweeper(store, coordinator).sweep()

    assert coordinator.positions == [1, 2, 3]
    assert summary.acknowledged == 3
    assert store.pending_outbox_count(workspace) == 0


@pytest.mark.anyio
async def test_head_retry_never_steps_over_to_a_later_row_of_the_same_session(
    tmp_path: Path,
) -> None:
    """A lane whose head fails retryably sits out the pass; other lanes keep draining (#272)."""

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    stuck = store.bind_codex_session(workspace, "stuck-session")
    healthy = store.bind_codex_session(workspace, "healthy-session")
    outcomes: dict[str, ObservationIngestResult | Exception] = {}
    for ordinal in (1, 2):
        envelope = _envelope(stuck, f"hook:stuck:{ordinal}", ordinal)
        store.enqueue_outbox(workspace, "stuck-session", envelope)
        outcomes[envelope.source_identity] = ObservationIngestResult(
            ObservationIngestDisposition.REJECTED,
            ObservationGapCode.SERVICE_UNAVAILABLE.value,
            None,
        )
    healthy_envelope = _envelope(healthy, "hook:healthy", 1)
    store.enqueue_outbox(workspace, "healthy-session", healthy_envelope)
    outcomes[healthy_envelope.source_identity] = ObservationIngestResult(
        ObservationIngestDisposition.ACCEPTED, None, healthy_envelope.cursor
    )

    coordinator = _Coordinator(outcomes)
    summary = await ObservationOutboxSweeper(store, coordinator).sweep()

    assert coordinator.calls.count("stuck-session") == 1
    assert coordinator.calls.count("healthy-session") == 1
    assert summary.attempted == 2
    assert summary.acknowledged == 1
    assert summary.retry_pending == 1
    stuck_rows = store.list_pending_outbox_rows(workspace, codex_session_id="stuck-session")
    assert [row.attempts for row in stuck_rows] == [1, 0]
    assert [row.last_reason for row in stuck_rows] == [
        ObservationGapCode.SERVICE_UNAVAILABLE.value,
        ObservationGapCode.SERVICE_UNAVAILABLE.value,
    ]


@pytest.mark.anyio
async def test_mapping_missing_for_an_ended_session_is_terminally_quarantined(
    tmp_path: Path,
) -> None:
    """Rows of a session that ended unmapped can never deliver; retire them loudly (#275).

    A live unmapped session keeps its rows pending: a later ``start`` (or the hook-side
    auto-attach re-attempt) can still map it.
    """

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    ended = store.bind_codex_session(workspace, "ended-session")
    live = store.bind_codex_session(workspace, "live-session")
    mapping_missing = ObservationIngestResult(
        ObservationIngestDisposition.REJECTED,
        ObservationGapCode.MAPPING_MISSING.value,
        None,
    )
    outcomes: dict[str, ObservationIngestResult | Exception] = {}
    for ordinal in (1, 2):
        envelope = _envelope(ended, f"hook:ended:{ordinal}", ordinal)
        store.enqueue_outbox(workspace, "ended-session", envelope)
        outcomes[envelope.source_identity] = mapping_missing
    live_envelope = _envelope(live, "hook:live", 1)
    store.enqueue_outbox(workspace, "live-session", live_envelope)
    outcomes[live_envelope.source_identity] = mapping_missing
    store.note_session_end(workspace, ended)

    coordinator = _Coordinator(outcomes)
    with acquire_session_lock("ended-session", _state=tmp_path) as owned:
        assert owned is True
        contested = await ObservationOutboxSweeper(store, coordinator).sweep()

    assert contested.quarantined == 0
    assert contested.retry_pending == 2
    assert len(store.list_pending_outbox_rows(workspace)) == 3

    summary = await ObservationOutboxSweeper(store, coordinator).sweep()

    assert summary.quarantined == 2
    assert summary.retry_pending == 1
    remaining = store.list_pending_outbox_rows(workspace)
    assert [row.codex_session_id for row in remaining] == ["live-session"]
    assert store.quarantined_count(workspace) == 2
    assert {entry[2] for entry in store.list_quarantine(workspace)} == {
        ObservationGapCode.MAPPING_MISSING.value
    }


@pytest.mark.anyio
async def test_overlapping_sweeps_cannot_resolve_uningested_same_source_successor(
    tmp_path: Path,
) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.bind_codex_session(workspace, "overlap-session")
    first = _envelope(session, "hook:same-source", 1)
    second = _envelope(session, "hook:same-source", 2)
    store.enqueue_outbox(workspace, "overlap-session", first)
    store.enqueue_outbox(workspace, "overlap-session", second)

    accepted = ObservationIngestResult(ObservationIngestDisposition.DUPLICATE, "duplicate", None)

    class _OverlappingCoordinator:
        def __init__(self) -> None:
            self.calls: list[int] = []
            self.nested = False

        async def ingest_request(
            self, request: ObservationIngestRequest
        ) -> ObservationIngestResult:
            self.calls.append(request.envelope.cursor.event_position)
            if not self.nested:
                self.nested = True
                await ObservationOutboxSweeper(store, self, limit=1).sweep()
            return accepted

    coordinator = _OverlappingCoordinator()
    await ObservationOutboxSweeper(store, coordinator, limit=1).sweep()

    assert coordinator.calls == [1]
    remaining = store.list_pending_outbox_rows(workspace)
    assert len(remaining) == 1
    assert remaining[0].envelope.cursor.event_position == 2


class _BlockingStore(LocalObservationStore):
    """A store whose calls block their thread, standing in for flock plus a full re-encode."""

    delay = 0.05

    def pending_workspaces(self) -> tuple[str, ...]:
        time.sleep(self.delay)
        return super().pending_workspaces()

    def list_pending_outbox_rows(
        self, workspace: str, *, codex_session_id: str | None = None
    ) -> tuple[ObservationOutboxRow, ...]:
        time.sleep(self.delay)
        return super().list_pending_outbox_rows(workspace, codex_session_id=codex_session_id)

    def bump_outbox_row_attempt(
        self,
        workspace: str,
        expected: ObservationOutboxRow,
        *,
        reason: str | None,
        attempted_at: Timestamp | None = None,
    ) -> ObservationOutboxRow | None:
        time.sleep(self.delay)
        return super().bump_outbox_row_attempt(
            workspace, expected, reason=reason, attempted_at=attempted_at
        )

    def acknowledge_outbox_row(self, workspace: str, expected: ObservationOutboxRow) -> bool:
        time.sleep(self.delay)
        return super().acknowledge_outbox_row(workspace, expected)


class _RendezvousStore(LocalObservationStore):
    """Pause one worker-side store call until the test proves the loop still progresses."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self.worker_started = threading.Event()
        self.release_worker = threading.Event()

    def pending_workspaces(self) -> tuple[str, ...]:
        self.worker_started.set()
        if not self.release_worker.wait(timeout=5.0):
            raise AssertionError("worker_rendezvous_not_released")
        return super().pending_workspaces()


def _accepted_backlog(
    store: LocalObservationStore, tmp_path: Path, *, rows: int
) -> tuple[str, dict[str, ObservationIngestResult | Exception]]:
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.bind_codex_session(workspace, "loop-session")
    outcomes: dict[str, ObservationIngestResult | Exception] = {}
    for ordinal in range(1, rows + 1):
        envelope = _envelope(session, f"hook:loop:{ordinal}", ordinal)
        store.enqueue_outbox(workspace, "loop-session", envelope)
        outcomes[envelope.source_identity] = ObservationIngestResult(
            ObservationIngestDisposition.DUPLICATE, "duplicate", None
        )
    return workspace, outcomes


@pytest.mark.anyio
async def test_sweep_never_blocks_the_event_loop(tmp_path: Path) -> None:
    """Control work keeps its share of the loop while a sweep does its blocking store I/O."""

    store = _RendezvousStore(_state=tmp_path)
    _workspace, outcomes = _accepted_backlog(store, tmp_path, rows=3)
    sweeper = ObservationOutboxSweeper(store, _Coordinator(outcomes))
    sweep_task = asyncio.create_task(sweeper.sweep())
    try:
        assert await asyncio.to_thread(store.worker_started.wait, 5.0)
        loop_progress = asyncio.Event()

        async def mark_loop_progress() -> None:
            loop_progress.set()

        progress_task = asyncio.create_task(mark_loop_progress())
        await progress_task
        assert loop_progress.is_set()
    finally:
        store.release_worker.set()
    summary = await sweep_task
    sweeper.close()
    assert summary.acknowledged == 3


@pytest.mark.anyio
async def test_sweep_deadline_is_now_enforceable(tmp_path: Path) -> None:
    """``wait_for`` cannot preempt synchronous work; the sweep must give it await points."""

    store = _BlockingStore(_state=tmp_path)
    store.delay = 0.3
    _workspace, outcomes = _accepted_backlog(store, tmp_path, rows=2)
    sweeper = ObservationOutboxSweeper(store, _Coordinator(outcomes))
    started = asyncio.get_running_loop().time()

    with pytest.raises(TimeoutError):
        await asyncio.wait_for(sweeper.sweep(), timeout=0.2)

    assert asyncio.get_running_loop().time() - started < 0.4


class _SweepAbort(BaseException):
    """Not an Exception, so the sweeper's per-row guard cannot swallow it."""


@pytest.mark.anyio
async def test_drain_lease_is_released_even_when_a_row_raises(tmp_path: Path) -> None:
    """Entering and leaving the lease in different worker threads must still be balanced."""

    store = LocalObservationStore(_state=tmp_path)
    _workspace, _outcomes = _accepted_backlog(store, tmp_path, rows=1)
    exits = 0
    original = store.drain_lease

    @contextlib.contextmanager
    def counting(workspace: str) -> Generator[bool]:
        nonlocal exits
        with original(workspace) as owned:
            try:
                yield owned
            finally:
                exits += 1

    store.drain_lease = counting  # pyright: ignore[reportAttributeAccessIssue]

    class _Aborting:
        async def ingest_request(
            self, request: ObservationIngestRequest
        ) -> ObservationIngestResult:
            del request
            raise _SweepAbort("row abort")

    with pytest.raises(_SweepAbort):
        await ObservationOutboxSweeper(store, _Aborting()).sweep()

    assert exits == 1


@pytest.mark.anyio
async def test_cancelling_a_sweep_mid_lease_enter_still_releases_the_lease(tmp_path: Path) -> None:
    """A cancelled enter must not leave the drain flock owned until the generator is collected."""

    store = LocalObservationStore(_state=tmp_path)
    _workspace, outcomes = _accepted_backlog(store, tmp_path, rows=1)
    entering = threading.Event()
    unblock = threading.Event()
    events: list[str] = []

    @contextlib.contextmanager
    def blocking(workspace: str) -> Generator[bool]:
        del workspace
        entering.set()
        unblock.wait(timeout=5)
        events.append("enter")
        try:
            yield True
        finally:
            events.append("exit")

    store.drain_lease = blocking  # pyright: ignore[reportAttributeAccessIssue]
    sweeper = ObservationOutboxSweeper(store, _Coordinator(outcomes))
    sweep = asyncio.create_task(sweeper.sweep())
    try:
        assert await asyncio.to_thread(entering.wait, 5)
        sweep.cancel()
        with pytest.raises(asyncio.CancelledError):
            await sweep
        assert events == []

        unblock.set()
        for _ in range(500):
            if "exit" in events:
                break
            await asyncio.sleep(0.01)
    finally:
        unblock.set()
        sweeper.close()

    assert events == ["enter", "exit"]


@pytest.mark.anyio
async def test_sweep_uses_its_own_pool_and_releases_it_on_close(tmp_path: Path) -> None:
    """A sweep parked on a flock must not consume the shared default executor's workers."""

    store = LocalObservationStore(_state=tmp_path)
    _workspace, outcomes = _accepted_backlog(store, tmp_path, rows=1)
    sweeper = ObservationOutboxSweeper(store, _Coordinator(outcomes))
    names: list[str] = []
    original = store.pending_workspaces

    def naming() -> tuple[str, ...]:
        names.append(threading.current_thread().name)
        return original()

    store.pending_workspaces = naming  # pyright: ignore[reportAttributeAccessIssue]

    await sweeper.sweep()
    executor = sweeper._executor  # pyright: ignore[reportPrivateUsage]

    assert executor is not None
    assert names and all(name.startswith("finishup-obs-sweep") for name in names)

    sweeper.close()
    assert sweeper._executor is None  # pyright: ignore[reportPrivateUsage]


@pytest.mark.anyio
async def test_sweep_quarantines_single_row_on_dedup_conflict_and_lane_continues(
    tmp_path: Path,
) -> None:
    """Issue #309: a per-envelope claim conflict must not retire the session."""

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.bind_codex_session(workspace, "session-claim-conflict")
    conflicted = _envelope(session, "hook:conflicted", 1)
    healthy = _envelope(session, "hook:healthy", 2)
    store.enqueue_outbox(workspace, "session-claim-conflict", conflicted)
    store.enqueue_outbox(workspace, "session-claim-conflict", healthy)

    coordinator = _Coordinator(
        {
            conflicted.source_identity: ObservationIngestResult(
                ObservationIngestDisposition.REJECTED,
                ObservationGapCode.DEDUP_CONFLICT.value,
                None,
            ),
            healthy.source_identity: ObservationIngestResult(
                ObservationIngestDisposition.ACCEPTED, None, healthy.cursor
            ),
        }
    )
    summary = await ObservationOutboxSweeper(store, coordinator).sweep()

    assert summary.attempted == 2
    assert summary.quarantined == 1
    assert summary.acknowledged == 1
    assert store.quarantined_count(workspace) == 1
    assert store.list_pending_outbox_rows(workspace) == ()


@pytest.mark.anyio
async def test_sweep_quarantines_repeated_retry_reason_and_unblocks_lane(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#540: a future retry misclassification cannot make a FIFO head immortal."""

    import finishup.application.observation_drain as drain_module

    monkeypatch.setattr(drain_module, "MAX_CONSECUTIVE_OBSERVATION_REJECTIONS", 2)
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session_id = "bounded-retry"
    session = store.bind_codex_session(workspace, session_id)
    poisoned = _envelope(session, "hook:poisoned", 1)
    healthy = _envelope(session, "hook:healthy", 2)
    store.enqueue_outbox(workspace, session_id, poisoned)
    store.enqueue_outbox(workspace, session_id, healthy)
    first = store.list_pending_outbox_rows(workspace)[0]
    assert (
        store.bump_outbox_row_attempt(
            workspace,
            first,
            reason=ObservationGapCode.SERVICE_UNAVAILABLE.value,
        )
        is not None
    )

    coordinator = _Coordinator(
        {
            poisoned.source_identity: ObservationIngestResult(
                ObservationIngestDisposition.REJECTED,
                ObservationGapCode.SERVICE_UNAVAILABLE.value,
                None,
            ),
            healthy.source_identity: ObservationIngestResult(
                ObservationIngestDisposition.ACCEPTED,
                None,
                healthy.cursor,
            ),
        }
    )
    summary = await ObservationOutboxSweeper(store, coordinator).sweep()

    assert summary.attempted == 2
    assert summary.quarantined == 1
    assert summary.acknowledged == 1
    assert summary.retry_pending == 0
    assert store.list_pending_outbox_rows(workspace) == ()
    quarantined = store.list_quarantine(workspace)
    assert quarantined[0][1].source_identity == poisoned.source_identity
    assert quarantined[0][2] == ObservationGapCode.SERVICE_UNAVAILABLE.value


@pytest.mark.anyio
async def test_sweep_yields_its_partial_summary_when_the_budget_is_spent(tmp_path: Path) -> None:
    """#564: a pass that runs long returns what it resolved instead of being cancelled."""

    class _StepClock:
        value = 0.0

        def __call__(self) -> float:
            return self.value

    class _AdvancingCoordinator(_Coordinator):
        async def ingest_request(
            self, request: ObservationIngestRequest
        ) -> ObservationIngestResult:
            result = await super().ingest_request(request)
            clock.value += 0.1
            return result

    store = LocalObservationStore(_state=tmp_path)
    workspace, outcomes = _accepted_backlog(store, tmp_path, rows=6)
    clock = _StepClock()
    sweeper = ObservationOutboxSweeper(
        store,
        _AdvancingCoordinator(outcomes),
        budget_seconds=0.2,
        _monotonic=clock,
    )

    summary = await sweeper.sweep()

    assert summary.acknowledged == 2
    assert summary.attempted == summary.acknowledged
    assert store.pending_outbox_count(workspace) == 6 - summary.acknowledged
    # The remaining rows are still the lane's FIFO tail; an unbudgeted pass finishes them.
    rest = await ObservationOutboxSweeper(store, _Coordinator(outcomes)).sweep()
    assert rest.acknowledged == 6 - summary.acknowledged
    assert store.pending_outbox_count(workspace) == 0


@pytest.mark.anyio
async def test_cancelled_row_ingest_releases_the_maintenance_gate(tmp_path: Path) -> None:
    """A hook/service cancellation cannot strand the row-level workflow gate."""

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.bind_codex_session(workspace, "cancelled-gate")
    envelope = _envelope(session, "hook:cancelled-gate", 1)
    store.enqueue_outbox(workspace, "cancelled-gate", envelope)
    started = asyncio.Event()
    release = asyncio.Event()

    class _BlockingCoordinator:
        async def ingest_request(
            self, request: ObservationIngestRequest
        ) -> ObservationIngestResult:
            del request
            started.set()
            await release.wait()
            return ObservationIngestResult(
                ObservationIngestDisposition.ACCEPTED,
                None,
                envelope.cursor,
            )

    gate = asyncio.Lock()
    task = asyncio.create_task(
        ObservationOutboxSweeper(
            store,
            _BlockingCoordinator(),
            ingest_gate=gate,
        ).sweep()
    )
    await started.wait()
    assert gate.locked()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not gate.locked()

    # The row remains retryable after cancellation and can be delivered by a later pass.
    result = await ObservationOutboxSweeper(
        store,
        _Coordinator(
            {
                envelope.source_identity: ObservationIngestResult(
                    ObservationIngestDisposition.ACCEPTED,
                    None,
                    envelope.cursor,
                )
            }
        ),
        ingest_gate=gate,
    ).sweep()
    assert result.acknowledged == 1
    assert not gate.locked()


@pytest.mark.anyio
async def test_workflow_waiter_gets_the_gate_before_the_next_sweep_row(tmp_path: Path) -> None:
    """A queued workflow control turn wins before the sweeper takes its next row."""

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    first_session = store.bind_codex_session(workspace, "fair-first")
    second_session = store.bind_codex_session(workspace, "fair-second")
    first = _envelope(first_session, "hook:fair-first", 1)
    second = _envelope(second_session, "hook:fair-second", 1)
    store.enqueue_outbox(workspace, "fair-first", first)
    store.enqueue_outbox(workspace, "fair-second", second)
    first_started = asyncio.Event()
    release_first = asyncio.Event()
    workflow_queued = asyncio.Event()
    workflow_entered = asyncio.Event()
    second_started = asyncio.Event()
    events: list[str] = []

    class _FairCoordinator:
        async def ingest_request(
            self, request: ObservationIngestRequest
        ) -> ObservationIngestResult:
            if request.envelope.source_identity == first.source_identity:
                events.append("first_started")
                first_started.set()
                await release_first.wait()
                events.append("first_finished")
                envelope = first
            else:
                events.append("second_started")
                second_started.set()
                envelope = second
            return ObservationIngestResult(
                ObservationIngestDisposition.ACCEPTED,
                None,
                envelope.cursor,
            )

    gate = asyncio.Lock()
    sweep_task = asyncio.create_task(
        ObservationOutboxSweeper(
            store,
            _FairCoordinator(),
            limit=2,
            ingest_gate=gate,
        ).sweep()
    )
    await first_started.wait()

    async def workflow_turn() -> None:
        workflow_queued.set()
        async with gate:
            events.append("workflow_entered")
            workflow_entered.set()

    workflow_task = asyncio.create_task(workflow_turn())
    await workflow_queued.wait()
    release_first.set()
    await workflow_entered.wait()
    await second_started.wait()
    await workflow_task
    await sweep_task

    assert events.index("workflow_entered") < events.index("second_started")
    assert store.pending_outbox_count(workspace) == 0


def test_sweep_budget_must_be_a_positive_float_or_absent(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    coordinator = _Coordinator({})
    ObservationOutboxSweeper(store, coordinator, budget_seconds=None)
    ObservationOutboxSweeper(store, coordinator, budget_seconds=0.5)
    for invalid in (0.0, -1.0, 5, True):
        with pytest.raises(ValueError, match="observation_sweep_budget_invalid"):
            ObservationOutboxSweeper(
                store,
                coordinator,
                budget_seconds=invalid,  # type: ignore[arg-type]
            )


def test_sweep_budget_yields_under_the_daemon_deadline() -> None:
    """The budget is only useful if it fires before the deadline that discards the summary."""

    from finishup.application.observation_drain import DEFAULT_OBSERVATION_SWEEP_BUDGET_SECONDS
    from finishup.service import daemon as daemon_module

    deadline = daemon_module._OBSERVATION_SWEEP_DEADLINE_SECONDS  # pyright: ignore[reportPrivateUsage]
    assert DEFAULT_OBSERVATION_SWEEP_BUDGET_SECONDS < deadline
    # Room for one slow ingest plus its store bookkeeping to land after the budget check.
    assert deadline - DEFAULT_OBSERVATION_SWEEP_BUDGET_SECONDS >= 5.0


@pytest.mark.parametrize(
    ("reason", "attempts", "expected"),
    [
        ("frame_invalid", 0, ObservationDrainAction.RETRY),
        ("frame_invalid", 127, ObservationDrainAction.QUARANTINE),
        ("frame_too_large", 0, ObservationDrainAction.QUARANTINE),
        ("invalid_request", 0, ObservationDrainAction.QUARANTINE),
        ("method_forbidden", 128, ObservationDrainAction.RETRY),
        ("protocol_mismatch", 128, ObservationDrainAction.RETRY),
    ],
)
def test_control_recovery_is_bounded_without_fabricated_ledger_refusal(
    reason: str, attempts: int, expected: ObservationDrainAction
) -> None:
    from finishup.application.observation_drain import observation_control_failure
    from finishup.ports.control import ControlError

    failure = observation_control_failure(ControlError(reason))
    row = ObservationOutboxRow(
        "host",
        _envelope("hmac-sha256:" + "a" * 64, "input", 1),
        attempts=attempts,
        last_reason=failure.reason,
        consecutive_reason_attempts=attempts,
    )
    decision = route_observation_ingest(failure, row=row)
    assert decision.action is expected
    assert decision.reason == "control_" + reason


# --- Shared-store contention (#689) -------------------------------------------------------------


@pytest.mark.anyio
async def test_answered_row_settles_in_one_store_transaction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Attempt, gap, lane reason and acknowledgement used to be up to four full saves per row."""

    store = LocalObservationStore(_state=tmp_path)
    workspace, outcomes = _accepted_backlog(store, tmp_path, rows=3)
    rows = store.list_pending_outbox_rows(workspace)
    # The last row is refused retryably: it records an attempt, a coverage gap and a lane reason.
    outcomes[rows[-1].envelope.source_identity] = ObservationIngestResult(
        ObservationIngestDisposition.REJECTED,
        ObservationGapCode.SERVICE_UNAVAILABLE.value,
        None,
    )
    sweeper = ObservationOutboxSweeper(store, _Coordinator(outcomes))
    writes_per_settlement: list[int] = []
    writes = 0
    original_write = store._save_unchecked  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]

    def counting_write(*args: object, **kwargs: object) -> None:
        nonlocal writes
        writes += 1
        original_write(*args, **kwargs)  # type: ignore[arg-type]

    store._save_unchecked = counting_write  # type: ignore[method-assign]  # noqa: SLF001
    settle = ObservationOutboxSweeper._settle_row  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]

    def counting_settle(self: ObservationOutboxSweeper, *args: object) -> int | None:
        nonlocal writes
        writes = 0
        result = settle(self, *args)  # type: ignore[arg-type]
        writes_per_settlement.append(writes)
        return result

    monkeypatch.setattr(ObservationOutboxSweeper, "_settle_row", counting_settle)
    try:
        summary = await sweeper.sweep()
    finally:
        sweeper.close()
    assert summary.acknowledged == 2 and summary.retry_pending == 1
    assert writes_per_settlement == [1, 1, 1]
    remaining = store.list_pending_outbox_rows(workspace)
    assert [row.last_reason for row in remaining] == [ObservationGapCode.SERVICE_UNAVAILABLE.value]
    assert (
        ObservationGapCode.SERVICE_UNAVAILABLE.value
        in store.status(ObservationStatusQuery(workspace)).gaps
    )


class _HeldLock:
    """Hold the store's process-local lock on another thread until released."""

    def __init__(self, store: LocalObservationStore) -> None:
        self._store = store
        self.held = threading.Event()
        self._release = threading.Event()
        self._thread = threading.Thread(target=self._run)

    def _run(self) -> None:
        with self._store._lock:  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            self.held.set()
            self._release.wait(timeout=30)

    def start(self) -> None:
        self._thread.start()
        assert self.held.wait(timeout=30)

    def release(self) -> None:
        self._release.set()
        self._thread.join(timeout=30)


@pytest.mark.anyio
async def test_contended_settlement_yields_and_the_accepted_row_replays(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A lost acknowledgement race stops the pass, keeps the row, and deduplicates on replay."""

    import finishup.adapters.integrations.observation_local as local

    monkeypatch.setattr(local, "_STORE_LOCK_TIMEOUT_SECONDS", 0.2)
    store = LocalObservationStore(_state=tmp_path)
    workspace, outcomes = _accepted_backlog(store, tmp_path, rows=2)
    holder = _HeldLock(store)

    class _AcceptThenContend(_Coordinator):
        async def ingest_request(
            self, request: ObservationIngestRequest
        ) -> ObservationIngestResult:
            result = await super().ingest_request(request)
            if len(self.calls) == 1:
                # The service accepted the row; another writer takes the store before the
                # sweeper can record that.
                await asyncio.to_thread(holder.start)
            return result

    coordinator = _AcceptThenContend(outcomes)
    sweeper = ObservationOutboxSweeper(store, coordinator)
    try:
        summary = await sweeper.sweep()
        assert summary.attempted == 1
        assert summary.acknowledged == 0
        assert dict(summary.reasons) == {"observation_store_busy": 1}
    finally:
        await asyncio.to_thread(holder.release)
    # Nothing was committed for the answered row; it is still the head of its lane.
    assert len(store.list_pending_outbox_rows(workspace)) == 2
    assert (
        ObservationGapCode.SERVICE_UNAVAILABLE.value
        not in store.status(ObservationStatusQuery(workspace)).gaps
    )
    try:
        replay = await sweeper.sweep()
    finally:
        sweeper.close()
    assert replay.acknowledged == 2
    assert store.list_pending_outbox_rows(workspace) == ()
    # The first row reached the coordinator twice: once accepted, once as its exact replay.
    assert len(coordinator.calls) == 3


class _StrandingStore(LocalObservationStore):
    """Block admission maintenance on an event and record how many workers ever overlap."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self.entered = threading.Event()
        self.release = threading.Event()
        self.block = True
        self.active = 0
        self.max_active = 0
        self.entries = 0
        self._guard = threading.Lock()

    def maintain_selected_admission(self, workspace: str, *, force: bool = False) -> None:
        with self._guard:
            self.active += 1
            self.entries += 1
            self.max_active = max(self.max_active, self.active)
        try:
            self.entered.set()
            if self.block:
                assert self.release.wait(timeout=30)
            super().maintain_selected_admission(workspace, force=force)
        finally:
            with self._guard:
                self.active -= 1


@pytest.mark.anyio
async def test_next_pass_never_overlaps_a_worker_a_cancelled_pass_left_running(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import finishup.application.observation_drain as drain

    monkeypatch.setattr(drain, "_STRANDED_WORKER_JOIN_SECONDS", 0.05)
    store = _StrandingStore(_state=tmp_path)
    workspace, outcomes = _accepted_backlog(store, tmp_path, rows=2)
    sweeper = ObservationOutboxSweeper(store, _Coordinator(outcomes))
    try:
        first = asyncio.create_task(sweeper.sweep())
        assert await asyncio.to_thread(store.entered.wait, 30)
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first
        # The cancelled pass's worker is still inside the store. The next pass must not start
        # store work beside it: it yields a busy summary instead.
        yielded = await sweeper.sweep()
        assert dict(yielded.reasons) == {"observation_store_busy": 1}
        assert yielded.attempted == 0
        assert store.entries == 1
        # Releasing the store gate does not establish worker completion. Observe the
        # actual worker before testing resumed delivery, keeping the 50 ms busy check above.
        with sweeper._inflight_guard:  # pyright: ignore[reportPrivateUsage]
            workers = tuple(sweeper._inflight)  # pyright: ignore[reportPrivateUsage]
        assert len(workers) == 1
        store.block = False
        store.release.set()
        await asyncio.wait_for(
            asyncio.gather(*(asyncio.wrap_future(worker) for worker in workers)), timeout=30
        )
        delivered = await sweeper.sweep()
    finally:
        store.release.set()
        sweeper.close()
    assert delivered.acknowledged == 2
    assert store.list_pending_outbox_rows(workspace) == ()
    assert store.max_active == 1


@pytest.mark.anyio
async def test_joining_a_failed_stranded_worker_does_not_report_raw_exception(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import gc

    class FailingStore(_StrandingStore):
        def maintain_selected_admission(self, workspace: str, *, force: bool = False) -> None:
            super().maintain_selected_admission(workspace, force=force)
            if self.entries == 1:
                raise OSError("synthetic stranded worker failure")

    store = FailingStore(_state=tmp_path)
    workspace, outcomes = _accepted_backlog(store, tmp_path, rows=2)
    sweeper = ObservationOutboxSweeper(store, _Coordinator(outcomes))
    loop = asyncio.get_running_loop()
    previous_handler = loop.get_exception_handler()
    unhandled: list[object] = []
    loop.set_exception_handler(lambda _loop, context: unhandled.append(context))
    original_wait = asyncio.wait

    async def release_at_join(
        waiters: list[asyncio.Future[object]], *, timeout: float
    ) -> tuple[set[asyncio.Future[object]], set[asyncio.Future[object]]]:
        # The join has wrapped the stranded worker before it is allowed to fail.
        store.block = False
        store.release.set()
        return await original_wait(waiters, timeout=timeout)

    try:
        first = asyncio.create_task(sweeper.sweep())
        assert await asyncio.to_thread(store.entered.wait, 30)
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first
        monkeypatch.setattr(asyncio, "wait", release_at_join)
        delivered = await sweeper.sweep()
        assert delivered.acknowledged == 2
        assert store.list_pending_outbox_rows(workspace) == ()
        gc.collect()
        assert not unhandled
    finally:
        store.release.set()
        sweeper.close()
        loop.set_exception_handler(previous_handler)


class _ContendedMaintenanceStore(LocalObservationStore):
    contended: str | None = None

    def maintain_selected_admission(self, workspace: str, *, force: bool = False) -> None:
        if workspace == self.contended:
            from finishup.ports.observation import ObservationStoreLockTimeout

            raise ObservationStoreLockTimeout(
                scope="process",
                waited_ms=2_000,
                holder_role="hook",
                holder_phase="handle_observe",
                holder_held_ms=2_100,
            )
        super().maintain_selected_admission(workspace, force=force)


@pytest.mark.anyio
async def test_contended_maintenance_sits_out_only_its_own_workspace(tmp_path: Path) -> None:
    store = _ContendedMaintenanceStore(_state=tmp_path)
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    outcomes: dict[str, ObservationIngestResult | Exception] = {}
    workspaces: list[str] = []
    for index, root in enumerate((first, second)):
        workspace = store.workspace_commitment(str(root.resolve()))
        store.grant_consent(workspace)
        session = store.bind_codex_session(workspace, f"lane-{index}")
        envelope = _envelope(session, f"hook:ws:{index}", 1)
        store.enqueue_outbox(workspace, f"lane-{index}", envelope)
        outcomes[envelope.source_identity] = ObservationIngestResult(
            ObservationIngestDisposition.DUPLICATE, "duplicate", None
        )
        workspaces.append(workspace)
    store.contended = workspaces[0]
    sweeper = ObservationOutboxSweeper(store, _Coordinator(outcomes))
    try:
        summary = await sweeper.sweep()
    finally:
        sweeper.close()
    # Fail-closed for the contended workspace only; the other one still drains.
    assert summary.acknowledged == 1
    assert dict(summary.reasons) == {"observation_store_busy": 1}
    assert len(store.list_pending_outbox_rows(workspaces[0])) == 1
    assert store.list_pending_outbox_rows(workspaces[1]) == ()
