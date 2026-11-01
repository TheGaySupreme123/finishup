"""Session-lane isolation and bounded retention for the local observation spool (#498)."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

import finishup.adapters.integrations.observation_local as local_mod
from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.domain.observation import (
    ObservationCursor,
    ObservationEnvelope,
    ObservationGapCode,
    ObservationIngestDisposition,
    ObservationSource,
)
from finishup.domain.values import JsonObject, Timestamp

_dedup_key = cast(Callable[[str, ObservationEnvelope], str], getattr(local_mod, "_dedup_key"))
_LOCAL_ENVELOPE_RETENTION_GAP = cast(str, getattr(local_mod, "_LOCAL_ENVELOPE_RETENTION_GAP"))
_LOCAL_DEDUP_EVICTED_GAP = cast(str, getattr(local_mod, "_LOCAL_DEDUP_EVICTED_GAP"))


def _envelope(*, session: str, identity: str, ordinal: int = 1) -> ObservationEnvelope:
    return ObservationEnvelope(
        session_commitment=session,
        event_kind="PreToolUse",
        source_identity=identity,
        source=ObservationSource.CODEX_HOOK,
        cursor=ObservationCursor(
            1,
            0,
            ordinal,
            "hmac-sha256:" + "ab" * 32,
            "codex-obs-hook/1.0.0",
        ),
        receipt_time=Timestamp("2026-01-01T00:00:00.000Z"),
        structural_payload=JsonObject({"tool_name": "shell", "tool_call_id": f"call-{identity}"}),
        content_object_refs=(),
        gap_codes=(),
    )


def _store(tmp_path: Path) -> tuple[LocalObservationStore, str, str, str]:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    quiet = store.bind_codex_session(workspace, "session-quiet")
    busy = store.bind_codex_session(workspace, "session-busy")
    return store, workspace, quiet, busy


def test_envelope_bound_preserves_one_quiet_lane(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A busy session consumes its own retention share before a quiet sibling's row."""

    monkeypatch.setattr(local_mod, "_MAX_ENVELOPES", 3)
    store, workspace, quiet, busy = _store(tmp_path)

    assert store.ingest(_envelope(session=quiet, identity="quiet:1")).disposition is (
        ObservationIngestDisposition.ACCEPTED
    )
    for ordinal in range(1, 4):
        assert (
            store.ingest(
                _envelope(session=busy, identity=f"busy:{ordinal}", ordinal=ordinal)
            ).disposition
            is ObservationIngestDisposition.ACCEPTED
        )

    retained = store.list_envelopes(workspace)
    assert [item.source_identity for item in retained] == ["quiet:1", "busy:2", "busy:3"]
    assert store.session_gap_codes(workspace, quiet) == ()
    assert _LOCAL_ENVELOPE_RETENTION_GAP in store.session_gap_codes(workspace, busy)
    # Local retention, never content loss (tb4n5).
    assert ObservationGapCode.TRUNCATED_PAYLOAD.value not in store.session_gap_codes(
        workspace, busy
    )

    reopened = LocalObservationStore(_state=tmp_path)
    assert [item.source_identity for item in reopened.list_envelopes(workspace)] == [
        "quiet:1",
        "busy:2",
        "busy:3",
    ]
    assert _LOCAL_ENVELOPE_RETENTION_GAP in reopened.session_gap_codes(workspace, busy)


def test_dedup_bound_is_deterministic_and_lane_aware(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Dedup retention removes the oldest busy key and keeps the quiet replay fence."""

    monkeypatch.setattr(local_mod, "_MAX_DEDUP", 3)
    monkeypatch.setattr(local_mod, "_MAX_ENVELOPES", 32)
    store, workspace, quiet, busy = _store(tmp_path)
    quiet_envelope = _envelope(session=quiet, identity="quiet:1")
    busy_envelopes = [
        _envelope(session=busy, identity=f"busy:{ordinal}", ordinal=ordinal)
        for ordinal in range(1, 4)
    ]

    assert store.ingest(quiet_envelope).disposition is ObservationIngestDisposition.ACCEPTED
    for item in busy_envelopes:
        assert store.ingest(item).disposition is ObservationIngestDisposition.ACCEPTED

    state = store._load(workspace)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    assert state.dedup_order is not None
    assert state.dedup_lanes is not None
    assert len(state.dedup_order) == 3
    assert state.dedup is not None
    assert _dedup_key(workspace, quiet_envelope) in state.dedup
    assert _dedup_key(workspace, busy_envelopes[0]) not in state.dedup
    assert _dedup_key(workspace, busy_envelopes[1]) in state.dedup
    assert _dedup_key(workspace, busy_envelopes[2]) in state.dedup
    assert _LOCAL_DEDUP_EVICTED_GAP in store.session_gap_codes(workspace, busy)

    reopened = LocalObservationStore(_state=tmp_path)
    assert reopened.ingest(quiet_envelope).disposition is ObservationIngestDisposition.DUPLICATE
    assert reopened.ingest(busy_envelopes[2]).disposition is ObservationIngestDisposition.DUPLICATE


def test_new_lane_cannot_evict_protected_outbox_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A full queue of accepted rows fails closed without mutating the backlog."""

    monkeypatch.setattr(local_mod, "_MAX_OUTBOX", 3)
    store, workspace, quiet, busy = _store(tmp_path)
    for ordinal in range(1, 4):
        assert (
            store.enqueue_outbox(
                workspace,
                "session-busy",
                _envelope(session=busy, identity=f"busy:{ordinal}", ordinal=ordinal),
            )
            is None
        )

    quiet_result = store.enqueue_outbox(
        workspace,
        "session-quiet",
        _envelope(session=quiet, identity="quiet:1"),
    )
    assert quiet_result == ObservationGapCode.OUTBOX_OVERFLOW.value
    pending = store.list_pending_outbox_rows(workspace)
    assert [(row.codex_session_id, row.envelope.source_identity) for row in pending] == [
        ("session-busy", "busy:1"),
        ("session-busy", "busy:2"),
        ("session-busy", "busy:3"),
    ]
    assert store.list_quarantine(workspace) == ()
    assert ObservationGapCode.OUTBOX_OVERFLOW.value in store.session_gap_codes(workspace, quiet)

    # Existing-lane overflow leaves that lane's remaining rows in FIFO order
    # and reports a typed overflow instead of skipping its head or evicting a
    # protected row.
    assert (
        store.enqueue_outbox(
            workspace,
            "session-busy",
            _envelope(session=busy, identity="busy:4", ordinal=4),
        )
        == ObservationGapCode.OUTBOX_OVERFLOW.value
    )
    assert [
        row.envelope.source_identity
        for row in store.list_pending_outbox_rows(workspace, codex_session_id="session-busy")
    ] == ["busy:1", "busy:2", "busy:3"]


def test_new_lane_may_reclaim_disposable_row_after_admission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fairness can reclaim an optional row only after the new lane is admissible."""

    store, workspace, quiet, busy = _store(tmp_path)
    for ordinal in range(1, 3):
        assert (
            store.enqueue_outbox(
                workspace,
                "session-busy",
                _envelope(session=busy, identity=f"busy:{ordinal}", ordinal=ordinal),
            )
            is None
        )
    disposable = replace(
        _envelope(session=busy, identity="busy:summary", ordinal=3),
        event_kind="RoutineReadSummary",
    )
    # This row represents an input accepted under the prior larger profile;
    # lowering the active bound must preserve it until the fair candidate
    # check below decides whether it may be reclaimed.
    assert (
        store.enqueue_outbox(
            workspace,
            "session-busy",
            disposable,
            accepted_transfer=True,
        )
        is None
    )
    monkeypatch.setattr(local_mod, "_MAX_OUTBOX", 3)

    assert (
        store.enqueue_outbox(
            workspace,
            "session-quiet",
            _envelope(session=quiet, identity="quiet:1"),
        )
        is None
    )
    pending = store.list_pending_outbox_rows(workspace)
    assert [(row.codex_session_id, row.envelope.source_identity) for row in pending] == [
        ("session-busy", "busy:1"),
        ("session-busy", "busy:2"),
        ("session-quiet", "quiet:1"),
    ]
    assert [entry[1].source_identity for entry in store.list_quarantine(workspace)] == [
        "busy:summary"
    ]


def test_quarantine_one_lane_leaves_sibling_pending_rows_isolated(tmp_path: Path) -> None:
    """Terminalizing one session does not move or reorder its sibling's backlog."""

    store, workspace, quiet, busy = _store(tmp_path)
    for session_id, commitment, prefix in (
        ("session-busy", busy, "busy"),
        ("session-quiet", quiet, "quiet"),
    ):
        for ordinal in range(1, 3):
            assert (
                store.enqueue_outbox(
                    workspace,
                    session_id,
                    _envelope(
                        session=commitment,
                        identity=f"{prefix}:{ordinal}",
                        ordinal=ordinal,
                    ),
                )
                is None
            )

    assert (
        store.quarantine_outbox_session(
            workspace,
            "session-busy",
            ObservationGapCode.MAPPING_MISSING.value,
        )
        == 2
    )
    assert [row.envelope.source_identity for row in store.list_pending_outbox_rows(workspace)] == [
        "quiet:1",
        "quiet:2",
    ]
    assert [entry[1].source_identity for entry in store.list_quarantine(workspace)] == [
        "busy:1",
        "busy:2",
    ]


def test_state_byte_pressure_sheds_busy_detail_before_quiet_detail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The byte safety ladder uses the same lane-aware envelope selection."""

    monkeypatch.setattr(local_mod, "_MAX_ENVELOPES", 16)
    store, workspace, quiet, busy = _store(tmp_path)
    assert store.ingest(_envelope(session=quiet, identity="quiet:1")).disposition is (
        ObservationIngestDisposition.ACCEPTED
    )
    for ordinal in range(1, 5):
        assert (
            store.ingest(
                _envelope(session=busy, identity=f"busy:{ordinal}", ordinal=ordinal)
            ).disposition
            is ObservationIngestDisposition.ACCEPTED
        )

    state_path = next((tmp_path / "observation" / "workspaces").glob("*.json"))
    monkeypatch.setattr(local_mod, "_MAX_STATE_BYTES", state_path.stat().st_size - 250)
    store.note_coverage_gap(workspace, ObservationGapCode.SERVICE_UNAVAILABLE.value)

    retained = store.list_envelopes(workspace)
    assert retained[0].source_identity == "quiet:1"
    assert all(item.session_commitment == busy for item in retained[1:])
    assert store.session_gap_codes(workspace, quiet) == ()
    assert _LOCAL_ENVELOPE_RETENTION_GAP in store.session_gap_codes(workspace, busy)
    assert ObservationGapCode.TRUNCATED_PAYLOAD.value not in store.session_gap_codes(
        workspace, busy
    )
