"""Durable aggregate accounting for native observation capture handoffs."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import apsw
import pytest

from finishup.adapters.sqlite.migrations import initialize_bundle
from finishup.adapters.sqlite.observation import (
    SqliteObservationStore,
)
from finishup.domain.observation import (
    ObservationCaptureTicket,
    ObservationContentChunk,
    ObservationContentKind,
    ObservationCursor,
    ObservationSource,
)
from finishup.domain.values import Timestamp
from finishup.ports.objects import ObjectKind, ObjectMetadata, ObjectRef
from finishup.protocol.errors import PublicErrorCode, PublicOperationError

_WORKSPACE = "hmac-sha256:" + "1" * 64
_SESSION = "hmac-sha256:" + "2" * 64
_SOURCE = "hmac-sha256:" + "3" * 64
_TASK = "tsk_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
_FINISHUP_SESSION = "ses_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
_TIME = Timestamp("2026-09-10T10:00:00.000Z")


def _store(path: str = ":memory:") -> tuple[apsw.Connection, SqliteObservationStore]:
    db = apsw.Connection(path)
    initialize_bundle(db, {"task_id": _TASK, "owner_generation": "1"})
    return db, SqliteObservationStore(db)


def _ticket(index: int, *, captured_at: Timestamp = _TIME) -> ObservationCaptureTicket:
    return ObservationCaptureTicket(
        workspace_commitment=_WORKSPACE,
        task_id=_TASK,
        finishup_session_id=_FINISHUP_SESSION,
        session_commitment=_SESSION,
        source=ObservationSource.CLAUDE_HOOK,
        source_identity=f"hook:budget-{index}",
        cursor=ObservationCursor(
            source_generation=1,
            byte_position=10 + index,
            event_position=1 + index,
            last_source_commitment=_SOURCE,
            mapping_version="claude-observation-1",
        ),
        logical_identity=f"sha256:{index:064x}",
        content_capture_profile="claude-code-ordinary-observation-v1",
        authority_generation="sha256:" + "4" * 64,
        object_ids=(),
        captured_at=captured_at,
        state="staging",
        expected_parts=(
            (
                ObservationContentKind.TOOL_OUTPUT.value,
                f"hook:budget-{index}:tool-output",
                _SOURCE,
                0,
                1,
            ),
        ),
    )


def _chunk(index: int, content: bytes) -> ObservationContentChunk:
    return ObservationContentChunk(
        content_kind=ObservationContentKind.TOOL_OUTPUT,
        correlation_identity=f"hook:budget-{index}:tool-output",
        source_commitment=_SOURCE,
        media_type="text/plain",
        part_index=0,
        part_count=1,
        content=content,
    )


def _ref(index: int, content: bytes) -> ObjectRef:
    return ObjectRef(
        object_id=f"obj_00000000-0000-4000-8000-{index:012d}",
        plaintext_size=len(content),
        commitment="hmac-sha256:" + f"{index + 10:064x}"[-64:],
        envelope_digest="sha256:" + f"{index + 20:064x}"[-64:],
        encryption_format="yoetz-object/1",
        key_slot="slot-1",
        metadata=ObjectMetadata(
            ObjectKind.CAPTURED_CONTENT,
            "application/vnd.yoetz.observation-content+json",
            _TASK,
            datetime(2026, 9, 10, 10, 0, tzinfo=UTC),
        ),
    )


def _record_manifest(
    store: SqliteObservationStore,
    ticket: ObservationCaptureTicket,
    index: int,
    content: bytes,
) -> None:
    store.record_content_manifest(
        workspace=_WORKSPACE,
        logical_identity=ticket.logical_identity,
        chunk=_chunk(index, content),
        ref=_ref(index, content),
        content_digest="sha256:" + f"{index + 30:064x}"[-64:],
        content_bytes=len(content),
        recorded_at=ticket.captured_at,
    )


def test_capture_backlog_counts_active_manifest_bytes_and_releases_on_revoke() -> None:
    db, store = _store()
    try:
        ticket = _ticket(1)
        store.record_capture_ticket(ticket)
        assert store.capture_backlog(_WORKSPACE).count == 1
        assert store.capture_backlog(_WORKSPACE).byte_count == 0
        assert store.capture_backlog(_WORKSPACE).oldest_receipt_time == _TIME

        _record_manifest(store, ticket, 1, b"1234567")
        backlog = store.capture_backlog(_WORKSPACE)
        assert (backlog.count, backlog.byte_count, backlog.oldest_receipt_time) == (
            1,
            7,
            _TIME,
        )

        store.tombstone_capture_ticket(ticket)
        assert store.capture_backlog(_WORKSPACE) == type(backlog)(0, 0, None)
    finally:
        db.close()


def test_capture_byte_budget_exhaustion_is_independent_of_ticket_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import finishup.adapters.sqlite.observation as observation_module

    monkeypatch.setattr(observation_module, "_MAX_CAPTURE_CONTENT_BYTES", 10)
    db, store = _store()
    try:
        first = _ticket(2)
        second = _ticket(3)
        store.record_capture_ticket(first)
        store.record_capture_ticket(second)
        _record_manifest(store, first, 2, b"1234567")

        with pytest.raises(PublicOperationError) as exhausted:
            _record_manifest(store, second, 3, b"1234")
        assert exhausted.value.code is PublicErrorCode.LIMIT_EXCEEDED
        assert exhausted.value.retryable is False

        # The failed admission leaves the staging fence and prior bytes intact;
        # a revoke releases only the second ticket's zero-byte reservation.
        backlog = store.capture_backlog(_WORKSPACE)
        assert (backlog.count, backlog.byte_count) == (2, 7)
        store.tombstone_capture_ticket(second)
        backlog = store.capture_backlog(_WORKSPACE)
        assert (backlog.count, backlog.byte_count) == (1, 7)
    finally:
        db.close()


def test_capture_backlog_survives_sqlite_restart_and_revoke(tmp_path: Path) -> None:
    database = tmp_path / "capture-budget.sqlite3"
    db, store = _store(str(database))
    ticket = _ticket(4, captured_at=Timestamp("2026-09-10T09:59:00.000Z"))
    store.record_capture_ticket(ticket)
    _record_manifest(store, ticket, 4, b"restart")
    before = store.capture_backlog(_WORKSPACE)
    db.close()

    reopened_db = apsw.Connection(str(database))
    reopened = SqliteObservationStore(reopened_db)
    try:
        assert reopened.capture_backlog(_WORKSPACE) == before
        reopened.tombstone_capture_ticket(ticket)
        assert reopened.capture_backlog(_WORKSPACE).count == 0
        assert reopened.capture_backlog(_WORKSPACE).byte_count == 0
    finally:
        reopened_db.close()
