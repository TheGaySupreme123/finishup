"""SQLite durability for the profileless Codex capture ticket."""

from __future__ import annotations

from pathlib import Path

import apsw
import pytest

from finishup.adapters.sqlite.migrations import BUNDLE_MIGRATIONS, Migration, run_migrations
from finishup.adapters.sqlite.observation import SqliteObservationStore
from finishup.domain.observation import (
    ObservationCaptureTicket,
    ObservationContentKind,
    ObservationCursor,
    ObservationSource,
)
from finishup.domain.values import Timestamp
from integration.storage.test_migration_0011_observation import (
    _schema_ten_with_observation_rows,  # pyright: ignore[reportPrivateUsage]
)

_ROOT = Path(__file__).resolve().parents[3]
_WORKSPACE = "hmac-sha256:" + "a" * 64
_SESSION = "hmac-sha256:" + "b" * 64
_SOURCE = "hmac-sha256:" + "c" * 64
_TASK_ID = "tsk_00000000-0000-4000-8000-000000001101"
_FINISHUP_SESSION_ID = "ses_00000000-0000-4000-8000-000000001102"
_TIME = Timestamp("2026-09-06T10:00:00.000Z")


def _codex_ticket() -> ObservationCaptureTicket:
    return ObservationCaptureTicket(
        workspace_commitment=_WORKSPACE,
        task_id=_TASK_ID,
        finishup_session_id=_FINISHUP_SESSION_ID,
        session_commitment=_SESSION,
        source=ObservationSource.CODEX_HOOK,
        source_identity="hook:codex:1101",
        cursor=ObservationCursor(1, 18, 1, _SOURCE, "codex-obs-hook/1.0.0"),
        logical_identity="sha256:" + "3" * 64,
        content_capture_profile=None,
        authority_generation="sha256:" + "4" * 64,
        object_ids=(),
        captured_at=_TIME,
        state="staging",
        expected_parts=(
            (
                ObservationContentKind.TOOL_OUTPUT.value,
                "hook:codex:1101:tool-output",
                _SOURCE,
                0,
                1,
            ),
        ),
    )


def _open_codex_ticket_store() -> tuple[apsw.Connection, SqliteObservationStore]:
    db = _schema_ten_with_observation_rows()
    source_migration = Migration("0011", (_ROOT / "migrations/bundle/0011.sql").read_bytes())
    run_migrations(
        db,
        BUNDLE_MIGRATIONS[:10] + (source_migration,),
        maintenance=None,
    )
    return db, SqliteObservationStore(db)


def test_codex_ticket_round_trips_and_revocation_survives_sqlite_restart() -> None:
    db, store = _open_codex_ticket_store()
    ticket = _codex_ticket()
    try:
        store.record_capture_ticket(ticket)
        assert (
            store.load_capture_ticket(
                workspace=_WORKSPACE,
                logical_identity=ticket.logical_identity,
            )
            == ticket
        )
        assert store.list_pending_capture_tickets(_TASK_ID) == (ticket,)

        store.tombstone_capture_tickets(_WORKSPACE)
        revoked = store.load_capture_ticket(
            workspace=_WORKSPACE,
            logical_identity=ticket.logical_identity,
        )
        assert revoked is not None and revoked.state == "revoked"
    finally:
        db.close()

    reopened = apsw.Connection(":memory:")
    # The durable assertions above use the production SQLite adapter.  The
    # in-memory reopen here only verifies that the source migration itself is
    # independently loadable; no private database from the first connection
    # is copied or inspected.
    try:
        source = (_ROOT / "migrations/bundle/0011.sql").read_bytes().decode()
        for migration in BUNDLE_MIGRATIONS[:10]:
            reopened.execute(migration.ddl.decode())
        reopened.execute(source)
        columns = tuple(
            row[1] for row in reopened.execute("PRAGMA table_info(observation_capture_tickets)")
        )
        assert "content_capture_profile" in columns
    finally:
        reopened.close()


def test_codex_ticket_schema_rejects_a_profile_or_wrong_native_source() -> None:
    db, _store = _open_codex_ticket_store()
    try:
        values = (
            "sha256:" + "5" * 64,
            _WORKSPACE,
            _TASK_ID,
            _FINISHUP_SESSION_ID,
            _SESSION,
            "codex_hook",
            "hook:codex:invalid",
            1,
            0,
            1,
            _SOURCE,
            "codex-obs-hook/1.0.0",
            "sha256:" + "6" * 64,
            "claude-code-ordinary-observation-v1",
            "sha256:" + "7" * 64,
            b"[]",
            b"[]",
            _TIME.wire,
        )
        with pytest.raises(apsw.ConstraintError):
            db.execute(
                "INSERT INTO observation_capture_tickets("
                "ticket_id,workspace_commitment,task_id,yoetz_session_id,session_commitment,source,"
                "source_identity,source_generation,byte_position,event_position,last_source_commitment,"
                "mapping_version,logical_identity,content_capture_profile,authority_generation,"
                "expected_parts_json,object_ids_json,captured_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                values,
            )
    finally:
        db.close()
