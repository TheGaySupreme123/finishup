"""Migration 0009 widens the observation source CHECK to the full ``ObservationSource`` enum."""

from __future__ import annotations

import asyncio

import apsw
import pytest

from yoetz.adapters.sqlite.migrations import (
    BUNDLE_MIGRATIONS,
    current_schema_version,
    initialize_bundle,
    run_migrations,
)
from yoetz.adapters.sqlite.observation import SqliteObservationStore
from yoetz.domain.observation import (
    ObservationCursor,
    ObservationEnvelope,
    ObservationIngestDisposition,
    ObservationSource,
    ObservationStatusQuery,
)
from yoetz.domain.values import JsonObject, Timestamp
from yoetz.protocol.errors import PublicErrorCode, PublicOperationError

_WORKSPACE = "hmac-sha256:" + "a" * 64
_SESSION = "hmac-sha256:" + "b" * 64
_SOURCE = "hmac-sha256:" + "c" * 64
_TIME = "2026-09-04T09:17:29.514Z"
_CURSOR_COLUMNS = (
    "workspace_commitment, source, session_commitment, generation, byte_pos, event_pos, "
    "last_source_commitment, mapping_version"
)
_EVENT_COLUMNS = (
    "workspace_commitment, session_commitment, source, event_kind, structural_json, "
    "content_refs_json, gap_codes_json, receipt_time, source_generation, byte_position, "
    "event_position, last_source_commitment, mapping_version"
)


def _cursor_row(source: str, session: str = _SESSION) -> tuple[str | int, ...]:
    return (_WORKSPACE, source, session, 1, 10, 1, _SOURCE, "codex-obs-hook/1.0.0")


def _event_row(source: str, session: str = _SESSION) -> tuple[str | int | bytes, ...]:
    return (
        _WORKSPACE,
        session,
        source,
        "PostToolUse",
        b"{}",
        b"[]",
        b"[]",
        _TIME,
        1,
        10,
        1,
        _SOURCE,
        "codex-obs-hook/1.0.0",
    )


def _schema_eight() -> apsw.Connection:
    db = apsw.Connection(":memory:")
    db.execute("PRAGMA foreign_keys = ON")
    db.execute("PRAGMA trusted_schema = OFF")
    with db:
        for migration in BUNDLE_MIGRATIONS[:8]:
            db.execute(migration.ddl.decode())
        db.execute(
            "INSERT INTO observation_consent(workspace_commitment, granted_at, revoked_at, paused) "
            "VALUES (?, ?, NULL, 0)",
            (_WORKSPACE, _TIME),
        )
        db.execute(
            f"INSERT INTO observation_cursors({_CURSOR_COLUMNS}) VALUES (?,?,?,?,?,?,?,?)",
            _cursor_row("codex_hook"),
        )
        db.execute(
            f"INSERT INTO observation_events({_EVENT_COLUMNS}) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            _event_row("codex_hook"),
        )
    assert db.execute("PRAGMA user_version").fetchone() == (8,)
    return db


def _insert_both(db: apsw.Connection, source: str, session: str) -> None:
    with db:
        db.execute(
            f"INSERT INTO observation_cursors({_CURSOR_COLUMNS}) VALUES (?,?,?,?,?,?,?,?)",
            _cursor_row(source, session),
        )
        db.execute(
            f"INSERT INTO observation_events({_EVENT_COLUMNS}) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            _event_row(source, session),
        )


@pytest.mark.parametrize("source", ["claude_hook", "cursor_hook"])
def test_schema_eight_rejects_the_host_hook_sources(source: str) -> None:
    """The dogfood defect: pre-0009 DDL refuses every non-Codex source (issue #576)."""

    db = _schema_eight()
    with pytest.raises(apsw.ConstraintError):
        _insert_both(db, source, "hmac-sha256:" + "d" * 64)


def test_schema_eight_upgrade_preserves_rows_and_admits_every_source() -> None:
    db = _schema_eight()
    report = run_migrations(db, BUNDLE_MIGRATIONS, maintenance=None)  # type: ignore[arg-type]
    assert report.applied_versions == (
        "0009",
        "0010",
        "0011",
        "0012",
        "0013",
        "0014",
        "0015",
        "0016",
    )
    assert db.execute("PRAGMA user_version").fetchone() == (
        current_schema_version(BUNDLE_MIGRATIONS),
    )
    assert db.execute("PRAGMA foreign_key_check").fetchall() == []

    # Existing rows, their ids, and the receipt index survive the rebuild.
    assert db.execute(f"SELECT {_CURSOR_COLUMNS} FROM observation_cursors").fetchall() == [
        _cursor_row("codex_hook")
    ]
    assert db.execute(f"SELECT id, {_EVENT_COLUMNS} FROM observation_events").fetchall() == [
        (1, *_event_row("codex_hook"))
    ]
    assert db.execute(
        "SELECT tbl_name FROM sqlite_schema WHERE type = 'index' "
        "AND name = 'observation_events_by_workspace_receipt'"
    ).fetchone() == ("observation_events",)
    assert (
        db.execute("SELECT 1 FROM sqlite_schema WHERE name LIKE 'observation_%_v2'").fetchone()
        is None
    )

    # Every enum member is storable; the closed set is still enforced.
    for index, member in enumerate(ObservationSource):
        _insert_both(db, member.value, f"hmac-sha256:{str(index) * 64}")
    with pytest.raises(apsw.ConstraintError):
        _insert_both(db, "gemini_hook", "hmac-sha256:" + "e" * 64)
    assert db.execute("SELECT count(*) FROM observation_events").fetchone() == (
        1 + len(ObservationSource),
    )


def _envelope(source: ObservationSource, session: str) -> ObservationEnvelope:
    return ObservationEnvelope(
        session_commitment=session,
        event_kind="PostToolUse",
        source_identity=f"hook:{source.value}:1",
        source=source,
        cursor=ObservationCursor(1, 10, 1, _SOURCE, "codex-obs-hook/1.0.0"),
        receipt_time=Timestamp(_TIME),
        structural_payload=JsonObject({"tool_name": "shell", "exit_status": 0}),
        content_object_refs=(),
        gap_codes=(),
    )


def test_store_over_migrated_bundle_accepts_the_pending_claude_row_as_is() -> None:
    """The rows stranded by #576 deliver unchanged once the bundle reaches schema 9."""

    session = "hmac-sha256:" + "f" * 64
    envelope = _envelope(ObservationSource.CLAUDE_HOOK, session)
    db = _schema_eight()
    store = SqliteObservationStore(db)

    async def run() -> None:
        store.bind_session(_WORKSPACE, session)
        with pytest.raises(PublicOperationError) as before:
            await store.ingest(envelope)
        assert before.value.code is PublicErrorCode.INVALID_REQUEST
        assert before.value.retryable is False
        assert db.execute("SELECT count(*) FROM observation_dedup").fetchone() == (0,)

        run_migrations(db, BUNDLE_MIGRATIONS, maintenance=None)  # type: ignore[arg-type]
        after = await store.ingest(envelope)
        assert after.disposition is ObservationIngestDisposition.ACCEPTED
        status = await store.status(ObservationStatusQuery(_WORKSPACE))
        assert status.source_coverage[ObservationSource.CLAUDE_HOOK] is True

    asyncio.run(run())


@pytest.mark.parametrize("source", list(ObservationSource))
def test_fresh_bundle_stores_every_observation_source(source: ObservationSource) -> None:
    """Lock the domain enum to the DDL so the next source lands in CI, not in a dogfood."""

    db = apsw.Connection(":memory:")
    initialize_bundle(db, {"task_id": "task_obs", "owner_generation": "1"})
    store = SqliteObservationStore(db)

    async def run() -> None:
        store.grant_consent(_WORKSPACE, Timestamp(_TIME))
        store.bind_session(_WORKSPACE, _SESSION)
        result = await store.ingest(_envelope(source, _SESSION))
        assert result.disposition is ObservationIngestDisposition.ACCEPTED
        status = await store.status(ObservationStatusQuery(_WORKSPACE))
        assert status.source_coverage[source] is True
        assert len(store.list_envelopes(_WORKSPACE)) == 1

    asyncio.run(run())
