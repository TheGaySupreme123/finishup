"""Migration 0011 capture-ticket upgrade and backward-compatibility guards."""

from __future__ import annotations

import apsw

from yoetz.adapters.sqlite.connection import verify_schema_identity
from yoetz.adapters.sqlite.migrations import (
    BUNDLE_MIGRATIONS,
    current_schema_version,
    run_migrations,
)
from yoetz.protocol.canonical import canonical_encode

_WORKSPACE = "hmac-sha256:" + "a" * 64
_SESSION = "hmac-sha256:" + "b" * 64
_SOURCE = "hmac-sha256:" + "c" * 64
_CONTENT = "hmac-sha256:" + "d" * 64
_OBJECT_ID = "obj_00000000-0000-4000-8000-000000001101"
_TASK_ID = "tsk_00000000-0000-4000-8000-000000001101"
_YOETZ_SESSION_ID = "ses_00000000-0000-4000-8000-000000001102"
_TIME = "2026-09-06T10:00:00.000Z"


def _schema_ten_with_observation_rows() -> apsw.Connection:
    db = apsw.Connection(":memory:")
    db.execute("PRAGMA foreign_keys = ON")
    db.execute("PRAGMA trusted_schema = OFF")
    with db:
        for migration in BUNDLE_MIGRATIONS[:10]:
            db.execute(migration.ddl.decode())
        db.execute(
            "INSERT INTO bundle_meta(key,value) VALUES"
            "('task_id',?),('owner_generation','1'),"
            "('storage_schema_version','10'),('protocol_version','0.1'),"
            "('import_schema_version','1')",
            (_TASK_ID,),
        )
        db.execute("INSERT INTO counters(name,next_value) VALUES('ingestion_sequence',1)")
        db.execute(
            "INSERT INTO objects(object_id,kind,plaintext_size,commitment,envelope_digest,"
            "encryption_format,key_slot,state,durable_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (
                _OBJECT_ID,
                "captured_content",
                32,
                _CONTENT,
                "sha256:" + "e" * 64,
                "yoetz-object/1",
                "slot-1",
                "present",
                _TIME,
            ),
        )
        db.execute(
            "INSERT INTO observation_consent(workspace_commitment,granted_at,revoked_at,paused,"
            "content_capture_profiles_json) VALUES(?,?,NULL,0,?)",
            (_WORKSPACE, _TIME, '["claude-code-ordinary-observation-v1"]'),
        )
        db.execute(
            "INSERT INTO observation_cursors(workspace_commitment,source,session_commitment,"
            "generation,byte_pos,event_pos,last_source_commitment,mapping_version) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (
                _WORKSPACE,
                "claude_hook",
                _SESSION,
                1,
                18,
                1,
                _SOURCE,
                "claude-code-hooks-ordinary-v2",
            ),
        )
        db.execute(
            "INSERT INTO observation_events(workspace_commitment,session_commitment,source,"
            "event_kind,structural_json,content_refs_json,gap_codes_json,receipt_time,"
            "source_generation,byte_position,event_position,last_source_commitment,mapping_version) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                _WORKSPACE,
                _SESSION,
                "claude_hook",
                "PostToolUse",
                b'{"tool_name":"Bash","result_status":"unknown"}',
                (f'["{_OBJECT_ID}"]').encode("ascii"),
                b'["host_outcome_unavailable"]',
                _TIME,
                1,
                18,
                1,
                _SOURCE,
                "claude-code-hooks-ordinary-v2",
            ),
        )
        db.execute(
            "INSERT INTO observation_content_manifests("
            "object_id,workspace_commitment,logical_identity,content_kind,correlation_identity,"
            "source_commitment,media_type,part_index,part_count,plaintext_size,content_commitment,"
            "redacted,recorded_at,content_digest,content_bytes) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                _OBJECT_ID,
                _WORKSPACE,
                "sha256:" + "f" * 64,
                "tool_output",
                "call-1101",
                _SOURCE,
                "text/plain",
                0,
                1,
                32,
                _CONTENT,
                0,
                _TIME,
                "sha256:" + "1" * 64,
                31,
            ),
        )
    assert db.execute("PRAGMA user_version").fetchone() == (10,)
    assert verify_schema_identity(db).state == "migration_required"
    return db


def _legacy_development_schema_ten() -> apsw.Connection:
    """Build the short-lived 0.3 v10 shape whose frontier collides with released v0.2."""

    db = apsw.Connection(":memory:")
    db.execute("PRAGMA foreign_keys = OFF")
    db.execute("PRAGMA trusted_schema = OFF")
    with db:
        for migration in BUNDLE_MIGRATIONS[:9]:
            db.execute(migration.ddl.decode())
        # The historical branch rebuilt events as its 0010 and admitted lineage summaries,
        # but never added the released v0.2 native-content consent column.  Keep only the
        # schema evidence needed by the fail-closed upgrade guard; no user rows are fabricated.
        db.execute("DROP TABLE events")
        db.execute(
            "CREATE TABLE events(summary_code TEXT NOT NULL "
            "CHECK(summary_code IN ('delegation_declared'))) STRICT"
        )
        db.execute(
            "INSERT INTO bundle_meta(key,value) VALUES"
            "('task_id',?),('owner_generation','1'),"
            "('storage_schema_version','10'),('protocol_version','0.1'),"
            "('import_schema_version','1')",
            (_TASK_ID,),
        )
        db.execute("PRAGMA user_version = 10")
    db.execute("PRAGMA foreign_keys = ON")
    return db


def test_schema_ten_upgrade_preserves_rows_and_installs_capture_ticket_shape() -> None:
    db = _schema_ten_with_observation_rows()
    old_consent = db.execute(
        "SELECT workspace_commitment,granted_at,revoked_at,paused,content_capture_profiles_json "
        "FROM observation_consent"
    ).fetchall()
    old_cursor = db.execute(
        "SELECT workspace_commitment,source,session_commitment,generation,byte_pos,event_pos,"
        "last_source_commitment,mapping_version FROM observation_cursors"
    ).fetchall()
    old_event = db.execute(
        "SELECT id,workspace_commitment,session_commitment,source,event_kind,structural_json,"
        "content_refs_json,gap_codes_json,receipt_time,source_generation,byte_position,event_position,"
        "last_source_commitment,mapping_version FROM observation_events"
    ).fetchall()
    old_content = db.execute(
        "SELECT object_id,workspace_commitment,logical_identity,content_kind,correlation_identity,"
        "source_commitment,media_type,part_index,part_count,plaintext_size,content_commitment,"
        "redacted,recorded_at,content_digest,content_bytes FROM observation_content_manifests"
    ).fetchall()

    assert (
        db.execute(
            "SELECT 1 FROM sqlite_schema WHERE name='observation_capture_tickets'"
        ).fetchone()
        is None
    )

    report = run_migrations(db, BUNDLE_MIGRATIONS, maintenance=None)  # type: ignore[arg-type]
    assert report.from_version == 10
    current = current_schema_version(BUNDLE_MIGRATIONS)
    assert report.to_version == current
    assert report.applied_versions == ("0011", "0012", "0013", "0014", "0015", "0016")
    assert db.execute("PRAGMA user_version").fetchone() == (current,)
    assert verify_schema_identity(db).state == "current"
    assert db.execute(
        "SELECT value FROM bundle_meta WHERE key='storage_schema_version'"
    ).fetchone() == (str(current),)
    assert db.execute("PRAGMA foreign_key_check").fetchall() == []

    assert (
        db.execute(
            "SELECT workspace_commitment,granted_at,revoked_at,paused,content_capture_profiles_json "
            "FROM observation_consent"
        ).fetchall()
        == old_consent
    )
    assert (
        db.execute(
            "SELECT workspace_commitment,source,session_commitment,generation,byte_pos,event_pos,"
            "last_source_commitment,mapping_version FROM observation_cursors"
        ).fetchall()
        == old_cursor
    )
    assert (
        db.execute(
            "SELECT id,workspace_commitment,session_commitment,source,event_kind,structural_json,"
            "content_refs_json,gap_codes_json,receipt_time,source_generation,byte_position,event_position,"
            "last_source_commitment,mapping_version FROM observation_events"
        ).fetchall()
        == old_event
    )
    assert (
        db.execute(
            "SELECT object_id,workspace_commitment,logical_identity,content_kind,correlation_identity,"
            "source_commitment,media_type,part_index,part_count,plaintext_size,content_commitment,"
            "redacted,recorded_at,content_digest,content_bytes FROM observation_content_manifests"
        ).fetchall()
        == old_content
    )

    columns = tuple(row[1] for row in db.execute("PRAGMA table_info(observation_capture_tickets)"))
    assert columns == (
        "ticket_id",
        "workspace_commitment",
        "task_id",
        "yoetz_session_id",
        "session_commitment",
        "source",
        "source_identity",
        "source_generation",
        "byte_position",
        "event_position",
        "last_source_commitment",
        "mapping_version",
        "logical_identity",
        "content_capture_profile",
        "authority_generation",
        "expected_parts_json",
        "object_ids_json",
        "captured_at",
        "state",
    )
    assert db.execute(
        "SELECT strict,wr FROM pragma_table_list WHERE name='observation_capture_tickets'"
    ).fetchone() == (1, 0)
    assert db.execute(
        "SELECT name FROM sqlite_schema WHERE type='index' "
        "AND name='observation_capture_tickets_by_workspace'"
    ).fetchone() == ("observation_capture_tickets_by_workspace",)

    ticket_id = "sha256:" + "2" * 64
    logical_identity = "sha256:" + "3" * 64
    db.execute(
        "INSERT INTO observation_capture_tickets("
        "ticket_id,workspace_commitment,task_id,yoetz_session_id,session_commitment,source,"
        "source_identity,source_generation,byte_position,event_position,last_source_commitment,"
        "mapping_version,logical_identity,content_capture_profile,authority_generation,"
        "expected_parts_json,object_ids_json,captured_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            ticket_id,
            _WORKSPACE,
            _TASK_ID,
            _YOETZ_SESSION_ID,
            _SESSION,
            "claude_hook",
            "hook:claude:1101",
            1,
            18,
            1,
            _SOURCE,
            "claude-code-hooks-ordinary-v2",
            logical_identity,
            "claude-code-ordinary-observation-v1",
            "sha256:" + "4" * 64,
            canonical_encode((("tool_output", "call-1101", _SOURCE, 0, 1),)),
            b"[]",
            _TIME,
        ),
    )
    assert db.execute(
        "SELECT state,object_ids_json FROM observation_capture_tickets WHERE ticket_id=?",
        (ticket_id,),
    ).fetchone() == ("staging", b"[]")

    rerun = run_migrations(db, BUNDLE_MIGRATIONS, maintenance=None)  # type: ignore[arg-type]
    assert rerun.from_version == current
    assert rerun.to_version == current
    assert rerun.applied_versions == ()
    assert db.execute("SELECT count(*) FROM observation_capture_tickets").fetchone() == (1,)


def test_legacy_development_v10_fails_closed_before_running_released_migrations() -> None:
    db = _legacy_development_schema_ten()
    assert db.execute("PRAGMA user_version").fetchone() == (10,)
    assert tuple(row[1] for row in db.execute("PRAGMA table_info(observation_consent)")) == (
        "workspace_commitment",
        "granted_at",
        "revoked_at",
        "paused",
    )
    event_row = db.execute(
        "SELECT sql FROM sqlite_schema WHERE type='table' AND name='events'"
    ).fetchone()
    assert event_row is not None
    assert "delegation_declared" in event_row[0]

    try:
        run_migrations(db, BUNDLE_MIGRATIONS, maintenance=None)  # type: ignore[arg-type]
        raise AssertionError("expected ambiguous v10 schema to fail closed")
    except RuntimeError as exc:
        assert str(exc) == "schema_upgrade_path_unknown"

    assert db.execute("PRAGMA user_version").fetchone() == (10,)
    assert (
        db.execute(
            "SELECT 1 FROM sqlite_schema WHERE name='observation_capture_tickets'"
        ).fetchone()
        is None
    )
    assert db.execute(
        "SELECT value FROM bundle_meta WHERE key='storage_schema_version'"
    ).fetchone() == ("10",)
