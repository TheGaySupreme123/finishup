"""Populated 0015 -> 0016 upgrades preserve review state and remain retryable."""

from __future__ import annotations

import apsw
import pytest

from yoetz.adapters.sqlite.migrations import (
    BUNDLE_MIGRATIONS,
    Migration,
    run_migrations,
)

_WRITER_ID = "writer-migration-0016"
_TASK_ID = "task-migration-0016"
_SESSION_ID = "session-migration-0016"
_PENDING_OPERATION_ID = "operation-pending-0016"
_COMPLETE_OPERATION_ID = "operation-complete-0016"
_JOB_ID = "semantic-job-0016"
_ATTEMPT_ID = "semantic-attempt-0016"
_CREATED_AT = "2026-10-03T12:00:00.000Z"
_UPDATED_AT = "2026-10-03T12:01:00.000Z"
_TERMINAL_AT = "2026-10-03T12:02:00.000Z"
_LEASE_EXPIRES_AT = "2026-10-03T12:15:00.000Z"
_DIGEST = "sha256:" + "1" * 64


def _schema_fifteen_with_durable_rows() -> apsw.Connection:
    """Build a valid, populated v15 bundle without using the live store."""

    db = apsw.Connection(":memory:")
    db.execute("PRAGMA foreign_keys = ON")
    db.execute("PRAGMA trusted_schema = OFF")
    with db:
        for migration in BUNDLE_MIGRATIONS[:15]:
            db.execute(migration.ddl.decode("utf-8"))
        db.execute(
            "INSERT INTO bundle_meta(key,value) VALUES"
            "('task_id',?),('owner_generation','1'),"
            "('storage_schema_version','15'),('protocol_version','0.1'),"
            "('import_schema_version','1')",
            (_TASK_ID,),
        )
        db.execute("INSERT INTO counters(name,next_value) VALUES('ingestion_sequence',1)")
        db.execute(
            "INSERT INTO writers(writer_id,task_id,session_id,next_writer_seq,"
            "head_entry_digest,state,created_at) VALUES(?,?,?,?,?,?,?)",
            (_WRITER_ID, _TASK_ID, _SESSION_ID, 8, "head-before-0016", "active", _CREATED_AT),
        )
        db.executemany(
            "INSERT INTO objects(object_id,kind,plaintext_size,commitment,envelope_digest,"
            "encryption_format,key_slot,state,durable_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (
                (
                    "resume-object-0016",
                    "check_resume",
                    5,
                    "resume-commitment",
                    "resume-envelope",
                    "v1",
                    "slot",
                    "present",
                    _CREATED_AT,
                ),
                (
                    "case-object-0016",
                    "semantic_case",
                    11,
                    "case-commitment",
                    "case-envelope",
                    "v1",
                    "slot",
                    "present",
                    _CREATED_AT,
                ),
                (
                    "attempt-result-0016",
                    "semantic_result",
                    13,
                    "attempt-commitment",
                    "attempt-envelope",
                    "v1",
                    "slot",
                    "present",
                    _UPDATED_AT,
                ),
                (
                    "operation-result-0016",
                    "check_result",
                    12,
                    "result-commitment",
                    "result-envelope",
                    "v1",
                    "slot",
                    "present",
                    _UPDATED_AT,
                ),
            ),
        )

        operation_columns = (
            "writer_id,operation_id,operation_kind,request_digest,resume_object_id,"
            "state,phase,owner_generation,lease_owner_id,lease_generation,lease_expires_at,"
            "first_ingestion_seq,last_ingestion_seq,result_canonical,result_digest,"
            "result_object_id,quarantine_code,terminal_at,created_at,updated_at,suspension_kind"
        )
        operation_insert = f"INSERT INTO operations({operation_columns}) VALUES ({','.join('?' for _ in range(21))})"
        db.execute(
            operation_insert,
            (
                _WRITER_ID,
                _PENDING_OPERATION_ID,
                "check",
                _DIGEST,
                "resume-object-0016",
                "pending",
                "semantic_wait",
                "owner-generation-0016",
                "lease-owner-0016",
                3,
                _LEASE_EXPIRES_AT,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                _CREATED_AT,
                _UPDATED_AT,
                None,
            ),
        )
        db.execute(
            operation_insert,
            (
                _WRITER_ID,
                _COMPLETE_OPERATION_ID,
                "check",
                "sha256:" + "2" * 64,
                None,
                "complete",
                "terminal",
                None,
                None,
                None,
                None,
                7,
                7,
                b'{"ok":true}',
                "sha256:" + "3" * 64,
                "operation-result-0016",
                None,
                _TERMINAL_AT,
                _CREATED_AT,
                _UPDATED_AT,
                None,
            ),
        )

        db.execute(
            "INSERT INTO semantic_jobs(job_id,writer_id,operation_id,case_digest,case_object_id,"
            "state,active_attempt_id,selected_attempt_id,attempt_count,owner_generation,"
            "lease_owner_id,lease_generation,lease_expires_at,selected_result_object_id,"
            "terminal_code,terminal_at,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                _JOB_ID,
                _WRITER_ID,
                _PENDING_OPERATION_ID,
                "sha256:" + "4" * 64,
                "case-object-0016",
                "queued",
                None,
                None,
                0,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                _CREATED_AT,
                _UPDATED_AT,
            ),
        )
        db.execute(
            "INSERT INTO semantic_attempts(attempt_id,job_id,attempt_ordinal,provider_request_id,"
            "owner_generation,lease_owner_id,lease_generation,state,result_object_id,terminal_code,"
            "started_at,terminal_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                _ATTEMPT_ID,
                _JOB_ID,
                1,
                "provider-request-0016",
                "owner-generation-0016",
                "lease-owner-0016",
                3,
                "selected",
                "attempt-result-0016",
                "semantic_completed",
                _CREATED_AT,
                _TERMINAL_AT,
            ),
        )
        db.execute(
            "UPDATE semantic_jobs SET state='succeeded', selected_attempt_id=?, attempt_count=1,"
            "selected_result_object_id=?, terminal_code='semantic_completed', terminal_at=?, updated_at=? "
            "WHERE job_id=?",
            (_ATTEMPT_ID, "attempt-result-0016", _TERMINAL_AT, _UPDATED_AT, _JOB_ID),
        )
        db.execute(
            "INSERT INTO semantic_progress(job_id,attempt_ordinal,phase,phase_rank,"
            "phase_entered_at,queued_at,deadline_at) VALUES(?,?,?,?,?,?,?)",
            (
                _JOB_ID,
                1,
                "provider_sampling",
                5,
                _UPDATED_AT,
                _CREATED_AT,
                _LEASE_EXPIRES_AT,
            ),
        )
    return db


def _durable_rows(db: apsw.Connection) -> dict[str, tuple[tuple[object, ...], ...]]:
    return {
        "objects": tuple(
            db.execute(
                "SELECT object_id,kind,plaintext_size,commitment,envelope_digest,"
                "encryption_format,key_slot,state,durable_at FROM objects ORDER BY object_id"
            ).fetchall()
        ),
        "operations": tuple(
            db.execute(
                "SELECT writer_id,operation_id,operation_kind,request_digest,resume_object_id,"
                "state,phase,owner_generation,lease_owner_id,lease_generation,lease_expires_at,"
                "first_ingestion_seq,last_ingestion_seq,result_canonical,result_digest,"
                "result_object_id,quarantine_code,terminal_at,created_at,updated_at,suspension_kind "
                "FROM operations ORDER BY operation_id"
            ).fetchall()
        ),
        "semantic_jobs": tuple(
            db.execute(
                "SELECT job_id,writer_id,operation_id,case_digest,case_object_id,state,"
                "active_attempt_id,selected_attempt_id,attempt_count,owner_generation,"
                "lease_owner_id,lease_generation,lease_expires_at,selected_result_object_id,"
                "terminal_code,terminal_at,created_at,updated_at FROM semantic_jobs"
            ).fetchall()
        ),
        "semantic_attempts": tuple(
            db.execute(
                "SELECT attempt_id,job_id,attempt_ordinal,provider_request_id,owner_generation,"
                "lease_owner_id,lease_generation,state,result_object_id,terminal_code,started_at,"
                "terminal_at FROM semantic_attempts"
            ).fetchall()
        ),
        "semantic_progress": tuple(
            db.execute(
                "SELECT job_id,attempt_ordinal,phase,phase_rank,phase_entered_at,queued_at,"
                "deadline_at FROM semantic_progress"
            ).fetchall()
        ),
    }


def test_populated_v15_upgrade_preserves_operations_and_semantic_dependencies() -> None:
    db = _schema_fifteen_with_durable_rows()
    before = _durable_rows(db)

    report = run_migrations(db, BUNDLE_MIGRATIONS, maintenance=None)  # type: ignore[arg-type]

    assert (report.from_version, report.to_version) == (15, 16)
    assert report.applied_versions == ("0016",)
    assert db.execute("PRAGMA user_version").fetchone() == (16,)
    assert db.execute(
        "SELECT value FROM bundle_meta WHERE key='storage_schema_version'"
    ).fetchone() == ("16",)
    assert _durable_rows(db) == before
    assert db.execute("PRAGMA foreign_keys").fetchone() == (1,)
    assert db.execute("PRAGMA legacy_alter_table").fetchone() == (0,)
    assert db.execute("PRAGMA foreign_key_check").fetchone() is None
    semantic_job_foreign_keys = {
        (row[2], row[3], row[4]) for row in db.execute("PRAGMA foreign_key_list(semantic_jobs)")
    }
    assert {
        ("operations", "writer_id", "writer_id"),
        ("operations", "operation_id", "operation_id"),
        ("semantic_attempts", "job_id", "job_id"),
        ("semantic_attempts", "active_attempt_id", "attempt_id"),
        ("semantic_attempts", "selected_attempt_id", "attempt_id"),
    } <= semantic_job_foreign_keys

    operation_columns = {row[1] for row in db.execute("PRAGMA table_info(operations)")}
    assert "suspension_kind" in operation_columns
    db.execute(
        "UPDATE operations SET suspension_kind='review_input' WHERE writer_id=? AND operation_id=?",
        (_WRITER_ID, _PENDING_OPERATION_ID),
    )
    assert db.execute(
        "SELECT suspension_kind FROM operations WHERE writer_id=? AND operation_id=?",
        (_WRITER_ID, _PENDING_OPERATION_ID),
    ).fetchone() == ("review_input",)

    after_marker = _durable_rows(db)
    rerun = run_migrations(db, BUNDLE_MIGRATIONS, maintenance=None)  # type: ignore[arg-type]
    assert rerun.applied_versions == ()
    assert _durable_rows(db) == after_marker
    assert db.execute("PRAGMA foreign_key_check").fetchone() is None


def test_failed_v15_to_v16_upgrade_rolls_back_and_allows_retry() -> None:
    db = _schema_fifteen_with_durable_rows()
    before = _durable_rows(db)
    failing = Migration(
        "0016",
        b"CREATE TABLE migration_0016_rollback_probe(value TEXT) STRICT;\n"
        b"INSERT INTO table_that_does_not_exist(value) VALUES('x');\n"
        b"PRAGMA user_version = 16;\n",
    )

    with pytest.raises(apsw.SQLError):
        run_migrations(
            db,
            (*BUNDLE_MIGRATIONS[:15], failing),
            maintenance=None,
        )  # type: ignore[arg-type]

    assert db.execute("PRAGMA user_version").fetchone() == (15,)
    assert db.execute(
        "SELECT value FROM bundle_meta WHERE key='storage_schema_version'"
    ).fetchone() == ("15",)
    assert (
        db.execute(
            "SELECT 1 FROM sqlite_schema WHERE name='migration_0016_rollback_probe'"
        ).fetchone()
        is None
    )
    assert _durable_rows(db) == before
    assert db.execute("PRAGMA foreign_keys").fetchone() == (1,)
    assert db.execute("PRAGMA legacy_alter_table").fetchone() == (0,)
    assert db.execute("PRAGMA foreign_key_check").fetchone() is None
    assert {
        (row[2], row[3], row[4]) for row in db.execute("PRAGMA foreign_key_list(semantic_jobs)")
    } >= {
        ("operations", "writer_id", "writer_id"),
        ("operations", "operation_id", "operation_id"),
    }

    retry = run_migrations(db, BUNDLE_MIGRATIONS, maintenance=None)  # type: ignore[arg-type]
    assert retry.applied_versions == ("0016",)
    assert _durable_rows(db) == before
    assert db.execute("PRAGMA foreign_key_check").fetchone() is None
