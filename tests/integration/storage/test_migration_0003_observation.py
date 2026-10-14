"""Migration 0003 encrypted-observation authority, restart, and rollback."""

from __future__ import annotations

from pathlib import Path

import apsw
import pytest

from yoetz.adapters.sqlite.migrations import (
    BUNDLE_MIGRATIONS,
    Migration,
    current_schema_version,
    run_migrations,
)


def _schema_two(path: Path) -> apsw.Connection:
    db = apsw.Connection(str(path))
    db.execute("PRAGMA foreign_keys = ON")
    db.execute("PRAGMA trusted_schema = OFF")
    with db:
        for migration in BUNDLE_MIGRATIONS[:2]:
            db.execute(migration.ddl.decode())
        db.execute(
            "INSERT INTO bundle_meta(key,value) VALUES"
            "('task_id','task_upgrade'),('owner_generation','1'),"
            "('storage_schema_version','2'),('protocol_version','0.1'),"
            "('import_schema_version','1')"
        )
        db.execute("INSERT INTO counters(name,next_value) VALUES('ingestion_sequence',1)")
    return db


def test_schema_two_upgrade_survives_restart_and_file_copy_restore(tmp_path: Path) -> None:
    source = tmp_path / "bundle.sqlite3"
    db = _schema_two(source)
    assert db.execute("PRAGMA user_version").fetchone() == (2,)
    report = run_migrations(db, BUNDLE_MIGRATIONS, maintenance=None)  # type: ignore[arg-type]
    assert report.applied_versions == (
        "0003",
        "0004",
        "0005",
        "0006",
        "0007",
        "0008",
        "0009",
        "0010",
        "0011",
        "0012",
        "0013",
        "0014",
        "0015",
        "0016",
    )
    expected = {
        "observation_workspace_bindings",
        "observation_content_manifests",
        "observation_logical_identity",
        "observation_trusted_check_policies",
        "observation_verification_jobs",
        "observation_verification_results",
        "observation_advice_history",
        "observation_advice_delivery",
        "observation_inspection_snapshots",
        "observation_workspace_session_routes",
        "observation_session_advice",
    }
    actual = {
        str(row[0])
        for row in db.execute(
            "SELECT name FROM sqlite_schema WHERE type='table' AND name LIKE 'observation_%'"
        )
    }
    assert expected <= actual
    db.close()

    current = current_schema_version(BUNDLE_MIGRATIONS)
    reopened = apsw.Connection(str(source))
    assert reopened.execute("PRAGMA user_version").fetchone() == (current,)
    assert reopened.execute(
        "SELECT value FROM bundle_meta WHERE key='storage_schema_version'"
    ).fetchone() == (str(current),)
    reopened.close()

    restored_path = tmp_path / "restored.sqlite3"
    restored_path.write_bytes(source.read_bytes())
    restored = apsw.Connection(str(restored_path))
    assert restored.execute("PRAGMA integrity_check").fetchone() == ("ok",)
    assert restored.execute("PRAGMA user_version").fetchone() == (current,)


def test_failed_followup_migration_rolls_back_atomically(tmp_path: Path) -> None:
    db = _schema_two(tmp_path / "rollback.sqlite3")
    # Apply through 0003 only so a failing 0004 candidate can prove atomic rollback.
    run_migrations(db, BUNDLE_MIGRATIONS[:3], maintenance=None)  # type: ignore[arg-type]
    failing = Migration(
        "0004",
        b"CREATE TABLE must_rollback(value TEXT) STRICT;\n"
        b"INSERT INTO table_that_does_not_exist(value) VALUES('x');\n"
        b"PRAGMA user_version = 4;\n",
    )
    with pytest.raises(apsw.SQLError):
        run_migrations(db, (*BUNDLE_MIGRATIONS[:3], failing), maintenance=None)  # type: ignore[arg-type]
    assert db.execute("PRAGMA user_version").fetchone() == (3,)
    assert db.execute("SELECT 1 FROM sqlite_schema WHERE name='must_rollback'").fetchone() is None
