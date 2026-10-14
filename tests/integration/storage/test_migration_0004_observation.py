"""Migration 0004 inspection snapshots, session routes, and session advice."""

from __future__ import annotations

from pathlib import Path

import apsw

from yoetz.adapters.sqlite.migrations import (
    BUNDLE_MIGRATIONS,
    Migration,
    current_schema_version,
    run_migrations,
)


def _schema_three(path: Path) -> apsw.Connection:
    db = apsw.Connection(str(path))
    db.execute("PRAGMA foreign_keys = ON")
    db.execute("PRAGMA trusted_schema = OFF")
    with db:
        for migration in BUNDLE_MIGRATIONS[:3]:
            db.execute(migration.ddl.decode())
        db.execute(
            "INSERT INTO bundle_meta(key,value) VALUES"
            "('task_id','task_upgrade'),('owner_generation','1'),"
            "('storage_schema_version','3'),('protocol_version','0.1'),"
            "('import_schema_version','1')"
        )
        db.execute("INSERT INTO counters(name,next_value) VALUES('ingestion_sequence',1)")
    return db


def test_schema_three_upgrade_applies_0004_tables(tmp_path: Path) -> None:
    source = tmp_path / "bundle.sqlite3"
    db = _schema_three(source)
    assert db.execute("PRAGMA user_version").fetchone() == (3,)
    report = run_migrations(db, BUNDLE_MIGRATIONS, maintenance=None)  # type: ignore[arg-type]
    assert report.applied_versions == (
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
    current = current_schema_version(BUNDLE_MIGRATIONS)
    assert db.execute("PRAGMA user_version").fetchone() == (current,)
    assert db.execute(
        "SELECT value FROM bundle_meta WHERE key='storage_schema_version'"
    ).fetchone() == (str(current),)
    db.close()

    reopened = apsw.Connection(str(source))
    assert reopened.execute("PRAGMA user_version").fetchone() == (current,)
    assert reopened.execute("PRAGMA integrity_check").fetchone() == ("ok",)
    reopened.close()


def test_failed_followup_migration_after_0004_rolls_back(tmp_path: Path) -> None:
    db = _schema_three(tmp_path / "rollback.sqlite3")
    run_migrations(db, BUNDLE_MIGRATIONS, maintenance=None)  # type: ignore[arg-type]
    assert db.execute("PRAGMA user_version").fetchone() == (
        current_schema_version(BUNDLE_MIGRATIONS),
    )
    # The synthetic follow-up must be the version *after* the real registry, so adding a
    # genuine migration does not turn this into a duplicate-version registry error.
    next_version = current_schema_version(BUNDLE_MIGRATIONS) + 1
    failing = Migration(
        f"{next_version:04d}",
        b"CREATE TABLE must_rollback(value TEXT) STRICT;\n"
        b"INSERT INTO table_that_does_not_exist(value) VALUES('x');\n"
        + f"PRAGMA user_version = {next_version};\n".encode("ascii"),
    )
    try:
        run_migrations(db, (*BUNDLE_MIGRATIONS, failing), maintenance=None)  # type: ignore[arg-type]
        raise AssertionError("expected failing migration")
    except apsw.SQLError:
        pass
    assert db.execute("PRAGMA user_version").fetchone() == (
        current_schema_version(BUNDLE_MIGRATIONS),
    )
    assert db.execute("SELECT 1 FROM sqlite_schema WHERE name='must_rollback'").fetchone() is None
