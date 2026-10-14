"""Migration 0015 structural semantic-progress table (issue #571 item A2)."""

from __future__ import annotations

import apsw
import pytest

from yoetz.adapters.sqlite.connection import verify_schema_identity
from yoetz.adapters.sqlite.migrations import (
    BUNDLE_MIGRATIONS,
    current_schema_version,
    run_migrations,
)

_TASK_ID = "tsk_00000000-0000-4000-8000-000000001501"


def _schema_fourteen() -> apsw.Connection:
    db = apsw.Connection(":memory:")
    db.execute("PRAGMA foreign_keys = ON")
    db.execute("PRAGMA trusted_schema = OFF")
    with db:
        for migration in BUNDLE_MIGRATIONS[:14]:
            db.execute(migration.ddl.decode())
        db.execute(
            "INSERT INTO bundle_meta(key,value) VALUES"
            "('task_id',?),('owner_generation','1'),"
            "('storage_schema_version','14'),('protocol_version','0.1'),"
            "('import_schema_version','1')",
            (_TASK_ID,),
        )
        db.execute("INSERT INTO counters(name,next_value) VALUES('ingestion_sequence',1)")
    return db


def test_schema_fourteen_upgrade_adds_only_an_empty_progress_table() -> None:
    db = _schema_fourteen()
    before = {
        row[0]
        for row in db.execute(
            "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
    }
    assert "semantic_progress" not in before

    report = run_migrations(db, BUNDLE_MIGRATIONS, maintenance=None)  # type: ignore[arg-type]

    current = current_schema_version(BUNDLE_MIGRATIONS)
    assert (report.from_version, report.to_version) == (14, current)
    assert report.applied_versions == ("0015", "0016")
    assert db.execute("PRAGMA user_version").fetchone() == (current,)
    assert db.execute(
        "SELECT value FROM bundle_meta WHERE key='storage_schema_version'"
    ).fetchone() == (str(current),)
    assert verify_schema_identity(db).state == "current"
    after = {
        row[0]
        for row in db.execute(
            "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
    }
    assert after - before == {"semantic_progress"}
    assert db.execute("SELECT COUNT(*) FROM semantic_progress").fetchone() == (0,)
    columns = [row[1] for row in db.execute("PRAGMA table_info(semantic_progress)")]
    # Closed structure only: no provider text, token, account, or path column exists.
    assert columns == [
        "job_id",
        "attempt_ordinal",
        "phase",
        "phase_rank",
        "phase_entered_at",
        "queued_at",
        "deadline_at",
    ]
    rerun = run_migrations(db, BUNDLE_MIGRATIONS, maintenance=None)  # type: ignore[arg-type]
    assert rerun.applied_versions == ()


@pytest.mark.parametrize(
    ("ordinal", "phase", "rank"),
    (
        (1, "terminal", 8),
        (1, "provider_sampling", 1),
        (0, "provider_sampling", 5),
        (-1, "queued", 1),
    ),
)
def test_progress_rows_reject_terminal_mismatched_rank_and_unclaimed_phases(
    ordinal: int, phase: str, rank: int
) -> None:
    db = _schema_fourteen()
    run_migrations(db, BUNDLE_MIGRATIONS, maintenance=None)  # type: ignore[arg-type]
    # Isolate the table CHECKs from the job foreign key; the valid control row proves it.
    db.execute("PRAGMA foreign_keys = OFF")
    insert = (
        "INSERT INTO semantic_progress(job_id,attempt_ordinal,phase,phase_rank,"
        "phase_entered_at,queued_at,deadline_at) VALUES(?,?,?,?,?,?,?)"
    )
    times = ("2026-09-22T12:00:00.000Z", "2026-09-22T12:00:00.000Z", "2026-09-22T12:15:00.000Z")
    db.execute(insert, ("job_00000000-0000-4000-8000-000000001500", 1, "cleanup", 7, *times))
    with pytest.raises(apsw.ConstraintError):
        db.execute(
            insert, ("job_00000000-0000-4000-8000-000000001501", ordinal, phase, rank, *times)
        )
