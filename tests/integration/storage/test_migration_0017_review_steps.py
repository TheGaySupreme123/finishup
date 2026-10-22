"""Migration 0017 durable reviewer-loop steps (#1118 unit 2, ADR-003)."""

from __future__ import annotations

import apsw
import pytest

from finishup.adapters.sqlite.connection import verify_schema_identity
from finishup.adapters.sqlite.migrations import BUNDLE_MIGRATIONS, run_migrations

_TASK_ID = "tsk_00000000-0000-4000-8000-000000001701"
_JOB = "job_00000000-0000-4000-8000-000000001700"


def _schema_sixteen() -> apsw.Connection:
    db = apsw.Connection(":memory:")
    db.execute("PRAGMA foreign_keys = ON")
    db.execute("PRAGMA trusted_schema = OFF")
    with db:
        for migration in BUNDLE_MIGRATIONS[:16]:
            db.execute(migration.ddl.decode())
        db.execute(
            "INSERT INTO bundle_meta(key,value) VALUES"
            "('task_id',?),('owner_generation','1'),"
            "('storage_schema_version','16'),('protocol_version','0.1'),"
            "('import_schema_version','1')",
            (_TASK_ID,),
        )
        db.execute("INSERT INTO counters(name,next_value) VALUES('ingestion_sequence',1)")
    return db


def _tables(db: apsw.Connection) -> set[str]:
    query = "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'"
    return {row[0] for row in db.execute(query)}


def test_schema_sixteen_upgrade_adds_only_an_empty_structural_step_table() -> None:
    db = _schema_sixteen()
    before = _tables(db)
    report = run_migrations(db, BUNDLE_MIGRATIONS[:17], maintenance=None)  # type: ignore[arg-type]
    assert (report.from_version, report.to_version, report.applied_versions) == (16, 17, ("0017",))
    assert verify_schema_identity(db).state == "migration_required"
    assert _tables(db) - before == {"semantic_review_steps"}
    columns = [row[1] for row in db.execute("PRAGMA table_info(semantic_review_steps)")]
    # Keyed commitments and counts only: no path, argument, prompt, model text or result column.
    assert columns == [
        "job_id",
        "kind",
        "ordinal",
        "selector_commitment",
        "capture_commitment",
        "capture_bytes",
    ]
    assert run_migrations(db, BUNDLE_MIGRATIONS[:17], maintenance=None).applied_versions == ()  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("kind", "ordinal", "capture", "size"),
    (
        ("turn", 6, None, None),
        ("repair", 2, None, None),
        ("read", 4, None, None),
        ("read", 0, None, None),
        ("shell", 1, None, None),
        ("read", 1, "c", None),
    ),
)
def test_step_rows_enforce_the_review_limits(
    kind: str, ordinal: int, capture: str | None, size: int | None
) -> None:
    db = _schema_sixteen()
    run_migrations(db, BUNDLE_MIGRATIONS[:17], maintenance=None)  # type: ignore[arg-type]
    db.execute("PRAGMA foreign_keys = OFF")  # isolate the CHECKs; the control row proves it
    insert = (
        "INSERT INTO semantic_review_steps(job_id,kind,ordinal,selector_commitment,"
        "capture_commitment,capture_bytes) VALUES(?,?,?,?,?,?)"
    )
    db.execute(insert, (_JOB, "turn", 5, "k", "c", 0))
    with pytest.raises(apsw.ConstraintError):
        db.execute(insert, (_JOB, kind, ordinal, "k", capture, size))
