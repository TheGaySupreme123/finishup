"""Migration 0018 widens the reviewer step bounds on the real v17 chain (#1173, ADR-003).

Row preservation through a real leased job's step store is locked by
``tests/conformance/adapters/test_ledger_port.py::
test_reviewer_steps_upgrade_preserves_reservations_and_admits_bounded_corrections``.
"""

from __future__ import annotations

import re

import apsw
import pytest

from finishup.adapters.sqlite.connection import verify_schema_identity
from finishup.adapters.sqlite.migrations import BUNDLE_MIGRATIONS, run_migrations
from integration.storage.test_migration_0017_review_steps import (
    _schema_sixteen,  # pyright: ignore[reportPrivateUsage]
    _tables,  # pyright: ignore[reportPrivateUsage]
)

_JOB = "job_00000000-0000-4000-8000-000000001800"
_INSERT = (
    "INSERT INTO semantic_review_steps(job_id,kind,ordinal,selector_commitment,"
    "capture_commitment,capture_bytes) VALUES(?,?,?,?,?,?)"
)


def _schema_eighteen() -> apsw.Connection:
    db = _schema_sixteen()
    run_migrations(db, BUNDLE_MIGRATIONS[:17], maintenance=None)  # type: ignore[arg-type]
    report = run_migrations(db, BUNDLE_MIGRATIONS, maintenance=None)  # type: ignore[arg-type]
    assert (report.from_version, report.to_version, report.applied_versions) == (17, 18, ("0018",))
    db.execute("PRAGMA foreign_keys = OFF")  # isolate the CHECKs; the control rows prove it
    return db


def test_schema_seventeen_upgrade_widens_only_the_step_bounds() -> None:
    db = _schema_sixteen()
    run_migrations(db, BUNDLE_MIGRATIONS[:17], maintenance=None)  # type: ignore[arg-type]
    before = _tables(db), db.execute("PRAGMA table_info(semantic_review_steps)").fetchall()
    db.close()
    db = _schema_eighteen()
    assert verify_schema_identity(db).state == "current"
    after = _tables(db), db.execute("PRAGMA table_info(semantic_review_steps)").fetchall()
    assert after == before  # the same tables and the same commitment-only columns
    assert run_migrations(db, BUNDLE_MIGRATIONS, maintenance=None).applied_versions == ()  # type: ignore[arg-type]
    db.execute("PRAGMA foreign_keys = OFF")
    # Read 4-5 and turn 6-7 are the two extra attempts, the final judgment and one repair.
    for kind, ordinal in (("read", 4), ("read", 5), ("turn", 6), ("turn", 7), ("repair", 1)):
        db.execute(_INSERT, (_JOB, kind, ordinal, "k", "c", 0))


@pytest.mark.parametrize(
    ("kind", "ordinal", "capture", "size"),
    (
        ("read", 6, None, None),
        ("turn", 8, None, None),
        ("repair", 2, None, None),
        ("read", 0, None, None),
        ("shell", 1, None, None),
        ("read", 1, "c", None),
    ),
)
def test_v18_step_rows_still_enforce_the_review_limits(
    kind: str, ordinal: int, capture: str | None, size: int | None
) -> None:
    db = _schema_eighteen()
    db.execute(_INSERT, (_JOB, "turn", 7, "k", "c", 0))
    with pytest.raises(apsw.ConstraintError):
        db.execute(_INSERT, (_JOB, kind, ordinal, "k", capture, size))


def test_0018_drops_the_step_table_only_after_copying_every_row() -> None:
    # The one destructive statement is a reviewed rebuild: an unfiltered copy, then the drop,
    # then the rename (tests/packaging's DDL gate applies the same rule to the shipped file).
    migration = BUNDLE_MIGRATIONS[17]
    assert migration.version == "0018"
    ddl = re.sub(r"--[^\n]*", "", migration.ddl.decode()).upper()
    copy = "INSERT INTO SEMANTIC_REVIEW_STEPS_V18 SELECT * FROM SEMANTIC_REVIEW_STEPS;"
    drop = "DROP TABLE SEMANTIC_REVIEW_STEPS;"
    rename = "ALTER TABLE SEMANTIC_REVIEW_STEPS_V18 RENAME TO SEMANTIC_REVIEW_STEPS;"
    assert ddl.count(copy) == ddl.count(drop) == ddl.count(rename) == 1
    assert ddl.index(copy) < ddl.index(drop) < ddl.index(rename)
    rest = ddl.replace(drop, "", 1)
    for forbidden in (
        r"DROP\s+TABLE",
        r"DELETE\s+FROM",
        r"\bUPDATE\b",
        r"\bTRUNCATE\b",
        r"\bWHERE\b",
    ):
        assert re.search(forbidden, rest) is None, forbidden
