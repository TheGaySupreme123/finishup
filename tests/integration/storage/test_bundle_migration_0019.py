"""Bundle migration 0019 (#1239): ``events`` admits the declared quiet-period family.

0019 rebuilds ``events`` exactly as 0014 did, widening only the ``summary_code`` CHECK. Row
preservation across the rebuild is exercised with real ledger rows by the ledger-port upgrade
test; this pins the shape.
"""

from __future__ import annotations

import re

import apsw

from finishup.adapters.sqlite.migrations import BUNDLE_MIGRATIONS, run_migrations


def _events_shape(db: apsw.Connection) -> tuple[object, ...]:
    columns = tuple(db.execute("PRAGMA table_info(events)").fetchall())
    indexes = tuple(
        sorted(
            (row[0], row[1])
            for row in db.execute(
                "SELECT name, sql FROM sqlite_schema WHERE type = 'index' AND tbl_name = 'events' "
                "AND sql IS NOT NULL"
            )
        )
    )
    return columns, indexes


def _summary_codes(db: apsw.Connection) -> set[str]:
    row = db.execute(
        "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'events'"
    ).fetchone()
    assert row is not None
    sql = str(row[0])
    block = sql[sql.index("summary_code IN (") : sql.index("))", sql.index("summary_code IN ("))]
    return set(re.findall(r"'([a-z_]+)'", block))


def test_0019_widens_only_the_summary_check() -> None:
    db = apsw.Connection(":memory:")
    db.execute("PRAGMA foreign_keys = ON")
    db.execute("PRAGMA trusted_schema = OFF")
    try:
        with db:
            db.execute(BUNDLE_MIGRATIONS[0].ddl.decode("utf-8"))
            db.execute(
                "INSERT INTO bundle_meta(key, value) VALUES "
                "('task_id', 'task_test'), ('owner_generation', '1'), "
                "('storage_schema_version', '1'), ('protocol_version', '0.1'), "
                "('import_schema_version', '1')"
            )
            db.execute("INSERT INTO counters(name, next_value) VALUES ('ingestion_sequence', 1)")
        run_migrations(db, BUNDLE_MIGRATIONS[:18], maintenance=None)  # type: ignore[arg-type]
        assert db.pragma("user_version") == 18
        before_shape, before_codes = _events_shape(db), _summary_codes(db)
        assert "contact_expectation_declared" not in before_codes
        report = run_migrations(db, BUNDLE_MIGRATIONS, maintenance=None)  # type: ignore[arg-type]
        assert (report.from_version, report.to_version, report.applied_versions) == (
            18,
            19,
            ("0019",),
        )
        assert _events_shape(db) == before_shape
        assert _summary_codes(db) == before_codes | {"contact_expectation_declared"}
        assert db.execute("PRAGMA foreign_key_check").fetchone() is None
        assert db.execute("PRAGMA integrity_check").fetchone() == ("ok",)
    finally:
        db.close(force=True)
