"""Catalog migration 0007 (#1239): the lineage row keeps a declared quiet period's end."""

from __future__ import annotations

from pathlib import Path

import apsw

from finishup.adapters.sqlite import migrations

_TASK = "tsk_70000000-0000-4000-8000-000000000007"
_SESSION = "ses_70000000-0000-4000-8000-000000000007"
_AT = "2026-10-30T12:00:00.000Z"


def test_an_upgraded_row_keeps_its_facts_and_reads_no_quiet_period(tmp_path: Path) -> None:
    db = apsw.Connection(str(tmp_path / "catalog.sqlite3"))
    try:
        for migration in migrations.CATALOG_MIGRATIONS[:6]:
            db.execute(migration.ddl.decode("utf-8"))
        db.execute("INSERT INTO catalog_meta VALUES ('storage_schema_version', '6')")
        db.execute(
            "INSERT INTO task_routes(task_id, active_session_id, bundle_relpath, "
            "route_generation, active_route_identity_digest, state, created_at, updated_at) "
            "VALUES (?, ?, ?, 1, ?, 'active', ?, ?)",
            (_TASK, _SESSION, f"tasks/{_TASK}", "sha256:" + "a" * 64, _AT, _AT),
        )
        db.execute(
            "INSERT INTO lineage_task_meta(task_id, lineage_authority_revision, contact_lost_at, "
            "abandonment_deadline, abandonment_reason) VALUES (?, 2, ?, ?, 'contact_lost')",
            (_TASK, _AT, _AT),
        )
        assert db.pragma("user_version") == 6
        report = migrations.run_migrations(db, migrations.CATALOG_MIGRATIONS, maintenance=None)
        assert report.applied_versions == ("0007",)
        assert db.pragma("user_version") == 7
        assert db.execute(
            "SELECT lineage_authority_revision, contact_lost_at, abandonment_deadline, "
            "abandonment_reason, quiet_until FROM lineage_task_meta WHERE task_id = ?",
            (_TASK,),
        ).fetchall() == [(2, _AT, _AT, "contact_lost", None)]
        assert db.execute("PRAGMA foreign_key_check").fetchone() is None
    finally:
        db.close(force=True)
