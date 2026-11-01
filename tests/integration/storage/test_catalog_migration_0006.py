"""Catalog migration 0006 (#1239): the lineage row keeps why its work was abandoned."""

from __future__ import annotations

from pathlib import Path

import apsw
import pytest

from finishup.adapters.sqlite import migrations

_TASK = "tsk_70000000-0000-4000-8000-000000000006"
_SESSION = "ses_70000000-0000-4000-8000-000000000006"
_AT = "2026-10-29T12:00:00.000Z"


def _catalog_v5(path: Path) -> apsw.Connection:
    db = apsw.Connection(str(path))
    for migration in migrations.CATALOG_MIGRATIONS[:5]:
        db.execute(migration.ddl.decode("utf-8"))
    db.execute("INSERT INTO catalog_meta VALUES ('storage_schema_version', '5')")
    db.execute(
        "INSERT INTO task_routes(task_id, active_session_id, bundle_relpath, route_generation, "
        "active_route_identity_digest, state, created_at, updated_at) "
        "VALUES (?, ?, ?, 1, ?, 'active', ?, ?)",
        (_TASK, _SESSION, f"tasks/{_TASK}", "sha256:" + "a" * 64, _AT, _AT),
    )
    db.execute(
        "INSERT INTO lineage_task_meta(task_id, lineage_authority_revision, contact_lost_at, "
        "abandonment_deadline) VALUES (?, 3, ?, ?)",
        (_TASK, _AT, _AT),
    )
    return db


def test_an_upgraded_row_keeps_its_facts_and_reads_no_reason(tmp_path: Path) -> None:
    db = _catalog_v5(tmp_path / "catalog.sqlite3")
    try:
        assert db.pragma("user_version") == 5
        report = migrations.run_migrations(db, migrations.CATALOG_MIGRATIONS, maintenance=None)
        assert report.applied_versions == ("0006", "0007")
        assert db.pragma("user_version") == 7
        assert db.execute(
            "SELECT lineage_authority_revision, contact_lost_at, abandonment_deadline, "
            "abandonment_reason FROM lineage_task_meta WHERE task_id = ?",
            (_TASK,),
        ).fetchall() == [(3, _AT, _AT, None)]
        assert db.execute("PRAGMA foreign_key_check").fetchone() is None
    finally:
        db.close(force=True)


@pytest.mark.parametrize("reason", ("contact_lost", "session_ended", "attach_handle_expired"))
def test_the_reason_is_one_of_the_recorded_abandonment_reasons(tmp_path: Path, reason: str) -> None:
    db = _catalog_v5(tmp_path / "catalog.sqlite3")
    try:
        migrations.run_migrations(db, migrations.CATALOG_MIGRATIONS, maintenance=None)
        db.execute(
            "UPDATE lineage_task_meta SET abandonment_reason = ? WHERE task_id = ?",
            (reason, _TASK),
        )
        with pytest.raises(apsw.ConstraintError):
            db.execute(
                "UPDATE lineage_task_meta SET abandonment_reason = 'bored' WHERE task_id = ?",
                (_TASK,),
            )
        assert db.execute("SELECT abandonment_reason FROM lineage_task_meta").fetchall() == [
            (reason,)
        ]
    finally:
        db.close(force=True)
