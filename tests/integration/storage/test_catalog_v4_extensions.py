"""The catalog migration owns the durable lineage and coordination extension tables."""

from __future__ import annotations

from pathlib import Path

import apsw
import pytest

from finishup.adapters.sqlite import migrations
from finishup.adapters.sqlite.migrations import initialize_catalog


def test_catalog_v4_installs_provisional_and_coordination_tables() -> None:
    db = apsw.Connection(":memory:")
    try:
        initialize_catalog(db)
        expected = {
            "host_lineage_annotations",
            "host_lineage_annotation_aliases",
            "coordination_detections",
            "coordination_participants",
            "coordination_deliveries",
            "coordination_coverage",
            "coordination_obligations",
            "repository_grouping_preferences",
        }
        actual = {
            row[0]
            for row in db.execute(
                "SELECT name FROM sqlite_schema WHERE type = 'table' AND name IN "
                "('host_lineage_annotations', 'host_lineage_annotation_aliases', "
                "'coordination_detections', 'coordination_participants', "
                "'coordination_deliveries', 'coordination_coverage', 'coordination_obligations', "
                "'repository_grouping_preferences')"
            )
        }
        assert actual == expected
        assert tuple(
            row[1] for row in db.execute("PRAGMA table_info(coordination_obligations)")
        ) == (
            "detection_id",
            "task_id",
            "obligation_id",
            "declared",
            "addressed",
            "resolved",
        )
        assert tuple(row[1] for row in db.execute("PRAGMA table_info(coordination_coverage)")) == (
            "coverage_id",
            "project_id",
            "task_id",
            "membership_generation",
            "coverage",
            "gap_code",
        )
        assert tuple(row[1] for row in db.execute("PRAGMA table_info(lineage_operations)"))[
            -2:
        ] == ("project_id", "membership_generation")
        assert db.pragma("user_version") == 6
        assert db.execute("PRAGMA foreign_key_check").fetchone() is None
    finally:
        db.close(force=True)


@pytest.mark.parametrize("failed_version", ["0004", "0005", "0006"])
def test_catalog_upgrade_rolls_back_all_pending_ddl_and_retries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failed_version: str
) -> None:
    path = tmp_path / "catalog.sqlite3"
    db = apsw.Connection(str(path))
    for migration in migrations.CATALOG_MIGRATIONS[:3]:
        db.execute(migration.ddl.decode("utf-8"))
    db.execute("INSERT INTO catalog_meta VALUES ('storage_schema_version', '3')")
    task = "tsk_70000000-0000-4000-8000-000000000001"
    session = "ses_70000000-0000-4000-8000-000000000001"
    db.execute(
        "INSERT INTO task_routes(task_id, active_session_id, bundle_relpath, route_generation, "
        "active_route_identity_digest, state, created_at, updated_at) "
        "VALUES (?, ?, ?, 1, ?, 'active', ?, ?)",
        (
            task,
            session,
            f"tasks/{task}",
            "sha256:" + "a" * 64,
            "2026-09-05T12:00:00.000Z",
            "2026-09-05T12:00:00.000Z",
        ),
    )
    old_route = db.execute("SELECT * FROM task_routes").fetchall()
    old_schema = db.execute("SELECT type, name, sql FROM sqlite_schema ORDER BY name").fetchall()
    execute = migrations._execute  # pyright: ignore[reportPrivateUsage]

    def fail_after_ddl(connection: apsw.Connection, migration: migrations.Migration) -> None:
        execute(connection, migration)
        if migration.version == failed_version:
            raise RuntimeError("synthetic migration interruption")

    with monkeypatch.context() as patcher:
        patcher.setattr(migrations, "_execute", fail_after_ddl)
        with pytest.raises(RuntimeError, match="synthetic migration interruption"):
            migrations.run_migrations(db, migrations.CATALOG_MIGRATIONS, maintenance=None)
    db.close()
    db = apsw.Connection(str(path))
    try:
        assert db.pragma("user_version") == 3
        assert db.execute("SELECT * FROM task_routes").fetchall() == old_route
        assert (
            db.execute("SELECT type, name, sql FROM sqlite_schema ORDER BY name").fetchall()
            == old_schema
        )
        assert db.execute(
            "SELECT value FROM catalog_meta WHERE key='storage_schema_version'"
        ).fetchone() == ("3",)
        report = migrations.run_migrations(db, migrations.CATALOG_MIGRATIONS, maintenance=None)
        assert report.applied_versions == ("0004", "0005", "0006")
        assert report.backup_manifest_digest is None
        assert db.execute("SELECT session_id, health FROM task_sessions").fetchall() == [
            (session, "contact_lost")
        ]
        assert db.execute("PRAGMA foreign_key_check").fetchone() is None
        assert (
            migrations.run_migrations(
                db, migrations.CATALOG_MIGRATIONS, maintenance=None
            ).applied_versions
            == ()
        )
    finally:
        db.close()
