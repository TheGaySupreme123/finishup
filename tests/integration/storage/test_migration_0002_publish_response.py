"""Catalog migration 0002 publish-response storage checks."""

from __future__ import annotations

import apsw
import pytest

from finishup.adapters.sqlite.migrations import (
    CATALOG_MIGRATIONS,
    Migration,
    initialize_catalog,
    run_migrations,
)


def test_forward_migrate_catalog_0001_to_current() -> None:
    catalog = apsw.Connection(":memory:")
    catalog.execute("PRAGMA foreign_keys = ON")
    catalog.execute("PRAGMA trusted_schema = OFF")
    with catalog:
        catalog.execute(CATALOG_MIGRATIONS[0].ddl.decode("utf-8"))
        catalog.execute(
            "INSERT INTO catalog_meta(key, value) VALUES('storage_schema_version', '1')"
        )

    report = run_migrations(catalog, CATALOG_MIGRATIONS, maintenance=None)

    assert report.from_version == 1
    assert report.to_version == 5
    assert report.applied_versions == ("0002", "0003", "0004", "0005")
    assert catalog.execute("PRAGMA user_version").fetchone() == (5,)
    assert catalog.execute(
        "SELECT value FROM catalog_meta WHERE key = 'storage_schema_version'"
    ).fetchone() == ("5",)
    assert catalog.execute(
        "SELECT strict, wr FROM pragma_table_list WHERE name = 'publish_responses'"
    ).fetchone() == (1, 1)
    assert catalog.execute(
        "SELECT strict, wr FROM pragma_table_list WHERE name = 'coordination_coverage'"
    ).fetchone() == (1, 1)


def test_fresh_catalog_initialization_includes_publish_responses() -> None:
    catalog = apsw.Connection(":memory:")
    initialize_catalog(catalog)

    assert catalog.execute("PRAGMA user_version").fetchone() == (5,)
    assert tuple(row[1] for row in catalog.execute("PRAGMA table_info(publish_responses)")) == (
        "writer_id",
        "request_id",
        "sink",
        "task_id",
        "session_id",
        "request_digest",
        "result_canonical",
        "result_digest",
    )
    assert tuple(row[1] for row in catalog.execute("PRAGMA table_info(coordination_coverage)")) == (
        "coverage_id",
        "project_id",
        "task_id",
        "membership_generation",
        "coverage",
        "gap_code",
    )


def test_catalog_0004_failure_rolls_back_coverage_and_lineage_admission_ddl() -> None:
    catalog = apsw.Connection(":memory:")
    catalog.execute("PRAGMA foreign_keys = ON")
    catalog.execute("PRAGMA trusted_schema = OFF")
    with catalog:
        for migration in CATALOG_MIGRATIONS[:3]:
            catalog.execute(migration.ddl.decode("utf-8"))
        catalog.execute(
            "INSERT INTO catalog_meta(key, value) VALUES('storage_schema_version', '3')"
        )

    failing = Migration(
        "0004",
        b"CREATE TABLE coordination_coverage(value TEXT) STRICT;\n"
        b"ALTER TABLE missing_catalog_table ADD COLUMN value TEXT;\n"
        b"PRAGMA user_version = 4;\n",
    )
    with pytest.raises(apsw.SQLError):
        run_migrations(catalog, (*CATALOG_MIGRATIONS[:3], failing), maintenance=None)

    assert catalog.execute("PRAGMA user_version").fetchone() == (3,)
    assert (
        catalog.execute(
            "SELECT 1 FROM sqlite_schema WHERE name = 'coordination_coverage'"
        ).fetchone()
        is None
    )
