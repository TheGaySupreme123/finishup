"""Repository privacy authority migration checks."""

from __future__ import annotations

import apsw

from finishup.adapters.sqlite.migrations import CATALOG_MIGRATIONS, run_migrations


def test_catalog_0003_snapshots_only_preupgrade_routes_and_is_idempotent() -> None:
    db = apsw.Connection(":memory:")
    db.execute("PRAGMA foreign_keys = ON")
    db.execute("PRAGMA trusted_schema = OFF")
    db.execute(CATALOG_MIGRATIONS[0].ddl.decode("utf-8"))
    db.execute(
        """INSERT INTO privacy_policy_versions (
               policy_id, policy_version, scope_digest, scope_kind, installation_id,
               workspace_ref_commitment, task_id, request_id, policy_digest,
               policy_canonical, policy_generation, change_kind, source_proposal_id,
               state, created_at, superseded_at
           ) VALUES (
               'pvy_frontier', 1, 'sha256:scope', 'machine', 'ins_frontier',
               NULL, NULL, NULL,
               'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
               X'66726f6e74696572', 1, 'seed', NULL, 'current',
               '2026-08-09T00:00:00.000Z', NULL
           )"""
    )
    db.execute(
        """INSERT INTO task_routes (
               task_id, workspace_ref_commitment, external_ref_commitment,
               active_session_id, bundle_relpath, route_generation,
               active_route_identity_digest, state, quarantine_code, created_at, updated_at
           ) VALUES ('tsk_legacy', 'hmac-sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                     'hmac-sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                     'ses_legacy', 'tasks/tsk_legacy', 1,
                     'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
                     'active', NULL, '2026-08-09T00:00:00.000Z',
                     '2026-08-09T00:00:00.000Z')"""
    )
    db.execute("INSERT INTO catalog_meta(key, value) VALUES('storage_schema_version', '1')")

    report = run_migrations(db, CATALOG_MIGRATIONS, maintenance=None)

    assert report.applied_versions == ("0002", "0003", "0004", "0005", "0006", "0007")
    assert db.execute("PRAGMA user_version").fetchone() == (7,)
    assert db.execute(
        "SELECT task_id, route_identity_digest, migration_policy_generation, "
        "migration_policy_digest, migration_policy_canonical, entitlement_state "
        "FROM privacy_legacy_route_entitlements"
    ).fetchone() == (
        "tsk_legacy",
        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        1,
        "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        b"frontier",
        "available",
    )
    assert db.execute(
        "SELECT repository_privacy_commitment FROM task_routes WHERE task_id = 'tsk_legacy'"
    ).fetchone() == (None,)
    assert db.execute("PRAGMA foreign_key_check").fetchone() is None

    replay = run_migrations(db, CATALOG_MIGRATIONS, maintenance=None)
    assert replay.applied_versions == ()
    assert db.execute("SELECT COUNT(*) FROM privacy_legacy_route_entitlements").fetchone() == (1,)
