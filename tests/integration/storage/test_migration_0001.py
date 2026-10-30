"""Fresh-database and frozen importer-schema checks for migration 0001."""

from pathlib import Path

import apsw
import pytest

from finishup.adapters.sqlite.connection import (  # pyright: ignore[reportPrivateUsage]
    _writer_authorizer,  # pyright: ignore[reportPrivateUsage]
)
from finishup.adapters.sqlite.migrations import (
    BUNDLE_MIGRATIONS,
    CATALOG_MIGRATIONS,
    _set_event_summary_rebuild_mode,  # pyright: ignore[reportPrivateUsage]
    current_schema_version,
    initialize_bundle,
    initialize_catalog,
    run_migrations,
)

ROOT = Path(__file__).parents[3]


def test_root_and_installed_migration_resources_are_byte_identical() -> None:
    for family, versions in (
        ("catalog", tuple(item.version for item in CATALOG_MIGRATIONS)),
        ("bundle", tuple(item.version for item in BUNDLE_MIGRATIONS)),
    ):
        for version in versions:
            root = ROOT / "migrations" / family / f"{version}.sql"
            resource = (
                ROOT / "src" / "finishup" / "resources" / "migrations" / family / f"{version}.sql"
            )
            assert root.read_bytes() == resource.read_bytes()


def test_fresh_migrations_install_identified_foreign_key_clean_schemas() -> None:
    catalog = apsw.Connection(":memory:")
    initialize_catalog(catalog)

    bundle = apsw.Connection(":memory:")
    initialize_bundle(bundle, {"task_id": "task_test", "owner_generation": "generation_test"})

    assert catalog.execute("PRAGMA application_id").fetchone() == (0x594F4554,)
    assert catalog.execute("PRAGMA user_version").fetchone() == (7,)
    assert catalog.execute("PRAGMA foreign_keys").fetchone() == (1,)
    assert catalog.execute("PRAGMA trusted_schema").fetchone() == (0,)
    assert catalog.execute("PRAGMA foreign_key_check").fetchone() is None

    assert bundle.execute("PRAGMA application_id").fetchone() == (0x594F4554,)
    current = current_schema_version(BUNDLE_MIGRATIONS)
    assert bundle.execute("PRAGMA user_version").fetchone() == (current,)
    assert bundle.execute("PRAGMA foreign_keys").fetchone() == (1,)
    assert bundle.execute("PRAGMA trusted_schema").fetchone() == (0,)
    assert bundle.execute("PRAGMA foreign_key_check").fetchone() is None

    assert bundle.execute(
        "SELECT value FROM bundle_meta WHERE key = 'import_schema_version'"
    ).fetchone() == ("1",)
    assert bundle.execute(
        "SELECT value FROM bundle_meta WHERE key = 'storage_schema_version'"
    ).fetchone() == (str(current),)
    assert bundle.execute(
        "SELECT 1 FROM sqlite_schema WHERE name = 'observation_consent'"
    ).fetchone() == (1,)


def test_fresh_bundle_migration_window_restores_strict_writer_authorizer() -> None:
    bundle = apsw.Connection(":memory:")
    bundle.set_authorizer(_writer_authorizer)

    initialize_bundle(
        bundle,
        {"task_id": "task_test", "owner_generation": "generation_test", "protocol_version": "0.1"},
    )

    assert bundle.execute("PRAGMA user_version").fetchone() == (
        current_schema_version(BUNDLE_MIGRATIONS),
    )
    assert bundle.execute("PRAGMA foreign_keys").fetchone() == (1,)
    assert bundle.authorizer is _writer_authorizer
    assert bundle.execute("PRAGMA table_info(observation_consent)").fetchall()
    with pytest.raises(apsw.AuthError):
        bundle.execute("PRAGMA legacy_alter_table = ON")
    with pytest.raises(apsw.AuthError):
        bundle.execute("PRAGMA foreign_keys = OFF")


def test_event_summary_rebuild_rejects_active_transaction_without_changing_pragmas() -> None:
    bundle = apsw.Connection(":memory:")
    bundle.execute("PRAGMA foreign_keys = ON")
    bundle.execute("PRAGMA legacy_alter_table = OFF")
    bundle.execute("BEGIN")

    with pytest.raises(RuntimeError, match="schema_rebuild_transaction_active"):
        _set_event_summary_rebuild_mode(bundle)

    assert bundle.execute("PRAGMA foreign_keys").fetchone() == (1,)
    assert bundle.execute("PRAGMA legacy_alter_table").fetchone() == (0,)
    bundle.execute("ROLLBACK")


def test_bundle_run_migrations_applies_pending_versions_from_schema_version_one() -> None:
    bundle = apsw.Connection(":memory:")
    bundle.execute("PRAGMA foreign_keys = ON")
    bundle.execute("PRAGMA trusted_schema = OFF")
    ddl = BUNDLE_MIGRATIONS[0].ddl.decode("utf-8")
    with bundle:
        bundle.execute(ddl)
        bundle.execute(
            "INSERT INTO bundle_meta(key, value) VALUES "
            "('task_id', 'task_test'), "
            "('owner_generation', '1'), "
            "('storage_schema_version', '1'), "
            "('protocol_version', '0.1'), "
            "('import_schema_version', '1')"
        )
        bundle.execute("INSERT INTO counters(name, next_value) VALUES ('ingestion_sequence', 1)")
    assert bundle.execute("PRAGMA user_version").fetchone() == (1,)
    assert (
        bundle.execute("SELECT 1 FROM sqlite_schema WHERE name = 'observation_consent'").fetchone()
        is None
    )

    report = run_migrations(bundle, BUNDLE_MIGRATIONS, maintenance=None)  # type: ignore[arg-type]
    assert report.from_version == 1
    assert report.to_version == current_schema_version(BUNDLE_MIGRATIONS)
    assert report.applied_versions == tuple(item.version for item in BUNDLE_MIGRATIONS[1:])
    assert bundle.execute("PRAGMA user_version").fetchone() == (
        current_schema_version(BUNDLE_MIGRATIONS),
    )
    assert bundle.execute(
        "SELECT value FROM bundle_meta WHERE key = 'storage_schema_version'"
    ).fetchone() == (str(current_schema_version(BUNDLE_MIGRATIONS)),)
    assert bundle.execute(
        "SELECT 1 FROM sqlite_schema WHERE name = 'observation_consent'"
    ).fetchone() == (1,)


def test_bundle_migration_0014_preserves_event_history_and_admits_current_families() -> None:
    bundle = apsw.Connection(":memory:")
    bundle.execute("PRAGMA foreign_keys = ON")
    bundle.execute("PRAGMA trusted_schema = OFF")
    target_version = current_schema_version(BUNDLE_MIGRATIONS)
    event_rebuild_index = next(
        index for index, migration in enumerate(BUNDLE_MIGRATIONS) if migration.version == "0014"
    )
    main_frontier = int(BUNDLE_MIGRATIONS[event_rebuild_index].version) - 1
    with bundle:
        for migration in BUNDLE_MIGRATIONS[:9]:
            bundle.execute(migration.ddl.decode("utf-8"))
        bundle.execute(
            "INSERT INTO bundle_meta(key, value) VALUES "
            "('task_id', 'task_test'), "
            "('owner_generation', '1'), "
            "('storage_schema_version', '9'), "
            "('protocol_version', '0.1'), "
            "('import_schema_version', '1')"
        )
        # The released 0.2 migrations occupy 0010-0013. Apply them before
        # exercising the 0.3 events-table rebuild at 0014.
        for migration in BUNDLE_MIGRATIONS[9:event_rebuild_index]:
            bundle.execute(migration.ddl.decode("utf-8"))
        bundle.execute(
            "UPDATE bundle_meta SET value=? WHERE key='storage_schema_version'",
            (str(main_frontier),),
        )
        bundle.execute("INSERT INTO counters(name, next_value) VALUES ('ingestion_sequence', 2)")
        bundle.execute(
            "INSERT INTO writers(writer_id, task_id, session_id, next_writer_seq, "
            "head_entry_digest, state, created_at) VALUES "
            "('writer', 'task_test', 'session', 2, 'head', 'active', '2026-01-01')"
        )
        bundle.execute(
            "INSERT INTO objects(object_id, kind, plaintext_size, commitment, envelope_digest, "
            "encryption_format, key_slot, state, durable_at) VALUES "
            "('object-1', 'event_payload', 1, 'commitment-1', 'envelope-1', 'v1', "
            "'slot', 'present', '2026-01-01')"
        )
        bundle.execute(
            "INSERT INTO events("
            "ingestion_seq, event_id, task_id, session_id, schema_name, schema_version, "
            "projection_status, summary_code, author_id, author_type, author_assurance, "
            "writer_id, writer_seq, operation_id, previous_ledger_digest, "
            "previous_writer_digest, entry_digest, canonical_entry, payload_object_id, "
            "payload_commitment, publication_channel, redaction_state, occurred_at, accepted_at"
            ") VALUES (1, 'event-1', 'task_test', 'session', 'action_recorded', '1.0.0', "
            "'projected', 'action_recorded', 'author', 'host', 'self_asserted', 'writer', 1, "
            "'operation-1', 'previous-ledger', 'previous-writer', 'entry-1', X'01', "
            "'object-1', 'commitment-1', 'local', 'none', '2026-01-01', '2026-01-01')"
        )
        bundle.execute(
            "INSERT INTO event_projection_locators("
            "event_id, schema_name, schema_version, logical_key, canonical_payload_digest, "
            "redaction_target_event_ids, redaction_target_object_ids) VALUES "
            "('event-1', 'action_recorded', '1.0.0', 'logical-1', 'payload-1', X'00', X'00')"
        )
        bundle.execute(
            "INSERT INTO event_refs(event_id, ref_type, target_id) "
            "VALUES ('event-1', 'artifact', 'artifact-1')"
        )

    original_event = bundle.execute(
        "SELECT canonical_entry, summary_code FROM events WHERE event_id = 'event-1'"
    ).fetchone()
    original_locator = bundle.execute(
        "SELECT * FROM event_projection_locators WHERE event_id = 'event-1'"
    ).fetchone()
    original_ref = bundle.execute("SELECT * FROM event_refs WHERE event_id = 'event-1'").fetchone()

    report = run_migrations(bundle, BUNDLE_MIGRATIONS, maintenance=None)  # type: ignore[arg-type]

    assert report.from_version == main_frontier
    assert report.to_version == target_version
    assert report.applied_versions == tuple(
        migration.version for migration in BUNDLE_MIGRATIONS[event_rebuild_index:]
    )
    assert report.applied_versions[0] == "0014"
    assert bundle.execute("PRAGMA user_version").fetchone() == (target_version,)
    assert bundle.execute("PRAGMA foreign_keys").fetchone() == (1,)
    assert bundle.execute("PRAGMA legacy_alter_table").fetchone() == (0,)
    assert bundle.execute("PRAGMA foreign_key_check").fetchone() is None
    for child in (
        "event_projection_locators",
        "event_parents",
        "event_refs",
        "p1_coverage_gaps",
    ):
        child_sql = bundle.execute(
            "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = ?",
            (child,),
        ).fetchone()
        assert child_sql is not None and "events_v14" not in child_sql[0]
    assert (
        bundle.execute(
            "SELECT canonical_entry, summary_code FROM events WHERE event_id = 'event-1'"
        ).fetchone()
        == original_event
    )
    assert (
        bundle.execute(
            "SELECT * FROM event_projection_locators WHERE event_id = 'event-1'"
        ).fetchone()
        == original_locator
    )
    assert bundle.execute("SELECT * FROM event_refs WHERE event_id = 'event-1'").fetchone() == (
        original_ref
    )
    assert {
        row[0]
        for row in bundle.execute(
            "SELECT name FROM sqlite_schema WHERE type = 'index' AND name LIKE 'events_%'"
        )
    } == {
        "events_session_seq",
        "events_session_schema_seq",
        "events_session_author_seq",
        "events_session_schema_author_seq",
        "events_schema_seq",
        "events_writer_seq",
        "events_payload_object",
    }

    current_families = (
        "delegation_declared",
        "delegation_cancelled",
        "child_accepted",
        "child_rejected",
        "child_written_off",
        "child_dependencies_recorded",
        "work_closed",
        "work_abandoned",
        "work_cancelled",
        "work_written_off",
        "coordination_context_recorded",
        "coordination_disposition_recorded",
        "coordination_obligation_declared",
    )
    for writer_seq, summary_code in enumerate(current_families, start=2):
        object_id = f"object-{writer_seq}"
        bundle.execute(
            "INSERT INTO objects(object_id, kind, plaintext_size, commitment, envelope_digest, "
            "encryption_format, key_slot, state, durable_at) VALUES (?, 'event_payload', 1, ?, ?, "
            "'v1', 'slot', 'present', '2026-01-01')",
            (object_id, f"commitment-{writer_seq}", f"envelope-{writer_seq}"),
        )
        bundle.execute(
            "INSERT INTO events("
            "ingestion_seq, event_id, task_id, session_id, schema_name, schema_version, "
            "projection_status, summary_code, author_id, author_type, author_assurance, "
            "writer_id, writer_seq, operation_id, previous_ledger_digest, "
            "previous_writer_digest, entry_digest, canonical_entry, payload_object_id, "
            "payload_commitment, publication_channel, redaction_state, occurred_at, accepted_at"
            ") VALUES (?, ?, 'task_test', 'session', ?, '1.0.0', 'projected', ?, 'author', "
            "'host', 'self_asserted', 'writer', ?, ?, 'previous-ledger', 'previous-writer', "
            "?, X'02', ?, ?, 'local', 'none', '2026-01-01', '2026-01-01')",
            (
                writer_seq,
                f"event-{writer_seq}",
                summary_code,
                summary_code,
                writer_seq,
                f"operation-{writer_seq}",
                f"entry-{writer_seq}",
                object_id,
                f"commitment-{writer_seq}",
            ),
        )

    assert bundle.execute("SELECT COUNT(*) FROM events").fetchone() == (14,)


def test_bundle_migration_0007_preserves_rows_and_widens_all_disposition_checks() -> None:
    bundle = apsw.Connection(":memory:")
    bundle.execute("PRAGMA foreign_keys = OFF")
    with bundle:
        for migration in BUNDLE_MIGRATIONS[:6]:
            bundle.execute(migration.ddl.decode("utf-8"))
        bundle.execute(
            "INSERT INTO p1_query_findings VALUES ("
            "'fnd_00000000-0000-4000-8000-000000000001', 1, NULL, "
            "'evt_00000000-0000-4000-8000-000000000001', 1, X'7B7D', "
            "'weak_or_stale_response', 'deterministic', 'work-integrity', '0.1.0', "
            "0, 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', "
            "2, 1, 0, 0, 0, 0, 1, 0, 0, X'7B7D', 'rejected', "
            "'evt_00000000-0000-4000-8000-000000000002', 0, 0)"
        )
        bundle.execute(
            "INSERT INTO p1_query_finding_order VALUES ("
            "'fnd_00000000-0000-4000-8000-000000000001', 1, NULL, '*', 0, "
            "'rejected', 'active', 2, -1, 0, 0, 0, 0, -1, 0, 0)"
        )
        bundle.execute(
            "INSERT INTO p1_query_responses VALUES ("
            "'fnd_00000000-0000-4000-8000-000000000001', 1, NULL, "
            "'evt_00000000-0000-4000-8000-000000000002', 1, 'rejected', NULL, NULL, 0)"
        )
        bundle.execute(BUNDLE_MIGRATIONS[6].ddl.decode("utf-8"))

    assert bundle.execute("PRAGMA user_version").fetchone() == (7,)
    assert bundle.execute("SELECT disposition FROM p2_query_findings").fetchone() == ("rejected",)
    assert bundle.execute("SELECT disposition_filter FROM p2_query_finding_order").fetchone() == (
        "rejected",
    )
    assert bundle.execute("SELECT disposition FROM p2_query_responses").fetchone() == ("rejected",)

    bundle.execute(
        "UPDATE p2_query_findings SET disposition = 'provenance_disputed' "
        "WHERE finding_id = 'fnd_00000000-0000-4000-8000-000000000001'"
    )
    bundle.execute("UPDATE p2_query_finding_order SET disposition_filter = 'provenance_disputed'")
    bundle.execute("UPDATE p2_query_responses SET disposition = 'provenance_disputed'")
    assert bundle.execute("SELECT disposition FROM p2_query_findings").fetchone() == (
        "provenance_disputed",
    )
    assert bundle.execute("SELECT disposition_filter FROM p2_query_finding_order").fetchone() == (
        "provenance_disputed",
    )
    assert bundle.execute("SELECT disposition FROM p2_query_responses").fetchone() == (
        "provenance_disputed",
    )


def test_importer_tables_have_frozen_columns_indexes_and_no_triggers() -> None:
    database = apsw.Connection(":memory:")
    initialize_bundle(database, {})

    expected_columns = {
        "import_jobs": tuple(
            "source_identity_digest task_id session_id source_commitment "
            "codex_capability_profile_id mapping_version publishing_writer_id "
            "source_object_id capture_metadata_object_id "
            "capture_metadata_object_commitment source_byte_count source_line_count "
            "source_final_newline codex_version source_kind source_exit_status "
            "stderr_present stderr_captured_byte_count stderr_truncated stderr_commitment "
            "metadata_digest state phase job_revision owner_generation lease_owner_id "
            "lease_generation lease_expires_at plan_digest batch_count completed_batch_count "
            "report_request_id report_event_id report_evidence_id report_object_id "
            "report_digest report_result_canonical report_result_digest "
            "report_evidence_draft_canonical report_evidence_draft_digest "
            "report_append_result_canonical report_append_result_digest report_ingestion_seq "
            "report_entry_digest terminal_result_canonical terminal_result_digest "
            "quarantine_code terminal_at created_at updated_at".split()
        ),
        "import_request_aliases": (
            "requesting_writer_id",
            "request_id",
            "request_digest",
            "source_identity_digest",
            "created_at",
        ),
        "import_batches": (
            "source_identity_digest",
            "batch_index",
            "state",
            "request_id",
            "plan_object_id",
            "plan_object_commitment",
            "plan_digest",
            "event_ids_canonical",
            "event_ids_digest",
            "event_count",
            "append_result_canonical",
            "append_result_digest",
            "subject_frontier_seq",
            "subject_frontier_digest",
            "result_frontier_seq",
            "result_frontier_digest",
            "first_ingestion_seq",
            "last_ingestion_seq",
            "completed_at",
            "created_at",
            "updated_at",
        ),
        "import_publication_requests": (
            "publishing_writer_id",
            "request_id",
            "source_identity_digest",
            "publication_ordinal",
        ),
    }
    for table, expected in expected_columns.items():
        actual = tuple(row[1] for row in database.execute(f"PRAGMA table_info({table})"))
        assert actual == expected

    indexes = {
        row[0]
        for row in database.execute(
            "SELECT name FROM sqlite_schema WHERE type = 'index' AND name NOT LIKE 'sqlite_%'"
        )
    }
    assert {
        "import_request_aliases_source",
        "import_jobs_session_state",
        "import_jobs_session_terminal",
        "import_batches_next",
    } <= indexes
    assert (
        database.execute(
            "SELECT name FROM sqlite_schema WHERE type IN ('trigger', 'view')"
        ).fetchall()
        == []
    )


def test_importer_source_reserved_shape_and_publication_reservations_are_enforced() -> None:
    database = apsw.Connection(":memory:")
    initialize_bundle(database, {})
    database.execute(
        "INSERT INTO writers VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("writer", "task", "session", 1, "genesis", "active", "2026-07-19T00:00:00.000Z"),
    )
    for object_id in ("source", "manifest"):
        database.execute(
            "INSERT INTO objects VALUES (?, ?, 0, ?, ?, ?, ?, 'present', ?)",
            (
                object_id,
                "import_source",
                "commitment",
                "envelope",
                "v1",
                "slot",
                "2026-07-19T00:00:00.000Z",
            ),
        )

    columns = (
        "source_identity_digest",
        "task_id",
        "session_id",
        "source_commitment",
        "codex_capability_profile_id",
        "mapping_version",
        "publishing_writer_id",
        "source_object_id",
        "capture_metadata_object_id",
        "capture_metadata_object_commitment",
        "source_byte_count",
        "source_line_count",
        "source_final_newline",
        "codex_version",
        "source_kind",
        "source_exit_status",
        "stderr_present",
        "stderr_captured_byte_count",
        "stderr_truncated",
        "stderr_commitment",
        "metadata_digest",
        "state",
        "phase",
        "job_revision",
        "owner_generation",
        "lease_owner_id",
        "lease_generation",
        "lease_expires_at",
        "plan_digest",
        "batch_count",
        "completed_batch_count",
        "report_request_id",
        "report_event_id",
        "report_evidence_id",
        "report_object_id",
        "report_digest",
        "report_result_canonical",
        "report_result_digest",
        "report_evidence_draft_canonical",
        "report_evidence_draft_digest",
        "report_append_result_canonical",
        "report_append_result_digest",
        "report_ingestion_seq",
        "report_entry_digest",
        "terminal_result_canonical",
        "terminal_result_digest",
        "quarantine_code",
        "terminal_at",
        "created_at",
        "updated_at",
    )
    values = (
        "source-id",
        "task",
        "session",
        "source-commitment",
        "profile",
        "mapping-v1",
        "writer",
        "source",
        "manifest",
        "manifest-commitment",
        0,
        0,
        0,
        "codex-v",
        "file",
        None,
        0,
        0,
        0,
        None,
        "metadata",
        "pending",
        "source_reserved",
        0,
        "generation",
        "lease",
        1,
        "2026-07-19T00:01:00.000Z",
        None,
        0,
        0,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        "2026-07-19T00:00:00.000Z",
        "2026-07-19T00:00:00.000Z",
    )
    placeholders = ", ".join("?" for _ in columns)
    database.execute(
        f"INSERT INTO import_jobs ({', '.join(columns)}) VALUES ({placeholders})", values
    )

    database.execute(
        "INSERT INTO import_publication_requests VALUES ('writer', 'request-0', 'source-id', 0)"
    )
    with pytest.raises(apsw.ConstraintError):
        database.execute(
            "INSERT INTO import_publication_requests VALUES ('writer', 'request-0', 'source-id', 1)"
        )
    with pytest.raises(apsw.ConstraintError):
        database.execute(
            "INSERT INTO import_publication_requests VALUES ('writer', 'request-1', 'source-id', 0)"
        )
    with pytest.raises(apsw.ConstraintError):
        database.execute(
            "UPDATE import_jobs SET phase = 'publishing' WHERE source_identity_digest = 'source-id'"
        )
