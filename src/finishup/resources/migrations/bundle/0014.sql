PRAGMA application_id = 0x594F4554;

-- Migration 0014 admits the lineage, work, and coordination event families that the
-- domain has carried since the multi-agent service landed.  SQLite cannot widen the
-- events summary CHECK in place.  Rebuild only events, retaining every column and byte;
-- the dependent tables keep their existing foreign-key definitions and history.  Build the new
-- table beside the old one, then drop and rename it; renaming the old table first makes SQLite
-- rewrite every dependent REFERENCES clause to `events_v14_old` even under legacy_alter_table.
--
-- The migration runner disables foreign-key enforcement around this DDL because existing
-- event rows may be referenced by event_projection_locators, event_parents, event_refs,
-- and projection tables.  legacy_alter_table keeps those references named `events` while
-- the old table is replaced.  The PRAGMA pair also makes direct execution safe when it is
-- run outside a transaction; the runner restores its reviewed connection settings after
-- the migration transaction completes.

PRAGMA foreign_keys = OFF;
PRAGMA legacy_alter_table = ON;

DROP INDEX IF EXISTS events_session_seq;
DROP INDEX IF EXISTS events_session_schema_seq;
DROP INDEX IF EXISTS events_session_author_seq;
DROP INDEX IF EXISTS events_session_schema_author_seq;
DROP INDEX IF EXISTS events_schema_seq;
DROP INDEX IF EXISTS events_writer_seq;
DROP INDEX IF EXISTS events_payload_object;

CREATE TABLE events_v14_new (
    ingestion_seq INTEGER PRIMARY KEY CHECK (ingestion_seq > 0),
    event_id TEXT NOT NULL UNIQUE,
    task_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    schema_name TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    projection_status TEXT NOT NULL
        CHECK (projection_status IN ('projected', 'unknown_unprojected')),
    summary_code TEXT NOT NULL CHECK (summary_code IN (
        'session_opened',
        'session_resumed',
        'plan_published',
        'obligation_published',
        'assignment_recorded',
        'decision_recorded',
        'action_recorded',
        'result_recorded',
        'evidence_recorded',
        'claim_recorded',
        'plan_revised',
        'finding_recorded',
        'response_recorded',
        'redaction_recorded',
        'check_recorded',
        'receipt_recorded',
        'delegation_declared',
        'delegation_cancelled',
        'child_accepted',
        'child_rejected',
        'child_written_off',
        'child_dependencies_recorded',
        'work_closed',
        'work_abandoned',
        'work_cancelled',
        'work_written_off',
        'coordination_context_recorded',
        'coordination_disposition_recorded',
        'coordination_obligation_declared',
        'opaque_unknown'
    )),
    author_id TEXT NOT NULL,
    author_type TEXT NOT NULL,
    author_assurance TEXT NOT NULL,
    writer_id TEXT NOT NULL REFERENCES writers(writer_id),
    writer_seq INTEGER NOT NULL CHECK (writer_seq > 0),
    operation_id TEXT NOT NULL,
    previous_ledger_digest TEXT NOT NULL,
    previous_writer_digest TEXT NOT NULL,
    entry_digest TEXT NOT NULL UNIQUE,
    canonical_entry BLOB NOT NULL,
    payload_object_id TEXT NOT NULL REFERENCES objects(object_id),
    payload_commitment TEXT NOT NULL,
    publication_channel TEXT NOT NULL,
    redaction_state TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    accepted_at TEXT NOT NULL,
    UNIQUE (writer_id, writer_seq),
    UNIQUE (writer_id, operation_id, event_id),
    CHECK (
        (
            projection_status = 'unknown_unprojected'
            AND summary_code = 'opaque_unknown'
        )
        OR
        (
            projection_status = 'projected'
            AND summary_code = schema_name
            AND summary_code <> 'opaque_unknown'
        )
    )
) STRICT;

INSERT INTO events_v14_new (
    ingestion_seq, event_id, task_id, session_id, schema_name, schema_version,
    projection_status, summary_code, author_id, author_type, author_assurance,
    writer_id, writer_seq, operation_id, previous_ledger_digest, previous_writer_digest,
    entry_digest, canonical_entry, payload_object_id, payload_commitment, publication_channel,
    redaction_state, occurred_at, accepted_at
) SELECT
    ingestion_seq, event_id, task_id, session_id, schema_name, schema_version,
    projection_status, summary_code, author_id, author_type, author_assurance,
    writer_id, writer_seq, operation_id, previous_ledger_digest, previous_writer_digest,
    entry_digest, canonical_entry, payload_object_id, payload_commitment, publication_channel,
    redaction_state, occurred_at, accepted_at
FROM events;

DROP TABLE events;
ALTER TABLE events_v14_new RENAME TO events;

CREATE INDEX events_session_seq
ON events(session_id, ingestion_seq);

CREATE INDEX events_session_schema_seq
ON events(session_id, schema_name, ingestion_seq);

CREATE INDEX events_session_author_seq
ON events(session_id, author_id, ingestion_seq);

CREATE INDEX events_session_schema_author_seq
ON events(session_id, schema_name, author_id, ingestion_seq);

CREATE INDEX events_schema_seq
ON events(schema_name, ingestion_seq);

CREATE INDEX events_writer_seq
ON events(writer_id, writer_seq);

CREATE UNIQUE INDEX events_payload_object
ON events(payload_object_id);

PRAGMA legacy_alter_table = OFF;
PRAGMA foreign_keys = ON;
PRAGMA user_version = 14;
