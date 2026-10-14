PRAGMA application_id = 0x594F4554;

-- Migration 0016 admits the review-input suspension marker. SQLite cannot widen the CHECK
-- constraint added by 0006 in place, so rebuild only operations while retaining every durable
-- row and its exact result/object bindings. A parked review-input check has no provider job and
-- releases its lease so the supported start/resume input flow can append the statement.
PRAGMA foreign_keys = OFF;
PRAGMA legacy_alter_table = ON;

CREATE TABLE operations_v16 (
    writer_id TEXT NOT NULL REFERENCES writers(writer_id),
    operation_id TEXT NOT NULL,
    operation_kind TEXT NOT NULL
        CHECK (operation_kind IN ('start', 'publish_work', 'check', 'respond', 'receipt')),
    request_digest TEXT NOT NULL,
    resume_object_id TEXT REFERENCES objects(object_id),
    state TEXT NOT NULL CHECK (state IN ('pending', 'complete', 'quarantined')),
    phase TEXT NOT NULL CHECK (phase IN (
        'reserved',
        'local_ready',
        'semantic_wait',
        'ready_to_finalize',
        'terminal'
    )),
    owner_generation TEXT,
    lease_owner_id TEXT,
    lease_generation INTEGER CHECK (lease_generation > 0),
    lease_expires_at TEXT,
    first_ingestion_seq INTEGER,
    last_ingestion_seq INTEGER,
    result_canonical BLOB,
    result_digest TEXT,
    result_object_id TEXT REFERENCES objects(object_id),
    quarantine_code TEXT,
    terminal_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    suspension_kind TEXT
        CHECK (suspension_kind IS NULL OR suspension_kind IN ('repository_grant', 'review_input')),
    PRIMARY KEY (writer_id, operation_id),
    CHECK (
        (
            state = 'pending'
            AND operation_kind = 'check'
            AND phase != 'terminal'
            AND resume_object_id IS NOT NULL
            AND owner_generation IS NOT NULL
            AND lease_owner_id IS NOT NULL
            AND lease_generation IS NOT NULL
            AND lease_expires_at IS NOT NULL
            AND result_canonical IS NULL
            AND result_digest IS NULL
            AND quarantine_code IS NULL
            AND terminal_at IS NULL
        )
        OR
        (
            state = 'complete'
            AND phase = 'terminal'
            AND owner_generation IS NULL
            AND lease_owner_id IS NULL
            AND lease_generation IS NULL
            AND lease_expires_at IS NULL
            AND result_canonical IS NOT NULL
            AND result_digest IS NOT NULL
            AND quarantine_code IS NULL
            AND terminal_at IS NOT NULL
        )
        OR
        (
            state = 'quarantined'
            AND phase = 'terminal'
            AND owner_generation IS NULL
            AND lease_owner_id IS NULL
            AND lease_generation IS NULL
            AND lease_expires_at IS NULL
            AND result_canonical IS NOT NULL
            AND result_digest IS NOT NULL
            AND quarantine_code IS NOT NULL
            AND terminal_at IS NOT NULL
        )
    ),
    CHECK (phase != 'semantic_wait' OR operation_kind = 'check'),
    CHECK (
        (first_ingestion_seq IS NULL AND last_ingestion_seq IS NULL)
        OR
        (first_ingestion_seq IS NOT NULL AND last_ingestion_seq >= first_ingestion_seq)
    )
) STRICT, WITHOUT ROWID;

INSERT INTO operations_v16 (
    writer_id, operation_id, operation_kind, request_digest, resume_object_id, state, phase,
    owner_generation, lease_owner_id, lease_generation, lease_expires_at, first_ingestion_seq,
    last_ingestion_seq, result_canonical, result_digest, result_object_id, quarantine_code,
    terminal_at, created_at, updated_at, suspension_kind
) SELECT
    writer_id, operation_id, operation_kind, request_digest, resume_object_id, state, phase,
    owner_generation, lease_owner_id, lease_generation, lease_expires_at, first_ingestion_seq,
    last_ingestion_seq, result_canonical, result_digest, result_object_id, quarantine_code,
    terminal_at, created_at, updated_at, suspension_kind
FROM operations;

DROP TABLE operations;
ALTER TABLE operations_v16 RENAME TO operations;

PRAGMA legacy_alter_table = OFF;
PRAGMA foreign_keys = ON;
PRAGMA user_version = 16;
