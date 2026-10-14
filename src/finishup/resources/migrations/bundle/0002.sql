PRAGMA application_id = 0x594F4554;

CREATE TABLE observation_consent (
    workspace_commitment TEXT PRIMARY KEY,
    granted_at TEXT NOT NULL,
    revoked_at TEXT,
    paused INTEGER NOT NULL CHECK (paused IN (0, 1))
) STRICT, WITHOUT ROWID;

CREATE TABLE observation_cursors (
    workspace_commitment TEXT NOT NULL,
    source TEXT NOT NULL CHECK (source IN ('codex_hook', 'codex_session_stream')),
    session_commitment TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK (generation > 0),
    byte_pos INTEGER NOT NULL CHECK (byte_pos >= 0),
    event_pos INTEGER NOT NULL CHECK (event_pos >= 0),
    last_source_commitment TEXT NOT NULL,
    mapping_version TEXT NOT NULL,
    PRIMARY KEY (workspace_commitment, source, session_commitment)
) STRICT, WITHOUT ROWID;

CREATE TABLE observation_dedup (
    dedup_key TEXT PRIMARY KEY,
    workspace_commitment TEXT NOT NULL,
    ingested_at TEXT NOT NULL
) STRICT, WITHOUT ROWID;

CREATE TABLE observation_events (
    id INTEGER PRIMARY KEY,
    workspace_commitment TEXT NOT NULL,
    session_commitment TEXT NOT NULL,
    source TEXT NOT NULL CHECK (source IN ('codex_hook', 'codex_session_stream')),
    event_kind TEXT NOT NULL,
    structural_json BLOB NOT NULL,
    content_refs_json BLOB NOT NULL,
    gap_codes_json BLOB NOT NULL,
    receipt_time TEXT NOT NULL,
    source_generation INTEGER NOT NULL CHECK (source_generation > 0),
    byte_position INTEGER NOT NULL CHECK (byte_position >= 0),
    event_position INTEGER NOT NULL CHECK (event_position >= 0),
    last_source_commitment TEXT NOT NULL,
    mapping_version TEXT NOT NULL
) STRICT;

CREATE TABLE observation_advice (
    workspace_commitment TEXT PRIMARY KEY,
    suppression_identity TEXT NOT NULL,
    snapshot_json BLOB NOT NULL,
    updated_at TEXT NOT NULL
) STRICT, WITHOUT ROWID;

CREATE INDEX observation_events_by_workspace_receipt
    ON observation_events (workspace_commitment, receipt_time);

CREATE INDEX observation_dedup_by_workspace
    ON observation_dedup (workspace_commitment);

PRAGMA user_version = 2;
