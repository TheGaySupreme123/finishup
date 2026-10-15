PRAGMA application_id = 0x594F4554;

-- Migration 0004 owns durable inspection snapshots and workspace→Yoetz-session
-- routing used by background verification and session-scoped advice. Migration
-- 0003 remains immutable; existing ledger/object/observation rows stay readable.

CREATE TABLE observation_inspection_snapshots (
    snapshot_id TEXT PRIMARY KEY,
    workspace_commitment TEXT NOT NULL,
    yoetz_session_id TEXT NOT NULL,
    subject_state_digest TEXT NOT NULL,
    changed_paths_digest TEXT NOT NULL,
    relative_paths_json BLOB NOT NULL,
    facts_object_id TEXT REFERENCES objects(object_id),
    excerpt_object_id TEXT REFERENCES objects(object_id),
    is_current INTEGER NOT NULL CHECK (is_current IN (0, 1)),
    recorded_at TEXT NOT NULL,
    UNIQUE (workspace_commitment, yoetz_session_id, subject_state_digest)
) STRICT, WITHOUT ROWID;

CREATE INDEX observation_inspection_by_workspace_current
    ON observation_inspection_snapshots (
        workspace_commitment,
        yoetz_session_id,
        is_current,
        recorded_at
    );

CREATE TABLE observation_workspace_session_routes (
    workspace_commitment TEXT NOT NULL,
    yoetz_session_id TEXT NOT NULL,
    yoetz_task_id TEXT NOT NULL,
    yoetz_writer_id TEXT NOT NULL,
    codex_session_commitment TEXT NOT NULL,
    active INTEGER NOT NULL CHECK (active IN (0, 1)),
    bound_at TEXT NOT NULL,
    unbound_at TEXT,
    PRIMARY KEY (workspace_commitment, yoetz_session_id),
    UNIQUE (yoetz_session_id),
    CHECK (
        (active = 1 AND unbound_at IS NULL)
        OR (active = 0 AND unbound_at IS NOT NULL)
    )
) STRICT, WITHOUT ROWID;

CREATE INDEX observation_routes_by_codex_session
    ON observation_workspace_session_routes (codex_session_commitment, active);

CREATE INDEX observation_routes_by_task
    ON observation_workspace_session_routes (yoetz_task_id, active);

-- Session-scoped current advice (replaces cross-workspace "latest anywhere" reads).
CREATE TABLE observation_session_advice (
    workspace_commitment TEXT NOT NULL,
    yoetz_session_id TEXT NOT NULL,
    suppression_identity TEXT NOT NULL,
    snapshot_json BLOB NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (workspace_commitment, yoetz_session_id)
) STRICT, WITHOUT ROWID;

CREATE INDEX observation_session_advice_by_session
    ON observation_session_advice (yoetz_session_id, updated_at);

PRAGMA user_version = 4;
