PRAGMA application_id = 0x594F4554;

-- Migration 0009 admits the claude_hook and cursor_hook observation sources that the domain
-- enum has carried since the Cursor and Claude Code integrations landed. SQLite cannot widen a
-- table CHECK constraint in place, and nothing references observation_cursors or
-- observation_events by foreign key, so each table is rebuilt under a temporary name from its
-- existing rows and renamed back. Every column, every existing row (including
-- observation_events.id), and the receipt index are preserved; only the closed source set grows.
-- Rows for the two new sources were never storable before this migration, so no data is
-- reinterpreted (issue #576).

CREATE TABLE observation_cursors_v2 (
    workspace_commitment TEXT NOT NULL,
    source TEXT NOT NULL CHECK (
        source IN ('claude_hook', 'codex_hook', 'codex_session_stream', 'cursor_hook')
    ),
    session_commitment TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK (generation > 0),
    byte_pos INTEGER NOT NULL CHECK (byte_pos >= 0),
    event_pos INTEGER NOT NULL CHECK (event_pos >= 0),
    last_source_commitment TEXT NOT NULL,
    mapping_version TEXT NOT NULL,
    PRIMARY KEY (workspace_commitment, source, session_commitment)
) STRICT, WITHOUT ROWID;

INSERT INTO observation_cursors_v2 (
    workspace_commitment, source, session_commitment, generation, byte_pos, event_pos,
    last_source_commitment, mapping_version
) SELECT
    workspace_commitment, source, session_commitment, generation, byte_pos, event_pos,
    last_source_commitment, mapping_version
FROM observation_cursors;

DROP TABLE observation_cursors;

ALTER TABLE observation_cursors_v2 RENAME TO observation_cursors;

CREATE TABLE observation_events_v2 (
    id INTEGER PRIMARY KEY,
    workspace_commitment TEXT NOT NULL,
    session_commitment TEXT NOT NULL,
    source TEXT NOT NULL CHECK (
        source IN ('claude_hook', 'codex_hook', 'codex_session_stream', 'cursor_hook')
    ),
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

INSERT INTO observation_events_v2 (
    id, workspace_commitment, session_commitment, source, event_kind, structural_json,
    content_refs_json, gap_codes_json, receipt_time, source_generation, byte_position,
    event_position, last_source_commitment, mapping_version
) SELECT
    id, workspace_commitment, session_commitment, source, event_kind, structural_json,
    content_refs_json, gap_codes_json, receipt_time, source_generation, byte_position,
    event_position, last_source_commitment, mapping_version
FROM observation_events;

DROP TABLE observation_events;

ALTER TABLE observation_events_v2 RENAME TO observation_events;

CREATE INDEX observation_events_by_workspace_receipt
    ON observation_events (workspace_commitment, receipt_time);

PRAGMA user_version = 9;
