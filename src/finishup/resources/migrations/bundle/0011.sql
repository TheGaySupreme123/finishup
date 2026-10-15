PRAGMA application_id = 0x594F4554;

-- Migration 0011 records the authenticated handoff between native content
-- capture and FIFO structural ingest.  The ticket contains only encrypted
-- object identities and the exact source/consent fence needed to reuse them;
-- content remains encrypted in the existing task object store.
CREATE TABLE observation_capture_tickets (
    ticket_id TEXT NOT NULL PRIMARY KEY CHECK (
        length(ticket_id) = 71
        AND substr(ticket_id, 1, 7) = 'sha256:'
        AND substr(ticket_id, 8) NOT GLOB '*[^0-9a-f]*'
    ),
    workspace_commitment TEXT NOT NULL CHECK (length(workspace_commitment) = 76),
    task_id TEXT NOT NULL CHECK (length(task_id) = 40),
    yoetz_session_id TEXT NOT NULL CHECK (length(yoetz_session_id) = 40),
    session_commitment TEXT NOT NULL CHECK (length(session_commitment) = 76),
    source TEXT NOT NULL CHECK (source IN ('claude_hook', 'codex_hook', 'cursor_hook')),
    source_identity TEXT NOT NULL CHECK (length(source_identity) BETWEEN 1 AND 128),
    source_generation INTEGER NOT NULL CHECK (source_generation > 0),
    byte_position INTEGER NOT NULL CHECK (byte_position >= 0),
    event_position INTEGER NOT NULL CHECK (event_position >= 0),
    last_source_commitment TEXT NOT NULL CHECK (length(last_source_commitment) = 76),
    mapping_version TEXT NOT NULL CHECK (length(mapping_version) BETWEEN 1 AND 128),
    logical_identity TEXT NOT NULL CHECK (length(logical_identity) BETWEEN 1 AND 128),
    content_capture_profile TEXT CHECK (
        (source = 'codex_hook' AND content_capture_profile IS NULL)
        OR (
            source IN ('claude_hook', 'cursor_hook')
            AND content_capture_profile IN (
                'claude-code-ordinary-observation-v1',
                'cursor-ordinary-observation-v1'
            )
        )
    ),
    authority_generation TEXT NOT NULL CHECK (
        length(authority_generation) = 71
        AND substr(authority_generation, 1, 7) = 'sha256:'
        AND substr(authority_generation, 8) NOT GLOB '*[^0-9a-f]*'
    ),
    expected_parts_json BLOB NOT NULL CHECK (length(expected_parts_json) BETWEEN 2 AND 8192),
    object_ids_json BLOB NOT NULL CHECK (length(object_ids_json) BETWEEN 2 AND 4096),
    captured_at TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'staging' CHECK (state IN ('staging', 'pending', 'revoked')),
    UNIQUE (workspace_commitment, logical_identity)
) STRICT;

CREATE INDEX observation_capture_tickets_by_workspace
    ON observation_capture_tickets (workspace_commitment, captured_at);

PRAGMA user_version = 11;
PRAGMA application_id = 0x594F4554;
