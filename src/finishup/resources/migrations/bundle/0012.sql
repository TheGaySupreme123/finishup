PRAGMA application_id = 0x594F4554;

-- Migration 0012 records durable observation-advice semantic attempts (issue #619).
-- Hook ingest only enqueues a bounded, minimized packet here; a background worker
-- resolves repository-scoped provider authority at dispatch time and records the
-- outcome. A row that was never attempted, or whose lease was interrupted, is never
-- a semantic success: only 'succeeded' with validated output may add advice.
CREATE TABLE observation_advice_semantic_attempts (
    attempt_id TEXT PRIMARY KEY,
    workspace_commitment TEXT NOT NULL,
    yoetz_session_id TEXT NOT NULL CHECK (length(yoetz_session_id) = 40),
    basis_digest TEXT NOT NULL CHECK (length(basis_digest) BETWEEN 1 AND 128),
    subject_digest TEXT NOT NULL CHECK (
        length(subject_digest) = 71
        AND substr(subject_digest, 1, 7) = 'sha256:'
        AND substr(subject_digest, 8) NOT GLOB '*[^0-9a-f]*'
    ),
    coverage_gaps_json BLOB NOT NULL CHECK (length(coverage_gaps_json) BETWEEN 2 AND 16384),
    packet_json BLOB NOT NULL CHECK (length(packet_json) BETWEEN 2 AND 65536),
    status TEXT NOT NULL CHECK (
        status IN ('pending', 'running', 'succeeded', 'failed', 'unavailable', 'cancelled')
    ),
    failure_reason TEXT CHECK (
        failure_reason IS NULL
        OR failure_reason IN (
            'queue_full',
            'superseded',
            'authorization_missing',
            'provider_unavailable',
            'provider_failed',
            'output_invalid',
            'cancelled',
            'interrupted'
        )
    ),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    state_token INTEGER NOT NULL CHECK (state_token > 0),
    service_generation INTEGER,
    lease_owner TEXT,
    lease_expires_at TEXT,
    attempt_receipt TEXT CHECK (attempt_receipt IS NULL OR length(attempt_receipt) BETWEEN 1 AND 128),
    provider_identity TEXT CHECK (
        provider_identity IS NULL OR length(provider_identity) BETWEEN 1 AND 128
    ),
    finding_ids_json BLOB NOT NULL DEFAULT X'5B5D' CHECK (length(finding_ids_json) BETWEEN 2 AND 4096),
    evidence_digest TEXT CHECK (
        evidence_digest IS NULL
        OR (
            length(evidence_digest) = 71
            AND substr(evidence_digest, 1, 7) = 'sha256:'
            AND substr(evidence_digest, 8) NOT GLOB '*[^0-9a-f]*'
        )
    ),
    summaries_json BLOB NOT NULL DEFAULT X'5B5D' CHECK (length(summaries_json) BETWEEN 2 AND 4096),
    details_json BLOB NOT NULL DEFAULT X'5B5D' CHECK (length(details_json) BETWEEN 2 AND 8192),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (workspace_commitment, yoetz_session_id, basis_digest),
    CHECK (
        (status = 'running'
            AND service_generation IS NOT NULL
            AND lease_owner IS NOT NULL
            AND lease_expires_at IS NOT NULL)
        OR
        (status <> 'running'
            AND service_generation IS NULL
            AND lease_owner IS NULL
            AND lease_expires_at IS NULL)
    ),
    CHECK (
        (status = 'succeeded' AND failure_reason IS NULL)
        OR (status IN ('failed', 'unavailable', 'cancelled') AND failure_reason IS NOT NULL)
        OR (status IN ('pending', 'running') AND failure_reason IS NULL)
    )
) STRICT, WITHOUT ROWID;

CREATE INDEX observation_advice_semantic_attempts_by_workspace
    ON observation_advice_semantic_attempts (workspace_commitment, status, state_token);

CREATE INDEX observation_advice_semantic_attempts_by_session
    ON observation_advice_semantic_attempts (yoetz_session_id, basis_digest);

PRAGMA user_version = 12;
