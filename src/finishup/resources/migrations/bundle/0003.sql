PRAGMA application_id = 0x594F4554;

-- Migration 0003 is intentionally the single unmerged owner for encrypted
-- observation content, workspace bindings, verification authority/results,
-- logical identities, and advice history/delivery.

CREATE TABLE observation_workspace_bindings (
    workspace_commitment TEXT PRIMARY KEY,
    locator_object_id TEXT NOT NULL REFERENCES objects(object_id),
    active INTEGER NOT NULL CHECK (active IN (0, 1)),
    bound_at TEXT NOT NULL,
    revoked_at TEXT,
    CHECK (
        (active = 1 AND revoked_at IS NULL)
        OR (active = 0 AND revoked_at IS NOT NULL)
    )
) STRICT, WITHOUT ROWID;

CREATE TABLE observation_content_manifests (
    object_id TEXT PRIMARY KEY REFERENCES objects(object_id),
    workspace_commitment TEXT NOT NULL,
    logical_identity TEXT NOT NULL,
    content_kind TEXT NOT NULL CHECK (
        content_kind IN (
            'visible_user_message',
            'visible_assistant_message',
            'visible_subagent_message',
            'tool_input',
            'tool_output',
            'changed_file',
            'workspace_diff',
            'approved_check_output',
            'unsupported_visible_payload',
            'workspace_locator'
        )
    ),
    correlation_identity TEXT NOT NULL,
    source_commitment TEXT NOT NULL,
    media_type TEXT NOT NULL,
    part_index INTEGER NOT NULL CHECK (part_index >= 0),
    part_count INTEGER NOT NULL CHECK (part_count > 0 AND part_index < part_count),
    plaintext_size INTEGER NOT NULL CHECK (plaintext_size > 0 AND plaintext_size <= 4194304),
    content_commitment TEXT NOT NULL,
    redacted INTEGER NOT NULL CHECK (redacted IN (0, 1)),
    recorded_at TEXT NOT NULL,
    UNIQUE (
        workspace_commitment,
        logical_identity,
        content_kind,
        correlation_identity,
        source_commitment,
        part_index
    )
) STRICT, WITHOUT ROWID;

CREATE INDEX observation_content_by_logical_identity
    ON observation_content_manifests (
        workspace_commitment,
        logical_identity,
        content_kind,
        correlation_identity,
        part_index
    );

CREATE TABLE observation_logical_identity (
    workspace_commitment TEXT NOT NULL,
    logical_identity TEXT NOT NULL,
    canonical_materialization_digest TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    source_mask INTEGER NOT NULL CHECK (source_mask BETWEEN 1 AND 3),
    mapping_version TEXT NOT NULL,
    materialized_at TEXT NOT NULL,
    PRIMARY KEY (workspace_commitment, logical_identity),
    UNIQUE (workspace_commitment, operation_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE observation_trusted_check_policies (
    workspace_commitment TEXT NOT NULL,
    policy_digest TEXT NOT NULL,
    trust_object_id TEXT NOT NULL REFERENCES objects(object_id),
    state TEXT NOT NULL CHECK (state IN ('trusted', 'revoked', 'superseded')),
    trusted_at TEXT NOT NULL,
    revoked_at TEXT,
    state_token INTEGER NOT NULL CHECK (state_token > 0),
    PRIMARY KEY (workspace_commitment, policy_digest),
    UNIQUE (workspace_commitment, state_token),
    CHECK (
        (state = 'trusted' AND revoked_at IS NULL)
        OR (state <> 'trusted' AND revoked_at IS NOT NULL)
    )
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX observation_one_trusted_policy_per_workspace
    ON observation_trusted_check_policies (workspace_commitment)
    WHERE state = 'trusted';

CREATE TABLE observation_verification_jobs (
    job_id TEXT PRIMARY KEY,
    workspace_commitment TEXT NOT NULL,
    policy_digest TEXT NOT NULL,
    approval_commitment TEXT NOT NULL,
    subject_state_digest TEXT NOT NULL,
    status TEXT NOT NULL CHECK (
        status IN ('pending', 'running', 'complete', 'stale', 'rejected')
    ),
    state_token INTEGER NOT NULL CHECK (state_token > 0),
    service_generation INTEGER,
    lease_owner TEXT,
    lease_generation INTEGER,
    lease_expires_at TEXT,
    enqueued_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (
        workspace_commitment,
        policy_digest,
        approval_commitment,
        subject_state_digest
    ),
    CHECK (
        (status = 'running'
            AND service_generation IS NOT NULL
            AND lease_owner IS NOT NULL
            AND lease_generation IS NOT NULL
            AND lease_generation > 0
            AND lease_expires_at IS NOT NULL)
        OR
        (status <> 'running'
            AND service_generation IS NULL
            AND lease_owner IS NULL
            AND lease_generation IS NULL
            AND lease_expires_at IS NULL)
    )
) STRICT, WITHOUT ROWID;

CREATE INDEX observation_verification_jobs_by_workspace
    ON observation_verification_jobs (workspace_commitment, status, state_token);

CREATE TABLE observation_verification_results (
    result_id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL REFERENCES observation_verification_jobs(job_id),
    workspace_commitment TEXT NOT NULL,
    check_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (
        status IN ('passed', 'failed', 'rejected', 'unavailable', 'stale')
    ),
    subject_state_before TEXT NOT NULL,
    subject_state_after TEXT,
    result_commitment TEXT NOT NULL,
    output_object_id TEXT REFERENCES objects(object_id),
    limitations_json BLOB NOT NULL,
    is_current INTEGER NOT NULL CHECK (is_current IN (0, 1)),
    recorded_at TEXT NOT NULL,
    UNIQUE (job_id, check_id)
) STRICT, WITHOUT ROWID;

CREATE INDEX observation_verification_results_by_workspace
    ON observation_verification_results (workspace_commitment, recorded_at, result_id);

CREATE TABLE observation_advice_history (
    advice_id TEXT PRIMARY KEY,
    workspace_commitment TEXT NOT NULL,
    subject_frontier TEXT NOT NULL,
    evidence_basis_digest TEXT NOT NULL,
    suppression_identity TEXT NOT NULL,
    snapshot_json BLOB NOT NULL,
    verification_state TEXT NOT NULL CHECK (
        verification_state IN ('current', 'stale', 'unavailable', 'not_required')
    ),
    semantic_state TEXT NOT NULL CHECK (
        semantic_state IN ('ready', 'disabled', 'unavailable', 'failed')
    ),
    freshness TEXT NOT NULL CHECK (
        freshness IN ('current', 'partial', 'stale_after_material_change', 'unknown')
    ),
    recorded_at TEXT NOT NULL,
    UNIQUE (workspace_commitment, suppression_identity, evidence_basis_digest)
) STRICT, WITHOUT ROWID;

CREATE INDEX observation_advice_history_by_frontier
    ON observation_advice_history (workspace_commitment, subject_frontier, recorded_at);

CREATE TABLE observation_advice_delivery (
    advice_id TEXT NOT NULL REFERENCES observation_advice_history(advice_id),
    channel TEXT NOT NULL CHECK (channel IN ('hook', 'status', 'finding')),
    attempt INTEGER NOT NULL CHECK (attempt > 0),
    outcome TEXT NOT NULL CHECK (outcome IN ('delivered', 'suppressed', 'failed')),
    attempted_at TEXT NOT NULL,
    PRIMARY KEY (advice_id, channel, attempt)
) STRICT, WITHOUT ROWID;

PRAGMA user_version = 3;
