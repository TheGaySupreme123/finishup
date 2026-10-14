PRAGMA application_id = 0x594F4554;

CREATE TABLE catalog_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT, WITHOUT ROWID;

CREATE TABLE task_routes (
    task_id TEXT PRIMARY KEY,
    workspace_ref_commitment TEXT,
    external_ref_commitment TEXT,
    active_session_id TEXT NOT NULL UNIQUE,
    bundle_relpath TEXT NOT NULL UNIQUE,
    route_generation INTEGER NOT NULL CHECK (route_generation > 0),
    active_route_identity_digest TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL CHECK (state IN ('initializing', 'active', 'quarantined')),
    quarantine_code TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK (
        (workspace_ref_commitment IS NULL AND external_ref_commitment IS NULL)
        OR
        (workspace_ref_commitment IS NOT NULL AND external_ref_commitment IS NOT NULL)
    ),
    CHECK (
        (state IN ('initializing', 'active') AND quarantine_code IS NULL)
        OR
        (state = 'quarantined' AND quarantine_code IS NOT NULL)
    )
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX task_routes_scoped_attachment
ON task_routes(workspace_ref_commitment, external_ref_commitment)
WHERE workspace_ref_commitment IS NOT NULL
  AND external_ref_commitment IS NOT NULL;

CREATE TABLE start_operations (
    installation_id TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    requested_mode TEXT NOT NULL
        CHECK (requested_mode IN ('create', 'attach', 'create_or_attach')),
    route_action TEXT NOT NULL CHECK (route_action IN ('created', 'attached')),
    state TEXT NOT NULL CHECK (state IN ('pending', 'complete', 'quarantined')),
    phase TEXT NOT NULL CHECK (phase IN (
        'route_reserved',
        'bundle_ready',
        'lifecycle_committed',
        'result_published',
        'terminal'
    )),
    task_id TEXT NOT NULL REFERENCES task_routes(task_id),
    session_id TEXT NOT NULL,
    writer_id TEXT NOT NULL,
    lifecycle_event_id TEXT NOT NULL,
    route_generation INTEGER NOT NULL CHECK (route_generation > 0),
    route_identity_digest TEXT NOT NULL,
    owner_generation TEXT,
    lease_owner_id TEXT,
    lease_generation INTEGER CHECK (lease_generation > 0),
    lease_expires_at TEXT,
    response_object_id TEXT,
    response_envelope_digest TEXT,
    terminal_result_canonical BLOB,
    terminal_result_digest TEXT,
    quarantine_code TEXT,
    terminal_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (installation_id, operation_id),
    CHECK (
        (
            state = 'pending'
            AND phase != 'terminal'
            AND owner_generation IS NOT NULL
            AND lease_owner_id IS NOT NULL
            AND lease_generation IS NOT NULL
            AND lease_expires_at IS NOT NULL
            AND quarantine_code IS NULL
            AND terminal_at IS NULL
            AND (
                (
                    phase = 'result_published'
                    AND response_object_id IS NOT NULL
                    AND response_envelope_digest IS NOT NULL
                    AND terminal_result_canonical IS NOT NULL
                    AND terminal_result_digest IS NOT NULL
                )
                OR
                (
                    phase != 'result_published'
                    AND response_object_id IS NULL
                    AND response_envelope_digest IS NULL
                    AND terminal_result_canonical IS NULL
                    AND terminal_result_digest IS NULL
                )
            )
        )
        OR
        (
            state = 'complete'
            AND phase = 'terminal'
            AND owner_generation IS NULL
            AND lease_owner_id IS NULL
            AND lease_generation IS NULL
            AND lease_expires_at IS NULL
            AND response_object_id IS NOT NULL
            AND response_envelope_digest IS NOT NULL
            AND terminal_result_canonical IS NOT NULL
            AND terminal_result_digest IS NOT NULL
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
            AND response_object_id IS NULL
            AND response_envelope_digest IS NULL
            AND terminal_result_canonical IS NOT NULL
            AND terminal_result_digest IS NOT NULL
            AND quarantine_code IS NOT NULL
            AND terminal_at IS NOT NULL
        )
    )
) STRICT, WITHOUT ROWID;

CREATE TABLE privacy_policy_versions (
    policy_id TEXT NOT NULL,
    policy_version INTEGER NOT NULL CHECK (policy_version > 0),
    scope_digest TEXT NOT NULL,
    scope_kind TEXT NOT NULL
        CHECK (scope_kind IN ('machine', 'workspace', 'task', 'request')),
    installation_id TEXT NOT NULL,
    workspace_ref_commitment TEXT,
    task_id TEXT REFERENCES task_routes(task_id),
    request_id TEXT,
    policy_digest TEXT NOT NULL,
    policy_canonical BLOB NOT NULL,
    policy_generation INTEGER NOT NULL UNIQUE CHECK (policy_generation > 0),
    change_kind TEXT NOT NULL
        CHECK (change_kind IN ('seed', 'tightening', 'human_expansion')),
    source_proposal_id TEXT,
    state TEXT NOT NULL CHECK (state IN ('current', 'superseded')),
    created_at TEXT NOT NULL,
    superseded_at TEXT,
    PRIMARY KEY (policy_id, policy_version),
    UNIQUE (scope_digest, policy_version),
    CHECK (
        (scope_kind = 'machine'
            AND workspace_ref_commitment IS NULL AND task_id IS NULL AND request_id IS NULL)
        OR (scope_kind = 'workspace'
            AND workspace_ref_commitment IS NOT NULL AND task_id IS NULL AND request_id IS NULL)
        OR (scope_kind = 'task'
            AND workspace_ref_commitment IS NOT NULL AND task_id IS NOT NULL AND request_id IS NULL)
        OR (scope_kind = 'request'
            AND workspace_ref_commitment IS NOT NULL AND task_id IS NOT NULL AND request_id IS NOT NULL)
    ),
    CHECK (
        (change_kind = 'human_expansion' AND source_proposal_id IS NOT NULL)
        OR (change_kind IN ('seed', 'tightening') AND source_proposal_id IS NULL)
    ),
    CHECK (
        (state = 'current' AND superseded_at IS NULL)
        OR (state = 'superseded' AND superseded_at IS NOT NULL)
    )
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX privacy_policy_versions_one_current_scope
ON privacy_policy_versions(scope_digest)
WHERE state = 'current';

CREATE TABLE privacy_policy_transitions (
    proposal_id TEXT PRIMARY KEY,
    scope_digest TEXT NOT NULL,
    base_policy_id TEXT NOT NULL,
    base_policy_version INTEGER NOT NULL CHECK (base_policy_version > 0),
    base_policy_generation INTEGER NOT NULL CHECK (base_policy_generation > 0),
    proposal_digest TEXT NOT NULL UNIQUE,
    candidate_policy_digest TEXT NOT NULL,
    candidate_policy_canonical BLOB NOT NULL,
    diff_canonical BLOB NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'committed', 'denied', 'expired', 'stale')),
    human_decision TEXT CHECK (human_decision IN ('approved', 'denied')),
    decision_digest TEXT,
    authority_commitment TEXT,
    committed_policy_id TEXT,
    committed_policy_version INTEGER CHECK (committed_policy_version > 0),
    expires_at TEXT NOT NULL,
    terminal_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (base_policy_id, base_policy_version)
        REFERENCES privacy_policy_versions(policy_id, policy_version),
    FOREIGN KEY (committed_policy_id, committed_policy_version)
        REFERENCES privacy_policy_versions(policy_id, policy_version),
    CHECK (
        (state = 'pending'
            AND human_decision IS NULL AND decision_digest IS NULL
            AND authority_commitment IS NULL AND committed_policy_id IS NULL
            AND committed_policy_version IS NULL AND terminal_at IS NULL)
        OR (state = 'committed'
            AND human_decision = 'approved' AND decision_digest IS NOT NULL
            AND authority_commitment IS NOT NULL AND committed_policy_id IS NOT NULL
            AND committed_policy_version IS NOT NULL AND terminal_at IS NOT NULL)
        OR (state = 'denied'
            AND human_decision = 'denied' AND decision_digest IS NOT NULL
            AND authority_commitment IS NULL AND committed_policy_id IS NULL
            AND committed_policy_version IS NULL AND terminal_at IS NOT NULL)
        OR (state IN ('expired', 'stale')
            AND human_decision IS NULL AND decision_digest IS NULL
            AND authority_commitment IS NULL AND committed_policy_id IS NULL
            AND committed_policy_version IS NULL AND terminal_at IS NOT NULL)
    )
) STRICT, WITHOUT ROWID;

CREATE INDEX privacy_policy_transitions_scope_state
ON privacy_policy_transitions(scope_digest, state, expires_at);

CREATE TABLE privacy_audit_records (
    proposal_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    originating_workflow_request_id TEXT,
    control_rpc_id TEXT,
    control_method TEXT,
    service_instance_id TEXT,
    service_generation INTEGER CHECK (service_generation > 0),
    control_request_commitment TEXT,
    subject_lookup_identity TEXT NOT NULL,
    subject_kind TEXT NOT NULL
        CHECK (subject_kind IN ('pre_dispatch', 'agent_projection', 'disclosure')),
    destination_kind TEXT NOT NULL CHECK (destination_kind IN ('network', 'local')),
    channel TEXT CHECK (channel IN (
        'llm_inference', 'product_telemetry', 'crash_diagnostics',
        'update_checks', 'capability_testing'
    )),
    local_sink TEXT CHECK (local_sink IN (
        'local_model', 'agent_context', 'local_human_view', 'trusted_human_control'
    )),
    provider_id TEXT,
    model_id TEXT,
    endpoint_profile_id TEXT,
    endpoint_profile_version TEXT,
    purpose TEXT NOT NULL,
    scope_kind TEXT NOT NULL
        CHECK (scope_kind IN ('machine', 'workspace', 'task', 'request')),
    scope_digest TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    policy_version INTEGER NOT NULL CHECK (policy_version > 0),
    policy_digest TEXT NOT NULL,
    subject_structural_canonical BLOB NOT NULL,
    task_id TEXT REFERENCES task_routes(task_id),
    route_identity_digest TEXT,
    content_object_id TEXT UNIQUE,
    content_object_kind TEXT CHECK (content_object_kind = 'privacy_audit'),
    content_plaintext_size INTEGER CHECK (content_plaintext_size >= 0),
    content_commitment TEXT,
    content_envelope_digest TEXT,
    content_encryption_format TEXT CHECK (content_encryption_format = 'yoetz-object/1'),
    content_key_slot TEXT,
    content_media_type TEXT,
    content_created_at TEXT,
    state TEXT NOT NULL CHECK (state IN (
        'decision_receipt_pending', 'decision_completed', 'reserved', 'awaiting_human',
        'approved', 'authorized', 'receipt_pending', 'attempt_completed',
        'local_disclosure_pending', 'local_disclosure_completed',
        'denied', 'expired', 'quarantined'
    )),
    consent_source TEXT CHECK (consent_source IN (
        'none', 'baseline_policy', 'scoped_local_human', 'per_request_local_human'
    )),
    decision_structural_canonical BLOB,
    decision_commitment TEXT,
    approval_binding_commitment TEXT,
    authorization_id TEXT UNIQUE,
    authorization_structural_canonical BLOB,
    authorization_commitment TEXT,
    dispatch_id TEXT UNIQUE,
    dispatch_started_at TEXT,
    consumed_at TEXT,
    attempt_result_structural_canonical BLOB,
    attempt_result_commitment TEXT,
    receipt_id TEXT UNIQUE,
    receipt_outcome TEXT CHECK (receipt_outcome IN (
        'blocked_by_policy', 'blocked_forbidden_data', 'classification_uncertain',
        'human_denied', 'approval_expired', 'channel_unavailable', 'provider_refused',
        'timeout', 'invalid_response', 'transport_failed', 'late', 'stale',
        'audit_failed', 'completed'
    )),
    receipt_reason TEXT CHECK (receipt_reason IN (
        'policy_denied', 'never_send_detected', 'classification_uncertain', 'scope_mismatch',
        'purpose_not_allowed', 'destination_not_allowed', 'category_not_allowed',
        'channel_unavailable', 'human_denied', 'authorization_expired',
        'authorization_stale', 'authorization_reused', 'insufficient_approved_context',
        'provider_unavailable', 'provider_refused', 'provider_timeout',
        'provider_invalid_response', 'transport_failed', 'audit_failed', 'deadline_expired',
        'late', 'stale', 'outcome_unknown'
    )),
    receipt_canonical BLOB,
    receipt_digest TEXT,
    receipt_finished_at TEXT,
    audit_store_version INTEGER NOT NULL DEFAULT 1 CHECK (audit_store_version = 1),
    expires_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (request_id, subject_lookup_identity),
    CHECK (
        (destination_kind = 'network' AND channel IS NOT NULL AND local_sink IS NULL)
        OR (destination_kind = 'local' AND channel IS NULL AND local_sink IS NOT NULL)
    ),
    CHECK (
        (content_object_id IS NULL AND content_object_kind IS NULL
            AND content_plaintext_size IS NULL AND content_commitment IS NULL
            AND content_envelope_digest IS NULL AND content_encryption_format IS NULL
            AND content_key_slot IS NULL AND content_media_type IS NULL
            AND content_created_at IS NULL)
        OR (content_object_id IS NOT NULL AND content_object_kind = 'privacy_audit'
            AND content_plaintext_size IS NOT NULL AND content_commitment IS NOT NULL
            AND content_envelope_digest IS NOT NULL AND content_encryption_format = 'yoetz-object/1'
            AND content_key_slot IS NOT NULL AND content_media_type IS NOT NULL
            AND content_created_at IS NOT NULL AND task_id IS NOT NULL
            AND route_identity_digest IS NOT NULL)
    ),
    CHECK (
        subject_kind != 'pre_dispatch'
        OR (content_object_id IS NULL
            AND originating_workflow_request_id IS NULL
            AND control_rpc_id IS NULL AND control_method IS NULL
            AND service_instance_id IS NULL AND service_generation IS NULL
            AND control_request_commitment IS NULL
            AND state IN ('decision_receipt_pending', 'decision_completed', 'quarantined')
            AND approval_binding_commitment IS NULL
            AND authorization_id IS NULL AND dispatch_id IS NULL AND consumed_at IS NULL)
    ),
    CHECK (
        subject_kind != 'agent_projection'
        OR (destination_kind = 'local' AND local_sink IN ('agent_context', 'local_human_view')
            AND purpose = 'client_result_projection'
            AND control_rpc_id IS NOT NULL AND control_method IS NOT NULL
            AND service_instance_id IS NOT NULL AND service_generation IS NOT NULL
            AND control_request_commitment IS NOT NULL AND content_object_id IS NULL
            AND ((scope_kind IN ('machine', 'workspace')
                    AND task_id IS NULL AND route_identity_digest IS NULL)
                OR (scope_kind IN ('task', 'request')
                    AND task_id IS NOT NULL AND route_identity_digest IS NOT NULL))
            AND authorization_id IS NULL AND dispatch_id IS NULL
            AND state IN ('approved', 'local_disclosure_pending',
                'local_disclosure_completed', 'quarantined'))
    ),
    CHECK (
        subject_kind != 'disclosure'
        OR (content_object_id IS NOT NULL
            AND originating_workflow_request_id IS NULL
            AND control_rpc_id IS NULL AND control_method IS NULL
            AND service_instance_id IS NULL AND service_generation IS NULL
            AND control_request_commitment IS NULL)
    ),
    CHECK (
        destination_kind != 'network'
        OR state NOT IN ('local_disclosure_pending', 'local_disclosure_completed')
    ),
    CHECK (
        destination_kind != 'local'
        OR (state NOT IN ('authorized', 'receipt_pending', 'attempt_completed')
            AND authorization_id IS NULL AND authorization_structural_canonical IS NULL
            AND authorization_commitment IS NULL AND dispatch_id IS NULL
            AND dispatch_started_at IS NULL)
    ),
    CHECK (
        state != 'authorized'
        OR (approval_binding_commitment IS NOT NULL AND authorization_id IS NOT NULL
            AND authorization_structural_canonical IS NOT NULL
            AND authorization_commitment IS NOT NULL
            AND dispatch_id IS NULL AND consumed_at IS NULL AND receipt_id IS NULL)
    ),
    CHECK (
        state != 'receipt_pending'
        OR (authorization_id IS NOT NULL AND dispatch_id IS NOT NULL
            AND dispatch_started_at IS NOT NULL AND consumed_at IS NOT NULL
            AND receipt_id IS NULL)
    ),
    CHECK (
        state != 'local_disclosure_pending'
        OR (approval_binding_commitment IS NOT NULL
            AND consumed_at IS NOT NULL AND receipt_id IS NULL)
    ),
    CHECK (
        (receipt_id IS NULL AND receipt_outcome IS NULL AND receipt_reason IS NULL
            AND receipt_canonical IS NULL AND receipt_digest IS NULL
            AND receipt_finished_at IS NULL)
        OR (receipt_id IS NOT NULL AND receipt_outcome IS NOT NULL
            AND receipt_canonical IS NOT NULL AND receipt_digest IS NOT NULL
            AND receipt_finished_at IS NOT NULL
            AND ((receipt_outcome = 'completed' AND receipt_reason IS NULL)
                OR (receipt_outcome != 'completed' AND receipt_reason IS NOT NULL)))
    ),
    CHECK (
        receipt_id IS NULL
        OR (receipt_outcome = 'blocked_by_policy' AND receipt_reason IN (
                'policy_denied', 'scope_mismatch', 'purpose_not_allowed',
                'destination_not_allowed', 'category_not_allowed',
                'insufficient_approved_context'))
        OR (receipt_outcome = 'blocked_forbidden_data' AND receipt_reason = 'never_send_detected')
        OR (receipt_outcome = 'classification_uncertain' AND receipt_reason = 'classification_uncertain')
        OR (receipt_outcome = 'human_denied' AND receipt_reason = 'human_denied')
        OR (receipt_outcome = 'approval_expired' AND receipt_reason IN (
                'authorization_expired', 'authorization_stale', 'authorization_reused'))
        OR (receipt_outcome = 'channel_unavailable' AND receipt_reason = 'channel_unavailable')
        OR (receipt_outcome = 'provider_refused' AND receipt_reason = 'provider_refused')
        OR (receipt_outcome = 'timeout' AND receipt_reason IN ('provider_timeout', 'deadline_expired'))
        OR (receipt_outcome = 'invalid_response' AND receipt_reason = 'provider_invalid_response')
        OR (receipt_outcome = 'transport_failed' AND receipt_reason IN (
                'provider_unavailable', 'transport_failed', 'outcome_unknown'))
        OR (receipt_outcome = 'late' AND receipt_reason = 'late')
        OR (receipt_outcome = 'stale' AND receipt_reason = 'stale')
        OR (receipt_outcome = 'audit_failed' AND receipt_reason = 'audit_failed')
        OR (receipt_outcome = 'completed' AND receipt_reason IS NULL)
    ),
    CHECK (
        state NOT IN ('decision_completed', 'attempt_completed',
            'local_disclosure_completed', 'denied', 'expired')
        OR receipt_id IS NOT NULL
    ),
    CHECK (state != 'attempt_completed' OR (
        authorization_id IS NOT NULL AND dispatch_id IS NOT NULL AND consumed_at IS NOT NULL
        AND attempt_result_structural_canonical IS NOT NULL
        AND attempt_result_commitment IS NOT NULL)),
    CHECK (state != 'local_disclosure_completed' OR (
        consumed_at IS NOT NULL AND attempt_result_structural_canonical IS NOT NULL
        AND attempt_result_commitment IS NOT NULL))
) STRICT, WITHOUT ROWID;

CREATE INDEX privacy_audit_task_roots
ON privacy_audit_records(task_id, content_object_id)
WHERE content_object_id IS NOT NULL;

CREATE INDEX privacy_audit_receipt_order
ON privacy_audit_records(receipt_finished_at DESC, receipt_id DESC)
WHERE receipt_id IS NOT NULL;

CREATE INDEX privacy_audit_receipt_filter
ON privacy_audit_records(
    receipt_outcome, channel, local_sink, provider_id, endpoint_profile_id,
    policy_version, scope_kind, receipt_finished_at
)
WHERE receipt_id IS NOT NULL;

CREATE TABLE privacy_root_sets (
    task_id TEXT PRIMARY KEY REFERENCES task_routes(task_id),
    route_identity_digest TEXT NOT NULL,
    root_generation INTEGER NOT NULL CHECK (root_generation >= 0),
    root_count INTEGER NOT NULL CHECK (root_count >= 0),
    root_digest TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT, WITHOUT ROWID;

CREATE TABLE maintenance_operations (
    installation_id TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    task_id TEXT NOT NULL REFERENCES task_routes(task_id),
    kind TEXT NOT NULL CHECK (kind IN ('backup', 'restore', 'migration')),
    request_digest TEXT NOT NULL,
    plan_digest TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'complete', 'quarantined')),
    phase TEXT NOT NULL CHECK (phase IN (
        'reserved',
        'pinned', 'database_ready', 'objects_ready', 'manifest_ready',
        'source_verified', 'target_ready', 'target_verified', 'route_switched',
        'backup_ready', 'schema_applied', 'replay_verified',
        'terminal'
    )),
    subject_frontier_seq INTEGER NOT NULL CHECK (subject_frontier_seq >= 0),
    subject_frontier_digest TEXT NOT NULL,
    privacy_root_generation INTEGER NOT NULL CHECK (privacy_root_generation >= 0),
    privacy_root_digest TEXT NOT NULL,
    source_route_identity_digest TEXT NOT NULL,
    target_route_identity_digest TEXT,
    source_location_commitment TEXT,
    target_location_commitment TEXT,
    backup_mode TEXT NOT NULL
        CHECK (backup_mode IN ('machine_bound', 'portable_recovery')),
    requested_target_version TEXT,
    owner_generation TEXT,
    lease_owner_id TEXT,
    lease_generation INTEGER CHECK (lease_generation > 0),
    lease_expires_at TEXT,
    backup_manifest_digest TEXT,
    result_canonical BLOB,
    result_digest TEXT,
    quarantine_code TEXT,
    terminal_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (installation_id, operation_id),
    CHECK (
        (kind = 'backup' AND phase IN (
            'reserved', 'pinned', 'database_ready', 'objects_ready',
            'manifest_ready', 'terminal'
        ))
        OR
        (kind = 'restore' AND phase IN (
            'reserved', 'source_verified', 'target_ready', 'target_verified',
            'route_switched', 'terminal'
        ))
        OR
        (kind = 'migration' AND phase IN (
            'reserved', 'backup_ready', 'schema_applied', 'replay_verified', 'terminal'
        ))
    ),
    CHECK (
        (kind = 'backup'
            AND source_location_commitment IS NULL
            AND target_location_commitment IS NOT NULL
            AND target_route_identity_digest IS NULL
            AND requested_target_version IS NULL)
        OR
        (kind = 'restore'
            AND source_location_commitment IS NOT NULL
            AND target_location_commitment IS NULL
            AND requested_target_version IS NULL)
        OR
        (kind = 'migration'
            AND source_location_commitment IS NULL
            AND target_location_commitment IS NULL
            AND target_route_identity_digest IS NULL
            AND requested_target_version IS NOT NULL)
    ),
    CHECK (
        state != 'pending'
        OR
        (kind = 'backup'
            AND (
                phase IN ('reserved', 'pinned', 'database_ready', 'objects_ready')
                OR (phase = 'manifest_ready' AND backup_manifest_digest IS NOT NULL)
            ))
        OR
        (kind = 'restore'
            AND (
                phase = 'reserved'
                OR (phase = 'source_verified' AND backup_manifest_digest IS NOT NULL)
                OR (phase IN ('target_ready', 'target_verified', 'route_switched')
                    AND backup_manifest_digest IS NOT NULL
                    AND target_route_identity_digest IS NOT NULL)
            ))
        OR
        (kind = 'migration'
            AND (
                phase = 'reserved'
                OR (phase IN ('backup_ready', 'schema_applied', 'replay_verified')
                    AND backup_manifest_digest IS NOT NULL)
            ))
    ),
    CHECK (
        (state = 'pending'
            AND phase != 'terminal'
            AND owner_generation IS NOT NULL
            AND lease_owner_id IS NOT NULL
            AND lease_generation IS NOT NULL
            AND lease_expires_at IS NOT NULL
            AND result_canonical IS NULL
            AND result_digest IS NULL
            AND quarantine_code IS NULL
            AND terminal_at IS NULL)
        OR
        (state = 'complete'
            AND phase = 'terminal'
            AND owner_generation IS NULL
            AND lease_owner_id IS NULL
            AND lease_generation IS NULL
            AND lease_expires_at IS NULL
            AND backup_manifest_digest IS NOT NULL
            AND result_canonical IS NOT NULL
            AND result_digest IS NOT NULL
            AND quarantine_code IS NULL
            AND terminal_at IS NOT NULL)
        OR
        (state = 'quarantined'
            AND phase = 'terminal'
            AND owner_generation IS NULL
            AND lease_owner_id IS NULL
            AND lease_generation IS NULL
            AND lease_expires_at IS NULL
            AND result_canonical IS NOT NULL
            AND result_digest IS NOT NULL
            AND quarantine_code IS NOT NULL
            AND terminal_at IS NOT NULL)
    )
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX maintenance_operations_one_pending_task
ON maintenance_operations(task_id)
WHERE state = 'pending';

CREATE INDEX maintenance_operations_task_state
ON maintenance_operations(task_id, state, kind);

CREATE TABLE retained_task_routes (
    installation_id TEXT NOT NULL,
    task_id TEXT NOT NULL REFERENCES task_routes(task_id),
    route_generation INTEGER NOT NULL CHECK (route_generation > 0),
    bundle_relpath TEXT NOT NULL UNIQUE,
    route_identity_digest TEXT NOT NULL UNIQUE,
    retained_by_operation_id TEXT NOT NULL,
    retained_reason TEXT NOT NULL
        CHECK (retained_reason IN ('restore_replaced', 'migration_rollback', 'quarantine')),
    state TEXT NOT NULL CHECK (state IN ('retained', 'quarantined', 'released')),
    quarantine_code TEXT,
    frontier_seq INTEGER NOT NULL CHECK (frontier_seq >= 0),
    frontier_digest TEXT NOT NULL,
    retained_at TEXT NOT NULL,
    released_at TEXT,
    PRIMARY KEY (installation_id, task_id, route_generation),
    FOREIGN KEY (installation_id, retained_by_operation_id)
        REFERENCES maintenance_operations(installation_id, operation_id),
    CHECK (
        (state = 'retained' AND quarantine_code IS NULL AND released_at IS NULL)
        OR
        (state = 'quarantined' AND quarantine_code IS NOT NULL AND released_at IS NULL)
        OR
        (state = 'released' AND released_at IS NOT NULL)
    )
) STRICT, WITHOUT ROWID;

CREATE INDEX retained_task_routes_task_state
ON retained_task_routes(task_id, state, route_generation);

PRAGMA user_version = 1;
