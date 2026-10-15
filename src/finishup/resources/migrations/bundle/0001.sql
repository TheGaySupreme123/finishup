PRAGMA application_id = 0x594F4554;

CREATE TABLE bundle_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT, WITHOUT ROWID;

CREATE TABLE counters (
    name TEXT PRIMARY KEY,
    next_value INTEGER NOT NULL CHECK (next_value > 0)
) STRICT, WITHOUT ROWID;

CREATE TABLE writers (
    writer_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    next_writer_seq INTEGER NOT NULL CHECK (next_writer_seq > 0),
    head_entry_digest TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('active', 'closed', 'quarantined')),
    created_at TEXT NOT NULL
) STRICT, WITHOUT ROWID;

CREATE TABLE operations (
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

CREATE TABLE objects (
    object_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    plaintext_size INTEGER NOT NULL CHECK (plaintext_size >= 0),
    commitment TEXT NOT NULL,
    envelope_digest TEXT NOT NULL,
    encryption_format TEXT NOT NULL,
    key_slot TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('present', 'redacted', 'missing', 'quarantined')),
    durable_at TEXT NOT NULL
) STRICT, WITHOUT ROWID;

CREATE TABLE import_jobs (
    source_identity_digest TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    source_commitment TEXT NOT NULL,
    codex_capability_profile_id TEXT NOT NULL,
    mapping_version TEXT NOT NULL,
    publishing_writer_id TEXT NOT NULL REFERENCES writers(writer_id),
    source_object_id TEXT NOT NULL REFERENCES objects(object_id),
    capture_metadata_object_id TEXT NOT NULL REFERENCES objects(object_id),
    capture_metadata_object_commitment TEXT NOT NULL,
    source_byte_count INTEGER NOT NULL
        CHECK (source_byte_count BETWEEN 0 AND 4194304),
    source_line_count INTEGER NOT NULL
        CHECK (source_line_count BETWEEN 0 AND 20000),
    source_final_newline INTEGER NOT NULL CHECK (source_final_newline IN (0, 1)),
    codex_version TEXT NOT NULL,
    source_kind TEXT NOT NULL CHECK (source_kind IN ('file', 'stdin')),
    source_exit_status INTEGER
        CHECK (source_exit_status BETWEEN -2147483648 AND 2147483647),
    stderr_present INTEGER NOT NULL CHECK (stderr_present IN (0, 1)),
    stderr_captured_byte_count INTEGER NOT NULL
        CHECK (stderr_captured_byte_count BETWEEN 0 AND 65536),
    stderr_truncated INTEGER NOT NULL CHECK (stderr_truncated IN (0, 1)),
    stderr_commitment TEXT,
    metadata_digest TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'complete', 'quarantined')),
    phase TEXT NOT NULL CHECK (phase IN (
        'source_reserved',
        'plan_ready',
        'publishing',
        'report_ready',
        'report_published',
        'terminal'
    )),
    job_revision INTEGER NOT NULL CHECK (job_revision >= 0),
    owner_generation TEXT,
    lease_owner_id TEXT,
    lease_generation INTEGER CHECK (lease_generation > 0),
    lease_expires_at TEXT,
    plan_digest TEXT,
    batch_count INTEGER NOT NULL CHECK (batch_count BETWEEN 0 AND 1024),
    completed_batch_count INTEGER NOT NULL
        CHECK (completed_batch_count BETWEEN 0 AND batch_count),
    report_request_id TEXT,
    report_event_id TEXT,
    report_evidence_id TEXT,
    report_object_id TEXT REFERENCES objects(object_id),
    report_digest TEXT,
    report_result_canonical BLOB,
    report_result_digest TEXT,
    report_evidence_draft_canonical BLOB,
    report_evidence_draft_digest TEXT,
    report_append_result_canonical BLOB,
    report_append_result_digest TEXT,
    report_ingestion_seq INTEGER CHECK (report_ingestion_seq > 0),
    report_entry_digest TEXT,
    terminal_result_canonical BLOB,
    terminal_result_digest TEXT,
    quarantine_code TEXT CHECK (quarantine_code IN (
        'import_source_identity_contradiction',
        'import_object_identity_contradiction',
        'import_plan_identity_contradiction',
        'import_batch_identity_contradiction',
        'import_report_identity_contradiction',
        'import_phase_state_contradiction',
        'import_commit_state_ambiguous'
    )),
    terminal_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK (
        (
            stderr_present = 0
            AND stderr_captured_byte_count = 0
            AND stderr_truncated = 0
            AND stderr_commitment IS NULL
        )
        OR
        (
            stderr_present = 1
            AND stderr_commitment IS NOT NULL
            AND (
                stderr_truncated = 0
                OR stderr_captured_byte_count = 65536
            )
        )
    ),
    CHECK (
        (
            plan_digest IS NULL
            AND report_request_id IS NULL
            AND report_event_id IS NULL
            AND report_evidence_id IS NULL
        )
        OR
        (
            plan_digest IS NOT NULL
            AND report_request_id IS NOT NULL
            AND report_event_id IS NOT NULL
            AND report_evidence_id IS NOT NULL
        )
    ),
    CHECK (
        (
            report_object_id IS NULL
            AND report_digest IS NULL
            AND report_result_canonical IS NULL
            AND report_result_digest IS NULL
            AND report_evidence_draft_canonical IS NULL
            AND report_evidence_draft_digest IS NULL
        )
        OR
        (
            report_object_id IS NOT NULL
            AND report_digest IS NOT NULL
            AND report_result_canonical IS NOT NULL
            AND report_result_digest IS NOT NULL
            AND report_evidence_draft_canonical IS NOT NULL
            AND report_evidence_draft_digest IS NOT NULL
        )
    ),
    CHECK (
        (
            report_append_result_canonical IS NULL
            AND report_append_result_digest IS NULL
            AND report_ingestion_seq IS NULL
            AND report_entry_digest IS NULL
        )
        OR
        (
            report_append_result_canonical IS NOT NULL
            AND report_append_result_digest IS NOT NULL
            AND report_ingestion_seq IS NOT NULL
            AND report_entry_digest IS NOT NULL
        )
    ),
    CHECK (report_object_id IS NULL OR plan_digest IS NOT NULL),
    CHECK (report_append_result_canonical IS NULL OR report_object_id IS NOT NULL),
    CHECK (
        (
            state = 'pending'
            AND phase != 'terminal'
            AND owner_generation IS NOT NULL
            AND lease_owner_id IS NOT NULL
            AND lease_generation IS NOT NULL
            AND lease_expires_at IS NOT NULL
            AND terminal_result_canonical IS NULL
            AND terminal_result_digest IS NULL
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
            AND terminal_result_canonical IS NOT NULL
            AND terminal_result_digest IS NOT NULL
            AND quarantine_code IS NOT NULL
            AND terminal_at IS NOT NULL
        )
    ),
    CHECK (
        (
            state = 'pending'
            AND phase = 'source_reserved'
            AND plan_digest IS NULL
            AND batch_count = 0
            AND completed_batch_count = 0
            AND report_object_id IS NULL
            AND report_append_result_canonical IS NULL
        )
        OR
        (
            state = 'pending'
            AND phase = 'plan_ready'
            AND plan_digest IS NOT NULL
            AND completed_batch_count = 0
            AND report_object_id IS NULL
            AND report_append_result_canonical IS NULL
        )
        OR
        (
            state = 'pending'
            AND phase = 'publishing'
            AND plan_digest IS NOT NULL
            AND batch_count > 0
            AND completed_batch_count > 0
            AND report_object_id IS NULL
            AND report_append_result_canonical IS NULL
        )
        OR
        (
            state = 'pending'
            AND phase = 'report_ready'
            AND plan_digest IS NOT NULL
            AND completed_batch_count = batch_count
            AND report_object_id IS NOT NULL
            AND report_append_result_canonical IS NULL
        )
        OR
        (
            state = 'pending'
            AND phase = 'report_published'
            AND plan_digest IS NOT NULL
            AND completed_batch_count = batch_count
            AND report_object_id IS NOT NULL
            AND report_append_result_canonical IS NOT NULL
        )
        OR
        (
            state = 'complete'
            AND phase = 'terminal'
            AND plan_digest IS NOT NULL
            AND completed_batch_count = batch_count
            AND report_object_id IS NOT NULL
            AND report_append_result_canonical IS NOT NULL
        )
        OR
        (state = 'quarantined' AND phase = 'terminal')
    )
) STRICT, WITHOUT ROWID;

CREATE TABLE import_request_aliases (
    requesting_writer_id TEXT NOT NULL REFERENCES writers(writer_id),
    request_id TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    source_identity_digest TEXT NOT NULL REFERENCES import_jobs(source_identity_digest),
    created_at TEXT NOT NULL,
    PRIMARY KEY (requesting_writer_id, request_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE import_batches (
    source_identity_digest TEXT NOT NULL REFERENCES import_jobs(source_identity_digest),
    batch_index INTEGER NOT NULL CHECK (batch_index BETWEEN 0 AND 1023),
    state TEXT NOT NULL CHECK (state IN ('planned', 'complete')),
    request_id TEXT NOT NULL,
    plan_object_id TEXT NOT NULL REFERENCES objects(object_id),
    plan_object_commitment TEXT NOT NULL,
    plan_digest TEXT NOT NULL,
    event_ids_canonical BLOB NOT NULL,
    event_ids_digest TEXT NOT NULL,
    event_count INTEGER NOT NULL CHECK (event_count BETWEEN 1 AND 100),
    append_result_canonical BLOB,
    append_result_digest TEXT,
    subject_frontier_seq INTEGER CHECK (subject_frontier_seq >= 0),
    subject_frontier_digest TEXT,
    result_frontier_seq INTEGER CHECK (result_frontier_seq > 0),
    result_frontier_digest TEXT,
    first_ingestion_seq INTEGER CHECK (first_ingestion_seq > 0),
    last_ingestion_seq INTEGER CHECK (last_ingestion_seq > 0),
    completed_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (source_identity_digest, batch_index),
    CHECK (
        (
            state = 'planned'
            AND append_result_canonical IS NULL
            AND append_result_digest IS NULL
            AND subject_frontier_seq IS NULL
            AND subject_frontier_digest IS NULL
            AND result_frontier_seq IS NULL
            AND result_frontier_digest IS NULL
            AND first_ingestion_seq IS NULL
            AND last_ingestion_seq IS NULL
            AND completed_at IS NULL
        )
        OR
        (
            state = 'complete'
            AND append_result_canonical IS NOT NULL
            AND append_result_digest IS NOT NULL
            AND subject_frontier_seq IS NOT NULL
            AND subject_frontier_digest IS NOT NULL
            AND result_frontier_seq IS NOT NULL
            AND result_frontier_digest IS NOT NULL
            AND first_ingestion_seq IS NOT NULL
            AND last_ingestion_seq IS NOT NULL
            AND completed_at IS NOT NULL
            AND first_ingestion_seq = subject_frontier_seq + 1
            AND last_ingestion_seq = first_ingestion_seq + event_count - 1
            AND result_frontier_seq = last_ingestion_seq
        )
    )
) STRICT, WITHOUT ROWID;

CREATE TABLE import_publication_requests (
    publishing_writer_id TEXT NOT NULL REFERENCES writers(writer_id),
    request_id TEXT NOT NULL,
    source_identity_digest TEXT NOT NULL REFERENCES import_jobs(source_identity_digest),
    publication_ordinal INTEGER NOT NULL CHECK (publication_ordinal BETWEEN 0 AND 1024),
    PRIMARY KEY (publishing_writer_id, request_id),
    UNIQUE (source_identity_digest, publication_ordinal)
) STRICT, WITHOUT ROWID;

CREATE TABLE semantic_jobs (
    job_id TEXT PRIMARY KEY,
    writer_id TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    case_digest TEXT NOT NULL,
    case_object_id TEXT NOT NULL REFERENCES objects(object_id),
    state TEXT NOT NULL
        CHECK (state IN ('queued', 'leased', 'succeeded', 'failed', 'quarantined')),
    active_attempt_id TEXT,
    selected_attempt_id TEXT,
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    owner_generation TEXT,
    lease_owner_id TEXT,
    lease_generation INTEGER CHECK (lease_generation > 0),
    lease_expires_at TEXT,
    selected_result_object_id TEXT REFERENCES objects(object_id),
    terminal_code TEXT,
    terminal_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (writer_id, operation_id)
        REFERENCES operations(writer_id, operation_id),
    FOREIGN KEY (job_id, active_attempt_id)
        REFERENCES semantic_attempts(job_id, attempt_id),
    FOREIGN KEY (job_id, selected_attempt_id)
        REFERENCES semantic_attempts(job_id, attempt_id),
    UNIQUE (writer_id, operation_id, case_digest),
    CHECK (
        (
            state = 'queued'
            AND active_attempt_id IS NULL
            AND selected_attempt_id IS NULL
            AND owner_generation IS NULL
            AND lease_owner_id IS NULL
            AND lease_generation IS NULL
            AND lease_expires_at IS NULL
            AND selected_result_object_id IS NULL
            AND terminal_code IS NULL
            AND terminal_at IS NULL
        )
        OR
        (
            state = 'leased'
            AND active_attempt_id IS NOT NULL
            AND selected_attempt_id IS NULL
            AND owner_generation IS NOT NULL
            AND lease_owner_id IS NOT NULL
            AND lease_generation IS NOT NULL
            AND lease_expires_at IS NOT NULL
            AND selected_result_object_id IS NULL
            AND terminal_code IS NULL
            AND terminal_at IS NULL
        )
        OR
        (
            state = 'succeeded'
            AND active_attempt_id IS NULL
            AND selected_attempt_id IS NOT NULL
            AND owner_generation IS NULL
            AND lease_owner_id IS NULL
            AND lease_generation IS NULL
            AND lease_expires_at IS NULL
            AND selected_result_object_id IS NOT NULL
            AND terminal_code IS NOT NULL
            AND terminal_at IS NOT NULL
        )
        OR
        (
            state IN ('failed', 'quarantined')
            AND active_attempt_id IS NULL
            AND selected_attempt_id IS NULL
            AND owner_generation IS NULL
            AND lease_owner_id IS NULL
            AND lease_generation IS NULL
            AND lease_expires_at IS NULL
            AND selected_result_object_id IS NULL
            AND terminal_code IS NOT NULL
            AND terminal_at IS NOT NULL
        )
    )
) STRICT, WITHOUT ROWID;

CREATE TABLE semantic_attempts (
    attempt_id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL REFERENCES semantic_jobs(job_id),
    attempt_ordinal INTEGER NOT NULL CHECK (attempt_ordinal > 0),
    provider_request_id TEXT NOT NULL,
    owner_generation TEXT NOT NULL,
    lease_owner_id TEXT NOT NULL,
    lease_generation INTEGER NOT NULL CHECK (lease_generation > 0),
    state TEXT NOT NULL CHECK (state IN (
        'started',
        'response_durable',
        'selected',
        'failed',
        'expired',
        'late'
    )),
    result_object_id TEXT REFERENCES objects(object_id),
    terminal_code TEXT,
    started_at TEXT NOT NULL,
    terminal_at TEXT,
    UNIQUE (job_id, attempt_id),
    UNIQUE (job_id, attempt_ordinal),
    UNIQUE (job_id, lease_generation),
    CHECK (
        (
            state = 'started'
            AND result_object_id IS NULL
            AND terminal_code IS NULL
            AND terminal_at IS NULL
        )
        OR
        (
            state = 'response_durable'
            AND result_object_id IS NOT NULL
            AND terminal_code IS NULL
            AND terminal_at IS NULL
        )
        OR
        (
            state = 'selected'
            AND result_object_id IS NOT NULL
            AND terminal_code IS NOT NULL
            AND terminal_at IS NOT NULL
        )
        OR
        (
            state = 'failed'
            AND terminal_code IS NOT NULL
            AND terminal_at IS NOT NULL
        )
        OR
        (
            state = 'expired'
            AND result_object_id IS NULL
            AND terminal_code IS NOT NULL
            AND terminal_at IS NOT NULL
        )
        OR
        (
            state = 'late'
            AND result_object_id IS NOT NULL
            AND terminal_code IS NOT NULL
            AND terminal_at IS NOT NULL
        )
    )
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX semantic_attempts_one_selected
ON semantic_attempts(job_id)
WHERE state = 'selected';

CREATE TABLE events (
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

CREATE TABLE event_projection_locators (
    event_id TEXT PRIMARY KEY REFERENCES events(event_id),
    schema_name TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    logical_key TEXT,
    canonical_payload_digest TEXT NOT NULL,
    redaction_target_event_ids BLOB NOT NULL,
    redaction_target_object_ids BLOB NOT NULL
) STRICT, WITHOUT ROWID;

CREATE TABLE event_parents (
    child_event_id TEXT NOT NULL REFERENCES events(event_id),
    parent_event_id TEXT NOT NULL REFERENCES events(event_id),
    PRIMARY KEY (child_event_id, parent_event_id),
    CHECK (child_event_id <> parent_event_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE event_refs (
    event_id TEXT NOT NULL REFERENCES events(event_id),
    ref_type TEXT NOT NULL CHECK (ref_type IN ('artifact', 'evidence', 'result', 'finding', 'claim')),
    target_id TEXT NOT NULL,
    PRIMARY KEY (event_id, ref_type, target_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE projection_state (
    projection_name TEXT PRIMARY KEY CHECK (projection_name = 'work'),
    projection_version TEXT NOT NULL CHECK (projection_version = 'yoetz/0.1.0'),
    projection_generation INTEGER NOT NULL CHECK (projection_generation = 1),
    applied_through_seq INTEGER NOT NULL CHECK (applied_through_seq >= 0),
    state_digest TEXT NOT NULL,
    engine_version TEXT NOT NULL CHECK (engine_version = '0.1.0')
) STRICT, WITHOUT ROWID;

CREATE TABLE p1_projection_state (
    projection_name TEXT PRIMARY KEY REFERENCES projection_state(projection_name),
    frontier_seq INTEGER NOT NULL CHECK (frontier_seq >= 0),
    head_digest TEXT NOT NULL,
    task_title_source_event_id TEXT REFERENCES event_projection_locators(event_id),
    current_plan_source_event_id TEXT REFERENCES event_projection_locators(event_id),
    open_obligation_count INTEGER NOT NULL
        CHECK (open_obligation_count BETWEEN 0 AND 9007199254740991),
    unresolved_finding_count INTEGER NOT NULL
        CHECK (unresolved_finding_count BETWEEN 0 AND 9007199254740991),
    status_coverage_canonical BLOB,
    status_gap_codes_canonical BLOB,
    latest_check_event_id TEXT REFERENCES event_projection_locators(event_id),
    latest_subject_frontier_seq INTEGER CHECK (latest_subject_frontier_seq >= 0),
    latest_subject_frontier_digest TEXT,
    latest_verdict TEXT CHECK (latest_verdict IN (
        'action_required',
        'no_issue_detected',
        'insufficient_coverage',
        'incomplete_check'
    )),
    latest_returned_finding_ids BLOB,
    latest_suppressed_count INTEGER
        CHECK (latest_suppressed_count BETWEEN 0 AND 9007199254740991),
    latest_coverage_canonical BLOB,
    freshness TEXT NOT NULL CHECK (freshness IN (
        'unknown',
        'redacted_gap',
        'partial',
        'stale_after_material_change',
        'current'
    )),
    unknown_event_count INTEGER NOT NULL
        CHECK (unknown_event_count BETWEEN 0 AND frontier_seq),
    CHECK (
        (frontier_seq = 0 AND head_digest = 'genesis')
        OR
        (frontier_seq > 0 AND head_digest <> 'genesis')
    ),
    CHECK (
        (
            frontier_seq = 0
            AND task_title_source_event_id IS NULL
            AND current_plan_source_event_id IS NULL
            AND open_obligation_count = 0
            AND unresolved_finding_count = 0
            AND status_coverage_canonical IS NULL
            AND status_gap_codes_canonical IS NULL
        )
        OR
        (
            frontier_seq > 0
            AND task_title_source_event_id IS NOT NULL
            AND status_coverage_canonical IS NOT NULL
            AND status_gap_codes_canonical IS NOT NULL
        )
    ),
    CHECK (
        (
            latest_check_event_id IS NULL
            AND latest_subject_frontier_seq IS NULL
            AND latest_subject_frontier_digest IS NULL
            AND latest_verdict IS NULL
            AND latest_returned_finding_ids IS NULL
            AND latest_suppressed_count IS NULL
            AND latest_coverage_canonical IS NULL
        )
        OR
        (
            latest_check_event_id IS NOT NULL
            AND latest_subject_frontier_seq IS NOT NULL
            AND latest_subject_frontier_digest IS NOT NULL
            AND latest_verdict IS NOT NULL
            AND latest_returned_finding_ids IS NOT NULL
            AND latest_suppressed_count IS NOT NULL
            AND latest_coverage_canonical IS NOT NULL
            AND latest_subject_frontier_seq <= frontier_seq
            AND (
                (
                    latest_subject_frontier_seq = 0
                    AND latest_subject_frontier_digest = 'genesis'
                )
                OR
                (
                    latest_subject_frontier_seq > 0
                    AND latest_subject_frontier_digest <> 'genesis'
                )
            )
        )
    )
) STRICT, WITHOUT ROWID;

CREATE TABLE p1_plans (
    plan_version INTEGER PRIMARY KEY
        CHECK (plan_version BETWEEN 1 AND 9007199254740991),
    payload_digest TEXT NOT NULL,
    redacted INTEGER NOT NULL CHECK (redacted IN (0, 1)),
    source_event_id TEXT NOT NULL REFERENCES event_projection_locators(event_id),
    source_frontier INTEGER NOT NULL CHECK (source_frontier > 0),
    superseded_by_plan_version INTEGER REFERENCES p1_plans(plan_version),
    CHECK (
        superseded_by_plan_version IS NULL
        OR superseded_by_plan_version > plan_version
    )
) STRICT, WITHOUT ROWID;

CREATE TABLE p1_obligations (
    obligation_id TEXT PRIMARY KEY,
    payload_digest TEXT NOT NULL,
    redacted INTEGER NOT NULL CHECK (redacted IN (0, 1)),
    source_event_id TEXT NOT NULL REFERENCES event_projection_locators(event_id),
    source_frontier INTEGER NOT NULL CHECK (source_frontier > 0),
    plan_change TEXT CHECK (plan_change IN ('superseded', 'waived', 'carried')),
    plan_change_source_event_id TEXT REFERENCES event_projection_locators(event_id),
    CHECK (
        (plan_change IS NULL AND plan_change_source_event_id IS NULL)
        OR
        (plan_change IS NOT NULL AND plan_change_source_event_id IS NOT NULL)
    )
) STRICT, WITHOUT ROWID;

CREATE TABLE p1_obligation_replacements (
    obligation_id TEXT NOT NULL REFERENCES p1_obligations(obligation_id),
    replacement_obligation_id TEXT NOT NULL,
    PRIMARY KEY (obligation_id, replacement_obligation_id),
    CHECK (obligation_id <> replacement_obligation_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE p1_decisions (
    decision_event_id TEXT PRIMARY KEY,
    payload_digest TEXT NOT NULL,
    redacted INTEGER NOT NULL CHECK (redacted IN (0, 1)),
    source_event_id TEXT NOT NULL REFERENCES event_projection_locators(event_id),
    source_frontier INTEGER NOT NULL CHECK (source_frontier > 0),
    superseded_by_event_id TEXT REFERENCES p1_decisions(decision_event_id),
    CHECK (decision_event_id = source_event_id),
    CHECK (
        superseded_by_event_id IS NULL
        OR superseded_by_event_id <> decision_event_id
    )
) STRICT, WITHOUT ROWID;

CREATE TABLE p1_assignments (
    assignment_event_id TEXT PRIMARY KEY,
    payload_digest TEXT NOT NULL,
    redacted INTEGER NOT NULL CHECK (redacted IN (0, 1)),
    source_event_id TEXT NOT NULL REFERENCES event_projection_locators(event_id),
    source_frontier INTEGER NOT NULL CHECK (source_frontier > 0),
    CHECK (assignment_event_id = source_event_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE p1_actions (
    action_id TEXT PRIMARY KEY,
    payload_digest TEXT NOT NULL,
    redacted INTEGER NOT NULL CHECK (redacted IN (0, 1)),
    source_event_id TEXT NOT NULL REFERENCES event_projection_locators(event_id),
    source_frontier INTEGER NOT NULL CHECK (source_frontier > 0)
) STRICT, WITHOUT ROWID;

CREATE TABLE p1_results (
    result_id TEXT PRIMARY KEY,
    payload_digest TEXT NOT NULL,
    redacted INTEGER NOT NULL CHECK (redacted IN (0, 1)),
    source_event_id TEXT NOT NULL REFERENCES event_projection_locators(event_id),
    source_frontier INTEGER NOT NULL CHECK (source_frontier > 0),
    action_id TEXT,
    CHECK (
        (redacted = 1 AND action_id IS NULL)
        OR
        (redacted = 0 AND action_id IS NOT NULL)
    )
) STRICT, WITHOUT ROWID;

CREATE TABLE p1_evidence (
    evidence_id TEXT PRIMARY KEY,
    payload_digest TEXT NOT NULL,
    redacted INTEGER NOT NULL CHECK (redacted IN (0, 1)),
    source_event_id TEXT NOT NULL REFERENCES event_projection_locators(event_id),
    source_frontier INTEGER NOT NULL CHECK (source_frontier > 0),
    object_available INTEGER NOT NULL CHECK (object_available IN (0, 1)),
    redacted_object_id TEXT REFERENCES objects(object_id),
    CHECK (
        (object_available = 1 AND redacted_object_id IS NULL)
        OR
        (object_available = 0 AND redacted_object_id IS NOT NULL)
    )
) STRICT, WITHOUT ROWID;

CREATE TABLE p1_claims (
    claim_id TEXT PRIMARY KEY,
    payload_digest TEXT NOT NULL,
    redacted INTEGER NOT NULL CHECK (redacted IN (0, 1)),
    source_event_id TEXT NOT NULL REFERENCES event_projection_locators(event_id),
    source_frontier INTEGER NOT NULL CHECK (source_frontier > 0)
) STRICT, WITHOUT ROWID;

CREATE TABLE p1_contradictions (
    disputing_claim_id TEXT NOT NULL REFERENCES p1_claims(claim_id),
    disputed_ref TEXT NOT NULL,
    source_event_id TEXT NOT NULL REFERENCES event_projection_locators(event_id),
    source_frontier INTEGER NOT NULL CHECK (source_frontier > 0),
    PRIMARY KEY (disputing_claim_id, disputed_ref),
    CHECK (disputing_claim_id <> disputed_ref)
) STRICT, WITHOUT ROWID;

CREATE TABLE p1_findings (
    finding_id TEXT PRIMARY KEY,
    payload_digest TEXT NOT NULL,
    redacted INTEGER NOT NULL CHECK (redacted IN (0, 1)),
    source_event_id TEXT NOT NULL REFERENCES event_projection_locators(event_id),
    source_frontier INTEGER NOT NULL CHECK (source_frontier > 0)
) STRICT, WITHOUT ROWID;

CREATE TABLE p1_responses (
    finding_id TEXT PRIMARY KEY,
    payload_digest TEXT NOT NULL,
    redacted INTEGER NOT NULL CHECK (redacted IN (0, 1)),
    source_event_id TEXT NOT NULL REFERENCES event_projection_locators(event_id),
    source_frontier INTEGER NOT NULL CHECK (source_frontier > 0)
) STRICT, WITHOUT ROWID;

CREATE TABLE p1_coverage_gaps (
    gap_marker TEXT PRIMARY KEY,
    gap_kind TEXT NOT NULL CHECK (gap_kind IN (
        'unknown_event',
        'redacted_event',
        'redacted_object',
        'missing_ref'
    )),
    root_event_id TEXT NOT NULL REFERENCES events(event_id),
    source_event_id TEXT REFERENCES events(event_id),
    target_event_id TEXT REFERENCES events(event_id),
    target_object_id TEXT REFERENCES objects(object_id),
    target_logical_id TEXT,
    schema_name TEXT,
    schema_version TEXT,
    CHECK (
        (
            gap_kind = 'unknown_event'
            AND source_event_id IS NULL
            AND target_event_id IS NOT NULL
            AND target_event_id = root_event_id
            AND target_object_id IS NULL
            AND target_logical_id IS NULL
            AND schema_name IS NOT NULL
            AND schema_version IS NOT NULL
        )
        OR
        (
            gap_kind = 'redacted_event'
            AND source_event_id IS NULL
            AND target_event_id IS NOT NULL
            AND target_event_id = root_event_id
            AND target_object_id IS NULL
            AND target_logical_id IS NULL
            AND schema_name IS NULL
            AND schema_version IS NULL
        )
        OR
        (
            gap_kind = 'redacted_object'
            AND source_event_id IS NULL
            AND target_event_id IS NULL
            AND target_object_id IS NOT NULL
            AND target_logical_id IS NULL
            AND schema_name IS NULL
            AND schema_version IS NULL
        )
        OR
        (
            gap_kind = 'missing_ref'
            AND source_event_id IS NOT NULL
            AND source_event_id = root_event_id
            AND target_event_id IS NULL
            AND target_object_id IS NULL
            AND target_logical_id IS NOT NULL
            AND schema_name IS NULL
            AND schema_version IS NULL
        )
    )
) STRICT, WITHOUT ROWID;

CREATE TABLE p1_query_snapshots (
    valid_from_seq INTEGER PRIMARY KEY CHECK (valid_from_seq >= 0),
    valid_to_seq INTEGER CHECK (valid_to_seq > valid_from_seq),
    head_digest TEXT NOT NULL,
    task_title_source_event_id TEXT REFERENCES event_projection_locators(event_id),
    current_plan_source_event_id TEXT REFERENCES event_projection_locators(event_id),
    open_obligation_count INTEGER NOT NULL
        CHECK (open_obligation_count BETWEEN 0 AND 9007199254740991),
    unresolved_finding_count INTEGER NOT NULL
        CHECK (unresolved_finding_count BETWEEN 0 AND 9007199254740991),
    freshness TEXT NOT NULL CHECK (freshness IN (
        'unknown',
        'redacted_gap',
        'partial',
        'stale_after_material_change',
        'current'
    )),
    coverage_canonical BLOB,
    gap_codes_canonical BLOB,
    CHECK (
        (
            valid_from_seq = 0
            AND head_digest = 'genesis'
            AND task_title_source_event_id IS NULL
            AND current_plan_source_event_id IS NULL
            AND open_obligation_count = 0
            AND unresolved_finding_count = 0
            AND coverage_canonical IS NULL
            AND gap_codes_canonical IS NULL
        )
        OR
        (
            valid_from_seq > 0
            AND head_digest <> 'genesis'
            AND task_title_source_event_id IS NOT NULL
            AND coverage_canonical IS NOT NULL
            AND gap_codes_canonical IS NOT NULL
        )
    )
) STRICT, WITHOUT ROWID;

CREATE TABLE p1_query_assignments (
    assignment_event_id TEXT NOT NULL REFERENCES p1_assignments(assignment_event_id),
    valid_from_seq INTEGER NOT NULL CHECK (valid_from_seq > 0),
    valid_to_seq INTEGER CHECK (valid_to_seq > valid_from_seq),
    actor_id TEXT,
    handoff_event_id TEXT,
    resolved INTEGER CHECK (resolved IN (0, 1)),
    tombstone INTEGER NOT NULL CHECK (tombstone IN (0, 1)),
    PRIMARY KEY (assignment_event_id, valid_from_seq),
    CHECK (
        (tombstone = 1 AND actor_id IS NULL AND handoff_event_id IS NULL AND resolved IS NULL)
        OR
        (tombstone = 0 AND actor_id IS NOT NULL AND resolved IS NOT NULL)
    )
) STRICT, WITHOUT ROWID;

CREATE TABLE p1_query_assignment_obligations (
    assignment_event_id TEXT NOT NULL,
    valid_from_seq INTEGER NOT NULL,
    obligation_id TEXT NOT NULL,
    PRIMARY KEY (assignment_event_id, valid_from_seq, obligation_id),
    FOREIGN KEY (assignment_event_id, valid_from_seq)
        REFERENCES p1_query_assignments(assignment_event_id, valid_from_seq)
) STRICT, WITHOUT ROWID;

CREATE TABLE p1_query_obligations (
    obligation_id TEXT NOT NULL REFERENCES p1_obligations(obligation_id),
    valid_from_seq INTEGER NOT NULL CHECK (valid_from_seq > 0),
    valid_to_seq INTEGER CHECK (valid_to_seq > valid_from_seq),
    declared_status TEXT CHECK (declared_status IN ('open', 'resolved')),
    effective_status TEXT CHECK (effective_status IN ('open', 'resolved')),
    first_source_event_id TEXT REFERENCES event_projection_locators(event_id),
    latest_source_event_id TEXT NOT NULL REFERENCES event_projection_locators(event_id),
    revision_event_id TEXT REFERENCES event_projection_locators(event_id),
    tombstone INTEGER NOT NULL CHECK (tombstone IN (0, 1)),
    PRIMARY KEY (obligation_id, valid_from_seq),
    CHECK (
        (
            tombstone = 1
            AND declared_status IS NULL
            AND effective_status IS NULL
            AND first_source_event_id IS NULL
            AND revision_event_id IS NULL
        )
        OR
        (
            tombstone = 0
            AND declared_status IS NOT NULL
            AND effective_status IS NOT NULL
            AND first_source_event_id IS NOT NULL
        )
    )
) STRICT, WITHOUT ROWID;

CREATE TABLE p1_query_obligation_source_refs (
    obligation_id TEXT NOT NULL,
    valid_from_seq INTEGER NOT NULL,
    source_ref TEXT NOT NULL,
    PRIMARY KEY (obligation_id, valid_from_seq, source_ref),
    FOREIGN KEY (obligation_id, valid_from_seq)
        REFERENCES p1_query_obligations(obligation_id, valid_from_seq)
) STRICT, WITHOUT ROWID;

CREATE TABLE p1_query_obligation_evidence_refs (
    obligation_id TEXT NOT NULL,
    valid_from_seq INTEGER NOT NULL,
    evidence_ref TEXT NOT NULL,
    PRIMARY KEY (obligation_id, valid_from_seq, evidence_ref),
    FOREIGN KEY (obligation_id, valid_from_seq)
        REFERENCES p1_query_obligations(obligation_id, valid_from_seq)
) STRICT, WITHOUT ROWID;

CREATE TABLE p1_query_obligation_actors (
    obligation_id TEXT NOT NULL,
    valid_from_seq INTEGER NOT NULL,
    actor_id TEXT NOT NULL,
    effective_status TEXT NOT NULL CHECK (effective_status IN ('open', 'resolved')),
    PRIMARY KEY (obligation_id, valid_from_seq, actor_id),
    FOREIGN KEY (obligation_id, valid_from_seq)
        REFERENCES p1_query_obligations(obligation_id, valid_from_seq)
) STRICT, WITHOUT ROWID;

CREATE TABLE p1_query_findings (
    finding_id TEXT NOT NULL REFERENCES p1_findings(finding_id),
    valid_from_seq INTEGER NOT NULL CHECK (valid_from_seq > 0),
    valid_to_seq INTEGER CHECK (valid_to_seq > valid_from_seq),
    source_event_id TEXT NOT NULL REFERENCES event_projection_locators(event_id),
    source_frontier INTEGER NOT NULL CHECK (source_frontier > 0),
    issue_key_canonical BLOB,
    kind TEXT CHECK (kind IN (
        'action_without_result',
        'claim_without_admissible_evidence',
        'completion_with_open_obligations',
        'contradictory_claims_unresolved',
        'diff_does_not_match_account',
        'evidence_does_not_support_claim',
        'failed_work_omitted',
        'ledger_stale_or_incomplete',
        'material_limitation_omitted',
        'questionable_finding_rejection',
        'requested_item_never_attempted',
        'result_without_action',
        'stale_evidence_for_changed_state',
        'weak_or_stale_response'
    )),
    origin TEXT CHECK (origin IN ('deterministic', 'semantic_model_derived')),
    policy_id TEXT CHECK (policy_id IN ('research-evidence', 'work-integrity')),
    policy_version TEXT CHECK (policy_version = '0.1.0'),
    subject_frontier_seq INTEGER CHECK (subject_frontier_seq >= 0),
    subject_frontier_digest TEXT,
    priority INTEGER CHECK (priority BETWEEN 1 AND 3),
    actionable INTEGER CHECK (actionable IN (0, 1)),
    artifact_ordinal INTEGER CHECK (artifact_ordinal >= 0),
    immutability_ordinal INTEGER CHECK (immutability_ordinal >= 0),
    freshness_ordinal INTEGER CHECK (freshness_ordinal >= 0),
    authorship_ordinal INTEGER CHECK (authorship_ordinal >= 0),
    real_check_present INTEGER CHECK (real_check_present IN (0, 1)),
    known_gap_count INTEGER CHECK (known_gap_count BETWEEN 0 AND 64),
    origin_ordinal INTEGER CHECK (origin_ordinal IN (0, 1)),
    coverage_canonical BLOB,
    disposition TEXT CHECK (disposition IN (
        'none', 'acknowledged', 'rejected', 'waived'
    )),
    response_event_id TEXT REFERENCES event_projection_locators(event_id),
    resolved INTEGER CHECK (resolved IN (0, 1)),
    tombstone INTEGER NOT NULL CHECK (tombstone IN (0, 1)),
    PRIMARY KEY (finding_id, valid_from_seq),
    CHECK (
        (
            tombstone = 1
            AND issue_key_canonical IS NULL
            AND kind IS NULL
            AND origin IS NULL
            AND policy_id IS NULL
            AND policy_version IS NULL
            AND subject_frontier_seq IS NULL
            AND subject_frontier_digest IS NULL
            AND priority IS NULL
            AND actionable IS NULL
            AND artifact_ordinal IS NULL
            AND immutability_ordinal IS NULL
            AND freshness_ordinal IS NULL
            AND authorship_ordinal IS NULL
            AND real_check_present IS NULL
            AND known_gap_count IS NULL
            AND origin_ordinal IS NULL
            AND coverage_canonical IS NULL
            AND disposition IS NULL
            AND response_event_id IS NULL
            AND resolved IS NULL
        )
        OR
        (
            tombstone = 0
            AND issue_key_canonical IS NOT NULL
            AND kind IS NOT NULL
            AND origin IS NOT NULL
            AND policy_id IS NOT NULL
            AND policy_version IS NOT NULL
            AND subject_frontier_seq IS NOT NULL
            AND subject_frontier_digest IS NOT NULL
            AND priority IS NOT NULL
            AND actionable IS NOT NULL
            AND artifact_ordinal IS NOT NULL
            AND immutability_ordinal IS NOT NULL
            AND freshness_ordinal IS NOT NULL
            AND authorship_ordinal IS NOT NULL
            AND real_check_present IS NOT NULL
            AND known_gap_count IS NOT NULL
            AND origin_ordinal IS NOT NULL
            AND coverage_canonical IS NOT NULL
            AND disposition IS NOT NULL
            AND resolved IS NOT NULL
            AND (
                (origin = 'deterministic' AND origin_ordinal = 0)
                OR
                (origin = 'semantic_model_derived' AND origin_ordinal = 1)
            )
            AND (
                (disposition = 'none' AND response_event_id IS NULL)
                OR
                (disposition <> 'none' AND response_event_id IS NOT NULL)
            )
        )
    )
) STRICT, WITHOUT ROWID;

CREATE TABLE p1_query_finding_subject_refs (
    finding_id TEXT NOT NULL,
    valid_from_seq INTEGER NOT NULL,
    subject_ref TEXT NOT NULL,
    PRIMARY KEY (finding_id, valid_from_seq, subject_ref),
    FOREIGN KEY (finding_id, valid_from_seq)
        REFERENCES p1_query_findings(finding_id, valid_from_seq)
) STRICT, WITHOUT ROWID;

CREATE TABLE p1_query_finding_order (
    finding_id TEXT NOT NULL,
    valid_from_seq INTEGER NOT NULL,
    valid_to_seq INTEGER,
    origin_filter TEXT NOT NULL CHECK (origin_filter IN (
        '*', 'deterministic', 'semantic_model_derived'
    )),
    priority_filter INTEGER NOT NULL CHECK (priority_filter BETWEEN 0 AND 3),
    disposition_filter TEXT NOT NULL CHECK (disposition_filter IN (
        '*', 'none', 'acknowledged', 'rejected', 'waived'
    )),
    resolution_filter TEXT NOT NULL CHECK (resolution_filter IN ('active', 'all')),
    rank_priority INTEGER NOT NULL CHECK (rank_priority BETWEEN 1 AND 3),
    rank_actionable_sort INTEGER NOT NULL CHECK (rank_actionable_sort IN (-1, 0)),
    rank_artifact_sort INTEGER NOT NULL CHECK (rank_artifact_sort <= 0),
    rank_immutability_sort INTEGER NOT NULL CHECK (rank_immutability_sort <= 0),
    rank_freshness_sort INTEGER NOT NULL CHECK (rank_freshness_sort <= 0),
    rank_authorship_sort INTEGER NOT NULL CHECK (rank_authorship_sort <= 0),
    rank_real_check_sort INTEGER NOT NULL CHECK (rank_real_check_sort IN (-1, 0)),
    rank_known_gap_count INTEGER NOT NULL CHECK (rank_known_gap_count BETWEEN 0 AND 64),
    rank_origin_ordinal INTEGER NOT NULL CHECK (rank_origin_ordinal IN (0, 1)),
    PRIMARY KEY (
        finding_id,
        valid_from_seq,
        origin_filter,
        priority_filter,
        disposition_filter,
        resolution_filter
    ),
    FOREIGN KEY (finding_id, valid_from_seq)
        REFERENCES p1_query_findings(finding_id, valid_from_seq),
    CHECK (valid_to_seq IS NULL OR valid_to_seq > valid_from_seq)
) STRICT, WITHOUT ROWID;

CREATE TABLE p1_query_responses (
    finding_id TEXT NOT NULL,
    valid_from_seq INTEGER NOT NULL CHECK (valid_from_seq > 0),
    valid_to_seq INTEGER CHECK (valid_to_seq > valid_from_seq),
    response_event_id TEXT NOT NULL REFERENCES event_projection_locators(event_id),
    source_frontier INTEGER NOT NULL CHECK (source_frontier > 0),
    disposition TEXT CHECK (disposition IN ('acknowledged', 'rejected', 'waived')),
    waiver_scope TEXT CHECK (waiver_scope = 'finding_only'),
    waiver_expiry TEXT,
    tombstone INTEGER NOT NULL CHECK (tombstone IN (0, 1)),
    PRIMARY KEY (finding_id, valid_from_seq),
    CHECK (
        (
            tombstone = 1
            AND disposition IS NULL
            AND waiver_scope IS NULL
            AND waiver_expiry IS NULL
        )
        OR
        (
            tombstone = 0
            AND disposition IS NOT NULL
            AND (
                (
                    disposition = 'waived'
                    AND waiver_scope = 'finding_only'
                )
                OR
                (
                    disposition <> 'waived'
                    AND waiver_scope IS NULL
                    AND waiver_expiry IS NULL
                )
            )
        )
    )
) STRICT, WITHOUT ROWID;

CREATE TABLE p1_query_response_evidence_refs (
    finding_id TEXT NOT NULL,
    valid_from_seq INTEGER NOT NULL,
    evidence_ref TEXT NOT NULL,
    PRIMARY KEY (finding_id, valid_from_seq, evidence_ref),
    FOREIGN KEY (finding_id, valid_from_seq)
        REFERENCES p1_query_responses(finding_id, valid_from_seq)
) STRICT, WITHOUT ROWID;

CREATE TABLE p1_query_checks (
    check_event_id TEXT NOT NULL REFERENCES event_projection_locators(event_id),
    valid_from_seq INTEGER NOT NULL CHECK (valid_from_seq > 0),
    valid_to_seq INTEGER CHECK (valid_to_seq > valid_from_seq),
    source_frontier INTEGER NOT NULL CHECK (source_frontier > 0),
    subject_frontier_seq INTEGER CHECK (subject_frontier_seq >= 0),
    subject_frontier_digest TEXT,
    suppressed_count INTEGER
        CHECK (suppressed_count BETWEEN 0 AND 9007199254740991),
    semantic_status TEXT CHECK (semantic_status IN (
        'not_requested',
        'not_configured',
        'blocked_by_policy',
        'blocked_forbidden_data',
        'classification_uncertain',
        'awaiting_human',
        'human_denied',
        'approval_expired',
        'succeeded',
        'refused',
        'timeout',
        'invalid',
        'unavailable',
        'late',
        'stale',
        'failed'
    )),
    semantic_reason TEXT CHECK (semantic_reason IN (
        'deterministic_mode',
        'no_material_semantic_case',
        'provider_not_configured',
        'local_model_not_configured',
        'network_egress_denied',
        'channel_disabled',
        'provider_binding_not_authorized',
        'scope_not_authorized',
        'content_category_not_authorized',
        'policy_generation_revoked',
        'never_send_detected',
        'secret_detected',
        'classification_uncertain',
        'human_approval_required',
        'human_denied',
        'human_approval_expired',
        'semantic_completed',
        'provider_refused',
        'provider_timeout',
        'response_schema_invalid',
        'response_content_invalid',
        'semantic_judgment_rejected',
        'credential_unavailable',
        'endpoint_profile_unavailable',
        'transport_unavailable',
        'provider_rate_limited',
        'provider_quota_exhausted',
        'retry_budget_exhausted',
        'audit_reservation_unavailable',
        'receipt_persistence_unknown',
        'deadline_authority_lost',
        'lease_authority_lost',
        'frontier_changed',
        'dependency_changed',
        'coordinator_failure'
    )),
    coverage_freshness TEXT CHECK (coverage_freshness IN (
        'unknown',
        'redacted_gap',
        'partial',
        'stale_after_material_change',
        'current'
    )),
    coverage_gap_count INTEGER CHECK (coverage_gap_count BETWEEN 0 AND 64),
    coverage_canonical BLOB,
    whole_case_scope INTEGER CHECK (whole_case_scope IN (0, 1)),
    tombstone INTEGER NOT NULL CHECK (tombstone IN (0, 1)),
    PRIMARY KEY (check_event_id, valid_from_seq),
    CHECK (
        (
            tombstone = 1
            AND subject_frontier_seq IS NULL
            AND subject_frontier_digest IS NULL
            AND suppressed_count IS NULL
            AND semantic_status IS NULL
            AND semantic_reason IS NULL
            AND coverage_freshness IS NULL
            AND coverage_gap_count IS NULL
            AND coverage_canonical IS NULL
            AND whole_case_scope IS NULL
        )
        OR
        (
            tombstone = 0
            AND subject_frontier_seq IS NOT NULL
            AND subject_frontier_digest IS NOT NULL
            AND suppressed_count IS NOT NULL
            AND semantic_status IS NOT NULL
            AND semantic_reason IS NOT NULL
            AND coverage_freshness IS NOT NULL
            AND coverage_gap_count IS NOT NULL
            AND coverage_canonical IS NOT NULL
            AND whole_case_scope IS NOT NULL
        )
    )
) STRICT, WITHOUT ROWID;

CREATE TABLE p1_query_check_scope_refs (
    check_event_id TEXT NOT NULL,
    valid_from_seq INTEGER NOT NULL,
    scope_kind TEXT NOT NULL CHECK (scope_kind IN ('claim', 'obligation')),
    target_id TEXT NOT NULL,
    PRIMARY KEY (check_event_id, valid_from_seq, scope_kind, target_id),
    FOREIGN KEY (check_event_id, valid_from_seq)
        REFERENCES p1_query_checks(check_event_id, valid_from_seq)
) STRICT, WITHOUT ROWID;

CREATE TABLE p1_query_check_policy_executions (
    check_event_id TEXT NOT NULL,
    valid_from_seq INTEGER NOT NULL,
    policy_id TEXT NOT NULL CHECK (policy_id IN ('research-evidence', 'work-integrity')),
    policy_version TEXT NOT NULL CHECK (policy_version = '0.1.0'),
    outcome TEXT NOT NULL CHECK (outcome IN ('run', 'skipped', 'failed')),
    execution_reason TEXT NOT NULL CHECK (execution_reason IN (
        'completed',
        'material_unavailable',
        'not_applicable',
        'policy_failure',
        'scope_excluded'
    )),
    subject_frontier_seq INTEGER NOT NULL CHECK (subject_frontier_seq >= 0),
    PRIMARY KEY (check_event_id, valid_from_seq, policy_id),
    FOREIGN KEY (check_event_id, valid_from_seq)
        REFERENCES p1_query_checks(check_event_id, valid_from_seq),
    CHECK (
        (outcome = 'run' AND execution_reason = 'completed')
        OR
        (outcome = 'failed' AND execution_reason = 'policy_failure')
        OR
        (
            outcome = 'skipped'
            AND execution_reason IN (
                'material_unavailable', 'not_applicable', 'scope_excluded'
            )
        )
    )
) STRICT, WITHOUT ROWID;

CREATE TABLE p1_query_check_returned_findings (
    check_event_id TEXT NOT NULL,
    valid_from_seq INTEGER NOT NULL,
    finding_id TEXT NOT NULL,
    PRIMARY KEY (check_event_id, valid_from_seq, finding_id),
    FOREIGN KEY (check_event_id, valid_from_seq)
        REFERENCES p1_query_checks(check_event_id, valid_from_seq)
) STRICT, WITHOUT ROWID;

CREATE TABLE p1_query_evidence (
    evidence_id TEXT NOT NULL REFERENCES p1_evidence(evidence_id),
    valid_from_seq INTEGER NOT NULL CHECK (valid_from_seq > 0),
    valid_to_seq INTEGER CHECK (valid_to_seq > valid_from_seq),
    source_event_id TEXT NOT NULL REFERENCES event_projection_locators(event_id),
    strength TEXT CHECK (strength IN (
        'mutable_reference',
        'metadata_only',
        'content_digest',
        'immutable_snapshot',
        'independently_reproduced'
    )),
    captured_object_id TEXT REFERENCES objects(object_id),
    content_digest TEXT,
    subject_tree_digest TEXT,
    subject_diff_digest TEXT,
    source_freshness TEXT CHECK (source_freshness IN (
        'unknown',
        'redacted_gap',
        'partial',
        'stale_after_material_change',
        'current'
    )),
    freshness TEXT CHECK (freshness IN (
        'unknown',
        'redacted_gap',
        'partial',
        'stale_after_material_change',
        'current'
    )),
    available INTEGER CHECK (available IN (0, 1)),
    tombstone INTEGER NOT NULL CHECK (tombstone IN (0, 1)),
    PRIMARY KEY (evidence_id, valid_from_seq),
    CHECK (
        (
            tombstone = 1
            AND strength IS NULL
            AND captured_object_id IS NULL
            AND content_digest IS NULL
            AND subject_tree_digest IS NULL
            AND subject_diff_digest IS NULL
            AND source_freshness IS NULL
            AND freshness IS NULL
            AND available IS NULL
        )
        OR
        (
            tombstone = 0
            AND strength IS NOT NULL
            AND source_freshness IS NOT NULL
            AND freshness IS NOT NULL
            AND available IS NOT NULL
            AND (captured_object_id IS NOT NULL OR available = 1)
        )
    )
) STRICT, WITHOUT ROWID;

CREATE INDEX p1_query_snapshots_visibility
ON p1_query_snapshots(valid_from_seq DESC, valid_to_seq);

CREATE INDEX p1_query_assignments_all
ON p1_query_assignments(
    tombstone,
    assignment_event_id,
    valid_from_seq,
    valid_to_seq
);

CREATE INDEX p1_query_assignments_resolved
ON p1_query_assignments(
    tombstone,
    resolved,
    assignment_event_id,
    valid_from_seq,
    valid_to_seq
);

CREATE INDEX p1_query_assignments_actor
ON p1_query_assignments(
    tombstone,
    actor_id,
    assignment_event_id,
    valid_from_seq,
    valid_to_seq
);

CREATE INDEX p1_query_assignments_actor_resolved
ON p1_query_assignments(
    tombstone,
    actor_id,
    resolved,
    assignment_event_id,
    valid_from_seq,
    valid_to_seq
);

CREATE INDEX p1_query_assignments_handoff
ON p1_query_assignments(handoff_event_id, assignment_event_id, valid_from_seq)
WHERE handoff_event_id IS NOT NULL;

CREATE INDEX p1_query_assignment_obligations_target
ON p1_query_assignment_obligations(
    obligation_id,
    assignment_event_id,
    valid_from_seq
);

CREATE INDEX p1_query_obligations_all
ON p1_query_obligations(
    tombstone,
    obligation_id,
    valid_from_seq,
    valid_to_seq
);

CREATE INDEX p1_query_obligations_status
ON p1_query_obligations(
    tombstone,
    effective_status,
    obligation_id,
    valid_from_seq,
    valid_to_seq
);

CREATE INDEX p1_query_obligations_compact
ON p1_query_obligations(
    obligation_id,
    valid_from_seq,
    valid_to_seq,
    tombstone,
    effective_status
);

CREATE INDEX p1_query_obligation_source_refs_target
ON p1_query_obligation_source_refs(source_ref, obligation_id, valid_from_seq);

CREATE INDEX p1_query_obligation_evidence_refs_target
ON p1_query_obligation_evidence_refs(evidence_ref, obligation_id, valid_from_seq);

CREATE INDEX p1_query_obligation_actors_actor
ON p1_query_obligation_actors(actor_id, obligation_id, valid_from_seq);

CREATE INDEX p1_query_obligation_actors_actor_status
ON p1_query_obligation_actors(
    actor_id,
    effective_status,
    obligation_id,
    valid_from_seq
);

CREATE INDEX p1_query_findings_issue
ON p1_query_findings(
    issue_key_canonical,
    source_frontier,
    finding_id,
    valid_from_seq,
    valid_to_seq
);

CREATE INDEX p1_query_finding_subject_refs_target
ON p1_query_finding_subject_refs(subject_ref, finding_id, valid_from_seq);

CREATE INDEX p1_query_finding_order_cover
ON p1_query_finding_order(
    origin_filter,
    priority_filter,
    disposition_filter,
    resolution_filter,
    rank_priority,
    rank_actionable_sort,
    rank_artifact_sort,
    rank_immutability_sort,
    rank_freshness_sort,
    rank_authorship_sort,
    rank_real_check_sort,
    rank_known_gap_count,
    rank_origin_ordinal,
    finding_id,
    valid_from_seq,
    valid_to_seq
);

CREATE INDEX p1_query_response_evidence_refs_target
ON p1_query_response_evidence_refs(evidence_ref, finding_id, valid_from_seq);

CREATE INDEX p1_query_checks_whole_case
ON p1_query_checks(
    whole_case_scope,
    subject_frontier_seq,
    check_event_id,
    valid_from_seq,
    valid_to_seq
);

CREATE INDEX p1_query_check_scope_refs_target
ON p1_query_check_scope_refs(
    scope_kind,
    target_id,
    check_event_id,
    valid_from_seq
);

CREATE INDEX p1_query_check_policy_applicability
ON p1_query_check_policy_executions(
    policy_id,
    policy_version,
    outcome,
    execution_reason,
    subject_frontier_seq,
    check_event_id,
    valid_from_seq
);

CREATE INDEX p1_query_check_returned_findings_target
ON p1_query_check_returned_findings(finding_id, check_event_id, valid_from_seq);

CREATE INDEX p1_query_evidence_all
ON p1_query_evidence(
    tombstone,
    evidence_id,
    valid_from_seq,
    valid_to_seq
);

CREATE INDEX p1_query_evidence_strength
ON p1_query_evidence(
    tombstone,
    strength,
    evidence_id,
    valid_from_seq,
    valid_to_seq
);

CREATE INDEX p1_query_evidence_freshness
ON p1_query_evidence(
    tombstone,
    freshness,
    evidence_id,
    valid_from_seq,
    valid_to_seq
);

CREATE INDEX p1_query_evidence_strength_freshness
ON p1_query_evidence(
    tombstone,
    strength,
    freshness,
    evidence_id,
    valid_from_seq,
    valid_to_seq
);

CREATE INDEX p1_query_evidence_available
ON p1_query_evidence(
    tombstone,
    available,
    evidence_id,
    valid_from_seq,
    valid_to_seq
);

CREATE INDEX p1_query_evidence_available_strength
ON p1_query_evidence(
    tombstone,
    available,
    strength,
    evidence_id,
    valid_from_seq,
    valid_to_seq
);

CREATE INDEX p1_query_evidence_available_freshness
ON p1_query_evidence(
    tombstone,
    available,
    freshness,
    evidence_id,
    valid_from_seq,
    valid_to_seq
);

CREATE INDEX p1_query_evidence_available_strength_freshness
ON p1_query_evidence(
    tombstone,
    available,
    strength,
    freshness,
    evidence_id,
    valid_from_seq,
    valid_to_seq
);

CREATE INDEX p1_plans_source_event
ON p1_plans(source_event_id);

CREATE INDEX p1_plans_superseded_by
ON p1_plans(superseded_by_plan_version)
WHERE superseded_by_plan_version IS NOT NULL;

CREATE INDEX p1_obligations_source_event
ON p1_obligations(source_event_id);

CREATE INDEX p1_obligations_change_source_event
ON p1_obligations(plan_change_source_event_id)
WHERE plan_change_source_event_id IS NOT NULL;

CREATE INDEX p1_decisions_superseded_by
ON p1_decisions(superseded_by_event_id)
WHERE superseded_by_event_id IS NOT NULL;

CREATE INDEX p1_actions_source_event
ON p1_actions(source_event_id);

CREATE INDEX p1_results_source_event
ON p1_results(source_event_id);

CREATE INDEX p1_results_action
ON p1_results(action_id);

CREATE INDEX p1_evidence_source_event
ON p1_evidence(source_event_id);

CREATE INDEX p1_claims_source_event
ON p1_claims(source_event_id);

CREATE INDEX p1_contradictions_source_event
ON p1_contradictions(source_event_id);

CREATE INDEX p1_findings_source_event
ON p1_findings(source_event_id);

CREATE INDEX p1_responses_source_event
ON p1_responses(source_event_id);

CREATE INDEX p1_coverage_gaps_root
ON p1_coverage_gaps(root_event_id, gap_marker);

CREATE INDEX p1_coverage_gaps_source
ON p1_coverage_gaps(source_event_id, gap_marker)
WHERE source_event_id IS NOT NULL;

CREATE INDEX p1_coverage_gaps_target_object
ON p1_coverage_gaps(target_object_id, gap_marker)
WHERE target_object_id IS NOT NULL;

CREATE TABLE maintenance_pins (
    pin_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('backup', 'export', 'rebuild')),
    frontier_seq INTEGER NOT NULL CHECK (frontier_seq >= 0),
    frontier_digest TEXT NOT NULL,
    privacy_root_generation INTEGER NOT NULL CHECK (privacy_root_generation >= 0),
    privacy_root_digest TEXT NOT NULL,
    owner_generation TEXT NOT NULL,
    lease_generation INTEGER NOT NULL CHECK (lease_generation > 0),
    expires_at TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('active', 'released', 'expired')),
    created_at TEXT NOT NULL,
    released_at TEXT,
    CHECK (
        (state = 'active' AND released_at IS NULL)
        OR
        (state IN ('released', 'expired') AND released_at IS NOT NULL)
    )
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX maintenance_pins_one_active_operation
ON maintenance_pins(operation_id)
WHERE state = 'active';

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

CREATE INDEX refs_target
ON event_refs(ref_type, target_id);

CREATE INDEX semantic_jobs_operation_state
ON semantic_jobs(writer_id, operation_id, state);

CREATE INDEX import_request_aliases_source
ON import_request_aliases(
    source_identity_digest,
    requesting_writer_id,
    request_id
);

CREATE INDEX import_jobs_session_state
ON import_jobs(session_id, state, source_identity_digest);

CREATE INDEX import_jobs_session_terminal
ON import_jobs(session_id, terminal_at, source_identity_digest);

CREATE INDEX import_batches_next
ON import_batches(source_identity_digest, state, batch_index);

PRAGMA user_version = 1;
