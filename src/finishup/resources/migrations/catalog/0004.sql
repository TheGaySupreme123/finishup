-- Task lineage, per-session health, and the installation-scoped project registry.
-- User text and task evidence remain in task bundles; catalog columns contain only structural
-- identifiers, keyed commitments, digests, and state vocabulary.

ALTER TABLE task_routes
ADD COLUMN parent_task_id TEXT REFERENCES task_routes(task_id);

ALTER TABLE task_routes
ADD COLUMN depth INTEGER NOT NULL DEFAULT 0 CHECK (depth >= 0);

ALTER TABLE task_routes
ADD COLUMN lineage_digest TEXT NOT NULL
    DEFAULT 'sha256:0000000000000000000000000000000000000000000000000000000000000000'
    CHECK (length(lineage_digest) = 71 AND substr(lineage_digest, 1, 7) = 'sha256:');

ALTER TABLE task_routes
ADD COLUMN origin TEXT CHECK (origin IN ('parent_minted', 'self_registered', 'host_observed'));

ALTER TABLE task_routes
ADD COLUMN acceptance TEXT CHECK (acceptance IN ('pending', 'accepted', 'rejected'));

ALTER TABLE task_routes
ADD COLUMN work_state TEXT NOT NULL DEFAULT 'open'
    CHECK (work_state IN ('open', 'closed', 'cancelled', 'abandoned', 'written_off'));

-- A pre-0004 route is a root. Its route identity is the stable initial lineage identity; this
-- backfill avoids fabricating one shared digest for all existing routes.
UPDATE task_routes
SET lineage_digest = active_route_identity_digest
WHERE lineage_digest =
    'sha256:0000000000000000000000000000000000000000000000000000000000000000';

-- `delegate` is a start mode, so widen the pre-existing CHECK without weakening any of the
-- operation-state invariants.  No catalog table has a foreign key to start_operations; the
-- rename/copy is therefore failure-atomic inside the migration transaction and preserves every
-- existing request row byte-for-byte.
ALTER TABLE start_operations RENAME TO start_operations_v3;

CREATE TABLE start_operations (
    installation_id TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    requested_mode TEXT NOT NULL
        CHECK (requested_mode IN ('create', 'attach', 'create_or_attach', 'delegate')),
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

INSERT INTO start_operations(
    installation_id, operation_id, request_digest, requested_mode, route_action, state, phase,
    task_id, session_id, writer_id, lifecycle_event_id, route_generation, route_identity_digest,
    owner_generation, lease_owner_id, lease_generation, lease_expires_at, response_object_id,
    response_envelope_digest, terminal_result_canonical, terminal_result_digest, quarantine_code,
    terminal_at, created_at, updated_at
)
SELECT
    installation_id, operation_id, request_digest, requested_mode, route_action, state, phase,
    task_id, session_id, writer_id, lifecycle_event_id, route_generation, route_identity_digest,
    owner_generation, lease_owner_id, lease_generation, lease_expires_at, response_object_id,
    response_envelope_digest, terminal_result_canonical, terminal_result_digest, quarantine_code,
    terminal_at, created_at, updated_at
FROM start_operations_v3;

DROP TABLE start_operations_v3;

CREATE INDEX task_routes_parent_work_state
ON task_routes(parent_task_id, work_state, task_id)
WHERE parent_task_id IS NOT NULL;

CREATE INDEX task_routes_repository_work_state
ON task_routes(repository_privacy_commitment, work_state, task_id)
WHERE repository_privacy_commitment IS NOT NULL;

CREATE TABLE task_sessions (
    session_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES task_routes(task_id),
    health TEXT NOT NULL CHECK (health IN ('active', 'contact_lost', 'ended')),
    changed_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    ended_at TEXT,
    lease_expires_at TEXT,
    actor_id TEXT
) STRICT, WITHOUT ROWID;

CREATE INDEX task_sessions_task_health
ON task_sessions(task_id, health, session_id);

INSERT INTO task_sessions(
    session_id, task_id, health, changed_at, created_at, ended_at, lease_expires_at, actor_id
)
SELECT active_session_id, task_id, 'contact_lost', updated_at, created_at, NULL, NULL, NULL
FROM task_routes;

CREATE TABLE projects (
    project_id TEXT PRIMARY KEY
        CHECK (length(project_id) = 40 AND substr(project_id, 1, 4) = 'prj_'),
    kind TEXT NOT NULL CHECK (kind IN ('repository', 'general')),
    repository_commitment TEXT,
    auto_grouping INTEGER NOT NULL DEFAULT 1 CHECK (auto_grouping IN (0, 1)),
    membership_generation INTEGER NOT NULL DEFAULT 1 CHECK (membership_generation > 0),
    created_at TEXT NOT NULL,
    dissolved_at TEXT,
    title_ref_canonical BLOB CHECK (title_ref_canonical IS NULL OR length(title_ref_canonical) BETWEEN 1 AND 2048),
    description_ref_canonical BLOB CHECK (description_ref_canonical IS NULL OR length(description_ref_canonical) BETWEEN 1 AND 2048),
    CHECK (
        (kind = 'repository' AND repository_commitment IS NOT NULL)
        OR
        (kind = 'general' AND repository_commitment IS NULL)
    ),
    CHECK (dissolved_at IS NULL OR dissolved_at >= created_at)
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX projects_repository_commitment
ON projects(repository_commitment)
WHERE kind = 'repository' AND repository_commitment IS NOT NULL;

-- A repository may opt out before its first implicit project is born.  Keep that
-- repository-scoped preference separate from projects so an opt-out never creates
-- a project row as a side effect.  The preference is structural authority only;
-- it contains no task or user content.
CREATE TABLE repository_grouping_preferences (
    repository_commitment TEXT PRIMARY KEY
        CHECK (length(repository_commitment) = 76
            AND substr(repository_commitment, 1, 12) = 'hmac-sha256:'),
    auto_grouping INTEGER NOT NULL CHECK (auto_grouping IN (0, 1)),
    updated_at TEXT NOT NULL
) STRICT, WITHOUT ROWID;

CREATE TABLE project_memberships (
    project_id TEXT NOT NULL REFERENCES projects(project_id),
    membership_generation INTEGER NOT NULL CHECK (membership_generation > 0),
    member_kind TEXT NOT NULL CHECK (member_kind IN ('repository', 'workspace', 'task')),
    member_commitment_or_id TEXT NOT NULL,
    bound_at TEXT NOT NULL,
    unbound_at TEXT,
    PRIMARY KEY (
        project_id,
        membership_generation,
        member_kind,
        member_commitment_or_id
    ),
    CHECK (length(member_commitment_or_id) BETWEEN 1 AND 128),
    CHECK (unbound_at IS NULL OR unbound_at >= bound_at)
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX project_memberships_one_active_member
ON project_memberships(project_id, member_kind, member_commitment_or_id)
WHERE unbound_at IS NULL;

CREATE INDEX project_memberships_generation
ON project_memberships(project_id, membership_generation, member_kind, member_commitment_or_id);

CREATE TABLE coordination_grants (
    project_id TEXT NOT NULL REFERENCES projects(project_id),
    membership_generation INTEGER NOT NULL CHECK (membership_generation > 0),
    grant_state TEXT NOT NULL CHECK (grant_state IN ('active', 'revoked')),
    audit_record_id TEXT NOT NULL CHECK (length(audit_record_id) BETWEEN 1 AND 128),
    granted_at TEXT NOT NULL,
    revoked_at TEXT,
    PRIMARY KEY (project_id, membership_generation),
    CHECK (
        (grant_state = 'active' AND revoked_at IS NULL)
        OR
        (grant_state = 'revoked' AND revoked_at IS NOT NULL)
    ),
    CHECK (revoked_at IS NULL OR revoked_at >= granted_at)
) STRICT, WITHOUT ROWID;

CREATE INDEX coordination_grants_current
ON coordination_grants(project_id, grant_state, membership_generation);

CREATE TRIGGER task_routes_lineage_shape_insert
BEFORE INSERT ON task_routes
WHEN (
    (NEW.parent_task_id IS NULL AND (NEW.depth != 0 OR NEW.origin IS NOT NULL OR NEW.acceptance IS NOT NULL))
    OR
    (NEW.parent_task_id IS NOT NULL AND (NEW.depth <= 0 OR NEW.origin IS NULL OR NEW.acceptance IS NULL))
)
BEGIN
    SELECT RAISE(ABORT, 'task_lineage_shape_invalid');
END;

CREATE TRIGGER task_routes_lineage_shape_update
BEFORE UPDATE OF parent_task_id, depth, lineage_digest, origin, acceptance ON task_routes
WHEN NOT (
    OLD.parent_task_id IS NULL AND OLD.depth = 0 AND OLD.origin IS NULL AND OLD.acceptance IS NULL
    AND OLD.state != 'quarantined'
    AND NEW.parent_task_id IS NOT NULL AND NEW.depth > 0
    AND NEW.origin IS NOT NULL AND NEW.acceptance IS NOT NULL
)
AND (
    OLD.parent_task_id IS NOT NEW.parent_task_id
    OR OLD.depth IS NOT NEW.depth
    OR OLD.lineage_digest IS NOT NEW.lineage_digest
    OR OLD.origin IS NOT NEW.origin
    OR (
        OLD.acceptance IS NOT NEW.acceptance
        AND NOT (OLD.acceptance = 'pending' AND NEW.acceptance IN ('accepted', 'rejected'))
    )
    OR (NEW.parent_task_id IS NULL AND (NEW.depth != 0 OR NEW.origin IS NOT NULL OR NEW.acceptance IS NOT NULL))
    OR (NEW.parent_task_id IS NOT NULL AND (NEW.depth <= 0 OR NEW.origin IS NULL OR NEW.acceptance IS NULL))
)
BEGIN
    SELECT RAISE(ABORT, 'task_lineage_transition_invalid');
END;

CREATE TRIGGER task_sessions_health_transition
BEFORE UPDATE OF health ON task_sessions
WHEN NOT (
    OLD.health IS NEW.health
    OR (OLD.health = 'active' AND NEW.health IN ('contact_lost', 'ended'))
    OR (OLD.health = 'contact_lost' AND NEW.health IN ('active', 'ended'))
)
BEGIN
    SELECT RAISE(ABORT, 'session_health_transition_invalid');
END;

CREATE TRIGGER project_memberships_append_only
BEFORE UPDATE OF project_id, membership_generation, member_kind, member_commitment_or_id, bound_at, unbound_at
ON project_memberships
WHEN OLD.unbound_at IS NOT NULL
  OR OLD.project_id IS NOT NEW.project_id
  OR OLD.membership_generation IS NOT NEW.membership_generation
  OR OLD.member_kind IS NOT NEW.member_kind
  OR OLD.member_commitment_or_id IS NOT NEW.member_commitment_or_id
  OR OLD.bound_at IS NOT NEW.bound_at
  OR NEW.unbound_at IS NULL
BEGIN
    SELECT RAISE(ABORT, 'project_membership_append_only');
END;

CREATE TRIGGER coordination_grants_monotonic
BEFORE UPDATE OF grant_state, membership_generation, audit_record_id, granted_at, revoked_at
ON coordination_grants
WHEN OLD.grant_state = 'revoked'
  OR OLD.membership_generation IS NOT NEW.membership_generation
  OR OLD.audit_record_id IS NOT NEW.audit_record_id
  OR OLD.granted_at IS NOT NEW.granted_at
  OR NEW.grant_state != 'revoked'
  OR NEW.revoked_at IS NULL
BEGIN
    SELECT RAISE(ABORT, 'coordination_grant_transition_invalid');
END;

-- Delegation reservations, single-use attach capabilities, and frozen child manifests.  The
-- operation rows are installation-scoped and retain their request identity across restart.  The
-- opaque handle value is private catalog material; structural status and receipts expose only its
-- digest and the child binding.
CREATE TABLE lineage_task_meta (
    task_id TEXT PRIMARY KEY REFERENCES task_routes(task_id),
    lineage_authority_revision INTEGER NOT NULL CHECK (lineage_authority_revision > 0),
    contact_lost_at TEXT,
    abandonment_deadline TEXT
) STRICT, WITHOUT ROWID;

CREATE TABLE lineage_operations (
    installation_id TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    parent_task_id TEXT NOT NULL REFERENCES task_routes(task_id),
    parent_session_id TEXT NOT NULL,
    child_task_id TEXT NOT NULL REFERENCES task_routes(task_id),
    depth INTEGER NOT NULL CHECK (depth > 0),
    phase TEXT NOT NULL CHECK (phase IN (
        'lineage_reserved', 'child_bundle_ready', 'parent_event_committed',
        'handle_published', 'terminal'
    )),
    state TEXT NOT NULL CHECK (state IN ('pending', 'complete', 'quarantined')),
    handle_digest TEXT NOT NULL,
    owner_generation INTEGER NOT NULL CHECK (owner_generation > 0),
    lease_expires_at TEXT NOT NULL,
    terminal_at TEXT,
    project_id TEXT REFERENCES projects(project_id)
        CHECK (project_id IS NULL OR (
            length(project_id) = 40 AND substr(project_id, 1, 4) = 'prj_'
        )),
    membership_generation INTEGER
        CHECK (membership_generation IS NULL OR membership_generation > 0),
    PRIMARY KEY (installation_id, operation_id),
    UNIQUE (installation_id, handle_digest),
    CHECK ((project_id IS NULL) = (membership_generation IS NULL))
) STRICT, WITHOUT ROWID;

CREATE INDEX lineage_operations_pending
ON lineage_operations(installation_id, state, lease_expires_at, operation_id);

CREATE TABLE lineage_attach_handles (
    handle_digest TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES task_routes(task_id),
    handle_value TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_session_id TEXT,
    revoked INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1))
) STRICT, WITHOUT ROWID;

CREATE TABLE lineage_manifests (
    parent_task_id TEXT NOT NULL REFERENCES task_routes(task_id),
    child_task_id TEXT NOT NULL REFERENCES task_routes(task_id),
    manifest_digest TEXT NOT NULL,
    lineage_authority_revision INTEGER NOT NULL CHECK (lineage_authority_revision > 0),
    membership_generation INTEGER,
    canonical BLOB NOT NULL,
    PRIMARY KEY (parent_task_id, child_task_id)
) STRICT, WITHOUT ROWID;

-- Host hooks can observe a subagent before the service has minted a child route.  Keep this
-- provisional registry installation-scoped and commitment-only: the host ids and conversation
-- values never enter the catalog in cleartext.  Correlation ids are HMAC commitments, so a
-- correlation may be safely unique within one installation while aliases remain many-to-one for
-- ambiguity detection.
CREATE TABLE host_lineage_annotations (
    installation_id TEXT NOT NULL,
    correlation_id TEXT NOT NULL
        CHECK (length(correlation_id) = 76 AND substr(correlation_id, 1, 12) = 'hmac-sha256:'),
    parent_task_id TEXT NOT NULL REFERENCES task_routes(task_id),
    host_profile TEXT NOT NULL CHECK (host_profile IN ('claude', 'codex', 'cursor')),
    subagent_id_commitment TEXT NOT NULL
        CHECK (length(subagent_id_commitment) = 76
            AND substr(subagent_id_commitment, 1, 12) = 'hmac-sha256:'),
    parent_tool_call_id_commitment TEXT
        CHECK (parent_tool_call_id_commitment IS NULL OR (
            length(parent_tool_call_id_commitment) = 76
            AND substr(parent_tool_call_id_commitment, 1, 12) = 'hmac-sha256:'
        )),
    parent_conversation_id_commitment TEXT
        CHECK (parent_conversation_id_commitment IS NULL OR (
            length(parent_conversation_id_commitment) = 76
            AND substr(parent_conversation_id_commitment, 1, 12) = 'hmac-sha256:'
        )),
    conversation_id_commitment TEXT
        CHECK (conversation_id_commitment IS NULL OR (
            length(conversation_id_commitment) = 76
            AND substr(conversation_id_commitment, 1, 12) = 'hmac-sha256:'
        )),
    phase_mask INTEGER NOT NULL CHECK (phase_mask IN (1, 2, 3)),
    source_mask INTEGER NOT NULL CHECK (source_mask IN (1, 2, 3)),
    last_session_commitment TEXT NOT NULL
        CHECK (length(last_session_commitment) = 76
            AND substr(last_session_commitment, 1, 12) = 'hmac-sha256:'),
    first_observed_at TEXT NOT NULL,
    last_observed_at TEXT NOT NULL,
    bound_child_task_id TEXT REFERENCES task_routes(task_id),
    bound_at TEXT,
    PRIMARY KEY (installation_id, correlation_id),
    UNIQUE (installation_id, parent_task_id, correlation_id),
    CHECK (last_observed_at >= first_observed_at),
    CHECK (
        (bound_child_task_id IS NULL AND bound_at IS NULL)
        OR (bound_child_task_id IS NOT NULL AND bound_at IS NOT NULL)
    )
) STRICT, WITHOUT ROWID;

CREATE INDEX host_lineage_annotations_parent
ON host_lineage_annotations(
    installation_id, parent_task_id, bound_child_task_id, correlation_id
);

CREATE TABLE host_lineage_annotation_aliases (
    installation_id TEXT NOT NULL,
    parent_task_id TEXT NOT NULL,
    host_profile TEXT NOT NULL CHECK (host_profile IN ('claude', 'codex', 'cursor')),
    alias_kind TEXT NOT NULL CHECK (
        alias_kind IN ('strong', 'parent_tool', 'parent_conversation', 'conversation', 'child')
    ),
    alias_commitment TEXT NOT NULL
        CHECK (length(alias_commitment) = 76 AND substr(alias_commitment, 1, 12) = 'hmac-sha256:'),
    correlation_id TEXT NOT NULL,
    PRIMARY KEY (
        installation_id, parent_task_id, host_profile, alias_kind, alias_commitment, correlation_id
    ),
    FOREIGN KEY (installation_id, parent_task_id, correlation_id)
        REFERENCES host_lineage_annotations(installation_id, parent_task_id, correlation_id)
) STRICT, WITHOUT ROWID;

CREATE INDEX host_lineage_alias_lookup
ON host_lineage_annotation_aliases(
    installation_id, parent_task_id, host_profile, alias_kind, alias_commitment
);

-- Coordination detections and deliveries are structural retry state.  Resource names and plan
-- prose live in the encrypted detail object named by detail_ref_json; JSON columns here are
-- canonical, bounded containers only.  Duplicate delivery outcomes are derived by the adapter
-- from the durable first result and are never written as a third state.
CREATE TABLE coordination_detections (
    detection_id TEXT PRIMARY KEY
        CHECK (length(detection_id) = 40 AND substr(detection_id, 1, 4) = 'evt_'),
    project_id TEXT NOT NULL REFERENCES projects(project_id),
    membership_generation INTEGER NOT NULL CHECK (membership_generation > 0),
    left_task_id TEXT NOT NULL REFERENCES task_routes(task_id),
    right_task_id TEXT NOT NULL REFERENCES task_routes(task_id),
    overlap_kind TEXT NOT NULL CHECK (overlap_kind IN ('physical', 'integration', 'plan')),
    resource_identities_json TEXT NOT NULL
        CHECK (length(resource_identities_json) BETWEEN 2 AND 65536),
    counterpart_task_id TEXT NOT NULL REFERENCES task_routes(task_id),
    advice_only INTEGER NOT NULL CHECK (advice_only IN (0, 1)),
    obligation_declared INTEGER NOT NULL CHECK (obligation_declared IN (0, 1)),
    addressed INTEGER NOT NULL CHECK (addressed IN (0, 1)),
    generation_valid INTEGER NOT NULL CHECK (generation_valid IN (0, 1)),
    detail_ref_json TEXT CHECK (detail_ref_json IS NULL OR (
        length(detail_ref_json) BETWEEN 2 AND 2048
    )),
    resolved INTEGER NOT NULL CHECK (resolved IN (0, 1)),
    CHECK (left_task_id != right_task_id),
    CHECK (counterpart_task_id IN (left_task_id, right_task_id)),
    CHECK (addressed = 0 OR obligation_declared = 1),
    CHECK (resolved = 0 OR (obligation_declared = 1 AND addressed = 1))
) STRICT, WITHOUT ROWID;

CREATE INDEX coordination_detections_project_generation
ON coordination_detections(project_id, membership_generation, detection_id);

CREATE TABLE coordination_participants (
    detection_id TEXT NOT NULL REFERENCES coordination_detections(detection_id),
    task_id TEXT NOT NULL REFERENCES task_routes(task_id),
    project_id TEXT NOT NULL REFERENCES projects(project_id),
    repository_commitment TEXT NOT NULL
        CHECK (length(repository_commitment) = 76
            AND substr(repository_commitment, 1, 12) = 'hmac-sha256:'),
    workspace_commitment TEXT NOT NULL
        CHECK (length(workspace_commitment) = 76
            AND substr(workspace_commitment, 1, 12) = 'hmac-sha256:'),
    route_generation INTEGER NOT NULL CHECK (route_generation > 0),
    source_has_attributable_paths INTEGER NOT NULL CHECK (source_has_attributable_paths IN (0, 1)),
    PRIMARY KEY (detection_id, task_id)
) STRICT, WITHOUT ROWID;

CREATE INDEX coordination_participants_project
ON coordination_participants(project_id, task_id, detection_id);

CREATE TABLE coordination_deliveries (
    detection_id TEXT NOT NULL REFERENCES coordination_detections(detection_id),
    target_task_id TEXT NOT NULL REFERENCES task_routes(task_id),
    outcome TEXT NOT NULL CHECK (outcome IN ('delivered', 'refused')),
    expected_generation INTEGER NOT NULL CHECK (expected_generation > 0),
    observed_generation INTEGER NOT NULL CHECK (observed_generation > 0),
    reason_code TEXT CHECK (reason_code IS NULL OR (
        length(reason_code) BETWEEN 1 AND 128
        AND reason_code NOT GLOB '*[^A-Za-z0-9_:-]*'
    )),
    advice_json TEXT CHECK (advice_json IS NULL OR length(advice_json) BETWEEN 2 AND 65536),
    PRIMARY KEY (detection_id, target_task_id),
    CHECK (outcome = 'delivered' OR reason_code IS NOT NULL),
    CHECK (outcome = 'refused' OR reason_code IS NULL)
) STRICT, WITHOUT ROWID;

CREATE INDEX coordination_deliveries_target
ON coordination_deliveries(target_task_id, detection_id);

CREATE TABLE coordination_coverage (
    coverage_id TEXT PRIMARY KEY
        CHECK (length(coverage_id) = 40 AND substr(coverage_id, 1, 4) = 'evt_'),
    project_id TEXT NOT NULL REFERENCES projects(project_id),
    task_id TEXT NOT NULL REFERENCES task_routes(task_id),
    membership_generation INTEGER NOT NULL CHECK (membership_generation > 0),
    coverage TEXT NOT NULL CHECK (coverage = 'unobservable'),
    gap_code TEXT NOT NULL CHECK (gap_code = 'not_observable'),
    UNIQUE (project_id, task_id, membership_generation)
) STRICT, WITHOUT ROWID;

CREATE INDEX coordination_coverage_project_generation
ON coordination_coverage(project_id, membership_generation, task_id, coverage_id);

CREATE TABLE coordination_obligations (
    detection_id TEXT NOT NULL REFERENCES coordination_detections(detection_id),
    task_id TEXT NOT NULL REFERENCES task_routes(task_id),
    obligation_id TEXT CHECK (obligation_id IS NULL OR (
        length(obligation_id) = 40 AND substr(obligation_id, 1, 4) = 'obl_'
    )),
    declared INTEGER NOT NULL CHECK (declared IN (0, 1)),
    addressed INTEGER NOT NULL CHECK (addressed IN (0, 1)),
    resolved INTEGER NOT NULL CHECK (resolved IN (0, 1)),
    PRIMARY KEY (detection_id, task_id),
    CHECK (declared = 0 OR obligation_id IS NOT NULL),
    CHECK (addressed = 0 OR declared = 1),
    CHECK (resolved = 0 OR (declared = 1 AND addressed = 1))
) STRICT, WITHOUT ROWID;

CREATE INDEX coordination_obligations_task
ON coordination_obligations(task_id, detection_id);

-- A delegated child inherits the parent's source commitments so the lineage source gate can
-- prove the same workspace/repository scope. It is service-minted and therefore must not
-- consume the caller's create-or-attach identity pair. Keep the uniqueness fence for root
-- caller bindings only; otherwise the first delegated child collides with its parent before its
-- attach handle can be returned.
DROP INDEX IF EXISTS task_routes_scoped_attachment;
CREATE UNIQUE INDEX task_routes_scoped_attachment
ON task_routes(workspace_ref_commitment, external_ref_commitment)
WHERE parent_task_id IS NULL
  AND workspace_ref_commitment IS NOT NULL
  AND external_ref_commitment IS NOT NULL;

PRAGMA user_version = 4;
