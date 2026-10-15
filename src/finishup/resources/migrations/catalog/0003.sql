ALTER TABLE task_routes
ADD COLUMN repository_privacy_commitment TEXT;

CREATE TABLE privacy_installation_authority (
    installation_id TEXT PRIMARY KEY,
    authority_mode TEXT NOT NULL CHECK (authority_mode = 'repository_grants'),
    migration_frontier TEXT NOT NULL,
    migration_policy_generation INTEGER NOT NULL CHECK (migration_policy_generation > 0),
    migration_policy_digest TEXT NOT NULL,
    migration_policy_canonical BLOB NOT NULL,
    first_repository_carry_forward_state TEXT NOT NULL
        CHECK (first_repository_carry_forward_state IN ('available', 'consumed', 'not_applicable')),
    first_repository_carry_forward_commitment TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK (
        (first_repository_carry_forward_state = 'consumed'
            AND first_repository_carry_forward_commitment IS NOT NULL)
        OR
        (first_repository_carry_forward_state != 'consumed'
            AND first_repository_carry_forward_commitment IS NULL)
    )
) STRICT, WITHOUT ROWID;

CREATE TABLE privacy_legacy_route_entitlements (
    task_id TEXT PRIMARY KEY REFERENCES task_routes(task_id),
    legacy_workspace_ref_commitment TEXT,
    route_identity_digest TEXT NOT NULL,
    migration_policy_generation INTEGER NOT NULL CHECK (migration_policy_generation > 0),
    migration_policy_digest TEXT NOT NULL,
    migration_policy_canonical BLOB NOT NULL,
    entitlement_state TEXT NOT NULL CHECK (entitlement_state IN ('available', 'consumed')),
    repository_privacy_commitment TEXT,
    consumed_at TEXT,
    CHECK (
        (entitlement_state = 'available'
            AND repository_privacy_commitment IS NULL AND consumed_at IS NULL)
        OR
        (entitlement_state = 'consumed'
            AND repository_privacy_commitment IS NOT NULL AND consumed_at IS NOT NULL)
    )
) STRICT, WITHOUT ROWID;

INSERT INTO privacy_legacy_route_entitlements (
    task_id,
    legacy_workspace_ref_commitment,
    route_identity_digest,
    migration_policy_generation,
    migration_policy_digest,
    migration_policy_canonical,
    entitlement_state
)
SELECT
    route.task_id,
    route.workspace_ref_commitment,
    route.active_route_identity_digest,
    machine.policy_generation,
    machine.policy_digest,
    machine.policy_canonical,
    'available'
FROM task_routes AS route
CROSS JOIN privacy_policy_versions AS machine
WHERE machine.scope_kind = 'machine' AND machine.state = 'current';

INSERT INTO privacy_installation_authority (
    installation_id,
    authority_mode,
    migration_frontier,
    migration_policy_generation,
    migration_policy_digest,
    migration_policy_canonical,
    first_repository_carry_forward_state,
    created_at,
    updated_at
)
SELECT
    machine.installation_id,
    'repository_grants',
    machine.policy_digest,
    machine.policy_generation,
    machine.policy_digest,
    machine.policy_canonical,
    CASE
        WHEN EXISTS (SELECT 1 FROM privacy_legacy_route_entitlements) THEN 'not_applicable'
        WHEN json_extract(
            CAST(machine.policy_canonical AS TEXT),
            '$.network_egress_permitted'
        ) = 1 THEN 'available'
        ELSE 'not_applicable'
    END,
    machine.created_at,
    machine.created_at
FROM privacy_policy_versions AS machine
WHERE machine.scope_kind = 'machine' AND machine.state = 'current';

ALTER TABLE privacy_policy_transitions
ADD COLUMN authority_digest TEXT;

ALTER TABLE privacy_policy_transitions
ADD COLUMN terminal_result_canonical BLOB;

ALTER TABLE privacy_policy_transitions
ADD COLUMN terminal_result_digest TEXT;

ALTER TABLE privacy_policy_transitions
ADD COLUMN decision_at TEXT;

ALTER TABLE privacy_policy_transitions
ADD COLUMN terminal_result_version INTEGER;

CREATE TABLE privacy_policy_transition_members (
    proposal_id TEXT NOT NULL REFERENCES privacy_policy_transitions(proposal_id),
    member_ordinal INTEGER NOT NULL CHECK (member_ordinal >= 0),
    action TEXT NOT NULL CHECK (action IN ('replace', 'insert')),
    scope_digest TEXT NOT NULL,
    scope_kind TEXT NOT NULL CHECK (scope_kind IN ('machine', 'workspace', 'task', 'request')),
    scope_canonical BLOB NOT NULL,
    expected_policy_generation INTEGER CHECK (expected_policy_generation > 0),
    expected_policy_digest TEXT,
    candidate_policy_digest TEXT NOT NULL,
    candidate_policy_canonical BLOB NOT NULL,
    PRIMARY KEY (proposal_id, member_ordinal),
    UNIQUE (proposal_id, scope_digest),
    CHECK (
        (action = 'replace'
            AND expected_policy_generation IS NOT NULL AND expected_policy_digest IS NOT NULL)
        OR
        (action = 'insert'
            AND expected_policy_generation IS NULL AND expected_policy_digest IS NULL)
    )
) STRICT, WITHOUT ROWID;

PRAGMA user_version = 3;
