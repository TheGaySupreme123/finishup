PRAGMA application_id = 0x594F4554;

-- Migration 0007 admits the provenance_disputed response disposition. SQLite cannot widen a
-- table CHECK constraint in place. Preserve the generation-1 query tables as immutable history,
-- seed generation-2 replacements from them, and let the current repository write only p2 rows.

CREATE TABLE p2_query_findings (
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
        'none', 'acknowledged', 'provenance_disputed', 'rejected', 'waived'
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

CREATE TABLE p2_query_finding_subject_refs (
    finding_id TEXT NOT NULL,
    valid_from_seq INTEGER NOT NULL,
    subject_ref TEXT NOT NULL,
    PRIMARY KEY (finding_id, valid_from_seq, subject_ref),
    FOREIGN KEY (finding_id, valid_from_seq)
        REFERENCES p2_query_findings(finding_id, valid_from_seq)
) STRICT, WITHOUT ROWID;

CREATE TABLE p2_query_finding_order (
    finding_id TEXT NOT NULL,
    valid_from_seq INTEGER NOT NULL,
    valid_to_seq INTEGER,
    origin_filter TEXT NOT NULL CHECK (origin_filter IN (
        '*', 'deterministic', 'semantic_model_derived'
    )),
    priority_filter INTEGER NOT NULL CHECK (priority_filter BETWEEN 0 AND 3),
    disposition_filter TEXT NOT NULL CHECK (disposition_filter IN (
        '*', 'none', 'acknowledged', 'provenance_disputed', 'rejected', 'waived'
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
        REFERENCES p2_query_findings(finding_id, valid_from_seq),
    CHECK (valid_to_seq IS NULL OR valid_to_seq > valid_from_seq)
) STRICT, WITHOUT ROWID;

CREATE TABLE p2_query_responses (
    finding_id TEXT NOT NULL,
    valid_from_seq INTEGER NOT NULL CHECK (valid_from_seq > 0),
    valid_to_seq INTEGER CHECK (valid_to_seq > valid_from_seq),
    response_event_id TEXT NOT NULL REFERENCES event_projection_locators(event_id),
    source_frontier INTEGER NOT NULL CHECK (source_frontier > 0),
    disposition TEXT CHECK (
        disposition IN ('acknowledged', 'provenance_disputed', 'rejected', 'waived')
    ),
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

CREATE TABLE p2_query_response_evidence_refs (
    finding_id TEXT NOT NULL,
    valid_from_seq INTEGER NOT NULL,
    evidence_ref TEXT NOT NULL,
    PRIMARY KEY (finding_id, valid_from_seq, evidence_ref),
    FOREIGN KEY (finding_id, valid_from_seq)
        REFERENCES p2_query_responses(finding_id, valid_from_seq)
) STRICT, WITHOUT ROWID;

INSERT INTO p2_query_findings (
    finding_id, valid_from_seq, valid_to_seq, source_event_id, source_frontier,
    issue_key_canonical, kind, origin, policy_id, policy_version, subject_frontier_seq,
    subject_frontier_digest, priority, actionable, artifact_ordinal, immutability_ordinal,
    freshness_ordinal, authorship_ordinal, real_check_present, known_gap_count, origin_ordinal,
    coverage_canonical, disposition, response_event_id, resolved, tombstone
) SELECT
    finding_id, valid_from_seq, valid_to_seq, source_event_id, source_frontier,
    issue_key_canonical, kind, origin, policy_id, policy_version, subject_frontier_seq,
    subject_frontier_digest, priority, actionable, artifact_ordinal, immutability_ordinal,
    freshness_ordinal, authorship_ordinal, real_check_present, known_gap_count, origin_ordinal,
    coverage_canonical, disposition, response_event_id, resolved, tombstone
FROM p1_query_findings;

INSERT INTO p2_query_finding_subject_refs (finding_id, valid_from_seq, subject_ref)
SELECT finding_id, valid_from_seq, subject_ref FROM p1_query_finding_subject_refs;

INSERT INTO p2_query_finding_order (
    finding_id, valid_from_seq, valid_to_seq, origin_filter, priority_filter,
    disposition_filter, resolution_filter, rank_priority, rank_actionable_sort,
    rank_artifact_sort, rank_immutability_sort, rank_freshness_sort, rank_authorship_sort,
    rank_real_check_sort, rank_known_gap_count, rank_origin_ordinal
) SELECT
    finding_id, valid_from_seq, valid_to_seq, origin_filter, priority_filter,
    disposition_filter, resolution_filter, rank_priority, rank_actionable_sort,
    rank_artifact_sort, rank_immutability_sort, rank_freshness_sort, rank_authorship_sort,
    rank_real_check_sort, rank_known_gap_count, rank_origin_ordinal
FROM p1_query_finding_order;

INSERT INTO p2_query_responses (
    finding_id, valid_from_seq, valid_to_seq, response_event_id, source_frontier,
    disposition, waiver_scope, waiver_expiry, tombstone
) SELECT
    finding_id, valid_from_seq, valid_to_seq, response_event_id, source_frontier,
    disposition, waiver_scope, waiver_expiry, tombstone
FROM p1_query_responses;

INSERT INTO p2_query_response_evidence_refs (finding_id, valid_from_seq, evidence_ref)
SELECT finding_id, valid_from_seq, evidence_ref FROM p1_query_response_evidence_refs;

CREATE INDEX p2_query_findings_issue
ON p2_query_findings(
    issue_key_canonical,
    source_frontier,
    finding_id,
    valid_from_seq,
    valid_to_seq
);

CREATE INDEX p2_query_finding_subject_refs_target
ON p2_query_finding_subject_refs(subject_ref, finding_id, valid_from_seq);

CREATE INDEX p2_query_finding_order_cover
ON p2_query_finding_order(
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

CREATE INDEX p2_query_response_evidence_refs_target
ON p2_query_response_evidence_refs(evidence_ref, finding_id, valid_from_seq);

PRAGMA user_version = 7;
