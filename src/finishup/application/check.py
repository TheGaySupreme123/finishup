"""Local check coordination and AI-powered review result validation fences."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, replace
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, Literal, NamedTuple, Protocol, TypedDict, cast

from finishup.application.closure_basis import (
    ClosureBasisUnavailable,
    LoadedClosureBasis,
    load_closure_basis,
)
from finishup.application.ledger_snapshot import projection_for_records, trusted_projection_at
from finishup.application.missing_for_assessment import (
    MissingItemsReview,
    review_missing_for_assessment,
    unsupported_data_type,
)
from finishup.application.review_concern import answer_bound, concern_material_after
from finishup.domain.coordination import CoordinationError, CoordinationErrorCode
from finishup.domain.correctness_advisories import (
    MAX_ADVISORIES_PER_CHECK,
    TRACKED_ADVICE_FAMILIES,
    validate_advisories,
)
from finishup.domain.events import (
    MAX_SEMANTIC_INCLUDED_REFS,
    MAX_UNDECLARED_REFERENCES,
    SEMANTIC_INCLUDED_REFS_NOT_RECORDED_GAP,
    ActionKind,
    CheckChangeShownFiles,
    CheckRecordedPayload,
    CheckReviewMode,
    ClaimKind,
    DeliverableState,
    LedgerRecord,
    ResultRecordedPayload,
    ReviewMode,
    undeclared_reference_path_valid,
)
from finishup.domain.findings import (
    DISPUTED_AFTER_REBUTTAL_VERDICT,
    FINDING_KIND_TRAITS,
    MAX_RECORDED_VERDICTS,
    CandidateFinding,
    Finding,
    FindingChallenge,
    FindingKind,
    FindingOrigin,
    PriorFindingVerdictRecord,
    RankedFindings,
    SemanticProvenance,
    finding_demands_work,
    finding_from_json,
    finding_policy_identity,
    finding_to_json,
    is_limitation_request,
    semantic_provenance_to_json,
)
from finishup.domain.privacy import ConversationReview
from finishup.domain.receipts import (
    CHECK_TIME_CHANGE_GAPS,
    CHECK_TIME_CHANGE_PATH_UNREPRESENTABLE_GAP,
    CHECK_TIME_CHANGE_REDACTED_GAP,
    CHECK_TIME_CHANGE_TRUNCATED_GAP,
    CHECK_TIME_CHANGE_UNAVAILABLE_GAP,
    COMPLETION_SCOPE_DECLARED_NONE_GAP,
    COMPLETION_SCOPE_UNDECLARED_GAP,
    OPTIONAL_SEMANTIC_REVIEW_BLOCKED_BY_POLICY_GAP,
    OPTIONAL_SEMANTIC_REVIEW_REGISTRATION_DRIFT_GAP,
    PREEXISTING_TEST_BASELINE_UNKNOWN_GAP,
    SEMANTIC_CASE_CONTENT_OVER_ITEM_LIMIT_GAP,
    SEMANTIC_CASE_FINDING_REFS_OVER_LIMIT_GAP,
    SEMANTIC_CHALLENGES_REJECTED_GAP,
    SEMANTIC_PACKET_INSUFFICIENT_GAP,
    SEMANTIC_PRIOR_FINDINGS_OVER_LIMIT_GAP,
    SEMANTIC_PRIOR_VERDICTS_UNSUPPORTED_GAP,
    SEMANTIC_PROCESS_STATE_FILTERED_GAP,
    SEMANTIC_PROVIDER_INPUT_MANIFEST_FAILURES,
    SEMANTIC_PROVIDER_INPUT_MANIFEST_MISSING_GAP,
    SEMANTIC_RELEVANCE_REVIEW_NOT_RUN_GAP,
    SEMANTIC_RESTATEMENTS_SUPPRESSED_GAP,
    SEMANTIC_REVIEW_CONTEXT_WITHHELD_GAP,
    SEMANTIC_REVIEW_CREDENTIAL_HEURISTIC_DISABLED_GAP,
    SEMANTIC_REVIEW_DEFERRED_BEFORE_FIRST_EDIT_GAP,
    SEMANTIC_REVIEW_ITEM_WITHHELD_GAP,
    SEMANTIC_REVIEW_NOT_CONFIGURED_GAP,
    SEMANTIC_REVIEW_REFS_REDUCED_GAP,
    SEMANTIC_REVIEW_SKIPPED_INSUFFICIENT_PACKET_GAP,
    SEMANTIC_REVIEW_SNIPPET_INVALID_GAP,
    SEMANTIC_REVIEW_VALUE_REDACTED_GAP,
    TASK_INPUT_BASELINE_UNAVAILABLE_GAP,
    TASK_INPUT_OUTSIDE_NOT_ADMITTED_GAP,
    VERIFICATION_INPUT_DIRECTORY_UNRESOLVED_GAP,
    check_time_change_unavailable_reason_gap,
    semantic_coverage_gap_code,
)
from finishup.domain.review_guidance import ReviewGuidance
from finishup.domain.review_input_render import render_agent_next
from finishup.domain.reviewer_reads import ReviewerRecord
from finishup.domain.task_statement import TASK_STATEMENT_GAPS, SpecificationPreflight
from finishup.domain.values import (
    REPOSITORY_GRANT_CONTINUATION_KIND,
    REVIEW_INPUT_CONTINUATION_KIND,
    ClaimId,
    EventId,
    FindingId,
    Frontier,
    JsonObject,
    ObligationId,
    SemanticContinuation,
    claim_id,
    event_id,
    evidence_id,
    finding_id,
    freeze_json,
    obligation_id,
    result_id,
)
from finishup.kernel.check_totals import build_check_totals
from finishup.kernel.claims import (
    claim_discloses_result,
    completion_claim_present,
    effective_claim_items,
    result_is_relevant_to_claim,
)
from finishup.kernel.closure_class import (
    FindingClosureClass,
    ObligationClosure,
    ObligationClosureClass,
    closure_counts,
    counted_findings,
    finding_closures,
    obligation_closures,
)
from finishup.kernel.closure_readiness import semantic_review_used
from finishup.kernel.concern import (
    ConcernKey,
    concern_key,
    equal_concern,
    kinds_comparable,
    same_concern,
)
from finishup.kernel.correctness_advisories import (
    CorrectnessAdvisory,
    correctness_advisory_index,
)
from finishup.kernel.delivered_set import (
    DECLARED_OUTPUT_CONTENT_MOVED_GAP,
    DECLARED_OUTPUT_EMPTIED_GAP,
    DECLARED_OUTPUT_REMOVED_GAP,
    DeliverableSnapshot,
    assess_deliverables,
    content_moved_declared_items,
    declared_delivered_items,
    deliverable_history,
    deliverable_lineage,
)
from finishup.kernel.deterministic_checks import (
    DETERMINISTIC_TEXT_CONTRACT_DIGEST,
    REQUESTED_OUTPUT_ABSENT_FACT,
    DeterministicAssessment,
    DeterministicCase,
    FindingBasisRef,
    build_task_statement_unmapped_assessment,
    build_test_edit_integrity_assessment,
    case_coverage,
    finding_basis_from_json,
    finding_basis_to_json,
    render_deterministic_finding_text,
)
from finishup.kernel.deterministic_scope import (
    deterministic_scope_is_clean,
    gaps_are_clean,
)
from finishup.kernel.fact_lineage import FactLineage, lineage_to_wire
from finishup.kernel.finding_resolution import (
    AGENT_SETTLED_DISPOSITION_VALUES,
    SEMANTIC_FINDING_CAPTURE_BASELINE_GAPS,
    SEMANTIC_REFERENCE_SCOPE_REDUCED_GAP,
    finding_is_resolved,
    rejection_stands,
)
from finishup.kernel.finding_todo import (
    DEFAULT_FINDING_ATTEMPT_BUDGET,
    FindingTodoState,
    duplicate_link_target,
    finding_todo,
    finding_todo_state,
    todo_counts,
)
from finishup.kernel.limitation import limitation_standing
from finishup.kernel.lineage import LineageEvaluation, evaluate_recorded_lineage
from finishup.kernel.observed_failures import (
    ObservedFailureState,
    observed_action_runner_class,
    observed_event_ids_from_coverage,
    observed_event_ids_from_records,
    observed_failure_exempt,
    observed_failure_states,
)
from finishup.kernel.plan_scope import current_plan_scope
from finishup.kernel.policies.research_evidence import research_evidence_findings
from finishup.kernel.policies.response_support import (
    RESEARCH_REJECTION_PRESENT_FACT,
    WORK_RESPONSE_PRESENT_FACT,
)
from finishup.kernel.policies.work_integrity import (
    reportable_absent_outputs,
    work_integrity_findings,
)
from finishup.kernel.projections import (
    PROJECTION_VERSION,
    EvidenceProjectionRecord,
    ProjectionRecord,
    ProjectionState,
)
from finishup.kernel.ranking import CheckCompleteness, RankingContext, rank_findings
from finishup.kernel.receipt_capacity import current_receipt_findings
from finishup.kernel.receipt_prediction import predict_receipt_conclusion
from finishup.kernel.reducers import replay
from finishup.kernel.review_frame import (
    agent_probe_only,
    finishup_process_state_only,
    local_rule_owned,
)
from finishup.kernel.review_mode import (
    REQUESTED_BUT_LOCAL_REASONS,
    ConversationReviewContext,
    ConversationReviewMode,
    conversation_review_mode,
)
from finishup.kernel.review_round import review_round_stopped
from finishup.kernel.task_facts import (
    DECLARED_OUTPUT_NOT_REVIEWABLE_GAP,
    DELIVERABLE_REFERENCES_AMBIGUOUS_NAME_GAP,
    DELIVERABLE_REFERENCES_UNDECLARED_FILE_GAP,
    agent_linked_run_events,
    confirmed_blocked_obligation_ids,
    cooperative_event_ids_from_coverage,
    material_edit_recorded,
    passing_verification_observed,
    requested_output_facts,
    task_fact_signals,
)
from finishup.kernel.test_edit_visibility import PreExistingTestEdits, preexisting_test_edits
from finishup.kernel.verification_freshness import freshness_detail, freshness_rows_for
from finishup.observability.logging import (
    record_bounded_counts_without_raising,
    record_unexpected_exception_without_raising,
)
from finishup.ports.change_capture import (
    CheckChangeMetadata,
    CheckWorkspaceSource,
    current_check_workspace_source,
)
from finishup.ports.clock import ClockPort
from finishup.ports.control import McpHostProfile
from finishup.ports.diagnostics import RuntimeCapability
from finishup.ports.ids import IdPort
from finishup.ports.ledger import (
    MAX_CHECKLIST_ITEMS,
    CheckAdmissionStage,
    CheckAdvisoryNote,
    CheckAwaitingHuman,
    CheckChecklistItem,
    CheckChildPreviewItem,
    CheckChildrenPreview,
    CheckCommitResult,
    CheckFindingChecklist,
    ChecklistClosureCounts,
    CheckOverallNext,
    CheckPhase,
    CheckPolicyExecution,
    CheckVersionSlice,
    FrozenCase,
    OperationLease,
    OperationRecord,
    OperationState,
    check_admission_refused,
    check_admission_stage,
)
from finishup.ports.objects import ObjectKind, ObjectMetadata, ObjectRef, ObjectSource
from finishup.ports.observation import ObservationStoreLockTimeout
from finishup.ports.runtime import BundleRuntimePort, RouteAccess, RouteCommand, TaskRuntime
from finishup.ports.semantic import (
    ReviewerChallenge,
    ReviewInputManifest,
    SemanticJudgment,
    VerifiedReviewItem,
)
from finishup.ports.semantic_budget import select_semantic_budget_profile
from finishup.ports.start_catalog import TaskRoute
from finishup.protocol.canonical import (
    JsonValue,
    canonical_digest,
    canonical_encode,
    strict_json_parse,
)
from finishup.protocol.coverage import (
    Coverage,
    LedgerFreshness,
    coverage_to_json,
    weakest,
)
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.ids import IdKind, validate_opaque_item_id
from finishup.protocol.models import (
    MAX_OBJECT_PLAINTEXT_BYTES,
    MAX_REVIEW_TEXT_BYTES,
    MISSING_FOR_ASSESSMENT_KINDS,
    CheckRequest,
    CheckScopeModel,
    SemanticReason,
    SemanticStatus,
    validate_semantic_outcome,
    validate_semantic_provenance_binding,
)
from finishup.protocol.policy_packs import (
    COORDINATION_POLICY_ID,
    RESEARCH_EVIDENCE_POLICY_ID,
    WORK_INTEGRITY_POLICY_ID,
    current_policy_pack,
)
from finishup.protocol.redacted_values import (
    SemanticRedactedValue,
    validate_semantic_redacted_values,
)
from finishup.version import ENGINE_VERSION

if TYPE_CHECKING:  # the inspection module imports status, which imports this module
    from finishup.application.check_inspection import Application as CheckInspectionApplication
    from finishup.application.check_inspection import CheckInspection
    from finishup.application.status import Application as StatusApplication

__all__ = [
    "SEMANTIC_CASE_CONTENT_GAPS",
    "SEMANTIC_REJECTED_HIDDEN_SOURCE_CLAIM",
    "SEMANTIC_REJECTED_LOCAL_RULE_OWNED",
    "SEMANTIC_REJECTED_ROUTINE_COMPLETENESS",
    "SEMANTIC_REJECTED_FINISHUP_PROCESS_STATE",
    "SEMANTIC_REJECTED_REF_NOT_CARRIED",
    "SEMANTIC_REJECTED_REF_OUTSIDE_CASE",
    "SEMANTIC_REJECTED_SNIPPET",
    "SEMANTIC_REJECTED_SUBJECTS_OVER_LIMIT",
    "Application",
    "CheckScope",
    "FinalSemanticEvaluation",
    "SemanticJudgmentRejected",
    "SemanticJudgmentReview",
    "allocate_findings",
    "build_finding_checklist",
    "build_overall_next",
    "carried_semantic_attempt_gaps",
    "case_coverage",
    "check_awaiting_human_json",
    "check_internal_json",
    "execute_check",
    "execute_check_commit",
    "normalize_check_scope",
    "prior_finding_ids",
    "replayed_check_view",
    "run_deterministic_policies",
    "semantic_coverage_gap_code",
    "validate_semantic_judgment",
]

_RESEARCH_PACK = current_policy_pack(RESEARCH_EVIDENCE_POLICY_ID)
_WORK_PACK = current_policy_pack(WORK_INTEGRITY_POLICY_ID)
_COORDINATION_PACK = current_policy_pack(COORDINATION_POLICY_ID)
_CANONICAL_PACKS = (_RESEARCH_PACK, _WORK_PACK, _COORDINATION_PACK)
_UNAVAILABLE_GAPS = frozenset(
    {
        "captured_object_unavailable",
        "event_payload_unavailable",
        "missing_ref",
        "redacted_event",
        "redacted_object",
        "unknown_event",
    }
)
SEMANTIC_REJECTED_REF_OUTSIDE_CASE: Final = "ref_outside_case"
SEMANTIC_REJECTED_HIDDEN_SOURCE_CLAIM: Final = "hidden_source_claim"
SEMANTIC_REJECTED_SNIPPET: Final = "snippet_invalid"
# None of a challenge's cited refs is proven sent in the packet (issue #976). Distinct from a quote
# problem: the concern itself is surfaced as advisory text, it just anchors to nothing.
SEMANTIC_REJECTED_REF_NOT_CARRIED: Final = "ref_not_carried"
SEMANTIC_REJECTED_SUBJECTS_OVER_LIMIT: Final = "subject_refs_over_limit"
# Issue #1020 (tb4n2 P1-7): before any completion claim the work is still in progress, so an
# AI-powered "requested item never attempted" says nothing about incomplete work yet. Dropped and
# counted, never minted; the deterministic requested-item facts still apply.
SEMANTIC_REJECTED_ROUTINE_COMPLETENESS: Final = "routine_completeness"
# Issue #1042 (tb4n4: five ``action_without_result`` findings about FinishUP's own capture): a
# challenge whose every subject is FinishUP's own capture or process record
# (``kernel.review_frame.finishup_process_state_only``). Counted, never minted.
SEMANTIC_REJECTED_FINISHUP_PROCESS_STATE: Final = "yoetz_process_state"
# tb4n5 follow-up of #1042: an ``action_without_result`` or ``result_without_action`` challenge
# about readable ledger actions or results (``kernel.review_frame.local_rule_owned``). The local
# work-integrity rule owns that relation over the whole ledger. Counted, never minted.
SEMANTIC_REJECTED_LOCAL_RULE_OWNED: Final = "local_rule_owned"
# The three reasons above are about work in progress, FinishUP's own state or a ledger relation
# the local rule decides, not about material the check failed to carry: they are disclosed as
# ``semantic_process_state_filtered`` (never bounding, never vetoing an absence proof) instead of
# ``semantic_challenges_rejected``.
_PROCESS_STATE_REJECTIONS: Final = frozenset(
    {
        SEMANTIC_REJECTED_ROUTINE_COMPLETENESS,
        SEMANTIC_REJECTED_FINISHUP_PROCESS_STATE,
        SEMANTIC_REJECTED_LOCAL_RULE_OWNED,
    }
)
# The closed packet content gaps a semantic evaluation may carry into check coverage. Each is
# classified for finding resolution in ``kernel/finding_resolution.py`` (issue #904); adding one
# here without deciding its resolution class is caught by that module's tests.
SEMANTIC_CASE_CONTENT_GAPS: Final = frozenset(
    {
        "captured_object_unavailable",
        "content_capture_unavailable",
        "truncated_payload",
        "content_unselected",
        "content_redacted",
        SEMANTIC_REVIEW_VALUE_REDACTED_GAP,
        SEMANTIC_REVIEW_ITEM_WITHHELD_GAP,
        SEMANTIC_CASE_FINDING_REFS_OVER_LIMIT_GAP,
        "preexisting_test_baseline_unknown",
        "preexisting_test_modified",
        "preexisting_test_renamed",
        "preexisting_test_deleted",
        "preexisting_test_skipped",
        "preexisting_test_skip_unknown",
        "preexisting_test_edit_unjustified",
        # Issue #1102: a task-named input outside the workspace no admitted root covers.
        TASK_INPUT_OUTSIDE_NOT_ADMITTED_GAP,
        # #1118 unit 1: an outside input sent as current bytes with no kept copy.
        TASK_INPUT_BASELINE_UNAVAILABLE_GAP,
        # #1118 unit 4 (AIP-2): a verification oracle left out for an unresolvable directory.
        VERIFICATION_INPUT_DIRECTORY_UNRESOLVED_GAP,
    }
)
# Every packet gap an evaluation may report: the content gaps above plus the codes whose resolution
# rules live beside their own features (#905 prior findings, #908 task statement, ADR-031 check-time
# change).
_SEMANTIC_EVALUATION_GAPS: Final = SEMANTIC_CASE_CONTENT_GAPS | frozenset(
    {SEMANTIC_PRIOR_FINDINGS_OVER_LIMIT_GAP, *TASK_STATEMENT_GAPS, *CHECK_TIME_CHANGE_GAPS}
)
# Public name for composition: the case-content vocabulary a FinalSemanticEvaluation admits.
SEMANTIC_EVALUATION_GAPS: Final = _SEMANTIC_EVALUATION_GAPS


class SemanticJudgmentRejected(ValueError):
    """The reviewer's judgment failed a structural fence and cannot become findings.

    Deliberately narrower than the module's other ``ValueError``s: the commit path catches exactly
    this, so a rejected judgment records ``invalid``/``semantic_judgment_rejected`` and still
    commits the local findings, while a genuine coordinator bug keeps its old disposition.
    """


def _invalid(reason: str = "check_coordinator_invalid") -> ValueError:
    return ValueError(reason)


def _valid_opaque_item_id(value: object) -> bool:
    try:
        validate_opaque_item_id(value)
    except ValueError:
        return False
    return True


def _rejected(reason: str) -> SemanticJudgmentRejected:
    return SemanticJudgmentRejected(reason)


@dataclass(frozen=True, slots=True)
class SemanticJudgmentReview:
    """What the reviewer returned and what the post-validation fence did with it.

    ``rejected_by_reason`` is a sorted tuple of bounded ``(reason, count)`` pairs, never text from
    the challenge itself: it exists so "the reviewer answered and none of it reached you" is a
    countable fact on the check path instead of silence.
    """

    candidates: tuple[CandidateFinding, ...]
    challenges_returned: int
    rejected_by_reason: tuple[tuple[str, int], ...]
    # Admitted per-finding rulings on earlier AI-powered findings (issue #905), and how many the
    # reviewer returned that the fence dropped or reduced to ``unassessable``.
    verdicts: tuple[PriorFindingVerdictRecord, ...] = ()
    verdicts_unsupported: int = 0
    # Challenges that restated a recorded AI-powered finding with nothing newer (issue #905).
    restatements_suppressed: int = 0
    # Rulings set aside without the unsupported gap: on a final item, or contradicted by the same
    # review's restatement (issue #905). A diagnostic count only.
    verdicts_set_aside: int = 0
    # Part 2 reviewer output that survived packet/ref/snippet validation. These are retained on the
    # check result as advisory judgements; they never upgrade a deterministic verdict by
    # themselves.
    review_summary: str = "No review summary recorded."
    verified: tuple[VerifiedReviewItem, ...] = ()
    snippets_rejected: int = 0
    # Kept challenges and verified rows whose citations of unsent refs were removed (issue #976).
    refs_reduced: int = 0
    # Issue #1042: routine-phase correctness concerns (``code_defect``) recorded as advisory,
    # non-blocking notes in the review summary instead of findings.
    advisory_notes: int = 0
    # Issue #1162: the retained, answerable rows of those notes, keyed by their fence-resolved
    # subjects. A note whose row cannot be retained stays in the summary only, with a disclosure.
    # Tracked advice rows (``origin`` set) follow the notes: verified rows marked not_supported or
    # not_assessable that cite an obligation or claim, and the strongest remaining check.
    correctness_advisories: tuple[JsonObject, ...] = ()
    # Issue #1043: requirement challenges recorded as the agent's own criterion
    # (``agent_criterion_unmet``); they are still candidates, so this is a diagnostic count only.
    agent_criteria: int = 0

    def __post_init__(self) -> None:
        if (
            type(self.candidates) is not tuple
            or type(self.challenges_returned) is not int
            or self.challenges_returned < 0
            or type(self.rejected_by_reason) is not tuple
        ):
            raise _invalid("semantic_judgment_review_invalid")
        if any(type(pair) is not tuple or len(pair) != 2 for pair in self.rejected_by_reason):
            raise _invalid("semantic_judgment_review_invalid")
        if type(self.restatements_suppressed) is not int or self.restatements_suppressed < 0:
            raise _invalid("semantic_judgment_review_invalid")
        if type(self.verdicts_set_aside) is not int or self.verdicts_set_aside < 0:
            raise _invalid("semantic_judgment_review_invalid")
        if type(self.review_summary) is not str or not self.review_summary:
            raise _invalid("semantic_judgment_review_invalid")
        if type(self.verified) is not tuple or any(
            type(item) is not VerifiedReviewItem for item in self.verified
        ):
            raise _invalid("semantic_judgment_review_invalid")
        if type(self.snippets_rejected) is not int or self.snippets_rejected < 0:
            raise _invalid("semantic_judgment_review_invalid")
        if type(self.refs_reduced) is not int or self.refs_reduced < 0:
            raise _invalid("semantic_judgment_review_invalid")
        if (
            type(self.advisory_notes) is not int
            or self.advisory_notes < 0
            or type(self.correctness_advisories) is not tuple
            # Rows without ``origin`` are routine notes, one per counted note at most; tracked
            # advice rows (#1162) come from verified rows and the strongest remaining check.
            or sum("origin" not in row for row in self.correctness_advisories) > self.advisory_notes
        ):
            raise _invalid("semantic_judgment_review_invalid")
        validate_advisories(self.correctness_advisories)
        if type(self.agent_criteria) is not int or not 0 <= self.agent_criteria <= len(
            self.candidates
        ):
            raise _invalid("semantic_judgment_review_invalid")
        if any(
            reason not in _SEMANTIC_REJECTION_REASONS or type(count) is not int or count < 1
            for reason, count in self.rejected_by_reason
        ):
            raise _invalid("semantic_judgment_review_invalid")
        # The diagnostic this value feeds claims that returned == accepted + rejected + suppressed
        # restatements + advisory notes. Owning the invariant here turns any future accounting
        # drift into an immediate failure rather than a durable count that quietly does not add up.
        if self.challenges_returned != (
            len(self.candidates)
            + self.challenges_rejected
            + self.restatements_suppressed
            + self.advisory_notes
        ):
            raise _invalid("semantic_judgment_review_invalid")

    @property
    def challenges_rejected(self) -> int:
        return sum(count for _reason, count in self.rejected_by_reason)


_SEMANTIC_REJECTION_REASONS: Final = frozenset(
    {
        SEMANTIC_REJECTED_HIDDEN_SOURCE_CLAIM,
        SEMANTIC_REJECTED_LOCAL_RULE_OWNED,
        SEMANTIC_REJECTED_REF_NOT_CARRIED,
        SEMANTIC_REJECTED_REF_OUTSIDE_CASE,
        SEMANTIC_REJECTED_ROUTINE_COMPLETENESS,
        SEMANTIC_REJECTED_SNIPPET,
        SEMANTIC_REJECTED_SUBJECTS_OVER_LIMIT,
        SEMANTIC_REJECTED_FINISHUP_PROCESS_STATE,
    }
)
_EMPTY_SEMANTIC_REVIEW: Final = SemanticJudgmentReview((), 0, ())
_EMPTY_MISSING_ITEMS: Final = MissingItemsReview((), frozenset())


def _projected_finding_json(finding: Finding) -> JsonValue:
    """Adapt one encoded finding to the CHECK result's projected-finding shape.

    ``findings/finding-1.0.0`` leaves ``provenance`` simply absent on a local finding, and
    ``finding_to_json`` honors that — it is the encoding events and receipt documents carry. The
    CHECK result's ``projected_finding`` is stricter: ``provenance`` is *required* and nullable, so
    a local finding must present it as an explicit null. This mirrors the top-level
    ``semantic_provenance`` immediately below, which the same result already emits that way.
    """

    encoded = dict(finding_to_json(finding).items())
    if finding.challenge is not None:
        challenge = finding.challenge
        encoded["challenge"] = JsonObject(
            {
                "alternative_interpretation": challenge.alternative_interpretation,
                "discrepancy": challenge.discrepancy,
                "requested_next_step": challenge.requested_next_step,
                "uncertainty": challenge.uncertainty,
                **({} if challenge.snippet is None else {"snippet": challenge.snippet}),
            }
        )
    if "provenance" not in encoded:
        encoded["provenance"] = None
    return JsonObject(encoded)


def check_awaiting_human_json(result: CheckAwaitingHuman) -> dict[str, JsonValue]:
    """Serialize the nonterminal CHECK branch: a continuation, never a verdict.

    No verdict, findings, coverage, or AI-powered review provenance appear here. Emitting a
    completion-grade shape for a check that has not run would let a caller conclude from it.
    """

    continuation: dict[str, JsonValue] = {
        "kind": result.continuation.kind,
        "command": result.continuation.command,
        "replay_request_id": result.continuation.request_id,
        "instruction": result.continuation.instruction,
    }
    if result.continuation.pending_id is not None:
        continuation["pending_id"] = result.continuation.pending_id
    if result.continuation.expires_at is not None:
        continuation["expires_at"] = result.continuation.expires_at.wire
    body: dict[str, JsonValue] = {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": result.request_id,
        "ok": True,
        "state": result.state,
        "task_id": result.task_id,
        "session_id": result.session_id,
        "writer_id": result.writer_id,
        "subject_frontier": dict(result.subject_frontier.as_wire().items()),
        "result_frontier": dict(result.result_frontier.as_wire().items()),
        # The historical semantic enum remains frozen for terminal/projection contracts.  The
        # explicit state/reason pair below distinguishes a missing review input from a human
        # approval pause without widening that enum for a nonterminal response.
        "semantic_status": (
            "awaiting_input"
            if result.state == "awaiting_input"
            else SemanticStatus.AWAITING_HUMAN.value
        ),
        "semantic_reason": (
            "review_input_required"
            if result.state == "awaiting_input"
            else SemanticReason.HUMAN_APPROVAL_REQUIRED.value
        ),
        "continuation": continuation,
        "versions": {
            "protocol_version": result.versions.protocol_version,
            "engine_version": result.versions.engine_version,
            "projection_version": result.versions.projection_version,
            "policy_packs": result.versions.policy_packs,
        },
    }
    if result.specification_preflight is not None:
        preflight = result.specification_preflight
        body["specification_preflight"] = {
            "actionable": preflight.actionable,
            "content_bytes": preflight.content_bytes,
            "content_digest": preflight.content_digest,
            "gap": preflight.gap,
            "required": preflight.required,
            "revision": preflight.revision,
            "source": None if preflight.source is None else preflight.source.value,
            "status": preflight.status,
        }
    return body


def check_internal_json(result: CheckCommitResult) -> dict[str, JsonValue]:
    """Serialize sink-independent CHECK success without a privacy projection."""

    def children_json(children: CheckChildrenPreview) -> JsonValue:
        return {
            "label": children.label,
            "items": tuple(
                {
                    "child_task_id": item.child_task_id,
                    "origin": item.origin.value,
                    "acceptance": item.acceptance.value,
                    "work_state": item.work_state.value,
                    "session_health": item.session_health.value,
                    "rollup_state": item.rollup_state.value,
                    "blocking_conditions": item.blocking_conditions,
                }
                for item in children.items
            ),
            "tested_manifest_frontier": (
                None
                if children.tested_manifest_frontier is None
                else dict(children.tested_manifest_frontier.as_wire().items())
            ),
        }

    def advisory_notes_json(
        notes: tuple[CheckAdvisoryNote, ...],
    ) -> tuple[JsonValue, ...]:
        return tuple(
            {
                "kind": note.kind,
                "project_id": note.project_id,
                "task_ids": note.task_ids,
                "count": str(note.count),
            }
            for note in notes
        )

    return {
        "protocol_version": "0.1",
        "state": "complete",
        "schema_version": "1.0.0",
        "request_id": result.request_id,
        "ok": True,
        "task_id": result.task_id,
        "session_id": result.session_id,
        "writer_id": result.writer_id,
        "subject_frontier": dict(result.subject_frontier.as_wire().items()),
        "result_frontier": dict(result.result_frontier.as_wire().items()),
        "verdict": result.verdict.value,
        "findings": tuple(_projected_finding_json(item) for item in result.findings),
        "suppressed_count": str(result.suppressed_count),
        "policy_executions": tuple(
            {
                "policy_id": item.policy_id,
                "policy_version": item.policy_version,
                "outcome": item.outcome,
                "reason": item.reason,
            }
            for item in result.policy_executions
        ),
        "semantic_status": result.semantic_status.value,
        "semantic_reason": result.semantic_reason.value,
        **(
            {}
            if result.semantic_conclusion is None
            else {"semantic_conclusion": result.semantic_conclusion}
        ),
        "semantic_provenance": (
            None
            if result.semantic_provenance is None
            # Public Pydantic validation deliberately accepts a built-in dict here
            # before inspecting the safe identity fields.  The domain encoder
            # returns an immutable JsonObject, so thaw only its root container;
            # nested values remain canonical JSON mappings.
            else dict(semantic_provenance_to_json(result.semantic_provenance).items())
        ),
        **(
            {}
            if not result.semantic_withheld_item_ids
            else {
                "semantic_withheld_items": tuple(
                    {
                        "item_id": item_id,
                        "reason": "never_send_heuristic",
                    }
                    for item_id in result.semantic_withheld_item_ids
                )
            }
        ),
        # PL2-1: item refs and line numbers only; written only when present.
        **(
            {}
            if not getattr(result, "semantic_redacted_values", ())
            else {
                "semantic_redacted_values": tuple(
                    cast(JsonValue, item.as_wire()) for item in result.semantic_redacted_values
                )
            }
        ),
        # ADR-045: where each derived fact came from; omitted when there is none.
        **(
            {}
            if not (lineage := getattr(result, "fact_lineage", ()))
            else {"fact_lineage": tuple(cast(JsonValue, lineage_to_wire(item)) for item in lineage)}
        ),
        # Issue #986: present (``false``) only when the check's route did not require review.
        **(
            {}
            if (route_required := getattr(result, "semantic_route_required", None)) is None
            else {"semantic_route_required": route_required}
        ),
        # ADR-049: the conversation review mode this check ran in and why, when it was read.
        **(
            {}
            if (review_mode := getattr(result, "review_mode", None)) is None
            else {"review_mode": cast(CheckReviewMode, review_mode).as_wire()}
        ),
        "coverage": coverage_to_json(result.coverage),
        "versions": {
            "protocol_version": result.versions.protocol_version,
            "engine_version": result.versions.engine_version,
            "projection_version": result.versions.projection_version,
            "policy_packs": result.versions.policy_packs,
        },
        **(
            {}
            if result.semantic_status is not SemanticStatus.SUCCEEDED
            else {
                "review_guidance": ReviewGuidance.MATERIAL_CONCERNS.value,
                "review_summary": (result.review_summary or "No review summary recorded."),
                "verified": tuple(dict(item.items()) for item in result.verified),
            }
        ),
        **({} if result.children is None else {"children": children_json(result.children)}),
        **(
            {}
            if not result.advisory_notes
            else {"advisory_notes": advisory_notes_json(result.advisory_notes)}
        ),
        # #1162 tracked advice: each advisory row this check recorded, with its identity.
        **(
            {}
            if not (advice := getattr(result, "correctness_advisories", ()))
            else {"correctness_advisories": tuple(dict(row.items()) for row in advice)}
        ),
        **(
            {}
            if not result.missing_for_assessment
            else {
                "missing_for_assessment": tuple(
                    {
                        "availability": item.availability,
                        "kind": item.kind,
                        "target_refs": item.target_refs,
                    }
                    for item in result.missing_for_assessment
                )
            }
        ),
        **(
            {}
            if result.finding_checklist is None
            else {"finding_checklist": _checklist_json(result.finding_checklist)}
        ),
        **(
            {}
            if result.overall_next is None
            else {"overall_next": _overall_next_json(result.overall_next)}
        ),
        **(
            {"closure_readiness": dict(result.closure_readiness.items())}
            if result.closure_readiness is not None
            else {}
        ),
        # W6 (ADR-043 amendment): the bounded lead every host reads first, derived here so the
        # MCP result, CLI JSON, an import's check result and a status recovery read agree.
        **({} if not (agent_next := _agent_next(result)) else {"agent_next": agent_next}),
        **(
            {}
            if result.review_input_manifest is None
            else {"review_input_manifest": dict(result.review_input_manifest.items())}
        ),
        # #1118: what the reviewer conversation read and why it ended, when one ran.
        **(
            {}
            if (reviewer := getattr(result, "reviewer", None)) is None
            else {"reviewer": dict(cast(JsonObject, reviewer).items())}
        ),
        **({} if result.totals is None else {"totals": result.totals}),
        # Issue #1012: present only when the request set ``await_observations``.
        **(
            {}
            if result.observations_awaited is None
            else {
                "observations_awaited": {
                    "state": result.observations_awaited.state,
                    "pending_count": str(result.observations_awaited.pending_count),
                }
            }
        ),
    }


def _agent_next(result: CheckCommitResult) -> str:
    """The ``agent_next`` lead of a committed check, or empty without a continuation.

    Derived at serialization from the attached ``overall_next`` and the recorded missing items,
    so older ``check_recorded`` rows project it too. A committed check never fails on it.
    """

    if result.overall_next is None:
        return ""
    checklist = result.finding_checklist
    limitation_requests = checklist is not None and any(
        item.closure_class == "agent_work" and item.closure_basis == "limitation_requested"
        for item in checklist.items
    )
    return render_agent_next(
        result.overall_next,
        result.missing_for_assessment,
        limitation_requests=limitation_requests,
    )


def _checklist_json(checklist: CheckFindingChecklist) -> JsonValue:
    counts = checklist.counts
    return {
        "attempt_budget": str(checklist.attempt_budget),
        "counts": {
            "acknowledged_not_done": str(counts.acknowledged_not_done),
            "open": str(counts.open),
            "open_at_budget": str(counts.budget_reached),
            "rejection_accepted": str(counts.rejection_accepted),
            "self_verified": str(counts.self_verified),
            "verified_resolved": str(counts.verified_resolved),
            # Issue #1020 and ADR-046: emitted only when non-zero, so earlier results keep their
            # bytes.
            **(
                {"disputed_after_rebuttal": str(counts.disputed_after_rebuttal)}
                if counts.disputed_after_rebuttal
                else {}
            ),
            **(
                {}
                if checklist.closure_counts is None
                else {
                    "to_do": str(checklist.closure_counts.to_do),
                    "awaiting_ruling": str(checklist.closure_counts.awaiting_ruling),
                    "unmet": str(checklist.closure_counts.unmet),
                    "disclosed": str(checklist.closure_counts.disclosed),
                    "to_disclose": str(checklist.closure_counts.to_disclose),
                }
            ),
        },
        "items": tuple(
            {
                "finding_id": item.finding_id,
                "todo_state": item.todo_state,
                "review_rounds": str(item.review_rounds),
                **(
                    {}
                    if item.closure_class is None or item.closure_basis is None
                    else {
                        "closure_class": item.closure_class,
                        "closure_basis": item.closure_basis,
                    }
                ),
            }
            for item in checklist.items
        ),
        "next": checklist.next,
    }


def _overall_next_json(next_step: CheckOverallNext) -> JsonObject:
    return JsonObject(
        {
            "action": next_step.action,
            "status": next_step.status,
            "target_refs": next_step.target_refs,
            **(
                {}
                if next_step.acknowledged_incomplete_endpoint is None
                else {
                    "acknowledged_incomplete_endpoint": (next_step.acknowledged_incomplete_endpoint)
                }
            ),
            **(
                {}
                if next_step.predicted_conclusion is None
                else {"predicted_conclusion": next_step.predicted_conclusion}
            ),
        }
    )


def _lineage_preview(
    evaluation: LineageEvaluation,
    subject_frontier: Frontier,
) -> CheckChildrenPreview | None:
    """Adapt one frozen evaluator result to the additive CHECK child preview section."""

    if not evaluation.snapshots:
        return None
    snapshots = {item.child_task_id: item for item in evaluation.snapshots}
    items = tuple(
        CheckChildPreviewItem(
            child_task_id=str(rollup.child_task_id),
            origin=snapshots[rollup.child_task_id].origin,
            acceptance=snapshots[rollup.child_task_id].acceptance,
            work_state=snapshots[rollup.child_task_id].work_state,
            session_health=snapshots[rollup.child_task_id].session_health,
            rollup_state=rollup.state,
            blocking_conditions=rollup.blockers,
        )
        for rollup in evaluation.children
        if rollup.child_task_id in snapshots
    )
    if not items:
        return None
    label = (
        "preview"
        if any(item.later_manifest_ref is not None for item in evaluation.children)
        or any(gap.code == "lineage_manifest_uncovered" for gap in evaluation.gaps)
        else "recorded"
    )
    return CheckChildrenPreview(label, items, subject_frontier)


async def _lineage_at_frontier(
    runtime: TaskRuntime,
    frontier: Frontier,
    *,
    base_coverage: Coverage | None = None,
) -> LineageEvaluation:
    """Read only the parent ledger prefix named by a frozen check result."""

    records = tuple(
        [
            record
            async for record in runtime.ledger.load_events(
                runtime.session_id,
                through=frontier.sequence,
            )
        ]
    )
    if base_coverage is None:
        return evaluate_recorded_lineage(
            records,
            tested_through_sequence=frontier.sequence,
        )
    return evaluate_recorded_lineage(
        records,
        tested_through_sequence=frontier.sequence,
        base_coverage=base_coverage,
    )


async def replayed_check_view(
    app: Application,
    runtime: TaskRuntime,
    result: CheckCommitResult,
    *,
    route_profile: Literal["policy", "strict"] | None = None,
) -> CheckCommitResult:
    """A stored committed check as a same-id replay returns it (before project advice).

    The ledger result is frozen; the child preview, fact lineage, finding checklist and
    ``overall_next`` are rebuilt from the exact recorded prefix. ``status view=operation`` reads
    a finished check's outcome through this too (W6), so the two always agree.
    """

    replayed = await _attach_replayed_lineage_preview(runtime, result)
    replayed = await _attach_replayed_fact_lineage(runtime, replayed)
    return await _attach_finding_checklist(app, runtime, replayed, route_profile=route_profile)


async def _attach_replayed_lineage_preview(
    runtime: TaskRuntime,
    result: CheckCommitResult,
) -> CheckCommitResult:
    """Reconstruct the additive child preview from the exact recorded result prefix."""

    if result.children is not None:
        return result
    evaluation = await _lineage_at_frontier(
        runtime,
        result.subject_frontier,
        base_coverage=result.coverage,
    )
    preview = _lineage_preview(evaluation, result.subject_frontier)
    return result if preview is None else replace(result, children=preview)


type _AdvisoryFindingKey = tuple[
    str,
    str,
    str,
    tuple[str, ...],
    tuple[str, ...],
    tuple[str, ...],
]


async def _current_task_findings(
    app: Application,
    task_id: str,
) -> tuple[Finding, ...]:
    """Read only current unresolved finding identities from an admitted task ledger.

    Finding kinds and subject references are fields of encrypted accepted payloads, so the read
    needs payload authority.  A keyless structural lease would open no object store on a cold
    runtime entry and expose no payload on a warm one (#839).  The caller admits the counterpart
    through ``live_admitted_member_task_ids`` and the coordination input provider before this
    read, and only the typed finding signature leaves this function.
    """

    catalog = getattr(app, "start_catalog", None)
    runtime_port = getattr(app, "runtime", None)
    task_route = None if catalog is None else getattr(catalog, "task_route", None)
    route = None
    if not callable(task_route) or runtime_port is None:
        return ()
    try:
        route = await cast(Callable[[str], Awaitable[object | None]], task_route)(task_id)
        session_id = getattr(route, "session_id", None)
        if type(session_id) is not str:
            return ()
        child_runtime = await runtime_port.route(
            RouteCommand(
                session_id,
                None,
                RouteAccess.PAYLOAD_READ,
                frozenset({RuntimeCapability.STRUCTURAL_READ, RuntimeCapability.PAYLOAD_READ}),
            )
        )
        if type(child_runtime) is not TaskRuntime or child_runtime.task_id != task_id:
            if type(child_runtime) is TaskRuntime:
                await runtime_port.release(child_runtime)
            return ()
        try:
            records: tuple[LedgerRecord, ...] = tuple(
                [
                    record
                    async for record in child_runtime.ledger.load_events(child_runtime.session_id)
                ]
            )
            projection = await projection_for_records(
                child_runtime.ledger,
                child_runtime.session_id,
                (
                    Frontier(records[-1].ledger.ingestion_sequence, records[-1].entry_digest)
                    if records
                    else Frontier(0, "genesis")
                ),
                records,
            )
        finally:
            await runtime_port.release(child_runtime)
    except Exception as exc:
        record_unexpected_exception_without_raising(
            exc,
            component="check",
            operation="project_advisory_finding_read",
        )
        return ()
    return tuple(
        finding
        for item in projection.findings.values()
        if not item.redacted
        and item.proof_event_id is None
        and type(finding := item.payload) is Finding
    )


async def _current_task_structural_context(
    app: Application,
    task_id: str,
    project_id: str,
) -> tuple[tuple[str, ...], tuple[str, ...]] | None:
    """Return digest-only resource/plan identities for one admitted project member."""

    project_application = getattr(app, "project_application", None)
    coordination = (
        None
        if project_application is None
        else getattr(project_application, "coordination_runtime", None)
    )
    inputs = None if coordination is None else getattr(coordination, "inputs", None)
    input_for = None if inputs is None else getattr(inputs, "input_for", None)
    if not callable(input_for):
        return None
    try:
        declared = await cast(Callable[..., Awaitable[object | None]], input_for)(
            task_id,
            project_id,
        )
        if declared is None:
            return None
        resource_identities = getattr(declared, "resource_identities", None)
        plan_identities = getattr(declared, "plan_identities", None)
        if not callable(resource_identities) or not callable(plan_identities):
            return None
        resources_value: object = resource_identities()
        plans_value: object = plan_identities()
        if type(resources_value) is not tuple or type(plans_value) is not tuple:
            return None
        resources = cast(tuple[object, ...], resources_value)
        plans = cast(tuple[object, ...], plans_value)
        if any(type(item) is not str for item in (*resources, *plans)):
            return None
        resource_strings = cast(tuple[str, ...], resources)
        plan_strings = cast(tuple[str, ...], plans)
        return (
            tuple(sorted(set(resource_strings), key=str.encode)),
            tuple(sorted(set(plan_strings), key=str.encode)),
        )
    except Exception as exc:
        record_unexpected_exception_without_raising(
            exc,
            component="check",
            operation="project_advisory_context_read",
        )
        return None


def _advisory_finding_key(
    finding: Finding,
    context: tuple[tuple[str, ...], tuple[str, ...]],
) -> _AdvisoryFindingKey | None:
    resources, plans = context
    if not resources and not plans:
        return None
    subject_kinds = tuple(
        sorted(
            {
                str(reference).split("_", 1)[0]
                for reference in finding.subject_refs
                if type(reference) is str and "_" in reference
            },
            key=str.encode,
        )
    )
    return (
        finding.kind.value,
        finding.policy_id,
        finding.policy_version,
        subject_kinds,
        resources,
        plans,
    )


async def _duplicate_project_advisory_task_ids(
    app: Application,
    requester_task_id: str,
    project_id: str,
    counterpart_ids: tuple[str, ...],
    findings: tuple[Finding, ...],
) -> tuple[str, ...]:
    """Find counterpart identities sharing a typed, resource-only finding signature."""

    requester_context = await _current_task_structural_context(app, requester_task_id, project_id)
    if requester_context is None:
        return ()
    own_keys = {
        key
        for finding in findings
        if (key := _advisory_finding_key(finding, requester_context)) is not None
    }
    if not own_keys:
        return ()
    duplicate_tasks: set[str] = set()
    for counterpart_id in counterpart_ids:
        context = await _current_task_structural_context(app, counterpart_id, project_id)
        if context is None:
            continue
        counterpart_findings = await _current_task_findings(app, counterpart_id)
        counterpart_keys = {
            key
            for finding in counterpart_findings
            if (key := _advisory_finding_key(finding, context)) is not None
        }
        if own_keys & counterpart_keys:
            duplicate_tasks.add(counterpart_id)
    if not duplicate_tasks:
        return ()
    return tuple(sorted({requester_task_id, *duplicate_tasks}, key=str.encode))


_PROJECT_ADVICE_AUTHORITY_REFUSALS: Final = frozenset(
    {
        CoordinationErrorCode.CONSENT_REQUIRED,
        CoordinationErrorCode.GRANT_REQUIRED,
        CoordinationErrorCode.GRANT_REVOKED,
        CoordinationErrorCode.GENERATION_MISMATCH,
        CoordinationErrorCode.PROJECT_NOT_FOUND,
        CoordinationErrorCode.PROJECT_DISSOLVED,
        CoordinationErrorCode.MEMBER_NOT_FOUND,
    }
)


async def _current_project_advisory_notes(
    app: Application,
    task_id: str,
    findings: tuple[Finding, ...],
) -> tuple[CheckAdvisoryNote, ...]:
    """Project current, consented coordination advice beside a recorded check result.

    Coordination advice is a projection-time observation.  It is deliberately looked up after
    the ledger check has frozen/committed its deterministic result, and it is never passed to the
    ranking or ledger commit paths.  ``ProjectApplication.live_admitted_member_task_ids`` is the
    admission boundary here: it rechecks source consent, membership, grant, task liveness, and
    current project generation before returning counterpart identities, so a revoked generation
    fails closed. Recorded overlap advice can supply candidate identities, but every result still
    requires the current member-admission boundary at the same captured generation.
    """

    project_application = getattr(app, "project_application", None)
    catalog = getattr(project_application, "catalog", None)
    list_projects = None if catalog is None else getattr(catalog, "list_task_project_ids", None)
    project_state = None if catalog is None else getattr(catalog, "project_state", None)
    live_members_for = (
        None
        if project_application is None
        else getattr(project_application, "live_admitted_member_task_ids", None)
    )
    advice_for = (
        None
        if project_application is None
        else getattr(project_application, "coordination_advice_for", None)
    )
    if not callable(list_projects) or not callable(project_state) or not callable(live_members_for):
        return ()
    try:
        project_ids = await cast(Callable[[str], Awaitable[tuple[str, ...]]], list_projects)(
            task_id
        )
    except Exception as exc:
        # Advice is additive and optional.  A projection failure must not change the deterministic
        # check outcome or strand an already committed operation; it simply produces no note.
        record_unexpected_exception_without_raising(
            exc,
            component="check",
            operation="project_advisory_membership_read",
        )
        return ()

    notes: list[CheckAdvisoryNote] = []
    valid_project_ids = tuple(item for item in project_ids if type(item) is str)
    for project_id in sorted(set(valid_project_ids), key=str.encode):
        try:
            descriptor = await cast(Callable[[str], Awaitable[object | None]], project_state)(
                project_id
            )
            generation = getattr(descriptor, "membership_generation", None)
            if type(generation) is not int or generation < 1:
                continue
        except Exception:
            continue
        counterpart_ids: tuple[str, ...] = ()
        live_lookup_failed = False
        if callable(live_members_for):
            try:
                counterpart_ids = tuple(
                    sorted(
                        {
                            member
                            for member in await cast(
                                Callable[..., Awaitable[tuple[str, ...]]], live_members_for
                            )(task_id, project=project_id, expected_generation=generation)
                            if type(member) is str and member != task_id
                        },
                        key=str.encode,
                    )
                )
            except Exception as exc:
                if (
                    isinstance(exc, CoordinationError)
                    and exc.code in _PROJECT_ADVICE_AUTHORITY_REFUSALS
                ):
                    # A missing or revoked authority is an expected absence of optional advice.
                    # Do not retry it through the compatibility fallback or diagnose corruption.
                    continue
                live_lookup_failed = True
                # A single stale or revoked project cannot suppress notes for other independently
                # admitted projects, and never changes the recorded check verdict.
                record_unexpected_exception_without_raising(
                    exc,
                    component="check",
                    operation="project_advisory_read",
                )
        if (
            (not callable(live_members_for) or live_lookup_failed)
            and not counterpart_ids
            and callable(advice_for)
        ):
            # Compatibility fallback for pre-B3 compositions: this remains generation/consent
            # fenced but only knows about projects for which overlap advice was already delivered.
            try:
                rows = await cast(Callable[..., Awaitable[tuple[object, ...]]], advice_for)(
                    task_id, project=project_id, expected_generation=generation
                )
                counterpart_ids = tuple(
                    sorted(
                        {
                            counterpart
                            for row in rows
                            if getattr(row, "target_task_id", None) == task_id
                            and getattr(row, "project_id", None) == project_id
                            and type(counterpart := getattr(row, "counterpart_task_id", None))
                            is str
                            and counterpart != task_id
                        },
                        key=str.encode,
                    )
                )
            except Exception as exc:
                if (
                    isinstance(exc, CoordinationError)
                    and exc.code in _PROJECT_ADVICE_AUTHORITY_REFUSALS
                ):
                    continue
                record_unexpected_exception_without_raising(
                    exc,
                    component="check",
                    operation="project_advisory_read",
                )
        if counterpart_ids and callable(live_members_for):
            try:
                current_members = tuple(
                    sorted(
                        {
                            member
                            for member in await cast(
                                Callable[..., Awaitable[tuple[str, ...]]], live_members_for
                            )(task_id, project=project_id, expected_generation=generation)
                            if type(member) is str and member != task_id
                        },
                        key=str.encode,
                    )
                )
            except Exception:
                # The second admission read is a revoke/generation fence.  A race here must
                # suppress this projection rather than deliver identities from the prior page.
                counterpart_ids = ()
            else:
                if current_members != counterpart_ids:
                    counterpart_ids = ()
        if counterpart_ids:
            duplicate_task_ids = await _duplicate_project_advisory_task_ids(
                app,
                task_id,
                project_id,
                counterpart_ids,
                findings,
            )
            if callable(live_members_for):
                try:
                    final_members = tuple(
                        sorted(
                            {
                                member
                                for member in await cast(
                                    Callable[..., Awaitable[tuple[str, ...]]], live_members_for
                                )(task_id, project=project_id, expected_generation=generation)
                                if type(member) is str and member != task_id
                            },
                            key=str.encode,
                        )
                    )
                except Exception:
                    # Duplicate context and ledger reads can await long enough for source consent,
                    # a recipient grant, or the project generation to change.  A failed final
                    # admission read must suppress both notes from this stale projection.
                    counterpart_ids = ()
                    duplicate_task_ids = ()
                else:
                    if final_members != counterpart_ids:
                        counterpart_ids = ()
                        duplicate_task_ids = ()
            if counterpart_ids:
                try:
                    notes.append(
                        CheckAdvisoryNote(
                            "live_member_present",
                            project_id,
                            counterpart_ids,
                            len(counterpart_ids),
                        )
                    )
                except (TypeError, ValueError):
                    # IDs are validated again at the structural result boundary.  An invalid adapter
                    # row is not allowed to become a public note or affect the check itself.
                    pass
            if counterpart_ids and duplicate_task_ids:
                try:
                    notes.append(
                        CheckAdvisoryNote(
                            "duplicate_finding",
                            project_id,
                            duplicate_task_ids,
                            len(duplicate_task_ids),
                        )
                    )
                except (TypeError, ValueError):
                    pass
        if len(notes) >= 64:
            break
    return tuple(notes)


def _own_criterion(projection: ProjectionState | None, finding_id: FindingId) -> bool:
    """Whether the finding is the agent's own criterion (``agent_criterion_unmet``, issue #1043).

    It reads the ``limitation_requested`` basis like a reviewer's request to state a limit, but
    its probe fails here: the continuation for it is work (fix it, or narrow it with a reasoned
    ``acknowledged``), never "disclose, no repair is needed".
    """

    record = None if projection is None else projection.findings.get(finding_id)
    return (
        record is not None
        and record.payload is not None
        and record.payload.kind is FindingKind.AGENT_CRITERION_UNMET
    )


def build_finding_checklist(
    projection: ProjectionState,
    *,
    attempt_budget: int,
    records: tuple[LedgerRecord, ...] = (),
) -> CheckFindingChecklist:
    """The current actionable findings as a to-do list, with whole-list counts (issue #905).

    Items are the newest row per issue, open items first and otherwise in rank order, at most
    100; the counts and ``next`` cover every current actionable item, so a long list can never
    read as done. Coverage limitations are not to-dos and never drive ``next``. Each item names
    its closure class and basis (ADR-046), and a rejection that awaits a reviewer ruling is told
    to ``request_ruling`` instead of being listed as work (``records`` lets the classifier know
    whether the route can still rule).
    """

    closures = finding_closures(projection, records=records, with_self_verify=False)
    todos = tuple(
        finding_todo(projection, finding.finding_id, attempt_budget=attempt_budget)
        for finding in current_receipt_findings(projection)
        if FINDING_KIND_TRAITS[finding.kind][1]
    )
    counts = todo_counts(
        projection, (todo.finding_id for todo in todos), attempt_budget=attempt_budget
    )
    counted = closure_counts(closures.values(), ())
    # ADR-046: work is what the closure class says the agent owes (``agent_work``). A settled basis
    # (a disclosed limitation, a rejection nobody can rule on) keeps an ``open`` to-do state but is
    # never work. A limitation request the agent has not answered is agent work of its own kind:
    # when it is the ONLY remaining work the continuation is ``disclose_limitations`` (owner
    # decision 2026-10-12, #1024); mixed with real work it stays ``work_open_findings``. The
    # agent's own criterion reads the same basis but is work to fix or narrow (review of #1043).
    awaiting = counted.findings_awaiting_ruling
    own_criteria = sum(
        closure.closure_class is FindingClosureClass.AGENT_WORK
        and closure.basis == "limitation_requested"
        and _own_criterion(projection, closure.finding_id)
        for closure in counted_findings(closures.values()).values()
    )
    real_work = counted.findings_to_do - awaiting + own_criteria
    next_step: Literal[
        "decide_at_budget",
        "disclose_limitations",
        "request_receipt",
        "request_ruling",
        "work_open_findings",
    ]
    if counts.budget_reached:
        next_step = "decide_at_budget"
    elif real_work > 0:
        next_step = "work_open_findings"
    elif counted.findings_to_disclose > 0:
        next_step = "disclose_limitations"
    elif awaiting > 0:
        next_step = "request_ruling"
    else:
        next_step = "request_receipt"
    # Open items first (a stable sort keeps rank order inside each group), so a long history of
    # closed rows can never push the remaining work out of the listed hundred.
    listed = sorted(todos, key=lambda todo: todo.state is not FindingTodoState.OPEN)
    return CheckFindingChecklist(
        attempt_budget,
        tuple(
            CheckChecklistItem(
                str(todo.finding_id),
                todo.state.value,
                todo.review_rounds,
                None
                if todo.finding_id not in closures
                else closures[todo.finding_id].closure_class.value,
                None if todo.finding_id not in closures else closures[todo.finding_id].basis,
            )
            for todo in listed[:MAX_CHECKLIST_ITEMS]
        ),
        next_step,
        counts,
        closure_counts=ChecklistClosureCounts(
            to_do=counted.findings_to_do,
            awaiting_ruling=counted.findings_awaiting_ruling,
            unmet=counted.findings_unmet,
            disclosed=counted.findings_disclosed,
            to_disclose=counted.findings_to_disclose,
        ),
    )


def _supply_overall_next(
    result: CheckCommitResult, predicted_conclusion: str | None
) -> CheckOverallNext | None:
    """``supply_missing_input`` when the stored check names an agent_suppliable item.

    The first branch of ``build_overall_next``: it reads only the recorded missing items, never
    the finding list or the closure basis, so a replay or a status recovery read can rebuild it
    from the stored check alone (W6) when the basis at its result frontier is no longer readable.
    """

    actionable_missing = tuple(
        item for item in result.missing_for_assessment if item.availability == "agent_suppliable"
    )
    if not actionable_missing:
        return None
    return CheckOverallNext(
        status="action_required",
        action="supply_missing_input",
        # A global missing input is actionable even when the reviewer could not attach a
        # subject id.  The empty target list is the honest representation of that request.
        target_refs=_bounded_overall_refs(
            ref for item in actionable_missing for ref in item.target_refs
        ),
        predicted_conclusion=predicted_conclusion,
    )


def _with_stored_supply_next(result: CheckCommitResult) -> CheckCommitResult:
    """The check with the supply continuation its stored missing items alone determine (W6).

    Used when the finding list and closure basis cannot be read at the result frontier (a later
    material record on a cold closure-basis memo, or a successor writer after a same-task attach):
    an agent_suppliable request then still leads with what to supply and how, from durable rows.
    The predicted conclusion needs the basis, so it is omitted, never guessed; every other
    continuation needs the finding list, so it stays omitted too.
    """

    if result.overall_next is not None:
        return result
    supply = _supply_overall_next(result, None)
    return result if supply is None else replace(result, overall_next=supply)


def build_overall_next(
    result: CheckCommitResult,
    checklist: CheckFindingChecklist | None,
    projection: ProjectionState | None = None,
    coverage_by_ref: Mapping[FindingBasisRef, Coverage] | None = None,
    *,
    obligations: tuple[ObligationClosure, ...] | None = None,
    predicted_conclusion: str | None = None,
    readiness: object | None = None,
    observed_event_ids: frozenset[EventId] | None = None,
) -> CheckOverallNext | None:
    """Derive the task continuation without letting the finding list speak for the task (#963).

    ADR-046: every branch reads the closure classes. Findings the agent owes a move on are work;
    a rejection that awaits a reviewer ruling is ``request_ruling``; an obligation the agent
    acknowledged as not done, or disclosed, is not work (the receipt discloses it), so the check
    no longer disagrees with status about whether anything is left to do.
    """

    if checklist is None:
        # Without the projection that supplies finding counts, claiming readiness would be
        # fabricated. The structured continuation is therefore omitted and the caller keeps the
        # existing coverage/result fields.
        return None
    if readiness is not None and getattr(readiness, "state", None) in {
        "ready",
        "ready_with_limitations",
    }:
        ready_state = cast(Literal["ready", "ready_with_limitations"], getattr(readiness, "state"))
        return CheckOverallNext(
            status=ready_state,
            action="request_receipt",
            acknowledged_incomplete_endpoint="receipt"
            if ready_state == "ready_with_limitations"
            else None,
            predicted_conclusion=predicted_conclusion,
        )
    supply = _supply_overall_next(result, predicted_conclusion)
    if supply is not None:
        return supply
    # A limitation request nobody answered yet is agent work that asks for a disclosure, not a
    # repair: alone it is ``disclose_limitations``; beside real work it rides in the same
    # ``work_open_findings`` target list (the text names both). The agent's own criterion is
    # real work under that basis: fix it, or narrow it (review of #1043).
    agent_items = tuple(
        item
        for item in checklist.items
        if item.closure_class == "agent_work"
        or (item.closure_class is None and item.todo_state == "open")
    )
    open_refs = _bounded_overall_refs(item.finding_id for item in agent_items)
    if open_refs:
        counted = checklist.closure_counts
        only_requests = all(
            item.closure_class == "agent_work"
            and item.closure_basis == "limitation_requested"
            and not _own_criterion(projection, FindingId(item.finding_id))
            for item in agent_items
        ) and (counted is None or counted.to_do - counted.awaiting_ruling == 0)
        return CheckOverallNext(
            status="action_required",
            action="disclose_limitations" if only_requests else "work_open_findings",
            target_refs=open_refs,
            predicted_conclusion=predicted_conclusion,
        )
    awaiting_refs = _bounded_overall_refs(
        item.finding_id for item in checklist.items if item.closure_class == "awaiting_ruling"
    )
    if awaiting_refs:
        return CheckOverallNext(
            status="action_required",
            action="request_ruling",
            target_refs=awaiting_refs,
            predicted_conclusion=predicted_conclusion,
        )
    recorded_work_refs, disclosed_live_failure = _recorded_work_refs(
        result, projection, coverage_by_ref, obligations, observed_event_ids
    )
    recorded_work_refs = _bounded_overall_refs(
        (*recorded_work_refs, *_undeclared_reference_refs(result))
    )
    if recorded_work_refs:
        return CheckOverallNext(
            status="action_required",
            action="review_recorded_work",
            target_refs=recorded_work_refs,
            predicted_conclusion=predicted_conclusion,
        )
    # The finding list is only one part of closure. Use the same verdict Stop and status read,
    # including live lineage, stale verification and check currency, before offering a receipt.
    if readiness is not None:
        state = getattr(readiness, "state", None)
        if state == "action_required":
            plans = () if projection is None else tuple(projection.plans.values())
            tested = None if projection is None else projection.latest_tested_state
            target = (
                str(max(plans, key=lambda row: row.source_frontier).source_event_id)
                if plans
                else str(tested.source_check_event_id)
                if tested is not None
                else None
            )
            if target is None:
                return None
            return CheckOverallNext(
                status="action_required",
                action="review_recorded_work",
                target_refs=(target,),
                predicted_conclusion=predicted_conclusion,
            )
        return None
    counted_closures = checklist.closure_counts
    settled = bool(
        (
            counted_closures is not None
            and (
                counted_closures.unmet or counted_closures.disclosed or counted_closures.to_disclose
            )
        )
        or checklist.counts.acknowledged_not_done
        or checklist.counts.self_verified
        or checklist.counts.disputed_after_rebuttal
    )
    settled_obligations = any(
        item.closure_class is not ObligationClosureClass.RESOLVED for item in obligations or ()
    )
    if (
        disclosed_live_failure
        or result.missing_for_assessment
        or result.coverage.known_gaps
        or settled
        or settled_obligations
        or predicted_conclusion not in {None, "no_unresolved_deterministic_findings"}
    ):
        return CheckOverallNext(
            status="ready_with_limitations",
            action="request_receipt",
            acknowledged_incomplete_endpoint="receipt",
            predicted_conclusion=predicted_conclusion,
        )
    return CheckOverallNext(
        status="ready", action="request_receipt", predicted_conclusion=predicted_conclusion
    )


class _PacketLimits(TypedDict):
    packet_limited_refs: frozenset[str]
    privacy_withheld_refs: frozenset[str]
    change_clipped: bool


def _packet_limits(
    semantic_result: FinalSemanticEvaluation, deterministic: tuple[Finding, ...]
) -> _PacketLimits:
    """What the sent packet could not show, for classifying named missing items (tb4n1 D1).

    ``packet_limited_refs`` are refs an omission row of the exact sent packet withheld for room
    or selection; a ``not_recorded`` omission (nothing more was ever recorded) never counts, and
    this check's own local findings are never packet content. Unknown when the sent packet was
    not read. ``privacy_withheld_refs`` are the refs an owner privacy rule withheld (a privacy
    limit, classified structurally unavailable). ``change_clipped`` says the check-time change's
    own text was clipped for room or redacted (``_change_text_redacted``).
    """

    withheld = semantic_result.case_withheld_refs
    local = {str(item.finding_id) for item in deterministic}
    gaps = set(semantic_result.case_content_gaps)
    return {
        "packet_limited_refs": (frozenset() if withheld is None else frozenset(withheld - local)),
        "privacy_withheld_refs": frozenset(semantic_result.case_privacy_withheld_refs - local),
        "change_clipped": CHECK_TIME_CHANGE_TRUNCATED_GAP in gaps
        or (CHECK_TIME_CHANGE_REDACTED_GAP in gaps and _change_text_redacted(semantic_result)),
    }


def _change_text_redacted(semantic_result: FinalSemanticEvaluation) -> bool:
    """Whether redaction altered the check-time change text the packet carried (#1045 review).

    ``check_time_change_redacted`` also reports a task input file that was redacted or withheld,
    which leaves every diff whole. A redacted diff section the packet carried holds a marker, so
    the packet's shown-file record (a pure function of the stored change and the bytes carried,
    the same on replay) lists it in part with its redactions; a section the packet did not carry
    is already ``check_time_change_truncated``. A record that is missing, incomplete or names no
    file at all cannot tell, and answers yes, as before.
    """

    files = semantic_result.check_change_files
    if files is None or not files.complete or not (files.fully_shown or files.partially_shown):
        return True
    return any(item.redactions for item in files.partially_shown)


async def _review_round_stopped_at(
    runtime: TaskRuntime, request: CheckRequest, frozen: FrozenCase
) -> bool:
    """``review_round_stopped`` over the ledger prefix the check froze; fails open to a review.

    A caller-chosen local-only check never asks, so it never carries the skip disclosure. A
    ``semantic_required`` check is bounded too (#1118 unit 4, AIM-5): it no longer redispatches an
    unchanged packet past the limits, and its stopped review ends ``incomplete_check``.
    """

    if request.mode == "deterministic_only":
        return False
    try:
        records = tuple(
            [
                record
                async for record in runtime.ledger.load_events(
                    runtime.session_id, through=frozen.case.frontier.sequence
                )
            ]
        )
    except Exception as exc:
        record_unexpected_exception_without_raising(
            exc, component="check", operation="review_round_read", request_id=request.request_id
        )
        return False
    return review_round_stopped(records)


def _review_phase(
    request: CheckRequest, frozen: FrozenCase, result: FinalSemanticEvaluation
) -> Literal["routine", "final"]:
    """The phase the review packet named, or the same pure selector's answer (issue #1042)."""

    manifest = result.review_input_manifest
    if manifest is not None and manifest.review_phase is not None:
        return manifest.review_phase
    return select_semantic_budget_profile(
        frozen.case.projection, final_review=bool(request.final_review)
    )


def _semantic_wait(request: CheckRequest, runtime: TaskRuntime, *, round_stopped: bool) -> bool:
    return (
        request.mode != "deterministic_only"
        and not round_stopped
        and RuntimeCapability.SEMANTIC in runtime.capabilities
    )


def _review_deferred_before_first_edit(
    request: CheckRequest,
    runtime: TaskRuntime,
    frozen: FrozenCase,
    *,
    route_profile: Literal["policy", "strict"],
    workspace_changed: bool | None,
) -> bool:
    """Whether this check defers the AI-powered review until the first material edit (#1046).

    True only for a routine check (no completion claim and not the closing review) that would
    otherwise dispatch a review (not ``deterministic_only``, the policy route, a configured
    reviewer), when the frozen ledger records no material edit (``material_edit_recorded``) and
    the check-time workspace capture did not observe a change. tb4n4: 18 of 61 semantic-arm tasks
    reviewed the plan before any work, and most routine ``insufficient_packet`` answers were
    those. The deferral never applies to the closing review, so a task whose work is not an edit
    still reaches one (the tb4n1 D3 stopped-round skip above is a separate rule).
    A check already waiting on a review keeps it (a resumed attempt never changes its decision);
    a check resumed in ``ready_to_finalize`` decides through ``_review_skip_gaps`` from durable
    state only, never from a fresh capture.
    """

    if (
        request.mode == "deterministic_only"
        or route_profile != "policy"
        or RuntimeCapability.SEMANTIC not in runtime.capabilities
        or frozen.lease.phase is CheckPhase.SEMANTIC_WAIT
        or workspace_changed is True
        or select_semantic_budget_profile(
            frozen.case.projection, final_review=bool(request.final_review)
        )
        != "routine"
    ):
        return False
    coverage = frozen.case.coverage_by_ref
    return not material_edit_recorded(
        frozen.case.projection,
        observed_event_ids_from_coverage(coverage),
        cooperative_event_ids_from_coverage(coverage),
    )


async def _review_skip_gaps(
    runtime: TaskRuntime,
    request: CheckRequest,
    frozen: FrozenCase,
    *,
    route_profile: Literal["policy", "strict"],
    workspace_changed: bool | None,
) -> frozenset[str]:
    """The gap that discloses why this check skips the AI-powered review, if it does.

    tb4n1 D3: the round stopped after the one insufficient-packet retry. Issue #1046: the check
    runs before the first material edit (``_review_deferred_before_first_edit``). Empty when the
    check reviews as configured.

    A check resumed in ``ready_to_finalize`` already made this decision before it was
    interrupted (#1046 review): if it sent a review, the operation owns a review job and the
    check is never deferred on retry, so a paid review is kept; if it sent none, a capture that
    now sees a change cannot make it dispatch one in a phase that cannot send it. The live
    capture is not read there; the frozen ledger prefix decides, as for the stopped round.
    """

    if await _review_round_stopped_at(runtime, request, frozen):
        return frozenset({SEMANTIC_REVIEW_SKIPPED_INSUFFICIENT_PACKET_GAP})
    if frozen.lease.phase is CheckPhase.READY_TO_FINALIZE:
        if await _review_job_recorded(runtime, frozen):
            return frozenset()
        workspace_changed = None
    if _review_deferred_before_first_edit(
        request,
        runtime,
        frozen,
        route_profile=route_profile,
        workspace_changed=workspace_changed,
    ):
        return frozenset({SEMANTIC_REVIEW_DEFERRED_BEFORE_FIRST_EDIT_GAP})
    return frozenset()


async def _review_job_recorded(runtime: TaskRuntime, frozen: FrozenCase) -> bool:
    """Whether this check operation already owns an AI-powered review job (#1046 review).

    An unreadable answer counts as none: the resumed check then decides from the frozen prefix,
    which is what a check that sent no review decided too.
    """

    load = getattr(runtime.ledger, "load_semantic_job", None)
    if not callable(load):
        return False
    try:
        job = await cast(Callable[[str, str], Awaitable[object | None]], load)(
            frozen.lease.writer_id, frozen.lease.operation_id
        )
    except Exception as exc:
        record_unexpected_exception_without_raising(
            exc, component="check", operation="review_job_read"
        )
        return False
    return job is not None


def _undeclared_reference_refs(result: CheckCommitResult) -> tuple[str, ...]:
    """The obligations whose delivered file loads an undeclared file this check found (#1044).

    ADR-046 rule ``G0c``: the fact is agent work on every surface, but its obligation stays
    ``resolved``, so the obligation classes never name it. The referencing deliverable's recorded
    state does; if no state names the files, every deliverable the check read is the target.
    """

    if DELIVERABLE_REFERENCES_UNDECLARED_FILE_GAP not in result.coverage.known_gaps:
        return ()
    named = tuple(
        str(state.obligation_id)
        for state in result.deliverable_states
        if state.undeclared_references or state.undeclared_reference_count
    )
    return named or tuple(str(state.obligation_id) for state in result.deliverable_states)


def _bounded_overall_refs(values: Iterable[object]) -> tuple[str, ...]:
    """Canonicalize task-level continuation references at the public 64-item bound."""

    refs = {value for value in values if type(value) is str and value and len(value) <= 128}
    return tuple(sorted(refs, key=str.encode)[:64])


def _overall_total_count(result: CheckCommitResult, group: str, key: str) -> int:
    totals = result.totals
    if not isinstance(totals, Mapping):
        return 0
    values = totals.get(group)
    if not isinstance(values, Mapping):
        return 0
    value = values.get(key)
    if type(value) is int and value >= 0:
        return value
    if type(value) is str and value.isascii() and value.isdecimal():
        return int(value)
    return 0


def _result_is_disclosed_for_completion(projection: ProjectionState, result_ref: object) -> bool:
    if type(result_ref) is not str:
        return False
    try:
        result_key = result_id(result_ref)
    except ValueError:
        return False
    for _, claim_record in effective_claim_items(projection):
        claim = claim_record.payload
        if (
            claim is not None
            and claim.claim_kind is ClaimKind.COMPLETION
            and result_is_relevant_to_claim(projection, claim_record, result_key)
            and claim_discloses_result(claim, result_key)
        ):
            return True
    return False


def _recorded_work_refs(
    result: CheckCommitResult,
    projection: ProjectionState | None,
    coverage_by_ref: Mapping[FindingBasisRef, Coverage] | None = None,
    obligations: tuple[ObligationClosure, ...] | None = None,
    observed_event_ids: frozenset[EventId] | None = None,
) -> tuple[tuple[str, ...], bool]:
    """Find open effective work that a coverage-limited result still requires.

    The frozen totals establish whether a live observed failure exists.  The trusted case
    coverage and projection then identify the exact currently-live observed result ids. Completion
    claim disclosure is consulted before a continuation is emitted: an explicitly disclosed live
    failure can proceed to its limited receipt rather than forcing an endless rerun. The second
    return value preserves that disclosed-live limitation for the coverage-limited status.
    """

    if projection is None:
        return (), False
    refs: set[str] = set()
    scope = current_plan_scope(projection.plans, projection.coverage_gaps)
    # ADR-046: only an obligation the agent can still act on is work here. One it acknowledged as
    # not done, or disclosed (a confirmed blocker, an externally evaluated requirement), is
    # settled: status and the receipt say so, so the next step must not call it open work.
    classes = (
        tuple(obligation_closures(projection).values()) if obligations is None else obligations
    )
    refs.update(
        str(item.obligation_id)
        for item in classes
        if item.closure_class is ObligationClosureClass.AGENT_WORK
    )

    if _overall_total_count(result, "commands", "live_failed") <= 0:
        return _bounded_overall_refs(refs), False

    if coverage_by_ref is None and observed_event_ids is None:
        return _bounded_overall_refs(refs), False
    try:
        observed = (
            observed_event_ids
            if observed_event_ids is not None
            else observed_event_ids_from_coverage(coverage_by_ref or {})
        )
        states = observed_failure_states(projection, observed, through=projection.frontier)
    except (TypeError, ValueError):
        return _bounded_overall_refs(refs), False
    active_obligations: frozenset[ObligationId] = (
        frozenset(scope.effective_obligation_refs or ()) if scope.readable else frozenset()
    )
    disclosed_live_failure = False
    for result_ref, state in sorted(states.items(), key=lambda item: str(item[0]).encode()):
        if state is not ObservedFailureState.LIVE:
            continue
        record = projection.results.get(result_ref)
        payload = None if record is None else record.payload
        if payload is None:
            continue
        action = projection.actions.get(payload.action_id)
        if action is None or action.payload is None:
            continue
        action_payload = action.payload
        if action_payload.action_kind is not ActionKind.COMMAND:
            continue
        if observed_failure_exempt(action_payload, payload):
            continue
        if action_payload.obligation_refs and not active_obligations.intersection(
            action_payload.obligation_refs
        ):
            continue
        if _result_is_disclosed_for_completion(projection, result_ref):
            disclosed_live_failure = True
            continue
        refs.add(str(result_ref))
        refs.add(str(payload.action_id))
    return _bounded_overall_refs(refs), disclosed_live_failure


async def _attach_finding_checklist(
    app: Application,
    runtime: TaskRuntime,
    result: CheckCommitResult,
    *,
    coverage_by_ref: Mapping[FindingBasisRef, Coverage] | None = None,
    route_profile: Literal["policy", "strict"] | None = None,
) -> CheckCommitResult:
    """Attach the task's findings as a to-do list after this check (issue #905).

    Like project advice this is current projection context beside the frozen check: it never
    changes the recorded event or its verdict. It reads only the adapter-owned projection at the
    result frontier (never a replay or a status page); when that is unavailable, or anything
    fails, the check is returned without the list rather than stranded after its commit, keeping
    only the supply continuation its stored missing items determine (``_with_stored_supply_next``).

    The list holds the current actionable items (the newest row per issue, in rank order, at most
    100); the counts and the ``next`` token are computed over all of them. Coverage limitations
    are not to-dos and never drive ``next``. The budget only chooses ``next``: nothing here
    closes, acknowledges or throttles.
    """

    policy = getattr(app, "verification_policy", None)
    budget = getattr(policy, "finding_attempt_budget", DEFAULT_FINDING_ATTEMPT_BUDGET)
    if type(budget) is not int:
        budget = DEFAULT_FINDING_ATTEMPT_BUDGET
    try:
        projection = await trusted_projection_at(
            runtime.ledger, result.session_id, result.result_frontier
        )
        if projection is None:
            return _with_stored_supply_next(result)
        # ADR-046: the receipt's own context at the result frontier gives the predicted
        # conclusion and the records the classes need. A read that fails omits the prediction
        # (never guesses one) and leaves a bounded diagnostic.
        loaded: LoadedClosureBasis | None = None
        try:
            loaded = await load_closure_basis(runtime, result.result_frontier)
        except (ClosureBasisUnavailable, PublicOperationError, TypeError, ValueError) as exc:
            record_unexpected_exception_without_raising(
                exc, component="check", operation="closure_basis_read"
            )
        if loaded is None:
            # The closure classes need the ledger prefix (can a reviewer still rule, which
            # obligations are emptied or blocked). Without it any class would be a guess that
            # status, reading the real basis, could contradict; the check is returned without the
            # list, like every other failed read here (the diagnostic above is the trace).
            return _with_stored_supply_next(result)
        checklist = build_finding_checklist(
            projection, attempt_budget=budget, records=loaded.records
        )
        # Local import: status recovers check outcomes through this module, while both now
        # consume its one snapshot-bound closure verdict rather than deriving competing ones.
        from finishup.application.status import closure_readiness_at

        readiness = await closure_readiness_at(
            cast("StatusApplication", app),
            runtime,
            result.result_frontier,
            result.request_id,
            loaded=loaded,
            route_profile=route_profile,
        )
        overall_next = build_overall_next(
            result,
            checklist,
            projection,
            coverage_by_ref,
            obligations=loaded.basis.obligations,
            predicted_conclusion=predict_receipt_conclusion(loaded.basis).conclusion.value,
            readiness=readiness,
            observed_event_ids=observed_event_ids_from_records(loaded.records),
        )
        return replace(
            result,
            correctness_advisories=check_advisory_rows(loaded.records, result.result_frontier),
            finding_checklist=(
                replace(checklist, next="request_receipt")
                if readiness.state in {"ready", "ready_with_limitations"}
                else replace(checklist, next="follow_overall_next")
                if checklist.next == "request_receipt"
                else checklist
            ),
            overall_next=overall_next,
            closure_readiness=JsonObject(
                cast(dict[str, JsonValue], readiness.model_dump(mode="json", exclude_unset=True))
            ),
        )
    except Exception as exc:
        record_unexpected_exception_without_raising(
            exc,
            component="check",
            operation="finding_checklist_read",
        )
        return _with_stored_supply_next(result)


def check_advisory_rows(
    records: tuple[LedgerRecord, ...], result_frontier: Frontier
) -> tuple[JsonObject, ...]:
    """The advisory rows of the check recorded at *result_frontier*, with identities (#1162).

    Read from the recorded check itself, so a commit, a same-id replay and a status recovery of
    the check agree. A row without ``origin`` is a routine correctness note.
    """

    check = next(
        (
            record
            for record in reversed(records)
            if record.ledger.ingestion_sequence == result_frontier.sequence
            and isinstance(record.payload, CheckRecordedPayload)
        ),
        None,
    )
    if check is None:
        return ()
    payload = check.payload
    assert isinstance(payload, CheckRecordedPayload)
    return tuple(
        JsonObject(
            {
                "advisory_id": f"{check.event_id}:{ordinal}",
                "origin": str(row.get("origin", "routine_correctness_note")),
                "subject_refs": row["subject_refs"],
                "summary": row["summary"],
            }
        )
        for ordinal, row in enumerate(payload.correctness_advisories, 1)
    )


async def _attach_current_project_advisory_notes(
    app: Application,
    task_id: str,
    result: CheckCommitResult,
) -> CheckCommitResult:
    """Attach current advice without changing the frozen result or replay semantics."""

    notes = await _current_project_advisory_notes(app, task_id, result.findings)
    return result if result.advisory_notes == notes else replace(result, advisory_notes=notes)


@dataclass(frozen=True, slots=True)
class CheckScope:
    claim_ids: tuple[str, ...]
    obligation_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        claims = tuple(claim_id(value) for value in self.claim_ids)
        obligations = tuple(obligation_id(value) for value in self.obligation_ids)
        if claims != tuple(sorted(set(claims), key=str.encode)):
            raise _invalid("check_scope_invalid")
        if obligations != tuple(sorted(set(obligations), key=str.encode)):
            raise _invalid("check_scope_invalid")
        object.__setattr__(self, "claim_ids", cast(tuple[str, ...], claims))
        object.__setattr__(self, "obligation_ids", cast(tuple[str, ...], obligations))

    @property
    def roots(self) -> frozenset[str]:
        return frozenset((*self.claim_ids, *self.obligation_ids))

    @property
    def whole_case(self) -> bool:
        return not self.claim_ids and not self.obligation_ids


def normalize_check_scope(request: CheckRequest) -> CheckScope:
    """Normalize omitted and explicit-empty scope to the same immutable value."""

    scope = request.scope
    if scope is None:
        return CheckScope((), ())
    return CheckScope(
        tuple(sorted(scope.claim_ids, key=str.encode)),
        tuple(sorted(scope.obligation_ids, key=str.encode)),
    )


@dataclass(frozen=True, slots=True)
class FinalSemanticEvaluation:
    status: SemanticStatus
    reason: SemanticReason
    judgment: SemanticJudgment | None = None
    provenance: SemanticProvenance | None = None
    # Bounded structural attempt accounting reconstructed from durable rows when a job ran.
    # Not part of the frozen public check-result wire; owner recovery reads the ledger.
    attempt_accounting: object | None = None
    # When the durable AI-powered review phase renewed the check operation lease (lease TTL is 60s while
    # timeout_seconds may be longer), later phase advance / commit must use this CAS fence.
    operation_lease: OperationLease | None = None
    # Categories the review profile selected that the inference channel did not permit. A review
    # can succeed while structurally unable to answer its own question; coverage must say so.
    withheld_review_categories: tuple[str, ...] = ()
    # True when the owner policy the review ran under had the low-confidence credential heuristic
    # turned off (issue #982 owner opt-out). Coverage discloses it on every such review.
    credential_heuristic_disabled: bool = False
    # True when composing the case had to shorten or replace recorded text that the publish-side
    # prose bound had already accepted. The reviewer judged a fragment; coverage must say so
    # rather than let the shortening pass as material the author chose not to send.
    case_content_over_item_limit: bool = False
    case_reference_scope_reduced: bool = False
    # The frontier references whose own content item the exact sent review packet carried, after
    # envelope bounding and privacy minimization (issue #904); None when no packet was sent or it
    # could not be read. The check records them only for a completed reduced review.
    case_included_refs: frozenset[str] | None = None
    # tb4n1 D1: the frontier references an omission row of the exact sent packet withheld for a
    # reason other than ``not_recorded`` (room, selection or policy). A reviewer request for one of
    # them is FinishUP's limit, never agent work. ``None`` when the packet was not read.
    case_withheld_refs: frozenset[str] | None = None
    # The refs an owner privacy rule withheld (with a withheld captured group's parts, which the
    # omission row names only by its lead); a request for one is a privacy limit.
    case_privacy_withheld_refs: frozenset[str] = frozenset()
    # Opaque case item identities omitted by the low-confidence never-send heuristic. The
    # public check result names these identities and the closed remediation reason, never bytes
    # or source prose.
    semantic_withheld_item_ids: tuple[str, ...] = ()
    # PL2-1 (issue #982): per item, the catalogued ref and the 1-based lines where the external
    # reviewer's copy had a credential-like value replaced, or the item withheld. Never values.
    semantic_redacted_values: tuple[SemanticRedactedValue, ...] = ()
    case_content_gaps: tuple[str, ...] = ()
    # Missing-item kinds the effective review selection or channel can never carry (issue #907).
    # Computed where the case is composed, so the check can classify what a reviewer names.
    unsuppliable_missing_kinds: tuple[str, ...] = ()
    # The packet the reviewer was shown (issue #905): the earlier findings its prior-findings
    # section carried and its citable refs. ``None`` when the evaluator did not report them.
    case_prior_finding_refs: frozenset[str] | None = None
    case_citable_refs: frozenset[str] | None = None
    # Findings the agent settled that the packet carried as nameable, non-rulable rows (#980).
    case_settled_finding_refs: frozenset[str] | None = None
    # Issue #907: workspace-relative paths each hook-captured edit in the case records, keyed by
    # evidence ref. In process only, to bind a fresh diff to a repeated missing-item request;
    # never recorded, logged or sent. ``None`` when the evaluator did not resolve captures.
    case_captured_edit_paths: Mapping[str, frozenset[str]] | None = None
    # Issue #907: the absolute workspace root the session opened with, anchoring absolute paths
    # an agent names; in process only, never recorded. ``None`` when it was not resolved.
    case_workspace_root: str | None = None
    # tb4n2 A11: repository-relative paths the check-time change marks binary, so a suffix-less
    # binary a reviewer names is FinishUP's unsupported-data-type limit. In process only.
    case_binary_paths: frozenset[str] = frozenset()
    # ADR-045: the paths the same change lists as text; Git's NUL sniff overrules a suffix.
    case_text_paths: frozenset[str] = frozenset()
    # ADR-031: keyed commitments to the check-time change files the review packet carried.
    check_change_files: CheckChangeShownFiles | None = None
    # Set only on the nonterminal awaiting_human branch: what the caller must do to resume this
    # exact request. Every terminal outcome leaves it None. A one-use disclosure wait keeps its
    # job and attempt open; a missing standing repository grant stops before either exists.
    continuation: SemanticContinuation | None = None
    # Structural admission result for the task specification. It is surfaced on the actionable
    # preflight branch and retained with terminal evaluation metadata; statement prose never
    # enters this value.
    specification_preflight: SpecificationPreflight | None = None
    review_input_manifest: ReviewInputManifest | None = None
    # Provider-bound manifest reconstructed from the exact minimized packet.  It is intentionally
    # separate from the composed manifest so the final check receipt can report what was sent.
    provider_input_manifest: JsonObject | None = None
    # Closed provenance reason for a successful provider call whose exact provider-bound input
    # manifest could not be retained/restored.  A composed manifest is never a substitute.
    provider_input_manifest_failure: str | None = None
    # Ephemeral exact provider-bound row text used to validate reviewer snippets. It is omitted
    # from durable/public result objects; recovery without it rejects unverifiable quotes.
    provider_input_text_by_ref: Mapping[str, tuple[str, ...]] | None = None
    # Issue #1047: the refs whose content the exact sent packet's excerpts held (a captured
    # group's parts included), read from its provider-bound manifest, so an in-check follow-up
    # can tell what was shown and what a later packet adds. In process only; ``None`` when what
    # was sent is unknown. A source split into parts counts only once every part was sent.
    case_excerpt_refs: frozenset[str] | None = None
    # tb4n5: the excerpt parts (``excerpt_span_key``) the same sent packet carried, so a follow-up
    # tells a later part of a partly shown source from a repeat. In process only; ``None`` when
    # what was sent is unknown.
    case_excerpt_parts: frozenset[str] | None = None
    # tb4n5: each captured edit's evidence ref mapped to the check-time change sections of the
    # paths it changed (``semantic_case.current_section_parts``), when this packet's recipe and
    # channel could carry them. In process only; never recorded or logged.
    case_current_section_parts: Mapping[str, frozenset[str]] | None = None
    # #1118: what the reviewer conversation did (exchanges, reads, why it ended, cleanup); the
    # bounded structural record every surface renders. ``None`` for a review that ran no
    # conversation (older ledgers, local-only paths).
    reviewer: ReviewerRecord | None = None
    # The refs the conversation's admitted reads sent, joined to the packet's citable refs for the
    # judgment fence. In process only, like ``provider_input_text_by_ref``.
    reviewer_citable_refs: frozenset[str] = frozenset()
    # Each file read's ``alias:path`` by call, kept only in the encrypted review response.
    reviewer_paths: Mapping[int, str] | None = None
    # Selector-only diagnostics; private payload in the encrypted attempt response, never public.
    reviewer_read_usage: tuple[Mapping[str, JsonValue], ...] | None = None

    def __post_init__(self) -> None:
        if (
            type(self.case_content_gaps) is not tuple
            or self.case_content_gaps != tuple(sorted(set(self.case_content_gaps)))
            or not set(self.case_content_gaps) <= _SEMANTIC_EVALUATION_GAPS
        ):
            raise _invalid("semantic_judgment_invalid")
        if self.case_included_refs is not None and (
            type(self.case_included_refs) is not frozenset
            or any(type(ref) is not str for ref in self.case_included_refs)
        ):
            raise _invalid("semantic_judgment_invalid")
        for refs in (self.case_excerpt_refs, self.case_excerpt_parts):
            if refs is not None and (
                type(refs) is not frozenset or any(type(ref) is not str for ref in refs)
            ):
                raise _invalid("semantic_judgment_invalid")
        if (
            type(self.semantic_withheld_item_ids) is not tuple
            or self.semantic_withheld_item_ids
            != tuple(sorted(set(self.semantic_withheld_item_ids), key=str.encode))
            or len(self.semantic_withheld_item_ids) > 64
            or any(
                not _valid_opaque_item_id(item_id) for item_id in self.semantic_withheld_item_ids
            )
        ):
            raise _invalid("semantic_judgment_invalid")
        try:
            validate_semantic_redacted_values(self.semantic_redacted_values)
        except ValueError as exc:
            raise _invalid("semantic_judgment_invalid") from exc
        if (
            type(self.unsuppliable_missing_kinds) is not tuple
            or self.unsuppliable_missing_kinds
            != tuple(sorted(set(self.unsuppliable_missing_kinds), key=str.encode))
            or not set(self.unsuppliable_missing_kinds) <= MISSING_FOR_ASSESSMENT_KINDS
        ):
            raise _invalid("semantic_judgment_invalid")
        validate_semantic_outcome(self.status, self.reason)
        validate_semantic_provenance_binding(
            self.status,
            self.reason,
            None if self.provenance is None else self.provenance.status,
            None if self.provenance is None else self.provenance.reason,
        )
        if self.provenance is not None and type(self.provenance) is not SemanticProvenance:
            raise _invalid("semantic_provenance_invalid")
        if self.status is SemanticStatus.SUCCEEDED:
            if type(self.judgment) is not SemanticJudgment or self.provenance is None:
                raise _invalid("semantic_judgment_invalid")
        elif self.judgment is not None:
            raise _invalid("semantic_judgment_invalid")
        if self.operation_lease is not None and type(self.operation_lease) is not OperationLease:
            raise _invalid("operation_lease_invalid")
        if self.continuation is not None:
            if type(self.continuation) is not SemanticContinuation:
                raise _invalid("semantic_continuation_invalid")
            # A continuation on a terminal outcome would tell the caller to resume a request the
            # ledger has already closed. Bind it to the one status that keeps the job open.
            if self.status is not SemanticStatus.AWAITING_HUMAN:
                raise _invalid("semantic_continuation_invalid")
        if (
            self.specification_preflight is not None
            and type(self.specification_preflight) is not SpecificationPreflight
        ):
            raise _invalid("specification_preflight_invalid")
        if (
            self.review_input_manifest is not None
            and type(self.review_input_manifest) is not ReviewInputManifest
        ):
            raise _invalid("review_input_manifest_invalid")
        if (
            self.provider_input_manifest is not None
            and type(self.provider_input_manifest) is not JsonObject
        ):
            raise _invalid("provider_input_manifest_invalid")
        if self.provider_input_manifest_failure is not None and (
            self.provider_input_manifest_failure not in SEMANTIC_PROVIDER_INPUT_MANIFEST_FAILURES
        ):
            raise _invalid("provider_input_manifest_failure_invalid")
        if (
            self.provider_input_manifest is not None
            and self.provider_input_manifest_failure is not None
        ):
            raise _invalid("provider_input_manifest_failure_invalid")
        if self.provider_input_text_by_ref is not None and not isinstance(
            cast(object, self.provider_input_text_by_ref), Mapping
        ):
            raise _invalid("provider_input_text_invalid")
        if self.provider_input_text_by_ref is not None and any(
            type(ref) is not str
            or type(texts) is not tuple
            or any(type(text) is not str for text in texts)
            for ref, texts in self.provider_input_text_by_ref.items()
        ):
            raise _invalid("provider_input_text_invalid")


# Gaps that record an AI-powered review the task actually attempted and did not get. They are the
# environment's account of the missing review, never the caller's; `semantic_review_not_requested`
# is deliberately absent because it is the one this set exists to disambiguate.
# `optional_semantic_review_registration_drift` is deliberately absent too: it is re-added
# fresh on the strict-ceiling path only after reading the live applied-route record, so
# carrying it would let a stale drift claim survive a `mcp remove` (which clears the
# record) or a strict reinstall on a later local-only successor (issue #537).
_SEMANTIC_ATTEMPT_GAPS: Final = frozenset(
    {
        "semantic_case_capacity_exceeded",
        OPTIONAL_SEMANTIC_REVIEW_BLOCKED_BY_POLICY_GAP,
        SEMANTIC_RELEVANCE_REVIEW_NOT_RUN_GAP,
        SEMANTIC_REVIEW_NOT_CONFIGURED_GAP,
    }
)


def _strict_ceiling_route_drift(
    *, host_profile: McpHostProfile = "generic", _state: Path | None
) -> bool:
    """Fail-soft applied-policy probe for the strict route ceiling (issue #537).

    True only when the durable applied-route record says the last install applied the
    policy route while this check serves the strict ceiling: the serving process is
    stale, not the privacy posture. Any missing, corrupt, unsafe, or non-policy record
    reads as no drift. Never raises, never logs content, never changes the terminal
    status/reason/provenance — the caller only adds a structural coverage gap.
    """

    # A bare or otherwise generic serving command does not prove that Codex owns the process.
    # The applied-route record is Codex-specific, so comparing it against another host would
    # manufacture a registration-drift claim (issue #548).
    if host_profile != "codex":
        return False
    try:
        from finishup.application.applied_mcp_route import read_applied_route

        record = read_applied_route(_state=_state)
    except Exception:
        return False
    return isinstance(record, dict) and record.get("applied_profile") == "policy"


def carried_semantic_attempt_gaps(case: DeterministicCase, status: SemanticStatus) -> set[str]:
    """Carry a superseded check's AI-powered review attempt gap onto a local-only successor.

    A blocked or unavailable AI-powered review is normally followed by a ``deterministic_only``
    re-check, which is the stop-rule behaviour: a blocked review is a coverage gap, not a retry
    problem. That successor replaces ``latest_tested_state`` wholesale, so without this the only
    surviving disclosure is ``semantic_review_not_requested`` -- which attributes the missing
    review to the agent not asking, when the environment refused (issue #185). Carrying the
    earlier gap forward keeps the receipt's account of *why* there is no AI-powered review.

    The carry is task-level, not scope-bound: ``LatestTestedState`` records no scope, and the
    successor replaces it wholesale whatever its scope, so a gap from a differently-scoped
    attempt is inherited too. That errs toward disclosing a refusal the task did experience,
    never toward claiming coverage.
    """

    # Only a check that did not itself request review can inherit; an attempt of its own already
    # states its own outcome, and a succeeded review has closed the gap rather than carried it.
    if status is not SemanticStatus.NOT_REQUESTED:
        return set()
    latest = case.projection.latest_tested_state
    if latest is None:
        return set()
    return set(_SEMANTIC_ATTEMPT_GAPS & set(latest.coverage.known_gaps))


class _VerificationPolicy(Protocol):
    @property
    def semantic(self) -> Literal["disabled", "optional", "required"]: ...

    @property
    def max_findings(self) -> int: ...

    @property
    def default_check_mode(
        self,
    ) -> Literal["deterministic_only", "semantic_if_configured", "semantic_required"]: ...


class Application(Protocol):
    @property
    def runtime(self) -> BundleRuntimePort: ...

    @property
    def clock(self) -> ClockPort: ...

    @property
    def ids(self) -> IdPort: ...

    @property
    def verification_policy(self) -> _VerificationPolicy: ...

    @property
    def reconcile_observation_capture(
        self,
    ) -> Callable[[TaskRuntime], Awaitable[None]] | None: ...

    async def evaluate_semantic_check(
        self,
        frozen: FrozenCase,
        deterministic_findings: tuple[Finding, ...],
        runtime: TaskRuntime | None = None,
        lineage_evaluation: LineageEvaluation | None = None,
        require_complete_specification: bool = False,
    ) -> FinalSemanticEvaluation: ...


type _PolicyEvaluator = Callable[[DeterministicCase], tuple[DeterministicAssessment, ...]]


@dataclass(frozen=True, slots=True)
class _DurableDeterministicResult:
    findings: tuple[Finding, ...]
    executions: tuple[CheckPolicyExecution, ...]


class _DeterministicCheckpointSuperseded(Exception):
    """The persisted local result predates the current finding-text contract.

    The checkpoint's bindings verified, so this is not corruption: the same digest-verified
    frozen case is still available and the local phase recomputes from it instead of
    failing the request (issue #340).
    """


_DETERMINISTIC_RESULT_KEYS: Final = frozenset(
    {
        "schema_version",
        "request_id",
        "request_digest",
        "task_id",
        "session_id",
        "writer_id",
        "subject_frontier",
        "dependency_digest",
        "text_contract_digest",
        "prior_resume",
        "policy_executions",
        "assessments",
    }
)
# Checkpoints written before the text-contract stamp existed. Their wording generation is
# unknowable, so they are always superseded, never validated byte-for-byte.
_LEGACY_DETERMINISTIC_RESULT_KEYS: Final = _DETERMINISTIC_RESULT_KEYS - {"text_contract_digest"}


def _object_pointer(ref: ObjectRef) -> dict[str, JsonValue]:
    return {
        "object_id": ref.object_id,
        "envelope_digest": ref.envelope_digest,
        "commitment": ref.commitment,
    }


async def _read_all(ref: ObjectRef, runtime: TaskRuntime) -> bytes:
    return b"".join([chunk async for chunk in runtime.objects.open_verified(ref)])


def _mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError("deterministic_result_shape_invalid")
    source = cast(Mapping[object, object], value)
    if any(type(key) is not str for key in source):
        raise ValueError("deterministic_result_shape_invalid")
    return cast(Mapping[str, object], source)


async def _load_deterministic_result(
    runtime: TaskRuntime,
    request: CheckRequest,
    request_digest_value: str,
    frozen: FrozenCase,
) -> _DurableDeterministicResult:
    record = await runtime.ledger.lookup_operation(request.writer_id, request.request_id)
    try:
        if (
            type(record) is not OperationRecord
            or record.state is not OperationState.PENDING
            or record.phase is CheckPhase.RESERVED
            or record.request_digest != request_digest_value
            or record.resume_object_ref is None
            or record.resume_object_ref.metadata.kind is not ObjectKind.DETERMINISTIC_RESULT
        ):
            raise ValueError("deterministic_result_binding_invalid")
        ref = record.resume_object_ref
        raw = await _read_all(ref, runtime)
        parsed = strict_json_parse(raw)
        if canonical_encode(parsed) != raw:
            raise ValueError("deterministic_result_noncanonical")
        source = _mapping(parsed)
        if frozenset(source) not in {
            _DETERMINISTIC_RESULT_KEYS,
            _LEGACY_DETERMINISTIC_RESULT_KEYS,
        }:
            raise ValueError("deterministic_result_shape_invalid")
        if (
            source["schema_version"] != "1.0.0"
            or source["request_id"] != request.request_id
            or source["request_digest"] != request_digest_value
            or source["task_id"] != runtime.task_id
            or source["session_id"] != runtime.session_id
            or source["writer_id"] != runtime.writer_id
            or source["subject_frontier"] != frozen.case.frontier.as_wire()
            or source["dependency_digest"] != frozen.lease.dependency_digest
        ):
            raise ValueError("deterministic_result_binding_invalid")
        pointer = _mapping(source["prior_resume"])
        if frozenset(pointer) != frozenset({"object_id", "envelope_digest", "commitment"}):
            raise ValueError("deterministic_result_pointer_invalid")
        prior = await runtime.objects.resolve_verified(
            cast(str, pointer["object_id"]), cast(str, pointer["envelope_digest"])
        )
        if (
            prior.metadata.kind is not ObjectKind.CHECK_RESUME
            or prior.metadata.task_id != runtime.task_id
            or prior.commitment != pointer["commitment"]
        ):
            raise ValueError("deterministic_result_pointer_invalid")
        await _read_all(prior, runtime)
        # Defer supersession until every persisted result field has been decoded and validated.
        # A stale stamp does not make otherwise malformed checkpoint content safe to ignore.
        checkpoint_superseded = (
            source.get("text_contract_digest") != DETERMINISTIC_TEXT_CONTRACT_DIGEST
        )
        raw_executions = source["policy_executions"]
        raw_assessments = source["assessments"]
        if type(raw_executions) is not list or type(raw_assessments) is not list:
            raise ValueError("deterministic_result_shape_invalid")
        execution_values = cast(list[object], raw_executions)
        assessment_values = cast(list[object], raw_assessments)
        executions = tuple(
            CheckPolicyExecution(
                cast(str, item["policy_id"]),
                cast(str, item["policy_version"]),
                cast(Literal["run", "skipped", "failed"], item["outcome"]),
                cast(
                    Literal[
                        "completed",
                        "material_unavailable",
                        "not_applicable",
                        "policy_failure",
                        "scope_excluded",
                    ],
                    item["reason"],
                ),
            )
            for item in (_mapping(value) for value in execution_values)
            if frozenset(item) == frozenset({"policy_id", "policy_version", "outcome", "reason"})
        )
        if len(executions) != len(execution_values):
            raise ValueError("deterministic_result_execution_invalid")
        findings: list[Finding] = []
        for raw_assessment in assessment_values:
            item = _mapping(raw_assessment)
            if frozenset(item) != frozenset({"finding", "basis"}):
                raise ValueError("deterministic_result_assessment_invalid")
            finding = finding_from_json(freeze_json(item["finding"]))
            basis = finding_basis_from_json(freeze_json(item["basis"]))
            candidate = CandidateFinding(
                finding.kind,
                finding.origin,
                finding.priority,
                finding.summary,
                finding.detail,
                finding.subject_refs,
                finding.policy_id,
                finding.policy_version,
                finding.subject_frontier,
                finding.coverage,
                finding.provenance,
            )
            # A matching contract stamp with drifted text means a wording branch the contract
            # corpus missed. Keep validating the finding and basis, but defer recomputation
            # until every assessment has been checked.
            rendered_text = render_deterministic_finding_text(
                finding.kind,
                finding.subject_refs,
                basis.coverage_gaps,
                basis.observed_facts,
            )
            template_candidate = replace(
                candidate, summary=rendered_text[0], detail=rendered_text[1]
            )
            expected = _freshness_candidate(template_candidate, frozen.case)
            if (finding.summary, finding.detail) != (expected.summary, expected.detail):
                checkpoint_superseded = True
            DeterministicAssessment(template_candidate, basis)
            findings.append(finding)
        if len({item.finding_id for item in findings}) != len(findings):
            raise ValueError("deterministic_result_finding_invalid")
        if checkpoint_superseded:
            raise _DeterministicCheckpointSuperseded()
        return _DurableDeterministicResult(tuple(findings), executions)
    except (PublicOperationError, _DeterministicCheckpointSuperseded):
        raise
    except Exception as exc:
        raise PublicOperationError(
            PublicErrorCode.STORAGE_CORRUPT,
            "The local checkpoint is corrupt.",
            False,
        ) from exc


def _selected_packs(request: CheckRequest) -> tuple[str, ...]:
    selected = _CANONICAL_PACKS if request.policy_packs is None else tuple(request.policy_packs)
    if not selected:
        raise _invalid("check_policy_selection_invalid")
    normalized = tuple(sorted(set(selected), key=str.encode))
    if len(normalized) != len(selected) or any(pack not in _CANONICAL_PACKS for pack in normalized):
        raise _invalid("check_policy_selection_invalid")
    return normalized


def _pack_identity(pack: str) -> tuple[str, str]:
    policy_id, version = pack.split("/", maxsplit=1)
    return policy_id, version


def _pack_roots(case: DeterministicCase, pack: str) -> frozenset[str]:
    if pack == _RESEARCH_PACK:
        collections = (
            case.projection.claims,
            case.projection.results,
            case.projection.evidence,
            case.projection.findings,
        )
    elif pack == _WORK_PACK:
        collections = (
            case.projection.obligations,
            case.projection.claims,
            case.projection.actions,
            case.projection.results,
            case.projection.evidence,
            case.projection.findings,
            case.projection.responses,
        )
    else:
        collections = (
            case.projection.coordination_contexts,
            case.projection.coordination_declarations,
            case.projection.coordination_dispositions,
        )
    roots = frozenset(str(value) for collection in collections for value in collection)
    if pack == _RESEARCH_PACK and case.task_statement is not None:
        # The research-evidence pack owns the statement finding, so a recorded statement is one of
        # its roots: the pack runs (and can resolve that finding) before the first claim exists.
        roots = roots | {str(case.task_statement.source_event_id)}
    return roots


def _scope_execution(
    case: DeterministicCase,
    scope: CheckScope,
    pack: str,
) -> CheckPolicyExecution | None:
    policy_id, version = _pack_identity(pack)
    roots = _pack_roots(case, pack)
    if scope.whole_case:
        if not roots:
            return CheckPolicyExecution(policy_id, version, "skipped", "not_applicable")
        selected = roots
    else:
        selected = roots & scope.roots
        if not selected:
            return CheckPolicyExecution(policy_id, version, "skipped", "scope_excluded")
    available = tuple(case.coverage_by_ref.get(cast(FindingBasisRef, root)) for root in selected)
    if available and all(
        coverage is None or _UNAVAILABLE_GAPS & set(coverage.known_gaps) for coverage in available
    ):
        return CheckPolicyExecution(policy_id, version, "skipped", "material_unavailable")
    return None


def _response_identity(
    assessment: DeterministicAssessment,
    fact_code: str,
) -> tuple[FindingBasisRef, ...] | None:
    """Return the (finding, response event, admissible evidence) refs a response rule reported."""

    for fact in assessment.basis.observed_facts:
        if fact.fact_code == fact_code:
            return fact.subject_refs
    return None


def _collapse_response_overlap(
    assessments: tuple[DeterministicAssessment, ...],
) -> tuple[DeterministicAssessment, ...]:
    """Drop the work-integrity response finding when research-evidence reported the same response.

    A current unsupported rejection or waiver of a local finding satisfies both
    ``weak_or_stale_response`` and ``questionable_finding_rejection``. Each pack is a closed rule
    table that cannot see the other, so the collapse belongs here, where it is known which packs
    actually ran. Keying on the assessment research-evidence really produced -- rather than
    re-deriving its predicate inside work-integrity -- means a research pack that was deselected,
    scope-excluded, skipped as unavailable, or that failed leaves the work-integrity finding
    standing instead of silently losing it.
    """

    rejected = {
        identity
        for item in assessments
        if item.candidate.kind is FindingKind.QUESTIONABLE_FINDING_REJECTION
        and (identity := _response_identity(item, RESEARCH_REJECTION_PRESENT_FACT)) is not None
    }
    if not rejected:
        return assessments
    return tuple(
        item
        for item in assessments
        if item.candidate.kind is not FindingKind.WEAK_OR_STALE_RESPONSE
        or _response_identity(item, WORK_RESPONSE_PRESENT_FACT) not in rejected
    )


def _fact_refs(
    assessment: DeterministicAssessment,
    fact_code: str,
) -> tuple[FindingBasisRef, ...] | None:
    for fact in assessment.basis.required_but_missing_facts + assessment.basis.observed_facts:
        if fact.fact_code == fact_code:
            return fact.subject_refs
    return None


def _collapse_failed_work_overlap(
    assessments: tuple[DeterministicAssessment, ...],
) -> tuple[DeterministicAssessment, ...]:
    """Report one omitted failure once: drop research's copy when work integrity reported it.

    A failed or partial result a completion claim does not disclose satisfies both
    ``failed_work_omitted`` and ``material_limitation_omitted`` for the same claim and result,
    and the same ``limitation_refs`` entry answers both. The packs cannot see each other, so the
    collapse happens here, keyed on the work-integrity assessment that really ran (#909). A
    deselected, skipped, or failed work-integrity pack leaves the research finding standing.
    """

    omitted = {
        refs
        for item in assessments
        if item.candidate.kind is FindingKind.FAILED_WORK_OMITTED
        and (refs := _fact_refs(item, "failure_disclosure_absent")) is not None
    }
    if not omitted:
        return assessments
    return tuple(
        item
        for item in assessments
        if item.candidate.kind is not FindingKind.MATERIAL_LIMITATION_OMITTED
        or _fact_refs(item, "material_limitation_present") not in omitted
    )


def _task_statement_assessments(
    case: DeterministicCase,
    scope: CheckScope,
    workspace_changed: bool | None,
) -> tuple[DeterministicAssessment, ...]:
    """The unmapped-task-statement finding for a whole-case check (TB4 pilot).

    The statement bounds the whole task, so a claim- or obligation-scoped check neither raises nor
    resolves it. Like the test-edit integrity finding it runs in every check mode: the agent must
    decompose the request into statement-sourced obligations before completion can read clean.
    ``workspace_changed`` is the check-time change capture's answer (``None`` when unavailable);
    a no-material-work decision answers the empty-scope form only when it is ``False``.
    """

    if not scope.whole_case:
        return ()
    assessment = build_task_statement_unmapped_assessment(case, workspace_changed=workspace_changed)
    return () if assessment is None else (assessment,)


def _research_pack_completed(executions: tuple[CheckPolicyExecution, ...]) -> bool:
    policy_id, version = _pack_identity(_RESEARCH_PACK)
    return any(
        execution.policy_id == policy_id
        and execution.policy_version == version
        and execution.outcome == "run"
        and execution.reason == "completed"
        for execution in executions
    )


def _requirement_assessments(
    case: DeterministicCase,
    scope: CheckScope,
    executions: tuple[CheckPolicyExecution, ...],
    test_edit_support_refs: tuple[EventId, ...],
    workspace_changed: bool | None = None,
) -> tuple[DeterministicAssessment, ...]:
    """The research-evidence ``task_requirement_unmet`` findings computed beside the pack run.

    Both the unjustified test edit and the undecomposed task statement are recorded under the
    research-evidence pack, and only a check that ran that pack to completion can resolve them.
    Emission follows the same rule (TB4 pilot): a check that did not complete the pack neither
    raises nor resolves them, so a finding is never raised that its own repair cannot clear. A
    recorded statement makes the pack applicable (``_pack_roots``), so ordinary checks still raise
    the statement finding before the first claim.
    """

    if not _research_pack_completed(executions):
        return ()
    output: list[DeterministicAssessment] = []
    if test_edit_support_refs and completion_claim_present(case.projection):
        output.append(
            build_test_edit_integrity_assessment(
                case, test_edit_support_refs, test_edit_support_refs
            )
        )
    output.extend(_task_statement_assessments(case, scope, workspace_changed))
    return tuple(output)


def _with_structural_capture_gaps(
    gaps: tuple[str, ...], capture: CheckChangeMetadata
) -> tuple[str, ...]:
    """Add the structural read's own disclosures to the test-edit accounting gaps.

    A changed path whose name holds a CR or LF was skipped and counted (issue #1019): the read
    stays usable and is marked truncated, and the check names the skip by code only.
    """

    if not capture.unrepresentable_files:
        return gaps
    return tuple(sorted({*gaps, CHECK_TIME_CHANGE_PATH_UNREPRESENTABLE_GAP}, key=str.encode))


class _OutputInputs(NamedTuple):
    """What the check-time read of the declared outputs contributes to one check."""

    evaluator: _PolicyEvaluator
    gaps: tuple[str, ...]
    absent: bool
    # ADR-045: the deliverable states this check records (history for the next check, lineage
    # for every surface). Empty when the check read no declared output file.
    states: tuple[DeliverableState, ...] = ()
    # In process only: the root-relative path of each existing declared output file, so the
    # commit can tell which ones the review packet could not carry.
    files: tuple[tuple[ObligationId, int, str], ...] = ()


def _mark_unreviewable(
    states: tuple[DeliverableState, ...],
    files: tuple[tuple[ObligationId, int, str], ...],
    binary_paths: frozenset[str],
    text_paths: frozenset[str],
) -> tuple[tuple[DeliverableState, ...], bool]:
    """Mark each recorded deliverable state whose file the review packet could not carry.

    Git's NUL sniff of the check-time change decides first (``binary_paths`` / ``text_paths``);
    the suffix decides only for a file the change did not list (ADR-045).
    """

    names = {(obligation, index): relative for obligation, index, relative in files}
    marked: list[DeliverableState] = []
    found = False
    for state in states:
        relative = names.get((state.obligation_id, state.item_index))
        unreviewable = relative is not None and (
            relative in binary_paths
            or (relative not in text_paths and unsupported_data_type(relative))
        )
        found = found or unreviewable
        marked.append(replace(state, unreviewable=True) if unreviewable else state)
    return tuple(marked), found


def _initial_declared_gaps(
    semantic_gap: str | None,
    gap_groups: tuple[Iterable[str], ...],
    semantic_result: FinalSemanticEvaluation,
    states: tuple[DeliverableState, ...],
    files: tuple[tuple[ObligationId, int, str], ...],
) -> tuple[set[str], tuple[DeliverableState, ...]]:
    """The check's declared gap set so far, and the deliverable states to record (ADR-045).

    ``gap_groups`` are the deterministic test-edit and declared-output gaps. A review that ran
    makes a declared deliverable of a type its packet never carries a present but unreviewed one:
    the recorded state says so and the set gains ``declared_output_not_reviewable``.
    """

    gaps: set[str] = set() if semantic_gap is None else {semantic_gap}
    for group in gap_groups:
        gaps.update(group)
    if semantic_result.status is not SemanticStatus.SUCCEEDED:
        return gaps, states
    marked, not_reviewable = _mark_unreviewable(
        states,
        files,
        semantic_result.case_binary_paths,
        semantic_result.case_text_paths,
    )
    if not_reviewable:
        gaps.add(DECLARED_OUTPUT_NOT_REVIEWABLE_GAP)
    return gaps, marked


def _with_fact_lineage(
    result: CheckCommitResult, case: DeterministicCase, records: tuple[LedgerRecord, ...]
) -> CheckCommitResult:
    """*result* with where each derived fact it carries came from (ADR-045)."""

    return replace(
        result,
        fact_lineage=_check_fact_lineage(
            case.projection, records, case.frontier.sequence, result.deliverable_states
        ),
    )


async def _attach_replayed_fact_lineage(
    runtime: TaskRuntime, result: CheckCommitResult
) -> CheckCommitResult:
    """A same-request replay with the lineage its first answer carried.

    The lineage is derived, never stored: the recorded deliverable states plus the task facts
    of the exact ledger prefix the check froze, so a retry reads the same story (ADR-045).
    """

    if result.fact_lineage:
        return result
    try:
        records = tuple(
            [
                record
                async for record in runtime.ledger.load_events(
                    runtime.session_id, through=result.subject_frontier.sequence
                )
            ]
        )
        if not records:
            return result
        lineage = _check_fact_lineage(
            replay(records),
            records,
            result.subject_frontier.sequence,
            result.deliverable_states,
        )
    except Exception as exc:
        record_unexpected_exception_without_raising(
            exc,
            component="check",
            operation="replayed_fact_lineage_read",
            request_id=None,
        )
        return result
    return replace(result, fact_lineage=lineage)


def _route_requires_ai_review(
    policy_semantic: Literal["disabled", "optional", "required"],
    route_profile: Literal["policy", "strict"],
) -> bool:
    """The serving route's own answer under the effective policy (#1143, PR #1167 review).

    ``policy_semantic`` is the policy this check runs with (``_check_review_mode``): an owner's
    local conversation setting or switch already relaxed ``required`` to ``optional``, exactly as
    status computes it (``_semantic_review_required`` and not ``_task_local_by_choice``).
    """

    return route_profile == "policy" and policy_semantic == "required"


async def _read_declared_outputs(
    runtime: TaskRuntime,
    request: CheckRequest,
    frozen: FrozenCase,
    capture: CheckChangeMetadata | None,
    source: CheckWorkspaceSource | None,
    port: object | None,
    policy_semantic: Literal["disabled", "optional", "required"],
    route_profile: Literal["policy", "strict"],
) -> tuple[
    _PolicyEvaluator,
    tuple[str, ...],
    bool,
    tuple[DeliverableState, ...],
    tuple[tuple[ObligationId, int, str], ...],
    tuple[LedgerRecord, ...],
]:
    """Read the declared outputs against their recorded history (ADR-045).

    Returns the work evaluator, the task-fact gaps, whether an output is absent, the deliverable
    states to record, the in-process file names the commit classifies by type, and the frozen
    prefix's records (for the lineage the result carries).

    Freshness is AI-advisory (#1143) only on the AI route, judged at the check's input frontier
    with the predicate status and Stop use (``derive_closure_readiness``): the serving route
    requires AI-powered review (``_route_requires_ai_review``), or the task already used one.
    The requested mode never decides it: no configured reviewer, the strict route, a disabled
    policy or a failed review keep the local rule, and a local-only check on an AI-route task
    stays advisory, so check, status and Stop agree.
    """

    records = await _frozen_prefix_records(runtime, request, frozen)
    outputs = await _requested_output_inputs(
        frozen.case, capture, source, port, request.request_id, deliverable_history(records)
    )
    advisory = _route_requires_ai_review(policy_semantic, route_profile) or semantic_review_used(
        records
    )

    def evaluate(case: DeterministicCase) -> tuple[DeterministicAssessment, ...]:
        return outputs.evaluator(replace(case, verification_advisory=advisory))

    return evaluate, outputs.gaps, outputs.absent, outputs.states, outputs.files, records


async def _frozen_prefix_records(
    runtime: TaskRuntime, request: CheckRequest, frozen: FrozenCase
) -> tuple[LedgerRecord, ...]:
    """The accepted records of the prefix the check froze (ADR-045), or none on a failed read.

    Fails open to no records: the deliverable history then offers no proof of earlier content, so
    the path-history rule cannot fire on a guess, and no ledger-derived lineage is attached.
    """

    try:
        return tuple(
            [
                record
                async for record in runtime.ledger.load_events(
                    runtime.session_id, through=frozen.case.frontier.sequence
                )
            ]
        )
    except Exception as exc:
        record_unexpected_exception_without_raising(
            exc,
            component="check",
            operation="deliverable_history_read",
            request_id=request.request_id,
        )
        return ()


def _check_fact_lineage(
    projection: ProjectionState,
    records: tuple[LedgerRecord, ...],
    subject_frontier: int,
    states: tuple[DeliverableState, ...],
) -> tuple[FactLineage, ...]:
    """Where the derived facts this check carries came from (ADR-045).

    The deliverable facts come from the states the check just recorded; the planned-verification
    and edit-after-verification facts from the ledger over the frozen prefix. The same lineage
    ``current_fact_lineage`` derives later for status, so every surface tells the same story.
    """

    items = list(deliverable_lineage(None, subject_frontier, states))
    if records and len(records) == projection.frontier:
        items.extend(task_fact_signals(projection, records).lineage)
    return tuple(sorted(dict.fromkeys(items), key=lambda item: item.sort_key)[:64])


async def _requested_output_inputs(
    case: DeterministicCase,
    capture: CheckChangeMetadata | None,
    source: CheckWorkspaceSource | None,
    port: object | None,
    request_id: str,
    history: tuple[DeliverableSnapshot, ...] = (),
) -> _OutputInputs:

    from finishup.application.check_change import (
        UndeclaredReferenceRead,
        requested_output_states,
        undeclared_references,
    )

    states = await requested_output_states(
        projection=case.projection,
        capture=capture,
        source=source,
        port=port,
        request_id=request_id,
    )
    confirmed = confirmed_blocked_obligation_ids((gap.code, gap.subject_refs) for gap in case.gaps)
    found, markers = requested_output_facts(case.projection, states, blocked=confirmed)
    codes = {code for code, _obligation in markers}
    observed = observed_event_ids_from_coverage(case.coverage_by_ref)
    assessment = assess_deliverables(
        case.projection,
        states,
        blocked=confirmed,
        history=history,
        verified=passing_verification_observed(
            case.projection, observed, cooperative_event_ids_from_coverage(case.coverage_by_ref)
        ),
    )
    removed = set(assessment.removed)
    if removed:
        # One fact per item: a removed deliverable is not also reported as an absent output.
        codes.add(DECLARED_OUTPUT_REMOVED_GAP)
        found = [item for item in found if item not in removed]
    if assessment.emptied:
        # tb4n2 R2 / tb4n3 RC-5 (ADR-045): a declared file that held content is now empty or
        # truncated, keyed on the path, so its obligation's recorded ``resolved`` no longer
        # counts as delivered (agent work, Stop-gate token). Never raised for a file created
        # empty or one a ``finishup-assumption`` decision names.
        codes.add(DECLARED_OUTPUT_EMPTIED_GAP)
    if content_moved_declared_items(case.projection, states, blocked=confirmed, history=history):
        # A non-blocking disclosure (ADR-035): never a Stop-gate token, never a finding.
        codes.add(DECLARED_OUTPUT_CONTENT_MOVED_GAP)
    read: object = await undeclared_references(
        projection=case.projection,
        capture=capture,
        source=source,
        port=port,
        states=states,
        blocked=confirmed,
        request_id=request_id,
    )
    # A reader that predates the ambiguous count returns the dependency pairs alone.
    reading = (
        read
        if type(read) is UndeclaredReferenceRead
        else UndeclaredReferenceRead(cast(tuple[tuple[str, str], ...], read))
    )
    references = reading.pairs
    if reading.ambiguous:
        # tb4n5 (the #1044 follow-up, ADR-035 amendment): a deliverable names created files only
        # by an ambiguous basename, so they were not treated as dependencies. A standing
        # disclosure with the count on the receipt; never a name, never a Stop-gate token.
        codes.add(DELIVERABLE_REFERENCES_AMBIGUOUS_NAME_GAP)
    if references:
        # tb4n2 R2 / tb4n4 (#1044): a declared deliverable names a file the change created but
        # never declared, so the delivery may not carry what it needs. Agent work and a Stop-gate
        # token (ADR-035 amendment); the referencing deliverable's state names the files.
        codes.add(DELIVERABLE_REFERENCES_UNDECLARED_FILE_GAP)
    # E4 (#989): an absent output is reported only once work on its obligation began.
    absent = reportable_absent_outputs(case, frozenset(found))
    gaps = tuple(sorted(codes, key=str.encode))
    files = tuple(
        (obligation, index, state.relative)
        for (obligation, index), state in sorted(
            states.items(), key=lambda item: (item[0][0].encode(), item[0][1])
        )
        if state.location == "inside"
        and state.exists is True
        and state.relative is not None
        and state.relative != "."
        and any(
            (obligation, index) == (row[0], row[1])
            for row in declared_delivered_items(case.projection, blocked=confirmed)
            if row[2] == "file"
        )
    )
    return _OutputInputs(
        partial(work_integrity_findings, absent_outputs=absent),
        gaps,
        bool(absent),
        _with_undeclared_references(
            assessment.states, files, references, ambiguous=reading.ambiguous
        ),
        files,
    )


def _with_undeclared_references(
    states: tuple[DeliverableState, ...],
    files: tuple[tuple[ObligationId, int, str], ...],
    references: tuple[tuple[str, str], ...],
    *,
    ambiguous: tuple[tuple[str, int], ...] = (),
) -> tuple[DeliverableState, ...]:
    """Each referencing deliverable's state, naming the undeclared files it names (#1044).

    ``references`` are ``(deliverable, referenced file)`` root-relative pairs from the check-time
    read; ``files`` maps each recorded state to its deliverable's root-relative path. At most
    ``MAX_UNDECLARED_REFERENCES`` nameable paths are recorded per state, sorted; when more were
    found (or one cannot be named) the state also records how many. ``ambiguous`` counts, per
    deliverable, the created files it names only by an ambiguous basename (tb4n5): recorded as
    ``undeclared_reference_ambiguous``, never named.
    """

    if not references and not ambiguous:
        return states
    unclear = dict(ambiguous)
    found: dict[str, set[str]] = {}
    for deliverable, referenced in references:
        found.setdefault(deliverable, set()).add(referenced)
    relatives = {(obligation, index): relative for obligation, index, relative in files}
    recorded: list[DeliverableState] = []
    for state in states:
        relative = relatives.get((state.obligation_id, state.item_index))
        named = found.get(relative) if relative is not None else None
        count = unclear.get(relative) if relative is not None else None
        if count:
            state = replace(state, undeclared_reference_ambiguous=count)
        if not named:
            recorded.append(state)
            continue
        shown = tuple(
            sorted(
                (path for path in named if undeclared_reference_path_valid(path)),
                key=lambda path: path.encode("utf-8"),
            )[:MAX_UNDECLARED_REFERENCES]
        )
        recorded.append(
            replace(
                state,
                undeclared_references=shown,
                undeclared_reference_count=len(named) if len(named) > len(shown) else None,
            )
        )
    return tuple(recorded)


def _freshness_candidate(candidate: CandidateFinding, case: DeterministicCase) -> CandidateFinding:
    """Name the affected verification, how its inputs are known, and the later changes (#1143).

    Only a local ledger-stale finding about a run (the rerun question, or a known input change)
    carries this detail. Each verification is identified by its result id and, when it matched
    one, the requested command, so the agent knows what to rerun. Paths are named only where the
    record names them; keyed-only identities are counted, never guessed. The review packet
    carries the name-free form (``kernel.verification_freshness.freshness_detail``).
    """

    if candidate.kind is not FindingKind.LEDGER_STALE_OR_INCOMPLETE:
        return candidate
    rows = freshness_rows_for(case, candidate.subject_refs, candidate.coverage.known_gaps)
    if not rows:
        return candidate
    return replace(
        candidate, detail=candidate.detail + freshness_detail(rows, len(candidate.detail))
    )


def _freshness_candidates(
    assessments: tuple[DeterministicAssessment, ...],
    case: DeterministicCase,
) -> tuple[CandidateFinding, ...]:
    return tuple(_freshness_candidate(item.candidate, case) for item in assessments)


def run_deterministic_policies(
    case: DeterministicCase,
    scope: CheckScope,
    packs: tuple[str, ...],
    *,
    evaluators: dict[str, _PolicyEvaluator] | None = None,
    verification_advisory: bool = False,
) -> tuple[tuple[DeterministicAssessment, ...], tuple[CheckPolicyExecution, ...]]:
    """Run the selected built-ins with application-owned scope and execution accounting."""

    if type(case) is not DeterministicCase or type(scope) is not CheckScope:
        raise _invalid()
    if verification_advisory:
        case = replace(case, verification_advisory=True)
    registered: dict[str, _PolicyEvaluator] = {
        _RESEARCH_PACK: research_evidence_findings,
        _WORK_PACK: work_integrity_findings,
    }
    if evaluators is not None:
        for key, evaluator in evaluators.items():
            registered[key] = evaluator
    executions: list[CheckPolicyExecution] = []
    by_pack: dict[str, tuple[DeterministicAssessment, ...]] = {}
    for pack in packs:
        skip = _scope_execution(case, scope, pack)
        if skip is not None:
            executions.append(skip)
            by_pack[pack] = ()
            continue
        policy_id, version = _pack_identity(pack)
        if pack == _COORDINATION_PACK:
            # Coordination assessments are supplied by the application runtime from the same
            # frozen recipient projection immediately before this function's caller allocates
            # finding IDs.  Keeping the execution row here makes selection/coverage explicit
            # without consulting live catalog state from this pure dispatcher.
            executions.append(CheckPolicyExecution(policy_id, version, "run", "completed"))
            by_pack[pack] = ()
            continue
        try:
            evaluated = registered[pack](case)
            if not scope.whole_case:
                evaluated = tuple(
                    item
                    for item in evaluated
                    if not scope.roots.isdisjoint(map(str, item.candidate.subject_refs))
                )
        except Exception:
            executions.append(CheckPolicyExecution(policy_id, version, "failed", "policy_failure"))
            by_pack[pack] = ()
        else:
            executions.append(CheckPolicyExecution(policy_id, version, "run", "completed"))
            by_pack[pack] = evaluated

    # Finding emission order is intentionally distinct from execution accounting order.
    assessments = _collapse_failed_work_overlap(
        _collapse_response_overlap(by_pack.get(_WORK_PACK, ()) + by_pack.get(_RESEARCH_PACK, ()))
    )
    keys = tuple(
        (item.candidate.policy_id, item.basis.rule_id, item.candidate.subject_refs)
        for item in assessments
    )
    if len(keys) != len(set(keys)):
        raise _invalid("duplicate_deterministic_assessment")
    return assessments, tuple(executions)


type _SupersededCoordinationRetirer = Callable[..., object]


def _superseded_coordination_retirer(
    app: Application, packs: tuple[str, ...]
) -> _SupersededCoordinationRetirer | None:
    """Return the composed superseded-context reconciler when this check runs coordination."""

    if _COORDINATION_PACK not in packs:
        return None
    project_application = getattr(app, "project_application", None)
    coordinator = getattr(project_application, "coordination_runtime", None)
    retire = getattr(coordinator, "retire_superseded_contexts", None)
    return retire if callable(retire) else None


async def _retire_superseded_coordination(
    retire: _SupersededCoordinationRetirer,
    runtime: TaskRuntime,
    request_id: str,
) -> None:
    """Record superseded-generation closures before a new check freezes its case (#842).

    A project generation change fences coordination authority immediately, but a context and
    declaration already in this task's ledger would keep deriving an actionable finding that no
    disposition can address.  The coordination runtime appends a service-stamped ``revoked``
    context for each such declared delivery.  That append is observation-authored, so the check
    tolerates it after the caller's frontier and freezes it into the case it evaluates.

    This is a secondary reconciliation of an already fenced state.  A failure leaves the ledger
    unchanged, so the check proceeds with the prior frozen facts and the next check retries.
    """

    try:
        # The check's own lease reads the task projection; only a needed closure opens the
        # observation writer route.
        pending = retire(runtime.task_id, runtime=runtime)
        if inspect.isawaitable(pending):
            await pending
    except Exception as exc:
        record_unexpected_exception_without_raising(
            exc,
            component="check",
            operation="coordination_supersession_reconcile",
            request_id=request_id,
        )


async def _coordination_assessments_for_frozen_case(
    app: Application,
    runtime: TaskRuntime,
    case: DeterministicCase,
    scope: CheckScope,
    packs: tuple[str, ...],
) -> tuple[DeterministicAssessment, ...]:
    """Ask the composed coordination runtime to assess only frozen recipient facts."""

    if _COORDINATION_PACK not in packs:
        return ()
    project_application = getattr(app, "project_application", None)
    coordinator = getattr(project_application, "coordination_runtime", None)
    assess = getattr(coordinator, "assessments_for_check", None)
    if not callable(assess):
        return ()
    pending = assess(
        runtime.task_id,
        case,
        scope_roots=scope.roots,
        whole_case=scope.whole_case,
    )
    if not inspect.isawaitable(pending):
        raise _invalid("coordination_assessment_invalid")
    result = await cast(Awaitable[object], pending)
    values = cast(tuple[object, ...], result)
    if type(result) is not tuple or any(
        type(item) is not DeterministicAssessment for item in values
    ):
        raise _invalid("coordination_assessment_invalid")
    return cast(tuple[DeterministicAssessment, ...], result)


FindingIdentity = tuple[FindingKind, str, tuple[EventId | ObligationId | ClaimId, ...]]


def prior_finding_ids(projection: ProjectionState) -> dict[FindingIdentity, FindingId]:
    """Index the live recorded findings by the identity a policy re-derives them under.

    A finding a later qualifying check already resolved is history, not a live row: an issue that
    fires again after that proof is a successor and takes a fresh ID, so the resolved row keeps
    its proof and the new row starts unresolved (issue #458).

    Only local rows are offered: local candidates are the only ones allocated against this map.
    An AI-powered finding with the same kind, policy and subject is a different issue; letting a
    local re-derivation take its ID would rewrite that row's origin and leave the real local row
    unreturned, and so look resolved (issue #884).

    A ``self_verified`` row (issue #984) is not offered either: the agent answered it because FinishUP
    could not prove the repair. If the rule fires again, FinishUP positively sees the issue, so the
    re-derivation is a new finding the agent must answer instead of landing silently on the
    terminal row.
    """

    prior: dict[FindingIdentity, FindingId] = {}
    for key, record in projection.findings.items():
        if (
            record.payload is None
            or record.proof_event_id is not None
            or record.payload.origin is not FindingOrigin.DETERMINISTIC
            or finding_todo_state(projection, key) is FindingTodoState.SELF_VERIFIED
        ):
            continue
        prior[(record.payload.kind, record.payload.policy_id, record.payload.subject_refs)] = key
    return prior


def allocate_findings(
    ids: IdPort,
    candidates: tuple[CandidateFinding, ...],
    prior: Mapping[FindingIdentity, FindingId] | None = None,
) -> tuple[Finding, ...]:
    """Allocate stable IDs in deterministic candidate order.

    A candidate that re-derives a live recorded finding keeps that finding's ID, so a re-check
    converges on the record already answered instead of minting an unresolvable duplicate.
    """

    output: list[Finding] = []
    for candidate in candidates:
        if type(candidate) is not CandidateFinding:
            raise _invalid("finding_candidate_invalid")
        existing = (
            None
            if prior is None
            else prior.get((candidate.kind, candidate.policy_id, candidate.subject_refs))
        )
        output.append(
            Finding(
                existing if existing is not None else finding_id(ids.new(IdKind.FINDING)),
                candidate.kind,
                candidate.origin,
                candidate.priority,
                candidate.summary,
                candidate.detail,
                candidate.subject_refs,
                candidate.policy_id,
                candidate.policy_version,
                candidate.subject_frontier,
                candidate.coverage,
                candidate.provenance,
                candidate.challenge,
                candidate.related_finding_ids,
            )
        )
    return tuple(output)


async def _publish_deterministic_result(
    app: Application,
    runtime: TaskRuntime,
    request: CheckRequest,
    frozen: FrozenCase,
    assessments: tuple[DeterministicAssessment, ...],
    findings: tuple[Finding, ...],
    executions: tuple[CheckPolicyExecution, ...],
    request_digest_value: str,
) -> FrozenCase:
    """Pin local finding identities and bases before optional AI-powered work."""

    if frozen.lease.phase is not CheckPhase.RESERVED:
        raise PublicOperationError(
            PublicErrorCode.OPERATION_PENDING,
            "The check operation is pending.",
            True,
        )
    if len(assessments) != len(findings):
        raise PublicOperationError(
            PublicErrorCode.STORAGE_CORRUPT,
            "The local result is inconsistent.",
            False,
        )
    operation = await runtime.ledger.lookup_operation(request.writer_id, request.request_id)
    if (
        type(operation) is not OperationRecord
        or operation.state is not OperationState.PENDING
        or operation.phase is not CheckPhase.RESERVED
        or operation.request_digest != request_digest_value
        or operation.resume_object_ref is None
        or operation.resume_object_ref.metadata.kind is not ObjectKind.CHECK_RESUME
    ):
        raise PublicOperationError(
            PublicErrorCode.STORAGE_CORRUPT,
            "The check resume checkpoint is inconsistent.",
            False,
        )
    prior_resume = operation.resume_object_ref
    canonical = canonical_encode(
        cast(
            JsonValue,
            {
                "schema_version": "1.0.0",
                "request_id": request.request_id,
                "request_digest": request_digest_value,
                "task_id": runtime.task_id,
                "session_id": runtime.session_id,
                "writer_id": runtime.writer_id,
                "subject_frontier": dict(frozen.case.frontier.as_wire().items()),
                "dependency_digest": frozen.lease.dependency_digest,
                "text_contract_digest": DETERMINISTIC_TEXT_CONTRACT_DIGEST,
                "prior_resume": _object_pointer(prior_resume),
                "policy_executions": tuple(
                    {
                        "policy_id": item.policy_id,
                        "policy_version": item.policy_version,
                        "outcome": item.outcome,
                        "reason": item.reason,
                    }
                    for item in executions
                ),
                "assessments": tuple(
                    {
                        "finding": finding_to_json(finding),
                        "basis": finding_basis_to_json(assessment.basis),
                    }
                    for assessment, finding in zip(assessments, findings, strict=True)
                ),
            },
        )
    )
    metadata = ObjectMetadata(
        ObjectKind.DETERMINISTIC_RESULT,
        "application/vnd.yoetz.deterministic-result+json",
        runtime.task_id,
        app.clock.now_utc(),
    )
    if len(canonical) > MAX_OBJECT_PLAINTEXT_BYTES:
        raise PublicOperationError(
            PublicErrorCode.LIMIT_EXCEEDED,
            "The local check result checkpoint exceeds its capacity. Retain this task and "
            "report the limitation; unchanged check retries cannot reduce it.",
            False,
            safe_details={
                "reason_code": "check_result_capacity_exceeded",
                "count": len(canonical),
                "limit": MAX_OBJECT_PLAINTEXT_BYTES,
            },
        )
    staged = await runtime.objects.stage(
        ObjectSource(data=canonical, declared_size=len(canonical)),
        metadata,
    )
    result_ref = await runtime.objects.finalize(staged)
    lease = await runtime.ledger.advance_check_phase(
        frozen.lease,
        CheckPhase.RESERVED,
        CheckPhase.LOCAL_READY,
        result_ref,
    )
    return FrozenCase(frozen.case, lease)


def _policy_identity(kind: FindingKind) -> tuple[str, str]:
    return finding_policy_identity(kind)


@dataclass(frozen=True, slots=True)
class _ResolvedChallengeRefs:
    subject_refs: tuple[str, ...]
    # The cited earlier (recorded) findings: the ``relates_to`` link the new finding records.
    related_finding_ids: tuple[FindingId, ...]


def _resolve_challenge_refs(
    case: DeterministicCase,
    deterministic: tuple[Finding, ...],
    challenge: ReviewerChallenge,
) -> _ResolvedChallengeRefs | None:
    """Resolve one challenge's citations to frozen subject refs, or ``None`` if any is outside."""

    return _resolve_cited_refs(case, deterministic, challenge.cited_refs)


def _resolve_cited_refs(
    case: DeterministicCase,
    deterministic: tuple[Finding, ...],
    cited_refs: tuple[str, ...],
) -> _ResolvedChallengeRefs | None:
    """Resolve reviewer citations to frozen subject refs, or ``None`` if any is outside.

    Every per-ref test below is byte-identical to the fence this replaced; only the disposition of
    a failure changed, from raising (which discarded the entire judgment, and with it the check)
    to returning ``None`` so the caller can drop this one challenge and count it.

    A cited ``fnd_`` resolves to that finding's subjects. It is either one of this check's local
    findings or a recorded finding the frozen case carries: ``citable_refs`` offers every recorded
    finding id, and the prompt asks the reviewer to name the earlier finding a re-raise concerns,
    so a challenge that does exactly that must not be dropped as outside the case (issue #905).
    Cited recorded findings are kept as the new finding's ``relates_to`` link.
    """

    findings = {str(item.finding_id): item for item in deterministic}
    resolved: set[str] = set()
    related: set[str] = set()
    for ref in cited_refs:
        if ref.startswith("fnd_"):
            local = findings.get(ref)
            subjects = (
                tuple(map(str, local.subject_refs))
                if local is not None
                else _recorded_finding_subjects(case, ref)
            )
            if subjects is None:
                return None
            resolved.update(subjects)
            if finding_id(ref) in case.projection.findings:
                # Only an already-recorded finding is linked: a fresh local finding of this check
                # may still be ranked away and never recorded, and a link must never dangle.
                related.add(ref)
        elif ref not in case.allowed_ids:
            return None
        elif ref.startswith(("evt_", "obl_", "clm_")):
            resolved.add(ref)
        else:
            source = None
            if ref.startswith("act_"):
                from finishup.domain.values import action_id

                record = case.projection.actions.get(action_id(ref))
                source = None if record is None else str(record.source_event_id)
            elif ref.startswith("res_"):
                from finishup.domain.values import result_id

                record = case.projection.results.get(result_id(ref))
                source = None if record is None else str(record.source_event_id)
            elif ref.startswith("evd_"):
                from finishup.domain.values import evidence_id

                record = case.projection.evidence.get(evidence_id(ref))
                source = None if record is None else str(record.source_event_id)
            if source is None:
                return None
            resolved.add(source)
    if not resolved:
        return None
    return _ResolvedChallengeRefs(
        tuple(sorted(resolved, key=str.encode)),
        tuple(finding_id(ref) for ref in sorted(related, key=str.encode)),
    )


def _packet_text_for_refs(
    refs: tuple[str, ...],
    provider_input_text_by_ref: Mapping[str, tuple[str, ...]] | None,
) -> tuple[str, ...]:
    """Return text from the exact provider-bound rows supporting *refs*.

    A source ref alone proves only that a ledger row exists. Snippet admission needs the exact
    post-selection, post-privacy text the provider received; when that ephemeral view is absent,
    no quote can be proved from the frozen case alone.
    """

    if provider_input_text_by_ref is None:
        return ()
    return tuple(text for ref in refs for text in provider_input_text_by_ref.get(ref, ()))


@dataclass(frozen=True, slots=True)
class _ReviewerQuoteFence:
    """What the provider-bound fence kept of one judgment, and what it removed (issue #976)."""

    judgment: SemanticJudgment
    # Challenges no cited ref of which is proven sent. They mint no finding; their text is
    # surfaced as an advisory concern and their drop is counted and disclosed.
    not_carried: tuple[ReviewerChallenge, ...] = ()
    # Challenges whose citations were all outside the advertised citable set.
    outside: int = 0
    # Kept challenges that lost citations of unsent refs, plus verified rows dropped for one.
    refs_reduced: int = 0
    # Unproven quotes removed from kept challenges plus verified rows dropped for their quote.
    snippet_losses: int = 0


def _validate_reviewer_snippets(
    judgment: SemanticJudgment,
    *,
    citable_refs: frozenset[str] | None,
    provider_input_text_by_ref: Mapping[str, tuple[str, ...]] | None,
) -> _ReviewerQuoteFence:
    """Fence reviewer citations and quotes to what the provider was actually sent.

    ``citable_refs`` is the set the packet advertised (not yet narrowed to the text index). A ref
    is proven sent when the provider-bound text index carries text for it: a content row's source
    or linked subject, or one of this check's local findings whose assessment row survived.

    A challenge is a concern the reviewer raised; it is never discarded because one of its
    citations or its quote cannot be proved (TB4 tb4v1, issue #976):

    * Cited refs that were not sent are removed; the challenge stands on the refs that were sent,
      and the reduction is disclosed.
    * A challenge with no sent ref (or any quote-bearing challenge when the text index is
      unavailable, so nothing is proven sent) mints no finding, but its text is surfaced to the
      agent as an advisory concern and its drop is counted under its own reason.
    * A quote is kept only as the exact sent span it matches (``review_quotes.prove_quote``); an
      unproven quote is removed, never shown, and disclosed through the snippet gap.

    A verified row reads as support, so it keeps the stricter rule: it is dropped when any cited
    ref was not sent or its required quote cannot be proved.
    """

    from finishup.application.review_quotes import prove_quote

    # A recovered response from before the exact provider-bound text index existed has no proof
    # for a newly added quote. Keep legacy judgments without snippets readable.
    if (
        provider_input_text_by_ref is None
        and not any(challenge.snippet is not None for challenge in judgment.challenges)
        and not any(item.snippet is not None for item in judgment.verified)
    ):
        return _ReviewerQuoteFence(judgment)

    # Without the text index nothing is proven sent.
    sent = frozenset(() if provider_input_text_by_ref is None else provider_input_text_by_ref)
    carried = sent if citable_refs is None else citable_refs & sent

    not_carried: list[ReviewerChallenge] = []
    outside = 0
    refs_reduced = 0
    snippet_losses = 0
    challenges: list[ReviewerChallenge] = []
    for challenge in judgment.challenges:
        kept_refs = tuple(ref for ref in challenge.cited_refs if ref in carried)
        if not kept_refs:
            if citable_refs is not None and not any(
                ref in citable_refs for ref in challenge.cited_refs
            ):
                outside += 1
            else:
                not_carried.append(challenge)
            continue
        if len(kept_refs) != len(challenge.cited_refs):
            refs_reduced += 1
            challenge = replace(challenge, cited_refs=kept_refs)
        if challenge.snippet is not None:
            proven = prove_quote(
                challenge.snippet, _packet_text_for_refs(kept_refs, provider_input_text_by_ref)
            )
            if proven is None:
                # The quote is removed, never shown as one, and its loss is disclosed.
                snippet_losses += 1
                challenge = replace(challenge, snippet=None)
            elif proven != challenge.snippet:
                # Record the verbatim sent span, never the reviewer's spelling of it.
                challenge = replace(challenge, snippet=proven)
        challenges.append(challenge)

    verified: list[VerifiedReviewItem] = []
    for item in judgment.verified:
        if any(ref not in carried for ref in item.cited_refs):
            refs_reduced += 1
            continue
        if item.snippet is not None:
            proven = prove_quote(
                item.snippet, _packet_text_for_refs(item.cited_refs, provider_input_text_by_ref)
            )
            if proven is None:
                snippet_losses += 1
                continue
            if proven != item.snippet:
                item = replace(item, snippet=proven)
        verified.append(item)

    # #1162 tracked advice: the strongest remaining check keeps its sent citations like a
    # challenge; one left with none is removed (no identity on unsent material) and disclosed.
    remaining = judgment.strongest_remaining_check
    if remaining is not None:
        kept_remaining = tuple(ref for ref in remaining.cited_refs if ref in carried)
        if len(kept_remaining) != len(remaining.cited_refs):
            refs_reduced += 1
            remaining = replace(remaining, cited_refs=kept_remaining) if kept_remaining else None

    if (
        not not_carried
        and outside == 0
        and refs_reduced == 0
        and snippet_losses == 0
        and tuple(challenges) == judgment.challenges
        and tuple(verified) == judgment.verified
    ):
        return _ReviewerQuoteFence(judgment)
    if judgment.conclusion == "challenges_returned" and not challenges:
        # The domain coupling requires at least one challenge for that conclusion. The check keeps
        # the provider's original conclusion separately; the dropped concerns are counted, and an
        # unanchored concern is surfaced as advisory text by the caller.
        fenced = replace(
            judgment,
            conclusion="no_material_discrepancy",
            challenges=(),
            verified=tuple(verified),
            strongest_remaining_check=remaining,
        )
    else:
        fenced = replace(
            judgment,
            challenges=tuple(challenges),
            verified=tuple(verified),
            strongest_remaining_check=remaining,
        )
    return _ReviewerQuoteFence(fenced, tuple(not_carried), outside, refs_reduced, snippet_losses)


_UNANCHORED_CONCERNS_HEADER: Final = (
    "Reviewer concerns not recorded as findings (no record they cite was in the sent packet; "
    "advisory and unverified, answer them in your next published work):"
)
# #1118 unit 4 (AIM-1): the reviewer's own reason for each residual request.
# The least of the reviewer's own summary kept when residual requests overflow the bound.
_RESIDUAL_SUMMARY_FLOOR_BYTES: Final = 256
_RESIDUAL_REQUESTS_HEADER: Final = (
    "What the reviewer still needs (its own words; advisory and unverified. Non-blocking. For"
    " each material concern: run a proportionate check, cite evidence that already settles it,"
    " or decline with a reason; supply only material that exists, or state the limit in the"
    " receipt):"
)
# Issue #1042: a routine review judges incomplete work; its correctness concerns are notes.
_ADVISORY_NOTES_HEADER: Final = (
    "Reviewer correctness notes (advisory and non-blocking: a review during work in progress "
    "judges incomplete work only, so these are not findings. For each material concern: run a "
    "proportionate check, cite evidence that already settles it, or decline with a reason; "
    "recording a response is optional):"
)
# Issue #1162: a note whose bounded advisory row could not be retained (never expected once its
# subjects are fence-resolved) degrades to this summary instead of discarding the review.
_ADVISORY_ROWS_NOT_RETAINED_NOTE: Final = (
    "FinishUP note: {count} reviewer correctness note(s) above are kept in this summary only; "
    "they have no advisory identity, so the receipt does not count them and respond cannot "
    "target them."
)
# Issue #1043: fixed words and a count only; the findings carry the reviewer's own text.
_AGENT_CRITERIA_NOTE: Final = (
    "FinishUP recorded {count} requirement challenge(s) as your own criterion "
    "(agent_criterion_unmet), not the task's: the only work they cite is your own runs beyond "
    "the task's declared verification, which holds. Fix it, or narrow the criterion by "
    "responding acknowledged with the reason (a disclosed limitation that does not block)."
)


_RE_RAISED_HEADER: Final = (
    "Reviewer re-raised earlier findings (recorded on that finding, which stays open; answer it "
    "there):"
)
# tb4n3 RC-7: a re-raise of a finding the agent already settled (acknowledged_not_done,
# self_verified or a disclosed limitation) is recorded on it. No new finding exists and respond
# refuses most answers on it, so the header must not say "answer it there".
_SETTLED_HEADER: Final = (
    "Reviewer repeated findings you already settled, citing nothing newer (recorded on that "
    "finding as a standing re-raise; no new finding was opened and no answer is needed. To take "
    "an acknowledged_not_done answer back and do the work, respond reopened with a reason; never "
    "empty or withdraw a working deliverable over it):"
)
# Issue #1020: a repeat over the agent's reasoned rejection with nothing newer.
_DISPUTED_HEADER: Final = (
    "Reviewer repeated findings you rejected with a reason, citing nothing newer (recorded as "
    "disputed_after_rebuttal: final and disclosed on the receipt; no answer is needed, and never "
    "withdraw working deliverables over them):"
)


def _bounded_review_text(text: str, limit: int = MAX_REVIEW_TEXT_BYTES) -> str:
    encoded = text.encode("utf-8")
    if len(encoded) <= limit:
        return text
    marker = " [truncated]"
    budget = max(0, limit - len(marker.encode("utf-8")))
    return encoded[:budget].decode("utf-8", errors="ignore") + marker


def _summary_with_re_raised(
    summary: str,
    re_raised: tuple[tuple[FindingId, ReviewerChallenge], ...],
    disputed: frozenset[FindingId] = frozenset(),
    settled: frozenset[FindingId] = frozenset(),
) -> str:
    """Append the reviewer's words on each restated finding to the review summary (issue #980).

    A challenge that names the earlier finding it restates is recorded on that finding as a
    ruling, so no new finding carries its text; the summary does, under a header naming the item.
    A repeat recorded as ``disputed_after_rebuttal`` (issue #1020) is final and needs no answer,
    so it goes under its own header that says so instead of asking for one. So does a repeat of a
    finding the agent already settled (``acknowledged_not_done``, ``self_verified`` or a disclosed
    limitation; tb4n3 RC-7): ``respond`` refuses most answers on it, so it never says "answer it
    there".
    """

    if not re_raised:
        return summary
    lines = [summary]
    final_items = [item for item in re_raised if item[0] in disputed]
    settled_items = [item for item in re_raised if item[0] in settled and item[0] not in disputed]
    open_items = [item for item in re_raised if item[0] not in disputed and item[0] not in settled]
    for header, items in (
        (_RE_RAISED_HEADER, open_items),
        (_SETTLED_HEADER, settled_items),
        (_DISPUTED_HEADER, final_items),
    ):
        if items:
            lines.extend(("", header))
            for restated, challenge in items:
                lines.append(f"- {restated}: {challenge.summary} {challenge.message_to_main_agent}")
    return _bounded_review_text("\n".join(lines))


# How a challenge's ``restates`` target is treated (issue #980, TB4 tb4n1 D5).
_RESTATES_OPEN: Final = "open"  # a carried, open AI-powered finding: rulable
_RESTATES_SETTLED: Final = "settled"  # a carried finding the agent settled: nameable only
_RESTATES_LINKED: Final = "linked"  # any other readable recorded finding: linked, never folded


def _restates_target(
    case: DeterministicCase,
    challenge: ReviewerChallenge,
    prior_finding_refs: frozenset[str] | None,
    settled_finding_refs: frozenset[str] | None,
) -> tuple[str, FindingId] | None:
    """Classify the earlier finding a challenge's ``restates`` names (issue #980).

    ``open``: one of the packet's rulable prior findings (``prior_finding_refs``, when the
    composing evaluator reported the packet), readable, unresolved and open. ``settled``: a
    readable AI-powered finding the agent answered ``acknowledged_not_done`` (or
    ``self_verified``) that the packet carried as a nameable, non-rulable row
    (``settled_finding_refs``). ``linked``: any other readable finding inside the frozen fence (a
    resolved or final item, or one the packet did not carry): done stays done, so the challenge
    is minted as a new item that relates to it. ``None``: no target, or one outside the fence;
    the challenge stands on its own and nothing is counted, because a citation of an earlier
    finding is not a ref the challenge rests on.
    """

    target = challenge.restates
    if target is None or target not in case.allowed_ids:
        return None
    key = finding_id(target)
    record = case.projection.findings.get(key)
    if record is None or record.payload is None or record.redacted:
        return None
    semantic = record.payload.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED
    unresolved = not finding_is_resolved(case.projection, key)
    state = finding_todo_state(case.projection, key)
    # tb4n3 RC-1: a limitation request the agent disclosed is settled, so a re-raise of it is
    # recorded on it exactly like a re-raise of an acknowledged_not_done answer.
    settled_answer = _latest_response_value(case, key) in AGENT_SETTLED_DISPOSITION_VALUES or (
        _limitation_disclosed(case, key)
    )
    if (
        semantic
        and unresolved
        and state is FindingTodoState.OPEN
        and (prior_finding_refs is None or target in prior_finding_refs)
        and not settled_answer
    ):
        return _RESTATES_OPEN, key
    if (
        semantic
        and unresolved
        and settled_answer
        and (settled_finding_refs is None or target in settled_finding_refs)
    ):
        return _RESTATES_SETTLED, key
    return _RESTATES_LINKED, key


def _limitation_disclosed(case: DeterministicCase, key: FindingId) -> bool:
    """Whether *key* is a reviewer limitation request the agent already disclosed (Q4)."""

    standing = limitation_standing(case.projection, key)
    return standing is not None and standing.disclosed


def _latest_response_value(case: DeterministicCase, key: FindingId) -> str | None:
    response = case.projection.responses.get(key)
    if response is None or response.payload is None or response.redacted:
        return None
    return response.payload.disposition.value


def _summary_with_unanchored_concerns(summary: str, concerns: tuple[ReviewerChallenge, ...]) -> str:
    """Append concerns that could not be anchored to the review summary, within its byte bound.

    The reviewer's words travel only inside the fenced review-summary field, never as a finding;
    the header says they are unverified. Text that does not fit is cut at a character boundary
    and marked, so a clipped concern is never presented as whole.
    """

    return _summary_with_concerns(summary, _UNANCHORED_CONCERNS_HEADER, concerns)


def _summary_with_residual_requests(
    summary: str, judgment: SemanticJudgment, shown: frozenset[str]
) -> str:
    """Append what the reviewer still needs, in its own words, to the fenced summary (AIM-1).

    #1118 unit 4: the closed ``missing_for_assessment`` item says only a kind and its targets, so
    two different needs read alike. The reviewer's bounded reason travels here, inside the
    advisory review-summary field the privacy projection already governs, never in a structural
    record, a log or ``agent_next``. Targets the sent packet did not hold are left out, as the
    check fence leaves them out of the item; an item with none left is not repeated.
    """

    lines: list[str] = []
    for entry in judgment.missing_for_assessment:
        refs = tuple(ref for ref in entry.target_refs if ref in shown)
        if entry.target_refs and not refs:
            continue
        target = ", ".join(refs) if refs else "no named target"
        lines.append(f"{len(lines) + 1}. {entry.kind} ({target}): {entry.reason}")
    if not lines:
        return summary
    text = "\n".join((summary, "", _RESIDUAL_REQUESTS_HEADER, *lines))
    if len(text.encode("utf-8")) <= MAX_REVIEW_TEXT_BYTES:
        return text
    # Over the bound: the summary is clipped first (down to a floor) so every kept request keeps
    # its own words; only then does each line get an equal share, clipped and marked.
    fixed = len(f"\n\n{_RESIDUAL_REQUESTS_HEADER}".encode()) + len(lines)
    floor = min(len(summary.encode("utf-8")), _RESIDUAL_SUMMARY_FLOOR_BYTES)
    remaining = MAX_REVIEW_TEXT_BYTES - fixed - floor
    kept: dict[int, str] = {}
    for count, index in enumerate(sorted(range(len(lines)), key=lambda i: len(lines[i].encode()))):
        kept[index] = _bounded_review_text(lines[index], remaining // (len(lines) - count))
        remaining -= len(kept[index].encode("utf-8"))
    body = [kept[index] for index in range(len(lines))]
    room = MAX_REVIEW_TEXT_BYTES - fixed - sum(len(line.encode("utf-8")) for line in body)
    return "\n".join((_bounded_review_text(summary, room), "", _RESIDUAL_REQUESTS_HEADER, *body))


def _summary_with_agent_criteria(summary: str, count: int) -> str:
    """Say, in fixed words and a count, which requirement challenges became the agent's own
    criterion (issue #1043), so the reviewer's "requirement" wording is never read as the task's."""

    if count == 0:
        return summary
    return _bounded_review_text("\n".join((summary, "", _AGENT_CRITERIA_NOTE.format(count=count))))


def _summary_with_concerns(
    summary: str, header: str, concerns: tuple[ReviewerChallenge, ...]
) -> str:
    """Append reviewer concerns under a fixed FinishUP header, within the summary's byte bound."""

    if not concerns:
        return summary
    lines = [summary, "", header]
    for position, concern in enumerate(concerns, start=1):
        lines.append(f"{position}. {concern.summary} {concern.message_to_main_agent}")
    text = "\n".join(lines)
    encoded = text.encode("utf-8")
    if len(encoded) <= MAX_REVIEW_TEXT_BYTES:
        return text
    marker = " [truncated]"
    budget = MAX_REVIEW_TEXT_BYTES - len(marker.encode("utf-8"))
    return encoded[:budget].decode("utf-8", errors="ignore") + marker


# A finding names at most 64 subjects. Several cited findings can union past that; such a
# challenge is dropped and counted rather than failing the whole check on the finding bound.
_MAX_CHALLENGE_SUBJECT_REFS: Final = 64


def _recorded_finding_subjects(case: DeterministicCase, ref: str) -> tuple[str, ...] | None:
    """The subjects of a readable recorded finding inside the frozen case, else ``None``.

    The finding id and each of its subjects must be inside the frozen fence, exactly as a
    directly cited subject would have to be; an unreadable (redacted) finding proves nothing.
    """

    if ref not in case.allowed_ids:
        return None
    record = case.projection.findings.get(finding_id(ref))
    if record is None or record.payload is None:
        return None
    subjects = tuple(str(item) for item in record.payload.subject_refs)
    if any(item not in case.allowed_ids for item in subjects):
        return None
    return subjects


def _claims_unchanged_over_hidden_source(
    case: DeterministicCase,
    challenge: ReviewerChallenge,
) -> bool:
    """Whether this challenge asserts nothing changed while its own basis was withheld."""

    return any(
        "unchanged" in text.casefold()
        for text in (challenge.discrepancy, challenge.alternative_interpretation)
    ) and any(
        _UNAVAILABLE_GAPS & set(case.coverage_by_ref[cast(FindingBasisRef, ref)].known_gaps)
        for ref in challenge.cited_refs
        if ref in case.coverage_by_ref
    )


def _ruling_material(
    projection: ProjectionState, ref: str
) -> EvidenceProjectionRecord | ProjectionRecord[ResultRecordedPayload] | None:
    """The evidence or result a ruling cites, by its own id or by the event that recorded it."""

    if ref.startswith("evd_"):
        return projection.evidence.get(evidence_id(ref))
    if ref.startswith("res_"):
        return projection.results.get(result_id(ref))
    if ref.startswith("evt_"):
        for evidence_row in projection.evidence.values():
            if str(evidence_row.source_event_id) == ref:
                return evidence_row
        for result_row in projection.results.values():
            if str(result_row.source_event_id) == ref:
                return result_row
    return None


def _ruling_supported(
    kind: str,
    cited: tuple[str, ...],
    finding_frontier: int,
    finding: FindingId,
    projection: ProjectionState,
) -> bool:
    """Whether the refs a ruling kept can carry what that ruling claims.

    A ``fixed`` ruling needs readable evidence or a result recorded after the finding. The packet
    offers both by the event that recorded them as well as by their own id, and reviewers cite the
    event (tb4n5: 0 ``res_`` citations in 41 reviews; kv ``fnd_c96c2b9f`` was ruled supported on
    ``evt_3318a99d``, the repair result's event), so an ``evt_`` resolves to the evidence or result
    it recorded before the frontier test. An ``evt_`` that recorded anything else (an action, a
    claim, a response) never supports ``fixed``.
    """

    if kind == "fixed":
        for ref in cited:
            row = _ruling_material(projection, ref)
            if (
                row is not None
                and row.payload is not None
                and not row.redacted
                and row.source_frontier > finding_frontier
            ):
                return True
        return False
    if kind in {"still_present", "answered_not_fixed"}:
        return bool(cited)
    if kind == "withdrawn":
        # tb4n3 RC-7: the reviewer accepts a rejection that still stands, even when a later
        # acknowledgement was recorded after it; ``reopened`` retracts it.
        return rejection_stands(projection.findings.get(finding), projection.responses.get(finding))
    return True


# The reviewer rulings that keep an answered finding open (issue #1020).
_HELD_OPEN_RULINGS: Final = frozenset({"still_present", "answered_not_fixed", "unassessable"})
# The rulings that say the concern remains, the only ones ruling admission records as a standing
# disagreement over the agent's position (tb4n5 follow-up of #1046). ``unassessable`` keeps the
# item open but disagrees with nothing: the reviewer could not judge it, so it stays an open round.
# A restatement of the concern is a re-raise and keeps its own dispute rule
# (``_record_restatement``).
_DISAGREEING_RULINGS: Final = frozenset({"still_present", "answered_not_fixed"})


def _finding_concern(case: DeterministicCase, key: FindingId) -> ConcernKey:
    """The concern identity of a recorded finding's subjects (tb4n3 RC-7)."""

    record = case.projection.findings.get(key)
    subjects = () if record is None or record.payload is None else record.payload.subject_refs
    return concern_key(case.projection, (str(ref) for ref in subjects))


def _cites_concern_material_after(
    case: DeterministicCase,
    finding: FindingId,
    refs: Iterable[str],
    frontier: int,
    *,
    also: ConcernKey | None = None,
) -> bool:
    """Whether *refs* hold concern-relevant material recorded after *frontier* (tb4n3 RC-7).

    Only evidence, results and actions linked to the concern count (``review_concern``): never a
    finding, claim, obligation, response, decision or other bookkeeping, and never the agent's
    own acknowledgement evidence. The earlier ``_cites_material_after`` counted any newer ref,
    including another finding's response event and the latest test run every agent re-runs.
    """

    concern = _finding_concern(case, finding)
    if also is not None:
        concern = ConcernKey(
            concern.obligations | also.obligations,
            concern.refs | also.refs,
            concern.named_obligations or also.named_obligations,
        )
    return concern_material_after(case, concern, refs, frontier)


def _disputed_after_rebuttal(
    case: DeterministicCase, finding: FindingId, ruling: str, cited: Iterable[str]
) -> bool:
    """Whether a ruling keeping *finding* open repeats it over the agent's position (#1020, #1030).

    True when the agent holds a standing reasoned position on the finding (a ``rejected``, or an
    ``acknowledged`` with a reason: the earliest one not retracted, ``standing_answer_frontier``)
    and the ruling (``still_present``, ``answered_not_fixed`` or ``unassessable``) cites no
    concern-relevant material recorded after the later of that position and the reviewer's last
    ruling. The prompt already asks the reviewer to cite newer material before raising an answered
    finding again; this enforces it in code, so a repeated demand can never turn into pressure on
    the agent (TB4 tb4n2 formal-crypto: three repeats, then a working deliverable was emptied).
    Reading only the latest answer made it unreachable: agents answer ``acknowledged`` (21 of 23
    answers in tb4n3), and a later acknowledgement erased an earlier rebuttal.
    """

    if ruling not in _HELD_OPEN_RULINGS:
        return False
    bound = answer_bound(case.projection, finding)
    return bound is not None and not _cites_concern_material_after(case, finding, cited, bound)


def _admit_prior_verdicts(
    case: DeterministicCase,
    judgment: SemanticJudgment,
    *,
    prior_finding_refs: frozenset[str] | None,
    citable_refs: frozenset[str] | None,
) -> tuple[dict[str, PriorFindingVerdictRecord], int, int]:
    """Fence the reviewer's per-finding rulings (issue #905).

    Returns the admitted rulings, the count of unsupported ones (malformed, unknown or outside
    the fence, unshown, trimmed, reduced or repeated; disclosed as
    ``semantic_prior_verdicts_unsupported``), and the count set aside because their target is
    already final (``verified_resolved``, ``acknowledged_not_done``, ``rejection_accepted``,
    ``self_verified``).
    A final item is never re-reviewed, so a ruling on it says nothing about the review's other
    findings and must not raise the gap that blocks every unruled open finding; it is only
    counted as a diagnostic.

    A ruling is kept only for a readable, unresolved AI-powered finding inside the frozen fence;
    one on such a finding the packet's prior-findings section did not carry
    (``prior_finding_refs``, when the composing evaluator reported the packet) is kept as
    ``unassessable``. Its cited refs are trimmed to what the packet offered
    as citable. What a ruling may claim is bounded by what it still cites: ``fixed`` must cite
    evidence or a result recorded after the finding (a hallucinated ``fixed`` must not close a
    real defect), ``still_present`` and ``answered_not_fixed`` must cite something, and
    ``withdrawn`` answers only a readable ``rejected`` response. A ruling that loses any cited ref
    or fails its claim is kept as ``unassessable`` for that finding alone, so a bad ruling can
    never leave its finding to close by silence; two different rulings on one finding become
    ``unassessable``. Every dropped, trimmed, reduced or repeated ruling is counted.

    Issue #1020 (ADR-040): a shown finding the agent rejected with a reason that the reviewer
    keeps open (``still_present``, ``answered_not_fixed`` or ``unassessable``) without citing
    anything recorded after that rejection is recorded as ``disputed_after_rebuttal``
    (``_disputed_after_rebuttal``): a final, non-blocking standing disagreement, never a new
    review round. Material newer than the rejection keeps the ruling as the reviewer gave it.
    """

    admitted: dict[str, PriorFindingVerdictRecord] = {}
    unsupported = judgment.prior_finding_verdicts_dropped
    set_aside = 0
    projection = case.projection
    for verdict in judgment.prior_finding_verdicts:
        key = verdict.finding_id
        record = projection.findings.get(finding_id(key))
        if (
            key not in case.allowed_ids
            or record is None
            or record.payload is None
            or record.redacted
        ):
            unsupported += 1
            continue
        if record.payload.origin is not FindingOrigin.SEMANTIC_MODEL_DERIVED:
            # A local finding's answer is carried as non-rulable context (issue #976); a ruling
            # on it says nothing about the review's own findings and is only counted.
            set_aside += 1
            continue
        if (
            finding_is_resolved(projection, record.payload.finding_id)
            or (
                finding_todo_state(projection, record.payload.finding_id)
                is not FindingTodoState.OPEN
                # Issue #996: a linked duplicate only inherits a final state; the reviewer can
                # still rule on it, and a still_present ruling breaks the link.
                and duplicate_link_target(projection, record.payload.finding_id) is None
            )
            # tb4n3 RC-1: a disclosed limitation request is settled; the reviewer accepting the
            # disclosure (``withdrawn``) or repeating itself says nothing about the review's
            # other findings, so it is only counted, like a ruling on any final item.
            or _limitation_disclosed(case, record.payload.finding_id)
        ):
            # A terminal item is never re-reviewed, so no ruling on it is admitted.
            set_aside += 1
            continue
        cited = tuple(
            ref
            for ref in verdict.cited_refs
            if ref in case.allowed_ids and (citable_refs is None or ref in citable_refs)
        )
        kind: str = verdict.verdict
        # A readable open finding the packet did not carry (past the section's row cap, or
        # dropped by envelope bounding) was not shown to the reviewer: its ruling cannot stand,
        # but an explicit ruling must not fall back to silence either, so it is unassessable.
        shown = prior_finding_refs is None or key in prior_finding_refs
        lost_cite = len(cited) != len(verdict.cited_refs)
        supported = _ruling_supported(
            kind, cited, record.source_frontier, record.payload.finding_id, projection
        )
        if (
            shown
            and kind in _DISAGREEING_RULINGS
            and _disputed_after_rebuttal(case, record.payload.finding_id, kind, cited)
        ):
            # Issue #1020 (ADR-040): the reviewer saw the agent's reasoned position and kept the
            # item open without citing anything newer. Recorded as a standing disagreement.
            unsupported += lost_cite
            kind = DISPUTED_AFTER_REBUTTAL_VERDICT
        elif not shown or not supported or (lost_cite and kind not in {"withdrawn", "fixed"}):
            unsupported += 1
            if (
                shown
                and kind in _DISAGREEING_RULINGS
                and _disputed_after_rebuttal(case, record.payload.finding_id, "unassessable", cited)
            ):
                # tb4n3 RC-7 (D-6): a ruling that keeps the item open, cannot stand over a standing
                # position and cites nothing newer is the standing disagreement, not an open
                # review round.
                kind = DISPUTED_AFTER_REBUTTAL_VERDICT
            else:
                # tb4n5 follow-up of #1046: an unsupported ``fixed`` (the reviewer says the issue
                # is gone), a ``withdrawn`` with no rejection to accept, or an honest
                # ``unassessable`` is never a reviewer disagreement; it is unassessable, an open
                # round the next review can rule on (kv ``fnd_c96c2b9f`` latched as a dispute).
                kind = "unassessable"
        elif lost_cite and kind == "fixed":
            # A trimmed citation is disclosed, but a ``fixed`` the remaining cites still support
            # (it keeps one recorded newer result) stays ``fixed`` (D-6). ``withdrawn`` needs no
            # citation at all; ``still_present`` and ``answered_not_fixed`` that lose a citation
            # are ``unassessable`` as before.
            unsupported += 1
        earlier = admitted.get(key)
        if earlier is not None:
            unsupported += 1
            if earlier.verdict != kind:
                admitted[key] = PriorFindingVerdictRecord(finding_id(key), "unassessable", ())
            continue
        admitted[key] = PriorFindingVerdictRecord(finding_id(key), kind, cited)
    return admitted, unsupported, set_aside


def semantic_capture_baseline_gaps(result: FinalSemanticEvaluation) -> frozenset[str]:
    """The closed native capture limits a completed review ran under (issues #884, #904).

    These are the same codes the commit path adds to check coverage from the semantic case,
    including the reduced reference scope of a bounded review packet. Only this closed set becomes
    a finding's baseline; every other packet limitation, such as a truncated payload, stays
    check-only and keeps blocking semantic absence proof.
    """

    gaps = set(result.case_content_gaps) & SEMANTIC_FINDING_CAPTURE_BASELINE_GAPS
    if result.case_content_over_item_limit:
        gaps.add(SEMANTIC_CASE_CONTENT_OVER_ITEM_LIMIT_GAP)
    if result.case_reference_scope_reduced:
        gaps.add(SEMANTIC_REFERENCE_SCOPE_REDUCED_GAP)
    return frozenset(gaps)


def semantic_included_refs(result: FinalSemanticEvaluation) -> tuple[str, ...] | None:
    """The check record of what a completed reduced review's sent packet carried (issue #904).

    Only a completed review that reached a conclusion and ran over a reduced reference scope
    records them: the frontier references whose own content item survived envelope bounding and
    privacy minimization. An unreadable, empty or oversized set records none; the check then
    carries ``semantic_included_refs_not_recorded`` and no AI-powered finding resolves through it.
    """

    refs = result.case_included_refs
    if (
        refs is None
        or not result.case_reference_scope_reduced
        or result.status is not SemanticStatus.SUCCEEDED
        or result.judgment is None
        or not 1 <= len(refs) <= MAX_SEMANTIC_INCLUDED_REFS
    ):
        return None
    return tuple(sorted(refs, key=str.encode))


def validate_semantic_judgment(
    case: DeterministicCase,
    deterministic: tuple[Finding, ...],
    judgment: SemanticJudgment,
    provenance: SemanticProvenance,
    *,
    expected_frontier: Frontier,
    capture_baseline_gaps: frozenset[str] = frozenset(),
    prior_finding_refs: frozenset[str] | None = None,
    citable_refs: frozenset[str] | None = None,
    provider_input_text_by_ref: Mapping[str, tuple[str, ...]] | None = None,
    settled_finding_refs: frozenset[str] | None = None,
    review_phase: Literal["routine", "final"] | None = None,
    agent_linked_runs: frozenset[EventId] | None = frozenset(),
    prior_advisories: tuple[CorrectnessAdvisory, ...] = (),
) -> SemanticJudgmentReview:
    """Fence AI-powered challenges to the exact frozen refs, coverage, and final provenance.

    ``prior_advisories`` are the task's advisory rows in the frozen prefix (#1162 tracked
    advice): a verified row or strongest remaining check that repeats one of them with no newer
    concern material is folded onto it and disclosed, never given a second identity.

    ``review_phase`` is the phase the packet's question set named (``select_semantic_budget_profile``).
    A routine review judges incomplete work only (issue #1042): a ``code_defect`` it returns is a
    correctness concern, recorded as an advisory note in the review summary rather than a finding,
    and a "never attempted" challenge is work in progress (ADR-040 section 5). ``None`` (a caller
    that did not say) keeps the earlier rules: the "never attempted" drop reads the completion
    claim alone and nothing is recorded as an advisory note.

    ``agent_linked_runs`` are the observed command actions the agent linked to a requested command
    (PL6-3, ``task_facts.agent_linked_run_events`` over the frozen prefix): the declared
    verification, never the agent's own probe (``agent_probe_only``). ``None`` means the prefix
    could not be read, and then no requirement challenge is recorded as the agent's own criterion.

    ``prior_finding_refs`` and ``citable_refs`` describe the packet the reviewer was actually
    shown (its prior-findings rows and its ``citable_refs``); per-finding rulings are fenced to
    them (issue #905). ``settled_finding_refs`` are the findings the agent settled that the packet
    carried as nameable, non-rulable rows: a challenge's ``restates`` may name them (issue #980). ``None`` means the composing evaluator did not report the packet, and the
    frozen fence bounds them instead.

    ``capture_baseline_gaps`` are the closed native capture limits under which this review ran
    (issue #884). They are stamped onto every accepted challenge's coverage, so each semantic
    finding durably records the capture baseline it was raised under; a later review can compare
    against that baseline instead of an under-reported deterministic-only one.

    Each challenge is fenced independently against the same frozen case. A challenge that fails is
    dropped and counted by reason; the challenges beside it are unaffected, because nothing about
    one reviewer challenge is evidence about another. No fence is loosened here — the accept test
    for a single challenge is unchanged.

    The structural checks below stay hard failures: a wrong type, a drifted frontier, or a
    provenance that is not the final SUCCEEDED attempt means the *coordinator* handed this function
    the wrong inputs, not that the reviewer answered badly. They raise
    :class:`SemanticJudgmentRejected`, which the commit path converts into an honest
    ``invalid``/``semantic_judgment_rejected`` AI-powered review outcome rather than losing the check.
    """

    if (
        type(case) is not DeterministicCase
        or type(judgment) is not SemanticJudgment
        or type(provenance) is not SemanticProvenance
        or expected_frontier != case.frontier
        or provenance.status is not SemanticStatus.SUCCEEDED
        or provenance.reason is not SemanticReason.SEMANTIC_COMPLETED
    ):
        raise _rejected("semantic_judgment_invalid")
    # The advertised set, before it is narrowed to the text index for rulings below: challenge
    # citations are fenced against it together with what was actually sent (issue #976).
    advertised_refs = citable_refs
    if provider_input_text_by_ref is not None:
        # The composed case can advertise refs whose rows were later withheld by privacy or
        # minimization. Once the exact provider-bound text index is available, prior rulings and
        # missing-input requests use that narrower fence too; otherwise a ``fixed`` ruling could
        # cite a result the provider never saw and close a finding on unreviewed material.
        provider_refs = frozenset(provider_input_text_by_ref)
        if citable_refs is not None:
            citable_refs &= provider_refs
        if prior_finding_refs is not None:
            prior_finding_refs &= provider_refs
        if settled_finding_refs is not None:
            settled_finding_refs &= provider_refs
    returned_challenges = len(judgment.challenges)
    fence = _validate_reviewer_snippets(
        judgment,
        citable_refs=advertised_refs,
        provider_input_text_by_ref=provider_input_text_by_ref,
    )
    judgment = fence.judgment
    # Every dropped quote is disclosed through the snippet gap (including verified rows the
    # normalizer already dropped as inconsistent with their verdict); only dropped challenges
    # count toward the returned == accepted + rejected + suppressed challenge accounting.
    snippets_rejected = fence.snippet_losses + judgment.verified_dropped
    review_summary = _summary_with_unanchored_concerns(judgment.review_summary, fence.not_carried)
    rejections: dict[str, int] = {}
    if fence.not_carried:
        rejections[SEMANTIC_REJECTED_REF_NOT_CARRIED] = len(fence.not_carried)
    if fence.outside:
        rejections[SEMANTIC_REJECTED_REF_OUTSIDE_CASE] = fence.outside
    admitted, verdicts_unsupported, verdicts_set_aside = _admit_prior_verdicts(
        case, judgment, prior_finding_refs=prior_finding_refs, citable_refs=citable_refs
    )
    if judgment.conclusion == "insufficient_packet":
        review_summary = _summary_with_residual_requests(
            review_summary,
            judgment,
            citable_refs if citable_refs is not None else frozenset(map(str, case.allowed_ids)),
        )
    if judgment.conclusion != "challenges_returned":
        tracked_rows, review_summary = _with_tracked_advice(
            case,
            deterministic,
            judgment,
            review_summary,
            room=MAX_ADVISORIES_PER_CHECK,
            prior=prior_advisories,
        )
        return _judgment_review(
            (),
            returned_challenges,
            tuple(sorted(rejections.items(), key=lambda item: item[0].encode("ascii"))),
            _sorted_verdicts(admitted),
            verdicts_unsupported,
            verdicts_set_aside=verdicts_set_aside,
            review_summary=review_summary,
            verified=judgment.verified,
            snippets_rejected=snippets_rejected,
            refs_reduced=fence.refs_reduced,
            correctness_advisories=tracked_rows,
        )
    coverage = case_coverage(case, semantic=True)
    if not capture_baseline_gaps <= SEMANTIC_FINDING_CAPTURE_BASELINE_GAPS:
        raise _rejected("semantic_judgment_invalid")
    stamped = capture_baseline_gaps - set(coverage.known_gaps)
    if stamped:
        # Mirror exactly how the check folds the same gaps into its own coverage below.
        coverage = replace(
            coverage,
            ledger_freshness=(
                LedgerFreshness.PARTIAL
                if coverage.ledger_freshness is LedgerFreshness.CURRENT
                else coverage.ledger_freshness
            ),
            known_gaps=tuple(sorted(set(coverage.known_gaps) | stamped, key=str.encode)),
        )
    candidates: list[CandidateFinding] = []
    restatements = 0
    re_raised: list[tuple[FindingId, ReviewerChallenge]] = []
    advisory: list[tuple[ReviewerChallenge, tuple[str, ...]]] = []
    agent_criteria = 0
    work_claimed = completion_claim_present(case.projection)
    # Issue #1042: the phase the packet named decides; without it, the completion claim alone does
    # (ADR-040 section 5 as first written).
    routine = (not work_claimed) if review_phase is None else review_phase == "routine"
    observed = observed_event_ids_from_coverage(case.coverage_by_ref)
    case_gap_codes = frozenset(gap.code for gap in case.gaps)
    blocked = confirmed_blocked_obligation_ids((gap.code, gap.subject_refs) for gap in case.gaps)
    verification_runs: frozenset[str] | None = None
    for challenge in judgment.challenges:
        resolution = _resolve_challenge_refs(case, deterministic, challenge)
        if resolution is None:
            rejections[SEMANTIC_REJECTED_REF_OUTSIDE_CASE] = (
                rejections.get(SEMANTIC_REJECTED_REF_OUTSIDE_CASE, 0) + 1
            )
            continue
        refs = resolution.subject_refs
        if challenge.finding_kind is FindingKind.STALE_EVIDENCE_FOR_CHANGED_STATE:
            if verification_runs is None:
                verification_runs = _verification_run_events(case, agent_linked_runs)
            if verification_runs.intersection(refs):
                # #1143: a concern that a recorded verification run predates later changes asks
                # for a rerun decision, never a repair gate. The reviewer's own summary stays in
                # the detail; any other stale-evidence concern keeps its kind and text.
                challenge = _verification_rerun_challenge(challenge)
        if challenge.finding_kind is FindingKind.DECISION_NEEDED:
            # #1146: a choice can never become a repair directive, even if the model asks for act.
            challenge = replace(challenge, requested_next_step="answer_question")
        if len(refs) > _MAX_CHALLENGE_SUBJECT_REFS:
            rejections[SEMANTIC_REJECTED_SUBJECTS_OVER_LIMIT] = (
                rejections.get(SEMANTIC_REJECTED_SUBJECTS_OVER_LIMIT, 0) + 1
            )
            continue
        if _claims_unchanged_over_hidden_source(case, challenge):
            rejections[SEMANTIC_REJECTED_HIDDEN_SOURCE_CLAIM] = (
                rejections.get(SEMANTIC_REJECTED_HIDDEN_SOURCE_CLAIM, 0) + 1
            )
            continue
        if finishup_process_state_only(case.projection, challenge.finding_kind, refs, observed):
            # Issue #1042: the challenge is about FinishUP's own capture or process state (the hook
            # pairing an observed call with its result, a FinishUP tool call), never the agent's
            # work. Counted and disclosed, never minted.
            rejections[SEMANTIC_REJECTED_FINISHUP_PROCESS_STATE] = (
                rejections.get(SEMANTIC_REJECTED_FINISHUP_PROCESS_STATE, 0) + 1
            )
            continue
        if local_rule_owned(case.projection, challenge.finding_kind, refs):
            # tb4n5 follow-up of #1042: the action/result relation is the local rule's, decided over
            # the whole ledger; the reviewer's copy duplicated or misplaced it and latched
            # ``disputed_after_rebuttal`` while the local twin resolved. Counted and disclosed,
            # never minted. Every other kind about the same action is still reviewed.
            rejections[SEMANTIC_REJECTED_LOCAL_RULE_OWNED] = (
                rejections.get(SEMANTIC_REJECTED_LOCAL_RULE_OWNED, 0) + 1
            )
            continue
        if routine and challenge.finding_kind is FindingKind.REQUESTED_ITEM_NEVER_ATTEMPTED:
            # Issue #1020 (tb4n2 P1-7): during work in progress nothing is "never attempted" yet.
            # Issue #1042: "in progress" is the routine phase the packet named, so the closing
            # review keeps it even without a completion claim. Counted and disclosed, never minted.
            rejections[SEMANTIC_REJECTED_ROUTINE_COMPLETENESS] = (
                rejections.get(SEMANTIC_REJECTED_ROUTINE_COMPLETENESS, 0) + 1
            )
            continue
        if agent_probe_only(
            case.projection,
            challenge.finding_kind,
            refs,
            observed=observed,
            case_gap_codes=case_gap_codes,
            blocked=blocked,
            linked=agent_linked_runs,
        ):
            # Issue #1043: the only cited work is the agent's own runs beyond the task's declared
            # verification, which holds. The concern is the agent's own criterion, never the
            # task's: it may fix it or narrow it with a reason (a disclosed, non-blocking limit).
            challenge = replace(challenge, finding_kind=FindingKind.AGENT_CRITERION_UNMET)
            rerouted = True
        else:
            rerouted = False
        target = _restates_target(case, challenge, prior_finding_refs, settled_finding_refs)
        named: FindingId | None = None
        linked: FindingId | None = None
        if target is not None:
            treatment, target_id = target
            target_kind = _finding_kind_of(case, target_id)
            # tb4n3 RC-7: the requirement-family kinds name one concern across kinds (a limitation
            # request raised as ``task_requirement_unmet`` after ``completion_with_open_obligations``
            # is the same concern); every other kind folds only onto its own.
            # An open item folds only the same kind; a settled one (the agent's final word, or a
            # disclosed limitation) also folds a comparable kind, because the re-raise cannot
            # change what the agent settled. Folding a different kind into an open item would
            # hide a requirement demand behind a bookkeeping finding (cargo S).
            same_kind = target_kind is not None and (
                target_kind is challenge.finding_kind
                or (
                    treatment == _RESTATES_SETTLED
                    and kinds_comparable(
                        target_kind,
                        challenge.finding_kind,
                        obligation_concern=(
                            _finding_concern(case, target_id).named_obligations
                            and concern_key(case.projection, refs).named_obligations
                        ),
                    )
                )
            )
            if treatment == _RESTATES_OPEN and same_kind:
                named = target_id
            elif treatment == _RESTATES_SETTLED and same_kind:
                # The reviewer raised again a concern the agent settled (issue #980, D7): the
                # re-raise is recorded on that item as a standing dispute, never a new finding,
                # so the give-up cannot loop into fresh ids.
                if _record_settled_reraise(admitted, target_id, refs):
                    restatements += 1
                    re_raised.append((target_id, challenge))
                    continue
                linked = target_id
            elif (
                same_kind
                and finding_todo_state(case.projection, target_id)
                is FindingTodoState.DISPUTED_AFTER_REBUTTAL
                and not _cites_concern_material_after(
                    case,
                    target_id,
                    (*refs, *challenge.cited_refs),
                    answer_bound(case.projection, target_id) or 0,
                )
            ):
                # Issue #1020: the reviewer named a standing disagreement again with nothing
                # recorded after the agent's rebuttal. Folded and disclosed, never a new finding.
                restatements += 1
                re_raised.append((target_id, challenge))
                continue
            else:
                # A different concern about the named item, or an item that is done or was not
                # carried: a new finding that relates to it, never folded into it, and never a
                # ruling on the named item (the reviewer's own ruling on it stands).
                linked = target_id
        restated = (
            named
            if named is not None
            else None
            if target is not None and target[0] != _RESTATES_LINKED
            else _restated_finding(
                case,
                challenge.finding_kind,
                refs,
                replies_to=resolution.related_finding_ids,
                cited=challenge.cited_refs,
            )
        )
        if restated is not None:
            suppressed, reduced = _record_restatement(
                case,
                admitted,
                restated,
                refs,
                verdict=(
                    "answered_not_fixed"
                    if named is not None and _answered(case.projection, restated)
                    else "still_present"
                ),
                cited=challenge.cited_refs,
            )
            # A ruling the same review's restatement contradicts is recorded as unassessable on
            # that item; it is not an unsupported ruling about the review's other findings.
            verdicts_set_aside += reduced
            if suppressed:
                # Seen again, suppressed (issue #905): the recorded item already carries this
                # problem and its state; a second row would only restart it. Disclosed on the
                # check, and recorded on the open item so it can never close by silence.
                restatements += 1
                # The reviewer's renewed words reach the agent in the review summary, named by
                # the item they were recorded on (issue #980). tb4n3 RC-7: also when the reviewer
                # did not name it (``restates`` is optional), so a fold never hides the repeat.
                re_raised.append((named if named is not None else restated, challenge))
                continue
        if (
            review_phase == "routine"
            and challenge.finding_kind is FindingKind.CODE_DEFECT
            and named is None
        ):
            # Issue #1042: a routine review judges incomplete work only. Its correctness concern is
            # recorded as an advisory, non-blocking note in the review summary, not a finding. A
            # re-raise of a recorded finding was folded onto that finding above, unchanged.
            # #1162: the retained row keeps the fence-resolved subjects (an ``act_``/``res_``/
            # ``evd_`` citation resolves to its source event), never the raw citations.
            advisory.append((challenge, refs))
            continue
        agent_criteria += rerouted
        policy_id, policy_version = _policy_identity(challenge.finding_kind)
        priority, _actionable = FINDING_KIND_TRAITS[challenge.finding_kind]
        candidates.append(
            CandidateFinding(
                challenge.finding_kind,
                FindingOrigin.SEMANTIC_MODEL_DERIVED,
                priority,
                challenge.summary,
                challenge.message_to_main_agent,
                tuple(
                    event_id(ref)
                    if ref.startswith("evt_")
                    else obligation_id(ref)
                    if ref.startswith("obl_")
                    else claim_id(ref)
                    for ref in refs
                ),
                policy_id,
                policy_version,
                case.frontier,
                coverage,
                provenance,
                # Persisted so a later review and the agent see what would settle the finding,
                # not only its headline (issue #905).
                FindingChallenge(
                    discrepancy=challenge.discrepancy,
                    alternative_interpretation=challenge.alternative_interpretation,
                    requested_next_step=challenge.requested_next_step,
                    uncertainty=challenge.uncertainty,
                    snippet=challenge.snippet,
                ),
                (
                    tuple(
                        sorted(
                            {
                                *resolution.related_finding_ids,
                                *(ref for ref in (named, linked) if ref is not None),
                            },
                            key=str.encode,
                        )
                    )
                    if named is not None or linked is not None
                    else resolution.related_finding_ids
                ),
            )
        )
    # A ruling of ``fixed`` on a finding an admitted challenge of the same review re-raises
    # contradicts itself: neither half proves the issue gone.
    contested = {str(ref) for candidate in candidates for ref in candidate.related_finding_ids}
    for key in sorted(contested & set(admitted), key=str.encode):
        if admitted[key].verdict == "fixed":
            admitted[key] = PriorFindingVerdictRecord(finding_id(key), "unassessable", ())
            verdicts_unsupported += 1
    advisory_rows = _correctness_advisory_rows(tuple(advisory))
    advisory_summary = _summary_with_concerns(
        review_summary, _ADVISORY_NOTES_HEADER, tuple(item for item, _refs in advisory)
    )
    if len(advisory_rows) < len(advisory):
        advisory_summary = _bounded_review_text(
            "\n".join(
                (
                    advisory_summary,
                    "",
                    _ADVISORY_ROWS_NOT_RETAINED_NOTE.format(
                        count=len(advisory) - len(advisory_rows)
                    ),
                )
            )
        )
    tracked_rows, advisory_summary = _with_tracked_advice(
        case,
        deterministic,
        judgment,
        advisory_summary,
        room=MAX_ADVISORIES_PER_CHECK - len(advisory_rows),
        prior=prior_advisories,
        # #1211 counter-example notes and this review's findings already carry an identity: a
        # tracked candidate about the same concern is not raised twice.
        same_review=(
            *(refs for _challenge, refs in advisory),
            *(tuple(map(str, candidate.subject_refs)) for candidate in candidates),
        ),
    )
    return _judgment_review(
        tuple(candidates),
        returned_challenges,
        tuple(sorted(rejections.items(), key=lambda item: item[0].encode("ascii"))),
        _sorted_verdicts(admitted),
        verdicts_unsupported,
        restatements,
        verdicts_set_aside,
        _summary_with_re_raised(
            _summary_with_agent_criteria(advisory_summary, agent_criteria),
            tuple(re_raised),
            frozenset(
                restated
                for restated, _challenge in re_raised
                if (
                    (ruling := admitted.get(str(restated))) is not None
                    and ruling.verdict == DISPUTED_AFTER_REBUTTAL_VERDICT
                )
                or finding_todo_state(case.projection, restated)
                is FindingTodoState.DISPUTED_AFTER_REBUTTAL
            ),
            frozenset(
                restated
                for restated, _challenge in re_raised
                if finding_todo_state(case.projection, restated)
                in {FindingTodoState.ACKNOWLEDGED_NOT_DONE, FindingTodoState.SELF_VERIFIED}
                or _limitation_disclosed(case, restated)
            ),
        ),
        judgment.verified,
        snippets_rejected,
        fence.refs_reduced,
        advisory_notes=len(advisory),
        correctness_advisories=(*advisory_rows, *tracked_rows),
        agent_criteria=agent_criteria,
    )


def _correctness_advisory_rows(
    advisory: tuple[tuple[ReviewerChallenge, tuple[str, ...]], ...],
) -> tuple[JsonObject, ...]:
    """The retained advisory rows (#1162), each admitted on its own.

    A row that does not fit the bounded record is left out instead of failing the review: the
    note is still in the review summary, the caller discloses that it was not retained, and every
    other challenge of the same review is kept.
    """

    rows: list[JsonObject] = []
    for challenge, refs in advisory:
        if len(rows) >= MAX_ADVISORIES_PER_CHECK:
            break
        row = JsonObject(
            {
                "summary": _bounded_review_text(challenge.summary),
                "detail": _bounded_review_text(challenge.message_to_main_agent),
                "subject_refs": tuple(sorted(set(refs), key=str.encode)),
            }
        )
        try:
            validate_advisories((row,))
        except ValueError:
            continue
        rows.append(row)
    return tuple(rows)


# #1162 tracked advice: fixed FinishUP words and identities only; the rows carry reviewer text.
_TRACKED_ADVICE_FOLDED_NOTE: Final = (
    "FinishUP note: {count} reviewer item(s) repeat tracked advice with no newer material and "
    "were not raised again: {ids}."
)
_TRACKED_ADVICE_SAME_REVIEW_NOTE: Final = (
    "FinishUP note: {count} reviewer item(s) repeat a correctness note or finding of this review "
    "and were not raised twice."
)
_TRACKED_ADVICE_NO_ROOM_NOTE: Final = (
    "FinishUP note: {count} reviewer item(s) had no room for an advisory identity on this check "
    "(at most ten); they remain in this review's verified rows or summary only."
)


def _tracked_advice_bound(row: CorrectnessAdvisory) -> int:
    """The frontier newer material must beat for one tracked row: its answer, else its review."""

    if row.response is not None:
        return row.response.ledger.ingestion_sequence
    payload = row.check.payload
    assert isinstance(payload, CheckRecordedPayload)
    return payload.subject_frontier.sequence


def _with_tracked_advice(
    case: DeterministicCase,
    deterministic: tuple[Finding, ...],
    judgment: SemanticJudgment,
    review_summary: str,
    *,
    room: int,
    prior: tuple[CorrectnessAdvisory, ...],
    same_review: tuple[tuple[str, ...], ...] = (),
) -> tuple[tuple[JsonObject, ...], str]:
    """Tracked advice rows (#1162) for a fenced judgment, and the summary with their notes.

    A verified row marked ``not_supported`` or ``not_assessable`` whose fence-resolved subjects
    name an obligation or claim, and the reviewer's single strongest remaining check, each become
    an advisory row (non-blocking; answered once through ``respond``). One that repeats an
    earlier tracked row of the same family about the same concern, citing no concern material
    newer than that row's answer (or, unanswered, its review), is folded onto it: the answer
    stands and no second identity is minted. The fold and any overflow are disclosed in fixed words.
    """

    candidates: list[tuple[str, str, tuple[str, ...]]] = []
    remaining = judgment.strongest_remaining_check
    if remaining is not None:
        candidates.append(("strongest_remaining_check", remaining.check, remaining.cited_refs))
    for verdict in ("not_supported", "not_assessable"):
        candidates.extend(
            (f"verified_{verdict}", item.requirement_or_claim, item.cited_refs)
            for item in judgment.verified
            if item.verdict == verdict
        )
    rows: list[JsonObject] = []
    folded: list[str] = []
    folded_items = 0
    overflow = 0
    repeated_here = 0
    review_concerns = tuple(concern_key(case.projection, refs) for refs in same_review)
    for origin, text, cited in candidates:
        resolution = _resolve_cited_refs(case, deterministic, cited)
        if resolution is None:
            continue
        subjects = resolution.subject_refs
        if origin != "strongest_remaining_check" and not any(
            ref.startswith(("obl_", "clm_")) for ref in subjects
        ):
            # A verified row about an event alone stays a plain verified row.
            continue
        family = TRACKED_ADVICE_FAMILIES[origin]
        wanted = concern_key(case.projection, subjects)
        if any(same_concern(wanted, concern) for concern in review_concerns):
            # A correctness note (with its #1211 counter-example) or a finding of this same
            # review already names the concern with an identity.
            repeated_here += 1
            continue
        earlier = next(
            (
                row
                for row in prior
                if TRACKED_ADVICE_FAMILIES.get(str(row.concern.get("origin", ""))) == family
                and same_concern(
                    wanted,
                    concern_key(
                        case.projection,
                        (str(ref) for ref in cast(tuple[str, ...], row.concern["subject_refs"])),
                    ),
                )
                and not concern_material_after(
                    case, wanted, (*cited, *subjects), _tracked_advice_bound(row)
                )
            ),
            None,
        )
        if earlier is not None:
            folded_items += 1
            if earlier.advisory_id not in folded:
                folded.append(earlier.advisory_id)
            continue
        if len(rows) >= room:
            overflow += 1
            continue
        bounded = _bounded_review_text(text)
        row = JsonObject(
            {
                "summary": bounded,
                "detail": bounded,
                "subject_refs": subjects,
                "origin": origin,
            }
        )
        try:
            validate_advisories((row,))
        except ValueError:
            overflow += 1
            continue
        rows.append(row)
    notes: list[str] = []
    if folded:
        notes.append(_TRACKED_ADVICE_FOLDED_NOTE.format(count=folded_items, ids=", ".join(folded)))
    if repeated_here:
        notes.append(_TRACKED_ADVICE_SAME_REVIEW_NOTE.format(count=repeated_here))
    if overflow:
        notes.append(_TRACKED_ADVICE_NO_ROOM_NOTE.format(count=overflow))
    if notes:
        review_summary = _bounded_review_text("\n".join((review_summary, "", *notes)))
    return tuple(rows), review_summary


_VERIFICATION_RERUN_SUMMARY: Final = "Is a verification rerun needed after these changes?"


def _verification_run_events(
    case: DeterministicCase, agent_linked: frozenset[EventId] | None
) -> frozenset[str]:
    """The action and result events of observed verification runs (#1143).

    A test, lint, typecheck or build run, a run the agent linked to a requested command, or a run
    the frozen freshness rows track. A reviewer concern citing one of these is about rerunning a
    verification; a concern citing anything else is about other evidence.
    """

    observed = observed_event_ids_from_coverage(case.coverage_by_ref)
    tracked = {row.run_ref for row in case.verification_freshness or ()}
    events: set[str] = set()
    for ref, row in case.projection.results.items():
        result = row.payload
        if result is None or row.source_event_id not in observed:
            continue
        action = case.projection.actions.get(result.action_id)
        if (
            action is None
            or action.payload is None
            or action.payload.action_kind is not ActionKind.COMMAND
        ):
            continue
        if (
            ref in tracked
            or action.source_event_id in (agent_linked or ())
            or observed_action_runner_class(action.payload.description)
            in {"test", "lint", "typecheck", "build"}
        ):
            events.update((str(row.source_event_id), str(action.source_event_id)))
    return frozenset(events)


def _verification_rerun_challenge(challenge: ReviewerChallenge) -> ReviewerChallenge:
    """Route a verification staleness concern to the rerun question, keeping the reviewer's words."""

    message = _bounded_review_text(
        f"Reviewer observation: {challenge.summary} {challenge.message_to_main_agent}"
    )
    return replace(
        challenge,
        finding_kind=FindingKind.DECISION_NEEDED,
        summary=_VERIFICATION_RERUN_SUMMARY,
        message_to_main_agent=message,
        requested_next_step="answer_question",
    )


def _review_fence_gaps(review: SemanticJudgmentReview) -> frozenset[str]:
    """The coverage gaps that disclose what the post-validation fence removed from a review."""

    gaps: set[str] = set()
    # A challenge the fence dropped is material the reviewer raised and the check does not
    # carry. Saying so is what keeps a dropped challenge from reading as one never made.
    if any(reason not in _PROCESS_STATE_REJECTIONS for reason, _count in review.rejected_by_reason):
        gaps.add(SEMANTIC_CHALLENGES_REJECTED_GAP)
    # Issue #1042: a "never attempted" challenge during work in progress, or one about FinishUP's own
    # state, is not material the check failed to carry: disclosed, never bounding, never a veto.
    if any(reason in _PROCESS_STATE_REJECTIONS for reason, _count in review.rejected_by_reason):
        gaps.add(SEMANTIC_PROCESS_STATE_FILTERED_GAP)
    # A per-finding ruling the fence dropped or reduced: disclosed, never read as agreement.
    if review.verdicts_unsupported:
        gaps.add(SEMANTIC_PRIOR_VERDICTS_UNSUPPORTED_GAP)
    if review.snippets_rejected:
        gaps.add(SEMANTIC_REVIEW_SNIPPET_INVALID_GAP)
    # Citations of unsent refs removed from kept items (issue #976).
    if review.refs_reduced:
        gaps.add(SEMANTIC_REVIEW_REFS_REDUCED_GAP)
    # A restated finding was suppressed rather than minted twice: disclosed, never silent.
    if review.restatements_suppressed:
        gaps.add(SEMANTIC_RESTATEMENTS_SUPPRESSED_GAP)
    return frozenset(gaps)


def _judgment_review(*args: object, **kwargs: object) -> SemanticJudgmentReview:
    """Build the review, turning an accounting-invariant failure into a rejected judgment.

    The invariant still fails loudly (a diagnostic and ``semantic_judgment_rejected``), but the
    check commits its local findings and terminates instead of failing as a non-retryable internal
    error that a same-request replay re-raises forever.
    """

    try:
        return SemanticJudgmentReview(*args, **kwargs)  # pyright: ignore[reportArgumentType]
    except SemanticJudgmentRejected:
        raise
    except ValueError as exc:
        raise _rejected("semantic_judgment_review_invalid") from exc


_MAX_RULING_CITED_REFS: Final = 16


def _record_restatement(
    case: DeterministicCase,
    admitted: dict[str, PriorFindingVerdictRecord],
    restated: FindingId,
    refs: tuple[str, ...],
    *,
    verdict: Literal["still_present", "answered_not_fixed"] = "still_present",
    cited: tuple[str, ...] = (),
) -> tuple[bool, bool]:
    """Carry a suppressed restatement onto the earlier item it restates (issue #905).

    Returns whether the restatement is suppressed and whether an explicit ruling was reduced.

    Suppression must never read as absence: a restatement of an open item records that the
    reviewer still finds it (``still_present``, citing what the challenge cited; a challenge that
    names an answered item in ``restates`` records ``answered_not_fixed``, issue #980), so the
    check cannot resolve it by silence and the item's review round advances once per concern. A
    restatement contradicts an explicit ``fixed`` or ``withdrawn`` ruling on the same item, which
    becomes ``unassessable``. A settled item (``acknowledged_not_done``, ``self_verified`` or a
    disclosed limitation) is final: the re-raise is recorded on it as a standing re-raise
    (``_record_settled_reraise``, #980) and it is never reopened or duplicated. tb4n3 RC-7
    (#1030) applies that to ``self_verified`` too: a reviewer that raises the same concern again
    over the agent's own verification, citing nothing concern-relevant newer, is not a new
    sighting (the old rule minted a fresh finding, which is how vpp S got three ids). A
    ``rejection_accepted`` or ``disputed_after_rebuttal`` item is final, stays disclosed on the
    receipt, and needs nothing recorded. An open item the agent holds a reasoned position on
    (a rejection, or an acknowledgement with a reason), restated with nothing newer than that
    position, is ruled ``disputed_after_rebuttal`` (#1020, #1030). (A ``verified_resolved`` item is
    never a restatement target: see ``_restated_finding``.) When no ruling can be recorded (the
    check's ruling bound is full) the restatement is not suppressed and is minted as before.
    """

    todo = finding_todo_state(case.projection, restated)
    if duplicate_link_target(case.projection, restated) is not None:
        # Issue #996: a linked duplicate's final state is only inherited; a restatement of it is
        # a still_present ruling that breaks the link, never a silent suppression.
        todo = FindingTodoState.OPEN
    if todo in {
        FindingTodoState.ACKNOWLEDGED_NOT_DONE,
        FindingTodoState.SELF_VERIFIED,
    } or (todo is FindingTodoState.OPEN and _limitation_disclosed(case, restated)):
        # The agent settled it; the re-raise is recorded on it as a standing dispute (#980).
        return _record_settled_reraise(admitted, restated, refs), False
    if todo in {FindingTodoState.REJECTION_ACCEPTED, FindingTodoState.DISPUTED_AFTER_REBUTTAL}:
        # Final, disclosed on the receipt: a repeat needs nothing recorded (issue #1020: a
        # standing disagreement is not reopened by the same concern raised again).
        return True, False
    key = str(restated)
    earlier = admitted.get(key)
    if earlier is None:
        if len(admitted) >= MAX_RECORDED_VERDICTS:
            return False, False
        kept = tuple(sorted(refs, key=str.encode))[:_MAX_RULING_CITED_REFS]
        recorded: str = verdict
        if _disputed_after_rebuttal(case, restated, verdict, (*refs, *cited)):
            # Issue #1020: the same concern raised again over the agent's reasoned position,
            # with nothing newer, is the standing disagreement, not another round.
            recorded = DISPUTED_AFTER_REBUTTAL_VERDICT
        admitted[key] = PriorFindingVerdictRecord(restated, recorded, kept)
        return True, False
    if earlier.verdict in {"fixed", "withdrawn"}:
        # A contradicted explicit ruling; when the restatement itself only repeats the concern
        # over the agent's reasoned position, the item is the standing disagreement (#1020).
        contradicted = (
            DISPUTED_AFTER_REBUTTAL_VERDICT
            if _disputed_after_rebuttal(case, restated, verdict, (*refs, *cited))
            else "unassessable"
        )
        admitted[key] = PriorFindingVerdictRecord(restated, contradicted, ())
        return True, True
    if (
        earlier.verdict in _HELD_OPEN_RULINGS
        and earlier.verdict != DISPUTED_AFTER_REBUTTAL_VERDICT
        and _disputed_after_rebuttal(case, restated, verdict, (*refs, *cited, *earlier.cited_refs))
    ):
        # Issue #1020: the explicit ruling was reduced (or kept open) without anything newer, and
        # the restatement repeats the concern over the position: the standing disagreement.
        admitted[key] = PriorFindingVerdictRecord(
            restated, DISPUTED_AFTER_REBUTTAL_VERDICT, earlier.cited_refs
        )
        return True, False
    if earlier.verdict == DISPUTED_AFTER_REBUTTAL_VERDICT and not _disputed_after_rebuttal(
        case, restated, verdict, (*refs, *cited)
    ):
        # Issue #1020: the same review also restated it with material newer than the position;
        # that newer sighting outranks the stale ruling, so the item stays open.
        kept = tuple(sorted(refs, key=str.encode))[:_MAX_RULING_CITED_REFS]
        admitted[key] = PriorFindingVerdictRecord(restated, verdict, kept)
    return True, False


def _record_settled_reraise(
    admitted: dict[str, PriorFindingVerdictRecord],
    settled: FindingId,
    refs: tuple[str, ...],
) -> bool:
    """Record a re-raise of a finding the agent settled as the reviewer's ruling on it (#980).

    The item stays final: the ``still_present`` ruling never reopens it or counts a review round.
    The reducer records it as a re-raise after the agent's terminal answer
    (``settled_reraise_count``), which is what a standing premise dispute reads (TB4 tb4n1 D7a).
    Returns ``False`` only when the check's ruling bound is full, so the challenge is minted as a
    linked item instead of being lost.
    """

    key = str(settled)
    if key in admitted:
        return True
    if len(admitted) >= MAX_RECORDED_VERDICTS:
        return False
    cited = tuple(sorted(refs, key=str.encode))[:_MAX_RULING_CITED_REFS]
    admitted[key] = PriorFindingVerdictRecord(settled, "still_present", cited)
    return True


def _finding_kind_of(case: DeterministicCase, key: FindingId) -> FindingKind | None:
    record = case.projection.findings.get(key)
    return None if record is None or record.payload is None else record.payload.kind


def _restated_finding(
    case: DeterministicCase,
    kind: FindingKind,
    refs: tuple[str, ...],
    *,
    replies_to: tuple[FindingId, ...] = (),
    cited: tuple[str, ...] = (),
) -> FindingId | None:
    """The recorded AI-powered finding a challenge restates, if any (issues #905, #1020, #1030).

    A restatement is a challenge about the same *concern* as a recorded finding of a comparable
    kind (``kernel.concern``): the same obligations, or one subject set containing the other, with
    the requirement-family kinds folding across kinds and claim churn normalised. The earlier rule
    keyed the concern on the kind and an exact or asymmetric subject set (an obligation set on
    one side, a raw event set on the other), so a re-raise under another kind, over a
    ``self_verified`` answer, or after the agent republished its own obligation was minted as a
    new finding: vpp S three ids, payments S four, formal-crypto S four for one concern.

    The challenge must also bring nothing concern-relevant newer than the dialogue so far
    (``review_concern.concern_material_after``): evidence, results and actions linked to the
    concern's obligations, recorded after the agent's standing position and the reviewer's last
    ruling, and not evidence the agent itself cited when it answered. Responses, decisions,
    claims, obligations and other bookkeeping are never material, so the agent's own republish
    cannot defeat the fold. A challenge with newer material is a new, linked item, never a
    restatement. An exact subject match outranks a concern match; then the newest finding wins.

    A ``verified_resolved`` row is never a target: done stays done, and the reviewer finding the
    problem again after that proof is a #458 successor, minted and blocking. Suppressing it would
    hide a real re-raise behind a closed row.

    A challenge that cites an open item the main agent has already answered without a reasoned
    position (``replies_to``, the earlier ``fnd_`` ids the challenge names) is the reviewer's reply
    to that answer, as the reviewer instruction asks: it is minted as a new item linked to the
    earlier one, so the agent receives it as a finding instead of a ruling it never sees (TB4
    tb4f1, issue #976). A reply over a reasoned position (a rejection or a reasoned
    acknowledgement) that brings nothing newer is the same demand repeated over the position
    (issue #1020), so it folds onto the item, where ``_record_restatement`` records the standing
    disagreement.
    """

    wanted = frozenset(refs)
    if not wanted:
        return None
    wanted_key = concern_key(case.projection, refs)
    best: tuple[int, int, FindingId] | None = None
    for key, record in case.projection.findings.items():
        payload = record.payload
        if (
            payload is None
            or record.redacted
            or payload.origin is not FindingOrigin.SEMANTIC_MODEL_DERIVED
            or finding_todo_state(case.projection, key) is FindingTodoState.VERIFIED_RESOLVED
        ):
            continue
        subjects = tuple(str(ref) for ref in payload.subject_refs)
        exact = wanted == frozenset(subjects)
        target_state = finding_todo_state(case.projection, key)
        # A settled item's concern is widened by the re-raises recorded on it (bounded).
        target_key = concern_key(case.projection, (*subjects, *record.absorbed_refs))
        # An open item folds only a challenge about the very same concern: a narrower or wider
        # one is a distinct issue whose discrepancy a ruling cannot carry (Greptile P1 on #943).
        # A settled item (the agent's final word, or a disclosed limitation) folds any overlap,
        # because the re-raise cannot change what the agent already settled (tb4n3 RC-7).
        settled_target = target_state is not FindingTodoState.OPEN or _limitation_disclosed(
            case, key
        )
        if payload.kind is not kind and not (
            settled_target
            and kinds_comparable(
                payload.kind,
                kind,
                obligation_concern=wanted_key.named_obligations and target_key.named_obligations,
            )
        ):
            continue
        if not exact and not (
            same_concern(wanted_key, target_key)
            if settled_target
            else equal_concern(wanted_key, target_key)
        ):
            continue
        bound = answer_bound(case.projection, key)
        if (
            key in replies_to
            and target_state is FindingTodoState.OPEN
            and _answered(case.projection, key)
            and not rejection_stands(record, case.projection.responses.get(key))
        ):
            # The reviewer's reply to an answer reaches the agent as a finding (issue #976); only
            # a reply to a standing rejection that brings nothing newer folds (issue #1020).
            continue
        if bound is None:
            bound = max(record.source_frontier, record.last_ruling_frontier or 0)
        merged = ConcernKey(
            wanted_key.obligations | target_key.obligations,
            wanted_key.refs | target_key.refs,
            wanted_key.named_obligations or target_key.named_obligations,
        )
        if concern_material_after(case, merged, (*refs, *cited), bound):
            continue
        # An exact match outranks a concern match; then the newest finding wins.
        rank = (int(exact), record.source_frontier, key)
        if best is None or rank[:2] > best[:2]:
            best = rank
    return None if best is None else best[2]


def _answered(projection: ProjectionState, finding: FindingId) -> bool:
    response = projection.responses.get(finding)
    return response is not None and response.payload is not None and not response.redacted


def _sorted_verdicts(
    admitted: Mapping[str, PriorFindingVerdictRecord],
) -> tuple[PriorFindingVerdictRecord, ...]:
    return tuple(admitted[key] for key in sorted(admitted, key=str.encode))


async def _conversation_review_context(
    app: Application, runtime: TaskRuntime, request_id: str
) -> ConversationReviewContext | None | Literal["unreadable"]:
    """The owner's conversation setting and review availability for this task (ADR-049).

    ``None`` when the application has no reader (a composition that predates the setting): the
    check then keeps the released behaviour and records no review mode. ``"unreadable"`` when the
    reader failed: the check fails closed (``_resolve_check_review_mode``).
    """

    reader = getattr(app, "conversation_review_context", None)
    if not callable(reader):
        return None
    try:
        context = await cast(
            Callable[[TaskRuntime], Awaitable[ConversationReviewContext | None]], reader
        )(runtime)
    except Exception as exc:
        record_unexpected_exception_without_raising(
            exc,
            component="check",
            operation="conversation_review_context_failed",
            request_id=request_id,
        )
        return "unreadable"
    return context if type(context) is ConversationReviewContext else None


async def _semantic_review_used_at(
    runtime: TaskRuntime, request: CheckRequest, frozen: FrozenCase
) -> bool:
    """Whether the frozen prefix already used AI-powered review; read for the closing review only.

    Only a ``final_review: true`` check that names no mode asks: in a task now running local, that
    check is the closing review the task owes (ADR-049). A failed read says no, so the check runs
    in the task's mode and the closing review stays owed rather than dispatched unasked.
    """

    if not request.final_review:
        return False
    try:
        records = tuple(
            [
                record
                async for record in runtime.ledger.load_events(
                    runtime.session_id, through=frozen.case.frontier.sequence
                )
            ]
        )
    except Exception as exc:
        record_unexpected_exception_without_raising(
            exc, component="check", operation="review_used_read", request_id=request.request_id
        )
        return False
    return semantic_review_used(records)


async def _check_review_mode(
    app: Application,
    runtime: TaskRuntime,
    request: CheckRequest,
    *,
    mode_explicit: bool,
    frozen: FrozenCase,
    route_profile: Literal["policy", "strict"],
) -> tuple[CheckRequest, CheckReviewMode | None, Literal["disabled", "optional", "required"]]:
    """``(request, recorded review mode, verification policy)`` this check runs with (ADR-049).

    Kept out of ``execute_check_commit`` so the commit path stays analyzable; see
    ``_resolve_check_review_mode`` for the rules.
    """

    resolved, review_mode, override = _resolve_check_review_mode(
        request,
        mode_explicit=mode_explicit,
        frozen=frozen,
        context=await _conversation_review_context(app, runtime, request.request_id),
        route_profile=route_profile,
        review_used=not mode_explicit and await _semantic_review_used_at(runtime, request, frozen),
        review_enabled=app.verification_policy.semantic != "disabled",
    )
    return (
        resolved,
        review_mode,
        app.verification_policy.semantic if override is None else override,
    )


def _requested_review(
    request: CheckRequest,
    conversation: ConversationReviewMode,
    context: ConversationReviewContext,
    *,
    route_profile: Literal["policy", "strict"],
    keeps_requirement: bool,
) -> tuple[CheckRequest, CheckReviewMode, Literal["optional", "required"] | None]:
    """A check's own request for AI-powered review (``source`` ``check_request``).

    It runs under the effective privacy policy (which may still ask the owner per review), except
    where the owner explicitly chose local only, where it runs local: a ``semantic_required``
    request the caller named keeps its requirement there (``keeps_requirement``), so the missing
    review stays an honest gap rather than a clean local result. On the strict route nothing can
    dispatch, and the recorded mode says so.
    """

    if conversation.setting is ConversationReview.LOCAL_ONLY and (
        context.setting_explicit or context.ai_review_available
    ):
        # The owner chose local checks only: an agent's one-check request does not opt in.
        return (
            request.model_copy(update={"mode": "deterministic_only"}),
            CheckReviewMode(ReviewMode.LOCAL, "check_request", "owner_local_only"),
            "required" if keeps_requirement else "optional",
        )
    if route_profile == "strict":
        return request, CheckReviewMode(ReviewMode.LOCAL, "check_request", "route_local_only"), None
    return request, CheckReviewMode(ReviewMode.AI_POWERED, "check_request"), None


def _resolve_check_review_mode(
    request: CheckRequest,
    *,
    mode_explicit: bool,
    frozen: FrozenCase,
    context: ConversationReviewContext | None | Literal["unreadable"],
    route_profile: Literal["policy", "strict"] = "policy",
    review_used: bool = False,
    review_enabled: bool = True,
) -> tuple[CheckRequest, CheckReviewMode | None, Literal["optional", "required"] | None]:
    """``(request, recorded review mode, verification override)`` for one check (ADR-049).

    A check that did not name its mode runs in its conversation's mode. A conversation local by a
    choice its owner's setting allows runs ``deterministic_only`` on a route that did not require
    AI-powered review (override ``optional``), so it completes at local coverage and discloses
    that. Under the owner's "every task" setting a switch to local decides nothing: the check runs
    as configured and a missing review stays the owner's required-review gap.

    A ``final_review: true`` check that names no mode, in a task that already used AI-powered
    review and now runs local, is the closing review the task owes (the Stop gate's instruction):
    it is that check's own request. A check that names an AI-powered mode is that check's own
    request (``_requested_review``). A check that names ``deterministic_only`` runs local; it
    lowers the requirement only in a conversation local by choice. Without a context nothing
    changes and no mode is recorded (``None`` override: the configured verification policy).

    Upgrade rule: where the owner's policy predates the setting and the conversation recorded no
    switch, the check keeps its released behaviour exactly and records no mode, so an existing
    installation's checks and receipts are unchanged until the owner chooses a setting or an
    agent switches the task.

    Fail closed: where the owner's setting could not be read, a check that names no mode runs
    local checks only under the configured requirement (a required review stays a bounding gap)
    and records no mode; a check that named its mode keeps it, and the privacy gateway still
    enforces the owner's policy at dispatch.
    """

    if context == "unreadable":
        if mode_explicit:
            return request, None, None
        return request.model_copy(update={"mode": "deterministic_only"}), None, None
    if context is None:
        return request, None, None
    conversation = conversation_review_mode(
        frozen.case.projection,
        context.setting,
        ai_review_available=context.ai_review_available,
        setting_explicit=context.setting_explicit,
        route_allows_review=route_profile == "policy",
        review_enabled=review_enabled,
    )
    if not context.setting_explicit and not conversation.switches:
        return request, None, None
    if (
        not mode_explicit
        and review_used
        and request.final_review
        and conversation.mode is ReviewMode.LOCAL
    ):
        # The closing review of a task that already used AI-powered review (review round 1).
        if request.mode == "deterministic_only":
            # The verification settings turn review off for checks that name no mode: the
            # closing review cannot run here, and the recorded reason says so.
            return (
                request,
                CheckReviewMode(ReviewMode.LOCAL, "check_request", "review_disabled"),
                "optional" if conversation.local_by_choice else None,
            )
        return _requested_review(
            request, conversation, context, route_profile=route_profile, keeps_requirement=False
        )
    if not mode_explicit:
        switch = conversation.latest_switch if conversation.driven_by_switch else None
        source = "conversation_switch" if switch is not None else "conversation_default"
        switch_id = None if switch is None else switch.event_id
        if conversation.mode is ReviewMode.LOCAL:
            reason = (
                conversation.local_reason
                if conversation.local_reason in REQUESTED_BUT_LOCAL_REASONS
                else None
            )
            return (
                request.model_copy(update={"mode": "deterministic_only"}),
                CheckReviewMode(ReviewMode.LOCAL, source, reason, switch_id),
                "optional" if conversation.local_by_choice else None,
            )
        return request, CheckReviewMode(ReviewMode.AI_POWERED, source, None, switch_id), None
    if request.mode == "deterministic_only":
        return (
            request,
            CheckReviewMode(ReviewMode.LOCAL, "check_request"),
            "optional" if conversation.local_by_choice else None,
        )
    return _requested_review(
        request,
        conversation,
        context,
        route_profile=route_profile,
        keeps_requirement=request.mode == "semantic_required",
    )


def semantic_route_required(
    mode: str | None,
    policy_semantic: Literal["disabled", "optional", "required"],
    *,
    route_profile: Literal["policy", "strict"] = "policy",
    route_drift: bool = False,
) -> bool:
    """Whether a check's route required AI-powered review (issue #986, owner decision E2).

    True when the check asked for it (``semantic_required``), whatever route served the call.
    Otherwise an explicitly deterministic-only route (the owner registered the strict MCP route,
    which can never dispatch AI-powered review) did not require one, whatever the verification
    policy says (issue #1021, owner decision tb4n2 P0-8): that owner chose local checks for this
    host. A strict process serving a host whose applied route is ``policy``
    (``route_drift``, issue #537) is stale, not an owner choice, so the policy still decides.
    On the policy route, a ``required`` verification policy requires review. Only a check on a
    route that did not require review records ``semantic_route_required: false``; there
    ``semantic_review_not_requested`` is a disclosure that does not bound the receipt.
    """

    if mode == "semantic_required":
        return True
    if route_profile == "strict" and not route_drift:
        return False
    return policy_semantic == "required"


def _recorded_route_required(
    mode: str | None,
    policy_semantic: Literal["disabled", "optional", "required"],
    *,
    route_profile: Literal["policy", "strict"],
    host_profile: McpHostProfile,
    _state: Path | None,
) -> Literal[False] | None:
    """The recorded ``semantic_route_required`` value: ``False`` or omitted (issue #986).

    Only a route that did not require review is written; a requiring route keeps today's bytes.
    """

    drift = route_profile == "strict" and _strict_ceiling_route_drift(
        host_profile=host_profile, _state=_state
    )
    required = semantic_route_required(
        mode, policy_semantic, route_profile=route_profile, route_drift=drift
    )
    return None if required else False


def _check_semantic_gap(
    mode: str | None,
    policy_semantic: Literal["disabled", "optional", "required"],
    semantic_result: FinalSemanticEvaluation,
    *,
    route_profile: Literal["policy", "strict"],
    host_profile: McpHostProfile,
    _state: Path | None,
) -> str | None:
    """The review-outcome gap this check records (issue #1041).

    A check that asked for no review (``deterministic_only``) on a route that required none ran
    exactly what was requested, so it records no ``semantic_review_not_requested``. Where the
    route required review, or the round stopped the review, the outcome's gap stays.
    """

    requested_deterministic = mode == "deterministic_only" and (
        _recorded_route_required(
            mode,
            policy_semantic,
            route_profile=route_profile,
            host_profile=host_profile,
            _state=_state,
        )
        is False
    )
    if requested_deterministic:
        return None
    return semantic_coverage_gap_code(semantic_result.status, semantic_result.reason)


def _route_and_insufficiency(
    mode: str | None,
    policy_semantic: Literal["disabled", "optional", "required"],
    *,
    route_profile: Literal["policy", "strict"],
    host_profile: McpHostProfile,
    state: Path | None,
    known_gaps: Iterable[str],
) -> tuple[bool, bool]:
    """``(route requires review, reviewer reported insufficiency)`` for one check (ADR-046).

    The route is the value this check records (``semantic_route_required``); the insufficiency is
    whether the same check's coverage carries a reviewer-reported "could not assess" gap, which is
    what keeps a FinishUP review-packet budget a bound instead of a disclosure.
    """

    required = (
        _recorded_route_required(
            mode,
            policy_semantic,
            route_profile=route_profile,
            host_profile=host_profile,
            _state=state,
        )
        is None
    )
    codes = tuple(known_gaps)
    insufficient = any(
        code in {"semantic_packet_insufficient", SEMANTIC_REVIEW_SKIPPED_INSUFFICIENT_PACKET_GAP}
        or code.startswith("semantic_missing_")
        for code in codes
    )
    return required, insufficient


def _full_check_is_complete(
    known_gaps: Iterable[str],
    totals: Mapping[str, object],
    findings: Iterable[Finding],
    *,
    route_requires_review: bool,
    review_succeeded: bool,
    reviewer_reported_insufficiency: bool,
) -> bool:
    """Whether a full check may read ``complete``: clean gaps and no returned limit finding.

    A returned finding that asks for no work is a coverage limit (a stale or incomplete ledger), so
    the check can never read complete beside it (ADR-046). A reviewer's limitation request is the
    exception only in how it is judged: the ranking verdict reads it as ``insufficient_coverage``
    itself, so it does not make the completeness incomplete here.
    """

    return full_check_gaps_clean(
        known_gaps,
        totals,
        route_requires_review=route_requires_review,
        review_succeeded=review_succeeded,
        reviewer_reported_insufficiency=reviewer_reported_insufficiency,
    ) and all(
        finding_demands_work(finding) or is_limitation_request(finding) for finding in findings
    )


def full_check_gaps_clean(
    known_gaps: Iterable[str],
    totals: Mapping[str, object],
    *,
    route_requires_review: bool = True,
    review_succeeded: bool = False,
    reviewer_reported_insufficiency: bool = False,
) -> bool:
    """Whether a full check's gaps allow ``complete`` (#986): the receipt's own judgment.

    ADR-046: the same table and the same context the receipt uses (``kernel.gap_effect``), so the
    check's verdict and the receipt's conclusion cannot disagree about a gap. The route is the one
    this check records; a host-observation member counts only when the case's command counters
    show no unknown or live failed outcome; a FinishUP review-packet budget is disclosed only when the
    review succeeded and the reviewer reported no insufficiency.
    """

    return gaps_are_clean(
        known_gaps,
        totals,
        route_requires_review=route_requires_review,
        review_succeeded=review_succeeded,
        reviewer_reported_insufficiency=reviewer_reported_insufficiency,
    )


def _request_digest(
    request: CheckRequest,
    scope: CheckScope,
    packs: tuple[str, ...],
    *,
    route_profile: Literal["policy", "strict"],
) -> str:
    source = cast(dict[str, JsonValue], request.model_dump(mode="json", by_alias=True))
    # Issue #1012: the optional pre-check wait shapes only the call that asked for it and records
    # nothing, so it stays outside the operation identity. Requests without it keep their digest,
    # and a same-request recovery may set or omit it.
    source.pop("await_observations", None)
    source["scope"] = {"claim_ids": scope.claim_ids, "obligation_ids": scope.obligation_ids}
    source["policy_packs"] = packs
    source["route_profile"] = route_profile
    return canonical_digest(source)


def _skipped_review_reason(
    request: CheckRequest,
    *,
    round_stopped: bool,
    deferred_before_first_edit: bool,
) -> SemanticReason | None:
    """The ``not_requested`` reason when this check will not dispatch a review.

    Local-only, pre-edit deferral and a requested review stopped at its round cap are distinct.
    """

    if deferred_before_first_edit:
        return SemanticReason.DEFERRED_BEFORE_FIRST_EDIT
    if request.mode == "deterministic_only":
        return SemanticReason.DETERMINISTIC_MODE
    if round_stopped:
        return SemanticReason.ROUND_LIMIT_UNASSESSABLE
    return None


async def _semantic_evaluation(
    app: Application,
    request: CheckRequest,
    runtime: TaskRuntime,
    frozen: FrozenCase,
    deterministic: tuple[Finding, ...],
    *,
    route_profile: Literal["policy", "strict"],
    lineage_evaluation: LineageEvaluation | None = None,
    require_complete_specification: bool = False,
    task_fact_gaps: tuple[str, ...] = (),
    round_stopped: bool = False,
    deferred_before_first_edit: bool = False,
) -> FinalSemanticEvaluation:
    skipped = _skipped_review_reason(
        request,
        round_stopped=round_stopped,
        deferred_before_first_edit=deferred_before_first_edit,
    )
    if skipped is not None:
        # tb4n1 D3: after two insufficient-packet reviews in a row with no edit since, the round
        # stops; the check runs its local checks only and discloses why (see the commit path).
        # Issue #1046: the pre-edit deferral is the same local-only run with its own reason.
        status = (
            SemanticStatus.UNAVAILABLE
            if skipped is SemanticReason.ROUND_LIMIT_UNASSESSABLE
            else SemanticStatus.NOT_REQUESTED
        )
        return FinalSemanticEvaluation(status, skipped)
    if route_profile == "strict":
        return FinalSemanticEvaluation(
            SemanticStatus.BLOCKED_BY_POLICY,
            SemanticReason.ROUTE_SEMANTIC_CEILING,
        )
    if RuntimeCapability.SEMANTIC not in runtime.capabilities:
        return FinalSemanticEvaluation(
            SemanticStatus.NOT_CONFIGURED,
            SemanticReason.PROVIDER_NOT_CONFIGURED,
        )
    try:
        accepts_lineage = _semantic_evaluator_accepts_lineage(app)
        accepts_full_spec = _semantic_evaluator_accepts_complete_specification(app)
        if accepts_lineage:
            kwargs: dict[str, bool] = {}
            if accepts_full_spec:
                kwargs["require_complete_specification"] = require_complete_specification
            # The closing review (issue #976) reaches only an evaluator that declares it.
            if request.final_review and _semantic_evaluator_accepts_keyword(app, "final_review"):
                kwargs["final_review"] = True
            # Requested-output facts (#977) are read at check time, after the case is frozen;
            # the reviewer sees their closed codes in the packet's coverage.
            if task_fact_gaps and _semantic_evaluator_accepts_keyword(app, "task_fact_gaps"):
                # The seam declares the keyword (checked above); the port protocol keeps it
                # optional so older application doubles stay assignable.
                evaluate = cast(
                    Callable[..., Awaitable[FinalSemanticEvaluation]],
                    app.evaluate_semantic_check,
                )
                return await evaluate(
                    frozen,
                    deterministic,
                    runtime,
                    lineage_evaluation,
                    task_fact_gaps=task_fact_gaps,
                    **kwargs,
                )
            return await app.evaluate_semantic_check(
                frozen,
                deterministic,
                runtime,
                lineage_evaluation,
                **kwargs,
            )
        if accepts_full_spec and lineage_evaluation is None:
            return await app.evaluate_semantic_check(
                frozen,
                deterministic,
                runtime,
                require_complete_specification=require_complete_specification,
            )
        if lineage_evaluation is None:
            # Keep the original three-argument application seam for integrations that predate
            # the optional lineage semantic channel.  The production facade accepts the fourth
            # argument below; omitting it when there is no lineage also avoids turning an old
            # evaluator's harmless signature difference into a semantic coordinator failure.
            return await app.evaluate_semantic_check(frozen, deterministic, runtime)
        return await app.evaluate_semantic_check(frozen, deterministic, runtime, lineage_evaluation)
    except Exception as exc:
        # Optional/required AI-powered evaluator crash must never fabricate a clean AI-powered review pass.
        record_unexpected_exception_without_raising(
            exc,
            component="check",
            operation="semantic_not_dispatched_coordinator_failure",
            request_id=request.request_id,
        )
        # Deliberately no operation_lease: reaching here means the evaluator raised *before* it
        # could renew, so the caller's token is still the live one. The evaluator itself catches
        # everything from the durable path and returns its renewed lease, and the attempt loop
        # terminalizes rather than raising — if either of those regresses, this path would start
        # handing back a stale lease and the check would be lost to OPERATION_PENDING instead of
        # recording an honest failure. There is no API to re-acquire a lease you already hold.
        return FinalSemanticEvaluation(
            SemanticStatus.FAILED,
            SemanticReason.COORDINATOR_FAILURE,
        )


def _semantic_evaluator_accepts_lineage(app: Application) -> bool:
    """Detect legacy application doubles before adding the optional lineage argument.

    The service facade owns the four-argument seam.  A few embedders still provide the original
    three-argument evaluator, so signature inspection keeps those integrations on their existing
    path without catching a ``TypeError`` raised from inside an evaluator as if it were a harmless
    signature mismatch.
    """

    try:
        parameters = tuple(inspect.signature(app.evaluate_semantic_check).parameters.values())
    except (TypeError, ValueError):
        # An opaque callable may still accept the new optional argument; let the normal exception
        # fence below classify a genuine failure.
        return True
    return len(
        tuple(
            parameter
            for parameter in parameters
            if parameter.kind
            in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
        )
    ) >= 4 or any(parameter.kind is inspect.Parameter.VAR_POSITIONAL for parameter in parameters)


def _semantic_evaluator_accepts_keyword(app: Application, name: str) -> bool:
    """Whether the application's evaluator seam declares keyword ``name`` (or ``**kwargs``)."""

    try:
        parameters = tuple(inspect.signature(app.evaluate_semantic_check).parameters.values())
    except (TypeError, ValueError):
        return False
    return any(
        parameter.name == name or parameter.kind is inspect.Parameter.VAR_KEYWORD
        for parameter in parameters
    )


def _semantic_evaluator_accepts_complete_specification(app: Application) -> bool:
    """Detect the optional full-specification admission keyword on legacy evaluator doubles."""

    try:
        parameters = tuple(inspect.signature(app.evaluate_semantic_check).parameters.values())
    except (TypeError, ValueError):
        return True
    return any(
        parameter.name == "require_complete_specification"
        or parameter.kind is inspect.Parameter.VAR_KEYWORD
        for parameter in parameters
    )


def _semantic_conclusion_token(result: FinalSemanticEvaluation) -> str:
    """The reviewer's own conclusion when it reached one; otherwise why it did not."""

    judgment = result.judgment
    if judgment is None:
        return result.reason.value
    return judgment.conclusion


def _record_semantic_review_accounting(
    request: CheckRequest,
    result: FinalSemanticEvaluation,
    review: SemanticJudgmentReview,
    semantic: tuple[Finding, ...],
    ranked: RankedFindings,
) -> None:
    """Say what the reviewer produced and what became of it, on every dispatched review.

    Without this, "the model returned three challenges and none of them reached you" is invisible:
    the check reports ``semantic_status: succeeded`` and zero AI-powered findings, which reads
    identically to a reviewer that found nothing. The record is counts and closed tokens only, and
    it reconciles — ``returned == accepted + rejected + restated + advisory`` and
    ``accepted == selected + suppressed``.
    """

    # Provenance present means a provider attempt reached a terminal outcome. Nothing was reviewed
    # before that, so there is nothing to account for and no reason to fill the durable ring.
    if result.provenance is None:
        return
    selected = sum(
        1 for finding in ranked.findings if finding.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED
    )
    record_bounded_counts_without_raising(
        component="check",
        operation="semantic_review_accounting",
        outcome=result.status.value,
        request_id=request.request_id,
        counts={
            "semantic_conclusion": _semantic_conclusion_token(result),
            "semantic_challenges_returned": review.challenges_returned,
            "semantic_candidates_accepted": len(review.candidates),
            "semantic_challenges_rejected": review.challenges_rejected,
            # Per-reason split so a run can be attributed without guessing (issue #976).
            **{f"semantic_rejected_{reason}": count for reason, count in review.rejected_by_reason},
            "semantic_review_refs_reduced": review.refs_reduced,
            "semantic_review_snippets_rejected": review.snippets_rejected,
            "semantic_restatements_suppressed": review.restatements_suppressed,
            # Issue #1042 item 3: what the maintainer's harness needs to attribute a run's
            # findings to the frame (advisory correctness notes, the agent's own criteria).
            "semantic_challenges_advisory": review.advisory_notes,
            "semantic_agent_criteria": review.agent_criteria,
            "semantic_prior_rulings_set_aside": review.verdicts_set_aside,
            "semantic_rulings_disputed_after_rebuttal": sum(
                1 for item in review.verdicts if item.verdict == DISPUTED_AFTER_REBUTTAL_VERDICT
            ),
            "semantic_findings_selected": selected,
            "semantic_findings_suppressed": len(semantic) - selected,
        },
    )


def _judgment_rejected_evaluation(
    result: FinalSemanticEvaluation,
) -> FinalSemanticEvaluation:
    """Restate a structurally unusable reviewer answer as the honest terminal AI-powered review outcome.

    ``SemanticStatus.INVALID`` / ``SEMANTIC_JUDGMENT_REJECTED`` has existed in the enum, the ledger
    CHECK constraints, and ``check-result-1.0.0`` since 0.1 and nothing had ever written it: the
    rejection escaped as ``INVALID_REQUEST`` instead, taking the whole check — local
    findings included — with it. The provenance is the same attempt, restated to the outcome it
    actually reached, because the binding fence requires provenance and result to agree.
    """

    provenance = result.provenance
    if provenance is None:  # pragma: no cover - SUCCEEDED always carries final provenance
        return FinalSemanticEvaluation(SemanticStatus.FAILED, SemanticReason.COORDINATOR_FAILURE)
    return FinalSemanticEvaluation(
        SemanticStatus.INVALID,
        SemanticReason.SEMANTIC_JUDGMENT_REJECTED,
        None,
        # failure_class stays unset. Every member of the enum names a provider-side fault, and
        # this path runs only for the structural fence — the coordinator's own inputs were wrong,
        # not the provider's answer. Naming one would send an operator after the wrong component;
        # semantic_judgment_rejected already says exactly what happened.
        replace(
            provenance,
            status=SemanticStatus.INVALID,
            reason=SemanticReason.SEMANTIC_JUDGMENT_REJECTED,
        ),
        attempt_accounting=result.attempt_accounting,
        operation_lease=result.operation_lease,
        withheld_review_categories=result.withheld_review_categories,
        credential_heuristic_disabled=result.credential_heuristic_disabled,
        # The rejection restates the outcome, not the case: a truncated case stays truncated.
        case_content_over_item_limit=result.case_content_over_item_limit,
        case_reference_scope_reduced=result.case_reference_scope_reduced,
        case_included_refs=result.case_included_refs,
        semantic_withheld_item_ids=result.semantic_withheld_item_ids,
        semantic_redacted_values=result.semantic_redacted_values,
        case_content_gaps=result.case_content_gaps,
    )


def _credential_heuristic_gaps(semantic_result: FinalSemanticEvaluation) -> frozenset[str]:
    """Disclose the owner's credential-heuristic opt-out on a review that ran (issue #982).

    The reviewer may have seen values that only look like passwords or tokens. It is an owner
    disclosure choice, recorded on every review that ran under it, never agent work.
    """

    if semantic_result.credential_heuristic_disabled and (
        semantic_result.status is SemanticStatus.SUCCEEDED
        or semantic_result.provider_input_manifest is not None
    ):
        return frozenset({SEMANTIC_REVIEW_CREDENTIAL_HEURISTIC_DISABLED_GAP})
    return frozenset()


def _reviewer_wire(record: ReviewerRecord | None) -> JsonObject | None:
    """The reviewer conversation's record as the check result carries it (#1118)."""

    return (
        None if record is None else cast(JsonObject, freeze_json(cast(JsonValue, record.as_wire())))
    )


async def _semantic_evaluation_with_follow_up(
    app: Application,
    request: CheckRequest,
    runtime: TaskRuntime,
    frozen: FrozenCase,
    deterministic: tuple[Finding, ...],
    *,
    route_profile: Literal["policy", "strict"],
    lineage_evaluation: LineageEvaluation | None,
    round_stopped: bool,
    deferred_before_first_edit: bool,
    deterministic_output_gaps: Iterable[str],
    output_absent: bool,
) -> FinalSemanticEvaluation:
    """The check's AI-powered review: one round; the old in-check follow-up is gone (#1118).

    Kept out of ``execute_check_commit`` so the commit path stays within what the type checker
    can analyze; the order and arguments are exactly the commit path's own.
    """

    task_fact_gaps = tuple(
        sorted(
            {
                *deterministic_output_gaps,
                *((REQUESTED_OUTPUT_ABSENT_FACT,) if output_absent else ()),
            },
            key=str.encode,
        )
    )
    # #1118 unit 4: the automatic in-check follow-up (insufficient -> re-rank -> rebuild the
    # whole packet -> a new job, #1047) is gone. The reviewer reads permitted evidence itself
    # inside one bounded conversation; a request it still makes goes back to the agent.
    return await _semantic_evaluation(
        app,
        request,
        runtime,
        frozen,
        deterministic,
        route_profile=route_profile,
        lineage_evaluation=lineage_evaluation,
        require_complete_specification=request.mode == "semantic_required",
        round_stopped=round_stopped,
        deferred_before_first_edit=deferred_before_first_edit,
        task_fact_gaps=task_fact_gaps,
    )


async def execute_check_commit(
    app: Application,
    request: CheckRequest,
    *,
    route_profile: Literal["policy", "strict"] = "policy",
    host_profile: McpHostProfile = "generic",
    _state: Path | None = None,
    mode_explicit: bool | None = None,
) -> CheckCommitResult | CheckAwaitingHuman:
    """Freeze, evaluate, rank, and atomically commit one check operation.

    ``mode_explicit`` says whether the caller named the check mode. A check that did not runs in
    its conversation's review mode (ADR-049); ``None`` reads it from the request.

    Returns ``CheckAwaitingHuman`` instead when the AI-powered review phase is suspended on a local
    disclosure decision: nothing is committed and the operation stays resumable.

    ``_state`` isolates the applied-route drift probe (issue #537 slice C): production
    callers leave it unset so the probe reads the live state directory, while tests pass
    an isolated root.
    """

    # The public facade resolves this before entering the commit pipeline. Keep the internal
    # entrypoint equally honest for recovery/tests that call it directly: an omitted mode follows
    # the configured policy, so a disabled semantic route produces NOT_REQUESTED rather than an
    # unavailable semantic attempt. Optional/required routes retain their effective modes.
    if mode_explicit is None:
        mode_explicit = request.mode is not None
    if request.mode is None:
        request = request.model_copy(update={"mode": app.verification_policy.default_check_mode})
    if route_profile not in {"policy", "strict"}:
        raise TypeError("check_route_profile_invalid")
    scope = normalize_check_scope(request)
    packs = _selected_packs(request)
    required_capabilities = {
        RuntimeCapability.WRITE,
        RuntimeCapability.PAYLOAD_READ,
    }
    # A ready service grants SEMANTIC independently of the ordinary write route.  Preserve that
    # admission on checks that are not local-only; otherwise the leased task runtime loses the
    # capability and reports provider_not_configured before the configured evaluator can run.
    # An explicit AI-powered review request while AI-powered review is disabled retains the existing
    # honest not-configured result instead of becoming a routing failure.
    if (
        route_profile == "policy"
        and request.mode != "deterministic_only"
        and app.verification_policy.semantic != "disabled"
    ):
        required_capabilities.add(RuntimeCapability.SEMANTIC)
    runtime = await app.runtime.route(
        RouteCommand(
            request.session_id,
            request.writer_id,
            RouteAccess.WRITE,
            frozenset(required_capabilities),
        )
    )
    frozen: FrozenCase | None = None
    lineage_evaluation: LineageEvaluation
    try:
        if runtime.session_id != request.session_id or runtime.writer_id != request.writer_id:
            raise PublicOperationError(
                PublicErrorCode.SESSION_CONFLICT,
                "The writer route is inconsistent.",
                False,
            )
        digest = _request_digest(request, scope, packs, route_profile=route_profile)
        reconcile_losses = getattr(app, "reconcile_observation_losses", None)
        retire_superseded = _superseded_coordination_retirer(app, packs)
        if callable(reconcile_losses) or retire_superseded is not None:
            # Pre-freeze reconciliation belongs to a new check only; a completed or frozen
            # request replays its recorded result without new ledger motion.
            existing = await runtime.ledger.lookup_operation(request.writer_id, request.request_id)
            if existing is None:
                if callable(reconcile_losses):
                    try:
                        await cast(Callable[[TaskRuntime], Awaitable[None]], reconcile_losses)(
                            runtime
                        )
                    except ObservationStoreLockTimeout as exc:
                        # Hooks held the shared local store through the bounded wait. Nothing
                        # was admitted or recorded for this request, so the honest answer is
                        # the retryable same-identity refusal, not a terminal internal error
                        # (issue #689).
                        raise check_admission_refused(
                            CheckAdmissionStage.ACQUISITION_CONTENDED
                        ) from exc
                if retire_superseded is not None:
                    await _retire_superseded_coordination(
                        retire_superseded, runtime, request.request_id
                    )

        try:
            frozen_or_replay = await runtime.ledger.freeze_case(
                request.session_id,
                request.writer_id,
                int(request.expected_frontier.sequence),
                request.request_id,
                digest,
            )
        except PublicOperationError as exc:
            # A completed same-request replay must return before consulting newer capture state:
            # a corrupt or unrelated ticket cannot turn an idempotent result into STORAGE_CORRUPT.
            # A new CHECK that hit the capture barrier gets one task-local reconciliation (stale
            # authority and orphaned handoffs) and one retry; live tickets remain pending. A lost
            # acquisition race staged nothing durable, so it retries once directly. Every other
            # refusal, including a same-request acquisition still in flight, keeps its original
            # typed disposition for the caller's exact replay (issue #838).
            if exc.code is not PublicErrorCode.OPERATION_PENDING or not exc.retryable:
                raise
            stage = check_admission_stage(exc)
            if stage is CheckAdmissionStage.ACQUISITION_CONTENDED:
                pass
            elif stage is CheckAdmissionStage.CAPTURE_HANDOFF_PENDING or stage is None:
                reconcile_capture = getattr(app, "reconcile_observation_capture", None)
                if not callable(reconcile_capture):
                    raise
                try:
                    await cast(Callable[[TaskRuntime], Awaitable[None]], reconcile_capture)(runtime)
                except ObservationStoreLockTimeout as timeout:
                    # Store contention during the one task-local reconciliation leaves the
                    # capture barrier exactly as refused: keep its typed refusal (#689).
                    raise exc from timeout
            else:
                raise
            frozen_or_replay = await runtime.ledger.freeze_case(
                request.session_id,
                request.writer_id,
                int(request.expected_frontier.sequence),
                request.request_id,
                digest,
            )
        if isinstance(frozen_or_replay, CheckCommitResult):
            replayed = await replayed_check_view(
                app, runtime, frozen_or_replay, route_profile=route_profile
            )
            # The ledger replay is frozen; only the additive project-advice projection is current.
            return await _attach_current_project_advisory_notes(app, runtime.task_id, replayed)
        frozen = frozen_or_replay
        # ADR-049: the conversation's review mode, read from the frozen prefix and the owner's
        # setting. A local conversation runs this check with local checks only, on a route that
        # did not require AI-powered review; the recorded mode says which and why.
        request, check_review_mode, policy_semantic = await _check_review_mode(
            app,
            runtime,
            request,
            mode_explicit=mode_explicit,
            frozen=frozen,
            route_profile=route_profile,
        )
        # The child preview and its coverage are evaluated from the same immutable parent prefix
        # that the check froze.  This is intentionally before semantic dispatch: a later child
        # sweep cannot alter this check's subject, and no child bundle is opened on this path.
        lineage_evaluation = await _lineage_at_frontier(
            runtime,
            frozen.case.frontier,
            base_coverage=case_coverage(frozen.case),
        )
        # Every check mode gets the same local, privacy-fenced test-edit accounting. Semantic
        # composition may retain a separate encrypted copy for provider review; this reduction
        # stays local so structural findings and totals do not depend on reviewer selection.
        deterministic_test_edit_gaps: tuple[str, ...] = ()
        deterministic_test_edit_support_refs: tuple[EventId, ...] = ()
        deterministic_test_edit_facts: PreExistingTestEdits | None = None
        # Whether the check-time change capture shows any changed path; ``None`` when no capture
        # ran. A no-material-work decision counts only on an observed ``False`` (fail closed):
        # hosts record shell writes as command actions, so edit actions alone cannot prove it.
        workspace_changed: bool | None = None
        # Requested-file facts (#977) read beside the structural capture, through the same fence.
        structural_capture: CheckChangeMetadata | None = None
        structural_source: CheckWorkspaceSource | None = None
        change_capture = getattr(app, "change_capture", None)
        start_catalog = getattr(app, "start_catalog", None)
        recorded_edit = any(
            record.payload is not None and record.payload.action_kind is ActionKind.EDIT
            for record in frozen.case.projection.actions.values()
        )
        if change_capture is not None:
            source = current_check_workspace_source()
            route: TaskRoute | None = None
            resolve_route = getattr(start_catalog, "resolve_route", None)
            if callable(resolve_route):
                try:
                    route = await cast(Callable[[str], Awaitable[TaskRoute | None]], resolve_route)(
                        request.session_id
                    )
                except Exception:
                    route = None
            if (
                source is not None
                and route is not None
                and route.repository_privacy_commitment is not None
            ):
                # Import lazily: check-time capture composes the semantic-case module, which
                # imports this coordinator for its pure scope/policy helpers.
                from finishup.application.check_change import capture_structural_check_change

                capture, unavailable_reason = await capture_structural_check_change(
                    runtime=runtime,
                    source=source,
                    route_repository_commitment=route.repository_privacy_commitment,
                    port=change_capture,
                    clock=app.clock,
                    request_id=request.request_id,
                )
                if capture is not None:
                    structural_capture = capture
                    structural_source = source
                    workspace_changed = bool(
                        capture.entries or capture.tracked_files or capture.untracked_files
                    )
                    test_edit_facts = preexisting_test_edits(
                        capture,
                        frozen.case.projection,
                        task_statement_event_id=(
                            None
                            if frozen.case.task_statement is None
                            else frozen.case.task_statement.equivalent_event_ids
                        ),
                    )
                    deterministic_test_edit_facts = (
                        test_edit_facts if test_edit_facts.baseline_known else None
                    )
                    deterministic_test_edit_gaps = _with_structural_capture_gaps(
                        test_edit_facts.gaps, capture
                    )
                    deterministic_test_edit_support_refs = (
                        test_edit_facts.unjustified_action_event_ids
                    )
                    if (
                        "preexisting_test_edit_unjustified" in deterministic_test_edit_gaps
                        and not deterministic_test_edit_support_refs
                    ):
                        deterministic_test_edit_support_refs = tuple(
                            sorted(
                                {
                                    row.source_event_id
                                    for row in frozen.case.projection.actions.values()
                                    if row.payload is not None
                                },
                                key=str.encode,
                            )[:1]
                        )
                        if not deterministic_test_edit_support_refs and frozen.case.history:
                            deterministic_test_edit_support_refs = (
                                frozen.case.history[-1].event_id,
                            )
                else:
                    # A structural port without metadata-only support, or a metadata read that
                    # failed, must remain visible as unknown.  In particular, never fall back to
                    # its content-returning ``capture`` method just to make this accounting green.
                    # Leave totals unexamined: ``baseline_known=False`` with a synthetic facts
                    # object would incorrectly serialize ``examined=1`` and zero edit counts.
                    deterministic_test_edit_gaps = (PREEXISTING_TEST_BASELINE_UNKNOWN_GAP,)
                    if (
                        unavailable_reason is not None
                        and unavailable_reason != "metadata_unavailable"
                    ):
                        deterministic_test_edit_gaps = tuple(
                            sorted(
                                {
                                    *deterministic_test_edit_gaps,
                                    CHECK_TIME_CHANGE_UNAVAILABLE_GAP,
                                    check_time_change_unavailable_reason_gap(unavailable_reason),
                                },
                                key=str.encode,
                            )
                        )
            elif recorded_edit:
                deterministic_test_edit_gaps = (
                    PREEXISTING_TEST_BASELINE_UNKNOWN_GAP,
                    CHECK_TIME_CHANGE_UNAVAILABLE_GAP,
                )
        elif recorded_edit:
            deterministic_test_edit_gaps = (
                PREEXISTING_TEST_BASELINE_UNKNOWN_GAP,
                CHECK_TIME_CHANGE_UNAVAILABLE_GAP,
            )
        (
            work_evaluator,
            deterministic_output_gaps,
            output_absent,
            output_states,
            output_files,
            prefix_records,
        ) = await _read_declared_outputs(
            runtime,
            request,
            frozen,
            structural_capture,
            structural_source,
            change_capture,
            policy_semantic,
            route_profile,
        )
        if frozen.lease.phase is CheckPhase.RESERVED:
            assessments, executions = run_deterministic_policies(
                frozen.case,
                scope,
                packs,
                evaluators={_WORK_PACK: work_evaluator},
            )
            assessments = assessments + await _coordination_assessments_for_frozen_case(
                app,
                runtime,
                frozen.case,
                scope,
                packs,
            )
            assessments = assessments + _requirement_assessments(
                frozen.case,
                scope,
                executions,
                deterministic_test_edit_support_refs,
                workspace_changed,
            )
            deterministic = allocate_findings(
                app.ids,
                _freshness_candidates(assessments, frozen.case),
                prior_finding_ids(frozen.case.projection),
            )
            frozen = await _publish_deterministic_result(
                app,
                runtime,
                request,
                frozen,
                assessments,
                deterministic,
                executions,
                digest,
            )
        else:
            try:
                checkpoint = await _load_deterministic_result(
                    runtime,
                    request,
                    digest,
                    frozen,
                )
            except _DeterministicCheckpointSuperseded:
                # The checkpoint's bindings verified but its finding wording predates the
                # current text contract. The frozen case is unchanged and digest-verified, so
                # the local phase recomputes from it instead of wedging the request
                # behind a non-retryable STORAGE_CORRUPT (issue #340). The stale checkpoint
                # keeps serving as the durable case pointer until commit clears it.
                record_bounded_counts_without_raising(
                    component="check",
                    operation="deterministic_checkpoint_superseded",
                    outcome="recomputed",
                    request_id=request.request_id,
                    counts={"superseded_checkpoints": 1},
                )
                assessments, executions = run_deterministic_policies(
                    frozen.case,
                    scope,
                    packs,
                    evaluators={_WORK_PACK: work_evaluator},
                )
                assessments = assessments + await _coordination_assessments_for_frozen_case(
                    app,
                    runtime,
                    frozen.case,
                    scope,
                    packs,
                )
                assessments = assessments + _requirement_assessments(
                    frozen.case,
                    scope,
                    executions,
                    deterministic_test_edit_support_refs,
                    workspace_changed,
                )
                deterministic = allocate_findings(
                    app.ids,
                    _freshness_candidates(assessments, frozen.case),
                    prior_finding_ids(frozen.case.projection),
                )
            else:
                deterministic = checkpoint.findings
                executions = checkpoint.executions
        # tb4n1 D3: the reviewer twice in a row could not assess the packet and no edit followed,
        # so this check skips the AI-powered review rather than loop on the same packet.
        # Issue #1046: nor before the first material edit. Either skip runs the local checks only
        # and discloses why; nothing is composed or sent.
        skip_gaps = await _review_skip_gaps(
            runtime,
            request,
            frozen,
            route_profile=route_profile,
            workspace_changed=workspace_changed,
        )
        round_stopped = SEMANTIC_REVIEW_SKIPPED_INSUFFICIENT_PACKET_GAP in skip_gaps
        deferred_before_first_edit = SEMANTIC_REVIEW_DEFERRED_BEFORE_FIRST_EDIT_GAP in skip_gaps
        semantic_wait = _semantic_wait(request, runtime, round_stopped=bool(skip_gaps))
        if semantic_wait and frozen.lease.phase is CheckPhase.LOCAL_READY:
            lease = await runtime.ledger.advance_check_phase(
                frozen.lease,
                CheckPhase.LOCAL_READY,
                CheckPhase.SEMANTIC_WAIT,
            )
            frozen = FrozenCase(frozen.case, lease)
        semantic_result = await _semantic_evaluation_with_follow_up(
            app,
            request,
            runtime,
            frozen,
            deterministic,
            route_profile=route_profile,
            lineage_evaluation=lineage_evaluation,
            round_stopped=round_stopped,
            deferred_before_first_edit=deferred_before_first_edit,
            deterministic_output_gaps=deterministic_output_gaps,
            output_absent=output_absent,
        )
        # Durable AI-powered review attempts may renew the check lease (TTL 60s vs timeout up to 300s).
        if semantic_result.operation_lease is not None:
            frozen = FrozenCase(frozen.case, semantic_result.operation_lease)
        # A check waiting on a local disclosure decision returns here, before ranking, phase
        # advance, or commit. Everything below produces a terminal result, and a terminal result
        # is exactly what makes the human's later approval useless: the operation is closed, the
        # attempt is spent, and there is nothing left to resume. The operation stays in
        # SEMANTIC_WAIT so replaying this same request_id resumes the same request. A one-use
        # decision resumes its exact attempt; a standing-grant handoff has not created one yet.
        if (
            semantic_result.status is SemanticStatus.AWAITING_HUMAN
            and semantic_result.continuation is None
        ):
            # A suspension the caller cannot act on is not a suspension. The attempt runner
            # already terminalizes this case, so reaching here is a coordinator bug: degrade to
            # the ordinary terminal path rather than stranding the check on an unusable branch.
            record_bounded_counts_without_raising(
                component="check",
                operation="semantic_awaiting_human_without_continuation",
                outcome="internal_error",
                counts={"suspensions_without_continuation": 1},
                request_id=request.request_id,
            )
            semantic_result = replace(
                semantic_result,
                status=SemanticStatus.FAILED,
                reason=SemanticReason.COORDINATOR_FAILURE,
            )
        if semantic_result.status is SemanticStatus.AWAITING_HUMAN:
            assert semantic_result.continuation is not None
            if semantic_result.continuation.kind == REPOSITORY_GRANT_CONTINUATION_KIND:
                # No provider job or attempt exists for a missing standing grant. Expire this
                # operation lease before returning so exact same-request replay can reclaim it
                # immediately after the trusted ceremony (or reproduce the same handoff before
                # approval) without opening a fresh check.
                await runtime.ledger.suspend_check_for_repository_grant(frozen.lease)
            elif semantic_result.continuation.kind == REVIEW_INPUT_CONTINUATION_KIND:
                # A statement-bearing plan amends input within the existing session. Park the
                # operation and release its observation barrier so the amendment can converge
                # on the same request identity without replacing its session or writer.
                await runtime.ledger.suspend_check_for_review_input(frozen.lease)
            return CheckAwaitingHuman(
                runtime.task_id,
                request.session_id,
                request.writer_id,
                request.request_id,
                frozen.case.frontier,
                frozen.case.frontier,
                semantic_result.continuation,
                CheckVersionSlice("0.1", ENGINE_VERSION, PROJECTION_VERSION, packs),
                semantic_result.specification_preflight,
                state=(
                    "awaiting_input"
                    if semantic_result.continuation.kind == REVIEW_INPUT_CONTINUATION_KIND
                    else "awaiting_human"
                ),
            )
        review = _EMPTY_SEMANTIC_REVIEW
        if semantic_result.status is SemanticStatus.SUCCEEDED:
            assert semantic_result.judgment is not None
            assert semantic_result.provenance is not None
            try:
                review = validate_semantic_judgment(
                    frozen.case,
                    deterministic,
                    semantic_result.judgment,
                    semantic_result.provenance,
                    expected_frontier=frozen.case.frontier,
                    capture_baseline_gaps=semantic_capture_baseline_gaps(semantic_result),
                    prior_finding_refs=semantic_result.case_prior_finding_refs,
                    citable_refs=semantic_result.case_citable_refs,
                    provider_input_text_by_ref=semantic_result.provider_input_text_by_ref,
                    settled_finding_refs=semantic_result.case_settled_finding_refs,
                    review_phase=_review_phase(request, frozen, semantic_result),
                    # Review of #1043 x #1049: a run the agent linked to a requested command is
                    # the declared verification. A prefix that could not be read leaves the links
                    # unknown, and then no challenge is narrowed to the agent's own criterion.
                    agent_linked_runs=(
                        agent_linked_run_events(frozen.case.projection, prefix_records)
                        if prefix_records
                        else None
                    ),
                    # #1162 tracked advice: the frozen prefix's advisory rows, so a repeat with
                    # no newer material folds onto its earlier identity (replay-pure).
                    prior_advisories=correctness_advisory_index(prefix_records).rows,
                )
            except SemanticJudgmentRejected as exc:
                # The reviewer's answer is unusable, so the check has no AI-powered review result — but the
                # local findings below were already earned and must still be committed.
                record_unexpected_exception_without_raising(
                    exc,
                    component="check",
                    operation="semantic_judgment_rejected",
                    request_id=request.request_id,
                )
                semantic_result = _judgment_rejected_evaluation(semantic_result)
        semantic = allocate_findings(app.ids, review.candidates)
        coverage = case_coverage(
            frozen.case,
            semantic=semantic_result.status is SemanticStatus.SUCCEEDED,
        )
        coverage = weakest(coverage, lineage_evaluation.coverage)
        policy_failed = any(item.outcome == "failed" for item in executions)
        semantic_failed = semantic_result.status not in {
            SemanticStatus.NOT_REQUESTED,
            SemanticStatus.SUCCEEDED,
        }
        semantic_gap = _check_semantic_gap(
            request.mode,
            policy_semantic,
            semantic_result,
            route_profile=route_profile,
            host_profile=host_profile,
            _state=_state,
        )
        declared_gaps, recorded_deliverables = _initial_declared_gaps(
            semantic_gap,
            (deterministic_test_edit_gaps, deterministic_output_gaps),
            semantic_result,
            output_states,
            output_files,
        )
        missing = _EMPTY_MISSING_ITEMS
        if (
            semantic_result.status is SemanticStatus.SUCCEEDED
            and semantic_result.judgment is not None
            and semantic_result.judgment.conclusion == "insufficient_packet"
        ):
            declared_gaps.add(SEMANTIC_PACKET_INSUFFICIENT_GAP)
            # Issue #907: what the reviewer named, fenced to the case and classified by FinishUP.
            # The gaps below are check limitations, never findings or a clean review.
            missing = review_missing_for_assessment(
                frozen.case,
                deterministic,
                semantic_result.judgment,
                unsuppliable_kinds=frozenset(semantic_result.unsuppliable_missing_kinds),
                citable_refs=semantic_result.case_citable_refs,
                captured_edit_paths=semantic_result.case_captured_edit_paths,
                workspace_root=semantic_result.case_workspace_root,
                binary_paths=semantic_result.case_binary_paths,
                text_paths=semantic_result.case_text_paths,
                excerpt_refs=semantic_result.case_excerpt_refs,
                excerpt_parts=semantic_result.case_excerpt_parts,
                **_packet_limits(semantic_result, deterministic),
            )
            declared_gaps |= missing.gaps
        if (
            route_profile == "strict"
            and semantic_result.status is SemanticStatus.BLOCKED_BY_POLICY
            and semantic_result.reason is SemanticReason.ROUTE_SEMANTIC_CEILING
            and _strict_ceiling_route_drift(host_profile=host_profile, _state=_state)
        ):
            # The ceiling still blocks this process with the same status, reason, and null
            # provenance. The extra gap is the structural route_drift detail — applied policy
            # serving strict — and the receipt names the recovery; a genuinely applied
            # strict route keeps today's terminal wording exactly.
            declared_gaps.add(OPTIONAL_SEMANTIC_REVIEW_REGISTRATION_DRIFT_GAP)
        declared_gaps |= (
            carried_semantic_attempt_gaps(frozen.case, semantic_result.status) | skip_gaps
        )
        # A review that ran without material its own profile selected is not full coverage, even
        # though it reports succeeded. Saying so here is what stops a hollow review from reading
        # as a clean one in the check result and the receipt derived from it.
        if (
            semantic_result.status is SemanticStatus.SUCCEEDED
            and semantic_result.withheld_review_categories
        ):
            declared_gaps.add(SEMANTIC_REVIEW_CONTEXT_WITHHELD_GAP)
        declared_gaps |= _credential_heuristic_gaps(semantic_result)
        if semantic_result.semantic_withheld_item_ids:
            # Item-level withholding is an egress decision about what the external model may see.
            # It bounds only this AI-powered review (issue #982, owner decision B2), so it is the
            # review-scoped code and never ``content_redacted``, which would also veto local proof.
            declared_gaps.add(SEMANTIC_REVIEW_ITEM_WITHHELD_GAP)
        if (
            semantic_result.status is SemanticStatus.SUCCEEDED
            and semantic_result.provider_input_manifest is None
        ):
            # A composed manifest describes pre-admission selection and cannot stand in for the
            # exact bytes that crossed the provider boundary (#965).  Keep the success result and
            # disclose the bounded provenance loss instead.
            declared_gaps.add(
                semantic_result.provider_input_manifest_failure
                or SEMANTIC_PROVIDER_INPUT_MANIFEST_MISSING_GAP
            )
        declared_gaps.update(_review_fence_gaps(review))
        # Recorded prose the case could not carry whole. The reviewer answered on a fragment, and
        # the author has no other signal that the text they published never arrived (issue #177).
        declared_gaps.update(semantic_result.case_content_gaps)
        if semantic_result.case_content_over_item_limit:
            declared_gaps.add(SEMANTIC_CASE_CONTENT_OVER_ITEM_LIMIT_GAP)
        if semantic_result.case_reference_scope_reduced:
            declared_gaps.add(SEMANTIC_REFERENCE_SCOPE_REDUCED_GAP)
            if (
                semantic_result.status is SemanticStatus.SUCCEEDED
                and semantic_result.judgment is not None
                and semantic_included_refs(semantic_result) is None
            ):
                # The reduced review completed but its sent content could not be recorded, so
                # no AI-powered finding can be resolved by it; say so rather than fail silently.
                declared_gaps.add(SEMANTIC_INCLUDED_REFS_NOT_RECORDED_GAP)
        new_gaps = declared_gaps - set(coverage.known_gaps)
        if new_gaps:
            gaps = set(coverage.known_gaps) | new_gaps
            freshness = coverage.ledger_freshness
            if freshness is LedgerFreshness.CURRENT:
                freshness = LedgerFreshness.PARTIAL
            coverage = replace(
                coverage,
                ledger_freshness=freshness,
                known_gaps=tuple(sorted(gaps, key=str.encode)),
            )
        # Build the scope gate from the same frozen case and every candidate before the public
        # finding cap.  This keeps suppressed actionable findings, unattempted requested items,
        # open obligations and relevant live failures from being hidden by a short result list.
        candidate_findings = deterministic + semantic
        # The route this check records decides whether a missing review and the review's own
        # bounds are limits or only disclosures: the same value the receipt reads back.
        route_requires_review, reviewer_reported_insufficiency = _route_and_insufficiency(
            request.mode,
            policy_semantic,
            route_profile=route_profile,
            host_profile=host_profile,
            state=_state,
            known_gaps=coverage.known_gaps,
        )
        scoped_local_clean = (
            request.mode == "deterministic_only"
            and not policy_failed
            and deterministic_scope_is_clean(
                coverage=coverage,
                totals=build_check_totals(
                    frozen.case,
                    candidate_findings,
                    test_edits=deterministic_test_edit_facts,
                ),
                findings=candidate_findings,
                route_requires_review=route_requires_review,
            )
        )
        completion_scope_incomplete = bool(
            {COMPLETION_SCOPE_DECLARED_NONE_GAP, COMPLETION_SCOPE_UNDECLARED_GAP}
            & set(coverage.known_gaps)
        )
        if completion_scope_incomplete:
            # Completion scope is the subject-level boundary named by ADR-019. Even a separately
            # incomplete required AI-powered review attempt cannot turn either closed scope gap into the
            # broader incomplete-check verdict.
            completeness = CheckCompleteness.COVERAGE_INCOMPLETE
        elif policy_failed or (
            request.mode == "semantic_required"
            and (semantic_failed or SEMANTIC_REVIEW_SKIPPED_INSUFFICIENT_PACKET_GAP in skip_gaps)
        ):
            # #1118 unit 4 (AIM-5): a required review the round limits stopped was not satisfied;
            # the check is incomplete, never a local fallback or success.
            completeness = CheckCompleteness.REQUIRED_INCOMPLETE
        elif scoped_local_clean:
            completeness = CheckCompleteness.SCOPED_COMPLETE
        elif semantic_failed or not _full_check_is_complete(
            coverage.known_gaps,
            build_check_totals(
                frozen.case, candidate_findings, test_edits=deterministic_test_edit_facts
            ),
            candidate_findings,
            route_requires_review=route_requires_review,
            review_succeeded=semantic_result.status is SemanticStatus.SUCCEEDED,
            reviewer_reported_insufficiency=reviewer_reported_insufficiency,
        ):
            completeness = (
                CheckCompleteness.COVERAGE_INCOMPLETE
                if coverage.known_gaps
                # A returned coverage-only finding is itself the disclosed reason; no gap names it.
                else CheckCompleteness.SCOPED_COMPLETE
            )
        else:
            completeness = CheckCompleteness.COMPLETE
        maximum = (
            app.verification_policy.max_findings
            if request.max_findings is None
            else int(request.max_findings)
        )
        ranked = rank_findings(
            deterministic,
            semantic,
            RankingContext(coverage, completeness),
            maximum,
        )
        _record_semantic_review_accounting(
            request,
            semantic_result,
            review,
            semantic,
            ranked,
        )
        if frozen.lease.phase is not CheckPhase.READY_TO_FINALIZE:
            lease = await runtime.ledger.advance_check_phase(
                frozen.lease,
                CheckPhase.SEMANTIC_WAIT if semantic_wait else CheckPhase.LOCAL_READY,
                CheckPhase.READY_TO_FINALIZE,
            )
            frozen = FrozenCase(frozen.case, lease)
        semantic_conclusion = (
            semantic_result.judgment.conclusion
            if semantic_result.status is SemanticStatus.SUCCEEDED
            and semantic_result.judgment is not None
            else None
        )
        from finishup.application.semantic_case import review_input_manifest_to_json

        recorded_manifest: JsonObject | None = semantic_result.provider_input_manifest
        if (
            recorded_manifest is None
            and semantic_result.status is not SemanticStatus.SUCCEEDED
            and semantic_result.review_input_manifest is not None
        ):
            recorded_manifest = cast(
                JsonObject,
                freeze_json(review_input_manifest_to_json(semantic_result.review_input_manifest)),
            )
        commit_kwargs: dict[str, Any] = {
            "scope": CheckScopeModel(
                claim_ids=scope.claim_ids, obligation_ids=scope.obligation_ids
            ),
            "semantic_conclusion": semantic_conclusion,
            "correctness_advisories": review.correctness_advisories,
            "review_summary": (
                review.review_summary
                if semantic_result.status is SemanticStatus.SUCCEEDED
                else None
            ),
            "verified": (
                tuple(
                    JsonObject(
                        {
                            "requirement_or_claim": item.requirement_or_claim,
                            "verdict": item.verdict,
                            "cited_refs": item.cited_refs,
                            **({} if item.snippet is None else {"snippet": item.snippet}),
                        }
                    )
                    for item in review.verified
                )
                if semantic_result.status is SemanticStatus.SUCCEEDED
                else ()
            ),
            # Recorded only beside a conclusion: resolution reads it from completed reviews only.
            "check_change_files": (
                None if semantic_conclusion is None else semantic_result.check_change_files
            ),
            "prior_finding_verdicts": (
                review.verdicts if semantic_result.status is SemanticStatus.SUCCEEDED else ()
            ),
            "missing_for_assessment": missing.items,
            "semantic_included_refs": semantic_included_refs(semantic_result),
            "semantic_withheld_item_ids": semantic_result.semantic_withheld_item_ids,
            "semantic_redacted_values": semantic_result.semantic_redacted_values,
            # Issue #986: record the route, never block on it here. Only a route that did not
            # require review is written (``False``); a requiring route keeps today's bytes.
            "semantic_route_required": _recorded_route_required(
                request.mode,
                policy_semantic,
                route_profile=route_profile,
                host_profile=host_profile,
                _state=_state,
            ),
            "review_mode": check_review_mode,
            # ADR-045: how each declared output file stood at this check and what was concluded
            # from it and from the earlier checks of the same path; empty when none was read.
            "deliverable_states": recorded_deliverables,
            "review_input_manifest": recorded_manifest,
            "reviewer": _reviewer_wire(semantic_result.reviewer),
            "totals": build_check_totals(
                frozen.case,
                candidate_findings,
                ranked.suppressed_count,
                deterministic_test_edit_facts,
            ),
        }
        commit_parameters: Mapping[str, inspect.Parameter] = {}
        try:
            commit_parameters = inspect.signature(runtime.ledger.commit_check_if_current).parameters
        except (TypeError, ValueError):
            commit_parameters = {}
        if commit_parameters and not any(
            parameter.kind is inspect.Parameter.VAR_KEYWORD
            for parameter in commit_parameters.values()
        ):
            commit_kwargs = {
                key: value for key, value in commit_kwargs.items() if key in commit_parameters
            }
        committed = await runtime.ledger.commit_check_if_current(
            frozen,
            ranked,
            executions,
            semantic_result.status,
            semantic_result.reason,
            semantic_result.provenance,
            request.request_id,
            **commit_kwargs,
        )
        preview = _lineage_preview(lineage_evaluation, frozen.case.frontier)
        projected = committed if preview is None else replace(committed, children=preview)
        projected = _with_fact_lineage(projected, frozen.case, prefix_records)
        projected = await _attach_finding_checklist(
            app,
            runtime,
            projected,
            coverage_by_ref=frozen.case.coverage_by_ref,
            route_profile=route_profile,
        )
        # Advice is deliberately attached after the deterministic commit.  It is current
        # projection context, never part of the frozen check event or its verdict calculation.
        return await _attach_current_project_advisory_notes(app, runtime.task_id, projected)
    except PublicOperationError as exc:
        if frozen is not None and not exc.retryable:
            try:
                await runtime.ledger.fail_check_if_current(frozen.lease, exc)
            except Exception as terminalize_exc:
                record_unexpected_exception_without_raising(
                    terminalize_exc,
                    component="check",
                    operation="check_pipeline_terminalization_failed",
                    request_id=request.request_id,
                )
        raise
    except Exception as exc:
        # The request is already a validated CheckRequest. Any protocol-value failure raised from
        # this pipeline is therefore an implementation/storage defect, not malformed caller input.
        # Close an admitted operation before surfacing the internal error so exact replay and
        # status never wait forever on work this invocation has abandoned.
        record_unexpected_exception_without_raising(
            exc,
            component="check",
            operation="check_pipeline_failed",
            request_id=request.request_id,
        )
        failure = PublicOperationError(
            PublicErrorCode.INTERNAL_ERROR,
            "The check hit an internal failure (stage: check pipeline) and may not have produced "
            "a verdict. Replay the same request_id once: a check that committed returns its "
            "stored verdict. If the replay fails the same way, run check again under a new "
            "request_id. The correlation_id resolves the failure in the service diagnostics.",
            False,
            safe_details={"reason_code": "check_pipeline_failed"},
        )
        if frozen is not None:
            try:
                await runtime.ledger.fail_check_if_current(frozen.lease, failure)
            except Exception as terminalize_exc:
                record_unexpected_exception_without_raising(
                    terminalize_exc,
                    component="check",
                    operation="check_pipeline_terminalization_failed",
                    request_id=request.request_id,
                )
        raise failure from exc
    finally:
        await app.runtime.release(runtime)


async def execute_check(
    app: Application,
    request: CheckRequest,
    *,
    route_profile: Literal["policy", "strict"] = "policy",
    host_profile: McpHostProfile = "generic",
    _state: Path | None = None,
    mode_explicit: bool | None = None,
) -> CheckCommitResult | CheckAwaitingHuman | CheckInspection:
    """Return the closed sink-independent result for the facade's sole projection step.

    ``mode_explicit`` is whether the caller named the mode; ``None`` reads it from the request.
    """

    if request.mode == "inspect":
        # ADR-047: a read, routed like status. It never enters the commit pipeline below, so it
        # freezes no case, records no event and dispatches no reviewer.
        from finishup.application.check_inspection import execute_check_inspection

        return await execute_check_inspection(
            cast("CheckInspectionApplication", app), request, route_profile=route_profile
        )
    # Omitted mode resolves via policy so recorded check events always carry a concrete mode.
    if mode_explicit is None:
        mode_explicit = request.mode is not None
    if request.mode is None:
        request = request.model_copy(update={"mode": app.verification_policy.default_check_mode})
    return await execute_check_commit(
        app,
        request,
        route_profile=route_profile,
        host_profile=host_profile,
        _state=_state,
        mode_explicit=mode_explicit,
    )
