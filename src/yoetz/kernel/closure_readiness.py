"""Closed classification of coverage gap codes for closure readiness (ADR-032).

Closure readiness answers one question for the agent: is there anything left that *it* can do, or
is every remaining condition a limitation that the receipt will disclose? A gap code answers that
only through this table. Each code the product can emit is assigned exactly once:

* ``agent_actionable`` — a documented agent action (publish, respond, revise a claim or plan,
  recheck after a material change, or re-read status once the service catches up) removes it.
* ``standing_limitation`` — no agent action available under the current host, profile and privacy
  policy removes it. It describes the bounds of observation, capture, review or the ledger — a
  deliberate selection or a capture failure — and is disclosed on the receipt; it is never an
  instruction.
* ``route_dependent`` — only ``semantic_review_not_requested``: standing on a route where
  AI-powered review is optional or off, and on a strict MCP route, which never dispatches
  AI-powered review (ADR-018) whatever the repository policy says. It is actionable only on a
  route that requires AI-powered review and can dispatch it, when none has completed since the
  last material change (remedy: run it).

The table is a closed, versioned vocabulary rather than a heuristic. A conformance test
(``tests/conformance/honesty/test_gap_classification_completeness.py``) enumerates every gap-code
producer in the codebase and fails when one emits a code this table does not classify, so a new
code cannot ship unclassified. A code the running build does not know (for example one read from a
ledger written by a newer build) is reported as ``unclassified_gap:<code>`` in the agent-actionable
group: the conservative default stays visible instead of silently masking a missing entry.

Classification never removes, renames or weakens a gap. Coverage ``known_gaps``, receipts and
verdicts are unchanged; this module only decides which readiness group names the code.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Final, Literal, cast

from yoetz.domain.events import CheckRecordedPayload, LedgerRecord
from yoetz.domain.receipts import (
    CHECK_TIME_CHANGE_UNAVAILABLE_REASON_GAPS,
    COMPLETION_PLAN_NOT_CLAIMED_GAP,
)
from yoetz.domain.values import EventId, FindingId, ObligationId
from yoetz.kernel import finding_todo as _finding_todo_module
from yoetz.kernel.claim_limitations import required_limitation_ids_for_projection
from yoetz.kernel.claims import completion_claim_present
from yoetz.kernel.finding_resolution import finding_is_resolved
from yoetz.kernel.finding_todo import (
    FindingTodoState,
    duplicate_counting_id,
    finding_blocks_receipt,
    finding_todo_state,
)
from yoetz.kernel.observed_failures import observed_event_ids_from_records
from yoetz.kernel.plan_drift import PLAN_DRIFT_ADVISORY_GAPS, PLAN_DRIFT_GAPS
from yoetz.kernel.plan_scope import current_plan_scope
from yoetz.kernel.projections import ProjectionState, observation_limitation_finding_ids
from yoetz.kernel.receipt_capacity import current_receipt_findings
from yoetz.kernel.reducers import invalidates_recorded_check
from yoetz.kernel.review_round import review_round_stopped
from yoetz.kernel.task_facts import (
    AGENT_ACTIONABLE_TASK_FACT_GAPS,
    OBLIGATION_BLOCKED_GAP,
    OBLIGATION_BLOCKER_UNCONFIRMED_GAP,
    STANDING_TASK_FACT_GAPS,
    acknowledged_obligation_ids,
    blocker_declarations,
    decision_batches,
    disclosure_declarations,
    open_effective_obligations,
)
from yoetz.protocol.models import SemanticStatus

# L5's D7 predicate (#984, D7a), looked up by name so this module works on a build without it:
# absent, nothing is reported as disputed. Tests monkeypatch this attribute.
_standing_premise_disputes: Callable[[ProjectionState], Iterable[object]] | None = cast(
    "Callable[[ProjectionState], Iterable[object]] | None",
    getattr(_finding_todo_module, "standing_premise_disputes", None),
)

__all__ = [
    "ACKNOWLEDGED_NOT_DONE",
    "AGENT_READINESS_CONDITIONS",
    "ASSUMPTION_DISCLOSED_GAP",
    "FINDING_PREMISE_DISPUTED_GAP",
    "premise_disputed_finding_ids",
    "VERIFICATION_LIMIT_DISCLOSED_GAP",
    "FINDING_SELF_VERIFIED_GAP",
    "GAP_CLASSIFICATION",
    "GAP_CLASSIFICATION_VERSION",
    "MAX_ACKNOWLEDGED_READINESS_ITEMS",
    "READINESS_CHECK_CONDITIONS",
    "UNCLASSIFIED_GAP_PREFIX",
    "CheckApplicability",
    "ClosureReadinessFacts",
    "ClosureReadinessSplit",
    "GapClass",
    "GapSplit",
    "classify_gap",
    "closure_readiness_facts",
    "derive_closure_readiness",
    "finding_acknowledged_not_done",
    "gap_base_code",
    "live_lineage_blockers",
    "split_gaps",
]

# Bump when any assignment below changes meaning. Status responses carry the version so a reader
# can tell which table classified a recorded readiness answer. "2": the task-statement gap
# ``instruction_requirement_unmapped`` became agent-actionable and the previously unclassified
# ``compound_outcome_unavailable`` became a standing limitation. "3": the standing readiness code
# ``finding_self_verified`` (issue #984, ADR-034) was added. "4": the standing disclosure codes
# ``assumption_disclosed`` and ``verification_limit_disclosed`` (issue #995, ADR-033) and
# ``finding_premise_disputed`` (issue #984, D7a) were added.
GAP_CLASSIFICATION_VERSION: Final = "4"
# Issue #984 (ADR-034): a current finding the agent answered ``self_verified``. Yoetz could not
# prove the repair; the agent verified it itself. Disclosed, never agent work.
FINDING_SELF_VERIFIED_GAP: Final = "finding_self_verified"
# Issue #995 (ADR-033): a recorded ``yoetz-assumption:`` / ``yoetz-verification-limit:`` decision
# line on an obligation. A disclosure, never a blocker and never agent work.
ASSUMPTION_DISCLOSED_GAP: Final = "assumption_disclosed"
VERIFICATION_LIMIT_DISCLOSED_GAP: Final = "verification_limit_disclosed"
# Issue #984 (D7a): the agent answered ``acknowledged_not_done`` on an AI-powered finding whose
# challenge says the task itself requires the work. Terminal, so never agent work: disclosed, and
# the Stop gate asks once.
FINDING_PREMISE_DISPUTED_GAP: Final = "finding_premise_disputed"
_DISCLOSURE_CODES: Final[Mapping[str, str]] = MappingProxyType(
    {"assumption": ASSUMPTION_DISCLOSED_GAP, "verification_limit": VERIFICATION_LIMIT_DISCLOSED_GAP}
)
UNCLASSIFIED_GAP_PREFIX: Final = "unclassified_gap:"

_CODE_RE: Final = re.compile(r"^[a-z][a-z0-9_]{0,127}$", re.ASCII)
# Markers that wrap a base code in a named envelope: ``coverage:<code>`` (finding resolution),
# ``check_coverage:<code>``, ``retained_finding_coverage:<code>``, ``semantic_outcome:<code>``
# (receipt case gaps) and ``lineage:<code>:<child>:<event>`` (receipt lineage gaps). Every other
# ``<code>:<subject...>`` marker (``unknown_event:``, ``missing_ref:``, ``redacted_event:``,
# ``completion_scope_undeclared:<event>``) already leads with its base code.
_WRAPPER_PREFIXES: Final = frozenset(
    {"check_coverage", "coverage", "lineage", "retained_finding_coverage", "semantic_outcome"}
)


class GapClass(str, Enum):  # noqa: UP042 - exact internal contract token
    AGENT_ACTIONABLE = "agent_actionable"
    STANDING_LIMITATION = "standing_limitation"
    ROUTE_DEPENDENT = "route_dependent"


_A: Final = GapClass.AGENT_ACTIONABLE
_S: Final = GapClass.STANDING_LIMITATION
_R: Final = GapClass.ROUTE_DEPENDENT

GAP_CLASSIFICATION: Final[Mapping[str, GapClass]] = MappingProxyType(
    {
        # -- Host observation (ObservationGapCode and the local observation store). Recorded into
        # the coverage of the observed rows; host-profile, consent, capture-profile and delivery
        # facts that no agent action rewrites.
        "unpaired_event": _S,  # host pairing loss; sticky by design (#917 owns its surfacing)
        "unsupported_event": _S,
        "unsupported_format": _S,
        "truncated_payload": _S,  # capture failure: bounded capture or packet truncation (#904)
        "service_unavailable": _S,
        "vault_locked": _S,
        "ledger_rejected": _S,
        "dedup_conflict": _S,
        "cursor_stale": _S,
        "consent_missing": _S,
        "consent_revoked": _S,
        "source_lag": _S,
        "mapping_missing": _S,
        "missing_subagent_identity": _S,
        "session_superseded": _S,
        "outbox_overflow": _S,
        "observation_input_loss": _S,
        "outbox_quarantined": _S,
        "observation_storage_corrupt": _S,
        "quarantine_detail_evicted": _S,
        "content_capture_unavailable": _S,  # consent or capture profile
        "capture_budget_exhausted": _S,
        "content_capture_profile_mismatch": _S,
        "content_unselected": _S,  # deliberate selection: the policy chose not to capture
        "content_redacted": _S,  # capture-time redaction of a high-confidence secret shape
        "routine_read_detail_omitted": _S,
        "routine_read_summary_invalid": _S,
        "routine_summary_invalid": _S,
        "payload_too_large": _S,
        "payload_content_omitted": _S,
        "selection_route_changed": _S,
        "policy_untrusted": _S,
        "verification_stale": _S,
        "network_check_unsupported": _S,
        "pending_attempt_expired": _S,  # open pre-events pruned by TTL or generation fence
        "pending_attempt_limit": _S,
        "optional_observation_detail_omitted": _S,
        "drain_diagnostic_unavailable": _S,
        "host_outcome_unavailable": _S,  # the host did not state an outcome (#910)
        # A piped or chained command reports one exit status for several commands, so the
        # observer cannot attribute an outcome; no agent action rewrites the recorded row.
        "compound_outcome_unavailable": _S,
        # -- Background observation advice: pipeline state, not an agent task (#923).
        "advice_coverage_gaps_truncated": _S,
        "advice_evidence_refs_truncated": _S,
        "advice_ranked_findings_truncated": _S,
        "advice_semantic_deferred": _S,
        "advice_semantic_output_invalid": _S,
        "advice_semantic_pending": _S,
        "advice_semantic_text_truncated": _S,
        "advice_semantic_unavailable": _S,
        "observation_qualified_partial": _S,
        # -- Completion scope (ADR-019). A scope difference is repaired by the agent: claim the
        # omitted plan item, revise the plan or claim, declare obligations, or acknowledge the
        # obligation as not done. An explicit "no obligations" declaration is the agent's own
        # recorded choice and stays a disclosure.
        "completion_plan_not_claimed": _A,
        "completion_claim_outside_plan": _A,
        "completion_scope_undeclared": _A,
        "completion_scope_declared_none": _S,
        # -- Check applicability. A missing or superseded check is removed by running a check
        # after the material change; a check that only trails attributable answers and
        # observations is a disclosure (real material staleness reads check_not_applicable).
        "check_not_recorded": _A,
        "check_not_applicable": _A,
        # A readiness condition rather than a recorded gap: a check holds the session frontier
        # right now, so its result (and any finding it returns) is still to come.
        "check_in_progress": _A,
        # Issue #976: AI-powered review is required or in use on this task and no closing
        # review (final phase, with or without a completion claim) is current since the last
        # material change. Removed by `check` with `final_review: true`.
        "closing_review_required": _A,
        "check_current_as_of_earlier_frontier": _S,
        "check_payload_unavailable": _S,
        # -- AI-powered review outcome and packet bounds: disclosure of how the review was bounded.
        "semantic_review_not_requested": _R,
        # Plan drift is a diagnostic about the quality of the recorded planning trace.  The
        # advisory codes are deliberately standing: a refinement may remove them, but their
        # presence never turns a receipt into an agent-actionable closure blocker by itself.
        **{code: _S for code in sorted(PLAN_DRIFT_ADVISORY_GAPS)},
        # A recorded task statement that no effective obligation cites in source_refs is agent
        # work (TB4 pilot): decompose the request into statement-sourced obligations, or revise
        # the plan to an explicit empty scope. Yoetz checks the link, never the request prose.
        "instruction_requirement_unmapped": _A,
        # Test-edit accounting is structural and path-private.  A baseline gap is a standing
        # limit; an unjustified edit remains agent-actionable until an explicit action/path
        # decision is recorded.
        "preexisting_test_baseline_unknown": _S,
        "preexisting_test_modified": _S,
        "preexisting_test_renamed": _S,
        "preexisting_test_deleted": _S,
        "preexisting_test_skipped": _S,
        "preexisting_test_skip_unknown": _S,  # path metadata only: skip markers unreadable
        "preexisting_test_edit_unjustified": _A,
        "semantic_review_not_configured": _S,
        "semantic_relevance_review_not_run": _S,  # provider or evaluator failure
        "semantic_review_context_withheld": _S,
        # Egress-only privacy redaction of the review packet (#982): bounds the review, never the
        # agent's work. Never ask the agent to reveal the value or widen consent to clear it.
        "semantic_review_value_redacted": _S,
        "semantic_review_item_withheld": _S,
        # Owner opt-out (#982): the policy disabled the low-confidence credential heuristic, so the
        # review saw more, not less. A disclosure, never agent work.
        "semantic_review_credential_heuristic_disabled": _S,
        "semantic_packet_insufficient": _S,  # agent-suppliable items arrive as findings (#907)
        # #907: what an insufficient_packet review named as missing. Only an item the agent can
        # supply is agent work; the rest disclose how the review was bounded.
        "semantic_missing_agent_suppliable": _A,
        "semantic_missing_structurally_unavailable": _S,
        "semantic_missing_yoetz_limit": _S,  # tb4n1 D1: Yoetz cannot show it; self-verify
        "semantic_missing_already_supplied": _S,
        "semantic_missing_items_rejected": _S,
        "semantic_missing_non_convergent": _S,
        # tb4n1 D3: the reviewer twice could not assess the same content; the round stopped.
        "semantic_review_skipped_insufficient_packet": _S,
        "semantic_provider_input_manifest_missing": _S,
        "semantic_provider_input_manifest_invalid": _S,
        "semantic_provider_input_manifest_parse_failed": _S,
        "semantic_provider_input_manifest_mismatch": _S,
        "semantic_provider_input_manifest_recovery_failed": _S,
        "semantic_challenges_rejected": _S,  # reviewer output dropped by the validation fence
        "semantic_review_snippet_invalid": _S,  # provider quote could not be proved against sent text
        "semantic_review_refs_reduced": _S,  # reviewer citations of unsent refs removed (#976)
        "semantic_case_content_over_item_limit": _S,  # packet item bound (#907)
        "semantic_case_finding_refs_over_limit": _S,
        # #904: what a reduced review sent could not be recorded; one new check is the remedy only
        # when the agent has recorded and cited its repair evidence, so it is disclosed, not a task.
        "semantic_included_refs_not_recorded": _S,
        "semantic_prior_findings_over_limit": _S,  # prior-findings packet bound (#905)
        "semantic_prior_verdicts_unsupported": _S,  # reviewer rulings dropped by the fence (#905)
        "semantic_restatements_suppressed": _S,  # duplicate re-raises folded into one item (#905)
        # #908: what the reviewer knew of the user's request. Withholding is the owner's policy;
        # a missing statement is agent work through a same-session statement-carrying plan event.
        "task_statement_unavailable": _S,
        "task_statement_not_authorized": _S,
        "task_statement_not_supplied": _A,
        # ADR-031: the service's own check-time read of the repository. Every limit on it is the
        # service's (capture, Git state, redaction, packet room), not work the agent can redo.
        "check_time_change_unavailable": _S,
        "check_time_change_base_unavailable": _S,
        "check_time_change_truncated": _S,
        "check_time_change_redacted": _S,
        "check_time_change_resolution_unverified": _S,
        # Each closed unavailability reason travels beside the generic code with the same class.
        **{code: _S for code in sorted(CHECK_TIME_CHANGE_UNAVAILABLE_REASON_GAPS)},
        "semantic_case_capacity_exceeded": _S,
        "semantic_reference_scope_reduced": _S,  # deliberate selection: bounded review scope (#904)
        "optional_semantic_review_blocked_by_policy": _S,
        "optional_semantic_review_registration_drift": _S,  # owner reinstall, not the agent
        # -- Ledger and evidence facts found by the deterministic case.
        "unknown_event": _S,  # written by a newer build
        "redacted_event": _S,  # capture failures: the recorded payload or object is unreadable
        "redacted_object": _S,
        "event_payload_unavailable": _S,
        "captured_object_unavailable": _S,
        "missing_ref": _A,  # publish the referenced record or supersede the reference
        "evidence_content_digest_only": _S,  # provenance label (#912)
        "evidence_content_withheld": _S,
        "evidence_digest_subject_legacy_unknown": _S,
        "unknown_event_schema_preserved": _S,
        # -- Command attempts: an uncorroborated command has no observable command identity
        # (#909); a mismatch is removed by running the requested command or correcting the
        # assertion.
        "command_attempt_uncorroborated": _S,
        "command_attempt_mismatch": _A,
        # -- Findings the agent self-verified because a Yoetz limit kept the repair unproven
        # (issue #984). Final and disclosed; no agent action removes it.
        FINDING_SELF_VERIFIED_GAP: _S,
        # -- The agent's own disclosures (issue #995): a best-effort assumption or a check it
        # inherently cannot run, recorded on an obligation. Disclosed; no agent action removes it.
        ASSUMPTION_DISCLOSED_GAP: _S,
        VERIFICATION_LIMIT_DISCLOSED_GAP: _S,
        # Acknowledged-not-done findings the reviewer says the task requires (D7a). Final
        # answers, so standing; the Stop gate asks about them once.
        FINDING_PREMISE_DISPUTED_GAP: _S,
        # -- Lineage (ADR-027). Child work, child verification and a check that has not covered
        # the latest manifest are actionable; unreadable, restricted or terminal child facts are
        # disclosures. A manifest that trails the catalog is refreshed by the service, so, like
        # ``projection_stale``, the remedy is to re-read status rather than a standing limit.
        "lineage_child_actionable_finding": _A,
        "lineage_child_open": _A,
        "lineage_child_incomplete": _A,
        "lineage_child_check_stale": _A,
        "lineage_child_verification_unknown": _A,
        "lineage_child_check_frontier_unknown": _S,
        "lineage_child_coverage_gap": _S,
        "lineage_child_frontier_unknown": _S,
        "lineage_child_provenance_restricted": _S,
        "lineage_child_read_gap": _S,
        "lineage_child_unavailable": _S,
        # Always accompanied by lineage_child_actionable_finding, which carries the action.
        "lineage_invalid_acceptance_transition": _S,
        "lineage_manifest_uncovered": _A,
        "lineage_manifest_not_recorded": _A,
        "lineage_manifest_state_changed": _A,
        "lineage_readiness_unavailable": _A,
        "lineage_manifest_missing": _S,
        "lineage_manifest_not_authorized": _S,
        "lineage_manifest_quarantined": _S,
        "lineage_manifest_revoked": _S,
        "lineage_manifest_unknown": _S,
        "lineage_manifest_unreadable": _S,
        # -- Project and coordination detail bounds.
        "project_member_unavailable": _S,
        "source_unavailable": _S,
        "revoked": _S,
        "not_observable": _S,
        "details_truncated": _S,
        # -- Imported source streams (Codex JSONL and rollout imports, human imports). The import
        # records what the source stream held; the agent cannot rewrite the imported source.
        "import_source_range_not_universal": _S,
        "human_import_scope_not_universal": _S,
        "command_declined_not_executed": _S,
        "command_outcome_incomplete": _S,
        "file_content_not_captured": _S,
        "final_newline_absent": _S,
        "item_shape_unsupported": _S,
        "item_transition_invalid": _S,
        "json_profile_unsupported": _S,
        "line_oversized": _S,
        "malformed_line": _S,
        "result_outcome_incomplete": _S,
        "source_category_not_mapped": _S,
        "source_line_unmapped": _S,
        "source_text_not_represented": _S,
        "source_timestamp_unavailable": _S,
        "truncated_final_line": _S,
        "unknown_item_type": _S,
        "unknown_wrapper_type": _S,
        "unsupported_codex_profile": _S,
        "web_results_not_captured": _S,
        "wrapper_shape_unsupported": _S,
        # -- Task facts (#977): what hook observations, the ledger and the check-time workspace
        # read establish about the task's own work. A planned verification that was not observed,
        # failed, or ran before the last edit, an edit after the last verification run, and a
        # requested output Git would not deliver are removed by the agent's own action. Installs,
        # writes and the user a run had are recorded history, an unmatched or unread item is a
        # bound on what Yoetz could see, and a declared blocker is the agent's recorded position.
        **{code: _A for code in sorted(AGENT_ACTIONABLE_TASK_FACT_GAPS)},
        **{code: _S for code in sorted(STANDING_TASK_FACT_GAPS)},
    }
)
if not PLAN_DRIFT_GAPS <= set(GAP_CLASSIFICATION):  # pragma: no cover - closed drift vocabulary
    raise ValueError("gap_classification_plan_drift_incomplete")
if any(_CODE_RE.fullmatch(code) is None for code in GAP_CLASSIFICATION):  # pragma: no cover
    raise ValueError("gap_classification_code_invalid")
if [code for code, value in GAP_CLASSIFICATION.items() if value is _R] != [
    "semantic_review_not_requested"
]:  # pragma: no cover - the route rule is defined for exactly one code
    raise ValueError("gap_classification_route_rule_invalid")


def gap_base_code(marker: str) -> str:
    """Return the base code a gap marker or prefixed form classifies by.

    ``coverage:<code>``, ``check_coverage:<code>``, ``retained_finding_coverage:<code>``,
    ``semantic_outcome:<code>`` and ``lineage:<code>:…`` name their base code second; every other
    ``<code>:<subject…>`` marker names it first. A bare code is its own base.
    """

    if type(marker) is not str:
        raise TypeError("gap_marker_invalid")
    head, separator, rest = marker.partition(":")
    if not separator:
        return marker
    if head in _WRAPPER_PREFIXES:
        return rest.partition(":")[0]
    return head


def classify_gap(
    marker: str,
    *,
    semantic_review_required: bool,
    semantic_review_current: bool,
) -> GapClass | None:
    """Resolve one gap to ``agent_actionable`` or ``standing_limitation``; ``None`` if unknown.

    ``semantic_review_required`` is true only on a route whose verification policy requires
    AI-powered review and which can dispatch it (never a strict MCP route, ADR-018).
    ``semantic_review_current`` is true when an AI-powered review completed and no material
    change has been recorded since. Neither flag affects any other code.
    """

    assigned = GAP_CLASSIFICATION.get(gap_base_code(marker))
    if assigned is not _R:
        return assigned
    if semantic_review_required and not semantic_review_current:
        return _A
    return _S


@dataclass(frozen=True, slots=True)
class GapSplit:
    """Gap codes grouped for closure readiness; each tuple is sorted and duplicate-free."""

    agent_actionable: tuple[str, ...]
    standing_limitations: tuple[str, ...]


def _unclassified(code: str) -> str:
    # Page gaps are already validated tokens; bound anything else to a fixed, content-free token
    # so an unreadable value can never echo into a structural readiness field.
    return UNCLASSIFIED_GAP_PREFIX + (code if _CODE_RE.fullmatch(code) else "unreadable_gap_code")


def split_gaps(
    markers: Iterable[str],
    *,
    semantic_review_required: bool,
    semantic_review_current: bool,
) -> GapSplit:
    """Split gap markers into agent-actionable and standing groups by their base codes.

    An unknown base code lands in the agent-actionable group as ``unclassified_gap:<code>``.
    """

    actionable: set[str] = set()
    standing: set[str] = set()
    for marker in markers:
        code = gap_base_code(marker)
        assigned = classify_gap(
            code,
            semantic_review_required=semantic_review_required,
            semantic_review_current=semantic_review_current,
        )
        if assigned is None:
            actionable.add(_unclassified(code))
        elif assigned is _A:
            actionable.add(code)
        else:
            standing.add(code)
    return GapSplit(
        tuple(sorted(actionable, key=str.encode)),
        tuple(sorted(standing, key=str.encode)),
    )


# ---------------------------------------------------------------------------------------------
# Readiness facts and the checklist split
# ---------------------------------------------------------------------------------------------

# The one "not done" vocabulary shared by findings (#905's ``respond`` disposition) and
# obligations (ADR-032; the obligation form is #997's ``obligation_published`` 1.1.0). An
# acknowledged item is carried to the receipt as not done; it is never resolved and never counted
# as clean. A finding's acknowledgement is final; an obligation's is undone only by a later
# publication of that obligation (open or resolved).
ACKNOWLEDGED_NOT_DONE: Final = "acknowledged_not_done"
# Readiness conditions the agent removes by its own action, in their wire order.
# ``receipt_findings_unresolved`` joins them unless every receipt-blocking finding is acknowledged
# as not done; ``coverage_gaps_declared`` is replaced by the per-code classification above.
AGENT_READINESS_CONDITIONS: Final = (
    "obligations_open",
    "findings_unanswered",
    "receipt_findings_unresolved",
    "no_plan_published",
    "no_obligations_declared",
    "projection_stale",
)
MAX_ACKNOWLEDGED_READINESS_ITEMS: Final = 64
# A live lineage blocker token and the code a recorded lineage evaluation (the one checks and
# receipts fold) uses for the same fact; every other token is its own recorded code.
_LINEAGE_RECORDED_CODES: Final[Mapping[str, str]] = MappingProxyType(
    {"lineage_child_read_gap": "lineage_child_unavailable"}
)
# Check conditions readiness derives itself, in their wire order; each is classified above.
READINESS_CHECK_CONDITIONS: Final = (
    "check_in_progress",
    "check_not_recorded",
    "check_not_applicable",
    "closing_review_required",
)

type CheckApplicability = Literal[
    "applicable", "not_recorded", "not_applicable", "payload_unavailable"
]


@dataclass(frozen=True, slots=True)
class ClosureReadinessFacts:
    """Ledger-derived inputs closure readiness cannot read off the compact row.

    Derived per request from the exact projection and record prefix at the requested frontier;
    never cached across frontiers and never persisted, so a restart, a reattach or an upgrade over
    an older ledger recomputes the same answer without migrating any recorded event.
    """

    check_applicability: CheckApplicability
    semantic_review_current: bool
    receipt_blocking_finding_ids: tuple[FindingId, ...]
    acknowledged_finding_ids: tuple[FindingId, ...]
    acknowledged_obligation_ids: tuple[ObligationId, ...]
    # Open effective obligations, and the subset a recorded blocker decision names (#977).
    open_obligation_ids: tuple[ObligationId, ...] = ()
    blocked_obligation_ids: tuple[ObligationId, ...] = ()
    # ``(obligation, blocker kind, decision event id)`` for each blocked open obligation, in
    # obligation order: what the Stop gate names when it re-asks a blocker once (#977).
    blocked_obligation_details: tuple[tuple[ObligationId, str, EventId], ...] = ()
    # ``(obligation, confirming decision event id)`` for each blocked open obligation whose
    # blocker a later decision confirmed (#985), in obligation order. A blocked obligation absent
    # here is only claimed: it stays agent work (``obligation_blocker_unconfirmed``).
    blocked_obligation_confirmations: tuple[tuple[ObligationId, EventId], ...] = ()
    # Issue #976. Whether a closing review (final phase) is current since the last material
    # change, or a review attempt since then could not complete for a reason the agent cannot
    # remove; and whether any AI-powered review completed on this task. The defaults keep a
    # hand-built fact set at its pre-#976 answer.
    closing_review_current: bool = True
    semantic_review_used: bool = False
    # Issue #984: current findings in the terminal ``self_verified`` state. Not agent work (they
    # never count as receipt-blocking); readiness discloses them as ``finding_self_verified``.
    self_verified_finding_ids: tuple[FindingId, ...] = ()
    # F3: every result id a whole-task completion claim recorded now must name in
    # ``limitation_refs`` (``kernel.claim_limitations``, the reducer's rule), sorted. Status
    # lists them before the claim so the first claim is accepted.
    limitation_refs_required: tuple[str, ...] = ()
    # Issue #995: ``(obligation, kind, decision event id)`` for each recorded disclosure line
    # (``task_facts.disclosure_declarations``), in obligation then kind order. Standing only.
    disclosed_obligations: tuple[tuple[ObligationId, str, EventId], ...] = ()
    # #997: an effective obligation whose payload is unreadable may be open; it keeps
    # ``obligations_open`` actionable even when every readable one is acknowledged. A hand-built
    # fact set that does not say defaults to unknown, which never clears the condition.
    open_obligations_unreadable: bool = True
    # Issue #984 (D7a): acknowledged-not-done findings whose premise the reviewer disputes.
    premise_disputed_finding_ids: tuple[FindingId, ...] = ()

    def __post_init__(self) -> None:
        if (
            self.check_applicability
            not in {
                "applicable",
                "not_recorded",
                "not_applicable",
                "payload_unavailable",
            }
            or type(self.semantic_review_current) is not bool
            or type(self.closing_review_current) is not bool
            or type(self.semantic_review_used) is not bool
        ):
            raise ValueError("closure_readiness_facts_invalid")
        for values in (
            self.receipt_blocking_finding_ids,
            self.acknowledged_finding_ids,
            self.self_verified_finding_ids,
            self.acknowledged_obligation_ids,
            self.open_obligation_ids,
            self.blocked_obligation_ids,
            self.limitation_refs_required,
            self.premise_disputed_finding_ids,
        ):
            if type(values) is not tuple or values != tuple(sorted(set(values), key=str.encode)):
                raise ValueError("closure_readiness_facts_invalid")
        if (
            type(self.blocked_obligation_details) is not tuple
            or tuple(item[0] for item in self.blocked_obligation_details)
            != self.blocked_obligation_ids
        ):
            raise ValueError("closure_readiness_facts_invalid")
        confirmed = tuple(item[0] for item in self.blocked_obligation_confirmations)
        if (
            type(self.blocked_obligation_confirmations) is not tuple
            or confirmed != tuple(sorted(set(confirmed), key=str.encode))
            or not set(confirmed) <= set(self.blocked_obligation_ids)
        ):
            raise ValueError("closure_readiness_facts_invalid")
        if type(self.disclosed_obligations) is not tuple or any(
            type(item) is not tuple or len(item) != 3 or item[1] not in _DISCLOSURE_CODES
            for item in self.disclosed_obligations
        ):
            raise ValueError("closure_readiness_facts_invalid")

    @property
    def confirmed_blocked_obligation_ids(self) -> tuple[ObligationId, ...]:
        return tuple(item[0] for item in self.blocked_obligation_confirmations)


def live_lineage_blockers(tokens: Iterable[str], recorded_gaps: Iterable[str]) -> tuple[str, ...]:
    """Return the live lineage tokens a receipt at this frontier would not yet disclose.

    Status compares accepted catalog children with the parent's recorded manifest live; a receipt
    folds only recorded lineage. A token whose recorded code is already among the task's recorded
    gaps is disclosed through that code and classified with it. Any other token describes a
    current dependency fact the receipt cannot carry yet, so readiness never promises to disclose
    it as a standing limitation: it stays agent-actionable (let the service record the manifest,
    then check) until a recorded evaluation carries it.
    """

    recorded = set(recorded_gaps)
    return tuple(
        sorted(
            {
                token
                for token in tokens
                if _LINEAGE_RECORDED_CODES.get(token, token) not in recorded
            },
            key=str.encode,
        )
    )


def finding_acknowledged_not_done(state: ProjectionState, finding: FindingId) -> bool:
    """True when the finding's latest response records it as acknowledged, not done.

    Read by disposition *value* so the finding form defined by #905 flows into readiness as soon
    as that disposition is recorded, without a second acknowledgement mechanism here.
    """

    response = state.responses.get(finding)
    if response is None or response.payload is None:
        return False
    return str(response.payload.disposition.value) == ACKNOWLEDGED_NOT_DONE


def _check_applicability(
    state: ProjectionState,
    records: tuple[LedgerRecord, ...],
    limitations: frozenset[FindingId],
) -> CheckApplicability:
    # The receipt's own applicability rule (application/receipt.py, kernel/receipt_capacity.py):
    # a check covers this state unless a later material record superseded it.
    latest = state.latest_tested_state
    if latest is None:
        return "not_recorded"
    check_record = next(
        (record for record in records if record.event_id == latest.source_check_event_id), None
    )
    if check_record is None:
        return "payload_unavailable"
    if any(
        invalidates_recorded_check(
            record,
            check_record.ledger.ingestion_sequence,
            latest.returned_finding_ids,
            limitation_finding_ids=limitations,
        )
        for record in records
    ):
        return "not_applicable"
    if type(check_record.payload) is not CheckRecordedPayload:
        return "payload_unavailable"
    return "applicable"


def _review_round_stopped(payload: CheckRecordedPayload) -> bool:
    """A check that skipped the AI-powered review because the packet twice could not show the
    content the reviewer needed (tb4n1 D3). Another review cannot assess more, so neither a
    current review nor a closing review is demanded again; the gap discloses the limit."""

    return (
        payload.semantic_status is SemanticStatus.NOT_REQUESTED
        and "semantic_review_skipped_insufficient_packet" in payload.coverage.known_gaps
    )


def _semantic_review_current(
    records: tuple[LedgerRecord, ...], limitations: frozenset[FindingId]
) -> bool:
    """True when an AI-powered review completed and no material change was recorded since.

    ``limitations`` is ``observation_limitation_finding_ids`` over the same prefix, so an unscored
    answer to an observation-authored limitation is not material change here either (issue #911).
    """

    for record in reversed(records):
        payload = record.payload
        if record.schema.name != "check_recorded" or type(payload) is not CheckRecordedPayload:
            continue
        if _review_round_stopped(payload):
            # Current only while the round is still stopped: an edit since re-arms the review.
            return review_round_stopped(records)
        if payload.semantic_status is not SemanticStatus.SUCCEEDED:
            continue
        return not any(
            invalidates_recorded_check(
                later,
                record.ledger.ingestion_sequence,
                payload.returned_finding_ids,
                limitation_finding_ids=limitations,
            )
            for later in records
        )
    return False


# Statuses of an AI-powered review attempt that did not complete for a reason a recheck by the
# agent cannot remove (policy, privacy, configuration or a human decision). A timeout or an
# unavailable or failed provider is transient: the closing review stays actionable. Their own gaps disclose it, and
# closure does not also demand a closing review the route cannot deliver.
_UNDELIVERABLE_SEMANTIC_STATUSES: Final = frozenset(
    {
        SemanticStatus.BLOCKED_BY_POLICY,
        SemanticStatus.BLOCKED_FORBIDDEN_DATA,
        SemanticStatus.NOT_CONFIGURED,
        SemanticStatus.CLASSIFICATION_UNCERTAIN,
        SemanticStatus.HUMAN_DENIED,
        SemanticStatus.APPROVAL_EXPIRED,
    }
)


def _closing_review_facts(
    state: ProjectionState,
    records: tuple[LedgerRecord, ...],
    limitations: frozenset[FindingId],
) -> tuple[bool, bool]:
    """Return ``(closing_review_current, semantic_review_used)`` for this prefix (issue #976).

    A check is the closing review when its recorded review input manifest names the final
    phase. A check recorded before the manifest carried the phase was final exactly when an
    effective completion claim preceded it; with no material change since it, the current
    projection's claim answers that.
    """

    used = False
    for record in records:
        payload = record.payload
        if (
            record.schema.name == "check_recorded"
            and type(payload) is CheckRecordedPayload
            and payload.semantic_status is SemanticStatus.SUCCEEDED
        ):
            used = True
            break
    for record in reversed(records):
        payload = record.payload
        if record.schema.name != "check_recorded" or type(payload) is not CheckRecordedPayload:
            continue
        if any(
            invalidates_recorded_check(
                later,
                record.ledger.ingestion_sequence,
                payload.returned_finding_ids,
                limitation_finding_ids=limitations,
            )
            for later in records
        ):
            return False, used
        status = payload.semantic_status
        if status in _UNDELIVERABLE_SEMANTIC_STATUSES:
            return True, used
        if _review_round_stopped(payload):
            return review_round_stopped(records), used
        if status is not SemanticStatus.SUCCEEDED:
            continue
        manifest = payload.review_input_manifest
        phase = None if manifest is None else manifest.get("review_phase")
        if phase == "final":
            return True, used
        if phase is None and completion_claim_present(state):
            return True, used
    return False, used


def _acknowledged_obligation_ids(state: ProjectionState) -> tuple[ObligationId, ...]:
    """Effective obligations whose latest publication is ``acknowledged_not_done`` (#997).

    ADR-032 slice C: an ``obligation_published`` 1.1.0 with that status and a reason. Such an
    obligation is not open (it leaves ``obligations_open``) and not resolved; readiness lists it
    in ``acknowledged_not_done`` and the receipt discloses it as not done. A later publication
    with ``open`` or ``resolved`` takes it out again. Nothing is inferred from other records.
    """

    return tuple(sorted(acknowledged_obligation_ids(state), key=str.encode))


def premise_disputed_finding_ids(state: ProjectionState) -> tuple[FindingId, ...]:
    """Acknowledged-not-done findings the reviewer says the task itself requires (D7a, #984).

    Reads L5's ``finding_todo.standing_premise_disputes`` as an opaque predicate. On a build
    without it, or if it fails, nothing is reported as disputed (a disclosure is never invented).
    """

    predicate = _standing_premise_disputes
    if predicate is None:
        return ()
    try:
        values: tuple[object, ...] = tuple(predicate(state))
    except (AttributeError, KeyError, LookupError, TypeError, ValueError) as exc:
        # A predicate defect must not break status; it is recorded, never silently hidden, and
        # nothing is reported as disputed.
        from yoetz.observability.logging import record_unexpected_exception_without_raising

        record_unexpected_exception_without_raising(
            exc,
            component="kernel.closure_readiness",
            operation="premise_dispute_predicate_failed",
        )
        return ()
    disputed = {
        FindingId(value) for value in values if type(value) is str and value.startswith("fnd_")
    }
    return tuple(sorted(disputed, key=str.encode))


def _open_obligations_unreadable(state: ProjectionState) -> bool:
    scope = current_plan_scope(state.plans, state.coverage_gaps)
    refs = scope.effective_obligation_refs
    if refs is None:
        return True
    return any(
        (record := state.obligations.get(item)) is None or record.payload is None for item in refs
    )


def closure_readiness_facts(
    state: ProjectionState, records: tuple[LedgerRecord, ...]
) -> ClosureReadinessFacts:
    """Derive the readiness facts for exactly this projection and its record prefix."""

    if type(state) is not ProjectionState or type(records) is not tuple:
        raise ValueError("closure_readiness_facts_invalid")
    current = tuple(
        finding
        for finding in current_receipt_findings(state)
        if not finding_is_resolved(state, finding.finding_id)
    )
    # Same predicate as receipt_blocking_finding_count (``finding_todo.finding_blocks_receipt``): an
    # actionable finding kind that no later qualifying check resolved and that is not a terminal
    # ``rejection_accepted`` item (issue #905). A linked ``duplicate_of`` item (issue #996) is
    # named by the finding that answers for it (``duplicate_counting_id``), so a pair counts once.
    blocking = {
        duplicate_counting_id(state, finding.finding_id)
        for finding in current
        if finding_blocks_receipt(state, finding.finding_id)
    }
    acknowledged = {
        duplicate_counting_id(state, finding.finding_id)
        for finding in current
        if finding_acknowledged_not_done(state, finding.finding_id)
        or finding_todo_state(state, finding.finding_id) is FindingTodoState.ACKNOWLEDGED_NOT_DONE
    }
    self_verified = {
        duplicate_counting_id(state, finding.finding_id)
        for finding in current
        if finding_todo_state(state, finding.finding_id) is FindingTodoState.SELF_VERIFIED
    }
    # The receipt's applicability rule reads the same observation-limitation set (issue #911).
    limitations = observation_limitation_finding_ids(state, records)
    # #997: an acknowledged obligation is never open work here, whichever counting regime the
    # projection uses (L6 counts it among open obligations); it is listed once, as acknowledged.
    acknowledged_obligations = _acknowledged_obligation_ids(state)
    open_obligations = tuple(
        item
        for item in open_effective_obligations(state)
        if item not in set(acknowledged_obligations)
    )
    blocked = blocker_declarations(state, decision_batches(records))
    blocked_open = tuple(
        sorted({item for item in open_obligations if item in blocked}, key=str.encode)
    )
    closing_current, review_used = _closing_review_facts(state, records, limitations)
    return ClosureReadinessFacts(
        check_applicability=_check_applicability(state, records, limitations),
        semantic_review_current=_semantic_review_current(records, limitations),
        receipt_blocking_finding_ids=tuple(sorted(blocking, key=str.encode)),
        acknowledged_finding_ids=tuple(sorted(acknowledged, key=str.encode)),
        acknowledged_obligation_ids=acknowledged_obligations,
        open_obligations_unreadable=_open_obligations_unreadable(state),
        open_obligation_ids=tuple(sorted(set(open_obligations), key=str.encode)),
        blocked_obligation_ids=blocked_open,
        blocked_obligation_details=tuple(
            (item, blocked[item].kind, blocked[item].decision_event_id) for item in blocked_open
        ),
        blocked_obligation_confirmations=tuple(
            (item, confirmation)
            for item in blocked_open
            if (confirmation := blocked[item].confirmation_event_id) is not None
        ),
        closing_review_current=closing_current,
        semantic_review_used=review_used,
        self_verified_finding_ids=tuple(sorted(self_verified, key=str.encode)),
        limitation_refs_required=tuple(
            required_limitation_ids_for_projection(state, observed_event_ids_from_records(records))
        ),
        disclosed_obligations=tuple(
            (item.obligation_id, item.kind, item.decision_event_id)
            for item in disclosure_declarations(state)
        ),
        premise_disputed_finding_ids=premise_disputed_finding_ids(state),
    )


@dataclass(frozen=True, slots=True)
class ClosureReadinessSplit:
    """The checklist answer: what the agent can still do, and what the receipt will disclose."""

    state: Literal["action_required", "ready", "ready_with_limitations"]
    agent_actionable: tuple[str, ...]
    standing_limitations: tuple[str, ...]
    acknowledged_not_done: tuple[str, ...]
    acknowledged_not_done_count: int


def derive_closure_readiness(
    blocking_conditions: Iterable[str],
    gap_markers: Iterable[str],
    facts: ClosureReadinessFacts | None,
    *,
    semantic_review_required: bool,
    check_in_flight: bool = False,
    live_blockers: Iterable[str] = (),
    lineage_self_verified: bool = False,
) -> ClosureReadinessSplit:
    """Split readiness into agent-actionable work, standing limitations and acknowledged items.

    ``blocking_conditions`` is the unchanged condition list. Open obligations, unanswered
    findings, missing plan or scope, a stale projection, an unacknowledged receipt-blocking
    finding, a missing or superseded check and every actionable gap stay agent-actionable. When
    ``facts`` is unavailable nothing is inferred from its absence: no acknowledgement is assumed
    and a receipt-blocking condition stays actionable. ``check_in_flight`` means a check holds the
    session frontier right now: nothing reads as done until its result is recorded.
    ``live_blockers`` are live dependency facts a receipt cannot disclose yet
    (``live_lineage_blockers``); they are agent-actionable whatever their recorded class.
    """

    conditions = tuple(blocking_conditions)
    actionable: list[str] = []
    standing: set[str] = set()
    # Every open obligation is named by a recorded blocker (#977), and every one of those blockers
    # was confirmed by a later decision after the challenge (#985).
    blocked_confirmed_only = False
    for condition in AGENT_READINESS_CONDITIONS:
        if condition not in conditions:
            continue
        if condition == "receipt_findings_unresolved" and facts is not None:
            blocking = set(facts.receipt_blocking_finding_ids)
            # Acknowledged-not-done (#905) and self-verified (#984) items are final answers,
            # not agent work.
            settled = {*facts.acknowledged_finding_ids, *facts.self_verified_finding_ids}
            if blocking and blocking <= settled:
                continue
        if (
            condition == "obligations_open"
            and facts is not None
            and not facts.open_obligation_ids
            and facts.acknowledged_obligation_ids
            and not facts.open_obligations_unreadable
        ):
            # #997: the only obligations the projection counts as open are acknowledged as not
            # done (L6's counting regime). They are listed once, under acknowledged_not_done.
            continue
        if (
            condition == "obligations_open"
            and facts is not None
            and facts.open_obligation_ids
            and set(facts.open_obligation_ids) <= set(facts.blocked_obligation_ids)
        ):
            # Every open obligation is named by a recorded blocker outside the agent's control
            # (authority, consent, credential, an unobtainable dependency; #977). A blocker the
            # agent only claimed is still its work: repair the obligation, or confirm the blocker
            # in a later decision after the challenge (#985). Only when every one is confirmed
            # is it disclosed rather than listed as work.
            unconfirmed = set(facts.blocked_obligation_ids) - set(
                facts.confirmed_blocked_obligation_ids
            )
            if unconfirmed:
                actionable.append(OBLIGATION_BLOCKER_UNCONFIRMED_GAP)
            else:
                blocked_confirmed_only = True
            if facts.confirmed_blocked_obligation_ids:
                standing.add(OBLIGATION_BLOCKED_GAP)
            continue
        actionable.append(condition)
    if check_in_flight:
        actionable.append("check_in_progress")
    if facts is not None:
        if facts.check_applicability in {"not_recorded", "not_applicable"}:
            actionable.append("check_" + facts.check_applicability)
        elif facts.check_applicability == "payload_unavailable":
            standing.add("check_payload_unavailable")
    split = split_gaps(
        gap_markers,
        semantic_review_required=semantic_review_required,
        semantic_review_current=facts is not None and facts.semantic_review_current,
    )
    split_actionable = split.agent_actionable
    if blocked_confirmed_only and COMPLETION_PLAN_NOT_CLAIMED_GAP in split_actionable:
        # Issue #985 (C9): every open obligation is confirmed blocked, so no completion claim can
        # cover the plan; the unclaimed plan is disclosed beside the blocker, not listed as work.
        split_actionable = tuple(
            code for code in split_actionable if code != COMPLETION_PLAN_NOT_CLAIMED_GAP
        )
        standing.add(COMPLETION_PLAN_NOT_CLAIMED_GAP)
    actionable.extend(code for code in split_actionable if code not in actionable)
    # Issue #976: the receipt is the last step, so the last review before it judges
    # completeness. Required on a route that requires AI-powered review, and on any task that
    # already used it; not repeated while the missing review is already the actionable item.
    if (
        facts is not None
        and (semantic_review_required or facts.semantic_review_used)
        and not facts.closing_review_current
        and "semantic_review_not_requested" not in actionable
    ):
        actionable.append("closing_review_required")
    for token in live_blockers:
        item = token if _CODE_RE.fullmatch(token) else _unclassified(token)
        if item not in actionable:
            actionable.append(item)
    standing.update(split.standing_limitations)
    if (facts is not None and facts.self_verified_finding_ids) or lineage_self_verified:
        # ``lineage_self_verified``: an accepted child holds self-verified findings (ADR-034,
        # ADR-027). The parent receipt is then at best insufficient_coverage; status says so.
        standing.add(FINDING_SELF_VERIFIED_GAP)
    if facts is not None:
        # Issue #995: disclosed assumptions and verification limits never add or remove work.
        standing.update(
            _DISCLOSURE_CODES[kind] for _obligation, kind, _event in facts.disclosed_obligations
        )
        if facts.premise_disputed_finding_ids:
            standing.add(FINDING_PREMISE_DISPUTED_GAP)
    acknowledged: tuple[str, ...] = ()
    if facts is not None:
        acknowledged = tuple(
            sorted(
                {*facts.acknowledged_obligation_ids, *facts.acknowledged_finding_ids},
                key=str.encode,
            )
        )
    state: Literal["action_required", "ready", "ready_with_limitations"]
    if actionable:
        state = "action_required"
    elif standing or acknowledged:
        state = "ready_with_limitations"
    else:
        state = "ready"
    return ClosureReadinessSplit(
        state=state,
        agent_actionable=tuple(actionable),
        standing_limitations=tuple(sorted(standing, key=str.encode)),
        acknowledged_not_done=acknowledged[:MAX_ACKNOWLEDGED_READINESS_ITEMS],
        acknowledged_not_done_count=len(acknowledged),
    )
