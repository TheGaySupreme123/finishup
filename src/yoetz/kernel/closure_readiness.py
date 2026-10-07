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
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Final, Literal

from yoetz.domain.events import CheckRecordedPayload, LedgerRecord
from yoetz.domain.receipts import CHECK_TIME_CHANGE_UNAVAILABLE_REASON_GAPS
from yoetz.domain.values import EventId, FindingId, ObligationId
from yoetz.kernel.claims import completion_claim_present
from yoetz.kernel.finding_resolution import finding_is_resolved
from yoetz.kernel.finding_todo import finding_blocks_receipt
from yoetz.kernel.plan_drift import PLAN_DRIFT_ADVISORY_GAPS, PLAN_DRIFT_GAPS
from yoetz.kernel.projections import ProjectionState, observation_limitation_finding_ids
from yoetz.kernel.receipt_capacity import current_receipt_findings
from yoetz.kernel.reducers import invalidates_recorded_check
from yoetz.kernel.task_facts import (
    AGENT_ACTIONABLE_TASK_FACT_GAPS,
    OBLIGATION_BLOCKED_GAP,
    STANDING_TASK_FACT_GAPS,
    blocker_declarations,
    open_effective_obligations,
)
from yoetz.protocol.models import SemanticStatus

__all__ = [
    "ACKNOWLEDGED_NOT_DONE",
    "AGENT_READINESS_CONDITIONS",
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
# ``compound_outcome_unavailable`` became a standing limitation.
GAP_CLASSIFICATION_VERSION: Final = "2"
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
        "semantic_missing_already_supplied": _S,
        "semantic_missing_items_rejected": _S,
        "semantic_missing_non_convergent": _S,
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
# obligations (ADR-032). An acknowledged item is carried to the receipt as not done; it is never
# resolved, never counted as clean, and never reopened.
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
    # Issue #976. Whether a closing review (final phase) is current since the last material
    # change, or a review attempt since then could not complete for a reason the agent cannot
    # remove; and whether any AI-powered review completed on this task. The defaults keep a
    # hand-built fact set at its pre-#976 answer.
    closing_review_current: bool = True
    semantic_review_used: bool = False

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
            self.acknowledged_obligation_ids,
            self.open_obligation_ids,
            self.blocked_obligation_ids,
        ):
            if type(values) is not tuple or values != tuple(sorted(set(values), key=str.encode)):
                raise ValueError("closure_readiness_facts_invalid")
        if (
            type(self.blocked_obligation_details) is not tuple
            or tuple(item[0] for item in self.blocked_obligation_details)
            != self.blocked_obligation_ids
        ):
            raise ValueError("closure_readiness_facts_invalid")


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


def _semantic_review_current(
    records: tuple[LedgerRecord, ...], limitations: frozenset[FindingId]
) -> bool:
    """True when an AI-powered review completed and no material change was recorded since.

    ``limitations`` is ``observation_limitation_finding_ids`` over the same prefix, so an unscored
    answer to an observation-authored limitation is not material change here either (issue #911).
    """

    for record in reversed(records):
        payload = record.payload
        if (
            record.schema.name != "check_recorded"
            or type(payload) is not CheckRecordedPayload
            or payload.semantic_status is not SemanticStatus.SUCCEEDED
        ):
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
    """Always empty: no recorded form acknowledges an obligation as not done yet.

    The obligation-level acknowledgement is issue #913 slice C (it needs a new
    ``obligation_published`` version); #905 owns only the finding form, which
    ``finding_acknowledged_not_done`` already reads. Until slice C ships, an obligation the agent
    cannot finish stays open, so ``obligations_open`` keeps readiness ``action_required``; the
    guidance says so. Nothing here may be inferred from other records.
    """

    del state
    return ()


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
    # ``rejection_accepted`` item (issue #905).
    blocking = {
        finding.finding_id
        for finding in current
        if finding_blocks_receipt(state, finding.finding_id)
    }
    acknowledged = {
        finding.finding_id
        for finding in current
        if finding_acknowledged_not_done(state, finding.finding_id)
    }
    # The receipt's applicability rule reads the same observation-limitation set (issue #911).
    limitations = observation_limitation_finding_ids(state, records)
    open_obligations = open_effective_obligations(state)
    blocked = blocker_declarations(state)
    blocked_open = tuple(
        sorted({item for item in open_obligations if item in blocked}, key=str.encode)
    )
    closing_current, review_used = _closing_review_facts(state, records, limitations)
    return ClosureReadinessFacts(
        check_applicability=_check_applicability(state, records, limitations),
        semantic_review_current=_semantic_review_current(records, limitations),
        receipt_blocking_finding_ids=tuple(sorted(blocking, key=str.encode)),
        acknowledged_finding_ids=tuple(sorted(acknowledged, key=str.encode)),
        acknowledged_obligation_ids=_acknowledged_obligation_ids(state),
        open_obligation_ids=tuple(sorted(set(open_obligations), key=str.encode)),
        blocked_obligation_ids=blocked_open,
        blocked_obligation_details=tuple(
            (item, blocked[item].kind, blocked[item].decision_event_id) for item in blocked_open
        ),
        closing_review_current=closing_current,
        semantic_review_used=review_used,
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
    blocked_only = False
    for condition in AGENT_READINESS_CONDITIONS:
        if condition not in conditions:
            continue
        if condition == "receipt_findings_unresolved" and facts is not None:
            blocking = set(facts.receipt_blocking_finding_ids)
            if blocking and blocking <= set(facts.acknowledged_finding_ids):
                continue
        if (
            condition == "obligations_open"
            and facts is not None
            and facts.open_obligation_ids
            and set(facts.open_obligation_ids) <= set(facts.blocked_obligation_ids)
        ):
            # Every open obligation is named by a recorded blocker outside the agent's control
            # (authority, consent, credential, an unobtainable dependency; #977). Nothing the
            # agent can do removes it, so it is disclosed rather than listed as work.
            blocked_only = True
            continue
        actionable.append(condition)
    standing: set[str] = set()
    if blocked_only:
        standing.add(OBLIGATION_BLOCKED_GAP)
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
    actionable.extend(code for code in split.agent_actionable if code not in actionable)
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
