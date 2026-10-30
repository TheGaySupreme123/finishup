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
* ``fix_or_decline`` (issue #1209) — an agent action removes it, but nothing requires one: a
  requested file the record says was written is unchanged, a planned verification matched only
  through the agent's own link, or a planned part whose outcome the host-stated run does not
  establish. Disclosed on the receipt like a standing limitation and never a Stop item (ADR-033
  D1); readiness names each open item with its obligation so the agent fixes it or declines it
  with a recorded reason before the receipt.

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
from types import MappingProxyType
from typing import Final, Literal, cast

from finishup.domain.events import (
    CheckRecordedPayload,
    LedgerRecord,
    ObligationPublishedPayload,
    ObligationStatus,
)
from finishup.domain.receipts import (
    COMPLETION_PLAN_NOT_CLAIMED_GAP,
    SEMANTIC_REVIEW_DEFERRED_BEFORE_FIRST_EDIT_GAP,
)
from finishup.domain.values import EventId, FindingId, ObligationId, obligation_id
from finishup.kernel import finding_todo as _finding_todo_module
from finishup.kernel.acceptance_risk import ACCEPTANCE_RISK_REASONS, acceptance_risk
from finishup.kernel.check_standing import CheckCause, CheckStanding, check_standing
from finishup.kernel.claim_limitations import required_limitation_ids_for_projection
from finishup.kernel.claim_verification import unresolved_acceptance_risk
from finishup.kernel.claims import completion_claim_present
from finishup.kernel.closing_review_delta import (
    closing_material_frontier,
    closing_review_delta,
)
from finishup.kernel.closure_class import (
    ACKNOWLEDGED_NOT_DONE_BASES,
    FINDING_REJECTION_AWAITING_RULING_GAP,
    UNDELIVERABLE_SEMANTIC_STATUSES,
    FindingClosure,
    FindingClosureClass,
    ObligationClosure,
    ReceiptEffect,
    counted_findings,
    finding_closures,
    obligation_closures,
)
from finishup.kernel.delivered_set import (
    UndeclaredReferenceRow,
    deliverable_lineage,
    undeclared_reference_rows,
)
from finishup.kernel.fact_lineage import MAX_FACT_LINEAGE_ITEMS, FactLineage
from finishup.kernel.finding_resolution import finding_is_resolved
from finishup.kernel.finding_todo import (
    duplicate_counting_id,
)
from finishup.kernel.gap_effect import (
    GAP_EFFECT_TABLE,
    UNCLASSIFIED_GAP_PREFIX,
    GapClass,
    gap_base_code,
    unclassified_marker,
)
from finishup.kernel.later_material import WorkspaceEffects, workspace_effects
from finishup.kernel.observed_failures import observed_event_ids_from_records
from finishup.kernel.plan_drift import PLAN_DRIFT_GAPS
from finishup.kernel.plan_scope import current_plan_scope
from finishup.kernel.projections import ProjectionState, observation_limitation_finding_ids
from finishup.kernel.receipt_capacity import current_receipt_findings
from finishup.kernel.reducers import invalidates_recorded_check
from finishup.kernel.review_round import review_round_stopped
from finishup.kernel.task_facts import (
    OBLIGATION_BLOCKED_GAP,
    OBLIGATION_BLOCKER_UNCONFIRMED_GAP,
    REQUESTED_OUTPUT_UNCHANGED_GAP,
    TaskFactSignals,
    acknowledged_obligation_ids,
    blocked_obligations,
    blocker_declarations,
    decision_batches,
    disclosure_declarations,
    open_effective_obligations,
    requested_output_unchanged_candidates,
    task_fact_signals,
)
from finishup.protocol.models import SemanticReason, SemanticStatus

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
    "FINDING_DISPUTED_AFTER_REBUTTAL_GAP",
    "FINDING_LIMITATION_DISCLOSED_GAP",
    "FINDING_PREMISE_DISPUTED_GAP",
    "FINDING_REJECTION_UNREVIEWABLE_GAP",
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
    "current_fact_lineage",
    "derive_closure_readiness",
    "finding_acknowledged_not_done",
    "gap_base_code",
    "live_lineage_blockers",
    "semantic_review_used",
    "split_gaps",
]

# Bump when any assignment below changes meaning. Status responses carry the version so a reader
# can tell which table classified a recorded readiness answer. "2": the task-statement gap
# ``instruction_requirement_unmapped`` became agent-actionable and the previously unclassified
# ``compound_outcome_unavailable`` became a standing limitation. "3": the standing readiness code
# ``finding_self_verified`` (issue #984, ADR-034) was added. "4": the standing disclosure codes
# ``assumption_disclosed`` and ``verification_limit_disclosed`` (issue #995, ADR-033) and
# ``finding_premise_disputed`` (issue #984, D7a) were added. "5": the standing disclosure code
# ``finding_disputed_after_rebuttal`` (issue #1020, ADR-040) was added. "6": the agent-actionable
# task fact ``declared_output_emptied`` and the standing disclosure
# ``deliverable_references_undeclared_file`` (tb4n2 R2, issue #1022, ADR-035) were added. "7": the
# table became a derived view of ``kernel.gap_effect`` (tb4n3 RC-3, issue #1026, ADR-046), and the
# agent-actionable readiness token ``finding_rejection_awaiting_ruling`` was added. The standing
# disclosures ``planned_verification_matched_by_prefix`` and
# ``declared_output_not_reviewable`` were added and ``declared_output_emptied`` became a path-keyed
# fact with provenance (tb4n3 RC-5, issue #1028, ADR-045). "8" (tb4n4, unreleased): the standing
# disclosure ``deliverable_references_undeclared_file`` became an agent-actionable task fact and
# Stop-gate token (issue #1044, ADR-035 amendment); the standing disclosure
# ``semantic_process_state_filtered`` (issue #1042) and the standing limit
# ``semantic_review_deferred_before_first_edit`` (issue #1046; disclosed where the deferred check's
# route did not require review, gap table G7) were added (ADR-040 amendment). "9" (issue #1209,
# ADR-032 amendment): the standing disclosures ``requested_output_unchanged``,
# ``planned_verification_agent_linked`` and ``planned_verification_outcome_unknown`` joined the
# new ``fix_or_decline`` readiness group (gap table G4f): still disclosed and never bounding or a
# Stop item, but named to the agent as "fix, or decline with a reason" before the receipt.
GAP_CLASSIFICATION_VERSION: Final = "9"
# Issue #1020 (ADR-040): a current AI-powered finding the reviewer repeated over the agent's
# reasoned rejection without newer material. A standing disagreement; never agent work.
FINDING_DISPUTED_AFTER_REBUTTAL_GAP: Final = "finding_disputed_after_rebuttal"
# Issue #984 (ADR-034): a current finding the agent answered ``self_verified``. FinishUP could not
# prove the repair; the agent verified it itself. Disclosed, never agent work.
FINDING_SELF_VERIFIED_GAP: Final = "finding_self_verified"
# Issue #995 (ADR-033): a recorded ``finishup-assumption:`` / ``finishup-verification-limit:`` decision
# line on an obligation. A disclosure, never a blocker and never agent work.
ASSUMPTION_DISCLOSED_GAP: Final = "assumption_disclosed"
VERIFICATION_LIMIT_DISCLOSED_GAP: Final = "verification_limit_disclosed"
# Issue #984 (D7a): the agent answered ``acknowledged_not_done`` on an AI-powered finding whose
# challenge says the task itself requires the work. Terminal, so never agent work: disclosed, and
# the Stop gate asks once.
FINDING_PREMISE_DISPUTED_GAP: Final = "finding_premise_disputed"
# tb4n3 RC-3 (ADR-046, owner decision Q4): a reviewer's limitation request the agent disclosed, and
# a rejection no reviewer on this route can rule on. Settled and disclosed, never agent work.
FINDING_LIMITATION_DISCLOSED_GAP: Final = "finding_limitation_disclosed"
FINDING_REJECTION_UNREVIEWABLE_GAP: Final = "finding_rejection_unreviewable"
_DISCLOSURE_CODES: Final[Mapping[str, str]] = MappingProxyType(
    {"assumption": ASSUMPTION_DISCLOSED_GAP, "verification_limit": VERIFICATION_LIMIT_DISCLOSED_GAP}
)

_CODE_RE: Final = re.compile(r"^[a-z][a-z0-9_]{0,127}$", re.ASCII)


_A: Final = GapClass.AGENT_ACTIONABLE
_S: Final = GapClass.STANDING_LIMITATION
_R: Final = GapClass.ROUTE_DEPENDENT
_F: Final = GapClass.FIX_OR_DECLINE


def _fix_or_decline_key(item: tuple[str, str]) -> tuple[bytes, bytes]:
    return item[0].encode(), item[1].encode()


# The ADR-032 readiness group of every code, derived from the one table of gap effects
# (``kernel.gap_effect``, ADR-046): who owes the next move. What a code does to the receipt is the
# table's other column; nothing re-classifies a code here. The rationale for each group lives with
# the table's families (``GAP_EFFECT_WHY``) and in ADR-032; the vocabulary stays closed and a code
# the build does not know is reported as ``unclassified_gap:<code>`` (agent-actionable).
GAP_CLASSIFICATION: Final[Mapping[str, GapClass]] = MappingProxyType(
    {code: row.readiness for code, row in GAP_EFFECT_TABLE.items()}
)
if not PLAN_DRIFT_GAPS <= set(GAP_CLASSIFICATION):  # pragma: no cover - closed drift vocabulary
    raise ValueError("gap_classification_plan_drift_incomplete")
if any(_CODE_RE.fullmatch(code) is None for code in GAP_CLASSIFICATION):  # pragma: no cover
    raise ValueError("gap_classification_code_invalid")


def classify_gap(
    marker: str,
    *,
    semantic_review_required: bool,
    semantic_review_current: bool,
) -> GapClass | None:
    """Resolve one gap's readiness group (ADR-032, #1209); ``None`` if the code is unknown.

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
    return unclassified_marker(code)


def split_gaps(
    markers: Iterable[str],
    *,
    semantic_review_required: bool,
    semantic_review_current: bool,
) -> GapSplit:
    """Split gap markers into agent-actionable and standing groups by their base codes.

    An unknown base code lands in the agent-actionable group as ``unclassified_gap:<code>``. A
    fix-or-decline code (#1209) is never agent work: it is split with the standing limitations,
    which the receipt discloses, and readiness names its open items separately
    (``ClosureReadinessFacts.fix_or_decline``).
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

_ADMISSIBLE_REF: Final = re.compile(
    r"^(?:evd|res)_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z"
)


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
    # remove; and whether any AI-powered review completed on this task, or was deferred before the
    # first material edit by a check whose route requires review (issue #1046: the review the task
    # owes). The defaults keep a hand-built fact set at its pre-#976 answer.
    closing_review_current: bool = True
    semantic_review_used: bool = False
    # #1143 (PR #1167 review): an AI-powered review was used before the latest recorded check,
    # the state that check judged freshness on (``freshness_review_used``).
    freshness_review_used: bool = False
    # Issue #1046 (review): the latest recorded check deferred a review its route requires before
    # the first material edit, so a routine check cannot supply the missing review; only the
    # closing review can, and readiness asks for it even while ``semantic_review_not_requested``
    # is agent work.
    semantic_review_deferred: bool = False
    # Issue #984: current findings in the terminal ``self_verified`` state. Not agent work (they
    # never count as receipt-blocking); readiness discloses them as ``finding_self_verified``.
    self_verified_finding_ids: tuple[FindingId, ...] = ()
    # Issue #1020: current findings in the final ``disputed_after_rebuttal`` state. Not agent
    # work; readiness discloses them as ``finding_disputed_after_rebuttal``.
    disputed_after_rebuttal_finding_ids: tuple[FindingId, ...] = ()
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
    # Why the check is not applicable, or why the earlier-frontier code bounds: the first later
    # record that decided it (event id, ledger sequence, family, class, closed rule, tool token).
    check_cause: CheckCause | None = None
    # tb4n3 RC-3 (ADR-046): the closure of every current finding and every effective obligation,
    # computed once by ``kernel.closure_class``. ``None`` marks a hand-built fact set that predates
    # the classes: readiness then falls back to the id lists above (acknowledged and self-verified
    # findings settle ``receipt_findings_unresolved``) exactly as before.
    finding_closures: tuple[FindingClosure, ...] | None = None
    obligation_closures: tuple[ObligationClosure, ...] | None = None
    # ADR-045: where each derived task fact came from, so the agent sees why a code fired.
    fact_lineage: tuple[FactLineage, ...] = ()
    # tb4n4 (#1044): the undeclared files the applicable check found delivered files naming,
    # ``(obligation id, item index, paths, total, created in task)``
    # (``delivered_set.undeclared_reference_rows``).
    undeclared_references: tuple[UndeclaredReferenceRow, ...] = ()
    # tb4n5 (#1050, ADR-033): the resolved obligations the ledger flags as risky to call met
    # (``kernel.acceptance_risk``: a requested item never attempted, evidence not linked to a
    # declared item, or only self-asserted evidence), sorted. Since D1 this is never a Stop item.
    # ``None`` marks a hand-built fact set that predates the rule.
    acceptance_risk_obligation_ids: tuple[ObligationId, ...] | None = None
    # Issue #1079 item 3: the newest check failed with ``coordinator_failure`` and no material
    # task or verification change followed it, and no current closing review covers this state.
    # Readiness names that as ``semantic_coordinator_failure`` and does not ask for the same
    # closing review again. A hand-built fact set defaults to false.
    coordinator_failure_unchanged: bool = False
    # n7 RC1 (#1105): the newest closing-review attempt that still covers this state ended
    # without a judgment (``unavailable`` or ``timeout``, any reason), nothing material followed
    # it, and no current closing review succeeded. Readiness names that as
    # ``semantic_review_no_judgment`` and does not ask for the closing review again: the check's
    # own continuation says what may follow. A hand-built fact set defaults to false.
    closing_review_no_judgment: bool = False
    # #1079: recorded ``evd_`` / ``res_`` ids that are admissible verification for a flagged
    # obligation (an observed verification row linked to that obligation, its target, or the
    # task, at or before this frontier). An agent-asserted id is omitted. Since D1 the derivation
    # no longer computes it (its only readers were the retired final-message attestation and a
    # duplicate status sentence), so status omits the field; a hand-built fact set may still carry
    # it for the older standing rule below.
    admissible_verification: tuple[tuple[ObligationId, tuple[str, ...]], ...] | None = None
    # Newest ``closing_review_delta`` ingestion sequence at or before this frontier, or 0 when
    # none exists. ``None`` is a hand-built fact set: status omits the field. ``0`` was computed
    # and found no material record, which is distinct from an omitted field.
    closing_material_frontier: int | None = None
    # ADR-033 (owner decision D1): ``(obligation, reasons)`` for each flagged resolved obligation
    # with neither an admissible observed link nor a recorded verification limit, in id order
    # (``claim_verification.unresolved_acceptance_risk``): the receipt's own coverage-limit set,
    # uncapped, so status, the check and the receipt agree (ADR-046). ``None`` is a hand-built
    # fact set: standing then falls back to the older linked/limited rule.
    unresolved_acceptance_risk: tuple[tuple[ObligationId, tuple[str, ...]], ...] | None = None
    # ADR-033 (D1): acknowledged obligations whose effective ``acknowledged_not_done``
    # publication directly followed a ``resolved`` one (an honest downgrade), sorted. The
    # acknowledgement re-check does not challenge them: the status note invites exactly that
    # downgrade for an output that does not meet its criteria.
    downgraded_obligation_ids: tuple[ObligationId, ...] = ()
    # Issue #1209 (ADR-032 amendment): the open ``(code, obligation)`` items an agent action
    # removes (gap table rule G4f), sorted: fix it, or decline it with a reason. An item is
    # declined, and no longer listed, once a readable, unsuperseded disclosure decision
    # (``finishup-assumption:`` or ``finishup-verification-limit:``, #995) names its obligation;
    # the receipt then lists that decision, whose rationale holds the reason, beside the code.
    # Never a Stop item and never agent work. A hand-built fact set lists none.
    fix_or_decline: tuple[tuple[str, ObligationId], ...] = ()

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
            or type(self.freshness_review_used) is not bool
            or type(self.semantic_review_deferred) is not bool
            or type(self.coordinator_failure_unchanged) is not bool
            or type(self.closing_review_no_judgment) is not bool
            or (self.check_cause is not None and type(self.check_cause) is not CheckCause)
            or (
                self.finding_closures is not None
                and (
                    type(self.finding_closures) is not tuple
                    or any(type(item) is not FindingClosure for item in self.finding_closures)
                )
            )
            or (
                self.obligation_closures is not None
                and (
                    type(self.obligation_closures) is not tuple
                    or any(type(item) is not ObligationClosure for item in self.obligation_closures)
                )
            )
        ):
            raise ValueError("closure_readiness_facts_invalid")
        for values in (
            self.receipt_blocking_finding_ids,
            self.acknowledged_finding_ids,
            self.self_verified_finding_ids,
            self.disputed_after_rebuttal_finding_ids,
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
        risky = self.acceptance_risk_obligation_ids
        if risky is not None and (
            type(risky) is not tuple or risky != tuple(sorted(set(risky), key=str.encode))
        ):
            raise ValueError("closure_readiness_facts_invalid")
        linked_refs = self.admissible_verification
        if linked_refs is not None and (
            type(linked_refs) is not tuple
            or len(linked_refs) > 8
            or any(type(item) is not tuple or len(item) != 2 for item in linked_refs)
            or tuple(item[0] for item in linked_refs)
            != tuple(sorted({item[0] for item in linked_refs}, key=str.encode))
            or any(
                type(refs) is not tuple
                or not refs
                or len(refs) > 8
                or refs != tuple(sorted(set(refs), key=str.encode))
                or any(
                    type(ref) is not str or _ADMISSIBLE_REF.fullmatch(ref) is None for ref in refs
                )
                for _obligation, refs in linked_refs
            )
        ):
            raise ValueError("closure_readiness_facts_invalid")
        material = self.closing_material_frontier
        if material is not None and (type(material) is not int or material < 0):
            raise ValueError("closure_readiness_facts_invalid")
        unresolved = self.unresolved_acceptance_risk
        if unresolved is not None and (
            type(unresolved) is not tuple
            or any(type(item) is not tuple or len(item) != 2 for item in unresolved)
            or tuple(item[0] for item in unresolved)
            != tuple(sorted({item[0] for item in unresolved}, key=str.encode))
            or any(
                type(reasons) is not tuple
                or not reasons
                or reasons
                != tuple(reason for reason in ACCEPTANCE_RISK_REASONS if reason in reasons)
                for _obligation, reasons in unresolved
            )
            or (risky is not None and not {item[0] for item in unresolved} <= set(risky))
        ):
            raise ValueError("closure_readiness_facts_invalid")
        downgraded = self.downgraded_obligation_ids
        if type(downgraded) is not tuple or downgraded != tuple(
            sorted(set(downgraded), key=str.encode)
        ):
            raise ValueError("closure_readiness_facts_invalid")
        fixable = self.fix_or_decline
        if (
            type(fixable) is not tuple
            or any(
                type(item) is not tuple
                or len(item) != 2
                or GAP_CLASSIFICATION.get(item[0]) is not _F
                for item in fixable
            )
            or fixable != tuple(sorted(set(fixable), key=_fix_or_decline_key))
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
) -> tuple[CheckApplicability, CheckStanding]:
    # The receipt's own applicability rule (application/receipt.py, kernel/receipt_capacity.py):
    # a check covers this state unless a later material record superseded it. ``check_standing``
    # is the one walk all of them share (tb4n3 RC-6).
    standing = check_standing(state, records)
    if standing.latest is None:
        return "not_recorded", standing
    if standing.check_record is None:
        return "payload_unavailable", standing
    if standing.superseded:
        return "not_applicable", standing
    if type(standing.check_record.payload) is not CheckRecordedPayload:
        return "payload_unavailable", standing
    return "applicable", standing


def _review_round_stopped(payload: CheckRecordedPayload) -> bool:
    """A check that skipped the AI-powered review because the packet twice could not show the
    content the reviewer needed (tb4n1 D3). Another review cannot assess more, so neither a
    current review nor a closing review is demanded again; the gap discloses the limit."""

    return (
        payload.semantic_status is SemanticStatus.NOT_REQUESTED
        and "semantic_review_skipped_insufficient_packet" in payload.coverage.known_gaps
    )


def _semantic_review_current(
    state: ProjectionState,
    records: tuple[LedgerRecord, ...],
    limitations: frozenset[FindingId],
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
                projection=state,
                check_event_id=record.event_id,
            )
            for later in records
        )
    return False


# Statuses of an AI-powered review attempt that did not complete for a reason a recheck by the
# agent cannot remove (policy, privacy, configuration or a human decision). A timeout or an
# unavailable or failed provider is transient: the closing review stays actionable. Their own gaps disclose it, and
# closure does not also demand a closing review the route cannot deliver.
_UNDELIVERABLE_SEMANTIC_STATUSES: Final = UNDELIVERABLE_SEMANTIC_STATUSES


def _review_deferred(payload: CheckRecordedPayload) -> bool:
    """Whether this check deferred a review its route requires before the first edit (#1046).

    A check on a route that did not require review records ``semantic_route_required: false``;
    there the deferral is a disclosure that asks for nothing, exactly like a ``deterministic_only``
    check on that route (review of #1046: otherwise an unreachable optional reviewer would keep
    the closing review demanded forever).
    """

    return (
        SEMANTIC_REVIEW_DEFERRED_BEFORE_FIRST_EDIT_GAP in payload.coverage.known_gaps
        and payload.semantic_route_required is not False
    )


def _recorded_checks(records: Iterable[LedgerRecord]) -> tuple[CheckRecordedPayload, ...]:
    return tuple(
        record.payload
        for record in records
        if record.schema.name == "check_recorded" and type(record.payload) is CheckRecordedPayload
    )


def freshness_review_used(records: Iterable[LedgerRecord]) -> bool:
    """Whether an AI-powered review was used before the latest recorded check (#1143).

    The check judges freshness at its input frontier: it is AI-advisory when the route requires
    review or ``semantic_review_used`` holds over the records before it. Status, Stop and receipts
    ask the same question of the same state, the records before the latest check, so a task's
    first AI-powered review never turns the check that ran it advisory after the fact (PR #1167
    review). Without a recorded check, every record counts.
    """

    prefix = tuple(records)
    latest = max(
        (index for index, record in enumerate(prefix) if record.schema.name == "check_recorded"),
        default=len(prefix),
    )
    return semantic_review_used(prefix[:latest])


def semantic_review_used(records: Iterable[LedgerRecord]) -> bool:
    """Whether the task already used AI-powered review (#976, #1046).

    A recorded check whose AI-powered review succeeded, or that deferred before the first edit a
    review its route requires. Such a task owes its closing review; a ``final_review: true``
    check that names no mode in a task now running local is that review (ADR-049).
    """

    return any(
        payload.semantic_status is SemanticStatus.SUCCEEDED or _review_deferred(payload)
        for payload in _recorded_checks(records)
    )


def _review_mode_undeliverable(payload: CheckRecordedPayload) -> bool:
    """Whether this check asked for AI-powered review and its task's setting kept it local.

    The owner chose local checks only, the host connection is on the strict route, review is
    turned off, or AI-powered review is not set up (ADR-049): no recheck by the agent can
    supply the review, exactly like an undeliverable review status.
    """

    review_mode = payload.review_mode
    return review_mode is not None and review_mode.local_reason is not None


def _closing_delta_after(
    check: LedgerRecord,
    records: tuple[LedgerRecord, ...],
    state: ProjectionState,
    effects: WorkspaceEffects,
) -> bool:
    """Whether a material task or verification change was recorded after *check*."""

    sequence = check.ledger.ingestion_sequence
    return any(
        later.ledger.ingestion_sequence > sequence
        and closing_review_delta(later, state, effects=effects)
        for later in records
    )


def _coordinator_failure(payload: CheckRecordedPayload) -> bool:
    return (
        payload.semantic_status is SemanticStatus.FAILED
        and payload.semantic_reason is SemanticReason.COORDINATOR_FAILURE
    )


def _capacity_refused(payload: CheckRecordedPayload) -> bool:
    """A closing review refused because its case did not fit the disclosure capacity (#1118).

    ``failed`` / ``case_capacity_exceeded`` is retryable only when the case changes: the same
    unchanged case is refused again. With nothing material after it, it ends like a review with
    no judgment (disclosed, not asked again); a material change makes the walk ask again.
    """

    return (
        payload.semantic_status is SemanticStatus.FAILED
        and payload.semantic_reason is SemanticReason.CASE_CAPACITY_EXCEEDED
    )


def _closing_review_current_check(payload: CheckRecordedPayload, state: ProjectionState) -> bool:
    """Whether this check is a closing review that still covers *state*."""

    manifest = payload.review_input_manifest
    phase = None if manifest is None else manifest.get("review_phase")
    if phase == "final":
        return True
    return phase is None and completion_claim_present(state)


# Statuses of a closing review that returned no judgment (n7 RC1, #1105), whatever the reason:
# its own continuation (``semantic_no_judgment``, ``semantic_timeout``,
# ``semantic_transport_retry``, ``semantic_capacity_exceeded``, or none for a configuration
# outcome refused before dispatch) says what may follow, never "the same closing review again".
_NO_JUDGMENT_STATUSES: Final = frozenset({SemanticStatus.UNAVAILABLE, SemanticStatus.TIMEOUT})


def _closing_review_facts(
    state: ProjectionState,
    records: tuple[LedgerRecord, ...],
    limitations: frozenset[FindingId],
) -> tuple[bool, bool, bool, bool, bool]:
    """``(current, used, deferred, coordinator_failure_unchanged, no_judgment)`` (#976, #1079).

    A check is the closing review when its recorded review input manifest names the final
    phase. A check recorded before the manifest carried the phase was final exactly when an
    effective completion claim preceded it; with no material task or verification change since
    it, the current projection's claim answers that. Bookkeeping and dispositions do not count
    as that change (``closing_review_delta``). ``limitations`` is unused here: check staleness
    still reads it through ``invalidates_recorded_check``, which this walk no longer calls.

    Issue #1046 (review): a check that deferred, before the first material edit, a review its
    route requires counts as using AI-powered review, because it stands in for the review the task
    owes; so a task whose work is not an edit is still asked for the closing review there. The
    third value says the latest check so deferred: no routine check can supply that review.

    The fourth value is true only when the newest check failed with ``coordinator_failure``,
    nothing material followed it, and no earlier closing review still covers this state. That
    failure is a FinishUP limit, not another identical ``final_review`` request. A material
    change after it asks again and clears the flag.

    The fifth value (n7 RC1, #1105) is true when the newest closing-review attempt that still
    covers this state ended without a judgment (``unavailable`` or ``timeout``) and no current
    closing review succeeded. The walk no longer falls back past it to an older, staled review:
    asking for "the closing review" again would contradict the check's own continuation. A newer
    current closing-review attempt with another outcome (refused, invalid ...) decides instead,
    so the flag stays false behind it; a newer local-only check (``not_requested``) asked for no
    review and changes nothing; an older current review that succeeded still wins. A
    material change after it asks again and clears the flag; an ordinary mid-task check without a
    judgment changes nothing.
    """

    del limitations
    checks = _recorded_checks(records)
    used = semantic_review_used(records)
    deferred = bool(checks) and _review_deferred(checks[-1])
    newest_coordinator_failure = False
    no_judgment = False
    newer_closing_attempt = False
    first = True
    effects = workspace_effects(records, state)
    for record in reversed(records):
        payload = record.payload
        if record.schema.name != "check_recorded" or type(payload) is not CheckRecordedPayload:
            continue
        stale = _closing_delta_after(record, records, state, effects)
        is_newest = first
        first = False
        if is_newest and stale:
            return False, used, deferred, False, False
        if stale:
            continue
        if is_newest and _coordinator_failure(payload):
            newest_coordinator_failure = True
            continue
        status = payload.semantic_status
        if status in _UNDELIVERABLE_SEMANTIC_STATUSES or _review_mode_undeliverable(payload):
            return True, used, deferred, False, False
        if _review_round_stopped(payload):
            return review_round_stopped(records), used, deferred, False, False
        if not _closing_review_current_check(payload, state):
            continue
        if status is SemanticStatus.SUCCEEDED:
            return True, used, deferred, False, False
        if status is SemanticStatus.NOT_REQUESTED:
            # A local-only check (``deterministic_mode``, ``no_material_semantic_case``) asked for
            # no AI-powered review, so it is no newer attempt: following the no-judgment
            # continuation's "go local-only" must not bring the closing-review request back.
            continue
        if (status in _NO_JUDGMENT_STATUSES or _capacity_refused(payload)) and not (
            newer_closing_attempt
        ):
            # The newest closing-review attempt on this state ended without a judgment. An
            # older current review that succeeded still wins; a staled one no longer does.
            no_judgment = True
        newer_closing_attempt = True
    if newest_coordinator_failure:
        return True, used, deferred, True, False
    if no_judgment:
        return True, used, deferred, False, True
    return False, used, deferred, False, False


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
        from finishup.observability.logging import record_unexpected_exception_without_raising

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


def _publication_locator_obligation(record: LedgerRecord) -> ObligationId | None:
    """The obligation an unreadable ``obligation_published`` names in its projection locator."""

    key = record.projection_locator.logical_key
    if key is None:
        return None
    try:
        return obligation_id(key)
    except ValueError:
        return None


def _downgraded_from_resolved(
    state: ProjectionState,
    records: tuple[LedgerRecord, ...],
    acknowledged: Iterable[ObligationId],
) -> tuple[ObligationId, ...]:
    """Acknowledged obligations whose effective publication downgraded a ``resolved`` one (D1).

    For each obligation in *acknowledged*, its ``obligation_published`` records at or before the
    projection frontier are read in ingestion order: it is a downgrade when the newest one is
    ``acknowledged_not_done`` and the one right before it is ``resolved``. An unreadable
    publication on either side is not a downgrade (fail toward asking); it is attributed through
    its projection locator, as the reducer does, and only one that names no obligation breaks every
    chain. An acknowledgement of work never claimed (``open`` to ``acknowledged_not_done``) is not
    one either. Pure over the projection and the prefix, so it replays to the same set.
    """

    wanted = frozenset(acknowledged)
    if not wanted:
        return ()
    versions: dict[ObligationId, list[ObligationPublishedPayload | None]] = {}
    for record in sorted(records, key=lambda row: row.ledger.ingestion_sequence):
        if (
            record.schema.name != "obligation_published"
            or record.ledger.ingestion_sequence > state.frontier
        ):
            continue
        payload = record.payload
        typed = payload if type(payload) is ObligationPublishedPayload else None
        obligation = (
            _publication_locator_obligation(record) if typed is None else typed.obligation_id
        )
        if obligation is None:
            # An unreadable publication whose locator does not name its obligation may be any
            # obligation's: it breaks every chain it could belong to, so a later acknowledgement
            # is not exempted on the strength of an older resolved version.
            for chain in versions.values():
                chain.append(None)
            continue
        if obligation in wanted:
            # An unreadable publication the locator attributes (as the reducer does) breaks only
            # that obligation's chain.
            versions.setdefault(obligation, []).append(typed)
    found: list[ObligationId] = []
    for obligation, chain in versions.items():
        if len(chain) < 2:
            continue
        newest, previous = chain[-1], chain[-2]
        if (
            newest is not None
            and previous is not None
            and newest.status is ObligationStatus.ACKNOWLEDGED_NOT_DONE
            and previous.status is ObligationStatus.RESOLVED
        ):
            found.append(obligation)
    return tuple(sorted(found, key=str.encode))


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
    # ADR-046: one classifier decides who owes the next move and what each finding does to the
    # receipt. The id lists below are views of it (a linked ``duplicate_of`` item is named by the
    # finding that answers for it, ``duplicate_counting_id``, so a pair counts once).
    finding_classes = finding_closures(state, records=records)
    blocking = {
        key
        for key, closure in counted_findings(finding_classes.values()).items()
        if closure.receipt_effect is ReceiptEffect.UNRESOLVED_FINDINGS_REMAIN
    }
    # D8 (#1243): a kind the classifier leaves out (a process note) is never listed as settled
    # here either, so readiness, the prediction and the receipt's terminal lists read one set.
    # A limitation request answered ``acknowledged_not_done`` is listed here too: the agent said
    # the requirement is NOT met (owner decision 2026-10-12). A disclosed one is not.
    acknowledged = {
        duplicate_counting_id(state, finding.finding_id)
        for finding in current
        if finding.finding_id in finding_classes
        and finding_classes[finding.finding_id].basis in ACKNOWLEDGED_NOT_DONE_BASES
    }
    self_verified = {
        closure.counts_as
        for closure in finding_classes.values()
        if closure.basis == "self_verified"
    }
    disputed = {
        closure.finding_id
        for closure in finding_classes.values()
        if closure.basis == "disputed_after_rebuttal"
    }
    # The receipt's applicability rule reads the same observation-limitation set (issue #911).
    limitations = observation_limitation_finding_ids(state, records)
    # #997: an acknowledged obligation is never open work here, whichever counting regime the
    # projection uses (L6 counts it among open obligations); it is listed once, as acknowledged.
    acknowledged_status = _acknowledged_obligation_ids(state)
    obligation_classes = obligation_closures(state, records=records)
    # ADR-046: the acknowledged list is the closure class, not the status alone. An acknowledged
    # obligation the agent also disclosed as verifiable only outside this environment is
    # ``externally_evaluated`` (disclosed), so it is listed once, there, and never as "not done".
    acknowledged_obligations = tuple(
        sorted(
            (
                item.obligation_id
                for item in obligation_classes.values()
                if item.basis == "acknowledged_not_done"
            ),
            key=str.encode,
        )
    )
    # An open obligation the agent disclosed as verifiable only outside this environment
    # (``externally_evaluated``, RC-1) is disclosed, not work: it leaves ``obligations_open``.
    externally_evaluated = {
        item.obligation_id
        for item in obligation_classes.values()
        if item.basis == "externally_evaluated"
    }
    open_obligations = tuple(
        item
        for item in open_effective_obligations(state)
        if item not in set(acknowledged_status) and item not in externally_evaluated
    )
    blocked = blocker_declarations(state, decision_batches(records))
    blocked_open = tuple(
        sorted({item for item in open_obligations if item in blocked}, key=str.encode)
    )
    closing_current, review_used, review_deferred, coordinator_failure, no_judgment = (
        _closing_review_facts(state, records, limitations)
    )
    applicability, standing = _check_applicability(state, records)
    signals = task_fact_signals(state, records)
    disclosures = disclosure_declarations(state)
    risky_pairs = acceptance_risk(
        state,
        records,
        (item.obligation_id for item in obligation_classes.values() if item.basis == "resolved"),
    )
    return ClosureReadinessFacts(
        check_applicability=applicability,
        check_cause=standing.cause if applicability in {"applicable", "not_applicable"} else None,
        semantic_review_current=_semantic_review_current(state, records, limitations),
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
        freshness_review_used=freshness_review_used(records),
        semantic_review_deferred=review_deferred,
        self_verified_finding_ids=tuple(sorted(self_verified, key=str.encode)),
        disputed_after_rebuttal_finding_ids=tuple(sorted(disputed, key=str.encode)),
        limitation_refs_required=tuple(
            required_limitation_ids_for_projection(state, observed_event_ids_from_records(records))
        ),
        disclosed_obligations=tuple(
            (item.obligation_id, item.kind, item.decision_event_id) for item in disclosures
        ),
        premise_disputed_finding_ids=premise_disputed_finding_ids(state),
        finding_closures=tuple(
            finding_classes[key] for key in sorted(finding_classes, key=str.encode)
        ),
        obligation_closures=tuple(
            obligation_classes[key] for key in sorted(obligation_classes, key=str.encode)
        ),
        fact_lineage=current_fact_lineage(state, records, applicability, signals=signals),
        undeclared_references=current_undeclared_references(state, records, applicability),
        acceptance_risk_obligation_ids=tuple(obligation for obligation, _reasons in risky_pairs),
        coordinator_failure_unchanged=coordinator_failure,
        closing_review_no_judgment=no_judgment,
        closing_material_frontier=closing_material_frontier(state, records),
        # D1: the receipt's own coverage-limit set, walked without the status cap (R5).
        unresolved_acceptance_risk=unresolved_acceptance_risk(state, records, flagged=risky_pairs),
        downgraded_obligation_ids=_downgraded_from_resolved(
            state, records, acknowledged_obligations
        ),
        fix_or_decline=_open_fix_or_decline(
            state,
            records,
            applicability,
            signals.fix_or_decline,
            declined={item.obligation_id for item in disclosures},
        ),
    )


def _open_fix_or_decline(
    state: ProjectionState,
    records: tuple[LedgerRecord, ...],
    applicability: CheckApplicability,
    planned: Iterable[tuple[str, ObligationId]],
    *,
    declined: set[ObligationId],
) -> tuple[tuple[str, ObligationId], ...]:
    """The fix-or-decline items still open at this prefix (issue #1209), sorted.

    The planned-verification items are the ledger-derived task facts' own
    (``TaskFactSignals.fix_or_decline``). ``requested_output_unchanged`` is recorded by the
    applicable check without its obligation, so it names every obligation it can concern
    (``requested_output_unchanged_candidates``) and is declined as a whole once any of them is.
    An item whose obligation a disclosure decision names is declined.
    """

    items = {item for item in planned if item[1] not in declined}
    found = _applicable_check_payload(state, records, applicability)
    if found is not None and REQUESTED_OUTPUT_UNCHANGED_GAP in found[1].coverage.known_gaps:
        candidates = requested_output_unchanged_candidates(
            state, blocked=blocked_obligations(state, decision_batches(records))
        )
        if not declined.intersection(candidates):
            items.update((REQUESTED_OUTPUT_UNCHANGED_GAP, item) for item in candidates)
    return tuple(sorted(items, key=_fix_or_decline_key))


def current_fact_lineage(
    state: ProjectionState,
    records: tuple[LedgerRecord, ...],
    applicability: CheckApplicability,
    *,
    signals: TaskFactSignals | None = None,
) -> tuple[FactLineage, ...]:
    """Where every derived task fact in force at this prefix came from (ADR-045).

    The check-time deliverable facts (``declared_output_emptied``, ``..._removed``,
    ``..._not_reviewable``) come from the newest check's recorded deliverable states, and only
    while that check still applies (a later material change makes the check, and so its facts,
    stale: ``check_not_applicable`` says so instead). The ledger-derived facts (planned
    verification, edits after the last verification) come from ``task_fact_signals`` over the
    same prefix. Sorted and bounded, so every surface renders the same list.
    """

    items: list[FactLineage] = []
    found = _applicable_check_payload(state, records, applicability)
    if found is not None:
        check_record, payload = found
        items.extend(
            deliverable_lineage(
                check_record.event_id,
                payload.subject_frontier.sequence,
                payload.deliverable_states,
            )
        )
    items.extend((task_fact_signals(state, records) if signals is None else signals).lineage)
    ordered = sorted(dict.fromkeys(items), key=lambda item: item.sort_key)
    return tuple(ordered[:MAX_FACT_LINEAGE_ITEMS])


def _applicable_check_payload(
    state: ProjectionState,
    records: tuple[LedgerRecord, ...],
    applicability: CheckApplicability,
) -> tuple[LedgerRecord, CheckRecordedPayload] | None:
    """The newest check's record and payload while that check still applies, else ``None``."""

    latest = state.latest_tested_state
    if applicability != "applicable" or latest is None:
        return None
    check_record = next(
        (record for record in records if record.event_id == latest.source_check_event_id),
        None,
    )
    if check_record is None or type(check_record.payload) is not CheckRecordedPayload:
        return None
    return check_record, check_record.payload


def current_undeclared_references(
    state: ProjectionState,
    records: tuple[LedgerRecord, ...],
    applicability: CheckApplicability,
) -> tuple[UndeclaredReferenceRow, ...]:
    """The undeclared files the applicable check found delivered files naming (tb4n4, #1044).

    Read from the newest check's recorded deliverable states, and only while that check still
    applies, exactly like the deliverable lineage: a stale check names nothing.
    """

    found = _applicable_check_payload(state, records, applicability)
    if found is None:
        return ()
    return undeclared_reference_rows(found[1].deliverable_states)


@dataclass(frozen=True, slots=True)
class ClosureReadinessSplit:
    """The checklist answer: what the agent can still do, and what the receipt will disclose."""

    state: Literal["action_required", "ready", "ready_with_limitations"]
    agent_actionable: tuple[str, ...]
    standing_limitations: tuple[str, ...]
    acknowledged_not_done: tuple[str, ...]
    acknowledged_not_done_count: int
    # Issue #1209: the open fix-or-decline ``(code, obligation)`` items, each code also listed in
    # ``standing_limitations`` (the receipt discloses it unless the agent fixes it). Never makes
    # the state ``action_required`` and never a Stop item (ADR-033 D1).
    fix_or_decline: tuple[tuple[str, str], ...] = ()


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
        if (
            condition == "receipt_findings_unresolved"
            and facts is not None
            and facts.finding_closures is not None
        ):
            # ADR-046: only a finding the agent still owes a move on is agent work. A rejection
            # that awaits a reviewer ruling is its own token (the only useful move is `check`
            # with `final_review: true`); an acknowledged requirement is final (listed under
            # acknowledged, the receipt keeps it unresolved).
            counted = {
                key: closure
                for key, closure in counted_findings(facts.finding_closures).items()
                if closure.receipt_effect is ReceiptEffect.UNRESOLVED_FINDINGS_REMAIN
            }
            classes = {closure.closure_class for closure in counted.values()}
            if counted:
                if FindingClosureClass.AGENT_WORK in classes:
                    actionable.append(condition)
                if FindingClosureClass.AWAITING_RULING in classes:
                    actionable.append(FINDING_REJECTION_AWAITING_RULING_GAP)
                continue
            # The condition names findings these facts do not classify (a count from another
            # derivation): never infer "nothing to do" from the absence of an explanation.
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
            and (
                facts.acknowledged_obligation_ids
                or any(
                    item.basis == "externally_evaluated" for item in facts.obligation_closures or ()
                )
            )
            and not facts.open_obligations_unreadable
        ):
            # #997: the only obligations the projection counts as open are acknowledged as not
            # done (L6's counting regime), or acknowledged and disclosed as verifiable only
            # outside this environment. None is agent work; each is listed once, under
            # acknowledged_not_done or as a disclosed limitation.
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
    if semantic_review_required or facts is not None and facts.freshness_review_used:
        # #1143: freshness is AI-advisory on the route the latest check judged it on, the same
        # predicate the check used at its input frontier (``freshness_review_used``).
        freshness_codes = {"planned_verification_stale", "edited_after_last_verification"}
        if freshness_codes & set(split_actionable):
            split_actionable = tuple(
                code for code in split_actionable if code not in freshness_codes
            )
            standing.add("verification_rerun_question")
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
    # already used it (or deferred it before the first edit where its route requires it, #1046);
    # not repeated while the missing review is already the actionable item, unless the latest check
    # deferred it: then no routine check can supply it and the closing review, the Stop gate's
    # review token, is the way.
    if (
        facts is not None
        and (semantic_review_required or facts.semantic_review_used)
        and not facts.closing_review_current
        and ("semantic_review_not_requested" not in actionable or facts.semantic_review_deferred)
    ):
        actionable.append("closing_review_required")
    for token in live_blockers:
        item = token if _CODE_RE.fullmatch(token) else _unclassified(token)
        if item not in actionable:
            actionable.append(item)
    standing.update(split.standing_limitations)
    if facts is not None and facts.unresolved_acceptance_risk is not None:
        # ADR-033 (D1): the receipt's coverage-limit set itself, so status names the limit
        # exactly when the check and the receipt do (ADR-046), past any status cap.
        if facts.unresolved_acceptance_risk:
            standing.add("unresolved_verification_limitation")
    elif facts is not None and facts.acceptance_risk_obligation_ids:
        # A hand-built fact set without the computed set: the older linked/limited rule.
        linked = dict(facts.admissible_verification or ())
        limited = {
            obligation
            for obligation, kind, _event in facts.disclosed_obligations
            if kind == "verification_limit"
        }
        if any(
            obligation not in limited and not linked.get(obligation)
            for obligation in facts.acceptance_risk_obligation_ids
        ):
            standing.add("unresolved_verification_limitation")
    if facts is not None and facts.finding_closures is not None:
        bases = {closure.basis for closure in facts.finding_closures}
        # A settled finding nobody owes a move on is still disclosed, never silently dropped.
        if "limitation_disclosed" in bases:
            standing.add(FINDING_LIMITATION_DISCLOSED_GAP)
        if "rejected_review_unavailable" in bases:
            standing.add(FINDING_REJECTION_UNREVIEWABLE_GAP)
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
        if facts.disputed_after_rebuttal_finding_ids:
            standing.add(FINDING_DISPUTED_AFTER_REBUTTAL_GAP)
        if facts.coordinator_failure_unchanged:
            # Not a coverage gap: the check recorded the failure. Status names it so the Stop
            # gate does not ask for the same closing review again.
            standing.add("semantic_coordinator_failure")
        if facts.closing_review_no_judgment:
            # Not a coverage gap either: the newest closing review returned no judgment, so the
            # Stop gate does not ask for it again (n7 RC1). Its own semantic facts still disclose
            # a required review as unmet.
            standing.add("semantic_review_no_judgment")
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
    fixable: tuple[tuple[str, str], ...] = ()
    if facts is not None:
        # Only a code the receipt will disclose is named: a check that no longer applies, or a
        # code a later check cleared, names nothing to fix (the readiness lists that instead).
        fixable = tuple(item for item in facts.fix_or_decline if item[0] in standing)
    return ClosureReadinessSplit(
        state=state,
        agent_actionable=tuple(actionable),
        standing_limitations=tuple(sorted(standing, key=str.encode)),
        acknowledged_not_done=acknowledged[:MAX_ACKNOWLEDGED_READINESS_ITEMS],
        acknowledged_not_done_count=len(acknowledged),
        fix_or_decline=fixable,
    )
