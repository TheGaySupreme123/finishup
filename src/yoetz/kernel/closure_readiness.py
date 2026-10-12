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
from types import MappingProxyType
from typing import Final, Literal, cast

from yoetz.domain.events import CheckRecordedPayload, LedgerRecord
from yoetz.domain.receipts import COMPLETION_PLAN_NOT_CLAIMED_GAP
from yoetz.domain.values import EventId, FindingId, ObligationId
from yoetz.kernel import finding_todo as _finding_todo_module
from yoetz.kernel.check_standing import CheckCause, CheckStanding, check_standing
from yoetz.kernel.claim_limitations import required_limitation_ids_for_projection
from yoetz.kernel.claims import completion_claim_present
from yoetz.kernel.closure_class import (
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
from yoetz.kernel.delivered_set import deliverable_lineage
from yoetz.kernel.fact_lineage import MAX_FACT_LINEAGE_ITEMS, FactLineage
from yoetz.kernel.finding_resolution import finding_is_resolved
from yoetz.kernel.finding_todo import (
    FindingTodoState,
    duplicate_counting_id,
    finding_todo_state,
)
from yoetz.kernel.gap_effect import (
    GAP_EFFECT_TABLE,
    UNCLASSIFIED_GAP_PREFIX,
    GapClass,
    gap_base_code,
    unclassified_marker,
)
from yoetz.kernel.observed_failures import observed_event_ids_from_records
from yoetz.kernel.plan_drift import PLAN_DRIFT_GAPS
from yoetz.kernel.plan_scope import current_plan_scope
from yoetz.kernel.projections import ProjectionState, observation_limitation_finding_ids
from yoetz.kernel.receipt_capacity import current_receipt_findings
from yoetz.kernel.reducers import invalidates_recorded_check
from yoetz.kernel.review_round import review_round_stopped
from yoetz.kernel.task_facts import (
    OBLIGATION_BLOCKED_GAP,
    OBLIGATION_BLOCKER_UNCONFIRMED_GAP,
    acknowledged_obligation_ids,
    blocker_declarations,
    decision_batches,
    disclosure_declarations,
    open_effective_obligations,
    task_fact_signals,
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
# fact with provenance (tb4n3 RC-5, issue #1028, ADR-045).
GAP_CLASSIFICATION_VERSION: Final = "7"
# Issue #1020 (ADR-040): a current AI-powered finding the reviewer repeated over the agent's
# reasoned rejection without newer material. A standing disagreement; never agent work.
FINDING_DISPUTED_AFTER_REBUTTAL_GAP: Final = "finding_disputed_after_rebuttal"
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
    return unclassified_marker(code)


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
            )
            for later in records
        )
    return False


# Statuses of an AI-powered review attempt that did not complete for a reason a recheck by the
# agent cannot remove (policy, privacy, configuration or a human decision). A timeout or an
# unavailable or failed provider is transient: the closing review stays actionable. Their own gaps disclose it, and
# closure does not also demand a closing review the route cannot deliver.
_UNDELIVERABLE_SEMANTIC_STATUSES: Final = UNDELIVERABLE_SEMANTIC_STATUSES


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
                projection=state,
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
    # ADR-046: one classifier decides who owes the next move and what each finding does to the
    # receipt. The id lists below are views of it (a linked ``duplicate_of`` item is named by the
    # finding that answers for it, ``duplicate_counting_id``, so a pair counts once).
    finding_classes = finding_closures(state, records=records)
    blocking = {
        key
        for key, closure in counted_findings(finding_classes.values()).items()
        if closure.receipt_effect is ReceiptEffect.UNRESOLVED_FINDINGS_REMAIN
    }
    acknowledged = {
        duplicate_counting_id(state, finding.finding_id)
        for finding in current
        # A limitation request answered ``acknowledged_not_done`` is listed here too: the agent
        # said the requirement is NOT met (owner decision 2026-10-12). A disclosed one is not.
        if finding_acknowledged_not_done(state, finding.finding_id)
        or finding_todo_state(state, finding.finding_id) is FindingTodoState.ACKNOWLEDGED_NOT_DONE
    }
    self_verified = {
        duplicate_counting_id(state, finding.finding_id)
        for finding in current
        if finding_todo_state(state, finding.finding_id) is FindingTodoState.SELF_VERIFIED
    }
    disputed = {
        finding.finding_id
        for finding in current
        if finding_todo_state(state, finding.finding_id) is FindingTodoState.DISPUTED_AFTER_REBUTTAL
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
    closing_current, review_used = _closing_review_facts(state, records, limitations)
    applicability, standing = _check_applicability(state, records)
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
        self_verified_finding_ids=tuple(sorted(self_verified, key=str.encode)),
        disputed_after_rebuttal_finding_ids=tuple(sorted(disputed, key=str.encode)),
        limitation_refs_required=tuple(
            required_limitation_ids_for_projection(state, observed_event_ids_from_records(records))
        ),
        disclosed_obligations=tuple(
            (item.obligation_id, item.kind, item.decision_event_id)
            for item in disclosure_declarations(state)
        ),
        premise_disputed_finding_ids=premise_disputed_finding_ids(state),
        finding_closures=tuple(
            finding_classes[key] for key in sorted(finding_classes, key=str.encode)
        ),
        obligation_closures=tuple(
            obligation_classes[key] for key in sorted(obligation_classes, key=str.encode)
        ),
        fact_lineage=current_fact_lineage(state, records, applicability),
    )


def current_fact_lineage(
    state: ProjectionState,
    records: tuple[LedgerRecord, ...],
    applicability: CheckApplicability,
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
    latest = state.latest_tested_state
    if applicability == "applicable" and latest is not None:
        check_record = next(
            (record for record in records if record.event_id == latest.source_check_event_id),
            None,
        )
        if check_record is not None and type(check_record.payload) is CheckRecordedPayload:
            items.extend(
                deliverable_lineage(
                    check_record.event_id,
                    check_record.payload.subject_frontier.sequence,
                    check_record.payload.deliverable_states,
                )
            )
    items.extend(task_fact_signals(state, records).lineage)
    ordered = sorted(dict.fromkeys(items), key=lambda item: item.sort_key)
    return tuple(ordered[:MAX_FACT_LINEAGE_ITEMS])


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
