"""The vocabulary of the one closure verdict (tb4n3 RC-3, issue #1026, ADR-046).

"Does this item still bound closure?" used to be answered by about fourteen places, each with its
own rule. The answer now has two parts that were never kept apart:

* the *class*: who owes the next move (the agent, the reviewer, nobody);
* the *effect*: what the item does to the receipt conclusion.

This module holds the closed tokens and the immutable value types every surface renders. The
classifier functions live beside them (``finding_closure``, ``obligation_closure``); the receipt
prediction (``kernel.receipt_prediction``) and the composer (``kernel.closure_verdict``) read these
types and nothing else, so no surface re-derives a class from raw state.

Findings (``FindingClosureClass``):

``agent_work``        the agent can still do something: repair, rebut, acknowledge or, for a
                      reviewer's limitation request, disclose the limitation once.
``awaiting_ruling``   the agent rejected an AI-powered finding with a reason and the reviewer has
                      not ruled yet: the only useful move is ``check`` with ``final_review: true``.
``settled_unmet``     final, and the requirement is not met: an acknowledged requirement. The
                      receipt keeps ``unresolved_findings_remain``.
``settled_disclosed`` final, nobody owes a move, and the receipt discloses it. "Settled" is not
                      "harmless": the receipt effect column says what it does to the label.
``resolved``          a later qualifying check proved the issue absent.

Obligations (``ObligationClosureClass``) use the same words without ``awaiting_ruling``.

Owner decision Q4 (DESIGN_RC3 section 8), with the owner's reading of ``acknowledged_not_done``
replaced on 2026-10-12 (#1024): a reviewer's ``state_unresolved_limitation`` request does not
settle by itself, and the AGENT'S ANSWER decides what it means. Until the agent answers it is
``agent_work`` / ``limitation_requested`` with the single next action ``acknowledge``; it is
counted as "to disclose", never as receipt-blocking work. A reasoned ``acknowledged`` (or a
reasoned ``self_verified``, or a recorded ``yoetz-verification-limit:<obl>`` decision covering the
obligation) says the requirement may be met but cannot be verified here: the item is
``settled_disclosed`` / ``limitation_disclosed``, effect ``insufficient_coverage``, listed under
"Verification limits", and never clean. ``acknowledged_not_done`` says the requirement is NOT met:
the item is ``settled_unmet`` / ``limitation_acknowledged_not_done``, effect
``unresolved_findings_remain``, exactly like a requirement acknowledged as not done.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Final, Literal

from yoetz.domain.events import CheckRecordedPayload, LedgerRecord, ObligationStatus
from yoetz.domain.findings import (
    FINDING_KIND_TRAITS,
    Finding,
    FindingKind,
    FindingOrigin,
    ResponseDisposition,
    is_limitation_request,
)
from yoetz.domain.task_fact_tokens import (
    FINDING_REJECTION_AWAITING_RULING_GAP as FINDING_REJECTION_AWAITING_RULING_GAP,
)
from yoetz.domain.values import EventId, FindingId, ObligationId
from yoetz.kernel.check_standing import check_standing
from yoetz.kernel.finding_todo import (
    FindingTodoState,
    duplicate_counting_id,
    finding_standing,
    finding_todo_state,
    ruling_since,
)
from yoetz.kernel.limitation import externally_evaluated_obligations, limitation_standing
from yoetz.kernel.projections import ProjectionState
from yoetz.kernel.receipt_capacity import current_receipt_findings
from yoetz.kernel.task_facts import (
    blocker_declarations,
    decision_batches,
    effective_obligations,
)
from yoetz.protocol.models import SemanticStatus

__all__ = [
    "BOOKKEEPING_KINDS",
    "UNDELIVERABLE_SEMANTIC_STATUSES",
    "FINDING_BASES",
    "FINDING_REJECTION_AWAITING_RULING_GAP",
    "NEXT_ACTIONS",
    "OBLIGATION_BASES",
    "ClosureCounts",
    "FindingClosure",
    "FindingClosureClass",
    "ObligationClosure",
    "ObligationClosureClass",
    "ReceiptEffect",
    "Recheck",
    "RecheckKind",
    "basis_class",
    "basis_effect",
    "closure_counts",
    "counted_findings",
    "finding_closure",
    "finding_closure_class",
    "finding_closures",
    "obligation_closure",
    "obligation_closures",
    "review_can_rule",
]

# The readiness token raised for an ``awaiting_ruling`` finding is frozen in the dependency-free
# token module so the Stop gate, status and the check agree on the literal.


class FindingClosureClass(str, Enum):  # noqa: UP042 - exact wire enum base
    AGENT_WORK = "agent_work"
    AWAITING_RULING = "awaiting_ruling"
    SETTLED_UNMET = "settled_unmet"
    SETTLED_DISCLOSED = "settled_disclosed"
    RESOLVED = "resolved"


class ObligationClosureClass(str, Enum):  # noqa: UP042 - exact wire enum base
    AGENT_WORK = "agent_work"
    SETTLED_UNMET = "settled_unmet"
    SETTLED_DISCLOSED = "settled_disclosed"
    RESOLVED = "resolved"


class ReceiptEffect(str, Enum):  # noqa: UP042 - exact wire enum base
    """What an item does to the receipt conclusion; ``none`` leaves it untouched."""

    NONE = "none"
    INSUFFICIENT_COVERAGE = "insufficient_coverage"
    UNRESOLVED_FINDINGS_REMAIN = "unresolved_findings_remain"


_NONE: Final = ReceiptEffect.NONE
_INSUFFICIENT: Final = ReceiptEffect.INSUFFICIENT_COVERAGE
_UNRESOLVED: Final = ReceiptEffect.UNRESOLVED_FINDINGS_REMAIN
_F: Final = FindingClosureClass
_O: Final = ObligationClosureClass

# basis -> (class, receipt effect). One row per closed basis token; the classifier picks the
# basis from the ledger and the class and the effect follow from this table alone.
FINDING_BASES: Final[Mapping[str, tuple[FindingClosureClass, ReceiptEffect]]] = MappingProxyType(
    {
        "open_unanswered": (_F.AGENT_WORK, _UNRESOLVED),
        "open_answered": (_F.AGENT_WORK, _UNRESOLVED),
        "reopened": (_F.AGENT_WORK, _UNRESOLVED),
        "limitation_requested": (_F.AGENT_WORK, _INSUFFICIENT),
        "rejected_awaiting_ruling": (_F.AWAITING_RULING, _UNRESOLVED),
        "rejected_review_unavailable": (_F.SETTLED_DISCLOSED, _INSUFFICIENT),
        "acknowledged_not_done_requirement": (_F.SETTLED_UNMET, _UNRESOLVED),
        "limitation_acknowledged_not_done": (_F.SETTLED_UNMET, _UNRESOLVED),
        "acknowledged_not_done_bookkeeping": (_F.SETTLED_DISCLOSED, _INSUFFICIENT),
        "self_verified": (_F.SETTLED_DISCLOSED, _INSUFFICIENT),
        "disputed_after_rebuttal": (_F.SETTLED_DISCLOSED, _INSUFFICIENT),
        "rejection_accepted": (_F.SETTLED_DISCLOSED, _NONE),
        "limitation_disclosed": (_F.SETTLED_DISCLOSED, _INSUFFICIENT),
        "absence_proved": (_F.RESOLVED, _NONE),
        "absence_proved_after_acknowledged_not_done": (_F.RESOLVED, _NONE),
        "absence_proved_after_self_verified": (_F.RESOLVED, _NONE),
    }
)

OBLIGATION_BASES: Final[Mapping[str, tuple[ObligationClosureClass, ReceiptEffect]]] = (
    MappingProxyType(
        {
            "open": (_O.AGENT_WORK, _INSUFFICIENT),
            "blocker_claimed": (_O.AGENT_WORK, _INSUFFICIENT),
            "resolved_deliverable_emptied": (_O.AGENT_WORK, _INSUFFICIENT),
            "acknowledged_not_done": (_O.SETTLED_UNMET, _INSUFFICIENT),
            "blocker_confirmed": (_O.SETTLED_DISCLOSED, _INSUFFICIENT),
            "externally_evaluated": (_O.SETTLED_DISCLOSED, _INSUFFICIENT),
            "resolved": (_O.RESOLVED, _NONE),
        }
    )
)

# The closed vocabulary of "what the agent may do next" on a finding.
NEXT_ACTIONS: Final = (
    "repair",
    "recheck",
    "reject",
    "acknowledge",
    "acknowledge_not_done",
    "self_verify",
    "reopen",
    "none",
)

# The one actionable work-integrity kind whose acknowledgement is bookkeeping, not an unmet
# requirement: an action recorded without a result (priority 3). Kept as data so the set is
# reviewed in one place.
BOOKKEEPING_KINDS: Final = frozenset({FindingKind.ACTION_WITHOUT_RESULT})


def basis_class(basis: str) -> FindingClosureClass:
    return FINDING_BASES[basis][0]


def basis_effect(basis: str) -> ReceiptEffect:
    return FINDING_BASES[basis][1]


@dataclass(frozen=True, slots=True)
class FindingClosure:
    """One finding's class, why (``basis``), effect and lineage."""

    finding_id: FindingId
    closure_class: FindingClosureClass
    basis: str
    receipt_effect: ReceiptEffect
    next_actions: tuple[str, ...]
    # The frontier at which the standing position was taken, when a recorded fact names one.
    since_frontier: int | None
    # At most three events that decided it (the response, the ruling, the proving check).
    source_event_ids: tuple[EventId, ...]
    # ``duplicate_counting_id``: a linked pair counts once, under the earlier finding.
    counts_as: FindingId

    def __post_init__(self) -> None:
        if (
            self.basis not in FINDING_BASES
            or FINDING_BASES[self.basis] != (self.closure_class, self.receipt_effect)
            or any(item not in NEXT_ACTIONS for item in self.next_actions)
            or len(self.source_event_ids) > 3
        ):
            raise ValueError("finding_closure_invalid")


@dataclass(frozen=True, slots=True)
class ObligationClosure:
    """One obligation's class, why (``basis``), effect and lineage."""

    obligation_id: ObligationId
    closure_class: ObligationClosureClass
    basis: str
    receipt_effect: ReceiptEffect
    since_frontier: int | None
    source_event_ids: tuple[EventId, ...]

    def __post_init__(self) -> None:
        if (
            self.basis not in OBLIGATION_BASES
            or OBLIGATION_BASES[self.basis] != (self.closure_class, self.receipt_effect)
            or len(self.source_event_ids) > 3
        ):
            raise ValueError("obligation_closure_invalid")


@dataclass(frozen=True, slots=True)
class ClosureCounts:
    """The counters every surface prints; nothing else is counted.

    ``findings_to_do`` is agent work the receipt waits for (``agent_work`` other than a
    limitation request, plus ``awaiting_ruling``); ``findings_awaiting_ruling`` is the subset the
    reviewer must rule on; ``findings_unmet`` the acknowledged requirements (a limitation request
    answered ``acknowledged_not_done`` included); ``findings_disclosed`` the settled and disclosed
    ones (including disclosed limitations); ``findings_to_disclose`` the reviewer's limitation
    requests the agent has not yet answered.
    Wire form: ``finding_counts {to_do, awaiting_ruling, unmet, disclosed, to_disclose,
    self_verify_eligible}`` and ``obligation_counts {open, acknowledged, disclosed}``.
    """

    findings_to_do: int = 0
    findings_awaiting_ruling: int = 0
    findings_unmet: int = 0
    findings_disclosed: int = 0
    findings_to_disclose: int = 0
    findings_self_verify_eligible: int = 0
    obligations_open: int = 0
    obligations_acknowledged: int = 0
    obligations_disclosed: int = 0

    def __post_init__(self) -> None:
        values = (
            self.findings_to_do,
            self.findings_awaiting_ruling,
            self.findings_unmet,
            self.findings_disclosed,
            self.findings_to_disclose,
            self.findings_self_verify_eligible,
            self.obligations_open,
            self.obligations_acknowledged,
            self.obligations_disclosed,
        )
        if any(type(value) is not int or value < 0 for value in values) or (
            self.findings_awaiting_ruling > self.findings_to_do
            or self.findings_self_verify_eligible > self.findings_to_do
        ):
            raise ValueError("closure_counts_invalid")

    @property
    def receipt_blocking_findings(self) -> int:
        """The wire value of ``receipt_blocking_finding_count``: to do plus unmet."""

        return self.findings_to_do + self.findings_unmet


type RecheckKind = Literal["acceptance", "acknowledgement", "blocker", "premise"]


@dataclass(frozen=True, slots=True)
class Recheck:
    """One once-per-frontier re-read the Stop gate may ask for (RC-8), as a stateless candidate.

    Delivery memory ("asked once per session") stays client-side in the gate; the candidate list
    is computed by the service so status, closure_prepare, the CLI, the TUI and the gate read one
    list. ``key`` is content keyed (``accept:<h8 of resolved ids>``, ``ack:<obl>``,
    ``blocker:<obl>:<kind>``, ``premise:<n>``).
    """

    kind: RecheckKind
    key: str
    subjects: tuple[str, ...]
    rule: str
    since_frontier: int

    def __post_init__(self) -> None:
        if (
            self.kind not in {"acceptance", "acknowledgement", "blocker", "premise"}
            or type(self.key) is not str
            or not self.key
            or type(self.subjects) is not tuple
            or type(self.rule) is not str
            or type(self.since_frontier) is not int
            or self.since_frontier < 0
        ):
            raise ValueError("recheck_invalid")


# ---------------------------------------------------------------------------------------------
# The classifier: one function per item kind, replay-derived, no side effects
# ---------------------------------------------------------------------------------------------

# Statuses of an AI-powered review attempt that did not complete for a reason a recheck by the
# agent cannot remove (policy, privacy, configuration or a human decision). A timeout or an
# unavailable or failed provider is transient. Shared by the closing-review rule (closure
# readiness) and by "can the reviewer still rule on a rejection" below.
UNDELIVERABLE_SEMANTIC_STATUSES: Final = frozenset(
    {
        SemanticStatus.BLOCKED_BY_POLICY,
        SemanticStatus.BLOCKED_FORBIDDEN_DATA,
        SemanticStatus.NOT_CONFIGURED,
        SemanticStatus.CLASSIFICATION_UNCERTAIN,
        SemanticStatus.HUMAN_DENIED,
        SemanticStatus.APPROVAL_EXPIRED,
    }
)


def review_can_rule(state: ProjectionState, records: Iterable[LedgerRecord] = ()) -> bool:
    """Whether a reviewer can still rule on a rejected AI-powered finding on this task's route.

    Derived from the latest recorded check only, so status, check and the receipt (which cannot
    see the serving route) agree: a route that recorded ``semantic_route_required: false`` with no
    review requested never dispatches one (a strict MCP route, ADR-018), and a review attempt that
    ended for a durable reason (policy, privacy, configuration, a human decision) will not
    succeed on a retry. With no check recorded yet the answer is yes: the next ``check`` decides.
    """

    latest = state.latest_tested_state
    if latest is None:
        return True
    check = next(
        (
            record.payload
            for record in records
            if record.event_id == latest.source_check_event_id
            and type(record.payload) is CheckRecordedPayload
        ),
        None,
    )
    if check is None:
        return True
    if check.semantic_status in UNDELIVERABLE_SEMANTIC_STATUSES:
        return False
    return not (
        check.semantic_route_required is False
        and check.semantic_status is SemanticStatus.NOT_REQUESTED
    )


def _make(
    state: ProjectionState,
    finding: Finding,
    basis: str,
    next_actions: tuple[str, ...],
    *,
    since: int | None,
    sources: tuple[EventId, ...],
) -> FindingClosure:
    klass, effect = FINDING_BASES[basis]
    return FindingClosure(
        finding.finding_id,
        klass,
        basis,
        effect,
        next_actions,
        since,
        sources[:3],
        duplicate_counting_id(state, finding.finding_id),
    )


def finding_closure(
    state: ProjectionState,
    finding_id: FindingId,
    *,
    records: tuple[LedgerRecord, ...] = (),
    review_can_rule_: bool | None = None,
    self_verify_eligible: bool = False,
) -> FindingClosure | None:
    """The class, basis and receipt effect of one finding; ``None`` for a coverage-only kind.

    ``review_can_rule_`` defaults to ``review_can_rule(state, records)``. ``self_verify_eligible``
    adds the ``self_verify`` next action; ``finding_closures`` computes it from ``records``.
    """

    record = state.findings.get(finding_id)
    if record is None or record.payload is None:
        return None
    finding = record.payload
    if not FINDING_KIND_TRAITS[finding.kind][1]:
        return None
    todo = finding_todo_state(state, finding_id)
    response = state.responses.get(finding_id)
    disposition = (
        None if response is None or response.payload is None else response.payload.disposition
    )
    response_event = () if response is None else (response.source_event_id,)
    response_frontier = None if response is None else response.source_frontier
    limitation = is_limitation_request(finding)

    if todo is FindingTodoState.VERIFIED_RESOLVED:
        if disposition is ResponseDisposition.ACKNOWLEDGED_NOT_DONE:
            basis = "absence_proved_after_acknowledged_not_done"
        elif disposition is ResponseDisposition.SELF_VERIFIED:
            basis = "absence_proved_after_self_verified"
        else:
            basis = "absence_proved"
        proof = record.resolved_by_check_event_id
        return _make(
            state,
            finding,
            basis,
            ("none",),
            since=response_frontier,
            sources=() if proof is None else (proof,),
        )
    if todo is FindingTodoState.REJECTION_ACCEPTED:
        ruling = record.rejection_accepted_by_check_event_id
        return _make(
            state,
            finding,
            "rejection_accepted",
            ("none",),
            since=response_frontier,
            sources=(*response_event, *(() if ruling is None else (ruling,))),
        )
    if todo is FindingTodoState.DISPUTED_AFTER_REBUTTAL:
        ruling = record.disputed_after_rebuttal_by_check_event_id
        return _make(
            state,
            finding,
            "disputed_after_rebuttal",
            ("none",),
            since=response_frontier,
            sources=(*response_event, *(() if ruling is None else (ruling,))),
        )
    if todo is FindingTodoState.SELF_VERIFIED:
        return _make(
            state,
            finding,
            "self_verified",
            ("recheck",),
            since=response_frontier,
            sources=response_event,
        )
    if todo is FindingTodoState.ACKNOWLEDGED_NOT_DONE:
        # The agent's answer decides (owner decision 2026-10-12): ``acknowledged_not_done`` on a
        # reviewer's limitation request says the requirement is NOT met, so it is an unmet
        # requirement, not a verification limit.
        if limitation:
            basis = "limitation_acknowledged_not_done"
        else:
            basis = (
                "acknowledged_not_done_bookkeeping"
                if finding.kind in BOOKKEEPING_KINDS
                else "acknowledged_not_done_requirement"
            )
        return _make(
            state,
            finding,
            basis,
            ("reopen", "repair"),
            since=response_frontier,
            sources=response_event,
        )

    # Open: the agent still owes a move, or the reviewer owes a ruling.
    standing = finding_standing(state, finding_id)
    rejected = standing is not None and standing[0] == ResponseDisposition.REJECTED.value
    if rejected and finding.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED:
        ruled = ruling_since(state, finding_id)
        assert standing is not None
        if ruled is None or ruled < standing[1]:
            can_rule = (
                review_can_rule(state, records) if review_can_rule_ is None else review_can_rule_
            )
            if can_rule:
                return _make(
                    state,
                    finding,
                    "rejected_awaiting_ruling",
                    ("recheck", "repair", "acknowledge_not_done"),
                    since=standing[1],
                    sources=response_event,
                )
            return _make(
                state,
                finding,
                "rejected_review_unavailable",
                ("recheck",),
                since=standing[1],
                sources=response_event,
            )
    if limitation and not rejected:
        # One implementation of the Q4 lifecycle: ``kernel.limitation`` (recorded facts only, G2).
        standing_limit = limitation_standing(state, finding_id)
        if standing_limit is not None and standing_limit.disclosed:
            return _make(
                state,
                finding,
                "limitation_disclosed",
                ("none",),
                since=standing_limit.since_frontier,
                sources=standing_limit.source_event_ids,
            )
        return _make(
            state,
            finding,
            "limitation_requested",
            # Issue #1043: the agent's own criterion may also be fixed (a later check proves it
            # absent); narrowing it with a reason is the disclosure.
            ("acknowledge", "repair")
            if finding.kind is FindingKind.AGENT_CRITERION_UNMET
            else ("acknowledge",),
            since=None,
            sources=(),
        )
    actions = ["repair", "reject", "acknowledge_not_done"]
    if self_verify_eligible:
        actions.append("self_verify")
    return _make(
        state,
        finding,
        "reopened"
        if disposition is ResponseDisposition.REOPENED
        else "open_answered"
        if disposition is not None
        else "open_unanswered",
        tuple(actions),
        since=response_frontier,
        sources=response_event,
    )


def finding_closure_class(
    state: ProjectionState, finding_id: FindingId, **kwargs: object
) -> FindingClosureClass | None:
    """Convenience: the class of ``finding_closure`` or ``None``."""

    closure = finding_closure(state, finding_id, **kwargs)  # type: ignore[arg-type]
    return None if closure is None else closure.closure_class


def finding_closures(
    state: ProjectionState,
    *,
    records: tuple[LedgerRecord, ...] = (),
    review_can_rule_: bool | None = None,
    with_self_verify: bool = True,
) -> Mapping[FindingId, FindingClosure]:
    """Closures of every current finding (the newest readable row per receipt issue key).

    A resolved finding is included (class ``resolved``): history is part of the verdict. With
    ``records`` the ``self_verify`` next action is offered only for an agent-work finding that
    ``respond`` would accept as ``self_verified`` (``self_verification_refusal``).
    """

    can_rule = review_can_rule(state, records) if review_can_rule_ is None else review_can_rule_
    closures: dict[FindingId, FindingClosure] = {}
    for finding in current_receipt_findings(state):
        eligible = False
        if records and with_self_verify:
            first = finding_closure(
                state, finding.finding_id, records=records, review_can_rule_=can_rule
            )
            if first is not None and first.basis in {
                "open_unanswered",
                "open_answered",
                "reopened",
            }:
                from yoetz.kernel.self_verification import self_verification_refusal

                eligible = self_verification_refusal(state, finding.finding_id, records) is None
        closure = finding_closure(
            state,
            finding.finding_id,
            records=records,
            review_can_rule_=can_rule,
            self_verify_eligible=eligible,
        )
        if closure is not None:
            closures[finding.finding_id] = closure
    return MappingProxyType(closures)


def _emptied_obligations(
    state: ProjectionState, records: tuple[LedgerRecord, ...]
) -> frozenset[ObligationId]:
    """Obligations whose declared deliverable the newest applicable check found emptied.

    The path-keyed fact ``declared_output_emptied`` (ADR-045) as the newest check recorded it: a
    deliverable state whose ``change`` is ``emptied`` or ``truncated`` and that no
    ``yoetz-assumption`` decision accepted (``accepted_by``). It speaks only while that check
    still applies: a later material record (an edit that refills the file, the decision that
    accepts the path) supersedes the check, the fact is then stale and the obligation reads
    ``resolved`` again until the next check re-reads the file. Without ``records`` nothing is
    inferred.
    """

    latest = state.latest_tested_state
    if latest is None or not records:
        return frozenset()
    check = next((item for item in records if item.event_id == latest.source_check_event_id), None)
    payload = getattr(check, "payload", None)
    if type(payload) is not CheckRecordedPayload:
        return frozenset()
    emptied = frozenset(
        item.obligation_id
        for item in payload.deliverable_states
        if item.change in {"emptied", "truncated"} and item.accepted_by is None
    )
    if not emptied or check_standing(state, records).superseded:
        return frozenset()
    return emptied


def obligation_closures(
    state: ProjectionState, *, records: Iterable[LedgerRecord] = ()
) -> Mapping[ObligationId, ObligationClosure]:
    """Closures of every effective obligation of the current plan chain."""

    ledger = tuple(records)
    emptied = _emptied_obligations(state, ledger)
    blocked = blocker_declarations(state, decision_batches(ledger))
    external = externally_evaluated_obligations(state)
    closures: dict[ObligationId, ObligationClosure] = {}
    for obligation in effective_obligations(state):
        record = state.obligations[obligation]
        payload = record.payload
        assert payload is not None
        status = payload.status
        sources: tuple[EventId, ...] = (record.source_event_id,)
        if status is ObligationStatus.RESOLVED:
            # A resolution whose deliverable was later emptied is not delivered (ADR-045): the
            # agent can still restore it, and the receipt reads below clean until it does.
            basis = "resolved_deliverable_emptied" if obligation in emptied else "resolved"
        elif obligation in external:
            basis = "externally_evaluated"
        elif status is ObligationStatus.ACKNOWLEDGED_NOT_DONE:
            basis = "acknowledged_not_done"
        elif obligation in blocked:
            declaration = blocked[obligation]
            sources = (declaration.decision_event_id,)
            if declaration.confirmation_event_id is not None:
                sources = (*sources, declaration.confirmation_event_id)
            basis = (
                "blocker_confirmed"
                if declaration.confirmation_event_id is not None
                else "blocker_claimed"
            )
        else:
            basis = "open"
        klass, effect = OBLIGATION_BASES[basis]
        closures[obligation] = ObligationClosure(
            obligation, klass, basis, effect, record.source_frontier, sources[:3]
        )
    return MappingProxyType(closures)


def obligation_closure(
    state: ProjectionState, obligation_id: ObligationId, *, records: Iterable[LedgerRecord] = ()
) -> ObligationClosure | None:
    return obligation_closures(state, records=records).get(obligation_id)


_EFFECT_SEVERITY: Final = {_UNRESOLVED: 0, _INSUFFICIENT: 1, _NONE: 2}
_CLASS_SEVERITY: Final = {
    _F.AGENT_WORK: 0,
    _F.AWAITING_RULING: 1,
    _F.SETTLED_UNMET: 2,
    _F.SETTLED_DISCLOSED: 3,
    _F.RESOLVED: 4,
}


def _severity_key(closure: FindingClosure) -> tuple[int, int, bytes]:
    return (
        _EFFECT_SEVERITY[closure.receipt_effect],
        _CLASS_SEVERITY[closure.closure_class],
        str(closure.finding_id).encode(),
    )


def counted_findings(findings: Iterable[FindingClosure]) -> dict[FindingId, FindingClosure]:
    """One closure per counted finding: a ``counts_as`` group is represented by its most severe member.

    Severity orders by receipt effect (``unresolved_findings_remain`` before
    ``insufficient_coverage`` before ``none``), then by class (``agent_work``,
    ``awaiting_ruling``, ``settled_unmet``, ``settled_disclosed``, ``resolved``), then by finding
    id, so the representative is deterministic and a group never reads cleaner than its worst
    member. Every counter, reason, list and readiness id that names findings reads this one
    selection (ADR-046), so a count and the ids it summarises can never differ.
    """

    seen: dict[FindingId, FindingClosure] = {}
    for closure in findings:
        prior = seen.get(closure.counts_as)
        if prior is None or _severity_key(closure) < _severity_key(prior):
            seen[closure.counts_as] = closure
    return seen


def closure_counts(
    findings: Iterable[FindingClosure], obligations: Iterable[ObligationClosure]
) -> ClosureCounts:
    """The counters every surface prints; a linked ``duplicate_of`` pair counts once."""

    seen = counted_findings(findings)
    to_do = awaiting = unmet = disclosed = to_disclose = eligible = 0
    for closure in seen.values():
        klass = closure.closure_class
        if klass is FindingClosureClass.AGENT_WORK:
            if closure.basis == "limitation_requested":
                to_disclose += 1
            else:
                to_do += 1
                eligible += "self_verify" in closure.next_actions
        elif klass is FindingClosureClass.AWAITING_RULING:
            to_do += 1
            awaiting += 1
        elif klass is FindingClosureClass.SETTLED_UNMET:
            unmet += 1
        elif klass is FindingClosureClass.SETTLED_DISCLOSED:
            disclosed += 1
    open_ = acknowledged = disclosed_obligations = 0
    for obligation in obligations:
        if obligation.closure_class is ObligationClosureClass.AGENT_WORK:
            open_ += 1
        elif obligation.closure_class is ObligationClosureClass.SETTLED_UNMET:
            acknowledged += 1
        elif obligation.closure_class is ObligationClosureClass.SETTLED_DISCLOSED:
            disclosed_obligations += 1
    return ClosureCounts(
        findings_to_do=to_do,
        findings_awaiting_ruling=awaiting,
        findings_unmet=unmet,
        findings_disclosed=disclosed,
        findings_to_disclose=to_disclose,
        findings_self_verify_eligible=eligible,
        obligations_open=open_,
        obligations_acknowledged=acknowledged,
        obligations_disclosed=disclosed_obligations,
    )
