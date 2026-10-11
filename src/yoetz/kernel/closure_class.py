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

Owner decision Q4 (DESIGN_RC3 section 8): a reviewer's ``state_unresolved_limitation`` request does
not settle by itself. Until the agent discloses it (any ``respond`` acknowledgement with a reason,
or a recorded ``yoetz-verification-limit:<obl>`` decision covering the obligation) it is
``agent_work`` / ``limitation_requested`` with the single next action ``acknowledge``; it is
counted as "to disclose", never as receipt-blocking work. After the disclosure it is
``settled_disclosed`` / ``limitation_disclosed``, effect ``insufficient_coverage``, listed under
"Verification limits". It is never clean.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Final, Literal

from yoetz.domain.findings import FindingKind
from yoetz.domain.values import EventId, FindingId, ObligationId

__all__ = [
    "BOOKKEEPING_KINDS",
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
]

# The readiness token raised for an ``awaiting_ruling`` finding (agent-actionable: a recorded
# action clears it). Frozen here so the Stop gate, status and the check agree on the literal.
FINDING_REJECTION_AWAITING_RULING_GAP: Final = "finding_rejection_awaiting_ruling"


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
    reviewer must rule on; ``findings_unmet`` the acknowledged requirements;
    ``findings_disclosed`` the settled and disclosed ones (including disclosed limitations);
    ``findings_to_disclose`` the reviewer's limitation requests the agent has not yet disclosed.
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
