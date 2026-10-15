"""The receipt's conclusion as one pure function of the closure basis (tb4n3 RC-3, ADR-046).

Sixteen of sixteen successful tb4n3 runs ended on a status that said "Nothing further to do" and
then received a receipt below clean, because nothing computed the receipt's own question before the
receipt existed. ``predict_receipt_conclusion`` is that computation: the receipt builder's
conclusion rules, extracted, ordered and named. The receipt builder calls it to choose the label,
and status, the check, the Stop gate, ``closure_prepare`` and the three human renderings call it
over the same basis to print the label before the receipt is asked for, so "status predicted X and
the receipt said Y" cannot happen by construction. A property test over every recorded run locks
the equality.

The first rule that fires selects the conclusion (the order is the receipt's own); every rule that
fires is kept as a reason, so a surface can say both "unresolved" and "also insufficient". Each
reason carries the rule id, a count, at most three referenced ids and the frontier it began at
(owner lineage rule: the text says why it fired).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum
from typing import Final

from finishup.domain.findings import CheckVerdict
from finishup.domain.values import Frontier
from finishup.kernel.closure_class import (
    FindingClosure,
    FindingClosureClass,
    ObligationClosure,
    ReceiptEffect,
    counted_findings,
)
from finishup.kernel.gap_effect import GapEffect, GapEffectKind

__all__ = [
    "MAX_LISTED_REASONS",
    "PREDICTION_REASON_CODES",
    "AppliedCheck",
    "ClosureBasis",
    "LineageBasis",
    "PredictionConclusion",
    "PredictionReason",
    "ReceiptPrediction",
    "predict_receipt_conclusion",
]

MAX_LISTED_REASONS: Final = 8
_MAX_REFS: Final = 3

_COMPLETION_SCOPE_GAPS: Final = frozenset(
    {"completion_scope_declared_none", "completion_scope_undeclared"}
)


class PredictionConclusion(str, Enum):  # noqa: UP042 - exact wire enum base
    """The three receipt conclusions, by wire value (``ReceiptConclusion`` mirrors them)."""

    UNRESOLVED_FINDINGS_REMAIN = "unresolved_findings_remain"
    INSUFFICIENT_COVERAGE = "insufficient_coverage"
    NO_UNRESOLVED_DETERMINISTIC_FINDINGS = "no_unresolved_deterministic_findings"


# reason code -> rule id (lineage). The code is the closed token a surface renders.
PREDICTION_REASON_CODES: Final = {
    "completion_scope_gap": "R1",
    "findings_to_do": "R2",
    "findings_awaiting_ruling": "R2",
    "findings_unmet": "R2",
    "child_findings_actionable": "R2",
    "limitations_to_disclose": "R3",
    "findings_disclosed": "R3",
    "obligations_open": "R4",
    "obligations_acknowledged": "R4",
    "obligations_disclosed": "R4",
    "lineage_blocks": "R5",
    "no_applicable_check": "R6",
    "check_suppressed_findings": "R7",
    "check_verdict_insufficient": "R8",
    "policy_execution_incomplete": "R9",
    "live_gap_bounds": "R10",
}


@dataclass(frozen=True, slots=True)
class AppliedCheck:
    """The facts of the applicable check the conclusion reads, nothing more."""

    verdict: CheckVerdict
    suppressed_count: int
    executions_complete: bool

    def __post_init__(self) -> None:
        if (
            type(self.verdict) is not CheckVerdict
            or type(self.suppressed_count) is not int
            or self.suppressed_count < 0
            or type(self.executions_complete) is not bool
        ):
            raise ValueError("applied_check_invalid")


@dataclass(frozen=True, slots=True)
class LineageBasis:
    """What child tasks do to the parent's conclusion."""

    actionable_finding_ids: tuple[str, ...] = ()
    blocks_clean_completion: bool = False


@dataclass(frozen=True, slots=True)
class ClosureBasis:
    """Exactly what the conclusion reads: the findings, obligations and gaps, judged once."""

    frontier: Frontier
    findings: tuple[FindingClosure, ...]
    obligations: tuple[ObligationClosure, ...]
    # Live gaps (a cleared historical gap is history and bounds nothing), already judged with the
    # ``GapContext`` of the applicable check.
    gaps: tuple[GapEffect, ...]
    check: AppliedCheck | None
    lineage: LineageBasis | None = None
    # Live dependency facts a receipt cannot disclose yet (``live_lineage_blockers``): while any
    # exists the prediction is provisional.
    live_blockers: tuple[str, ...] = ()
    check_in_flight: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.frontier) is not Frontier
            or type(self.findings) is not tuple
            or type(self.obligations) is not tuple
            or type(self.gaps) is not tuple
            or (self.check is not None and type(self.check) is not AppliedCheck)
        ):
            raise ValueError("closure_basis_invalid")


@dataclass(frozen=True, slots=True)
class PredictionReason:
    code: str
    rule: str
    count: int
    refs: tuple[str, ...]
    since_frontier: int | None

    def __post_init__(self) -> None:
        if (
            PREDICTION_REASON_CODES.get(self.code) != self.rule
            or type(self.count) is not int
            or self.count < 1
            or len(self.refs) > _MAX_REFS
        ):
            raise ValueError("prediction_reason_invalid")


@dataclass(frozen=True, slots=True)
class ReceiptPrediction:
    conclusion: PredictionConclusion
    # Every rule that fired, the one that selected the conclusion first; at most
    # ``MAX_LISTED_REASONS`` are kept and ``reason_total`` says how many fired.
    reasons: tuple[PredictionReason, ...]
    reason_total: int
    basis_frontier: Frontier
    provisional: bool

    @property
    def primary(self) -> PredictionReason | None:
        return self.reasons[0] if self.reasons else None


def _refs(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted(set(values), key=str.encode))[:_MAX_REFS]


def _earliest(values: Iterable[int | None]) -> int | None:
    present = [value for value in values if value is not None]
    return min(present) if present else None


def _reasons(basis: ClosureBasis) -> list[PredictionReason]:
    reasons: list[PredictionReason] = []

    def add(code: str, count: int, refs: Iterable[str], since: int | None) -> None:
        if count:
            reasons.append(
                PredictionReason(code, PREDICTION_REASON_CODES[code], count, _refs(refs), since)
            )

    live = [gap for gap in basis.gaps if gap.kind is not GapEffectKind.HISTORICAL]
    scope = [gap for gap in live if gap.code in _COMPLETION_SCOPE_GAPS]
    add("completion_scope_gap", len(scope), (gap.code for gap in scope), None)

    counted = counted_findings(basis.findings)
    work = [
        item
        for item in counted.values()
        if item.closure_class is FindingClosureClass.AGENT_WORK
        and item.receipt_effect is ReceiptEffect.UNRESOLVED_FINDINGS_REMAIN
    ]
    awaiting = [
        item
        for item in counted.values()
        if item.closure_class is FindingClosureClass.AWAITING_RULING
    ]
    unmet = [
        item for item in counted.values() if item.closure_class is FindingClosureClass.SETTLED_UNMET
    ]
    add(
        "findings_to_do",
        len(work),
        (str(i.finding_id) for i in work),
        _earliest(i.since_frontier for i in work),
    )
    add(
        "findings_awaiting_ruling",
        len(awaiting),
        (str(i.finding_id) for i in awaiting),
        _earliest(i.since_frontier for i in awaiting),
    )
    add(
        "findings_unmet",
        len(unmet),
        (str(i.finding_id) for i in unmet),
        _earliest(i.since_frontier for i in unmet),
    )
    if basis.lineage is not None:
        add(
            "child_findings_actionable",
            len(basis.lineage.actionable_finding_ids),
            basis.lineage.actionable_finding_ids,
            None,
        )

    to_disclose = [i for i in counted.values() if i.basis == "limitation_requested"]
    disclosed = [
        item
        for item in counted.values()
        if item.receipt_effect is ReceiptEffect.INSUFFICIENT_COVERAGE
        and item.basis != "limitation_requested"
    ]
    add(
        "limitations_to_disclose",
        len(to_disclose),
        (str(i.finding_id) for i in to_disclose),
        _earliest(i.since_frontier for i in to_disclose),
    )
    add(
        "findings_disclosed",
        len(disclosed),
        (str(i.finding_id) for i in disclosed),
        _earliest(i.since_frontier for i in disclosed),
    )

    binding = [item for item in basis.obligations if item.receipt_effect is not ReceiptEffect.NONE]
    for code, bases in (
        ("obligations_open", {"open", "blocker_claimed", "resolved_deliverable_emptied"}),
        ("obligations_acknowledged", {"acknowledged_not_done"}),
        ("obligations_disclosed", {"blocker_confirmed", "externally_evaluated"}),
    ):
        group = [item for item in binding if item.basis in bases]
        add(
            code,
            len(group),
            (str(i.obligation_id) for i in group),
            _earliest(i.since_frontier for i in group),
        )

    if basis.lineage is not None and basis.lineage.blocks_clean_completion:
        add("lineage_blocks", 1, (), None)
    check = basis.check
    if check is None:
        add("no_applicable_check", 1, (), None)
    else:
        add("check_suppressed_findings", check.suppressed_count, (), None)
        if check.verdict in {
            CheckVerdict.INSUFFICIENT_COVERAGE,
            CheckVerdict.INCOMPLETE_CHECK,
            CheckVerdict.ACTION_REQUIRED,
        }:
            # A recorded ``action_required`` whose findings are all settled now reads here instead
            # of failing the receipt (migration note: the findings carry the work, not the label).
            add("check_verdict_insufficient", 1, (check.verdict.value,), None)
        if not check.executions_complete:
            add("policy_execution_incomplete", 1, (), None)
    bounding = [gap for gap in live if gap.kind.bounds]
    add("live_gap_bounds", len(bounding), (gap.code for gap in bounding), None)
    return reasons


def predict_receipt_conclusion(basis: ClosureBasis) -> ReceiptPrediction:
    """Return the conclusion a receipt over ``basis`` carries, and every reason behind it.

    Order (the receipt's own, first match wins): a missing completion scope; an open or unmet
    finding or an actionable child finding (``unresolved_findings_remain``); every other bound
    reads ``insufficient_coverage``; otherwise ``no_unresolved_deterministic_findings``.
    """

    if type(basis) is not ClosureBasis:
        raise ValueError("closure_basis_invalid")
    reasons = _reasons(basis)
    rules = {reason.rule for reason in reasons}
    if "R1" in rules:
        conclusion = PredictionConclusion.INSUFFICIENT_COVERAGE
    elif "R2" in rules:
        conclusion = PredictionConclusion.UNRESOLVED_FINDINGS_REMAIN
    elif reasons:
        conclusion = PredictionConclusion.INSUFFICIENT_COVERAGE
    else:
        conclusion = PredictionConclusion.NO_UNRESOLVED_DETERMINISTIC_FINDINGS
    return ReceiptPrediction(
        conclusion,
        tuple(reasons[:MAX_LISTED_REASONS]),
        len(reasons),
        basis.frontier,
        provisional=bool(basis.live_blockers) or basis.check_in_flight,
    )
