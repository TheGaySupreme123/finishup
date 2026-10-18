"""The composer: one closure verdict from the ledger, printed by every surface (ADR-046).

Status, the check's next step, the Stop gate, ``closure_prepare``, the MCP, CLI and terminal
renderings and the receipt do not decide whether an item still bounds closure. They print this
verdict. It holds the classes of every finding and obligation, the gaps judged once, the
readiness split (who owes the next move), the counters, the receipt conclusion the state would
carry and the once-per-frontier re-checks the Stop gate may ask for (acknowledgement, blocker and
premise). Acceptance-provenance risk is not among them (ADR-033, owner decision D1): status names
it once and the receipt records it as a coverage limit.

The pieces it composes are pure and replay-derived: nothing here is stored, and a ledger replays
to the same verdict after a restart, a reattach or an upgrade.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Final

from finishup.domain.values import Frontier
from finishup.kernel.closure_class import (
    ClosureCounts,
    FindingClosure,
    ObligationClosure,
    Recheck,
    closure_counts,
)
from finishup.kernel.closure_readiness import ClosureReadinessFacts, ClosureReadinessSplit
from finishup.kernel.gap_effect import GapEffect
from finishup.kernel.receipt_prediction import (
    ClosureBasis,
    ReceiptPrediction,
    predict_receipt_conclusion,
)

__all__ = [
    "MAX_RECHECK_SUBJECTS",
    "ClosureVerdict",
    "Recheck",
    "closure_verdict",
    "rechecks_from_closures",
]

MAX_RECHECK_SUBJECTS: Final = 8


@dataclass(frozen=True, slots=True)
class ClosureVerdict:
    frontier: Frontier
    findings: tuple[FindingClosure, ...]
    obligations: tuple[ObligationClosure, ...]
    gaps: tuple[GapEffect, ...]
    readiness: ClosureReadinessSplit
    prediction: ReceiptPrediction
    counts: ClosureCounts
    rechecks: tuple[Recheck, ...]


def rechecks_from_closures(
    obligations: Iterable[ObligationClosure],
    facts: ClosureReadinessFacts | None,
    *,
    acknowledged_count: int,
) -> tuple[Recheck, ...]:
    """The stateless once-per-frontier re-check candidates (RC-8); delivery memory stays in the gate.

    * ``acknowledgement``: an obligation acknowledged as not done that is not disclosed as
      verifiable only outside this environment. ``since_frontier`` is when it was acknowledged.
      An honest downgrade (``facts.downgraded_obligation_ids``: the acknowledgement directly
      followed a ``resolved`` publication, ADR-033 D1) is not challenged: status invites exactly
      that downgrade for an output that does not meet its criteria.
    * ``blocker``: a recorded blocker the agent claimed and has not confirmed.
    * ``premise``: an acknowledged finding the reviewer still disputes (D7a).

    No ``acceptance`` re-check is emitted (ADR-033, owner decision D1). The wire kind stays
    defined so a status from an earlier 0.3 build still validates; the gate drops it.
    """

    rows = tuple(obligations)
    out: list[Recheck] = []
    downgraded = frozenset(() if facts is None else facts.downgraded_obligation_ids)
    for item in sorted(rows, key=lambda row: str(row.obligation_id).encode()):
        if item.basis == "acknowledged_not_done" and item.obligation_id not in downgraded:
            out.append(
                Recheck(
                    "acknowledgement",
                    f"ack:{item.obligation_id}",
                    (str(item.obligation_id),),
                    "obligation_acknowledged_not_done",
                    item.since_frontier or 0,
                )
            )
    if facts is not None:
        confirmed = set(facts.confirmed_blocked_obligation_ids)
        since = {item.obligation_id: item.since_frontier or 0 for item in rows}
        for obligation, kind, _decision in facts.blocked_obligation_details:
            if obligation in confirmed:
                continue
            out.append(
                Recheck(
                    "blocker",
                    f"blocker:{obligation}:{kind}",
                    (str(obligation),),
                    "obligation_blocker_claimed",
                    since.get(obligation, 0),
                )
            )
        if facts.premise_disputed_finding_ids:
            out.append(
                Recheck(
                    "premise",
                    f"premise:{acknowledged_count}",
                    tuple(str(item) for item in facts.premise_disputed_finding_ids)[
                        :MAX_RECHECK_SUBJECTS
                    ],
                    "acknowledged_finding_premise_disputed",
                    0,
                )
            )
    return tuple(out)


def closure_verdict(
    *,
    basis: ClosureBasis,
    readiness: ClosureReadinessSplit,
    facts: ClosureReadinessFacts | None,
    findings: tuple[FindingClosure, ...] | None = None,
    obligations: tuple[ObligationClosure, ...] | None = None,
) -> ClosureVerdict:
    """Compose the verdict from the receipt basis, the readiness split and the readiness facts.

    ``findings`` and ``obligations`` default to the facts' closures (status carries the
    self-verify eligibility there) and fall back to the basis's.
    """

    finding_rows = (
        findings
        if findings is not None
        else (
            facts.finding_closures
            if facts is not None and facts.finding_closures is not None
            else basis.findings
        )
    )
    obligation_rows = (
        obligations
        if obligations is not None
        else (
            facts.obligation_closures
            if facts is not None and facts.obligation_closures is not None
            else basis.obligations
        )
    )
    return ClosureVerdict(
        basis.frontier,
        finding_rows,
        obligation_rows,
        basis.gaps,
        readiness,
        predict_receipt_conclusion(basis),
        closure_counts(finding_rows, obligation_rows),
        rechecks_from_closures(
            obligation_rows, facts, acknowledged_count=readiness.acknowledged_not_done_count
        ),
    )
