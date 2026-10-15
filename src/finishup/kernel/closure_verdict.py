"""The composer: one closure verdict from the ledger, printed by every surface (ADR-046).

Status, the check's next step, the Stop gate, ``closure_prepare``, the MCP, CLI and terminal
renderings and the receipt do not decide whether an item still bounds closure. They print this
verdict. It holds the classes of every finding and obligation, the gaps judged once, the
readiness split (who owes the next move), the counters, the receipt conclusion the state would
carry and the once-per-frontier re-reads the Stop gate may ask for.

The pieces it composes are pure and replay-derived: nothing here is stored, and a ledger replays
to the same verdict after a restart, a reattach or an upgrade.
"""

from __future__ import annotations

import hashlib
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
    "ACCEPTANCE_RISK_RULE",
    "MAX_RECHECK_SUBJECTS",
    "ClosureVerdict",
    "Recheck",
    "closure_verdict",
    "rechecks_from_closures",
]

MAX_RECHECK_SUBJECTS: Final = 8
# tb4n5 (#1050): the rule token of an acceptance re-read limited to the ledger-flagged obligations.
ACCEPTANCE_RISK_RULE: Final = "resolved_obligations_acceptance_risk"


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


def _digest8(values: Iterable[str]) -> str:
    return hashlib.sha256("\n".join(values).encode("ascii")).hexdigest()[:8]


def rechecks_from_closures(
    obligations: Iterable[ObligationClosure],
    facts: ClosureReadinessFacts | None,
    *,
    acknowledged_count: int,
) -> tuple[Recheck, ...]:
    """The stateless once-per-frontier re-read candidates (RC-8); delivery memory stays in the gate.

    * ``acceptance`` (A-12): at least one resolved obligation the ledger flags as risky to call
      met (``facts.acceptance_risk_obligation_ids``, tb4n5 #1050); the key names that set, so a
      changed set asks again and an unchanged one does not. A fact set without the risk list (a
      hand-built one that predates the rule) names every resolved obligation, as before. An
      obligation with a recorded ``verification_limit`` disclosure is left out (#1079): that
      statement is already on the ledger, and the receipt still names it.
    * ``acknowledgement``: an obligation acknowledged as not done that is not disclosed as
      verifiable only outside this environment. ``since_frontier`` is when it was acknowledged,
      so an acknowledgement recorded after an acceptance re-read was delivered is not asked again.
    * ``blocker``: a recorded blocker the agent claimed and has not confirmed.
    * ``premise``: an acknowledged finding the reviewer still disputes (D7a).
    """

    rows = tuple(obligations)
    out: list[Recheck] = []
    risky_ids = None if facts is None else facts.acceptance_risk_obligation_ids
    risky = None if risky_ids is None else frozenset(risky_ids)
    # A recorded verification limit is the statement the flagged rule asks for (#1079). It leaves
    # the acceptance re-read, including the legacy unflagged rule. The receipt still lists it.
    limited = {
        obligation
        for obligation, kind, _decision in (() if facts is None else facts.disclosed_obligations)
        if kind == "verification_limit"
    }
    asked = [
        item
        for item in rows
        if item.basis == "resolved"
        and (risky is None or item.obligation_id in risky)
        and item.obligation_id not in limited
    ]
    resolved = sorted((str(item.obligation_id) for item in asked), key=str.encode)
    if resolved:
        newest = max(item.since_frontier or 0 for item in asked)
        out.append(
            Recheck(
                "acceptance",
                f"accept:{_digest8(resolved)}",
                tuple(resolved[:MAX_RECHECK_SUBJECTS]),
                (
                    "resolved_obligations_acceptance_reread"
                    if risky is None
                    else ACCEPTANCE_RISK_RULE
                ),
                newest,
            )
        )
    for item in sorted(rows, key=lambda row: str(row.obligation_id).encode()):
        if item.basis == "acknowledged_not_done":
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
