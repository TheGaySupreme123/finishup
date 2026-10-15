"""Pair a risky resolved obligation with a verification limit on the receipt (#1079).

The Stop gate can be answered by a final-message line. That line does not create a ledger link.
This rendering says what the ledger itself has: the acceptance-risk reasons, and whether a
``verification_limit`` disclosure is recorded. It does not judge whether the claim is true, and
it does not reject a claim at publish time. A generic all-met claim is not that pairing.
"""

from __future__ import annotations

from finishup.domain.events import LedgerRecord
from finishup.kernel.acceptance_risk import acceptance_risk
from finishup.kernel.closure_class import obligation_closures
from finishup.kernel.projections import ProjectionState
from finishup.kernel.task_facts import disclosure_declarations

__all__ = ["CLAIM_VERIFICATION_HEADER", "claim_verification_lines"]

CLAIM_VERIFICATION_HEADER: str = (
    "A generic all-met claim does not stand in for a linked observed verification or a "
    "finishup-verification-limit statement."
)


def claim_verification_lines(
    projection: ProjectionState, records: tuple[LedgerRecord, ...]
) -> tuple[str, ...]:
    """One header and one line per flagged resolved obligation, or nothing.

    Each line is ``<obligation id> <comma-joined reason tokens> verification_limit`` or
    ``no_verification_limit``. No user prose. Empty records, or no flagged obligation, leave
    the receipt body unchanged.
    """

    if type(projection) is not ProjectionState or type(records) is not tuple or not records:
        return ()
    closures = obligation_closures(projection, records=records)
    resolved = (item.obligation_id for item in closures.values() if item.basis == "resolved")
    flagged = acceptance_risk(projection, records, resolved)
    if not flagged:
        return ()
    limited = {
        item.obligation_id
        for item in disclosure_declarations(projection)
        if item.kind == "verification_limit"
    }
    lines = [CLAIM_VERIFICATION_HEADER]
    for obligation, reasons in flagged:
        flag = "verification_limit" if obligation in limited else "no_verification_limit"
        lines.append(f"{obligation} {','.join(reasons)} {flag}")
    return tuple(lines)
