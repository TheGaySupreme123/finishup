"""Pair a risky resolved obligation with a verification limit on the receipt (#1079).

The Stop gate can be answered by a final-message line. That line does not create a ledger link.
This rendering says what the ledger itself has: the acceptance-risk reasons, and whether a
``verification_limit`` disclosure is recorded. It does not judge whether the claim is true, and
it does not reject a claim at publish time. A generic all-met claim is not that pairing.

A projection hole must not stop the receipt. The pairing for an unreadable obligation is omitted
and a plain limitation sentence names that obligation id, or says the pairing could not be read.
"""

from __future__ import annotations

from finishup.domain.events import LedgerRecord
from finishup.domain.values import ObligationId
from finishup.kernel.acceptance_risk import acceptance_risk
from finishup.kernel.closure_class import obligation_closures
from finishup.kernel.plan_scope import current_plan_scope
from finishup.kernel.projections import ProjectionState
from finishup.kernel.task_facts import disclosure_declarations
from finishup.kernel.verification_link import admissible_verification_refs

__all__ = [
    "CLAIM_VERIFICATION_HEADER",
    "CLAIM_VERIFICATION_UNREADABLE",
    "claim_verification_lines",
    "claim_verification_report",
    "unresolved_verification_obligations",
    "UNRESOLVED_VERIFICATION_GAP",
]

CLAIM_VERIFICATION_HEADER: str = (
    "A generic all-met claim does not stand in for a linked observed verification or a "
    "finishup-verification-limit statement."
)
CLAIM_VERIFICATION_UNREADABLE: str = "The claim-verification pairing could not be read."
_MAX_NAMED_HOLES: int = 8
UNRESOLVED_VERIFICATION_GAP = "unresolved_verification_limitation"


def unresolved_verification_obligations(
    projection: ProjectionState, records: tuple[LedgerRecord, ...]
) -> tuple[ObligationId, ...]:
    """Risky resolved obligations with neither admissible verification nor a recorded limit.

    Invitation delivery is deliberately irrelevant. This is recomputed from the ledger,
    so a bounded Stop can proceed without turning an unanswered invitation into coverage.
    """
    if not records:
        return ()
    closures = obligation_closures(projection, records=records)
    resolved = (item.obligation_id for item in closures.values() if item.basis == "resolved")
    flagged = acceptance_risk(projection, records, resolved)
    limited = {
        item.obligation_id
        for item in disclosure_declarations(projection)
        if item.kind == "verification_limit"
    }
    linked = dict(
        admissible_verification_refs(projection, records, (obligation for obligation, _ in flagged))
    )
    return tuple(
        obligation
        for obligation, _ in flagged
        if obligation not in limited and not linked.get(obligation)
    )


def claim_verification_lines(
    projection: ProjectionState, records: tuple[LedgerRecord, ...]
) -> tuple[str, ...]:
    """One header and one line per flagged resolved obligation, or nothing.

    Each line is ``<obligation id> <comma-joined reason tokens> <flag>``. ``<flag>`` is
    ``verification_limit``, ``verification_limit linked <ids>``, ``linked <ids>``, or
    ``no_verification_limit``. ``<ids>`` are the comma-joined admissible observed ``evd_`` or
    ``res_`` ids. No user prose. Empty records, or no flagged obligation, leave the receipt
    body unchanged. A hole omits that obligation here; ``claim_verification_report`` carries
    the limitation sentence.
    """

    lines, _limitation = claim_verification_report(projection, records)
    return lines


def claim_verification_report(
    projection: ProjectionState, records: tuple[LedgerRecord, ...]
) -> tuple[tuple[str, ...], str]:
    """``(pairing lines, limitation sentence)``.

    The limitation sentence is empty when every in-scope obligation could be read. It names
    only obligation ids when some could not, and a fixed sentence when the plan scope itself
    could not be read or the walk failed. Pairing lines are omitted for an unreadable
    obligation. This function does not raise for a partial projection.
    """

    if type(projection) is not ProjectionState or type(records) is not tuple:
        return (), CLAIM_VERIFICATION_UNREADABLE
    try:
        limitation = _pairing_limitation(projection)
        if not records:
            return (), limitation
        unresolved = unresolved_verification_obligations(projection, records)
        if unresolved:
            named = ", ".join(str(ref) for ref in unresolved)
            sentence = (
                f"Unresolved verification limitation for {named}: no admissible observed "
                "verification link or recorded verification limit; an unanswered acceptance "
                "invitation does not establish coverage."
            )
            limitation = " ".join(part for part in (limitation, sentence) if part)
        return _pairing_lines(projection, records), limitation
    except AssertionError, KeyError, TypeError, ValueError:
        return (), CLAIM_VERIFICATION_UNREADABLE


def _pairing_limitation(projection: ProjectionState) -> str:
    scope = current_plan_scope(projection.plans, projection.coverage_gaps)
    if not scope.has_plan:
        return ""
    refs = scope.effective_obligation_refs
    if refs is None:
        return CLAIM_VERIFICATION_UNREADABLE
    missing = tuple(
        sorted(
            (
                str(item)
                for item in refs
                if (record := projection.obligations.get(item)) is None or record.payload is None
            ),
            key=str.encode,
        )
    )
    if not missing:
        return ""
    shown = ", ".join(missing[:_MAX_NAMED_HOLES])
    hidden = len(missing) - _MAX_NAMED_HOLES
    if hidden > 0:
        shown = f"{shown} and {hidden} more"
    return f"{CLAIM_VERIFICATION_UNREADABLE[:-1]} for {shown}."


def _pairing_lines(
    projection: ProjectionState, records: tuple[LedgerRecord, ...]
) -> tuple[str, ...]:
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
    linked = dict(
        admissible_verification_refs(
            projection, records, (obligation for obligation, _reasons in flagged)
        )
    )
    lines = [CLAIM_VERIFICATION_HEADER]
    for obligation, reasons in flagged:
        lines.append(
            f"{obligation} {','.join(reasons)} {_pairing_flag(obligation in limited, linked.get(obligation, ()))}"
        )
    return tuple(lines)


def _pairing_flag(limited: bool, refs: tuple[str, ...]) -> str:
    """The receipt flag: a recorded limit, admissible observed ids, or neither."""

    cited = f"linked {','.join(refs)}" if refs else ""
    if limited and cited:
        return f"verification_limit {cited}"
    if limited:
        return "verification_limit"
    if cited:
        return cited
    return "no_verification_limit"
