"""Pair a risky resolved obligation with a verification limit on the receipt (#1079).

Acceptance-provenance risk is never a Stop item (ADR-033, owner decision D1): status names it once
and the receipt records it as a coverage limit. This module is the single source of that limit's
set (``unresolved_acceptance_risk``), which status, the check and the receipt all read. The
rendering says what the ledger itself has: the acceptance-risk reasons, and whether a
``verification_limit`` disclosure or an admissible observed link is recorded. It does not judge
whether the claim is true, and it does not reject a claim at publish time. A generic all-met claim
is not that pairing.

A projection hole must not stop the receipt. The pairing for an unreadable obligation is omitted
and a plain limitation sentence names that obligation id, or says the pairing could not be read.
"""

from __future__ import annotations

from finishup.domain.events import LedgerRecord
from finishup.domain.receipts import UNRESOLVED_VERIFICATION_GAP
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
    "unresolved_acceptance_risk",
    "unresolved_verification_obligations",
    "UNRESOLVED_VERIFICATION_GAP",
]

CLAIM_VERIFICATION_HEADER: str = (
    "A generic all-met claim does not stand in for a linked observed verification or a "
    "finishup-verification-limit statement."
)
CLAIM_VERIFICATION_UNREADABLE: str = "The claim-verification pairing could not be read."
_MAX_NAMED_HOLES: int = 8


def unresolved_acceptance_risk(
    projection: ProjectionState,
    records: tuple[LedgerRecord, ...],
    *,
    flagged: tuple[tuple[ObligationId, tuple[str, ...]], ...] | None = None,
) -> tuple[tuple[ObligationId, tuple[str, ...]], ...]:
    """``(obligation, reasons)`` for each flagged resolved obligation the receipt bounds on.

    A flagged obligation (``kernel.acceptance_risk``) with neither an admissible observed
    verification link nor a recorded ``verification_limit`` disclosure, in id order. ``flagged``
    is the caller's already-computed ``acceptance_risk`` pairs for this same projection and
    prefix; ``None`` computes them from the closure classes. Every flagged obligation is walked
    (no cap), so status, the check and the receipt read one set (ADR-046).
    """

    if not records:
        return ()
    if flagged is None:
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
    candidates = tuple(obligation for obligation, _ in flagged if obligation not in limited)
    linked = dict(admissible_verification_refs(projection, records, candidates, limit=None))
    return tuple(
        (obligation, reasons)
        for obligation, reasons in flagged
        if obligation not in limited and not linked.get(obligation)
    )


def unresolved_verification_obligations(
    projection: ProjectionState, records: tuple[LedgerRecord, ...]
) -> tuple[ObligationId, ...]:
    """Risky resolved obligations with neither admissible verification nor a recorded limit.

    The ids of ``unresolved_acceptance_risk``. Recomputed from the ledger, never from what a
    surface showed or what a final message said.
    """

    return tuple(obligation for obligation, _ in unresolved_acceptance_risk(projection, records))


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
                f"Acceptance provenance not established for {named}: no admissible observed "
                "verification link or recorded verification limit; the receipt records this as "
                "a coverage limit."
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
            projection, records, (obligation for obligation, _reasons in flagged), limit=None
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
