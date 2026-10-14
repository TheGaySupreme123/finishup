"""Which task facts bear on one finding (tb4n2 R4 / P1-2, issue #1018, ADR-042).

Task facts (``kernel.task_facts``) describe the task's own work: a planned verification not run, a
requested output Git would not deliver, an edit after the last verification run. Closure readiness
and the Stop gate keep every one of them task-wide: they are work the agent owes whatever finding
is open. A finding's resolution reasons, however, carry the codes of the whole check as
``coverage:<code>``, so an unrelated fact used to disqualify an unrelated finding from
``respond self_verified`` (tb4n2 interleaved S: ``edited_after_last_verification`` blocked two
review findings about the decoder's benchmark result).

The scope rule is structural and replay-derived:

* an obligation-scoped fact (its marker names an obligation) bears on a finding only when the
  finding is about that obligation: an obligation subject ref, a claim subject ref naming it (a
  completion claim naming none covers every effective obligation), or an action event subject ref
  naming it;
* the task-wide ``edited_after_last_verification`` bears only on a finding about verification or
  evidence (the kinds in ``VERIFICATION_FINDING_KINDS``);
* every other code, including every non-task-fact code, bears as before.

Only ``scoped_resolution_reasons`` changes what a caller sees; nothing here changes a fact, a
finding's resolution, closure readiness or the Stop gate.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Final

from finishup.domain.events import ClaimKind, LedgerRecord
from finishup.domain.findings import FindingKind
from finishup.domain.values import ClaimId, EventId, FindingId, ObligationId
from finishup.kernel.projections import ProjectionState
from finishup.kernel.task_facts import (
    EDITED_AFTER_LAST_VERIFICATION_GAP,
    TASK_FACT_GAPS,
    effective_obligations,
    task_fact_signals,
)

__all__ = [
    "VERIFICATION_FINDING_KINDS",
    "finding_obligation_scope",
    "scoped_resolution_reasons",
    "task_fact_bears_on_finding",
]

# Findings about whether the work was verified, or whether evidence still describes it: the only
# findings a task-wide "edited after the last verification run" fact says anything about.
VERIFICATION_FINDING_KINDS: Final = frozenset(
    {
        FindingKind.CLAIM_WITHOUT_ADMISSIBLE_EVIDENCE,
        FindingKind.EVIDENCE_DOES_NOT_SUPPORT_CLAIM,
        FindingKind.STALE_EVIDENCE_FOR_CHANGED_STATE,
        FindingKind.FAILED_WORK_OMITTED,
        FindingKind.WEAK_OR_STALE_RESPONSE,
        FindingKind.LEDGER_STALE_OR_INCOMPLETE,
    }
)
_TASK_WIDE_SCOPED: Final = frozenset({EDITED_AFTER_LAST_VERIFICATION_GAP})
_CHECK_TIME_FACTS: Final = frozenset(
    code
    for code in TASK_FACT_GAPS
    if code.startswith("requested_output_") or code.startswith("declared_output_")
)
_COVERAGE_PREFIX: Final = "coverage:"


def finding_obligation_scope(
    state: ProjectionState, finding_id: FindingId
) -> frozenset[ObligationId]:
    """The obligations one finding is about; empty when it names none (or is unknown)."""

    record = state.findings.get(finding_id)
    if record is None or record.payload is None:
        return frozenset()
    scope: set[ObligationId] = set()
    actions_by_event = {
        action.source_event_id: action.payload
        for action in state.actions.values()
        if action.payload is not None
    }
    for ref in record.payload.subject_refs:
        text = str(ref)
        if text.startswith("obl_"):
            scope.add(ObligationId(text))
        elif text.startswith("clm_"):
            item = state.claims.get(ClaimId(text))
            claim = None if item is None else item.payload
            if claim is None:
                continue
            if claim.obligation_refs:
                scope.update(claim.obligation_refs)
            elif claim.claim_kind is ClaimKind.COMPLETION:
                scope.update(effective_obligations(state))
        elif text.startswith("evt_"):
            action = actions_by_event.get(EventId(text))
            if action is not None:
                scope.update(action.obligation_refs)
    return frozenset(scope)


def task_fact_bears_on_finding(
    code: str,
    *,
    state: ProjectionState,
    finding_id: FindingId,
    markers: Iterable[tuple[str, ObligationId | None]] | None,
) -> bool:
    """Whether the task-fact *code* says anything about *finding_id*.

    ``markers`` are ``task_fact_signals(state, records).markers`` for the same prefix, or ``None``
    when unknown: obligation-scoped codes then count as bearing (fail closed). A code that is not a
    task fact always bears (unchanged behaviour).
    """

    if code not in TASK_FACT_GAPS:
        return True
    record = state.findings.get(finding_id)
    if record is None or record.payload is None:
        return True
    if code in _TASK_WIDE_SCOPED:
        return record.payload.kind in VERIFICATION_FINDING_KINDS
    if code in _CHECK_TIME_FACTS or markers is None:
        # Requested- and declared-output facts come from the check-time workspace read, never
        # from ``task_fact_signals``: their obligation scope is not replayable here, so they bear
        # (fail closed).
        return True
    named = {obligation for marker, obligation in markers if marker == code}
    if None in named:
        # A task-wide fact (an install, a write outside the workspace, verification only as
        # root): a standing disclosure, kept wherever it appears.
        return True
    return bool(named & finding_obligation_scope(state, finding_id))


def scoped_resolution_reasons(
    reasons: tuple[str, ...],
    *,
    state: ProjectionState,
    finding_id: FindingId,
    records: tuple[LedgerRecord, ...] | None,
) -> tuple[str, ...]:
    """*reasons* without the ``coverage:<task fact>`` reasons that do not bear on the finding.

    ``records`` is the exact prefix ``state`` replays (``None`` when unavailable: only the
    task-wide edited-after-verification scoping applies then). Order is kept. When every reason
    would be dropped the original reasons are returned unchanged.
    """

    task_fact_reasons = [
        reason
        for reason in reasons
        if reason.startswith(_COVERAGE_PREFIX) and reason[len(_COVERAGE_PREFIX) :] in TASK_FACT_GAPS
    ]
    if not task_fact_reasons:
        return reasons
    markers = None if records is None else task_fact_signals(state, records).markers
    dropped = {
        reason
        for reason in task_fact_reasons
        if not task_fact_bears_on_finding(
            reason[len(_COVERAGE_PREFIX) :],
            state=state,
            finding_id=finding_id,
            markers=markers,
        )
    }
    scoped = tuple(reason for reason in reasons if reason not in dropped)
    # When an unrelated task fact is the only thing left between the finding and its resolution,
    # keep it: the agent clears it by doing that work (re-running its verification), and saying
    # "nothing blocks" would be false.
    return scoped if scoped else reasons
