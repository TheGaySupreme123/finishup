"""What the verification rerun question cost and earned, from the ledger alone (#1241 D9).

Counts only: the questions answered, and the reruns that followed an answer and whether they
changed the covered run's result. Derived from replayed events, so a harness export reconciles
with the ledger whatever the diagnostics ring kept.
"""

from __future__ import annotations

from dataclasses import dataclass

from finishup.kernel.freshness_answers import freshness_answers
from finishup.kernel.observed_failures import command_identity
from finishup.kernel.projections import ProjectionState

__all__ = ["RerunAccounting", "rerun_question_accounting"]


@dataclass(frozen=True, slots=True)
class RerunAccounting:
    answered: int
    reruns_after_answer: int
    reruns_after_answer_changed: int


def rerun_question_accounting(state: ProjectionState) -> RerunAccounting:
    """Answered questions, and reruns of a covered run's command after its answer."""

    answers = freshness_answers(state)
    by_event = {str(row.source_event_id): row for row in state.results.values()}
    reruns = 0
    changed = 0
    for answer in answers:
        for ref in sorted(answer.refs):
            covered = by_event.get(ref)
            if covered is None or covered.payload is None:
                continue
            action = state.actions.get(covered.payload.action_id)
            identity = (
                None
                if action is None or action.payload is None
                else command_identity(action.payload.command)
            )
            if identity is None:
                continue
            later = [
                row
                for row in state.results.values()
                if row.payload is not None
                and row.source_frontier > answer.response_frontier
                and (other := state.actions.get(row.payload.action_id)) is not None
                and other.payload is not None
                and command_identity(other.payload.command) == identity
            ]
            if not later:
                continue
            reruns += 1
            first = min(later, key=lambda row: row.source_frontier)
            assert first.payload is not None
            if first.payload.outcome is not covered.payload.outcome:
                changed += 1
    return RerunAccounting(len(answers), reruns, changed)
