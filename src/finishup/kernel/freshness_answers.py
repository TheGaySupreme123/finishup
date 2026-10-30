"""Which recorded answer settles the verification rerun question (#1143, #1241 D9/D10).

The question is about one or more verification runs and the changes after them. A reasoned
``acknowledged`` response answers it, and that answer stands for every later question whose runs
and changes it already covered: only a change it did not cover (a new change that may be an
input) asks again. Replay-only and deterministic.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from finishup.domain.findings import ResponseDisposition
from finishup.domain.freshness_question import is_freshness_question
from finishup.domain.values import FindingId
from finishup.kernel.projections import ProjectionState

__all__ = ["FreshnessAnswer", "covering_freshness_answer", "freshness_answers"]


@dataclass(frozen=True, slots=True)
class FreshnessAnswer:
    """One reasoned answer to a rerun question: what it covered and the agent's own reason."""

    finding_id: FindingId
    refs: frozenset[str]
    reason: str
    response_frontier: int


def freshness_answers(state: ProjectionState) -> tuple[FreshnessAnswer, ...]:
    """Every reasoned ``acknowledged`` answer to a rerun question, oldest response first."""

    answers: list[FreshnessAnswer] = []
    for key, record in state.findings.items():
        finding = record.payload
        if finding is None or not is_freshness_question(finding):
            continue
        response = state.responses.get(key)
        payload = None if response is None else response.payload
        if (
            response is None
            or payload is None
            or payload.disposition is not ResponseDisposition.ACKNOWLEDGED
            or not payload.reason
            or not payload.reason.strip()
            or response.source_frontier <= record.source_frontier
            or payload.finding_frontier.sequence < finding.subject_frontier.sequence
        ):
            continue
        answers.append(
            FreshnessAnswer(
                key, frozenset(finding.subject_refs), payload.reason, response.source_frontier
            )
        )
    return tuple(sorted(answers, key=lambda item: (item.response_frontier, item.finding_id)))


def covering_freshness_answer(
    state: ProjectionState, refs: Iterable[str]
) -> FreshnessAnswer | None:
    """The latest answer whose question covered every one of *refs* (runs and changes)."""

    wanted = frozenset(refs)
    covering = [answer for answer in freshness_answers(state) if wanted <= answer.refs]
    return covering[-1] if covering else None
