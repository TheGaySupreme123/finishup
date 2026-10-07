"""Findings as a converging to-do list (issue #905).

Every recorded finding is in exactly one to-do state, read from replay-derived projection facts
only, so status, check, receipts and ``respond`` all agree:

- ``open``: still to do.
- ``verified_resolved``: a later qualifying check proved it absent (``finding_is_resolved``).
- ``acknowledged_not_done``: the agent answered, with a required reason, that it will not do it.
  It is never re-reviewed and never reads as clean.
- ``rejection_accepted``: the agent rejected an AI-powered finding with a reason and a later
  review withdrew it. It no longer blocks a receipt but stays disclosed. When the withdrawing
  review would also have proved the item absent, the explicit ruling wins: the item is
  ``rejection_accepted``, not ``verified_resolved``.

The last three are terminal: no transition leaves them, and ``respond`` refuses to record anything
further on a terminal item. New evidence about the same problem becomes a new finding. The
transition table is kept as data in ``TODO_TRANSITIONS``.

``review_rounds`` counts later checks that assessed an item and left it open. The owner's attempt
budget (``verification.finding_attempt_budget``, default 5) only changes what Yoetz asks for next:
at the budget it asks for a repair with new evidence or an explicit ``acknowledged_not_done``. It
never throttles ``check`` and never closes or acknowledges anything on the agent's behalf.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum
from typing import Final

from yoetz.domain.findings import (
    FINDING_KIND_TRAITS,
    Finding,
    FindingKind,
    FindingOrigin,
    ResponseDisposition,
)
from yoetz.domain.values import FindingId
from yoetz.kernel.finding_resolution import finding_is_resolved
from yoetz.kernel.projections import ProjectionState

__all__ = [
    "DEFAULT_FINDING_ATTEMPT_BUDGET",
    "MAX_FINDING_ATTEMPT_BUDGET",
    "TERMINAL_TODO_STATES",
    "TODO_TRANSITIONS",
    "FindingTodo",
    "FindingTodoCounts",
    "FindingTodoState",
    "PREMISE_CHALLENGE_KINDS",
    "finding_blocks_receipt",
    "is_premise_challenge",
    "standing_premise_disputes",
    "finding_todo",
    "finding_todo_state",
    "todo_counts",
]

DEFAULT_FINDING_ATTEMPT_BUDGET: Final = 5
MAX_FINDING_ATTEMPT_BUDGET: Final = 50


class FindingTodoState(str, Enum):  # noqa: UP042 - exact wire enum base
    OPEN = "open"
    VERIFIED_RESOLVED = "verified_resolved"
    ACKNOWLEDGED_NOT_DONE = "acknowledged_not_done"
    REJECTION_ACCEPTED = "rejection_accepted"


TERMINAL_TODO_STATES: Final = frozenset(
    {
        FindingTodoState.VERIFIED_RESOLVED,
        FindingTodoState.ACKNOWLEDGED_NOT_DONE,
        FindingTodoState.REJECTION_ACCEPTED,
    }
)

# The only transitions a recorded item makes, and what makes each one. Terminal states have none.
TODO_TRANSITIONS: Final[tuple[tuple[FindingTodoState, str, FindingTodoState], ...]] = (
    (FindingTodoState.OPEN, "qualifying_check_proves_absent", FindingTodoState.VERIFIED_RESOLVED),
    (
        FindingTodoState.OPEN,
        "respond_acknowledged_not_done_with_reason",
        FindingTodoState.ACKNOWLEDGED_NOT_DONE,
    ),
    (
        FindingTodoState.OPEN,
        "reviewer_withdraws_after_reasoned_rejection",
        FindingTodoState.REJECTION_ACCEPTED,
    ),
)


@dataclass(frozen=True, slots=True)
class FindingTodo:
    finding_id: FindingId
    state: FindingTodoState
    review_rounds: int
    attempt_budget: int
    # An ``acknowledged_not_done`` premise challenge the reviewer still disputes (TB4 tb4n1 D7a);
    # see ``standing_premise_disputes``. Never changes the state.
    premise_disputed: bool = False

    @property
    def budget_reached(self) -> bool:
        return self.state is FindingTodoState.OPEN and self.review_rounds >= self.attempt_budget


@dataclass(frozen=True, slots=True)
class FindingTodoCounts:
    open: int = 0
    verified_resolved: int = 0
    acknowledged_not_done: int = 0
    rejection_accepted: int = 0
    budget_reached: int = 0


def _validated_budget(attempt_budget: int) -> int:
    if type(attempt_budget) is not int or not 1 <= attempt_budget <= MAX_FINDING_ATTEMPT_BUDGET:
        raise ValueError("finding_attempt_budget_invalid")
    return attempt_budget


def finding_todo_state(state: ProjectionState, finding_id: FindingId) -> FindingTodoState:
    """The one shared to-do state of a recorded finding."""

    record = state.findings.get(finding_id)
    if record is None or record.payload is None:
        return FindingTodoState.OPEN
    response = state.responses.get(finding_id)
    disposition = (
        None if response is None or response.payload is None else response.payload.disposition
    )
    # ``respond`` refuses anything after a terminal state, so an ``acknowledged_not_done``
    # response is always the item's last word and precedes any later absence proof.
    if disposition is ResponseDisposition.ACKNOWLEDGED_NOT_DONE:
        return FindingTodoState.ACKNOWLEDGED_NOT_DONE
    if finding_is_resolved(state, finding_id):
        return FindingTodoState.VERIFIED_RESOLVED
    if (
        record.rejection_accepted_by_check_event_id is not None
        and disposition is ResponseDisposition.REJECTED
    ):
        return FindingTodoState.REJECTION_ACCEPTED
    return FindingTodoState.OPEN


def finding_todo(
    state: ProjectionState,
    finding_id: FindingId,
    *,
    attempt_budget: int = DEFAULT_FINDING_ATTEMPT_BUDGET,
) -> FindingTodo:
    budget = _validated_budget(attempt_budget)
    record = state.findings.get(finding_id)
    rounds = 0 if record is None else record.review_rounds
    todo_state = finding_todo_state(state, finding_id)
    disputed = (
        todo_state is FindingTodoState.ACKNOWLEDGED_NOT_DONE
        and record is not None
        and record.payload is not None
        and is_premise_challenge(record.payload)
    )
    return FindingTodo(finding_id, todo_state, rounds, budget, disputed)


# A premise challenge (TB4 tb4n1 D7a): the reviewer says a stated requirement is not delivered or
# never attempted and asks the agent to do it (``act``). These are the reviewer's answer to an
# agent concluding the outcome is impossible, infeasible or blocked (cargo, pretrain).
PREMISE_CHALLENGE_KINDS: Final = frozenset(
    {FindingKind.TASK_REQUIREMENT_UNMET, FindingKind.REQUESTED_ITEM_NEVER_ATTEMPTED}
)


def is_premise_challenge(finding: Finding) -> bool:
    """Whether *finding* is an AI-powered challenge to the premise that the outcome is out of reach."""

    return (
        finding.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED
        and finding.kind in PREMISE_CHALLENGE_KINDS
        and finding.challenge is not None
        and finding.challenge.requested_next_step == "act"
    )


def standing_premise_disputes(
    state: ProjectionState, finding_ids: Iterable[FindingId] | None = None
) -> tuple[FindingId, ...]:
    """Premise challenges the agent answered ``acknowledged_not_done`` (TB4 tb4n1 D7a).

    ``acknowledged_not_done`` keeps its meaning ("I will not do it") and stays final. But when the
    reviewer challenged the agent's give-up itself (the requirement is unmet and the reviewer asked
    for it to be done), the acknowledgement does not settle the dispute: the reviewer still
    disputes the infeasibility conclusion. These items are returned in finding-id order so a
    readiness or Stop surface can show them once as standing disputes. Nothing here changes a
    to-do state, blocks a check, or closes anything; the receipt already keeps every
    ``acknowledged_not_done`` item receipt-blocking.
    """

    candidates = state.findings if finding_ids is None else finding_ids
    return tuple(
        key
        for key in sorted(candidates, key=str.encode)
        if finding_todo(state, key).premise_disputed
    )


def finding_blocks_receipt(state: ProjectionState, finding_id: FindingId) -> bool:
    """Whether a current actionable finding keeps a receipt from reading clean.

    ``rejection_accepted`` is the only unresolved state that stops blocking; it stays disclosed.
    ``acknowledged_not_done`` keeps blocking: it is never clean.
    """

    record = state.findings.get(finding_id)
    if record is None or record.payload is None:
        return False
    if not FINDING_KIND_TRAITS[record.payload.kind][1]:
        return False
    return finding_todo_state(state, finding_id) not in {
        FindingTodoState.VERIFIED_RESOLVED,
        FindingTodoState.REJECTION_ACCEPTED,
    }


def todo_counts(
    state: ProjectionState,
    finding_ids: Iterable[FindingId],
    *,
    attempt_budget: int = DEFAULT_FINDING_ATTEMPT_BUDGET,
) -> FindingTodoCounts:
    values = {item: 0 for item in FindingTodoState}
    reached = 0
    for current in finding_ids:
        item = finding_todo(state, current, attempt_budget=attempt_budget)
        values[item.state] += 1
        reached += item.budget_reached
    return FindingTodoCounts(
        open=values[FindingTodoState.OPEN],
        verified_resolved=values[FindingTodoState.VERIFIED_RESOLVED],
        acknowledged_not_done=values[FindingTodoState.ACKNOWLEDGED_NOT_DONE],
        rejection_accepted=values[FindingTodoState.REJECTION_ACCEPTED],
        budget_reached=reached,
    )
