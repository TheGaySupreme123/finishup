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
- ``self_verified`` (issue #984, ADR-034): the agent repaired it, Yoetz could not prove the repair
  because of its own limits, and the agent verified it itself with a reason and its own recorded
  evidence (admission: ``kernel/self_verification.py``). It is not agent work and no longer counts
  as receipt-blocking, but it is never resolved: it stays disclosed and keeps the receipt
  conclusion at best ``insufficient_coverage``.

The last four are terminal: no transition leaves them, and ``respond`` refuses to record anything
further on a terminal item. New evidence about the same problem becomes a new finding. The
transition table is kept as data in ``TODO_TRANSITIONS``.

A ``duplicate_of`` answer (issue #996, ADR-034 amendment) adds no state of its own and never
makes a finding read clean. While its link holds (``duplicate_link_target``) the duplicate inherits
only the earlier finding's never-clean final answers (``self_verified``, ``acknowledged_not_done``);
otherwise it stays ``open`` but answered, and only its own qualifying check resolves it. An open
pair counts once in readiness (``duplicate_counting_id``). The link breaks while any later
readable check raised the duplicate's own issue again
(``finding_resolution._break_duplicate_links``), or when the earlier finding becomes unreadable;
the duplicate then needs its own answer. ``duplicate_of`` is never terminal by itself.

``review_rounds`` counts later checks that assessed an item and left it open. The owner's attempt
budget (``verification.finding_attempt_budget``, default 5) only changes what Yoetz asks for next:
at the budget it asks for a repair with new evidence, a ``self_verified`` answer when only a Yoetz
limit stops the proof, or, as the last resort, an explicit ``acknowledged_not_done``. It
never throttles ``check`` and never closes or acknowledges anything on the agent's behalf.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum
from typing import Final

from yoetz.domain.findings import FINDING_KIND_TRAITS, ResponseDisposition
from yoetz.domain.values import FindingId
from yoetz.kernel.finding_resolution import finding_is_resolved
from yoetz.kernel.projections import ProjectionState, duplicate_link_holds

__all__ = [
    "DEFAULT_FINDING_ATTEMPT_BUDGET",
    "MAX_FINDING_ATTEMPT_BUDGET",
    "TERMINAL_TODO_STATES",
    "TODO_TRANSITIONS",
    "FindingTodo",
    "FindingTodoCounts",
    "FindingTodoState",
    "INHERITED_TODO_STATES",
    "duplicate_counting_id",
    "duplicate_link_target",
    "duplicate_root",
    "finding_blocks_receipt",
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
    SELF_VERIFIED = "self_verified"


TERMINAL_TODO_STATES: Final = frozenset(
    {
        FindingTodoState.VERIFIED_RESOLVED,
        FindingTodoState.ACKNOWLEDGED_NOT_DONE,
        FindingTodoState.REJECTION_ACCEPTED,
        FindingTodoState.SELF_VERIFIED,
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
    (
        FindingTodoState.OPEN,
        "respond_self_verified_with_reason_and_evidence_on_proof_limited_item",
        FindingTodoState.SELF_VERIFIED,
    ),
)


@dataclass(frozen=True, slots=True)
class FindingTodo:
    finding_id: FindingId
    state: FindingTodoState
    review_rounds: int
    attempt_budget: int

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
    self_verified: int = 0


def _validated_budget(attempt_budget: int) -> int:
    if type(attempt_budget) is not int or not 1 <= attempt_budget <= MAX_FINDING_ATTEMPT_BUDGET:
        raise ValueError("finding_attempt_budget_invalid")
    return attempt_budget


def duplicate_link_target(state: ProjectionState, finding_id: FindingId) -> FindingId | None:
    """The earlier finding a holding ``duplicate_of`` answer links *finding_id* to (#996).

    See ``projections.duplicate_link_holds``: readable, earlier, same origin and kind, and no
    remaining readable check broke the link.
    """

    return duplicate_link_holds(state, finding_id)


def duplicate_root(state: ProjectionState, finding_id: FindingId) -> FindingId:
    """The end of *finding_id*'s holding links: itself, or the earlier finding it repeats.

    ``respond`` refuses a link to a linked finding and a link from a finding that is already
    linked to, so a holding chain has at most one hop; the loop is finite either way because
    every link points to an earlier record.
    """

    current = finding_id
    while (target := duplicate_link_target(state, current)) is not None:
        current = target
    return current


# The only states a linked duplicate inherits: the earlier finding's never-clean final answers.
# Resolution and an accepted rejection are never inherited: only the duplicate's own proof or
# ruling clears it (issue #996).
INHERITED_TODO_STATES: Final = frozenset(
    {FindingTodoState.SELF_VERIFIED, FindingTodoState.ACKNOWLEDGED_NOT_DONE}
)


def _own_todo_state(state: ProjectionState, finding_id: FindingId) -> FindingTodoState:
    record = state.findings.get(finding_id)
    if record is None or record.payload is None:
        return FindingTodoState.OPEN
    response = state.responses.get(finding_id)
    disposition = (
        None if response is None or response.payload is None else response.payload.disposition
    )
    # ``respond`` refuses anything after a terminal state, so an ``acknowledged_not_done`` or
    # ``self_verified`` response is always the item's last word and precedes any later absence
    # proof.
    if disposition is ResponseDisposition.ACKNOWLEDGED_NOT_DONE:
        return FindingTodoState.ACKNOWLEDGED_NOT_DONE
    if disposition is ResponseDisposition.SELF_VERIFIED:
        return FindingTodoState.SELF_VERIFIED
    if finding_is_resolved(state, finding_id):
        return FindingTodoState.VERIFIED_RESOLVED
    if (
        record.rejection_accepted_by_check_event_id is not None
        and disposition is ResponseDisposition.REJECTED
    ):
        return FindingTodoState.REJECTION_ACCEPTED
    return FindingTodoState.OPEN


def finding_todo_state(state: ProjectionState, finding_id: FindingId) -> FindingTodoState:
    """The one shared to-do state of a recorded finding."""

    own = _own_todo_state(state, finding_id)
    root = duplicate_root(state, finding_id)
    if root != finding_id and own is FindingTodoState.OPEN:
        # Issue #996: a holding link inherits only the earlier finding's never-clean final
        # answers. An open, resolved or rejection-accepted earlier finding leaves the duplicate
        # open (answered): only its own qualifying proof resolves it.
        inherited = _own_todo_state(state, root)
        if inherited in INHERITED_TODO_STATES:
            return inherited
    return own


def duplicate_counting_id(state: ProjectionState, finding_id: FindingId) -> FindingId:
    """The id a readiness counter names *finding_id* by, so a linked pair counts once (#996).

    The earlier finding, while the link holds, that finding is an actionable kind, and the
    duplicate's state is the earlier finding's (both open, or an inherited final answer);
    otherwise the duplicate itself, so an open duplicate is never hidden behind a resolved or
    non-actionable earlier finding.
    """

    root = duplicate_root(state, finding_id)
    if root == finding_id:
        return finding_id
    root_record = state.findings.get(root)
    if root_record is None or root_record.payload is None:
        return finding_id
    if not FINDING_KIND_TRAITS[root_record.payload.kind][1]:
        return finding_id
    if finding_todo_state(state, finding_id) is not _own_todo_state(state, root):
        return finding_id
    return root


def finding_todo(
    state: ProjectionState,
    finding_id: FindingId,
    *,
    attempt_budget: int = DEFAULT_FINDING_ATTEMPT_BUDGET,
) -> FindingTodo:
    budget = _validated_budget(attempt_budget)
    record = state.findings.get(finding_id)
    rounds = 0 if record is None else record.review_rounds
    return FindingTodo(finding_id, finding_todo_state(state, finding_id), rounds, budget)


def finding_blocks_receipt(state: ProjectionState, finding_id: FindingId) -> bool:
    """Whether a current actionable finding keeps a receipt from reading clean.

    ``rejection_accepted`` and ``self_verified`` (issue #984) are the unresolved states that stop
    blocking; both stay disclosed, and ``self_verified`` still keeps the receipt conclusion from
    reading clean. ``acknowledged_not_done`` keeps blocking: it is never clean. A linked
    ``duplicate_of`` item (issue #996) blocks unless its own proof resolved it or it inherited
    ``self_verified``; counters name it by ``duplicate_counting_id``.
    """

    record = state.findings.get(finding_id)
    if record is None or record.payload is None:
        return False
    if not FINDING_KIND_TRAITS[record.payload.kind][1]:
        return False
    return finding_todo_state(state, finding_id) not in {
        FindingTodoState.VERIFIED_RESOLVED,
        FindingTodoState.REJECTION_ACCEPTED,
        FindingTodoState.SELF_VERIFIED,
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
        self_verified=values[FindingTodoState.SELF_VERIFIED],
    )
