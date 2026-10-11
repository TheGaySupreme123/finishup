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
- ``disputed_after_rebuttal`` (issue #1020, ADR-040): the agent rejected an AI-powered finding
  with a reason, and a later review kept it open (``still_present``, ``answered_not_fixed`` or
  ``unassessable``) without citing anything recorded after that rejection. Yoetz records the
  standing disagreement instead of letting the reviewer repeat a demand it no longer supports:
  the item is not agent work and does not block a receipt or fire the Stop gate, but it stays
  disclosed and keeps the receipt conclusion at best ``insufficient_coverage``.
- ``self_verified`` (issue #984, ADR-034): the agent repaired it, Yoetz could not prove the repair
  because of its own limits, and the agent verified it itself with a reason and its own recorded
  evidence (admission: ``kernel/self_verification.py``). It is not agent work and no longer counts
  as receipt-blocking, but it is never resolved: it stays disclosed and keeps the receipt
  conclusion at best ``insufficient_coverage``.

Every state but ``open`` is terminal: no transition leaves them, and ``respond`` refuses to record anything
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
from types import MappingProxyType
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
from yoetz.kernel.projections import ProjectionState, duplicate_link_holds
from yoetz.kernel.task_facts import blocker_declarations

__all__ = [
    "DEFAULT_FINDING_ATTEMPT_BUDGET",
    "MAX_FINDING_ATTEMPT_BUDGET",
    "TERMINAL_TODO_STATES",
    "TODO_TRANSITIONS",
    "FindingTodo",
    "FindingTodoCounts",
    "FindingTodoState",
    "PREMISE_CHALLENGE_KINDS",
    "PREMISE_DISPUTE_BLOCKER_CITED",
    "PREMISE_DISPUTE_GIVE_UP_RERAISED",
    "INHERITED_TODO_STATES",
    "duplicate_counting_id",
    "duplicate_link_target",
    "duplicate_root",
    "finding_blocks_receipt",
    "is_premise_challenge",
    "premise_dispute_basis",
    "standing_premise_disputes",
    "finding_standing",
    "finding_todo",
    "finding_todo_state",
    "ruling_since",
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
    DISPUTED_AFTER_REBUTTAL = "disputed_after_rebuttal"


TERMINAL_TODO_STATES: Final = frozenset(
    {
        FindingTodoState.VERIFIED_RESOLVED,
        FindingTodoState.ACKNOWLEDGED_NOT_DONE,
        FindingTodoState.REJECTION_ACCEPTED,
        FindingTodoState.SELF_VERIFIED,
        FindingTodoState.DISPUTED_AFTER_REBUTTAL,
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
    (
        FindingTodoState.OPEN,
        "reviewer_keeps_open_without_newer_material_after_reasoned_rejection",
        FindingTodoState.DISPUTED_AFTER_REBUTTAL,
    ),
)


@dataclass(frozen=True, slots=True)
class FindingTodo:
    finding_id: FindingId
    state: FindingTodoState
    review_rounds: int
    attempt_budget: int
    # An ``acknowledged_not_done`` premise challenge the reviewer still disputes (TB4 tb4n1 D7a);
    # see ``premise_dispute_basis``. Never changes the state.
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
    self_verified: int = 0
    disputed_after_rebuttal: int = 0


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
    if (
        record.disputed_after_rebuttal_by_check_event_id is not None
        and disposition is ResponseDisposition.REJECTED
    ):
        return FindingTodoState.DISPUTED_AFTER_REBUTTAL
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
    todo_state = finding_todo_state(state, finding_id)
    disputed = (
        todo_state is FindingTodoState.ACKNOWLEDGED_NOT_DONE
        and premise_dispute_basis(state, finding_id) is not None
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


# Why a premise dispute stands (``premise_dispute_basis``), as closed tokens.
PREMISE_DISPUTE_BLOCKER_CITED: Final = "blocker_cited"
PREMISE_DISPUTE_GIVE_UP_RERAISED: Final = "give_up_reraised"


def premise_dispute_basis(state: ProjectionState, finding_id: FindingId) -> str | None:
    """Why the reviewer still disputes the premise of an acknowledged finding, or ``None`` (D7a).

    A deterministic, structural rule over recorded refs; no prose is read. The item must be
    ``acknowledged_not_done`` (the agent gave up; ``self_verified`` says it repaired the item, so
    it is never a premise dispute) and a premise challenge (``is_premise_challenge``: an
    AI-powered ``task_requirement_unmet`` or ``requested_item_never_attempted`` asking the agent to
    ``act``). It then needs one recorded anchor:

    * ``blocker_cited``: the finding's subject refs name a readable, unsuperseded
      ``yoetz-blocker:<kind>`` decision (its ``evt_`` id) or an obligation such a decision declares
      blocked: the reviewer challenged the agent's blocker itself.
    * ``give_up_reraised``: after the agent's ``acknowledged_not_done`` answer, a review re-raised
      the same concern (``settled_reraise_count``, recorded by ``apply_check_rulings`` from a
      ``still_present``/``answered_not_fixed`` ruling a restatement put on the item): the reviewer
      disputes the give-up.

    A premise challenge acknowledged with neither anchor is not flagged: the reviewer never
    disputed the stop, so the acknowledgement stands alone (still final and receipt-blocking).
    """

    if finding_todo_state(state, finding_id) is not FindingTodoState.ACKNOWLEDGED_NOT_DONE:
        return None
    record = state.findings.get(finding_id)
    if record is None or record.payload is None or not is_premise_challenge(record.payload):
        return None
    cited = frozenset(str(ref) for ref in record.payload.subject_refs)
    if cited:
        # A claimed or confirmed blocker both anchor the dispute; batches do not matter here.
        for obligation, declaration in blocker_declarations(state, MappingProxyType({})).items():
            if str(obligation) in cited or str(declaration.decision_event_id) in cited:
                return PREMISE_DISPUTE_BLOCKER_CITED
    if record.settled_reraise_count:
        return PREMISE_DISPUTE_GIVE_UP_RERAISED
    return None


def standing_premise_disputes(
    state: ProjectionState, finding_ids: Iterable[FindingId] | None = None
) -> tuple[FindingId, ...]:
    """Acknowledged premise challenges the reviewer still disputes (TB4 tb4n1 D7a).

    ``acknowledged_not_done`` keeps its meaning ("I will not do it") and stays final. But when the
    reviewer challenged the agent's give-up itself, the acknowledgement does not settle the
    dispute; ``premise_dispute_basis`` is the exact structural rule. These items are returned in
    finding-id order so a readiness or Stop surface can show them once as standing disputes.
    Nothing here changes a to-do state, blocks a check, or closes anything; the receipt already
    keeps every ``acknowledged_not_done`` item receipt-blocking.
    """

    candidates = state.findings if finding_ids is None else finding_ids
    return tuple(
        key
        for key in sorted(candidates, key=str.encode)
        if finding_todo(state, key).premise_disputed
    )


def finding_blocks_receipt(state: ProjectionState, finding_id: FindingId) -> bool:
    """Whether a current actionable finding keeps a receipt from reading clean.

    ``rejection_accepted``, ``self_verified`` (issue #984) and ``disputed_after_rebuttal``
    (issue #1020) are the unresolved states that stop blocking; all stay disclosed, and the last
    two still keep the receipt conclusion from reading clean. ``acknowledged_not_done`` keeps blocking: it is never clean. A linked
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
        FindingTodoState.DISPUTED_AFTER_REBUTTAL,
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
        disputed_after_rebuttal=values[FindingTodoState.DISPUTED_AFTER_REBUTTAL],
    )


def finding_standing(state: ProjectionState, finding_id: FindingId) -> tuple[str, int] | None:
    """The agent's standing answer on a finding as ``(disposition value, frontier)``, or ``None``.

    Seam for tb4n3 RC-3 / RC-7 (issue #1026). The closure classifier asks only this accessor what
    the agent last said and when, so the dialogue lane can replace the body (the earliest
    unretracted reasoned answer, ``standing_answer_frontier``) without touching any consumer. This
    body is today's behaviour: the latest recorded response and the frontier it was recorded at.
    """

    response = state.responses.get(finding_id)
    if response is None or response.payload is None:
        return None
    return str(response.payload.disposition.value), response.source_frontier


def ruling_since(state: ProjectionState, finding_id: FindingId) -> int | None:
    """The frontier of the newest reviewer ruling on a finding, or ``None`` when none is recorded.

    Seam for tb4n3 RC-3 / RC-7 (issue #1026). ``None`` means "no ruling frontier is recorded", so
    a rejected finding reads as awaiting a ruling until the dialogue lane records
    ``last_ruling_frontier`` and replaces this body. Callers compare it with ``finding_standing``.
    """

    del state, finding_id
    return None
