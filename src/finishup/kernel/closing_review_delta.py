"""Whether a later record is a new closing-review input (issue #1079, item 3).

A closing review judges the work. Bookkeeping and dispositions — claims, decisions, obligation
publications, responses, plans, coordination, assignments, findings, and evidence publication —
do not. This predicate is narrower than ``invalidates_recorded_check`` on purpose: that rule
still makes a check inapplicable after those records, and a real edit still does both.

A later record requires a new closing review when:

* its later-material class supersedes (an observed deliverable edit or shell write);
* it is an unclassified observed command, or the result of one (a verification run FinishUP
  cannot prove harmless);
* an observed result has no readable action (fail closed);
* it is a cooperative ``action_recorded`` of kind ``edit`` or ``command``, or the result of one,
  including a result whose action row cannot be read.

FinishUP's own calls, exploration, host bookkeeping, and non-counting writes do not.
"""

from __future__ import annotations

from finishup.domain.events import (
    ActionKind,
    ActionRecordedPayload,
    LedgerRecord,
    ResultRecordedPayload,
    is_observation_authored,
)
from finishup.kernel.later_material import LaterMaterialClass, classify_later_material
from finishup.kernel.projections import ProjectionState

__all__ = ["closing_review_delta"]

_OBSERVED_COMMAND_RULES = frozenset(
    {
        "unclassified_observed_action",
        "result_of_action",
        "result_without_readable_action",
    }
)


def _command_kind(payload: ActionRecordedPayload | None) -> bool:
    return payload is not None and payload.action_kind is ActionKind.COMMAND


def _observed_command(record: LedgerRecord, projection: ProjectionState) -> bool:
    """An observed command FinishUP could not classify as harmless, or an unreadable result."""

    payload = record.payload
    name = record.schema.name
    if name == "action_recorded" and type(payload) is ActionRecordedPayload:
        return _command_kind(payload)
    if name == "result_recorded" and type(payload) is ResultRecordedPayload:
        action = projection.actions.get(payload.action_id)
        if action is None or action.payload is None:
            return True
        return _command_kind(action.payload)
    return True


def closing_review_delta(record: LedgerRecord, projection: ProjectionState) -> bool:
    """True when *record* is a material task or verification change for the closing review.

    An unreadable projection fails closed: the closing review is asked again rather than treated
    as current.
    """

    if type(projection) is not ProjectionState:
        return True
    if is_observation_authored(record):
        classified = classify_later_material(record, projection)
        if classified.supersedes:
            return True
        if (
            classified.material_class is LaterMaterialClass.OTHER
            and classified.rule in _OBSERVED_COMMAND_RULES
        ):
            return _observed_command(record, projection)
        return False
    name = record.schema.name
    payload = record.payload
    if name == "action_recorded" and type(payload) is ActionRecordedPayload:
        return payload.action_kind in {ActionKind.EDIT, ActionKind.COMMAND}
    if name == "result_recorded" and type(payload) is ResultRecordedPayload:
        action = projection.actions.get(payload.action_id)
        kind = None if action is None or action.payload is None else action.payload.action_kind
        return kind in {None, ActionKind.EDIT, ActionKind.COMMAND}
    return False
