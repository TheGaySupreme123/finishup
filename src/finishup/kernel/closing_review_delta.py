"""Whether a later record is a new closing-review input (issue #1079, item 3).

A closing review judges the work. Bookkeeping and dispositions — claims, decisions, obligation
publications, responses, plans, coordination, assignments, findings, and evidence publication —
do not. This predicate is narrower than ``invalidates_recorded_check`` on purpose: that rule
still makes a check inapplicable after those records, and a real edit still does both.

A later record requires a new closing review when:

* its later-material class supersedes (an observed deliverable edit or shell write);
* it is an observed shell command, or the result of one, unless the hook's before/after workspace
  fingerprint reported the workspace ``unchanged`` across it and it is neither a verification run
  (a test, build, lint or typecheck runner, or a run of a command the task requests) nor a
  package install (PR #1080). A command without that fact - no pre-call snapshot, a call still
  running, a workspace beyond the walk bound, a record from before the fact existed - is material:
  FinishUP could not establish that it left the workspace unchanged. Command text never decides;
* it is another observed tool call whose result reports the workspace ``changed`` (a third-party
  MCP tool, a subagent, a process poll that wrote files);
* it is a later delivery's workspace fact for an already recorded call (an observed evidence row
  carrying ``Observed workspace effect=<token>``, round 6), judged as that call with every fact
  of the call folded, so a ``changed`` or ``unavailable`` that arrives after a closing review
  re-arms it;
* an observed result has no readable action (fail closed);
* it is a cooperative ``action_recorded`` of kind ``edit`` or ``command``, or the result of one,
  including a result whose action row cannot be read;
* it is a ``decision_recorded`` that switches review mode (ADR-049). Any other decision stays
  bookkeeping.

FinishUP's own calls, host-native reads, unchanged commands, host bookkeeping, and non-counting
writes do not. Callers that classify many records compute ``workspace_effects`` once and pass it;
without it every observed shell command stays material.
"""

from __future__ import annotations

from finishup.domain.events import (
    ActionKind,
    ActionRecordedPayload,
    DecisionRecordedPayload,
    LedgerRecord,
    ResultRecordedPayload,
    is_observation_authored,
)
from finishup.kernel.later_material import (
    LaterMaterialClass,
    WorkspaceEffects,
    classify_later_material,
    workspace_effects,
)
from finishup.kernel.projections import ProjectionState

__all__ = ["closing_material_frontier", "closing_review_delta"]

_OBSERVED_COMMAND_RULES = frozenset(
    {
        "unclassified_observed_action",
        "result_of_action",
        "result_without_readable_action",
        "workspace_effect_of_action",
    }
)


def _material_call(payload: ActionRecordedPayload | None, effects: WorkspaceEffects) -> bool:
    if payload is None:
        return True
    if payload.action_kind is ActionKind.COMMAND:
        return True
    # Another tool (not FinishUP's own, not a host read): material only when its own fingerprint
    # saw the workspace change. Without a fact it keeps its #1079 bookkeeping reading.
    return payload.action_id in effects.changed


def _observed_command(
    record: LedgerRecord, projection: ProjectionState, effects: WorkspaceEffects
) -> bool:
    """An observed call FinishUP could not establish as harmless, or an unreadable result."""

    payload = record.payload
    name = record.schema.name
    if name == "action_recorded" and type(payload) is ActionRecordedPayload:
        return _material_call(payload, effects)
    if name == "result_recorded" and type(payload) is ResultRecordedPayload:
        action = projection.actions.get(payload.action_id)
        if action is None or action.payload is None:
            return True
        return _material_call(action.payload, effects)
    annotated = effects.annotations.get(record.event_id)
    if annotated is not None:
        # A later delivery's workspace fact for a recorded call (round 6) is that call, judged at
        # the position the fact arrived: a contradiction re-arms from here, not only from the
        # call's original result.
        action = projection.actions.get(annotated)
        if action is None or action.payload is None:
            return True
        return _material_call(action.payload, effects)
    return True


def closing_review_delta(
    record: LedgerRecord,
    projection: ProjectionState,
    *,
    effects: WorkspaceEffects | None = None,
) -> bool:
    """True when *record* is a material task or verification change for the closing review.

    An unreadable projection fails closed: the closing review is asked again rather than treated
    as current. ``effects`` is ``workspace_effects`` over the prefix holding *record*; when it is
    omitted no observed command can be shown to have left the workspace unchanged.
    """

    if type(projection) is not ProjectionState:
        return True
    if is_observation_authored(record):
        facts = WorkspaceEffects() if effects is None else effects
        classified = classify_later_material(record, projection, effects=facts)
        if classified.supersedes:
            return True
        if (
            classified.material_class is LaterMaterialClass.OTHER
            and classified.rule in _OBSERVED_COMMAND_RULES
        ):
            return _observed_command(record, projection, facts)
        return False
    name = record.schema.name
    payload = record.payload
    if name == "action_recorded" and type(payload) is ActionRecordedPayload:
        return payload.action_kind in {ActionKind.EDIT, ActionKind.COMMAND}
    if name == "result_recorded" and type(payload) is ResultRecordedPayload:
        action = projection.actions.get(payload.action_id)
        kind = None if action is None or action.payload is None else action.payload.action_kind
        return kind in {None, ActionKind.EDIT, ActionKind.COMMAND}
    # ADR-049: switching review mode after the closing review makes that review stale. A decision
    # that does not switch mode is still bookkeeping.
    if name == "decision_recorded" and type(payload) is DecisionRecordedPayload:
        return payload.review_mode is not None
    return False


def closing_material_frontier(
    projection: ProjectionState, records: tuple[LedgerRecord, ...]
) -> int:
    """The newest material closing-review input at or before the projection frontier.

    Zero when this prefix has no such record. The Stop gate remembers an acceptance re-read
    against this sequence, so bookkeeping at a later ledger frontier does not ask it again.
    """

    if type(projection) is not ProjectionState or type(records) is not tuple:
        return 0
    frontier = projection.frontier
    effects = workspace_effects(records, projection)
    best = 0
    for record in records:
        sequence = record.ledger.ingestion_sequence
        if type(sequence) is not int or sequence > frontier or sequence <= best:
            continue
        if closing_review_delta(record, projection, effects=effects):
            best = sequence
    return best
