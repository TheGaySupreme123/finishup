"""Integration of ADR-035 (L5, #1005) with ``obligation_published`` 1.1.0 roles (L6, #1002).

The declared delivered set reads real 1.1.0 ``role: output`` items, agrees with L6's
``task_facts.declared_output_items`` (minus blocked obligations), and ``declared_output_removed``
fires for a removed output but never for an input or a role-less item. No monkeypatching.
"""

from __future__ import annotations

from builders.observed_runs import ObservedLedger
from yoetz.domain.events import (
    DecisionRecordedPayload,
    EventSchema,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
    RequestedItem,
    RequestedItemKind,
    RequestedItemRole,
)
from yoetz.domain.values import actor_id, obligation_id
from yoetz.kernel.delivered_set import declared_delivered_items, declared_output_removed
from yoetz.kernel.projections import ProjectionState
from yoetz.kernel.reducers import replay
from yoetz.kernel.task_facts import (
    RequestedOutputState,
    blocked_obligations,
    declared_output_items,
)

_FIRST = obligation_id("obl_00000000-0000-4000-8000-000000000001")
_SECOND = obligation_id("obl_00000000-0000-4000-8000-000000000002")
_GONE = RequestedOutputState("inside", exists=False, deleted=True)
_ITEMS = (
    RequestedItem(RequestedItemKind.FILE, "/app/data/input.csv", RequestedItemRole.INPUT),
    RequestedItem(RequestedItemKind.FILE, "/app/out.json", RequestedItemRole.OUTPUT),
    RequestedItem(RequestedItemKind.DIRECTORY, "/app/results/", RequestedItemRole.OUTPUT),
    RequestedItem(RequestedItemKind.FILE, "/app/legacy.txt"),
)


def _projection(*, block_second: bool = False) -> ProjectionState:
    ledger = ObservedLedger()
    for obligation in (_FIRST, _SECOND):
        ledger.append(
            EventSchema("obligation_published", "1.1.0"),
            ObligationPublishedPayload(
                obligation_id=obligation,
                description="Deliver the outputs",
                evidence_expectation="The files",
                status=ObligationStatus.OPEN,
                requested_items=_ITEMS,
            ),
            observed=False,
        )
    ledger.append(
        EventSchema("plan_published", "1.0.0"),
        PlanPublishedPayload(1, "Plan", (_FIRST, _SECOND)),
        observed=False,
    )
    if block_second:
        ledger.append(
            EventSchema("decision_recorded", "1.0.0"),
            DecisionRecordedPayload(
                statement="Blocked.\nyoetz-blocker:consent",
                rationale="The operator holds the consent.",
                authority=actor_id("agt_codex"),
                affected_obligation_ids=(_SECOND,),
            ),
            observed=False,
        )
    return replay(ledger.prefix)


def _l6_rows(projection: ProjectionState) -> set[tuple[object, int, str, str]]:
    blocked = blocked_obligations(projection)
    return {
        (obligation, index, kind.value, value)
        for obligation, index, kind, value in declared_output_items(projection)
        if obligation not in blocked
    }


def test_declared_set_reads_l6_output_roles_and_agrees_with_its_helper() -> None:
    for block_second in (False, True):
        projection = _projection(block_second=block_second)
        rows = declared_delivered_items(projection)
        assert set(rows) == _l6_rows(projection)
        assert {(index, kind) for _o, index, kind, _v in rows} == {(1, "file"), (2, "directory")}
        assert (_SECOND in {row[0] for row in rows}) is not block_second


def test_removed_output_fires_and_input_or_roleless_never_does() -> None:
    projection = _projection()
    assert declared_output_removed(projection, {(_FIRST, 1): _GONE}) == (_FIRST,)
    assert declared_output_removed(projection, {(_FIRST, 2): _GONE}) == (_FIRST,)
    assert declared_output_removed(projection, {(_FIRST, 0): _GONE, (_FIRST, 3): _GONE}) == ()
