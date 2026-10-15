"""Closing-review currency follows a material task or verification change (#1079 item 3)."""

from __future__ import annotations

from dataclasses import fields, replace
from typing import cast

from builders.replay import replay_records
from finishup.domain.events import (
    AcceptedEvent,
    ActionKind,
    ActionRecordedPayload,
    CheckRecordedPayload,
    DecisionRecordedPayload,
    LedgerRecord,
    PlanRevisedPayload,
    ResponseRecordedPayload,
    ReviewMode,
)
from finishup.kernel.closing_review_delta import (
    closing_material_frontier,
    closing_review_delta,
)
from finishup.kernel.projections import ProjectionState
from finishup.kernel.reducers import replay


def _prefix() -> tuple[AcceptedEvent, ...]:
    records = replay_records("all-event-families")
    index = next(
        position
        for position, record in enumerate(records)
        if type(record) is AcceptedEvent and type(record.payload) is CheckRecordedPayload
    )
    return tuple(cast(AcceptedEvent, record) for record in records[: index + 1])


def _with_payload(
    record: LedgerRecord, payload: ActionRecordedPayload | DecisionRecordedPayload
) -> LedgerRecord:
    clone = object.__new__(type(record))
    for field in fields(type(record)):
        object.__setattr__(clone, field.name, getattr(record, field.name))
    object.__setattr__(clone, "payload", payload)
    return clone


def test_bookkeeping_is_not_a_closing_review_delta_and_an_edit_is() -> None:
    prefix = _prefix()
    state = replay(prefix)
    assert type(state) is ProjectionState
    later = tuple(replay_records("all-event-families"))[len(prefix) :]
    bookkeeping = [
        record
        for record in later
        if type(record.payload) in {ResponseRecordedPayload, PlanRevisedPayload}
        or record.schema.name
        in {
            "response_recorded",
            "plan_revised",
            "plan_published",
            "claim_recorded",
            "decision_recorded",
            "receipt_recorded",
        }
    ]
    assert bookkeeping
    assert all(closing_review_delta(record, state) is False for record in bookkeeping)
    source = next(
        record
        for record in prefix
        if record.schema.name == "action_recorded" and type(record.payload) is ActionRecordedPayload
    )

    edited = replace(cast(ActionRecordedPayload, source.payload), action_kind=ActionKind.EDIT)
    assert closing_review_delta(_with_payload(source, edited), state) is True
    command = replace(edited, action_kind=ActionKind.COMMAND, command="pytest -q")
    assert closing_review_delta(_with_payload(source, command), state) is True
    decision = next(record for record in prefix if record.schema.name == "decision_recorded")
    assert type(decision.payload) is DecisionRecordedPayload
    assert decision.payload.review_mode is None
    switched = replace(decision.payload, review_mode=ReviewMode.LOCAL)
    assert closing_review_delta(_with_payload(decision, switched), state) is True


def test_closing_material_frontier_follows_a_review_mode_switch() -> None:
    """The Stop gate remembers this sequence. Bookkeeping does not move it; a mode switch does.
    A material record after the projection frontier does not count.
    """

    prefix = _prefix()
    state = replay(prefix)
    assert type(state) is ProjectionState
    before = closing_material_frontier(state, prefix)
    decision = next(record for record in prefix if record.schema.name == "decision_recorded")
    assert type(decision.payload) is DecisionRecordedPayload
    assert decision.payload.review_mode is None
    switched = _with_payload(decision, replace(decision.payload, review_mode=ReviewMode.LOCAL))
    records = tuple(switched if record is decision else record for record in prefix)
    assert closing_material_frontier(state, records) >= decision.ledger.ingestion_sequence
    assert closing_material_frontier(state, records) >= before
    later = _with_payload(decision, replace(decision.payload, review_mode=ReviewMode.LOCAL))
    object.__setattr__(
        later, "ledger", replace(decision.ledger, ingestion_sequence=state.frontier + 1)
    )
    assert closing_material_frontier(state, (*prefix, later)) == before
    assert closing_material_frontier(cast(ProjectionState, object()), prefix) == 0
    assert closing_material_frontier(state, cast(tuple[LedgerRecord, ...], [prefix[0]])) == 0
