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
    LedgerRecord,
    PlanRevisedPayload,
    ResponseRecordedPayload,
)
from finishup.kernel.closing_review_delta import closing_review_delta
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

    def _with_payload(record: LedgerRecord, payload: ActionRecordedPayload) -> LedgerRecord:
        clone = object.__new__(type(record))
        for field in fields(type(record)):
            object.__setattr__(clone, field.name, getattr(record, field.name))
        object.__setattr__(clone, "payload", payload)
        return clone

    edited = replace(cast(ActionRecordedPayload, source.payload), action_kind=ActionKind.EDIT)
    assert closing_review_delta(_with_payload(source, edited), state) is True
    command = replace(edited, action_kind=ActionKind.COMMAND, command="pytest -q")
    assert closing_review_delta(_with_payload(source, command), state) is True
