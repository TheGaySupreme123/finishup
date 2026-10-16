"""Closing-review currency follows a material task or verification change (#1079 item 3)."""

from __future__ import annotations

from dataclasses import fields, replace
from typing import cast

import pytest

from builders.observed_runs import ObservedLedger
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
    ResultOutcome,
    ReviewMode,
)
from finishup.kernel.closing_review_delta import (
    closing_material_frontier,
    closing_review_delta,
)
from finishup.kernel.projections import ProjectionState
from finishup.kernel.reducers import replay
from finishup.kernel.task_facts import EDITED_AFTER_LAST_VERIFICATION_GAP, task_fact_signals


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


@pytest.mark.parametrize(
    "command",
    [
        "date -u",
        "date -u +%Y-%m-%dT%H:%M:%S.%3NZ",
        "rg -n closing guidance/",
        "sed -n '1,120p' guidance/receipt.md",
        "git status --short",
        "finishup status --json",
        "finishup receipt --json",
        "rg closing guidance/receipt.md; sed -n '1,120p' guidance/receipt.md",
    ],
)
def test_native_read_commands_do_not_rearm_final_review(command: str) -> None:
    ledger = ObservedLedger(records=list(_prefix()))
    start = len(ledger.records)
    ledger.passes(command)
    state = replay(ledger.prefix)
    assert all(not closing_review_delta(row, state) for row in ledger.records[start:])
    assert closing_material_frontier(state, ledger.prefix) <= start


@pytest.mark.parametrize(
    "command,scope",
    [
        ("sed -i '' s/a/b/ module.py", "workspace"),
        ("rg x module.py > result.txt", "workspace"),
        ("finishup status --json > result.txt", "workspace"),
        ("python arbitrary.py", None),
        ("date -u; python arbitrary.py", None),
        ("rg --pre ./rewrite x module.py", None),
        ("date -s tomorrow", None),
        ("./date -u; date -u", None),
        ("./finishup status --json; rg x module.py", None),
        ("pytest -q", None),
    ],
)
def test_writes_verifiers_and_unproven_commands_rearm(command: str, scope: str | None) -> None:
    ledger = ObservedLedger(records=list(_prefix()))
    start = len(ledger.records)
    ledger.run(command, ResultOutcome.SUCCESS, write_scope=scope)
    state = replay(ledger.prefix)
    assert all(closing_review_delta(row, state) for row in ledger.records[start:])
    assert closing_material_frontier(state, ledger.prefix) > start


@pytest.mark.parametrize(
    "command",
    [
        "apply_patch <<'PATCH'\n*** Begin Patch\n*** Update File: /app/solution/finalize.py\n@@\n-old\n+new\n*** End Patch\nPATCH\npython /app/solution/finalize.py",
        "printf updated > module.py && python tests/check.py",
    ],
)
def test_edit_then_verification_in_same_command_is_current(command: str) -> None:
    ledger = ObservedLedger()
    ledger.passes("npm run build")
    ledger.run(command, ResultOutcome.SUCCESS, exit_status=0, write_scope="workspace")
    assert (
        EDITED_AFTER_LAST_VERIFICATION_GAP
        not in task_fact_signals(replay(ledger.prefix), ledger.prefix).codes
    )
    ledger.edit()
    assert (
        EDITED_AFTER_LAST_VERIFICATION_GAP
        in task_fact_signals(replay(ledger.prefix), ledger.prefix).codes
    )


def test_receipt_close_and_lifecycle_do_not_rearm() -> None:
    from finishup.domain.events import EventSchema, WorkClosedPayload

    state = replay(_prefix())
    records = tuple(replay_records("all-event-families"))
    for name in ("receipt_recorded", "session_opened", "session_resumed"):
        row = next(row for row in records if row.schema.name == name)
        assert not closing_review_delta(row, state)
    source = records[0]
    closed = _with_payload(source, cast(ActionRecordedPayload, WorkClosedPayload()))
    object.__setattr__(closed, "schema", EventSchema("work_closed", "1.0.0"))
    assert not closing_review_delta(closed, state)
