"""Closing-review currency follows a material task or verification change (#1079 item 3)."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import fields, replace
from typing import cast

import pytest

from builders.observed_runs import INSTALLATION_KEY, ObservedLedger
from builders.replay import replay_records
from finishup.domain.events import (
    AcceptedEvent,
    ActionKind,
    ActionRecordedPayload,
    CheckRecordedPayload,
    DecisionRecordedPayload,
    EventSchema,
    LedgerRecord,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
    PlanRevisedPayload,
    RequestedItem,
    RequestedItemKind,
    ResponseRecordedPayload,
    ResultOutcome,
    ResultRecordedPayload,
    ReviewMode,
)
from finishup.domain.values import obligation_id, result_id
from finishup.kernel.closing_review_delta import (
    closing_material_frontier,
    closing_review_delta,
)
from finishup.kernel.later_material import workspace_effects
from finishup.kernel.projections import ProjectionState
from finishup.kernel.reducers import replay
from finishup.kernel.task_facts import (
    EDITED_AFTER_LAST_VERIFICATION_GAP,
    register_command_identity_key,
    task_fact_signals,
)


@pytest.fixture(autouse=True)
def installation_key() -> Iterator[None]:
    register_command_identity_key(INSTALLATION_KEY)
    yield
    register_command_identity_key(None)


def declare_verifier(ledger: ObservedLedger, command: str) -> None:
    obligation = obligation_id("obl_00000000-0000-4000-8000-000000001080")
    ledger.append(
        EventSchema("obligation_published", "1.0.0"),
        ObligationPublishedPayload(
            obligation_id=obligation,
            description="Task-specific verification",
            evidence_expectation="Observed verifier command",
            status=ObligationStatus.OPEN,
            requested_items=(RequestedItem(RequestedItemKind.COMMAND, command),),
        ),
        observed=False,
    )
    ledger.append(
        EventSchema("plan_published", "1.0.0"),
        PlanPublishedPayload(1, "Plan", (obligation,)),
        observed=False,
    )


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


# The audited false-stale shapes (DLANE N6 issue 1): read-only traffic after the final review.
_AUDITED_READS = (
    "date -u",
    "date -u +%Y-%m-%dT%H:%M:%S.%3NZ",
    "rg -n closing guidance/",
    "sed -n '1,120p' guidance/receipt.md",
    "git status --short",
    "finishup status --json",
    "finishup receipt --json",
    "rg closing guidance/receipt.md; sed -n '1,120p' guidance/receipt.md",
    "date -u && git status --short",
)


@pytest.mark.parametrize("command", _AUDITED_READS)
def test_unchanged_workspace_reads_do_not_rearm_final_review(command: str) -> None:
    """PR #1080: the hook saw the workspace unchanged across the command, so it is not input."""

    ledger = ObservedLedger(records=list(_prefix()))
    start = len(ledger.records)
    ledger.passes(command, workspace_effect="unchanged")
    state = replay(ledger.prefix)
    effects = workspace_effects(ledger.prefix, state)
    assert all(
        not closing_review_delta(row, state, effects=effects) for row in ledger.records[start:]
    )
    assert closing_material_frontier(state, ledger.prefix) <= start


@pytest.mark.parametrize("command", _AUDITED_READS)
@pytest.mark.parametrize("effect", [None, "changed", "unavailable"])
def test_command_text_alone_never_makes_a_command_harmless(
    command: str, effect: str | None
) -> None:
    """Without an ``unchanged`` fingerprint the same read-looking command stays material."""

    ledger = ObservedLedger(records=list(_prefix()))
    start = len(ledger.records)
    ledger.passes(command, workspace_effect=effect)
    state = replay(ledger.prefix)
    effects = workspace_effects(ledger.prefix, state)
    assert all(closing_review_delta(row, state, effects=effects) for row in ledger.records[start:])
    assert closing_material_frontier(state, ledger.prefix) > start


@pytest.mark.parametrize(
    "command,scope,install",
    [
        ("sed -i '' s/a/b/ module.py", "workspace", None),
        ("rg x module.py > result.txt", "workspace", None),
        ("finishup status --json > result.txt", "workspace", None),
        ("pytest -q", None, None),
        ("npm run build", None, None),
        ("ruff check .", None, None),
        ("pytest -q 2>&1 | tail -5", None, None),
        ("pip install requests", None, "workspace_env"),
    ],
)
def test_writes_verifiers_and_installs_rearm_even_when_unchanged(
    command: str, scope: str | None, install: str | None
) -> None:
    """Verification-run semantics, lexical writes and environment installs keep their #1079 rule."""

    ledger = ObservedLedger(records=list(_prefix()))
    start = len(ledger.records)
    ledger.run(
        command,
        ResultOutcome.SUCCESS,
        exit_status=0,
        write_scope=scope,
        install_target=install,
        workspace_effect="unchanged",
    )
    state = replay(ledger.prefix)
    effects = workspace_effects(ledger.prefix, state)
    assert all(closing_review_delta(row, state, effects=effects) for row in ledger.records[start:])
    assert closing_material_frontier(state, ledger.prefix) > start


def test_a_declared_verifier_stays_material_when_it_writes_nothing() -> None:
    ledger = ObservedLedger()
    declare_verifier(ledger, "python check.py")
    start = len(ledger.records)
    ledger.passes("python check.py", workspace_effect="unchanged")
    state = replay(ledger.prefix)
    assert closing_material_frontier(state, ledger.prefix) > start
    # The same unchanged run of a command no obligation requests is not input.
    other = ObservedLedger()
    declare_verifier(other, "python check.py")
    begin = len(other.records)
    other.passes("python inspect.py", workspace_effect="unchanged")
    assert closing_material_frontier(replay(other.prefix), other.prefix) <= begin


def test_unregistered_key_with_requested_command_keeps_every_command_material() -> None:
    ledger = ObservedLedger()
    declare_verifier(ledger, "python check.py")
    start = len(ledger.records)
    ledger.passes("date -u", workspace_effect="unchanged")
    register_command_identity_key(None)
    try:
        state = replay(ledger.prefix)
        assert closing_material_frontier(state, ledger.prefix) > start
    finally:
        register_command_identity_key(INSTALLATION_KEY)


def test_a_contradicting_result_or_a_cooperative_claim_cannot_quiet_a_command() -> None:
    ledger = ObservedLedger(records=list(_prefix()))
    start = len(ledger.records)
    result = ledger.passes("date -u", workspace_effect="unchanged")
    # A second observed result of the same call (a stream correction) that saw a change wins.
    ledger.correct_outcome(result, ResultOutcome.SUCCESS, exit_status=0)
    action = next(
        row.payload.action_id
        for row in ledger.records
        if isinstance(row.payload, ResultRecordedPayload) and row.payload.result_id == result
    )
    ledger.append(
        EventSchema("result_recorded", "1.0.0"),
        ResultRecordedPayload(
            result_id("res_00000000-0000-4000-8000-000000108099"),
            action,
            ResultOutcome.SUCCESS,
            exit_status=0,
            summary="Observed result status=success (workspace changed)",
        ),
        observed=True,
    )
    state = replay(ledger.prefix)
    assert closing_material_frontier(state, ledger.prefix) > start
    # An agent-published result cannot claim the workspace was unchanged.
    forged = ObservedLedger(records=list(_prefix()))
    begin = len(forged.records)
    forged.run("date -u", ResultOutcome.SUCCESS, exit_status=0)
    forged_action = next(
        row.payload.action_id
        for row in forged.records[begin:]
        if isinstance(row.payload, ActionRecordedPayload)
    )
    forged.append(
        EventSchema("result_recorded", "1.0.0"),
        ResultRecordedPayload(
            result_id("res_00000000-0000-4000-8000-000000108098"),
            forged_action,
            ResultOutcome.SUCCESS,
            exit_status=0,
            summary="Observed result status=success (workspace unchanged)",
        ),
        observed=False,
    )
    forged_state = replay(forged.prefix)
    assert workspace_effects(forged.prefix, forged_state).quiet == frozenset()
    assert closing_material_frontier(forged_state, forged.prefix) > begin


def test_another_tool_that_changed_the_workspace_rearms() -> None:
    """A third-party MCP tool or a process poll that wrote files is input; an unchanged one is not."""

    for effect, material in (("changed", True), ("unchanged", False), (None, False)):
        ledger = ObservedLedger(records=list(_prefix()))
        start = len(ledger.records)
        ledger.run(
            None,
            ResultOutcome.SUCCESS,
            kind=ActionKind.OTHER,
            tool="write_stdin",
            runner="other",
            workspace_effect=effect,
        )
        state = replay(ledger.prefix)
        assert (closing_material_frontier(state, ledger.prefix) > start) is material, effect


@pytest.mark.parametrize(
    "command",
    [
        "apply_patch <<'PATCH'\n*** Begin Patch\n*** Update File: /app/solution/finalize.py\n@@\n-old\n+new\n*** End Patch\nPATCH\npython /app/solution/finalize.py",
        "printf updated > module.py && python tests/check.py",
    ],
)
def test_edit_then_verification_in_same_command_is_current(command: str) -> None:
    ledger = ObservedLedger()
    if "finalize.py" in command:
        # The task names this verifier explicitly. The filename alone proves no verification.
        declare_verifier(ledger, "python /app/solution/finalize.py")
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


@pytest.mark.parametrize("command", ["python finalize.py", "python fit_regression.py"])
def test_generator_does_not_clear_real_stale_verification(command: str) -> None:
    ledger = ObservedLedger()
    ledger.passes("pytest -q")
    ledger.edit()
    ledger.run(command, ResultOutcome.SUCCESS, exit_status=0, write_scope="workspace")
    assert (
        EDITED_AFTER_LAST_VERIFICATION_GAP
        in task_fact_signals(replay(ledger.prefix), ledger.prefix).codes
    )


def test_undeclared_hof_finalizer_does_not_clear_verification_gap() -> None:
    ledger = ObservedLedger()
    ledger.passes("npm run build")
    ledger.run(
        "printf edit > module.py && python /app/solution/finalize.py",
        ResultOutcome.SUCCESS,
        exit_status=0,
        write_scope="workspace",
    )
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


def test_check_currency_disclosure_follows_the_same_workspace_fact() -> None:
    """The receipt's later-material suffix ignores an unchanged command and keeps the rest."""

    from finishup.kernel.later_material import (
        LaterMaterialClass,
        classify_later_material,
        counted_later_material,
    )

    ledger = ObservedLedger(records=list(_prefix()))
    start = len(ledger.records)
    ledger.passes("date -u", workspace_effect="unchanged")
    quiet_rows = ledger.records[start:]
    ledger.passes("rg x module.py")
    loud_rows = ledger.records[start + len(quiet_rows) :]
    state = replay(ledger.prefix)
    counted = counted_later_material(ledger.records[start:], state, all_records=ledger.prefix)
    assert set(counted) == set(loud_rows)
    effects = workspace_effects(ledger.prefix, state)
    assert {classify_later_material(row, state, effects=effects).rule for row in quiet_rows} == {
        "observed_workspace_unchanged",
        "result_of_action",
    }
    assert all(
        classify_later_material(row, state, effects=effects).material_class
        is LaterMaterialClass.EXPLORATION
        for row in quiet_rows
    )
