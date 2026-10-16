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
    ReviewMode,
)
from finishup.domain.values import obligation_id
from finishup.kernel.closing_review_delta import (
    closing_material_frontier,
    closing_review_delta,
)
from finishup.kernel.projections import ProjectionState
from finishup.kernel.reducers import replay
from finishup.kernel.task_facts import (
    EDITED_AFTER_LAST_VERIFICATION_GAP,
    register_command_identity_key,
    task_fact_signals,
)

_OBLIGATION = obligation_id("obl_00000000-0000-4000-8000-000000001080")


@pytest.fixture(autouse=True)
def installation_key() -> Iterator[None]:
    register_command_identity_key(INSTALLATION_KEY)
    yield
    register_command_identity_key(None)


def _plan_verification(ledger: ObservedLedger, command: str) -> None:
    """The agent declares its verifier as a requested command (ADR-045 planned verification)."""

    ledger.append(
        EventSchema("obligation_published", "1.0.0"),
        ObligationPublishedPayload(
            obligation_id=_OBLIGATION,
            description="Deliverable verified by the task's own verifier",
            evidence_expectation="Observed verifier run",
            status=ObligationStatus.OPEN,
            requested_items=(RequestedItem(RequestedItemKind.COMMAND, command),),
        ),
        observed=False,
    )
    ledger.append(
        EventSchema("plan_published", "1.0.0"),
        PlanPublishedPayload(1, "Plan", (_OBLIGATION,)),
        observed=False,
    )


def _stale(ledger: ObservedLedger) -> bool:
    prefix = ledger.prefix
    return EDITED_AFTER_LAST_VERIFICATION_GAP in task_fact_signals(replay(prefix), prefix).codes


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
        # PR #1080 round-3 review counterexamples: each changed a deliverable with no write fact.
        ("env PATH=/agent/shadow date -u", None),
        ("/agent/shadow/bin/date -u", None),
        (
            "finishup closure-prepare --session-id ses_x --writer-id wri_x"
            " --output ./deliverable.txt",
            None,
        ),
        ("git status --short", None),
        (
            "env GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.fsmonitor GIT_CONFIG_VALUE_0=./rewrite"
            " git status --short",
            None,
        ),
        ("python finalize.py", "workspace"),
        ("python fit_regression.py", "workspace"),
    ],
)
def test_writes_verifiers_and_unproven_commands_rearm(command: str, scope: str | None) -> None:
    ledger = ObservedLedger(records=list(_prefix()))
    start = len(ledger.records)
    ledger.run(command, ResultOutcome.SUCCESS, write_scope=scope)
    state = replay(ledger.prefix)
    assert all(closing_review_delta(row, state) for row in ledger.records[start:])
    assert closing_material_frontier(state, ledger.prefix) > start


def test_git_status_is_exploration_only_with_the_host_proof() -> None:
    """Finding 4: the hook records ``exploration`` only after reading the repository's config.

    Without that proof (an fsmonitor, hook or filter Git could run, or no payload directory) the
    classifier's own ``vcs`` class re-arms the closing review.
    """

    proven = ObservedLedger(records=list(_prefix()))
    start = len(proven.records)
    proven.run("git status --short", ResultOutcome.SUCCESS, exit_status=0, runner="exploration")
    state = replay(proven.prefix)
    assert all(not closing_review_delta(row, state) for row in proven.records[start:])
    unproven = ObservedLedger(records=list(_prefix()))
    unproven.run("git status --short", ResultOutcome.SUCCESS, exit_status=0)
    state = replay(unproven.prefix)
    assert all(closing_review_delta(row, state) for row in unproven.records[start:])


HOF_COMMAND = (
    "apply_patch <<'PATCH'\n*** Begin Patch\n*** Update File: /app/solution/finalize.py\n@@\n"
    "-old\n+new\n*** End Patch\nPATCH\npython /app/solution/finalize.py"
)


def test_edit_then_named_verification_in_same_command_is_current() -> None:
    ledger = ObservedLedger()
    ledger.passes("npm run build")
    ledger.run(
        "printf updated > module.py && python tests/check.py",
        ResultOutcome.SUCCESS,
        exit_status=0,
        write_scope="workspace",
    )
    assert not _stale(ledger)
    ledger.edit()
    assert _stale(ledger)


def test_hof_finalizer_counts_as_verification_only_when_declared() -> None:
    """Finding 3: the audited HOF verifier is credited through its declared requested command.

    Its file name grants nothing, so an undeclared generator never clears the stale-verification
    gap; the declared verifier, run in the same command as the last edit, does. A later edit makes
    it stale again.
    """

    undeclared = ObservedLedger()
    undeclared.passes("npm run build")
    undeclared.run(HOF_COMMAND, ResultOutcome.SUCCESS, exit_status=0, write_scope="workspace")
    assert _stale(undeclared)
    declared = ObservedLedger()
    _plan_verification(declared, "python /app/solution/finalize.py")
    declared.passes("npm run build")
    declared.run(HOF_COMMAND, ResultOutcome.SUCCESS, exit_status=0, write_scope="workspace")
    assert not _stale(declared)
    declared.edit()
    assert _stale(declared)


@pytest.mark.parametrize("generator", ["python finalize.py", "python fit_regression.py"])
def test_a_generator_never_clears_the_stale_verification_gap(generator: str) -> None:
    """Finding 3 counterexample: pytest, an edit, then a generator that writes the workspace."""

    ledger = ObservedLedger()
    ledger.passes("pytest -q")
    ledger.edit()
    assert _stale(ledger)
    ledger.run(generator, ResultOutcome.SUCCESS, exit_status=0, write_scope="workspace")
    assert _stale(ledger)


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
