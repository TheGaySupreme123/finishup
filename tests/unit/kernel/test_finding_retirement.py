"""An observed failed-command finding retires on a later passing run (#1104, owner decision D2).

The observation coordinator records a ``failed_work_omitted`` finding seconds after a hook reports
a failed shell call. These ledgers are built the way the coordinator writes them
(``builders.observed_runs``): hook-observed actions and results, then an observation-authored
finding whose subject refs are the event ids the failed call materialized. The production replay,
closure classifier and to-do predicates then decide what every surface reads.
"""

from __future__ import annotations

import random

import pytest

from builders.observed_runs import ObservedLedger, observed_receipt
from finishup.domain.events import ResultOutcome
from finishup.domain.findings import ResponseDisposition
from finishup.domain.receipts import ReceiptSectionKey, render_receipt_human
from finishup.domain.values import EventId, FindingId, ResultId
from finishup.kernel.closure_class import FindingClosureClass, ReceiptEffect, finding_closure
from finishup.kernel.finding_retirement import is_observed_failed_command_finding
from finishup.kernel.finding_todo import (
    FindingTodoState,
    finding_blocks_receipt,
    finding_todo_state,
)
from finishup.kernel.observed_failures import (
    _projection_runs,  # pyright: ignore[reportPrivateUsage]
    observed_event_ids_from_records,
    superseding_witnesses,
)
from finishup.kernel.projections import (
    ProjectionState,
    projection_from_snapshot,
    projection_snapshot,
)
from finishup.kernel.reducers import replay

_PYTEST = "pytest -q tests/test_x.py"


def _finding_for(ledger: ObservedLedger, failed: ResultId, *, number: int = 1) -> FindingId:
    return ledger.advice_finding(ledger.events_of(failed), number=number)


def _state(ledger: ObservedLedger) -> ProjectionState:
    return replay(ledger.prefix)


def _result_event(ledger: ObservedLedger, result: ResultId) -> EventId:
    return ledger.events_of(result)[1]


def _assert_retired(ledger: ObservedLedger, finding: FindingId, passing: EventId) -> None:
    state = _state(ledger)
    record = state.findings[finding]
    assert record.payload is not None, "the finding stays in history"
    assert record.retired_by_event_id == passing
    assert finding_todo_state(state, finding) is FindingTodoState.VERIFIED_RESOLVED
    assert not finding_blocks_receipt(state, finding)
    closure = finding_closure(state, finding)
    assert closure is not None
    assert closure.basis == "retired_by_passing_run"
    assert closure.closure_class is FindingClosureClass.RESOLVED
    assert closure.source_event_ids == (passing,)


def _assert_open(ledger: ObservedLedger, finding: FindingId) -> None:
    state = _state(ledger)
    record = state.findings[finding]
    assert record.retired_by_event_id is None
    assert finding_todo_state(state, finding) is FindingTodoState.OPEN
    assert finding_blocks_receipt(state, finding)


def test_a_later_pass_retires_the_observed_failed_command_finding() -> None:
    ledger = ObservedLedger()
    failed = ledger.fail(_PYTEST)
    finding = _finding_for(ledger, failed)
    _assert_open(ledger, finding)
    state = _state(ledger)
    assert is_observed_failed_command_finding(state.findings[finding])
    assert state.findings[finding].failed_run_result_id == failed

    passing = ledger.passes(_PYTEST)
    _assert_retired(ledger, finding, _result_event(ledger, passing))


def test_a_passing_and_chain_containing_the_failed_command_retires_it() -> None:
    ledger = ObservedLedger()
    finding = _finding_for(ledger, ledger.fail(_PYTEST))
    passing = ledger.passes(f"cd /app && FOO=1 {_PYTEST}")
    _assert_retired(ledger, finding, _result_event(ledger, passing))


def test_a_finding_materialized_after_the_pass_is_retired_at_birth() -> None:
    ledger = ObservedLedger()
    failed = ledger.fail(_PYTEST)
    passing = ledger.passes(_PYTEST)
    finding = _finding_for(ledger, failed)
    _assert_retired(ledger, finding, _result_event(ledger, passing))


def test_the_witness_is_the_earliest_later_pass() -> None:
    ledger = ObservedLedger()
    finding = _finding_for(ledger, ledger.fail(_PYTEST))
    first = ledger.passes(_PYTEST)
    ledger.passes(f"cd /app && {_PYTEST}")
    _assert_retired(ledger, finding, _result_event(ledger, first))


@pytest.mark.parametrize(
    "later",
    [
        "edit",
        "different_command",
        "unknown_outcome",
        "cooperative_success",
        "masked_chain",
        "pipe",
        "failed_chain_whole",
    ],
)
def test_an_edit_or_another_command_never_retires_it(later: str) -> None:
    ledger = ObservedLedger()
    finding = _finding_for(ledger, ledger.fail(_PYTEST))
    if later == "edit":
        ledger.edit()
    elif later == "different_command":
        ledger.passes("pytest -q tests/test_other.py")
    elif later == "unknown_outcome":
        ledger.run(_PYTEST, ResultOutcome.UNKNOWN)
    elif later == "cooperative_success":
        ledger.run(_PYTEST, ResultOutcome.SUCCESS, exit_status=0, observed=False)
    elif later == "masked_chain":
        ledger.passes(f"cd /app; {_PYTEST}")
    elif later == "pipe":
        ledger.passes(f"{_PYTEST} | tail -5")
    else:
        # A canonical spelling of the same test (``python -m pytest``) is domain-separated.
        ledger.passes(f"python3 -m {_PYTEST}")
    _assert_open(ledger, finding)


def test_a_failed_chain_is_retired_only_by_its_own_whole_command() -> None:
    ledger = ObservedLedger()
    finding = _finding_for(ledger, ledger.fail(f"cd /app && {_PYTEST}"))
    ledger.passes(_PYTEST)
    _assert_open(ledger, finding)
    passing = ledger.passes(f"cd /app && {_PYTEST}")
    _assert_retired(ledger, finding, _result_event(ledger, passing))


def test_a_later_failure_of_the_same_command_keeps_it_open_until_a_pass() -> None:
    ledger = ObservedLedger()
    first = _finding_for(ledger, ledger.fail(_PYTEST), number=1)
    second = _finding_for(ledger, ledger.fail(_PYTEST, exit_status=2), number=2)
    _assert_open(ledger, first)
    _assert_open(ledger, second)
    passing = _result_event(ledger, ledger.passes(_PYTEST))
    _assert_retired(ledger, first, passing)
    _assert_retired(ledger, second, passing)


def test_redacting_the_passing_run_reopens_it() -> None:
    ledger = ObservedLedger()
    finding = _finding_for(ledger, ledger.fail(_PYTEST))
    passing = _result_event(ledger, ledger.passes(_PYTEST))
    _assert_retired(ledger, finding, passing)
    ledger.redact(passing)
    _assert_open(ledger, finding)


def test_a_second_pass_still_retires_it_after_the_first_is_redacted() -> None:
    ledger = ObservedLedger()
    finding = _finding_for(ledger, ledger.fail(_PYTEST))
    first = _result_event(ledger, ledger.passes(_PYTEST))
    second = _result_event(ledger, ledger.passes(_PYTEST))
    ledger.redact(first)
    _assert_retired(ledger, finding, second)


def test_redacting_the_failed_run_drops_the_failed_run_fact() -> None:
    ledger = ObservedLedger()
    failed = ledger.fail(_PYTEST)
    finding = _finding_for(ledger, failed)
    ledger.passes(_PYTEST)
    ledger.redact(_result_event(ledger, failed))
    state = _state(ledger)
    assert state.findings[finding].failed_run_result_id is None
    assert state.findings[finding].retired_by_event_id is None
    assert finding_todo_state(state, finding) is FindingTodoState.OPEN


def test_a_pack_failed_work_finding_is_never_retired_by_this_rule() -> None:
    """A claim-level finding names its claim; the retirement rule never applies to it."""

    ledger = ObservedLedger()
    failed = ledger.fail(_PYTEST)
    claim = ledger.claim()
    action_event, result_event = ledger.events_of(failed)
    finding = ledger.advice_finding(
        (), subject=tuple(sorted((str(claim), str(action_event), str(result_event))))
    )
    ledger.passes(_PYTEST)
    state = _state(ledger)
    record = state.findings[finding]
    assert not record.observed_failed_command
    assert record.retired_by_event_id is None
    assert finding_todo_state(state, finding) is FindingTodoState.OPEN


def test_lifecycle_anchored_finding_has_no_failed_run_but_acknowledgement_settles_it() -> None:
    """A finding anchored on a non-run event (the coordinator's lifecycle fallback) names no
    failed run: no rerun can retire it, and ``acknowledged`` still settles it as disclosed."""

    ledger = ObservedLedger()
    ledger.fail(_PYTEST)
    ledger.claim(statement="Probing.")
    finding = ledger.advice_finding((ledger.prefix[-1].event_id,))
    ledger.passes(_PYTEST)
    state = _state(ledger)
    assert state.findings[finding].observed_failed_command
    assert state.findings[finding].failed_run_result_id is None
    assert finding_todo_state(state, finding) is FindingTodoState.OPEN

    ledger.respond(finding, ResponseDisposition.ACKNOWLEDGED)
    state = _state(ledger)
    closure = finding_closure(state, finding)
    assert closure is not None
    assert closure.basis == "failed_run_disclosed"
    assert closure.closure_class is FindingClosureClass.SETTLED_DISCLOSED
    assert closure.receipt_effect is ReceiptEffect.INSUFFICIENT_COVERAGE


def test_codex_outcome_correction_is_the_failed_run_and_the_pass() -> None:
    """Codex 0.159 states no exit in ``PostToolUse``: the hook result is ``unknown`` and the
    session stream's outcome correction for the same call is the recorded outcome (#1001)."""

    ledger = ObservedLedger()
    hook_failed = ledger.run(_PYTEST, ResultOutcome.UNKNOWN)
    corrected_failure = ledger.correct_outcome(hook_failed, ResultOutcome.FAILURE, exit_status=1)
    # The coordinator names the call's hook action and result events.
    finding = ledger.advice_finding(ledger.events_of(hook_failed))
    assert _state(ledger).findings[finding].failed_run_result_id == corrected_failure

    hook_pass = ledger.run(_PYTEST, ResultOutcome.UNKNOWN)
    _assert_open(ledger, finding)
    corrected_pass = ledger.correct_outcome(hook_pass, ResultOutcome.SUCCESS, exit_status=0)
    _assert_retired(ledger, finding, _result_event(ledger, corrected_pass))


def test_codex_finding_recorded_before_its_correction_still_finds_the_failed_run() -> None:
    ledger = ObservedLedger()
    hook_failed = ledger.run(_PYTEST, ResultOutcome.UNKNOWN)
    finding = ledger.advice_finding(ledger.events_of(hook_failed))
    assert _state(ledger).findings[finding].failed_run_result_id is None
    ledger.correct_outcome(hook_failed, ResultOutcome.FAILURE, exit_status=1)
    passing = ledger.passes(_PYTEST)
    _assert_retired(ledger, finding, _result_event(ledger, passing))


def test_a_conflicting_outcome_for_the_same_call_never_retires_it() -> None:
    ledger = ObservedLedger()
    failed = ledger.fail(_PYTEST)
    finding = _finding_for(ledger, failed)
    ledger.correct_outcome(failed, ResultOutcome.SUCCESS, exit_status=0)
    _assert_open(ledger, finding)


def test_pass_after_acknowledgement_resolves() -> None:
    ledger = ObservedLedger()
    finding = _finding_for(ledger, ledger.fail(_PYTEST))
    ledger.respond(finding, ResponseDisposition.ACKNOWLEDGED, reason="the fixture is missing")
    closure = finding_closure(_state(ledger), finding)
    assert closure is not None and closure.basis == "failed_run_disclosed"
    assert closure.next_actions == ("repair",)
    passing = ledger.passes(_PYTEST)
    _assert_retired(ledger, finding, _result_event(ledger, passing))


@pytest.mark.parametrize("disposition", [ResponseDisposition.ACKNOWLEDGED_NOT_DONE])
def test_pass_after_acknowledged_not_done_resolves(disposition: ResponseDisposition) -> None:
    ledger = ObservedLedger()
    finding = _finding_for(ledger, ledger.fail(_PYTEST))
    ledger.respond(finding, disposition, reason="out of scope for this task")
    closure = finding_closure(_state(ledger), finding)
    assert closure is not None and closure.basis == "acknowledged_not_done_bookkeeping"
    passing = ledger.passes(_PYTEST)
    _assert_retired(ledger, finding, _result_event(ledger, passing))


_COMMANDS = (
    _PYTEST,
    "pytest -q tests/test_other.py",
    f"cd /app && {_PYTEST}",
    f"cd /app; {_PYTEST}",
    "npm test",
    "cd web && npm test && npm run lint",
)


@pytest.mark.parametrize("seed", range(24))
def test_incremental_fold_equals_full_classification(seed: int) -> None:
    """The reducer's per-event retirement equals the shared rule over the whole prefix."""

    chooser = random.Random(seed)
    ledger = ObservedLedger()
    findings: dict[FindingId, ResultId] = {}
    for step in range(14):
        command = chooser.choice(_COMMANDS)
        roll = chooser.random()
        if roll < 0.4:
            failed = ledger.fail(command, exit_status=chooser.choice((1, 2)))
            if chooser.random() < 0.7:
                findings[_finding_for(ledger, failed, number=step + 1)] = failed
        elif roll < 0.8:
            ledger.passes(command)
        elif roll < 0.9:
            ledger.edit()
        else:
            ledger.run(command, ResultOutcome.UNKNOWN)
    state = _state(ledger)
    observed = observed_event_ids_from_records(ledger.prefix)
    witnesses = superseding_witnesses(
        _projection_runs(state.results, state.actions, observed, state.frontier)
    )
    for finding, failed in findings.items():
        record = state.findings[finding]
        witness = witnesses.get(str(failed))
        expected = None if witness is None else state.results[ResultId(witness)].source_event_id
        assert record.retired_by_event_id == expected, (seed, finding)


def test_snapshot_round_trip_and_byte_identity_without_retirement() -> None:
    plain = ObservedLedger()
    plain.fail(_PYTEST)
    plain.passes(_PYTEST)
    plain_snapshot = projection_snapshot(_state(plain))
    assert "observed_failed_command" not in repr(plain_snapshot)
    assert "retired_by_event_id" not in repr(plain_snapshot)

    retired = ObservedLedger()
    finding = _finding_for(retired, retired.fail(_PYTEST))
    retired.passes(_PYTEST)
    state = _state(retired)
    snapshot = projection_snapshot(state)
    restored = projection_from_snapshot(snapshot)
    assert restored.findings[finding] == state.findings[finding]
    assert projection_snapshot(restored) == snapshot


@pytest.mark.parametrize(
    ("disposition", "basis"),
    [
        (ResponseDisposition.ACKNOWLEDGED, "open_answered"),
        (ResponseDisposition.ACKNOWLEDGED_NOT_DONE, "acknowledged_not_done_requirement"),
    ],
)
def test_answers_on_any_other_failed_work_finding_are_unchanged(
    disposition: ResponseDisposition, basis: str
) -> None:
    """No widening: a claim-level failed-work finding answered the same way keeps its basis."""

    ledger = ObservedLedger()
    failed = ledger.fail(_PYTEST)
    claim = ledger.claim()
    finding = ledger.advice_finding(
        (), subject=tuple(sorted((str(claim), str(_result_event(ledger, failed)))))
    )
    ledger.respond(finding, disposition, reason="the fixture is missing")
    closure = finding_closure(_state(ledger), finding)
    assert closure is not None
    assert closure.basis == basis


def _receipt_texts(ledger: ObservedLedger) -> tuple[str, str, str]:
    document = observed_receipt(ledger)
    summary = next(
        section.body for section in document.sections if section.key is ReceiptSectionKey.SUMMARY
    )
    return (
        summary,
        render_receipt_human(document, markdown=True),
        render_receipt_human(document, markdown=False),
    )


def test_retired_failed_commands_are_named_as_history_apart_from_check_resolved() -> None:
    ledger = ObservedLedger()
    _finding_for(ledger, ledger.fail(_PYTEST))
    ledger.passes(_PYTEST)
    sentence = (
        "One earlier failed-command finding was retired by a later passing run of the same "
        "command and remains visible as history."
    )
    summary, markdown, text = _receipt_texts(ledger)
    for rendered in (summary, markdown, text):
        assert sentence in rendered
        assert "resolved by a later qualifying check" not in rendered
    for rendered in (markdown, text):
        assert "Retired by a later passing run of the same command" in rendered
        assert "qualifying check None" not in rendered


def test_disclosed_failed_command_is_named_as_disclosed_never_clean() -> None:
    ledger = ObservedLedger()
    finding = _finding_for(ledger, ledger.fail(_PYTEST))
    ledger.respond(finding, ResponseDisposition.ACKNOWLEDGED, reason="the fixture is missing")
    state = _state(ledger)
    assert not finding_blocks_receipt(state, finding)
    _summary, markdown, text = _receipt_texts(ledger)
    for rendered in (markdown, text):
        assert "Disclosed failed command" in rendered
        assert "no later recorded check is available" not in rendered


def test_an_open_observed_failure_says_rerun_not_check() -> None:
    ledger = ObservedLedger()
    _finding_for(ledger, ledger.fail(_PYTEST))
    _summary, _markdown, text = _receipt_texts(ledger)
    assert "no later passing run of the same command was observed" in text
    assert "no later recorded check is available" not in text
