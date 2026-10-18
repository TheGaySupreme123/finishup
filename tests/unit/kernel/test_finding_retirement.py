"""An observed failed-command finding retires on a later passing run (#1104, owner decision D2).

The observation coordinator records a ``failed_work_omitted`` finding seconds after a hook reports
a failed shell call. These ledgers are built the way the coordinator writes them
(``builders.observed_runs``): hook-observed actions and results, then an observation-authored
finding whose subject refs are the event ids the failed call materialized. The production replay,
closure classifier and to-do predicates then decide what every surface reads.
"""

from __future__ import annotations

import dataclasses
import random
from collections.abc import Iterator

import pytest

from builders.observed_runs import (
    INSTALLATION_KEY,
    ObservedLedger,
    observed_receipt,
    omitted_results,
)
from finishup.domain.events import ResultOutcome
from finishup.domain.findings import ResponseDisposition
from finishup.domain.receipts import ReceiptSectionKey, render_receipt_human
from finishup.domain.values import EventId, FindingId, ObligationId, ResultId
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
from finishup.kernel.task_facts import (
    planned_verification_commands,
    register_command_identity_key,
)

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
    passing = ledger.passes(f"cd /app && {_PYTEST} > log.txt 2>&1")
    _assert_retired(ledger, finding, _result_event(ledger, passing))


@pytest.mark.parametrize(
    "conditioned",
    [
        f"PYTEST_ADDOPTS=--collect-only {_PYTEST}",
        f"cd /app && PYTEST_ADDOPTS=--co {_PYTEST}",
        f"PYTEST_ADDOPTS='--deselect tests/test_x.py::t' {_PYTEST}",
        f"env PYTEST_ADDOPTS=--lf {_PYTEST}",
        f"nohup {_PYTEST}",
        f"exec {_PYTEST}",
        f"time {_PYTEST}",
        f"{_PYTEST} < answers.txt",
    ],
)
def test_a_pass_of_a_conditioned_segment_never_retires_it(conditioned: str) -> None:
    """#1104 round 1: a segment listed after dropping a leading assignment, a wrapper or an input
    redirection ran a different command than the one that failed, so its pass retires nothing."""

    ledger = ObservedLedger()
    finding = _finding_for(ledger, ledger.fail(_PYTEST))
    ledger.passes(conditioned)
    _assert_open(ledger, finding)


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
    f"FOO=1 {_PYTEST}",
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
    assert (
        "no later passing run of the same command or of a planned verification was observed" in text
    )
    assert "no later recorded check is available" not in text


@pytest.mark.parametrize("seed", range(12))
def test_incremental_fold_equals_recompute_all_with_codex_and_unlinked_findings(seed: int) -> None:
    """The fold's narrowed failure branch (#1104 round 1) derives what ``recompute_all`` derives.

    Codex-shaped calls (an ``unknown`` hook result, then a stream correction), findings recorded
    before their correction, and lifecycle-anchored findings that never link all take part.
    """

    from dataclasses import replace as dc_replace

    from finishup.kernel.finding_retirement import recompute_all

    chooser = random.Random(seed)
    ledger = ObservedLedger()
    for step in range(18):
        command = chooser.choice(_COMMANDS)
        roll = chooser.random()
        if roll < 0.3:
            failed = ledger.fail(command, exit_status=chooser.choice((1, 2)))
            if chooser.random() < 0.6:
                _finding_for(ledger, failed, number=step + 1)
        elif roll < 0.5:
            hook = ledger.run(command, ResultOutcome.UNKNOWN)
            if chooser.random() < 0.5:
                ledger.advice_finding(ledger.events_of(hook), number=step + 1)
            outcome = chooser.choice((ResultOutcome.FAILURE, ResultOutcome.SUCCESS))
            ledger.correct_outcome(
                hook, outcome, exit_status=0 if outcome is ResultOutcome.SUCCESS else 1
            )
        elif roll < 0.6:
            ledger.claim(statement="Probing.")
            ledger.advice_finding((ledger.prefix[-1].event_id,), number=step + 1)
        elif roll < 0.9:
            ledger.passes(command)
        else:
            ledger.edit()
    state = _state(ledger)
    observed = observed_event_ids_from_records(ledger.prefix)
    folded = dict(state.findings)
    cleared = {
        key: dc_replace(
            record,
            failed_run_result_id=None,
            retired_by_event_id=None,
            retired_frontier=None,
            retired_by_planned_verification=False,
        )
        for key, record in folded.items()
    }
    recompute_all(cleared, state.results, state.actions, observed)
    assert cleared == folded, seed


# --- a passing planned verification (owner decision 2026-10-18, the broad reading) -------------

_INSTALL = "pip install -e ."
_PLANNED = "pytest -q"


@pytest.fixture
def installation_key() -> Iterator[None]:
    register_command_identity_key(INSTALLATION_KEY)
    yield
    register_command_identity_key(None)


def _assert_retired_by_plan(ledger: ObservedLedger, finding: FindingId, passing: EventId) -> None:
    state = _state(ledger)
    record = state.findings[finding]
    assert record.payload is not None, "the finding stays in history"
    assert record.retired_by_event_id == passing
    assert record.retired_by_planned_verification
    assert finding_todo_state(state, finding) is FindingTodoState.VERIFIED_RESOLVED
    assert not finding_blocks_receipt(state, finding)
    closure = finding_closure(state, finding)
    assert closure is not None
    assert closure.basis == "retired_by_planned_verification"
    assert closure.closure_class is FindingClosureClass.RESOLVED
    assert closure.source_event_ids == (passing,)


@pytest.mark.usefixtures("installation_key")
@pytest.mark.parametrize("plan_first", [True, False])
def test_a_passing_planned_verification_retires_an_unrelated_earlier_failure(
    plan_first: bool,
) -> None:
    """The owner's accepted trade-off: a passing planned verification also clears a failed
    install it never reran. The plan may be published before or after the failure."""

    ledger = ObservedLedger()
    if plan_first:
        ledger.plan(_PLANNED)
    finding = _finding_for(ledger, ledger.fail(_INSTALL))
    if not plan_first:
        ledger.plan(_PLANNED)
    _assert_open(ledger, finding)
    passing = ledger.passes(_PLANNED)
    _assert_retired_by_plan(ledger, finding, _result_event(ledger, passing))


@pytest.mark.usefixtures("installation_key")
@pytest.mark.parametrize(
    "later",
    [
        f"cd /app && {_PLANNED}",
        f"{_PLANNED} > log.txt 2>&1",
        f"cd /app && {_PLANNED} && echo done",
    ],
)
def test_a_planned_verification_inside_a_passing_chain_or_with_prefixes_retires_it(
    later: str,
) -> None:
    """The ADR-033 segment rule under the bare-segment reading: the planned command as a segment
    of a passing ``single`` run or ``&&`` chain that ran exactly as planned is the planned
    verification passing."""

    ledger = ObservedLedger()
    ledger.plan(_PLANNED)
    finding = _finding_for(ledger, ledger.fail(_INSTALL))
    passing = ledger.passes(later)
    _assert_retired_by_plan(ledger, finding, _result_event(ledger, passing))


@pytest.mark.usefixtures("installation_key")
@pytest.mark.parametrize(
    "later",
    [
        "unknown_outcome",
        "failure",
        "masked_chain",
        "pipe",
        "canonical_spelling",
        "unplanned_command",
        "cooperative_success",
        "edit",
    ],
)
def test_what_is_not_a_passing_planned_verification(later: str) -> None:
    ledger = ObservedLedger()
    ledger.plan(_PLANNED)
    finding = _finding_for(ledger, ledger.fail(_INSTALL))
    if later == "unknown_outcome":
        ledger.run(_PLANNED, ResultOutcome.UNKNOWN)
    elif later == "failure":
        ledger.fail(_PLANNED)
    elif later == "masked_chain":
        ledger.passes(f"{_PLANNED}; true")
    elif later == "pipe":
        ledger.passes(f"{_PLANNED} | tail -5")
    elif later == "canonical_spelling":
        # ``normalized``, ``prefix`` and ``flags`` matches are task facts, never a retirement.
        ledger.passes(f"python3 -m {_PLANNED}")
    elif later == "unplanned_command":
        ledger.passes("pytest -q tests/test_other.py")
    elif later == "cooperative_success":
        ledger.run(_PLANNED, ResultOutcome.SUCCESS, exit_status=0, observed=False)
    else:
        ledger.edit()
    _assert_open(ledger, finding)


@pytest.mark.usefixtures("installation_key")
@pytest.mark.parametrize(
    "conditioned",
    [
        f"FOO=1 {_PLANNED}",
        f"PYTEST_ADDOPTS=--collect-only {_PLANNED}",
        f"cd /app && PYTEST_ADDOPTS=--co {_PLANNED}",
        f"env PYTEST_ADDOPTS=--lf {_PLANNED}",
        f"exec {_PLANNED}",
        f"nohup {_PLANNED}",
        f"time {_PLANNED}",
        f"{_PLANNED} < answers.txt",
    ],
)
def test_a_conditioned_planned_segment_never_retires_anything(conditioned: str) -> None:
    """#1104 round 1 (planned path): a segment listed after dropping a leading assignment, a
    wrapper or an input redirection ran a different command than the planned one, so it neither
    retires the failed planned command itself nor any other earlier failure."""

    ledger = ObservedLedger()
    ledger.plan(_PLANNED)
    same = _finding_for(ledger, ledger.fail(_PLANNED))
    other = _finding_for(ledger, ledger.fail(_INSTALL), number=2)
    ledger.passes(conditioned)
    _assert_open(ledger, same)
    _assert_open(ledger, other)


@pytest.mark.usefixtures("installation_key")
@pytest.mark.parametrize(
    "masked",
    [
        f"{_PLANNED} 2>&1 | tail -5",
        f"! {_PLANNED}",
        f"{_PLANNED} || true",
        f"{_PLANNED} &",
        f"{_PLANNED}; true",
    ],
)
def test_a_masked_planned_command_run_exactly_as_planned_never_retires(masked: str) -> None:
    """A planned command whose own composition masks its exit (``| tail``, ``!``, ``|| true``,
    ``&``, ``;``) records the exit of something else, so its success is not a known success of
    the planned work, even when it is run verbatim."""

    ledger = ObservedLedger()
    ledger.plan(masked)
    finding = _finding_for(ledger, ledger.fail(_INSTALL))
    ledger.passes(masked)
    _assert_open(ledger, finding)


@pytest.mark.usefixtures("installation_key")
def test_an_obligation_acknowledged_as_not_done_plans_no_verification() -> None:
    """The obligation set is the task facts' one: an acknowledged-not-done obligation's command
    is no planned verification, and acknowledging it later un-retires what only its pass retired
    (its status is read as the ledger records it now; owner decision 2026-10-18 keeps the
    replay's existing reverse state)."""

    ledger = ObservedLedger()
    obligation = ledger.plan(_PLANNED)
    finding = _finding_for(ledger, ledger.fail(_INSTALL))
    passing = ledger.passes(_PLANNED)
    _assert_retired_by_plan(ledger, finding, _result_event(ledger, passing))
    ledger.acknowledge_not_done(obligation, _PLANNED)
    _assert_open(ledger, finding)
    ledger.passes(_PLANNED)
    _assert_open(ledger, finding)


@pytest.mark.usefixtures("installation_key")
@pytest.mark.parametrize("planned", [True, False])
def test_a_pass_whose_call_began_before_the_failure_finished_never_retires_it(
    planned: bool,
) -> None:
    """Claude Code-shaped parallel calls: the passing call's ``PreToolUse`` action is recorded
    before the failed call's result, so it started before the failure and repairs nothing, even
    though its own result lands later. A pass begun after the failure still retires it."""

    command = _PLANNED if planned else _INSTALL
    ledger = ObservedLedger()
    ledger.plan(_PLANNED)
    early = ledger.begin(command)
    failed = ledger.fail(_INSTALL)
    finding = _finding_for(ledger, failed)
    ledger.end(early, ResultOutcome.SUCCESS, exit_status=0)
    _assert_open(ledger, finding)
    later = ledger.passes(command)
    if planned:
        _assert_retired_by_plan(ledger, finding, _result_event(ledger, later))
    else:
        _assert_retired(ledger, finding, _result_event(ledger, later))


@pytest.mark.usefixtures("installation_key")
def test_a_planned_retirement_still_leaves_the_claim_level_duty() -> None:
    """ADR-025: the completion-claim duty follows the shared supersession rule, which a planned
    verification does not change. A retired install failure must still be named in the claim's
    ``limitation_refs``, or the work-integrity pack reports it as omitted."""

    ledger = ObservedLedger()
    ledger.plan(_PLANNED)
    failed = ledger.fail(_INSTALL)
    finding = _finding_for(ledger, failed)
    passing = ledger.passes(_PLANNED)
    _assert_retired_by_plan(ledger, finding, _result_event(ledger, passing))
    unnamed = dataclasses.replace(ledger, records=list(ledger.records))
    unnamed.claim()
    assert omitted_results(unnamed) == (str(failed),)
    named = dataclasses.replace(ledger, records=list(ledger.records))
    named.claim(limitations=(failed,))
    assert omitted_results(named) == ()


@pytest.mark.usefixtures("installation_key")
def test_a_planned_pass_before_the_failure_never_retires_it() -> None:
    ledger = ObservedLedger()
    ledger.plan(_PLANNED)
    ledger.passes(_PLANNED)
    finding = _finding_for(ledger, ledger.fail(_INSTALL))
    _assert_open(ledger, finding)


def test_without_the_installation_key_no_run_is_a_planned_verification() -> None:
    ledger = ObservedLedger()
    ledger.plan(_PLANNED)
    finding = _finding_for(ledger, ledger.fail(_INSTALL))
    ledger.passes(_PLANNED)
    _assert_open(ledger, finding)


@pytest.mark.usefixtures("installation_key")
def test_the_same_command_passing_is_named_as_such_even_when_it_is_planned() -> None:
    ledger = ObservedLedger()
    ledger.plan(_PLANNED)
    finding = _finding_for(ledger, ledger.fail(_PLANNED))
    passing = ledger.passes(_PLANNED)
    _assert_retired(ledger, finding, _result_event(ledger, passing))
    assert not _state(ledger).findings[finding].retired_by_planned_verification


@pytest.mark.usefixtures("installation_key")
def test_the_earliest_pass_decides_the_kind() -> None:
    ledger = ObservedLedger()
    ledger.plan(_PLANNED)
    finding = _finding_for(ledger, ledger.fail(_INSTALL))
    planned = ledger.passes(_PLANNED)
    ledger.passes(_INSTALL)
    _assert_retired_by_plan(ledger, finding, _result_event(ledger, planned))


@pytest.mark.usefixtures("installation_key")
def test_a_finding_materialized_after_the_planned_pass_is_retired_at_birth() -> None:
    ledger = ObservedLedger()
    ledger.plan(_PLANNED)
    failed = ledger.fail(_INSTALL)
    passing = ledger.passes(_PLANNED)
    finding = _finding_for(ledger, failed)
    _assert_retired_by_plan(ledger, finding, _result_event(ledger, passing))


@pytest.mark.usefixtures("installation_key")
@pytest.mark.parametrize("earlier_plan", [False, True])
def test_a_plan_published_after_the_pass_retires_nothing(earlier_plan: bool) -> None:
    """Owner decision 2026-10-18 (#1104): the obligation naming the planned verification must be
    effective when the run passed, in ledger order. A plan published after the pass, or a later
    plan version that first introduces the obligation, retires nothing; a pass after it does."""

    ledger = ObservedLedger()
    if earlier_plan:
        ledger.plan("npm test")
    finding = _finding_for(ledger, ledger.fail(_INSTALL))
    ledger.passes(_PLANNED)
    _assert_open(ledger, finding)
    ledger.plan(_PLANNED, number=2)
    _assert_open(ledger, finding)
    later = ledger.passes(_PLANNED)
    _assert_retired_by_plan(ledger, finding, _result_event(ledger, later))


@pytest.mark.usefixtures("installation_key")
@pytest.mark.parametrize(
    "planned", ["true", "ls", "ls -la src", "echo ok", "git status", "cat setup.cfg"]
)
def test_a_planned_command_that_is_no_verifier_retires_nothing(planned: str) -> None:
    """Owner decision 2026-10-18 (#1104): only a verifier (runner class test, build, lint or
    typecheck) passing the planned command counts. A plan that requests ``true`` or ``ls``
    cannot clear an earlier failure by running it."""

    from finishup.domain.events import ActionRecordedPayload
    from finishup.kernel.task_facts import planned_verification_passed

    ledger = ObservedLedger()
    ledger.plan(planned)
    finding = _finding_for(ledger, ledger.fail(_INSTALL))
    ledger.passes(planned)
    action = ledger.records[-2].payload
    assert type(action) is ActionRecordedPayload
    state = _state(ledger)
    # Not vacuous: the run passes the planned command; only its runner class refuses it.
    assert planned_verification_passed(
        action.command,
        planned_verification_commands(state.plans, state.obligations, state.coverage_gaps),
    )
    _assert_open(ledger, finding)


@pytest.mark.usefixtures("installation_key")
@pytest.mark.parametrize(
    ("planned", "runner"),
    [
        (_PLANNED, "test"),
        ("pytest -q tests/test_x.py", "test"),
        ("npm run build", "build"),
        ("ruff check .", "lint"),
        ("pyright", "typecheck"),
    ],
)
def test_a_planned_verifier_that_passes_retires(planned: str, runner: str) -> None:
    from finishup.domain.events import ActionRecordedPayload
    from finishup.kernel.observed_failures import observed_action_runner_class

    ledger = ObservedLedger()
    ledger.plan(planned)
    finding = _finding_for(ledger, ledger.fail(_INSTALL))
    passing = ledger.passes(planned)
    action = ledger.records[-2].payload
    assert type(action) is ActionRecordedPayload
    assert observed_action_runner_class(action.description) == runner
    _assert_retired_by_plan(ledger, finding, _result_event(ledger, passing))


@pytest.mark.usefixtures("installation_key")
def test_a_recorded_non_verifier_class_never_passes_a_planned_verification() -> None:
    """The class is the one recorded at the host boundary: the same planned command recorded
    with a non-verifier class (an older build, or a host that classed it ``other``) is no
    verifier, and a later run recorded as ``test`` is."""

    ledger = ObservedLedger()
    ledger.plan(_PLANNED)
    finding = _finding_for(ledger, ledger.fail(_INSTALL))
    ledger.run(_PLANNED, ResultOutcome.SUCCESS, exit_status=0, runner="other")
    _assert_open(ledger, finding)
    passing = ledger.passes(_PLANNED)
    _assert_retired_by_plan(ledger, finding, _result_event(ledger, passing))


@pytest.mark.usefixtures("installation_key")
def test_a_plan_published_while_the_call_runs_counts_when_it_passes() -> None:
    """Claude Code shape: the planned call's ``PreToolUse`` lands before the plan and its
    passing ``PostToolUse`` after it. The obligation was effective when the run passed."""

    ledger = ObservedLedger()
    finding = _finding_for(ledger, ledger.fail(_INSTALL))
    running = ledger.begin(_PLANNED)
    ledger.plan(_PLANNED)
    passing = ledger.end(running, ResultOutcome.SUCCESS, exit_status=0)
    _assert_retired_by_plan(ledger, finding, _result_event(ledger, passing))


@pytest.mark.usefixtures("installation_key")
def test_codex_a_plan_published_before_the_correction_but_after_the_call_ended_retires_nothing() -> (
    None
):
    """Codex shape: the hook result (no exit) marks when the call finished; its passing exit is
    the stream correction joined later. A plan published in between was not effective when the
    run passed, so the correction retires nothing."""

    ledger = ObservedLedger()
    finding = _finding_for(ledger, ledger.fail(_INSTALL))
    hook = ledger.run(_PLANNED, ResultOutcome.UNKNOWN)
    ledger.plan(_PLANNED)
    ledger.correct_outcome(hook, ResultOutcome.SUCCESS, exit_status=0)
    _assert_open(ledger, finding)
    rerun = ledger.run(_PLANNED, ResultOutcome.UNKNOWN)
    corrected = ledger.correct_outcome(rerun, ResultOutcome.SUCCESS, exit_status=0)
    _assert_retired_by_plan(ledger, finding, _result_event(ledger, corrected))


@pytest.mark.usefixtures("installation_key")
def test_codex_a_plan_effective_before_the_call_ended_counts_for_its_correction() -> None:
    ledger = ObservedLedger()
    ledger.plan(_PLANNED)
    finding = _finding_for(ledger, ledger.fail(_INSTALL))
    hook = ledger.run(_PLANNED, ResultOutcome.UNKNOWN)
    _assert_open(ledger, finding)
    corrected = ledger.correct_outcome(hook, ResultOutcome.SUCCESS, exit_status=0)
    _assert_retired_by_plan(ledger, finding, _result_event(ledger, corrected))


@pytest.mark.usefixtures("installation_key")
def test_a_later_plan_version_dropping_the_obligation_does_not_undo_the_retirement() -> None:
    """The retirement was valid when made: a later plan that no longer names the obligation (a
    new restatement of the scope) does not undo it. A waiver or an ``acknowledged_not_done``
    answer, the agent's own statement that it is not being done, does (see below)."""

    ledger = ObservedLedger()
    ledger.plan(_PLANNED)
    finding = _finding_for(ledger, ledger.fail(_INSTALL))
    passing = ledger.passes(_PLANNED)
    _assert_retired_by_plan(ledger, finding, _result_event(ledger, passing))
    ledger.plan("npm test", number=2)
    _assert_retired_by_plan(ledger, finding, _result_event(ledger, passing))


@pytest.mark.usefixtures("installation_key")
def test_waiving_the_planned_obligation_un_retires_what_only_it_retired() -> None:
    """Reverse state: once the plan no longer requests the command, its pass retires nothing,
    and a later pass of the failed command itself still does."""

    ledger = ObservedLedger()
    obligation = ledger.plan(_PLANNED)
    finding = _finding_for(ledger, ledger.fail(_INSTALL))
    passing = ledger.passes(_PLANNED)
    _assert_retired_by_plan(ledger, finding, _result_event(ledger, passing))
    ledger.waive(obligation)
    _assert_open(ledger, finding)
    rerun = ledger.passes(_INSTALL)
    _assert_retired(ledger, finding, _result_event(ledger, rerun))


@pytest.mark.usefixtures("installation_key")
def test_redacting_the_planned_pass_or_the_obligation_reopens_it() -> None:
    for target in ("pass", "obligation"):
        ledger = ObservedLedger()
        ledger.plan(_PLANNED)
        obligation_event = ledger.prefix[-2].event_id
        finding = _finding_for(ledger, ledger.fail(_INSTALL))
        passing = _result_event(ledger, ledger.passes(_PLANNED))
        _assert_retired_by_plan(ledger, finding, passing)
        ledger.redact(passing if target == "pass" else obligation_event)
        _assert_open(ledger, finding)


@pytest.mark.usefixtures("installation_key")
def test_planned_retirement_round_trips_the_snapshot() -> None:
    ledger = ObservedLedger()
    ledger.plan(_PLANNED)
    finding = _finding_for(ledger, ledger.fail(_INSTALL))
    ledger.passes(_PLANNED)
    state = _state(ledger)
    snapshot = projection_snapshot(state)
    assert "retired_by_planned_verification" in repr(snapshot)
    restored = projection_from_snapshot(snapshot)
    assert restored.findings[finding] == state.findings[finding]
    assert projection_snapshot(restored) == snapshot


@pytest.mark.usefixtures("installation_key")
def test_a_planned_retirement_is_named_apart_on_the_receipt() -> None:
    ledger = ObservedLedger()
    ledger.plan(_PLANNED)
    _finding_for(ledger, ledger.fail(_INSTALL))
    ledger.passes(_PLANNED)
    sentence = (
        "One earlier failed-command finding was retired by a later passing run of a planned "
        "verification, not of the command that failed, and remains visible as history."
    )
    summary, markdown, text = _receipt_texts(ledger)
    for rendered in (summary, markdown, text):
        assert sentence in rendered
        assert "retired by a later passing run of the same command" not in rendered
        assert "resolved by a later qualifying check" not in rendered
    for rendered in (markdown, text):
        assert "Retired by a later passing run of a planned verification" in rendered


_PLANNED_COMMANDS = (
    _PLANNED,
    _INSTALL,
    f"cd /app && {_PLANNED}",
    f"{_PLANNED}; true",
    "npm test",
    "cd web && npm test && npm run lint",
)


@pytest.mark.usefixtures("installation_key")
@pytest.mark.parametrize("seed", range(16))
def test_incremental_fold_equals_recompute_all_with_plan_changes(seed: int) -> None:
    """Plans published and waived between failures and passes: the fold (``on_plan_changed``
    included) derives exactly what ``recompute_all`` derives from the final projection."""

    from dataclasses import replace as dc_replace

    from finishup.kernel.finding_retirement import recompute_all

    chooser = random.Random(seed)
    ledger = ObservedLedger()
    obligations: list[ObligationId] = []
    for step in range(20):
        command = chooser.choice(_PLANNED_COMMANDS)
        roll = chooser.random()
        if roll < 0.3:
            failed = ledger.fail(command)
            if chooser.random() < 0.7:
                _finding_for(ledger, failed, number=step + 1)
        elif roll < 0.4:
            obligations.append(
                ledger.plan(chooser.choice(("pytest -q", "npm test")), number=step + 1)
            )
        elif roll < 0.45 and obligations:
            ledger.waive(obligations.pop(0))
        elif roll < 0.9:
            ledger.passes(command)
        else:
            ledger.run(command, ResultOutcome.UNKNOWN)
    state = _state(ledger)
    observed = observed_event_ids_from_records(ledger.prefix)
    folded = dict(state.findings)
    cleared = {
        key: dc_replace(
            record,
            failed_run_result_id=None,
            retired_by_event_id=None,
            retired_frontier=None,
            retired_by_planned_verification=False,
        )
        for key, record in folded.items()
    }
    recompute_all(
        cleared,
        state.results,
        state.actions,
        observed,
        lambda point: planned_verification_commands(
            state.plans, state.obligations, state.coverage_gaps, effective_at=point
        ),
    )
    assert cleared == folded, seed
