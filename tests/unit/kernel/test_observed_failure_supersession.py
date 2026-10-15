"""A later passing run supersedes an earlier observed failure before a completion claim (#909).

Every vector here drives the production path end to end over one exact accepted prefix: the pure
``replay`` (which owns the claim-revision invariant), ``build_deterministic_case``, the composed
local packs with their cross-pack collapse, and the receipt builder. Hook-observed rows carry the
service-stamped observation authorship and ``hook_observed`` channel the coordinator writes; a
command action carries the ``omitted:<hmac commitment>`` identity materialization derives from the
hook's keyed ``command_commitment``. Outcomes are set as the ledger records them once a host
reports them (Claude Code and Cursor ordinary profiles today, Codex after #910).
"""

from __future__ import annotations

import pytest

from builders.observed_runs import (
    ObservedLedger,
    command_identity_for,
    omissions,
    omitted_results,
    receipt_limitations,
)
from finishup.domain.events import ActionKind, ClaimRevisionMismatch, ResultOutcome
from finishup.domain.findings import FindingKind
from finishup.domain.values import ResultId, SubjectStateRef
from finishup.kernel.claims import effective_claim_ids
from finishup.kernel.observed_failures import (
    ObservedFailureState,
    ObservedRun,
    classify_observed_runs,
    command_identity,
    observed_event_ids_from_records,
    observed_failure_states,
)
from finishup.kernel.reducers import build_replay_index, replay

# --- the shared predicate itself -------------------------------------------------------------


def _run(position: int, outcome: ResultOutcome, identity: str | None = None, *, edit: bool = False):
    return ObservedRun(f"r{position}", position, outcome, identity, edit)


_A = "hmac-sha256:" + "a" * 64
_B = "hmac-sha256:" + "b" * 64


def test_classification_is_one_backward_pass_over_command_identity() -> None:
    states = classify_observed_runs(
        (
            _run(1, ResultOutcome.FAILURE, _A),  # later passed by the same identity
            _run(2, ResultOutcome.SUCCESS, _A),
            _run(3, ResultOutcome.FAILURE, _A),  # a new failure after the pass is live again
            _run(4, ResultOutcome.FAILURE, _B),  # different identity: the pass never touches it
            _run(5, ResultOutcome.PARTIAL, None),
        )
    )
    assert states == {
        "r1": ObservedFailureState.SUPERSEDED,
        "r3": ObservedFailureState.LIVE,
        "r4": ObservedFailureState.LIVE,
        "r5": ObservedFailureState.LIVE,
    }
    edited = classify_observed_runs(
        (
            _run(1, ResultOutcome.FAILURE, _A),
            _run(2, ResultOutcome.FAILURE, None),
            _run(3, ResultOutcome.FAILURE, None, edit=True),  # a failed edit changed nothing
            _run(4, ResultOutcome.FAILURE, _B),
            _run(5, ResultOutcome.SUCCESS, None, edit=True),  # an edit with a stated success
            _run(6, ResultOutcome.FAILURE, _A),
        )
    )
    # r6 reruns r1's command, so r1 is judged through that later run, not the edit.
    assert edited["r1"] is ObservedFailureState.RERUN
    # A successful edit changes the state under test but proves no covering rerun. Both unrelated
    # failures remain live until an exact command rerun or explicit acknowledgement.
    assert edited["r2"] is ObservedFailureState.LIVE
    assert edited["r4"] is ObservedFailureState.LIVE
    assert edited["r6"] is ObservedFailureState.LIVE


@pytest.mark.parametrize(
    "command",
    [
        "omitted:structural",
        "omitted:sha256:" + "a" * 64,
        "pytest -q tests/x.py",
        "omitted:hmac-sha256:" + "A" * 64,
        None,
    ],
)
def test_only_the_keyed_commitment_is_a_command_identity(command: str | None) -> None:
    assert command_identity(command) is None
    assert command_identity("omitted:" + _A) == _A


# --- acceptance: red, green, claim ---------------------------------------------------------------


def test_red_then_identical_green_then_claim_raises_no_omission() -> None:
    ledger = ObservedLedger()
    ledger.fail("pytest -q tests/x.py")
    ledger.passes("pytest -q tests/x.py")
    claim = ledger.claim(versioned=True)
    # The v1.1 claim needs no limitation_refs: replay admits it (#909 extends ADR-025).
    assert effective_claim_ids(replay(ledger.prefix)) == frozenset({claim})
    assert omissions(ledger) == ()


def test_normalized_identity_supersedes_a_wrapped_or_respaced_rerun() -> None:
    ledger = ObservedLedger()
    ledger.fail("/bin/bash -lc 'pytest -q tests/x.py'")
    ledger.passes("pytest  -q   tests/x.py")
    ledger.claim()
    assert omissions(ledger) == ()


def test_red_then_claim_raises_exactly_one_finding_naming_the_observed_run() -> None:
    ledger = ObservedLedger()
    failed = ledger.fail("pytest -q tests/x.py", exit_status=2)
    ledger.claim()
    found = omissions(ledger)
    assert len(found) == 1
    finding = found[0].candidate
    assert finding.kind is FindingKind.FAILED_WORK_OMITTED
    assert f"Observed run: result {failed} of action act_" in finding.detail
    assert "status view=results lists its tool, occurrence, command commitment" in finding.detail
    assert "pytest" not in finding.detail and "tests/x.py" not in finding.detail
    # The same live failure still blocks an undisclosed v1.1 claim at admission.
    blocked = ObservedLedger()
    blocked.fail("pytest -q tests/x.py")
    with pytest.raises(ClaimRevisionMismatch) as caught:
        blocked.claim(versioned=True)
        replay(blocked.prefix)
    assert caught.value.invariant == "limitation_refs_complete"


def test_structural_disclosure_clears_the_finding_and_the_receipt_carries_it() -> None:
    ledger = ObservedLedger()
    failed = ledger.fail("pytest -q tests/x.py")
    ledger.claim(limitations=(failed,))
    assert omissions(ledger) == ()
    limitations = receipt_limitations(ledger)
    assert "1 hook-observed failing run is disclosed as a limitation" in limitations
    assert limitations.count(failed) == 1


def test_a_different_command_does_not_supersede_without_an_edit() -> None:
    ledger = ObservedLedger()
    failed = ledger.fail("pytest -q tests/a.py")
    ledger.passes("pytest -q tests/b.py")
    ledger.claim()
    assert omitted_results(ledger) == (failed,)


def test_any_later_success_of_another_command_never_supersedes() -> None:
    ledger = ObservedLedger()
    failed = ledger.fail("pytest -q tests/x.py")
    ledger.passes("echo ok")
    ledger.claim()
    assert omitted_results(ledger) == (failed,)


# --- acceptance: edits do not retire required verification (#909) ------------------------------


def test_failure_then_unrelated_edit_stays_outstanding_until_acknowledged() -> None:
    ledger = ObservedLedger()
    failed = ledger.fail("cargo test -p pest_meta")
    ledger.edit()
    ledger.claim(versioned=True, limitations=(failed,))
    assert omissions(ledger) == ()
    limitations = receipt_limitations(ledger)
    assert "1 hook-observed failing run is disclosed as a limitation" in limitations
    assert "observed workspace edit" not in limitations
    assert limitations.count(failed) == 1
    assert "cargo" not in limitations


def test_differing_subject_states_do_not_turn_an_edit_into_a_covering_rerun() -> None:
    ledger = ObservedLedger()
    failed = ledger.run(
        "pytest -q tests/x.py",
        ResultOutcome.FAILURE,
        subject_state=SubjectStateRef(tree_digest="sha256:" + "1" * 64),
    )
    ledger.edit(subject_state=SubjectStateRef(tree_digest="sha256:" + "2" * 64))
    ledger.claim(versioned=True, limitations=(failed,))
    assert omissions(ledger) == ()
    assert "observed workspace edit" not in receipt_limitations(ledger)


def test_failure_then_claim_without_an_edit_is_a_finding() -> None:
    ledger = ObservedLedger()
    failed = ledger.fail("cargo test -p pest_meta")
    ledger.claim()
    assert omitted_results(ledger) == (failed,)


def test_a_failed_edit_changes_nothing_and_keeps_the_failure_live() -> None:
    ledger = ObservedLedger()
    failed = ledger.fail("npm test")
    failed_edit = ledger.edit(ResultOutcome.FAILURE)
    ledger.claim()
    # The rejected patch is itself undisclosed failed work; it retires nothing before it.
    assert omitted_results(ledger) == (failed, failed_edit)


def test_edit_after_the_claim_does_not_retire_a_failure_before_it() -> None:
    ledger = ObservedLedger()
    failed = ledger.fail("npm test")
    ledger.claim()
    ledger.edit()
    ledger.passes("npm test")
    assert omitted_results(ledger) == (failed,)


def test_a_repaired_replacement_claim_is_clean_while_history_stays() -> None:
    """Done stays done: the live failure is fixed, rerun green, and a replacement is published."""

    ledger = ObservedLedger()
    failed = ledger.fail("npm test")
    first = ledger.claim(1)
    assert omitted_results(ledger) == (failed,)
    ledger.edit()
    ledger.passes("npm test")
    ledger.claim(2, supersedes=(first,), statement="The change is complete; npm test passes.")
    assert omissions(ledger) == ()
    assert "1 was later passed by the same command" in receipt_limitations(ledger)


# --- provenance: only service-stamped observations retire an observed failure -------------------


def test_cooperative_success_or_edit_never_retires_an_observed_failure() -> None:
    ledger = ObservedLedger()
    failed = ledger.fail("pytest -q tests/x.py")
    # The agent can read the commitment from status and republish it; it proves nothing.
    ledger.run("pytest -q tests/x.py", ResultOutcome.SUCCESS, exit_status=0, observed=False)
    ledger.run(None, ResultOutcome.SUCCESS, kind=ActionKind.EDIT, observed=False)
    ledger.claim()
    assert omitted_results(ledger) == (failed,)


def test_cooperative_failures_keep_their_exact_disclosure_duty() -> None:
    ledger = ObservedLedger()
    failed = ledger.run("pytest -q tests/x.py", ResultOutcome.FAILURE, observed=False)
    ledger.edit()
    ledger.passes("pytest -q tests/x.py")
    ledger.claim()
    assert omitted_results(ledger) == (failed,)


# --- lifecycles: legacy rows without an identity never retire on edits -------------------------


def test_legacy_structural_rows_never_supersede_each_other_or_edits() -> None:
    legacy = ObservedLedger()
    failed = legacy.fail(None)
    legacy.passes(None)
    legacy.claim()
    assert omitted_results(legacy) == (failed,)

    upgraded = ObservedLedger()
    legacy_failed = upgraded.fail(None)
    upgraded.edit()
    upgraded.claim(versioned=True, limitations=(legacy_failed,))
    assert omissions(upgraded) == ()
    records = upgraded.prefix
    states = observed_failure_states(
        replay(records), observed_event_ids_from_records(records), through=len(records)
    )
    assert set(states.values()) == {ObservedFailureState.LIVE}


def test_replay_index_names_only_service_stamped_observed_runs() -> None:
    ledger = ObservedLedger()
    ledger.fail("pytest -q tests/x.py")
    ledger.run("pytest -q tests/x.py", ResultOutcome.SUCCESS, observed=False)
    ledger.claim()
    index = build_replay_index(ledger.prefix)
    assert index.observed_event_ids == observed_event_ids_from_records(ledger.prefix)
    assert len(index.observed_event_ids) == 2


# --- replays of the post-mortem examples ----------------------------------------------------------

_PEST_FULL = (
    "cargo test --offline -p pest_meta -p pest_generator -p pest_vm -p pest_derive "
    "--features grammar-extras"
)
_PEST_QUIET = (
    "cargo test --offline -q -p pest_meta -p pest_generator -p pest_vm -p pest_derive "
    "--features grammar-extras"
)
_PEST_DEFAULT = "cargo test --offline -q -p pest_meta -p pest_generator -p pest_vm -p pest_derive"


def test_pest_b_replay_keeps_uncovered_validation_failures_until_acknowledged() -> None:
    ledger = ObservedLedger()
    ledger.fail("rg -n PUSH_LITERAL pest/src")  # a non-test failure early in the session
    ledger.fail(_PEST_FULL, exit_status=101)  # L123
    ledger.edit()
    full_latest = ledger.fail(_PEST_FULL, exit_status=101)  # L127
    ledger.edit()
    ledger.passes(_PEST_QUIET)  # L133
    red_latest = ledger.fail(_PEST_DEFAULT, exit_status=101)  # L135
    ledger.claim(
        versioned=True, limitations=(full_latest, red_latest)
    )  # L186, disclosed through exact result ids
    assert omissions(ledger) == ()
    assert "hook-observed failing" in receipt_limitations(ledger)


def test_pest_l127_edit_then_quiet_l133_leaves_no_finding() -> None:
    ledger = ObservedLedger()
    failed = ledger.fail(_PEST_FULL, exit_status=101)  # L127
    ledger.edit()
    ledger.passes(_PEST_QUIET)  # L133 adds -q: a different identity
    ledger.claim(versioned=True, limitations=(failed,))
    assert omissions(ledger) == ()


def test_dynamodb_b_replay_red_green_tdd_cycle_is_clean() -> None:
    ledger = ObservedLedger()
    failures: list[ResultId] = []
    for index in range(4):
        failures.append(
            ledger.fail(f"npx vitest run src/schema/attributes/required{index}.unit.test.ts")
        )
    failures.append(ledger.fail("test -f src/schema/actions/dto/getSchemaDTO/any.ts"))
    failures.append(ledger.fail("npm run test-type", exit_status=2))  # L89, TS2322
    failures.append(ledger.fail("npx vitest run src/schema"))
    failures.append(ledger.fail("npm run test-type", exit_status=2))
    failures.append(ledger.fail("npx vitest run src/schema --reporter dot"))
    ledger.edit()  # the repair
    ledger.passes("npm run test-type")
    ledger.passes("npx vitest run src/schema")
    ledger.claim(versioned=True, limitations=tuple(failures))
    assert omissions(ledger) == ()
    limitations = receipt_limitations(ledger)
    assert "hook-observed failing" in limitations


def test_ink_c_replay_keeps_the_final_full_suite_failure_visible_exactly_once() -> None:
    ledger = ObservedLedger()
    initial = ledger.fail("npx ava test/grid.tsx && npm test")  # L109
    ledger.passes(
        "npx prettier --write src/grid-layout.ts && npx ava test/grid.tsx && npm run typecheck"
    )  # L128
    full_suite = ledger.fail("FORCE_COLOR=true npx ava")  # L131, a pre-existing fixture timeout
    ledger.edit()
    ledger.passes("npx ava test/grid.tsx")
    ledger.claim(versioned=True, limitations=(initial, full_suite))  # L240, disclosed structurally
    assert omissions(ledger) == ()
    limitations = receipt_limitations(ledger)
    assert limitations.count(full_suite) == 1
    assert "hook-observed failing" in limitations
    assert "ava" not in limitations and "FORCE_COLOR" not in limitations


# --- results view: recognize the observed run without command text -------------------------------


def test_results_view_names_tool_occurrence_commitment_and_exit_status() -> None:
    from finishup.adapters.memory import ledger as memory_ledger
    from finishup.ports.ledger import ProjectionView
    from finishup.protocol.models import StatusResultItemModel

    ledger = ObservedLedger()
    ledger.passes("pytest -q tests/x.py")
    red = ledger.fail("pytest -q tests/y.py", exit_status=2)
    cooperative = ledger.run(
        "pytest -q tests/y.py", ResultOutcome.SUCCESS, exit_status=0, observed=False
    )
    records = ledger.prefix
    items = memory_ledger._projection_items(  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
        ProjectionView.RESULTS,
        replay(records),
        records,
        task="tsk_00000000-0000-4000-8000-000000000909",
        session="ses_00000000-0000-4000-8000-000000000909",
    )
    by_id = {item.result_id: item for item in items if type(item) is StatusResultItemModel}
    run = by_id[red].observed_run
    assert run is not None
    assert run.occurrence == "2"
    assert run.tool_name == "exec_command"
    assert run.exit_status == 2
    assert run.command_commitment is not None
    # The action's command field also carries the segment and canonical commitments (ADR-045); the
    # results view names only the whole-command commitment.
    assert (
        "omitted:" + run.command_commitment
        == command_identity_for("pytest -q tests/y.py").split(" ", 1)[0]
    )
    # A cooperative result carries no observed run, even when it republishes the commitment.
    assert by_id[cooperative].observed_run is None
    assert "observed_run" not in by_id[cooperative].model_dump(mode="json", exclude_unset=True)
    red_wire = by_id[red].model_dump(mode="json", exclude_unset=True)
    assert red_wire["observed_run"] == {
        "occurrence": "2",
        "tool_name": "exec_command",
        "command_commitment": run.command_commitment,
        "exit_status": 2,
    }
    assert "pytest" not in str(red_wire)


# --- only the latest run of a command identity can be live (#909 review) ----------------------


def test_repeated_red_runs_raise_one_finding_for_the_latest_and_name_the_earlier_as_history() -> (
    None
):
    ledger = ObservedLedger()
    earlier = ledger.fail("pytest -q tests/x.py")
    latest = ledger.fail("pytest -q tests/x.py")
    ledger.claim()
    assert omitted_results(ledger) == (latest,)
    detail = omissions(ledger)[0].candidate.detail
    assert "is the latest" not in detail
    assert f"Observed run: result {latest}" in detail
    limitations = receipt_limitations(ledger)
    assert "1 was rerun later by the same command" in limitations
    assert limitations.count(earlier) == 1 and latest not in limitations
    # A v1.1 claim must name only the latest red run.
    versioned = ObservedLedger()
    versioned.fail("pytest -q tests/x.py")
    last = versioned.fail("pytest -q tests/x.py")
    versioned.claim(limitations=(last,))
    assert omissions(versioned) == ()


def test_repeated_red_runs_then_green_are_clean() -> None:
    ledger = ObservedLedger()
    ledger.fail("pytest -q tests/x.py")
    ledger.fail("pytest -q tests/x.py")
    ledger.passes("pytest -q tests/x.py")
    ledger.claim(versioned=True)
    assert omissions(ledger) == ()
    assert "2 were later passed by the same command" in receipt_limitations(ledger)


def test_a_later_unknown_outcome_keeps_the_failed_run_outstanding() -> None:
    ledger = ObservedLedger()
    failed = ledger.fail("pytest -q tests/x.py")
    ledger.run("pytest -q tests/x.py", ResultOutcome.UNKNOWN)
    ledger.claim()
    assert omitted_results(ledger) == (failed,)


def test_a_successful_rerun_stays_superseded_after_a_later_unknown_outcome() -> None:
    ledger = ObservedLedger()
    failed = ledger.fail("pytest -q tests/x.py")
    ledger.passes("pytest -q tests/x.py")
    ledger.run("pytest -q tests/x.py", ResultOutcome.UNKNOWN)
    ledger.claim(versioned=True)
    assert omissions(ledger) == ()
    assert failed not in omitted_results(ledger)


def test_a_failure_without_command_identity_never_promises_a_rerun_clears_it() -> None:
    ledger = ObservedLedger()
    ledger.fail(None)
    ledger.claim()
    (finding,) = omissions(ledger)
    detail = finding.candidate.detail
    assert "A run without a command commitment keeps its disclosure duty" in detail
    assert "until it passes" not in detail and "is the latest" not in detail


@pytest.mark.parametrize("outcome", [ResultOutcome.UNKNOWN, ResultOutcome.PARTIAL])
def test_an_edit_never_retires_a_failure(outcome: ResultOutcome) -> None:
    """An edit does not prove that a failed validation was covered, whatever its outcome."""

    states = classify_observed_runs(
        (
            _run(1, ResultOutcome.FAILURE, _A),
            _run(2, outcome, None, edit=True),
        )
    )
    assert states["r1"] is ObservedFailureState.LIVE
    ledger = ObservedLedger()
    failed = ledger.fail("npm test")
    edit = ledger.edit(outcome)
    ledger.claim()
    expected = (failed, edit) if outcome is ResultOutcome.PARTIAL else (failed,)
    assert omitted_results(ledger) == expected


def test_a_stream_corrected_unknown_hook_result_is_not_a_claim_limitation() -> None:
    """#1001: the unknown hook copy of a corrected Codex call never mints its own limitation."""

    for outcome, exit_status, expected_limiting in (
        (ResultOutcome.SUCCESS, 0, 0),
        (ResultOutcome.FAILURE, 2, 1),
    ):
        ledger = ObservedLedger()
        unknown = ledger.run("pytest -q tests/test_soc.py", ResultOutcome.UNKNOWN)
        corrected = ledger.correct_outcome(unknown, outcome, exit_status=exit_status)
        ledger.claim()
        limiting = omitted_results(ledger)
        assert unknown not in limiting
        assert len(limiting) == expected_limiting
        if expected_limiting:
            assert limiting == (corrected,)
