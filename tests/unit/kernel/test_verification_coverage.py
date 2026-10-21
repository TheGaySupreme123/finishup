"""Advisory coverage witnesses cannot wash out failures or certify a criterion."""

from __future__ import annotations

from dataclasses import replace

import pytest

from builders.observed_runs import ObservedLedger
from finishup.domain.events import (
    ActionKind,
    ActionRecordedPayload,
    EventPayload,
    EventSchema,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
    ResultOutcome,
    ResultRecordedPayload,
    ResultVerification,
    VerificationDataSource,
    encode_payload,
)
from finishup.domain.values import (
    SubjectStateRef,
    action_id,
    event_id,
    obligation_id,
    result_id,
)
from finishup.domain.verification_coverage import (
    verification_coverage_from_json,
    verification_coverage_to_json,
    verification_coverage_wire_lines,
)
from finishup.kernel.observed_failures import observed_event_ids_from_records
from finishup.kernel.projections import (
    ObligationProjectionRecord,
    PlanProjectionRecord,
    ProjectionRecord,
    ProjectionState,
    empty_projection_state,
)
from finishup.kernel.reducers import replay
from finishup.kernel.task_facts import verification_unchanged_actions, workspace_verification_edits
from finishup.kernel.verification_coverage import build_verification_coverage
from finishup.protocol.canonical import canonical_digest

_QUOTE = "Every prediction must meet the bound"
_OBLIGATION = obligation_id("obl_00000000-0000-4000-8000-000000001170")


def _row[T: EventPayload](payload: T, sequence: int) -> ProjectionRecord[T]:
    return ProjectionRecord(
        payload,
        canonical_digest(encode_payload(payload)),
        False,
        event_id(f"evt_00000000-0000-4000-8000-{sequence:012x}"),
        sequence,
    )


def _run(
    number: int,
    *,
    command: str = "python probe.py",
    source: str = "independent",
    cases: int = 100,
    failing: int = 0,
    tuned: bool | None = False,
    state: SubjectStateRef | None = None,
    quote: str = _QUOTE,
    test_file: str | None = None,
) -> tuple[ActionRecordedPayload, ResultRecordedPayload]:
    action = ActionRecordedPayload(
        action_id(f"act_00000000-0000-4000-8000-{number:012x}"),
        ActionKind.COMMAND,
        "Run a discriminating check",
        command=command,
        subject_state=state,
    )
    manifest = ResultVerification(
        quote,
        VerificationDataSource(source),
        cases,
        failing,
        "105.61 mm",
        tuned,
        **(
            {}
            if test_file is None
            else {
                "test_file": test_file,
                "results_file": "results.json",
                "report_digest": "sha256:" + "a" * 64,
            }
        ),
    )
    result = ResultRecordedPayload(
        result_id(f"res_00000000-0000-4000-8000-{number:012x}"),
        action.action_id,
        ResultOutcome.FAILURE if failing else ResultOutcome.SUCCESS,
        verification=manifest,
        subject_state=state,
    )
    return action, result


def _projection(
    *runs: tuple[ActionRecordedPayload, ResultRecordedPayload],
    edit: ActionRecordedPayload | None = None,
    statement: str = _QUOTE,
    gaps: tuple[str, ...] = (),
) -> ProjectionState:
    plan = PlanPublishedPayload(
        1, "Deliver the requested work", (_OBLIGATION,), task_statement=statement
    )
    obligation = ObligationPublishedPayload(
        _OBLIGATION, "Deliver work", "Discriminating check", ObligationStatus.OPEN
    )
    actions = {
        action.action_id: _row(action, 2 * index + 2) for index, (action, _) in enumerate(runs)
    }
    results = {
        result.result_id: _row(result, 2 * index + 3) for index, (_, result) in enumerate(runs)
    }
    frontier = 2 * len(runs) + 4
    if edit is not None:
        actions[edit.action_id] = _row(edit, frontier)
    return replace(
        empty_projection_state(),
        frontier=frontier,
        head_digest="sha256:" + "1" * 64,
        plans={
            1: PlanProjectionRecord(
                **{
                    name: getattr(_row(plan, 1), name)
                    for name in (
                        "payload",
                        "payload_digest",
                        "redacted",
                        "source_event_id",
                        "source_frontier",
                    )
                }
            )
        },
        obligations={
            _OBLIGATION: ObligationProjectionRecord(
                **{
                    name: getattr(_row(obligation, 1), name)
                    for name in (
                        "payload",
                        "payload_digest",
                        "redacted",
                        "source_event_id",
                        "source_frontier",
                    )
                }
            )
        },
        actions=actions,
        results=results,
        coverage_gaps=gaps,
    )


def test_unrelated_success_does_not_erase_latest_failing_cases() -> None:
    view = build_verification_coverage(
        _projection(
            _run(1, failing=6, source="own_generated"),
            _run(2, command="python independent_oracle.py"),
        )
    )
    row = view.criteria[0]
    assert row.unresolved_failing_runs == 1 and "failing_cases" in row.flags
    assert [(item.data_source, item.failing) for item in row.witnesses] == [
        ("independent", 0),
        ("own_generated", 6),
    ]
    # Passing a smaller subset of the same check also cannot clear the larger failing run.
    subset = build_verification_coverage(_projection(_run(1, failing=6), _run(2, cases=5)))
    assert subset.criteria[0].unresolved_failing_runs == 1
    rerun = build_verification_coverage(_projection(_run(1, failing=6), _run(2)))
    assert rerun.criteria[0].unresolved_failing_runs == 0
    opaque = build_verification_coverage(
        _projection(
            _run(1, command="omitted:structural", failing=6),
            _run(2, command="omitted:structural"),
        )
    )
    assert opaque.criteria[0].unresolved_failing_runs == 1
    action, unknown_rerun = _run(2)
    still_failing = build_verification_coverage(
        _projection(
            _run(1, failing=6),
            (action, replace(unknown_rerun, outcome=ResultOutcome.UNKNOWN)),
        )
    )
    assert still_failing.criteria[0].unresolved_failing_runs == 1


@pytest.mark.parametrize(
    ("source", "tuned", "flags"),
    [
        ("task_public", True, {"public_only", "own_or_tuned_only"}),
        ("own_generated", False, {"own_or_tuned_only"}),
        ("held_out", False, set[str]()),
    ],
)
def test_scope_is_limited_without_green_coverage(source: str, tuned: bool, flags: set[str]) -> None:
    view = build_verification_coverage(_projection(_run(1, source=source, tuned=tuned)))
    assert set(view.criteria[0].flags) == flags
    wire = verification_coverage_to_json(view)
    assert wire["label"] == "agent-declared" and wire["advisory"] is True
    assert "covered" not in str(wire)


@pytest.mark.parametrize("frozen_statement", [False, True])
def test_amended_task_drops_old_witness_even_when_an_effective_obligation_retains_the_quote(
    frozen_statement: bool,
) -> None:
    projection = _projection(_run(1))
    obligation_row = projection.obligations[_OBLIGATION]
    assert obligation_row.payload is not None
    obligation = replace(obligation_row.payload, acceptance_criteria=_QUOTE)
    projection = replace(
        projection,
        obligations={
            _OBLIGATION: replace(
                obligation_row,
                payload=obligation,
                payload_digest=canonical_digest(encode_payload(obligation)),
            )
        },
    )
    assert any(row.witnesses for row in build_verification_coverage(projection).criteria)
    amended = "Every output must be sorted"
    if frozen_statement:
        after = build_verification_coverage(projection, task_statement=amended)
    else:
        plan_row = projection.plans[1]
        assert plan_row.payload is not None
        plan = replace(plan_row.payload, task_statement=amended)
        projection = replace(
            projection,
            plans={
                1: replace(
                    plan_row,
                    payload=plan,
                    payload_digest=canonical_digest(encode_payload(plan)),
                )
            },
        )
        after = build_verification_coverage(projection)
    assert any(row.criterion_quote == _QUOTE for row in after.criteria)
    assert all(not row.witnesses for row in after.criteria)


def test_legacy_projection_without_task_statement_can_use_effective_obligation_text() -> None:
    projection = _projection(_run(1))
    plan_row = projection.plans[1]
    obligation_row = projection.obligations[_OBLIGATION]
    assert plan_row.payload is not None and obligation_row.payload is not None
    plan = replace(plan_row.payload, task_statement=None)
    obligation = replace(obligation_row.payload, acceptance_criteria=_QUOTE)
    projection = replace(
        projection,
        plans={
            1: replace(
                plan_row, payload=plan, payload_digest=canonical_digest(encode_payload(plan))
            )
        },
        obligations={
            _OBLIGATION: replace(
                obligation_row,
                payload=obligation,
                payload_digest=canonical_digest(encode_payload(obligation)),
            )
        },
    )
    after = build_verification_coverage(projection)
    assert after.criteria[0].source == "obligation"
    assert after.criteria[0].witnesses


def test_untested_output_is_a_candidate_but_longer_cited_sentence_is_not_a_false_gap() -> None:
    statement = f"For every input, {_QUOTE}. Write the labels."
    decimal = build_verification_coverage(
        _projection(statement="The ratio must be at most 1.06 on every scenario.")
    )
    assert (
        decimal.criteria[0].criterion_quote == "The ratio must be at most 1.06 on every scenario."
    )
    view = build_verification_coverage(_projection(_run(1), statement=statement))
    assert len(view.criteria) == 2
    assert [
        (row.criterion_quote, row.flags) for row in view.criteria if "no_test" in row.flags
    ] == [("Write the labels.", ("no_test",))]
    assert (
        not build_verification_coverage(
            _projection(_run(1), statement="Every output must be sorted")
        )
        .criteria[0]
        .witnesses
    )


@pytest.mark.parametrize(
    ("description", "stale"),
    [
        ("updated solver", True),
        ("Observed edit (tool apply_patch) (write workspace)", True),
        ("Observed edit (tool apply_patch) (write docs)", False),
        ("Observed edit (tool apply_patch) (write scratch)", False),
    ],
)
def test_material_edits_stale_witnesses_but_bookkeeping_and_docs_do_not(
    description: str, stale: bool
) -> None:
    edit = ActionRecordedPayload(
        action_id("act_00000000-0000-4000-8000-000000009999"), ActionKind.EDIT, description
    )
    view = build_verification_coverage(_projection(_run(1), edit=edit))
    assert view.criteria[0].witnesses[0].stale is stale
    assert ("stale" in view.criteria[0].flags) is stale


def test_repeats_require_same_recorded_work_and_redundancy_requires_registered_test() -> None:
    projection = _projection(_run(1), _run(2))
    row = build_verification_coverage(projection).criteria[0]
    assert row.repeated_runs == 1
    assert len(row.witnesses) == 1
    assert (
        not build_verification_coverage(
            replace(
                projection,
                coverage_gaps=("redacted_event:evt_00000000-0000-4000-8000-000000009999",),
            )
        )
        .criteria[0]
        .repeated_runs
    )
    independent = build_verification_coverage(
        _projection(
            _run(1, command="python numerical_oracle.py"),
            _run(2, command="python permutation_check.py"),
        )
    )
    assert independent.criteria[0].redundant_tests == 0
    same_script = build_verification_coverage(
        _projection(
            _run(1, test_file="probe.py"),
            _run(2, command="python ./probe.py", test_file="probe.py"),
        )
    )
    assert same_script.criteria[0].redundant_tests == 1
    # An edit between runs splits the recorded-work generation even without subject digests.
    edited = ActionRecordedPayload(
        action_id("act_00000000-0000-4000-8000-000000009999"), ActionKind.EDIT, "updated solver"
    )
    changed = replace(projection, actions={**projection.actions, edited.action_id: _row(edited, 4)})
    assert build_verification_coverage(changed).criteria[0].repeated_runs == 0


def test_stronger_witness_does_not_reward_case_volume_and_bounds_preserve_failing_count() -> None:
    runs = [_run(1, source="held_out", cases=1)] + [
        _run(number, command=f"python failing_{number}.py", source="own_generated", failing=number)
        for number in range(2, 8)
    ]
    view = build_verification_coverage(_projection(*runs))
    row = view.criteria[0]
    assert row.witnesses[0].data_source == "held_out"
    assert len(row.witnesses) == 3 and row.omitted_witnesses == 4
    assert row.unresolved_failing_runs == 6
    assert verification_coverage_from_json(verification_coverage_to_json(view)) == view


@pytest.mark.parametrize("effect", ["unchanged", "changed", "unavailable"])
@pytest.mark.parametrize("write_scope", ["workspace", None])
def test_trusted_unchanged_workspace_facts_keep_the_same_staleness_as_task_facts(
    effect: str,
    write_scope: str | None,
) -> None:
    ledger = ObservedLedger()
    action, result = _run(100)
    ledger.append(EventSchema("action_recorded", "1.0.0"), action, observed=False)
    ledger.append(EventSchema("result_recorded", "1.1.0"), result, observed=False)
    later = ledger.run(
        "cat saved.json > report.json",
        ResultOutcome.SUCCESS,
        write_scope=write_scope,
        workspace_effect=effect,
    )
    projection = replay(ledger.prefix)
    view = build_verification_coverage(projection, ledger.prefix, task_statement=_QUOTE)
    assert view.criteria[0].witnesses[0].stale is (effect != "unchanged")
    frozen_view = build_verification_coverage(
        projection,
        task_statement=_QUOTE,
        unchanged_action_ids=verification_unchanged_actions(projection, ledger.prefix),
        workspace_verification_edit_frontier=max(
            (
                position
                for position, _ in workspace_verification_edits(
                    projection, observed_event_ids_from_records(ledger.prefix), ledger.prefix
                )
            ),
            default=0,
        ),
    )
    assert frozen_view == view
    if effect == "unchanged":
        ledger.annotate_workspace_effect(later, "changed")
        contradicted = build_verification_coverage(
            replay(ledger.prefix), ledger.prefix, task_statement=_QUOTE
        )
        assert contradicted.criteria[0].witnesses[0].stale is True


def test_projected_text_never_reappears_in_terminal_rendering() -> None:
    wire = verification_coverage_to_json(build_verification_coverage(_projection(_run(1))))
    rows = wire["criteria"]
    assert isinstance(rows, list) and isinstance(rows[0], dict)
    rows[0]["task_criterion_quote"] = {
        "omitted": True,
        "category": "task_description",
        "reason": "not_selected",
    }
    witnesses = rows[0]["witnesses"]
    assert isinstance(witnesses, list) and isinstance(witnesses[0], dict)
    witnesses[0]["worst"] = {
        "omitted": True,
        "category": "command_metadata",
        "reason": "not_selected",
    }
    text = "\n".join(verification_coverage_wire_lines(wire))
    assert _QUOTE not in text and "105.61" not in text
    assert "criterion text withheld" in text and "worst value withheld" in text
