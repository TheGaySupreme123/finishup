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
    VerificationExpectedFrom,
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
    verification_coverage_lines,
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
from finishup.kernel.verification_freshness import VerificationFreshness
from finishup.protocol.canonical import canonical_digest
from finishup.protocol.errors import ProtocolValueError
from finishup.protocol.models import StatusVerificationCoverageModel

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
        test_file=test_file,
        results_file=None if test_file is None else "results.json",
        report_digest=None if test_file is None else "sha256:" + "a" * 64,
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


_TWO_CRITERIA = "The ratio must be at most 1.06. The labels must be saved."


def _with_acceptance(projection: ProjectionState, text: str) -> ProjectionState:
    row = projection.obligations[_OBLIGATION]
    assert row.payload is not None
    obligation = replace(row.payload, acceptance_criteria=text)
    return replace(
        projection,
        obligations={
            _OBLIGATION: replace(
                row, payload=obligation, payload_digest=canonical_digest(encode_payload(obligation))
            )
        },
    )


@pytest.mark.parametrize("quote", [".", "a", "must", "must be", "at most 1"])
def test_generic_quote_cannot_erase_other_criteria(quote: str) -> None:
    view = build_verification_coverage(
        _projection(_run(1, source="task_public", quote=quote), statement=_TWO_CRITERIA)
    )
    gaps = {row.criterion_quote for row in view.criteria if "no_test" in row.flags}
    assert gaps == {"The ratio must be at most 1.06.", "The labels must be saved."}
    assert view.omitted_criteria == 0
    # The generic declaration remains visible as its own row; it maps no stated criterion.
    assert [row.criterion_quote for row in view.criteria if row.witnesses] == [quote]


@pytest.mark.parametrize(
    "quote",
    [
        _TWO_CRITERIA,
        "The ratio must be at most 1.06. The labels must be saved",
        "at most 1.06. The labels",
    ],
)
def test_cross_sentence_quote_keeps_the_second_criterion_gap(quote: str) -> None:
    view = build_verification_coverage(
        _projection(_run(1, source="task_public", quote=quote), statement=_TWO_CRITERIA)
    )
    assert ("The labels must be saved.", ("no_test",)) in [
        (row.criterion_quote, row.flags) for row in view.criteria
    ]
    assert [row.criterion_quote for row in view.criteria if row.witnesses] == [quote]


def test_specific_quote_maps_only_the_criterion_it_identifies() -> None:
    view = build_verification_coverage(
        _projection(
            _run(1, source="task_public", quote="ratio must be at most 1.06"),
            statement=_TWO_CRITERIA,
        )
    )
    assert [(row.criterion_quote, row.flags) for row in view.criteria] == [
        ("The labels must be saved.", ("no_test",)),
        ("ratio must be at most 1.06", ("public_only",)),
    ]
    # A partial word or a number prefix is not an occurrence, so it maps nothing.
    for partial in ("atio must be at most 1", "1.0"):
        rows = build_verification_coverage(
            _projection(_run(1, quote=partial), statement=_TWO_CRITERIA)
        ).criteria
        assert sum("no_test" in row.flags for row in rows) == 2
    # A quote that occurs in two criteria identifies neither; both gaps remain.
    repeated = "The ratio must be at most 1.06 on A. The ratio must be at most 1.10 on B."
    rows = build_verification_coverage(
        _projection(_run(1, quote="The ratio must be at most"), statement=repeated)
    ).criteria
    assert sum("no_test" in row.flags for row in rows) == 2


@pytest.mark.parametrize(
    "sentence",
    [
        "The inelastic labels are correct.",
        "The function returns the ratio.",
        "Outputs match the reference.",
        "Each label is saved.",
        "Write and label the report.",
    ],
)
def test_inflected_condition_words_propose_a_criterion(sentence: str) -> None:
    view = build_verification_coverage(_projection(statement=f"Background only here. {sentence}"))
    assert [(row.criterion_quote, row.flags) for row in view.criteria] == [(sentence, ("no_test",))]


def test_descriptive_past_tense_prose_proposes_no_criterion() -> None:
    # #1170 review: a past tense or participle describes what happened; alone it is no gap.
    statement = (
        "The repository was written in Python. Dependencies are listed in requirements.txt. "
        "The report was saved and labelled. The ratio must be at most 1.06."
    )
    view = build_verification_coverage(_projection(statement=statement))
    assert [row.criterion_quote for row in view.criteria if row.source == "task_statement"] == [
        "The ratio must be at most 1.06."
    ]


def test_a_partial_quote_keeps_the_rest_of_a_compound_sentence_visible() -> None:
    # #1170 review: a ratio witness must not make the labels requirement in its sentence vanish.
    statement = (
        "Use the provided reactor data. "
        "The labels must be saved to labels.csv and the ratio must be at most 1.06."
    )
    view = build_verification_coverage(
        _projection(_run(1, quote="ratio must be at most 1.06"), statement=statement)
    )
    rows = {row.criterion_quote: row for row in view.criteria if row.source == "task_statement"}
    sentence = "The labels must be saved to labels.csv and the ratio must be at most 1.06."
    assert rows[sentence].flags == ("no_test",)
    assert rows["ratio must be at most 1.06"].witnesses
    # A second witness for the remaining clause retires the sentence; a bare quantifier left
    # outside the quote ("For every input, ...") qualifies it and is not a further criterion.
    both = build_verification_coverage(
        _projection(
            _run(1, quote="ratio must be at most 1.06"),
            _run(2, quote="labels must be saved to labels.csv"),
            statement=statement,
        )
    )
    assert sentence not in {row.criterion_quote for row in both.criteria}


def test_an_obligation_restating_a_task_criterion_is_the_same_criterion() -> None:
    # #1170 review: the restatement must not turn the tested task criterion back into a gap,
    # and an identical (recased, re-ended) restatement is one row with the task source.
    statement = "The ratio must be at most 1.06. The labels must be saved."
    restated = build_verification_coverage(
        _with_acceptance(
            _projection(_run(1, quote="ratio must be at most 1.06"), statement=statement),
            "The ratio must be at most 1.06 for every scenario.",
        )
    )
    gaps = {row.criterion_quote for row in restated.criteria if "no_test" in row.flags}
    assert gaps == {"The labels must be saved."}
    same = build_verification_coverage(
        _with_acceptance(_projection(statement=statement), "the ratio must be at most 1.06")
    )
    assert [(row.criterion_quote, row.source) for row in same.criteria] == [
        ("The labels must be saved.", "task_statement"),
        ("The ratio must be at most 1.06.", "task_statement"),
    ]


def test_a_sentence_longer_than_a_quote_is_counted_not_dropped() -> None:
    long = (
        "The exported predictions file must contain one row per scenario with the scenario id, "
        "the predicted ratio, the lower and upper bounds of the 95% interval, and the label "
        "assigned by the classifier, and every predicted ratio must be within 6% of the "
        "reference value."
    )
    assert len(long) > 240
    view = build_verification_coverage(_projection(statement=f"{long} The labels must be saved."))
    assert [row.criterion_quote for row in view.criteria if row.source == "task_statement"] == [
        "The labels must be saved."
    ]
    assert view.omitted_criteria == 1


def test_an_amended_task_does_not_keep_an_obsolete_quote_inside_a_longer_number() -> None:
    view = build_verification_coverage(
        _projection(
            _run(1, quote="error must be at most 0.1"),
            statement="Each error must be at most 0.15 mm.",
        )
    )
    assert not any(row.witnesses for row in view.criteria)
    assert [
        (row.criterion_quote, row.flags) for row in view.criteria if row.source == "task_statement"
    ] == [("Each error must be at most 0.15 mm.", ("no_test",))]


def test_obligation_prose_cannot_evict_the_task_gap_from_the_display_bound() -> None:
    notes = " ".join(f"Note {index} is background." for index in range(30))
    view = build_verification_coverage(
        _with_acceptance(_projection(statement="The ratio must be at most 1.06."), notes)
    )
    assert view.criteria[0].criterion_quote == "The ratio must be at most 1.06."
    assert view.criteria[0].source == "task_statement"
    assert len(view.criteria) == 24 and view.omitted_criteria == 7
    # A failing obligation-backed row still leads; a task witness is not hidden by notes.
    tested = build_verification_coverage(
        _with_acceptance(
            _projection(
                _run(1, source="task_public", quote="The ratio must be at most 1.06."),
                statement="The ratio must be at most 1.06. The labels must be saved.",
            ),
            notes,
        )
    )
    assert [row.criterion_quote for row in tested.criteria[:2]] == [
        "The labels must be saved.",
        "The ratio must be at most 1.06.",
    ]
    assert tested.omitted_criteria == 8


def test_quote_in_task_and_obligation_keeps_the_task_source() -> None:
    view = build_verification_coverage(_with_acceptance(_projection(_run(1)), _QUOTE))
    assert [(row.criterion_quote, row.source) for row in view.criteria] == [
        (_QUOTE, "task_statement")
    ]
    wire = verification_coverage_to_json(view)
    rows = wire["criteria"]
    assert isinstance(rows, list) and isinstance(rows[0], dict)
    assert rows[0]["task_criterion_quote"] == _QUOTE


def test_tuned_public_cases_render_as_two_independent_axes() -> None:
    view = build_verification_coverage(_projection(_run(1, source="task_public", tuned=True)))
    text = "\n".join(verification_coverage_lines(view))
    assert "only own-generated or tuned-on cases, only task-public cases" in text
    assert "tuned on these cases" in text
    wire_text = "\n".join(verification_coverage_wire_lines(verification_coverage_to_json(view)))
    assert "only own-generated or tuned-on cases, only task-public cases" in wire_text


@pytest.mark.parametrize(
    ("sentence", "quote"),
    [
        (
            "The ratio must be at most 1.06 and the error is at most 2 mm.",
            "ratio must be at most 1.06",
        ),
        (
            "The ratio must be at most 1.06 and the error is ≤ 2 mm.",
            "ratio must be at most 1.06",
        ),
        (
            "Every response includes a timestamp and each identifier is unique.",
            "response includes a timestamp",
        ),
    ],
)
def test_partial_quote_keeps_unwitnessed_quantified_conditions(sentence: str, quote: str) -> None:
    view = build_verification_coverage(_projection(_run(1, quote=quote), statement=sentence))
    gaps = {row.criterion_quote for row in view.criteria if "no_test" in row.flags}
    assert sentence in gaps
    assert any(row.witnesses for row in view.criteria)


@pytest.mark.parametrize(
    "statement",
    [
        "For every input, the ratio must be at most 1.06.",
        "Every ratio must be at most 1.06.",
    ],
)
def test_quantified_context_of_a_witness_is_not_a_separate_gap(statement: str) -> None:
    view = build_verification_coverage(
        _projection(_run(1, quote="ratio must be at most 1.06"), statement=statement)
    )
    assert not any("no_test" in row.flags for row in view.criteria)


def test_exact_task_quote_also_maps_its_longer_obligation_restatement() -> None:
    statement = "The ratio must be at most 1.06"
    view = build_verification_coverage(
        _with_acceptance(
            _projection(_run(1, quote=statement), statement=statement),
            statement + " for every scenario.",
        )
    )
    assert not any("no_test" in row.flags for row in view.criteria)
    assert len(view.criteria) == 1


@pytest.mark.parametrize("tracked", [False, True])
@pytest.mark.parametrize("state", [None, "stale", "unknown"])
def test_frozen_missing_row_means_current_only_for_a_judged_run(
    tracked: bool, state: str | None
) -> None:
    projection = _projection(_run(1))
    ref = next(iter(projection.results))
    rows = () if state is None else (VerificationFreshness(ref, state, (), ()),)
    view = build_verification_coverage(
        projection, freshness=rows, tracked_runs=(ref,) if tracked else ()
    )
    witness = view.criteria[0].witnesses[0]
    expected = (state or "current") if tracked else "legacy"
    assert witness.freshness == expected
    assert witness.stale is (expected == "stale")
    wire = verification_coverage_to_json(view)
    assert verification_coverage_from_json(wire) == view
    assert (
        f"freshness={expected}" in "\n".join(verification_coverage_wire_lines(wire))
        if tracked
        else "legacy latest-edit candidate" in "\n".join(verification_coverage_wire_lines(wire))
    )


def test_frozen_tracking_without_freshness_cannot_assert_current() -> None:
    projection = _projection(_run(1))
    ref = next(iter(projection.results))
    view = build_verification_coverage(projection, freshness=None, tracked_runs=(ref,))
    assert view.criteria[0].witnesses[0].freshness == "legacy"


def test_issued_coverage_receipts_without_freshness_roundtrip_without_backfill() -> None:
    view = build_verification_coverage(_projection(_run(1)))
    criterion = view.criteria[0]
    legacy = replace(
        view,
        criteria=(
            replace(criterion, witnesses=(replace(criterion.witnesses[0], freshness=None),)),
        ),
    )
    wire = verification_coverage_to_json(legacy)
    assert verification_coverage_to_json(verification_coverage_from_json(wire)) == wire
    assert "freshness=" not in "\n".join(verification_coverage_lines(legacy))
    assert "legacy latest-edit candidate" not in "\n".join(verification_coverage_wire_lines(wire))


@pytest.mark.parametrize(
    ("state", "stale"),
    [("unknown", True), ("current", True), ("stale", False), ("invented", False)],
)
def test_freshness_witness_rejects_contradictory_stale_boolean(state: str, stale: bool) -> None:
    witness = build_verification_coverage(_projection(_run(1))).criteria[0].witnesses[0]
    with pytest.raises(ProtocolValueError):
        replace(witness, freshness=state, stale=stale)


def _tagged(
    run: tuple[ActionRecordedPayload, ResultRecordedPayload], checks: str, expected_from: str
) -> tuple[ActionRecordedPayload, ResultRecordedPayload]:
    action, result = run
    assert result.verification is not None
    manifest = replace(
        result.verification,
        checks=checks,
        expected_from=VerificationExpectedFrom(expected_from),
    )
    return action, replace(result, verification=manifest)


def test_declared_checks_and_expected_from_reach_the_witness_without_changing_flags() -> None:
    # Issue #1219: display-only declarations. Flags, counts, ordering and the selected witnesses
    # are the same with and without them, and the untagged wire keeps its earlier keys.
    plain_runs = (_run(1, failing=6, source="own_generated"), _run(2, command="python oracle.py"))
    tagged_runs = (
        _tagged(plain_runs[0], "parses every named date", "implementation_output"),
        _tagged(plain_runs[1], "an  independent\noracle", "independent_source"),
    )
    plain = build_verification_coverage(_projection(*plain_runs))
    tagged = build_verification_coverage(_projection(*tagged_runs))
    strip = [
        replace(
            row,
            witnesses=tuple(
                replace(item, checks=None, expected_from=None) for item in row.witnesses
            ),
        )
        for row in tagged.criteria
    ]
    assert tuple(strip) == plain.criteria
    witnesses = tagged.criteria[0].witnesses
    assert [(item.expected_from, item.checks) for item in witnesses] == [
        ("independent_source", "an  independent\noracle"),
        ("implementation_output", "parses every named date"),
    ]
    plain_wire = verification_coverage_to_json(plain)
    assert "checks" not in str(plain_wire) and "expected_from" not in str(plain_wire)
    wire = verification_coverage_to_json(tagged)
    assert verification_coverage_to_json(verification_coverage_from_json(wire)) == wire
    StatusVerificationCoverageModel.model_validate(wire)
    local = "\n".join(verification_coverage_lines(tagged))
    assert "expected from independent source; checks=an independent oracle" in local
    exported = "\n".join(verification_coverage_lines(tagged, include_content=False))
    assert "expected from implementation output" in exported
    assert "parses every named date" not in exported
    rows = wire["criteria"]
    assert isinstance(rows, list) and isinstance(rows[0], dict)
    first = rows[0]["witnesses"]
    assert isinstance(first, list) and isinstance(first[0], dict)
    first[0]["checks"] = {"omitted": True, "category": "command_metadata", "reason": "not_selected"}
    projected = "\n".join(verification_coverage_wire_lines(wire))
    assert "independent oracle" not in projected
    assert "checks text withheld" in projected
    assert "checks=parses every named date" in projected
    first[0]["expected_from"] = "from_memory"
    with pytest.raises(ValueError):
        StatusVerificationCoverageModel.model_validate(wire)
