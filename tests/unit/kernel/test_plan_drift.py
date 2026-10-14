"""Plan drift remains an explicit, conservative coverage signal."""

from __future__ import annotations

from types import SimpleNamespace

from builders.policy_cases import (
    act,
    evt,
    make_case,
    obl,
    obligation_record,
    plan_record,
    record,
    res,
)
from yoetz.domain.events import (
    AcceptedEvent,
    ActionKind,
    ActionRecordedPayload,
    EventSchema,
    ObligationChange,
    ObligationChangeKind,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
    PlanRevisedPayload,
    RedactionState,
    ResultOutcome,
    ResultRecordedPayload,
)
from yoetz.domain.values import event_id
from yoetz.kernel.plan_drift import (
    INSTRUCTION_REQUIREMENT_UNMAPPED_GAP,
    OBLIGATION_EVIDENCE_STALE_AFTER_SCOPE_EDIT_GAP,
    PLAN_UNREFINED_BEFORE_FIRST_EDIT_GAP,
    plan_drift_signals,
)


def _accepted(payload: object, sequence: int, *, schema_name: str) -> AcceptedEvent:
    """Build the small accepted-record view used by plan-drift's frontier-only logic."""

    record = object.__new__(AcceptedEvent)
    object.__setattr__(record, "payload", payload)
    object.__setattr__(record, "ledger", SimpleNamespace(ingestion_sequence=sequence))
    object.__setattr__(record, "redaction", RedactionState.PRESENT)
    object.__setattr__(record, "schema", EventSchema(schema_name, "1.0.0"))
    object.__setattr__(record, "event_id", evt(sequence))
    return record


def _edit(*, sequence: int, obligation: str | None = None) -> ActionRecordedPayload:
    return ActionRecordedPayload(
        act(sequence),
        ActionKind.EDIT,
        "Edit source",
        obligation_refs=() if obligation is None else (obl(int(obligation)),),
    )


def test_late_legitimate_refinement_clears_the_initial_drift_signal() -> None:
    initial = PlanPublishedPayload(1, "Initial", (obl(1),))
    refinement = PlanRevisedPayload(
        2,
        1,
        "Exploration clarified the scope",
        "Refined",
        (ObligationChange(obl(1), ObligationChangeKind.CARRIED),),
    )
    edit = _edit(sequence=2, obligation="1")
    projection = make_case(
        plans={1: plan_record(initial, 1), 2: plan_record(refinement, 3)},
        actions={act(2): record(edit, 2)},
    ).projection

    signals = plan_drift_signals(
        projection,
        (
            _accepted(initial, 1, schema_name="plan_published"),
            _accepted(edit, 2, schema_name="action_recorded"),
            _accepted(refinement, 3, schema_name="plan_revised"),
        ),
    )

    assert PLAN_UNREFINED_BEFORE_FIRST_EDIT_GAP not in signals.codes


def test_unrefined_plan_before_first_edit_is_reported() -> None:
    plan = PlanPublishedPayload(1, "Initial", (obl(1),))
    edit = _edit(sequence=2, obligation="1")
    projection = make_case(
        plans={1: plan_record(plan, 1)},
        actions={act(2): record(edit, 2)},
    ).projection

    signals = plan_drift_signals(
        projection,
        (
            _accepted(plan, 1, schema_name="plan_published"),
            _accepted(edit, 2, schema_name="action_recorded"),
        ),
    )

    assert PLAN_UNREFINED_BEFORE_FIRST_EDIT_GAP in signals.codes


def test_plan_published_after_the_first_edit_does_not_claim_a_pre_edit_gap() -> None:
    plan = PlanPublishedPayload(1, "Late plan", (obl(1),))
    edit = _edit(sequence=2, obligation="1")
    projection = make_case(
        plans={1: plan_record(plan, 3)},
        actions={act(2): record(edit, 2)},
    ).projection

    signals = plan_drift_signals(
        projection,
        (_accepted(edit, 2, schema_name="action_recorded"),),
    )

    assert PLAN_UNREFINED_BEFORE_FIRST_EDIT_GAP not in signals.codes


def test_late_full_plan_restatement_does_not_count_as_refinement() -> None:
    initial = PlanPublishedPayload(1, "Initial", (obl(1),))
    edit = _edit(sequence=2, obligation="1")
    restatement = PlanPublishedPayload(2, "Restated after editing", (obl(1),))
    projection = make_case(
        plans={1: plan_record(initial, 1), 2: plan_record(restatement, 3)},
        actions={act(2): record(edit, 2)},
    ).projection

    signals = plan_drift_signals(
        projection,
        (
            _accepted(initial, 1, schema_name="plan_published"),
            _accepted(edit, 2, schema_name="action_recorded"),
            _accepted(restatement, 3, schema_name="plan_published"),
        ),
    )

    assert PLAN_UNREFINED_BEFORE_FIRST_EDIT_GAP in signals.codes


def test_stale_resolution_requires_every_evidence_reference_to_be_readable() -> None:
    plan = PlanPublishedPayload(1, "Plan", (obl(1),))
    obligation = ObligationPublishedPayload(
        obl(1),
        "Resolve the obligation",
        "A result",
        ObligationStatus.RESOLVED,
        resolution_evidence_refs=(res(1), res(2)),
    )
    result = ResultRecordedPayload(res(1), act(1), ResultOutcome.SUCCESS)
    edit = _edit(sequence=4, obligation="1")
    projection = make_case(
        plans={1: plan_record(plan, 1)},
        obligations={obl(1): obligation_record(obligation, 2)},
        results={res(1): record(result, 3)},
        actions={act(4): record(edit, 4)},
    ).projection

    signals = plan_drift_signals(
        projection,
        (
            _accepted(plan, 1, schema_name="plan_published"),
            _accepted(obligation, 2, schema_name="obligation_published"),
            _accepted(result, 3, schema_name="result_recorded"),
            _accepted(edit, 4, schema_name="action_recorded"),
        ),
    )

    assert OBLIGATION_EVIDENCE_STALE_AFTER_SCOPE_EDIT_GAP not in signals.codes


def test_unscoped_edit_marks_all_resolved_plan_obligations_stale() -> None:
    plan = PlanPublishedPayload(1, "Plan", (obl(1), obl(2)))
    obligation_one = ObligationPublishedPayload(
        obl(1), "First", "A result", ObligationStatus.RESOLVED, resolution_evidence_refs=(res(1),)
    )
    obligation_two = ObligationPublishedPayload(
        obl(2), "Second", "A result", ObligationStatus.RESOLVED, resolution_evidence_refs=(res(1),)
    )
    result = ResultRecordedPayload(res(1), act(1), ResultOutcome.SUCCESS)
    edit = _edit(sequence=4)
    projection = make_case(
        plans={1: plan_record(plan, 1)},
        obligations={
            obl(1): obligation_record(obligation_one, 2),
            obl(2): obligation_record(obligation_two, 3),
        },
        results={res(1): record(result, 4)},
        actions={act(4): record(edit, 5)},
    ).projection

    signals = plan_drift_signals(
        projection,
        (
            _accepted(plan, 1, schema_name="plan_published"),
            _accepted(obligation_one, 2, schema_name="obligation_published"),
            _accepted(obligation_two, 3, schema_name="obligation_published"),
            _accepted(result, 4, schema_name="result_recorded"),
            _accepted(edit, 5, schema_name="action_recorded"),
        ),
    )

    assert signals.stale_obligation_ids == (obl(1), obl(2))
    assert OBLIGATION_EVIDENCE_STALE_AFTER_SCOPE_EDIT_GAP in signals.codes


def test_later_global_edit_wins_over_an_earlier_scoped_edit() -> None:
    plan = PlanPublishedPayload(1, "Plan", (obl(1), obl(2)))
    obligation_one = ObligationPublishedPayload(
        obl(1), "First", "A result", ObligationStatus.RESOLVED, resolution_evidence_refs=(res(1),)
    )
    obligation_two = ObligationPublishedPayload(
        obl(2), "Second", "A result", ObligationStatus.RESOLVED, resolution_evidence_refs=(res(1),)
    )
    scoped_edit = _edit(sequence=4, obligation="1")
    result = ResultRecordedPayload(res(1), act(1), ResultOutcome.SUCCESS)
    global_edit = _edit(sequence=6)
    projection = make_case(
        plans={1: plan_record(plan, 1)},
        obligations={
            obl(1): obligation_record(obligation_one, 2),
            obl(2): obligation_record(obligation_two, 3),
        },
        results={res(1): record(result, 5)},
        actions={
            act(4): record(scoped_edit, 4),
            act(6): record(global_edit, 6),
        },
    ).projection

    signals = plan_drift_signals(
        projection,
        (
            _accepted(plan, 1, schema_name="plan_published"),
            _accepted(obligation_one, 2, schema_name="obligation_published"),
            _accepted(obligation_two, 3, schema_name="obligation_published"),
            _accepted(scoped_edit, 4, schema_name="action_recorded"),
            _accepted(result, 5, schema_name="result_recorded"),
            _accepted(global_edit, 6, schema_name="action_recorded"),
        ),
    )

    assert signals.stale_obligation_ids == (obl(1), obl(2))
    assert OBLIGATION_EVIDENCE_STALE_AFTER_SCOPE_EDIT_GAP in signals.codes


def test_instruction_mapping_requires_the_exact_statement_event_reference() -> None:
    statement = "Implement the required behavior exactly."
    plan = PlanPublishedPayload(1, "Plan", (obl(1),), task_statement=statement)
    obligation = ObligationPublishedPayload(
        obl(1),
        "Requirement",
        "A result",
        ObligationStatus.OPEN,
        source_refs=(event_id("evt_10000000-0000-4000-8000-000000000099"),),
    )
    projection = make_case(
        plans={1: plan_record(plan, 1)},
        obligations={obl(1): obligation_record(obligation, 2)},
    ).projection

    signals = plan_drift_signals(
        projection,
        (_accepted(plan, 1, schema_name="plan_published"),),
    )

    assert INSTRUCTION_REQUIREMENT_UNMAPPED_GAP in signals.codes
