"""The receipt conclusion as one pure function of the closure basis (ADR-046).

The receipt builder picks its label by calling this function and status prints the label by
calling it over the same basis, so these rules are the only place the order is written down.
"""

from __future__ import annotations

import pytest

from builders.policy_cases import fnd, obl
from finishup.domain.findings import CheckVerdict
from finishup.domain.values import Frontier
from finishup.kernel.closure_class import (
    FINDING_BASES,
    OBLIGATION_BASES,
    FindingClosure,
    ObligationClosure,
)
from finishup.kernel.gap_effect import GapContext, gap_effect
from finishup.kernel.receipt_prediction import (
    AppliedCheck,
    ClosureBasis,
    LineageBasis,
    PredictionConclusion,
    predict_receipt_conclusion,
)

_DIGEST = "sha256:" + "4" * 64
_FRONTIER = Frontier(30, _DIGEST)
_CLEAN_CHECK = AppliedCheck(CheckVerdict.NO_ISSUE_DETECTED, 0, True)


def _finding(number: int, basis: str, since: int | None = 6) -> FindingClosure:
    klass, effect = FINDING_BASES[basis]
    return FindingClosure(fnd(number), klass, basis, effect, ("none",), since, (), fnd(number))


def _obligation(number: int, basis: str) -> ObligationClosure:
    klass, effect = OBLIGATION_BASES[basis]
    return ObligationClosure(obl(number), klass, basis, effect, 4, ())


def _basis(
    *,
    findings: tuple[FindingClosure, ...] = (),
    obligations: tuple[ObligationClosure, ...] = (),
    gaps: tuple[str, ...] = (),
    check: AppliedCheck | None = _CLEAN_CHECK,
    lineage: LineageBasis | None = None,
    context: GapContext | None = None,
    **kwargs: object,
) -> ClosureBasis:
    return ClosureBasis(
        _FRONTIER,
        findings,
        obligations,
        tuple(gap_effect(code, context) for code in gaps),
        check,
        lineage,
        **kwargs,  # type: ignore[arg-type]
    )


def test_nothing_unresolved_and_a_clean_check_reads_clean() -> None:
    prediction = predict_receipt_conclusion(_basis())
    assert prediction.conclusion is PredictionConclusion.NO_UNRESOLVED_DETERMINISTIC_FINDINGS
    assert prediction.reasons == () and prediction.reason_total == 0 and not prediction.provisional


def test_disclosed_gaps_and_settled_history_do_not_bound_a_clean_conclusion() -> None:
    prediction = predict_receipt_conclusion(
        _basis(
            findings=(_finding(1, "absence_proved"), _finding(2, "rejection_accepted")),
            obligations=(_obligation(1, "resolved"),),
            gaps=("content_unselected", "capture_handoff_retired"),
        )
    )
    assert prediction.conclusion is PredictionConclusion.NO_UNRESOLVED_DETERMINISTIC_FINDINGS


@pytest.mark.parametrize(
    "basis",
    [
        "open_unanswered",
        "open_answered",
        "rejected_awaiting_ruling",
        "acknowledged_not_done_requirement",
        # A limitation request the agent answered ``acknowledged_not_done`` (decision 2026-10-12).
        "limitation_acknowledged_not_done",
    ],
)
def test_an_open_awaiting_or_unmet_finding_reads_unresolved(basis: str) -> None:
    prediction = predict_receipt_conclusion(_basis(findings=(_finding(1, basis),)))
    assert prediction.conclusion is PredictionConclusion.UNRESOLVED_FINDINGS_REMAIN
    assert prediction.reasons[0].rule == "R2"


@pytest.mark.parametrize(
    "basis",
    [
        "self_verified",
        "disputed_after_rebuttal",
        "limitation_disclosed",
        "limitation_requested",
        "acknowledged_not_done_bookkeeping",
        "rejected_review_unavailable",
    ],
)
def test_a_settled_but_not_clean_finding_caps_the_label_at_insufficient(basis: str) -> None:
    prediction = predict_receipt_conclusion(_basis(findings=(_finding(1, basis),)))
    assert prediction.conclusion is PredictionConclusion.INSUFFICIENT_COVERAGE
    assert prediction.reasons[0].rule == "R3"


@pytest.mark.parametrize(
    "basis",
    [
        "open",
        "blocker_claimed",
        "acknowledged_not_done",
        "blocker_confirmed",
        "externally_evaluated",
    ],
)
def test_an_obligation_that_is_not_done_never_reads_clean(basis: str) -> None:
    prediction = predict_receipt_conclusion(_basis(obligations=(_obligation(1, basis),)))
    assert prediction.conclusion is PredictionConclusion.INSUFFICIENT_COVERAGE
    assert prediction.reasons[0].rule == "R4"


def test_a_missing_completion_scope_outranks_unresolved_findings() -> None:
    prediction = predict_receipt_conclusion(
        _basis(
            findings=(_finding(1, "open_unanswered"),),
            gaps=("completion_scope_undeclared",),
        )
    )
    assert prediction.conclusion is PredictionConclusion.INSUFFICIENT_COVERAGE
    assert [item.rule for item in prediction.reasons][:2] == ["R1", "R2"]


def test_every_rule_that_fires_is_kept_with_the_selecting_one_first() -> None:
    prediction = predict_receipt_conclusion(
        _basis(
            findings=(_finding(1, "open_unanswered"), _finding(2, "self_verified")),
            obligations=(_obligation(1, "acknowledged_not_done"),),
            gaps=("ledger_rejected", "unknown_event"),
            check=AppliedCheck(CheckVerdict.INSUFFICIENT_COVERAGE, 2, False),
        )
    )
    assert prediction.conclusion is PredictionConclusion.UNRESOLVED_FINDINGS_REMAIN
    codes = [item.code for item in prediction.reasons]
    assert codes[0] == "findings_to_do"
    assert set(codes) == {
        "findings_to_do",
        "findings_disclosed",
        "obligations_acknowledged",
        "check_suppressed_findings",
        "check_verdict_insufficient",
        "policy_execution_incomplete",
        "live_gap_bounds",
    }
    live = next(item for item in prediction.reasons if item.code == "live_gap_bounds")
    assert live.count == 2 and live.refs == ("ledger_rejected", "unknown_event")


def test_no_applicable_check_is_the_reason_not_a_second_gap() -> None:
    prediction = predict_receipt_conclusion(_basis(check=None))
    assert prediction.conclusion is PredictionConclusion.INSUFFICIENT_COVERAGE
    assert [item.code for item in prediction.reasons] == ["no_applicable_check"]


def test_a_recorded_action_required_verdict_with_settled_findings_reads_insufficient() -> None:
    """Migration: the old builder raised here; the findings carry the work, the label does not."""

    prediction = predict_receipt_conclusion(
        _basis(
            findings=(_finding(1, "limitation_disclosed"),),
            check=AppliedCheck(CheckVerdict.ACTION_REQUIRED, 0, True),
        )
    )
    assert prediction.conclusion is PredictionConclusion.INSUFFICIENT_COVERAGE


def test_child_findings_and_a_blocking_child_follow_the_receipt_rules() -> None:
    actionable = predict_receipt_conclusion(_basis(lineage=LineageBasis((str(fnd(9)),), True)))
    assert actionable.conclusion is PredictionConclusion.UNRESOLVED_FINDINGS_REMAIN
    blocking = predict_receipt_conclusion(_basis(lineage=LineageBasis((), True)))
    assert blocking.conclusion is PredictionConclusion.INSUFFICIENT_COVERAGE


def test_a_pending_dependency_or_running_check_makes_the_prediction_provisional() -> None:
    assert predict_receipt_conclusion(_basis(check_in_flight=True)).provisional
    assert predict_receipt_conclusion(
        _basis(live_blockers=("lineage_manifest_not_recorded",))
    ).provisional


def test_reasons_are_bounded_and_the_total_is_kept() -> None:
    prediction = predict_receipt_conclusion(
        _basis(
            findings=tuple(_finding(n, "open_unanswered") for n in range(1, 6)),
            gaps=("ledger_rejected",),
        )
    )
    first = prediction.reasons[0]
    assert first.count == 5 and len(first.refs) == 3
    assert prediction.reason_total == len(prediction.reasons)


@pytest.mark.parametrize("application_states", (True, False))
@pytest.mark.parametrize("kind_name", ("ledger_stale_or_incomplete", "decision_needed"))
def test_a_self_verified_process_note_predicts_the_issued_conclusion(
    kind_name: str, application_states: bool
) -> None:
    """D8 (#1243): the prediction is the conclusion the receipt issues, and it stays clean.

    The predictor read the closures (which leave a process note out) while the receipt's terminal
    lists read kind-blind flags, so status predicted clean and the receipt refused.
    """

    from finishup.domain.findings import FindingKind
    from finishup.kernel.receipt_builder import predict_context_conclusion
    from unit.kernel import test_receipt_builder as builder_tests

    context = builder_tests._self_verified_context(  # pyright: ignore[reportPrivateUsage]
        FindingKind(kind_name), application_states=application_states
    )
    predicted = predict_context_conclusion(context)
    issued = builder_tests._build_current(context)  # pyright: ignore[reportPrivateUsage]
    assert predicted.conclusion is PredictionConclusion.NO_UNRESOLVED_DETERMINISTIC_FINDINGS
    assert predicted.reasons == ()
    assert issued.conclusion.value == predicted.conclusion.value
