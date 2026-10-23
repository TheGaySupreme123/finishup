"""The check's continuation reads the closure classes, never the to-do state (ADR-046).

A settled basis (a disclosed limitation, a rejection nobody can rule on) keeps the ``open`` to-do
state but is not work: status says "Nothing further to do", so the checklist ``next`` and the
overall continuation must not say "Repair the open findings".
"""

# pyright: reportPrivateUsage=false, reportUnknownLambdaType=false, reportUnknownArgumentType=false

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from builders.policy_cases import finding_record, fnd
from finishup.application.check import build_finding_checklist, build_overall_next
from finishup.domain.findings import FindingKind, ResponseDisposition
from unit.kernel.test_closure_class import (  # pyright: ignore[reportMissingImports]
    _finding,  # pyright: ignore[reportPrivateUsage]
    _one,  # pyright: ignore[reportPrivateUsage]
    _response,  # pyright: ignore[reportPrivateUsage]
    _state,  # pyright: ignore[reportPrivateUsage]
)

# What ``build_overall_next`` reads of a check result once no finding is left for the agent.
_RESULT: Any = SimpleNamespace(
    missing_for_assessment=(),
    totals={"commands": {"live_failed": "0"}},
    coverage=SimpleNamespace(known_gaps=()),
)


def test_reloaded_check_keeps_live_observed_work_without_transient_case_coverage() -> None:
    from builders.observed_runs import ObservedLedger
    from finishup.kernel.observed_failures import observed_event_ids_from_records
    from finishup.kernel.reducers import replay

    ledger = ObservedLedger()
    failed = ledger.fail("pytest tests/unit/test_example.py")
    projection = replay(ledger.prefix)
    result: Any = SimpleNamespace(
        missing_for_assessment=(),
        totals={"commands": {"live_failed": "1"}},
        coverage=SimpleNamespace(known_gaps=("content_unselected",)),
    )
    overall = build_overall_next(
        result,
        build_finding_checklist(projection, attempt_budget=5),
        projection,
        observed_event_ids=observed_event_ids_from_records(ledger.prefix),
    )
    assert overall is not None
    assert (overall.status, overall.action) == ("action_required", "review_recorded_work")
    assert str(failed) in overall.target_refs


def test_a_reasoned_acknowledgement_of_a_limitation_request_is_not_open_work() -> None:
    finding = _finding(1, semantic=True, next_step="state_unresolved_limitation")
    state, closure = _one(finding, ResponseDisposition.ACKNOWLEDGED, reasoned=True)
    assert closure.basis == "limitation_disclosed"
    checklist = build_finding_checklist(state, attempt_budget=5)
    assert [(item.todo_state, item.closure_basis) for item in checklist.items] == [
        ("open", "limitation_disclosed")
    ]
    assert checklist.next == "request_receipt"


def test_a_pending_limitation_request_is_something_to_disclose() -> None:
    """Owner decision 2026-10-12: when it is the only remaining agent work the continuation has
    its own value, so the JSON and the text agree and nothing says "repair"."""

    finding = _finding(1, semantic=True, next_step="state_unresolved_limitation")
    state, closure = _one(finding)
    assert closure.basis == "limitation_requested"
    checklist = build_finding_checklist(state, attempt_budget=5)
    assert checklist.next == "disclose_limitations"
    overall = build_overall_next(_RESULT, checklist, state)
    assert overall is not None
    assert (overall.status, overall.action) == ("action_required", "disclose_limitations")
    assert overall.target_refs == (str(fnd(1)),)


def test_a_limitation_request_beside_real_work_keeps_work_open_findings() -> None:
    limitation = _finding(1, semantic=True, next_step="state_unresolved_limitation")
    work = _finding(2, semantic=True, next_step="act")
    state = _state(
        {fnd(1): finding_record(limitation, 4), fnd(2): finding_record(work, 5)},
    )
    checklist = build_finding_checklist(state, attempt_budget=5)
    assert checklist.next == "work_open_findings"
    overall = build_overall_next(_RESULT, checklist, state)
    assert overall is not None
    assert overall.action == "work_open_findings"
    # Both are named, so the text can say how each is answered.
    assert overall.target_refs == (str(fnd(1)), str(fnd(2)))


def test_a_limitation_request_to_disclose_outranks_a_ruling_to_request() -> None:
    """The agent can disclose now; the ruling needs a check after it: disclose first."""

    limitation = _finding(1, semantic=True, next_step="state_unresolved_limitation")
    rejected = _finding(2, semantic=True, next_step="act")
    state = _state(
        {fnd(1): finding_record(limitation, 4), fnd(2): finding_record(rejected, 5)},
        {fnd(2): _response(2, ResponseDisposition.REJECTED, reasoned=True)},
    )
    checklist = build_finding_checklist(state, attempt_budget=5)
    assert checklist.next == "disclose_limitations"
    overall = build_overall_next(_RESULT, checklist, state)
    assert overall is not None and overall.action == "disclose_limitations"


def test_the_agents_own_criterion_is_work_to_fix_or_narrow_never_disclose_only() -> None:
    """Review of #1043: ``agent_criterion_unmet`` reads ``limitation_requested`` with next actions
    ``acknowledge`` and ``repair``. Its probe demonstrably fails, so "disclose the limitation, no
    repair is needed" would steer an honest agent to ``acknowledged_not_done``: alone, beside a
    reviewer's limitation request or a ruling to request, it is work (fix it, or narrow it)."""

    criterion = _finding(1, kind=FindingKind.AGENT_CRITERION_UNMET, semantic=True, next_step="act")
    state, closure = _one(criterion)
    assert (closure.basis, closure.next_actions) == (
        "limitation_requested",
        ("acknowledge", "repair"),
    )
    checklist = build_finding_checklist(state, attempt_budget=5)
    assert checklist.next == "work_open_findings"
    overall = build_overall_next(_RESULT, checklist, state)
    assert overall is not None
    assert (overall.status, overall.action) == ("action_required", "work_open_findings")
    assert overall.target_refs == (str(fnd(1)),)

    limitation = _finding(2, semantic=True, next_step="state_unresolved_limitation")
    rejected = _finding(3, semantic=True, next_step="act")
    mixed = _state(
        {
            fnd(1): finding_record(criterion, 4),
            fnd(2): finding_record(limitation, 5),
            fnd(3): finding_record(rejected, 6),
        },
        {fnd(3): _response(3, ResponseDisposition.REJECTED, reasoned=True)},
    )
    checklist = build_finding_checklist(mixed, attempt_budget=5)
    assert checklist.next == "work_open_findings"
    overall = build_overall_next(_RESULT, checklist, mixed)
    assert overall is not None and overall.action == "work_open_findings"
    assert overall.target_refs == (str(fnd(1)), str(fnd(2)))

    # Narrowed with a reason, it is settled and nothing is left to do.
    narrowed, closure = _one(criterion, ResponseDisposition.ACKNOWLEDGED, reasoned=True)
    assert closure.basis == "limitation_disclosed"
    assert build_finding_checklist(narrowed, attempt_budget=5).next == "request_receipt"


def test_a_limitation_request_answered_not_done_is_settled_unmet_not_work_to_disclose() -> None:
    """The answer decides: "not done" says the requirement is not met, so there is nothing left
    for the agent to disclose and the receipt keeps ``unresolved_findings_remain``."""

    finding = _finding(1, semantic=True, next_step="state_unresolved_limitation")
    state, closure = _one(finding, ResponseDisposition.ACKNOWLEDGED_NOT_DONE, reasoned=True)
    assert closure.basis == "limitation_acknowledged_not_done"
    checklist = build_finding_checklist(state, attempt_budget=5)
    assert checklist.next == "request_receipt"
    assert checklist.closure_counts is not None
    assert (checklist.closure_counts.unmet, checklist.closure_counts.disclosed) == (1, 0)
    overall = build_overall_next(_RESULT, checklist, state, predicted_conclusion=None)
    assert overall is not None
    assert (overall.status, overall.action) == ("ready_with_limitations", "request_receipt")


def test_a_rejection_no_reviewer_can_rule_on_is_not_open_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The route cannot dispatch a review (the latest check recorded a durable reason), so the
    # rejection is settled and disclosed: asking the agent to "request a ruling" would be untrue.
    monkeypatch.setattr("finishup.kernel.closure_class.review_can_rule", lambda *a, **k: False)
    finding = _finding(1, semantic=True, next_step="act")
    state, closure = _one(finding, ResponseDisposition.REJECTED, reasoned=True)
    assert closure.basis == "rejected_review_unavailable"
    checklist = build_finding_checklist(state, attempt_budget=5)
    assert [(item.todo_state, item.closure_basis) for item in checklist.items] == [
        ("open", "rejected_review_unavailable")
    ]
    assert checklist.next == "request_receipt"


def test_whole_task_readiness_prevents_a_finding_only_receipt_invitation() -> None:
    from dataclasses import replace

    from builders.policy_cases import plan_record
    from finishup.domain.events import PlanPublishedPayload

    state, _ = _one(_finding(1), ResponseDisposition.SELF_VERIFIED, reasoned=True)
    # A plan row supplies a structural target for the task-level instruction.
    state = replace(state, plans={1: plan_record(PlanPublishedPayload(1, "Plan", ()), 2)})
    checklist = build_finding_checklist(state, attempt_budget=5)
    assert checklist.next == "request_receipt"
    overall = build_overall_next(
        _RESULT,
        checklist,
        state,
        readiness=SimpleNamespace(
            state="action_required", agent_actionable=("edited_after_last_verification",)
        ),
    )
    assert overall is not None
    assert (overall.status, overall.action) == ("action_required", "review_recorded_work")
