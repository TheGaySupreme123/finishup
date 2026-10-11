"""The check's continuation reads the closure classes, never the to-do state (ADR-046).

A settled basis (a disclosed limitation, a rejection nobody can rule on) keeps the ``open`` to-do
state but is not work: status says "Nothing further to do", so the checklist ``next`` and the
overall continuation must not say "Repair the open findings".
"""

# pyright: reportPrivateUsage=false, reportUnknownLambdaType=false, reportUnknownArgumentType=false

from __future__ import annotations

import pytest

from unit.kernel.test_closure_class import _finding, _one  # pyright: ignore[reportMissingImports]
from yoetz.application.check import build_finding_checklist
from yoetz.domain.findings import ResponseDisposition


def test_a_reasoned_acknowledgement_of_a_limitation_request_is_not_open_work() -> None:
    finding = _finding(1, semantic=True, next_step="state_unresolved_limitation")
    state, closure = _one(finding, ResponseDisposition.ACKNOWLEDGED, reasoned=True)
    assert closure.basis == "limitation_disclosed"
    checklist = build_finding_checklist(state, attempt_budget=5)
    assert [(item.todo_state, item.closure_basis) for item in checklist.items] == [
        ("open", "limitation_disclosed")
    ]
    assert checklist.next == "request_receipt"


def test_a_pending_limitation_request_is_still_something_to_do() -> None:
    finding = _finding(1, semantic=True, next_step="state_unresolved_limitation")
    state, closure = _one(finding)
    assert closure.basis == "limitation_requested"
    checklist = build_finding_checklist(state, attempt_budget=5)
    assert checklist.next == "work_open_findings"


def test_a_rejection_no_reviewer_can_rule_on_is_not_open_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The route cannot dispatch a review (the latest check recorded a durable reason), so the
    # rejection is settled and disclosed: asking the agent to "request a ruling" would be untrue.
    monkeypatch.setattr("yoetz.kernel.closure_class.review_can_rule", lambda *a, **k: False)
    finding = _finding(1, semantic=True, next_step="act")
    state, closure = _one(finding, ResponseDisposition.REJECTED, reasoned=True)
    assert closure.basis == "rejected_review_unavailable"
    checklist = build_finding_checklist(state, attempt_budget=5)
    assert [(item.todo_state, item.closure_basis) for item in checklist.items] == [
        ("open", "rejected_review_unavailable")
    ]
    assert checklist.next == "request_receipt"
