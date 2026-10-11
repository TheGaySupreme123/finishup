"""The Stop gate and the new readiness work items (tb4n3 RC-6, issue #1029).

Readiness now lists ``check_current_as_of_earlier_frontier`` as work while unclassified
observations bound the receipt, and ``check_not_applicable`` after an observed edit. Neither is a
Stop-gate token: the gate must not become a new way to hold an agent that merely polled status.
A closing review that an observed edit re-armed (``closing_review_required``) is a gate token and
keeps its existing text.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from yoetz.cli.closure_gate import closure_gate_from_readiness


def _readiness(*actionable: str) -> SimpleNamespace:
    return SimpleNamespace(
        state="action_required",
        agent_actionable=actionable,
        open_obligation_count="0",
        acknowledged_obligation_count="0",
        receipt_blocking_finding_count="0",
    )


@pytest.mark.parametrize("token", ("check_current_as_of_earlier_frontier", "check_not_applicable"))
def test_the_new_work_items_alone_never_continue_the_agent(token: str) -> None:
    assert (
        closure_gate_from_readiness(
            _readiness(token),
            frontier_sequence="12",
            frontier_digest="sha256:x",
            observation_pending=False,
        )
        is None
    )


def test_a_rearmed_closing_review_still_continues_the_agent_once() -> None:
    gate = closure_gate_from_readiness(
        _readiness("check_not_applicable", "closing_review_required"),
        frontier_sequence="12",
        frontier_digest="sha256:x",
        observation_pending=False,
    )
    assert gate is not None
    assert "closing review has not run since your last change" in gate.text
    assert "check_not_applicable" not in gate.text
