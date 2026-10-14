"""Readiness with recorded blockers validates exactly when it is consistent (#977)."""

from __future__ import annotations

from typing import Any

import pytest

from yoetz.protocol.models import StatusClosureReadinessModel

_OBL = "obl_97700000-0000-4000-8000-00000000000{}"
_EVT = "evt_97700000-0000-4000-8000-000000000009"


def _row(index: int) -> dict[str, str]:
    return {
        "obligation_id": _OBL.format(index),
        "blocker_kind": "dependency_unavailable",
        "decision_event_id": _EVT,
    }


def _readiness(
    *, open_count: int, actionable: tuple[str, ...], rows: int | None, standing: bool = True
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "declared_obligation_count": str(max(open_count, 1)),
        "no_obligations_reason": None,
        "open_obligation_count": str(open_count),
        "unanswered_finding_count": "0",
        "receipt_blocking_finding_count": "0",
        "blocking_conditions": ("obligations_open",) if open_count else (),
        "state": "action_required" if actionable else "ready_with_limitations",
        "gap_classification_version": "2",
        "agent_actionable": actionable,
        "standing_limitations": ("obligation_blocked_outside_agent_control",) if standing else (),
        "acknowledged_not_done": (),
        "acknowledged_not_done_count": "0",
    }
    if rows is not None:
        body["blocked_obligations"] = tuple(_row(index) for index in range(rows))
    return body


def test_every_open_obligation_blocked_is_a_standing_disclosure() -> None:
    model = StatusClosureReadinessModel.model_validate(
        _readiness(open_count=2, actionable=(), rows=2)
    )
    assert model.state == "ready_with_limitations"
    assert model.blocked_obligations is not None
    assert [row.blocker_kind for row in model.blocked_obligations] == ["dependency_unavailable"] * 2
    # An earlier 0.3 build omits the list; the shape still validates.
    StatusClosureReadinessModel.model_validate(_readiness(open_count=2, actionable=(), rows=None))


@pytest.mark.parametrize(
    "body",
    [
        # Open obligations dropped from the agent's work without the blocker disclosure.
        _readiness(open_count=2, actionable=(), rows=None, standing=False),
        # Only one of two open obligations is blocked, yet none is listed as work.
        _readiness(open_count=2, actionable=(), rows=1),
        # More blocked rows than open obligations.
        _readiness(open_count=1, actionable=("obligations_open",), rows=2),
    ],
)
def test_inconsistent_blocker_readiness_is_rejected(body: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        StatusClosureReadinessModel.model_validate(body)


def test_a_partial_block_keeps_open_obligations_actionable() -> None:
    model = StatusClosureReadinessModel.model_validate(
        _readiness(open_count=2, actionable=("obligations_open",), rows=1)
    )
    assert model.agent_actionable == ("obligations_open",)
