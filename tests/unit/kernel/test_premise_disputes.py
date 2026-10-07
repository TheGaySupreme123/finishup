"""D7a (#984; L5's D7): surface standing premise disputes once at Stop and on the receipt.

L5's ``finding_todo.standing_premise_disputes`` is imported behind a guard, so these tests
monkeypatch the predicate: it is read as opaque, and a build without it reports nothing.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from builders.observed_runs import ObservedLedger
from yoetz.cli.closure_gate import (
    BLOCKER_RECHECK_ITEM,
    PREMISE_RECHECK_ITEM,
    closure_gate_from_readiness,
)
from yoetz.domain.values import FindingId
from yoetz.kernel import closure_readiness
from yoetz.kernel.closure_readiness import (
    FINDING_PREMISE_DISPUTED_GAP,
    GAP_CLASSIFICATION,
    GapClass,
    closure_readiness_facts,
    derive_closure_readiness,
)
from yoetz.kernel.reducers import replay

_FINDING = FindingId("fnd_00000000-0000-4000-8000-000000000007")


def _facts(monkeypatch: pytest.MonkeyPatch, disputed: tuple[str, ...]) -> object:
    def predicate(state: object) -> tuple[str, ...]:
        del state
        return disputed

    monkeypatch.setattr(closure_readiness, "_standing_premise_disputes", predicate)
    prefix = ObservedLedger().prefix
    return closure_readiness_facts(replay(prefix), prefix)


def test_a_build_without_the_predicate_reports_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(closure_readiness, "_standing_premise_disputes", None)
    assert closure_readiness.premise_disputed_finding_ids(replay(())) == ()

    def broken(state: object) -> tuple[str, ...]:
        raise RuntimeError("predicate failed")

    monkeypatch.setattr(closure_readiness, "_standing_premise_disputes", broken)
    assert closure_readiness.premise_disputed_finding_ids(replay(())) == ()


def test_a_premise_dispute_is_standing_never_work(monkeypatch: pytest.MonkeyPatch) -> None:
    facts = _facts(monkeypatch, (_FINDING, "not-an-id"))
    assert facts.premise_disputed_finding_ids == (_FINDING,)  # type: ignore[attr-defined]
    readiness = derive_closure_readiness((), (), facts, semantic_review_required=False)  # type: ignore[arg-type]
    assert FINDING_PREMISE_DISPUTED_GAP in readiness.standing_limitations
    assert FINDING_PREMISE_DISPUTED_GAP not in readiness.agent_actionable
    assert GAP_CLASSIFICATION[FINDING_PREMISE_DISPUTED_GAP] is GapClass.STANDING_LIMITATION


def _view(**fields: object) -> SimpleNamespace:
    base: dict[str, object] = {
        "state": "ready_with_limitations",
        "agent_actionable": (),
        "standing_limitations": (FINDING_PREMISE_DISPUTED_GAP,),
        "acknowledged_not_done_count": "2",
        "open_obligation_count": "0",
        "receipt_blocking_finding_count": "0",
        "blocked_obligations": (),
    }
    base.update(fields)
    return SimpleNamespace(**base)


def _gate(view: SimpleNamespace, **kwargs: object) -> object:
    return closure_gate_from_readiness(
        view,
        frontier_sequence="9",
        frontier_digest="sha256:" + "0" * 64,
        observation_pending=False,
        **kwargs,  # type: ignore[arg-type]
    )


def test_the_gate_asks_once_about_a_premise_dispute() -> None:
    gate = _gate(_view())
    assert gate is not None
    assert gate.items == (PREMISE_RECHECK_ITEM,)  # type: ignore[attr-defined]
    assert gate.blocker_keys == ("premise:2",)  # type: ignore[attr-defined]
    assert "the reviewer says the task itself requires" in gate.text  # type: ignore[attr-defined]
    assert "a Yoetz limit or a hard result is not a reason" in gate.text  # type: ignore[attr-defined]
    # Asked already: the agent may stop. A new acknowledgement asks again.
    assert _gate(_view(), reasked_blockers=frozenset({"premise:2"})) is None
    assert _gate(_view(acknowledged_not_done_count="3"), reasked_blockers=frozenset({"premise:2"}))
    # Never on a Stop the host already continued this turn.
    assert _gate(_view(), active_stop=True) is None
    # No dispute, nothing to ask.
    assert _gate(_view(standing_limitations=("finding_self_verified",))) is None


def test_the_premise_ask_rides_an_ordinary_gate_and_drops_before_the_recheck() -> None:
    view = _view(
        state="action_required",
        agent_actionable=("obligations_open", "obligation_blocker_unconfirmed"),
        open_obligation_count="1",
        blocked_obligations=(
            SimpleNamespace(
                obligation_id="obl_00000000-0000-4000-8000-000000000001",
                blocker_kind="authority",
                confirmation="claimed",
            ),
        ),
    )
    gate = _gate(view)
    assert gate is not None
    assert PREMISE_RECHECK_ITEM in gate.items  # type: ignore[attr-defined]
    assert BLOCKER_RECHECK_ITEM in gate.items  # type: ignore[attr-defined]
    assert len(gate.text) <= 2_000  # type: ignore[attr-defined]
    assert "premise:2" in gate.blocker_keys  # type: ignore[attr-defined]
