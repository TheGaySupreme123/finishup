"""The check's in-check follow-up loop and its facade seam (issue #1047).

``check._review_follow_up`` re-asks the reviewer only while it concludes ``insufficient_packet``
and names content Yoetz holds, at most ``MAX_REVIEW_FOLLOW_UP_ROUNDS`` times; the last round's
outcome is the check's. The service facade forwards a follow-up only to an evaluator that names
the keyword itself, so every older evaluator keeps today's single review.
"""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any, cast

import pytest

from builders.dialogue import provenance
from builders.policy_cases import FRONTIER, act, evd, res
from unit.application.test_review_follow_up import (
    _verification_case,  # pyright: ignore[reportPrivateUsage]
)
from yoetz.application.check import (
    FinalSemanticEvaluation,
    _review_follow_up,  # pyright: ignore[reportPrivateUsage]
)
from yoetz.application.missing_for_assessment import ReviewFollowUp, ReviewFollowUpItem
from yoetz.application.service import Application
from yoetz.kernel.deterministic_checks import DeterministicCase
from yoetz.ports.ledger import CheckPhase, FrozenCase, OperationLease
from yoetz.ports.semantic import MissingForAssessment, SemanticJudgment
from yoetz.protocol.models import MAX_REVIEW_FOLLOW_UP_ROUNDS, SemanticReason, SemanticStatus

pytestmark = pytest.mark.anyio

_LEASE = OperationLease(
    "wri_10000000-0000-4000-8000-000000000001",
    "req_10000000-0000-4000-8000-000000000001",
    "ses_10000000-0000-4000-8000-000000000001",
    CheckPhase.SEMANTIC_WAIT,
    "owner-generation-1",
    "lease-owner-1",
    1,
    datetime(2030, 1, 1, tzinfo=UTC),
    FRONTIER,
    "sha256:" + "d" * 64,
)
_REQUEST = SimpleNamespace(
    final_review=False, request_id="req_10000000-0000-4000-8000-000000000001"
)


def _insufficient() -> SemanticJudgment:
    return SemanticJudgment(
        "insufficient_packet",
        (),
        missing_for_assessment=(
            MissingForAssessment("verification_output", (str(res(1)),), "The first failure."),
        ),
    )


def _evaluation(
    judgment: SemanticJudgment, excerpts: frozenset[str], case: DeterministicCase
) -> FinalSemanticEvaluation:
    allowed = frozenset(str(ref) for ref in case.allowed_ids)
    return FinalSemanticEvaluation(
        SemanticStatus.SUCCEEDED,
        SemanticReason.SEMANTIC_COMPLETED,
        judgment=judgment,
        provenance=provenance(),
        operation_lease=_LEASE,
        case_citable_refs=allowed,
        case_withheld_refs=frozenset({str(evd(1))}),
        case_excerpt_refs=excerpts,
    )


class _ScriptedReviewer:
    """An evaluator seam that answers each follow-up from a script, recording what it got."""

    def __init__(self, case: DeterministicCase, answers: list[object]) -> None:
        self.case = case
        self.answers = answers
        self.follow_ups: list[ReviewFollowUp] = []

    async def evaluate_semantic_check(
        self,
        frozen: FrozenCase,
        deterministic_findings: tuple[object, ...],
        runtime: object | None = None,
        lineage_evaluation: object | None = None,
        require_complete_specification: bool = False,
        final_review: bool = False,
        task_fact_gaps: tuple[str, ...] = (),
        follow_up: ReviewFollowUp | None = None,
    ) -> object:
        del frozen, deterministic_findings, runtime, lineage_evaluation
        del require_complete_specification, final_review, task_fact_gaps
        assert follow_up is not None
        self.follow_ups.append(follow_up)
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer


async def _loop(app: object, case: DeterministicCase, first: FinalSemanticEvaluation) -> object:
    return await _review_follow_up(
        cast(Any, app),
        cast(Any, _REQUEST),
        cast(Any, object()),
        FrozenCase(case, _LEASE),
        (),
        first,
        lineage_evaluation=None,
        require_complete_specification=False,
        task_fact_gaps=(),
    )


async def test_rounds_stop_at_the_bound_while_each_still_adds_something() -> None:
    case, _refs = _verification_case(20)
    first = _evaluation(_insufficient(), frozenset(), case)
    # Each round shows one more requested row, and the reviewer still asks for more.
    rounds = [
        _evaluation(_insufficient(), frozenset({str(res(1))}), case),
        _evaluation(_insufficient(), frozenset({str(res(1)), str(act(1))}), case),
        _evaluation(_insufficient(), frozenset({str(res(1)), str(act(1)), str(evd(1))}), case),
    ]
    app = _ScriptedReviewer(case, list(rounds))

    result = await _loop(app, case, first)

    assert result is rounds[-1]
    assert (
        [item.round for item in app.follow_ups]
        == [1, 2, 3]
        == list(range(1, MAX_REVIEW_FOLLOW_UP_ROUNDS + 1))
    )
    assert [item.added_refs for item in app.follow_ups] == [
        frozenset(),
        frozenset({str(res(1))}),
        frozenset({str(res(1)), str(act(1))}),
    ]


async def test_a_reviewer_that_can_now_assess_ends_the_follow_up() -> None:
    case, _refs = _verification_case(20)
    first = _evaluation(_insufficient(), frozenset(), case)
    settled = _evaluation(
        SemanticJudgment("no_material_discrepancy", ()), frozenset({str(evd(1))}), case
    )
    app = _ScriptedReviewer(case, [settled])
    assert await _loop(app, case, first) is settled
    assert len(app.follow_ups) == 1


async def test_a_round_that_sends_nothing_leaves_the_first_review_standing() -> None:
    case, _refs = _verification_case(20)
    first = _evaluation(_insufficient(), frozenset(), case)
    app = _ScriptedReviewer(case, [None])
    assert await _loop(app, case, first) is first


async def test_a_coordinator_crash_in_a_round_is_an_honest_failure() -> None:
    case, _refs = _verification_case(20)
    first = _evaluation(_insufficient(), frozenset(), case)
    app = _ScriptedReviewer(case, [RuntimeError("boom")])
    result = cast(FinalSemanticEvaluation, await _loop(app, case, first))
    assert (result.status, result.reason) == (
        SemanticStatus.FAILED,
        SemanticReason.COORDINATOR_FAILURE,
    )
    assert result.judgment is None
    assert result.operation_lease == _LEASE


async def test_nothing_is_asked_again_without_an_answerable_request() -> None:
    case, _refs = _verification_case(20)
    app = _ScriptedReviewer(case, [])
    clean = _evaluation(SemanticJudgment("no_material_discrepancy", ()), frozenset(), case)
    assert await _loop(app, case, clean) is clean
    statement = _evaluation(
        SemanticJudgment(
            "insufficient_packet",
            (),
            missing_for_assessment=(MissingForAssessment("task_statement", (), "The request."),),
        ),
        frozenset(),
        case,
    )
    assert await _loop(app, case, statement) is statement
    failed = FinalSemanticEvaluation(SemanticStatus.FAILED, SemanticReason.COORDINATOR_FAILURE)
    assert await _loop(app, case, failed) is failed
    assert app.follow_ups == []


async def test_an_evaluator_that_does_not_name_follow_ups_keeps_todays_single_review() -> None:
    case, _refs = _verification_case(20)
    first = _evaluation(_insufficient(), frozenset(), case)
    calls: list[dict[str, object]] = []

    async def kwargs_only(
        frozen: object,
        deterministic: object,
        runtime: object | None = None,
        lineage_evaluation: object | None = None,
        **kwargs: object,
    ) -> object:
        del frozen, deterministic, runtime, lineage_evaluation
        calls.append(kwargs)
        return first

    assert await _loop(SimpleNamespace(evaluate_semantic_check=kwargs_only), case, first) is first
    assert calls == []


async def test_the_facade_forwards_a_follow_up_only_to_an_evaluator_that_names_it() -> None:
    follow_up = ReviewFollowUp(
        1,
        (ReviewFollowUpItem("verification_output", (str(res(1)),), frozenset({str(evd(1))})),),
        frozenset(),
    )
    seen: list[object] = []

    async def naming(
        frozen: object,
        findings: object,
        runtime: object | None = None,
        lineage_evaluation: object | None = None,
        require_complete_specification: bool = False,
        follow_up: ReviewFollowUp | None = None,
    ) -> object:
        del frozen, findings, runtime, lineage_evaluation, require_complete_specification
        seen.append(follow_up)
        return "round"

    async def kwargs_only(
        frozen: object,
        findings: object,
        runtime: object | None = None,
        lineage_evaluation: object | None = None,
        **kwargs: object,
    ) -> object:
        del frozen, findings, runtime, lineage_evaluation
        seen.append(kwargs)
        return "first review"

    async def call(evaluator: object) -> object:
        holder = SimpleNamespace(semantic_evaluator=evaluator)
        return await Application.evaluate_semantic_check(
            cast(Any, holder), cast(Any, object()), (), None, None, follow_up=follow_up
        )

    assert await call(naming) == "round"
    assert seen == [follow_up]
    # ``**kwargs`` is not a declaration: nothing is dispatched, and no first-review call shape
    # stands in for the round.
    assert await call(kwargs_only) is None
    assert seen == [follow_up]
