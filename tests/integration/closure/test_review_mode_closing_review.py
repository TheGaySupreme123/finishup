"""The closing review and the owner's required review under per-task review modes (ADR-049).

Review round 1 of the hybrid default found two ways a task's review mode broke closure:

* P2-2: a task that already used AI-powered review and now runs local (it switched back, or it
  never switched and one check named an AI-powered mode) was asked for the closing review by the
  Stop gate (`check` with `final_review: true`), and that check, naming no mode, ran local. The
  closing review could never clear. Now such a check is the closing review the gate asks for: it
  runs AI-powered under the effective privacy policy and records that it asked.
* P2-1: under the owner's "every task" setting (explicit ``ai_powered``) or the released reading
  of an older policy, an agent's switch to local dropped the owner's required review and closed
  with a clean local receipt. Now the setting governs: the switch is recorded but the task's
  checks still run AI-powered review, and a missing review stays a bounding gap.

Each scenario runs the real check, status and Stop-gate path over the in-memory composition with
a hermetic reviewer and a fixed owner-setting reader.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from typing import Any, cast

import pytest

from builders.start_application import protocol_id
from finishup.application.check import CheckCommitResult
from finishup.domain.events import CheckReviewMode, ReviewMode
from finishup.domain.privacy import ConversationReview
from finishup.kernel.review_mode import ConversationReviewContext
from finishup.protocol.models import CheckRequest
from integration.application import test_respond_status_receipt as h
from integration.closure.test_closure_shapes import (
    _Run,
    _surfaces,
    receipt_artifact_1_3_0,  # noqa: F401  # pyright: ignore[reportUnusedImport] - autouse fixture
)
from integration.closure.test_review_deferral_shape import _gate_items, _investigation, _Reviewer

pytestmark = pytest.mark.anyio

_CLOSING = "closing_review_required"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _setting(run: _Run, setting: ConversationReview, *, explicit: bool = True) -> None:
    async def reader(_runtime: object) -> ConversationReviewContext:
        return ConversationReviewContext(setting, True, explicit)

    object.__setattr__(run.app, "conversation_review_reader", reader)


async def _edit(run: _Run, number: int) -> None:
    """One published edit, so a routine review is not deferred to the first edit (#1046)."""

    await run.publish(
        run.draft(
            "action_recorded",
            {
                "action_id": protocol_id("act_", 7400 + number),
                "action_kind": "edit",
                "description": f"Edit {number}",
                "obligation_refs": [protocol_id("obl_", 7001)],
            },
        )
    )


def _switch(run: _Run, mode: ReviewMode) -> dict[str, Any]:
    draft = run.draft(
        "decision_recorded",
        {
            "statement": "Switch this task's review mode.",
            "rationale": "Regression test.",
            "authority": "harness:review-mode",
            "review_mode": mode.value,
        },
    )
    cast(dict[str, Any], draft["schema"])["version"] = "1.1.0"
    return draft


async def _check(
    run: _Run, *, mode: str | None = None, final_review: bool = False
) -> CheckCommitResult:
    body: dict[str, Any] = {
        **h._request_base(run.next("req_")),
        "session_id": run.started.session_id,
        "writer_id": run.started.writer_id,
        "expected_frontier": h._frontier(run.frontier),
        "max_findings": "10",
        **({} if mode is None else {"mode": mode}),
        **({"final_review": True} if final_review else {}),
    }
    result = await run.app.check(CheckRequest.model_validate(body))
    assert type(result) is CheckCommitResult, result
    run.frontier = result.result_frontier
    return result


async def _closing_owed(run: _Run) -> bool:
    status = (await _surfaces(run, receipts=False)).status["compact"]
    actionable = tuple(status.closure_readiness.agent_actionable or ())
    assert (_CLOSING in actionable) == (_CLOSING in _gate_items(status))
    return _CLOSING in actionable


async def test_switch_on_review_switch_back_then_the_stop_gate_closing_review_clears() -> None:
    """P2-2 (a): the gate's literal instruction now supplies the review it asks for."""

    run, reviewer = await _investigation(20_500, "required", _Reviewer())
    _setting(run, ConversationReview.LOCAL_AGENT_OPT_IN)
    await _edit(run, 1)

    await run.publish(_switch(run, ReviewMode.AI_POWERED))
    reviewed = await _check(run)
    assert reviewed.review_mode is not None
    assert reviewed.review_mode.mode is ReviewMode.AI_POWERED
    assert reviewer.calls == [False]

    await run.publish(_switch(run, ReviewMode.LOCAL))
    local = await _check(run)
    assert local.review_mode is not None and local.review_mode.mode is ReviewMode.LOCAL
    assert reviewer.calls == [False]
    assert await _closing_owed(run)

    closing = await _check(run, final_review=True)
    assert closing.review_mode == CheckReviewMode(ReviewMode.AI_POWERED, "check_request")
    assert reviewer.calls == [False, True]
    assert not await _closing_owed(run)


async def test_one_requested_review_then_the_stop_gate_closing_review_clears() -> None:
    """P2-2 (b): never switched; one check named an AI-powered mode."""

    run, reviewer = await _investigation(20_510, "required", _Reviewer())
    _setting(run, ConversationReview.LOCAL_AGENT_OPT_IN)
    await _edit(run, 1)

    asked = await _check(run, mode="semantic_required")
    assert asked.review_mode == CheckReviewMode(ReviewMode.AI_POWERED, "check_request")
    local = await _check(run)
    assert local.review_mode == CheckReviewMode(ReviewMode.LOCAL, "conversation_default")
    assert reviewer.calls == [False]
    assert await _closing_owed(run)

    closing = await _check(run, final_review=True)
    assert closing.review_mode == CheckReviewMode(ReviewMode.AI_POWERED, "check_request")
    assert reviewer.calls == [False, True]
    assert not await _closing_owed(run)


async def test_a_local_task_that_never_used_review_is_not_asked_for_a_closing_review() -> None:
    run, reviewer = await _investigation(20_520, "required", _Reviewer())
    _setting(run, ConversationReview.LOCAL_AGENT_OPT_IN)
    await _edit(run, 1)
    await _check(run)
    assert not await _closing_owed(run)
    final = await _check(run, final_review=True)
    assert final.review_mode == CheckReviewMode(ReviewMode.LOCAL, "conversation_default")
    assert reviewer.calls == []


async def test_the_closing_review_under_owner_local_only_is_not_owed_forever() -> None:
    """The owner narrowed to local only after a review: the closing review is undeliverable."""

    run, reviewer = await _investigation(20_530, "required", _Reviewer())
    _setting(run, ConversationReview.LOCAL_AGENT_OPT_IN)
    await _edit(run, 1)
    await _check(run, mode="semantic_required")
    _setting(run, ConversationReview.LOCAL_ONLY)
    await _check(run)
    assert await _closing_owed(run)
    closing = await _check(run, final_review=True)
    assert closing.review_mode == CheckReviewMode(
        ReviewMode.LOCAL, "check_request", "owner_local_only"
    )
    assert reviewer.calls == [False]
    assert not await _closing_owed(run)


@pytest.mark.parametrize("explicit", [True, False], ids=["every_task", "released_policy"])
async def test_under_every_task_a_switch_to_local_keeps_the_owner_required_review(
    explicit: bool,
) -> None:
    """P2-1: the owner's setting reviews every task; an agent's switch cannot waive it."""

    run, reviewer = await _investigation(20_540 + int(explicit), "required", _Reviewer())
    _setting(run, ConversationReview.AI_POWERED, explicit=explicit)
    await _edit(run, 1)
    await run.publish(_switch(run, ReviewMode.LOCAL))

    checked = await _check(run)
    assert checked.review_mode == CheckReviewMode(ReviewMode.AI_POWERED, "conversation_default")
    assert checked.semantic_route_required is not False
    assert reviewer.calls == [False]

    status = (await _surfaces(run, receipts=False)).status["compact"]
    assert status.review_mode is not None
    assert (status.review_mode["mode"], status.review_mode["requested"]) == ("ai_powered", "local")


async def test_under_every_task_a_named_local_check_leaves_the_required_review_bounding() -> None:
    """P2-1: a check that names local checks runs local; the missing review still bounds."""

    run, reviewer = await _investigation(20_550, "required", _Reviewer())
    _setting(run, ConversationReview.AI_POWERED)
    await _edit(run, 1)
    await run.publish(_switch(run, ReviewMode.LOCAL))
    local = await _check(run, mode="deterministic_only")
    assert local.review_mode == CheckReviewMode(ReviewMode.LOCAL, "check_request")
    assert local.semantic_route_required is not False
    assert "semantic_review_not_requested" in local.coverage.known_gaps
    assert reviewer.calls == []
    status = (await _surfaces(run, receipts=False)).status["compact"]
    assert "semantic_review_not_requested" in tuple(status.closure_readiness.agent_actionable or ())


async def test_a_failed_setting_read_runs_the_check_local_and_keeps_the_gap() -> None:
    """Review round 1 (P3): the reader failing never dispatches a review nobody asked for."""

    run, reviewer = await _investigation(20_560, "required", _Reviewer())

    async def broken(_runtime: object) -> ConversationReviewContext:
        raise OSError("policy store unreadable")

    object.__setattr__(run.app, "conversation_review_reader", broken)
    await _edit(run, 1)
    checked = await _check(run)
    assert checked.review_mode is None
    assert reviewer.calls == []
    assert "semantic_review_not_requested" in checked.coverage.known_gaps
    assert checked.semantic_route_required is not False


async def test_switching_back_after_the_closing_review_costs_one_more_closing_review() -> None:
    """Review round 3 (P3): what review.md says, held here. A switch is a material record."""

    run, reviewer = await _investigation(20_570, "required", _Reviewer())
    _setting(run, ConversationReview.LOCAL_AGENT_OPT_IN)
    await _edit(run, 1)
    await run.publish(_switch(run, ReviewMode.AI_POWERED))
    await _check(run)
    await _check(run, final_review=True)
    assert reviewer.calls == [False, True]
    assert not await _closing_owed(run)

    await run.publish(_switch(run, ReviewMode.LOCAL))
    assert await _closing_owed(run)
    again = await _check(run, final_review=True)
    assert again.review_mode == CheckReviewMode(ReviewMode.AI_POWERED, "check_request")
    assert reviewer.calls == [False, True, True]
    assert not await _closing_owed(run)
