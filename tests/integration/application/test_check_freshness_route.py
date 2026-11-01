"""Freshness is AI-advisory only where AI-powered review applies (#1143, PR #1167 review).

A check on a route that runs no review (none configured, the strict route, a disabled policy or a
failed review) judges verification freshness by the local rule, exactly as status and Stop do at
the same frontier: an edit after the last test run is ``edited_after_last_verification``, never
the AI route's rerun question. On a route that requires AI-powered review the same edit is the
advisory question and never a Stop item. These tests drive the real ``Application`` facade.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

import pytest

import finishup.observability.diagnostics as diagnostics_module
from builders.start_application import protocol_id, start_request
from finishup.domain.events import ActionKind
from finishup.domain.privacy import ConversationReview
from finishup.kernel.review_mode import ConversationReviewContext
from finishup.ports.ledger import CheckCommitResult
from finishup.protocol.canonical import canonical_encode
from finishup.protocol.models import CheckRequest, RespondRequest, SemanticStatus
from integration.application import test_respond_status_receipt as h
from integration.application import test_tb4n3_own_calls_cross_surface as s

pytestmark = pytest.mark.anyio

_QUESTION = "Is a verification rerun needed after the recorded changes?"


async def _edit_after_a_test_run(
    semantic: Literal["disabled", "optional", "required"],
    mode: str | None,
    seed_offset: int,
    *,
    pending: bool = False,
    final_review: bool = False,
    conversation: str | None = None,
) -> tuple[CheckCommitResult, Any]:
    """A test run, then an ``apply_patch`` edit, then one check; returns it and its readiness.

    ``pending`` leaves the test run without a result (its post-event never arrived);
    ``conversation`` is the owner's explicit conversation review setting.
    """

    app, runtime, _ = h._build_app(seed_offset=seed_offset, semantic=semantic)
    if conversation is not None:
        setting = ConversationReview(conversation)

        async def reader(_runtime: object) -> ConversationReviewContext:
            return ConversationReviewContext(setting, True, True)

        object.__setattr__(app, "conversation_review_reader", reader)
    started = await app.start(start_request(5100, title="freshness route"))
    appended = await s._append_observed(
        app,
        runtime,
        started,
        (
            s._action(5620, ActionKind.COMMAND, "Bash", "test"),
            *(() if pending else (s._result(5621, 5620),)),
            s._action(5622, ActionKind.EDIT, "apply_patch", "compound"),
            s._result(5623, 5622),
        ),
        seed=5600,
        expected_frontier=int(started.frontier.sequence),
    )
    checked = await app.check(
        CheckRequest.model_validate(
            {
                **h._request_base(protocol_id("req_", 5800)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": h._frontier(appended.result_frontier),
                **({} if mode is None else {"mode": mode}),
                "max_findings": "5",
                **({"final_review": True} if final_review else {}),
            }
        )
    )
    assert type(checked) is CheckCommitResult
    surfaces = await s._surfaces(app, runtime, started, checked.result_frontier, 6000)
    return checked, surfaces["status"].closure_readiness


@pytest.mark.parametrize("mode", ["deterministic_only", "semantic_if_configured"])
async def test_a_check_without_ai_review_keeps_the_local_freshness_rule(mode: str) -> None:
    checked, readiness = await _edit_after_a_test_run("disabled", mode, 77)
    assert all(finding.summary != _QUESTION for finding in checked.findings)
    assert "edited_after_last_verification" in checked.coverage.known_gaps
    # Status and Stop read the same local route: the stale verification is agent work there too.
    assert "edited_after_last_verification" in readiness.agent_actionable
    assert "verification_rerun_question" not in readiness.agent_actionable


async def test_a_check_on_a_route_that_requires_ai_review_asks_instead() -> None:
    checked, readiness = await _edit_after_a_test_run("required", "semantic_if_configured", 78)
    assert any(finding.summary == _QUESTION for finding in checked.findings)
    assert "edited_after_last_verification" not in readiness.agent_actionable


async def test_the_first_ai_review_as_the_final_review_keeps_check_and_status_on_one_route() -> (
    None
):
    """Optional policy: the first AI-powered review is the closing one (#1167 review, round 2).

    The check judged freshness before any review was used, so it applied the local rule and
    asked nothing; status and Stop judge the same state and keep the stale verification as
    agent work, never a standing question with no finding to answer.
    """

    checked, readiness = await _edit_after_a_test_run(
        "optional", "semantic_if_configured", 79, final_review=True
    )
    assert checked.semantic_status is SemanticStatus.SUCCEEDED
    assert all(finding.summary != _QUESTION for finding in checked.findings)
    assert "edited_after_last_verification" in readiness.agent_actionable
    assert "verification_rerun_question" not in readiness.standing_limitations


async def test_a_pending_run_then_an_edit_on_the_ai_route_is_asked_not_phantom() -> None:
    """Required route: a run whose result never arrived, then an edit, mints the question."""

    checked, readiness = await _edit_after_a_test_run(
        "required", "semantic_if_configured", 80, pending=True
    )
    assert any(finding.summary == _QUESTION for finding in checked.findings)
    assert "edited_after_last_verification" not in readiness.agent_actionable


@pytest.mark.parametrize("setting", ["local_only", "local_agent_opt_in"])
async def test_an_owner_local_setting_keeps_a_required_policy_on_the_local_rule(
    setting: str,
) -> None:
    """The owner chose local checks for this conversation (#1167 final check, finding 2).

    The check runs local, so it judges freshness by the local rule like status and Stop: no rerun
    question whose answer could never release Stop.
    """

    checked, readiness = await _edit_after_a_test_run("required", None, 81, conversation=setting)
    assert all(finding.summary != _QUESTION for finding in checked.findings)
    assert "edited_after_last_verification" in checked.coverage.known_gaps
    assert "edited_after_last_verification" in readiness.agent_actionable
    assert "verification_rerun_question" not in readiness.standing_limitations


async def test_an_answered_rerun_question_stands_reaches_the_receipt_and_is_counted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#1241 D9/D10 through the real facade, on the route that asks.

    The question is never unanswered work; a reasoned answer stands, so the next check over the
    same runs and changes does not ask again; every receipt format shows the agent's reason; and
    each check records the question's accounting.
    """

    monkeypatch.setattr(diagnostics_module, "log_dir", lambda: tmp_path)
    app, runtime, _ = h._build_app(seed_offset=82, semantic="required")
    started = await app.start(start_request(5100, title="freshness route"))
    appended = await s._append_observed(
        app,
        runtime,
        started,
        (
            s._action(5620, ActionKind.COMMAND, "Bash", "test"),
            s._result(5621, 5620),
            s._action(5622, ActionKind.EDIT, "apply_patch", "compound"),
            s._result(5623, 5622),
        ),
        seed=5600,
        expected_frontier=int(started.frontier.sequence),
    )

    def check(seed: int, frontier: Any) -> CheckRequest:
        return CheckRequest.model_validate(
            {
                **h._request_base(protocol_id("req_", seed)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": h._frontier(frontier),
                "mode": "semantic_if_configured",
                "max_findings": "5",
            }
        )

    first = await app.check(check(5800, appended.result_frontier))
    assert type(first) is CheckCommitResult
    question = next(finding for finding in first.findings if finding.summary == _QUESTION)
    asked = await s._surfaces(app, runtime, started, first.result_frontier, 6000)
    # Visible, never unanswered work: status agrees with the check, which never counted it.
    assert asked["compact"].unanswered_finding_count == "0"
    assert "findings_unanswered" not in asked["status"].closure_readiness.blocking_conditions

    reason = "Only a code comment changed; the test run does not read it."
    responded = await app.respond(
        RespondRequest.model_validate(
            {
                **h._request_base(protocol_id("req_", 5801)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": h._frontier(first.result_frontier),
                "finding_id": question.finding_id,
                "finding_frontier": h._frontier(first.result_frontier),
                "disposition": "acknowledged",
                "reason": reason,
            }
        )
    )
    second = await app.check(check(5802, responded.result_frontier))
    assert type(second) is CheckCommitResult
    assert all(finding.summary != _QUESTION for finding in second.findings)
    surfaces = await s._surfaces(app, runtime, started, second.result_frontier, 6100)
    readiness = surfaces["status"].closure_readiness
    assert "findings_unanswered" not in readiness.blocking_conditions
    # The edit after the run is still a fact: a standing limit on this route, never agent work.
    assert "edited_after_last_verification" not in readiness.agent_actionable
    for fmt, receipt in surfaces["receipts"].items():
        rendered = (
            canonical_encode(receipt.document).decode("utf-8")
            if receipt.document is not None
            else receipt.human_text
        )
        assert f"rerun not needed: {reason}" in rendered, fmt

    raw = diagnostics_module.diagnostic_log_path(root=tmp_path).read_text(encoding="ascii")
    counted = [
        (record["rerun_questions_asked"], record["rerun_questions_answered"])
        for record in map(json.loads, filter(None, raw.splitlines()))
        if record["operation"] == "rerun_question_accounting"
    ]
    assert counted == [(1, 0), (0, 1)]
    # Counts only: the agent's reason never reaches the diagnostics log.
    assert reason not in raw
