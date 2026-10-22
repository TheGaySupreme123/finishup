"""Freshness is AI-advisory only where AI-powered review applies (#1143, PR #1167 review).

A check on a route that runs no review (none configured, the strict route, a disabled policy or a
failed review) judges verification freshness by the local rule, exactly as status and Stop do at
the same frontier: an edit after the last test run is ``edited_after_last_verification``, never
the AI route's rerun question. On a route that requires AI-powered review the same edit is the
advisory question and never a Stop item. These tests drive the real ``Application`` facade.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from typing import Any, Literal

import pytest

from builders.start_application import protocol_id, start_request
from finishup.domain.events import ActionKind
from finishup.ports.ledger import CheckCommitResult
from finishup.protocol.models import CheckRequest
from integration.application import test_respond_status_receipt as h
from integration.application import test_tb4n3_own_calls_cross_surface as s

pytestmark = pytest.mark.anyio

_QUESTION = "Is a verification rerun needed after the recorded changes?"


async def _edit_after_a_test_run(
    semantic: Literal["disabled", "optional", "required"], mode: str, seed_offset: int
) -> tuple[CheckCommitResult, Any]:
    """A test run, then an ``apply_patch`` edit, then one check; returns it and its readiness."""

    app, runtime, _ = h._build_app(seed_offset=seed_offset, semantic=semantic)
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
    checked = await app.check(
        CheckRequest.model_validate(
            {
                **h._request_base(protocol_id("req_", 5800)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": h._frontier(appended.result_frontier),
                "mode": mode,
                "max_findings": "5",
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
