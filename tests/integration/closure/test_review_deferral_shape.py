"""A review Yoetz deferred before the first edit, on every surface (issue #1046, review).

A routine check before the first material edit sends nothing and records
``semantic_review_deferred_before_first_edit`` beside ``semantic_review_not_requested``. An
investigation task whose work is never an edit therefore reaches its end with only deferred checks,
and two things went wrong there:

* on a route that does not require AI-powered review the deferral bounded the receipt
  (``insufficient_coverage``) while status read "nothing further to do", although the same ledger
  checked with ``deterministic_only`` reads clean and the ``semantic_review_not_requested`` it
  rides with is only disclosed there (ADR-046 rule G1);
* no surface asked for the closing review: on that route it is asked for only once a review was
  used, and on a route that requires review the deferred check's actionable
  ``semantic_review_not_requested`` suppressed ``closing_review_required``, the one review token
  the Stop gate continues on. A routine check just defers again, so the agent stopped unreviewed.

Now the deferral follows the recorded route like ``semantic_review_not_requested`` (gap table G7:
disclosed where the route did not require review, bounding where it did), and readiness asks for
the closing review after a deferral on both routes. Check, status in every view, ``closure_prepare``,
the Stop gate and the receipt in three formats agree (``assert_surfaces_agree``).
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any, Literal, cast

import pytest

from builders.review_manifests import provider_bound_manifest
from builders.start_application import protocol_id, start_request
from integration.application import test_respond_status_receipt as h
from integration.closure.test_closure_shapes import (
    _CLEAN,
    _INSUFFICIENT,
    _NO_FINDINGS,
    _obligation,
    _plan,
    _public,
    _Run,
    _surfaces,
    assert_surfaces_agree,
    receipt_artifact_1_3_0,  # noqa: F401  # pyright: ignore[reportUnusedImport] - autouse fixture
)
from yoetz.application.check import CheckCommitResult, FinalSemanticEvaluation
from yoetz.cli.closure_gate import closure_gate_from_readiness
from yoetz.domain.receipts import (
    SEMANTIC_REVIEW_DEFERRED_BEFORE_FIRST_EDIT_GAP,
    SEMANTIC_REVIEW_NOT_REQUESTED_GAP,
)
from yoetz.domain.task_fact_tokens import STOP_GATE_TOKENS
from yoetz.domain.values import JsonObject
from yoetz.protocol.models import CheckRequest

pytestmark = pytest.mark.anyio

_DEFERRED = SEMANTIC_REVIEW_DEFERRED_BEFORE_FIRST_EDIT_GAP
_CLOSING = "closing_review_required"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@dataclass
class _Reviewer:
    """A hermetic reviewer that records each call's phase and names it in the sent manifest."""

    calls: list[bool] = field(default_factory=lambda: [])

    async def __call__(
        self,
        frozen: object,
        findings: object,
        runtime: object | None = None,
        lineage_evaluation: object | None = None,
        require_complete_specification: bool = False,
        final_review: bool = False,
    ) -> object:
        del runtime, lineage_evaluation, require_complete_specification
        self.calls.append(final_review)
        succeeded = cast(FinalSemanticEvaluation, await h._semantic_succeeds(frozen, findings))
        manifest = JsonObject(
            {**provider_bound_manifest(), "review_phase": "final" if final_review else "routine"}
        )
        return replace(succeeded, provider_input_manifest=manifest)


async def _check(run: _Run, mode: str, *, final_review: bool = False) -> CheckCommitResult:
    result = await run.app.check(
        CheckRequest.model_validate(
            {
                **h._request_base(run.next("req_")),
                "session_id": run.started.session_id,
                "writer_id": run.started.writer_id,
                "expected_frontier": h._frontier(run.frontier),
                "mode": mode,
                "max_findings": "10",
                **({"final_review": True} if final_review else {}),
            }
        )
    )
    assert type(result) is CheckCommitResult
    run.frontier = result.result_frontier
    return result


async def _investigation(
    seed: int, policy: Literal["optional", "required"]
) -> tuple[_Run, _Reviewer]:
    """A task whose work is not an edit: one requirement, answered on recorded evidence."""

    reviewer = _Reviewer()
    app, runtime, _ = h._build_app(seed_offset=seed, semantic=policy, semantic_evaluator=reviewer)
    started = await app.start(start_request(seed, title=f"investigation {seed}"))
    run = _Run(app, runtime, started)
    evidence = protocol_id("evd_", 7301)
    await run.publish(_obligation(run, 1), _plan(run, 1))
    await run.publish(
        run.draft(
            "evidence_recorded",
            {
                "evidence_id": evidence,
                "evidence_kind": "test_result",
                "strength": "metadata_only",
                "observed_at": "2026-09-28T12:00:00.000Z",
                "description": "The investigation found the answer.",
            },
        ),
        _obligation(run, 1, status="resolved", resolution_evidence_refs=[evidence]),
    )
    return run, reviewer


def _gate_items(status: Any) -> tuple[str, ...]:
    gate = closure_gate_from_readiness(
        _public(status).closure_readiness,
        frontier_sequence="9",
        frontier_digest="d",
        observation_pending=False,
    )
    return () if gate is None else gate.items


async def test_a_deferral_where_review_is_optional_reads_like_a_local_only_check() -> None:
    """The deferral is disclosed where the check's route did not require review."""

    run, reviewer = await _investigation(10_460, "optional")
    deferred = await _check(run, "semantic_if_configured")
    assert reviewer.calls == []
    assert {_DEFERRED, SEMANTIC_REVIEW_NOT_REQUESTED_GAP} <= set(deferred.coverage.known_gaps)
    assert deferred.semantic_route_required is False
    assert deferred.verdict.value == "no_issue_detected"

    gathered = await _surfaces(run)
    assert_surfaces_agree(gathered, conclusion=_CLEAN, counts=_NO_FINDINGS, check=deferred)
    document = gathered.receipts["json"].document
    effects = {gap["code"]: gap["effect"] for gap in document["gaps"]}
    assert effects[_DEFERRED] == effects[SEMANTIC_REVIEW_NOT_REQUESTED_GAP] != "bounds"
    for fmt in ("markdown", "text"):
        text = str(gathered.receipts[fmt].human_text)
        assert "AI-powered review was deferred" in text, fmt
        assert "none of these bounds the conclusion" in text, fmt

    # The control: the same ledger checked local-only on the same route.
    control, _ = await _investigation(10_470, "optional")
    local = await _check(control, "deterministic_only")
    assert_surfaces_agree(
        await _surfaces(control), conclusion=_CLEAN, counts=_NO_FINDINGS, check=local
    )


@pytest.mark.parametrize("policy", ["optional", "required"])
async def test_a_task_whose_work_is_not_an_edit_is_asked_for_the_closing_review(
    policy: Literal["optional", "required"],
) -> None:
    """After a deferral readiness and the Stop gate ask for the closing review, on both routes."""

    run, reviewer = await _investigation(10_480 + len(policy), policy)
    deferred = await _check(run, "semantic_if_configured")
    assert _DEFERRED in deferred.coverage.known_gaps
    # A second routine check before any edit defers again: only the closing review can help.
    again = await _check(run, "semantic_if_configured")
    assert _DEFERRED in again.coverage.known_gaps
    assert reviewer.calls == []

    gathered = await _surfaces(run, receipts=False)
    status = gathered.status["compact"]
    readiness = status.closure_readiness
    assert readiness.state == "action_required"
    actionable = tuple(readiness.agent_actionable or ())
    assert _CLOSING in actionable and _CLOSING in STOP_GATE_TOKENS
    # Where review is required the missing review stays agent work beside it.
    assert (SEMANTIC_REVIEW_NOT_REQUESTED_GAP in actionable) is (policy == "required")
    assert _CLOSING in _gate_items(status)

    closing = await _check(run, "semantic_if_configured", final_review=True)
    assert reviewer.calls == [True]
    assert closing.semantic_status.value == "succeeded"
    assert _DEFERRED not in closing.coverage.known_gaps
    after = await _surfaces(run)
    readiness = after.status["compact"].closure_readiness
    assert readiness.state == "ready", readiness.agent_actionable
    assert _CLOSING not in _gate_items(after.status["compact"])
    assert_surfaces_agree(after, conclusion=_CLEAN, counts=_NO_FINDINGS, check=closing)


async def test_a_deferral_where_review_is_required_bounds_until_the_closing_review() -> None:
    """Where the route requires review, the deferral and the missing review both bound."""

    run, _reviewer = await _investigation(10_490, "required")
    deferred = await _check(run, "semantic_if_configured")
    assert deferred.semantic_route_required is None
    gathered = await _surfaces(run)
    assert_surfaces_agree(gathered, conclusion=_INSUFFICIENT, counts=_NO_FINDINGS, check=deferred)
    document = gathered.receipts["json"].document
    effects = {gap["code"]: gap["effect"] for gap in document["gaps"]}
    assert effects[_DEFERRED] == "bounds"
