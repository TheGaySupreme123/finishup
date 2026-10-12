"""A plan-time check never calls the reviewer; the first edit re-arms it (issue #1046 item 1).

tb4n4: 18 of 61 semantic-arm tasks ran a ``semantic_required`` review of the plan before any work,
and most routine ``insufficient_packet`` answers came from those. These cases run the real ready
composition with a hermetic reviewer that records every case it is shown:

* a ``semantic_required`` check after only the plan runs the local plan checks, records
  ``not_requested`` with ``semantic_review_deferred_before_first_edit`` and never composes a case;
* the CLI and MCP summaries say why in the same words;
* after the first published edit the next check reviews as configured;
* the closing review (``final_review``) always runs, edit or not.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from typing import Any

import pytest

from builders.projection_workflow import (
    build_projection_application,
    frontier_json,
    request_base,
)
from builders.review_manifests import provider_bound_manifest
from builders.start_application import protocol_id, start_request
from yoetz.application.check import FinalSemanticEvaluation
from yoetz.application.service import Application
from yoetz.domain.findings import Finding, SemanticDispatchKind, SemanticProvenance
from yoetz.domain.privacy import ReviewContextProfile
from yoetz.domain.receipts import SEMANTIC_REVIEW_DEFERRED_BEFORE_FIRST_EDIT_GAP
from yoetz.ports.ledger import CheckCommitResult, FrozenCase
from yoetz.ports.semantic import SamplingParams, SemanticJudgment
from yoetz.protocol.canonical import JsonValue
from yoetz.protocol.models import (
    CheckRequest,
    PublishWorkRequest,
    SemanticReason,
    SemanticStatus,
)

pytestmark = pytest.mark.anyio

_DIGEST = "sha256:" + "6" * 64


def _provenance(seed: int) -> SemanticProvenance:
    return SemanticProvenance(
        provider="fake",
        endpoint_profile_id="fake",
        endpoint_profile_version="1.0.0",
        model="fake/model",
        sdk_version="1.0.0",
        prompt_digest=_DIGEST,
        schema_digest=_DIGEST,
        policy_digest=_DIGEST,
        privacy_policy_digest=_DIGEST,
        sampling_params=SamplingParams(128),
        latency_ms=1,
        semantic_attempt_id=protocol_id("att_", seed),
        dispatch_kind=SemanticDispatchKind.EXTERNAL,
        privacy_receipt_id=protocol_id("egr_", seed + 1),
        status=SemanticStatus.SUCCEEDED,
        reason=SemanticReason.SEMANTIC_COMPLETED,
        provider_request_id=f"fake-timing-{seed}",
        egress_authorization_id=protocol_id("aut_", seed + 2),
        request_commitment="hmac-sha256:" + "c" * 64,
    )


@dataclass
class _Reviewer:
    """A hermetic reviewer that counts the cases it was asked to judge."""

    calls: list[bool] = field(default_factory=lambda: [])
    seed: int = 10460
    profile: ReviewContextProfile = ReviewContextProfile.GOAL_AWARE

    async def __call__(
        self,
        frozen: FrozenCase,
        findings: tuple[Finding, ...],
        runtime: object | None = None,
        lineage_evaluation: object | None = None,
        require_complete_specification: bool = False,
        final_review: bool = False,
    ) -> FinalSemanticEvaluation:
        del frozen, findings, runtime, lineage_evaluation, require_complete_specification
        self.calls.append(final_review)
        return FinalSemanticEvaluation(
            SemanticStatus.SUCCEEDED,
            SemanticReason.SEMANTIC_COMPLETED,
            judgment=SemanticJudgment("no_material_discrepancy", ()),
            provenance=_provenance(self.seed + 10 * len(self.calls)),
            provider_input_manifest=provider_bound_manifest(),
        )


@dataclass(frozen=True, slots=True)
class _Session:
    app: Application
    session_id: str
    writer_id: str


def _draft(event_id: str, name: str, payload: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
    return {
        "event_id": event_id,
        "schema": {"name": name, "version": "1.0.0"},
        "occurred_at": "2026-10-12T12:00:00.000Z",
        "causal_parents": [],
        "payload": dict(payload),
        "artifact_refs": [],
        "evidence_refs": [],
    }


async def _publish(
    session: _Session, frontier: JsonValue, seed: int, *drafts: dict[str, JsonValue]
) -> JsonValue:
    published = await session.app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **request_base(protocol_id("req_", seed)),
                "session_id": session.session_id,
                "writer_id": session.writer_id,
                "expected_frontier": frontier,
                "event_drafts": list(drafts),
            }
        )
    )
    return frontier_json(published.result_frontier)


async def _planned(reviewer: _Reviewer, seed: int) -> tuple[_Session, JsonValue]:
    app, _policy = await build_projection_application("optional", seed=seed, max_findings=5)
    app = replace(app, semantic_evaluator=reviewer)
    started = await app.start(start_request(seed, title="Fix the parser's unicode handling"))
    session = _Session(app, started.session_id, started.writer_id)
    obligation = protocol_id("obl_", seed + 1)
    frontier = await _publish(
        session,
        frontier_json(started.frontier),
        seed + 2,
        _draft(
            protocol_id("evt_", seed + 3),
            "obligation_published",
            {
                "obligation_id": obligation,
                "description": "Make the parser accept unicode identifiers.",
                "evidence_expectation": "The parser tests pass.",
                "status": "open",
            },
        ),
        _draft(
            protocol_id("evt_", seed + 4),
            "plan_published",
            {
                "plan_version": 1,
                "summary": "Fix the tokenizer, then run the parser tests.",
                "obligation_refs": [obligation],
            },
        ),
    )
    return session, frontier


async def _check(
    session: _Session, frontier: JsonValue, seed: int, *, final_review: bool = False
) -> CheckCommitResult:
    checked = await session.app.check(
        CheckRequest.model_validate(
            {
                **request_base(protocol_id("req_", seed)),
                "session_id": session.session_id,
                "writer_id": session.writer_id,
                "expected_frontier": frontier,
                "mode": "semantic_required",
                "max_findings": "5",
                **({"final_review": True} if final_review else {}),
            }
        )
    )
    assert type(checked) is CheckCommitResult, f"unexpected nonterminal check: {type(checked)}"
    return checked


def _body(result: CheckCommitResult) -> Mapping[str, Any]:
    from yoetz.application.check import check_internal_json

    return check_internal_json(result)  # type: ignore[return-value]


async def test_a_plan_time_check_defers_the_review_and_the_first_edit_rearms_it() -> None:
    from yoetz.cli.render import render_human_check
    from yoetz.mcp.summaries import summary_for_check
    from yoetz.protocol.models import CheckSuccessModel, CoverageModel

    seed = 10461
    reviewer = _Reviewer()
    session, frontier = await _planned(reviewer, seed)

    planned = await _check(session, frontier, seed + 10)
    body = _body(planned)
    assert reviewer.calls == []
    assert body["semantic_status"] == "not_requested"
    gaps = body["coverage"]["known_gaps"]
    assert SEMANTIC_REVIEW_DEFERRED_BEFORE_FIRST_EDIT_GAP in gaps
    # Nothing was dropped or found by a review that never ran.
    assert "semantic_challenges_rejected" not in gaps
    assert "AI-powered review deferred until the first material edit" in summary_for_check(body)
    cli = render_human_check(
        CheckSuccessModel.model_construct(
            verdict=body["verdict"],
            semantic_status="not_requested",
            semantic_reason=body["semantic_reason"],
            semantic_provenance=None,
            findings=(),
            suppressed_count="0",
            finding_checklist=None,
            children=None,
            advisory_notes=(),
            coverage=CoverageModel.model_construct(known_gaps=tuple(gaps)),
        )
    )
    assert "AI-powered review deferred: no material edit is recorded yet" in cli

    edited = await _publish(
        session,
        frontier_json(planned.result_frontier),
        seed + 20,
        _draft(
            protocol_id("evt_", seed + 21),
            "action_recorded",
            {
                "action_id": protocol_id("act_", seed + 22),
                "action_kind": "edit",
                "description": "Rewrote the tokenizer's identifier rule.",
            },
        ),
    )
    reviewed = await _check(session, edited, seed + 30)
    assert reviewer.calls == [False]
    assert _body(reviewed)["semantic_status"] == "succeeded"
    assert (
        SEMANTIC_REVIEW_DEFERRED_BEFORE_FIRST_EDIT_GAP
        not in (_body(reviewed)["coverage"]["known_gaps"])
    )


async def test_the_closing_review_runs_before_any_edit() -> None:
    seed = 10481
    reviewer = _Reviewer()
    session, frontier = await _planned(reviewer, seed)

    closing = await _check(session, frontier, seed + 10, final_review=True)
    assert reviewer.calls == [True]
    body = _body(closing)
    assert body["semantic_status"] == "succeeded"
    assert SEMANTIC_REVIEW_DEFERRED_BEFORE_FIRST_EDIT_GAP not in body["coverage"]["known_gaps"]
