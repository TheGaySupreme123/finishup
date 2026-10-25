"""A closing review asks whether a repair withholds a requested output (issue #975).

TB4 Bun a1: after a review reproduced a leak, the agent "fixed" it by refusing to build the
affected apps; its own tests passed and later reviews missed it. A closing review after an earlier
AI-powered review now asks once whether any repair since withholds or refuses a requested output
for some inputs. The reviewer (the scripted fake provider here) answers with one challenge naming
the criterion, and that finding reaches every host surface with its id. A first review, a routine
one, and a small channel already full with the linked-check question do not ask it.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from typing import Any, cast

import pytest

from builders.projection_workflow import (
    ProjectionCase,
    build_projection_application,
    frontier_json,
    project_case,
    request_base,
)
from builders.review_manifests import provider_bound_manifest
from builders.start_application import protocol_id, start_request
from finishup.adapters.providers.fake import scripted_success
from finishup.application.check import FinalSemanticEvaluation
from finishup.application.semantic_case import (
    SMALL_REVIEW_CHANNEL_BYTES,
    WITHHELD_OUTPUT_QUESTION,
    build_semantic_case,
    repair_review_asked,
    semantic_case_packet_view,
)
from finishup.cli.render import render_human_check
from finishup.domain.findings import Finding, FindingKind, FindingOrigin
from finishup.domain.privacy import ReviewContextProfile, ReviewSelectionPolicy
from finishup.mcp.server import _result_text  # pyright: ignore[reportPrivateUsage]
from finishup.ports.control import ControlMethod
from finishup.ports.ledger import CheckCommitResult, FrozenCase
from finishup.ports.semantic import ReviewerChallenge, SemanticCase, SemanticJudgment
from finishup.protocol.canonical import JsonValue
from finishup.protocol.models import (
    CheckRequest,
    CheckResult,
    CheckSuccessModel,
    PublishWorkRequest,
    SemanticReason,
    SemanticStatus,
    public_model_to_wire,
)
from integration.application.test_review_dialogue_workflow import (
    _provenance,  # pyright: ignore[reportPrivateUsage]
)

pytestmark = pytest.mark.anyio

_CRITERION = "Every app must build with the private constant stripped."
_WITHHELD = (
    "The repair makes the build refuse to compile any app that imports the private constant, so "
    "the affected apps get no build output at all. Criterion: '" + _CRITERION + "'"
)


@dataclass
class _Reviewer:
    """Builds the real case each time, then answers from the scripted fake provider."""

    obligation: str
    result: str
    seed: int = 9750
    cases: list[SemanticCase] = field(default_factory=lambda: [])
    frozen: list[FrozenCase] = field(default_factory=lambda: [])

    async def __call__(
        self,
        frozen: FrozenCase,
        findings: tuple[Finding, ...],
        runtime: object | None = None,
        lineage_evaluation: object | None = None,
    ) -> FinalSemanticEvaluation:
        del runtime, lineage_evaluation
        final = bool(self.cases)
        case = build_semantic_case(
            case_id=protocol_id("cas_", self.seed + len(self.cases)),
            frozen_case=frozen.case,
            dependency_digest=frozen.lease.dependency_digest,
            findings=findings,
            review_context_profile=ReviewContextProfile.GOAL_AWARE,
            review_selection=ReviewSelectionPolicy.for_profile(ReviewContextProfile.GOAL_AWARE),
            policy_id=protocol_id("pvy_", self.seed),
            policy_version="1",
            final_review=final,
        )
        self.cases.append(case)
        self.frozen.append(frozen)
        refs = tuple(sorted((self.obligation, self.result)))
        challenge = (
            ReviewerChallenge(
                FindingKind.TASK_REQUIREMENT_UNMET,
                "The repair withholds the build output for the affected apps",
                refs,
                _WITHHELD,
                "The task may allow refusing such builds.",
                "Build every affected app with the constant stripped instead of refusing the "
                "build. Criterion: '" + _CRITERION + "'",
                "act",
                "The task statement asks for every app to build.",
            )
            if final
            else ReviewerChallenge(
                FindingKind.CODE_DEFECT,
                "The private constant is still shipped",
                refs,
                "The bundle still contains the private literal.",
                "A later step may strip it.",
                "Strip the literal from the shipped bundle.",
                "act",
                "The bundle output is in the packet.",
            )
        )
        step = scripted_success(SemanticJudgment("challenges_returned", (challenge,)))
        view = semantic_case_packet_view(case)
        return FinalSemanticEvaluation(
            SemanticStatus.SUCCEEDED,
            SemanticReason.SEMANTIC_COMPLETED,
            judgment=cast(Any, step.result).judgment,
            provenance=_provenance(self.seed + 10 + len(self.cases)),
            case_prior_finding_refs=view.prior_finding_refs,
            case_citable_refs=view.citable_refs,
            provider_input_manifest=provider_bound_manifest(),
        )


def _draft(event_id: str, name: str, payload: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
    return {
        "event_id": event_id,
        "schema": {"name": name, "version": "1.0.0"},
        "occurred_at": "2026-10-25T12:00:00.000Z",
        "causal_parents": [],
        "payload": dict(payload),
        "artifact_refs": [],
        "evidence_refs": [],
    }


async def test_a_closing_review_after_a_review_asks_and_the_withheld_output_finding_has_an_id() -> (
    None
):
    seed = 9700
    obligation = protocol_id("obl_", seed + 1)
    command = protocol_id("act_", seed + 3)
    result = protocol_id("res_", seed + 5)
    reviewer = _Reviewer(obligation, result)
    app, _policy = await build_projection_application("optional", seed=seed, max_findings=5)
    app = replace(app, semantic_evaluator=reviewer)
    started = await app.start(start_request(seed, title="Strip the private constant"))
    ids = {"session_id": started.session_id, "writer_id": started.writer_id}

    async def publish(serial: int, frontier: Any, *drafts: dict[str, JsonValue]) -> Any:
        return await app.publish_work(
            PublishWorkRequest.model_validate(
                {
                    **request_base(protocol_id("req_", seed + serial)),
                    **ids,
                    "expected_frontier": frontier_json(frontier),
                    "event_drafts": list(drafts),
                }
            )
        )

    async def check(serial: int, frontier: Any, *, final: bool) -> tuple[Any, dict[str, Any]]:
        body: dict[str, JsonValue] = {
            **request_base(protocol_id("req_", seed + serial)),
            **ids,
            "expected_frontier": frontier_json(frontier),
            "mode": "semantic_required",
            "max_findings": "5",
            "final_review": final,
        }
        checked = await app.check(CheckRequest.model_validate(body))
        assert type(checked) is CheckCommitResult, type(checked)
        wire = await project_case(
            app, ProjectionCase("check", ControlMethod.CHECK, body, checked), seed + serial + 1
        )
        return checked, wire

    published = await publish(
        10,
        started.frontier,
        _draft(
            protocol_id("evt_", seed + 2),
            "obligation_published",
            {
                "obligation_id": obligation,
                "description": "Build every app without the private constant.",
                "acceptance_criteria": _CRITERION,
                "evidence_expectation": "The release build test passes.",
                "status": "open",
            },
        ),
        _draft(
            protocol_id("evt_", seed + 11),
            "action_recorded",
            {
                "action_id": protocol_id("act_", seed + 12),
                "action_kind": "edit",
                "description": "Strip the private constant from the bundle.",
            },
        ),
        _draft(
            protocol_id("evt_", seed + 4),
            "action_recorded",
            {
                "action_id": command,
                "action_kind": "command",
                "description": "Run the release build test.",
                "command": "bun test release",
                "obligation_refs": [obligation],
            },
        ),
        _draft(
            protocol_id("evt_", seed + 6),
            "result_recorded",
            {"result_id": result, "action_id": command, "outcome": "success", "summary": "ok"},
        ),
    )
    first, _first_wire = await check(20, published.result_frontier, final=False)
    # The first, routine review: no earlier review, no withheld-output question.
    assert WITHHELD_OUTPUT_QUESTION not in reviewer.cases[0].question_set
    repaired = await publish(
        40,
        first.result_frontier,
        _draft(
            protocol_id("evt_", seed + 8),
            "action_recorded",
            {
                "action_id": protocol_id("act_", seed + 9),
                "action_kind": "edit",
                "description": "Refuse builds that import the private constant.",
            },
        ),
    )
    _second, projected = await check(50, repaired.result_frontier, final=True)

    # The closing review after that one asks, before the linked-check question (kept last).
    closing = reviewer.cases[1]
    assert closing.question_set[0].startswith("Review phase: final.")
    assert repair_review_asked(reviewer.frozen[1].case)
    assert WITHHELD_OUTPUT_QUESTION in closing.question_set
    assert "Counter-example" in closing.question_set[-1]
    assert closing.question_set.index(WITHHELD_OUTPUT_QUESTION) == len(closing.question_set) - 2
    # On a channel no larger than the minimal policy's, a packet that still carries the
    # linked-check question has no room left (#1173): exactly one of the two rides there.
    small = build_semantic_case(
        case_id=protocol_id("cas_", 9790),
        frozen_case=reviewer.frozen[1].case,
        dependency_digest=reviewer.frozen[1].lease.dependency_digest,
        findings=(),
        review_context_profile=ReviewContextProfile.GOAL_AWARE,
        review_selection=ReviewSelectionPolicy.for_profile(ReviewContextProfile.GOAL_AWARE),
        policy_id=protocol_id("pvy_", 9790),
        policy_version="1",
        final_review=True,
        prepared_byte_ceiling=SMALL_REVIEW_CHANNEL_BYTES,
    )
    linked = any("Counter-example" in question for question in small.question_set)
    assert (WITHHELD_OUTPUT_QUESTION in small.question_set) != linked

    # The reviewer's answer is an AI-powered finding with its id and the affected criterion.
    wire = public_model_to_wire(CheckResult.model_validate(projected))
    findings = cast(list[Mapping[str, Any]], wire["findings"])
    (raised,) = [
        row
        for row in findings
        if row["origin"] == FindingOrigin.SEMANTIC_MODEL_DERIVED
        and row["kind"] == "task_requirement_unmet"
    ]
    finding_id = cast(str, raised["finding_id"])
    assert _CRITERION in cast(str, raised["detail"])
    assert obligation in json.dumps(raised["subject_refs"]) or result in json.dumps(
        raised["subject_refs"]
    )
    for host in ("codex", "claude", "cursor"):
        text = _result_text(wire, host_profile=host)
        assert finding_id in text, host
        assert _CRITERION in text, host
    model = CheckResult.model_validate(projected).root
    assert type(model) is CheckSuccessModel
    cli = render_human_check(model)
    assert finding_id in cli and _CRITERION in cli
