"""A linked check whose expected value shares the implementation's derivation (issue #1145).

TB4 agents' own tests derived their expected value from the same stopping rule, file glob or
sampling window as the implementation, passed, and the hidden grader failed. These cases run the
real ready composition with a hermetic reviewer answering from the scripted fake provider: a
linked command result with no manifest asks the test-quality question, and the reviewer's one
challenge with a counter-example reaches the agent with its id on every host surface.
"""

from __future__ import annotations

import json
import re
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
from finishup.application.semantic_case import build_semantic_case, semantic_case_packet_view
from finishup.application.service import Application
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

_COUNTER_EXAMPLE = (
    "Counter-example: generate with min_new_tokens=4 from a prompt whose second sampled token is "
    "EOS; single-sequence generation keeps going, the batched path stops."
)


@dataclass
class _ScriptedReviewer:
    """Builds the real case, then answers with the scripted fake provider's judgment."""

    obligation: str
    result: str
    final: bool
    seed: int = 4500
    cases: list[SemanticCase] = field(default_factory=lambda: [])

    async def __call__(
        self,
        frozen: FrozenCase,
        findings: tuple[Finding, ...],
        runtime: object | None = None,
        lineage_evaluation: object | None = None,
    ) -> FinalSemanticEvaluation:
        del runtime, lineage_evaluation
        case = build_semantic_case(
            case_id=protocol_id("cas_", self.seed + len(self.cases)),
            frozen_case=frozen.case,
            dependency_digest=frozen.lease.dependency_digest,
            findings=findings,
            review_context_profile=ReviewContextProfile.GOAL_AWARE,
            review_selection=ReviewSelectionPolicy.for_profile(ReviewContextProfile.GOAL_AWARE),
            policy_id=protocol_id("pvy_", self.seed),
            policy_version="1",
            final_review=self.final,
        )
        self.cases.append(case)
        challenge = ReviewerChallenge(
            # The phase's kind: a routine correctness concern is code_defect (#1042).
            FindingKind.EVIDENCE_DOES_NOT_SUPPORT_CLAIM if self.final else FindingKind.CODE_DEFECT,
            "The parity test derives its expected stop from the implementation's own rule",
            tuple(sorted((self.obligation, self.result))),
            "The oracle repeats `step + 1 >= min_new_tokens` from the batched loop, so it agrees "
            "with the implementation whatever the EOS convention should be.",
            "The shared rule may be the specified convention.",
            "Compare against single-sequence generation instead of the copied rule. "
            + _COUNTER_EXAMPLE,
            "act",
            "The task statement does not quote the reference implementation.",
        )
        step = scripted_success(SemanticJudgment("challenges_returned", (challenge,)))
        judgment = cast(Any, step.result).judgment
        view = semantic_case_packet_view(case)
        return FinalSemanticEvaluation(
            SemanticStatus.SUCCEEDED,
            SemanticReason.SEMANTIC_COMPLETED,
            judgment=judgment,
            provenance=_provenance(self.seed + 10),
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


async def _linked_check(
    seed: int, *, final: bool
) -> tuple[Application, _ScriptedReviewer, Mapping[str, Any]]:
    obligation = protocol_id("obl_", seed + 1)
    command = protocol_id("act_", seed + 3)
    result = protocol_id("res_", seed + 5)
    reviewer = _ScriptedReviewer(obligation, result, final)
    app, _policy = await build_projection_application("optional", seed=seed, max_findings=5)
    app = replace(app, semantic_evaluator=reviewer)
    started = await app.start(start_request(seed, title="Batched evaluation parity"))
    ids = {"session_id": started.session_id, "writer_id": started.writer_id}
    published = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **request_base(protocol_id("req_", seed + 10)),
                **ids,
                "expected_frontier": frontier_json(started.frontier),
                "event_drafts": [
                    _draft(
                        protocol_id("evt_", seed + 2),
                        "obligation_published",
                        {
                            "obligation_id": obligation,
                            "description": "Batched generation matches single-sequence output.",
                            "acceptance_criteria": "Stop at EOS once min_new_tokens is reached.",
                            "evidence_expectation": "The parity test passes.",
                            "status": "open",
                        },
                    ),
                    _draft(
                        protocol_id("evt_", seed + 6),
                        "action_recorded",
                        {
                            "action_id": protocol_id("act_", seed + 7),
                            "action_kind": "edit",
                            "description": "Changed the batched stopping rule.",
                        },
                    ),
                    _draft(
                        protocol_id("evt_", seed + 4),
                        "action_recorded",
                        {
                            "action_id": command,
                            "action_kind": "command",
                            "description": "Run the parity test.",
                            "command": "pytest tests/test_parity.py",
                            "obligation_refs": [obligation],
                        },
                    ),
                    _draft(
                        protocol_id("evt_", seed + 8),
                        "result_recorded",
                        {
                            "result_id": result,
                            "action_id": command,
                            "outcome": "success",
                            "summary": "4 passed.",
                        },
                    ),
                ],
            }
        )
    )
    body: dict[str, JsonValue] = {
        **request_base(protocol_id("req_", seed + 20)),
        **ids,
        "expected_frontier": frontier_json(published.result_frontier),
        "mode": "semantic_required",
        "max_findings": "5",
        "final_review": final,
    }
    checked = await app.check(CheckRequest.model_validate(body))
    assert type(checked) is CheckCommitResult, type(checked)
    wire = await project_case(
        app, ProjectionCase("check", ControlMethod.CHECK, body, checked), seed + 30
    )
    return app, reviewer, wire


async def test_a_linked_check_asks_for_the_expected_value_and_the_counter_example_reaches_hosts() -> (
    None
):
    _app, reviewer, projected = await _linked_check(4600, final=True)
    # The packet carried no manifest, but its obligation row links the command result.
    (case,) = reviewer.cases
    assert case.packet.verification_coverage_item_ids == ()
    assert "'Counter-example: <an input or probe to run>'" in case.question_set[-1]
    assert "agent-declared manifest" not in case.question_set[-1]

    wire = public_model_to_wire(CheckResult.model_validate(projected))
    findings = cast(list[Mapping[str, Any]], wire["findings"])
    (raised,) = [row for row in findings if row["origin"] == FindingOrigin.SEMANTIC_MODEL_DERIVED]
    finding_id = cast(str, raised["finding_id"])
    assert raised["kind"] == "evidence_does_not_support_claim"
    assert _COUNTER_EXAMPLE in cast(str, raised["detail"])
    assert reviewer.result in json.dumps(raised["subject_refs"]) or reviewer.obligation in (
        json.dumps(raised["subject_refs"])
    )

    # Codex reads structuredContent: the finding row above, id and counter-example together.
    # Claude reads the text channel; Cursor its canonical JSON copy.
    for host in ("codex", "claude", "cursor"):
        text = _result_text(wire, host_profile=host)
        assert finding_id in text, host
        assert _COUNTER_EXAMPLE in text, host
    # The CLI and terminal interface render the same finding with its id on the checklist.
    model = CheckResult.model_validate(projected).root
    assert type(model) is CheckSuccessModel
    cli = render_human_check(model)
    assert finding_id in cli
    assert _COUNTER_EXAMPLE in cli


async def test_a_routine_counter_example_is_an_advisory_note_with_its_id_on_every_host() -> None:
    _app, reviewer, projected = await _linked_check(4700, final=False)
    (case,) = reviewer.cases
    assert case.question_set[0].startswith("Review phase: routine.")
    assert "'Counter-example: <an input or probe to run>'" in case.question_set[-1]

    wire = public_model_to_wire(CheckResult.model_validate(projected))
    # A routine correctness concern is an advisory note (#1042), never a finding; its id is
    # minted from the check event (#1162) and named where readiness lists unanswered notes.
    assert wire["findings"] == []
    assert _COUNTER_EXAMPLE in cast(str, wire["review_summary"])
    readiness = cast(Mapping[str, Any], wire["closure_readiness"])
    (advisory_id,) = re.findall(
        r"evt_[0-9a-f-]+:1", cast(str, readiness["correctness_advisory_summary"])
    )
    for host in ("codex", "claude", "cursor"):
        text = _result_text(wire, host_profile=host)
        assert advisory_id in text, host
        assert _COUNTER_EXAMPLE in text, host
    model = CheckResult.model_validate(projected).root
    assert type(model) is CheckSuccessModel
    cli = render_human_check(model)
    assert advisory_id in cli
    assert _COUNTER_EXAMPLE in cli
