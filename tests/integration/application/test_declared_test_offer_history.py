"""A declared test is offered once per digest, then again only at the closing review (#1220).

Real checks through the application: the reviewer builds the real case from the frozen ledger
with the service's pinned declared test, and its provider-bound manifest is recorded on
``check_recorded`` exactly as the reviewer conversation records it. The next check's frozen case
derives the digests already offered from those records, so recovery and replay agree.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from typing import cast

import pytest

from builders.projection_workflow import build_projection_application, frontier_json, request_base
from builders.start_application import protocol_id, start_request
from finishup.application.check import FinalSemanticEvaluation
from finishup.application.semantic_case import (
    build_semantic_case,
    semantic_case_packet_view,
    semantic_case_to_prepared_payload,
)
from finishup.domain.findings import Finding
from finishup.domain.privacy import ReviewContextProfile, ReviewSelectionPolicy
from finishup.domain.values import JsonObject, freeze_json
from finishup.kernel.declared_checks import DECLARED_TEST_QUESTION, DeclaredTest
from finishup.ports.ledger import CheckCommitResult, FrozenCase
from finishup.ports.semantic import SemanticCase, SemanticJudgment
from finishup.protocol.models import (
    CheckRequest,
    PublishWorkRequest,
    SemanticReason,
    SemanticStatus,
)
from integration.application.test_review_dialogue_workflow import (
    _provenance,  # pyright: ignore[reportPrivateUsage]
)

pytestmark = pytest.mark.anyio


@dataclass
class _Reviewer:
    tests: tuple[DeclaredTest, ...]
    final: bool = False
    cases: list[SemanticCase] = field(default_factory=lambda: [])
    offered: list[tuple[str, ...]] = field(default_factory=lambda: [])

    async def __call__(
        self,
        frozen: FrozenCase,
        findings: tuple[Finding, ...],
        runtime: object | None = None,
        lineage_evaluation: object | None = None,
    ) -> FinalSemanticEvaluation:
        del runtime, lineage_evaluation
        self.offered.append(frozen.case.offered_test_digests)
        case = build_semantic_case(
            case_id=protocol_id("cas_", 7100 + len(self.cases)),
            frozen_case=frozen.case,
            dependency_digest=frozen.lease.dependency_digest,
            findings=findings,
            review_context_profile=ReviewContextProfile.GOAL_AWARE,
            review_selection=ReviewSelectionPolicy.for_profile(ReviewContextProfile.GOAL_AWARE),
            policy_id=protocol_id("pvy_", 7100),
            policy_version="1",
            final_review=self.final,
            declared_tests=self.tests,
        )
        self.cases.append(case)
        prepared = json.loads(
            semantic_case_to_prepared_payload(case, frozenset(item.item_id for item in case.items))
        )
        view = semantic_case_packet_view(case)
        return FinalSemanticEvaluation(
            SemanticStatus.SUCCEEDED,
            SemanticReason.SEMANTIC_COMPLETED,
            judgment=SemanticJudgment("no_material_discrepancy", ()),
            provenance=_provenance(7110 + len(self.cases)),
            case_prior_finding_refs=view.prior_finding_refs,
            case_citable_refs=view.citable_refs,
            provider_input_manifest=cast(
                JsonObject, freeze_json(prepared["review_packet"]["provider_input_manifest"])
            ),
        )


async def test_a_declared_test_is_offered_once_per_digest_and_at_the_closing_review() -> None:
    seed = 7000
    first = DeclaredTest("dt1", "/tmp/test_stop.py", "sha256:" + "1" * 64, "res_criterion")
    reviewer = _Reviewer((first,))
    app, _policy = await build_projection_application("optional", seed=seed, max_findings=5)
    app = replace(app, semantic_evaluator=reviewer)
    started = await app.start(start_request(seed, title="Declared tests"))
    ids = {"session_id": started.session_id, "writer_id": started.writer_id}
    published = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **request_base(protocol_id("req_", seed + 10)),
                **ids,
                "expected_frontier": frontier_json(started.frontier),
                "event_drafts": [
                    {
                        "event_id": protocol_id("evt_", seed + 2),
                        "schema": {"name": "obligation_published", "version": "1.0.0"},
                        "occurred_at": "2026-10-25T12:00:00.000Z",
                        "causal_parents": [],
                        "payload": {
                            "obligation_id": protocol_id("obl_", seed + 1),
                            "description": "Generation stops at EOS.",
                            "acceptance_criteria": "Stop at EOS once min_new_tokens is reached.",
                            "evidence_expectation": "The stop-rule test passes.",
                            "status": "open",
                        },
                        "artifact_refs": [],
                        "evidence_refs": [],
                    },
                    {
                        "event_id": protocol_id("evt_", seed + 4),
                        "schema": {"name": "action_recorded", "version": "1.0.0"},
                        "occurred_at": "2026-10-25T12:00:00.000Z",
                        "causal_parents": [],
                        "payload": {
                            "action_id": protocol_id("act_", seed + 5),
                            "action_kind": "edit",
                            "description": "Changed the stopping rule.",
                        },
                        "artifact_refs": [],
                        "evidence_refs": [],
                    },
                ],
            }
        )
    )
    frontier = published.result_frontier

    async def check(number: int, *, final: bool) -> SemanticCase:
        nonlocal frontier
        reviewer.final = final
        checked = await app.check(
            CheckRequest.model_validate(
                {
                    **request_base(protocol_id("req_", seed + number)),
                    **ids,
                    "expected_frontier": frontier_json(frontier),
                    "mode": "semantic_required",
                    "max_findings": "5",
                    "final_review": final,
                }
            )
        )
        assert type(checked) is CheckCommitResult, type(checked)
        assert checked.semantic_status is SemanticStatus.SUCCEEDED, (
            number,
            checked.semantic_reason,
        )
        frontier = checked.result_frontier
        return reviewer.cases[-1]

    offered = await check(1, final=False)
    assert offered.packet.declared_tests == (first,)
    assert offered.question_set[-1] == DECLARED_TEST_QUESTION
    # The recorded review's manifest lets the next frozen case know the digest was offered.
    unchanged = await check(2, final=False)
    assert reviewer.offered[-1] == (first.content_digest,)
    assert unchanged.packet.declared_tests == ()
    assert DECLARED_TEST_QUESTION not in unchanged.question_set
    assert unchanged.packet.input_manifest is not None
    assert not unchanged.packet.input_manifest.test_check_offered
    # A changed digest is offered at the next routine review; then the closing review asks again.
    changed = replace(first, content_digest="sha256:" + "2" * 64)
    reviewer.tests = (changed,)
    assert (await check(3, final=False)).packet.declared_tests == (changed,)
    closing = await check(4, final=True)
    assert reviewer.offered[-1] == tuple(sorted((first.content_digest, changed.content_digest)))
    assert closing.packet.declared_tests == (changed,)
    assert closing.question_set[-1] == DECLARED_TEST_QUESTION
