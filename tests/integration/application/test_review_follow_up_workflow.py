"""An insufficient review is one dispatch; the request returns to the agent (#1118 unit 4).

The automatic in-check follow-up of issue #1047 is deleted.

The real application, ledger and check commit with a hermetic reviewer that builds the real review
case: the first packet has room for one excerpt and carries the newer of two recorded test
outputs, the reviewer concludes ``insufficient_packet`` naming the older one, and inside the same
check FinishUP sends the case again with that output ranked first. The check records the reviewer's
answer on the follow-up packet, and its manifest, the check summary and the receipt say which
round ran and what was added.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import cast

import pytest

from builders.projection_workflow import (
    build_projection_application,
    frontier_json,
    request_base,
)
from builders.start_application import protocol_id, start_request
from finishup.application.check import FinalSemanticEvaluation, check_internal_json
from finishup.application.missing_for_assessment import ReviewFollowUp
from finishup.application.semantic_case import (
    assemble_filtered_review_packet,
    bounded_case_envelope,
    build_semantic_case,
    semantic_case_packet_view,
)
from finishup.domain.findings import Finding, SemanticDispatchKind, SemanticProvenance
from finishup.domain.privacy import ReviewContextProfile, ReviewSelectionPolicy
from finishup.domain.values import JsonObject, freeze_json
from finishup.ports.ledger import CheckCommitResult, FrozenCase
from finishup.ports.semantic import (
    MissingForAssessment,
    SamplingParams,
    SemanticCase,
    SemanticJudgment,
)
from finishup.protocol.canonical import strict_json_parse
from finishup.protocol.models import (
    CheckRequest,
    PublishWorkRequest,
    SemanticReason,
    SemanticStatus,
)

pytestmark = pytest.mark.anyio

_DIGEST = "sha256:" + "7" * 64
_SEED = 4700
_OLDER = protocol_id("evd_", _SEED + 4)
_NEWER = protocol_id("evd_", _SEED + 6)


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
        provider_request_id=f"fake-follow-up-{seed}",
        egress_authorization_id=protocol_id("aut_", seed + 2),
        request_commitment="hmac-sha256:" + "b" * 64,
    )


def _provider_manifest(case: SemanticCase) -> JsonObject:
    """The provider-bound manifest of the exact packet, as the composition reports it."""

    envelope = strict_json_parse(bounded_case_envelope(case))
    assert isinstance(envelope, dict)
    content = {item.item_id: item.content for item in case.items}
    sent = strict_json_parse(
        assemble_filtered_review_packet(
            envelope, content_by_id=content, included_item_ids=frozenset(content)
        )
    )
    assert isinstance(sent, dict)
    packet = sent["review_packet"]
    assert isinstance(packet, dict)
    return cast(JsonObject, freeze_json(packet["provider_input_manifest"]))


@dataclass
class _Reviewer:
    """Builds the real case (one excerpt of room) and needs the older output to assess."""

    cases: list[SemanticCase] = field(default_factory=lambda: [])
    follow_ups: list[ReviewFollowUp | None] = field(default_factory=lambda: [])

    async def __call__(
        self,
        frozen: FrozenCase,
        findings: tuple[Finding, ...],
        runtime: object | None = None,
        lineage_evaluation: object | None = None,
        follow_up: ReviewFollowUp | None = None,
    ) -> FinalSemanticEvaluation:
        del runtime, lineage_evaluation
        case = build_semantic_case(
            case_id=protocol_id("cas_", _SEED),
            frozen_case=frozen.case,
            dependency_digest=frozen.lease.dependency_digest,
            findings=findings,
            review_context_profile=ReviewContextProfile.EXPANDED,
            review_selection=replace(
                ReviewSelectionPolicy.for_profile(ReviewContextProfile.EXPANDED), max_excerpts=1
            ),
            policy_id=protocol_id("pvy_", _SEED),
            policy_version="1",
            follow_up=follow_up,
        )
        self.cases.append(case)
        self.follow_ups.append(follow_up)
        excerpts = frozenset(item.source_ref for item in case.items if item.section == "excerpt")
        judgment = (
            SemanticJudgment("no_material_discrepancy", (), review_summary="Both runs read.")
            if _OLDER in excerpts
            else SemanticJudgment(
                "insufficient_packet",
                (),
                missing_for_assessment=(
                    MissingForAssessment(
                        "verification_output", (_OLDER,), "The first run's output."
                    ),
                ),
                review_summary="The first run's output is not in the packet.",
            )
        )
        view = semantic_case_packet_view(case)
        return FinalSemanticEvaluation(
            SemanticStatus.SUCCEEDED,
            SemanticReason.SEMANTIC_COMPLETED,
            judgment=judgment,
            provenance=_provenance(_SEED + 10 * len(self.cases)),
            case_prior_finding_refs=view.prior_finding_refs,
            case_citable_refs=view.citable_refs,
            case_withheld_refs=frozenset(
                omission.subject_ref
                for omission in case.packet.omissions
                if omission.reason != "not_recorded"
            ),
            provider_input_manifest=_provider_manifest(case),
            review_input_manifest=case.packet.input_manifest,
            case_excerpt_refs=excerpts,
        )


def _evidence(event: int, evidence: str, at: str, text: str) -> dict[str, object]:
    return {
        "event_id": protocol_id("evt_", event),
        "schema": {"name": "evidence_recorded", "version": "1.0.0"},
        "occurred_at": at,
        "causal_parents": [],
        "payload": {
            "evidence_id": evidence,
            "evidence_kind": "test_result",
            "strength": "metadata_only",
            "observed_at": at,
            "description": text,
        },
        "artifact_refs": [],
        "evidence_refs": [],
    }


async def test_an_insufficient_review_is_one_dispatch_and_returns_the_request() -> None:
    app, _policy = await build_projection_application("optional", seed=_SEED, max_findings=5)
    reviewer = _Reviewer()
    app = replace(app, semantic_evaluator=reviewer)
    started = await app.start(start_request(_SEED, title="Follow-up inside one check"))
    published = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **request_base(protocol_id("req_", _SEED + 1)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": frontier_json(started.frontier),
                "event_drafts": [
                    _evidence(
                        _SEED + 3,
                        _OLDER,
                        "2026-10-12T12:00:00.000Z",
                        "FAILED tests/test_api.py::test_lookup - KeyError: 'id'",
                    ),
                    _evidence(
                        _SEED + 5, _NEWER, "2026-10-12T12:01:00.000Z", "tests/test_api.py 12 passed"
                    ),
                    {
                        "event_id": protocol_id("evt_", _SEED + 7),
                        "schema": {"name": "claim_recorded", "version": "1.0.0"},
                        "occurred_at": "2026-10-12T12:02:00.000Z",
                        "causal_parents": [],
                        "payload": {
                            "claim_id": protocol_id("clm_", _SEED + 8),
                            "claim_kind": "completion",
                            "statement": "The lookup failure is fixed.",
                            "supporting_refs": [_OLDER, _NEWER],
                        },
                        "artifact_refs": [],
                        "evidence_refs": [],
                    },
                ],
            }
        )
    )

    checked = await app.check(
        CheckRequest.model_validate(
            {
                **request_base(protocol_id("req_", _SEED + 9)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": frontier_json(published.result_frontier),
                "mode": "semantic_required",
                "max_findings": "5",
            }
        )
    )

    assert type(checked) is CheckCommitResult
    # #1118 unit 4: one dispatch. No follow-up job rebuilds the packet; the reviewer's request
    # goes back to the agent with its own reason in the fenced summary.
    assert [None if item is None else item.round for item in reviewer.follow_ups] == [None]
    assert checked.semantic_status is SemanticStatus.SUCCEEDED
    assert checked.semantic_conclusion == "insufficient_packet"
    assert [item.kind for item in checked.missing_for_assessment] == ["verification_output"]
    manifest = checked.review_input_manifest
    assert manifest is not None
    assert "follow_up_round" not in manifest
    wire = check_internal_json(checked)
    assert "What the reviewer still needs" in str(wire.get("review_summary"))
