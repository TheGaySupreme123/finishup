"""One check answers the reviewer's own request and asks again (issue #1047).

The real application, ledger and check commit with a hermetic reviewer that builds the real review
case: the first packet has room for one excerpt and carries the newer of two recorded test
outputs, the reviewer concludes ``insufficient_packet`` naming the older one, and inside the same
check Yoetz sends the case again with that output ranked first. The check records the reviewer's
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
from yoetz.application.check import FinalSemanticEvaluation, check_internal_json
from yoetz.application.missing_for_assessment import ReviewFollowUp
from yoetz.application.semantic_case import (
    assemble_filtered_review_packet,
    bounded_case_envelope,
    build_semantic_case,
    semantic_case_packet_view,
)
from yoetz.domain.findings import Finding, SemanticDispatchKind, SemanticProvenance
from yoetz.domain.privacy import ReviewContextProfile, ReviewSelectionPolicy
from yoetz.domain.review_input_render import render_review_input_manifest_lines
from yoetz.domain.values import JsonObject, freeze_json
from yoetz.mcp.summaries import summary_for_check
from yoetz.ports.ledger import CheckCommitResult, FrozenCase
from yoetz.ports.semantic import (
    MissingForAssessment,
    SamplingParams,
    SemanticCase,
    SemanticJudgment,
)
from yoetz.protocol.canonical import canonical_encode, strict_json_parse
from yoetz.protocol.models import (
    CheckRequest,
    PublishWorkRequest,
    ReceiptRequest,
    ReviewInputManifestModel,
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


async def test_one_check_adds_the_requested_output_and_records_the_answer_on_it() -> None:
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
    # Two dispatches: the check's own packet, then the follow-up with the requested output.
    assert [None if item is None else item.round for item in reviewer.follow_ups] == [None, 1]
    shown = [
        {item.source_ref for item in case.items if item.section == "excerpt"}
        for case in reviewer.cases
    ]
    assert shown == [{_NEWER}, {_OLDER}]
    assert checked.semantic_status is SemanticStatus.SUCCEEDED
    assert checked.semantic_conclusion == "no_material_discrepancy"
    assert checked.missing_for_assessment == ()
    manifest = checked.review_input_manifest
    assert manifest is not None
    assert manifest["follow_up_round"] == 1
    rows = cast(tuple[JsonObject, ...], manifest["missing_inputs"])
    assert [
        (row["kind"], row["status"], tuple(cast(tuple[str, ...], row["supplied_refs"])))
        for row in rows
    ] == [("verification_output", "supplied", (_OLDER,))]

    # The check wire (MCP structured content and the CLI) carries the round; the CLI renders it
    # from the public model exactly as the receipt does.
    wire = check_internal_json(checked)
    public = ReviewInputManifestModel.model_validate(
        strict_json_parse(canonical_encode(wire["review_input_manifest"]))
    )
    assert public.follow_up_round == 1
    cli_lines = render_review_input_manifest_lines(public.model_dump(mode="json", by_alias=True))
    assert "follow-up round 1 of 3" in cli_lines[0]
    assert "follow-up round 1 of 3" in summary_for_check(wire)

    for offset, receipt_format in enumerate(("json", "markdown", "text")):
        receipt = await app.receipt(
            ReceiptRequest.model_validate(
                {
                    **request_base(protocol_id("req_", _SEED + 20 + offset)),
                    "task_id": started.task_id,
                    "session_id": started.session_id,
                    "writer_id": started.writer_id,
                    "expected_frontier": frontier_json(checked.result_frontier),
                    "format": receipt_format,
                    "include": "standard",
                    "redaction_profile": "full_local",
                }
            )
        )
        rendered = str(receipt)
        assert "follow-up round 1 of 3" in rendered
        assert "verification_output=supplied; targets 1; supplied 1" in rendered
