"""The excerpt byte budget binds, not a 16-count constant (issue #907 Phase 1b).

Privacy policy 1.2.0 lifts the Expanded preset's excerpt count to the protocol maximum while its
byte budget (16 KiB per excerpt, 128 KiB in total) stays. A policy approved under the 1.1.0 preset
keeps its 16-excerpt limit until its owner re-approves.
"""

from __future__ import annotations

from builders.policy_cases import (
    claim_record,
    clm,
    evd,
    evidence_record,
    make_case,
    obl,
    obligation_record,
    plan_record,
)
from finishup.application.semantic_case import build_semantic_case
from finishup.domain.events import (
    ClaimKind,
    ClaimRecordedPayload,
    EvidenceKind,
    EvidenceRecordedPayload,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
)
from finishup.domain.privacy import ReviewContextProfile, ReviewSelectionPolicy
from finishup.domain.values import EvidenceId, timestamp_from_string
from finishup.kernel.deterministic_checks import DeterministicCase
from finishup.kernel.projections import EvidenceProjectionRecord
from finishup.ports.semantic import SemanticCase
from finishup.protocol.coverage import EvidenceImmutability
from finishup.protocol.models import MAX_REVIEW_EXCERPTS

_ITEMS = 40


def _case(count: int = _ITEMS, *, description: str | None = None) -> DeterministicCase:
    evidence: dict[EvidenceId, EvidenceProjectionRecord] = {}
    for index in range(1, count + 1):
        ref = evd(index)
        evidence[ref] = evidence_record(
            EvidenceRecordedPayload(
                evidence_id=ref,
                evidence_kind=EvidenceKind.TEST_RESULT,
                strength=EvidenceImmutability.METADATA_ONLY,
                observed_at=timestamp_from_string("2026-07-01T00:00:00.000Z"),
                description=description or f"test run {index}: 12 passed, 0 failed",
            ),
            index + 3,
        )
    plan = plan_record(PlanPublishedPayload(1, "Ship the review packet", (obl(1),)), 1)
    obligation = obligation_record(
        ObligationPublishedPayload(obl(1), "Build it", "tests pass", ObligationStatus.OPEN), 2
    )
    claim = claim_record(
        ClaimRecordedPayload(
            clm(1),
            ClaimKind.COMPLETION,
            "Work is complete",
            tuple(evidence),
            obligation_refs=(obl(1),),
        ),
        3,
    )
    return make_case(
        plans={1: plan},
        obligations={obl(1): obligation},
        claims={clm(1): claim},
        evidence=evidence,
        extra_refs=(clm(1), obl(1), *evidence),
    )


def _build(selection: ReviewSelectionPolicy) -> SemanticCase:
    return build_semantic_case(
        case_id="cas_90700000-0000-4000-8000-000000000001",
        frozen_case=_case(),
        dependency_digest="sha256:" + "b" * 64,
        findings=(),
        review_context_profile=ReviewContextProfile.EXPANDED,
        review_selection=selection,
        policy_id="pvy_90700000-0000-4000-8000-000000000001",
        policy_version="1",
    )


def _excerpt_bytes(semantic: SemanticCase) -> int:
    return sum(item.content_bytes for item in semantic.items if item.section == "excerpt")


def test_forty_small_items_are_all_selected_under_the_current_expanded_preset() -> None:
    selection = ReviewSelectionPolicy.for_profile(ReviewContextProfile.EXPANDED)
    assert selection.max_excerpts == MAX_REVIEW_EXCERPTS == 64
    assert selection.max_total_excerpt_bytes == 131_072

    semantic = _build(selection)

    assert len(semantic.packet.targeted_excerpts) == _ITEMS
    # Neither limit bound: the count is below the protocol maximum and the bytes below budget.
    assert _ITEMS < selection.max_excerpts
    assert _excerpt_bytes(semantic) < selection.max_total_excerpt_bytes
    assert "content_unselected" not in semantic.packet.coverage.known_gaps


def test_an_expanded_policy_approved_under_the_1_1_0_preset_still_stops_at_16() -> None:
    legacy = ReviewSelectionPolicy.for_profile(
        ReviewContextProfile.EXPANDED, preset_version="1.1.0"
    )
    assert legacy.max_excerpts == 16

    semantic = _build(legacy)

    assert len(semantic.packet.targeted_excerpts) == 16


def test_assisted_keeps_16_under_every_preset_version() -> None:
    for version in ("1.1.0", "1.2.0"):
        assisted = ReviewSelectionPolicy.for_profile(
            ReviewContextProfile.ASSISTED, preset_version=version
        )
        assert assisted.max_excerpts == 16
        assert (assisted.max_excerpt_bytes, assisted.max_total_excerpt_bytes) == (16_384, 131_072)
