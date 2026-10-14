"""Finding prose wider than one case item stays a bounded, honest case (issue #858).

A local finding may cite up to 64 subjects; one AI-powered review case item links at most 16.
``ledger_stale_or_incomplete`` reaches that width in ordinary work — every unresolved coverage gap
adds a subject — and the complete tuple used to reach ``SemanticCaseItem`` and fail its bound.
Case construction then died before dispatch as ``coordinator_failure`` with no review at all.
"""

from __future__ import annotations

from collections.abc import Sequence

import pytest

from builders.policy_cases import (
    clm,
    evd,
    evidence_record,
    finding_record,
    make_case,
    obl,
    obligation_record,
    plan_record,
    record,
)
from yoetz.application.check import (
    CheckScope,
    allocate_findings,
    prior_finding_ids,
    run_deterministic_policies,
)
from yoetz.application.semantic_case import (
    build_semantic_case,
    semantic_case_to_prepared_payload,
)
from yoetz.domain.events import (
    ClaimKind,
    ClaimRecordedPayload,
    EvidenceKind,
    EvidenceRecordedPayload,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
)
from yoetz.domain.findings import Finding, FindingKind
from yoetz.domain.privacy import ReviewContextProfile, ReviewSelectionPolicy
from yoetz.domain.receipts import SEMANTIC_CASE_FINDING_REFS_OVER_LIMIT_GAP
from yoetz.domain.values import EvidenceId, FindingId, timestamp_from_string
from yoetz.kernel.deterministic_checks import CaseGap, DeterministicCase
from yoetz.kernel.projections import EvidenceProjectionRecord, FindingProjectionRecord
from yoetz.ports.semantic import MAX_SEMANTIC_ITEM_SUBJECT_REFS, SemanticCase
from yoetz.protocol.coverage import EvidenceImmutability, LedgerFreshness
from yoetz.protocol.ids import IdKind, new_id
from yoetz.protocol.models import DataCategory

_PACKS = ("research-evidence/0.2.0", "work-integrity/0.3.0")
_PROSE_PROFILES = (
    ReviewContextProfile.GOAL_AWARE,
    ReviewContextProfile.ASSISTED,
    ReviewContextProfile.EXPANDED,
)
_OVER_LIMIT_WIDTHS = (MAX_SEMANTIC_ITEM_SUBJECT_REFS + 1, 21)


class _Ids:
    def new(self, kind: IdKind) -> str:
        return new_id(kind)


def _case(
    width: int, findings: dict[FindingId, FindingProjectionRecord] | None = None
) -> DeterministicCase:
    """Ordinary task material plus one freshness gap naming ``width`` public subjects.

    The gap makes the work-integrity pack emit one ``ledger_stale_or_incomplete`` finding whose
    subject tuple is exactly ``width`` wide; the material keeps the pack applicable and gives the
    run its ordinary narrow findings beside it.
    """

    plan = plan_record(PlanPublishedPayload(1, "Ship the review packet", (obl(1),)), 1)
    obligation = obligation_record(
        ObligationPublishedPayload(
            obl(1), "Build the real packet", "tests pass", ObligationStatus.OPEN
        ),
        2,
    )
    claim = record(
        ClaimRecordedPayload(
            clm(1),
            ClaimKind.COMPLETION,
            "Work is complete",
            (evd(1),),
            obligation_refs=(obl(1),),
        ),
        3,
    )
    evidence: dict[EvidenceId, EvidenceProjectionRecord] = {
        evd(1): evidence_record(
            EvidenceRecordedPayload(
                evd(1),
                EvidenceKind.TEST_RESULT,
                EvidenceImmutability.METADATA_ONLY,
                timestamp_from_string("2026-07-01T00:00:00.000Z"),
                description="test output: 1 failed assertion",
            ),
            4,
        )
    }
    subjects = tuple(sorted((clm(number) for number in range(100, 100 + width)), key=str.encode))
    return make_case(
        plans={1: plan},
        obligations={obl(1): obligation},
        claims={clm(1): claim},
        evidence=evidence,
        findings=findings,
        extra_refs=(clm(1), obl(1), evd(1)),
        gaps=(CaseGap("missing_ref:bulk", "missing_ref", subjects),),
    )


def _wide_findings(case: DeterministicCase, width: int) -> tuple[Finding, ...]:
    assessments, _ = run_deterministic_policies(case, CheckScope((), ()), _PACKS)
    findings = allocate_findings(
        _Ids(),
        tuple(item.candidate for item in assessments),
        prior_finding_ids(case.projection),
    )
    wide = [item for item in findings if item.kind is FindingKind.LEDGER_STALE_OR_INCOMPLETE]
    assert len(wide) == 1 and len(wide[0].subject_refs) == width
    return findings


def _build(
    case: DeterministicCase, profile: ReviewContextProfile, findings: Sequence[Finding]
) -> SemanticCase:
    return build_semantic_case(
        case_id="cas_10000000-0000-4000-8000-000000000001",
        frozen_case=case,
        dependency_digest="sha256:" + "b" * 64,
        findings=findings,
        review_context_profile=profile,
        review_selection=ReviewSelectionPolicy.for_profile(profile),
        policy_id="pvy_10000000-0000-4000-8000-000000000001",
        policy_version="1",
    )


def _wide(findings: Sequence[Finding]) -> Finding:
    return next(item for item in findings if item.kind is FindingKind.LEDGER_STALE_OR_INCOMPLETE)


def _prose_items(semantic: SemanticCase, finding_ref: str) -> list[str]:
    return [
        item.item_id
        for item in semantic.items
        if item.section in {"deterministic_summary", "deterministic_detail"}
        and item.source_ref == finding_ref
    ]


def _omission_keys(semantic: SemanticCase, finding_ref: str) -> set[tuple[DataCategory, str]]:
    return {
        (item.category, item.reason)
        for item in semantic.packet.omissions
        if item.subject_ref == finding_ref
    }


@pytest.mark.parametrize("profile", _PROSE_PROFILES)
def test_finding_at_the_item_bound_is_carried_whole(profile: ReviewContextProfile) -> None:
    width = MAX_SEMANTIC_ITEM_SUBJECT_REFS
    case = _case(width)
    findings = _wide_findings(case, width)
    semantic = _build(case, profile, findings)
    finding_ref = str(_wide(findings).finding_id)

    assessment = next(
        item
        for item in semantic.packet.deterministic_assessments
        if item.finding_ref == finding_ref
    )
    assert len(assessment.subject_refs) == width
    assert assessment.summary_item_id is not None and assessment.detail_item_id is not None
    assert set(_prose_items(semantic, finding_ref)) == {
        assessment.summary_item_id,
        assessment.detail_item_id,
    }
    summary = next(item for item in semantic.items if item.item_id == assessment.summary_item_id)
    assert len(summary.linked_subject_refs) == width
    assert not _omission_keys(semantic, finding_ref)
    assert SEMANTIC_CASE_FINDING_REFS_OVER_LIMIT_GAP not in semantic.packet.coverage.known_gaps


@pytest.mark.parametrize("width", _OVER_LIMIT_WIDTHS)
@pytest.mark.parametrize("profile", _PROSE_PROFILES)
def test_finding_over_the_item_bound_is_an_explicit_bounded_omission(
    profile: ReviewContextProfile, width: int
) -> None:
    case = _case(width)
    findings = _wide_findings(case, width)
    semantic = _build(case, profile, findings)
    finding_ref = str(_wide(findings).finding_id)

    # The case still builds, the finding keeps its identity, and nothing pretends to carry it.
    assert finding_ref in semantic.local_check_refs
    assert not _prose_items(semantic, finding_ref)
    assert finding_ref not in {
        item.finding_ref for item in semantic.packet.deterministic_assessments
    }
    assert _omission_keys(semantic, finding_ref) == {
        (DataCategory.FINDING_SUMMARY, "not_selected"),
        (DataCategory.BOUNDED_STRUCTURAL_METADATA, "not_selected"),
    }
    assert SEMANTIC_CASE_FINDING_REFS_OVER_LIMIT_GAP in semantic.packet.coverage.known_gaps
    assert semantic.packet.coverage.ledger_freshness is LedgerFreshness.PARTIAL
    # No linked-ref catalog anywhere in the case exceeds the bound the port enforces.
    assert all(
        len(item.linked_subject_refs) <= MAX_SEMANTIC_ITEM_SUBJECT_REFS for item in semantic.items
    )
    # The other local findings of the same run are unaffected.
    narrow = [item for item in findings if item.finding_id != _wide(findings).finding_id]
    assessed = {item.finding_ref for item in semantic.packet.deterministic_assessments}
    assert {str(item.finding_id) for item in narrow} <= assessed
    # The prepared payload names the wide finding as citable even though no item carries it.
    included = {item.item_id for item in semantic.items}
    payload = semantic_case_to_prepared_payload(semantic, included)
    assert finding_ref.encode("ascii") in payload


@pytest.mark.parametrize("width", _OVER_LIMIT_WIDTHS)
def test_over_limit_omission_is_deterministic(width: int) -> None:
    case = _case(width)
    findings = _wide_findings(case, width)
    left = _build(case, ReviewContextProfile.EXPANDED, findings)
    right = _build(case, ReviewContextProfile.EXPANDED, findings)
    assert left.case_digest == right.case_digest
    assert left.packet.omissions == right.packet.omissions


@pytest.mark.parametrize("width", _OVER_LIMIT_WIDTHS)
def test_structural_profile_skips_only_the_assessment(width: int) -> None:
    case = _case(width)
    findings = _wide_findings(case, width)
    semantic = _build(case, ReviewContextProfile.STRUCTURAL, findings)
    finding_ref = str(_wide(findings).finding_id)

    # Prose was never selected, so its absence is not a capacity gap; the projected assessment
    # still skips itself for the same width exactly as before.
    assert _omission_keys(semantic, finding_ref) == {
        (DataCategory.BOUNDED_STRUCTURAL_METADATA, "not_selected")
    }
    assert SEMANTIC_CASE_FINDING_REFS_OVER_LIMIT_GAP not in semantic.packet.coverage.known_gaps


@pytest.mark.parametrize("profile", _PROSE_PROFILES)
def test_persistent_wide_finding_on_recheck_keeps_its_recorded_id(
    profile: ReviewContextProfile,
) -> None:
    width = 21
    first_case = _case(width)
    first_findings = _wide_findings(first_case, width)
    recorded = {
        item.finding_id: finding_record(item, 5 + index)
        for index, item in enumerate(first_findings)
    }
    second_case = _case(width, findings=recorded)
    second_findings = _wide_findings(second_case, width)
    assert {item.finding_id for item in first_findings} <= {
        item.finding_id for item in second_findings
    }
    semantic = _build(second_case, profile, second_findings)
    finding_ref = str(_wide(first_findings).finding_id)

    assert finding_ref in semantic.local_check_refs
    assert not _prose_items(semantic, finding_ref)
    assert _omission_keys(semantic, finding_ref) == {
        (DataCategory.FINDING_SUMMARY, "not_selected"),
        (DataCategory.BOUNDED_STRUCTURAL_METADATA, "not_selected"),
    }
    assert SEMANTIC_CASE_FINDING_REFS_OVER_LIMIT_GAP in semantic.packet.coverage.known_gaps
