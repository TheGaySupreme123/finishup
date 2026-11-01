"""Stable finding ranking, cap, diversity, coverage, and verdict tests."""

from __future__ import annotations

from dataclasses import replace

import pytest

from finishup.domain.findings import (
    FINDING_KIND_TRAITS,
    CheckVerdict,
    Finding,
    FindingKind,
    FindingOrigin,
    SamplingParams,
    SemanticDispatchKind,
    SemanticProvenance,
)
from finishup.domain.values import Frontier, finding_id, obligation_id
from finishup.kernel.ranking import CheckCompleteness, RankingContext, rank_findings
from finishup.protocol.coverage import (
    ArtifactObservation,
    AuthorshipAssurance,
    CheckType,
    Coverage,
    EvidenceImmutability,
    LedgerFreshness,
    PublicationChannel,
)
from finishup.protocol.errors import ProtocolValueError
from finishup.protocol.models import SemanticReason, SemanticStatus

_DIGEST = "sha256:" + "1" * 64
_COMMITMENT = "hmac-sha256:" + "2" * 64


def _coverage(
    *,
    observation: ArtifactObservation = ArtifactObservation.ARTIFACT_VERIFIED,
    immutability: EvidenceImmutability = EvidenceImmutability.IMMUTABLE_SNAPSHOT,
    freshness: LedgerFreshness = LedgerFreshness.CURRENT,
    assurance: AuthorshipAssurance = AuthorshipAssurance.SERVICE_AUTHENTICATED,
    checks: tuple[CheckType, ...] = (CheckType.DETERMINISTIC,),
    gaps: tuple[str, ...] = (),
) -> Coverage:
    return Coverage(
        publication_channels=(PublicationChannel.ENGINE_DERIVED,),
        authorship_assurance=assurance,
        artifact_observation=observation,
        evidence_immutability=immutability,
        ledger_freshness=freshness,
        check_types=checks,
        known_gaps=gaps,
    )


def _provenance(index: int) -> SemanticProvenance:
    suffix = f"{index:012d}"
    return SemanticProvenance(
        provider="openai",
        endpoint_profile_id="review.default",
        endpoint_profile_version="1.0.0",
        model="gpt-5.4",
        sdk_version="2.46.0",
        prompt_digest=_DIGEST,
        schema_digest=_DIGEST,
        policy_digest=_DIGEST,
        privacy_policy_digest=_DIGEST,
        sampling_params=SamplingParams(max_output_tokens=512),
        latency_ms=1,
        semantic_attempt_id=f"att_00000000-0000-4000-8000-{suffix}",
        dispatch_kind=SemanticDispatchKind.EXTERNAL,
        privacy_receipt_id=f"egr_00000000-0000-4000-8000-{suffix}",
        status=SemanticStatus.SUCCEEDED,
        reason=SemanticReason.SEMANTIC_COMPLETED,
        egress_authorization_id=f"aut_00000000-0000-4000-8000-{suffix}",
        request_commitment=_COMMITMENT,
    )


def _finding(
    index: int,
    *,
    kind: FindingKind = FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS,
    origin: FindingOrigin = FindingOrigin.DETERMINISTIC,
    coverage: Coverage | None = None,
) -> Finding:
    policy_id = (
        "coordination"
        if kind is FindingKind.COORDINATION_OVERLAP
        else "work-integrity"
        if kind
        in {
            FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS,
            FindingKind.REQUESTED_ITEM_NEVER_ATTEMPTED,
            FindingKind.FAILED_WORK_OMITTED,
            FindingKind.CLAIM_WITHOUT_ADMISSIBLE_EVIDENCE,
            FindingKind.RESULT_WITHOUT_ACTION,
            FindingKind.ACTION_WITHOUT_RESULT,
            FindingKind.STALE_EVIDENCE_FOR_CHANGED_STATE,
            FindingKind.CONTRADICTORY_CLAIMS_UNRESOLVED,
            FindingKind.LEDGER_STALE_OR_INCOMPLETE,
            FindingKind.WEAK_OR_STALE_RESPONSE,
        }
        else "research-evidence"
    )
    suffix = f"{index:012d}"
    return Finding(
        finding_id=finding_id(f"fnd_00000000-0000-4000-8000-{suffix}"),
        kind=kind,
        origin=origin,
        priority=FINDING_KIND_TRAITS[kind][0],
        summary="Registered finding",
        detail="Registered detail",
        subject_refs=(obligation_id("obl_00000000-0000-4000-8000-000000000001"),),
        policy_id=policy_id,
        policy_version="0.1.0",
        subject_frontier=Frontier(1, _DIGEST),
        coverage=_coverage() if coverage is None else coverage,
        provenance=_provenance(index) if origin is FindingOrigin.SEMANTIC_MODEL_DERIVED else None,
    )


def test_ordering_by_priority_actionability_evidence_id() -> None:
    weak = _coverage(
        observation=ArtifactObservation.PUBLISHED_ONLY,
        immutability=EvidenceImmutability.MUTABLE_REFERENCE,
        freshness=LedgerFreshness.PARTIAL,
        assurance=AuthorshipAssurance.SELF_ASSERTED,
        checks=(CheckType.NONE,),
        gaps=("weak_material",),
    )
    context_coverage = replace(
        weak,
        check_types=(CheckType.DETERMINISTIC,),
    )
    first = _finding(2, coverage=weak)
    second = _finding(1, coverage=weak)
    priority_two = _finding(3, kind=FindingKind.RESULT_WITHOUT_ACTION, coverage=weak)
    ranked = rank_findings(
        (priority_two, first, second),
        (),
        RankingContext(context_coverage, CheckCompleteness.COVERAGE_INCOMPLETE),
        3,
    )
    assert ranked.findings == (second, first, priority_two)


def test_deterministic_out_ranks_semantic_on_ties() -> None:
    deterministic = _finding(2)
    semantic = _finding(1, origin=FindingOrigin.SEMANTIC_MODEL_DERIVED)
    ranked = rank_findings(
        (deterministic,),
        (semantic,),
        RankingContext(_coverage(), CheckCompleteness.COMPLETE),
        2,
    )
    assert ranked.findings == (deterministic, semantic)


def test_max_findings_cap_and_suppressed_count() -> None:
    findings = tuple(_finding(index) for index in range(1, 5))
    ranked = rank_findings(
        findings,
        (),
        RankingContext(_coverage(), CheckCompleteness.COMPLETE),
        2,
    )
    assert len(ranked.findings) == 2
    assert ranked.suppressed_count == 2
    with pytest.raises(ProtocolValueError, match="invalid_ranked_findings"):
        rank_findings(findings, (), RankingContext(_coverage(), CheckCompleteness.COMPLETE), 11)
    with pytest.raises(ProtocolValueError, match="invalid_ranked_findings"):
        rank_findings(
            (findings[0], findings[0]),
            (),
            RankingContext(_coverage(), CheckCompleteness.COMPLETE),
            2,
        )


def test_verdict_selection_from_selection_and_context() -> None:
    actionable = _finding(1)
    gap_coverage = replace(_coverage(), known_gaps=("semantic_unavailable",))
    assert (
        rank_findings(
            (actionable,),
            (),
            RankingContext(_coverage(), CheckCompleteness.REQUIRED_INCOMPLETE),
            1,
        ).verdict
        is CheckVerdict.INCOMPLETE_CHECK
    )
    assert (
        rank_findings(
            (actionable,),
            (),
            RankingContext(_coverage(), CheckCompleteness.COMPLETE),
            1,
        ).verdict
        is CheckVerdict.ACTION_REQUIRED
    )
    assert (
        rank_findings(
            (),
            (),
            RankingContext(gap_coverage, CheckCompleteness.COVERAGE_INCOMPLETE),
            1,
        ).verdict
        is CheckVerdict.INSUFFICIENT_COVERAGE
    )
    assert (
        rank_findings(
            (),
            (),
            RankingContext(_coverage(), CheckCompleteness.COMPLETE),
            1,
        ).verdict
        is CheckVerdict.NO_ISSUE_DETECTED
    )


def test_result_coverage_uses_full_pre_cap_context() -> None:
    gap_coverage = replace(_coverage(), known_gaps=("suppressed_weak_material",))
    weak = _finding(2, coverage=gap_coverage)
    strong = _finding(1)
    result = rank_findings(
        (strong, weak),
        (),
        RankingContext(gap_coverage, CheckCompleteness.COVERAGE_INCOMPLETE),
        1,
    )
    assert result.findings == (strong,)
    assert result.coverage is gap_coverage


def test_one_material_reviewer_challenge_slot_at_default_cap() -> None:
    deterministic = tuple(_finding(index) for index in range(1, 5))
    challenge = _finding(
        10,
        kind=FindingKind.QUESTIONABLE_FINDING_REJECTION,
        origin=FindingOrigin.SEMANTIC_MODEL_DERIVED,
    )
    selected = rank_findings(
        deterministic,
        (challenge,),
        RankingContext(_coverage(), CheckCompleteness.COMPLETE),
        3,
    )
    assert challenge in selected.findings
    assert len(selected.findings) == 3
    assert selected.suppressed_count == 2
    max_one = rank_findings(
        deterministic,
        (challenge,),
        RankingContext(_coverage(), CheckCompleteness.COMPLETE),
        1,
    )
    assert challenge not in max_one.findings


def test_reviewer_challenge_slots_scale_with_the_cap() -> None:
    """More than one material challenge survives when the cap has room for it.

    The rescue used to be exactly one challenge, so a reviewer that raised two or three material
    discrepancies had all but the best folded into ``suppressed_count`` — invisible, and
    indistinguishable from a reviewer that only found one. Up to half the cap is reservable now,
    which keeps local findings in the majority without discarding the rest of the review.
    """

    deterministic = tuple(_finding(index) for index in range(1, 7))
    challenges = (
        _finding(
            10,
            kind=FindingKind.MATERIAL_LIMITATION_OMITTED,
            origin=FindingOrigin.SEMANTIC_MODEL_DERIVED,
        ),
        _finding(
            11,
            kind=FindingKind.QUESTIONABLE_FINDING_REJECTION,
            origin=FindingOrigin.SEMANTIC_MODEL_DERIVED,
        ),
        _finding(
            12,
            kind=FindingKind.REQUESTED_ITEM_NEVER_ATTEMPTED,
            origin=FindingOrigin.SEMANTIC_MODEL_DERIVED,
        ),
    )
    context = RankingContext(_coverage(), CheckCompleteness.COMPLETE)

    at_six = rank_findings(deterministic, challenges, context, 6)
    semantic_at_six = [
        finding
        for finding in at_six.findings
        if finding.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED
    ]
    assert len(at_six.findings) == 6
    assert len(semantic_at_six) == 3
    assert at_six.suppressed_count == 3

    at_four = rank_findings(deterministic, challenges, context, 4)
    assert (
        len(
            [
                finding
                for finding in at_four.findings
                if finding.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED
            ]
        )
        == 2
    )
    assert len(at_four.findings) == 4

    # Local findings still hold the majority of every selection.
    for ranked in (at_six, at_four):
        deterministic_selected = [
            finding for finding in ranked.findings if finding.origin is FindingOrigin.DETERMINISTIC
        ]
        assert len(deterministic_selected) >= len(ranked.findings) // 2

    # A cap of one still admits no reserved slot at all.
    at_one = rank_findings(deterministic, challenges, context, 1)
    assert all(finding.origin is FindingOrigin.DETERMINISTIC for finding in at_one.findings)
