"""Property checks for stable, capped, coverage-preserving finding ranking."""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from yoetz.domain.findings import (
    FINDING_KIND_TRAITS,
    CheckVerdict,
    Finding,
    FindingKind,
    FindingOrigin,
    finding_policy_identity,
)
from yoetz.domain.values import Frontier, finding_id, obligation_id
from yoetz.kernel.ranking import CheckCompleteness, RankingContext, rank_findings
from yoetz.protocol.coverage import (
    ArtifactObservation,
    AuthorshipAssurance,
    CheckType,
    Coverage,
    EvidenceImmutability,
    LedgerFreshness,
    PublicationChannel,
)

_DIGEST = "sha256:" + "3" * 64
_KINDS = tuple(kind for kind in FindingKind if FINDING_KIND_TRAITS[kind][1])


def _coverage(*, gaps: tuple[str, ...] = ()) -> Coverage:
    return Coverage(
        publication_channels=(PublicationChannel.ENGINE_DERIVED,),
        authorship_assurance=AuthorshipAssurance.SERVICE_AUTHENTICATED,
        artifact_observation=ArtifactObservation.ARTIFACT_VERIFIED,
        evidence_immutability=EvidenceImmutability.IMMUTABLE_SNAPSHOT,
        ledger_freshness=LedgerFreshness.CURRENT,
        check_types=(CheckType.DETERMINISTIC,),
        known_gaps=gaps,
    )


def _finding(index: int, kind: FindingKind, coverage: Coverage) -> Finding:
    # The pack that owns each kind is the domain's decision (`finding_policy_identity`), not this
    # test's: a hardcoded id went stale when more kinds moved to the research-evidence pack and
    # the Finding constructor began refusing any other identity (`invalid_finding_policy_identity`).
    policy_id, policy_version = finding_policy_identity(kind)
    return Finding(
        finding_id=finding_id(f"fnd_00000000-0000-4000-8000-{index:012d}"),
        kind=kind,
        origin=FindingOrigin.DETERMINISTIC,
        priority=FINDING_KIND_TRAITS[kind][0],
        summary="Property finding",
        detail="Property detail",
        subject_refs=(obligation_id("obl_00000000-0000-4000-8000-000000000001"),),
        policy_id=policy_id,
        policy_version=policy_version,
        subject_frontier=Frontier(1, _DIGEST),
        coverage=coverage,
    )


@st.composite
def _finding_tuples(draw: st.DrawFn) -> tuple[Finding, ...]:
    size = draw(st.integers(min_value=0, max_value=10))
    kinds = draw(st.lists(st.sampled_from(_KINDS), min_size=size, max_size=size))
    coverage = _coverage()
    return tuple(_finding(index + 1, kind, coverage) for index, kind in enumerate(kinds))


@given(_finding_tuples(), st.data())
def test_permutation_invariance(findings: tuple[Finding, ...], data: st.DataObject) -> None:
    permuted = tuple(data.draw(st.permutations(findings)))
    context = RankingContext(_coverage(), CheckCompleteness.COMPLETE)
    assert rank_findings(findings, (), context, 3) == rank_findings(permuted, (), context, 3)


@given(_finding_tuples(), st.integers(min_value=1, max_value=10))
def test_cap_and_suppressed_count_properties(findings: tuple[Finding, ...], cap: int) -> None:
    result = rank_findings(
        findings,
        (),
        RankingContext(_coverage(), CheckCompleteness.COMPLETE),
        cap,
    )
    assert len(result.findings) == min(len(findings), cap)
    assert result.suppressed_count == len(findings) - len(result.findings)
    assert len({finding.finding_id for finding in result.findings}) == len(result.findings)


@given(st.integers(min_value=1, max_value=999_998))
def test_tie_break_is_finding_id(index: int) -> None:
    coverage = _coverage()
    first = _finding(index, FindingKind.ACTION_WITHOUT_RESULT, coverage)
    second = _finding(index + 1, FindingKind.ACTION_WITHOUT_RESULT, coverage)
    result = rank_findings(
        (second, first),
        (),
        RankingContext(coverage, CheckCompleteness.COMPLETE),
        2,
    )
    assert result.findings == (first, second)


@given(_finding_tuples())
def test_verdict_tracks_selection_and_context(findings: tuple[Finding, ...]) -> None:
    complete = rank_findings(
        findings,
        (),
        RankingContext(_coverage(), CheckCompleteness.COMPLETE),
        10,
    )
    expected = (
        CheckVerdict.ACTION_REQUIRED
        if any(FINDING_KIND_TRAITS[finding.kind][1] for finding in findings)
        else CheckVerdict.NO_ISSUE_DETECTED
    )
    assert complete.verdict is expected
    required = rank_findings(
        findings,
        (),
        RankingContext(_coverage(), CheckCompleteness.REQUIRED_INCOMPLETE),
        10,
    )
    assert required.verdict is CheckVerdict.INCOMPLETE_CHECK


@given(_finding_tuples(), st.integers(min_value=1, max_value=10))
def test_suppression_never_strengthens_coverage(findings: tuple[Finding, ...], cap: int) -> None:
    baseline = _coverage(gaps=("full_pre_cap_material",))
    weakened_findings = tuple(
        Finding(
            finding.finding_id,
            finding.kind,
            finding.origin,
            finding.priority,
            finding.summary,
            finding.detail,
            finding.subject_refs,
            finding.policy_id,
            finding.policy_version,
            finding.subject_frontier,
            baseline,
            finding.provenance,
        )
        for finding in findings
    )
    result = rank_findings(
        weakened_findings,
        (),
        RankingContext(baseline, CheckCompleteness.COVERAGE_INCOMPLETE),
        cap,
    )
    assert result.coverage == baseline
