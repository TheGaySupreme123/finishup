"""AI-powered review cases built from a recheck whose findings are already recorded (issue #304).

A recheck re-derives a live recorded finding under its recorded id (issue #186), so the same
``fnd_`` ref arrives both in ``allowed_ids`` (frozen ledger material) and in this run's findings.
The builder used to strip the overlap from ``local_check_refs`` while still emitting the finding's
local assessment, and the boundary fence then rejected its own case — every check after
the first died with ``coordinator_failure`` before provider dispatch.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import replace

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
from yoetz.application.semantic_case import build_semantic_case
from yoetz.domain.events import (
    ClaimKind,
    ClaimRecordedPayload,
    EvidenceKind,
    EvidenceRecordedPayload,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
)
from yoetz.domain.findings import Finding
from yoetz.domain.privacy import ReviewContextProfile, ReviewSelectionPolicy
from yoetz.domain.values import EvidenceId, FindingId, finding_id, timestamp_from_string
from yoetz.kernel.deterministic_checks import DeterministicCase
from yoetz.kernel.projections import EvidenceProjectionRecord, FindingProjectionRecord
from yoetz.ports.semantic import SemanticCase
from yoetz.protocol.coverage import EvidenceImmutability
from yoetz.protocol.ids import IdKind, new_id

_PACKS = ("research-evidence/0.2.0", "work-integrity/0.3.0")
_PROFILES = (
    ReviewContextProfile.STRUCTURAL,
    ReviewContextProfile.GOAL_AWARE,
    ReviewContextProfile.ASSISTED,
    ReviewContextProfile.EXPANDED,
)


class _Ids:
    def new(self, kind: IdKind) -> str:
        return new_id(kind)


def _case(
    findings: Mapping[FindingId, FindingProjectionRecord] | None = None,
) -> DeterministicCase:
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
    return make_case(
        plans={1: plan},
        obligations={obl(1): obligation},
        claims={clm(1): claim},
        evidence=evidence,
        findings=findings,
        extra_refs=(clm(1), obl(1), evd(1)),
    )


def _derived_findings(case: DeterministicCase) -> tuple[Finding, ...]:
    assessments, _ = run_deterministic_policies(case, CheckScope((), ()), _PACKS)
    return allocate_findings(
        _Ids(),
        tuple(item.candidate for item in assessments),
        prior_finding_ids(case.projection),
    )


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


def _recheck() -> tuple[DeterministicCase, tuple[Finding, ...], Finding]:
    """Run check #1, record its findings plus one retired finding, and freeze check #2's case."""

    first_case = _case()
    first_findings = _derived_findings(first_case)
    assert first_findings, "the recheck scenario needs at least one local finding"
    # A prior recorded finding this run does not re-derive: same kind and policy, but a subject
    # tuple no current policy emits, so its identity matches no check #2 candidate.
    retired = replace(
        first_findings[0],
        finding_id=finding_id(new_id(IdKind.FINDING)),
        subject_refs=(clm(1),),
    )
    recorded: dict[FindingId, FindingProjectionRecord] = {}
    for index, item in enumerate((*first_findings, retired)):
        recorded[item.finding_id] = finding_record(item, 5 + index)
    second_case = _case(findings=recorded)
    second_findings = _derived_findings(second_case)
    assert {item.finding_id for item in first_findings} <= {
        item.finding_id for item in second_findings
    }, "check #2 must re-derive check #1's findings under their recorded ids"
    return second_case, second_findings, retired


@pytest.mark.parametrize("profile", _PROFILES)
def test_recheck_with_recorded_findings_builds_and_owns_reused_ids_locally(
    profile: ReviewContextProfile,
) -> None:
    case, findings, _retired = _recheck()
    semantic = _build(case, profile, findings)

    reused = {str(item.finding_id) for item in findings}
    assert reused <= semantic.local_check_refs
    assert not reused & semantic.frontier_refs
    # No id is lost: the union still covers every frozen ref and every finding of this run.
    assert (
        semantic.frontier_refs | semantic.local_check_refs
        == {str(ref) for ref in case.allowed_ids} | reused
    )


@pytest.mark.parametrize("profile", _PROFILES)
def test_recheck_keeps_assessments_for_rederived_findings(profile: ReviewContextProfile) -> None:
    case, findings, _retired = _recheck()
    semantic = _build(case, profile, findings)

    assessed = {item.finding_ref for item in semantic.packet.deterministic_assessments}
    assert {str(item.finding_id) for item in findings} <= assessed


def test_recheck_keeps_prior_findings_it_does_not_rederive_in_frontier() -> None:
    case, findings, retired = _recheck()
    semantic = _build(case, ReviewContextProfile.EXPANDED, findings)

    assert str(retired.finding_id) in semantic.frontier_refs
    assert str(retired.finding_id) not in semantic.local_check_refs


@pytest.mark.parametrize("through_result", (False, True))
@pytest.mark.parametrize("profile", (ReviewContextProfile.ASSISTED, ReviewContextProfile.EXPANDED))
def test_repair_response_evidence_wins_excerpt_cap(
    through_result: bool,
    profile: ReviewContextProfile,
) -> None:
    from builders.policy_cases import act, res
    from yoetz.domain.events import ResponseRecordedPayload, ResultOutcome, ResultRecordedPayload
    from yoetz.domain.findings import ResponseDisposition

    base = _case()
    finding = _derived_findings(base)[0]
    repair = evidence_record(
        EvidenceRecordedPayload(
            evd(2),
            EvidenceKind.ARTIFACT,
            EvidenceImmutability.METADATA_ONLY,
            timestamp_from_string("2026-07-01T00:00:00.000Z"),
            description="REPAIR_MARKER: tested corrected line wrapping",
        ),
        8,
    )
    result = record(
        ResultRecordedPayload(res(1), act(1), ResultOutcome.SUCCESS, evidence_refs=(evd(2),)), 9
    )
    response = record(
        ResponseRecordedPayload(
            finding.finding_id,
            base.frontier,
            ResponseDisposition.ACKNOWLEDGED,
            evidence_refs=(res(1),) if through_result else (evd(2),),
        ),
        10,
    )
    case = make_case(
        plans=base.projection.plans,
        obligations=base.projection.obligations,
        claims=base.projection.claims,
        evidence={**base.projection.evidence, evd(2): repair},
        findings={finding.finding_id: finding_record(finding, 6)},
        responses={finding.finding_id: response},
        results={res(1): result} if through_result else {},
    )
    selection = replace(ReviewSelectionPolicy.for_profile(profile), max_excerpts=1)
    semantic = build_semantic_case(
        case_id="cas_10000000-0000-4000-8000-000000000884",
        frozen_case=case,
        dependency_digest="sha256:" + "a" * 64,
        findings=(),
        review_context_profile=profile,
        review_selection=selection,
        policy_id="research-evidence",
        policy_version="0.1.0",
    )
    assert semantic.packet.targeted_excerpts[0].excerpt_item_id == f"excerpt-{evd(2)}"
    assert any(
        b"REPAIR_MARKER" in item.content for item in semantic.items if item.section == "excerpt"
    )

    from yoetz.application.semantic_case import repair_evidence_refs

    allowed = frozenset(str(ref) for ref in case.allowed_ids)
    assert repair_evidence_refs(case.projection, allowed) == frozenset({str(evd(2))})
    for excluded in (finding.finding_id, response.source_event_id, evd(2)):
        assert repair_evidence_refs(case.projection, allowed - {str(excluded)}) == frozenset()
    if through_result:
        assert repair_evidence_refs(case.projection, allowed - {str(res(1))}) == frozenset()
        hidden_result = replace(
            case.projection, results={res(1): replace(result, payload=None, redacted=True)}
        )
        assert repair_evidence_refs(hidden_result, allowed) == frozenset()
    hidden_response = replace(
        case.projection,
        responses={finding.finding_id: replace(response, payload=None, redacted=True)},
    )
    assert repair_evidence_refs(hidden_response, allowed) == frozenset()
    hidden_evidence = replace(
        case.projection, evidence={evd(2): replace(repair, payload=None, redacted=True)}
    )
    assert repair_evidence_refs(hidden_evidence, allowed) == frozenset()
    closed = replace(
        case.projection,
        findings={
            finding.finding_id: replace(
                case.projection.findings[finding.finding_id],
                resolved_by_check_event_id=response.source_event_id,
            )
        },
    )
    assert repair_evidence_refs(closed, allowed) == frozenset()
