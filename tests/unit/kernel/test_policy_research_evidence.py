"""Minimum trigger and closest-nontrigger vectors for research evidence."""

from __future__ import annotations

from builders.policy_cases import (
    BASE_COVERAGE,
    FRONTIER,
    act,
    clm,
    evd,
    evidence_record,
    evt,
    fnd,
    make_case,
    obl,
    obligation_record,
    record,
    res,
)
from finishup.domain.events import (
    ActionKind,
    ActionRecordedPayload,
    ClaimKind,
    ClaimRecordedPayload,
    ClaimRecordedPayloadV1_1,
    EvidenceKind,
    EvidenceRecordedPayload,
    ObligationChangeKind,
    ObligationPublishedPayload,
    ObligationStatus,
    ResponseDisposition,
    ResponseRecordedPayload,
    ResultOutcome,
    ResultRecordedPayload,
)
from finishup.domain.findings import Finding, FindingKind, FindingOrigin
from finishup.domain.values import SubjectStateRef, object_id, timestamp_from_string
from finishup.kernel.deterministic_checks import case_coverage, run_deterministic_policies
from finishup.kernel.policies.research_evidence import RESEARCH_EVIDENCE_POLICY_PACK
from finishup.protocol.coverage import (
    EvidenceImmutability,
    PublicationChannel,
    coverage_for_channel,
)

_NOW = timestamp_from_string("2026-01-01T00:00:00.000Z")
_DIGEST_A = "sha256:" + "3" * 64
_DIGEST_B = "sha256:" + "4" * 64


def _kinds(case: object) -> tuple[FindingKind, ...]:
    result = run_deterministic_policies(case, RESEARCH_EVIDENCE_POLICY_PACK)  # type: ignore[arg-type]
    return tuple(item.candidate.kind for item in result.assessments)


def _action() -> ActionRecordedPayload:
    return ActionRecordedPayload(
        action_id=act(1),
        action_kind=ActionKind.EDIT,
        description="Synthetic edit",
    )


def _result(outcome: ResultOutcome, state: SubjectStateRef | None = None) -> ResultRecordedPayload:
    return ResultRecordedPayload(
        result_id=res(1),
        action_id=act(1),
        outcome=outcome,
        subject_state=state,
    )


def _evidence(state: SubjectStateRef | None = None) -> EvidenceRecordedPayload:
    return EvidenceRecordedPayload(
        evidence_id=evd(1),
        evidence_kind=EvidenceKind.TEST_RESULT,
        strength=EvidenceImmutability.IMMUTABLE_SNAPSHOT,
        observed_at=_NOW,
        captured_object_id=object_id("obj_10000000-0000-4000-8000-000000000001"),
        content_digest=_DIGEST_A,
        subject_state=state,
    )


def test_evidence_does_not_support_claim_and_success_nontrigger() -> None:
    open_obligation = ObligationPublishedPayload(
        obligation_id=obl(1),
        description="Synthetic obligation",
        evidence_expectation="Typed evidence",
        status=ObligationStatus.OPEN,
        requested_items=(),
    )
    claim = ClaimRecordedPayload(
        claim_id=clm(1),
        claim_kind=ClaimKind.COMPLETION,
        statement="Complete",
        supporting_refs=(obl(1),),
    )
    trigger = make_case(
        obligations={obl(1): obligation_record(open_obligation, 1)},
        claims={clm(1): record(claim, 2)},
    )
    result = run_deterministic_policies(trigger, RESEARCH_EVIDENCE_POLICY_PACK)
    finding = next(
        item
        for item in result.assessments
        if item.candidate.kind is FindingKind.EVIDENCE_DOES_NOT_SUPPORT_CLAIM
    )
    assert tuple(fact.fact_code for fact in finding.basis.observed_facts) == (
        "claim_support_present",
    )
    assert tuple(fact.fact_code for fact in finding.basis.required_but_missing_facts) == (
        "claim_support_mismatch",
    )
    waived = make_case(
        obligations={
            obl(1): obligation_record(open_obligation, 1, plan_change=ObligationChangeKind.WAIVED)
        },
        claims={clm(1): record(claim, 2)},
    )
    assert FindingKind.EVIDENCE_DOES_NOT_SUPPORT_CLAIM not in _kinds(waived)


def test_cited_non_success_result_is_limitation_disclosure_not_support_mismatch() -> None:
    """#429: citing a partial/failed result is disclosure, not contradictory support facts."""

    failure = _result(ResultOutcome.FAILURE)
    claim = ClaimRecordedPayload(
        claim_id=clm(1),
        claim_kind=ClaimKind.COMPLETION,
        statement="Complete",
        supporting_refs=(res(1),),
    )
    disclosed = make_case(
        actions={act(1): record(_action(), 1)},
        results={res(1): record(failure, 2)},
        claims={clm(1): record(claim, 3)},
    )
    kinds = _kinds(disclosed)
    assert FindingKind.EVIDENCE_DOES_NOT_SUPPORT_CLAIM not in kinds
    assert FindingKind.MATERIAL_LIMITATION_OMITTED not in kinds


def test_versioned_claim_uses_limitation_refs_without_treating_them_as_support() -> None:
    claim = ClaimRecordedPayloadV1_1(
        claim_id=clm(1),
        claim_kind=ClaimKind.COMPLETION,
        statement="Partial result retained as a limitation",
        supporting_refs=(evd(1),),
        limitation_refs=(res(1),),
    )
    case = make_case(
        actions={act(1): record(_action(), 1)},
        results={res(1): record(_result(ResultOutcome.PARTIAL), 2)},
        evidence={evd(1): evidence_record(_evidence(), 3)},
        claims={clm(1): record(claim, 4)},
    )
    kinds = _kinds(case)
    assert FindingKind.MATERIAL_LIMITATION_OMITTED not in kinds
    assert FindingKind.EVIDENCE_DOES_NOT_SUPPORT_CLAIM not in kinds


def test_diff_does_not_match_account_and_equal_digest_nontrigger() -> None:
    old = SubjectStateRef(tree_digest=_DIGEST_A)
    new = SubjectStateRef(tree_digest=_DIGEST_B)
    evidence = _evidence(old)
    mismatch = ClaimRecordedPayload(
        claim_id=clm(1),
        claim_kind=ClaimKind.MATERIAL,
        statement="New state",
        supporting_refs=(evd(1),),
        subject_state=new,
    )
    trigger = make_case(
        evidence={evd(1): evidence_record(evidence, 1)},
        claims={clm(1): record(mismatch, 2)},
    )
    result = run_deterministic_policies(trigger, RESEARCH_EVIDENCE_POLICY_PACK)
    finding = next(
        item
        for item in result.assessments
        if item.candidate.kind is FindingKind.DIFF_DOES_NOT_MATCH_ACCOUNT
    )
    assert finding.basis.subject_state_relation.value == "different"
    same = ClaimRecordedPayload(
        claim_id=clm(1),
        claim_kind=ClaimKind.MATERIAL,
        statement="Same state",
        supporting_refs=(evd(1),),
        subject_state=old,
    )
    near = make_case(
        evidence={evd(1): evidence_record(evidence, 1)},
        claims={clm(1): record(same, 2)},
    )
    assert FindingKind.DIFF_DOES_NOT_MATCH_ACCOUNT not in _kinds(near)


def test_material_limitation_omitted_and_exact_link_nontrigger() -> None:
    failure = _result(ResultOutcome.PARTIAL)
    omitted = ClaimRecordedPayload(
        claim_id=clm(1),
        claim_kind=ClaimKind.COMPLETION,
        statement="Complete",
        supporting_refs=(),
    )
    trigger = make_case(
        actions={act(1): record(_action(), 1)},
        results={res(1): record(failure, 2)},
        claims={clm(1): record(omitted, 3)},
    )
    result = run_deterministic_policies(trigger, RESEARCH_EVIDENCE_POLICY_PACK)
    finding = next(
        item
        for item in result.assessments
        if item.candidate.kind is FindingKind.MATERIAL_LIMITATION_OMITTED
    )
    assert finding.basis.required_but_missing_facts[0].fact_code == ("limitation_disclosure_absent")
    assert f"Omitted limitation basis: limiting result {res(1)}." in finding.candidate.detail
    assert f"limitation_refs [{res(1)}]" in finding.candidate.detail
    assert f"supersedes_claim_refs names [{clm(1)}]" in finding.candidate.detail
    assert omitted.statement not in finding.candidate.detail
    disclosed = ClaimRecordedPayload(
        claim_id=clm(1),
        claim_kind=ClaimKind.COMPLETION,
        statement="Partial",
        supporting_refs=(res(1),),
    )
    near = make_case(
        actions={act(1): record(_action(), 1)},
        results={res(1): record(failure, 2)},
        claims={clm(1): record(disclosed, 3)},
    )
    assert FindingKind.MATERIAL_LIMITATION_OMITTED not in _kinds(near)
    assert FindingKind.EVIDENCE_DOES_NOT_SUPPORT_CLAIM not in _kinds(near)


def _hook_observed_coverage() -> object:
    from dataclasses import replace as dc_replace

    from finishup.application.observation_materialize import HOST_OUTCOME_UNAVAILABLE_GAP

    base = coverage_for_channel(PublicationChannel.HOOK_OBSERVED)
    return dc_replace(base, known_gaps=(HOST_OUTCOME_UNAVAILABLE_GAP,))


def _observed_unknown_result(number: int) -> ResultRecordedPayload:
    return ResultRecordedPayload(
        result_id=res(number),
        action_id=act(number),
        outcome=ResultOutcome.UNKNOWN,
        exit_status=None,
    )


def test_outcome_less_observation_results_collapse_to_one_coverage_condition() -> None:
    """#350: N outcome-less hook-observed calls yield zero per-result
    material_limitation_omitted candidates and one bounded coverage code, while
    an explicit observed FAILURE stays individually actionable."""

    from finishup.application.observation_materialize import HOST_OUTCOME_UNAVAILABLE_GAP

    hook_coverage = _hook_observed_coverage()
    count = 70  # deliberately above the 64-gap/ref bounds in the acceptance criteria
    results = {res(i): record(_observed_unknown_result(i), i) for i in range(1, count + 1)}
    failure_number = count + 1
    results[res(failure_number)] = record(
        ResultRecordedPayload(
            result_id=res(failure_number),
            action_id=act(failure_number),
            outcome=ResultOutcome.FAILURE,
            exit_status=2,
        ),
        failure_number,
    )
    claim_number = count + 2
    claim = ClaimRecordedPayload(
        claim_id=clm(1),
        claim_kind=ClaimKind.COMPLETION,
        statement="Complete",
        supporting_refs=(),
    )
    overrides = {res(i): hook_coverage for i in range(1, count + 1)}
    overrides[res(failure_number)] = coverage_for_channel(PublicationChannel.HOOK_OBSERVED)
    case = make_case(
        results=results,
        claims={clm(1): record(claim, claim_number)},
        coverage_overrides=overrides,  # type: ignore[arg-type]
    )
    result = run_deterministic_policies(case, RESEARCH_EVIDENCE_POLICY_PACK)
    limitations = [
        item
        for item in result.assessments
        if item.candidate.kind is FindingKind.MATERIAL_LIMITATION_OMITTED
    ]
    # Exactly one finding — the explicit FAILURE — never one per outcome-less call.
    assert len(limitations) == 1
    assert res(failure_number) in limitations[0].basis.supporting_refs
    # The limitation is preserved as one deduplicated coverage code, so the
    # receipt keeps the honest condition without a finding storm.
    folded = case_coverage(case)
    assert folded.known_gaps.count(HOST_OUTCOME_UNAVAILABLE_GAP) == 1


def test_cooperative_unknown_result_remains_individually_limiting() -> None:
    """#350: the narrowing is provenance-aware — a cooperative UNKNOWN result
    (no hook_observed channel) is not exempted."""

    claim = ClaimRecordedPayload(
        claim_id=clm(1),
        claim_kind=ClaimKind.COMPLETION,
        statement="Complete",
        supporting_refs=(),
    )
    case = make_case(
        results={res(1): record(_observed_unknown_result(1), 1)},
        claims={clm(1): record(claim, 2)},
    )
    result = run_deterministic_policies(case, RESEARCH_EVIDENCE_POLICY_PACK)
    assert FindingKind.MATERIAL_LIMITATION_OMITTED in _kinds(case)
    assert any(
        res(1) in item.basis.supporting_refs
        for item in result.assessments
        if item.candidate.kind is FindingKind.MATERIAL_LIMITATION_OMITTED
    )


def test_hook_observed_unknown_with_exit_status_remains_limiting() -> None:
    """#350: the narrowing is cause-aware — an UNKNOWN result that carries an
    exit status was not caused by absent host outcome semantics."""

    payload = ResultRecordedPayload(
        result_id=res(1),
        action_id=act(1),
        outcome=ResultOutcome.UNKNOWN,
        exit_status=7,
    )
    claim = ClaimRecordedPayload(
        claim_id=clm(1),
        claim_kind=ClaimKind.COMPLETION,
        statement="Complete",
        supporting_refs=(),
    )
    case = make_case(
        results={res(1): record(payload, 1)},
        claims={clm(1): record(claim, 2)},
        coverage_overrides={res(1): _hook_observed_coverage()},  # type: ignore[dict-item]
    )
    assert FindingKind.MATERIAL_LIMITATION_OMITTED in _kinds(case)


def test_historical_hook_observed_unknown_without_capability_gap_remains_limiting() -> None:
    """Historical rows lack the new cause marker and retain old limitation semantics."""

    claim = ClaimRecordedPayload(
        claim_id=clm(1),
        claim_kind=ClaimKind.COMPLETION,
        statement="Complete",
        supporting_refs=(),
    )
    case = make_case(
        results={res(1): record(_observed_unknown_result(1), 1)},
        claims={clm(1): record(claim, 2)},
        # The channel alone is not enough to prove this is a newly materialized
        # outcome-less row; historical coverage has no cause-specific gap.
        coverage_overrides={res(1): coverage_for_channel(PublicationChannel.HOOK_OBSERVED)},  # type: ignore[dict-item]
    )
    result = run_deterministic_policies(case, RESEARCH_EVIDENCE_POLICY_PACK)
    assert any(
        item.candidate.kind is FindingKind.MATERIAL_LIMITATION_OMITTED
        and res(1) in item.basis.supporting_refs
        for item in result.assessments
    )


def test_outcome_less_observation_result_cannot_support_a_completion_claim() -> None:
    """#350: exempting the finding storm never upgrades the record — citing an
    outcome-less observed result as completion support still mismatches."""

    claim = ClaimRecordedPayload(
        claim_id=clm(1),
        claim_kind=ClaimKind.COMPLETION,
        statement="Complete",
        supporting_refs=(res(1),),
    )
    case = make_case(
        results={res(1): record(_observed_unknown_result(1), 1)},
        claims={clm(1): record(claim, 2)},
        coverage_overrides={res(1): _hook_observed_coverage()},  # type: ignore[dict-item]
    )
    kinds = _kinds(case)
    assert FindingKind.EVIDENCE_DOES_NOT_SUPPORT_CLAIM in kinds
    assert FindingKind.MATERIAL_LIMITATION_OMITTED not in kinds


def _recorded_finding() -> Finding:
    return Finding(
        finding_id=fnd(1),
        kind=FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS,
        origin=FindingOrigin.DETERMINISTIC,
        priority=1,
        summary="A completion claim covers an obligation that remains open.",
        detail="Subjects: evt_10000000-0000-4000-8000-000000000063. Main agent: Resolve it.",
        subject_refs=(evt(99),),
        policy_id="work-integrity",
        policy_version="0.1.0",
        subject_frontier=FRONTIER,
        coverage=BASE_COVERAGE,
        provenance=None,
    )


def test_questionable_finding_rejection_and_supported_nontrigger() -> None:
    finding = _recorded_finding()
    hollow = ResponseRecordedPayload(
        finding_id=fnd(1),
        finding_frontier=FRONTIER,
        disposition=ResponseDisposition.REJECTED,
        reason="Rejected",
    )
    trigger = make_case(
        findings={fnd(1): record(finding, 1)},
        responses={fnd(1): record(hollow, 2)},
        extra_refs=(evt(99),),
    )
    result = run_deterministic_policies(trigger, RESEARCH_EVIDENCE_POLICY_PACK)
    finding_assessment = next(
        item
        for item in result.assessments
        if item.candidate.kind is FindingKind.QUESTIONABLE_FINDING_REJECTION
    )
    assert finding_assessment.candidate.origin is FindingOrigin.DETERMINISTIC
    evidence = _evidence()
    supported = ResponseRecordedPayload(
        finding_id=fnd(1),
        finding_frontier=FRONTIER,
        disposition=ResponseDisposition.REJECTED,
        reason="Rejected",
        evidence_refs=(evd(1),),
    )
    near = make_case(
        evidence={evd(1): evidence_record(evidence, 1)},
        findings={fnd(1): record(finding, 2)},
        responses={fnd(1): record(supported, 3)},
        extra_refs=(evt(99),),
    )
    assert FindingKind.QUESTIONABLE_FINDING_REJECTION not in _kinds(near)


def test_provenance_dispute_does_not_trigger_rejection_penalty() -> None:
    finding = _recorded_finding()
    dispute = ResponseRecordedPayload(
        finding_id=fnd(1),
        finding_frontier=FRONTIER,
        disposition=ResponseDisposition.PROVENANCE_DISPUTED,
        reason="The finding attributes the underlying claim to this agent, but it came from a harness.",
    )
    case = make_case(
        findings={fnd(1): record(finding, 1)},
        responses={fnd(1): record(dispute, 2)},
        extra_refs=(evt(99),),
    )
    assert FindingKind.QUESTIONABLE_FINDING_REJECTION not in _kinds(case)


def _material_gap_coverage() -> object:
    from dataclasses import replace as dc_replace

    return dc_replace(BASE_COVERAGE, known_gaps=("redacted_object",))


def test_uncited_evidence_material_gap_still_omits_a_limitation() -> None:
    """A material coverage gap is task-level, not claim-linked.

    ADR-025 bounds which recorded *results* a claim must disclose. Bounding the coverage-gap scan
    to refs the claim already links silently dropped this finding for every uncited record, which
    is exactly the honesty regression the claim-correction work must not introduce.
    """

    claim = ClaimRecordedPayloadV1_1(
        claim_id=clm(1),
        claim_kind=ClaimKind.COMPLETION,
        statement="Complete",
        supporting_refs=(),
        obligation_refs=(obl(1),),
    )
    case = make_case(
        evidence={evd(1): evidence_record(_evidence(), 1)},
        claims={clm(1): record(claim, 2)},
        coverage_overrides={evd(1): _material_gap_coverage()},  # type: ignore[dict-item]
    )
    result = run_deterministic_policies(case, RESEARCH_EVIDENCE_POLICY_PACK)
    finding = next(
        item
        for item in result.assessments
        if item.candidate.kind is FindingKind.MATERIAL_LIMITATION_OMITTED
    )
    material_fact = next(
        fact
        for fact in finding.basis.observed_facts
        if fact.fact_code == "material_limitation_present"
    )
    assert evd(1) in material_fact.subject_refs
    assert f"material coverage-gap record {evd(1)}" in finding.candidate.detail


def test_versioned_claim_can_disclose_a_relevant_unknown_result() -> None:
    """#432: v1.1 must keep a disclosure channel for an `unknown` outcome.

    `claim_discloses_result` reads only `limitation_refs` for v1.1, so an `unknown` result that the
    limitation policy treats as limiting would otherwise have no field that clears the finding.
    """

    unknown = ResultRecordedPayload(
        result_id=res(1),
        action_id=act(1),
        outcome=ResultOutcome.UNKNOWN,
        exit_status=3,
    )
    omitted = ClaimRecordedPayloadV1_1(
        claim_id=clm(1),
        claim_kind=ClaimKind.COMPLETION,
        statement="Complete",
        supporting_refs=(),
        obligation_refs=(obl(1),),
    )
    trigger = make_case(
        actions={act(1): record(_action(), 1)},
        results={res(1): record(unknown, 2)},
        claims={clm(1): record(omitted, 3)},
    )
    assert FindingKind.MATERIAL_LIMITATION_OMITTED in _kinds(trigger)

    disclosed = ClaimRecordedPayloadV1_1(
        claim_id=clm(1),
        claim_kind=ClaimKind.COMPLETION,
        statement="Complete subject to one unknown outcome",
        supporting_refs=(),
        obligation_refs=(obl(1),),
        limitation_refs=(res(1),),
    )
    near = make_case(
        actions={act(1): record(_action(), 1)},
        results={res(1): record(unknown, 2)},
        claims={clm(1): record(disclosed, 3)},
    )
    assert FindingKind.MATERIAL_LIMITATION_OMITTED not in _kinds(near)
