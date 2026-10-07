"""Minimum trigger and closest-nontrigger vectors for work integrity."""

from __future__ import annotations

from dataclasses import replace

import pytest

from builders.policy_cases import (
    BASE_COVERAGE,
    FRONTIER,
    act,
    claim_record,
    clm,
    evd,
    evidence_record,
    evt,
    fnd,
    make_case,
    obl,
    obligation_record,
    plan_record,
    record,
    res,
)
from yoetz.domain.events import (
    ActionKind,
    ActionRecordedPayload,
    ClaimKind,
    ClaimRecordedPayload,
    ClaimRecordedPayloadV1_1,
    DecisionRecordedPayload,
    EvidenceKind,
    EvidenceRecordedPayload,
    ObligationChange,
    ObligationChangeKind,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
    PlanRevisedPayload,
    RequestedItem,
    RequestedItemKind,
    ResponseDisposition,
    ResponseRecordedPayload,
    ResultOutcome,
    ResultRecordedPayload,
)
from yoetz.domain.findings import (
    Finding,
    FindingKind,
    FindingOrigin,
    SamplingParams,
    SemanticDispatchKind,
    SemanticProvenance,
)
from yoetz.domain.values import (
    SubjectStateRef,
    actor_id,
    object_id,
    timestamp_from_string,
)
from yoetz.kernel.deterministic_checks import (
    REQUESTED_OUTPUT_ABSENT_FACT,
    CaseGap,
    render_deterministic_finding_text,
    run_deterministic_policies,
)
from yoetz.kernel.policies.work_integrity import (
    WORK_INTEGRITY_POLICY_PACK,
    reportable_absent_outputs,
    work_integrity_findings,
)
from yoetz.kernel.projections import (
    ContradictionKey,
    ContradictionRecord,
    DecisionProjectionRecord,
)
from yoetz.protocol.coverage import EvidenceImmutability
from yoetz.protocol.models import SemanticReason, SemanticStatus

_NOW = timestamp_from_string("2026-01-01T00:00:00.000Z")
_DIGEST_A = "sha256:" + "1" * 64
_DIGEST_B = "sha256:" + "2" * 64


def _decision_record(payload: DecisionRecordedPayload) -> DecisionProjectionRecord:
    from yoetz.domain.events import encode_payload
    from yoetz.protocol.canonical import canonical_digest

    return DecisionProjectionRecord(
        payload=payload,
        payload_digest=canonical_digest(encode_payload(payload)),
        redacted=False,
        source_event_id=evt(50),
        source_frontier=4,
    )


def _kinds(case: object) -> tuple[FindingKind, ...]:
    result = run_deterministic_policies(case, WORK_INTEGRITY_POLICY_PACK)  # type: ignore[arg-type]
    return tuple(item.candidate.kind for item in result.assessments)


def _open_obligation(number: int, *, requested: str | None = None) -> ObligationPublishedPayload:
    items = () if requested is None else (RequestedItem(RequestedItemKind.CHANGE, requested),)
    return ObligationPublishedPayload(
        obligation_id=obl(number),
        description="Synthetic obligation",
        evidence_expectation="Typed evidence",
        status=ObligationStatus.OPEN,
        requested_items=items,
    )


def _action(number: int, obligation: int) -> ActionRecordedPayload:
    return ActionRecordedPayload(
        action_id=act(number),
        action_kind=ActionKind.EDIT,
        description="Synthetic action",
        obligation_refs=(obl(obligation),),
        attempted_items=(f"item-{obligation}",),
    )


def _result(
    number: int,
    action: int,
    outcome: ResultOutcome,
    *,
    state: SubjectStateRef | None = None,
) -> ResultRecordedPayload:
    return ResultRecordedPayload(
        result_id=res(number),
        action_id=act(action),
        outcome=outcome,
        subject_state=state,
    )


def _evidence(number: int, state: SubjectStateRef | None = None) -> EvidenceRecordedPayload:
    return EvidenceRecordedPayload(
        evidence_id=evd(number),
        evidence_kind=EvidenceKind.TEST_RESULT,
        strength=EvidenceImmutability.IMMUTABLE_SNAPSHOT,
        observed_at=_NOW,
        captured_object_id=object_id(f"obj_10000000-0000-4000-8000-{number:012x}"),
        content_digest=_DIGEST_A,
        subject_state=state,
    )


def test_completion_with_open_obligations_and_waiver_nontrigger() -> None:
    obligation = _open_obligation(1)
    claim = ClaimRecordedPayload(
        claim_id=clm(1),
        claim_kind=ClaimKind.COMPLETION,
        statement="Complete",
        supporting_refs=(obl(1),),
        obligation_refs=(obl(1),),
    )
    trigger = make_case(
        obligations={obl(1): obligation_record(obligation, 1)},
        claims={clm(1): record(claim, 2)},
    )
    result = run_deterministic_policies(trigger, WORK_INTEGRITY_POLICY_PACK)
    finding = next(
        item
        for item in result.assessments
        if item.candidate.kind is FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS
    )
    assert finding.candidate.subject_refs == (clm(1), obl(1))
    assert tuple(fact.fact_code for fact in finding.basis.observed_facts) == (
        "completion_claim_present",
        "open_obligation_present",
    )
    waived = make_case(
        obligations={
            obl(1): obligation_record(
                obligation,
                1,
                plan_change=ObligationChangeKind.WAIVED,
            )
        },
        claims={clm(1): record(claim, 2)},
    )
    assert FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS not in _kinds(waived)


def _unrelated_action(number: int) -> ActionRecordedPayload:
    """A published action on another obligation: the agent has started acting (#977)."""

    return ActionRecordedPayload(
        action_id=act(number),
        action_kind=ActionKind.EDIT,
        description="Work on another obligation",
        obligation_refs=(obl(99),),
        attempted_items=("other-item",),
    )


def test_requested_item_never_attempted_and_exact_attempt_nontrigger() -> None:
    obligation = _open_obligation(1, requested="item-1")
    plan = PlanPublishedPayload(1, "Plan", (obl(1),))
    trigger = make_case(
        plans={1: plan_record(plan, 1)},
        obligations={obl(1): obligation_record(obligation, 2)},
        actions={act(9): record(_unrelated_action(9), 3)},
    )
    assert FindingKind.REQUESTED_ITEM_NEVER_ATTEMPTED in _kinds(trigger)
    attempted = make_case(
        plans={1: plan_record(plan, 1)},
        obligations={obl(1): obligation_record(obligation, 2)},
        actions={act(1): record(_action(1, 1), 3)},
    )
    assert FindingKind.REQUESTED_ITEM_NEVER_ATTEMPTED not in _kinds(attempted)


def test_identical_requested_items_require_obligation_scoped_attempt() -> None:
    first = _open_obligation(1, requested="shared-check")
    second = _open_obligation(2, requested="shared-check")
    plan = PlanPublishedPayload(1, "Plan", (obl(1), obl(2)))
    scoped = ActionRecordedPayload(
        action_id=act(1),
        action_kind=ActionKind.EDIT,
        description="Attempt only the first obligation.",
        obligation_refs=(obl(1),),
        attempted_items=("shared-check",),
    )
    case = make_case(
        plans={1: plan_record(plan, 1)},
        obligations={
            obl(1): obligation_record(first, 2),
            obl(2): obligation_record(second, 3),
        },
        actions={act(1): record(scoped, 4)},
    )

    findings = [
        assessment
        for assessment in run_deterministic_policies(case, WORK_INTEGRITY_POLICY_PACK).assessments
        if assessment.candidate.kind is FindingKind.REQUESTED_ITEM_NEVER_ATTEMPTED
    ]
    assert [assessment.candidate.subject_refs for assessment in findings] == [(obl(2),)]


def test_requested_item_on_carried_revision_uses_effective_plan_scope() -> None:
    obligation = _open_obligation(2, requested="item-2")
    initial = PlanPublishedPayload(1, "Initial plan", ())
    revision = PlanRevisedPayload(
        2,
        1,
        "Carry newly declared work.",
        "Expanded plan.",
        (ObligationChange(obl(2), ObligationChangeKind.CARRIED),),
    )
    case = make_case(
        plans={1: plan_record(initial, 1), 2: plan_record(revision, 2)},
        obligations={obl(2): obligation_record(obligation, 3)},
        actions={act(9): record(_unrelated_action(9), 4)},
    )

    assert FindingKind.REQUESTED_ITEM_NEVER_ATTEMPTED in _kinds(case)


def test_requested_item_is_not_reported_before_the_agent_starts_acting() -> None:
    """TB4 tb4f1: 86% of all findings were this notice raised against a fresh plan (#977)."""

    obligation = _open_obligation(1, requested="item-1")
    plan = PlanPublishedPayload(1, "Plan", (obl(1),))
    plan_only = make_case(
        plans={1: plan_record(plan, 1)},
        obligations={obl(1): obligation_record(obligation, 2)},
    )
    assert FindingKind.REQUESTED_ITEM_NEVER_ATTEMPTED not in _kinds(plan_only)


def test_absent_requested_output_is_reported_even_when_an_action_names_it() -> None:
    """atrx-vep-crispr: naming the report in attempted_items never wrote it (#977)."""

    obligation = ObligationPublishedPayload(
        obligation_id=obl(1),
        description="Write the report",
        evidence_expectation="The file",
        status=ObligationStatus.OPEN,
        requested_items=(RequestedItem(RequestedItemKind.FILE, "out/report.json"),),
    )
    named = ActionRecordedPayload(
        action_id=act(1),
        action_kind=ActionKind.OTHER,
        description="Attempted the report",
        obligation_refs=(obl(1),),
        attempted_items=("out/report.json",),
    )
    plan = PlanPublishedPayload(1, "Plan", (obl(1),))
    case = make_case(
        plans={1: plan_record(plan, 1)},
        obligations={obl(1): obligation_record(obligation, 2)},
        actions={act(1): record(named, 3)},
    )
    assert FindingKind.REQUESTED_ITEM_NEVER_ATTEMPTED not in _kinds(case)
    assessments = work_integrity_findings(case, absent_outputs=frozenset({(obl(1), 0)}))
    found = [
        item
        for item in assessments
        if item.candidate.kind is FindingKind.REQUESTED_ITEM_NEVER_ATTEMPTED
    ]
    assert len(found) == 1
    facts = {fact.fact_code for fact in found[0].basis.observed_facts}
    assert REQUESTED_OUTPUT_ABSENT_FACT in facts
    assert found[0].basis.required_but_missing_facts == ()
    detail = found[0].candidate.detail
    assert "best-effort artifact" in detail
    assert "revise" not in found[0].candidate.detail.lower()


def test_pre_work_check_reports_no_absent_requested_output() -> None:
    """tb4n1 E4: the guided pre-work check found every requested output absent.

    48 of 68 first findings were this variant, 42 of them before any edit: after the plan, before
    work, the file obviously does not exist yet. A research action is still investigation, and an
    action on another obligation is not work on this one.
    """

    report = ObligationPublishedPayload(
        obligation_id=obl(1),
        description="Write the report",
        evidence_expectation="The file",
        status=ObligationStatus.OPEN,
        requested_items=(RequestedItem(RequestedItemKind.FILE, "out/report.json"),),
    )
    other = ObligationPublishedPayload(
        obligation_id=obl(2),
        description="Fix the parser",
        evidence_expectation="Tests",
        status=ObligationStatus.OPEN,
    )
    plan = PlanPublishedPayload(1, "Plan", (obl(1), obl(2)))
    research = ActionRecordedPayload(
        action_id=act(1),
        action_kind=ActionKind.RESEARCH,
        description="Read the task inputs",
        obligation_refs=(obl(1),),
        attempted_items=("out/report.json",),
    )
    parser_edit = ActionRecordedPayload(
        action_id=act(2),
        action_kind=ActionKind.EDIT,
        description="Edited the parser",
        obligation_refs=(obl(2),),
    )
    absent = frozenset({(obl(1), 0)})
    obligations = {obl(1): obligation_record(report, 2), obl(2): obligation_record(other, 3)}

    plan_only = make_case(plans={1: plan_record(plan, 1)}, obligations=obligations)
    assert reportable_absent_outputs(plan_only, absent) == frozenset()
    assert not work_integrity_findings(plan_only, absent_outputs=absent)

    investigating = make_case(
        plans={1: plan_record(plan, 1)},
        obligations=obligations,
        actions={act(1): record(research, 4), act(2): record(parser_edit, 5)},
    )
    assert reportable_absent_outputs(investigating, absent) == frozenset()
    assert not any(
        REQUESTED_OUTPUT_ABSENT_FACT in {fact.fact_code for fact in item.basis.observed_facts}
        for item in work_integrity_findings(investigating, absent_outputs=absent)
    )

    # Work on the report obligation begins: the absent file is now a finding.
    report_edit = ActionRecordedPayload(
        action_id=act(3),
        action_kind=ActionKind.EDIT,
        description="Started the report",
        obligation_refs=(obl(1),),
    )
    working = make_case(
        plans={1: plan_record(plan, 1)},
        obligations=obligations,
        actions={
            act(1): record(research, 4),
            act(2): record(parser_edit, 5),
            act(3): record(report_edit, 6),
        },
    )
    assert reportable_absent_outputs(working, absent) == absent
    assert any(
        REQUESTED_OUTPUT_ABSENT_FACT in {fact.fact_code for fact in item.basis.observed_facts}
        for item in work_integrity_findings(working, absent_outputs=absent)
    )


def test_blocked_obligation_raises_no_requested_item_finding() -> None:
    obligation = _open_obligation(1, requested="item-1")
    plan = PlanPublishedPayload(1, "Plan", (obl(1),))
    blocker = DecisionRecordedPayload(
        statement="yoetz-blocker:credential",
        rationale="The registry token is the operator's.",
        authority=actor_id("agt_codex"),
        affected_obligation_ids=(obl(1),),
    )
    case = make_case(
        plans={1: plan_record(plan, 1)},
        obligations={obl(1): obligation_record(obligation, 2)},
        actions={act(9): record(_unrelated_action(9), 3)},
    )
    case = replace(
        case,
        projection=replace(
            case.projection,
            decisions={evt(50): _decision_record(blocker)},
        ),
    )
    assert FindingKind.REQUESTED_ITEM_NEVER_ATTEMPTED not in _kinds(case)
    absent = work_integrity_findings(case, absent_outputs=frozenset({(obl(1), 0)}))
    assert FindingKind.REQUESTED_ITEM_NEVER_ATTEMPTED not in {
        item.candidate.kind for item in absent
    }


def test_failed_work_omitted_and_exact_disclosure_nontrigger() -> None:
    action = _action(1, 1)
    failed = _result(1, 1, ResultOutcome.FAILURE)
    omitted = ClaimRecordedPayload(
        claim_id=clm(1),
        claim_kind=ClaimKind.COMPLETION,
        statement="Complete",
        supporting_refs=(),
    )
    trigger = make_case(
        actions={act(1): record(action, 1)},
        results={res(1): record(failed, 2)},
        claims={clm(1): record(omitted, 3)},
    )
    assert FindingKind.FAILED_WORK_OMITTED in _kinds(trigger)
    disclosed = ClaimRecordedPayload(
        claim_id=clm(1),
        claim_kind=ClaimKind.COMPLETION,
        statement="Partial",
        supporting_refs=(res(1),),
    )
    near = make_case(
        actions={act(1): record(action, 1)},
        results={res(1): record(failed, 2)},
        claims={clm(1): record(disclosed, 3)},
    )
    assert FindingKind.FAILED_WORK_OMITTED not in _kinds(near)


def test_versioned_replacement_is_effective_and_keeps_partial_result_as_limitation() -> None:
    old = ClaimRecordedPayload(
        claim_id=clm(1),
        claim_kind=ClaimKind.COMPLETION,
        statement="Overbroad completion",
        supporting_refs=(),
        obligation_refs=(obl(1),),
    )
    replacement = ClaimRecordedPayloadV1_1(
        claim_id=clm(2),
        claim_kind=ClaimKind.COMPLETION,
        statement="Narrowed completion with partial result disclosed",
        supporting_refs=(res(1),),
        obligation_refs=(obl(1),),
        limitation_refs=(res(2),),
        supersedes_claim_refs=(clm(1),),
    )
    case = make_case(
        actions={act(1): record(_action(1, 1), 1), act(2): record(_action(2, 1), 2)},
        results={
            res(1): record(_result(1, 1, ResultOutcome.SUCCESS), 3),
            res(2): record(_result(2, 2, ResultOutcome.PARTIAL), 4),
        },
        claims={
            clm(1): claim_record(old, 5, superseded_by_claim_id=clm(2)),
            clm(2): record(replacement, 6),
        },
    )
    kinds = _kinds(case)
    assert FindingKind.FAILED_WORK_OMITTED not in kinds
    assert FindingKind.CLAIM_WITHOUT_ADMISSIBLE_EVIDENCE not in kinds


def test_completion_does_not_inherit_future_or_disjoint_partial_results() -> None:
    claim = ClaimRecordedPayloadV1_1(
        claim_id=clm(1),
        claim_kind=ClaimKind.COMPLETION,
        statement="Obligation two completed",
        supporting_refs=(res(2),),
        obligation_refs=(obl(2),),
    )
    case = make_case(
        actions={act(1): record(_action(1, 1), 1), act(2): record(_action(2, 2), 2)},
        results={
            res(1): record(_result(1, 1, ResultOutcome.PARTIAL), 3),
            res(2): record(_result(2, 2, ResultOutcome.SUCCESS), 4),
            res(3): record(_result(3, 2, ResultOutcome.PARTIAL), 6),
        },
        claims={clm(1): record(claim, 5)},
    )
    assert FindingKind.FAILED_WORK_OMITTED not in _kinds(case)


def test_failed_work_finding_names_exact_versioned_repair_refs() -> None:
    claim = ClaimRecordedPayload(
        claim_id=clm(1),
        claim_kind=ClaimKind.COMPLETION,
        statement="Complete",
        supporting_refs=(),
        obligation_refs=(obl(1),),
    )
    case = make_case(
        actions={act(1): record(_action(1, 1), 1)},
        results={res(1): record(_result(1, 1, ResultOutcome.PARTIAL), 2)},
        claims={clm(1): record(claim, 3)},
    )
    result = run_deterministic_policies(case, WORK_INTEGRITY_POLICY_PACK)
    finding = next(
        item
        for item in result.assessments
        if item.candidate.kind is FindingKind.FAILED_WORK_OMITTED
    )
    assert f"supersedes_claim_refs [{clm(1)}]" in finding.candidate.detail
    assert f"limitation_refs [{res(1)}]" in finding.candidate.detail


def test_claim_without_admissible_evidence_and_supported_nontrigger() -> None:
    unsupported = ClaimRecordedPayload(
        claim_id=clm(1),
        claim_kind=ClaimKind.MATERIAL,
        statement="Material claim",
        supporting_refs=(),
    )
    assert FindingKind.CLAIM_WITHOUT_ADMISSIBLE_EVIDENCE in _kinds(
        make_case(claims={clm(1): record(unsupported, 1)})
    )
    evidence = _evidence(1)
    supported = ClaimRecordedPayload(
        claim_id=clm(1),
        claim_kind=ClaimKind.MATERIAL,
        statement="Material claim",
        supporting_refs=(evd(1),),
    )
    near = make_case(
        evidence={evd(1): evidence_record(evidence, 1)},
        claims={clm(1): record(supported, 2)},
    )
    assert FindingKind.CLAIM_WITHOUT_ADMISSIBLE_EVIDENCE not in _kinds(near)


def test_result_without_action_and_linked_action_nontrigger() -> None:
    result = _result(1, 1, ResultOutcome.SUCCESS)
    assert FindingKind.RESULT_WITHOUT_ACTION in _kinds(
        make_case(results={res(1): record(result, 1)})
    )
    linked = make_case(
        actions={act(1): record(_action(1, 1), 1)},
        results={res(1): record(result, 2)},
    )
    assert FindingKind.RESULT_WITHOUT_ACTION not in _kinds(linked)


def test_action_without_result_requires_later_disjoint_work() -> None:
    unresolved = _action(1, 1)
    later = _action(2, 2)
    trigger = make_case(
        actions={
            act(1): record(unresolved, 1),
            act(2): record(later, 2),
        }
    )
    assert FindingKind.ACTION_WITHOUT_RESULT in _kinds(trigger)
    latest_only = make_case(actions={act(1): record(unresolved, 1)})
    assert FindingKind.ACTION_WITHOUT_RESULT not in _kinds(latest_only)


@pytest.mark.parametrize(
    ("left_obligations", "left_items", "right_obligations", "right_items", "expected"),
    [
        ((1,), ("shared",), (2,), ("shared",), True),
        ((1,), ("left",), (1,), ("right",), False),
        ((1, 2), (), (2, 3), (), False),
        ((1, 2), (), (3, 4), (), True),
        ((), ("a", "b"), (), ("b", "c"), False),
        ((), ("a",), (), ("c",), True),
        ((1,), ("same",), (), ("same",), False),
        ((), ("same",), (1,), ("other",), False),
        ((), (), (), ("known",), False),
        ((), ("known",), (), (), False),
        ((), (), (), (), False),
    ],
)
def test_action_subject_precedence_and_unknown_subjects(
    left_obligations: tuple[int, ...],
    left_items: tuple[str, ...],
    right_obligations: tuple[int, ...],
    right_items: tuple[str, ...],
    expected: bool,
) -> None:
    left = replace(
        _action(1, 1),
        obligation_refs=tuple(obl(number) for number in left_obligations),
        attempted_items=left_items,
    )
    right = replace(
        _action(2, 2),
        obligation_refs=tuple(obl(number) for number in right_obligations),
        attempted_items=right_items,
    )
    case = make_case(actions={act(1): record(left, 1), act(2): record(right, 2)})

    assert (FindingKind.ACTION_WITHOUT_RESULT in _kinds(case)) is expected


def test_unresolved_action_basis_preserves_frontier_and_reference_order() -> None:
    case = make_case(
        actions={
            act(5): replace(record(_action(5, 3), 5), source_frontier=3),
            act(3): replace(record(_action(3, 2), 3), source_frontier=2),
            act(4): replace(record(_action(4, 4), 4), source_frontier=2),
            act(2): replace(record(_action(2, 2), 2), source_frontier=1),
            act(1): record(_action(1, 1), 1),
            act(6): replace(record(_action(6, 2), 6), source_frontier=4),
            act(7): replace(record(_action(7, 7), 7), payload=None, redacted=True),
        },
        results={res(1): record(_result(1, 6, ResultOutcome.SUCCESS), 8)},
    )
    result = run_deterministic_policies(case, WORK_INTEGRITY_POLICY_PACK)
    facts = tuple(
        fact.subject_refs
        for assessment in result.assessments
        if assessment.candidate.kind is FindingKind.ACTION_WITHOUT_RESULT
        for fact in assessment.basis.observed_facts
        if fact.fact_code == "subsequent_unrelated_work_present"
    )

    assert facts == (
        (act(1), act(3), act(4), act(5), act(6)),
        (act(2), act(4), act(5)),
        (act(3), act(5)),
        (act(4), act(5), act(6)),
        (act(5), act(6)),
    )


def test_stale_evidence_requires_comparable_different_tree_state() -> None:
    old_state = SubjectStateRef(tree_digest=_DIGEST_A)
    new_state = SubjectStateRef(tree_digest=_DIGEST_B)
    evidence = _evidence(1, old_state)
    claim = ClaimRecordedPayload(
        claim_id=clm(1),
        claim_kind=ClaimKind.MATERIAL,
        statement="Changed state",
        supporting_refs=(evd(1),),
        subject_state=new_state,
    )
    trigger = make_case(
        evidence={evd(1): evidence_record(evidence, 1)},
        claims={clm(1): record(claim, 2)},
    )
    result = run_deterministic_policies(trigger, WORK_INTEGRITY_POLICY_PACK)
    finding = next(
        item
        for item in result.assessments
        if item.candidate.kind is FindingKind.STALE_EVIDENCE_FOR_CHANGED_STATE
    )
    assert finding.basis.subject_state_relation.value == "different"
    same = ClaimRecordedPayload(
        claim_id=clm(1),
        claim_kind=ClaimKind.MATERIAL,
        statement="Same state",
        supporting_refs=(evd(1),),
        subject_state=old_state,
    )
    near = make_case(
        evidence={evd(1): evidence_record(evidence, 1)},
        claims={clm(1): record(same, 2)},
    )
    assert FindingKind.STALE_EVIDENCE_FOR_CHANGED_STATE not in _kinds(near)


def test_contradictory_claims_require_explicit_unresolved_edge() -> None:
    left = ClaimRecordedPayload(clm(1), ClaimKind.MATERIAL, "Left", ())
    right = ClaimRecordedPayload(clm(2), ClaimKind.MATERIAL, "Right", ())
    key = ContradictionKey(clm(1), clm(2))
    edge = ContradictionRecord(clm(1), clm(2), evt(1), 1)
    trigger = make_case(
        claims={clm(1): record(left, 1), clm(2): record(right, 2)},
        contradictions={key: edge},
    )
    assert FindingKind.CONTRADICTORY_CLAIMS_UNRESOLVED in _kinds(trigger)
    result = run_deterministic_policies(trigger, WORK_INTEGRITY_POLICY_PACK)
    finding = next(
        item
        for item in result.assessments
        if item.candidate.kind is FindingKind.CONTRADICTORY_CLAIMS_UNRESOLVED
    )
    assert "claim_recorded/1.1.0 supersedes_claim_refs" in finding.candidate.detail
    assert str(clm(1)) in finding.candidate.detail
    assert str(clm(2)) in finding.candidate.detail
    assert "disputes_refs" in finding.candidate.detail
    assert "decision supersedes_event_id" in finding.candidate.detail
    near = make_case(claims={clm(1): record(left, 1), clm(2): record(right, 2)})
    assert FindingKind.CONTRADICTORY_CLAIMS_UNRESOLVED not in _kinds(near)


def test_ledger_stale_or_incomplete_requires_a_nonrootless_gap() -> None:
    gap = CaseGap(
        f"unknown_event:{evt(9)}:future_event@2.0.0",
        "unknown_event",
        (evt(9),),
    )
    trigger = make_case(gaps=(gap,), extra_refs=(evt(9),))
    assert FindingKind.LEDGER_STALE_OR_INCOMPLETE in _kinds(trigger)
    rootless = CaseGap("import_source_range_not_universal", "freshness_gap", ())
    assert FindingKind.LEDGER_STALE_OR_INCOMPLETE not in _kinds(make_case(gaps=(rootless,)))


@pytest.mark.parametrize("code", ("evidence_content_digest_only", "evidence_content_withheld"))
def test_caller_digest_provenance_is_a_label_not_a_ledger_finding(code: str) -> None:
    """Issue #912: an unverified caller digest raises no finding; the case keeps the gap.

    Nothing an agent can publish turns ``caller_asserted`` bytes into captured content, so a
    finding would only invite answers and further digest-only publications. The exact gap still
    rides on the case and on every ref it roots, so the receipt keeps disclosing it.
    """

    gaps = tuple(CaseGap(f"{code}:{evt(n)}", code, (evt(n),)) for n in (9, 10, 11))
    limited = replace(BASE_COVERAGE, known_gaps=(code,))
    case = make_case(
        gaps=gaps,
        extra_refs=(evt(9), evt(10), evt(11)),
        coverage_overrides={evt(9): limited, evt(10): limited, evt(11): limited},
    )
    assert FindingKind.LEDGER_STALE_OR_INCOMPLETE not in _kinds(case)
    assert {gap.code for gap in case.gaps} == {code}
    assert case.coverage_by_ref[evt(9)].known_gaps == (code,)

    # A real ledger defect beside it still fires, and never names the caller digest roots.
    unknown = CaseGap(f"unknown_event:{evt(12)}:future_event@2.0.0", "unknown_event", (evt(12),))
    mixed = make_case(
        gaps=(*gaps, unknown),
        extra_refs=(evt(9), evt(10), evt(11), evt(12)),
        coverage_overrides={evt(9): limited, evt(10): limited, evt(11): limited},
    )
    result = run_deterministic_policies(mixed, WORK_INTEGRITY_POLICY_PACK)
    ledger = [
        item
        for item in result.assessments
        if item.candidate.kind is FindingKind.LEDGER_STALE_OR_INCOMPLETE
    ]
    assert len(ledger) == 1
    assert ledger[0].candidate.subject_refs == (evt(12),)


def test_legacy_digest_finding_names_only_actions_an_agent_can_take() -> None:
    code = "evidence_digest_subject_legacy_unknown"
    gap = CaseGap(f"{code}:{evt(9)}", code, (evt(9),))
    legacy = replace(BASE_COVERAGE, known_gaps=(code,))
    trigger = make_case(gaps=(gap,), extra_refs=(evt(9),), coverage_overrides={evt(9): legacy})
    result = run_deterministic_policies(trigger, WORK_INTEGRITY_POLICY_PACK)
    finding = next(
        item
        for item in result.assessments
        if item.candidate.kind is FindingKind.LEDGER_STALE_OR_INCOMPLETE
    )
    detail = finding.candidate.detail
    # The detail names the concrete gap and says a response cannot resolve it, so an agent is
    # never steered into acknowledging its way out of a coverage gap (issue #186) ...
    assert code in detail
    assert "no finding response, recheck, or further digest-only publication changes it" in detail
    assert "it needs no repair or recheck; one acknowledged response answers it" in detail
    # ... and it no longer promises a remedy ordinary publication cannot perform (issue #912).
    assert "content-bearing" not in detail
    assert "filter.strength immutable_snapshot" in detail
    assert "typed digest_binding" in detail


def test_mixed_legacy_digest_finding_does_not_claim_acknowledgement_resolves_it() -> None:
    """Greptile P1 on #912: provenance advice must not cover a finding's other, current gaps.

    A legacy digest beside an unknown event (or beside a rootless-coded subject such as a
    command-attempt obligation) keeps the finding current after any acknowledgement, so the text
    must say so instead of "one acknowledged response answers it".
    """

    code = "evidence_digest_subject_legacy_unknown"
    legacy = replace(BASE_COVERAGE, known_gaps=(code,))
    unknown = CaseGap(f"unknown_event:{evt(12)}:future_event@2.0.0", "unknown_event", (evt(12),))
    mixed = make_case(
        gaps=(CaseGap(f"{code}:{evt(9)}", code, (evt(9),)), unknown),
        extra_refs=(evt(9), evt(12)),
        coverage_overrides={evt(9): legacy},
    )
    result = run_deterministic_policies(mixed, WORK_INTEGRITY_POLICY_PACK)
    detail = next(
        item.candidate.detail
        for item in result.assessments
        if item.candidate.kind is FindingKind.LEDGER_STALE_OR_INCOMPLETE
    )
    assert "one acknowledged response answers it" not in detail
    assert "needs no repair or recheck" not in detail
    assert "an acknowledgement answers this finding but does not resolve it" in detail
    assert "until a qualifying check proves those other gaps absent" in detail

    # Same wording when the other subject is an obligation whose gap code is not listed.
    _, rendered = render_deterministic_finding_text(
        FindingKind.LEDGER_STALE_OR_INCOMPLETE,
        (evt(9), obl(1)),
        (code,),
    )
    assert "one acknowledged response answers it" not in rendered
    assert "does not resolve it" in rendered


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


def test_weak_or_stale_response_and_supported_rejection_nontrigger() -> None:
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
    # This pack is a closed rule table and still owns the hollow rejection on its own. The overlap
    # with research-evidence is collapsed at composition, not by this pack falling silent; see
    # tests/unit/application/test_verdict_rules.py.
    assert FindingKind.WEAK_OR_STALE_RESPONSE in _kinds(trigger)

    stale = replace(
        hollow,
        finding_frontier=replace(FRONTIER, sequence=FRONTIER.sequence - 1),
    )
    stale_case = make_case(
        findings={fnd(1): record(finding, 1)},
        responses={fnd(1): record(stale, 2)},
        extra_refs=(evt(99),),
    )
    assert FindingKind.WEAK_OR_STALE_RESPONSE in _kinds(stale_case)

    evidence = _evidence(1)
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
    assert FindingKind.WEAK_OR_STALE_RESPONSE not in _kinds(near)

    legacy_unknown = replace(
        BASE_COVERAGE,
        known_gaps=("evidence_digest_subject_legacy_unknown",),
    )
    work_only_gap = make_case(
        evidence={evd(1): evidence_record(evidence, 1)},
        findings={fnd(1): record(finding, 2)},
        responses={fnd(1): record(supported, 3)},
        extra_refs=(evt(99),),
        coverage_overrides={evd(1): legacy_unknown},
    )
    assert FindingKind.WEAK_OR_STALE_RESPONSE in _kinds(work_only_gap)


def test_provenance_dispute_does_not_trigger_weak_response_penalty() -> None:
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
    assert FindingKind.WEAK_OR_STALE_RESPONSE not in _kinds(case)


def test_ai_origin_rejection_without_evidence_mints_no_weak_response() -> None:
    """Rejecting an AI-powered false positive must not add a local blocking finding (#905).

    termenv shape: the reviewer asked for a tail the task text explicitly excludes, and the agent
    rejected it by quoting the task, with no evidence ref. research-evidence already skipped
    non-local findings; work integrity now applies the same origin filter, stale or not. The
    local-origin trigger above is unchanged.
    """

    semantic = replace(
        _recorded_finding(),
        kind=FindingKind.EVIDENCE_DOES_NOT_SUPPORT_CLAIM,
        policy_id="research-evidence",
        origin=FindingOrigin.SEMANTIC_MODEL_DERIVED,
        summary="Ascii Style.Truncate discards the requested tail",
        detail="Please pass the stripped tail through the Ascii branch.",
        provenance=_semantic_provenance(),
    )
    rejected = ResponseRecordedPayload(
        finding_id=fnd(1),
        finding_frontier=FRONTIER,
        disposition=ResponseDisposition.REJECTED,
        reason=(
            "The user explicitly requires Ascii Style.Truncate to return plain text without a "
            "tail; adding the tail would violate the task."
        ),
    )
    for response in (
        rejected,
        replace(rejected, finding_frontier=replace(FRONTIER, sequence=FRONTIER.sequence - 1)),
    ):
        case = make_case(
            findings={fnd(1): record(semantic, 1)},
            responses={fnd(1): record(response, 2)},
            extra_refs=(evt(99),),
        )
        assert FindingKind.WEAK_OR_STALE_RESPONSE not in _kinds(case)


def _semantic_provenance() -> SemanticProvenance:
    digest = "sha256:" + "1" * 64
    return SemanticProvenance(
        provider="fake",
        endpoint_profile_id="fake",
        endpoint_profile_version="1.0.0",
        model="fake/model",
        sdk_version="1.0.0",
        prompt_digest=digest,
        schema_digest=digest,
        policy_digest=digest,
        privacy_policy_digest=digest,
        sampling_params=SamplingParams(128),
        latency_ms=1,
        semantic_attempt_id="att_00000000-0000-4000-8000-000000000001",
        dispatch_kind=SemanticDispatchKind.EXTERNAL,
        privacy_receipt_id="egr_00000000-0000-4000-8000-000000000001",
        status=SemanticStatus.SUCCEEDED,
        reason=SemanticReason.SEMANTIC_COMPLETED,
        provider_request_id="fake-1",
        egress_authorization_id="aut_00000000-0000-4000-8000-000000000001",
        request_commitment="hmac-sha256:" + "b" * 64,
    )


def test_supported_rejection_at_the_findings_own_frontier_is_not_stale() -> None:
    """respond requires a frontier that already carries the finding_recorded event, so the
    frontier that validates necessarily follows the subject the check tested. Only a response
    aimed at an older state is stale (issue #192)."""

    finding = _recorded_finding()
    evidence = _evidence(1)
    recorded_frontier = replace(FRONTIER, sequence=FRONTIER.sequence + 2)
    supported = ResponseRecordedPayload(
        finding_id=fnd(1),
        finding_frontier=recorded_frontier,
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
    assert FindingKind.WEAK_OR_STALE_RESPONSE not in _kinds(near)

    older = replace(supported, finding_frontier=replace(FRONTIER, sequence=FRONTIER.sequence - 1))
    trigger = make_case(
        evidence={evd(1): evidence_record(evidence, 1)},
        findings={fnd(1): record(finding, 2)},
        responses={fnd(1): record(older, 3)},
        extra_refs=(evt(99),),
    )
    assert FindingKind.WEAK_OR_STALE_RESPONSE in _kinds(trigger)


def test_finding_coverage_adds_only_engine_and_deterministic_dimensions() -> None:
    result = _result(1, 1, ResultOutcome.SUCCESS)
    case = make_case(results={res(1): record(result, 1)})
    assessment = next(
        item
        for item in run_deterministic_policies(
            case,
            WORK_INTEGRITY_POLICY_PACK,
        ).assessments
        if item.candidate.kind is FindingKind.RESULT_WITHOUT_ACTION
    )
    coverage = assessment.candidate.coverage
    assert tuple(channel.value for channel in coverage.publication_channels) == (
        "cooperative_mcp",
        "engine_derived",
    )
    assert tuple(check.value for check in coverage.check_types) == ("deterministic",)
    assert coverage.authorship_assurance is BASE_COVERAGE.authorship_assurance
    assert coverage.artifact_observation is BASE_COVERAGE.artifact_observation
    assert coverage.evidence_immutability is BASE_COVERAGE.evidence_immutability
    assert coverage.ledger_freshness is BASE_COVERAGE.ledger_freshness
