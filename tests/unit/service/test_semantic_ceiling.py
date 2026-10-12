"""Planning a review case below the channel ceiling (issue #907 Phase 1b)."""

from __future__ import annotations

from dataclasses import replace

import pytest

from builders.policy_cases import (
    claim_record,
    clm,
    evd,
    evidence_record,
    fnd,
    make_case,
    plan_record,
)
from builders.privacy_policies import machine_scope, minimal_external_policy
from yoetz.adapters.privacy.local_enforcer import LocalPrivacyEnforcer
from yoetz.application.check import (
    CheckScope,
    allocate_findings,
    prior_finding_ids,
    run_deterministic_policies,
)
from yoetz.application.egress import _within_excerpt_limits  # pyright: ignore[reportPrivateUsage]
from yoetz.application.semantic_case import (
    LineageSemanticCapacityExceeded,
    SemanticCaseCapacityExceeded,
    build_semantic_case,
    semantic_case_to_candidate_context,
    semantic_case_to_prepared_payload,
)
from yoetz.domain.events import (
    ClaimKind,
    ClaimRecordedPayload,
    EvidenceKind,
    EvidenceRecordedPayload,
    PlanPublishedPayload,
)
from yoetz.domain.findings import Finding, FindingKind
from yoetz.domain.privacy import (
    EgressChannel,
    PrivacyDecision,
    PrivacyOutcome,
    PrivacyPolicy,
    ReviewContextProfile,
    ReviewSelectionPolicy,
)
from yoetz.domain.values import ClaimId, EvidenceId, timestamp_from_string
from yoetz.kernel.deterministic_checks import DeterministicCase
from yoetz.kernel.projections import ClaimProjectionRecord, EvidenceProjectionRecord
from yoetz.ports.privacy import EffectivePrivacyPolicy
from yoetz.ports.semantic import SemanticCase
from yoetz.protocol.coverage import EvidenceImmutability
from yoetz.protocol.ids import IdKind, new_id
from yoetz.protocol.models import MAX_SEMANTIC_CASE_BYTES, DataCategory
from yoetz.service.semantic_ceiling import (
    CEILING_PLANNING_GAP,
    MAX_CEILING_PLANNING_ROUNDS,
    channel_admission,
    channel_prepared_limit,
    plan_under_channel_ceiling,
    with_ceiling_planning_gap,
)

_LIMIT = 262_144
_CURRENT = ReviewSelectionPolicy.for_profile(ReviewContextProfile.EXPANDED)


def _case(description: str, count: int = 64) -> DeterministicCase:
    evidence: dict[EvidenceId, EvidenceProjectionRecord] = {}
    for index in range(1, count + 1):
        evidence[evd(index)] = evidence_record(
            EvidenceRecordedPayload(
                evidence_id=evd(index),
                evidence_kind=EvidenceKind.TEST_RESULT,
                strength=EvidenceImmutability.METADATA_ONLY,
                observed_at=timestamp_from_string("2026-07-01T00:00:00.000Z"),
                description=description,
            ),
            index + 3,
        )
    claim = claim_record(
        ClaimRecordedPayload(
            clm(1), ClaimKind.COMPLETION, "Work is complete", tuple(evidence), obligation_refs=()
        ),
        3,
    )
    return make_case(
        plans={1: plan_record(PlanPublishedPayload(1, "Ship it", ()), 1)},
        claims={clm(1): claim},
        evidence=evidence,
        extra_refs=(clm(1), *evidence),
    )


def _builder(case: DeterministicCase):  # noqa: ANN202 - local test factory
    def build(selection: ReviewSelectionPolicy, gaps: tuple[str, ...] = ()) -> SemanticCase:
        return build_semantic_case(
            case_id="cas_90700000-0000-4000-8000-000000000002",
            frozen_case=case,
            dependency_digest="sha256:" + "b" * 64,
            findings=(),
            review_context_profile=ReviewContextProfile.EXPANDED,
            review_selection=selection,
            policy_id="pvy_90700000-0000-4000-8000-000000000001",
            policy_version="1",
            captured_content_gaps=gaps,
        )

    return build


def _prepared(case: SemanticCase) -> bytes:
    return semantic_case_to_prepared_payload(case, {item.item_id for item in case.items})


def _plan(case: DeterministicCase, limit: int) -> tuple[SemanticCase, ReviewSelectionPolicy, int]:
    build = _builder(case)
    return plan_under_channel_ceiling(
        build(_CURRENT),
        _CURRENT,
        limit,
        lambda selection: build(selection, with_ceiling_planning_gap(())),
    )


def test_the_limit_is_the_narrowest_ceiling_and_never_above_the_disclosure_bound() -> None:
    policy = minimal_external_policy()

    def with_llm(max_bytes: int, max_tokens: int):  # noqa: ANN202
        return replace(
            policy,
            channel_policies=tuple(
                replace(channel, max_bytes=max_bytes, max_tokens=max_tokens)
                if channel.channel is EgressChannel.LLM_INFERENCE
                else channel
                for channel in policy.channel_policies
            ),
        )

    assert channel_prepared_limit(with_llm(262_144, 65_536)) == 262_144
    assert channel_prepared_limit(with_llm(262_144, 4_096)) == 16_384
    assert channel_prepared_limit(with_llm(0, 1_000)) == 4_000
    # Unset or high ceilings still plan below the largest disclosure egress can prepare.
    assert channel_prepared_limit(with_llm(0, 0)) == 262_144
    assert channel_prepared_limit(with_llm(0, 100_000)) == 262_144


def test_a_case_over_the_ceiling_is_rebuilt_below_it_with_the_reduction_disclosed() -> None:
    # 4,000 quotes escape to about 8 KB per excerpt. Excerpts now carry their approved bytes
    # instead of a 4 KiB structural clip (#907 Phase 1a), so the fixture carries 4 KB itself.
    case = _case('"' * 4_000)
    unplanned = _builder(case)(_CURRENT)
    # Without planning, egress would refuse this whole packet.
    assert len(_prepared(unplanned)) > _LIMIT

    planned, selection, rounds = _plan(case, _LIMIT)

    prepared = _prepared(planned)
    assert len(prepared) <= _LIMIT
    assert _within_excerpt_limits(prepared, _CURRENT)
    assert 1 <= rounds <= MAX_CEILING_PLANNING_ROUNDS
    assert CEILING_PLANNING_GAP in planned.packet.coverage.known_gaps
    # A narrowing of the approved selection, never a widening, and still more than 16 excerpts.
    assert selection.max_total_excerpt_bytes < _CURRENT.max_total_excerpt_bytes
    assert selection.max_excerpts == _CURRENT.max_excerpts
    assert 16 < len(planned.packet.targeted_excerpts) < len(unplanned.packet.targeted_excerpts)
    # A replay or recovery builds the identical case.
    again, _, _ = _plan(case, _LIMIT)
    assert again.case_digest == planned.case_digest


def test_a_case_within_the_ceiling_is_left_exactly_as_built() -> None:
    case = _case("test run: 12 passed, 0 failed", count=40)
    built = _builder(case)(_CURRENT)

    planned, selection, rounds = _plan(case, _LIMIT)

    assert (rounds, selection) == (0, _CURRENT)
    assert planned.case_digest == built.case_digest
    assert CEILING_PLANNING_GAP not in planned.packet.coverage.known_gaps
    assert len(planned.packet.targeted_excerpts) == 40


def test_a_ceiling_nothing_fits_under_is_left_for_egress_to_deny() -> None:
    case = _case('"' * 8_000)

    planned, selection, rounds = _plan(case, 1_024)

    assert rounds == 1
    assert selection.max_excerpts == 0
    assert planned.packet.targeted_excerpts == ()
    assert len(_prepared(planned)) > 1_024


class _Ids:
    def new(self, kind: IdKind) -> str:
        return new_id(kind)


def _prose_heavy_case(
    excerpts: int, unsupported_claims: int = 18
) -> tuple[DeterministicCase, tuple[Finding, ...]]:
    """18 claims with no admissible evidence, and one claim that ``excerpts`` 2,000-byte rows
    support. Each finding carries 8,192-byte summary and detail prose, which the builder clips to
    its 4,096-byte item bound (the R944-01 review trigger)."""

    evidence: dict[EvidenceId, EvidenceProjectionRecord] = {}
    for index in range(1, excerpts + 1):
        evidence[evd(index)] = evidence_record(
            EvidenceRecordedPayload(
                evidence_id=evd(index),
                evidence_kind=EvidenceKind.TEST_RESULT,
                strength=EvidenceImmutability.METADATA_ONLY,
                observed_at=timestamp_from_string("2026-07-01T00:00:00.000Z"),
                description="e" * 2_000,
            ),
            index + 30,
        )
    claims: dict[ClaimId, ClaimProjectionRecord] = {
        clm(1): claim_record(
            ClaimRecordedPayload(
                clm(1),
                ClaimKind.COMPLETION,
                "Work is complete",
                tuple(evidence),
                obligation_refs=(),
            ),
            3,
        )
    }
    for number in range(2, unsupported_claims + 2):
        claims[clm(number)] = claim_record(
            ClaimRecordedPayload(
                clm(number), ClaimKind.COMPLETION, f"Claim {number}", (), obligation_refs=()
            ),
            number + 3,
        )
    case = make_case(
        plans={1: plan_record(PlanPublishedPayload(1, "Ship it", ()), 1)},
        claims=claims,
        evidence=evidence,
        extra_refs=(*claims, *evidence),
    )
    assessments, _ = run_deterministic_policies(
        case, CheckScope((), ()), ("research-evidence/0.2.0", "work-integrity/0.3.0")
    )
    base = allocate_findings(
        _Ids(), tuple(item.candidate for item in assessments), prior_finding_ids(case.projection)
    )
    findings = tuple(
        replace(finding, finding_id=fnd(index), summary="s" * 8_192, detail="d" * 8_192)
        for index, finding in enumerate(base, 1)
    )
    return case, findings


def _prose_builder(case: DeterministicCase, findings: tuple[Finding, ...]):  # noqa: ANN202
    def build(selection: ReviewSelectionPolicy, gaps: tuple[str, ...] = ()) -> SemanticCase:
        return build_semantic_case(
            case_id="cas_90700000-0000-4000-8000-000000000003",
            frozen_case=case,
            dependency_digest="sha256:" + "b" * 64,
            findings=findings,
            review_context_profile=ReviewContextProfile.EXPANDED,
            review_selection=selection,
            policy_id="pvy_90700000-0000-4000-8000-000000000001",
            policy_version="1",
            captured_content_gaps=gaps,
        )

    return build


def _excerpt_refs(case: SemanticCase) -> set[str]:
    return {item.source_ref for item in case.items if item.section == "excerpt"}


def test_a_case_over_the_aggregate_case_bound_is_narrowed_before_it_is_constructed() -> None:
    """R944-01: 64 excerpts must not make the builder raise before the planner can narrow them."""

    case, findings = _prose_heavy_case(64)
    assert len(findings) == 18
    assert {finding.kind for finding in findings} == {FindingKind.CLAIM_WITHOUT_ADMISSIBLE_EVIDENCE}
    build = _prose_builder(case, findings)
    legacy = build(
        ReviewSelectionPolicy.for_profile(ReviewContextProfile.EXPANDED, preset_version="1.1.0")
    )
    assert len(legacy.packet.targeted_excerpts) == 16
    assert legacy.excerpts_cut_for_case_bound == 0
    fixed = sum(item.content_bytes for item in legacy.items if item.section != "excerpt")
    # Every approved excerpt beside the fixed part is over the case's aggregate bound.
    assert fixed + 64 * 2_000 > MAX_SEMANTIC_CASE_BYTES

    built = build(_CURRENT)

    assert sum(item.content_bytes for item in built.items) <= MAX_SEMANTIC_CASE_BYTES
    assert 16 < len(built.packet.targeted_excerpts) < 64
    # The cut is reported as its own cause, distinct from consent and from ceiling planning.
    assert built.excerpts_cut_for_case_bound == 64 - len(built.packet.targeted_excerpts)
    assert "content_unselected" in built.packet.coverage.known_gaps
    # Every cut is disclosed as an unselected excerpt, and the highest-ranked excerpts stay: with
    # no diff or verification output to reserve room for, ledger evidence ranks by recency
    # (#907 Phase 1a), so the newest rows are kept and the oldest are cut.
    kept = _excerpt_refs(built)
    assert kept == {str(evd(index)) for index in range(65 - len(kept), 65)}
    omitted = {
        omission.subject_ref
        for omission in built.packet.omissions
        if omission.category is DataCategory.EVIDENCE_EXCERPT and omission.reason == "not_selected"
    }
    assert omitted == {str(evd(index)) for index in range(1, 65)} - kept
    assert build(_CURRENT).case_digest == built.case_digest

    planned, selection, _ = plan_under_channel_ceiling(
        built,
        _CURRENT,
        _LIMIT,
        lambda narrowed: build(narrowed, with_ceiling_planning_gap(())),
    )
    assert len(_prepared(planned)) <= _LIMIT
    assert selection.max_total_excerpt_bytes <= _CURRENT.max_total_excerpt_bytes


def test_fixed_material_over_the_case_bound_is_a_typed_capacity_refusal() -> None:
    """The residual: without any excerpt, 32 findings' clipped prose alone is over the bound.

    Cutting excerpts cannot help, so the builder refuses with a typed capacity error the
    composition maps to ``case_capacity_exceeded`` instead of the constructor's generic
    ``semantic_case_invalid``.
    """

    # The completion claim has no evidence either, so 31 unsupported claims give 32 findings.
    case, findings = _prose_heavy_case(0, unsupported_claims=31)
    assert len(findings) == 32

    with pytest.raises(SemanticCaseCapacityExceeded) as raised:
        _prose_builder(case, findings)(_CURRENT)
    assert type(raised.value) is not LineageSemanticCapacityExceeded


def _withholding_policy() -> PrivacyPolicy:
    policy = minimal_external_policy()
    return replace(
        policy, review_context_profile=ReviewContextProfile.EXPANDED, review_selection=_CURRENT
    )


def _egress_prepared(case: SemanticCase, policy: PrivacyPolicy) -> bytes:
    """What the local privacy enforcer would release for ``case`` on the LLM channel."""

    llm = next(
        channel
        for channel in policy.channel_policies
        if channel.channel is EgressChannel.LLM_INFERENCE
    )
    assert llm.provider_binding is not None
    enforcer = LocalPrivacyEnforcer()
    candidate = semantic_case_to_candidate_context(
        case,
        request_id="req_10000000-0000-4000-8000-000000000003",
        scope=machine_scope(),
        provider_binding=llm.provider_binding,
    )
    classified = enforcer.classify(
        candidate, EffectivePrivacyPolicy(policy, 1, "sha256:" + "2" * 64)
    )
    # The same category and data-class ceiling egress applies before minimization.
    approved = tuple(
        item.candidate.item_id
        for item in classified.items
        if item.candidate.category in llm.allowed_categories
        and item.data_class in llm.allowed_data_classes
        and not item.forbidden_findings
    )
    minimized = enforcer.minimize_and_scan(
        classified, PrivacyDecision(approved, (), PrivacyOutcome.COMPLETED, None)
    )
    return minimized.prepared_bytes


def test_items_the_channel_withholds_do_not_cost_eligible_excerpts() -> None:
    """R944-02: the planner measures what egress releases, not every item the case carries."""

    policy = _withholding_policy()
    llm = next(
        channel
        for channel in policy.channel_policies
        if channel.channel is EgressChannel.LLM_INFERENCE
    )
    assert DataCategory.FINDING_SUMMARY not in llm.allowed_categories
    case, findings = _prose_heavy_case(40)
    build = _prose_builder(case, findings)
    built = build(_CURRENT)
    assert len(built.packet.targeted_excerpts) == 40
    # Counting the withheld finding prose, the packet looks over the ceiling; what egress would
    # actually release is well under it.
    assert len(_prepared(built)) > _LIMIT
    assert len(_egress_prepared(built, policy)) <= _LIMIT

    planned, selection, rounds = plan_under_channel_ceiling(
        built,
        _CURRENT,
        _LIMIT,
        lambda narrowed: build(narrowed, with_ceiling_planning_gap(())),
        channel_admission(policy, (llm.provider_binding,)),
    )

    assert (rounds, selection) == (0, _CURRENT)
    assert planned.case_digest == built.case_digest
    assert len(planned.packet.targeted_excerpts) == 40
    assert CEILING_PLANNING_GAP not in planned.packet.coverage.known_gaps


def test_the_planner_brings_the_released_payload_under_a_narrow_ceiling() -> None:
    """R944-02: when the released payload is over the ceiling, planning sizes that payload."""

    policy = _withholding_policy()
    llm = next(
        channel
        for channel in policy.channel_policies
        if channel.channel is EgressChannel.LLM_INFERENCE
    )
    case, findings = _prose_heavy_case(40)
    build = _prose_builder(case, findings)
    built = build(_CURRENT)
    released = len(_egress_prepared(built, policy))
    limit = released - 20_000

    planned, _, rounds = plan_under_channel_ceiling(
        built,
        _CURRENT,
        limit,
        lambda narrowed: build(narrowed, with_ceiling_planning_gap(())),
        channel_admission(policy, (llm.provider_binding,)),
    )

    assert rounds >= 1
    assert len(_egress_prepared(planned, policy)) <= limit
    assert CEILING_PLANNING_GAP in planned.packet.coverage.known_gaps
    # Only the released payload had to shrink, so most excerpts stay.
    assert len(planned.packet.targeted_excerpts) > 16
