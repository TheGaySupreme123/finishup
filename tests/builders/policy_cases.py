"""Small immutable local cases for policy rule unit tests."""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast, overload

from finishup.domain.events import (
    ActionRecordedPayload,
    AssignmentRecordedPayload,
    ClaimRecordedPayload,
    ClaimRecordedPayloadV1_1,
    EventPayload,
    EvidenceRecordedPayload,
    ObligationChangeKind,
    ObligationPublishedPayload,
    PlanPublishedPayload,
    PlanRevisedPayload,
    ResponseRecordedPayload,
    ResultRecordedPayload,
    encode_payload,
)
from finishup.domain.findings import Finding
from finishup.domain.values import (
    ActionId,
    ClaimId,
    EventId,
    EvidenceId,
    FindingId,
    Frontier,
    ObligationId,
    ResultId,
    action_id,
    claim_id,
    event_id,
    evidence_id,
    finding_id,
    obligation_id,
    result_id,
)
from finishup.kernel.deterministic_checks import (
    CaseAvailabilityFacts,
    CaseGap,
    DeterministicCase,
    FindingBasisRef,
)
from finishup.kernel.projections import (
    ClaimProjectionRecord,
    ContradictionKey,
    ContradictionRecord,
    DecisionProjectionRecord,
    EvidenceProjectionRecord,
    FindingProjectionRecord,
    ObligationProjectionRecord,
    PlanProjectionRecord,
    ProjectionRecord,
    ProjectionState,
    StandingPosition,
)
from finishup.protocol.canonical import canonical_digest
from finishup.protocol.coverage import (
    ArtifactObservation,
    AuthorshipAssurance,
    CheckType,
    Coverage,
    EvidenceImmutability,
    LedgerFreshness,
    PublicationChannel,
)

HEAD_DIGEST = "sha256:" + "a" * 64
FRONTIER = Frontier(100, HEAD_DIGEST)
BASE_COVERAGE = Coverage(
    publication_channels=(PublicationChannel.COOPERATIVE_MCP,),
    authorship_assurance=AuthorshipAssurance.SELF_ASSERTED,
    artifact_observation=ArtifactObservation.CONTENT_CAPTURED,
    evidence_immutability=EvidenceImmutability.IMMUTABLE_SNAPSHOT,
    ledger_freshness=LedgerFreshness.CURRENT,
    check_types=(CheckType.NONE,),
    known_gaps=(),
)


def evt(number: int) -> EventId:
    return event_id(f"evt_10000000-0000-4000-8000-{number:012x}")


def obl(number: int) -> ObligationId:
    return obligation_id(f"obl_10000000-0000-4000-8000-{number:012x}")


def act(number: int) -> ActionId:
    return action_id(f"act_10000000-0000-4000-8000-{number:012x}")


def res(number: int) -> ResultId:
    return result_id(f"res_10000000-0000-4000-8000-{number:012x}")


def evd(number: int) -> EvidenceId:
    return evidence_id(f"evd_10000000-0000-4000-8000-{number:012x}")


def clm(number: int) -> ClaimId:
    return claim_id(f"clm_10000000-0000-4000-8000-{number:012x}")


def fnd(number: int) -> FindingId:
    return finding_id(f"fnd_10000000-0000-4000-8000-{number:012x}")


@overload
def record(payload: Finding, number: int) -> FindingProjectionRecord: ...


@overload
def record(
    payload: ClaimRecordedPayload | ClaimRecordedPayloadV1_1, number: int
) -> ClaimProjectionRecord: ...


@overload
def record[T](payload: T, number: int) -> ProjectionRecord[T]: ...


def record[T](payload: T, number: int) -> ProjectionRecord[T]:
    if type(payload) is Finding:
        return cast(ProjectionRecord[T], finding_record(payload, number))
    if type(payload) in {ClaimRecordedPayload, ClaimRecordedPayloadV1_1}:
        return cast(
            ProjectionRecord[T],
            claim_record(cast(ClaimRecordedPayload | ClaimRecordedPayloadV1_1, payload), number),
        )
    return ProjectionRecord(
        payload=payload,
        payload_digest=canonical_digest(encode_payload(cast(EventPayload, payload))),
        redacted=False,
        source_event_id=evt(number),
        source_frontier=number,
    )


def claim_record(
    payload: ClaimRecordedPayload | ClaimRecordedPayloadV1_1,
    number: int,
    *,
    superseded_by_claim_id: ClaimId | None = None,
) -> ClaimProjectionRecord:
    return ClaimProjectionRecord(
        payload=payload,
        payload_digest=canonical_digest(encode_payload(payload)),
        redacted=False,
        source_event_id=evt(number),
        source_frontier=number,
        superseded_by_claim_id=superseded_by_claim_id,
    )


def finding_record(
    payload: Finding,
    number: int,
    *,
    resolved_by_check_event_id: EventId | None = None,
    resolution_frontier: int | None = None,
    standing_position: StandingPosition | None = None,
    last_ruling_frontier: int | None = None,
    absorbed_refs: tuple[str, ...] = (),
) -> FindingProjectionRecord:
    return FindingProjectionRecord(
        payload=payload,
        payload_digest=canonical_digest(encode_payload(payload)),
        redacted=False,
        source_event_id=evt(number),
        source_frontier=number,
        resolved_by_check_event_id=resolved_by_check_event_id,
        resolution_frontier=resolution_frontier,
        standing_position=standing_position,
        last_ruling_frontier=last_ruling_frontier,
        absorbed_refs=absorbed_refs,
    )


def plan_record(
    payload: PlanPublishedPayload | PlanRevisedPayload,
    number: int,
) -> PlanProjectionRecord:
    return PlanProjectionRecord(
        payload=payload,
        payload_digest=canonical_digest(encode_payload(payload)),
        redacted=False,
        source_event_id=evt(number),
        source_frontier=number,
    )


def obligation_record(
    payload: ObligationPublishedPayload,
    number: int,
    *,
    plan_change: ObligationChangeKind | None = None,
) -> ObligationProjectionRecord:
    return ObligationProjectionRecord(
        payload=payload,
        payload_digest=canonical_digest(encode_payload(payload)),
        redacted=False,
        source_event_id=evt(number),
        source_frontier=number,
        plan_change=plan_change,
    )


def evidence_record(
    payload: EvidenceRecordedPayload,
    number: int,
) -> EvidenceProjectionRecord:
    return EvidenceProjectionRecord(
        payload=payload,
        payload_digest=canonical_digest(encode_payload(payload)),
        redacted=False,
        source_event_id=evt(number),
        source_frontier=number,
    )


def make_case(
    *,
    plans: Mapping[int, PlanProjectionRecord] | None = None,
    obligations: Mapping[ObligationId, ObligationProjectionRecord] | None = None,
    actions: Mapping[ActionId, ProjectionRecord[ActionRecordedPayload]] | None = None,
    results: Mapping[ResultId, ProjectionRecord[ResultRecordedPayload]] | None = None,
    evidence: Mapping[EvidenceId, EvidenceProjectionRecord] | None = None,
    claims: Mapping[ClaimId, ClaimProjectionRecord] | None = None,
    findings: Mapping[FindingId, FindingProjectionRecord] | None = None,
    responses: Mapping[FindingId, ProjectionRecord[ResponseRecordedPayload]] | None = None,
    contradictions: Mapping[ContradictionKey, ContradictionRecord] | None = None,
    gaps: tuple[CaseGap, ...] = (),
    extra_refs: tuple[FindingBasisRef, ...] = (),
    coverage_overrides: Mapping[FindingBasisRef, Coverage] | None = None,
) -> DeterministicCase:
    plan_map = {} if plans is None else dict(plans)
    obligation_map = {} if obligations is None else dict(obligations)
    action_map = {} if actions is None else dict(actions)
    result_map = {} if results is None else dict(results)
    evidence_map = {} if evidence is None else dict(evidence)
    claim_map = {} if claims is None else dict(claims)
    finding_map = {} if findings is None else dict(findings)
    response_map = {} if responses is None else dict(responses)
    contradiction_map = {} if contradictions is None else dict(contradictions)
    projection = ProjectionState(
        frontier=FRONTIER.sequence,
        head_digest=FRONTIER.head_digest,
        plans=plan_map,
        obligations=obligation_map,
        decisions=cast(Mapping[EventId, DecisionProjectionRecord], {}),
        assignments=cast(Mapping[EventId, ProjectionRecord[AssignmentRecordedPayload]], {}),
        actions=action_map,
        results=result_map,
        evidence=evidence_map,
        claims=claim_map,
        contradictions=contradiction_map,
        findings=finding_map,
        responses=response_map,
        latest_tested_state=None,
        freshness=LedgerFreshness.CURRENT,
        unknown_event_count=0,
        coverage_gaps=(),
    )
    logical: dict[FindingBasisRef, EventId] = {}
    for mapping in (
        obligation_map,
        action_map,
        result_map,
        evidence_map,
        claim_map,
        finding_map,
    ):
        for ref, value in mapping.items():
            logical[cast(FindingBasisRef, ref)] = value.source_event_id
    source_events = {
        value.source_event_id
        for mapping in (
            plan_map,
            obligation_map,
            action_map,
            result_map,
            evidence_map,
            claim_map,
            finding_map,
            response_map,
        )
        for value in mapping.values()
    }
    allowed = set(logical) | set(source_events) | set(extra_refs)
    for gap in gaps:
        allowed.update(gap.subject_refs)
    for finding in finding_map.values():
        if finding.payload is not None:
            allowed.update(finding.payload.subject_refs)
    coverage = {ref: BASE_COVERAGE for ref in allowed}
    if coverage_overrides is not None:
        coverage.update(coverage_overrides)
    return DeterministicCase(
        projection=projection,
        frontier=FRONTIER,
        availability=CaseAvailabilityFacts(),
        allowed_ids=frozenset(allowed),
        coverage_by_ref=coverage,
        gaps=gaps,
    )
