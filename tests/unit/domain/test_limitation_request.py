"""The reviewer's limitation request is a pure fact of the recorded finding (tb4n3 RC-1/RC-3).

It never reads the agent's own words (guard G2), so "I could not find it" can never qualify, and a
challenge asking the agent to ``act`` never qualifies (guard G1).
"""

from __future__ import annotations

import pytest

from builders.policy_cases import fnd, obl
from finishup.domain.findings import (
    FINDING_KIND_TRAITS,
    Finding,
    FindingChallenge,
    FindingKind,
    FindingOrigin,
    SemanticDispatchKind,
    SemanticProvenance,
    finding_demands_work,
    finding_policy_identity,
    is_limitation_request,
)
from finishup.domain.values import Frontier
from finishup.ports.semantic import SamplingParams
from finishup.protocol.coverage import (
    ArtifactObservation,
    AuthorshipAssurance,
    CheckType,
    Coverage,
    EvidenceImmutability,
    LedgerFreshness,
    PublicationChannel,
)
from finishup.protocol.models import SemanticReason, SemanticStatus

_DIGEST = "sha256:" + "3" * 64


def _provenance() -> SemanticProvenance:
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
        semantic_attempt_id="att_00000000-0000-4000-8000-000000000001",
        dispatch_kind=SemanticDispatchKind.EXTERNAL,
        privacy_receipt_id="egr_00000000-0000-4000-8000-000000000001",
        status=SemanticStatus.SUCCEEDED,
        reason=SemanticReason.SEMANTIC_COMPLETED,
        provider_request_id="fake-1",
        egress_authorization_id="aut_00000000-0000-4000-8000-000000000001",
        request_commitment="hmac-sha256:" + "b" * 64,
    )


def _finding(
    kind: FindingKind,
    *,
    origin: FindingOrigin = FindingOrigin.SEMANTIC_MODEL_DERIVED,
    next_step: str | None = "state_unresolved_limitation",
) -> Finding:
    semantic = origin is FindingOrigin.SEMANTIC_MODEL_DERIVED
    coverage = Coverage(
        publication_channels=(PublicationChannel.ENGINE_DERIVED,),
        authorship_assurance=AuthorshipAssurance.SERVICE_AUTHENTICATED,
        artifact_observation=ArtifactObservation.PUBLISHED_ONLY,
        evidence_immutability=EvidenceImmutability.METADATA_ONLY,
        ledger_freshness=LedgerFreshness.CURRENT,
        check_types=(
            (CheckType.DETERMINISTIC, CheckType.SEMANTIC_MODEL_DERIVED)
            if semantic
            else (CheckType.DETERMINISTIC,)
        ),
        known_gaps=(),
    )
    provenance = _provenance() if semantic else None
    challenge = (
        None
        if next_step is None or not semantic
        else FindingChallenge(
            discrepancy="The accuracy cannot be reproduced here.",
            alternative_interpretation="A hidden evaluator may measure it.",
            requested_next_step=next_step,
            uncertainty="Unknown.",
        )
    )
    return Finding(
        finding_id=fnd(1),
        kind=kind,
        origin=origin,
        priority=FINDING_KIND_TRAITS[kind][0],
        summary="A requirement cannot be verified.",
        detail="State the limitation.",
        subject_refs=(obl(1),),
        policy_id=finding_policy_identity(kind)[0],
        policy_version=finding_policy_identity(kind)[1],
        subject_frontier=Frontier(3, _DIGEST),
        coverage=coverage,
        provenance=provenance,
        challenge=challenge,
    )


def test_a_reviewer_limitation_request_on_a_requirement_kind_does_not_demand_work() -> None:
    finding = _finding(FindingKind.TASK_REQUIREMENT_UNMET)
    assert is_limitation_request(finding)
    assert not finding_demands_work(finding)


@pytest.mark.parametrize("next_step", ["act", "provide_evidence", "answer_question"])
def test_a_challenge_that_asks_for_work_never_qualifies(next_step: str) -> None:
    finding = _finding(FindingKind.TASK_REQUIREMENT_UNMET, next_step=next_step)
    assert not is_limitation_request(finding)
    assert finding_demands_work(finding)


def test_a_finding_without_a_reviewer_challenge_never_qualifies() -> None:
    finding = _finding(FindingKind.TASK_REQUIREMENT_UNMET, origin=FindingOrigin.DETERMINISTIC)
    assert not is_limitation_request(finding)
    assert finding_demands_work(finding)


def test_a_limitation_request_cannot_attach_to_a_code_defect() -> None:
    finding = _finding(FindingKind.CODE_DEFECT)
    assert not is_limitation_request(finding)
    assert finding_demands_work(finding)


def test_a_coverage_only_kind_never_demands_work() -> None:
    finding = _finding(FindingKind.LEDGER_STALE_OR_INCOMPLETE, origin=FindingOrigin.DETERMINISTIC)
    assert not finding_demands_work(finding)
