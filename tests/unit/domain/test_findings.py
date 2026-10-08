"""Contract tests for canonical finding and AI-powered review provenance values."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import FrozenInstanceError, fields, replace
from types import MappingProxyType
from typing import cast

import pytest

from yoetz.domain.findings import (
    FINDING_KIND_TRAITS,
    CandidateFinding,
    CheckVerdict,
    CostFields,
    DeterministicFinding,
    Finding,
    FindingKind,
    FindingOrigin,
    RankedFindings,
    ResponseDisposition,
    SamplingParams,
    SemanticDispatchKind,
    SemanticFailureClass,
    SemanticFinding,
    SemanticProvenance,
    TokenUsage,
    WaiverScope,
    finding_from_json,
    finding_to_json,
    rank_key,
    semantic_provenance_from_json,
    semantic_provenance_to_json,
)
from yoetz.domain.values import (
    Frontier,
    JsonObject,
    claim_id,
    event_id,
    finding_id,
    obligation_id,
)
from yoetz.protocol.canonical import JsonValue as CanonicalJsonValue
from yoetz.protocol.canonical import canonical_encode
from yoetz.protocol.coverage import (
    ArtifactObservation,
    AuthorshipAssurance,
    CheckType,
    Coverage,
    EvidenceImmutability,
    LedgerFreshness,
    PublicationChannel,
    weakest,
)
from yoetz.protocol.errors import ProtocolValueError
from yoetz.protocol.models import SemanticReason, SemanticStatus
from yoetz.protocol.schemas import validate_schema_instance

_UUID_ONE = "00000000-0000-4000-8000-000000000001"
_UUID_TWO = "00000000-0000-4000-8000-000000000002"
_UUID_THREE = "00000000-0000-4000-8000-000000000003"
_DIGEST = "sha256:" + "0" * 64
_COMMITMENT = "hmac-sha256:" + "1" * 64

_WORK_INTEGRITY_KINDS = frozenset(
    {
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
)
_COORDINATION_KINDS = frozenset({FindingKind.COORDINATION_OVERLAP})


def _assert_reason(reason: str, operation: Callable[[], object]) -> None:
    with pytest.raises(ProtocolValueError) as caught:
        operation()
    assert caught.value.reason_code == reason


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


def _provenance(
    *,
    status: SemanticStatus = SemanticStatus.SUCCEEDED,
    reason: SemanticReason = SemanticReason.SEMANTIC_COMPLETED,
    dispatch_kind: SemanticDispatchKind = SemanticDispatchKind.EXTERNAL,
) -> SemanticProvenance:
    external = dispatch_kind is SemanticDispatchKind.EXTERNAL
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
        sampling_params=SamplingParams(
            max_output_tokens=2_048,
            temperature="0.20",
            top_p="1.0",
            seed=7,
        ),
        latency_ms=321,
        semantic_attempt_id="att_" + _UUID_ONE,
        dispatch_kind=dispatch_kind,
        privacy_receipt_id="egr_" + _UUID_TWO,
        status=status,
        reason=reason,
        provider_request_id="request:abc-123",
        token_usage=TokenUsage(input_tokens=12, output_tokens=7, total_tokens=19),
        cost_fields=CostFields(
            currency="USD",
            input_microunits=12,
            output_microunits=14,
            total_microunits=26,
        ),
        failure_class=None,
        egress_authorization_id="aut_" + _UUID_THREE if external else None,
        local_disclosure_reservation_id=None if external else "ppr_" + _UUID_THREE,
        request_commitment=_COMMITMENT if external else None,
    )


def _policy_identity(kind: FindingKind) -> tuple[str, str]:
    if kind in _WORK_INTEGRITY_KINDS:
        return "work-integrity", "0.1.0"
    if kind in _COORDINATION_KINDS:
        return "coordination", "0.1.0"
    return "research-evidence", "0.1.0"


def _finding(
    *,
    kind: FindingKind = FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS,
    origin: FindingOrigin = FindingOrigin.DETERMINISTIC,
    provenance: SemanticProvenance | None = None,
    identifier: str = "fnd_" + _UUID_ONE,
    coverage: Coverage | None = None,
    summary: str = "Open obligation remains",
    detail: str = "Resolve obligation obl_00000000-0000-4000-8000-000000000001.",
) -> Finding:
    if origin is FindingOrigin.SEMANTIC_MODEL_DERIVED and provenance is None:
        provenance = _provenance()
    policy_id, policy_version = _policy_identity(kind)
    return Finding(
        finding_id=finding_id(identifier),
        kind=kind,
        origin=origin,
        priority=FINDING_KIND_TRAITS[kind][0],
        summary=summary,
        detail=detail,
        subject_refs=(obligation_id("obl_" + _UUID_ONE),),
        policy_id=policy_id,
        policy_version=policy_version,
        subject_frontier=Frontier(1, _DIGEST),
        coverage=_coverage() if coverage is None else coverage,
        provenance=provenance,
    )


def test_finding_kind_traits_are_exhaustive_and_exact() -> None:
    expected = {
        FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS: (1, True),
        FindingKind.REQUESTED_ITEM_NEVER_ATTEMPTED: (2, True),
        FindingKind.FAILED_WORK_OMITTED: (1, True),
        FindingKind.CLAIM_WITHOUT_ADMISSIBLE_EVIDENCE: (1, True),
        FindingKind.RESULT_WITHOUT_ACTION: (2, True),
        FindingKind.ACTION_WITHOUT_RESULT: (3, True),
        FindingKind.STALE_EVIDENCE_FOR_CHANGED_STATE: (2, True),
        FindingKind.CONTRADICTORY_CLAIMS_UNRESOLVED: (1, True),
        FindingKind.LEDGER_STALE_OR_INCOMPLETE: (3, False),
        FindingKind.WEAK_OR_STALE_RESPONSE: (2, True),
        FindingKind.EVIDENCE_DOES_NOT_SUPPORT_CLAIM: (1, True),
        FindingKind.DIFF_DOES_NOT_MATCH_ACCOUNT: (1, True),
        FindingKind.MATERIAL_LIMITATION_OMITTED: (1, True),
        FindingKind.QUESTIONABLE_FINDING_REJECTION: (2, True),
        FindingKind.COORDINATION_OVERLAP: (2, True),
        FindingKind.CODE_DEFECT: (1, True),
        FindingKind.TASK_REQUIREMENT_UNMET: (1, True),
    }
    assert isinstance(FINDING_KIND_TRAITS, MappingProxyType)
    assert dict(FINDING_KIND_TRAITS) == expected
    assert set(FINDING_KIND_TRAITS) == set(FindingKind)


def test_nominal_public_enums_are_closed() -> None:
    assert [member.value for member in CheckVerdict] == [
        "action_required",
        "no_issue_detected",
        "insufficient_coverage",
        "incomplete_check",
    ]
    assert tuple(WaiverScope) == (WaiverScope.FINDING_ONLY,)
    assert {member.value for member in ResponseDisposition} == {
        "acknowledged",
        "acknowledged_not_done",
        "duplicate_of",
        "provenance_disputed",
        "rejected",
        "self_verified",
        "waived",
    }
    assert "pass" not in {member.value for member in CheckVerdict}
    assert DeterministicFinding is Finding
    assert SemanticFinding is Finding


def test_finding_requires_bounded_subject_refs() -> None:
    base = _finding()
    canonical_refs = (
        claim_id("clm_" + _UUID_ONE),
        event_id("evt_" + _UUID_TWO),
        obligation_id("obl_" + _UUID_THREE),
    )
    accepted = replace(base, subject_refs=canonical_refs)
    assert accepted.subject_refs == canonical_refs

    _assert_reason(
        "invalid_finding_subject_refs",
        lambda: replace(base, subject_refs=cast(tuple[object, ...], ())),
    )
    _assert_reason(
        "invalid_finding_subject_refs",
        lambda: replace(
            base,
            subject_refs=cast(tuple[object, ...], tuple("evt_" + _UUID_ONE for _ in range(65))),
        ),
    )
    _assert_reason(
        "duplicate_set_member",
        lambda: replace(base, subject_refs=(event_id("evt_" + _UUID_ONE),) * 2),
    )
    _assert_reason(
        "unsorted_set_field",
        lambda: replace(
            base,
            subject_refs=(
                obligation_id("obl_" + _UUID_ONE),
                event_id("evt_" + _UUID_ONE),
            ),
        ),
    )
    _assert_reason(
        "invalid_finding_subject_refs",
        lambda: replace(
            base,
            subject_refs=cast(tuple[object, ...], ("res_" + _UUID_ONE,)),
        ),
    )


def test_priority_and_origin_validation() -> None:
    base = _finding()
    _assert_reason("finding_priority_mismatch", lambda: replace(base, priority=2))
    _assert_reason("finding_priority_mismatch", lambda: replace(base, priority=cast(int, True)))
    _assert_reason(
        "invalid_finding_origin",
        lambda: replace(base, origin=cast(FindingOrigin, "deterministic-ish")),
    )
    _assert_reason(
        "invalid_finding_kind",
        lambda: replace(base, kind=cast(FindingKind, "unknown")),
    )


@pytest.mark.parametrize(
    ("status", "reason"),
    [
        (SemanticStatus.REFUSED, SemanticReason.PROVIDER_REFUSED),
        (SemanticStatus.TIMEOUT, SemanticReason.PROVIDER_TIMEOUT),
        (SemanticStatus.INVALID, SemanticReason.RESPONSE_SCHEMA_INVALID),
        (SemanticStatus.UNAVAILABLE, SemanticReason.TRANSPORT_UNAVAILABLE),
        (SemanticStatus.LATE, SemanticReason.DEADLINE_AUTHORITY_LOST),
        (SemanticStatus.STALE, SemanticReason.FRONTIER_CHANGED),
        (SemanticStatus.FAILED, SemanticReason.COORDINATOR_FAILURE),
    ],
)
def test_semantic_finding_requires_successful_final_provenance(
    status: SemanticStatus,
    reason: SemanticReason,
) -> None:
    successful = _finding(origin=FindingOrigin.SEMANTIC_MODEL_DERIVED)
    assert successful.provenance is not None
    terminal_attempt = _provenance(status=status, reason=reason)
    _assert_reason(
        "invalid_finding_provenance",
        lambda: replace(successful, provenance=terminal_attempt),
    )
    _assert_reason(
        "invalid_finding_provenance",
        lambda: CandidateFinding(
            kind=successful.kind,
            origin=successful.origin,
            priority=successful.priority,
            summary=successful.summary,
            detail=successful.detail,
            subject_refs=successful.subject_refs,
            policy_id=successful.policy_id,
            policy_version=successful.policy_version,
            subject_frontier=successful.subject_frontier,
            coverage=successful.coverage,
            provenance=terminal_attempt,
        ),
    )


def test_semantic_finding_without_provenance_is_invalid() -> None:
    successful = _finding(origin=FindingOrigin.SEMANTIC_MODEL_DERIVED)
    _assert_reason(
        "invalid_finding_provenance",
        lambda: replace(successful, provenance=None),
    )


def test_deterministic_finding_forbids_provenance() -> None:
    _assert_reason(
        "invalid_finding_provenance",
        lambda: replace(_finding(), provenance=_provenance()),
    )


@pytest.mark.parametrize("kind", tuple(FindingKind))
def test_finding_kind_is_independent_of_origin(kind: FindingKind) -> None:
    deterministic = _finding(kind=kind)
    semantic = _finding(kind=kind, origin=FindingOrigin.SEMANTIC_MODEL_DERIVED)
    assert deterministic.kind is semantic.kind is kind
    assert deterministic.origin is FindingOrigin.DETERMINISTIC
    assert semantic.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED


@pytest.mark.parametrize("kind", tuple(FindingKind))
def test_finding_policy_identity_is_derived_from_kind_owner(kind: FindingKind) -> None:
    accepted = _finding(kind=kind)
    assert (accepted.policy_id, accepted.policy_version) == _policy_identity(kind)
    assert accepted.policy_id != "semantic-review"
    wrong_policy = (
        "research-evidence" if accepted.policy_id == "work-integrity" else "work-integrity"
    )
    _assert_reason(
        "invalid_finding_policy_identity",
        lambda: replace(accepted, policy_id=wrong_policy),
    )
    _assert_reason(
        "invalid_finding_policy_identity",
        lambda: replace(accepted, policy_version="0.1.1"),
    )


def test_reviewer_challenge_uses_existing_summary_and_detail() -> None:
    summary = "The claimed result conflicts with the cited evidence."
    detail = "Alternative: the command inspected an older tree. Verify the current tree digest."
    challenge = _finding(
        kind=FindingKind.EVIDENCE_DOES_NOT_SUPPORT_CLAIM,
        origin=FindingOrigin.SEMANTIC_MODEL_DERIVED,
        summary=summary,
        detail=detail,
    )
    assert challenge.summary == summary
    assert challenge.detail == detail
    assert [field.name for field in fields(Finding)] == [
        "finding_id",
        "kind",
        "origin",
        "priority",
        "summary",
        "detail",
        "subject_refs",
        "policy_id",
        "policy_version",
        "subject_frontier",
        "coverage",
        "provenance",
        "challenge",
        "related_finding_ids",
    ]
    # The remaining challenge fields are event facts (issue #905); the public finding wire keeps
    # carrying the challenge only as summary and detail.
    assert "challenge" not in finding_to_json(challenge)


def test_sampling_usage_cost_and_provenance_are_strict_and_frozen() -> None:
    provenance = _provenance()
    assert provenance.sampling_params.temperature == "0.20"
    with pytest.raises(FrozenInstanceError):
        setattr(provenance, "latency_ms", 1)

    _assert_reason("invalid_sampling_params", lambda: SamplingParams(max_output_tokens=True))
    _assert_reason("invalid_sampling_params", lambda: SamplingParams(max_output_tokens=8_193))
    _assert_reason(
        "invalid_sampling_params",
        lambda: SamplingParams(max_output_tokens=1, temperature="01.0"),
    )
    _assert_reason("invalid_token_usage", lambda: TokenUsage(0, -1, 0))
    _assert_reason("invalid_cost_fields", lambda: CostFields("usd", 0, 0, 0))


def test_semantic_provenance_dispatch_partition_and_terminal_pairs() -> None:
    local = _provenance(dispatch_kind=SemanticDispatchKind.LOCAL_MODEL)
    assert local.local_disclosure_reservation_id == "ppr_" + _UUID_THREE
    assert local.egress_authorization_id is None
    assert local.request_commitment is None

    _assert_reason(
        "invalid_semantic_provenance",
        lambda: replace(_provenance(), egress_authorization_id=None),
    )
    _assert_reason(
        "invalid_semantic_provenance",
        lambda: replace(local, local_disclosure_reservation_id=None),
    )
    _assert_reason(
        "invalid_semantic_status_reason_pair",
        lambda: replace(_provenance(), reason=SemanticReason.PROVIDER_TIMEOUT),
    )
    _assert_reason(
        "invalid_semantic_provenance",
        lambda: replace(
            _provenance(),
            status=SemanticStatus.NOT_REQUESTED,
            reason=SemanticReason.DETERMINISTIC_MODE,
        ),
    )


def test_semantic_provenance_codecs_preserve_exact_wire_spelling() -> None:
    provenance = replace(_provenance(), failure_class=SemanticFailureClass.TRANSPORT)
    encoded = semantic_provenance_to_json(provenance)
    assert encoded["latency_ms"] == "321"
    sampling = cast(JsonObject, encoded["sampling_params"])
    assert sampling["temperature"] == "0.20"
    assert sampling["max_output_tokens"] == "2048"
    validate_schema_instance("semantic-provenance", "1.0.0", cast(CanonicalJsonValue, encoded))
    assert semantic_provenance_from_json(encoded) == provenance
    assert canonical_encode(cast(CanonicalJsonValue, encoded)) == canonical_encode(
        cast(
            CanonicalJsonValue, semantic_provenance_to_json(semantic_provenance_from_json(encoded))
        )
    )

    with_unknown = JsonObject((*tuple(encoded.items()), ("unknown", True)))
    _assert_reason(
        "semantic_provenance_json_shape_invalid",
        lambda: semantic_provenance_from_json(with_unknown),
    )
    with_null_optional = JsonObject(
        (
            *tuple((key, value) for key, value in encoded.items() if key != "failure_class"),
            ("failure_class", None),
        )
    )
    _assert_reason(
        "semantic_provenance_json_shape_invalid",
        lambda: semantic_provenance_from_json(with_null_optional),
    )


def test_semantic_provenance_codec_rejects_noncanonical_domain_integers() -> None:
    encoded = semantic_provenance_to_json(_provenance())
    changed = JsonObject(
        tuple((key, "01" if key == "latency_ms" else value) for key, value in encoded.items())
    )
    _assert_reason(
        "noncanonical_integer_string",
        lambda: semantic_provenance_from_json(changed),
    )

    sampling = cast(JsonObject, encoded["sampling_params"])
    null_temperature = JsonObject(
        (
            *tuple((key, value) for key, value in sampling.items() if key != "temperature"),
            ("temperature", None),
        )
    )
    changed_sampling = JsonObject(
        tuple(
            (key, null_temperature if key == "sampling_params" else value)
            for key, value in encoded.items()
        )
    )
    _assert_reason(
        "semantic_provenance_json_shape_invalid",
        lambda: semantic_provenance_from_json(changed_sampling),
    )


def test_finding_codecs_are_exact_inverses() -> None:
    for original in (
        _finding(),
        _finding(
            kind=FindingKind.QUESTIONABLE_FINDING_REJECTION,
            origin=FindingOrigin.SEMANTIC_MODEL_DERIVED,
        ),
    ):
        encoded = finding_to_json(original)
        validate_schema_instance("finding", "1.0.0", cast(CanonicalJsonValue, encoded))
        decoded = finding_from_json(encoded)
        assert decoded == original
        assert canonical_encode(
            cast(CanonicalJsonValue, finding_to_json(decoded))
        ) == canonical_encode(cast(CanonicalJsonValue, encoded))


def test_finding_codec_rejects_open_or_non_frozen_objects() -> None:
    encoded = finding_to_json(_finding())
    _assert_reason(
        "finding_json_shape_invalid",
        lambda: finding_from_json(cast(JsonObject, dict(encoded))),
    )
    with_unknown = JsonObject((*tuple(encoded.items()), ("unknown", True)))
    _assert_reason("finding_json_shape_invalid", lambda: finding_from_json(with_unknown))
    with_null_provenance = JsonObject((*tuple(encoded.items()), ("provenance", None)))
    _assert_reason(
        "finding_json_shape_invalid",
        lambda: finding_from_json(with_null_provenance),
    )


def test_rank_key_is_deterministic_and_uses_id_as_final_tiebreak() -> None:
    earlier = _finding(identifier="fnd_" + _UUID_ONE)
    later = _finding(identifier="fnd_" + _UUID_TWO)
    assert rank_key(earlier) == rank_key(earlier)
    assert rank_key(earlier) < rank_key(later)
    assert rank_key(earlier)[-1] == earlier.finding_id.encode("ascii")

    semantic = _finding(origin=FindingOrigin.SEMANTIC_MODEL_DERIVED)
    assert rank_key(earlier)[:-1] < rank_key(semantic)[:-1]


def test_rank_key_prefers_stronger_coverage_without_strengthening_it() -> None:
    weak = _coverage(
        observation=ArtifactObservation.PUBLISHED_ONLY,
        immutability=EvidenceImmutability.MUTABLE_REFERENCE,
        freshness=LedgerFreshness.PARTIAL,
        assurance=AuthorshipAssurance.SELF_ASSERTED,
        checks=(CheckType.NONE,),
        gaps=("source_unavailable",),
    )
    strong = _coverage()
    weak_finding = _finding(coverage=weak)
    strong_finding = _finding(coverage=strong)
    assert rank_key(strong_finding) < rank_key(weak_finding)
    combined = weakest(strong, weak)
    assert combined.artifact_observation is weak.artifact_observation
    assert combined.evidence_immutability is weak.evidence_immutability
    assert combined.ledger_freshness is weak.ledger_freshness
    assert combined.authorship_assurance is weak.authorship_assurance
    assert combined.check_types == (CheckType.DETERMINISTIC,)
    assert combined.known_gaps == weak.known_gaps
    assert weak_finding.coverage == weak


def test_ranked_findings_has_exact_four_field_shape() -> None:
    finding = _finding()
    ranked = RankedFindings(
        findings=(finding,),
        suppressed_count=2,
        verdict=CheckVerdict.ACTION_REQUIRED,
        coverage=finding.coverage,
    )
    assert [field.name for field in fields(RankedFindings)] == [
        "findings",
        "suppressed_count",
        "verdict",
        "coverage",
    ]
    assert ranked.suppressed_count == 2
    with pytest.raises(FrozenInstanceError):
        setattr(ranked, "suppressed_count", 3)

    _assert_reason(
        "invalid_ranked_findings",
        lambda: replace(ranked, suppressed_count=cast(int, True)),
    )
    _assert_reason(
        "invalid_ranked_findings",
        lambda: replace(ranked, findings=(finding, finding)),
    )
