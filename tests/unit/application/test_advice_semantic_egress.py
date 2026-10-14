"""Advice reaches a fake external reviewer only through approved categories (#1019)."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime
from importlib.resources import files
from typing import Any, cast

import pytest

from builders.privacy_policies import local_only_policy, minimal_external_policy
from builders.privacy_widenings import with_llm, with_review
from unit.application.test_egress_origin_operation import (
    _COMMITMENT,  # pyright: ignore[reportPrivateUsage]
    _DIGEST,  # pyright: ignore[reportPrivateUsage]
    _NOW,  # pyright: ignore[reportPrivateUsage]
    _REQUEST,  # pyright: ignore[reportPrivateUsage]
    _TASK,  # pyright: ignore[reportPrivateUsage]
    _Audit,  # pyright: ignore[reportPrivateUsage]
    _Clock,  # pyright: ignore[reportPrivateUsage]
    _Gateway,  # pyright: ignore[reportPrivateUsage]
    _Store,  # pyright: ignore[reportPrivateUsage]
)
from unit.privacy.test_planted_credentials_semantic_arm import (
    _AWS_KEY,  # pyright: ignore[reportPrivateUsage]
)
from yoetz.adapters.privacy.local_enforcer import LocalPrivacyEnforcer
from yoetz.adapters.providers.fake import scripted_success
from yoetz.application.egress import (
    PrivacyCoordinator,
    SemanticEgressBlocked,
    SemanticEgressSuccess,
    semantic_preview_required,
)
from yoetz.application.observation_advice import minimized_semantic_evidence_packet
from yoetz.application.observation_advice_semantic import (
    ObservationAdviceSemanticAttempt,
    observation_advice_to_candidate_context,
)
from yoetz.domain.findings import FINDING_KIND_TRAITS, FindingKind
from yoetz.domain.privacy import (
    REVIEW_PACKET_ITEM_ID,
    ApprovedOutboundCase,
    AuthorizationScope,
    AuthorizationScopeKind,
    CandidateContext,
    ConsentSource,
    DataClass,
    DisclosureProposal,
    EgressAuthorization,
    EgressChannel,
    EgressOriginOperation,
    PrivacyOutcome,
    PrivacyProfile,
    PrivacyReason,
    ProviderBinding,
    ReviewContextProfile,
    egress_origin_operation,
)
from yoetz.kernel.policies.observation_advice import ObservationAdviceCandidate
from yoetz.ports.clock import ClockPort
from yoetz.ports.ids import IdPort
from yoetz.ports.privacy import (
    DisclosureProposalRequest,
    HumanAuthorityCapability,
    OutboundGatewayPort,
    PreparedDisclosureReservation,
    PrivacyAuditPort,
    PrivacyClassifierPort,
    PrivacyPolicyStorePort,
)
from yoetz.ports.semantic import Deadline, SemanticJudgment, SemanticResultSuccess
from yoetz.protocol.canonical import (
    JsonValue,
    canonical_digest,
    canonical_encode,
    strict_json_parse,
)
from yoetz.protocol.ids import IdKind, new_id
from yoetz.protocol.models import DataCategory


class _Ids:
    def new(self, kind: IdKind) -> str:
        return str(new_id(kind))


class _DispatchAudit(_Audit):
    def __init__(self) -> None:
        super().__init__()
        self.proposal: DisclosureProposal | None = None

    async def prepare_disclosure_proposal(
        self, request: DisclosureProposalRequest
    ) -> PreparedDisclosureReservation:
        m = request.minimized
        proposal = DisclosureProposal(
            request.privacy_proposal_id,
            request.request_id,
            request.task_id,
            m.source_item_digests,
            m.prepared_bytes,
            m.approved_categories,
            m.blocked_categories,
            m.transformation_summary,
            m.case_digest,
            request.provider_binding,
            request.local_sink,
            request.purpose,
            request.scope,
            request.policy_version,
            request.policy_digest,
            request.max_bytes,
            request.max_tokens,
            request.expires_at,
            _COMMITMENT,
            included_item_ids=m.included_item_ids,
        )
        self.proposal = proposal
        return PreparedDisclosureReservation(proposal, await self.reserve(proposal))

    async def authorize(self, proposal_id: str, digest: str, now: datetime) -> EgressAuthorization:
        p = self.proposal
        assert p is not None and p.provider_binding is not None
        assert (proposal_id, digest) == (p.privacy_proposal_id, p.prepared_case_digest)
        return EgressAuthorization(
            str(new_id(IdKind.EGRESS_AUTHORIZATION)),
            proposal_id,
            digest,
            EgressChannel.LLM_INFERENCE,
            p.provider_binding,
            p.purpose,
            p.scope,
            p.policy_version,
            p.policy_digest,
            p.max_bytes,
            p.max_tokens,
            ConsentSource.BASELINE_POLICY,
            now,
            p.expires_at,
            1,
        )

    async def load(self, *_args: object) -> None:
        return None


class _FakeProvider(_Gateway):
    def __init__(self) -> None:
        self.cases: list[ApprovedOutboundCase] = []

    async def dispatch_external_semantic(
        self, case: ApprovedOutboundCase, authorization: EgressAuthorization, _deadline: Deadline
    ) -> SemanticResultSuccess:
        assert case.case_digest == authorization.case_digest
        assert case.authorization_id == authorization.authorization_id
        self.cases.append(case)
        result = scripted_success(SemanticJudgment("no_material_discrepancy", ())).result
        assert isinstance(result, SemanticResultSuccess)
        return result


def _candidate(
    packet: bytes | None = None,
    *,
    profile: ReviewContextProfile = ReviewContextProfile.ASSISTED,
    include_finding_prose: bool = True,
) -> CandidateContext:
    scope = AuthorizationScope(
        AuthorizationScopeKind.TASK,
        minimal_external_policy().effective_scope.installation_id,
        _COMMITMENT,
        _TASK,
    )
    binding = next(
        c.provider_binding
        for c in minimal_external_policy().channel_policies
        if c.channel is EgressChannel.LLM_INFERENCE
    )
    assert binding is not None
    packet = packet or canonical_encode(
        cast(
            JsonValue,
            minimized_semantic_evidence_packet(
                (
                    ObservationAdviceCandidate(
                        FindingKind.FAILED_WORK_OMITTED,
                        "failed_command_unresolved",
                        "resolve_failed_command",
                        ("hook:one",),
                        FINDING_KIND_TRAITS[FindingKind.FAILED_WORK_OMITTED][0],
                        "fixture",
                    ),
                ),
                _DIGEST,
                coverage_gaps=("source_lag",),
                finding_summaries=("A retained finding summary",),
            ),
        )
    )
    attempt = ObservationAdviceSemanticAttempt(
        "attempt",
        _COMMITMENT,
        "ses_40000000-0000-4000-8000-000000000001",
        "basis",
        canonical_digest(strict_json_parse(packet)),
        ("source_lag",),
        packet,
        "running",
        1,
    )
    return observation_advice_to_candidate_context(
        attempt,
        request_id=_REQUEST,
        scope=scope,
        provider_binding=binding,
        review_context_profile=profile,
        include_finding_prose=include_finding_prose,
    )


async def _evaluate(
    candidate: CandidateContext,
    *,
    summaries: bool = True,
    profile: ReviewContextProfile = ReviewContextProfile.ASSISTED,
    **channel: object,
) -> tuple[object, _DispatchAudit, _FakeProvider]:
    store = _Store()
    disabled = channel.pop("disabled", False)
    changes: dict[str, object] = {
        "allowed_categories": (
            DataCategory.BOUNDED_STRUCTURAL_METADATA,
            DataCategory.FINDING_SUMMARY,
        )
        if summaries
        else (DataCategory.BOUNDED_STRUCTURAL_METADATA,),
        "allowed_data_classes": (DataClass.PUBLIC_STRUCTURAL, DataClass.ORDINARY_USER_CONTENT),
        **channel,
    }
    store._policy = (  # pyright: ignore[reportPrivateUsage]
        local_only_policy()
        if disabled
        # pyright: ignore[reportPrivateUsage]
        else with_llm(with_review(minimal_external_policy(), profile), **changes)
    )
    audit, provider = _DispatchAudit(), _FakeProvider()
    coordinator = PrivacyCoordinator(
        cast(PrivacyPolicyStorePort, store),
        cast(PrivacyClassifierPort, LocalPrivacyEnforcer()),
        cast(PrivacyAuditPort, audit),
        cast(OutboundGatewayPort, provider),
        cast(ClockPort, _Clock()),
        cast(IdPort, _Ids()),
        human_authority=HumanAuthorityCapability(
            "established_passphrase",
            "sha256:" + "8" * 64,
            1,
            "passphrase",
            1,
            True,
        ),
    )
    return await coordinator.evaluate_semantic(candidate, Deadline(_NOW, 61.0)), audit, provider


@pytest.mark.anyio
@pytest.mark.parametrize("profile", [ReviewContextProfile.ASSISTED, ReviewContextProfile.EXPANDED])
@pytest.mark.parametrize("summaries", [False, True])
async def test_approved_advice_reaches_fake_provider_with_retained_content(
    profile: ReviewContextProfile,
    summaries: bool,
) -> None:
    result, _audit, provider = await _evaluate(
        _candidate(profile=profile), profile=profile, summaries=summaries
    )
    assert isinstance(result, SemanticEgressSuccess)
    (case,) = provider.cases
    payload = strict_json_parse(case.payload)
    assert isinstance(payload, dict)
    assert payload["review_context_profile"] == profile.value
    rows = cast(list[dict[str, JsonValue]], payload["items"])
    assert any("source_lag" in str(row["content"]) for row in rows)
    assert b"failed_command_unresolved" in case.payload
    assert (b"A retained finding summary" in case.payload) is summaries
    assert {cast(str, row["category"]) for row in rows} <= {
        c.value for c in case.approved_categories
    }
    assert (DataCategory.FINDING_SUMMARY in case.blocked_categories) is not summaries
    assert (
        egress_origin_operation(case.purpose, case.included_item_ids)
        is EgressOriginOperation.OBSERVATION_ADVICE
    )
    assert b"finding_summaries" not in _candidate().items[0].plaintext


@pytest.mark.anyio
@pytest.mark.parametrize(
    "envelope",
    [b"{}", b"[]", b"not json", b'{"schema":"wrong","review_packet":{},"item_catalog":[]}'],
)
async def test_invalid_advice_envelope_fails_closed_without_category_denial(
    envelope: bytes,
) -> None:
    candidate = _candidate()
    candidate = replace(
        candidate,
        items=tuple(
            replace(item, plaintext=envelope) if item.item_id == REVIEW_PACKET_ITEM_ID else item
            for item in candidate.items
        ),
    )
    result, audit, provider = await _evaluate(candidate, summaries=False)
    assert isinstance(result, SemanticEgressBlocked)
    assert result.reason is PrivacyReason.INSUFFICIENT_APPROVED_CONTEXT
    assert provider.cases == []
    (receipt,) = audit.receipts
    assert receipt.blocked_categories == (DataCategory.FINDING_SUMMARY,)
    assert receipt.counts.approved_items == 2
    assert receipt.counts.blocked_items == 1
    assert receipt.origin_operation is EgressOriginOperation.OBSERVATION_ADVICE


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("channel", "reason"),
    [
        ({"disabled": True}, PrivacyReason.DESTINATION_NOT_ALLOWED),
        ({"allowed_purposes": ("credential-probe",)}, PrivacyReason.PURPOSE_NOT_ALLOWED),
        (
            {
                "provider_binding": replace(
                    cast(ProviderBinding, _candidate().provider_binding), model_id="different"
                )
            },
            PrivacyReason.DESTINATION_NOT_ALLOWED,
        ),
        ({"max_bytes": 1}, PrivacyReason.POLICY_DENIED),
    ],
)
async def test_request_failure_does_not_invent_denied_categories(
    channel: dict[str, object], reason: PrivacyReason
) -> None:
    result, audit, provider = await _evaluate(_candidate(), **cast(dict[str, Any], channel))
    assert isinstance(result, SemanticEgressBlocked)
    assert result.reason is reason
    assert provider.cases == []
    (receipt,) = audit.receipts
    assert receipt.blocked_categories == ()
    assert receipt.safe_failure_reason is reason


@pytest.mark.anyio
async def test_category_denied_advice_never_dispatches() -> None:
    candidate = _candidate()
    # Every advice item denied by sensitivity, including its envelope.
    result, audit, provider = await _evaluate(candidate, allowed_data_classes=())
    assert isinstance(result, SemanticEgressBlocked)
    assert result.reason is PrivacyReason.CATEGORY_NOT_ALLOWED
    assert provider.cases == []
    (receipt,) = audit.receipts
    assert set(receipt.blocked_categories) == {
        DataCategory.BOUNDED_STRUCTURAL_METADATA,
        DataCategory.FINDING_SUMMARY,
    }


@pytest.mark.anyio
@pytest.mark.parametrize("summaries", [False, True])
async def test_advice_golden_vector_is_the_exact_approved_packet(summaries: bool) -> None:
    fixture = strict_json_parse(
        files("yoetz.resources")
        .joinpath("fixtures/canonical/advice-egress-1.1.0.case.json")
        .read_bytes()
    )
    assert isinstance(fixture, dict)
    source = cast(dict[str, JsonValue], fixture["input"])
    candidate = _candidate(
        canonical_encode(source["packet"]), profile=ReviewContextProfile.ASSISTED
    )
    assert [
        {
            "item_id": item.item_id,
            "category": item.category.value,
            "plaintext": item.plaintext.decode(),
        }
        for item in candidate.items
    ] == source["candidate_items"]
    result, _audit, provider = await _evaluate(candidate, summaries=summaries)
    assert isinstance(result, SemanticEgressSuccess)
    (case,) = provider.cases
    payload = cast(dict[str, JsonValue], strict_json_parse(case.payload))
    expected = cast(dict[str, JsonValue], fixture["expected"])
    branch = cast(
        dict[str, JsonValue],
        expected["all_categories_approved" if summaries else "summary_category_denied"],
    )
    rows = cast(list[dict[str, JsonValue]], payload["items"])
    assert [row["item_id"] for row in rows] == branch["retained_item_ids"]
    assert [category.value for category in case.blocked_categories] == branch["blocked_categories"]


@pytest.mark.anyio
@pytest.mark.parametrize(
    "mutation", ["format", "policy", "gap", "extra", "rule_summary", "rule_count"]
)
async def test_invalid_frozen_advice_packet_never_dispatches(mutation: str) -> None:
    raw = cast(dict[str, JsonValue], strict_json_parse(_candidate().items[1].plaintext))
    raw["finding_summaries"] = ["A retained finding summary"]
    if mutation in {"format", "policy"}:
        raw[mutation] = "unrecognized"
    elif mutation == "gap":
        raw["coverage_gaps"] = ["injected prose instead of a gap"]
    elif mutation == "extra":
        raw["repository_excerpt"] = "unapproved source prose"
    else:
        rule = cast(list[dict[str, JsonValue]], raw["deterministic_rules"])[0]
        rule["summary" if mutation == "rule_summary" else "evidence_ref_count"] = (
            "unapproved source prose" if mutation == "rule_summary" else -1
        )
    result, audit, provider = await _evaluate(_candidate(canonical_encode(raw)))
    assert isinstance(result, SemanticEgressBlocked)
    assert result.reason is PrivacyReason.INSUFFICIENT_APPROVED_CONTEXT
    assert provider.cases == []
    assert audit.receipts[0].blocked_categories == ()


@pytest.mark.anyio
async def test_forbidden_summary_denies_only_its_actual_category() -> None:
    candidate = _candidate()
    candidate = replace(
        candidate,
        items=tuple(
            replace(item, plaintext=b"AWS_ACCESS_KEY_ID=" + _AWS_KEY)
            if item.category is DataCategory.FINDING_SUMMARY
            else item
            for item in candidate.items
        ),
    )
    result, audit, provider = await _evaluate(candidate)
    assert isinstance(result, SemanticEgressBlocked)
    assert result.reason is PrivacyReason.NEVER_SEND_DETECTED
    assert provider.cases == []
    assert audit.receipts[0].blocked_categories == (DataCategory.FINDING_SUMMARY,)


@pytest.mark.anyio
async def test_structural_profile_advice_carries_no_finding_prose() -> None:
    """The owner's review-context profile shapes the advice packet like an explicit check."""

    candidate = _candidate(profile=ReviewContextProfile.STRUCTURAL, include_finding_prose=False)
    assert all(item.category is not DataCategory.FINDING_SUMMARY for item in candidate.items)
    result, _audit, provider = await _evaluate(candidate, profile=ReviewContextProfile.STRUCTURAL)
    assert isinstance(result, SemanticEgressSuccess)
    (case,) = provider.cases
    payload = strict_json_parse(case.payload)
    assert isinstance(payload, dict)
    assert payload["review_context_profile"] == "structural"
    assert b"A retained finding summary" not in case.payload
    assert b"failed_command_unresolved" in case.payload


def test_preview_requirement_covers_confirm_every_request_and_channel_preview() -> None:
    external = minimal_external_policy()
    assert not semantic_preview_required(external)
    assert semantic_preview_required(with_llm(external, preview_required=True))
    # Metadata-only is ``confirm_every_request``, which the policy itself binds to preview.
    assert semantic_preview_required(
        replace(
            with_llm(external, preview_required=True),
            profile=PrivacyProfile.CONFIRM_EVERY_REQUEST,
        )
    )


@pytest.mark.anyio
async def test_preview_required_advice_never_creates_a_proposal() -> None:
    """Background advice has no human to preview it: refuse before any proposal (#1019)."""

    result, audit, provider = await _evaluate(_candidate(), preview_required=True)
    assert isinstance(result, SemanticEgressBlocked)
    assert result.reason is PrivacyReason.POLICY_DENIED
    assert audit.proposal is None
    assert provider.cases == []
    (receipt,) = audit.receipts
    # Nothing was classified for sending, so the receipt asserts no approval at all.
    assert receipt.approved_categories == ()
    assert receipt.counts.approved_items == 0
    assert receipt.counts.included_items == 0


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("built", "effective"),
    [
        (ReviewContextProfile.ASSISTED, ReviewContextProfile.STRUCTURAL),
        (ReviewContextProfile.STRUCTURAL, ReviewContextProfile.ASSISTED),
    ],
)
async def test_advice_built_for_another_profile_is_fenced_before_classification(
    built: ReviewContextProfile, effective: ReviewContextProfile
) -> None:
    """#1019 r3: a stale review-context selection never reaches the provider."""

    candidate = _candidate(
        profile=built, include_finding_prose=built is not ReviewContextProfile.STRUCTURAL
    )
    result, audit, provider = await _evaluate(candidate, profile=effective)
    assert isinstance(result, SemanticEgressBlocked)
    assert result.reason is PrivacyReason.SCOPE_MISMATCH
    assert audit.proposal is None
    assert provider.cases == []
    (receipt,) = audit.receipts
    assert receipt.approved_categories == ()


@pytest.mark.parametrize(
    ("reason", "outcome", "expected"),
    [
        (PrivacyReason.POLICY_DENIED, PrivacyOutcome.BLOCKED_BY_POLICY, "unavailable"),
        (PrivacyReason.SCOPE_MISMATCH, PrivacyOutcome.BLOCKED_BY_POLICY, "unavailable"),
        (PrivacyReason.CATEGORY_NOT_ALLOWED, PrivacyOutcome.BLOCKED_BY_POLICY, "failed"),
        (PrivacyReason.OUTCOME_UNKNOWN, PrivacyOutcome.TRANSPORT_FAILED, "failed"),
    ],
)
def test_blocked_advice_outcome_follows_typed_provenance(
    reason: PrivacyReason, outcome: PrivacyOutcome, expected: str
) -> None:
    from yoetz.service.ready_composition import advice_outcome_for_blocked

    mapped = advice_outcome_for_blocked(
        SemanticEgressBlocked(_REQUEST, outcome, reason, privacy_proposal_id="ppr_x"),
        "fireworks",
    )
    assert mapped.status == expected
    assert mapped.attempt_receipt == "ppr_x"
    # Only a request that may have left the machine names the provider.
    assert (mapped.provider_identity == "fireworks") is (reason is PrivacyReason.OUTCOME_UNKNOWN)
    if expected == "unavailable":
        assert mapped.failure_reason == "authorization_missing"
