"""RT-privacy-egress-1: channel max_bytes/max_tokens/scope_ceiling fence AI-powered review admission."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import cast

import pytest

from builders.privacy_policies import INSTALLATION_ID, local_only_policy, minimal_external_policy
from builders.privacy_widenings import llm_channel, with_llm
from finishup.application.egress import PrivacyCoordinator, SemanticEgressBlocked
from finishup.domain.privacy import (
    AuthorizationScope,
    AuthorizationScopeKind,
    CandidateContext,
    CandidateContextItem,
    ClassifiedContext,
    ClassifiedContextItem,
    DataClass,
    EgressChannel,
    PrivacyDecision,
    PrivacyOutcome,
    PrivacyPolicy,
    PrivacyPolicyPresetVersion,
    PrivacyReason,
    ProviderBinding,
    ReviewContextProfile,
    ReviewSelectionPolicy,
)
from finishup.ports.clock import ClockPort
from finishup.ports.ids import IdPort
from finishup.ports.privacy import (
    DisclosureProposalRequest,
    EffectivePrivacyPolicy,
    HumanAuthorityCapability,
    MinimizedDisclosure,
    OutboundGatewayPort,
    PrivacyAuditPort,
    PrivacyAuditReservation,
    PrivacyClassifierPort,
    PrivacyPolicyStorePort,
)
from finishup.ports.semantic import Deadline
from finishup.protocol.canonical import JsonValue
from finishup.protocol.ids import IdKind
from finishup.protocol.models import DataCategory

_NOW = datetime(2026, 8, 3, tzinfo=UTC)
_REQUEST = "req_30000000-0000-4000-8000-000000000101"
_TASK = "tsk_30000000-0000-4000-8000-000000000102"
_SUBJECT = "sha256:" + "d" * 64
_ITEM_DIGEST = "sha256:" + "e" * 64
_CASE_DIGEST = "sha256:" + "c" * 64
_POLICY_CEILING_BYTES = 1024
_OVERSIZE_BYTES = 2048
_POLICY_CEILING_TOKENS = 10
_OVERSIZE_TOKENS = 512


class _Clock:
    def now_utc(self) -> datetime:
        return _NOW

    def monotonic_seconds(self) -> float:
        return 1.0


class _Ids:
    def __init__(self) -> None:
        self._n = 0

    def new(self, kind: IdKind) -> str:
        self._n += 1
        prefix = {
            IdKind.PRIVACY_PROPOSAL: "ppr",
            IdKind.EGRESS_RECEIPT: "egr",
            IdKind.EGRESS_AUTHORIZATION: "aut",
            IdKind.EGRESS_DISPATCH: "dsp",
        }.get(kind, "ppr")
        return f"{prefix}_30000000-0000-4000-8000-{self._n:012d}"


class _Store:
    def __init__(
        self,
        policy: PrivacyPolicy,
        *,
        grant_state: str = "granted",
        repository_privacy_commitment: str | None = "hmac-sha256:" + "a" * 64,
    ) -> None:
        self._policy = policy
        self._grant_state = grant_state
        self._repository_privacy_commitment = repository_privacy_commitment

    async def effective_policy(self, scope: AuthorizationScope) -> EffectivePrivacyPolicy:
        del scope
        return EffectivePrivacyPolicy(self._policy, 1, self._policy.policy_digest)

    async def repository_authority(self, scope: AuthorizationScope) -> object:
        effective = await self.effective_policy(scope)
        return SimpleNamespace(
            effective=effective,
            grant_state=self._grant_state,
            repository_privacy_commitment=self._repository_privacy_commitment,
            authority_digest="sha256:" + "9" * 64,
        )


class _Classifier:
    def __init__(self, *, byte_count: int, token_count: int, prepared: bytes | None = None) -> None:
        self._byte_count = byte_count if prepared is None else len(prepared)
        self._token_count = token_count
        self._prepared = prepared
        self.classify_calls = 0

    def classify(
        self, candidate: CandidateContext, effective: EffectivePrivacyPolicy
    ) -> ClassifiedContext:
        del effective
        self.classify_calls += 1
        items = tuple(
            ClassifiedContextItem(
                item,
                DataClass.PUBLIC_STRUCTURAL,
                (),
                True,
                "1.0.0",
            )
            for item in candidate.items
        )
        return ClassifiedContext(candidate, items)

    def minimize_and_scan(
        self, classified: ClassifiedContext, decision: PrivacyDecision
    ) -> MinimizedDisclosure:
        del decision
        # A readable prepared document of exactly the requested size with no excerpt rows, so
        # only the channel ceilings under test can refuse it.
        payload = (
            b'{"p":"' + b"x" * (self._byte_count - 8) + b'"}'
            if self._prepared is None
            else self._prepared
        )
        return MinimizedDisclosure(
            prepared_bytes=payload,
            included_item_ids=tuple(item.candidate.item_id for item in classified.items),
            source_item_digests=(_ITEM_DIGEST,),
            approved_categories=(DataCategory.BOUNDED_STRUCTURAL_METADATA,),
            blocked_categories=(),
            transformation_summary=(),
            byte_count=self._byte_count,
            token_count=self._token_count,
            case_digest=_CASE_DIGEST,
            scanner_registry_version="test",
            scanner_profile_digest="sha256:" + "f" * 64,
            forbidden_findings=(),
        )


class _Audit:
    def __init__(self) -> None:
        self.prepared: list[DisclosureProposalRequest] = []

    async def reserve(self, subject: object) -> PrivacyAuditReservation:
        proposal_id = getattr(
            subject, "privacy_proposal_id", "ppr_30000000-0000-4000-8000-000000000001"
        )
        request_id = getattr(subject, "request_id", _REQUEST)
        return PrivacyAuditReservation(
            proposal_id,
            request_id,
            _SUBJECT,
            "reserved",
            1,
            _NOW,
        )

    async def complete_decision(self, *args: object, **kwargs: object) -> None:
        del args, kwargs

    async def prepare_disclosure_proposal(self, request: DisclosureProposalRequest) -> object:
        self.prepared.append(request)
        raise RuntimeError("stop_after_prepare")


class _Gateway:
    def __init__(self) -> None:
        self.reconcile_calls = 0

    async def reconcile_repository_policy(self, *args: object, **kwargs: object) -> object:
        del args, kwargs
        self.reconcile_calls += 1
        return object()

    async def close(self) -> None:
        return None


def _policy_with_ceilings(
    *,
    max_bytes: int = 262_144,
    max_tokens: int = 4096,
    scope_ceiling: AuthorizationScopeKind = AuthorizationScopeKind.TASK,
) -> PrivacyPolicy:
    return with_llm(
        minimal_external_policy(),
        max_bytes=max_bytes,
        max_tokens=max_tokens,
        scope_ceiling=scope_ceiling,
    )


def _candidate(
    *,
    scope_kind: AuthorizationScopeKind = AuthorizationScopeKind.TASK,
    purpose: str = "semantic-review",
    binding: ProviderBinding | None = None,
) -> CandidateContext:
    scope = AuthorizationScope(
        scope_kind,
        INSTALLATION_ID,
        f"hmac-sha256:{'a' * 64}",
        _TASK
        if scope_kind in {AuthorizationScopeKind.TASK, AuthorizationScopeKind.REQUEST}
        else None,
        _REQUEST if scope_kind is AuthorizationScopeKind.REQUEST else None,
    )
    binding = binding or llm_channel(minimal_external_policy()).provider_binding
    assert binding is not None
    return CandidateContext(
        _REQUEST,
        EgressChannel.LLM_INFERENCE,
        None,
        purpose,
        scope,
        _SUBJECT,
        binding,
        (
            CandidateContextItem(
                "item-1",
                DataCategory.BOUNDED_STRUCTURAL_METADATA,
                scope,
                "origin-1",
                b"{}",
            ),
        ),
    )


def _deadline() -> Deadline:
    return Deadline(_NOW + timedelta(minutes=1), _Clock().monotonic_seconds() + 60.0)


def _coordinator(
    policy: PrivacyPolicy, *, byte_count: int, token_count: int
) -> tuple[PrivacyCoordinator, _Audit]:
    audit = _Audit()
    coordinator = PrivacyCoordinator(
        cast(PrivacyPolicyStorePort, _Store(policy)),
        cast(PrivacyClassifierPort, _Classifier(byte_count=byte_count, token_count=token_count)),
        cast(PrivacyAuditPort, audit),
        cast(OutboundGatewayPort, _Gateway()),
        cast(ClockPort, _Clock()),
        cast(IdPort, _Ids()),
        human_authority=_human_authority(),
    )
    return coordinator, audit


def _human_authority() -> HumanAuthorityCapability:
    return HumanAuthorityCapability(
        "established_passphrase",
        "sha256:" + "8" * 64,
        1,
        "passphrase",
        1,
        True,
    )


@pytest.mark.anyio
async def test_missing_repository_grant_blocks_before_classification_or_reconciliation() -> None:
    policy = _policy_with_ceilings()
    store = _Store(policy, grant_state="missing")
    classifier = _Classifier(byte_count=16, token_count=1)
    audit = _Audit()
    gateway = _Gateway()
    coordinator = PrivacyCoordinator(
        cast(PrivacyPolicyStorePort, store),
        cast(PrivacyClassifierPort, classifier),
        cast(PrivacyAuditPort, audit),
        cast(OutboundGatewayPort, gateway),
        cast(ClockPort, _Clock()),
        cast(IdPort, _Ids()),
        human_authority=_human_authority(),
    )

    result = await coordinator.evaluate_semantic(_candidate(), _deadline())
    assert isinstance(result, SemanticEgressBlocked)
    assert result.reason is PrivacyReason.SCOPE_MISMATCH
    assert classifier.classify_calls == 0
    assert gateway.reconcile_calls == 0
    assert audit.prepared == []


@pytest.mark.anyio
async def test_mismatched_repository_grant_blocks_before_classification_or_reconciliation() -> None:
    policy = _policy_with_ceilings()
    store = _Store(
        policy,
        grant_state="granted",
        repository_privacy_commitment="hmac-sha256:" + "b" * 64,
    )
    classifier = _Classifier(byte_count=16, token_count=1)
    audit = _Audit()
    gateway = _Gateway()
    coordinator = PrivacyCoordinator(
        cast(PrivacyPolicyStorePort, store),
        cast(PrivacyClassifierPort, classifier),
        cast(PrivacyAuditPort, audit),
        cast(OutboundGatewayPort, gateway),
        cast(ClockPort, _Clock()),
        cast(IdPort, _Ids()),
        human_authority=_human_authority(),
    )

    result = await coordinator.evaluate_semantic(_candidate(), _deadline())
    assert isinstance(result, SemanticEgressBlocked)
    assert result.reason is PrivacyReason.SCOPE_MISMATCH
    assert classifier.classify_calls == 0
    assert gateway.reconcile_calls == 0
    assert audit.prepared == []


@pytest.mark.anyio
async def test_oversize_bytes_blocks_admission() -> None:
    policy = _policy_with_ceilings(max_bytes=_POLICY_CEILING_BYTES)
    coordinator, audit = _coordinator(policy, byte_count=_OVERSIZE_BYTES, token_count=1)
    result = await coordinator.evaluate_semantic(_candidate(), _deadline())
    assert isinstance(result, SemanticEgressBlocked)
    assert result.outcome is PrivacyOutcome.BLOCKED_BY_POLICY
    assert result.reason is PrivacyReason.POLICY_DENIED
    assert audit.prepared == []


@pytest.mark.anyio
async def test_oversize_tokens_blocks_admission() -> None:
    policy = _policy_with_ceilings(max_tokens=_POLICY_CEILING_TOKENS)
    coordinator, audit = _coordinator(policy, byte_count=16, token_count=_OVERSIZE_TOKENS)
    result = await coordinator.evaluate_semantic(_candidate(), _deadline())
    assert isinstance(result, SemanticEgressBlocked)
    assert result.outcome is PrivacyOutcome.BLOCKED_BY_POLICY
    assert result.reason is PrivacyReason.POLICY_DENIED
    assert audit.prepared == []


@pytest.mark.anyio
async def test_scope_broader_than_ceiling_blocks() -> None:
    """A request-scoped ceiling is the narrowest one; a task-scoped case is broader than it."""

    policy = _policy_with_ceilings(scope_ceiling=AuthorizationScopeKind.REQUEST)
    coordinator, audit = _coordinator(policy, byte_count=16, token_count=1)
    result = await coordinator.evaluate_semantic(
        _candidate(scope_kind=AuthorizationScopeKind.TASK),
        _deadline(),
    )
    assert isinstance(result, SemanticEgressBlocked)
    assert result.reason is PrivacyReason.SCOPE_MISMATCH
    assert audit.prepared == []


@pytest.mark.anyio
async def test_workspace_ceiling_admits_task_scoped_candidate() -> None:
    """The shipped assisted_review / expanded_review shape must keep working.

    Those recipes commit ``scope_ceiling=workspace`` while every AI-powered review case is task-scoped.
    A task scope is narrower than a workspace ceiling, so it sits inside the consented
    authority and must be admitted rather than blocked as a scope mismatch.
    """

    policy = _policy_with_ceilings(scope_ceiling=AuthorizationScopeKind.WORKSPACE)
    coordinator, audit = _coordinator(policy, byte_count=16, token_count=1)
    result = await coordinator.evaluate_semantic(
        _candidate(scope_kind=AuthorizationScopeKind.TASK),
        _deadline(),
    )
    assert audit.prepared, f"task case under a workspace ceiling must reach prepare; got {result!r}"


@pytest.mark.anyio
async def test_within_ceilings_stamps_policy_intersect_case_max() -> None:
    policy = _policy_with_ceilings(max_bytes=4096, max_tokens=100)
    coordinator, audit = _coordinator(policy, byte_count=100, token_count=8)
    result = await coordinator.evaluate_semantic(_candidate(), _deadline())
    assert audit.prepared, f"expected prepare; got {result!r}"
    request = audit.prepared[0]
    assert request.max_bytes == 100
    assert request.max_tokens == 8


@pytest.mark.anyio
async def test_credential_probe_requires_an_explicit_purpose_and_is_capped_at_one_token() -> None:
    denied, denied_audit = _coordinator(minimal_external_policy(), byte_count=100, token_count=8)
    denied_result = await denied.evaluate_semantic(
        _candidate(purpose="credential-probe"),
        _deadline(),
    )
    assert isinstance(denied_result, SemanticEgressBlocked)
    assert denied_result.reason is PrivacyReason.PURPOSE_NOT_ALLOWED
    assert denied_audit.prepared == []

    admitted_policy = with_llm(
        minimal_external_policy(),
        allowed_purposes=("credential-probe", "semantic-review"),
    )
    admitted, admitted_audit = _coordinator(admitted_policy, byte_count=100, token_count=8)
    result = await admitted.evaluate_semantic(
        _candidate(purpose="credential-probe"),
        _deadline(),
    )
    assert admitted_audit.prepared, f"credential probe must reach prepare; got {result!r}"
    assert admitted_audit.prepared[0].max_tokens == 1


@pytest.mark.anyio
async def test_disabled_llm_policy_still_rejects_a_local_model_unknown_purpose() -> None:
    """A local transport does not bypass the policy's purpose fence when LLM egress is off."""

    coordinator, audit = _coordinator(local_only_policy(), byte_count=100, token_count=1)
    result = await coordinator.evaluate_semantic(
        _candidate(
            purpose="credential-probe",
            binding=ProviderBinding(
                "local-model",
                "test-model",
                "local-model-af-unix",
                "1.0.0",
                "local_af_unix",
            ),
        ),
        _deadline(),
    )

    assert isinstance(result, SemanticEgressBlocked)
    assert result.reason is PrivacyReason.PURPOSE_NOT_ALLOWED
    assert audit.prepared == []


@pytest.mark.anyio
async def test_shipped_recipe_ceilings_admit_a_full_size_review_case() -> None:
    """The recipe's two whole-case ceilings must express the same budget.

    max_tokens is compared against a token count the enforcer estimates from the prepared byte
    count, so a token ceiling chosen independently of the byte ceiling becomes the real limit at
    a different size. At 4096 tokens it bound at 16 KiB — sixteen times tighter than the 256 KiB
    byte ceiling, and below the 128 KiB of excerpts the assisted and expanded review selections
    are allowed to gather — so enforcing it refused essentially every real review case.
    """

    from finishup.adapters.privacy.local_enforcer import estimated_token_count
    from finishup.cli.privacy_setup import (
        _CASE_MAX_BYTES,  # pyright: ignore[reportPrivateUsage]
        _CASE_MAX_TOKENS,  # pyright: ignore[reportPrivateUsage]
    )

    # A case at the byte ceiling must not be over the token ceiling.
    assert estimated_token_count(_CASE_MAX_BYTES) <= _CASE_MAX_TOKENS

    # The largest excerpt payload either review selection may gather, admitted end to end.
    selection_bytes = 131_072
    assert selection_bytes <= _CASE_MAX_BYTES
    policy = _policy_with_ceilings(max_bytes=_CASE_MAX_BYTES, max_tokens=_CASE_MAX_TOKENS)
    coordinator, audit = _coordinator(
        policy,
        byte_count=selection_bytes,
        token_count=estimated_token_count(selection_bytes),
    )
    result = await coordinator.evaluate_semantic(_candidate(), _deadline())
    assert audit.prepared, f"a full-size review case must reach prepare; got {result!r}"


def _packet_with_excerpts(count: int, *, content_bytes: int = 64) -> bytes:
    """A prepared review packet whose ``excerpt`` rows are what the egress check counts."""

    from finishup.protocol.canonical import canonical_encode

    rows = [
        {
            "category": "evidence_excerpt",
            "content": "x" * content_bytes,
            "content_bytes": content_bytes,
            "item_id": f"excerpt-{index:03d}",
            "section": "excerpt",
        }
        for index in range(count)
    ]
    return canonical_encode(
        cast(JsonValue, {"items": rows, "omissions": [], "schema": "yoetz.review-packet-case/1"})
    )


def _expanded(preset_version: PrivacyPolicyPresetVersion) -> PrivacyPolicy:
    return replace(
        _policy_with_ceilings(max_bytes=262_144, max_tokens=65_536),
        review_context_profile=ReviewContextProfile.EXPANDED,
        review_selection=ReviewSelectionPolicy.for_profile(
            ReviewContextProfile.EXPANDED, preset_version=preset_version
        ),
    )


async def _evaluate(policy: PrivacyPolicy, prepared: bytes) -> tuple[object, _Audit]:
    audit = _Audit()
    coordinator = PrivacyCoordinator(
        cast(PrivacyPolicyStorePort, _Store(policy)),
        cast(
            PrivacyClassifierPort,
            _Classifier(byte_count=0, token_count=len(prepared) // 4, prepared=prepared),
        ),
        cast(PrivacyAuditPort, audit),
        cast(OutboundGatewayPort, _Gateway()),
        cast(ClockPort, _Clock()),
        cast(IdPort, _Ids()),
        human_authority=_human_authority(),
    )
    return await coordinator.evaluate_semantic(_candidate(), _deadline()), audit


@pytest.mark.anyio
async def test_more_excerpts_than_the_policy_approved_is_policy_denied_never_trimmed() -> None:
    """Issue #907 Phase 1b: the approved excerpt count is authoritative at egress."""

    current = _expanded("1.2.0")
    assert current.review_selection.max_excerpts == 64
    admitted, admitted_audit = await _evaluate(current, _packet_with_excerpts(40))
    assert admitted_audit.prepared, f"40 excerpts fit a 64-excerpt approval; got {admitted!r}"

    over, over_audit = await _evaluate(current, _packet_with_excerpts(65))
    assert isinstance(over, SemanticEgressBlocked)
    assert over.reason is PrivacyReason.POLICY_DENIED
    assert over_audit.prepared == []


@pytest.mark.anyio
async def test_a_1_1_0_approval_denies_more_than_16_excerpts() -> None:
    legacy = _expanded("1.1.0")
    assert legacy.review_selection.max_excerpts == 16
    within, within_audit = await _evaluate(legacy, _packet_with_excerpts(16))
    assert within_audit.prepared, f"16 excerpts fit a 1.1.0 approval; got {within!r}"

    over, over_audit = await _evaluate(legacy, _packet_with_excerpts(17))
    assert isinstance(over, SemanticEgressBlocked)
    assert over.reason is PrivacyReason.POLICY_DENIED
    assert over_audit.prepared == []


@pytest.mark.anyio
async def test_excerpt_bytes_over_the_approved_budget_are_policy_denied() -> None:
    current = _expanded("1.2.0")
    per_excerpt = current.review_selection.max_excerpt_bytes
    # Nine full-size excerpts exceed the 128 KiB total while each fits its own 16 KiB bound.
    over_total, _ = await _evaluate(current, _packet_with_excerpts(9, content_bytes=per_excerpt))
    assert isinstance(over_total, SemanticEgressBlocked)
    assert over_total.reason is PrivacyReason.POLICY_DENIED
    over_one, _ = await _evaluate(current, _packet_with_excerpts(1, content_bytes=per_excerpt + 1))
    assert isinstance(over_one, SemanticEgressBlocked)
    assert over_one.reason is PrivacyReason.POLICY_DENIED
    unreadable, _ = await _evaluate(current, b"not a review packet")
    assert isinstance(unreadable, SemanticEgressBlocked)
    assert unreadable.reason is PrivacyReason.POLICY_DENIED


@pytest.mark.anyio
async def test_a_packet_over_the_channel_ceiling_is_denied_whatever_its_excerpt_count() -> None:
    """Issue #907 acceptance 1: more than 16 excerpts inside the approved excerpt budget, plus a
    large (100 KB) non-excerpt row, still exceed the channel ceiling and are never dispatched.

    The ceiling is narrowed to 200,000 bytes because a prepared disclosure can never exceed
    262,144 bytes by construction, so the shipped ceiling cannot be crossed in a unit fixture.
    """

    from finishup.application.egress import (
        _within_excerpt_limits,  # pyright: ignore[reportPrivateUsage]
    )
    from finishup.protocol.canonical import canonical_encode

    policy = replace(
        _expanded("1.2.0"),
        channel_policies=tuple(
            replace(channel, max_bytes=200_000)
            if channel.channel is EgressChannel.LLM_INFERENCE
            else channel
            for channel in _expanded("1.2.0").channel_policies
        ),
    )
    rows: list[dict[str, JsonValue]] = [
        {
            "content": "x" * 3_000,
            "content_bytes": 3_000,
            "item_id": f"excerpt-{index:03d}",
            "section": "excerpt",
        }
        for index in range(40)
    ]
    rows.append(
        {
            "content": "t" * 100_000,
            "content_bytes": 100_000,
            "item_id": "timeline-1",
            "section": "timeline",
        }
    )
    prepared = canonical_encode(
        cast(JsonValue, {"items": rows, "schema": "yoetz.review-packet-case/1"})
    )
    assert len(prepared) > 200_000
    assert _within_excerpt_limits(prepared, policy.review_selection)

    result, audit = await _evaluate(policy, prepared)

    assert isinstance(result, SemanticEgressBlocked)
    assert result.reason is PrivacyReason.POLICY_DENIED
    assert audit.prepared == []
