"""Issue #582: the fallback binding is admitted by exact membership, primary and fallback alike.

Egress admits a candidate only when its external binding is one of the row's authorized
destinations; the gateway builds each authorized destination's factory on its own, so a missing
fallback factory is reported for that binding only and never fences the primary.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from builders.privacy_policies import minimal_external_policy
from builders.privacy_widenings import llm_channel, other_provider, with_llm
from finishup.adapters.privacy.gateway import (
    PolicyEnforcingOutboundGateway,
    _binding_digest,  # pyright: ignore[reportPrivateUsage]
)
from finishup.adapters.privacy.local_enforcer import LocalPrivacyEnforcer
from finishup.adapters.providers.local_model import InstalledLocalModelProfileRegistry
from finishup.application.egress import SemanticEgressBlocked
from finishup.domain.privacy import (
    EgressChannel,
    PrivacyOutcome,
    PrivacyPolicy,
    PrivacyReason,
    ProviderBinding,
)
from finishup.ports.privacy import EffectivePrivacyPolicy
from integration.privacy.test_egress_gateway import (
    _AuditKey,  # pyright: ignore[reportPrivateUsage]
    _Clock,  # pyright: ignore[reportPrivateUsage]
    _CredentialMinter,  # pyright: ignore[reportPrivateUsage]
    _FullPrivacyAudit,  # pyright: ignore[reportPrivateUsage]
    _human_authority,  # pyright: ignore[reportPrivateUsage]
    _Ids,  # pyright: ignore[reportPrivateUsage]
    _policy,  # pyright: ignore[reportPrivateUsage]
    _provider_binding,  # pyright: ignore[reportPrivateUsage]
    _reconcile_repository,  # pyright: ignore[reportPrivateUsage]
)
from unit.application.test_channel_ceilings_enforced import (
    _candidate,  # pyright: ignore[reportPrivateUsage]
    _coordinator,  # pyright: ignore[reportPrivateUsage]
    _deadline,  # pyright: ignore[reportPrivateUsage]
)


def _third() -> ProviderBinding:
    return ProviderBinding("anthropic", "claude-sonnet-4-6", "anthropic-chat", "1.0.0", "external")


def _paired_policy() -> PrivacyPolicy:
    return with_llm(minimal_external_policy(), fallback_provider_binding=other_provider())


@pytest.mark.anyio
async def test_the_fallback_binding_is_admitted_under_a_paired_row() -> None:
    coordinator, audit = _coordinator(_paired_policy(), byte_count=16, token_count=1)
    result = await coordinator.evaluate_semantic(_candidate(binding=other_provider()), _deadline())
    assert audit.prepared, f"the fallback destination must reach prepare; got {result!r}"
    assert audit.prepared[0].max_bytes == 16


@pytest.mark.anyio
async def test_the_primary_is_still_admitted_under_a_paired_row() -> None:
    coordinator, audit = _coordinator(_paired_policy(), byte_count=16, token_count=1)
    primary = llm_channel(_paired_policy()).provider_binding
    assert primary is not None
    await coordinator.evaluate_semantic(_candidate(binding=primary), _deadline())
    assert audit.prepared


@pytest.mark.anyio
async def test_a_third_destination_is_blocked_by_exact_membership() -> None:
    coordinator, audit = _coordinator(_paired_policy(), byte_count=16, token_count=1)
    result = await coordinator.evaluate_semantic(_candidate(binding=_third()), _deadline())
    assert isinstance(result, SemanticEgressBlocked)
    assert result.outcome is PrivacyOutcome.BLOCKED_BY_POLICY
    assert result.reason is PrivacyReason.DESTINATION_NOT_ALLOWED
    assert audit.prepared == []


@pytest.mark.anyio
async def test_the_would_be_fallback_is_blocked_when_the_row_names_only_the_primary() -> None:
    # Same provider id as a later fallback is not enough: only the approved binding counts.
    coordinator, audit = _coordinator(minimal_external_policy(), byte_count=16, token_count=1)
    result = await coordinator.evaluate_semantic(_candidate(binding=other_provider()), _deadline())
    assert isinstance(result, SemanticEgressBlocked)
    assert result.reason is PrivacyReason.DESTINATION_NOT_ALLOWED
    assert audit.prepared == []


def _gateway(
    builders: dict[ProviderBinding, object], audit: _FullPrivacyAudit, clock: _Clock
) -> PolicyEnforcingOutboundGateway:
    return PolicyEnforcingOutboundGateway(
        external_factory_builders=builders,  # type: ignore[arg-type]
        local_model_registry=InstalledLocalModelProfileRegistry(),
        local_model_resolver=None,
        credential_minter=_CredentialMinter(),  # type: ignore[arg-type]
        audit=audit,  # type: ignore[arg-type]
        classifier=LocalPrivacyEnforcer(),
        audit_mac=_AuditKey(),  # type: ignore[arg-type]
        clock=clock,  # type: ignore[arg-type]
        ids=_Ids(),  # type: ignore[arg-type]
        repository_authority_validator=_repository_authority_current,  # type: ignore[arg-type]
    )


async def _repository_authority_current(_scope: object, _authority_digest: str) -> bool:
    return True


def _paired_effective() -> EffectivePrivacyPolicy:
    policy = _policy(external_enabled=True, local_enabled=False, binding=_provider_binding())
    channels = tuple(
        replace(channel, fallback_provider_binding=other_provider())
        if channel.channel is EgressChannel.LLM_INFERENCE
        else channel
        for channel in policy.channel_policies
    )
    paired = replace(policy, channel_policies=channels)
    return EffectivePrivacyPolicy(paired, 1, paired.policy_digest)


@pytest.mark.anyio
async def test_gateway_activates_both_authorized_bindings_from_their_own_factories() -> None:
    built: list[str] = []
    builders: dict[ProviderBinding, object] = {
        _provider_binding(): lambda: built.append("primary") or object(),
        other_provider(): lambda: built.append("fallback") or object(),
    }
    gateway = _gateway(builders, _FullPrivacyAudit(), _Clock())
    try:
        reconciliation = await _reconcile_repository(
            gateway, _paired_effective(), _human_authority(available=True)
        )
    finally:
        await gateway.close()

    assert reconciliation.unavailable_bindings == ()
    assert reconciliation.activated_count == 2
    assert sorted(built) == ["fallback", "primary"]


@pytest.mark.anyio
async def test_a_missing_fallback_factory_is_unavailable_for_that_binding_only() -> None:
    builders: dict[ProviderBinding, object] = {_provider_binding(): lambda: object()}
    gateway = _gateway(builders, _FullPrivacyAudit(), _Clock())
    try:
        reconciliation = await _reconcile_repository(
            gateway, _paired_effective(), _human_authority(available=True)
        )
    finally:
        await gateway.close()

    assert reconciliation.activated_count == 1
    assert reconciliation.unavailable_bindings == (
        (_binding_digest(other_provider()), "factory_unavailable"),
    )


@pytest.mark.anyio
async def test_a_failing_fallback_factory_does_not_fence_the_primary() -> None:
    def explode() -> object:
        raise RuntimeError("fallback_factory_broken")

    builders: dict[ProviderBinding, object] = {
        _provider_binding(): lambda: object(),
        other_provider(): explode,
    }
    gateway = _gateway(builders, _FullPrivacyAudit(), _Clock())
    try:
        reconciliation = await _reconcile_repository(
            gateway, _paired_effective(), _human_authority(available=True)
        )
    finally:
        await gateway.close()

    assert reconciliation.activated_count == 1
    assert reconciliation.unavailable_bindings == (
        (_binding_digest(other_provider()), "factory_construction_failed"),
    )


@pytest.mark.anyio
async def test_a_single_endpoint_row_never_builds_the_extra_factory() -> None:
    built: list[str] = []
    builders: dict[ProviderBinding, object] = {
        _provider_binding(): lambda: built.append("primary") or object(),
        other_provider(): lambda: built.append("fallback") or object(),
    }
    gateway = _gateway(builders, _FullPrivacyAudit(), _Clock())
    policy = _policy(external_enabled=True, local_enabled=False, binding=_provider_binding())
    try:
        reconciliation = await _reconcile_repository(
            gateway,
            EffectivePrivacyPolicy(policy, 1, policy.policy_digest),
            _human_authority(available=True),
        )
    finally:
        await gateway.close()

    assert reconciliation.activated_count == 1
    assert reconciliation.unavailable_bindings == ()
    assert built == ["primary"]
