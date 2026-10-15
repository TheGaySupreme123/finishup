"""Privacy profile, fake-provider, and local-model runtime capability evidence.

Offline cells prove closed privacy/review-context vocabularies, v0.1 non-LLM channel
unavailability, empty local-model registry fail-closed behavior, ProviderDataUseProfile
eligibility binding, and scripted fake-provider AI-powered review success without network.
"""

from __future__ import annotations

import socket
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest
from tests.capability.evidence import (
    CapabilityCase,
    EvidenceOutcome,
    Observation,
    bytes_digest,
    record_and_write,
    runtime_capability_context,
)

from finishup.adapters.providers.fake import (
    FakeSemanticScript,
    ScriptedFakeSemanticEvaluator,
    scripted_success,
)
from finishup.adapters.providers.local_model import InstalledLocalModelProfileRegistry
from finishup.domain.privacy import (
    ApprovedOutboundCase,
    AuthorizationScope,
    AuthorizationScopeKind,
    ChannelPolicy,
    DataCategory,
    DataClass,
    EgressChannel,
    PrivacyPolicy,
    PrivacyProfile,
    ProviderBinding,
    ProviderDataUseProfile,
    ReviewContextProfile,
    ReviewSelectionPolicy,
)
from finishup.ports.privacy import PolicyTransitionProposal
from finishup.ports.semantic import Deadline, SemanticJudgment, SemanticResultSuccess
from finishup.protocol.canonical import JsonValue, canonical_digest, canonical_encode

_TEST_REVISION = bytes_digest(Path(__file__).read_bytes())
_DIGEST = "sha256:" + "c" * 64
_POLICY_ID = "pvy_70000000-0000-4000-8000-000000000001"
_INSTALLATION_ID = "ins_70000000-0000-4000-8000-000000000002"
_NOW = datetime(2026, 7, 20, tzinfo=UTC)

_CASE_PRIVACY = CapabilityCase(
    case_id="PRIV-001",
    requirement_id="ADR-009.privacy-profiles",
    claim_id="E-009.privacy-local-model",
    capability_family="privacy_provider_local",
    required_observation_codes=frozenset(
        {
            "privacy_profiles_complete",
            "review_contexts_complete",
            "non_llm_channels_unavailable",
            "empty_local_registry_unavailable",
        }
    ),
    allowed_observation_codes=frozenset(
        {
            "privacy_profiles_complete",
            "review_contexts_complete",
            "non_llm_channels_unavailable",
            "empty_local_registry_unavailable",
            "data_use_eligibility_bound",
            "fake_provider_offline_success",
            "adapter_process_no_inet",
        }
    ),
)


def _disabled(channel: EgressChannel) -> ChannelPolicy:
    return ChannelPolicy(
        channel=channel,
        enabled=False,
        allowed_categories=(),
        allowed_data_classes=(),
        provider_binding=None,
        allowed_purposes=(),
        scope_ceiling=AuthorizationScopeKind.MACHINE,
        preview_required=False,
        max_bytes=0,
        max_tokens=0,
        authorization_ttl_seconds=0,
    )


def _policy_forcing(channel: EgressChannel) -> PrivacyPolicy:
    policies = {item: _disabled(item) for item in EgressChannel}
    policies[channel] = ChannelPolicy(
        channel=channel,
        enabled=True,
        allowed_categories=(DataCategory.BOUNDED_STRUCTURAL_METADATA,),
        allowed_data_classes=(DataClass.PUBLIC_STRUCTURAL,),
        provider_binding=None,
        allowed_purposes=("capability-testing-probe",),
        scope_ceiling=AuthorizationScopeKind.MACHINE,
        preview_required=False,
        max_bytes=4096,
        max_tokens=1024,
        authorization_ttl_seconds=60,
    )
    return PrivacyPolicy(
        policy_id=_POLICY_ID,
        version=1,
        policy_digest=_DIGEST,
        profile=PrivacyProfile.LOCAL_ONLY,
        review_context_profile=ReviewContextProfile.STRUCTURAL,
        review_selection=ReviewSelectionPolicy.for_profile(ReviewContextProfile.STRUCTURAL),
        require_current_provider_data_use_evidence=False,
        network_egress_permitted=True,
        effective_scope=AuthorizationScope(AuthorizationScopeKind.MACHINE, _INSTALLATION_ID),
        channel_policies=tuple(
            policies[item] for item in sorted(EgressChannel, key=lambda value: value.value)
        ),
        local_model_enabled=False,
        local_model_binding=None,
        local_model_categories=(),
        local_model_data_classes=(),
        agent_context_categories=(),
        agent_context_data_classes=(),
        trusted_human_control_categories=(),
        trusted_human_control_data_classes=(),
        created_at=_NOW,
    )


def _approved_case() -> ApprovedOutboundCase:
    payload = canonical_encode(
        cast(JsonValue, {"goal": "capability-synthetic", "obligations": [], "claims": []})
    )
    return ApprovedOutboundCase(
        case_id="cas_70000000-0000-4000-8000-000000000001",
        request_id="req_70000000-0000-4000-8000-000000000001",
        payload=payload,
        media_type="application/json",
        schema_id="yoetz-semantic-case-1.0.0",
        included_item_ids=("goal-1",),
        approved_categories=(DataCategory.TASK_DESCRIPTION,),
        blocked_categories=(),
        byte_count=len(payload),
        token_count=16,
        provider_binding=ProviderBinding(
            provider_id="openai",
            model_id="gpt-5-fake",
            endpoint_profile_id="openai-responses",
            endpoint_profile_version="1.0.0",
            transport="external",
        ),
        purpose="semantic-review",
        authorization_id="aut_70000000-0000-4000-8000-000000000001",
        policy_digest=_DIGEST,
        case_digest="sha256:" + "d" * 64,
    )


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_privacy_profiles_channels_and_local_model_offline_cells(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir(mode=0o700)

    assert {profile.value for profile in PrivacyProfile} == {
        "local_only",
        "confirm_every_request",
        "minimal_external",
        "trusted_provider",
    }
    assert {profile.value for profile in ReviewContextProfile} == {
        "structural",
        "goal_aware",
        "assisted",
        "expanded",
        "custom",
    }

    unsupported_non_llm = (
        EgressChannel.PRODUCT_TELEMETRY,
        EgressChannel.CRASH_DIAGNOSTICS,
        EgressChannel.CAPABILITY_TESTING,
    )
    for channel in unsupported_non_llm:
        forced = _policy_forcing(channel)
        assert forced.unsupported_enabled_channels == (channel,)
        with pytest.raises(ValueError, match="channel_unavailable"):
            PolicyTransitionProposal(
                scope=forced.effective_scope,
                expected_generation=1,
                proposed_policy=forced,
                proposal_digest=_DIGEST,
                created_at=_NOW,
                expires_at=_NOW + timedelta(minutes=1),
            )
    # update_checks ships a production transport; enablement is not channel_unavailable.
    update_forced = _policy_forcing(EgressChannel.UPDATE_CHECKS)
    assert update_forced.unsupported_enabled_channels == ()
    PolicyTransitionProposal(
        scope=update_forced.effective_scope,
        expected_generation=1,
        proposed_policy=update_forced,
        proposal_digest=_DIGEST,
        created_at=_NOW,
        expires_at=_NOW + timedelta(minutes=1),
    )

    empty = InstalledLocalModelProfileRegistry()
    assert empty.resolve("missing", "1.0.0") is None

    eligible = ProviderDataUseProfile(
        data_use_profile_id="openai-data-use",
        data_use_profile_version="1.0.0",
        customer_content_training="prohibited",
        retention="bounded",
        retention_days_ceiling=30,
        provider_human_access="restricted",
        reviewed_at=_NOW - timedelta(days=1),
        expires_at=_NOW + timedelta(days=30),
        evidence_digest=_DIGEST,
    )
    ineligible = ProviderDataUseProfile(
        data_use_profile_id="openai-data-use",
        data_use_profile_version="1.0.1",
        customer_content_training="unknown",
        retention="unknown",
        retention_days_ceiling=None,
        provider_human_access="unknown",
        reviewed_at=_NOW - timedelta(days=1),
        expires_at=_NOW + timedelta(days=30),
        evidence_digest=_DIGEST,
    )
    assert eligible.recommendation_eligible(_NOW)
    assert not ineligible.recommendation_eligible(_NOW)

    opened_families: list[int] = []
    real_socket = socket.socket

    def _guarded_socket(*args: object, **kwargs: object) -> socket.socket:
        family = int(args[0]) if args else int(kwargs.get("family", socket.AF_INET))  # type: ignore[arg-type]
        opened_families.append(family)
        return real_socket(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(socket, "socket", _guarded_socket)
    evaluator = ScriptedFakeSemanticEvaluator(
        FakeSemanticScript((scripted_success(SemanticJudgment("no_material_discrepancy", ())),))
    )
    result = await evaluator.evaluate(
        _approved_case(), Deadline(_NOW + timedelta(minutes=1), 10_000.0)
    )
    assert type(result) is SemanticResultSuccess
    assert socket.AF_INET not in opened_families
    assert socket.AF_INET6 not in opened_families

    context = runtime_capability_context(
        fixture_digest=bytes_digest(b"privacy-local-model-offline"),
        test_revision=_TEST_REVISION,
        config_profile_digest=canonical_digest(
            {
                "cell": "privacy_local",
                "channels": [channel.value for channel in unsupported_non_llm],
            }
        ),
        external_tool="fake_provider",
        external_version="0.1.0",
        integration_channel="privacy_gateway",
        provider_id="fake_provider",
    )
    evidence = record_and_write(
        _CASE_PRIVACY,
        context,
        (
            Observation("adapter_process_no_inet", boolean_value=True),
            Observation("data_use_eligibility_bound", boolean_value=True),
            Observation("empty_local_registry_unavailable", boolean_value=True),
            Observation("fake_provider_offline_success", boolean_value=True),
            Observation("non_llm_channels_unavailable", integer_value=len(unsupported_non_llm)),
            Observation("privacy_profiles_complete", integer_value=len(PrivacyProfile)),
            Observation("review_contexts_complete", integer_value=len(ReviewContextProfile)),
        ),
        EvidenceOutcome.PASS,
        output_root=evidence_root,
    )
    assert evidence.outcome is EvidenceOutcome.PASS
