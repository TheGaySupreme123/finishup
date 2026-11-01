from __future__ import annotations

import inspect
import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from finishup.domain.privacy import (
    NEVER_SEND_KINDS,
    AuthorizationScope,
    AuthorizationScopeKind,
    ChannelPolicy,
    DataClass,
    EgressChannel,
    ForbiddenDataKind,
    PrivacyOutcome,
    PrivacyPolicy,
    PrivacyProfile,
    PrivacyReason,
    ProviderBinding,
    ReviewContextProfile,
    ReviewSelectionPolicy,
    outcome_reason_is_valid,
)
from finishup.ports.privacy import OutboundGatewayPort, PolicyTransitionProposal
from finishup.protocol.models import DataCategory

_HERE = Path(__file__).resolve()
_ROOT = _HERE.parents[3]
_DIGEST = "sha256:" + "1" * 64
_POLICY_ID = "pvy_88888888-8888-4888-8888-888888888888"
_INSTALLATION_ID = "ins_08000000-0000-4000-8000-000000000001"
_NOW = datetime(2026, 3, 8, tzinfo=UTC)


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


def _local_only_policy(*, enabled_channel: EgressChannel | None = None) -> PrivacyPolicy:
    policies = {channel: _disabled(channel) for channel in EgressChannel}
    if enabled_channel is not None:
        policies[enabled_channel] = ChannelPolicy(
            channel=enabled_channel,
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
        version=3,
        policy_digest=_DIGEST,
        profile=PrivacyProfile.LOCAL_ONLY,
        review_context_profile=ReviewContextProfile.STRUCTURAL,
        review_selection=ReviewSelectionPolicy.for_profile(ReviewContextProfile.STRUCTURAL),
        require_current_provider_data_use_evidence=False,
        network_egress_permitted=enabled_channel is not None,
        effective_scope=AuthorizationScope(AuthorizationScopeKind.MACHINE, _INSTALLATION_ID),
        channel_policies=tuple(
            policies[channel] for channel in sorted(EgressChannel, key=lambda item: item.value)
        ),
        local_model_enabled=False,
        local_model_binding=None,
        local_model_categories=(),
        local_model_data_classes=(),
        agent_context_categories=(
            DataCategory.BOUNDED_STRUCTURAL_METADATA,
            DataCategory.DECLARED_FILE_TYPE,
        ),
        agent_context_data_classes=(DataClass.PUBLIC_STRUCTURAL,),
        trusted_human_control_categories=tuple(DataCategory),
        trusted_human_control_data_classes=(
            DataClass.ORDINARY_USER_CONTENT,
            DataClass.PUBLIC_STRUCTURAL,
            DataClass.SENSITIVE_CONFIDENTIAL,
        ),
        created_at=_NOW,
    )


def _policy_with_llm_categories(categories: tuple[DataCategory, ...]) -> PrivacyPolicy:
    """An assisted-review policy whose inference channel permits exactly *categories*."""

    policies = {channel: _disabled(channel) for channel in EgressChannel}
    policies[EgressChannel.LLM_INFERENCE] = ChannelPolicy(
        channel=EgressChannel.LLM_INFERENCE,
        enabled=True,
        allowed_categories=categories,
        allowed_data_classes=(DataClass.ORDINARY_USER_CONTENT, DataClass.PUBLIC_STRUCTURAL),
        provider_binding=ProviderBinding(
            "fireworks", "test-model", "chat-completions", "1", "external"
        ),
        allowed_purposes=("semantic-review",),
        scope_ceiling=AuthorizationScopeKind.TASK,
        preview_required=False,
        max_bytes=262_144,
        max_tokens=4096,
        authorization_ttl_seconds=300,
    )
    return replace(
        _local_only_policy(),
        profile=PrivacyProfile.MINIMAL_EXTERNAL,
        review_context_profile=ReviewContextProfile.ASSISTED,
        review_selection=ReviewSelectionPolicy.for_profile(ReviewContextProfile.ASSISTED),
        network_egress_permitted=True,
        channel_policies=tuple(
            policies[channel] for channel in sorted(EgressChannel, key=lambda item: item.value)
        ),
    )


def test_closed_privacy_vocabularies_and_never_send_set() -> None:
    assert NEVER_SEND_KINDS == frozenset(ForbiddenDataKind)
    assert {profile.value for profile in PrivacyProfile} == {
        "local_only",
        "confirm_every_request",
        "minimal_external",
        "trusted_provider",
    }
    assert {channel.value for channel in EgressChannel} == {
        "llm_inference",
        "product_telemetry",
        "crash_diagnostics",
        "update_checks",
        "capability_testing",
    }


def test_outbound_gateway_contract_includes_terminal_async_close() -> None:
    assert "close" in OutboundGatewayPort.__dict__
    assert inspect.iscoroutinefunction(OutboundGatewayPort.close)


def test_named_review_selectors_are_exact_and_orthogonal() -> None:
    structural = ReviewSelectionPolicy.for_profile(ReviewContextProfile.STRUCTURAL)
    assisted = ReviewSelectionPolicy.for_profile(ReviewContextProfile.ASSISTED)
    expanded = ReviewSelectionPolicy.for_profile(ReviewContextProfile.EXPANDED)

    assert structural.excerpt_kinds == ()
    assert not structural.include_finding_prose
    assert assisted.include_finding_prose and not assisted.include_exact_command_text
    assert expanded.include_exact_command_text
    assert structural.meet(expanded) == structural


def test_scope_preserves_and_checks_the_complete_ancestor_chain() -> None:
    workspace = AuthorizationScope(
        AuthorizationScopeKind.WORKSPACE,
        _INSTALLATION_ID,
        "hmac-sha256:" + "2" * 64,
    )
    task = AuthorizationScope(
        AuthorizationScopeKind.TASK,
        _INSTALLATION_ID,
        "hmac-sha256:" + "2" * 64,
        "tsk_08000000-0000-4000-8000-000000000002",
    )
    assert workspace.contains(task)
    with pytest.raises(ValueError, match="invalid_privacy_value"):
        AuthorizationScope(
            AuthorizationScopeKind.MACHINE, _INSTALLATION_ID, "hmac-sha256:" + "2" * 64
        )


def test_terminal_outcome_reason_matrix_is_closed() -> None:
    assert outcome_reason_is_valid(PrivacyOutcome.COMPLETED, None)
    assert not outcome_reason_is_valid(PrivacyOutcome.COMPLETED, PrivacyReason.STALE)
    assert outcome_reason_is_valid(
        PrivacyOutcome.CHANNEL_UNAVAILABLE, PrivacyReason.CHANNEL_UNAVAILABLE
    )
    assert not outcome_reason_is_valid(
        PrivacyOutcome.CHANNEL_UNAVAILABLE, PrivacyReason.TRANSPORT_FAILED
    )


def test_p0_4_non_llm_enablement_is_rejected_before_pending_consent() -> None:
    forced_policy = _local_only_policy(enabled_channel=EgressChannel.CAPABILITY_TESTING)
    fixture = json.loads(
        (_ROOT / "fixtures/privacy/PRIV-008-independent-channels.case.json").read_text()
    )
    expected = fixture["expected"]["unsupported_channels"]["capability_testing"]

    assert forced_policy.unsupported_enabled_channels == (EgressChannel.CAPABILITY_TESTING,)
    assert expected["outcome"] == "channel_unavailable"
    assert expected["policy_transition_committed"] is False
    assert expected["network_attempts"] == 0
    with pytest.raises(ValueError, match="channel_unavailable"):
        PolicyTransitionProposal(
            scope=forced_policy.effective_scope,
            expected_generation=2,
            proposed_policy=forced_policy,
            proposal_digest="sha256:" + "3" * 64,
            created_at=_NOW,
            expires_at=datetime(2026, 3, 8, 0, 1, tzinfo=UTC),
        )


def test_review_recipes_recommend_a_reviewable_context_without_loosening_first_run() -> None:
    """The recommended recipe must actually enable review; config.toml seed stays fail-safe.

    Both halves matter together. A structural recipe sends no goal, obligations, claims,
    decisions or finding prose, so a reviewer given one cannot judge whether a claim is supported
    — recommending it makes AI-powered review ceremonial. Config.toml generation-1 bootstrap remains
    all-denied (fail-safe file seed). Durable product default separately enables structural
    package update checks only — never LLM task content — until the user commits a recipe.
    """

    recipes = ReviewSelectionPolicy.for_profile(ReviewContextProfile.ASSISTED)
    # The recommended recipe carries the material a reviewer needs.
    assert recipes.include_finding_prose is True
    assert {"goal", "obligations", "claims", "decisions"} <= set(recipes.sections)
    assert recipes.max_excerpts > 0

    # The structural recipes remain available and remain metadata-only.
    structural = ReviewSelectionPolicy.for_profile(ReviewContextProfile.STRUCTURAL)
    assert structural.include_finding_prose is False
    assert structural.max_excerpts == 0

    # Config.toml generation-1 bootstrap is fail-safe all-denied (not durable policy).
    # finishup.config.privacy and finishup.config.models import each other, so the package must be
    # entered through models for the cycle to resolve in the order the runtime uses.
    from finishup.config.models import ConfigError  # noqa: F401  # enters the package first
    from finishup.config.privacy import safe_privacy_bootstrap

    assert ConfigError is not None

    seed = safe_privacy_bootstrap()
    assert seed.profile == "local_only"
    assert seed.network_egress_permitted is False
    assert seed.local_model_enabled is False
    assert seed.review_context_profile == "structural"
    assert all(value is False for value in seed.channel_policies.model_dump().values())


def test_review_selection_names_the_categories_its_sections_need() -> None:
    """Selection must be able to state what it requires, so a channel can be compared against it."""

    assisted = ReviewSelectionPolicy.for_profile(ReviewContextProfile.ASSISTED)
    required = {item.value for item in assisted.required_categories()}
    # 'assisted' selects goal, obligations, claims, decisions and finding prose.
    assert {"task_description", "obligation_text", "claim_text", "decision_excerpt"} <= required
    assert "finding_summary" in required

    structural = ReviewSelectionPolicy.for_profile(ReviewContextProfile.STRUCTURAL)
    structural_required = {item.value for item in structural.required_categories()}
    # Structural sends no prose, so it must not claim to need any.
    assert "obligation_text" not in structural_required
    assert "finding_summary" not in structural_required
    assert "bounded_structural_metadata" in structural_required


def test_selecting_diff_excerpts_requires_repository_excerpts_for_the_check_time_change() -> None:
    """The check-time change is the service's repository read (ADR-031, #883)."""

    for profile in ReviewContextProfile:
        if profile is ReviewContextProfile.CUSTOM:
            continue
        selection = ReviewSelectionPolicy.for_profile(profile)
        required = selection.required_categories()
        assert (DataCategory.REPOSITORY_EXCERPT in required) is (
            selection.carries_check_time_change
        )
    expanded = ReviewSelectionPolicy.for_profile(ReviewContextProfile.EXPANDED)
    assert expanded.carries_check_time_change
    without_diff = replace(
        expanded, excerpt_kinds=tuple(kind for kind in expanded.excerpt_kinds if kind != "diff")
    )
    assert not without_diff.carries_check_time_change
    assert DataCategory.REPOSITORY_EXCERPT not in without_diff.required_categories()


def test_withheld_review_categories_reports_a_self_defeating_configuration() -> None:
    """A review profile selecting sections the channel forbids must be nameable, not silent.

    This is the configuration a live installation was actually running: profile ``assisted``,
    while the inference channel permitted neither ``obligation_text`` nor ``finding_summary``. The
    reviewer was asked whether the work satisfied its obligations, with the obligations withheld,
    and unsurprisingly produced no findings at all — while still reporting ``succeeded``.
    """

    narrow = _policy_with_llm_categories(
        (
            DataCategory.BOUNDED_STRUCTURAL_METADATA,
            DataCategory.CLAIM_TEXT,
            DataCategory.EVIDENCE_EXCERPT,
            DataCategory.TASK_DESCRIPTION,
        )
    )
    withheld = {item.value for item in narrow.withheld_review_categories}
    assert "obligation_text" in withheld
    assert "finding_summary" in withheld

    wide = _policy_with_llm_categories(
        tuple(
            ReviewSelectionPolicy.for_profile(ReviewContextProfile.ASSISTED).required_categories()
        )
    )
    assert wide.withheld_review_categories == ()

    # A disabled inference channel discloses nothing, so nothing can be withheld from a review
    # that never happens; reporting a gap there would be noise, not honesty.
    assert _local_only_policy().withheld_review_categories == ()
