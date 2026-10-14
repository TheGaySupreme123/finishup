"""Every policy dimension the widening classifier recognizes, as a diffable pair.

Shared by the application-layer diff tests and the trusted-terminal renderer tests so both
enumerate the same list: a dimension added to one and forgotten in the other is exactly how a
widening ends up classified but not displayed.

Each entry is ``(id, current, candidate, identity, screen_label)`` where ``identity`` is the
``(area, field, subject)`` tuple the diff must report and ``screen_label`` is the plain-English
label the trusted terminal must print for it.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Final

from builders.privacy_policies import local_only_policy, machine_scope, minimal_external_policy
from finishup.domain.privacy import (
    AuthorizationScope,
    AuthorizationScopeKind,
    ChannelPolicy,
    DataClass,
    EgressChannel,
    PrivacyPolicy,
    ProviderBinding,
    ReviewContextProfile,
    ReviewSelectionPolicy,
)
from finishup.protocol.models import DataCategory

__all__ = ["WIDENING_CASES", "llm_channel", "with_llm", "with_review"]

# The wording the trusted terminal must print, spelled out here rather than imported from the
# renderer, so a label change has to be made deliberately in two places instead of silently
# agreeing with itself.
_SCREEN_LABELS: Final[dict[tuple[str, str], str]] = {
    ("global", "network_egress"): "Data leaving this computer",
    ("global", "effective_scope"): "Policy applies to",
    ("global", "provider_data_use_evidence"): "Current provider data-use evidence",
    ("channel", "enabled"): "External model review",
    ("channel", "provider"): "Provider and model",
    ("channel", "purposes"): "Purposes",
    ("channel", "categories"): "Information allowed",
    ("channel", "data_classes"): "Sensitivity allowed",
    ("channel", "scope_ceiling"): "Authorization ceiling",
    ("channel", "preview_required"): "Confirmation",
    ("channel", "max_bytes"): "Maximum bytes per case",
    ("channel", "max_tokens"): "Maximum tokens per case",
    ("channel", "authorization_ttl_seconds"): "Authorization lifetime (seconds)",
    ("local_model", "enabled"): "Local model processing",
    ("local_model", "categories"): "Information the local model may receive",
    ("local_model", "data_classes"): "Sensitivity the local model may receive",
    ("agent_context", "categories"): "Information released to the agent host",
    ("agent_context", "data_classes"): "Sensitivity released to the agent host",
    ("human_control", "data_classes"): "Sensitivity shown on your own terminal",
    ("review", "include_exact_command_text"): "Reviewer sees exact command text",
}


def llm_channel(policy: PrivacyPolicy) -> ChannelPolicy:
    return next(
        channel
        for channel in policy.channel_policies
        if channel.channel is EgressChannel.LLM_INFERENCE
    )


def with_llm(policy: PrivacyPolicy, **changes: object) -> PrivacyPolicy:
    updated = replace(llm_channel(policy), **changes)  # pyright: ignore[reportArgumentType]
    return replace(
        policy,
        channel_policies=tuple(
            updated if channel.channel is EgressChannel.LLM_INFERENCE else channel
            for channel in policy.channel_policies
        ),
    )


def with_review(policy: PrivacyPolicy, profile: ReviewContextProfile) -> PrivacyPolicy:
    """The selector is derived from the profile, so both move together or neither is valid."""

    return replace(
        policy,
        review_context_profile=profile,
        review_selection=ReviewSelectionPolicy.for_profile(profile),
    )


# ---------------------------------------------------------------------------
# The original failure
# ---------------------------------------------------------------------------


EXTERNAL = minimal_external_policy()


def other_provider() -> ProviderBinding:
    return ProviderBinding("openai", "gpt-4.1-mini", "openai-responses", "1.0.0", "external")


_RAW: tuple[tuple[str, PrivacyPolicy, PrivacyPolicy, tuple[str, str, str]], ...] = (
    (
        "network_egress",
        local_only_policy(),
        replace(local_only_policy(), network_egress_permitted=True),
        ("global", "network_egress", ""),
    ),
    (
        "channel_enabled",
        local_only_policy(),
        EXTERNAL,
        ("channel", "enabled", "llm_inference"),
    ),
    (
        "preview_removed",
        with_llm(EXTERNAL, preview_required=True),
        with_llm(EXTERNAL, preview_required=False),
        ("channel", "preview_required", "llm_inference"),
    ),
    (
        "provider_swapped",
        EXTERNAL,
        with_llm(EXTERNAL, provider_binding=other_provider()),
        ("channel", "provider", "llm_inference"),
    ),
    (
        "max_bytes_raised",
        with_llm(EXTERNAL, max_bytes=1024),
        with_llm(EXTERNAL, max_bytes=2048),
        ("channel", "max_bytes", "llm_inference"),
    ),
    (
        "max_tokens_raised",
        with_llm(EXTERNAL, max_tokens=1024),
        with_llm(EXTERNAL, max_tokens=2048),
        ("channel", "max_tokens", "llm_inference"),
    ),
    (
        "authorization_ttl_raised",
        with_llm(EXTERNAL, authorization_ttl_seconds=60),
        with_llm(EXTERNAL, authorization_ttl_seconds=600),
        ("channel", "authorization_ttl_seconds", "llm_inference"),
    ),
    (
        "data_class_added",
        with_llm(EXTERNAL, allowed_data_classes=(DataClass.PUBLIC_STRUCTURAL,)),
        with_llm(
            EXTERNAL,
            allowed_data_classes=(DataClass.PUBLIC_STRUCTURAL, DataClass.ORDINARY_USER_CONTENT),
        ),
        ("channel", "data_classes", "llm_inference"),
    ),
    (
        "purpose_added",
        with_llm(EXTERNAL, allowed_purposes=("semantic-review",)),
        with_llm(EXTERNAL, allowed_purposes=("semantic-review", "finding-triage")),
        ("channel", "purposes", "llm_inference"),
    ),
    (
        "scope_ceiling_broadened",
        with_llm(EXTERNAL, scope_ceiling=AuthorizationScopeKind.TASK),
        with_llm(EXTERNAL, scope_ceiling=AuthorizationScopeKind.MACHINE),
        ("channel", "scope_ceiling", "llm_inference"),
    ),
    (
        "category_added",
        with_llm(EXTERNAL, allowed_categories=(DataCategory.BOUNDED_STRUCTURAL_METADATA,)),
        with_llm(
            EXTERNAL,
            allowed_categories=(
                DataCategory.BOUNDED_STRUCTURAL_METADATA,
                DataCategory.TRANSCRIPT_EXCERPT,
            ),
        ),
        ("channel", "categories", "llm_inference"),
    ),
    (
        "data_use_evidence_dropped",
        replace(EXTERNAL, require_current_provider_data_use_evidence=True),
        replace(EXTERNAL, require_current_provider_data_use_evidence=False),
        ("global", "provider_data_use_evidence", ""),
    ),
    (
        "effective_scope_changed",
        local_only_policy(),
        replace(
            local_only_policy(),
            effective_scope=AuthorizationScope(
                AuthorizationScopeKind.WORKSPACE,
                machine_scope().installation_id,
                workspace_ref_commitment="hmac-sha256:" + "1" * 64,
            ),
        ),
        ("global", "effective_scope", ""),
    ),
    (
        "local_model_enabled",
        local_only_policy(),
        replace(
            local_only_policy(),
            local_model_enabled=True,
            local_model_binding=ProviderBinding(
                "ollama", "qwen3", "local-af-unix", "1.0.0", "local_af_unix"
            ),
        ),
        ("local_model", "enabled", ""),
    ),
    (
        "local_model_categories_added",
        local_only_policy(),
        replace(local_only_policy(), local_model_categories=(DataCategory.CLAIM_TEXT,)),
        ("local_model", "categories", ""),
    ),
    (
        "local_model_data_classes_added",
        local_only_policy(),
        replace(local_only_policy(), local_model_data_classes=(DataClass.SENSITIVE_CONFIDENTIAL,)),
        ("local_model", "data_classes", ""),
    ),
    (
        "agent_context_categories_added",
        local_only_policy(),
        replace(
            local_only_policy(),
            agent_context_categories=(
                *local_only_policy().agent_context_categories,
                DataCategory.TRANSCRIPT_EXCERPT,
            ),
        ),
        ("agent_context", "categories", ""),
    ),
    (
        "agent_context_data_classes_added",
        local_only_policy(),
        replace(
            local_only_policy(),
            agent_context_data_classes=(
                *local_only_policy().agent_context_data_classes,
                DataClass.SENSITIVE_CONFIDENTIAL,
            ),
        ),
        ("agent_context", "data_classes", ""),
    ),
    (
        "human_control_data_classes_added",
        replace(local_only_policy(), trusted_human_control_data_classes=()),
        replace(
            local_only_policy(),
            trusted_human_control_data_classes=(DataClass.SENSITIVE_CONFIDENTIAL,),
        ),
        ("human_control", "data_classes", ""),
    ),
    (
        "review_selector_relaxed",
        with_review(local_only_policy(), ReviewContextProfile.ASSISTED),
        with_review(local_only_policy(), ReviewContextProfile.EXPANDED),
        ("review", "include_exact_command_text", ""),
    ),
)


WIDENING_CASES: Final[
    tuple[tuple[str, PrivacyPolicy, PrivacyPolicy, tuple[str, str, str], str], ...]
] = tuple(
    (name, current, candidate, identity, _SCREEN_LABELS[identity[:2]])
    for name, current, candidate, identity in _RAW
)
