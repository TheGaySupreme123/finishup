"""Exact in-memory privacy policies for wire-codec and control-encoder tests."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Final

from finishup.domain.privacy import (
    AuthorizationScope,
    AuthorizationScopeKind,
    ChannelPolicy,
    DataClass,
    EgressChannel,
    PrivacyPolicy,
    PrivacyProfile,
    ProviderBinding,
    ReviewContextProfile,
    ReviewSelectionPolicy,
)
from finishup.protocol.models import DataCategory

__all__ = [
    "INSTALLATION_ID",
    "POLICY_DIGEST",
    "POLICY_ID",
    "SUCCESSOR_POLICY_DIGEST",
    "disabled_channel",
    "local_only_policy",
    "machine_scope",
    "minimal_external_policy",
]

NOW: Final = datetime(2026, 7, 25, tzinfo=UTC)
INSTALLATION_ID: Final = "ins_30000000-0000-4000-8000-000000000001"
POLICY_ID: Final = "pvy_30000000-0000-4000-8000-000000000002"
POLICY_DIGEST: Final = f"sha256:{'a' * 64}"
SUCCESSOR_POLICY_DIGEST: Final = f"sha256:{'b' * 64}"

_AGENT_CONTEXT_DATA_CLASSES: Final = (
    DataClass.ORDINARY_USER_CONTENT,
    DataClass.PUBLIC_STRUCTURAL,
    DataClass.SENSITIVE_CONFIDENTIAL,
)


def machine_scope() -> AuthorizationScope:
    return AuthorizationScope(AuthorizationScopeKind.MACHINE, INSTALLATION_ID)


def disabled_channel(channel: EgressChannel) -> ChannelPolicy:
    return ChannelPolicy(
        channel,
        False,
        (),
        (),
        None,
        (),
        AuthorizationScopeKind.MACHINE,
        False,
        0,
        0,
        0,
    )


def _ordered(channels: dict[EgressChannel, ChannelPolicy]) -> tuple[ChannelPolicy, ...]:
    return tuple(channels[channel] for channel in sorted(EgressChannel, key=lambda c: c.value))


def local_only_policy() -> PrivacyPolicy:
    """Version 1, every egress channel off — the shape a fresh installation carries."""

    return PrivacyPolicy(
        POLICY_ID,
        1,
        POLICY_DIGEST,
        PrivacyProfile.LOCAL_ONLY,
        ReviewContextProfile.STRUCTURAL,
        ReviewSelectionPolicy.for_profile(ReviewContextProfile.STRUCTURAL),
        False,
        False,
        machine_scope(),
        _ordered({channel: disabled_channel(channel) for channel in EgressChannel}),
        False,
        None,
        (),
        (),
        (
            DataCategory.BOUNDED_STRUCTURAL_METADATA,
            DataCategory.DECLARED_FILE_TYPE,
            DataCategory.FINDING_SUMMARY,
            DataCategory.OBLIGATION_TEXT,
        ),
        (DataClass.PUBLIC_STRUCTURAL, DataClass.ORDINARY_USER_CONTENT),
        tuple(DataCategory),
        _AGENT_CONTEXT_DATA_CLASSES,
        NOW,
    )


def minimal_external_policy() -> PrivacyPolicy:
    """Version 2, ``llm_inference`` enabled against a bound provider — the widened shape."""

    channels = {channel: disabled_channel(channel) for channel in EgressChannel}
    channels[EgressChannel.LLM_INFERENCE] = ChannelPolicy(
        EgressChannel.LLM_INFERENCE,
        True,
        (
            DataCategory.BOUNDED_STRUCTURAL_METADATA,
            DataCategory.CLAIM_TEXT,
            DataCategory.EVIDENCE_EXCERPT,
            DataCategory.REPOSITORY_EXCERPT,
            DataCategory.TASK_DESCRIPTION,
        ),
        (DataClass.ORDINARY_USER_CONTENT, DataClass.PUBLIC_STRUCTURAL),
        ProviderBinding(
            "fireworks",
            "accounts/fireworks/models/minimax-m3",
            "fireworks-responses",
            "1.0.0",
            "external",
        ),
        ("semantic-review",),
        AuthorizationScopeKind.TASK,
        False,
        262_144,
        4096,
        300,
    )
    return PrivacyPolicy(
        POLICY_ID,
        2,
        SUCCESSOR_POLICY_DIGEST,
        PrivacyProfile.MINIMAL_EXTERNAL,
        ReviewContextProfile.ASSISTED,
        ReviewSelectionPolicy.for_profile(ReviewContextProfile.ASSISTED),
        False,
        True,
        machine_scope(),
        _ordered(channels),
        False,
        None,
        (),
        (),
        (
            DataCategory.BOUNDED_STRUCTURAL_METADATA,
            DataCategory.DECLARED_FILE_TYPE,
        ),
        (DataClass.PUBLIC_STRUCTURAL,),
        tuple(DataCategory),
        _AGENT_CONTEXT_DATA_CLASSES,
        NOW,
        POLICY_DIGEST,
    )
