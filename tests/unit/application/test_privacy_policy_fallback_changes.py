"""Issue #582: a fallback destination is one more authorized destination on the approval screen.

Adding or swapping it is a widening of exactly that destination; dropping it is a tightening.
The trusted screen names it in plain English right after the primary, through the same binding
renderer.
"""

from __future__ import annotations

from dataclasses import replace

from builders.privacy_policies import (
    disabled_channel,
    local_only_policy,
    minimal_external_policy,
)
from builders.privacy_widenings import llm_channel, other_provider, with_llm
from finishup.application.privacy_policy import is_privacy_tightening, privacy_policy_changes
from finishup.cli.unlock import (
    _privacy_policy_change_text,  # pyright: ignore[reportPrivateUsage]
)
from finishup.domain.privacy import (
    PrivacyPolicy,
    PrivacyPolicyChangeValue,
    PrivacyProfile,
    ProviderBinding,
    privacy_change_order,
    sort_privacy_changes,
)
from finishup.service.confidential_protocol import PrivacyPolicyDecisionPreview

_DIGEST = "sha256:" + "b" * 64
_IDENTITY = ("channel", "fallback_provider", "llm_inference")


def _single() -> PrivacyPolicy:
    return minimal_external_policy()


def _paired(fallback: ProviderBinding | None = None) -> PrivacyPolicy:
    return with_llm(_single(), fallback_provider_binding=fallback or other_provider())


def _third() -> ProviderBinding:
    return ProviderBinding("anthropic", "claude-sonnet-4-6", "anthropic-chat", "1.0.0", "external")


def _rendered(current: PrivacyPolicy, candidate: PrivacyPolicy) -> str:
    changes = privacy_policy_changes(current, candidate)
    return _privacy_policy_change_text(PrivacyPolicyDecisionPreview("pending-1", _DIGEST, changes))


def test_adding_a_fallback_is_a_widening_of_exactly_that_destination() -> None:
    changes = privacy_policy_changes(_single(), _paired())

    assert is_privacy_tightening(_single(), _paired()) is False
    assert [change.identity for change in changes] == [_IDENTITY]
    (change,) = changes
    assert change.widens is True
    assert change.before == PrivacyPolicyChangeValue.absent()
    assert change.after == PrivacyPolicyChangeValue.of_labels(
        (
            "endpoint:openai-responses",
            "endpoint_version:1.0.0",
            "model:gpt-4.1-mini",
            "provider:openai",
            "transport:external",
        )
    )


def test_swapping_the_fallback_widens_and_keeping_it_is_not_a_change() -> None:
    assert privacy_policy_changes(_paired(), _paired()) == ()
    assert is_privacy_tightening(_paired(), _paired()) is True

    changes = privacy_policy_changes(_paired(), _paired(_third()))
    assert [change.identity for change in changes] == [_IDENTITY]
    assert changes[0].widens is True
    assert is_privacy_tightening(_paired(), _paired(_third())) is False


def test_dropping_the_fallback_is_a_tightening_that_still_shows_the_lost_destination() -> None:
    changes = privacy_policy_changes(_paired(), _single())

    assert is_privacy_tightening(_paired(), _single()) is True
    assert [change.identity for change in changes] == [_IDENTITY]
    (change,) = changes
    assert change.widens is False
    assert change.after == PrivacyPolicyChangeValue.absent()
    assert change.before.kind == "labels"


def test_disabling_the_channel_names_the_fallback_among_the_lost_ceilings() -> None:
    current = _paired()
    candidate = replace(
        current,
        profile=PrivacyProfile.LOCAL_ONLY,
        network_egress_permitted=False,
        require_current_provider_data_use_evidence=False,
        channel_policies=tuple(
            disabled_channel(channel.channel) for channel in current.channel_policies
        ),
    )
    changes = privacy_policy_changes(current, candidate)

    assert is_privacy_tightening(current, candidate) is True
    identities = {change.identity for change in changes}
    assert ("channel", "provider", "llm_inference") in identities
    assert _IDENTITY in identities
    fallback = next(change for change in changes if change.field == "fallback_provider")
    assert fallback.widens is False
    assert fallback.after.kind == "none"


def test_the_fallback_reads_right_after_the_primary_destination() -> None:
    changes = privacy_policy_changes(local_only_policy(), _paired())

    assert sort_privacy_changes(tuple(reversed(changes))) == changes
    assert [change.identity for change in changes[:4]] == [
        ("global", "network_egress", ""),
        ("channel", "enabled", "llm_inference"),
        ("channel", "provider", "llm_inference"),
        _IDENTITY,
    ]
    keys = [privacy_change_order(change) for change in changes]
    assert keys == sorted(keys) and len(set(keys)) == len(keys)


def test_the_trusted_screen_names_the_fallback_through_the_binding_renderer() -> None:
    text = _rendered(_single(), _paired())

    line = next(line for line in text.splitlines() if "Fallback provider and model" in line)
    assert "(!)" in line
    assert "Not applicable -> openai / gpt-4.1-mini (openai-responses, external)" in line
    assert "1 of 1 change" in text or "1 change" in text
    # Nothing a proposal author writes can reach the screen: only closed vocabulary appears.
    assert "gpt-4.1-mini" in text and "Provider and model" not in line


def test_the_screen_shows_a_dropped_fallback_without_marking_it_as_widening() -> None:
    # A preview must carry at least one widening; the raised byte ceiling supplies it.
    text = _rendered(_paired(), with_llm(_single(), max_bytes=524_288))

    line = next(line for line in text.splitlines() if "Fallback provider and model" in line)
    assert "(!)" not in line
    assert "openai / gpt-4.1-mini (openai-responses, external) -> Not applicable" in line


def test_the_screen_places_the_fallback_under_destination_after_the_primary() -> None:
    original_primary = llm_channel(_paired()).provider_binding
    assert original_primary is not None
    # Both destinations move: the primary becomes a third provider, the old primary becomes
    # the fallback. Two widenings, read in the fixed order.
    candidate = with_llm(
        _paired(), provider_binding=_third(), fallback_provider_binding=original_primary
    )
    lines = _rendered(_paired(), candidate).splitlines()

    primary_at = next(
        index
        for index, line in enumerate(lines)
        if "Provider and model" in line and "Fallback" not in line
    )
    fallback_at = next(
        index for index, line in enumerate(lines) if "Fallback provider and model" in line
    )
    destination_at = next(
        index for index, line in enumerate(lines) if line.strip().startswith("Destination")
    )
    assert destination_at < primary_at < fallback_at
    assert "(!)" in lines[primary_at] and "(!)" in lines[fallback_at]
    assert "2 of 2 changes" in "\n".join(lines)
