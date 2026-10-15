"""Issue #582: ``ChannelPolicy.fallback_provider_binding`` — invariants, meet, wire, ordering."""

from __future__ import annotations

from dataclasses import replace
from typing import cast

import pytest

from builders.privacy_policies import disabled_channel, minimal_external_policy
from builders.privacy_widenings import llm_channel, other_provider, with_llm
from finishup.adapters.privacy.catalog import (
    decode_privacy_policy_canonical,
    encode_privacy_policy_json,
)
from finishup.domain.privacy import (
    _CHANGE_IMPACT,  # pyright: ignore[reportPrivateUsage]
    PRIVACY_CHANGE_FIELDS,
    ChannelPolicy,
    EgressChannel,
    ProviderBinding,
)
from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.protocol.schemas import validate_schema_instance


def _llm() -> ChannelPolicy:
    return llm_channel(minimal_external_policy())


def _local() -> ProviderBinding:
    return ProviderBinding("local", "reviewer-7b", "af-unix-json", "1.0.0", "local_af_unix")


def _paired() -> ChannelPolicy:
    return replace(_llm(), fallback_provider_binding=other_provider())


def _channel_json(policy_json: dict[str, JsonValue]) -> dict[str, JsonValue]:
    channels = cast(list[dict[str, JsonValue]], policy_json["channel_policies"])
    return next(item for item in channels if item["channel"] == "llm_inference")


def test_authorized_bindings_are_primary_first_and_empty_when_disabled() -> None:
    primary = _llm().provider_binding
    assert primary is not None
    assert _llm().authorized_provider_bindings == (primary,)
    assert _paired().authorized_provider_bindings == (primary, other_provider())
    assert disabled_channel(EgressChannel.LLM_INFERENCE).authorized_provider_bindings == ()
    # The trailing default keeps every positional constructor unchanged.
    assert _llm().fallback_provider_binding is None


@pytest.mark.parametrize(
    ("factory", "why"),
    (
        (lambda: replace(_llm(), enabled=False, fallback_provider_binding=other_provider()), "off"),
        (
            lambda: replace(
                _llm(), provider_binding=None, fallback_provider_binding=other_provider()
            ),
            "no primary",
        ),
        (
            lambda: replace(
                _llm(), provider_binding=_local(), fallback_provider_binding=other_provider()
            ),
            "local primary",
        ),
        (lambda: replace(_llm(), fallback_provider_binding=_local()), "local fallback"),
        (lambda: replace(_llm(), fallback_provider_binding=_llm().provider_binding), "same"),
        (
            lambda: replace(_llm(), fallback_provider_binding=cast(ProviderBinding, object())),
            "wrong type",
        ),
        (
            lambda: replace(
                disabled_channel(EgressChannel.UPDATE_CHECKS),
                enabled=True,
                fallback_provider_binding=other_provider(),
            ),
            "not llm",
        ),
    ),
    ids=(
        "off",
        "no_primary",
        "local_primary",
        "local_fallback",
        "same_as_primary",
        "wrong_type",
        "not_llm",
    ),
)
def test_a_fallback_is_only_valid_behind_a_different_external_primary_on_llm_inference(
    factory: object, why: str
) -> None:
    assert callable(factory)
    with pytest.raises(ValueError, match="invalid_privacy_value"):
        factory()


def test_meet_keeps_the_fallback_only_when_both_scopes_name_the_identical_one() -> None:
    paired = _paired()
    both = paired.meet(paired)
    assert both.fallback_provider_binding == other_provider()
    assert both.authorized_provider_bindings == paired.authorized_provider_bindings

    third = ProviderBinding("anthropic", "claude-sonnet-4-6", "anthropic-chat", "1.0.0", "external")
    disagree = paired.meet(replace(paired, fallback_provider_binding=third))
    assert disagree.enabled is True
    assert disagree.provider_binding == paired.provider_binding
    assert disagree.fallback_provider_binding is None

    one_sided = paired.meet(_llm())
    assert one_sided.fallback_provider_binding is None
    assert one_sided.provider_binding == paired.provider_binding
    assert _llm().meet(paired).fallback_provider_binding is None

    # Primary disagreement still disables the channel, fallback or not.
    primary_swap = paired.meet(
        replace(paired, provider_binding=third, fallback_provider_binding=other_provider())
    )
    assert primary_swap.enabled is False
    assert primary_swap.provider_binding is None
    assert primary_swap.fallback_provider_binding is None
    assert primary_swap.authorized_provider_bindings == ()


def test_the_fallback_field_is_in_the_change_vocabulary_right_after_the_primary() -> None:
    assert "fallback_provider" in PRIVACY_CHANGE_FIELDS["channel"]
    assert _CHANGE_IMPACT[("channel", "fallback_provider")] == 3
    assert _CHANGE_IMPACT[("channel", "fallback_provider")] == (
        _CHANGE_IMPACT[("channel", "provider")] + 1
    )
    # Every other ceiling reads after it: the destination question outranks "how much".
    assert all(
        rank > 3
        for key, rank in _CHANGE_IMPACT.items()
        if key
        not in {
            ("global", "network_egress"),
            ("channel", "enabled"),
            ("channel", "provider"),
            ("channel", "fallback_provider"),
        }
    )


def test_wire_omits_the_fallback_when_absent_so_existing_digests_are_unchanged() -> None:
    single = encode_privacy_policy_json(minimal_external_policy())
    assert "fallback_provider_binding" not in _channel_json(single)
    # The current Assisted preset names the task_statement section, so it encodes at 1.2.0.
    assert single["schema_version"] == "1.2.0"
    validate_schema_instance("privacy-policy", "1.2.0", single)
    assert decode_privacy_policy_canonical(canonical_encode(single)) == minimal_external_policy()


def test_wire_round_trips_the_fallback_binding_when_present() -> None:
    policy = with_llm(minimal_external_policy(), fallback_provider_binding=other_provider())
    wire = encode_privacy_policy_json(policy)
    channel = _channel_json(wire)
    assert channel["fallback_provider_binding"] == {
        "provider_id": "openai",
        "model_id": "gpt-4.1-mini",
        "endpoint_profile_id": "openai-responses",
        "endpoint_profile_version": "1.0.0",
        "transport": "external",
    }
    validate_schema_instance("privacy-policy", "1.2.0", wire)
    decoded = decode_privacy_policy_canonical(canonical_encode(wire))
    assert decoded == policy
    assert llm_channel(decoded).authorized_provider_bindings == (
        llm_channel(policy).provider_binding,
        other_provider(),
    )
    # The two encodings differ by exactly that one key.
    single = _channel_json(encode_privacy_policy_json(minimal_external_policy()))
    assert {key for key in channel if key not in single} == {"fallback_provider_binding"}


def test_fallback_cannot_be_smuggled_under_the_released_wire_version() -> None:
    policy = with_llm(minimal_external_policy(), fallback_provider_binding=other_provider())
    wire = encode_privacy_policy_json(policy)
    wire["schema_version"] = "1.0.0"
    with pytest.raises(ValueError, match="privacy_policy_row_corrupt"):
        decode_privacy_policy_canonical(canonical_encode(wire))
