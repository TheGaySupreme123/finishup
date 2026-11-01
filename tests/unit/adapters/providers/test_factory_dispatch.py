"""Every configurable endpoint profile selects exactly one runtime factory."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from finishup.adapters.providers.factory import (
    ChatCompletionsExternalFactory,
    OpenAIResponsesExternalFactory,
    external_factory_builders_from_config,
)
from finishup.config.models import ProviderProfileConfig
from finishup.config.write import (
    anthropic_provider,
    fireworks_provider,
    google_gemini_provider,
    grok_provider,
    official_openai_provider,
    openrouter_provider,
    owner_declared_openai_provider,
    vercel_ai_gateway_provider,
)

_NOW = datetime(2026, 7, 24, tzinfo=UTC)


class _Clock:
    def now_utc(self) -> datetime:
        return _NOW

    def monotonic_seconds(self) -> float:
        return 1.0


def _built(provider: ProviderProfileConfig) -> object:
    builders = external_factory_builders_from_config(provider, clock=_Clock())  # pyright: ignore[reportArgumentType]
    assert len(builders) == 1
    ((binding, builder),) = builders.items()
    assert binding.endpoint_profile_id == provider.endpoint_profile_id
    assert binding.transport == "external"
    assert callable(builder)
    return builder()


@pytest.mark.parametrize(
    ("provider", "factory_type", "host", "path"),
    (
        (
            official_openai_provider(model="gpt-4.1-mini"),
            OpenAIResponsesExternalFactory,
            "api.openai.com",
            "/v1/responses",
        ),
        (
            fireworks_provider(model="accounts/fireworks/models/qwen3-235b-a22b"),
            OpenAIResponsesExternalFactory,
            "api.fireworks.ai",
            "/inference/v1/responses",
        ),
        (
            vercel_ai_gateway_provider(model="anthropic/claude-sonnet-4-6"),
            OpenAIResponsesExternalFactory,
            "ai-gateway.vercel.sh",
            "/v1/responses",
        ),
        (
            anthropic_provider(model="claude-sonnet-4-6"),
            ChatCompletionsExternalFactory,
            "api.anthropic.com",
            "/v1/chat/completions",
        ),
        (
            google_gemini_provider(model="gemini-3.5-flash"),
            ChatCompletionsExternalFactory,
            "generativelanguage.googleapis.com",
            "/v1beta/openai/chat/completions",
        ),
        (
            openrouter_provider(model="openai/gpt-5.2"),
            ChatCompletionsExternalFactory,
            "openrouter.ai",
            "/api/v1/chat/completions",
        ),
        (
            grok_provider(model="grok-4.5"),
            ChatCompletionsExternalFactory,
            "api.x.ai",
            "/v1/chat/completions",
        ),
    ),
)
def test_each_bundled_preset_dispatches_to_its_exact_endpoint(
    provider: ProviderProfileConfig, factory_type: type[object], host: str, path: str
) -> None:
    """A preset the setup surface can write must resolve to a factory, never factory_unavailable."""

    factory = _built(provider)

    assert type(factory) is factory_type
    profile = getattr(factory, "profile")
    assert profile.host == host
    assert profile.port == 443
    assert profile.path == path
    assert profile.base_url == f"https://{host}{profile.base_path_prefix}"


def test_owner_declared_origin_still_reaches_the_responses_factory() -> None:
    provider = owner_declared_openai_provider(model="local-model", https_origin="https://box:8443")

    factory = _built(provider)

    assert type(factory) is OpenAIResponsesExternalFactory
    assert factory.profile.host == "box"
    assert factory.profile.port == 8443


def test_unknown_endpoint_profile_yields_no_builder() -> None:
    """An unregistered profile must produce nothing rather than a wrongly-shaped request."""

    provider = ProviderProfileConfig(
        provider_id="someone",
        endpoint_profile_id="someone-unregistered-protocol",
        endpoint_profile_version="1.0.0",
        model="some-model",
        capability_profile="openai-responses-structured-1",
    )

    assert external_factory_builders_from_config(provider, clock=_Clock()) == {}  # pyright: ignore[reportArgumentType]
    assert external_factory_builders_from_config(None, clock=_Clock()) == {}  # pyright: ignore[reportArgumentType]


def test_chat_completions_bindings_use_exact_profile_data_use_facts() -> None:
    """Only a route with its own catalog record can carry favorable data-use facts."""

    anthropic = getattr(_built(anthropic_provider(model="claude-sonnet-4-6")), "profile")
    assert anthropic.data_use_profile.customer_content_training == "prohibited"
    assert anthropic.data_use_profile.retention_days_ceiling == 30

    for provider in (
        google_gemini_provider(model="gemini-3.5-flash"),
        openrouter_provider(model="openai/gpt-5.2"),
    ):
        profile = getattr(_built(provider), "profile")
        data_use = profile.data_use_profile
        assert data_use.customer_content_training == "unknown"
        assert data_use.retention == "unknown"
        assert data_use.provider_human_access == "unknown"

    xai = getattr(_built(grok_provider(model="grok-4.5")), "profile").data_use_profile
    assert xai.customer_content_training == "prohibited"
    assert xai.retention_days_ceiling == 30
    assert xai.provider_human_access == "restricted"
