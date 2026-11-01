"""Issue #582: the ``[semantic_fallback]`` pairing of the two external AI-powered review authorities."""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Literal, cast

import pytest

from finishup.config.load import validate_config_mapping
from finishup.config.models import (
    ConfigError,
    ExternalRuntimeProfileConfig,
    FinishUpConfig,
    LocalModelProfileConfig,
    ProviderProfileConfig,
    SemanticFallbackConfig,
    fallback_external_endpoint,
    primary_external_endpoint,
)
from finishup.config.write import (
    cleared_external_runtime_config,
    codex_subscription_runtime,
    external_runtime_binding_config,
    fireworks_provider,
    provider_binding_config,
    render_config_toml,
    semantic_fallback_primary_config,
    semantic_fallback_removed_config,
    write_external_runtime_binding,
    write_provider_binding,
)

_DIGEST = "sha256:" + "a" * 64
_MODEL = "accounts/fireworks/models/minimax-m3"


def _provider() -> ProviderProfileConfig:
    return fireworks_provider(model=_MODEL)


def _runtime() -> ExternalRuntimeProfileConfig:
    return codex_subscription_runtime(
        executable_path="/Applications/Codex.app/Contents/Resources/codex",
        executable_sha256=_DIGEST,
        runtime_version="0.150.1",
        source_identity="openai-codex-npm-darwin-arm64-0.150.1",
        app_server_schema_sha256=_DIGEST,
        capability_cell_sha256=_DIGEST,
        isolated_config_sha256=_DIGEST,
        capability_profile="codex-evaluator/0.150.1/v1",
        capability_evidence_expires_at="2026-11-30T00:00:00Z",
        codex_home="/opt/FinishUP Tools/codex-home",
        model="gpt-5.6-sol",
        reasoning_effort="high",
    )


def _local_model() -> LocalModelProfileConfig:
    return LocalModelProfileConfig(
        profile_id="local-reviewed",
        profile_version="1.0.0",
        endpoint_profile_id="af-unix-json",
        endpoint_profile_version="1.0.0",
        model="reviewer-7b",
        protocol_version="1.0.0",
        judgment_schema_version="1.0.0",
        capability_digest=_DIGEST,
    )


def _paired(primary: Literal["api_provider", "codex_subscription"]) -> FinishUpConfig:
    return FinishUpConfig(
        profile="codex-subscription" if primary == "codex_subscription" else "local-openai",
        provider=_provider(),
        external_runtime=_runtime(),
        semantic_fallback=SemanticFallbackConfig(primary=primary),
    )


def _reason(factory: object) -> str:
    assert callable(factory)
    with pytest.raises(ConfigError) as caught:
        factory()
    return caught.value.reason_code


def test_selector_is_a_closed_nonsecret_literal() -> None:
    assert SemanticFallbackConfig(primary="api_provider").primary == "api_provider"
    assert SemanticFallbackConfig.model_validate({"primary": "codex_subscription"}).primary == (
        "codex_subscription"
    )
    assert (
        _reason(
            lambda: SemanticFallbackConfig.model_validate({"primary": "api_provider", "extra": 1})
        )
        == "unknown_config_key"
    )
    assert (
        _reason(
            lambda: SemanticFallbackConfig.model_validate(
                {"primary": "api_provider", "api_key": "sk-x"}
            )
        )
        == "secret_in_config"
    )
    assert (
        _reason(lambda: SemanticFallbackConfig.model_validate({"primary": "local_model"}))
        == "config_value_invalid"
    )


@pytest.mark.parametrize("primary", ("api_provider", "codex_subscription"))
def test_a_pairing_binds_both_tables_under_the_primary_profile(
    primary: Literal["api_provider", "codex_subscription"],
) -> None:
    config = _paired(primary)
    assert config.provider is not None and config.external_runtime is not None
    primary_endpoint = primary_external_endpoint(config)
    fallback_endpoint = fallback_external_endpoint(config)
    if primary == "api_provider":
        assert type(primary_endpoint) is ProviderProfileConfig
        assert type(fallback_endpoint) is ExternalRuntimeProfileConfig
        assert (primary_endpoint, fallback_endpoint) == (config.provider, config.external_runtime)
    else:
        assert type(primary_endpoint) is ExternalRuntimeProfileConfig
        assert type(fallback_endpoint) is ProviderProfileConfig
        assert (primary_endpoint, fallback_endpoint) == (config.external_runtime, config.provider)


def test_a_pairing_fails_closed_on_every_incomplete_or_mismatched_shape() -> None:
    selector = SemanticFallbackConfig(primary="api_provider")
    assert (
        _reason(
            lambda: FinishUpConfig(
                profile="local-openai", provider=_provider(), semantic_fallback=selector
            )
        )
        == "semantic_fallback_endpoint_missing"
    )
    assert (
        _reason(
            lambda: FinishUpConfig(
                profile="codex-subscription",
                external_runtime=_runtime(),
                semantic_fallback=SemanticFallbackConfig(primary="codex_subscription"),
            )
        )
        == "semantic_fallback_endpoint_missing"
    )
    assert (
        _reason(lambda: FinishUpConfig(profile="local-openai", semantic_fallback=selector))
        == "semantic_fallback_endpoint_missing"
    )
    assert (
        _reason(
            lambda: FinishUpConfig(
                profile="local-openai",
                provider=_provider(),
                external_runtime=_runtime(),
                local_model=_local_model(),
                semantic_fallback=selector,
            )
        )
        == "external_runtime_forbids_local_model"
    )
    # The profile must name the primary: swapping either side is a mismatch, not a coercion.
    assert (
        _reason(
            lambda: FinishUpConfig(
                profile="codex-subscription",
                provider=_provider(),
                external_runtime=_runtime(),
                semantic_fallback=selector,
            )
        )
        == "semantic_fallback_profile_mismatch"
    )
    assert (
        _reason(
            lambda: FinishUpConfig(
                profile="local-openai",
                provider=_provider(),
                external_runtime=_runtime(),
                semantic_fallback=SemanticFallbackConfig(primary="codex_subscription"),
            )
        )
        == "semantic_fallback_profile_mismatch"
    )
    for profile in ("strict-local", "test-fake"):
        assert (
            _reason(
                lambda: FinishUpConfig(
                    profile=cast(Literal["strict-local"], profile),
                    provider=_provider(),
                    external_runtime=_runtime(),
                    semantic_fallback=selector,
                )
            )
            == "semantic_fallback_profile_mismatch"
        )


def test_without_a_pairing_the_single_bound_table_is_the_primary() -> None:
    api_only = FinishUpConfig(profile="local-openai", provider=_provider())
    codex_only = FinishUpConfig(profile="codex-subscription", external_runtime=_runtime())
    assert primary_external_endpoint(api_only) == _provider()
    assert primary_external_endpoint(codex_only) == _runtime()
    assert primary_external_endpoint(FinishUpConfig()) is None
    assert fallback_external_endpoint(api_only) is None
    assert fallback_external_endpoint(codex_only) is None
    # Both tables without a selector is still the pre-#582 exclusivity error.
    assert (
        _reason(
            lambda: FinishUpConfig(
                profile="codex-subscription", provider=_provider(), external_runtime=_runtime()
            )
        )
        == "external_runtime_forbids_provider"
    )
    with pytest.raises(TypeError, match="config_wrong_type"):
        primary_external_endpoint(cast(FinishUpConfig, object()))
    with pytest.raises(TypeError, match="config_wrong_type"):
        fallback_external_endpoint(cast(FinishUpConfig, object()))


@pytest.mark.parametrize("primary", ("api_provider", "codex_subscription"))
def test_rendered_toml_carries_the_selector_and_round_trips_through_the_loader(
    primary: Literal["api_provider", "codex_subscription"], tmp_path: Path
) -> None:
    config = _paired(primary)
    text = render_config_toml(config)
    assert "[semantic_fallback]" in text
    assert f'primary = "{primary}"' in text
    assert "[provider]" in text and "[external_runtime]" in text
    assert "api_key" not in text and "oauth" not in text.replace("external_runtime_oauth", "")
    loaded = validate_config_mapping(tomllib.loads(text))
    assert loaded == config
    assert render_config_toml(loaded) == text
    # A single-endpoint config still renders without the table.
    assert "[semantic_fallback]" not in render_config_toml(
        FinishUpConfig(profile="local-openai", provider=_provider())
    )


def test_binding_an_api_provider_as_fallback_needs_the_bound_subscription() -> None:
    assert (
        _reason(
            lambda: provider_binding_config(_provider(), base=FinishUpConfig(), as_fallback=True)
        )
        == "semantic_fallback_endpoint_missing"
    )
    with pytest.raises(TypeError, match="config_write_wrong_type"):
        provider_binding_config(cast(ProviderProfileConfig, _runtime()))

    base = FinishUpConfig(profile="codex-subscription", external_runtime=_runtime())
    paired = provider_binding_config(_provider(), base=base, as_fallback=True)
    assert paired == _paired("codex_subscription")

    # Inside a pairing, a plain rebind replaces only the API slot and keeps the selector.
    replacement = fireworks_provider(model="accounts/fireworks/models/other")
    rebound = provider_binding_config(replacement, base=_paired("api_provider"))
    assert rebound.provider == replacement
    assert rebound.external_runtime == _runtime()
    assert rebound.semantic_fallback == SemanticFallbackConfig(primary="api_provider")
    assert rebound.profile == "local-openai"

    # Without a pairing the single-endpoint rule holds: the subscription binding is dropped.
    single = provider_binding_config(_provider(), base=base)
    assert single.external_runtime is None
    assert single.semantic_fallback is None
    assert single.profile == "local-openai"


def test_binding_a_subscription_as_fallback_needs_the_bound_api_provider() -> None:
    assert (
        _reason(
            lambda: external_runtime_binding_config(
                _runtime(), base=FinishUpConfig(), as_fallback=True
            )
        )
        == "semantic_fallback_endpoint_missing"
    )

    base = FinishUpConfig(profile="local-openai", provider=_provider())
    paired = external_runtime_binding_config(_runtime(), base=base, as_fallback=True)
    assert paired == _paired("api_provider")

    rebound = external_runtime_binding_config(_runtime(), base=_paired("codex_subscription"))
    assert rebound == _paired("codex_subscription")

    single = external_runtime_binding_config(_runtime(), base=base)
    assert single.provider is None
    assert single.semantic_fallback is None
    assert single.profile == "codex-subscription"


@pytest.mark.parametrize("primary", ("api_provider", "codex_subscription"))
def test_clearing_the_subscription_inside_a_pairing_keeps_the_api_provider_alone(
    primary: Literal["api_provider", "codex_subscription"],
) -> None:
    cleared = cleared_external_runtime_config(_paired(primary))
    assert cleared == FinishUpConfig(profile="local-openai", provider=_provider())
    assert cleared_external_runtime_config(cleared) == cleared


def test_removing_the_fallback_is_the_exact_reverse_of_declaring_it() -> None:
    assert semantic_fallback_removed_config(_paired("api_provider")) == FinishUpConfig(
        profile="local-openai", provider=_provider()
    )
    assert semantic_fallback_removed_config(_paired("codex_subscription")) == FinishUpConfig(
        profile="codex-subscription", external_runtime=_runtime()
    )
    assert (
        _reason(
            lambda: semantic_fallback_removed_config(
                FinishUpConfig(profile="local-openai", provider=_provider())
            )
        )
        == "semantic_fallback_endpoint_missing"
    )
    with pytest.raises(TypeError, match="config_write_wrong_type"):
        semantic_fallback_removed_config(cast(FinishUpConfig, object()))


def test_swapping_the_primary_keeps_both_endpoints_bound() -> None:
    swapped = semantic_fallback_primary_config(_paired("api_provider"), "codex_subscription")
    assert swapped == _paired("codex_subscription")
    assert semantic_fallback_primary_config(swapped, "api_provider") == _paired("api_provider")
    assert semantic_fallback_primary_config(swapped, "codex_subscription") == swapped
    assert (
        _reason(
            lambda: semantic_fallback_primary_config(
                FinishUpConfig(profile="local-openai", provider=_provider()), "codex_subscription"
            )
        )
        == "semantic_fallback_endpoint_missing"
    )
    with pytest.raises(TypeError, match="config_write_wrong_type"):
        semantic_fallback_primary_config(cast(FinishUpConfig, object()), "api_provider")


def test_written_pairings_round_trip_from_disk_in_both_directions(tmp_path: Path) -> None:
    api_first = tmp_path / "api-first.toml"
    write_provider_binding(_provider(), path=api_first)
    base = validate_config_mapping(tomllib.loads(api_first.read_text()))
    write_external_runtime_binding(_runtime(), path=api_first, base=base, as_fallback=True)
    assert validate_config_mapping(tomllib.loads(api_first.read_text())) == _paired("api_provider")

    codex_first = tmp_path / "codex-first.toml"
    write_external_runtime_binding(_runtime(), path=codex_first)
    base = validate_config_mapping(tomllib.loads(codex_first.read_text()))
    write_provider_binding(_provider(), path=codex_first, base=base, as_fallback=True)
    assert validate_config_mapping(tomllib.loads(codex_first.read_text())) == _paired(
        "codex_subscription"
    )
