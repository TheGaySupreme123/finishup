"""Issue #582: the pairing's CLI surface and its flow into the privacy candidate.

``provider fallback remove|primary`` are exercised through the Typer app with the config writers
patched: the default write target is the live user config directory, which no unit test may
touch. The writers themselves run against ``tmp_path`` files.
"""

from __future__ import annotations

import json
import tomllib
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import pytest
from typer.testing import CliRunner

import finishup.cli.privacy_setup as privacy_setup
import finishup.cli.provider_binding as provider_binding
import finishup.config.load as config_load
from builders.privacy_policies import local_only_policy
from finishup.cli.app import app
from finishup.cli.privacy_setup import build_candidate_policy
from finishup.cli.provider_binding import (
    apply_provider_endpoint_choice,
    remove_semantic_fallback,
    set_semantic_fallback_primary,
)
from finishup.config.load import validate_config_mapping
from finishup.config.models import ConfigError, FinishUpConfig, SemanticFallbackConfig
from finishup.config.write import codex_subscription_runtime, write_config_toml
from finishup.domain.privacy import EgressChannel, ProviderBinding
from unit.cli.test_privacy_setup import _answers  # pyright: ignore[reportPrivateUsage]

_DIGEST = "sha256:" + "a" * 64
_MODEL = "accounts/fireworks/models/minimax-m3"


def _runtime():  # noqa: ANN202 - builder return type is the config model
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


def _codex_only(path: Path) -> Path:
    return write_config_toml(
        FinishUpConfig(profile="codex-subscription", external_runtime=_runtime()), path=path
    )


def _loaded(path: Path) -> FinishUpConfig:
    return validate_config_mapping(tomllib.loads(path.read_text()))


def _codex_binding() -> ProviderBinding:
    return ProviderBinding(
        "openai-codex", "gpt-5.6-sol", "codex-chatgpt-subscription", "1.0.0", "external"
    )


def test_endpoint_as_fallback_pairs_behind_the_bound_subscription(tmp_path: Path) -> None:
    target = _codex_only(tmp_path / "config.toml")
    path, provider = apply_provider_endpoint_choice(
        "fireworks", model=_MODEL, path=target, as_fallback=True
    )
    assert path == target
    loaded = _loaded(target)
    assert loaded.profile == "codex-subscription"
    assert loaded.provider == provider
    assert loaded.external_runtime == _runtime()
    assert loaded.semantic_fallback == SemanticFallbackConfig(primary="codex_subscription")


def test_endpoint_as_fallback_refuses_without_a_bound_subscription(tmp_path: Path) -> None:
    target = tmp_path / "config.toml"
    with pytest.raises(ConfigError) as caught:
        apply_provider_endpoint_choice("fireworks", model=_MODEL, path=target, as_fallback=True)
    assert caught.value.reason_code == "semantic_fallback_endpoint_missing"
    assert not target.exists()


def test_remove_and_primary_writers_round_trip_on_disk(tmp_path: Path) -> None:
    target = _codex_only(tmp_path / "config.toml")
    apply_provider_endpoint_choice("fireworks", model=_MODEL, path=target, as_fallback=True)

    swapped_path, swapped = set_semantic_fallback_primary("api_provider", path=target)
    assert swapped_path == target
    assert swapped == _loaded(target)
    assert swapped.profile == "local-openai"
    assert swapped.semantic_fallback == SemanticFallbackConfig(primary="api_provider")
    assert swapped.provider is not None and swapped.external_runtime is not None

    removed_path, removed = remove_semantic_fallback(path=target)
    assert removed_path == target
    assert removed == _loaded(target)
    assert removed.semantic_fallback is None
    assert removed.external_runtime is None
    assert removed.provider is not None
    assert removed.profile == "local-openai"

    with pytest.raises(ConfigError) as caught:
        remove_semantic_fallback(path=target)
    assert caught.value.reason_code == "semantic_fallback_endpoint_missing"
    with pytest.raises(ConfigError) as caught:
        set_semantic_fallback_primary("codex_subscription", path=target)
    assert caught.value.reason_code == "semantic_fallback_endpoint_missing"


def _paired_config() -> FinishUpConfig:
    from finishup.config.write import fireworks_provider

    return FinishUpConfig(
        profile="local-openai",
        provider=fireworks_provider(model=_MODEL),
        external_runtime=_runtime(),
        semantic_fallback=SemanticFallbackConfig(primary="api_provider"),
    )


def test_cli_fallback_remove_reports_the_remaining_primary(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: list[object] = []

    def fake_remove(*, path: Path | None = None) -> tuple[Path, FinishUpConfig]:
        calls.append(path)
        return tmp_path / "config.toml", FinishUpConfig(
            profile="local-openai", provider=_paired_config().provider
        )

    monkeypatch.setattr(provider_binding, "remove_semantic_fallback", fake_remove)
    result = CliRunner().invoke(app, ["provider", "fallback", "remove", "--json"])

    assert result.exit_code == 0, result.output
    assert calls == [None]
    payload = json.loads(result.stdout)
    assert payload["primary"] is None
    assert payload["fallback_endpoint"] is None
    assert payload["primary_endpoint"]["provider_id"] == "fireworks"
    assert payload["config_path"] == str(tmp_path / "config.toml")
    assert "finishup privacy setup" in result.stderr


def test_cli_fallback_primary_reports_both_endpoints_in_role_order(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    chosen: list[str] = []

    def fake_primary(
        primary: Literal["api_provider", "codex_subscription"], *, path: Path | None = None
    ) -> tuple[Path, FinishUpConfig]:
        chosen.append(primary)
        config = _paired_config().model_copy(
            update={
                "profile": "codex-subscription",
                "semantic_fallback": SemanticFallbackConfig(primary="codex_subscription"),
            }
        )
        return tmp_path / "config.toml", config

    monkeypatch.setattr(provider_binding, "set_semantic_fallback_primary", fake_primary)
    result = CliRunner().invoke(
        app, ["provider", "fallback", "primary", "codex_subscription", "--json"]
    )

    assert result.exit_code == 0, result.output
    assert chosen == ["codex_subscription"]
    payload = json.loads(result.stdout)
    assert payload["primary"] == "codex_subscription"
    assert payload["profile"] == "codex-subscription"
    assert payload["primary_endpoint"]["provider_id"] == "openai-codex"
    assert payload["fallback_endpoint"]["provider_id"] == "fireworks"
    assert set(payload["fallback_endpoint"]) == {
        "provider_id",
        "model",
        "endpoint_profile_id",
        "endpoint_profile_version",
    }


def test_cli_fallback_primary_rejects_an_unknown_selector_before_any_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def explode(*_args: object, **_kwargs: object) -> tuple[Path, FinishUpConfig]:
        raise AssertionError("write_not_expected")

    monkeypatch.setattr(provider_binding, "set_semantic_fallback_primary", explode)
    result = CliRunner().invoke(app, ["provider", "fallback", "primary", "local_model"])

    assert result.exit_code == 2
    assert "invalid_request" in result.stderr


def test_cli_fallback_commands_surface_a_config_error_as_invalid_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def refuse(*_args: object, **_kwargs: object) -> tuple[Path, FinishUpConfig]:
        raise ConfigError("semantic_fallback_endpoint_missing")

    monkeypatch.setattr(provider_binding, "remove_semantic_fallback", refuse)
    monkeypatch.setattr(provider_binding, "set_semantic_fallback_primary", refuse)

    removed = CliRunner().invoke(app, ["provider", "fallback", "remove"])
    swapped = CliRunner().invoke(app, ["provider", "fallback", "primary", "api_provider"])

    assert removed.exit_code == 2
    assert "invalid_request: semantic_fallback_endpoint_missing" in removed.stderr
    assert swapped.exit_code == 2
    assert "invalid_request: semantic_fallback_endpoint_missing" in swapped.stderr


def test_the_fallback_answer_flows_into_the_llm_channel(monkeypatch: pytest.MonkeyPatch) -> None:
    candidate = build_candidate_policy(
        local_only_policy(),
        _answers(fallback_provider=_codex_binding()),
        now=datetime(2026, 7, 29, tzinfo=UTC),
    )
    llm = next(
        channel
        for channel in candidate.channel_policies
        if channel.channel is EgressChannel.LLM_INFERENCE
    )
    assert llm.fallback_provider_binding == _codex_binding()
    assert llm.provider_binding is not None
    assert llm.authorized_provider_bindings == (llm.provider_binding, _codex_binding())

    plain = build_candidate_policy(
        local_only_policy(), _answers(), now=datetime(2026, 7, 29, tzinfo=UTC)
    )
    assert (
        next(
            channel
            for channel in plain.channel_policies
            if channel.channel is EgressChannel.LLM_INFERENCE
        ).fallback_provider_binding
        is None
    )


def test_configured_fallback_binding_reads_the_pairing_and_nothing_else(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _load_paired(*_args: object, **_kwargs: object) -> FinishUpConfig:
        return _paired_config()

    monkeypatch.setattr(config_load, "load_config", _load_paired)
    assert privacy_setup.configured_fallback_binding() == _codex_binding()
    external, local = privacy_setup.configured_bindings()
    assert local is None
    assert external is not None and external.provider_id == "fireworks"

    def _load_codex_only(*_args: object, **_kwargs: object) -> FinishUpConfig:
        return FinishUpConfig(profile="codex-subscription", external_runtime=_runtime())

    monkeypatch.setattr(config_load, "load_config", _load_codex_only)
    assert privacy_setup.configured_fallback_binding() is None
    assert privacy_setup.configured_bindings()[0] == _codex_binding()


def test_named_recipes_carry_the_configured_fallback_only_when_network_is_on(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(privacy_setup, "_configured_fallback_binding", _codex_binding)
    external = _answers().external_provider

    for recipe in ("metadata_only", "assisted_review", "expanded_review"):
        answers = privacy_setup._recipe_answers(  # pyright: ignore[reportPrivateUsage]
            recipe, local_only_policy(), external, _codex_binding()
        )
        assert answers.network_egress is True
        assert answers.fallback_provider == _codex_binding()

    private = privacy_setup._recipe_answers(  # pyright: ignore[reportPrivateUsage]
        "private", local_only_policy(), None
    )
    assert private.network_egress is False
    assert private.fallback_provider is None


@pytest.mark.parametrize("approve", [False, True])
def test_custom_setup_requires_explicit_fallback_consent(
    monkeypatch: pytest.MonkeyPatch, approve: bool
) -> None:
    prompts: list[str] = []

    def confirm(prompt: str, *, default: bool = False) -> bool:
        prompts.append(prompt)
        if prompt.startswith("Authorize fallback"):
            assert default is False
            return approve
        return prompt.startswith(("Permit network", "Bind external"))

    monkeypatch.setattr(privacy_setup.typer, "confirm", confirm)

    def prompt(_label: str, *, default: str = "") -> str:
        return default

    monkeypatch.setattr(privacy_setup.typer, "prompt", prompt)
    answers = privacy_setup._ask_custom_answers(  # pyright: ignore[reportPrivateUsage]
        local_only_policy(), _answers().external_provider, None, _codex_binding()
    )
    assert answers.fallback_provider == (_codex_binding() if approve else None)
    assert any("openai-codex/gpt-5.6-sol" in prompt for prompt in prompts)


def test_recipe_construction_does_not_load_live_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden() -> None:
        raise AssertionError("pure recipe construction read live configuration")

    monkeypatch.setattr(privacy_setup, "_configured_fallback_binding", forbidden)
    answers = privacy_setup._recipe_answers(  # pyright: ignore[reportPrivateUsage]
        "assisted_review", local_only_policy(), _answers().external_provider
    )
    assert answers.fallback_provider is None
