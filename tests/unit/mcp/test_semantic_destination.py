"""Issue #479: the policy-route initialize instructions name the AI-powered review destination.

Every rendered value must be a closed catalog token, a ``Literal`` configuration field, or an
already-validated hostname; absent or invalid configuration must stay unknown; a fallback must be
disclosed beside the primary; strict instructions must stay byte-identical; and the passage must
fit the reviewed instructions budgets at its longest possible shape.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest

from yoetz.adapters.providers.factory import (
    CHAT_COMPLETIONS_ENDPOINT_PROFILES,
    RESPONSES_ENDPOINT_PROFILE_IDS,
    chat_completions_profile_from_provider_config,
)
from yoetz.adapters.providers.openai_responses_factory import openai_profile_from_provider_config
from yoetz.config.models import (
    CODEX_SUBSCRIPTION_PROVIDER_ID,
    OWNER_DECLARED_ENDPOINT_PROFILE_ID,
    OWNER_DECLARED_PROVIDER_ID,
    ExternalRuntimeProfileConfig,
    LocalModelProfileConfig,
    OwnerDeclaredEndpointConfig,
    ProviderProfileConfig,
    SemanticFallbackConfig,
    VerificationConfig,
    YoetzConfig,
)
from yoetz.config.write import PROVIDER_PRESETS, codex_subscription_runtime, fireworks_provider
from yoetz.mcp import server as bridge
from yoetz.mcp.descriptors import (
    ADVERTISED_SURFACE_BUDGET,
    SERVER_INSTRUCTIONS_BUDGET,
    advertised_surface_metrics,
    server_instructions,
)
from yoetz.mcp.semantic_destination import (
    BUNDLED_ENDPOINT_HOSTS,
    DISCLOSABLE_PROVIDER_IDS,
    DISCLOSURE_PREFIX,
    MAX_DISCLOSURE_ENCODED_BYTES,
    SemanticDestinationDisclosure,
    disclose_semantic_destination,
    read_semantic_destination_disclosure,
)

_DIGEST = "sha256:" + "a" * 64
# Mirrors the descriptor honesty lint in ``mcp/descriptors.py``: the passage may not claim
# verification, proof, enforcement, or observation.
_FORBIDDEN_CLAIMS = re.compile(
    r"\b(?:authenticated|enforces?|gates?|observes?|proved|proves?|verified)\b",
    re.IGNORECASE | re.ASCII,
)
_NOW = datetime(2026, 9, 6, tzinfo=UTC)
_EXECUTABLE = "/Applications/Codex.app/Contents/Resources/codex"
_CODEX_HOME = "/opt/Yoetz Tools/codex-home"
# 63 + 1 + 63 + 1 + 63 + 1 + 61 = 253, the longest hostname the origin validator admits.
_LONGEST_HOST = ".".join(("a" * 63, "b" * 63, "c" * 63, "d" * 61))


def _provider(
    endpoint_profile_id: str,
    *,
    provider_id: str = "openai",
    https_origin: str | None = None,
) -> ProviderProfileConfig:
    return ProviderProfileConfig(
        provider_id=provider_id,
        endpoint_profile_id=endpoint_profile_id,
        endpoint_profile_version="1.0.0",
        model="reviewer-model",
        capability_profile="reviewed-capability/1.0.0",
        owner_declared_endpoint=(
            None if https_origin is None else OwnerDeclaredEndpointConfig(https_origin=https_origin)
        ),
    )


def _runtime() -> ExternalRuntimeProfileConfig:
    return codex_subscription_runtime(
        executable_path=_EXECUTABLE,
        executable_sha256=_DIGEST,
        runtime_version="0.150.1",
        source_identity="openai-codex-npm-darwin-arm64-0.150.1",
        app_server_schema_sha256=_DIGEST,
        capability_cell_sha256=_DIGEST,
        isolated_config_sha256=_DIGEST,
        capability_profile="codex-evaluator/0.150.1/v1",
        capability_evidence_expires_at="2026-11-30T00:00:00Z",
        codex_home=_CODEX_HOME,
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


def _assert_honest(disclosure: SemanticDestinationDisclosure) -> None:
    assert disclosure.sentence.startswith(DISCLOSURE_PREFIX)
    assert _FORBIDDEN_CLAIMS.search(disclosure.sentence) is None
    assert "https://" not in disclosure.sentence
    assert "/" not in disclosure.sentence.replace("read once at", "")
    assert len(disclosure.sentence.encode("utf-8")) <= MAX_DISCLOSURE_ENCODED_BYTES


def test_bundled_host_catalog_matches_the_adapters_that_dial_them() -> None:
    """The disclosure may only ever name a host the dispatch path actually uses."""

    chat_ids = set(CHAT_COMPLETIONS_ENDPOINT_PROFILES)
    responses_ids = set(RESPONSES_ENDPOINT_PROFILE_IDS) - {OWNER_DECLARED_ENDPOINT_PROFILE_ID}
    assert set(BUNDLED_ENDPOINT_HOSTS) == chat_ids | responses_ids
    for endpoint_profile_id, host in BUNDLED_ENDPOINT_HOSTS.items():
        provider = _provider(endpoint_profile_id)
        if endpoint_profile_id in chat_ids:
            actual = chat_completions_profile_from_provider_config(provider, now=_NOW).host
        else:
            actual = openai_profile_from_provider_config(provider, now=_NOW).host
        assert actual == host, endpoint_profile_id


def test_disclosable_provider_ids_cover_every_bundled_binding() -> None:
    preset_ids = {preset.provider_id for preset in PROVIDER_PRESETS.values()}
    expected = preset_ids | {OWNER_DECLARED_PROVIDER_ID, CODEX_SUBSCRIPTION_PROVIDER_ID}
    assert DISCLOSABLE_PROVIDER_IDS == frozenset(expected)


def test_api_provider_names_provider_endpoint_profile_and_catalog_host() -> None:
    config = YoetzConfig(
        profile="local-openai", provider=fireworks_provider(model="accounts/fireworks/models/m")
    )
    disclosure = disclose_semantic_destination(config)
    _assert_honest(disclosure)
    assert disclosure.kind == "external"
    assert (
        "provider fireworks (endpoint profile fireworks-responses, host api.fireworks.ai) over "
        "HTTPS with the owner's vault-held API credential."
    ) in disclosure.sentence
    assert "review packet composed from this ledger" in disclosure.sentence
    assert "no repository handle" in disclosure.sentence
    assert "Fallback" not in disclosure.sentence


def test_owner_declared_endpoint_renders_only_the_validated_host_and_port() -> None:
    provider = _provider(
        OWNER_DECLARED_ENDPOINT_PROFILE_ID,
        provider_id=OWNER_DECLARED_PROVIDER_ID,
        https_origin="https://LLM.Example.internal:8443/",
    )
    disclosure = disclose_semantic_destination(
        YoetzConfig(profile="local-openai", provider=provider)
    )
    _assert_honest(disclosure)
    assert "owner-declared host llm.example.internal:8443)" in disclosure.sentence
    default_port = _provider(
        OWNER_DECLARED_ENDPOINT_PROFILE_ID,
        provider_id=OWNER_DECLARED_PROVIDER_ID,
        https_origin="https://llm.example.internal",
    )
    sentence = disclose_semantic_destination(
        YoetzConfig(profile="local-openai", provider=default_port)
    ).sentence
    assert "owner-declared host llm.example.internal)" in sentence
    assert ":443" not in sentence


def test_codex_runtime_names_the_runtime_class_and_no_path() -> None:
    config = YoetzConfig(profile="codex-subscription", external_runtime=_runtime())
    disclosure = disclose_semantic_destination(config)
    _assert_honest(disclosure)
    assert disclosure.kind == "external"
    assert (
        "provider openai-codex (endpoint profile codex-chatgpt-subscription) through the locally "
        "installed Codex runtime under its own ChatGPT login"
    ) in disclosure.sentence
    assert "Yoetz does not name" in disclosure.sentence
    assert _EXECUTABLE not in disclosure.sentence
    assert _CODEX_HOME not in disclosure.sentence
    assert "gpt-5.6-sol" not in disclosure.sentence


@pytest.mark.parametrize("primary", ["api_provider", "codex_subscription"])
def test_fallback_endpoint_is_disclosed_beside_the_primary(primary: str) -> None:
    config = YoetzConfig(
        profile="codex-subscription" if primary == "codex_subscription" else "local-openai",
        provider=fireworks_provider(model="accounts/fireworks/models/m"),
        external_runtime=_runtime(),
        semantic_fallback=SemanticFallbackConfig(
            primary=cast(Any, primary),
        ),
    )
    disclosure = disclose_semantic_destination(config)
    _assert_honest(disclosure)
    first, _, rest = disclosure.sentence.partition(" Fallback after primary failure: ")
    assert rest, disclosure.sentence
    if primary == "api_provider":
        assert "host api.fireworks.ai" in first
        assert "Codex runtime" in rest
    else:
        assert "Codex runtime" in first
        assert "host api.fireworks.ai" in rest


@pytest.mark.parametrize(
    ("config", "reason"),
    [
        (YoetzConfig(), "no external endpoint is bound under the strict-local profile"),
        (YoetzConfig(profile="test-fake"), "no external endpoint is bound under the test-fake"),
        (
            YoetzConfig(local_model=_local_model()),
            "only a local model daemon on this machine is bound",
        ),
        (
            YoetzConfig(
                profile="codex-subscription",
                external_runtime=_runtime(),
                verification=VerificationConfig(semantic="disabled"),
            ),
            "verification.semantic is disabled",
        ),
    ],
)
def test_no_external_destination_is_stated_with_its_reason(
    config: YoetzConfig, reason: str
) -> None:
    disclosure = disclose_semantic_destination(config)
    _assert_honest(disclosure)
    assert disclosure.kind == "none"
    assert reason in disclosure.sentence
    assert "snapshot may differ from the live service" in disclosure.sentence
    assert "cannot reach" not in disclosure.sentence
    assert "Fallback" not in disclosure.sentence
    assert "Codex" not in disclosure.sentence


def test_missing_configuration_stays_unknown() -> None:
    disclosure = disclose_semantic_destination(None)
    _assert_honest(disclosure)
    assert disclosure.kind == "unknown"
    assert "absent or invalid" in disclosure.sentence
    assert "may reach an external reviewer" in disclosure.sentence
    assert "only the local ledger" not in disclosure.sentence


def test_read_from_environment_renders_unknown_for_invalid_and_external_for_valid(
    tmp_path: Path,
) -> None:
    invalid = tmp_path / "invalid.toml"
    invalid.write_text('schema_version = "1"\nprofile = "not-a-profile"\n', encoding="utf-8")
    assert read_semantic_destination_disclosure({"YOETZ_CONFIG": str(invalid)}).kind == "unknown"
    absent = tmp_path / "absent.toml"
    assert read_semantic_destination_disclosure({"YOETZ_CONFIG": str(absent)}).kind == "unknown"
    valid = tmp_path / "valid.toml"
    valid.write_text(
        "\n".join(
            (
                'schema_version = "1"',
                'profile = "local-openai"',
                "[provider]",
                'provider_id = "fireworks"',
                'endpoint_profile_id = "fireworks-responses"',
                'endpoint_profile_version = "1.0.0"',
                'model = "accounts/fireworks/models/m"',
                'capability_profile = "fireworks-responses/1.0.0"',
                "",
            )
        ),
        encoding="utf-8",
    )
    disclosure = read_semantic_destination_disclosure({"YOETZ_CONFIG": str(valid)})
    assert disclosure.kind == "external"
    assert "host api.fireworks.ai" in disclosure.sentence
    assert str(tmp_path) not in disclosure.sentence


def test_a_disclosure_that_cannot_render_within_its_bound_reads_unknown_not_a_bridge_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """tb4n3 A10: rendering sat outside the guard, so a sentence over its bound (a wording change
    plus a long declared host) would have kept the bridge from starting instead of reading unknown."""

    valid = tmp_path / "valid.toml"
    valid.write_text(
        'schema_version = "1"\nprofile = "local-openai"\n[provider]\n'
        'provider_id = "fireworks"\nendpoint_profile_id = "fireworks-responses"\n'
        'endpoint_profile_version = "1.0.0"\nmodel = "accounts/fireworks/models/m"\n'
        'capability_profile = "fireworks-responses/1.0.0"\n',
        encoding="utf-8",
    )
    real = disclose_semantic_destination
    calls: list[object] = []

    def refuse_a_real_config(config: object) -> SemanticDestinationDisclosure:
        calls.append(config)
        if config is not None:
            raise ValueError("semantic_destination_sentence_too_long")
        return real(None)

    monkeypatch.setattr(
        "yoetz.mcp.semantic_destination.disclose_semantic_destination", refuse_a_real_config
    )
    disclosure = read_semantic_destination_disclosure({"YOETZ_CONFIG": str(valid)})
    assert disclosure.kind == "unknown"
    assert len(calls) == 2 and calls[-1] is None


def test_hostile_identifiers_never_reach_the_text() -> None:
    hostile_provider = "x/../../etc/passwd"
    disclosure = disclose_semantic_destination(
        YoetzConfig(
            profile="local-openai",
            provider=_provider("openai-responses", provider_id=hostile_provider),
        )
    )
    _assert_honest(disclosure)
    assert hostile_provider not in disclosure.sentence
    assert "an unlisted provider id (endpoint profile openai-responses, host api.openai.com)" in (
        disclosure.sentence
    )
    off_catalog = disclose_semantic_destination(
        YoetzConfig(
            profile="local-openai",
            provider=_provider("proxy.example.com:8443/v1", provider_id="openai"),
        )
    )
    _assert_honest(off_catalog)
    assert "proxy.example.com" not in off_catalog.sentence
    assert "outside the bundled catalog, so the destination host is unknown" in (
        off_catalog.sentence
    )


def test_disclosure_is_typed_and_bounded() -> None:
    with pytest.raises(ValueError, match="semantic_destination_kind_invalid"):
        SemanticDestinationDisclosure(cast(Any, "external-ish"), DISCLOSURE_PREFIX + "x")
    with pytest.raises(ValueError, match="semantic_destination_sentence_invalid"):
        SemanticDestinationDisclosure("external", "provider openai")
    with pytest.raises(ValueError, match="semantic_destination_sentence_too_long"):
        SemanticDestinationDisclosure(
            "external", DISCLOSURE_PREFIX + "x" * MAX_DISCLOSURE_ENCODED_BYTES
        )
    with pytest.raises(TypeError, match="config_wrong_type"):
        disclose_semantic_destination(cast(Any, {"profile": "local-openai"}))
    with pytest.raises(TypeError, match="semantic_destination_wrong_type"):
        server_instructions("policy", semantic_destination=cast(Any, "provider openai"))


def _longest_disclosure() -> SemanticDestinationDisclosure:
    provider = _provider(
        OWNER_DECLARED_ENDPOINT_PROFILE_ID,
        provider_id=OWNER_DECLARED_PROVIDER_ID,
        https_origin=f"https://{_LONGEST_HOST}:65535",
    )
    return disclose_semantic_destination(
        YoetzConfig(
            profile="local-openai",
            provider=provider,
            external_runtime=_runtime(),
            semantic_fallback=SemanticFallbackConfig(primary="api_provider"),
        )
    )


def test_longest_disclosure_fits_the_reviewed_instructions_budgets() -> None:
    longest = _longest_disclosure()
    assert f"owner-declared host {_LONGEST_HOST}:65535" in longest.sentence
    assert "Fallback after primary failure" in longest.sentence
    assert len(longest.sentence.encode("utf-8")) <= MAX_DISCLOSURE_ENCODED_BYTES
    packaged = advertised_surface_metrics("policy")
    assert (
        packaged["instructions_encoded_bytes"]
        <= (SERVER_INSTRUCTIONS_BUDGET["packaged_max_encoded_bytes"])
    )
    assert (
        packaged["replicated_encoded_bytes"]
        <= (ADVERTISED_SURFACE_BUDGET["packaged_max_encoded_bytes"])
    )
    metrics = advertised_surface_metrics("policy", semantic_destination=longest)
    assert metrics["instructions_encoded_bytes"] <= SERVER_INSTRUCTIONS_BUDGET["max_encoded_bytes"]
    assert metrics["replicated_encoded_bytes"] <= ADVERTISED_SURFACE_BUDGET["max_encoded_bytes"]
    assert SERVER_INSTRUCTIONS_BUDGET["max_encoded_bytes"] == (
        SERVER_INSTRUCTIONS_BUDGET["packaged_max_encoded_bytes"] + MAX_DISCLOSURE_ENCODED_BYTES
    )
    # The aggregate allowance is charged once per advertised descriptor, read_guidance included,
    # which is exactly what advertised_surface_metrics replicates.
    assert ADVERTISED_SURFACE_BUDGET["max_encoded_bytes"] == (
        ADVERTISED_SURFACE_BUDGET["packaged_max_encoded_bytes"]
        + packaged["tool_count"] * MAX_DISCLOSURE_ENCODED_BYTES
    )
    joiner = 1  # the single space that joins the disclosure to the policy tail
    assert metrics["replicated_encoded_bytes"] - packaged["replicated_encoded_bytes"] == (
        packaged["tool_count"] * (len(longest.sentence.encode("utf-8")) + joiner)
    )


def test_policy_instructions_append_the_disclosure_and_strict_ignores_it() -> None:
    disclosure = disclose_semantic_destination(
        YoetzConfig(profile="codex-subscription", external_runtime=_runtime())
    )
    policy = server_instructions("policy", semantic_destination=disclosure)
    assert policy == server_instructions("policy").rstrip("\n") + " " + disclosure.sentence + "\n"
    assert "Route profile: policy. External AI-powered review follows the configured policy. " in (
        policy
    )
    strict = server_instructions("strict")
    assert server_instructions("strict", semantic_destination=disclosure) == strict
    assert DISCLOSURE_PREFIX not in strict
    assert "This route will not request external AI-powered review" in strict


def test_bridge_runtime_carries_the_disclosure_on_the_policy_route_only() -> None:
    disclosure = disclose_semantic_destination(None)
    policy = bridge.build_bridge_runtime("policy", semantic_destination=disclosure)
    assert policy.instructions.endswith(" " + disclosure.sentence + "\n")
    strict = bridge.build_bridge_runtime("strict", semantic_destination=disclosure)
    assert strict.instructions == server_instructions("strict")
    # Without an injected disclosure the policy bridge reads configuration once at startup and
    # always renders one of the three closed shapes; it never serves the bare pre-#479 tail.
    default = bridge.build_bridge_runtime("policy")
    assert DISCLOSURE_PREFIX in default.instructions
    assert bridge.BRIDGE_RUNTIME.instructions == default.instructions
    with pytest.raises(TypeError, match="semantic_destination_wrong_type"):
        bridge.build_bridge_runtime("policy", semantic_destination=cast(Any, "provider openai"))


@pytest.mark.parametrize("contents", [None, "invalid = [", 'profile = "not-a-profile"'])
def test_failed_config_read_never_promises_local_only(tmp_path: Path, contents: str | None) -> None:
    config = tmp_path / "selected.toml"
    if contents is not None:
        config.write_text(contents, encoding="utf-8")
    disclosure = read_semantic_destination_disclosure({"YOETZ_CONFIG": str(config)})
    assert disclosure.kind == "unknown"
    assert "may reach an external reviewer" in disclosure.sentence
    assert "only the local ledger" not in disclosure.sentence
    assert "cannot reach" not in disclosure.sentence
    assert str(config) not in disclosure.sentence
