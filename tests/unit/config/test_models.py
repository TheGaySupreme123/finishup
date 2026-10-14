from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest
from pydantic import ValidationError

from finishup.config.models import (
    PROFILE_CAPABILITIES,
    ConfigError,
    ExternalRuntimeProfileConfig,
    FinishUpConfig,
    LineageSettings,
    LocalModelProfileConfig,
    LoggingConfig,
    NetworkPolicy,
    ObservationConfig,
    ProviderProfileConfig,
    SemanticPolicy,
    StorageConfig,
    VerificationConfig,
)
from finishup.config.privacy import (
    PrivacyBootstrapConfig,
    safe_privacy_bootstrap,
    seed_policy_if_absent,
)
from finishup.domain.privacy import (
    AuthorizationScope,
    AuthorizationScopeKind,
    ChannelPolicy,
    DataClass,
    EgressChannel,
    PrivacyPolicy,
    PrivacyProfile,
    ReviewContextProfile,
    ReviewSelectionPolicy,
)
from finishup.ports.privacy import PrivacyPolicyStorePort
from finishup.protocol.models import DataCategory

_DIGEST = "sha256:" + "1" * 64
_POLICY_ID = "pvy_88888888-8888-4888-8888-888888888888"
_INSTALLATION_ID = "ins_08000000-0000-4000-8000-000000000001"
_NOW = datetime(2026, 3, 8, tzinfo=UTC)


def _provider() -> ProviderProfileConfig:
    return ProviderProfileConfig(
        provider_id="openai",
        endpoint_profile_id="openai-responses",
        endpoint_profile_version="1.0.0",
        model="gpt-5.4",
        capability_profile="openai-responses/gpt-5.4/1",
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


def _external_runtime() -> ExternalRuntimeProfileConfig:
    return ExternalRuntimeProfileConfig(
        provider_id="openai-codex",
        endpoint_profile_id="codex-chatgpt-subscription",
        endpoint_profile_version="1.0.0",
        credential_authority="external_runtime_oauth",
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


def _denied_policy() -> PrivacyPolicy:
    channel_policies = tuple(
        ChannelPolicy(
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
        for channel in sorted(EgressChannel, key=lambda item: item.value)
    )
    return PrivacyPolicy(
        policy_id=_POLICY_ID,
        version=1,
        policy_digest=_DIGEST,
        profile=PrivacyProfile.LOCAL_ONLY,
        review_context_profile=ReviewContextProfile.STRUCTURAL,
        review_selection=ReviewSelectionPolicy.for_profile(ReviewContextProfile.STRUCTURAL),
        require_current_provider_data_use_evidence=False,
        network_egress_permitted=False,
        effective_scope=AuthorizationScope(AuthorizationScopeKind.MACHINE, _INSTALLATION_ID),
        channel_policies=channel_policies,
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


class _AtomicSeedStore:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self.existing: PrivacyPolicy | None = None

    async def seed_if_absent(self, policy: PrivacyPolicy) -> PrivacyPolicy:
        async with self._lock:
            if self.existing is None:
                self.existing = policy
            elif self.existing != policy:
                raise RuntimeError("privacy_seed_conflict")
            return self.existing


def test_defaults_are_frozen_and_all_disclosure_is_denied() -> None:
    config = FinishUpConfig()
    assert config.schema_version == "1"
    assert config.profile == "strict-local"
    assert config.storage == StorageConfig(data_dir=None, durability="full")
    assert config.verification == VerificationConfig(semantic="required", max_findings=10)
    assert config.observation == ObservationConfig(enabled=True)
    assert config.lineage == LineageSettings()
    assert config.logging == LoggingConfig(level="info", payloads=False)
    assert config.privacy == safe_privacy_bootstrap()
    assert not config.privacy.network_egress_permitted
    assert not any(config.privacy.channel_policies.model_dump().values())
    with pytest.raises(ValidationError):
        config.profile = "test-fake"  # type: ignore[misc]


def test_lineage_fanout_matches_child_manifest_capacity() -> None:
    assert LineageSettings(max_fanout=64).max_fanout == 64
    with pytest.raises(ConfigError, match="config_value_invalid"):
        LineageSettings(max_fanout=65)


def test_profile_capability_matrix_is_closed() -> None:
    assert PROFILE_CAPABILITIES["strict-local"].network is NetworkPolicy.DENIED
    assert PROFILE_CAPABILITIES["strict-local"].semantic is SemanticPolicy.OPTIONAL_LOCAL_MODEL
    assert PROFILE_CAPABILITIES["local-openai"].network is NetworkPolicy.CANDIDATE_EXTERNAL
    assert PROFILE_CAPABILITIES["codex-subscription"].network is NetworkPolicy.CANDIDATE_EXTERNAL
    assert PROFILE_CAPABILITIES["test-fake"].semantic is SemanticPolicy.SCRIPTED_FAKE
    assert PROFILE_CAPABILITIES["release-probe"].network is NetworkPolicy.EXPLICIT_PER_PROBE


@pytest.mark.parametrize(
    ("factory", "reason"),
    [
        (
            lambda: FinishUpConfig(schema_version="2"),  # type: ignore[arg-type]
            "config_schema_unsupported",
        ),
        (
            lambda: StorageConfig(durability="normal"),  # type: ignore[arg-type]
            "durability_unsupported",
        ),
        (lambda: VerificationConfig(max_findings=0), "max_findings_out_of_range"),
        (lambda: VerificationConfig(max_findings=11), "max_findings_out_of_range"),
        (lambda: VerificationConfig(finding_attempt_budget=0), "config_value_invalid"),
        (lambda: VerificationConfig(finding_attempt_budget=51), "config_value_invalid"),
        (lambda: LineageSettings(max_depth=-1), "config_value_invalid"),
        (lambda: LineageSettings(max_fanout=65), "config_value_invalid"),
        (
            lambda: ObservationConfig.model_validate(
                {"enabled": True, "interval_seconds": 60}, strict=True
            ),
            "unknown_config_key",
        ),
        (lambda: LoggingConfig(payloads=True), "payload_logging_forbidden"),
        (
            lambda: FinishUpConfig(profile="strict-local", provider=_provider()),
            "strict_local_forbids_provider",
        ),
        (
            lambda: FinishUpConfig(profile="local-openai", local_model=_local_model()),
            "external_profile_forbids_local_model",
        ),
        (
            lambda: FinishUpConfig(profile="test-fake", provider=_provider()),
            "test_fake_forbids_provider",
        ),
        (
            lambda: FinishUpConfig(profile="test-fake", local_model=_local_model()),
            "test_fake_forbids_local_model",
        ),
        (
            lambda: FinishUpConfig(profile="local-openai"),
            "provider_required_for_semantic",
        ),
        (
            lambda: FinishUpConfig(profile="codex-subscription"),
            "external_runtime_required_for_semantic",
        ),
        (
            lambda: FinishUpConfig(
                profile="codex-subscription",
                provider=_provider(),
                external_runtime=_external_runtime(),
            ),
            "external_runtime_forbids_provider",
        ),
    ],
)
def test_reason_coded_validation(factory: object, reason: str) -> None:
    callable_factory = factory
    assert callable(callable_factory)
    with pytest.raises(ConfigError) as caught:
        callable_factory()
    assert caught.value.reason_code == reason


def test_profiles_accept_only_their_exact_structural_sink() -> None:
    assert (
        FinishUpConfig(profile="strict-local", local_model=_local_model()).local_model is not None
    )
    assert FinishUpConfig(profile="local-openai", provider=_provider()).provider is not None
    runtime = FinishUpConfig(
        profile="codex-subscription", external_runtime=_external_runtime()
    ).external_runtime
    assert runtime is not None
    assert runtime.credential_authority == "external_runtime_oauth"
    assert (
        FinishUpConfig(
            profile="local-openai",
            verification=VerificationConfig(semantic="disabled"),
        ).provider
        is None
    )


def test_unknown_secret_and_local_locator_keys_fail_before_values_escape() -> None:
    with pytest.raises(ConfigError) as unknown:
        FinishUpConfig.model_validate({"unreviewed": "content"}, strict=True)
    assert unknown.value.reason_code == "unknown_config_key"
    assert str(unknown.value) == "unknown_config_key"

    with pytest.raises(ConfigError) as secret:
        ProviderProfileConfig.model_validate(
            {
                "provider_id": "openai",
                "endpoint_profile_id": "responses",
                "endpoint_profile_version": "1",
                "model": "gpt",
                "capability_profile": "profile",
                "api_key": "must-not-appear",
            },
            strict=True,
        )
    assert secret.value.reason_code == "secret_in_config"
    assert secret.value.safe_name == "api_key"
    assert "must-not-appear" not in repr(secret.value)

    runtime = _external_runtime().model_dump()
    runtime["oauth_token"] = "must-not-appear"
    with pytest.raises(ConfigError) as runtime_secret:
        ExternalRuntimeProfileConfig.model_validate(runtime, strict=True)
    assert runtime_secret.value.reason_code == "secret_in_config"
    assert "must-not-appear" not in repr(runtime_secret.value)

    local = _local_model().model_dump()
    local["socket_path"] = "/private/content.sock"
    with pytest.raises(ConfigError) as locator:
        LocalModelProfileConfig.model_validate(local, strict=True)
    assert locator.value.reason_code == "local_model_locator_forbidden"


def test_direct_strict_models_do_not_coerce_string_scalars() -> None:
    with pytest.raises(ConfigError):
        VerificationConfig(max_findings="3")  # type: ignore[arg-type]
    with pytest.raises(ConfigError):
        StorageConfig(data_dir="/tmp/not-a-path-object")  # type: ignore[arg-type]
    with pytest.raises(ConfigError):
        ObservationConfig(enabled="false")  # type: ignore[arg-type]
    assert StorageConfig(data_dir=Path("/safe")).data_dir == Path("/safe")


def test_privacy_bootstrap_accepts_only_the_complete_safe_seed() -> None:
    safe = safe_privacy_bootstrap().model_dump(mode="json")
    assert PrivacyBootstrapConfig.model_validate(safe, strict=True) == safe_privacy_bootstrap()

    enabled = safe.copy()
    enabled["network_egress_permitted"] = True
    with pytest.raises(ConfigError) as permissive:
        PrivacyBootstrapConfig.model_validate(enabled, strict=True)
    assert permissive.value.reason_code == "privacy_bootstrap_unsafe"

    incomplete = safe.copy()
    channels = dict(incomplete["channel_policies"])
    del channels["update_checks"]
    incomplete["channel_policies"] = channels
    with pytest.raises(ConfigError) as missing:
        PrivacyBootstrapConfig.model_validate(incomplete, strict=True)
    assert missing.value.reason_code == "privacy_bootstrap_unsafe"


def test_privacy_seed_delegate_is_atomic_idempotent_and_never_overwrites() -> None:
    policy = _denied_policy()
    store = _AtomicSeedStore()

    async def exercise() -> None:
        port = cast(PrivacyPolicyStorePort, store)
        first, second = await asyncio.gather(
            seed_policy_if_absent(policy, port),
            seed_policy_if_absent(policy, port),
        )
        assert first is policy
        assert second is policy

        conflict = replace(policy, policy_digest="sha256:" + "2" * 64)
        with pytest.raises(RuntimeError, match="privacy_seed_conflict"):
            await seed_policy_if_absent(conflict, port)
        assert store.existing is policy

    asyncio.run(exercise())


def test_codex_review_budget_default_and_explicit_limits() -> None:
    runtime = _external_runtime()
    assert runtime.timeout_seconds == 900
    for seconds in (1, 120, 900, 3600):
        values = runtime.model_dump()
        values["timeout_seconds"] = seconds
        assert ExternalRuntimeProfileConfig.model_validate(values).timeout_seconds == seconds
    for seconds in (0, 3601):
        values = runtime.model_dump()
        values["timeout_seconds"] = seconds
        with pytest.raises(ConfigError):
            ExternalRuntimeProfileConfig.model_validate(values)


def test_legacy_codex_binding_loads_with_bounded_phase_budget_defaults() -> None:
    """A binding written before #571 keeps its single effort for routine checks."""

    legacy = _external_runtime().model_dump()
    for key in ("routine_reasoning_effort", "routine_output_limit", "final_output_limit"):
        legacy.pop(key)
    runtime = ExternalRuntimeProfileConfig.model_validate(legacy)

    assert runtime.routine_reasoning_effort is None
    assert runtime.effective_routine_reasoning_effort == "high"
    assert runtime.routine_output_limit == 4096
    assert runtime.final_output_limit == 8192
    assert runtime.review_budget_facts() == {
        "routine": {
            "reasoning_effort": "high",
            "output_limit": 4096,
            "effort_source": "legacy_single_effort",
        },
        "final": {"reasoning_effort": "high", "output_limit": 8192, "effort_source": "configured"},
    }


def test_codex_phase_budgets_are_independent_and_bounded() -> None:
    values = _external_runtime().model_dump()
    values.update(routine_reasoning_effort="low", routine_output_limit=1, final_output_limit=8192)
    runtime = ExternalRuntimeProfileConfig.model_validate(values)
    assert runtime.effective_routine_reasoning_effort == "low"
    assert runtime.review_budget_facts()["routine"] == {
        "reasoning_effort": "low",
        "output_limit": 1,
        "effort_source": "configured",
    }
    for key in ("routine_output_limit", "final_output_limit"):
        for limit in (0, 8193):
            bad = _external_runtime().model_dump()
            bad[key] = limit
            with pytest.raises(ConfigError):
                ExternalRuntimeProfileConfig.model_validate(bad)
    bad = _external_runtime().model_dump()
    bad["routine_reasoning_effort"] = "not an identifier"
    with pytest.raises(ConfigError):
        ExternalRuntimeProfileConfig.model_validate(bad)


def test_rendered_codex_binding_emits_phase_budget_keys_only_when_explicit() -> None:
    import tomllib

    from finishup.config.load import validate_config_mapping
    from finishup.config.write import render_config_toml

    legacy = FinishUpConfig(profile="codex-subscription", external_runtime=_external_runtime())
    legacy_text = render_config_toml(legacy)
    for key in ("routine_reasoning_effort", "routine_output_limit", "final_output_limit"):
        assert key not in legacy_text
    assert validate_config_mapping(tomllib.loads(legacy_text)) == legacy

    explicit_runtime = _external_runtime().model_copy(
        update={
            "routine_reasoning_effort": "medium",
            "routine_output_limit": 2048,
            "final_output_limit": 6000,
        }
    )
    explicit = FinishUpConfig(profile="codex-subscription", external_runtime=explicit_runtime)
    text = render_config_toml(explicit)
    assert 'routine_reasoning_effort = "medium"' in text
    assert "routine_output_limit = 2048" in text
    assert "final_output_limit = 6000" in text
    loaded = validate_config_mapping(tomllib.loads(text))
    assert loaded == explicit
    assert render_config_toml(loaded) == text
