"""Atomic writers for service-owned nonsecret ``config.toml`` desired state."""

from __future__ import annotations

import fcntl
import os
import stat
import tempfile
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Final, Literal

from finishup.config.load import load_config, validate_config_mapping
from finishup.config.models import (
    CODEX_FINAL_OUTPUT_LIMIT_DEFAULT,
    CODEX_ROUTINE_OUTPUT_LIMIT_DEFAULT,
    CODEX_SUBSCRIPTION_ENDPOINT_PROFILE_ID,
    CODEX_SUBSCRIPTION_PROVIDER_ID,
    DEFAULT_FINDING_ATTEMPT_BUDGET,
    DEFAULT_MAX_DECLARED_QUIET_SECONDS,
    DEFAULT_TOP_LEVEL_CONTACT_LOST_HORIZON_SECONDS,
    ConfigError,
    ExternalRuntimeProfileConfig,
    FinishUpConfig,
    OwnerDeclaredEndpointConfig,
    ProviderProfileConfig,
    SemanticFallbackConfig,
)
from finishup.config.paths import PathSafetyError, config_file_path, ensure_owner_only_dir
from finishup.config.privacy import safe_privacy_bootstrap

__all__ = [
    "PROVIDER_PRESETS",
    "ProviderPreset",
    "codex_subscription_runtime",
    "anthropic_provider",
    "default_capability_profile",
    "fireworks_provider",
    "grok_provider",
    "gemini_provider",
    "google_gemini_provider",
    "official_openai_provider",
    "openrouter_provider",
    "owner_declared_openai_provider",
    "provider_preset",
    "render_config_toml",
    "vercel_ai_gateway_provider",
    "xai_provider",
    "write_config_toml",
    "write_config_toml_if_unchanged",
    "config_write_snapshot",
    "cleared_external_runtime_config",
    "clear_external_runtime_binding",
    "external_runtime_binding_config",
    "preflight_config_write",
    "provider_binding_config",
    "semantic_fallback_primary_config",
    "semantic_fallback_removed_config",
    "write_provider_binding",
    "write_external_runtime_binding",
]

_OFFICIAL_CAPABILITY: Final = "openai-responses-structured-1"
_OWNER_CAPABILITY: Final = "openai-responses-structured-1"
_FIREWORKS_CAPABILITY: Final = "fireworks-responses-structured-1"
_ANTHROPIC_CAPABILITY: Final = "anthropic-openai-chat-completions-1"
_GEMINI_CAPABILITY: Final = "google-gemini-openai-chat-completions-1"
_OPENROUTER_CAPABILITY: Final = "openrouter-openai-chat-completions-1"
_XAI_CAPABILITY: Final = "xai-openai-chat-completions-1"
_VERCEL_AI_GATEWAY_CAPABILITY: Final = "vercel-ai-gateway-openai-responses-1"
_CONFIG_LOCK_SUFFIX: Final = ".lock"
_PROVIDER_CHOICE_ALIASES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "openai": "official_openai",
        "official-openai": "official_openai",
        "claude": "anthropic",
        "anthropic-claude": "anthropic",
        "gemini": "google_gemini",
        "google": "google_gemini",
        "google-gemini": "google_gemini",
        "vercel-ai-gateway": "vercel_ai_gateway",
        "xai": "grok",
        "x-ai": "grok",
    }
)


@dataclass(frozen=True, slots=True)
class ProviderPreset:
    """Exact nonsecret endpoint facts displayed by a bundled setup choice."""

    choice: str
    provider_id: str
    endpoint_profile_id: str
    endpoint_profile_version: str
    capability_profile: str
    host: str
    base_path_prefix: str
    default_model: str
    api_style: str
    suggested_models: tuple[str, ...]

    def __post_init__(self) -> None:
        """Keep the reviewed setup catalog deterministic, bounded, and default-first."""

        suggestions = self.suggested_models
        if (
            not suggestions
            or len(suggestions) > 10
            or next(iter(suggestions), None) != self.default_model
            or len(set(suggestions)) != len(suggestions)
            or any(type(model) is not str or not model for model in suggestions)
        ):
            raise ValueError("provider_model_catalog_invalid")


PROVIDER_PRESETS: Final[Mapping[str, ProviderPreset]] = MappingProxyType(
    {
        "official_openai": ProviderPreset(
            "official_openai",
            "openai",
            "openai-responses",
            "1.0.0",
            _OFFICIAL_CAPABILITY,
            "api.openai.com",
            "/v1",
            "gpt-6.1-sol",
            "responses",
            (
                "gpt-6.1-sol",
                "gpt-6-astra",
                "gpt-6-luna",
                "gpt-6-sol",
            ),
        ),
        "fireworks": ProviderPreset(
            "fireworks",
            "fireworks",
            "fireworks-responses",
            "1.0.0",
            _FIREWORKS_CAPABILITY,
            "api.fireworks.ai",
            "/inference/v1",
            "accounts/fireworks/models/kimi-k3",
            "responses",
            (
                "accounts/fireworks/models/kimi-k3",
                "accounts/fireworks/models/glm-5p3",
                "accounts/fireworks/models/qwen3p8-max",
            ),
        ),
        "anthropic": ProviderPreset(
            "anthropic",
            "anthropic",
            "anthropic-openai-chat-completions",
            "1.0.0",
            _ANTHROPIC_CAPABILITY,
            "api.anthropic.com",
            "/v1",
            "claude-opus-5-5",
            "chat_completions",
            (
                "claude-opus-5-5",
                "claude-sonnet-5-5",
                "claude-haiku-5-5",
                "claude-fable-5-1",
            ),
        ),
        "google_gemini": ProviderPreset(
            "google_gemini",
            "google",
            "google-gemini-openai-chat-completions",
            "1.0.0",
            _GEMINI_CAPABILITY,
            "generativelanguage.googleapis.com",
            "/v1beta/openai",
            "gemini-4-argon",
            "chat_completions",
            (
                "gemini-4-argon",
                "gemini-3.8-flash",
                "gemini-3.5-flash-lite",
            ),
        ),
        "openrouter": ProviderPreset(
            "openrouter",
            "openrouter",
            "openrouter-openai-chat-completions",
            "1.0.0",
            _OPENROUTER_CAPABILITY,
            "openrouter.ai",
            "/api/v1",
            "openai/gpt-6.1-sol",
            "chat_completions",
            (
                "openai/gpt-6.1-sol",
                "openai/gpt-6-astra",
                "anthropic/claude-opus-5.5",
                "anthropic/claude-sonnet-5.5",
                "google/gemini-4-argon",
                "x-ai/grok-4.7",
                "moonshotai/kimi-k3",
            ),
        ),
        "grok": ProviderPreset(
            "grok",
            "xai",
            "xai-openai-chat-completions",
            "1.0.0",
            _XAI_CAPABILITY,
            "api.x.ai",
            "/v1",
            "grok-4.7",
            "chat_completions",
            (
                "grok-4.7",
                "grok-4.3",
                "grok-4.6",
            ),
        ),
        "vercel_ai_gateway": ProviderPreset(
            "vercel_ai_gateway",
            "vercel-ai-gateway",
            "vercel-ai-gateway-openai-responses",
            "1.0.0",
            _VERCEL_AI_GATEWAY_CAPABILITY,
            "ai-gateway.vercel.sh",
            "/v1",
            "openai/gpt-6.1-sol",
            "responses",
            (
                "openai/gpt-6.1-sol",
                "openai/gpt-6-astra",
                "anthropic/claude-opus-5.5",
                "anthropic/claude-sonnet-5.5",
                "google/gemini-4-argon",
                "spacexai/grok-4.7",
                "moonshotai/kimi-k3",
            ),
        ),
    }
)


def provider_preset(choice: str) -> ProviderPreset:
    """Return one closed bundled preset or a bounded configuration error."""

    try:
        normalized = choice.strip().lower()
        canonical = _PROVIDER_CHOICE_ALIASES.get(normalized, normalized)
        return PROVIDER_PRESETS[canonical]
    except (AttributeError, KeyError, TypeError) as exc:
        raise ConfigError("config_value_invalid") from exc


def default_capability_profile() -> str:
    return _OFFICIAL_CAPABILITY


def official_openai_provider(
    *,
    model: str,
    endpoint_profile_version: str = "1.0.0",
    timeout_seconds: int = 60,
    max_retries: int = 2,
) -> ProviderProfileConfig:
    """Build the bundled official OpenAI Responses structural binding (no URL field)."""

    return ProviderProfileConfig(
        provider_id="openai",
        endpoint_profile_id="openai-responses",
        endpoint_profile_version=endpoint_profile_version,
        model=model,
        capability_profile=_OFFICIAL_CAPABILITY,
        timeout_seconds=timeout_seconds,
        max_retries=max_retries,
    )


def _bundled_provider(
    choice: str,
    *,
    model: str,
    timeout_seconds: int = 60,
    max_retries: int = 2,
) -> ProviderProfileConfig:
    preset = provider_preset(choice)
    if not model:
        raise ConfigError("config_value_invalid")
    return ProviderProfileConfig(
        provider_id=preset.provider_id,
        endpoint_profile_id=preset.endpoint_profile_id,
        endpoint_profile_version=preset.endpoint_profile_version,
        model=model,
        capability_profile=preset.capability_profile,
        timeout_seconds=timeout_seconds,
        max_retries=max_retries,
    )


def fireworks_provider(
    *,
    model: str,
    endpoint_profile_version: str = "1.0.0",
    timeout_seconds: int = 60,
    max_retries: int = 2,
) -> ProviderProfileConfig:
    """Build the reviewed fixed Fireworks Responses endpoint binding."""

    return ProviderProfileConfig(
        provider_id="fireworks",
        endpoint_profile_id="fireworks-responses",
        endpoint_profile_version=endpoint_profile_version,
        model=model,
        capability_profile=_FIREWORKS_CAPABILITY,
        timeout_seconds=timeout_seconds,
        max_retries=max_retries,
    )


def anthropic_provider(
    *,
    model: str,
    timeout_seconds: int = 60,
    max_retries: int = 2,
) -> ProviderProfileConfig:
    """Build Anthropic's exact OpenAI-compatible Chat Completions binding."""

    return _bundled_provider(
        "anthropic", model=model, timeout_seconds=timeout_seconds, max_retries=max_retries
    )


def google_gemini_provider(
    *,
    model: str,
    timeout_seconds: int = 60,
    max_retries: int = 2,
) -> ProviderProfileConfig:
    """Build Google's exact Gemini OpenAI-compatible Chat Completions binding."""

    return _bundled_provider(
        "google_gemini", model=model, timeout_seconds=timeout_seconds, max_retries=max_retries
    )


gemini_provider = google_gemini_provider


def openrouter_provider(
    *,
    model: str,
    timeout_seconds: int = 60,
    max_retries: int = 2,
) -> ProviderProfileConfig:
    """Build OpenRouter's exact OpenAI-compatible Chat Completions binding."""

    return _bundled_provider(
        "openrouter", model=model, timeout_seconds=timeout_seconds, max_retries=max_retries
    )


def grok_provider(
    *,
    model: str,
    timeout_seconds: int = 60,
    max_retries: int = 2,
) -> ProviderProfileConfig:
    """Build xAI's exact Grok OpenAI-compatible Chat Completions binding."""

    return _bundled_provider(
        "grok", model=model, timeout_seconds=timeout_seconds, max_retries=max_retries
    )


xai_provider = grok_provider


def vercel_ai_gateway_provider(
    *,
    model: str,
    timeout_seconds: int = 60,
    max_retries: int = 2,
) -> ProviderProfileConfig:
    """Build Vercel AI Gateway's exact OpenAI-compatible Responses binding."""

    return _bundled_provider(
        "vercel_ai_gateway", model=model, timeout_seconds=timeout_seconds, max_retries=max_retries
    )


def owner_declared_openai_provider(
    *,
    model: str,
    https_origin: str,
    endpoint_profile_version: str = "1.0.0",
    timeout_seconds: int = 60,
    max_retries: int = 2,
) -> ProviderProfileConfig:
    """Build the exact owner-declared OpenAI-compatible Responses binding."""

    return ProviderProfileConfig(
        provider_id="openai-compatible",
        endpoint_profile_id="owner-declared-openai-responses",
        endpoint_profile_version=endpoint_profile_version,
        model=model,
        capability_profile=_OWNER_CAPABILITY,
        timeout_seconds=timeout_seconds,
        max_retries=max_retries,
        owner_declared_endpoint=OwnerDeclaredEndpointConfig(https_origin=https_origin),
    )


def codex_subscription_runtime(
    *,
    executable_path: str,
    executable_sha256: str,
    runtime_version: str,
    source_identity: str,
    app_server_schema_sha256: str,
    capability_cell_sha256: str,
    isolated_config_sha256: str,
    capability_profile: str,
    capability_evidence_expires_at: Literal["2026-11-30T00:00:00Z"],
    codex_home: str,
    model: str,
    reasoning_effort: str,
    timeout_seconds: int = 900,
    max_retries: int = 2,
    routine_reasoning_effort: str | None = None,
    routine_output_limit: int = CODEX_ROUTINE_OUTPUT_LIMIT_DEFAULT,
    final_output_limit: int = CODEX_FINAL_OUTPUT_LIMIT_DEFAULT,
) -> ExternalRuntimeProfileConfig:
    """Build the exact nonsecret Codex app-server subscription binding.

    ``reasoning_effort`` is the final-profile effort. ``routine_reasoning_effort=None`` keeps the
    legacy single-effort behavior for routine checks; setup passes an explicit value.
    """

    return ExternalRuntimeProfileConfig(
        provider_id=CODEX_SUBSCRIPTION_PROVIDER_ID,
        endpoint_profile_id=CODEX_SUBSCRIPTION_ENDPOINT_PROFILE_ID,
        endpoint_profile_version="1.0.0",
        credential_authority="external_runtime_oauth",
        executable_path=executable_path,
        executable_sha256=executable_sha256,
        runtime_version=runtime_version,
        source_identity=source_identity,
        app_server_schema_sha256=app_server_schema_sha256,
        capability_cell_sha256=capability_cell_sha256,
        isolated_config_sha256=isolated_config_sha256,
        capability_profile=capability_profile,
        capability_evidence_expires_at=capability_evidence_expires_at,
        codex_home=codex_home,
        model=model,
        reasoning_effort=reasoning_effort,
        timeout_seconds=timeout_seconds,
        max_retries=max_retries,
        routine_reasoning_effort=routine_reasoning_effort,
        routine_output_limit=routine_output_limit,
        final_output_limit=final_output_limit,
    )


def _codex_review_budget_fields(runtime: ExternalRuntimeProfileConfig) -> dict[str, object]:
    fields: dict[str, object] = {}
    if runtime.routine_reasoning_effort is not None:
        fields["routine_reasoning_effort"] = runtime.routine_reasoning_effort
    if runtime.routine_output_limit != CODEX_ROUTINE_OUTPUT_LIMIT_DEFAULT:
        fields["routine_output_limit"] = runtime.routine_output_limit
    if runtime.final_output_limit != CODEX_FINAL_OUTPUT_LIMIT_DEFAULT:
        fields["final_output_limit"] = runtime.final_output_limit
    return fields


def _escape_basic(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )


def _toml_str(value: str) -> str:
    return f'"{_escape_basic(value)}"'


def _toml_bool(value: bool) -> str:
    return "true" if value else "false"


def _emit_table(lines: list[str], header: str, mapping: Mapping[str, object]) -> None:
    lines.append(f"[{header}]")
    for key, raw in mapping.items():
        if isinstance(raw, bool):
            lines.append(f"{key} = {_toml_bool(raw)}")
        elif type(raw) is int:
            lines.append(f"{key} = {raw}")
        elif type(raw) is str:
            lines.append(f"{key} = {_toml_str(raw)}")
        else:
            raise ConfigError("config_value_invalid", safe_name=key[:256])
    lines.append("")


def render_config_toml(config: FinishUpConfig) -> str:
    """Render a validated ``FinishUpConfig`` as UTF-8 TOML text (no secrets).

    The first-run ``[privacy]`` bootstrap seed is omitted when it equals the safe default so
    loaders keep generation-1-only bootstrap semantics; durable privacy desired-state lives in
    the separate privacy desired-state path (ADR-014), never as silent authority here.
    """

    if type(config) is not FinishUpConfig:
        raise TypeError("config_write_wrong_type")
    lines: list[str] = [
        f"schema_version = {_toml_str(config.schema_version)}",
        f"profile = {_toml_str(config.profile)}",
        "",
    ]
    storage: dict[str, object] = {"durability": config.storage.durability}
    if config.storage.data_dir is not None:
        storage["data_dir"] = str(config.storage.data_dir)
    _emit_table(lines, "storage", storage)
    verification: dict[str, object] = {
        "semantic": config.verification.semantic,
        "max_findings": config.verification.max_findings,
    }
    # Written only when the owner chose a non-default budget, so existing files keep their bytes.
    if config.verification.finding_attempt_budget != DEFAULT_FINDING_ATTEMPT_BUDGET:
        verification["finding_attempt_budget"] = config.verification.finding_attempt_budget
    _emit_table(lines, "verification", verification)
    # An unset background-advice switch stays unset so the product default keeps applying; only
    # an owner's explicit choice is persisted (#888).
    observation: dict[str, object] = {"enabled": config.observation.enabled}
    if config.observation.semantic_advice_enabled is not None:
        observation["semantic_advice_enabled"] = config.observation.semantic_advice_enabled
    observation["semantic_advice_min_interval_seconds"] = (
        config.observation.semantic_advice_min_interval_seconds
    )
    _emit_table(lines, "observation", observation)
    lineage: dict[str, object] = {
        "start_lease_seconds": config.lineage.start_lease_seconds,
        "attach_handle_ttl_seconds": config.lineage.attach_handle_ttl_seconds,
        "contact_lost_recovery_seconds": config.lineage.contact_lost_recovery_seconds,
    }
    # #1239: written only when the owner chose a non-default horizon, so existing files keep
    # their bytes.
    if (
        config.lineage.top_level_contact_lost_horizon_seconds
        != DEFAULT_TOP_LEVEL_CONTACT_LOST_HORIZON_SECONDS
    ):
        lineage["top_level_contact_lost_horizon_seconds"] = (
            config.lineage.top_level_contact_lost_horizon_seconds
        )
    if config.lineage.max_declared_quiet_seconds != DEFAULT_MAX_DECLARED_QUIET_SECONDS:
        lineage["max_declared_quiet_seconds"] = config.lineage.max_declared_quiet_seconds
    lineage["max_depth"] = config.lineage.max_depth
    lineage["max_fanout"] = config.lineage.max_fanout
    _emit_table(lines, "lineage", lineage)
    _emit_table(
        lines,
        "logging",
        {"level": config.logging.level, "payloads": config.logging.payloads},
    )

    if config.privacy != safe_privacy_bootstrap():
        raise ConfigError("privacy_bootstrap_unsafe")

    if config.provider is not None:
        provider = config.provider
        _emit_table(
            lines,
            "provider",
            {
                "provider_id": provider.provider_id,
                "endpoint_profile_id": provider.endpoint_profile_id,
                "endpoint_profile_version": provider.endpoint_profile_version,
                "model": provider.model,
                "capability_profile": provider.capability_profile,
                "timeout_seconds": provider.timeout_seconds,
                "max_retries": provider.max_retries,
            },
        )
        if provider.owner_declared_endpoint is not None:
            _emit_table(
                lines,
                "provider.owner_declared_endpoint",
                {"https_origin": provider.owner_declared_endpoint.https_origin},
            )

    if config.external_runtime is not None:
        runtime = config.external_runtime
        _emit_table(
            lines,
            "external_runtime",
            {
                "provider_id": runtime.provider_id,
                "endpoint_profile_id": runtime.endpoint_profile_id,
                "endpoint_profile_version": runtime.endpoint_profile_version,
                "credential_authority": runtime.credential_authority,
                "executable_path": runtime.executable_path,
                "executable_sha256": runtime.executable_sha256,
                "runtime_version": runtime.runtime_version,
                "source_identity": runtime.source_identity,
                "app_server_schema_sha256": runtime.app_server_schema_sha256,
                "capability_cell_sha256": runtime.capability_cell_sha256,
                "isolated_config_sha256": runtime.isolated_config_sha256,
                "capability_profile": runtime.capability_profile,
                "capability_evidence_expires_at": runtime.capability_evidence_expires_at,
                "codex_home": runtime.codex_home,
                "model": runtime.model,
                "reasoning_effort": runtime.reasoning_effort,
                "timeout_seconds": runtime.timeout_seconds,
                "max_retries": runtime.max_retries,
                # Phase-aware budget keys are emitted only when they carry an explicit choice,
                # so a legacy binding rewritten by an unrelated command stays byte-compatible.
                **_codex_review_budget_fields(runtime),
            },
        )

    if config.semantic_fallback is not None:
        _emit_table(lines, "semantic_fallback", {"primary": config.semantic_fallback.primary})

    if config.local_model is not None:
        local = config.local_model
        _emit_table(
            lines,
            "local_model",
            {
                "profile_id": local.profile_id,
                "profile_version": local.profile_version,
                "endpoint_profile_id": local.endpoint_profile_id,
                "endpoint_profile_version": local.endpoint_profile_version,
                "model": local.model,
                "protocol_version": local.protocol_version,
                "judgment_schema_version": local.judgment_schema_version,
                "capability_digest": local.capability_digest,
                "timeout_seconds": local.timeout_seconds,
            },
        )

    text = "\n".join(lines).rstrip() + "\n"
    # Round-trip through the canonical loader rule, not raw strict validation: a rendered
    # ``storage.data_dir`` is file-shape (a string) and only the loader's normalization makes
    # the written file provably loadable (#520).
    validate_config_mapping(tomllib.loads(text))
    return text


def _config_target(path: Path | None) -> Path:
    using_default = path is None
    target = config_file_path() if using_default else path
    assert target is not None
    if using_default:
        try:
            ensure_owner_only_dir(target.parent)
        except PathSafetyError as exc:
            raise ConfigError("config_value_invalid", safe_name=exc.reason_code) from exc
    else:
        target.parent.mkdir(parents=True, exist_ok=True)
    return target


class _ConfigWriteLock:
    """Persistent owner-only advisory lock shared by every config writer."""

    def __init__(self, target: Path) -> None:
        self._path = target.with_name(f".{target.name}{_CONFIG_LOCK_SUFFIX}")
        self._descriptor: int | None = None

    def __enter__(self) -> None:
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor: int | None = None
        try:
            descriptor = os.open(self._path, flags, 0o600)
            facts = os.fstat(descriptor)
            effective_uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
            if not stat.S_ISREG(facts.st_mode) or (
                hasattr(facts, "st_uid") and facts.st_uid != effective_uid
            ):
                raise OSError("config_lock_unsafe")
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
        except OSError as exc:
            if descriptor is not None:
                os.close(descriptor)
            raise ConfigError("config_value_invalid") from exc
        self._descriptor = descriptor

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        descriptor = self._descriptor
        self._descriptor = None
        if descriptor is not None:
            os.close(descriptor)


def _current_config_bytes(target: Path) -> bytes | None:
    try:
        return target.read_bytes()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ConfigError("config_value_invalid") from exc


def config_write_snapshot(path: Path | None = None) -> tuple[FinishUpConfig, bytes | None]:
    """Load a config and its exact write preimage under the shared config lock.

    Interactive provider operations keep the returned bytes across the external login/logout
    boundary and compare them again before persisting. This prevents a stale model snapshot from
    replacing a concurrent configuration edit.
    """

    target = _config_target(path)
    with _ConfigWriteLock(target):
        expected_bytes = _current_config_bytes(target)
        config = load_config({}, {}, target)
    return config, expected_bytes


def _atomic_write_config(target: Path, payload: bytes) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=".finishup-config-", dir=target.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)
    except OSError as exc:
        temporary.unlink(missing_ok=True)
        raise ConfigError("config_value_invalid") from exc


def write_config_toml(config: FinishUpConfig, path: Path | None = None) -> Path:
    """Atomically write validated nonsecret config to the service-owned path."""

    target = _config_target(path)
    payload = render_config_toml(config).encode("utf-8")
    with _ConfigWriteLock(target):
        _atomic_write_config(target, payload)
    return target


def write_config_toml_if_unchanged(
    config: FinishUpConfig,
    *,
    expected_bytes: bytes | None,
    path: Path | None = None,
) -> Path:
    """Write only when the locked config preimage exactly matches ``expected_bytes``.

    ``None`` means the caller previewed an absent file. Every in-process config writer uses the
    same persistent interprocess lock, so the comparison and atomic replacement form one
    serialized operation across cooperating FinishUP processes.
    """

    if expected_bytes is not None and type(expected_bytes) is not bytes:
        raise TypeError("config_expected_bytes_wrong_type")
    target = _config_target(path)
    payload = render_config_toml(config).encode("utf-8")
    with _ConfigWriteLock(target):
        if _current_config_bytes(target) != expected_bytes:
            raise ConfigError("config_preimage_mismatch")
        _atomic_write_config(target, payload)
    return target


def preflight_config_write(
    config: FinishUpConfig,
    path: Path | None = None,
    *,
    expected_bytes: bytes | None,
) -> Path:
    """Prove the exact config renders and its locked target accepts a write, without writing.

    Runs every deterministic local step of :func:`write_config_toml` except the final atomic
    replacement: target directory preparation, full strict render validation, and acquisition of
    the shared persistent write lock. A caller about to perform a non-local side effect (such as
    opening a provider login flow) uses this to fail closed before that side effect instead of
    after it (#520).
    """

    target = _config_target(path)
    render_config_toml(config)
    with _ConfigWriteLock(target):
        if _current_config_bytes(target) != expected_bytes:
            raise ConfigError("config_preimage_mismatch")
    return target


def provider_binding_config(
    provider: ProviderProfileConfig,
    *,
    profile: str = "local-openai",
    base: FinishUpConfig | None = None,
    as_fallback: bool = False,
) -> FinishUpConfig:
    """Return the config binding this API provider, without writing it.

    ``as_fallback`` keeps the already-bound Codex subscription as the primary and declares this
    provider as its fallback (issue #582); it requires that subscription to be bound. Without the
    flag, an existing pairing keeps its selector and only the API slot is replaced; with no
    pairing the single-endpoint rule holds and the subscription binding is removed.
    """

    if type(provider) is not ProviderProfileConfig:
        raise TypeError("config_write_wrong_type")
    current = FinishUpConfig() if base is None else base
    if as_fallback:
        if current.external_runtime is None:
            raise ConfigError("semantic_fallback_endpoint_missing")
        return current.model_copy(
            update={
                "profile": "codex-subscription",
                "provider": provider,
                "local_model": None,
                "semantic_fallback": SemanticFallbackConfig(primary="codex_subscription"),
            }
        )
    if current.semantic_fallback is not None:
        return current.model_copy(update={"provider": provider})
    return current.model_copy(
        update={
            "profile": profile,
            "provider": provider,
            "external_runtime": None,
            "local_model": None if profile == "local-openai" else current.local_model,
        }
    )


def write_provider_binding(
    provider: ProviderProfileConfig,
    *,
    profile: str = "local-openai",
    path: Path | None = None,
    base: FinishUpConfig | None = None,
    as_fallback: bool = False,
) -> Path:
    """Merge a provider binding into service config and write it."""

    return write_config_toml(
        provider_binding_config(provider, profile=profile, base=base, as_fallback=as_fallback),
        path=path,
    )


def external_runtime_binding_config(
    runtime: ExternalRuntimeProfileConfig,
    *,
    base: FinishUpConfig | None = None,
    as_fallback: bool = False,
) -> FinishUpConfig:
    """Return the exact config selecting this external runtime, without writing it.

    ``as_fallback`` keeps the already-bound API provider as the primary and declares this
    runtime as its fallback (issue #582); it requires that provider to be bound. Without the
    flag, an existing pairing keeps its selector and only the runtime slot is replaced; with no
    pairing the single-endpoint rule holds and the API binding is removed.
    """

    if type(runtime) is not ExternalRuntimeProfileConfig:
        raise TypeError("config_write_wrong_type")
    source = FinishUpConfig() if base is None else base
    if as_fallback:
        if source.provider is None:
            raise ConfigError("semantic_fallback_endpoint_missing")
        return source.model_copy(
            update={
                "profile": "local-openai",
                "local_model": None,
                "external_runtime": runtime,
                "semantic_fallback": SemanticFallbackConfig(primary="api_provider"),
            }
        )
    if source.semantic_fallback is not None:
        return source.model_copy(update={"external_runtime": runtime})
    return source.model_copy(
        update={
            "profile": "codex-subscription",
            "provider": None,
            "local_model": None,
            "external_runtime": runtime,
        }
    )


def write_external_runtime_binding(
    runtime: ExternalRuntimeProfileConfig,
    *,
    path: Path | None = None,
    base: FinishUpConfig | None = None,
    as_fallback: bool = False,
) -> Path:
    """Atomically select the exact external-runtime route.

    Without a declared pairing this removes the API and local bindings; with one it replaces
    only the runtime slot (see :func:`external_runtime_binding_config`).
    """

    return write_config_toml(
        external_runtime_binding_config(runtime, base=base, as_fallback=as_fallback), path=path
    )


def cleared_external_runtime_config(base: FinishUpConfig | None = None) -> FinishUpConfig:
    """Return the config with only the Codex evaluator binding removed, without writing it.

    Inside a pairing the API provider stays bound as the sole endpoint and the selector is
    dropped, whichever role the runtime held; single-endpoint behaviour is restored exactly.
    """

    source = FinishUpConfig() if base is None else base
    if source.external_runtime is None:
        return source
    if source.semantic_fallback is not None:
        return source.model_copy(
            update={
                "profile": "local-openai",
                "external_runtime": None,
                "semantic_fallback": None,
            }
        )
    return source.model_copy(
        update={
            "profile": "strict-local",
            "external_runtime": None,
        }
    )


def semantic_fallback_removed_config(base: FinishUpConfig) -> FinishUpConfig:
    """Return the config with the fallback endpoint and its selector removed.

    The primary keeps serving alone: this is the exact reverse of declaring the pairing, so
    ``provider status`` and the privacy candidate return to their single-endpoint shape.
    """

    if type(base) is not FinishUpConfig:
        raise TypeError("config_write_wrong_type")
    if base.semantic_fallback is None:
        raise ConfigError("semantic_fallback_endpoint_missing")
    if base.semantic_fallback.primary == "codex_subscription":
        return base.model_copy(
            update={
                "profile": "codex-subscription",
                "provider": None,
                "semantic_fallback": None,
            }
        )
    return base.model_copy(
        update={
            "profile": "local-openai",
            "external_runtime": None,
            "semantic_fallback": None,
        }
    )


def semantic_fallback_primary_config(
    base: FinishUpConfig, primary: Literal["api_provider", "codex_subscription"]
) -> FinishUpConfig:
    """Return the config with the pairing's primary swapped, both endpoints kept."""

    if type(base) is not FinishUpConfig:
        raise TypeError("config_write_wrong_type")
    if base.semantic_fallback is None:
        raise ConfigError("semantic_fallback_endpoint_missing")
    return base.model_copy(
        update={
            "profile": "codex-subscription" if primary == "codex_subscription" else "local-openai",
            "semantic_fallback": SemanticFallbackConfig(primary=primary),
        }
    )


def clear_external_runtime_binding(
    *, path: Path | None = None, base: FinishUpConfig | None = None
) -> Path:
    """Remove only the Codex evaluator binding; never touch its installation or home."""

    return write_config_toml(cleared_external_runtime_config(base), path=path)
