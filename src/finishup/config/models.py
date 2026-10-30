"""Strict, frozen service-owned configuration models."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Final, Literal, cast
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from finishup.domain.privacy import ProviderDataUseProfile
from finishup.protocol.models import MAX_FINDINGS_LIMIT

__all__ = [
    "CODEX_FINAL_OUTPUT_LIMIT_DEFAULT",
    "CODEX_OUTPUT_LIMIT_MAX",
    "CODEX_ROUTINE_OUTPUT_LIMIT_DEFAULT",
    "CODEX_ROUTINE_REASONING_EFFORT_DEFAULT",
    "CODEX_SUBSCRIPTION_ENDPOINT_PROFILE_ID",
    "CODEX_SUBSCRIPTION_PROVIDER_ID",
    "OFFICIAL_OPENAI_ENDPOINT_PROFILE_ID",
    "OWNER_DECLARED_ENDPOINT_PROFILE_ID",
    "OWNER_DECLARED_PROVIDER_ID",
    "PROFILE_CAPABILITIES",
    "BackgroundAdviceReason",
    "BackgroundAdviceSetting",
    "ConfigError",
    "ExternalRuntimeProfileConfig",
    "LocalModelProfileConfig",
    "LoggingConfig",
    "LineageSettings",
    "NetworkPolicy",
    "ObservationConfig",
    "OwnerDeclaredEndpointConfig",
    "PrivacyBootstrapConfig",
    "ProfileCapabilities",
    "ProviderDataUseProfile",
    "ProviderProfileConfig",
    "SemanticFallbackConfig",
    "SemanticPolicy",
    "StorageConfig",
    "VerificationConfig",
    "FinishUpConfig",
    "background_advice_setting",
    "fallback_external_endpoint",
    "parse_https_origin",
    "primary_external_endpoint",
]

OFFICIAL_OPENAI_ENDPOINT_PROFILE_ID: Final = "openai-responses"
CODEX_SUBSCRIPTION_ENDPOINT_PROFILE_ID: Final = "codex-chatgpt-subscription"
CODEX_SUBSCRIPTION_PROVIDER_ID: Final = "openai-codex"
# Phase-aware Codex review budgets (issue #571).  Output limits count output tokens and share
# the provenance ``sampling_params.max_output_tokens`` bound.
CODEX_OUTPUT_LIMIT_MAX: Final = 8_192
CODEX_ROUTINE_OUTPUT_LIMIT_DEFAULT: Final = 4_096
CODEX_FINAL_OUTPUT_LIMIT_DEFAULT: Final = 8_192
CODEX_ROUTINE_REASONING_EFFORT_DEFAULT: Final = "medium"
OWNER_DECLARED_ENDPOINT_PROFILE_ID: Final = "owner-declared-openai-responses"
OWNER_DECLARED_PROVIDER_ID: Final = "openai-compatible"

_MODEL_CONFIG: Final = ConfigDict(
    strict=True,
    extra="forbid",
    frozen=True,
    validate_default=True,
)
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,255}$", re.ASCII)
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$", re.ASCII)
_SECRET_KEY_TOKENS: Final = ("api_key", "apikey", "token", "secret", "password")
_LOCAL_LOCATOR_KEYS: Final = frozenset(
    {
        "arguments",
        "base_url",
        "command",
        "discovery_mode",
        "download_source",
        "environment",
        "executable",
        "headers",
        "host",
        "options",
        "port",
        "socket",
        "socket_path",
        "url",
    }
)
_CONFIG_ERROR_REASONS: Final = frozenset(
    {
        "config_schema_unsupported",
        "config_value_invalid",
        "durability_unsupported",
        "external_profile_forbids_local_model",
        "external_runtime_forbids_local_model",
        "external_runtime_forbids_provider",
        "external_runtime_required_for_semantic",
        "https_origin_invalid",
        "local_model_locator_forbidden",
        "max_findings_out_of_range",
        "owner_declared_endpoint_forbidden",
        "owner_declared_endpoint_required",
        "payload_logging_forbidden",
        "privacy_bootstrap_unsafe",
        "provider_required_for_semantic",
        "secret_config_override_forbidden",
        "secret_in_config",
        "semantic_fallback_endpoint_missing",
        "semantic_fallback_profile_mismatch",
        "strict_local_forbids_provider",
        "test_fake_forbids_local_model",
        "test_fake_forbids_provider",
        "unknown_config_key",
    }
)
_OWNER_DECLARED_FORBIDDEN_KEYS: Final = frozenset(
    {
        "api_key",
        "authorization",
        "base_url",
        "credential",
        "headers",
        "host",
        "http_origin",
        "path",
        "port",
        "query",
        "token",
        "url",
    }
)
_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$",
    re.ASCII,
)


class ConfigError(Exception):
    """A bounded reviewed configuration failure."""

    reason_code: str
    safe_name: str | None
    line: int | None
    column: int | None

    def __init__(
        self,
        reason_code: str,
        *,
        safe_name: str | None = None,
        line: int | None = None,
        column: int | None = None,
    ) -> None:
        # Loader-owned reason codes extend this closed model-owned set.
        if type(reason_code) is not str or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", reason_code):
            raise ValueError("config_reason_code_invalid")
        if reason_code not in _CONFIG_ERROR_REASONS and not reason_code.startswith(
            ("config_", "secret_env_", "unknown_config_", "release_probe_")
        ):
            raise ValueError("config_reason_code_invalid")
        if safe_name is not None and (type(safe_name) is not str or len(safe_name) > 256):
            raise ValueError("config_safe_name_invalid")
        if line is not None and (type(line) is not int or line < 1):
            raise ValueError("config_line_invalid")
        if column is not None and (type(column) is not int or column < 1):
            raise ValueError("config_column_invalid")
        self.reason_code = reason_code
        self.safe_name = safe_name
        self.line = line
        self.column = column
        super().__init__(reason_code)


def _validation_reason(error: ValidationError) -> str:
    for item in error.errors(include_url=False, include_context=False, include_input=False):
        if item["type"] == "extra_forbidden":
            return "unknown_config_key"
    return "config_value_invalid"


class StrictConfigModel(BaseModel):
    model_config = _MODEL_CONFIG

    def __init__(self, /, **data: object) -> None:
        try:
            super().__init__(**data)
        except ValidationError as exc:
            raise ConfigError(_validation_reason(exc)) from None


def _mapping(value: object) -> Mapping[object, object]:
    if not isinstance(value, Mapping):
        raise ConfigError("config_value_invalid")
    return cast(Mapping[object, object], value)


def _keys(value: object) -> tuple[object, ...]:
    source = _mapping(value)
    try:
        return tuple(source.keys())
    except Exception as exc:
        raise ConfigError("config_value_invalid") from exc


def _reject_unknown(value: object, allowed: frozenset[str]) -> None:
    unknown = sorted(
        (key for key in _keys(value) if type(key) is not str or key not in allowed),
        key=lambda key: str(key),
    )
    if unknown:
        key = unknown[0]
        raise ConfigError(
            "unknown_config_key", safe_name=key if type(key) is str and len(key) <= 256 else None
        )


def _secret_key(key: object) -> bool:
    return type(key) is str and any(token in key.casefold() for token in _SECRET_KEY_TOKENS)


def _scan_secret_keys(value: object) -> None:
    matches: list[str] = []
    for key in _keys(value):
        if type(key) is str and _secret_key(key):
            matches.append(key)
    matches.sort()
    if matches:
        raise ConfigError("secret_in_config", safe_name=matches[0][:256])


def _validate_identifier(value: object) -> None:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise ConfigError("config_value_invalid")


def parse_https_origin(value: object) -> tuple[str, int]:
    """Validate a constrained HTTPS origin (scheme+host+optional port only).

    Rejects ``http``, userinfo, path (other than empty/``/``), query, fragment, and credentials.
    Returns ``(hostname, port)`` with default port ``443``.
    """

    if type(value) is not str or not 8 <= len(value) <= 512:
        raise ConfigError("https_origin_invalid")
    try:
        parsed = urlparse(value)
        # urllib raises ValueError lazily from .port for out-of-range / non-numeric ports
        port = 443 if parsed.port is None else parsed.port
    except ValueError as exc:
        raise ConfigError("https_origin_invalid") from exc
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
        or type(parsed.hostname) is not str
        or not parsed.hostname
        or _HOSTNAME.fullmatch(parsed.hostname) is None
    ):
        raise ConfigError("https_origin_invalid")
    if type(port) is not int or not 1 <= port <= 65535:
        raise ConfigError("https_origin_invalid")
    return parsed.hostname.casefold(), port


class OwnerDeclaredEndpointConfig(StrictConfigModel):
    """Owner-supplied HTTPS origin for the exact owner-declared Responses profile kind."""

    https_origin: str

    @model_validator(mode="before")
    @classmethod
    def _validate_raw(cls, value: object) -> object:
        _scan_secret_keys(value)
        source = _mapping(value)
        forbidden = sorted(
            key
            for key in _keys(value)
            if type(key) is str and key.casefold() in _OWNER_DECLARED_FORBIDDEN_KEYS
        )
        if forbidden:
            raise ConfigError("unknown_config_key", safe_name=forbidden[0][:256])
        _reject_unknown(value, frozenset({"https_origin"}))
        if "https_origin" not in source:
            raise ConfigError("https_origin_invalid")
        host, port = parse_https_origin(source["https_origin"])
        origin = f"https://{host}" if port == 443 else f"https://{host}:{port}"
        return {"https_origin": origin}

    @property
    def host(self) -> str:
        return parse_https_origin(self.https_origin)[0]

    @property
    def port(self) -> int:
        return parse_https_origin(self.https_origin)[1]


class StorageConfig(StrictConfigModel):
    data_dir: Path | None = None
    durability: Literal["full"] = "full"

    @model_validator(mode="before")
    @classmethod
    def _validate_raw(cls, value: object) -> object:
        _reject_unknown(value, frozenset({"data_dir", "durability"}))
        source = _mapping(value)
        if "durability" in source and source["durability"] != "full":
            raise ConfigError("durability_unsupported")
        return value


# Mirrors ``finishup.kernel.finding_todo``; config stays free of kernel imports.
DEFAULT_FINDING_ATTEMPT_BUDGET: Final = 5
# #1239: how long a quiet task no parent waits on keeps its open work (one day).
DEFAULT_TOP_LEVEL_CONTACT_LOST_HORIZON_SECONDS: Final = 86_400
# #1239: the longest declared quiet period that takes effect (one hour); 0 disables declarations.
DEFAULT_MAX_DECLARED_QUIET_SECONDS: Final = 3_600
MAX_FINDING_ATTEMPT_BUDGET: Final = 50


class VerificationConfig(StrictConfigModel):
    semantic: Literal["disabled", "optional", "required"] = "required"
    max_findings: int = 10
    # Issue #905: review rounds an item may stay open before FinishUP asks for a repair with new
    # evidence, a ``self_verified`` answer when only a FinishUP limit keeps the repair unproven
    # (issue #984), or, as the last resort, an explicit ``acknowledged_not_done``. It never
    # throttles ``check`` and never closes or acknowledges anything.
    finding_attempt_budget: int = Field(
        default=DEFAULT_FINDING_ATTEMPT_BUDGET, ge=1, le=MAX_FINDING_ATTEMPT_BUDGET
    )

    @model_validator(mode="before")
    @classmethod
    def _validate_raw(cls, value: object) -> object:
        _reject_unknown(value, frozenset({"semantic", "max_findings", "finding_attempt_budget"}))
        source = _mapping(value)
        if "max_findings" in source:
            maximum = source["max_findings"]
            if type(maximum) is not int or not 1 <= maximum <= MAX_FINDINGS_LIMIT:
                raise ConfigError("max_findings_out_of_range")
        return value


class ObservationConfig(StrictConfigModel):
    enabled: bool = True
    # ``None`` means the owner has not chosen: the effective default applies (see
    # ``background_advice_setting``). An explicit ``true`` or ``false`` always wins (#888).
    semantic_advice_enabled: bool | None = None
    semantic_advice_min_interval_seconds: int = Field(default=180, ge=1, le=86_400)

    @model_validator(mode="before")
    @classmethod
    def _validate_raw(cls, value: object) -> object:
        _reject_unknown(
            value,
            frozenset(
                {"enabled", "semantic_advice_enabled", "semantic_advice_min_interval_seconds"}
            ),
        )
        return value


class LineageSettings(StrictConfigModel):
    """Bounded delegation and liveness policy consumed by the ready lineage coordinator."""

    start_lease_seconds: int = Field(default=60, ge=1, le=86_400)
    attach_handle_ttl_seconds: int = Field(default=300, ge=1, le=86_400)
    contact_lost_recovery_seconds: int = Field(default=300, ge=1, le=86_400)
    # D6 (#1239): how long a quiet task with no parent waiting stays open as ``contact_lost``.
    # At least ``contact_lost_recovery_seconds``; at most a week.
    top_level_contact_lost_horizon_seconds: int = Field(
        default=DEFAULT_TOP_LEVEL_CONTACT_LOST_HORIZON_SECONDS, ge=1, le=604_800
    )
    # D6 (#1239): the cap on a declared quiet period; 0 records declarations without effect.
    max_declared_quiet_seconds: int = Field(
        default=DEFAULT_MAX_DECLARED_QUIET_SECONDS, ge=0, le=86_400
    )
    max_depth: int = Field(default=8, ge=0, le=64)
    max_fanout: int = Field(default=32, ge=1, le=64)

    @model_validator(mode="before")
    @classmethod
    def _validate_raw(cls, value: object) -> object:
        _reject_unknown(
            value,
            frozenset(
                {
                    "start_lease_seconds",
                    "attach_handle_ttl_seconds",
                    "contact_lost_recovery_seconds",
                    "top_level_contact_lost_horizon_seconds",
                    "max_declared_quiet_seconds",
                    "max_depth",
                    "max_fanout",
                }
            ),
        )
        return value

    @model_validator(mode="after")
    def _horizon_covers_the_child_window(self) -> LineageSettings:
        if self.top_level_contact_lost_horizon_seconds < self.contact_lost_recovery_seconds:
            raise ConfigError("config_value_invalid")
        return self


class LoggingConfig(StrictConfigModel):
    level: Literal["debug", "info", "warning", "error"] = "info"
    payloads: bool = False

    @model_validator(mode="before")
    @classmethod
    def _validate_raw(cls, value: object) -> object:
        _reject_unknown(value, frozenset({"level", "payloads"}))
        source = _mapping(value)
        if "payloads" in source and source["payloads"] is not False:
            raise ConfigError("payload_logging_forbidden")
        return value


class ProviderProfileConfig(StrictConfigModel):
    provider_id: str
    endpoint_profile_id: str
    endpoint_profile_version: str
    model: str
    capability_profile: str
    timeout_seconds: int = Field(default=60, ge=1, le=300)
    max_retries: int = Field(default=2, ge=0, le=2)
    owner_declared_endpoint: OwnerDeclaredEndpointConfig | None = None

    @model_validator(mode="before")
    @classmethod
    def _validate_raw(cls, value: object) -> object:
        _scan_secret_keys(value)
        # Free-form locators stay forbidden on the ordinary provider surface (ADR-006/014).
        locator_keys = sorted(
            key
            for key in _keys(value)
            if type(key) is str
            and key.casefold() in _LOCAL_LOCATOR_KEYS.union({"https_origin", "http_origin"})
        )
        if locator_keys:
            raise ConfigError("unknown_config_key", safe_name=locator_keys[0][:256])
        allowed = frozenset(
            {
                "provider_id",
                "endpoint_profile_id",
                "endpoint_profile_version",
                "model",
                "capability_profile",
                "timeout_seconds",
                "max_retries",
                "owner_declared_endpoint",
            }
        )
        _reject_unknown(value, allowed)
        source = _mapping(value)
        for key in (
            "provider_id",
            "endpoint_profile_id",
            "endpoint_profile_version",
            "model",
            "capability_profile",
        ):
            if key in source:
                _validate_identifier(source[key])
        return value

    @model_validator(mode="after")
    def _validate_owner_declared(self) -> ProviderProfileConfig:
        owner_declared = self.endpoint_profile_id == OWNER_DECLARED_ENDPOINT_PROFILE_ID
        if owner_declared and self.owner_declared_endpoint is None:
            raise ConfigError("owner_declared_endpoint_required")
        if not owner_declared and self.owner_declared_endpoint is not None:
            raise ConfigError("owner_declared_endpoint_forbidden")
        return self


class ExternalRuntimeProfileConfig(StrictConfigModel):
    """Exact nonsecret binding for a vendor-owned OAuth evaluator runtime.

    Paths are retained only as local service configuration.  Credential bytes remain owned by the
    selected runtime and never cross this model or any FinishUP secret/configuration surface.
    """

    provider_id: Literal["openai-codex"]
    endpoint_profile_id: Literal["codex-chatgpt-subscription"]
    endpoint_profile_version: Literal["1.0.0"]
    credential_authority: Literal["external_runtime_oauth"]
    executable_path: str
    executable_sha256: str
    runtime_version: str
    source_identity: str
    app_server_schema_sha256: str
    capability_cell_sha256: str
    isolated_config_sha256: str
    capability_profile: str
    capability_evidence_expires_at: Literal["2026-11-30T00:00:00Z"]
    codex_home: str
    model: str
    # The final-profile effort (completion reviews).  Legacy bindings carry only this field, so
    # it also serves the routine profile until ``routine_reasoning_effort`` is set explicitly.
    reasoning_effort: str
    timeout_seconds: int = Field(default=900, ge=1, le=3600)
    max_retries: int = Field(default=2, ge=0, le=2)
    # Phase-aware review budgets (issue #571, ADR-006).  ``None`` preserves the legacy single
    # effort for routine checks; new setups write the recommended bounded routine effort.
    routine_reasoning_effort: str | None = None
    # Output limits are counted in output tokens.  The names avoid the secret-key token scan.
    routine_output_limit: int = Field(
        default=CODEX_ROUTINE_OUTPUT_LIMIT_DEFAULT, ge=1, le=CODEX_OUTPUT_LIMIT_MAX
    )
    final_output_limit: int = Field(
        default=CODEX_FINAL_OUTPUT_LIMIT_DEFAULT, ge=1, le=CODEX_OUTPUT_LIMIT_MAX
    )

    @model_validator(mode="before")
    @classmethod
    def _validate_raw(cls, value: object) -> object:
        _scan_secret_keys(value)
        allowed = frozenset(
            {
                "provider_id",
                "endpoint_profile_id",
                "endpoint_profile_version",
                "credential_authority",
                "executable_path",
                "executable_sha256",
                "runtime_version",
                "source_identity",
                "app_server_schema_sha256",
                "capability_cell_sha256",
                "isolated_config_sha256",
                "capability_profile",
                "capability_evidence_expires_at",
                "codex_home",
                "model",
                "reasoning_effort",
                "timeout_seconds",
                "max_retries",
                "routine_reasoning_effort",
                "routine_output_limit",
                "final_output_limit",
            }
        )
        _reject_unknown(value, allowed)
        source = _mapping(value)
        for key in (
            "provider_id",
            "endpoint_profile_id",
            "endpoint_profile_version",
            "credential_authority",
            "runtime_version",
            "source_identity",
            "capability_profile",
            "capability_evidence_expires_at",
            "model",
            "reasoning_effort",
        ):
            if key in source:
                _validate_identifier(source[key])
        if source.get("routine_reasoning_effort") is not None:
            _validate_identifier(source["routine_reasoning_effort"])
        for key in (
            "executable_sha256",
            "app_server_schema_sha256",
            "capability_cell_sha256",
            "isolated_config_sha256",
        ):
            digest = source.get(key)
            if type(digest) is not str or _DIGEST.fullmatch(digest) is None:
                raise ConfigError("config_value_invalid", safe_name=key)
        for key in ("executable_path", "codex_home"):
            raw = source.get(key)
            if type(raw) is not str or not raw or "\x00" in raw:
                raise ConfigError("config_value_invalid", safe_name=key)
            path = Path(raw)
            if not path.is_absolute() or ".." in path.parts or str(path) != raw:
                raise ConfigError("config_value_invalid", safe_name=key)
        return value

    @property
    def effective_routine_reasoning_effort(self) -> str:
        """Routine effort in force: the explicit routine choice, else the legacy single effort."""

        if self.routine_reasoning_effort is None:
            return self.reasoning_effort
        return self.routine_reasoning_effort

    def review_budget_facts(self) -> dict[str, dict[str, str | int]]:
        """Nonsecret per-profile effort and output limit shared by status surfaces."""

        return {
            "routine": {
                "reasoning_effort": self.effective_routine_reasoning_effort,
                "output_limit": self.routine_output_limit,
                "effort_source": (
                    "legacy_single_effort"
                    if self.routine_reasoning_effort is None
                    else "configured"
                ),
            },
            "final": {
                "reasoning_effort": self.reasoning_effort,
                "output_limit": self.final_output_limit,
                "effort_source": "configured",
            },
        }


class SemanticFallbackConfig(StrictConfigModel):
    """Pair the two external AI-powered review authorities: one primary, the other its fallback.

    ``primary`` names which bound table serves first: ``api_provider`` is ``[provider]`` (vault
    API credential), ``codex_subscription`` is ``[external_runtime]`` (Codex-managed OAuth). The
    other table serves only after the primary records the closed fallback-licensing failures
    (ADR-006, issue #582). Both tables must be bound; the selector is declarative and nonsecret.
    """

    primary: Literal["api_provider", "codex_subscription"]

    @model_validator(mode="before")
    @classmethod
    def _validate_raw(cls, value: object) -> object:
        _scan_secret_keys(value)
        _reject_unknown(value, frozenset({"primary"}))
        return value


class LocalModelProfileConfig(StrictConfigModel):
    profile_id: str
    profile_version: str
    endpoint_profile_id: str
    endpoint_profile_version: str
    model: str
    protocol_version: str
    judgment_schema_version: str
    capability_digest: str
    timeout_seconds: int = Field(default=60, ge=1, le=300)

    @model_validator(mode="before")
    @classmethod
    def _validate_raw(cls, value: object) -> object:
        _scan_secret_keys(value)
        raw_keys = _keys(value)
        locator_keys = sorted(
            key for key in raw_keys if type(key) is str and key.casefold() in _LOCAL_LOCATOR_KEYS
        )
        if locator_keys:
            raise ConfigError("local_model_locator_forbidden", safe_name=locator_keys[0][:256])
        allowed = frozenset(
            {
                "profile_id",
                "profile_version",
                "endpoint_profile_id",
                "endpoint_profile_version",
                "model",
                "protocol_version",
                "judgment_schema_version",
                "capability_digest",
                "timeout_seconds",
            }
        )
        _reject_unknown(value, allowed)
        source = _mapping(value)
        for key in allowed - {"capability_digest", "timeout_seconds"}:
            if key in source:
                _validate_identifier(source[key])
        if "capability_digest" in source and (
            type(source["capability_digest"]) is not str
            or _DIGEST.fullmatch(source["capability_digest"]) is None
        ):
            raise ConfigError("config_value_invalid")
        return value


class NetworkPolicy(str, Enum):  # noqa: UP042 - frozen composition vocabulary
    DENIED = "denied"
    CANDIDATE_EXTERNAL = "candidate_external"
    EXPLICIT_PER_PROBE = "explicit_per_probe"


class SemanticPolicy(str, Enum):  # noqa: UP042 - frozen composition vocabulary
    OPTIONAL_LOCAL_MODEL = "optional_local_model"
    OPTIONAL_EXTERNAL = "optional_external"
    SCRIPTED_FAKE = "scripted_fake"
    NO_IMPLICIT_MODEL = "no_implicit_model"


@dataclass(frozen=True, slots=True)
class ProfileCapabilities:
    network: NetworkPolicy
    semantic: SemanticPolicy

    def __post_init__(self) -> None:
        if type(self.network) is not NetworkPolicy or type(self.semantic) is not SemanticPolicy:
            raise TypeError("profile_capability_wrong_type")


PROFILE_CAPABILITIES: Final[Mapping[str, ProfileCapabilities]] = MappingProxyType(
    {
        "strict-local": ProfileCapabilities(
            NetworkPolicy.DENIED, SemanticPolicy.OPTIONAL_LOCAL_MODEL
        ),
        "local-openai": ProfileCapabilities(
            NetworkPolicy.CANDIDATE_EXTERNAL, SemanticPolicy.OPTIONAL_EXTERNAL
        ),
        "codex-subscription": ProfileCapabilities(
            NetworkPolicy.CANDIDATE_EXTERNAL, SemanticPolicy.OPTIONAL_EXTERNAL
        ),
        "test-fake": ProfileCapabilities(NetworkPolicy.DENIED, SemanticPolicy.SCRIPTED_FAKE),
        "release-probe": ProfileCapabilities(
            NetworkPolicy.EXPLICIT_PER_PROBE, SemanticPolicy.NO_IMPLICIT_MODEL
        ),
    }
)


# Imported only after ConfigError and the shared strict base exist; config/privacy.py uses both.
from finishup.config.privacy import PrivacyBootstrapConfig  # noqa: E402


class FinishUpConfig(StrictConfigModel):
    schema_version: Literal["1"] = "1"
    profile: Literal[
        "strict-local",
        "local-openai",
        "codex-subscription",
        "test-fake",
        "release-probe",
    ] = "strict-local"
    storage: StorageConfig = Field(default_factory=StorageConfig)
    verification: VerificationConfig = Field(default_factory=VerificationConfig)
    observation: ObservationConfig = Field(default_factory=ObservationConfig)
    lineage: LineageSettings = Field(default_factory=LineageSettings)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    privacy: PrivacyBootstrapConfig = Field(default_factory=PrivacyBootstrapConfig)
    provider: ProviderProfileConfig | None = None
    external_runtime: ExternalRuntimeProfileConfig | None = None
    local_model: LocalModelProfileConfig | None = None
    semantic_fallback: SemanticFallbackConfig | None = None

    @model_validator(mode="before")
    @classmethod
    def _validate_raw(cls, value: object) -> object:
        allowed = frozenset(
            {
                "schema_version",
                "profile",
                "storage",
                "verification",
                "observation",
                "lineage",
                "logging",
                "privacy",
                "provider",
                "external_runtime",
                "local_model",
                "semantic_fallback",
            }
        )
        _reject_unknown(value, allowed)
        source = _mapping(value)
        if "schema_version" in source and source["schema_version"] != "1":
            raise ConfigError("config_schema_unsupported")
        for section in ("provider", "external_runtime", "local_model", "privacy"):
            raw_section = source.get(section)
            if isinstance(raw_section, Mapping):
                _scan_secret_keys(cast(Mapping[object, object], raw_section))
        return value

    @model_validator(mode="after")
    def _validate_profile(self) -> FinishUpConfig:
        if self.semantic_fallback is not None:
            # A declared pairing binds both authorities at once; the profile names the primary.
            # Every single-endpoint exclusivity rule below is therefore replaced by these three.
            if self.provider is None or self.external_runtime is None:
                raise ConfigError("semantic_fallback_endpoint_missing")
            if self.local_model is not None:
                raise ConfigError("external_runtime_forbids_local_model")
            expected = (
                "codex-subscription"
                if self.semantic_fallback.primary == "codex_subscription"
                else "local-openai"
            )
            if self.profile != expected:
                raise ConfigError("semantic_fallback_profile_mismatch")
            return self
        if self.profile == "strict-local" and (
            self.provider is not None or self.external_runtime is not None
        ):
            raise ConfigError("strict_local_forbids_provider")
        if self.profile == "local-openai" and self.local_model is not None:
            raise ConfigError("external_profile_forbids_local_model")
        if self.profile == "test-fake" and self.provider is not None:
            raise ConfigError("test_fake_forbids_provider")
        if self.profile == "test-fake" and self.local_model is not None:
            raise ConfigError("test_fake_forbids_local_model")
        if self.profile != "codex-subscription" and self.external_runtime is not None:
            raise ConfigError("external_runtime_forbids_provider")
        if self.profile == "codex-subscription" and self.provider is not None:
            raise ConfigError("external_runtime_forbids_provider")
        if self.profile == "codex-subscription" and self.local_model is not None:
            raise ConfigError("external_runtime_forbids_local_model")
        if (
            self.profile == "codex-subscription"
            and self.verification.semantic != "disabled"
            and self.external_runtime is None
        ):
            raise ConfigError("external_runtime_required_for_semantic")
        if (
            self.profile == "local-openai"
            and self.verification.semantic != "disabled"
            and self.provider is None
        ):
            raise ConfigError("provider_required_for_semantic")
        return self


type ExternalEndpointConfig = ProviderProfileConfig | ExternalRuntimeProfileConfig


def primary_external_endpoint(config: FinishUpConfig) -> ExternalEndpointConfig | None:
    """Return the bound external endpoint that serves AI-powered review first.

    Without a ``[semantic_fallback]`` pairing this is the single bound table (at most one is
    bound). With a pairing it is the table the selector names as primary.
    """

    if type(config) is not FinishUpConfig:
        raise TypeError("config_wrong_type")
    if config.semantic_fallback is None:
        return config.provider if config.provider is not None else config.external_runtime
    if config.semantic_fallback.primary == "codex_subscription":
        return config.external_runtime
    return config.provider


def fallback_external_endpoint(config: FinishUpConfig) -> ExternalEndpointConfig | None:
    """Return the bound endpoint that serves only after the primary fails, or ``None``."""

    if type(config) is not FinishUpConfig:
        raise TypeError("config_wrong_type")
    if config.semantic_fallback is None:
        return None
    if config.semantic_fallback.primary == "codex_subscription":
        return config.provider
    return config.external_runtime


type BackgroundAdviceReason = Literal[
    "owner_enabled",
    "owner_disabled",
    "default_enabled",
    "semantic_review_disabled",
    "observation_disabled",
]


@dataclass(frozen=True, slots=True)
class BackgroundAdviceSetting:
    """Whether background AI-powered observation advice may be scheduled, and why (#888)."""

    enabled: bool
    reason: BackgroundAdviceReason


def background_advice_setting(config: FinishUpConfig) -> BackgroundAdviceSetting:
    """Resolve the effective background-advice switch from the owner's configuration.

    Unless the owner sets ``[observation] semantic_advice_enabled``, background advice is on
    wherever AI-powered review is configured (``verification.semantic`` ``required`` or
    ``optional``); this is the maintainer's recorded decision on issue #888 (2026-09-30). An
    explicit value always wins, so ``false`` turns it off; observation or AI-powered review being
    off leaves nothing to enable. Provider readiness is a separate, live fact read by the service
    on every build (#923).
    """

    if type(config) is not FinishUpConfig:
        raise TypeError("config_wrong_type")
    if not config.observation.enabled:
        return BackgroundAdviceSetting(False, "observation_disabled")
    if config.verification.semantic == "disabled":
        return BackgroundAdviceSetting(False, "semantic_review_disabled")
    chosen = config.observation.semantic_advice_enabled
    if chosen is True:
        return BackgroundAdviceSetting(True, "owner_enabled")
    if chosen is False:
        return BackgroundAdviceSetting(False, "owner_disabled")
    return BackgroundAdviceSetting(True, "default_enabled")
