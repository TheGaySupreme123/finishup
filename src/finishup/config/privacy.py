"""Fail-closed first-run privacy bootstrap configuration."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final, Literal, cast

from pydantic import Field, model_validator

from finishup.config.models import ConfigError, StrictConfigModel
from finishup.domain.privacy import (
    PrivacyPolicy,
    ReviewContextProfile,
    ReviewSelectionPolicy,
)
from finishup.ports.privacy import PrivacyPolicyStorePort

__all__ = ["PrivacyBootstrapConfig", "safe_privacy_bootstrap", "seed_policy_if_absent"]

_CHANNEL_NAMES: Final = frozenset(
    {
        "llm_inference",
        "product_telemetry",
        "crash_diagnostics",
        "update_checks",
        "capability_testing",
    }
)
_BOOTSTRAP_KEYS: Final = frozenset(
    {
        "profile",
        "review_context_profile",
        "review_selection",
        "require_current_provider_data_use_evidence",
        "network_egress_permitted",
        "channel_policies",
        "local_model_enabled",
    }
)
_LOCATOR_KEYS: Final = frozenset(
    {"base_url", "endpoint_url", "host", "port", "socket", "socket_path", "url"}
)


def _structural_selection() -> ReviewSelectionPolicy:
    return ReviewSelectionPolicy.for_profile(ReviewContextProfile.STRUCTURAL)


def _selection_mapping(value: ReviewSelectionPolicy) -> dict[str, object]:
    return {
        "sections": list(value.sections),
        "excerpt_kinds": list(value.excerpt_kinds),
        "relevance": value.relevance,
        "include_finding_prose": value.include_finding_prose,
        "include_exact_command_text": value.include_exact_command_text,
        "max_timeline_items": value.max_timeline_items,
        "max_assessments": value.max_assessments,
        "max_change_observations": value.max_change_observations,
        "max_excerpts": value.max_excerpts,
        "max_omissions": value.max_omissions,
        "max_excerpt_bytes": value.max_excerpt_bytes,
        "max_total_excerpt_bytes": value.max_total_excerpt_bytes,
    }


_SAFE_SELECTION: Final = _structural_selection()
_SAFE_SELECTION_MAPPING: Final = _selection_mapping(_SAFE_SELECTION)


def _string_mapping(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise ConfigError("privacy_bootstrap_unsafe")
    source = cast(Mapping[object, object], value)
    try:
        keys = tuple(source.keys())
    except Exception as exc:
        raise ConfigError("privacy_bootstrap_unsafe") from exc
    if any(type(key) is not str for key in keys):
        raise ConfigError("privacy_bootstrap_unsafe")
    result: dict[str, object] = {}
    for key in cast(tuple[str, ...], keys):
        try:
            result[key] = source[key]
        except Exception as exc:
            raise ConfigError("privacy_bootstrap_unsafe") from exc
    return result


class _BootstrapChannelPolicies(StrictConfigModel):
    llm_inference: Literal[False] = False
    product_telemetry: Literal[False] = False
    crash_diagnostics: Literal[False] = False
    update_checks: Literal[False] = False
    capability_testing: Literal[False] = False

    @model_validator(mode="before")
    @classmethod
    def _closed_denied_rows(cls, value: object) -> object:
        source = _string_mapping(value)
        if set(source) != set(_CHANNEL_NAMES) or any(item is not False for item in source.values()):
            raise ConfigError("privacy_bootstrap_unsafe")
        return cast(object, source)


def _safe_channels() -> _BootstrapChannelPolicies:
    return _BootstrapChannelPolicies(
        llm_inference=False,
        product_telemetry=False,
        crash_diagnostics=False,
        update_checks=False,
        capability_testing=False,
    )


class PrivacyBootstrapConfig(StrictConfigModel):
    """The sole accepted v0.1 first-run seed: all disclosure denied."""

    profile: Literal["local_only"] = "local_only"
    review_context_profile: Literal["structural"] = "structural"
    review_selection: ReviewSelectionPolicy = Field(default_factory=_structural_selection)
    require_current_provider_data_use_evidence: Literal[False] = False
    network_egress_permitted: Literal[False] = False
    channel_policies: _BootstrapChannelPolicies = Field(default_factory=_safe_channels)
    local_model_enabled: Literal[False] = False

    @model_validator(mode="before")
    @classmethod
    def _exact_safe_seed(cls, value: object) -> object:
        source = _string_mapping(value)
        keys = tuple(source)
        if not keys:
            return {}

        secret_keys = sorted(
            key
            for key in keys
            if any(
                token in key.casefold()
                for token in ("api_key", "apikey", "token", "secret", "password")
            )
        )
        if secret_keys:
            raise ConfigError("secret_in_config", safe_name=secret_keys[0][:256])
        if any(key.casefold() in _LOCATOR_KEYS for key in keys):
            raise ConfigError("privacy_bootstrap_unsafe")
        if set(keys) != set(_BOOTSTRAP_KEYS):
            unknown = sorted(key for key in keys if key not in _BOOTSTRAP_KEYS)
            raise ConfigError("unknown_config_key", safe_name=unknown[0][:256] if unknown else None)

        exact_scalars = (
            source["profile"] == "local_only"
            and type(source["profile"]) is str
            and source["review_context_profile"] == "structural"
            and type(source["review_context_profile"]) is str
            and source["require_current_provider_data_use_evidence"] is False
            and source["network_egress_permitted"] is False
            and source["local_model_enabled"] is False
        )
        if not exact_scalars:
            raise ConfigError("privacy_bootstrap_unsafe")

        selection = source["review_selection"]
        if type(selection) is ReviewSelectionPolicy:
            if selection != _SAFE_SELECTION:
                raise ConfigError("privacy_bootstrap_unsafe")
        elif isinstance(selection, Mapping):
            if _string_mapping(cast(object, selection)) != _SAFE_SELECTION_MAPPING:
                raise ConfigError("privacy_bootstrap_unsafe")
        else:
            raise ConfigError("privacy_bootstrap_unsafe")

        channels = source["channel_policies"]
        if type(channels) is _BootstrapChannelPolicies:
            normalized_channels = channels
        else:
            normalized_channels = _BootstrapChannelPolicies.model_validate(channels, strict=True)

        return {
            "profile": "local_only",
            "review_context_profile": "structural",
            "review_selection": _SAFE_SELECTION,
            "require_current_provider_data_use_evidence": False,
            "network_egress_permitted": False,
            "channel_policies": normalized_channels,
            "local_model_enabled": False,
        }


def safe_privacy_bootstrap() -> PrivacyBootstrapConfig:
    """Return a fresh immutable all-denied first-run bootstrap."""

    return PrivacyBootstrapConfig()


async def seed_policy_if_absent(
    policy: PrivacyPolicy, store: PrivacyPolicyStorePort
) -> PrivacyPolicy:
    """Delegate one fully materialized denied policy to the atomic policy store."""

    if type(policy) is not PrivacyPolicy:
        raise TypeError("privacy_seed_policy_wrong_type")
    return await store.seed_if_absent(policy)
