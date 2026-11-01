"""Bounded, nonsecret disclosure of the policy route's AI-powered review destination.

Issue #479. A host's automatic tool-call reviewer reads the initialize ``instructions`` (Codex
copies them into every tool description) and, before this module, saw only "external AI-powered
review follows the configured policy": no destination class and no payload bound. This module
renders one bounded passage from the configuration the bridge reads at startup so the reviewer can
score the call from a named destination rather than from nothing.

Every rendered value is either a closed catalog token owned by this module, a ``Literal`` field of
the validated configuration model, or a hostname that already passed the owner-declared HTTPS
origin validator. Nothing else from configuration reaches the text: no secret, filesystem path,
URL, query string, repository handle, or free-form prose. Absent, unreadable, or invalid
configuration renders as *unknown*, and an endpoint profile outside the bundled catalog renders as
an unknown destination rather than a guessed one. A configured fallback endpoint is disclosed
beside the primary because a reviewer told "only the primary can receive data" would be misled.

The passage carries no authority. It cannot admit the call (the ADR-018 amendment for #467 keeps
admission with the owner's trusted host configuration), cannot widen privacy policy, and does not
prove that a dispatch happened. It is stamped "read once at bridge startup": the bridge process
has one immutable route profile (ADR-018 decision 1) and reads configuration once, so a route
change after startup is reflected only after the host restarts the bridge; the live authority for
what a particular check did is that check's recorded ``semantic_status`` and provider attempt.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Literal

from finishup.config.load import load_config, parse_minimal_safe_config
from finishup.config.models import (
    OWNER_DECLARED_ENDPOINT_PROFILE_ID,
    ExternalEndpointConfig,
    ExternalRuntimeProfileConfig,
    FinishUpConfig,
    ProviderProfileConfig,
    fallback_external_endpoint,
    primary_external_endpoint,
)

__all__ = [
    "BUNDLED_ENDPOINT_HOSTS",
    "DISCLOSABLE_PROVIDER_IDS",
    "DISCLOSURE_PREFIX",
    "MAX_DISCLOSURE_ENCODED_BYTES",
    "SemanticDestinationDisclosure",
    "SemanticDestinationKind",
    "disclose_semantic_destination",
    "read_semantic_destination_disclosure",
]

type SemanticDestinationKind = Literal["unknown", "none", "external"]

# The exact host each bundled endpoint profile stands for. This table is the disclosure's own
# closed catalog; a unit test locks it to the adapter catalogs that actually dial these hosts
# (`adapters/providers/factory.py`, `adapters/providers/openai_responses_factory.py`), so the
# passage can never name a host the dispatch path does not use.
BUNDLED_ENDPOINT_HOSTS: Final[Mapping[str, str]] = MappingProxyType(
    {
        "anthropic-openai-chat-completions": "api.anthropic.com",
        "fireworks-responses": "api.fireworks.ai",
        "google-gemini-openai-chat-completions": "generativelanguage.googleapis.com",
        "openai-responses": "api.openai.com",
        "openrouter-openai-chat-completions": "openrouter.ai",
        "vercel-ai-gateway-openai-responses": "ai-gateway.vercel.sh",
        "xai-openai-chat-completions": "api.x.ai",
    }
)

# Provider identifiers the passage may echo verbatim: the bundled preset ids plus the two fixed
# ids of the owner-declared and Codex-subscription bindings. Any other (schema-valid) identifier
# is user-authored prose as far as this surface is concerned and is rendered as unlisted.
DISCLOSABLE_PROVIDER_IDS: Final[frozenset[str]] = frozenset(
    {
        "anthropic",
        "fireworks",
        "google",
        "openai",
        "openai-codex",
        "openai-compatible",
        "openrouter",
        "vercel-ai-gateway",
        "xai",
    }
)

# Ceiling on the passage this module can emit. The longest shape is an owner-declared primary with
# a maximum-length hostname and explicit port plus a Codex fallback; a unit test renders exactly
# that and asserts it fits, and `SERVER_INSTRUCTIONS_BUDGET` adds this allowance to the packaged
# text's own bound, so the initialize-instructions budget stays reviewable as two numbers.
MAX_DISCLOSURE_ENCODED_BYTES: Final = 1_000

DISCLOSURE_PREFIX: Final = "AI-powered review destination, read once at bridge startup: "

_HOSTNAME: Final = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$",
    re.ASCII,
)
_PAYLOAD_BOUND: Final = (
    " The payload is a review packet composed from this ledger under the owner's standing "
    "privacy policy with no repository handle; every other operation writes only the local "
    "ledger on this machine."
)
_SNAPSHOT_BOUND: Final = " This configuration snapshot may differ from the live service."
_UNKNOWN_SENTENCE: Final = (
    DISCLOSURE_PREFIX
    + "unknown, because the configuration was absent or invalid. A policy-route check may reach "
    "an external reviewer whose destination this bridge could not determine."
)


@dataclass(frozen=True, slots=True)
class SemanticDestinationDisclosure:
    """One rendered disclosure. Only this module composes the text; callers never author it."""

    kind: SemanticDestinationKind
    sentence: str

    def __post_init__(self) -> None:
        if self.kind not in {"unknown", "none", "external"}:
            raise ValueError("semantic_destination_kind_invalid")
        if type(self.sentence) is not str or not self.sentence.startswith(DISCLOSURE_PREFIX):
            raise ValueError("semantic_destination_sentence_invalid")
        if len(self.sentence.encode("utf-8")) > MAX_DISCLOSURE_ENCODED_BYTES:
            raise ValueError("semantic_destination_sentence_too_long")


def _none(reason: str) -> SemanticDestinationDisclosure:
    return SemanticDestinationDisclosure(
        "none",
        DISCLOSURE_PREFIX + f"none in this configuration; {reason}." + _SNAPSHOT_BOUND,
    )


def _provider_label(provider_id: str) -> str:
    if provider_id in DISCLOSABLE_PROVIDER_IDS:
        return f"provider {provider_id}"
    return "an unlisted provider id"


def _api_provider_phrase(endpoint: ProviderProfileConfig) -> str:
    label = _provider_label(endpoint.provider_id)
    profile_id = endpoint.endpoint_profile_id
    if profile_id == OWNER_DECLARED_ENDPOINT_PROFILE_ID:
        declared = endpoint.owner_declared_endpoint
        host = declared.host if declared is not None else ""
        if declared is None or _HOSTNAME.fullmatch(host) is None:
            return (
                f"{label} (endpoint profile {profile_id}) with an owner-declared host that could "
                "not be rendered, so the destination host is unknown"
            )
        rendered_host = host if declared.port == 443 else f"{host}:{declared.port}"
        return (
            f"{label} (endpoint profile {profile_id}, owner-declared host {rendered_host}) over "
            "HTTPS with the owner's vault-held API credential"
        )
    host = BUNDLED_ENDPOINT_HOSTS.get(profile_id)
    if host is None:
        return (
            f"{label} with an endpoint profile outside the bundled catalog, so the destination "
            "host is unknown"
        )
    return (
        f"{label} (endpoint profile {profile_id}, host {host}) over HTTPS with the owner's "
        "vault-held API credential"
    )


def _external_runtime_phrase(endpoint: ExternalRuntimeProfileConfig) -> str:
    # Both identifiers are ``Literal`` fields of the validated model, so they are closed tokens.
    return (
        f"provider {endpoint.provider_id} (endpoint profile {endpoint.endpoint_profile_id}) "
        "through the locally installed Codex runtime under its own ChatGPT login, which chooses "
        "the upstream OpenAI host that FinishUP does not name"
    )


def _endpoint_phrase(endpoint: ExternalEndpointConfig) -> str:
    if isinstance(endpoint, ExternalRuntimeProfileConfig):
        return _external_runtime_phrase(endpoint)
    return _api_provider_phrase(endpoint)


def disclose_semantic_destination(
    config: FinishUpConfig | None,
) -> SemanticDestinationDisclosure:
    """Render the destination the policy route would dispatch to under ``config``.

    ``None`` means the bridge could not obtain a validated configuration and renders as unknown.
    The function reads only validated model fields; it never touches the environment, the file
    system, the vault, or the service.
    """

    if config is None:
        return SemanticDestinationDisclosure("unknown", _UNKNOWN_SENTENCE)
    if type(config) is not FinishUpConfig:
        raise TypeError("config_wrong_type")
    if config.verification.semantic == "disabled":
        return _none("verification.semantic is disabled")
    primary = primary_external_endpoint(config)
    if primary is None:
        if config.local_model is not None:
            return _none("only a local model daemon on this machine is bound")
        return _none(f"no external endpoint is bound under the {config.profile} profile")
    sentence = DISCLOSURE_PREFIX + _endpoint_phrase(primary) + "."
    fallback = fallback_external_endpoint(config)
    if fallback is not None:
        sentence += f" Fallback after primary failure: {_endpoint_phrase(fallback)}."
    return SemanticDestinationDisclosure("external", sentence + _PAYLOAD_BOUND + _SNAPSHOT_BOUND)


def read_semantic_destination_disclosure(
    env: Mapping[str, str] | None = None,
) -> SemanticDestinationDisclosure:
    """Load the bridge's configuration once and render its disclosure; never raise.

    Mirrors ``_bridge_logging_config`` in ``mcp/server.py``: an unreadable or invalid
    configuration must never keep the bridge from serving, and here it must not be guessed at
    either, so every failure renders as unknown.
    """

    try:
        selected_env = os.environ if env is None else env
        if parse_minimal_safe_config(selected_env, {}).config_path_used is None:
            return disclose_semantic_destination(None)
        config = load_config({}, selected_env, None)
        return disclose_semantic_destination(config)
    except Exception:
        # Rendering is inside the guard too: a wording change that pushed the sentence past its
        # bound (a 253-character host) must render "unknown", not keep the bridge from starting
        # (tb4n3 A10).
        return disclose_semantic_destination(None)
