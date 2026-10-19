"""Credential-free ExternalProviderFactory for OpenAI Responses (and compatible hosts)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from finishup.adapters.privacy.gateway import ExternalProviderFactory
from finishup.adapters.providers.data_use_catalog import (
    data_use_record_for_endpoint,
    endpoint_profile_data_use_recommendation_eligible,
)
from finishup.adapters.providers.openai_responses import (
    OneAttemptCredentialTransport,
    OpenAIProfile,
    OpenAIResponsesEvaluator,
    RenderedOpenAIRequest,
    render_case,
)
from finishup.adapters.providers.reviewer_reply import REVIEWER_REPLY_SCHEMAS
from finishup.config.models import (
    OFFICIAL_OPENAI_ENDPOINT_PROFILE_ID,
    OWNER_DECLARED_ENDPOINT_PROFILE_ID,
    ProviderProfileConfig,
    parse_https_origin,
)
from finishup.domain.privacy import ApprovedOutboundCase, ProviderBinding
from finishup.ports.clock import ClockPort
from finishup.ports.secret_memory import ProviderAttemptAuthBinding, ProviderCredentialHandle
from finishup.ports.semantic import (
    ExternalRuntimeAuthority,
    ReviewerReplySchemas,
    SemanticEvaluatorPort,
)

__all__ = [
    "OpenAIResponsesExternalFactory",
    "endpoint_profile_data_use_reviewed",
    "external_factory_builders_from_config",
    "openai_profile_from_provider_config",
    "provider_binding_from_config",
]


def endpoint_profile_data_use_reviewed(endpoint_profile_id: str, *, now: datetime) -> bool:
    """True when this endpoint profile ships recommendation-eligible provider data-use evidence.

    A policy that sets ``require_current_provider_data_use_evidence`` against a profile this
    returns ``False`` for cannot dispatch external AI-powered review at all, so setup surfaces the
    pairing before the operator commits it rather than at first dispatch.
    """

    return endpoint_profile_data_use_recommendation_eligible(endpoint_profile_id, now=now)


def provider_binding_from_config(provider: ProviderProfileConfig) -> ProviderBinding:
    return ProviderBinding(
        provider.provider_id,
        provider.model,
        provider.endpoint_profile_id,
        provider.endpoint_profile_version,
        "external",
    )


def openai_profile_from_provider_config(
    provider: ProviderProfileConfig, *, now: datetime
) -> OpenAIProfile:
    """Build the exact nonsecret OpenAIProfile for an allowed config binding."""

    timeout = provider.timeout_seconds
    if provider.endpoint_profile_id == OFFICIAL_OPENAI_ENDPOINT_PROFILE_ID:
        return OpenAIProfile(
            provider_id=provider.provider_id,
            model=provider.model,
            endpoint_profile_id=provider.endpoint_profile_id,
            endpoint_profile_version=provider.endpoint_profile_version,
            timeout_seconds=timeout,
            supports_structured_outputs=True,
            data_use_profile=data_use_record_for_endpoint(provider.endpoint_profile_id).profile,
        )
    if provider.endpoint_profile_id == "fireworks-responses":
        return OpenAIProfile(
            provider_id=provider.provider_id,
            model=provider.model,
            endpoint_profile_id=provider.endpoint_profile_id,
            endpoint_profile_version=provider.endpoint_profile_version,
            timeout_seconds=timeout,
            supports_structured_outputs=True,
            data_use_profile=data_use_record_for_endpoint(provider.endpoint_profile_id).profile,
            host="api.fireworks.ai",
            base_path_prefix="/inference/v1",
        )
    if provider.endpoint_profile_id == "vercel-ai-gateway-openai-responses":
        # The AI Gateway speaks the OpenAI Responses protocol on its own host, so it needs no
        # adapter of its own — only its endpoint facts and an unknown data-use record.
        return OpenAIProfile(
            provider_id=provider.provider_id,
            model=provider.model,
            endpoint_profile_id=provider.endpoint_profile_id,
            endpoint_profile_version=provider.endpoint_profile_version,
            timeout_seconds=timeout,
            supports_structured_outputs=True,
            data_use_profile=data_use_record_for_endpoint(provider.endpoint_profile_id).profile,
            host="ai-gateway.vercel.sh",
            base_path_prefix="/v1",
        )
    if provider.endpoint_profile_id == OWNER_DECLARED_ENDPOINT_PROFILE_ID:
        if provider.owner_declared_endpoint is None:
            raise ValueError("owner_declared_endpoint_required")
        host, port = parse_https_origin(provider.owner_declared_endpoint.https_origin)
        return OpenAIProfile(
            provider_id=provider.provider_id,
            model=provider.model,
            endpoint_profile_id=provider.endpoint_profile_id,
            endpoint_profile_version=provider.endpoint_profile_version,
            timeout_seconds=timeout,
            supports_structured_outputs=True,
            data_use_profile=data_use_record_for_endpoint(provider.endpoint_profile_id).profile,
            host=host,
            port=port,
            base_path_prefix="/v1",
        )
    raise ValueError("provider_endpoint_profile_unsupported")


@dataclass
class OpenAIResponsesExternalFactory:
    """Render + one-attempt evaluator factory installed by ready composition."""

    profile: OpenAIProfile
    clock: ClockPort
    credential_authority: str = "finishup_vault_api_credential"
    reply_schemas: ReviewerReplySchemas | None = None

    def __post_init__(self) -> None:
        self._last_rendered: RenderedOpenAIRequest | None = None

    def render(self, case: ApprovedOutboundCase) -> bytes:
        rendered = render_case(case, self.reply_schemas)
        self._last_rendered = rendered
        return rendered.body

    def build_evaluator(
        self,
        binding: ProviderAttemptAuthBinding,
        credential: ProviderCredentialHandle | ExternalRuntimeAuthority,
        request_commitment: object,
    ) -> SemanticEvaluatorPort:
        del request_commitment
        # `ProviderCredentialHandle` is a Protocol: an exact `type(...) is` comparison never holds
        # for a real vault handle, which refused every API-provider dispatch after #480 (found by
        # the dogfood lane, #802). The runtime-checkable Protocol admits any one-attempt handle
        # and still excludes the vendor OAuth authority, which carries no `authorize_attempt`.
        if not isinstance(credential, ProviderCredentialHandle):
            raise ValueError("openai_credential_authority_invalid")
        rendered = self._last_rendered
        if rendered is None or binding.request_body_digest != rendered.body_sha256:
            raise ValueError("openai_factory_render_required")
        transport = OneAttemptCredentialTransport(
            rendered=rendered,
            credential=credential,
            binding=binding,
            host=self.profile.host,
            port=self.profile.port,
            path=self.profile.path,
        )
        return OpenAIResponsesEvaluator(
            self.profile, transport, self.clock, reply_schemas=self.reply_schemas
        )


def external_factory_builders_from_config(
    provider: ProviderProfileConfig | None, *, clock: ClockPort
) -> dict[ProviderBinding, object]:
    """Return builders only for the Responses-protocol endpoint profiles.

    Chat Completions profiles are dispatched by `adapters/providers/factory.py`; this module stays
    Responses-only so neither adapter has to carry the other's request shape.
    """

    if provider is None:
        return {}
    allowed = {
        OFFICIAL_OPENAI_ENDPOINT_PROFILE_ID,
        "fireworks-responses",
        OWNER_DECLARED_ENDPOINT_PROFILE_ID,
        "vercel-ai-gateway-openai-responses",
    }
    if provider.endpoint_profile_id not in allowed:
        return {}
    binding = provider_binding_from_config(provider)
    now = clock.now_utc()

    def _builder() -> ExternalProviderFactory:
        profile = openai_profile_from_provider_config(provider, now=now)
        return OpenAIResponsesExternalFactory(profile, clock, reply_schemas=REVIEWER_REPLY_SCHEMAS)

    return {binding: _builder}
