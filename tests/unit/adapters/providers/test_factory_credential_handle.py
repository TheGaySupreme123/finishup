"""The bundled factories must accept a real one-attempt credential handle (issue #802 finding).

``ProviderCredentialHandle`` is a Protocol. An exact ``type(credential) is`` comparison against it
never holds for any real object, so after #480 every API-provider dispatch through the Responses
and Chat Completions factories was refused before a request existed, and the public result read
``unavailable / receipt_persistence_unknown``. These tests drive the real factories from the real
config presets with a handle shaped like the vault's and lock the accept/refuse boundary.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any, cast

import pytest

from finishup.adapters.providers.factory import external_factory_builders_from_config
from finishup.adapters.providers.openai_responses_factory import provider_binding_from_config
from finishup.config.models import ProviderProfileConfig
from finishup.config.write import anthropic_provider, fireworks_provider
from finishup.domain.privacy import ApprovedOutboundCase, DataCategory
from finishup.ports.secret_memory import (
    ProviderAttemptAuthBinding,
    ProviderAuthTransportCallback,
    ProviderCredentialHandle,
)
from finishup.ports.semantic import ExternalRuntimeAuthority
from finishup.protocol.canonical import canonical_digest, canonical_encode

_DIGEST = "sha256:" + "c" * 64


class _Clock:
    def now_utc(self) -> datetime:
        return datetime(2026, 9, 23, tzinfo=UTC)

    def monotonic_seconds(self) -> float:
        return 0.0


class _VaultLikeHandle:
    """Shaped like ``finishup.service.vault._ProviderHandle``: only ``authorize_attempt``."""

    async def authorize_attempt[T](
        self,
        binding: ProviderAttemptAuthBinding,
        inject_and_start: ProviderAuthTransportCallback[T],
    ) -> T:
        raise AssertionError("never dispatched in this test")


def _case(provider: ProviderProfileConfig) -> ApprovedOutboundCase:
    payload = canonical_encode({"schema": "yoetz.semantic-check-candidate/1"})
    return ApprovedOutboundCase(
        case_id="cas_80000000-0000-4000-8000-000000000001",
        request_id="req_80000000-0000-4000-8000-000000000001",
        payload=payload,
        media_type="application/json",
        schema_id="yoetz-semantic-case-1.0.0",
        included_item_ids=("case-packet",),
        approved_categories=(DataCategory.BOUNDED_STRUCTURAL_METADATA,),
        blocked_categories=(),
        byte_count=len(payload),
        token_count=8,
        provider_binding=provider_binding_from_config(provider),
        purpose="semantic-review",
        authorization_id="aut_80000000-0000-4000-8000-000000000001",
        policy_digest=_DIGEST,
        case_digest="sha256:" + "d" * 64,
    )


def _attempt(provider: ProviderProfileConfig, body: bytes) -> ProviderAttemptAuthBinding:
    return ProviderAttemptAuthBinding(
        provider_id=provider.provider_id,
        model_id=provider.model,
        endpoint_profile_id=provider.endpoint_profile_id,
        endpoint_profile_version=provider.endpoint_profile_version,
        purpose="semantic-review",
        authorization_scope_digest=_DIGEST,
        purpose_digest=canonical_digest({"purpose": "semantic-review"}),
        dispatch_id="dsp_80000000-0000-4000-8000-000000000001",
        request_body_digest="sha256:" + hashlib.sha256(body).hexdigest(),
        service_generation=1,
        monotonic_deadline=30.0,
    )


def _factory(provider: ProviderProfileConfig) -> Any:
    builders = external_factory_builders_from_config(provider, clock=cast(Any, _Clock()))
    builder = builders[provider_binding_from_config(provider)]
    return cast(Any, builder)()


@pytest.mark.parametrize(
    "provider",
    [
        fireworks_provider(model="accounts/fireworks/models/glm-5p3-flash"),
        anthropic_provider(model="claude-sonnet-4-6"),
    ],
    ids=["fireworks-responses", "anthropic-openai-chat-completions"],
)
def test_bundled_factories_accept_a_vault_shaped_credential_handle(
    provider: ProviderProfileConfig,
) -> None:
    factory = _factory(provider)
    body = factory.render(_case(provider))
    handle = _VaultLikeHandle()
    assert isinstance(handle, ProviderCredentialHandle)

    evaluator = factory.build_evaluator(_attempt(provider, body), handle, object())

    assert evaluator is not None


@pytest.mark.parametrize(
    ("provider", "token"),
    [
        (
            fireworks_provider(model="accounts/fireworks/models/glm-5p3-flash"),
            "openai_credential_authority_invalid",
        ),
        (
            anthropic_provider(model="claude-sonnet-4-6"),
            "chat_completions_credential_authority_invalid",
        ),
    ],
    ids=["fireworks-responses", "anthropic-openai-chat-completions"],
)
def test_bundled_factories_still_refuse_the_vendor_oauth_authority(
    provider: ProviderProfileConfig, token: str
) -> None:
    factory = _factory(provider)
    body = factory.render(_case(provider))
    authority = ExternalRuntimeAuthority(
        dispatch_id="dsp_80000000-0000-4000-8000-000000000002",
        request_body_digest="sha256:" + hashlib.sha256(body).hexdigest(),
        request_commitment="hmac-sha256:" + "e" * 64,
        service_generation=1,
        monotonic_deadline=30.0,
    )
    assert not isinstance(authority, ProviderCredentialHandle)

    with pytest.raises(ValueError, match=token):
        factory.build_evaluator(_attempt(provider, body), authority, object())
