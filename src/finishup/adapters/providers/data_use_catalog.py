"""Versioned, package-owned provider data-use evidence.

The catalog is deliberately static. A daemon start may determine whether a record has
expired, but it must never create a newer review date or extend an evidence lifetime.
Each entry is bound to one endpoint profile; gateways and owner-declared endpoints never
inherit another provider's posture.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Final, Literal

from finishup.domain.privacy import ProviderDataUseProfile
from finishup.protocol.canonical import canonical_digest

__all__ = [
    "ProviderDataUseRecord",
    "data_use_record_for_endpoint",
    "endpoint_profile_data_use_recommendation_eligible",
]


@dataclass(frozen=True, slots=True)
class ProviderDataUseRecord:
    """One reviewed, route-specific provider data-use record."""

    endpoint_profile_id: str
    route_qualifier: str
    official_source_urls: tuple[str, ...]
    caveats: tuple[str, ...]
    profile: ProviderDataUseProfile


_REVIEWED_AT: Final = datetime(2026, 8, 4, tzinfo=UTC)
_EXPIRES_AT: Final = datetime(2026, 11, 4, tzinfo=UTC)


def _profile(
    profile_id: str,
    *,
    training: Literal["prohibited", "permitted", "unknown"],
    retention: Literal["none", "bounded", "unbounded", "unknown"],
    retention_days: int | None,
    human_access: Literal["prohibited", "restricted", "permitted", "unknown"],
    sources: tuple[str, ...],
    route_qualifier: str,
    caveats: tuple[str, ...],
) -> ProviderDataUseProfile:
    """Build the fixed profile whose digest binds all displayed evidence facts."""

    return ProviderDataUseProfile(
        data_use_profile_id=profile_id,
        data_use_profile_version="2026.08.04",
        customer_content_training=training,
        retention=retention,
        retention_days_ceiling=retention_days,
        provider_human_access=human_access,
        reviewed_at=_REVIEWED_AT,
        expires_at=_EXPIRES_AT,
        evidence_digest=canonical_digest(
            {
                "profile": profile_id,
                "reviewed_at": _REVIEWED_AT.isoformat(),
                "expires_at": _EXPIRES_AT.isoformat(),
                "customer_content_training": training,
                "retention": retention,
                "retention_days_ceiling": retention_days,
                "provider_human_access": human_access,
                "route_qualifier": route_qualifier,
                "caveats": list(caveats),
                "sources": list(sources),
            }
        ),
    )


def _record(
    endpoint_profile_id: str,
    profile_id: str,
    *,
    route_qualifier: str,
    caveats: tuple[str, ...],
    sources: tuple[str, ...],
    training: Literal["prohibited", "permitted", "unknown"],
    retention: Literal["none", "bounded", "unbounded", "unknown"],
    retention_days: int | None,
    human_access: Literal["prohibited", "restricted", "permitted", "unknown"],
) -> ProviderDataUseRecord:
    """Build display text and its evidence digest from the same immutable values."""

    return ProviderDataUseRecord(
        endpoint_profile_id=endpoint_profile_id,
        route_qualifier=route_qualifier,
        official_source_urls=sources,
        caveats=caveats,
        profile=_profile(
            profile_id,
            training=training,
            retention=retention,
            retention_days=retention_days,
            human_access=human_access,
            sources=sources,
            route_qualifier=route_qualifier,
            caveats=caveats,
        ),
    )


_OPENAI_SOURCES: Final = (
    "https://platform.openai.com/docs/models/default-usage-policies-by-endpoint",
    "https://help.openai.com/en/articles/5722486-api-data-usage-policies",
)
_ANTHROPIC_SOURCES: Final = (
    "https://privacy.claude.com/en/articles/7996868-is-my-data-used-for-model-training",
    "https://privacy.claude.com/en/articles/7996866-how-long-do-you-store-my-organization-s-data",
)
_FIREWORKS_SOURCES: Final = ("https://docs.fireworks.ai/guides/security_compliance/data_handling",)
_XAI_SOURCES: Final = ("https://docs.x.ai/developers/faq/security",)
_GEMINI_SOURCES: Final = (
    "https://ai.google.dev/gemini-api/terms",
    "https://ai.google.dev/gemini-api/docs/zdr",
)
_OPENROUTER_SOURCES: Final = (
    "https://openrouter.ai/docs/guides/privacy/data-collection",
    "https://openrouter.ai/docs/guides/features/zdr",
)
_VERCEL_SOURCES: Final = (
    "https://vercel.com/docs/ai-gateway/models-and-providers/provider-options",
    "https://vercel.com/docs/ai-gateway/byok",
)
_CODEX_SUBSCRIPTION_SOURCES: Final = (
    "https://help.openai.com/en/articles/11369540-codex-in-chatgpt",
    "https://openai.com/policies/terms-of-use/",
    "https://openai.com/policies/privacy-policy/",
)
_CODEX_SUBSCRIPTION_CAVEATS: Final = (
    "The exact ChatGPT plan, workspace controls, regional terms, and retention posture are not "
    "proven by login or a returned plan label.",
    "Codex constructs the upstream OpenAI request internally; FinishUP observes only the disclosed "
    "case at the local app-server boundary.",
)
_CODEX_SUBSCRIPTION_REVIEWED_AT: Final = datetime(2026, 8, 30, tzinfo=UTC)
_CODEX_SUBSCRIPTION_EXPIRES_AT: Final = datetime(2026, 11, 30, tzinfo=UTC)


def _codex_subscription_record() -> ProviderDataUseRecord:
    route = (
        "ChatGPT-authenticated Codex app-server subscription route; plan-specific data controls "
        "and terms remain unverified, so v1 keeps an unknown posture."
    )
    profile_id = "codex-chatgpt-subscription-unverified"
    profile = ProviderDataUseProfile(
        data_use_profile_id=profile_id,
        data_use_profile_version="2026.08.30",
        customer_content_training="unknown",
        retention="unknown",
        retention_days_ceiling=None,
        provider_human_access="unknown",
        reviewed_at=_CODEX_SUBSCRIPTION_REVIEWED_AT,
        expires_at=_CODEX_SUBSCRIPTION_EXPIRES_AT,
        evidence_digest=canonical_digest(
            {
                "profile": profile_id,
                "reviewed_at": _CODEX_SUBSCRIPTION_REVIEWED_AT.isoformat(),
                "expires_at": _CODEX_SUBSCRIPTION_EXPIRES_AT.isoformat(),
                "customer_content_training": "unknown",
                "retention": "unknown",
                "retention_days_ceiling": None,
                "provider_human_access": "unknown",
                "route_qualifier": route,
                "caveats": list(_CODEX_SUBSCRIPTION_CAVEATS),
                "sources": list(_CODEX_SUBSCRIPTION_SOURCES),
            }
        ),
    )
    return ProviderDataUseRecord(
        endpoint_profile_id="codex-chatgpt-subscription",
        route_qualifier=route,
        official_source_urls=_CODEX_SUBSCRIPTION_SOURCES,
        caveats=_CODEX_SUBSCRIPTION_CAVEATS,
        profile=profile,
    )


_CATALOG: Final = MappingProxyType(
    {
        "codex-chatgpt-subscription": _codex_subscription_record(),
        "openai-responses": _record(
            "openai-responses",
            "openai-api-responses",
            route_qualifier="OpenAI API Responses endpoint with renderer-fixed store=false; "
            "account-level data controls are outside this binding.",
            sources=_OPENAI_SOURCES,
            caveats=(
                "Abuse-monitoring, legal, safety, and support exceptions may permit retained data "
                "or restricted authorized access.",
                "The renderer sets store=false; organization opt-ins and separately stored API "
                "features are outside this route claim.",
            ),
            training="prohibited",
            retention="bounded",
            retention_days=30,
            human_access="restricted",
        ),
        "anthropic-openai-chat-completions": _record(
            "anthropic-openai-chat-completions",
            "anthropic-commercial-api",
            route_qualifier="Anthropic commercial API compatibility endpoint; consumer and "
            "opted-in routes excluded.",
            sources=_ANTHROPIC_SOURCES,
            caveats=(
                "Abuse-policy, legal, safety, and support exceptions may permit longer retention "
                "or restricted authorized access.",
                "Consumer, feedback-opt-in, and third-party cloud routes are excluded.",
            ),
            training="prohibited",
            retention="bounded",
            retention_days=30,
            human_access="restricted",
        ),
        "fireworks-responses": _record(
            "fireworks-responses",
            "fireworks-responses-store-false",
            route_qualifier="Fireworks Responses API only, with the renderer-fixed store=false "
            "opt-out.",
            sources=_FIREWORKS_SOURCES,
            caveats=(
                "Operational metadata is retained; safety, legal, and support handling may still "
                "involve restricted authorized access.",
                "Opt-in logging, training products, and other stored features are excluded.",
            ),
            training="prohibited",
            retention="none",
            retention_days=None,
            human_access="restricted",
        ),
        "xai-openai-chat-completions": _record(
            "xai-openai-chat-completions",
            "xai-direct-api-default",
            route_qualifier="Direct xAI API compatibility endpoint; ordinary 30-day abuse-audit "
            "retention, without a team-level ZDR claim.",
            sources=_XAI_SOURCES,
            caveats=(
                "The 30-day window is for abuse/misuse auditing; legal and safety exceptions may "
                "apply and authorized access is restricted rather than impossible.",
                "Files, collections, stateful features, consumer Grok, and team ZDR are excluded.",
            ),
            training="prohibited",
            retention="bounded",
            retention_days=30,
            human_access="restricted",
        ),
        "google-gemini-openai-chat-completions": _record(
            "google-gemini-openai-chat-completions",
            "gemini-developer-api-tier-unverified",
            route_qualifier="Gemini Developer API compatibility endpoint; this binding does not "
            "establish paid-service billing status, region-specific terms, or ZDR eligibility.",
            sources=_GEMINI_SOURCES,
            caveats=(
                "Paid and unpaid Gemini Developer API use have materially different training and "
                "retention terms.",
                "Possession of an API key does not prove an active paid Cloud Billing project.",
            ),
            training="unknown",
            retention="unknown",
            retention_days=None,
            human_access="unknown",
        ),
        "openrouter-openai-chat-completions": _record(
            "openrouter-openai-chat-completions",
            "openrouter-downstream-unconstrained",
            route_qualifier="OpenRouter gateway route; the binding does not constrain the "
            "downstream provider, fallback set, endpoint-level ZDR posture, or account logging "
            "settings.",
            sources=_OPENROUTER_SOURCES,
            caveats=(
                "Gateway defaults and account logging settings do not establish downstream "
                "provider behavior.",
                "Standing authority is unavailable until downstream/fallback constraints and "
                "actual-route receipts are represented.",
            ),
            training="unknown",
            retention="unknown",
            retention_days=None,
            human_access="unknown",
        ),
        "vercel-ai-gateway-openai-responses": _record(
            "vercel-ai-gateway-openai-responses",
            "vercel-ai-gateway-downstream-unconstrained",
            route_qualifier="Vercel AI Gateway route; the binding does not constrain the downstream "
            "provider or fallback set and cannot inherit a gateway-level posture as provider "
            "assurance.",
            sources=_VERCEL_SOURCES,
            caveats=(
                "Gateway-layer deletion does not establish downstream provider retention or training.",
                "Standing authority is unavailable until downstream/fallback constraints and "
                "actual-route receipts are represented.",
            ),
            training="unknown",
            retention="unknown",
            retention_days=None,
            human_access="unknown",
        ),
        "owner-declared-openai-responses": _record(
            "owner-declared-openai-responses",
            "owner-declared-route-unreviewed",
            route_qualifier="Owner-declared Responses-compatible endpoint; host ownership and "
            "downstream data-use posture are not established by this endpoint profile.",
            sources=(),
            caveats=("No packaged provider-policy evidence exists for this owner-declared route.",),
            training="unknown",
            retention="unknown",
            retention_days=None,
            human_access="unknown",
        ),
    }
)

_UNKNOWN = _record(
    "unknown",
    "unreviewed-provider-route",
    route_qualifier="No reviewed exact-route/account-tier evidence is packaged for this endpoint "
    "profile.",
    sources=(),
    caveats=("No packaged exact-route evidence exists for this endpoint profile.",),
    training="unknown",
    retention="unknown",
    retention_days=None,
    human_access="unknown",
)


def data_use_record_for_endpoint(endpoint_profile_id: str) -> ProviderDataUseRecord:
    """Return one exact-profile record, never a host-level fallback."""

    return _CATALOG.get(endpoint_profile_id, _UNKNOWN)


def endpoint_profile_data_use_recommendation_eligible(
    endpoint_profile_id: str, *, now: datetime
) -> bool:
    """Whether current, route-specific evidence supports Assisted as the recommendation."""

    current = now.replace(microsecond=(now.microsecond // 1000) * 1000)
    return data_use_record_for_endpoint(endpoint_profile_id).profile.recommendation_eligible(
        current
    )
