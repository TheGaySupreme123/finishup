"""Approved bounded live AI-powered review provider capability probe (E-007).

Marked ``live_provider`` / ``live``. Written for the release capability job; excluded from the
default gate. Credentials must never enter this process — the cell exercises only an opaque
service-owned configured profile after an operator-provisioned ready ceremony.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Final

import pytest
from tests.capability.evidence import (
    CapabilityCase,
    EvidenceOutcome,
    Observation,
    bytes_digest,
    live_provider_authorized,
    record_and_write,
    runtime_capability_context,
)

from finishup.adapters.providers.factory import external_factory_builders_from_config
from finishup.adapters.providers.openai_responses import (
    OPENAI_MAX_OUTPUT_TOKENS,
    OPENAI_MAX_RESPONSE_BODY_BYTES,
    OpenAIProfile,
)
from finishup.config.models import ProviderProfileConfig
from finishup.config.write import provider_preset
from finishup.domain.privacy import ProviderDataUseProfile
from finishup.protocol.canonical import canonical_digest

_TEST_REVISION = bytes_digest(Path(__file__).read_bytes())
_DIGEST = "sha256:" + "e" * 64
_NOW = datetime(2026, 7, 20, tzinfo=UTC)


class _LiveClock:
    """Wall clock for factory construction only; no provider call happens in an unauthorized run."""

    def now_utc(self) -> datetime:
        return _NOW

    def monotonic_seconds(self) -> float:
        return 1.0


_CASE_LIVE = CapabilityCase(
    case_id="PROV-LIVE-001",
    requirement_id="ADR-006.provider-live",
    claim_id="E-007.provider-profile-live",
    capability_family="provider_profile_live",
    required_observation_codes=frozenset({"live_authorized"}),
    allowed_observation_codes=frozenset(
        {
            "live_authorized",
            "credential_absent_from_process",
            "caps_bound",
            "data_use_eligibility_bound",
            "service_ready",
            "synthetic_case_bound",
        }
    ),
)


def _data_use_profile() -> ProviderDataUseProfile:
    return ProviderDataUseProfile(
        data_use_profile_id="openai-data-use",
        data_use_profile_version="1.0.0",
        customer_content_training="prohibited",
        retention="bounded",
        retention_days_ceiling=30,
        provider_human_access="restricted",
        reviewed_at=_NOW - timedelta(days=1),
        expires_at=_NOW + timedelta(days=30),
        evidence_digest=_DIGEST,
    )


@pytest.mark.live
@pytest.mark.live_provider
def test_live_provider_profile_requires_authorized_ready_service(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir(mode=0o700)

    profile = OpenAIProfile(
        provider_id="openai",
        model="gpt-5",
        endpoint_profile_id="openai-responses",
        endpoint_profile_version="1.0.0",
        timeout_seconds=60,
        supports_structured_outputs=True,
        data_use_profile=_data_use_profile(),
    )
    assert profile.host == "api.openai.com"
    assert profile.port == 443
    assert profile.path == "/v1/responses"
    assert OPENAI_MAX_OUTPUT_TOKENS == 2_048
    assert OPENAI_MAX_RESPONSE_BODY_BYTES == 1_048_576
    assert profile.data_use_profile.recommendation_eligible(_NOW)

    # Spec: credential never enters/is consumed by this process. The cell only accepts an opaque
    # ready-service ceremony (see FINISHUP_LIVE_SERVICE_READY / FINISHUP_LIVE_PROVIDER_PROFILE_ID).

    context = runtime_capability_context(
        fixture_digest=bytes_digest(b"provider-profile-live-e007"),
        test_revision=_TEST_REVISION,
        config_profile_digest=canonical_digest(
            {
                "endpoint": profile.endpoint_profile_id,
                "model": profile.model,
                "provider": profile.provider_id,
                "version": profile.endpoint_profile_version,
            }
        ),
        external_tool="openai",
        external_version="absent",
        integration_channel="llm_inference",
        provider_id=profile.provider_id,
    )

    if not live_provider_authorized():
        evidence = record_and_write(
            _CASE_LIVE,
            context,
            (
                Observation("credential_absent_from_process", boolean_value=True),
                Observation("live_authorized", boolean_value=False),
            ),
            EvidenceOutcome.UNSUPPORTED,
            ("live_provider_not_authorized",),
            output_root=evidence_root,
        )
        assert evidence.outcome is EvidenceOutcome.UNSUPPORTED
        return

    # Ready isolated service + opaque configured profile are operator-provisioned outside this
    # process. Until that ceremony is present, the cell remains unsupported rather than bypassed.
    service_ready = os.environ.get("FINISHUP_LIVE_SERVICE_READY") == "1"
    configured_profile = os.environ.get("FINISHUP_LIVE_PROVIDER_PROFILE_ID", "").strip()
    if not service_ready or not configured_profile:
        evidence = record_and_write(
            _CASE_LIVE,
            context,
            (
                Observation("caps_bound", boolean_value=True),
                Observation("credential_absent_from_process", boolean_value=True),
                Observation("data_use_eligibility_bound", boolean_value=True),
                Observation("live_authorized", boolean_value=True),
                Observation("service_ready", boolean_value=False),
                Observation("synthetic_case_bound", boolean_value=True),
            ),
            EvidenceOutcome.UNSUPPORTED,
            ("ready_service_ceremony_unavailable",),
            output_root=evidence_root,
        )
        assert evidence.outcome is EvidenceOutcome.UNSUPPORTED
        return

    pytest.fail(
        "live provider dispatch path requires a wired ready-service client; "
        "ceremony flags were set but no service client is available in this revision"
    )


_CASE_MULTIPROVIDER = CapabilityCase(
    case_id="PROV-LIVE-002",
    requirement_id="ADR-006.provider-live",
    claim_id="E-007.provider-profile-live",
    capability_family="provider_profile_live",
    required_observation_codes=frozenset({"live_authorized"}),
    allowed_observation_codes=frozenset(
        {
            "caps_bound",
            "credential_absent_from_process",
            "data_use_eligibility_bound",
            "factory_dispatch_bound",
            "live_authorized",
            "service_ready",
            "synthetic_case_bound",
        }
    ),
)

# Each bundled non-official preset with the endpoint facts its factory must produce. Live behavior
# — whether the host honors strict response_format, and whether the default model ID is current —
# is exactly what this cell exists to record, and is unclaimed until it runs authorized.
_BUNDLED_PRESETS: Final = (
    ("anthropic", "api.anthropic.com", "/v1/chat/completions"),
    ("google_gemini", "generativelanguage.googleapis.com", "/v1beta/openai/chat/completions"),
    ("openrouter", "openrouter.ai", "/api/v1/chat/completions"),
    ("vercel_ai_gateway", "ai-gateway.vercel.sh", "/v1/responses"),
)


@pytest.mark.live
@pytest.mark.live_provider
@pytest.mark.parametrize(("choice", "host", "path"), _BUNDLED_PRESETS)
def test_bundled_provider_preset_dispatches_and_awaits_live_evidence(
    tmp_path: Path, choice: str, host: str, path: str
) -> None:
    """A bundled preset must reach a real factory, and stay unclaimed until live evidence exists."""

    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir(mode=0o700)

    preset = provider_preset(choice)
    provider = ProviderProfileConfig(
        provider_id=preset.provider_id,
        endpoint_profile_id=preset.endpoint_profile_id,
        endpoint_profile_version=preset.endpoint_profile_version,
        model=preset.default_model,
        capability_profile=preset.capability_profile,
    )
    builders = external_factory_builders_from_config(provider, clock=_LiveClock())
    assert len(builders) == 1
    ((_binding, builder),) = builders.items()
    assert callable(builder)
    profile = getattr(builder(), "profile")
    assert profile.host == host
    assert profile.path == path
    # This cell's frozen clock predates the packaged review records, so the lower-bound reason is
    # explicit rather than accidentally shared with a conservative provider posture. Live dispatch
    # remains separately unclaimed until authorized.
    assert profile.data_use_profile.reviewed_at is not None
    assert profile.data_use_profile.reviewed_at > _NOW
    assert not profile.data_use_profile.recommendation_eligible(_NOW)

    context = runtime_capability_context(
        fixture_digest=bytes_digest(b"provider-preset-live-e007"),
        test_revision=_TEST_REVISION,
        config_profile_digest=canonical_digest(
            {
                "endpoint": preset.endpoint_profile_id,
                "model": preset.default_model,
                "provider": preset.provider_id,
                "version": preset.endpoint_profile_version,
            }
        ),
        external_tool="openai",
        external_version="absent",
        integration_channel="llm_inference",
        provider_id=preset.provider_id,
    )
    observations = (
        Observation("credential_absent_from_process", boolean_value=True),
        Observation("factory_dispatch_bound", boolean_value=True),
        Observation("live_authorized", boolean_value=live_provider_authorized()),
    )
    evidence = record_and_write(
        _CASE_MULTIPROVIDER,
        context,
        observations,
        EvidenceOutcome.UNSUPPORTED,
        (
            "live_provider_not_authorized"
            if not live_provider_authorized()
            else "ready_service_ceremony_unavailable",
        ),
        output_root=evidence_root,
    )
    assert evidence.outcome is EvidenceOutcome.UNSUPPORTED
