"""Privacy desired-state TOML never silently widens (ADR-014)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from finishup.adapters.privacy.catalog import decode_privacy_policy_canonical
from finishup.application.privacy_policy import is_privacy_tightening
from finishup.config.privacy_desired import (
    load_privacy_desired_canonical,
    render_privacy_desired_toml,
    write_privacy_desired_toml,
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
from finishup.protocol.models import DataCategory

_DIGEST = "sha256:" + "1" * 64
_POLICY_ID = "pvy_88888888-8888-4888-8888-888888888888"
_INSTALLATION_ID = "ins_08000000-0000-4000-8000-000000000001"
_NOW = datetime(2026, 3, 8, tzinfo=UTC)


def _channel(
    channel: EgressChannel,
    *,
    enabled: bool = False,
    max_bytes: int = 0,
) -> ChannelPolicy:
    return ChannelPolicy(
        channel=channel,
        enabled=enabled,
        allowed_categories=(DataCategory.BOUNDED_STRUCTURAL_METADATA,) if enabled else (),
        allowed_data_classes=(DataClass.PUBLIC_STRUCTURAL,) if enabled else (),
        provider_binding=None,
        allowed_purposes=("capability-testing-probe",) if enabled else (),
        scope_ceiling=AuthorizationScopeKind.MACHINE,
        preview_required=False,
        max_bytes=max_bytes,
        max_tokens=1024 if enabled else 0,
        authorization_ttl_seconds=60 if enabled else 0,
    )


def _policy(*, network: bool, telemetry: bool) -> PrivacyPolicy:
    policies = {
        channel: _channel(
            channel,
            enabled=telemetry and channel is EgressChannel.PRODUCT_TELEMETRY,
            max_bytes=4096 if telemetry and channel is EgressChannel.PRODUCT_TELEMETRY else 0,
        )
        for channel in EgressChannel
    }
    return PrivacyPolicy(
        policy_id=_POLICY_ID,
        version=1,
        policy_digest=_DIGEST,
        profile=PrivacyProfile.LOCAL_ONLY,
        review_context_profile=ReviewContextProfile.STRUCTURAL,
        review_selection=ReviewSelectionPolicy.for_profile(ReviewContextProfile.STRUCTURAL),
        require_current_provider_data_use_evidence=False,
        network_egress_permitted=network,
        effective_scope=AuthorizationScope(AuthorizationScopeKind.MACHINE, _INSTALLATION_ID),
        channel_policies=tuple(
            policies[item] for item in sorted(EgressChannel, key=lambda value: value.value)
        ),
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


def test_privacy_desired_toml_round_trip(tmp_path: Path) -> None:
    policy = _policy(network=False, telemetry=False)
    path = write_privacy_desired_toml(policy, tmp_path / "privacy-desired.toml")
    text = path.read_text()
    assert "yoetz.privacy-desired/1" in text
    assert "silently widen" in text
    decoded = decode_privacy_policy_canonical(load_privacy_desired_canonical(path))
    assert decoded == policy
    assert render_privacy_desired_toml(policy).startswith('schema = "yoetz.privacy-desired/1"')


def test_widening_is_not_classified_as_tighten() -> None:
    current = _policy(network=False, telemetry=False)
    wider = _policy(network=True, telemetry=True)
    assert not is_privacy_tightening(current, wider)
    assert is_privacy_tightening(wider, current)
