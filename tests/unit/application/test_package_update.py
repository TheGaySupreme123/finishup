"""Package update advisory: version compare, policy gate, cache, transport mock."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from finishup.adapters.privacy.update_checks import (
    PYPI_FINISHUP_JSON_URL,
    UpdateChecksTransportError,
    parse_latest_version,
)
from finishup.application.package_update import (
    PACKAGE_UPDATE_UPGRADE_COMMAND,
    build_package_update_advisory,
    compare_versions,
    is_update_checks_permitted,
    load_package_update_cache,
    resolve_package_update_advisory,
    store_package_update_cache,
)
from finishup.domain.privacy import (
    AuthorizationScope,
    AuthorizationScopeKind,
    ChannelPolicy,
    DataCategory,
    DataClass,
    EgressChannel,
    PrivacyPolicy,
    PrivacyProfile,
    ReviewContextProfile,
    ReviewSelectionPolicy,
)

_NOW = datetime(2026, 8, 3, 12, 0, 0, tzinfo=UTC)
_INSTALLATION = "ins_00000000-0000-4000-8000-000000000001"
_POLICY_ID = "pvy_00000000-0000-4000-8000-000000000001"
_DIGEST = "sha256:" + "a" * 64


def _disabled(channel: EgressChannel) -> ChannelPolicy:
    return ChannelPolicy(
        channel,
        False,
        (),
        (),
        None,
        (),
        AuthorizationScopeKind.MACHINE,
        False,
        0,
        0,
        0,
    )


def _policy(*, update_checks: bool, network: bool) -> PrivacyPolicy:
    channels = {channel: _disabled(channel) for channel in EgressChannel}
    if update_checks:
        channels[EgressChannel.UPDATE_CHECKS] = ChannelPolicy(
            EgressChannel.UPDATE_CHECKS,
            True,
            (DataCategory.BOUNDED_STRUCTURAL_METADATA,),
            (DataClass.PUBLIC_STRUCTURAL,),
            None,
            ("package-update-check",),
            AuthorizationScopeKind.MACHINE,
            False,
            4096,
            1024,
            60,
        )
    ordered = tuple(channels[channel] for channel in sorted(EgressChannel, key=lambda c: c.value))
    return PrivacyPolicy(
        _POLICY_ID,
        1,
        _DIGEST,
        PrivacyProfile.LOCAL_ONLY,
        ReviewContextProfile.STRUCTURAL,
        ReviewSelectionPolicy.for_profile(ReviewContextProfile.STRUCTURAL),
        False,
        network,
        AuthorizationScope(AuthorizationScopeKind.MACHINE, _INSTALLATION),
        ordered,
        False,
        None,
        (),
        (),
        (
            DataCategory.BOUNDED_STRUCTURAL_METADATA,
            DataCategory.DECLARED_FILE_TYPE,
            DataCategory.FINDING_SUMMARY,
            DataCategory.OBLIGATION_TEXT,
        ),
        (DataClass.PUBLIC_STRUCTURAL, DataClass.ORDINARY_USER_CONTENT),
        tuple(DataCategory),
        (
            DataClass.ORDINARY_USER_CONTENT,
            DataClass.PUBLIC_STRUCTURAL,
            DataClass.SENSITIVE_CONFIDENTIAL,
        ),
        _NOW,
    )


class _ScriptedTransport:
    def __init__(self, *, version: str | None = None, error: str | None = None) -> None:
        self.version = version
        self.error = error
        self.calls = 0

    async def fetch_latest_version(self) -> str:
        self.calls += 1
        if self.error is not None:
            raise UpdateChecksTransportError(self.error)
        assert self.version is not None
        return self.version


def test_compare_versions_newer_equal_older_garbage() -> None:
    assert compare_versions("0.1.0", "0.2.0") is True
    assert compare_versions("0.2.0", "0.2.0") is False
    assert compare_versions("0.2.0", "0.1.0") is False
    assert compare_versions("not-a-version", "0.2.0") is None
    assert compare_versions("0.1.0", "??") is None


def test_advisory_command_text_and_tip_lines() -> None:
    newer = build_package_update_advisory(
        installed_version="0.1.0", latest_version="0.2.0", source="network"
    )
    assert newer.is_newer is True
    assert newer.upgrade_command == PACKAGE_UPDATE_UPGRADE_COMMAND
    lines = newer.tip_lines()
    assert any("0.1.0" in line and "0.2.0" in line for line in lines)
    assert any(PACKAGE_UPDATE_UPGRADE_COMMAND in line for line in lines)

    same = build_package_update_advisory(
        installed_version="0.2.0", latest_version="0.2.0", source="cache"
    )
    assert same.is_newer is False
    assert same.tip_lines() == ()


def test_policy_deny_skips_network(tmp_path: Path) -> None:
    transport = _ScriptedTransport(version="9.9.9")

    async def run() -> None:
        denied = await resolve_package_update_advisory(
            policy=_policy(update_checks=False, network=False),
            installed_version="0.1.0",
            transport=transport,
            now=_NOW,
            cache_root=tmp_path,
            allow_network=True,
        )
        assert denied.outcome == "skipped_policy"
        assert denied.is_newer is False
        assert transport.calls == 0

        # Ceiling false with a channel bit asserted only via posture booleans (invalid
        # as a full PrivacyPolicy, but the advisory gate must still deny).
        ceiling_false = await resolve_package_update_advisory(
            network_egress_permitted=False,
            update_checks_enabled=True,
            installed_version="0.1.0",
            transport=transport,
            allow_network=True,
        )
        assert ceiling_false.outcome == "skipped_policy"
        assert transport.calls == 0

    import asyncio

    asyncio.run(run())


def test_cache_ttl_and_network_success(tmp_path: Path) -> None:
    transport = _ScriptedTransport(version="0.3.0")

    async def run() -> None:
        policy = _policy(update_checks=True, network=True)
        first = await resolve_package_update_advisory(
            policy=policy,
            installed_version="0.1.0",
            transport=transport,  # type: ignore[arg-type]
            now=_NOW,
            cache_root=tmp_path,
            allow_network=True,
        )
        assert first.outcome == "newer_available"
        assert first.source == "network"
        assert first.latest_version == "0.3.0"
        assert transport.calls == 1

        cached = load_package_update_cache(root=tmp_path)
        assert cached is not None
        assert cached.latest_version == "0.3.0"
        assert cached.is_fresh(now=_NOW + timedelta(hours=1))
        assert not cached.is_fresh(now=_NOW + timedelta(hours=48))

        second = await resolve_package_update_advisory(
            policy=policy,
            installed_version="0.1.0",
            transport=transport,  # type: ignore[arg-type]
            now=_NOW + timedelta(hours=1),
            cache_root=tmp_path,
            allow_network=True,
        )
        assert second.source == "cache"
        assert transport.calls == 1

    import asyncio

    asyncio.run(run())


def test_transport_failure_is_silent(tmp_path: Path) -> None:
    transport = _ScriptedTransport(error="timeout")

    async def run() -> None:
        result = await resolve_package_update_advisory(
            policy=_policy(update_checks=True, network=True),
            installed_version="0.1.0",
            transport=transport,  # type: ignore[arg-type]
            now=_NOW,
            cache_root=tmp_path,
            allow_network=True,
        )
        assert result.outcome == "skipped_unavailable"
        assert result.is_newer is False
        assert result.tip_lines() == ()

    import asyncio

    asyncio.run(run())


def test_parse_latest_version_rejects_bad_bodies() -> None:
    assert parse_latest_version(b'{"info":{"version":"1.2.3"}}') == "1.2.3"
    with pytest.raises(UpdateChecksTransportError):
        parse_latest_version(b"not-json")
    with pytest.raises(UpdateChecksTransportError):
        parse_latest_version(b'{"info":{}}')
    with pytest.raises(UpdateChecksTransportError):
        parse_latest_version(b'{"info":{"version":"1 2"}}')


def test_allowlisted_url_constant() -> None:
    assert PYPI_FINISHUP_JSON_URL == "https://pypi.org/pypi/finishup/json"


def test_is_update_checks_permitted_bits() -> None:
    assert is_update_checks_permitted(_policy(update_checks=True, network=True)) is True
    assert is_update_checks_permitted(_policy(update_checks=False, network=False)) is False
    assert (
        is_update_checks_permitted(network_egress_permitted=True, update_checks_enabled=True)
        is True
    )
    assert (
        is_update_checks_permitted(network_egress_permitted=True, update_checks_enabled=False)
        is False
    )


def test_store_and_load_cache_roundtrip(tmp_path: Path) -> None:
    store_package_update_cache(
        latest_version="1.0.0",
        fetched_at=_NOW,
        ttl=timedelta(hours=12),
        root=tmp_path,
    )
    loaded = load_package_update_cache(root=tmp_path)
    assert loaded is not None
    assert loaded.latest_version == "1.0.0"
    assert loaded.ttl_seconds == 12 * 3600


def test_update_tip_includes_complete_upgrade_guide() -> None:
    advisory = build_package_update_advisory(
        installed_version="0.2.0", latest_version="0.3.0", source="cache"
    )
    assert any("finishup upgrade" in line for line in advisory.tip_lines())
