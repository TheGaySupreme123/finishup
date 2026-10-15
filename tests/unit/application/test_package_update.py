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


# --- The transitional ``yoetz`` installation (ADR-048) -------------------------------------------


@pytest.mark.parametrize(
    ("legacy_version", "expected"),
    [("same", "yoetz"), ("0.2.5", "finishup"), (None, "finishup")],
)
def test_installed_package_name_follows_the_transitional_distribution(
    monkeypatch: pytest.MonkeyPatch, legacy_version: str | None, expected: str
) -> None:
    import importlib.metadata

    from finishup.application import package_update

    def version(name: str) -> str:
        assert name == "yoetz"
        if legacy_version is None:
            raise importlib.metadata.PackageNotFoundError(name)
        return package_update.installed_package_version() if legacy_version == "same" else "0.2.5"

    monkeypatch.setattr(importlib.metadata, "version", version)

    assert package_update.installed_package_name() == expected


def test_legacy_install_polls_and_names_its_own_package(tmp_path: Path) -> None:
    transport = _ScriptedTransport(version="0.4.0")

    async def run() -> None:
        advisory = await resolve_package_update_advisory(
            policy=_policy(update_checks=True, network=True),
            installed_version="0.3.0",
            transport=transport,
            now=_NOW,
            cache_root=tmp_path,
            package="yoetz",
        )
        assert advisory.outcome == "newer_available"
        assert advisory.upgrade_command == "yoetz upgrade"
        assert any("yoetz upgrade" in line for line in advisory.tip_lines())
        assert not any("finishup upgrade" in line for line in advisory.tip_lines())
        assert any(
            "move this installation to the finishup command" in line
            and "also works as yoetz with the same subcommand" in line
            for line in advisory.tip_lines()
        )
        cached = load_package_update_cache(root=tmp_path, package="yoetz")
        assert cached is not None and cached.package == "yoetz"
        assert load_package_update_cache(root=tmp_path, package="finishup") is None

    import asyncio

    asyncio.run(run())


def test_a_cache_polled_for_one_package_never_answers_for_the_other(tmp_path: Path) -> None:
    store_package_update_cache(
        latest_version="9.0.0", fetched_at=_NOW, root=tmp_path, package="yoetz"
    )
    transport = _ScriptedTransport(version="0.4.0")

    async def run() -> None:
        advisory = await resolve_package_update_advisory(
            policy=_policy(update_checks=True, network=True),
            installed_version="0.3.0",
            transport=transport,
            now=_NOW,
            cache_root=tmp_path,
            package="finishup",
        )
        assert advisory.source == "network"
        assert advisory.latest_version == "0.4.0"
        assert advisory.upgrade_command == PACKAGE_UPDATE_UPGRADE_COMMAND
        assert transport.calls == 1

    import asyncio

    asyncio.run(run())
    kept = load_package_update_cache(root=tmp_path, package="yoetz")
    assert kept is not None and kept.latest_version == "9.0.0"
    refreshed = load_package_update_cache(root=tmp_path, package="finishup")
    assert refreshed is not None and refreshed.latest_version == "0.4.0"


def test_a_pre_rename_cache_without_package_was_polled_for_yoetz(tmp_path: Path) -> None:
    (tmp_path / "package-update-cache.json").write_text(
        '{"fetched_at":"2026-08-03T12:00:00Z","latest_version":"0.2.5",'
        '"schema":"yoetz.package-update-cache/1","ttl_seconds":86400}\n',
        encoding="utf-8",
    )

    legacy = load_package_update_cache(root=tmp_path, package="yoetz")
    assert legacy is not None and legacy.package == "yoetz"
    assert load_package_update_cache(root=tmp_path, package="finishup") is None


def test_unknown_package_values_are_refused(tmp_path: Path) -> None:
    (tmp_path / "package-update-cache.json").write_text(
        '{"fetched_at":"2026-08-03T12:00:00Z","latest_version":"1.0.0","package":"other",'
        '"schema":"yoetz.package-update-cache/1","ttl_seconds":86400}\n',
        encoding="utf-8",
    )
    assert load_package_update_cache(root=tmp_path, package="yoetz") is None
    assert load_package_update_cache(root=tmp_path, package="other") is None
    with pytest.raises(ValueError, match="package_invalid"):
        build_package_update_advisory(
            installed_version="0.3.0", latest_version="0.4.0", package="other"
        )
    with pytest.raises(ValueError, match="package_invalid"):
        store_package_update_cache(
            latest_version="1.0.0", fetched_at=_NOW, root=tmp_path, package="other"
        )

    async def run() -> None:
        with pytest.raises(ValueError, match="package_invalid"):
            await resolve_package_update_advisory(
                policy=_policy(update_checks=True, network=True),
                installed_version="0.3.0",
                transport=_ScriptedTransport(version="0.4.0"),
                cache_root=tmp_path,
                package="other",
            )

    import asyncio

    asyncio.run(run())


@pytest.mark.parametrize(
    ("package", "url"),
    [("finishup", PYPI_FINISHUP_JSON_URL), ("yoetz", "https://pypi.org/pypi/yoetz/json")],
)
def test_transport_requests_only_the_allowlisted_identity(package: str, url: str) -> None:
    import asyncio

    import httpx

    from finishup.adapters.privacy.update_checks import fetch_latest_finishup_version

    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        return httpx.Response(200, content=b'{"info":{"version":"0.4.0"}}')

    async def run() -> str:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await fetch_latest_finishup_version(client=client, package=package)

    assert asyncio.run(run()) == "0.4.0"
    assert requested == [url]


def test_transport_refuses_other_identities_before_any_request() -> None:
    import asyncio

    import httpx

    from finishup.adapters.privacy.update_checks import fetch_latest_finishup_version

    def handler(_request: httpx.Request) -> httpx.Response:
        raise AssertionError("no request may be made")

    async def run() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            with pytest.raises(ValueError, match="package_invalid"):
                await fetch_latest_finishup_version(client=client, package="other")

    asyncio.run(run())


def test_alternating_installations_keep_their_own_ttl(tmp_path: Path) -> None:
    """A ``finishup`` and a ``yoetz`` tool sharing one state directory poll once each per TTL."""

    import asyncio

    finishup_transport = _ScriptedTransport(version="0.4.0")
    yoetz_transport = _ScriptedTransport(version="0.4.0")

    async def resolve(package: str, transport: _ScriptedTransport, hours: int) -> str:
        advisory = await resolve_package_update_advisory(
            policy=_policy(update_checks=True, network=True),
            installed_version="0.3.0",
            transport=transport,
            now=_NOW + timedelta(hours=hours),
            cache_root=tmp_path,
            package=package,
        )
        return advisory.source

    async def run() -> list[str]:
        sources: list[str] = []
        for hours in range(4):
            sources.append(await resolve("finishup", finishup_transport, hours))
            sources.append(await resolve("yoetz", yoetz_transport, hours))
        return sources

    assert asyncio.run(run()) == ["network", "network"] + ["cache"] * 6
    assert finishup_transport.calls == 1
    assert yoetz_transport.calls == 1


def test_a_finishup_poll_never_lands_where_pre_rename_releases_read(tmp_path: Path) -> None:
    """Released Yoetz readers treat any entry in the legacy file as a ``yoetz`` poll (ADR-048)."""

    legacy = tmp_path / "package-update-cache.json"
    legacy_bytes = (
        b'{"fetched_at":"2026-08-03T12:00:00Z","latest_version":"0.2.5",'
        b'"schema":"yoetz.package-update-cache/1","ttl_seconds":86400}\n'
    )
    legacy.write_bytes(legacy_bytes)

    store_package_update_cache(
        latest_version="0.4.0", fetched_at=_NOW, root=tmp_path, package="finishup"
    )

    assert legacy.read_bytes() == legacy_bytes
    assert (tmp_path / "package-update-cache-finishup.json").is_file()


def test_each_cache_file_answers_only_for_its_own_identity(tmp_path: Path) -> None:
    body = (
        '{{"fetched_at":"2026-08-03T12:00:00Z","latest_version":"0.4.0",{package}'
        '"schema":"yoetz.package-update-cache/1","ttl_seconds":86400}}\n'
    )
    # A legacy-file entry recording a finishup poll is not a yoetz answer.
    (tmp_path / "package-update-cache.json").write_text(
        body.format(package='"package":"finishup",'), encoding="utf-8"
    )
    # A finishup-file entry without a package member is not a finishup answer.
    (tmp_path / "package-update-cache-finishup.json").write_text(
        body.format(package=""), encoding="utf-8"
    )

    assert load_package_update_cache(root=tmp_path, package="yoetz") is None
    assert load_package_update_cache(root=tmp_path, package="finishup") is None


def test_finishup_tip_has_no_alias_notice() -> None:
    advisory = build_package_update_advisory(
        installed_version="0.3.0", latest_version="0.4.0", source="cache"
    )

    assert advisory.package == "finishup"
    assert not any("yoetz" in line for line in advisory.tip_lines())
