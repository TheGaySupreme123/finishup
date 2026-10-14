"""Package update advisory: structural compare + upgrade command text.

Interactive surfaces only. Never writes work receipts. Network use is gated by the durable
``update_checks`` channel and the global ``network_egress_permitted`` ceiling; failures are
silent (no advisory), never scary false failures.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Final, Literal, cast

from packaging.version import InvalidVersion, Version

from yoetz.adapters.privacy.update_checks import (
    HttpxUpdateChecksTransport,
    UpdateChecksTransport,
    UpdateChecksTransportError,
)
from yoetz.config.paths import PathSafetyError, ensure_owner_only_dir, state_dir
from yoetz.domain.privacy import EgressChannel, PrivacyPolicy

__all__ = [
    "PACKAGE_UPDATE_UPGRADE_COMMAND",
    "PACKAGE_INSTALL_COMMAND",
    "PackageUpdateAdvisory",
    "PackageUpdateCache",
    "PackageUpdateOutcome",
    "advisory_tip_lines",
    "build_package_update_advisory",
    "compare_versions",
    "installed_package_version",
    "is_update_checks_permitted",
    "load_package_update_cache",
    "package_update_report_fields",
    "resolve_package_update_advisory",
    "store_package_update_cache",
    "upgrade_command_for",
]

PACKAGE_UPDATE_UPGRADE_COMMAND: Final = "yoetz upgrade"
PACKAGE_INSTALL_COMMAND: Final = (
    "uv tool install --compile-bytecode --managed-python --python 3.14.6 yoetz"
)
_CACHE_SCHEMA: Final = "yoetz.package-update-cache/1"
_CACHE_NAME: Final = "package-update-cache.json"
_DEFAULT_TTL: Final = timedelta(hours=24)
_MAX_CACHE_BYTES: Final = 4096

type PackageUpdateOutcome = Literal[
    "newer_available",
    "up_to_date",
    "skipped_policy",
    "skipped_unavailable",
    "skipped_unknown_version",
]


@dataclass(frozen=True, slots=True)
class PackageUpdateAdvisory:
    """Closed UX payload for interactive package-update tips."""

    outcome: PackageUpdateOutcome
    installed_version: str
    latest_version: str | None
    is_newer: bool
    upgrade_command: str
    source: Literal["network", "cache", "none"]

    def tip_lines(self) -> tuple[str, ...]:
        return advisory_tip_lines(self)


@dataclass(frozen=True, slots=True)
class PackageUpdateCache:
    schema: str
    latest_version: str
    fetched_at: datetime
    ttl_seconds: int

    def is_fresh(self, *, now: datetime) -> bool:
        if now.tzinfo is None or self.fetched_at.tzinfo is None:
            return False
        age = now - self.fetched_at
        return age >= timedelta(0) and age <= timedelta(seconds=self.ttl_seconds)


def installed_package_version() -> str:
    """Return the running distribution version without network I/O."""

    from yoetz import __version__

    return __version__


def is_update_checks_permitted(
    policy: PrivacyPolicy | None = None,
    *,
    network_egress_permitted: bool | None = None,
    update_checks_enabled: bool | None = None,
) -> bool:
    """True only when the durable policy admits structural package-update checks.

    Prefer a full ``PrivacyPolicy``. When only posture bits are available (TUI wire
    summary), pass the two booleans instead.
    """

    if policy is not None:
        if type(policy) is not PrivacyPolicy:
            return False
        if not policy.network_egress_permitted:
            return False
        for row in policy.channel_policies:
            if row.channel is EgressChannel.UPDATE_CHECKS:
                return row.enabled is True
        return False
    return network_egress_permitted is True and update_checks_enabled is True


def compare_versions(installed: str, candidate: str) -> bool | None:
    """Return True when candidate is strictly newer; None when either version is unparsable."""

    if type(installed) is not str or type(candidate) is not str:
        return None
    if not installed or not candidate:
        return None
    try:
        left = Version(installed)
        right = Version(candidate)
    except InvalidVersion:
        return None
    return right > left


def upgrade_command_for(*, latest_version: str | None = None) -> str:
    """Primary remediation string (ADR-007). Never invents a pin from a failed check."""

    del latest_version  # Reserved for optional display; the guided command owns version selection.
    return PACKAGE_UPDATE_UPGRADE_COMMAND


def build_package_update_advisory(
    *,
    installed_version: str,
    latest_version: str | None,
    source: Literal["network", "cache", "none"] = "none",
    outcome: PackageUpdateOutcome | None = None,
) -> PackageUpdateAdvisory:
    """Pure advisory builder from already-resolved version strings."""

    if type(installed_version) is not str or not installed_version:
        raise ValueError("installed_version_invalid")
    if latest_version is not None and (type(latest_version) is not str or not latest_version):
        raise ValueError("latest_version_invalid")

    newer = False if latest_version is None else compare_versions(installed_version, latest_version)
    if newer is None:
        resolved: PackageUpdateOutcome = outcome or "skipped_unknown_version"
        return PackageUpdateAdvisory(
            outcome=resolved,
            installed_version=installed_version,
            latest_version=latest_version,
            is_newer=False,
            upgrade_command=upgrade_command_for(latest_version=latest_version),
            source=source,
        )
    if outcome is not None:
        resolved = outcome
    elif latest_version is None:
        resolved = "skipped_unavailable"
    elif newer:
        resolved = "newer_available"
    else:
        resolved = "up_to_date"
    return PackageUpdateAdvisory(
        outcome=resolved,
        installed_version=installed_version,
        latest_version=latest_version,
        is_newer=bool(newer),
        upgrade_command=upgrade_command_for(latest_version=latest_version),
        source=source,
    )


def advisory_tip_lines(advisory: PackageUpdateAdvisory) -> tuple[str, ...]:
    """Short interactive tip; empty when there is nothing to show."""

    if not advisory.is_newer or advisory.latest_version is None:
        return ()
    return (
        f"A newer Yoetz package is available "
        f"({advisory.installed_version} → {advisory.latest_version}).",
        f"Upgrade with: {advisory.upgrade_command}",
        "Use yoetz upgrade to plan host refresh and any migration. Nothing needs to be stopped: "
        "open sessions keep working and switch to the new version when reopened.",
    )


def _cache_path(root: Path | None = None) -> Path:
    base = state_dir() if root is None else root
    return base / _CACHE_NAME


def load_package_update_cache(
    *,
    root: Path | None = None,
    now: datetime | None = None,
) -> PackageUpdateCache | None:
    """Load a structural cache entry; fail closed on any parse/TTL problem."""

    del now  # Freshness is evaluated by callers that hold a clock.
    path = _cache_path(root)
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    if len(raw) > _MAX_CACHE_BYTES or not raw:
        return None
    try:
        parsed: object = json.loads(raw.decode("utf-8"))
    except UnicodeError, json.JSONDecodeError:
        return None
    if type(parsed) is not dict:
        return None
    document = cast(dict[str, object], parsed)
    if document.get("schema") != _CACHE_SCHEMA:
        return None
    version_raw = document.get("latest_version")
    fetched_raw = document.get("fetched_at")
    ttl_raw = document.get("ttl_seconds")
    if type(version_raw) is not str or not version_raw or type(fetched_raw) is not str:
        return None
    if type(ttl_raw) is not int or ttl_raw <= 0 or ttl_raw > 7 * 24 * 3600:
        return None
    try:
        fetched_at = datetime.fromisoformat(fetched_raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if fetched_at.tzinfo is None:
        return None
    return PackageUpdateCache(
        schema=_CACHE_SCHEMA,
        latest_version=version_raw,
        fetched_at=fetched_at.astimezone(UTC),
        ttl_seconds=ttl_raw,
    )


def store_package_update_cache(
    *,
    latest_version: str,
    fetched_at: datetime,
    ttl: timedelta = _DEFAULT_TTL,
    root: Path | None = None,
) -> None:
    """Write a structural cache entry under the state directory. Best-effort."""

    if type(latest_version) is not str or not latest_version:
        raise ValueError("latest_version_invalid")
    if fetched_at.tzinfo is None:
        raise ValueError("fetched_at_naive")
    ttl_seconds = int(ttl.total_seconds())
    if ttl_seconds <= 0:
        raise ValueError("ttl_invalid")
    document = {
        "schema": _CACHE_SCHEMA,
        "latest_version": latest_version,
        "fetched_at": fetched_at.astimezone(UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "ttl_seconds": ttl_seconds,
    }
    path = _cache_path(root)
    try:
        ensure_owner_only_dir(path.parent)
        payload = (
            json.dumps(document, separators=(",", ":"), sort_keys=True).encode("utf-8") + b"\n"
        )
        if len(payload) > _MAX_CACHE_BYTES:
            return
        path.write_bytes(payload)
        path.chmod(0o600)
    except OSError, PathSafetyError, ValueError:
        return


async def resolve_package_update_advisory(
    *,
    policy: PrivacyPolicy | None = None,
    network_egress_permitted: bool | None = None,
    update_checks_enabled: bool | None = None,
    installed_version: str | None = None,
    transport: UpdateChecksTransport | None = None,
    now: datetime | None = None,
    cache_root: Path | None = None,
    allow_network: bool = True,
) -> PackageUpdateAdvisory:
    """Policy-gated advisory resolution with cache and fail-closed network errors."""

    installed = installed_version if installed_version is not None else installed_package_version()
    permitted = (
        is_update_checks_permitted(policy)
        if policy is not None
        else is_update_checks_permitted(
            network_egress_permitted=network_egress_permitted,
            update_checks_enabled=update_checks_enabled,
        )
    )
    if not permitted:
        return build_package_update_advisory(
            installed_version=installed,
            latest_version=None,
            source="none",
            outcome="skipped_policy",
        )
    clock = now if now is not None else datetime.now(tz=UTC)
    cached = load_package_update_cache(root=cache_root)
    if cached is not None and cached.is_fresh(now=clock):
        return build_package_update_advisory(
            installed_version=installed,
            latest_version=cached.latest_version,
            source="cache",
        )
    if not allow_network:
        if cached is not None:
            return build_package_update_advisory(
                installed_version=installed,
                latest_version=cached.latest_version,
                source="cache",
            )
        return build_package_update_advisory(
            installed_version=installed,
            latest_version=None,
            source="none",
            outcome="skipped_unavailable",
        )
    client = transport if transport is not None else HttpxUpdateChecksTransport()
    try:
        latest = await client.fetch_latest_version()
    except UpdateChecksTransportError:
        if cached is not None:
            return build_package_update_advisory(
                installed_version=installed,
                latest_version=cached.latest_version,
                source="cache",
            )
        return build_package_update_advisory(
            installed_version=installed,
            latest_version=None,
            source="none",
            outcome="skipped_unavailable",
        )
    store_package_update_cache(latest_version=latest, fetched_at=clock, root=cache_root)
    return build_package_update_advisory(
        installed_version=installed,
        latest_version=latest,
        source="network",
    )


def package_update_report_fields(advisory: PackageUpdateAdvisory) -> Mapping[str, object]:
    """Structural fields for setup/connect reports (never work receipts)."""

    return {
        "installed_version": advisory.installed_version,
        "is_newer": advisory.is_newer,
        "latest_version": advisory.latest_version,
        "outcome": advisory.outcome,
        "source": advisory.source,
        "upgrade_command": advisory.upgrade_command,
    }
