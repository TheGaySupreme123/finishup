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

from finishup.adapters.privacy.update_checks import (
    HttpxUpdateChecksTransport,
    UpdateChecksTransport,
    UpdateChecksTransportError,
)
from finishup.config.paths import PathSafetyError, ensure_owner_only_dir, state_dir
from finishup.domain.privacy import EgressChannel, PrivacyPolicy
from finishup.legacy_names import LAUNCHER_NAME, LEGACY_LAUNCHER_NAME

__all__ = [
    "PACKAGE_UPDATE_UPGRADE_COMMAND",
    "PACKAGE_INSTALL_COMMAND",
    "PackageUpdateAdvisory",
    "PackageUpdateCache",
    "PackageUpdateOutcome",
    "advisory_tip_lines",
    "build_package_update_advisory",
    "compare_versions",
    "installed_package_name",
    "installed_package_version",
    "is_update_checks_permitted",
    "load_package_update_cache",
    "package_update_report_fields",
    "resolve_package_update_advisory",
    "store_package_update_cache",
    "upgrade_command_for",
]

PACKAGE_UPDATE_UPGRADE_COMMAND: Final = "finishup upgrade"
PACKAGE_INSTALL_COMMAND: Final = "uv tool install --managed-python --python 3.14.6 finishup"
# Frozen legacy identifier (ADR-048): the cache file keeps its schema tag so earlier releases
# sharing the state directory still read it. The optional ``package`` member names the PyPI
# identity that was polled; a cache without one was written by a release that polled ``yoetz``.
_CACHE_SCHEMA: Final = "yoetz.package-update-cache/1"
# One cache file per polled PyPI identity, so a ``finishup`` and a ``yoetz`` installation sharing
# an adopted state directory never overwrite each other's entry or bypass its TTL.
_CACHE_NAMES: Final = {
    # Releases before the rename read this file and treat any entry in it as a ``yoetz`` poll,
    # so it only ever holds ``yoetz`` polls (ADR-048).
    LEGACY_LAUNCHER_NAME: "package-update-cache.json",
    LAUNCHER_NAME: "package-update-cache-finishup.json",
}
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
    package: str = LAUNCHER_NAME

    def tip_lines(self) -> tuple[str, ...]:
        return advisory_tip_lines(self)


@dataclass(frozen=True, slots=True)
class PackageUpdateCache:
    schema: str
    latest_version: str
    fetched_at: datetime
    ttl_seconds: int
    package: str = LAUNCHER_NAME

    def is_fresh(self, *, now: datetime) -> bool:
        if now.tzinfo is None or self.fetched_at.tzinfo is None:
            return False
        age = now - self.fetched_at
        return age >= timedelta(0) and age <= timedelta(seconds=self.ttl_seconds)


def installed_package_version() -> str:
    """Return the running distribution version without network I/O."""

    from finishup import __version__

    return __version__


def installed_package_name() -> str:
    """Name the PyPI identity this installation upgrades through, without network I/O.

    An installation that came from the transitional ``yoetz`` distribution (ADR-048) has that
    distribution, at exactly this version, installed beside ``finishup``; it upgrades and polls
    through ``yoetz``. Everything else is ``finishup``.
    """

    from importlib.metadata import PackageNotFoundError, version

    try:
        legacy = version(LEGACY_LAUNCHER_NAME)
    except PackageNotFoundError, ValueError:
        return LAUNCHER_NAME
    return LEGACY_LAUNCHER_NAME if legacy == installed_package_version() else LAUNCHER_NAME


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


def upgrade_command_for(*, latest_version: str | None = None, package: str = LAUNCHER_NAME) -> str:
    """Primary remediation string (ADR-007). Never invents a pin from a failed check.

    An installation from the transitional ``yoetz`` distribution names the command it has on
    ``PATH``: its ``finishup`` script sits inside the tool environment, not on ``PATH``.
    """

    del latest_version  # Reserved for optional display; the guided command owns version selection.
    if package == LEGACY_LAUNCHER_NAME:
        return f"{LEGACY_LAUNCHER_NAME} upgrade"
    return PACKAGE_UPDATE_UPGRADE_COMMAND


def build_package_update_advisory(
    *,
    installed_version: str,
    latest_version: str | None,
    source: Literal["network", "cache", "none"] = "none",
    outcome: PackageUpdateOutcome | None = None,
    package: str = LAUNCHER_NAME,
) -> PackageUpdateAdvisory:
    """Pure advisory builder from already-resolved version strings."""

    if type(installed_version) is not str or not installed_version:
        raise ValueError("installed_version_invalid")
    if package not in _CACHE_NAMES:
        raise ValueError("package_invalid")
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
            upgrade_command=upgrade_command_for(latest_version=latest_version, package=package),
            source=source,
            package=package,
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
        upgrade_command=upgrade_command_for(latest_version=latest_version, package=package),
        source=source,
        package=package,
    )


def advisory_tip_lines(advisory: PackageUpdateAdvisory) -> tuple[str, ...]:
    """Short interactive tip; empty when there is nothing to show."""

    if not advisory.is_newer or advisory.latest_version is None:
        return ()
    lines = (
        f"A newer FinishUP package is available "
        f"({advisory.installed_version} → {advisory.latest_version}).",
        f"Upgrade with: {advisory.upgrade_command}",
        f"Use {advisory.upgrade_command} to plan host refresh and any migration. Nothing needs to "
        "be stopped: open sessions keep working and switch to the new version when reopened.",
    )
    if advisory.package == LEGACY_LAUNCHER_NAME:
        lines += (
            "The yoetz command is deprecated and a later release removes it. Until then, any "
            "finishup command FinishUP shows also works as yoetz with the same subcommand. Its "
            "plan ends with the steps to move this installation to the finishup command.",
        )
    return lines


def _cache_path(root: Path | None, package: str) -> Path:
    name = _CACHE_NAMES.get(package)
    if name is None:
        raise ValueError("package_invalid")
    base = state_dir() if root is None else root
    return base / name


def load_package_update_cache(
    *,
    root: Path | None = None,
    now: datetime | None = None,
    package: str | None = None,
) -> PackageUpdateCache | None:
    """Load a structural cache entry; fail closed on any parse/TTL problem.

    ``package`` (default: this installation's, ``installed_package_name``) selects that PyPI
    identity's own cache file. An entry recording a different identity is not returned, so a
    state directory shared by a ``finishup`` and a ``yoetz`` installation never mixes answers.
    """

    del now  # Freshness is evaluated by callers that hold a clock.
    wanted = installed_package_name() if package is None else package
    if wanted not in _CACHE_NAMES:
        return None
    path = _cache_path(root, wanted)
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
    # A cache without ``package`` was written by a pre-rename release polling ``yoetz`` (ADR-048).
    polled = document.get("package", LEGACY_LAUNCHER_NAME)
    if polled != wanted:
        return None
    return PackageUpdateCache(
        schema=_CACHE_SCHEMA,
        latest_version=version_raw,
        fetched_at=fetched_at.astimezone(UTC),
        ttl_seconds=ttl_raw,
        package=wanted,
    )


def store_package_update_cache(
    *,
    latest_version: str,
    fetched_at: datetime,
    ttl: timedelta = _DEFAULT_TTL,
    root: Path | None = None,
    package: str | None = None,
) -> None:
    """Write a structural cache entry to the polled identity's own file. Best-effort.

    ``package`` defaults to this installation's identity (``installed_package_name``).
    """

    if type(latest_version) is not str or not latest_version:
        raise ValueError("latest_version_invalid")
    polled = installed_package_name() if package is None else package
    if polled not in _CACHE_NAMES:
        raise ValueError("package_invalid")
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
        "package": polled,
    }
    path = _cache_path(root, polled)
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
    package: str | None = None,
) -> PackageUpdateAdvisory:
    """Policy-gated advisory resolution with cache and fail-closed network errors.

    ``package`` defaults to the identity this installation came from (``installed_package_name``).
    """

    installed = installed_version if installed_version is not None else installed_package_version()
    polled = package if package is not None else installed_package_name()
    if polled not in _CACHE_NAMES:
        raise ValueError("package_invalid")
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
            package=polled,
            latest_version=None,
            source="none",
            outcome="skipped_policy",
        )
    clock = now if now is not None else datetime.now(tz=UTC)
    cached = load_package_update_cache(root=cache_root, package=polled)
    if cached is not None and cached.is_fresh(now=clock):
        return build_package_update_advisory(
            installed_version=installed,
            package=polled,
            latest_version=cached.latest_version,
            source="cache",
        )
    if not allow_network:
        if cached is not None:
            return build_package_update_advisory(
                installed_version=installed,
                package=polled,
                latest_version=cached.latest_version,
                source="cache",
            )
        return build_package_update_advisory(
            installed_version=installed,
            package=polled,
            latest_version=None,
            source="none",
            outcome="skipped_unavailable",
        )
    client = transport if transport is not None else HttpxUpdateChecksTransport(package=polled)
    try:
        latest = await client.fetch_latest_version()
    except UpdateChecksTransportError:
        if cached is not None:
            return build_package_update_advisory(
                installed_version=installed,
                package=polled,
                latest_version=cached.latest_version,
                source="cache",
            )
        return build_package_update_advisory(
            installed_version=installed,
            package=polled,
            latest_version=None,
            source="none",
            outcome="skipped_unavailable",
        )
    store_package_update_cache(
        latest_version=latest, fetched_at=clock, root=cache_root, package=polled
    )
    return build_package_update_advisory(
        installed_version=installed,
        latest_version=latest,
        source="network",
        package=polled,
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
