"""Bounded identity probe of a rendered FinishUP launcher.

A native carrier binds an absolute launcher into its hooks and plugin-owned MCP entry, and the
managed marker records that launcher. Carrier-byte equality proves what the host will *spawn*; it
does not prove which FinishUP package answers. This probe runs the recorded launcher's read-only
``version --json`` and compares the package version, control result schema, and resource-manifest
digest with the runtime performing the status read, so ``status`` can say whether the bound
executable is this installation or a neighbouring channel (issue #468).
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, Protocol, cast

from finishup.adapters.integrations.launcher import valid_launcher
from finishup.protocol.canonical import JsonValue, ProtocolValueError, strict_json_parse

__all__ = [
    "FixedLauncherProbe",
    "LauncherIdentity",
    "LauncherProbePort",
    "OsLauncherProbe",
    "compare_launcher_identity",
]

_PROBE_TIMEOUT_SECONDS: Final = 20.0
_MAX_PROBE_BYTES: Final = 256 * 1024
_MAX_TOKEN: Final = 128
_CONTROL_RESULT_SCHEMA: Final = "control-result"


@dataclass(frozen=True, slots=True)
class LauncherIdentity:
    """Bounded identity facts of the runtime behind one launcher.

    ``observed`` is false when the probe did not run or its answer was unusable; every other
    field is then ``None``. ``matched`` is true only when package version, control result schema
    version, and resource-manifest digest all equal the comparing runtime's own values.
    """

    observed: bool
    matched: bool | None
    package_version: str | None
    control_schema_version: str | None
    resource_manifest_digest: str | None

    def __post_init__(self) -> None:
        if type(self.observed) is not bool:
            raise ValueError("launcher_identity_invalid")
        if not self.observed:
            if any(
                value is not None
                for value in (
                    self.matched,
                    self.package_version,
                    self.control_schema_version,
                    self.resource_manifest_digest,
                )
            ):
                raise ValueError("launcher_identity_invalid")
            return
        if type(self.matched) is not bool:
            raise ValueError("launcher_identity_invalid")
        for value in (
            self.package_version,
            self.control_schema_version,
            self.resource_manifest_digest,
        ):
            if type(value) is not str or not value or len(value) > _MAX_TOKEN:
                raise ValueError("launcher_identity_invalid")
            if any(ord(char) < 32 or ord(char) == 127 for char in value):
                raise ValueError("launcher_identity_invalid")


UNOBSERVED_LAUNCHER_IDENTITY: Final = LauncherIdentity(False, None, None, None, None)


class LauncherProbePort(Protocol):
    def probe(self, launcher: tuple[str, ...]) -> Mapping[str, JsonValue] | None:
        """Return the launcher's parsed ``version --json`` document, or ``None``."""


@dataclass(frozen=True, slots=True)
class FixedLauncherProbe:
    document: Mapping[str, JsonValue] | None

    def probe(self, launcher: tuple[str, ...]) -> Mapping[str, JsonValue] | None:
        del launcher
        return self.document


class OsLauncherProbe:
    """Run ``<launcher> version --json`` with no shell, no stdin, and a minimal environment."""

    def probe(self, launcher: tuple[str, ...]) -> Mapping[str, JsonValue] | None:
        if not valid_launcher(launcher):
            return None
        env: dict[str, str] = {"LANG": "C", "LC_ALL": "C"}
        for name in ("HOME", "PATH", "TMPDIR", "SYSTEMROOT", "USERPROFILE"):
            value = os.environ.get(name)
            if value is not None:
                env[name] = value
        try:
            completed = subprocess.run(
                [*launcher, "version", "--json"],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                check=False,
                env=env,
                shell=False,
                timeout=_PROBE_TIMEOUT_SECONDS,
            )
        except OSError, ValueError, subprocess.SubprocessError:
            return None
        if completed.returncode != 0 or len(completed.stdout) > _MAX_PROBE_BYTES:
            return None
        try:
            parsed = strict_json_parse(completed.stdout.strip())
        except ProtocolValueError, UnicodeError, ValueError:
            return None
        if not isinstance(parsed, Mapping):
            return None
        return cast(Mapping[str, JsonValue], parsed)


def _token(value: object) -> str | None:
    if type(value) is not str or not value or len(value) > _MAX_TOKEN:
        return None
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        return None
    return value


def compare_launcher_identity(
    document: Mapping[str, JsonValue] | None,
    *,
    package_version: str,
    control_schema_version: str,
    resource_manifest_digest: str,
) -> LauncherIdentity:
    """Compare one probed ``version --json`` document with the comparing runtime's identity."""

    if document is None:
        return UNOBSERVED_LAUNCHER_IDENTITY
    probed_version = _token(document.get("package_version"))
    probed_digest = _token(document.get("resource_manifest_digest"))
    schema_versions = document.get("request_result_schema_versions")
    probed_control = (
        _token(cast(Mapping[str, object], schema_versions).get(_CONTROL_RESULT_SCHEMA))
        if isinstance(schema_versions, Mapping)
        else None
    )
    if probed_version is None or probed_digest is None or probed_control is None:
        return UNOBSERVED_LAUNCHER_IDENTITY
    matched = (
        probed_version == package_version
        and probed_control == control_schema_version
        and probed_digest == resource_manifest_digest
    )
    return LauncherIdentity(True, matched, probed_version, probed_control, probed_digest)
