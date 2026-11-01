"""Gate-2 Codex capability harness skeleton: exact artifact identity and fail-closed discovery.

This module captures structural identity for an exact Codex executable and exposes a bounded
entry point for future app-server conduit checks. It does not drive app-server protocol, claim a
supported Codex profile, or treat discovery alone as capability evidence.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal

from finishup.adapters.integrations.codex_discovery import discover_codex_binaries

__all__ = [
    "CODEX_ARTIFACT_UNAVAILABLE",
    "CODEX_CONDUIT_DRIVER_UNAVAILABLE",
    "CodexArtifactIdentity",
    "CodexConduitAvailability",
    "capture_codex_artifact_identity",
    "discover_codex_capability_artifact",
    "evaluate_codex_conduit_availability",
]

CODEX_ARTIFACT_UNAVAILABLE: Final = "codex_artifact_unavailable"
CODEX_CONDUIT_DRIVER_UNAVAILABLE: Final = "codex_conduit_driver_unavailable"

type CodexConduitAvailability = Literal[
    "codex_artifact_unavailable", "codex_conduit_driver_unavailable"
]


@dataclass(frozen=True, slots=True, repr=False)
class CodexArtifactIdentity:
    """Exact Codex executable identity for capability evidence binding.

    ``reported_version`` retains the full SemVer token including any prerelease/build suffix.
    ``executable_digest`` is the SHA-256 of the executable file bytes. Paths are never echoed in
    ``repr``.
    """

    executable_path: str
    reported_version: str
    executable_digest: str

    def __post_init__(self) -> None:
        if type(self.executable_path) is not str or not self.executable_path:
            raise ValueError("executable_path_invalid")
        if type(self.reported_version) is not str or not self.reported_version:
            raise ValueError("reported_version_invalid")
        if (
            type(self.executable_digest) is not str
            or not self.executable_digest.startswith("sha256:")
            or len(self.executable_digest) != 71
        ):
            raise ValueError("executable_digest_invalid")


def capture_codex_artifact_identity(
    executable_path: str,
    *,
    reported_version: str,
) -> CodexArtifactIdentity:
    """Return path, full version string, and sha256 digest of one Codex executable file.

    This is a pure structural capture: it reads file bytes and never executes the binary.
    """

    if type(executable_path) is not str or not executable_path:
        raise ValueError("executable_path_invalid")
    if type(reported_version) is not str or not reported_version:
        raise ValueError("reported_version_invalid")
    path = Path(executable_path)
    if path.is_symlink() or not path.is_file():
        raise ValueError("executable_not_regular_file")
    data = path.read_bytes()
    digest = f"sha256:{hashlib.sha256(data).hexdigest()}"
    return CodexArtifactIdentity(
        executable_path=str(path),
        reported_version=reported_version,
        executable_digest=digest,
    )


def discover_codex_capability_artifact() -> CodexArtifactIdentity | None:
    """Discover one Codex executable and capture its exact identity, or return ``None``.

    Returns ``None`` when no Codex binary is discoverable or no candidate reports a parseable
    full version string. Callers must treat ``None`` as ``codex_artifact_unavailable`` and must
    not invent a supported profile.
    """

    binaries = discover_codex_binaries()
    for binary in binaries:
        version = binary.reported_version
        if version is None:
            continue
        try:
            return capture_codex_artifact_identity(
                binary.executable_path,
                reported_version=version,
            )
        except (OSError, ValueError):
            continue
    return None


def evaluate_codex_conduit_availability() -> tuple[
    CodexConduitAvailability, CodexArtifactIdentity | None
]:
    """Gate-2 entry point: report whether a Codex conduit harness can run.

    When no exact artifact is available this returns
    ``("codex_artifact_unavailable", None)`` and never pretends the conduit checks passed.
    Discovery alone never means ready. When an exact artifact exists but the app-server driver
    is not implemented, return its identity with ``codex_conduit_driver_unavailable``.
    """

    identity = discover_codex_capability_artifact()
    if identity is None:
        return (CODEX_ARTIFACT_UNAVAILABLE, None)
    return (CODEX_CONDUIT_DRIVER_UNAVAILABLE, identity)
