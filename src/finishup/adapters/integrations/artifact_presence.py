"""Per-platform selection of the scoped ``plugin_artifact_apply`` presence cell.

Each cell proves fresh, action-bound, OS-authenticated user presence for one exact preview
digest and pending review before ``ElevatedPortableArtifactReview`` consumes the pending
(ADR-016, ADR-023). A platform without a proven cell fails closed with
``human_authority_unavailable`` before mutation; nothing here widens authority to another
operation or to the service-wide ``UserPresencePort``.
"""

from __future__ import annotations

import sys
from typing import Final, Literal

from finishup.adapters.integrations.linux_artifact_presence import LinuxArtifactUserPresence
from finishup.adapters.integrations.macos_artifact_presence import MacOSArtifactUserPresence
from finishup.adapters.integrations.portable_plugin import ArtifactUserPresencePort
from finishup.ports.plugin_artifacts import ArtifactAuthority

__all__ = [
    "PresenceMechanism",
    "UnsupportedArtifactUserPresence",
    "describe_artifact_presence",
    "select_artifact_user_presence",
]

PresenceMechanism = Literal[
    "macos_local_authentication",
    "linux_pam_trusted_console",
    "unsupported",
]

_MECHANISMS: Final[dict[str, PresenceMechanism]] = {
    "darwin": "macos_local_authentication",
    "linux": "linux_pam_trusted_console",
}
_INGRESS: Final[dict[PresenceMechanism, str | None]] = {
    "macos_local_authentication": "os_dialog",
    "linux_pam_trusted_console": "trusted_console",
    "unsupported": None,
}


class UnsupportedArtifactUserPresence:
    """Fail closed on every platform without a proven action-bound presence cell."""

    def verify_artifact_review(self, authority: ArtifactAuthority) -> None:
        del authority
        raise RuntimeError("human_authority_unavailable")


def _platform(platform: str | None) -> str:
    return sys.platform if platform is None else platform


def presence_mechanism(platform: str | None = None) -> PresenceMechanism:
    return _MECHANISMS.get(_platform(platform), "unsupported")


def select_artifact_user_presence(platform: str | None = None) -> ArtifactUserPresencePort:
    """Return the presence cell for ``platform`` (default: the running interpreter's)."""

    mechanism = presence_mechanism(platform)
    if mechanism == "macos_local_authentication":
        return MacOSArtifactUserPresence()
    if mechanism == "linux_pam_trusted_console":
        return LinuxArtifactUserPresence()
    return UnsupportedArtifactUserPresence()


def describe_artifact_presence(platform: str | None = None) -> dict[str, str | bool | None]:
    """Preview-facing description of the authority mechanism the mutation will consume."""

    mechanism = presence_mechanism(platform)
    return {
        "ingress": _INGRESS[mechanism],
        "mechanism": mechanism,
        "platform": _platform(platform),
        "supported": mechanism != "unsupported",
    }
