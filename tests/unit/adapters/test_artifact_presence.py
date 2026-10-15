from __future__ import annotations

from types import SimpleNamespace

import pytest

from finishup.adapters.integrations import artifact_presence
from finishup.adapters.integrations.artifact_presence import (
    UnsupportedArtifactUserPresence,
    describe_artifact_presence,
    select_artifact_user_presence,
)
from finishup.adapters.integrations.linux_artifact_presence import LinuxArtifactUserPresence
from finishup.adapters.integrations.macos_artifact_presence import MacOSArtifactUserPresence
from finishup.ports.plugin_artifacts import ArtifactAuthority


@pytest.mark.parametrize(
    ("platform", "adapter", "mechanism", "ingress"),
    [
        ("darwin", MacOSArtifactUserPresence, "macos_local_authentication", "os_dialog"),
        ("linux", LinuxArtifactUserPresence, "linux_pam_trusted_console", "trusted_console"),
        ("win32", UnsupportedArtifactUserPresence, "unsupported", None),
        ("freebsd14", UnsupportedArtifactUserPresence, "unsupported", None),
    ],
)
def test_presence_cell_follows_the_platform(
    platform: str, adapter: type[object], mechanism: str, ingress: str | None
) -> None:
    assert type(select_artifact_user_presence(platform)) is adapter
    assert describe_artifact_presence(platform) == {
        "ingress": ingress,
        "mechanism": mechanism,
        "platform": platform,
        "supported": mechanism != "unsupported",
    }


def test_presence_cell_defaults_to_the_running_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(artifact_presence, "sys", SimpleNamespace(platform="linux"))
    assert type(select_artifact_user_presence()) is LinuxArtifactUserPresence
    assert describe_artifact_presence()["platform"] == "linux"

    monkeypatch.setattr(artifact_presence, "sys", SimpleNamespace(platform="win32"))
    assert type(select_artifact_user_presence()) is UnsupportedArtifactUserPresence
    assert describe_artifact_presence()["supported"] is False


def test_unsupported_cell_always_fails_closed() -> None:
    authority = ArtifactAuthority("review_only", "sha256:" + "a" * 64, "b" * 64)
    with pytest.raises(RuntimeError, match="human_authority_unavailable"):
        UnsupportedArtifactUserPresence().verify_artifact_review(authority)
