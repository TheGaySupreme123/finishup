from __future__ import annotations

import subprocess

import pytest

from finishup.adapters.integrations.macos_artifact_presence import MacOSArtifactUserPresence
from finishup.ports.plugin_artifacts import ArtifactAuthority

_DIGEST = "sha256:" + "a" * 64
_REVIEW_ID = "b" * 64


def _authority() -> ArtifactAuthority:
    return ArtifactAuthority("review_only", _DIGEST, _REVIEW_ID)


def test_macos_presence_uses_fixed_local_authentication_prompt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        captured["command"] = command
        captured.update(kwargs)
        return subprocess.CompletedProcess(command, 0, b"approved\n", b"")

    monkeypatch.setattr(
        "finishup.adapters.integrations.macos_artifact_presence.sys.platform", "darwin"
    )
    monkeypatch.setattr(
        "finishup.adapters.integrations.macos_artifact_presence.subprocess.run", run
    )

    MacOSArtifactUserPresence().verify_artifact_review(_authority())

    command = captured["command"]
    assert isinstance(command, list)
    assert command[:4] == ["/usr/bin/osascript", "-l", "JavaScript", "-"]
    assert "plugin_artifact_apply" in command[4]
    assert _DIGEST in command[4]
    assert _REVIEW_ID in command[4]
    script = captured["input"]
    assert isinstance(script, bytes)
    assert b"LocalAuthentication" in script
    assert b"LAPolicyDeviceOwnerAuthentication" in script
    assert b"touchIDAuthenticationAllowableReuseDuration = 0" in script
    assert b"approved = Boolean(success);" in script
    assert captured["env"] == {"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"}
    assert captured["timeout"] == 130


@pytest.mark.parametrize(
    "completed",
    [
        subprocess.CompletedProcess([], 0, b"denied\n", b""),
        subprocess.CompletedProcess([], 0, b"unavailable\n", b""),
        subprocess.CompletedProcess([], 1, b"approved\n", b""),
    ],
)
def test_macos_presence_denial_or_invalid_result_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    completed: subprocess.CompletedProcess[bytes],
) -> None:
    def run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        return completed

    monkeypatch.setattr(
        "finishup.adapters.integrations.macos_artifact_presence.sys.platform", "darwin"
    )
    monkeypatch.setattr(
        "finishup.adapters.integrations.macos_artifact_presence.subprocess.run",
        run,
    )

    with pytest.raises(RuntimeError, match="human_authority_unavailable"):
        MacOSArtifactUserPresence().verify_artifact_review(_authority())


def test_non_macos_presence_fails_before_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "finishup.adapters.integrations.macos_artifact_presence.sys.platform", "linux"
    )
    called = False

    def run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        nonlocal called
        called = True
        return subprocess.CompletedProcess([], 0, b"approved\n", b"")

    monkeypatch.setattr(
        "finishup.adapters.integrations.macos_artifact_presence.subprocess.run", run
    )

    with pytest.raises(RuntimeError, match="human_authority_unavailable"):
        MacOSArtifactUserPresence().verify_artifact_review(_authority())
    assert called is False
