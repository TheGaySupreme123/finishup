"""Unit tests for exact Codex capability artifact identity capture."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

import pytest

from finishup.adapters.integrations.codex_capability_harness import (
    CODEX_ARTIFACT_UNAVAILABLE,
    CODEX_CONDUIT_DRIVER_UNAVAILABLE,
    CodexArtifactIdentity,
    capture_codex_artifact_identity,
    evaluate_codex_conduit_availability,
)


def _fake_binary(directory: Path, *, name: str = "codex", payload: bytes = b"codex-fake\n") -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    binary = directory / name
    binary.write_bytes(payload)
    os.chmod(binary, stat.S_IRWXU)
    return binary


def test_capture_codex_artifact_identity_includes_prerelease_and_digest(tmp_path: Path) -> None:
    binary = _fake_binary(tmp_path / "bin", payload=b"#!/bin/sh\necho fake\n")
    identity = capture_codex_artifact_identity(
        str(binary),
        reported_version="0.146.0-alpha.2",
    )
    expected = f"sha256:{hashlib.sha256(binary.read_bytes()).hexdigest()}"
    assert identity.reported_version == "0.146.0-alpha.2"
    assert identity.executable_digest == expected
    assert identity.executable_path == str(binary)


def test_capture_rejects_missing_file(tmp_path: Path) -> None:
    missing = tmp_path / "missing-codex"
    with pytest.raises(ValueError, match="executable_not_regular_file"):
        capture_codex_artifact_identity(str(missing), reported_version="0.146.0")


def test_evaluate_codex_conduit_availability_fail_closed_without_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "finishup.adapters.integrations.codex_capability_harness.discover_codex_binaries",
        lambda: (),
    )
    availability, identity = evaluate_codex_conduit_availability()
    assert availability == CODEX_ARTIFACT_UNAVAILABLE
    assert identity is None


def test_evaluate_codex_conduit_availability_never_calls_discovery_ready(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = CodexArtifactIdentity("/safe/codex", "0.146.0", "sha256:" + "a" * 64)
    monkeypatch.setattr(
        "finishup.adapters.integrations.codex_capability_harness.discover_codex_capability_artifact",
        lambda: expected,
    )
    availability, identity = evaluate_codex_conduit_availability()
    assert availability == CODEX_CONDUIT_DRIVER_UNAVAILABLE
    assert identity is expected
