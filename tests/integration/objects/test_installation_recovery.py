"""Installation recovery artifact, secret-form, and one-shot boundaries."""

from __future__ import annotations

import json
from typing import cast

import pytest

from finishup.adapters.keys.installation_recovery import (
    InstallationRecoveryArtifact,
    InstallationRecoveryArtifactError,
    InstallationRecoveryMode,
    InstallationRecoverySecretKind,
    create_installation_recovery_artifact,
    generate_recovery_code,
    unlock_installation_recovery_artifact,
    validate_generated_recovery_code,
)
from finishup.adapters.keys.secret_memory import LocalSecretMemory
from finishup.ports.secret_memory import SecretPurpose
from finishup.protocol.canonical import JsonValue, canonical_encode

_SNAPSHOT_DIGEST = "sha256:" + "7" * 64


def _artifact(
    memory: LocalSecretMemory,
    *,
    mode: InstallationRecoveryMode,
    kind: InstallationRecoverySecretKind,
    secret: bytearray,
) -> InstallationRecoveryArtifact:
    return create_installation_recovery_artifact(
        memory.capture(SecretPurpose.VAULT_ROOT_KEY, bytearray(range(32))),
        memory.capture(SecretPurpose.INSTALLATION_RECOVERY, secret),
        recovery_generation=3,
        mode=mode,
        secret_kind=kind,
        snapshot_manifest_digest=(
            _SNAPSHOT_DIGEST if mode is InstallationRecoveryMode.SELF_CONTAINED else None
        ),
    )


def test_generated_recovery_code_has_160_bits_and_checksum() -> None:
    code = generate_recovery_code()
    validate_generated_recovery_code(memoryview(code))
    assert code.startswith(b"YRK1-")
    assert len(code.replace(b"-", b"").removeprefix(b"YRK1")) == 36

    changed = bytearray(code)
    changed[-1] = ord("A") if changed[-1] != ord("A") else ord("B")
    with pytest.raises(InstallationRecoveryArtifactError, match="secret_invalid"):
        validate_generated_recovery_code(memoryview(changed))


@pytest.mark.parametrize(
    ("mode", "kind"),
    [
        (
            InstallationRecoveryMode.COMPACT,
            InstallationRecoverySecretKind.ARGON2ID_PASSPHRASE,
        ),
        (
            InstallationRecoveryMode.SELF_CONTAINED,
            InstallationRecoverySecretKind.GENERATED_CODE,
        ),
    ],
)
def test_installation_artifact_round_trips_exact_ivk(
    mode: InstallationRecoveryMode,
    kind: InstallationRecoverySecretKind,
) -> None:
    memory = LocalSecretMemory()
    source = (
        generate_recovery_code()
        if kind is InstallationRecoverySecretKind.GENERATED_CODE
        else bytearray(b"correct horse battery staple")
    )
    secret_copy = bytearray(source)
    artifact = _artifact(memory, mode=mode, kind=kind, secret=source)
    material = unlock_installation_recovery_artifact(
        artifact,
        memory.capture(SecretPurpose.INSTALLATION_RECOVERY, secret_copy),
    )
    assert material.recovery_generation == 3
    assert material.mode is mode
    assert material.snapshot_manifest_digest == (
        _SNAPSHOT_DIGEST if mode is InstallationRecoveryMode.SELF_CONTAINED else None
    )
    assert material.consume_ivk(bytes) == bytes(range(32))
    with pytest.raises(InstallationRecoveryArtifactError, match="stale_handle"):
        material.consume_ivk(bytes)
    memory.close()


def test_wrong_secret_and_authenticated_tamper_fail_without_ivk() -> None:
    memory = LocalSecretMemory()
    secret = bytearray(b"correct horse battery staple")
    artifact = _artifact(
        memory,
        mode=InstallationRecoveryMode.COMPACT,
        kind=InstallationRecoverySecretKind.ARGON2ID_PASSPHRASE,
        secret=bytearray(secret),
    )
    with pytest.raises(InstallationRecoveryArtifactError, match="secret_or_artifact_invalid"):
        unlock_installation_recovery_artifact(
            artifact,
            memory.capture(
                SecretPurpose.INSTALLATION_RECOVERY,
                bytearray(b"wrong horse battery staple"),
            ),
        )

    source = cast(dict[str, JsonValue], json.loads(artifact.canonical_bytes))
    tag = source["auth_tag"]
    assert isinstance(tag, str)
    source["auth_tag"] = ("A" if tag[0] != "A" else "B") + tag[1:]
    tampered = InstallationRecoveryArtifact(canonical_encode(source))
    with pytest.raises(InstallationRecoveryArtifactError, match="secret_or_artifact_invalid"):
        unlock_installation_recovery_artifact(
            tampered,
            memory.capture(SecretPurpose.INSTALLATION_RECOVERY, bytearray(secret)),
        )
    memory.close()


def test_artifact_and_failures_expose_no_secret_path_or_plaintext_key_canaries() -> None:
    memory = LocalSecretMemory()
    secret = bytearray(b"recovery-secret-canary-horse-battery")
    root = bytearray(b"vault-root-canary-32-bytes-long!")
    assert len(root) == 32
    artifact = create_installation_recovery_artifact(
        memory.capture(SecretPurpose.VAULT_ROOT_KEY, bytearray(root)),
        memory.capture(SecretPurpose.INSTALLATION_RECOVERY, bytearray(secret)),
        recovery_generation=9,
        mode=InstallationRecoveryMode.COMPACT,
        secret_kind=InstallationRecoverySecretKind.ARGON2ID_PASSPHRASE,
        snapshot_manifest_digest=None,
    )
    forbidden = (
        bytes(secret),
        bytes(root),
        b"/" + b"Users/canary/private/path",
        b"provider-credential-canary",
        b"keyring-account-canary",
    )
    assert all(value not in artifact.canonical_bytes for value in forbidden)
    assert repr(artifact) == "<InstallationRecoveryArtifact redacted>"

    wrong = memory.capture(
        SecretPurpose.INSTALLATION_RECOVERY,
        bytearray(b"different recovery secret battery"),
    )
    with pytest.raises(InstallationRecoveryArtifactError) as captured:
        unlock_installation_recovery_artifact(artifact, wrong)
    encoded_error = str(captured.value).encode("utf-8")
    assert encoded_error == b"secret_or_artifact_invalid"
    assert all(value not in encoded_error for value in forbidden)
    memory.close()


def test_mode_snapshot_binding_and_secret_purpose_fail_closed() -> None:
    memory = LocalSecretMemory()
    with pytest.raises(InstallationRecoveryArtifactError, match="snapshot_binding_invalid"):
        create_installation_recovery_artifact(
            memory.capture(SecretPurpose.VAULT_ROOT_KEY, bytearray(range(32))),
            memory.capture(
                SecretPurpose.INSTALLATION_RECOVERY,
                bytearray(b"correct horse battery staple"),
            ),
            recovery_generation=1,
            mode=InstallationRecoveryMode.SELF_CONTAINED,
            secret_kind=InstallationRecoverySecretKind.ARGON2ID_PASSPHRASE,
            snapshot_manifest_digest=None,
        )

    with pytest.raises(InstallationRecoveryArtifactError, match="secret_purpose_mismatch"):
        create_installation_recovery_artifact(
            memory.capture(SecretPurpose.VAULT_ROOT_KEY, bytearray(range(32))),
            memory.capture(
                SecretPurpose.PORTABLE_RECOVERY,
                bytearray(b"correct horse battery staple"),
            ),
            recovery_generation=1,
            mode=InstallationRecoveryMode.COMPACT,
            secret_kind=InstallationRecoverySecretKind.ARGON2ID_PASSPHRASE,
            snapshot_manifest_digest=None,
        )
    memory.close()
