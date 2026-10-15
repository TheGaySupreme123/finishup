"""Portable-recovery known answers and one-shot boundaries."""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Callable
from typing import cast

import pytest

import finishup.adapters.keys.passphrase as passphrase_adapter
from finishup.adapters.keys.passphrase import unlock_recovery_artifact, wrap_recovery_artifact
from finishup.adapters.keys.secret_memory import LocalSecretMemory
from finishup.ports.keys import RecoveryArtifact, RecoveryKeyMaterialHandle, RecoverySecret
from finishup.ports.secret_memory import SecretPurpose
from fixture_loader import FixtureLoader, JsonValue


class _FixedKeyMaterial:
    def __init__(self, value: bytes) -> None:
        self._value = value

    def consume[T](self, fn: Callable[[memoryview], T]) -> T:
        return fn(memoryview(self._value))


def _portable_vector(loader: FixtureLoader) -> dict[str, JsonValue]:
    fixture = loader.load_json("canonical/object-envelope.case.json")
    assert isinstance(fixture, dict)
    inputs = fixture["input"]
    assert isinstance(inputs, dict)
    value = inputs["portable_recovery"]
    assert isinstance(value, dict)
    return value


def test_passphrase_recovery_is_portable(fixture_loader: FixtureLoader) -> None:
    portable = _portable_vector(fixture_loader)
    vector = portable["vector"]
    assert isinstance(vector, dict)
    artifact_value = vector["artifact"]
    assert isinstance(artifact_value, dict)
    encoded = artifact_value["base64"]
    assert isinstance(encoded, str)
    raw = base64.b64decode(encoded)
    artifact = RecoveryArtifact(raw, f"sha256:{hashlib.sha256(raw).hexdigest()}")
    secret_value = portable["recovery_secret"]
    assert isinstance(secret_value, dict)
    secret_b64 = secret_value["test_only_base64"]
    assert isinstance(secret_b64, str)
    memory = LocalSecretMemory()
    secret = cast(
        RecoverySecret,
        memory.capture(SecretPurpose.PORTABLE_RECOVERY, bytearray(base64.b64decode(secret_b64))),
    )
    recovered = unlock_recovery_artifact(artifact, secret)
    expected = portable["bmk_hex"]
    assert isinstance(expected, str)
    assert recovered.consume(lambda view: bytes(view).hex()) == expected
    memory.close()


def test_recovery_envelope_known_answers_and_parameter_caps(
    fixture_loader: FixtureLoader,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    portable = _portable_vector(fixture_loader)
    vector = portable["vector"]
    assert isinstance(vector, dict)
    salt_hex = vector["salt_hex"]
    bmk_hex = portable["bmk_hex"]
    body = vector["body"]
    secret_value = portable["recovery_secret"]
    artifact_value = vector["artifact"]
    assert isinstance(salt_hex, str)
    assert isinstance(bmk_hex, str)
    assert (
        isinstance(body, dict)
        and isinstance(secret_value, dict)
        and isinstance(artifact_value, dict)
    )
    binding = body["binding"]
    assert isinstance(binding, dict)
    task_id = binding["task_id"]
    key_slot = binding["key_slot"]
    secret_b64 = secret_value["test_only_base64"]
    expected_b64 = artifact_value["base64"]
    assert isinstance(task_id, str)
    assert isinstance(key_slot, str)
    assert isinstance(secret_b64, str)
    assert isinstance(expected_b64, str)

    def _fixed_salt(size: int) -> bytes:
        assert size == 32
        return bytes.fromhex(salt_hex)

    monkeypatch.setattr(passphrase_adapter.os, "urandom", _fixed_salt)
    memory = LocalSecretMemory()
    secret = cast(
        RecoverySecret,
        memory.capture(SecretPurpose.PORTABLE_RECOVERY, bytearray(base64.b64decode(secret_b64))),
    )
    material = cast(RecoveryKeyMaterialHandle, _FixedKeyMaterial(bytes.fromhex(bmk_hex)))
    artifact = wrap_recovery_artifact(
        material,
        secret,
        task_id=task_id,
        key_slot=key_slot,
    )
    assert artifact.canonical_bytes == base64.b64decode(expected_b64)
    memory.close()
