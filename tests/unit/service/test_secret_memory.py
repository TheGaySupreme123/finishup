"""Local secret-memory one-shot, overwrite, and close semantics."""

from __future__ import annotations

import copy

import pytest

from finishup.adapters.keys.secret_memory import LocalSecretMemory
from finishup.ports.secret_memory import SecretConsumer, SecretMemoryError, SecretPurpose


def test_capture_overwrites_source_and_consumes_once() -> None:
    memory = LocalSecretMemory()
    source = bytearray(b"sixteen-byte-key")
    expected = bytes(source)
    handle = memory.capture(SecretPurpose.PORTABLE_RECOVERY, source)
    assert source == bytearray(len(source))
    assert handle.consume(SecretConsumer.RECOVERY_WRAPPER, bytes) == expected
    with pytest.raises(SecretMemoryError, match="already_consumed"):
        handle.consume(SecretConsumer.RECOVERY_WRAPPER, bytes)
    memory.close()


def test_wrong_consumer_fails_before_access() -> None:
    memory = LocalSecretMemory()
    handle = memory.capture(SecretPurpose.VAULT_UNLOCK, bytearray(b"sixteen-byte-key"))
    with pytest.raises(SecretMemoryError, match="consumer_forbidden"):
        handle.consume(SecretConsumer.PROVIDER_AUTHORIZER, bytes)
    assert handle.consume(SecretConsumer.VAULT_ROOT, bytes) == b"sixteen-byte-key"
    memory.close()


def test_close_invalidates_and_handles_are_not_copyable() -> None:
    memory = LocalSecretMemory()
    capability = memory.capability()
    handle = memory.allocate(SecretPurpose.VAULT_ROOT_KEY, 32)
    with pytest.raises(TypeError, match="not_copyable"):
        copy.copy(handle)
    memory.close()
    with pytest.raises(SecretMemoryError, match="already_consumed"):
        handle.consume(SecretConsumer.VAULT_ROOT, bytes)
    assert capability.one_shot_consumption == "active"
    assert capability.best_effort_overwrite == "active"
