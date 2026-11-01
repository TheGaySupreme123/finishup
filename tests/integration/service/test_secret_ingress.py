"""One-shot purpose and binding integration for confidential secret ingress."""

from __future__ import annotations

import asyncio
from datetime import datetime

import pytest

from finishup.adapters.keys.secret_memory import LocalSecretMemory
from finishup.ports.secret_memory import SecretConsumer, SecretHandle
from finishup.service.confidential_protocol import (
    ConfidentialSecretPurpose,
    SecretIngressBinding,
    encode_secret_header,
)
from finishup.service.secret_ingress import SecretIngressError, SecretIngressService

_SERVICE_ID = "svc_00000000-0000-4000-8000-000000000001"
_DIGEST = "sha256:" + "a" * 64


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class _Clock:
    def __init__(self, monotonic: float = 1.0) -> None:
        self.monotonic = monotonic

    def monotonic_seconds(self) -> float:
        return self.monotonic

    def now_utc(self) -> datetime:
        raise AssertionError("wall clock must not be sampled")


class _Stream:
    def __init__(self, payload: bytes, *, chunks: tuple[int, ...] = ()) -> None:
        self._payload = payload
        self._offset = 0
        self._chunks = iter(chunks)
        self.closed = False

    async def receive(self, max_bytes: int) -> bytes:
        if self._offset == len(self._payload):
            return b""
        try:
            requested = next(self._chunks)
        except StopIteration:
            requested = max_bytes
        size = min(max_bytes, requested, len(self._payload) - self._offset)
        result = self._payload[self._offset : self._offset + size]
        self._offset += size
        return result

    async def aclose(self) -> None:
        self.closed = True


class _BlockingStream:
    def __init__(self) -> None:
        self.entered = asyncio.Event()
        self.closed = False

    async def receive(self, max_bytes: int) -> bytes:
        del max_bytes
        self.entered.set()
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    async def aclose(self) -> None:
        self.closed = True


class _Listener:
    def __init__(self, streams: list[_Stream | _BlockingStream]) -> None:
        self._streams = streams
        self.closed = False

    async def accept(self) -> _Stream | _BlockingStream:
        if not self._streams:
            raise AssertionError("unexpected accept")
        return self._streams.pop(0)

    async def aclose(self) -> None:
        self.closed = True


def _binding(
    purpose: ConfidentialSecretPurpose,
    *,
    challenge: str = "2" * 64,
    service_generation: int = 3,
    vault_generation: int = 4,
    policy_generation: int | None = None,
    target_digest: str = _DIGEST,
    expiry_ms: int = 60_000,
) -> SecretIngressBinding:
    return SecretIngressBinding(
        binding_version=1,
        ceremony_id="1" * 64,
        secret_challenge=challenge,
        purpose=purpose,
        service_instance_id=_SERVICE_ID,
        service_generation=service_generation,
        vault_generation=vault_generation,
        policy_generation=policy_generation,
        target_digest=target_digest,
        expires_at_monotonic_ms=expiry_ms,
    )


def _frame(binding: SecretIngressBinding, secret: bytes, *, suffix: bytes = b"") -> bytes:
    return encode_secret_header(binding, len(secret)) + secret + suffix


def _consumer(purpose: ConfidentialSecretPurpose) -> SecretConsumer:
    if purpose is ConfidentialSecretPurpose.PORTABLE_RECOVERY:
        return SecretConsumer.RECOVERY_WRAPPER
    if purpose is ConfidentialSecretPurpose.INSTALLATION_RECOVERY:
        return SecretConsumer.INSTALLATION_RECOVERY
    if purpose in {
        ConfidentialSecretPurpose.VAULT_INITIALIZE,
        ConfidentialSecretPurpose.VAULT_UNLOCK,
        ConfidentialSecretPurpose.PROVIDER_REAUTHENTICATION,
        ConfidentialSecretPurpose.PROVIDER_CREDENTIAL,
        ConfidentialSecretPurpose.PRIVACY_REAUTHENTICATION,
        ConfidentialSecretPurpose.SECURITY_REAUTHENTICATION,
        ConfidentialSecretPurpose.VAULT_REWRAP,
    }:
        return SecretConsumer.VAULT_ROOT
    raise AssertionError("unmapped confidential purpose")


def _read_handle(handle: SecretHandle, consumer: SecretConsumer) -> bytes:
    return handle.consume(consumer, lambda view: bytes(view))


@pytest.mark.anyio
@pytest.mark.parametrize("purpose", list(ConfidentialSecretPurpose))
async def test_all_nine_purposes_capture_one_exact_handle(
    purpose: ConfidentialSecretPurpose,
) -> None:
    binding = _binding(purpose)
    secret = (
        b"opaque-provider-key"
        if purpose is ConfidentialSecretPurpose.PROVIDER_CREDENTIAL
        else b"correct horse battery staple"
    )
    stream = _Stream(_frame(binding, secret), chunks=(1, 2, 4, 3, 7, 5, 11))
    listener = _Listener([stream])
    memory = LocalSecretMemory()
    service = SecretIngressService(_Clock(), memory, listener=listener)
    try:
        handle = await service.accept_once(binding)
        assert handle.purpose.value == purpose.name.lower()
        assert _read_handle(handle, _consumer(purpose)) == secret
        with pytest.raises(Exception, match="already_consumed"):
            _read_handle(handle, _consumer(purpose))
        assert stream.closed
    finally:
        await service.close()
        memory.close()


@pytest.mark.anyio
async def test_cross_purpose_generation_policy_target_and_challenge_are_rejected() -> None:
    expected = _binding(ConfidentialSecretPurpose.VAULT_UNLOCK)
    crossed = (
        _binding(ConfidentialSecretPurpose.PORTABLE_RECOVERY),
        _binding(ConfidentialSecretPurpose.VAULT_UNLOCK, service_generation=4),
        _binding(ConfidentialSecretPurpose.VAULT_UNLOCK, vault_generation=5),
        _binding(ConfidentialSecretPurpose.VAULT_UNLOCK, policy_generation=7),
        _binding(ConfidentialSecretPurpose.VAULT_UNLOCK, target_digest="sha256:" + "b" * 64),
        _binding(ConfidentialSecretPurpose.VAULT_UNLOCK, challenge="3" * 64),
    )
    for index, wire in enumerate(crossed):
        listener = _Listener([_Stream(_frame(wire, b"correct horse battery staple"))])
        memory = LocalSecretMemory()
        service = SecretIngressService(_Clock(), memory, listener=listener)
        expected_fresh = _binding(
            ConfidentialSecretPurpose.VAULT_UNLOCK,
            challenge=f"{index + 4:x}" * 64,
        )
        # Keep every field equal except the one deliberately crossed in the wire value.
        if index != 5:
            expected_fresh = SecretIngressBinding(
                expected.binding_version,
                expected.ceremony_id,
                expected_fresh.secret_challenge,
                expected.purpose,
                expected.service_instance_id,
                expected.service_generation,
                expected.vault_generation,
                expected.policy_generation,
                expected.target_digest,
                expected.expires_at_monotonic_ms,
            )
            wire = SecretIngressBinding(
                wire.binding_version,
                wire.ceremony_id,
                expected_fresh.secret_challenge,
                wire.purpose,
                wire.service_instance_id,
                wire.service_generation,
                wire.vault_generation,
                wire.policy_generation,
                wire.target_digest,
                wire.expires_at_monotonic_ms,
            )
            listener = _Listener([_Stream(_frame(wire, b"correct horse battery staple"))])
            service = SecretIngressService(_Clock(), memory, listener=listener)
        with pytest.raises(SecretIngressError, match="binding_invalid"):
            await service.accept_once(expected_fresh)
        await service.close()
        memory.close()


@pytest.mark.anyio
async def test_expired_binding_fails_before_accept_or_allocation() -> None:
    binding = _binding(ConfidentialSecretPurpose.VAULT_UNLOCK, expiry_ms=1_000)
    listener = _Listener([])
    memory = LocalSecretMemory()
    service = SecretIngressService(_Clock(1.0), memory, listener=listener)
    with pytest.raises(SecretIngressError, match="binding_expired"):
        await service.accept_once(binding)
    await service.close()
    memory.close()


@pytest.mark.anyio
async def test_partial_extra_zero_and_oversize_frames_fail_closed() -> None:
    secret = b"correct horse battery staple"
    cases: tuple[tuple[bytes, str], ...] = (
        (b"YZS1", "partial_frame"),
        (
            _frame(_binding(ConfidentialSecretPurpose.VAULT_UNLOCK), secret, suffix=b"x"),
            "partial_frame",
        ),
        (b"YZS1\x01\x02\x00\x01\x00\x00\x00\x00x", "secret_too_large"),
        (b"YZS1\x01\x02\x00\x01\x00\x00@\x01x", "secret_too_large"),
    )
    for index, (payload, reason) in enumerate(cases):
        binding = _binding(
            ConfidentialSecretPurpose.VAULT_UNLOCK,
            challenge=f"{index + 4:x}" * 64,
        )
        if index == 1:
            payload = _frame(binding, secret, suffix=b"x")
        listener = _Listener([_Stream(payload)])
        memory = LocalSecretMemory()
        service = SecretIngressService(_Clock(), memory, listener=listener)
        with pytest.raises(SecretIngressError, match=reason):
            await service.accept_once(binding)
        await service.close()
        memory.close()


@pytest.mark.anyio
async def test_challenge_is_consumed_after_failure_and_cannot_replay() -> None:
    binding = _binding(ConfidentialSecretPurpose.VAULT_UNLOCK)
    listener = _Listener(
        [_Stream(b"YZS1"), _Stream(_frame(binding, b"correct horse battery staple"))]
    )
    memory = LocalSecretMemory()
    service = SecretIngressService(_Clock(), memory, listener=listener)
    with pytest.raises(SecretIngressError, match="partial_frame"):
        await service.accept_once(binding)
    with pytest.raises(SecretIngressError, match="binding_invalid"):
        await service.accept_once(binding)
    await service.close()
    memory.close()


@pytest.mark.anyio
async def test_admission_rate_limit_happens_before_secret_capture() -> None:
    binding = _binding(ConfidentialSecretPurpose.VAULT_UNLOCK)
    listener = _Listener([_Stream(_frame(binding, b"correct horse battery staple"))])
    memory = LocalSecretMemory()
    service = SecretIngressService(_Clock(), memory, listener=listener)

    def deny(_: SecretIngressBinding) -> None:
        raise SecretIngressError("rate_limited")

    with pytest.raises(SecretIngressError, match="rate_limited"):
        await service.accept_once(binding, admit=deny)
    await service.close()
    memory.close()


@pytest.mark.anyio
async def test_cancel_pending_closes_connection_and_returns_bounded_cancel() -> None:
    binding = _binding(ConfidentialSecretPurpose.VAULT_UNLOCK)
    stream = _BlockingStream()
    listener = _Listener([stream])
    memory = LocalSecretMemory()
    service = SecretIngressService(_Clock(), memory, listener=listener)
    task = asyncio.create_task(service.accept_once(binding))
    await stream.entered.wait()
    await service.cancel_pending()
    with pytest.raises(SecretIngressError, match="cancelled"):
        await task
    assert stream.closed
    await service.close()
    memory.close()


@pytest.mark.anyio
async def test_close_is_idempotent_and_accept_after_close_is_forbidden() -> None:
    listener = _Listener([])
    memory = LocalSecretMemory()
    service = SecretIngressService(_Clock(), memory, listener=listener)
    await service.close()
    await service.close()
    assert listener.closed
    with pytest.raises(SecretIngressError, match="state_forbidden"):
        await service.accept_once(_binding(ConfidentialSecretPurpose.VAULT_UNLOCK))
    memory.close()
