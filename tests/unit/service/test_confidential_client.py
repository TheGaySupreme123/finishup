"""Client-safe confidential channel sequencing and one-shot secret tests."""

from __future__ import annotations

import asyncio
import copy
import time
from collections.abc import Buffer
from typing import cast

import pytest

from yoetz.adapters.control.unix_socket import AuthenticatedUnixStream
from yoetz.service import confidential_protocol
from yoetz.service.confidential_client import (
    ConfidentialClientError,
    ConfidentialResultUnconfirmed,
    HumanControlClient,
)
from yoetz.service.confidential_protocol import (
    ClientOpenEnvelope,
    ConfidentialSecretPurpose,
    EmptyVaultTarget,
    HumanCeremonyBinding,
    HumanCeremonyKind,
    InstallationRecoveryPreview,
    InstallationRecoveryTarget,
    SecretIngressBinding,
    SecretRequiredPhase,
    ServerCloseEnvelope,
    ServerErrorEnvelope,
    ServerOpenedEnvelope,
    ServerResultEnvelope,
    VaultInitializePreview,
    VaultStateResult,
    decode_human_frame,
    decode_secret_header,
    encode_human_frame,
    monotonic_milliseconds,
)

_SERVICE_ID = "svc_00000000-0000-4000-8000-000000000001"
_CEREMONY_ID = "1" * 64
_DIGEST = "sha256:" + "0" * 64


def _expiry() -> int:
    return monotonic_milliseconds(time.monotonic()) + 60_000


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class _HumanStream:
    def __init__(self) -> None:
        self.peer_identity = object()
        self.sent: list[bytes] = []
        self._incoming = bytearray()
        self._ready = asyncio.Condition()
        self.closed = False
        self.binding: SecretIngressBinding | None = None

    async def receive(self, max_bytes: int) -> bytes:
        async with self._ready:
            await self._ready.wait_for(lambda: bool(self._incoming) or self.closed)
            if not self._incoming:
                return b""
            size = min(max_bytes, len(self._incoming))
            result = bytes(self._incoming[:size])
            del self._incoming[:size]
            return result

    async def send_all(self, data: Buffer) -> None:
        encoded = bytes(data)
        self.sent.append(encoded)
        frame = decode_human_frame(encoded)
        if type(frame) is ClientOpenEnvelope:
            binding = SecretIngressBinding(
                binding_version=1,
                ceremony_id=_CEREMONY_ID,
                secret_challenge="2" * 64,
                purpose=ConfidentialSecretPurpose.VAULT_INITIALIZE,
                service_instance_id=_SERVICE_ID,
                service_generation=1,
                vault_generation=0,
                policy_generation=None,
                target_digest=_DIGEST,
                expires_at_monotonic_ms=_expiry(),
            )
            self.binding = binding
            opened = ServerOpenedEnvelope(
                ceremony_id=_CEREMONY_ID,
                step=1,
                binding=HumanCeremonyBinding(
                    binding_version=1,
                    ceremony_id=_CEREMONY_ID,
                    connection_nonce=frame.connection_nonce,
                    ceremony_kind=frame.ceremony_kind,
                    service_instance_id=_SERVICE_ID,
                    service_generation=1,
                    vault_generation=0,
                    policy_generation=None,
                    target_digest=_DIGEST,
                    expires_at_monotonic_ms=_expiry(),
                ),
                preview=VaultInitializePreview(),
                phase=SecretRequiredPhase(binding=binding),
            )
            await self.feed(encode_human_frame(opened))

    async def feed(self, data: bytes) -> None:
        async with self._ready:
            self._incoming.extend(data)
            self._ready.notify_all()

    async def shutdown_write(self) -> None:
        return None

    async def aclose(self) -> None:
        async with self._ready:
            self.closed = True
            self._ready.notify_all()


class _SecretStream:
    def __init__(self, response: bytes = b"") -> None:
        self.peer_identity = object()
        self.sent: list[tuple[type[object], bytes]] = []
        self.response = response
        self.closed = False

    async def receive(self, max_bytes: int) -> bytes:
        response, self.response = self.response[:max_bytes], self.response[max_bytes:]
        return response

    async def send_all(self, data: Buffer) -> None:
        self.sent.append((type(data), bytes(data)))

    async def shutdown_write(self) -> None:
        return None

    async def aclose(self) -> None:
        self.closed = True


async def _open(
    secret_stream: _SecretStream,
) -> tuple[HumanControlClient, _HumanStream, object]:
    human_stream = _HumanStream()

    async def connect_human() -> AuthenticatedUnixStream:
        return cast(AuthenticatedUnixStream, human_stream)

    async def connect_secret() -> AuthenticatedUnixStream:
        return cast(AuthenticatedUnixStream, secret_stream)

    factory = getattr(HumanControlClient, "_with_connectors")
    client = cast(HumanControlClient, factory(connect_human, connect_secret, timeout_seconds=1.0))
    session = await client.open(
        HumanCeremonyKind.VAULT_INITIALIZE,
        EmptyVaultTarget(expected_mode="uninitialized"),
    )
    return client, human_stream, session


@pytest.mark.anyio
async def test_live_session_token_allows_one_secret_send_and_overwrites_source() -> None:
    secret_stream = _SecretStream()
    client, human_stream, raw_session = await _open(secret_stream)
    session = raw_session
    binding = human_stream.binding
    assert binding is not None
    secret_client = getattr(session, "_secret_client")()
    token = getattr(session, "_session_token")()
    source = bytearray(b"sixteen-byte-key")
    await secret_client.send_once(binding, source, token)
    assert source == bytearray(len(source))
    assert secret_stream.sent[0][0] is bytes
    assert secret_stream.sent[1][0] is memoryview
    parsed_binding, length = decode_secret_header(secret_stream.sent[0][1])
    assert parsed_binding == binding
    assert length == len(b"sixteen-byte-key")
    with pytest.raises(TypeError, match="opaque"):
        repr(token)
    with pytest.raises(TypeError, match="not_copyable"):
        copy.copy(token)

    await human_stream.feed(
        encode_human_frame(
            ServerResultEnvelope(
                ceremony_id=_CEREMONY_ID,
                step=2,
                result=VaultStateResult(state="ready", reason="succeeded"),
            )
        )
        + encode_human_frame(
            ServerCloseEnvelope(ceremony_id=_CEREMONY_ID, step=3, outcome="completed")
        )
    )
    result = await getattr(session, "wait_phase_or_result")()
    assert result == VaultStateResult(state="ready", reason="succeeded")
    await client.close()


@pytest.mark.anyio
async def test_duplicate_or_crossed_secret_attempt_fails_and_still_overwrites() -> None:
    secret_stream = _SecretStream()
    client, human_stream, session = await _open(secret_stream)
    binding = human_stream.binding
    assert binding is not None
    secret_client = getattr(session, "_secret_client")()
    token = getattr(session, "_session_token")()
    first = bytearray(b"sixteen-byte-key")
    await secret_client.send_once(binding, first, token)
    duplicate = bytearray(b"sixteen-byte-key")
    with pytest.raises(ConfidentialClientError, match="correlation_mismatch"):
        await secret_client.send_once(binding, duplicate, token)
    assert duplicate == bytearray(len(duplicate))
    assert len(secret_stream.sent) == 2
    await client.close()


@pytest.mark.anyio
async def test_yzs_response_bytes_fail_closed_and_source_is_overwritten() -> None:
    secret_stream = _SecretStream(b"x")
    client, human_stream, session = await _open(secret_stream)
    binding = human_stream.binding
    assert binding is not None
    source = bytearray(b"sixteen-byte-key")
    with pytest.raises(ConfidentialClientError, match="response_bytes"):
        await getattr(session, "_secret_client")().send_once(
            binding,
            source,
            getattr(session, "_session_token")(),
        )
    assert source == bytearray(len(source))
    assert secret_stream.closed
    await client.close()


def test_confidential_clients_have_no_raw_endpoint_or_secret_constructor() -> None:
    with pytest.raises(TypeError, match="constructor_private"):
        getattr(
            __import__("yoetz.service.confidential_client", fromlist=["x"]),
            "ConfidentialSecretClient",
        )(lambda: None, object(), _token=None)
    assert not hasattr(HumanControlClient, "connect_secret")
    assert "HumanEnvelope" in confidential_protocol.__all__


_READY_RESULT = VaultStateResult(state="ready", reason="succeeded")


def _result_frame() -> bytes:
    return encode_human_frame(
        ServerResultEnvelope(ceremony_id=_CEREMONY_ID, step=2, result=_READY_RESULT)
    )


@pytest.mark.anyio
async def test_missing_close_after_result_carries_the_validated_result() -> None:
    """#519: a lost close confirmation must not discard a correlated terminal result."""

    client, human_stream, session = await _open(_SecretStream())
    await human_stream.feed(_result_frame())
    await human_stream.aclose()
    with pytest.raises(ConfidentialResultUnconfirmed) as caught:
        await getattr(session, "wait_phase_or_result")()
    assert caught.value.result == _READY_RESULT
    assert caught.value.reason == "ambiguous"
    # Callers that only understand the bounded error taxonomy observe it unchanged.
    assert isinstance(caught.value, ConfidentialClientError)
    await client.close()


@pytest.mark.anyio
async def test_wrong_close_outcome_after_result_carries_the_validated_result() -> None:
    client, human_stream, session = await _open(_SecretStream())
    await human_stream.feed(
        _result_frame()
        + encode_human_frame(
            ServerCloseEnvelope(ceremony_id=_CEREMONY_ID, step=3, outcome="failed")
        )
    )
    with pytest.raises(ConfidentialResultUnconfirmed) as caught:
        await getattr(session, "wait_phase_or_result")()
    assert caught.value.result == _READY_RESULT
    assert caught.value.reason == "ambiguous"
    await client.close()


@pytest.mark.anyio
async def test_miscorrelated_close_after_result_keeps_its_exact_reason() -> None:
    client, human_stream, session = await _open(_SecretStream())
    await human_stream.feed(
        _result_frame()
        + encode_human_frame(
            ServerCloseEnvelope(ceremony_id=_CEREMONY_ID, step=9, outcome="completed")
        )
    )
    with pytest.raises(ConfidentialResultUnconfirmed) as caught:
        await getattr(session, "wait_phase_or_result")()
    assert caught.value.result == _READY_RESULT
    assert caught.value.reason == "correlation_mismatch"
    await client.close()


class _RecoveryStream:
    """Serves the exact frame the daemon opens a provision ceremony with: a reauth secret phase.

    Provision, rotation, and revocation all reauthenticate against the ready vault before any
    recovery secret is collected, so `SECURITY_REAUTHENTICATION` is the first purpose the client
    ever sees for this ceremony. Omitting it from the per-kind allowlist made the trusted client
    hang up with `correlation_mismatch` on the daemon's very first phase.
    """

    def __init__(self, purpose: ConfidentialSecretPurpose) -> None:
        self.peer_identity = object()
        self._purpose = purpose
        self._incoming = bytearray()
        self._ready = asyncio.Condition()
        self.closed = False

    async def receive(self, max_bytes: int) -> bytes:
        async with self._ready:
            await self._ready.wait_for(lambda: bool(self._incoming) or self.closed)
            if not self._incoming:
                return b""
            size = min(max_bytes, len(self._incoming))
            result = bytes(self._incoming[:size])
            del self._incoming[:size]
            return result

    async def send_all(self, data: Buffer) -> None:
        frame = decode_human_frame(bytes(data))
        if type(frame) is not ClientOpenEnvelope:
            return
        target = cast(InstallationRecoveryTarget, frame.target)
        opened = ServerOpenedEnvelope(
            ceremony_id=_CEREMONY_ID,
            step=1,
            binding=HumanCeremonyBinding(
                binding_version=1,
                ceremony_id=_CEREMONY_ID,
                connection_nonce=frame.connection_nonce,
                ceremony_kind=frame.ceremony_kind,
                service_instance_id=_SERVICE_ID,
                service_generation=1,
                vault_generation=2,
                policy_generation=None,
                target_digest=target.confirmed_plan_digest,
                expires_at_monotonic_ms=_expiry(),
            ),
            preview=InstallationRecoveryPreview(
                operation=target.operation,
                request_id=target.request_id,
                confirmed_plan_digest=target.confirmed_plan_digest,
                recovery_generation=target.recovery_generation,
                set_mode=target.set_mode,
                secret_kind=target.secret_kind,
                target_envelope=target.target_envelope,
                item_count=1,
                total_bytes=0,
                native_prompt_available=False,
            ),
            phase=SecretRequiredPhase(
                binding=SecretIngressBinding(
                    binding_version=1,
                    ceremony_id=_CEREMONY_ID,
                    secret_challenge="3" * 64,
                    purpose=self._purpose,
                    service_instance_id=_SERVICE_ID,
                    service_generation=1,
                    vault_generation=2,
                    policy_generation=None,
                    target_digest=target.confirmed_plan_digest,
                    expires_at_monotonic_ms=_expiry(),
                )
            ),
        )
        async with self._ready:
            self._incoming.extend(encode_human_frame(opened))
            self._ready.notify_all()

    async def shutdown_write(self) -> None:
        return None

    async def aclose(self) -> None:
        async with self._ready:
            self.closed = True
            self._ready.notify_all()


def _recovery_target() -> InstallationRecoveryTarget:
    unbound = InstallationRecoveryTarget(
        operation="provision",
        request_id="req_00000000-0000-4000-8000-000000000009",
        confirmed_plan_digest=_DIGEST,
        recovery_generation=1,
        set_mode="compact",
        secret_kind="generated_code",
        target_envelope="preserve",
    )
    return InstallationRecoveryTarget(
        unbound.operation,
        unbound.request_id,
        unbound.plan_digest(),
        unbound.recovery_generation,
        unbound.set_mode,
        unbound.secret_kind,
        unbound.target_envelope,
    )


async def _open_recovery(purpose: ConfidentialSecretPurpose) -> None:
    stream = _RecoveryStream(purpose)

    async def connect_human() -> AuthenticatedUnixStream:
        return cast(AuthenticatedUnixStream, stream)

    async def connect_secret() -> AuthenticatedUnixStream:
        raise AssertionError("no secret connection is opened while observing the first phase")

    factory = getattr(HumanControlClient, "_with_connectors")
    client = cast(HumanControlClient, factory(connect_human, connect_secret, timeout_seconds=1.0))
    try:
        await client.open(HumanCeremonyKind.INSTALLATION_RECOVERY, _recovery_target())
    finally:
        await client.close()


@pytest.mark.anyio
async def test_recovery_client_accepts_the_security_reauthentication_frame() -> None:
    await _open_recovery(ConfidentialSecretPurpose.SECURITY_REAUTHENTICATION)


@pytest.mark.anyio
async def test_recovery_client_still_refuses_a_purpose_this_ceremony_never_uses() -> None:
    with pytest.raises(ConfidentialClientError, match="correlation_mismatch"):
        await _open_recovery(ConfidentialSecretPurpose.PROVIDER_CREDENTIAL)


class _RefusingHumanStream(_HumanStream):
    """A service that declines the ceremony at open with a bounded refusal."""

    def __init__(self, code: str) -> None:
        super().__init__()
        self.code = code

    async def send_all(self, data: Buffer) -> None:
        self.sent.append(bytes(data))
        await self.feed(encode_human_frame(ServerErrorEnvelope(code=self.code, retryable=False)))


@pytest.mark.anyio
@pytest.mark.parametrize("code", ["kind_forbidden", "state_forbidden", "ceremony_unsupported"])
async def test_a_refusal_at_open_reaches_the_caller_as_its_bounded_reason(code: str) -> None:
    """tb4n1 A8: `yoetz service idle-relock disabled` under the production daemon printed
    "service_unavailable: the confidential ceremony could not be completed" although the
    daemon answered kind_forbidden."""

    human_stream = _RefusingHumanStream(code)

    async def connect_human() -> AuthenticatedUnixStream:
        return cast(AuthenticatedUnixStream, human_stream)

    async def connect_secret() -> AuthenticatedUnixStream:
        return cast(AuthenticatedUnixStream, _SecretStream())

    factory = getattr(HumanControlClient, "_with_connectors")
    client = cast(HumanControlClient, factory(connect_human, connect_secret, timeout_seconds=1.0))
    with pytest.raises(ConfidentialClientError) as raised:
        await client.open(
            HumanCeremonyKind.VAULT_INITIALIZE,
            EmptyVaultTarget(expected_mode="uninitialized"),
        )
    assert raised.value.reason == code
    assert human_stream.closed
