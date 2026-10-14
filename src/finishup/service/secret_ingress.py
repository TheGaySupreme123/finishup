"""Server-side one-secret confidential ingress.

The endpoint accepts one YZS1 frame for one already-minted live YZH1 binding.
It emits no response bytes and never reflects received material in an error.
"""

from __future__ import annotations

import asyncio
import struct
from collections import deque
from collections.abc import Callable
from typing import Final, Protocol

from finishup.adapters.control.unix_socket import (
    LocalControlTransportError,
    bind_secret_listener,
)
from finishup.ports.clock import ClockPort
from finishup.ports.secret_memory import SecretHandle, SecretMemoryPort, SecretPurpose
from finishup.service.confidential_protocol import (
    CEREMONY_EXPIRY_SECONDS,
    MAX_SECRET_BINDING_BYTES,
    MAX_SECRET_BYTES,
    SECRET_PROTOCOL_MAGIC,
    SECRET_PROTOCOL_VERSION,
    ConfidentialProtocolError,
    ConfidentialSecretPurpose,
    SecretIngressBinding,
    decode_secret_header,
    monotonic_milliseconds,
    validate_passphrase_buffer,
    validate_provider_credential_buffer,
)

__all__ = ["SecretIngressError", "SecretIngressService"]

_SECRET_HEADER = struct.Struct(">4sBBHI")
_REPLAY_WINDOW: Final = 4_096
_ERROR_REASONS: Final = frozenset(
    {
        "tty_required",
        "peer_untrusted",
        "purpose_forbidden",
        "state_forbidden",
        "binding_invalid",
        "binding_expired",
        "secret_too_large",
        "partial_frame",
        "rate_limited",
        "cancelled",
    }
)
_PURPOSE_MAP: Final = {
    ConfidentialSecretPurpose.VAULT_INITIALIZE: SecretPurpose.VAULT_INITIALIZE,
    ConfidentialSecretPurpose.VAULT_UNLOCK: SecretPurpose.VAULT_UNLOCK,
    ConfidentialSecretPurpose.PORTABLE_RECOVERY: SecretPurpose.PORTABLE_RECOVERY,
    ConfidentialSecretPurpose.PROVIDER_REAUTHENTICATION: SecretPurpose.PROVIDER_REAUTHENTICATION,
    ConfidentialSecretPurpose.PROVIDER_CREDENTIAL: SecretPurpose.PROVIDER_CREDENTIAL,
    ConfidentialSecretPurpose.PRIVACY_REAUTHENTICATION: SecretPurpose.PRIVACY_REAUTHENTICATION,
    ConfidentialSecretPurpose.SECURITY_REAUTHENTICATION: SecretPurpose.SECURITY_REAUTHENTICATION,
    ConfidentialSecretPurpose.INSTALLATION_RECOVERY: SecretPurpose.INSTALLATION_RECOVERY,
    ConfidentialSecretPurpose.VAULT_REWRAP: SecretPurpose.VAULT_REWRAP,
}
_PASSPHRASE_PURPOSES: Final = frozenset(
    {
        ConfidentialSecretPurpose.VAULT_INITIALIZE,
        ConfidentialSecretPurpose.VAULT_UNLOCK,
        ConfidentialSecretPurpose.PORTABLE_RECOVERY,
        ConfidentialSecretPurpose.PROVIDER_REAUTHENTICATION,
        ConfidentialSecretPurpose.PRIVACY_REAUTHENTICATION,
        ConfidentialSecretPurpose.SECURITY_REAUTHENTICATION,
        ConfidentialSecretPurpose.INSTALLATION_RECOVERY,
        ConfidentialSecretPurpose.VAULT_REWRAP,
    }
)


class SecretIngressError(Exception):
    """A bounded ingress failure without peer, binding, or secret-derived text."""

    __slots__ = ("reason",)

    def __init__(self, reason: str) -> None:
        if type(reason) is not str or reason not in _ERROR_REASONS:
            raise ValueError("secret_ingress_reason_invalid")
        self.reason = reason
        super().__init__(reason)


class _SecretStream(Protocol):
    async def receive(self, max_bytes: int) -> bytes: ...

    async def aclose(self) -> None: ...


class _SecretListener(Protocol):
    async def accept(self) -> _SecretStream: ...

    async def aclose(self) -> None: ...


type SecretAdmission = Callable[[SecretIngressBinding], None]


class SecretIngressService:
    """Single-owner YZS1 listener and one-live-binding parser."""

    def __init__(
        self,
        clock: ClockPort,
        secret_memory: SecretMemoryPort,
        *,
        listener: _SecretListener | None = None,
    ) -> None:
        self._clock = clock
        self._secret_memory = secret_memory
        self._listener = listener
        self._accept_lock = asyncio.Lock()
        self._state_lock = asyncio.Lock()
        self._active_task: asyncio.Task[SecretHandle] | None = None
        self._active_stream: _SecretStream | None = None
        self._closed = False
        self._started = listener is not None
        self._consumed_order: deque[str] = deque()
        self._consumed: set[str] = set()

    async def serve(self) -> None:
        """Bind the fixed owner-only secret endpoint exactly once."""

        async with self._state_lock:
            if self._closed:
                raise SecretIngressError("state_forbidden")
            if self._started:
                return
            try:
                self._listener = await bind_secret_listener()
            except LocalControlTransportError as exc:
                reason = "peer_untrusted" if exc.reason == "peer_untrusted" else "state_forbidden"
                raise SecretIngressError(reason) from exc
            self._started = True

    async def accept_once(
        self,
        expected_binding: SecretIngressBinding,
        *,
        admit: SecretAdmission | None = None,
    ) -> SecretHandle:
        """Accept and capture one secret for one exact live ceremony binding.

        The caller is the trusted YZH1 authority.  Passing the binding fixes purpose,
        target, and generations before any connection or secret allocation is read.
        """

        if type(expected_binding) is not SecretIngressBinding:
            raise TypeError("secret_binding_invalid")
        if admit is not None and not callable(admit):
            raise TypeError("secret_admission_invalid")
        async with self._accept_lock:
            if self._closed or not self._started or self._listener is None:
                raise SecretIngressError("state_forbidden")
            if expected_binding.secret_challenge in self._consumed:
                raise SecretIngressError("binding_invalid")
            self._consume_challenge(expected_binding.secret_challenge)
            self._validate_current_expiry(expected_binding)
            task = asyncio.create_task(self._accept_and_capture(expected_binding, admit))
            async with self._state_lock:
                if self._closed:
                    task.cancel()
                self._active_task = task
            try:
                async with asyncio.timeout(CEREMONY_EXPIRY_SECONDS):
                    return await task
            except TimeoutError as exc:
                task.cancel()
                await _await_cancelled(task)
                raise SecretIngressError("binding_expired") from exc
            except asyncio.CancelledError as exc:
                task.cancel()
                await _await_cancelled(task)
                raise SecretIngressError("cancelled") from exc
            finally:
                async with self._state_lock:
                    if self._active_task is task:
                        self._active_task = None
                    self._active_stream = None

    async def cancel_pending(self) -> None:
        """Consume and cancel the current pending binding, if any."""

        async with self._state_lock:
            task = self._active_task
            stream = self._active_stream
            if task is not None:
                task.cancel()
        if stream is not None:
            await stream.aclose()
        if task is not None:
            await _await_cancelled(task)

    async def close(self) -> None:
        """Idempotently close the listener and any in-progress connection."""

        async with self._state_lock:
            if self._closed:
                return
            self._closed = True
            task = self._active_task
            stream = self._active_stream
            listener = self._listener
            if task is not None:
                task.cancel()
        if stream is not None:
            await stream.aclose()
        if task is not None:
            await _await_cancelled(task)
        if listener is not None:
            try:
                await listener.aclose()
            except LocalControlTransportError as exc:
                raise SecretIngressError("state_forbidden") from exc

    async def _accept_and_capture(
        self,
        expected_binding: SecretIngressBinding,
        admit: SecretAdmission | None,
    ) -> SecretHandle:
        listener = self._listener
        if listener is None:
            raise SecretIngressError("state_forbidden")
        stream: _SecretStream | None = None
        secret = bytearray()
        try:
            try:
                stream = await listener.accept()
            except LocalControlTransportError as exc:
                reason = "peer_untrusted" if exc.reason == "peer_untrusted" else "partial_frame"
                raise SecretIngressError(reason) from exc
            async with self._state_lock:
                if self._closed:
                    raise SecretIngressError("cancelled")
                self._active_stream = stream

            fixed = await _read_exact(stream, _SECRET_HEADER.size)
            magic, version, raw_purpose, binding_length, secret_length = _SECRET_HEADER.unpack(
                fixed
            )
            if magic != SECRET_PROTOCOL_MAGIC or version != SECRET_PROTOCOL_VERSION:
                raise SecretIngressError("binding_invalid")
            if not 1 <= binding_length <= MAX_SECRET_BINDING_BYTES:
                raise SecretIngressError("binding_invalid")
            if not 1 <= secret_length <= MAX_SECRET_BYTES:
                raise SecretIngressError("secret_too_large")
            try:
                wire_purpose = ConfidentialSecretPurpose(raw_purpose)
            except ValueError as exc:
                raise SecretIngressError("purpose_forbidden") from exc
            if wire_purpose is not expected_binding.purpose:
                raise SecretIngressError("binding_invalid")

            binding_bytes = await _read_exact(stream, binding_length)
            try:
                wire_binding, decoded_secret_length = decode_secret_header(fixed + binding_bytes)
            except ConfidentialProtocolError as exc:
                reason = (
                    "secret_too_large"
                    if exc.reason in {"frame_too_large", "secret_rejected"}
                    else "binding_invalid"
                )
                raise SecretIngressError(reason) from exc
            if decoded_secret_length != secret_length or wire_binding != expected_binding:
                raise SecretIngressError("binding_invalid")
            self._validate_current_expiry(wire_binding)
            if admit is not None:
                admit(wire_binding)

            secret = bytearray(await _read_exact(stream, secret_length))
            extra = await stream.receive(1)
            if extra:
                raise SecretIngressError("partial_frame")
            view = memoryview(secret)
            try:
                if wire_purpose in _PASSPHRASE_PURPOSES:
                    validate_passphrase_buffer(view)
                elif wire_purpose is ConfidentialSecretPurpose.PROVIDER_CREDENTIAL:
                    validate_provider_credential_buffer(view)
                else:
                    raise SecretIngressError("purpose_forbidden")
            except ConfidentialProtocolError as exc:
                raise SecretIngressError("binding_invalid") from exc
            finally:
                view.release()
            purpose = _PURPOSE_MAP.get(wire_purpose)
            if purpose is None:
                raise SecretIngressError("purpose_forbidden")
            return self._secret_memory.capture(purpose, secret)
        except SecretIngressError:
            raise
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            raise SecretIngressError("binding_invalid") from exc
        finally:
            secret[:] = b"\x00" * len(secret)
            if stream is not None:
                await stream.aclose()

    def _validate_current_expiry(self, binding: SecretIngressBinding) -> None:
        try:
            current_ms = monotonic_milliseconds(self._clock.monotonic_seconds())
        except (TypeError, ValueError) as exc:
            raise SecretIngressError("binding_invalid") from exc
        if current_ms >= binding.expires_at_monotonic_ms:
            raise SecretIngressError("binding_expired")

    def _consume_challenge(self, challenge: str) -> None:
        self._consumed.add(challenge)
        self._consumed_order.append(challenge)
        if len(self._consumed_order) > _REPLAY_WINDOW:
            self._consumed.discard(self._consumed_order.popleft())


async def _read_exact(stream: _SecretStream, size: int) -> bytes:
    remaining = size
    chunks: list[bytes] = []
    while remaining:
        chunk = await stream.receive(remaining)
        if not chunk:
            raise SecretIngressError("partial_frame")
        if len(chunk) > remaining:
            raise SecretIngressError("partial_frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


async def _await_cancelled(task: asyncio.Task[SecretHandle]) -> None:
    try:
        await task
    except asyncio.CancelledError, SecretIngressError:
        pass
