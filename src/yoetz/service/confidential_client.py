"""Client-safe sequencing for the local YZH1 and one-shot YZS1 channels."""

from __future__ import annotations

import asyncio
import secrets
import struct
import time
from collections.abc import Awaitable, Callable, Mapping
from typing import Final, Never, Self

from yoetz.adapters.control.unix_socket import (
    AuthenticatedUnixStream,
    LocalControlTransportError,
    connect_human_control,
    connect_secret,
)
from yoetz.service.confidential_protocol import (
    CEREMONY_EXPIRY_SECONDS,
    HUMAN_PROTOCOL_MAGIC,
    HUMAN_PROTOCOL_VERSION,
    MAX_HUMAN_CONTROL_FRAME_BYTES,
    CancelAction,
    ClientActionEnvelope,
    ClientCancelEnvelope,
    ClientOpenEnvelope,
    ConfidentialProtocolError,
    ConfidentialSecretPurpose,
    DecisionAction,
    HumanAction,
    HumanCeremonyKind,
    HumanEnvelope,
    HumanOpenTarget,
    HumanPhase,
    HumanResult,
    RetryAction,
    SecretIngressBinding,
    SecretRequiredPhase,
    SelectAuthorizationSourceAction,
    ServerCloseEnvelope,
    ServerErrorEnvelope,
    ServerOpenedEnvelope,
    ServerPhaseEnvelope,
    ServerResultEnvelope,
    decode_human_frame,
    encode_human_frame,
    encode_secret_header,
    monotonic_milliseconds,
    validate_passphrase_buffer,
    validate_provider_credential_buffer,
)

__all__ = [
    "ConfidentialClientError",
    "ConfidentialResultUnconfirmed",
    "ConfidentialSecretClient",
    "HumanControlClient",
    "HumanControlSession",
]

_HUMAN_HEADER: Final = struct.Struct(">4sBBI")
_TOKEN_CONSTRUCTOR: Final = object()
_SECRET_CLIENT_CONSTRUCTOR: Final = object()
_CLIENT_CONSTRUCTOR: Final = object()
_SECRET_PURPOSES_BY_KIND: Final[
    Mapping[HumanCeremonyKind, frozenset[ConfidentialSecretPurpose]]
] = {
    HumanCeremonyKind.VAULT_INITIALIZE: frozenset({ConfidentialSecretPurpose.VAULT_INITIALIZE}),
    HumanCeremonyKind.VAULT_PASSPHRASE_ROTATE: frozenset(
        {
            ConfidentialSecretPurpose.SECURITY_REAUTHENTICATION,
            ConfidentialSecretPurpose.VAULT_REWRAP,
        }
    ),
    HumanCeremonyKind.VAULT_UNLOCK: frozenset({ConfidentialSecretPurpose.VAULT_UNLOCK}),
    HumanCeremonyKind.KEYRING_RETRY: frozenset[ConfidentialSecretPurpose](),
    HumanCeremonyKind.PORTABLE_RECOVERY: frozenset({ConfidentialSecretPurpose.PORTABLE_RECOVERY}),
    HumanCeremonyKind.INSTALLATION_RECOVERY: frozenset(
        {
            # Provision/rotate/revoke reauthenticate against the ready vault before the
            # recovery secret is collected, so the security reauthentication frame belongs to
            # this ceremony exactly as much as the recovery and rewrap frames do.
            ConfidentialSecretPurpose.SECURITY_REAUTHENTICATION,
            ConfidentialSecretPurpose.INSTALLATION_RECOVERY,
            ConfidentialSecretPurpose.VAULT_REWRAP,
        }
    ),
    HumanCeremonyKind.PROVIDER_CREDENTIAL_SET: frozenset(
        {
            ConfidentialSecretPurpose.PROVIDER_REAUTHENTICATION,
            ConfidentialSecretPurpose.PROVIDER_CREDENTIAL,
        }
    ),
    HumanCeremonyKind.PROVIDER_CREDENTIAL_ROTATE: frozenset(
        {
            ConfidentialSecretPurpose.PROVIDER_REAUTHENTICATION,
            ConfidentialSecretPurpose.PROVIDER_CREDENTIAL,
        }
    ),
    HumanCeremonyKind.PRIVACY_POLICY_DECISION: frozenset(
        {ConfidentialSecretPurpose.PRIVACY_REAUTHENTICATION}
    ),
    HumanCeremonyKind.PRIVACY_DISCLOSURE_DECISION: frozenset(
        {ConfidentialSecretPurpose.PRIVACY_REAUTHENTICATION}
    ),
    HumanCeremonyKind.IDLE_RELOCK_POLICY_CHANGE: frozenset(
        {ConfidentialSecretPurpose.SECURITY_REAUTHENTICATION}
    ),
    HumanCeremonyKind.OWNER_RECEIPT_VIEW: frozenset(
        {ConfidentialSecretPurpose.PRIVACY_REAUTHENTICATION}
    ),
}
_ERROR_REASONS: Final = frozenset(
    {
        "ambiguous",
        "cancelled",
        "ceremony_busy",
        # Structural ceremony refusals. They are deliberately distinct from
        # "service_unavailable": the service answered and declined, and collapsing them told
        # the operator to restart a service that was running fine.
        "ceremony_unsupported",
        "correlation_mismatch",
        "kind_forbidden",
        "peer_untrusted",
        "pending_not_actionable",
        "pending_unavailable",
        "presence_refused",
        "presence_timeout",
        "presence_unavailable",
        "protocol_error",
        "reauthentication_rate_limited",
        "reauthentication_unavailable",
        "response_bytes",
        "secret_rejected",
        "service_unavailable",
        "session_busy",
        "session_closed",
        "stale_generation",
        "state_forbidden",
        "target_invalid",
        "timeout",
    }
)

# Server codes that name an actionable, bounded ceremony outcome and must reach the operator
# intact rather than degrading to a generic transport failure.
_PASS_THROUGH_SERVER_CODES: Final = frozenset(
    {
        # Another ceremony is open (perhaps one an agent started): not a locked vault.
        "ceremony_busy",
        "ceremony_unsupported",
        "kind_forbidden",
        "pending_not_actionable",
        "pending_unavailable",
        # No way to confirm the owner on this installation (no OS presence, no passphrase
        # vault): the caller needs the typed reason to say so, not a transport failure.
        "presence_unavailable",
        # The OS presence prompt was cancelled, failed, or timed out: a refusal the owner can
        # retry, not a transport failure.
        "presence_refused",
        "presence_timeout",
        "reauthentication_rate_limited",
        "reauthentication_unavailable",
        "state_forbidden",
        "target_invalid",
    }
)

type _Connector = Callable[[], Awaitable[AuthenticatedUnixStream]]


class ConfidentialClientError(Exception):
    """One fixed confidential-client failure with no reflected input details."""

    __slots__ = ("reason",)

    reason: str

    def __init__(self, reason: str) -> None:
        if type(reason) is not str or reason not in _ERROR_REASONS:
            raise ValueError("confidential_client_reason_invalid")
        self.reason = reason
        super().__init__(reason)


class ConfidentialResultUnconfirmed(ConfidentialClientError):
    """The correlated terminal result arrived; only the close confirmation did not.

    The server records its durable terminal transition before it writes the result frame, so a
    result that already passed correlation on the authenticated stream is authoritative even when
    the trailing close frame is missing, wrong, or lost with the connection. The validated result
    rides on the exception so a caller that can act on it recovers the stored terminal outcome
    exactly once, read-only; every other caller observes the unchanged bounded reason token.
    """

    __slots__ = ("result",)

    result: HumanResult

    def __init__(self, reason: str, result: HumanResult) -> None:
        super().__init__(reason)
        self.result = result


def _mapped_error(error: BaseException) -> ConfidentialClientError:
    if isinstance(error, ConfidentialClientError):
        return error
    if isinstance(error, LocalControlTransportError):
        if error.reason == "peer_untrusted":
            return ConfidentialClientError("peer_untrusted")
        return ConfidentialClientError("service_unavailable")
    if isinstance(error, ConfidentialProtocolError) and error.reason == "secret_rejected":
        return ConfidentialClientError("secret_rejected")
    return ConfidentialClientError("protocol_error")


async def _read_exact(stream: AuthenticatedUnixStream, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        try:
            chunk = await stream.receive(min(remaining, MAX_HUMAN_CONTROL_FRAME_BYTES))
        except asyncio.CancelledError:
            raise
        except BaseException as exc:
            raise _mapped_error(exc) from None
        if type(chunk) is not bytes or not chunk or len(chunk) > remaining:
            raise ConfidentialClientError("ambiguous")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


async def _read_human_frame(stream: AuthenticatedUnixStream) -> object:
    header = await _read_exact(stream, _HUMAN_HEADER.size)
    magic, version, _frame_type, payload_length = _HUMAN_HEADER.unpack(header)
    if magic != HUMAN_PROTOCOL_MAGIC or version != HUMAN_PROTOCOL_VERSION:
        raise ConfidentialClientError("protocol_error")
    if payload_length > MAX_HUMAN_CONTROL_FRAME_BYTES:
        raise ConfidentialClientError("protocol_error")
    payload = await _read_exact(stream, payload_length)
    try:
        return decode_human_frame(header + payload)
    except ConfidentialProtocolError as exc:
        raise _mapped_error(exc) from None


async def _write_human_frame(stream: AuthenticatedUnixStream, envelope: HumanEnvelope) -> None:
    try:
        encoded = encode_human_frame(envelope)
        await stream.send_all(encoded)
    except asyncio.CancelledError:
        raise
    except BaseException as exc:
        raise _mapped_error(exc) from None


class ConfidentialSessionToken:
    """Opaque, live-session-only authority for one exact secret-required phase."""

    __slots__ = ("_binding", "_consumed", "_live", "_peer_identity")

    def __init__(
        self,
        binding: SecretIngressBinding,
        peer_identity: object,
        *,
        _token: object,
    ) -> None:
        if _token is not _TOKEN_CONSTRUCTOR:
            raise TypeError("confidential_session_token_constructor_private")
        self._binding = binding
        self._peer_identity = peer_identity
        self._consumed = False
        self._live = True

    def _consume(self, binding: SecretIngressBinding, peer_identity: object) -> None:
        if (
            not self._live
            or self._consumed
            or peer_identity is not self._peer_identity
            or binding != self._binding
        ):
            raise ConfidentialClientError("correlation_mismatch")
        self._consumed = True

    def _invalidate(self) -> None:
        self._live = False

    def __repr__(self) -> Never:
        raise TypeError("confidential_session_token_opaque")

    def __copy__(self) -> Never:
        raise TypeError("confidential_session_token_not_copyable")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("confidential_session_token_not_copyable")

    def __reduce__(self) -> Never:
        raise TypeError("confidential_session_token_not_serializable")


class ConfidentialSecretClient:
    """One-shot YZS1 sender available only through a live human session."""

    __slots__ = ("_connect", "_peer_identity")

    def __init__(
        self,
        connect: _Connector,
        peer_identity: object,
        *,
        _token: object,
    ) -> None:
        if _token is not _SECRET_CLIENT_CONSTRUCTOR:
            raise TypeError("confidential_secret_client_constructor_private")
        self._connect = connect
        self._peer_identity = peer_identity

    async def send_once(
        self,
        binding: SecretIngressBinding,
        source: bytearray,
        session_token: ConfidentialSessionToken,
    ) -> None:
        if type(binding) is not SecretIngressBinding or type(source) is not bytearray:
            raise TypeError("confidential_secret_input_invalid")
        if type(session_token) is not ConfidentialSessionToken:
            raise TypeError("confidential_session_token_invalid")

        view = memoryview(source)
        stream: AuthenticatedUnixStream | None = None
        try:
            session_token._consume(  # pyright: ignore[reportPrivateUsage]
                binding, self._peer_identity
            )
            if monotonic_milliseconds(time.monotonic()) >= binding.expires_at_monotonic_ms:
                raise ConfidentialClientError("timeout")
            if binding.purpose is ConfidentialSecretPurpose.PROVIDER_CREDENTIAL:
                validate_provider_credential_buffer(view)
            else:
                validate_passphrase_buffer(view)
            header = encode_secret_header(binding, len(source))
            stream = await self._connect()
            await stream.send_all(header)
            await stream.send_all(view)
            await stream.shutdown_write()
            response = await stream.receive(1)
            if response != b"":
                raise ConfidentialClientError("response_bytes")
        except asyncio.CancelledError:
            raise
        except BaseException as exc:
            raise _mapped_error(exc) from None
        finally:
            for index in range(len(source)):
                source[index] = 0
            view.release()
            if stream is not None:
                await stream.aclose()


class HumanControlSession:
    """One exact correlated YZH1 ceremony state machine."""

    __slots__ = (
        "_awaiting_server",
        "_closed",
        "_connect_secret",
        "_decision_attempted",
        "_next_step",
        "_opened",
        "_stream",
        "_timeout_seconds",
        "_token",
    )

    def __init__(
        self,
        stream: AuthenticatedUnixStream,
        opened: ServerOpenedEnvelope,
        connect_secret_channel: _Connector,
        timeout_seconds: float,
        *,
        _token: object,
    ) -> None:
        if _token is not _CLIENT_CONSTRUCTOR:
            raise TypeError("human_control_session_constructor_private")
        self._stream = stream
        self._opened = opened
        if monotonic_milliseconds(time.monotonic()) >= opened.binding.expires_at_monotonic_ms:
            raise ConfidentialClientError("timeout")
        self._connect_secret = connect_secret_channel
        self._timeout_seconds = timeout_seconds
        self._next_step = opened.step + 1
        self._closed = False
        self._awaiting_server = isinstance(opened.phase, SecretRequiredPhase)
        self._decision_attempted = False
        self._token: ConfidentialSessionToken | None = None
        self._replace_token(opened.phase)

    @property
    def opened(self) -> ServerOpenedEnvelope:
        return self._opened

    def _ensure_open(self) -> None:
        if self._closed:
            raise ConfidentialClientError("session_closed")

    def _replace_token(self, phase: HumanPhase | None) -> None:
        if self._token is not None:
            self._token._invalidate()  # pyright: ignore[reportPrivateUsage]
            self._token = None
        if isinstance(phase, SecretRequiredPhase):
            binding = phase.binding
            ceremony = self._opened.binding
            if (
                binding.ceremony_id != ceremony.ceremony_id
                or binding.service_instance_id != ceremony.service_instance_id
                or binding.service_generation != ceremony.service_generation
                or binding.vault_generation != ceremony.vault_generation
                or binding.policy_generation != ceremony.policy_generation
                or binding.target_digest != ceremony.target_digest
                or binding.purpose not in _SECRET_PURPOSES_BY_KIND[ceremony.ceremony_kind]
            ):
                raise ConfidentialClientError("correlation_mismatch")
            self._token = ConfidentialSessionToken(
                binding,
                self._stream.peer_identity,
                _token=_TOKEN_CONSTRUCTOR,
            )

    def _session_token(self) -> ConfidentialSessionToken:
        self._ensure_open()
        if self._token is None:
            raise ConfidentialClientError("correlation_mismatch")
        return self._token

    def _secret_client(self) -> ConfidentialSecretClient:
        self._ensure_open()
        return ConfidentialSecretClient(
            self._connect_secret,
            self._stream.peer_identity,
            _token=_SECRET_CLIENT_CONSTRUCTOR,
        )

    @property
    def decision_attempted(self) -> bool:
        """Whether this session began sending an approve/deny action.

        The flag is set before the transport write because a failed send may still have delivered
        the complete frame. Callers use it only to distinguish failures that happened before any
        decision attempt from genuinely ambiguous post-attempt outcomes.
        """

        return self._decision_attempted

    async def send_action(self, action: HumanAction) -> None:
        self._ensure_open()
        if self._awaiting_server:
            raise ConfidentialClientError("session_busy")
        if type(action) not in {
            RetryAction,
            SelectAuthorizationSourceAction,
            DecisionAction,
            CancelAction,
        }:
            raise TypeError("human_action_invalid")
        envelope = ClientActionEnvelope(
            ceremony_id=self._opened.ceremony_id,
            step=self._next_step,
            action=action,
        )
        if type(action) is DecisionAction:
            self._decision_attempted = True
        await _write_human_frame(self._stream, envelope)
        self._replace_token(None)
        self._next_step += 1
        self._awaiting_server = True

    async def _read_correlated(self) -> object:
        try:
            async with asyncio.timeout(self._timeout_seconds):
                frame = await _read_human_frame(self._stream)
        except TimeoutError as exc:
            await self.close()
            raise ConfidentialClientError("timeout") from exc
        ceremony_id = getattr(frame, "ceremony_id", None)
        step = getattr(frame, "step", None)
        if ceremony_id != self._opened.ceremony_id or step != self._next_step:
            await self.close()
            raise ConfidentialClientError("correlation_mismatch")
        self._next_step += 1
        return frame

    async def _require_close(self, outcome: str) -> None:
        try:
            frame = await self._read_correlated()
        except ConfidentialClientError as exc:
            if exc.reason == "timeout":
                raise ConfidentialClientError("ambiguous") from exc
            raise
        if type(frame) is not ServerCloseEnvelope or frame.outcome != outcome:
            await self.close()
            raise ConfidentialClientError("ambiguous")
        await self.close()

    async def wait_phase_or_result(self) -> HumanPhase | HumanResult:
        self._ensure_open()
        if not self._awaiting_server:
            raise ConfidentialClientError("session_busy")
        frame = await self._read_correlated()
        if type(frame) is ServerPhaseEnvelope:
            self._replace_token(frame.phase)
            self._awaiting_server = isinstance(frame.phase, SecretRequiredPhase)
            return frame.phase
        if type(frame) is ServerResultEnvelope:
            self._replace_token(None)
            try:
                await self._require_close("completed")
            except ConfidentialClientError as exc:
                # The durable terminal transition committed before this result frame was sent
                # (issue #519): losing only the close confirmation must not discard the
                # validated result in hand.
                raise ConfidentialResultUnconfirmed(exc.reason, frame.result) from exc
            return frame.result
        if type(frame) is ServerErrorEnvelope:
            self._replace_token(None)
            close_outcome = "cancelled" if frame.code == "cancelled" else "failed"
            await self._require_close(close_outcome)
            if frame.code in _PASS_THROUGH_SERVER_CODES:
                raise ConfidentialClientError(frame.code)
            reason = {
                "binding_expired": "timeout",
                "cancelled": "cancelled",
                "secret_rejected": "secret_rejected",
                "stale_generation": "stale_generation",
            }.get(frame.code, "protocol_error")
            raise ConfidentialClientError(reason)
        await self.close()
        raise ConfidentialClientError("protocol_error")

    async def cancel(self) -> None:
        self._ensure_open()
        envelope = ClientCancelEnvelope(
            ceremony_id=self._opened.ceremony_id,
            step=self._next_step,
        )
        await _write_human_frame(self._stream, envelope)
        self._replace_token(None)
        self._next_step += 1
        self._awaiting_server = True
        try:
            await self.wait_phase_or_result()
        except ConfidentialClientError as exc:
            if exc.reason != "cancelled":
                raise

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._replace_token(None)
        await self._stream.aclose()

    async def __aenter__(self) -> Self:
        self._ensure_open()
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.close()


class HumanControlClient:
    """Open at most one live human-control ceremony on the fixed endpoint."""

    __slots__ = ("_connect_human", "_connect_secret", "_session", "_timeout_seconds")

    def __init__(self) -> None:
        self._connect_human: _Connector = connect_human_control
        self._connect_secret: _Connector = connect_secret
        self._timeout_seconds = float(CEREMONY_EXPIRY_SECONDS)
        self._session: HumanControlSession | None = None

    @classmethod
    def _with_connectors(
        cls,
        connect_human_channel: _Connector,
        connect_secret_channel: _Connector,
        *,
        timeout_seconds: float = float(CEREMONY_EXPIRY_SECONDS),
    ) -> HumanControlClient:
        if not 0 < timeout_seconds <= CEREMONY_EXPIRY_SECONDS:
            raise ValueError("confidential_timeout_invalid")
        instance = cls()
        instance._connect_human = connect_human_channel
        instance._connect_secret = connect_secret_channel
        instance._timeout_seconds = timeout_seconds
        return instance

    async def open(self, kind: HumanCeremonyKind, target: HumanOpenTarget) -> HumanControlSession:
        if self._session is not None:
            try:
                self._session._ensure_open()  # pyright: ignore[reportPrivateUsage]
            except ConfidentialClientError:
                self._session = None
            else:
                raise ConfidentialClientError("session_busy")
        stream: AuthenticatedUnixStream | None = None
        nonce = secrets.token_hex(32)
        try:
            stream = await self._connect_human()
            await _write_human_frame(
                stream,
                ClientOpenEnvelope(connection_nonce=nonce, ceremony_kind=kind, target=target),
            )
            async with asyncio.timeout(self._timeout_seconds):
                frame = await _read_human_frame(stream)
            if type(frame) is ServerErrorEnvelope and frame.code in _PASS_THROUGH_SERVER_CODES:
                # A service that refuses the ceremony at open (the production daemon's
                # kind_forbidden for an idle-relock change, say) answered and declined; its
                # bounded reason must reach the operator, not collapse to "service unavailable"
                # (tb4n1 A8).
                raise ConfidentialClientError(frame.code)
            if type(frame) is not ServerOpenedEnvelope:
                raise ConfidentialClientError("protocol_error")
            if (
                frame.binding.connection_nonce != nonce
                or frame.binding.ceremony_kind is not kind
                or frame.binding.ceremony_id != frame.ceremony_id
            ):
                raise ConfidentialClientError("correlation_mismatch")
            session = HumanControlSession(
                stream,
                frame,
                self._connect_secret,
                self._timeout_seconds,
                _token=_CLIENT_CONSTRUCTOR,
            )
            self._session = session
            return session
        except TimeoutError as exc:
            if stream is not None:
                await stream.aclose()
            raise ConfidentialClientError("timeout") from exc
        except asyncio.CancelledError:
            if stream is not None:
                await stream.aclose()
            raise
        except BaseException as exc:
            if stream is not None:
                await stream.aclose()
            raise _mapped_error(exc) from None

    async def close(self) -> None:
        if self._session is None:
            return
        await self._session.close()
        self._session = None
