"""A ``ServiceClient`` that reaches a remote FinishUP server's network API (ADR-051).

For a remote target (``https``, ``local_port`` or ``ssh``) every client surface — hooks, the MCP
bridge, the CLI and the terminal interface — gets a ``RestServiceClient`` from
``service.client.connect_service`` in place of the Unix-socket client. It has the same public
methods and raises the same ``ControlError``s, so nothing above it changes. Each call is one
stateless request to ``POST /v1/{method}`` whose body is the method's existing request body and
whose answer is the existing control-result body; a call still running after the long-poll window
is followed at ``/v1/operations/{id}``.

* ``https`` and ``local_port`` targets speak HTTPS to the server, trusting the target's
  ``--ca-file``, its ``--tls-pin`` (checked during the TLS handshake, before any key is sent), or
  the public certificate store. The API key is read from the target's credential store by this
  process; same-user software can read that store too (ADR-051 decision 7).
* ``ssh`` targets speak HTTP over ``<target root>/run/api.sock``, which this client's OpenSSH
  master forwards to the server's owner-only API socket (``client.rest_runtime``). SSH is
  owner-equivalent: no key is sent.

The server is never named in an error, a log or an MCP text: failures are the control protocol's
closed reasons, with a remote phase (``remote_unreachable``, ``remote_auth_failed``,
``remote_identity_changed``, ``remote_service_not_running``, ``remote_incompatible``). A remote
phase means the call was never dispatched (nothing was sent, or the server refused it before
dispatch), so every surface may say that nothing was recorded. A call that may have been admitted
— its answer lost after the request was sent, a long-poll that failed, an operation whose answer
the server no longer keeps — is ``request_timeout`` instead: its outcome is unknown, and the
ADR-030 timeout continuation says how to recover it under the same identity. Proxy variables are
ignored: the server hop goes only where the owner's target record says.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import os
import secrets
import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, cast

import httpx

from finishup.client.targets import ServerTarget, TargetKind
from finishup.domain.values import JsonObject, freeze_json
from finishup.ports.control import (
    ControlCallRequest,
    ControlCancelRequest,
    ControlClientKind,
    ControlError,
    ControlMethod,
    ControlResult,
    WorkspaceBinding,
    WorkspaceClaim,
)
from finishup.protocol.canonical import JsonValue, canonical_encode, strict_json_parse
from finishup.protocol.schemas import schema_manifest_digest
from finishup.service.client import ServiceClient
from finishup.service.control_protocol import (
    CONTROL_PROTOCOL_VERSION,
    ControlProtocolError,
    ControlSession,
    encode_control_frame,
    parse_control_result,
)
from finishup.service.network_protocol import (
    API_SOCKET_NAME,
    HEADER_CLAIM,
    HEADER_CLIENT_KIND,
    HEADER_DEADLINE_MS,
    HEADER_HOST_PROFILE,
    HEADER_OPERATION_ID,
    HEADER_OUTCOME,
    HEADER_ROUTE_PROFILE,
    HEADER_SERVICE_GENERATION,
    HEADER_SERVICE_INSTANCE,
    MAX_WAIT_MS,
    ServerInfo,
    encode_claim_header,
    parse_rest_error,
    parse_server_info,
)

if TYPE_CHECKING:
    from finishup.service.confidential_protocol import OwnerReceiptViewTarget

__all__ = [
    "RestEndpoint",
    "RestServiceClient",
    "connect_rest_service",
    "open_rest_http",
    "read_server_info",
    "rest_endpoint_for",
]

# Room past the long-poll window for the server to answer.
_READ_SLACK_SECONDS: Final = 10.0
_CONNECT_SECONDS: Final = 5.0
_MAX_RESPONSE_BYTES: Final = 6_291_456 + 65_536
_SSH_BASE_URL: Final = "http://finishup.invalid"
_CANCEL_SECONDS: Final = 2.0
# A call refused because this key has too many running operations was never dispatched; it is
# sent again after a growing wait, for at most this long (or the call's own deadline).
_BUSY_FIRST_SECONDS: Final = 0.25
_BUSY_MAX_SECONDS: Final = 2.0
_BUSY_TOTAL_SECONDS: Final = 30.0
_PRIVATE: Final = object()
_WORKFLOW: Final = frozenset(
    {
        ControlMethod.START,
        ControlMethod.PUBLISH_WORK,
        ControlMethod.CHECK,
        ControlMethod.RESPOND,
        ControlMethod.STATUS,
        ControlMethod.RECEIPT,
    }
)


def _remote(phase: str, *, retryable: bool = True) -> ControlError:
    return ControlError("service_unavailable", retryable=retryable, phase=phase)


class _RestPeer:
    """The session's peer marker: the server the target record names, reached over HTTP."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "RestPeer(<redacted>)"


# --- TLS pinning ----------------------------------------------------------------------------


class _PinMismatch:
    """Set when a TLS handshake presented a certificate other than the pinned one."""

    __slots__ = ("seen",)

    def __init__(self) -> None:
        self.seen = False


def _pinned_backend(pin: bytes, mismatch: _PinMismatch) -> Any:
    """An httpcore network backend that checks the leaf certificate digest after the handshake.

    The check runs inside ``start_tls``, before httpcore writes a single request byte, so a key
    is never sent to a server whose certificate does not match the owner's pin.
    """

    import httpcore

    class _PinnedStream(httpcore.AsyncNetworkStream):
        def __init__(self, inner: httpcore.AsyncNetworkStream) -> None:
            self._inner = inner

        async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
            return await self._inner.read(max_bytes, timeout)

        async def write(self, buffer: bytes, timeout: float | None = None) -> None:
            await self._inner.write(buffer, timeout)

        async def aclose(self) -> None:
            await self._inner.aclose()

        async def start_tls(
            self,
            ssl_context: ssl.SSLContext,
            server_hostname: str | None = None,
            timeout: float | None = None,
        ) -> httpcore.AsyncNetworkStream:
            stream = await self._inner.start_tls(ssl_context, server_hostname, timeout)
            ssl_object = stream.get_extra_info("ssl_object")
            leaf = None if ssl_object is None else ssl_object.getpeercert(binary_form=True)
            if leaf is None or not hmac.compare_digest(hashlib.sha256(leaf).digest(), pin):
                mismatch.seen = True
                await stream.aclose()
                raise httpcore.ConnectError("tls_pin_mismatch")
            return stream

        def get_extra_info(self, info: str) -> Any:
            return self._inner.get_extra_info(info)

    class _PinnedBackend(httpcore.AsyncNetworkBackend):
        def __init__(self) -> None:
            self._inner = cast(httpcore.AsyncNetworkBackend, httpcore.AnyIOBackend())

        async def connect_tcp(
            self,
            host: str,
            port: int,
            timeout: float | None = None,
            local_address: str | None = None,
            socket_options: Any = None,
        ) -> httpcore.AsyncNetworkStream:
            return _PinnedStream(
                await self._inner.connect_tcp(host, port, timeout, local_address, socket_options)
            )

        async def connect_unix_socket(
            self, path: str, timeout: float | None = None, socket_options: Any = None
        ) -> httpcore.AsyncNetworkStream:
            raise httpcore.ConnectError("unix_socket_not_pinned")

        async def sleep(self, seconds: float) -> None:
            await self._inner.sleep(seconds)

    return _PinnedBackend()


class _PinnedTransport(httpx.AsyncHTTPTransport):
    """``httpx``'s transport over a connection pool whose TLS handshakes check a pin.

    The certificate chain and host name are not checked — the pin is the trust decision the
    owner made with ``--tls-pin`` — but the leaf certificate must match it byte for byte.
    """

    def __init__(self, pin: str, mismatch: _PinMismatch) -> None:
        import httpcore

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        super().__init__(verify=context, http1=True, http2=False, retries=0)
        # httpx 0.28 (pinned) keeps its pool in ``_pool``; a pool with the pinning backend
        # replaces it, so the check runs inside every handshake.
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=context,
            http1=True,
            http2=False,
            max_connections=10,
            keepalive_expiry=30.0,
            network_backend=_pinned_backend(bytes.fromhex(pin.removeprefix("sha256:")), mismatch),
        )


# --- endpoints ------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RestEndpoint:
    """Where one target's API is and how to reach it; the credential stays out of every repr."""

    kind: TargetKind
    base_url: str
    transport: httpx.AsyncBaseTransport
    credential: str | None
    pin_mismatch: _PinMismatch | None = None

    def __repr__(self) -> str:
        return f"RestEndpoint(kind={self.kind!r}, <redacted>)"


def rest_endpoint_for(record: ServerTarget, root: Path) -> RestEndpoint:
    """The endpoint of a remote target root: its URL, TLS trust, and credential."""

    if not record.is_remote:
        raise ControlError("frame_invalid")
    if record.kind == "ssh":
        return RestEndpoint(
            "ssh",
            _SSH_BASE_URL,
            httpx.AsyncHTTPTransport(uds=os.fspath(root / "run" / API_SOCKET_NAME), retries=0),
            None,
        )
    from finishup.client.credentials import CredentialError, KeyringOrFileCredential

    try:
        credential = KeyringOrFileCredential(
            record.target_id, root, recorded=record.credential
        ).read()
    except CredentialError:
        raise _remote("remote_auth_failed", retryable=False) from None
    mismatch: _PinMismatch | None = None
    transport: httpx.AsyncBaseTransport
    if record.tls_pin is not None:
        mismatch = _PinMismatch()
        transport = _PinnedTransport(record.tls_pin, mismatch)
    elif record.ca_file is not None:
        try:
            context = ssl.create_default_context(cafile=record.ca_file)
        except (OSError, ssl.SSLError):
            raise _remote("remote_identity_changed", retryable=False) from None
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        transport = httpx.AsyncHTTPTransport(verify=context, retries=0)
    else:
        transport = httpx.AsyncHTTPTransport(verify=True, retries=0)
    return RestEndpoint(
        record.kind, cast(str, record.base_url), transport, credential, pin_mismatch=mismatch
    )


def _certificate_failure(error: BaseException) -> bool:
    seen: set[int] = set()
    current: BaseException | None = error
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, ssl.SSLCertVerificationError):
            return True
        current = current.__cause__ or current.__context__
    return False


def _outcome_unknown() -> ControlError:
    """A call that may have been admitted and whose answer this client did not get."""

    return ControlError("request_timeout", retryable=True)


def _never_sent(error: BaseException) -> bool:
    """Whether an HTTP failure happened before any request byte could reach the server."""

    return isinstance(error, (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout))


def _transport_failure(error: BaseException, endpoint: RestEndpoint) -> ControlError:
    if endpoint.pin_mismatch is not None and endpoint.pin_mismatch.seen:
        return _remote("remote_identity_changed", retryable=False)
    if _certificate_failure(error):
        return _remote("remote_identity_changed", retryable=False)
    return _remote("remote_unreachable")


def _refusal_error(response: httpx.Response) -> ControlError:
    """The control reason for a transport refusal (never echoing anything the server sent).

    Every refusal here came before dispatch, except ``operation_unknown`` for a call's own id:
    that id was dispatched earlier and its answer is gone, so its outcome is unknown.
    """

    reason = parse_rest_error(response.content)
    if reason == "operation_unknown":
        return _outcome_unknown()
    if reason == "server_keys_unusable":
        # The server cannot check any key until its owner repairs its key file there.
        return _remote("remote_auth_failed", retryable=False)
    if reason == "internal_failure":
        return ControlError("internal_error")
    if reason in {"operation_limit", "agent_limit"}:
        # Refused before dispatch while this key has too many running operations; the caller
        # already waited its share, so the outcome is the timeout's (nothing was sent to run).
        return _outcome_unknown()
    if response.status_code == 401:
        return _remote("remote_auth_failed", retryable=False)
    if reason in {"frame_too_large"}:
        return ControlError("frame_too_large")
    if reason in {
        "frame_invalid",
        "header_invalid",
        "origin_forbidden",
        "workspace_claim_required",
    }:
        return ControlError("frame_invalid")
    if reason == "route_unknown":
        # A server without this route speaks another release of the API.
        return _remote("remote_incompatible", retryable=False)
    if reason in {"service_unavailable", "workspace_agent_unavailable"}:
        return _remote("remote_service_not_running")
    return _remote("remote_unreachable")


def _client(endpoint: RestEndpoint, *, transport: httpx.AsyncBaseTransport | None) -> Any:
    return httpx.AsyncClient(
        base_url=endpoint.base_url,
        transport=transport or endpoint.transport,
        trust_env=False,
        follow_redirects=False,
        timeout=httpx.Timeout(
            connect=_CONNECT_SECONDS,
            read=MAX_WAIT_MS / 1_000 + _READ_SLACK_SECONDS,
            write=30.0,
            pool=_CONNECT_SECONDS,
        ),
    )


def _base_headers(endpoint: RestEndpoint, claim: WorkspaceClaim | None) -> dict[str, str]:
    headers = {"accept": "application/json"}
    if endpoint.credential is not None:
        headers["authorization"] = f"Bearer {endpoint.credential}"
    if claim is not None:
        headers[HEADER_CLAIM] = encode_claim_header(claim)
    return headers


def _allowed_methods(client_kind: ControlClientKind) -> tuple[ControlMethod, ...]:
    methods = _WORKFLOW if client_kind is ControlClientKind.MCP_BRIDGE else frozenset(ControlMethod)
    return tuple(sorted(methods, key=lambda value: value.value.encode("ascii")))


def _request_body(request: ControlCallRequest) -> bytes:
    """The call's body exactly as the control socket would frame it."""

    try:
        frame = encode_control_frame(request)
    except ControlProtocolError as error:
        raise ControlError(
            "frame_too_large" if error.reason == "frame_too_large" else "frame_invalid"
        ) from None
    parsed = cast(dict[str, JsonValue], strict_json_parse(frame[4:]))
    return canonical_encode(parsed["body"])


def _refuse_workspace_path(body: bytes) -> None:
    """Never send a path to a server on another machine (ADR-051).

    The MCP bridge, the CLI and the hooks already name a claim-bound task's workspace by the
    connection's handle (``client.workspace_ref``); a ``start`` that still names an absolute path
    here is refused before anything is sent, with the same fixed refusal, which names no path.
    """

    from finishup.client.workspace_ref import WorkspaceRefNotPortable

    parsed = strict_json_parse(body)
    if type(parsed) is not dict:
        return
    workspace_ref = cast(dict[str, JsonValue], parsed).get("workspace_ref")
    if type(workspace_ref) is str and workspace_ref.startswith("/"):
        raise WorkspaceRefNotPortable()


class RestServiceClient(ServiceClient):
    """One server target's network API behind the ``ServiceClient`` interface.

    Constructed only by ``connect_rest_service``. It shares every typed method of
    ``ServiceClient`` (they all reach ``call``); it never opens the Unix socket, so the
    socket-specific state of its base class is never initialized or used.
    """

    __slots__ = ("_claim", "_endpoint", "_http")

    def __init__(
        self,
        http: Any,
        endpoint: RestEndpoint,
        info: ServerInfo,
        client_kind: ControlClientKind,
        *,
        claim: WorkspaceClaim | None,
        _token: object,
    ) -> None:
        # Deliberately not ``super().__init__``: that starts a receiver on a Unix stream, and
        # this client has none. Every base method that touches the stream is overridden here.
        if _token is not _PRIVATE:
            raise TypeError("rest_service_client_constructor_private")
        if type(client_kind) is not ControlClientKind:
            raise TypeError("control_client_kind_invalid")
        binding: WorkspaceBinding = "client_claim" if claim is not None else "none"
        self._http = http
        self._endpoint = endpoint
        self._claim = claim
        self._client_kind = client_kind
        # The base class's socket-side members, never used here: this client serves no workspace
        # calls (the target's workspace agent does) and owns no stream or receiver.
        self._agent = None
        self._agent_busy = 0
        self._agent_calls = {}
        self._agent_executor = None
        self._transport = "ssh" if endpoint.kind == "ssh" else "https"
        self._pid = os.getpid()
        self._closed = False
        self._last_project_request = None
        self._pending = {}
        self._retired_rpc_ids = set()
        self._write_lock = asyncio.Lock()
        self._session = ControlSession(
            protocol_version="1.0",
            client_kind=client_kind,
            service_instance_id=info.service_instance_id,
            service_generation=info.service_generation,
            allowed_methods=_allowed_methods(client_kind),
            peer_identity=_RestPeer(),
            connection_nonce=secrets.token_hex(32),
            service_status=info.status,
            workspace_binding=binding,
            workspace_handle=info.workspace_handle,
        )

    @property
    def transport_kind(self) -> TargetKind:
        """The target kind this client reaches (a closed token, for "served by" lines)."""

        return self._endpoint.kind

    def owner_receipt_view_target(self, request: object) -> OwnerReceiptViewTarget:
        # The owner view is bound to a ceremony on the server host's own connection.
        del request
        raise ControlError("method_forbidden")

    async def _fail_connection(self, error: ControlError, *, from_receiver: bool = False) -> None:
        del error, from_receiver
        if not self._closed:
            self._closed = True
            self._session.close()
            with contextlib.suppress(Exception):
                await self._http.aclose()

    def _headers(self, request: ControlCallRequest, *, rpc_id: str) -> dict[str, str]:
        headers = _base_headers(self._endpoint, self._claim)
        headers.update(
            {
                "content-type": "application/json",
                HEADER_CLIENT_KIND: self._client_kind.value,
                HEADER_SERVICE_INSTANCE: request.service_instance_id,
                HEADER_SERVICE_GENERATION: request.service_generation,
                HEADER_OPERATION_ID: rpc_id,
            }
        )
        if request.deadline_ms is not None:
            headers[HEADER_DEADLINE_MS] = str(request.deadline_ms)
        if request.route_profile is not None:
            headers[HEADER_ROUTE_PROFILE] = request.route_profile
        if request.host_profile is not None:
            headers[HEADER_HOST_PROFILE] = request.host_profile
        return headers

    async def _send_request(
        self,
        method: str,
        path: str,
        *,
        content: bytes | None = None,
        headers: dict[str, str],
        admitted: bool = False,
    ) -> httpx.Response:
        """One request; a lost answer of a call that may have been admitted is outcome-unknown.

        ``admitted`` says the server already accepted the call (a long-poll of its operation).
        Otherwise only a failure before any byte was sent (connecting, TLS, the pin) is a remote
        phase; one after the request went out may have reached the server.
        """

        try:
            response = await self._http.request(method, path, content=content, headers=headers)
        except httpx.HTTPError as error:
            failure = (
                _transport_failure(error, self._endpoint)
                if not admitted and _never_sent(error)
                else _outcome_unknown()
            )
            await self._fail_connection(failure)
            raise failure from None
        if len(response.content) > _MAX_RESPONSE_BYTES:
            await self._fail_connection(ControlError("frame_invalid"))
            raise ControlError("frame_invalid")
        return cast(httpx.Response, response)

    def _result(self, request: ControlCallRequest, response: httpx.Response) -> ControlResult:
        outcome = response.headers.get(HEADER_OUTCOME)
        instance = response.headers.get(HEADER_SERVICE_INSTANCE)
        generation = response.headers.get(HEADER_SERVICE_GENERATION)
        if outcome not in {"ok", "error"} or instance is None or generation is None:
            raise ControlError("frame_invalid")
        try:
            body = strict_json_parse(response.content)
            if canonical_encode(body) != response.content:
                raise ValueError("body_not_canonical")
            wire = freeze_json(
                {
                    "body": body,
                    "method": request.method.value,
                    "outcome": outcome,
                    "protocol_version": CONTROL_PROTOCOL_VERSION,
                    "rpc_id": request.rpc_id,
                    "service_generation": generation,
                    "service_instance_id": instance,
                }
            )
            if type(wire) is not JsonObject:
                raise ValueError("result_invalid")
            result = parse_control_result(wire)
        except (ControlProtocolError, TypeError, ValueError):
            raise ControlError("frame_invalid") from None
        if (
            result.service_instance_id != self._session.service_instance_id
            or result.service_generation != self._session.service_generation
        ):
            raise ControlError("frame_invalid")
        return result

    async def _cancel_remote(self, rpc_id: str) -> None:
        """Best effort: ask the server to cancel an operation this client stopped waiting for."""

        if self._closed:
            return
        with contextlib.suppress(Exception):
            async with asyncio.timeout(_CANCEL_SECONDS):
                await self._http.request(
                    "DELETE",
                    f"/v1/operations/{rpc_id}",
                    headers=_base_headers(self._endpoint, self._claim),
                )

    async def call(self, request: ControlCallRequest) -> ControlResult:
        self._ensure_live()
        self._admit(request.method)
        if (
            request.service_instance_id != self._session.service_instance_id
            or request.service_generation != self._session.service_generation
        ):
            raise ControlError("service_unavailable", retryable=True)
        body = _request_body(request)
        if request.method is ControlMethod.START:
            _refuse_workspace_path(body)
        headers = self._headers(request, rpc_id=request.rpc_id)
        deadline = (
            None if request.deadline_ms is None else time.monotonic() + request.deadline_ms / 1_000
        )

        def wait_ms() -> int:
            """The next long-poll window; the call's own deadline ends the wait, never a spin."""

            if deadline is None:
                return MAX_WAIT_MS
            remaining = int((deadline - time.monotonic()) * 1_000)
            if remaining <= 0:
                raise TimeoutError
            return min(MAX_WAIT_MS, remaining)

        admitted = False
        try:
            async with asyncio.timeout(
                None if request.deadline_ms is None else request.deadline_ms / 1_000
            ):
                response = await self._post_when_admitted(request, body, headers, wait_ms)
                while response.status_code == 202:
                    admitted = True
                    response = await self._send_request(
                        "GET",
                        f"/v1/operations/{request.rpc_id}?wait_ms={wait_ms()}",
                        headers=_base_headers(self._endpoint, self._claim),
                        admitted=True,
                    )
        except TimeoutError as exc:
            # As on the socket: a check keeps running for a later status read; anything else
            # the client stopped waiting for is cancelled.
            if request.method is not ControlMethod.CHECK:
                await self._cancel_remote(request.rpc_id)
            raise ControlError("request_timeout", retryable=True) from exc
        except asyncio.CancelledError:
            if request.method is not ControlMethod.CHECK:
                with contextlib.suppress(BaseException):
                    await asyncio.shield(self._cancel_remote(request.rpc_id))
            raise
        if response.status_code != 200:
            # Once admitted, any refusal (the answer expired, the key was revoked meanwhile, the
            # service restarted) leaves the call's outcome unknown.
            error = _outcome_unknown() if admitted else _refusal_error(response)
            if error.reason == "service_unavailable" and error.phase == "remote_auth_failed":
                await self._fail_connection(error)
            raise error
        result = self._result(request, response)
        if (
            result.outcome == "error"
            and isinstance(result.body, ControlError)
            and result.body.reason == "service_generation_changed"
        ):
            # Same rule as the socket: a generation change retires this client.
            await self._fail_connection(ControlError("service_unavailable", retryable=True))
            return ControlResult(
                protocol_version=result.protocol_version,
                rpc_id=result.rpc_id,
                service_instance_id=result.service_instance_id,
                service_generation=result.service_generation,
                method=result.method,
                outcome="error",
                body=ControlError("service_unavailable", retryable=True),
            )
        return result

    async def _post_when_admitted(
        self,
        request: ControlCallRequest,
        body: bytes,
        headers: dict[str, str],
        wait_ms: Callable[[], int],
    ) -> httpx.Response:
        """POST the call; one refused for this key's running-operation limit is sent again.

        That refusal comes before dispatch, so sending the same operation id again is safe; the
        waits grow and stop at ``_BUSY_TOTAL_SECONDS`` or the call's own deadline.
        """

        waited = 0.0
        delay = _BUSY_FIRST_SECONDS
        while True:
            response = await self._send_request(
                "POST",
                f"/v1/{request.method.value}?wait_ms={wait_ms()}",
                content=body,
                headers=headers,
            )
            if (
                response.status_code != 429
                or parse_rest_error(response.content) != "operation_limit"
                or waited + delay > _BUSY_TOTAL_SECONDS
            ):
                return response
            await asyncio.sleep(delay)
            waited += delay
            delay = min(delay * 2, _BUSY_MAX_SECONDS)

    async def cancel(self, request: ControlCancelRequest) -> None:
        self._ensure_live()
        if (
            request.service_instance_id != self._session.service_instance_id
            or request.service_generation != self._session.service_generation
        ):
            raise ControlError("service_unavailable", retryable=True)
        await self._cancel_remote(request.target_rpc_id)

    async def close(self) -> None:
        if os.getpid() != self._pid:
            self._closed = True
            return
        await self._fail_connection(ControlError("service_unavailable", retryable=True))


async def read_server_info(
    http: Any, endpoint: RestEndpoint, claim: WorkspaceClaim | None
) -> ServerInfo:
    """``GET /v1/server`` as this client: the service, the key's scope, the claim's binding."""

    try:
        response = await http.request("GET", "/v1/server", headers=_base_headers(endpoint, claim))
    except httpx.HTTPError as error:
        raise _transport_failure(error, endpoint) from None
    if response.status_code != 200:
        raise _refusal_error(response)
    try:
        info = parse_server_info(response.content)
    except ValueError:
        raise _remote("remote_incompatible", retryable=False) from None
    if info.schema_manifest_digest != schema_manifest_digest():
        # Lockstep releases (ADR-051 decision 10): the wire contract differs.
        raise _remote("remote_incompatible", retryable=False)
    return info


async def connect_rest_service(
    client_kind: ControlClientKind,
    *,
    record: ServerTarget,
    root: Path,
    claim: WorkspaceClaim | None = None,
    _transport: httpx.AsyncBaseTransport | None = None,
    _endpoint: RestEndpoint | None = None,
) -> RestServiceClient:
    """Connect to ``record``'s server through its network API.

    ``claim`` names the workspace (``service.client._remote_claim`` makes it from a locator, which
    is never sent); every request carries it and the server answers with the workspace handle.
    ``_transport``/``_endpoint`` are test seams (an in-process ASGI app, a fixed credential).
    """

    if type(client_kind) is not ControlClientKind:
        raise TypeError("control_client_kind_invalid")
    if claim is not None and type(claim) is not WorkspaceClaim:
        raise TypeError("workspace_claim_invalid")
    endpoint = _endpoint or rest_endpoint_for(record, root)
    http = _client(endpoint, transport=_transport)
    try:
        info = await read_server_info(http, endpoint, claim)
    except BaseException:
        with contextlib.suppress(Exception):
            await http.aclose()
        raise
    return RestServiceClient(http, endpoint, info, client_kind, claim=claim, _token=_PRIVATE)


def open_rest_http(record: ServerTarget, root: Path) -> tuple[Any, dict[str, str]]:
    """An HTTP client for ``record``'s API and the headers every request carries (the agent's)."""

    endpoint = rest_endpoint_for(record, root)
    return _client(endpoint, transport=None), _base_headers(endpoint, None)
