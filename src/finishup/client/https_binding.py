"""HTTPS binding v1 carried as a control byte stream (ADR-051, approach B).

``HttpsTransport`` hands ``ServiceClient`` a ``BindingControlStream``: the client writes and reads
the very length-prefixed frames it writes to a Unix socket, and this adapter maps each frame onto
the binding the server's gateway speaks (``docs/INTERFACES.md``, *HTTPS binding v1*):

* the hello → ``POST /v1/sessions`` (``201`` hello-result and ``Location``; ``409`` the daemon's
  hello-result on a manifest mismatch, which the handshake names);
* a call → ``POST …/calls?wait_ms=`` with a short first wait (``CALL_WAIT_MS``); a ``202`` is
  followed by ``GET …/results/{rpc_id}?wait_ms=`` long-polls until the result arrives. A call is
  never posted twice: after an ambiguous failure the adapter only asks for the result (at most
  once);
* a cancel → ``POST …/cancel``, sent only once the gateway answered the call it names, so it never
  overtakes that call (the short first wait bounds how long a cancel waits), and only while that
  call's result has not arrived: the service refuses a cancel naming a call it already finished
  by closing the whole connection; any other client frame (``workspace_reply``) →
  ``POST …/frames``;
* server frames (``workspace_call``) → a long-poll on ``GET …/frames?wait_ms=`` (``200`` one frame,
  ``204`` none yet), run only for a session whose hello declared a workspace agent;
* close → ``DELETE /v1/sessions/{sid}``, sent before the long-polls are cancelled (best effort;
  the gateway also expires idle sessions, and an agent session whose frames long-poll stopped).

The gateway expires a session after 120 idle seconds. Before a call on a session idle for longer
than ``SESSION_IDLE_CHECK_SECONDS``, the stream asks whether it still exists (``GET …/frames`` with
no wait); if it expired, the write fails, so ``ServiceClient`` reports a retryable
``service_unavailable`` and the caller's reconnect-once re-handshakes and replays the same
``request_id`` (one extra round trip after an idle period).

Each response body is the exact canonical JSON a socket frame carries after its length prefix, so
the adapter only adds the prefix back; the control protocol above validates every frame as it does
on a socket. TLS trusts the target's CA file, or its ``sha256:`` pin of the leaf certificate,
checked inside the TLS handshake before any request (and so before the key) is sent, or else the
default trust store. The bearer key comes from the target's ``CredentialSource`` in this process.

This is the only client module that imports ``httpx``; ``finishup.client.transports`` loads it for
HTTPS targets only. Failures are closed remote phases; no URL, header, body or key appears in an
error, log or representation.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import re
import ssl
import struct
import time
from collections.abc import Awaitable, Buffer, Callable, Coroutine, Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Final, cast
from urllib.parse import urlsplit

import httpcore
import httpx

from finishup.client.credentials import CredentialError, CredentialSource
from finishup.client.targets import ServerTarget
from finishup.client.transports import RemotePeerIdentity, TransportError
from finishup.protocol.canonical import JsonValue, strict_json_parse
from finishup.protocol.ids import IdKind, validate_id
from finishup.service.control_protocol import MAX_CONTROL_FRAME_BYTES

__all__ = [
    "BINDING_HEADER",
    "BINDING_VERSION",
    "CALL_WAIT_MS",
    "LONG_POLL_WAIT_MS",
    "SESSION_ID_PATTERN",
    "SESSION_IDLE_CHECK_SECONDS",
    "BindingControlStream",
    "ServerInfo",
    "TlsPinMismatch",
    "binding_client",
    "build_http_transport",
    "certificate_matches_pin",
    "fetch_server_info",
    "open_binding_stream",
    "phase_for_http_error",
    "phase_for_status",
]

BINDING_HEADER: Final = "FinishUP-Binding"
BINDING_VERSION: Final = "1.0"
# The binding caps a long-poll at 25 s, under the 60 s idle cut of common proxies.
LONG_POLL_WAIT_MS: Final = 25_000
# A call's own post waits this long for its result. A quick call (a hook's ingest, a status read)
# is answered in that one round trip; a longer one answers ``202`` and its result is long-polled.
# It also bounds how long a cancel waits for the gateway to have its call (see ``_dispatch``).
CALL_WAIT_MS: Final = 2_000
# Under the gateway's 120 s idle expiry, with room for a slow round trip.
SESSION_IDLE_CHECK_SECONDS: Final = 90.0
_CONNECT_SECONDS: Final = 10.0
_REQUEST_SECONDS: Final = 30.0
_POLL_MARGIN_SECONDS: Final = 15.0
_DELETE_SECONDS: Final = 1.0
_MAX_RECEIVE_BYTES: Final = 65_536
_MAX_SERVER_INFO_BYTES: Final = 65_536
# A session id is 32 random bytes, base64url without padding (the gateway's ``sid``).
SESSION_ID_PATTERN: Final = re.compile(r"^[A-Za-z0-9_-]{43}$", re.ASCII)
_RELEASE: Final = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+-]{0,63}$", re.ASCII)
_DIGEST: Final = re.compile(r"^sha256:[0-9a-f]{64}$", re.ASCII)
_JSON: Final = {"Content-Type": "application/json"}


class _SessionExpired(Exception):
    """The gateway no longer knows this session; the write fails so the caller reconnects."""


class TlsPinMismatch(httpcore.ConnectError):
    """The server's leaf certificate is not the pinned one; nothing was sent over the connection."""


def certificate_matches_pin(ssl_object: object, pin: str) -> bool:
    """Whether the peer's leaf certificate (DER) hashes to ``pin`` (``sha256:<64 hex>``)."""

    getpeercert = getattr(ssl_object, "getpeercert", None)
    if getpeercert is None:
        return False
    try:
        der: object = getpeercert(binary_form=True)
    except (ValueError, ssl.SSLError):
        return False
    if type(der) is not bytes or not der:
        return False
    observed = "sha256:" + hashlib.sha256(der).hexdigest()
    return hmac.compare_digest(observed.encode("ascii"), pin.encode("ascii"))


class _PinnedStream(httpcore.AsyncNetworkStream):
    """A TCP stream whose TLS upgrade fails unless the leaf certificate matches the pin."""

    def __init__(self, inner: httpcore.AsyncNetworkStream, pin: str) -> None:
        self._inner = inner
        self._pin = pin

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
        upgraded = await self._inner.start_tls(ssl_context, server_hostname, timeout)
        if not certificate_matches_pin(upgraded.get_extra_info("ssl_object"), self._pin):
            await upgraded.aclose()
            raise TlsPinMismatch("tls_pin_mismatch")
        return upgraded

    def get_extra_info(self, info: str) -> Any:
        return self._inner.get_extra_info(info)


class _PinnedBackend(httpcore.AsyncNetworkBackend):
    def __init__(self, pin: str) -> None:
        # ``httpcore`` exports the anyio backend conditionally; anyio is a FinishUP dependency.
        self._inner = cast(httpcore.AsyncNetworkBackend, httpcore.AnyIOBackend())
        self._pin = pin

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        inner = await self._inner.connect_tcp(host, port, timeout, local_address, socket_options)
        return _PinnedStream(inner, self._pin)

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


class _PinnedHTTPTransport(httpx.AsyncHTTPTransport):
    """``httpx``'s transport over a connection pool whose TLS upgrades check the pin."""

    def __init__(self, pin: str) -> None:
        # The pin is the trust anchor (a self-signed server certificate is the usual case), so
        # chain and hostname checks are off and the pin check inside the handshake replaces them.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        super().__init__(verify=context, trust_env=False)
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=context, network_backend=_PinnedBackend(pin), http1=True, http2=False
        )


def build_http_transport(target: ServerTarget) -> httpx.AsyncBaseTransport:
    """The TLS transport for a target: its pin, its CA file, or the default trust store.

    Environment proxies and ``.netrc`` are never consulted (``trust_env=False``): the owner's
    recorded address and trust decide where the key goes.
    """

    if target.tls_pin is not None:
        return _PinnedHTTPTransport(target.tls_pin)
    if target.ca_file is not None:
        try:
            context = ssl.create_default_context(cafile=target.ca_file)
        except (OSError, ssl.SSLError, ValueError):
            raise TransportError("remote_identity_changed") from None
        return httpx.AsyncHTTPTransport(verify=context, trust_env=False)
    return httpx.AsyncHTTPTransport(verify=True, trust_env=False)


def binding_client(
    target: ServerTarget, secret: str, *, http_transport: httpx.AsyncBaseTransport | None = None
) -> httpx.AsyncClient:
    """An ``httpx`` client for one target: its base URL, its key, the binding version header."""

    base_url = target.base_url
    if base_url is None:
        raise ValueError("https_target_required")
    return httpx.AsyncClient(
        base_url=base_url,
        transport=http_transport if http_transport is not None else build_http_transport(target),
        headers={"Authorization": f"Bearer {secret}", BINDING_HEADER: BINDING_VERSION},
        timeout=httpx.Timeout(_REQUEST_SECONDS, connect=_CONNECT_SECONDS),
        follow_redirects=False,
        trust_env=False,
    )


def phase_for_status(status: int) -> str:
    """The closed remote phase of an unexpected binding status (``rest-error`` reasons)."""

    if status in {401, 403}:
        return "remote_auth_failed"
    if status == 503:
        return "remote_service_not_running"
    return "remote_unreachable"


def phase_for_http_error(error: BaseException) -> str:
    """``remote_identity_changed`` for a refused certificate or pin, else ``remote_unreachable``."""

    seen: set[int] = set()
    current: BaseException | None = error
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, TlsPinMismatch | ssl.SSLCertVerificationError):
            return "remote_identity_changed"
        current = current.__cause__ or current.__context__
    return "remote_unreachable"


async def _bounded_body(response: httpx.Response, limit: int) -> bytes:
    chunks: list[bytes] = []
    size = 0
    async for chunk in response.aiter_bytes():
        size += len(chunk)
        if size > limit:
            raise TransportError("remote_incompatible")
        chunks.append(chunk)
    return b"".join(chunks)


type _Trace = Callable[[str, Mapping[str, object]], Awaitable[None]]


async def _request(
    client: httpx.AsyncClient,
    method: str,
    path: str,
    *,
    content: bytes | None = None,
    wait_ms: int | None = None,
    limit: int = MAX_CONTROL_FRAME_BYTES,
    trace: _Trace | None = None,
) -> tuple[int, httpx.Headers, bytes]:
    """One bounded request; every ``httpx`` failure becomes a closed phase, never its text.

    ``trace`` receives the connection's progress events (``httpcore``'s ``trace`` extension).
    """

    params = None if wait_ms is None else {"wait_ms": str(wait_ms)}
    read = _REQUEST_SECONDS if wait_ms is None else wait_ms / 1_000 + _POLL_MARGIN_SECONDS
    try:
        async with client.stream(
            method,
            path,
            content=content,
            params=params,
            headers=_JSON if content is not None else None,
            timeout=httpx.Timeout(read, connect=_CONNECT_SECONDS),
            extensions=None if trace is None else {"trace": trace},
        ) as response:
            body = await _bounded_body(response, limit)
            return response.status_code, response.headers, body
    except httpx.HTTPError as error:
        raise TransportError(phase_for_http_error(error)) from None


def _session_id(location: str | None) -> str | None:
    if location is None:
        return None
    try:
        path = urlsplit(location).path
    except ValueError:
        return None
    head, _separator, sid = path.rpartition("/")
    if not head.endswith("/v1/sessions") or not SESSION_ID_PATTERN.match(sid):
        return None
    return sid


class BindingControlStream:
    """One binding session presented as the length-prefixed byte stream ``ServiceClient`` reads.

    ``send_all`` parses the outgoing frames and dispatches each as its binding request; responses
    and server frames are queued as whole frames for ``receive``. Calls, cancels and replies run
    as tasks so one long-polled call never blocks another frame.
    """

    __slots__ = (
        "_agent",
        "_client",
        "_closed",
        "_ended",
        "_failure",
        "_hello",
        "_inbound",
        "_last_activity",
        "_open_calls",
        "_outbound",
        "_peer",
        "_posted",
        "_readable",
        "_session",
        "_tasks",
    )

    _agent: bool
    _client: httpx.AsyncClient
    _closed: bool
    _ended: bool
    _failure: str | None
    _hello: str
    _inbound: bytearray
    _last_activity: float
    _open_calls: set[str]
    _outbound: bytearray
    _peer: RemotePeerIdentity
    _posted: dict[str, asyncio.Event]
    _readable: asyncio.Event
    _session: str | None
    _tasks: set[asyncio.Task[None]]

    def __init__(self, client: httpx.AsyncClient) -> None:
        self._client = client
        self._peer = RemotePeerIdentity("https")
        self._agent = False
        self._closed = False
        self._ended = False
        self._failure = None
        self._hello = "unsent"
        self._inbound = bytearray()
        self._last_activity = time.monotonic()
        self._open_calls = set()
        self._outbound = bytearray()
        self._posted = {}
        self._readable = asyncio.Event()
        self._session = None
        self._tasks = set()

    @property
    def peer_identity(self) -> RemotePeerIdentity:
        return self._peer

    async def failure_phase(self) -> str | None:
        """Why this stream ended; ``None`` when it ended cleanly.

        A hello the gateway received and has not answered means its service is not answering
        yet (the gateway starts an idle-stopped service inside ``POST /v1/sessions`` and answers
        ``503`` when that fails): a caller that gives up waiting reads ``remote_service_not_running``,
        never a network fault.
        """

        if self._failure is None and self._hello == "delivered":
            return "remote_service_not_running"
        return self._failure

    async def _trace_hello(self, event: str, _info: Mapping[str, object]) -> None:
        if event.endswith(".send_request_body.complete") and self._hello == "unsent":
            self._hello = "delivered"

    def _deliver(self, body: bytes) -> None:
        if self._ended:
            return
        if not body or len(body) > MAX_CONTROL_FRAME_BYTES:
            self._end("remote_incompatible")
            return
        self._inbound += struct.pack(">I", len(body)) + body
        self._readable.set()

    def _end(self, failure: str | None) -> None:
        if failure is not None and self._failure is None:
            self._failure = failure
        self._ended = True
        self._readable.set()

    def _spawn(self, work: Coroutine[Any, Any, None]) -> None:
        task = asyncio.create_task(work)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def receive(self, max_bytes: int = _MAX_RECEIVE_BYTES) -> bytes:
        if type(max_bytes) is not int or not 1 <= max_bytes <= _MAX_RECEIVE_BYTES:
            raise ValueError("receive_size_invalid")
        while not self._inbound and not self._ended:
            self._readable.clear()
            await self._readable.wait()
        chunk = bytes(self._inbound[:max_bytes])
        del self._inbound[:max_bytes]
        return chunk

    async def send_all(self, data: Buffer) -> None:
        if self._ended or self._closed:
            raise TransportError(self._failure or "remote_unreachable")
        view = memoryview(data)
        if view.ndim != 1 or not view.contiguous:
            raise TypeError("send_buffer_invalid")
        self._outbound += view
        while len(self._outbound) >= 4:
            declared = struct.unpack(">I", bytes(self._outbound[:4]))[0]
            if declared == 0 or declared > MAX_CONTROL_FRAME_BYTES:
                self._end("remote_unreachable")
                raise TransportError("remote_unreachable")
            if len(self._outbound) < 4 + declared:
                return
            payload = bytes(self._outbound[4 : 4 + declared])
            del self._outbound[: 4 + declared]
            try:
                await self._dispatch(payload)
            except TransportError as error:
                self._end(error.phase)
                raise

    async def _dispatch(self, payload: bytes) -> None:
        try:
            parsed = strict_json_parse(payload)
        except ValueError:
            raise TransportError("remote_unreachable") from None
        if not isinstance(parsed, Mapping):
            raise TransportError("remote_unreachable")
        frame = cast(Mapping[str, JsonValue], parsed)
        if self._session is None:
            if "connection_nonce" not in frame:
                raise TransportError("remote_unreachable")
            self._agent = "workspace_agent" in frame
            await self._open_session(payload)
            return
        kind = frame.get("kind")
        if kind == "call":
            await self._check_idle_session()
            rpc_id = frame.get("rpc_id")
            try:
                validate_id(IdKind.CONTROL_RPC, cast(str, rpc_id))
            except (TypeError, ValueError):
                raise TransportError("remote_unreachable") from None
            posted = asyncio.Event()
            self._posted[cast(str, rpc_id)] = posted
            self._open_calls.add(cast(str, rpc_id))
            self._spawn(self._call(cast(str, rpc_id), payload, posted))
        elif kind == "cancel":
            target = frame.get("target_rpc_id")
            if type(target) is not str:
                raise TransportError("remote_unreachable")
            self._spawn(self._cancel(target, payload, self._posted.get(target)))
        elif kind == "workspace_reply":
            self._spawn(self._post("frames", payload))
        else:
            raise TransportError("remote_unreachable")

    async def _open_session(self, payload: bytes) -> None:
        status, headers, body = await self._request(
            "POST", "/v1/sessions", content=payload, trace=self._trace_hello
        )
        self._hello = "answered"
        if status == 409:
            # A manifest mismatch: the daemon's hello-result lets the handshake name it.
            self._deliver(body)
            return
        if status != 201:
            raise TransportError(phase_for_status(status))
        sid = _session_id(headers.get("location"))
        if sid is None:
            raise TransportError("remote_incompatible")
        self._session = f"/v1/sessions/{sid}"
        self._deliver(body)
        if self._agent:
            self._spawn(self._poll_frames())

    async def _request(
        self,
        method: str,
        path: str,
        *,
        content: bytes | None = None,
        wait_ms: int | None = None,
        trace: _Trace | None = None,
    ) -> tuple[int, httpx.Headers, bytes]:
        answer = await _request(
            self._client, method, path, content=content, wait_ms=wait_ms, trace=trace
        )
        self._last_activity = time.monotonic()
        return answer

    async def _check_idle_session(self) -> None:
        """After a long idle period, confirm the session before posting a call into it."""

        if self._agent or time.monotonic() - self._last_activity < SESSION_IDLE_CHECK_SECONDS:
            return
        status, _headers, body = await self._request(
            "GET", f"{self._session_path()}/frames", wait_ms=0
        )
        if status == 404:
            self._end(None)
            raise _SessionExpired
        if status == 200:
            self._deliver(body)

    def _session_path(self) -> str:
        session = self._session
        if session is None:
            raise TransportError("remote_unreachable")
        return session

    async def _call(self, rpc_id: str, payload: bytes, posted: asyncio.Event) -> None:
        path = self._session_path()
        status: int | None = None
        body = b""
        try:
            try:
                status, _headers, body = await self._request(
                    "POST", f"{path}/calls", content=payload, wait_ms=CALL_WAIT_MS
                )
            except TransportError:
                # The call may have reached the gateway: never post it again, only ask for its
                # result.
                status, body = None, b""
            finally:
                if status == 200:
                    # Answered in its own post: the service finished it, so a cancel waiting
                    # for this post is dropped instead of sent.
                    self._open_calls.discard(rpc_id)
                posted.set()
                if self._posted.get(rpc_id) is posted:
                    del self._posted[rpc_id]
            while not self._ended:
                if status == 200:
                    self._deliver(body)
                    return
                if status is not None and status != 202:
                    # ``404`` is an expired session: end the stream so the caller reconnects.
                    self._end(None if status == 404 else phase_for_status(status))
                    return
                try:
                    status, _headers, body = await self._request(
                        "GET", f"{path}/results/{rpc_id}", wait_ms=LONG_POLL_WAIT_MS
                    )
                except TransportError as error:
                    self._end(error.phase)
                    return
        finally:
            self._open_calls.discard(rpc_id)

    async def _cancel(self, target: str, payload: bytes, posted: asyncio.Event | None) -> None:
        """Send a cancel once its call's post was answered, and only while that call is open."""

        if posted is not None:
            await posted.wait()
        if target not in self._open_calls:
            # Its result arrived (or no call of this stream has that id): the service has
            # nothing to cancel, and a cancel naming no active call closes the whole connection.
            return
        await self._post("cancel", payload)

    async def _post(self, endpoint: str, payload: bytes) -> None:
        try:
            status, _headers, _body = await self._request(
                "POST", f"{self._session_path()}/{endpoint}", content=payload
            )
        except TransportError as error:
            self._end(error.phase)
            return
        if status not in {200, 202, 204}:
            self._end(None if status == 404 else phase_for_status(status))

    async def _poll_frames(self) -> None:
        path = self._session_path()
        while not self._ended:
            try:
                status, _headers, body = await self._request(
                    "GET", f"{path}/frames", wait_ms=LONG_POLL_WAIT_MS
                )
            except TransportError as error:
                self._end(error.phase)
                return
            if status == 200:
                self._deliver(body)
            elif status != 204:
                self._end(None if status == 404 else phase_for_status(status))
                return

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._end(None)
        try:
            if self._session is not None:
                # First, while the long-polls still run: the gateway ends the session, and with it
                # the daemon's agent registration for it, before this process goes away.
                with contextlib.suppress(Exception):
                    async with asyncio.timeout(_DELETE_SECONDS):
                        await self._client.delete(self._session)
            tasks = tuple(self._tasks)
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            await self._client.aclose()


async def open_binding_stream(
    target: ServerTarget, credential: CredentialSource, *, http_transport: object | None = None
) -> BindingControlStream:
    """A fresh binding stream for ``target``; the key is read here, in this process."""

    try:
        secret = credential.read()
    except CredentialError:
        raise TransportError("remote_auth_failed") from None
    if http_transport is not None and not isinstance(http_transport, httpx.AsyncBaseTransport):
        raise TypeError("http_transport_invalid")
    return BindingControlStream(binding_client(target, secret, http_transport=http_transport))


@dataclass(frozen=True, slots=True)
class ServerInfo:
    """What ``GET /v1/server`` reported, reduced to closed, validated values."""

    release: str | None
    schema_manifest_digest: str | None


async def fetch_server_info(
    target: ServerTarget, secret: str, *, http_transport: httpx.AsyncBaseTransport | None = None
) -> ServerInfo:
    """Ask the gateway who it is; ``remote_incompatible`` when its manifest is not this client's.

    A release or digest the server sends in an unexpected shape is dropped, never shown.
    """

    from finishup.protocol.schemas import schema_manifest_digest

    async with binding_client(target, secret, http_transport=http_transport) as client:
        status, _headers, body = await _request(
            client, "GET", "/v1/server", limit=_MAX_SERVER_INFO_BYTES
        )
    if status != 200:
        raise TransportError(phase_for_status(status))
    try:
        parsed = strict_json_parse(body)
    except ValueError:
        raise TransportError("remote_incompatible") from None
    if not isinstance(parsed, Mapping):
        raise TransportError("remote_incompatible")
    document = cast(Mapping[str, JsonValue], parsed)
    release = document.get("release")
    digest = document.get("schema_manifest_digest")
    bindings = document.get("bindings")
    if not isinstance(bindings, list) or BINDING_VERSION not in bindings:
        # The gateway does not speak this client's binding version.
        raise TransportError("remote_incompatible")
    info = ServerInfo(
        release if type(release) is str and _RELEASE.match(release) else None,
        digest if type(digest) is str and _DIGEST.match(digest) else None,
    )
    if info.schema_manifest_digest is not None and (
        info.schema_manifest_digest != schema_manifest_digest()
    ):
        raise TransportError("remote_incompatible")
    return info
