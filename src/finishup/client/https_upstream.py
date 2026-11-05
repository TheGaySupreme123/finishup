"""The connector's side of the HTTPS binding v1, for ``https`` and ``local_port`` targets.

One local control connection becomes one gateway session (ADR-051, approach A; design section 4):

* the client's hello frame is ``POST /v1/sessions``; the hello-result is written back;
* each ``call`` is ``POST /v1/sessions/{sid}/calls?wait_ms=``; a ``202`` is followed by long-polls
  of ``GET …/results/{rpc_id}``. A call is never posted twice: after an ambiguous failure the
  connector only polls for its result (at most once);
* a ``cancel`` is ``POST …/cancel``; any other client frame (a ``workspace_reply``) is
  ``POST …/frames``;
* when the hello declared a workspace agent, server frames (``workspace_call``) arrive through a
  long-poll of ``GET …/frames`` and are written to the local stream as they come;
* local end of stream is ``DELETE /v1/sessions/{sid}``; ``session_unknown`` closes the local
  stream before anything is dispatched again, so the client's reconnect re-handshakes.

Bodies are the exact canonical frame payloads. TLS uses the target's CA file, or its
``sha256:`` pin of the leaf certificate, checked right after the handshake and before any request
byte (so the key is never sent to an unpinned peer). Only the connector reads the credential.
Failures are closed remote connection phases; no host, URL or response text is kept.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import ssl
import struct
from collections.abc import Awaitable, Callable, Coroutine, Iterable
from typing import Any, Final, cast

import httpcore
import httpx

from finishup.client.ssh_upstream import UpstreamUnavailable
from finishup.client.targets import ServerTarget
from finishup.protocol.canonical import JsonValue, strict_json_parse
from finishup.protocol.rest_binding import (
    BINDING_HEADER,
    BINDING_VERSION,
    MAX_WAIT_MS,
    SESSION_ID_PATTERN,
)
from finishup.service.control_protocol import (
    MAX_CONTROL_FRAME_BYTES,
    ControlFrame,
    ControlProtocolError,
    ControlStream,
    decode_control_frame,
    encode_control_frame,
    read_control_frame,
)

__all__ = [
    "HttpsUpstream",
    "PinnedStream",
    "PinnedTlsTransport",
    "relay_https_connection",
]

_CONNECT_SECONDS: Final = 10.0
# A long-poll answers within ``MAX_WAIT_MS``; the read timeout leaves room for the network.
_READ_SECONDS: Final = MAX_WAIT_MS / 1000 + 15.0
_AMBIGUOUS_POLLS: Final = 3
_AMBIGUOUS_BACKOFF_SECONDS: Final = 0.5
_JSON: Final = "application/json"


class PinnedStream(httpcore.AsyncNetworkStream):
    """A TCP stream whose TLS upgrade is refused unless the leaf certificate matches the pin."""

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
        tls = upgraded.get_extra_info("ssl_object")
        leaf = tls.getpeercert(binary_form=True) if isinstance(tls, ssl.SSLObject) else None
        if not leaf or f"sha256:{hashlib.sha256(leaf).hexdigest()}" != self._pin:
            await upgraded.aclose()
            raise httpcore.ConnectError("tls_pin_mismatch")
        return upgraded

    def get_extra_info(self, info: str) -> object:
        return self._inner.get_extra_info(info)


class _PinnedBackend(httpcore.AsyncNetworkBackend):
    def __init__(self, pin: str) -> None:
        self._inner = cast(httpcore.AsyncNetworkBackend, httpcore.AnyIOBackend())
        self._pin = pin

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[object] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        stream = await self._inner.connect_tcp(
            host,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=cast(Iterable[Any] | None, socket_options),
        )
        return PinnedStream(stream, self._pin)

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[object] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        raise httpcore.ConnectError("tls_pin_requires_tcp")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


class PinnedTlsTransport(httpx.AsyncHTTPTransport):
    """``httpx`` transport whose TCP connections must present the pinned leaf certificate.

    The pin replaces chain and host-name validation, as the owner chose with ``--tls-pin``; it is
    checked on every new connection before the request is written.
    """

    def __init__(self, pin: str) -> None:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        super().__init__(verify=context, trust_env=False)
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=context,
            max_connections=100,
            max_keepalive_connections=20,
            keepalive_expiry=5.0,
            network_backend=_PinnedBackend(pin),
        )


def _transport_for(record: ServerTarget) -> httpx.AsyncBaseTransport:
    if record.tls_pin is not None:
        return PinnedTlsTransport(record.tls_pin)
    if record.ca_file is not None:
        return httpx.AsyncHTTPTransport(
            verify=ssl.create_default_context(cafile=record.ca_file), trust_env=False
        )
    return httpx.AsyncHTTPTransport(verify=True, trust_env=False)


def _is_identity_failure(error: BaseException) -> bool:
    seen: set[int] = set()
    current: BaseException | None = error
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, ssl.SSLError) or "tls_pin_mismatch" in str(current.args[:1]):
            return True
        current = current.__cause__ or current.__context__
    return False


def _unreachable(error: httpx.HTTPError) -> UpstreamUnavailable:
    return UpstreamUnavailable(
        "remote_identity_changed" if _is_identity_failure(error) else "remote_unreachable"
    )


class HttpsUpstream:
    """One target's HTTPS client: TLS per the record, the bearer key, the binding's routes."""

    def __init__(
        self,
        record: ServerTarget,
        credential: Callable[[], str],
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if record.kind not in {"https", "local_port"} or record.base_url is None:
            raise ValueError("target_not_https")
        self._base = record.base_url
        self._credential = credential
        self._client = httpx.AsyncClient(
            transport=transport if transport is not None else _transport_for(record),
            timeout=httpx.Timeout(_READ_SECONDS, connect=_CONNECT_SECONDS),
            follow_redirects=False,
            trust_env=False,
        )

    def _headers(self) -> dict[str, str]:
        try:
            key = self._credential()
        except Exception:
            raise UpstreamUnavailable("remote_auth_failed") from None
        return {
            "Authorization": f"Bearer {key}",
            BINDING_HEADER: BINDING_VERSION,
            "Content-Type": _JSON,
            "Accept": _JSON,
        }

    async def request(
        self, method: str, path: str, *, body: bytes | None = None, wait_ms: int | None = None
    ) -> httpx.Response:
        params = None if wait_ms is None else {"wait_ms": str(wait_ms)}
        try:
            response = await self._client.request(
                method, f"{self._base}{path}", content=body, params=params, headers=self._headers()
            )
        except httpx.HTTPError as error:
            raise _unreachable(error) from None
        if response.status_code == 401:
            raise UpstreamUnavailable("remote_auth_failed")
        if response.status_code == 503:
            raise UpstreamUnavailable("remote_service_not_running")
        return response

    async def server_info(self) -> dict[str, JsonValue]:
        """``GET /v1/server``, validated against ``server-info`` 1.0.0."""

        from finishup.protocol.rest_binding import ServerInfoContract

        response = await self.request("GET", "/v1/server")
        if response.status_code != 200:
            raise UpstreamUnavailable("remote_unreachable")
        try:
            parsed = strict_json_parse(response.content)
            ServerInfoContract.model_validate(parsed)
        except ValueError:
            raise UpstreamUnavailable("remote_incompatible") from None
        return cast(dict[str, JsonValue], parsed)

    async def aclose(self) -> None:
        await self._client.aclose()


async def _read_frame(stream: ControlStream) -> tuple[ControlFrame, bytes]:
    """One local frame, validated, with its exact payload bytes (the length prefix removed)."""

    frame = await read_control_frame(stream)
    return frame, encode_control_frame(frame)[4:]


class _Relay:
    """One local connection mapped onto one gateway session."""

    def __init__(
        self,
        local: ControlStream,
        upstream: HttpsUpstream,
        on_unavailable: Callable[[str], Awaitable[None]],
    ) -> None:
        self._local = local
        self._upstream = upstream
        self._on_unavailable = on_unavailable
        self._write_lock = asyncio.Lock()
        self._sid: str | None = None
        self._tasks: set[asyncio.Task[object]] = set()
        self._closed = asyncio.Event()
        # The remote phase that ended this relay, reported once after it stops.
        self.unavailable: str | None = None

    async def _write(self, payload: bytes) -> None:
        if len(payload) > MAX_CONTROL_FRAME_BYTES:
            raise ControlProtocolError("frame_too_large")
        async with self._write_lock:
            await self._local.send_all(struct.pack(">I", len(payload)) + payload)

    def _close(self) -> None:
        self._closed.set()

    def _spawn(self, work: Coroutine[object, object, object]) -> None:
        task = asyncio.create_task(work)
        self._tasks.add(task)
        task.add_done_callback(self._task_done)

    def _task_done(self, task: asyncio.Task[object]) -> None:
        self._tasks.discard(task)
        if not task.cancelled() and task.exception() is not None:
            self._failure(task.exception())

    def _failure(self, error: BaseException | None) -> None:
        if isinstance(error, UpstreamUnavailable) and self.unavailable is None:
            self.unavailable = error.reason
        self._close()

    def _session_path(self, suffix: str = "") -> str:
        assert self._sid is not None
        return f"/v1/sessions/{self._sid}{suffix}"

    async def open(self, hello_payload: bytes) -> bool:
        response = await self._upstream.request("POST", "/v1/sessions", body=hello_payload)
        if response.status_code == 409:
            # The server answered with its own hello-result on a manifest mismatch; the client
            # decodes it and names the mismatch.
            await self._on_unavailable("remote_incompatible")
            await self._write(response.content)
            return False
        if response.status_code != 201:
            return False
        location = response.headers.get("Location", "")
        sid = location.rsplit("/", 1)[-1]
        if not location.startswith("/") or not SESSION_ID_PATTERN.match(sid):
            return False
        decode_control_frame(struct.pack(">I", len(response.content)) + response.content)
        self._sid = sid
        await self._write(response.content)
        return True

    async def _await_result(self, rpc_id: str) -> None:
        failures = 0
        while not self._closed.is_set():
            try:
                response = await self._upstream.request(
                    "GET", self._session_path(f"/results/{rpc_id}"), wait_ms=MAX_WAIT_MS
                )
            except UpstreamUnavailable as error:
                failures += 1
                if failures >= _AMBIGUOUS_POLLS:
                    await self._on_unavailable(error.reason)
                    self._close()
                    return
                await asyncio.sleep(_AMBIGUOUS_BACKOFF_SECONDS * failures)
                continue
            failures = 0
            if response.status_code == 200:
                await self._write(response.content)
                return
            if response.status_code != 202:
                self._close()
                return

    async def _call(self, rpc_id: str, payload: bytes) -> None:
        try:
            response = await self._upstream.request(
                "POST", self._session_path("/calls"), body=payload, wait_ms=MAX_WAIT_MS
            )
        except UpstreamUnavailable as error:
            if error.reason in {"remote_auth_failed", "remote_service_not_running"}:
                await self._on_unavailable(error.reason)
                self._close()
                return
            # The call may or may not have reached the gateway: never post it again; poll for it.
            await self._await_result(rpc_id)
            return
        if response.status_code == 200:
            await self._write(response.content)
        elif response.status_code == 202:
            await self._await_result(rpc_id)
        else:
            self._close()

    async def _send(self, path: str, payload: bytes) -> None:
        response = await self._upstream.request("POST", self._session_path(path), body=payload)
        if response.status_code != 202:
            self._close()

    async def _poll_frames(self) -> None:
        while not self._closed.is_set():
            response = await self._upstream.request(
                "GET", self._session_path("/frames"), wait_ms=MAX_WAIT_MS
            )
            if response.status_code == 200:
                await self._write(response.content)
            elif response.status_code != 204:
                self._close()
                return

    async def _read_local(self) -> None:
        while not self._closed.is_set():
            frame, payload = await _read_frame(self._local)
            kind = frame.get("kind")
            if kind == "call":
                self._spawn(self._call(cast(str, frame["rpc_id"]), payload))
            elif kind == "cancel":
                self._spawn(self._send("/cancel", payload))
            elif kind == "workspace_reply":
                self._spawn(self._send("/frames", payload))
            else:
                self._close()
                return

    async def run(self, hello: ControlFrame) -> None:
        closed: asyncio.Task[object] = asyncio.create_task(self._closed.wait())
        waiting: set[asyncio.Task[object]] = {asyncio.create_task(self._read_local()), closed}
        if hello.get("workspace_agent") is not None:
            waiting.add(asyncio.create_task(self._poll_frames()))
        try:
            done, _pending = await asyncio.wait(waiting, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                if task is not closed and not task.cancelled():
                    self._failure(task.exception())
        finally:
            everything: list[asyncio.Task[object]] = [*waiting, *self._tasks]
            for task in everything:
                task.cancel()
            await asyncio.gather(*everything, return_exceptions=True)
            if self._sid is not None:
                with contextlib.suppress(UpstreamUnavailable):
                    await self._upstream.request("DELETE", self._session_path())


async def relay_https_connection(
    local: ControlStream,
    upstream: HttpsUpstream,
    hello: ControlFrame,
    hello_payload: bytes,
    *,
    on_unavailable: Callable[[str], Awaitable[None]],
    on_ready: Callable[[], Awaitable[None]],
) -> None:
    """Serve one local connection whose hello frame the connector already read and checked."""

    relay = _Relay(local, upstream, on_unavailable)
    try:
        if not await relay.open(hello_payload):
            return
    except UpstreamUnavailable as error:
        await on_unavailable(error.reason)
        return
    await on_ready()
    await relay.run(hello)
    if relay.unavailable is not None:
        await on_unavailable(relay.unavailable)
