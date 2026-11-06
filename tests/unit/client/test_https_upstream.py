"""The connector's HTTPS relay against the in-process gateway, and the certificate pin.

At most once: a call whose POST failed ambiguously is never posted again, only polled. A key the
gateway stops accepting is a recorded ``remote_auth_failed`` (and is read again next time); a
session the gateway forgot closes the local stream; a manifest mismatch hands the client the
server's own hello-result. The pin is checked right after the TLS handshake, before any byte of
a request (so the key never reaches an unpinned peer).
"""

from __future__ import annotations

import asyncio
import hashlib
import socket
import ssl
from collections.abc import Callable, Iterator
from pathlib import Path

import httpcore
import httpx
import pytest

from builders.control_relay import (
    ScriptedDaemon,
    call_request,
    memory_pair,
    run_scripted_session,
)
from builders.server_targets import ambient_home
from finishup.adapters.control.unix_socket import AuthenticatedUnixStream, authenticate_peer
from finishup.client import targets
from finishup.client.connector import Connector
from finishup.client.connector_status import read_connector_status
from finishup.client.https_upstream import PinnedStream, PinnedTlsTransport
from finishup.config.paths import selection_override
from finishup.gateway.app import GatewayApp, build_gateway_app
from finishup.gateway.keys import create_key, revoke_key
from finishup.ports.control import ControlMethod
from finishup.protocol.canonical import JsonValue
from finishup.protocol.schemas import load_schema_catalog
from finishup.service.control_protocol import encode_control_frame, read_control_frame


class _Audit:
    def write(self, record: dict[str, JsonValue]) -> None:
        del record


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as root:
        yield root


def _pair() -> tuple[AuthenticatedUnixStream, AuthenticatedUnixStream]:
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    return (
        AuthenticatedUnixStream(left, authenticate_peer(left)),
        AuthenticatedUnixStream(right, authenticate_peer(right)),
    )


class _Flaky(httpx.AsyncBaseTransport):
    """Forwards every request, but loses the answer to the first POST of a call."""

    def __init__(self, inner: httpx.AsyncBaseTransport) -> None:
        self.inner = inner
        self.calls_posted = 0
        self.lost = False

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        response = await self.inner.handle_async_request(request)
        if request.method == "POST" and request.url.path.endswith("/calls"):
            self.calls_posted += 1
            if not self.lost:
                self.lost = True
                await response.aread()
                raise httpx.ReadError("answer_lost", request=request)
        return response


def _setup(
    home: Path,
    *,
    transport_wrapper: Callable[[httpx.AsyncBaseTransport], httpx.AsyncBaseTransport] | None = None,
) -> tuple[GatewayApp, Connector, ScriptedDaemon, str, Path, httpx.AsyncBaseTransport]:
    with targets.registry_lock():
        record, root = targets.new_remote_target("gw", "https", base_url="https://gw.example")
    keys = home / "gateway"
    _key_record, key = create_key(keys, label="client", scope="agent")
    daemon = ScriptedDaemon()

    async def connect_upstream() -> object:
        client, server = memory_pair()
        asyncio.get_running_loop().create_task(daemon.serve(server))
        return client

    state, app = build_gateway_app(
        keys_directory=keys,
        connect_upstream=connect_upstream,  # type: ignore[arg-type]
        audit=_Audit(),
    )
    transport: httpx.AsyncBaseTransport = httpx.ASGITransport(app=app)
    if transport_wrapper is not None:
        transport = transport_wrapper(transport)
    connector = Connector(root, record, https_transport=transport, credential=lambda: key)
    return state, connector, daemon, key, root, transport


def test_an_ambiguous_call_failure_is_polled_never_posted_twice(home: Path) -> None:
    _state, connector, daemon, _key, root, transport = _setup(home, transport_wrapper=_Flaky)

    async def exercise() -> None:
        client, local = _pair()
        relay = asyncio.create_task(connector._serve_local(local))  # pyright: ignore[reportPrivateUsage]
        received = await run_scripted_session(client, agent=False)
        await client.shutdown_write()
        async with asyncio.timeout(10):
            await relay
        assert len(received) == 9
        assert isinstance(transport, _Flaky) and transport.lost
        calls = [frame for frame in daemon.received() if b'"kind":"call"' in frame]
        assert len(calls) == len(set(calls)) == 8  # seven methods and the slow call, once each

    with selection_override(root):
        asyncio.run(exercise())


class _Blips(httpx.AsyncBaseTransport):
    """Fails the first frames poll, cancel and workspace reply once each, as a network blip.

    The poll and the cancel fail before they reach the gateway; the reply reaches it and only
    its answer is lost, so the retry delivers it a second time.
    """

    def __init__(self, inner: httpx.AsyncBaseTransport) -> None:
        self.inner = inner
        self.failed: list[str] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        route = f"{request.method} {path.rsplit('/', 1)[-1]}"
        first = route not in self.failed and route in {"GET frames", "POST cancel", "POST frames"}
        if first and route != "POST frames":
            self.failed.append(route)
            raise httpx.ConnectError("blip", request=request)
        response = await self.inner.handle_async_request(request)
        if first:
            self.failed.append(route)
            await response.aread()
            raise httpx.ReadError("answer_lost", request=request)
        return response


def test_a_network_blip_on_a_poll_cancel_or_reply_does_not_end_the_connection(
    home: Path,
) -> None:
    _state, connector, daemon, _key, root, transport = _setup(home, transport_wrapper=_Blips)

    async def exercise() -> None:
        client, local = _pair()
        relay = asyncio.create_task(connector._serve_local(local))  # pyright: ignore[reportPrivateUsage]
        async with asyncio.timeout(20):
            received = await run_scripted_session(client, agent=True)
            await client.shutdown_write()
            await relay
        assert len(received) == 10
        assert received[-1].count(b"request_cancelled") == 1
        assert isinstance(transport, _Blips)
        assert sorted(transport.failed) == ["GET frames", "POST cancel", "POST frames"]
        assert len(daemon.replies) == 2  # the retried reply arrived twice; the second is moot
        status = read_connector_status(root)
        assert status is None or status.phase != "unavailable"

    with selection_override(root):
        asyncio.run(exercise())


def test_a_refused_key_is_recorded_and_forgotten(home: Path) -> None:
    _state, connector, _daemon, key, root, _transport = _setup(home)

    async def exercise() -> None:
        revoke_key(home / "gateway", key.split("_")[1])
        client, local = _pair()
        relay = asyncio.create_task(connector._serve_local(local))  # pyright: ignore[reportPrivateUsage]
        await client.send_all(
            encode_control_frame(
                {
                    "protocol_version": "1.0",
                    "client_kind": "cli",
                    "client_version": "0.1.0",
                    "connection_nonce": "4c" * 32,
                    "schema_manifest_digest": load_schema_catalog().manifest_digest,
                }
            )
        )
        async with asyncio.timeout(5):
            assert await client.receive(65_536) == b""
            await relay
        status = read_connector_status(root)
        assert status is not None
        assert (status.phase, status.reason) == ("unavailable", "remote_auth_failed")
        assert connector._credential.value is None  # pyright: ignore[reportPrivateUsage]

    with selection_override(root):
        asyncio.run(exercise())


def test_a_forgotten_session_closes_the_local_stream(home: Path) -> None:
    state, connector, _daemon, _key, root, _transport = _setup(home)

    async def exercise() -> None:
        client, local = _pair()
        relay = asyncio.create_task(connector._serve_local(local))  # pyright: ignore[reportPrivateUsage]
        await client.send_all(
            encode_control_frame(
                {
                    "protocol_version": "1.0",
                    "client_kind": "cli",
                    "client_version": "0.1.0",
                    "connection_nonce": "5d" * 32,
                    "schema_manifest_digest": load_schema_catalog().manifest_digest,
                }
            )
        )
        await read_control_frame(client)
        await state.sessions.close_all()  # the gateway expired the session
        await client.send_all(
            encode_control_frame(call_request(0x7001, ControlMethod.SERVICE_STATUS))
        )
        async with asyncio.timeout(5):
            assert await client.receive(65_536) == b""
            await relay

    with selection_override(root):
        asyncio.run(exercise())


def test_a_server_of_another_release_hands_back_its_own_hello_result(home: Path) -> None:
    _state, connector, _daemon, _key, root, _transport = _setup(home)

    async def exercise() -> None:
        client, local = _pair()
        relay = asyncio.create_task(connector._serve_local(local))  # pyright: ignore[reportPrivateUsage]
        await client.send_all(
            encode_control_frame(
                {
                    "protocol_version": "1.0",
                    "client_kind": "cli",
                    "client_version": "0.1.0",
                    "connection_nonce": "6e" * 32,
                    "schema_manifest_digest": "sha256:" + "0" * 64,
                }
            )
        )
        answer = await read_control_frame(client)
        assert answer["schema_manifest_digest"] == load_schema_catalog().manifest_digest
        async with asyncio.timeout(5):
            await relay
        status = read_connector_status(root)
        assert status is not None and status.reason == "remote_incompatible"

    with selection_override(root):
        asyncio.run(exercise())


class _TlsStream(httpcore.AsyncNetworkStream):
    def __init__(self, certificate: bytes) -> None:
        self.certificate = certificate
        self.closed = False

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        return b""

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        raise AssertionError("nothing is written before the pin is checked")

    async def aclose(self) -> None:
        self.closed = True

    async def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore.AsyncNetworkStream:
        return self

    def get_extra_info(self, info: str) -> object:
        if info != "ssl_object":
            return None
        certificate = self.certificate

        class _Object(ssl.SSLObject):
            def __init__(self) -> None:
                pass

            def getpeercert(self, binary_form: bool = False) -> bytes:  # type: ignore[override]
                return certificate

        return _Object()


def test_the_pin_is_checked_after_the_handshake_and_before_any_request_byte() -> None:
    certificate = b"leaf certificate der"
    pin = f"sha256:{hashlib.sha256(certificate).hexdigest()}"

    async def exercise() -> None:
        context = ssl.create_default_context()
        accepted = _TlsStream(certificate)
        upgraded = await PinnedStream(accepted, pin).start_tls(context, "gw.example")
        assert upgraded is accepted and not accepted.closed
        other = _TlsStream(b"another certificate")
        with pytest.raises(httpcore.ConnectError, match="tls_pin_mismatch"):
            await PinnedStream(other, pin).start_tls(context, "gw.example")
        assert other.closed
        transport = PinnedTlsTransport(pin)
        await transport.aclose()

    asyncio.run(exercise())


def _wrapped(cause: BaseException) -> httpx.ConnectError:
    """An ``httpx.ConnectError`` raised from ``cause`` the way httpx and anyio chain them."""

    try:
        try:
            raise cause
        except BaseException as inner:
            raise httpcore.ConnectError(str(inner)) from inner
    except httpcore.ConnectError as middle:
        try:
            raise httpx.ConnectError(str(middle)) from middle
        except httpx.ConnectError as outer:
            return outer


@pytest.mark.parametrize(
    ("cause", "reason"),
    [
        (ssl.SSLCertVerificationError(1, "certificate verify failed"), "remote_identity_changed"),
        (httpcore.ConnectError("tls_pin_mismatch"), "remote_identity_changed"),
        (ssl.SSLEOFError(8, "EOF occurred in violation of protocol"), "remote_unreachable"),
        (ssl.SSLError(1, "[SSL: WRONG_VERSION_NUMBER] wrong version number"), "remote_unreachable"),
        (ConnectionResetError(104, "Connection reset by peer"), "remote_unreachable"),
    ],
)
def test_only_a_refused_identity_is_named_an_identity_change(
    cause: BaseException, reason: str
) -> None:
    from finishup.client.https_upstream import (
        _unreachable,  # pyright: ignore[reportPrivateUsage]
    )

    assert _unreachable(_wrapped(cause)).reason == reason


def test_a_plain_http_port_is_unreachable_not_an_identity_change(home: Path) -> None:
    """A client pointed at a gateway run ``--behind-proxy`` (plain HTTP) is a configuration
    fault: the TLS handshake fails on the HTTP answer, before any certificate is seen."""

    from finishup.client.https_upstream import HttpsUpstream
    from finishup.client.ssh_upstream import UpstreamUnavailable

    async def exercise() -> None:
        async def answer(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await reader.read(1_024)
            writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(answer, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        with targets.registry_lock():
            record, _root = targets.new_remote_target(
                "plain", "https", base_url=f"https://127.0.0.1:{port}", tls_pin="sha256:" + "a" * 64
            )
        upstream = HttpsUpstream(record, lambda: "fuk_000000000000_secret")
        try:
            with pytest.raises(UpstreamUnavailable) as failed:
                await upstream.server_info()
            assert failed.value.reason == "remote_unreachable"
        finally:
            await upstream.aclose()
            server.close()
            await server.wait_closed()

    asyncio.run(exercise())
