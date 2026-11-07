"""HTTPS binding v1 under ``ServiceClient``: same client above the stream, closed phases below.

``ServiceClient`` runs unchanged over ``BindingControlStream``. A refused key, an unavailable
service, an incompatible release, an expired session and a lost response each end as one closed
remote phase or the ordinary retryable outcome; a call is never posted twice. TLS trusts the
recorded pin or CA file, and a pin mismatch stops the connection inside the TLS handshake, before
any request (and so the key) is sent.
"""

from __future__ import annotations

import asyncio
import datetime
import hashlib
import ipaddress
import json
import ssl
import tempfile
import threading
import time
from collections.abc import Callable, Coroutine
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import httpx
import pytest

from builders.direct_dial import (
    API_KEY,
    FakeBindingGateway,
    StaticCredential,
    https_target,
    memory_pair,
    service_status,
)
from finishup.client.https_binding import (
    LONG_POLL_WAIT_MS,
    TlsPinMismatch,
    fetch_server_info,
    phase_for_http_error,
    phase_for_status,
)
from finishup.client.transports import HttpsTransport, TransportError
from finishup.ports.control import (
    ControlCancelRequest,
    ControlClientKind,
    ControlError,
    ControlMethod,
    ControlResult,
    ProjectionRenderMode,
)
from finishup.service import client as client_module
from finishup.service.control_protocol import (
    ControlStream,
    parse_control_request,
    read_control_frame,
    server_handshake,
    write_control_frame,
)


async def _status_server(stream: ControlStream) -> None:
    """A service that answers every ``service_status`` call."""

    session = await server_handshake(stream, stream.peer_identity, service_status())
    while True:
        try:
            frame = await read_control_frame(stream, eof_reason="session_closed")
        except Exception:
            return
        request = parse_control_request(frame)
        await write_control_frame(
            stream,
            ControlResult(
                protocol_version="1.0",
                rpc_id=request.rpc_id,
                service_instance_id=session.service_instance_id,
                service_generation=session.service_generation,
                method=ControlMethod.SERVICE_STATUS,
                outcome="ok",
                body=service_status(),
            ),
        )


def _gateway(
    server: Callable[[ControlStream], Coroutine[Any, Any, None]] = _status_server,
) -> FakeBindingGateway:
    async def upstream() -> ControlStream:
        gateway_end, server_end = memory_pair()
        asyncio.get_running_loop().create_task(server(server_end))
        return gateway_end

    return FakeBindingGateway(upstream)


def _transport(
    http: httpx.AsyncBaseTransport, *, credential: StaticCredential | None = None
) -> HttpsTransport:
    return HttpsTransport(
        https_target(),
        Path("/nonexistent"),
        credential=credential or StaticCredential(),
        http_transport=http,
    )


async def _connect(transport: HttpsTransport) -> client_module.ServiceClient:
    return await client_module._connect_service_attempt(  # pyright: ignore[reportPrivateUsage]
        ControlClientKind.CLI,
        workspace_locator=None,
        projection_render_mode=ProjectionRenderMode.MACHINE_READABLE,
        output_is_controlling_tty=False,
        timeout_seconds=5.0,
        transport=transport,
    )


def test_service_client_runs_unchanged_over_the_binding() -> None:
    gateway = _gateway()

    async def exercise() -> None:
        client = await _connect(_transport(httpx.ASGITransport(app=gateway)))
        try:
            statuses = await asyncio.gather(*(client.service_status() for _ in range(5)))
        finally:
            await client.close()
        assert {status.service_instance_id for status in statuses} == {
            service_status().service_instance_id
        }

    asyncio.run(exercise())
    paths = [(method, path) for method, path, _headers in gateway.requests]
    assert paths[0] == ("POST", "/base/v1/sessions")
    assert sum(1 for _method, path in paths if path.endswith("/calls")) == 5
    # No agent was declared, so no frames long-poll ran.
    assert not any(path.endswith("/frames") for _method, path in paths)


@pytest.mark.parametrize(
    ("status", "phase"),
    [
        (401, "remote_auth_failed"),
        (403, "remote_auth_failed"),
        # The gateway refused a hello this client built correctly: another release.
        (400, "remote_incompatible"),
        (413, "remote_incompatible"),
        (503, "remote_service_not_running"),
    ],
)
def test_a_refused_session_is_a_closed_remote_phase(status: int, phase: str) -> None:
    gateway = _gateway()
    gateway.statuses["POST sessions"] = status

    async def exercise() -> ControlError:
        with pytest.raises(ControlError) as raised:
            await _connect(_transport(httpx.ASGITransport(app=gateway)))
        return raised.value

    error = asyncio.run(exercise())
    assert (error.reason, error.retryable, error.phase) == ("service_unavailable", True, phase)


def test_a_wrong_key_is_refused_by_the_gateway_as_an_auth_failure() -> None:
    gateway = _gateway()
    gateway.key = "fuk_ffffffffffff_" + "C" * 43

    async def exercise() -> ControlError:
        with pytest.raises(ControlError) as raised:
            await _connect(_transport(httpx.ASGITransport(app=gateway)))
        return raised.value

    assert asyncio.run(exercise()).phase == "remote_auth_failed"


def test_a_missing_key_never_dials() -> None:
    gateway = _gateway()

    async def exercise() -> ControlError:
        with pytest.raises(ControlError) as raised:
            await _connect(
                _transport(
                    httpx.ASGITransport(app=gateway), credential=StaticCredential(secret=None)
                )
            )
        return raised.value

    assert asyncio.run(exercise()).phase == "remote_auth_failed"
    assert gateway.requests == []


class _PromptingCredential(StaticCredential):
    """A keyring waiting on an unlock prompt: ``read`` blocks until ``answered`` is set."""

    def __init__(self) -> None:
        super().__init__()
        self.reading = threading.Event()
        self.answered = threading.Event()
        self.finished = threading.Event()

    def read(self) -> str:
        self.reading.set()
        try:
            self.answered.wait(timeout=10.0)
            return super().read()
        finally:
            self.finished.set()


def test_a_keyring_waiting_on_a_prompt_never_blocks_the_connect_or_the_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from finishup.client import https_binding

    monkeypatch.setattr(https_binding, "_CREDENTIAL_READ_SECONDS", 0.2)
    gateway = _gateway()
    credential = _PromptingCredential()

    async def exercise() -> ControlError:
        connecting = asyncio.create_task(
            _connect(_transport(httpx.ASGITransport(app=gateway), credential=credential))
        )
        # The event loop keeps running while the key is read: this coroutine sees the read
        # begin, and the connect ends at the read's own bound.
        while not credential.reading.is_set():
            await asyncio.sleep(0.001)
        with pytest.raises(ControlError) as raised:
            await connecting
        return raised.value

    try:
        error = asyncio.run(exercise())
        # The loop closed while the prompt was still open: nothing waited for the read.
        assert not credential.finished.is_set()
    finally:
        credential.answered.set()
    assert (error.reason, error.retryable, error.phase) == (
        "service_unavailable",
        True,
        "remote_auth_failed",
    )
    assert gateway.requests == []
    assert credential.finished.wait(timeout=10.0)


def test_another_release_behind_the_gateway_is_remote_incompatible() -> None:
    from finishup.protocol.canonical import JsonValue, canonical_encode
    from finishup.service import control_protocol

    async def other_release(stream: ControlStream) -> None:
        await read_control_frame(stream)
        allowed = control_protocol._allowed_for(  # pyright: ignore[reportPrivateUsage]
            ControlClientKind.CLI
        )
        wire = control_protocol._hello_result_wire(  # pyright: ignore[reportPrivateUsage]
            service_status(), allowed
        )
        wire["schema_manifest_digest"] = "sha256:" + "0" * 64
        payload = canonical_encode(cast(JsonValue, wire))
        await stream.send_all(len(payload).to_bytes(4, "big") + payload)

    gateway = _gateway(other_release)

    async def exercise() -> ControlError:
        with pytest.raises(ControlError) as raised:
            await _connect(_transport(httpx.ASGITransport(app=gateway)))
        return raised.value

    error = asyncio.run(exercise())
    assert (error.reason, error.phase) == ("service_unavailable", "remote_incompatible")


def test_an_idle_expired_session_fails_the_write_so_the_caller_reconnects() -> None:
    from finishup.client.https_binding import SESSION_IDLE_CHECK_SECONDS, BindingControlStream

    gateway = _gateway()

    async def exercise() -> ControlError:
        client = await _connect(_transport(httpx.ASGITransport(app=gateway)))
        stream = cast(BindingControlStream, client._stream)  # pyright: ignore[reportPrivateUsage]
        # Idle past the check, and the gateway has expired the session meanwhile.
        stream._last_activity -= SESSION_IDLE_CHECK_SECONDS + 1  # pyright: ignore[reportPrivateUsage]
        gateway.sessions.clear()
        try:
            with pytest.raises(ControlError) as raised:
                await client.service_status()
        finally:
            await client.close()
        return raised.value

    error = asyncio.run(exercise())
    # Retryable ``service_unavailable`` is the class the MCP bridge's reconnect-once handles.
    assert (error.reason, error.retryable) == ("service_unavailable", True)
    paths = [(method, path) for method, path, _headers in gateway.requests]
    assert not any(path.endswith("/calls") for _method, path in paths)


def test_an_idle_live_session_is_checked_once_and_used() -> None:
    from finishup.client.https_binding import SESSION_IDLE_CHECK_SECONDS, BindingControlStream

    gateway = _gateway()

    async def exercise() -> None:
        client = await _connect(_transport(httpx.ASGITransport(app=gateway)))
        stream = cast(BindingControlStream, client._stream)  # pyright: ignore[reportPrivateUsage]
        stream._last_activity -= SESSION_IDLE_CHECK_SECONDS + 1  # pyright: ignore[reportPrivateUsage]
        try:
            await client.service_status()
            await client.service_status()
        finally:
            await client.close()

    asyncio.run(exercise())
    frames_checks = [path for _method, path, _h in gateway.requests if path.endswith("/frames")]
    assert len(frames_checks) == 1


@pytest.mark.parametrize(
    ("status", "phase"),
    [
        # The gateway expired or lost the session (a restart, its idle sweep).
        (404, "remote_unreachable"),
        # The key was revoked while the session lived.
        (401, "remote_auth_failed"),
        (503, "remote_service_not_running"),
    ],
)
def test_a_session_lost_under_a_call_is_a_retryable_remote_phase(status: int, phase: str) -> None:
    gateway = _gateway()

    async def exercise() -> tuple[ControlError, ControlError]:
        client = await _connect(_transport(httpx.ASGITransport(app=gateway)))
        gateway.statuses["POST calls"] = status
        try:
            with pytest.raises(ControlError) as raised:
                await client.service_status()
            # A later call on the closed connection names the same phase.
            with pytest.raises(ControlError) as later:
                await client.service_status()
        finally:
            await client.close()
        return raised.value, later.value

    # Never ``frame_invalid``: the request was valid, the call may have reached the server, and
    # the caller's reconnect-once replays the same request_id.
    for error in asyncio.run(exercise()):
        assert (error.reason, error.retryable, error.phase) == ("service_unavailable", True, phase)


def test_a_cancel_for_a_call_its_own_post_answered_is_never_sent() -> None:
    # The service refuses a cancel naming a call it already finished by closing the whole
    # connection, so a cancel that waited for its call's post is dropped once that post answered.
    from finishup.client.https_binding import BindingControlStream

    seen: list[str] = []

    async def exercise() -> None:
        received = asyncio.Event()
        release = asyncio.Event()

        async def strict_server(stream: ControlStream) -> None:
            session = await server_handshake(stream, stream.peer_identity, service_status())
            while True:
                try:
                    request = parse_control_request(
                        await read_control_frame(stream, eof_reason="session_closed")
                    )
                    seen.append(request.kind)
                    # As the daemon admits every frame: a cancel naming no active call fails.
                    session.admit(request)
                except Exception:
                    await stream.aclose()
                    return
                if isinstance(request, ControlCancelRequest):
                    continue
                received.set()
                await release.wait()
                result = ControlResult(
                    protocol_version="1.0",
                    rpc_id=request.rpc_id,
                    service_instance_id=session.service_instance_id,
                    service_generation=session.service_generation,
                    method=ControlMethod.SERVICE_STATUS,
                    outcome="ok",
                    body=service_status(),
                )
                session.correlate(result)
                await write_control_frame(stream, result)

        gateway = _gateway(strict_server)
        gateway.wait_cap_ms = 5_000  # the call's own post waits for its result
        client = await _connect(_transport(httpx.ASGITransport(app=gateway)))
        stream = cast(BindingControlStream, client._stream)  # pyright: ignore[reportPrivateUsage]
        try:
            caller = asyncio.create_task(client.service_status())
            await received.wait()
            # The caller gives up while the post is still waiting: the cancel waits for it.
            caller.cancel()
            await asyncio.gather(caller, return_exceptions=True)
            release.set()
            # Every request the stream started (the call's post, the cancel) has settled.
            await asyncio.gather(*tuple(stream._tasks))  # pyright: ignore[reportPrivateUsage]
            # The connection stays usable: the service never saw a cancel it would refuse.
            status = await client.service_status()
            assert status.service_instance_id == service_status().service_instance_id
        finally:
            await client.close()

    asyncio.run(exercise())
    assert seen == ["call", "call"]


class _HoldTheHello(httpx.AsyncBaseTransport):
    """A gateway that never answers the hello; ``delivered`` says whether its body went out."""

    def __init__(self, *, delivered: bool) -> None:
        self.delivered = delivered

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        trace = request.extensions.get("trace")
        if self.delivered and trace is not None:
            await trace("http11.send_request_body.complete", {})
        await asyncio.Event().wait()  # held: a service that is still starting, or a dead network
        raise AssertionError("unreachable")


@pytest.mark.parametrize(
    ("delivered", "phase"),
    [
        # The gateway holds a hello it received while it starts its service.
        (True, "remote_service_not_running"),
        # Nothing reached the server.
        (False, "remote_unreachable"),
    ],
)
def test_a_hello_held_past_the_budget_names_where_it_stopped(delivered: bool, phase: str) -> None:
    async def exercise() -> ControlError:
        with pytest.raises(ControlError) as raised:
            await client_module._connect_service_attempt(  # pyright: ignore[reportPrivateUsage]
                ControlClientKind.CLI,
                workspace_locator=None,
                projection_render_mode=ProjectionRenderMode.MACHINE_READABLE,
                output_is_controlling_tty=False,
                timeout_seconds=0.2,
                transport=_transport(_HoldTheHello(delivered=delivered)),
            )
        return raised.value

    error = asyncio.run(exercise())
    assert (error.reason, error.retryable, error.phase) == ("service_unavailable", True, phase)


@pytest.mark.parametrize(("kind", "bounded"), [("https", False), ("ssh", True)])
def test_an_https_hello_on_demand_may_take_the_whole_budget(
    monkeypatch: pytest.MonkeyPatch, kind: str, bounded: bool
) -> None:
    # The gateway starts an idle-stopped service while it holds the hello, so an HTTPS hello is
    # not cut at one handshake's 5 s; an SSH service is started explicitly instead.
    budgets: list[float] = []

    async def attempt(_kind: ControlClientKind, **kwargs: object) -> object:
        budgets.append(cast(float, kwargs["timeout_seconds"]))
        return object()

    class _Transport:
        target = https_target()

        @property
        def kind(self) -> str:
            return kind

    monkeypatch.setattr(client_module, "_connect_service_attempt", attempt)

    async def exercise() -> None:
        await client_module._connect_remote_on_demand(  # pyright: ignore[reportPrivateUsage]
            cast(Any, _Transport()),
            ControlClientKind.MCP_BRIDGE,
            workspace_locator=None,
            deadline=time.monotonic() + 20.0,
        )

    asyncio.run(exercise())
    (budget,) = budgets
    assert (budget <= 5.0) is bounded
    assert budget <= 20.0


class _LoseFirstCallResponse(httpx.AsyncBaseTransport):
    """Deliver the first call to the gateway, then lose its response on the way back."""

    def __init__(self, inner: httpx.AsyncBaseTransport) -> None:
        self.inner = inner
        self.lost = False

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        response = await self.inner.handle_async_request(request)
        if not self.lost and request.method == "POST" and request.url.path.endswith("/calls"):
            self.lost = True
            await response.aclose()
            raise httpx.ReadError("lost", request=request)
        return response


def test_a_lost_call_response_is_fetched_again_never_reposted() -> None:
    gateway = _gateway()
    lossy = _LoseFirstCallResponse(httpx.ASGITransport(app=gateway))

    async def exercise() -> None:
        client = await _connect(_transport(lossy))
        try:
            status = await client.service_status()
        finally:
            await client.close()
        assert status.service_instance_id == service_status().service_instance_id

    asyncio.run(exercise())
    assert lossy.lost
    paths = [(method, path) for method, path, _headers in gateway.requests]
    assert sum(1 for _method, path in paths if path.endswith("/calls")) == 1
    assert any(method == "GET" and "/results/" in path for method, path in paths)


def test_long_polls_carry_the_binding_wait_and_the_version_header() -> None:
    seen: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(401, json={"reason": "api_key_invalid", "schema_version": "1.0.0"})

    async def exercise() -> None:
        with pytest.raises(ControlError):
            await _connect(_transport(httpx.MockTransport(handler)))

    asyncio.run(exercise())
    (request,) = seen
    assert request.headers["authorization"] == f"Bearer {API_KEY}"
    assert request.headers["finishup-binding"] == "1.0"
    assert "origin" not in request.headers
    assert request.url.path == "/base/v1/sessions"
    assert LONG_POLL_WAIT_MS == 25_000


def test_server_info_checks_the_manifest_and_keeps_only_closed_values() -> None:
    gateway = _gateway()

    async def info() -> object:
        return await fetch_server_info(
            https_target(), API_KEY, http_transport=httpx.ASGITransport(app=gateway)
        )

    reported = asyncio.run(info())
    assert reported.schema_manifest_digest == gateway.digest  # type: ignore[attr-defined]

    gateway.digest = "sha256:" + "0" * 64
    with pytest.raises(TransportError) as raised:
        asyncio.run(info())
    assert raised.value.phase == "remote_incompatible"

    gateway.statuses["GET server"] = 401
    with pytest.raises(TransportError) as raised:
        asyncio.run(info())
    assert raised.value.phase == "remote_auth_failed"


def test_status_and_error_phases_are_closed() -> None:
    assert [phase_for_status(code) for code in (400, 401, 403, 404, 413, 429, 500, 503)] == [
        "remote_incompatible",
        "remote_auth_failed",
        "remote_auth_failed",
        "remote_unreachable",
        "remote_incompatible",
        "remote_unreachable",
        "remote_unreachable",
        "remote_service_not_running",
    ]
    nested = httpx.ConnectError("wrapped")
    nested.__cause__ = TlsPinMismatch("tls_pin_mismatch")
    assert phase_for_http_error(nested) == "remote_identity_changed"
    assert phase_for_http_error(httpx.ConnectTimeout("slow")) == "remote_unreachable"


# -- real TLS: the pin is checked inside the handshake, the CA file by ordinary verification ----


def _certificate(directory: Path, name: str) -> tuple[Path, Path, str]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path = directory / f"{name}.pem"
    key_path = directory / f"{name}.key"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    der = certificate.public_bytes(serialization.Encoding.DER)
    return cert_path, key_path, "sha256:" + hashlib.sha256(der).hexdigest()


async def _tls_info(target_for: Callable[[int], object], cert: Path, key: Path) -> list[bytes]:
    """Serve ``GET /v1/server`` over TLS once per connection; return what each connection read."""

    from finishup.protocol.schemas import schema_manifest_digest

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    received: list[bytes] = []

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        data = b""
        try:
            while b"\r\n\r\n" not in data:
                chunk = await reader.read(4096)
                if not chunk:
                    break
                data += chunk
        except (ConnectionError, ssl.SSLError):
            pass
        received.append(data)
        if data:
            body = json.dumps(
                {
                    "bindings": ["1.0"],
                    "release": "0.3.0",
                    "schema_manifest_digest": schema_manifest_digest(),
                }
            ).encode()
            writer.write(
                b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n"
                + f"content-length: {len(body)}\r\nconnection: close\r\n\r\n".encode()
                + body
            )
            await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=context)
    port = cast(int, server.sockets[0].getsockname()[1])
    try:
        await fetch_server_info(cast("object", target_for(port)), API_KEY)  # type: ignore[arg-type]
    finally:
        server.close()
        await server.wait_closed()
    return received


def test_a_matching_pin_connects_and_a_mismatch_sends_nothing() -> None:
    with tempfile.TemporaryDirectory(prefix="fu-tls-") as raw:
        cert, key, pin = _certificate(Path(raw), "server")
        _other, _other_key, other_pin = _certificate(Path(raw), "other")

        def pinned(value: str) -> Callable[[int], object]:
            return lambda port: replace(
                https_target(kind="local_port", tls_pin=value),
                base_url=f"https://127.0.0.1:{port}",
            )

        received = asyncio.run(_tls_info(pinned(pin), cert, key))
        assert len(received) == 1 and received[0].startswith(b"GET /v1/server HTTP/1.1")
        assert f"Bearer {API_KEY}".encode() in received[0]

        with pytest.raises(TransportError) as raised:
            asyncio.run(_tls_info(pinned(other_pin), cert, key))
        assert raised.value.phase == "remote_identity_changed"


def test_a_ca_file_verifies_the_server_and_refuses_another() -> None:
    with tempfile.TemporaryDirectory(prefix="fu-tls-") as raw:
        cert, key, _pin = _certificate(Path(raw), "server")
        other, _other_key, _other_pin = _certificate(Path(raw), "other")

        def trusting(ca: Path) -> Callable[[int], object]:
            return lambda port: replace(
                https_target(kind="local_port"),
                base_url=f"https://127.0.0.1:{port}",
                ca_file=str(ca),
            )

        received = asyncio.run(_tls_info(trusting(cert), cert, key))
        assert len(received) == 1 and received[0].startswith(b"GET /v1/server")

        with pytest.raises(TransportError) as raised:
            asyncio.run(_tls_info(trusting(other), cert, key))
        assert raised.value.phase == "remote_identity_changed"
