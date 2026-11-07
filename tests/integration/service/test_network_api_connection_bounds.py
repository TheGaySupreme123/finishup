"""What an unauthenticated TCP peer can hold on the network API's listeners (ADR-051).

The service that holds the vault is the network edge, so its TCP listeners bound connections
before any key is checked: a cap in total and per peer address (a connection over either is
closed before TLS or a byte is read), a deadline from acceptance (TLS included) to a complete
request head, and one for a request's body. A request being answered, such as a long-poll, is
never cut. Every wait here observes the socket itself and ends on a deadline.
"""

from __future__ import annotations

import asyncio
import contextlib
import resource
import shutil
import ssl
from collections.abc import AsyncGenerator
from pathlib import Path

import pytest

import finishup.service.http_api as http_api
from builders.network_api import FakeService, key_store
from finishup.config.models import ConfigError, NetworkListenAddress
from finishup.service.api_keys import ApiKeyStore
from finishup.service.http_api import NetworkApiBindings, NetworkApiServer

_EOF_DEADLINE = 10.0


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _bindings(service: FakeService) -> NetworkApiBindings:
    return NetworkApiBindings(
        status=service.status, dispatch=service.dispatch, activity=service.activity
    )


@contextlib.asynccontextmanager
async def _serving(
    service: FakeService,
    *,
    limits: tuple[int, int] = (8, 8),
    tls: ssl.SSLContext | None = None,
) -> AsyncGenerator[tuple[NetworkApiServer, int]]:
    keys = key_store()
    server = NetworkApiServer.bind_addresses(
        (NetworkListenAddress("127.0.0.1", 0),),
        keys=keys,
        tls=tls,
        runtime=None,
        tcp_limits=limits,
    )
    await server.start(_bindings(service))
    try:
        yield server, server.tcp_ports[0]
    finally:
        await server.close()
        _discard(keys)


def _discard(keys: ApiKeyStore) -> None:
    shutil.rmtree(keys.path.parent.parent, ignore_errors=True)


async def _closed_by_server(reader: asyncio.StreamReader) -> bool:
    """Whether the server closed the connection (EOF or reset) before the deadline."""

    try:
        async with asyncio.timeout(_EOF_DEADLINE):
            while True:
                chunk = await reader.read(65_536)
                if not chunk:
                    return True
    except (ConnectionResetError, BrokenPipeError):
        return True
    except TimeoutError:
        return False


async def _until(predicate: object, *, deadline: float = _EOF_DEADLINE) -> None:
    async with asyncio.timeout(deadline):
        while not predicate():  # type: ignore[operator]
            await asyncio.sleep(0.01)


@pytest.mark.anyio
async def test_connections_over_the_per_peer_cap_are_closed_before_a_byte_is_read() -> None:
    async with _serving(FakeService(), limits=(8, 2)) as (server, port):
        held = [await asyncio.open_connection("127.0.0.1", port) for _ in range(2)]
        await _until(lambda: server.open_tcp_connections == 2)
        _reader, writer = await asyncio.open_connection("127.0.0.1", port)
        assert await _closed_by_server(_reader)
        assert server.open_tcp_connections == 2
        writer.close()
        # Closing a held connection frees its place for the next one.
        held[0][1].close()
        await _until(lambda: server.open_tcp_connections == 1)
        again = await asyncio.open_connection("127.0.0.1", port)
        await _until(lambda: server.open_tcp_connections == 2)
        for _reader, each in (*held[1:], again):
            each.close()
        await _until(lambda: server.open_tcp_connections == 0)


@pytest.mark.anyio
async def test_the_total_cap_holds_across_peers() -> None:
    async with _serving(FakeService(), limits=(1, 1)) as (server, port):
        _first = await asyncio.open_connection("127.0.0.1", port)
        await _until(lambda: server.open_tcp_connections == 1)
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        assert await _closed_by_server(reader)
        writer.close()
        _first[1].close()


@pytest.mark.anyio
async def test_a_connection_without_a_request_head_is_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(http_api, "REQUEST_HEAD_SECONDS", 0.2)
    async with _serving(FakeService()) as (server, port):
        # Nothing at all, then half a request head: both are closed on the head deadline.
        idle_reader, idle = await asyncio.open_connection("127.0.0.1", port)
        slow_reader, slow = await asyncio.open_connection("127.0.0.1", port)
        slow.write(b"GET /v1/server HTTP/1.1\r\nhost: x\r\n")
        await slow.drain()
        assert await _closed_by_server(idle_reader)
        assert await _closed_by_server(slow_reader)
        await _until(lambda: server.open_tcp_connections == 0)
        idle.close()
        slow.close()


@pytest.mark.anyio
async def test_an_answered_connection_owes_its_next_head_on_the_same_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(http_api, "REQUEST_HEAD_SECONDS", 0.3)
    monkeypatch.setattr(http_api, "REQUEST_BODY_SECONDS", 0.3)
    async with _serving(FakeService()) as (server, port):
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"GET /v1/server HTTP/1.1\r\nhost: x\r\n\r\n")
        await writer.drain()
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=_EOF_DEADLINE)
        assert head.startswith(b"HTTP/1.1 401")
        # A trickled next head holds the connection no longer than a first one.
        writer.write(b"GET /v1/ser")
        await writer.drain()
        assert await _closed_by_server(reader)
        writer.close()
        # A body that stops short is closed on the body deadline.
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"POST /v1/status HTTP/1.1\r\nhost: x\r\ncontent-length: 100\r\n\r\n{")
        await writer.drain()
        assert await _closed_by_server(reader)
        writer.close()
        await _until(lambda: server.open_tcp_connections == 0)


@pytest.mark.anyio
async def test_a_request_being_answered_is_never_cut(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(http_api, "REQUEST_HEAD_SECONDS", 0.2)
    gate = asyncio.Event()
    service = FakeService(gate=gate)
    keys = key_store()
    _record, token = keys.create("laptop", "agent")
    server = NetworkApiServer.bind_addresses(
        (NetworkListenAddress("127.0.0.1", 0),),
        keys=keys,
        tls=None,
        runtime=None,
        tcp_limits=(8, 8),
    )
    await server.start(_bindings(service))
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", server.tcp_ports[0])
        writer.write(
            b"POST /v1/service_status?wait_ms=5000 HTTP/1.1\r\nhost: x\r\n"
            b"authorization: Bearer " + token.encode("ascii") + b"\r\n"
            b"content-length: 2\r\n\r\n{}"
        )
        await writer.drain()
        await _until(lambda: service.active == 1)
        # Well past the head deadline, the call is still being answered on this connection.
        loop = asyncio.get_running_loop()
        waited = loop.time() + 0.6
        await _until(lambda: loop.time() >= waited)
        assert server.open_tcp_connections == 1
        gate.set()
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=_EOF_DEADLINE)
        assert head.startswith(b"HTTP/1.1 200")
        writer.close()
    finally:
        await server.close()
        _discard(keys)


@pytest.mark.anyio
async def test_a_tls_handshake_that_never_comes_is_closed_and_frees_its_place(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tests.integration.service.test_network_api_listeners import (
        _certificate_authority,  # pyright: ignore[reportPrivateUsage]
    )

    monkeypatch.setattr(http_api, "REQUEST_HEAD_SECONDS", 0.2)
    tmp_path.chmod(0o700)
    _ca, cert, key, _pin = _certificate_authority(tmp_path)
    context = http_api._tls_context(str(cert), str(key))  # pyright: ignore[reportPrivateUsage]
    async with _serving(FakeService(), limits=(1, 1), tls=context) as (server, port):
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await _until(lambda: server.open_tcp_connections == 1)
        assert await _closed_by_server(reader)
        await _until(lambda: server.open_tcp_connections == 0)
        writer.close()
        # The freed place serves a real TLS client.
        client = ssl.create_default_context()
        client.check_hostname = False
        client.verify_mode = ssl.CERT_NONE
        reader, writer = await asyncio.open_connection("127.0.0.1", port, ssl=client)
        writer.write(b"GET /v1/server HTTP/1.1\r\nhost: x\r\n\r\n")
        await writer.drain()
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=_EOF_DEADLINE)
        assert head.startswith(b"HTTP/1.1 401")
        writer.close()


def test_the_descriptor_budget_raises_the_soft_limit_and_keeps_most_of_it() -> None:
    infinity = resource.RLIM_INFINITY
    raised: list[tuple[int, int]] = []

    def put(_which: int, value: tuple[int, int]) -> None:
        raised.append(value)

    budget = http_api._tcp_connection_budget  # pyright: ignore[reportPrivateUsage]
    # macOS's usual soft limit, raised toward the target: the full caps fit in a quarter.
    assert budget(getrlimit=lambda _which: (256, infinity), setrlimit=put) == (256, 64)
    assert raised == [(4_096, infinity)]
    # A hard limit bounds the raise, and the caps shrink with it.
    raised.clear()
    assert budget(getrlimit=lambda _which: (256, 512), setrlimit=put) == (128, 64)
    assert raised == [(512, 512)]

    def refuse(_which: int, _value: tuple[int, int]) -> None:
        raise ValueError("not permitted")

    # A limit that cannot be raised keeps three quarters of what there is for everything else.
    assert budget(getrlimit=lambda _which: (128, 128), setrlimit=refuse) == (32, 32)
    assert budget(getrlimit=lambda _which: (8_192, infinity), setrlimit=refuse) == (256, 64)


def test_an_http_stack_the_service_cannot_drive_fails_the_start_with_a_closed_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import uvicorn

    def incompatible(*_args: object, **_kwargs: object) -> object:
        raise TypeError("unexpected keyword argument")

    monkeypatch.setattr(uvicorn, "Config", incompatible)
    keys = key_store()
    try:
        with pytest.raises(ConfigError) as raised:
            NetworkApiServer.bind_addresses(
                (NetworkListenAddress("127.0.0.1", 0),),
                keys=keys,
                tls=None,
                runtime=None,
                tcp_limits=(8, 8),
            )
        assert raised.value.reason_code == "network_listener_unavailable"
    finally:
        _discard(keys)


def test_tls_is_the_listeners_own_so_no_newer_uvicorn_keyword_is_used(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import uvicorn

    seen: list[set[str]] = []
    real = uvicorn.Config

    def recording(*args: object, **kwargs: object) -> object:
        seen.append(set(kwargs))
        return real(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(uvicorn, "Config", recording)
    keys = key_store()
    try:
        server = NetworkApiServer.bind_addresses(
            (NetworkListenAddress("127.0.0.1", 0),),
            keys=keys,
            tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER),
            runtime=None,
            tcp_limits=(8, 8),
        )
        asyncio.run(server.close())
    finally:
        _discard(keys)
    # uvicorn 0.31.1 (the floor the MCP SDK allows) accepts every keyword used here; the TLS
    # keywords added later (``ssl_context_factory``) are never passed.
    assert seen and all(not {"ssl_context_factory", "ssl_certfile"} & used for used in seen)
