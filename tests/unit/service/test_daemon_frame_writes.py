"""A control connection never carries a frame spliced onto one a write cut off (ADR-051).

Control results and workspace calls share one connection. A write that a timeout or a
cancellation interrupts may leave part of a frame on the stream; whatever is written next would
be read as the rest of it. The daemon's ``_FrameWrites`` ends such a connection's write side
instead, so the peer reads the end of the stream, never a spliced frame.
"""

from __future__ import annotations

import asyncio
import socket
from collections.abc import Awaitable, Callable, Iterator

import pytest

from finishup.adapters.control.unix_socket import LocalControlTransportError
from finishup.service import daemon as daemon_module
from finishup.service.control_protocol import ControlProtocolError

pytestmark = pytest.mark.anyio

_FrameWrites = getattr(daemon_module, "_FrameWrites")


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class _SocketStream:
    """A minimal control stream over one end of a socket pair."""

    def __init__(self, raw: socket.socket) -> None:
        raw.setblocking(False)
        self.raw = raw
        self.peer_identity = object()
        self.shut = False

    async def receive(self, max_bytes: int) -> bytes:
        return await asyncio.get_running_loop().sock_recv(self.raw, max_bytes)

    async def send_all(self, data: memoryview | bytes) -> None:
        try:
            await asyncio.get_running_loop().sock_sendall(self.raw, data)
        except OSError as exc:
            raise LocalControlTransportError("connection_failed") from exc

    async def shutdown_write(self) -> None:
        self.shut = True
        self.raw.shutdown(socket.SHUT_WR)

    async def aclose(self) -> None:
        self.raw.close()


@pytest.fixture
def pair() -> Iterator[tuple[_SocketStream, _SocketStream]]:
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    for end in (left, right):
        end.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        end.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    streams = (_SocketStream(left), _SocketStream(right))
    try:
        yield streams
    finally:
        left.close()
        right.close()


def _frame(size: int) -> bytes:
    """A length-prefixed frame of ``size`` body bytes, as the control framing writes one."""

    return size.to_bytes(4, "big") + b"x" * size


def _writer(stream: _SocketStream, size: int) -> Callable[[], Awaitable[None]]:
    return lambda: stream.send_all(_frame(size))


async def _drain(stream: _SocketStream) -> bytes:
    """Everything the peer can read until the end of the stream."""

    received = bytearray()
    while True:
        chunk = await asyncio.wait_for(stream.receive(65_536), 5.0)
        if not chunk:
            return bytes(received)
        received.extend(chunk)


async def test_a_write_cut_off_by_its_deadline_ends_the_connection_rather_than_splice(
    pair: tuple[_SocketStream, _SocketStream], monkeypatch: pytest.MonkeyPatch
) -> None:
    server, client = pair
    monkeypatch.setattr(daemon_module, "_CONTROL_RESPONSE_WRITE_DEADLINE_SECONDS", 0.2)
    writes = _FrameWrites()
    # The peer is not reading: a 1 MiB frame cannot be written whole within the deadline.
    with pytest.raises(TimeoutError):
        await writes.write(server, _writer(server, 1 << 20))
    assert writes.out_of_step and server.shut
    # No later frame is ever written on that stream.
    with pytest.raises(LocalControlTransportError):
        await writes.write(server, _writer(server, 16))
    # The peer reads the torn frame's start, then the end of the stream: never a spliced frame.
    received = await _drain(client)
    assert 0 < len(received) < len(_frame(1 << 20))
    assert received == _frame(1 << 20)[: len(received)]


async def test_a_cancelled_write_also_ends_the_connection(
    pair: tuple[_SocketStream, _SocketStream],
) -> None:
    server, _client = pair
    writes = _FrameWrites()
    pending = asyncio.create_task(writes.write(server, _writer(server, 1 << 20)))
    await asyncio.sleep(0.1)
    pending.cancel()
    with pytest.raises(asyncio.CancelledError):
        await pending
    assert writes.out_of_step and server.shut


async def test_whole_frames_keep_the_connection_in_step(
    pair: tuple[_SocketStream, _SocketStream],
) -> None:
    server, client = pair
    writes = _FrameWrites()
    for size in (16, 32):
        await writes.write(server, _writer(server, size))
    await server.shutdown_write()
    assert await _drain(client) == _frame(16) + _frame(32)
    assert not writes.out_of_step


async def test_a_frame_refused_before_any_byte_is_written_keeps_the_connection(
    pair: tuple[_SocketStream, _SocketStream],
) -> None:
    server, _client = pair
    writes = _FrameWrites()

    async def unencodable() -> None:
        raise ControlProtocolError("frame_invalid")

    with pytest.raises(ControlProtocolError):
        await writes.write(server, unencodable)
    assert not writes.out_of_step and not server.shut
