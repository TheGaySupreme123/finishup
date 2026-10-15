"""Descriptor fault schedules for the bounded MCP stdio transport."""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import errno
import os
import signal
import subprocess
import sys

import anyio
import pytest
from anyio.abc import ObjectSendStream
from anyio.lowlevel import checkpoint
from mcp.shared.message import SessionMessage

import finishup.adapters.mcp_stdio as transport


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
@pytest.mark.parametrize(
    "schedule",
    [
        ("eintr", 1, 1, 1, 1, 1, 1, 1, 1),
        (2, "eintr", 3, 1, 8),
        (1, 4, 2, 16),
    ],
)
async def test_write_all_retries_eintr_and_every_partial_write(
    monkeypatch: pytest.MonkeyPatch,
    schedule: tuple[int | str, ...],
) -> None:
    calls: list[bytes] = []
    output = bytearray()
    pending = list(schedule)

    async def writable(fd: int) -> None:
        assert fd == 17

    def write(fd: int, payload: bytes) -> int:
        assert fd == 17
        calls.append(payload)
        action = pending.pop(0) if pending else len(payload)
        if action == "eintr":
            raise InterruptedError(errno.EINTR, "hostile hidden detail")
        assert type(action) is int
        written = min(action, len(payload))
        output.extend(payload[:written])
        return written

    monkeypatch.setattr(transport.anyio, "wait_writable", writable)
    monkeypatch.setattr(transport, "_write_fd", write)

    await transport._write_all(17, b'{"id":1}')

    assert bytes(output) == b'{"id":1}\n'
    assert len(calls) >= 2


_HOME_LEAK = "/" + "Users/private"


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("failure", "reason"),
    [
        (OSError(errno.EIO, "secret " + _HOME_LEAK + "/input.json"), "write_failed"),
        (BrokenPipeError(errno.EPIPE, "secret " + _HOME_LEAK + "/client.pipe"), "broken_pipe"),
    ],
)
async def test_write_failure_is_bounded_and_never_contains_os_detail(
    monkeypatch: pytest.MonkeyPatch,
    failure: OSError,
    reason: str,
) -> None:
    async def writable(fd: int) -> None:
        assert fd == 18

    def write(fd: int, payload: bytes) -> int:
        del fd, payload
        raise failure

    monkeypatch.setattr(transport.anyio, "wait_writable", writable)
    monkeypatch.setattr(transport, "_write_fd", write)

    with pytest.raises(transport.TransportFailure) as caught:
        await transport._write_all(18, b"{}")

    assert caught.value.reason == reason
    assert str(caught.value) == reason
    assert _HOME_LEAK not in repr(caught.value)


@pytest.mark.anyio
async def test_reader_retries_eintr_and_forwards_only_complete_frame(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    chunks: list[bytes | BaseException] = [
        InterruptedError(errno.EINTR, "hidden"),
        b'{"jsonrpc":"2.0",',
        b'"id":7,"method":"ping"}\n',
        b"",
    ]

    async def readable(fd: int) -> None:
        assert fd == 19

    def read(fd: int, maximum: int) -> bytes:
        assert fd == 19
        assert maximum <= transport._MAX_READ_CHUNK
        value = chunks.pop(0)
        if isinstance(value, BaseException):
            raise value
        return value

    monkeypatch.setattr(transport.anyio, "wait_readable", readable)
    monkeypatch.setattr(transport, "_read_fd", read)
    inbound_send, inbound_receive = anyio.create_memory_object_stream[SessionMessage](1)
    item_send, item_receive = anyio.create_memory_object_stream[transport._WriterItem](1)

    await transport._reader(19, 512, inbound_send, item_send)
    message = await inbound_receive.receive()

    assert message.message.model_dump(by_alias=True)["id"] == 7
    with pytest.raises(anyio.EndOfStream):
        await inbound_receive.receive()
    await item_receive.aclose()


@pytest.mark.anyio
async def test_reader_never_requests_more_than_64_kib(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requested: list[int] = []

    async def readable(fd: int) -> None:
        assert fd == 23

    def read(fd: int, maximum: int) -> bytes:
        assert fd == 23
        requested.append(maximum)
        return b""

    monkeypatch.setattr(transport.anyio, "wait_readable", readable)
    monkeypatch.setattr(transport, "_read_fd", read)
    inbound_send, inbound_receive = anyio.create_memory_object_stream[SessionMessage](1)
    item_send, item_receive = anyio.create_memory_object_stream[transport._WriterItem](1)

    await transport._reader(
        23,
        transport.MAX_JSON_FRAME_BYTES,
        inbound_send,
        item_send,
    )

    assert requested == [65_536]
    await inbound_receive.aclose()
    await item_receive.aclose()


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("chunks", "reason"),
    [
        ([b'{"jsonrpc":"2.0"', b""], "partial_eof"),
        ([OSError(errno.EIO, "secret /tmp/hostile-frame")], "read_failed"),
    ],
)
async def test_partial_eof_and_read_failure_are_bounded_stream_termination(
    monkeypatch: pytest.MonkeyPatch,
    chunks: list[bytes | BaseException],
    reason: str,
) -> None:
    async def readable(fd: int) -> None:
        assert fd == 20

    def read(fd: int, maximum: int) -> bytes:
        del fd, maximum
        value = chunks.pop(0)
        if isinstance(value, BaseException):
            raise value
        return value

    monkeypatch.setattr(transport.anyio, "wait_readable", readable)
    monkeypatch.setattr(transport, "_read_fd", read)
    inbound_send, inbound_receive = anyio.create_memory_object_stream[SessionMessage](1)
    item_send, item_receive = anyio.create_memory_object_stream[transport._WriterItem](1)

    with pytest.raises(transport.TransportFailure) as caught:
        await transport._reader(20, 512, inbound_send, item_send)

    assert caught.value.reason == reason
    assert str(caught.value) == reason
    assert "secret" not in repr(caught.value)
    with pytest.raises(anyio.EndOfStream):
        await inbound_receive.receive()
    await item_receive.aclose()


@pytest.mark.anyio
async def test_zero_capacity_writer_queue_backpressures_second_frame(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    blocked = anyio.Event()
    release = anyio.Event()
    first_sent = anyio.Event()
    second_started = anyio.Event()
    second_sent = anyio.Event()
    writes: list[bytes] = []

    async def writable(fd: int) -> None:
        assert fd == 21
        blocked.set()
        await release.wait()

    def write(fd: int, payload: bytes) -> int:
        assert fd == 21
        writes.append(payload)
        return len(payload)

    async def produce(send: ObjectSendStream[transport._WriterItem]) -> None:
        async with send:
            await send.send(transport._WriterItem(b'{"id":1}'))
            first_sent.set()
            second_started.set()
            await send.send(transport._WriterItem(b'{"id":2}'))
            second_sent.set()

    monkeypatch.setattr(transport.anyio, "wait_writable", writable)
    monkeypatch.setattr(transport, "_write_fd", write)
    send, receive = anyio.create_memory_object_stream[transport._WriterItem](0)

    async with anyio.create_task_group() as tasks:
        tasks.start_soon(transport._writer, 21, 512, receive)
        tasks.start_soon(produce, send)
        await first_sent.wait()
        await second_started.wait()
        await blocked.wait()
        await checkpoint()
        assert not second_sent.is_set()
        release.set()

    assert b"".join(writes) == b'{"id":1}\n{"id":2}\n'


@pytest.mark.anyio
async def test_cancellation_while_waiting_to_write_is_not_converted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entered = anyio.Event()
    never = anyio.Event()
    write_called = False

    async def writable(fd: int) -> None:
        assert fd == 22
        entered.set()
        await never.wait()

    def write(fd: int, payload: bytes) -> int:
        nonlocal write_called
        del fd, payload
        write_called = True
        return 1

    monkeypatch.setattr(transport.anyio, "wait_writable", writable)
    monkeypatch.setattr(transport, "_write_fd", write)

    async with anyio.create_task_group() as tasks:
        tasks.start_soon(transport._write_all, 22, b"{}")
        await entered.wait()
        tasks.cancel_scope.cancel()

    assert not write_called


def test_sigterm_while_idle_emits_no_partial_frame_or_traceback() -> None:
    child = r"""
import anyio
import sys
from finishup.adapters.mcp_stdio import bounded_stdio_server

async def main():
    async with bounded_stdio_server(512) as (read_stream, write_stream):
        print("READY", file=sys.stderr, flush=True)
        async with write_stream:
            async for message in read_stream:
                await write_stream.send(message)

anyio.run(main)
"""
    environment = dict(os.environ)
    environment["PYTHONPATH"] = os.pathsep.join(("tests", "tests/subprocess", "src"))
    process = subprocess.Popen(
        [sys.executable, "-I", "-c", child],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
    )
    assert process.stderr is not None
    assert process.stderr.readline() == b"READY\n"
    process.send_signal(signal.SIGTERM)
    stdout, stderr = process.communicate(timeout=5)

    assert process.returncode == -signal.SIGTERM
    assert stdout == b""
    assert b"Traceback" not in stderr
