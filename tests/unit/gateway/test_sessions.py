"""Gateway session bounds hold under concurrency (ADR-051, approach A)."""

from __future__ import annotations

import asyncio

import pytest

from builders.control_relay import MemoryStream, ScriptedDaemon, memory_pair
from finishup.gateway.sessions import SessionLimit, SessionRegistry
from finishup.protocol.canonical import JsonValue
from finishup.protocol.schemas import load_schema_catalog
from finishup.service.control_protocol import (
    ControlFrame,
    ControlProtocolError,
    ControlStream,
    decode_control_frame,
    encode_control_frame,
)


def _hello() -> tuple[ControlFrame, bytes]:
    hello: dict[str, JsonValue] = {
        "protocol_version": "1.0",
        "client_kind": "cli",
        "client_version": "0.1.0",
        "connection_nonce": "8a" * 32,
        "schema_manifest_digest": load_schema_catalog().manifest_digest,
    }
    encoded = encode_control_frame(hello)
    return decode_control_frame(encoded), encoded[4:]


def test_concurrent_opens_of_one_key_cannot_pass_its_bound_together() -> None:
    """Each open awaits the daemon's connect and hello before it registers, so the bound must
    count opens in flight; otherwise every concurrent open sees room."""

    async def exercise() -> None:
        daemon = ScriptedDaemon()
        release = asyncio.Event()
        connected: list[asyncio.Task[None]] = []

        async def connect_upstream() -> ControlStream:
            await release.wait()  # the daemon is slow to accept
            client, server = memory_pair()
            connected.append(asyncio.create_task(daemon.serve(server)))
            return client

        registry = SessionRegistry(connect_upstream, per_key=2)
        hello, payload = _hello()
        digest = load_schema_catalog().manifest_digest

        async def open_one(key_id: str) -> str:
            try:
                await registry.open(
                    key_id=key_id,
                    scope="agent",
                    hello=hello,
                    hello_payload=payload,
                    manifest_digest=digest,
                )
            except SessionLimit:
                return "limit"
            return "opened"

        opening = [asyncio.create_task(open_one("k_one")) for _ in range(5)]
        other = asyncio.create_task(open_one("k_two"))
        await asyncio.sleep(0)
        release.set()
        outcomes = await asyncio.gather(*opening)
        assert sorted(outcomes) == ["limit", "limit", "limit", "opened", "opened"]
        assert await other == "opened"  # another key's bound is its own
        assert len(connected) == 3 and daemon.connections == 3
        assert registry.count_for("k_one") == 2
        await registry.close_all()
        assert registry.count_for("k_one") == 0
        await asyncio.gather(*connected, return_exceptions=True)

    asyncio.run(exercise())


def test_a_failed_open_gives_its_place_back() -> None:
    async def exercise() -> None:
        async def unreachable() -> ControlStream:
            raise OSError("daemon_down")

        registry = SessionRegistry(unreachable, per_key=1)
        hello, payload = _hello()
        for _attempt in range(3):
            with pytest.raises(OSError):
                await registry.open(
                    key_id="k_one",
                    scope="agent",
                    hello=hello,
                    hello_payload=payload,
                    manifest_digest=load_schema_catalog().manifest_digest,
                )
        assert registry.count_for("k_one") == 0

    asyncio.run(exercise())


def test_a_daemon_that_never_answers_the_hello_gives_the_place_back() -> None:
    """A daemon that accepted the connection and never answers (a wedged holder) must not hold
    the open, or its place against the key's bound, forever: the open fails within the hello
    deadline and its upstream is closed."""

    async def exercise() -> None:
        wedged: list[MemoryStream] = []

        async def connect_upstream() -> ControlStream:
            client, server = memory_pair()
            wedged.append(server)  # accepted, never answered
            return client

        registry = SessionRegistry(connect_upstream, per_key=1, hello_result_seconds=0.05)
        hello, payload = _hello()
        for _attempt in range(2):  # the second would be ``SessionLimit`` if the place leaked
            async with asyncio.timeout(5):
                with pytest.raises(ControlProtocolError):
                    await registry.open(
                        key_id="k_one",
                        scope="agent",
                        hello=hello,
                        hello_payload=payload,
                        manifest_digest=load_schema_catalog().manifest_digest,
                    )
            assert registry.count_for("k_one") == 0
        assert len(registry) == 0 and len(wedged) == 2
        for server in wedged:
            # The daemon's end got the hello, then the end of the stream.
            received = bytearray()
            async with asyncio.timeout(5):
                while chunk := await server.receive(65_536):
                    received.extend(chunk)
            assert bytes(received) == len(payload).to_bytes(4, "big") + payload

    asyncio.run(exercise())
