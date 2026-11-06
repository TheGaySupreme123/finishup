"""The gateway in front of the real in-memory ``ServiceDaemon`` (ADR-051, approach A).

The daemon from the existing client harness (``test_daemon_clients``: real control loop,
handshake, client-kind gate, dispatch and projection; fake application and vault) serves each
gateway session's upstream connection. An MCP-bridge hello opens a session, and a ``start``
through the HTTPS binding reaches the daemon's real dispatch and returns its control-result.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest

from builders.control_relay import memory_pair
from builders.server_targets import ambient_home
from finishup.gateway.app import build_gateway_app
from finishup.gateway.keys import create_key
from finishup.ports.control import ControlCallRequest, ControlMethod
from finishup.protocol.canonical import JsonValue
from finishup.protocol.schemas import load_schema_catalog, validate_schema_instance
from finishup.service.control_protocol import encode_control_frame
from integration.service.test_daemon_clients import (  # pyright: ignore[reportPrivateUsage]
    _daemon,  # pyright: ignore[reportPrivateUsage]
    _start_body,  # pyright: ignore[reportPrivateUsage]
)


class _Audit:
    def write(self, record: dict[str, JsonValue]) -> None:
        del record


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as root:
        yield root


def test_a_start_through_the_gateway_reaches_the_real_daemon(home: Path) -> None:
    async def exercise() -> None:
        daemon, application, _vault, _listener = _daemon()
        await daemon.start()
        served: list[asyncio.Task[None]] = []

        async def connect_upstream() -> object:
            client, server = memory_pair()
            served.append(
                asyncio.create_task(daemon._serve_control_connection(server))  # pyright: ignore[reportPrivateUsage,reportArgumentType]
            )
            return client

        keys = home / "gateway"
        _record, key = create_key(keys, label="real", scope="agent")
        _state, app = build_gateway_app(
            keys_directory=keys,
            connect_upstream=connect_upstream,  # type: ignore[arg-type]
            audit=_Audit(),
        )
        headers = {"Authorization": f"Bearer {key}", "FinishUP-Binding": "1.0"}
        hello: dict[str, JsonValue] = {
            "protocol_version": "1.0",
            "client_kind": "mcp_bridge",
            "client_version": "0.1.0",
            "connection_nonce": "7a" * 32,
            "schema_manifest_digest": load_schema_catalog().manifest_digest,
        }
        try:
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="https://gw.example"
            ) as client:
                opened = await client.post(
                    "/v1/sessions", content=encode_control_frame(hello)[4:], headers=headers
                )
                assert opened.status_code == 201, opened.content
                answer = json.loads(opened.content)
                validate_schema_instance("control-hello-result", "2.10.0", answer)
                assert answer["workspace_binding"] == "none"
                session = opened.headers["Location"]
                instance = daemon.composition.lifecycle.instance
                start = ControlCallRequest(
                    kind="call",
                    protocol_version="1.0",
                    rpc_id="rpc_00000000-0000-4000-8000-0000000000b1",
                    service_instance_id=instance.instance_id,
                    service_generation=str(instance.generation),
                    method=ControlMethod.START,
                    body=_start_body(),
                )
                started = await client.post(
                    f"{session}/calls?wait_ms=10000",
                    content=encode_control_frame(start)[4:],
                    headers=headers,
                )
                assert started.status_code == 200, started.content
                result = json.loads(started.content)
                validate_schema_instance("control-result", "2.10.0", result)
                assert result["outcome"] == "ok" and result["method"] == "start"
                assert application.start_calls == 1
                closed = await client.delete(session, headers=headers)
                assert closed.status_code == 204
        finally:
            for task in served:
                task.cancel()
            await asyncio.gather(*served, return_exceptions=True)
            await daemon.close()

    asyncio.run(exercise())
