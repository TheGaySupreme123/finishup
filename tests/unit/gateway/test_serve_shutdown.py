"""Stopping the gateway answers every open long-poll at once (ADR-051, approach A).

A connector keeps a frames long-poll open for up to 25 s. Found in the real-environment run: a
SIGTERM to ``finishup service gateway run`` sat out uvicorn's graceful wait and then cancelled the
open poll with an ``Exception in ASGI application`` traceback. ``gateway_server`` closes the
gateway's sessions first, so the poll is answered, the server exits well inside the graceful
timeout and nothing is cancelled.
"""

from __future__ import annotations

import asyncio
import datetime
import ipaddress
import logging
import socket
import ssl
import time
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from builders.control_relay import CLAIM_DIGEST, WORKTREE_DIGEST, ScriptedDaemon, memory_pair
from builders.server_targets import ambient_home
from finishup.gateway.app import build_gateway_app
from finishup.gateway.keys import create_key
from finishup.gateway.serve import gateway_server
from finishup.protocol.canonical import JsonValue
from finishup.protocol.schemas import load_schema_catalog
from finishup.service.control_protocol import encode_control_frame

_GRACEFUL_SECONDS = 5


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as root:
        yield root


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _certificate(directory: Path) -> tuple[Path, Path]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "finishup-gateway-test")])
    now = datetime.datetime.now(datetime.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
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
    cert_path = directory / "gateway.pem"
    key_path = directory / "gateway-key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    return cert_path, key_path


def _agent_hello() -> bytes:
    hello: dict[str, JsonValue] = {
        "protocol_version": "1.0",
        "client_kind": "cli",
        "client_version": "0.1.0",
        "connection_nonce": "3f" * 32,
        "schema_manifest_digest": load_schema_catalog().manifest_digest,
        "workspace_claim": {
            "schema_version": "1.0.0",
            "identity_kind": "directory",
            "digest": CLAIM_DIGEST,
            "worktree": WORKTREE_DIGEST,
        },
        "workspace_agent": {
            "schema_version": "1.0.0",
            "operations": ["read_task_base"],
            "max_reply_bytes": 65_536,
        },
    }
    return encode_control_frame(hello)[4:]


@pytest.mark.parametrize("tls", [False, True], ids=["http", "tls"])
def test_a_stop_answers_the_open_long_poll_and_cancels_nothing(
    home: Path, caplog: pytest.LogCaptureFixture, tls: bool
) -> None:
    """Over TLS an idle keep-alive connection must not hold the stop open either.

    A client that keeps an idle pooled connection never answers the server's TLS close, so a
    plain close waited out the whole graceful timeout and logged ``Cancel 0 running task(s)``.
    """

    keys = home / "gateway"
    cert, key_file = _certificate(home) if tls else (None, None)
    _record, api_key = create_key(keys, label="agent", scope="agent")
    port = _free_port()
    headers = {"Authorization": f"Bearer {api_key}", "FinishUP-Binding": "1.0"}

    class _Audit:
        def write(self, record: dict[str, JsonValue]) -> None:
            del record

    async def exercise() -> tuple[int, float]:
        daemon = ScriptedDaemon()
        served: list[asyncio.Task[None]] = []

        async def connect_upstream() -> object:
            client, server = memory_pair()
            served.append(asyncio.get_running_loop().create_task(daemon.serve(server)))
            return client

        state, app = build_gateway_app(
            keys_directory=keys,
            connect_upstream=connect_upstream,  # type: ignore[arg-type]
            audit=_Audit(),
        )
        server = gateway_server(
            uvicorn.Config(
                app,
                host="127.0.0.1",
                port=port,
                ssl_certfile=None if cert is None else str(cert),
                ssl_keyfile=None if key_file is None else str(key_file),
                access_log=False,
                log_level="warning",
                lifespan="on",
                timeout_graceful_shutdown=_GRACEFUL_SECONDS,
            ),
            state,
        )
        serving = asyncio.create_task(server.serve())
        verify: ssl.SSLContext | bool = (
            False if cert is None else ssl.create_default_context(cafile=str(cert))
        )
        scheme = "https" if tls else "http"
        async with httpx.AsyncClient(
            base_url=f"{scheme}://127.0.0.1:{port}", verify=verify, trust_env=False
        ) as client:
            async with asyncio.timeout(10):
                while not server.started:
                    await asyncio.sleep(0.02)
            opened = await client.post("/v1/sessions", content=_agent_hello(), headers=headers)
            assert opened.status_code == 201, opened.content
            sid = opened.headers["Location"].rsplit("/", 1)[1]
            session = state.sessions.get(sid, _record.key_id)
            assert session is not None
            opened_at = session.last_seen
            poll = asyncio.create_task(
                client.get(f"/v1/sessions/{sid}/frames?wait_ms=20000", headers=headers)
            )
            # The poll is in its handler once it has looked its session up (which touches it).
            async with asyncio.timeout(10):
                while session.last_seen == opened_at:
                    await asyncio.sleep(0.01)
            stopped = time.monotonic()
            server.should_exit = True
            async with asyncio.timeout(_GRACEFUL_SECONDS + 10):
                answered = await poll
                await serving
            elapsed = time.monotonic() - stopped
        await asyncio.gather(*served, return_exceptions=True)
        return answered.status_code, elapsed

    with caplog.at_level(logging.ERROR, logger="uvicorn.error"):
        status, elapsed = asyncio.run(exercise())
    # The poll got an answer (its session ended), not a cancelled request.
    assert status < 500
    assert elapsed < _GRACEFUL_SECONDS
    assert not [record for record in caplog.records if record.levelno >= logging.ERROR]
