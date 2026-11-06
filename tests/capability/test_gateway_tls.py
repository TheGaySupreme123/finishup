"""Real TLS between the connector and the gateway (ADR-051, approach A).

Serves the gateway with uvicorn on a free loopback port under a throwaway self-signed certificate
and drives the scripted session through the connector's HTTPS relay, once trusting the
certificate as a CA file and once by its ``sha256`` pin. The bytes match the in-memory transport.
A wrong pin is refused right after the TLS handshake: the status names
``remote_identity_changed`` and the gateway never saw a request (so the key never left).
"""

from __future__ import annotations

import asyncio
import datetime
import hashlib
import ipaddress
import socket
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from builders.control_relay import ScriptedDaemon, memory_pair, run_scripted_session
from builders.server_targets import ambient_home
from finishup.adapters.control.unix_socket import AuthenticatedUnixStream, authenticate_peer
from finishup.client import targets
from finishup.client.connector import Connector
from finishup.client.connector_status import read_connector_status
from finishup.client.https_upstream import HttpsUpstream
from finishup.config.paths import selection_override
from finishup.gateway.app import build_gateway_app
from finishup.gateway.keys import create_key
from finishup.protocol.canonical import JsonValue


class _Audit:
    def __init__(self) -> None:
        self.records: list[dict[str, JsonValue]] = []

    def write(self, record: dict[str, JsonValue]) -> None:
        self.records.append(record)


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as root:
        yield root


def _certificate(directory: Path) -> tuple[Path, Path, str]:
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
    der = certificate.public_bytes(serialization.Encoding.DER)
    return cert_path, key_path, f"sha256:{hashlib.sha256(der).hexdigest()}"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


async def _reference() -> list[bytes]:
    daemon = ScriptedDaemon()
    client, server = memory_pair()
    served = asyncio.create_task(daemon.serve(server))
    received = await run_scripted_session(client)
    await client.aclose()
    await served
    return received


def test_the_https_relay_over_real_tls_with_a_ca_file_and_with_a_pin(home: Path) -> None:
    cert, key_file, pin = _certificate(home)
    keys = home / "gateway"
    _record, api_key = create_key(keys, label="tls", scope="agent")
    port = _free_port()
    expected = asyncio.run(_reference())
    with targets.registry_lock():
        base, root = targets.new_remote_target(
            "gw", "local_port", base_url=f"https://127.0.0.1:{port}"
        )
    audit = _Audit()

    async def exercise() -> None:
        daemon = ScriptedDaemon()

        async def connect_upstream() -> object:
            client, server = memory_pair()
            asyncio.get_running_loop().create_task(daemon.serve(server))
            return client

        _state, app = build_gateway_app(
            keys_directory=keys,
            connect_upstream=connect_upstream,  # type: ignore[arg-type]
            audit=audit,
        )
        server = uvicorn.Server(
            uvicorn.Config(
                app,
                host="127.0.0.1",
                port=port,
                ssl_certfile=str(cert),
                ssl_keyfile=str(key_file),
                access_log=False,
                log_level="warning",
                lifespan="on",
            )
        )
        serving = asyncio.create_task(server.serve())
        try:
            async with asyncio.timeout(10):
                while not server.started:
                    await asyncio.sleep(0.02)
            for record in (
                replace(base, ca_file=str(cert)),
                replace(base, tls_pin=pin),
            ):
                connector = Connector(root, record, credential=lambda: api_key)
                left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
                client = AuthenticatedUnixStream(left, authenticate_peer(left))
                local = AuthenticatedUnixStream(right, authenticate_peer(right))
                relay = asyncio.create_task(connector._serve_local(local))  # pyright: ignore[reportPrivateUsage]
                async with asyncio.timeout(30):
                    received = await run_scripted_session(client)
                    await client.shutdown_write()
                    await relay
                await client.aclose()
                await cast(HttpsUpstream, connector._https).aclose()  # pyright: ignore[reportPrivateUsage]
                assert received == expected
            requests_before = len(audit.records)
            wrong = Connector(
                root, replace(base, tls_pin="sha256:" + "0" * 64), credential=lambda: api_key
            )
            await wrong.warm()
            await cast(HttpsUpstream, wrong._https).aclose()  # pyright: ignore[reportPrivateUsage]
            status = read_connector_status(root)
            assert status is not None
            assert (status.phase, status.reason) == ("unavailable", "remote_identity_changed")
            assert len(audit.records) == requests_before
        finally:
            server.should_exit = True
            await serving

    with selection_override(root):
        asyncio.run(exercise())
    assert {str(record["route"]) for record in audit.records} >= {"sessions", "calls", "frames_out"}
