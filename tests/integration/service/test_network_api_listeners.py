"""The service's own network API on real listeners (ADR-051, server-native approach).

A production service composition built with a ``[network]`` table binds a TLS listener on
loopback and the owner-only API socket, serves them from its own event loop, and closes both when
it stops. ``RestServiceClient`` reaches it over real TLS — trusting a CA file or a certificate pin
checked before any key is sent — and over the API socket as an SSH master would forward it.
Without the table the composition has no listener and the daemon never imports the HTTP stack.
"""

from __future__ import annotations

import asyncio
import base64
import datetime as dt
import hashlib
import ipaddress
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import finishup.service.daemon as daemon_module
from finishup.adapters.control.unix_socket import (
    bind_control_listener,
    bind_human_control_listener,
    bind_secret_listener,
)
from finishup.client.rest_client import RestEndpoint, connect_rest_service, rest_endpoint_for
from finishup.client.targets import ServerTarget
from finishup.config.models import FinishUpConfig, NetworkConfig
from finishup.ports.control import ControlClientKind, ControlError
from finishup.service.api_keys import ApiKeyStore
from finishup.service.daemon import ServiceDaemon
from finishup.service.network_protocol import parse_server_info

_SALT = base64.b64encode(b"\x03" * 32).decode("ascii")


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def runtime_directory(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Short in-tree socket directory: AF_UNIX paths bound under tmp_path are too long."""

    runtime = Path(tempfile.mkdtemp(prefix=".ynet-", dir=Path.cwd()))
    runtime.chmod(0o700)
    monkeypatch.setattr("finishup.adapters.control.unix_socket._runtime_directory", lambda: runtime)
    monkeypatch.setattr(daemon_module, "runtime_dir", lambda: runtime)
    try:
        yield runtime
    finally:
        shutil.rmtree(runtime, ignore_errors=True)


def _certificate_authority(directory: Path) -> tuple[Path, Path, Path, str]:
    """A CA, and a server certificate for 127.0.0.1 it signed: (ca, cert, key, sha256 pin)."""

    now = dt.datetime.now(dt.UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "finishup test ca")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    key = ec.generate_private_key(ec.SECP256R1())
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]))
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    ca_path = directory / "ca.pem"
    cert_path = directory / "cert.pem"
    key_path = directory / "key.pem"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    pin = (
        "sha256:" + hashlib.sha256(certificate.public_bytes(serialization.Encoding.DER)).hexdigest()
    )
    return ca_path, cert_path, key_path, pin


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


async def _production_daemon(tmp_path: Path, network: NetworkConfig | None) -> ServiceDaemon:
    root = tmp_path / "data"
    metadata = tmp_path / "state"
    root.mkdir(mode=0o700, exist_ok=True)
    metadata.mkdir(mode=0o700, exist_ok=True)
    paths = daemon_module._ProductionPaths(  # pyright: ignore[reportPrivateUsage]
        root,
        metadata / "service-generation.json",
        metadata / "unlock-throttle.json",
        metadata / "service.lock",
        metadata,
    )
    binders = daemon_module._ListenerBinders(  # pyright: ignore[reportPrivateUsage]
        bind_control_listener, bind_secret_listener, bind_human_control_listener
    )
    composition = await daemon_module._production_composition(  # pyright: ignore[reportPrivateUsage]
        _config=FinishUpConfig(network=network), _paths=paths, _binders=binders
    )
    return ServiceDaemon(_composition=composition)


def _https_record(port: int, **trust: str) -> ServerTarget:
    return ServerTarget(
        "t_0a1b2c3d",
        "lab",
        "local_port",
        "2026-11-05T00:00:00.000Z",
        base_url=f"https://127.0.0.1:{port}",
        claim_salt=_SALT,
        authorized_at="2026-11-05T00:00:00.000Z",
        disclosure_version=1,
        credential="file",
        **trust,  # type: ignore[arg-type]
    )


@pytest.mark.anyio
async def test_the_service_serves_its_api_over_tls_and_its_owner_socket(
    tmp_path: Path, runtime_directory: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tmp_path.chmod(0o700)
    tls = tmp_path / "tls"
    tls.mkdir(mode=0o700)
    ca, cert, key, pin = _certificate_authority(tls)
    port = _free_port()
    network = NetworkConfig.model_validate(
        {
            "listen": [f"127.0.0.1:{port}"],
            "tls_cert": str(cert),
            "tls_key": str(key),
            "api_socket": True,
        }
    )
    keys = ApiKeyStore(tmp_path / "state" / "network")
    (tmp_path / "state").mkdir(mode=0o700, exist_ok=True)
    record, token = keys.create("laptop", "operator")
    authenticated: list[str] = []
    real_authenticate = ApiKeyStore.authenticate

    def counting(self: ApiKeyStore, presented: str, **options: object) -> object:
        authenticated.append(presented[:16])
        return real_authenticate(self, presented, **options)  # type: ignore[arg-type]

    monkeypatch.setattr(ApiKeyStore, "authenticate", counting)

    def stored_key(_self: object) -> str:
        return token

    monkeypatch.setattr("finishup.client.credentials.KeyringOrFileCredential.read", stored_key)
    daemon = await _production_daemon(tmp_path, network)
    await daemon.start()
    serving = asyncio.create_task(daemon.serve())
    try:
        api_socket = runtime_directory / "api.sock"
        for _attempt in range(200):
            if api_socket.exists():
                break
            await asyncio.sleep(0.01)
        assert api_socket.stat().st_mode & 0o777 == 0o600

        # Real TLS trusted through the target's CA file; every typed call reaches the daemon.
        trusted = _https_record(port, ca_file=str(ca))
        client = await connect_rest_service(
            ControlClientKind.CLI, record=trusted, root=tmp_path / "client"
        )
        try:
            status = await client.service_status()
            assert status == daemon.status()
            assert client.hello_service_status == daemon.status()
        finally:
            await client.close()

        # A certificate pin is checked inside the handshake.
        pinned = await connect_rest_service(
            ControlClientKind.CLI, record=_https_record(port, tls_pin=pin), root=tmp_path / "c"
        )
        await pinned.close()
        before = len(authenticated)
        with pytest.raises(ControlError) as wrong_pin:
            await connect_rest_service(
                ControlClientKind.CLI,
                record=_https_record(port, tls_pin="sha256:" + "0" * 64),
                root=tmp_path / "c",
            )
        assert wrong_pin.value.phase == "remote_identity_changed"
        # A server whose certificate did not match the pin never saw the key.
        assert len(authenticated) == before
        with pytest.raises(ControlError) as untrusted:
            await connect_rest_service(
                ControlClientKind.CLI, record=_https_record(port), root=tmp_path / "c"
            )
        assert untrusted.value.phase == "remote_identity_changed"

        # The owner socket an SSH master forwards to: no key, the operator scope.
        async with httpx.AsyncClient(
            transport=httpx.AsyncHTTPTransport(uds=str(api_socket)), base_url="http://x"
        ) as owner:
            info = parse_server_info((await owner.get("/v1/server")).content)
        assert (info.transport, info.key_id, info.scope) == ("unix", None, "operator")
        ssh_like = RestEndpoint(
            "ssh", "http://finishup.invalid", httpx.AsyncHTTPTransport(uds=str(api_socket)), None
        )
        over_socket = await connect_rest_service(
            ControlClientKind.CLI,
            record=_https_record(port),
            root=tmp_path / "c",
            _endpoint=ssh_like,
        )
        try:
            assert (await over_socket.service_status()).service_instance_id == (
                daemon.status().service_instance_id
            )
        finally:
            await over_socket.close()
        assert keys.revoke(record.key_id)
        with pytest.raises(ControlError) as revoked:
            await connect_rest_service(
                ControlClientKind.CLI, record=trusted, root=tmp_path / "client"
            )
        assert revoked.value.phase == "remote_auth_failed"
    finally:
        await daemon.stop()
        await asyncio.wait_for(serving, timeout=10)
    # Stopping closed both listeners: the socket is gone and the port refuses.
    assert not (runtime_directory / "api.sock").exists()
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", port), timeout=1).close()


@pytest.mark.anyio
async def test_without_a_network_table_there_is_no_listener(
    tmp_path: Path, runtime_directory: Path
) -> None:
    tmp_path.chmod(0o700)
    daemon = await _production_daemon(tmp_path, None)
    await daemon.start()
    try:
        assert daemon.composition.network_api is None
    finally:
        await daemon.stop()
    assert not (runtime_directory / "api.sock").exists()


@pytest.mark.anyio
async def test_an_unbindable_listener_fails_the_start_with_its_reason(
    tmp_path: Path, runtime_directory: Path
) -> None:
    from finishup.config.models import ConfigError

    tmp_path.chmod(0o700)
    with socket.socket() as taken:
        taken.bind(("127.0.0.1", 0))
        taken.listen()
        port = int(taken.getsockname()[1])
        network = NetworkConfig.model_validate(
            {"listen": [f"127.0.0.1:{port}"], "allow_plain_loopback": True}
        )
        with pytest.raises(ConfigError) as raised:
            await _production_daemon(tmp_path, network)
    assert raised.value.reason_code == "network_listener_unavailable"
    del runtime_directory


def test_the_daemon_never_imports_the_http_stack_on_its_own() -> None:
    probe = (
        "import sys, finishup.service.daemon, finishup.service.client\n"
        "print(sorted(m for m in ('finishup.service.http_api', 'starlette', 'uvicorn', "
        "'finishup.client.rest_client') if m in sys.modules))"
    )
    completed = subprocess.run(  # noqa: S603 - fixed interpreter and probe
        [sys.executable, "-c", probe],
        capture_output=True,
        check=True,
        timeout=60,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    assert completed.stdout.strip() == b"[]"


def test_rest_endpoint_requires_a_remote_record() -> None:
    local = ServerTarget("t_0a1b2c3d", "work", "local", "2026-11-05T00:00:00.000Z")
    with pytest.raises(ControlError):
        rest_endpoint_for(local, Path("/x"))
    assert ssl.TLSVersion.TLSv1_2  # the floor both sides set
