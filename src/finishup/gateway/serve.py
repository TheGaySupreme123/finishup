"""Run the gateway in the foreground: ``finishup service gateway run`` (ADR-051, approach A).

``--tls-cert``/``--tls-key`` serve HTTPS on any address. ``--behind-proxy`` serves plain HTTP for a
TLS-terminating proxy, and only on a loopback address; plain HTTP on any other address is refused
before anything listens. The server keeps no access log (a session id in a path is a bearer of
that session), sends no ``Server`` header, and trusts no forwarded-for header.

The gateway reaches the daemon through ``finishup.service.client.ensure_service_running``: the
same owner-only control endpoint, peer-UID authentication and on-demand start as any local client,
without a handshake of its own — each session forwards its client's hello.
"""

from __future__ import annotations

import ipaddress
import ssl
from pathlib import Path
from typing import Final

__all__ = ["GatewayConfigError", "parse_listen", "run_gateway"]

_STALE_EXIT: Final = 21


class GatewayConfigError(Exception):
    """A refused gateway configuration; ``reason`` is a closed token."""

    def __init__(self, reason: str) -> None:
        if reason not in {
            "gateway_listen_invalid",
            "gateway_tls_required",
            "gateway_proxy_not_loopback",
            "gateway_tls_invalid",
        }:
            raise ValueError("gateway_config_reason_invalid")
        self.reason = reason
        super().__init__(reason)


def parse_listen(value: str) -> tuple[str, int]:
    """``HOST:PORT`` or ``[V6]:PORT`` with an IP literal or ``localhost``; nothing else."""

    host, separator, port_text = value.rpartition(":")
    if not separator or not port_text.isdigit() or not 1 <= int(port_text) <= 65_535:
        raise GatewayConfigError("gateway_listen_invalid")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if host != "localhost":
        try:
            ipaddress.ip_address(host)
        except ValueError:
            raise GatewayConfigError("gateway_listen_invalid") from None
    return host, int(port_text)


def _loopback(host: str) -> bool:
    return host == "localhost" or ipaddress.ip_address(host).is_loopback


def run_gateway(
    *,
    listen: str,
    tls_cert: Path | None,
    tls_key: Path | None,
    behind_proxy: bool,
) -> int:
    """Serve until interrupted; return the process exit code (21 when the gateway is stale)."""

    host, port = parse_listen(listen)
    if behind_proxy:
        if tls_cert is not None or tls_key is not None:
            raise GatewayConfigError("gateway_tls_invalid")
        if not _loopback(host):
            raise GatewayConfigError("gateway_proxy_not_loopback")
    elif tls_cert is None or tls_key is None:
        raise GatewayConfigError("gateway_tls_required")
    else:
        try:
            ssl.create_default_context(ssl.Purpose.CLIENT_AUTH).load_cert_chain(tls_cert, tls_key)
        except (OSError, ssl.SSLError):
            raise GatewayConfigError("gateway_tls_invalid") from None

    import uvicorn

    from finishup.config.paths import log_dir, state_dir
    from finishup.gateway.app import FileAuditSink, build_gateway_app
    from finishup.gateway.keys import GATEWAY_DIR_NAME
    from finishup.service.client import ensure_service_running

    stale = False
    server: uvicorn.Server | None = None

    def on_stale() -> None:
        nonlocal stale
        stale = True
        if server is not None:
            server.should_exit = True

    _state, application = build_gateway_app(
        keys_directory=state_dir() / GATEWAY_DIR_NAME,
        connect_upstream=ensure_service_running,
        audit=FileAuditSink(log_dir() / "gateway-audit.jsonl"),
        on_stale=on_stale,
    )
    config = uvicorn.Config(
        application,
        host=host,
        port=port,
        ssl_certfile=None if tls_cert is None else str(tls_cert),
        ssl_keyfile=None if tls_key is None else str(tls_key),
        access_log=False,
        server_header=False,
        date_header=False,
        proxy_headers=False,
        forwarded_allow_ips="",
        log_level="warning",
        lifespan="on",
        timeout_keep_alive=30,
    )
    server = uvicorn.Server(config)
    server.run()
    return _STALE_EXIT if stale else 0
