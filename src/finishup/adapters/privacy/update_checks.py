"""Bounded structural package-update transport for the ``update_checks`` channel.

This adapter is intentionally independent of the LLM egress gateway. It may only:

- issue a fixed allowlisted HTTPS GET for the ``finishup`` distribution identity on PyPI;
- parse version fields from a size-capped JSON body;
- never accept task/user content, proxies (``trust_env=False``), redirects beyond one hop,
  or open endpoint configuration.

Policy admission is the caller's responsibility. Network failure fails closed: callers treat
an empty/missing version as "no advisory," never as an error surfaced to work receipts.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Final, Protocol, cast

import httpx

__all__ = [
    "PYPI_FINISHUP_JSON_URL",
    "UpdateChecksTransport",
    "UpdateChecksTransportError",
    "fetch_latest_finishup_version",
    "parse_latest_version",
]

# Exact product allowlist for the update_checks channel. Do not generalize to arbitrary hosts.
PYPI_FINISHUP_JSON_URL: Final = "https://pypi.org/pypi/finishup/json"
_MAX_BODY_BYTES: Final = 64 * 1024
_DEFAULT_TIMEOUT_SECONDS: Final = 3.0


class UpdateChecksTransportError(Exception):
    """Structural transport failure; never carries user/task content."""

    def __init__(self, reason: str) -> None:
        if type(reason) is not str or not reason or len(reason) > 128:
            raise ValueError("update_checks_reason_invalid")
        self.reason = reason
        super().__init__(reason)


class UpdateChecksTransport(Protocol):
    """Narrow fetch seam so unit tests can inject scripted responses without sockets."""

    async def fetch_latest_version(self) -> str:
        """Return a non-empty version string from the allowlisted registry document."""
        ...


@dataclass(frozen=True, slots=True)
class HttpxUpdateChecksTransport:
    """Production transport: one bounded httpx GET with no ambient proxy trust."""

    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS
    max_body_bytes: int = _MAX_BODY_BYTES

    async def fetch_latest_version(self) -> str:
        return await fetch_latest_finishup_version(
            timeout_seconds=self.timeout_seconds,
            max_body_bytes=self.max_body_bytes,
        )


def parse_latest_version(body: bytes) -> str:
    """Extract ``info.version`` from a size-capped PyPI JSON body.

    Raises ``UpdateChecksTransportError`` on invalid JSON, missing fields, or malformed
    version strings. Callers treat failure as silent unavailability.
    """
    if not body or len(body) > _MAX_BODY_BYTES:
        raise UpdateChecksTransportError("body_invalid")
    try:
        parsed: object = json.loads(body.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise UpdateChecksTransportError("body_not_json") from exc
    if type(parsed) is not dict:
        raise UpdateChecksTransportError("body_shape_invalid")
    document = cast(dict[str, object], parsed)
    info_raw = document.get("info")
    if type(info_raw) is not dict:
        raise UpdateChecksTransportError("info_missing")
    info = cast(dict[str, object], info_raw)
    version_raw = info.get("version")
    if type(version_raw) is not str or not version_raw or len(version_raw) > 64:
        raise UpdateChecksTransportError("version_invalid")
    version = version_raw
    if any(char.isspace() for char in version):
        raise UpdateChecksTransportError("version_invalid")
    return version


async def fetch_latest_finishup_version(
    *,
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
    max_body_bytes: int = _MAX_BODY_BYTES,
    client: httpx.AsyncClient | None = None,
) -> str:
    """GET the allowlisted PyPI JSON document and return ``info.version`` only."""

    if type(timeout_seconds) is not float and type(timeout_seconds) is not int:
        raise TypeError("timeout_seconds_invalid")
    if type(max_body_bytes) is not int or max_body_bytes <= 0 or max_body_bytes > _MAX_BODY_BYTES:
        raise ValueError("max_body_bytes_invalid")

    owns_client = client is None
    http_client = client or httpx.AsyncClient(
        trust_env=False,
        follow_redirects=False,
        timeout=httpx.Timeout(float(timeout_seconds)),
    )
    try:
        try:
            response = await http_client.get(PYPI_FINISHUP_JSON_URL)
        except httpx.TimeoutException as exc:
            raise UpdateChecksTransportError("timeout") from exc
        except httpx.HTTPError as exc:
            raise UpdateChecksTransportError("transport_failed") from exc
        if response.status_code != 200:
            raise UpdateChecksTransportError("http_status")
        # Bound body without trusting Content-Length alone.
        body = response.content
        if len(body) > max_body_bytes:
            raise UpdateChecksTransportError("body_too_large")
        return parse_latest_version(body)
    finally:
        if owns_client:
            await http_client.aclose()
