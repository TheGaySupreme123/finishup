"""The HTTPS binding v1 of the control frames (ADR-051, approach A): shared names and contracts.

A FinishUP connector on the client machine and ``finishup service gateway`` on the server host
speak this binding. Every request and response body is the exact canonical JSON a control socket
frame carries after its 4-byte length prefix, so a frame crosses HTTPS byte for byte. Only
transport and authentication failures use their own body, ``rest-error`` 1.0.0, with a closed
reason; workflow outcomes stay inside a ``200`` control-result.

``server-info`` 1.0.0 is what ``GET /v1/server`` answers: the server's release and schema-manifest
digest (so a client can refuse a lockstep mismatch before it opens a session), and the
authenticated key's id and scope. The key's label, the server's host name and every path stay
off the wire.

This module is SHARED: it holds constants, the two closed contracts, and the method allow-list of
each key scope. Both the connector (CLIENT) and the gateway (GATEWAY) import it.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from types import MappingProxyType
from typing import Annotated, Final, Literal

from pydantic import BaseModel, ConfigDict, Field

from finishup.ports.control import ControlMethod

__all__ = [
    "API_KEY_PATTERN",
    "BINDING_HEADER",
    "BINDING_VERSION",
    "CORRELATION_HEADER",
    "KEY_SCOPES",
    "MAX_SESSIONS_PER_KEY",
    "MAX_WAIT_MS",
    "REST_ERROR_SCHEMA_VERSION",
    "REST_ERROR_STATUS",
    "SERVER_INFO_SCHEMA_VERSION",
    "SESSION_ID_PATTERN",
    "SESSION_IDLE_SECONDS",
    "KeyScope",
    "RestErrorContract",
    "RestErrorReason",
    "ServerInfoContract",
    "method_allowed",
    "parse_api_key",
]

BINDING_VERSION: Final = "1.0"
BINDING_HEADER: Final = "FinishUP-Binding"
CORRELATION_HEADER: Final = "FinishUP-Correlation-Id"
# A long-poll never holds a request past this, so a 60-second proxy timeout never cuts one.
MAX_WAIT_MS: Final = 25_000
SESSION_IDLE_SECONDS: Final = 120.0
MAX_SESSIONS_PER_KEY: Final = 64
REST_ERROR_SCHEMA_VERSION: Literal["1.0.0"] = "1.0.0"
SERVER_INFO_SCHEMA_VERSION: Literal["1.0.0"] = "1.0.0"

# ``fuk_<12 hex key id>_<43 base64url secret>``: 256 bits of secret, a shape scanners can match.
API_KEY_PATTERN: Final = re.compile(r"^fuk_([0-9a-f]{12})_([A-Za-z0-9_-]{43})$", re.ASCII)
# 32 random bytes, base64url without padding.
SESSION_ID_PATTERN: Final = re.compile(r"^[A-Za-z0-9_-]{43}$", re.ASCII)

type KeyScope = Literal["agent", "operator"]
type RestErrorReason = Literal[
    "frame_invalid",
    "api_key_invalid",
    "api_key_revoked",
    "api_key_expired",
    "origin_forbidden",
    "workspace_locator_forbidden",
    "session_unknown",
    "frame_too_large",
    "session_limit",
    "service_unavailable",
]

# The HTTP status of every closed transport reason (INTERFACES, HTTPS binding v1).
REST_ERROR_STATUS: Final[Mapping[str, int]] = MappingProxyType(
    {
        "frame_invalid": 400,
        "api_key_invalid": 401,
        "api_key_revoked": 401,
        "api_key_expired": 401,
        "origin_forbidden": 403,
        "workspace_locator_forbidden": 403,
        "session_unknown": 404,
        "frame_too_large": 413,
        "session_limit": 429,
        "service_unavailable": 503,
    }
)

_WORKFLOW: Final = frozenset(
    {
        ControlMethod.START,
        ControlMethod.PUBLISH_WORK,
        ControlMethod.CHECK,
        ControlMethod.RESPOND,
        ControlMethod.STATUS,
        ControlMethod.RECEIPT,
    }
)
# What hooks, the MCP bridge, the closure gate and the startup-gate probe call (ADR-051
# decision 9). ``observation_ingest`` is admitted only on a claim-bound session.
_AGENT: Final = _WORKFLOW | {ControlMethod.SERVICE_STATUS}
_OPERATOR: Final = _AGENT | {
    ControlMethod.PROJECT,
    ControlMethod.REVIEW,
    ControlMethod.IMPORT_CODEX_JSONL,
    ControlMethod.OBSERVATION_STATUS,
    ControlMethod.PRIVACY_GET_SETUP,
    ControlMethod.PRIVACY_GET_EFFECTIVE,
    ControlMethod.PRIVACY_PENDING_LIST,
    ControlMethod.PRIVACY_RECEIPTS_LIST,
    ControlMethod.PRIVACY_RECEIPTS_GET,
    ControlMethod.PRIVACY_PROPOSE_POLICY,
    ControlMethod.PRIVACY_TIGHTEN_POLICY,
    ControlMethod.SERVICE_LOCK,
}
KEY_SCOPES: Final[Mapping[str, frozenset[ControlMethod]]] = MappingProxyType(
    {"agent": _AGENT, "operator": _OPERATOR}
)


def method_allowed(scope: KeyScope, method: ControlMethod, *, claim_bound: bool) -> bool:
    """Whether a key of ``scope`` may call ``method`` on a session.

    ``service_stop``, ``backup_*``, ``restore_*``, ``migrate_*``, ``integration_*`` and
    ``observation_pause|resume|revoke`` are never reachable over HTTPS, whatever the scope.
    """

    if method is ControlMethod.OBSERVATION_INGEST:
        return claim_bound
    return method in KEY_SCOPES[scope]


def parse_api_key(value: str) -> tuple[str, str] | None:
    """Split a bearer key into ``(key id, secret)``; ``None`` when it does not have the shape."""

    if type(value) is not str:
        return None
    matched = API_KEY_PATTERN.match(value)
    if matched is None:
        return None
    return matched.group(1), matched.group(2)


class RestErrorContract(BaseModel):
    """``rest-error`` 1.0.0: a transport or authentication failure of the HTTPS binding."""

    model_config = ConfigDict(extra="forbid", strict=True)

    schema_version: Literal["1.0.0"]
    reason: RestErrorReason


class ServerInfoContract(BaseModel):
    """``server-info`` 1.0.0: what ``GET /v1/server`` tells an authenticated client."""

    model_config = ConfigDict(extra="forbid", strict=True)

    schema_version: Literal["1.0.0"]
    release: Annotated[str, Field(min_length=1, max_length=128)]
    schema_manifest_digest: Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
    key_id: Annotated[str, Field(pattern=r"^[0-9a-f]{12}$")]
    scope: KeyScope
    bindings: list[Literal["1.0"]] = Field(min_length=1, max_length=1)
