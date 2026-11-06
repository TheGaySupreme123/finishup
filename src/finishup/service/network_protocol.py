"""The service's network API wire contract (ADR-051, server-native approach), shared by both sides.

The service itself serves a resource-shaped HTTP API when its ``[network]`` table asks for one
(``finishup.service.http_api``); remote clients reach it with ``finishup.client.rest_client``.
This module holds what both sides must agree on and nothing else: routes, header names, key
scopes and their method allow-lists, the API key token shape, the claim header codec, the closed
transport-error reasons, and the small documents the API adds (``server-info``, agent
registration and work). Request and result *bodies* are not redefined here: a call's body is the
existing operation request, and its answer is the existing control-result body, byte for byte.

Everything that crosses the wire is canonical JSON with closed tokens. No document here carries a
path, a host name, an owner-typed label or a key.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, Literal, cast

from finishup.ports.control import (
    ControlClientKind,
    ControlMethod,
    McpHostProfile,
    ServiceStatus,
    WorkspaceAgentDeclaration,
    WorkspaceBinding,
    WorkspaceClaim,
)
from finishup.ports.workspace_agent import workspace_handle_valid
from finishup.protocol.canonical import JsonValue, canonical_encode, strict_json_parse
from finishup.service.control_protocol import service_status_from_wire, service_status_wire

__all__ = [
    "AGENT_LEASE_MS",
    "AGENT_SCOPE_METHODS",
    "API_KEY_PREFIX",
    "API_SOCKET_NAME",
    "API_SCOPES",
    "CLAIM_BOUND_ONLY_METHODS",
    "DEFAULT_WAIT_MS",
    "HEADER_CLAIM",
    "HEADER_CLIENT_KIND",
    "HEADER_DEADLINE_MS",
    "HEADER_HOST_PROFILE",
    "HEADER_OPERATION_ID",
    "HEADER_OUTCOME",
    "HEADER_ROUTE_PROFILE",
    "HEADER_SERVICE_GENERATION",
    "HEADER_SERVICE_INSTANCE",
    "HEADER_WORKSPACE_HANDLE",
    "MAX_WAIT_MS",
    "NETWORK_API_SCHEMA_VERSION",
    "NEVER_OVER_NETWORK_METHODS",
    "OPERATOR_SCOPE_METHODS",
    "OWNER_PRINCIPAL",
    "REST_ERROR_STATUS",
    "AgentRegistration",
    "AgentWork",
    "ApiKeyToken",
    "ApiScope",
    "NetworkTransport",
    "ServerInfo",
    "agent_declaration_document",
    "agent_id_valid",
    "agent_registration_document",
    "agent_work_document",
    "claim_principal_digest",
    "encode_claim_header",
    "method_allowed",
    "mint_api_key",
    "new_agent_id",
    "parse_agent_declaration",
    "parse_agent_registration",
    "parse_agent_work",
    "parse_api_key",
    "parse_claim_header",
    "parse_client_kind",
    "parse_host_profile",
    "parse_rest_error",
    "parse_server_info",
    "parse_wait_ms",
    "rest_error_document",
    "server_info_document",
]

NETWORK_API_SCHEMA_VERSION: Final = "1.0.0"
# The owner-only Unix socket in the service's runtime directory that an SSH client forwards to.
API_SOCKET_NAME: Final = "api.sock"
# Long-poll bound: under the 60 s idle timeout common HTTP proxies apply.
MAX_WAIT_MS: Final = 25_000
DEFAULT_WAIT_MS: Final = 25_000
# How long a registered workspace agent stays registered without polling for work.
AGENT_LEASE_MS: Final = 60_000

# Request headers. Header names are case-insensitive; these are the canonical lowercase spellings.
HEADER_CLAIM: Final = "x-finishup-workspace-claim"
HEADER_CLIENT_KIND: Final = "finishup-client-kind"
HEADER_SERVICE_INSTANCE: Final = "finishup-service-instance"
HEADER_SERVICE_GENERATION: Final = "finishup-service-generation"
HEADER_OPERATION_ID: Final = "finishup-operation-id"
HEADER_DEADLINE_MS: Final = "finishup-deadline-ms"
HEADER_ROUTE_PROFILE: Final = "finishup-route-profile"
HEADER_HOST_PROFILE: Final = "finishup-host-profile"
# Response headers.
HEADER_OUTCOME: Final = "finishup-outcome"
HEADER_WORKSPACE_HANDLE: Final = "finishup-workspace-handle"

type ApiScope = Literal["agent", "operator"]
# How the request reached the service: TLS on a TCP listener, plain HTTP on an opted-in loopback
# listener, or the owner-only Unix socket an SSH client forwards to.
type NetworkTransport = Literal["https", "http", "unix"]

API_SCOPES: Final[tuple[ApiScope, ...]] = ("agent", "operator")
# The principal of a request that arrived on the owner-only API socket (SSH is owner-equivalent).
OWNER_PRINCIPAL: Final = "p_owner"

# Every method a hook, the closure gate, the startup-gate probe or the MCP bridge calls.
AGENT_SCOPE_METHODS: Final[frozenset[ControlMethod]] = frozenset(
    {
        ControlMethod.START,
        ControlMethod.PUBLISH_WORK,
        ControlMethod.CHECK,
        ControlMethod.RESPOND,
        ControlMethod.STATUS,
        ControlMethod.RECEIPT,
        ControlMethod.SERVICE_STATUS,
        ControlMethod.OBSERVATION_INGEST,
    }
)
OPERATOR_SCOPE_METHODS: Final[frozenset[ControlMethod]] = AGENT_SCOPE_METHODS | frozenset(
    {
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
)
# Stopping the service, server-path operations (backup, restore, migrate, integration) and the
# observation-store administration stay on the server host whatever the key.
NEVER_OVER_NETWORK_METHODS: Final[frozenset[ControlMethod]] = (
    frozenset(ControlMethod) - OPERATOR_SCOPE_METHODS
)
# Allowed only on a request whose claim the service resolved (the workspace it names is the
# client's own, read by the client's workspace agent).
CLAIM_BOUND_ONLY_METHODS: Final[frozenset[ControlMethod]] = frozenset(
    {ControlMethod.OBSERVATION_INGEST}
)

# Transport and authentication refusals. A dispatched call's own outcome — a workflow error,
# ``vault_locked``, ``method_forbidden`` — is never one of these: it is the control-result body.
REST_ERROR_STATUS: Final[Mapping[str, int]] = {
    "frame_invalid": 400,
    "header_invalid": 400,
    "api_key_invalid": 401,
    "api_key_revoked": 401,
    "api_key_expired": 401,
    "origin_forbidden": 403,
    "workspace_claim_required": 403,
    "route_unknown": 404,
    "operation_unknown": 404,
    "agent_unknown": 404,
    "method_not_allowed": 405,
    "frame_too_large": 413,
    "operation_limit": 429,
    "agent_limit": 429,
    # An unexpected failure of the API itself (a request it could not serve, an answer it could
    # not frame): a defect of this service, never "not running".
    "internal_failure": 500,
    "service_unavailable": 503,
    # The service's key file is unusable (permissions, damage): no key can be checked until the
    # owner repairs it on the server host.
    "server_keys_unusable": 503,
    "workspace_agent_unavailable": 503,
}

API_KEY_PREFIX: Final = "fuk_"
_API_KEY: Final = re.compile(r"^fuk_([0-9a-f]{12})_([A-Za-z0-9_-]{43})$", re.ASCII)
_API_KEY_SECRET_BYTES: Final = 32
_CLAIM_HEADER: Final = re.compile(r"^(git_common_root|directory):(sha256:[0-9a-f]{64})$", re.ASCII)
_AGENT_ID: Final = re.compile(r"^agt_[0-9a-f]{32}$", re.ASCII)
_KEY_ID: Final = re.compile(r"^[0-9a-f]{12}$", re.ASCII)
_SHA256: Final = re.compile(r"^sha256:[0-9a-f]{64}$", re.ASCII)
_SEMVER: Final = re.compile(r"^[0-9A-Za-z.+-]{1,64}$", re.ASCII)
_MAX_DOCUMENT_BYTES: Final = 65_536
_TRANSPORTS: Final = frozenset({"https", "http", "unix"})
_BINDINGS: Final = frozenset({"none", "client_claim"})
_CLIENT_KINDS: Final = frozenset(kind.value for kind in ControlClientKind)
_HOST_PROFILES: Final = frozenset({"generic", "codex", "claude", "cursor"})


class _Invalid(ValueError):
    def __init__(self) -> None:
        super().__init__("network_document_invalid")


def method_allowed(scope: ApiScope, method: ControlMethod, *, claim_bound: bool) -> bool:
    """Whether a key of ``scope`` may call ``method`` on a request bound (or not) to a claim."""

    allowed = AGENT_SCOPE_METHODS if scope == "agent" else OPERATOR_SCOPE_METHODS
    if method not in allowed:
        return False
    return claim_bound or method not in CLAIM_BOUND_ONLY_METHODS


def parse_wait_ms(raw: str | None, *, default: int = DEFAULT_WAIT_MS) -> int:
    """A ``wait_ms`` query value: decimal milliseconds in ``0..MAX_WAIT_MS``."""

    if raw is None:
        return default
    if not raw.isascii() or not raw.isdigit() or len(raw) > 6:
        raise ValueError("wait_ms_invalid")
    value = int(raw)
    if value > MAX_WAIT_MS:
        raise ValueError("wait_ms_invalid")
    return value


def parse_client_kind(raw: str | None) -> ControlClientKind:
    """The ``FinishUP-Client-Kind`` header; absent means ``cli``."""

    if raw is None:
        return ControlClientKind.CLI
    if raw not in _CLIENT_KINDS:
        raise ValueError("client_kind_invalid")
    return ControlClientKind(raw)


def parse_host_profile(raw: str | None) -> McpHostProfile | None:
    if raw is None:
        return None
    if raw not in _HOST_PROFILES:
        raise ValueError("host_profile_invalid")
    return cast(McpHostProfile, raw)


@dataclass(frozen=True, slots=True)
class ApiKeyToken:
    """A parsed ``fuk_<12 hex key id>_<43 base64url secret>`` bearer key."""

    key_id: str
    secret: bytes = b""

    def __repr__(self) -> str:
        return f"ApiKeyToken(key_id={self.key_id!r}, secret=<redacted>)"


def parse_api_key(token: str) -> ApiKeyToken | None:
    """The key id and secret of a well-formed key, or ``None`` (never echoing the value)."""

    if type(token) is not str:
        return None
    match = _API_KEY.fullmatch(token)
    if match is None:
        return None
    try:
        secret = base64.urlsafe_b64decode(match.group(2) + "=")
    except (ValueError, binascii.Error):
        return None
    if len(secret) != _API_KEY_SECRET_BYTES:
        return None
    # One spelling per key: the final character's padding bits must be zero.
    if base64.urlsafe_b64encode(secret).decode("ascii").rstrip("=") != match.group(2):
        return None
    return ApiKeyToken(match.group(1), secret)


def mint_api_key() -> tuple[ApiKeyToken, str]:
    """A fresh key: its parsed form and the one-time token text the owner copies."""

    key_id = secrets.token_hex(6)
    secret = secrets.token_bytes(_API_KEY_SECRET_BYTES)
    encoded = base64.urlsafe_b64encode(secret).decode("ascii").rstrip("=")
    return ApiKeyToken(key_id, secret), f"{API_KEY_PREFIX}{key_id}_{encoded}"


def encode_claim_header(claim: WorkspaceClaim) -> str:
    """``<identity_kind>:sha256:<64 hex>``: the claim a request names its workspace by."""

    if type(claim) is not WorkspaceClaim:
        raise TypeError("workspace_claim_invalid")
    return f"{claim.identity_kind}:{claim.digest}"


def parse_claim_header(raw: str) -> WorkspaceClaim:
    match = _CLAIM_HEADER.fullmatch(raw) if type(raw) is str else None
    if match is None:
        raise ValueError("workspace_claim_invalid")
    kind = cast(Literal["git_common_root", "directory"], match.group(1))
    return WorkspaceClaim(identity_kind=kind, digest=match.group(2))


def _encode(document: Mapping[str, JsonValue]) -> bytes:
    return canonical_encode(dict(document))


def _decode(body: bytes, keys: frozenset[str]) -> dict[str, JsonValue]:
    if type(body) is not bytes or len(body) > _MAX_DOCUMENT_BYTES:
        raise _Invalid
    try:
        value = strict_json_parse(body)
    except ValueError:
        raise _Invalid from None
    if type(value) is not dict:
        raise _Invalid
    document = cast(dict[str, JsonValue], value)
    if frozenset(document) != keys or document.get("schema_version") != (
        NETWORK_API_SCHEMA_VERSION
    ):
        raise _Invalid
    return document


def rest_error_document(reason: str) -> bytes:
    """The body of a transport refusal: ``{reason, schema_version}`` with a closed reason."""

    if reason not in REST_ERROR_STATUS:
        raise ValueError("rest_error_reason_invalid")
    return _encode({"reason": reason, "schema_version": NETWORK_API_SCHEMA_VERSION})


def parse_rest_error(body: bytes) -> str | None:
    """The closed reason of a transport refusal body, or ``None`` when it is not one."""

    try:
        document = _decode(body, frozenset({"reason", "schema_version"}))
    except _Invalid:
        return None
    reason = document["reason"]
    return reason if type(reason) is str and reason in REST_ERROR_STATUS else None


@dataclass(frozen=True, slots=True)
class ServerInfo:
    """What ``GET /v1/server`` reports: the service, the caller's key, and its workspace binding."""

    release: str
    schema_manifest_digest: str
    status: ServiceStatus
    key_id: str | None
    scope: ApiScope
    transport: NetworkTransport
    workspace_binding: WorkspaceBinding
    workspace_handle: str | None

    def __post_init__(self) -> None:
        if type(self.release) is not str or not _SEMVER.fullmatch(self.release):
            raise _Invalid
        if type(self.schema_manifest_digest) is not str or not _SHA256.fullmatch(
            self.schema_manifest_digest
        ):
            raise _Invalid
        if type(self.status) is not ServiceStatus:
            raise _Invalid
        if self.key_id is not None and (
            type(self.key_id) is not str or not _KEY_ID.fullmatch(self.key_id)
        ):
            raise _Invalid
        if self.scope not in API_SCOPES or self.transport not in _TRANSPORTS:
            raise _Invalid
        if (self.key_id is None) is not (self.transport == "unix"):
            raise _Invalid
        if self.workspace_binding not in _BINDINGS:
            raise _Invalid
        if self.workspace_handle is not None and (
            self.workspace_binding != "client_claim"
            or not workspace_handle_valid(self.workspace_handle)
        ):
            raise _Invalid

    @property
    def service_instance_id(self) -> str:
        return self.status.service_instance_id

    @property
    def service_generation(self) -> str:
        return self.status.service_generation


_SERVER_INFO_KEYS: Final = frozenset(
    {
        "key_id",
        "release",
        "schema_manifest_digest",
        "schema_version",
        "scope",
        "status",
        "transport",
        "workspace_binding",
        "workspace_handle",
    }
)


def server_info_document(info: ServerInfo) -> bytes:
    if type(info) is not ServerInfo:
        raise TypeError("server_info_invalid")
    return _encode(
        {
            "key_id": info.key_id,
            "release": info.release,
            "schema_manifest_digest": info.schema_manifest_digest,
            "schema_version": NETWORK_API_SCHEMA_VERSION,
            "scope": info.scope,
            "status": cast(JsonValue, service_status_wire(info.status)),
            "transport": info.transport,
            "workspace_binding": info.workspace_binding,
            "workspace_handle": info.workspace_handle,
        }
    )


def parse_server_info(body: bytes) -> ServerInfo:
    document = _decode(body, _SERVER_INFO_KEYS)
    try:
        status = service_status_from_wire(document["status"])
        return ServerInfo(
            release=cast(str, document["release"]),
            schema_manifest_digest=cast(str, document["schema_manifest_digest"]),
            status=status,
            key_id=cast(str | None, document["key_id"]),
            scope=cast(ApiScope, document["scope"]),
            transport=cast(NetworkTransport, document["transport"]),
            workspace_binding=cast(WorkspaceBinding, document["workspace_binding"]),
            workspace_handle=cast(str | None, document["workspace_handle"]),
        )
    except _Invalid:
        raise
    except (KeyError, TypeError, ValueError):
        raise _Invalid from None
    except Exception:
        # A service-status shape the shared validator refuses (``ControlProtocolError``).
        raise _Invalid from None


def agent_declaration_document(declaration: WorkspaceAgentDeclaration) -> bytes:
    """``POST /v1/agents`` body: the agent's offer, the same shape a hello's ``workspace_agent``."""

    if type(declaration) is not WorkspaceAgentDeclaration:
        raise TypeError("workspace_agent_invalid")
    return _encode(
        {
            "max_reply_bytes": declaration.max_reply_bytes,
            "operations": list(declaration.operations),
            "schema_version": declaration.schema_version,
        }
    )


def parse_agent_declaration(body: bytes) -> WorkspaceAgentDeclaration:
    document = _decode(body, frozenset({"max_reply_bytes", "operations", "schema_version"}))
    operations = document["operations"]
    if type(operations) is not list:
        raise _Invalid
    try:
        return WorkspaceAgentDeclaration(
            operations=tuple(cast(list[str], operations)),
            max_reply_bytes=cast(int, document["max_reply_bytes"]),
        )
    except (TypeError, ValueError):
        raise _Invalid from None


@dataclass(frozen=True, slots=True)
class AgentRegistration:
    """``201`` answer to ``POST /v1/agents``: the agent id and the handle it answers for."""

    agent_id: str
    workspace_handle: str
    lease_ms: int

    def __post_init__(self) -> None:
        if type(self.agent_id) is not str or not _AGENT_ID.fullmatch(self.agent_id):
            raise _Invalid
        if not workspace_handle_valid(self.workspace_handle):
            raise _Invalid
        if type(self.lease_ms) is not int or not 1_000 <= self.lease_ms <= 600_000:
            raise _Invalid


def new_agent_id() -> str:
    return f"agt_{secrets.token_hex(16)}"


def agent_id_valid(value: object) -> bool:
    return type(value) is str and _AGENT_ID.fullmatch(value) is not None


def agent_registration_document(registration: AgentRegistration) -> bytes:
    return _encode(
        {
            "agent_id": registration.agent_id,
            "lease_ms": registration.lease_ms,
            "schema_version": NETWORK_API_SCHEMA_VERSION,
            "workspace_handle": registration.workspace_handle,
        }
    )


def parse_agent_registration(body: bytes) -> AgentRegistration:
    document = _decode(
        body, frozenset({"agent_id", "lease_ms", "schema_version", "workspace_handle"})
    )
    try:
        return AgentRegistration(
            agent_id=cast(str, document["agent_id"]),
            workspace_handle=cast(str, document["workspace_handle"]),
            lease_ms=cast(int, document["lease_ms"]),
        )
    except (TypeError, ValueError):
        raise _Invalid from None


@dataclass(frozen=True, slots=True)
class AgentWork:
    """``GET /v1/agents/{id}/work``: the pending ``workspace_call`` frames, oldest first."""

    calls: tuple[Mapping[str, JsonValue], ...]


def agent_work_document(calls: tuple[Mapping[str, JsonValue], ...]) -> bytes:
    return _encode(
        {
            "calls": [cast(JsonValue, dict(call)) for call in calls],
            "schema_version": NETWORK_API_SCHEMA_VERSION,
        }
    )


def parse_agent_work(body: bytes, *, max_bytes: int) -> AgentWork:
    if type(body) is not bytes or len(body) > max_bytes:
        raise _Invalid
    try:
        value = strict_json_parse(body)
    except ValueError:
        raise _Invalid from None
    if type(value) is not dict:
        raise _Invalid
    document = cast(dict[str, JsonValue], value)
    if frozenset(document) != frozenset({"calls", "schema_version"}) or (
        document["schema_version"] != NETWORK_API_SCHEMA_VERSION
    ):
        raise _Invalid
    calls = document["calls"]
    if type(calls) is not list or any(type(call) is not dict for call in calls):
        raise _Invalid
    return AgentWork(tuple(cast(list[dict[str, JsonValue]], calls)))


def claim_principal_digest(claim: WorkspaceClaim, principal: str) -> WorkspaceClaim:
    """The claim as the service keys it for one principal (keys of one owner share a principal).

    Two principals presenting the same digest reach different repositories; a rotated key keeps
    its predecessor's principal, so rotation never strands a task.
    """

    if type(claim) is not WorkspaceClaim or type(principal) is not str or not principal:
        raise TypeError("workspace_claim_invalid")
    digest = hashlib.sha256(
        b"yoetz/claim-principal/v1\x00"
        + principal.encode("ascii")
        + b"\x00"
        + claim.digest.encode("ascii")
    ).hexdigest()
    return WorkspaceClaim(identity_kind=claim.identity_kind, digest="sha256:" + digest)
