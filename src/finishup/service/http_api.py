"""The service's own network API (ADR-051, server-native approach).

When the service's ``config.toml`` has a ``[network]`` table, the daemon serves a resource-shaped
HTTP API from its own event loop, next to its Unix control endpoint. Without that table nothing
here is imported and the service opens no network listener. Three kinds of listener exist:

* TCP addresses from ``listen`` speaking TLS (``tls_cert``/``tls_key``); plain HTTP only on a
  loopback address the owner opted into (``allow_plain_loopback``), behind a same-host TLS proxy.
* With ``api_socket = true``, an owner-only Unix socket ``<runtime>/api.sock`` that an SSH client
  forwards to. Its peer must be the service's own user; a request there acts as the owner with
  the ``operator`` scope and needs no key (SSH is owner-equivalent, ADR-051 decision 9).

Every TCP request carries ``Authorization: Bearer fuk_…``; keys are hashed in the service state
(``finishup.service.api_keys``) and each carries a scope. A request with an ``Origin`` header is
refused (browsers and DNS rebinding), and nothing answers before authentication.

The TCP listeners bound what an unauthenticated peer can hold before that: open connections in
total and per peer address (a connection over either cap is closed before TLS), the time from
accepting a connection (or answering its last request) to a complete request head, TLS handshake
included, and the time a request's body may take. The service raises its own descriptor limit and
keeps most descriptors for its control plane, ledgers and key file.

Routes (bodies and answers are canonical JSON; see ``finishup.service.network_protocol``):

* ``GET /v1/server`` — release, schema-manifest digest, the service status, the caller's key id,
  scope and transport, and the workspace binding of the request's claim.
* ``POST /v1/{method}`` — one control method. The body is the method's existing request body; the
  answer is its existing control-result body, byte-identical to what the control socket carries,
  with ``FinishUP-Outcome: ok|error``. A call still running after ``wait_ms`` answers ``202`` and
  ``Location: /v1/operations/{id}``; ``GET`` there long-polls it and ``DELETE`` cancels it.
* ``POST /v1/agents`` registers a workspace agent for the request's claim; ``GET
  /v1/agents/{id}/work`` long-polls its ``workspace_call`` frames; ``POST
  /v1/agents/{id}/replies`` delivers one ``workspace_reply``; ``DELETE /v1/agents/{id}`` ends it.

Out-of-scope methods answer the existing ``method_forbidden`` control error. Transport refusals
use closed ``rest-error`` reasons. Audit lines carry closed tokens only, never a body, a header
value, a key or an address.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import socket
import ssl
import stat
import time
from collections.abc import Awaitable, Callable, Mapping
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, Protocol, cast

from starlette.applications import Starlette
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

from finishup.adapters.control.unix_socket import LocalControlTransportError, authenticate_peer
from finishup.config.models import ConfigError, NetworkConfig, NetworkListenAddress
from finishup.domain.values import JsonObject, freeze_json
from finishup.observability.logging import (
    record_bounded_event_without_raising,
    record_unexpected_exception_without_raising,
)
from finishup.ports.control import (
    ControlCallRequest,
    ControlClientKind,
    ControlError,
    ControlMethod,
    ControlResult,
    RepositoryPrivacyContext,
    ServiceStatus,
    WorkspaceAgentDeclaration,
    WorkspaceBinding,
    WorkspaceCall,
    WorkspaceClaim,
    WorkspaceReply,
)
from finishup.ports.workspace_agent import MAX_WORKSPACE_FRAME_BYTES
from finishup.protocol.canonical import JsonValue, canonical_encode, strict_json_parse
from finishup.protocol.ids import IdKind, new_id, validate_id
from finishup.protocol.schemas import schema_manifest_digest
from finishup.service.api_keys import ApiKeyError, ApiKeyStore
from finishup.service.check_waits import EXPLICIT_CONTROL_CANCEL
from finishup.service.control_protocol import (
    CONTROL_PROTOCOL_VERSION,
    MAX_CONTROL_FRAME_BYTES,
    ControlProtocolError,
    encode_control_frame,
    parse_control_request,
    parse_workspace_reply,
    validate_result,
    workspace_call_frame,
)
from finishup.service.network_protocol import (
    AGENT_LEASE_MS,
    API_SOCKET_NAME,
    HEADER_CLAIM,
    HEADER_CLIENT_KIND,
    HEADER_DEADLINE_MS,
    HEADER_HOST_PROFILE,
    HEADER_OPERATION_ID,
    HEADER_OUTCOME,
    HEADER_ROUTE_PROFILE,
    HEADER_SERVICE_GENERATION,
    HEADER_SERVICE_INSTANCE,
    HEADER_WORKSPACE_HANDLE,
    NETWORK_API_SCHEMA_VERSION,
    OWNER_PRINCIPAL,
    REST_ERROR_STATUS,
    AgentRegistration,
    ApiScope,
    NetworkTransport,
    ServerInfo,
    agent_id_valid,
    agent_registration_document,
    agent_work_document,
    claim_principal_digest,
    method_allowed,
    new_agent_id,
    parse_agent_declaration,
    parse_claim_header,
    parse_client_kind,
    parse_host_profile,
    parse_wait_ms,
    rest_error_document,
    server_info_document,
)

if TYPE_CHECKING:
    import uvicorn

__all__ = [
    "API_SOCKET_NAME",
    "MAX_AGENTS_PER_KEY",
    "MAX_PENDING_OPERATIONS_PER_KEY",
    "MAX_RETAINED_OPERATIONS",
    "MAX_RETAINED_OPERATIONS_PER_KEY",
    "MAX_RETAINED_RESULT_BYTES",
    "MAX_TCP_CONNECTIONS",
    "MAX_TCP_CONNECTIONS_PER_PEER",
    "REQUEST_BODY_SECONDS",
    "REQUEST_HEAD_SECONDS",
    "NetworkApi",
    "NetworkApiBindings",
    "NetworkApiServer",
    "WorkspaceAgentRegistry",
]

MAX_PENDING_OPERATIONS_PER_KEY: Final = 32
MAX_AGENTS_PER_KEY: Final = 16
# A finished operation's answer stays retrievable this long (an answer lost on the way can be
# fetched again by its id); every request id is idempotent besides.
OPERATION_RESULT_SECONDS: Final = 120.0
# Finished answers are kept as their encoded bytes, at most this many per key and in all, and at
# most this many bytes in all; past any bound the oldest go first (a later GET for them answers
# ``operation_unknown``).
MAX_RETAINED_OPERATIONS_PER_KEY: Final = 64
MAX_RETAINED_OPERATIONS: Final = 1_024
MAX_RETAINED_RESULT_BYTES: Final = 64 * 1024 * 1024
# An operation id whose answer was dropped stays spent this long, so a late duplicate is refused
# (``operation_unknown``) rather than dispatched again; at most this many are remembered.
SPENT_OPERATION_SECONDS: Final = 900.0
MAX_SPENT_OPERATIONS: Final = 16_384
_AGENT_QUEUE_CAPACITY: Final = 64
_MAX_CALLS_PER_POLL: Final = 16
_SWEEP_SECONDS: Final = 5.0
_COMPONENT: Final = "service.http_api"
_LISTEN_BACKLOG: Final = 128
_API_SOCKET_MODE: Final = 0o600
_JSON: Final = "application/json"
# Request bodies: one control frame for a call, one workspace frame for a reply.
_MAX_CALL_BODY_BYTES: Final = MAX_CONTROL_FRAME_BYTES
_MAX_SMALL_BODY_BYTES: Final = 65_536
_CALLER_SCOPE_KEY: Final = "finishup.caller"
_HTTP_SERVER_LOGGERS: Final = ("uvicorn", "uvicorn.error", "uvicorn.access", "uvicorn.asgi")
# Open TCP connections over every listener, and from one peer address; a connection over either
# cap is closed at once, before TLS and before a byte is read (ADR-051, "256 concurrent
# connections"). Both shrink with the descriptor budget (``_tcp_connection_budget``).
MAX_TCP_CONNECTIONS: Final = 256
MAX_TCP_CONNECTIONS_PER_PEER: Final = 64
# A TCP connection finishes TLS and sends a complete request head this soon after it is accepted
# or answered, and a request's body arrives this soon after its head; otherwise it is closed. A
# request the API is serving (a long-poll, say) has no such bound.
REQUEST_HEAD_SECONDS: Final = 10.0
REQUEST_BODY_SECONDS: Final = 120.0
# The soft descriptor limit the service asks for when it listens on TCP; at most a quarter of
# the limit it gets goes to the API's TCP connections.
_DESCRIPTOR_TARGET: Final = 4_096
_DESCRIPTOR_SHARE: Final = 4


class WorkspaceAgentRegistry(Protocol):
    """The service's registry of workspace agents (``service.workspace_hub.WorkspaceAgentHub``).

    A REST agent registers one in-process channel whose ``writer`` queues each ``workspace_call``
    for the agent's next long-poll; its replies come back through ``deliver``. ``worktree`` is the
    claim's worktree digest: the hub never admits an agent for another worktree under a live
    handle.
    """

    async def register(
        self,
        *,
        handle: str,
        declaration: WorkspaceAgentDeclaration,
        service_instance_id: str,
        service_generation: str,
        writer: Callable[[WorkspaceCall], Awaitable[None]],
        worktree: str | None = None,
    ) -> Any: ...

    def deliver(self, channel: Any, reply: WorkspaceReply) -> None: ...

    async def unregister(self, channel: Any) -> None: ...


type _Dispatch = Callable[
    [ControlClientKind, ControlCallRequest, RepositoryPrivacyContext | None],
    Awaitable[ControlResult],
]
type _ClaimResolver = Callable[[WorkspaceClaim], Awaitable[RepositoryPrivacyContext | None]]


@dataclass(frozen=True, slots=True)
class NetworkApiBindings:
    """What the network API needs from the daemon that serves it.

    ``activity`` holds the daemon's idle shutdown for as long as a request or a registered agent
    is active, as an open control connection does. ``claim_resolver`` and ``agent_hub`` are the
    workspace-remoting seams (``ServiceDaemon._network_api_bindings``).
    """

    status: Callable[[], ServiceStatus]
    dispatch: _Dispatch
    activity: Callable[[], AbstractAsyncContextManager[None]]
    claim_resolver: _ClaimResolver | None = None
    agent_hub: WorkspaceAgentRegistry | None = None


class _Refusal(Exception):
    def __init__(self, reason: str) -> None:
        if reason not in REST_ERROR_STATUS:
            raise ValueError("rest_error_reason_invalid")
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True, slots=True)
class _Caller:
    """Who a request acts as: its key (none on the owner socket), scope and principal."""

    key_id: str | None
    scope: ApiScope
    principal: str
    transport: NetworkTransport

    @property
    def owner_key(self) -> str:
        """What operations and agents are filed under: the key id, or the owner socket."""

        return self.key_id if self.key_id is not None else OWNER_PRINCIPAL


@dataclass(frozen=True, slots=True)
class _Answer:
    """A finished operation's answer, kept as the bytes it is sent as (``body`` None: unframable)."""

    body: bytes | None
    outcome: str
    service_instance_id: str
    service_generation: str


@dataclass(slots=True)
class _Operation:
    """One admitted call: its task while it runs, then only its encoded answer."""

    operation_id: str
    owner_key: str
    task: asyncio.Task[ControlResult] | None
    request: ControlCallRequest | None
    workspace_handle: str | None
    finished_at: float | None = None
    answer: _Answer | None = None


@dataclass(slots=True)
class _Admission:
    """An operation id being admitted: a duplicate waits for it rather than dispatching again."""

    owner_key: str
    settled: asyncio.Event = field(default_factory=asyncio.Event)


@dataclass(slots=True)
class _Agent:
    agent_id: str
    owner_key: str
    key_id: str | None
    workspace_handle: str
    declaration: WorkspaceAgentDeclaration
    channel: object
    calls: asyncio.Queue[WorkspaceCall]
    lease_expires: float
    exit_stack: contextlib.AsyncExitStack = field(default_factory=contextlib.AsyncExitStack)


def _error_response(reason: str) -> Response:
    return Response(
        rest_error_document(reason),
        status_code=REST_ERROR_STATUS[reason],
        media_type=_JSON,
        headers={"cache-control": "no-store"},
    )


def _audit(operation: str, reason: str, context: Mapping[str, object] | None = None) -> None:
    record_bounded_event_without_raising(
        component=_COMPONENT, operation=operation, reason=reason, context=context
    )


def _single_header(request: Request, name: str) -> str | None:
    values = request.headers.getlist(name)
    if len(values) > 1:
        raise _Refusal("header_invalid")
    return values[0] if values else None


async def _read_body(request: Request, limit: int) -> bytes:
    declared = _single_header(request, "content-length")
    if declared is not None:
        if not declared.isascii() or not declared.isdigit() or len(declared) > 12:
            raise _Refusal("header_invalid")
        if int(declared) > limit:
            raise _Refusal("frame_too_large")
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > limit:
            raise _Refusal("frame_too_large")
        chunks.append(chunk)
    return b"".join(chunks)


def _json_object(body: bytes) -> dict[str, JsonValue]:
    try:
        value = strict_json_parse(body)
    except ValueError:
        raise _Refusal("frame_invalid") from None
    if type(value) is not dict:
        raise _Refusal("frame_invalid")
    return cast(dict[str, JsonValue], value)


def _wait_ms(request: Request) -> int:
    values = request.query_params.getlist("wait_ms")
    if len(values) > 1 or set(request.query_params) - {"wait_ms"}:
        raise _Refusal("header_invalid")
    try:
        return parse_wait_ms(values[0] if values else None)
    except ValueError:
        raise _Refusal("header_invalid") from None


def _result_body(result: ControlResult) -> bytes:
    """The result's body exactly as the control socket frames it (canonical JSON is
    compositional, so the sub-object encodes to the same bytes it occupies in the frame)."""

    frame = encode_control_frame(result)
    parsed = strict_json_parse(frame[4:])
    return canonical_encode(cast(dict[str, JsonValue], parsed)["body"])


class NetworkApi:
    """The routes, the operations still running, and the registered workspace agents."""

    def __init__(
        self,
        bindings: NetworkApiBindings,
        keys: ApiKeyStore,
        *,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], datetime] | None = None,
    ) -> None:
        if type(bindings) is not NetworkApiBindings:
            raise TypeError("network_api_bindings_invalid")
        self._bindings = bindings
        self._keys = keys
        self._clock = clock
        self._wall_clock = wall_clock or (lambda: datetime.now(UTC))
        self._operations: dict[str, _Operation] = {}
        self._admitting: dict[str, _Admission] = {}
        # Operation ids whose answer was dropped: id -> (owner key, until), oldest first.
        self._spent: dict[str, tuple[str, float]] = {}
        self._agents: dict[str, _Agent] = {}
        self._closing = asyncio.Event()
        self._sweeper: asyncio.Task[None] | None = None
        endpoint = self._endpoint
        self._router = Starlette(
            routes=[
                Route("/v1/server", endpoint(self._server), methods=["GET"]),
                Route("/v1/agents", endpoint(self._register_agent), methods=["POST"]),
                Route("/v1/agents/{agent_id}/work", endpoint(self._agent_work), methods=["GET"]),
                Route(
                    "/v1/agents/{agent_id}/replies", endpoint(self._agent_reply), methods=["POST"]
                ),
                Route("/v1/agents/{agent_id}", endpoint(self._end_agent), methods=["DELETE"]),
                Route("/v1/operations/{operation_id}", endpoint(self._operation), methods=["GET"]),
                Route(
                    "/v1/operations/{operation_id}",
                    endpoint(self._cancel_operation),
                    methods=["DELETE"],
                ),
                Route("/v1/{method}", endpoint(self._call), methods=["POST"]),
            ],
            exception_handlers={HTTPException: self._http_exception},
        )

    def __repr__(self) -> str:
        return "NetworkApi(<redacted>)"

    # --- ASGI entry ---------------------------------------------------------------------------

    def asgi(self, transport: NetworkTransport) -> ASGIApp:
        """The ASGI application of one listener; ``transport`` is how its requests arrive."""

        if transport not in {"https", "http", "unix"}:
            raise ValueError("network_transport_invalid")

        async def application(scope: Scope, receive: Receive, send: Send) -> None:
            if scope.get("type") != "http":
                # Websockets are off in the server; lifespan is not used. Nothing else is served.
                return
            request = Request(scope, receive)
            try:
                caller = self._authenticate(request, transport)
            except _Refusal as refusal:
                _audit("network_refusal", refusal.reason)
                await _error_response(refusal.reason)(scope, receive, send)
                return
            scope[_CALLER_SCOPE_KEY] = caller
            await self._router(scope, receive, send)

        return application

    def _authenticate(self, request: Request, transport: NetworkTransport) -> _Caller:
        if request.headers.getlist("origin"):
            raise _Refusal("origin_forbidden")
        if transport == "unix":
            return _Caller(None, "operator", OWNER_PRINCIPAL, "unix")
        authorization = _single_header(request, "authorization")
        if authorization is None or not authorization.startswith("Bearer "):
            raise _Refusal("api_key_invalid")
        try:
            record = self._keys.authenticate(
                authorization.removeprefix("Bearer "), now=self._wall_clock()
            )
        except ApiKeyError as error:
            reason = error.reason
            if reason not in {"api_key_invalid", "api_key_revoked", "api_key_expired"}:
                # The key file itself is unusable: no request is authenticated until it is fixed.
                raise _Refusal("server_keys_unusable") from None
            raise _Refusal(reason) from None
        return _Caller(record.key_id, record.scope, record.principal, transport)

    async def _http_exception(self, request: Request, exc: Exception) -> Response:
        del request
        status = exc.status_code if isinstance(exc, HTTPException) else 500
        return _error_response(
            "route_unknown"
            if status == 404
            else "method_not_allowed"
            if status == 405
            else "frame_invalid"
        )

    @staticmethod
    def _endpoint(
        handler: Callable[[Request], Awaitable[Response]],
    ) -> Callable[[Request], Awaitable[Response]]:
        """Answer a refusal with its closed reason and anything unexpected with a bounded 500."""

        async def run(request: Request) -> Response:
            try:
                return await handler(request)
            except _Refusal as refusal:
                _audit("network_refusal", refusal.reason)
                return _error_response(refusal.reason)
            except Exception as exc:
                record_unexpected_exception_without_raising(
                    exc, component=_COMPONENT, operation="network_request"
                )
                return _error_response("internal_failure")

        return run

    @staticmethod
    def _caller(request: Request) -> _Caller:
        return cast(_Caller, request.scope[_CALLER_SCOPE_KEY])

    # --- workspace claims ---------------------------------------------------------------------

    async def _claim(
        self, request: Request, caller: _Caller
    ) -> tuple[WorkspaceBinding, RepositoryPrivacyContext | None]:
        """The request's workspace binding: none, or the caller's claim keyed by its principal.

        Nothing here resolves a path: a claim names a workspace on the client's machine, and the
        service only derives its own commitment from it.
        """

        raw = _single_header(request, HEADER_CLAIM)
        if raw is None:
            return "none", None
        try:
            claim = parse_claim_header(raw)
        except ValueError:
            raise _Refusal("header_invalid") from None
        resolver = self._bindings.claim_resolver
        if resolver is None:
            return "client_claim", None
        context = await resolver(claim_principal_digest(claim, caller.principal))
        if context is not None and (
            type(context) is not RepositoryPrivacyContext
            or context.identity_kind != "client_claim"
            or context.workspace_locator is not None
        ):
            raise _Refusal("internal_failure")
        return "client_claim", context

    # --- GET /v1/server -----------------------------------------------------------------------

    async def _server(self, request: Request) -> Response:
        caller = self._caller(request)
        binding, context = await self._claim(request, caller)
        status = self._bindings.status()
        info = ServerInfo(
            release=status.service_version,
            schema_manifest_digest=schema_manifest_digest(),
            status=status,
            key_id=caller.key_id,
            scope=caller.scope,
            transport=caller.transport,
            workspace_binding=binding,
            workspace_handle=None if context is None else context.workspace_handle,
        )
        return Response(
            server_info_document(info),
            media_type=_JSON,
            headers={"cache-control": "no-store"},
        )

    # --- POST /v1/{method} --------------------------------------------------------------------

    def _generation(self, request: Request) -> tuple[str, str]:
        """The service instance and generation a call is addressed to.

        A client that read ``GET /v1/server`` names them, and a call addressed to an earlier
        generation answers ``service_generation_changed`` exactly as on the socket; a request
        without them is addressed to the current one.
        """

        instance = _single_header(request, HEADER_SERVICE_INSTANCE)
        generation = _single_header(request, HEADER_SERVICE_GENERATION)
        if (instance is None) is not (generation is None):
            raise _Refusal("header_invalid")
        if instance is not None and generation is not None:
            try:
                validate_id(IdKind.SERVICE_INSTANCE, instance)
            except (TypeError, ValueError):
                raise _Refusal("header_invalid") from None
            if not generation.isascii() or not generation.isdigit() or len(generation) > 20:
                raise _Refusal("header_invalid")
            return instance, generation
        status = self._bindings.status()
        return status.service_instance_id, status.service_generation

    def _call_request(
        self,
        request: Request,
        method: ControlMethod,
        body: dict[str, JsonValue],
        rpc_id: str,
        addressed: tuple[str, str],
    ) -> ControlCallRequest:
        wire: dict[str, JsonValue] = {
            "body": body,
            "kind": "call",
            "method": method.value,
            "protocol_version": CONTROL_PROTOCOL_VERSION,
            "rpc_id": rpc_id,
            "service_generation": addressed[1],
            "service_instance_id": addressed[0],
        }
        deadline = _single_header(request, HEADER_DEADLINE_MS)
        if deadline is not None:
            if not deadline.isascii() or not deadline.isdigit() or len(deadline) > 7:
                raise _Refusal("header_invalid")
            wire["deadline_ms"] = int(deadline)
        route = _single_header(request, HEADER_ROUTE_PROFILE)
        if route is not None:
            if route not in {"policy", "strict"}:
                raise _Refusal("header_invalid")
            wire["route_profile"] = route
        try:
            host = parse_host_profile(_single_header(request, HEADER_HOST_PROFILE))
        except ValueError:
            raise _Refusal("header_invalid") from None
        if host is not None:
            wire["host_profile"] = host
        try:
            frozen = freeze_json(wire)
            if type(frozen) is not JsonObject:
                raise _Refusal("frame_invalid")
            parsed = parse_control_request(frozen)
            # The ordinary frame bounds hold over the network exactly as on the socket.
            encode_control_frame(parsed)
        except ControlProtocolError as error:
            raise _Refusal(
                "frame_too_large" if error.reason == "frame_too_large" else "frame_invalid"
            ) from None
        except (TypeError, ValueError):
            raise _Refusal("frame_invalid") from None
        if not isinstance(parsed, ControlCallRequest):
            raise _Refusal("frame_invalid")
        return parsed

    async def _call(self, request: Request) -> Response:
        caller = self._caller(request)
        try:
            method = ControlMethod(request.path_params["method"])
        except ValueError:
            raise _Refusal("route_unknown") from None
        try:
            client_kind = parse_client_kind(_single_header(request, HEADER_CLIENT_KIND))
        except ValueError:
            raise _Refusal("header_invalid") from None
        wait_ms = _wait_ms(request)
        operation_id = _single_header(request, HEADER_OPERATION_ID)
        admission: _Admission | None = None
        if operation_id is not None:
            try:
                validate_id(IdKind.CONTROL_RPC, operation_id)
            except (TypeError, ValueError):
                raise _Refusal("header_invalid") from None
            while True:
                existing = self._known_operation(operation_id, caller)
                if existing is not None:
                    # At most once: an id already admitted answers with that operation.
                    return await self._answer(existing, wait_ms)
                admitting = self._admitting.get(operation_id)
                if admitting is None:
                    break
                if admitting.owner_key != caller.owner_key:
                    raise _Refusal("header_invalid")
                # The same id is being admitted on another request: its outcome decides.
                await admitting.settled.wait()
            # Reserved before anything is awaited, so a concurrent duplicate waits for it.
            admission = _Admission(caller.owner_key)
            self._admitting[operation_id] = admission
        try:
            operation = await self._admit(request, caller, method, client_kind, operation_id)
        finally:
            if admission is not None and operation_id is not None:
                if self._admitting.get(operation_id) is admission:
                    del self._admitting[operation_id]
                admission.settled.set()
        if isinstance(operation, Response):
            return operation
        return await self._answer(operation, wait_ms)

    def _known_operation(self, operation_id: str, caller: _Caller) -> _Operation | None:
        """The operation an id already names for this caller; a spent id is refused."""

        existing = self._operations.get(operation_id)
        spent = self._spent.get(operation_id)
        owner = existing.owner_key if existing is not None else None if spent is None else spent[0]
        if owner is not None and owner != caller.owner_key:
            raise _Refusal("header_invalid")
        if existing is None and spent is not None:
            # Its answer was dropped: it is never dispatched again.
            raise _Refusal("operation_unknown")
        return existing

    async def _admit(
        self,
        request: Request,
        caller: _Caller,
        method: ControlMethod,
        client_kind: ControlClientKind,
        operation_id: str | None,
    ) -> _Operation | Response:
        """Check, read and dispatch one call; a refusal before dispatch is answered at once."""

        binding, context = await self._claim(request, caller)
        handle = None if context is None else context.workspace_handle
        addressed = self._generation(request)
        rpc_id = operation_id or new_id(IdKind.CONTROL_RPC)
        if not method_allowed(caller.scope, method, claim_bound=context is not None):
            # The key's scope, not the client's own word, bounds its methods. The answer is the
            # control protocol's own refusal, before any body is read or dispatched.
            _audit(
                "network_call",
                "method_forbidden",
                {"control_method": method.value, "client_kind": client_kind.value},
            )
            forbidden = self._error_result(
                rpc_id, addressed, method, ControlError("method_forbidden")
            )
            return self._result_response(forbidden, operation_id=rpc_id, workspace_handle=handle)
        body = _json_object(await _read_body(request, _MAX_CALL_BODY_BYTES))
        if method is ControlMethod.START:
            self._require_portable_start(body, caller, binding, handle)
        call = self._call_request(request, method, body, rpc_id, addressed)
        self._purge()
        pending = sum(
            1
            for item in self._operations.values()
            if item.owner_key == caller.owner_key and item.answer is None
        )
        if pending >= MAX_PENDING_OPERATIONS_PER_KEY:
            raise _Refusal("operation_limit")
        task = asyncio.create_task(self._dispatch(client_kind, call, context))
        operation = _Operation(call.rpc_id, caller.owner_key, task, call, handle)
        task.add_done_callback(lambda _task: self._finished(operation))
        self._operations[call.rpc_id] = operation
        self._ensure_sweeper()
        return operation

    @staticmethod
    def _require_portable_start(
        body: Mapping[str, JsonValue],
        caller: _Caller,
        binding: WorkspaceBinding,
        handle: str | None,
    ) -> None:
        """A start over the network never names a path, and a keyed one carries its claim.

        The only workspace a network start may name is this request's own ``client:`` handle; a
        path (or another handle) is refused before dispatch, so the service never resolves a path
        for a network caller, with or without a claim. A keyed caller must also send its claim:
        its tasks are then keyed by its principal's commitment, so it can neither create nor
        attach to a task bound to another principal's repository, the server owner's included.
        The owner's API socket (SSH, owner-equivalent) may start without a claim.
        """

        reference = body.get("workspace_ref")
        if reference is not None and (handle is None or reference != handle):
            _audit("network_call", "workspace_ref_not_portable", {"control_method": "start"})
            raise _Refusal("frame_invalid")
        if caller.key_id is not None and binding == "none":
            _audit("network_call", "workspace_claim_required", {"control_method": "start"})
            raise _Refusal("workspace_claim_required")

    async def _dispatch(
        self,
        client_kind: ControlClientKind,
        call: ControlCallRequest,
        context: RepositoryPrivacyContext | None,
    ) -> ControlResult:
        started = time.monotonic()
        try:
            async with self._bindings.activity():
                result = await self._bindings.dispatch(client_kind, call, context)
        except asyncio.CancelledError:
            result = self._call_error(call, ControlError("request_cancelled", retryable=True))
        except Exception as exc:
            from finishup.service.lifecycle import LifecycleError

            if isinstance(exc, LifecycleError):
                result = self._call_error(call, ControlError("service_draining", retryable=True))
            else:
                correlation_id = record_unexpected_exception_without_raising(
                    exc, component=_COMPONENT, operation="network_dispatch"
                )
                result = self._call_error(
                    call, ControlError("internal_error", correlation_id=correlation_id)
                )
        _audit(
            "network_call",
            result.outcome,
            {
                "control_method": call.method.value,
                "client_kind": client_kind.value,
                "duration_ms": max(0, int((time.monotonic() - started) * 1_000)),
            },
        )
        return result

    @staticmethod
    def _error_result(
        rpc_id: str, addressed: tuple[str, str], method: ControlMethod, error: ControlError
    ) -> ControlResult:
        result = ControlResult(
            protocol_version=CONTROL_PROTOCOL_VERSION,
            rpc_id=rpc_id,
            service_instance_id=addressed[0],
            service_generation=addressed[1],
            method=method,
            outcome="error",
            body=error,
        )
        validate_result(result)
        return result

    @classmethod
    def _call_error(cls, call: ControlCallRequest, error: ControlError) -> ControlResult:
        return cls._error_result(
            call.rpc_id, (call.service_instance_id, call.service_generation), call.method, error
        )

    def _finished(self, operation: _Operation) -> None:
        """Keep only the finished call's encoded answer, then hold the retained answers' bounds."""

        task, request = operation.task, operation.request
        if operation.answer is not None or task is None or request is None or not task.done():
            return
        result = (
            # Cancelled before its first step ran, the call never reached the daemon.
            self._call_error(request, ControlError("request_cancelled", retryable=True))
            if task.cancelled()
            else task.result()
        )
        try:
            body: bytes | None = _result_body(result)
        except ControlProtocolError:
            # A result this service cannot frame is its own defect; the socket would drop it too.
            body = None
        operation.answer = _Answer(
            body, result.outcome, result.service_instance_id, result.service_generation
        )
        operation.task = None
        operation.request = None
        operation.finished_at = self._clock()
        self._retain()

    def _drop_answer(self, operation_id: str, now: float) -> None:
        operation = self._operations.pop(operation_id, None)
        if operation is None:
            return
        self._spent.pop(operation_id, None)
        self._spent[operation_id] = (operation.owner_key, now + SPENT_OPERATION_SECONDS)
        while len(self._spent) > MAX_SPENT_OPERATIONS:
            del self._spent[next(iter(self._spent))]

    def _retain(self) -> None:
        """Drop the oldest finished answers past the per-key, total and byte bounds."""

        now = self._clock()
        finished = sorted(
            (item for item in self._operations.values() if item.answer is not None),
            key=lambda item: cast(float, item.finished_at),
        )
        per_key: dict[str, int] = {}
        for item in finished:
            per_key[item.owner_key] = per_key.get(item.owner_key, 0) + 1
        total = len(finished)
        size = sum(len(cast(_Answer, item.answer).body or b"") for item in finished)
        for item in finished:
            if (
                per_key[item.owner_key] <= MAX_RETAINED_OPERATIONS_PER_KEY
                and total <= MAX_RETAINED_OPERATIONS
                and size <= MAX_RETAINED_RESULT_BYTES
            ):
                continue
            per_key[item.owner_key] -= 1
            total -= 1
            size -= len(cast(_Answer, item.answer).body or b"")
            self._drop_answer(item.operation_id, now)

    def _purge(self) -> None:
        now = self._clock()
        for operation_id, operation in tuple(self._operations.items()):
            if (
                operation.finished_at is not None
                and now - operation.finished_at >= OPERATION_RESULT_SECONDS
            ):
                self._drop_answer(operation_id, now)
        for operation_id, (_owner, until) in tuple(self._spent.items()):
            if until <= now:
                del self._spent[operation_id]

    async def _answer(self, operation: _Operation, wait_ms: int) -> Response:
        task = operation.task
        if task is not None and not task.done() and wait_ms > 0:
            closing = asyncio.ensure_future(self._closing.wait())
            try:
                await asyncio.wait(
                    {task, closing},
                    timeout=wait_ms / 1_000,
                    return_when=asyncio.FIRST_COMPLETED,
                )
            finally:
                closing.cancel()
        # A task that just ended may not have run its done callback yet.
        self._finished(operation)
        answer = operation.answer
        if answer is None:
            return Response(
                canonical_encode(
                    {
                        "operation_id": operation.operation_id,
                        "schema_version": NETWORK_API_SCHEMA_VERSION,
                        "state": "pending",
                    }
                ),
                status_code=202,
                media_type=_JSON,
                headers={
                    "cache-control": "no-store",
                    "location": f"/v1/operations/{operation.operation_id}",
                    HEADER_OPERATION_ID: operation.operation_id,
                },
            )
        return self._answer_response(
            answer,
            operation_id=operation.operation_id,
            workspace_handle=operation.workspace_handle,
        )

    def _result_response(
        self, result: ControlResult, *, operation_id: str, workspace_handle: str | None
    ) -> Response:
        try:
            body: bytes | None = _result_body(result)
        except ControlProtocolError:
            body = None
        answer = _Answer(
            body, result.outcome, result.service_instance_id, result.service_generation
        )
        return self._answer_response(
            answer, operation_id=operation_id, workspace_handle=workspace_handle
        )

    @staticmethod
    def _answer_response(
        answer: _Answer, *, operation_id: str, workspace_handle: str | None
    ) -> Response:
        if answer.body is None:
            # A result this service cannot frame is its own defect; the socket would drop it too.
            raise _Refusal("internal_failure")
        headers = {
            "cache-control": "no-store",
            HEADER_OUTCOME: answer.outcome,
            HEADER_OPERATION_ID: operation_id,
            HEADER_SERVICE_INSTANCE: answer.service_instance_id,
            HEADER_SERVICE_GENERATION: answer.service_generation,
        }
        if workspace_handle is not None:
            headers[HEADER_WORKSPACE_HANDLE] = workspace_handle
        return Response(answer.body, media_type=_JSON, headers=headers)

    def _owned_operation(self, request: Request) -> _Operation:
        caller = self._caller(request)
        operation = self._operations.get(request.path_params["operation_id"])
        if operation is None or operation.owner_key != caller.owner_key:
            raise _Refusal("operation_unknown")
        return operation

    async def _operation(self, request: Request) -> Response:
        wait_ms = _wait_ms(request)
        self._purge()
        return await self._answer(self._owned_operation(request), wait_ms)

    async def _cancel_operation(self, request: Request) -> Response:
        operation = self._owned_operation(request)
        if operation.task is not None and not operation.task.done():
            operation.task.cancel(EXPLICIT_CONTROL_CANCEL)
        return Response(status_code=204, headers={"cache-control": "no-store"})

    # --- workspace agents ---------------------------------------------------------------------

    async def _register_agent(self, request: Request) -> Response:
        caller = self._caller(request)
        raw_claim = _single_header(request, HEADER_CLAIM)
        if raw_claim is None:
            raise _Refusal("workspace_claim_required")
        _binding, context = await self._claim(request, caller)
        hub = self._bindings.agent_hub
        if hub is None or context is None:
            # No registry of agents yet, or the service cannot key the claim now (locked vault).
            raise _Refusal("workspace_agent_unavailable")
        try:
            declaration = parse_agent_declaration(await _read_body(request, _MAX_SMALL_BODY_BYTES))
        except ValueError:
            raise _Refusal("frame_invalid") from None
        if (
            sum(1 for agent in self._agents.values() if agent.owner_key == caller.owner_key)
            >= MAX_AGENTS_PER_KEY
        ):
            raise _Refusal("agent_limit")
        handle = context.workspace_handle
        # ``_claim`` parsed it already. Its worktree digest is what tells linked worktrees of one
        # repository apart; the hub refuses an agent for another worktree under a live handle.
        worktree = parse_claim_header(raw_claim).worktree
        if handle is None:
            raise _Refusal("internal_failure")
        calls: asyncio.Queue[WorkspaceCall] = asyncio.Queue(maxsize=_AGENT_QUEUE_CAPACITY)

        async def writer(call: WorkspaceCall) -> None:
            # The hub bounds calls in flight per channel well below this capacity.
            calls.put_nowait(call)

        status = self._bindings.status()
        agent = _Agent(
            agent_id=new_agent_id(),
            owner_key=caller.owner_key,
            key_id=caller.key_id,
            workspace_handle=handle,
            declaration=declaration,
            channel=None,
            calls=calls,
            lease_expires=self._clock() + AGENT_LEASE_MS / 1_000,
        )
        try:
            # A registered agent holds the service up like an open agent connection does.
            await agent.exit_stack.enter_async_context(self._bindings.activity())
            agent.channel = await hub.register(
                handle=handle,
                declaration=declaration,
                service_instance_id=status.service_instance_id,
                service_generation=status.service_generation,
                writer=writer,
                worktree=worktree,
            )
        except Exception:
            await agent.exit_stack.aclose()
            raise _Refusal("service_unavailable") from None
        self._agents[agent.agent_id] = agent
        self._ensure_sweeper()
        _audit("workspace_agent_registered", "registered")
        registration = AgentRegistration(agent.agent_id, handle, AGENT_LEASE_MS)
        return Response(
            agent_registration_document(registration),
            status_code=201,
            media_type=_JSON,
            headers={"cache-control": "no-store", "location": f"/v1/agents/{agent.agent_id}"},
        )

    def _owned_agent(self, request: Request) -> _Agent:
        caller = self._caller(request)
        agent_id = request.path_params["agent_id"]
        agent = self._agents.get(agent_id) if agent_id_valid(agent_id) else None
        if agent is None or agent.owner_key != caller.owner_key:
            raise _Refusal("agent_unknown")
        agent.lease_expires = self._clock() + AGENT_LEASE_MS / 1_000
        return agent

    async def _agent_work(self, request: Request) -> Response:
        wait_ms = _wait_ms(request)
        agent = self._owned_agent(request)
        calls: list[WorkspaceCall] = []
        if agent.calls.empty() and wait_ms > 0:
            getter = asyncio.ensure_future(agent.calls.get())
            closing = asyncio.ensure_future(self._closing.wait())
            try:
                done, _pending = await asyncio.wait(
                    {getter, closing}, timeout=wait_ms / 1_000, return_when=asyncio.FIRST_COMPLETED
                )
                if getter in done:
                    calls.append(getter.result())
            finally:
                closing.cancel()
                if not getter.done():
                    getter.cancel()
                elif not getter.cancelled() and not calls:
                    # The call arrived as the wait ended: keep it for the next poll.
                    calls.append(getter.result())
        frames: list[Mapping[str, JsonValue]] = []
        size = 0
        for call in calls:
            frame = workspace_call_frame(call)
            frames.append(frame)
            size += len(canonical_encode(dict(frame)))
        while len(frames) < _MAX_CALLS_PER_POLL and not agent.calls.empty():
            frame = workspace_call_frame(agent.calls.get_nowait())
            frames.append(frame)
            size += len(canonical_encode(dict(frame)))
            if size >= MAX_WORKSPACE_FRAME_BYTES:
                break
        agent.lease_expires = self._clock() + AGENT_LEASE_MS / 1_000
        return Response(
            agent_work_document(tuple(frames)),
            media_type=_JSON,
            headers={"cache-control": "no-store"},
        )

    async def _agent_reply(self, request: Request) -> Response:
        agent = self._owned_agent(request)
        body = await _read_body(request, agent.declaration.max_reply_bytes)
        try:
            frozen = freeze_json(_json_object(body))
            if type(frozen) is not JsonObject:
                raise _Refusal("frame_invalid")
            reply = parse_workspace_reply(frozen)
        except ControlProtocolError:
            raise _Refusal("frame_invalid") from None
        except (TypeError, ValueError):
            raise _Refusal("frame_invalid") from None
        hub = self._bindings.agent_hub
        if hub is not None:
            hub.deliver(agent.channel, reply)
        return Response(status_code=202, headers={"cache-control": "no-store"})

    async def _end_agent(self, request: Request) -> Response:
        agent = self._owned_agent(request)
        await self._unregister(agent, "ended")
        return Response(status_code=204, headers={"cache-control": "no-store"})

    async def _unregister(self, agent: _Agent, reason: str) -> None:
        if self._agents.pop(agent.agent_id, None) is None:
            return
        hub = self._bindings.agent_hub
        try:
            if hub is not None and agent.channel is not None:
                await hub.unregister(agent.channel)
        finally:
            await agent.exit_stack.aclose()
        _audit("workspace_agent_unregistered", reason)

    def _ensure_sweeper(self) -> None:
        if self._sweeper is None or self._sweeper.done():
            self._sweeper = asyncio.create_task(self._sweep())

    async def _sweep(self) -> None:
        """Drop expired answers, and end agents whose lease ran out or whose key ended."""

        while (self._agents or self._operations or self._spent) and not self._closing.is_set():
            await asyncio.sleep(_SWEEP_SECONDS)
            self._purge()
            await self.sweep_once()

    async def sweep_once(self) -> None:
        now = self._clock()
        wall = self._wall_clock()
        for agent in tuple(self._agents.values()):
            if agent.lease_expires <= now:
                await self._unregister(agent, "lease_expired")
            elif agent.key_id is not None and not self._keys.is_active(agent.key_id, now=wall):
                await self._unregister(agent, "key_inactive")

    # --- lifecycle ----------------------------------------------------------------------------

    async def close(self) -> None:
        """Answer every long-poll, cancel running calls, and end every registered agent."""

        self._closing.set()
        running = [
            operation.task
            for operation in self._operations.values()
            if operation.task is not None and not operation.task.done()
        ]
        for task in running:
            task.cancel(EXPLICIT_CONTROL_CANCEL)
        await asyncio.gather(*running, return_exceptions=True)
        for agent in tuple(self._agents.values()):
            with contextlib.suppress(Exception):
                await self._unregister(agent, "service_stopping")
        if self._sweeper is not None:
            self._sweeper.cancel()
            await asyncio.gather(self._sweeper, return_exceptions=True)


# --- listeners ----------------------------------------------------------------------------------


def _tls_context(cert: str, key: str) -> ssl.SSLContext:
    """A TLS 1.2+ server context; the key file must be the owner's and owner-only."""

    try:
        facts = Path(key).lstat()
    except OSError:
        raise ConfigError("network_tls_unusable") from None
    if (
        not stat.S_ISREG(facts.st_mode)
        or facts.st_uid != os.geteuid()
        or stat.S_IMODE(facts.st_mode) & 0o077
    ):
        raise ConfigError("network_tls_unusable")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        context.load_cert_chain(cert, key)
    except (OSError, ssl.SSLError):
        raise ConfigError("network_tls_unusable") from None
    return context


def _bind_tcp(address: NetworkListenAddress) -> socket.socket:
    family = socket.AF_INET6 if ":" in address.host else socket.AF_INET
    # Name TCP explicitly: asyncio turns Nagle off (TCP_NODELAY) only for accepted sockets whose
    # protocol is IPPROTO_TCP, and an accepted socket inherits the listener's. With protocol 0
    # every TLS response waited on the client's delayed ACK, about 40 ms per request.
    raw = socket.socket(family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    try:
        raw.set_inheritable(False)
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            raw.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        raw.bind((address.host, address.port))
        raw.listen(_LISTEN_BACKLOG)
        raw.setblocking(False)
    except OSError:
        raw.close()
        raise ConfigError("network_listener_unavailable") from None
    return raw


def _bind_api_socket(runtime: Path) -> socket.socket:
    """Bind ``<runtime>/api.sock`` owner-only; a leftover socket of this owner is stale.

    The daemon holds its singleton lock before this runs, so no other service of this root can be
    serving the path; anything there that is not the owner's own socket is refused.
    """

    from finishup.config.paths import PathSafetyError, ensure_owner_only_dir

    try:
        ensure_owner_only_dir(runtime)
        directory = runtime.lstat()
    except (OSError, PathSafetyError):
        raise ConfigError("network_listener_unavailable") from None
    if (
        not stat.S_ISDIR(directory.st_mode)
        or directory.st_uid != os.geteuid()
        or stat.S_IMODE(directory.st_mode) & 0o077
    ):
        raise ConfigError("network_listener_unavailable")
    path = runtime / API_SOCKET_NAME
    try:
        existing = path.lstat()
    except FileNotFoundError:
        pass
    except OSError:
        raise ConfigError("network_listener_unavailable") from None
    else:
        if not stat.S_ISSOCK(existing.st_mode) or existing.st_uid != os.geteuid():
            raise ConfigError("network_listener_unavailable")
        path.unlink()
    raw = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        raw.set_inheritable(False)
        raw.bind(os.fspath(path))
        created = path.lstat()
        try:
            os.chmod(path, _API_SOCKET_MODE, follow_symlinks=False)
        except NotImplementedError:
            current = path.lstat()
            if (current.st_dev, current.st_ino) != (created.st_dev, created.st_ino):
                raise OSError("api_socket_replaced") from None
            os.chmod(path, _API_SOCKET_MODE)
        bound = path.lstat()
        if (
            not stat.S_ISSOCK(bound.st_mode)
            or (bound.st_dev, bound.st_ino) != (created.st_dev, created.st_ino)
            or stat.S_IMODE(bound.st_mode) != _API_SOCKET_MODE
        ):
            raise OSError("api_socket_unsafe")
        raw.listen(_LISTEN_BACKLOG)
        raw.setblocking(False)
    except OSError:
        raw.close()
        with contextlib.suppress(OSError):
            path.unlink()
        raise ConfigError("network_listener_unavailable") from None
    return raw


def _owner_only_protocol() -> type[Any]:
    """uvicorn's h11 protocol, closing any Unix-socket peer that is not this service's user."""

    from uvicorn.protocols.http.h11_impl import H11Protocol

    class _OwnerOnlyH11Protocol(H11Protocol):
        def connection_made(self, transport: asyncio.Transport) -> None:  # type: ignore[override]
            peer = transport.get_extra_info("socket")
            try:
                if peer is None or peer.family != socket.AF_UNIX:
                    raise LocalControlTransportError("peer_untrusted")
                # The transport exposes a wrapper; check the credentials of a duplicate handle.
                with socket.socket(fileno=os.dup(peer.fileno())) as duplicate:
                    authenticate_peer(duplicate)
            except (LocalControlTransportError, OSError, ValueError):
                transport.abort()
                _audit("network_refusal", "peer_untrusted")
                return
            super().connection_made(transport)

    return _OwnerOnlyH11Protocol


def _tcp_connection_budget(
    *,
    getrlimit: Callable[[int], tuple[int, int]] | None = None,
    setrlimit: Callable[[int, tuple[int, int]], None] | None = None,
) -> tuple[int, int]:
    """``(total, per peer address)`` open TCP connections, after raising the descriptor limit.

    The soft ``RLIMIT_NOFILE`` is raised toward ``_DESCRIPTOR_TARGET`` (never past the hard
    limit), and at most a quarter of what the service then has goes to the API's TCP connections,
    so a peer that fills them still leaves the control socket, the ledgers and the key file their
    descriptors.
    """

    import resource

    get = getrlimit or resource.getrlimit
    put = setrlimit or resource.setrlimit
    infinity = resource.RLIM_INFINITY
    try:
        soft, hard = get(resource.RLIMIT_NOFILE)
    except (OSError, ValueError):
        soft = hard = 256
    if soft != infinity and soft < _DESCRIPTOR_TARGET:
        wanted = _DESCRIPTOR_TARGET if hard == infinity else min(hard, _DESCRIPTOR_TARGET)
        if wanted > soft:
            try:
                put(resource.RLIMIT_NOFILE, (wanted, hard))
            except (OSError, ValueError):
                pass
            else:
                soft = wanted
    usable = _DESCRIPTOR_TARGET if soft == infinity else soft
    total = max(1, min(MAX_TCP_CONNECTIONS, usable // _DESCRIPTOR_SHARE))
    return total, max(1, min(MAX_TCP_CONNECTIONS_PER_PEER, total))


class _ConnectionGate:
    """The TCP listeners' open connections, in total and per peer address."""

    __slots__ = ("_members", "_per_peer", "per_peer_limit", "total_limit")

    def __init__(self, total_limit: int, per_peer_limit: int) -> None:
        if total_limit < 1 or per_peer_limit < 1:
            raise ValueError("connection_limit_invalid")
        self.total_limit = total_limit
        self.per_peer_limit = per_peer_limit
        self._per_peer: dict[str, int] = {}
        self._members: set[_GatedConnection] = set()

    @property
    def open(self) -> int:
        return len(self._members)

    def admit(self, peer: str, member: _GatedConnection) -> bool:
        held = self._per_peer.get(peer, 0)
        if len(self._members) >= self.total_limit or held >= self.per_peer_limit:
            return False
        self._per_peer[peer] = held + 1
        self._members.add(member)
        return True

    def release(self, peer: str, member: _GatedConnection) -> None:
        if member not in self._members:
            return
        self._members.discard(member)
        held = self._per_peer.get(peer, 0) - 1
        if held > 0:
            self._per_peer[peer] = held
        else:
            self._per_peer.pop(peer, None)

    def abort_all(self) -> None:
        """Close every connection still open (the listeners are stopping)."""

        for member in tuple(self._members):
            member.abort_connection()


class _GatedConnection(Protocol):
    def abort_connection(self) -> None: ...


def _peer_address(transport: asyncio.BaseTransport) -> str | None:
    peer = transport.get_extra_info("peername")
    if not isinstance(peer, tuple) or not peer:
        return None
    host = cast(tuple[object, ...], peer)[0]
    return host if isinstance(host, str) and host else None


def _tcp_protocol(gate: _ConnectionGate, tls: ssl.SSLContext | None) -> type[Any]:
    """uvicorn's h11 protocol behind the TCP listeners' admission and time bounds.

    The listener hands each accepted connection to this protocol before TLS: one over the gate's
    caps is aborted at once. An admitted one runs TLS itself (``loop.start_tls``) when the
    listener speaks it, then serves HTTP exactly as uvicorn does. Until a complete request head
    arrives — from acceptance, TLS included, and again after every answer — the connection lives
    at most ``REQUEST_HEAD_SECONDS``; a request's body must then arrive within
    ``REQUEST_BODY_SECONDS``. A request being answered has no bound here.
    """

    import h11
    from uvicorn.protocols.http.h11_impl import H11Protocol

    class _BoundedH11Protocol(H11Protocol):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            self._peer: str | None = None
            self._raw: asyncio.BaseTransport | None = None
            self._serving = False
            self._deadline: asyncio.TimerHandle | None = None
            self._watching: object = None
            self._securing: asyncio.Task[None] | None = None
            # Bytes TLS decrypted with its last handshake flight, before ``start_tls`` handed the
            # secured transport back (at most one read).
            self._early: list[bytes] = []

        # --- admission and TLS ---------------------------------------------------------------

        def connection_made(self, transport: asyncio.BaseTransport) -> None:
            # Called once, by the listener, with the raw TCP transport.
            peer = _peer_address(transport)
            if peer is None or not gate.admit(peer, self):
                cast(asyncio.Transport, transport).abort()
                _audit("network_refusal", "connection_limit")
                return
            self._peer = peer
            self._raw = transport
            self._watch(h11.IDLE, REQUEST_HEAD_SECONDS)
            if tls is None:
                self._serve(cast(asyncio.Transport, transport))
                return
            # Nothing is read until TLS owns the connection.
            cast(asyncio.Transport, transport).pause_reading()
            self._securing = self.loop.create_task(
                self._secure(cast(asyncio.Transport, transport), tls)
            )

        async def _secure(self, raw: asyncio.Transport, context: ssl.SSLContext) -> None:
            try:
                secured = await self.loop.start_tls(
                    raw,
                    self,
                    context,
                    server_side=True,
                    ssl_handshake_timeout=REQUEST_HEAD_SECONDS,
                )
            except asyncio.CancelledError:
                self._drop()
                raise
            except Exception:
                self._drop()
                return
            if secured is None or self._peer is None:
                self._drop()
                return
            self._serve(secured)

        def _serve(self, transport: asyncio.Transport) -> None:
            self._serving = True
            super().connection_made(transport)
            early, self._early = self._early, []
            for chunk in early:
                self.data_received(chunk)

        def _drop(self) -> None:
            self._unwatch()
            self._early.clear()
            if self._raw is not None:
                cast(asyncio.Transport, self._raw).abort()
            self._release()

        def _release(self) -> None:
            if self._peer is not None:
                gate.release(self._peer, self)
                self._peer = None

        def abort_connection(self) -> None:
            self._drop()

        def connection_lost(self, exc: Exception | None) -> None:
            self._unwatch()
            self._release()
            if self._serving:
                self._serving = False
                super().connection_lost(exc)

        # --- request deadlines ---------------------------------------------------------------

        def data_received(self, data: bytes) -> None:
            if not self._serving:
                self._early.append(data)
                return
            super().data_received(data)
            self._follow()

        def on_response_complete(self) -> None:
            super().on_response_complete()
            self._follow()

        def _follow(self) -> None:
            """Watch what the peer owes next: a request head, a body, or nothing."""

            transport = cast(asyncio.Transport | None, self.transport)
            if transport is None or transport.is_closing():
                self._unwatch()
                return
            state = self.conn.their_state
            if state is h11.IDLE:
                self._watch(h11.IDLE, REQUEST_HEAD_SECONDS)
            elif state is h11.SEND_BODY:
                self._watch(h11.SEND_BODY, REQUEST_BODY_SECONDS)
            else:
                self._unwatch()

        def _watch(self, state: object, seconds: float) -> None:
            if self._watching is state and self._deadline is not None:
                return
            self._unwatch()
            self._watching = state
            self._deadline = self.loop.call_later(seconds, self._expire)

        def _unwatch(self) -> None:
            if self._deadline is not None:
                self._deadline.cancel()
                self._deadline = None
            self._watching = None

        def _expire(self) -> None:
            self._deadline = None
            _audit("network_refusal", "request_timeout")
            self._drop()

    return _BoundedH11Protocol


def _quiet_http_server_logs() -> None:
    """uvicorn's own log lines may carry addresses and request lines; FinishUP records closed
    tokens instead, so they go nowhere."""

    for name in _HTTP_SERVER_LOGGERS:
        logger = logging.getLogger(name)
        logger.handlers = [logging.NullHandler()]
        logger.propagate = False


@dataclass(slots=True)
class _ServerRun:
    transport: NetworkTransport
    server: uvicorn.Server
    sockets: list[socket.socket]
    protocol: type[Any]
    task: asyncio.Task[None] | None = None


class NetworkApiServer:
    """The bound listeners of one ``[network]`` table and the uvicorn servers that serve them.

    ``bind`` runs during service composition, under the singleton lock and before any endpoint is
    published: it binds every listener and prepares its HTTP server, so a listener that cannot be
    bound or served fails the service start with a closed configuration reason. ``start`` serves
    the API on the daemon's own event loop; ``close`` stops accepting, ends the API's agents and
    calls, and removes the API socket.
    """

    def __init__(
        self,
        *,
        keys: ApiKeyStore,
        tcp_sockets: tuple[socket.socket, ...],
        tls: ssl.SSLContext | None,
        unix_socket: socket.socket | None,
        unix_path: Path | None,
        tcp_limits: tuple[int, int] = (MAX_TCP_CONNECTIONS, MAX_TCP_CONNECTIONS_PER_PEER),
    ) -> None:
        self._keys = keys
        self._tcp_sockets = tcp_sockets
        self._tls = tls
        self._unix_socket = unix_socket
        self._unix_path = unix_path
        self._api: NetworkApi | None = None
        self._applications: dict[NetworkTransport, ASGIApp] = {}
        self._gate = _ConnectionGate(*tcp_limits)
        self._closed = False
        try:
            self._runs = self._prepare()
        except Exception:
            # An HTTP stack this service cannot drive is a configuration it cannot serve.
            raise ConfigError("network_listener_unavailable") from None

    def __repr__(self) -> str:
        return "NetworkApiServer(<redacted>)"

    @classmethod
    def bind(cls, config: NetworkConfig, *, keys: ApiKeyStore, runtime: Path) -> NetworkApiServer:
        tls = (
            None
            if config.tls_cert is None or config.tls_key is None
            else _tls_context(config.tls_cert, config.tls_key)
        )
        return cls.bind_addresses(
            config.listen_addresses,
            keys=keys,
            tls=tls,
            runtime=runtime if config.api_socket else None,
        )

    @classmethod
    def bind_addresses(
        cls,
        addresses: tuple[NetworkListenAddress, ...],
        *,
        keys: ApiKeyStore,
        tls: ssl.SSLContext | None,
        runtime: Path | None,
        tcp_limits: tuple[int, int] | None = None,
    ) -> NetworkApiServer:
        """Bind explicit addresses (port 0 picks a free port, for tests) and the API socket.

        ``tcp_limits`` overrides the connection caps (tests); by default they come from the
        descriptor budget, which is claimed only when there is a TCP address to serve.
        """

        bound: list[socket.socket] = []
        unix_socket: socket.socket | None = None
        try:
            for address in addresses:
                bound.append(_bind_tcp(address))
            unix_socket = None if runtime is None else _bind_api_socket(runtime)
            limits = tcp_limits or (
                _tcp_connection_budget()
                if bound
                else (MAX_TCP_CONNECTIONS, MAX_TCP_CONNECTIONS_PER_PEER)
            )
            return cls(
                keys=keys,
                tcp_sockets=tuple(bound),
                tls=tls,
                unix_socket=unix_socket,
                unix_path=None if runtime is None else runtime / API_SOCKET_NAME,
                tcp_limits=limits,
            )
        except BaseException:
            for item in (*bound, unix_socket):
                if item is not None:
                    with contextlib.suppress(OSError):
                        item.close()
            if unix_socket is not None and runtime is not None:
                with contextlib.suppress(OSError):
                    (runtime / API_SOCKET_NAME).unlink()
            raise

    @property
    def tcp_ports(self) -> tuple[int, ...]:
        return tuple(int(item.getsockname()[1]) for item in self._tcp_sockets)

    @property
    def tcp_limits(self) -> tuple[int, int]:
        return self._gate.total_limit, self._gate.per_peer_limit

    @property
    def open_tcp_connections(self) -> int:
        return self._gate.open

    @property
    def api(self) -> NetworkApi | None:
        return self._api

    def _forward(self, transport: NetworkTransport) -> ASGIApp:
        """The listener's application: the API once ``start`` made it."""

        async def application(scope: Scope, receive: Receive, send: Send) -> None:
            served = self._applications.get(transport)
            if served is not None:
                await served(scope, receive, send)

        return application

    def _prepare(self) -> list[_ServerRun]:
        """One uvicorn server per listener kind, configured and loaded (nothing served yet).

        TLS is the listener's own (``_tcp_protocol``), never uvicorn's, so only uvicorn's
        long-standing configuration is used.
        """

        import uvicorn

        runs: list[_ServerRun] = []
        kinds: list[tuple[NetworkTransport, list[socket.socket], type[Any], int | None]] = []
        if self._tcp_sockets:
            transport: NetworkTransport = "https" if self._tls is not None else "http"
            # The gate bounds TCP connections; uvicorn's own 503 above a count is not needed.
            kinds.append(
                (transport, list(self._tcp_sockets), _tcp_protocol(self._gate, self._tls), None)
            )
        if self._unix_socket is not None:
            kinds.append(("unix", [self._unix_socket], _owner_only_protocol(), 256))
        for transport, sockets, protocol, concurrency in kinds:
            config = uvicorn.Config(
                self._forward(transport),
                http=protocol,
                ws="none",
                lifespan="off",
                log_config=None,
                access_log=False,
                proxy_headers=False,
                server_header=False,
                date_header=False,
                timeout_graceful_shutdown=2,
                limit_concurrency=concurrency,
            )
            config.load()
            server = uvicorn.Server(config)
            server.lifespan = config.lifespan_class(config)
            runs.append(_ServerRun(transport, server, sockets, protocol))
        return runs

    async def start(self, bindings: NetworkApiBindings) -> None:
        """Serve the API on this event loop until ``close``."""

        if self._api is not None or self._closed:
            raise RuntimeError("network_api_already_started")
        _quiet_http_server_logs()
        self._api = NetworkApi(bindings, self._keys)
        for run in self._runs:
            self._applications[run.transport] = self._api.asgi(run.transport)
        for run in self._runs:
            await self._listen(run)
            run.task = asyncio.create_task(self._serve(run))

    @staticmethod
    async def _listen(run: _ServerRun) -> None:
        """Accept on the run's sockets with its protocol (uvicorn's ``startup``, minus TLS)."""

        loop = asyncio.get_running_loop()
        server = run.server
        config = server.config

        def connection() -> asyncio.Protocol:
            return cast(
                asyncio.Protocol,
                run.protocol(
                    config=config,
                    server_state=server.server_state,
                    app_state=server.lifespan.state,
                    _loop=loop,
                ),
            )

        listening: list[asyncio.Server] = []
        try:
            for item in run.sockets:
                listening.append(
                    await loop.create_server(connection, sock=item, backlog=_LISTEN_BACKLOG)
                )
        except BaseException:
            for each in listening:
                each.close()
            raise
        server.servers = listening
        server.started = True

    @staticmethod
    async def _serve(run: _ServerRun) -> None:
        # ``Server.serve`` would replace the daemon's own signal handling; drive its parts here.
        await run.server.main_loop()
        await run.server.shutdown(sockets=run.sockets)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._api is not None:
            await self._api.close()
        for run in self._runs:
            run.server.should_exit = True
        tasks = [run.task for run in self._runs if run.task is not None]
        await asyncio.gather(*tasks, return_exceptions=True)
        # Connections still in TLS or before their first request are not uvicorn's to close.
        self._gate.abort_all()
        for item in (*self._tcp_sockets, self._unix_socket):
            if item is not None:
                with contextlib.suppress(OSError):
                    item.close()
        if self._unix_path is not None:
            with contextlib.suppress(OSError):
                facts = self._unix_path.lstat()
                if stat.S_ISSOCK(facts.st_mode) and facts.st_uid == os.geteuid():
                    self._unix_path.unlink()
