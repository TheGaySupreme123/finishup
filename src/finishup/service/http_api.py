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
from finishup.ports.workspace_agent import (
    MAX_WORKSPACE_FRAME_BYTES,
    workspace_handle_for_commitment,
)
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


class WorkspaceAgentRegistry(Protocol):
    """The service's registry of workspace agents (``service.workspace_hub.WorkspaceAgentHub``).

    A REST agent registers one in-process channel whose ``writer`` queues each ``workspace_call``
    for the agent's next long-poll; its replies come back through ``deliver``.
    """

    async def register(
        self,
        *,
        handle: str,
        declaration: WorkspaceAgentDeclaration,
        service_instance_id: str,
        service_generation: str,
        writer: Callable[[WorkspaceCall], Awaitable[None]],
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


@dataclass(slots=True)
class _Operation:
    operation_id: str
    owner_key: str
    task: asyncio.Task[ControlResult]
    request: ControlCallRequest
    workspace_handle: str | None
    finished_at: float | None = None


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
                raise _Refusal("service_unavailable") from None
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
        """Answer a refusal with its closed reason and anything unexpected with a bounded 503."""

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
                return _error_response("service_unavailable")

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
            raise _Refusal("service_unavailable")
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
            workspace_handle=None
            if context is None
            else workspace_handle_for_commitment(context.commitment),
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
        if operation_id is not None:
            try:
                validate_id(IdKind.CONTROL_RPC, operation_id)
            except (TypeError, ValueError):
                raise _Refusal("header_invalid") from None
            existing = self._operations.get(operation_id)
            if existing is not None:
                # At most once: an id already admitted answers with that operation, never anew.
                if existing.owner_key != caller.owner_key:
                    raise _Refusal("header_invalid")
                return await self._answer(existing, wait_ms)
        _binding, context = await self._claim(request, caller)
        handle = None if context is None else workspace_handle_for_commitment(context.commitment)
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
        call = self._call_request(request, method, body, rpc_id, addressed)
        self._purge()
        pending = sum(
            1
            for item in self._operations.values()
            if item.owner_key == caller.owner_key and not item.task.done()
        )
        if pending >= MAX_PENDING_OPERATIONS_PER_KEY:
            raise _Refusal("operation_limit")
        operation = _Operation(
            call.rpc_id,
            caller.owner_key,
            asyncio.create_task(self._dispatch(client_kind, call, context)),
            call,
            handle,
        )
        operation.task.add_done_callback(lambda _task: self._finished(operation))
        self._operations[call.rpc_id] = operation
        return await self._answer(operation, wait_ms)

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
        operation.finished_at = self._clock()

    def _purge(self) -> None:
        now = self._clock()
        for operation_id, operation in tuple(self._operations.items()):
            if (
                operation.finished_at is not None
                and now - operation.finished_at >= OPERATION_RESULT_SECONDS
            ):
                del self._operations[operation_id]

    async def _answer(self, operation: _Operation, wait_ms: int) -> Response:
        if not operation.task.done() and wait_ms > 0:
            closing = asyncio.ensure_future(self._closing.wait())
            try:
                await asyncio.wait(
                    {operation.task, closing},
                    timeout=wait_ms / 1_000,
                    return_when=asyncio.FIRST_COMPLETED,
                )
            finally:
                closing.cancel()
        if not operation.task.done():
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
        result = (
            # Cancelled before its first step ran, the call never reached the daemon.
            self._call_error(operation.request, ControlError("request_cancelled", retryable=True))
            if operation.task.cancelled()
            else operation.task.result()
        )
        return self._result_response(
            result,
            operation_id=operation.operation_id,
            workspace_handle=operation.workspace_handle,
        )

    def _result_response(
        self, result: ControlResult, *, operation_id: str, workspace_handle: str | None
    ) -> Response:
        try:
            body = _result_body(result)
        except ControlProtocolError:
            # A result this service cannot frame is its own defect; the socket would drop it too.
            raise _Refusal("service_unavailable") from None
        headers = {
            "cache-control": "no-store",
            HEADER_OUTCOME: result.outcome,
            HEADER_OPERATION_ID: operation_id,
            HEADER_SERVICE_INSTANCE: result.service_instance_id,
            HEADER_SERVICE_GENERATION: result.service_generation,
        }
        if workspace_handle is not None:
            headers[HEADER_WORKSPACE_HANDLE] = workspace_handle
        return Response(body, media_type=_JSON, headers=headers)

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
        if not operation.task.done():
            operation.task.cancel(EXPLICIT_CONTROL_CANCEL)
        return Response(status_code=204, headers={"cache-control": "no-store"})

    # --- workspace agents ---------------------------------------------------------------------

    async def _register_agent(self, request: Request) -> Response:
        caller = self._caller(request)
        if _single_header(request, HEADER_CLAIM) is None:
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
        handle = workspace_handle_for_commitment(context.commitment)
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
        """End agents whose lease ran out or whose key was revoked or expired."""

        while self._agents and not self._closing.is_set():
            await asyncio.sleep(_SWEEP_SECONDS)
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
        for operation in tuple(self._operations.values()):
            if not operation.task.done():
                operation.task.cancel(EXPLICIT_CONTROL_CANCEL)
        await asyncio.gather(
            *(operation.task for operation in self._operations.values()), return_exceptions=True
        )
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


def _quiet_http_server_logs() -> None:
    """uvicorn's own log lines may carry addresses and request lines; FinishUP records closed
    tokens instead, so they go nowhere."""

    for name in _HTTP_SERVER_LOGGERS:
        logger = logging.getLogger(name)
        logger.handlers = [logging.NullHandler()]
        logger.propagate = False


@dataclass(slots=True)
class _ServerRun:
    server: uvicorn.Server
    sockets: list[socket.socket]
    task: asyncio.Task[None] | None = None


class NetworkApiServer:
    """The bound listeners of one ``[network]`` table and the uvicorn servers that serve them.

    ``bind`` runs during service composition, under the singleton lock and before any endpoint is
    published, so a listener that cannot be bound fails the service start with a closed
    configuration reason. ``start`` serves the API on the daemon's own event loop; ``close`` stops
    accepting, ends the API's agents and calls, and removes the API socket.
    """

    def __init__(
        self,
        *,
        keys: ApiKeyStore,
        tcp_sockets: tuple[socket.socket, ...],
        tls: ssl.SSLContext | None,
        unix_socket: socket.socket | None,
        unix_path: Path | None,
    ) -> None:
        self._keys = keys
        self._tcp_sockets = tcp_sockets
        self._tls = tls
        self._unix_socket = unix_socket
        self._unix_path = unix_path
        self._api: NetworkApi | None = None
        self._runs: list[_ServerRun] = []
        self._closed = False

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
    ) -> NetworkApiServer:
        """Bind explicit addresses (port 0 picks a free port, for tests) and the API socket."""

        bound: list[socket.socket] = []
        try:
            for address in addresses:
                bound.append(_bind_tcp(address))
            unix_socket = None if runtime is None else _bind_api_socket(runtime)
        except BaseException:
            for item in bound:
                item.close()
            raise
        return cls(
            keys=keys,
            tcp_sockets=tuple(bound),
            tls=tls,
            unix_socket=unix_socket,
            unix_path=None if runtime is None else runtime / API_SOCKET_NAME,
        )

    @property
    def tcp_ports(self) -> tuple[int, ...]:
        return tuple(int(item.getsockname()[1]) for item in self._tcp_sockets)

    @property
    def api(self) -> NetworkApi | None:
        return self._api

    @staticmethod
    def _uvicorn_server(
        application: Callable[..., Awaitable[None]],
        *,
        http: type[Any] | str,
        tls: ssl.SSLContext | None,
    ) -> uvicorn.Server:
        import uvicorn

        config = uvicorn.Config(
            application,
            http=http,
            ws="none",
            lifespan="off",
            log_config=None,
            access_log=False,
            proxy_headers=False,
            server_header=False,
            date_header=False,
            timeout_graceful_shutdown=2,
            limit_concurrency=256,
            ssl_context_factory=None if tls is None else (lambda _config, _default: tls),
        )
        return uvicorn.Server(config)

    async def start(self, bindings: NetworkApiBindings) -> None:
        """Serve the API on this event loop until ``close``."""

        if self._api is not None or self._closed:
            raise RuntimeError("network_api_already_started")
        _quiet_http_server_logs()
        self._api = NetworkApi(bindings, self._keys)
        if self._tcp_sockets:
            transport: NetworkTransport = "https" if self._tls is not None else "http"
            server = self._uvicorn_server(self._api.asgi(transport), http="h11", tls=self._tls)
            self._runs.append(_ServerRun(server, list(self._tcp_sockets)))
        if self._unix_socket is not None:
            server = self._uvicorn_server(
                self._api.asgi("unix"), http=_owner_only_protocol(), tls=None
            )
            self._runs.append(_ServerRun(server, [self._unix_socket]))
        for run in self._runs:
            run.server.config.load()
            run.server.lifespan = run.server.config.lifespan_class(run.server.config)
            await run.server.startup(sockets=run.sockets)
            run.task = asyncio.create_task(self._serve(run))

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
        for item in (*self._tcp_sockets, self._unix_socket):
            if item is not None:
                with contextlib.suppress(OSError):
                    item.close()
        if self._unix_path is not None:
            with contextlib.suppress(OSError):
                facts = self._unix_path.lstat()
                if stat.S_ISSOCK(facts.st_mode) and facts.st_uid == os.geteuid():
                    self._unix_path.unlink()
