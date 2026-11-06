"""The gateway's HTTP application: the HTTPS binding v1 routes (ADR-051, approach A).

Every route answers only an authenticated request: a request carrying any ``Origin`` header is
refused first (``origin_forbidden``, against browser and DNS-rebinding abuse), then the bearer key
must authenticate (``api_key_invalid|revoked|expired``), and the ``FinishUP-Binding: 1.0`` header
must be present. Bodies are exact canonical control frames without their length prefix, validated
against the active control envelopes before anything is forwarded.

A key's scope is enforced here, as a method allow-list over the daemon's own client-kind gate: an
out-of-scope call is answered with a synthesized ``method_forbidden`` control-result built from
the session's service instance and generation, byte-shaped like any daemon error result, and is
never forwarded. A hello carrying ``workspace_locator`` is refused (``workspace_locator_forbidden``):
a client on another machine names its workspace by a claim.

Claims are namespaced by principal. v1 has a single principal, ``owner``, so a claim passes
unchanged and an SSH client and an HTTPS client of the same owner reach the same tasks;
per-principal claim namespaces wait for multi-key hosting (ADR-051 decision 9).

Audit lines carry closed tokens only — key id, route, control method, HTTP status, closed
reason, correlation id — never a body, a header value, a label or an address.
"""

from __future__ import annotations

import asyncio
import contextlib
import struct
from collections.abc import AsyncGenerator, Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Protocol, cast

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

from finishup import __version__
from finishup.gateway.keys import GatewayKey, KeyRing, record_use
from finishup.gateway.sessions import (
    GatewaySession,
    SessionLimit,
    SessionRegistry,
    UpstreamStream,
)
from finishup.ports.control import ControlError, ControlMethod, ControlResult
from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.protocol.ids import IdKind, new_id
from finishup.protocol.rest_binding import (
    BINDING_HEADER,
    BINDING_VERSION,
    CORRELATION_HEADER,
    MAX_WAIT_MS,
    REST_ERROR_SCHEMA_VERSION,
    REST_ERROR_STATUS,
    SERVER_INFO_SCHEMA_VERSION,
    SESSION_ID_PATTERN,
    method_allowed,
)
from finishup.service.control_protocol import (
    MAX_CONTROL_FRAME_BYTES,
    ControlFrame,
    ControlProtocolError,
    decode_control_frame,
    encode_control_frame,
)

__all__ = ["AuditSink", "FileAuditSink", "GatewayApp", "build_gateway_app"]

_JSON: Final = "application/json"
_SWEEP_SECONDS: Final = 5.0
_USE_RECORD_SECONDS: Final = 60.0
_RPC_ID_MAX: Final = 128


class AuditSink(Protocol):
    def write(self, record: dict[str, JsonValue]) -> None: ...


class FileAuditSink:
    """Append canonical audit lines to an owner-only file (``<log dir>/gateway-audit.jsonl``)."""

    def __init__(self, path: Path) -> None:
        self._path = path

    def write(self, record: dict[str, JsonValue]) -> None:
        import os

        with contextlib.suppress(OSError):
            self._path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_CLOEXEC | os.O_NOFOLLOW
            descriptor = os.open(self._path, flags, 0o600)
            try:
                os.write(descriptor, canonical_encode(record) + b"\n")
            finally:
                os.close(descriptor)


@dataclass(frozen=True, slots=True)
class _Answer:
    status: int
    body: bytes = b""
    method: str | None = None
    location: str | None = None
    # A closed token for the audit line when a 200 answer is itself a refusal (a scope gap).
    reason: str | None = None


class _Refused(Exception):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def _error_body(reason: str) -> bytes:
    return canonical_encode({"reason": reason, "schema_version": REST_ERROR_SCHEMA_VERSION})


def _frame(payload: bytes) -> ControlFrame:
    if len(payload) > MAX_CONTROL_FRAME_BYTES:
        raise _Refused("frame_too_large")
    try:
        return decode_control_frame(struct.pack(">I", len(payload)) + payload)
    except ControlProtocolError as error:
        raise _Refused(
            "frame_too_large" if error.reason == "frame_too_large" else "frame_invalid"
        ) from None


def _wait_seconds(request: Request) -> float:
    raw = request.query_params.get("wait_ms", "0")
    if not raw.isdigit() or len(raw) > 6:
        raise _Refused("frame_invalid")
    return min(int(raw), MAX_WAIT_MS) / 1000


def _forbidden_result(session: GatewaySession, frame: ControlFrame) -> bytes:
    """The fixture-locked ``method_forbidden`` control-result for an out-of-scope call."""

    result = ControlResult(
        protocol_version="1.0",
        rpc_id=cast(str, frame["rpc_id"]),
        service_instance_id=session.service_instance_id,
        service_generation=session.service_generation,
        method=ControlMethod(cast(str, frame["method"])),
        outcome="error",
        body=ControlError("method_forbidden"),
    )
    return encode_control_frame(result)[4:]


class GatewayApp:
    """The routes' state: the key ring, the sessions, the audit sink."""

    def __init__(
        self,
        *,
        keys_directory: Path,
        connect_upstream: Callable[[], Awaitable[UpstreamStream]],
        audit: AuditSink,
        manifest_digest: str,
        on_stale: Callable[[], None] | None = None,
        idle_seconds: float | None = None,
    ) -> None:
        self._keys_directory = keys_directory
        self.keys = KeyRing(keys_directory)
        self.sessions = (
            SessionRegistry(connect_upstream)
            if idle_seconds is None
            else SessionRegistry(connect_upstream, idle_seconds=idle_seconds)
        )
        self._audit = audit
        self._digest = manifest_digest
        self._on_stale = on_stale
        self._last_use: dict[str, float] = {}
        self._sweeper: asyncio.Task[None] | None = None

    # -- lifecycle ----------------------------------------------------------------------------

    @contextlib.asynccontextmanager
    async def lifespan(self, _app: Starlette) -> AsyncGenerator[None]:
        self._sweeper = asyncio.create_task(self._sweep_forever())
        try:
            yield
        finally:
            self._sweeper.cancel()
            await asyncio.gather(self._sweeper, return_exceptions=True)
            await self.sessions.close_all()

    async def sweep(self) -> None:
        """Close idle and dead sessions and every session of a key that stopped authenticating."""

        self.keys.refresh()
        await self.sessions.close_keys(self.keys.revoked_ids())
        await self.sessions.sweep()

    async def _sweep_forever(self) -> None:
        while True:
            await asyncio.sleep(_SWEEP_SECONDS)
            with contextlib.suppress(Exception):
                await self.sweep()

    # -- request plumbing ---------------------------------------------------------------------

    def _record(
        self,
        *,
        correlation_id: str,
        route: str,
        status: int,
        key: GatewayKey | None = None,
        method: str | None = None,
        reason: str | None = None,
    ) -> None:
        with contextlib.suppress(Exception):
            self._audit.write(
                {
                    "event": "gateway_request",
                    "correlation_id": correlation_id,
                    "route": route,
                    "key_id": None if key is None else key.key_id,
                    "method": method,
                    "status": status,
                    "reason": reason,
                }
            )

    def _note_use(self, key: GatewayKey) -> None:
        import time

        now = time.monotonic()
        if now - self._last_use.get(key.key_id, -_USE_RECORD_SECONDS) < _USE_RECORD_SECONDS:
            return
        self._last_use[key.key_id] = now
        with contextlib.suppress(Exception):
            record_use(self._keys_directory, key.key_id)

    def _authenticate(self, request: Request) -> GatewayKey:
        if "origin" in request.headers:
            raise _Refused("origin_forbidden")
        authorization = request.headers.get("authorization", "")
        scheme, _, bearer = authorization.partition(" ")
        if scheme.lower() != "bearer" or not bearer:
            raise _Refused("api_key_invalid")
        outcome = self.keys.authenticate(bearer.strip(), datetime.now(UTC))
        if isinstance(outcome, str):
            raise _Refused(outcome)
        if request.headers.get(BINDING_HEADER.lower()) != BINDING_VERSION:
            raise _Refused("frame_invalid")
        self._note_use(outcome)
        return outcome

    async def _body(self, request: Request) -> bytes:
        chunks: list[bytes] = []
        size = 0
        async for chunk in request.stream():
            size += len(chunk)
            if size > MAX_CONTROL_FRAME_BYTES:
                raise _Refused("frame_too_large")
            chunks.append(chunk)
        return b"".join(chunks)

    def _session(self, request: Request, key: GatewayKey) -> GatewaySession:
        sid = request.path_params.get("sid", "")
        if not SESSION_ID_PATTERN.match(sid):
            raise _Refused("session_unknown")
        session = self.sessions.get(sid, key.key_id)
        if session is None:
            raise _Refused("session_unknown")
        session.touch()
        return session

    def _route(
        self, name: str, handler: Callable[[Request, GatewayKey], Awaitable[_Answer]]
    ) -> Callable[[Request], Awaitable[Response]]:
        async def endpoint(request: Request) -> Response:
            correlation_id = new_id(IdKind.CORRELATION)
            key: GatewayKey | None = None
            reason: str | None = None
            try:
                key = self._authenticate(request)
                answer = await handler(request, key)
            except _Refused as refused:
                reason = refused.reason
                answer = _Answer(REST_ERROR_STATUS[reason], _error_body(reason))
            except Exception:
                reason = "service_unavailable"
                answer = _Answer(503, _error_body(reason))
            self._record(
                correlation_id=correlation_id,
                route=name,
                status=answer.status,
                key=key,
                method=answer.method,
                reason=reason if reason is not None else answer.reason,
            )
            headers = {CORRELATION_HEADER: correlation_id, "Cache-Control": "no-store"}
            if answer.location is not None:
                headers["Location"] = answer.location
            return Response(
                content=answer.body,
                status_code=answer.status,
                media_type=_JSON if answer.body else None,
                headers=headers,
            )

        return endpoint

    # -- routes -------------------------------------------------------------------------------

    async def server_info(self, _request: Request, key: GatewayKey) -> _Answer:
        document: dict[str, JsonValue] = {
            "schema_version": SERVER_INFO_SCHEMA_VERSION,
            "release": __version__,
            "schema_manifest_digest": self._digest,
            "key_id": key.key_id,
            "scope": key.scope,
            "bindings": [BINDING_VERSION],
        }
        return _Answer(200, canonical_encode(document))

    async def open_session(self, request: Request, key: GatewayKey) -> _Answer:
        payload = await self._body(request)
        hello = _frame(payload)
        if "connection_nonce" not in hello:
            raise _Refused("frame_invalid")
        if hello.get("workspace_locator") is not None:
            raise _Refused("workspace_locator_forbidden")
        try:
            opened = await self.sessions.open(
                key_id=key.key_id,
                scope=key.scope,
                hello=hello,
                hello_payload=payload,
                manifest_digest=self._digest,
            )
        except SessionLimit:
            raise _Refused("session_limit") from None
        except ControlProtocolError:
            raise _Refused("service_unavailable") from None
        if opened.session is None:
            answer = _frame(opened.body)
            if (
                answer.get("schema_manifest_digest") != self._digest
                and hello.get("schema_manifest_digest") == answer.get("schema_manifest_digest")
                and self._on_stale is not None
            ):
                # The daemon runs a release this gateway does not: restart the gateway.
                self._on_stale()
                raise _Refused("service_unavailable")
            return _Answer(opened.status, opened.body)
        return _Answer(201, opened.body, location=f"/v1/sessions/{opened.session.sid}")

    async def call(self, request: Request, key: GatewayKey) -> _Answer:
        session = self._session(request, key)
        seconds = _wait_seconds(request)
        payload = await self._body(request)
        frame = _frame(payload)
        if frame.get("kind") != "call":
            raise _Refused("frame_invalid")
        rpc_id = cast(str, frame["rpc_id"])
        method_name = cast(str, frame["method"])
        method = ControlMethod(method_name)
        if not method_allowed(key.scope, method, claim_bound=session.claim_bound):
            return _Answer(
                200, _forbidden_result(session, frame), method_name, reason="method_forbidden"
            )
        if session.delivered(rpc_id):
            raise _Refused("frame_invalid")
        if session.slot(rpc_id) is None:
            try:
                await session.forward_call(rpc_id, payload)
            except SessionLimit:
                raise _Refused("session_limit") from None
        result = await session.wait_result(rpc_id, seconds)
        if result is not None:
            return _Answer(200, result, method_name)
        if session.closed.is_set():
            raise _Refused("session_unknown")
        return _Answer(202, method=method_name)

    async def result(self, request: Request, key: GatewayKey) -> _Answer:
        session = self._session(request, key)
        seconds = _wait_seconds(request)
        rpc_id = request.path_params.get("rpc_id", "")
        if not 0 < len(rpc_id) <= _RPC_ID_MAX or not session.known(rpc_id):
            raise _Refused("frame_invalid")
        result = await session.wait_result(rpc_id, seconds)
        if result is not None:
            return _Answer(200, result)
        if session.closed.is_set():
            raise _Refused("session_unknown")
        return _Answer(202)

    async def cancel(self, request: Request, key: GatewayKey) -> _Answer:
        session = self._session(request, key)
        frame = _frame(payload := await self._body(request))
        if frame.get("kind") != "cancel":
            raise _Refused("frame_invalid")
        # Never a cancel the daemon would end the connection for (a finished call, one this
        # gateway answered itself); one that overtook its call follows it (``sessions``).
        await session.forward_cancel(cast(str, frame["target_rpc_id"]), payload)
        return _Answer(202)

    async def post_frame(self, request: Request, key: GatewayKey) -> _Answer:
        session = self._session(request, key)
        frame = _frame(payload := await self._body(request))
        if frame.get("kind") != "workspace_reply" or not session.agent:
            raise _Refused("frame_invalid")
        await session.forward(payload)
        return _Answer(202)

    async def next_frame(self, request: Request, key: GatewayKey) -> _Answer:
        session = self._session(request, key)
        seconds = _wait_seconds(request)
        frame = await session.next_frame(seconds)
        session.touch()
        if frame is not None:
            return _Answer(200, frame)
        if session.closed.is_set():
            raise _Refused("session_unknown")
        return _Answer(204)

    async def close_session(self, request: Request, key: GatewayKey) -> _Answer:
        session = self._session(request, key)
        await self.sessions.close(session.sid)
        return _Answer(204)

    def application(self) -> Starlette:
        routes = [
            Route("/v1/server", self._route("server", self.server_info), methods=["GET"]),
            Route("/v1/sessions", self._route("sessions", self.open_session), methods=["POST"]),
            Route("/v1/sessions/{sid}/calls", self._route("calls", self.call), methods=["POST"]),
            Route(
                "/v1/sessions/{sid}/results/{rpc_id}",
                self._route("results", self.result),
                methods=["GET"],
            ),
            Route(
                "/v1/sessions/{sid}/cancel", self._route("cancel", self.cancel), methods=["POST"]
            ),
            Route(
                "/v1/sessions/{sid}/frames",
                self._route("frames_in", self.post_frame),
                methods=["POST"],
            ),
            Route(
                "/v1/sessions/{sid}/frames",
                self._route("frames_out", self.next_frame),
                methods=["GET"],
            ),
            Route(
                "/v1/sessions/{sid}",
                self._route("close", self.close_session),
                methods=["DELETE"],
            ),
        ]
        return Starlette(routes=routes, lifespan=self.lifespan)


def build_gateway_app(
    *,
    keys_directory: Path,
    connect_upstream: Callable[[], Awaitable[UpstreamStream]],
    audit: AuditSink,
    on_stale: Callable[[], None] | None = None,
    idle_seconds: float | None = None,
) -> tuple[GatewayApp, Starlette]:
    """The gateway state and its ASGI application."""

    from finishup.protocol.schemas import schema_manifest_digest

    state = GatewayApp(
        keys_directory=keys_directory,
        connect_upstream=connect_upstream,
        audit=audit,
        manifest_digest=schema_manifest_digest(),
        on_stale=on_stale,
        idle_seconds=idle_seconds,
    )
    return state, state.application()
