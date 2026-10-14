"""Frozen ordinary local-service control framing and handshake protocol."""

from __future__ import annotations

import asyncio
import base64
import binascii
import secrets
import struct
from collections.abc import Awaitable, Buffer, Callable, Mapping
from dataclasses import dataclass, field, fields, is_dataclass
from enum import Enum
from typing import Final, Literal, Never, Protocol, cast

from pydantic import BaseModel

from yoetz.adapters.control.unix_socket import LocalControlTransportError
from yoetz.domain.coordination import CoordinationErrorCode
from yoetz.domain.values import JsonObject, freeze_json
from yoetz.ports.control import (
    ControlCallRequest,
    ControlCancelRequest,
    ControlClientKind,
    ControlError,
    ControlMethod,
    ControlRequest,
    ControlResult,
    McpHostProfile,
    ProjectionRenderMode,
    RepositoryPrivacyContext,
    ServiceState,
    ServiceStatus,
    ServiceStopResult,
    WorkspaceLocator,
)
from yoetz.protocol.canonical import JsonValue, canonical_encode, strict_json_parse
from yoetz.protocol.errors import ProtocolValueError, PublicErrorCode, SafeDetailValue
from yoetz.protocol.models import (
    CheckRequest,
    CheckResult,
    PublishWorkRequest,
    PublishWorkResult,
    ReceiptRequest,
    ReceiptResult,
    RespondRequest,
    RespondResult,
    StartRequest,
    StartResult,
    StatusRequest,
    StatusResult,
)
from yoetz.protocol.schemas import (
    schema_document_for,
    schema_manifest_digest,
    validate_schema_instance,
)

__all__ = [
    "CONTROL_FRAME_READ_DEADLINE_SECONDS",
    "CONTROL_PROTOCOL_VERSION",
    "MAX_ACTIVE_REQUESTS_PER_SESSION",
    "MAX_CONTROL_FRAME_BYTES",
    "MAX_ORDINARY_CONTROL_FRAME_BYTES",
    "BoundedControlQueue",
    "ControlFrame",
    "ControlProtocolError",
    "ControlSession",
    "ControlStream",
    "client_handshake",
    "decode_control_frame",
    "encode_control_frame",
    "parse_control_request",
    "parse_control_result",
    "public_error_code_for_control_reason",
    "read_control_frame",
    "schema_for_method",
    "server_handshake",
    "validate_request",
    "validate_result",
    "write_control_frame",
]

CONTROL_PROTOCOL_VERSION: Final = "1.0"
MAX_CONTROL_FRAME_BYTES: Final = 6_291_456
MAX_ORDINARY_CONTROL_FRAME_BYTES: Final = 1_048_576
MAX_ACTIVE_REQUESTS_PER_SESSION: Final = 32
# The largest single ``ControlStream.receive`` a frame reader requests. The authenticated Unix
# stream refuses a larger request (``receive_size_invalid``), so a frame above it is read in
# bounded chunks. Asking for the whole remaining frame at once made every frame over 64 KiB
# unreadable: the refusal surfaced as ``frame_invalid``, and a privacy receipt page of about 45
# receipts reached the operator as a caller's ``invalid_request`` (issue #921).
MAX_CONTROL_RECEIVE_CHUNK_BYTES: Final = 65_536
# Once the first byte of a frame arrives, the whole frame must arrive within this bound. Waiting
# for a frame to *begin* stays the caller's policy (the daemon's inactive-session deadline, the
# client's own call deadlines); a frame that has begun is never left open-ended. Chunked reads
# made frames up to ``MAX_CONTROL_FRAME_BYTES`` readable, so without this bound a same-user peer
# could declare a large frame and drip it while a call is active, holding the partial body and a
# listener slot indefinitely. A local socket carries the largest frame in well under a second;
# the bound only has to exceed that with a wide margin for a loaded machine.
CONTROL_FRAME_READ_DEADLINE_SECONDS: Final = 60.0

_CONTROL_SCHEMA_VERSION: Final = "2.9.0"
# The 0.2.3 line split request/result (2.6.1) from hello (2.6.0); the 0.3 line carries
# every 2.6.1 addition inside its single live 2.9.0 contract, so all three agree.
_CONTROL_RESULT_SCHEMA_VERSION: Final = _CONTROL_SCHEMA_VERSION
_CONTROL_REQUEST_SCHEMA_VERSION: Final = _CONTROL_SCHEMA_VERSION
_SCHEMA_VERSION: Final = "1.0.0"
_MAX_IMPORT_SOURCE_BYTES: Final = 4 * 1024 * 1024
_ERROR_REASONS: Final = frozenset(
    {
        "correlation_mismatch",
        "duplicate_rpc_id",
        "frame_invalid",
        "frame_read_timeout",
        "frame_too_large",
        "handshake_rejected",
        "manifest_mismatch",
        "method_forbidden",
        "peer_untrusted",
        "protocol_mismatch",
        "request_limit_exceeded",
        "service_generation_changed",
        "session_closed",
        "transport_failed",
    }
)
_COORDINATION_CONTROL_ERROR_REASONS: Final[frozenset[str]] = frozenset(
    code.value for code in CoordinationErrorCode
)
_WORKFLOW_METHODS: Final = tuple(
    sorted(
        (
            ControlMethod.START,
            ControlMethod.PUBLISH_WORK,
            ControlMethod.CHECK,
            ControlMethod.RESPOND,
            ControlMethod.STATUS,
            ControlMethod.RECEIPT,
        ),
        key=lambda value: value.value.encode("ascii"),
    )
)
_ALL_METHODS: Final = tuple(sorted(ControlMethod, key=lambda value: value.value.encode("ascii")))
_WORKFLOW_REQUEST_MODELS: Final[Mapping[ControlMethod, type[BaseModel]]] = {
    ControlMethod.START: StartRequest,
    ControlMethod.PUBLISH_WORK: PublishWorkRequest,
    ControlMethod.CHECK: CheckRequest,
    ControlMethod.RESPOND: RespondRequest,
    ControlMethod.STATUS: StatusRequest,
    ControlMethod.RECEIPT: ReceiptRequest,
}
_WORKFLOW_RESULT_MODELS: Final[Mapping[ControlMethod, type[BaseModel]]] = {
    ControlMethod.START: StartResult,
    ControlMethod.PUBLISH_WORK: PublishWorkResult,
    ControlMethod.CHECK: CheckResult,
    ControlMethod.RESPOND: RespondResult,
    ControlMethod.STATUS: StatusResult,
    ControlMethod.RECEIPT: ReceiptResult,
}

type ControlFrame = JsonObject
type SchemaDirection = Literal["request", "result"]


class ControlStream(Protocol):
    """Authenticated bounded byte stream used by the ordinary protocol."""

    @property
    def peer_identity(self) -> object: ...

    async def receive(self, max_bytes: int) -> bytes: ...

    async def send_all(self, data: Buffer) -> None: ...

    async def aclose(self) -> None: ...


class ControlProtocolError(Exception):
    """A fixed, sanitized control-protocol failure."""

    __slots__ = ("reason",)

    reason: str

    def __init__(self, reason: str) -> None:
        if type(reason) is not str or reason not in _ERROR_REASONS:
            raise ValueError("control_protocol_reason_invalid")
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True, slots=True)
class _PendingCall:
    method: ControlMethod


def _new_pending_calls() -> dict[str, _PendingCall]:
    return {}


@dataclass(frozen=True, slots=True)
class ControlSession:
    """Peer-bound negotiated session with bounded request correlation state."""

    protocol_version: Literal["1.0"]
    client_kind: ControlClientKind
    service_instance_id: str
    service_generation: str
    allowed_methods: tuple[ControlMethod, ...]
    peer_identity: object = field(repr=False, compare=False)
    connection_nonce: str = field(repr=False, compare=False)
    repository_privacy_context: RepositoryPrivacyContext | None = field(
        default=None, repr=False, compare=False
    )
    projection_render_mode: ProjectionRenderMode = field(
        default=ProjectionRenderMode.MACHINE_READABLE, repr=False, compare=False
    )
    output_is_controlling_tty: bool = field(default=False, repr=False, compare=False)
    # The service-status snapshot the hello-result carried at handshake time. Client sessions
    # retain it so a caller can name the structural state (for example an uninitialized vault,
    # issue #512) without a follow-up method the peer may forbid; it is connect-time data, never
    # a live read.
    service_status: ServiceStatus | None = field(default=None, repr=False, compare=False)
    _active: dict[str, _PendingCall] = field(
        default_factory=_new_pending_calls, init=False, repr=False, compare=False
    )
    _closed: bool = field(default=False, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.protocol_version != CONTROL_PROTOCOL_VERSION:
            raise ValueError("control_protocol_version_invalid")
        if type(self.client_kind) is not ControlClientKind:
            raise TypeError("control_client_kind_invalid")
        if self.service_status is not None and type(self.service_status) is not ServiceStatus:
            raise TypeError("service_status_invalid")
        if (
            self.repository_privacy_context is not None
            and type(self.repository_privacy_context) is not RepositoryPrivacyContext
        ):
            raise TypeError("repository_privacy_context_invalid")
        if type(self.projection_render_mode) is not ProjectionRenderMode:
            raise TypeError("projection_render_mode_invalid")
        if type(self.output_is_controlling_tty) is not bool:
            raise TypeError("projection_tty_fact_invalid")
        if type(self.allowed_methods) is not tuple or not self.allowed_methods:
            raise ValueError("control_allowed_methods_invalid")
        expected = tuple(
            sorted(set(self.allowed_methods), key=lambda value: value.value.encode("ascii"))
        )
        if self.allowed_methods != expected:
            raise ValueError("control_allowed_methods_invalid")
        if self.client_kind is ControlClientKind.MCP_BRIDGE:
            if self.allowed_methods != _WORKFLOW_METHODS:
                raise ValueError("control_allowed_methods_invalid")
        elif self.allowed_methods != _ALL_METHODS:
            raise ValueError("control_allowed_methods_invalid")
        if (
            type(self.connection_nonce) is not str
            or len(self.connection_nonce) != 64
            or any(character not in "0123456789abcdef" for character in self.connection_nonce)
        ):
            raise ValueError("connection_nonce_invalid")
        if self.peer_identity is None or isinstance(
            self.peer_identity, str | bytes | bytearray | int | float | bool
        ):
            raise TypeError("peer_identity_invalid")

    @property
    def active_request_count(self) -> int:
        return len(self._active)

    def admit(self, request: ControlRequest) -> None:
        """Admit one call under the per-session authority and 32-call cap."""

        if self._closed:
            raise ControlProtocolError("session_closed")
        validate_request(request)
        if request.service_instance_id != self.service_instance_id:
            raise ControlProtocolError("service_generation_changed")
        if request.service_generation != self.service_generation:
            raise ControlProtocolError("service_generation_changed")
        if isinstance(request, ControlCancelRequest):
            if request.rpc_id in self._active:
                raise ControlProtocolError("duplicate_rpc_id")
            if request.target_rpc_id not in self._active:
                raise ControlProtocolError("correlation_mismatch")
            return
        if request.method not in self.allowed_methods:
            raise ControlProtocolError("method_forbidden")
        if request.rpc_id in self._active:
            raise ControlProtocolError("duplicate_rpc_id")
        if len(self._active) >= MAX_ACTIVE_REQUESTS_PER_SESSION:
            raise ControlProtocolError("request_limit_exceeded")
        self._active[request.rpc_id] = _PendingCall(request.method)

    def correlate(self, result: ControlResult) -> None:
        """Resolve exactly one active call by RPC ID, method, instance, and generation."""

        if self._closed:
            raise ControlProtocolError("session_closed")
        validate_result(result)
        pending = self._active.get(result.rpc_id)
        if (
            pending is None
            or pending.method is not result.method
            or result.service_instance_id != self.service_instance_id
            or result.service_generation != self.service_generation
        ):
            raise ControlProtocolError("correlation_mismatch")
        del self._active[result.rpc_id]

    def close(self) -> None:
        self._active.clear()
        object.__setattr__(self, "_closed", True)

    def __reduce__(self) -> Never:
        raise TypeError("control_session_not_serializable")


class BoundedControlQueue:
    """A queue whose capacity can never silently become unbounded."""

    __slots__ = ("_queue", "capacity")

    capacity: int
    _queue: asyncio.Queue[ControlFrame]

    def __init__(self, capacity: int = MAX_ACTIVE_REQUESTS_PER_SESSION) -> None:
        if type(capacity) is not int or not 1 <= capacity <= MAX_ACTIVE_REQUESTS_PER_SESSION:
            raise ValueError("control_queue_capacity_invalid")
        self.capacity = capacity
        self._queue = asyncio.Queue(maxsize=capacity)

    async def put(self, frame: ControlFrame) -> None:
        if type(frame) is not JsonObject:
            raise TypeError("control_frame_invalid")
        await self._queue.put(frame)

    async def get(self) -> ControlFrame:
        return await self._queue.get()

    @property
    def size(self) -> int:
        return self._queue.qsize()


def _fail(reason: str) -> Never:
    raise ControlProtocolError(reason)


def _plain_mapping_for_model(value: object) -> Mapping[str, JsonValue]:
    """Thaw a deeply frozen wire body into plain dicts/lists for pydantic models."""

    if not isinstance(value, Mapping):
        _fail("frame_invalid")
    thawed = strict_json_parse(canonical_encode(cast(JsonValue, value)))
    if type(thawed) is not dict:
        _fail("frame_invalid")
    return cast(Mapping[str, JsonValue], thawed)


def _plain_wire_value(value: object) -> JsonValue:
    if isinstance(value, Enum):
        return cast(JsonValue, value.value)
    if isinstance(value, ControlError):
        body: dict[str, JsonValue] = {"code": value.reason, "retryable": value.retryable}
        if value.correlation_id is not None:
            body["correlation_id"] = value.correlation_id
        if value.phase is not None:
            body["phase"] = value.phase
        if value.accepted_state:
            body["accepted_state"] = {
                key: cast(JsonValue, value.accepted_state[key])
                for key in sorted(value.accepted_state)
            }
        return body
    if isinstance(value, BaseModel):
        # Match public_model_to_wire: keep explicit nulls required by closed schemas,
        # omit unset optional fields (optional_non_null must stay absent, not null).
        return cast(
            JsonValue,
            value.model_dump(mode="json", by_alias=True, exclude_unset=True, exclude_none=False),
        )
    if is_dataclass(value) and not isinstance(value, type):
        converted: dict[str, JsonValue] = {}
        for item in fields(value):
            if item.name.startswith("_"):
                continue
            member = getattr(value, item.name)
            if member is None:
                continue
            converted[item.name] = _plain_wire_value(member)
        return converted
    if isinstance(value, Mapping):
        source = cast(Mapping[object, object], value)
        converted_mapping: dict[str, JsonValue] = {}
        for key, member in source.items():
            if type(key) is not str:
                raise TypeError("control_object_key_invalid")
            converted_mapping[key] = _plain_wire_value(member)
        return converted_mapping
    if type(value) in {list, tuple}:
        return [
            _plain_wire_value(member) for member in cast(list[object] | tuple[object, ...], value)
        ]
    return cast(JsonValue, value)


def _validated_wire(value: object, schema_name: str) -> JsonObject:
    try:
        wire = _plain_wire_value(value)
        if not isinstance(wire, Mapping):
            _fail("frame_invalid")
        schema_version = (
            _CONTROL_RESULT_SCHEMA_VERSION
            if schema_name == "control-result"
            else _CONTROL_REQUEST_SCHEMA_VERSION
            if schema_name == "control-request"
            else _CONTROL_SCHEMA_VERSION
            if schema_name
            in {"control-hello", "control-hello-result", "control-request", "control-result"}
            else _SCHEMA_VERSION
        )
        validate_schema_instance(schema_name, schema_version, wire)
        frozen = freeze_json(wire)
        if type(frozen) is not JsonObject:
            _fail("frame_invalid")
        return frozen
    except ControlProtocolError:
        raise
    except ProtocolValueError, TypeError, ValueError:
        raise ControlProtocolError("frame_invalid") from None


def _schema_name_for_frame(value: Mapping[str, JsonValue]) -> str:
    keys = frozenset(value)
    if "connection_nonce" in keys:
        return "control-hello"
    if "allowed_methods" in keys and "status" in keys:
        return "control-hello-result"
    if "kind" in keys:
        return "control-request"
    if "outcome" in keys:
        return "control-result"
    if "state" in keys and "vault_mode" in keys:
        return "service-status"
    _fail("frame_invalid")


def _is_bounded_import(frame: JsonObject) -> bool:
    if frame.get("kind") != "call" or frame.get("method") != "import_codex_jsonl":
        return False
    body = frame.get("body")
    if type(body) is not JsonObject:
        return False
    encoded = body.get("source_bytes_base64")
    if type(encoded) is not str:
        return False
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except ValueError, binascii.Error:
        return False
    return len(decoded) <= _MAX_IMPORT_SOURCE_BYTES


def _validate_frame_size(payload: bytes, frame: JsonObject) -> None:
    if len(payload) > MAX_CONTROL_FRAME_BYTES:
        _fail("frame_too_large")
    if len(payload) > MAX_ORDINARY_CONTROL_FRAME_BYTES and not _is_bounded_import(frame):
        _fail("frame_too_large")


def encode_control_frame(value: object) -> bytes:
    """Validate and encode one length-prefixed canonical control frame."""

    try:
        wire = _plain_wire_value(value)
        if not isinstance(wire, Mapping):
            _fail("frame_invalid")
        schema_name = _schema_name_for_frame(wire)
        frame = _validated_wire(wire, schema_name)
        payload = canonical_encode(frame)
        _validate_frame_size(payload, frame)
        return struct.pack(">I", len(payload)) + payload
    except ControlProtocolError:
        raise
    except ProtocolValueError, TypeError, ValueError, struct.error:
        raise ControlProtocolError("frame_invalid") from None


def decode_control_frame(frame: bytes) -> ControlFrame:
    """Decode exactly one complete length-prefixed control frame."""

    if type(frame) is not bytes:
        raise TypeError("control_frame_bytes_required")
    if len(frame) < 4:
        _fail("frame_invalid")
    declared = struct.unpack(">I", frame[:4])[0]
    if declared == 0:
        _fail("frame_invalid")
    if declared > MAX_CONTROL_FRAME_BYTES:
        _fail("frame_too_large")
    if len(frame) != declared + 4:
        _fail("frame_invalid")
    return _decode_control_payload(frame[4:])


def _decode_control_payload(payload: bytes) -> ControlFrame:
    """Decode one frame body whose length prefix the caller has already checked."""

    try:
        parsed = strict_json_parse(payload)
        if canonical_encode(parsed) != payload or not isinstance(parsed, Mapping):
            _fail("frame_invalid")
        schema_name = _schema_name_for_frame(parsed)
        value = _validated_wire(parsed, schema_name)
        _validate_frame_size(payload, value)
        return value
    except ControlProtocolError:
        raise
    except ProtocolValueError, TypeError, ValueError:
        raise ControlProtocolError("frame_invalid") from None


async def _read_exact(
    stream: ControlStream, byte_count: int, *, eof_reason: str = "frame_invalid"
) -> bytes:
    chunks: list[bytes] = []
    remaining = byte_count
    while remaining:
        try:
            chunk = await stream.receive(min(remaining, MAX_CONTROL_RECEIVE_CHUNK_BYTES))
        except BaseException as exc:
            if isinstance(exc, asyncio.CancelledError):
                raise
            # A transport failure before the first byte of a frame is indistinguishable, for
            # the caller, from the peer closing on us; both take the caller's EOF reason.
            raise ControlProtocolError(eof_reason if not chunks else "frame_invalid") from None
        if type(chunk) is not bytes or not chunk:
            _fail(eof_reason if not chunks else "frame_invalid")
        if len(chunk) > remaining:
            _fail("frame_invalid")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


async def read_control_frame(
    stream: ControlStream,
    *,
    eof_reason: str = "frame_invalid",
    frame_deadline_seconds: float = CONTROL_FRAME_READ_DEADLINE_SECONDS,
) -> ControlFrame:
    """Read one frame without consuming bytes belonging to its successor.

    ``eof_reason`` names the failure when the peer closes before the first byte of this frame
    arrives. The client handshake uses it to tell "the listening service dropped my hello"
    (``handshake_rejected``: an incompatible peer that closed without answering) apart from a
    frame truncated mid-flight, which stays the generic ``frame_invalid``.

    ``frame_deadline_seconds`` bounds the frame from its first byte to its last
    (``frame_read_timeout``); a declared length above ``MAX_CONTROL_FRAME_BYTES`` is refused as
    ``frame_too_large`` before any body byte is read.
    """

    # Waiting for the first byte is unbounded here; everything after it shares one deadline, so a
    # peer that begins a frame and stalls is cut off as ``frame_read_timeout`` instead of holding
    # the partial body. A declared length above the ceiling is refused before any body is read.
    first = await _read_exact(stream, 1, eof_reason=eof_reason)
    try:
        async with asyncio.timeout(frame_deadline_seconds):
            prefix = first + await _read_exact(stream, 3)
            declared = struct.unpack(">I", prefix)[0]
            if declared == 0:
                _fail("frame_invalid")
            if declared > MAX_CONTROL_FRAME_BYTES:
                _fail("frame_too_large")
            payload = await _read_exact(stream, declared)
    except TimeoutError:
        raise ControlProtocolError("frame_read_timeout") from None
    # Decoding the body directly avoids re-joining prefix and payload: two fewer frame-sized
    # copies at peak for the largest frames.
    return _decode_control_payload(payload)


async def write_control_frame(stream: ControlStream, value: object) -> None:
    """Write one validated frame using the stream's backpressure-aware send.

    Encoding happens before the write, so a frame this caller built wrong never reaches the
    wire and keeps ``frame_invalid``. A failure raised by the stream itself is a transport
    fact about this connection, not a statement about the frame: the bounded
    ``LocalControlTransportError`` travels unchanged so the caller keeps the safe transport
    classification (``service_unavailable`` and friends, retryable), and any other send failure
    becomes the bounded retryable ``transport_failed`` rather than leaking a raw exception.
    Relabelling every send failure ``frame_invalid`` told a caller its valid request was
    malformed, made the client's transport mapping dead code, and published a terminal
    ``INVALID_REQUEST`` for a retryable condition (issue #678).
    """

    encoded = encode_control_frame(value)
    try:
        await stream.send_all(encoded)
    except asyncio.CancelledError, LocalControlTransportError:
        raise
    except BaseException:
        raise ControlProtocolError("transport_failed") from None


def schema_for_method(method: ControlMethod, direction: SchemaDirection) -> Mapping[str, JsonValue]:
    """Return the one frozen reviewed schema branch for a method and direction."""

    if type(method) is not ControlMethod:
        raise TypeError("control_method_invalid")
    if direction not in {"request", "result"}:
        raise ValueError("control_schema_direction_invalid")
    schema_name = "control-request" if direction == "request" else "control-result"
    document = schema_document_for(schema_name, _CONTROL_SCHEMA_VERSION)
    branches = document.json_schema.get("oneOf")
    if not isinstance(branches, list | tuple):
        _fail("frame_invalid")
    matches: list[Mapping[str, JsonValue]] = []
    for branch in branches:
        if not isinstance(branch, Mapping):
            continue
        properties = branch.get("properties")
        if not isinstance(properties, Mapping):
            continue
        method_schema = properties.get("method")
        if not isinstance(method_schema, Mapping) or method_schema.get("const") != method.value:
            continue
        if direction == "result":
            outcome = properties.get("outcome")
            if not isinstance(outcome, Mapping) or outcome.get("const") != "ok":
                continue
        matches.append(cast(Mapping[str, JsonValue], branch))
    if len(matches) != 1:
        _fail("frame_invalid")
    return matches[0]


def validate_request(request: ControlRequest) -> None:
    """Validate a typed request against the exact closed request envelope."""

    _validated_wire(request, "control-request")


def validate_result(result: ControlResult) -> None:
    """Validate a typed result against the exact matching result envelope."""

    if type(result) is not ControlResult:
        raise TypeError("control_result_invalid")
    _validated_wire(result, "control-result")


def _service_status_from_wire(value: object) -> ServiceStatus:
    if not isinstance(value, Mapping):
        _fail("frame_invalid")
    source = cast(Mapping[str, object], value)
    try:
        return ServiceStatus(
            protocol_version=cast(Literal["1.0"], source["protocol_version"]),
            service_version=cast(str, source["service_version"]),
            service_instance_id=cast(str, source["service_instance_id"]),
            service_generation=cast(str, source["service_generation"]),
            state=ServiceState(cast(str, source["state"])),
            state_reason=cast(str, source["state_reason"]),
            vault_mode=cast(str, source["vault_mode"]),
            capabilities=tuple(cast(tuple[str, ...], source["capabilities"])),
            session_monitor=cast(str, source["session_monitor"]),
            idle_relock_seconds=cast(int | None, source.get("idle_relock_seconds")),
        )
    except KeyError, TypeError, ValueError:
        raise ControlProtocolError("frame_invalid") from None


def parse_control_request(frame: ControlFrame) -> ControlRequest:
    """Convert one validated request frame to the exact typed port union."""

    wire = _validated_wire(frame, "control-request")
    try:
        if wire["kind"] == "cancel":
            return ControlCancelRequest(
                kind="cancel",
                protocol_version="1.0",
                rpc_id=cast(str, wire["rpc_id"]),
                service_instance_id=cast(str, wire["service_instance_id"]),
                service_generation=cast(str, wire["service_generation"]),
                target_rpc_id=cast(str, wire["target_rpc_id"]),
            )
        method = ControlMethod(cast(str, wire["method"]))
        raw_body = wire["body"]
        model = _WORKFLOW_REQUEST_MODELS.get(method)
        body = (
            JsonObject(cast(Mapping[str, JsonValue], raw_body))
            if model is None
            else model.model_validate(_plain_mapping_for_model(raw_body))
        )
        deadline = wire.get("deadline_ms")
        return ControlCallRequest(
            kind="call",
            protocol_version="1.0",
            rpc_id=cast(str, wire["rpc_id"]),
            service_instance_id=cast(str, wire["service_instance_id"]),
            service_generation=cast(str, wire["service_generation"]),
            method=method,
            body=body,
            deadline_ms=cast(int | None, deadline),
            route_profile=cast(Literal["policy", "strict"] | None, wire.get("route_profile")),
            host_profile=cast(
                McpHostProfile | None,
                wire.get("host_profile"),
            ),
        )
    except KeyError, TypeError, ValueError:
        raise ControlProtocolError("frame_invalid") from None


def parse_control_result(frame: ControlFrame) -> ControlResult:
    """Convert one validated result frame to the exact typed port result."""

    wire = _validated_wire(frame, "control-result")
    try:
        method = ControlMethod(cast(str, wire["method"]))
        raw_body = wire["body"]
        if wire["outcome"] == "error":
            if not isinstance(raw_body, Mapping):
                _fail("frame_invalid")
            error = cast(Mapping[str, object], raw_body)
            raw_accepted = error.get("accepted_state")
            accepted_state = (
                cast(Mapping[str, SafeDetailValue], raw_accepted)
                if isinstance(raw_accepted, Mapping)
                else None
            )
            raw_correlation = error.get("correlation_id")
            correlation_id = raw_correlation if type(raw_correlation) is str else None
            raw_phase = error.get("phase")
            phase = raw_phase if type(raw_phase) is str else None
            body: object = ControlError(
                cast(str, error["code"]),
                retryable=cast(bool, error["retryable"]),
                accepted_state=accepted_state,
                correlation_id=correlation_id,
                phase=phase,
            )
        elif method in {ControlMethod.SERVICE_STATUS, ControlMethod.SERVICE_LOCK}:
            body = _service_status_from_wire(raw_body)
        elif method is ControlMethod.SERVICE_STOP:
            if not isinstance(raw_body, Mapping):
                _fail("frame_invalid")
            body = ServiceStopResult(
                schema_version=cast(Literal["1.0.0"], raw_body["schema_version"]),
                state=cast(Literal["draining"], raw_body["state"]),
                accepted=cast(Literal[True], raw_body["accepted"]),
            )
        else:
            model = _WORKFLOW_RESULT_MODELS.get(method)
            body = (
                JsonObject(cast(Mapping[str, JsonValue], raw_body))
                if model is None
                else model.model_validate(_plain_mapping_for_model(raw_body))
            )
        return ControlResult(
            protocol_version="1.0",
            rpc_id=cast(str, wire["rpc_id"]),
            service_instance_id=cast(str, wire["service_instance_id"]),
            service_generation=cast(str, wire["service_generation"]),
            method=method,
            outcome=cast(Literal["ok", "error"], wire["outcome"]),
            body=body,
        )
    except ControlProtocolError:
        raise
    except KeyError, TypeError, ValueError:
        raise ControlProtocolError("frame_invalid") from None


def _status_wire(status: ServiceStatus) -> JsonObject:
    if type(status) is not ServiceStatus:
        raise TypeError("service_status_invalid")
    return _validated_wire(status, "service-status")


def _allowed_for(kind: ControlClientKind) -> tuple[ControlMethod, ...]:
    return _WORKFLOW_METHODS if kind is ControlClientKind.MCP_BRIDGE else _ALL_METHODS


def _hello_result_wire(
    service_status: ServiceStatus, allowed: tuple[ControlMethod, ...]
) -> dict[str, JsonValue]:
    return {
        "protocol_version": CONTROL_PROTOCOL_VERSION,
        "service_version": service_status.service_version,
        "service_instance_id": service_status.service_instance_id,
        "service_generation": service_status.service_generation,
        "status": _status_wire(service_status),
        "allowed_methods": [method.value for method in allowed],
        "schema_manifest_digest": _manifest_digest(),
    }


def _manifest_digest() -> str:
    # sha256(manifest.json) only — never build the catalog to hash it (#210).
    return schema_manifest_digest()


async def _close_after_failure(stream: ControlStream, error: BaseException) -> Never:
    try:
        await stream.aclose()
    except BaseException:
        pass
    if isinstance(error, ControlProtocolError):
        raise error
    if isinstance(error, LocalControlTransportError):
        # A handshake that failed on the transport is not a malformed handshake. Both peers
        # already classify this bounded reason; folding it into `frame_invalid` here would
        # restore the mislabelling the write path just stopped doing (issue #678).
        raise error
    raise ControlProtocolError("frame_invalid") from None


async def client_handshake(
    stream: ControlStream,
    client_kind: ControlClientKind,
    client_version: str,
    *,
    workspace_locator: WorkspaceLocator | None = None,
    projection_render_mode: ProjectionRenderMode = ProjectionRenderMode.MACHINE_READABLE,
    output_is_controlling_tty: bool = False,
) -> ControlSession:
    """Negotiate an ordinary peer-authenticated client session."""

    if type(client_kind) is not ControlClientKind:
        raise TypeError("control_client_kind_invalid")
    if workspace_locator is not None and type(workspace_locator) is not WorkspaceLocator:
        raise TypeError("workspace_locator_invalid")
    if type(projection_render_mode) is not ProjectionRenderMode:
        raise TypeError("projection_render_mode_invalid")
    if type(output_is_controlling_tty) is not bool:
        raise TypeError("projection_tty_fact_invalid")
    nonce = secrets.token_hex(32)
    hello: dict[str, JsonValue] = {
        "protocol_version": CONTROL_PROTOCOL_VERSION,
        "client_kind": client_kind.value,
        "client_version": client_version,
        "connection_nonce": nonce,
        "schema_manifest_digest": _manifest_digest(),
    }
    if workspace_locator is not None:
        hello["workspace_locator"] = {
            "schema_version": workspace_locator.schema_version,
            "path": workspace_locator.path,
        }
    hello["presentation_context"] = {
        "render_mode": projection_render_mode.value,
        "output_is_controlling_tty": output_is_controlling_tty,
    }
    try:
        await write_control_frame(stream, hello)
        # A service that rejects this hello (schema-manifest or protocol mismatch, or a hello
        # shape its decoder does not know) closes without answering. Name that outcome so the
        # client can treat the listening peer as incompatible instead of merely malformed.
        result = await read_control_frame(stream, eof_reason="handshake_rejected")
        _validated_wire(result, "control-hello-result")
        if result["protocol_version"] != CONTROL_PROTOCOL_VERSION:
            _fail("protocol_mismatch")
        if result["schema_manifest_digest"] != _manifest_digest():
            _fail("manifest_mismatch")
        status = _service_status_from_wire(result["status"])
        if (
            status.service_version != result["service_version"]
            or status.service_instance_id != result["service_instance_id"]
            or status.service_generation != result["service_generation"]
        ):
            _fail("protocol_mismatch")
        raw_allowed = result["allowed_methods"]
        if type(raw_allowed) is not tuple:
            _fail("protocol_mismatch")
        allowed = tuple(ControlMethod(cast(str, method)) for method in raw_allowed)
        if allowed != _allowed_for(client_kind):
            _fail("method_forbidden")
        return ControlSession(
            protocol_version="1.0",
            client_kind=client_kind,
            service_instance_id=cast(str, result["service_instance_id"]),
            service_generation=cast(str, result["service_generation"]),
            allowed_methods=allowed,
            peer_identity=stream.peer_identity,
            connection_nonce=nonce,
            projection_render_mode=projection_render_mode,
            output_is_controlling_tty=output_is_controlling_tty,
            service_status=status,
        )
    except BaseException as exc:
        if isinstance(exc, asyncio.CancelledError):
            raise
        await _close_after_failure(stream, exc)


async def server_handshake(
    stream: ControlStream,
    peer_identity: object,
    service_status: ServiceStatus,
    *,
    repository_context_resolver: Callable[
        [WorkspaceLocator], Awaitable[RepositoryPrivacyContext | None]
    ]
    | None = None,
) -> ControlSession:
    """Negotiate a server session only after transport peer authentication."""

    try:
        if stream.peer_identity is not peer_identity:
            _fail("peer_untrusted")
        hello = await read_control_frame(stream)
        _validated_wire(hello, "control-hello")
        if hello["protocol_version"] != CONTROL_PROTOCOL_VERSION:
            _fail("protocol_mismatch")
        kind = ControlClientKind(cast(str, hello["client_kind"]))
        if hello["schema_manifest_digest"] != _manifest_digest():
            # Answer with this installation's hello-result so a peer that still
            # decodes the frozen 2.x shape names `manifest_mismatch` instead of
            # treating a silent close as `frame_invalid`. The session is not admitted.
            await write_control_frame(
                stream, _hello_result_wire(service_status, _allowed_for(kind))
            )
            _fail("manifest_mismatch")
        raw_presentation = hello.get("presentation_context")
        render_mode = ProjectionRenderMode.MACHINE_READABLE
        output_is_controlling_tty = False
        if raw_presentation is not None:
            if not isinstance(raw_presentation, Mapping):
                _fail("protocol_mismatch")
            render_mode = ProjectionRenderMode(cast(str, raw_presentation["render_mode"]))
            output_is_controlling_tty = cast(bool, raw_presentation["output_is_controlling_tty"])
            if type(output_is_controlling_tty) is not bool:
                _fail("protocol_mismatch")
        raw_locator = hello.get("workspace_locator")
        repository_context: RepositoryPrivacyContext | None = None
        if raw_locator is not None and repository_context_resolver is not None:
            if not isinstance(raw_locator, Mapping):
                _fail("protocol_mismatch")
            locator_wire = cast(Mapping[str, JsonValue], raw_locator)
            repository_context = await repository_context_resolver(
                WorkspaceLocator(
                    path=cast(str, locator_wire["path"]),
                    schema_version=cast(Literal["1.0.0"], locator_wire["schema_version"]),
                )
            )
            if (
                repository_context is not None
                and type(repository_context) is not RepositoryPrivacyContext
            ):
                _fail("protocol_mismatch")
        allowed = _allowed_for(kind)
        await write_control_frame(stream, _hello_result_wire(service_status, allowed))
        return ControlSession(
            protocol_version="1.0",
            client_kind=kind,
            service_instance_id=service_status.service_instance_id,
            service_generation=service_status.service_generation,
            allowed_methods=allowed,
            repository_privacy_context=repository_context,
            projection_render_mode=render_mode,
            output_is_controlling_tty=output_is_controlling_tty,
            peer_identity=peer_identity,
            connection_nonce=cast(str, hello["connection_nonce"]),
        )
    except BaseException as exc:
        if isinstance(exc, asyncio.CancelledError):
            raise
        await _close_after_failure(stream, exc)


def public_error_code_for_control_reason(reason: str) -> PublicErrorCode:
    """Map a bounded control reason without exposing wire-only tokens."""

    if reason in _COORDINATION_CONTROL_ERROR_REASONS:
        # Project lifecycle refusals are caller-actionable command outcomes. They share the
        # INVALID_REQUEST shell exit while the original finite token remains available to the CLI
        # renderer and MCP-safe reason projection.
        return PublicErrorCode.INVALID_REQUEST
    if reason in {
        "service_generation_changed",
        "privacy_projection_unavailable",
        "service_unavailable",
        "service_incompatible",
        "request_timeout",
        "endpoint_unsafe",
        "peer_untrusted",
        "service_draining",
        "transport_failed",
    }:
        return PublicErrorCode.SERVICE_UNAVAILABLE
    if reason == "privacy_projection_blocked":
        return PublicErrorCode.PRIVACY_AUTHORITY_REQUIRED
    # The request was valid and reached the audit store; a stored receipt it holds cannot be read
    # back. That is the store's condition, never the caller's INVALID_REQUEST (issue #921).
    if reason == "privacy_audit_unreadable":
        return PublicErrorCode.STORAGE_CORRUPT
    if reason == "vault_locked":
        return PublicErrorCode.VAULT_LOCKED
    if reason == "request_cancelled":
        return PublicErrorCode.CANCELLED
    # The operation completed; only its response could not be shaped. The public code stays
    # INTERNAL_ERROR, but the bridge pairs it with retryable=True and a same-request_id remedy.
    if reason in {"internal_error", "response_projection_failed", "read_projection_failed"}:
        return PublicErrorCode.INTERNAL_ERROR
    if reason in {
        "invalid_request",
        "frame_invalid",
        "frame_too_large",
        "method_forbidden",
        "protocol_mismatch",
    }:
        return PublicErrorCode.INVALID_REQUEST
    return PublicErrorCode.SERVICE_UNAVAILABLE
