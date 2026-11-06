"""Unit tests for the frozen ordinary local-service control protocol."""

from __future__ import annotations

import asyncio
import base64
import struct
from collections.abc import Buffer
from typing import Any, cast

import pytest

from finishup.adapters.control.unix_socket import LocalControlTransportError
from finishup.adapters.repository_identity import RepositoryIdentityError
from finishup.domain.values import JsonObject
from finishup.ports.control import (
    ControlCallRequest,
    ControlCancelRequest,
    ControlClientKind,
    ControlError,
    ControlMethod,
    ControlResult,
    ProjectionRenderMode,
    RepositoryPrivacyContext,
    ServiceState,
    ServiceStatus,
    WorkspaceAgentDeclaration,
    WorkspaceCall,
    WorkspaceClaim,
    WorkspaceLocator,
    WorkspaceReply,
)
from finishup.ports.workspace_agent import workspace_handle_for_claim
from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.protocol.errors import PublicErrorCode
from finishup.protocol.schemas import (
    SchemaInstanceInvalid,
    load_schema_catalog,
    validate_schema_instance,
)
from finishup.service.control_protocol import (
    CONTROL_PROTOCOL_VERSION,
    MAX_ACTIVE_REQUESTS_PER_SESSION,
    MAX_CONTROL_FRAME_BYTES,
    MAX_ORDINARY_CONTROL_FRAME_BYTES,
    BoundedControlQueue,
    ControlProtocolError,
    ControlSession,
    HandshakeServiceFault,
    client_handshake,
    decode_control_frame,
    encode_control_frame,
    is_workspace_call_frame,
    is_workspace_reply_frame,
    parse_control_request,
    parse_control_result,
    parse_workspace_call,
    parse_workspace_reply,
    public_error_code_for_control_reason,
    read_control_frame,
    schema_for_method,
    server_handshake,
    workspace_call_frame,
    workspace_reply_frame,
    write_control_frame,
    write_workspace_call,
    write_workspace_reply,
)

_SERVICE_ID = "svc_00000000-0000-4000-8000-000000000001"
_REQUEST_ID = "req_00000000-0000-4000-8000-000000000002"
_SESSION_ID = "ses_00000000-0000-4000-8000-000000000003"
_WRITER_ID = "wri_00000000-0000-4000-8000-000000000004"


def _rpc_id(sequence: int) -> str:
    return f"rpc_00000000-0000-4000-8000-{sequence:012x}"


def _hello(*, client_kind: str = "cli") -> dict[str, JsonValue]:
    return {
        "protocol_version": "1.0",
        "client_kind": client_kind,
        "client_version": "0.1.0",
        "connection_nonce": "0" * 64,
        "schema_manifest_digest": load_schema_catalog().manifest_digest,
    }


def _status() -> ServiceStatus:
    return ServiceStatus(
        protocol_version="1.0",
        service_version="0.1.0",
        service_instance_id=_SERVICE_ID,
        service_generation="1",
        state=ServiceState.LOCKED,
        state_reason="human_authority_unavailable",
        vault_mode="uninitialized",
        capabilities=(),
        session_monitor="unavailable",
    )


def _status_call(sequence: int) -> ControlCallRequest:
    return ControlCallRequest(
        kind="call",
        protocol_version="1.0",
        rpc_id=_rpc_id(sequence),
        service_instance_id=_SERVICE_ID,
        service_generation="1",
        method=ControlMethod.SERVICE_STATUS,
        body=JsonObject({}),
    )


def _assert_reason(error: pytest.ExceptionInfo[ControlProtocolError], reason: str) -> None:
    assert error.value.reason == reason
    assert error.value.args == (reason,)


def test_canonical_frame_golden_and_exact_consumption() -> None:
    hello = _hello()
    payload = canonical_encode(hello)
    expected = struct.pack(">I", len(payload)) + payload

    assert CONTROL_PROTOCOL_VERSION == "1.0"
    assert MAX_CONTROL_FRAME_BYTES == 6_291_456
    assert MAX_ORDINARY_CONTROL_FRAME_BYTES == 1_048_576
    assert encode_control_frame(hello) == expected
    assert decode_control_frame(expected) == hello

    with pytest.raises(ControlProtocolError) as trailing:
        decode_control_frame(expected + b"x")
    _assert_reason(trailing, "frame_invalid")


@pytest.mark.parametrize(
    ("frame", "reason"),
    [
        (b"", "frame_invalid"),
        (b"\x00\x00\x00\x00", "frame_invalid"),
        (struct.pack(">I", MAX_CONTROL_FRAME_BYTES + 1), "frame_too_large"),
        (b"\x00\x00\x00\x02{}", "frame_invalid"),
        (b"\x00\x00\x00\x03{}x", "frame_invalid"),
    ],
)
def test_length_and_payload_failures_are_sanitized(frame: bytes, reason: str) -> None:
    with pytest.raises(ControlProtocolError) as caught:
        decode_control_frame(frame)
    _assert_reason(caught, reason)


@pytest.mark.parametrize(
    "payload",
    [
        b'{"client_kind":"cli","client_kind":"ui"}',
        b"\xef\xbb\xbf{}",
        b'{"value":1.0}',
        b'{"value":-0}',
        b'{"value":"\\ud800"}',
        b'{"value":"x\\u0000y"}',
        b'{"client_kind": "cli"}',
    ],
)
def test_strict_json_failures_never_echo_input(payload: bytes) -> None:
    frame = struct.pack(">I", len(payload)) + payload
    with pytest.raises(ControlProtocolError) as caught:
        decode_control_frame(frame)
    _assert_reason(caught, "frame_invalid")
    assert payload not in str(caught.value).encode()


def test_large_frame_exception_is_only_the_exact_bounded_import_branch() -> None:
    source = b"x" * 800_000
    request: dict[str, JsonValue] = {
        "kind": "call",
        "protocol_version": "1.0",
        "rpc_id": _rpc_id(1),
        "service_instance_id": _SERVICE_ID,
        "service_generation": "1",
        "method": "import_codex_jsonl",
        "body": {
            "schema_version": "1.0.0",
            "codex_capability_profile_id": "codex-local",
            "codex_version": "0.1.0",
            "exit_status": 0,
            "mapping_version": "v1",
            "request_id": _REQUEST_ID,
            "session_id": _SESSION_ID,
            "source_bytes_base64": base64.b64encode(source).decode("ascii"),
            "source_encoding": "base64",
            "source_kind": "file",
            "stderr_captured_bytes": 0,
            "stderr_present": False,
            "stderr_truncated": False,
            "writer_id": _WRITER_ID,
        },
    }
    encoded = encode_control_frame(request)
    assert len(encoded) - 4 > MAX_ORDINARY_CONTROL_FRAME_BYTES
    assert decode_control_frame(encoded)["method"] == "import_codex_jsonl"

    for field, value in (
        ("stderr_present", True),
        ("stderr_captured_bytes", 1),
        ("stderr_truncated", True),
    ):
        legacy_body = dict(cast(dict[str, JsonValue], request["body"]))
        legacy_body[field] = value
        legacy = dict(request)
        legacy["body"] = legacy_body
        with pytest.raises(ControlProtocolError) as legacy_stderr:
            encode_control_frame(legacy)
        _assert_reason(legacy_stderr, "frame_invalid")

    widened = dict(request)
    widened["method"] = "service_status"
    with pytest.raises(ControlProtocolError) as wrong_branch:
        encode_control_frame(widened)
    _assert_reason(wrong_branch, "frame_invalid")

    too_large_body = dict(cast(dict[str, JsonValue], request["body"]))
    too_large_body["source_bytes_base64"] = base64.b64encode(b"x" * (4 * 1024 * 1024 + 1)).decode(
        "ascii"
    )
    too_large = dict(request)
    too_large["body"] = too_large_body
    with pytest.raises(ControlProtocolError) as source_overflow:
        encode_control_frame(too_large)
    _assert_reason(source_overflow, "frame_invalid")


def test_method_schema_registry_is_closed_and_secret_fields_are_impossible() -> None:
    for method in ControlMethod:
        request = schema_for_method(method, "request")
        result = schema_for_method(method, "result")
        assert cast(dict[str, JsonValue], request["properties"])["method"] == {
            "const": method.value
        }
        assert cast(dict[str, JsonValue], result["properties"])["method"] == {"const": method.value}

    request = _plain_status_call()
    request["body"] = {"passphrase": "must-not-cross"}
    with pytest.raises(ControlProtocolError) as secret:
        encode_control_frame(request)
    _assert_reason(secret, "frame_invalid")


def _plain_status_call() -> dict[str, JsonValue]:
    return {
        "kind": "call",
        "protocol_version": "1.0",
        "rpc_id": _rpc_id(1),
        "service_instance_id": _SERVICE_ID,
        "service_generation": "1",
        "method": "service_status",
        "body": {},
    }


def test_session_admission_cap_duplicate_and_result_correlation() -> None:
    peer = object()
    session = ControlSession(
        protocol_version="1.0",
        client_kind=ControlClientKind.CLI,
        service_instance_id=_SERVICE_ID,
        service_generation="1",
        allowed_methods=tuple(sorted(ControlMethod, key=lambda item: item.value.encode("ascii"))),
        peer_identity=peer,
        connection_nonce="1" * 64,
    )
    for sequence in range(1, MAX_ACTIVE_REQUESTS_PER_SESSION + 1):
        session.admit(_status_call(sequence))
    assert session.active_request_count == MAX_ACTIVE_REQUESTS_PER_SESSION

    with pytest.raises(ControlProtocolError) as duplicate:
        session.admit(_status_call(1))
    _assert_reason(duplicate, "duplicate_rpc_id")
    with pytest.raises(ControlProtocolError) as full:
        session.admit(_status_call(MAX_ACTIVE_REQUESTS_PER_SESSION + 1))
    _assert_reason(full, "request_limit_exceeded")

    session.admit(
        ControlCancelRequest(
            kind="cancel",
            protocol_version="1.0",
            rpc_id=_rpc_id(99),
            service_instance_id=_SERVICE_ID,
            service_generation="1",
            target_rpc_id=_rpc_id(1),
        )
    )
    with pytest.raises(ControlProtocolError) as unknown_target:
        session.admit(
            ControlCancelRequest(
                kind="cancel",
                protocol_version="1.0",
                rpc_id=_rpc_id(100),
                service_instance_id=_SERVICE_ID,
                service_generation="1",
                target_rpc_id=_rpc_id(1000),
            )
        )
    _assert_reason(unknown_target, "correlation_mismatch")

    result = ControlResult(
        protocol_version="1.0",
        rpc_id=_rpc_id(1),
        service_instance_id=_SERVICE_ID,
        service_generation="1",
        method=ControlMethod.SERVICE_STATUS,
        outcome="ok",
        body=_status(),
    )
    session.correlate(result)
    assert session.active_request_count == MAX_ACTIVE_REQUESTS_PER_SESSION - 1
    with pytest.raises(ControlProtocolError) as lost:
        session.correlate(result)
    _assert_reason(lost, "correlation_mismatch")


def test_wire_frames_convert_to_exact_typed_request_and_result() -> None:
    request = _status_call(7)
    parsed_request = parse_control_request(decode_control_frame(encode_control_frame(request)))
    assert parsed_request == request
    assert type(cast(ControlCallRequest, parsed_request).body) is JsonObject

    result = ControlResult(
        protocol_version="1.0",
        rpc_id=_rpc_id(7),
        service_instance_id=_SERVICE_ID,
        service_generation="1",
        method=ControlMethod.SERVICE_STATUS,
        outcome="ok",
        body=_status(),
    )
    parsed_result = parse_control_result(decode_control_frame(encode_control_frame(result)))
    assert parsed_result == result
    assert type(parsed_result.body) is ServiceStatus


def test_status_projection_phase_survives_the_control_wire() -> None:
    result = ControlResult(
        protocol_version="1.0",
        rpc_id=_rpc_id(8),
        service_instance_id=_SERVICE_ID,
        service_generation="1",
        method=ControlMethod.STATUS,
        outcome="error",
        body=ControlError(
            "read_projection_failed",
            retryable=True,
            correlation_id="err_00000000-0000-4000-8000-000000000009",
            phase="projection",
        ),
    )

    parsed = parse_control_result(decode_control_frame(encode_control_frame(result)))

    assert isinstance(parsed.body, ControlError)
    assert parsed.body.reason == "read_projection_failed"
    assert parsed.body.retryable is True
    assert parsed.body.phase == "projection"
    original_error = result.body
    assert isinstance(original_error, ControlError)
    assert parsed.body.correlation_id == original_error.correlation_id


def test_workflow_start_request_round_trips_through_frozen_json_object() -> None:
    from finishup.protocol.models import StartRequest

    start = StartRequest.model_validate(
        {
            "protocol_version": "0.1",
            "schema_version": "1.0.0",
            "request_id": _REQUEST_ID,
            "mode": "create",
            "task_title": "Make documentation fully consistent",
            "actor": {"actor_id": "harness:pytest", "actor_type": "harness"},
            "client": {
                "kind": "yoetz_cli",
                "version": "0.1.0",
                "integration": "local_cli",
            },
            "requested_view": "compact",
        }
    )
    request = ControlCallRequest(
        kind="call",
        protocol_version="1.0",
        rpc_id=_rpc_id(9),
        service_instance_id=_SERVICE_ID,
        service_generation="1",
        method=ControlMethod.START,
        body=start,
    )
    parsed = parse_control_request(decode_control_frame(encode_control_frame(request)))
    assert isinstance(parsed, ControlCallRequest)
    assert parsed.method is ControlMethod.START
    assert isinstance(parsed.body, StartRequest)
    assert parsed.body.request_id == start.request_id
    assert parsed.body.task_title == start.task_title
    assert parsed.body.mode == start.mode


def test_private_mcp_route_profile_round_trips_only_for_check_and_status() -> None:
    from finishup.protocol.models import CheckRequest

    check = CheckRequest.model_validate(
        {
            "protocol_version": "0.1",
            "schema_version": "1.0.0",
            "request_id": _REQUEST_ID,
            "session_id": _SESSION_ID,
            "writer_id": _WRITER_ID,
            "expected_frontier": {"sequence": "0", "head_digest": "genesis"},
            "mode": "semantic_required",
            "actor": {"actor_id": "harness:pytest", "actor_type": "harness"},
            "client": {
                "kind": "cooperative_agent",
                "version": "0.1.0",
                "integration": "cooperative_mcp",
            },
        }
    )
    request = ControlCallRequest(
        kind="call",
        protocol_version="1.0",
        rpc_id=_rpc_id(10),
        service_instance_id=_SERVICE_ID,
        service_generation="1",
        method=ControlMethod.CHECK,
        body=check,
        route_profile="strict",
        host_profile="codex",
    )

    wire = decode_control_frame(encode_control_frame(request))
    parsed = parse_control_request(wire)

    assert isinstance(parsed, ControlCallRequest)
    assert parsed.route_profile == "strict"
    assert parsed.host_profile == "codex"
    legacy_wire = dict(wire)
    legacy_wire.pop("host_profile")
    for version in ("1.0.0", "2.0.0", "2.1.0", "2.2.0", "2.3.0"):
        validate_schema_instance("control-request", version, legacy_wire)
        with pytest.raises(SchemaInstanceInvalid):
            validate_schema_instance("control-request", version, wire)
    validate_schema_instance("control-request", "2.4.0", wire)
    with pytest.raises(ValueError, match="control_route_profile_invalid"):
        ControlCallRequest(
            kind="call",
            protocol_version="1.0",
            rpc_id=_rpc_id(11),
            service_instance_id=_SERVICE_ID,
            service_generation="1",
            method=ControlMethod.SERVICE_STATUS,
            body=JsonObject({}),
            route_profile="strict",
        )
    with pytest.raises(ValueError, match="control_host_profile_invalid"):
        ControlCallRequest(
            kind="call",
            protocol_version="1.0",
            rpc_id=_rpc_id(12),
            service_instance_id=_SERVICE_ID,
            service_generation="1",
            method=ControlMethod.CHECK,
            body=check,
            host_profile="vscode",  # type: ignore[arg-type]
        )


class _MemoryStream:
    def __init__(self, peer_identity: object) -> None:
        self.peer_identity = peer_identity
        self.other: _MemoryStream | None = None
        self.closed = False
        self._chunks: asyncio.Queue[bytes] = asyncio.Queue(maxsize=4)
        self._buffer = bytearray()

    async def receive(self, max_bytes: int) -> bytes:
        while not self._buffer:
            chunk = await self._chunks.get()
            if not chunk:
                return b""
            self._buffer.extend(chunk)
        chunk = bytes(self._buffer[:max_bytes])
        del self._buffer[:max_bytes]
        return chunk

    async def send_all(self, data: Buffer) -> None:
        assert self.other is not None
        await self.other._chunks.put(bytes(data))

    async def aclose(self) -> None:
        self.closed = True

    def close_inbound(self) -> None:
        """Deliver the end of stream the peer's close would: the next read returns no bytes."""

        self._chunks.put_nowait(b"")


def _stream_pair() -> tuple[_MemoryStream, _MemoryStream, object]:
    client_peer = object()
    service_peer = object()
    client = _MemoryStream(service_peer)
    server = _MemoryStream(client_peer)
    client.other = server
    server.other = client
    return client, server, client_peer


def test_handshake_negotiates_exact_mcp_authority_and_peer_binding() -> None:
    async def exercise() -> None:
        client, server, client_peer = _stream_pair()
        client_result, server_result = await asyncio.gather(
            client_handshake(client, ControlClientKind.MCP_BRIDGE, "0.1.0"),
            server_handshake(server, client_peer, _status()),
        )

        assert client_result.allowed_methods == server_result.allowed_methods
        assert tuple(method.value for method in client_result.allowed_methods) == (
            "check",
            "publish_work",
            "receipt",
            "respond",
            "start",
            "status",
        )
        assert client_result.connection_nonce == server_result.connection_nonce
        assert client_result.peer_identity is client.peer_identity
        assert server_result.peer_identity is client_peer

    asyncio.run(exercise())


def test_v2_handshake_consumes_locator_and_retains_only_opaque_server_context() -> None:
    async def exercise() -> None:
        client, server, client_peer = _stream_pair()
        observed: list[str] = []
        context = RepositoryPrivacyContext("hmac-sha256:" + "1" * 64, "git_common_root")

        async def resolve(locator: WorkspaceLocator) -> RepositoryPrivacyContext:
            observed.append(locator.path)
            return context

        client_result, server_result = await asyncio.gather(
            client_handshake(
                client,
                ControlClientKind.CLI,
                "0.1.0",
                workspace_locator=WorkspaceLocator("/private/raw-repository"),
                projection_render_mode=ProjectionRenderMode.HUMAN_READABLE,
                output_is_controlling_tty=True,
            ),
            server_handshake(
                server,
                client_peer,
                _status(),
                repository_context_resolver=resolve,
            ),
        )

        assert observed == ["/private/raw-repository"]
        assert client_result.repository_privacy_context is None
        assert server_result.repository_privacy_context == context
        assert server_result.projection_render_mode is ProjectionRenderMode.HUMAN_READABLE
        assert server_result.output_is_controlling_tty is True
        assert "raw-repository" not in repr(server_result)

    asyncio.run(exercise())


def test_legacy_hello_remains_unbound_and_never_invokes_locator_resolver() -> None:
    async def exercise() -> None:
        client, server, client_peer = _stream_pair()

        async def reject(_locator: WorkspaceLocator) -> RepositoryPrivacyContext:
            raise AssertionError("legacy hello must not resolve a repository")

        _client_result, server_result = await asyncio.gather(
            client_handshake(client, ControlClientKind.CLI, "0.1.0"),
            server_handshake(
                server,
                client_peer,
                _status(),
                repository_context_resolver=reject,
            ),
        )
        assert server_result.repository_privacy_context is None

    asyncio.run(exercise())


@pytest.mark.parametrize(
    ("raised", "refusal"),
    [
        (RepositoryIdentityError("git_version_unsupported"), "git_version_unsupported"),
        (
            RepositoryIdentityError("repository_identity_unavailable"),
            "repository_identity_unavailable",
        ),
        (RuntimeError("/private/raw-repository: fatal"), None),
    ],
)
def test_a_service_side_handshake_fault_is_typed_for_the_daemon(
    raised: Exception, refusal: str | None
) -> None:
    """#1040: a resolver fault after unlock closes the hello as a typed, recordable fault."""

    async def exercise() -> tuple[HandshakeServiceFault, BaseException]:
        client, server, client_peer = _stream_pair()

        async def fail(_locator: WorkspaceLocator) -> RepositoryPrivacyContext:
            raise raised

        hello = asyncio.create_task(
            client_handshake(
                client,
                ControlClientKind.CLI,
                "0.1.0",
                workspace_locator=WorkspaceLocator("/private/raw-repository"),
            )
        )
        with pytest.raises(HandshakeServiceFault) as fault:
            await server_handshake(server, client_peer, _status(), repository_context_resolver=fail)
        # The service closed without answering, which the client reads as `handshake_rejected`.
        assert server.closed
        client.close_inbound()
        rejected = (await asyncio.gather(hello, return_exceptions=True))[0]
        assert isinstance(rejected, BaseException)
        return fault.value, rejected

    fault, rejected = asyncio.run(exercise())
    assert fault.reason == "handshake_service_fault"
    assert fault.refusal == refusal
    assert fault.__cause__ is raised
    # Nothing the fault carries names the locator; only the closed token travels.
    assert "/private/raw-repository" not in f"{fault!r} {fault}"
    assert isinstance(rejected, ControlProtocolError)
    assert rejected.reason == "handshake_rejected"


def test_the_daemon_records_a_handshake_fault_by_its_closed_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from finishup.service import daemon

    public: list[dict[str, object]] = []
    unexpected: list[tuple[BaseException, dict[str, object]]] = []

    def record_public(**fields: object) -> str:
        public.append(fields)
        return "err_00000000-0000-4000-8000-000000000001"

    def record_unexpected(exc: BaseException, **fields: object) -> str:
        unexpected.append((exc, fields))
        return "err_00000000-0000-4000-8000-000000000002"

    monkeypatch.setattr(daemon, "record_public_error_without_raising", record_public)
    monkeypatch.setattr(daemon, "record_unexpected_exception_without_raising", record_unexpected)
    record = daemon._record_handshake_service_fault  # pyright: ignore[reportPrivateUsage]

    record(HandshakeServiceFault("git_version_unsupported"))
    cause = RuntimeError("/private/raw-repository")
    fault = HandshakeServiceFault()
    fault.__cause__ = cause
    record(fault)

    assert public == [
        {
            "component": "service.daemon",
            "operation": "control_handshake",
            "reason": "handshake_service_fault",
            "reason_code": "git_version_unsupported",
        }
    ]
    assert unexpected == [
        (
            cause,
            {
                "component": "service.daemon",
                "operation": "control_handshake",
                "phase": "handshake",
            },
        )
    ]


def test_partial_reads_do_not_consume_the_next_frame_and_eof_is_fatal() -> None:
    first = encode_control_frame(_hello())
    second = encode_control_frame(_hello(client_kind="ui"))

    class _Chunked:
        peer_identity = object()

        def __init__(self, data: bytes) -> None:
            self.data = bytearray(data)

        async def receive(self, max_bytes: int) -> bytes:
            if not self.data:
                return b""
            count = min(3, max_bytes, len(self.data))
            chunk = bytes(self.data[:count])
            del self.data[:count]
            return chunk

        async def send_all(self, data: Buffer) -> None:
            raise AssertionError(bytes(data))

        async def aclose(self) -> None:
            return None

    async def exercise() -> None:
        stream = _Chunked(first + second)
        assert (await read_control_frame(stream))["client_kind"] == "cli"
        assert (await read_control_frame(stream))["client_kind"] == "ui"

        truncated = _Chunked(first[:-1])
        with pytest.raises(ControlProtocolError) as eof:
            await read_control_frame(truncated)
        _assert_reason(eof, "frame_invalid")

    asyncio.run(exercise())


def test_bounded_queue_applies_backpressure() -> None:
    async def exercise() -> None:
        queue = BoundedControlQueue(capacity=1)
        frame = decode_control_frame(encode_control_frame(_hello()))
        await queue.put(frame)
        blocked = asyncio.create_task(queue.put(frame))
        await asyncio.sleep(0)
        assert not blocked.done()
        assert await queue.get() == frame
        await blocked
        assert queue.size == 1

    asyncio.run(exercise())


def test_wire_only_errors_map_to_existing_public_codes() -> None:
    assert (
        public_error_code_for_control_reason("service_generation_changed")
        is PublicErrorCode.SERVICE_UNAVAILABLE
    )
    assert (
        public_error_code_for_control_reason("privacy_projection_unavailable")
        is PublicErrorCode.SERVICE_UNAVAILABLE
    )
    assert (
        public_error_code_for_control_reason("privacy_projection_blocked")
        is PublicErrorCode.PRIVACY_AUTHORITY_REQUIRED
    )
    assert public_error_code_for_control_reason("vault_locked") is PublicErrorCode.VAULT_LOCKED
    assert public_error_code_for_control_reason("frame_invalid") is PublicErrorCode.INVALID_REQUEST
    assert (
        public_error_code_for_control_reason("invalid_request") is PublicErrorCode.INVALID_REQUEST
    )
    assert (
        public_error_code_for_control_reason("endpoint_unsafe")
        is PublicErrorCode.SERVICE_UNAVAILABLE
    )
    assert (
        public_error_code_for_control_reason("peer_untrusted")
        is PublicErrorCode.SERVICE_UNAVAILABLE
    )
    assert (
        public_error_code_for_control_reason("service_draining")
        is PublicErrorCode.SERVICE_UNAVAILABLE
    )


def test_client_handshake_names_a_peer_that_closes_on_the_hello_as_rejected() -> None:
    """A service that rejects the hello closes without answering; that is not a bad frame."""

    class _ClosesAfterHello:
        peer_identity = object()

        def __init__(self, answer: bytes) -> None:
            self.sent: list[bytes] = []
            self.answer = bytearray(answer)

        async def receive(self, max_bytes: int) -> bytes:
            if not self.answer:
                return b""
            chunk = bytes(self.answer[:max_bytes])
            del self.answer[:max_bytes]
            return chunk

        async def send_all(self, data: Buffer) -> None:
            self.sent.append(bytes(data))

        async def aclose(self) -> None:
            return None

    async def exercise() -> None:
        rejected = _ClosesAfterHello(b"")
        with pytest.raises(ControlProtocolError) as eof:
            await client_handshake(rejected, ControlClientKind.MCP_BRIDGE, "0.1.0")
        _assert_reason(eof, "handshake_rejected")
        assert len(rejected.sent) == 1

        truncated = _ClosesAfterHello(b"\x00\x00")
        with pytest.raises(ControlProtocolError) as partial:
            await client_handshake(truncated, ControlClientKind.MCP_BRIDGE, "0.1.0")
        _assert_reason(partial, "frame_invalid")

    asyncio.run(exercise())


def test_server_answers_hello_result_then_refuses_a_foreign_manifest() -> None:
    """Issue #436: a decodable older hello must not be a silent close."""

    async def exercise() -> None:
        client, server, client_peer = _stream_pair()
        hello = _hello()
        hello["schema_manifest_digest"] = "sha256:" + "a" * 64
        await write_control_frame(client, hello)
        with pytest.raises(ControlProtocolError) as refused:
            await server_handshake(server, client_peer, _status())
        _assert_reason(refused, "manifest_mismatch")
        result = await read_control_frame(client)
        # The refusal is emitted by the active 2.7 service.  The released 2.5/2.6
        # hello-result schemas remain byte-frozen and cannot describe the new project method.
        validate_schema_instance("control-hello-result", "2.7.0", result)
        assert result["schema_manifest_digest"] == load_schema_catalog().manifest_digest
        assert result["service_instance_id"] == _SERVICE_ID

    asyncio.run(exercise())


def test_client_handshake_names_an_answered_foreign_digest_as_manifest_mismatch() -> None:
    """A 2.1.0-shaped hello-result with another installation's digest is not frame_invalid."""

    async def exercise() -> None:
        import finishup.service.control_protocol as proto

        client, server, _peer = _stream_pair()

        async def answer_foreign() -> None:
            await read_control_frame(server)
            result = proto._hello_result_wire(  # pyright: ignore[reportPrivateUsage]
                _status(),
                proto._allowed_for(ControlClientKind.CLI),  # pyright: ignore[reportPrivateUsage]
            )
            result["schema_manifest_digest"] = "sha256:" + "b" * 64
            await write_control_frame(server, result)

        task = asyncio.create_task(answer_foreign())
        with pytest.raises(ControlProtocolError) as mismatch:
            await client_handshake(client, ControlClientKind.CLI, "0.1.0")
        await task
        _assert_reason(mismatch, "manifest_mismatch")

    asyncio.run(exercise())


def test_service_incompatible_maps_to_service_unavailable() -> None:
    assert (
        public_error_code_for_control_reason("service_incompatible")
        is PublicErrorCode.SERVICE_UNAVAILABLE
    )


class _SendFailureStream:
    """A stream that encodes nothing and fails exactly one way on the write."""

    def __init__(self, failure: BaseException) -> None:
        self.peer_identity = object()
        self.failure = failure
        self.sent: list[bytes] = []
        self.closed = False

    async def receive(self, max_bytes: int) -> bytes:
        del max_bytes
        return b""

    async def send_all(self, data: Buffer) -> None:
        del data
        raise self.failure

    async def aclose(self) -> None:
        self.closed = True


def test_a_failed_send_is_a_transport_fact_not_a_malformed_frame() -> None:
    """Issue #678: the frame validated and encoded, so the write failure is not frame_invalid."""

    async def exercise() -> None:
        transport = _SendFailureStream(LocalControlTransportError("connection_failed"))
        with pytest.raises(LocalControlTransportError) as failed:
            await write_control_frame(transport, _hello())
        # The bounded transport reason survives the protocol layer, which is what keeps the
        # client's safe transport classification (retryable) reachable for a failed local write.
        assert failed.value.reason == "connection_failed"

        opaque = _SendFailureStream(OSError(32, "broken pipe", "/private/var/socket"))
        with pytest.raises(ControlProtocolError) as unclassified:
            await write_control_frame(opaque, _hello())
        _assert_reason(unclassified, "transport_failed")
        assert "socket" not in str(unclassified.value)
        assert "broken pipe" not in str(unclassified.value)

    asyncio.run(exercise())


def test_write_cancellation_stays_cancellation_and_encode_failures_stay_frame_invalid() -> None:
    async def exercise() -> None:
        cancelled = _SendFailureStream(asyncio.CancelledError())
        with pytest.raises(asyncio.CancelledError):
            await write_control_frame(cancelled, _hello())

        malformed = _SendFailureStream(LocalControlTransportError("connection_failed"))
        hello = _hello()
        hello["client_kind"] = "unknown_host"
        with pytest.raises(ControlProtocolError) as rejected:
            await write_control_frame(malformed, hello)
        # Encoding happens before the write: a frame this caller built wrong never reaches the
        # stream, so the transport failure armed above is not what the caller is told about.
        _assert_reason(rejected, "frame_invalid")
        assert malformed.sent == []

    asyncio.run(exercise())


def test_transport_failed_is_a_retryable_public_service_code() -> None:
    assert (
        public_error_code_for_control_reason("transport_failed")
        is PublicErrorCode.SERVICE_UNAVAILABLE
    )
    assert public_error_code_for_control_reason("frame_invalid") is PublicErrorCode.INVALID_REQUEST


# --- ADR-051: workspace claims, the session binding, and workspace-agent frames -------------

_COMMITMENT = "hmac-sha256:" + "0123456789abcdef" + "e" * 48
_WORKTREE = "sha256:" + "d" * 64
_CLAIM_HANDLE = workspace_handle_for_claim(_COMMITMENT, _WORKTREE)


def _claim() -> WorkspaceClaim:
    return WorkspaceClaim("git_common_root", "sha256:" + "c" * 64, _WORKTREE)


def _claim_context() -> RepositoryPrivacyContext:
    return RepositoryPrivacyContext(_COMMITMENT, "client_claim", workspace_handle=_CLAIM_HANDLE)


def _agent() -> WorkspaceAgentDeclaration:
    return WorkspaceAgentDeclaration(("capture", "read_task_base"), 6_291_456)


def test_a_claim_bound_handshake_records_binding_handle_and_agent_without_a_path() -> None:
    async def exercise() -> None:
        client, server, client_peer = _stream_pair()
        seen: list[WorkspaceClaim] = []

        async def resolve_claim(claim: WorkspaceClaim) -> RepositoryPrivacyContext:
            seen.append(claim)
            return _claim_context()

        async def no_locator(_locator: WorkspaceLocator) -> RepositoryPrivacyContext:
            raise AssertionError("a claim-bound hello must never resolve a path")

        client_session, server_session = await asyncio.gather(
            client_handshake(
                client,
                ControlClientKind.MCP_BRIDGE,
                "0.1.0",
                workspace_claim=_claim(),
                workspace_agent=_agent(),
            ),
            server_handshake(
                server,
                client_peer,
                _status(),
                repository_context_resolver=no_locator,
                claim_context_resolver=resolve_claim,
            ),
        )
        assert seen == [_claim()]
        for session in (client_session, server_session):
            assert session.workspace_binding == "client_claim"
            assert session.workspace_handle == _CLAIM_HANDLE
            assert session.workspace_agent == _agent()
            # The worktree digest rides beside the claim; neither is ever rendered.
            assert session.workspace_worktree == _WORKTREE
            assert "c" * 64 not in repr(session) and "d" * 64 not in repr(session)
        assert server_session.repository_privacy_context == _claim_context()
        assert client_session.repository_privacy_context is None
        assert "c" * 64 not in repr(_claim()) and "d" * 64 not in repr(_claim())

    asyncio.run(exercise())


def test_a_claim_without_a_claim_resolver_is_bound_but_has_no_context_or_handle() -> None:
    """A daemon that wires no claim resolver yet still names the binding honestly."""

    async def exercise() -> None:
        client, server, client_peer = _stream_pair()
        client_session, server_session = await asyncio.gather(
            client_handshake(client, ControlClientKind.CLI, "0.1.0", workspace_claim=_claim()),
            server_handshake(server, client_peer, _status()),
        )
        for session in (client_session, server_session):
            assert session.workspace_binding == "client_claim"
            assert session.workspace_handle is None
            assert session.workspace_agent is None
            assert session.repository_privacy_context is None

    asyncio.run(exercise())


def test_locator_and_unbound_hellos_keep_their_shape_and_name_their_binding() -> None:
    """Local behavior: the hello is unchanged; the answer adds only the binding."""

    class _Recording(_MemoryStream):
        def __init__(self, peer_identity: object) -> None:
            super().__init__(peer_identity)
            self.frames: list[bytes] = []

        async def send_all(self, data: Buffer) -> None:
            self.frames.append(bytes(data))
            await super().send_all(data)

    async def exercise(locator: WorkspaceLocator | None, binding: str) -> None:
        client_peer = object()
        client = _Recording(object())
        server = _Recording(client_peer)
        client.other, server.other = server, client
        client_session, server_session = await asyncio.gather(
            client_handshake(client, ControlClientKind.CLI, "0.1.0", workspace_locator=locator),
            server_handshake(server, client_peer, _status()),
        )
        hello = decode_control_frame(client.frames[0])
        expected: set[str] = {
            "protocol_version",
            "client_kind",
            "client_version",
            "connection_nonce",
            "schema_manifest_digest",
            "presentation_context",
        } | ({"workspace_locator"} if locator is not None else set())
        assert set(hello) == expected
        answer = decode_control_frame(server.frames[0])
        assert answer["workspace_binding"] == binding
        assert "workspace_handle" not in answer
        assert client_session.workspace_binding == server_session.workspace_binding == binding
        assert client_session.workspace_handle is None

    asyncio.run(exercise(WorkspaceLocator("/private/raw-repository"), "local_path"))
    asyncio.run(exercise(None, "none"))


def test_a_hello_with_both_a_locator_and_a_claim_is_refused_before_any_binding() -> None:
    async def exercise() -> None:
        client, _server, _peer = _stream_pair()
        with pytest.raises(ValueError, match="workspace_binding_conflict"):
            await client_handshake(
                client,
                ControlClientKind.CLI,
                "0.1.0",
                workspace_locator=WorkspaceLocator("/private/raw-repository"),
                workspace_claim=_claim(),
            )
        with pytest.raises(ValueError, match="workspace_binding_conflict"):
            await client_handshake(client, ControlClientKind.CLI, "0.1.0", workspace_agent=_agent())
        assert client.other is not None and client.other._chunks.empty()  # pyright: ignore[reportPrivateUsage]

        for extra in (
            {
                "workspace_locator": {"schema_version": "1.0.0", "path": "/private/raw"},
                "workspace_claim": {
                    "schema_version": "1.0.0",
                    "identity_kind": "directory",
                    "digest": "sha256:" + "d" * 64,
                    "worktree": _WORKTREE,
                },
            },
            {
                "workspace_agent": {
                    "schema_version": "1.0.0",
                    "operations": ["capture"],
                    "max_reply_bytes": 1024,
                }
            },
        ):
            client, server, client_peer = _stream_pair()

            async def never(_value: object) -> RepositoryPrivacyContext:
                raise AssertionError("a conflicting hello resolves nothing")

            await write_control_frame(client, {**_hello(), **extra})
            with pytest.raises(ControlProtocolError) as refused:
                await server_handshake(
                    server,
                    client_peer,
                    _status(),
                    repository_context_resolver=never,
                    claim_context_resolver=never,
                )
            _assert_reason(refused, "workspace_binding_conflict")
            assert server.closed
            assert client._chunks.empty()  # pyright: ignore[reportPrivateUsage]

    asyncio.run(exercise())
    assert (
        public_error_code_for_control_reason("workspace_binding_conflict")
        is PublicErrorCode.INVALID_REQUEST
    )


def test_a_claim_resolver_must_answer_a_claim_identity() -> None:
    async def exercise(context: object) -> BaseException:
        client, server, client_peer = _stream_pair()

        async def resolve(_claim: WorkspaceClaim) -> RepositoryPrivacyContext:
            if isinstance(context, BaseException):
                raise context
            return cast(RepositoryPrivacyContext, context)

        hello = asyncio.create_task(
            client_handshake(client, ControlClientKind.CLI, "0.1.0", workspace_claim=_claim())
        )
        with pytest.raises(ControlProtocolError) as failed:
            await server_handshake(server, client_peer, _status(), claim_context_resolver=resolve)
        client.close_inbound()
        await asyncio.gather(hello, return_exceptions=True)
        return failed.value

    path_identity = RepositoryPrivacyContext(_COMMITMENT, "directory")
    assert cast(ControlProtocolError, asyncio.run(exercise(path_identity))).reason == (
        "protocol_mismatch"
    )
    fault = asyncio.run(exercise(RuntimeError("/private/claim-store: boom")))
    assert isinstance(fault, HandshakeServiceFault)
    assert fault.refusal is None
    assert "claim-store" not in f"{fault!r} {fault}"


def test_the_client_refuses_an_answer_that_names_another_binding() -> None:
    import finishup.service.control_protocol as proto

    async def exercise(binding: str | None, handle: str | None, claim: bool) -> str:
        client, server, _peer = _stream_pair()

        async def answer() -> None:
            await read_control_frame(server)
            result = proto._hello_result_wire(  # pyright: ignore[reportPrivateUsage]
                _status(),
                proto._allowed_for(ControlClientKind.CLI),  # pyright: ignore[reportPrivateUsage]
                workspace_binding=cast(Any, binding),
                workspace_handle=handle,
            )
            # Written raw, as a peer that ignores the contract would: this service's own encoder
            # refuses a handle outside ``client_claim``.
            payload = canonical_encode(result)
            await server.send_all(struct.pack(">I", len(payload)) + payload)

        task = asyncio.create_task(answer())
        with pytest.raises(ControlProtocolError) as refused:
            await client_handshake(
                client,
                ControlClientKind.CLI,
                "0.1.0",
                workspace_claim=_claim() if claim else None,
            )
        await task
        return refused.value.reason

    assert asyncio.run(exercise(None, None, False)) == "protocol_mismatch"
    assert asyncio.run(exercise("local_path", None, False)) == "protocol_mismatch"
    assert asyncio.run(exercise("none", None, True)) == "protocol_mismatch"
    # A handle outside a claim breaks the 2.10.0 contract itself: neither side can frame it.
    for binding in ("none", "local_path"):
        assert asyncio.run(exercise(binding, _CLAIM_HANDLE, False)) == "frame_invalid"
        with pytest.raises(ControlProtocolError) as unframed:
            encode_control_frame(
                proto._hello_result_wire(  # pyright: ignore[reportPrivateUsage]
                    _status(),
                    proto._allowed_for(ControlClientKind.CLI),  # pyright: ignore[reportPrivateUsage]
                    workspace_binding=cast(Any, binding),
                    workspace_handle=_CLAIM_HANDLE,
                )
            )
        assert unframed.value.reason == "frame_invalid"


def test_the_manifest_mismatch_answer_keeps_the_frozen_hello_result_shape() -> None:
    async def exercise() -> None:
        client, server, client_peer = _stream_pair()
        hello = _hello()
        hello["schema_manifest_digest"] = "sha256:" + "a" * 64
        await write_control_frame(client, hello)
        with pytest.raises(ControlProtocolError):
            await server_handshake(server, client_peer, _status())
        result = await read_control_frame(client)
        assert "workspace_binding" not in result
        validate_schema_instance("control-hello-result", "2.9.0", result)

    asyncio.run(exercise())


def test_session_binding_facts_are_validated_together() -> None:
    base: dict[str, Any] = {
        "protocol_version": "1.0",
        "client_kind": ControlClientKind.CLI,
        "service_instance_id": _SERVICE_ID,
        "service_generation": "1",
        "allowed_methods": tuple(sorted(ControlMethod, key=lambda item: item.value.encode())),
        "peer_identity": object(),
        "connection_nonce": "1" * 64,
    }
    claim_context = _claim_context()
    path_context = RepositoryPrivacyContext(_COMMITMENT, "git_common_root")
    ControlSession(**base, workspace_binding="local_path", repository_privacy_context=path_context)
    ControlSession(
        **base,
        workspace_binding="client_claim",
        repository_privacy_context=claim_context,
        workspace_handle=_CLAIM_HANDLE,
        workspace_agent=_agent(),
    )
    invalid_cases: tuple[dict[str, Any], ...] = (
        {"workspace_binding": "remote"},
        {"workspace_binding": "none", "repository_privacy_context": path_context},
        {"workspace_binding": "local_path", "repository_privacy_context": claim_context},
        {"workspace_binding": "client_claim", "repository_privacy_context": path_context},
        {"workspace_binding": "local_path", "workspace_handle": _CLAIM_HANDLE},
        {"workspace_binding": "client_claim", "workspace_handle": "client:XYZ"},
        {
            "workspace_binding": "client_claim",
            "repository_privacy_context": claim_context,
            "workspace_handle": "client:ffffffffffffffff",
        },
        {"workspace_binding": "local_path", "workspace_agent": _agent()},
        {"workspace_binding": "local_path", "workspace_worktree": _WORKTREE},
        {"workspace_binding": "client_claim", "workspace_worktree": "sha256:" + "D" * 64},
        {
            # The handle of another worktree of the same repository is not this session's.
            "workspace_binding": "client_claim",
            "repository_privacy_context": claim_context,
            "workspace_handle": workspace_handle_for_claim(_COMMITMENT, "sha256:" + "f" * 64),
        },
    )
    for invalid in invalid_cases:
        with pytest.raises(ValueError):
            ControlSession(**base, **invalid)
    with pytest.raises(ValueError, match="repository_identity_kind_invalid"):
        RepositoryPrivacyContext(
            _COMMITMENT,
            "client_claim",
            WorkspaceLocator("/private/raw-repository"),
            workspace_handle=_CLAIM_HANDLE,
        )
    # A claim-bound identity always names its worktree's handle, and only it does.
    for kind, handle in (
        ("client_claim", None),
        ("client_claim", "client:XYZ"),
        ("git_common_root", _CLAIM_HANDLE),
    ):
        with pytest.raises(ValueError, match="workspace_handle_invalid"):
            RepositoryPrivacyContext(_COMMITMENT, cast(Any, kind), workspace_handle=handle)


def _workspace_call(arguments: dict[str, JsonValue] | None = None) -> WorkspaceCall:
    return WorkspaceCall(
        kind="workspace_call",
        protocol_version="1.0",
        call_id=_rpc_id(41),
        service_instance_id=_SERVICE_ID,
        service_generation="1",
        operation="read_task_base",
        arguments=JsonObject(arguments or {"workspace": _CLAIM_HANDLE}),
        deadline_ms=5_000,
    )


def test_workspace_call_and_reply_frames_round_trip_through_the_stream() -> None:
    async def exercise() -> None:
        client, server, _peer = _stream_pair()
        call = _workspace_call()
        await write_workspace_call(server, call)
        received = await read_control_frame(client)
        assert is_workspace_call_frame(received) and not is_workspace_reply_frame(received)
        assert parse_workspace_call(received) == call
        with pytest.raises(ControlProtocolError) as not_a_result:
            parse_control_result(received)
        _assert_reason(not_a_result, "frame_invalid")

        reply = WorkspaceReply(
            kind="workspace_reply",
            protocol_version="1.0",
            call_id=call.call_id,
            outcome="ok",
            result={"commit": "a" * 40, "object_format": "sha1"},
            reason=None,
        )
        await write_workspace_reply(client, reply)
        answered = await read_control_frame(server)
        assert is_workspace_reply_frame(answered)
        assert parse_workspace_reply(answered) == reply
        with pytest.raises(ControlProtocolError) as not_a_call:
            parse_control_request(answered)
        _assert_reason(not_a_call, "frame_invalid")

        unavailable = WorkspaceReply(
            kind="workspace_reply",
            protocol_version="1.0",
            call_id=call.call_id,
            outcome="unavailable",
            result=None,
            reason="not_git",
        )
        wire = workspace_reply_frame(unavailable)
        assert wire["result"] is None and wire["reason"] == "not_git"
        assert parse_workspace_reply(decode_control_frame(encode_control_frame(wire))) == (
            unavailable
        )
        assert set(workspace_call_frame(call)) == {
            "arguments",
            "call_id",
            "deadline_ms",
            "kind",
            "operation",
            "protocol_version",
            "service_generation",
            "service_instance_id",
        }

    asyncio.run(exercise())


def test_workspace_replies_are_closed_by_outcome() -> None:
    def reply(outcome: str, result: JsonValue, reason: str | None) -> WorkspaceReply:
        return WorkspaceReply(
            kind="workspace_reply",
            protocol_version="1.0",
            call_id=_rpc_id(42),
            outcome=cast(Any, outcome),
            result=result,
            reason=reason,
        )

    reply("ok", None, None)
    reply("refused", None, "root_not_admitted")
    reply("failed", None, "internal_error")
    for outcome, result, reason in (
        ("ok", None, "not_git"),
        ("unavailable", {"partial": True}, "not_git"),
        ("unavailable", None, "root_not_admitted"),
        ("refused", None, "not_git"),
        ("failed", None, "not_git"),
        ("unavailable", None, "/private/path"),
        ("lost", None, None),
    ):
        with pytest.raises(ValueError):
            reply(outcome, result, reason)
    for frame in (
        {
            "kind": "workspace_reply",
            "protocol_version": "1.0",
            "call_id": _rpc_id(42),
            "outcome": "refused",
            "result": None,
            "reason": "not_git",
        },
        {
            "kind": "workspace_reply",
            "protocol_version": "1.0",
            "call_id": _rpc_id(42),
            "outcome": "ok",
            "result": None,
        },
    ):
        with pytest.raises(ControlProtocolError) as invalid:
            encode_control_frame(frame)
        _assert_reason(invalid, "frame_invalid")
    with pytest.raises(ValueError, match="workspace_operation_invalid"):
        replace_call = dict(
            kind="workspace_call",
            protocol_version="1.0",
            call_id=_rpc_id(43),
            service_instance_id=_SERVICE_ID,
            service_generation="1",
            operation="rm_rf",
            arguments=JsonObject({}),
            deadline_ms=1,
        )
        WorkspaceCall(**cast(Any, replace_call))


def test_workspace_frames_may_use_the_whole_frame_and_no_more() -> None:
    large = "A" * (2 * MAX_ORDINARY_CONTROL_FRAME_BYTES)
    reply = {
        "kind": "workspace_reply",
        "protocol_version": "1.0",
        "call_id": _rpc_id(44),
        "outcome": "ok",
        "result": large,
        "reason": None,
    }
    encoded = encode_control_frame(reply)
    assert len(encoded) > MAX_ORDINARY_CONTROL_FRAME_BYTES
    assert decode_control_frame(encoded)["result"] == large
    call = workspace_call_frame(_workspace_call({"blob": large}))
    assert decode_control_frame(encode_control_frame(call))["arguments"] == {"blob": large}
    with pytest.raises(ControlProtocolError) as too_large:
        encode_control_frame({**reply, "result": "A" * MAX_CONTROL_FRAME_BYTES})
    _assert_reason(too_large, "frame_too_large")
    # Every other frame keeps the ordinary 1 MiB bound.
    import finishup.service.control_protocol as proto

    oversized = b"x" * (MAX_ORDINARY_CONTROL_FRAME_BYTES + 1)
    for kind in ("call", "cancel"):
        with pytest.raises(ControlProtocolError) as ordinary:
            proto._validate_frame_size(oversized, JsonObject({"kind": kind}))  # pyright: ignore[reportPrivateUsage]
        _assert_reason(ordinary, "frame_too_large")


def test_the_workspace_agent_declaration_is_closed_and_sorted() -> None:
    _agent()
    for operations, size in (
        ((), 1024),
        (("read_task_base", "capture"), 1024),
        (("capture", "capture"), 1024),
        (("capture", "rm_rf"), 1024),
        (("capture",), 0),
        (("capture",), MAX_CONTROL_FRAME_BYTES + 1),
    ):
        with pytest.raises(ValueError):
            WorkspaceAgentDeclaration(operations, size)
    for digest in ("sha256:" + "C" * 64, "hmac-sha256:" + "c" * 64, ""):
        with pytest.raises(ValueError, match="workspace_claim_digest_invalid"):
            WorkspaceClaim("directory", digest, _WORKTREE)
        with pytest.raises(ValueError, match="workspace_claim_worktree_invalid"):
            WorkspaceClaim("directory", "sha256:" + "c" * 64, digest)
    with pytest.raises(ValueError, match="workspace_claim_identity_kind_invalid"):
        WorkspaceClaim(cast(Any, "client_claim"), "sha256:" + "c" * 64, _WORKTREE)
