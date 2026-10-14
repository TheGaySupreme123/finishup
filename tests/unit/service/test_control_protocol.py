"""Unit tests for the frozen ordinary local-service control protocol."""

from __future__ import annotations

import asyncio
import base64
import struct
from collections.abc import Buffer
from typing import cast

import pytest

from yoetz.adapters.control.unix_socket import LocalControlTransportError
from yoetz.domain.values import JsonObject
from yoetz.ports.control import (
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
    WorkspaceLocator,
)
from yoetz.protocol.canonical import JsonValue, canonical_encode
from yoetz.protocol.errors import PublicErrorCode
from yoetz.protocol.schemas import (
    SchemaInstanceInvalid,
    load_schema_catalog,
    validate_schema_instance,
)
from yoetz.service.control_protocol import (
    CONTROL_PROTOCOL_VERSION,
    MAX_ACTIVE_REQUESTS_PER_SESSION,
    MAX_CONTROL_FRAME_BYTES,
    MAX_ORDINARY_CONTROL_FRAME_BYTES,
    BoundedControlQueue,
    ControlProtocolError,
    ControlSession,
    client_handshake,
    decode_control_frame,
    encode_control_frame,
    parse_control_request,
    parse_control_result,
    public_error_code_for_control_reason,
    read_control_frame,
    schema_for_method,
    server_handshake,
    write_control_frame,
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
    from yoetz.protocol.models import StartRequest

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
    from yoetz.protocol.models import CheckRequest

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
            self._buffer.extend(await self._chunks.get())
        chunk = bytes(self._buffer[:max_bytes])
        del self._buffer[:max_bytes]
        return chunk

    async def send_all(self, data: Buffer) -> None:
        assert self.other is not None
        await self.other._chunks.put(bytes(data))

    async def aclose(self) -> None:
        self.closed = True


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
        import yoetz.service.control_protocol as proto

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
