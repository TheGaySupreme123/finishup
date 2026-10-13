"""Unit tests for the shared bounded ordinary service client."""

from __future__ import annotations

import asyncio
import gc
import os
import stat
import subprocess
import time
from collections.abc import Buffer, Generator
from contextlib import contextmanager
from inspect import signature
from pathlib import Path
from types import SimpleNamespace
from typing import BinaryIO, cast

import pytest

from yoetz.adapters.control.unix_socket import (
    AuthenticatedUnixStream,
    LocalControlTransportError,
)
from yoetz.domain.values import JsonObject
from yoetz.ports.control import (
    ControlClientKind,
    ControlError,
    ControlMethod,
    ControlResult,
    ServiceState,
    ServiceStatus,
    ServiceStopResult,
    WorkspaceLocator,
)
from yoetz.ports.privacy import LocalDisclosureReceiptView, PrivacyReceiptPage
from yoetz.protocol.errors import PublicErrorCode
from yoetz.protocol.ids import IdKind, new_id
from yoetz.protocol.models import CheckRequest, ReceiptRequest
from yoetz.service.client import (
    GetPrivacyReceiptRequest,
    ListPrivacyReceiptsRequest,
    PreparedProjectRequest,
    PrivacyReceiptFound,
    PrivacyReceiptNotFound,
    ServiceClient,
    connect_service_on_demand,
    prepare_project_request,
)
from yoetz.service.control_protocol import (
    ControlSession,
    decode_control_frame,
    encode_control_frame,
    parse_control_result,
    public_error_code_for_control_reason,
)

_SERVICE_ID = "svc_00000000-0000-4000-8000-000000000001"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class _FakeStream:
    def __init__(self) -> None:
        self.peer_identity = object()
        self.sent: list[bytes] = []
        self._incoming = bytearray()
        self._ready = asyncio.Condition()
        self.closed = False
        # Armed by the transport regressions: the exact failure this stream raises instead of
        # accepting the next write.
        self.send_failure: BaseException | None = None

    async def receive(self, max_bytes: int) -> bytes:
        async with self._ready:
            await self._ready.wait_for(lambda: bool(self._incoming) or self.closed)
            if not self._incoming:
                return b""
            size = min(max_bytes, len(self._incoming))
            result = bytes(self._incoming[:size])
            del self._incoming[:size]
            return result

    async def send_all(self, data: Buffer) -> None:
        if self.send_failure is not None:
            raise self.send_failure
        self.sent.append(bytes(data))

    async def aclose(self) -> None:
        async with self._ready:
            self.closed = True
            self._ready.notify_all()

    async def feed(self, data: bytes) -> None:
        async with self._ready:
            self._incoming.extend(data)
            self._ready.notify_all()


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


def _session(stream: _FakeStream, kind: ControlClientKind) -> ControlSession:
    methods = tuple(
        sorted(
            (
                {
                    ControlMethod.START,
                    ControlMethod.PUBLISH_WORK,
                    ControlMethod.CHECK,
                    ControlMethod.RESPOND,
                    ControlMethod.STATUS,
                    ControlMethod.RECEIPT,
                }
                if kind is ControlClientKind.MCP_BRIDGE
                else set(ControlMethod)
            ),
            key=lambda method: method.value.encode("ascii"),
        )
    )
    return ControlSession(
        protocol_version="1.0",
        client_kind=kind,
        service_instance_id=_SERVICE_ID,
        service_generation="1",
        allowed_methods=methods,
        peer_identity=stream.peer_identity,
        connection_nonce="0" * 64,
    )


def _client(stream: _FakeStream, kind: ControlClientKind = ControlClientKind.CLI) -> ServiceClient:
    factory = getattr(__import__("yoetz.service.client", fromlist=["x"]), "_connected_client")
    return cast(
        ServiceClient,
        factory(
            cast(AuthenticatedUnixStream, stream),
            _session(stream, kind),
            kind,
        ),
    )


@contextmanager
def _captured_loop_exceptions() -> Generator[list[dict[str, object]]]:
    """Collect every context the running loop would otherwise report as an unhandled failure."""

    loop = asyncio.get_running_loop()
    contexts: list[dict[str, object]] = []
    previous = loop.get_exception_handler()
    loop.set_exception_handler(lambda _loop, context: contexts.append(context))
    try:
        yield contexts
    finally:
        loop.set_exception_handler(previous)


async def _settle_loop_callbacks() -> None:
    """Run every callback already queued on the loop, waiting on that fact and not on a clock."""

    flushed = asyncio.Event()
    asyncio.get_running_loop().call_soon(flushed.set)
    await flushed.wait()


async def _wait_for_sent(stream: _FakeStream, count: int) -> None:
    for _ in range(100):
        if len(stream.sent) >= count:
            return
        await asyncio.sleep(0)
    raise AssertionError("client did not write expected frame")


@pytest.mark.anyio
async def test_project_preserves_supplied_request_id_on_the_control_wire() -> None:
    stream = _FakeStream()
    client = _client(stream)
    supplied = "req_00000000-0000-4000-8000-000000000101"
    task = asyncio.create_task(
        client.project(
            JsonObject(
                {
                    "schema_version": "1.0.0",
                    "operation": "create",
                    "owner_task_id": "tsk_00000000-0000-4000-8000-000000000102",
                    "title": "project",
                    "request_id": supplied,
                }
            )
        )
    )
    await _wait_for_sent(stream, 1)
    request = decode_control_frame(stream.sent[0])
    body = cast(dict[str, object], request["body"])
    assert body["request_id"] == supplied
    assert client.last_project_request == PreparedProjectRequest(JsonObject(body), supplied)
    await stream.feed(
        encode_control_frame(
            ControlResult(
                protocol_version="1.0",
                rpc_id=cast(str, request["rpc_id"]),
                service_instance_id=_SERVICE_ID,
                service_generation="1",
                method=ControlMethod.PROJECT,
                outcome="error",
                body=ControlError("project_not_found"),
            )
        )
    )
    with pytest.raises(ControlError, match="project_not_found"):
        await task
    await client.close()


@pytest.mark.anyio
async def test_project_generated_request_id_is_exposed_and_reusable_for_recovery() -> None:
    stream = _FakeStream()
    client = _client(stream)
    original = JsonObject(
        {
            "schema_version": "1.0.0",
            "operation": "create",
            "owner_task_id": "tsk_00000000-0000-4000-8000-000000000103",
            "title": "project",
        }
    )
    first_task = asyncio.create_task(client.project(original))
    await _wait_for_sent(stream, 1)
    first = decode_control_frame(stream.sent[0])
    first_body = cast(dict[str, object], first["body"])
    prepared = client.last_project_request
    assert prepared is not None
    assert prepared.body is not original
    assert prepared.body["request_id"] == prepared.request_id
    assert first_body["request_id"] == prepared.request_id
    assert "request_id" not in original
    await stream.feed(
        encode_control_frame(
            ControlResult(
                protocol_version="1.0",
                rpc_id=cast(str, first["rpc_id"]),
                service_instance_id=_SERVICE_ID,
                service_generation="1",
                method=ControlMethod.PROJECT,
                outcome="error",
                body=ControlError("project_not_found"),
            )
        )
    )
    with pytest.raises(ControlError, match="project_not_found"):
        await first_task

    retry_task = asyncio.create_task(client.project(prepared.body))
    await _wait_for_sent(stream, 2)
    retry = decode_control_frame(stream.sent[1])
    assert retry["body"] == first["body"]
    await stream.feed(
        encode_control_frame(
            ControlResult(
                protocol_version="1.0",
                rpc_id=cast(str, retry["rpc_id"]),
                service_instance_id=_SERVICE_ID,
                service_generation="1",
                method=ControlMethod.PROJECT,
                outcome="error",
                body=ControlError("project_not_found"),
            )
        )
    )
    with pytest.raises(ControlError, match="project_not_found"):
        await retry_task
    await client.close()


def test_prepare_project_request_uses_matching_explicit_identity() -> None:
    supplied = "req_00000000-0000-4000-8000-000000000104"
    prepared = prepare_project_request(
        JsonObject({"schema_version": "1.0.0", "operation": "opt_in"}),
        request_id=supplied,
    )
    assert prepared.request_id == supplied
    assert prepared.body["request_id"] == supplied
    assert prepared.request == prepared.body


@pytest.mark.anyio
async def test_request_result_correlation_and_lifecycle_conversion() -> None:
    stream = _FakeStream()
    client = _client(stream)
    task = asyncio.create_task(client.service_status())
    await _wait_for_sent(stream, 1)
    request = decode_control_frame(stream.sent[0])
    rpc_id = cast(str, request["rpc_id"])
    assert request["method"] == "service_status"
    await stream.feed(
        encode_control_frame(
            ControlResult(
                protocol_version="1.0",
                rpc_id=rpc_id,
                service_instance_id=_SERVICE_ID,
                service_generation="1",
                method=ControlMethod.SERVICE_STATUS,
                outcome="ok",
                body=_status(),
            )
        )
    )
    assert await task == _status()
    await client.close()


@pytest.mark.anyio
async def test_valid_stop_result_survives_immediate_eof_and_fails_unrelated_pending_call() -> None:
    stream = _FakeStream()
    client = _client(stream)
    status_task = asyncio.create_task(client.service_status())
    stop_task = asyncio.create_task(client.stop())
    await _wait_for_sent(stream, 2)
    requests = {
        cast(str, frame["method"]): frame
        for frame in (decode_control_frame(encoded) for encoded in stream.sent)
    }
    stop_request = requests["service_stop"]
    expected = ServiceStopResult()
    await stream.feed(
        encode_control_frame(
            ControlResult(
                protocol_version="1.0",
                rpc_id=cast(str, stop_request["rpc_id"]),
                service_instance_id=_SERVICE_ID,
                service_generation="1",
                method=ControlMethod.SERVICE_STOP,
                outcome="ok",
                body=expected,
            )
        )
    )
    await stream.aclose()

    assert await stop_task == expected
    with pytest.raises(ControlError, match="frame_invalid"):
        await status_task


@pytest.mark.anyio
async def test_result_correlation_mismatch_remains_a_protocol_failure() -> None:
    stream = _FakeStream()
    client = _client(stream)
    task = asyncio.create_task(client.service_status())
    await _wait_for_sent(stream, 1)
    request = decode_control_frame(stream.sent[0])
    await stream.feed(
        encode_control_frame(
            ControlResult(
                protocol_version="1.0",
                rpc_id=cast(str, request["rpc_id"]),
                service_instance_id=_SERVICE_ID,
                service_generation="1",
                method=ControlMethod.SERVICE_LOCK,
                outcome="ok",
                body=_status(),
            )
        )
    )

    with pytest.raises(ControlError, match="frame_invalid"):
        await task
    await client.close()


@pytest.mark.anyio
async def test_mcp_rejects_every_support_method_before_transport() -> None:
    stream = _FakeStream()
    client = _client(stream, ControlClientKind.MCP_BRIDGE)
    with pytest.raises(ControlError, match="method_forbidden"):
        await client.privacy_get_effective(JsonObject({}))
    assert stream.sent == []
    await client.close()


@pytest.mark.anyio
async def test_on_demand_connect_spawns_only_after_absent_service(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import yoetz.service.client as client_module

    expected = object()
    calls = 0
    spawned = 0

    async def scripted_connect(
        kind: ControlClientKind,
        **_kwargs: object,
    ) -> object:
        nonlocal calls
        assert kind is ControlClientKind.MCP_BRIDGE
        calls += 1
        if calls == 1:
            raise ControlError("service_unavailable", retryable=True)
        return expected

    def spawn() -> None:
        nonlocal spawned
        spawned += 1

    monkeypatch.setattr(client_module, "_connect_service_attempt", scripted_connect)
    monkeypatch.setattr(client_module, "_spawn_service_process", spawn)
    monkeypatch.setattr(client_module, "_SERVICE_START_POLL_SECONDS", 0.01)
    connected = await connect_service_on_demand(ControlClientKind.MCP_BRIDGE, timeout_seconds=0.2)
    assert connected is expected
    assert spawned == 1


class _ExitedProcess:
    """A spawned service that has already exited (``poll`` returns its code)."""

    def __init__(self, code: int | None) -> None:
        self.code = code

    def poll(self) -> int | None:
        return self.code


@pytest.mark.anyio
async def test_on_demand_names_a_spawned_service_startup_failure_at_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The conda-image bridge waited its whole budget, then said only "not running" (#1040)."""

    import yoetz.observability.diagnostics as diagnostics
    import yoetz.service.client as client_module
    from yoetz.service.startup_failure import record_startup_failure

    monkeypatch.setattr(diagnostics, "log_dir", lambda: tmp_path)
    startup_id = new_id(IdKind.CORRELATION)
    attempts = 0

    async def unavailable(_kind: ControlClientKind, **_kwargs: object) -> object:
        nonlocal attempts
        attempts += 1
        raise ControlError("service_unavailable", retryable=True)

    def spawn() -> object:
        record_startup_failure(
            NotImplementedError("chmod: follow_symlinks unavailable on this platform"),
            stage="activation",
            correlation_id=startup_id,
        )
        return client_module._SpawnedService(  # pyright: ignore[reportPrivateUsage]
            cast(subprocess.Popen[bytes], _ExitedProcess(70)), startup_id
        )

    monkeypatch.setattr(client_module, "_connect_service_attempt", unavailable)
    monkeypatch.setattr(client_module, "_spawn_service_process", spawn)
    monkeypatch.setattr(client_module, "_SERVICE_START_POLL_SECONDS", 0.01)
    started = time.monotonic()
    with pytest.raises(ControlError) as raised:
        await connect_service_on_demand(ControlClientKind.MCP_BRIDGE, timeout_seconds=30.0)

    assert time.monotonic() - started < 5.0
    assert attempts == 2
    assert raised.value.reason == "service_unavailable"
    assert raised.value.retryable is False
    assert raised.value.phase == "activation"
    assert raised.value.correlation_id == startup_id


@pytest.mark.anyio
async def test_on_demand_keeps_waiting_when_the_spawned_service_lost_the_singleton(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A spawn that exits without a startup record lost a race; the holder still answers."""

    import yoetz.observability.diagnostics as diagnostics
    import yoetz.service.client as client_module

    monkeypatch.setattr(diagnostics, "log_dir", lambda: tmp_path)
    expected = object()
    attempts = 0

    async def scripted(_kind: ControlClientKind, **_kwargs: object) -> object:
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise ControlError("service_unavailable", retryable=True)
        return expected

    def spawn() -> object:
        return client_module._SpawnedService(  # pyright: ignore[reportPrivateUsage]
            cast(subprocess.Popen[bytes], _ExitedProcess(20)), new_id(IdKind.CORRELATION)
        )

    monkeypatch.setattr(client_module, "_connect_service_attempt", scripted)
    monkeypatch.setattr(client_module, "_spawn_service_process", spawn)
    monkeypatch.setattr(client_module, "_SERVICE_START_POLL_SECONDS", 0.01)

    assert await connect_service_on_demand(ControlClientKind.MCP_BRIDGE, timeout_seconds=5.0) is (
        expected
    )
    assert attempts == 3


def test_on_demand_spawn_passes_the_id_it_will_look_a_failure_up_under(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import yoetz.service.client as client_module

    observed: list[object] = []

    def popen(command: object, **_kwargs: object) -> object:
        observed.append(command)
        return _ExitedProcess(None)

    monkeypatch.setattr(client_module, "log_dir", lambda: tmp_path / "logs")
    monkeypatch.setattr(client_module.subprocess, "Popen", popen)

    spawned = client_module._spawn_service_process()  # pyright: ignore[reportPrivateUsage]

    (command,) = observed
    assert isinstance(command, tuple)
    assert command[1:] == (
        "-m",
        "yoetz",
        "service",
        "run",
        "--startup-correlation-id",
        spawned.startup_correlation_id,
    )
    assert spawned.startup_correlation_id.startswith("err_")


@pytest.mark.anyio
async def test_on_demand_reuses_workspace_locator_for_every_reconnect_attempt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import yoetz.service.client as client_module

    expected = object()
    locator = WorkspaceLocator("/private/repository")
    observed: list[WorkspaceLocator | None] = []

    async def scripted_connect(
        kind: ControlClientKind,
        *,
        workspace_locator: WorkspaceLocator | None = None,
        **_kwargs: object,
    ) -> object:
        assert kind is ControlClientKind.MCP_BRIDGE
        observed.append(workspace_locator)
        if len(observed) == 1:
            raise ControlError("service_unavailable", retryable=True)
        return expected

    monkeypatch.setattr(client_module, "_connect_service_attempt", scripted_connect)
    monkeypatch.setattr(client_module, "_spawn_service_process", lambda: None)
    connected = await connect_service_on_demand(
        ControlClientKind.MCP_BRIDGE,
        workspace_locator=locator,
        timeout_seconds=0.2,
    )

    assert connected is expected
    assert observed == [locator, locator]


@pytest.mark.anyio
async def test_on_demand_does_not_spawn_after_accepted_service_stalls_handshake(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import yoetz.service.client as client_module

    stream = _FakeStream()
    spawned = 0

    async def connect() -> AuthenticatedUnixStream:
        return cast(AuthenticatedUnixStream, stream)

    async def stalled_handshake(*_args: object, **_kwargs: object) -> object:
        await asyncio.Event().wait()

    def spawn() -> None:
        nonlocal spawned
        spawned += 1

    monkeypatch.setattr(client_module, "connect_control", connect)
    monkeypatch.setattr(client_module, "client_handshake", stalled_handshake)
    monkeypatch.setattr(client_module, "_CONNECT_HANDSHAKE_TIMEOUT_SECONDS", 0.01)
    monkeypatch.setattr(client_module, "_spawn_service_process", spawn)

    with pytest.raises(ControlError, match="service_unavailable"):
        await connect_service_on_demand(ControlClientKind.MCP_BRIDGE, timeout_seconds=0.2)

    assert stream.closed is True
    assert spawned == 0


@pytest.mark.anyio
async def test_on_demand_tolerates_the_daemon_it_just_spawned_until_the_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A daemon this call started is still starting, not wedged, while it stays silent."""

    import yoetz.service.client as client_module

    expected = object()
    attempts = 0
    spawned = 0

    async def scripted_connect(
        kind: ControlClientKind,
        **_kwargs: object,
    ) -> object:
        nonlocal attempts
        assert kind is ControlClientKind.MCP_BRIDGE
        attempts += 1
        if attempts == 1:
            raise ControlError("service_unavailable", retryable=True)
        if attempts <= 3:
            raise client_module._AcceptedServiceUnresponsive()  # pyright: ignore[reportPrivateUsage]
        return expected

    def spawn() -> None:
        nonlocal spawned
        spawned += 1

    monkeypatch.setattr(client_module, "_connect_service_attempt", scripted_connect)
    monkeypatch.setattr(client_module, "_spawn_service_process", spawn)

    connected = await connect_service_on_demand(ControlClientKind.MCP_BRIDGE, timeout_seconds=1.0)

    assert connected is expected
    assert spawned == 1
    assert attempts == 4


@pytest.mark.anyio
async def test_on_demand_accepted_unresponsive_after_spawn_still_ends_at_the_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Tolerating the startup window must not restore an unbounded wait."""

    import yoetz.service.client as client_module

    attempts = 0
    spawned = 0

    async def scripted_connect(
        kind: ControlClientKind,
        **_kwargs: object,
    ) -> object:
        nonlocal attempts
        assert kind is ControlClientKind.MCP_BRIDGE
        attempts += 1
        if attempts == 1:
            raise ControlError("service_unavailable", retryable=True)
        raise client_module._AcceptedServiceUnresponsive()  # pyright: ignore[reportPrivateUsage]

    def spawn() -> None:
        nonlocal spawned
        spawned += 1

    monkeypatch.setattr(client_module, "_connect_service_attempt", scripted_connect)
    monkeypatch.setattr(client_module, "_spawn_service_process", spawn)
    started = asyncio.get_running_loop().time()

    with pytest.raises(ControlError, match="service_unavailable"):
        await connect_service_on_demand(ControlClientKind.MCP_BRIDGE, timeout_seconds=0.3)

    assert asyncio.get_running_loop().time() - started < 1.0
    assert spawned == 1
    assert attempts > 2


@pytest.mark.anyio
async def test_on_demand_initial_connect_is_inside_the_total_start_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import yoetz.service.client as client_module

    spawned = 0

    async def stalled_connect() -> AuthenticatedUnixStream:
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    def spawn() -> None:
        nonlocal spawned
        spawned += 1

    monkeypatch.setattr(client_module, "connect_control", stalled_connect)
    monkeypatch.setattr(client_module, "_spawn_service_process", spawn)
    started = asyncio.get_running_loop().time()

    with pytest.raises(ControlError, match="service_unavailable"):
        await connect_service_on_demand(ControlClientKind.MCP_BRIDGE, timeout_seconds=0.1)

    assert asyncio.get_running_loop().time() - started < 0.5
    assert spawned == 0


@pytest.mark.anyio
async def test_connect_timeout_does_not_wait_for_never_closing_accepted_stream(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import yoetz.service.client as client_module

    class _NeverClosingStream(_FakeStream):
        async def aclose(self) -> None:
            await asyncio.Event().wait()

    stream = _NeverClosingStream()
    spawned = 0

    async def connect() -> AuthenticatedUnixStream:
        return cast(AuthenticatedUnixStream, stream)

    async def stalled_handshake(*_args: object, **_kwargs: object) -> object:
        await asyncio.Event().wait()

    def spawn() -> None:
        nonlocal spawned
        spawned += 1

    monkeypatch.setattr(client_module, "connect_control", connect)
    monkeypatch.setattr(client_module, "client_handshake", stalled_handshake)
    monkeypatch.setattr(client_module, "_CONNECT_HANDSHAKE_TIMEOUT_SECONDS", 0.01)
    monkeypatch.setattr(client_module, "_STREAM_CLOSE_TIMEOUT_SECONDS", 0.01)
    monkeypatch.setattr(client_module, "_spawn_service_process", spawn)
    started = asyncio.get_running_loop().time()

    with pytest.raises(ControlError, match="service_unavailable"):
        await connect_service_on_demand(ControlClientKind.MCP_BRIDGE, timeout_seconds=0.2)

    assert asyncio.get_running_loop().time() - started < 0.1
    assert spawned == 0


def test_on_demand_service_environment_forwards_the_pinned_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A pinned runtime spawns its service with the resolved root made explicit (issue #604)."""

    import yoetz.service.client as client_module
    from yoetz.config.paths import ISOLATED_ROOT_ENV

    monkeypatch.delenv(ISOLATED_ROOT_ENV, raising=False)
    monkeypatch.setattr(client_module, "isolated_root", lambda: tmp_path / "pinned")
    environment = client_module._service_environment()  # pyright: ignore[reportPrivateUsage]
    assert environment[ISOLATED_ROOT_ENV] == str(tmp_path / "pinned")

    monkeypatch.setattr(client_module, "isolated_root", lambda: None)
    forwarded = client_module._service_environment()  # pyright: ignore[reportPrivateUsage]
    assert ISOLATED_ROOT_ENV not in forwarded


def test_on_demand_service_environment_strips_secret_shaped_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import yoetz.service.client as client_module

    monkeypatch.setenv("FIREWORKS_API_KEY", "must-not-cross")
    monkeypatch.setenv("UNRELATED_TOKEN", "must-not-cross")
    monkeypatch.setenv("YOETZ_UNRELATED_APP_SETTING", "must-not-cross")
    monkeypatch.setenv("YOETZ_LOG_LEVEL", "warning")
    monkeypatch.setenv("PATH", "/safe/bin")
    environment = client_module._service_environment()  # pyright: ignore[reportPrivateUsage]
    assert environment["PATH"] == "/safe/bin"
    assert environment["YOETZ_LOG_LEVEL"] == "warning"
    assert "FIREWORKS_API_KEY" not in environment
    assert "UNRELATED_TOKEN" not in environment
    assert "YOETZ_UNRELATED_APP_SETTING" not in environment
    assert "must-not-cross" not in environment.values()


def test_on_demand_spawn_routes_stderr_to_owner_only_log(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import yoetz.service.client as client_module

    log_root = tmp_path / "logs"
    observed: dict[str, object] = {}

    def popen(command: object, **kwargs: object) -> object:
        stderr = cast(BinaryIO, kwargs["stderr"])
        path = log_root / "service.stderr.jsonl"
        observed["command"] = command
        observed["path"] = path
        observed["mode"] = stat.S_IMODE(path.stat().st_mode)
        observed["fd_mode"] = stat.S_IMODE(os.fstat(stderr.fileno()).st_mode)
        return object()

    monkeypatch.setattr(client_module, "log_dir", lambda: log_root)
    monkeypatch.setattr(client_module.subprocess, "Popen", popen)

    client_module._spawn_service_process()  # pyright: ignore[reportPrivateUsage]

    assert observed["path"] == log_root / "service.stderr.jsonl"
    assert observed["mode"] == 0o600
    assert observed["fd_mode"] == 0o600
    assert stat.S_IMODE(log_root.stat().st_mode) == 0o700


@pytest.mark.anyio
async def test_task_cancellation_sends_one_way_distinct_cancel_frame() -> None:
    stream = _FakeStream()
    client = _client(stream)
    task = asyncio.create_task(client.service_status())
    await _wait_for_sent(stream, 1)
    call = decode_control_frame(stream.sent[0])
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await _wait_for_sent(stream, 2)
    cancel = decode_control_frame(stream.sent[1])
    assert cancel["kind"] == "cancel"
    assert cancel["target_rpc_id"] == call["rpc_id"]
    assert cancel["rpc_id"] != call["rpc_id"]
    await client.close()


@pytest.mark.anyio
async def test_receipt_list_and_get_preserve_snapshot_and_closed_outcome() -> None:
    stream = _FakeStream()
    client = _client(stream)

    list_task = asyncio.create_task(client.privacy_receipts_list(ListPrivacyReceiptsRequest()))
    await _wait_for_sent(stream, 1)
    list_request = decode_control_frame(stream.sent[0])
    assert list_request["method"] == "privacy_receipts_list"
    await stream.feed(
        encode_control_frame(
            ControlResult(
                protocol_version="1.0",
                rpc_id=cast(str, list_request["rpc_id"]),
                service_instance_id=_SERVICE_ID,
                service_generation="1",
                method=ControlMethod.PRIVACY_RECEIPTS_LIST,
                outcome="ok",
                body=JsonObject(
                    {
                        "schema_version": "1.0.0",
                        "snapshot_generation": "7",
                        "receipts": (),
                    }
                ),
            )
        )
    )
    assert await list_task == PrivacyReceiptPage(
        snapshot_generation=7, receipts=(), next_cursor=None
    )

    get_task = asyncio.create_task(
        client.privacy_receipts_get(
            GetPrivacyReceiptRequest("egr_00000000-0000-4000-8000-000000000009")
        )
    )
    await _wait_for_sent(stream, 2)
    get_request = decode_control_frame(stream.sent[1])
    await stream.feed(
        encode_control_frame(
            ControlResult(
                protocol_version="1.0",
                rpc_id=cast(str, get_request["rpc_id"]),
                service_instance_id=_SERVICE_ID,
                service_generation="1",
                method=ControlMethod.PRIVACY_RECEIPTS_GET,
                outcome="ok",
                body=JsonObject({"schema_version": "1.0.0", "outcome": "not_found"}),
            )
        )
    )
    assert await get_task == PrivacyReceiptNotFound()
    await client.close()


@pytest.mark.anyio
async def test_receipt_get_parses_schema_native_found_view() -> None:
    stream = _FakeStream()
    client = _client(stream)
    task = asyncio.create_task(
        client.privacy_receipts_get(
            GetPrivacyReceiptRequest("egr_00000000-0000-4000-8000-000000000009")
        )
    )
    await _wait_for_sent(stream, 1)
    request = decode_control_frame(stream.sent[0])
    receipt = {
        "schema_version": "1.0.0",
        "receipt_id": "egr_00000000-0000-4000-8000-000000000009",
        "request_id": "req_00000000-0000-4000-8000-000000000002",
        "privacy_proposal_id": "ppr_00000000-0000-4000-8000-000000000003",
        "sink": "local_human_view",
        "outcome": "blocked_by_policy",
        "finished_at": "2026-07-19T00:00:00.000Z",
        "scope": {
            "kind": "machine",
            "installation_id": "ins_00000000-0000-4000-8000-000000000004",
        },
        "purpose": "structural-review",
        "policy": {
            "policy_id": "pvy_00000000-0000-4000-8000-000000000005",
            "version": "1",
            "policy_digest": "sha256:" + "1" * 64,
            "authorization_scope_digest": "sha256:" + "2" * 64,
        },
        "consent_source": "none",
        "approved_categories": (),
        "blocked_categories": ("bounded_structural_metadata",),
        "counts": {
            "candidate_items": "1",
            "included_items": "0",
            "removed_items": "1",
            "approved_items": "0",
            "blocked_items": "1",
            "candidate_bytes": "1",
            "final_bytes": "0",
        },
        "transformations": {
            "minimized_items": "0",
            "redacted_spans": "0",
            "blocked_items": "1",
        },
        "secret_scan": {
            "registry_version": "1.0.0",
            "scanner_profile_digest": "sha256:" + "3" * 64,
            "match_count": "0",
            "passed": True,
        },
        "safe_failure_reason": "policy_denied",
        "audit_store_version": 1,
    }
    await stream.feed(
        encode_control_frame(
            ControlResult(
                protocol_version="1.0",
                rpc_id=cast(str, request["rpc_id"]),
                service_instance_id=_SERVICE_ID,
                service_generation="1",
                method=ControlMethod.PRIVACY_RECEIPTS_GET,
                outcome="ok",
                body=JsonObject(
                    {
                        "schema_version": "1.0.0",
                        "outcome": "found",
                        "receipt": {"kind": "local_disclosure", "receipt": receipt},
                    }
                ),
            )
        )
    )
    result = await task
    assert isinstance(result, PrivacyReceiptFound)
    assert isinstance(result.receipt, LocalDisclosureReceiptView)
    assert result.receipt.receipt.receipt_id == receipt["receipt_id"]
    await client.close()


def test_stop_result_parser_and_reconciled_receipt_page_contract() -> None:
    rpc_id = new_id(IdKind.CONTROL_RPC)
    parsed = parse_control_result(
        decode_control_frame(
            encode_control_frame(
                ControlResult(
                    protocol_version="1.0",
                    rpc_id=rpc_id,
                    service_instance_id=_SERVICE_ID,
                    service_generation="1",
                    method=ControlMethod.SERVICE_STOP,
                    outcome="ok",
                    body=ServiceStopResult(),
                )
            )
        )
    )
    assert parsed.body == ServiceStopResult()
    assert (
        PrivacyReceiptPage(snapshot_generation=1, receipts=(), next_cursor=None).snapshot_generation
        == 1
    )
    with pytest.raises(ValueError, match="invalid_privacy_port_value"):
        PrivacyReceiptPage(snapshot_generation=0, receipts=(), next_cursor=None)


def test_no_direct_runtime_or_endpoint_constructor_surface() -> None:
    names = set(signature(ServiceClient).parameters)
    assert not names & {
        "socket_path",
        "data_directory",
        "password",
        "credential",
        "application",
        "provider_client",
    }
    with pytest.raises(TypeError, match="constructor_private"):
        ServiceClient(
            cast(AuthenticatedUnixStream, _FakeStream()),
            cast(ControlSession, object()),
            ControlClientKind.CLI,
            _token=None,
        )


def _receipt_request(seed: int) -> ReceiptRequest:
    identity = f"00000000-0000-4000-8000-{seed:012d}"
    return ReceiptRequest.model_validate(
        {
            "protocol_version": "0.1",
            "schema_version": "1.0.0",
            "request_id": f"req_{identity}",
            "actor": {"actor_id": "harness:pytest", "actor_type": "harness"},
            "client": {
                "kind": "cooperative_agent",
                "version": "0.1.0",
                "integration": "cooperative_mcp",
            },
            "session_id": f"ses_{identity}",
            "writer_id": f"wri_{identity}",
            "task_id": f"tsk_{identity}",
            "expected_frontier": {"sequence": "0", "head_digest": "genesis"},
            "format": "json",
            "include": "summary",
            "redaction_profile": "default_local_export",
        }
    )


class _BlockedSendStream(_FakeStream):
    def __init__(self, *, allow_count: int) -> None:
        super().__init__()
        self.allow_count = allow_count
        self.send_attempts = 0

    async def send_all(self, data: Buffer) -> None:
        self.send_attempts += 1
        if self.send_attempts > self.allow_count:
            await asyncio.Event().wait()
        await super().send_all(data)


@pytest.mark.anyio
async def test_rpc_deadline_covers_blocked_send_and_bounded_cancel_attempt() -> None:
    stream = _BlockedSendStream(allow_count=0)
    client = _client(stream, ControlClientKind.MCP_BRIDGE)
    started = asyncio.get_running_loop().time()

    with pytest.raises(ControlError, match="request_timeout"):
        await client.receipt(_receipt_request(20), deadline_ms=10)

    # Keep a strict bound while allowing ordinary shared-runner scheduling jitter.
    assert asyncio.get_running_loop().time() - started < 0.5
    assert stream.send_attempts == 1
    assert stream.closed is True
    await client.close()


@pytest.mark.anyio
async def test_blocked_cancel_notification_cannot_materially_extend_rpc_deadline() -> None:
    stream = _BlockedSendStream(allow_count=1)
    client = _client(stream, ControlClientKind.MCP_BRIDGE)
    started = asyncio.get_running_loop().time()

    with pytest.raises(ControlError, match="request_timeout"):
        await client.receipt(_receipt_request(21), deadline_ms=10)

    assert asyncio.get_running_loop().time() - started < 0.2
    assert len(stream.sent) == 1
    assert stream.send_attempts == 2
    await client.close()


@pytest.mark.anyio
async def test_late_timed_out_result_is_retired_without_poisoning_concurrent_call() -> None:
    stream = _FakeStream()
    client = _client(stream, ControlClientKind.MCP_BRIDGE)

    with pytest.raises(ControlError, match="request_timeout"):
        await client.receipt(_receipt_request(22), deadline_ms=10)
    first = next(
        frame
        for frame in (decode_control_frame(encoded) for encoded in stream.sent)
        if frame["kind"] == "call"
    )

    # The second call tests correlation, not another timeout. Its completion is driven by
    # the explicit reply below, so unrelated CI load cannot spend a second wall-clock budget.
    healthy = asyncio.create_task(client.receipt(_receipt_request(23)))
    await _wait_for_sent(stream, 3)
    second = decode_control_frame(stream.sent[2])
    assert second["kind"] == "call"

    for frame in (first, second):
        await stream.feed(
            encode_control_frame(
                ControlResult(
                    protocol_version="1.0",
                    rpc_id=cast(str, frame["rpc_id"]),
                    service_instance_id=_SERVICE_ID,
                    service_generation="1",
                    method=ControlMethod.RECEIPT,
                    outcome="error",
                    body=ControlError("privacy_projection_unavailable", retryable=True),
                )
            )
        )

    with pytest.raises(ControlError, match="privacy_projection_unavailable"):
        await healthy
    assert stream.closed is False
    assert client._retired_rpc_ids == set()  # pyright: ignore[reportPrivateUsage]
    await client.close()


@pytest.mark.anyio
async def test_late_result_during_bounded_cancel_window_uses_tombstone_first() -> None:
    class _BlockedCancelOnceStream(_FakeStream):
        def __init__(self) -> None:
            super().__init__()
            self.send_attempts = 0

        async def send_all(self, data: Buffer) -> None:
            self.send_attempts += 1
            if self.send_attempts == 2:
                await asyncio.Event().wait()
            await super().send_all(data)

    stream = _BlockedCancelOnceStream()
    client = _client(stream, ControlClientKind.MCP_BRIDGE)
    timed_out = asyncio.create_task(client.receipt(_receipt_request(24), deadline_ms=10))
    await _wait_for_sent(stream, 1)
    first = decode_control_frame(stream.sent[0])
    for _ in range(100):
        if stream.send_attempts == 2:
            break
        await asyncio.sleep(0.001)
    assert stream.send_attempts == 2

    await stream.feed(
        encode_control_frame(
            ControlResult(
                protocol_version="1.0",
                rpc_id=cast(str, first["rpc_id"]),
                service_instance_id=_SERVICE_ID,
                service_generation="1",
                method=ControlMethod.RECEIPT,
                outcome="error",
                body=ControlError("privacy_projection_unavailable", retryable=True),
            )
        )
    )
    with pytest.raises(ControlError, match="request_timeout"):
        await timed_out

    # This call checks that retiring the late result preserved correlation. The reply
    # below drives completion; an unrelated 500 ms deadline only races CI scheduling.
    healthy = asyncio.create_task(client.receipt(_receipt_request(25)))
    await _wait_for_sent(stream, 2)
    second = decode_control_frame(stream.sent[1])
    await stream.feed(
        encode_control_frame(
            ControlResult(
                protocol_version="1.0",
                rpc_id=cast(str, second["rpc_id"]),
                service_instance_id=_SERVICE_ID,
                service_generation="1",
                method=ControlMethod.RECEIPT,
                outcome="error",
                body=ControlError("privacy_projection_unavailable", retryable=True),
            )
        )
    )
    with pytest.raises(ControlError, match="privacy_projection_unavailable"):
        await healthy
    assert stream.closed is False
    await client.close()


@pytest.mark.anyio
async def test_unanswered_timeout_tombstones_bound_new_admission() -> None:
    stream = _FakeStream()
    client = _client(stream, ControlClientKind.MCP_BRIDGE)

    for seed in range(30, 62):
        with pytest.raises(ControlError, match="request_timeout"):
            await client.receipt(_receipt_request(seed), deadline_ms=1)

    assert len(client._retired_rpc_ids) == 32  # pyright: ignore[reportPrivateUsage]
    sent_before = len(stream.sent)
    with pytest.raises(ControlError, match="service_unavailable"):
        await client.receipt(_receipt_request(63), deadline_ms=1)
    assert len(stream.sent) == sent_before
    assert stream.closed is True
    await client.close()


@pytest.mark.anyio
async def test_projection_errors_reach_the_caller_without_closing_the_connection() -> None:
    """A caller that cannot get one receipt format must be able to ask for another one.

    Collapsing these two reasons into a retryable teardown is what left a real agent retrying the
    single shape that could never succeed, so the surviving connection is the property under test.
    """

    stream = _FakeStream()
    client = _client(stream, ControlClientKind.MCP_BRIDGE)
    projection_reasons = (
        ("privacy_projection_blocked", False),
        ("privacy_projection_unavailable", True),
    )

    for index, (reason, retryable) in enumerate(projection_reasons, start=1):
        task = asyncio.create_task(client.receipt(_receipt_request(index)))
        await _wait_for_sent(stream, index)
        request = decode_control_frame(stream.sent[index - 1])
        await stream.feed(
            encode_control_frame(
                ControlResult(
                    protocol_version="1.0",
                    rpc_id=cast(str, request["rpc_id"]),
                    service_instance_id=_SERVICE_ID,
                    service_generation="1",
                    method=ControlMethod.RECEIPT,
                    outcome="error",
                    body=ControlError(reason, retryable=retryable),
                )
            )
        )
        with pytest.raises(ControlError) as raised:
            await task
        # The exact reason survives: rewriting it to service_unavailable hides the remedy.
        assert raised.value.reason == reason
        assert raised.value.retryable is retryable
        assert stream.closed is False

    # The same connection still carries a following call rather than requiring a reconnect.
    follow_up = asyncio.create_task(client.receipt(_receipt_request(3)))
    await _wait_for_sent(stream, 3)
    assert decode_control_frame(stream.sent[2])["method"] == "receipt"
    follow_up.cancel()
    await asyncio.gather(follow_up, return_exceptions=True)
    await client.close()


_CORRELATION_FOR_TEST = "err_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"


@pytest.mark.anyio
async def test_on_demand_supersedes_an_incompatible_holder_then_spawns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An upgraded client must replace a stale installation's service, not fail opaquely."""

    import yoetz.service.client as client_module

    expected = object()
    calls = 0
    spawned = 0
    superseded: list[float] = []

    async def scripted_connect(kind: ControlClientKind, **_kwargs: object) -> object:
        nonlocal calls
        assert kind is ControlClientKind.MCP_BRIDGE
        calls += 1
        if calls == 1:
            raise ControlError("service_incompatible", retryable=True)
        if calls == 2:
            raise ControlError("service_unavailable", retryable=True)
        return expected

    async def supersede(*, deadline: float) -> bool:
        superseded.append(deadline)
        return True

    def spawn() -> None:
        nonlocal spawned
        spawned += 1

    monkeypatch.setattr(client_module, "_connect_service_attempt", scripted_connect)
    monkeypatch.setattr(client_module, "supersede_incompatible_service", supersede)
    monkeypatch.setattr(client_module, "_spawn_service_process", spawn)
    monkeypatch.setattr(client_module, "_SERVICE_START_POLL_SECONDS", 0.01)
    connected = await connect_service_on_demand(ControlClientKind.MCP_BRIDGE, timeout_seconds=0.5)
    assert connected is expected
    assert len(superseded) == 1
    assert spawned == 1


@pytest.mark.anyio
async def test_on_demand_reports_incompatibility_when_no_supersede_candidate_exists(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import yoetz.service.client as client_module

    spawned = 0

    async def scripted_connect(kind: ControlClientKind, **_kwargs: object) -> object:
        raise ControlError("service_incompatible", retryable=True)

    async def no_candidate(*, deadline: float) -> bool:
        return False

    def spawn() -> None:
        nonlocal spawned
        spawned += 1

    monkeypatch.setattr(client_module, "_connect_service_attempt", scripted_connect)
    monkeypatch.setattr(client_module, "supersede_incompatible_service", no_candidate)
    monkeypatch.setattr(client_module, "_spawn_service_process", spawn)
    with pytest.raises(ControlError) as refused:
        await connect_service_on_demand(ControlClientKind.MCP_BRIDGE, timeout_seconds=0.2)
    assert refused.value.reason == "service_incompatible"
    assert refused.value.retryable is True
    assert spawned == 0

    # Callers that opt out (the explicit restart path owns supersede itself) never signal.
    async def must_not_run(*, deadline: float) -> bool:
        raise AssertionError("supersede must not run when disabled")

    monkeypatch.setattr(client_module, "supersede_incompatible_service", must_not_run)
    with pytest.raises(ControlError) as untouched:
        await connect_service_on_demand(
            ControlClientKind.MCP_BRIDGE, timeout_seconds=0.2, supersede_incompatible=False
        )
    assert untouched.value.reason == "service_incompatible"


def test_only_an_answered_manifest_mismatch_maps_to_service_incompatible() -> None:
    import yoetz.service.client as client_module
    from yoetz.service.control_protocol import ControlProtocolError

    mapped = client_module._protocol_error(  # pyright: ignore[reportPrivateUsage]
        ControlProtocolError("manifest_mismatch")
    )
    assert mapped.reason == "service_incompatible"
    assert mapped.retryable is True
    mismatch = client_module._protocol_error(  # pyright: ignore[reportPrivateUsage]
        ControlProtocolError("protocol_mismatch")
    )
    assert mismatch.reason == "protocol_mismatch"


def _holder(digest: str | None, version: str | None) -> object:
    from yoetz.service.lifecycle import SingletonHolder

    return SingletonHolder(
        pid=626, instance_id="svc_test", schema_manifest_digest=digest, service_version=version
    )


@pytest.mark.parametrize(
    ("stamp", "locator", "git_too_old", "expected"),
    [
        # #1040 (tb4n5 wdm): the holder is this installation (same pid, version and manifest).
        ("same", True, False, ("service_unavailable", "handshake", False)),
        ("same", True, True, ("service_unavailable", "handshake_git_version", False)),
        # Without a workspace the service never runs Git during the handshake.
        ("same", False, True, ("service_unavailable", "handshake", False)),
        # An unreadable stamp demonstrates nothing either way.
        ("none", True, False, ("service_unavailable", "handshake", False)),
        # Only a stamp naming another identity is an incompatibility.
        ("other_digest", True, True, ("service_incompatible", None, True)),
        ("other_version", True, False, ("service_incompatible", None, True)),
        ("predates_stamp_fields", True, False, ("service_incompatible", None, True)),
    ],
)
def test_an_unanswered_hello_is_incompatible_only_when_the_stamp_names_another_installation(
    monkeypatch: pytest.MonkeyPatch,
    stamp: str,
    locator: bool,
    git_too_old: bool,
    expected: tuple[str, str | None, bool],
) -> None:
    import yoetz.observability.logging as logging_module
    import yoetz.service.client as client_module
    from yoetz import __version__
    from yoetz.protocol.schemas import schema_manifest_digest

    own = schema_manifest_digest()
    holders: dict[str, object | None] = {
        "same": _holder(own, __version__),
        "none": None,
        "other_digest": _holder("sha256:" + "0" * 64, __version__),
        "other_version": _holder(own, "0.0.1"),
        "predates_stamp_fields": _holder(None, None),
    }
    recorded: list[dict[str, object]] = []

    def record(**fields: object) -> str:
        recorded.append(fields)
        return _CORRELATION_FOR_TEST

    monkeypatch.setattr(client_module, "service_holder_identity", lambda: holders[stamp])
    monkeypatch.setattr(client_module, "_system_git_below_minimum", lambda: git_too_old)
    monkeypatch.setattr(logging_module, "record_public_error_without_raising", record)

    error = client_module._unanswered_hello(  # pyright: ignore[reportPrivateUsage]
        WorkspaceLocator("/private/repository") if locator else None
    )

    reason, phase, retryable = expected
    assert (error.reason, error.phase, error.retryable) == (reason, phase, retryable)
    assert client_module.handshake_failure(error) == phase
    if reason == "service_incompatible":
        assert recorded == []
        assert error.correlation_id is None
    else:
        assert error.correlation_id == _CORRELATION_FOR_TEST
        assert recorded == [
            {
                "component": "service.client",
                "operation": "control_handshake",
                "reason": "service_handshake_failed",
                "reason_code": "git_version_unsupported" if git_too_old and locator else None,
            }
        ]


@pytest.mark.anyio
async def test_a_hello_closed_by_this_installations_holder_is_a_failed_handshake(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """tb4n5 wdm: same pid, version and manifest, so neither incompatible nor replaceable."""

    import yoetz.observability.logging as logging_module
    import yoetz.service.client as client_module
    from yoetz import __version__
    from yoetz.protocol.schemas import schema_manifest_digest
    from yoetz.service.control_protocol import ControlProtocolError

    stream = _FakeStream()
    spawned = 0

    async def connect() -> AuthenticatedUnixStream:
        return cast(AuthenticatedUnixStream, stream)

    async def rejected_handshake(*_args: object, **_kwargs: object) -> object:
        raise ControlProtocolError("handshake_rejected")

    async def must_not_supersede(*, deadline: float, replace_newer: bool = False) -> bool:
        raise AssertionError("an identical holder is never signalled")

    def spawn() -> None:
        nonlocal spawned
        spawned += 1

    monkeypatch.setattr(client_module, "connect_control", connect)
    monkeypatch.setattr(client_module, "client_handshake", rejected_handshake)
    monkeypatch.setattr(
        client_module,
        "service_holder_identity",
        lambda: _holder(schema_manifest_digest(), __version__),
    )
    monkeypatch.setattr(client_module, "_system_git_below_minimum", lambda: True)

    def record(**_fields: object) -> str:
        return _CORRELATION_FOR_TEST

    monkeypatch.setattr(logging_module, "record_public_error_without_raising", record)
    monkeypatch.setattr(client_module, "supersede_incompatible_service", must_not_supersede)
    monkeypatch.setattr(client_module, "_spawn_service_process", spawn)

    with pytest.raises(ControlError) as refused:
        await connect_service_on_demand(
            ControlClientKind.MCP_BRIDGE,
            workspace_locator=WorkspaceLocator("/private/repository"),
            timeout_seconds=1.0,
        )

    assert refused.value.reason == "service_unavailable"
    assert refused.value.phase == "handshake_git_version"
    assert refused.value.retryable is False
    assert refused.value.correlation_id == _CORRELATION_FOR_TEST
    assert stream.closed is True
    assert spawned == 0


@pytest.mark.anyio
async def test_on_demand_reports_a_failed_handshake_without_spawning_or_superseding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A holder of this installation that closes the hello is reported, never replaced (#1040)."""

    import yoetz.service.client as client_module

    attempts = 0
    failed = ControlError(
        "service_unavailable",
        retryable=False,
        phase="handshake",
        correlation_id=_CORRELATION_FOR_TEST,
    )

    async def scripted_connect(kind: ControlClientKind, **_kwargs: object) -> object:
        nonlocal attempts
        attempts += 1
        raise failed

    async def must_not_supersede(*, deadline: float) -> bool:
        raise AssertionError("a failed handshake is not an incompatible holder")

    def must_not_spawn() -> None:
        raise AssertionError("a running holder must not race a spawned successor")

    monkeypatch.setattr(client_module, "_connect_service_attempt", scripted_connect)
    monkeypatch.setattr(client_module, "supersede_incompatible_service", must_not_supersede)
    monkeypatch.setattr(client_module, "_spawn_service_process", must_not_spawn)
    with pytest.raises(ControlError) as refused:
        await connect_service_on_demand(ControlClientKind.MCP_BRIDGE, timeout_seconds=5.0)
    assert refused.value is failed
    assert attempts == 1


def test_transport_error_preserves_endpoint_unsafe() -> None:
    import yoetz.service.client as client_module
    from yoetz.adapters.control.unix_socket import LocalControlTransportError

    mapped = client_module._transport_error(  # pyright: ignore[reportPrivateUsage]
        LocalControlTransportError("endpoint_unsafe")
    )
    assert mapped.reason == "endpoint_unsafe"
    assert mapped.retryable is False


@pytest.mark.anyio
async def test_supersede_signals_only_a_live_foreign_identity_holder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import subprocess
    import sys
    import threading

    import yoetz.observability.logging as logging_module
    import yoetz.service.client as client_module
    from yoetz import __version__
    from yoetz.protocol.canonical import canonical_encode
    from yoetz.protocol.schemas import schema_manifest_digest

    lock = tmp_path / "service.lock"
    monkeypatch.setattr(client_module, "_singleton_lock_path", lambda: lock)
    recorded: list[str] = []

    def record(
        *, component: str, operation: str, reason: str, request_id: str | None = None
    ) -> str:
        del component, reason, request_id
        recorded.append(operation)
        return _CORRELATION_FOR_TEST

    monkeypatch.setattr(logging_module, "record_public_error_without_raising", record)

    def stamp(pid: int, digest: str | None, version: str | None) -> None:
        body: dict[str, object] = {"instance_id": "svc_test", "pid": pid}
        if digest is not None:
            body["schema_manifest_digest"] = digest
        if version is not None:
            body["service_version"] = version
        lock.write_bytes(canonical_encode(body) + b"\n")  # type: ignore[arg-type]
        lock.chmod(0o600)

    deadline = time.monotonic() + 5.0
    # No stamp at all: nothing to supersede.
    assert await client_module.supersede_incompatible_service(deadline=deadline) is False
    # Same identity that still rejected us is not an upgrade; never signalled.
    holder = subprocess.Popen(  # noqa: S603 - fixed interpreter
        (sys.executable, "-c", "import time; time.sleep(30)"),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    # A real service is detached and reaped by init; reap this child so its exit is visible
    # to the liveness probe instead of lingering as a zombie that ``kill(pid, 0)`` still sees.
    reaper = threading.Thread(target=holder.wait, daemon=True)
    reaper.start()
    try:
        stamp(holder.pid, schema_manifest_digest(), __version__)
        assert await client_module.supersede_incompatible_service(deadline=deadline) is False
        assert holder.poll() is None
        assert recorded == []
        # A legacy stamp (no identity) from a live process is a supersede candidate.
        stamp(holder.pid, None, None)
        assert await client_module.supersede_incompatible_service(deadline=deadline) is True
        reaper.join(timeout=5)
        assert holder.returncode is not None and holder.returncode != 0
        assert recorded == ["service_supersede"]
    finally:
        if holder.poll() is None:
            holder.kill()
            holder.wait(timeout=5)


def test_holder_version_order_orders_packages_and_never_guesses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import yoetz.service.client as client_module

    monkeypatch.setattr(client_module, "__version__", "0.3.1")
    order = client_module.holder_version_order
    assert order("0.3.0") == "older"
    assert order("0.3.1") == "same"
    assert order("0.3.2") == "newer"
    assert order("0.10.0") == "newer"
    # A legacy stamp or an unparsable version keeps the version-agnostic behavior.
    assert order(None) is None
    assert order("not-a-version") is None


@pytest.mark.anyio
async def test_supersede_never_replaces_a_newer_holder_unless_explicitly_restarted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A process from before an in-place upgrade must not undo it (#820)."""

    import subprocess
    import sys
    import threading

    import yoetz.observability.logging as logging_module
    import yoetz.service.client as client_module
    from yoetz.protocol.canonical import canonical_encode

    lock = tmp_path / "service.lock"
    monkeypatch.setattr(client_module, "_singleton_lock_path", lambda: lock)
    monkeypatch.setattr(client_module, "__version__", "0.3.1")
    recorded: list[str] = []

    def record(
        *, component: str, operation: str, reason: str, request_id: str | None = None
    ) -> str:
        del component, reason, request_id
        recorded.append(operation)
        return _CORRELATION_FOR_TEST

    monkeypatch.setattr(logging_module, "record_public_error_without_raising", record)

    def sleeper() -> tuple[subprocess.Popen[bytes], threading.Thread]:
        process = subprocess.Popen(  # noqa: S603 - fixed interpreter
            (sys.executable, "-c", "import time; time.sleep(30)"),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        reaper = threading.Thread(target=process.wait, daemon=True)
        reaper.start()
        return process, reaper

    def stamp(pid: int, version: str) -> None:
        body = {
            "instance_id": "svc_test",
            "pid": pid,
            "schema_manifest_digest": "sha256:" + "0" * 64,
            "service_version": version,
        }
        lock.write_bytes(canonical_encode(body) + b"\n")  # type: ignore[arg-type]
        lock.chmod(0o600)

    deadline = time.monotonic() + 5.0
    newer, newer_reaper = sleeper()
    older, older_reaper = sleeper()
    try:
        stamp(newer.pid, "0.4.0")
        assert await client_module.supersede_incompatible_service(deadline=deadline) is False
        assert newer.poll() is None
        assert recorded == []
        # An explicit human restart may still roll back.
        assert (
            await client_module.supersede_incompatible_service(
                deadline=deadline, replace_newer=True
            )
            is True
        )
        newer_reaper.join(timeout=5)
        assert newer.returncode is not None
        assert recorded == ["service_supersede"]
        # The upgrade direction is unchanged: an older holder is replaced.
        stamp(older.pid, "0.3.0")
        assert await client_module.supersede_incompatible_service(deadline=deadline) is True
        older_reaper.join(timeout=5)
        assert older.returncode is not None
        assert recorded == ["service_supersede", "service_supersede"]
    finally:
        for process in (newer, older):
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)


class _HelloClient:
    """A connected client whose hello reported ``service_version``."""

    def __init__(self, service_version: str) -> None:
        self.hello_service_status = SimpleNamespace(service_version=service_version)
        self.closed = False

    async def close(self) -> None:
        self.closed = True


def _script_on_demand(
    monkeypatch: pytest.MonkeyPatch,
    connections: list[object],
    *,
    supersede_result: bool | ControlError = True,
) -> dict[str, int]:
    import yoetz.service.client as client_module

    counts = {"connect": 0, "supersede": 0, "spawn": 0}

    async def scripted_connect(_kind: ControlClientKind, **_kwargs: object) -> object:
        counts["connect"] += 1
        item = connections.pop(0)
        if isinstance(item, ControlError):
            raise item
        return item

    async def supersede(*, deadline: float, replace_newer: bool = False) -> bool:
        assert replace_newer is False
        counts["supersede"] += 1
        if isinstance(supersede_result, ControlError):
            raise supersede_result
        return supersede_result

    def spawn() -> None:
        counts["spawn"] += 1

    monkeypatch.setattr(client_module, "__version__", "0.3.1")
    monkeypatch.setattr(client_module, "_connect_service_attempt", scripted_connect)
    monkeypatch.setattr(client_module, "supersede_incompatible_service", supersede)
    monkeypatch.setattr(client_module, "_spawn_service_process", spawn)
    monkeypatch.setattr(client_module, "_SERVICE_START_POLL_SECONDS", 0.01)
    return counts


@pytest.mark.anyio
async def test_new_session_bridge_retires_an_older_compatible_service(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The first session opened after an in-place upgrade switches to the new package (#820)."""

    stale = _HelloClient("0.3.0")
    successor = _HelloClient("0.3.1")
    counts = _script_on_demand(
        monkeypatch,
        [stale, ControlError("service_unavailable", retryable=True), successor],
    )
    connected = await connect_service_on_demand(ControlClientKind.MCP_BRIDGE, timeout_seconds=0.5)
    assert connected is successor
    assert stale.closed is True
    assert counts == {"connect": 3, "supersede": 1, "spawn": 1}


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("kind", "version"),
    [
        # Open sessions' hooks and ordinary CLI commands keep the service they found.
        (ControlClientKind.CLI, "0.3.0"),
        # Same or newer packages are never retired by a bridge.
        (ControlClientKind.MCP_BRIDGE, "0.3.1"),
        (ControlClientKind.MCP_BRIDGE, "0.4.0"),
    ],
)
async def test_only_a_bridge_retires_and_only_an_older_service(
    monkeypatch: pytest.MonkeyPatch, kind: ControlClientKind, version: str
) -> None:
    running = _HelloClient(version)
    counts = _script_on_demand(monkeypatch, [running])
    connected = await connect_service_on_demand(kind, timeout_seconds=0.5)
    assert connected is running
    assert running.closed is False
    assert counts == {"connect": 1, "supersede": 0, "spawn": 0}


@pytest.mark.anyio
async def test_bridge_keeps_the_compatible_service_when_nothing_can_be_retired(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stale = _HelloClient("0.3.0")
    again = _HelloClient("0.3.0")
    counts = _script_on_demand(monkeypatch, [stale, again], supersede_result=False)
    connected = await connect_service_on_demand(ControlClientKind.MCP_BRIDGE, timeout_seconds=0.5)
    assert connected is again
    assert counts == {"connect": 2, "supersede": 1, "spawn": 0}


@pytest.mark.anyio
async def test_bridge_reports_a_retryable_outage_while_the_older_service_drains(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    counts = _script_on_demand(
        monkeypatch,
        [_HelloClient("0.3.0")],
        supersede_result=ControlError(
            "service_incompatible", retryable=True, correlation_id=_CORRELATION_FOR_TEST
        ),
    )
    with pytest.raises(ControlError) as outage:
        await connect_service_on_demand(ControlClientKind.MCP_BRIDGE, timeout_seconds=0.5)
    assert outage.value.reason == "service_unavailable"
    assert outage.value.retryable is True
    assert outage.value.correlation_id == _CORRELATION_FOR_TEST
    assert counts == {"connect": 1, "supersede": 1, "spawn": 0}


@pytest.mark.anyio
async def test_cancelled_check_wait_consumes_late_result_without_cancelling_review() -> None:
    stream = _FakeStream()
    client = _client(stream, ControlClientKind.MCP_BRIDGE)
    source = _receipt_request(31).model_dump(mode="json", exclude_none=True)
    for key in ("task_id", "format", "include", "redaction_profile"):
        source.pop(key)
    source["mode"] = "semantic_required"
    check = CheckRequest.model_validate(source)
    waiting = asyncio.create_task(client.check(check))
    await _wait_for_sent(stream, 1)
    first = decode_control_frame(stream.sent[0])
    waiting.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiting
    # Local wait cancellation is not an explicit control cancel of the admitted review.
    assert len(stream.sent) == 1
    assert first["rpc_id"] in client._retired_rpc_ids  # pyright: ignore[reportPrivateUsage]
    healthy = asyncio.create_task(client.receipt(_receipt_request(32), deadline_ms=500))
    await _wait_for_sent(stream, 2)
    second = decode_control_frame(stream.sent[1])
    for frame, method in ((first, ControlMethod.CHECK), (second, ControlMethod.RECEIPT)):
        await stream.feed(
            encode_control_frame(
                ControlResult(
                    protocol_version="1.0",
                    rpc_id=cast(str, frame["rpc_id"]),
                    service_instance_id=_SERVICE_ID,
                    service_generation="1",
                    method=method,
                    outcome="error",
                    body=ControlError("privacy_projection_unavailable", retryable=True),
                )
            )
        )
    with pytest.raises(ControlError, match="privacy_projection_unavailable"):
        await healthy
    assert not stream.closed
    assert not client._retired_rpc_ids  # pyright: ignore[reportPrivateUsage]
    await client.close()


@pytest.mark.anyio
async def test_failed_send_reports_the_retryable_transport_mapping() -> None:
    """Issue #678: a request that validated and encoded is not the caller's malformed frame."""

    stream = _FakeStream()
    stream.send_failure = LocalControlTransportError("connection_failed")
    client = _client(stream)

    with pytest.raises(ControlError) as caught:
        await client.service_status()

    assert caught.value.reason == "service_unavailable"
    assert caught.value.retryable is True
    assert (
        public_error_code_for_control_reason(caught.value.reason)
        is PublicErrorCode.SERVICE_UNAVAILABLE
    )
    assert stream.sent == []
    await client.close()


@pytest.mark.anyio
async def test_failed_send_leaves_no_unretrieved_future_for_the_event_loop() -> None:
    """Issue #678: the call's own future is failed by teardown and must still be consumed."""

    stream = _FakeStream()
    stream.send_failure = LocalControlTransportError("connection_failed")
    client = _client(stream)

    with _captured_loop_exceptions() as contexts:
        with pytest.raises(ControlError, match="service_unavailable"):
            await client.service_status()
        await client.close()
        gc.collect()
        await _settle_loop_callbacks()

        assert [context.get("message") for context in contexts] == []


@pytest.mark.anyio
async def test_send_cancellation_stays_cancellation() -> None:
    """A cancelled write is never reclassified, and it strands no future either."""

    stream = _FakeStream()
    stream.send_failure = asyncio.CancelledError()
    client = _client(stream)

    with _captured_loop_exceptions() as contexts:
        with pytest.raises(asyncio.CancelledError):
            await client.service_status()
        await client.close()
        gc.collect()
        await _settle_loop_callbacks()

        assert [context.get("message") for context in contexts] == []


@pytest.mark.anyio
async def test_failed_send_bounds_every_concurrent_pending_caller() -> None:
    """One failed write retires the connection; every pending caller ends consumed and bounded."""

    stream = _FakeStream()
    client = _client(stream)

    with _captured_loop_exceptions() as contexts:
        awaiting_answer = asyncio.create_task(client.service_status())
        await _wait_for_sent(stream, 1)
        stream.send_failure = LocalControlTransportError("connection_failed")

        with pytest.raises(ControlError) as failed_write:
            await client.service_status()
        assert failed_write.value.reason == "service_unavailable"
        assert failed_write.value.retryable is True

        with pytest.raises(ControlError) as stranded:
            await awaiting_answer
        assert stranded.value.reason == "service_unavailable"
        assert stranded.value.retryable is True

        await client.close()
        gc.collect()
        await _settle_loop_callbacks()

        assert [context.get("message") for context in contexts] == []


@pytest.mark.anyio
@pytest.mark.parametrize("compatible", [True, False])
async def test_hook_startup_reuses_starting_holder_without_spawning_or_signalling(
    monkeypatch: pytest.MonkeyPatch, compatible: bool
) -> None:
    import yoetz.service.client as client_module
    from yoetz.service.lifecycle import SingletonHolder

    expected = object()
    calls = 0

    async def connect(_kind: ControlClientKind, **_kwargs: object) -> object:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise ControlError("service_unavailable", retryable=True)
        return expected

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("a hook must not spawn beside or signal an existing holder")

    holder = SingletonHolder(
        pid=123,
        instance_id=None,
        schema_manifest_digest="selected" if compatible else "other",
        service_version=client_module.__version__,
    )
    monkeypatch.setattr(client_module, "service_holder_identity", lambda: holder)
    monkeypatch.setattr(client_module, "_singleton_holder_lock_is_held", lambda: True)
    monkeypatch.setattr(client_module, "_manifest_digest_for_client", lambda: "selected")
    monkeypatch.setattr(client_module, "_connect_service_attempt", connect)
    monkeypatch.setattr(client_module, "_spawn_service_process", forbidden)
    monkeypatch.setattr(client_module, "supersede_incompatible_service", forbidden)
    if compatible:
        assert (
            await connect_service_on_demand(
                ControlClientKind.CLI, timeout_seconds=0.2, supersede_incompatible=False
            )
            is expected
        )
        assert calls == 2
    else:
        with pytest.raises(ControlError, match="service_incompatible"):
            await connect_service_on_demand(
                ControlClientKind.CLI, timeout_seconds=0.2, supersede_incompatible=False
            )
        assert calls == 1


@pytest.mark.anyio
@pytest.mark.parametrize("digest", ["selected", "other"])
async def test_hook_startup_spawns_after_an_unheld_holder_stamp(
    monkeypatch: pytest.MonkeyPatch,
    digest: str,
) -> None:
    """An unheld stamp, including an old-version one, must not block hook startup."""

    import yoetz.service.client as client_module
    from yoetz.service.lifecycle import SingletonHolder

    expected = object()
    calls = 0
    spawned = 0

    async def connect(_kind: ControlClientKind, **_kwargs: object) -> object:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise ControlError("service_unavailable", retryable=True)
        return expected

    def spawn() -> None:
        nonlocal spawned
        spawned += 1

    holder = SingletonHolder(
        pid=123,
        instance_id=None,
        schema_manifest_digest=digest,
        service_version=client_module.__version__,
    )
    monkeypatch.setattr(client_module, "service_holder_identity", lambda: holder)
    monkeypatch.setattr(client_module, "_singleton_holder_lock_is_held", lambda: False)
    monkeypatch.setattr(client_module, "_manifest_digest_for_client", lambda: "selected")
    monkeypatch.setattr(client_module, "_connect_service_attempt", connect)
    monkeypatch.setattr(client_module, "_spawn_service_process", spawn)
    monkeypatch.setattr(client_module, "_SERVICE_START_POLL_SECONDS", 0.01)

    connected = await connect_service_on_demand(
        ControlClientKind.CLI,
        timeout_seconds=0.2,
        supersede_incompatible=False,
    )
    assert connected is expected
    assert calls == 2
    assert spawned == 1
