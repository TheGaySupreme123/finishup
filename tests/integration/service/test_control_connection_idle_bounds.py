"""AF_UNIX regressions for ordinary-control handshake and inactive-session bounds.

Closes the validated slot-exhaustion path (issue #106): same-UID clients that withhold the
handshake or the next post-handshake frame must not retain listener admission capacity
indefinitely. Active long-running calls remain exempt from the inactive timer.
"""

from __future__ import annotations

import asyncio
import shutil
import struct
import sys
import tempfile
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

import finishup.adapters.control.unix_socket as unix_socket_module
import finishup.service.daemon as daemon_module
from finishup.adapters.control.unix_socket import (
    RUNTIME_DIRECTORY_MODE,
    AuthenticatedUnixStream,
    bind_control_listener,
    close_endpoint,
    connect_control,
)
from finishup.domain.values import JsonObject
from finishup.ports.control import (
    ControlCallRequest,
    ControlClientKind,
    ControlMethod,
    ControlResult,
    ServiceState,
)
from finishup.protocol.ids import IdKind, new_id
from finishup.service.control_protocol import (
    MAX_CONTROL_FRAME_BYTES,
    ControlProtocolError,
    client_handshake,
    parse_control_result,
    read_control_frame,
    write_control_frame,
)
from finishup.service.daemon import ServiceComposition, ServiceDaemon
from finishup.service.lifecycle import ServiceLifecycle
from finishup.service.vault import VaultMode

_INSTANCE_ID = "svc_00000000-0000-4000-8000-000000000106"
_COMMITMENT = "sha256:" + "6" * 64
_CAPACITY = 2
_SHORT_HANDSHAKE = 0.25
_SHORT_IDLE = 0.35
_LONG_CALL = 0.9


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def runtime_directory(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    runtime = Path(tempfile.mkdtemp(prefix=".yctl-idle-", dir=Path.cwd()))
    runtime.chmod(RUNTIME_DIRECTORY_MODE)
    monkeypatch.setattr(
        "finishup.adapters.control.unix_socket._runtime_directory",
        lambda: runtime,
    )
    try:
        yield runtime
    finally:
        shutil.rmtree(runtime)


class _Clock:
    def now_utc(self) -> datetime:
        return datetime(2026, 8, 2, tzinfo=UTC)

    def monotonic_seconds(self) -> float:
        return 10.0


class _GenerationStore:
    def advance(self, instance_id: str) -> int:
        assert instance_id == _INSTANCE_ID
        return 1


class _Capability:
    active = False


class _Monitor:
    capability = _Capability()

    async def start(self, callback: object) -> None:
        del callback

    async def close(self) -> None:
        return None


class _Vault:
    mode = VaultMode.OS_KEYRING
    generation = 1
    ready = True

    async def lock(self) -> None:
        self.ready = False

    async def close(self) -> None:
        self.ready = False


class _Application:
    provider_credential_connected = False

    async def close(self) -> None:
        return None


async def _daemon_with_real_listener() -> tuple[ServiceDaemon, asyncio.Task[None]]:
    listener = await bind_control_listener()
    lifecycle = ServiceLifecycle(
        _Clock(),
        generation_store=_GenerationStore(),
        process_start_identity_commitment=_COMMITMENT,
        instance_id=_INSTANCE_ID,
    )
    composition = ServiceComposition(
        lifecycle=lifecycle,
        control_listener=listener,  # pyright: ignore[reportArgumentType]
        secret_ingress_listener=None,
        human_control_listener=None,
        human_control_service=None,
        session_monitor=_Monitor(),  # pyright: ignore[reportArgumentType]
        vault=_Vault(),
        application=_Application(),  # pyright: ignore[reportArgumentType]
    )
    daemon = ServiceDaemon(_composition=composition)
    await daemon.start()
    assert daemon.composition.lifecycle.state is ServiceState.READY
    accept_task = asyncio.create_task(
        daemon._accept_loop(  # pyright: ignore[reportPrivateUsage]
            listener,  # pyright: ignore[reportArgumentType]
            daemon._serve_control_connection,  # pyright: ignore[reportPrivateUsage]
        )
    )
    return daemon, accept_task


async def _shutdown(
    daemon: ServiceDaemon,
    accept_task: asyncio.Task[None],
    listener: object,
) -> None:
    accept_task.cancel()
    await asyncio.gather(accept_task, return_exceptions=True)
    await daemon.close()
    await close_endpoint(listener)  # pyright: ignore[reportArgumentType]


@pytest.mark.anyio
@pytest.mark.skipif(
    not (sys.platform == "darwin" or sys.platform.startswith("linux")),
    reason="certified local peer APIs are macOS/Linux only",
)
async def test_handshake_withholders_release_slots_after_deadline(
    runtime_directory: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del runtime_directory
    monkeypatch.setattr(unix_socket_module, "_MAX_ACTIVE_CONNECTIONS", _CAPACITY)
    monkeypatch.setattr(daemon_module, "_CONTROL_HANDSHAKE_DEADLINE_SECONDS", _SHORT_HANDSHAKE)
    monkeypatch.setattr(daemon_module, "_CONTROL_INACTIVE_SESSION_DEADLINE_SECONDS", _SHORT_IDLE)

    daemon, accept_task = await _daemon_with_real_listener()
    listener = daemon.composition.control_listener
    holders = [await connect_control() for _ in range(_CAPACITY)]
    try:
        # Fill every admission slot with clients that never send a handshake. Connect still
        # succeeds into the listen backlog; the bound is that a further session cannot complete
        # handshake until a slot is released.
        await asyncio.sleep(0.05)

        legitimate = await connect_control()
        blocked_handshake = asyncio.create_task(
            client_handshake(legitimate, ControlClientKind.CLI, "0.1.0")
        )
        await asyncio.sleep(0.1)
        assert not blocked_handshake.done(), (
            "legitimate handshake must wait while capacity is exhausted"
        )

        # After the short handshake deadline, stale streams close and release slots.
        session = await asyncio.wait_for(blocked_handshake, timeout=_SHORT_HANDSHAKE + 1.5)
        try:
            assert session.protocol_version == "1.0"
            assert session.service_instance_id == _INSTANCE_ID
        finally:
            await legitimate.aclose()
    finally:
        for holder in holders:
            await holder.aclose()
        await _shutdown(daemon, accept_task, listener)


@pytest.mark.anyio
@pytest.mark.skipif(
    not (sys.platform == "darwin" or sys.platform.startswith("linux")),
    reason="certified local peer APIs are macOS/Linux only",
)
async def test_post_handshake_frame_withholders_release_slots_after_idle(
    runtime_directory: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del runtime_directory
    monkeypatch.setattr(unix_socket_module, "_MAX_ACTIVE_CONNECTIONS", _CAPACITY)
    monkeypatch.setattr(daemon_module, "_CONTROL_HANDSHAKE_DEADLINE_SECONDS", 5.0)
    monkeypatch.setattr(daemon_module, "_CONTROL_INACTIVE_SESSION_DEADLINE_SECONDS", _SHORT_IDLE)

    daemon, accept_task = await _daemon_with_real_listener()
    listener = daemon.composition.control_listener
    holders: list[AuthenticatedUnixStream] = []
    try:
        for _ in range(_CAPACITY):
            client = await connect_control()
            holders.append(client)
            await client_handshake(client, ControlClientKind.CLI, "0.1.0")
            # Withhold every subsequent frame; idle countdown starts immediately.

        await asyncio.sleep(0.05)
        legitimate = await connect_control()
        blocked_handshake = asyncio.create_task(
            client_handshake(legitimate, ControlClientKind.CLI, "0.1.0")
        )
        await asyncio.sleep(0.1)
        assert not blocked_handshake.done(), (
            "legitimate handshake must wait while idle sessions hold slots"
        )

        session = await asyncio.wait_for(blocked_handshake, timeout=_SHORT_IDLE + 1.5)
        try:
            assert session.service_instance_id == _INSTANCE_ID
        finally:
            await legitimate.aclose()
    finally:
        for holder in holders:
            await holder.aclose()
        await _shutdown(daemon, accept_task, listener)


@pytest.mark.anyio
@pytest.mark.skipif(
    not (sys.platform == "darwin" or sys.platform.startswith("linux")),
    reason="certified local peer APIs are macOS/Linux only",
)
async def test_active_request_exempts_session_from_idle_deadline(
    runtime_directory: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A request longer than the idle interval still completes; idle starts only after it ends."""

    del runtime_directory
    monkeypatch.setattr(unix_socket_module, "_MAX_ACTIVE_CONNECTIONS", 8)
    monkeypatch.setattr(daemon_module, "_CONTROL_HANDSHAKE_DEADLINE_SECONDS", 5.0)
    monkeypatch.setattr(daemon_module, "_CONTROL_INACTIVE_SESSION_DEADLINE_SECONDS", _SHORT_IDLE)

    original_dispatch = ServiceDaemon.dispatch

    async def _slow_status_dispatch(
        self: ServiceDaemon,
        client_kind: ControlClientKind,
        request: ControlCallRequest,
        *,
        projection_context: object | None = None,
        _defer_stop: bool = False,
    ) -> ControlResult:
        if request.method is ControlMethod.SERVICE_STATUS:
            await asyncio.sleep(_LONG_CALL)
        return await original_dispatch(
            self,
            client_kind,
            request,
            projection_context=projection_context,  # pyright: ignore[reportArgumentType]
            _defer_stop=_defer_stop,
        )

    monkeypatch.setattr(ServiceDaemon, "dispatch", _slow_status_dispatch)

    daemon, accept_task = await _daemon_with_real_listener()
    listener = daemon.composition.control_listener
    client = await connect_control()
    try:
        session = await client_handshake(client, ControlClientKind.CLI, "0.1.0")
        request = ControlCallRequest(
            kind="call",
            protocol_version="1.0",
            rpc_id=new_id(IdKind.CONTROL_RPC),
            service_instance_id=session.service_instance_id,
            service_generation=session.service_generation,
            method=ControlMethod.SERVICE_STATUS,
            body=JsonObject({}),
        )
        # No further frames while the call is in flight; idle must not cancel it.
        await write_control_frame(client, request)
        assert _LONG_CALL > _SHORT_IDLE
        await asyncio.sleep(_SHORT_IDLE + 0.1)
        # Stream must still be live so the result frame can arrive after the long call.
        result = parse_control_result(
            await asyncio.wait_for(read_control_frame(client), timeout=_LONG_CALL + 1.0)
        )
        assert result.outcome == "ok"
        assert result.method is ControlMethod.SERVICE_STATUS

        # After the final call completes, the inactive deadline begins. Withholding the next
        # frame must eventually close the stream. Assert the server-side close path
        # (ControlProtocolError on EOF), not a client wait_for TimeoutError that would mask a
        # missing idle eviction.
        await asyncio.sleep(_SHORT_IDLE + 0.25)
        with pytest.raises(ControlProtocolError) as idle_close:
            await asyncio.wait_for(read_control_frame(client), timeout=1.0)
        assert idle_close.value.reason == "frame_invalid"
    finally:
        await client.aclose()
        await _shutdown(daemon, accept_task, listener)


@pytest.mark.anyio
@pytest.mark.skipif(
    not (sys.platform == "darwin" or sys.platform.startswith("linux")),
    reason="certified local peer APIs are macOS/Linux only",
)
async def test_valid_handshake_and_service_status_still_succeed(
    runtime_directory: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Retain a positive control for ordinary valid handshake + one structural call."""

    del runtime_directory
    monkeypatch.setattr(unix_socket_module, "_MAX_ACTIVE_CONNECTIONS", 8)

    daemon, accept_task = await _daemon_with_real_listener()
    listener = daemon.composition.control_listener
    client = await connect_control()
    try:
        session = await client_handshake(client, ControlClientKind.CLI, "0.1.0")
        request = ControlCallRequest(
            kind="call",
            protocol_version="1.0",
            rpc_id=new_id(IdKind.CONTROL_RPC),
            service_instance_id=session.service_instance_id,
            service_generation=session.service_generation,
            method=ControlMethod.SERVICE_STATUS,
            body=JsonObject({}),
        )
        await write_control_frame(client, request)
        result = parse_control_result(await read_control_frame(client))
        assert result.outcome == "ok"
        assert result.method is ControlMethod.SERVICE_STATUS
    finally:
        await client.aclose()
        await _shutdown(daemon, accept_task, listener)


class _FrameRefusals:
    """Captures the daemon's structural frame-refusal diagnostics as observable state."""

    def __init__(self) -> None:
        self.reasons: list[str] = []
        self.recorded = asyncio.Event()

    def __call__(self, *, component: str, operation: str, reason: str, **_: object) -> str:
        if component == "service.daemon" and operation == "control_frame_read":
            self.reasons.append(reason)
            self.recorded.set()
        return "cor_00000000-0000-4000-8000-000000000921"


async def _assert_server_closed(client: AuthenticatedUnixStream) -> None:
    # EOF before any byte of a reply is the server-side close; the outer bound only guards the run.
    with pytest.raises(ControlProtocolError) as closed:
        await asyncio.wait_for(read_control_frame(client), timeout=5.0)
    assert closed.value.reason == "frame_invalid"


@pytest.mark.anyio
@pytest.mark.skipif(
    not (sys.platform == "darwin" or sys.platform.startswith("linux")),
    reason="certified local peer APIs are macOS/Linux only",
)
async def test_a_frame_declared_one_byte_over_the_ceiling_closes_the_connection(
    runtime_directory: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del runtime_directory
    monkeypatch.setattr(unix_socket_module, "_MAX_ACTIVE_CONNECTIONS", 8)
    refusals = _FrameRefusals()
    monkeypatch.setattr(daemon_module, "record_public_error_without_raising", refusals)

    daemon, accept_task = await _daemon_with_real_listener()
    listener = daemon.composition.control_listener
    client = await connect_control()
    try:
        await client_handshake(client, ControlClientKind.CLI, "0.1.0")
        await client.send_all(struct.pack(">I", MAX_CONTROL_FRAME_BYTES + 1))
        await asyncio.wait_for(refusals.recorded.wait(), timeout=5.0)
        assert refusals.reasons == ["frame_too_large"]
        await _assert_server_closed(client)
    finally:
        await client.aclose()
        await _shutdown(daemon, accept_task, listener)


@pytest.mark.anyio
@pytest.mark.skipif(
    not (sys.platform == "darwin" or sys.platform.startswith("linux")),
    reason="certified local peer APIs are macOS/Linux only",
)
async def test_a_stalled_frame_is_cut_off_even_while_a_call_is_active(
    runtime_directory: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An in-flight call exempts the session from idle, never a begun frame from its deadline."""

    del runtime_directory
    monkeypatch.setattr(unix_socket_module, "_MAX_ACTIVE_CONNECTIONS", 8)
    monkeypatch.setattr(daemon_module, "_CONTROL_HANDSHAKE_DEADLINE_SECONDS", 5.0)
    # Idle can never fire during this test; only the frame deadline can close the stream.
    monkeypatch.setattr(daemon_module, "_CONTROL_INACTIVE_SESSION_DEADLINE_SECONDS", 600.0)
    monkeypatch.setattr(daemon_module, "_CONTROL_FRAME_READ_DEADLINE_SECONDS", _SHORT_IDLE)
    refusals = _FrameRefusals()
    monkeypatch.setattr(daemon_module, "record_public_error_without_raising", refusals)

    call_started = asyncio.Event()
    original_dispatch = ServiceDaemon.dispatch

    async def _held_status_dispatch(
        self: ServiceDaemon,
        client_kind: ControlClientKind,
        request: ControlCallRequest,
        *,
        projection_context: object | None = None,
        _defer_stop: bool = False,
    ) -> ControlResult:
        if request.method is ControlMethod.SERVICE_STATUS:
            call_started.set()
            await asyncio.Event().wait()
        return await original_dispatch(
            self,
            client_kind,
            request,
            projection_context=projection_context,  # pyright: ignore[reportArgumentType]
            _defer_stop=_defer_stop,
        )

    monkeypatch.setattr(ServiceDaemon, "dispatch", _held_status_dispatch)

    daemon, accept_task = await _daemon_with_real_listener()
    listener = daemon.composition.control_listener
    client = await connect_control()
    try:
        session = await client_handshake(client, ControlClientKind.CLI, "0.1.0")
        await write_control_frame(
            client,
            ControlCallRequest(
                kind="call",
                protocol_version="1.0",
                rpc_id=new_id(IdKind.CONTROL_RPC),
                service_instance_id=session.service_instance_id,
                service_generation=session.service_generation,
                method=ControlMethod.SERVICE_STATUS,
                body=JsonObject({}),
            ),
        )
        await asyncio.wait_for(call_started.wait(), timeout=5.0)
        # Begin a large frame while the call is in flight, then stop sending.
        await client.send_all(struct.pack(">I", 1_000_000) + b"{" * 70_000)
        await asyncio.wait_for(refusals.recorded.wait(), timeout=5.0)
        assert refusals.reasons == ["frame_read_timeout"]
        await _assert_server_closed(client)
    finally:
        await client.aclose()
        await _shutdown(daemon, accept_task, listener)
