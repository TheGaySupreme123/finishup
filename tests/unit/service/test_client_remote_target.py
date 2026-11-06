"""``service.client`` with a remote target selected (ADR-051, approach B: direct dial).

A remote root is dialled through its own transport. It never spawns or supersedes a local
service, never sends a path on the hello, reports every failure as a retryable
``service_unavailable`` with one closed remote phase, and starts a stopped SSH service once
through its recorded launcher. A damaged target record refuses before any dial.
"""

from __future__ import annotations

import asyncio
import base64
import hmac
import os
from collections.abc import Awaitable, Buffer, Callable, Iterator
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from builders.direct_dial import TapStream, memory_pair, service_status
from builders.server_targets import ambient_home
from finishup.client import targets, transports
from finishup.client.targets import ServerTarget
from finishup.client.transports import TransportError
from finishup.client.workspace_claim import worktree_digest
from finishup.config.paths import reset_selection_memo
from finishup.ports.control import (
    ControlClientKind,
    ControlError,
    ControlMethod,
    ControlResult,
    RepositoryPrivacyContext,
    ServiceState,
    ServiceStatus,
    WorkspaceClaim,
    WorkspaceLocator,
)
from finishup.service import client as client_module
from finishup.service.control_protocol import (
    ControlStream,
    parse_control_request,
    read_control_frame,
    server_handshake,
    write_control_frame,
)


class _FakeTransport:
    """A remote transport whose streams come from ``dial`` (a test script)."""

    def __init__(self, target: ServerTarget, dial: Callable[[], Awaitable[ControlStream]]) -> None:
        self._target = target
        self._dial = dial
        self.dials = 0

    @property
    def kind(self) -> str:
        return "ssh"

    @property
    def target(self) -> ServerTarget:
        return self._target

    async def connect(self) -> ControlStream:
        self.dials += 1
        return await self._dial()


@pytest.fixture
def remote(monkeypatch: pytest.MonkeyPatch) -> Iterator[ServerTarget]:
    """Select an SSH target, and forbid every local lifecycle step a remote root must not take."""

    with ambient_home(monkeypatch):
        with targets.registry_lock():
            record, _root = targets.new_remote_target(
                "lab",
                "ssh",
                user="owner",
                host="lab.example",
                port=22,
                remote_root="/srv/fu",
                remote_launcher="/opt/fu/bin/finishup",
            )
            targets.write_selection(record)
        reset_selection_memo()

        def forbidden(*_args: object, **_kwargs: object) -> object:
            raise AssertionError("a remote root never spawns or supersedes a local service")

        monkeypatch.setattr(client_module, "_spawn_service_process", forbidden)
        monkeypatch.setattr(client_module, "supersede_incompatible_service", forbidden)
        monkeypatch.setattr(client_module, "connect_control", forbidden)
        yield record


def _use(monkeypatch: pytest.MonkeyPatch, transport: _FakeTransport) -> None:
    def chosen(_target: ServerTarget, _root: Path) -> _FakeTransport:
        return transport

    monkeypatch.setattr(transports, "transport_for_target", chosen)


async def _key_claim(claim: WorkspaceClaim) -> RepositoryPrivacyContext:
    """The daemon's answer to a claim while its vault is ready: a keyed ``client_claim``."""

    from finishup.ports.workspace_agent import workspace_handle_for_claim

    commitment = "hmac-sha256:" + hmac.new(
        b"installation", claim.digest.encode("ascii"), "sha256"
    ).hexdigest()
    return RepositoryPrivacyContext(
        commitment=commitment,
        identity_kind="client_claim",
        workspace_handle=workspace_handle_for_claim(commitment, claim.worktree),
    )


async def _serve(
    stream: ControlStream,
    *,
    status: ServiceStatus | None = None,
    keyed: bool = True,
) -> None:
    session = await server_handshake(
        stream,
        stream.peer_identity,
        status or service_status(),
        claim_context_resolver=_key_claim if keyed else None,
    )
    while True:
        try:
            frame = await read_control_frame(stream, eof_reason="session_closed")
        except Exception:
            return
        request = parse_control_request(frame)
        await write_control_frame(
            stream,
            ControlResult(
                protocol_version="1.0",
                rpc_id=request.rpc_id,
                service_instance_id=session.service_instance_id,
                service_generation=session.service_generation,
                method=ControlMethod.SERVICE_STATUS,
                outcome="ok",
                body=service_status(),
            ),
        )


def test_a_remote_root_never_spawns_or_supersedes(
    remote: ServerTarget, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    async def unreachable() -> ControlStream:
        raise TransportError("remote_unreachable")

    transport = _FakeTransport(remote, unreachable)
    _use(monkeypatch, transport)

    async def exercise() -> ControlError:
        with pytest.raises(ControlError) as raised:
            await client_module.connect_service_on_demand(
                ControlClientKind.MCP_BRIDGE,
                workspace_locator=WorkspaceLocator(str(tmp_path)),
                timeout_seconds=2.0,
            )
        return raised.value

    error = asyncio.run(exercise())
    assert (error.reason, error.retryable, error.phase) == (
        "service_unavailable",
        True,
        "remote_unreachable",
    )
    assert transport.dials == 1


def test_the_hello_to_a_remote_server_carries_a_claim_and_no_path(
    remote: ServerTarget, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    workspace = tmp_path / "secret-repository"
    workspace.mkdir()
    taps: list[TapStream] = []

    async def dial() -> ControlStream:
        client_end, server_end = memory_pair()
        tap = TapStream(server_end)
        taps.append(tap)
        asyncio.get_running_loop().create_task(_serve(tap))
        return client_end

    _use(monkeypatch, _FakeTransport(remote, dial))

    async def exercise() -> tuple[str, str, str]:
        client = await client_module.connect_service(
            ControlClientKind.CLI, workspace_locator=WorkspaceLocator(str(workspace))
        )
        try:
            status = await client.service_status()
        finally:
            await client.close()
        return status.service_instance_id, client.workspace_binding, client.transport

    assert asyncio.run(exercise()) == (
        service_status().service_instance_id,
        "client_claim",
        "ssh",
    )
    (tap,) = taps
    assert b"secret-repository" not in tap.received
    assert os.fsencode(tmp_path) not in tap.received
    assert b"workspace_locator" not in tap.received
    assert b'"workspace_claim"' in tap.received
    # The claim names this worktree by its keyed digest (each linked worktree has its own).
    assert b'"worktree":"sha256:' in tap.received
    # A connection that names a workspace but no binding claims it and offers no agent.
    assert b'"workspace_agent"' not in tap.received
    assert b'"workspace_binding":"client_claim"' in tap.sent


def test_a_workspace_the_root_rule_cannot_resolve_is_never_dialled(
    remote: ServerTarget, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    async def dial() -> ControlStream:
        raise AssertionError("an unclaimable workspace is refused before any dial")

    _use(monkeypatch, _FakeTransport(remote, dial))

    async def exercise() -> ControlError:
        with pytest.raises(ControlError) as raised:
            await client_module.connect_service(
                ControlClientKind.CLI,
                workspace_locator=WorkspaceLocator(str(tmp_path / "missing")),
            )
        return raised.value

    error = asyncio.run(exercise())
    assert (error.reason, error.retryable, error.phase) == (
        "service_unavailable",
        False,
        "handshake",
    )
    assert "missing" not in str(error)


@pytest.mark.parametrize("started", [True, False])
def test_a_stopped_ssh_service_is_started_once_through_its_launcher(
    remote: ServerTarget, monkeypatch: pytest.MonkeyPatch, started: bool
) -> None:
    starts: list[float] = []

    async def dial() -> ControlStream:
        if not starts:
            raise TransportError("remote_service_not_running")
        client_end, server_end = memory_pair()
        asyncio.get_running_loop().create_task(_serve(server_end))
        return client_end

    async def start(_transport: object, seconds: float) -> bool:
        starts.append(seconds)
        return started

    transport = _FakeTransport(remote, dial)
    _use(monkeypatch, transport)
    monkeypatch.setattr(transports, "start_remote_service", start)

    async def exercise() -> None:
        client = await client_module.connect_service_on_demand(
            ControlClientKind.CLI, timeout_seconds=5.0
        )
        await client.close()

    if started:
        asyncio.run(exercise())
        assert transport.dials == 2
    else:
        with pytest.raises(ControlError) as raised:
            asyncio.run(exercise())
        assert raised.value.phase == "remote_service_not_running"
        assert transport.dials == 1
    assert len(starts) == 1 and 0 < starts[0] <= 5.0


def test_a_channel_refused_after_a_successful_start_is_not_a_stopped_service(
    remote: ServerTarget, monkeypatch: pytest.MonkeyPatch
) -> None:
    # OpenSSH reports a refused stream-local channel the same way when sshd refuses forwarding:
    # once the server's own start reported its service running, starting it is not the remedy.
    starts: list[float] = []

    async def dial() -> ControlStream:
        raise TransportError("remote_service_not_running")

    async def start(_transport: object, seconds: float) -> bool:
        starts.append(seconds)
        return True

    transport = _FakeTransport(remote, dial)
    _use(monkeypatch, transport)
    monkeypatch.setattr(transports, "start_remote_service", start)

    async def exercise() -> ControlError:
        with pytest.raises(ControlError) as raised:
            await client_module.connect_service_on_demand(
                ControlClientKind.CLI, timeout_seconds=5.0
            )
        return raised.value

    error = asyncio.run(exercise())
    assert (error.reason, error.retryable, error.phase) == (
        "service_unavailable",
        True,
        "remote_unreachable",
    )
    assert transport.dials == 2 and len(starts) == 1


class _ClosingStream:
    """A remote stream that ends at once and names why (as an ``ssh`` child would)."""

    def __init__(self, phase: str | None) -> None:
        self.peer_identity = object()
        self._phase = phase

    async def receive(self, max_bytes: int = 65_536) -> bytes:
        del max_bytes
        return b""

    async def send_all(self, data: object) -> None:
        del data

    async def aclose(self) -> None:
        return None

    async def failure_phase(self) -> str | None:
        return self._phase


@pytest.mark.parametrize(
    ("phase", "expected"),
    [
        ("remote_auth_failed", "remote_auth_failed"),
        ("remote_identity_changed", "remote_identity_changed"),
        # The server's own end closed the hello: another release.
        (None, "remote_incompatible"),
    ],
)
def test_a_closed_hello_takes_the_streams_own_phase(
    remote: ServerTarget, monkeypatch: pytest.MonkeyPatch, phase: str | None, expected: str
) -> None:
    async def dial() -> ControlStream:
        return _ClosingStream(phase)

    _use(monkeypatch, _FakeTransport(remote, dial))

    async def exercise() -> ControlError:
        with pytest.raises(ControlError) as raised:
            await client_module.connect_service(ControlClientKind.CLI)
        return raised.value

    error = asyncio.run(exercise())
    assert (error.reason, error.retryable, error.phase) == ("service_unavailable", True, expected)


class _PhasedStream:
    """A remote stream (as an ``ssh`` child is) that names a phase once its peer is gone."""

    def __init__(self, inner: ControlStream, phase: str | None) -> None:
        self._inner = inner
        self._phase = phase
        self.peer_identity = inner.peer_identity

    async def receive(self, max_bytes: int = 65_536) -> bytes:
        return await self._inner.receive(max_bytes)

    async def send_all(self, data: Buffer) -> None:
        await self._inner.send_all(data)

    async def aclose(self) -> None:
        await self._inner.aclose()

    async def failure_phase(self) -> str | None:
        return self._phase


async def _serve_then_drop(stream: ControlStream, *, partial_frame: bool) -> None:
    """Answer the hello, take one call, then lose the connection (optionally inside a frame)."""

    await server_handshake(stream, stream.peer_identity, service_status())
    await read_control_frame(stream)
    if partial_frame:
        # A length prefix promising a body that never arrives: cut off inside a frame.
        await stream.send_all(b"\x00\x00\x01\x00{")
    await stream.aclose()


@pytest.mark.parametrize(
    ("phase", "partial_frame", "expected"),
    [
        # The stream names why it ended (a key revoked under a long-poll, say).
        ("remote_auth_failed", False, "remote_auth_failed"),
        # It names nothing: the server is no longer reachable.
        (None, False, "remote_unreachable"),
        # An ``ssh`` child that exited inside a frame names its phase too.
        ("remote_unreachable", True, "remote_unreachable"),
    ],
)
def test_a_remote_connection_lost_under_a_call_is_retryable_and_names_its_phase(
    remote: ServerTarget,
    monkeypatch: pytest.MonkeyPatch,
    phase: str | None,
    partial_frame: bool,
    expected: str,
) -> None:
    async def dial() -> ControlStream:
        client_end, server_end = memory_pair()
        asyncio.get_running_loop().create_task(
            _serve_then_drop(server_end, partial_frame=partial_frame)
        )
        return _PhasedStream(client_end, phase)

    _use(monkeypatch, _FakeTransport(remote, dial))

    async def exercise() -> tuple[ControlError, ControlError]:
        client = await client_module.connect_service(ControlClientKind.CLI)
        try:
            with pytest.raises(ControlError) as raised:
                await client.service_status()
            with pytest.raises(ControlError) as later:
                await client.service_status()
        finally:
            await client.close()
        return raised.value, later.value

    # Never ``frame_invalid``: the request was valid and may have reached the server, so the
    # caller reconnects and replays the same request_id.
    for error in asyncio.run(exercise()):
        assert (error.reason, error.retryable, error.phase) == (
            "service_unavailable",
            True,
            expected,
        )


def test_an_invalid_whole_frame_on_a_live_remote_stream_stays_frame_invalid(
    remote: ServerTarget, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def serve(stream: ControlStream) -> None:
        await server_handshake(stream, stream.peer_identity, service_status())
        await read_control_frame(stream)
        body = b'{"kind":"nonsense"}'
        await stream.send_all(len(body).to_bytes(4, "big") + body)

    async def dial() -> ControlStream:
        client_end, server_end = memory_pair()
        asyncio.get_running_loop().create_task(serve(server_end))
        return _PhasedStream(client_end, None)

    _use(monkeypatch, _FakeTransport(remote, dial))

    async def exercise() -> ControlError:
        client = await client_module.connect_service(ControlClientKind.CLI)
        try:
            with pytest.raises(ControlError) as raised:
                await client.service_status()
        finally:
            await client.close()
        return raised.value

    assert asyncio.run(exercise()).reason == "frame_invalid"


def test_a_damaged_selected_target_refuses_before_any_dial(
    remote: ServerTarget, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = targets.target_root(remote.target_id)
    (root / "target.json").write_bytes(b"{}\n")
    reset_selection_memo()

    async def exercise() -> ControlError:
        with pytest.raises(ControlError) as raised:
            await client_module.connect_service_on_demand(
                ControlClientKind.CLI, timeout_seconds=1.0
            )
        return raised.value

    error = asyncio.run(exercise())
    assert error.reason == "endpoint_unsafe"
    assert client_module.path_refusal_reason(error) == "isolation_root_invalid"


def test_a_local_root_still_dials_this_modules_unix_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dials: list[str] = []

    async def connect_control() -> ControlStream:
        dials.append("unix")
        raise ConnectionError

    with ambient_home(monkeypatch):
        monkeypatch.setattr(client_module, "connect_control", connect_control)
        transport = client_module._control_transport()  # pyright: ignore[reportPrivateUsage]
        assert transport.target is None
        with pytest.raises(ConnectionError):
            asyncio.run(transport.connect())  # type: ignore[arg-type]
    assert dials == ["unix"]


def test_remote_root_paths_stay_beneath_the_target_root(remote: ServerTarget) -> None:
    from finishup.config.paths import runtime_dir

    root = targets.target_root(remote.target_id)
    assert runtime_dir() == root / "run"
    assert Path(root / "run").is_dir()


def test_a_serving_binding_claims_the_workspace_and_offers_the_agent(
    remote: ServerTarget, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    taps: list[TapStream] = []

    async def dial() -> ControlStream:
        client_end, server_end = memory_pair()
        tap = TapStream(server_end)
        taps.append(tap)
        asyncio.get_running_loop().create_task(_serve(tap))
        return client_end

    _use(monkeypatch, _FakeTransport(remote, dial))

    async def exercise() -> str:
        binding = await client_module.serving_workspace_binding(WorkspaceLocator(str(tmp_path)))
        assert binding is not None and binding.agent is not None
        # The foundation's claim, under this target's own salt: the worktree it serves included.
        salt = base64.b64decode(cast(str, remote.claim_salt))
        assert binding.claim.worktree == worktree_digest(os.path.normpath(tmp_path), salt)
        client = await client_module.connect_service(
            ControlClientKind.MCP_BRIDGE, workspace_binding=binding
        )
        try:
            await client.connect()
        finally:
            await client.close()
        return client.workspace_binding

    assert asyncio.run(exercise()) == "client_claim"
    (tap,) = taps
    assert b'"workspace_claim"' in tap.received
    assert b'"workspace_agent"' in tap.received
    assert os.fsencode(tmp_path) not in tap.received


def test_a_local_root_has_no_serving_binding(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    with ambient_home(monkeypatch):
        binding = asyncio.run(
            client_module.serving_workspace_binding(WorkspaceLocator(str(tmp_path)))
        )
    assert binding is None
    assert asyncio.run(client_module.serving_workspace_binding(None)) is None


@pytest.mark.parametrize(
    ("state", "reason", "expected"),
    [
        # A hard lock needs the owner on the server: not retryable, as the service would say.
        (ServiceState.LOCKED, "passphrase_required", ("vault_locked", False, None)),
        # A soft lock re-opens on the next request: retryable, as the service would say.
        (ServiceState.LOCKED, "idle_relock", ("vault_locked", True, None)),
        # A service still starting or already stopping is retried as not running.
        (
            ServiceState.DRAINING,
            "none",
            ("service_unavailable", True, "remote_service_not_running"),
        ),
        # A ready service that keyed nothing does not speak this protocol.
        (ServiceState.READY, "none", ("service_unavailable", False, "remote_incompatible")),
    ],
)
def test_a_claim_the_server_did_not_key_is_refused_at_connect(
    remote: ServerTarget,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    state: ServiceState,
    reason: str,
    expected: tuple[str, bool, str | None],
) -> None:
    # ADR-051: a claim-bound connection with no handle could not name its workspace, serve as
    # an agent or route a hook row, so it is never handed out; the caller gets the server's own
    # reason (a locked vault, most often) instead of a misleading workspace_ref refusal later.
    status = replace(service_status(), state=state, state_reason=reason, vault_mode="passphrase")
    taps: list[TapStream] = []

    async def dial() -> ControlStream:
        client_end, server_end = memory_pair()
        tap = TapStream(server_end)
        taps.append(tap)
        asyncio.get_running_loop().create_task(_serve(tap, status=status, keyed=False))
        return client_end

    _use(monkeypatch, _FakeTransport(remote, dial))

    async def exercise() -> ControlError:
        with pytest.raises(ControlError) as raised:
            await client_module.connect_service(
                ControlClientKind.MCP_BRIDGE, workspace_locator=WorkspaceLocator(str(tmp_path))
            )
        return raised.value

    error = asyncio.run(exercise())
    assert (error.reason, error.retryable, error.phase) == expected
    (tap,) = taps
    assert b'"workspace_claim"' in tap.received
    assert os.fsencode(tmp_path) not in tap.received


def test_a_connection_without_a_workspace_needs_no_handle(
    remote: ServerTarget, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A locked server still answers what needs no workspace (service status, say).
    async def dial() -> ControlStream:
        client_end, server_end = memory_pair()
        asyncio.get_running_loop().create_task(_serve(server_end, keyed=False))
        return client_end

    _use(monkeypatch, _FakeTransport(remote, dial))

    async def exercise() -> str:
        client = await client_module.connect_service(ControlClientKind.CLI)
        try:
            await client.service_status()
        finally:
            await client.close()
        return client.workspace_binding

    assert asyncio.run(exercise()) == "none"


def test_the_retryable_lock_reasons_are_the_services_own() -> None:
    from finishup.service import daemon

    assert client_module._RETRYABLE_LOCK_REASONS == (  # pyright: ignore[reportPrivateUsage]
        daemon._SOFT_LOCK_AUTO_READY_REASONS | {"none"}  # pyright: ignore[reportPrivateUsage]
    )
