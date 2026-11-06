"""A remote target root in ``service.client`` (ADR-051, approach A).

A selected remote target is reached through its connector: on demand the client starts the
connector (never ``service run``) and never supersedes anything; the hello names no path; a
connection the connector closed is named by the connector's status (a closed remote phase),
never by the local service stamp; a lockstep mismatch is ``remote_incompatible``; and the MCP
availability latch keys on the connector's status generation. Local roots are untouched. The
CLI and the MCP bridge render a remote phase with its recovery directive, with no host, name or
local-service remedy.
"""

from __future__ import annotations

import asyncio
import json
import os
from collections.abc import Iterator
from pathlib import Path
from typing import cast

import pytest

from builders.control_relay import ScriptedDaemon, service_status
from builders.server_targets import ambient_home
from finishup.adapters.control.unix_socket import (
    AuthenticatedUnixStream,
    UnixEndpointListener,
    bind_control_listener,
)
from finishup.client import targets
from finishup.client.connector_status import (
    ConnectorLock,
    new_status,
    now_stamp,
    write_connector_status,
)
from finishup.config.paths import reset_selection_memo
from finishup.ports.control import ControlClientKind, ControlError, WorkspaceLocator
from finishup.protocol.canonical import JsonValue
from finishup.service import client as service_client
from finishup.service.control_protocol import (
    encode_control_frame,
    read_control_frame,
)


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as root:
        yield root


@pytest.fixture
def remote(home: Path) -> Path:
    with targets.registry_lock():
        record, root = targets.new_remote_target(
            "lab", "ssh", host="lab.example", port=22, remote_launcher="/opt/fu/bin/finishup"
        )
        targets.write_selection(record)
    reset_selection_memo()
    return root


@pytest.fixture
def no_local_service(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("a remote root never starts or supersedes a local service")

    monkeypatch.setattr(service_client, "_spawn_service_process", refuse)
    monkeypatch.setattr(service_client, "supersede_incompatible_service", refuse)


async def _serve(listener: UnixEndpointListener, handle: object) -> None:
    try:
        while True:
            stream = await listener.accept()
            asyncio.get_running_loop().create_task(handle(stream))  # type: ignore[operator]
    except Exception:
        return


def _fake_connector(
    monkeypatch: pytest.MonkeyPatch, handle: object, spawned: list[Path]
) -> list[asyncio.Task[None]]:
    """``spawn_connector`` binds the root's endpoint in-process and serves it with ``handle``."""

    tasks: list[asyncio.Task[None]] = []

    def spawn(root: Path) -> object:
        spawned.append(root)

        async def run() -> None:
            listener = await bind_control_listener()
            try:
                await _serve(listener, handle)
            finally:
                await listener.aclose()

        tasks.append(asyncio.get_running_loop().create_task(run()))
        return None

    monkeypatch.setattr("finishup.client.connector_status.spawn_connector", spawn)
    return tasks


def _stop(tasks: list[asyncio.Task[None]]) -> None:
    for task in tasks:
        task.cancel()


def test_local_roots_keep_todays_path(home: Path) -> None:
    assert service_client._remote_target_root() is None  # pyright: ignore[reportPrivateUsage]
    with targets.registry_lock():
        record, _root = targets.new_local_target("work")
        targets.write_selection(record)
    reset_selection_memo()
    assert service_client._remote_target_root() is None  # pyright: ignore[reportPrivateUsage]


def test_on_demand_starts_the_connector_and_sends_no_path(
    remote: Path, monkeypatch: pytest.MonkeyPatch, no_local_service: None
) -> None:
    daemon = ScriptedDaemon()
    spawned: list[Path] = []

    async def exercise() -> None:
        tasks = _fake_connector(monkeypatch, daemon.serve, spawned)
        try:
            client = await service_client.connect_service_on_demand(
                ControlClientKind.CLI,
                workspace_locator=WorkspaceLocator(path=str(remote.parent / "repo")),
                timeout_seconds=10.0,
            )
            try:
                status = await client.service_status()
            finally:
                await client.close()
        finally:
            _stop(tasks)
        assert status.service_instance_id == service_status().service_instance_id

    asyncio.run(exercise())
    assert spawned == [remote]
    hello = json.loads(daemon.received(0)[0])
    assert "workspace_locator" not in hello and "workspace_claim" not in hello


def _closing_connector(root: Path, reason: str) -> object:
    async def handle(stream: AuthenticatedUnixStream) -> None:
        await read_control_frame(stream)
        status = new_status(None, "unavailable", reason, started_at=now_stamp())
        write_connector_status(
            root,
            type(status)(
                status.generation,
                status.phase,
                status.reason,
                "err_00000000-0000-4000-8000-0000000000e1",
                status.pid,
                status.started_at,
            ),
        )
        await stream.aclose()

    return handle


@pytest.mark.parametrize(
    "reason",
    [
        "remote_auth_failed",
        "remote_identity_changed",
        "remote_unreachable",
        "remote_service_not_running",
    ],
)
def test_a_refused_connection_is_named_by_the_connector_status(
    remote: Path,
    monkeypatch: pytest.MonkeyPatch,
    no_local_service: None,
    reason: str,
) -> None:
    spawned: list[Path] = []

    async def exercise() -> ControlError:
        tasks = _fake_connector(monkeypatch, _closing_connector(remote, reason), spawned)
        try:
            with pytest.raises(ControlError) as raised:
                await service_client.connect_service_on_demand(
                    ControlClientKind.MCP_BRIDGE, timeout_seconds=10.0
                )
            return raised.value
        finally:
            _stop(tasks)

    error = asyncio.run(exercise())
    # Every remote phase is retryable once its own repair is made (INTERFACES, ADR-051).
    assert (error.reason, error.phase, error.retryable) == ("service_unavailable", reason, True)
    assert error.correlation_id == "err_00000000-0000-4000-8000-0000000000e1"


def test_a_server_of_another_release_is_remote_incompatible_never_superseded(
    remote: Path, monkeypatch: pytest.MonkeyPatch, no_local_service: None
) -> None:
    async def other_release(stream: AuthenticatedUnixStream) -> None:
        from finishup.service import control_protocol

        await read_control_frame(stream)
        answer = control_protocol._hello_result_wire(  # pyright: ignore[reportPrivateUsage]
            service_status(),
            control_protocol._allowed_for(ControlClientKind.CLI),  # pyright: ignore[reportPrivateUsage]
        )
        answer["schema_manifest_digest"] = "sha256:" + "0" * 64
        await stream.send_all(encode_control_frame(answer))
        await stream.aclose()

    spawned: list[Path] = []

    async def exercise() -> ControlError:
        tasks = _fake_connector(monkeypatch, other_release, spawned)
        try:
            with pytest.raises(ControlError) as raised:
                await service_client.connect_service_on_demand(
                    ControlClientKind.CLI, timeout_seconds=10.0
                )
            return raised.value
        finally:
            _stop(tasks)

    error = asyncio.run(exercise())
    assert (error.reason, error.phase, error.retryable) == (
        "service_unavailable",
        "remote_incompatible",
        True,
    )


def test_a_connector_of_another_release_is_replaced_by_its_stamped_pid(
    remote: Path, monkeypatch: pytest.MonkeyPatch, no_local_service: None
) -> None:
    lock = ConnectorLock(remote)
    lock.acquire(version="0.0.1", schema_manifest_digest="sha256:" + "a" * 64)
    stopped: list[Path] = []

    def stop(root: Path, *, timeout_seconds: float = 5.0) -> bool:
        del timeout_seconds
        stopped.append(root)
        lock.release()
        return True

    monkeypatch.setattr("finishup.client.connector_status.stop_connector", stop)

    spawned: list[Path] = []
    daemon = ScriptedDaemon()

    async def exercise() -> None:
        tasks = _fake_connector(monkeypatch, daemon.serve, spawned)
        try:
            client = await service_client.connect_service_on_demand(
                ControlClientKind.CLI, timeout_seconds=10.0
            )
            await client.close()
        finally:
            _stop(tasks)

    try:
        asyncio.run(exercise())
    finally:
        lock.release()
    assert stopped == [remote] and spawned == [remote]


def test_a_connector_of_a_newer_release_is_never_replaced(
    remote: Path, monkeypatch: pytest.MonkeyPatch, no_local_service: None
) -> None:
    """A process left from before an in-place upgrade (an open session's bridge) must not stop
    the connector the upgraded clients use; it waits for that connector like any other."""

    lock = ConnectorLock(remote)
    lock.acquire(version="999.0.0", schema_manifest_digest="sha256:" + "b" * 64)

    def stop(root: Path, *, timeout_seconds: float = 5.0) -> bool:
        raise AssertionError("a newer connector is never stopped by an older client")

    spawned: list[Path] = []

    def spawn(root: Path) -> None:
        spawned.append(root)

    monkeypatch.setattr("finishup.client.connector_status.stop_connector", stop)
    monkeypatch.setattr("finishup.client.connector_status.spawn_connector", spawn)
    daemon = ScriptedDaemon()

    async def exercise() -> None:
        async def bind_late() -> None:
            # The newer connector's endpoint is not up when the first attempt is made.
            await asyncio.sleep(0.3)
            listener = await bind_control_listener()
            try:
                await _serve(listener, daemon.serve)
            finally:
                await listener.aclose()

        serving = asyncio.create_task(bind_late())
        try:
            client = await service_client.connect_service_on_demand(
                ControlClientKind.CLI, timeout_seconds=10.0
            )
            await client.close()
        finally:
            serving.cancel()
            await asyncio.gather(serving, return_exceptions=True)

    try:
        asyncio.run(exercise())
    finally:
        lock.release()
    assert spawned == [] and daemon.connections == 1


def test_the_latch_keys_on_the_connector_status_generation(remote: Path) -> None:
    assert service_client.service_holder_identity() is None
    lock = ConnectorLock(remote)
    lock.acquire(version="0.1.0", schema_manifest_digest="sha256:" + "a" * 64)
    try:
        assert service_client.service_holder_identity() is None  # no status yet
        down = new_status(None, "unavailable", "remote_unreachable", started_at=now_stamp())
        write_connector_status(remote, down)
        first = service_client.service_holder_identity()
        assert first is not None and first.pid == os.getpid()
        assert first.instance_id == f"connector-{down.generation}"
        repaired = new_status(down, "ready", None, started_at=down.started_at)
        write_connector_status(remote, repaired)
        second = service_client.service_holder_identity()
        assert second is not None and second.instance_id != first.instance_id
        # The connector carries this installation's identity: never a supersede candidate.
        assert service_client._stamp_identity(second) == "same"  # pyright: ignore[reportPrivateUsage]
    finally:
        lock.release()
    assert service_client.service_holder_identity() is None


@pytest.mark.parametrize(
    "phase",
    [
        "remote_auth_failed",
        "remote_identity_changed",
        "remote_incompatible",
        "remote_service_not_running",
        "remote_unreachable",
    ],
)
def test_cli_and_mcp_render_a_remote_phase_with_its_directive_only(home: Path, phase: str) -> None:
    from finishup.cli.bootstrap import control_failure
    from finishup.mcp import server as bridge
    from finishup.protocol.errors import REASON_CODE_CONTINUATIONS
    from finishup.protocol.recovery import RECOVERY_DIRECTIVES

    error = ControlError(
        "service_unavailable",
        retryable=True,
        phase=phase,
        correlation_id="err_00000000-0000-4000-8000-0000000000e2",
    )
    lines: list[str] = []
    documents: list[JsonValue] = []
    control_failure(
        error, json_output=True, stderr_writer=lines.append, stdout_writer=documents.append
    )
    directive = RECOVERY_DIRECTIVES[REASON_CODE_CONTINUATIONS[phase]]
    text = "\n".join(lines)
    assert phase in text and directive.directive in text
    assert "local" not in lines[0].splitlines()[0]
    for forbidden in ("local terminal", "service restart", "service diagnostics", "lab.example"):
        assert forbidden not in text
    (document,) = documents
    assert cast(dict[str, JsonValue], document)["phase"] == phase

    result = bridge._control_error_result(  # pyright: ignore[reportPrivateUsage]
        error, request_id=None, operation="start"
    )
    structured = cast(dict[str, object], result.structuredContent)
    public = cast(dict[str, object], structured["error"])
    assert public["message"] == directive.directive
    details = cast(dict[str, object], public["safe_details"])
    assert details["reason_code"] == phase
    assert details["continuation"] == REASON_CODE_CONTINUATIONS[phase]
    assert "local" not in cast(str, public["message"]).lower()


def _workspace(home: Path) -> WorkspaceLocator:
    folder = home / "work" / "project"
    folder.mkdir(parents=True, mode=0o700)
    return WorkspaceLocator(path=str(folder))


@pytest.mark.parametrize("serve_workspace", [False, True])
def test_a_remote_connection_claims_its_workspace_and_records_it_for_the_connector(
    remote: Path,
    home: Path,
    monkeypatch: pytest.MonkeyPatch,
    no_local_service: None,
    serve_workspace: bool,
) -> None:
    from finishup.client.claimed_workspaces import claimed_workspace
    from finishup.ports.control import WorkspaceClaim, WorkspaceIdentityKind

    workspace = _workspace(home)
    daemon = ScriptedDaemon()
    spawned: list[Path] = []

    async def exercise() -> None:
        tasks = _fake_connector(monkeypatch, daemon.serve, spawned)
        try:
            # The plain connect starts the client-owned connector too; it is not a service.
            client = await service_client.connect_service(
                ControlClientKind.CLI, workspace_locator=workspace, serve_workspace=serve_workspace
            )
            try:
                assert client.transport == "connector"
                # This scripted server keys no claim (a locked vault answers the same way): the
                # connection is claim-bound without a handle, so no workspace call can name it.
                assert client.workspace_binding == "client_claim"
                assert client.workspace_handle is None
                await client.service_status()
            finally:
                await client.close()
        finally:
            _stop(tasks)

    asyncio.run(exercise())
    assert spawned == [remote]
    raw = daemon.received(0)[0]
    assert workspace.path.encode() not in b"".join(daemon.received(0))
    hello = json.loads(raw)
    assert "workspace_locator" not in hello
    assert ("workspace_agent" in hello) is serve_workspace
    claim = cast(dict[str, str], hello["workspace_claim"])
    kind = cast(WorkspaceIdentityKind, claim["identity_kind"])
    recorded = claimed_workspace(remote, WorkspaceClaim(kind, claim["digest"], claim["worktree"]))
    assert recorded == workspace


def test_an_outage_the_connector_never_named_is_remote_unreachable(
    remote: Path, monkeypatch: pytest.MonkeyPatch, no_local_service: None
) -> None:
    started: list[Path] = []

    def spawn(root: Path) -> None:
        started.append(root)

    monkeypatch.setattr("finishup.client.connector_status.spawn_connector", spawn)

    async def exercise() -> ControlError:
        with pytest.raises(ControlError) as raised:
            await service_client.connect_service_on_demand(
                ControlClientKind.MCP_BRIDGE, timeout_seconds=0.5
            )
        return raised.value

    error = asyncio.run(exercise())
    # Never the local service's remedy: the selected server could not be reached through it.
    assert (error.reason, error.phase, error.retryable) == (
        "service_unavailable",
        "remote_unreachable",
        True,
    )
    assert started == [remote]


def _earlier_failure(root: Path, reason: str) -> None:
    """A phase an earlier connection recorded (and the owner has since repaired)."""

    write_connector_status(root, new_status(None, "unavailable", reason, started_at=now_stamp()))


def test_a_slow_answer_is_waited_for_never_named_by_an_earlier_phase(
    remote: Path, monkeypatch: pytest.MonkeyPatch, no_local_service: None
) -> None:
    """The owner loaded the SSH key after a refusal; the connector is now restarting its master,
    slower than one handshake attempt. The earlier ``remote_auth_failed`` must not end the
    wait."""

    _earlier_failure(remote, "remote_auth_failed")
    monkeypatch.setattr(service_client, "_CONNECT_HANDSHAKE_TIMEOUT_SECONDS", 0.3)
    daemon = ScriptedDaemon()
    held: list[AuthenticatedUnixStream] = []

    async def handle(stream: AuthenticatedUnixStream) -> None:
        if not held:
            held.append(stream)  # the first connection waits on the master: no answer yet
            return
        await daemon.serve(stream)

    spawned: list[Path] = []

    async def exercise() -> None:
        tasks = _fake_connector(monkeypatch, handle, spawned)
        try:
            client = await service_client.connect_service_on_demand(
                ControlClientKind.CLI, timeout_seconds=10.0
            )
            await client.close()
        finally:
            for stream in held:
                await stream.aclose()
            _stop(tasks)

    asyncio.run(exercise())
    assert held and daemon.connections == 1


def test_a_wait_that_ran_out_names_only_a_phase_recorded_during_it(
    remote: Path, monkeypatch: pytest.MonkeyPatch, no_local_service: None
) -> None:
    _earlier_failure(remote, "remote_auth_failed")
    monkeypatch.setattr(service_client, "_CONNECT_HANDSHAKE_TIMEOUT_SECONDS", 0.2)
    held: list[AuthenticatedUnixStream] = []
    record_during_wait: list[str] = []

    async def handle(stream: AuthenticatedUnixStream) -> None:
        held.append(stream)  # accepted, never answered
        if record_during_wait:
            write_connector_status(
                remote,
                new_status(None, "unavailable", record_during_wait[0], started_at=now_stamp()),
            )

    async def exercise() -> ControlError:
        spawned: list[Path] = []
        tasks = _fake_connector(monkeypatch, handle, spawned)
        try:
            with pytest.raises(ControlError) as raised:
                await service_client.connect_service_on_demand(
                    ControlClientKind.CLI, timeout_seconds=1.0
                )
            return raised.value
        finally:
            for stream in held:
                await stream.aclose()
            held.clear()
            _stop(tasks)

    stale = asyncio.run(exercise())
    assert (stale.reason, stale.phase) == ("service_unavailable", "remote_unreachable")
    record_during_wait.append("remote_identity_changed")
    fresh = asyncio.run(exercise())
    assert (fresh.reason, fresh.phase) == ("service_unavailable", "remote_identity_changed")


def test_a_relay_lost_mid_session_names_the_remote_phase(
    remote: Path, monkeypatch: pytest.MonkeyPatch, no_local_service: None
) -> None:
    hangups: list[AuthenticatedUnixStream] = []

    async def hang_up_after_hello(stream: AuthenticatedUnixStream) -> None:
        from finishup.service import control_protocol

        await read_control_frame(stream)
        answer = control_protocol._hello_result_wire(  # pyright: ignore[reportPrivateUsage]
            service_status(),
            control_protocol._allowed_for(ControlClientKind.CLI),  # pyright: ignore[reportPrivateUsage]
            workspace_binding="none",
        )
        await stream.send_all(encode_control_frame(answer))
        hangups.append(stream)

    spawned: list[Path] = []

    async def exercise() -> ControlError:
        tasks = _fake_connector(monkeypatch, hang_up_after_hello, spawned)
        try:
            client = await service_client.connect_service_on_demand(
                ControlClientKind.CLI, timeout_seconds=10.0
            )
            try:
                await hangups[0].aclose()
                await client.wait_closed()
                assert client.closed
                with pytest.raises(ControlError) as raised:
                    await client.service_status()
                return raised.value
            finally:
                await client.close()
        finally:
            _stop(tasks)

    error = asyncio.run(exercise())
    assert (error.reason, error.phase) == ("service_unavailable", "remote_unreachable")


@pytest.mark.parametrize("with_workspace", [True, False])
def test_a_target_confirmed_under_an_older_disclosure_is_never_dialled(
    remote: Path,
    monkeypatch: pytest.MonkeyPatch,
    no_local_service: None,
    with_workspace: bool,
) -> None:
    """Nothing is sent to it, with or without a workspace to claim, until ``server use`` renews."""

    spawned: list[Path] = []
    _fake_connector(monkeypatch, ScriptedDaemon().serve, spawned)
    monkeypatch.setattr(targets, "DISCLOSURE_VERSION", targets.DISCLOSURE_VERSION + 1)
    locator = WorkspaceLocator(path=str(remote.parent / "repo")) if with_workspace else None

    async def exercise() -> None:
        for connect in (service_client.connect_service, service_client.connect_service_on_demand):
            with pytest.raises(ControlError) as refused:
                await connect(ControlClientKind.CLI, workspace_locator=locator)
            error = refused.value
            assert (error.reason, error.phase) == (
                "service_unavailable",
                "target_reauthorization_required",
            )
            assert error.retryable is True

    asyncio.run(exercise())
    assert spawned == []
    assert not (remote / "state" / "claimed-workspaces").exists()


def test_every_folder_of_one_worktree_claims_the_same_worktree(
    remote: Path,
    home: Path,
    monkeypatch: pytest.MonkeyPatch,
    no_local_service: None,
) -> None:
    """A bridge started in a subfolder claims its worktree's top level, as hooks and the CLI do."""

    import subprocess

    from finishup.client.claimed_workspaces import claimed_workspace
    from finishup.ports.control import WorkspaceClaim, WorkspaceIdentityKind

    repository = home / "work" / "repo"
    (repository / "src" / "deep").mkdir(parents=True, mode=0o700)
    subprocess.run(("git", "init", "-q", "-b", "main", str(repository)), check=True)
    daemon = ScriptedDaemon()
    spawned: list[Path] = []

    async def exercise() -> None:
        tasks = _fake_connector(monkeypatch, daemon.serve, spawned)
        try:
            for folder in (repository / "src" / "deep", repository):
                client = await service_client.connect_service(
                    ControlClientKind.CLI, workspace_locator=WorkspaceLocator(path=str(folder))
                )
                await client.close()
        finally:
            _stop(tasks)

    asyncio.run(exercise())
    claims = [
        cast(dict[str, str], json.loads(daemon.received(index)[0])["workspace_claim"])
        for index in (0, 1)
    ]
    assert claims[0] == claims[1]
    kind = cast(WorkspaceIdentityKind, claims[0]["identity_kind"])
    claim = WorkspaceClaim(kind, claims[0]["digest"], claims[0]["worktree"])
    assert claimed_workspace(remote, claim) == WorkspaceLocator(path=str(repository))
