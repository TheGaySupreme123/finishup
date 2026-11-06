"""A remote target end to end through the edge relay (ADR-051, approach A).

Everything a client machine runs is real here: the selected remote target root and its claim
salt, the connect seam (``connect_service`` claims the workspace and records the claim), the
``ServiceClient`` answering workspace calls with the real ``WorkspaceAgentHandler`` on a temporary
git repository, and the ``Connector`` serving the target's ``control.sock``. Upstream of the
connector is the server: the real in-memory daemon with a real vault and the real ready
composition (``test_claim_bound_sessions``), reached

* for ``ssh`` through the connector's own ``SshMaster`` driving an ``ssh`` stand-in that forwards
  ``run/upstream.sock`` to the daemon's endpoint, byte for byte;
* for ``https`` through the connector's HTTPS binding v1 relay to the real gateway application
  (``httpx.ASGITransport``), which maps the session onto one daemon connection.

The server never reads the workspace: spies on its local adapters stay empty, and a decoy
repository at the claimed path is never touched. What the server could not reach is a typed
outcome, and a lost upstream is a remote phase with no local service started.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import io
import json
import os
import socket
import time
from collections.abc import AsyncGenerator, Callable, Iterator
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, ClassVar, Literal, cast

import httpx
import pytest

import finishup.client.workspace_agent as workspace_agent_module
from builders.control_relay import write_fake_ssh
from builders.server_targets import ambient_home
from finishup.adapters.control.unix_socket import (
    AuthenticatedUnixStream,
    authenticate_peer,
    bind_control_listener,
)
from finishup.adapters.integrations.codex_lifecycle import mapping_from_start_ids, store_mapping
from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.application.observation_check_policy import load_observation_check_policy
from finishup.cli.observe_hooks import handle_observe
from finishup.client import targets
from finishup.client.attribution import attribution_lines, connection_attribution
from finishup.client.connector import Connector
from finishup.client.workspace_agent import WorkspaceAgentHandler
from finishup.client.workspace_claim import workspace_claim
from finishup.client.workspace_ref import start_request_for_connection
from finishup.config.paths import selection_override
from finishup.domain.receipts import (
    CLIENT_ATTESTED_OBSERVATION_LINE,
    CLIENT_ATTESTED_WORKSPACE_LINE,
)
from finishup.gateway.app import build_gateway_app
from finishup.gateway.keys import create_key
from finishup.ports.control import (
    ControlClientKind,
    ControlError,
    WorkspaceCall,
    WorkspaceLocator,
    WorkspaceReply,
)
from finishup.protocol.canonical import JsonValue
from finishup.protocol.errors import REMOTE_CONNECTION_PHASES
from finishup.protocol.ids import IdKind, new_id
from finishup.protocol.models import (
    CheckRequest,
    PublishWorkRequest,
    ReceiptRequest,
    RespondRequest,
    StartRequest,
    StatusRequest,
)
from finishup.service import client as service_client
from finishup.service.client import ClientWorkspaceBinding, ServiceClient, connect_service
from integration.service.test_claim_bound_observation import (  # noqa: F401 - fixtures
    _POLICY,  # pyright: ignore[reportPrivateUsage]
    _ReadySandbox,  # pyright: ignore[reportPrivateUsage]
    local_reads,  # pyright: ignore[reportUnusedImport]
)
from integration.service.test_claim_bound_sessions import (  # noqa: F401 - fixtures
    _COMMON,  # pyright: ignore[reportPrivateUsage]
    _frontier,  # pyright: ignore[reportPrivateUsage]
    _git,  # pyright: ignore[reportPrivateUsage]
    _publish_batches,  # pyright: ignore[reportPrivateUsage]
    _repository,  # pyright: ignore[reportPrivateUsage]
    _review,  # pyright: ignore[reportPrivateUsage]
    _reviewed_repository,  # pyright: ignore[reportPrivateUsage]
    _Service,  # pyright: ignore[reportPrivateUsage]
    _Spy,  # pyright: ignore[reportPrivateUsage]
    service,  # pyright: ignore[reportUnusedImport]
    spy,  # pyright: ignore[reportUnusedImport]
)
from integration.service.test_ready_composition import (  # noqa: F401 - autouse SQLite policy
    _sqlite_policy,  # pyright: ignore[reportPrivateUsage, reportUnusedImport]
)

pytestmark = pytest.mark.anyio

_DEADLINE_SECONDS = 30.0
_HOST_SESSION = "codex-remote-session-a"
_OBSERVATION_ACTOR = "yoetz:observation-coordinator"
_APPROVED_CHECK_ACTOR = "yoetz:approved-check-service"

type Kind = Literal["ssh", "https"]


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as root:
        yield root


@pytest.fixture
def no_local_service(monkeypatch: pytest.MonkeyPatch) -> list[Path]:
    """No local service is ever started for a remote root; connector starts are recorded."""

    def refuse(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("a remote root never starts or supersedes a local service")

    spawned: list[Path] = []

    def spawn(root: Path) -> None:
        spawned.append(root)

    monkeypatch.setattr(service_client, "_spawn_service_process", refuse)
    monkeypatch.setattr(service_client, "supersede_incompatible_service", refuse)
    monkeypatch.setattr("finishup.client.connector_status.spawn_connector", spawn)
    return spawned


class _RecordingHandler(WorkspaceAgentHandler):
    """The real workspace agent, recording the operations it answered (both its connections).

    Approved checks run through the unit sandbox seam the approved-check adapter tests use; the
    sandbox's enforcement has its own tests.
    """

    operations: ClassVar[list[str]] = []
    on_operation: ClassVar[Callable[[str], None] | None] = None

    def __init__(self, workspace: WorkspaceLocator, **options: Any) -> None:  # noqa: ANN401
        options.setdefault("check_sandbox", _ReadySandbox())
        super().__init__(workspace, **options)

    def answer(self, call: WorkspaceCall, *, workspace_handle: str | None) -> WorkspaceReply:
        type(self).operations.append(call.operation)
        hook = type(self).on_operation
        if hook is not None:
            hook(call.operation)
        return super().answer(call, workspace_handle=workspace_handle)


@pytest.fixture
def agents(monkeypatch: pytest.MonkeyPatch) -> type[_RecordingHandler]:
    """Every agent the client side builds is the recording one, with a fresh log per test."""

    class Recording(_RecordingHandler):
        operations: ClassVar[list[str]] = []
        on_operation: ClassVar[Callable[[str], None] | None] = None

    monkeypatch.setattr(workspace_agent_module, "WorkspaceAgentHandler", Recording)
    return Recording


# --- the topology: client root -> connector -> (ssh | https gateway) -> daemon -------------------


async def _serve_daemon_socket(path: Path, service: _Service) -> asyncio.Task[None]:  # noqa: F811
    """The server host's control endpoint: an owner-only socket served by the real daemon."""

    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    previous = os.umask(0o177)
    try:
        listener.bind(str(path))
    finally:
        os.umask(previous)
    listener.listen(16)
    listener.setblocking(False)
    loop = asyncio.get_running_loop()
    served: set[asyncio.Task[None]] = set()

    async def accept() -> None:
        try:
            while True:
                accepted, _address = await loop.sock_accept(listener)
                stream = AuthenticatedUnixStream(accepted, authenticate_peer(accepted))
                task = asyncio.create_task(
                    service.daemon._serve_control_connection(stream)  # pyright: ignore[reportPrivateUsage]
                )
                served.add(task)
                task.add_done_callback(served.discard)
        finally:
            listener.close()
            with contextlib.suppress(FileNotFoundError):
                path.unlink()
            for task in tuple(served):
                task.cancel()
            await asyncio.gather(*served, return_exceptions=True)

    return asyncio.create_task(accept())


class _Audit:
    def write(self, record: dict[str, JsonValue]) -> None:
        del record


@dataclass
class _Topology:
    """One remote target root on this "client machine" and its relay to the "server"."""

    kind: Kind
    root: Path
    connector: Connector
    serving: asyncio.Task[str]
    upstream: asyncio.Task[None] | None

    async def lose_upstream(self) -> None:
        """The server host goes away: its endpoint and every connection to it end."""

        if self.upstream is not None:
            self.upstream.cancel()
            await asyncio.gather(self.upstream, return_exceptions=True)

    async def stop(self) -> None:
        self.connector.request_stop()
        async with asyncio.timeout(_DEADLINE_SECONDS):
            await asyncio.gather(self.serving, return_exceptions=True)
        await self.lose_upstream()


@contextlib.asynccontextmanager
async def _topology(
    kind: Kind,
    home: Path,
    service: _Service,  # noqa: F811
    *,
    drain_interval: float = 30.0,
    background_agents: bool = True,
) -> AsyncGenerator[_Topology]:
    upstream: asyncio.Task[None] | None = None
    with targets.registry_lock():
        if kind == "ssh":
            record, root = targets.new_remote_target(
                "lab", "ssh", host="lab.example", port=22, remote_launcher="/bin/false"
            )
        else:
            record, root = targets.new_remote_target("gw", "https", base_url="https://gw.example")
    options: dict[str, Any] = {"drain_interval": drain_interval}
    if not background_agents:

        async def no_agent(*_args: object) -> None:
            return None

        options["agent_opener"] = no_agent
    if kind == "ssh":
        endpoint = home / "srv.sock"
        upstream = await _serve_daemon_socket(endpoint, service)
        record = replace(record, remote_endpoint=str(endpoint))
        ssh = write_fake_ssh(home / "bin")
        connector = Connector(root, record, ssh=str(ssh), **options)
    else:
        keys = home / "gateway"
        _key_record, key = create_key(keys, label="e2e", scope="agent")

        async def connect_upstream() -> object:
            ours, theirs = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
            served = AuthenticatedUnixStream(theirs, authenticate_peer(theirs))
            service.tasks.append(
                asyncio.create_task(
                    service.daemon._serve_control_connection(served)  # pyright: ignore[reportPrivateUsage]
                )
            )
            return AuthenticatedUnixStream(ours, authenticate_peer(ours))

        _state, app = build_gateway_app(
            keys_directory=keys,
            connect_upstream=connect_upstream,  # type: ignore[arg-type]
            audit=_Audit(),
        )
        connector = Connector(
            root,
            record,
            https_transport=httpx.ASGITransport(app=app),
            credential=lambda: key,
            **options,
        )
    with selection_override(root):
        listener = await bind_control_listener()
        serving = asyncio.create_task(connector.serve(listener))
        topology = _Topology(kind, root, connector, serving, upstream)
        try:
            yield topology
        finally:
            await topology.stop()
            ssh_master = connector._ssh  # pyright: ignore[reportPrivateUsage]
            if ssh_master is not None:
                with contextlib.suppress(Exception):
                    await ssh_master.close()


async def _connect(repo: Path) -> ServiceClient:
    """What the CLI, the menu, the terminal interface and the MCP bridge do for this root."""

    return await connect_service(
        ControlClientKind.CLI,
        workspace_locator=WorkspaceLocator(str(repo.resolve())),
        serve_workspace=True,
    )


def _client_repository(tmp_path: Path) -> tuple[Path, str]:
    repo = tmp_path / "client" / "repo"
    head = _repository(repo, "app.py", "print('client')\n")
    (repo / ".finishup").mkdir()
    (repo / ".finishup" / "checks.toml").write_text(_POLICY, encoding="utf-8")
    _git(repo, "add", ".finishup/checks.toml")
    _git(repo, "commit", "-q", "-m", "approved checks")
    return repo, _git(repo, "rev-parse", "HEAD") or head


async def _start(connection: ServiceClient, repo: Path, external_ref: str) -> Any:  # noqa: ANN401
    request = StartRequest.model_validate(
        {
            **_COMMON,
            "request_id": new_id(IdKind.REQUEST),
            "mode": "create",
            "task_title": "Change the client's app module",
            "requested_view": "compact",
            # Written as an agent would; the client sends the connection's handle instead.
            "workspace_ref": str(repo.resolve()),
            "external_ref": external_ref,
        }
    )
    started = (await connection.start(start_request_for_connection(request, connection))).root
    assert started.ok is True, started
    return started


async def _receipt(connection: ServiceClient, started: Any, frontier: Any) -> Any:  # noqa: ANN401
    receipt = (
        await connection.receipt(
            ReceiptRequest.model_validate(
                {
                    **_COMMON,
                    "request_id": new_id(IdKind.REQUEST),
                    "session_id": started.session_id,
                    "writer_id": started.writer_id,
                    "task_id": started.task_id,
                    "expected_frontier": _frontier(frontier),
                    "format": "text",
                    "include": "standard",
                    "redaction_profile": "full_local",
                }
            )
        )
    ).root
    assert receipt.ok is True, receipt
    return receipt


async def _status(connection: ServiceClient, started: Any, view: str = "compact") -> Any:  # noqa: ANN401
    status = (
        await connection.status(
            StatusRequest.model_validate(
                {
                    **_COMMON,
                    "request_id": new_id(IdKind.REQUEST),
                    "session_id": started.session_id,
                    "writer_id": started.writer_id,
                    "view": view,
                    "limit": "50",
                }
            )
        )
    ).root
    assert status.ok is True, status
    return status


async def _recorded_base(service: _Service, started: Any) -> str:  # noqa: ANN401, F811
    """The commit the server recorded as the task's change base."""

    from finishup.ports.change_capture import decode_task_change_base
    from finishup.ports.runtime import RouteAccess, RouteCommand, RuntimeCapability

    application = cast(Any, service.daemon._application)  # pyright: ignore[reportPrivateUsage]
    runtime = await application.runtime.route(
        RouteCommand(
            started.session_id,
            started.writer_id,
            RouteAccess.WRITE,
            frozenset({RuntimeCapability.WRITE, RuntimeCapability.PAYLOAD_READ}),
        )
    )
    try:
        ref = await runtime.ledger.load_task_change_base()
        assert ref is not None
        chunks = [chunk async for chunk in runtime.objects.open_verified(ref)]
        return decode_task_change_base(b"".join(chunks)).commit
    finally:
        await application.runtime.release(runtime)


async def _until(condition: Callable[[], bool]) -> None:
    deadline = time.monotonic() + _DEADLINE_SECONDS
    while not condition():
        assert time.monotonic() < deadline, "deadline passed before the state was observed"
        await asyncio.sleep(0.02)


# --- the whole workflow -------------------------------------------------------------------------


@pytest.mark.parametrize("kind", ["ssh", "https"])
async def test_a_remote_task_runs_its_whole_workflow_through_the_connector(
    kind: Kind,
    tmp_path: Path,
    home: Path,
    spy: _Spy,  # noqa: F811
    service: _Service,  # noqa: F811
    agents: type[_RecordingHandler],
    no_local_service: list[Path],
) -> None:
    repo, head = _client_repository(tmp_path)
    (repo / "app.py").write_text("print('client, edited')\n")
    async with _topology(kind, home, service) as topology:
        connection = await _connect(repo)
        try:
            handle = connection.workspace_handle
            assert connection.workspace_binding == "client_claim"
            assert handle is not None and handle.startswith("client:")
            assert connection.transport == "connector"
            # The claim was recorded for the connector, on this machine only.
            index = topology.root / "state" / "claimed-workspaces"
            assert len(list(index.iterdir())) == 1

            started = await _start(connection, repo, f"connector-{kind}")
            frontier = started.frontier
            for request_id, drafts in _publish_batches():
                published = (
                    await connection.publish_work(
                        PublishWorkRequest.model_validate(
                            {
                                **_COMMON,
                                "request_id": request_id,
                                "session_id": started.session_id,
                                "writer_id": started.writer_id,
                                "expected_frontier": _frontier(frontier),
                                "event_drafts": drafts,
                            }
                        )
                    )
                ).root
                assert published.ok is True, published
                frontier = published.result_frontier
            checked: Any = (
                await connection.check(
                    CheckRequest.model_validate(
                        {
                            **_COMMON,
                            "request_id": new_id(IdKind.REQUEST),
                            "session_id": started.session_id,
                            "writer_id": started.writer_id,
                            "expected_frontier": _frontier(frontier),
                            "mode": "deterministic_only",
                            "max_findings": "3",
                        }
                    )
                )
            ).root
            assert checked.ok is True, checked
            # The check-time change came from the client's workspace: no agent gap was recorded.
            assert not any(
                "workspace_agent_unavailable" in gap for gap in checked.coverage.known_gaps
            ), checked.coverage.known_gaps
            frontier = checked.result_frontier
            assert checked.findings, checked
            responded = (
                await connection.respond(
                    RespondRequest.model_validate(
                        {
                            **_COMMON,
                            "request_id": new_id(IdKind.REQUEST),
                            "session_id": started.session_id,
                            "writer_id": started.writer_id,
                            "expected_frontier": _frontier(frontier),
                            "finding_id": checked.findings[0].finding_id,
                            "finding_frontier": _frontier(frontier),
                            "disposition": "acknowledged",
                            "reason": "The remaining verification follows in a later batch.",
                        }
                    )
                )
            ).root
            assert responded.ok is True, responded
            receipt = await _receipt(connection, started, responded.result_frontier)
            recorded_base = await _recorded_base(service, started)
        finally:
            await connection.close()

    # Every workspace fact was read on the client by its agent, through the relay.
    assert {"read_task_base", "capture_metadata"} <= set(agents.operations), agents.operations
    assert spy.workspaces == [], spy.workspaces
    # The receipt says where the evidence came from and who served it, in fixed words.
    text = receipt.human_text
    assert type(text) is str and CLIENT_ATTESTED_WORKSPACE_LINE in text
    attribution = connection_attribution(connection)
    assert attribution is not None and attribution.transport == "connector"
    lines = attribution_lines(attribution, shown=text)
    assert lines == (
        f"This client reached FinishUP service {connection.service_instance_id} "
        "(transport: connector).",
    )
    assert str(repo) not in text and str(tmp_path) not in text
    # The task base the server recorded is the client's HEAD, read by the agent.
    assert recorded_base == head
    assert no_local_service == []


async def test_a_decoy_at_the_claimed_path_is_never_read(
    tmp_path: Path,
    home: Path,
    spy: _Spy,  # noqa: F811
    service: _Service,  # noqa: F811
    no_local_service: list[Path],
) -> None:
    """The claim names the decoy's path; only the client's agent answers, from its own repo."""

    decoy = tmp_path / "work" / "repo"
    decoy_head = _repository(decoy, "decoy.py", "print('decoy')\n")
    client_repo, client_head = _client_repository(tmp_path)
    assert decoy_head != client_head
    async with _topology("ssh", home, service, background_agents=False) as topology:
        record = targets.read_target(topology.root)
        assert record is not None and record.claim_salt is not None
        claim = await workspace_claim(
            WorkspaceLocator(str(decoy.resolve())), base64.b64decode(record.claim_salt)
        )
        binding = ClientWorkspaceBinding(
            claim,
            WorkspaceAgentHandler(WorkspaceLocator(str(client_repo.resolve()))),
        )
        connection = await connect_service(ControlClientKind.CLI, workspace_binding=binding)
        try:
            started = await _start(connection, decoy, "connector-decoy")
            assert await _recorded_base(service, started) == client_head
        finally:
            await connection.close()
    assert spy.workspaces == [], spy.workspaces
    # A claim the client never recorded leaves the connector's index empty.
    assert not (topology.root / "state" / "claimed-workspaces").exists()


# --- AI-powered review: reads through the relay, and the client going away ---------------------


@pytest.mark.parametrize("kind", ["ssh", "https"])
async def test_the_reviewers_reads_reach_the_client_workspace_through_the_connector(
    kind: Kind,
    tmp_path: Path,
    home: Path,
    monkeypatch: pytest.MonkeyPatch,
    service: _Service,  # noqa: F811
    agents: type[_RecordingHandler],
    no_local_service: list[Path],
) -> None:
    from integration.service import test_reviewer_conversation_composition as reviewer

    work = _reviewed_repository(tmp_path)
    async with _topology(kind, home, service) as _topology_value:
        connection = await _connect(work)
        try:
            handle = connection.workspace_handle
            assert handle is not None
            result, gateway = await _review(
                tmp_path,
                monkeypatch,
                service.hub,
                reviewer._read_file("calc.py"),  # pyright: ignore[reportPrivateUsage]
                reviewer._read_file("secret.txt"),  # pyright: ignore[reportPrivateUsage]
                reviewer._FINAL,  # pyright: ignore[reportPrivateUsage]
                handle=handle,
            )
        finally:
            await connection.close()
    assert result.status.value == "succeeded", (result.status, result.reason)
    _first, _, last = (history for _, history in gateway.exchanges)
    observation = json.loads(last[4][1])
    assert observation["status"] == "ok" and "return a + b" in observation["data"]["text"]
    denied = json.loads(last[6][1])
    assert (denied["status"], denied["reason"]) == ("denied", "forbidden_path")
    assert {"capture", "probe_requested_paths", "read_text_beneath"} <= set(agents.operations)


async def test_the_client_machine_going_away_mid_review_is_the_typed_unavailable(
    tmp_path: Path,
    home: Path,
    monkeypatch: pytest.MonkeyPatch,
    service: _Service,  # noqa: F811
    agents: type[_RecordingHandler],
    no_local_service: list[Path],
) -> None:
    """The connector and the client both drop while the reviewer's read is in flight."""

    from integration.service import test_reviewer_conversation_composition as reviewer

    work = _reviewed_repository(tmp_path)
    loop = asyncio.get_running_loop()
    async with _topology("ssh", home, service) as topology:
        connection = await _connect(work)
        handle = connection.workspace_handle
        assert handle is not None
        gone = asyncio.Event()

        def go_away(operation: str) -> None:
            if operation != "read_text_beneath":
                return
            # This machine disappears: its relay stops and every connection through it ends.
            loop.call_soon_threadsafe(topology.connector.request_stop)
            loop.call_soon_threadsafe(gone.set)
            time.sleep(1.0)

        agents.on_operation = go_away
        try:
            result, gateway = await _review(
                tmp_path,
                monkeypatch,
                service.hub,
                reviewer._read_file("calc.py"),  # pyright: ignore[reportPrivateUsage]
                reviewer._FINAL,  # pyright: ignore[reportPrivateUsage]
                handle=handle,
            )
        finally:
            agents.on_operation = None
            await connection.close()
    assert gone.is_set()
    assert result.status.value == "unavailable", (result.status, result.reason)
    assert result.judgment is None
    assert result.reviewer is not None
    assert result.reviewer.ended == "workspace_agent_unavailable"
    # The judgment the provider would have given was never asked for.
    assert len(gateway.exchanges) == 1


# --- observation: a hook row, drained and verified by the connector's background agent ----------


async def test_a_hook_row_is_drained_by_the_connector_and_verified_by_its_agent(
    tmp_path: Path,
    home: Path,
    spy: _Spy,  # noqa: F811
    service: _Service,  # noqa: F811
    agents: type[_RecordingHandler],
    no_local_service: list[Path],
    local_reads: list[str],  # noqa: F811
) -> None:
    repo, _head = _client_repository(tmp_path)
    path = str(repo.resolve())
    async with _topology("ssh", home, service, drain_interval=0.2) as topology:
        state = topology.root / "state"
        store = LocalObservationStore(_state=state)
        workspace = store.workspace_commitment(path)
        store.grant_consent(workspace)
        policy, _raw = load_observation_check_policy(repo)
        store.trust_policy_digest(workspace, policy.raw_digest)

        connection = await _connect(repo)
        try:
            started = await _start(connection, repo, "connector-observation")
        finally:
            await connection.close()
        # What the SessionStart auto-attach stores after a remote start.
        store_mapping(
            mapping_from_start_ids(
                codex_session_id=_HOST_SESSION,
                finishup_task_id=started.task_id,
                finishup_session_id=started.session_id,
                finishup_writer_id=started.writer_id,
                last_frontier=None,
            ),
            _state=state,
        )
        # The client's own connection is gone; only the connector's background agent is left.
        handle = connection.workspace_handle
        assert handle is not None
        await _until(lambda: service.hub.has_agent(handle))
        agents.operations.clear()

        (repo / "app.py").write_text("print('client, edited')\n")
        handle_observe(
            event_name="PostToolUse",
            stdin_bytes=json.dumps(
                {
                    "session_id": _HOST_SESSION,
                    "tool_name": "shell",
                    "exit_status": 1,
                    "correlation_id": "remote-cmd-a",
                    "event_ordinal": 2,
                }
            ).encode(),
            stdout=io.BytesIO(),
            workspace=path,
            _state=state,
            skip_service=True,
        )
        assert store.pending_outbox_count(workspace) >= 1
        # The connector delivers the row over its agent connection; the server verifies it by
        # running the approved check through that same agent.
        await _until(lambda: store.pending_outbox_count(workspace) == 0)
        await _until(lambda: "run_approved_check" in agents.operations)
        assert {"open_workspace", "load_check_policy", "subject_state_capture"} <= set(
            agents.operations
        )

        reader = await _connect(repo)
        try:
            deadline = time.monotonic() + _DEADLINE_SECONDS
            while True:
                history = await _status(reader, started, "history")
                items = tuple(history.page.items)
                if any(item.actor_id == _APPROVED_CHECK_ACTOR for item in items):
                    break
                assert time.monotonic() < deadline, [
                    (item.actor_id, item.publication_channel) for item in items
                ]
                await asyncio.sleep(0.05)
            assert any(
                item.actor_id == _OBSERVATION_ACTOR and item.publication_channel == "hook_observed"
                for item in items
            )
            status = await _status(reader, started)
            receipt = await _receipt(reader, started, status.head_frontier)
        finally:
            await reader.close()
    text = receipt.human_text
    assert type(text) is str
    assert CLIENT_ATTESTED_WORKSPACE_LINE in text and CLIENT_ATTESTED_OBSERVATION_LINE in text
    assert path not in text
    assert local_reads == [] and spy.workspaces == []


# --- the upstream lost: a typed remote phase, never a local service ------------------------------


async def test_losing_the_server_is_a_remote_phase_and_never_a_local_service(
    tmp_path: Path,
    home: Path,
    service: _Service,  # noqa: F811
    agents: type[_RecordingHandler],
    no_local_service: list[Path],
) -> None:
    del agents
    repo, _head = _client_repository(tmp_path)
    async with _topology("ssh", home, service) as topology:
        connection = await _connect(repo)
        try:
            await connection.service_status()
            await topology.lose_upstream()
            await connection.wait_closed()
            with pytest.raises(ControlError) as lost:
                await connection.service_status()
        finally:
            await connection.close()
        # A new connection finds the server's endpoint gone; the connector tries the server's own
        # start once (``/bin/false`` here), then names the phase.
        with pytest.raises(ControlError) as refused:
            await _connect(repo)
    assert (lost.value.reason, lost.value.phase) == ("service_unavailable", "remote_unreachable")
    assert refused.value.reason == "service_unavailable"
    assert refused.value.phase in REMOTE_CONNECTION_PHASES
    assert refused.value.phase == "remote_service_not_running"
    # The relay was already running; nothing was started on this machine, and no local service.
    assert no_local_service == []
