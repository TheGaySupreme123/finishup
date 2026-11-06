"""A remote target end to end through the server-native network API (ADR-051, approach C).

The server is a real daemon with a real vault and the real ready composition
(``test_claim_bound_sessions``) whose own network API (``NetworkApiServer``, wired by
``ServiceDaemon._network_api_bindings``) listens on loopback TCP, or on its owner-only API socket
for an SSH target. The client is this machine's real code: a selected remote target root, the
``connect_service`` seam (which claims the workspace and never sends its path), the
``RestServiceClient``, the hook pass's own drain, and the pull-based workspace agent
(``WorkspaceAgentLoop``) running the real ``WorkspaceAgentHandler`` on a temporary Git
repository and delivering its captured observation in the background. Only the agent's process
spawn is replaced (the loop runs in this process), the approved-check sandbox is the unit seam the
approved-check tests use (this container has none), and the SSH master is not started (the API
socket is bound where the master would forward it).

Spies on the server's own local workspace readers prove they never see a remote task's workspace,
and a recording transport proves no request the client sent carries the repository's path.
"""

from __future__ import annotations

import asyncio
import io
import json
import threading
import time
from collections.abc import AsyncIterator, Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

import httpx
import pytest

from builders.server_targets import ambient_home
from finishup.adapters.integrations.codex_lifecycle import mapping_from_start_ids, store_mapping
from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.application.observation_check_policy import load_observation_check_policy
from finishup.cli.observe_hooks import handle_observe
from finishup.cli.render import render_human_receipt
from finishup.client import agent as agent_module
from finishup.client import rest_client as rest_client_module
from finishup.client import targets
from finishup.client.agent import WorkspaceAgentLoop
from finishup.client.attribution import connection_attribution
from finishup.client.rest_client import RestEndpoint, RestServiceClient
from finishup.client.targets import ServerTarget
from finishup.client.workspace_agent import WorkspaceAgentHandler, client_protected_directories
from finishup.client.workspace_ref import WorkspaceRefNotPortable, start_request_for_connection
from finishup.config.models import NetworkListenAddress
from finishup.config.paths import reset_selection_memo
from finishup.domain.receipts import (
    CLIENT_ATTESTED_OBSERVATION_LINE,
    CLIENT_ATTESTED_WORKSPACE_LINE,
)
from finishup.ports.change_capture import decode_task_change_base
from finishup.ports.control import (
    ControlClientKind,
    ControlError,
    WorkspaceAgentDeclaration,
    WorkspaceCall,
    WorkspaceLocator,
    WorkspaceReply,
)
from finishup.ports.runtime import RouteAccess, RouteCommand, RuntimeCapability
from finishup.ports.workspace_agent import ReadTextBeneathArguments, WorkspaceOperation
from finishup.protocol.ids import IdKind, new_id
from finishup.protocol.models import (
    CheckRequest,
    PublishWorkRequest,
    ReceiptRequest,
    RespondRequest,
    StartRequest,
    StatusRequest,
)
from finishup.protocol.recovery import continuation_for_reason
from finishup.service import client as service_client
from finishup.service.api_keys import ApiKeyStore
from finishup.service.http_api import NetworkApiServer
from integration.service import test_claim_bound_sessions as sessions
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

_HOST_SESSION = "codex-network-session-1"
# Waits observe real state (the hub's registry, the agent's call log, the client's outbox, the
# server's answers) and fail on this deadline; nothing sleeps to infer success.
_DEADLINE_SECONDS = 30.0
_OBSERVATION_ACTOR = "yoetz:observation-coordinator"
_APPROVED_CHECK_ACTOR = "yoetz:approved-check-service"


async def _until(condition: Callable[[], bool]) -> None:
    deadline = time.monotonic() + _DEADLINE_SECONDS
    while not condition():
        assert time.monotonic() < deadline, "deadline passed before the state was observed"
        await asyncio.sleep(0.02)


# --- the client machine: a selected remote target, a repository, an agent ------------------------


class _RecordingTransport(httpx.AsyncHTTPTransport):
    """The client's real HTTP transport, with every request it sent kept for inspection."""

    def __init__(self, sent: list[bytes], **options: Any) -> None:  # noqa: ANN401
        super().__init__(retries=0, **options)
        self._sent = sent

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        body = await request.aread()
        self._sent.append(
            request.url.raw_path + b"\n" + b"\n".join(k + b": " + v for k, v in request.headers.raw)
        )
        self._sent.append(body)
        return await super().handle_async_request(request)


class _Agent:
    """The real workspace agent's handler, with the operations it answered recorded in order.

    ``drop_on`` names an operation at which the client machine goes away: the agent loop is
    stopped (its registration ends with ``DELETE /v1/agents/{id}``) while that call is in flight.
    """

    def __init__(self, handler: WorkspaceAgentHandler, *, drop_on: str | None = None) -> None:
        self._handler = handler
        self._drop_on = drop_on
        self.operations: list[str] = []
        self.on_drop: Callable[[], None] | None = None
        self.released = threading.Event()

    @property
    def declaration(self) -> WorkspaceAgentDeclaration:
        return self._handler.declaration

    def answer(self, call: WorkspaceCall, *, workspace_handle: str | None) -> WorkspaceReply:
        self.operations.append(call.operation)
        if call.operation == self._drop_on and self.on_drop is not None:
            self.on_drop()
            # The machine is gone: this reply is never sent.
            self.released.wait(_DEADLINE_SECONDS)
        return self._handler.answer(call, workspace_handle=workspace_handle)


@dataclass
class _Remote:
    """The client side of one remote target: its record, root, and in-process agent."""

    record: ServerTarget
    root: Path
    sent: list[bytes] = field(default_factory=list[bytes])
    agents: dict[str, _Agent] = field(default_factory=dict[str, _Agent])
    drop_on: str | None = None
    # A claimed path whose agent answers from another checkout: the decoy setup (see below).
    answer_from: dict[str, Path] = field(default_factory=dict[str, Path])
    ensured: list[Path] = field(default_factory=list[Path])
    loop: WorkspaceAgentLoop | None = None
    running: asyncio.Task[int] | None = None

    @property
    def state(self) -> Path:
        return self.root / "state"

    def handler(self, locator: WorkspaceLocator, root: Path) -> _Agent:
        answers = self.answer_from.get(locator.path)
        handler = WorkspaceAgentHandler(
            locator if answers is None else WorkspaceLocator(str(answers.resolve())),
            protected=(*client_protected_directories(), str(root)),
            check_sandbox=_ReadySandbox(),
        )
        agent = _Agent(handler, drop_on=self.drop_on)
        self.agents[locator.path] = agent
        return agent

    def start_agent(self) -> WorkspaceAgentLoop:
        loop = WorkspaceAgentLoop(
            self.root, self.record, handler_factory=self.handler, scan_seconds=0.05
        )
        self.loop = loop
        self.running = asyncio.create_task(loop.run())
        return loop

    async def stop_agent(self) -> None:
        if self.loop is not None and self.running is not None:
            self.loop.stop()
            for agent in self.agents.values():
                agent.released.set()
            assert await asyncio.wait_for(self.running, _DEADLINE_SECONDS) == 0

    def assert_no_path_sent(self, *paths: str) -> None:
        assert self.sent
        for path in paths:
            assert all(path.encode() not in item for item in self.sent), path


@pytest.fixture
def remote(monkeypatch: pytest.MonkeyPatch) -> Iterator[_Remote]:
    """An HTTPS target selected on this machine, its agent spawn captured, no local spawn."""

    with ambient_home(monkeypatch):
        with targets.registry_lock():
            record, root = targets.new_remote_target("lab", "https", base_url="https://lab.example")
            targets.write_selection(record)
        reset_selection_memo()
        remote = _Remote(record, root)

        def ensure(at: Path) -> bool:
            remote.ensured.append(at)
            return False

        def no_spawn() -> object:
            raise AssertionError("a remote target never spawns a local service")

        monkeypatch.setattr(agent_module, "ensure_agent", ensure)
        monkeypatch.setattr(service_client, "_spawn_service_process", no_spawn)
        yield remote


@pytest.fixture
async def network(
    service: _Service,  # noqa: F811
    remote: _Remote,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> AsyncIterator[NetworkApiServer]:
    """The daemon's own network API on loopback, and the client's endpoint for the target."""

    keys_dir = tmp_path / "network-keys"
    keys_dir.mkdir(mode=0o700)
    keys = ApiKeyStore(keys_dir)
    _key, token = keys.create("laptop", "agent")
    server = NetworkApiServer.bind_addresses(
        (NetworkListenAddress("127.0.0.1", 0),), keys=keys, tls=None, runtime=None
    )
    await server.start(service.daemon._network_api_bindings())  # pyright: ignore[reportPrivateUsage]
    port = server.tcp_ports[0]

    def endpoint_for(record: ServerTarget, root: Path) -> RestEndpoint:
        # The target record's own endpoint, reached here over plain loopback HTTP (the TLS
        # trust paths are covered by ``test_network_api_listeners``) with a recorded transport.
        assert record.target_id == remote.record.target_id and root == remote.root
        return RestEndpoint(
            "https", f"http://127.0.0.1:{port}", _RecordingTransport(remote.sent), token
        )

    monkeypatch.setattr(rest_client_module, "rest_endpoint_for", endpoint_for)
    try:
        yield server
    finally:
        await remote.stop_agent()
        await server.close()


# --- the client's requests -------------------------------------------------------------------


async def _connect(path: str, kind: ControlClientKind = ControlClientKind.CLI) -> RestServiceClient:
    client = await service_client.connect_service_on_demand(
        kind, workspace_locator=WorkspaceLocator(path)
    )
    assert type(client) is RestServiceClient
    return client


async def _started(client: RestServiceClient, path: str, hub: Any) -> Any:  # noqa: ANN401
    handle = client.workspace_handle
    assert client.workspace_binding == "client_claim" and handle is not None
    # The agent registers the workspace the connect seam noted: wait for the hub to see it.
    await _until(lambda: hub.has_agent(handle))
    request = StartRequest.model_validate(
        {
            **_COMMON,
            "request_id": new_id(IdKind.REQUEST),
            "mode": "create",
            "task_title": "Change the client's app module",
            "requested_view": "compact",
            "workspace_ref": path,
            "external_ref": "network-api-task",
        }
    )
    started = (await client.start(start_request_for_connection(request, client))).root
    assert started.ok is True, started
    return started


async def _receipt(client: RestServiceClient, started: Any, frontier: Any) -> Any:  # noqa: ANN401
    receipt = (
        await client.receipt(
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


async def _status(client: RestServiceClient, started: Any, view: str = "compact") -> Any:  # noqa: ANN401
    status = (
        await client.status(
            StatusRequest.model_validate(
                {
                    **_COMMON,
                    "request_id": new_id(IdKind.REQUEST),
                    "session_id": started.session_id,
                    "writer_id": started.writer_id,
                    "view": view,
                    "limit": "50" if view == "history" else "10",
                }
            )
        )
    ).root
    assert status.ok is True, status
    return status


async def _task_base_ref(service: _Service, started: Any) -> Any:  # noqa: F811, ANN401
    """The task's recorded change-base reference, or None when its base could not be read."""

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
        return await runtime.ledger.load_task_change_base()
    finally:
        await application.runtime.release(runtime)


async def _task_base_commit(service: _Service, started: Any) -> str:  # noqa: F811, ANN401
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
        chunks: list[bytes] = [chunk async for chunk in runtime.objects.open_verified(ref)]
        return decode_task_change_base(b"".join(chunks)).commit
    finally:
        await application.runtime.release(runtime)


# --- the workflow ----------------------------------------------------------------------------


async def test_a_remote_task_runs_its_whole_workflow_through_the_network_api_and_its_agent(
    tmp_path: Path,
    spy: _Spy,  # noqa: F811
    service: _Service,  # noqa: F811
    remote: _Remote,
    network: NetworkApiServer,
) -> None:
    del network
    # The decoy: a repository at the very path this client claims, readable by the server's
    # process. The agent answers from the client's own checkout elsewhere, so a server that read
    # the claimed path itself would record the decoy's commit instead of the client's.
    claimed = tmp_path / "work" / "repo"
    decoy_head = _repository(claimed, "decoy.py", "print('decoy')\n")
    repo = tmp_path / "client" / "repo"
    head = _repository(repo, "app.py", "print('client')\n")
    (repo / "app.py").write_text("print('client, edited')\n")
    assert head != decoy_head
    path = str(claimed.resolve())
    remote.answer_from[path] = repo
    remote.start_agent()
    client = await _connect(path, ControlClientKind.MCP_BRIDGE)
    try:
        # The connect seam noted the workspace for the agent and asked for the agent once.
        assert remote.ensured == [remote.root]
        started = await _started(client, path, service.hub)
        frontier = started.frontier
        for request_id, drafts in _publish_batches():
            published = (
                await client.publish_work(
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
            await client.check(
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
        assert not any("workspace_agent" in gap for gap in checked.coverage.known_gaps), (
            checked.coverage.known_gaps
        )
        frontier = checked.result_frontier
        assert checked.findings, checked
        responded = (
            await client.respond(
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
        receipt = await _receipt(client, started, responded.result_frontier)

        # Every workspace fact came from the agent, which read the client's repository.
        agent = remote.agents[path]
        assert {"read_task_base", "capture_metadata"} <= set(agent.operations), agent.operations
        assert await _task_base_commit(service, started) == head
        # The server's own adapters were never handed this task's workspace in any form.
        assert all(
            path not in entry and str(repo.resolve()) not in entry for entry in spy.workspaces
        ), spy.workspaces
        handle = cast(str, client.workspace_handle)
        assert all(handle not in entry for entry in spy.workspaces), spy.workspaces
        # The receipt says, in fixed words, where the evidence came from and who served it; the
        # client adds how it reached that service (``https``, a closed token).
        assert receipt.human_text is not None
        assert CLIENT_ATTESTED_WORKSPACE_LINE in receipt.human_text
        assert f"Served by FinishUP service {client.service_instance_id}" in receipt.human_text
        attribution = connection_attribution(client)
        assert attribution is not None and attribution.transport == "https"
        rendered = render_human_receipt(receipt, attribution=attribution)
        assert (
            f"This client reached FinishUP service {client.service_instance_id} (transport: https)."
        ) in rendered
        assert path not in rendered and path not in receipt.human_text
        # No request this client sent carried either path, in a body or a header.
        remote.assert_no_path_sent(path, str(repo.resolve()))
    finally:
        await client.close()


async def test_a_start_naming_a_path_is_never_sent_to_a_remote_server(
    tmp_path: Path,
    service: _Service,  # noqa: F811
    remote: _Remote,
    network: NetworkApiServer,
) -> None:
    del network, service
    repo = tmp_path / "client" / "repo"
    _repository(repo, "app.py", "print('client')\n")
    path = str(repo.resolve())
    client = await _connect(path)
    try:
        sent = len(remote.sent)
        request = StartRequest.model_validate(
            {
                **_COMMON,
                "request_id": new_id(IdKind.REQUEST),
                "mode": "create",
                "task_title": "Change the client's app module",
                "requested_view": "compact",
                "workspace_ref": path,
                "external_ref": "network-api-task",
            }
        )
        with pytest.raises(WorkspaceRefNotPortable):
            # A caller that skipped the handle rewrite: refused here, nothing is sent.
            await client.start(request)
        assert len(remote.sent) == sent
    finally:
        await client.close()
    remote.assert_no_path_sent(path)


# --- linked worktrees: one repository, one target, one handle and one agent per worktree --------


async def _published_and_checked(client: RestServiceClient, started: Any) -> Any:  # noqa: ANN401
    frontier = started.frontier
    for request_id, drafts in _publish_batches():
        published = (
            await client.publish_work(
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
        await client.check(
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
    assert not any("workspace_agent" in gap for gap in checked.coverage.known_gaps), (
        checked.coverage.known_gaps
    )
    return checked


async def test_linked_worktrees_on_one_target_each_get_their_own_handle_agent_and_evidence(
    tmp_path: Path,
    spy: _Spy,  # noqa: F811
    service: _Service,  # noqa: F811
    remote: _Remote,
    network: NetworkApiServer,
) -> None:
    """Two linked worktrees of one repository, one remote target, the daemon's own API.

    Both worktrees claim the same repository, so their tasks share its commitment (privacy
    authority and consent scope); each claim also carries its own worktree digest in the
    ``X-FinishUP-Workspace-Claim`` header, so the service derives one handle per worktree, the one
    pull agent registers each worktree under its own handle, and every workspace call for a task
    is answered from that task's own worktree alone.

    The main checkout's task base is its HEAD. The linked worktree's base is that worktree's own
    answer: the local Git capture refuses a checkout whose ``.git`` is a file (``unsafe_root``),
    on one computer exactly as here, so its task records the gap and never the main HEAD.
    """

    del network
    main = tmp_path / "client" / "repo"
    main_head = _repository(main, "app.py", "print('main')\n")
    linked = tmp_path / "client" / "feature"
    _git(main, "worktree", "add", "-q", "-b", "feature", str(linked))
    (linked / "feature.py").write_text("print('feature')\n")
    _git(linked, "add", "feature.py")
    _git(linked, "commit", "-q", "-m", "feature")
    assert _git(linked, "rev-parse", "HEAD") != main_head
    (main / "app.py").write_text("print('main, edited')\n")
    (linked / "feature.py").write_text("print('feature, edited')\n")
    main_path, linked_path = str(main.resolve()), str(linked.resolve())
    remote.start_agent()
    main_client = await _connect(main_path, ControlClientKind.MCP_BRIDGE)
    linked_client = await _connect(linked_path, ControlClientKind.MCP_BRIDGE)
    try:
        main_handle = main_client.workspace_handle
        linked_handle = linked_client.workspace_handle
        assert main_handle is not None and linked_handle is not None
        assert main_handle != linked_handle
        main_started = await _started(main_client, main_path, service.hub)
        linked_started = await _started(linked_client, linked_path, service.hub)
        main_agent, linked_agent = remote.agents[main_path], remote.agents[linked_path]
        # Each task's base was asked of its own worktree's agent, once.
        assert main_agent.operations.count("read_task_base") == 1, main_agent.operations
        assert linked_agent.operations.count("read_task_base") == 1, linked_agent.operations
        assert await _task_base_commit(service, main_started) == main_head
        assert await _task_base_ref(service, linked_started) is None

        # A reviewer's read of one task's file is answered from that task's worktree.
        async def read(handle: str, relative: str) -> bytes | None:
            answer = await service.hub.call(
                handle,
                WorkspaceOperation.READ_TEXT_BENEATH,
                ReadTextBeneathArguments(handle, relative),
                timeout_seconds=_DEADLINE_SECONDS,
            )
            return None if answer is None else cast(tuple[bytes, int], answer)[0]

        assert await read(main_handle, "app.py") == b"print('main, edited')\n"
        assert await read(linked_handle, "app.py") == b"print('main')\n"
        assert await read(linked_handle, "feature.py") == b"print('feature, edited')\n"
        assert not await read(main_handle, "feature.py")

        # A check's workspace calls go to its own worktree's agent and to no other.
        main_count, linked_count = len(main_agent.operations), len(linked_agent.operations)
        await _published_and_checked(main_client, main_started)
        assert "capture_metadata" in main_agent.operations[main_count:], main_agent.operations
        assert len(linked_agent.operations) == linked_count, linked_agent.operations
        main_count = len(main_agent.operations)
        await _published_and_checked(linked_client, linked_started)
        assert len(linked_agent.operations) > linked_count, linked_agent.operations
        assert len(main_agent.operations) == main_count, main_agent.operations

        # One repository: both tasks share its commitment.
        application = cast(Any, service.daemon._application)  # pyright: ignore[reportPrivateUsage]
        routes = [
            await application.start_catalog.task_route(main_started.task_id),
            await application.start_catalog.task_route(linked_started.task_id),
        ]
        commitments = {route.repository_privacy_commitment for route in routes}
        assert len(commitments) == 1 and None not in commitments
        # The claim header carried two digests and never a path; one repository digest, two
        # worktree digests. The server's own readers saw neither worktree.
        claims = {
            line.split(b": ", 1)[1]
            for item in remote.sent
            for line in item.split(b"\n")
            if line.lower().startswith(b"x-finishup-workspace-claim: ")
        }
        assert len(claims) == 2, claims
        assert len({claim.rsplit(b":sha256:", 1)[0] for claim in claims}) == 1
        remote.assert_no_path_sent(main_path, linked_path)
        assert spy.workspaces == []
    finally:
        await main_client.close()
        await linked_client.close()


# --- AI-powered review: the reviewer's reads go to the REST agent, and its loss is typed ------


async def _reviewed_agent_handle(
    tmp_path: Path,
    service: _Service,  # noqa: F811
    remote: _Remote,
) -> tuple[str, str]:
    work = _reviewed_repository(tmp_path)
    path = str(work.resolve())
    remote.start_agent()
    client = await _connect(path)
    try:
        handle = client.workspace_handle
        assert handle is not None
        await _until(lambda: service.hub.has_agent(handle))
    finally:
        await client.close()
    return path, handle


async def test_the_reviewers_reads_are_answered_by_the_rest_workspace_agent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    service: _Service,  # noqa: F811
    remote: _Remote,
    network: NetworkApiServer,
) -> None:
    from integration.service import test_reviewer_conversation_composition as reviewer

    del network
    path, handle = await _reviewed_agent_handle(tmp_path, service, remote)
    # The reviewer harness of ``test_claim_bound_sessions``, bound to this agent's handle.
    monkeypatch.setattr(sessions, "_HANDLE", handle)
    result, gateway = await sessions._review(  # pyright: ignore[reportPrivateUsage]
        tmp_path,
        monkeypatch,
        service.hub,
        reviewer._read_file("calc.py"),  # pyright: ignore[reportPrivateUsage]
        reviewer._read_file("secret.txt"),  # pyright: ignore[reportPrivateUsage]
        reviewer._FINAL,  # pyright: ignore[reportPrivateUsage]
    )
    assert result.status.value == "succeeded", (result.status, result.reason)
    _first, _, last = (history for _, history in gateway.exchanges)
    observation = json.loads(last[4][1])
    assert observation["status"] == "ok" and "return a + b" in observation["data"]["text"]
    denied = json.loads(last[6][1])
    assert (denied["status"], denied["reason"]) == ("denied", "forbidden_path")
    operations = remote.agents[path].operations
    assert {"probe_requested_paths", "read_text_beneath"} <= set(operations), operations
    remote.assert_no_path_sent(path)


async def test_an_agent_lost_mid_review_ends_the_review_unavailable_never_a_pass(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    service: _Service,  # noqa: F811
    remote: _Remote,
    network: NetworkApiServer,
) -> None:
    from integration.service import test_reviewer_conversation_composition as reviewer

    del network
    remote.drop_on = "read_text_beneath"
    path, handle = await _reviewed_agent_handle(tmp_path, service, remote)
    agent = remote.agents[path]
    event_loop = asyncio.get_running_loop()
    loop = remote.loop
    assert loop is not None

    def drop() -> None:
        event_loop.call_soon_threadsafe(loop.stop)

    agent.on_drop = drop
    monkeypatch.setattr(sessions, "_HANDLE", handle)
    result, gateway = await sessions._review(  # pyright: ignore[reportPrivateUsage]
        tmp_path,
        monkeypatch,
        service.hub,
        reviewer._read_file("calc.py"),  # pyright: ignore[reportPrivateUsage]
        reviewer._FINAL,  # pyright: ignore[reportPrivateUsage]
    )
    agent.released.set()
    assert result.status.value == "unavailable", (result.status, result.reason)
    assert result.judgment is None
    assert result.reviewer is not None
    assert result.reviewer.ended == "workspace_agent_unavailable"
    # The judgment the provider would have given was never asked for.
    assert len(gateway.exchanges) == 1
    assert not service.hub.has_agent(handle)


# --- observation: a hook's row is claim-bound, attested, and verified through the agent -------


class _Workspace:
    """The client's repository with an approved check, and its store under the target root."""

    def __init__(self, tmp_path: Path, remote: _Remote) -> None:
        self.repo = tmp_path / "client" / "repo"
        _repository(self.repo, "app.py", "print('client')\n")
        (self.repo / ".finishup").mkdir()
        (self.repo / ".finishup" / "checks.toml").write_text(_POLICY, encoding="utf-8")
        self.path = str(self.repo.resolve())
        self.state = remote.state
        self.store = LocalObservationStore(_state=self.state)
        self.workspace = self.store.workspace_commitment(self.path)
        self.store.grant_consent(self.workspace)
        policy, _raw = load_observation_check_policy(self.repo)
        self.store.trust_policy_digest(self.workspace, policy.raw_digest)

    def map(self, started: Any) -> None:  # noqa: ANN401
        store_mapping(
            mapping_from_start_ids(
                codex_session_id=_HOST_SESSION,
                finishup_task_id=started.task_id,
                finishup_session_id=started.session_id,
                finishup_writer_id=started.writer_id,
                last_frontier=None,
            ),
            _state=self.state,
        )

    def hook(self, payload: dict[str, object], *, skip_service: bool) -> None:
        """One Codex ``PostToolUse`` hook pass on the client, run as a hook process runs it."""

        handle_observe(
            event_name="PostToolUse",
            stdin_bytes=json.dumps({"session_id": _HOST_SESSION, **payload}).encode(),
            stdout=io.BytesIO(),
            workspace=self.path,
            _state=self.state,
            skip_service=skip_service,
        )


async def _history_until(
    client: RestServiceClient,
    started: Any,  # noqa: ANN401
    condition: Callable[[tuple[Any, ...]], bool],
) -> tuple[Any, ...]:
    deadline = time.monotonic() + _DEADLINE_SECONDS
    while True:
        status = await _status(client, started, "history")
        items: tuple[Any, ...] = tuple(status.page.items)
        if condition(items):
            return items
        assert time.monotonic() < deadline, "deadline passed before the history was observed"
        await asyncio.sleep(0.05)


async def test_a_hook_pass_delivers_its_row_attested_and_the_agent_verifies_it(
    tmp_path: Path,
    spy: _Spy,  # noqa: F811
    service: _Service,  # noqa: F811
    remote: _Remote,
    network: NetworkApiServer,
    local_reads: list[str],  # noqa: F811
) -> None:
    del network
    workspace = _Workspace(tmp_path, remote)
    remote.start_agent()
    client = await _connect(workspace.path)
    try:
        started = await _started(client, workspace.path, service.hub)
        workspace.map(started)
        (workspace.repo / "app.py").write_text("print('client, edited')\n")
        # The hook process: capture, then its own drain over a claim-bound connection (it runs
        # its own event loop, as a hook does, so it runs in a worker thread here).
        await asyncio.to_thread(
            workspace.hook,
            {"tool_name": "shell", "exit_status": 1, "correlation_id": "c-1", "event_ordinal": 2},
            skip_service=False,
        )
        await _until(lambda: workspace.store.pending_outbox_count(workspace.workspace) == 0)
        agent = remote.agents[workspace.path]
        # Verification ran on the client through the REST agent; the server read nothing itself.
        await _until(lambda: "run_approved_check" in agent.operations)
        assert {"open_workspace", "load_check_policy", "subject_state_capture"} <= set(
            agent.operations
        )
        assert local_reads == []
        assert spy.workspaces == []
        history = await _history_until(
            client,
            started,
            lambda items: any(item.actor_id == _APPROVED_CHECK_ACTOR for item in items),
        )
        assert any(
            item.actor_id == _OBSERVATION_ACTOR and item.publication_channel == "hook_observed"
            for item in history
        )
        status = await _status(client, started)
        receipt = await _receipt(client, started, status.head_frontier)
        assert CLIENT_ATTESTED_WORKSPACE_LINE in receipt.human_text
        assert CLIENT_ATTESTED_OBSERVATION_LINE in receipt.human_text
        assert workspace.path not in receipt.human_text
        remote.assert_no_path_sent(workspace.path)
    finally:
        await client.close()


async def test_rows_a_hook_could_not_send_are_delivered_by_the_agent_in_the_background(
    tmp_path: Path,
    service: _Service,  # noqa: F811
    remote: _Remote,
    network: NetworkApiServer,
) -> None:
    del network
    workspace = _Workspace(tmp_path, remote)
    client = await _connect(workspace.path)
    try:
        remote.start_agent()
        started = await _started(client, workspace.path, service.hub)
        workspace.map(started)
        # The hook could not reach the server: its row stays in this client's outbox.
        workspace.hook(
            {"tool_name": "shell", "exit_status": 0, "event_ordinal": 2}, skip_service=True
        )
        assert workspace.store.pending_outbox_count(workspace.workspace) >= 1
        # The agent's background delivery sends it, attested, over its own claim-bound client.
        await _until(lambda: workspace.store.pending_outbox_count(workspace.workspace) == 0)
        history = await _history_until(
            client,
            started,
            lambda items: any(
                item.actor_id == _OBSERVATION_ACTOR and item.publication_channel == "hook_observed"
                for item in items
            ),
        )
        assert history
        remote.assert_no_path_sent(workspace.path)
    finally:
        await client.close()


# --- upstream loss: a typed remote phase, never a local service ------------------------------


async def test_losing_the_server_is_a_typed_remote_phase_and_never_starts_a_local_service(
    tmp_path: Path,
    service: _Service,  # noqa: F811
    remote: _Remote,
    network: NetworkApiServer,
) -> None:
    workspace = _Workspace(tmp_path, remote)
    client = await _connect(workspace.path)
    remote.start_agent()
    try:
        started = await _started(client, workspace.path, service.hub)
        workspace.map(started)
        await network.close()
        with pytest.raises(ControlError) as live:
            await _status(client, started)
        assert (live.value.reason, live.value.phase) == (
            "service_unavailable",
            "remote_unreachable",
        )
        with pytest.raises(ControlError) as fresh:
            await _connect(workspace.path)
        assert (fresh.value.reason, fresh.value.phase) == (
            "service_unavailable",
            "remote_unreachable",
        )
        # Every surface resolves the phase to the same ADR-030 directive.
        assert continuation_for_reason("remote_unreachable") == "remote_server_test"
        # A hook pass meanwhile keeps its row pending (never quarantined, never sent elsewhere).
        await asyncio.to_thread(
            workspace.hook,
            {"tool_name": "shell", "exit_status": 0, "event_ordinal": 2},
            skip_service=False,
        )
        assert workspace.store.pending_outbox_count(workspace.workspace) >= 1
    finally:
        await client.close()


# --- SSH: the same API over the owner-only socket the master forwards -------------------------


@pytest.fixture
def ssh_remote(monkeypatch: pytest.MonkeyPatch) -> Iterator[_Remote]:
    """An SSH target selected on this machine; its master is not started (see the module)."""

    from finishup.client.rest_runtime import SshTargetRuntime

    with ambient_home(monkeypatch):
        with targets.registry_lock():
            record, root = targets.new_remote_target(
                "lab", "ssh", user="srv", host="127.0.0.1", port=2222
            )
            targets.write_selection(record)
        reset_selection_memo()
        remote = _Remote(record, root)

        def ensure(at: Path) -> bool:
            remote.ensured.append(at)
            return False

        def no_spawn() -> object:
            raise AssertionError("a remote target never spawns a local service")

        def master(_self: object, _record: object, _root: object, **_options: object) -> None:
            return None

        monkeypatch.setattr(agent_module, "ensure_agent", ensure)
        monkeypatch.setattr(service_client, "_spawn_service_process", no_spawn)
        monkeypatch.setattr(SshTargetRuntime, "ensure_master", master)
        yield remote


async def test_an_ssh_target_runs_the_workflow_over_the_forwarded_api_socket(
    tmp_path: Path,
    spy: _Spy,  # noqa: F811
    service: _Service,  # noqa: F811
    ssh_remote: _Remote,
) -> None:
    keys_dir = tmp_path / "network-keys"
    keys_dir.mkdir(mode=0o700)
    # The server's API socket, bound where this client's SSH master forwards ``run/api.sock``.
    (ssh_remote.root / "run").mkdir(mode=0o700, exist_ok=True)
    server = NetworkApiServer.bind_addresses(
        (), keys=ApiKeyStore(keys_dir), tls=None, runtime=ssh_remote.root / "run"
    )
    await server.start(service.daemon._network_api_bindings())  # pyright: ignore[reportPrivateUsage]
    repo = tmp_path / "client" / "repo"
    head = _repository(repo, "app.py", "print('client')\n")
    (repo / "app.py").write_text("print('client, edited')\n")
    path = str(repo.resolve())
    ssh_remote.start_agent()
    try:
        client = await _connect(path)
        try:
            assert client.transport == "ssh"
            started = await _started(client, path, service.hub)
            checked = (
                await client.check(
                    CheckRequest.model_validate(
                        {
                            **_COMMON,
                            "request_id": new_id(IdKind.REQUEST),
                            "session_id": started.session_id,
                            "writer_id": started.writer_id,
                            "expected_frontier": _frontier(started.frontier),
                            "mode": "deterministic_only",
                            "max_findings": "3",
                        }
                    )
                )
            ).root
            assert checked.ok is True, checked
            assert await _task_base_commit(service, started) == head
            assert "read_task_base" in ssh_remote.agents[path].operations
            assert spy.workspaces == []
            attribution = connection_attribution(client)
            assert attribution is not None and attribution.transport == "ssh"
        finally:
            await client.close()
    finally:
        await ssh_remote.stop_agent()
        await server.close()
