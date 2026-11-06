"""Claim-bound sessions: a client on another machine, its workspace read only by its agent.

ADR-051. A real daemon with a real vault and the real ready composition serves one control
connection, in memory, whose hello claims a workspace instead of naming a path and offers a
workspace agent. A decoy repository sits at the very path the client claims, on this ("server")
machine; the test's agent answers from a different repository. Spies on the server's own local
adapters prove they never see a claim-bound task's workspace, and every workspace fact the
server recorded is the agent's.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import subprocess
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

import pytest

import finishup.application.check_change as check_change_module
import finishup.service.ready_composition as ready_composition_module
from builders.workspace_agent_fake import FakeWorkspaceAgent, fake_declaration
from finishup.adapters.git_change_capture import GitChangeCaptureAdapter
from finishup.adapters.keys.encrypted_vault import EncryptedVaultStore
from finishup.adapters.keys.secret_memory import LocalSecretMemory
from finishup.config.models import FinishUpConfig
from finishup.domain.events import SessionOpenedPayload
from finishup.domain.receipts import CLIENT_ATTESTED_WORKSPACE_LINE
from finishup.ports.change_capture import decode_task_change_base
from finishup.ports.control import (
    ControlCallRequest,
    ControlClientKind,
    ControlError,
    ControlMethod,
    ControlResult,
    ServiceState,
    WorkspaceClaim,
    WorkspaceLocator,
)
from finishup.ports.runtime import RouteAccess, RouteCommand, RuntimeCapability
from finishup.ports.secret_memory import SecretPurpose
from finishup.ports.workspace_agent import (
    WorkspaceAgentUnavailable,
    WorkspaceOnlyArguments,
    WorkspaceOperation,
)
from finishup.protocol.ids import IdKind, new_id
from finishup.protocol.models import (
    CheckRequest,
    PublishWorkRequest,
    ReceiptRequest,
    RespondRequest,
    StartRequest,
)
from finishup.service.control_protocol import (
    ControlProtocolError,
    ControlSession,
    client_handshake,
    is_workspace_call_frame,
    parse_control_result,
    parse_workspace_call,
    read_control_frame,
    write_control_frame,
    write_workspace_reply,
)
from finishup.service.daemon import ServiceComposition, ServiceDaemon
from finishup.service.lifecycle import ServiceLifecycle
from finishup.service.ready_composition import build_ready_application_factory
from finishup.service.vault import VaultMode, VaultService
from finishup.service.workspace_hub import WorkspaceAgentChannel, WorkspaceAgentHub
from integration.service import test_ready_composition as composition
from integration.service.test_ready_composition import (  # noqa: F401 - autouse SQLite policy
    _sqlite_policy,  # pyright: ignore[reportPrivateUsage, reportUnusedImport]
)

pytestmark = pytest.mark.anyio

_INSTALLATION_ID: str = getattr(composition, "_INSTALLATION_ID")
_Clock: Any = getattr(composition, "_Clock")
_GenerationStore: Any = getattr(composition, "_GenerationStore")
_Paths: Any = getattr(composition, "_Paths")
_Diagnostics: Any = getattr(composition, "_Diagnostics")
_Listener: Any = getattr(composition, "_Listener")
_COMMON: dict[str, Any] = {
    "protocol_version": "0.1",
    "schema_version": "1.0.0",
    "actor": {"actor_id": "harness:pytest", "actor_type": "harness"},
    "client": {"kind": "cooperative_agent", "version": "0.1.0", "integration": "cooperative_mcp"},
}


# --- an in-memory control connection that can drop ------------------------------------------


class _Stream:
    def __init__(self, peer_identity: object) -> None:
        self.peer_identity = peer_identity
        self.other: _Stream | None = None
        self._chunks: asyncio.Queue[bytes] = asyncio.Queue()
        self._buffer = bytearray()
        self._eof = False

    async def receive(self, max_bytes: int) -> bytes:
        while not self._buffer:
            if self._eof:
                return b""
            chunk = await self._chunks.get()
            if not chunk:
                self._eof = True
                return b""
            self._buffer.extend(chunk)
        chunk = bytes(self._buffer[:max_bytes])
        del self._buffer[:max_bytes]
        return chunk

    async def send_all(self, data: object) -> None:
        assert self.other is not None
        if self.other._eof:
            raise ConnectionResetError("peer_closed")
        await self.other._chunks.put(bytes(cast(bytes, data)))

    async def aclose(self) -> None:
        if self.other is not None:
            await self.other._chunks.put(b"")
        await self._chunks.put(b"")


def _pair() -> tuple[_Stream, _Stream]:
    client_peer, service_peer = object(), object()
    client, server = _Stream(service_peer), _Stream(client_peer)
    client.other, server.other = server, client
    return client, server


# --- the client side: one connection that calls and answers workspace calls -------------------


@dataclass
class _ClaimClient:
    stream: _Stream
    session: ControlSession
    agent: FakeWorkspaceAgent | None
    pending: dict[str, asyncio.Future[ControlResult]] = field(
        default_factory=dict[str, "asyncio.Future[ControlResult]"]
    )
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    reader: asyncio.Task[None] | None = None
    # The loop keeps only weak references to tasks: each answer in flight is held here until it
    # finishes, and ``close`` cancels and awaits any left.
    answering: set[asyncio.Task[None]] = field(default_factory=set["asyncio.Task[None]"])

    def start(self) -> None:
        self.reader = asyncio.create_task(self._read())

    async def _read(self) -> None:
        try:
            while True:
                frame = await read_control_frame(self.stream)  # pyright: ignore[reportArgumentType]
                if is_workspace_call_frame(frame):
                    assert self.agent is not None
                    task = asyncio.create_task(self._answer(parse_workspace_call(frame)))
                    self.answering.add(task)
                    task.add_done_callback(self.answering.discard)
                    continue
                result = parse_control_result(frame)
                self.session.correlate(result)
                self.pending.pop(result.rpc_id).set_result(result)
        except (ControlProtocolError, ConnectionError):
            for future in self.pending.values():
                if not future.done():
                    future.set_exception(ConnectionError("closed"))

    async def _answer(self, call: Any) -> None:  # noqa: ANN401
        assert self.agent is not None
        reply = await asyncio.to_thread(self.agent.answer, call)
        async with self.lock:
            await write_workspace_reply(self.stream, reply)  # pyright: ignore[reportArgumentType]

    async def call(self, method: ControlMethod, body: Any) -> Any:  # noqa: ANN401
        request = ControlCallRequest(
            kind="call",
            protocol_version="1.0",
            rpc_id=new_id(IdKind.CONTROL_RPC),
            service_instance_id=self.session.service_instance_id,
            service_generation=self.session.service_generation,
            method=method,
            body=body,
        )
        self.session.admit(request)
        future: asyncio.Future[ControlResult] = asyncio.get_running_loop().create_future()
        self.pending[request.rpc_id] = future
        async with self.lock:
            await write_control_frame(self.stream, request)  # pyright: ignore[reportArgumentType]
        result = await asyncio.wait_for(future, 60)
        return result.body

    async def close(self) -> None:
        await self.stream.aclose()
        tasks = [*self.answering, *(() if self.reader is None else (self.reader,))]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


# --- repositories, spies and the service ---------------------------------------------------------


def _git(repository: Path, *arguments: str) -> str:
    return subprocess.run(
        (
            "git",
            "-c",
            "user.name=FinishUP Test",
            "-c",
            "user.email=test@example.invalid",
            *arguments,
        ),
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _repository(path: Path, name: str, text: str) -> str:
    path.mkdir(parents=True, mode=0o700)
    _git(path, "init", "-q", "-b", "main")
    (path / name).write_text(text)
    _git(path, "add", name)
    _git(path, "commit", "-q", "-m", "initial")
    return _git(path, "rev-parse", "HEAD")


def _claim_for(path: Path, *, repository: Path | None = None) -> WorkspaceClaim:
    """The client's keyed claim on ``path``, as its own machine would compute it.

    ``repository`` stands for the Git common directory a linked worktree shares with its main
    checkout: the claim is over it, the worktree digest over ``path`` itself.
    """

    common = path if repository is None else repository
    preimage = b"yoetz/workspace-claim/v1\x00" + b"git_common_root\x00" + bytes(common)
    digest = hmac.new(b"s" * 32, preimage, hashlib.sha256).hexdigest()
    worktree = hmac.new(
        b"s" * 32, b"yoetz/workspace-worktree/v1\x00" + bytes(path), hashlib.sha256
    ).hexdigest()
    return WorkspaceClaim("git_common_root", "sha256:" + digest, "sha256:" + worktree)


@dataclass
class _Spy:
    """Every workspace argument the server's own local readers were handed."""

    workspaces: list[str] = field(default_factory=list[str])


def _install_spies(monkeypatch: pytest.MonkeyPatch, spy: _Spy) -> None:
    class SpyCapture(GitChangeCaptureAdapter):
        def __getattribute__(self, name: str) -> Any:  # noqa: ANN401
            found = super().__getattribute__(name)
            if name not in {
                "read_task_base",
                "capture",
                "capture_metadata",
                "probe_requested_paths",
                "count_change_lines",
                "classify_undeclared_references",
            }:
                return found

            def recorded_call(workspace: str, *args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
                spy.workspaces.append(workspace)
                return found(workspace, *args, **kwargs)

            return recorded_call

    def recorded(name: str, original: Callable[..., Any]) -> Callable[..., Any]:
        def call(*args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
            spy.workspaces.append(f"{name}:{args[0]!r}")
            return original(*args, **kwargs)

        return call

    monkeypatch.setattr(ready_composition_module, "GitChangeCaptureAdapter", SpyCapture)
    for name in ("read_declared_test", "read_outside_inputs", "snapshot_outside_inputs"):
        monkeypatch.setattr(
            ready_composition_module, name, recorded(name, getattr(ready_composition_module, name))
        )
    monkeypatch.setattr(
        check_change_module,
        "_lstat_or_none",
        recorded("lstat", getattr(check_change_module, "_lstat_or_none")),
    )


@dataclass
class _Service:
    daemon: ServiceDaemon
    hub: WorkspaceAgentHub
    tasks: list[asyncio.Task[None]] = field(default_factory=list["asyncio.Task[None]"])

    async def connect(
        self,
        *,
        claim: WorkspaceClaim | None = None,
        agent: FakeWorkspaceAgent | None = None,
        locator: WorkspaceLocator | None = None,
    ) -> _ClaimClient:
        client_stream, server_stream = _pair()
        self.tasks.append(
            asyncio.create_task(
                self.daemon._serve_control_connection(server_stream)  # pyright: ignore[reportPrivateUsage, reportArgumentType]
            )
        )
        session = await client_handshake(
            client_stream,  # pyright: ignore[reportArgumentType]
            ControlClientKind.CLI,
            "0.3.0",
            workspace_claim=claim,
            workspace_locator=locator,
            workspace_agent=None if agent is None else fake_declaration(),
        )
        if agent is not None:
            agent.handle = session.workspace_handle
        client = _ClaimClient(client_stream, session, agent)
        client.start()
        return client


@pytest.fixture
def spy(monkeypatch: pytest.MonkeyPatch) -> _Spy:
    """Spies on the server's own local readers, installed before the application is composed."""

    recorded = _Spy()
    _install_spies(monkeypatch, recorded)
    return recorded


@pytest.fixture
async def service(tmp_path: Path, spy: _Spy) -> AsyncIterator[_Service]:
    del spy  # composed with the spies in place
    tmp_path.chmod(0o700)
    clock = _Clock()
    memory = LocalSecretMemory()
    lifecycle = ServiceLifecycle(
        clock,
        generation_store=_GenerationStore(),
        process_start_identity_commitment="sha256:" + "4" * 64,
        instance_id=getattr(composition, "_INSTANCE_ID"),
    )
    vault = VaultService(
        installation_id=_INSTALLATION_ID,
        service_generation=1,
        mode=VaultMode.UNINITIALIZED,
        secret_memory=memory,
        clock=clock,
        vault_store_factory=lambda: EncryptedVaultStore(tmp_path / "vault"),
        pristine_state_digest="sha256:" + "5" * 64,
    )
    initialize = memory.capture(SecretPurpose.VAULT_INITIALIZE, bytearray(b"correct horse battery"))
    await vault.initialize_passphrase(initialize, "sha256:" + "6" * 64)
    await vault.lock()
    hub = WorkspaceAgentHub(inline_wait_seconds=0.5, background_wait_seconds=0.5)
    diagnostics = _Diagnostics()
    factory = build_ready_application_factory(
        lifecycle=lifecycle,
        vault=vault,
        config=FinishUpConfig(),
        paths=_Paths(tmp_path / "bundle"),
        clock=clock,
        secret_memory=memory,
        diagnostics=diagnostics,
        workspace_hub=hub,
    )
    daemon = ServiceDaemon(
        _composition=ServiceComposition(
            lifecycle=lifecycle,
            control_listener=_Listener(),
            secret_ingress_listener=None,
            human_control_listener=None,
            human_control_service=None,
            session_monitor=None,
            vault=vault,
            ready_application_factory=factory,  # pyright: ignore[reportArgumentType]
            secret_memory=memory,
            diagnostics=diagnostics,
            workspace_hub=hub,
        )
    )
    running = _Service(daemon, hub)
    try:
        await daemon.start()
        await lifecycle.transition(ServiceState.UNLOCKING)
        unlock = memory.capture(SecretPurpose.VAULT_UNLOCK, bytearray(b"correct horse battery"))
        await vault.unlock(unlock)
        await daemon.activate_ready_application(1, vault.generation)
        assert daemon.status().state is ServiceState.READY
        yield running
    finally:
        for task in running.tasks:
            task.cancel()
        await asyncio.gather(*running.tasks, return_exceptions=True)
        await daemon.close()


# --- the workflow ----------------------------------------------------------------------------


def _frontier(value: Any) -> dict[str, str]:  # noqa: ANN401
    return {"sequence": str(value.sequence), "head_digest": value.head_digest}


def _publish_batches() -> tuple[tuple[str, list[dict[str, Any]]], ...]:
    return (
        (
            "req_00000000-0000-4000-8000-000000051102",
            [
                {
                    "event_id": "evt_00000000-0000-4000-8000-000000051201",
                    "schema": {"name": "plan_published", "version": "1.0.0"},
                    "occurred_at": "2026-07-21T18:00:00.000Z",
                    "causal_parents": [],
                    "payload": {
                        "plan_version": 1,
                        "summary": "Change the client's app module and verify it.",
                        "obligation_refs": [],
                    },
                    "artifact_refs": [],
                    "evidence_refs": [],
                },
                {
                    "event_id": "evt_00000000-0000-4000-8000-000000051202",
                    "schema": {"name": "claim_recorded", "version": "1.0.0"},
                    "occurred_at": "2026-07-21T18:04:00.000Z",
                    "causal_parents": ["evt_00000000-0000-4000-8000-000000051201"],
                    "payload": {
                        "claim_id": "clm_00000000-0000-4000-8000-000000051201",
                        "claim_kind": "completion",
                        "statement": "The app module change is complete.",
                        "supporting_refs": [],
                    },
                    "artifact_refs": [],
                    "evidence_refs": [],
                },
            ],
        ),
    )


async def _start(client: _ClaimClient, workspace_ref: str | None) -> Any:  # noqa: ANN401
    body: dict[str, Any] = {
        **_COMMON,
        "request_id": new_id(IdKind.REQUEST),
        "mode": "create",
        "task_title": "Change the client's app module",
        "requested_view": "compact",
    }
    if workspace_ref is not None:
        body["workspace_ref"] = workspace_ref
        body["external_ref"] = "claim-bound-task"
    return await client.call(ControlMethod.START, StartRequest.model_validate(body))


async def test_linked_worktrees_of_one_repository_are_answered_by_their_own_agents(
    tmp_path: Path, spy: _Spy, service: _Service
) -> None:
    """ADR-051: worktrees share the repository's claim, never a handle or an agent."""

    repository = tmp_path / "client" / "repo" / ".git"
    main = tmp_path / "client" / "repo"
    linked = tmp_path / "client" / "linked"
    _repository(main, "app.py", "print('main')\n")
    _repository(linked, "app.py", "print('linked')\n")
    main_agent, linked_agent = FakeWorkspaceAgent(main), FakeWorkspaceAgent(linked)
    main_client = await service.connect(
        claim=_claim_for(main, repository=repository), agent=main_agent
    )
    # The linked worktree's agent connects after the main one: newest, but not the main's.
    linked_client = await service.connect(
        claim=_claim_for(linked, repository=repository), agent=linked_agent
    )
    try:
        main_handle = main_client.session.workspace_handle
        linked_handle = linked_client.session.workspace_handle
        assert main_handle is not None and linked_handle is not None
        assert main_handle != linked_handle

        started = (await _start(main_client, main_handle)).root
        assert started.ok is True, started
        # The main worktree's task base came from its own agent alone.
        assert "read_task_base" in main_agent.operations
        assert linked_agent.operations == []
        # The other worktree's handle is not this connection's workspace.
        refused = (await _start(main_client, linked_handle)).root
        assert refused.ok is False
        sibling = (await _start(linked_client, linked_handle)).root
        assert sibling.ok is True, sibling
        assert main_agent.operations.count("read_task_base") == 1
        assert linked_agent.operations.count("read_task_base") == 1
        # Both tasks share the repository's commitment (privacy authority and consent scope).
        application = cast(Any, service.daemon._application)  # pyright: ignore[reportPrivateUsage]
        routes = [
            await application.start_catalog.task_route(started.task_id),
            await application.start_catalog.task_route(sibling.task_id),
        ]
        commitments = {route.repository_privacy_commitment for route in routes}
        assert len(commitments) == 1 and None not in commitments

        # With the main worktree's agent gone, its handle has no agent: the linked worktree's
        # live agent never answers for it.
        await main_client.close()
        with pytest.raises(WorkspaceAgentUnavailable) as caught:
            await service.hub.call(
                main_handle,
                WorkspaceOperation.READ_TASK_BASE,
                WorkspaceOnlyArguments(main_handle),
                timeout_seconds=1.0,
            )
        assert caught.value.reason == "no_agent"
        assert linked_agent.operations.count("read_task_base") == 1
    finally:
        await main_client.close()
        await linked_client.close()
    assert spy.workspaces == []


async def test_an_agent_for_another_worktree_is_never_admitted_under_a_live_handle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, service: _Service
) -> None:
    """Defense in depth: were two worktrees ever to meet under one handle, the second is shut."""

    import finishup.adapters.repository_identity as identity_module

    def one_handle(commitment: str, worktree: str) -> str:
        del commitment, worktree
        return "client:00000000000000aa"

    monkeypatch.setattr(identity_module, "workspace_handle_for_claim", one_handle)
    first, second = tmp_path / "client" / "first", tmp_path / "client" / "second"
    _repository(first, "app.py", "print('first')\n")
    _repository(second, "app.py", "print('second')\n")
    first_agent, second_agent = FakeWorkspaceAgent(first), FakeWorkspaceAgent(second)
    first_client = await service.connect(claim=_claim_for(first), agent=first_agent)
    second_client = await service.connect(claim=_claim_for(second), agent=second_agent)
    try:
        assert first_client.session.workspace_handle == second_client.session.workspace_handle
        assert second_client.reader is not None
        # The service closed the second connection instead of admitting its agent.
        await asyncio.wait_for(second_client.reader, 5.0)
        handle = "client:00000000000000aa"
        await service.hub.call(
            handle,
            WorkspaceOperation.READ_TASK_BASE,
            WorkspaceOnlyArguments(handle),
            timeout_seconds=5.0,
        )
        assert first_agent.operations == ["read_task_base"]
        assert second_agent.operations == []
    finally:
        await first_client.close()
        await second_client.close()


async def test_a_claim_bound_task_runs_its_whole_workflow_on_its_agent_alone(
    tmp_path: Path, spy: _Spy, service: _Service
) -> None:
    # The decoy: a repository at the claimed path, on the server. The agent answers elsewhere.
    claimed = tmp_path / "work" / "repo"
    decoy_head = _repository(claimed, "decoy.py", "print('decoy')\n")
    client_repo = tmp_path / "client" / "repo"
    client_head = _repository(client_repo, "app.py", "print('client')\n")
    (client_repo / "app.py").write_text("print('client, edited')\n")
    assert decoy_head != client_head
    agent = FakeWorkspaceAgent(client_repo)
    client = await service.connect(claim=_claim_for(claimed), agent=agent)
    try:
        handle = client.session.workspace_handle
        assert client.session.workspace_binding == "client_claim"
        assert handle is not None and handle.startswith("client:")

        started = (await _start(client, handle)).root
        assert started.ok is True, started
        frontier = started.frontier
        for request_id, drafts in _publish_batches():
            published = (
                await client.call(
                    ControlMethod.PUBLISH_WORK,
                    PublishWorkRequest.model_validate(
                        {
                            **_COMMON,
                            "request_id": request_id,
                            "session_id": started.session_id,
                            "writer_id": started.writer_id,
                            "expected_frontier": _frontier(frontier),
                            "event_drafts": drafts,
                        }
                    ),
                )
            ).root
            assert published.ok is True, published
            frontier = published.result_frontier
        checked = (
            await client.call(
                ControlMethod.CHECK,
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
                ),
            )
        ).root
        assert checked.ok is True, checked
        frontier = checked.result_frontier
        # The unverified completion claim is a finding the agent answers.
        assert checked.findings, checked
        finding = checked.findings[0]
        responded = (
            await client.call(
                ControlMethod.RESPOND,
                RespondRequest.model_validate(
                    {
                        **_COMMON,
                        "request_id": new_id(IdKind.REQUEST),
                        "session_id": started.session_id,
                        "writer_id": started.writer_id,
                        "expected_frontier": _frontier(frontier),
                        "finding_id": finding.finding_id,
                        "finding_frontier": _frontier(frontier),
                        "disposition": "acknowledged",
                        "reason": "The remaining verification follows in a later batch.",
                    }
                ),
            )
        ).root
        assert responded.ok is True, responded
        frontier = responded.result_frontier
        receipt = (
            await client.call(
                ControlMethod.RECEIPT,
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
                ),
            )
        ).root
        assert receipt.ok is True, receipt

        # Every workspace fact came from the agent's repository, never the decoy at the path.
        assert "read_task_base" in agent.operations
        assert "capture_metadata" in agent.operations
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
            assert decode_task_change_base(b"".join(chunks)).commit == client_head
        finally:
            await application.runtime.release(runtime)
        # The server's own adapters were never handed this task's workspace in any form.
        assert all(
            handle not in entry and str(claimed) not in entry and str(client_repo) not in entry
            for entry in spy.workspaces
        ), spy.workspaces
        # The receipt says, in fixed words, where the evidence came from and who served it.
        assert receipt.human_text is not None
        assert CLIENT_ATTESTED_WORKSPACE_LINE in receipt.human_text
        assert f"Served by FinishUP service {client.session.service_instance_id}" in (
            receipt.human_text
        )
        assert str(client_repo) not in receipt.human_text and str(claimed) not in receipt.human_text
    finally:
        await client.close()


async def _start_naming_no_workspace(client: _ClaimClient, kind: str) -> Any:  # noqa: ANN401
    """Open a task by a start that names no workspace, as a host may on one computer."""

    def body(**fields: Any) -> StartRequest:  # noqa: ANN401
        return StartRequest.model_validate(
            {
                **_COMMON,
                "request_id": new_id(IdKind.REQUEST),
                "task_title": "Change the client's app module",
                "requested_view": "compact",
                **fields,
            }
        )

    if kind == "create":
        return (await client.call(ControlMethod.START, body(mode="create"))).root
    parent = (await client.call(ControlMethod.START, body(mode="create"))).root
    assert parent.ok is True, parent
    if kind == "parent_registered":
        return (
            await client.call(
                ControlMethod.START, body(mode="create", parent_session_id=parent.session_id)
            )
        ).root
    assert kind == "delegate_then_attach"
    delegated = (
        await client.call(ControlMethod.START, body(mode="delegate", session_id=parent.session_id))
    ).root
    assert delegated.ok is True, delegated
    assert delegated.attach_handle is not None
    return (
        await client.call(
            ControlMethod.START,
            body(mode="attach", attach_handle=delegated.attach_handle.model_dump(mode="json")),
        )
    ).root


@pytest.mark.parametrize("kind", ["create", "parent_registered", "delegate_then_attach"])
async def test_a_start_naming_no_workspace_opens_on_the_claims_handle_and_attests(
    tmp_path: Path, spy: _Spy, service: _Service, kind: str
) -> None:
    """ADR-051: a start may name no workspace on a claim-bound connection, as on one computer.

    The pair is both or neither, so a host that sends neither cannot add the handle alone. The
    session it opens records the connection's handle, its change base comes from the agent and
    its receipt carries the fixed workspace-evidence block; the server reads no path.
    """

    client_repo = tmp_path / "client" / "repo"
    client_head = _repository(client_repo, "app.py", "print('client')\n")
    agent = FakeWorkspaceAgent(client_repo)
    client = await service.connect(claim=_claim_for(client_repo), agent=agent)
    try:
        handle = client.session.workspace_handle
        assert handle is not None
        started = await _start_naming_no_workspace(client, kind)
        assert started.ok is True, started
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
            opened = [
                record.payload
                async for record in runtime.ledger.load_events(runtime.session_id)
                if isinstance(record.payload, SessionOpenedPayload)
            ]
            assert [payload.workspace_ref for payload in opened] == [handle]
            # Only a start that creates a task records its base (ADR-031), as on one computer;
            # the parent's create in the other cases read it from the agent too.
            ref = await runtime.ledger.load_task_change_base()
            if kind == "create":
                assert ref is not None
                chunks = [chunk async for chunk in runtime.objects.open_verified(ref)]
                assert decode_task_change_base(b"".join(chunks)).commit == client_head
        finally:
            await application.runtime.release(runtime)
        assert "read_task_base" in agent.operations
        receipt = (
            await client.call(
                ControlMethod.RECEIPT,
                ReceiptRequest.model_validate(
                    {
                        **_COMMON,
                        "request_id": new_id(IdKind.REQUEST),
                        "session_id": started.session_id,
                        "writer_id": started.writer_id,
                        "task_id": started.task_id,
                        "expected_frontier": _frontier(started.frontier),
                        "format": "text",
                        "include": "summary",
                        "redaction_profile": "full_local",
                    }
                ),
            )
        ).root
        assert receipt.ok is True, receipt
        assert receipt.human_text is not None
        assert CLIENT_ATTESTED_WORKSPACE_LINE in receipt.human_text
        assert str(client_repo) not in receipt.human_text
        assert all(
            handle not in entry and str(client_repo) not in entry for entry in spy.workspaces
        ), spy.workspaces
    finally:
        await client.close()


async def test_an_absolute_workspace_ref_on_a_claim_connection_is_refused_before_any_write(
    tmp_path: Path, service: _Service
) -> None:
    client_repo = tmp_path / "client" / "repo"
    _repository(client_repo, "app.py", "print('client')\n")
    agent = FakeWorkspaceAgent(client_repo)
    client = await service.connect(claim=_claim_for(client_repo), agent=agent)
    try:
        refused = (await _start(client, str(client_repo))).root
        assert refused.ok is False
        assert refused.error.safe_details["reason_code"] == "workspace_ref_not_portable"
        assert str(client_repo) not in refused.error.message
        # Nothing was read for a start that was never admitted.
        assert agent.operations == []
    finally:
        await client.close()


async def test_a_claim_without_an_agent_records_the_typed_gap_and_never_reads_here(
    tmp_path: Path, spy: _Spy, service: _Service
) -> None:
    claimed = tmp_path / "work" / "repo"
    _repository(claimed, "decoy.py", "print('decoy')\n")
    (claimed / "decoy.py").write_text("print('decoy, edited')\n")
    client = await service.connect(claim=_claim_for(claimed))
    try:
        handle = client.session.workspace_handle
        assert handle is not None
        started = (await _start(client, handle)).root
        assert started.ok is True, started
        checked = (
            await client.call(
                ControlMethod.CHECK,
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
                ),
            )
        ).root
        assert checked.ok is True, checked
        gaps = set(checked.coverage.known_gaps)
        assert "check_time_change_unavailable_workspace_agent_unavailable" in gaps, gaps
        assert spy.workspaces == []
    finally:
        await client.close()


async def test_a_locator_is_refused_where_the_edge_admits_only_claims(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from integration.service import test_daemon_clients as clients

    daemon, _application, _vault, _listener = clients._daemon()  # pyright: ignore[reportPrivateUsage]
    composition_value = daemon.composition
    object.__setattr__(composition_value, "refuse_workspace_locators", True)
    await daemon.start()
    client_stream, server_stream = _pair()
    served = asyncio.create_task(
        daemon._serve_control_connection(server_stream)  # pyright: ignore[reportPrivateUsage, reportArgumentType]
    )
    try:
        with pytest.raises((ControlProtocolError, ControlError)):
            await client_handshake(
                client_stream,  # pyright: ignore[reportArgumentType]
                ControlClientKind.CLI,
                "0.3.0",
                workspace_locator=WorkspaceLocator(str(tmp_path)),
            )
        await asyncio.wait_for(served, 5)
    finally:
        served.cancel()
        await asyncio.gather(served, return_exceptions=True)
        await daemon.close()


async def test_a_reply_on_a_connection_that_offered_no_agent_closes_it() -> None:
    from finishup.ports.control import WorkspaceReply
    from finishup.service.control_protocol import write_workspace_reply
    from integration.service import test_daemon_clients as clients

    daemon, _application, _vault, _listener = clients._daemon()  # pyright: ignore[reportPrivateUsage]
    await daemon.start()
    client_stream, server_stream = _pair()
    served = asyncio.create_task(
        daemon._serve_control_connection(server_stream)  # pyright: ignore[reportPrivateUsage, reportArgumentType]
    )
    try:
        await client_handshake(client_stream, ControlClientKind.CLI, "0.3.0")  # pyright: ignore[reportArgumentType]
        reply = WorkspaceReply(
            "workspace_reply", "1.0", new_id(IdKind.CONTROL_RPC), "ok", None, None
        )
        await write_workspace_reply(client_stream, reply)  # pyright: ignore[reportArgumentType]
        await asyncio.wait_for(served, 5)
    finally:
        served.cancel()
        await asyncio.gather(served, return_exceptions=True)
        await daemon.close()


async def test_an_agent_connection_registers_and_unregisters_with_the_hub(
    tmp_path: Path, service: _Service
) -> None:
    client_repo = tmp_path / "client" / "repo"
    _repository(client_repo, "app.py", "print('client')\n")
    client = await service.connect(
        claim=_claim_for(client_repo), agent=FakeWorkspaceAgent(client_repo)
    )
    handle = client.session.workspace_handle
    assert handle is not None and service.hub.has_agent(handle)
    await client.close()
    for _ in range(100):
        if not service.hub.has_agent(handle):
            break
        await asyncio.sleep(0.01)
    assert not service.hub.has_agent(handle)


# --- AI-powered review: the reviewer's reads go to the agent, and its loss is a typed gap ----

_HANDLE = "client:00112233445566aa"


async def _attach(
    hub: WorkspaceAgentHub, agent: FakeWorkspaceAgent, *, drop_on: str | None = None
) -> WorkspaceAgentChannel:
    """Register ``agent`` on the hub as a connection would; it drops on a ``drop_on`` call."""

    holder: dict[str, WorkspaceAgentChannel] = {}

    async def writer(call: Any) -> None:  # noqa: ANN401
        channel = holder["channel"]
        loop = asyncio.get_running_loop()
        if call.operation == drop_on:
            # The client machine went away with this call in flight.
            loop.create_task(hub.unregister(channel))
            return

        async def answer() -> None:
            hub.deliver(channel, await asyncio.to_thread(agent.answer, call))

        loop.create_task(answer())

    agent.handle = _HANDLE
    channel = await hub.register(
        handle=_HANDLE,
        declaration=fake_declaration(),
        service_instance_id=getattr(composition, "_INSTANCE_ID"),
        service_generation="1",
        writer=writer,
    )
    holder["channel"] = channel
    return channel


async def _review(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    hub: WorkspaceAgentHub,
    *replies: Any,  # noqa: ANN401
) -> tuple[Any, Any]:  # noqa: ANN401
    """The reviewer composition suite's harness, with a claim-bound workspace (ADR-051)."""

    from types import SimpleNamespace

    from builders.ledger_adapters import FixedClock, append_command, sqlite_adapter
    from builders.privacy_policies import minimal_external_policy
    from finishup.adapters.memory.privacy import MemoryPrivacyCatalogState
    from finishup.adapters.privacy.local_enforcer import LocalPrivacyEnforcer
    from finishup.application.egress import PrivacyCoordinator
    from finishup.ports.privacy import EffectivePrivacyPolicy, HumanAuthorityCapability
    from finishup.service.workspace_routing import WorkspaceRouting
    from integration.service import test_reviewer_conversation_composition as reviewer
    from integration.service import test_semantic_non_dispatch as non_dispatch

    async def workspace_root(_runtime: object) -> str:
        return _HANDLE

    monkeypatch.setattr(ready_composition_module, "_workspace_root_for_runtime", workspace_root)
    adapter = sqlite_adapter(append_command())
    frozen, runtime = await non_dispatch._durable_semantic_case(adapter)  # pyright: ignore[reportPrivateUsage]
    policy = minimal_external_policy()
    store = non_dispatch._PolicyStore(  # pyright: ignore[reportPrivateUsage]
        EffectivePrivacyPolicy(policy, 1, policy.policy_digest), repository_granted=True
    )
    gateway = reviewer._ScriptedGateway(*replies)  # pyright: ignore[reportPrivateUsage]
    clock = FixedClock()
    route = non_dispatch._route_for(runtime.task_id, runtime.session_id)  # pyright: ignore[reportPrivateUsage]
    state = MemoryPrivacyCatalogState()
    state.routes[runtime.task_id] = route.route_identity_digest
    coordinator = PrivacyCoordinator(
        store,  # pyright: ignore[reportArgumentType]
        LocalPrivacyEnforcer(),
        reviewer._Audit(state, runtime.objects, reviewer._Key(), clock),  # pyright: ignore[reportPrivateUsage, reportArgumentType]
        gateway,  # pyright: ignore[reportArgumentType]
        clock,
        ready_composition_module.IdPort(),
        human_authority=HumanAuthorityCapability(
            "established_passphrase", "sha256:" + "9" * 64, 1, "unlocked", 1, True
        ),
    )
    coordinator._policy_app = SimpleNamespace(policy_store=store)  # type: ignore[assignment]  # pyright: ignore

    async def resolve_provider() -> Any:  # noqa: ANN401
        return reviewer._BINDING  # pyright: ignore[reportPrivateUsage]

    from finishup.ports.change_capture import CheckWorkspaceSource, check_workspace_source_scope

    routing = WorkspaceRouting.compose(hub, SpyLocalCapture())
    evaluator = getattr(ready_composition_module, "_privacy_gated_semantic_evaluator")(
        coordinator,
        clock,
        non_dispatch._INSTALLATION,  # pyright: ignore[reportPrivateUsage]
        resolve_provider,
        non_dispatch._Catalog(route),  # pyright: ignore[reportPrivateUsage]
        ready_composition_module.IdPort(),
        change_capture=routing.change_capture,
        workspace_routing=routing,
    )
    # The check's own connection bound this claim, so the check-time change is the agent's too.
    source = CheckWorkspaceSource(_HANDLE, non_dispatch._REPOSITORY)  # pyright: ignore[reportPrivateUsage]
    with check_workspace_source_scope(source):
        return await evaluator(frozen, (), runtime), gateway


class SpyLocalCapture(GitChangeCaptureAdapter):
    """A local capture adapter that must never be reached for a claim-bound review."""

    def __getattribute__(self, name: str) -> Any:  # noqa: ANN401
        if name in {
            "read_task_base",
            "capture",
            "capture_metadata",
            "probe_requested_paths",
            "count_change_lines",
            "classify_undeclared_references",
        }:
            raise AssertionError("local_capture_reached")
        return super().__getattribute__(name)


def _reviewed_repository(tmp_path: Path) -> Path:
    work = tmp_path / "client" / "work"
    _repository(work, "calc.py", "def add(a, b):\n    return a + b\n")
    (work / ".gitignore").write_text("secret.txt\n")
    (work / "secret.txt").write_text("not for review\n")
    return work


async def test_the_reviewers_reads_are_answered_by_the_workspace_agent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from integration.service import test_reviewer_conversation_composition as reviewer

    hub = WorkspaceAgentHub(inline_wait_seconds=0.5, background_wait_seconds=0.5)
    agent = FakeWorkspaceAgent(_reviewed_repository(tmp_path))
    await _attach(hub, agent)
    result, gateway = await _review(
        tmp_path,
        monkeypatch,
        hub,
        reviewer._read_file("calc.py"),  # pyright: ignore[reportPrivateUsage]
        reviewer._read_file("secret.txt"),  # pyright: ignore[reportPrivateUsage]
        reviewer._FINAL,  # pyright: ignore[reportPrivateUsage]
    )
    assert result.status.value == "succeeded", (result.status, result.reason)
    first, _, last = (history for _, history in gateway.exchanges)
    observation = json.loads(last[4][1])
    assert observation["status"] == "ok" and "return a + b" in observation["data"]["text"]
    denied = json.loads(last[6][1])
    assert (denied["status"], denied["reason"]) == ("denied", "forbidden_path")
    # The check-time change, the ignore probe and the read all went to the agent.
    assert "capture" in agent.operations, agent.operations
    assert "probe_requested_paths" in agent.operations
    assert "read_text_beneath" in agent.operations
    assert "reviewer_catalog" in first[2][1]


@pytest.mark.parametrize("drop_on", ("probe_requested_paths", "read_text_beneath"))
async def test_an_agent_lost_mid_review_ends_the_review_unavailable_never_a_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, drop_on: str
) -> None:
    from integration.service import test_reviewer_conversation_composition as reviewer

    hub = WorkspaceAgentHub(inline_wait_seconds=0.2, background_wait_seconds=0.2)
    agent = FakeWorkspaceAgent(_reviewed_repository(tmp_path))
    # The check-time change is answered; the read's ignore probe, or the read itself, finds the
    # agent gone.
    await _attach(hub, agent, drop_on=drop_on)
    result, gateway = await _review(
        tmp_path,
        monkeypatch,
        hub,
        reviewer._read_file("calc.py"),  # pyright: ignore[reportPrivateUsage]
        reviewer._FINAL,  # pyright: ignore[reportPrivateUsage]
    )
    assert result.status.value == "unavailable", (result.status, result.reason)
    assert result.judgment is None
    assert result.reviewer is not None
    assert result.reviewer.ended == "workspace_agent_unavailable"
    # The judgment the provider would have given was never asked for.
    assert len(gateway.exchanges) == 1


async def test_a_pending_workspace_call_keeps_an_idle_agent_connection_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, service: _Service
) -> None:
    import time

    import finishup.service.daemon as daemon_module

    class SlowAgent(FakeWorkspaceAgent):
        def answer(self, call: Any) -> Any:  # noqa: ANN401
            time.sleep(0.4)
            return super().answer(call)

    client_repo = tmp_path / "client" / "repo"
    head = _repository(client_repo, "app.py", "print('client')\n")
    # A session with no control call in flight idles out after this long.
    monkeypatch.setattr(daemon_module, "_CONTROL_INACTIVE_SESSION_DEADLINE_SECONDS", 0.1)
    client = await service.connect(claim=_claim_for(client_repo), agent=SlowAgent(client_repo))
    try:
        handle = client.session.workspace_handle
        assert handle is not None
        base = await service.hub.call(
            handle,
            WorkspaceOperation.READ_TASK_BASE,
            WorkspaceOnlyArguments(handle),
            timeout_seconds=5.0,
        )
        assert base.commit == head
        # With nothing pending the idle bound applies again and the connection is released.
        for _ in range(200):
            if not service.hub.has_agent(handle):
                break
            await asyncio.sleep(0.01)
        assert not service.hub.has_agent(handle)
    finally:
        await client.close()


async def test_a_claim_on_a_locked_service_binds_no_handle_and_registers_no_agent(
    tmp_path: Path,
) -> None:
    from integration.service import test_daemon_clients as clients

    daemon, _application, vault, _listener = clients._daemon()  # pyright: ignore[reportPrivateUsage]
    await daemon.start()
    vault.ready = False  # no installation key: the claim cannot be keyed yet
    client_stream, server_stream = _pair()
    served = asyncio.create_task(
        daemon._serve_control_connection(server_stream)  # pyright: ignore[reportPrivateUsage, reportArgumentType]
    )
    try:
        session = await client_handshake(
            client_stream,  # pyright: ignore[reportArgumentType]
            ControlClientKind.CLI,
            "0.3.0",
            workspace_claim=_claim_for(tmp_path),
            workspace_agent=fake_declaration(),
        )
        assert session.workspace_binding == "client_claim"
        assert session.workspace_handle is None
        hub = daemon.composition.workspace_hub
        assert hub._channels == {}  # pyright: ignore[reportPrivateUsage]
    finally:
        await client_stream.aclose()
        served.cancel()
        await asyncio.gather(served, return_exceptions=True)
        await daemon.close()


async def test_a_child_attached_by_its_handle_keeps_the_client_attested_receipt(
    tmp_path: Path, service: _Service
) -> None:
    """ADR-051: a delegated child attached by handle, with no workspace_ref, is still claim-bound.

    The child's only opening event comes from the attach. Its evidence is read by the client's
    agent, so its receipt keeps the fixed workspace-evidence block naming the serving service.
    """

    client_repo = tmp_path / "client" / "repo"
    _repository(client_repo, "app.py", "print('client')\n")
    agent = FakeWorkspaceAgent(client_repo)
    client = await service.connect(claim=_claim_for(client_repo), agent=agent)
    try:
        handle = client.session.workspace_handle
        assert handle is not None
        parent = (await _start(client, handle)).root
        assert parent.ok is True, parent
        delegated = (
            await client.call(
                ControlMethod.START,
                StartRequest.model_validate(
                    {
                        **_COMMON,
                        "request_id": new_id(IdKind.REQUEST),
                        "mode": "delegate",
                        "session_id": parent.session_id,
                        "task_title": "The client's child task",
                        "requested_view": "compact",
                        "workspace_ref": handle,
                        "external_ref": "claim-bound-child",
                    }
                ),
            )
        ).root
        assert delegated.ok is True, delegated
        capability = delegated.attach_handle
        assert capability is not None
        attached = (
            await client.call(
                ControlMethod.START,
                StartRequest.model_validate(
                    {
                        **_COMMON,
                        "request_id": new_id(IdKind.REQUEST),
                        "mode": "attach",
                        "task_title": "The client's child task",
                        "requested_view": "compact",
                        "attach_handle": capability.model_dump(mode="json"),
                    }
                ),
            )
        ).root
        assert attached.ok is True, attached
        assert attached.task_id == delegated.task_id
        receipt = (
            await client.call(
                ControlMethod.RECEIPT,
                ReceiptRequest.model_validate(
                    {
                        **_COMMON,
                        "request_id": new_id(IdKind.REQUEST),
                        "session_id": attached.session_id,
                        "writer_id": attached.writer_id,
                        "task_id": attached.task_id,
                        "expected_frontier": _frontier(attached.frontier),
                        "format": "text",
                        "include": "standard",
                        "redaction_profile": "full_local",
                    }
                ),
            )
        ).root
        assert receipt.ok is True, receipt
        assert receipt.human_text is not None
        assert CLIENT_ATTESTED_WORKSPACE_LINE in receipt.human_text
        assert f"Served by FinishUP service {client.session.service_instance_id}" in (
            receipt.human_text
        )
        assert str(client_repo) not in receipt.human_text
    finally:
        await client.close()
