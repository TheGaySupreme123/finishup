"""A remote target end to end through direct dial (ADR-051, approach B).

A real daemon with a real vault and the real ready composition (``test_claim_bound_sessions``)
serves a client that dials it the way approach B does, in process:

* **HTTPS** — ``HttpsTransport`` through the real gateway (``finishup service gateway``, over
  ``httpx.ASGITransport``, with a real key), which relays each binding session to one control
  connection of the daemon;
* **SSH** — ``SshTransport`` with its production argv, where a stand-in for ``ssh`` honours
  ``-W`` by relaying to a Unix socket the daemon serves.

Above the transport everything is production code: the active root is a selected remote target,
``service.client`` claims the workspace (never sending its path), the CLI's serving binding
offers the real ``WorkspaceAgentHandler`` on the same connection, the MCP bridge's
``BridgeBackgroundWork`` holds the background agent and drains captured rows. Spies on the
server's own adapters prove it never read the workspace itself; every workspace fact is the
agent's, attested on the client.
"""

from __future__ import annotations

import asyncio
import dataclasses
import io
import json
import os
import shutil
import socket
import sys
import time
from collections.abc import AsyncGenerator, Callable, Iterator, Mapping, Sequence
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, ClassVar, cast

import httpx
import pytest

import finishup.service.ready_composition as ready_composition_module
from builders.direct_dial import RELAY_SOURCE, StaticCredential, real_gateway
from builders.server_targets import ambient_home
from finishup.adapters.control.unix_socket import AuthenticatedUnixStream, authenticate_peer
from finishup.adapters.integrations.codex_lifecycle import mapping_from_start_ids, store_mapping
from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.application.observation_check_policy import load_observation_check_policy
from finishup.application.observation_workspace import LocalObservationWorkspace
from finishup.cli.observe_hooks import handle_observe
from finishup.client import targets, transports
from finishup.client import workspace_agent as workspace_agent_module
from finishup.client.agent_session import BridgeBackgroundWork
from finishup.client.attribution import connection_attribution
from finishup.client.targets import ServerTarget
from finishup.client.transports import HttpsTransport, SshTransport
from finishup.client.workspace_agent import WorkspaceAgentHandler
from finishup.client.workspace_claim import workspace_claim
from finishup.client.workspace_ref import start_request_for_connection
from finishup.config.paths import reset_selection_memo, state_dir
from finishup.domain.receipts import (
    CLIENT_ATTESTED_OBSERVATION_LINE,
    CLIENT_ATTESTED_WORKSPACE_LINE,
)
from finishup.ports.change_capture import decode_task_change_base
from finishup.ports.check_sandbox import CheckSandboxLaunch, CheckSandboxStatus
from finishup.ports.control import (
    ControlClientKind,
    ControlError,
    WorkspaceCall,
    WorkspaceLocator,
    WorkspaceReply,
)
from finishup.ports.runtime import RouteAccess, RouteCommand, RuntimeCapability
from finishup.protocol.ids import IdKind, new_id
from finishup.protocol.models import (
    CheckRequest,
    PublishWorkRequest,
    ReceiptRequest,
    RespondRequest,
    StartRequest,
    StatusRequest,
)
from finishup.service import client as client_module
from finishup.service.client import ClientWorkspaceBinding, ServiceClient
from integration.service.test_claim_bound_sessions import (  # noqa: F401 - fixtures
    _COMMON,  # pyright: ignore[reportPrivateUsage]
    _frontier,  # pyright: ignore[reportPrivateUsage]
    _pair,  # pyright: ignore[reportPrivateUsage]
    _publish_batches,  # pyright: ignore[reportPrivateUsage]
    _repository,  # pyright: ignore[reportPrivateUsage]
    _Service,  # pyright: ignore[reportPrivateUsage]
    _Spy,  # pyright: ignore[reportPrivateUsage]
    service,  # pyright: ignore[reportUnusedImport]
    spy,  # pyright: ignore[reportUnusedImport]
)
from integration.service.test_ready_composition import (  # noqa: F401 - autouse SQLite policy
    _sqlite_policy,  # pyright: ignore[reportPrivateUsage, reportUnusedImport]
)

pytestmark = pytest.mark.anyio

_TRUE = shutil.which("true", path=os.defpath) or "/usr/bin/true"
_POLICY = (
    'format = "yoetz.approved-check-policy/1"\n\n'
    "[[checks]]\n"
    'id = "unit"\n'
    f'argv = ["{_TRUE}"]\n'
    "timeout_seconds = 10\n"
    "network = false\n"
)
_HOST_SESSION = "codex-direct-dial-1"
# Waits observe real state (the agent's own call log, the server's answers) and fail on this
# deadline; nothing sleeps to infer success.
_DEADLINE_SECONDS = 30.0
_APPROVED_CHECK_ACTOR = "yoetz:approved-check-service"


# --- the client machine's agent: the real handler, recorded, with the unit sandbox seam ------


class _ReadySandbox:
    """The unit seam the approved-check adapter tests use; enforcement has its own tests."""

    def prepare(
        self,
        *,
        argv: Sequence[str],
        cwd: Path,
        env: Mapping[str, str],
        deny_network: bool,
    ) -> CheckSandboxLaunch:
        return CheckSandboxLaunch(
            argv=tuple(argv),
            env=dict(env),
            cwd=cwd,
            status=CheckSandboxStatus.READY,
            network_isolated=deny_network,
        )


class _Recorded(WorkspaceAgentHandler):
    """The real ``WorkspaceAgentHandler``; every operation it answered is recorded in order.

    ``drops`` names, per operation, what happens to the client machine while that call is in
    flight (it goes away).
    """

    operations: ClassVar[list[str]] = []
    drops: ClassVar[dict[str, Callable[[], None]]] = {}

    def __init__(self, workspace: WorkspaceLocator, **kwargs: Any) -> None:  # noqa: ANN401
        kwargs.setdefault("check_sandbox", _ReadySandbox())
        super().__init__(workspace, **kwargs)

    def answer(self, call: WorkspaceCall, *, workspace_handle: str | None) -> WorkspaceReply:
        type(self).operations.append(call.operation)
        drop = type(self).drops.get(call.operation)
        if drop is not None:
            drop()
        return super().answer(call, workspace_handle=workspace_handle)


@pytest.fixture
def agent(monkeypatch: pytest.MonkeyPatch) -> Iterator[type[_Recorded]]:
    """Every workspace agent this process builds is the recorded real handler."""

    class _Agent(_Recorded):
        operations: ClassVar[list[str]] = []
        drops: ClassVar[dict[str, Callable[[], None]]] = {}

    monkeypatch.setattr(workspace_agent_module, "WorkspaceAgentHandler", _Agent)
    yield _Agent


@pytest.fixture
def local_reads(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[str]]:
    """Every observation read the server tried on its own disk; a claim must make none."""

    recorded: list[str] = []

    def refuse(name: str) -> Callable[..., Any]:
        def call(_self: object, *args: object, **kwargs: object) -> Any:  # noqa: ANN401
            recorded.append(name)
            raise AssertionError("server_read_its_own_disk")

        return call

    for name in ("open", "load_policy", "list_changed", "runner"):
        monkeypatch.setattr(LocalObservationWorkspace, name, refuse(name))
    yield recorded


# --- the remote target and its transports ----------------------------------------------------


@dataclasses.dataclass
class _Remote:
    kind: str
    target: ServerTarget
    root: Path
    dialled: list[str] = dataclasses.field(default_factory=list[str])


@pytest.fixture
def forbid_local(monkeypatch: pytest.MonkeyPatch) -> None:
    """A remote root never dials, spawns or supersedes a local service."""

    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("a remote root never reaches a local service")

    monkeypatch.setattr(client_module, "_spawn_service_process", forbidden)
    monkeypatch.setattr(client_module, "supersede_incompatible_service", forbidden)
    monkeypatch.setattr(client_module, "connect_control", forbidden)


@asynccontextmanager
async def _remote(
    kind: str,
    service: _Service,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
    directory: Path,
) -> AsyncGenerator[_Remote]:
    """Select a remote target of ``kind`` whose transport reaches ``service``'s daemon."""

    with ambient_home(monkeypatch) as home:
        with targets.registry_lock():
            if kind == "https":
                record, root = targets.new_remote_target(
                    "lab", "https", base_url="https://gateway.test/base"
                )
            else:
                record, root = targets.new_remote_target(
                    "lab", "ssh", user="owner", host="lab.example", port=2222
                )
            targets.write_selection(record)
        reset_selection_memo()
        remote = _Remote(kind, record, root)
        cleanup: list[Callable[[], Any]] = []
        if kind == "https":

            async def upstream() -> Any:  # noqa: ANN401
                client_end, server_end = _pair()
                service.tasks.append(
                    asyncio.create_task(
                        service.daemon._serve_control_connection(server_end)  # pyright: ignore[reportPrivateUsage, reportArgumentType]
                    )
                )
                remote.dialled.append("https")
                return client_end

            gateway = real_gateway(home / "gateway", upstream)
            transport: Any = HttpsTransport(
                record,
                root,
                credential=StaticCredential(gateway.key),
                http_transport=httpx.ASGITransport(app=gateway),
            )
            cleanup.append(gateway.state.sessions.close_all)
        else:
            relay = directory / "relay.py"
            relay.write_text(RELAY_SOURCE, encoding="utf-8")
            monkeypatch.setenv("FU_RELAY_LOG", os.fspath(directory / "relay.log"))
            endpoint = directory / "c.sock"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(os.fspath(endpoint))
            listener.listen(8)
            listener.setblocking(False)

            async def accept() -> None:
                loop = asyncio.get_running_loop()
                while True:
                    connection, _address = await loop.sock_accept(listener)
                    stream = AuthenticatedUnixStream(connection, authenticate_peer(connection))
                    remote.dialled.append("ssh")
                    service.tasks.append(
                        asyncio.create_task(
                            service.daemon._serve_control_connection(stream)  # pyright: ignore[reportPrivateUsage, reportArgumentType]
                        )
                    )

            accepting = asyncio.create_task(accept())
            target = dataclasses.replace(record, remote_endpoint=os.fspath(endpoint))
            transport = SshTransport(target, root, program=(sys.executable, "-I", os.fspath(relay)))

            async def stop_accepting() -> None:
                accepting.cancel()
                await asyncio.gather(accepting, return_exceptions=True)
                listener.close()

            cleanup.append(stop_accepting)

        def chosen(_target: ServerTarget, _root: Path) -> Any:  # noqa: ANN401
            return transport

        monkeypatch.setattr(transports, "transport_for_target", chosen)
        try:
            yield remote
        finally:
            for step in cleanup:
                await step()
            reset_selection_memo()


def _short_directory() -> Path:
    """A short owner-only directory for the relay's socket (AF_UNIX paths are short)."""

    import tempfile

    return Path(tempfile.mkdtemp(prefix="fu-dd-"))


# --- the workflow --------------------------------------------------------------------------------


async def _serving_connection(workspace: Path) -> ServiceClient:
    """What ``build_service_client`` does for a CLI workflow command on a remote root."""

    locator = WorkspaceLocator(str(workspace))
    binding = await client_module.serving_workspace_binding(locator)
    assert binding is not None and binding.agent is not None
    return await client_module.connect_service(ControlClientKind.CLI, workspace_binding=binding)


async def _start(connection: ServiceClient, workspace: Path) -> Any:  # noqa: ANN401
    request = StartRequest.model_validate(
        {
            **_COMMON,
            "request_id": new_id(IdKind.REQUEST),
            "mode": "create",
            "task_title": "Change the client's app module",
            "requested_view": "compact",
            # Written as the MCP bridge and the CLI write it; the client sends the handle instead.
            "workspace_ref": str(workspace),
            "external_ref": "direct-dial-task",
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


async def _workflow(connection: ServiceClient, workspace: Path) -> tuple[Any, Any]:  # noqa: ANN401
    """start, publish_work, a deterministic check, respond and receipt over ``connection``."""

    started = await _start(connection, workspace)
    frontier = started.frontier
    for request_id, drafts in _publish_batches():
        published: Any = (
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
    frontier = checked.result_frontier
    assert checked.findings, checked
    responded: Any = (
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
    return started, await _receipt(connection, started, responded.result_frontier)


@pytest.mark.parametrize("kind", ["https", "ssh"])
async def test_a_remote_task_runs_end_to_end_through_the_direct_dial_transport(
    kind: str,
    tmp_path: Path,
    spy: _Spy,  # noqa: F811
    service: _Service,  # noqa: F811
    agent: type[_Recorded],
    forbid_local: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del forbid_local
    workspace = tmp_path / "client" / "repo"
    head = _repository(workspace, "app.py", "print('client')\n")
    (workspace / "app.py").write_text("print('client, edited')\n")
    directory = _short_directory()
    try:
        async with _remote(kind, service, monkeypatch, directory) as remote:
            connection = await _serving_connection(workspace)
            try:
                assert connection.workspace_binding == "client_claim"
                handle = connection.workspace_handle
                assert handle is not None and handle.startswith("client:")
                assert connection.transport == kind
                started, receipt = await _workflow(connection, workspace)
            finally:
                await connection.close()
            assert remote.dialled and set(remote.dialled) == {kind}
    finally:
        shutil.rmtree(directory, ignore_errors=True)

    # Every workspace fact came from the client's agent over the transport: the change base the
    # server recorded is the client repository's HEAD, read by the agent.
    assert {"read_task_base", "capture_metadata"} <= set(agent.operations), agent.operations
    assert await _task_base_commit(service, started) == head
    # The server's own adapters were never handed this task's workspace in any form.
    assert all(handle not in entry and str(workspace) not in entry for entry in spy.workspaces), (
        spy.workspaces
    )
    # The receipt says, in fixed words, where the evidence came from and who served it; the
    # client attributes the producing service and the transport it reached it by.
    text = receipt.human_text
    assert type(text) is str
    assert CLIENT_ATTESTED_WORKSPACE_LINE in text
    assert f"Served by FinishUP service {connection.service_instance_id}" in text
    assert str(workspace) not in text and "lab.example" not in text
    attribution = connection_attribution(connection)
    assert attribution is not None
    assert attribution.lines()[1] == (
        f"This client reached FinishUP service {connection.service_instance_id} "
        f"(transport: {kind})."
    )


async def test_a_decoy_at_the_claimed_path_is_never_read(
    tmp_path: Path,
    spy: _Spy,  # noqa: F811
    service: _Service,  # noqa: F811
    agent: type[_Recorded],
    forbid_local: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The hello claims a path where the server finds a decoy; the agent answers from the client.

    Both machines share one disk in process, so the claim is made on the decoy's path while the
    real agent serves the client's repository: had the server read its own disk at the claimed
    path, the decoy's HEAD would be the task's base.
    """

    del forbid_local
    decoy = tmp_path / "work" / "repo"
    decoy_head = _repository(decoy, "decoy.py", "print('decoy')\n")
    workspace = tmp_path / "client" / "repo"
    head = _repository(workspace, "app.py", "print('client')\n")
    (workspace / "app.py").write_text("print('client, edited')\n")
    assert head != decoy_head
    directory = _short_directory()
    try:
        async with _remote("https", service, monkeypatch, directory) as remote:
            import base64

            salt = base64.b64decode(cast(str, remote.target.claim_salt))
            binding = ClientWorkspaceBinding(
                claim=await workspace_claim(WorkspaceLocator(str(decoy)), salt),
                agent=agent(WorkspaceLocator(str(workspace))),
            )
            connection = await client_module.connect_service(
                ControlClientKind.CLI, workspace_binding=binding
            )
            try:
                started, _receipt_result = await _workflow(connection, workspace)
            finally:
                await connection.close()
    finally:
        shutil.rmtree(directory, ignore_errors=True)
    assert await _task_base_commit(service, started) == head
    assert all(
        str(decoy) not in entry and str(workspace) not in entry for entry in spy.workspaces
    ), spy.workspaces


# --- the reviewer's reads, through the transport, and the agent lost mid-review -----------------


async def _review_through(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    service: _Service,  # noqa: F811
    handle: str,
    *replies: Any,  # noqa: ANN401
) -> tuple[Any, Any]:  # noqa: ANN401
    """The reviewer composition harness (``test_claim_bound_sessions._review``) on the daemon's hub.

    The review's workspace is ``handle``, the claim of a live connection that reached the daemon
    through the transport, so every read goes daemon -> transport -> the client's agent.
    """

    from types import SimpleNamespace

    from builders.ledger_adapters import FixedClock, append_command, sqlite_adapter
    from builders.privacy_policies import minimal_external_policy
    from finishup.adapters.memory.privacy import MemoryPrivacyCatalogState
    from finishup.adapters.privacy.local_enforcer import LocalPrivacyEnforcer
    from finishup.application.egress import PrivacyCoordinator
    from finishup.ports.change_capture import CheckWorkspaceSource, check_workspace_source_scope
    from finishup.ports.privacy import EffectivePrivacyPolicy, HumanAuthorityCapability
    from finishup.service.workspace_routing import WorkspaceRouting
    from integration.service import test_reviewer_conversation_composition as reviewer
    from integration.service import test_semantic_non_dispatch as non_dispatch
    from integration.service.test_claim_bound_sessions import SpyLocalCapture

    async def workspace_root(_runtime: object) -> str:
        return handle

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

    routing = WorkspaceRouting.compose(service.hub, SpyLocalCapture())
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
    source = CheckWorkspaceSource(handle, non_dispatch._REPOSITORY)  # pyright: ignore[reportPrivateUsage]
    with check_workspace_source_scope(source):
        return await evaluator(frozen, (), runtime), gateway


def _reviewed_repository(tmp_path: Path) -> Path:
    work = tmp_path / "client" / "work"
    _repository(work, "calc.py", "def add(a, b):\n    return a + b\n")
    (work / ".gitignore").write_text("secret.txt\n")
    (work / "secret.txt").write_text("not for review\n")
    return work


async def test_the_reviewers_reads_are_answered_through_the_gateway_by_the_agent(
    tmp_path: Path,
    service: _Service,  # noqa: F811
    agent: type[_Recorded],
    forbid_local: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from integration.service import test_reviewer_conversation_composition as reviewer

    del forbid_local
    workspace = _reviewed_repository(tmp_path)
    directory = _short_directory()
    try:
        async with _remote("https", service, monkeypatch, directory):
            connection = await _serving_connection(workspace)
            try:
                handle = connection.workspace_handle
                assert handle is not None
                result, gateway = await _review_through(
                    tmp_path,
                    monkeypatch,
                    service,
                    handle,
                    reviewer._read_file("calc.py"),  # pyright: ignore[reportPrivateUsage]
                    reviewer._read_file("secret.txt"),  # pyright: ignore[reportPrivateUsage]
                    reviewer._FINAL,  # pyright: ignore[reportPrivateUsage]
                )
            finally:
                await connection.close()
    finally:
        shutil.rmtree(directory, ignore_errors=True)
    assert result.status.value == "succeeded", (result.status, result.reason)
    _first, _, last = (history for _, history in gateway.exchanges)
    observation = json.loads(last[4][1])
    assert observation["status"] == "ok" and "return a + b" in observation["data"]["text"]
    denied = json.loads(last[6][1])
    assert (denied["status"], denied["reason"]) == ("denied", "forbidden_path")
    # The check-time change, the ignore probe and the read all went to the client's agent.
    assert {"capture", "probe_requested_paths", "read_text_beneath"} <= set(agent.operations)


@pytest.mark.parametrize("kind", ["https", "ssh"])
async def test_the_agent_lost_mid_review_ends_the_review_unavailable_never_a_pass(
    kind: str,
    tmp_path: Path,
    service: _Service,  # noqa: F811
    agent: type[_Recorded],
    forbid_local: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from integration.service import test_reviewer_conversation_composition as reviewer

    del forbid_local
    workspace = _reviewed_repository(tmp_path)
    directory = _short_directory()
    loop = asyncio.get_running_loop()
    try:
        async with _remote(kind, service, monkeypatch, directory):
            connection = await _serving_connection(workspace)
            handle = connection.workspace_handle
            assert handle is not None

            def drop() -> None:
                # The client machine goes away while the reviewer's read is in flight.
                asyncio.run_coroutine_threadsafe(connection.close(), loop)

            agent.drops["read_text_beneath"] = drop
            try:
                result, gateway = await _review_through(
                    tmp_path,
                    monkeypatch,
                    service,
                    handle,
                    reviewer._read_file("calc.py"),  # pyright: ignore[reportPrivateUsage]
                    reviewer._FINAL,  # pyright: ignore[reportPrivateUsage]
                )
            finally:
                await connection.close()
    finally:
        shutil.rmtree(directory, ignore_errors=True)
    assert result.status.value == "unavailable", (result.status, result.reason)
    assert result.judgment is None
    assert result.reviewer is not None
    assert result.reviewer.ended == "workspace_agent_unavailable"
    # The judgment the provider would have given was never asked for.
    assert len(gateway.exchanges) == 1


# --- observation: a hook's row, delivered and verified through the bridge's background agent -----


class _ClientStore:
    """This client's observation store under the selected remote root, as the hooks keep it."""

    def __init__(self, workspace: Path) -> None:
        self.repo = workspace
        (workspace / ".finishup").mkdir()
        (workspace / ".finishup" / "checks.toml").write_text(_POLICY, encoding="utf-8")
        self.path = str(workspace.resolve())
        self.state = state_dir()
        self.store = LocalObservationStore(_state=self.state)
        self.workspace = self.store.workspace_commitment(self.path)
        self.store.grant_consent(self.workspace)
        policy, _raw = load_observation_check_policy(workspace)
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

    def hook(self, event_name: str, payload: dict[str, object]) -> None:
        """One Codex hook pass that captured but could not deliver (it left the row pending)."""

        handle_observe(
            event_name=event_name,
            stdin_bytes=json.dumps({"session_id": _HOST_SESSION, **payload}).encode(),
            stdout=io.BytesIO(),
            workspace=self.path,
            _state=self.state,
            skip_service=True,
        )


async def _until(condition: Callable[[], bool]) -> None:
    deadline = time.monotonic() + _DEADLINE_SECONDS
    while not condition():
        assert time.monotonic() < deadline, "deadline passed before the state was observed"
        await asyncio.sleep(0.02)


async def _history_until(
    connection: ServiceClient, started: Any, condition: Callable[[tuple[Any, ...]], bool]
) -> tuple[Any, ...]:  # noqa: ANN401
    deadline = time.monotonic() + _DEADLINE_SECONDS
    while True:
        status = (
            await connection.status(
                StatusRequest.model_validate(
                    {
                        **_COMMON,
                        "request_id": new_id(IdKind.REQUEST),
                        "session_id": started.session_id,
                        "writer_id": started.writer_id,
                        "view": "history",
                        "limit": "50",
                    }
                )
            )
        ).root
        assert status.ok is True, status
        items: tuple[Any, ...] = tuple(cast(Any, status).page.items)
        if condition(items):
            return items
        assert time.monotonic() < deadline, "deadline passed before the history was observed"
        await asyncio.sleep(0.05)


async def test_a_hook_row_is_delivered_and_verified_through_the_bridges_background_agent(
    tmp_path: Path,
    spy: _Spy,  # noqa: F811
    service: _Service,  # noqa: F811
    agent: type[_Recorded],
    forbid_local: None,
    local_reads: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del forbid_local
    workspace = tmp_path / "client" / "repo"
    _repository(workspace, "app.py", "print('client')\n")
    directory = _short_directory()
    try:
        async with _remote("https", service, monkeypatch, directory):
            client = _ClientStore(workspace)
            connection = await _serving_connection(workspace)
            background = BridgeBackgroundWork()
            try:
                started = await _start(connection, workspace)
                client.map(started)
                (workspace / "app.py").write_text("print('client, edited')\n")
                client.hook(
                    "PostToolUse",
                    {
                        "tool_name": "shell",
                        "exit_status": 1,
                        "correlation_id": "direct-dial-cmd-1",
                        "event_ordinal": 2,
                    },
                )
                assert client.store.pending_outbox_count(client.workspace) >= 1
                # The CLI call ended; only the bridge's background agent serves the workspace now.
                await connection.close()
                background.note_activity(WorkspaceLocator(client.path))
                delivered = await background.run_pass()
                assert delivered.connected and delivered.drained is not None, delivered
                assert delivered.drained.delivery is not None
                assert delivered.drained.delivery.acknowledged >= 1, delivered
                assert client.store.pending_outbox_count(client.workspace) == 0
                # The server verified the row through the background agent: it opened the claimed
                # workspace, read its policy, hashed its state and ran the approved check there.
                await _until(lambda: "run_approved_check" in agent.operations)
                assert {"open_workspace", "load_check_policy", "subject_state_capture"} <= set(
                    agent.operations
                )
                held = background.connection
                assert held is not None
                connection = await _serving_connection(workspace)
                history = await _history_until(
                    connection,
                    started,
                    lambda items: any(item.actor_id == _APPROVED_CHECK_ACTOR for item in items),
                )
                assert any(item.publication_channel == "hook_observed" for item in history)
                status = (
                    await connection.status(
                        StatusRequest.model_validate(
                            {
                                **_COMMON,
                                "request_id": new_id(IdKind.REQUEST),
                                "session_id": started.session_id,
                                "writer_id": started.writer_id,
                                "view": "compact",
                                "limit": "10",
                            }
                        )
                    )
                ).root
                receipt = await _receipt(connection, started, cast(Any, status).head_frontier)
            finally:
                await connection.close()
                await background.aclose()
    finally:
        shutil.rmtree(directory, ignore_errors=True)
    assert local_reads == []
    assert spy.workspaces == []
    text = receipt.human_text
    assert CLIENT_ATTESTED_WORKSPACE_LINE in text
    assert CLIENT_ATTESTED_OBSERVATION_LINE in text
    assert client.path not in text


async def test_a_hooks_claim_only_connection_delivers_an_attested_row(
    tmp_path: Path,
    service: _Service,  # noqa: F811
    agent: type[_Recorded],
    forbid_local: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A hook names its workspace; on a remote root ``service.client`` claims it, without an agent."""

    from finishup.client.observation_outbox import ClientObservationDrain

    del forbid_local
    workspace = tmp_path / "client" / "repo"
    _repository(workspace, "app.py", "print('client')\n")
    directory = _short_directory()
    try:
        async with _remote("ssh", service, monkeypatch, directory):
            client = _ClientStore(workspace)
            serving = await _serving_connection(workspace)
            try:
                started = await _start(serving, workspace)
            finally:
                await serving.close()
            client.map(started)
            client.hook(
                "PostToolUse",
                {"tool_name": "shell", "exit_status": 0, "correlation_id": "c", "event_ordinal": 2},
            )
            hook = await client_module.connect_service(
                ControlClientKind.CLI, workspace_locator=WorkspaceLocator(client.path)
            )
            drain = ClientObservationDrain(WorkspaceLocator(client.path))
            try:
                assert hook.workspace_binding == "client_claim"
                assert hook.workspace_handle is not None
                summary = await drain.drain(hook)
            finally:
                drain.close()
                await hook.close()
    finally:
        shutil.rmtree(directory, ignore_errors=True)
    assert summary.stopped is None, summary
    assert summary.delivery is not None and summary.delivery.acknowledged >= 1, summary
    # The hook's connection offered no agent: it never became the server's agent.
    assert "open_workspace" not in agent.operations


# --- loss of the remote side: typed, remote, never a local fallback ------------------------------


async def test_an_unreachable_gateway_upstream_is_a_typed_remote_phase(
    tmp_path: Path,
    forbid_local: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The gateway cannot reach its daemon: ``remote_service_not_running``, nothing local."""

    del forbid_local
    with ambient_home(monkeypatch) as home:
        with targets.registry_lock():
            record, root = targets.new_remote_target(
                "lab", "https", base_url="https://gateway.test/base"
            )
            targets.write_selection(record)
        reset_selection_memo()

        async def upstream() -> Any:  # noqa: ANN401
            raise ConnectionRefusedError("the daemon is not running")

        gateway = real_gateway(home / "gateway", upstream)
        transport = HttpsTransport(
            record,
            root,
            credential=StaticCredential(gateway.key),
            http_transport=httpx.ASGITransport(app=gateway),
        )

        def chosen(_target: ServerTarget, _root: Path) -> HttpsTransport:
            return transport

        monkeypatch.setattr(transports, "transport_for_target", chosen)
        workspace = tmp_path / "repo"
        workspace.mkdir()
        with pytest.raises(ControlError) as raised:
            await client_module.connect_service_on_demand(
                ControlClientKind.MCP_BRIDGE,
                workspace_locator=WorkspaceLocator(str(workspace)),
                timeout_seconds=5.0,
            )
    error = raised.value
    assert (error.reason, error.retryable, error.phase) == (
        "service_unavailable",
        True,
        "remote_service_not_running",
    )


@pytest.mark.parametrize("kind", ["https", "ssh"])
async def test_a_daemon_that_goes_away_mid_session_is_retryable_and_never_local(
    kind: str,
    tmp_path: Path,
    service: _Service,  # noqa: F811
    agent: type[_Recorded],
    forbid_local: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del forbid_local, agent
    workspace = tmp_path / "client" / "repo"
    _repository(workspace, "app.py", "print('client')\n")
    directory = _short_directory()
    try:
        async with _remote(kind, service, monkeypatch, directory):
            connection = await _serving_connection(workspace)
            try:
                await connection.service_status()
                # The server side ends every connection (a stop, a restart, a lost upstream).
                for task in service.tasks:
                    task.cancel()
                await asyncio.gather(*service.tasks, return_exceptions=True)
                await asyncio.wait_for(connection.wait_closed(), _DEADLINE_SECONDS)
                with pytest.raises(ControlError) as raised:
                    await connection.service_status()
            finally:
                await connection.close()
    finally:
        shutil.rmtree(directory, ignore_errors=True)
    assert (raised.value.reason, raised.value.retryable) == ("service_unavailable", True)
