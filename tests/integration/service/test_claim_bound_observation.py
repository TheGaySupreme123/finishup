"""Observation from a remote target's hooks, over a claim-bound connection (ADR-051 decision 12).

A real daemon with a real vault and the real ready composition (``test_claim_bound_sessions``)
serves the real client: ``ServiceClient`` with a workspace claim and the real
``WorkspaceAgentHandler``. The client's own observation store lives under a separate root, as on
another machine: consent, the trusted check policy, the lifecycle mapping and the outbox are
there, and every commitment in a row was made under the client's key, which the server never
sees. The real ``ClientObservationDrain`` delivers what a Codex hook captured. The server accepts
the row as client-attested, verifies it by running the approved check through the agent, never
reads the workspace itself, and says so in the receipt.
"""

from __future__ import annotations

import asyncio
import io
import json
import os
import shutil
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any, cast

import pytest

from finishup.adapters.integrations.codex_lifecycle import (
    load_mapping,
    mapping_from_start_ids,
    store_mapping,
)
from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.application.observation_check_policy import load_observation_check_policy
from finishup.application.observation_claims import CLAIM_OBSERVATION_DIRECTORY
from finishup.application.observation_workspace import LocalObservationWorkspace
from finishup.cli.observe_hooks import handle_observe
from finishup.client.observation_outbox import ClientObservationDrain
from finishup.client.workspace_agent import WorkspaceAgentHandler
from finishup.client.workspace_claim import workspace_claim
from finishup.client.workspace_ref import start_request_for_connection
from finishup.domain.observation import (
    ObservationIngestRequest,
    observation_ingest_request_to_json,
    observation_ingest_result_from_json,
)
from finishup.domain.receipts import (
    CLIENT_ATTESTED_OBSERVATION_LINE,
    CLIENT_ATTESTED_WORKSPACE_LINE,
)
from finishup.ports.check_sandbox import CheckSandboxLaunch, CheckSandboxStatus
from finishup.ports.control import (
    ControlClientKind,
    ControlError,
    ControlMethod,
    WorkspaceAgentDeclaration,
    WorkspaceCall,
    WorkspaceLocator,
    WorkspaceReply,
)
from finishup.protocol.ids import IdKind, new_id
from finishup.protocol.models import ReceiptRequest, StartRequest, StatusRequest
from finishup.service import client as client_module
from finishup.service.client import ClientWorkspaceBinding, ServiceClient, connect_service
from integration.service.test_claim_bound_sessions import (  # noqa: F401 - fixtures
    _COMMON,  # pyright: ignore[reportPrivateUsage]
    _frontier,  # pyright: ignore[reportPrivateUsage]
    _pair,  # pyright: ignore[reportPrivateUsage]
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

_SALT = b"s" * 32
_HOST_SESSION = "codex-remote-session-1"
_TRUE = shutil.which("true", path=os.defpath) or "/usr/bin/true"
_POLICY = (
    'format = "yoetz.approved-check-policy/1"\n\n'
    "[[checks]]\n"
    'id = "unit"\n'
    f'argv = ["{_TRUE}"]\n'
    "timeout_seconds = 10\n"
    "network = false\n"
)
# Waits observe real state (the agent's own call log, the server's answers) and fail on this
# deadline; nothing sleeps to infer success.
_DEADLINE_SECONDS = 30.0
_OBSERVATION_ACTOR = "yoetz:observation-coordinator"
_APPROVED_CHECK_ACTOR = "yoetz:approved-check-service"


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


class _RecordingAgent:
    """The real workspace agent, with the operations it answered recorded in order."""

    def __init__(self, handler: WorkspaceAgentHandler) -> None:
        self._handler = handler
        self.operations: list[str] = []

    @property
    def declaration(self) -> WorkspaceAgentDeclaration:
        return self._handler.declaration

    def answer(self, call: WorkspaceCall, *, workspace_handle: str | None) -> WorkspaceReply:
        self.operations.append(call.operation)
        return self._handler.answer(call, workspace_handle=workspace_handle)


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


@pytest.fixture
def loop_reads(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[str]]:
    """Every observation access built on the event loop's own thread; none may be (ADR-051)."""

    recorded: list[str] = []

    def watch(name: str) -> None:
        original = getattr(LocalObservationWorkspace, name)

        def call(self: object, *args: object, **kwargs: object) -> Any:  # noqa: ANN401
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                recorded.append(name + ":worker")
            else:
                recorded.append(name + ":event_loop")
            return original(self, *args, **kwargs)

        monkeypatch.setattr(LocalObservationWorkspace, name, call)

    # Building the local Git adapter probes the Git version; a client's workspace builds it too.
    for name in ("subject_state", "inspect_port"):
        watch(name)
    yield recorded


class _Client:
    """The client machine: its repository, its own state root and its observation store."""

    def __init__(self, tmp_path: Path) -> None:
        self.repo = tmp_path / "client" / "repo"
        _repository(self.repo, "app.py", "print('client')\n")
        (self.repo / ".finishup").mkdir()
        (self.repo / ".finishup" / "checks.toml").write_text(_POLICY, encoding="utf-8")
        self.path = str(self.repo.resolve())
        self.state = tmp_path / "client-state"
        self.state.mkdir(mode=0o700)
        self.store = LocalObservationStore(_state=self.state)
        self.workspace = self.store.workspace_commitment(self.path)

    def consent(self) -> None:
        self.store.grant_consent(self.workspace)
        policy, _raw = load_observation_check_policy(self.repo)
        self.store.trust_policy_digest(self.workspace, policy.raw_digest)

    def map(self, started: Any) -> None:  # noqa: ANN401
        """What the SessionStart auto-attach stores after a remote ``start``."""

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
        """One Codex hook pass on the client, kept local: capture, bind, enqueue."""

        handle_observe(
            event_name=event_name,
            stdin_bytes=json.dumps({"session_id": _HOST_SESSION, **payload}).encode(),
            stdout=io.BytesIO(),
            workspace=self.path,
            _state=self.state,
            skip_service=True,
        )


async def _connect(
    service: _Service,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
    client: _Client,
    agent: _RecordingAgent | None,
) -> ServiceClient:
    locator = WorkspaceLocator(client.path)
    binding = ClientWorkspaceBinding(
        claim=await workspace_claim(locator, _SALT),
        agent=agent,
    )
    client_stream, server_stream = _pair()
    service.tasks.append(
        asyncio.create_task(
            service.daemon._serve_control_connection(server_stream)  # pyright: ignore[reportPrivateUsage, reportArgumentType]
        )
    )

    async def connect() -> Any:  # noqa: ANN401
        return client_stream

    monkeypatch.setattr(client_module, "connect_control", connect)
    return await connect_service(ControlClientKind.CLI, workspace_binding=binding)


def _agent(client: _Client) -> _RecordingAgent:
    from finishup.client.observation_outbox import check_policy_trusted

    return _RecordingAgent(
        WorkspaceAgentHandler(
            WorkspaceLocator(client.path),
            protected=(str(client.state),),
            check_sandbox=_ReadySandbox(),
            # The client's own store decides approved-check trust (ADR-051 decision 12); here it
            # lives under the client's separate state root, as on another machine.
            check_policy_trust=lambda digest: check_policy_trusted(
                client.path, digest, state=client.state
            ),
        )
    )


async def _start(connection: ServiceClient, client: _Client) -> Any:  # noqa: ANN401
    request = StartRequest.model_validate(
        {
            **_COMMON,
            "request_id": new_id(IdKind.REQUEST),
            "mode": "create",
            "task_title": "Change the client's app module",
            "requested_view": "compact",
            "workspace_ref": client.path,
            "external_ref": "claim-bound-observation",
        }
    )
    started = (await connection.start(start_request_for_connection(request, connection))).root
    assert started.ok is True, started
    return started


async def _status(connection: ServiceClient, started: Any) -> Any:  # noqa: ANN401
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
    assert status.ok is True, status
    return status


async def _history_until(
    connection: ServiceClient,
    started: Any,  # noqa: ANN401
    condition: Callable[[tuple[Any, ...]], bool],
) -> tuple[Any, ...]:
    """The task's history once ``condition`` holds for it; fails on the deadline."""

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


async def _until(condition: Callable[[], bool]) -> None:
    deadline = time.monotonic() + _DEADLINE_SECONDS
    while not condition():
        assert time.monotonic() < deadline, "deadline passed before the state was observed"
        await asyncio.sleep(0.02)


async def test_a_remote_hook_row_is_accepted_verified_through_the_agent_and_attested(
    tmp_path: Path,
    spy: _Spy,  # noqa: F811
    service: _Service,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
    local_reads: list[str],
    loop_reads: list[str],
) -> None:
    client = _Client(tmp_path)
    client.consent()
    agent = _agent(client)
    connection = await _connect(service, monkeypatch, client, agent)
    try:
        handle = connection.workspace_handle
        assert connection.workspace_binding == "client_claim" and handle is not None
        started = await _start(connection, client)
        client.map(started)
        (client.repo / "app.py").write_text("print('client, edited')\n")
        client.hook(
            "PostToolUse",
            {
                "tool_name": "shell",
                "exit_status": 1,
                "correlation_id": "remote-cmd-1",
                "event_ordinal": 2,
            },
        )
        assert client.store.pending_outbox_count(client.workspace) >= 1

        drain = ClientObservationDrain(WorkspaceLocator(client.path), state=client.state)
        try:
            summary = await drain.drain(connection)
        finally:
            drain.close()
        assert summary.stopped is None, summary
        assert summary.delivery is not None and summary.delivery.acknowledged >= 1, summary
        assert client.store.pending_outbox_count(client.workspace) == 0

        # Verification ran on the client: the agent opened the claimed workspace, read its policy,
        # hashed its state and ran the approved check. The server read nothing of its own.
        await _until(lambda: "run_approved_check" in agent.operations)
        assert {"open_workspace", "load_check_policy", "subject_state_capture"} <= set(
            agent.operations
        )
        assert local_reads == []
        assert spy.workspaces == []
        assert "subject_state:worker" in loop_reads
        assert not [read for read in loop_reads if read.endswith(":event_loop")], loop_reads

        # The attested route, consent and commitments were recorded for the claim, in the claim's
        # own store; nothing on the server names the client's path.
        claim_root = service_state(tmp_path) / CLAIM_OBSERVATION_DIRECTORY
        claims = [entry.name for entry in claim_root.iterdir()]
        assert claims == [handle.removeprefix("client:")]
        mapped = load_mapping(_HOST_SESSION, _state=claim_root / claims[0])
        assert mapped is not None and mapped.finishup_task_id == started.task_id
        assert all(client.path.encode() not in path.read_bytes() for path in _files(claim_root))

        # Status shows the client-attested row as hook-observed evidence and the approved check
        # the agent ran as the approved-check service's own record.
        history = await _history_until(
            connection,
            started,
            lambda items: any(item.actor_id == _APPROVED_CHECK_ACTOR for item in items),
        )
        assert any(
            item.actor_id == _OBSERVATION_ACTOR and item.publication_channel == "hook_observed"
            for item in history
        )
        status = await _status(connection, started)
        receipt = (
            await connection.receipt(
                ReceiptRequest.model_validate(
                    {
                        **_COMMON,
                        "request_id": new_id(IdKind.REQUEST),
                        "session_id": started.session_id,
                        "writer_id": started.writer_id,
                        "task_id": started.task_id,
                        "expected_frontier": _frontier(status.head_frontier),
                        "format": "text",
                        "include": "standard",
                        "redaction_profile": "full_local",
                    }
                )
            )
        ).root
        assert receipt.ok is True, receipt
        text = cast(Any, receipt).human_text
        assert type(text) is str
        assert CLIENT_ATTESTED_WORKSPACE_LINE in text
        assert CLIENT_ATTESTED_OBSERVATION_LINE in text
        assert client.path not in text
    finally:
        await connection.close()


async def test_a_claim_bound_row_without_an_attestation_is_refused_consent_missing(
    tmp_path: Path,
    spy: _Spy,  # noqa: F811
    service: _Service,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
    local_reads: list[str],
) -> None:
    client = _Client(tmp_path)
    client.consent()
    connection = await _connect(service, monkeypatch, client, None)
    try:
        started = await _start(connection, client)
        client.map(started)
        client.hook("PostToolUse", {"tool_name": "shell", "exit_status": 0, "event_ordinal": 2})
        rows = client.store.list_pending_outbox_rows(client.workspace)
        assert rows
        # Sent as a client that does not attest: the server holds no consent for a claim.
        raw = await connection.observation_ingest(
            observation_ingest_request_to_json(
                ObservationIngestRequest(rows[0].codex_session_id, rows[0].envelope)
            )
        )
        result = observation_ingest_result_from_json(raw)
        assert (result.disposition.value, result.reason) == ("rejected", "consent_missing")
        claim_root = service_state(tmp_path) / CLAIM_OBSERVATION_DIRECTORY
        assert not claim_root.exists()
        assert local_reads == [] and spy.workspaces == []
    finally:
        await connection.close()


async def test_an_attested_route_outside_the_claim_is_refused_before_any_write(
    tmp_path: Path,
    spy: _Spy,  # noqa: F811
    service: _Service,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A client cannot attest its way into a task another connection opened."""

    del spy
    other = _Client(tmp_path / "other")
    other.consent()
    foreign = await _connect(service, monkeypatch, other, None)
    try:
        foreign_task = await _start(foreign, other)
    finally:
        await foreign.close()
    client = _Client(tmp_path)
    client.consent()
    connection = await _connect(service, monkeypatch, client, None)
    try:
        client.map(foreign_task)
        client.hook("PostToolUse", {"tool_name": "shell", "exit_status": 0, "event_ordinal": 2})
        drain = ClientObservationDrain(WorkspaceLocator(client.path), state=client.state)
        try:
            summary = await drain.drain(connection)
        finally:
            drain.close()
        assert summary.delivery is not None
        assert dict(summary.delivery.reasons).get("consent_missing", 0) >= 1, summary
        assert summary.delivery.acknowledged == 0
        assert not (service_state(tmp_path) / CLAIM_OBSERVATION_DIRECTORY).exists()
    finally:
        await connection.close()


async def test_an_attestation_on_a_connection_without_a_claim_is_malformed(
    tmp_path: Path,
    spy: _Spy,  # noqa: F811
    service: _Service,  # noqa: F811
) -> None:
    """The local path keeps its own checks; a client attestation there is never honoured."""

    del spy
    client = _Client(tmp_path)
    client.consent()
    client.hook("PostToolUse", {"tool_name": "shell", "exit_status": 0, "event_ordinal": 2})
    rows = client.store.list_pending_outbox_rows(client.workspace)
    assert rows
    from finishup.client.observation_attestation import client_attestation

    attestation = client_attestation(
        client.store, client.workspace, rows[0].codex_session_id, state=client.state
    )
    assert attestation is not None
    unbound = await service.connect()
    try:
        answer = await unbound.call(
            ControlMethod.OBSERVATION_INGEST,
            observation_ingest_request_to_json(
                ObservationIngestRequest(
                    rows[0].codex_session_id, rows[0].envelope, client_attestation=attestation
                )
            ),
        )
        assert type(answer) is ControlError and answer.reason == "frame_invalid", answer
    finally:
        await unbound.close()


def service_state(tmp_path: Path) -> Path:
    """The server's state directory in ``test_claim_bound_sessions``'s composition."""

    return tmp_path / "bundle" / "state"


def _files(root: Path) -> list[Path]:
    return [path for path in root.rglob("*") if path.is_file()]


async def test_a_locator_bound_rows_path_is_unchanged(
    tmp_path: Path,
    spy: _Spy,  # noqa: F811
    service: _Service,  # noqa: F811
) -> None:
    """A local hook shares the service's state: its store, key and mapping, exactly as before."""

    del spy
    repo = tmp_path / "local" / "repo"
    _repository(repo, "app.py", "print('local')\n")
    path = str(repo.resolve())
    local = await service.connect(locator=WorkspaceLocator(path))
    try:
        body = {
            **_COMMON,
            "request_id": new_id(IdKind.REQUEST),
            "mode": "create",
            "task_title": "Change the local app module",
            "requested_view": "compact",
            "workspace_ref": path,
            "external_ref": "locator-bound-observation",
        }
        started = (await local.call(ControlMethod.START, StartRequest.model_validate(body))).root
        assert started.ok is True, started
        state = service_state(tmp_path)
        store = LocalObservationStore(_state=state)
        workspace = store.workspace_commitment(path)
        store.grant_consent(workspace)
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
        handle_observe(
            event_name="PostToolUse",
            stdin_bytes=json.dumps(
                {"session_id": _HOST_SESSION, "tool_name": "shell", "exit_status": 0}
            ).encode(),
            stdout=io.BytesIO(),
            workspace=path,
            _state=state,
            skip_service=True,
        )
        rows = store.list_pending_outbox_rows(workspace)
        assert rows
        answer = await local.call(
            ControlMethod.OBSERVATION_INGEST,
            observation_ingest_request_to_json(
                ObservationIngestRequest(rows[0].codex_session_id, rows[0].envelope)
            ),
        )
        result = observation_ingest_result_from_json(answer)
        assert result.disposition.value == "accepted", result
        # The service's own store decided it; no claim store was made.
        assert not (state / CLAIM_OBSERVATION_DIRECTORY).exists()
    finally:
        await local.close()
