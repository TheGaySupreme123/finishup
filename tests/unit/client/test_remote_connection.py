"""End to end over an in-memory connection: a claim-bound client never sends a path, and its agent
answers the server's workspace calls with the local adapter's own result."""

from __future__ import annotations

import asyncio
import os
import subprocess
from collections.abc import Buffer
from pathlib import Path
from typing import cast

import pytest

from finishup.adapters.control.unix_socket import AuthenticatedUnixStream
from finishup.adapters.git_change_capture import GitChangeCaptureAdapter
from finishup.client.workspace_agent import WorkspaceAgentHandler
from finishup.client.workspace_claim import workspace_claim
from finishup.client.workspace_ref import start_request_for_connection
from finishup.domain.values import JsonObject
from finishup.ports.control import (
    ControlClientKind,
    RepositoryPrivacyContext,
    ServiceState,
    ServiceStatus,
    WorkspaceCall,
    WorkspaceClaim,
    WorkspaceLocator,
)
from finishup.ports.workspace_agent import (
    WorkspaceOnlyArguments,
    WorkspaceOperation,
    operation_spec,
)
from finishup.protocol.ids import IdKind, new_id
from finishup.protocol.models import StartRequest
from finishup.service import client as client_module
from finishup.service.client import ClientWorkspaceBinding, connect_service
from finishup.service.control_protocol import (
    parse_workspace_reply,
    read_control_frame,
    server_handshake,
    write_workspace_call,
)

_SERVICE_ID = "svc_00000000-0000-4000-8000-000000000071"
_COMMITMENT = "hmac-sha256:" + "c0ffee" * 10 + "abcd"
_GIT_ENV = {
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": os.defpath,
}


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(autouse=True)
def isolated_global_git(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    monkeypatch.setenv("HOME", os.fspath(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)


class _MemoryStream:
    def __init__(self, peer_identity: object) -> None:
        self.peer_identity = peer_identity
        self.other: _MemoryStream | None = None
        self.closed = False
        self.sent = bytearray()
        self._chunks: asyncio.Queue[bytes] = asyncio.Queue()
        self._buffer = bytearray()

    async def receive(self, max_bytes: int) -> bytes:
        while not self._buffer:
            chunk = await self._chunks.get()
            if not chunk:
                return b""
            self._buffer.extend(chunk)
        chunk = bytes(self._buffer[:max_bytes])
        del self._buffer[:max_bytes]
        return chunk

    async def send_all(self, data: Buffer) -> None:
        assert self.other is not None
        self.sent.extend(bytes(data))
        await self.other._chunks.put(bytes(data))

    async def aclose(self) -> None:
        if not self.closed:
            self.closed = True
            if self.other is not None:
                self.other._chunks.put_nowait(b"")


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


def _repository(tmp_path: Path) -> Path:
    root = tmp_path / "private-project"
    root.mkdir(mode=0o700)
    for arguments in (
        ("init", "--quiet"),
        (
            "-c",
            "user.name=T",
            "-c",
            "user.email=t@finishup.invalid",
            "commit",
            "--allow-empty",
            "--quiet",
            "-m",
            "initial",
        ),
    ):
        subprocess.run(
            ("git", *arguments),
            cwd=root,
            check=True,
            capture_output=True,
            env={**_GIT_ENV, "HOME": os.fspath(root)},
        )
    return root.resolve()


@pytest.mark.anyio
async def test_a_claim_bound_connection_sends_no_path_and_answers_workspace_calls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = _repository(tmp_path)
    locator = WorkspaceLocator(os.fspath(repository))
    claim = await workspace_claim(locator, bytes(range(32)))
    handler = WorkspaceAgentHandler(locator, protected=(os.fspath(tmp_path / "state"),))

    client_peer, service_peer = object(), object()
    client_stream, server_stream = _MemoryStream(service_peer), _MemoryStream(client_peer)
    client_stream.other, server_stream.other = server_stream, client_stream
    resolved: list[WorkspaceClaim] = []

    async def resolve(seen: WorkspaceClaim) -> RepositoryPrivacyContext:
        resolved.append(seen)
        return RepositoryPrivacyContext(_COMMITMENT, "client_claim")

    async def connect() -> AuthenticatedUnixStream:
        return cast(AuthenticatedUnixStream, client_stream)

    monkeypatch.setattr(client_module, "connect_control", connect)
    client, server = await asyncio.gather(
        connect_service(
            ControlClientKind.CLI, workspace_binding=ClientWorkspaceBinding(claim, handler)
        ),
        server_handshake(server_stream, client_peer, _status(), claim_context_resolver=resolve),
    )
    try:
        assert resolved == [claim]
        assert server.workspace_binding == client.workspace_binding == "client_claim"
        assert server.workspace_agent == handler.declaration
        handle = server.workspace_handle
        assert handle is not None
        assert handle == "client:" + _COMMITMENT.removeprefix("hmac-sha256:")[:16]
        assert client.workspace_handle == handle

        spec = operation_spec(WorkspaceOperation.READ_TASK_BASE)
        assert spec is not None
        call = WorkspaceCall(
            kind="workspace_call",
            protocol_version="1.0",
            call_id=new_id(IdKind.CONTROL_RPC),
            service_instance_id=_SERVICE_ID,
            service_generation="1",
            operation=WorkspaceOperation.READ_TASK_BASE.value,
            arguments=JsonObject(spec.encode_arguments(WorkspaceOnlyArguments(handle))),
            deadline_ms=30_000,
        )
        await write_workspace_call(server_stream, call)
        reply = parse_workspace_reply(await read_control_frame(server_stream))
        assert (reply.call_id, reply.outcome, reply.reason) == (call.call_id, "ok", None)
        base = spec.decode_result(reply.result)
        assert base == GitChangeCaptureAdapter(admitted_home_project=True).read_task_base(
            os.fspath(repository)
        )

        start = StartRequest.model_validate(
            {
                "protocol_version": "0.1",
                "schema_version": "1.0.0",
                "request_id": new_id(IdKind.REQUEST),
                "actor": {"actor_id": "harness:cli", "actor_type": "harness"},
                "client": {"kind": "yoetz_cli", "version": "0.1.0", "integration": "local_cli"},
                "mode": "create_or_attach",
                "task_title": "Remote task",
                "requested_view": "compact",
                "workspace_ref": os.fspath(repository),
                "external_ref": "host-session:1",
            }
        )
        assert start_request_for_connection(start, client).workspace_ref == handle
    finally:
        await client.close()

    # Nothing the client wrote names the workspace: the hello carried the claim only.
    sent = bytes(client_stream.sent)
    assert sent
    assert os.fsencode(repository) not in sent
    assert b"private-project" not in sent
