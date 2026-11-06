"""The workspace agent on a direct-dial connection (ADR-051, approach B).

``serve_workspace_calls`` answers ``workspace_call`` frames with the injected handler and writes
each ``workspace_reply`` back, over any transport — here a memory pair and the HTTPS binding
(frames long-poll in, ``POST …/frames`` out). Until the client workspace track merges,
``remote_workspace_binding`` offers nothing, so no remote connection claims a workspace and the
foreground agent refuses before dialling.
"""

from __future__ import annotations

import asyncio
import threading
from dataclasses import replace
from pathlib import Path

import httpx
import pytest

from builders.direct_dial import (
    AGENT,
    CALL_ID,
    CLAIM,
    COMMITMENT,
    HANDLE,
    SERVICE_ID,
    WORKSPACE_CALL,
    FakeBindingGateway,
    StaticCredential,
    https_target,
    memory_pair,
    service_status,
    ssh_target,
)
from finishup.client import agent_session
from finishup.client.agent_session import (
    NO_BINDING,
    AgentSessionError,
    RemoteWorkspaceBinding,
    open_agent_session,
    remote_workspace_binding,
    run_foreground_agent,
    serve_workspace_calls,
)
from finishup.client.transports import HttpsTransport
from finishup.ports.control import (
    RepositoryPrivacyContext,
    WorkspaceCall,
    WorkspaceClaim,
    WorkspaceLocator,
    WorkspaceReply,
)
from finishup.service.control_protocol import (
    ControlProtocolError,
    ControlStream,
    client_handshake,
    parse_workspace_reply,
    read_control_frame,
    server_handshake,
    write_workspace_call,
)

_SECOND_CALL = "rpc_00000000-0000-4000-8000-0000000000c2"


class _Answers:
    """A handler double: records each call in its worker thread and answers ``unavailable``."""

    def __init__(self) -> None:
        self.seen: list[tuple[str, str | None, bool]] = []

    def __call__(self, call: WorkspaceCall, handle: str | None) -> WorkspaceReply:
        on_loop_thread = threading.current_thread() is threading.main_thread()
        self.seen.append((call.call_id, handle, on_loop_thread))
        return WorkspaceReply(
            kind="workspace_reply",
            protocol_version="1.0",
            call_id=call.call_id,
            outcome="unavailable",
            result=None,
            reason="workspace_unavailable",
        )


async def _claiming_server(stream: ControlStream, calls: tuple[WorkspaceCall, ...]) -> list[str]:
    """Handshake a claim-bound agent session, send ``calls``, collect the replies, then close."""

    async def resolve(_claim: WorkspaceClaim) -> RepositoryPrivacyContext:
        return RepositoryPrivacyContext(COMMITMENT, "client_claim")

    session = await server_handshake(
        stream, stream.peer_identity, service_status(), claim_context_resolver=resolve
    )
    assert session.workspace_agent == AGENT
    for call in calls:
        await write_workspace_call(stream, call)
    replies = [parse_workspace_reply(await read_control_frame(stream)).call_id for _call in calls]
    await stream.aclose()
    return replies


def test_a_binding_is_all_or_nothing() -> None:
    with pytest.raises(ValueError, match="remote_workspace_binding_incomplete"):
        RemoteWorkspaceBinding(CLAIM, None, None)
    assert not NO_BINDING.declares_agent


def test_no_remote_connection_claims_a_workspace_before_the_client_track_merges() -> None:
    binding = asyncio.run(
        remote_workspace_binding(ssh_target(), WorkspaceLocator("/home/owner/repository"))
    )
    assert binding is NO_BINDING


def test_workspace_calls_are_answered_in_worker_threads_and_replied_in_order() -> None:
    answers = _Answers()
    second = replace(WORKSPACE_CALL, call_id=_SECOND_CALL)

    async def exercise() -> list[str]:
        client, server = memory_pair()
        serving = asyncio.create_task(_claiming_server(server, (WORKSPACE_CALL, second)))
        session = await client_handshake(
            client,
            agent_session.ControlClientKind.CLI,
            "0.3.0",
            workspace_claim=CLAIM,
            workspace_agent=AGENT,
        )
        await serve_workspace_calls(client, session, answers)
        return await serving

    replies = asyncio.run(exercise())
    assert sorted(replies) == sorted([CALL_ID, _SECOND_CALL])
    assert sorted(answers.seen) == sorted([(CALL_ID, HANDLE, False), (_SECOND_CALL, HANDLE, False)])


def test_a_call_of_another_service_instance_ends_the_loop() -> None:
    stranger = replace(WORKSPACE_CALL, service_instance_id=SERVICE_ID.replace("b1", "b2"))

    async def exercise() -> None:
        client, server = memory_pair()
        asyncio.create_task(_claiming_server(server, (stranger,)))
        session = await client_handshake(
            client,
            agent_session.ControlClientKind.CLI,
            "0.3.0",
            workspace_claim=CLAIM,
            workspace_agent=AGENT,
        )
        await serve_workspace_calls(client, session, _Answers())

    with pytest.raises(ControlProtocolError) as raised:
        asyncio.run(exercise())
    assert raised.value.reason == "frame_invalid"


def test_an_agent_connection_serves_calls_through_the_https_binding() -> None:
    answers = _Answers()
    replies: list[list[str]] = []

    async def upstream() -> ControlStream:
        gateway_end, server_end = memory_pair()

        async def serve() -> None:
            replies.append(await _claiming_server(server_end, (WORKSPACE_CALL,)))

        asyncio.get_running_loop().create_task(serve())
        return gateway_end

    gateway = FakeBindingGateway(upstream)
    transport = HttpsTransport(
        https_target(),
        Path("/nonexistent"),
        credential=StaticCredential(),
        http_transport=httpx.ASGITransport(app=gateway),
    )
    binding = RemoteWorkspaceBinding(CLAIM, AGENT, answers)

    async def exercise() -> None:
        stream, session = await open_agent_session(transport, binding)
        assert session.workspace_handle == HANDLE
        try:
            await asyncio.wait_for(serve_workspace_calls(stream, session, answers), 10)
        finally:
            await stream.aclose()

    asyncio.run(exercise())
    assert replies == [[CALL_ID]]
    assert answers.seen == [(CALL_ID, HANDLE, False)]
    paths = [(method, path) for method, path, _headers in gateway.requests]
    assert any(method == "GET" and path.endswith("/frames") for method, path in paths)
    assert any(method == "POST" and path.endswith("/frames") for method, path in paths)


def test_an_agent_session_needs_a_binding() -> None:
    transport = HttpsTransport(https_target(), Path("/nonexistent"), credential=StaticCredential())
    with pytest.raises(AgentSessionError) as raised:
        asyncio.run(open_agent_session(transport, NO_BINDING))
    assert raised.value.reason == "workspace_agent_unavailable"


def test_the_foreground_agent_refuses_before_dialling_until_wired(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def never(*_arguments: object) -> object:
        raise AssertionError("no dial without a binding")

    monkeypatch.setattr(agent_session, "transport_for_target", never)
    with pytest.raises(AgentSessionError) as raised:
        asyncio.run(
            run_foreground_agent(
                ssh_target(), Path("/nonexistent"), WorkspaceLocator("/home/owner/repository")
            )
        )
    assert raised.value.reason == "workspace_agent_unavailable"


def test_only_a_remote_root_starts_the_bridges_background_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from builders.server_targets import ambient_home
    from finishup.client import targets
    from finishup.client.agent_session import start_remote_background_work
    from finishup.config.paths import reset_selection_memo

    drained: list[tuple[str, Path]] = []

    async def drain(target: object, root: Path) -> None:
        drained.append((getattr(target, "target_id"), root))

    monkeypatch.setattr(agent_session, "remote_background_drain", drain)

    async def started() -> bool:
        task = start_remote_background_work()
        if task is None:
            return False
        await task
        return True

    with ambient_home(monkeypatch):
        assert asyncio.run(started()) is False  # the everyday server
        with targets.registry_lock():
            local, _local_root = targets.new_local_target("work")
            targets.write_selection(local)
        reset_selection_memo()
        assert asyncio.run(started()) is False  # a named local server
        with targets.registry_lock():
            remote, root = targets.new_remote_target("lab", "https", base_url="https://fu.example")
            targets.write_selection(remote)
        reset_selection_memo()
        assert asyncio.run(started()) is True
    assert drained == [(remote.target_id, root)]
