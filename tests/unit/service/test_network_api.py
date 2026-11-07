"""The service's network API in process (ADR-051, server-native approach).

Every route is driven through ``httpx.ASGITransport`` against ``NetworkApi`` with a fake daemon
behind its bindings: authentication and its refusals, the ``Origin`` refusal, key scopes, the
claim header keyed by principal, the long-poll of a long call, at-most-once operation ids, the
socket's own generation rule, and the workspace-agent routes against a fake hub.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import socket
from collections.abc import AsyncGenerator, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import httpx
import pytest

from builders.network_api import (
    INSTANCE_ID,
    FakeHub,
    FakeService,
    claim,
    context_for,
    key_store,
    make_api,
)
from finishup.domain.values import JsonObject
from finishup.ports.control import ControlClientKind, ControlMethod, ServiceStatus
from finishup.protocol.canonical import canonical_encode, strict_json_parse
from finishup.protocol.ids import IdKind, new_id
from finishup.service.api_keys import ApiKeyStore
from finishup.service.control_protocol import encode_control_frame
from finishup.service.http_api import NetworkApi, NetworkApiBindings
from finishup.service.network_protocol import (
    AGENT_SCOPE_METHODS,
    NEVER_OVER_NETWORK_METHODS,
    OPERATOR_SCOPE_METHODS,
    OWNER_PRINCIPAL,
    NetworkTransport,
    claim_principal_digest,
    encode_claim_header,
    parse_agent_registration,
    parse_server_info,
)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def keys(tmp_path: Path) -> Iterator[ApiKeyStore]:
    home_dir = Path.home() / f".yz-net-{tmp_path.name}"
    home_dir.mkdir(mode=0o700)
    try:
        yield key_store(home_dir)
    finally:
        import shutil

        shutil.rmtree(home_dir, ignore_errors=True)


@contextlib.asynccontextmanager
async def _client(
    api: NetworkApi, transport: NetworkTransport = "https"
) -> AsyncGenerator[httpx.AsyncClient]:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=api.asgi(transport)),  # type: ignore[arg-type]
        base_url="https://api.test",
    ) as client:
        yield client


def _bearer(token: str) -> dict[str, str]:
    return {"authorization": f"Bearer {token}"}


def _reason(response: httpx.Response) -> str:
    return cast(str, json.loads(response.content)["reason"])


# ``service_status`` takes an empty body; the fake daemon answers it with its status.
_STATUS_BODY = b"{}"


@pytest.mark.anyio
async def test_nothing_answers_without_a_valid_key(keys: ApiKeyStore) -> None:
    api = make_api(FakeService(), keys)
    _record, token = keys.create("laptop", "agent")
    async with _client(api) as client:
        for path, method in (("/v1/server", "GET"), ("/v1/status", "POST"), ("/v1/nope", "GET")):
            missing = await client.request(method, path)
            assert (missing.status_code, _reason(missing)) == (401, "api_key_invalid")
        flipped = "B" if token[20] == "A" else "A"
        wrong = await client.get("/v1/server", headers=_bearer(token[:20] + flipped + token[21:]))
        assert (wrong.status_code, _reason(wrong)) == (401, "api_key_invalid")
        assert token not in wrong.text
        good = await client.get("/v1/server", headers=_bearer(token))
        assert good.status_code == 200


@pytest.mark.anyio
async def test_revoked_and_expired_keys_fail_their_next_request(keys: ApiKeyStore) -> None:
    api = make_api(FakeService(), keys)
    record, token = keys.create("laptop", "agent")
    _old, expired = keys.create(
        "old", "agent", expires_in_days=1, now=datetime.now(UTC) - timedelta(days=2)
    )
    async with _client(api) as client:
        assert (await client.get("/v1/server", headers=_bearer(token))).status_code == 200
        assert keys.revoke(record.key_id) is True
        revoked = await client.get("/v1/server", headers=_bearer(token))
        assert (revoked.status_code, _reason(revoked)) == (401, "api_key_revoked")
        stale = await client.get("/v1/server", headers=_bearer(expired))
        assert (stale.status_code, _reason(stale)) == (401, "api_key_expired")


@pytest.mark.anyio
async def test_any_origin_header_is_refused_before_authentication(keys: ApiKeyStore) -> None:
    api = make_api(FakeService(), keys)
    _record, token = keys.create("laptop", "operator")
    async with _client(api) as client:
        for headers in ({"origin": "https://evil.example"}, {**_bearer(token), "origin": "null"}):
            response = await client.get("/v1/server", headers=headers)
            assert (response.status_code, _reason(response)) == (403, "origin_forbidden")
            assert "evil" not in response.text


@pytest.mark.anyio
async def test_server_info_names_the_key_scope_and_transport(keys: ApiKeyStore) -> None:
    api = make_api(FakeService(), keys)
    record, token = keys.create("laptop", "agent")
    async with _client(api) as client:
        info = parse_server_info((await client.get("/v1/server", headers=_bearer(token))).content)
    assert (info.key_id, info.scope, info.transport) == (record.key_id, "agent", "https")
    assert info.service_instance_id == INSTANCE_ID
    assert (info.workspace_binding, info.workspace_handle) == ("none", None)
    async with _client(api, "unix") as client:
        owner = parse_server_info((await client.get("/v1/server")).content)
    # The owner socket an SSH client forwards to needs no key: SSH is owner-equivalent.
    assert (owner.key_id, owner.scope, owner.transport) == (None, "operator", "unix")


@pytest.mark.anyio
async def test_a_call_answers_the_socket_result_body_byte_for_byte(keys: ApiKeyStore) -> None:
    service = FakeService()
    api = make_api(service, keys)
    _record, token = keys.create("laptop", "agent")
    async with _client(api) as client:
        response = await client.post(
            "/v1/service_status",
            headers={**_bearer(token), "finishup-client-kind": "mcp_bridge"},
            content=b"{}",
        )
    assert response.status_code == 200
    assert response.headers["finishup-outcome"] == "ok"
    kind, request, context = service.seen[-1]
    assert (kind, request.method, context) == (
        ControlClientKind.MCP_BRIDGE,
        ControlMethod.SERVICE_STATUS,
        None,
    )
    assert response.headers["finishup-operation-id"] == request.rpc_id
    # The control socket would frame exactly these body bytes for this result.
    result = await service.dispatch(kind, request, None)
    frame = encode_control_frame(result)
    payload = cast(dict[str, object], strict_json_parse(frame[4:]))
    assert response.content == canonical_encode(payload["body"])  # type: ignore[arg-type]
    assert b'"body":' + response.content in frame


@pytest.mark.anyio
async def test_scopes_bound_methods_with_the_control_refusal(keys: ApiKeyStore) -> None:
    service = FakeService()
    api = make_api(service, keys)
    _agent, agent_token = keys.create("agent", "agent")
    _operator, operator_token = keys.create("ops", "operator")
    async with _client(api) as client:
        for token, method in (
            (agent_token, "service_lock"),
            (agent_token, "privacy_get_setup"),
            (operator_token, "backup_preview"),
            (operator_token, "service_stop"),
            (operator_token, "observation_pause"),
        ):
            response = await client.post(f"/v1/{method}", headers=_bearer(token), content=b"{}")
            assert response.status_code == 200
            assert response.headers["finishup-outcome"] == "error"
            assert json.loads(response.content) == {"code": "method_forbidden", "retryable": False}
        allowed = await client.post(
            "/v1/service_lock", headers=_bearer(operator_token), content=b"{}"
        )
        assert allowed.headers["finishup-outcome"] == "ok"
    # Out-of-scope calls never reach the daemon.
    assert [request.method for _kind, request, _context in service.seen] == [
        ControlMethod.SERVICE_LOCK
    ]


def test_the_scope_tables_match_the_adr() -> None:
    assert {method.value for method in AGENT_SCOPE_METHODS} == {
        "start",
        "publish_work",
        "check",
        "respond",
        "status",
        "receipt",
        "service_status",
        "observation_ingest",
    }
    assert AGENT_SCOPE_METHODS < OPERATOR_SCOPE_METHODS
    assert {method.value for method in NEVER_OVER_NETWORK_METHODS} == {
        "service_stop",
        "backup_preview",
        "backup_execute",
        "restore_preview",
        "restore_execute",
        "migrate_preview",
        "migrate_execute",
        "integration_preview",
        "integration_execute",
        "observation_pause",
        "observation_resume",
        "observation_revoke",
    }


@pytest.mark.anyio
async def test_a_claim_is_keyed_by_the_principal_and_binds_the_call(keys: ApiKeyStore) -> None:
    service = FakeService()
    api = make_api(service, keys)
    record, token = keys.create("laptop", "agent")
    rotated, rotated_token = keys.create("laptop-2", "agent", rotate=record.key_id)
    _other, other_token = keys.create("other", "agent")
    workspace = claim("repo")
    header = {"x-finishup-workspace-claim": encode_claim_header(workspace)}
    async with _client(api) as client:
        handles: list[str | None] = []
        for key in (token, rotated_token, other_token):
            info = parse_server_info(
                (await client.get("/v1/server", headers={**_bearer(key), **header})).content
            )
            assert info.workspace_binding == "client_claim"
            handles.append(info.workspace_handle)
        # A rotated key keeps its principal; another principal reaches another repository.
        assert handles[0] == handles[1] != handles[2]
        expected = context_for(claim_principal_digest(workspace, record.principal))
        assert handles[0] == expected.workspace_handle
        assert rotated.principal == record.principal
        response = await client.post(
            "/v1/service_status", headers={**_bearer(token), **header}, content=_STATUS_BODY
        )
    assert response.headers["finishup-workspace-handle"] == handles[0]
    assert service.seen[-1][2] == expected
    bad = make_api(FakeService(), keys)
    async with _client(bad) as client:
        refused = await client.get(
            "/v1/server", headers={**_bearer(token), "x-finishup-workspace-claim": "/srv/x/repo"}
        )
        assert (refused.status_code, _reason(refused)) == (400, "header_invalid")
        assert "/srv/x" not in refused.text


@pytest.mark.anyio
async def test_observation_ingest_needs_a_resolved_claim(keys: ApiKeyStore) -> None:
    service = FakeService()
    _record, token = keys.create("laptop", "agent")
    async with _client(make_api(service, keys)) as client:
        unbound = await client.post("/v1/observation_ingest", headers=_bearer(token), content=b"{}")
        assert json.loads(unbound.content)["code"] == "method_forbidden"
        bound = await client.post(
            "/v1/observation_ingest",
            headers={**_bearer(token), "x-finishup-workspace-claim": encode_claim_header(claim())},
            content=b"{}",
        )
        # Past the scope gate: the (empty) body itself is what is refused now.
        assert (bound.status_code, _reason(bound)) == (400, "frame_invalid")
    assert service.seen == []


@pytest.mark.anyio
async def test_a_long_call_answers_202_and_its_operation_long_polls(keys: ApiKeyStore) -> None:
    gate = asyncio.Event()
    service = FakeService(gate=gate)
    api = make_api(service, keys)
    _record, token = keys.create("laptop", "agent")
    async with _client(api) as client:
        pending = await client.post(
            "/v1/service_status?wait_ms=0", headers=_bearer(token), content=_STATUS_BODY
        )
        assert pending.status_code == 202
        location = pending.headers["location"]
        operation_id = pending.headers["finishup-operation-id"]
        assert location == f"/v1/operations/{operation_id}"
        assert json.loads(pending.content)["state"] == "pending"
        still = await client.get(f"{location}?wait_ms=10", headers=_bearer(token))
        assert still.status_code == 202
        assert service.active == 1  # the running call holds the daemon's idle shutdown
        poll = asyncio.create_task(client.get(f"{location}?wait_ms=5000", headers=_bearer(token)))
        await asyncio.sleep(0.05)
        gate.set()
        done = await poll
        assert done.status_code == 200
        assert json.loads(done.content)["service_instance_id"] == INSTANCE_ID
        # An answer lost on the way can be fetched again by its id.
        again = await client.get(location, headers=_bearer(token))
        assert again.content == done.content
        _other_record, other_token = keys.create("other", "agent")
        foreign = await client.get(location, headers=_bearer(other_token))
        assert (foreign.status_code, _reason(foreign)) == (404, "operation_unknown")
    assert service.active == 0


@pytest.mark.anyio
async def test_an_operation_id_is_dispatched_at_most_once(keys: ApiKeyStore) -> None:
    service = FakeService()
    api = make_api(service, keys)
    _record, token = keys.create("laptop", "agent")
    operation_id = new_id(IdKind.CONTROL_RPC)
    headers = {**_bearer(token), "finishup-operation-id": operation_id}
    async with _client(api) as client:
        first = await client.post("/v1/service_status", headers=headers, content=_STATUS_BODY)
        second = await client.post("/v1/service_status", headers=headers, content=_STATUS_BODY)
    assert first.content == second.content
    assert len(service.seen) == 1
    assert service.seen[0][1].rpc_id == operation_id


@pytest.mark.anyio
async def test_cancelling_an_operation_ends_its_call(keys: ApiKeyStore) -> None:
    service = FakeService(gate=asyncio.Event())
    api = make_api(service, keys)
    _record, token = keys.create("laptop", "agent")
    async with _client(api) as client:
        pending = await client.post(
            "/v1/respond?wait_ms=0", headers=_bearer(token), content=_STATUS_BODY
        )
        # A respond body that fails its schema is refused before dispatch.
        assert (pending.status_code, _reason(pending)) == (400, "frame_invalid")
        pending = await client.post(
            "/v1/service_status?wait_ms=0", headers=_bearer(token), content=_STATUS_BODY
        )
        location = pending.headers["location"]
        cancelled = await client.delete(location, headers=_bearer(token))
        assert cancelled.status_code == 204
        result = await client.get(f"{location}?wait_ms=2000", headers=_bearer(token))
    assert result.status_code == 200
    assert result.headers["finishup-outcome"] == "error"
    assert json.loads(result.content)["code"] == "request_cancelled"
    await api.close()


@pytest.mark.anyio
async def test_a_call_to_an_earlier_generation_answers_like_the_socket(keys: ApiKeyStore) -> None:
    service = FakeService(generation="8")
    api = make_api(service, keys)
    _record, token = keys.create("laptop", "agent")
    async with _client(api) as client:
        response = await client.post(
            "/v1/service_status",
            headers={
                **_bearer(token),
                "finishup-service-instance": INSTANCE_ID,
                "finishup-service-generation": "7",
            },
            content=_STATUS_BODY,
        )
        half = await client.post(
            "/v1/service_status",
            headers={**_bearer(token), "finishup-service-generation": "7"},
            content=_STATUS_BODY,
        )
    assert json.loads(response.content)["code"] == "service_generation_changed"
    assert (half.status_code, _reason(half)) == (400, "header_invalid")


@pytest.mark.anyio
async def test_bodies_and_routes_are_bounded(keys: ApiKeyStore) -> None:
    api = make_api(FakeService(), keys)
    _record, token = keys.create("laptop", "operator")
    async with _client(api) as client:
        large = await client.post(
            "/v1/service_status", headers=_bearer(token), content=b"{" + b" " * 7_000_000 + b"}"
        )
        assert (large.status_code, _reason(large)) == (413, "frame_too_large")
        not_json = await client.post("/v1/service_status", headers=_bearer(token), content=b"[1]")
        assert (not_json.status_code, _reason(not_json)) == (400, "frame_invalid")
        unknown = await client.post("/v1/teleport", headers=_bearer(token), content=b"{}")
        assert (unknown.status_code, _reason(unknown)) == (404, "route_unknown")
        wrong = await client.put("/v1/server", headers=_bearer(token))
        assert (wrong.status_code, _reason(wrong)) == (405, "method_not_allowed")
        wait = await client.post(
            "/v1/service_status?wait_ms=99999", headers=_bearer(token), content=b"{}"
        )
        assert (wait.status_code, _reason(wait)) == (400, "header_invalid")


# --- workspace agents ----------------------------------------------------------------------


def _declaration() -> bytes:
    return canonical_encode(
        {"max_reply_bytes": 65_536, "operations": ["capture", "inspect"], "schema_version": "1.0.0"}
    )


@pytest.mark.anyio
async def test_agent_routes_carry_calls_and_replies_through_the_hub(keys: ApiKeyStore) -> None:
    service = FakeService()
    hub = FakeHub()
    api = make_api(service, keys, hub=hub)
    _record, token = keys.create("laptop", "agent")
    header = {**_bearer(token), "x-finishup-workspace-claim": encode_claim_header(claim("w"))}
    async with _client(api) as client:
        registered = await client.post("/v1/agents", headers=header, content=_declaration())
        assert registered.status_code == 201
        registration = parse_agent_registration(registered.content)
        assert registered.headers["location"] == f"/v1/agents/{registration.agent_id}"
        assert service.active == 1  # a registered agent holds idle shutdown like a connection
        (channel,) = hub.channels
        assert channel.handle == registration.workspace_handle
        # The hub learns the claim's worktree digest, so it never admits another worktree's agent
        # under this handle.
        assert channel.worktree == claim("w").worktree
        call = asyncio.create_task(hub.call(channel.handle, "inspect", {"x": 1}))
        work = await client.get(
            f"/v1/agents/{registration.agent_id}/work?wait_ms=2000", headers=_bearer(token)
        )
        assert work.status_code == 200
        (frame,) = json.loads(work.content)["calls"]
        assert (frame["kind"], frame["operation"]) == ("workspace_call", "inspect")
        reply = canonical_encode(
            {
                "call_id": frame["call_id"],
                "kind": "workspace_reply",
                "outcome": "ok",
                "protocol_version": "1.0",
                "reason": None,
                "result": {"answered": True},
            }
        )
        delivered = await client.post(
            f"/v1/agents/{registration.agent_id}/replies", headers=_bearer(token), content=reply
        )
        assert delivered.status_code == 202
        answer = await call
        assert answer.result == JsonObject({"answered": True})
        idle = await client.get(
            f"/v1/agents/{registration.agent_id}/work?wait_ms=10", headers=_bearer(token)
        )
        assert json.loads(idle.content)["calls"] == []
        ended = await client.delete(f"/v1/agents/{registration.agent_id}", headers=_bearer(token))
        assert ended.status_code == 204
        gone = await client.get(
            f"/v1/agents/{registration.agent_id}/work?wait_ms=0", headers=_bearer(token)
        )
        assert (gone.status_code, _reason(gone)) == (404, "agent_unknown")
    assert channel.closed
    assert service.active == 0


@pytest.mark.anyio
async def test_agent_registration_needs_a_claim_a_hub_and_a_resolvable_claim(
    keys: ApiKeyStore,
) -> None:
    _record, token = keys.create("laptop", "agent")
    header = {**_bearer(token), "x-finishup-workspace-claim": encode_claim_header(claim())}
    async with _client(make_api(FakeService(), keys, hub=FakeHub())) as client:
        missing = await client.post("/v1/agents", headers=_bearer(token), content=_declaration())
        assert (missing.status_code, _reason(missing)) == (403, "workspace_claim_required")
        bad = await client.post("/v1/agents", headers=header, content=b'{"operations":["x"]}')
        assert (bad.status_code, _reason(bad)) == (400, "frame_invalid")
    for api in (
        make_api(FakeService(), keys, hub=None),
        make_api(FakeService(), keys, hub=FakeHub(), resolve=False),
    ):
        async with _client(api) as client:
            refused = await client.post("/v1/agents", headers=header, content=_declaration())
            assert (refused.status_code, _reason(refused)) == (503, "workspace_agent_unavailable")


@pytest.mark.anyio
async def test_an_agent_whose_lease_ran_out_or_key_was_revoked_is_ended(
    keys: ApiKeyStore,
) -> None:
    now = [100.0]
    hub = FakeHub()
    service = FakeService()
    api = make_api(service, keys, hub=hub, clock=lambda: now[0])
    record, token = keys.create("laptop", "agent")
    _other, other_token = keys.create("other", "agent")
    async with _client(api) as client:
        for key in (token, other_token):
            registered = await client.post(
                "/v1/agents",
                headers={
                    **_bearer(key),
                    "x-finishup-workspace-claim": encode_claim_header(claim()),
                },
                content=_declaration(),
            )
            assert registered.status_code == 201
        assert keys.revoke(record.key_id)
        await api.sweep_once()
        assert [channel.closed for channel in hub.channels] == [True, False]
        now[0] += 61.0
        await api.sweep_once()
        assert all(channel.closed for channel in hub.channels)
    assert service.active == 0
    await api.close()


def test_owner_principal_is_a_fixed_token() -> None:
    assert OWNER_PRINCIPAL == "p_owner"


@pytest.mark.anyio
async def test_an_accepted_tcp_connection_has_nagle_off() -> None:
    # A listener bound with protocol 0 left Nagle on for every accepted connection, so each TLS
    # response waited on the client's delayed ACK (about 40 ms per request, seen in a real run).
    from finishup.config.models import NetworkListenAddress
    from finishup.service.http_api import _bind_tcp  # pyright: ignore[reportPrivateUsage]

    listener = _bind_tcp(NetworkListenAddress("127.0.0.1", 0))
    accepted: asyncio.Future[int] = asyncio.get_running_loop().create_future()

    class _Probe(asyncio.Protocol):
        def connection_made(self, transport: asyncio.BaseTransport) -> None:
            raw = cast(socket.socket, transport.get_extra_info("socket"))
            accepted.set_result(raw.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY))
            transport.close()

    server = await asyncio.get_running_loop().create_server(_Probe, sock=listener)
    async with server:
        port = int(listener.getsockname()[1])
        _reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            assert listener.proto == socket.IPPROTO_TCP
            assert await asyncio.wait_for(accepted, timeout=10.0) != 0
        finally:
            writer.close()


def _start_body(**fields: object) -> bytes:
    body: dict[str, object] = {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "actor": {"actor_id": "harness:pytest", "actor_type": "harness"},
        "client": {
            "kind": "cooperative_agent",
            "version": "0.1.0",
            "integration": "cooperative_mcp",
        },
        "request_id": new_id(IdKind.REQUEST),
        "mode": "create_or_attach",
        "task_title": "Change the app module",
        "requested_view": "compact",
        **fields,
    }
    return canonical_encode(cast(dict[str, object], body))  # type: ignore[arg-type]


@pytest.mark.anyio
async def test_a_network_start_never_names_a_path_and_a_keyed_one_carries_its_claim(
    keys: ApiKeyStore,
) -> None:
    # A key holder that sends a hook-shaped start naming the server owner's path, with or
    # without a claim, never reaches a task by that path: nothing is dispatched.
    service = FakeService()
    _record, token = keys.create("ci", "agent")
    workspace = claim("repo")
    header = {"x-finishup-workspace-claim": encode_claim_header(workspace)}
    path = "/srv/server/proj"
    async with _client(make_api(service, keys)) as client:
        for headers in (_bearer(token), {**_bearer(token), **header}):
            refused = await client.post(
                "/v1/start",
                headers=headers,
                content=_start_body(workspace_ref=path, external_ref="x"),
            )
            assert (refused.status_code, _reason(refused)) == (400, "frame_invalid")
            assert path not in refused.text
        # Another principal's handle is not this request's either.
        foreign = await client.post(
            "/v1/start",
            headers={**_bearer(token), **header},
            content=_start_body(workspace_ref="client:0123456789abcdef", external_ref="x"),
        )
        assert (foreign.status_code, _reason(foreign)) == (400, "frame_invalid")
        # A keyed start without a claim cannot reach tasks keyed to no principal.
        unclaimed = await client.post(
            "/v1/start", headers=_bearer(token), content=_start_body(mode="create")
        )
        assert (unclaimed.status_code, _reason(unclaimed)) == (403, "workspace_claim_required")
        assert service.seen == []
        info = parse_server_info(
            (await client.get("/v1/server", headers={**_bearer(token), **header})).content
        )
        assert info.workspace_handle is not None
        for fields in (
            {"workspace_ref": info.workspace_handle, "external_ref": "x"},
            {"mode": "create"},
        ):
            accepted = await client.post(
                "/v1/start", headers={**_bearer(token), **header}, content=_start_body(**fields)
            )
            assert accepted.status_code == 200
    assert len(service.seen) == 2
    assert all(seen[2] is not None for seen in service.seen)
    # The owner's socket (SSH) may start without a claim, but never by a path.
    owner = FakeService()
    async with _client(make_api(owner, keys), "unix") as client:
        refused = await client.post(
            "/v1/start", content=_start_body(workspace_ref=path, external_ref="x")
        )
        assert (refused.status_code, _reason(refused)) == (400, "frame_invalid")
        accepted = await client.post("/v1/start", content=_start_body(mode="create"))
        assert accepted.status_code == 200
    assert [seen[2] for seen in owner.seen] == [None]


@pytest.mark.anyio
async def test_one_operation_id_sent_twice_at_once_is_dispatched_once(
    keys: ApiKeyStore,
) -> None:
    # Two requests with the same id, the first still sending its body: the second waits for the
    # first's admission and answers with that operation instead of dispatching again.
    service = FakeService()
    api = make_api(service, keys)
    _record, token = keys.create("laptop", "agent")
    operation_id = new_id(IdKind.CONTROL_RPC)
    headers = {**_bearer(token), "finishup-operation-id": operation_id}
    release = asyncio.Event()

    async def slow_body() -> AsyncGenerator[bytes]:
        await release.wait()
        yield _STATUS_BODY

    async with _client(api) as client:
        first = asyncio.create_task(
            client.post("/v1/service_status", headers=headers, content=slow_body())
        )
        second = asyncio.create_task(
            client.post("/v1/service_status", headers=headers, content=_STATUS_BODY)
        )
        await asyncio.sleep(0)
        release.set()
        answers = await asyncio.gather(first, second)
    assert [answer.status_code for answer in answers] == [200, 200]
    assert answers[0].content == answers[1].content
    assert len(service.seen) == 1


@pytest.mark.anyio
async def test_finished_answers_are_bounded_and_a_dropped_id_is_never_dispatched_again(
    keys: ApiKeyStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    import finishup.service.http_api as http_api

    monkeypatch.setattr(http_api, "MAX_RETAINED_OPERATIONS_PER_KEY", 3)
    now = [1_000.0]
    service = FakeService()
    api = make_api(service, keys, clock=lambda: now[0])
    _record, token = keys.create("laptop", "agent")
    ids = [new_id(IdKind.CONTROL_RPC) for _ in range(5)]
    async with _client(api) as client:
        for index, operation_id in enumerate(ids):
            now[0] += 1
            answer = await client.post(
                "/v1/service_status",
                headers={**_bearer(token), "finishup-operation-id": operation_id},
                content=_STATUS_BODY,
            )
            assert answer.status_code == 200, index
        retained = api._operations  # pyright: ignore[reportPrivateUsage]
        # Only the newest three are kept, and only as their answer's bytes.
        assert sorted(retained) == sorted(ids[2:])
        assert all(item.task is None and item.request is None for item in retained.values())
        for dropped in ids[:2]:
            fetched = await client.get(f"/v1/operations/{dropped}", headers=_bearer(token))
            assert (fetched.status_code, _reason(fetched)) == (404, "operation_unknown")
            again = await client.post(
                "/v1/service_status",
                headers={**_bearer(token), "finishup-operation-id": dropped},
                content=_STATUS_BODY,
            )
            assert (again.status_code, _reason(again)) == (404, "operation_unknown")
        assert len(service.seen) == 5
        kept = await client.get(f"/v1/operations/{ids[-1]}", headers=_bearer(token))
        assert kept.status_code == 200
        # Another key reusing a spent id is refused as before, never told about it.
        _other, other_token = keys.create("other", "agent")
        foreign = await client.post(
            "/v1/service_status",
            headers={**_bearer(other_token), "finishup-operation-id": ids[0]},
            content=_STATUS_BODY,
        )
        assert (foreign.status_code, _reason(foreign)) == (400, "header_invalid")


@pytest.mark.anyio
async def test_retained_answers_are_bounded_in_bytes_and_in_all(
    keys: ApiKeyStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    import finishup.service.http_api as http_api

    service = FakeService()
    api = make_api(service, keys)
    _record, token = keys.create("laptop", "agent")
    _other, other_token = keys.create("other", "agent")

    async def call(key: str) -> None:
        answer = await client.post(
            "/v1/service_status",
            headers={**_bearer(key), "finishup-operation-id": new_id(IdKind.CONTROL_RPC)},
            content=_STATUS_BODY,
        )
        assert answer.status_code == 200

    async with _client(api) as client:
        monkeypatch.setattr(http_api, "MAX_RETAINED_OPERATIONS", 3)
        for key in (token, other_token, token, other_token, token):
            await call(key)
        assert len(api._operations) == 3  # pyright: ignore[reportPrivateUsage]
        await call(token)
        size = len(
            cast(
                bytes,
                next(iter(api._operations.values())).answer.body,  # pyright: ignore[reportPrivateUsage, reportOptionalMemberAccess]
            )
        )
        monkeypatch.setattr(http_api, "MAX_RETAINED_RESULT_BYTES", size * 2)
        await call(other_token)
        assert len(api._operations) == 2  # pyright: ignore[reportPrivateUsage]


@pytest.mark.anyio
async def test_expired_answers_are_dropped_on_the_sweeper_too(
    keys: ApiKeyStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    import finishup.service.http_api as http_api

    monkeypatch.setattr(http_api, "_SWEEP_SECONDS", 0.01)
    now = [1_000.0]
    api = make_api(FakeService(), keys, clock=lambda: now[0])
    _record, token = keys.create("laptop", "agent")
    async with _client(api) as client:
        answer = await client.post(
            "/v1/service_status", headers=_bearer(token), content=_STATUS_BODY
        )
        assert answer.status_code == 200
    assert len(api._operations) == 1  # pyright: ignore[reportPrivateUsage]
    # No further request arrives; the sweeper alone drops the answer once it expires.
    now[0] += http_api.OPERATION_RESULT_SECONDS
    async with asyncio.timeout(10):
        while api._operations:  # pyright: ignore[reportPrivateUsage]
            await asyncio.sleep(0.01)
    await api.close()


@pytest.mark.anyio
async def test_an_unusable_key_file_and_a_defect_are_not_a_stopped_service(
    keys: ApiKeyStore,
) -> None:
    _record, token = keys.create("laptop", "agent")
    service = FakeService()
    api = make_api(service, keys)
    async with _client(api) as client:
        keys.path.chmod(0o640)
        try:
            unusable = await client.get("/v1/server", headers=_bearer(token))
        finally:
            keys.path.chmod(0o600)
        assert (unusable.status_code, _reason(unusable)) == (503, "server_keys_unusable")

    def broken() -> ServiceStatus:
        raise RuntimeError("defect")

    defective = NetworkApi(
        NetworkApiBindings(status=broken, dispatch=service.dispatch, activity=service.activity),
        keys,
    )
    async with _client(defective) as client:
        failed = await client.get("/v1/server", headers=_bearer(token))
    assert (failed.status_code, _reason(failed)) == (500, "internal_failure")
    assert "defect" not in failed.text
