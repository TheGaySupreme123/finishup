"""``RestServiceClient``: the ``ServiceClient`` interface over the server's network API (ADR-051).

The client runs against the real ``NetworkApi`` in process (``httpx.ASGITransport``) with a fake
daemon behind it: typed methods, the control refusals they raise, the long-poll of a long call,
timeouts that cancel, the socket's generation rule, the remote phases of a failed connection,
and ``connect_service`` choosing this client for a remote target root — never a local spawn.
"""

from __future__ import annotations

import asyncio
import base64
import shutil
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest

from builders.network_api import INSTANCE_ID, FakeHub, FakeService, claim, key_store, make_api
from builders.server_targets import ambient_home
from finishup.client import rest_client
from finishup.client.rest_client import RestEndpoint, RestServiceClient, connect_rest_service
from finishup.client.targets import ServerTarget
from finishup.domain.values import JsonObject
from finishup.ports.control import (
    ControlClientKind,
    ControlError,
    ControlMethod,
    ServiceState,
    WorkspaceLocator,
)
from finishup.service import client as service_client
from finishup.service.api_keys import ApiKeyStore
from finishup.service.client import ClientWorkspaceBinding
from finishup.service.http_api import NetworkApi

_RECORD = ServerTarget(
    "t_0a1b2c3d",
    "lab",
    "https",
    "2026-11-05T00:00:00.000Z",
    base_url="https://api.test",
    claim_salt=base64.b64encode(b"\x01" * 32).decode("ascii"),
    authorized_at="2026-11-05T00:00:00.000Z",
    disclosure_version=1,
)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def keys() -> Iterator[ApiKeyStore]:
    base = Path.home() / f".yz-rest-{id(object())}"
    base.mkdir(mode=0o700)
    try:
        yield key_store(base)
    finally:
        shutil.rmtree(base, ignore_errors=True)


def _endpoint(api: NetworkApi, token: str | None) -> RestEndpoint:
    return RestEndpoint(
        "https",
        "https://api.test",
        httpx.ASGITransport(app=api.asgi("https")),  # type: ignore[arg-type]
        token,
    )


async def _connect(
    api: NetworkApi, token: str, kind: ControlClientKind = ControlClientKind.CLI
) -> RestServiceClient:
    return await connect_rest_service(
        kind, record=_RECORD, root=Path("/nonexistent"), _endpoint=_endpoint(api, token)
    )


@pytest.mark.anyio
async def test_typed_methods_reach_the_service_through_the_api(keys: ApiKeyStore) -> None:
    service = FakeService()
    _record, token = keys.create("laptop", "operator")
    client = await _connect(make_api(service, keys), token)
    try:
        assert client.transport_kind == "https"
        assert client.hello_service_status == service.status()
        assert (client.workspace_binding, client.workspace_handle) == ("none", None)
        status = await client.service_status()
        assert status.state is ServiceState.READY
        locked = await client.lock()
        assert locked.state is ServiceState.LOCKED
    finally:
        await client.close()
    assert [request.method for _kind, request, _context in service.seen] == [
        ControlMethod.SERVICE_STATUS,
        ControlMethod.SERVICE_LOCK,
    ]
    # The client names the generation it read; the server would refuse an older one.
    assert all(request.service_instance_id == INSTANCE_ID for _k, request, _c in service.seen)
    with pytest.raises(ControlError) as raised:
        await client.service_status()
    assert raised.value.reason == "service_unavailable"


@pytest.mark.anyio
async def test_scope_refusals_raise_the_control_error(keys: ApiKeyStore) -> None:
    service = FakeService()
    _record, token = keys.create("laptop", "agent")
    client = await _connect(make_api(service, keys), token)
    try:
        with pytest.raises(ControlError) as raised:
            await client.lock()
        assert (raised.value.reason, raised.value.retryable) == ("method_forbidden", False)
        with pytest.raises(ControlError) as stopped:
            await client.stop()
        assert stopped.value.reason == "method_forbidden"
        with pytest.raises(ControlError, match="method_forbidden"):
            client.owner_receipt_view_target(object())
        # The connection stays usable after a workflow refusal.
        assert (await client.service_status()).service_instance_id == INSTANCE_ID
    finally:
        await client.close()
    assert service.seen[-1][1].method is ControlMethod.SERVICE_STATUS


@pytest.mark.anyio
async def test_a_long_call_is_followed_by_long_poll(
    keys: ApiKeyStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(rest_client, "MAX_WAIT_MS", 20)
    service = FakeService(delay=0.2)
    _record, token = keys.create("laptop", "agent")
    client = await _connect(make_api(service, keys), token)
    try:
        assert (await client.service_status()).state is ServiceState.READY
    finally:
        await client.close()
    assert len(service.seen) == 1


@pytest.mark.anyio
async def test_a_deadline_times_out_and_cancels_the_operation(keys: ApiKeyStore) -> None:
    service = FakeService(gate=asyncio.Event())
    api = make_api(service, keys)
    _record, token = keys.create("laptop", "operator")
    client = await _connect(api, token)
    try:
        with pytest.raises(ControlError) as raised:
            await client.privacy_get_setup(JsonObject({"schema_version": "2.0.0"}), deadline_ms=100)
        assert (raised.value.reason, raised.value.retryable) == ("request_timeout", True)
        (operation,) = api._operations.values()  # pyright: ignore[reportPrivateUsage]
        # The cancelled call finished: only its answer is kept.
        async with asyncio.timeout(10):
            while operation.answer is None:
                await asyncio.sleep(0.01)
        assert operation.task is None
    finally:
        await client.close()
        await api.close()


@pytest.mark.anyio
async def test_a_generation_change_retires_the_client_like_the_socket(keys: ApiKeyStore) -> None:
    service = FakeService()
    _record, token = keys.create("laptop", "agent")
    client = await _connect(make_api(service, keys), token)
    service.generation = "8"
    with pytest.raises(ControlError) as raised:
        await client.service_status()
    assert (raised.value.reason, raised.value.retryable) == ("service_unavailable", True)
    with pytest.raises(ControlError, match="service_unavailable"):
        await client.service_status()


@pytest.mark.anyio
async def test_connection_failures_carry_a_remote_phase(
    keys: ApiKeyStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    api = make_api(FakeService(), keys)
    record, token = keys.create("laptop", "agent")

    async def phase_of(endpoint: RestEndpoint) -> tuple[str | None, bool]:
        with pytest.raises(ControlError) as raised:
            await connect_rest_service(
                ControlClientKind.CLI, record=_RECORD, root=Path("/x"), _endpoint=endpoint
            )
        assert raised.value.reason == "service_unavailable"
        return raised.value.phase, raised.value.retryable

    assert await phase_of(_endpoint(api, None)) == ("remote_auth_failed", False)
    keys.revoke(record.key_id)
    assert await phase_of(_endpoint(api, token)) == ("remote_auth_failed", False)

    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    unreachable = RestEndpoint("https", "https://api.test", httpx.MockTransport(refuse), "x" * 20)
    assert await phase_of(unreachable) == ("remote_unreachable", True)

    _fresh, fresh_token = keys.create("again", "agent")
    monkeypatch.setattr(rest_client, "schema_manifest_digest", lambda: "sha256:" + "0" * 64)
    assert await phase_of(_endpoint(api, fresh_token)) == ("remote_incompatible", False)


@pytest.mark.anyio
async def test_a_claim_binds_the_client_and_names_its_handle(
    keys: ApiKeyStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = FakeService()
    api = make_api(service, keys, hub=FakeHub())
    _record, token = keys.create("laptop", "agent")
    del monkeypatch
    workspace = claim("repo")
    client = await connect_rest_service(
        ControlClientKind.CLI,
        record=_RECORD,
        root=Path("/x"),
        claim=workspace,
        _endpoint=_endpoint(api, token),
    )
    try:
        assert client.workspace_binding == "client_claim"
        handle = client.workspace_handle
        assert handle is not None and handle.startswith("client:")
        # What client-side attribution reads (``client.attribution``): the answering service and
        # this transport's closed token.
        assert client.service_instance_id == INSTANCE_ID
        assert client.transport == "https"
        await client.service_status()
    finally:
        await client.close()
    context = service.seen[-1][2]
    assert context is not None and context.identity_kind == "client_claim"


@pytest.mark.anyio
async def test_connect_service_uses_the_api_for_a_remote_root_and_never_spawns(
    keys: ApiKeyStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = FakeService()
    api = make_api(service, keys)
    _record, token = keys.create("laptop", "agent")
    noted: list[tuple[Path, str]] = []

    def endpoint_for(_record: ServerTarget, _root: Path) -> RestEndpoint:
        return _endpoint(api, token)

    def note(root: Path, locator: WorkspaceLocator) -> None:
        noted.append((root, locator.path))

    def ensure(_root: Path) -> bool:
        return True

    bound: list[tuple[str, bool]] = []

    async def binding_for(
        locator: WorkspaceLocator | None, *, serve_workspace: bool
    ) -> ClientWorkspaceBinding | None:
        assert locator is not None
        bound.append((locator.path, serve_workspace))
        return ClientWorkspaceBinding(claim("repo"))

    monkeypatch.setattr(service_client, "_remote_target", lambda: (_RECORD, Path("/x/t")))
    monkeypatch.setattr(rest_client, "rest_endpoint_for", endpoint_for)
    monkeypatch.setattr("finishup.client.agent.note_workspace", note)
    monkeypatch.setattr("finishup.client.agent.ensure_agent", ensure)
    monkeypatch.setattr("finishup.client.remote_binding.binding_for_active_root", binding_for)

    def no_spawn() -> object:
        raise AssertionError("a remote target never spawns a local service")

    monkeypatch.setattr(service_client, "_spawn_service_process", no_spawn)
    plain = await service_client.connect_service(ControlClientKind.CLI)
    on_demand = await service_client.connect_service_on_demand(
        ControlClientKind.UI, workspace_locator=WorkspaceLocator("/srv/me/repo")
    )
    try:
        assert type(plain) is RestServiceClient and type(on_demand) is RestServiceClient
        assert (await on_demand.service_status()).service_instance_id == INSTANCE_ID
    finally:
        await plain.close()
        await on_demand.close()
    # The locator is bound at the connect seam (a claim only: the target's agent answers) and
    # noted for this target's agent, again once the server answered (so an agent waiting out a
    # retry registers now); its path stays on this machine.
    assert bound == [("/srv/me/repo", False)]
    assert noted == [(Path("/x/t"), "/srv/me/repo")] * 2
    assert on_demand.workspace_binding == "client_claim"
    assert plain.workspace_binding == "none"
    assert service.seen[-1][0] is ControlClientKind.UI
    assert service.seen[-1][2] is not None


def test_local_roots_keep_the_socket_path(monkeypatch: pytest.MonkeyPatch) -> None:
    with ambient_home(monkeypatch):
        assert service_client._remote_target() is None  # pyright: ignore[reportPrivateUsage]


def test_a_named_local_target_keeps_the_socket_path(monkeypatch: pytest.MonkeyPatch) -> None:
    from finishup.client import targets

    with ambient_home(monkeypatch):
        with targets.registry_lock():
            record, _root = targets.new_local_target("work")
        targets.write_selection(record)
        assert service_client._remote_target() is None  # pyright: ignore[reportPrivateUsage]


def test_a_remote_target_root_is_recognized(monkeypatch: pytest.MonkeyPatch) -> None:
    from finishup.client import targets

    with ambient_home(monkeypatch):
        with targets.registry_lock():
            record, root = targets.new_remote_target("lab", "https", base_url="https://lab.example")
        targets.write_selection(record)
        remote = service_client._remote_target()  # pyright: ignore[reportPrivateUsage]
        assert remote is not None
        assert (remote[0].target_id, remote[1]) == (record.target_id, root)


class _Interrupting(httpx.AsyncBaseTransport):
    """The API in process, with one chosen request's answer lost after it was sent."""

    def __init__(self, api: NetworkApi, lose: str, error: type[httpx.TransportError]) -> None:
        self._inner = httpx.ASGITransport(app=api.asgi("https"))  # type: ignore[arg-type]
        self._lose = lose
        self._error = error

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if f"{request.method} {request.url.path}".startswith(self._lose):
            if self._error in (httpx.ConnectError, httpx.ConnectTimeout):
                raise self._error("never sent", request=request)
            # The server got the request (and may have run it); its answer is lost.
            await self._inner.handle_async_request(request)
            raise self._error("answer lost", request=request)
        return await self._inner.handle_async_request(request)


async def _connect_through(
    api: NetworkApi, token: str, transport: _Interrupting
) -> RestServiceClient:
    endpoint = RestEndpoint("https", "https://api.test", transport, token)
    return await connect_rest_service(
        ControlClientKind.CLI, record=_RECORD, root=Path("/x"), _endpoint=endpoint
    )


@pytest.mark.anyio
async def test_a_call_whose_answer_was_lost_after_sending_has_an_unknown_outcome(
    keys: ApiKeyStore,
) -> None:
    # "Nothing was recorded" is said only of calls that never reached the server. A call that
    # was sent (and may have run) and whose answer was lost is outcome-unknown: the timeout's
    # continuation then says how to recover it under its own identity.
    _record, token = keys.create("laptop", "operator")
    service = FakeService()
    for error in (httpx.ReadError, httpx.RemoteProtocolError, httpx.WriteError):
        api = make_api(service, keys)
        client = await _connect_through(api, token, _Interrupting(api, "POST /v1/", error))
        with pytest.raises(ControlError) as raised:
            await client.service_status()
        assert (raised.value.reason, raised.value.phase) == ("request_timeout", None), error
        assert raised.value.retryable is True
    # Never sent: a remote phase, and nothing was dispatched.
    seen = len(service.seen)
    api = make_api(service, keys)
    client = await _connect_through(api, token, _Interrupting(api, "POST /v1/", httpx.ConnectError))
    with pytest.raises(ControlError) as refused:
        await client.service_status()
    assert (refused.value.reason, refused.value.phase) == (
        "service_unavailable",
        "remote_unreachable",
    )
    assert len(service.seen) == seen


@pytest.mark.anyio
async def test_an_admitted_call_whose_long_poll_fails_has_an_unknown_outcome(
    keys: ApiKeyStore,
) -> None:
    _record, token = keys.create("laptop", "operator")
    gate = asyncio.Event()
    service = FakeService(gate=gate)
    api = make_api(service, keys)
    # Even a connection failure on the long-poll: the call was admitted and may finish.
    client = await _connect_through(
        api, token, _Interrupting(api, "GET /v1/operations/", httpx.ConnectError)
    )
    original = rest_client.MAX_WAIT_MS
    try:
        rest_client.MAX_WAIT_MS = 0  # type: ignore[misc]
        with pytest.raises(ControlError) as raised:
            await client.service_status()
    finally:
        rest_client.MAX_WAIT_MS = original  # type: ignore[misc]
        gate.set()
    assert (raised.value.reason, raised.value.phase) == ("request_timeout", None)
    # The server admitted it: the call runs on there whatever this client concluded.
    assert len(api._operations) == 1  # pyright: ignore[reportPrivateUsage]
    await api.close()


@pytest.mark.anyio
async def test_refusals_name_what_the_server_said_not_a_stopped_service(
    keys: ApiKeyStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    from finishup.service.network_protocol import rest_error_document

    def refusal(reason: str, status: int) -> httpx.Response:
        return httpx.Response(status, content=rest_error_document(reason))

    unusable = rest_client._refusal_error(refusal("server_keys_unusable", 503))  # pyright: ignore[reportPrivateUsage]
    assert (unusable.reason, unusable.phase, unusable.retryable) == (
        "service_unavailable",
        "remote_auth_failed",
        False,
    )
    internal = rest_client._refusal_error(refusal("internal_failure", 500))  # pyright: ignore[reportPrivateUsage]
    assert (internal.reason, internal.phase) == ("internal_error", None)
    busy = rest_client._refusal_error(refusal("operation_limit", 429))  # pyright: ignore[reportPrivateUsage]
    assert (busy.reason, busy.phase) == ("request_timeout", None)
    spent = rest_client._refusal_error(refusal("operation_unknown", 404))  # pyright: ignore[reportPrivateUsage]
    assert (spent.reason, spent.phase) == ("request_timeout", None)
    # A call refused only because this key has too many running operations is sent again.
    _record, token = keys.create("laptop", "operator")
    api = make_api(FakeService(), keys)
    calls: list[str] = []
    real = api._admit  # pyright: ignore[reportPrivateUsage]

    async def admit(*args: object, **kwargs: object) -> object:
        calls.append("admit")
        if len(calls) < 3:
            from finishup.service import http_api

            raise http_api._Refusal("operation_limit")  # pyright: ignore[reportPrivateUsage]
        return await real(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(api, "_admit", admit)
    monkeypatch.setattr(rest_client, "_BUSY_FIRST_SECONDS", 0.01)
    client = await _connect(api, token)
    try:
        status = await client.service_status()
    finally:
        await client.close()
    assert status.state is ServiceState.READY
    assert calls == ["admit", "admit", "admit"]
