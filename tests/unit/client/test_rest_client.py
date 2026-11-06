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
        await asyncio.sleep(0.05)
        (operation,) = api._operations.values()  # pyright: ignore[reportPrivateUsage]
        assert operation.task.done()
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
    workspace = claim("repo")

    async def claim_for(record: ServerTarget, locator: WorkspaceLocator) -> object:
        assert record is _RECORD and locator.path == "/home/me/repo"
        return workspace

    monkeypatch.setattr("finishup.client.remote_workspace.claim_for_workspace", claim_for)
    client = await connect_rest_service(
        ControlClientKind.CLI,
        record=_RECORD,
        root=Path("/x"),
        workspace_locator=WorkspaceLocator("/home/me/repo"),
        _endpoint=_endpoint(api, token),
    )
    try:
        assert client.workspace_binding == "client_claim"
        handle = client.workspace_handle
        assert handle is not None and handle.startswith("client:")
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

    monkeypatch.setattr(service_client, "_remote_target", lambda: (_RECORD, Path("/x/t")))
    monkeypatch.setattr(rest_client, "rest_endpoint_for", endpoint_for)
    monkeypatch.setattr("finishup.client.agent.note_workspace", note)
    monkeypatch.setattr("finishup.client.agent.ensure_agent", ensure)

    def no_spawn() -> object:
        raise AssertionError("a remote target never spawns a local service")

    monkeypatch.setattr(service_client, "_spawn_service_process", no_spawn)
    plain = await service_client.connect_service(ControlClientKind.CLI)
    on_demand = await service_client.connect_service_on_demand(
        ControlClientKind.UI, workspace_locator=WorkspaceLocator("/home/me/repo")
    )
    try:
        assert type(plain) is RestServiceClient and type(on_demand) is RestServiceClient
        assert (await on_demand.service_status()).service_instance_id == INSTANCE_ID
    finally:
        await plain.close()
        await on_demand.close()
    # The workspace is noted for this target's agent; its path stays on this machine.
    assert noted == [(Path("/x/t"), "/home/me/repo")]
    assert service.seen[-1][0] is ControlClientKind.UI


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
