"""Transport-only MCP bridge behavior across local-service outcomes."""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from collections.abc import Awaitable, Callable, Iterator
from pathlib import Path
from typing import Any, cast

import anyio
import pytest
from mcp import types
from mcp.shared.message import SessionMessage
from pydantic import BaseModel, FileUrl

import yoetz.mcp.server as bridge
from yoetz.config.models import LoggingConfig
from yoetz.domain.closure import PREPARATION_REMEDIATIONS
from yoetz.mcp.resources import GuidancePageAssembler, read_resource
from yoetz.observability.diagnostics import append_diagnostic_record, lookup_diagnostic_records
from yoetz.observability.logging import LogMode, configure_logging
from yoetz.ports.control import ControlError, WorkspaceLocator
from yoetz.protocol.canonical import JsonValue, canonical_encode
from yoetz.protocol.errors import PublicErrorCode, PublicOperationError
from yoetz.protocol.models import (
    CheckRequest,
    CheckResult,
    PublicRequestModel,
    PublishWorkRequest,
    PublishWorkResult,
    ReceiptRequest,
    ReceiptResult,
    RespondRequest,
    RespondResult,
    StartRequest,
    StartResult,
    StatusRequest,
    StatusResult,
)
from yoetz.service.client import _AcceptedServiceUnresponsive  # pyright: ignore[reportPrivateUsage]

_PREFIXES = {
    "request": "req_",
    "task": "tsk_",
    "session": "ses_",
    "writer": "wri_",
    "finding": "fnd_",
    "event": "evt_",
}


def _id(kind: str, seed: int) -> str:
    return f"{_PREFIXES[kind]}00000000-0000-4000-8000-{seed:012d}"


def _base(seed: int) -> dict[str, JsonValue]:
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": _id("request", seed),
        "actor": {"actor_id": "harness:mcp", "actor_type": "harness"},
        "client": {
            "kind": "cooperative_agent",
            "version": "0.1.0",
            "integration": "cooperative_mcp",
        },
    }


def _requests() -> dict[str, dict[str, JsonValue]]:
    frontier: dict[str, JsonValue] = {"sequence": "0", "head_digest": "genesis"}
    identity: dict[str, JsonValue] = {
        "session_id": _id("session", 1),
        "writer_id": _id("writer", 1),
    }
    return {
        "start": {
            **_base(1),
            "mode": "create",
            "task_title": "Bridge contract",
            "requested_view": "compact",
        },
        "publish_work": {
            **_base(2),
            **identity,
            "expected_frontier": frontier,
            "event_drafts": [
                {
                    "event_id": _id("event", 2),
                    "schema": {"name": "plan_published", "version": "1.0.0"},
                    "occurred_at": "2026-01-01T00:00:00.000Z",
                    "causal_parents": [],
                    "payload": {"plan_version": 1, "summary": "Plan", "obligation_refs": []},
                    "artifact_refs": [],
                    "evidence_refs": [],
                }
            ],
        },
        "check": {
            **_base(3),
            **identity,
            "expected_frontier": frontier,
            "mode": "deterministic_only",
        },
        "respond": {
            **_base(4),
            **identity,
            "expected_frontier": frontier,
            "finding_id": _id("finding", 4),
            "finding_frontier": frontier,
            "disposition": "acknowledged",
        },
        "status": {**_base(5), **identity, "view": "compact", "limit": "10"},
        "receipt": {
            **_base(6),
            **identity,
            "task_id": _id("task", 6),
            "expected_frontier": frontier,
            "format": "json",
            "include": "summary",
            "redaction_profile": "default_local_export",
        },
    }


def _failure[ResultT: BaseModel](result_type: type[ResultT], request_id: str) -> ResultT:
    return result_type.model_validate(
        {
            "protocol_version": "0.1",
            "schema_version": "1.0.0",
            "request_id": request_id,
            "ok": False,
            "error": {
                "code": "SESSION_CONFLICT",
                "message": "The session conflicts with the request.",
                "retryable": False,
                "correlation_id": "err_00000000-0000-4000-8000-000000000099",
            },
        }
    )


class _FakeClient:
    def __init__(
        self,
        failure: ControlError | PublicOperationError | RuntimeError | None = None,
    ) -> None:
        self.failure = failure
        self.calls: list[tuple[str, object]] = []
        self.route_profiles: list[tuple[str, str | None]] = []
        self.host_profiles: list[str | None] = []
        self.deadlines: list[tuple[str, int | None]] = []
        self.closed = False

    async def connect(self) -> None:
        return None

    async def _call[ResultT: BaseModel](
        self, name: str, request: PublicRequestModel, result_type: type[ResultT]
    ) -> ResultT:
        self.calls.append((name, request))
        if self.failure is not None:
            failure, self.failure = self.failure, None
            raise failure
        return _failure(result_type, request.request_id)

    async def start(self, request: StartRequest, *, deadline_ms: int | None = None) -> StartResult:
        self.deadlines.append(("start", deadline_ms))
        return await self._call("start", request, StartResult)

    async def publish_work(
        self, request: PublishWorkRequest, *, deadline_ms: int | None = None
    ) -> PublishWorkResult:
        self.deadlines.append(("publish_work", deadline_ms))
        return await self._call("publish_work", request, PublishWorkResult)

    async def check(
        self,
        request: CheckRequest,
        *,
        deadline_ms: int | None = None,
        route_profile: str | None = None,
        host_profile: str | None = None,
    ) -> CheckResult:
        self.deadlines.append(("check", deadline_ms))
        self.route_profiles.append(("check", route_profile))
        self.host_profiles.append(host_profile)
        return await self._call("check", request, CheckResult)

    async def respond(
        self, request: RespondRequest, *, deadline_ms: int | None = None
    ) -> RespondResult:
        self.deadlines.append(("respond", deadline_ms))
        return await self._call("respond", request, RespondResult)

    async def status(
        self,
        request: StatusRequest,
        *,
        deadline_ms: int | None = None,
        route_profile: str | None = None,
    ) -> StatusResult:
        self.deadlines.append(("status", deadline_ms))
        self.route_profiles.append(("status", route_profile))
        return await self._call("status", request, StatusResult)

    async def receipt(
        self, request: ReceiptRequest, *, deadline_ms: int | None = None
    ) -> ReceiptResult:
        self.deadlines.append(("receipt", deadline_ms))
        return await self._call("receipt", request, ReceiptResult)

    async def close(self) -> None:
        self.closed = True


class _RootsSession:
    def __init__(self, result: types.ListRootsResult) -> None:
        self.result = result
        self.calls = 0

    async def list_roots(self) -> types.ListRootsResult:
        self.calls += 1
        return self.result


def _root(uri: str) -> types.Root:
    return types.Root(uri=FileUrl(uri))


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _install_clients(
    monkeypatch: pytest.MonkeyPatch,
    clients: list[_FakeClient],
    observed_locators: list[object] | None = None,
) -> list[_FakeClient]:
    remaining = list(clients)

    async def connect(_kind: object, *, workspace_locator: object = None) -> object:
        if observed_locators is not None:
            observed_locators.append(workspace_locator)
        return remaining.pop(0)

    monkeypatch.setattr(
        bridge,
        "connect_service_on_demand",
        cast(Callable[[object], Awaitable[object]], connect),
    )
    return remaining


def _install_connect_failure(monkeypatch: pytest.MonkeyPatch, failure: BaseException) -> None:
    """Raise at connect time so `_RECONNECT_REASONS` cannot swallow service_unavailable."""

    async def connect(_kind: object, *, workspace_locator: object = None) -> object:
        del _kind, workspace_locator
        raise failure

    monkeypatch.setattr(
        bridge,
        "connect_service_on_demand",
        cast(Callable[[object], Awaitable[object]], connect),
    )


_LEAK_TOKENS = (
    "Traceback",
    "/tmp/",
    ".sock",
    "Application Support",
    "must-not-reach-public-output",
    "YZH1-",
    "Bearer ",
)
_ABSENT_SERVICE_MESSAGE = (
    "The local Yoetz service is not running. On a local terminal run "
    "'yoetz service run' under your selected user supervisor, then retry this "
    "operation with the same request_id."
)
_SERVICE_CORRELATION = "err_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"


def _assert_no_leakage(*blobs: object) -> None:
    rendered = json.dumps(blobs, default=str)
    for token in _LEAK_TOKENS:
        assert token not in rendered


def _start_error(result: object, request_id: str) -> dict[str, object]:
    structured = cast(dict[str, object], getattr(result, "structuredContent"))
    assert getattr(result, "isError") is True
    assert structured["request_id"] == request_id
    return cast(dict[str, object], structured["error"])


@pytest.mark.anyio
async def test_exact_six_dispatchers_use_one_ordinary_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _FakeClient()
    _install_clients(monkeypatch, [client])
    runtime = bridge.build_bridge_runtime()

    for name, arguments in _requests().items():
        result = await getattr(bridge, f"dispatch_{name}")(arguments, runtime)
        assert result.isError is True
        assert result.structuredContent is not None
        assert result.structuredContent["error"]["code"] == "SESSION_CONFLICT"

    assert [name for name, _request in client.calls] == [
        "start",
        "publish_work",
        "check",
        "respond",
        "status",
        "receipt",
    ]
    guidance = await bridge.dispatch_read_guidance(
        {"uri": "yoetz://guidance/workflow.md"},
        runtime,
    )
    assert guidance.isError is False
    assert client.calls[-1][0] == "receipt"
    assert client.deadlines == [
        ("start", 30_000),
        ("publish_work", 30_000),
        ("check", 300_000),
        ("respond", 50_000),
        ("status", 30_000),
        ("receipt", 50_000),
    ]
    assert client.closed is False
    await bridge.close_bridge_runtime(runtime)
    assert client.closed is True


@pytest.mark.anyio
async def test_cursor_host_profile_copies_exact_wire_json_into_model_visible_text(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    client = _FakeClient()
    _install_clients(monkeypatch, [client])
    runtime = bridge.build_bridge_runtime(
        host_profile="cursor", workspace_locator=WorkspaceLocator(str(tmp_path))
    )

    result = await bridge.dispatch_status(_requests()["status"], runtime)

    assert result.isError is True
    assert result.structuredContent is not None
    block = result.content[0]
    assert isinstance(block, types.TextContent)
    assert block.text == canonical_encode(cast(JsonValue, result.structuredContent)).decode("utf-8")
    assert json.loads(block.text) == result.structuredContent
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_cursor_native_handler_binds_root_before_service_handshake(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    client = _FakeClient()
    observed_locators: list[object] = []
    _install_clients(monkeypatch, [client], observed_locators)
    runtime = bridge.build_bridge_runtime(host_profile="cursor")
    session = _RootsSession(types.ListRootsResult(roots=[_root(tmp_path.as_uri())]))
    arguments = {**_requests()["start"], "external_ref": "cursor-root", "workspace_ref": "/other"}
    request = types.CallToolRequest(
        params=types.CallToolRequestParams(name="start", arguments=arguments)
    )

    response = await bridge._handle_call_tool_request(  # pyright: ignore[reportPrivateUsage]
        request, runtime, session=session
    )

    result = response.root
    assert isinstance(result, types.CallToolResult)
    assert result.structuredContent is not None
    assert result.structuredContent["ok"] is False
    assert session.calls == 1
    assert observed_locators == [WorkspaceLocator(str(tmp_path))]
    assert runtime._slot.workspace_locator == WorkspaceLocator(str(tmp_path))  # pyright: ignore[reportPrivateUsage]

    # Cursor 3.19.7 advertises roots.listChanged=false, so the bridge also revalidates on the next
    # workflow call when no notification arrives.
    other = tmp_path / "other"
    other.mkdir()
    session.result = types.ListRootsResult(roots=[_root(other.as_uri())])
    changed = await bridge._handle_call_tool_request(  # pyright: ignore[reportPrivateUsage]
        request, runtime, session=session
    )
    changed_result = changed.root
    assert isinstance(changed_result, types.CallToolResult)
    assert changed_result.structuredContent is not None
    assert changed_result.structuredContent["error"]["code"] == "SESSION_CONFLICT"
    assert session.calls == 2
    assert len(client.calls) == 1
    assert client.closed is True
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_cursor_native_protocol_requests_roots_before_service_handshake(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    client = _FakeClient()
    observed_locators: list[object] = []
    _install_clients(monkeypatch, [client], observed_locators)
    runtime = bridge.build_bridge_runtime(host_profile="cursor")
    active = bridge._build_server(runtime)  # pyright: ignore[reportPrivateUsage]
    client_to_server_send, client_to_server_receive = anyio.create_memory_object_stream[
        SessionMessage
    ](20)
    server_to_client_send, server_to_client_receive = anyio.create_memory_object_stream[
        SessionMessage
    ](20)

    async def roots(context: object) -> types.ListRootsResult:
        del context
        return types.ListRootsResult(roots=[_root(tmp_path.as_uri())])

    from mcp.client.session import ClientSession

    peer = ClientSession(
        client_to_server_receive,
        server_to_client_send,
        list_roots_callback=roots,
    )
    result: types.CallToolResult | None = None
    async with anyio.create_task_group() as tasks:
        tasks.start_soon(
            active.run,
            server_to_client_receive,
            client_to_server_send,
            bridge._initialization_options(  # pyright: ignore[reportPrivateUsage]
                runtime, active
            ),
        )
        async with peer:
            await peer.initialize()
            result = await peer.call_tool("start", _requests()["start"])
        tasks.cancel_scope.cancel()

    assert result is not None
    assert result.isError is True
    assert observed_locators == [WorkspaceLocator(str(tmp_path))]
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_cursor_native_handler_refuses_missing_or_ambiguous_roots_without_connecting(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    client = _FakeClient()
    observed_locators: list[object] = []
    _install_clients(monkeypatch, [client], observed_locators)
    runtime = bridge.build_bridge_runtime(host_profile="cursor")
    first = _RootsSession(types.ListRootsResult(roots=[]))
    request = types.CallToolRequest(
        params=types.CallToolRequestParams(name="start", arguments=_requests()["start"])
    )

    missing = await bridge._handle_call_tool_request(  # pyright: ignore[reportPrivateUsage]
        request, runtime, session=first
    )
    missing_result = missing.root
    assert isinstance(missing_result, types.CallToolResult)
    assert missing_result.structuredContent is not None
    missing_error = cast(dict[str, object], missing_result.structuredContent["error"])
    assert missing_error["code"] == "SESSION_CONFLICT"
    assert cast(dict[str, object], missing_error["safe_details"])["reason_code"] == (
        "repository_identity_required"
    )
    message = cast(str, missing_error["message"])
    for recovery_fact in ("roots/list", "project-mcp", ".cursor/mcp.json", "CLI CWD", "Hook"):
        assert recovery_fact in message
    assert first.calls == 1
    assert observed_locators == []

    # A second root-list response is never consulted after the session failed closed.
    second = _RootsSession(
        types.ListRootsResult(
            roots=[
                _root(tmp_path.as_uri()),
                _root((tmp_path / "nested").as_uri()),
            ]
        )
    )
    repeated = await bridge._handle_call_tool_request(  # pyright: ignore[reportPrivateUsage]
        request, runtime, session=second
    )
    repeated_result = repeated.root
    assert isinstance(repeated_result, types.CallToolResult)
    assert repeated_result.structuredContent is not None
    repeated_error = cast(dict[str, object], repeated_result.structuredContent["error"])
    assert repeated_error["code"] == "SESSION_CONFLICT"
    assert repeated_error["correlation_id"] == missing_error["correlation_id"]
    assert second.calls == 0
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_cursor_native_handler_retires_binding_when_roots_change(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    client = _FakeClient()
    _install_clients(monkeypatch, [client])
    runtime = bridge.build_bridge_runtime(host_profile="cursor")
    session = _RootsSession(types.ListRootsResult(roots=[_root(tmp_path.as_uri())]))
    request = types.CallToolRequest(
        params=types.CallToolRequestParams(name="start", arguments=_requests()["start"])
    )

    first = await bridge._handle_call_tool_request(  # pyright: ignore[reportPrivateUsage]
        request, runtime, session=session
    )
    assert isinstance(first.root, types.CallToolResult)
    assert runtime._slot.workspace_binding_state == "bound"  # pyright: ignore[reportPrivateUsage]
    assert client.closed is False

    active = bridge._build_server(runtime)  # pyright: ignore[reportPrivateUsage]
    await active.notification_handlers[types.RootsListChangedNotification](
        types.RootsListChangedNotification()
    )
    assert runtime._slot.workspace_binding_state == "failed"  # pyright: ignore[reportPrivateUsage]
    assert runtime._slot.workspace_locator is None  # pyright: ignore[reportPrivateUsage]
    assert client.closed is True
    await bridge.close_bridge_runtime(runtime)


def test_cursor_root_binding_rejects_remote_query_and_distinct_repositories(
    tmp_path: Path,
) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    encoded = tmp_path / "with space"
    unicode_encoded = tmp_path / "café"
    first.mkdir()
    second.mkdir()
    encoded.mkdir()
    unicode_encoded.mkdir()

    assert (
        bridge._cursor_workspace_locator(  # pyright: ignore[reportPrivateUsage]
            types.ListRootsResult(roots=[_root(first.as_uri()), _root(second.as_uri())])
        )
        is None
    )
    assert (
        bridge._cursor_workspace_locator(  # pyright: ignore[reportPrivateUsage]
            types.ListRootsResult(roots=[_root("file://remote.example/project")])
        )
        is None
    )
    assert (
        bridge._cursor_workspace_locator(  # pyright: ignore[reportPrivateUsage]
            types.ListRootsResult(roots=[_root(f"{first.as_uri()}?untrusted=1")])
        )
        is None
    )
    assert bridge._cursor_workspace_locator(  # pyright: ignore[reportPrivateUsage]
        types.ListRootsResult(roots=[_root(encoded.as_uri())])
    ) == WorkspaceLocator(str(encoded))
    assert bridge._cursor_workspace_locator(  # pyright: ignore[reportPrivateUsage]
        types.ListRootsResult(roots=[_root(unicode_encoded.as_uri())])
    ) == WorkspaceLocator(str(unicode_encoded))
    for escape in ("%", "%2", "%ZZ"):
        assert (
            bridge._cursor_workspace_locator(  # pyright: ignore[reportPrivateUsage]
                types.ListRootsResult(roots=[_root(f"{first.as_uri()}{escape}")])
            )
            is None
        )


@pytest.mark.anyio
async def test_generic_host_profile_keeps_bounded_weaker_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _FakeClient()
    _install_clients(monkeypatch, [client])
    runtime = bridge.build_bridge_runtime()

    result = await bridge.dispatch_status(_requests()["status"], runtime)

    assert result.structuredContent is not None
    block = result.content[0]
    assert isinstance(block, types.TextContent)
    assert block.text.startswith("Error SESSION_CONFLICT;")
    assert block.text != canonical_encode(cast(JsonValue, result.structuredContent)).decode("utf-8")
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_read_guidance_reconstructs_oversized_text_without_the_service_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _FakeClient()
    _install_clients(monkeypatch, [client])
    runtime = bridge.build_bridge_runtime()

    result = await bridge.dispatch_read_guidance(
        {"uri": "yoetz://guidance/workflow.md"},
        runtime,
    )

    expected = read_resource("yoetz://guidance/workflow.md").decode("utf-8")
    assembler = GuidancePageAssembler()
    pages = 0
    arguments: dict[str, object] = {"uri": "yoetz://guidance/workflow.md"}
    page_count: int | None = None
    while True:
        assert result.isError is False
        assert result.structuredContent is not None
        wire = cast(dict[str, object], result.structuredContent)
        block = result.content[0]
        assert isinstance(block, types.TextContent)
        if page_count is None:
            page_count = int(cast(str, wire["page_count"]))
            assert page_count > 1
        assembler.add(wire, host_text=block.text)
        pages += 1
        if wire["complete"] is True:
            break
        assert pages < page_count
        continuation = wire.get("continuation")
        assert isinstance(continuation, dict)
        arguments = dict(cast(dict[str, object], continuation))
        result = await bridge.dispatch_read_guidance(arguments, runtime)

    assert pages == page_count
    assert assembler.assemble() == expected
    assert client.calls == []
    assert runtime._slot.client is None  # pyright: ignore[reportPrivateUsage]
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_closure_prepare_reuses_cli_helper_and_projects_structured_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    async def prepare(
        _status: object,
        session_id: str,
        writer_id: str,
        selection: object,
        **kwargs: object,
    ) -> dict[str, JsonValue]:
        captured.update(
            session_id=session_id,
            writer_id=writer_id,
            selection=selection,
            **kwargs,
        )
        return {
            "preparatory_only": True,
            "frontier": {"sequence": "0", "head_digest": "genesis"},
            "closure_readiness": {},
            "inventory": {},
            "request": None,
            "notes": ["Nothing was published or judged."],
        }

    monkeypatch.setattr(bridge, "prepare_closure", prepare)
    runtime = bridge.build_bridge_runtime()

    result = await bridge.dispatch_closure_prepare(
        {
            "session_id": _id("session", 1),
            "writer_id": _id("writer", 1),
            "selection": {"phase": "inventory"},
        },
        runtime,
    )

    assert result.isError is False
    assert result.structuredContent is not None
    assert result.structuredContent["ok"] is True
    assert result.structuredContent["preparatory_only"] is True
    assert captured["session_id"] == _id("session", 1)
    assert captured["writer_id"] == _id("writer", 1)
    assert getattr(captured["selection"], "phase") == "inventory"
    assert captured["client_kind"] == "cooperative_agent"
    assert captured["integration"] == "cooperative_mcp"
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_closure_prepare_refuses_stale_inventory_without_writing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def prepare(*_args: object, **_kwargs: object) -> dict[str, JsonValue]:
        raise ValueError("closure_snapshot_unavailable")

    monkeypatch.setattr(bridge, "prepare_closure", prepare)
    runtime = bridge.build_bridge_runtime()

    result = await bridge.dispatch_closure_prepare(
        {
            "session_id": _id("session", 1),
            "writer_id": _id("writer", 1),
            "selection": {"phase": "claim"},
        },
        runtime,
    )

    assert result.isError is True
    assert result.structuredContent is not None
    assert result.structuredContent["error"]["code"] == "INVALID_REQUEST"
    assert result.structuredContent["error"]["safe_details"] == {
        "reason_code": "frontier_changed",
        "continuation": "frontier_refresh_required",
    }
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
@pytest.mark.parametrize(
    "reason",
    sorted(
        reason
        for reason in PREPARATION_REMEDIATIONS
        if reason
        not in {
            "closure_output_unwritable",
            "closure_output_not_durable",
            "closure_snapshot_unavailable",
            "closure_result_too_large",
        }
    ),
)
async def test_closure_prepare_names_its_refusal_and_the_remedy_on_the_text_channel(
    monkeypatch: pytest.MonkeyPatch, reason: str
) -> None:
    """tb4n3 formal-crypto S: `closure_attempt_selection_required` reached the agent as a bare
    "Error INVALID_REQUEST" because the reason was not an admitted protocol reason code."""

    async def prepare(*_args: object, **_kwargs: object) -> dict[str, JsonValue]:
        raise ValueError(reason)

    monkeypatch.setattr(bridge, "prepare_closure", prepare)
    runtime = bridge.build_bridge_runtime("policy", host_profile="codex")

    result = await bridge.dispatch_closure_prepare(
        {
            "session_id": _id("session", 1),
            "writer_id": _id("writer", 1),
            "selection": {"phase": "inventory"},
        },
        runtime,
    )

    assert result.isError is True
    assert result.structuredContent is not None
    error = cast(dict[str, Any], result.structuredContent["error"])
    assert error["code"] == "INVALID_REQUEST"
    assert error["safe_details"] == {"reason_code": reason}
    text = "".join(block.text for block in result.content if isinstance(block, types.TextContent))
    assert f"Reason: {reason}." in text
    assert f"Remedy: {PREPARATION_REMEDIATIONS[reason]}" in text
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_closure_prepare_scopes_a_draft_phase_to_the_selection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """tb4n3 formal-crypto S: the full-inventory echo (about 983 KB at frontier ~1,430) made the
    follow-up draft LIMIT_EXCEEDED. The MCP route now asks for the scoped echo."""

    seen: dict[str, object] = {}

    async def prepare(*_args: object, **kwargs: object) -> dict[str, JsonValue]:
        seen.update(kwargs)
        return {
            "preparatory_only": True,
            "frontier": {"sequence": "0", "head_digest": "genesis"},
            "closure_readiness": {},
            "inventory": {"obligations": [], "scope": {"mode": "selected_rows"}},
            "request": None,
            "notes": ["Nothing was published or judged."],
        }

    monkeypatch.setattr(bridge, "prepare_closure", prepare)
    runtime = bridge.build_bridge_runtime()
    result = await bridge.dispatch_closure_prepare(
        {
            "session_id": _id("session", 1),
            "writer_id": _id("writer", 1),
            "selection": {"phase": "inventory"},
        },
        runtime,
    )
    assert result.isError is False
    assert seen["scope_to_selection"] is True
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_an_unexpected_invoke_failure_is_a_typed_stage_with_a_remedy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """tb4n3 RC-2: no bare "The bridge could not complete the operation"; the agent is told whether
    its write may be recorded and what to read first."""

    reason = "bridge_invoke_failed"
    _install_clients(monkeypatch, [_FakeClient(RuntimeError("must-not-reach-public-output"))])
    runtime = bridge.build_bridge_runtime("policy", host_profile="codex")

    result = await bridge.dispatch_publish_work(_requests()["publish_work"], runtime)

    assert result.isError is True
    assert result.structuredContent is not None
    error = cast(dict[str, Any], result.structuredContent["error"])
    assert error["code"] == "INTERNAL_ERROR"
    assert error["safe_details"] == {"reason_code": reason}
    assert "status view=operation" in error["message"]
    assert "must-not-reach-public-output" not in json.dumps(result.structuredContent)
    text = "".join(block.text for block in result.content if isinstance(block, types.TextContent))
    assert f"Reason: {reason}." in text
    assert "Remedy:" in text and "status view=operation" in text
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_closure_prepare_refuses_an_unbounded_mcp_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def prepare(*_args: object, **_kwargs: object) -> dict[str, JsonValue]:
        history_row: dict[str, JsonValue] = {"event_id": "evt_" + "a" * 40_000}
        history: list[JsonValue] = [history_row] * 30
        return {
            "preparatory_only": True,
            "frontier": {"sequence": "0", "head_digest": "genesis"},
            "closure_readiness": {},
            "inventory": {"history": history},
            "request": None,
            "notes": ["Nothing was published or judged."],
        }

    monkeypatch.setattr(bridge, "prepare_closure", prepare)
    runtime = bridge.build_bridge_runtime()

    result = await bridge.dispatch_closure_prepare(
        {
            "session_id": _id("session", 1),
            "writer_id": _id("writer", 1),
            "selection": {"phase": "inventory"},
        },
        runtime,
    )

    assert result.isError is True
    assert result.structuredContent is not None
    assert result.structuredContent["error"]["code"] == "LIMIT_EXCEEDED"
    assert result.structuredContent["error"]["safe_details"] == {
        "reason_code": "closure_result_too_large",
    }
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_cursor_closure_prepare_refuses_projected_frame_with_escaped_content(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    escaped_detail = '"\\\n\r\t' * 60_000

    async def prepare(*_args: object, **_kwargs: object) -> dict[str, JsonValue]:
        return {
            "preparatory_only": True,
            "frontier": {"sequence": "0", "head_digest": "genesis"},
            "closure_readiness": {},
            "inventory": {"history": [{"description": escaped_detail}]},
            "request": None,
            "notes": ["Nothing was published or judged."],
        }

    monkeypatch.setattr(bridge, "prepare_closure", prepare)
    # Bypass the inexpensive pre-projection guard so this regression exercises the actual
    # JSON-RPC projection bound. Cursor carries the structured body and a canonical JSON copy.
    monkeypatch.setattr(bridge, "_MAX_CLOSURE_RESULT_BYTES", 2_000_000)
    runtime = bridge.build_bridge_runtime(
        host_profile="cursor", workspace_locator=WorkspaceLocator(str(tmp_path))
    )

    result = await bridge.dispatch_closure_prepare(
        {
            "session_id": _id("session", 1),
            "writer_id": _id("writer", 1),
            "selection": {"phase": "inventory"},
        },
        runtime,
        transport_request_id=1,
    )

    assert result.isError is True
    assert result.structuredContent is not None
    assert result.structuredContent["error"]["code"] == "LIMIT_EXCEEDED"
    assert result.structuredContent["error"]["safe_details"] == {
        "reason_code": "closure_result_too_large",
    }
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_closure_prepare_replay_rejects_malformed_selection_in_one_turn() -> None:
    runtime = bridge.build_bridge_runtime()
    base = {
        "session_id": _id("session", 1),
        "writer_id": _id("writer", 1),
    }
    malformed = (
        {**base},
        {**base, "selection": {"phase": "inventory", "unexpected": True}},
        {**base, "selection": {"phase": "attempt", "requested_item_indexes": [64]}},
    )

    for arguments in malformed:
        result = await bridge.dispatch_closure_prepare(arguments, runtime)
        assert result.isError is True
        assert result.structuredContent is not None
        assert result.structuredContent["error"]["code"] == "INVALID_REQUEST"
        assert result.structuredContent["error"]["safe_details"] is not None
    assert runtime._slot.client is None  # pyright: ignore[reportPrivateUsage]
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_read_guidance_rejects_unknown_uri_without_echoing_it() -> None:
    runtime = bridge.build_bridge_runtime()
    unknown = "yoetz://guidance/not-a-real-document.md"

    result = await bridge.dispatch_read_guidance({"uri": unknown}, runtime)

    assert result.isError is True
    assert result.structuredContent is not None
    assert result.structuredContent["error"]["code"] == "INVALID_REQUEST"
    rendered = json.dumps(result.structuredContent)
    assert unknown not in rendered
    if result.content:
        block = result.content[0]
        assert isinstance(block, types.TextContent)
        assert unknown not in block.text
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_read_guidance_rejects_extra_argument_keys() -> None:
    runtime = bridge.build_bridge_runtime()

    result = await bridge.dispatch_read_guidance(
        {"uri": "yoetz://guidance/workflow.md", "request_id": "req_extra"},
        runtime,
    )

    assert result.isError is True
    assert result.structuredContent is not None
    assert result.structuredContent["error"]["code"] == "INVALID_REQUEST"
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_strict_bridge_attaches_private_route_profile_after_public_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _FakeClient()
    _install_clients(monkeypatch, [client])
    runtime = bridge.build_bridge_runtime("strict")

    result = await bridge.dispatch_check(_requests()["check"], runtime)

    assert result.isError is True
    assert client.route_profiles == [("check", "strict")]
    assert client.host_profiles == ["generic"]
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_bridge_attaches_explicit_host_identity_to_check_rpc(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _FakeClient()
    _install_clients(monkeypatch, [client])
    runtime = bridge.build_bridge_runtime("strict", host_profile="codex")

    result = await bridge.dispatch_check(_requests()["check"], runtime)

    assert result.isError is True
    assert client.route_profiles == [("check", "strict")]
    assert client.host_profiles == ["codex"]
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_agent_cannot_supply_or_clear_the_private_route_profile() -> None:
    runtime = bridge.build_bridge_runtime("strict")
    arguments = {**_requests()["check"], "route_profile": "policy"}

    result = await bridge.dispatch_check(arguments, runtime)

    assert result.isError is True
    assert result.structuredContent is not None
    assert result.structuredContent["error"]["code"] == "INVALID_REQUEST"
    assert runtime._slot.client is None  # pyright: ignore[reportPrivateUsage]


@pytest.mark.anyio
async def test_agent_cannot_supply_the_private_serving_host_identity() -> None:
    runtime = bridge.build_bridge_runtime("strict", host_profile="generic")
    arguments = {**_requests()["check"], "host_profile": "codex"}

    result = await bridge.dispatch_check(arguments, runtime)

    assert result.isError is True
    assert result.structuredContent is not None
    assert result.structuredContent["error"]["code"] == "INVALID_REQUEST"
    assert runtime._slot.client is None  # pyright: ignore[reportPrivateUsage]


@pytest.mark.anyio
async def test_response_loss_reconnects_once_with_identical_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stale = _FakeClient(ControlError("service_unavailable", retryable=True))
    replacement = _FakeClient()
    observed_locators: list[object] = []
    _install_clients(monkeypatch, [stale, replacement], observed_locators)
    runtime = bridge.build_bridge_runtime()

    result = await bridge.dispatch_start(_requests()["start"], runtime)

    assert result.isError is True
    assert stale.closed is True
    assert len(stale.calls) == len(replacement.calls) == 1
    assert stale.calls[0][1] is replacement.calls[0][1]
    assert observed_locators == [runtime.workspace_locator, runtime.workspace_locator]


@pytest.mark.anyio
async def test_start_timeout_directs_an_exact_replay_not_an_operation_query(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A lost first start returns no session or writer id, so the operation view is unusable."""

    client = _FakeClient(ControlError("request_timeout", retryable=True))
    _install_clients(monkeypatch, [client])
    runtime = bridge.build_bridge_runtime()
    request = _requests()["start"]

    result = await bridge.dispatch_start(request, runtime)

    assert result.isError is True
    assert result.structuredContent is not None
    error = cast(dict[str, JsonValue], result.structuredContent["error"])
    assert error["code"] == "SERVICE_UNAVAILABLE"
    assert error["retryable"] is True
    assert error["safe_details"] == {
        "continuation": "start_timeout_same_identity",
        "reason_code": "request_timeout",
    }
    assert error["message"] == (
        "The local start timed out and may still have committed. Replay the exact same "
        "start body once with the same request_id; the idempotent start path returns the "
        "stored result or a typed boundary. Do not fabricate session or writer ids for a "
        "status query."
    )
    text = cast(str, cast(list[Any], result.content)[0].text)
    assert "Continuation: start_timeout_same_identity." in text
    assert "view=operation" not in text
    assert result.structuredContent["request_id"] == request["request_id"]
    assert client.closed is False
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_write_timeout_preserves_unknown_outcome_and_same_request_remedy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _FakeClient(ControlError("request_timeout", retryable=True))
    _install_clients(monkeypatch, [client])
    runtime = bridge.build_bridge_runtime()
    request = _requests()["publish_work"]

    result = await bridge.dispatch_publish_work(request, runtime)

    assert result.isError is True
    assert result.structuredContent is not None
    error = cast(dict[str, JsonValue], result.structuredContent["error"])
    assert error["code"] == "SERVICE_UNAVAILABLE"
    assert error["retryable"] is True
    # The bridge probed status view=operation once; the fake service could not answer it, so the
    # outcome stays unknown and the typed handle names the exact polling identity.
    assert [name for name, _request in client.calls] == ["publish_work", "status"]
    assert client.deadlines[-1] == ("status", 5_000)
    assert error["safe_details"] == {
        "continuation": "write_timeout_same_identity",
        "reason_code": "request_timeout",
        "replay_request_id": request["request_id"],
        "session_id": request["session_id"],
        "writer_id": request["writer_id"],
        "view": "operation",
        "state": "unknown",
    }
    assert error["message"] == (
        "The local operation timed out and may still have committed. Retry with the same "
        "request_id to recover the stored outcome; for an existing Yoetz session, status "
        "view=operation can inspect that request_id."
    )
    text = cast(str, cast(list[Any], result.content)[0].text)
    assert "Continuation: write_timeout_same_identity." in text
    assert "view=operation" in text
    assert result.structuredContent["request_id"] == request["request_id"]
    assert client.closed is False
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
@pytest.mark.parametrize("operation", ["respond", "receipt"])
async def test_write_timeout_reports_pending_operation_handle(
    monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    client = _FakeClient(ControlError("request_timeout", retryable=True))
    _install_clients(monkeypatch, [client])
    runtime = bridge.build_bridge_runtime()
    request = _requests()[operation]
    probes: list[str | None] = []

    async def pending(
        arguments: object, _runtime: object, request_id: str | None
    ) -> tuple[object, str, str]:
        del arguments
        probes.append(request_id)
        return (
            bridge._TimeoutOperationState.PENDING,  # pyright: ignore[reportPrivateUsage]
            cast(str, request["session_id"]),
            cast(str, request["writer_id"]),
        )

    monkeypatch.setattr(bridge, "_timeout_operation_state", pending)
    dispatch = bridge.dispatch_respond if operation == "respond" else bridge.dispatch_receipt
    result = await dispatch(request, runtime)

    assert probes == [request["request_id"]]
    assert result.isError is True
    assert result.structuredContent is not None
    error = cast(dict[str, JsonValue], result.structuredContent["error"])
    assert error["code"] == "SERVICE_UNAVAILABLE"
    assert error["retryable"] is True
    assert error["safe_details"] == {
        "continuation": "write_timeout_same_identity",
        "reason_code": "request_timeout",
        "replay_request_id": request["request_id"],
        "session_id": request["session_id"],
        "writer_id": request["writer_id"],
        "view": "operation",
        "state": "pending",
    }
    # Pending is not replayed: exactly one write reached the service.
    assert [name for name, _request in client.calls] == [operation]
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_write_timeout_returns_committed_outcome_via_same_request_replay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _FakeClient(ControlError("request_timeout", retryable=True))
    _install_clients(monkeypatch, [client])
    runtime = bridge.build_bridge_runtime()
    request = _requests()["receipt"]

    async def complete(
        arguments: object, _runtime: object, request_id: str | None
    ) -> tuple[object, str, str]:
        del arguments, request_id
        return (
            bridge._TimeoutOperationState.COMPLETE,  # pyright: ignore[reportPrivateUsage]
            cast(str, request["session_id"]),
            cast(str, request["writer_id"]),
        )

    monkeypatch.setattr(bridge, "_timeout_operation_state", complete)
    result = await bridge.dispatch_receipt(request, runtime)

    # The committed write is recovered by one idempotent same-request replay, whose stored
    # outcome (here the fake service's typed body) replaces the timeout.
    assert [name for name, _request in client.calls] == ["receipt", "receipt"]
    assert [call[1].request_id for call in client.calls] == [  # type: ignore[attr-defined]
        request["request_id"],
        request["request_id"],
    ]
    assert result.structuredContent is not None
    error = cast(dict[str, JsonValue], result.structuredContent["error"])
    assert error["code"] == "SESSION_CONFLICT"
    await bridge.close_bridge_runtime(runtime)


def test_rpc_deadlines_are_configurable_per_tool_with_sane_defaults() -> None:
    deadline = bridge._rpc_deadline_ms  # pyright: ignore[reportPrivateUsage]
    assert [deadline(tool, {}) for tool in ("start", "status", "publish_work")] == [30_000] * 3
    assert deadline("respond", {}) == 50_000
    assert deadline("receipt", {}) == 50_000
    assert deadline("check", {}) == 300_000
    env = {"YOETZ_MCP_DEADLINE_MS": "90000", "YOETZ_MCP_DEADLINE_MS_RECEIPT": " 45000 "}
    assert deadline("receipt", env) == 45_000
    assert deadline("respond", env) == 90_000
    # The global knob never shortens or lengthens check's semantic-review budget.
    assert deadline("check", env) == 300_000
    assert deadline("check", {"YOETZ_MCP_DEADLINE_MS_CHECK": "600000"}) == 600_000
    # Clamped and fail-safe.
    assert deadline("status", {"YOETZ_MCP_DEADLINE_MS": "5"}) == 1_000
    assert deadline("status", {"YOETZ_MCP_DEADLINE_MS": "99999999"}) == 900_000
    assert deadline("status", {"YOETZ_MCP_DEADLINE_MS": "-1"}) == 30_000
    assert deadline("status", {"YOETZ_MCP_DEADLINE_MS": "1e5"}) == 30_000


@pytest.mark.anyio
async def test_status_timeout_names_read_only_fresh_request_remedy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _FakeClient(ControlError("request_timeout", retryable=True))
    _install_clients(monkeypatch, [client])
    runtime = bridge.build_bridge_runtime()

    result = await bridge.dispatch_status(_requests()["status"], runtime)

    assert result.structuredContent is not None
    error = cast(dict[str, JsonValue], result.structuredContent["error"])
    assert error["code"] == "SERVICE_UNAVAILABLE"
    assert cast(dict[str, object], error["safe_details"])["reason_code"] == "request_timeout"
    assert "requested no write" in cast(str, error["message"])
    assert "new request_id" in cast(str, error["message"])
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_locked_error_is_structured_and_resources_never_connect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    locked = _FakeClient(ControlError("vault_locked"))
    unlocked = _FakeClient()
    remaining = _install_clients(monkeypatch, [locked, unlocked])
    runtime = bridge.build_bridge_runtime()

    resources = await bridge.list_resources()
    assert len(resources) == 5
    assert len(remaining) == 2

    result = await bridge.dispatch_start(_requests()["start"], runtime)
    assert result.isError is True
    assert result.structuredContent is not None
    assert result.structuredContent["error"]["code"] == "VAULT_LOCKED"
    assert "unlock" not in {tool.name for tool in await bridge.list_tools()}
    assert locked.closed is True
    # The failing client is discarded; the bounded initialization probe (issue #512) then
    # reconnects, finds no structural hello status on this peer, and leaves its live client in
    # the slot for the next dispatch instead of a dead binding.
    assert runtime._slot.client is unlocked  # pyright: ignore[reportPrivateUsage]

    after_unlock = await bridge.dispatch_start(_requests()["start"], runtime)
    assert after_unlock.isError is True
    assert unlocked.calls and unlocked.calls[0][0] == "start"
    assert runtime._slot.client is unlocked  # pyright: ignore[reportPrivateUsage]
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_public_operation_error_keeps_event_invalid_not_internal_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _FakeClient(
        PublicOperationError(
            PublicErrorCode.EVENT_INVALID,
            "The event batch is invalid.",
            False,
            safe_details={"reason_code": "unsorted_set_field"},
        )
    )
    _install_clients(monkeypatch, [client])
    runtime = bridge.build_bridge_runtime()

    result = await bridge.dispatch_publish_work(_requests()["publish_work"], runtime)

    assert result.isError is True
    assert result.structuredContent is not None
    error = result.structuredContent["error"]
    assert error["code"] == "EVENT_INVALID"
    assert error["safe_details"] == {
        "continuation": "sorted_set_required",
        "reason_code": "unsorted_set_field",
    }
    assert error["code"] != "INTERNAL_ERROR"
    assert result.structuredContent["request_id"] == _requests()["publish_work"]["request_id"]
    await bridge.close_bridge_runtime(runtime)


def _reference_mirror_error() -> PublicOperationError:
    """Build the real reference-mirror rejection the publish application produces.

    Hand-writing the message here would let the bridge case pass while the production text drifted,
    so the case rides on whatever `prepare_publication` actually raises.
    """

    from typing import cast as _cast

    from builders.replay import replay_records
    from yoetz.application.publish_work import Application, prepare_publication
    from yoetz.domain.events import EventPayload, LedgerRecord, encode_payload
    from yoetz.protocol.coverage import PublicationChannel
    from yoetz.protocol.models import PublishWorkRequestModel

    class _App:
        def authorizes_import_publication(self, request: PublishWorkRequest) -> bool:
            del request
            return False

    def draft(family: str) -> tuple[dict[str, JsonValue], LedgerRecord]:
        record = next(
            row for row in replay_records("all-event-families") if row.schema.name == family
        )
        assert record.payload is not None
        return {
            "event_id": record.event_id,
            "schema": {"name": record.schema.name, "version": record.schema.version},
            "occurred_at": record.occurred_at.wire,
            "causal_parents": list(record.causal_parents),
            "payload": encode_payload(_cast(EventPayload, record.payload)),
            "artifact_refs": list(record.artifact_refs),
            "evidence_refs": list(record.evidence_refs),
        }, record

    broken, record = draft("result_recorded")
    mirrored = cast(list[JsonValue], broken["evidence_refs"])
    # Break the mirror in whichever direction the recorded draft leaves available.
    broken["evidence_refs"] = [] if mirrored else ["evd_00000000-0000-4000-8000-0000000000ff"]
    request = PublishWorkRequestModel.model_validate(
        {
            "protocol_version": "0.1",
            "schema_version": "1.0.0",
            "request_id": _id("request", 2),
            "session_id": record.session_id,
            "writer_id": record.writer.writer_id,
            "expected_frontier": {"sequence": "0", "head_digest": "genesis"},
            "event_drafts": (broken,),
            "actor": {"actor_id": "harness:mcp", "actor_type": "harness"},
            "client": {
                "kind": "cooperative_agent",
                "version": "0.1.0",
                "integration": "cooperative_mcp",
            },
        }
    )
    with pytest.raises(PublicOperationError) as captured:
        prepare_publication(
            request,
            channel=PublicationChannel.LOCAL_CLI,
            app=cast(Application, _App()),
        )
    return captured.value


@pytest.mark.anyio
async def test_reference_mirror_correction_survives_the_bridge_round_trip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The corrective sentence only helps if it reaches the wire, not just the application layer."""

    failure = _reference_mirror_error()
    _install_clients(monkeypatch, [_FakeClient(failure)])
    runtime = bridge.build_bridge_runtime()

    result = await bridge.dispatch_publish_work(_requests()["publish_work"], runtime)

    assert result.isError is True
    assert result.structuredContent is not None
    error = cast(dict[str, JsonValue], result.structuredContent["error"])
    assert error["code"] == "EVENT_INVALID"
    assert error["code"] != "INTERNAL_ERROR"
    details = cast(dict[str, JsonValue], error["safe_details"])
    assert details["reason_code"] == "ref_mirror_mismatch"
    assert details["field"] == "/event_drafts/0/evidence_refs"
    message = cast(str, error["message"])
    assert "evidence_refs" in message
    assert "yoetz://guidance/publication-policy.md" in message
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_unexpected_bridge_error_logs_public_correlation_id(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    correlation_id = "err_00000000-0000-4000-8000-000000000098"
    client = _FakeClient(RuntimeError("must-not-reach-public-output"))
    _install_clients(monkeypatch, [client])

    def record(
        exc: BaseException,
        *,
        component: str,
        operation: str,
        request_id: str | None = None,
    ) -> str:
        assert type(exc) is RuntimeError
        print(
            json.dumps(
                {
                    "component": component,
                    "operation": operation,
                    "correlation_id": correlation_id,
                    "request_id": request_id,
                    "reason": "exception_runtime_error",
                }
            ),
            file=sys.stderr,
        )
        return correlation_id

    monkeypatch.setattr(bridge, "record_unexpected_exception_without_raising", record)
    runtime = bridge.build_bridge_runtime()

    result = await bridge.dispatch_check(_requests()["check"], runtime)

    captured = capsys.readouterr()
    assert captured.out == ""
    assert correlation_id in captured.err
    assert "check_internal_error" in captured.err
    assert result.isError is True
    assert result.structuredContent is not None
    assert result.structuredContent["error"]["code"] == "INTERNAL_ERROR"
    assert result.structuredContent["error"]["correlation_id"] == correlation_id
    assert "must-not-reach-public-output" not in str(result.structuredContent)
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_service_post_commit_projection_failure_maps_to_the_same_retryable_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The service's own post-commit failure must read exactly like the bridge's.

    The daemon raises ``response_projection_failed`` when shaping an already-completed operation
    fails. An agent cannot tell which side lost the response, so both must produce one identical
    retryable remedy rather than a bare "the bridge could not complete the operation".
    """

    service_correlation = "err_00000000-0000-4000-8000-000000000096"
    client = _FakeClient(
        ControlError(
            "response_projection_failed",
            retryable=True,
            correlation_id=service_correlation,
        )
    )
    _install_clients(monkeypatch, [client])
    request_id = cast(str, _requests()["publish_work"]["request_id"])
    runtime = bridge.build_bridge_runtime()

    result = await bridge.dispatch_publish_work(_requests()["publish_work"], runtime)

    assert result.isError is True
    assert result.structuredContent is not None
    error = cast(dict[str, object], result.structuredContent["error"])
    assert error["code"] == "INTERNAL_ERROR"
    assert error["retryable"] is True
    # Bridge reuses the service-minted id rather than generating a second one.
    assert error["correlation_id"] == service_correlation
    assert result.structuredContent["request_id"] == request_id
    assert "same request_id" in cast(str, error["message"])
    assert error.get("safe_details") == {"reason_code": "response_projection_failed"}
    # The text channel names the committed state and when to stop replaying (tb4n3 RC-2).
    text = "".join(block.text for block in result.content if isinstance(block, types.TextContent))
    assert "Remedy: The operation is recorded" in text
    assert "if that replay also fails, stop replaying" in text
    assert "status view=operation" in text
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_post_commit_structural_shaping_failure_names_the_stage_and_does_not_advise_replay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """tb4n3 RC-2: a durable invoke whose result cannot be built reads as recorded, not replayable.

    Replaying the same request_id rebuilds the same result and fails the same way, so the error
    names the stage, points at status view=operation and does not offer a replay.
    """

    correlation_id = "err_00000000-0000-4000-8000-000000000097"
    client = _FakeClient()
    _install_clients(monkeypatch, [client])
    request_id = cast(str, _requests()["publish_work"]["request_id"])

    def boom(_result: object) -> object:
        raise RuntimeError("post-commit-shape-failure")

    def record(
        exc: BaseException,
        *,
        component: str,
        operation: str,
        request_id: str | None = None,
    ) -> str:
        del exc, component, operation, request_id
        return correlation_id

    monkeypatch.setattr(bridge, "public_model_to_wire", boom)
    monkeypatch.setattr(bridge, "record_unexpected_exception_without_raising", record)
    runtime = bridge.build_bridge_runtime()

    result = await bridge.dispatch_publish_work(_requests()["publish_work"], runtime)

    assert result.isError is True
    assert result.structuredContent is not None
    error = cast(dict[str, object], result.structuredContent["error"])
    assert error["code"] == "INTERNAL_ERROR"
    assert error["retryable"] is False
    assert error["correlation_id"] == correlation_id
    assert result.structuredContent["request_id"] == request_id
    message = cast(str, error["message"])
    assert "stage: wire" in message and "status view=operation" in message
    assert "Replaying the same request_id" in message and "same way" in message
    assert error.get("safe_details") == {"reason_code": "bridge_result_wire_failed"}
    # The text channel carries the stage and the remedy too: a text-only host reads no message.
    text = "".join(block.text for block in result.content if isinstance(block, types.TextContent))
    assert "Reason: bridge_result_wire_failed." in text
    assert "Remedy:" in text and "status view=operation" in text
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_a_text_projection_failure_never_fails_a_committed_operation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """tb4n3 RC-2 (N3-1): the check committed, so its text failing returns the real result.

    The summary builder raising used to become INTERNAL_ERROR ``response_projection_failed`` with
    "retry the same request_id"; the replay re-rendered the same text and failed identically, and
    the agent never saw a verdict (10 of 13 deterministic runs).
    """

    from tests.unit.protocol.test_models_and_schemas import (
        _check_result_wire,  # pyright: ignore[reportPrivateUsage]
    )

    from yoetz.mcp import summaries

    class _CommittedCheckClient(_FakeClient):
        async def _call(  # pyright: ignore[reportIncompatibleMethodOverride]
            self, name: str, request: Any, result_type: type[Any]
        ) -> Any:
            return result_type.model_validate(_check_result_wire())

    client = _CommittedCheckClient()
    _install_clients(monkeypatch, [client])
    recorded: list[tuple[str, str | None]] = []

    def explode(_envelope: object) -> str:
        raise RuntimeError("summary-builder-defect")

    def record(
        exc: BaseException,
        *,
        component: str,
        operation: str,
        request_id: str | None = None,
        phase: str | None = None,
    ) -> str:
        del exc, component, request_id
        recorded.append((operation, phase))
        return "err_00000000-0000-4000-8000-000000000098"

    monkeypatch.setattr(summaries, "summary_for_check", explode)
    monkeypatch.setattr(bridge, "record_unexpected_exception_without_raising", record)
    runtime = bridge.build_bridge_runtime("policy", host_profile="codex")

    result = await bridge.dispatch_check(_requests()["check"], runtime)

    assert result.isError is False
    assert result.structuredContent is not None
    assert result.structuredContent["verdict"]
    text = "".join(block.text for block in result.content if isinstance(block, types.TextContent))
    assert "summary_render_failed:check" in text
    assert "read status view=compact" in text
    assert "frontier: " in text and "head_digest: sha256:" in text
    assert "err_00000000-0000-4000-8000-000000000098" in text
    assert "retry" not in text.lower()
    assert recorded == [("check_summary_degraded", "check")]
    await bridge.close_bridge_runtime(runtime)


def test_publish_work_validation_names_event_drafts_field() -> None:
    """`event_drafts` is untyped JsonValue to Pydantic, so this exercises schema translation.

    The rejection can only come from `_validate_model_against_schema` re-raising
    `SchemaInstanceInvalid.absolute_path`; a bare Pydantic field error cannot produce this
    location. The r4 dogfood returned an empty pointer here, giving the agent nothing to fix.
    """

    from yoetz.mcp.errors import safe_validation_locations
    from yoetz.protocol.models import PublishWorkRequest

    def arguments(event_id: str) -> dict[str, object]:
        return {
            "protocol_version": "0.1",
            "schema_version": "1.0.0",
            "request_id": _id("request", 9),
            "session_id": _id("session", 1),
            "writer_id": _id("writer", 1),
            "expected_frontier": {"sequence": "0", "head_digest": "genesis"},
            "actor": {"actor_id": "harness:mcp", "actor_type": "harness"},
            "client": {
                "kind": "cooperative_agent",
                "version": "0.1.0",
                "integration": "cooperative_mcp",
            },
            "event_drafts": [
                {
                    "event_id": event_id,
                    "schema": {"name": "plan_published", "version": "1.0.0"},
                    "occurred_at": "2026-01-01T00:00:00.000Z",
                    "causal_parents": [],
                    "payload": {
                        "plan_version": 1,
                        "summary": "Plan",
                        "obligation_refs": [],
                    },
                    "artifact_refs": [],
                    "evidence_refs": [],
                }
            ],
        }

    # Identical payload with a schema-valid event_id is accepted, so the only difference driving
    # the rejection below is the field the pointer names.
    PublishWorkRequest.model_validate(arguments(_id("event", 1)))

    with pytest.raises(Exception) as captured:
        PublishWorkRequest.model_validate(arguments("not-an-id"))

    locations = safe_validation_locations(captured.value)
    assert [item["field"] for item in locations] == ["/event_drafts/0/event_id"]


@pytest.fixture
def _restore_process_logging() -> Iterator[None]:  # pyright: ignore[reportUnusedFunction]
    """``configure_logging`` mutates process-global state; restore it for every other test."""

    root = logging.getLogger()
    root_handlers = tuple(root.handlers)
    root_level = root.level
    last_resort = logging.lastResort
    raise_exceptions = logging.raiseExceptions
    yield
    root.handlers.clear()
    root.handlers.extend(root_handlers)
    root.setLevel(root_level)
    logging.lastResort = last_resort
    logging.raiseExceptions = raise_exceptions


def test_bridge_entry_point_installs_the_stdout_safe_structural_sink(
    monkeypatch: pytest.MonkeyPatch,
    _restore_process_logging: None,
) -> None:
    """Without this call the recorder mints correlation ids that reach no sink at all."""

    installed: list[LogMode] = []

    def configure(config: LoggingConfig, mode: LogMode) -> None:
        del config
        installed.append(mode)

    def run(*args: object, **kwargs: object) -> None:
        del args, kwargs

    monkeypatch.setattr(bridge, "configure_logging", configure)
    monkeypatch.setattr(bridge.anyio, "run", run)

    bridge.main()

    assert installed == [LogMode.MCP_STDIO]


@pytest.mark.anyio
async def test_unexpected_bridge_error_emits_a_real_structured_diagnostic(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    _restore_process_logging: None,
) -> None:
    """Exercise the installed sink rather than a stand-in for the recorder."""

    client = _FakeClient(RuntimeError("must-not-reach-public-output"))
    _install_clients(monkeypatch, [client])
    configure_logging(LoggingConfig(), LogMode.MCP_STDIO)
    runtime = bridge.build_bridge_runtime()

    result = await bridge.dispatch_check(_requests()["check"], runtime)

    captured = capsys.readouterr()
    assert captured.out == ""
    assert result.structuredContent is not None
    error = cast(dict[str, object], result.structuredContent["error"])
    emitted = json.loads(captured.err.strip().splitlines()[-1])
    assert emitted["correlation_id"] == error["correlation_id"]
    assert emitted["component"] == "mcp.bridge"
    assert emitted["operation"] == "check_internal_error"
    assert emitted["reason"] == "exception_runtime_error"
    assert "must-not-reach-public-output" not in captured.err
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_cancellation_propagates_without_becoming_a_tool_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _CancellingClient(_FakeClient):
        async def start(
            self, request: StartRequest, *, deadline_ms: int | None = None
        ) -> StartResult:
            del request
            del deadline_ms
            raise asyncio.CancelledError

    _install_clients(monkeypatch, [_CancellingClient()])
    runtime = bridge.build_bridge_runtime()

    with pytest.raises(asyncio.CancelledError):
        await bridge.dispatch_start(_requests()["start"], runtime)


@pytest.mark.anyio
async def test_blocked_receipt_projection_keeps_the_client_and_names_the_next_step(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A policy-blocked receipt format must be answered on the live client, not reconnected around.

    This is the shape a real agent hit five times in a row: a retryable-looking failure plus a
    torn-down connection taught it to repeat the one request that could never succeed.
    """

    client = _FakeClient(ControlError("privacy_projection_blocked", retryable=False))
    remaining = _install_clients(monkeypatch, [client])
    runtime = bridge.build_bridge_runtime()

    blocked = await bridge.dispatch_receipt(_requests()["receipt"], runtime)

    assert blocked.isError is True
    assert blocked.structuredContent is not None
    error = cast(dict[str, JsonValue], blocked.structuredContent["error"])
    assert error["code"] == "PRIVACY_AUTHORITY_REQUIRED"
    assert error["retryable"] is False
    details = cast(dict[str, JsonValue], error["safe_details"])
    assert details["reason_code"] == "receipt_json_projection_blocked"
    message = cast(str, error["message"])
    # The message has to carry the remedy; the reason code alone is not actionable.
    assert "markdown" in message and "text" in message
    # No reconnect was attempted and the durable session was never dropped.
    assert client.closed is False
    assert len(remaining) == 0

    # The next receipt call reaches the same client, so switching format needs no new connection.
    follow_up = await bridge.dispatch_receipt(_requests()["receipt"], runtime)
    assert follow_up.isError is True
    assert [name for name, _request in client.calls] == ["receipt", "receipt"]
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_transient_projection_failure_stays_retryable_service_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The transient reservation failure keeps its retryable meaning and its own reason code."""

    client = _FakeClient(ControlError("privacy_projection_unavailable", retryable=True))
    _install_clients(monkeypatch, [client])
    runtime = bridge.build_bridge_runtime()

    result = await bridge.dispatch_receipt(_requests()["receipt"], runtime)

    assert result.structuredContent is not None
    error = cast(dict[str, JsonValue], result.structuredContent["error"])
    assert error["code"] == "SERVICE_UNAVAILABLE"
    assert error["retryable"] is True
    details = cast(dict[str, JsonValue], error["safe_details"])
    assert details["reason_code"] == "privacy_projection_unavailable"
    await bridge.close_bridge_runtime(runtime)


@pytest.fixture
def diagnostic_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    import yoetz.observability.diagnostics as diagnostics

    monkeypatch.setattr(diagnostics, "log_dir", lambda: tmp_path)
    return tmp_path


@pytest.mark.anyio
async def test_connect_absent_service_names_the_supervisor_repair(
    monkeypatch: pytest.MonkeyPatch, diagnostic_root: Path
) -> None:
    _install_connect_failure(monkeypatch, ControlError("service_unavailable", retryable=True))
    runtime = bridge.build_bridge_runtime()
    request = _requests()["start"]

    result = await bridge.dispatch_start(request, runtime)

    error = _start_error(result, cast(str, request["request_id"]))
    assert error["code"] == PublicErrorCode.SERVICE_UNAVAILABLE.value
    assert error["retryable"] is True
    assert error["message"] == _ABSENT_SERVICE_MESSAGE
    assert cast(dict[str, object], error["safe_details"])["reason_code"] == "service_unavailable"
    found = lookup_diagnostic_records(cast(str, error["correlation_id"]), root=diagnostic_root)
    assert len(found) == 1
    assert found[0]["reason"] == "service_unavailable"
    assert found[0]["reason"] != "exception_control_error"
    _assert_no_leakage(result.structuredContent, found)
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_connect_accepted_but_unresponsive_does_not_prescribe_service_run(
    monkeypatch: pytest.MonkeyPatch, diagnostic_root: Path
) -> None:
    _install_connect_failure(
        monkeypatch,
        _AcceptedServiceUnresponsive(),  # pyright: ignore[reportPrivateUsage]
    )
    runtime = bridge.build_bridge_runtime()
    request = _requests()["start"]

    result = await bridge.dispatch_start(request, runtime)

    error = _start_error(result, cast(str, request["request_id"]))
    assert error["code"] == PublicErrorCode.SERVICE_UNAVAILABLE.value
    assert error["retryable"] is True
    message = cast(str, error["message"])
    assert message != _ABSENT_SERVICE_MESSAGE
    assert "under your selected user supervisor" not in message
    assert "Do not run `yoetz service run`" in message
    assert (
        cast(dict[str, object], error["safe_details"])["reason_code"] == "accepted_but_unresponsive"
    )
    found = lookup_diagnostic_records(cast(str, error["correlation_id"]), root=diagnostic_root)
    assert len(found) == 1
    assert found[0]["reason"] == "accepted_but_unresponsive"
    _assert_no_leakage(result.structuredContent, found)
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_connect_incompatible_holder_reuses_service_correlation_id(
    monkeypatch: pytest.MonkeyPatch, diagnostic_root: Path
) -> None:
    append_diagnostic_record(
        correlation_id=_SERVICE_CORRELATION,
        component="service.daemon",
        operation="start_service_incompatible",
        reason="service_incompatible",
        request_id=cast(str, _requests()["start"]["request_id"]),
        root=diagnostic_root,
    )
    _install_connect_failure(
        monkeypatch,
        ControlError("service_incompatible", retryable=True, correlation_id=_SERVICE_CORRELATION),
    )
    runtime = bridge.build_bridge_runtime()
    request = _requests()["start"]

    result = await bridge.dispatch_start(request, runtime)

    error = _start_error(result, cast(str, request["request_id"]))
    assert error["code"] == PublicErrorCode.SERVICE_UNAVAILABLE.value
    assert error["retryable"] is True
    assert error["correlation_id"] == _SERVICE_CORRELATION
    assert "yoetz service restart" in str(error["message"])
    assert cast(dict[str, object], error["safe_details"])["reason_code"] == "service_incompatible"
    found = lookup_diagnostic_records(_SERVICE_CORRELATION, root=diagnostic_root)
    assert len(found) == 1
    _assert_no_leakage(result.structuredContent, found)
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_connect_protocol_mismatch_is_distinct_and_ships_non_retryable(
    monkeypatch: pytest.MonkeyPatch, diagnostic_root: Path
) -> None:
    append_diagnostic_record(
        correlation_id=_SERVICE_CORRELATION,
        component="service.daemon",
        operation="start_protocol_mismatch",
        reason="protocol_mismatch",
        request_id=cast(str, _requests()["start"]["request_id"]),
        root=diagnostic_root,
    )
    _install_connect_failure(
        monkeypatch,
        ControlError("protocol_mismatch", correlation_id=_SERVICE_CORRELATION),
    )
    runtime = bridge.build_bridge_runtime()
    request = _requests()["start"]

    result = await bridge.dispatch_start(request, runtime)

    error = _start_error(result, cast(str, request["request_id"]))
    assert error["code"] == PublicErrorCode.SERVICE_UNAVAILABLE.value
    assert error["retryable"] is False
    assert error["correlation_id"] == _SERVICE_CORRELATION
    assert "yoetz service restart" in str(error["message"])
    assert cast(dict[str, object], error["safe_details"])["reason_code"] == "protocol_mismatch"
    found = lookup_diagnostic_records(_SERVICE_CORRELATION, root=diagnostic_root)
    assert len(found) == 1
    _assert_no_leakage(result.structuredContent, found)
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_connect_endpoint_unsafe_is_non_retryable_without_a_socket_path(
    monkeypatch: pytest.MonkeyPatch, diagnostic_root: Path
) -> None:
    _install_connect_failure(monkeypatch, ControlError("endpoint_unsafe"))
    runtime = bridge.build_bridge_runtime()
    request = _requests()["start"]

    result = await bridge.dispatch_start(request, runtime)

    error = _start_error(result, cast(str, request["request_id"]))
    assert error["code"] == PublicErrorCode.SERVICE_UNAVAILABLE.value
    assert error["retryable"] is False
    assert "unsafe to use" in str(error["message"])
    assert "same request_id" in str(error["message"])
    assert cast(dict[str, object], error["safe_details"])["reason_code"] == "endpoint_unsafe"
    found = lookup_diagnostic_records(cast(str, error["correlation_id"]), root=diagnostic_root)
    assert len(found) == 1
    assert found[0]["reason"] == "endpoint_unsafe"
    _assert_no_leakage(result.structuredContent, found)
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_unexpected_start_error_stays_internal_without_exception_text(
    monkeypatch: pytest.MonkeyPatch, diagnostic_root: Path
) -> None:
    _install_clients(monkeypatch, [_FakeClient(RuntimeError("must-not-reach-public-output"))])
    runtime = bridge.build_bridge_runtime()
    request = _requests()["start"]

    result = await bridge.dispatch_start(request, runtime)

    error = _start_error(result, cast(str, request["request_id"]))
    assert error["code"] == PublicErrorCode.INTERNAL_ERROR.value
    assert error["retryable"] is False
    found = lookup_diagnostic_records(cast(str, error["correlation_id"]), root=diagnostic_root)
    assert len(found) == 1
    assert found[0]["operation"] == "start_internal_error"
    assert str(found[0]["reason"]).startswith("exception_")
    _assert_no_leakage(result.structuredContent, found)
    await bridge.close_bridge_runtime(runtime)
