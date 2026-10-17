"""Issue #1084 at the MCP bridge: host-owned publish identity and the brief status default.

ADR-050 decision 2 (review R1 of PR #1088): when an agent omits ``request_id`` the bridge mints one
per call and binds it durably before sending. The service still requires it. A lost reply is
retried safely by resending the identical body (the bridge resumes that call's id and the service
replays), while a deliberate identical repeat after a delivered outcome is a new publication.

The end-to-end cases drive the real ready application through the real disclosure boundary
(``project_case``); only the control-channel transport is replaced.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import dataclasses
import json
import os
from collections.abc import Awaitable, Callable, Mapping
from pathlib import Path
from typing import Any, cast

import pytest
from mcp import types
from pydantic import BaseModel

import finishup.mcp.server as bridge
from builders.projection_workflow import (
    ProjectionCase,
    build_projection_application,
    project_case,
    request_base,
)
from builders.start_application import protocol_id, start_request
from finishup.adapters.integrations.publish_call_identity import (
    PUBLISH_CALLS_DIRECTORY,
    PublishCallIdentities,
)
from finishup.domain.privacy import ConversationReview
from finishup.kernel.review_mode import conversation_review_mode
from finishup.ports.control import ControlError, ControlMethod
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.ids import IdKind, is_valid_id
from finishup.protocol.models import (
    PUBLISH_RESUMED_CALL_NOTICE_TEXT,
    PublishWorkRequest,
    PublishWorkResultModel,
    StatusRequest,
    StatusResultModel,
)

_SESSION = "ses_00000000-0000-4000-8000-000000000001"
_WRITER = "wri_00000000-0000-4000-8000-000000000001"
_ENVELOPE: dict[str, object] = {
    "protocol_version": "0.1",
    "schema_version": "1.0.0",
    "session_id": _SESSION,
    "writer_id": _WRITER,
    "actor": {"actor_id": "harness:mcp", "actor_type": "harness"},
    "client": {"kind": "cooperative_agent", "version": "0.1.0", "integration": "cooperative_mcp"},
}


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _sparse_publish() -> dict[str, object]:
    return {
        **_ENVELOPE,
        "event_drafts": [
            {
                "schema": {"name": "decision_recorded", "version": "1.0.0"},
                "payload": {
                    "statement": "Keep the adapter.",
                    "rationale": "It covers the case.",
                    "authority": "harness:mcp",
                },
            }
        ],
    }


def _runtime(root: Path) -> bridge.BridgeRuntime:
    return dataclasses.replace(
        bridge.build_bridge_runtime(), publish_calls=PublishCallIdentities(state_root=root)
    )


def _record(root: Path) -> list[dict[str, Any]]:
    path = root / PUBLISH_CALLS_DIRECTORY / "calls.json"
    if not path.exists():
        return []
    return cast(list[dict[str, Any]], json.loads(path.read_text())["entries"])


def _capture(
    monkeypatch: pytest.MonkeyPatch,
    *,
    root: Path | None = None,
    seen_records: list[list[dict[str, Any]]] | None = None,
) -> list[BaseModel]:
    seen: list[BaseModel] = []

    async def ensure(_runtime: object = bridge.BRIDGE_RUNTIME, **_kwargs: object) -> object:
        return object()

    async def invoke(
        _runtime: object,
        request: BaseModel,
        _call: Callable[[object, object], Awaitable[object]],
        _request_id: object = None,
        **_kwargs: object,
    ) -> object:
        seen.append(request)
        if root is not None and seen_records is not None:
            seen_records.append(_record(root))
        raise PublicOperationError(
            PublicErrorCode.EVENT_INVALID,
            "The event batch is invalid.",
            False,
            safe_details={"reason_code": "invalid_event_value_type"},
        )

    monkeypatch.setattr(bridge, "ensure_service_client", ensure)
    monkeypatch.setattr(bridge, "_invoke_with_reconnect", invoke)
    return seen


@pytest.mark.anyio
async def test_an_idless_publish_is_bound_to_a_minted_id_before_it_is_sent(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    records: list[list[dict[str, Any]]] = []
    seen = _capture(monkeypatch, root=tmp_path, seen_records=records)
    runtime = _runtime(tmp_path)

    result = await bridge.dispatch_publish_work(_sparse_publish(), runtime)

    (forwarded,) = seen
    assert isinstance(forwarded, PublishWorkRequest)
    minted = forwarded.request_id
    assert is_valid_id(IdKind.REQUEST, minted)
    # The binding was durable and in flight before the body reached the service.
    ((entry,),) = records
    assert entry["request_id"] == minted and entry["state"] == "in_flight"
    assert entry["pid"] == os.getpid()
    # Only commitments and the minted id cross the record: never the body.
    raw = (tmp_path / PUBLISH_CALLS_DIRECTORY / "calls.json").read_text()
    assert "Keep the adapter." not in raw and _SESSION not in raw and _WRITER not in raw
    # The service refused the body: nothing was delivered, so the call stays resumable.
    assert result.isError is True
    assert result.structuredContent is not None
    assert result.structuredContent["request_id"] == minted
    text = cast(types.TextContent, result.content[0]).text
    assert f"FinishUP minted request_id {minted} for this call" in text
    (after,) = _record(tmp_path)
    assert after["request_id"] == minted and after["state"] == "unresolved"
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_an_invalid_idless_body_is_never_bound_or_sent(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    seen = _capture(monkeypatch)
    runtime = _runtime(tmp_path)
    arguments = _sparse_publish()
    drafts = cast(list[dict[str, object]], arguments["event_drafts"])
    drafts[0]["schema"] = {"name": "decision_recorded", "version": "9.9.9"}

    result = await bridge.dispatch_publish_work(arguments, runtime)

    assert seen == []
    assert _record(tmp_path) == []
    assert result.isError is True
    assert result.structuredContent is not None
    assert result.structuredContent.get("request_id") is None
    error = cast(dict[str, object], result.structuredContent["error"])
    assert error["code"] == PublicErrorCode.INVALID_REQUEST.value
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_an_idless_dry_run_is_never_bound(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    seen = _capture(monkeypatch)
    runtime = _runtime(tmp_path)

    await bridge.dispatch_publish_work({**_sparse_publish(), "dry_run": True}, runtime)

    (forwarded,) = seen
    assert isinstance(forwarded, PublishWorkRequest)
    assert is_valid_id(IdKind.REQUEST, forwarded.request_id)
    assert _record(tmp_path) == []
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_an_unwritable_identity_record_refuses_to_send(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    seen = _capture(monkeypatch)
    blocked = tmp_path / "state"
    blocked.write_text("not a directory")
    runtime = _runtime(blocked)

    result = await bridge.dispatch_publish_work(_sparse_publish(), runtime)

    assert seen == []
    assert result.isError is True
    assert result.structuredContent is not None
    error = cast(dict[str, object], result.structuredContent["error"])
    assert error["code"] == PublicErrorCode.STORAGE_UNSAFE.value
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
@pytest.mark.parametrize(("sent", "expected"), [(None, "brief"), ("full", "full")])
async def test_status_asks_for_the_brief_detail_unless_the_agent_names_one(
    monkeypatch: pytest.MonkeyPatch, sent: str | None, expected: str
) -> None:
    seen = _capture(monkeypatch)
    runtime = bridge.build_bridge_runtime()
    arguments: dict[str, object] = {
        **_ENVELOPE,
        "request_id": "req_00000000-0000-4000-8000-000000001084",
        "view": "compact",
    }
    if sent is not None:
        arguments["detail"] = sent

    result: types.CallToolResult = await bridge.dispatch_status(arguments, runtime)

    (forwarded,) = seen
    assert isinstance(forwarded, StatusRequest)
    assert forwarded.detail == expected
    assert forwarded.limit == "20"
    assert result.isError is True
    await bridge.close_bridge_runtime(runtime)


class _Service:
    """The real ready application behind a fake control channel.

    ``lose_next_publish_reply`` commits the next publish and then loses its reply as a deadline
    expiry whose operation probe fails too: the bridge can only report an unknown outcome.
    """

    def __init__(self, app: Any, seed: int) -> None:
        self.app = app
        self.seed = seed
        self.publish_ids: list[str] = []
        self.lose_next_publish_reply = False

    async def invoke(
        self,
        _runtime: object,
        request: BaseModel,
        _call: Callable[[object, object], Awaitable[object]],
        _request_id: object = None,
        **_kwargs: object,
    ) -> object:
        self.seed += 1
        body = cast(
            Mapping[str, Any], request.model_dump(mode="json", by_alias=True, exclude_unset=True)
        )
        if isinstance(request, PublishWorkRequest):
            self.publish_ids.append(request.request_id)
            internal = await self.app.publish_work(request)
            if self.lose_next_publish_reply:
                self.lose_next_publish_reply = False
                raise ControlError("request_timeout", retryable=True)
            wire = await project_case(
                self.app,
                ProjectionCase("publish", ControlMethod.PUBLISH_WORK, body, internal),
                self.seed * 10,
            )
            return PublishWorkResultModel.model_validate(wire)
        if isinstance(request, StatusRequest):
            if cast(Any, request).view == "operation":
                raise ControlError("request_timeout", retryable=True)
            internal = await self.app.status(request)
            wire = await project_case(
                self.app,
                ProjectionCase("status", ControlMethod.STATUS, body, internal),
                self.seed * 10,
            )
            return StatusResultModel.model_validate(wire)
        raise AssertionError(type(request).__name__)


async def _service(
    monkeypatch: pytest.MonkeyPatch, seed: int
) -> tuple[_Service, Any, dict[str, Any]]:
    app, _policy = await build_projection_application(seed=seed)
    started = await app.start(start_request(seed, title="Bridge-owned publish identity"))
    service = _Service(app, seed)

    async def ensure(_runtime: object = bridge.BRIDGE_RUNTIME, **_kwargs: object) -> object:
        return object()

    monkeypatch.setattr(bridge, "ensure_service_client", ensure)
    monkeypatch.setattr(bridge, "_invoke_with_reconnect", service.invoke)
    envelope: dict[str, Any] = dict(request_base(protocol_id("req_", 1)))
    del envelope["request_id"]
    envelope["session_id"] = started.session_id
    envelope["writer_id"] = started.writer_id
    return service, started, envelope


def _switch(envelope: Mapping[str, object], mode: str) -> dict[str, object]:
    return {
        **envelope,
        "event_drafts": [
            {
                "schema": {"name": "decision_recorded", "version": "1.1.0"},
                "payload": {
                    "statement": f"Use {mode} review for this task.",
                    "rationale": "The current task review choice.",
                    "authority": "projection-sweep",
                    "review_mode": mode,
                },
            }
        ],
    }


def _decision_modes(app: Any) -> list[str]:
    ledger, _objects = next(iter(app.runtime.resources.values()))
    return [
        record.payload.review_mode.value
        for record in ledger._state.records
        if record.schema.name == "decision_recorded"
    ]


@pytest.mark.anyio
async def test_a_deliberate_identical_repeat_through_the_bridge_is_recorded(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Review R1 end to end: ai -> local -> ai, each an id-less call, records three switches."""

    service, _started, envelope = await _service(monkeypatch, 12000)
    runtime = _runtime(tmp_path)
    outcomes: list[object] = []
    for mode in ("ai_powered", "local", "ai_powered"):
        result = await bridge.dispatch_publish_work(_switch(envelope, mode), runtime)
        assert result.isError is not True
        assert result.structuredContent is not None
        outcomes.append(result.structuredContent["outcome"])
        assert "replay_notice" not in result.structuredContent
    assert outcomes == ["accepted", "accepted", "accepted"]
    assert len(set(service.publish_ids)) == 3
    assert _decision_modes(service.app) == ["ai_powered", "local", "ai_powered"]
    ledger, _objects = next(iter(service.app.runtime.resources.values()))
    resolved = conversation_review_mode(
        ledger._state.projection,
        ConversationReview.LOCAL_AGENT_OPT_IN,
        ai_review_available=True,
        setting_explicit=True,
    )
    assert resolved.mode.value == "ai_powered"
    # Every delivered call closed its binding.
    assert _record(tmp_path) == []
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_a_lost_reply_is_retried_under_the_same_identity(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A committed call whose reply was lost replays when the agent resends the same body."""

    service, _started, envelope = await _service(monkeypatch, 12100)
    runtime = _runtime(tmp_path)
    body = _switch(envelope, "local")

    service.lose_next_publish_reply = True
    lost = await bridge.dispatch_publish_work(body, runtime)
    assert lost.isError is True
    assert lost.structuredContent is not None
    first_id = cast(str, lost.structuredContent["request_id"])
    assert service.publish_ids == [first_id]
    assert _decision_modes(service.app) == ["local"]

    retried = await bridge.dispatch_publish_work(body, runtime)
    assert retried.isError is not True
    wire = cast(Mapping[str, Any], retried.structuredContent)
    assert wire["request_id"] == first_id
    assert wire["outcome"] == "replayed"
    assert wire["replay_notice"] == {
        "notice": "unresolved_call_resumed",
        "text": PUBLISH_RESUMED_CALL_NOTICE_TEXT,
    }
    text = "\n".join(
        block.text for block in retried.content if isinstance(block, types.TextContent)
    )
    assert "Resumed an earlier undelivered call" in text or PUBLISH_RESUMED_CALL_NOTICE_TEXT in text
    assert _decision_modes(service.app) == ["local"]

    # The outcome is delivered now: the same body again is a deliberate repeat, recorded.
    again = await bridge.dispatch_publish_work(body, runtime)
    assert again.isError is not True
    again_wire = cast(Mapping[str, Any], again.structuredContent)
    assert again_wire["outcome"] == "accepted"
    assert again_wire["request_id"] != first_id
    assert _decision_modes(service.app) == ["local", "local"]
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_a_call_orphaned_by_a_dead_bridge_is_resumed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A bridge that died mid-call left an in-flight binding; the next bridge resumes it."""

    _service_handle, _started, envelope = await _service(monkeypatch, 12200)
    body = _switch(envelope, "local")
    previous = PublishCallIdentities(state_root=tmp_path, owner="a" * 32)
    orphan = previous.bind(body)
    # The previous owner's process is gone: rewrite its pid to one that does not exist.
    record_path = tmp_path / PUBLISH_CALLS_DIRECTORY / "calls.json"
    document = json.loads(record_path.read_text())
    document["entries"][0]["pid"] = 2**22 + 12345
    record_path.write_text(json.dumps(document))
    runtime = _runtime(tmp_path)

    result = await bridge.dispatch_publish_work(body, runtime)

    assert result.isError is not True
    assert cast(Mapping[str, Any], result.structuredContent)["request_id"] == orphan.request_id
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_a_concurrent_identical_call_gets_its_own_identity(tmp_path: Path) -> None:
    """An identical call while the first is still in flight in a live process is not merged."""

    calls = PublishCallIdentities(state_root=tmp_path)
    first = calls.bind(_sparse_publish())
    second = calls.bind(_sparse_publish())
    assert first.request_id != second.request_id
    assert not first.resumed and not second.resumed


@pytest.mark.anyio
async def test_a_caller_retry_with_the_bound_id_closes_the_binding(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An agent that follows "retry with the same request_id" settles the host binding too."""

    service, _started, envelope = await _service(monkeypatch, 12300)
    runtime = _runtime(tmp_path)
    body = _switch(envelope, "local")
    service.lose_next_publish_reply = True
    lost = await bridge.dispatch_publish_work(body, runtime)
    first_id = cast(str, cast(Mapping[str, Any], lost.structuredContent)["request_id"])

    explicit = await bridge.dispatch_publish_work({**body, "request_id": first_id}, runtime)
    assert cast(Mapping[str, Any], explicit.structuredContent)["outcome"] == "replayed"
    assert _record(tmp_path) == []

    later = await bridge.dispatch_publish_work(body, runtime)
    later_wire = cast(Mapping[str, Any], later.structuredContent)
    assert later_wire["outcome"] == "accepted" and later_wire["request_id"] != first_id
    assert _decision_modes(service.app) == ["local", "local"]
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_brief_status_text_keeps_the_closure_instructions(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Review R5: a brief obligations read names the closure state and its action tokens."""

    _service_handle, started, envelope = await _service(monkeypatch, 12400)
    runtime = _runtime(tmp_path)
    obligation = protocol_id("obl_", 12401)
    plan = await bridge.dispatch_publish_work(
        {
            **envelope,
            "event_drafts": [
                {
                    "schema": {"name": "plan_published", "version": "1.0.0"},
                    "payload": {
                        "plan_version": 1,
                        "summary": "Do the requested work.",
                        "obligation_refs": [obligation],
                    },
                },
                {
                    "schema": {"name": "obligation_published", "version": "1.0.0"},
                    "payload": {
                        "obligation_id": obligation,
                        "description": "Implement change",
                        "status": "open",
                        "evidence_expectation": "test result",
                        "requested_items": [{"item_kind": "change", "value": "parser"}],
                    },
                },
            ],
        },
        runtime,
    )
    assert plan.isError is not True
    texts: dict[str, str] = {}
    for detail in ("brief", "full"):
        arguments: dict[str, object] = {
            **envelope,
            "request_id": protocol_id("req_", 12402 if detail == "brief" else 12403),
            "view": "obligations",
        }
        if detail == "full":
            arguments["detail"] = "full"
        result = await bridge.dispatch_status(arguments, runtime)
        assert result.isError is not True
        wire = cast(Mapping[str, Any], result.structuredContent)
        assert ("closure_state" in wire) is (detail == "brief")
        texts[detail] = cast(types.TextContent, result.content[0]).text
    for text in texts.values():
        assert "Closure: action_required." in text
        assert "Agent-actionable: " in text
        assert "obligations_open" in text
    assert "unavailable" not in texts["brief"]
    assert "detail: brief" in texts["brief"]
    del started
    await bridge.close_bridge_runtime(runtime)
