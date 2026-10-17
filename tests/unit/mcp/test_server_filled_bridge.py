"""Issue #1084 at the MCP bridge: the request identity of an id-less publish, and brief status.

ADR-050 decision 2, as revised by round 2 of the PR #1088 review: when an agent omits
``request_id`` the bridge mints a fresh one for that call. Its own transport retries reuse it and
every result and error names it; retrying an unknown outcome means sending that id. Nothing is
resumed by content and nothing is persisted. An id-less body identical to the writer's previous
id-less call that could have committed is refused, naming that call's id, so the caller chooses
(review N1-N6 of round 2 are pinned here as regressions).

The end-to-end cases drive the real ready application through the real disclosure boundary
(``project_case``); only the control-channel transport is replaced.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import dataclasses
import time
from collections.abc import Awaitable, Callable, Mapping
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
from finishup.domain.privacy import ConversationReview
from finishup.kernel.review_mode import conversation_review_mode
from finishup.mcp.publish_identity import PUBLISH_REPEAT_WINDOW_SECONDS, PublishRepeatGuard
from finishup.ports.control import ControlError, ControlMethod
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.ids import IdKind, is_valid_id, new_id
from finishup.protocol.models import (
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


def _runtime(guard: PublishRepeatGuard | None = None) -> bridge.BridgeRuntime:
    """A fresh bridge runtime: a new bridge process, with an empty guard unless one is given."""

    return dataclasses.replace(
        bridge.build_bridge_runtime(),
        publish_guard=PublishRepeatGuard() if guard is None else guard,
    )


def _capture(monkeypatch: pytest.MonkeyPatch, runtime: bridge.BridgeRuntime) -> list[BaseModel]:
    del runtime
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
        raise PublicOperationError(
            PublicErrorCode.OPERATION_PENDING,
            "The operation is still pending.",
            True,
        )

    monkeypatch.setattr(bridge, "ensure_service_client", ensure)
    monkeypatch.setattr(bridge, "_invoke_with_reconnect", invoke)
    return seen


def _text(result: types.CallToolResult) -> str:
    return "\n".join(block.text for block in result.content if isinstance(block, types.TextContent))


def _error(result: types.CallToolResult) -> Mapping[str, Any]:
    assert result.isError is True and result.structuredContent is not None
    return cast(Mapping[str, Any], result.structuredContent["error"])


@pytest.mark.anyio
async def test_an_idless_publish_gets_a_fresh_named_id(monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = _runtime()
    seen = _capture(monkeypatch, runtime)

    result = await bridge.dispatch_publish_work(_sparse_publish(), runtime)

    (forwarded,) = seen
    assert isinstance(forwarded, PublishWorkRequest)
    minted = forwarded.request_id
    assert is_valid_id(IdKind.REQUEST, minted)
    # The outcome is unknown: the error and its text name the id to retry with.
    assert result.structuredContent is not None
    assert result.structuredContent["request_id"] == minted
    assert f"FinishUP minted request_id {minted} for this call" in _text(result)
    assert "resending the body without it is not a retry" in _text(result)
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_an_invalid_idless_body_is_never_sent_or_remembered(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _runtime()
    seen = _capture(monkeypatch, runtime)
    arguments = _sparse_publish()
    drafts = cast(list[dict[str, object]], arguments["event_drafts"])
    drafts[0]["schema"] = {"name": "decision_recorded", "version": "9.9.9"}

    result = await bridge.dispatch_publish_work(arguments, runtime)

    assert seen == []
    assert runtime.publish_guard.previous_request_id(arguments) is None
    assert cast(Mapping[str, Any], result.structuredContent).get("request_id") is None
    assert _error(result)["code"] == PublicErrorCode.INVALID_REQUEST.value
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_an_idless_dry_run_touches_no_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = _runtime()
    seen = _capture(monkeypatch, runtime)
    arguments = {**_sparse_publish(), "dry_run": True}

    await bridge.dispatch_publish_work(arguments, runtime)
    await bridge.dispatch_publish_work(arguments, runtime)

    first, second = seen
    assert isinstance(first, PublishWorkRequest) and isinstance(second, PublishWorkRequest)
    assert first.request_id != second.request_id
    assert runtime.publish_guard.previous_request_id(_sparse_publish()) is None
    await bridge.close_bridge_runtime(runtime)


def test_the_guard_is_memory_only() -> None:
    """Review N2/N3: there is no record to corrupt, short-write or leave stale after cleanup."""

    import finishup.mcp.publish_identity as module

    for name in ("os", "Path", "state_dir", "fcntl", "json"):
        assert not hasattr(module, name), name


@pytest.mark.anyio
@pytest.mark.parametrize(("sent", "expected"), [(None, "brief"), ("full", "full")])
async def test_status_asks_for_the_brief_detail_unless_the_agent_names_one(
    monkeypatch: pytest.MonkeyPatch, sent: str | None, expected: str
) -> None:
    runtime = _runtime()
    seen = _capture(monkeypatch, runtime)
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


def _refusal(result: types.CallToolResult) -> str:
    """The earlier request id a repeat refusal names (structured and in the text)."""

    error = _error(result)
    assert error["code"] == PublicErrorCode.INVALID_REQUEST.value
    details = cast(Mapping[str, Any], error["safe_details"])
    assert details["reason_code"] == "publish_repeat_unconfirmed"
    assert details["continuation"] == "publish_identity_choice"
    previous = cast(str, details["replay_request_id"])
    assert f"The previous identical call ran under request_id {previous}" in _text(result)
    # The refusal names no request id of its own, so nothing (a host hook included) mistakes it
    # for the outcome of the earlier call.
    assert cast(Mapping[str, Any], result.structuredContent).get("request_id") is None
    return previous


async def _lose_one(
    service: _Service, runtime: bridge.BridgeRuntime, body: Mapping[str, Any]
) -> str:
    """Commit ``body`` and lose its reply; return the id the error named."""

    service.lose_next_publish_reply = True
    lost = await bridge.dispatch_publish_work(body, runtime)
    assert lost.isError is True
    minted = cast(str, cast(Mapping[str, Any], lost.structuredContent)["request_id"])
    assert f"FinishUP minted request_id {minted} for this call" in _text(lost)
    return minted


@pytest.mark.anyio
async def test_a_deliberate_identical_repeat_through_the_bridge_is_recorded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Review R1 end to end: ai -> local -> ai, each an id-less call, records three switches."""

    service, _started, envelope = await _service(monkeypatch, 12000)
    runtime = _runtime()
    outcomes: list[object] = []
    for mode in ("ai_powered", "local", "ai_powered"):
        result = await bridge.dispatch_publish_work(_switch(envelope, mode), runtime)
        assert result.isError is not True
        outcomes.append(cast(Mapping[str, Any], result.structuredContent)["outcome"])
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
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_a_lost_reply_is_retried_by_its_named_id_never_by_content(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A committed call whose reply was lost: a blind resend is refused, the named id replays."""

    service, _started, envelope = await _service(monkeypatch, 12100)
    runtime = _runtime()
    body = _switch(envelope, "local")
    minted = await _lose_one(service, runtime, body)

    refused = await bridge.dispatch_publish_work(body, runtime)
    assert _refusal(refused) == minted
    assert service.publish_ids == [minted]  # nothing was sent

    retried = await bridge.dispatch_publish_work({**body, "request_id": minted}, runtime)
    wire = cast(Mapping[str, Any], retried.structuredContent)
    assert wire["request_id"] == minted and wire["outcome"] == "replayed"
    assert _decision_modes(service.app) == ["local"]

    # The explicit retry settled it: the identical id-less body is now a new publication.
    again = await bridge.dispatch_publish_work(body, runtime)
    again_wire = cast(Mapping[str, Any], again.structuredContent)
    assert again_wire["outcome"] == "accepted" and again_wire["request_id"] != minted
    assert _decision_modes(service.app) == ["local", "local"]
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_a_result_lost_after_dispatch_still_guards_the_resend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Round 2 N1: a fault after the result was built, before it reaches the host."""

    service, _started, envelope = await _service(monkeypatch, 12150)
    runtime = _runtime()
    body = _switch(envelope, "local")
    with pytest.MonkeyPatch.context() as patch:

        def fail(*_args: object) -> types.CallToolResult:
            raise OSError("simulated failure before the result reaches the transport")

        patch.setattr(bridge, "_with_status_streak_nudge", fail)
        with pytest.raises(OSError):
            await bridge.call_tool("publish_work", body, runtime)
    (committed,) = service.publish_ids

    refused = await bridge.call_tool("publish_work", body, runtime)
    assert _refusal(refused) == committed
    retried = await bridge.call_tool("publish_work", {**body, "request_id": committed}, runtime)
    assert cast(Mapping[str, Any], retried.structuredContent)["outcome"] == "replayed"
    assert _decision_modes(service.app) == ["local"]
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_a_new_bridge_process_records_a_deliberate_switch_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Round 2 N2: no stale state survives a bridge to swallow ai -> local -> ai."""

    service, _started, envelope = await _service(monkeypatch, 12200)
    first = _runtime()
    accepted = await bridge.dispatch_publish_work(_switch(envelope, "ai_powered"), first)
    assert cast(Mapping[str, Any], accepted.structuredContent)["outcome"] == "accepted"
    await bridge.close_bridge_runtime(first)
    second = _runtime()
    outcomes = [
        cast(
            Mapping[str, Any],
            (await bridge.dispatch_publish_work(_switch(envelope, mode), second)).structuredContent,
        )["outcome"]
        for mode in ("local", "ai_powered")
    ]
    assert outcomes == ["accepted", "accepted"]
    assert _decision_modes(service.app) == ["ai_powered", "local", "ai_powered"]
    await bridge.close_bridge_runtime(second)


@pytest.mark.anyio
async def test_other_writers_never_displace_a_writers_guard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Round 2 N4: hundreds of other writers' id-less calls keep this writer's record."""

    service, _started, envelope = await _service(monkeypatch, 12250)
    runtime = _runtime()
    body = _switch(envelope, "local")
    minted = await _lose_one(service, runtime, body)
    for _ in range(300):
        runtime.publish_guard.record(
            {**body, "writer_id": new_id(IdKind.WRITER)}, new_id(IdKind.REQUEST)
        )
    assert _refusal(await bridge.dispatch_publish_work(body, runtime)) == minted
    assert _decision_modes(service.app) == ["local"]
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_a_backward_wall_clock_step_keeps_the_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    """Round 2 N5: the guard's window runs on monotonic time; a wall-clock step does nothing."""

    service, _started, envelope = await _service(monkeypatch, 12300)
    runtime = _runtime()
    body = _switch(envelope, "local")
    minted = await _lose_one(service, runtime, body)
    wall = time.time()
    monkeypatch.setattr(time, "time", lambda: wall - 1_000.0)
    assert _refusal(await bridge.dispatch_publish_work(body, runtime)) == minted
    assert _decision_modes(service.app) == ["local"]
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_another_writers_reuse_of_the_id_keeps_the_guard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Round 2 N6 (A): writer B publishing under A's unknown id never settles A's call."""

    service, started, envelope = await _service(monkeypatch, 12350)
    other = await service.app.start(
        start_request(12351, mode="attach", session_id=started.session_id)
    )
    assert other.task_id == started.task_id and other.writer_id != started.writer_id
    runtime = _runtime()
    body = _switch(envelope, "local")
    minted = await _lose_one(service, runtime, body)
    other_body = {
        **_switch(envelope, "ai_powered"),
        "session_id": other.session_id,
        "writer_id": other.writer_id,
        "request_id": minted,
    }
    accepted = await service.app.publish_work(PublishWorkRequest.model_validate(other_body))
    assert accepted.outcome == "accepted"
    runtime.publish_guard.explicit(other_body)  # the bridge's own call for B's delivery
    assert _refusal(await bridge.dispatch_publish_work(body, runtime)) == minted
    assert _decision_modes(service.app) == ["local", "ai_powered"]
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_a_same_id_preview_keeps_the_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    """Round 2 N6 (B): a dry run under the unknown call's id appends nothing and settles nothing."""

    service, _started, envelope = await _service(monkeypatch, 12400)
    runtime = _runtime()
    body = _switch(envelope, "local")
    minted = await _lose_one(service, runtime, body)
    base_invoke = service.invoke

    async def invoke(
        _runtime: object, request: BaseModel, _call: Any, *args: object, **kwargs: object
    ) -> object:
        if isinstance(request, PublishWorkRequest) and request.dry_run is True:
            return await service.app.publish_work(request)
        return await base_invoke(_runtime, request, _call, *args, **kwargs)

    monkeypatch.setattr(bridge, "_invoke_with_reconnect", invoke)
    preview = await bridge.dispatch_publish_work(
        {**body, "request_id": minted, "dry_run": True}, runtime
    )
    assert cast(Mapping[str, Any], preview.structuredContent)["outcome"] == "dry_run"
    assert _refusal(await bridge.dispatch_publish_work(body, runtime)) == minted
    assert _decision_modes(service.app) == ["local"]
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_the_guard_is_bounded_to_the_writers_previous_call_and_the_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The stated limits: after another publish, or after the window, the body is new."""

    service, _started, envelope = await _service(monkeypatch, 12450)
    now = [1_000.0]
    runtime = _runtime(PublishRepeatGuard(clock=lambda: now[0]))
    body = _switch(envelope, "ai_powered")
    await _lose_one(service, runtime, body)
    switched = await bridge.dispatch_publish_work(_switch(envelope, "local"), runtime)
    assert cast(Mapping[str, Any], switched.structuredContent)["outcome"] == "accepted"
    after_other = await bridge.dispatch_publish_work(body, runtime)
    assert cast(Mapping[str, Any], after_other.structuredContent)["outcome"] == "accepted"
    assert _decision_modes(service.app) == ["ai_powered", "local", "ai_powered"]

    lost_again = await _lose_one(service, runtime, _switch(envelope, "local"))
    now[0] += PUBLISH_REPEAT_WINDOW_SECONDS + 1
    expired = await bridge.dispatch_publish_work(_switch(envelope, "local"), runtime)
    expired_wire = cast(Mapping[str, Any], expired.structuredContent)
    assert expired_wire["outcome"] == "accepted" and expired_wire["request_id"] != lost_again
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_an_immediate_deliberate_repeat_is_asked_not_dropped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Identical id-less bodies back to back: the second is refused, a fresh id records it."""

    service, _started, envelope = await _service(monkeypatch, 12500)
    runtime = _runtime()
    body = _switch(envelope, "local")
    first = await bridge.dispatch_publish_work(body, runtime)
    first_id = cast(str, cast(Mapping[str, Any], first.structuredContent)["request_id"])
    assert _refusal(await bridge.dispatch_publish_work(body, runtime)) == first_id
    fresh = protocol_id("req_", 12501)
    again = await bridge.dispatch_publish_work({**body, "request_id": fresh}, runtime)
    assert cast(Mapping[str, Any], again.structuredContent)["outcome"] == "accepted"
    assert _decision_modes(service.app) == ["local", "local"]
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_a_certainly_rejected_call_does_not_guard_its_resend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A refusal before any append wrote nothing, so the identical resend is simply sent."""

    service, started, envelope = await _service(monkeypatch, 12550)
    runtime = _runtime()
    first = await bridge.dispatch_publish_work(_switch(envelope, "ai_powered"), runtime)
    assert first.isError is not True
    stale = {
        **_switch(envelope, "local"),
        "expected_frontier": {
            "sequence": started.frontier.sequence,
            "head_digest": started.frontier.head_digest,
        },
    }
    conflict = await bridge.dispatch_publish_work(stale, runtime)
    assert _error(conflict)["code"] == PublicErrorCode.FRONTIER_CONFLICT.value
    resend = await bridge.dispatch_publish_work(stale, runtime)
    assert _error(resend)["code"] == PublicErrorCode.FRONTIER_CONFLICT.value
    assert len(service.publish_ids) == 3
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_brief_status_text_keeps_the_closure_instructions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Review R5: a brief obligations read names the closure state and its action tokens."""

    _service_handle, started, envelope = await _service(monkeypatch, 12600)
    runtime = _runtime()
    obligation = protocol_id("obl_", 12601)
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
            "request_id": protocol_id("req_", 12602 if detail == "brief" else 12603),
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


async def _run_cli(
    monkeypatch: pytest.MonkeyPatch,
    service: _Service,
    body: Mapping[str, Any],
    *,
    broken_stdout: bool = False,
) -> tuple[int, list[str], list[str]]:
    """Run ``finishup publish-work`` in process against the real application."""

    import json

    import finishup.cli.app as cli

    events: list[str] = []
    errors: list[str] = []

    class Client:
        async def publish_work(self, request: PublishWorkRequest, **_kwargs: object) -> object:
            events.append(f"sent {request.request_id}")
            return await service.invoke(None, request, cast(Any, None))

        async def close(self) -> None:
            return None

    async def build() -> Client:
        return Client()

    def stderr(text: str) -> None:
        events.append("stderr")
        errors.append(text)

    def stdout(_wire: object) -> None:
        if broken_stdout:
            raise OSError("simulated broken stdout pipe")

    monkeypatch.setattr(cli, "build_service_client", build)
    monkeypatch.setattr(cli, "_stderr", stderr)
    monkeypatch.setattr(cli, "_stdout_json", stdout)
    code = await cli._call_workflow(
        "publish_work", PublishWorkRequest, None, json.dumps(body), True, None
    )
    return code, events, errors


@pytest.mark.anyio
async def test_the_cli_names_the_minted_id_before_sending(monkeypatch: pytest.MonkeyPatch) -> None:
    """``finishup publish-work`` keeps the bridge's contract, and states the id before sending."""

    service, _started, envelope = await _service(monkeypatch, 12700)
    code, events, errors = await _run_cli(monkeypatch, service, _switch(envelope, "local"))
    assert code == 0
    (minted,) = service.publish_ids
    assert events[:2] == ["stderr", f"sent {minted}"]
    assert errors[0].startswith(f"request_id {minted}: minted by FinishUP for this publish-work")


@pytest.mark.anyio
async def test_a_cli_output_failure_keeps_the_identity_and_is_not_a_usage_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Round 2 N1 (CLI): the write committed and only printing it failed."""

    from finishup.cli.exits import exit_code_for

    service, _started, envelope = await _service(monkeypatch, 12750)
    body = _switch(envelope, "ai_powered")
    code, _events, errors = await _run_cli(monkeypatch, service, body, broken_stdout=True)
    (minted,) = service.publish_ids
    assert code == exit_code_for(PublicErrorCode.INTERNAL_ERROR)
    assert any(minted in line and "minted by FinishUP" in line for line in errors)
    assert any(line.startswith("result_output_failed:") and minted in line for line in errors)
    retried, _events, _errors = await _run_cli(monkeypatch, service, {**body, "request_id": minted})
    assert retried == 0
    assert service.publish_ids == [minted, minted]
    assert _decision_modes(service.app) == ["ai_powered"]
