"""One deadline bounds a whole MCP tool call (review of PR #1227, issue #1226).

The check RPC deadline sat below Codex's 300-second tool-call limit, but service discovery ran
first on its own budget of up to 30 seconds and a reconnect started a fresh RPC budget, so a slow
cold connection plus an RPC timeout still answered after the host had given up. Discovery,
invocation and any reconnect now share one monotonic deadline; running out is FinishUP's typed
timeout with its recovery handle. A fake clock stands in for the elapsed time: nothing sleeps.
"""

from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace
from typing import Any, cast

import pytest
from mcp import types

import finishup.mcp.server as bridge
from finishup.ports.control import ControlError

_REQUEST = "req_80d0cc7a-150f-4d7b-9aa3-a50312db0078"
_SESSION = "ses_00000000-0000-4000-8000-000000000001"
_WRITER = "wri_00000000-0000-4000-8000-000000000001"
_HOST_LIMIT_MS = 300_000


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class _Clock:
    def __init__(self) -> None:
        self.now = 1_000.0

    def monotonic(self) -> float:
        return self.now

    def advance_ms(self, value: int | float) -> None:
        self.now += value / 1_000


class _Client:
    """A connected service client whose every RPC consumes its whole deadline, or fails first."""

    def __init__(self, clock: _Clock, *, disconnect_after_ms: int | None = None) -> None:
        self.clock = clock
        self.disconnect_after_ms = disconnect_after_ms
        self.deadlines: list[int] = []
        self.methods: list[str] = []

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def _rpc(self, method: str, deadline_ms: int | None) -> Any:
        assert type(deadline_ms) is int
        self.methods.append(method)
        self.deadlines.append(deadline_ms)
        if self.disconnect_after_ms is not None:
            self.clock.advance_ms(self.disconnect_after_ms)
            raise ControlError("service_unavailable", retryable=True)
        self.clock.advance_ms(deadline_ms)
        raise ControlError("request_timeout", retryable=True, phase="handler")

    def __getattr__(self, method: str) -> Any:
        async def call(_request: object, *, deadline_ms: int | None = None, **_: object) -> Any:
            return await self._rpc(method, deadline_ms)

        return call


def _install(
    monkeypatch: pytest.MonkeyPatch,
    clock: _Clock,
    clients: list[_Client],
    discovery_ms: int | list[int],
) -> list[float]:
    """Each discovery takes its ``discovery_ms`` of fake time and hands out the next client."""

    budgets: list[float] = []
    durations = list(discovery_ms) if isinstance(discovery_ms, list) else None

    async def on_demand(
        _kind: object, *, workspace_locator: object = None, timeout_seconds: float = 30.0
    ) -> object:
        del workspace_locator
        budgets.append(timeout_seconds)
        duration = durations.pop(0) if durations is not None else cast(int, discovery_ms)
        clock.advance_ms(min(duration, timeout_seconds * 1_000))
        return clients.pop(0)

    monkeypatch.setattr(bridge, "time", SimpleNamespace(monotonic=clock.monotonic))
    monkeypatch.setattr(bridge, "connect_service_on_demand", on_demand)
    for name in ("", "_CHECK", "_STATUS", "_PUBLISH_WORK"):
        for prefix in ("FINISHUP_", "YOETZ_"):
            monkeypatch.delenv(f"{prefix}MCP_DEADLINE_MS{name}", raising=False)
    return budgets


def _envelope() -> dict[str, object]:
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": _REQUEST,
        "actor": {"actor_id": "harness:mcp", "actor_type": "harness"},
        "client": {
            "kind": "cooperative_agent",
            "version": "0.1.0",
            "integration": "cooperative_mcp",
        },
        "session_id": _SESSION,
        "writer_id": _WRITER,
        "expected_frontier": {"sequence": "1", "head_digest": "sha256:" + "0" * 64},
    }


def _check_body() -> dict[str, object]:
    return {**_envelope(), "mode": "semantic_required"}


def _publish_body() -> dict[str, object]:
    return {
        **_envelope(),
        "event_drafts": [
            {
                "event_id": "evt_00000000-0000-4000-8000-000000000002",
                "schema": {"name": "result_recorded", "version": "1.0.0"},
                "occurred_at": "2026-01-01T00:00:00.000Z",
                "causal_parents": [],
                "payload": {
                    "result_id": "res_00000000-0000-4000-8000-000000000001",
                    "action_id": "act_00000000-0000-4000-8000-000000000001",
                    "outcome": "success",
                },
                "artifact_refs": [],
                "evidence_refs": [],
            }
        ],
    }


def _timeout_details(result: types.CallToolResult) -> dict[str, object]:
    structured = cast(dict[str, Any], result.structuredContent)
    error = cast(dict[str, Any], structured["error"])
    assert error["code"] == "SERVICE_UNAVAILABLE" and error["retryable"] is True
    details = cast(dict[str, object], error["safe_details"])
    assert details["reason_code"] == "request_timeout"
    return details


async def _run(dispatch: Any, body: dict[str, object]) -> types.CallToolResult:
    runtime = bridge.build_bridge_runtime()
    try:
        return await dispatch(body, runtime)
    finally:
        await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_a_slow_discovery_leaves_the_check_only_what_remains(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _Clock()
    client = _Client(clock)
    budgets = _install(monkeypatch, clock, [client], discovery_ms=29_000)
    started = clock.now

    result = await _run(bridge.dispatch_check, _check_body())

    elapsed_ms = (clock.now - started) * 1_000
    check_deadline = bridge._DEFAULT_RPC_DEADLINES_MS["check"]  # pyright: ignore[reportPrivateUsage]
    assert budgets == [30.0]
    assert client.deadlines == [check_deadline - 29_000]
    assert elapsed_ms <= check_deadline < _HOST_LIMIT_MS
    details = _timeout_details(result)
    # The typed timeout keeps its recovery handle: same request id, same-identity continuation.
    assert details["replay_request_id"] == _REQUEST
    assert details["continuation"] == "write_timeout_same_identity"


@pytest.mark.anyio
async def test_a_late_disconnect_and_reconnect_get_no_fresh_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _Clock()
    first = _Client(clock, disconnect_after_ms=230_000)
    second = _Client(clock)
    budgets = _install(monkeypatch, clock, [first, second], discovery_ms=[29_000, 5_000])
    started = clock.now

    result = await _run(bridge.dispatch_check, _check_body())

    check_deadline = bridge._DEFAULT_RPC_DEADLINES_MS["check"]  # pyright: ignore[reportPrivateUsage]
    # The reconnect's discovery is capped by what remains, and so is the replayed RPC: 280 s less
    # the first discovery (29 s), the dropped RPC (230 s) and the second discovery (5 s).
    assert budgets == [30.0, (check_deadline - 29_000 - 230_000) / 1_000]
    assert second.deadlines == [check_deadline - 29_000 - 230_000 - 5_000]
    assert (clock.now - started) * 1_000 <= check_deadline
    assert _timeout_details(result)["replay_request_id"] == _REQUEST


@pytest.mark.anyio
async def test_an_exhausted_call_answers_with_the_typed_timeout_before_reconnecting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _Clock()
    check_deadline = bridge._DEFAULT_RPC_DEADLINES_MS["check"]  # pyright: ignore[reportPrivateUsage]
    first = _Client(clock, disconnect_after_ms=check_deadline)
    budgets = _install(monkeypatch, clock, [first], discovery_ms=0)

    result = await _run(bridge.dispatch_check, _check_body())

    # No second discovery and no second RPC: the call had nothing left.
    assert len(budgets) == 1 and first.deadlines == [check_deadline]
    assert _timeout_details(result)["replay_request_id"] == _REQUEST


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("dispatch", "body", "tool"),
    [
        (bridge.dispatch_check, _check_body(), "CHECK"),
        (bridge.dispatch_publish_work, _publish_body(), "PUBLISH_WORK"),
    ],
    ids=("check", "publish_work"),
)
async def test_no_call_outlives_the_host_limit_even_at_the_largest_override(
    monkeypatch: pytest.MonkeyPatch, dispatch: Any, body: dict[str, object], tool: str
) -> None:
    """The largest override, a 29 s discovery, an RPC timeout and a write's probe all fit."""

    clock = _Clock()
    clients = [_Client(clock) for _ in range(4)]
    _install(monkeypatch, clock, clients, discovery_ms=29_000)
    monkeypatch.setenv(f"FINISHUP_MCP_DEADLINE_MS_{tool}", "999999")
    started = clock.now

    result = await _run(dispatch, body)

    assert (clock.now - started) * 1_000 < _HOST_LIMIT_MS
    assert _timeout_details(result)["replay_request_id"] == _REQUEST


def test_each_whole_call_budget_sits_below_its_host_limit() -> None:
    """The reads and ``start`` answer inside the common 60 s host limit; the rest inside 300 s."""

    budgets = bridge._CALL_BUDGET_MS  # pyright: ignore[reportPrivateUsage]
    deadlines = bridge._DEFAULT_RPC_DEADLINES_MS  # pyright: ignore[reportPrivateUsage]
    assert set(budgets) == set(deadlines)
    for tool, budget in budgets.items():
        # A budget never cuts a stage below its own configured RPC deadline.
        assert budget >= deadlines[tool], tool
        limit = 60_000 if tool in {"status", "start"} else _HOST_LIMIT_MS
        assert budget < limit, tool
    # ``closure_prepare`` and a ``check`` inspection are reads under the status budget.
    assert budgets["status"] == 55_000 and deadlines["status"] == 30_000


@pytest.mark.anyio
async def test_a_slow_discovery_and_a_status_timeout_answer_within_55_seconds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _Clock()
    client = _Client(clock)
    budgets = _install(monkeypatch, clock, [client], discovery_ms=29_000)
    started = clock.now
    body = {key: value for key, value in _envelope().items() if key != "expected_frontier"} | {
        "view": "compact"
    }

    result = await _run(bridge.dispatch_status, body)

    # Discovery keeps its full 30 s cap; the read gets the 26 s that remain of 55 s, not 30 s.
    assert budgets == [30.0]
    assert client.methods == ["status"] and client.deadlines == [26_000]
    assert (clock.now - started) * 1_000 <= 55_000
    details = _timeout_details(result)
    assert details["continuation"] == "read_timeout_new_identity"
    assert "replay_request_id" not in details


# -- Review round 2 -----------------------------------------------------------------------------

_COMPLETE_PAGE = object()
_CLEANUP_MS = 50


class _RecoveringClient(_Client):
    """Writes consume their whole deadline plus the permitted cancellation cleanup and time out;
    the operation probe finds the write ``complete`` after 5 s, so recovery replays it."""

    async def _rpc(self, method: str, deadline_ms: int | None) -> Any:
        assert type(deadline_ms) is int
        self.methods.append(method)
        self.deadlines.append(deadline_ms)
        if method == "status":
            self.clock.advance_ms(min(deadline_ms, 5_000))
            return _COMPLETE_PAGE
        self.clock.advance_ms(deadline_ms + _CLEANUP_MS)
        raise ControlError("request_timeout", retryable=True, phase="handler")


def _respond_body() -> dict[str, object]:
    return {
        **_envelope(),
        "finding_id": "fnd_00000000-0000-4000-8000-000000000001",
        "finding_frontier": {"sequence": "1", "head_digest": "sha256:" + "0" * 64},
        "disposition": "rejected",
        "reason": "Not an issue.",
        "evidence_refs": [],
    }


def _receipt_body() -> dict[str, object]:
    return {
        **_envelope(),
        "task_id": "tsk_00000000-0000-4000-8000-000000000001",
        "format": "json",
        "include": "summary",
        "redaction_profile": "full_local",
    }


_WRITES = [
    (bridge.dispatch_publish_work, _publish_body, "publish_work"),
    (bridge.dispatch_respond, _respond_body, "respond"),
    (bridge.dispatch_receipt, _receipt_body, "receipt"),
]


@pytest.mark.anyio
@pytest.mark.parametrize("override", [None, "999999"], ids=("default", "max_override"))
@pytest.mark.parametrize(("dispatch", "body", "tool"), _WRITES, ids=[w[2] for w in _WRITES])
async def test_write_recovery_and_cleanup_finish_under_the_host_ceiling(
    monkeypatch: pytest.MonkeyPatch, dispatch: Any, body: Any, tool: str, override: str | None
) -> None:
    """A timed-out write, a completed-operation probe and a slow same-request replay (each with
    the client's cancellation cleanup) still answer under the 60 s host limit."""

    clock = _Clock()
    client = _RecoveringClient(clock)
    _install(monkeypatch, clock, [client], discovery_ms=0)
    original = bridge.public_model_to_wire

    def to_wire(model: object) -> dict[str, Any]:
        if model is _COMPLETE_PAGE:
            return {"ok": True, "page": {"state": "complete"}}
        return original(model)

    monkeypatch.setattr(bridge, "public_model_to_wire", to_wire)
    if override is not None:
        monkeypatch.setenv(f"FINISHUP_MCP_DEADLINE_MS_{tool.upper()}", override)
    started = clock.now

    result = await _run(dispatch, body())

    ceiling = bridge._HOST_CEILING_MS[tool]  # pyright: ignore[reportPrivateUsage]
    margin = bridge._HOST_CEILING_MARGIN_MS  # pyright: ignore[reportPrivateUsage]
    elapsed_ms = (clock.now - started) * 1_000
    assert ceiling == 60_000
    # Every stage ends by the ceiling less the margin; cleanup overruns stay inside the margin.
    assert elapsed_ms <= ceiling - margin + 2 * _CLEANUP_MS < ceiling
    assert client.methods[0] == tool
    if override is None:
        # The probe found the write complete and the replay was tried with what remained.
        assert client.methods == [tool, "status", tool]
    details = _timeout_details(result)
    assert details["replay_request_id"] == _REQUEST


@pytest.mark.parametrize("override", [None, "999999"], ids=("default", "max_override"))
def test_every_budget_and_its_margin_fit_inside_the_tools_host_ceiling(
    monkeypatch: pytest.MonkeyPatch, override: str | None
) -> None:
    ceilings = bridge._HOST_CEILING_MS  # pyright: ignore[reportPrivateUsage]
    margin = bridge._HOST_CEILING_MARGIN_MS  # pyright: ignore[reportPrivateUsage]
    assert set(ceilings) == set(bridge._CALL_BUDGET_MS)  # pyright: ignore[reportPrivateUsage]
    assert ceilings["check"] == _HOST_LIMIT_MS
    assert all(ceilings[tool] == 60_000 for tool in ceilings if tool != "check")
    for tool in ceilings:
        for prefix in ("FINISHUP_", "YOETZ_"):
            monkeypatch.delenv(f"{prefix}MCP_DEADLINE_MS_{tool.upper()}", raising=False)
        if override is not None:
            monkeypatch.setenv(f"FINISHUP_MCP_DEADLINE_MS_{tool.upper()}", override)
        budget = bridge._call_budget_ms(tool)  # pyright: ignore[reportPrivateUsage]
        assert budget <= ceilings[tool] - margin, tool


@pytest.mark.anyio
@pytest.mark.parametrize("mode", [[], {}], ids=("list", "object"))
async def test_a_malformed_check_mode_is_an_invalid_request(mode: object) -> None:
    """Review round 2: an unhashable ``mode`` reached a set-membership test before validation."""

    sentinel = "zz_caller_sentinel"
    body = {**_check_body(), "mode": mode, "task_title": sentinel}
    runtime = bridge.build_bridge_runtime()
    try:
        result = await bridge.dispatch_check(body, runtime)
    finally:
        await bridge.close_bridge_runtime(runtime)
    structured = cast(dict[str, Any], result.structuredContent)
    assert result.isError is True
    assert structured["error"]["code"] == "INVALID_REQUEST"
    assert sentinel not in str(structured) and sentinel not in str(result.content)


class _Probe:
    """An on-demand start that parks until released, so another caller's probe stays in flight."""

    def __init__(self) -> None:
        self.entered = asyncio.Event()
        self.release = asyncio.Event()
        self.client = _LiveClient()

    async def __call__(
        self, _kind: object, *, workspace_locator: object = None, timeout_seconds: float = 30.0
    ) -> object:
        del workspace_locator, timeout_seconds
        self.entered.set()
        await self.release.wait()
        return self.client


class _LiveClient:
    def __init__(self, failure: BaseException | None = None) -> None:
        self.failure = failure
        self.proceed = asyncio.Event()
        self.called = asyncio.Event()

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def status(self, _request: object, **_: object) -> Any:
        self.called.set()
        await self.proceed.wait()
        assert self.failure is not None
        raise self.failure


async def _within(seconds: float, work: Any) -> Any:
    """Run ``work`` under a real call budget of ``seconds`` (real loop time, nothing sleeps)."""

    now = time.monotonic()
    token = bridge._CALL_BUDGET.set(  # pyright: ignore[reportPrivateUsage]
        bridge._CallBudget(now + seconds, now + seconds)  # pyright: ignore[reportPrivateUsage]
    )
    try:
        return await work()
    finally:
        bridge._CALL_BUDGET.reset(token)  # pyright: ignore[reportPrivateUsage]


@pytest.mark.anyio
async def test_an_expired_waiter_returns_promptly_and_leaves_the_other_probe_alone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probe = _Probe()
    monkeypatch.setattr(bridge, "connect_service_on_demand", probe)
    runtime = bridge.build_bridge_runtime()
    slot = runtime._slot  # pyright: ignore[reportPrivateUsage]
    try:
        owner = asyncio.create_task(
            _within(30.0, lambda: bridge.ensure_service_client(runtime, request_id=_REQUEST))
        )
        await probe.entered.wait()
        token = slot.attempt_owner
        assert slot.attempting is True and token is not None

        started = time.monotonic()
        with pytest.raises(ControlError) as caught:
            await _within(0.12, lambda: bridge.ensure_service_client(runtime))
        waited = time.monotonic() - started

        # The expired caller answers on its own deadline, not when the other probe finishes.
        assert caught.value.reason == "request_timeout"
        assert waited < 1.0 and not owner.done()
        assert slot.attempting is True and slot.attempt_owner is token
        probe.release.set()
        assert await owner is probe.client
        assert slot.client is probe.client and slot.attempting is False
    finally:
        await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_a_reconnect_behind_another_probe_times_out_on_its_own_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probe = _Probe()
    monkeypatch.setattr(bridge, "connect_service_on_demand", probe)
    runtime = bridge.build_bridge_runtime()
    slot = runtime._slot  # pyright: ignore[reportPrivateUsage]
    dropped = _LiveClient(ControlError("service_unavailable", retryable=True))
    slot.client = cast(Any, dropped)
    try:

        async def read() -> Any:
            return await bridge._invoke_with_reconnect(  # pyright: ignore[reportPrivateUsage]
                runtime,
                cast(Any, object()),
                lambda client, request: client.status(request),
                None,
            )

        reader = asyncio.create_task(_within(0.5, read))
        await dropped.called.wait()
        # While the read is in flight, the connection drops and another call starts the probe.
        slot.client = None
        owner = asyncio.create_task(
            _within(30.0, lambda: bridge.ensure_service_client(runtime, request_id=_REQUEST))
        )
        await probe.entered.wait()
        token = slot.attempt_owner
        dropped.proceed.set()

        started = time.monotonic()
        with pytest.raises(ControlError) as caught:
            await reader
        assert caught.value.reason == "request_timeout"
        assert time.monotonic() - started < 1.0 and not owner.done()
        assert slot.attempting is True and slot.attempt_owner is token
        probe.release.set()
        assert await owner is probe.client and slot.attempting is False
    finally:
        await bridge.close_bridge_runtime(runtime)
