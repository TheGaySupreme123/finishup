"""One deadline bounds a whole MCP tool call (review of PR #1227, issue #1226).

The check RPC deadline sat below Codex's 300-second tool-call limit, but service discovery ran
first on its own budget of up to 30 seconds and a reconnect started a fresh RPC budget, so a slow
cold connection plus an RPC timeout still answered after the host had given up. Discovery,
invocation and any reconnect now share one monotonic deadline; running out is FinishUP's typed
timeout with its recovery handle. A fake clock stands in for the elapsed time: nothing sleeps.
"""

from __future__ import annotations

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
