"""Issue #1012: the daemon runs the optional pre-check wait before the dispatch gates."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any

import pytest

from yoetz.ports.control import ControlCallRequest, ControlMethod
from yoetz.ports.ledger import CheckObservationsAwaited
from yoetz.protocol.models import CheckRequest
from yoetz.service.check_waits import CheckWaits
from yoetz.service.daemon import ServiceDaemon

_SESSION = "ses_00000000-0000-4000-8000-0000000000c4"


def _request(*, mode: str, await_observations: bool | None) -> ControlCallRequest:
    body: dict[str, object] = {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": "req_00000000-0000-4000-8000-0000000000c3",
        "session_id": _SESSION,
        "writer_id": "wri_00000000-0000-4000-8000-0000000000c5",
        "expected_frontier": {"sequence": "0", "head_digest": "genesis"},
        "mode": mode,
        "actor": {"actor_id": "harness:test", "actor_type": "harness"},
        "client": {"kind": "test_client", "version": "0.1.0", "integration": "cooperative_mcp"},
    }
    if await_observations is not None:
        body["await_observations"] = await_observations
    return ControlCallRequest(
        kind="call",
        protocol_version="1.0",
        rpc_id="rpc_00000000-0000-4000-8000-0000000000c2",
        service_instance_id="svc_00000000-0000-4000-8000-0000000000c1",
        service_generation="7",
        method=ControlMethod.CHECK,
        body=CheckRequest.model_validate(body),
        deadline_ms=30_000,
    )


class _Probe:
    def __init__(self, gate: asyncio.Lock, *states: frozenset[str]) -> None:
        self._gate = gate
        self._states = list(states)
        self.calls: list[str] = []
        self.gate_held: list[bool] = []

    def __call__(self, session_id: str, deadline: float) -> frozenset[str]:
        del deadline
        self.calls.append(session_id)
        self.gate_held.append(self._gate.locked())
        return self._states.pop(0) if len(self._states) > 1 else self._states[0]


def _daemon(gate: asyncio.Lock, probe: _Probe | None) -> tuple[Any, list[dict[str, Any]]]:
    daemon = ServiceDaemon.__new__(ServiceDaemon)
    setattr(daemon, "_composition", SimpleNamespace(maintenance_gate=gate))
    setattr(daemon, "_observation_sweep_wake", asyncio.Event())
    setattr(daemon, "_observation_ingest_wake", asyncio.Event())
    setattr(daemon, "_check_waits", CheckWaits())
    setattr(daemon, "_check_read_window", SimpleNamespace(admits_readers=False))
    sweep = SimpleNamespace(task_pending_probe=probe)
    setattr(daemon, "_application", SimpleNamespace(observation_sweep=sweep))
    seen: list[dict[str, Any]] = []

    async def under_gate(*_args: object, **kwargs: Any) -> object:
        assert gate.locked()
        seen.append(kwargs)
        return "dispatched"

    setattr(daemon, "_dispatch_ready_under_maintenance_gate", under_gate)
    return daemon, seen


@pytest.mark.anyio
@pytest.mark.parametrize("mode", ["deterministic_only", "semantic_if_configured"])
async def test_requested_wait_runs_before_the_gates_and_reaches_the_handler(mode: str) -> None:
    gate = asyncio.Lock()
    probe = _Probe(gate, frozenset({"row-1"}), frozenset())
    daemon, seen = _daemon(gate, probe)

    result = await daemon._dispatch_ready(
        SimpleNamespace(), _request(mode=mode, await_observations=True), None
    )

    assert result == "dispatched"
    assert probe.calls == [_SESSION, _SESSION]
    # The sweeper takes the observation gate per row; the wait must never hold a gate.
    assert probe.gate_held == [False, False]
    assert daemon._observation_sweep_wake.is_set()
    assert seen[-1]["observations_awaited"] == CheckObservationsAwaited("complete", 0)


@pytest.mark.anyio
@pytest.mark.parametrize("flag", [None, False])
async def test_without_the_flag_nothing_waits_and_nothing_is_attached(flag: bool | None) -> None:
    gate = asyncio.Lock()
    probe = _Probe(gate, frozenset({"row-1"}))
    daemon, seen = _daemon(gate, probe)

    await daemon._dispatch_ready(
        SimpleNamespace(), _request(mode="deterministic_only", await_observations=flag), None
    )

    assert probe.calls == []
    assert not daemon._observation_sweep_wake.is_set()
    assert seen[-1]["observations_awaited"] is None


@pytest.mark.anyio
async def test_without_a_probe_the_wait_reports_unavailable() -> None:
    gate = asyncio.Lock()
    daemon, seen = _daemon(gate, None)

    await daemon._dispatch_ready(
        SimpleNamespace(), _request(mode="deterministic_only", await_observations=True), None
    )

    assert seen[-1]["observations_awaited"] == CheckObservationsAwaited("unavailable", 0)


@pytest.mark.anyio
async def test_handler_receives_the_outcome_only_when_one_exists() -> None:
    calls: list[dict[str, object]] = []

    async def handler(_body: object, **kwargs: object) -> object:
        calls.append(kwargs)
        return None

    request = _request(mode="deterministic_only", await_observations=True)
    invoke = ServiceDaemon._invoke_ready_handler  # pyright: ignore[reportPrivateUsage]
    await invoke(handler, request, None)
    outcome = CheckObservationsAwaited("bounded_timeout", 1)
    await invoke(handler, request, None, observations_awaited=outcome)

    assert "observations_awaited" not in calls[0]
    assert calls[1]["observations_awaited"] == outcome
