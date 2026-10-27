"""A status read keeps one deadline across the dispatch gates and its handler (#1231).

While one read's handler waits on a slow projection recovery it holds both dispatch gates. Every
other read used to wait up to its full deadline for the gates and then start a fresh full deadline
for its own handler, so queued reads ran (and held the gates and the task ledger) long after their
callers had given up. Each read now spends one budget, and a timed-out read names the stage it was
still waiting on in the diagnostic ring under the correlation id the caller receives.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from finishup.observability.diagnostics import lookup_diagnostic_records
from finishup.ports.control import ControlClientKind, ControlError, ControlMethod
from finishup.protocol.models import StatusRequest
from integration.service.test_daemon_clients import (
    _daemon,  # pyright: ignore[reportPrivateUsage]
    _operation_status_body,  # pyright: ignore[reportPrivateUsage]
    _request,  # pyright: ignore[reportPrivateUsage]
    _status_body,  # pyright: ignore[reportPrivateUsage]
)

pytestmark = pytest.mark.anyio

_DEADLINE_MS = 300
# Scheduling slack on a loaded CI machine; far below the extra full deadline the old path spent.
_SLACK_SECONDS = 0.2
_BOUND_SECONDS = 10.0


def _body(view: str, index: int) -> StatusRequest:
    base = _operation_status_body() if view == "operation" else _status_body()
    return base.model_copy(update={"request_id": f"req_00000000-0000-4000-8000-{500 + index:012d}"})


@pytest.mark.parametrize("view", ["compact", "operation"])
async def test_reads_queued_behind_a_parked_projection_recovery_keep_their_deadline(
    view: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import finishup.observability.diagnostics as diagnostics

    monkeypatch.setattr(diagnostics, "log_dir", lambda: tmp_path)
    daemon, application, _vault, _listener = _daemon()
    await daemon.start()
    composition = daemon.composition
    entered = asyncio.Event()
    recovered = asyncio.Event()
    handler_calls = 0
    original_status = application.status

    async def recovering_status(request: object, **kwargs: object) -> object:
        nonlocal handler_calls
        handler_calls += 1
        entered.set()
        # Stands in for a cold task-ledger replay the read must wait for.
        await recovered.wait()
        return await original_status(request, **kwargs)  # pyright: ignore[reportArgumentType]

    monkeypatch.setattr(application, "status", recovering_status)
    loop = asyncio.get_running_loop()

    async def timed_read(index: int, deadline_ms: int = _DEADLINE_MS) -> tuple[float, object]:
        started = loop.time()
        response = await daemon.dispatch(
            ControlClientKind.MCP_BRIDGE,
            _request(daemon, ControlMethod.STATUS, _body(view, index), deadline_ms=deadline_ms),
        )
        return loop.time() - started, response.body

    try:
        # Warm the one-time import and diagnostic-sink costs of the dispatch and timeout paths so
        # the measured round observes only the deadline arithmetic.
        _elapsed, warm = await asyncio.wait_for(timed_read(8, deadline_ms=20), _BOUND_SECONDS)
        assert isinstance(warm, ControlError) and warm.reason == "request_timeout"
        entered.clear()
        first = asyncio.create_task(timed_read(0))
        await asyncio.wait_for(entered.wait(), _BOUND_SECONDS)
        # The first read now holds both gates while it waits on the recovery.
        assert composition.maintenance_gate.locked()
        queued = [asyncio.create_task(timed_read(index)) for index in range(1, 5)]
        results = await asyncio.wait_for(asyncio.gather(first, *queued), _BOUND_SECONDS)

        for _elapsed, body in results:
            assert isinstance(body, ControlError)
            assert body.reason == "request_timeout"
            assert body.retryable is True
        elapsed_all = [round(elapsed, 3) for elapsed, _body in results]
        assert max(elapsed_all) <= _DEADLINE_MS / 1_000 + _SLACK_SECONDS, elapsed_all
        for _elapsed, body in results:
            assert isinstance(body, ControlError)
            # The caller's id resolves to the stage the read was still waiting on.
            assert body.correlation_id is not None
            stages = [
                record
                for record in lookup_diagnostic_records(body.correlation_id, root=tmp_path)
                if record["operation"] == "status_read_stage_elapsed"
            ]
            waited_on = {
                record["phase"]
                for record in stages
                if record.get("reason") in {"interrupted", "in_flight"}
            }
            assert waited_on & {"observation_gate", "maintenance_gate", "handler"}, repr(stages)

        first_body = results[0][1]
        assert isinstance(first_body, ControlError)
        assert first_body.phase == "handler"
        # Timed-out reads released the gates; nothing keeps running on behalf of a gone caller.
        assert not composition.maintenance_gate.locked()
        assert not composition.observation_gate.locked()

        recovered.set()
        calls_before = handler_calls
        served = await asyncio.wait_for(
            daemon.dispatch(
                ControlClientKind.MCP_BRIDGE,
                _request(daemon, ControlMethod.STATUS, _body(view, 9), deadline_ms=_DEADLINE_MS),
            ),
            _BOUND_SECONDS,
        )
        assert not (
            isinstance(served.body, ControlError) and served.body.reason == "request_timeout"
        )
        assert handler_calls == calls_before + 1
    finally:
        recovered.set()
        await daemon.close()


async def test_a_blocked_response_projection_ends_at_the_read_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Codex review P3: shaping a read's response stays inside its one budget."""

    daemon, _application, _vault, _listener = _daemon()
    await daemon.start()
    composition = daemon.composition
    projecting = asyncio.Event()
    never = asyncio.Event()

    async def blocked_projection(*_args: object, **_kwargs: object) -> object:
        projecting.set()
        # Stands in for binding, privacy projection or hydration that does not return.
        await never.wait()
        raise AssertionError("unreachable")

    monkeypatch.setattr(daemon, "_project_completed_response", blocked_projection)
    loop = asyncio.get_running_loop()
    started = loop.time()
    read = asyncio.create_task(
        daemon.dispatch(
            ControlClientKind.MCP_BRIDGE,
            _request(daemon, ControlMethod.STATUS, _status_body(), deadline_ms=_DEADLINE_MS),
        )
    )
    try:
        await asyncio.wait_for(projecting.wait(), _BOUND_SECONDS)
        # ``asyncio.wait`` observes without cancelling the dispatch.
        done, _pending = await asyncio.wait((read,), timeout=_BOUND_SECONDS / 4)
        assert read in done, "the read outlived its deadline in response projection"
        elapsed = loop.time() - started
        assert elapsed <= _DEADLINE_MS / 1_000 + _SLACK_SECONDS, elapsed
        body = read.result().body
        assert isinstance(body, ControlError)
        assert body.reason == "request_timeout"
        assert body.retryable is True
        assert body.phase == "projection"
        assert not composition.maintenance_gate.locked()
        assert not composition.observation_gate.locked()
    finally:
        never.set()
        if not read.done():
            read.cancel()
            await asyncio.wait((read,), timeout=_BOUND_SECONDS)
        await daemon.close()


@pytest.mark.parametrize("teardown_fails", [False, True])
async def test_stop_retires_the_ledger_pools_and_later_work_gets_fresh_ones(
    teardown_fails: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Codex review round 2: every stop() path retires the process-wide ledger pools."""

    import finishup.adapters.memory.ledger as ledger_module

    daemon, _application, _vault, _listener = _daemon()
    await daemon.start()
    pools: tuple[ledger_module.LedgerPool, ...] = ("write", "read", "recovery")
    retired = {pool: ledger_module.ledger_executor(pool) for pool in pools}
    if teardown_fails:

        async def failing_close_components() -> None:
            raise RuntimeError("teardown-failure")

        monkeypatch.setattr(daemon, "_close_components", failing_close_components)
        with pytest.raises(RuntimeError, match="teardown-failure"):
            await daemon.stop()
    else:
        await daemon.stop()
    for pool in pools:
        executor = retired[pool]
        with pytest.raises(RuntimeError):
            executor.submit(lambda: None)
        fresh = ledger_module.ledger_executor(pool)
        assert fresh is not executor
    assert await ledger_module.run_ledger_work(lambda: "fresh") == "fresh"
    assert await ledger_module.run_ledger_read(lambda: "fresh") == "fresh"
