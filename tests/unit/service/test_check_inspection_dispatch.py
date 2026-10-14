"""Issue #1048 (ADR-047): the daemon dispatches ``mode: inspect`` as a read.

A minting AI-powered check runs detached under the check-wait registry and a failure after the
handler is reported as a write (same-``request_id`` replay). An inspection records nothing, so it
must do neither: it runs inline like ``status`` and a failure is a retryable read failure.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any

import pytest

from unit.service.test_check_await_observations_dispatch import _Probe, _request
from yoetz.ports.control import ControlCallRequest
from yoetz.ports.ledger import CheckObservationsAwaited
from yoetz.service import daemon as daemon_module
from yoetz.service.check_waits import CheckWaits
from yoetz.service.daemon import ServiceDaemon


class _NeverDetach(CheckWaits):
    async def run(self, *_args: Any, **_kwargs: Any) -> Any:  # type: ignore[override]
        raise AssertionError("an inspection must not run detached")


def _daemon(gate: asyncio.Lock, probe: _Probe | None) -> tuple[Any, list[dict[str, Any]]]:
    daemon = ServiceDaemon.__new__(ServiceDaemon)
    setattr(daemon, "_composition", SimpleNamespace(maintenance_gate=gate))
    setattr(daemon, "_observation_sweep_wake", asyncio.Event())
    setattr(daemon, "_observation_ingest_wake", asyncio.Event())
    setattr(daemon, "_check_waits", _NeverDetach())
    setattr(daemon, "_check_read_window", SimpleNamespace(admits_readers=False))
    sweep = SimpleNamespace(task_pending_probe=probe)
    setattr(daemon, "_application", SimpleNamespace(observation_sweep=sweep))
    seen: list[dict[str, Any]] = []

    async def under_gate(*_args: object, **kwargs: Any) -> object:
        seen.append(kwargs)
        return "dispatched"

    setattr(daemon, "_dispatch_ready_under_maintenance_gate", under_gate)
    return daemon, seen


def _inspect(await_observations: bool | None = None) -> ControlCallRequest:
    return _request(mode="inspect", await_observations=await_observations)


def test_an_inspection_is_classified_as_a_read() -> None:
    assert daemon_module._request_is_read_only(_inspect())
    assert not daemon_module._request_is_read_only(
        _request(mode="deterministic_only", await_observations=None)
    )
    assert not daemon_module._request_is_read_only(
        _request(mode="semantic_required", await_observations=None)
    )


@pytest.mark.anyio
async def test_an_inspection_runs_inline_and_keeps_its_requested_wait() -> None:
    gate = asyncio.Lock()
    probe = _Probe(gate, frozenset())
    daemon, seen = _daemon(gate, probe)

    assert await daemon._dispatch_ready(SimpleNamespace(), _inspect(True), None) == "dispatched"
    assert seen[-1].get("detached_check", False) is False
    assert seen[-1]["observations_awaited"] == CheckObservationsAwaited("complete", 0)

    assert await daemon._dispatch_ready(SimpleNamespace(), _inspect(), None) == "dispatched"
    assert seen[-1]["observations_awaited"] is None
