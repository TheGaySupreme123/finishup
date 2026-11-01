"""Bounded, fair scheduling for admission-independent capture recovery (#695)."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import cast

import pytest

from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.application.observation_drain import (
    ObservationCaptureRecoveryOutcome as Outcome,
)
from finishup.application.observation_drain import (
    ObservationIngestCoordinator,
    ObservationOutboxSweeper,
)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _sweeper(
    callback: Callable[[str], Awaitable[Outcome | None]], *, budget: float = 5.0
) -> ObservationOutboxSweeper:
    # These tests exercise the scheduling boundary only. The service integration
    # tests supply the real local store, SQLite catalog, and capture callback.
    return ObservationOutboxSweeper(
        cast(LocalObservationStore, None),
        cast(ObservationIngestCoordinator, None),
        capture_recovery=callback,
        capture_recovery_budget_seconds=budget,
    )


async def _pass(
    sweeper: ObservationOutboxSweeper,
    workspaces: tuple[str, ...],
    remaining: float | None = None,
) -> tuple[Outcome, ...]:
    return await sweeper._recover_capture_inventory(  # pyright: ignore[reportPrivateUsage]
        workspaces, remaining=remaining
    )


@pytest.mark.anyio
async def test_recovery_rotates_four_unique_workspace_lanes() -> None:
    calls: list[str] = []

    async def recover(workspace: str) -> Outcome:
        calls.append(workspace)
        return Outcome.RECOVERED

    sweeper = _sweeper(recover)
    workspaces = ("f", "b", "a", "d", "c", "e", "a")
    assert await _pass(sweeper, workspaces) == (Outcome.RECOVERED,) * 4
    assert calls == ["a", "b", "c", "d"]
    assert await _pass(sweeper, workspaces) == (Outcome.RECOVERED,) * 4
    assert calls == ["a", "b", "c", "d", "e", "f", "a", "b"]


@pytest.mark.anyio
async def test_timeout_rotates_next_pass_past_slow_workspace() -> None:
    calls: list[str] = []
    cancelled = asyncio.Event()

    async def recover(workspace: str) -> Outcome:
        calls.append(workspace)
        if workspace == "a":
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.set()
        return Outcome.RECOVERED

    sweeper = _sweeper(recover, budget=0.02)
    async with asyncio.timeout(1):
        assert await _pass(sweeper, ("a", "b")) == (Outcome.TIMEOUT,)
        assert cancelled.is_set()
        assert calls == ["a"]
        assert await _pass(sweeper, ("a", "b")) == (Outcome.RECOVERED, Outcome.TIMEOUT)
        assert calls == ["a", "b", "a"]


@pytest.mark.anyio
async def test_sweep_cancellation_is_not_reported_as_recovery_failure() -> None:
    entered = asyncio.Event()
    finalized = asyncio.Event()

    async def recover(_workspace: str) -> Outcome:
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            finalized.set()
        return Outcome.RECOVERED

    operation = asyncio.create_task(_pass(_sweeper(recover), ("a",)))
    async with asyncio.timeout(1):
        await entered.wait()
        operation.cancel()
        with pytest.raises(asyncio.CancelledError):
            await operation
    assert finalized.is_set()


@pytest.mark.anyio
@pytest.mark.parametrize("remaining", (0.0, -1.0))
async def test_spent_sweep_budget_starts_no_inventory_read(remaining: float) -> None:
    async def recover(_workspace: str) -> Outcome:
        raise AssertionError("must not start after the sweep budget")

    assert await _pass(_sweeper(recover), ("a",), remaining) == ()


@pytest.mark.anyio
@pytest.mark.parametrize("bad_result", (False, True))
async def test_callback_failures_have_only_closed_structural_outcomes(bad_result: bool) -> None:
    async def recover(_workspace: str) -> Outcome:
        if bad_result:
            return cast(Outcome, "private-untrusted-detail")
        raise OSError("private-untrusted-detail")

    assert await _pass(_sweeper(recover), ("a",)) == (Outcome.INVENTORY_UNKNOWN,)


@pytest.mark.anyio
async def test_healthy_workspace_creates_no_recovery_result() -> None:
    async def recover(_workspace: str) -> None:
        return None

    assert await _pass(_sweeper(recover), ("a",)) == ()


@pytest.mark.anyio
async def test_sweep_gives_unknown_capture_inventory_a_turn_when_admission_maintenance_fails() -> (
    None
):
    """Recovery remains independent while delivery stays fail-closed."""

    calls: list[str] = []

    class _AdmissionFailingStore:
        def pending_workspaces(self) -> tuple[str, ...]:
            # This represents a workspace whose capture inventory is unknown.
            return ("workspace",)

        def maintain_selected_admission(self, _workspace: str, *, force: bool) -> None:
            del force
            raise RuntimeError("admission maintenance failed")

    async def recover(workspace: str) -> Outcome:
        calls.append(workspace)
        return Outcome.INVENTORY_UNKNOWN

    sweeper = ObservationOutboxSweeper(
        cast(LocalObservationStore, _AdmissionFailingStore()),
        cast(ObservationIngestCoordinator, None),
        capture_recovery=recover,
    )
    try:
        with pytest.raises(RuntimeError, match="^admission maintenance failed$"):
            await sweeper.sweep()
    finally:
        sweeper.close()

    assert calls == ["workspace"]


@pytest.mark.parametrize("budget", (0.0, -1.0, float("nan"), float("inf"), 1, True, "5"))
def test_recovery_budget_must_be_finite_positive_float(budget: object) -> None:
    async def recover(_workspace: str) -> None:
        return None

    with pytest.raises(ValueError, match="^observation_capture_recovery_budget_invalid$"):
        _sweeper(recover, budget=cast(float, budget))
