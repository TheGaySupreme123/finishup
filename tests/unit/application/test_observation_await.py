"""Issue #1012: the optional bounded pre-check wait for this task's hook observations."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from finishup.application.observation_await import (
    AWAIT_OBSERVATIONS_BOUND_SECONDS,
    await_observations_bound,
    await_task_observations,
)
from finishup.ports.ledger import CheckObservationsAwaited

_SESSION = "ses_00000000-0000-4000-8000-000000000001"


class _Clock:
    """Deterministic monotonic clock that advances only when the wait pauses."""

    def __init__(self) -> None:
        self.now = 100.0
        self.pauses: list[float] = []

    def monotonic(self) -> float:
        return self.now

    async def pause(self, seconds: float) -> None:
        self.pauses.append(seconds)
        self.now += seconds


class _Probe:
    """Real-state stand-in: returns each scripted outbox snapshot in order, then the last."""

    def __init__(self, *states: frozenset[str]) -> None:
        self._states: Iterator[frozenset[str]] = iter(states)
        self._last = frozenset[str]()
        self.calls: list[str] = []

    def __call__(self, session_id: str, deadline: float) -> frozenset[str]:
        del deadline
        self.calls.append(session_id)
        self._last = next(self._states, self._last)
        return self._last


@pytest.mark.anyio
async def test_wait_completes_once_every_snapshot_row_is_delivered() -> None:
    clock = _Clock()
    wakes: list[None] = []
    # Row "c" arrives after the snapshot and is never waited for.
    probe = _Probe(
        frozenset({"a", "b"}),
        frozenset({"b"}),
        frozenset({"c"}),
    )

    outcome = await await_task_observations(
        probe,
        _SESSION,
        wake=lambda: wakes.append(None),
        bound_seconds=3.0,
        monotonic=clock.monotonic,
        pause=clock.pause,
    )

    assert outcome == CheckObservationsAwaited("complete", 0)
    assert wakes == [None]
    assert probe.calls == [_SESSION, _SESSION, _SESSION]
    assert clock.now - 100.0 < 3.0


@pytest.mark.anyio
async def test_a_row_that_never_drains_ends_in_a_bounded_timeout() -> None:
    clock = _Clock()
    wakes: list[None] = []
    probe = _Probe(frozenset({"stuck", "gone"}), frozenset({"stuck"}))

    outcome = await await_task_observations(
        probe,
        _SESSION,
        wake=lambda: wakes.append(None),
        bound_seconds=3.0,
        monotonic=clock.monotonic,
        pause=clock.pause,
    )

    assert outcome == CheckObservationsAwaited("bounded_timeout", 1)
    # Bounded by the injected deadline, observing real state between short pauses.
    assert clock.now == pytest.approx(103.0)
    assert max(clock.pauses) <= 0.1 + 1e-9
    # The sweeper is woken at the start and re-woken about once a second while rows remain.
    assert 2 <= len(wakes) <= 4


@pytest.mark.anyio
async def test_nothing_pending_completes_without_waking_or_pausing() -> None:
    clock = _Clock()
    wakes: list[None] = []

    outcome = await await_task_observations(
        _Probe(frozenset()),
        _SESSION,
        wake=lambda: wakes.append(None),
        bound_seconds=3.0,
        monotonic=clock.monotonic,
        pause=clock.pause,
    )

    assert outcome == CheckObservationsAwaited("complete", 0)
    assert wakes == []
    assert clock.pauses == []


@pytest.mark.anyio
async def test_unreadable_outbox_reports_unavailable_and_never_raises() -> None:
    def broken(session_id: str, deadline: float) -> frozenset[str]:
        raise TimeoutError("store lock contended")

    assert await await_task_observations(
        broken, _SESSION, wake=lambda: None, bound_seconds=3.0
    ) == CheckObservationsAwaited("unavailable", 0)
    assert await await_task_observations(
        None, _SESSION, wake=lambda: None, bound_seconds=3.0
    ) == CheckObservationsAwaited("unavailable", 0)


@pytest.mark.anyio
async def test_a_failed_poll_keeps_the_last_count() -> None:
    clock = _Clock()
    calls = 0

    def flaky(session_id: str, deadline: float) -> frozenset[str]:
        nonlocal calls
        calls += 1
        if calls == 1:
            return frozenset({"a"})
        raise TimeoutError("store lock contended")

    outcome = await await_task_observations(
        flaky,
        _SESSION,
        wake=lambda: None,
        bound_seconds=0.5,
        monotonic=clock.monotonic,
        pause=clock.pause,
    )

    assert outcome == CheckObservationsAwaited("bounded_timeout", 1)


def test_bound_is_three_seconds_and_a_tenth_of_the_request_deadline() -> None:
    assert await_observations_bound(None) == AWAIT_OBSERVATIONS_BOUND_SECONDS == 3.0
    assert await_observations_bound(30_000) == 3.0
    assert await_observations_bound(600_000) == 3.0
    assert await_observations_bound(10_000) == pytest.approx(1.0)
    assert await_observations_bound(1_000) == pytest.approx(0.1)


@pytest.mark.parametrize(
    ("state", "count"),
    (("complete", 1), ("unavailable", 2), ("bounded_timeout", 0), ("skipped", 0)),
)
def test_outcome_value_is_closed(state: str, count: int) -> None:
    with pytest.raises(ValueError):
        CheckObservationsAwaited(state, count)  # type: ignore[arg-type]
