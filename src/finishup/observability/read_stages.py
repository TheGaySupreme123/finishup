"""Per-stage elapsed time for one service read, recorded only when the read is slow (#1231).

A status read that times out used to leave one record naming the handler as a whole, so an
operator could not tell whether it waited on a dispatch gate, the task route, a cold ledger
replay, or the projection query. The daemon opens one :class:`ReadStageClock` per read-only
request; the layers it calls mark closed stage names with :func:`read_stage`. Outside such a
request the marker does nothing.

Records carry only a closed stage token (``phase``), an integer ``duration_ms`` and the outcome
``completed``, ``interrupted`` (the stage was left by an exception, such as the read's deadline
firing while it waited there) or ``in_flight`` (still open when the record was written). Nothing
about the request body, a path, or user content is recorded.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Generator, Iterable
from contextlib import contextmanager
from contextvars import ContextVar, Token
from typing import Final

from finishup.observability.logging import record_bounded_counts_without_raising

__all__ = [
    "READ_STAGES",
    "SLOW_READ_STAGE_MS",
    "SLOW_READ_TOTAL_MS",
    "ReadStageClock",
    "begin_read_stages",
    "end_read_stages",
    "read_stage",
]

# Closed vocabulary: a stage outside it is silently not timed, never recorded as free text.
READ_STAGES: Final = frozenset(
    {
        "observation_gate",
        "maintenance_gate",
        "admission",
        "handler",
        "repository_route",
        "session_renewal",
        "runtime_route",
        "ledger_recovery",
        "frontier",
        "operation_lookup",
        "projection_query",
        "credential_state",
        "response_projection",
    }
)
# A completed stage shorter than this is not worth a record; an interrupted or in-flight stage
# is always recorded.
SLOW_READ_STAGE_MS: Final = 50
# A read that completes slower than this records its stages even though it succeeded.
SLOW_READ_TOTAL_MS: Final = 2_000

_CURRENT: ContextVar[ReadStageClock | None] = ContextVar("finishup_read_stages", default=None)


class ReadStageClock:
    """Accumulate elapsed wall time per closed stage for one read."""

    __slots__ = ("_active", "_clock", "_elapsed", "_interrupted", "_order", "started")

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self.started = clock()
        self._elapsed: dict[str, float] = {}
        self._active: dict[str, float] = {}
        self._interrupted: set[str] = set()
        self._order: list[str] = []

    def enter(self, stage: str) -> None:
        if stage not in READ_STAGES or stage in self._active:
            return
        self._active[stage] = self._clock()
        if stage not in self._elapsed:
            self._elapsed[stage] = 0.0
            self._order.append(stage)

    def leave(self, stage: str, *, interrupted: bool = False) -> None:
        began = self._active.pop(stage, None)
        if began is not None:
            self._elapsed[stage] += max(0.0, self._clock() - began)
            if interrupted:
                self._interrupted.add(stage)
            else:
                self._interrupted.discard(stage)

    def total_ms(self) -> int:
        return _ms(self._clock() - self.started)

    def snapshot(self) -> tuple[tuple[str, int, str], ...]:
        """Return ``(stage, elapsed_ms, outcome)`` in first-entry order."""

        now = self._clock()
        rows: list[tuple[str, int, str]] = []
        for stage in self._order:
            elapsed = self._elapsed[stage]
            began = self._active.get(stage)
            if began is not None:
                elapsed += max(0.0, now - began)
                outcome = "in_flight"
            elif stage in self._interrupted:
                outcome = "interrupted"
            else:
                outcome = "completed"
            rows.append((stage, _ms(elapsed), outcome))
        return tuple(rows)

    def record(
        self,
        *,
        component: str,
        operation: str,
        request_id: str | None,
        correlation_id: str | None,
        force: bool,
    ) -> str | None:
        """Record slow and in-flight stages under one correlation; return it, or ``None``.

        ``force`` records even a fast read (the caller is reporting a timeout); otherwise only
        a read slower than ``SLOW_READ_TOTAL_MS`` records anything.
        """

        if not force and self.total_ms() < SLOW_READ_TOTAL_MS:
            return None
        written: str | None = None
        for stage, elapsed_ms, outcome in _selected(self.snapshot()):
            written = record_bounded_counts_without_raising(
                component=component,
                operation=operation,
                outcome=outcome,
                request_id=request_id,
                correlation_id=correlation_id if written is None else written,
                counts={"phase": stage, "duration_ms": elapsed_ms},
            )
        return written


def _selected(
    rows: Iterable[tuple[str, int, str]],
) -> Generator[tuple[str, int, str]]:
    for stage, elapsed_ms, outcome in rows:
        if outcome != "completed" or elapsed_ms >= SLOW_READ_STAGE_MS:
            yield stage, elapsed_ms, outcome


def _ms(seconds: float) -> int:
    return max(0, min(int(seconds * 1_000), 2**53 - 1))


def begin_read_stages(
    clock: Callable[[], float] = time.monotonic,
) -> tuple[ReadStageClock, Token[ReadStageClock | None]]:
    stages = ReadStageClock(clock)
    return stages, _CURRENT.set(stages)


def end_read_stages(token: Token[ReadStageClock | None]) -> None:
    _CURRENT.reset(token)


@contextmanager
def read_stage(stage: str) -> Generator[None]:
    """Time ``stage`` for the current read; a no-op outside a timed read."""

    stages = _CURRENT.get()
    if stages is None:
        yield
        return
    stages.enter(stage)
    try:
        yield
    except BaseException:
        stages.leave(stage, interrupted=True)
        raise
    stages.leave(stage)
