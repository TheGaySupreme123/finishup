"""Optional bounded pre-check wait for the caller's own hook observations (issue #1012).

``check`` with ``await_observations: true`` asks the service to let this task's hook rows that
are already in the local outbox reach the ledger before the case freezes. The wait snapshots
those rows, wakes the observation sweeper, and polls real local outbox state until none of the
snapshot rows is still pending or the bound expires. Rows that arrive after the snapshot are
not waited for. The wait never fails the check: an unreadable outbox reports ``unavailable``.

Since tb4n5 the snapshot also covers this task's rollout rows held for their hook post (#910):
the probe releases each one read long enough ago, with ``unpaired_event``, so it reaches the
ledger before the case freezes, and counts a younger one as pending, so a held row the wait
could not settle is the reported ``bounded_timeout`` remainder rather than a silent ``complete``.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from typing import Final

from finishup.ports.ledger import CheckObservationsAwaited

__all__ = [
    "AWAIT_OBSERVATIONS_BOUND_SECONDS",
    "AWAIT_OBSERVATIONS_DEADLINE_SHARE",
    "TaskPendingProbe",
    "await_observations_bound",
    "await_task_observations",
]

# The whole wait, wake to last poll, stays within about three seconds.
AWAIT_OBSERVATIONS_BOUND_SECONDS: Final = 3.0
# ...and never takes more than this share of the caller's request deadline, so the check itself
# keeps the rest of it (MCP check calls run under a bounded bridge deadline, issue #886).
AWAIT_OBSERVATIONS_DEADLINE_SHARE: Final = 0.1
# Real-state poll cadence and the sweeper re-wake cadence while rows remain.
_POLL_SECONDS: Final = 0.1
_REWAKE_SECONDS: Final = 1.0

# Blocking read: ``(finishup_session_id, monotonic_deadline) -> pending row identities``.
type TaskPendingProbe = Callable[[str, float], frozenset[str]]


def await_observations_bound(deadline_ms: int | None) -> float:
    """Return the wait bound in seconds for one request deadline."""

    if deadline_ms is None:
        return AWAIT_OBSERVATIONS_BOUND_SECONDS
    return max(
        0.0,
        min(
            AWAIT_OBSERVATIONS_BOUND_SECONDS,
            deadline_ms / 1_000 * AWAIT_OBSERVATIONS_DEADLINE_SHARE,
        ),
    )


async def await_task_observations(
    probe: TaskPendingProbe | None,
    session_id: str,
    *,
    wake: Callable[[], None],
    bound_seconds: float,
    monotonic: Callable[[], float] = time.monotonic,
    pause: Callable[[float], Awaitable[None]] = asyncio.sleep,
    poll_seconds: float = _POLL_SECONDS,
) -> CheckObservationsAwaited:
    """Wait, bounded, until this task's already-pending hook rows are delivered.

    ``probe`` runs off the event loop with its store-lock waits bounded by the wait deadline.
    ``pause`` exists so tests can drive the poll cadence without wall-clock sleeps; production
    uses ``asyncio.sleep`` between reads of real outbox state.
    """

    if probe is None:
        return CheckObservationsAwaited("unavailable", 0)
    started = monotonic()
    deadline = started + max(0.0, bound_seconds)
    # The probe's lock deadline uses ``time.monotonic`` regardless of the injected clock.
    lock_deadline = time.monotonic() + max(0.0, bound_seconds)
    try:
        snapshot = await asyncio.to_thread(probe, session_id, lock_deadline)
    except Exception:
        # Store contention or an unreadable state root: report it, never fail the check.
        return CheckObservationsAwaited("unavailable", 0)
    if not snapshot:
        return CheckObservationsAwaited("complete", 0)
    wake()
    last_wake = started
    left = snapshot
    while True:
        remaining = deadline - monotonic()
        if remaining <= 0.0:
            break
        await pause(min(poll_seconds, remaining))
        try:
            current = await asyncio.to_thread(
                probe, session_id, time.monotonic() + max(0.0, deadline - monotonic())
            )
        except Exception:
            # Keep the last observed count; a later poll may still read the store.
            continue
        left = snapshot & current
        if not left:
            return CheckObservationsAwaited("complete", 0)
        now = monotonic()
        if now - last_wake >= _REWAKE_SECONDS:
            # A pass that resolved nothing idles until its next wake; ask once more.
            wake()
            last_wake = now
    return CheckObservationsAwaited("bounded_timeout", len(left))
