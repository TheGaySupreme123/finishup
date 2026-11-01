"""Lightweight observation failures shared by hooks and service boundaries."""

from __future__ import annotations

__all__ = ["ObservationStoreLockTimeout"]


class ObservationStoreLockTimeout(TimeoutError):  # noqa: N818 - TimeoutError family
    """A bounded wait for the shared local observation-store lock expired.

    Contention, not a fault: nothing was committed by the attempt, so every
    caller may retry the same operation. ``str()`` stays
    ``observation_store_lock_timeout`` so existing timeout handling is
    unchanged. The attributes are closed structural facts about the observed
    holder, never a path, payload, or process argument (#689):

    - ``scope``: ``thread`` when another thread of this process held the
      process-local lock, ``process`` when another process held the flock;
    - ``holder_role``/``holder_phase``: the holder's role and store operation,
      ``unknown`` when the holder had not stamped the lock yet;
    - ``holder_held_ms``: how long the holder had held it when the wait expired;
    - ``holder_waiting``: the in-process holder was itself still queueing for
      the cross-process flock (a lock convoy, not a long critical section).
    """

    def __init__(
        self,
        *,
        scope: str,
        waited_ms: int,
        holder_role: str,
        holder_phase: str,
        holder_held_ms: int | None,
        holder_waiting: bool = False,
    ) -> None:
        super().__init__("observation_store_lock_timeout")
        self.scope = scope
        self.waited_ms = waited_ms
        self.holder_role = holder_role
        self.holder_phase = holder_phase
        self.holder_held_ms = holder_held_ms
        self.holder_waiting = holder_waiting
