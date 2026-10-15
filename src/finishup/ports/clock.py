"""Injectable wall-clock and process-local monotonic-time boundary."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

__all__ = ["ClockPort"]


class ClockPort(Protocol):
    """Supply validated UTC metadata time and process-local deadline samples."""

    def now_utc(self) -> datetime:
        """Return an exact-millisecond, zero-offset built-in ``datetime``."""
        ...

    def monotonic_seconds(self) -> float:
        """Return a finite, nonnegative, nondecreasing process-local sample."""
        ...
