"""Injectable identifier-generation boundary."""

from __future__ import annotations

from typing import Protocol

from finishup.protocol.ids import IdKind

__all__ = ["IdPort"]


class IdPort(Protocol):
    """Allocate one canonical identifier of the requested kind."""

    def new(self, kind: IdKind) -> str:
        """Return one fresh identifier without caching or retrying generation."""
        ...
