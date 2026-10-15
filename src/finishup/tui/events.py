"""The transcript event model.

The history is an append-only record of what FinishUP did and what it is prepared
to claim about it. Events carry an optional ``details`` block that the user can
open with ``D``; the summary above it never gets stronger because the details
exist. Events are frozen so a rendered transcript cannot drift from the moment
it described.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Self

from finishup.tui.symbols import Level

__all__ = ["HistoryEvent", "Transcript"]


@dataclass(frozen=True, slots=True)
class HistoryEvent:
    """One completed action, result, finding, or failure in the transcript."""

    level: Level
    title: str
    body: tuple[str, ...] = ()
    details: tuple[str, ...] = ()
    actions: tuple[str, ...] = ()

    @property
    def has_details(self) -> bool:
        return bool(self.details)

    def with_body(self, body: tuple[str, ...]) -> Self:
        return replace(self, body=body)


@dataclass(slots=True)
class Transcript:
    """An ordered, bounded history of events.

    The bound exists so a long session cannot grow the retained transcript
    without limit; it drops from the front, because the newest events are the
    ones the composer footer and the details view refer to.
    """

    limit: int = 500
    events: list[HistoryEvent] = field(default_factory=lambda: [])

    def append(self, event: HistoryEvent) -> HistoryEvent:
        self.events.append(event)
        if len(self.events) > self.limit:
            del self.events[: len(self.events) - self.limit]
        return event

    def replace_last(self, event: HistoryEvent) -> HistoryEvent:
        """Collapse an in-flight activity line into its completed form."""

        if not self.events:
            return self.append(event)
        self.events[-1] = event
        return event

    @property
    def last(self) -> HistoryEvent | None:
        return self.events[-1] if self.events else None

    def latest_with_details(self) -> HistoryEvent | None:
        for event in reversed(self.events):
            if event.has_details:
                return event
        return None

    def clear(self) -> None:
        self.events.clear()
