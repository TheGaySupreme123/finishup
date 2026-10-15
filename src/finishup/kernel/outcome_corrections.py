"""Hook results whose unknown outcome a later host result for the same action supplied (#1001).

Codex reports a shell call's outcome on its session stream, not in the PostToolUse hook. The hook
result is therefore recorded with outcome ``unknown`` and the ``host_outcome_unavailable`` gap, and
the stream later appends a source-independent corrected result linked to the same canonical action
(``materialize_observation_outcome_correction``). Both rows stay immutable in the ledger. A reader
that counts commands or folds coverage must treat the unknown row as superseded once a known
outcome for its action is recorded, or every Codex command reads as two runs, one of them unknown.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Final

from finishup.domain.events import ResultOutcome, ResultRecordedPayload
from finishup.domain.values import EventId, ResultId
from finishup.kernel.projections import ProjectionRecord

__all__ = [
    "HOST_OUTCOME_UNAVAILABLE_GAP",
    "superseded_unknown_results",
]

# Mirrors ``application.observation_materialize.HOST_OUTCOME_UNAVAILABLE_GAP``; the kernel does not
# import the application layer.
HOST_OUTCOME_UNAVAILABLE_GAP: Final = "host_outcome_unavailable"


def superseded_unknown_results(
    results: Mapping[ResultId, ProjectionRecord[ResultRecordedPayload]],
    *,
    include: Callable[[EventId], bool] | None = None,
) -> frozenset[ResultId]:
    """Return unknown-outcome results whose action also has a known-outcome result.

    ``include`` restricts both sides to results whose source event the caller can see (for
    example the events a check observed); a correction outside that set supersedes nothing.
    """

    def visible(record: ProjectionRecord[ResultRecordedPayload]) -> bool:
        return record.payload is not None and (include is None or include(record.source_event_id))

    known_actions = {
        record.payload.action_id
        for record in results.values()
        if visible(record)
        and record.payload is not None
        and record.payload.outcome is not ResultOutcome.UNKNOWN
    }
    return frozenset(
        result
        for result, record in results.items()
        if visible(record)
        and record.payload is not None
        and record.payload.outcome is ResultOutcome.UNKNOWN
        and record.payload.action_id in known_actions
    )
