"""Task-local joins from privacy/provider code to the owning check request and its progress."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from contextvars import ContextVar
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from finishup.protocol.models import SemanticProgressPhase

__all__ = [
    "SemanticProgressSink",
    "report_semantic_progress",
    "semantic_check_request",
    "semantic_progress_sink",
]

semantic_check_request: ContextVar[str | None] = ContextVar("semantic_check_request", default=None)

type SemanticProgressSink = Callable[[SemanticProgressPhase], Awaitable[None]]

# Bound by the service for exactly one physical AI-powered review attempt (issue #571 A2). The
# sink records only the closed phase value; callers never pass content, identities, or counts.
semantic_progress_sink: ContextVar[SemanticProgressSink | None] = ContextVar(
    "semantic_progress_sink", default=None
)


async def report_semantic_progress(phase: SemanticProgressPhase) -> None:
    """Record one structural phase for the current attempt, if a sink is bound.

    Progress is advisory telemetry beside the durable attempt. A failure to record it is a bounded
    diagnostic and never changes the attempt's outcome, retry, or provider authority.
    """

    sink = semantic_progress_sink.get()
    if sink is None:
        return
    try:
        await sink(phase)
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001 - telemetry must not fail the attempt
        from finishup.observability.logging import record_unexpected_exception_without_raising

        record_unexpected_exception_without_raising(
            exc,
            component="semantic_progress",
            operation="semantic_progress_record_failed",
            request_id=semantic_check_request.get(),
        )
