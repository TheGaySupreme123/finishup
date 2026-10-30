"""Fixed wording for a task's own work lifecycle on every rendering (issue #1239).

One owner of the line the CLI, the terminal interface and the MCP summaries print for the
``task_lifecycle`` block status reports. Every input is a closed token or a re-validated RFC 3339
timestamp; nothing else reaches this text. An open task in contact prints nothing: that is the
ordinary state, and the brief status body omits the block for it.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Final, cast

__all__ = ["status_task_lifecycle_line"]

_TIMESTAMP: Final = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z")
_WORK_STATES: Final = frozenset({"open", "closed", "abandoned", "cancelled", "written_off"})
_SESSION_HEALTH: Final = frozenset({"active", "contact_lost", "ended"})
_REASONS: Final = frozenset({"contact_lost", "session_ended", "attach_handle_expired"})


def _token(value: object, allowed: frozenset[str]) -> str | None:
    return value if type(value) is str and value in allowed else None


def _time(value: object) -> str | None:
    return value if type(value) is str and _TIMESTAMP.fullmatch(value) else None


def status_task_lifecycle_line(value: object) -> str:
    """One line for a status ``task_lifecycle`` block, or ``""`` for open work in contact."""

    if not isinstance(value, Mapping):
        return ""
    lifecycle = cast(Mapping[str, object], value)
    work = _token(lifecycle.get("work_state"), _WORK_STATES)
    health = _token(lifecycle.get("session_health"), _SESSION_HEALTH)
    if work is None or health is None:
        return ""
    reason = _token(lifecycle.get("abandonment_reason"), _REASONS)
    at = _time(lifecycle.get("abandonment_at"))
    lost = _time(lifecycle.get("contact_lost_at"))
    quiet = _time(lifecycle.get("quiet_until"))
    if work == "open" and quiet is not None:
        line = status_task_lifecycle_line({**lifecycle, "quiet_until": None})
        declared = f"quiet period declared until {quiet}"
        return f"Work: open; {declared}." if not line else f"{line[:-1]}; {declared}."
    if work == "open":
        if reason == "session_ended":
            return (
                "Work: open; the session ended"
                + ("" if at is None else f"; open work is abandoned at {at}")
                + " unless the session resumes first."
            )
        if health == "contact_lost":
            return (
                "Work: open; session contact lost"
                + ("" if lost is None else f" at {lost}")
                + ("" if at is None else f"; open work is abandoned at {at}")
                + " unless contact returns first (a FinishUP call or reported host activity)."
            )
        return "" if health == "active" else f"Work: open; session {health}."
    if work == "abandoned":
        # An ended session cannot publish the close, so only a live one is offered it.
        remedy = (
            "this session can still close it"
            if reason == "contact_lost" and health != "ended"
            else "start a successor task for new work"
        )
        return (
            "Work: abandoned by the service"
            + ("" if reason is None else f" ({reason})")
            + ("" if at is None else f" at {at}")
            + f"; {remedy}."
        )
    if work == "closed" and lifecycle.get("abandonment_reversed") is True:
        return (
            "Work: closed; this session's close reversed the service's contact_lost "
            "abandonment" + ("" if at is None else f" at {at}") + "."
        )
    return f"Work: {work.replace('_', ' ')}."
