"""A bounded nudge for an agent that keeps rereading ``status`` instead of writing (tb4 n5).

In the tb4 n5 S arm the agent called ``status`` 45+ times over an hour with no ``publish_work``,
``check``, ``respond`` or ``receipt`` while five obligations stayed open, although its tests had
passed. Guidance already says a status read is optional between ordinary steps; this module adds
the text-level counterpart on the result itself, with no protocol field and no ledger write.

The streak is the bridge's own per-process memory (one MCP bridge serves one host session): the
number of consecutive first-page ``status`` reads for one ``(session_id, actor_id)`` since that
session's last write call through this bridge. A write call (``start``, ``publish_work``,
``check``, ``respond`` or ``receipt``, whatever its outcome) resets the session's streaks. A
continuation page (a request carrying ``cursor``) and the ``operation`` view (polling a running
check) neither count nor nudge, because rereading is how those are meant to be used. A status
read cannot be recovered from the ledger (reads append nothing), so the rule cannot be stateless;
a bridge restart simply starts the count again, which only delays the nudge.

From the ``STATUS_STREAK_NUDGE_THRESHOLD``-th such read on, the result's text leads with one
concrete next write, chosen from the closure-readiness ``state`` and ``agent_actionable`` tokens
the same result already carries, and the first open obligation id it lists. Only closed tokens and
pattern-checked ids are rendered; nothing from the request or the ledger's prose reaches the text.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from collections.abc import Mapping, Sequence
from typing import Final, cast

from yoetz.domain.receipts import COMPLETION_PLAN_NOT_CLAIMED_GAP
from yoetz.domain.task_fact_tokens import (
    EDITED_AFTER_LAST_VERIFICATION_GAP,
    FINDING_REJECTION_AWAITING_RULING_GAP,
    PLANNED_VERIFICATION_FAILED_GAP,
    PLANNED_VERIFICATION_NOT_OBSERVED_GAP,
    PLANNED_VERIFICATION_STALE_GAP,
)
from yoetz.domain.values import JsonValue
from yoetz.protocol.ids import IdKind, is_valid_id

__all__ = [
    "STATUS_STREAK_NUDGE_THRESHOLD",
    "StatusReadStreaks",
    "status_streak_nudge",
]

STATUS_STREAK_NUDGE_THRESHOLD: Final = 3
# Write calls that end a streak. ``closure_prepare`` and ``read_guidance`` are reads.
_WRITE_OPERATIONS: Final = frozenset({"start", "publish_work", "check", "respond", "receipt"})
# Bound on the remembered (session, actor) pairs; the least recently read is forgotten first.
_MAX_TRACKED_STREAKS: Final = 64
_MAX_COUNT: Final = 1_000_000
_UNTRACKED_VIEWS: Final = frozenset({"operation"})
_RERUN_TOKENS: Final = frozenset(
    {
        EDITED_AFTER_LAST_VERIFICATION_GAP,
        PLANNED_VERIFICATION_FAILED_GAP,
        PLANNED_VERIFICATION_NOT_OBSERVED_GAP,
        PLANNED_VERIFICATION_STALE_GAP,
    }
)
_CHECK_TOKENS: Final = frozenset({"check_not_recorded", "semantic_review_not_requested"})


def _token(value: object) -> str:
    return value if type(value) is str and len(value) <= 128 else ""


class StatusReadStreaks:
    """Consecutive first-page ``status`` reads per ``(session_id, actor_id)`` in one bridge."""

    __slots__ = ("_counts", "_lock")

    def __init__(self) -> None:
        self._counts: OrderedDict[tuple[str, str], int] = OrderedDict()
        self._lock = threading.Lock()

    def note_call(self, operation: str, arguments: Mapping[str, object]) -> int:
        """Record one tool call; return the status streak it reached (``0`` when not counted)."""

        session = _token(arguments.get("session_id"))
        if operation in _WRITE_OPERATIONS:
            with self._lock:
                if not session:
                    # A start that creates a task names no session yet: every streak ends.
                    self._counts.clear()
                    return 0
                for key in [key for key in self._counts if key[0] == session]:
                    del self._counts[key]
            return 0
        if operation != "status" or not session:
            return 0
        if arguments.get("cursor") is not None or arguments.get("view") in _UNTRACKED_VIEWS:
            return 0
        actor = arguments.get("actor")
        actor_id = (
            _token(cast(Mapping[str, object], actor).get("actor_id"))
            if isinstance(actor, Mapping)
            else ""
        )
        key = (session, actor_id)
        with self._lock:
            count = min(self._counts.pop(key, 0) + 1, _MAX_COUNT)
            self._counts[key] = count
            while len(self._counts) > _MAX_TRACKED_STREAKS:
                self._counts.popitem(last=False)
        return count


def _readiness(wire: Mapping[str, object]) -> tuple[str, tuple[str, ...]]:
    raw = wire.get("closure_readiness")
    if not isinstance(raw, Mapping):
        return "", ()
    readiness = cast(Mapping[str, JsonValue], raw)
    state = _token(readiness.get("state"))
    items = readiness.get("agent_actionable")
    actionable = (
        tuple(item for item in cast(Sequence[JsonValue], items) if type(item) is str and item)
        if isinstance(items, (list, tuple))
        else ()
    )
    return state, actionable


def _first_open_obligation(wire: Mapping[str, object]) -> str | None:
    page = wire.get("page")
    if not isinstance(page, Mapping):
        return None
    raw_items = cast(Mapping[str, JsonValue], page).get("items")
    if not isinstance(raw_items, (list, tuple)):
        return None
    for raw in cast(Sequence[JsonValue], raw_items):
        if not isinstance(raw, Mapping):
            continue
        item = cast(Mapping[str, JsonValue], raw)
        nested = item.get("open_obligations")
        candidates: Sequence[object] = (
            cast(Sequence[JsonValue], nested) if isinstance(nested, (list, tuple)) else (item,)
        )
        for candidate in candidates:
            if not isinstance(candidate, Mapping):
                continue
            row = cast(Mapping[str, JsonValue], candidate)
            identifier = row.get("obligation_id")
            status = row.get("status")
            if (status is None or status == "open") and is_valid_id(IdKind.OBLIGATION, identifier):
                return cast(str, identifier)
    return None


def _next_write(wire: Mapping[str, object]) -> str:
    state, actionable = _readiness(wire)
    if state in {"ready", "ready_with_limitations"}:
        return "Next: call receipt."
    if "check_in_progress" in actionable:
        return ""
    if "obligations_open" in actionable:
        obligation = _first_open_obligation(wire)
        target = f"obligation_published for {obligation}" if obligation else "each open obligation"
        return (
            f"Next: publish_work {target} with status resolved and resolution_evidence_refs "
            "naming the evd_/res_ ids that show it done (publish that evidence first if it is "
            "not recorded), then call check."
        )
    if "findings_unanswered" in actionable:
        return "Next: call respond for each unanswered finding this result names."
    if "receipt_findings_unresolved" in actionable:
        return "Next: repair the receipt-blocking findings, publish_work the repair, then check."
    if "no_plan_published" in actionable or "no_obligations_declared" in actionable:
        return "Next: publish_work a plan that declares the obligations."
    if COMPLETION_PLAN_NOT_CLAIMED_GAP in actionable:
        return "Next: publish_work a completion claim_recorded citing your evidence."
    if any(token in _RERUN_TOKENS for token in actionable):
        return "Next: run the planned verification on the current state, then call check."
    if (
        "closing_review_required" in actionable
        or FINDING_REJECTION_AWAITING_RULING_GAP in actionable
    ):
        return "Next: call check with final_review: true."
    if any(token in _CHECK_TOKENS for token in actionable):
        return "Next: call check."
    if actionable:
        first = actionable[0] if len(actionable[0]) <= 145 else "an agent-actionable item"
        return f"Next: resolve {first} with publish_work, check, respond, or receipt."
    return "Next: publish_work your recorded results and evidence, then call check or receipt."


def status_streak_nudge(wire: Mapping[str, object], streak: int) -> str:
    """The one-line lead for a status result read ``streak`` times in a row, or ``""``.

    ``""`` below the threshold, for an error result, and while a check is still running.
    """

    if streak < STATUS_STREAK_NUDGE_THRESHOLD or wire.get("ok") is not True:
        return ""
    next_write = _next_write(wire)
    if not next_write:
        return ""
    return (
        f"Status read {streak} times in a row with no write. No status read is needed. {next_write}"
    )
