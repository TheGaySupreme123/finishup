"""When the AI-powered review round stops for an insufficient packet (tb4n1 D3, issue #983).

The owner's rule: semantic review helps only with good data, so after the reviewer twice in a
row could not assess the packet (``insufficient_packet``, whether or not it named what it
needed), the request and its one retry, later checks skip the AI-powered review instead of
looping. Publishing more evidence does not re-arm it, because feeding the reviewer excerpts is
the loop this rule ends; a recorded edit to the work does, because a repaired deliverable is new
data worth one more review. Reads recorded check payloads and edit actions only; pure.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Final

from yoetz.domain.events import (
    ActionKind,
    ActionRecordedPayload,
    CheckRecordedPayload,
    LedgerRecord,
)
from yoetz.protocol.models import SemanticStatus

__all__ = [
    "INSUFFICIENT_PACKET_ROUND_LIMIT",
    "INSUFFICIENT_PACKET_TASK_LIMIT",
    "review_round_stopped",
]

# The first ``insufficient_packet`` review and its one retry.
INSUFFICIENT_PACKET_ROUND_LIMIT: Final = 2
# Across the whole task, edits re-arm the round at most this many insufficient reviews: a host
# whose writes are shell commands never records an edit action, and a trivial edit must not buy
# endless reviews of a packet that cannot show the work.
INSUFFICIENT_PACKET_TASK_LIMIT: Final = 4


def review_round_stopped(records: Iterable[LedgerRecord]) -> bool:
    """Whether the next check skips the AI-powered review.

    True when the newest completed review concluded ``insufficient_packet`` and either the last
    ``INSUFFICIENT_PACKET_ROUND_LIMIT`` completed reviews all did with no edit action recorded
    after the older of them, or ``INSUFFICIENT_PACKET_TASK_LIMIT`` such reviews were recorded
    since the task's last assessed review. Checks that did not run a review (local-only, skipped, blocked or failed)
    neither count nor reset; a completed review with any other conclusion resets both counts.
    """

    consecutive = 0
    total = 0
    edited = False
    newest_insufficient: bool | None = None
    for record in reversed(tuple(records)):
        payload = record.payload
        name = record.schema.name
        if (
            name == "action_recorded"
            and type(payload) is ActionRecordedPayload
            and payload.action_kind is ActionKind.EDIT
        ):
            # An edit after (or between) the insufficient reviews is new work worth a review.
            edited = True
            continue
        if name != "check_recorded" or type(payload) is not CheckRecordedPayload:
            continue
        if payload.semantic_status is not SemanticStatus.SUCCEEDED:
            continue
        insufficient = payload.semantic_conclusion == "insufficient_packet"
        if newest_insufficient is None:
            newest_insufficient = insufficient
            if not insufficient:
                return False
        if not insufficient:
            break
        total += 1
        if not edited:
            consecutive += 1
            if consecutive >= INSUFFICIENT_PACKET_ROUND_LIMIT:
                return True
        if total >= INSUFFICIENT_PACKET_TASK_LIMIT:
            return True
    return False
