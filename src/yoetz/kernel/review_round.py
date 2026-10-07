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

__all__ = ["INSUFFICIENT_PACKET_ROUND_LIMIT", "review_round_stopped"]

# The first ``insufficient_packet`` review and its one retry.
INSUFFICIENT_PACKET_ROUND_LIMIT: Final = 2


def review_round_stopped(records: Iterable[LedgerRecord]) -> bool:
    """Whether the next check skips the AI-powered review.

    True when the last ``INSUFFICIENT_PACKET_ROUND_LIMIT`` completed reviews all concluded
    ``insufficient_packet`` and no edit action was recorded after the older of them. Checks that
    did not run a review (local-only, skipped, blocked or failed) neither count nor reset; a
    completed review with any other conclusion resets the count.
    """

    consecutive = 0
    for record in reversed(tuple(records)):
        payload = record.payload
        name = record.schema.name
        if (
            name == "action_recorded"
            and type(payload) is ActionRecordedPayload
            and payload.action_kind is ActionKind.EDIT
        ):
            # An edit after (or between) the insufficient reviews is new work worth a review.
            return False
        if name != "check_recorded" or type(payload) is not CheckRecordedPayload:
            continue
        if payload.semantic_status is not SemanticStatus.SUCCEEDED:
            continue
        if payload.semantic_conclusion != "insufficient_packet":
            return False
        consecutive += 1
        if consecutive >= INSUFFICIENT_PACKET_ROUND_LIMIT:
            return True
    return False
