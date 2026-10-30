"""When the AI-powered review round stops for an insufficient packet (tb4n1 D3, issue #983).

The owner's rule: semantic review helps only with good data, so after the reviewer twice in a
row could not assess the packet (``insufficient_packet``, whether or not it named what it
needed), the request and its one retry, later checks skip the AI-powered review instead of
looping. Publishing more evidence does not re-arm it, because feeding the reviewer excerpts is
the loop this rule ends; a recorded edit to the work does, because a repaired deliverable is new
data worth one more review. Reads recorded check payloads and edit actions only; pure.

tb4n5 follow-up of #1046: a reviewer's per-finding ``unassessable`` ruling is the same inability
for one finding. Since that ruling stays an open round (it is never a disagreement), the same
stop applies to it: after ``UNASSESSABLE_RULING_ROUND_LIMIT`` completed reviews in a row ruled one
AI-powered finding ``unassessable`` with no edit since the older of them, or
``UNASSESSABLE_RULING_TASK_LIMIT`` in a row whatever was edited, later checks skip the review the
same way. The finding is never resolved or turned into a dispute by this: it stays open and
unresolved on the receipt, which also discloses the skipped review.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Final

from finishup.domain.events import (
    ActionKind,
    ActionRecordedPayload,
    CheckRecordedPayload,
    EvidenceDigestProvenance,
    EvidenceRecordedPayload,
    LedgerRecord,
)
from finishup.domain.receipts import SEMANTIC_REVIEW_SKIPPED_PRIVACY_BLOCK_GAP
from finishup.domain.values import FindingId
from finishup.protocol.models import SemanticReason, SemanticStatus
from finishup.protocol.redacted_values import SemanticRedactedValue

__all__ = [
    "INSUFFICIENT_PACKET_ROUND_LIMIT",
    "INSUFFICIENT_PACKET_TASK_LIMIT",
    "UNASSESSABLE_RULING_ROUND_LIMIT",
    "UNASSESSABLE_RULING_TASK_LIMIT",
    "PrivacyBlockStanding",
    "privacy_block_standing",
    "review_round_stopped",
    "unassessable_review_exhausted",
]

# The first ``insufficient_packet`` review and its one retry.
INSUFFICIENT_PACKET_ROUND_LIMIT: Final = 2
# Since the task's last assessed review, edits re-arm the round at most this many insufficient
# reviews: a host whose writes are shell commands never records an edit action, and a trivial
# edit must not buy endless reviews of a packet that cannot show the work.
INSUFFICIENT_PACKET_TASK_LIMIT: Final = 4
# The same two bounds for consecutive per-finding ``unassessable`` rulings (tb4n5 follow-up).
UNASSESSABLE_RULING_ROUND_LIMIT: Final = 2
UNASSESSABLE_RULING_TASK_LIMIT: Final = 4


def review_round_stopped(records: Iterable[LedgerRecord]) -> bool:
    """Whether the next check skips the AI-powered review.

    True when the insufficient-packet stop holds (``_insufficient_round_stopped``) or some
    AI-powered finding's review is exhausted (``unassessable_review_exhausted``).
    """

    ordered = tuple(records)
    return _insufficient_round_stopped(ordered) or bool(unassessable_review_exhausted(ordered))


def _insufficient_round_stopped(records: tuple[LedgerRecord, ...]) -> bool:
    """Whether the reviewer twice in a row could not assess the packet.

    True when the newest completed review concluded ``insufficient_packet`` and either the last
    ``INSUFFICIENT_PACKET_ROUND_LIMIT`` completed reviews all did with no edit action recorded
    after the older of them, or ``INSUFFICIENT_PACKET_TASK_LIMIT`` such reviews were recorded
    since the task's last assessed review. Checks that did not run a review (local-only,
    skipped, blocked or failed) neither count nor reset; a completed review with any other
    conclusion resets both counts.
    """

    consecutive = 0
    total = 0
    edited = False
    newest_insufficient: bool | None = None
    for record in reversed(records):
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


def unassessable_review_exhausted(records: Iterable[LedgerRecord]) -> frozenset[FindingId]:
    """The AI-powered findings the reviewer kept ``unassessable`` round after round (tb4n5).

    A finding counts when the newest completed review ruled it ``unassessable`` and either the
    last ``UNASSESSABLE_RULING_ROUND_LIMIT`` completed reviews that ruled on it all did with no
    edit action recorded after the older of them, or ``UNASSESSABLE_RULING_TASK_LIMIT`` in a row
    did. A completed review that ruled it anything else ends its run; one that did not rule on it
    (not shown, or already final) neither counts nor ends it. Pure: recorded checks and edits only.
    """

    consecutive: dict[FindingId, int] = {}
    total: dict[FindingId, int] = {}
    running: set[FindingId] | None = None
    exhausted: set[FindingId] = set()
    edited = False
    for record in reversed(tuple(records)):
        payload = record.payload
        name = record.schema.name
        if (
            name == "action_recorded"
            and type(payload) is ActionRecordedPayload
            and payload.action_kind is ActionKind.EDIT
        ):
            edited = True
            continue
        if name != "check_recorded" or type(payload) is not CheckRecordedPayload:
            continue
        if payload.semantic_status is not SemanticStatus.SUCCEEDED:
            continue
        rulings = {item.finding_id: item.verdict for item in payload.prior_finding_verdicts}
        if running is None:
            running = {finding for finding, verdict in rulings.items() if verdict == "unassessable"}
        for finding in tuple(running):
            verdict = rulings.get(finding)
            if verdict is None:
                continue
            if verdict != "unassessable":
                running.discard(finding)
                continue
            total[finding] = total.get(finding, 0) + 1
            if not edited:
                consecutive[finding] = consecutive.get(finding, 0) + 1
            if (
                consecutive.get(finding, 0) >= UNASSESSABLE_RULING_ROUND_LIMIT
                or total[finding] >= UNASSESSABLE_RULING_TASK_LIMIT
            ):
                exhausted.add(finding)
                running.discard(finding)
        if not running:
            break
    return frozenset(exhausted)


@dataclass(frozen=True, slots=True)
class PrivacyBlockStanding:
    """The newest AI-powered review's privacy-boundary refusal, unchanged since (#1138).

    ``redacted_values`` are that refusal's recorded ``review_blocked`` items (and any other
    recorded item dispositions), carried onto the check that does not send it again.
    ``final_review`` says whether the refusal was a closing review's own.
    """

    redacted_values: tuple[SemanticRedactedValue, ...]
    final_review: bool


def _agent_published_evidence(payload: object) -> bool:
    """Evidence an agent published (a replacement item), as opposed to a hook capture."""

    if type(payload) is not EvidenceRecordedPayload:
        return False
    binding = payload.digest_binding
    return (
        binding is None or binding.provenance is not EvidenceDigestProvenance.OBSERVATION_CAPTURED
    )


# Agent-published text a review item is composed from (#966): a claim, plan goal, obligation,
# decision or local-finding answer. Publishing one may replace the refused text, so it ends the
# standing and the next check composes and scans the case again; nothing is sent unless it passes.
_AGENT_PUBLISHED_TEXT: Final = frozenset(
    {
        "claim_recorded",
        "decision_recorded",
        "obligation_published",
        "plan_published",
        "plan_revised",
        "response_recorded",
    }
)


def privacy_block_standing(records: Iterable[LedgerRecord]) -> PrivacyBlockStanding | None:
    """Whether the newest AI-powered review was refused at the privacy boundary, unchanged since.

    Issue #1138: a ``blocked_forbidden_data`` / ``never_send_detected`` refusal is deterministic:
    the same content is refused the same way. True when the newest check that asked for a review
    recorded that refusal (or carried it forward under ``semantic_review_skipped_privacy_block``)
    and neither an edit action, agent-published evidence nor agent-published text (a claim, plan,
    obligation, decision or answer, #966) was recorded after it: the content the refusal named
    cannot have changed through the ledger. Hook-captured tool output does not
    count, since capturing more output leaves the refused item in place. A local-only check asked
    for no review and neither counts nor resets; any other review outcome ends the standing.
    Reads recorded payloads only; pure.
    """

    for record in reversed(tuple(records)):
        payload = record.payload
        name = record.schema.name
        if (
            name == "action_recorded"
            and type(payload) is ActionRecordedPayload
            and payload.action_kind is ActionKind.EDIT
        ):
            return None
        if name == "evidence_recorded" and _agent_published_evidence(payload):
            return None
        if name in _AGENT_PUBLISHED_TEXT:
            return None
        if name != "check_recorded" or type(payload) is not CheckRecordedPayload:
            continue
        if payload.semantic_status is SemanticStatus.NOT_REQUESTED:
            continue
        if (
            payload.semantic_status is not SemanticStatus.BLOCKED_FORBIDDEN_DATA
            or payload.semantic_reason is not SemanticReason.NEVER_SEND_DETECTED
        ):
            return None
        if SEMANTIC_REVIEW_SKIPPED_PRIVACY_BLOCK_GAP in payload.coverage.known_gaps:
            # A carried refusal: the refusal it carried is older; keep walking to it.
            continue
        manifest = payload.review_input_manifest
        phase = None if manifest is None else manifest.get("review_phase")
        return PrivacyBlockStanding(payload.semantic_redacted_values, phase == "final")
    return None
