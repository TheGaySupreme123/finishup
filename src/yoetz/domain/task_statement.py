"""The task statement: what the user asked for, kept apart from the agent's plan (issue #908).

The AI-powered reviewer judges a change against the task. Until this module existed the only
"goal" it received was the agent's own latest plan summary, so it could neither see a requirement
the plan dropped nor avoid asking for behaviour the user had excluded. A task statement is a
separate, source-labelled fact:

* ``agent_transcribed`` — the agent passed the user's request on ``start`` (or revised it with a
  plan event). It is the agent's account of the request, never a host observation.
* ``host_captured_user_prompt`` — the host captured the user's prompt. Reserved: no recorded path
  produces it yet, and captured prompt text never enters a review packet in this version.
* ``task_title_only`` — neither exists, so only the task title stands in.

Everything here is pure and replay-derived: the current statement is the newest one recorded in
the accepted prefix, and every earlier one stays in the ledger history.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass, replace
from enum import Enum
from typing import Final, Literal

from yoetz.domain.events import (
    AcceptedEvent,
    LedgerRecord,
    PlanPublishedPayload,
    PlanRevisedPayload,
    RedactionState,
    SessionOpenedPayload,
    SessionResumedPayload,
)
from yoetz.domain.privacy import PrivacyPolicy, ReviewSelectionPolicy
from yoetz.domain.values import EventId, event_id, validate_sha256_digest
from yoetz.protocol.errors import ProtocolValueError
from yoetz.protocol.models import MAX_TASK_STATEMENT_BYTES, DataCategory

__all__ = [
    "TASK_STATEMENT_GAPS",
    "TASK_STATEMENT_NOT_AUTHORIZED_GAP",
    "TASK_STATEMENT_NOT_SUPPLIED_GAP",
    "TASK_STATEMENT_UNAVAILABLE_GAP",
    "TASK_STATEMENT_SECTION",
    "NO_MATERIAL_WORK_MARKER",
    "RecordedTaskStatement",
    "SpecificationPreflight",
    "TASK_STATEMENT_FINDING_SUMMARIES",
    "TASK_STATEMENT_SCOPE_EMPTY_SUMMARY",
    "TASK_STATEMENT_UNMAPPED_SUMMARY",
    "TaskStatementSource",
    "current_task_statement",
    "may_carry_task_statement",
    "recorded_task_title",
    "review_selection_for_delivery",
    "task_statement_disclosure_text",
    "task_statement_gap_detail",
    "specification_preflight",
]

# The privacy review section and the packet section share one name, so the consent vocabulary and
# the packet the owner consented to cannot drift apart.
TASK_STATEMENT_SECTION: Final = "task_statement"

# The reviewer received no task statement at all. Always paired with exactly one reason below.
# A task title standing in is not this gap: its ``task_title_only`` source label discloses it.
TASK_STATEMENT_UNAVAILABLE_GAP: Final = "task_statement_unavailable"
# Neither an agent-supplied statement nor a readable task title is recorded for the task.
TASK_STATEMENT_NOT_SUPPLIED_GAP: Final = "task_statement_not_supplied"
# The approved privacy policy does not let the statement out: its review selection does not list
# the ``task_statement`` section (an approval that predates the section never covers it), or its
# AI-powered review channel does not allow ``task_description``. Nothing is sent even when a
# statement is recorded.
TASK_STATEMENT_NOT_AUTHORIZED_GAP: Final = "task_statement_not_authorized"
TASK_STATEMENT_GAPS: Final = frozenset(
    {
        TASK_STATEMENT_UNAVAILABLE_GAP,
        TASK_STATEMENT_NOT_SUPPLIED_GAP,
        TASK_STATEMENT_NOT_AUTHORIZED_GAP,
    }
)
_GAP_DETAILS: Final = {
    TASK_STATEMENT_UNAVAILABLE_GAP: (
        "The AI-powered reviewer did not receive the task statement, so it could not compare "
        "the work with what the user asked for."
    ),
    TASK_STATEMENT_NOT_SUPPLIED_GAP: (
        "No task statement or readable task title is recorded for this task; pass the user's "
        "request verbatim in start.task_statement."
    ),
    TASK_STATEMENT_NOT_AUTHORIZED_GAP: (
        "The approved privacy policy does not list the task_statement review section, or its "
        "AI-powered review channel does not allow task_description, so the recorded statement "
        "stayed local. Run 'yoetz --privacy' to review and approve it."
    ),
}


# Fixed summaries of the two local findings whose basis is the task statement itself (TB4 pilot).
# Finding resolution reads the summary to tell these statement-based ``task_requirement_unmet``
# findings from the test-edit one, whose basis is structural test-edit accounting; any other
# summary is treated as the stricter test-edit basis, so a wording change can only fail closed.
TASK_STATEMENT_UNMAPPED_SUMMARY: Final = (
    "No obligation in the current plan cites the recorded task statement."
)
TASK_STATEMENT_SCOPE_EMPTY_SUMMARY: Final = (
    "A completion claim was recorded while the plan declares no obligation for the recorded"
    " task statement."
)
TASK_STATEMENT_FINDING_SUMMARIES: Final = frozenset(
    {TASK_STATEMENT_UNMAPPED_SUMMARY, TASK_STATEMENT_SCOPE_EMPTY_SUMMARY}
)
# A ``decision_recorded`` statement line ``yoetz-no-material-work:<statement event id>`` is the
# agent's recorded, justified decision that the user's request asks for no material work. It is
# read only as that exact line; it counts only while the task records no edit action.
NO_MATERIAL_WORK_MARKER: Final = "yoetz-no-material-work"


class TaskStatementSource(str, Enum):  # noqa: UP042 - exact wire enum base
    AGENT_TRANSCRIBED = "agent_transcribed"
    HOST_CAPTURED_USER_PROMPT = "host_captured_user_prompt"
    TASK_TITLE_ONLY = "task_title_only"


def task_statement_disclosure_text(
    *, section_selected: bool, channel_sends_task_description: bool, predates_section: bool
) -> str:
    """One plain sentence for ``privacy show``, ``yoetz --privacy`` and the policy draft.

    Fixed local wording only. It always says whether the agent's transcription of the user's
    request leaves the machine and that the host-captured prompt is not used.
    """

    captured = "The host-captured user prompt is never used."
    if section_selected and channel_sends_task_description:
        return (
            "sent. The agent's transcription of the user's request (or, when none was "
            "supplied, the task title) goes to the AI-powered reviewer as the task statement. "
            + captured
        )
    if section_selected:
        return (
            "not sent. The task_statement section is selected, but the review channel does not "
            "allow task_description, so the agent's transcription of the user's request stays "
            "local. " + captured
        )
    if predates_section:
        return (
            "not sent. This policy was approved before the task_statement section existed, so "
            "the agent's transcription of the user's request stays local. Approving the "
            "current recipe adds it. " + captured
        )
    return "not sent. The agent's transcription of the user's request stays local. " + captured


def task_statement_gap_detail(code: str) -> str | None:
    """Fixed receipt prose for one task-statement gap code, or ``None`` for any other code."""

    return _GAP_DETAILS.get(code)


@dataclass(frozen=True, slots=True)
class RecordedTaskStatement:
    """The newest agent-supplied statement at one frozen frontier.

    ``equivalent_event_ids`` names every readable statement-carrying event in the prefix whose
    statement content is byte-identical to this one (its own event included). A re-attach or a
    plan event that repeats an unchanged statement does not amend it, so an obligation citing any
    of these events still maps the current request; a genuinely amended statement has a different
    digest and none of the earlier events.
    """

    text: str
    source_event_id: EventId
    source_family: str
    ingestion_sequence: int
    equivalent_event_ids: tuple[EventId, ...] = ()

    def __post_init__(self) -> None:
        if type(self.text) is not str or not self.text:
            raise ValueError("task_statement_invalid")
        object.__setattr__(self, "source_event_id", event_id(self.source_event_id))
        if type(self.equivalent_event_ids) is not tuple:
            raise ValueError("task_statement_invalid")
        equivalent = tuple(
            sorted(
                {event_id(value) for value in self.equivalent_event_ids} | {self.source_event_id},
                key=str.encode,
            )
        )
        object.__setattr__(self, "equivalent_event_ids", equivalent)
        if self.source_family not in {
            "session_opened",
            "session_resumed",
            "plan_published",
            "plan_revised",
        }:
            raise ValueError("task_statement_invalid")
        if type(self.ingestion_sequence) is not int or self.ingestion_sequence < 1:
            raise ValueError("task_statement_invalid")

    @property
    def content_digest(self) -> str:
        return "sha256:" + hashlib.sha256(self.text.encode("utf-8")).hexdigest()

    @property
    def source(self) -> TaskStatementSource:
        # Every recorded statement arrives through the agent (``start`` or a plan event). Only a
        # future host-capture path may record anything else, and it will say so explicitly.
        return TaskStatementSource.AGENT_TRANSCRIBED


@dataclass(frozen=True, slots=True)
class SpecificationPreflight:
    """The service-owned completeness decision before a semantic provider call.

    ``title_only`` is intentionally a distinct state. A task title can identify a task, but it
    cannot stand in for a complete user specification when the caller requested full-spec review.
    The digest and byte length are structural commitments; the statement text never appears in
    this value (issue #951).
    """

    status: Literal["complete", "title_only", "missing", "withheld"]
    source: TaskStatementSource | None
    content_digest: str | None
    content_bytes: int
    revision: int | None
    required: bool
    actionable: bool
    gap: str | None = None

    def __post_init__(self) -> None:
        if self.status not in {"complete", "title_only", "missing", "withheld"}:
            raise ValueError("specification_preflight_invalid")
        if self.status == "complete" and self.source is not TaskStatementSource.AGENT_TRANSCRIBED:
            raise ValueError("specification_preflight_invalid")
        if self.status == "title_only" and self.source is not TaskStatementSource.TASK_TITLE_ONLY:
            raise ValueError("specification_preflight_invalid")
        if self.status in {"missing", "withheld"} and self.source is not None:
            raise ValueError("specification_preflight_invalid")
        if self.content_digest is not None:
            try:
                validate_sha256_digest(self.content_digest)
            except (ProtocolValueError, TypeError) as exc:
                raise ValueError("specification_preflight_invalid") from exc
        if (
            type(self.content_bytes) is not int
            or not 0 <= self.content_bytes <= MAX_TASK_STATEMENT_BYTES
        ):
            raise ValueError("specification_preflight_invalid")
        if self.revision is not None and (type(self.revision) is not int or self.revision < 0):
            raise ValueError("specification_preflight_invalid")
        if type(self.required) is not bool or type(self.actionable) is not bool:
            raise ValueError("specification_preflight_invalid")
        if self.status == "complete" and self.actionable:
            raise ValueError("specification_preflight_invalid")
        if self.status == "withheld" and self.actionable:
            raise ValueError("specification_preflight_invalid")

    @property
    def complete(self) -> bool:
        return self.status == "complete"


def specification_preflight(
    statement: RecordedTaskStatement | None,
    title: str | None,
    selection: ReviewSelectionPolicy,
    *,
    required: bool,
    channel_sends_task_description: bool = True,
) -> SpecificationPreflight:
    """Return the bounded specification state before substantive semantic dispatch.

    A policy that withholds ``task_description`` is never converted into an agent request to
    transmit it. When the channel is authorized, a title-only or missing specification is
    actionable only for a full-spec review; reduced review continues with the explicit status.
    """

    selected = TASK_STATEMENT_SECTION in selection.sections
    if not selected or not channel_sends_task_description:
        return SpecificationPreflight(
            "withheld", None, None, 0, None, required, False, TASK_STATEMENT_NOT_AUTHORIZED_GAP
        )
    if statement is not None:
        raw = statement.text.encode("utf-8")
        return SpecificationPreflight(
            "complete",
            statement.source,
            "sha256:" + hashlib.sha256(raw).hexdigest(),
            len(raw),
            statement.ingestion_sequence,
            required,
            False,
            None,
        )
    if title is not None:
        raw = title.encode("utf-8")
        return SpecificationPreflight(
            "title_only",
            TaskStatementSource.TASK_TITLE_ONLY,
            "sha256:" + hashlib.sha256(raw).hexdigest(),
            len(raw),
            0,
            required,
            required,
            TASK_STATEMENT_NOT_SUPPLIED_GAP if required else None,
        )
    return SpecificationPreflight(
        "missing",
        None,
        None,
        0,
        None,
        required,
        required,
        TASK_STATEMENT_NOT_SUPPLIED_GAP if required else None,
    )


def current_task_statement(records: Iterable[LedgerRecord]) -> RecordedTaskStatement | None:
    """Return the newest readable statement in ``records``, oldest-first ledger order.

    A redacted or unreadable event carries nothing: its statement is skipped, never
    reconstructed, and the earlier statements remain what the ledger still holds. A later event
    that repeats the current statement byte for byte does not amend it: the earlier event stays
    the current statement event. The result names every readable event that carried the same
    statement content (``equivalent_event_ids``), so an obligation citing any of them maps it.
    """

    current: RecordedTaskStatement | None = None
    by_text: dict[str, list[EventId]] = {}
    for record in records:
        if type(record) is not AcceptedEvent or record.redaction is not RedactionState.PRESENT:
            continue
        payload = record.payload
        if type(payload) not in {
            SessionOpenedPayload,
            SessionResumedPayload,
            PlanPublishedPayload,
            PlanRevisedPayload,
        }:
            continue
        statement = getattr(payload, "task_statement", None)
        if type(statement) is not str:
            continue
        by_text.setdefault(statement, []).append(record.event_id)
        if current is not None and current.text == statement:
            # Repeating the unchanged statement (a re-attach, or a plan event that restates it)
            # is not an amendment: the event that recorded it stays current, so the finding
            # subject, the review packet's source ref and every obligation citing it stay put.
            continue
        current = RecordedTaskStatement(
            text=statement,
            source_event_id=record.event_id,
            source_family=record.schema.name,
            ingestion_sequence=record.ledger.ingestion_sequence,
        )
    if current is None:
        return None
    return replace(current, equivalent_event_ids=tuple(by_text[current.text]))


# Event versions minted to carry a task statement. Nothing older can, so a review whose frozen
# frontier precedes the first of these that may hold one cannot have received a statement.
_STATEMENT_CAPABLE_SCHEMAS: Final = frozenset(
    {
        ("session_opened", "1.2.0"),
        ("session_resumed", "1.2.0"),
        ("plan_published", "1.1.0"),
        ("plan_revised", "1.1.0"),
    }
)


def may_carry_task_statement(record: LedgerRecord) -> bool:
    """Whether ``record`` may have carried a task statement.

    Its schema version must be one minted to carry a statement. A readable payload then decides:
    a lineage-only ``session_opened`` 1.2.0 without a statement carried none (review 942-G2). A
    payload the ledger cannot read still counts, so redacting an event later never makes a review
    that held the statement look like one that predates it (issue #908).
    """

    if (
        type(record) is not AcceptedEvent
        or (record.schema.name, record.schema.version) not in _STATEMENT_CAPABLE_SCHEMAS
    ):
        return False
    payload = record.payload
    return payload is None or getattr(payload, "task_statement", None) is not None


def review_selection_for_delivery(policy: PrivacyPolicy) -> ReviewSelectionPolicy:
    """The review selection a case is built from, given what the review channel lets out.

    A statement the LLM channel withholds (``task_description`` outside its allowed categories)
    would be built and then filtered at egress, and the review would say only that some context was
    withheld. Dropping the section here makes the packet name the absence itself:
    ``task_statement_unavailable`` with ``task_statement_not_authorized`` (issue #908). Every other
    section is left to the existing withheld-category disclosure.
    """

    selection = policy.review_selection
    if (
        TASK_STATEMENT_SECTION in selection.sections
        and DataCategory.TASK_DESCRIPTION in policy.withheld_review_categories
    ):
        return replace(
            selection,
            sections=tuple(item for item in selection.sections if item != TASK_STATEMENT_SECTION),
        )
    return selection


def recorded_task_title(records: Iterable[LedgerRecord]) -> str | None:
    """Return the task title from the task's readable ``session_opened`` event, if any."""

    for record in records:
        if (
            type(record) is AcceptedEvent
            and record.redaction is RedactionState.PRESENT
            and type(record.payload) is SessionOpenedPayload
        ):
            return record.payload.task_title
    return None
