"""Task-wide advisory index. Silence and later checks never answer a note."""

from dataclasses import dataclass, replace
from typing import cast

from finishup.domain.bounded_text import clip_to_limit
from finishup.domain.events import (
    DECISION_REVIEW_MODE_SCHEMA_VERSION,
    CheckRecordedPayload,
    DecisionRecordedPayload,
    LedgerRecord,
)
from finishup.domain.receipts import ReceiptRedactionProfile
from finishup.domain.values import JsonObject


@dataclass(frozen=True, slots=True)
class CorrectnessAdvisory:
    advisory_id: str
    check: LedgerRecord
    concern: JsonObject
    response: LedgerRecord | None = None

    @property
    def disposition(self) -> str:
        if self.response is None:
            return "no recorded response"
        payload = self.response.payload
        assert isinstance(payload, DecisionRecordedPayload)
        assert payload.advisory_response is not None
        return str(payload.advisory_response["disposition"])


# #1162 tracked advice: fixed words for each closed row origin (a row without one is a note).
_ORIGIN_LABELS = {
    "": "routine correctness note",
    "verified_not_supported": "reviewer row not_supported",
    "verified_not_assessable": "reviewer row not_assessable",
    "strongest_remaining_check": "reviewer's strongest remaining check",
}


def advisory_origin_label(row: CorrectnessAdvisory) -> str:
    """FinishUP's fixed label for where an advisory row came from, never reviewer prose."""

    return _ORIGIN_LABELS.get(str(row.concern.get("origin", "")), _ORIGIN_LABELS[""])


# Status history is session-scoped, so the continuation names the sessions that recorded the checks.
_NAMED_SESSIONS = 3


def advisory_history_continuation(rows: tuple[CorrectnessAdvisory, ...]) -> str:
    """Where the full rows are: history of the session that recorded each noted check."""

    sessions = tuple(dict.fromkeys(str(row.check.session_id) for row in rows))
    named = ", ".join(sessions[:_NAMED_SESSIONS])
    if len(sessions) > _NAMED_SESSIONS:
        named += f" and {len(sessions) - _NAMED_SESSIONS} more (each receipt row names its own)"
    return (
        "Full rows: status view=history filter.schema_name=check_recorded with session_id "
        f"{named or 'of the recording session'} (follow next_cursor)."
    )


@dataclass(frozen=True, slots=True)
class CorrectnessAdvisoryIndex:
    rows: tuple[CorrectnessAdvisory, ...]
    # Withheld decisions that may answer a note. A withheld payload hides both its target and
    # whether it is an advisory response at all (a review-mode switch can have the same envelope),
    # so none is attached to a note: each is counted (at most one per note of its check without a
    # recorded response) and disclosed beside the notes, which keep their own status.
    unmatched_withheld: int = 0


def _withheld_response_check(record: LedgerRecord) -> str | None:
    """The check a withheld decision may answer a note of, or ``None``.

    Only ``decision_recorded`` 1.1.0 can carry an advisory response, and every advisory response
    names exactly its check as causal parent. That envelope survives when the payload does not,
    but it does not prove the record is a response: it only says it may be one.
    """

    if getattr(record, "payload", None) is not None:
        return None
    schema = record.schema
    if schema.name != "decision_recorded" or schema.version != DECISION_REVIEW_MODE_SCHEMA_VERSION:
        return None
    parents = record.causal_parents
    return str(parents[0]) if len(parents) == 1 else None


def correctness_advisory_index(records: tuple[LedgerRecord, ...]) -> CorrectnessAdvisoryIndex:
    """Index every note with the readable response attached to it, and nothing else.

    A readable response attaches to the note it names; a later readable response replaces the
    displayed one. A withheld (payload-less) decision is never attached to a note: it is counted
    as one that may answer a note of its check, and the notes keep their own status.
    """

    rows: dict[str, CorrectnessAdvisory] = {}
    notes_by_check: dict[str, tuple[str, ...]] = {}
    withheld_by_check: dict[str, int] = {}
    for record in records:
        payload = getattr(record, "payload", None)
        if isinstance(payload, CheckRecordedPayload):
            keys: list[str] = []
            for ordinal, concern in enumerate(payload.correctness_advisories, 1):
                key = f"{record.event_id}:{ordinal}"
                rows[key] = CorrectnessAdvisory(key, record, concern)
                keys.append(key)
            if keys:
                notes_by_check[str(record.event_id)] = tuple(keys)
        elif isinstance(payload, DecisionRecordedPayload) and payload.advisory_response is not None:
            key = str(payload.advisory_response["advisory_id"])
            if key in rows:
                rows[key] = replace(rows[key], response=record)
        elif (check := _withheld_response_check(record)) is not None and check in notes_by_check:
            withheld_by_check[check] = withheld_by_check.get(check, 0) + 1
    unmatched = sum(
        min(count, sum(rows[key].response is None for key in notes_by_check[check]))
        for check, count in withheld_by_check.items()
    )
    return CorrectnessAdvisoryIndex(tuple(rows.values()), unmatched)


def correctness_advisories(records: tuple[LedgerRecord, ...]) -> tuple[CorrectnessAdvisory, ...]:
    return correctness_advisory_index(records).rows


def advisory_counts(index: CorrectnessAdvisoryIndex) -> JsonObject:
    rows = index.rows
    return JsonObject(
        {
            "total": str(len(rows)),
            "no_recorded_response": str(sum(row.response is None for row in rows)),
            "withheld_may_answer": str(index.unmatched_withheld),
        }
    )


def unanswered_advisory_count(index: CorrectnessAdvisoryIndex) -> int:
    """How many advisory rows have no readable recorded response (a status-line count)."""

    return sum(row.response is None for row in index.rows)


def advisory_closing_text(rows: tuple[CorrectnessAdvisory, ...]) -> str:
    """Closure-readiness text: only the notes that still have no recorded response.

    Readiness names what is still open, so the text is a function of that set alone (newest
    first, then the recording sessions). The set only grows by a new note, which leads the list,
    and only shrinks by an answer, which lowers the count; so the text changes exactly when the
    set does, and a Stop hook can compare it instead of parsing it (#1162 review).
    """

    unanswered = tuple(row for row in rows if row.response is None)
    newest = tuple(reversed(unanswered))

    def named_row(row: CorrectnessAdvisory) -> str:
        subjects = cast(tuple[str, ...], row.concern["subject_refs"])
        shown = ", ".join(subjects[:2]) + (f" +{len(subjects) - 2}" if len(subjects) > 2 else "")
        return f"{row.advisory_id} ({advisory_origin_label(row)}{'; ' + shown if shown else ''})"

    named = "; ".join(named_row(row) for row in newest[:3])
    if len(newest) > 3:
        named += f" (+{len(newest) - 3} earlier)"
    return (
        f"Earlier correctness advisories with no recorded response: {len(unanswered)}, newest "
        f"{named}. Non-blocking. For each material concern: run a proportionate check, cite "
        "evidence that already settles it, or decline with a reason. Recording a response is "
        "optional (respond finding_id=<id>: addressed with newly recorded evidence, or declined "
        "with a reason); one response closes it unless new material arrives. "
        + advisory_history_continuation(unanswered)
    )


def advisory_summary(rows: tuple[CorrectnessAdvisory, ...], *, unmatched_withheld: int = 0) -> str:
    text = (
        f"Earlier correctness advisories: {len(rows)}; no recorded response: "
        f"{sum(row.response is None for row in rows)}. Non-blocking. "
    )
    if unmatched_withheld:
        text += (
            f"Withheld decisions that may answer a note: {unmatched_withheld}; each may answer one "
            "note of its check listed with no recorded response. "
        )
    return text + advisory_history_continuation(rows)


def advisory_item(row: CorrectnessAdvisory, profile: ReceiptRedactionProfile) -> str:
    status = row.disposition
    if status == "addressed":
        status = "addressed (agent-reported, linked evidence)"
    elif status == "declined":
        status = "declined with reason"
    payload = row.check.payload
    assert isinstance(payload, CheckRecordedPayload)
    prefix = (
        f"Correctness advisory {row.advisory_id} ({advisory_origin_label(row)}): {status}. "
        f"Check {row.check.event_id} in session {row.check.session_id}; "
        f"subject frontier {payload.subject_frontier.sequence}; "
        f"subjects: {', '.join(str(ref) for ref in cast(tuple[str, ...], row.concern['subject_refs']))}."
    )
    if row.response is not None and isinstance(row.response.payload, DecisionRecordedPayload):
        answer = row.response.payload
        assert answer.advisory_response is not None
        refs = cast(tuple[str, ...], answer.advisory_response["evidence_refs"])
        prefix += (
            f" Linked evidence: {', '.join(refs) or 'none'}; response {row.response.event_id}."
        )
    # Like the existing reviewer-summary leaf, export profiles retain identity/counts but withhold
    # model and agent prose. Local client policy performs the second projection after building.
    if profile is not ReceiptRedactionProfile.FULL_LOCAL:
        return prefix + " [advisory concern and response prose withheld by receipt profile]"
    if payload.semantic_provenance is not None:
        provenance = payload.semantic_provenance
        prefix += (
            f" AI-powered source: {provenance.provider}, model {provenance.model}; "
            f"attempt {provenance.semantic_attempt_id}."
        )
    summary = clip_to_limit(
        str(row.concern["summary"]),
        1024,
        marker=" [summary cut; retrieve history]",
        ascii_only=False,
    )
    text = prefix + f"\nAI-powered reviewer concern (advisory): {summary}"
    if row.response is not None and isinstance(row.response.payload, DecisionRecordedPayload):
        answer = row.response.payload
        reason = clip_to_limit(
            answer.rationale, 1024, marker=" [response cut; retrieve history]", ascii_only=False
        )
        text += f"\nAgent response (self-reported): {reason}"
    if row.concern["detail"] != row.concern["summary"]:
        text += f"\nAI-powered reviewer detail (advisory): {row.concern['detail']}"
    return clip_to_limit(
        text, 8192, marker=" [advisory detail cut; retrieve history]", ascii_only=False
    )


def receipt_advisory_items(
    rows: tuple[CorrectnessAdvisory, ...], profile: ReceiptRedactionProfile
) -> tuple[tuple[str, ...], int]:
    """Bound the complete advisory prose, not merely each row; history retains all originals."""
    remaining = 8192
    items: list[str] = []
    for row in rows[:64]:
        if remaining < 512:
            break
        item = advisory_item(row, profile)
        item = clip_to_limit(
            item, remaining, marker=" [advisory detail cut; retrieve history]", ascii_only=False
        )
        items.append(item)
        remaining -= len(item)
    return tuple(items), len(rows) - len(items)
