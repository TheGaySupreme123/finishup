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

# Status history is session-scoped, so the continuation names the session that recorded the check.
ADVISORY_HISTORY_CONTINUATION = (
    "Retrieve status view=history filter.schema_name=check_recorded in the session that recorded "
    "the check (follow next_cursor)."
)


@dataclass(frozen=True, slots=True)
class CorrectnessAdvisory:
    advisory_id: str
    check: LedgerRecord
    concern: JsonObject
    response: LedgerRecord | None = None

    @property
    def readable_response(self) -> bool:
        return self.response is not None and self.response.payload is not None

    @property
    def disposition(self) -> str:
        if self.response is None:
            return "no recorded response"
        payload = self.response.payload
        if payload is None:
            return "response_unavailable"
        assert isinstance(payload, DecisionRecordedPayload)
        assert payload.advisory_response is not None
        return str(payload.advisory_response["disposition"])


@dataclass(frozen=True, slots=True)
class CorrectnessAdvisoryIndex:
    rows: tuple[CorrectnessAdvisory, ...]
    # Withheld responses on checks with several notes. Their target note is withheld with their
    # payload, so none is attached to a note; each is counted (at most one per note of that check
    # without a recorded response) and disclosed beside the notes, which keep their own status.
    unmatched_withheld: int = 0


def _withheld_response_check(record: LedgerRecord) -> str | None:
    """The check a withheld decision could answer a note of, or ``None``.

    Only ``decision_recorded`` 1.1.0 can carry an advisory response, and every advisory response
    names exactly its check as causal parent; that envelope survives when the payload does not.
    """

    if getattr(record, "payload", None) is not None:
        return None
    schema = record.schema
    if schema.name != "decision_recorded" or schema.version != DECISION_REVIEW_MODE_SCHEMA_VERSION:
        return None
    parents = record.causal_parents
    return str(parents[0]) if len(parents) == 1 else None


def correctness_advisory_index(records: tuple[LedgerRecord, ...]) -> CorrectnessAdvisoryIndex:
    """Index every note with the response attached to it, and nothing else.

    A readable response attaches to the note it names; a later readable response replaces the
    displayed one. A withheld (payload-less) decision never replaces a readable account. It is
    attached only where its target is certain: its check carries exactly one note. On a check
    with several notes it is counted as unmatched instead of rewriting the check's other notes.
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
            keys_of_check = notes_by_check[check]
            if len(keys_of_check) == 1:
                row = rows[keys_of_check[0]]
                if not row.readable_response:
                    rows[keys_of_check[0]] = replace(row, response=record)
            else:
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
            "response_unavailable": str(
                sum(row.disposition == "response_unavailable" for row in rows)
                + index.unmatched_withheld
            ),
        }
    )


def advisory_closing_text(
    rows: tuple[CorrectnessAdvisory, ...], *, unmatched_withheld: int = 0
) -> str:
    text = advisory_summary(rows, unmatched_withheld=unmatched_withheld)
    for row in rows[-3:]:
        status = row.disposition
        if status == "addressed":
            status = "addressed (agent-reported, linked evidence)"
        elif status == "declined":
            status = "declined with reason (retrieve history)"
        elif status == "response_unavailable":
            status = "response unavailable (withheld)"
        text += f" {row.advisory_id}: {status}."
    if len(rows) > 3:
        text += f" {len(rows) - 3} earlier rows omitted; retrieve history."
    return text


def advisory_summary(rows: tuple[CorrectnessAdvisory, ...], *, unmatched_withheld: int = 0) -> str:
    unavailable = sum(row.disposition == "response_unavailable" for row in rows)
    text = (
        f"Earlier correctness advisories: {len(rows)}; no recorded response: "
        f"{sum(row.response is None for row in rows)}. Non-blocking. "
    )
    if unavailable + unmatched_withheld:
        text += f"Response details unavailable: {unavailable + unmatched_withheld}. "
    if unmatched_withheld:
        text += (
            f"Withheld responses not matched to a note: {unmatched_withheld}; each may answer one "
            "note of its several-note check listed with no recorded response. "
        )
    return text + ADVISORY_HISTORY_CONTINUATION


def advisory_item(row: CorrectnessAdvisory, profile: ReceiptRedactionProfile) -> str:
    status = row.disposition
    if status == "addressed":
        status = "addressed (agent-reported, linked evidence)"
    elif status == "declined":
        status = "declined with reason"
    elif status == "response_unavailable":
        status = "response unavailable (withheld)"
    payload = row.check.payload
    assert isinstance(payload, CheckRecordedPayload)
    prefix = (
        f"Correctness advisory {row.advisory_id}: {status}. "
        f"Check {row.check.event_id}; subject frontier {payload.subject_frontier.sequence}; "
        f"subjects: {', '.join(str(ref) for ref in cast(tuple[str, ...], row.concern['subject_refs']))}."
    )
    if row.response is not None and isinstance(row.response.payload, DecisionRecordedPayload):
        answer = row.response.payload
        assert answer.advisory_response is not None
        refs = cast(tuple[str, ...], answer.advisory_response["evidence_refs"])
        prefix += (
            f" Linked evidence: {', '.join(refs) or 'none'}; response {row.response.event_id}."
        )
    elif row.response is not None:
        prefix += f" Response {row.response.event_id} (details withheld)."
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
