"""Task-wide advisory index. Silence and later checks never answer a note."""

from dataclasses import dataclass
from typing import cast

from finishup.domain.bounded_text import clip_to_limit
from finishup.domain.events import CheckRecordedPayload, DecisionRecordedPayload, LedgerRecord
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
        if payload is None:
            return "response_unavailable"
        assert isinstance(payload, DecisionRecordedPayload)
        assert payload.advisory_response is not None
        return str(payload.advisory_response["disposition"])


def correctness_advisories(records: tuple[LedgerRecord, ...]) -> tuple[CorrectnessAdvisory, ...]:
    rows: dict[str, CorrectnessAdvisory] = {}
    for record in records:
        payload = getattr(record, "payload", None)
        if isinstance(payload, CheckRecordedPayload):
            for ordinal, concern in enumerate(payload.correctness_advisories, 1):
                key = f"{record.event_id}:{ordinal}"
                rows[key] = CorrectnessAdvisory(key, record, concern)
        elif isinstance(payload, DecisionRecordedPayload) and payload.advisory_response is not None:
            key = str(payload.advisory_response["advisory_id"])
            if key in rows:
                row = rows[key]
                rows[key] = CorrectnessAdvisory(key, row.check, row.concern, record)
        elif payload is None and record.schema.name == "decision_recorded":
            # A source-redacted decision may be an answer to a check's note. Its missing payload
            # cannot establish the ordinal or disposition, so never call that silence.
            for key, row in tuple(rows.items()):
                if row.check.event_id in record.causal_parents:
                    rows[key] = CorrectnessAdvisory(key, row.check, row.concern, record)
    return tuple(rows.values())


def advisory_closing_text(rows: tuple[CorrectnessAdvisory, ...]) -> str:
    text = advisory_summary(rows)
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


def advisory_summary(rows: tuple[CorrectnessAdvisory, ...]) -> str:
    return (
        f"Earlier correctness advisories: {len(rows)}; no recorded response: "
        f"{sum(row.response is None for row in rows)}. Non-blocking; "
        + (
            f"Response details unavailable: {sum(row.disposition == 'response_unavailable' for row in rows)}. "
            if any(row.disposition == "response_unavailable" for row in rows)
            else ""
        )
        + "retrieve status view=history filter.schema_name=check_recorded (follow next_cursor)."
    )


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
