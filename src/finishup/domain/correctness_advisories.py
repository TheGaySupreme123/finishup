"""Bounded reviewer notes and optional, self-reported dispositions (#1162)."""

import re
from typing import cast

from finishup.domain.values import JsonObject
from finishup.protocol.errors import ProtocolValueError

ADVISORY_ID_PATTERN = (
    r"^evt_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}:(?:[1-9]|10)$"
)
MAX_ADVISORIES_PER_CHECK = 10
# A note keeps the fence-resolved subjects of its challenge, which a finding bounds the same way.
MAX_ADVISORY_SUBJECT_REFS = 64
ADVISORY_RESPONSE_STATEMENT = "Correctness advisory disposition (agent-reported; non-blocking)."


def is_advisory_id(value: str) -> bool:
    return re.fullmatch(ADVISORY_ID_PATTERN, value) is not None


def validate_advisories(rows: tuple[JsonObject, ...]) -> None:
    if type(rows) is not tuple or len(rows) > MAX_ADVISORIES_PER_CHECK:
        raise ProtocolValueError("invalid_event_value_type")
    for row in rows:
        if type(row) is not JsonObject or set(row) != {"summary", "detail", "subject_refs"}:
            raise ProtocolValueError("invalid_event_value_type")
        for key in ("summary", "detail"):
            value = row[key]
            if type(value) is not str or not 1 <= len(value.encode("utf-8")) <= 8192:
                raise ProtocolValueError("invalid_event_value_type")
        refs = row["subject_refs"]
        if (
            type(refs) is not tuple
            or len(refs) > MAX_ADVISORY_SUBJECT_REFS
            or any(
                type(ref) is not str
                or re.fullmatch(
                    r"(?:evt|obl|clm)_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
                    ref,
                )
                is None
                for ref in refs
            )
            or refs != tuple(sorted(set(cast(tuple[str, ...], refs))))
        ):
            raise ProtocolValueError("invalid_event_value_type")


def validate_advisory_response(row: JsonObject) -> None:
    if type(row) is not JsonObject or set(row) != {"advisory_id", "disposition", "evidence_refs"}:
        raise ProtocolValueError("invalid_event_value_type")
    target, disposition, refs = row["advisory_id"], row["disposition"], row["evidence_refs"]
    if (
        type(target) is not str
        or not is_advisory_id(target)
        or type(disposition) is not str
        or disposition not in {"addressed", "declined"}
        or type(refs) is not tuple
        or len(refs) > 64
        or any(
            type(ref) is not str
            or re.fullmatch(
                r"(?:evd|res)_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
                ref,
            )
            is None
            for ref in refs
        )
        or refs != tuple(sorted(set(cast(tuple[str, ...], refs))))
        or (disposition == "addressed" and not refs)
    ):
        raise ProtocolValueError("invalid_event_value_type")


def validate_advisory_counts(counts: JsonObject) -> None:
    if type(counts) is not JsonObject or set(counts) != {
        "total",
        "no_recorded_response",
        "withheld_may_answer",
    }:
        raise ProtocolValueError("invalid_event_value_type")
    for value in counts.values():
        if (
            type(value) is not str
            or re.fullmatch(r"(?:0|[1-9][0-9]{0,18})", value) is None
            or int(value) > 2**63 - 1
        ):
            raise ProtocolValueError("invalid_event_value_type")
    # A withheld decision is never attached to a note (it may not be a response at all), so the
    # notes it may answer keep counting as no recorded response and the two counts may overlap.
    total = int(str(counts["total"]))
    if (
        int(str(counts["no_recorded_response"])) > total
        or int(str(counts["withheld_may_answer"])) > total
    ):
        raise ProtocolValueError("invalid_event_value_type")
