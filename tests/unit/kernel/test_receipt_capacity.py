"""Append-time receipt-capacity admission unions."""

from __future__ import annotations

from dataclasses import replace
from typing import cast

import pytest

from builders.replay import replay_records
from finishup.domain.events import AcceptedEvent, CheckRecordedPayload, LedgerRecord
from finishup.domain.receipts import semantic_coverage_gap_code
from finishup.kernel.deterministic_checks import healthy_storage_availability
from finishup.kernel.receipt_capacity import (
    _receipt_gap_codes_validated,  # pyright: ignore[reportPrivateUsage]
    receipt_gap_codes,
)
from finishup.kernel.reducers import replay, replay_with_index


def _prefix_through_check() -> tuple[tuple[LedgerRecord, ...], CheckRecordedPayload]:
    """Return the accepted prefix ending at the recorded check, so that check stays applicable."""

    records = replay_records("all-event-families")
    index = next(
        position
        for position, record in enumerate(records)
        if type(record) is AcceptedEvent and type(record.payload) is CheckRecordedPayload
    )
    prefix = records[: index + 1]
    payload = cast(CheckRecordedPayload, cast(AcceptedEvent, prefix[-1]).payload)
    return prefix, payload


def test_admission_union_folds_the_semantic_outcome_gap() -> None:
    """Admission counts the AI-powered review gap the receipt builder adds outside recorded coverage.

    ``execute_receipt`` folds ``semantic_coverage_gap_code`` separately from the applicable
    check payload's own ``known_gaps``. While admission skipped it, a state could be accepted
    holding exactly the 64 codes admission could see and then fail receipt construction on a
    65th the builder still needed.
    """

    prefix, payload = _prefix_through_check()
    projection = replay(prefix)
    assert projection.latest_tested_state is not None

    semantic_gap = semantic_coverage_gap_code(payload.semantic_status, payload.semantic_reason)
    assert semantic_gap is not None
    # The interesting shape: a gap the receipt needs that recorded coverage does not carry.
    assert semantic_gap not in payload.coverage.known_gaps
    assert semantic_gap in receipt_gap_codes(projection, prefix)


def test_admission_derives_availability_instead_of_asserting_none() -> None:
    """Admission derives its availability facts rather than asserting there are none.

    ``build_deterministic_case`` requires ``unavailable_event_ids`` to equal the rows the
    projection already records as unreadable, so admission cannot assert empty facts: every
    later append on such a task would raise ``deterministic_case_invalid`` out of the ledger.
    """

    prefix, _payload = _prefix_through_check()
    projection = replay(prefix)
    facts = healthy_storage_availability(projection, prefix)
    # A healthy store resolves every reference it holds, so only the rows the projection itself
    # records as unreadable are declared and no captured object is reported missing.
    assert facts.unavailable_captured_objects == ()
    assert receipt_gap_codes(projection, prefix)


def test_validated_admission_matches_full_capacity_fold_for_mixed_capture_history() -> None:
    records = tuple(replay_records("all-event-families"))
    projection, replay_index = replay_with_index(records)

    assert _receipt_gap_codes_validated(projection, records, replay_index=replay_index) == (
        receipt_gap_codes(projection, records)
    )


def test_validated_admission_rejects_an_index_from_the_wrong_prefix_shape() -> None:
    records = tuple(replay_records("all-event-families"))
    projection, replay_index = replay_with_index(records)
    payloads = dict(replay_index.payload_event_by_object)
    objects = tuple(payloads)
    payloads[objects[0]], payloads[objects[1]] = payloads[objects[1]], payloads[objects[0]]
    mismatched = replace(replay_index, payload_event_by_object=payloads)

    with pytest.raises(ValueError, match="deterministic_case_invalid"):
        _receipt_gap_codes_validated(projection, records, replay_index=mismatched)
