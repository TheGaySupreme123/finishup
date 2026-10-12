"""A child's cleared gaps do not bound its parent (issue #1017, Codex review round 2)."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import tests.unit.kernel.test_receipt_builder as receipt_tests

from yoetz.application import lineage_coordinator

_check_record: Any = getattr(receipt_tests, "_check_record")
_cleared: Any = getattr(lineage_coordinator, "_cleared_retained_gaps")


def _records(*gap_sets: tuple[str, ...]) -> list[Any]:
    records: list[Any] = []
    for index, gaps in enumerate(gap_sets, start=1):
        record = _check_record(index, gaps)
        records.append(SimpleNamespace(payload=record.payload, event_id=f"evt_{index}"))
    return records


def test_a_code_the_latest_check_dropped_is_cleared_for_the_parent() -> None:
    records = _records(("planned_verification_not_observed",), ())

    assert _cleared(records, "evt_2", {"planned_verification_not_observed"}) == frozenset(
        {"planned_verification_not_observed"}
    )


def test_a_code_the_latest_check_carries_or_no_check_carried_stays() -> None:
    records = _records((), ("planned_verification_not_observed",))

    assert _cleared(records, "evt_2", {"planned_verification_not_observed", "other"}) == (
        frozenset()
    )
    # Checks after the latest tested one do not count; an unknown latest check clears nothing.
    later = _records(("planned_verification_not_observed",), (), ())
    assert _cleared(later, "evt_1", {"planned_verification_not_observed"}) == frozenset()
    assert _cleared(later, None, {"planned_verification_not_observed"}) == frozenset()
    assert _cleared(later, "evt_9", {"planned_verification_not_observed"}) == frozenset()
