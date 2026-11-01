"""Policy roots preserve source identity without task-wide lookup allocations."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace

import pytest

from builders.policy_cases import act, clm, evd, evt, fnd, obl, res
from builders.replay import replay_records
from finishup.kernel import deterministic_checks as checks
from finishup.kernel.deterministic_checks import (
    CaseAvailabilityFacts,
    FindingBasisRef,
    build_deterministic_case,
)
from finishup.kernel.reducers import replay


def test_source_lookup_matches_all_logical_families_without_rebuilding_map(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    records = replay_records("all-event-families")
    case = build_deterministic_case(replay(records), records, CaseAvailabilityFacts())
    expected = checks._logical_sources(case.projection)  # pyright: ignore[reportPrivateUsage]
    assert {ref[:4] for ref in expected} == {"obl_", "act_", "res_", "evd_", "clm_", "fnd_"}

    def no_scan(*_args: object) -> None:
        pytest.fail("A single reference lookup must not rebuild the task-wide source map")

    monkeypatch.setattr(checks, "_logical_sources", no_scan)
    for ref, source in expected.items():
        assert checks._source_event_for_ref(case, ref) == source  # pyright: ignore[reportPrivateUsage]
        root = ref if ref.startswith(("obl_", "clm_")) else source
        assert checks.policy_public_root(case, ref) == root
    for source in expected.values():
        assert checks.policy_public_root(case, source) == source


@pytest.mark.parametrize("make_ref", [act, res, evd, obl, clm, fnd, evt])
def test_missing_and_unadmitted_source_lookup(make_ref: Callable[[int], FindingBasisRef]) -> None:
    ref = make_ref(999)
    records = replay_records("all-event-families")
    case = build_deterministic_case(replay(records), records, CaseAvailabilityFacts())
    assert checks._source_event_for_ref(case, ref) is None  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(ValueError, match="policy_wiring_invalid"):
        checks.policy_public_root(case, ref)

    coverage = next(iter(case.coverage_by_ref.values()))
    admitted = replace(
        case,
        allowed_ids=case.allowed_ids | {ref},
        coverage_by_ref={**case.coverage_by_ref, ref: coverage},
    )
    expected = ref if ref.startswith("evt_") else None
    assert checks._source_event_for_ref(admitted, ref) == expected  # pyright: ignore[reportPrivateUsage]


def test_redacted_record_keeps_its_source_identity() -> None:
    records = replay_records("all-event-families")
    case = build_deterministic_case(replay(records), records, CaseAvailabilityFacts())
    ref, record = next(iter(case.projection.actions.items()))
    tombstone = replace(record, payload=None, redacted=True)
    projection = replace(case.projection, actions={**case.projection.actions, ref: tombstone})
    redacted = replace(case, projection=projection)
    assert checks.policy_public_root(redacted, ref) == record.source_event_id
