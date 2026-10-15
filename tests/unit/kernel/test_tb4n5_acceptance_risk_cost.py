"""The acceptance-risk classification stays inside the Stop gate's status deadline (tb4n5 check D3).

``acceptance_risk`` runs on every status read: the Stop gate reads compact status with a 4,000 ms
deadline (``cli/closure_gate.py``), and a timed-out read lets the agent stop. The first version
resolved every cited evidence id against the whole result inventory, per obligation: 200 resolved
obligations citing eight evidence items each against 20,003 results took about 4.5 s for this
function alone. The inventories are now indexed once per read and an identical read is answered
from memory; these hold the shape at that size well under the deadline and count the indexing.
"""

from __future__ import annotations

import time
from dataclasses import replace
from typing import Final

import pytest

from builders.policy_cases import (
    HEAD_DIGEST,
    act,
    evd,
    evidence_record,
    obl,
    obligation_record,
    record,
    res,
)
from finishup.domain.events import (
    ActionKind,
    ActionRecordedPayload,
    EvidenceImmutability,
    EvidenceKind,
    EvidenceRecordedPayload,
    ObligationPublishedPayload,
    ObligationStatus,
    RequestedItem,
    RequestedItemKind,
    RequestedItemRole,
    ResultOutcome,
    ResultRecordedPayload,
)
from finishup.domain.values import timestamp_from_string
from finishup.kernel import acceptance_risk as risk_module
from finishup.kernel import evidence_alignment
from finishup.kernel.acceptance_risk import acceptance_risk
from finishup.kernel.projections import ProjectionState, empty_projection_state

_OBLIGATIONS: Final = 200
_REFS_PER_OBLIGATION: Final = 8
_UNRELATED_RESULTS: Final = 20_003
# Far below the 4,000 ms Stop status deadline, which also pays for the rest of the status read.
_BUDGET_SECONDS: Final = 1.0
_OBSERVED_AT: Final = timestamp_from_string("2026-10-13T12:00:00.000Z")


def _projection(*, shared: bool = False, linked_actions: int = 0) -> ProjectionState:
    """``shared``: every obligation cites the same eight evidence items; ``linked_actions``
    distinct actions each have a result citing the first of them (check D3-R2)."""

    number = 0

    def next_number() -> int:
        nonlocal number
        number += 1
        return number

    obligations = {}
    evidence = {}
    for index in range(_OBLIGATIONS):
        base = 10_000 if shared else 10_000 + index * _REFS_PER_OBLIGATION
        refs = tuple(evd(base + slot) for slot in range(_REFS_PER_OBLIGATION))
        for ref in refs:
            if ref in evidence:
                continue
            evidence[ref] = evidence_record(
                EvidenceRecordedPayload(
                    evidence_id=ref,
                    evidence_kind=EvidenceKind.OTHER,
                    strength=EvidenceImmutability.METADATA_ONLY,
                    observed_at=_OBSERVED_AT,
                    description="A run summary",
                ),
                next_number(),
            )
        obligations[obl(index + 1)] = obligation_record(
            ObligationPublishedPayload(
                obligation_id=obl(index + 1),
                description="Deliver one output",
                evidence_expectation="A run",
                status=ObligationStatus.RESOLVED,
                requested_items=(
                    RequestedItem(
                        RequestedItemKind.FILE, f"out/{index}.txt", RequestedItemRole.OUTPUT
                    ),
                ),
                resolution_evidence_refs=tuple(sorted(refs, key=str.encode)),
            ),
            next_number(),
        )
    actions = {
        act(1): record(
            ActionRecordedPayload(act(1), ActionKind.COMMAND, "A run", command="make check"),
            next_number(),
        )
    }
    results = {
        res(index + 1): record(
            ResultRecordedPayload(res(index + 1), act(1), ResultOutcome.SUCCESS),
            next_number(),
        )
        for index in range(_UNRELATED_RESULTS)
    }
    for index in range(linked_actions):
        action = act(100_000 + index)
        actions[action] = record(
            ActionRecordedPayload(action, ActionKind.REVIEW, "Reviewed the shared report"),
            next_number(),
        )
        result = res(100_000 + index)
        results[result] = record(
            ResultRecordedPayload(
                result, action, ResultOutcome.SUCCESS, evidence_refs=(evd(10_000),)
            ),
            next_number(),
        )
    return replace(
        empty_projection_state(),
        frontier=number,
        head_digest=HEAD_DIGEST,
        obligations=obligations,
        evidence=evidence,
        actions=actions,
        results=results,
    )


def test_a_long_task_is_classified_well_inside_the_stop_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _projection()
    resolved = tuple(state.obligations)
    calls = 0
    original = evidence_alignment.results_by_evidence

    def counting(projection: ProjectionState) -> object:
        nonlocal calls
        calls += 1
        return original(projection)

    monkeypatch.setattr(risk_module, "results_by_evidence", counting)
    started = time.perf_counter()
    flagged = acceptance_risk(state, (), resolved)
    elapsed = time.perf_counter() - started
    # Every obligation's evidence is its own assertion and never names its output.
    assert len(flagged) == _OBLIGATIONS
    # The result inventory is indexed once for the whole read, not once per reference.
    assert calls == 1
    assert elapsed < _BUDGET_SECONDS, elapsed
    # The same read again is answered from memory.
    again_started = time.perf_counter()
    assert acceptance_risk(state, (), resolved) is flagged
    assert calls == 1
    assert time.perf_counter() - again_started < 0.05


def test_shared_evidence_behind_many_actions_is_resolved_once_per_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Check D3-R2: 200 obligations cite the same eight items; 1,000 actions stand behind one."""

    state = _projection(shared=True, linked_actions=1_000)
    resolved = tuple(state.obligations)
    resolutions = 0
    original = evidence_alignment.source_actions

    def counting(
        projection: ProjectionState,
        records_by_event: object,
        ref: str,
        evidence_actions: object = None,
        source_cache: dict[str, object] | None = None,
    ) -> object:
        nonlocal resolutions
        if source_cache is None or ref not in source_cache:
            resolutions += 1
        return original(projection, records_by_event, ref, evidence_actions, source_cache)  # type: ignore[arg-type]

    monkeypatch.setattr(evidence_alignment, "source_actions", counting)
    started = time.perf_counter()
    flagged = acceptance_risk(state, (), resolved)
    elapsed = time.perf_counter() - started
    assert len(flagged) == _OBLIGATIONS
    # Each shared reference is resolved once for the whole read, not once per obligation.
    assert resolutions == _REFS_PER_OBLIGATION
    assert elapsed < _BUDGET_SECONDS, elapsed
