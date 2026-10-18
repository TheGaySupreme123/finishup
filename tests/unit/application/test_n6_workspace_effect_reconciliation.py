"""Two deliveries of one call keep every workspace fact (PR #1080 round 6, review finding 1).

A Codex session-stream copy carries no fingerprint and a hook pass may repeat; both mint the same
call-keyed result id, so the later delivery appends no result. These cases run the production
coordinator over an in-memory task ledger and then the production kernel predicates over what it
recorded: a missing fact is enriched, a contradicting fact defeats an earlier ``unchanged`` in
either arrival order, and repeats and a coordinator restart append nothing more.
"""

# pyright: reportPrivateUsage=false
from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from finishup.domain.events import EvidenceRecordedPayload, LedgerRecord, ResultRecordedPayload
from finishup.domain.observation import (
    ObservationEnvelope,
    ObservationIngestDisposition,
    ObservationSource,
)
from finishup.domain.values import JsonObject
from finishup.domain.workspace_effect import (
    workspace_effect_from_annotation,
    workspace_effect_from_result_summary,
)
from finishup.kernel.closing_review_delta import closing_material_frontier, closing_review_delta
from finishup.kernel.later_material import workspace_effects
from finishup.kernel.reducers import replay
from unit.application.test_observation_coordinator import (
    _envelope,
    _reattach_fixture,
    _ReattachCell,
)

_COMMITMENT = "hmac-sha256:" + "a" * 64


def _post(
    cell: _ReattachCell, label: str, effect: str | None, *, stream: bool
) -> ObservationEnvelope:
    base = _envelope(
        session=cell.session,
        kind="PostToolUse",
        identity=f"{'stream' if stream else 'hook'}:{label}:{effect}",
        corr=label,
        tool="shell",
        exit_status=0,
    )
    structural: dict[str, object] = {
        **base.structural_payload,
        "command_commitment": _COMMITMENT,
    }
    if effect is not None:
        structural["workspace_effect"] = effect
    if stream:
        structural["action"] = "function_call_output"
        return replace(
            base,
            source=ObservationSource.CODEX_SESSION_STREAM,
            event_kind="function_call_output",
            structural_payload=JsonObject(structural),
        )
    return replace(base, structural_payload=JsonObject(structural))


def _records(cell: _ReattachCell) -> tuple[LedgerRecord, ...]:
    return tuple(cell.ledger._state.records)  # noqa: SLF001


def _facts(cell: _ReattachCell) -> tuple[list[str | None], list[str]]:
    records = _records(cell)
    summaries = [
        workspace_effect_from_result_summary(row.payload.summary)
        for row in records
        if type(row.payload) is ResultRecordedPayload
    ]
    annotations = [
        effect
        for row in records
        if type(row.payload) is EvidenceRecordedPayload
        and (effect := workspace_effect_from_annotation(row.payload.description)) is not None
    ]
    return summaries, annotations


def _material(cell: _ReattachCell) -> bool:
    records = _records(cell)
    state = replay(records)
    effects = workspace_effects(records, state)
    return any(closing_review_delta(row, state, effects=effects) for row in records)


async def _ingest(cell: _ReattachCell, envelope: ObservationEnvelope) -> None:
    result = await cell.ingest(envelope)
    assert result.disposition in {
        ObservationIngestDisposition.ACCEPTED,
        ObservationIngestDisposition.DUPLICATE,
    }, result.reason


@pytest.mark.anyio
async def test_a_stream_copy_first_is_enriched_by_the_hook_fact(tmp_path: Path) -> None:
    """The review's stream-first ``date -u``: the hook's ``unchanged`` must not be lost."""

    cell = _reattach_fixture(tmp_path, "effect-stream-first")
    await _ingest(cell, _post(cell, "date", None, stream=True))
    # Until the hook's fact arrives the call stays material (no fact reads like a change).
    assert _material(cell)
    await _ingest(cell, _post(cell, "date", "unchanged", stream=False))
    assert _facts(cell) == ([None], ["unchanged"])
    records = _records(cell)
    state = replay(records)
    assert workspace_effects(records, state).quiet
    assert not _material(cell)
    # A repeated hook delivery, and the same delivery after a service restart, add nothing.
    count = cell.record_count()
    await _ingest(cell, _post(cell, "date", "unchanged", stream=False))
    cell.coordinator = cell.build_coordinator()
    await _ingest(cell, _post(cell, "date", "unchanged", stream=False))
    await _ingest(cell, _post(cell, "date", None, stream=True))
    assert cell.record_count() == count
    assert not _material(cell)


@pytest.mark.anyio
async def test_a_hook_fact_first_keeps_it_when_the_stream_copy_follows(tmp_path: Path) -> None:
    cell = _reattach_fixture(tmp_path, "effect-hook-first")
    await _ingest(cell, _post(cell, "date", "unchanged", stream=False))
    await _ingest(cell, _post(cell, "date", None, stream=True))
    # The stream carries no fact: nothing to add, and the hook's fact stands.
    assert _facts(cell) == (["unchanged"], [])
    assert not _material(cell)


@pytest.mark.anyio
@pytest.mark.parametrize("later", ["changed", "unavailable"])
@pytest.mark.parametrize("first_from_stream", [False, True])
async def test_a_contradicting_fact_defeats_an_earlier_unchanged(
    tmp_path: Path, later: str, first_from_stream: bool
) -> None:
    """``changed``/``unavailable`` wins over ``unchanged`` in either order, through restarts."""

    cell = _reattach_fixture(tmp_path, f"effect-{later}-{first_from_stream}")
    if first_from_stream:
        await _ingest(cell, _post(cell, "call", None, stream=True))
    await _ingest(cell, _post(cell, "call", "unchanged", stream=False))
    assert not _material(cell)
    before = cell.record_count()
    await _ingest(cell, _post(cell, "call", later, stream=False))
    assert cell.record_count() > before
    assert _material(cell)
    records = _records(cell)
    state = replay(records)
    effects = workspace_effects(records, state)
    assert not effects.quiet
    assert bool(effects.changed) is (later == "changed")
    # The contradiction is judged where it arrived: a closing review taken before it is stale.
    annotation = next(
        row
        for row in records
        if type(row.payload) is EvidenceRecordedPayload
        and workspace_effect_from_annotation(row.payload.description) == later
    )
    assert closing_review_delta(annotation, state, effects=effects)
    assert closing_material_frontier(state, records) == annotation.ledger.ingestion_sequence
    # An ``unchanged`` repeat after the contradiction cannot quiet the call again.
    count = cell.record_count()
    cell.coordinator = cell.build_coordinator()
    await _ingest(cell, _post(cell, "call", "unchanged", stream=False))
    await _ingest(cell, _post(cell, "call", later, stream=False))
    assert cell.record_count() == count
    assert _material(cell)


@pytest.mark.anyio
@pytest.mark.parametrize("effect", ["changed", "unavailable"])
async def test_a_stream_copy_first_then_a_change_stays_material(
    tmp_path: Path, effect: str
) -> None:
    cell = _reattach_fixture(tmp_path, f"effect-stream-{effect}")
    await _ingest(cell, _post(cell, "gen", None, stream=True))
    await _ingest(cell, _post(cell, "gen", effect, stream=False))
    assert _facts(cell) == ([None], [effect])
    assert _material(cell)


@pytest.mark.anyio
async def test_a_stream_copy_whose_hook_never_arrives_stays_material(tmp_path: Path) -> None:
    cell = _reattach_fixture(tmp_path, "effect-stream-only")
    await _ingest(cell, _post(cell, "date", None, stream=True))
    assert _facts(cell) == ([None], [])
    assert _material(cell)


@pytest.mark.anyio
async def test_same_effect_with_different_classes_keeps_the_code_fact(tmp_path: Path) -> None:
    from finishup.kernel.observed_failures import observed_event_ids_from_records
    from finishup.kernel.task_facts import workspace_verification_edits

    cell = _reattach_fixture(tmp_path, "effect-class-change")
    first = _post(cell, "script", "changed", stream=False)
    first = replace(
        first,
        structural_payload=JsonObject(
            {**first.structural_payload, "workspace_write_scopes": ("docs",)}
        ),
    )
    await _ingest(cell, first)
    records = _records(cell)
    assert not workspace_verification_edits(
        replay(records), observed_event_ids_from_records(records), records
    )
    code = replace(
        first,
        source_identity=first.source_identity + ":code",
        structural_payload=JsonObject(
            {**first.structural_payload, "workspace_write_scopes": ("workspace",)}
        ),
    )
    await _ingest(cell, code)
    records = _records(cell)
    assert _facts(cell) == (["changed"], ["changed"])
    assert workspace_verification_edits(
        replay(records), observed_event_ids_from_records(records), records
    )
    count = cell.record_count()
    cell.coordinator = cell.build_coordinator()
    await _ingest(cell, code)
    assert cell.record_count() == count
