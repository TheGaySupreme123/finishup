"""A Codex hook's stated outcome reaches a call its stream copy recorded first (#1092 item 1).

Both Codex copies of one call mint the same action and result ids. When the stream copy commits
first without an outcome, the hook copy's events are all committed already; before this fix its
stated outcome was refused as a disagreement and lost. These cases run the production coordinator
over an in-memory task ledger: the hook fills the ``unknown`` with one correction, repeats and a
restart add nothing, the other copy stating the same fact adds nothing, and a hook that
contradicts a stated outcome is still refused.
"""

# pyright: reportPrivateUsage=false
from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from finishup.domain.events import ResultOutcome, ResultRecordedPayload
from finishup.domain.observation import (
    ObservationEnvelope,
    ObservationIngestDisposition,
    ObservationSource,
)
from finishup.domain.values import JsonObject
from unit.application.test_observation_coordinator import (
    _envelope,
    _reattach_fixture,
    _ReattachCell,
)

_COMMITMENT = "hmac-sha256:" + "a" * 64
_CALL = "call_n7_outcome"


def _copy(
    cell: _ReattachCell, kind: str, *, stream: bool, exit_status: int | None = None
) -> ObservationEnvelope:
    base = _envelope(
        session=cell.session,
        kind=kind,
        identity=f"{'stream' if stream else 'hook'}:{kind}:{exit_status}",
        corr=_CALL,
        tool="exec_command" if stream else "Bash",
        exit_status=exit_status,
    )
    structural: dict[str, object] = {
        **base.structural_payload,
        "command_commitment": _COMMITMENT,
        "runner_class": "test",
    }
    if not stream:
        return replace(base, structural_payload=JsonObject(structural))
    structural["action"] = "function_call_output"
    return replace(
        base,
        source=ObservationSource.CODEX_SESSION_STREAM,
        event_kind="function_call_output",
        structural_payload=JsonObject(structural),
    )


def _results(cell: _ReattachCell) -> list[tuple[ResultOutcome, int | None]]:
    return [
        (row.payload.outcome, row.payload.exit_status)
        for row in cell.ledger._state.records  # noqa: SLF001
        if type(row.payload) is ResultRecordedPayload
    ]


async def _ingest(cell: _ReattachCell, envelope: ObservationEnvelope) -> None:
    result = await cell.ingest(envelope)
    assert result.disposition in {
        ObservationIngestDisposition.ACCEPTED,
        ObservationIngestDisposition.DUPLICATE,
    }, result.reason


async def _stream_first_unknown(cell: _ReattachCell) -> None:
    await _ingest(cell, _copy(cell, "PostToolUse", stream=True))
    await _ingest(cell, _copy(cell, "PreToolUse", stream=False))
    assert _results(cell) == [(ResultOutcome.UNKNOWN, None)]


@pytest.mark.anyio
async def test_a_hook_outcome_after_a_stream_first_unknown_is_recorded_once(
    tmp_path: Path,
) -> None:
    cell = _reattach_fixture(tmp_path, "n7-hook-corrects")
    await _stream_first_unknown(cell)
    await _ingest(cell, _copy(cell, "PostToolUse", stream=False, exit_status=0))
    assert _results(cell) == [(ResultOutcome.UNKNOWN, None), (ResultOutcome.SUCCESS, 0)]
    # A repeated hook post, the same post after a service restart, and the stream copy stating
    # the same fact later all add nothing.
    count = cell.record_count()
    await _ingest(cell, _copy(cell, "PostToolUse", stream=False, exit_status=0))
    cell.coordinator = cell.build_coordinator()
    await _ingest(cell, _copy(cell, "PostToolUse", stream=False, exit_status=0))
    await _ingest(cell, _copy(cell, "PostToolUse", stream=True, exit_status=0))
    assert cell.record_count() == count


@pytest.mark.anyio
async def test_a_stream_correction_first_is_not_stated_twice_by_the_hook(tmp_path: Path) -> None:
    cell = _reattach_fixture(tmp_path, "n7-stream-corrects")
    # The hook commits first with no outcome; the stream's stated exit corrects it (#910).
    await _ingest(cell, _copy(cell, "PreToolUse", stream=False))
    await _ingest(cell, _copy(cell, "PostToolUse", stream=False))
    await _ingest(cell, _copy(cell, "PostToolUse", stream=True, exit_status=1))
    assert _results(cell) == [(ResultOutcome.UNKNOWN, None), (ResultOutcome.FAILURE, 1)]


@pytest.mark.anyio
async def test_a_hook_outcome_contradicting_a_stated_stream_outcome_is_still_refused(
    tmp_path: Path,
) -> None:
    cell = _reattach_fixture(tmp_path, "n7-hook-contradicts")
    await _ingest(cell, _copy(cell, "PostToolUse", stream=True, exit_status=1))
    count = cell.record_count()
    # Fail closed (#560): the contradiction is not recorded as a duplicate or a correction.
    await cell.ingest(_copy(cell, "PostToolUse", stream=False, exit_status=0))
    assert cell.record_count() == count
    assert _results(cell) == [(ResultOutcome.FAILURE, 1)]


@pytest.mark.anyio
async def test_a_hook_outcome_contradicting_an_earlier_hook_correction_is_refused(
    tmp_path: Path,
) -> None:
    cell = _reattach_fixture(tmp_path, "n7-two-hook-outcomes")
    await _stream_first_unknown(cell)
    await _ingest(cell, _copy(cell, "PostToolUse", stream=False, exit_status=0))
    count = cell.record_count()
    await cell.ingest(_copy(cell, "PostToolUse", stream=False, exit_status=3))
    assert cell.record_count() == count
    assert _results(cell) == [(ResultOutcome.UNKNOWN, None), (ResultOutcome.SUCCESS, 0)]
