"""A check's observation wait releases this task's held rollout rows first (tb4n5, biped S).

A rollout tool item that no hook post joins is held for pairing (#910) and released only by a
later post, the turn's end, eight idle reconciles or the soft bound; every new session activity
resets its idle count. In tb4n5 biped S one such row (occurred 19:43:07) was accepted 12m55s
later, 3 s after check 530 reported its awaited observations complete, and so made that check
stale. The pre-check wait now releases each held row of its task read long enough ago, with
``unpaired_event`` (its attribution stays unproven, no outcome is decided for it), so the row
lands before the check; a younger row is the wait's bounded remainder.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from typing import cast

import pytest

from builders.codex_replay import Replay as _Replay
from builders.codex_replay import (
    command_execution,
    replay_cell,  # noqa: F401  # pyright: ignore[reportUnusedImport]  (registers the ``replay`` fixture)
    session_start,
    sweep_all,
)
from builders.observed_runs import ObservedLedger
from finishup.adapters.integrations.codex_lifecycle import store_mapping
from finishup.adapters.integrations.observation_task_pending import session_pending_row_identities
from finishup.domain.events import AcceptedEvent, EventPayload
from finishup.domain.observation import ObservationGapCode, ObservationSource
from finishup.domain.values import EventId
from finishup.kernel.later_material import counted_later_material
from finishup.kernel.reducers import replay as replay_ledger

pytestmark = pytest.mark.anyio

_OBSERVED = frozenset({"action_recorded", "result_recorded", "evidence_recorded"})


def _observed(cell: _Replay) -> ObservedLedger:
    ledger = ObservedLedger()
    renamed: dict[EventId, EventId] = {}
    for row in cell.ledger._state.records:
        if type(row) is not AcceptedEvent or row.schema.name not in _OBSERVED:
            continue
        renamed[row.event_id] = ledger.append(
            row.schema,
            cast(EventPayload, row.payload),
            observed=True,
            causal_parents=tuple(renamed[p] for p in row.causal_parents if p in renamed),
        )
    return ledger


async def test_a_held_row_lands_before_the_check_that_awaited_it(replay: _Replay) -> None:
    session_start(replay, cli_version="0.159.3")
    store_mapping(replay.mapping, _state=replay.root)
    command = {"command": "pytest -q"}
    replay.hook("PreToolUse", tool_name="Bash", tool_use_id="call_tests", tool_input=command)
    replay.hook(
        "PostToolUse",
        tool_name="Bash",
        tool_use_id="call_tests",
        tool_input=command,
        tool_response='{"chunk_id":"a1","exit_code":0,"original_token_count":1,"output":"ok","wall_time_seconds":0.1}',
    )
    # A command item no hook post joins (a heredoc run beside polled background sessions).
    replay.append(
        command_execution(
            "exec-biped", "python - <<'PY'\nprint(1)\nPY", 0, "2026-10-12T19:43:07.246Z"
        )
    )
    replay.hook("PreToolUse", tool_name="Bash", tool_use_id="call_poll", tool_input=command)
    (held,) = replay.store.pending_rollout_items(replay.commitment)
    assert replay.store.held_rollout_summary(replay.commitment)["count"] == 1

    # The check's wait, well after the row was read.
    read_at = held.envelope.receipt_time.as_datetime().timestamp()
    snapshot = session_pending_row_identities(
        replay.store,
        yoetz_session_id=replay.mapping.yoetz_session_id,
        _state=replay.root,
        now=read_at + 60,
    )
    assert f"stream-input:{held.source_identity}" in snapshot
    recorder = await sweep_all(replay)
    assert replay.store.pending_rollout_items(replay.commitment) == ()
    released = [
        envelope
        for envelope in recorder.delivered
        if envelope.source is ObservationSource.CODEX_SESSION_STREAM
        and envelope.source_identity == held.source_identity
    ]
    assert len(released) == 1
    assert ObservationGapCode.UNPAIRED_EVENT.value in released[0].gap_codes
    boundary = len(_observed(replay).records)

    # The rest of the turn: the released row never arrives again after the check.
    replay.hook(
        "PostToolUse",
        tool_name="Bash",
        tool_use_id="call_poll",
        tool_input=command,
        tool_response='{"chunk_id":"a2","exit_code":0,"original_token_count":1,"output":"ok","wall_time_seconds":0.1}',
    )
    replay.hook("Stop", last_assistant_message="Done.", stop_hook_active=False)
    recorder = await sweep_all(replay)
    assert not [
        envelope
        for envelope in recorder.delivered
        if envelope.source_identity == held.source_identity
    ]
    records = _observed(replay).prefix
    later = counted_later_material(records[boundary:], replay_ledger(records), all_records=records)
    assert not [
        record
        for record in later
        if "Unpaired observed tool result" in str(getattr(record.payload, "description", ""))
    ]
