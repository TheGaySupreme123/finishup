"""A recorded Codex compaction replays with every post-compaction outcome intact (#1027, N3-7).

``tests/fixtures/codex/rollout-compaction-0.159.3.jsonl`` is a trimmed slice of a real tb4n3
Codex 0.159.3 rollout (sglang S): four commands, a ``compacted`` record with its
``ContextCompaction`` item, then eleven more commands, the last a failing ``pytest`` (exit 1),
with code-mode cells and Yoetz MCP calls in between. Output bodies, diffs, instructions and MCP
arguments are stripped; ids, command argv, exit codes, record types, order and timestamps are the
recorded ones. ``builders.codex_rollout_replay`` rebuilds the hooks Codex fired around each nested
item and drives them, the rollout and the outbox through the real coordinator into a task ledger,
as ``fix_n3/scratch_LC/replay_compaction.py`` does for the full recorded attempts.

On 26e9cecf, with hook posts that state no exit (the recorded shape), this slice quarantines every
post-compaction stream completion as ``ledger_rejected`` and leaves the eleven commands
``unknown``, failing ``pytest`` run included.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest

from builders.codex_replay import Replay
from builders.codex_replay import replay_cell as replay_cell  # noqa: F401  (registers ``replay``)
from builders.codex_rollout_replay import command_items, drive_rollout, summarize, tool_item
from yoetz.domain.events import AcceptedEvent

_ROLLOUT = (
    Path(__file__).resolve().parents[2] / "fixtures" / "codex" / "rollout-compaction-0.159.3.jsonl"
)


def _records() -> list[dict[str, Any]]:
    return [json.loads(line) for line in _ROLLOUT.read_text().splitlines() if line.strip()]


@pytest.mark.anyio
@pytest.mark.parametrize(
    "stated", [False, True], ids=["hook-posts-state-no-exit", "hook-posts-state-exit"]
)
async def test_recorded_compaction_rollout_keeps_every_post_compaction_outcome(
    replay: Replay, stated: bool
) -> None:
    records = _records()
    items = command_items(records)
    assert len(items) == 15  # the slice as recorded: 4 before the compaction, 11 after
    run = await drive_rollout(
        replay, records, stated_ids={str(item["id"]): stated for item in items}
    )
    summary = summarize(replay, records, run)

    assert run.refused == [], run.refused
    assert summary["quarantined"] == 0
    assert summary["compactions"] and summary["compactions"][0]["command_actions_before"] == 4
    assert summary["command_actions"] == 15  # one action per call, hook and stream folded
    assert summary["orphan_command_actions"] == 0
    assert summary["post_compaction_commands"] == 11
    assert summary["post_compaction_unknown_only"] == 0
    assert summary["post_compaction_with_explicit_outcome"] == 11
    # What reached the ledger is what the rollout recorded, once: the failing run is visible.
    assert summary["outcomes_checked"] == 15
    assert summary["outcome_mismatches"] == 0
    assert summary["actions_with_conflicting_outcomes"] == 0
    assert summary["actions_with_more_than_two_results"] == 0
    assert summary["pending_after"] == 0


def _itemless_cells(records: list[dict[str, Any]]) -> int:
    """Code-mode cells the slice records with no nested tool item between call and output."""

    open_cells: dict[str, bool] = {}
    itemless = 0
    for record in records:
        raw = record.get("payload")
        if not isinstance(raw, dict):
            continue
        payload = cast(dict[str, Any], raw)
        kind = payload.get("type")
        if kind == "custom_tool_call":
            open_cells[str(payload["call_id"])] = False
        elif kind == "custom_tool_call_output":
            itemless += not open_cells.pop(str(payload["call_id"]), True)
        elif tool_item(record) is not None:
            open_cells = dict.fromkeys(open_cells, True)
    return itemless


@pytest.mark.anyio
async def test_recorded_cells_pair_on_call_id_and_hooked_cells_stay_local(replay: Replay) -> None:
    """#1038: every 0.159.3 cell output pairs with its call on ``call_id`` (not ``ctc_``/``ctco_``).

    On 98f62af this slice delivered every one of its 28 cell outputs as an
    ``Unpaired observed tool result`` with no tool identity, which the later-material rule counts
    as ``other``. After #1038 only the cells that ran no nested tool at all kept a wrapper record;
    since the tb4n5 owner decision (ADR-029 amendment of 2026-10-13) a cell with no observable tool
    call, in a session whose rollout records tool items, is no workspace activity and keeps none.
    """

    records = _records()
    items = command_items(records)
    await drive_rollout(replay, records, stated_ids={str(item["id"]): True for item in items})
    observed = [
        row
        for row in replay.ledger._state.records  # pyright: ignore[reportPrivateUsage]
        if type(row) is AcceptedEvent
        and row.schema.name in {"action_recorded", "evidence_recorded"}
    ]
    descriptions = [str(getattr(row.payload, "description", "")) for row in observed]
    assert not [text for text in descriptions if text.startswith("Unpaired observed tool result")]
    wrappers = [text for text in descriptions if "(tool exec)" in text]
    assert _itemless_cells(records) == 3
    assert wrappers == []
