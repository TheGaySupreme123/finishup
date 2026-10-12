"""Codex 0.159.3 code-mode cells pair on ``call_id``, so Yoetz's own cells never bound a receipt (#1038).

Codex 0.159.3 names every response-item row itself (``custom_tool_call`` ``id: ctc_...``, its output
``id: ctco_...``) beside the ``call_id`` the two rows share. Pairing on ``id`` never joined a cell's
output to its call: the output was delivered as an unpaired result with no tool identity, the #917
hold never applied, and ``later_material`` read the agent's own ``mcp__yoetz__*`` cells as ``other``.
In tb4n4's deterministic arm that kept ``check_current_as_of_earlier_frontier`` on 35 of 60 final
receipts. These replays drive 0.159.3-shaped rows (both ids, as the recorded slice
``tests/fixtures/codex/rollout-compaction-0.159.3.jsonl`` carries them) through the real hook
ingress, stream reader, coordinator and ledger, and classify what follows the check with the
predicate the receipt uses (``counted_later_material``).
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from typing import Any, cast

import pytest

from builders.codex_replay import Replay as _Replay
from builders.codex_replay import (
    exec_cell,
    exec_cell_output,
    mcp_tool_call,
    replay_cell,  # noqa: F401  # pyright: ignore[reportUnusedImport]  (registers the ``replay`` fixture)
    rollout_row,
    session_start,
    sweep_all,
)
from builders.observed_runs import ObservedLedger
from yoetz.domain.events import AcceptedEvent, ActionRecordedPayload, EventPayload, LedgerRecord
from yoetz.domain.observation import ObservationGapCode, ObservationSource
from yoetz.domain.values import EventId
from yoetz.kernel.later_material import classify_later_material, counted_later_material
from yoetz.kernel.reducers import replay as replay_ledger

pytestmark = pytest.mark.anyio

_VERSION = "0.159.3"
_OBSERVED = frozenset({"action_recorded", "result_recorded", "evidence_recorded"})


def _ids(n: int) -> tuple[str, str, str]:
    """``call_id`` and the two row ids of cell ``n``, in the recorded 0.159.3 spelling."""

    return f"call_cell{n:02d}", f"ctc_cell{n:02d}", f"ctco_cell{n:02d}"


def _yoetz_cell(
    cell: _Replay, n: int, tool: str, timestamp: str, *, read_after_hooks: bool = False
) -> None:
    """One code-mode cell whose only nested call is ``tools.mcp__yoetz__<tool>``.

    By default the reader sees the cell's call before its nested hooks fire (each hook triggers
    its own reconcile), as on an idle host. ``read_after_hooks`` writes the whole cell first, so
    the hooks' reconciles read call, item and output in one pass: the hook-latency shape tb4n4
    showed (``hook_followup_deferred``), where the #917 timing rule cannot attribute the hooks.
    """

    call_id, ctc, ctco = _ids(n)
    name = f"mcp__yoetz__{tool}"
    tool_input: dict[str, Any] = {"request_id": f"req_public_{n}"}
    rows = (
        exec_cell(call_id, f"await tools.{name}({{}});\n", timestamp, item_id=ctc),
        mcp_tool_call(f"exec-yoetz-{n:02d}", tool, timestamp),
        exec_cell_output(call_id, '{"ok":true}', timestamp, item_id=ctco),
    )
    if read_after_hooks:
        cell.append(*rows)
    else:
        cell.append(rows[0])
    cell.hook(
        "PreToolUse", tool_name=name, tool_use_id=f"call_nested{n:02d}", tool_input=tool_input
    )
    if not read_after_hooks:
        cell.append(rows[1])
    cell.hook(
        "PostToolUse",
        tool_name=name,
        tool_use_id=f"call_nested{n:02d}",
        tool_input=tool_input,
        tool_response={"content": [{"text": "ok", "type": "text"}], "isError": False},
    )
    if not read_after_hooks:
        cell.append(rows[2])


def _patch_cell(cell: _Replay, n: int, timestamp: str) -> None:
    """One cell whose nested ``tools.apply_patch`` edits a workspace file."""

    call_id, ctc, ctco = _ids(n)
    patch = {
        "command": "*** Begin Patch\n*** Update File: src/public.ts\n@@\n-a\n+b\n*** End Patch"
    }
    cell.append(exec_cell(call_id, 'tools.apply_patch("...");\n', timestamp, item_id=ctc))
    cell.hook(
        "PreToolUse", tool_name="apply_patch", tool_use_id=f"call_nested{n:02d}", tool_input=patch
    )
    cell.append(
        rollout_row(
            "event_msg",
            {
                "item": {
                    "changes": {"/app/src/public.ts": {"type": "update"}},
                    "id": f"exec-patch-{n:02d}",
                    "status": "completed",
                    "type": "FileChange",
                },
                "type": "item_completed",
            },
            timestamp,
        )
    )
    cell.hook(
        "PostToolUse",
        tool_name="apply_patch",
        tool_use_id=f"call_nested{n:02d}",
        tool_input=patch,
        tool_response=(
            "Exit code: 0\nWall time: 0.1 seconds\nOutput:\nSuccess. Updated the following files:\n"
            "M src/public.ts\n"
        ),
    )
    cell.append(exec_cell_output(call_id, '{"ok":true}', timestamp, item_id=ctco))


def _observed_ledger(cell: _Replay) -> ObservedLedger:
    """The task ledger's observed records, in order, with their lineage kept."""

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


def _after_check(
    cell: _Replay, boundary: int
) -> tuple[tuple[LedgerRecord, ...], tuple[LedgerRecord, ...]]:
    records = _observed_ledger(cell).prefix
    return records, records[boundary:]


async def _checked(cell: _Replay) -> int:
    """Run the session up to and including a code-mode ``check``; return the ledger boundary."""

    session_start(cell, cli_version=_VERSION)
    _yoetz_cell(cell, 1, "check", "2026-10-09T08:43:39.717Z")
    await sweep_all(cell)
    return len(_observed_ledger(cell).records)


@pytest.mark.parametrize(
    "read_after_hooks", [False, True], ids=["read-before-hooks", "read-after-hooks"]
)
async def test_own_cells_after_the_check_do_not_bound_the_receipt(
    replay: _Replay, read_after_hooks: bool
) -> None:
    boundary = await _checked(replay)
    _yoetz_cell(replay, 2, "status", "2026-10-09T08:44:45.674Z", read_after_hooks=read_after_hooks)
    _yoetz_cell(replay, 3, "status", "2026-10-09T08:49:22.029Z", read_after_hooks=read_after_hooks)
    replay.hook("Stop", last_assistant_message="Done.", stop_hook_active=False)
    recorder = await sweep_all(replay)

    stream = [e for e in recorder.delivered if e.source is ObservationSource.CODEX_SESSION_STREAM]
    # Every cell output paired with its call: none is an orphan without a tool identity.
    assert not any(ObservationGapCode.UNPAIRED_EVENT.value in e.gap_codes for e in stream)
    # The cells' record is their nested Yoetz calls: no wrapper reaches the ledger.
    assert not any(e.structural_payload.get("tool_name") == "exec" for e in stream)
    records, later = _after_check(replay, boundary)
    assert later, "the later cells must have reached the ledger"
    assert counted_later_material(later, replay_ledger(records), all_records=records) == ()


async def test_a_post_check_workspace_edit_still_makes_the_check_stale(replay: _Replay) -> None:
    boundary = await _checked(replay)
    _yoetz_cell(replay, 2, "status", "2026-10-09T08:44:45.674Z")
    _patch_cell(replay, 3, "2026-10-09T08:49:53.093Z")
    replay.hook("Stop", last_assistant_message="Done.", stop_hook_active=False)
    await sweep_all(replay)

    records, later = _after_check(replay, boundary)
    projection = replay_ledger(records)
    superseding = [
        record for record in later if classify_later_material(record, projection).supersedes
    ]
    # The edit's action supersedes the check (its result is classified by that action).
    assert superseding and superseding[0].schema.name == "action_recorded"
    edit = cast(ActionRecordedPayload, superseding[0].payload)
    assert "apply_patch" in edit.description


async def test_a_cell_that_also_ran_a_command_keeps_its_own_record(replay: _Replay) -> None:
    """Only a cell whose every nested call is Yoetz's own is Yoetz's own; a mixed cell is not."""

    boundary = await _checked(replay)
    call_id, ctc, ctco = _ids(2)
    command = {"command": 'python -c \'open("x","w")\''}
    replay.append(
        exec_cell(
            call_id,
            "await tools.mcp__yoetz__status({});\n",
            "2026-10-09T08:45:00.000Z",
            item_id=ctc,
        ),
        mcp_tool_call("exec-yoetz-02", "status", "2026-10-09T08:45:00.100Z"),
        rollout_row(
            "event_msg",
            {
                "item": {
                    "command": ["/bin/bash", "-lc", command["command"]],
                    "exit_code": 0,
                    "id": "exec-cmd-02",
                    "status": "completed",
                    "type": "CommandExecution",
                },
                "type": "item_completed",
            },
            "2026-10-09T08:45:00.200Z",
        ),
        exec_cell_output(call_id, "{}", "2026-10-09T08:45:00.300Z", item_id=ctco),
    )
    # The nested hooks land only after the whole cell was written (the hook-latency shape).
    replay.hook("PreToolUse", tool_name="Bash", tool_use_id="call_nested02", tool_input=command)
    replay.hook(
        "PostToolUse",
        tool_name="Bash",
        tool_use_id="call_nested02",
        tool_input=command,
        tool_response='{"chunk_id":"a1","exit_code":0,"original_token_count":1,"output":"","wall_time_seconds":0.1}',
    )
    replay.hook("Stop", last_assistant_message="Done.", stop_hook_active=False)
    recorder = await sweep_all(replay)

    stream = [e for e in recorder.delivered if e.source is ObservationSource.CODEX_SESSION_STREAM]
    wrappers = [e for e in stream if e.structural_payload.get("tool_name") == "exec"]
    assert len(wrappers) == 1
    assert ObservationGapCode.UNPAIRED_EVENT.value not in wrappers[0].gap_codes
    records, later = _after_check(replay, boundary)
    assert counted_later_material(later, replay_ledger(records), all_records=records) != ()


@pytest.mark.parametrize(
    ("server", "own"),
    [(None, True), ("github", False), ("ci__bot", False)],
    ids=["server-less", "another-server", "unscopable-server"],
)
async def test_a_server_less_yoetz_item_keeps_its_cell_yoetz_own(
    replay: _Replay, server: str | None, own: bool
) -> None:
    """An ``McpToolCall`` without a ``server`` is named by its tool alone (``status``).

    The later-material rule reads that bare Yoetz name as Yoetz's own call, so the cell reads it
    alike: its output adds no ``exec`` action. Another server's ``status`` is named
    ``mcp__github__status`` and is not Yoetz's, so its cell keeps its own record; so does one
    under a server the reader cannot fold into that spelling (``ci__bot``), which names no tool.
    The nested hooks land only after the whole cell was written, so hook timing decides nothing.
    """

    boundary = await _checked(replay)
    call_id, ctc, ctco = _ids(2)
    hooked = f"mcp__{server or 'yoetz'}__status"
    tool_input = {"request_id": "req_public_2"}
    replay.append(
        exec_cell(
            call_id, f"await tools.{hooked}({{}});\n", "2026-10-09T08:45:00.000Z", item_id=ctc
        ),
        mcp_tool_call("exec-mcp-02", "status", "2026-10-09T08:45:00.100Z", server=server),
        exec_cell_output(call_id, '{"ok":true}', "2026-10-09T08:45:00.200Z", item_id=ctco),
    )
    replay.hook("PreToolUse", tool_name=hooked, tool_use_id="call_nested02", tool_input=tool_input)
    replay.hook(
        "PostToolUse",
        tool_name=hooked,
        tool_use_id="call_nested02",
        tool_input=tool_input,
        tool_response={"content": [{"text": "ok", "type": "text"}], "isError": False},
    )
    replay.hook("Stop", last_assistant_message="Done.", stop_hook_active=False)
    recorder = await sweep_all(replay)

    stream = [e for e in recorder.delivered if e.source is ObservationSource.CODEX_SESSION_STREAM]
    wrappers = [e for e in stream if e.structural_payload.get("tool_name") == "exec"]
    assert len(wrappers) == (0 if own else 1)
    records, later = _after_check(replay, boundary)
    counted = counted_later_material(later, replay_ledger(records), all_records=records)
    assert (counted == ()) is own


async def test_a_direct_call_with_both_ids_is_one_action(replay: _Replay) -> None:
    """A direct ``function_call`` (``fc_``/``fco_`` beside ``call_id``) folds with its hook copy.

    Keyed on ``id``, the stream copy of a hooked direct call recorded a second action and an
    unpaired result next to the hook's one action and result.
    """

    session_start(replay, cli_version=_VERSION)
    command = {"command": "pytest -q"}
    replay.hook("PreToolUse", tool_name="Bash", tool_use_id="call_direct", tool_input=command)
    replay.append(
        rollout_row(
            "response_item",
            {
                "arguments": '{"cmd":"pytest -q"}',
                "call_id": "call_direct",
                "id": "fc_direct",
                "name": "exec_command",
                "type": "function_call",
            },
            "2026-10-09T08:00:00.000Z",
        ),
        rollout_row(
            "response_item",
            {
                "call_id": "call_direct",
                "id": "fco_direct",
                "output": "Exit code: 1\nOutput:\npublic synthetic",
                "type": "function_call_output",
            },
            "2026-10-09T08:00:01.000Z",
        ),
    )
    replay.hook(
        "PostToolUse",
        tool_name="Bash",
        tool_use_id="call_direct",
        tool_input=command,
        tool_response='{"chunk_id":"a1","exit_code":1,"original_token_count":1,"output":"x","wall_time_seconds":0.1}',
    )
    replay.hook("Stop", last_assistant_message="Done.", stop_hook_active=False)
    recorder = await sweep_all(replay, capture_hook_output=True)

    assert recorder.refused == []
    assert len(replay.rows("action_recorded")) == 1
    assert len(replay.rows("result_recorded")) == 1
    descriptions = [
        str(getattr(row.payload, "description", "")) for row in replay.rows("evidence_recorded")
    ]
    assert not [text for text in descriptions if text.startswith("Unpaired observed tool result")]
