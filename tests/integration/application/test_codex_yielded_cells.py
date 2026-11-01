"""A yielded code-mode cell keeps its identity until its terminal ``wait`` output (tb4n5, #1038).

tb4n5 S arm: a cell whose only call was ``tools.mcp__yoetz__check`` outlived its yield window, so
Codex wrote ``Script running with cell ID 38`` as the ``exec`` output before the nested
``McpToolCall`` item. The reader decided the cell at that first output, delivered it as an
unclassified ``exec`` action after the check it ran, and the final receipt carried
``check_current_as_of_earlier_frontier`` (vpp S 292 -> 295; interleaved, react, kv, live-db alike).
A cell that called no tool at all did the same (medical S 607).

These replays drive the recorded topology through the real hook ingress, stream reader,
coordinator and ledger: the yield output, repeated ``wait`` polls (a 1 s pragma), ``clocksleep``
while the check runs, overlapping cells, a reload of the local store mid-cell, and the turn's end.
What follows the check is classified with the predicate the receipt uses
(``counted_later_material``).
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import json
from typing import Any, cast

import pytest

from builders.codex_replay import Replay as _Replay
from builders.codex_replay import (
    command_execution,
    exec_cell,
    exec_cell_output,
    mcp_tool_call,
    replay_cell,  # noqa: F401  # pyright: ignore[reportUnusedImport]  (registers the ``replay`` fixture)
    rollout_row,
    session_start,
    sweep_all,
)
from builders.observed_runs import ObservedLedger
from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.domain.events import AcceptedEvent, EventPayload, LedgerRecord
from finishup.domain.observation import ObservationSource
from finishup.domain.values import EventId
from finishup.kernel.later_material import counted_later_material
from finishup.kernel.reducers import replay as replay_ledger

pytestmark = pytest.mark.anyio

_VERSION = "0.159.3"
_OBSERVED = frozenset({"action_recorded", "result_recorded", "evidence_recorded"})
_OK = {"content": [{"text": "ok", "type": "text"}], "isError": False}


def _yield_output(call_id: str, cell: str, timestamp: str) -> dict[str, Any]:
    """The ``exec`` output Codex writes when a cell outlives its yield window."""

    return rollout_row(
        "response_item",
        {
            "call_id": call_id,
            "id": f"ctco_{call_id}",
            "output": [
                {
                    "text": f"Script running with cell ID {cell}\nWall time 31.0 seconds\nOutput:\n",
                    "type": "input_text",
                }
            ],
            "type": "custom_tool_call_output",
        },
        timestamp,
    )


def _wait_call(call_id: str, cell: str, timestamp: str) -> dict[str, Any]:
    return rollout_row(
        "response_item",
        {
            "arguments": json.dumps({"cell_id": cell, "max_tokens": 4000, "yield_time_ms": 1000}),
            "call_id": call_id,
            "id": f"fc_{call_id}",
            "name": "wait",
            "type": "function_call",
        },
        timestamp,
    )


def _wait_output(call_id: str, timestamp: str, *, running: str | None = None) -> dict[str, Any]:
    header = (
        f"Script running with cell ID {running}\nWall time 1.0 seconds\nOutput:\n"
        if running is not None
        else "Script completed\nWall time 0.0 seconds\nOutput:\n"
    )
    output: list[dict[str, str]] = [{"text": header, "type": "input_text"}]
    if running is None:
        output.append({"text": '{"verdict":"no_issue_detected"}', "type": "input_text"})
    return rollout_row(
        "response_item",
        {
            "call_id": call_id,
            "id": f"fco_{call_id}",
            "output": output,
            "type": "function_call_output",
        },
        timestamp,
    )


def _observed_ledger(cell: _Replay) -> ObservedLedger:
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


def _counted_after(cell: _Replay, boundary: int) -> tuple[LedgerRecord, ...]:
    records = _observed_ledger(cell).prefix
    return counted_later_material(records[boundary:], replay_ledger(records), all_records=records)


def _exec_records(recorder: Any) -> list[Any]:
    return [
        envelope
        for envelope in recorder.delivered
        if envelope.source is ObservationSource.CODEX_SESSION_STREAM
        and envelope.structural_payload.get("tool_name") == "exec"
    ]


async def _check_cell_started(cell: _Replay, *, call_id: str = "call_check") -> int:
    """Open a code-mode cell whose only call is ``tools.mcp__yoetz__check``; return the boundary.

    The service records the check while the nested call runs, after its ``PreToolUse``: every
    observed record from here on follows the check.
    """

    session_start(cell, cli_version=_VERSION)
    cell.append(
        exec_cell(
            call_id,
            "const r=await tools.mcp__yoetz__check({});text(r);\n",
            "2026-10-12T19:39:42.274Z",
            item_id=f"ctc_{call_id}",
        )
    )
    cell.hook(
        "PreToolUse",
        tool_name="mcp__yoetz__check",
        tool_use_id=f"{call_id}_nested",
        tool_input={"request_id": "req_public_check"},
    )
    await sweep_all(cell)
    return len(_observed_ledger(cell).records)


def _check_finishes(cell: _Replay, *, call_id: str = "call_check") -> None:
    cell.append(mcp_tool_call(f"exec-{call_id}", "check", "2026-10-12T19:40:17.900Z"))
    cell.hook(
        "PostToolUse",
        tool_name="mcp__yoetz__check",
        tool_use_id=f"{call_id}_nested",
        tool_input={"request_id": "req_public_check"},
        tool_response=_OK,
    )


async def test_a_yielded_check_cell_with_repeated_waits_does_not_bound_its_own_check(
    replay: _Replay,
) -> None:
    """vpp S: yield output, a running ``wait``, the nested item, then the completing ``wait``."""

    boundary = await _check_cell_started(replay)
    replay.append(
        _yield_output("call_check", "38", "2026-10-12T19:40:13.300Z"),
        _wait_call("call_w1", "38", "2026-10-12T19:40:15.638Z"),
        _wait_output("call_w1", "2026-10-12T19:40:16.700Z", running="38"),
    )
    _check_finishes(replay)
    replay.append(
        _wait_call("call_w2", "38", "2026-10-12T19:40:22.474Z"),
        _wait_output("call_w2", "2026-10-12T19:40:22.500Z"),
    )
    replay.hook("Stop", last_assistant_message="Done.", stop_hook_active=False)
    recorder = await sweep_all(replay)

    assert recorder.refused == []
    # The cell's record is its nested FinishUP call: neither its yield output nor any other
    # ``exec`` row reaches the ledger, and the polls are host bookkeeping.
    assert _exec_records(recorder) == []
    assert _counted_after(replay, boundary) == ()


async def test_a_yield_read_after_every_hook_is_still_decided_by_its_terminal_wait(
    replay: _Replay,
) -> None:
    """The hook-latency shape: every row is written before the hooks that read them fire."""

    boundary = await _check_cell_started(replay)
    replay.append(
        _yield_output("call_check", "38", "2026-10-12T19:40:13.300Z"),
        _wait_call("call_w1", "38", "2026-10-12T19:40:15.638Z"),
        _wait_output("call_w1", "2026-10-12T19:40:16.700Z", running="38"),
        mcp_tool_call("exec-call_check", "check", "2026-10-12T19:40:17.900Z"),
        _wait_call("call_w2", "38", "2026-10-12T19:40:22.474Z"),
        _wait_output("call_w2", "2026-10-12T19:40:22.500Z"),
    )
    replay.hook(
        "PostToolUse",
        tool_name="mcp__yoetz__check",
        tool_use_id="call_check_nested",
        tool_input={"request_id": "req_public_check"},
        tool_response=_OK,
    )
    replay.hook("Stop", last_assistant_message="Done.", stop_hook_active=False)
    recorder = await sweep_all(replay)

    assert _exec_records(recorder) == []
    assert _counted_after(replay, boundary) == ()


async def test_short_polls_and_sleeps_while_the_check_runs_do_not_bound_it(
    replay: _Replay,
) -> None:
    """react S: a 1 s pragma, many ``wait`` polls, and ``clocksleep`` while the check runs."""

    boundary = await _check_cell_started(replay)
    replay.append(_yield_output("call_check", "50", "2026-10-12T19:47:40.000Z"))
    for n in range(4):
        replay.append(
            _wait_call(f"call_p{n}", "50", f"2026-10-12T19:47:4{n + 1}.000Z"),
            _wait_output(f"call_p{n}", f"2026-10-12T19:47:4{n + 1}.500Z", running="50"),
        )
    for n in range(2):
        sleep = {"duration_ms": 20000}
        replay.hook(
            "PreToolUse", tool_name="clocksleep", tool_use_id=f"call_z{n}", tool_input=sleep
        )
        replay.hook(
            "PostToolUse",
            tool_name="clocksleep",
            tool_use_id=f"call_z{n}",
            tool_input=sleep,
            tool_response="Wall time: 20.0036 seconds\nSleep completed.",
        )
    _check_finishes(replay)
    replay.append(
        _wait_call("call_p9", "50", "2026-10-12T19:49:06.000Z"),
        _wait_output("call_p9", "2026-10-12T19:49:06.500Z"),
    )
    replay.hook("Stop", last_assistant_message="Done.", stop_hook_active=False)
    recorder = await sweep_all(replay)

    assert recorder.refused == []
    assert _exec_records(recorder) == []
    assert _counted_after(replay, boundary) == ()


async def test_an_open_yielded_cell_survives_a_store_reload(replay: _Replay) -> None:
    """The open cell, its runtime id and its held output are durable across a restart."""

    boundary = await _check_cell_started(replay)
    replay.append(
        _yield_output("call_check", "38", "2026-10-12T19:40:13.300Z"),
        _wait_call("call_w1", "38", "2026-10-12T19:40:15.638Z"),
    )
    replay.hook("PreToolUse", tool_name="clocksleep", tool_use_id="call_z", tool_input={})
    reloaded = LocalObservationStore(_state=replay.root)
    cells = [
        cell
        for cell in (reloaded._load(replay.commitment).code_mode_cells or {}).values()
        if cell.runtime_cell == "38"
    ]
    assert len(cells) == 1
    assert cells[0].output_local is None
    assert cells[0].held_output is not None
    assert cells[0].waits == ("call_w1",)
    replay.append(_wait_output("call_w1", "2026-10-12T19:40:16.700Z", running="38"))
    _check_finishes(replay)
    replay.append(
        _wait_call("call_w2", "38", "2026-10-12T19:40:22.474Z"),
        _wait_output("call_w2", "2026-10-12T19:40:22.500Z"),
    )
    replay.hook("Stop", last_assistant_message="Done.", stop_hook_active=False)
    recorder = await sweep_all(replay)

    assert _exec_records(recorder) == []
    assert _counted_after(replay, boundary) == ()


async def test_a_yielded_cell_that_ran_a_command_keeps_its_record(replay: _Replay) -> None:
    """A yielded cell whose nested activity was not only FinishUP's own still bounds the check."""

    boundary = await _check_cell_started(replay)
    command = 'python -c \'open("out.json","w")\''
    replay.append(
        _yield_output("call_check", "40", "2026-10-12T19:40:13.300Z"),
        command_execution("exec-cmd-40", command, 0, "2026-10-12T19:40:14.000Z"),
    )
    replay.hook(
        "PreToolUse", tool_name="Bash", tool_use_id="call_cmd40", tool_input={"command": command}
    )
    # The replayed command really writes its file: the workspace fingerprint reads what the
    # command changed, not its text, so a command that changed nothing would be quiet.
    (replay.workspace / "out.json").write_text("")
    replay.hook(
        "PostToolUse",
        tool_name="Bash",
        tool_use_id="call_cmd40",
        tool_input={"command": command},
        tool_response='{"chunk_id":"a1","exit_code":0,"original_token_count":1,"output":"","wall_time_seconds":0.1}',
    )
    _check_finishes(replay)
    replay.append(
        _wait_call("call_w2", "40", "2026-10-12T19:40:22.474Z"),
        _wait_output("call_w2", "2026-10-12T19:40:22.500Z"),
    )
    replay.hook("Stop", last_assistant_message="Done.", stop_hook_active=False)
    await sweep_all(replay)

    assert _counted_after(replay, boundary) != ()


async def test_overlapping_cells_never_borrow_each_others_finishup_calls(replay: _Replay) -> None:
    """A second cell that runs while the check cell is yielded makes both cells ambiguous.

    Its nested command cannot be told from the check cell's activity, so neither cell is read
    as FinishUP's own (both are marked ``other``) and the unrelated command keeps its own
    classification through its hook rows, which the #917 rule makes the cells' record.
    """

    boundary = await _check_cell_started(replay)
    command = "pytest -q"
    replay.append(
        _yield_output("call_check", "60", "2026-10-12T19:40:13.300Z"),
        exec_cell(
            "call_other",
            "await tools.exec_command({cmd:'pytest -q'});\n",
            "2026-10-12T19:40:14.000Z",
            item_id="ctc_call_other",
        ),
    )
    replay.hook(
        "PreToolUse", tool_name="Bash", tool_use_id="call_cmd61", tool_input={"command": command}
    )
    replay.append(command_execution("exec-cmd-61", command, 0, "2026-10-12T19:40:15.000Z"))
    replay.hook(
        "PostToolUse",
        tool_name="Bash",
        tool_use_id="call_cmd61",
        tool_input={"command": command},
        tool_response='{"chunk_id":"a2","exit_code":0,"original_token_count":1,"output":"1 passed","wall_time_seconds":0.1}',
    )
    replay.append(
        exec_cell_output("call_other", "{}", "2026-10-12T19:40:16.000Z", item_id="ctco_call_other")
    )
    _check_finishes(replay)
    replay.append(
        _wait_call("call_w2", "60", "2026-10-12T19:40:22.474Z"),
        _wait_output("call_w2", "2026-10-12T19:40:22.500Z"),
    )
    replay.hook("Stop", last_assistant_message="Done.", stop_hook_active=False)
    recorder = await sweep_all(replay)

    assert recorder.refused == []
    counted = _counted_after(replay, boundary)
    assert any("Bash" in str(getattr(record.payload, "description", "")) for record in counted), (
        "the unrelated command must keep bounding the check"
    )
    # Neither cell borrowed the other's calls: both are ``other``, never FinishUP's own.
    cells = (replay.store._load(replay.commitment).code_mode_cells or {}).values()
    assert {cell.nested for cell in cells if cell.session is not None} == {"other"}


async def test_a_cell_that_called_no_tool_is_no_workspace_activity(replay: _Replay) -> None:
    """medical S: a cell that only read stored state (``text(load(...))``) after the check."""

    boundary = await _check_cell_started(replay)
    replay.append(
        _yield_output("call_check", "70", "2026-10-12T19:40:13.300Z"),
    )
    _check_finishes(replay)
    replay.append(
        _wait_call("call_w2", "70", "2026-10-12T19:40:22.474Z"),
        _wait_output("call_w2", "2026-10-12T19:40:22.500Z"),
        exec_cell(
            "call_read",
            'text(load("obligations"));\n',
            "2026-10-12T19:47:43.000Z",
            item_id="ctc_call_read",
        ),
        exec_cell_output("call_read", "[]", "2026-10-12T19:47:43.100Z", item_id="ctco_call_read"),
    )
    replay.hook("Stop", last_assistant_message="Done.", stop_hook_active=False)
    recorder = await sweep_all(replay)

    assert _exec_records(recorder) == []
    assert _counted_after(replay, boundary) == ()


async def test_a_yielded_cell_nobody_waited_on_is_decided_at_the_turn_end(
    replay: _Replay,
) -> None:
    """Codex keeps a yielded cell running past the turn; its held output is not kept forever."""

    session_start(replay, cli_version=_VERSION)
    command = "make build"
    replay.append(
        exec_cell(
            "call_bg",
            "await tools.exec_command({cmd:'make build'});\n",
            "2026-10-12T19:40:00.000Z",
            item_id="ctc_call_bg",
        ),
        _yield_output("call_bg", "80", "2026-10-12T19:40:30.000Z"),
        command_execution("exec-cmd-80", command, 2, "2026-10-12T19:40:31.000Z"),
        rollout_row(
            "event_msg",
            {"last_agent_message": "Done.", "turn_id": "turn_1", "type": "task_complete"},
            "2026-10-12T19:40:32.000Z",
        ),
    )
    replay.hook("Stop", last_assistant_message="Done.", stop_hook_active=False)
    recorder = await sweep_all(replay)

    assert recorder.refused == []
    assert len(_exec_records(recorder)) == 1
    cells = (replay.store._load(replay.commitment).code_mode_cells or {}).values()
    assert all(cell.held_output is None for cell in cells)
