"""Parallel Codex shell calls whose rollout rows commit first keep their identity (n7 RC2, #1106).

Codex writes every ``function_call`` row of a turn before it runs them, so the first call's hook
reconciles the rollout and delivers the other calls' rows before their own hooks fire. Both
copies of a call mint the same action id, so whichever commits first defines the action. These
cases run real hook payloads through ``handle_observe``, the rollout through the session-stream
reader those hooks trigger, and every outbox row through the real coordinator, then read the
recorded actions and results back.
"""

# pyright: reportPrivateUsage=false
from __future__ import annotations

import json
from typing import cast

import pytest

from builders.codex_replay import Replay, replay_cell, rollout_row, session_start, sweep_all
from builders.observed_runs import ObservedLedger
from finishup.domain.events import (
    AcceptedEvent,
    ActionRecordedPayload,
    EventPayload,
    ResultOutcome,
    ResultRecordedPayload,
)
from finishup.kernel.reducers import replay as reduce_replay
from finishup.kernel.task_facts import (
    EDITED_AFTER_LAST_VERIFICATION_GAP,
    register_command_identity_key,
    task_fact_signals,
)
from unit.kernel.test_n6_closing_review_delta import declare_verifier

__all__ = ["replay_cell"]

_CALLS = {
    "call_n7_test": "python -m pytest -q",
    "call_n7_ls": "ls src",
}


def _call_row(call_id: str, index: int) -> dict[str, object]:
    return rollout_row(
        "response_item",
        {
            "arguments": json.dumps(
                {"cmd": _CALLS[call_id], "workdir": "/app", "yield_time_ms": 10000},
                separators=(",", ":"),
            ),
            "call_id": call_id,
            "id": f"fc_n7{index}",
            "name": "exec_command",
            "type": "function_call",
        },
        f"2026-10-17T09:00:0{index}.000Z",
    )


def _output_row(call_id: str, index: int, header: str) -> dict[str, object]:
    return rollout_row(
        "response_item",
        {
            "call_id": call_id,
            "output": f"Chunk ID: n7{index}\nWall time: 0.4000 seconds\n{header}\nOutput:\nok\n",
            "type": "function_call_output",
        },
        f"2026-10-17T09:00:0{index}.500Z",
    )


def _hook(replay: Replay, event: str, call_id: str) -> None:
    fields: dict[str, object] = {
        "tool_name": "Bash",
        "tool_use_id": call_id,
        "tool_input": {"command": _CALLS[call_id]},
    }
    if event == "PostToolUse":
        # Codex 0.159 hands a Bash post the process output only: no exit fact.
        fields["tool_response"] = "ok\n"
    replay.hook(event, **fields)


def _results(replay: Replay) -> list[ResultRecordedPayload]:
    results: list[ResultRecordedPayload] = []
    for row in replay.rows("result_recorded"):
        assert type(row.payload) is ResultRecordedPayload
        results.append(row.payload)
    return results


@pytest.mark.anyio
@pytest.mark.parametrize("stream_first", [True, False])
async def test_parallel_calls_keep_identity_runner_and_exit_in_either_order(
    replay: Replay, stream_first: bool
) -> None:
    session_start(replay, cli_version="0.159.0")
    if stream_first:
        # Both call rows are on disk before the first hook fires: its reconcile delivers both.
        replay.append(_call_row("call_n7_test", 1), _call_row("call_n7_ls", 2))
        _hook(replay, "PreToolUse", "call_n7_test")
        _hook(replay, "PreToolUse", "call_n7_ls")
    else:
        _hook(replay, "PreToolUse", "call_n7_test")
        _hook(replay, "PreToolUse", "call_n7_ls")
        replay.append(_call_row("call_n7_test", 1), _call_row("call_n7_ls", 2))
    replay.append(
        _output_row("call_n7_ls", 2, "Process exited with code 0"),
        _output_row("call_n7_test", 1, "Process exited with code 0"),
    )
    _hook(replay, "PostToolUse", "call_n7_ls")
    _hook(replay, "PostToolUse", "call_n7_test")
    replay.hook("Stop", stop_hook_active=False)
    recorder = await sweep_all(replay)
    assert recorder.refused == []

    actions = [row.payload for row in replay.rows("action_recorded")]
    shell_actions = [
        payload
        for payload in actions
        if type(payload) is ActionRecordedPayload
        and ("(tool Bash)" in payload.description or "(tool exec_command)" in payload.description)
    ]
    assert len(shell_actions) == 2, [getattr(item, "description", None) for item in actions]
    # Whichever copy defined the action, it carries the keyed command and the runner class.
    for payload in shell_actions:
        assert (payload.command or "").startswith("omitted:hmac-sha256:"), payload.command
    runners = sorted(
        "test" if "(runner test)" in payload.description else "other" for payload in shell_actions
    )
    assert runners == ["other", "test"], [item.description for item in shell_actions]
    if stream_first:
        # The second call's rollout row was delivered by the first call's hook: it defined the
        # action (the race this pins), and its hook copy then joined it as a duplicate.
        assert any("(tool exec_command)" in item.description for item in shell_actions)
    # The rollout header is each call's exit: the 0.159 hook states none.
    stated = [result for result in _results(replay) if result.outcome is not ResultOutcome.UNKNOWN]
    assert sorted((result.outcome, result.exit_status) for result in stated) == [
        (ResultOutcome.SUCCESS, 0),
        (ResultOutcome.SUCCESS, 0),
    ]
    # The kernel reads what the coordinator recorded: the planned command was observed, passed,
    # and ran after the edit, so no planned-verification or stale-verification fact stands.
    register_command_identity_key(replay.store.key_material())
    try:
        ledger = ObservedLedger()
        declare_verifier(ledger, "python -m pytest -q")
        ledger.edit()
        for row in replay.ledger._state.records:  # noqa: SLF001
            if type(row) is AcceptedEvent and row.schema.name in {
                "action_recorded",
                "result_recorded",
            }:
                ledger.append(row.schema, cast(EventPayload, row.payload), observed=True)
        codes = task_fact_signals(reduce_replay(ledger.prefix), ledger.prefix).codes
    finally:
        register_command_identity_key(None)
    assert not any(code.startswith("planned_verification") for code in codes), codes
    assert EDITED_AFTER_LAST_VERIFICATION_GAP not in codes
