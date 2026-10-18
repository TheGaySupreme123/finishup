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
import os
from typing import cast

import pytest

from builders.codex_replay import Replay, replay_cell, rollout_row, session_start, sweep_all
from builders.observed_runs import ObservedLedger
from finishup.cli import runtime_facts
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
    VERIFICATION_ONLY_AS_ROOT_GAP,
    register_command_identity_key,
    task_fact_signals,
)
from unit.kernel.test_n6_closing_review_delta import declare_verifier

__all__ = ["replay_cell"]

_CALLS = {
    "call_n7_test": "python -m pytest -q",
    "call_n7_ls": "ls src",
    "call_n7_lint": "ruff check src",
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


@pytest.mark.anyio
@pytest.mark.parametrize("stream_first", [True, False])
@pytest.mark.parametrize("euid", [0, 1000], ids=["root", "non_root"])
async def test_root_only_verification_does_not_depend_on_which_copy_came_first(
    replay: Replay, stream_first: bool, euid: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#1106 r1: a stream-first action states no user, but the disclosure stays the same.

    Only the hook process knows its effective user; a call whose session-stream row defined the
    action carries none. Root verification is still disclosed, and a non-root run still is not.
    """

    # Only the hook's own user fact is faked: the state directory's ownership checks keep
    # reading the real effective user.
    class _Os:
        def __getattr__(self, name: str) -> object:
            return getattr(os, name)

        def geteuid(self) -> int:
            return euid

    monkeypatch.setattr(runtime_facts, "os", _Os())
    session_start(replay, cli_version="0.159.0")
    calls = ("call_n7_test", "call_n7_lint")
    if stream_first:
        replay.append(_call_row(calls[0], 1), _call_row(calls[1], 2))
    for call_id in calls:
        _hook(replay, "PreToolUse", call_id)
    if not stream_first:
        replay.append(_call_row(calls[0], 1), _call_row(calls[1], 2))
    replay.append(
        _output_row(calls[1], 2, "Process exited with code 0"),
        _output_row(calls[0], 1, "Process exited with code 0"),
    )
    for call_id in reversed(calls):
        _hook(replay, "PostToolUse", call_id)
    replay.hook("Stop", stop_hook_active=False)
    recorder = await sweep_all(replay)
    assert recorder.refused == []

    register_command_identity_key(replay.store.key_material())
    try:
        ledger = ObservedLedger()
        for row in replay.ledger._state.records:  # noqa: SLF001
            if type(row) is AcceptedEvent and row.schema.name in {
                "action_recorded",
                "result_recorded",
            }:
                ledger.append(row.schema, cast(EventPayload, row.payload), observed=True)
        codes = task_fact_signals(reduce_replay(ledger.prefix), ledger.prefix).codes
    finally:
        register_command_identity_key(None)
    assert (VERIFICATION_ONLY_AS_ROOT_GAP in codes) is (euid == 0), codes


def _command_row(call_id: str, index: int, command: str) -> dict[str, object]:
    return rollout_row(
        "response_item",
        {
            "arguments": json.dumps(
                {"cmd": command, "workdir": "/app", "yield_time_ms": 10000},
                separators=(",", ":"),
            ),
            "call_id": call_id,
            "id": f"fc_n7{index}",
            "name": "exec_command",
            "type": "function_call",
        },
        f"2026-10-17T09:00:0{index}.000Z",
    )


def _command_hook(replay: Replay, event: str, call_id: str, command: str) -> None:
    fields: dict[str, object] = {
        "tool_name": "Bash",
        "tool_use_id": call_id,
        "tool_input": {"command": command},
    }
    if event == "PostToolUse":
        fields["tool_response"] = "ok\n"
    replay.hook(event, **fields)


async def _parallel_codes(
    replay: Replay, calls: tuple[tuple[str, str], ...], *, stream_first: bool, prior: str | None
) -> tuple[tuple[str, ...], list[str]]:
    """Run parallel Codex calls in either order; the task facts and the shell action texts.

    ``prior`` is a verification the ledger already holds, after an edit, before these calls.
    """

    session_start(replay, cli_version="0.159.0")
    rows = [
        _command_row(call_id, index, command) for index, (call_id, command) in enumerate(calls, 1)
    ]
    if stream_first:
        # Every call row is on disk before the first hook fires: its reconcile delivers them.
        replay.append(*rows)
    for call_id, command in calls:
        _command_hook(replay, "PreToolUse", call_id, command)
    if not stream_first:
        replay.append(*rows)
    replay.append(
        *(
            _output_row(call_id, index, "Process exited with code 0")
            for index, (call_id, _command) in reversed(list(enumerate(calls, 1)))
        )
    )
    for call_id, command in reversed(calls):
        _command_hook(replay, "PostToolUse", call_id, command)
    replay.hook("Stop", stop_hook_active=False)
    recorder = await sweep_all(replay)
    assert recorder.refused == []
    descriptions = [
        payload.description
        for payload in (row.payload for row in replay.rows("action_recorded"))
        if type(payload) is ActionRecordedPayload
        and ("(tool Bash)" in payload.description or "(tool exec_command)" in payload.description)
    ]
    register_command_identity_key(replay.store.key_material())
    try:
        ledger = ObservedLedger()
        if prior is not None:
            ledger.edit()
            ledger.passes(prior)
        for row in replay.ledger._state.records:  # noqa: SLF001
            if type(row) is AcceptedEvent and row.schema.name in {
                "action_recorded",
                "result_recorded",
            }:
                ledger.append(row.schema, cast(EventPayload, row.payload), observed=True)
        codes = task_fact_signals(reduce_replay(ledger.prefix), ledger.prefix).codes
    finally:
        register_command_identity_key(None)
    return codes, descriptions


@pytest.mark.anyio
@pytest.mark.parametrize("stream_first", [True, False])
@pytest.mark.parametrize("euid", [0, 1000], ids=["root", "non_root"])
@pytest.mark.parametrize(
    "verifier", ["python -m pytest -q", "pytest -q || true", "pytest -q | tail -5"]
)
async def test_root_only_verification_when_only_the_second_parallel_call_verifies(
    replay: Replay,
    stream_first: bool,
    euid: int,
    verifier: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#1106 r2: the n7 shape. The verifier is the second call of a batch, so with the rows on
    disk first, the first call's hook delivers its stream row and that row defines the only
    verification run. The reconciling hook gives the row its own user fact, so root verification
    is disclosed (and a non-root run is not) whichever copy came first."""

    class _Os:
        def __getattr__(self, name: str) -> object:
            return getattr(os, name)

        def geteuid(self) -> int:
            return euid

    monkeypatch.setattr(runtime_facts, "os", _Os())
    codes, descriptions = await _parallel_codes(
        replay,
        (("call_n7_ls", "ls src"), ("call_n7_verify", verifier)),
        stream_first=stream_first,
        prior=None,
    )
    if stream_first:
        assert any("(tool exec_command)" in item for item in descriptions), descriptions
    user = "(user root)" if euid == 0 else "(user non_root)"
    assert all(user in item for item in descriptions), descriptions
    assert (VERIFICATION_ONLY_AS_ROOT_GAP in codes) is (euid == 0), codes


@pytest.mark.anyio
@pytest.mark.parametrize("stream_first", [True, False])
@pytest.mark.parametrize(
    ("command", "code"),
    [
        pytest.param(
            "cat > {workspace}/src/x.py <<'EOF'\nx = 1\nEOF",
            EDITED_AFTER_LAST_VERIFICATION_GAP,
            id="absolute_workspace_write",
        ),
        pytest.param(
            "cat > src/x.py <<'EOF'\nx = 1\nEOF",
            EDITED_AFTER_LAST_VERIFICATION_GAP,
            id="relative_workspace_write",
        ),
        pytest.param(
            "pip install --target /opt/vendor requests",
            "install_into_private_env",
            id="install_target",
        ),
    ],
)
async def test_a_stream_defined_call_carries_the_hooks_write_and_install_facts(
    replay: Replay, stream_first: bool, command: str, code: str
) -> None:
    """#1106 r2 (goal-r2-2): a stream row that defines the action carries the hook's own write
    scope (an absolute path in the workspace included) and install target, so a real edit after
    the test makes it stale, and an install is disclosed, whichever copy came first."""

    filled = command.replace("{workspace}", str(replay.workspace))
    codes, _descriptions = await _parallel_codes(
        replay,
        (("call_n7_ls", "ls src"), ("call_n7_write", filled)),
        stream_first=stream_first,
        prior="pytest -q",
    )
    assert code in codes, codes
