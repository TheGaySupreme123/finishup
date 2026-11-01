"""A Codex hook copy places a relative shell write under its own call's ``workdir`` (#1106 r3).

A Codex 0.159 hook payload carries the session ``cwd``, never the call's ``workdir`` argument
(``exec_command.rs`` sends ``tool_input: {"command": args.cmd}``). Codex writes the call's
``function_call`` row before it runs the call, so the hook reads that row from the validated
rollout when, and only when, placing a relative write would make it documentation. A row it cannot
find keeps the write an ordinary edit. These cases run real hook payloads through
``handle_observe`` and every outbox row through the real coordinator, with the hook copy
committing first (a call made alone), then read the task facts back.
"""

# pyright: reportPrivateUsage=false
from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from builders.codex_replay import Replay, replay_cell, rollout_row, session_start, sweep_all
from builders.observed_runs import ObservedLedger
from finishup.domain.events import AcceptedEvent, ActionRecordedPayload, EventPayload
from finishup.kernel.reducers import replay as reduce_replay
from finishup.kernel.task_facts import (
    EDITED_AFTER_LAST_VERIFICATION_GAP,
    register_command_identity_key,
    task_fact_signals,
)

__all__ = ["replay_cell"]

_CALL = "call_r3_readme"
_COMMAND = "cat > README.md <<'EOF'\n# Usage\nEOF"
_ABSENT = object()


def _call_row(workdir: object) -> dict[str, object]:
    arguments: dict[str, object] = {"cmd": _COMMAND, "yield_time_ms": 10000}
    if workdir is not _ABSENT:
        arguments["workdir"] = workdir
    return rollout_row(
        "response_item",
        {
            "arguments": json.dumps(arguments, separators=(",", ":")),
            "call_id": _CALL,
            "id": "fc_r3",
            "name": "exec_command",
            "type": "function_call",
        },
        "2026-10-18T09:00:01.000Z",
    )


def _output_row() -> dict[str, object]:
    return rollout_row(
        "response_item",
        {
            "call_id": _CALL,
            "output": "Chunk ID: r3\nWall time: 0.1000 seconds\nProcess exited with code 0\n"
            "Output:\n",
            "type": "function_call_output",
        },
        "2026-10-18T09:00:01.500Z",
    )


def _hook(replay: Replay, event: str) -> None:
    fields: dict[str, object] = {
        "tool_name": "Bash",
        "tool_use_id": _CALL,
        "tool_input": {"command": _COMMAND},
    }
    if event == "PostToolUse":
        fields["tool_response"] = "ok\n"
    replay.hook(event, **fields)


async def _facts(replay: Replay, *, workdir: object, row_first: bool) -> tuple[set[str], str]:
    session_start(replay, cli_version="0.159.0")
    (replay.workspace / "tests").mkdir(exist_ok=True)
    if row_first:
        replay.append(_call_row(workdir))
    _hook(replay, "PreToolUse")
    if not row_first:
        replay.append(_call_row(workdir))
    # A successful write must change the actual workspace fingerprint, not only the trace.
    directory = Path(workdir) if isinstance(workdir, str) else replay.workspace
    if not directory.is_absolute():
        directory = replay.workspace / directory
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "README.md").write_text("# Usage\n")
    replay.append(_output_row())
    _hook(replay, "PostToolUse")
    replay.hook("Stop", stop_hook_active=False)
    recorder = await sweep_all(replay)
    assert recorder.refused == []
    descriptions = [
        payload.description
        for payload in (row.payload for row in replay.rows("action_recorded"))
        if type(payload) is ActionRecordedPayload and "(tool Bash)" in payload.description
    ]
    assert len(descriptions) == 1, descriptions
    register_command_identity_key(replay.store.key_material())
    try:
        ledger = ObservedLedger()
        ledger.edit()
        ledger.passes("pytest -q")
        for row in replay.ledger._state.records:  # noqa: SLF001
            if type(row) is AcceptedEvent and row.schema.name in {
                "action_recorded",
                "result_recorded",
            }:
                ledger.append(row.schema, cast(EventPayload, row.payload), observed=True)
        codes = set(task_fact_signals(reduce_replay(ledger.prefix), ledger.prefix).codes)
    finally:
        register_command_identity_key(None)
    return codes, descriptions[0]


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("workdir", "scope"),
    [
        pytest.param("{root}", "docs", id="workdir_root"),
        pytest.param("{root}/docs", "docs", id="workdir_docs"),
        pytest.param(_ABSENT, "docs", id="no_workdir"),
        pytest.param("{root}/tests", "workspace", id="workdir_tests"),
        pytest.param("tests", "workspace", id="relative_workdir"),
        pytest.param(7, "workspace", id="workdir_not_a_string"),
    ],
)
async def test_a_hook_first_codex_call_reads_its_own_workdir(
    replay: Replay, workdir: object, scope: str
) -> None:
    """goal-r3-3: hook first, a README written into a ``tests/`` ``workdir`` read as ``docs`` and
    the earlier test stayed current; one written at the root must still be documentation."""

    (replay.workspace / "docs").mkdir(exist_ok=True)
    filled = workdir.replace("{root}", str(replay.workspace)) if type(workdir) is str else workdir
    codes, description = await _facts(replay, workdir=filled, row_first=True)
    assert f"(write {scope})" in description, description
    assert (EDITED_AFTER_LAST_VERIFICATION_GAP in codes) is (scope == "workspace"), codes


@pytest.mark.anyio
async def test_a_hook_that_cannot_find_its_row_keeps_the_write_an_edit(replay: Replay) -> None:
    """A row not yet on disk when the hook fires gives no working directory: an ordinary edit."""

    codes, description = await _facts(replay, workdir=str(replay.workspace), row_first=False)
    assert "(write workspace)" in description, description
    assert EDITED_AFTER_LAST_VERIFICATION_GAP in codes, codes
