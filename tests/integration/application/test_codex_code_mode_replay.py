"""Replay a Codex 0.157 code-mode session through real hook ingress to the ledger (#917).

The hook payloads and rollout lines use the shapes a Codex 0.157.1 code-mode
session produces (issue #917 examples 1-3 and the issue #910 evidence): one
custom ``exec`` tool per model turn, nested ``tools.exec_command`` /
``tools.apply_patch`` / ``tools.mcp__yoetz__*`` calls that each fire their own
``Bash`` / ``apply_patch`` / MCP hooks, and a session rollout that records the
outer cell plus the nested ``CommandExecution`` items. Nothing is pre-normalised:
every hook payload goes through ``observe_hooks.handle_observe``, every rollout
line through the session-stream reader that the hooks trigger, and every outbox
row through the real sweeper and observation coordinator into a task ledger.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import asyncio
import json
from typing import Any, Literal, cast

import pytest

from builders.codex_replay import (
    HOST,
    command_execution,
    compact,
    exec_cell,
    exec_cell_output,
    replay_cell,  # noqa: F401  # pyright: ignore[reportUnusedImport]  (registers the ``replay`` fixture)
    rollout_row,
    running_run,
    session_start,
    sweep_all,
)
from builders.codex_replay import Recorder as _Recorder
from builders.codex_replay import Replay as _Replay
from builders.codex_replay import build_coordinator as _coordinator
from builders.observed_runs import ObservedLedger, omissions, omitted_results, receipt_limitations
from yoetz.adapters.integrations.observation_admission import build_routine_read_summary
from yoetz.application.observation_drain import ObservationOutboxSweeper
from yoetz.application.observation_materialize import materialize_observation_envelope
from yoetz.domain.events import (
    AcceptedEvent,
    ActionKind,
    ActionRecordedPayload,
    EventPayload,
    EvidenceRecordedPayload,
    ResultOutcome,
    ResultRecordedPayload,
)
from yoetz.domain.observation import (
    ObservationEnvelope,
    ObservationGapCode,
    ObservationIngestRequest,
    ObservationSource,
)
from yoetz.protocol.coverage import PublicationChannel


def _code_mode_session(cell: _Replay) -> dict[str, int]:
    """Drive one realistic code-mode session; return the host calls it made."""

    cell.append(
        rollout_row(
            "session_meta",
            {
                "cli_version": "0.157.1",
                "cwd": str(cell.workspace),
                "history_mode": "legacy",
                "id": HOST,
                "originator": "codex_exec",
            },
            "2026-09-29T17:54:00.000Z",
        )
    )
    cell.hook("SessionStart", source="startup")

    # Example 1 (#910): one cell, one failing typecheck through tools.exec_command.
    cell.append(
        exec_cell(
            "call_cellTypecheck",
            'const r=await tools.exec_command({cmd:"npm run test-type",workdir:"/app"});text(r)\n',
            "2026-09-29T17:57:47.000Z",
        )
    )
    command = {"command": "npm run test-type"}
    cell.hook("PreToolUse", tool_name="Bash", tool_use_id="call_nTypecheck", tool_input=command)
    cell.advance(23.0)
    cell.append(
        command_execution("exec-42439c0d-a", "npm run test-type", 2, "2026-09-29T17:58:10.743Z")
    )
    cell.hook(
        "PostToolUse",
        tool_name="Bash",
        tool_use_id="call_nTypecheck",
        tool_input=command,
        tool_response=json.dumps(
            {
                "chunk_id": "d74c6f",
                "exit_code": 2,
                "original_token_count": 1919,
                "output": "> tsc --noEmit\nerror TS2322: public synthetic",
                "wall_time_seconds": 23.226037979,
            }
        ),
    )
    cell.append(
        exec_cell_output(
            "call_cellTypecheck",
            '{"chunk_id":"d74c6f","exit_code":2,"output":"error TS2322"}',
            "2026-09-29T17:58:12.000Z",
        )
    )

    # Example 2 (#917): one cell, two nested Yoetz publish_work calls. Their pres
    # stay local by contract (#564); each post carries the call.
    cell.advance(2.0)
    cell.append(
        exec_cell(
            "call_cellPublish",
            "await tools.mcp__yoetz__publish_work({dry_run:true});"
            "await tools.mcp__yoetz__publish_work({dry_run:false});\n",
            "2026-09-29T17:55:00.355Z",
        )
    )
    for index, call in enumerate(("call_nPublishDry", "call_nPublishCommit")):
        publish_input = {"dry_run": index == 0, "request_id": f"req_public_{index}"}
        cell.hook(
            "PreToolUse",
            tool_name="mcp__yoetz__publish_work",
            tool_use_id=call,
            tool_input=publish_input,
        )
        cell.advance(0.3)
        cell.hook(
            "PostToolUse",
            tool_name="mcp__yoetz__publish_work",
            tool_use_id=call,
            tool_input=publish_input,
            tool_response={"content": [{"text": "published", "type": "text"}], "isError": False},
        )
    cell.append(exec_cell_output("call_cellPublish", '{"published":2}', "2026-09-29T17:55:03.582Z"))

    # A nested apply_patch and a passing rerun in one cell.
    cell.advance(2.0)
    cell.append(
        exec_cell(
            "call_cellPatch",
            'tools.apply_patch("*** Begin Patch\\n*** End Patch");'
            'await tools.exec_command({cmd:"npm run test-type"});\n',
            "2026-09-29T17:59:00.000Z",
        )
    )
    patch = {
        "command": "*** Begin Patch\n*** Update File: src/public.ts\n@@\n-a\n+b\n*** End Patch"
    }
    cell.hook("PreToolUse", tool_name="apply_patch", tool_use_id="call_nPatch", tool_input=patch)
    cell.hook(
        "PostToolUse",
        tool_name="apply_patch",
        tool_use_id="call_nPatch",
        tool_input=patch,
        tool_response="Exit code: 0\nWall time: 0.1 seconds\nOutput:\nSuccess. Updated the following files:\nM src/public.ts\n",
    )
    cell.hook("PreToolUse", tool_name="Bash", tool_use_id="call_nRerun", tool_input=command)
    cell.advance(20.0)
    cell.append(
        command_execution("exec-42439c0d-b", "npm run test-type", 0, "2026-09-29T17:59:21.000Z")
    )
    cell.hook(
        "PostToolUse",
        tool_name="Bash",
        tool_use_id="call_nRerun",
        tool_input=command,
        tool_response=json.dumps({"chunk_id": "e1", "exit_code": 0, "output": "ok"}),
    )
    cell.append(exec_cell_output("call_cellPatch", '{"exit_code":0}', "2026-09-29T17:59:22.000Z"))

    # A routine read whose pre is flushed individually at its five-second
    # deadline (ADR-029) before the read fails.
    cell.advance(2.0)
    cell.append(
        exec_cell(
            "call_cellRead",
            'await tools.exec_command({cmd:"cat missing-public.txt"});\n',
            "2026-09-29T17:59:30.000Z",
        )
    )
    read = {"command": "cat missing-public.txt"}
    cell.hook("PreToolUse", tool_name="Bash", tool_use_id="call_nRead", tool_input=read)
    cell.advance(6.0)
    assert cell.store.flush_selected_admission(
        cell.commitment, summary_builder=build_routine_read_summary
    )
    cell.append(
        command_execution(
            "exec-42439c0d-c", "cat missing-public.txt", 1, "2026-09-29T17:59:36.000Z"
        )
    )
    cell.hook(
        "PostToolUse",
        tool_name="Bash",
        tool_use_id="call_nRead",
        tool_input=read,
        tool_response=json.dumps({"chunk_id": "f1", "exit_code": 1, "output": "No such file"}),
    )
    cell.append(exec_cell_output("call_cellRead", '{"exit_code":1}', "2026-09-29T17:59:37.000Z"))
    cell.hook("Stop", last_assistant_message="Typecheck rerun passed.", stop_hook_active=False)
    return {"shell": 3, "patch": 1, "mcp": 2, "cells": 4, "stream_items": 3}


def _facts(
    actions: list[ActionRecordedPayload],
    results: list[ResultRecordedPayload],
    evidence: list[EvidenceRecordedPayload],
) -> set[tuple[str, ...]]:
    """Every observed fact the ledger holds, without record identities.

    An ``unknown`` outcome and a digest-free ``omitted:structural`` command state
    no fact; they are identity placeholders, not observations.
    """

    facts: set[tuple[str, ...]] = set()
    for result in results:
        if result.outcome is not ResultOutcome.UNKNOWN:
            facts.add(("outcome", result.outcome.value, str(result.exit_status)))
        elif result.exit_status is not None:
            facts.add(("exit_status", str(result.exit_status)))
    for action in actions:
        if action.command is not None and action.command != "omitted:structural":
            facts.add(("command", action.command))
    for item in evidence:
        if item.content_digest is not None:
            facts.add(("content", item.content_digest))
    return facts


@pytest.mark.anyio
async def test_code_mode_replay_records_one_action_per_host_call(replay: _Replay) -> None:
    calls = _code_mode_session(replay)
    host_calls = calls["shell"] + calls["patch"] + calls["mcp"]
    recorder = _Recorder(_coordinator(replay))
    sweeper = ObservationOutboxSweeper(replay.store, recorder)
    try:
        for _ in range(8):
            summary = await sweeper.sweep()
            if summary.attempted == 0:
                break
    finally:
        sweeper.close()
    assert replay.store.list_pending_outbox_rows(replay.commitment) == ()
    assert not replay.store.list_quarantine(replay.commitment)

    actions = [cast(ActionRecordedPayload, row.payload) for row in replay.rows("action_recorded")]
    results = [cast(ResultRecordedPayload, row.payload) for row in replay.rows("result_recorded")]
    evidence = [
        cast(EvidenceRecordedPayload, row.payload) for row in replay.rows("evidence_recorded")
    ]

    # One action and one result per host call: never 2N, and no independent
    # action for any of the four code-mode cells.
    assert len(actions) == host_calls, [item.description for item in actions]
    assert len(results) == host_calls
    assert len({item.action_id for item in actions}) == host_calls
    assert {item.action_id for item in results} == {item.action_id for item in actions}
    # The deadline-flushed read is one pending action, later linked to its failure.
    pending = [item for item in actions if "pending" in item.description]
    assert pending
    linked = {item.action_id: item for item in results}
    assert all(item.action_id in linked for item in pending)

    # Hook-observed ledger events per shell command stay within the issue's bound
    # (about 7.9 before #917): the call's action, its result, evidence recorded
    # under that action, and the stream's own record of the nested command.
    command_rows = [
        row
        for row in replay.rows("action_recorded")
        if cast(ActionRecordedPayload, row.payload).action_kind is ActionKind.COMMAND
    ]
    command_actions = {cast(ActionRecordedPayload, row.payload).action_id for row in command_rows}
    command_events = {row.event_id for row in command_rows}
    command_rows += [
        row
        for row in replay.rows("result_recorded")
        if cast(ResultRecordedPayload, row.payload).action_id in command_actions
    ]
    command_rows += [
        row
        for row in replay.rows("evidence_recorded")
        if command_events.intersection(row.causal_parents)
        or cast(EvidenceRecordedPayload, row.payload).description
        == "Opaque observation kind=event_msg"
    ]
    assert len(command_actions) == calls["shell"]
    assert all(row.publication_channel is PublicationChannel.HOOK_OBSERVED for row in command_rows)
    assert len(command_rows) / calls["shell"] <= 4, len(command_rows)

    # Nested tool hooks fired for this session, so the code-mode cell wrappers
    # stay in the local store: retained, not dropped. So do the rollout's
    # completed command items (#910): each hook row states the same exit status.
    assert replay.store.codex_tool_hook_count(replay.commitment, replay.session) > 0
    wrappers = [
        envelope
        for envelope in replay.store.list_envelopes(replay.commitment)
        if envelope.source is ObservationSource.CODEX_SESSION_STREAM
        and (
            envelope.structural_payload.get("tool_name") == "exec"
            or envelope.event_kind == "item_completed"
        )
    ]
    assert len(wrappers) == 2 * calls["cells"] + calls["stream_items"]
    assert not {item.source_identity for item in wrappers} & {
        item.source_identity for item in recorder.delivered
    }

    # Delay, not drop: every fact the pre-#917 pipeline would have materialized
    # from these inputs (every delivered envelope plus every cell wrapper, each
    # as a full independent batch) is still in the ledger.
    before_actions: list[ActionRecordedPayload] = []
    before_results: list[ResultRecordedPayload] = []
    before_evidence: list[EvidenceRecordedPayload] = []
    for envelope in (*recorder.delivered, *wrappers):
        batch = materialize_observation_envelope(envelope, task_id=replay.task_id)
        for item in batch.drafts:
            payload = item.draft.payload
            if type(payload) is ActionRecordedPayload:
                before_actions.append(payload)
            elif type(payload) is ResultRecordedPayload:
                before_results.append(payload)
            elif type(payload) is EvidenceRecordedPayload:
                before_evidence.append(payload)
    before = _facts(before_actions, before_results, before_evidence)
    after = _facts(actions, results, evidence)
    assert before <= after, before - after
    # The stated exit codes are such facts: the patch's success and, since #910,
    # the typecheck's failure and its passing rerun, each recorded once.
    assert ("outcome", "success", "0") in before
    assert ("outcome", "failure", "2") in after


@pytest.mark.anyio
async def test_cell_without_tool_hooks_is_still_recorded(replay: _Replay) -> None:
    """Delay, not drop: lifecycle hooks alone do not prove a cell's nested calls were hooked.

    A cell whose nested tool fired no tool hook (an unhooked tool, an older Codex,
    a hook timeout) is the only record of that work, so its output is delivered
    and records the cell. The call stays held until the output decides the cell,
    and the delivered output keeps every fact both wrapper rows would have
    recorded.
    """

    replay.append(
        rollout_row(
            "session_meta",
            {
                "cli_version": "0.157.1",
                "cwd": str(replay.workspace),
                "history_mode": "legacy",
                "id": HOST,
                "originator": "codex_exec",
            },
            "2026-09-29T17:54:00.000Z",
        )
    )
    replay.hook("SessionStart", source="startup")
    replay.append(
        exec_cell(
            "call_cellPlan",
            'await tools.update_plan({plan:[{step:"public",status:"completed"}]});\n',
            "2026-09-29T17:54:10.000Z",
        ),
        exec_cell_output("call_cellPlan", '{"ok":true}', "2026-09-29T17:54:11.000Z"),
    )
    replay.hook("Stop", last_assistant_message="Plan updated.", stop_hook_active=False)
    assert replay.store.codex_tool_hook_count(replay.commitment, replay.session) == 0

    recorder = _Recorder(_coordinator(replay))
    sweeper = ObservationOutboxSweeper(replay.store, recorder)
    try:
        for _ in range(8):
            if (await sweeper.sweep()).attempted == 0:
                break
    finally:
        sweeper.close()
    delivered = [
        envelope
        for envelope in recorder.delivered
        if envelope.structural_payload.get("tool_name") == "exec"
    ]
    assert [item.structural_payload.get("action") for item in delivered] == [
        "custom_tool_call_output"
    ]
    actions = [cast(ActionRecordedPayload, row.payload) for row in replay.rows("action_recorded")]
    results = [cast(ResultRecordedPayload, row.payload) for row in replay.rows("result_recorded")]
    evidence = [
        cast(EvidenceRecordedPayload, row.payload) for row in replay.rows("evidence_recorded")
    ]
    assert len(actions) == 1 and len(results) == 1
    assert results[0].action_id == actions[0].action_id
    # The held call pairs the delivered output locally: no orphan is disclosed.
    assert not any(
        ObservationGapCode.UNPAIRED_EVENT.value in envelope.gap_codes
        for envelope in recorder.delivered
    )
    wrappers = [
        envelope
        for envelope in replay.store.list_envelopes(replay.commitment)
        if envelope.source is ObservationSource.CODEX_SESSION_STREAM
        and envelope.structural_payload.get("tool_name") == "exec"
    ]
    assert len(wrappers) == 2
    before_actions: list[ActionRecordedPayload] = []
    before_results: list[ResultRecordedPayload] = []
    before_evidence: list[EvidenceRecordedPayload] = []
    for envelope in wrappers:
        batch = materialize_observation_envelope(envelope, task_id=replay.task_id)
        for item in batch.drafts:
            payload = item.draft.payload
            if type(payload) is ActionRecordedPayload:
                before_actions.append(payload)
            elif type(payload) is ResultRecordedPayload:
                before_results.append(payload)
            elif type(payload) is EvidenceRecordedPayload:
                before_evidence.append(payload)
    before = _facts(before_actions, before_results, before_evidence)
    after = _facts(actions, results, evidence)
    assert before <= after, before - after
    # The cell's action and result are the ones both wrapper rows would have
    # recorded; the held call row alone contributes only content-free metadata.
    assert before_actions == actions
    assert [(item.action_id, item.outcome) for item in before_results] == [
        (item.action_id, item.outcome) for item in results
    ]
    assert all(item.content_digest is None for item in before_evidence)
    accounting = replay.store.selection_accounting(replay.commitment)
    assert accounting["intentionally_omitted_input_count"] == 0
    # The held call is retained locally without an accounting bucket (disclosed).
    assert accounting["observed_count"] == cast(int, accounting["admitted_input_count"]) + 1


@pytest.mark.anyio
async def test_unhooked_cell_after_hooked_cells_is_still_recorded(replay: _Replay) -> None:
    """A cell whose tools fire no hook keeps its record even after other cells were hooked."""

    replay.append(
        rollout_row(
            "session_meta",
            {
                "cli_version": "0.157.1",
                "cwd": str(replay.workspace),
                "history_mode": "legacy",
                "id": HOST,
                "originator": "codex_exec",
            },
            "2026-09-29T17:54:00.000Z",
        )
    )
    replay.hook("SessionStart", source="startup")
    replay.append(
        exec_cell(
            "call_cellHooked",
            'const r=await tools.exec_command({cmd:"npm run test-type"});text(r)\n',
            "2026-09-29T17:57:47.000Z",
        )
    )
    command = {"command": "npm run test-type"}
    replay.hook("PreToolUse", tool_name="Bash", tool_use_id="call_nHooked", tool_input=command)
    replay.hook(
        "PostToolUse",
        tool_name="Bash",
        tool_use_id="call_nHooked",
        tool_input=command,
        tool_response=json.dumps({"chunk_id": "a1", "exit_code": 0, "output": "ok"}),
    )
    replay.append(
        exec_cell_output("call_cellHooked", '{"exit_code":0}', "2026-09-29T17:58:12.000Z"),
        exec_cell(
            "call_cellPlan",
            'await tools.update_plan({plan:[{step:"public",status:"completed"}]});\n',
            "2026-09-29T17:58:20.000Z",
        ),
        exec_cell_output("call_cellPlan", '{"ok":true}', "2026-09-29T17:58:21.000Z"),
    )
    replay.hook("Stop", last_assistant_message="Plan updated.", stop_hook_active=False)

    recorder = _Recorder(_coordinator(replay))
    sweeper = ObservationOutboxSweeper(replay.store, recorder)
    try:
        for _ in range(8):
            if (await sweeper.sweep()).attempted == 0:
                break
    finally:
        sweeper.close()
    delivered_cells = {
        cast(str, envelope.structural_payload.get("tool_call_id"))
        for envelope in recorder.delivered
        if envelope.structural_payload.get("tool_name") == "exec"
    }
    # The hooked cell stays local; the unhooked cell reaches the ledger.
    assert delivered_cells == {"call_cellPlan"}
    actions = [cast(ActionRecordedPayload, row.payload) for row in replay.rows("action_recorded")]
    results = [cast(ResultRecordedPayload, row.payload) for row in replay.rows("result_recorded")]
    assert len(actions) == 2 and len(results) == 2
    assert {item.action_id for item in results} == {item.action_id for item in actions}
    # The held call still pairs the delivered output locally: no orphan is disclosed.
    assert not any(
        ObservationGapCode.UNPAIRED_EVENT.value in envelope.gap_codes
        for envelope in recorder.delivered
    )


def _claim_ledger(cell: _Replay) -> ObservedLedger:
    """The task ledger's observed actions/results, in order, ahead of a cooperative claim."""

    ledger = ObservedLedger()
    for row in cell.ledger._state.records:
        if type(row) is AcceptedEvent and row.schema.name in {"action_recorded", "result_recorded"}:
            ledger.append(row.schema, cast(EventPayload, row.payload), observed=True)
    return ledger


def _hooked_run(cell: _Replay, call: str, item: str, exit_code: int, timestamp: str) -> None:
    """One nested ``tools.exec_command``: its hooks and the rollout's own item for it."""

    command = {"command": "npm run test-type"}
    cell.hook("PreToolUse", tool_name="Bash", tool_use_id=call, tool_input=command)
    cell.append(command_execution(item, "npm run test-type", exit_code, timestamp))
    cell.hook(
        "PostToolUse",
        tool_name="Bash",
        tool_use_id=call,
        tool_input=command,
        tool_response=json.dumps(
            {
                "chunk_id": call[-6:],
                "exit_code": exit_code,
                "original_token_count": 12,
                "output": "public synthetic output",
                "wall_time_seconds": 2.5,
            }
        ),
    )


@pytest.mark.anyio
async def test_hook_and_stream_copies_of_one_command_are_one_run(replay: _Replay) -> None:
    """#910 with #917: the rollout's copy of a hooked call adds no second action or finding.

    A red-latest claim names the one observed run exactly once; a passing rerun, seen by both
    paths, leaves the claim clean.
    """

    session_start(replay)
    _hooked_run(replay, "call_red", "exec-910-red", 2, "2026-09-29T17:58:10.000Z")
    recorder = await sweep_all(replay)
    actions = [cast(ActionRecordedPayload, row.payload) for row in replay.rows("action_recorded")]
    results = [cast(ResultRecordedPayload, row.payload) for row in replay.rows("result_recorded")]
    assert len(actions) == 1 and len(results) == 1
    assert (results[0].outcome, results[0].exit_status) == (ResultOutcome.FAILURE, 2)
    assert actions[0].command is not None and actions[0].command.startswith("omitted:hmac-")
    held = [
        envelope
        for envelope in replay.store.list_envelopes(replay.commitment)
        if envelope.event_kind == "item_completed"
    ]
    assert len(held) == 1
    # The action's command field is the whole-command commitment, then (for a composed command or
    # a simple one with arguments) its composition and segment commitments (#977, ADR-045): the
    # rollout copy holds the whole-command commitment, which is the field's first word.
    assert (
        held[0].structural_payload["command_commitment"]
        == (actions[0].command.removeprefix("omitted:").split(" ", 1)[0])
    )
    assert held[0].source_identity not in {item.source_identity for item in recorder.delivered}
    accounting = replay.store.selection_accounting(replay.commitment)
    assert accounting["intentionally_omitted_input_count"] == 0

    red_latest = _claim_ledger(replay)
    red_latest.claim()
    assert omitted_results(red_latest) == (results[0].result_id,)

    _hooked_run(replay, "call_green", "exec-910-green", 0, "2026-09-29T17:59:10.000Z")
    await sweep_all(replay)
    assert len(replay.rows("result_recorded")) == 2
    green = _claim_ledger(replay)
    green.claim(versioned=True)
    assert omissions(green) == ()


@pytest.mark.anyio
async def test_stream_only_command_items_are_recorded_with_outcomes(replay: _Replay) -> None:
    """Without tool hooks the rollout items are the only record, so they are delivered."""

    session_start(replay)
    replay.append(
        command_execution("exec-910-a", "npm run test-type", 2, "2026-09-29T17:58:10.000Z"),
        command_execution("exec-910-b", "npm run  test-type", 0, "2026-09-29T17:59:10.000Z"),
    )
    replay.hook("Stop", last_assistant_message="Done.", stop_hook_active=False)
    assert replay.store.codex_tool_hook_count(replay.commitment, replay.session) == 0
    await sweep_all(replay)
    actions = [cast(ActionRecordedPayload, row.payload) for row in replay.rows("action_recorded")]
    results = [cast(ResultRecordedPayload, row.payload) for row in replay.rows("result_recorded")]
    assert [(item.outcome, item.exit_status) for item in results] == [
        (ResultOutcome.FAILURE, 2),
        (ResultOutcome.SUCCESS, 0),
    ]
    assert len({item.command for item in actions}) == 1
    ledger = _claim_ledger(replay)
    ledger.claim(versioned=True)
    assert omissions(ledger) == ()


@pytest.mark.anyio
async def test_held_item_corrects_an_outcome_less_hook_result_when_ids_join(
    replay: _Replay,
) -> None:
    """ADR-022 decision 15 on the real reader path: the gate never holds the only outcome."""

    session_start(replay)
    running_run(replay, "call_join")
    replay.append(command_execution("call_join", "cargo test", 101, "2026-09-29T18:00:10.000Z"))
    replay.hook("Stop", last_assistant_message="Tests pass.", stop_hook_active=False)
    await sweep_all(replay)
    actions = replay.rows("action_recorded")
    results = [cast(ResultRecordedPayload, row.payload) for row in replay.rows("result_recorded")]
    assert len(actions) == 1
    assert [(item.outcome, item.exit_status) for item in results] == [
        (ResultOutcome.UNKNOWN, None),  # the hook row is never rewritten
        (ResultOutcome.FAILURE, 101),  # the appended correction
    ]


@pytest.mark.anyio
async def test_still_running_hook_result_is_completed_from_the_rollout(replay: _Replay) -> None:
    """Delay, not drop: an exit the hook never saw reaches the ledger from the rollout item."""

    session_start(replay)
    running_run(replay, "call_long")
    replay.append(command_execution("exec-910-long", "cargo test", 101, "2026-09-29T18:00:10.000Z"))
    replay.hook("Stop", last_assistant_message="Tests pass.", stop_hook_active=False)
    await sweep_all(replay)
    results = [cast(ResultRecordedPayload, row.payload) for row in replay.rows("result_recorded")]
    assert (ResultOutcome.FAILURE, 101) in [(item.outcome, item.exit_status) for item in results]


@pytest.mark.anyio
async def test_stream_only_patch_item_does_not_retire_a_failure(replay: _Replay) -> None:
    """A rollout ``FileChange`` is an edit, but #909 still requires a covering rerun."""

    session_start(replay)
    replay.append(
        command_execution("exec-910-red", "npm run test-type", 2, "2026-09-29T17:58:10.000Z"),
        rollout_row(
            "event_msg",
            {
                "completed_at_ms": 1_790_704_700_000,
                "item": {
                    "changes": [{"kind": "update", "path": "src/public.ts"}],
                    "id": "call_910_patch_item",
                    "status": "completed",
                    "stderr": "",
                    "stdout": "",
                    "type": "FileChange",
                },
                "started_at_ms": 1_790_704_699_000,
                "thread_id": HOST,
                "turn_id": "turn_1",
                "type": "item_completed",
            },
            "2026-09-29T17:58:20.000Z",
        ),
    )
    replay.hook("Stop", last_assistant_message="Fixed.", stop_hook_active=False)
    assert replay.store.codex_tool_hook_count(replay.commitment, replay.session) == 0
    await sweep_all(replay)
    kinds = [
        cast(ActionRecordedPayload, row.payload).action_kind
        for row in replay.rows("action_recorded")
    ]
    assert kinds == [ActionKind.COMMAND, ActionKind.EDIT]
    ledger = _claim_ledger(replay)
    failed_result = next(
        cast(ResultRecordedPayload, row.payload).result_id
        for row in replay.rows("result_recorded")
        if cast(ResultRecordedPayload, row.payload).outcome is ResultOutcome.FAILURE
    )
    ledger.claim(versioned=True, limitations=(failed_result,))
    assert omissions(ledger) == ()
    assert "hook-observed failing" in receipt_limitations(ledger)


@pytest.mark.anyio
@pytest.mark.parametrize("first_exit", [101, 0])
async def test_same_command_calls_each_keep_their_only_exit(
    replay: _Replay, first_exit: int
) -> None:
    """One call's stated outcome never withholds another same-command call's only exit (#910).

    The first ``cargo test`` outlives its yield window, so its hook states no exit; the second
    states exit 0. The second's rollout copy stays local, and the first's rollout item, under an
    id that joins neither hook call, is delivered as the first call's only exit.
    """

    session_start(replay)
    running_run(replay, "call_first")
    command = {"command": "cargo test"}
    replay.hook("PreToolUse", tool_name="Bash", tool_use_id="call_second", tool_input=command)
    replay.append(command_execution("exec-910-second", "cargo test", 0, "2026-09-29T18:00:05.000Z"))
    replay.hook(
        "PostToolUse",
        tool_name="Bash",
        tool_use_id="call_second",
        tool_input=command,
        tool_response=json.dumps(
            {
                "chunk_id": "second",
                "exit_code": 0,
                "original_token_count": 4,
                "output": "public synthetic output",
                "wall_time_seconds": 3.0,
            }
        ),
    )
    replay.append(
        command_execution("exec-910-first", "cargo test", first_exit, "2026-09-29T18:00:10.000Z")
    )
    replay.hook("Stop", last_assistant_message="Tests pass.", stop_hook_active=False)
    recorder = await sweep_all(replay)
    results = [cast(ResultRecordedPayload, row.payload) for row in replay.rows("result_recorded")]
    facts = sorted(((item.outcome.value, item.exit_status) for item in results), key=repr)
    expected_stream = (
        ResultOutcome.FAILURE.value if first_exit else ResultOutcome.SUCCESS.value,
        first_exit,
    )
    # The first call's hook row (unknown), the second's stated exit, and the first's exit from
    # its rollout item: each exactly once.
    assert facts == sorted(
        [(ResultOutcome.UNKNOWN.value, None), (ResultOutcome.SUCCESS.value, 0), expected_stream],
        key=repr,
    )
    delivered_items = [
        cast(str, envelope.structural_payload.get("tool_call_id"))
        for envelope in recorder.delivered
        if envelope.event_kind == "item_completed"
    ]
    assert len(delivered_items) == 1


def _interleaved_pre(cell: _Replay) -> None:
    """Another hooked call starts while the first is in flight; its hook reconciles the rollout."""

    cell.hook(
        "PreToolUse",
        tool_name="Bash",
        tool_use_id="call_parallel",
        tool_input={"command": "git status"},
    )


def _interleaved_post(cell: _Replay) -> None:
    cell.hook(
        "PostToolUse",
        tool_name="Bash",
        tool_use_id="call_parallel",
        tool_input={"command": "git status"},
        tool_response=json.dumps(
            {
                "chunk_id": "paral",
                "exit_code": 0,
                "original_token_count": 1,
                "output": "public synthetic output",
                "wall_time_seconds": 0.1,
            }
        ),
    )


@pytest.mark.anyio
@pytest.mark.parametrize("later_row", [False, True])
@pytest.mark.parametrize("item_id", ["call_before_post", "exec-910-before-post"])
async def test_item_read_before_its_outcome_less_post_is_released_once(
    replay: _Replay, item_id: str, later_row: bool
) -> None:
    """#910: a rollout item read ahead of its hook post is decided when that post lands.

    The completed ``CommandExecution`` (exit 101) is read by another call's hook before this
    call's ``PostToolUse`` is stored; the post then states no exit. The item is the only carrier
    of the call's outcome, so it reaches the ledger exactly once, although the stream cursor
    already moved past it and a later stream row may already have reached the task.
    """

    session_start(replay)
    command = {"command": "cargo test"}
    replay.hook("PreToolUse", tool_name="Bash", tool_use_id="call_before_post", tool_input=command)
    replay.append(command_execution(item_id, "cargo test", 101, "2026-09-29T18:00:10.000Z"))
    if later_row:
        # A stream-only tool row after the item, delivered before the item is decided.
        replay.append(
            rollout_row(
                "response_item",
                {
                    "arguments": json.dumps({"command": ["ls"]}),
                    "call_id": "call_stream_only",
                    "name": "shell",
                    "type": "function_call",
                },
                "2026-09-29T18:00:11.000Z",
            ),
            rollout_row(
                "response_item",
                {"call_id": "call_stream_only", "output": "x", "type": "function_call_output"},
                "2026-09-29T18:00:12.000Z",
            ),
        )
    _interleaved_pre(replay)
    if later_row:
        await sweep_all(replay)
    replay.hook(
        "PostToolUse",
        tool_name="Bash",
        tool_use_id="call_before_post",
        tool_input=command,
        tool_response=json.dumps(
            {
                "chunk_id": "before",
                "original_token_count": 0,
                "output": "public synthetic output",
                "session_id": 3,
                "wall_time_seconds": 10.0,
            }
        ),
    )
    _interleaved_post(replay)
    replay.hook("Stop", last_assistant_message="Tests pass.", stop_hook_active=False)
    recorder = await sweep_all(replay)
    replay.hook("Stop", last_assistant_message="Tests pass.", stop_hook_active=False)
    recorder_again = await sweep_all(replay)
    results = [cast(ResultRecordedPayload, row.payload) for row in replay.rows("result_recorded")]
    facts = [(item.outcome, item.exit_status) for item in results]
    assert facts.count((ResultOutcome.FAILURE, 101)) == 1
    assert (ResultOutcome.UNKNOWN, None) in facts
    delivered_items = [
        envelope
        for envelope in (*recorder.delivered, *recorder_again.delivered)
        if envelope.event_kind == "item_completed"
    ]
    assert len(delivered_items) == 1
    assert replay.store.pending_rollout_items(replay.commitment, replay.session) == ()
    # The released failure reaches the claim check: a completion claim names it.
    failed = next(item.result_id for item in results if item.exit_status == 101)
    ledger = _claim_ledger(replay)
    ledger.claim()
    assert failed in omitted_results(ledger)


@pytest.mark.anyio
async def test_item_read_before_its_stated_post_stays_one_run(replay: _Replay) -> None:
    """The ordinary copy read ahead of its post settles as that post's copy, never delivered."""

    session_start(replay)
    command = {"command": "npm run test-type"}
    replay.hook("PreToolUse", tool_name="Bash", tool_use_id="call_red", tool_input=command)
    replay.append(
        command_execution("exec-910-red", "npm run test-type", 2, "2026-09-29T17:58:10.000Z")
    )
    _interleaved_pre(replay)
    assert len(replay.store.pending_rollout_items(replay.commitment, replay.session)) == 1
    replay.hook(
        "PostToolUse",
        tool_name="Bash",
        tool_use_id="call_red",
        tool_input=command,
        tool_response=json.dumps(
            {
                "chunk_id": "redred",
                "exit_code": 2,
                "original_token_count": 12,
                "output": "public synthetic output",
                "wall_time_seconds": 2.5,
            }
        ),
    )
    _interleaved_post(replay)
    replay.hook("Stop", last_assistant_message="Done.", stop_hook_active=False)
    recorder = await sweep_all(replay)
    results = [cast(ResultRecordedPayload, row.payload) for row in replay.rows("result_recorded")]
    assert [(item.outcome, item.exit_status) for item in results].count(
        (ResultOutcome.FAILURE, 2)
    ) == 1
    assert not any(envelope.event_kind == "item_completed" for envelope in recorder.delivered)
    assert replay.store.pending_rollout_items(replay.commitment, replay.session) == ()


def _post(cell: _Replay, call: str, command: str, exit_code: int | None) -> None:
    response: dict[str, Any] = {
        "chunk_id": call[-6:],
        "original_token_count": 1,
        "output": "public synthetic output",
        "wall_time_seconds": 1.0,
    }
    if exit_code is None:
        response["session_id"] = 3
    else:
        response["exit_code"] = exit_code
    cell.hook(
        "PostToolUse",
        tool_name="Bash",
        tool_use_id=call,
        tool_input={"command": command},
        tool_response=json.dumps(response),
    )


@pytest.mark.anyio
@pytest.mark.parametrize("b_item_first", [True, False])
@pytest.mark.parametrize("items_first", [True, False])
async def test_parallel_same_command_runs_keep_each_outcome(
    replay: _Replay, items_first: bool, b_item_first: bool
) -> None:
    """#910: two parallel ``cargo test`` runs never trade outcomes, whatever the arrival order.

    A still runs when its hook fires (no exit) and its rollout item later records exit 1; B
    finishes first with exit 0, stated by its hook. B's item is B's copy and A's item is A's only
    exit, whether the items are read before or after the posts, and in either item order.
    """

    session_start(replay)
    command = {"command": "cargo test"}
    replay.hook("PreToolUse", tool_name="Bash", tool_use_id="call_run_a", tool_input=command)
    replay.hook("PreToolUse", tool_name="Bash", tool_use_id="call_run_b", tool_input=command)
    item_a = command_execution("exec-910-run-a", "cargo test", 1, "2026-09-29T18:00:20.000Z")
    item_b = command_execution("exec-910-run-b", "cargo test", 0, "2026-09-29T18:00:10.000Z")
    items = (item_b, item_a) if b_item_first else (item_a, item_b)
    if items_first:
        replay.append(*items)
        _interleaved_pre(replay)
        assert len(replay.store.pending_rollout_items(replay.commitment, replay.session)) == 2
    _post(replay, "call_run_a", "cargo test", None)
    _post(replay, "call_run_b", "cargo test", 0)
    if not items_first:
        replay.append(*items)
        _interleaved_pre(replay)
    _interleaved_post(replay)
    replay.hook("Stop", last_assistant_message="Tests pass.", stop_hook_active=False)
    recorder = await sweep_all(replay)
    results = [cast(ResultRecordedPayload, row.payload) for row in replay.rows("result_recorded")]
    facts = [(item.outcome, item.exit_status) for item in results]
    assert facts.count((ResultOutcome.FAILURE, 1)) == 1
    # B's pass once (its hook, plus the interleaved git status), A's hook unknown once.
    assert facts.count((ResultOutcome.SUCCESS, 0)) == 2
    assert facts.count((ResultOutcome.UNKNOWN, None)) == 1
    delivered = [
        envelope.structural_payload.get("exit_status")
        for envelope in recorder.delivered
        if envelope.event_kind == "item_completed"
    ]
    assert delivered == [1]
    assert replay.store.pending_rollout_items(replay.commitment, replay.session) == ()


def _unpaired_evidence(cell: _Replay) -> list[str | None]:
    return [
        cast(EvidenceRecordedPayload, row.payload).description
        for row in cell.rows("evidence_recorded")
        if (cast(EvidenceRecordedPayload, row.payload).description or "").startswith("Unpaired")
    ]


def _unpaired_items(recorder: _Recorder) -> list[object]:
    return [
        envelope.structural_payload.get("exit_status")
        for envelope in recorder.delivered
        if envelope.event_kind == "item_completed"
        and ObservationGapCode.UNPAIRED_EVENT.value in envelope.gap_codes
    ]


@pytest.mark.anyio
async def test_pending_item_evicted_from_the_envelope_ring_is_delivered_unpaired(
    replay: _Replay, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#910: a held item the local ring forgets before it is paired is disclosed, not dropped.

    It is delivered with ``unpaired_event``: the receipt names the unproven pairing, and the
    exit stays visible as unpaired evidence.
    """

    from yoetz.adapters.integrations import observation_local

    session_start(replay)
    command = {"command": "cargo test"}
    replay.hook("PreToolUse", tool_name="Bash", tool_use_id="call_evicted", tool_input=command)
    replay.append(
        command_execution("exec-910-evicted", "cargo test", 101, "2026-09-29T18:00:10.000Z")
    )
    _interleaved_pre(replay)
    assert len(replay.store.pending_rollout_items(replay.commitment, replay.session)) == 1
    monkeypatch.setattr(observation_local, "_MAX_ENVELOPES", 6)
    for index in range(4):
        call = f"call_flood_{index}"
        replay.hook(
            "PreToolUse", tool_name="Bash", tool_use_id=call, tool_input={"command": "git log"}
        )
        _post(replay, call, "git log", 0)
    assert not any(
        envelope.event_kind == "item_completed"
        for envelope in replay.store.list_envelopes(replay.commitment)
    )
    replay.hook("Stop", last_assistant_message="Tests pass.", stop_hook_active=False)
    recorder = await sweep_all(replay)
    # Its pairing is unproven, so it is unpaired evidence, not an attributed run.
    assert _unpaired_evidence(replay) == ["Unpaired observed tool result exit=101"]
    assert _unpaired_items(recorder) == [101]
    assert replay.store.pending_rollout_items(replay.commitment, replay.session) == ()


@pytest.mark.anyio
async def test_pending_items_over_the_bound_are_delivered_unpaired(
    replay: _Replay, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#910: the bounded pending account delivers its oldest item instead of dropping it."""

    from yoetz.adapters.integrations import codex_session_stream

    monkeypatch.setattr(codex_session_stream, "MAX_PENDING_ROLLOUT_ITEMS", 1, raising=False)
    session_start(replay)
    replay.hook(
        "PreToolUse", tool_name="Bash", tool_use_id="call_old", tool_input={"command": "make"}
    )
    replay.hook(
        "PreToolUse", tool_name="Bash", tool_use_id="call_new", tool_input={"command": "cargo test"}
    )
    replay.append(
        command_execution("exec-910-old", "make", 2, "2026-09-29T18:00:10.000Z"),
        command_execution("exec-910-new", "cargo test", 0, "2026-09-29T18:00:11.000Z"),
    )
    _interleaved_pre(replay)
    # The next reconcile finds two undecided items over a bound of one.
    _interleaved_post(replay)
    assert len(replay.store.pending_rollout_items(replay.commitment)) == 1
    _post(replay, "call_old", "make", 2)
    _post(replay, "call_new", "cargo test", 0)
    replay.hook("Stop", last_assistant_message="Done.", stop_hook_active=False)
    recorder = await sweep_all(replay)
    assert _unpaired_items(recorder) == [2]
    assert _unpaired_evidence(replay) == ["Unpaired observed tool result exit=2"]
    assert replay.store.pending_rollout_items(replay.commitment) == ()


def _flood_until_items_are_oldest(cell: _Replay, monkeypatch: pytest.MonkeyPatch) -> None:
    """Evict the ring's oldest rows, one per new hook row, until a rollout item is the oldest."""

    from yoetz.adapters.integrations import observation_local

    capacity = observation_local._MAX_ENVELOPES
    monkeypatch.setattr(observation_local, "_MAX_ENVELOPES", 1)
    for index in range(64):
        if cell.store.list_envelopes(cell.commitment)[0].event_kind == "item_completed":
            # Later rows no longer evict anything.
            monkeypatch.setattr(observation_local, "_MAX_ENVELOPES", capacity)
            return
        call = f"call_flood_{index // 2}"
        if index % 2 == 0:
            cell.hook(
                "PreToolUse", tool_name="Bash", tool_use_id=call, tool_input={"command": "git log"}
            )
        else:
            _post(cell, call, "git log", 0)
    raise AssertionError("the ring never reached the rollout items")


def _disclosed_failure(cell: _Replay, exit_status: int) -> bool:
    """The failure reached the ledger, as a result or as unpaired evidence with its gap."""

    results = [cast(ResultRecordedPayload, row.payload) for row in cell.rows("result_recorded")]
    if any(
        item.outcome is ResultOutcome.FAILURE and item.exit_status == exit_status
        for item in results
    ):
        return True
    return any(
        cast(EvidenceRecordedPayload, row.payload).description
        == f"Unpaired observed tool result exit={exit_status}"
        and ObservationGapCode.UNPAIRED_EVENT.value in row.coverage.known_gaps
        for row in cell.rows("evidence_recorded")
    )


def _hook_rows(cell: _Replay, event: str, call: str) -> list[ObservationEnvelope]:
    return [
        envelope
        for envelope in cell.store.list_envelopes(cell.commitment)
        if envelope.event_kind == event and envelope.structural_payload.get("tool_call_id") == call
    ]


@pytest.mark.anyio
@pytest.mark.parametrize("b_item_first", [True, False])
async def test_item_whose_owed_post_left_the_ring_is_disclosed_not_dropped(
    replay: _Replay, monkeypatch: pytest.MonkeyPatch, b_item_first: bool
) -> None:
    """#910: the turn's end settles an item as a copy only with a stored proof.

    A's outcome-less post leaves the ring while A's exit-1 item waits behind the still-open B.
    B's stated post then proves only B's item; A's item is delivered as unpaired evidence.
    """

    session_start(replay)
    command = {"command": "cargo test"}
    replay.hook("PreToolUse", tool_name="Bash", tool_use_id="call_run_a", tool_input=command)
    replay.hook("PreToolUse", tool_name="Bash", tool_use_id="call_run_b", tool_input=command)
    _post(replay, "call_run_a", "cargo test", None)
    item_a = command_execution("exec-910-run-a", "cargo test", 1, "2026-09-29T18:00:20.000Z")
    item_b = command_execution("exec-910-run-b", "cargo test", 0, "2026-09-29T18:00:10.000Z")
    replay.append(*((item_b, item_a) if b_item_first else (item_a, item_b)))
    _interleaved_pre(replay)
    assert len(replay.store.pending_rollout_items(replay.commitment, replay.session)) == 2
    _flood_until_items_are_oldest(replay, monkeypatch)
    assert _hook_rows(replay, "PostToolUse", "call_run_a") == []
    _post(replay, "call_run_b", "cargo test", 0)
    replay.hook("Stop", last_assistant_message="Tests pass.", stop_hook_active=False)
    await sweep_all(replay)
    assert _disclosed_failure(replay, 1)
    assert replay.store.pending_rollout_items(replay.commitment) == ()


@pytest.mark.anyio
async def test_item_whose_post_follows_the_turn_end_is_disclosed_not_dropped(
    replay: _Replay,
) -> None:
    """#910: Stop stored before the call's post leaves no proof of copy; the exit is disclosed."""

    session_start(replay)
    command = {"command": "cargo test"}
    replay.hook("PreToolUse", tool_name="Bash", tool_use_id="call_late", tool_input=command)
    replay.append(command_execution("exec-910-late", "cargo test", 1, "2026-09-29T18:00:10.000Z"))
    _interleaved_pre(replay)
    replay.hook("Stop", last_assistant_message="Tests pass.", stop_hook_active=False)
    _post(replay, "call_late", "cargo test", None)
    await sweep_all(replay)
    assert _disclosed_failure(replay, 1)
    assert replay.store.pending_rollout_items(replay.commitment) == ()


@pytest.mark.anyio
async def test_evicted_pre_of_a_parallel_run_keeps_it_open(
    replay: _Replay, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#910: a parallel run whose ``PreToolUse`` left the ring is still open to the pairing.

    B's exit-0 item is read first; both ``PreToolUse`` rows are then evicted. A's outcome-less
    post must not take B's item as A's exit, and A's exit-1 item must reach the ledger.
    """

    session_start(replay)
    command = {"command": "cargo test"}
    replay.hook("PreToolUse", tool_name="Bash", tool_use_id="call_run_a", tool_input=command)
    replay.hook("PreToolUse", tool_name="Bash", tool_use_id="call_run_b", tool_input=command)
    replay.append(command_execution("exec-910-run-b", "cargo test", 0, "2026-09-29T18:00:10.000Z"))
    _interleaved_pre(replay)
    _flood_until_items_are_oldest(replay, monkeypatch)
    assert _hook_rows(replay, "PreToolUse", "call_run_a") == []
    assert _hook_rows(replay, "PreToolUse", "call_run_b") == []
    _post(replay, "call_run_a", "cargo test", None)
    replay.append(command_execution("exec-910-run-a", "cargo test", 1, "2026-09-29T18:00:20.000Z"))
    _post(replay, "call_run_b", "cargo test", 0)
    replay.hook("Stop", last_assistant_message="Tests pass.", stop_hook_active=False)
    recorder = await sweep_all(replay)
    assert _disclosed_failure(replay, 1)
    delivered = [
        envelope.structural_payload.get("exit_status")
        for envelope in recorder.delivered
        if envelope.event_kind == "item_completed"
    ]
    # B's item is B's copy; only A's exit is delivered.
    assert delivered == [1]
    assert replay.store.pending_rollout_items(replay.commitment) == ()
    # The turn's end forgets the session's calls kept open past the ring.
    assert replay.store.evicted_open_calls(replay.commitment, replay.session) == ()


@pytest.mark.anyio
async def test_item_of_a_silent_session_is_released_after_idle_reconciles(
    replay: _Replay,
) -> None:
    """#910: a carrier waiting behind a call that never finishes is released by an age bound."""

    from yoetz.adapters.integrations.codex_session_stream import (
        PENDING_ROLLOUT_IDLE_RECONCILES,
        CodexSessionStreamLocator,
        reconcile_session_stream,
    )

    session_start(replay)
    command = {"command": "cargo test"}
    replay.hook("PreToolUse", tool_name="Bash", tool_use_id="call_run_a", tool_input=command)
    replay.hook("PreToolUse", tool_name="Bash", tool_use_id="call_run_b", tool_input=command)
    replay.append(command_execution("exec-910-run-a", "cargo test", 1, "2026-09-29T18:00:20.000Z"))
    _post(replay, "call_run_a", "cargo test", None)
    # B never finishes and the session stores nothing more: a crash.
    assert len(replay.store.pending_rollout_items(replay.commitment)) == 1

    def reconcile() -> None:
        reconcile_session_stream(
            replay.store,
            workspace_commitment=replay.commitment,
            session_commitment=replay.session,
            codex_session_id=HOST,
            locator=CodexSessionStreamLocator(replay.rollout.parents[4]),
        )

    for _ in range(PENDING_ROLLOUT_IDLE_RECONCILES):
        reconcile()
    assert len(replay.store.pending_rollout_items(replay.commitment)) == 1
    reconcile()
    assert replay.store.pending_rollout_items(replay.commitment) == ()
    await sweep_all(replay)
    assert _disclosed_failure(replay, 1)


@pytest.mark.anyio
async def test_concurrent_pre_and_post_deliveries_record_one_action(
    replay: _Replay, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The action-link read and its append are one step under the coordinator lock (#917).

    The pre and the post of one call are delivered concurrently. The first
    delivery pauses after its existence read and before its append; the second
    must still observe the action the first appended, never an empty read
    beside it.
    """

    replay.append(
        rollout_row(
            "session_meta",
            {
                "cli_version": "0.157.1",
                "cwd": str(replay.workspace),
                "history_mode": "legacy",
                "id": HOST,
                "originator": "codex_exec",
            },
            "2026-09-29T17:54:00.000Z",
        )
    )
    command = {"command": "npm run test-type"}
    replay.hook("PreToolUse", tool_name="Bash", tool_use_id="call_nRace", tool_input=command)
    replay.advance(6.0)
    assert replay.store.flush_selected_admission(
        replay.commitment, summary_builder=build_routine_read_summary
    )
    replay.hook(
        "PostToolUse",
        tool_name="Bash",
        tool_use_id="call_nRace",
        tool_input=command,
        tool_response=json.dumps({"chunk_id": "r1", "exit_code": 0, "output": "ok"}),
    )
    rows = [
        row
        for row in replay.store.list_pending_outbox_rows(replay.commitment)
        if row.envelope.source is ObservationSource.CODEX_HOOK
        and row.envelope.event_kind in {"PreToolUse", "PostToolUse"}
    ]
    assert sorted(row.envelope.event_kind for row in rows) == ["PostToolUse", "PreToolUse"]

    class _ObservedLock(asyncio.Lock):
        """The coordinator lock, noting when a second delivery waits on it."""

        def __init__(self) -> None:
            super().__init__()
            self.contended = asyncio.Event()

        async def acquire(self) -> Literal[True]:
            if self.locked():
                self.contended.set()
            return await super().acquire()

    coordinator = _coordinator(replay)
    lock = _ObservedLock()
    monkeypatch.setattr(coordinator, "_lock", lock)
    lookups: list[str | None] = []
    entered: list[str] = []
    second_lookup = asyncio.Event()
    original = replay.ledger.projected_action_event

    async def _racing_lookup(action_id: str) -> str | None:
        entered.append(action_id)
        found = await original(action_id)
        lookups.append(found)
        if len(entered) > 1:
            second_lookup.set()
        else:
            # Hold the first delivery between its existence read and its append
            # until the other delivery has either made its own read (the
            # check-then-append race) or is waiting on the coordinator lock.
            waiters = [
                asyncio.ensure_future(lock.contended.wait()),
                asyncio.ensure_future(second_lookup.wait()),
            ]
            done, pending = await asyncio.wait(
                waiters, timeout=10.0, return_when=asyncio.FIRST_COMPLETED
            )
            for waiter in pending:
                waiter.cancel()
            assert done, "the second delivery never reached the action-link window"
        return found

    monkeypatch.setattr(replay.ledger, "projected_action_event", _racing_lookup)
    requests = {
        row.envelope.event_kind: ObservationIngestRequest(
            codex_session_id=row.codex_session_id, envelope=row.envelope
        )
        for row in rows
    }
    # The pre takes the coordinator lock first, as the ordered drain delivers
    # it; the post is then delivered while the pre is still in flight.
    first = asyncio.ensure_future(coordinator.ingest_request(requests["PreToolUse"]))
    deadline = asyncio.get_running_loop().time() + 10.0
    while not lock.locked():
        assert not first.done(), "the pre finished before it was observed holding the lock"
        assert asyncio.get_running_loop().time() < deadline
        await asyncio.sleep(0.001)
    second = asyncio.ensure_future(coordinator.ingest_request(requests["PostToolUse"]))
    results = await asyncio.gather(first, second)
    assert [item.disposition.value for item in results] == ["accepted", "accepted"]
    assert not replay.store.list_quarantine(replay.commitment)
    actions = [cast(ActionRecordedPayload, row.payload) for row in replay.rows("action_recorded")]
    results_recorded = [
        cast(ResultRecordedPayload, row.payload) for row in replay.rows("result_recorded")
    ]
    assert len(actions) == 1, [item.description for item in actions]
    assert len(results_recorded) == 1
    assert results_recorded[0].action_id == actions[0].action_id
    # The other delivery waited on the lock while the first read was open, and
    # its own read then saw the action the first delivery committed.
    assert lock.contended.is_set()
    assert len(lookups) == 2 and lookups[0] is None and lookups[1] is not None


@pytest.mark.anyio
async def test_compaction_keeps_folding_stream_outcomes_into_hook_calls(
    replay: _Replay,
) -> None:
    """#1019 (tb4n2 N-1, pretrain D): a post-compaction outcome still corrects its hook call.

    Before the fix every shell call after the compact start became two actions: the hook's
    ``Bash`` row with an unknown outcome and a separate stream ``CommandExecution`` action.
    """

    session_start(replay)
    running_run(replay, "call_before")
    replay.append(command_execution("call_before", "cargo test", 101, "2026-09-29T18:00:10.000Z"))
    await sweep_all(replay)
    compact(replay)
    hook_generation = replay.store.current_session_generation(replay.commitment, replay.session)
    assert hook_generation == 2
    running_run(replay, "call_after")
    replay.append(command_execution("call_after", "cargo test", 0, "2026-09-29T18:05:10.000Z"))
    replay.hook("Stop", last_assistant_message="Tests pass.", stop_hook_active=False)
    await sweep_all(replay)
    actions = [cast(ActionRecordedPayload, row.payload) for row in replay.rows("action_recorded")]
    results = [cast(ResultRecordedPayload, row.payload) for row in replay.rows("result_recorded")]
    assert len(actions) == 2
    assert all(item.action_kind is ActionKind.COMMAND for item in actions)
    by_action: dict[str, list[tuple[ResultOutcome, int | None]]] = {}
    for item in results:
        by_action.setdefault(str(item.action_id), []).append((item.outcome, item.exit_status))
    assert sorted(by_action.values(), key=repr) == sorted(
        [
            [(ResultOutcome.UNKNOWN, None), (ResultOutcome.FAILURE, 101)],
            [(ResultOutcome.UNKNOWN, None), (ResultOutcome.SUCCESS, 0)],
        ],
        key=repr,
    )
    # Every unknown hook row is superseded by its stream outcome: none stays unknown alone.
    assert all(
        any(outcome is not ResultOutcome.UNKNOWN for outcome, _ in facts)
        for facts in by_action.values()
    )
    # A replay of the whole outbox is idempotent: no second action, no second correction.
    await sweep_all(replay)
    assert len(replay.rows("action_recorded")) == 2
    assert len(replay.rows("result_recorded")) == 4


@pytest.mark.anyio
@pytest.mark.parametrize("mismatch", ["call_id", "command"])
async def test_compaction_alias_never_folds_a_different_call_or_command(
    replay: _Replay, mismatch: str
) -> None:
    """#1019 guard: a different call id or command commitment never corrects the hook call."""

    session_start(replay)
    compact(replay)
    running_run(replay, "call_after")
    item = "call_other" if mismatch == "call_id" else "call_after"
    command = "cargo test" if mismatch == "call_id" else "cargo build"
    replay.append(command_execution(item, command, 0, "2026-09-29T18:05:10.000Z"))
    replay.hook("Stop", last_assistant_message="Tests pass.", stop_hook_active=False)
    await sweep_all(replay)
    actions = [cast(ActionRecordedPayload, row.payload) for row in replay.rows("action_recorded")]
    results = [cast(ResultRecordedPayload, row.payload) for row in replay.rows("result_recorded")]
    hook_action = next(item.action_id for item in actions if "Codex hook" in item.description)
    hook_facts = [
        (item.outcome, item.exit_status) for item in results if item.action_id == hook_action
    ]
    # The hook call keeps its unknown outcome; the success belongs to another action.
    assert hook_facts == [(ResultOutcome.UNKNOWN, None)]
    assert len(actions) == 2
    assert (ResultOutcome.SUCCESS, 0) in [(item.outcome, item.exit_status) for item in results]
