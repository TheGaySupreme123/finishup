"""Replay a recorded Codex rollout through hooks, stream reader, coordinator and ledger (#1027).

A real Codex session leaves one rollout file. This module rebuilds the hooks Codex fired around
each nested tool item the way Codex fires them (a ``PreToolUse`` before the item is written, the
item, a ``PostToolUse`` after it; the consecutive items of one code-mode cell are one parallel
batch), the compaction hooks around a ``compacted`` record (``PreCompact``, then ``PostCompact``
and ``SessionStart`` with source ``compact``), and ``Stop`` / ``SessionEnd`` at the end. Every hook
goes through ``observe_hooks.handle_observe`` (real local store, real stream reader, real
admission), every outbox row through the real sweeper and the real
:class:`ObservationCoordinator` into a task ledger (``builders.codex_replay``).

Used by the conformance test over a recorded rollout slice and by the tb4n3 N3-7 replay script
(``fix_n3/scratch_LC/replay_compaction.py``) over full recorded attempts, so both drive the same
code.
"""

from __future__ import annotations

import collections
import datetime as dt
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, cast

from builders.codex_replay import HOST, Recorder, Replay, build_coordinator
from yoetz.application.observation_drain import ObservationOutboxSweeper
from yoetz.domain.events import (
    ActionKind,
    ActionRecordedPayload,
    ResultOutcome,
    ResultRecordedPayload,
)
from yoetz.kernel.task_facts import task_fact_signals

__all__ = ["RolloutRun", "command_items", "drive_rollout", "summarize"]

_TOOL_ITEMS = frozenset({"CommandExecution", "McpToolCall", "FileChange"})


@dataclass
class RolloutRun:
    """What one replay did: refused rows, where compactions fell, and the outbox backlog."""

    refused: list[tuple[str, str, str, str | None]] = field(default_factory=lambda: [])
    compactions: list[dict[str, Any]] = field(default_factory=lambda: [])
    pending_max: int = 0
    pending_left: int = 0


def _payload(record: dict[str, Any]) -> dict[str, Any]:
    """The record's ``payload`` object, or an empty one."""

    payload = record.get("payload")
    return cast(dict[str, Any], payload) if isinstance(payload, dict) else {}


def _timestamp(record: dict[str, Any]) -> float:
    text = record.get("timestamp")
    if not isinstance(text, str):
        return 0.0
    return dt.datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()


def tool_item(record: dict[str, Any]) -> dict[str, Any] | None:
    """The nested tool item a rollout record completes, or ``None``."""

    if record.get("type") != "event_msg":
        return None
    payload = _payload(record)
    if payload.get("type") != "item_completed":
        return None
    item = cast(dict[str, Any], payload["item"])
    return item if item["type"] in _TOOL_ITEMS else None


def command_items(records: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """Every ``CommandExecution`` item of a rollout, in order."""

    return [
        item
        for record in records
        if (item := tool_item(record)) is not None and item["type"] == "CommandExecution"
    ]


def hook_tool(item: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """The hook ``tool_name`` and ``tool_input`` Codex fires for one nested item."""

    kind = item["type"]
    if kind == "CommandExecution":
        argv = item["command"]
        return "Bash", {"command": argv[-1] if isinstance(argv, list) else str(argv)}
    if kind == "FileChange":
        changes = cast(dict[str, Any], item.get("changes") or {})
        paths = [path.replace("/app/", "") for path in changes] or ["file.txt"]
        body = "".join(f"*** Update File: {path}\n@@\n-a\n+b\n" for path in paths[:3])
        return "apply_patch", {"command": f"*** Begin Patch\n{body}*** End Patch"}
    server = item.get("server", "")
    tool = item.get("tool", "tool")
    arguments = item.get("arguments")
    return (
        str(tool) if server == "codex" else f"mcp__{server}__{tool}",
        cast(dict[str, Any], arguments) if isinstance(arguments, dict) else {},
    )


def post_response(item: dict[str, Any], *, stated: bool) -> Any:
    """The ``tool_response`` of the hook post: exit stated, or none (the process outlived the yield)."""

    kind = item["type"]
    if kind == "CommandExecution":
        code = item.get("exit_code")
        base = {"chunk_id": str(item["id"])[-6:], "output": "public synthetic output"}
        if stated and isinstance(code, int):
            return json.dumps(
                {**base, "exit_code": code, "original_token_count": 3, "wall_time_seconds": 1.5}
            )
        return json.dumps(
            {**base, "original_token_count": 0, "session_id": 3, "wall_time_seconds": 10.0}
        )
    if kind == "FileChange":
        return (
            "Exit code: 0\nWall time: 0.1 seconds\nOutput:\nSuccess. Updated the following files:\n"
            "M file.txt\n"
        )
    return {"content": [{"type": "text", "text": "ok"}], "isError": item.get("status") == "failed"}


def _command_actions(cell: Replay) -> list[ActionRecordedPayload]:
    return [
        cast(ActionRecordedPayload, row.payload)
        for row in cell.rows("action_recorded")
        if cast(ActionRecordedPayload, row.payload).action_kind is ActionKind.COMMAND
    ]


async def _sweep(cell: Replay, run: RolloutRun, *, capture_hook_output: bool) -> int:
    recorder = Recorder(build_coordinator(cell), capture_hook_output=capture_hook_output)
    sweeper = ObservationOutboxSweeper(cell.store, recorder)
    try:
        for _ in range(12):
            if (await sweeper.sweep()).attempted == 0:
                break
    finally:
        sweeper.close()
    run.refused.extend(recorder.refused)
    return len(cell.store.list_pending_outbox_rows(cell.commitment))


async def drive_rollout(
    cell: Replay,
    records: Sequence[dict[str, Any]],
    *,
    stated_ids: Mapping[str, bool] | None = None,
    capture_hook_output: bool = True,
) -> RolloutRun:
    """Replay ``records`` (a rollout, ``session_meta`` first) and return what happened.

    ``stated_ids`` maps a command item id to whether its hook post stated the exit (default: none
    states it, the case the recorded ledgers show for most calls).
    """

    stated = stated_ids or {}
    run = RolloutRun()
    cell.wall[0] = _timestamp(records[0])
    header = dict(records[0])
    header["payload"] = dict(header["payload"], id=HOST, cwd=str(cell.workspace))
    cell.append(header)
    cell.hook("SessionStart", source="startup")
    run.pending_max = max(
        run.pending_max, await _sweep(cell, run, capture_hook_output=capture_hook_output)
    )
    index, total = 1, len(records)
    while index < total:
        record = records[index]
        cell.wall[0] = max(cell.wall[0], _timestamp(record))
        if record["type"] == "compacted":
            before = len(_command_actions(cell))
            cell.hook("PreCompact", trigger="auto")
            await _sweep(cell, run, capture_hook_output=capture_hook_output)
            end = index
            while end < total and not (
                records[end]["type"] == "event_msg"
                and _payload(records[end]).get("type") == "item_completed"
                and records[end]["payload"]["item"]["type"] == "ContextCompaction"
            ):
                end += 1
            cell.append(*records[index : end + 1])
            cell.wall[0] = max(cell.wall[0], _timestamp(records[min(end, total - 1)]))
            cell.hook("PostCompact", trigger="auto")
            cell.hook("SessionStart", source="compact")
            await _sweep(cell, run, capture_hook_output=capture_hook_output)
            run.compactions.append(
                {"command_actions_before": before, "at": record.get("timestamp")}
            )
            index = end + 1
            continue
        if tool_item(record) is None:
            cell.append(record)
            index += 1
            continue
        batch = [index]
        probe = index + 1
        while probe < total:
            if tool_item(records[probe]) is not None:
                batch.append(probe)
                probe += 1
            elif records[probe]["type"] == "token_usage_record" or (
                records[probe]["type"] == "event_msg"
                and _payload(records[probe]).get("type") == "token_count"
            ):
                probe += 1
            else:
                break
        items = [cast(dict[str, Any], tool_item(records[i])) for i in batch]
        for item in items:
            name, tool_input = hook_tool(item)
            cell.hook("PreToolUse", tool_name=name, tool_use_id=item["id"], tool_input=tool_input)
        cell.append(*records[batch[0] : batch[-1] + 1])
        cell.wall[0] = max(cell.wall[0], _timestamp(records[batch[-1]]))
        for item in items:
            name, tool_input = hook_tool(item)
            cell.hook(
                "PostToolUse",
                tool_name=name,
                tool_use_id=item["id"],
                tool_input=tool_input,
                tool_response=post_response(item, stated=stated.get(str(item["id"]), False)),
            )
        run.pending_max = max(
            run.pending_max, await _sweep(cell, run, capture_hook_output=capture_hook_output)
        )
        index = batch[-1] + 1
    cell.hook("Stop", last_assistant_message="Done.", stop_hook_active=False)
    await _sweep(cell, run, capture_hook_output=capture_hook_output)
    cell.hook("SessionEnd")
    run.pending_left = await _sweep(cell, run, capture_hook_output=capture_hook_output)
    return run


def summarize(cell: Replay, records: Sequence[dict[str, Any]], run: RolloutRun) -> dict[str, Any]:
    """Counts and correctness checks of the ledger a replay produced."""

    items = command_items(records)
    actions = _command_actions(cell)
    results_by_action: dict[str, list[ResultRecordedPayload]] = collections.defaultdict(list)
    for row in cell.rows("result_recorded"):
        payload = cast(ResultRecordedPayload, row.payload)
        results_by_action[str(payload.action_id)].append(payload)
    order = [str(action.action_id) for action in actions]
    unknown_only = [
        position
        for position, action_ref in enumerate(order)
        if not any(r.outcome is not ResultOutcome.UNKNOWN for r in results_by_action[action_ref])
    ]
    first_post = run.compactions[0]["command_actions_before"] if run.compactions else len(order)
    checked = mismatched = conflicted = overcounted = 0
    for position, action_ref in enumerate(order):
        explicit = {
            (r.outcome, r.exit_status)
            for r in results_by_action[action_ref]
            if r.outcome is not ResultOutcome.UNKNOWN
        }
        if len(results_by_action[action_ref]) > 2:
            overcounted += 1
        if len(explicit) > 1:
            conflicted += 1
        if position < len(items):
            code = items[position].get("exit_code")
            if isinstance(code, int) and explicit:
                checked += 1
                (outcome, status) = next(iter(explicit))
                expected = ResultOutcome.SUCCESS if code == 0 else ResultOutcome.FAILURE
                if outcome is not expected or (status is not None and status != code):
                    mismatched += 1
    state = cell.ledger._state  # pyright: ignore[reportPrivateUsage]
    quarantined = cell.store.list_quarantine(cell.commitment)
    return {
        "rollout_command_items": len(items),
        "command_actions": len(order),
        "orphan_command_actions": len(order) - len(items),
        "unknown_only_total": len(unknown_only),
        "post_compaction_commands": max(0, len(order) - first_post),
        "post_compaction_unknown_only": len([p for p in unknown_only if p >= first_post]),
        "post_compaction_with_explicit_outcome": sum(
            1
            for p in range(first_post, len(order))
            if any(r.outcome is not ResultOutcome.UNKNOWN for r in results_by_action[order[p]])
        ),
        "outcomes_checked": checked,
        "outcome_mismatches": mismatched,
        "actions_with_conflicting_outcomes": conflicted,
        "actions_with_more_than_two_results": overcounted,
        "quarantined": len(quarantined),
        "quarantine_reasons": dict(collections.Counter(entry[2] for entry in quarantined)),
        "refused_rows": len(run.refused),
        "pending_after": run.pending_left,
        "pending_max": run.pending_max,
        "task_facts": sorted(task_fact_signals(state.projection, state.records).codes),
        "compactions": run.compactions,
    }
