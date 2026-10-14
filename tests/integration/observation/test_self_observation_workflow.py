"""Installed-Codex regression for FinishUP observing its own MCP workflow (#564).

Offline replay through the exact hook command the rendered Codex plugin installs.
It is not a live Codex run (those stay ``@pytest.mark.live``): it proves that the
complete prescribed start/status/check/respond/receipt workflow produces outbox
work proportional to distinct evidence, retains every hook locally, and that the
final drain converges to a documented terminal condition without sleeping.
"""

from __future__ import annotations

import io
import json
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest

from finishup.adapters.integrations.codex_plugin import parse_hooks_json, render_plugin_tree
from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.cli import observe as observe_cli
from finishup.cli.observe_hooks import handle_observe
from finishup.domain.observation import (
    ObservationGapCode,
    ObservationIngestDisposition,
    ObservationIngestResult,
    observation_ingest_result_to_json,
)
from finishup.protocol.canonical import JsonValue

_CODEX_VERSION = "0.150.1"
_SESSION = "01a013c1-2222-4222-8222-000000000564"


def _installed_ingress_commands() -> dict[str, str]:
    """The ``PreToolUse``/``PostToolUse`` observe commands the installed plugin binds."""

    hooks = parse_hooks_json(render_plugin_tree(codex_version=_CODEX_VERSION)["hooks/hooks.json"])
    events = cast(Mapping[str, JsonValue], hooks["hooks"])
    commands: dict[str, str] = {}
    for event in ("PreToolUse", "PostToolUse"):
        for group in cast(list[Mapping[str, JsonValue]], events[event]):
            for handler in cast(list[Mapping[str, JsonValue]], group["hooks"]):
                command = str(handler["command"])
                if "hooks observe" in command:
                    assert event not in commands, f"two observe handlers for {event}"
                    commands[event] = command
    return commands


def _codex_payload(event: str, tool: str, call: str, **extra: JsonValue) -> dict[str, JsonValue]:
    """Field names as the Codex binary emits them (``tool_use_id``, ``tool_response``)."""

    payload: dict[str, JsonValue] = {
        "session_id": _SESSION,
        "turn_id": "turn-1",
        "agent_type": "main",
        "cwd": "/workspace/project",
        "hook_event_name": event,
        "model": "gpt-5.3-codex",
        "permission_mode": "on-request",
        "tool_name": tool,
        "tool_use_id": call,
        "tool_input": {"arguments": {"task_id": "tsk-private", "text": "private"}},
    }
    if event == "PostToolUse":
        payload["tool_response"] = {"content": [{"type": "text", "text": "private result"}]}
    payload.update(extra)
    return payload


def _tool_call(tool: str, call: str, **post_extra: JsonValue) -> list[dict[str, JsonValue]]:
    return [
        _codex_payload("PreToolUse", tool, call),
        _codex_payload("PostToolUse", tool, call, **post_extra),
    ]


def _workflow() -> list[dict[str, JsonValue]]:
    """The prescribed cooperative workflow with the repeated status reads that fed the loop."""

    lifecycle = {"session_id": _SESSION, "cwd": "/workspace/project"}
    return [
        {**lifecycle, "hook_event_name": "SessionStart", "source": "startup"},
        *_tool_call("mcp__finishup__start", "call-start"),
        *_tool_call("mcp__finishup__status", "call-status-1"),
        *_tool_call("shell", "call-shell", exit_status=0, tool_output="tests passed"),
        *_tool_call("mcp__finishup__status", "call-status-2"),
        *_tool_call("apply_patch", "call-patch", exit_status=0),
        *_tool_call("mcp__finishup__status", "call-status-3"),
        *_tool_call("mcp__finishup__check", "call-check"),
        *_tool_call("mcp__finishup__status", "call-status-4"),
        *_tool_call("mcp__finishup__respond", "call-respond"),
        *_tool_call("mcp__finishup__status", "call-status-5"),
        *_tool_call("mcp__finishup__receipt", "call-receipt"),
        *_tool_call("mcp__finishup__read_guidance", "call-guidance"),
        {**lifecycle, "hook_event_name": "Stop", "message": "done"},
        {**lifecycle, "hook_event_name": "SessionEnd", "reason": "exit"},
    ]


def _replay(root: Path, payloads: list[dict[str, JsonValue]]) -> None:
    for payload in payloads:
        assert (
            handle_observe(
                event_name=cast(str, payload["hook_event_name"]),
                stdin_bytes=json.dumps(payload).encode(),
                stdout=io.BytesIO(),
                workspace=str(root),
                _state=root,
                skip_service=True,
            )
            == 0
        )


def test_installed_codex_ingress_is_the_observe_command_this_replay_exercises() -> None:
    commands = _installed_ingress_commands()
    assert commands == {
        "PreToolUse": "finishup hooks observe --workspace . --event PreToolUse",
        "PostToolUse": "finishup hooks observe --workspace . --event PostToolUse",
    }


def test_complete_workflow_enqueues_only_distinct_evidence_and_retains_every_hook(
    tmp_path: Path,
) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    workflow = _workflow()

    _replay(tmp_path, workflow)

    pending = [
        (
            str(row.envelope.structural_payload["hook_name"]),
            row.envelope.structural_payload.get("tool_name"),
        )
        for row in store.list_pending_outbox_rows(workspace)
    ]
    # 27 hook invocations; before #564 every one became an outbox row (27) and each
    # FinishUP PostToolUse also captured FinishUP's own result bytes. Distinct evidence:
    assert pending == [
        ("SessionStart", None),
        ("PostToolUse", "mcp__finishup__start"),
        ("PreToolUse", "shell"),
        ("PostToolUse", "shell"),
        ("PreToolUse", "apply_patch"),
        ("PostToolUse", "apply_patch"),
        ("PostToolUse", "mcp__finishup__check"),
        ("PostToolUse", "mcp__finishup__respond"),
        ("Stop", None),
        ("SessionEnd", None),
    ]
    assert len(pending) == 10
    # Nothing is dropped from local evidence, and no retained pre event left its post
    # event unpaired.
    envelopes = store.list_envelopes(workspace)
    assert len(envelopes) == len(workflow) == 27
    assert all(ObservationGapCode.UNPAIRED_EVENT.value not in env.gap_codes for env in envelopes)
    for row in store.list_pending_outbox_rows(workspace):
        assert ObservationGapCode.UNPAIRED_EVENT.value not in row.envelope.gap_codes


def test_failed_finishup_calls_in_the_workflow_still_ship(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)

    _replay(
        tmp_path,
        [
            *_tool_call("mcp__finishup__status", "call-status-ok"),
            *_tool_call("mcp__finishup__status", "call-status-failed", success=False),
            *_tool_call("mcp__finishup__check", "call-check-failed", exit_status=1),
        ],
    )

    assert [
        (
            str(row.envelope.structural_payload["hook_name"]),
            row.envelope.structural_payload.get("tool_name"),
        )
        for row in store.list_pending_outbox_rows(workspace)
    ] == [
        ("PostToolUse", "mcp__finishup__status"),
        ("PostToolUse", "mcp__finishup__check"),
    ]


@pytest.mark.anyio
async def test_final_drain_after_the_producer_stops_reaches_drained_without_sleeping(
    tmp_path: Path,
) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    _replay(tmp_path, _workflow())
    assert store.pending_outbox_count(workspace) == 10
    ingested: list[str] = []

    class Client:
        async def observation_ingest(self, body: object, *, deadline_ms: int):
            del deadline_ms
            ingested.append(str(body["envelope"]["event_kind"]))  # type: ignore[index]
            return observation_ingest_result_to_json(
                ObservationIngestResult(ObservationIngestDisposition.DUPLICATE, "duplicate", None)
            )

        async def close(self) -> None:
            return None

    async def connect(_kind: object):
        return Client()

    code, summary = await observe_cli._drain_observation_async(  # pyright: ignore[reportPrivateUsage]
        workspace=str(tmp_path),
        _state=tmp_path,
        connect=connect,  # type: ignore[arg-type]
    )

    assert code == 0
    assert summary["terminal"] == "drained"
    assert summary["passes"] == 1
    assert summary["pending_after"] == 0
    assert summary["acknowledged"] == 10
    assert ingested[0] == "SessionStart" and ingested[-1] == "SessionEnd"
    assert store.pending_outbox_count(workspace) == 0
