"""Each host's pre/post tool hooks carry the before/after workspace fact (PR #1080 round 5).

The real host normalizers run with host-shaped payloads, an isolated state directory and no
service. Between the ``PreToolUse`` and ``PostToolUse`` passes the test does what the host's tool
call would do to the workspace; the stored post envelope must then carry the closed
``workspace_effect`` token, and materialization must put it on the observed result.
"""

from __future__ import annotations

import io
import json
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import cast

import pytest

from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.application.observation_materialize import materialize_observation_envelope
from finishup.cli import observe_hooks
from finishup.domain.events import ResultRecordedPayload
from finishup.domain.observation import ObservationEnvelope
from finishup.domain.observation_profiles import (
    CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
    CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
)
from finishup.domain.values import JsonValue
from finishup.domain.workspace_effect import workspace_effect_from_result_summary
from finishup.protocol.canonical import canonical_encode

_TASK = "tsk_00000000-0000-4000-8000-000000001080"


def _codex(event: str, call: str, command: str, **extra: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "session_id": "01a006a4-1111-4111-8111-000000001080",
        "turn_id": "turn-1",
        "cwd": "/ignored",
        "hook_event_name": event,
        "tool_name": "exec_command",
        "tool_input": {"cmd": command},
        "tool_use_id": call,
    }
    if event == "PostToolUse":
        payload["tool_response"] = "Process exited with code 0\nOutput:\n"
    payload.update(extra)
    return payload


def _claude(event: str, call: str, command: str, **extra: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "hook_event_name": event,
        "session_id": "claude-1080",
        "tool_name": "Bash",
        "tool_use_id": call,
        "tool_input": {"command": command},
    }
    if event == "PostToolUse":
        payload["tool_response"] = {"stdout": "", "stderr": "", "interrupted": False}
    payload.update(extra)
    return payload


def _cursor(event: str, call: str, command: str, **extra: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "hook_event_name": event,
        "session_id": "cursor-1080",
        "conversation_id": "cursor-1080-conversation",
        "generation_id": "generation-1080",
        "tool_name": "Shell",
        "tool_use_id": call,
        "tool_input": {"command": command},
    }
    if event == "postToolUse":
        payload["tool_output"] = '{"exitCode":0,"stdout":""}'
    payload.update(extra)
    return payload


Emit = Callable[[str, Mapping[str, object]], None]
Shape = Callable[..., dict[str, object]]


def _host(name: str, workspace: Path, state: Path) -> tuple[Emit, str, str, Shape]:
    def codex(event: str, payload: Mapping[str, object]) -> None:
        assert (
            observe_hooks.handle_observe(
                event_name=None,
                stdin_bytes=json.dumps(payload).encode(),
                stdout=io.BytesIO(),
                workspace=str(workspace),
                _state=state,
                skip_service=True,
            )
            == 0
        )

    def claude(event: str, payload: Mapping[str, object]) -> None:
        assert (
            observe_hooks.handle_claude_observe(
                event_name=event,
                stdin_bytes=canonical_encode(cast(JsonValue, payload)),
                stdout=io.BytesIO(),
                workspace=str(workspace),
                _state=state,
                skip_service=True,
                observation_profile=CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
            )
            == 0
        )

    def cursor(event: str, payload: Mapping[str, object]) -> None:
        assert (
            observe_hooks.handle_cursor_observe(
                event_name=event,
                stdin_bytes=canonical_encode(cast(JsonValue, payload)),
                stdout=io.BytesIO(),
                workspace=str(workspace),
                _state=state,
                skip_service=True,
                observation_profile=CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
            )
            == 0
        )

    hosts: dict[str, tuple[Emit, str, str, Shape]] = {
        "codex": (codex, "PreToolUse", "PostToolUse", _codex),
        "claude": (claude, "PreToolUse", "PostToolUse", _claude),
        "cursor": (cursor, "preToolUse", "postToolUse", _cursor),
    }
    return hosts[name]


def _setup(tmp_path: Path) -> tuple[Path, Path, str]:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "deliverable.txt").write_text("reviewed\n")
    # The state directory sits inside the workspace on purpose: FinishUP's own writes during
    # the hook passes must never read as a workspace change.
    state = workspace / ".finishup-state"
    store = LocalObservationStore(_state=state)
    commitment = store.workspace_commitment(str(workspace.resolve()))
    store.grant_consent(commitment)
    return workspace, state, commitment


def _posts(state: Path, commitment: str) -> list[ObservationEnvelope]:
    return [
        envelope
        for envelope in LocalObservationStore(_state=state).list_envelopes(commitment)
        if envelope.event_kind in {"PostToolUse", "postToolUse"}
    ]


@pytest.mark.parametrize("host", ["codex", "claude", "cursor"])
@pytest.mark.parametrize(
    "command,change,expected",
    [
        ("date -u", None, "unchanged"),
        ("git status --short", None, "unchanged"),
        ("sed -n '1,5p' deliverable.txt", None, "unchanged"),
        ("python gen.py", "write", "changed"),
        ("ls", "write", "changed"),
    ],
)
def test_each_host_records_the_workspace_effect_of_a_call(
    tmp_path: Path, host: str, command: str, change: str | None, expected: str
) -> None:
    workspace, state, commitment = _setup(tmp_path)
    emit, pre, post, shape = _host(host, workspace, state)
    emit(pre, shape(pre, f"{host}-call", command))
    if change == "write":
        (workspace / "deliverable.txt").write_text("rewritten by the call\n")
    emit(post, shape(post, f"{host}-call", command))
    (envelope,) = _posts(state, commitment)
    assert envelope.structural_payload["workspace_effect"] == expected
    # A read-shaped shell call that changed the workspace is never folded into a routine summary.
    if expected != "unchanged":
        assert envelope.structural_payload.get("action") not in {
            "routine_read",
            "routine_read_detailed",
        }
    batch = materialize_observation_envelope(envelope, task_id=_TASK)
    (result,) = [
        cast(ResultRecordedPayload, item.draft.payload)
        for item in batch.drafts
        if item.draft.schema.name == "result_recorded"
    ]
    assert workspace_effect_from_result_summary(result.summary) == expected


@pytest.mark.parametrize("host", ["codex", "claude", "cursor"])
def test_a_post_without_its_pre_snapshot_is_unavailable(tmp_path: Path, host: str) -> None:
    workspace, state, commitment = _setup(tmp_path)
    emit, _pre, post, shape = _host(host, workspace, state)
    emit(post, shape(post, f"{host}-lonely", "date -u"))
    (envelope,) = _posts(state, commitment)
    assert envelope.structural_payload["workspace_effect"] == "unavailable"
    # A missing pre-call snapshot is a per-call fact on the result, never a diagnostic row.
    diagnostics = state / "observation" / "hook-diagnostics.jsonl"
    reasons = (
        [json.loads(line)["reason"] for line in diagnostics.read_text().splitlines()]
        if diagnostics.exists()
        else []
    )
    assert not [reason for reason in reasons if reason.startswith("workspace_fingerprint_")]


def test_a_codex_call_still_running_is_unavailable(tmp_path: Path) -> None:
    workspace, state, commitment = _setup(tmp_path)
    emit, pre, post, _shape = _host("codex", workspace, state)
    emit(pre, _codex(pre, "codex-running", "python server.py"))
    emit(
        post,
        _codex(
            post,
            "codex-running",
            "python server.py",
            tool_response="Chunk ID: abc\nProcess running with session ID 7\nOutput:\n",
        ),
    )
    (envelope,) = _posts(state, commitment)
    assert envelope.structural_payload["workspace_effect"] == "unavailable"


def test_a_claude_background_launch_is_unavailable(tmp_path: Path) -> None:
    workspace, state, commitment = _setup(tmp_path)
    emit, pre, post, _shape = _host("claude", workspace, state)
    background = {"command": "npm run dev", "run_in_background": True}
    emit(pre, _claude(pre, "claude-bg", "npm run dev", tool_input=background))
    emit(post, _claude(post, "claude-bg", "npm run dev", tool_input=background))
    (envelope,) = _posts(state, commitment)
    assert envelope.structural_payload["workspace_effect"] == "unavailable"


def test_a_third_party_tool_is_fingerprinted_and_finishup_tools_are_not(tmp_path: Path) -> None:
    workspace, state, commitment = _setup(tmp_path)
    emit, pre, post, _shape = _host("claude", workspace, state)
    tool: dict[str, object] = {
        "hook_event_name": pre,
        "session_id": "claude-1080",
        "tool_name": "mcp__files__write_file",
        "tool_use_id": "claude-mcp",
        "tool_input": {"path": "deliverable.txt"},
    }
    emit(pre, tool)
    (workspace / "deliverable.txt").write_text("written by an MCP server\n")
    emit(post, {**tool, "hook_event_name": post, "tool_response": {"content": []}})
    own: dict[str, object] = {
        "hook_event_name": pre,
        "session_id": "claude-1080",
        "tool_name": "mcp__plugin_finishup_finishup__status",
        "tool_use_id": "claude-own",
        "tool_input": {},
    }
    emit(pre, own)
    emit(post, {**own, "hook_event_name": post, "tool_response": {"content": []}})
    posts = {
        envelope.structural_payload["tool_name"]: envelope.structural_payload
        for envelope in _posts(state, commitment)
    }
    assert posts["mcp__files__write_file"]["workspace_effect"] == "changed"
    assert "workspace_effect" not in posts["mcp__plugin_finishup_finishup__status"]


def test_a_host_payload_cannot_supply_the_fact(tmp_path: Path) -> None:
    workspace, state, commitment = _setup(tmp_path)
    emit, _pre, post, _shape = _host("codex", workspace, state)
    emit(post, _codex(post, "codex-forged", "python gen.py", workspace_effect="unchanged"))
    (envelope,) = _posts(state, commitment)
    assert envelope.structural_payload["workspace_effect"] == "unavailable"


def test_a_pre_snapshot_finished_after_the_host_window_is_withdrawn(tmp_path: Path) -> None:
    """A host may run the call once its pre-hook timeout passes; such a snapshot is not trusted."""

    import time

    from finishup.cli.workspace_effect_hook import workspace_fingerprint_pass

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "file.txt").write_text("reviewed")
    common = {
        "call_identity": "codex\x00session\x00call",
        "workspace_locator": str(workspace),
        "workspace_commitment": "hmac-sha256:" + "a" * 64,
        "key_material": b"k" * 32,
        "observation_root": tmp_path / "observation",
        "complete": True,
    }
    late = workspace_fingerprint_pass(
        "PreToolUse",
        host_deadline=time.monotonic() - 1,
        **common,  # type: ignore[arg-type]
    )
    assert late is not None and (late.effect, late.reason) == ("unavailable", "timeout")
    after = workspace_fingerprint_pass("PostToolUse", **common)  # type: ignore[arg-type]
    assert after is not None and (after.effect, after.reason) == ("unavailable", "timeout")
    on_time = workspace_fingerprint_pass(
        "PreToolUse",
        host_deadline=time.monotonic() + 30,
        **common,  # type: ignore[arg-type]
    )
    assert on_time is None
    after = workspace_fingerprint_pass("PostToolUse", **common)  # type: ignore[arg-type]
    assert after is not None and after.effect == "unchanged"


def test_a_workspace_beyond_the_bound_is_diagnosed_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from finishup.adapters import workspace_fingerprint

    workspace, state, commitment = _setup(tmp_path)
    for index in range(20):
        (workspace / f"f{index}").write_text(str(index))
    monkeypatch.setattr(workspace_fingerprint, "MAX_ENTRIES", 5)
    emit, pre, post, shape = _host("claude", workspace, state)
    for call in ("a", "b", "c"):
        emit(pre, shape(pre, call, "date -u"))
        emit(post, shape(post, call, "date -u"))
    posts = _posts(state, commitment)
    assert [envelope.structural_payload["workspace_effect"] for envelope in posts] == [
        "unavailable"
    ] * 3
    diagnostics = state / "observation" / "hook-diagnostics.jsonl"
    reasons = [json.loads(line)["reason"] for line in diagnostics.read_text().splitlines()]
    assert reasons.count("workspace_fingerprint_too_large") == 1


@pytest.mark.parametrize("host", ["codex", "claude", "cursor"])
@pytest.mark.parametrize(
    "command", ["./server &", "npm run dev & sleep 1", "nohup python worker.py", "setsid ./daemon"]
)
def test_a_command_that_may_outlive_its_call_is_unavailable(
    tmp_path: Path, host: str, command: str
) -> None:
    """A background or detached process can write after the post-call snapshot (PR #1080)."""

    workspace, state, commitment = _setup(tmp_path)
    emit, pre, post, shape = _host(host, workspace, state)
    emit(pre, shape(pre, f"{host}-bg", command))
    emit(post, shape(post, f"{host}-bg", command))
    (envelope,) = _posts(state, commitment)
    assert envelope.structural_payload["workspace_effect"] == "unavailable"
