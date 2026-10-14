"""Opt-in native-host ordinary observation and content-consent tests."""

from __future__ import annotations

import io
import json
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest

from yoetz.adapters.integrations.claude_code_integration import (
    CLAUDE_CODE_ORDINARY_HOOK_EVENTS,
    render_claude_code_plugin,
)
from yoetz.adapters.integrations.cursor_integration import (
    CURSOR_ORDINARY_HOOK_EVENTS,
    render_cursor_plugin,
)
from yoetz.adapters.integrations.observation_local import LocalObservationStore
from yoetz.cli import observe as observe_cli
from yoetz.cli import observe_hooks
from yoetz.domain.observation import (
    ObservationControlCommand,
    ObservationRevokeCommand,
    ObservationSource,
)
from yoetz.domain.observation_profiles import (
    CLAUDE_CODE_ORDINARY_HOOK_MAPPING_VERSION,
    CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
    CURSOR_ORDINARY_HOOK_MAPPING_VERSION,
    CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
)
from yoetz.domain.values import JsonObject, JsonValue
from yoetz.ports.plugin_artifacts import PluginFormatProfile
from yoetz.protocol.canonical import canonical_encode, strict_json_parse


def test_content_profiles_are_independent_and_user_controls_are_reversible(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    workspace = str(tmp_path)
    store = LocalObservationStore(_state=tmp_path / "state")
    commitment = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(commitment)

    assert (
        observe_cli.enable_observation_content(
            workspace=workspace,
            profile=CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
            _state=tmp_path / "state",
        )
        == 0
    )
    assert (
        observe_cli.enable_observation_content(
            workspace=workspace,
            profile=CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
            _state=tmp_path / "state",
        )
        == 0
    )
    assert LocalObservationStore(_state=tmp_path / "state").content_capture_profiles(
        commitment
    ) == (
        CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
        CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
    )

    assert (
        observe_cli.disable_observation_content(
            workspace=workspace,
            profile=CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
            _state=tmp_path / "state",
        )
        == 0
    )
    assert LocalObservationStore(_state=tmp_path / "state").content_capture_profiles(
        commitment
    ) == (CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,)
    capsys.readouterr()  # discard the human-readable enable/disable lines
    assert (
        observe_cli.observation_content_status(
            workspace=workspace,
            json_output=True,
            _state=tmp_path / "state",
        )
        == 0
    )
    status = json.loads(capsys.readouterr().out)
    assert status["enabled"] is True
    assert status["content_capture_scope"] == "ordinary_profiles"
    assert status["codex_hook_capture_scope"] == "observation_consent"
    assert status["content_capture_profiles"] == [CURSOR_ORDINARY_OBSERVATION_PROFILE_ID]


@pytest.mark.parametrize("mode", ("active", "paused", "revoked", "runtime_disabled", "mixed"))
def test_profileless_codex_status_names_the_ordinary_profile_scope(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    mode: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    store = LocalObservationStore(_state=state)
    commitment = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(commitment)
    if mode == "paused":
        store.pause(ObservationControlCommand(commitment))
    elif mode == "revoked":
        store.revoke(ObservationRevokeCommand(commitment))
    elif mode == "runtime_disabled":
        store.set_runtime_enabled(False)
    elif mode == "mixed":
        store.enable_content_capture(commitment, CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID)
        store.enable_content_capture(commitment, CURSOR_ORDINARY_OBSERVATION_PROFILE_ID)

    observe_cli.observation_content_status(workspace=str(tmp_path), json_output=True, _state=state)
    status = json.loads(capsys.readouterr().out)
    assert status["content_capture_scope"] == "ordinary_profiles"
    assert status["codex_hook_capture_scope"] == "observation_consent"
    assert status["enabled"] is (mode == "mixed")
    assert status["consent_active"] is (mode not in {"paused", "revoked"})
    assert status["runtime_enabled"] is (mode != "runtime_disabled")
    assert all("codex" not in profile for profile in status["content_capture_profiles"])

    observe_cli.observation_content_status(workspace=str(tmp_path), json_output=False, _state=state)
    text = capsys.readouterr().out
    assert "scope=ordinary_profiles" in text
    assert "Codex hook capture follows observation consent" in text
    assert "does not prove captured evidence or AI-powered selection" in text

    def no_activation_probe(*args: object, **kwargs: object) -> dict[str, JsonValue]:
        return {}

    monkeypatch.setattr(observe_cli, "_activation_state", no_activation_probe)
    observe_cli.observe_status(workspace=str(tmp_path), json_output=True, _state=state)
    overall = json.loads(capsys.readouterr().out)
    assert overall["content_capture_scope"] == status["content_capture_scope"]
    assert overall["codex_hook_capture_scope"] == status["codex_hook_capture_scope"]
    assert overall["content_capture_enabled"] == status["enabled"]
    observe_cli.observe_status(workspace=str(tmp_path), json_output=False, _state=state)
    assert "ordinary profiles; Codex hooks follow observation consent" in capsys.readouterr().out


def test_content_actions_report_requested_and_effective_profiles(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    workspace = str(tmp_path)
    state = tmp_path / "state"
    store = LocalObservationStore(_state=state)
    commitment = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(commitment)
    store.enable_content_capture(commitment, CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID)

    observe_cli.pause_observation(workspace=workspace, _state=state)
    store.set_runtime_enabled(False)
    capsys.readouterr()

    assert (
        observe_cli.enable_observation_content(
            workspace=workspace,
            profile=CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
            _state=state,
            json_output=True,
        )
        == 0
    )
    enabled_while_stopped = json.loads(capsys.readouterr().out)
    assert enabled_while_stopped["content_capture_profiles"] == [
        CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
        CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
    ]
    assert enabled_while_stopped["effective_content_capture_profiles"] == []
    assert enabled_while_stopped["consent_active"] is False
    assert enabled_while_stopped["runtime_enabled"] is False
    assert enabled_while_stopped["enabled"] is False

    assert (
        observe_cli.observation_content_status(
            workspace=workspace,
            json_output=True,
            _state=state,
        )
        == 0
    )
    stopped_status = json.loads(capsys.readouterr().out)
    assert (
        stopped_status["content_capture_profiles"]
        == enabled_while_stopped["content_capture_profiles"]
    )
    assert stopped_status["effective_content_capture_profiles"] == []
    assert stopped_status["enabled"] is False

    assert (
        observe_cli.disable_observation_content(
            workspace=workspace,
            profile=CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
            _state=state,
            json_output=True,
        )
        == 0
    )
    disabled_while_stopped = json.loads(capsys.readouterr().out)
    assert disabled_while_stopped["content_capture_profiles"] == [
        CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID
    ]
    assert disabled_while_stopped["effective_content_capture_profiles"] == []
    assert disabled_while_stopped["enabled"] is False

    store.set_runtime_enabled(True)
    observe_cli.resume_observation(workspace=workspace, _state=state)
    capsys.readouterr()
    assert (
        observe_cli.observation_content_status(
            workspace=workspace,
            json_output=True,
            _state=state,
        )
        == 0
    )
    resumed_status = json.loads(capsys.readouterr().out)
    assert resumed_status["consent_active"] is True
    assert resumed_status["runtime_enabled"] is True
    assert resumed_status["effective_content_capture_profiles"] == [
        CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID
    ]
    assert resumed_status["enabled"] is True


def test_claude_ordinary_profile_forwards_redacted_content_only_when_explicitly_selected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, object] = {}

    def fake_handle_observe(**kwargs: object) -> int:
        captured.update(kwargs)
        return 0

    monkeypatch.setattr(observe_hooks, "handle_observe", fake_handle_observe)
    payload: dict[str, JsonValue] = {
        "hook_event_name": "PostToolUse",
        "session_id": "claude-ordinary-session",
        "tool_name": "Bash",
        "tool_use_id": "tool-ordinary-1",
        "tool_input": JsonObject({"command": "printf ordinary"}),
        "tool_response": JsonObject({"output": "ordinary result"}),
        "error": "secret-error-text",
    }
    observe_hooks.handle_claude_observe(
        event_name="PostToolUse",
        stdin_bytes=canonical_encode(payload),
        stdout=io.BytesIO(),
        workspace=str(tmp_path),
        _state=tmp_path / "state",
        observation_profile=CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
    )
    structural = strict_json_parse(cast(bytes, captured["stdin_bytes"]))
    assert isinstance(structural, dict)
    assert structural["capability_profile_id"] == CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID
    assert structural["mapping_hint"] == CLAUDE_CODE_ORDINARY_HOOK_MAPPING_VERSION
    assert structural["tool_name"] == "Bash"
    assert structural["tool_use_id"] == "tool-ordinary-1"
    assert "secret-error-text" not in canonical_encode(structural).decode()
    assert captured["_content_capture_profile"] == CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID
    assert canonical_encode(cast(JsonValue, captured["_content_payload"])) == canonical_encode(
        payload
    )
    assert captured["source"] is ObservationSource.CLAUDE_HOOK


def test_cursor_ordinary_profile_uses_generic_tool_identity_and_events(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, object] = {}

    def fake_handle_observe(**kwargs: object) -> int:
        captured.update(kwargs)
        return 0

    monkeypatch.setattr(observe_hooks, "handle_observe", fake_handle_observe)
    payload: dict[str, JsonValue] = {
        "hook_event_name": "postToolUseFailure",
        "session_id": "cursor-ordinary-session",
        "conversation_id": "cursor-ordinary-conversation",
        "tool_name": "shell",
        "tool_use_id": "tool-ordinary-2",
        "result": JsonObject({"output": "failure output"}),
        "exit_code": 7,
        "failure_type": "error",
        "workspace_roots": (str(tmp_path),),
    }
    observe_hooks.handle_cursor_observe(
        event_name="postToolUseFailure",
        stdin_bytes=canonical_encode(payload),
        stdout=io.BytesIO(),
        workspace=str(tmp_path),
        _state=tmp_path / "state",
        observation_profile=CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
    )
    structural = strict_json_parse(cast(bytes, captured["stdin_bytes"]))
    assert isinstance(structural, dict)
    assert structural["capability_profile_id"] == CURSOR_ORDINARY_OBSERVATION_PROFILE_ID
    assert structural["mapping_hint"] == CURSOR_ORDINARY_HOOK_MAPPING_VERSION
    assert structural["action"] == "cursor_tool_failure"
    assert structural["tool_call_id"] == "tool-ordinary-2"
    assert structural["success"] is False
    assert structural["exit_status"] == 7
    assert captured["_content_capture_profile"] == CURSOR_ORDINARY_OBSERVATION_PROFILE_ID
    assert canonical_encode(cast(JsonValue, captured["_content_payload"])) == canonical_encode(
        payload
    )


def test_renderers_keep_old_default_and_emit_bounded_ordinary_subscriptions(tmp_path: Path) -> None:
    launcher = tmp_path / "yoetz"
    launcher.write_text("#!/bin/sh\n", encoding="utf-8")
    launcher.chmod(0o700)

    claude = render_claude_code_plugin(
        yoetz_launcher=launcher,
        observation_profile="ordinary",
    )
    claude_hooks = json.loads(claude.members["hooks/hooks.json"])["hooks"]
    assert tuple(sorted(claude_hooks)) == CLAUDE_CODE_ORDINARY_HOOK_EVENTS
    assert all(
        "--observation-profile claude-code-ordinary-observation-v1" in item["command"]
        for definitions in claude_hooks.values()
        for item in definitions[0]["hooks"]
        if "hooks claude-observe " in item["command"]
    )
    assert "FileChanged" not in claude_hooks
    assert "PostToolBatch" not in claude_hooks

    cursor = render_cursor_plugin(
        PluginFormatProfile.CURSOR_PLUGIN_NATIVE,
        yoetz_launcher=launcher,
        observation_profile="ordinary",
    )
    cursor_hooks = json.loads(cursor.members["hooks/hooks.json"])["hooks"]
    assert tuple(sorted(cursor_hooks)) == CURSOR_ORDINARY_HOOK_EVENTS
    assert all(
        "--observation-profile cursor-ordinary-observation-v1" in item["command"]
        for definitions in cursor_hooks.values()
        for item in definitions
        if "hooks cursor-observe " in item["command"]
    )
    assert "beforeShellExecution" not in cursor_hooks
    assert "afterFileEdit" not in cursor_hooks


def test_claude_ordinary_ingress_materializes_identity_and_nested_outcomes(
    tmp_path: Path,
) -> None:
    """Exercise the real handler and local store for ordinary command/tool outcomes."""

    store = LocalObservationStore(_state=tmp_path / "state")
    commitment = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(commitment)
    store.enable_content_capture(commitment, CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID)

    def emit(event: str, payload: Mapping[str, object]) -> None:
        output = io.BytesIO()
        assert (
            observe_hooks.handle_claude_observe(
                event_name=event,
                stdin_bytes=canonical_encode(cast(JsonValue, payload)),
                stdout=output,
                workspace=str(tmp_path),
                _state=tmp_path / "state",
                skip_service=True,
                observation_profile=CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
            )
            == 0
        )

    emit(
        "PreToolUse",
        {
            "hook_event_name": "PreToolUse",
            "session_id": "claude-real-ordinary",
            "tool_name": "Bash",
            "tool_use_id": "call-shell-failed",
            "tool_input": {"command": "false"},
        },
    )
    emit(
        "PostToolUse",
        {
            "hook_event_name": "PostToolUse",
            "session_id": "claude-real-ordinary",
            "tool_name": "Bash",
            "tool_use_id": "call-shell-failed",
            "tool_response": {
                "exitCode": 7,
                "stderr": "FAILED_COMMAND_CANARY",
                "interrupted": False,
            },
        },
    )
    emit(
        "PreToolUse",
        {
            "hook_event_name": "PreToolUse",
            "session_id": "claude-real-ordinary",
            "tool_name": "Bash",
            "tool_use_id": "call-read",
            "tool_input": {"command": "head file.txt"},
        },
    )
    emit(
        "PostToolUse",
        {
            "hook_event_name": "PostToolUse",
            "session_id": "claude-real-ordinary",
            "tool_name": "Bash",
            "tool_use_id": "call-read",
            "tool_input": {"command": "head file.txt"},
            "tool_response": '{"exitCode":0,"stdout":"READ_RESULT_CANARY"}',
        },
    )
    emit(
        "PreToolUse",
        {
            "hook_event_name": "PreToolUse",
            "session_id": "claude-real-ordinary",
            "tool_name": "Write",
            "tool_use_id": "call-write",
            "tool_input": {"file_path": "file.txt"},
        },
    )
    emit(
        "PostToolUse",
        {
            "hook_event_name": "PostToolUse",
            "session_id": "claude-real-ordinary",
            "tool_name": "Write",
            "tool_use_id": "call-write",
            "tool_response": {"success": True},
        },
    )
    emit(
        "PreToolUse",
        {
            "hook_event_name": "PreToolUse",
            "session_id": "claude-real-ordinary",
            "tool_name": "mcp__other__review",
            "tool_use_id": "call-mcp",
        },
    )
    emit(
        "PostToolUse",
        {
            "hook_event_name": "PostToolUse",
            "session_id": "claude-real-ordinary",
            "tool_name": "mcp__other__review",
            "tool_use_id": "call-mcp",
            "tool_response": '{"isError":false,"result":"MCP_RESULT_CANARY"}',
        },
    )
    emit(
        "PreToolUse",
        {
            "hook_event_name": "PreToolUse",
            "session_id": "claude-real-ordinary",
            "tool_name": "Edit",
            "tool_use_id": "call-conflicting-outcome",
            "tool_input": {"file_path": "file.txt"},
        },
    )
    emit(
        "PostToolUse",
        {
            "hook_event_name": "PostToolUse",
            "session_id": "claude-real-ordinary",
            "tool_name": "Edit",
            "tool_use_id": "call-conflicting-outcome",
            "tool_response": {"success": False, "exitCode": 0},
        },
    )

    envelopes = LocalObservationStore(_state=tmp_path / "state").list_envelopes(commitment)
    assert [item.event_kind for item in envelopes] == [
        "PreToolUse",
        "PostToolUse",
        "PreToolUse",
        "PostToolUse",
        "PreToolUse",
        "PostToolUse",
        "PreToolUse",
        "PostToolUse",
        "PreToolUse",
        "PostToolUse",
    ]
    failed = envelopes[1].structural_payload
    assert failed["tool_name"] == "Bash"
    assert failed["tool_call_id"] == "call-shell-failed"
    assert failed["success"] is False
    assert failed["exit_status"] == 7
    assert failed["result_status"] == "nonzero_exit"
    assert envelopes[0].structural_payload["tool_call_id"] == "call-shell-failed"
    assert envelopes[2].structural_payload["action"] == "routine_read"
    assert envelopes[3].structural_payload["action"] == "routine_read"
    assert envelopes[3].structural_payload["success"] is True
    assert envelopes[5].structural_payload["success"] is True
    assert envelopes[7].structural_payload["success"] is True
    assert envelopes[9].structural_payload["success"] is False
    assert envelopes[9].structural_payload["result_status"] == "failure"
    state_bytes = b"".join(
        path.read_bytes()
        for path in (tmp_path / "state").rglob("*")
        if path.is_file() and not path.is_symlink()
    )
    assert b"FAILED_COMMAND_CANARY" not in state_bytes
    assert b"READ_RESULT_CANARY" not in state_bytes
    assert b"MCP_RESULT_CANARY" not in state_bytes


def test_claude_permission_request_and_denial_keep_distinct_terminal_identity(
    tmp_path: Path,
) -> None:
    """PermissionRequest is supplemental; PermissionDenied is a terminal decision row."""

    store = LocalObservationStore(_state=tmp_path / "state")
    commitment = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(commitment)
    store.enable_content_capture(commitment, CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID)

    def emit(event: str, payload: Mapping[str, object]) -> None:
        assert (
            observe_hooks.handle_claude_observe(
                event_name=event,
                stdin_bytes=canonical_encode(cast(JsonValue, payload)),
                stdout=io.BytesIO(),
                workspace=str(tmp_path),
                _state=tmp_path / "state",
                skip_service=True,
                observation_profile=CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
            )
            == 0
        )

    base: dict[str, JsonValue] = {
        "session_id": "claude-permission-overlap",
        "tool_name": "Bash",
    }
    emit("PermissionRequest", {**base, "hook_event_name": "PermissionRequest"})
    paired = {**base, "tool_use_id": "call-permission"}
    emit(
        "PreToolUse",
        {
            **paired,
            "hook_event_name": "PreToolUse",
            "tool_input": {"command": "rm file.txt"},
        },
    )
    emit(
        "PostToolUse",
        {
            **paired,
            "hook_event_name": "PostToolUse",
            "tool_response": {"exitCode": 0},
        },
    )
    emit(
        "PermissionDenied",
        {
            **paired,
            "hook_event_name": "PermissionDenied",
            "source": "auto_mode",
            "reason": "DENIAL_REASON_CANARY",
        },
    )

    envelopes = LocalObservationStore(_state=tmp_path / "state").list_envelopes(commitment)
    assert [item.event_kind for item in envelopes] == [
        "PermissionRequest",
        "PreToolUse",
        "PostToolUse",
        "PermissionDecision",
    ]
    assert envelopes[0].structural_payload["action"] == "claude_permission_request"
    assert envelopes[0].structural_payload["permission_decision"] == "requested"
    assert envelopes[0].structural_payload["tool_name"] == "Bash"
    assert "tool_call_id" not in envelopes[0].structural_payload
    assert envelopes[1].structural_payload["tool_call_id"] == "call-permission"
    assert "unpaired_event" not in envelopes[2].gap_codes
    denied = envelopes[3].structural_payload
    assert denied["action"] == "claude_permission_denied"
    assert denied["tool_call_id"] == "call-permission"
    assert denied["denied"] is True
    assert denied["permission_decision"] == "denied"
    serialized = canonical_encode(denied)
    assert b"DENIAL_REASON_CANARY" not in serialized


def test_cursor_ordinary_ingress_reads_json_string_outcomes_and_fails_closed(
    tmp_path: Path,
) -> None:
    """Cursor's generic result strings yield bounded outcomes through the real handler."""

    store = LocalObservationStore(_state=tmp_path / "state")
    commitment = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(commitment)
    store.enable_content_capture(commitment, CURSOR_ORDINARY_OBSERVATION_PROFILE_ID)

    def emit(
        event: str,
        output: JsonValue,
        call_id: str,
        *,
        tool_name: str = "shell",
    ) -> None:
        payload: dict[str, JsonValue] = {
            "hook_event_name": event,
            "session_id": "cursor-real-ordinary",
            "conversation_id": "cursor-real-conversation",
            "tool_name": tool_name,
            "tool_use_id": call_id,
            "tool_output": output,
        }
        assert (
            observe_hooks.handle_cursor_observe(
                event_name=event,
                stdin_bytes=canonical_encode(payload),
                stdout=io.BytesIO(),
                workspace=str(tmp_path),
                _state=tmp_path / "state",
                skip_service=True,
                observation_profile=CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
            )
            == 0
        )

    emit("preToolUse", None, "cursor-call-failed")
    emit("postToolUse", '{"exitCode":7,"stdout":"CURSOR_FAILURE_CANARY"}', "cursor-call-failed")
    emit("preToolUse", None, "cursor-call-cancelled")
    emit(
        "postToolUseFailure",
        '{"isInterrupted":true,"message":"CANCEL_CANARY"}',
        "cursor-call-cancelled",
    )
    emit("preToolUse", None, "cursor-call-unknown")
    emit(
        "postToolUse",
        '{"exitCode":"bad","status":"future-host-status"}',
        "cursor-call-unknown",
    )
    emit("preToolUse", None, "cursor-call-tool-only")
    emit(
        "postToolUse",
        '{"isError":false,"message":"TOOL_SUCCESS_ONLY_CANARY"}',
        "cursor-call-tool-only",
    )
    emit("preToolUse", None, "cursor-call-denied")
    emit(
        "postToolUseFailure",
        '{"failure_type":"permission_denied","reason":"DENIAL_CANARY"}',
        "cursor-call-denied",
    )
    emit("preToolUse", None, "cursor-call-mcp-domain", tool_name="MCP:fixture_echo")
    emit(
        "postToolUse",
        (
            '{"success":false,"exitCode":99,'
            '"structuredContent":{"outcome":"rejected","status":"MCP_DOMAIN_CANARY"}}'
        ),
        "cursor-call-mcp-domain",
        tool_name="MCP:fixture_echo",
    )

    before_specialized = len(
        LocalObservationStore(_state=tmp_path / "state").list_envelopes(commitment)
    )
    observe_hooks.handle_cursor_observe(
        event_name="afterFileEdit",
        stdin_bytes=canonical_encode(
            {
                "hook_event_name": "afterFileEdit",
                "session_id": "cursor-real-ordinary",
                "conversation_id": "cursor-real-conversation",
                "tool_name": "edit",
                "tool_use_id": "cursor-specialized-duplicate",
                "file_path": "DUPLICATE_CANARY",
            }
        ),
        stdout=io.BytesIO(),
        workspace=str(tmp_path),
        _state=tmp_path / "state",
        skip_service=True,
        observation_profile=CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
    )

    envelopes = LocalObservationStore(_state=tmp_path / "state").list_envelopes(commitment)
    assert len(envelopes) == 12
    failed = envelopes[1].structural_payload
    assert failed["tool_call_id"] == "cursor-call-failed"
    assert failed["success"] is False
    assert failed["exit_status"] == 7
    assert failed["result_status"] == "nonzero_exit"
    cancelled = envelopes[3].structural_payload
    assert cancelled["success"] is False
    assert cancelled["result_status"] == "interrupted"
    unknown = envelopes[5].structural_payload
    assert unknown["action"] == "cursor_tool_outcome_unknown"
    assert "success" not in unknown
    assert unknown["result_status"] == "unknown"
    tool_only = envelopes[7].structural_payload
    assert tool_only["action"] == "cursor_tool_outcome_unknown"
    assert "success" not in tool_only
    assert tool_only["result_status"] == "unknown"
    denied = envelopes[9].structural_payload
    assert denied["action"] == "cursor_tool_denied"
    assert denied["denied"] is True
    assert denied["result_status"] == "denied"
    mcp_domain = envelopes[11].structural_payload
    assert mcp_domain["action"] == "cursor_tool_outcome_unknown"
    assert "success" not in mcp_domain
    assert "exit_status" not in mcp_domain
    assert "result_status" not in mcp_domain
    assert len(envelopes) == before_specialized
    state_bytes = b"".join(
        path.read_bytes()
        for path in (tmp_path / "state").rglob("*")
        if path.is_file() and not path.is_symlink()
    )
    assert b"CURSOR_FAILURE_CANARY" not in state_bytes
    assert b"CANCEL_CANARY" not in state_bytes
    assert b"TOOL_SUCCESS_ONLY_CANARY" not in state_bytes
    assert b"DENIAL_CANARY" not in state_bytes
    assert b"MCP_DOMAIN_CANARY" not in state_bytes
    assert b"future-host-status" not in state_bytes


def test_claude_ordinary_cancellation_and_invalid_status_are_closed(
    tmp_path: Path,
) -> None:
    store = LocalObservationStore(_state=tmp_path / "state")
    commitment = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(commitment)
    store.enable_content_capture(commitment, CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID)

    def emit(event: str, payload: Mapping[str, object]) -> None:
        assert (
            observe_hooks.handle_claude_observe(
                event_name=event,
                stdin_bytes=canonical_encode(cast(JsonValue, payload)),
                stdout=io.BytesIO(),
                workspace=str(tmp_path),
                _state=tmp_path / "state",
                skip_service=True,
                observation_profile=CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
            )
            == 0
        )

    base: dict[str, JsonValue] = {
        "session_id": "claude-closed-outcome",
        "tool_name": "Bash",
    }
    emit(
        "PreToolUse",
        {**base, "hook_event_name": "PreToolUse", "tool_use_id": "call-cancelled"},
    )
    emit(
        "PostToolUse",
        {
            **base,
            "hook_event_name": "PostToolUse",
            "tool_use_id": "call-cancelled",
            "tool_response": {"interrupted": True, "message": "CANCEL_CANARY"},
        },
    )
    emit(
        "PreToolUse",
        {**base, "hook_event_name": "PreToolUse", "tool_use_id": "call-tool-only"},
    )
    emit(
        "PostToolUse",
        {
            **base,
            "hook_event_name": "PostToolUse",
            "tool_use_id": "call-tool-only",
            # Claude's built-in Bash result has no exit-code field. The
            # PostToolUse event itself is the host-level success fact.
            "tool_response": {
                "stdout": "TOOL_SUCCESS_OUTPUT",
                "stderr": "",
                "interrupted": False,
                "isImage": False,
            },
        },
    )
    emit(
        "PreToolUse",
        {**base, "hook_event_name": "PreToolUse", "tool_use_id": "call-invalid"},
    )
    emit(
        "PostToolUse",
        {
            **base,
            "hook_event_name": "PostToolUse",
            "tool_use_id": "call-invalid",
            "tool_response": {
                "exitCode": "not-an-exit",
                "status": "future-status",
                "success": True,
            },
        },
    )
    emit(
        "StopFailure",
        {
            "hook_event_name": "StopFailure",
            "session_id": "claude-closed-outcome",
            "error": "API_ERROR_PROSE_CANARY",
        },
    )
    emit(
        "PostToolUse",
        {
            **base,
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_use_id": "call-after-stop-failure",
            "tool_response": "1\tREAD_RESULT_OUTPUT\n",
        },
    )

    envelopes = LocalObservationStore(_state=tmp_path / "state").list_envelopes(commitment)
    cancelled = envelopes[1].structural_payload
    assert cancelled["success"] is False
    assert cancelled["result_status"] == "interrupted"
    tool_only = envelopes[3].structural_payload
    assert tool_only["action"] == "claude_tool_success"
    assert tool_only["success"] is True
    assert tool_only["result_status"] == "success"
    assert "exit_status" not in tool_only
    unknown = envelopes[5].structural_payload
    assert unknown["action"] == "claude_tool_outcome_unknown"
    assert "success" not in unknown
    assert unknown["result_status"] == "unknown"
    api_failure = envelopes[6].structural_payload
    assert api_failure["action"] == "claude_api_failure"
    assert api_failure["result_status"] == "error"
    assert envelopes[6].event_kind == "Stop"
    assert envelopes[7].event_kind == "PostToolUse"
    assert envelopes[7].structural_payload["tool_name"] == "Read"
    assert envelopes[7].structural_payload["action"] == "routine_read"
    assert envelopes[7].structural_payload["success"] is True
    assert envelopes[7].structural_payload["result_status"] == "success"
    assert "exit_status" not in envelopes[7].structural_payload
    state_bytes = b"".join(
        path.read_bytes()
        for path in (tmp_path / "state").rglob("*")
        if path.is_file() and not path.is_symlink()
    )
    assert b"CANCEL_CANARY" not in state_bytes
    assert b"future-status" not in state_bytes
    assert b"API_ERROR_PROSE_CANARY" not in state_bytes


def test_claude_ordinary_posttooluse_event_success_preserves_unknown_boundaries(
    tmp_path: Path,
) -> None:
    """Use Claude's native result shapes without inventing an exit status."""

    store = LocalObservationStore(_state=tmp_path / "state")
    commitment = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(commitment)
    store.enable_content_capture(commitment, CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID)

    def emit(event: str, payload: Mapping[str, object]) -> None:
        assert (
            observe_hooks.handle_claude_observe(
                event_name=event,
                stdin_bytes=canonical_encode(cast(JsonValue, payload)),
                stdout=io.BytesIO(),
                workspace=str(tmp_path),
                _state=tmp_path / "state",
                skip_service=True,
                observation_profile=CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
            )
            == 0
        )

    def pair(
        call_id: str,
        tool_input: Mapping[str, object],
        post_event: str = "PostToolUse",
        tool_name: str = "Bash",
        **post_fields: object,
    ) -> None:
        base: dict[str, object] = {
            "session_id": "claude-native-contract",
            "tool_name": tool_name,
            "tool_use_id": call_id,
        }
        emit(
            "PreToolUse",
            {
                **base,
                "hook_event_name": "PreToolUse",
                "tool_input": dict(tool_input),
            },
        )
        emit(
            post_event,
            {
                **base,
                "hook_event_name": post_event,
                "tool_input": dict(tool_input),
                **post_fields,
            },
        )

    # Read returns display text, while Bash returns stdout/stderr metadata;
    # neither shape contains a success or exit field. PostToolUse is still the
    # documented host-level success signal for both calls.
    emit(
        "PreToolUse",
        {
            "hook_event_name": "PreToolUse",
            "session_id": "claude-native-contract",
            "tool_name": "Read",
            "tool_use_id": "call-read",
            "tool_input": {"file_path": str(tmp_path / "README.md")},
        },
    )
    emit(
        "PostToolUse",
        {
            "hook_event_name": "PostToolUse",
            "session_id": "claude-native-contract",
            "tool_name": "Read",
            "tool_use_id": "call-read",
            "tool_input": {"file_path": str(tmp_path / "README.md")},
            "tool_response": "1\tread output\n",
        },
    )
    pair(
        "call-bash",
        {"command": "python3 -m unittest -v", "run_in_background": False},
        tool_response={
            "stdout": "OK",
            "stderr": "",
            "interrupted": False,
            "isImage": False,
        },
    )
    pair(
        "call-background",
        {"command": "python3 -m unittest -v", "run_in_background": True},
        tool_response={
            "stdout": "started",
            "stderr": "",
            "interrupted": False,
            "isImage": False,
        },
    )
    pair(
        "call-failure",
        {"command": "python3 -m unittest -v", "run_in_background": False},
        post_event="PostToolUseFailure",
        error="Exit code 1\nFAILED_TEST_CANARY",
        is_interrupt=False,
    )
    pair(
        "call-conflict",
        {"command": "python3 -m unittest -v", "run_in_background": False},
        tool_response={"success": True, "status": "future-status"},
    )
    pair(
        "call-host-status",
        {"command": "python3 -m unittest -v", "run_in_background": False},
        status="future-host-status",
        tool_response={"success": True},
    )
    pair(
        "call-yoetz-accepted",
        {},
        tool_name="mcp__plugin_yoetz_yoetz__publish_work",
        tool_response={"outcome": "accepted"},
    )
    pair(
        "call-mcp-domain-rejection",
        {},
        tool_name="mcp__plugin_yoetz_yoetz__publish_work",
        tool_response={
            "success": False,
            "structuredContent": {"outcome": "rejected"},
        },
    )
    pair(
        "call-mcp-error",
        {},
        tool_name="mcp__plugin_yoetz_yoetz__publish_work",
        tool_response={
            "isError": True,
            "structuredContent": {"outcome": "rejected"},
        },
    )

    envelopes = LocalObservationStore(_state=tmp_path / "state").list_envelopes(commitment)
    read = envelopes[1].structural_payload
    assert read["action"] == "routine_read"
    assert read["success"] is True
    assert read["result_status"] == "success"
    assert "exit_status" not in read

    bash = envelopes[3].structural_payload
    assert bash["action"] == "claude_tool_success"
    assert bash["success"] is True
    assert bash["result_status"] == "success"
    assert "exit_status" not in bash

    background = envelopes[5].structural_payload
    assert background["action"] == "claude_tool_outcome_unknown"
    assert "success" not in background
    assert background["result_status"] == "partial"

    failure = envelopes[7].structural_payload
    assert failure["action"] == "claude_tool_failure"
    assert failure["success"] is False
    assert failure["result_status"] == "error"

    conflict = envelopes[9].structural_payload
    assert conflict["action"] == "claude_tool_success"
    assert conflict["success"] is True
    assert conflict["result_status"] == "success"

    host_status = envelopes[11].structural_payload
    assert host_status["action"] == "claude_tool_outcome_unknown"
    assert "success" not in host_status
    assert host_status["result_status"] == "unknown"

    yoetz_accepted = envelopes[13].structural_payload
    assert yoetz_accepted["action"] == "claude_tool_success"
    assert yoetz_accepted["success"] is True
    assert yoetz_accepted["result_status"] == "success"
    assert "exit_status" not in yoetz_accepted

    mcp_domain_rejection = envelopes[15].structural_payload
    assert mcp_domain_rejection["action"] == "claude_tool_success"
    assert mcp_domain_rejection["success"] is True
    assert mcp_domain_rejection["result_status"] == "success"

    mcp_error = envelopes[17].structural_payload
    assert mcp_error["action"] == "claude_tool_failure"
    assert mcp_error["success"] is False
    assert mcp_error["result_status"] == "error"


@pytest.mark.parametrize("host", ["claude", "cursor"])
def test_unknown_runtime_authority_never_extracts_native_content(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, host: str
) -> None:
    state = tmp_path / "state"
    store = LocalObservationStore(_state=state)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    profile = (
        CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID
        if host == "claude"
        else CURSOR_ORDINARY_OBSERVATION_PROFILE_ID
    )
    store.grant_consent(workspace)
    store.enable_content_capture(workspace, profile)
    extracted: list[bool] = []

    def contended(_store: LocalObservationStore) -> bool:
        raise TimeoutError("observation_store_lock_timeout")

    def visible_content(*args: object, **kwargs: object) -> tuple[tuple[()], bool]:
        extracted.append(True)
        return (), False

    monkeypatch.setattr(LocalObservationStore, "runtime_enabled", contended)
    monkeypatch.setattr(observe_hooks, "_visible_content_chunks", visible_content)
    event = "PostToolUse" if host == "claude" else "postToolUse"
    payload: dict[str, JsonValue] = {
        "hook_event_name": event,
        "session_id": "unknown-authority",
        "tool_name": "Read",
        "tool_use_id": "read-1",
        "tool_response": "PRIVATE_CONTENT_MUST_NOT_BE_EXTRACTED",
        "tool_output": "PRIVATE_CONTENT_MUST_NOT_BE_EXTRACTED",
        "workspace_roots": (str(tmp_path),),
    }
    handler = (
        observe_hooks.handle_claude_observe
        if host == "claude"
        else observe_hooks.handle_cursor_observe
    )
    assert (
        handler(
            event_name=event,
            stdin_bytes=canonical_encode(payload),
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=state,
            skip_service=True,
            observation_profile=profile,
        )
        == 0
    )
    assert extracted == []
    pending = tuple(row.envelope for row in store.list_pending_outbox_rows(workspace))
    assert len(pending) == 1
    assert "content_capture_unavailable" in pending[0].gap_codes
    assert "content_unselected" not in pending[0].gap_codes
    assert pending[0].content_object_refs == ()


def test_cursor_ordinary_yoetz_status_read_stays_local_while_other_mcp_calls_deliver(
    tmp_path: Path,
) -> None:
    """tb4 n5: Cursor's ``MCP:status`` read is not appended to the ledger it read."""

    store = LocalObservationStore(_state=tmp_path / "state")
    commitment = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(commitment)

    def emit(event: str, call_id: str, tool_name: str) -> None:
        payload: dict[str, JsonValue] = {
            "hook_event_name": event,
            "session_id": "cursor-n5-ordinary",
            "conversation_id": "cursor-n5-conversation",
            "tool_name": tool_name,
            "tool_use_id": call_id,
            "tool_output": None if event == "preToolUse" else '{"isError":false}',
        }
        assert (
            observe_hooks.handle_cursor_observe(
                event_name=event,
                stdin_bytes=canonical_encode(payload),
                stdout=io.BytesIO(),
                workspace=str(tmp_path),
                _state=tmp_path / "state",
                skip_service=True,
                observation_profile=CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
            )
            == 0
        )

    for call_id, tool_name in (
        ("cursor-n5-status", "MCP:status"),
        ("cursor-n5-publish", "MCP:publish_work"),
        ("cursor-n5-foreign", "MCP:fixture_echo"),
    ):
        emit("preToolUse", call_id, tool_name)
        emit("postToolUse", call_id, tool_name)

    reopened = LocalObservationStore(_state=tmp_path / "state")
    delivered = {
        (
            row.envelope.event_kind,
            row.envelope.structural_payload.get("tool_name"),
        )
        for row in reopened.list_pending_outbox_rows(commitment)
        if row.envelope.event_kind in {"PreToolUse", "PostToolUse"}
    }
    assert delivered == {
        ("PostToolUse", "MCP:publish_work"),
        ("PreToolUse", "MCP:fixture_echo"),
        ("PostToolUse", "MCP:fixture_echo"),
    }
    local = {
        envelope.structural_payload.get("tool_name")
        for envelope in reopened.list_envelopes(commitment)
    }
    assert {"MCP:status", "MCP:publish_work", "MCP:fixture_echo"} <= local
