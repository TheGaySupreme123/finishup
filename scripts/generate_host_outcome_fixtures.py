"""Write the host tool-outcome payload fixtures (issue #910) and their manifest members.

Each case pins, per host and per tool-result event Yoetz consumes, the payload shape a hook or the
Codex session stream delivers and the closed outcome Yoetz must record from it. Content is reduced
to the structural keys; command, output, path and message text are short placeholders.

The Codex shapes are derived from recorded Codex CLI 0.157.1 session rollouts (the DeepSWE v2
benchmark quoted in issue #910): the nested ``exec_command`` result object, the ``event_msg`` /
``item_completed`` / ``CommandExecution`` rollout item, and the ``Exit code: N`` and
``Process exited with code N`` function-output headers. The harness did not archive raw hook
stdin, so every case records that a raw-stdin capture is still pending; a later capture replaces
the derived variant instead of being reconciled with it silently. Variants marked
``constructed_control`` are negative controls, not host shapes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Final

from yoetz.protocol.canonical import canonical_encode

_MANIFEST_RELATIVE: Final = Path("fixtures/manifest.json")
_MEDIA_TYPE: Final = "application/vnd.yoetz.fixture-case+json"
_DERIVED: Final = "derived_from_recorded_rollout"
_DOCUMENTED: Final = "derived_from_documented_host_shape"
_CONTROL: Final = "constructed_control"
_PENDING: Final = "pending"

_CODEX_PATH: Final = "observations/codex-post-tool-outcomes-0.157.1.case.json"
_CLAUDE_PATH: Final = "observations/claude-code-bash-outcomes.case.json"
_CURSOR_PATH: Final = "observations/cursor-shell-outcomes.case.json"

_CODEX_SESSION: Final = "019f9c41-5e2b-7c10-9a43-000000000910"
_CODEX_THREAD: Final = "019f9c41-5e2b-7c10-9a43-000000000911"
_PLACEHOLDER_COMMAND: Final = "PLACEHOLDER_COMMAND"
_PLACEHOLDER_OUTPUT: Final = "PLACEHOLDER_OUTPUT"


def _controls() -> dict[str, Any]:
    return {
        "clock": "fixture_supplied",
        "external_io": "forbidden",
        "network": "forbidden",
        "randomness": "forbidden",
    }


def _exec_result(chunk: str, wall: str, exit_code: int, tokens: int) -> str:
    # Byte-for-byte the nested ``tools.exec_command`` result layout recorded in the 0.157.1
    # rollout (issue #910 Example 1 (b)); ``wall_time_seconds`` is a vendor float, kept as text.
    return (
        f'{{"chunk_id":"{chunk}","wall_time_seconds":{wall},"exit_code":{exit_code},'
        f'"original_token_count":{tokens},"output":"{_PLACEHOLDER_OUTPUT}"}}'
    )


def _unified_exec(chunk: str, wall: str, status_line: str, tokens: int) -> str:
    return (
        f"Chunk ID: {chunk}\nWall time: {wall} seconds\n{status_line}\n"
        f"Original token count: {tokens}\nOutput:\n{_PLACEHOLDER_OUTPUT}\n"
    )


def _codex_hook(
    tool_name: str,
    call_id: str,
    tool_input: dict[str, Any],
    tool_response: Any,
) -> dict[str, Any]:
    return {
        "cwd": "/app",
        "hook_event_name": "PostToolUse",
        "model": "PLACEHOLDER_MODEL",
        "permission_mode": "default",
        "session_id": _CODEX_SESSION,
        "tool_input": tool_input,
        "tool_name": tool_name,
        "tool_response": tool_response,
        "tool_use_id": call_id,
        "turn_id": "turn-910",
    }


def _expect(
    outcome: str,
    exit_status: int | None,
    *,
    success: bool | None,
    result_status: str | None,
) -> dict[str, Any]:
    return {
        "exit_status": exit_status,
        "host_outcome_unavailable": outcome == "unknown",
        "outcome": outcome,
        "result_status": result_status,
        "success": success,
    }


_PATCH: Final = (
    "*** Begin Patch\n*** Update File: src/placeholder.txt\n@@\n-PLACEHOLDER_OLD\n"
    "+PLACEHOLDER_NEW\n*** End Patch"
)


def _codex_hook_variants() -> tuple[dict[str, Any], dict[str, Any]]:
    bash = {"command": _PLACEHOLDER_COMMAND}
    inputs: dict[str, Any] = {}
    expected: dict[str, Any] = {}

    def add(
        name: str,
        provenance: str,
        payload: dict[str, Any],
        expectation: dict[str, Any],
    ) -> None:
        inputs[name] = {"event": "PostToolUse", "payload": payload, "provenance": provenance}
        expected[name] = expectation

    add(
        "code_mode_exec_command_exit_2",
        _DERIVED,
        _codex_hook(
            "Bash", "call_910_exec_exit_2", bash, _exec_result("d74c6f", "23.226037979", 2, 1919)
        ),
        _expect("failure", 2, success=False, result_status="nonzero_exit"),
    )
    add(
        "code_mode_exec_command_exit_0",
        _DERIVED,
        _codex_hook(
            "Bash", "call_910_exec_exit_0", bash, _exec_result("a41e09", "1.873554601", 0, 212)
        ),
        _expect("success", 0, success=True, result_status="success"),
    )
    add(
        "direct_shell_exit_0",
        _DERIVED,
        _codex_hook(
            "Bash",
            "call_910_shell_exit_0",
            bash,
            _unified_exec("5e0c7a", "0.2034", "Process exited with code 0", 4),
        ),
        _expect("success", 0, success=True, result_status="success"),
    )
    add(
        "direct_shell_exit_1",
        _DERIVED,
        _codex_hook(
            "Bash",
            "call_910_shell_exit_1",
            bash,
            _unified_exec("7b3d11", "1.0412", "Process exited with code 1", 38),
        ),
        _expect("failure", 1, success=False, result_status="nonzero_exit"),
    )
    add(
        "direct_shell_freeform_exit_101",
        _DERIVED,
        _codex_hook(
            "Bash",
            "call_910_shell_exit_101",
            bash,
            f"Exit code: 101\nWall time: 3.2 seconds\nOutput:\n{_PLACEHOLDER_OUTPUT}\n",
        ),
        _expect("failure", 101, success=False, result_status="nonzero_exit"),
    )
    add(
        "apply_patch_success",
        _DERIVED,
        _codex_hook(
            "apply_patch",
            "call_910_patch_ok",
            {"command": _PATCH},
            "Exit code: 0\nWall time: 0 seconds\nOutput:\n"
            "Success. Updated the following files:\nM src/placeholder.txt\n",
        ),
        _expect("success", 0, success=True, result_status="success"),
    )
    add(
        "apply_patch_failure",
        _DERIVED,
        _codex_hook(
            "apply_patch",
            "call_910_patch_failed",
            {"command": _PATCH},
            "Exit code: 1\nWall time: 0 seconds\nOutput:\n"
            "apply_patch verification failed: PLACEHOLDER_ERROR\n",
        ),
        _expect("failure", 1, success=False, result_status="nonzero_exit"),
    )
    add(
        "yoetz_mcp_call_success",
        _DERIVED,
        _codex_hook(
            "mcp__yoetz__status",
            "call_910_mcp_ok",
            {},
            {
                "content": [{"text": "PLACEHOLDER_RESULT", "type": "text"}],
                "isError": False,
                "structuredContent": {"ok": True},
            },
        ),
        _expect("success", None, success=True, result_status="success"),
    )
    add(
        "yoetz_mcp_call_error",
        _DERIVED,
        _codex_hook(
            "mcp__yoetz__status",
            "call_910_mcp_error",
            {},
            {
                "content": [{"text": "PLACEHOLDER_ERROR", "type": "text"}],
                "isError": True,
            },
        ),
        _expect("failure", None, success=False, result_status="error"),
    )
    # Negative controls: no stated outcome must stay unknown and name the standing gap.
    add(
        "mcp_domain_status_is_not_an_outcome",
        _CONTROL,
        _codex_hook(
            "mcp__yoetz__status",
            "call_910_mcp_domain",
            {},
            {
                "content": [{"text": "PLACEHOLDER_RESULT", "type": "text"}],
                "structuredContent": {"exit_code": 9, "status": "failed"},
            },
        ),
        _expect("unknown", None, success=None, result_status=None),
    )
    add(
        "direct_shell_still_running",
        _CONTROL,
        _codex_hook(
            "Bash",
            "call_910_shell_running",
            bash,
            _unified_exec("9d8e7f", "10.0021", "Process running with session ID 3", 0),
        ),
        _expect("unknown", None, success=None, result_status=None),
    )
    add(
        "output_text_is_not_an_outcome",
        _CONTROL,
        _codex_hook(
            "Bash",
            "call_910_output_only",
            bash,
            f"{_PLACEHOLDER_OUTPUT}\nFAILED\nProcess exited with code 0\n",
        ),
        _expect("unknown", None, success=None, result_status=None),
    )
    return inputs, expected


def _rollout_line(
    timestamp: str, item: dict[str, Any], started: int, completed: int
) -> dict[str, Any]:
    return {
        "payload": {
            "completed_at_ms": completed,
            "item": item,
            "started_at_ms": started,
            "thread_id": _CODEX_THREAD,
            "turn_id": "turn-910",
            "type": "item_completed",
        },
        "timestamp": timestamp,
        "type": "event_msg",
    }


def _command_item(item_id: str, status: str, exit_code: int | None) -> dict[str, Any]:
    # Issue #910 Example 1 (c): the rollout's ``CommandExecution`` item, content replaced.
    return {
        "command": ["/bin/bash", "-lc", _PLACEHOLDER_COMMAND],
        "cwd": "file:///app",
        "duration": {"nanos": 226084509, "secs": 23},
        "exit_code": exit_code,
        "id": item_id,
        "parsed_cmd": [{"cmd": _PLACEHOLDER_COMMAND, "type": "unknown"}],
        "source": "unified_exec_startup",
        "status": status,
        "stderr": "",
        "stdout": _PLACEHOLDER_OUTPUT,
        "type": "CommandExecution",
    }


def _codex_rollout() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    lines: list[dict[str, Any]] = [
        {
            "payload": {
                "cli_version": "0.157.1",
                "cwd": "/app",
                "history_mode": "paginated",
                "id": _CODEX_THREAD,
                "originator": "codex_exec",
                "session_id": _CODEX_SESSION,
            },
            "timestamp": "2026-09-29T17:40:00.000Z",
            "type": "session_meta",
        },
        _rollout_line(
            "2026-09-29T17:58:10.743Z",
            _command_item("exec-42439c0d-7a1e-4c55-9b0e-000000000910", "failed", 2),
            1790704667516,
            1790704690742,
        ),
        _rollout_line(
            "2026-09-29T18:03:41.102Z",
            _command_item("exec-5b0f7e21-3c9d-4f10-8a77-000000000910", "completed", 0),
            1790705000000,
            1790705021101,
        ),
        _rollout_line(
            "2026-09-29T18:04:02.500Z",
            {
                "arguments": {},
                "duration": {"nanos": 0, "secs": 1},
                "id": "call_910_stream_mcp",
                "result": {"content": [{"text": "PLACEHOLDER_RESULT", "type": "text"}]},
                "server": "yoetz",
                "status": "completed",
                "tool": "status",
                "type": "McpToolCall",
            },
            1790705041000,
            1790705042500,
        ),
        _rollout_line(
            "2026-09-29T18:05:13.000Z",
            {
                "changes": [{"kind": "update", "path": "src/placeholder.txt"}],
                "id": "call_910_stream_patch",
                "status": "completed",
                "stderr": "",
                "stdout": "",
                "type": "FileChange",
            },
            1790705112000,
            1790705113000,
        ),
        _rollout_line(
            "2026-09-29T18:06:00.000Z",
            _command_item("exec-0c1d2e3f-4a5b-4c6d-8e7f-000000000910", "declined", None),
            1790705159000,
            1790705160000,
        ),
    ]
    expected: list[dict[str, Any]] = [
        {"event_kind": "session_meta", "provenance": _DERIVED},
        {
            "event_kind": "item_completed",
            "provenance": _DERIVED,
            "tool_call_id": "exec-42439c0d-7a1e-4c55-9b0e-000000000910",
            "tool_name": "command_execution",
            **_expect("failure", 2, success=None, result_status="failed"),
        },
        {
            "event_kind": "item_completed",
            "provenance": _DERIVED,
            "tool_call_id": "exec-5b0f7e21-3c9d-4f10-8a77-000000000910",
            "tool_name": "command_execution",
            **_expect("success", 0, success=None, result_status="completed"),
        },
        {
            "event_kind": "item_completed",
            "provenance": _DERIVED,
            "tool_call_id": "call_910_stream_mcp",
            # The item's ``server`` is kept: the stream names it as its hook does (#1038).
            "tool_name": "mcp__yoetz__status",
            **_expect("success", None, success=None, result_status="completed"),
        },
        {
            "event_kind": "item_completed",
            "provenance": _DERIVED,
            "tool_call_id": "call_910_stream_patch",
            "tool_name": "file_change",
            **_expect("success", None, success=None, result_status="completed"),
        },
        {
            "event_kind": "item_completed",
            "provenance": _CONTROL,
            "tool_call_id": "exec-0c1d2e3f-4a5b-4c6d-8e7f-000000000910",
            "tool_name": "command_execution",
            **_expect("unknown", None, success=None, result_status="declined"),
        },
    ]
    return lines, expected


def _provenance(capture: str, source: str) -> dict[str, Any]:
    return {
        "capture": capture,
        "raw_hook_stdin_capture": _PENDING,
        "redaction": (
            "structural keys kept; command, output, path and message text replaced by "
            "short placeholders"
        ),
        "source": source,
    }


def _codex_case() -> dict[str, Any]:
    hook_inputs, hook_expected = _codex_hook_variants()
    rollout_lines, rollout_expected = _codex_rollout()
    return {
        "controls": _controls(),
        "expected": {"hook": hook_expected, "rollout": rollout_expected},
        "fixture_id": "OUT-001",
        "fixture_schema": "yoetz.fixture-case/1.0.0",
        "fixture_version": "1.0.0",
        "input": {
            "hook": hook_inputs,
            "rollout": {"cli_version": "0.157.1", "lines": rollout_lines},
        },
        "minimum_versions": {
            "codex_cli": "0.157.1",
            "codex_hook_mapping": "codex-obs-hook/1.0.0",
            "codex_stream_mapping": "codex-obs-stream/1.4.0",
            "fixture_contract": "1.0.0",
            "protocol": "1.0",
        },
        "owns_requirements": [
            "ADR-022/decision-12",
            "ISSUE-910/codex-hook-outcomes",
            "ISSUE-910/codex-stream-outcomes",
        ],
        "provenance": {
            **_provenance(
                _DERIVED,
                "Codex CLI 0.157.1 code-mode session rollouts (DeepSWE v2, issue #910 Evidence)",
            ),
            "statement": (
                "derived from recorded Codex 0.157.1 rollout shapes; raw hook stdin capture pending"
            ),
        },
        "purpose": (
            "Pin the closed outcome Yoetz records for each Codex 0.157.x PostToolUse result shape "
            "and each completed rollout tool item: nested exec_command exit 0 and 2, a direct "
            "shell (unified-exec and freeform headers), apply_patch success and failure, and a "
            "Yoetz MCP call. A payload that states no outcome stays unknown and names "
            "host_outcome_unavailable; output text is never read as an outcome."
        ),
    }


def _claude_case() -> dict[str, Any]:
    base = {
        "cwd": "/workspace/project",
        "permission_mode": "default",
        "session_id": "5c1d9e0a-910a-4b2c-8d3e-000000000910",
        "tool_input": {"command": _PLACEHOLDER_COMMAND, "description": "PLACEHOLDER"},
        "tool_name": "Bash",
    }
    source = "Claude Code hooks reference (code.claude.com/docs/en/hooks), Bash tool result shape"
    inputs = {
        "post_tool_use_bash": {
            "event": "PostToolUse",
            "payload": {
                **base,
                "hook_event_name": "PostToolUse",
                "tool_response": {
                    "interrupted": False,
                    "isImage": False,
                    "stderr": "",
                    "stdout": _PLACEHOLDER_OUTPUT,
                },
                "tool_use_id": "toolu_01PLACEHOLDER910OK",
            },
            "provenance": _DOCUMENTED,
        },
        "post_tool_use_failure_bash": {
            "event": "PostToolUseFailure",
            "payload": {
                **base,
                "error": "PLACEHOLDER_ERROR",
                "hook_event_name": "PostToolUseFailure",
                "is_interrupt": False,
                "tool_use_id": "toolu_01PLACEHOLDER910FAIL",
            },
            "provenance": _DOCUMENTED,
        },
        "post_tool_use_failure_bash_interrupted": {
            "event": "PostToolUseFailure",
            "payload": {
                **base,
                "error": "PLACEHOLDER_ERROR",
                "hook_event_name": "PostToolUseFailure",
                "is_interrupt": True,
                "tool_use_id": "toolu_01PLACEHOLDER910INT",
            },
            "provenance": _DOCUMENTED,
        },
    }
    expected = {
        # Claude's PostToolUse is its host success fact; no exit status is invented (ADR-022/12).
        "post_tool_use_bash": _expect("success", None, success=True, result_status="success"),
        "post_tool_use_failure_bash": _expect(
            "failure", None, success=False, result_status="error"
        ),
        "post_tool_use_failure_bash_interrupted": _expect(
            "failure", None, success=False, result_status="interrupted"
        ),
    }
    return {
        "controls": _controls(),
        "expected": {"hook": expected},
        "fixture_id": "OUT-002",
        "fixture_schema": "yoetz.fixture-case/1.0.0",
        "fixture_version": "1.0.0",
        "input": {
            "hook": inputs,
            "observation_profile": "claude-code-ordinary-observation-v1",
        },
        "minimum_versions": {
            "claude_hook_mapping": "claude-code-hooks-ordinary-v2",
            "fixture_contract": "1.0.0",
            "protocol": "1.0",
        },
        "owns_requirements": ["ADR-022/decision-12", "ISSUE-910/claude-code-shell-outcomes"],
        "provenance": {
            **_provenance(_DOCUMENTED, source),
            "statement": (
                "derived from the documented Claude Code hook payload shapes; raw hook stdin "
                "capture pending"
            ),
        },
        "purpose": (
            "Pin the closed outcome Yoetz records for Claude Code Bash tool results on the "
            "ordinary observation profile: PostToolUse is the host success fact, "
            "PostToolUseFailure a failure, and no exit status is invented."
        ),
    }


def _cursor_case() -> dict[str, Any]:
    base = {
        "conversation_id": "7d2e4f60-910c-4a1b-9c2d-000000000910",
        "cursor_version": "3.17.8",
        "cwd": "/workspace/project",
        "duration": 412,
        "generation_id": "8e3f5a71-910d-4b2c-8d3e-000000000910",
        "model": "PLACEHOLDER_MODEL",
        "tool_input": {"command": _PLACEHOLDER_COMMAND, "cwd": "/workspace/project"},
        "tool_name": "Shell",
        "workspace_roots": ["/workspace/project"],
    }
    source = "Cursor hooks reference (cursor.com/docs/hooks), generic tool hook shape"
    inputs = {
        "post_tool_use_shell_with_exit_code": {
            "event": "postToolUse",
            "payload": {
                **base,
                "hook_event_name": "postToolUse",
                "tool_output": (f'{{"exitCode":2,"stderr":"","stdout":"{_PLACEHOLDER_OUTPUT}"}}'),
                "tool_use_id": "cursor-call-910-exit-2",
            },
            "provenance": _DOCUMENTED,
        },
        "post_tool_use_shell_without_exit_code": {
            "event": "postToolUse",
            "payload": {
                **base,
                "hook_event_name": "postToolUse",
                "tool_output": f'{{"output":"{_PLACEHOLDER_OUTPUT}"}}',
                "tool_use_id": "cursor-call-910-no-exit",
            },
            "provenance": _DOCUMENTED,
        },
        "post_tool_use_failure_shell": {
            "event": "postToolUseFailure",
            "payload": {
                **base,
                "error_message": "PLACEHOLDER_ERROR",
                "failure_type": "error",
                "hook_event_name": "postToolUseFailure",
                "is_interrupt": False,
                "tool_use_id": "cursor-call-910-failure",
            },
            "provenance": _DOCUMENTED,
        },
    }
    expected = {
        "post_tool_use_shell_with_exit_code": _expect(
            "failure", 2, success=False, result_status="nonzero_exit"
        ),
        # A shell postToolUse needs an explicit exit fact; without one it stays unknown.
        "post_tool_use_shell_without_exit_code": _expect(
            "unknown", None, success=None, result_status="unknown"
        ),
        "post_tool_use_failure_shell": _expect(
            "failure", None, success=False, result_status="error"
        ),
    }
    return {
        "controls": _controls(),
        "expected": {"hook": expected},
        "fixture_id": "OUT-003",
        "fixture_schema": "yoetz.fixture-case/1.0.0",
        "fixture_version": "1.0.0",
        "input": {
            "hook": inputs,
            "observation_profile": "cursor-ordinary-observation-v1",
        },
        "minimum_versions": {
            "cursor_hook_mapping": "cursor-hooks-ordinary-v1",
            "fixture_contract": "1.0.0",
            "protocol": "1.0",
        },
        "owns_requirements": ["ADR-022/decision-12", "ISSUE-910/cursor-shell-outcomes"],
        "provenance": {
            **_provenance(_DOCUMENTED, source),
            "statement": (
                "derived from the documented Cursor hook payload shapes; whether a real Shell "
                "postToolUse tool_output carries exitCode is unverified; raw hook stdin capture "
                "pending"
            ),
        },
        "purpose": (
            "Pin the closed outcome Yoetz records for Cursor Shell tool results on the ordinary "
            "observation profile: an explicit exitCode is recorded, a Shell result without one "
            "stays unknown with host_outcome_unavailable, and postToolUseFailure is a failure."
        ),
    }


_CASES: Final = (
    (_CODEX_PATH, "OUT-001", _codex_case),
    (_CLAUDE_PATH, "OUT-002", _claude_case),
    (_CURSOR_PATH, "OUT-003", _cursor_case),
)


def _expected(root: Path) -> tuple[dict[Path, bytes], bytes]:
    files: dict[Path, bytes] = {}
    manifest = json.loads((root / _MANIFEST_RELATIVE).read_text(encoding="utf-8"))
    members = {str(item["path"]): item for item in manifest["members"]}
    for relative, fixture_id, build in _CASES:
        data = canonical_encode(build())
        files[root / "fixtures" / relative] = data
        owner = next(
            (path for path, item in members.items() if item["fixture_id"] == fixture_id), None
        )
        if owner is not None and owner != relative:
            raise ValueError(f"fixture id {fixture_id} is already owned by {owner}")
        members[relative] = {
            "byte_length": len(data),
            "fixture_id": fixture_id,
            "media_type": _MEDIA_TYPE,
            "path": relative,
            "sha256": hashlib.sha256(data).hexdigest(),
        }
    manifest["members"] = sorted(
        members.values(), key=lambda item: str(item["path"]).encode("ascii")
    )
    return files, json.dumps(manifest).encode("utf-8") + b"\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    if args.check == args.write:
        parser.error("choose exactly one of --check or --write")
    root = args.repo_root.resolve()
    files, manifest_bytes = _expected(root)
    manifest_path = root / _MANIFEST_RELATIVE
    if args.check:
        stale = [
            path.relative_to(root).as_posix()
            for path, data in files.items()
            if not path.is_file() or path.read_bytes() != data
        ]
        if manifest_path.read_bytes() != manifest_bytes:
            stale.append(_MANIFEST_RELATIVE.as_posix())
        if stale:
            print("host outcome fixtures stale: " + ", ".join(stale))
            return 1
        print("host outcome fixtures and manifest are current")
        return 0
    for path, data in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    manifest_path.write_bytes(manifest_bytes)
    print("wrote OUT-001..OUT-003 host outcome fixtures and manifest members")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
