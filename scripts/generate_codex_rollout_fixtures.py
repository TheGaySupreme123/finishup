"""Write reviewed Codex rollout grammar fixtures and refresh derived bounds."""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any, cast

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "src"))
sys.path.insert(0, str(_ROOT / "tests"))

from builders.codex_rollout import (  # noqa: E402
    encode_lines,
    event_msg,
    function_call,
    function_call_output,
    item_completed,
    response_item,
    session_meta,
)
from finishup.adapters.importers.codex_rollout_jsonl import (  # noqa: E402
    CODEX_ROLLOUT_COMPATIBLE_PROFILE_ID,
    SUPPORTED_ROLLOUT_PROFILES,
)
from finishup.adapters.integrations.codex_capability_cells import (  # noqa: E402
    skill_manifest_capability_fields,
)
from finishup.protocol.canonical import (  # noqa: E402
    canonical_digest,
    canonical_encode,
    entry_digest,
)

_CANARY = "sk-proj-CANARYLEGACYTOKEN0001"
_DIR = _ROOT / "fixtures" / "imports" / "codex"
_TS = "2026-08-22T12:00:00.000Z"
_WRAPPER_TYPES_0_150_1 = SUPPORTED_ROLLOUT_PROFILES["0.150.1"].wrapper_types
_ITEM_TYPES_0_150_1 = SUPPORTED_ROLLOUT_PROFILES["0.150.1"].item_types
# Every fixture is constructed from the observed key shape of a release, never copied from a
# real rollout: values are CANARY tokens so tests can prove nothing content-bearing leaks.
_VERSIONS = {
    "0.148.0": "codex-rollout-jsonl/0.148.0/v1",
    "0.150.1": "codex-rollout-jsonl/0.150.1/v1",
}


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _controls() -> dict[str, Any]:
    return {
        "clock": "fixture_supplied",
        "environment": {
            "locale": "C",
            "python_hash_seeds": ["0", "1", "4294967295"],
            "timezone": "UTC",
        },
        "external_io": "forbidden",
        "ids": "fixture_supplied",
        "network": "forbidden",
        "randomness": "forbidden",
    }


def _case(
    *,
    fixture_id: str,
    purpose: str,
    variants: dict[str, bytes],
    expected: dict[str, Any],
    cli_version: str = "0.148.0",
    profile_id: str | None = None,
    requirements: tuple[str, ...] = (
        "ADR-005/exact-profile-admission",
        "ISSUE-418/rollout-grammar",
        "ISSUE-413/capability-cell",
    ),
) -> dict[str, Any]:
    # ``profile_id`` names the exact profile expected to admit the source; an unsupported
    # release has none, and its case records the refusal instead.
    resolved_profile = _VERSIONS[cli_version] if profile_id is None else profile_id
    input_variants: dict[str, Any] = {}
    for name, raw in variants.items():
        input_variants[name] = {
            "codex_capability_profile_id": resolved_profile,
            "codex_version": cli_version,
            "source": {
                "byte_length": len(raw),
                "bytes_base64": _b64(raw),
                "sha256": f"sha256:{_sha(raw)}",
            },
        }
    return {
        "controls": _controls(),
        "expected": {"variants": expected},
        "fixture_id": fixture_id,
        "fixture_schema": "yoetz.fixture-case/1.0.0",
        "fixture_version": "1.0.0",
        "input": {"variants": input_variants},
        "minimum_versions": {
            "codex_cli": cli_version,
            "codex_mapping": "codex-rollout-jsonl/1.0.0",
            "codex_profile": resolved_profile,
            "fixture_contract": "1.0.0",
            "protocol": "0.1",
        },
        "owns_requirements": list(requirements),
        "purpose": purpose,
    }


def _legacy() -> bytes:
    return encode_lines(
        session_meta(history_mode="legacy", cwd="/canary/cwd/CANARY_LEGACY_CWD"),
        response_item(
            {
                "content": [{"text": f"CANARY_LEGACY_ASSISTANT {_CANARY}", "type": "output_text"}],
                "role": "assistant",
                "type": "message",
            }
        ),
        response_item(
            {
                "summary": [{"text": "CANARY_LEGACY_REASONING", "type": "summary_text"}],
                "type": "reasoning",
            }
        ),
        function_call(
            name="mcp__yoetz__status",
            call_id="call_yoetz_1",
            arguments='{"request_id":"CANARY_LEGACY_YOETZ_ARGS"}',
        ),
        function_call_output(call_id="call_yoetz_1", output="CANARY_LEGACY_YOETZ_OUTPUT"),
        function_call(
            name="shell",
            call_id="call_shell_1",
            arguments='{"command":"echo CANARY_LEGACY_SHELL"}',
        ),
        function_call_output(call_id="call_shell_1", output="CANARY_LEGACY_SHELL_OUTPUT"),
        {
            "payload": {"cwd": "/canary/cwd/CANARY_LEGACY_CWD", "model": "synthetic"},
            "timestamp": "2026-08-22T12:00:00.000Z",
            "type": "turn_context",
        },
        {
            "payload": {
                "message": {
                    "content": [{"text": "CANARY_LEGACY_COMPACTED", "type": "output_text"}],
                    "role": "assistant",
                    "type": "message",
                }
            },
            "timestamp": "2026-08-22T12:00:00.000Z",
            "type": "compacted",
        },
        {"payload": {}, "timestamp": "2026-08-22T12:00:00.000Z", "type": "world_state"},
    )


def _paginated() -> bytes:
    return encode_lines(
        session_meta(history_mode="paginated", ordinal=1),
        {
            "ordinal": 2,
            "payload": {
                "item": {
                    "content": [{"text": "CANARY_PAGINATED_USER", "type": "input_text"}],
                    "type": "user_message",
                },
                "type": "item_completed",
            },
            "timestamp": "2026-08-22T12:00:00.000Z",
            "type": "event_msg",
        },
        response_item(
            {
                "content": [{"text": "CANARY_PAGINATED_ASSISTANT", "type": "output_text"}],
                "role": "assistant",
                "type": "message",
            },
            ordinal=3,
        ),
        function_call(
            name="mcp__yoetz__check",
            call_id="call_yoetz_p",
            arguments="{}",
            ordinal=4,
        ),
        function_call_output(call_id="call_yoetz_p", output="ok", ordinal=5),
        function_call(name="web_search", call_id="call_web_p", arguments="{}", ordinal=6),
        function_call_output(call_id="call_web_p", output="CANARY_PAGINATED_WEB", ordinal=7),
        {
            "ordinal": 8,
            "payload": {},
            "timestamp": "2026-08-22T12:00:00.000Z",
            "type": "world_state",
        },
    )


def _current_0_150_1(cli_version: str = "0.150.1") -> bytes:
    """Constructed paginated (current-mode) 0.150.1 rollout covering every admitted shape.

    ``cli_version`` relabels only the session header: the differential compatibility fixture
    (IMP-014) reuses this exact event structure under an unproven release label (issue #656).

    Wrapper and item key sets mirror the observed 0.150.1 grammar; every value is a canary.
    Hidden reasoning (``encrypted_content``, ``raw_content``), the system prompt
    (``base_instructions``), developer messages, and a secret-looking token are all present so
    the privacy tests can prove none of them reach an observation envelope.
    """

    ordinal = 0

    def next_ordinal() -> int:
        nonlocal ordinal
        ordinal += 1
        return ordinal

    return encode_lines(
        session_meta(
            cli_version=cli_version,
            history_mode="paginated",
            ordinal=next_ordinal(),
            cwd="/canary/cwd/CANARY_0150_CWD",
            extra={
                "base_instructions": {"text": "CANARY_0150_SYSTEM_PROMPT"},
                "context_window": 1,
                "model_provider": "synthetic",
                "session_id": "019f8b27-b98e-7061-bbb5-d0b897594de6",
                "source": "cli",
                "thread_source": "cli",
                "timestamp": _TS,
            },
        ),
        {
            "ordinal": next_ordinal(),
            "payload": {
                "active_permission_profile": "CANARY_0150_PERMISSION_PROFILE",
                "approval_policy": "never",
                "cwd": "/canary/cwd/CANARY_0150_CWD",
                "model": "synthetic",
                "turn_id": "turn_1",
            },
            "timestamp": _TS,
            "type": "turn_context",
        },
        event_msg(
            {"thread_settings": {"model": "synthetic"}, "type": "thread_settings_applied"},
            ordinal=next_ordinal(),
        ),
        event_msg(
            {"started_at": _TS, "turn_id": "turn_1", "type": "task_started"},
            ordinal=next_ordinal(),
        ),
        response_item(
            {
                "content": [{"text": "CANARY_0150_DEVELOPER_PROMPT", "type": "input_text"}],
                "id": "msg_dev_1",
                "role": "developer",
                "type": "message",
            },
            ordinal=next_ordinal(),
        ),
        response_item(
            {
                "content": [{"text": "CANARY_0150_USER_TEXT", "type": "input_text"}],
                "id": "msg_user_1",
                "role": "user",
                "type": "message",
            },
            ordinal=next_ordinal(),
        ),
        item_completed(
            {
                "content": [{"text": "CANARY_0150_USER_TEXT", "type": "input_text"}],
                "id": "item_user_1",
                "type": "UserMessage",
            },
            ordinal=next_ordinal(),
        ),
        response_item(
            {
                "encrypted_content": "CANARY_0150_HIDDEN_REASONING",
                "id": "rs_1",
                "summary": [{"text": "CANARY_0150_REASONING_SUMMARY", "type": "summary_text"}],
                "type": "reasoning",
            },
            ordinal=next_ordinal(),
        ),
        item_completed(
            {
                "id": "item_reasoning_1",
                "raw_content": "CANARY_0150_HIDDEN_REASONING",
                "summary_text": "CANARY_0150_REASONING_SUMMARY",
                "type": "Reasoning",
            },
            ordinal=next_ordinal(),
        ),
        response_item(
            {
                "arguments": '{"request_id":"CANARY_0150_YOETZ_ARGS"}',
                "call_id": "call_yoetz_1",
                "id": "fc_1",
                "name": "mcp__yoetz__status",
                "namespace": "yoetz",
                "type": "function_call",
            },
            ordinal=next_ordinal(),
        ),
        response_item(
            {
                "call_id": "call_yoetz_1",
                "id": "fco_1",
                "output": "CANARY_0150_YOETZ_OUTPUT",
                "type": "function_call_output",
            },
            ordinal=next_ordinal(),
        ),
        item_completed(
            {
                "arguments": {"request_id": "CANARY_0150_YOETZ_ARGS"},
                "duration": {"nanos": 0, "secs": 1},
                "id": "call_yoetz_1",
                "result": {"content": [{"text": "CANARY_0150_YOETZ_OUTPUT", "type": "text"}]},
                "server": "yoetz",
                "status": "completed",
                "tool": "status",
                "type": "McpToolCall",
            },
            ordinal=next_ordinal(),
        ),
        response_item(
            {
                "call_id": "call_shell_1",
                "id": "ctc_1",
                "input": f"echo CANARY_0150_SHELL api_key={_CANARY}",
                "name": "shell_command",
                "status": "completed",
                "type": "custom_tool_call",
            },
            ordinal=next_ordinal(),
        ),
        response_item(
            {
                "call_id": "call_shell_1",
                "id": "ctco_1",
                "output": f"CANARY_0150_SHELL_OUTPUT {_CANARY}",
                "type": "custom_tool_call_output",
            },
            ordinal=next_ordinal(),
        ),
        item_completed(
            {
                "aggregated_output": "CANARY_0150_SHELL_OUTPUT",
                "command": "echo CANARY_0150_SHELL",
                "cwd": "/canary/cwd/CANARY_0150_CWD",
                "duration": {"nanos": 0, "secs": 1},
                "exit_code": 0,
                "id": "call_shell_1",
                "parsed_cmd": [],
                "source": "agent",
                "status": "completed",
                "stderr": "",
                "stdout": "CANARY_0150_SHELL_OUTPUT",
                "type": "CommandExecution",
            },
            ordinal=next_ordinal(),
        ),
        item_completed(
            {
                "changes": [{"kind": "update", "path": "/canary/cwd/CANARY_0150_FILE"}],
                "id": "item_file_1",
                "status": "completed",
                "stderr": "",
                "stdout": "",
                "type": "FileChange",
            },
            ordinal=next_ordinal(),
        ),
        item_completed(
            {
                "agents_states": {},
                "id": "item_collab_1",
                "receiver_agents": [],
                "receiver_thread_ids": [],
                "sender_thread_id": "019f8b27-b98e-7061-bbb5-d0b897594de6",
                "status": "completed",
                "tool": "spawn_agent",
                "type": "CollabAgentToolCall",
            },
            ordinal=next_ordinal(),
        ),
        item_completed(
            {
                "agent_path": "CANARY_0150_AGENT_PATH",
                "agent_thread_id": "019f8b27-b98e-7061-bbb5-d0b897594de7",
                "id": "item_subagent_1",
                "kind": "started",
                "type": "SubAgentActivity",
            },
            ordinal=next_ordinal(),
        ),
        {
            "ordinal": next_ordinal(),
            "payload": {"trigger_turn": "turn_1"},
            "timestamp": _TS,
            "type": "inter_agent_communication_metadata",
        },
        response_item(
            {
                "author": "CANARY_0150_AGENT_AUTHOR",
                "content": "CANARY_0150_AGENT_MESSAGE",
                "id": "am_1",
                "recipient": "CANARY_0150_AGENT_RECIPIENT",
                "type": "agent_message",
            },
            ordinal=next_ordinal(),
        ),
        response_item(
            {
                "content": [{"text": "CANARY_0150_ASSISTANT_TEXT", "type": "output_text"}],
                "id": "msg_assistant_1",
                "phase": "final_answer",
                "role": "assistant",
                "type": "message",
            },
            ordinal=next_ordinal(),
        ),
        item_completed(
            {
                "content": "CANARY_0150_ASSISTANT_TEXT",
                "id": "item_assistant_1",
                "phase": "final_answer",
                "type": "AgentMessage",
            },
            ordinal=next_ordinal(),
        ),
        event_msg(
            {
                "info": {"total_token_usage": {"input_tokens": 1}},
                "rate_limits": {},
                "type": "token_count",
            },
            ordinal=next_ordinal(),
        ),
        event_msg(
            {
                "completed_at": _TS,
                "duration_ms": 1,
                "last_agent_message": "CANARY_0150_ASSISTANT_TEXT",
                "started_at": _TS,
                "turn_id": "turn_1",
                "type": "task_complete",
            },
            ordinal=next_ordinal(),
        ),
        event_msg(
            {"started_at": _TS, "turn_id": "turn_2", "type": "task_started"},
            ordinal=next_ordinal(),
        ),
        event_msg(
            {
                "completed_at": _TS,
                "duration_ms": 1,
                "reason": "interrupted",
                "started_at": _TS,
                "turn_id": "turn_2",
                "type": "turn_aborted",
            },
            ordinal=next_ordinal(),
        ),
        item_completed(
            {"id": "item_compaction_1", "type": "ContextCompaction"},
            ordinal=next_ordinal(),
        ),
        {
            "ordinal": next_ordinal(),
            "payload": {
                "first_window_id": "w1",
                "message": "CANARY_0150_COMPACTED_SUMMARY",
                "previous_window_id": "w1",
                "replacement_history": [],
                "window_id": "w2",
                "window_number": 2,
            },
            "timestamp": _TS,
            "type": "compacted",
        },
        {
            "ordinal": next_ordinal(),
            "payload": {"full": True, "state": {"files": ["CANARY_0150_WORLD_FILE"]}},
            "timestamp": _TS,
            "type": "world_state",
        },
    )


def _unsupported_0_152_1() -> bytes:
    """A header whose ``history_mode`` names no known structure: refused structurally.

    Before issue #656 this case proved that an unlisted release was refused by version alone.
    The version is now diagnostic provenance, so the refused proof is a genuinely incompatible
    header shape (an unknown ``history_mode``) under the same release label.
    """

    return encode_lines(
        session_meta(cli_version="0.152.1", history_mode="streamed", ordinal=1),
        {
            "ordinal": 2,
            "payload": {"tokens": 1},
            "timestamp": _TS,
            "type": "token_usage_record",
        },
        function_call(name="shell", call_id="call_future_1", ordinal=3),
    )


_COMPATIBLE_VERSION = "0.153.4"


def _relabeled_0_153_4() -> bytes:
    """The full 0.150.1 paginated structure with only the header version changed."""

    return _current_0_150_1(cli_version=_COMPATIBLE_VERSION)


def _additive_0_153_4() -> bytes:
    """The relabeled stream with harmless additive fields on every wrapper and payload."""

    rows: list[dict[str, Any]] = []
    for line in _relabeled_0_153_4().split(b"\n"):
        if not line:
            continue
        row: dict[str, Any] = json.loads(line)
        row["x_future_wrapper_field"] = {"canary": "CANARY_0153_ADDITIVE_WRAPPER"}
        payload: Any = row.get("payload")
        if isinstance(payload, dict):
            payload_dict = cast(dict[str, Any], payload)
            payload_dict["x_future_payload_field"] = "CANARY_0153_ADDITIVE_PAYLOAD"
            item: Any = payload_dict.get("item")
            if isinstance(item, dict):
                item_dict = cast(dict[str, Any], item)
                item_dict["x_future_item_field"] = "CANARY_0153_ADDITIVE_ITEM"
        rows.append(row)
    return encode_lines(*rows)


def _unknown_event_0_153_4() -> bytes:
    """Relabeled header, one unknown wrapper, one unknown nested item, then a known call.

    The unknown wrapper is a token no observed Codex release emits. It was
    ``token_usage_record`` until that family was admitted as structurally ignored (issue #754);
    an admitted family can no longer prove that an unknown one stays a bounded per-line gap.
    """

    return encode_lines(
        session_meta(cli_version=_COMPATIBLE_VERSION, history_mode="paginated", ordinal=1),
        {
            "ordinal": 2,
            "payload": {"tokens": 1, "text": "CANARY_0153_UNKNOWN_WRAPPER"},
            "timestamp": _TS,
            "type": "future_usage_record",
        },
        item_completed(
            {"id": "item_future", "type": "FutureItem", "text": "CANARY_0153_UNKNOWN_ITEM"},
            ordinal=3,
        ),
        function_call(name="shell", call_id="call_0153_after", ordinal=4),
        function_call_output(call_id="call_0153_after", output="ok", ordinal=5),
    )


def _incompatible_known_0_153_4() -> bytes:
    """Known wrappers whose payload shape is incompatible: bounded per-line refusal, no outcome."""

    return encode_lines(
        session_meta(cli_version=_COMPATIBLE_VERSION, history_mode="paginated", ordinal=1),
        # Known ``response_item`` wrapper with a string payload instead of an object.
        {
            "ordinal": 2,
            "payload": "CANARY_0153_STRING_PAYLOAD",
            "timestamp": _TS,
            "type": "response_item",
        },
        # Known ``event_msg`` wrapper with a non-integer ordinal.
        {
            "ordinal": "three",
            "payload": {"type": "task_started", "turn_id": "turn_1"},
            "timestamp": _TS,
            "type": "event_msg",
        },
        function_call(name="shell", call_id="call_0153_ok", ordinal=4),
    )


def _truncated_0_153_4() -> bytes:
    """Relabeled header plus an unterminated live-append tail."""

    return encode_lines(
        session_meta(cli_version=_COMPATIBLE_VERSION, history_mode="paginated", ordinal=1),
        function_call(name="shell", call_id="call_0153_done", ordinal=2),
        terminated=True,
    ) + encode_lines(
        item_completed({"id": "item_partial", "type": "AgentMessage"}, ordinal=3),
        terminated=False,
    )


# Multi-agent v2 (issue #754). Key shapes are transcribed from a real Codex 0.153.4 v2 run on
# the maintainer machine; every value here is a canary, so the fixture proves the grammar and
# never carries transcript content. Established by that transcript: the parent emits
# ``SubAgentActivity`` nested in ``event_msg.item_completed`` (never as a ``response_item``), its
# ``kind`` is ``started`` once per delegation and ``interacted`` thereafter, the child thread is
# in ``agent_thread_id``, and the delegated child's own header carries ``thread_source``,
# ``parent_thread_id`` and ``agent_path`` while its ``session_id`` is the *parent* thread.
_V2_PARENT_THREAD = "019f8b27-b98e-7061-bbb5-d0b897594de6"
_V2_CHILD_THREAD = "019f8b27-b98e-7061-bbb5-d0b897594de7"
_V2_AGENT_PATH = "/root/canary_review"


def _v2_token_usage() -> dict[str, Any]:
    return {
        "cache_write_input_tokens": 1,
        "cached_input_tokens": 1,
        "input_tokens": 1,
        "output_tokens": 1,
        "reasoning_output_tokens": 1,
        "total_tokens": 1,
    }


def _v2_subagent_activity(
    *, kind: str, call_id: str, agent_thread_id: str, agent_path: str
) -> dict[str, Any]:
    return {
        "agent_path": agent_path,
        "agent_thread_id": agent_thread_id,
        "id": call_id,
        "kind": kind,
        "type": "SubAgentActivity",
    }


def _v2_child_header(
    *,
    ordinal: int,
    child_thread_id: str = _V2_CHILD_THREAD,
    parent_thread_id: str | None = _V2_PARENT_THREAD,
    agent_path: str = _V2_AGENT_PATH,
) -> dict[str, Any]:
    """One delegated child's own rollout header, in the observed v2 shape."""

    payload: dict[str, Any] = {
        "agent_nickname": "CANARY_0153_NICKNAME",
        "agent_path": agent_path,
        "cli_version": _COMPATIBLE_VERSION,
        "cwd": "/canary/cwd/CANARY_0153_CWD",
        "history_mode": "paginated",
        "id": child_thread_id,
        "multi_agent_version": "v2",
        "originator": "user",
        # v2 sets ``session_id`` to the parent thread; only ``id`` is the child.
        "session_id": _V2_PARENT_THREAD,
        "thread_source": "subagent",
    }
    if parent_thread_id is not None:
        payload["parent_thread_id"] = parent_thread_id
        payload["source"] = {
            "subagent": {
                "thread_spawn": {
                    "agent_nickname": "CANARY_0153_NICKNAME",
                    "agent_path": agent_path,
                    "agent_role": None,
                    "depth": 1,
                    "parent_thread_id": parent_thread_id,
                }
            }
        }
    return {"ordinal": ordinal, "payload": payload, "timestamp": _TS, "type": "session_meta"}


def _multi_agent_v2_parent() -> bytes:
    """A v2 parent turn: spawn, inter-agent message, accounting, and a later interaction."""

    return encode_lines(
        session_meta(
            cli_version=_COMPATIBLE_VERSION,
            history_mode="paginated",
            session_id=_V2_PARENT_THREAD,
            ordinal=1,
            cwd="/canary/cwd/CANARY_0153_CWD",
            extra={"session_id": _V2_PARENT_THREAD, "thread_source": "user"},
        ),
        {
            "ordinal": 2,
            "payload": {
                "approval_policy": "never",
                "cwd": "/canary/cwd/CANARY_0153_CWD",
                "model": "synthetic",
                "multi_agent_version": "v2",
                "turn_id": "turn_1",
            },
            "timestamp": _TS,
            "type": "turn_context",
        },
        item_completed(
            _v2_subagent_activity(
                kind="started",
                call_id="call_CANARY0153SPAWN",
                agent_thread_id=_V2_CHILD_THREAD,
                agent_path=_V2_AGENT_PATH,
            ),
            ordinal=3,
        ),
        response_item(
            {
                "author": _V2_AGENT_PATH,
                "content": [{"text": "CANARY_0153_AGENT_MESSAGE", "type": "output_text"}],
                "id": "amsg_CANARY0153",
                # 0.153.4 adds a fractional ``create_time`` to every response item.
                "internal_chat_message_metadata_passthrough": {
                    "create_time": 1_800_000_000.5,
                    "turn_id": "turn_1",
                },
                "recipient": "/root",
                "type": "agent_message",
            },
            ordinal=4,
        ),
        {
            "ordinal": 5,
            "payload": {"trigger_turn": True},
            "timestamp": _TS,
            "type": "inter_agent_communication_metadata",
        },
        {
            "ordinal": 6,
            "payload": {
                "response_id": "resp_CANARY0153",
                "root_turn_id": "turn_1",
                "session_id": _V2_PARENT_THREAD,
                "thread_id": _V2_PARENT_THREAD,
                "thread_token_usage": _v2_token_usage(),
                "turn_id": "turn_1",
                "turn_token_usage": _v2_token_usage(),
                "usage": _v2_token_usage(),
            },
            "timestamp": _TS,
            "type": "token_usage_record",
        },
        item_completed(
            _v2_subagent_activity(
                kind="interacted",
                call_id="call_CANARY0153INTERACT",
                agent_thread_id=_V2_CHILD_THREAD,
                agent_path=_V2_AGENT_PATH,
            ),
            ordinal=7,
        ),
        event_msg(
            {
                "info": {
                    "last_token_usage": _v2_token_usage(),
                    "model_context_window": 1,
                    "total_token_usage": _v2_token_usage(),
                },
                # 0.153.4 adds a fractional ``used_percent`` to every token_count row.
                "rate_limits": {
                    "limit_id": "CANARY_0153_LIMIT",
                    "primary": {"resets_at": 1, "used_percent": 12.5, "window_minutes": 1},
                },
                "type": "token_count",
            },
            ordinal=8,
        ),
    )


def _multi_agent_v2_child() -> bytes:
    """A delegated child's own rollout: its header is the only place v2 names the delegation."""

    return encode_lines(
        _v2_child_header(ordinal=1),
        response_item(
            {
                "content": [{"text": "CANARY_0153_CHILD_ASSISTANT", "type": "output_text"}],
                "role": "assistant",
                "type": "message",
            },
            ordinal=2,
        ),
        # A child reports its exchanges with the root the same way, with the counterpart in
        # ``agent_thread_id``. Only ``started`` opens a delegation, so this reversed row never
        # publishes the parent thread as somebody's child.
        item_completed(
            _v2_subagent_activity(
                kind="interacted",
                call_id="call_CANARY0153CHILDBACK",
                agent_thread_id=_V2_PARENT_THREAD,
                agent_path="/root",
            ),
            ordinal=3,
        ),
    )


def _multi_agent_v2_child_without_identity() -> bytes:
    """A header that declares itself a child but names no distinct spawning thread."""

    return encode_lines(
        _v2_child_header(ordinal=1, child_thread_id=_V2_PARENT_THREAD, parent_thread_id=None),
    )


def _write_case(name: str, document: dict[str, Any]) -> None:
    path = _DIR / name
    path.write_bytes(canonical_encode(document) + b"\n")


def _refresh_lineage_fixture_service_provenance() -> None:
    """Bind the service-only lineage positive vector to the observation coordinator stamp."""

    path = _ROOT / "fixtures" / "replay" / "lineage-event-families.case.json"
    document = json.loads(path.read_bytes())
    rows = document["input"]["accepted_entries"]
    if not any(
        row["envelope"]["schema"]["name"] == "coordination_obligation_declared" for row in rows
    ):
        template = next(
            row for row in rows if row["envelope"]["schema"]["name"] == "delegation_declared"
        )
        declaration = deepcopy(template)
        envelope = declaration["envelope"]
        payload = declaration["payload"]
        payload.clear()
        payload.update(
            {
                "detection_id": "evt_30000003-0000-4000-8000-000000000011",
                "project_id": "prj_30000003-0000-4000-8000-000000000012",
                "membership_generation": "1",
                "recipient_task_id": "tsk_30000003-0000-4000-8000-000000000013",
                "obligation_id": "obl_30000003-0000-4000-8000-000000000014",
            }
        )
        envelope["event_id"] = "evt_30000003-0000-4000-8000-00000000000b"
        envelope["operation_id"] = "req_30000003-0000-4000-8000-00000000000b"
        envelope["occurred_at"] = "2026-09-05T00:00:11.000Z"
        envelope["ledger"]["accepted_at"] = "2026-09-05T00:01:11.000Z"
        envelope["schema"] = {
            "name": "coordination_obligation_declared",
            "version": "1.0.0",
        }
        payload_ref = envelope["payload_ref"]
        payload_ref["object_id"] = "obj_30000003-0000-4000-8000-00000000006f"
        payload_ref["media_type"] = "application/vnd.yoetz.coordination_obligation_declared+json"
        payload_ref["plaintext_size"] = len(canonical_encode(payload))
        payload_ref["commitment"] = "hmac-sha256:" + "b" * 64
        declaration["canonical_payload_digest"] = canonical_digest(payload)
        envelope["entry_digest"] = entry_digest(
            {key: value for key, value in envelope.items() if key != "entry_digest"}
        )
        rows.append(declaration)
    expected_families = document["input"]["expected_event_families"]
    if "coordination_obligation_declared" not in expected_families:
        expected_families.insert(6, "coordination_obligation_declared")
    for row in rows:
        envelope = row["envelope"]
        if envelope["schema"]["name"] == "delegation_declared":
            payload = row["payload"]
            payload.update(
                {
                    "membership_generation": "7",
                    "project_id": "prj_30000003-0000-4000-8000-000000000012",
                }
            )
            row["canonical_payload_digest"] = canonical_digest(payload)
            envelope["payload_ref"]["plaintext_size"] = len(canonical_encode(payload))
        if envelope["schema"]["name"] == "coordination_obligation_declared":
            envelope["author"] = {
                "actor_id": "agent.fixture.primary",
                "actor_type": "logical_agent",
                "assurance": "self_asserted",
            }
            envelope["publication_channel"] = "cooperative_mcp"
            envelope["coverage"]["authorship_assurance"] = "self_asserted"
            envelope["coverage"]["publication_channels"] = ["cooperative_mcp"]
            envelope["entry_digest"] = entry_digest(
                {key: value for key, value in envelope.items() if key != "entry_digest"}
            )
            continue
        if envelope["schema"]["name"] not in {
            "delegation_declared",
            "child_dependencies_recorded",
            "work_abandoned",
        }:
            continue
        envelope["author"] = {
            "actor_id": "yoetz:observation-coordinator",
            "actor_type": "harness",
            "assurance": "harness_observed",
        }
        envelope["publication_channel"] = "hook_observed"
        envelope["coverage"]["authorship_assurance"] = "harness_observed"
        envelope["coverage"]["publication_channels"] = ["hook_observed"]
        preimage = {key: value for key, value in envelope.items() if key != "entry_digest"}
        envelope["entry_digest"] = entry_digest(preimage)
    path.write_bytes(canonical_encode(document))


def _refresh_manifest() -> None:
    manifest_path = _ROOT / "fixtures" / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    members: list[dict[str, Any]] = []
    fixture_root = _ROOT / "fixtures"
    for member in manifest["members"]:
        members.append(member)
    extra = [
        ("IMP-006", "imports/codex/rollout-legacy-0.148.0.case.json"),
        ("IMP-007", "imports/codex/rollout-paginated-0.148.0.case.json"),
        ("IMP-008", "imports/codex/rollout-truncated-0.148.0.case.json"),
        ("IMP-009", "imports/codex/rollout-zst-0.148.0.case.json"),
        ("IMP-011", "imports/codex/rollout-paginated-0.150.1.case.json"),
        ("IMP-012", "imports/codex/rollout-truncated-0.150.1.case.json"),
        ("IMP-013", "imports/codex/rollout-unsupported-0.152.1.case.json"),
        ("LINEAGE-001", "replay/lineage-event-families.case.json"),
        ("IMP-014", "imports/codex/rollout-compatible-0.153.4.case.json"),
        ("IMP-015", "imports/codex/rollout-multi-agent-v2-0.153.4.case.json"),
    ]
    by_path = {item["path"]: item for item in members}
    for fixture_id, rel in extra:
        data = (fixture_root / rel).read_bytes()
        by_path[rel] = {
            "byte_length": len(data),
            "fixture_id": fixture_id,
            "media_type": "application/vnd.yoetz.fixture-case+json",
            "path": rel,
            "sha256": _sha(data),
        }
    ordered = sorted(by_path.values(), key=lambda item: str(item["path"]).encode("ascii"))
    manifest["members"] = ordered
    manifest_path.write_bytes(json.dumps(manifest).encode("utf-8") + b"\n")


def _refresh_skill_manifest() -> None:
    path = _ROOT / "skills" / "codex" / "finishup" / "manifest.json"
    document = json.loads(path.read_bytes())
    document.update(dict(skill_manifest_capability_fields()))
    document.pop("member_digest", None)
    document["member_digest"] = canonical_digest(document)
    path.write_bytes(canonical_encode(document) + b"\n")


def main() -> None:
    legacy = _legacy()
    paginated = _paginated()
    truncated = encode_lines(session_meta(), terminated=True) + encode_lines(
        function_call(name="shell", call_id="partial"), terminated=False
    )
    compressed = b"\x28\xb5\x2f\xfd" + b"synthetic-zstd-frame-not-decoded-in-hook-pass"
    _write_case(
        "rollout-legacy-0.148.0.case.json",
        _case(
            fixture_id="IMP-006",
            purpose=(
                "Constructed 0.148.0 legacy-history rollout grammar lock for session-stream "
                "reconciliation. Not a live isolated codex-testing capture of skill/MCP/hooks."
            ),
            variants={"legacy": legacy},
            expected={"legacy": {"history_mode": "legacy", "unknown_count": 0}},
        ),
    )
    _write_case(
        "rollout-paginated-0.148.0.case.json",
        _case(
            fixture_id="IMP-007",
            purpose=(
                "Constructed 0.148.0 paginated-history rollout grammar lock for session-stream "
                "reconciliation. Not a live isolated codex-testing capture of skill/MCP/hooks."
            ),
            variants={"paginated": paginated},
            expected={"paginated": {"history_mode": "paginated", "unknown_count": 0}},
        ),
    )
    _write_case(
        "rollout-truncated-0.148.0.case.json",
        _case(
            fixture_id="IMP-008",
            purpose="Unterminated live-append rollout tail for incremental reader hold.",
            variants={"unterminated": truncated},
            expected={"unterminated": {"unknown_count": 0}},
        ),
    )
    _write_case(
        "rollout-zst-0.148.0.case.json",
        _case(
            fixture_id="IMP-009",
            purpose=(
                "Compressed rollout (.jsonl.zst) is a distinct unsupported_format gap; "
                "the hook pass never decompresses it."
            ),
            variants={"compressed": compressed},
            expected={"compressed": {"unknown_count": 0}},
        ),
    )
    current = _current_0_150_1()
    truncated_current = encode_lines(
        session_meta(cli_version="0.150.1", history_mode="paginated", ordinal=1),
        terminated=True,
    ) + encode_lines(
        item_completed({"id": "item_partial", "type": "AgentMessage"}, ordinal=2),
        terminated=False,
    )
    _write_case(
        "rollout-paginated-0.150.1.case.json",
        _case(
            fixture_id="IMP-011",
            cli_version="0.150.1",
            purpose=(
                "Constructed 0.150.1 paginated (current-mode) rollout grammar lock: every "
                "wrapper and item type the 0.150.1 profile admits appears exactly once or more, "
                "with hidden reasoning, system/developer prompts, and a secret canary present "
                "so privacy tests prove none reach observation envelopes. Not a live isolated "
                "codex-testing capture of skill/MCP/hooks; only paginated history was observed."
            ),
            variants={"paginated": current},
            expected={
                "paginated": {
                    "history_mode": "paginated",
                    "item_types": sorted(_ITEM_TYPES_0_150_1, key=str.encode),
                    "unknown_count": 0,
                    "wrapper_types": sorted(_WRAPPER_TYPES_0_150_1, key=str.encode),
                }
            },
            requirements=(
                "ADR-005/exact-profile-admission",
                "ISSUE-568/rollout-grammar-0.150.1",
            ),
        ),
    )
    _write_case(
        "rollout-truncated-0.150.1.case.json",
        _case(
            fixture_id="IMP-012",
            cli_version="0.150.1",
            purpose="Unterminated live-append 0.150.1 rollout tail for incremental reader hold.",
            variants={"unterminated": truncated_current},
            expected={"unterminated": {"unknown_count": 0}},
            requirements=(
                "ADR-005/exact-profile-admission",
                "ISSUE-568/rollout-grammar-0.150.1",
            ),
        ),
    )
    _write_case(
        "rollout-unsupported-0.152.1.case.json",
        _case(
            fixture_id="IMP-013",
            cli_version="0.152.1",
            profile_id="unsupported",
            purpose=(
                "A session header whose history_mode names no known structure is refused as "
                "unsupported_codex_profile regardless of its release label; no line maps and "
                "the stream reader keeps a durable refused cursor instead of losing position. "
                "Refusal is structural, never a version lookup (issue #656)."
            ),
            variants={"future": _unsupported_0_152_1()},
            expected={
                "future": {
                    "admitted": False,
                    "stream_gaps": ["unsupported_codex_profile"],
                    "unknown_count": 0,
                }
            },
            requirements=(
                "ADR-005/structural-admission",
                "ISSUE-656/incompatible-header-refused",
            ),
        ),
    )
    _write_case(
        "rollout-compatible-0.153.4.case.json",
        _case(
            fixture_id="IMP-014",
            cli_version=_COMPATIBLE_VERSION,
            profile_id=CODEX_ROLLOUT_COMPATIBLE_PROFILE_ID,
            purpose=(
                "Differential compatibility matrix for an unproven release label (0.153.4): the "
                "supported 0.150.1 structure relabeled, harmless additive fields, an unknown "
                "independent event, known wrappers with incompatible payload shapes, and a "
                "truncated tail. Every variant is constructed from the 0.150.1 grammar with "
                "canary values; no real 0.153.4 transcript was available, so this proves the "
                "admission policy, not the actual 0.153.4 event families (issue #656)."
            ),
            variants={
                "relabeled": _relabeled_0_153_4(),
                "additive": _additive_0_153_4(),
                "unknown_event": _unknown_event_0_153_4(),
                "incompatible_known": _incompatible_known_0_153_4(),
                "truncated": _truncated_0_153_4(),
            },
            expected={
                "relabeled": {
                    "admitted": True,
                    "provenance": "structural",
                    "stream_gaps": [],
                    "unknown_count": 0,
                    "unsupported_count": 0,
                },
                "additive": {
                    "admitted": True,
                    "provenance": "structural",
                    "stream_gaps": [],
                    "unknown_count": 0,
                    "unsupported_count": 0,
                },
                "unknown_event": {
                    "admitted": True,
                    "provenance": "structural",
                    "reason_codes": ["unknown_item_type", "unknown_wrapper_type"],
                    "stream_gaps": [],
                    "unknown_count": 2,
                    "unsupported_count": 0,
                },
                "incompatible_known": {
                    "admitted": True,
                    "provenance": "structural",
                    "reason_codes": ["wrapper_shape_unsupported"],
                    "stream_gaps": [],
                    "unknown_count": 0,
                    "unsupported_count": 2,
                },
                "truncated": {
                    "admitted": True,
                    "provenance": "structural",
                    "stream_gaps": ["final_newline_absent"],
                    "unknown_count": 0,
                    "unsupported_count": 0,
                },
            },
            requirements=(
                "ADR-005/structural-admission",
                "ISSUE-656/compatible-release-admitted",
            ),
        ),
    )
    _write_case(
        "rollout-multi-agent-v2-0.153.4.case.json",
        _case(
            fixture_id="IMP-015",
            cli_version=_COMPATIBLE_VERSION,
            profile_id=CODEX_ROLLOUT_COMPATIBLE_PROFILE_ID,
            purpose=(
                "Codex 0.153.4 multi-agent v2 record families, transcribed from a real v2 run's "
                "key shapes with canary values only (issue #754). The parent variant carries the "
                "spawn and a later interaction as event_msg.item_completed SubAgentActivity "
                "items, an agent_message with author/recipient paths, "
                "inter_agent_communication_metadata, token_usage_record, and the fractional "
                "leaves 0.153.4 added to agent_message and token_count. The child variants are "
                "the delegated child's own header: v2 names the delegation only there, and a "
                "header that declares a child without a distinct spawning thread is the one "
                "shape that earns missing_subagent_identity."
            ),
            variants={
                "parent": _multi_agent_v2_parent(),
                "child": _multi_agent_v2_child(),
                "child_without_identity": _multi_agent_v2_child_without_identity(),
            },
            expected={
                "parent": {
                    "admitted": True,
                    "provenance": "structural",
                    "stream_gaps": [],
                    "unknown_count": 0,
                    "unsupported_count": 0,
                    "subagent_start_count": 1,
                    "subagent_id": _V2_CHILD_THREAD,
                    "parent_tool_call_id": None,
                },
                "child": {
                    "admitted": True,
                    "provenance": "structural",
                    "stream_gaps": [],
                    "unknown_count": 0,
                    "unsupported_count": 0,
                    "subagent_start_count": 1,
                    "subagent_id": _V2_CHILD_THREAD,
                    "parent_tool_call_id": None,
                },
                "child_without_identity": {
                    "admitted": True,
                    "provenance": "structural",
                    "stream_gaps": [],
                    "unknown_count": 0,
                    "unsupported_count": 0,
                    "subagent_start_count": 1,
                    "subagent_id": None,
                    "gap_codes": ["missing_subagent_identity"],
                },
            },
            requirements=(
                "ADR-005/structural-admission",
                "ISSUE-754/multi-agent-v2-child-identity",
            ),
        ),
    )
    _refresh_lineage_fixture_service_provenance()
    _refresh_manifest()
    _refresh_skill_manifest()


if __name__ == "__main__":
    main()
