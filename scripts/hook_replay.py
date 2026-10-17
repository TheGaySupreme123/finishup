"""Replay recorded host hook payloads through FinishUP builds and compare what each did (#1083).

A build is replayed in its own disposable test instance (ADR-028, ``provision_test_instance.py``),
built from one exact revision, with its own service, synthetic vault, ledger and private ``HOME``.
The replay drives the instance's installed launcher exactly as a host does: one fresh process
per hook callback, the payload on stdin, the registered argv and working directory. It records
every exit code, stdout and stderr byte, the wall time of each callback, an ``observe drain``
after each one, and finally each workspace's ledger history read back through ``status``.
``compare`` then holds two records to byte equality after renaming only the values one run
generated and the other never saw (identifiers, timestamps, installation-keyed commitments).

Corpus sources:

* Codex: a recorded rollout (read-only). Each ``exec_command`` and FinishUP MCP call becomes the
  PreToolUse/PostToolUse pair Codex sends for it, in the shape pinned by
  ``fixtures/observations/codex-post-tool-outcomes-0.157.1.case.json``, preceded by SessionStart
  and UserPromptSubmit and followed by Stop and SessionEnd. ``transcript_path`` names a copy of the
  rollout that grows to the point the callback fired at. Calls with no recorded hook shape in this
  repository (``write_stdin``, ``view_image``, MCP resource listing) are left out.
* Claude Code and Cursor: the ordinary-profile session assembled from the repository's recorded
  shapes (``fixtures/observations/*-outcomes.case.json`` and the host test payloads).
* Malformed hook stdin for every host, and invalid workflow requests through the CLI, so the
  rejection paths are compared too.

``--mode pinned`` runs each callback through the retained interpreter with the hook budgets
raised equally for every build, so a build that is merely slower takes the same branch as a faster
one; that run is the equivalence proof. ``--mode shipped`` runs the launcher untouched and is the
latency measurement. Contributor tooling: it never targets an everyday installation, and every
instance process gets a scratch ``HOME``/``CODEX_HOME`` and a keyring backend that refuses all
access, so no host configuration or OS keychain is read.

Usage::

    hook_replay.py corpus --rollout <rollout.jsonl> [--rollout ...] --out corpus.json
    hook_replay.py replay --checkout <tree> --revision <sha> --tag <t> --corpus corpus.json \\
        --work-root <dir> --mode pinned --mode shipped --out old.json
    hook_replay.py compare old.json new.json [--report report.md]
    hook_replay.py latency --checkout <tree> --old-revision <sha> --new-revision <sha> --tag <t> \\
        --corpus corpus.json --work-root <dir> --out latency.json
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import os
import re
import secrets
import shutil
import statistics
import subprocess
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType
from typing import Any, Final, cast

_HERE: Final = Path(__file__).resolve().parent
_REPO: Final = _HERE.parent
_FIXTURES: Final = _REPO / "fixtures" / "observations"

type Item = dict[str, Any]

# ---------------------------------------------------------------------------------------- corpus

_CODEX_REPLAYED_MCP_NAMESPACES: Final = frozenset({"mcp__finishup", "mcp__yoetz"})
# Built-in tools with no hook shape recorded in this repository; replaying them would be invented.
_CODEX_UNRECORDED_TOOLS: Final = frozenset(
    {
        "write_stdin",
        "view_image",
        "list_mcp_resources",
        "list_mcp_resource_templates",
        "read_mcp_resource",
    }
)
_CWD_FIELDS: Final = {
    "session_meta": ("cwd", "runtime_workspace_roots"),
    "turn_context": ("cwd", "workspace_roots"),
}
WORKSPACE: Final = "{WORKSPACE}"
TRANSCRIPT: Final = "{TRANSCRIPT}"


def _fixture_hooks(name: str) -> tuple[str, dict[str, tuple[str, dict[str, Any]]]]:
    case = json.loads((_FIXTURES / name).read_text(encoding="utf-8"))
    hooks = {
        key: (cast(str, value["event"]), cast(dict[str, Any], value["payload"]))
        for key, value in case["input"]["hook"].items()
    }
    return cast(str, case["input"].get("observation_profile", "")), hooks


def _rehome(value: Any, original: str) -> Any:
    """Point a recorded workspace path at the replay workspace placeholder."""

    if isinstance(value, str):
        if value == original:
            return WORKSPACE
        if value.startswith(original + "/"):
            return WORKSPACE + value[len(original) :]
        return value
    if isinstance(value, list):
        return [_rehome(item, original) for item in cast(list[Any], value)]
    if isinstance(value, dict):
        return {key: _rehome(item, original) for key, item in cast(dict[str, Any], value).items()}
    return value


def _rollout_line(record: dict[str, Any], original_cwd: str) -> str:
    kind = record.get("type")
    fields = _CWD_FIELDS.get(cast(str, kind)) if isinstance(kind, str) else None
    if fields is not None:
        payload = dict(cast(dict[str, Any], record.get("payload", {})))
        for field in fields:
            if field in payload:
                payload[field] = _rehome(payload[field], original_cwd)
        record = {**record, "payload": payload}
    return json.dumps(record, ensure_ascii=False, separators=(",", ":"))


def _message_text(payload: Mapping[str, Any]) -> str:
    parts = [
        cast(str, part.get("text", ""))
        for part in cast(list[dict[str, Any]], payload.get("content") or [])
        if part.get("type") in {"input_text", "output_text"}
    ]
    return "".join(parts)


def mcp_tool_response(output: str) -> dict[str, Any]:
    """The MCP CallToolResult a hook receives, rebuilt from the rollout's flattened output text."""

    text = output
    marker = "\nOutput:\n"
    if text.startswith("Wall time:") and marker in text:
        text = text.split(marker, 1)[1]
    try:
        parsed: Any = json.loads(text)
    except ValueError:
        parsed = None
    response: dict[str, Any] = {"content": [{"text": text, "type": "text"}]}
    if isinstance(parsed, dict):
        response["isError"] = cast(dict[str, Any], parsed).get("ok") is False
        response["structuredContent"] = parsed
    else:
        response["isError"] = False
    return response


def codex_corpus(
    rollout_lines: Sequence[str], *, name: str, workspace: str, max_calls: int
) -> tuple[list[Item], list[str]]:
    """Codex hook callbacks reconstructed from one rollout, and the rollout prefix they read."""

    records = [cast(dict[str, Any], json.loads(line)) for line in rollout_lines if line.strip()]
    meta = next(r["payload"] for r in records if r.get("type") == "session_meta")
    turn = next(r["payload"] for r in records if r.get("type") == "turn_context")
    original_cwd = cast(str, meta.get("cwd") or turn.get("cwd"))
    session_id = cast(str, meta.get("id") or meta["session_id"])
    sandbox = cast(dict[str, Any], turn.get("sandbox_policy") or {}).get("type")
    permission_mode = (
        "bypassPermissions"
        if turn.get("approval_policy") == "never" and sandbox == "danger-full-access"
        else "default"
    )
    base: dict[str, Any] = {
        "cwd": WORKSPACE,
        "model": turn.get("model"),
        "permission_mode": permission_mode,
        "session_id": session_id,
        "transcript_path": TRANSCRIPT,
    }
    turn_id = cast(str, turn.get("turn_id"))
    observe = ["hooks", "observe", "--workspace", "."]
    items: list[Item] = []

    def add(label: str, argv: list[str], payload: Mapping[str, Any], upto: int) -> None:
        items.append(
            {
                "label": f"codex/{name}/{len(items):03d}/{label}",
                "host": "codex",
                "workspace": workspace,
                "cwd": WORKSPACE,
                "argv": argv,
                "stdin": json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
                "transcript": {"name": name, "upto": upto},
            }
        )

    add(
        "SessionStart",
        [*observe, "--event", "SessionStart"],
        {**base, "hook_event_name": "SessionStart", "source": "startup"},
        1,
    )
    prompt_index = next(
        index
        for index, record in enumerate(records)
        if record.get("type") == "response_item"
        and record["payload"].get("type") == "message"
        and record["payload"].get("role") == "user"
        # Host-written context (``<environment_context>``, ``<hook_prompt ...>``) is not the prompt.
        and not _message_text(record["payload"]).startswith("<")
    )
    add(
        "UserPromptSubmit",
        ["hooks", "user-prompt-submit", "--workspace", "."],
        {
            **base,
            "hook_event_name": "UserPromptSubmit",
            "prompt": _message_text(records[prompt_index]["payload"]),
            "turn_id": turn_id,
        },
        prompt_index,
    )
    outputs = {
        cast(str, record["payload"]["call_id"]): index
        for index, record in enumerate(records)
        if record.get("type") == "response_item"
        and record["payload"].get("type") == "function_call_output"
    }
    # A callback fires where its rollout line lands: Pre at the call, Post at the output. Parallel
    # calls therefore see both Pre callbacks before either Post, as Codex delivers them.
    callbacks: list[tuple[int, int, str, list[str], dict[str, Any]]] = []
    replayed = 0
    last = prompt_index + 1
    for index, record in enumerate(records):
        payload = cast(dict[str, Any], record.get("payload") or {})
        if replayed >= max_calls:
            break
        if record.get("type") != "response_item" or payload.get("type") != "function_call":
            continue
        call_name = cast(str, payload.get("name"))
        namespace = payload.get("namespace")
        output_index = outputs.get(cast(str, payload.get("call_id")))
        if output_index is None or call_name in _CODEX_UNRECORDED_TOOLS:
            continue
        arguments = json.loads(cast(str, payload.get("arguments") or "{}"))
        output = cast(str, records[output_index]["payload"].get("output") or "")
        if call_name == "exec_command" and namespace is None:
            tool_name = "Bash"
            tool_input: Any = {"command": arguments.get("cmd")}
            tool_response: Any = output
        elif namespace in _CODEX_REPLAYED_MCP_NAMESPACES:
            tool_name = f"{namespace}__{call_name}"
            tool_input = arguments
            tool_response = mcp_tool_response(output)
        else:
            continue
        call = {
            **base,
            "tool_input": tool_input,
            "tool_name": tool_name,
            "tool_use_id": payload.get("call_id"),
            "turn_id": turn_id,
        }
        pre_argv = [*observe, "--event", "PreToolUse"]
        callbacks.append(
            (
                index + 1,
                len(callbacks),
                f"PreToolUse/{tool_name}",
                pre_argv,
                {**call, "hook_event_name": "PreToolUse"},
            )
        )
        post = {**call, "hook_event_name": "PostToolUse", "tool_response": tool_response}
        if tool_name.endswith("__start"):
            callbacks.append(
                (
                    output_index + 1,
                    len(callbacks),
                    "PostToolUse/start-correlation",
                    ["hooks", "post-tool-use"],
                    post,
                )
            )
        post_argv = [*observe, "--event", "PostToolUse"]
        callbacks.append(
            (output_index + 1, len(callbacks), f"PostToolUse/{tool_name}", post_argv, post)
        )
        replayed += 1
        last = max(last, output_index + 1)
    for upto, _sequence, label, argv, payload in sorted(callbacks, key=lambda c: (c[0], c[1])):
        add(label, argv, payload, upto)
    last_message = ""
    for record in records[:last]:
        payload = cast(dict[str, Any], record.get("payload") or {})
        if (
            record.get("type") == "response_item"
            and payload.get("type") == "message"
            and payload.get("role") == "assistant"
        ):
            last_message = _message_text(payload)
    add(
        "Stop",
        [*observe, "--event", "Stop"],
        {
            **base,
            "hook_event_name": "Stop",
            "last_assistant_message": last_message,
            "stop_hook_active": False,
            "turn_id": turn_id,
        },
        last,
    )
    add(
        "SessionEnd",
        [*observe, "--event", "SessionEnd"],
        {**base, "hook_event_name": "SessionEnd"},
        last,
    )
    transcript = [_rollout_line(record, original_cwd) for record in records[:last]]
    return items, transcript


def _native_items(
    host: str,
    workspace: str,
    carrier: Callable[[str], list[str]],
    sequence: Sequence[tuple[str, Mapping[str, Any]]],
) -> list[Item]:
    items: list[Item] = []
    for event, payload in sequence:
        argv = (
            ["hooks", "startup-context", "--host", host]
            if event == "startup-context"
            else carrier(event)
        )
        items.append(
            {
                "label": f"{host}/{len(items):03d}/{event}",
                "host": host,
                "workspace": workspace,
                "cwd": WORKSPACE,
                "argv": argv,
                "stdin": json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
                "transcript": None,
            }
        )
    return items


def claude_corpus(workspace: str = "claude") -> list[Item]:
    """An ordinary-profile Claude Code session from the repository's recorded shapes."""

    profile, hooks = _fixture_hooks("claude-code-bash-outcomes.case.json")
    ok = _rehome(hooks["post_tool_use_bash"][1], "/workspace/project")
    failed = _rehome(hooks["post_tool_use_failure_bash"][1], "/workspace/project")
    interrupted = _rehome(hooks["post_tool_use_failure_bash_interrupted"][1], "/workspace/project")
    session = cast(str, ok["session_id"])
    common = {"cwd": WORKSPACE, "session_id": session, "transcript_path": TRANSCRIPT}

    def pre(post: Mapping[str, Any]) -> dict[str, Any]:
        keep = ("cwd", "permission_mode", "session_id", "tool_input", "tool_name", "tool_use_id")
        return {**{k: post[k] for k in keep}, "hook_event_name": "PreToolUse"}

    read = {
        "cwd": WORKSPACE,
        "permission_mode": "default",
        "session_id": session,
        "tool_input": {"file_path": f"{WORKSPACE}/README.md"},
        "tool_name": "Read",
        "tool_use_id": "toolu_01REPLAYREAD",
    }
    edit = {
        "cwd": WORKSPACE,
        "permission_mode": "default",
        "session_id": session,
        "tool_input": {
            "file_path": f"{WORKSPACE}/src/app.py",
            "new_string": "PLACEHOLDER_NEW",
            "old_string": "PLACEHOLDER_OLD",
        },
        "tool_name": "Edit",
        "tool_use_id": "toolu_01REPLAYEDIT",
    }
    mcp = {
        "cwd": WORKSPACE,
        "permission_mode": "default",
        "session_id": session,
        "tool_input": {"view": "compact"},
        "tool_name": "mcp__finishup__status",
        "tool_use_id": "toolu_01REPLAYMCP",
    }
    start = {**common, "hook_event_name": "SessionStart", "source": "startup"}
    sequence: list[tuple[str, Mapping[str, Any]]] = [
        ("startup-context", start),
        ("SessionStart", start),
        (
            "PermissionRequest",
            {
                **common,
                "hook_event_name": "PermissionRequest",
                "permission_mode": "default",
                "tool_input": ok["tool_input"],
                "tool_name": "Bash",
            },
        ),
        ("PreToolUse", pre(ok)),
        ("PostToolUse", ok),
        ("PreToolUse", pre(failed)),
        ("PostToolUseFailure", failed),
        ("PreToolUse", pre(interrupted)),
        ("PostToolUseFailure", interrupted),
        ("PreToolUse", {**read, "hook_event_name": "PreToolUse"}),
        (
            "PostToolUse",
            {
                **read,
                "hook_event_name": "PostToolUse",
                "tool_response": {
                    "file": {
                        "content": "PLACEHOLDER_CONTENT",
                        "filePath": f"{WORKSPACE}/README.md",
                        "numLines": 1,
                        "startLine": 1,
                        "totalLines": 1,
                    },
                    "type": "text",
                },
            },
        ),
        ("PreToolUse", {**edit, "hook_event_name": "PreToolUse"}),
        (
            "PostToolUse",
            {
                **edit,
                "hook_event_name": "PostToolUse",
                "tool_response": {
                    "filePath": f"{WORKSPACE}/src/app.py",
                    "newString": "PLACEHOLDER_NEW",
                    "oldString": "PLACEHOLDER_OLD",
                    "replaceAll": False,
                    "structuredPatch": [],
                    "userModified": False,
                },
            },
        ),
        ("PreToolUse", {**mcp, "hook_event_name": "PreToolUse"}),
        (
            "PostToolUse",
            {
                **mcp,
                "hook_event_name": "PostToolUse",
                "tool_response": {"content": [{"text": "ok", "type": "text"}]},
            },
        ),
        (
            "PermissionDenied",
            {
                **common,
                "hook_event_name": "PermissionDenied",
                "permission_mode": "auto",
                "reason": "classifier_denied",
                "tool_input": {"mode": "deterministic_only"},
                "tool_name": "mcp__finishup__check",
                "tool_use_id": "toolu_01REPLAYDENIED",
            },
        ),
        (
            "Stop",
            {
                **common,
                "hook_event_name": "Stop",
                "last_assistant_message": "PLACEHOLDER_MESSAGE",
                "permission_mode": "default",
                "stop_hook_active": False,
            },
        ),
        ("StopFailure", {**common, "hook_event_name": "StopFailure"}),
        ("SessionEnd", {**common, "hook_event_name": "SessionEnd", "reason": "other"}),
    ]

    def carrier(event: str) -> list[str]:
        return [
            "hooks",
            "claude-observe",
            "--workspace",
            WORKSPACE,
            "--event",
            event,
            "--observation-profile",
            profile,
        ]

    return _native_items("claude", workspace, carrier, sequence)


def cursor_corpus(workspace: str = "cursor") -> list[Item]:
    """An ordinary-profile Cursor session from the repository's recorded shapes."""

    profile, hooks = _fixture_hooks("cursor-shell-outcomes.case.json")
    exit_2 = _rehome(hooks["post_tool_use_shell_with_exit_code"][1], "/workspace/project")
    no_exit = _rehome(hooks["post_tool_use_shell_without_exit_code"][1], "/workspace/project")
    failure = _rehome(hooks["post_tool_use_failure_shell"][1], "/workspace/project")
    conversation = cast(str, exit_2["conversation_id"])
    common = {
        "conversation_id": conversation,
        "cursor_version": exit_2["cursor_version"],
        "generation_id": exit_2["generation_id"],
        "workspace_roots": [WORKSPACE],
    }

    def pre(post: Mapping[str, Any]) -> dict[str, Any]:
        keep = (
            "conversation_id",
            "cursor_version",
            "cwd",
            "generation_id",
            "model",
            "tool_input",
            "tool_name",
            "tool_use_id",
            "workspace_roots",
        )
        return {**{k: post[k] for k in keep}, "hook_event_name": "preToolUse"}

    start = {**common, "hook_event_name": "sessionStart"}
    mcp_call = {
        **common,
        "cwd": WORKSPACE,
        "model": "PLACEHOLDER_MODEL",
        "tool_input": {"view": "compact"},
        "tool_name": "mcp__finishup__status",
        "tool_use_id": "cursor-call-replay-mcp",
    }
    sequence: list[tuple[str, Mapping[str, Any]]] = [
        ("startup-context", start),
        ("sessionStart", start),
        ("preToolUse", pre(exit_2)),
        ("postToolUse", exit_2),
        ("preToolUse", pre(no_exit)),
        ("postToolUse", no_exit),
        ("preToolUse", pre(failure)),
        ("postToolUseFailure", failure),
        ("preToolUse", {**mcp_call, "hook_event_name": "preToolUse"}),
        (
            "postToolUse",
            {**mcp_call, "hook_event_name": "postToolUse", "tool_output": '{"ok":true}'},
        ),
        (
            "afterMCPExecution",
            {
                **common,
                "hook_event_name": "afterMCPExecution",
                "model_id": "PLACEHOLDER_MODEL",
                "result_json": '{"ok":true}',
                "tool_input": '{"view":"compact"}',
                "tool_name": "mcp__finishup__status",
            },
        ),
        ("stop", {**common, "hook_event_name": "stop", "loop_count": 0, "status": "completed"}),
        ("sessionEnd", {**common, "hook_event_name": "sessionEnd", "reason": "user_close"}),
    ]

    def carrier(event: str) -> list[str]:
        return [
            "hooks",
            "cursor-observe",
            "--workspace",
            ".",
            "--event",
            event,
            "--observation-profile",
            profile,
        ]

    return _native_items("cursor", workspace, carrier, sequence)


def invalid_hook_items(
    host: str, workspace: str, carrier: Callable[[str], list[str]]
) -> list[Item]:
    """Malformed hook stdin each host carrier must refuse the same way in every build."""

    pre, post = ("preToolUse", "postToolUse") if host == "cursor" else ("PreToolUse", "PostToolUse")
    session_key = "conversation_id" if host == "cursor" else "session_id"
    session = {session_key: f"replay-invalid-{host}"}
    good = {
        **session,
        "cwd": WORKSPACE,
        "hook_event_name": post,
        "tool_input": {"command": "true"},
        "tool_name": "Shell" if host == "cursor" else "Bash",
        "tool_use_id": f"replay-invalid-{host}-call",
    }
    cases: list[tuple[str, str, str]] = [
        ("empty-stdin", pre, ""),
        ("not-json", pre, "{not json"),
        ("json-array", pre, "[]"),
        (
            "wrong-types",
            pre,
            json.dumps({session_key: 7, "hook_event_name": [pre], "tool_name": {"x": 1}}),
        ),
        ("event-mismatch", pre, json.dumps(good)),
        (
            "unknown-event",
            "NotARealEvent",
            json.dumps({**good, "hook_event_name": "NotARealEvent"}),
        ),
        (
            "control-characters",
            post,
            json.dumps({**good, "tool_name": "Ba\nsh", "tool_use_id": "bad\u0000\u0007id"}),
        ),
        ("missing-session", post, json.dumps({k: v for k, v in good.items() if k != session_key})),
        (
            "oversized",
            post,
            json.dumps({**good, "tool_response": "x" * (3 * 1024 * 1024)}),
        ),
    ]
    return [
        {
            "label": f"{host}/invalid/{label}",
            "host": host,
            "workspace": workspace,
            "cwd": WORKSPACE,
            "argv": carrier(event),
            "stdin": stdin,
            "transcript": None,
        }
        for label, event, stdin in cases
    ]


_CLI_SESSION: Final = "ses_00000000-0000-4000-8000-0000000000a1"
_CLI_WRITER: Final = "wri_00000000-0000-4000-8000-0000000000a1"


def cli_items(workspace: str = "cli") -> list[Item]:
    """Workflow requests the client must reject, with the exact structured reason, in every build."""

    def request(number: int, **fields: Any) -> dict[str, Any]:
        return {
            "actor": {"actor_id": "harness:hook-replay", "actor_type": "harness"},
            "client": {"integration": "local_cli", "kind": "yoetz_cli", "version": "0.3.0"},
            "protocol_version": "0.1",
            "request_id": f"req_00000000-0000-4000-8000-{number:012d}",
            "schema_version": "1.0.0",
            **fields,
        }

    ids = {"session_id": _CLI_SESSION, "writer_id": _CLI_WRITER}
    frontier = {"head_digest": "sha256:" + "0" * 64, "sequence": "1"}
    draft = {
        "artifact_refs": [],
        "causal_parents": [],
        "event_id": "evt_00000000-0000-4000-8000-0000000000e1",
        "evidence_refs": [],
        "occurred_at": "2026-10-16T00:00:00.000Z",
    }
    cases: list[tuple[str, list[str], dict[str, Any]]] = [
        (
            "status-missing-writer",
            ["status"],
            request(1, session_id=_CLI_SESSION, view="compact", limit="10"),
        ),
        (
            "status-forbidden-filter",
            ["status"],
            request(
                2,
                **ids,
                view="compact",
                limit="10",
                filter={"operation_request_id": "req_00000000-0000-4000-8000-000000000099"},
            ),
        ),
        (
            "start-unpaired-workspace-ref",
            ["start"],
            request(
                3,
                mode="create_or_attach",
                requested_view="compact",
                task_title="replay",
                workspace_ref="/replay",
            ),
        ),
        (
            "publish-missing-payload-field",
            ["publish-work"],
            request(
                4,
                **ids,
                expected_frontier=frontier,
                event_drafts=[
                    {
                        **draft,
                        "payload": {"plan_version": 1, "summary": "replay"},
                        "schema": {"name": "plan_published", "version": "1.0.0"},
                    }
                ],
            ),
        ),
        (
            "publish-misplaced-field",
            ["publish-work"],
            request(
                5,
                **ids,
                expected_frontier=frontier,
                event_drafts=[
                    {
                        **draft,
                        "payload": {
                            "attempted_items": ["pytest -q"],
                            "claim_id": "clm_00000000-0000-4000-8000-0000000000c1",
                            "claim_kind": "completion",
                            "statement": "replay",
                            "supporting_refs": [],
                        },
                        "schema": {"name": "claim_recorded", "version": "1.0.0"},
                    }
                ],
            ),
        ),
        (
            "publish-conditional-subject",
            ["publish-work"],
            request(
                6,
                **ids,
                expected_frontier=frontier,
                event_drafts=[
                    {
                        **draft,
                        "payload": {
                            "content_digest": "sha256:" + "1" * 64,
                            "digest_binding": {
                                "byte_count": 1,
                                "content_availability": "digest_only",
                                "provenance": "caller_asserted",
                                "subject": "source_diff",
                            },
                            "evidence_id": "evd_00000000-0000-4000-8000-0000000000d1",
                            "evidence_kind": "test_result",
                            "observed_at": "2026-10-16T00:00:00.000Z",
                            "strength": "content_digest",
                        },
                        "schema": {"name": "evidence_recorded", "version": "1.1.0"},
                    }
                ],
            ),
        ),
        ("check-bad-mode", ["check"], request(7, **ids, expected_frontier=frontier, mode="always")),
        (
            "receipt-bad-format",
            ["receipt"],
            request(
                8,
                **ids,
                expected_frontier=frontier,
                format="pdf",
                include="standard",
                redaction_profile="default_local_export",
                task_id="tsk_00000000-0000-4000-8000-0000000000f1",
            ),
        ),
    ]
    return [
        {
            "label": f"cli/invalid/{label}",
            "host": "cli",
            "workspace": workspace,
            "cwd": WORKSPACE,
            "argv": [*command, "--input", "-", "--json"],
            "stdin": json.dumps(body, separators=(",", ":")),
            "transcript": None,
        }
        for label, command, body in cases
    ]


_PROBE: Final = (
    "import json, sys\n"
    "from finishup.protocol import schemas\n"
    "spec = json.loads(sys.stdin.read())\n"
    "try:\n"
    "    schemas.validate_schema_instance(spec['name'], spec['version'], spec['value'])\n"
    "    out = {'outcome': 'accepted'}\n"
    "except schemas.SchemaInstanceInvalid as error:\n"
    "    out = {'outcome': type(error).__name__, 'reason_code': error.reason_code,\n"
    "           'absolute_path': list(error.absolute_path),\n"
    "           'location_reasons': [[list(p), r] for p, r in error.location_reasons],\n"
    "           'reason': error.reason, 'family': error.family,\n"
    "           'family_version': error.family_version, 'unknown_count': error.unknown_count,\n"
    "           'misplaced_field': error.misplaced_field,\n"
    "           'missing_fields': list(error.missing_fields),\n"
    "           'condition_field': error.condition_field,\n"
    "           'condition_value': error.condition_value}\n"
    "except Exception as error:\n"
    "    out = {'outcome': type(error).__name__, 'reason_code': getattr(error, 'reason_code', None)}\n"
    "print(json.dumps(out, sort_keys=True))\n"
)
# The newest request schema of each workflow method at the replayed revisions.
_PROBE_VERSIONS: Final = {
    "check-request": "1.1.0",
    "publish-work-request": "1.2.0",
    "receipt-request": "1.0.0",
    "start-request": "1.1.0",
    "status-request": "1.2.0",
}


def probe_items(workspace: str = "cli") -> list[Item]:
    """Schema validation in a fresh installed-client process, every error field printed.

    One process per case, so each rejection is decided from a cold start, as a hook decides it.
    """

    by_command = {
        "check": "check-request",
        "publish-work": "publish-work-request",
        "receipt": "receipt-request",
        "start": "start-request",
        "status": "status-request",
    }
    cases: list[tuple[str, str, str, Any]] = []
    for item in cli_items(workspace):
        name = by_command[item["argv"][0]]
        label = cast(str, item["label"]).rsplit("/", 1)[1]
        cases.append((label, name, _PROBE_VERSIONS[name], json.loads(item["stdin"])))
    coverage = {
        "artifact_observation": "published_only",
        "authorship_assurance": "self_asserted",
        "check_types": ["none"],
        "evidence_immutability": "content_digest",
        "known_gaps": [],
        "ledger_freshness": "current",
        "publication_channels": ["cooperative_mcp"],
    }
    hello = {
        "client_kind": "cli",
        "client_version": "0.3.0",
        "connection_nonce": "a" * 64,
        "protocol_version": "1.0",
        "schema_manifest_digest": "sha256:" + "0" * 64,
    }
    cases += [
        ("coverage-valid", "coverage", "1.0.0", coverage),
        ("coverage-extra", "coverage", "1.0.0", {**coverage, "extra": True}),
        ("coverage-empty-channels", "coverage", "1.0.0", {**coverage, "publication_channels": []}),
        ("coverage-duplicate", "coverage", "1.0.0", {**coverage, "check_types": ["none", "none"]}),
        ("frontier-missing-digest", "frontier", "1.0.0", {"sequence": "3"}),
        ("public-error-empty", "public-error", "1.0.0", {}),
        ("control-hello-valid", "control-hello", "2.9.0", hello),
        ("control-hello-missing", "control-hello", "2.9.0", {"protocol_version": "1.0"}),
        ("float-value", "coverage", "1.0.0", {"value": 1.5}),
        ("unknown-schema", "not-a-schema", "1.0.0", {}),
        ("bad-version", "coverage", "1.0", {}),
    ]
    return [
        {
            "label": f"probe/{label}",
            "host": "probe",
            "workspace": workspace,
            "cwd": WORKSPACE,
            "argv": ["probe", name],
            "runner": "python",
            "stdin": json.dumps({"name": name, "value": value, "version": version}),
            "transcript": None,
        }
        for label, name, version, value in cases
    ]


def _codex_carrier(event: str) -> list[str]:
    return ["hooks", "observe", "--workspace", ".", "--event", event]


def build_corpus(rollouts: Sequence[Path], max_calls: int) -> dict[str, Any]:
    items: list[Item] = []
    transcripts: dict[str, dict[str, Any]] = {}
    for index, rollout in enumerate(rollouts):
        name = f"codex{index + 1}"
        lines = rollout.read_text(encoding="utf-8").splitlines()
        codex, transcript = codex_corpus(lines, name=name, workspace=name, max_calls=max_calls)
        items.extend(codex)
        transcripts[name] = {"file": rollout.name, "lines": transcript, "source": str(rollout)}
    items.extend(invalid_hook_items("codex", "codex1", _codex_carrier))
    claude = claude_corpus()
    items.extend(claude)
    items.extend(invalid_hook_items("claude", "claude", lambda e: _replace_event(claude[1], e)))
    cursor = cursor_corpus()
    items.extend(cursor)
    items.extend(invalid_hook_items("cursor", "cursor", lambda e: _replace_event(cursor[1], e)))
    items.extend(cli_items())
    items.extend(probe_items())
    return {"schema": "finishup.hook-replay-corpus/1", "items": items, "transcripts": transcripts}


def _replace_event(item: Item, event: str) -> list[str]:
    argv = list(cast(list[str], item["argv"]))
    argv[argv.index("--event") + 1] = event
    return argv


# ------------------------------------------------------------------------------------- execution

# Experiment control, pinned mode only and identical for every build (``--admission-clock``).
# The local admission buffer holds routine reads and pending attempts and flushes one once it is
# ``SUMMARY_FLUSH_MS`` (2 s) or ``PENDING_ATTEMPT_FLUSH_MS`` (5 s) old by the wall clock
# (``observation_admission.flush_admission``), so whether a held row is delivered at one callback
# or a later one depends on how fast the machine ran. ``held`` never makes a row due by age (only
# a forced flush at a material boundary, Stop, SessionStart or SessionEnd releases it); ``due``
# makes every held row due at the next flush. Either way that decision no longer reads the clock.
ADMISSION_CLOCKS: Final[Mapping[str, int]] = {"held": 10**15, "due": 0}
_ADMISSION_CLOCK_CONTROL: Final = (
    "clock = os.environ.get('HOOK_REPLAY_ADMISSION_CLOCK')\n"
    "if clock:\n"
    "    from finishup.adapters.integrations import observation_admission as _admission\n"
    "    for _name in ('SUMMARY_FLUSH_MS', 'PENDING_ATTEMPT_FLUSH_MS'):\n"
    "        if not hasattr(_admission, _name):\n"
    "            raise SystemExit('hook_replay_admission_unknown:' + _name)\n"
    "        setattr(_admission, _name, int(clock))\n"
)
# Experiment control, pinned mode only and identical for every build (``--fixed-observation-key``).
# Every keyed observation value (workspace, session and command commitments, and through them the
# ``hook:``/``stream:`` source identities and each failed command's advice ``detail_token``) is
# keyed by one random 32-byte file, ``<state>/observation/key-material.bin``, made on first use.
# Equal-priority advice candidates are ordered by that token, so with two unresolved failures
# which one an instance advises first is decided by its random key. This control writes the same
# fixed key into each disposable instance before its first service start, through the product's
# own ``observation_local._atomic_write``; it refuses a path outside the instance or an existing
# key. A test value only: never use it outside a disposable instance.
FIXED_OBSERVATION_KEY: Final = hashlib.sha256(b"finishup.hook-replay.observation-key/1").digest()
_SEED_OBSERVATION_KEY: Final = (
    "import json, sys\n"
    "from pathlib import Path\n"
    "spec = json.loads(sys.stdin.read())\n"
    "root = Path(spec['instance_root']).resolve(strict=True)\n"
    "from finishup.adapters.integrations import observation_local\n"
    "path = observation_local.observation_dir() / 'key-material.bin'\n"
    "if root not in path.resolve().parents:\n"
    "    raise SystemExit('seed_path_outside_instance')\n"
    "if path.exists():\n"
    "    raise SystemExit('seed_key_exists')\n"
    "observation_local._atomic_write(path, bytes.fromhex(spec['key']))\n"
    "print(json.dumps({'ok': True}))\n"
)
# Raised equally in every replayed build: a slower build then takes the branch a faster one takes.
PINNED_HOOK_BUDGETS: Final[Mapping[str, float | int]] = {
    "_AUTO_ATTACH_RETRY_BUDGET_SECONDS": 30.0,
    "_AUTO_ATTACH_RETRY_SERVICE_START_BUDGET_SECONDS": 30.0,
    "_HOOK_CONNECT_PREFLIGHT_SECONDS": 30.0,
    "_HOOK_DRAIN_BUDGET_SECONDS": 30.0,
    "_HOOK_DRAIN_ROW_LIMIT": 100_000,
    "_HOOK_LOCAL_STAGE_ALLOWANCE_SECONDS": 120.0,
    "_HOOK_SERVICE_START_BUDGET_SECONDS": 30.0,
    "_NATIVE_CONTENT_DRAIN_BUDGET_SECONDS": 30.0,
    "_NATIVE_CONTENT_ROW_LIMIT": 100_000,
    "_SESSION_END_DRAIN_BUDGET_SECONDS": 30.0,
    "_STOP_DRAIN_BUDGET_SECONDS": 30.0,
    "_STOP_DRAIN_ROW_LIMIT": 100_000,
    "_STOP_DRAIN_STALL_SECONDS": 30.0,
    "_STOP_PASS_BUDGET_SECONDS": 120.0,
}
# The release-runtime bootstrap (``adapters/release_runtime.py``) plus the pins above.
_PINNED_BOOTSTRAP: Final = (
    "import json, os, sys\n"
    "trace = os.environ.get('HOOK_REPLAY_CATALOG_TRACE')\n"
    "if trace:\n"
    "    import atexit\n"
    "    def _catalog_trace():\n"
    "        schemas = sys.modules.get('finishup.protocol.schemas')\n"
    "        if schemas is None:\n"
    "            row = {'full_catalog_built': False, 'lazy_documents': None}\n"
    "        else:\n"
    "            slot = getattr(schemas, '_lazy_catalog_slot', None) or [(None, None)]\n"
    "            lazy = slot[0][1]\n"
    "            built = schemas._load_catalog_state.cache_info().currsize > 0\n"
    "            count = None if lazy is None else len(lazy._plain)\n"
    "            row = {'full_catalog_built': built, 'lazy_documents': count}\n"
    "        with open(trace, 'a') as handle:\n"
    "            handle.write(json.dumps(row) + '\\n')\n"
    "    atexit.register(_catalog_trace)\n"
    + _ADMISSION_CLOCK_CONTROL
    + "from finishup.cli import observe_hooks\n"
    "for name, value in json.loads(os.environ['HOOK_REPLAY_PINS']).items():\n"
    "    if not hasattr(observe_hooks, name):\n"
    "        raise SystemExit('hook_replay_pin_unknown:' + name)\n"
    "    setattr(observe_hooks, name, value)\n"
    "delay = float(os.environ.get('HOOK_REPLAY_DELAY_SECONDS') or 0)\n"
    "if delay > 0:\n"
    "    import time\n"
    "    time.sleep(delay)\n"
    "sys.argv = sys.argv[1:]\n"
    "from finishup.cli.entry import main\n"
    "main()\n"
)
# Pinned mode only, identically for every build: the service's background observation sweep,
# lineage recovery and coordination retry run on their own timers and race each callback's own
# delivery, so the order in which hook and session-stream rows reach the ledger (and the advice
# that follows from it) would depend on scheduling. Paused, every row is delivered by the
# callback itself or by the ``observe drain`` that follows it, in replay order.
_SERVICE_BOOTSTRAP: Final = (
    "import os, sys\n" + _ADMISSION_CLOCK_CONTROL + "from finishup.service import daemon\n"
    "async def _paused(self, *args, **kwargs):\n"
    "    return None\n"
    "for name in ('_bounded_observation_sweep', '_bounded_lineage_recovery',\n"
    "             '_bounded_coordination_sweep'):\n"
    "    if not hasattr(daemon.ServiceDaemon, name):\n"
    "        raise SystemExit('hook_replay_service_hook_unknown:' + name)\n"
    "    setattr(daemon.ServiceDaemon, name, _paused)\n"
    "sys.argv = sys.argv[1:]\n"
    "from finishup.cli.entry import main\n"
    "main()\n"
)
# The isolated-store ledger reader: run under one instance's own retained interpreter after its
# service has stopped, it reads every accepted event of every task bundle in that instance and
# the payload object each event binds. It only reads: the bundle databases through the product's
# authorizer-guarded read-only connection, the payload objects through the product's own
# authenticated decryption, and the vault through an unlock with the passphrase this replay set
# (passed on stdin, never written). Every path it opens must resolve inside the instance root,
# so it can never read another installation. Any failed check makes it exit nonzero with the
# reason; a partial export is never printed as a success.
_LEDGER_EXPORT: Final = r"""
import asyncio, hashlib, json, os, sys
from pathlib import Path


class ExportFailure(Exception):
    pass


def require(condition, reason):
    if not condition:
        raise ExportFailure(reason)


async def export(spec):
    from finishup.adapters.keys.encrypted_vault import EncryptedVaultStore
    from finishup.adapters.keys.secret_memory import LocalSecretMemory
    from finishup.adapters.objects.encrypted_files import EncryptedFilesObjectStore
    from finishup.adapters.sqlite.connection import open_read_only
    from finishup.config import paths
    from finishup.config.installation import read_instance_identity
    from finishup.config.load import load_config
    from finishup.ports.secret_memory import SecretPurpose
    from finishup.protocol.canonical import (
        canonical_digest, canonical_encode, entry_digest, strict_json_parse,
    )
    from finishup.service import daemon
    from finishup.service.installation_recovery import InstallationRecoverySetStore
    from finishup.service.vault import VaultMode, VaultService

    root = Path(spec["instance_root"]).resolve(strict=True)

    def inside(path):
        resolved = Path(path).resolve()
        return resolved == root or root in resolved.parents

    isolated = paths.isolated_root()
    require(isolated is not None and inside(isolated), "export_root_not_isolated")
    config = load_config({}, os.environ, None)
    bundle = paths.bundle_root(_data_dir=config.storage.data_dir)
    state = paths.state_dir()
    throttle = paths.unlock_throttle_path()
    generation = paths.service_generation_path()
    for path in (bundle, state, throttle, generation):
        require(inside(path), "export_path_outside_instance")
    identity = read_instance_identity(state)
    require(identity is not None, "export_instance_identity_missing")
    markers = daemon._InstallationStateStore(
        bundle / daemon._INSTALLATION_MARKER_NAME,
        throttle,
        generation,
        InstallationRecoverySetStore(bundle),
        instance_installation_id=identity.installation_id,
    )
    marker = markers.load(reconcile=False)
    require(marker is not None, "export_installation_marker_missing")
    require(marker.vault_mode is VaultMode.PASSPHRASE, "export_vault_not_passphrase")
    memory = LocalSecretMemory()
    vault = VaultService(
        installation_id=markers.select_installation_id(marker),
        service_generation=1,
        mode=marker.vault_mode,
        secret_memory=memory,
        clock=daemon._SystemClock(),
        vault_store_factory=lambda: EncryptedVaultStore(bundle / "vault"),
        root_envelope=marker.root_envelope,
    )
    await vault.unlock(
        memory.capture(SecretPurpose.VAULT_UNLOCK, bytearray(spec["passphrase"].encode()))
    )
    tasks_root = bundle / "tasks"
    require(inside(tasks_root), "export_path_outside_instance")
    tasks = []
    for task_dir in sorted(tasks_root.iterdir()) if tasks_root.is_dir() else []:
        require(inside(task_dir), "export_path_outside_instance")
        task_id = task_dir.name
        db = open_read_only(task_dir / "ledger.sqlite3")
        try:
            rows = db.execute(
                "SELECT e.ingestion_seq, e.entry_digest, e.canonical_entry, e.payload_object_id, "
                "e.payload_commitment, e.previous_ledger_digest, e.redaction_state, "
                "l.canonical_payload_digest, o.envelope_digest, o.commitment, o.state "
                "FROM events AS e "
                "JOIN event_projection_locators AS l ON l.event_id = e.event_id "
                "JOIN objects AS o ON o.object_id = e.payload_object_id "
                "ORDER BY e.ingestion_seq"
            ).fetchall()
            count = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        finally:
            db.close()
        require(count == len(rows), "export_event_rows_unjoined")
        keys = await vault.load_bundle_keys(task_id)
        store = EncryptedFilesObjectStore(
            bundle_root=task_dir,
            bundle_keys=keys,
            secret_memory=memory,
            id_port=None,
            current_root_snapshot=lambda: None,
        )
        events = []
        previous = "genesis"
        for expected_seq, row in enumerate(rows, start=1):
            (seq, digest, canonical, object_id, commitment, previous_digest, redaction,
             payload_digest, envelope_digest, object_commitment, object_state) = row
            require(seq == expected_seq, "export_sequence_gap")
            require(type(canonical) is bytes, "export_canonical_entry_invalid")
            entry = strict_json_parse(canonical)
            require(canonical_encode(entry) == canonical, "export_canonical_entry_noncanonical")
            require(entry["entry_digest"] == digest, "export_entry_digest_column_mismatch")
            preimage = {key: value for key, value in entry.items() if key != "entry_digest"}
            require(entry_digest(preimage) == digest, "export_entry_digest_mismatch")
            require(entry["ledger"]["ingestion_sequence"] == str(seq), "export_entry_sequence")
            require(entry["ledger"]["previous_entry_digest"] == previous, "export_chain_broken")
            require(previous_digest == previous, "export_chain_column_mismatch")
            require(entry["task_id"] == task_id, "export_entry_task_mismatch")
            ref = entry["payload_ref"]
            require(ref["object_id"] == object_id, "export_payload_object_mismatch")
            require(ref["commitment"] == commitment == object_commitment,
                    "export_payload_commitment_mismatch")
            require(redaction == "present" and object_state == "present",
                    "export_payload_not_present")
            verified = await store.resolve_verified(object_id, envelope_digest)
            require(verified.commitment == commitment, "export_payload_commitment_mismatch")
            require(verified.plaintext_size == ref["plaintext_size"], "export_payload_size")
            payload = b"".join([chunk async for chunk in store.open_verified(verified)])
            parsed = strict_json_parse(payload)
            require(canonical_encode(parsed) == payload, "export_payload_noncanonical")
            require(canonical_digest(parsed) == payload_digest, "export_payload_digest_mismatch")
            events.append({
                "canonical_entry": canonical.decode("utf-8"),
                "payload": payload.decode("utf-8"),
                "payload_sha256": "sha256:" + hashlib.sha256(payload).hexdigest(),
            })
            previous = digest
        tasks.append({
            "task_id": task_id,
            "events": events,
            "head": {"head_digest": previous, "sequence": str(len(events))},
        })
    await vault.close()
    return tasks


def main():
    spec = json.loads(sys.stdin.read())
    try:
        tasks = asyncio.run(export(spec))
    except ExportFailure as failure:
        print(json.dumps({"ok": False, "error": str(failure)}))
        raise SystemExit(3)
    except Exception as error:
        print(json.dumps({"ok": False, "error": type(error).__name__ + ":" + str(error)[:300]}))
        raise SystemExit(4)
    print(json.dumps({"ok": True, "tasks": tasks}, ensure_ascii=False, sort_keys=True))


main()
"""
_PASSPHRASE_PROMPTS: Final = (r"Passphrase \(", r"Confirm passphrase")
_ITEM_TIMEOUT_SECONDS: Final = 180.0


def _load_by_path(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def instance_env(home: Path, extra: Mapping[str, str] | None = None) -> dict[str, str]:
    """Environment for every instance process: no ambient roots, host homes or keychain."""

    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("FINISHUP_", "YOETZ_", "PYTHON", "CODEX_", "CLAUDE_", "CURSOR_"))
    }
    env["HOME"] = str(home)
    env["CODEX_HOME"] = str(home / ".codex")
    env["PYTHON_KEYRING_BACKEND"] = "keyring.backends.fail.Keyring"
    env.update(extra or {})
    return env


def _git_workspace(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, mode=0o700)
    dated = {
        **os.environ,
        "GIT_AUTHOR_DATE": "2026-10-16T00:00:00Z",
        "GIT_COMMITTER_DATE": "2026-10-16T00:00:00Z",
    }
    git = ["git", "-C", str(path), "-c", "user.name=hook-replay"]
    git += ["-c", "user.email=hook-replay@example.invalid"]
    subprocess.run(["git", "-C", str(path), "init", "-q", "-b", "main"], check=True)
    subprocess.run([*git, "commit", "-q", "--allow-empty", "-m", "replay"], env=dated, check=True)


def _completed(done: subprocess.CompletedProcess[bytes]) -> dict[str, Any]:
    """One finished harness step: its exit code and both output streams, decoded."""

    return {
        "returncode": done.returncode,
        "stdout": done.stdout.decode("utf-8", errors="replace"),
        "stderr": done.stderr.decode("utf-8", errors="replace"),
    }


def stop_unclean(outcome: Mapping[str, Any]) -> bool:
    """Whether a ``Replayer.stop`` outcome is anything but a clean, unsignalled exit."""

    return (
        outcome.get("stop_returncode") != 0
        or outcome.get("exit_code") != 0
        or bool(outcome.get("terminated"))
    )


def _substitute(text: str, workspace: Path, transcript: Path) -> str:
    return text.replace(WORKSPACE, str(workspace)).replace(TRANSCRIPT, str(transcript))


@dataclass(slots=True)
class Instance:
    tag: str
    base: Path
    checkout: Path
    launcher: Path
    provenance: dict[str, Any]

    @property
    def directory(self) -> Path:
        return self.base / self.tag

    def retained_python(self) -> Path:
        candidates = sorted((self.directory / ".runtime-releases").glob("*/bin/python"))
        if len(candidates) != 1:
            raise SystemExit(f"expected one retained runtime, found {len(candidates)}")
        return candidates[0]


def provision(checkout: Path, revision: str, base: Path, tag: str, python: str) -> Instance:
    command = [
        sys.executable,
        str(checkout / "scripts" / "provision_test_instance.py"),
        "create",
        "--base",
        str(base),
        "--tag",
        tag,
        "--checkout",
        str(checkout),
        "--revision",
        revision,
        "--lifecycle",
        "disposable",
        "--expires-in",
        "6",
        "--python",
        python,
        "--json",
    ]
    env = {k: v for k, v in os.environ.items() if not k.startswith(("FINISHUP_", "YOETZ_"))}
    done = subprocess.run(command, env=env, capture_output=True, text=True, timeout=1800)
    if done.returncode != 0:
        raise SystemExit(f"provision failed: {done.stderr[-2000:]}")
    provenance = cast(dict[str, Any], json.loads(done.stdout))
    return Instance(tag, base, checkout, Path(cast(str, provenance["launcher"])), provenance)


def dispose(instance: Instance) -> dict[str, Any]:
    command = [
        sys.executable,
        str(instance.checkout / "scripts" / "provision_test_instance.py"),
        "dispose",
        "--base",
        str(instance.base),
        "--tag",
        instance.tag,
        "--json",
    ]
    env = {k: v for k, v in os.environ.items() if not k.startswith(("FINISHUP_", "YOETZ_"))}
    done = subprocess.run(command, env=env, capture_output=True, text=True, timeout=600)
    return {
        "returncode": done.returncode,
        "stdout": done.stdout[-4000:],
        "stderr": done.stderr[-2000:],
    }


@dataclass(slots=True)
class _ReplayState:
    mode: str
    root: Path
    items: list[Item]
    transcripts: dict[str, dict[str, Any]]
    workspaces: list[str]
    setup: dict[str, Any]
    transcript_written: dict[str, int]
    transcript_paths: dict[str, Path]
    claude_transcript: Path
    retained: Path
    trace_path: Path
    records: list[dict[str, Any]]
    # Each workspace's last corpus item (1-based), and the ``observe status`` read right after
    # that item's drain (see ``Replayer.step``).
    last_item: dict[str, int]
    status_snapshots: dict[str, dict[str, Any]]


class Replayer:
    """One provisioned build: its service, its ceremonies, and the replay through it."""

    def __init__(self, instance: Instance, work_root: Path, log: Callable[[str], None]) -> None:
        self.instance = instance
        self.work_root = work_root
        self.home = work_root / "home"
        self.log = log
        self.service: subprocess.Popen[bytes] | None = None
        self.delay_seconds = 0.0
        # ``ADMISSION_CLOCKS`` key, pinned mode only; ``None`` leaves the product clock alone.
        self.admission_clock: str | None = None
        # Pinned mode only: seed ``FIXED_OBSERVATION_KEY`` before the first service start.
        self.fixed_observation_key = False
        # Held in memory for the post-run ledger export only; never written anywhere.
        self._passphrase: str | None = None
        self._ceremony = _load_by_path("hook_replay_ceremony", _HERE / "dogfood_ci" / "ceremony.py")
        self._lane = _load_by_path("hook_replay_lane", _HERE / "dogfood_ci" / "lane.py")

    def env(self, extra: Mapping[str, str] | None = None) -> dict[str, str]:
        control = (
            {}
            if self.admission_clock is None
            else {"HOOK_REPLAY_ADMISSION_CLOCK": str(ADMISSION_CLOCKS[self.admission_clock])}
        )
        return instance_env(self.home, {**control, **(extra or {})})

    def finishup(
        self,
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        stdin: str | None = None,
        extra_env: Mapping[str, str] | None = None,
        timeout: float = _ITEM_TIMEOUT_SECONDS,
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [str(self.instance.launcher), *argv],
            cwd=cwd or self.home,
            env=self.env(extra_env),
            input=None if stdin is None else stdin.encode("utf-8"),
            capture_output=True,
            timeout=timeout,
            check=False,
        )

    def _spawn_service(self, command: list[str], log_name: str) -> None:
        log_path = self.work_root / log_name
        self.service = subprocess.Popen(  # noqa: S603 - fixed instance launcher argv
            command,
            cwd=self.home,
            env=self.env(),
            stdin=subprocess.DEVNULL,
            stdout=log_path.open("wb"),
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )

    def start(self, *, pause_background: bool) -> dict[str, Any]:
        if self.home.exists():
            shutil.rmtree(self.home)
        (self.home / ".codex").mkdir(parents=True, mode=0o700)
        launcher = str(self.instance.launcher)
        seeded: dict[str, Any] | None = None
        if self.fixed_observation_key:
            seeded = self._seed_observation_key()
        self._spawn_service([launcher, "service", "run"], f"service-{self.instance.tag}.log")
        status = self._wait_status(lambda s: True)
        pre_pause_stop: dict[str, Any] | None = None
        if pause_background:
            # The first launch made the retained runtime; serve again from it with the
            # background passes paused (see ``_SERVICE_BOOTSTRAP``). The unpaused service must
            # have stopped cleanly, or it could still be serving beside the paused one.
            pre_pause_stop = self.stop()
            if stop_unclean(pre_pause_stop):
                raise SystemExit(f"pre-pause service stop unclean: {pre_pause_stop}")
            retained = str(self.instance.retained_python())
            self._spawn_service(
                [retained, "-I", "-c", _SERVICE_BOOTSTRAP, launcher, "service", "run"],
                f"service-{self.instance.tag}-paused.log",
            )
            status = self._wait_status(lambda s: True)
        if status.get("vault_mode") != "uninitialized":
            raise SystemExit(f"vault not fresh: {status.get('vault_mode')}")
        passphrase = secrets.token_urlsafe(24)
        self._passphrase = passphrase
        reply = self._ceremony.Reply
        init = self._ceremony.run_ceremony(
            [str(self.instance.launcher), "service", "initialize-passphrase", "--json"],
            [reply(_PASSPHRASE_PROMPTS[0], passphrase), reply(_PASSPHRASE_PROMPTS[1], passphrase)],
            cwd=self.home,
            env=self.env(),
            timeout=240.0,
        )
        if init.exit_code != 0:
            raise SystemExit(f"vault initialize failed: {init.transcript[-2000:]}")
        ready = self._wait_status(lambda s: s.get("state") == "ready")
        lane = self._lane
        privacy = self._ceremony.run_ceremony(
            [str(self.instance.launcher), "privacy", "setup"],
            [
                reply(lane.PROMPT_PRIVACY_RECOMMENDED, "n", secret=False),
                reply(lane.PROMPT_PRIVACY_CHOICE, "1", secret=False),
                reply(lane.PROMPT_PRIVACY_CREATE, "y", secret=False),
                reply(lane.PROMPT_DECISION, "approve", secret=False),
                reply(lane.PROMPT_PASSPHRASE, passphrase),
            ],
            cwd=self.home,
            env=self.env(),
            timeout=240.0,
        )
        if privacy.exit_code != 0:
            raise SystemExit(f"privacy setup failed: {privacy.transcript[-2000:]}")
        return {
            "service_status": ready,
            "privacy_answered": privacy.answered,
            "observation_key_seeded": seeded,
            "pre_pause_stop": pre_pause_stop,
        }

    def _seed_observation_key(self) -> dict[str, Any]:
        root = str(self.instance.provenance["isolated_root"])
        done = subprocess.run(
            [str(self.instance.launcher.parent / "python"), "-I", "-c", _SEED_OBSERVATION_KEY],
            cwd=self.home,
            env=self.env({"FINISHUP_ISOLATED_ROOT": root, "YOETZ_ISOLATED_ROOT": root}),
            input=json.dumps({"instance_root": root, "key": FIXED_OBSERVATION_KEY.hex()}).encode(),
            capture_output=True,
            timeout=120,
            check=False,
        )
        if done.returncode != 0:
            raise SystemExit(f"observation key seed failed: {done.stderr[-2000:]!r}")
        return _completed(done)

    def _wait_status(self, accept: Callable[[dict[str, Any]], bool]) -> dict[str, Any]:
        deadline = time.monotonic() + 120.0
        while True:
            if self.service is not None and self.service.poll() is not None:
                raise SystemExit("service exited during startup")
            done = self.finishup(["service", "status", "--json"], timeout=60.0)
            try:
                status = cast(dict[str, Any], json.loads(done.stdout))
            except ValueError:
                status = {}
            if done.returncode == 0 and status and accept(status):
                return status
            if time.monotonic() > deadline:
                raise SystemExit(
                    f"service not ready: {done.stdout[-500:]!r} {done.stderr[-500:]!r}"
                )
            time.sleep(0.5)

    def stop(self) -> dict[str, Any]:
        outcome: dict[str, Any] = {}
        if self.service is None:
            return outcome
        done = self.finishup(["service", "stop", "--json"], timeout=60.0)
        outcome["stop_returncode"] = done.returncode
        outcome["stop_stderr"] = done.stderr.decode("utf-8", errors="replace")[-2000:]
        try:
            outcome["exit_code"] = self.service.wait(timeout=60.0)
        except subprocess.TimeoutExpired:
            # Only the PID this replayer spawned is ever signalled.
            self.service.terminate()
            outcome["exit_code"] = self.service.wait(timeout=30.0)
            outcome["terminated"] = True
        self.service = None
        return outcome

    def begin(self, corpus: Mapping[str, Any], mode: str) -> _ReplayState:
        """Fresh workspaces with their grants, ready for the corpus items in order."""

        mode_root = self.work_root / mode
        if mode_root.exists():
            shutil.rmtree(mode_root)
        items = cast(list[Item], corpus["items"])
        transcripts = cast(dict[str, dict[str, Any]], corpus["transcripts"])
        workspaces = sorted({cast(str, item["workspace"]) for item in items})
        setup: dict[str, Any] = {}
        for key in workspaces:
            path = mode_root / key
            _git_workspace(path)
            if key == "cli":
                continue
            grant = self.finishup(["observe", "grant", "--workspace", str(path)])
            # Every setup step's exit code and output is kept: ``compare`` refuses a run with a
            # failed step and compares the outputs of the rest.
            setup[key] = {"grant": _completed(grant)}
            profile = next(
                (
                    item["argv"][item["argv"].index("--observation-profile") + 1]
                    for item in items
                    if item["workspace"] == key and "--observation-profile" in item["argv"]
                ),
                None,
            )
            if profile is not None:
                enabled = self.finishup(
                    ["observe", "content-enable", "--workspace", str(path), "--profile", profile]
                )
                setup[key]["content_enable"] = _completed(enabled)
        transcript_written = {name: 0 for name in transcripts}
        transcript_paths = {
            name: self.home / ".codex" / "sessions" / "2026" / "10" / "16" / spec["file"]
            for name, spec in transcripts.items()
        }
        claude_transcript = self.home / ".claude" / "projects" / "replay" / "session.jsonl"
        claude_transcript.parent.mkdir(parents=True, exist_ok=True)
        claude_transcript.touch()
        retained = self.instance.retained_python()
        trace_path = mode_root / "catalog-trace.jsonl"
        last_item = {
            cast(str, item["workspace"]): number for number, item in enumerate(items, start=1)
        }
        return _ReplayState(
            mode=mode,
            root=mode_root,
            items=items,
            transcripts=transcripts,
            workspaces=workspaces,
            setup=setup,
            transcript_written=transcript_written,
            transcript_paths=transcript_paths,
            claude_transcript=claude_transcript,
            retained=retained,
            trace_path=trace_path,
            records=[],
            last_item=last_item,
            status_snapshots={},
        )

    def step(self, state: _ReplayState, number: int, item: Item) -> dict[str, Any]:
        """Run one corpus item as its host would, then the drain that follows it."""

        mode, mode_root, items = state.mode, state.root, state.items
        transcripts, transcript_written = state.transcripts, state.transcript_written
        transcript_paths, claude_transcript = state.transcript_paths, state.claude_transcript
        retained, trace_path, records = state.retained, state.trace_path, state.records
        workspace = mode_root / cast(str, item["workspace"])
        spec = cast(dict[str, Any] | None, item.get("transcript"))
        transcript = claude_transcript
        if spec is not None:
            name = cast(str, spec["name"])
            transcript = transcript_paths[name]
            transcript.parent.mkdir(parents=True, exist_ok=True)
            lines = cast(list[str], transcripts[name]["lines"])
            upto = cast(int, spec["upto"])
            with transcript.open("a", encoding="utf-8") as handle:
                for line in lines[transcript_written[name] : upto]:
                    handle.write(_substitute(line, workspace, transcript) + "\n")
            transcript_written[name] = max(transcript_written[name], upto)
        argv = [_substitute(token, workspace, transcript) for token in item["argv"]]
        stdin = item.get("stdin")
        text = None if stdin is None else _substitute(cast(str, stdin), workspace, transcript)
        host_env = {
            "claude": {"CLAUDE_PROJECT_DIR": str(workspace)},
            "cursor": {"CURSOR_PROJECT_DIR": str(workspace)},
        }.get(cast(str, item["host"]), {})
        if item.get("runner") == "python":
            command = [str(retained), "-I", "-c", _PROBE]
            extra = host_env
        elif mode == "pinned":
            command = [str(retained), "-I", "-c", _PINNED_BOOTSTRAP]
            command += [str(self.instance.launcher), *argv]
            extra = {
                **host_env,
                "HOOK_REPLAY_PINS": json.dumps(dict(PINNED_HOOK_BUDGETS)),
                # A side file only: never stdout or stderr, which are compared.
                "HOOK_REPLAY_CATALOG_TRACE": str(trace_path),
                # An experiment knob: hold a build's callbacks back to another build's pace.
                "HOOK_REPLAY_DELAY_SECONDS": str(self.delay_seconds),
            }
        else:
            command = [str(self.instance.launcher), *argv]
            extra = host_env
        traced = trace_path.read_text().splitlines() if trace_path.exists() else []
        started = time.monotonic()
        done = subprocess.run(
            command,
            cwd=workspace,
            env=self.env(extra),
            input=None if text is None else text.encode("utf-8"),
            capture_output=True,
            timeout=_ITEM_TIMEOUT_SECONDS,
            check=False,
        )
        elapsed_ms = (time.monotonic() - started) * 1000.0
        record: dict[str, Any] = {
            "label": item["label"],
            "host": item["host"],
            "workspace": item["workspace"],
            "event": _event_of(argv),
            "returncode": done.returncode,
            "stdout": done.stdout.decode("utf-8", errors="replace"),
            "stderr": done.stderr.decode("utf-8", errors="replace"),
            "elapsed_ms": round(elapsed_ms, 3),
        }
        if trace_path.exists():
            fresh = trace_path.read_text().splitlines()[len(traced) :]
            record["catalog_trace"] = [json.loads(line) for line in fresh]
        if item["workspace"] != "cli":
            drain_argv = ["observe", "drain", "--workspace", str(workspace), "--json"]
            if self.admission_clock is not None:
                # The drain flushes due admission accounts too, so it runs under the control.
                drained = subprocess.run(
                    [str(retained), "-I", "-c", _PINNED_BOOTSTRAP, str(self.instance.launcher)]
                    + drain_argv,
                    cwd=workspace,
                    env=self.env({"HOOK_REPLAY_PINS": "{}"}),
                    capture_output=True,
                    timeout=_ITEM_TIMEOUT_SECONDS,
                    check=False,
                )
            else:
                drained = self.finishup(drain_argv, cwd=workspace)
            # ``compare`` refuses a run with a failed drain and compares every drain's output.
            record["drain"] = _completed(drained)
            if state.last_item[cast(str, item["workspace"])] == number:
                # Observation lifecycle reads the age of the last successful drain against the
                # wall clock (``observation_health``: degraded once a pending row's drain is more
                # than 120 s old), so a read taken after every later workspace has run would
                # depend on how fast the build replayed them. Read it right after this
                # workspace's own last item and drain instead, and compare that read exactly.
                observed = self.finishup(
                    ["observe", "status", "--workspace", str(workspace), "--json"]
                )
                state.status_snapshots[cast(str, item["workspace"])] = {
                    **_completed(observed),
                    "read_after": item["label"],
                }
        records.append(record)
        self.log(
            f"[{mode}] {number}/{len(items)} {item['label']} rc={done.returncode} {elapsed_ms:.0f}ms"
        )
        return record

    def finish(self, state: _ReplayState) -> dict[str, Any]:
        """Read every workspace's ledger back after the last item."""

        ledgers = {
            key: self._ledger(state.root / key, state.records, key, state.status_snapshots.get(key))
            for key in state.workspaces
            if key != "cli"
        }
        return {"setup": state.setup, "items": state.records, "ledgers": ledgers}

    def replay(self, corpus: Mapping[str, Any], mode: str) -> dict[str, Any]:
        state = self.begin(corpus, mode)
        for number, item in enumerate(state.items, start=1):
            self.step(state, number, item)
        return self.finish(state)

    def _ledger(
        self,
        workspace: Path,
        records: Sequence[Mapping[str, Any]],
        key: str,
        snapshot: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        """Read one workspace's ledger history back; any failed or partial read is recorded.

        ``compare`` refuses a run whose record carries ``history_error`` or lacks a complete,
        cursor-exhausted history ending at the reported head, so a failed read can never pass as
        an empty history. ``snapshot`` is the ``observe status`` read taken right after the
        workspace's last item; a missing one is recorded as a failed read.
        """

        mapping = None
        for record in records:
            if record["workspace"] != key:
                continue
            match = _MAPPED.search(cast(str, record["stdout"]) + "\n" + cast(str, record["stderr"]))
            if match:
                mapping = {"session_id": match.group(2), "writer_id": match.group(3)}
                break
        observed = snapshot or {"returncode": None, "stdout": "", "stderr": "", "read_after": None}
        result: dict[str, Any] = {
            "mapped": mapping is not None,
            "observe_status_returncode": observed["returncode"],
            "observe_status": observed["stdout"],
            "observe_status_stderr": observed["stderr"],
            "observe_status_read_after": observed["read_after"],
        }
        if mapping is None:
            return result
        result["mapping"] = mapping
        history: list[Any] = []
        cursor: str | None = None
        complete = False
        for page in range(1, _HISTORY_MAX_PAGES + 1):
            body: dict[str, Any] = {
                "actor": {"actor_id": "harness:hook-replay", "actor_type": "harness"},
                "client": {"integration": "local_cli", "kind": "yoetz_cli", "version": "0.3.0"},
                "limit": "100",
                "protocol_version": "0.1",
                "request_id": f"req_00000000-0000-4000-8000-{900000 + page:012d}",
                "schema_version": "1.0.0",
                "view": "history",
                **mapping,
            }
            if cursor is not None:
                body["cursor"] = cursor
            done = self.finishup(
                ["status", "--input", "-", "--json"], cwd=workspace, stdin=json.dumps(body)
            )
            failure = history_page_failure(done.returncode, done.stdout)
            if failure is not None:
                result["history_error"] = {
                    "page": page,
                    "reason": failure,
                    "returncode": done.returncode,
                    "stdout": done.stdout.decode("utf-8", errors="replace")[-2000:],
                    "stderr": done.stderr.decode("utf-8", errors="replace")[-2000:],
                }
                break
            status = cast(dict[str, Any], json.loads(done.stdout))
            page_value = cast(dict[str, Any], status["page"])
            history.extend(cast(list[Any], page_value["items"]))
            cursor = cast(str | None, page_value.get("next_cursor"))
            if cursor is None:
                result["head_frontier"] = status["head_frontier"]
                complete = True
                break
        if not complete and "history_error" not in result:
            result["history_error"] = {"reason": "history_pages_exhausted"}
        result["history_complete"] = complete
        result["history"] = history
        return result

    def export_ledgers(self) -> dict[str, Any]:
        """Every accepted event and bound payload in this instance, read after the service stops."""

        if self.service is not None:
            return {"ok": False, "error": "export_service_running"}
        if self._passphrase is None:
            return {"ok": False, "error": "export_passphrase_unavailable"}
        root = str(self.instance.provenance["isolated_root"])
        done = subprocess.run(
            [str(self.instance.retained_python()), "-I", "-c", _LEDGER_EXPORT],
            cwd=self.home,
            env=self.env({"FINISHUP_ISOLATED_ROOT": root, "YOETZ_ISOLATED_ROOT": root}),
            input=json.dumps({"instance_root": root, "passphrase": self._passphrase}).encode(),
            capture_output=True,
            timeout=600,
            check=False,
        )
        exported: dict[str, Any]
        try:
            exported = cast(dict[str, Any], json.loads(done.stdout))
        except ValueError:
            exported = {"ok": False, "error": "export_output_unparsable"}
        if done.returncode != 0 and exported.get("ok") is not False:
            exported = {"ok": False, "error": f"export_exit_{done.returncode}"}
        exported["returncode"] = done.returncode
        if exported.get("ok") is not True:
            exported["stderr"] = done.stderr.decode("utf-8", errors="replace")[-4000:]
        return exported


_HISTORY_MAX_PAGES: Final = 200


def history_page_failure(returncode: int, stdout: bytes | str) -> str | None:
    """Why one ``status view=history`` page is not a successful page, or ``None``."""

    if returncode != 0:
        return "status_exit_nonzero"
    try:
        status: Any = json.loads(stdout)
    except ValueError:
        return "status_output_unparsable"
    if not isinstance(status, dict):
        return "status_output_not_object"
    status = cast(dict[str, Any], status)
    if status.get("ok") is False or "error" in status:
        return "status_error_result"
    page: Any = status.get("page")
    if not isinstance(page, dict):
        return "status_page_missing"
    page = cast(dict[str, Any], page)
    if page.get("view", "history") != "history":
        return "status_page_wrong_view"
    if not isinstance(page.get("items"), list):
        return "status_page_items_missing"
    cursor = page.get("next_cursor")
    if cursor is not None and (not isinstance(cursor, str) or not cursor):
        return "status_page_cursor_invalid"
    head: Any = status.get("head_frontier")
    if cursor is None and (
        not isinstance(head, dict)
        or not isinstance(cast(dict[str, Any], head).get("sequence"), str)
        or not isinstance(cast(dict[str, Any], head).get("head_digest"), str)
    ):
        return "status_head_frontier_missing"
    return None


_MAPPED: Final = re.compile(
    r"task (tsk_[0-9a-f-]{36}) is mapped .*? as session_id (ses_[0-9a-f-]{36}) and "
    r"writer_id (wri_[0-9a-f-]{36})",
    re.DOTALL,
)


def _event_of(argv: Sequence[str]) -> str:
    if "--event" in argv:
        return argv[list(argv).index("--event") + 1]
    if list(argv[:2]) == ["hooks", "user-prompt-submit"]:
        return "UserPromptSubmit"
    if list(argv[:2]) == ["hooks", "post-tool-use"]:
        return "PostToolUse:start-correlation"
    if list(argv[:2]) == ["hooks", "startup-context"]:
        return "startup-context"
    return argv[0]


# ------------------------------------------------------------------------------------ comparison
#
# ``compare`` holds two replay records to equality. It first refuses either record unless every
# read succeeded and is complete (setup, history pages, observe status, service stop, ledger
# export) and each run's exported hash chain recomputes from its own canonical entries. It then
# compares every part exactly, after normalizing only values whose provenance makes them
# run-generated:
#
# * ``id``: product identifiers (``<prefix>_<uuid>``). Most are minted at random; the rest
#   (action, result, evidence, finding) are digests over a run's random task ids, its keyed
#   commitments or clock-bearing evidence bases, so every one differs per run by construction.
# * ``keyed``: ``hmac-sha256:`` commitments, all under the instance's own random keys.
# * ``source``: observation source identities (``hook:`` and ``stream:``), digests over structural
#   records into which the installation-keyed command commitments are merged
#   (``observe_hooks.map_hook_payload_to_envelope``, ``codex_session_stream._stream_envelope``).
#   One without keyed fields comes out the same in both runs, and is then named the same.
# * ``derived``: routine-read summary identities and member digests (their members carry receipt
#   times, ``observation_admission``) and the advice freshness-frontier suffix (a digest over
#   evidence bases holding the identities above).
#
# A value of these classes that appears anywhere in the corpus is input and stays exact. These
# values are compared by where they occur rather than by value: each value is named by a digest
# of the sorted list of slots it occupies (part, path, ordinal), so two runs match only when a
# bijection maps every value of one run to a value of the other occupying exactly the same slots.
# A set-valued list of identifiers and a keyed command-segment list (sorted by keyed value, so its
# order is per-instance) are slots without positions.
#
# * ``chain``: a ``sha256:`` value that is a verified entry digest of the run is named by its chain
#   position; any other ``sha256:`` value (content digests, payload digests) is compared exactly.
# * ``clock``: named service clock fields only, each checked to be a time inside the run's wall
#   clock window: ``accepted_at``; ``occurred_at`` and evidence ``observed_at`` of events the
#   service or its observation coordinator authored; observe-status times (``_CLOCK_KEYS``) and
#   ages (``_AGE_KEYS``, each no longer than the run).
# * latency: observe-status timing statistics (``_LATENCY_KEYS``), dropped, and the
#   observability-only budget diagnostics (``_LATENCY_REASONS``), removed with their counts.

_ID_PREFIXES: Final = (
    "act aut agt att cas clm dsp egr err evd evt fnd ins job obj obl pin ppr prj psw pvy rcp req "
    "res rpc ses svc tsk wri"
).split()
_UUID: Final = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_TOKEN: Final = re.compile(
    r"(?P<id>\b(?:" + "|".join(_ID_PREFIXES) + r")_" + _UUID + r"\b)"
    r"|(?P<keyed>hmac-sha256:[0-9a-f]{64})"
    r"|\b(?:hook|stream):(?P<source>[0-9a-f]{48})\b"
    r"|\broutine_read_summary:summary:(?P<summary>[0-9a-f]{64})\b"
    r"|\bmember_digest=(?P<member>sha256:[0-9a-f]{64})\b"
    r"|\bfrontier-g[0-9]+-e[0-9]+-(?P<frontier>[0-9a-f]{16})\b"
    r"|(?P<sha>(?<![0-9a-z-])sha256:[0-9a-f]{64})"
)
_TOKEN_CLASS: Final = {
    "id": "id",
    "keyed": "keyed",
    "source": "source",
    "summary": "derived",
    "member": "derived",
    "frontier": "derived",
}
# The keyed segment commitments that follow a command composition word are sorted by keyed value.
_SEGMENT_GROUP: Final = re.compile(r"\b(?:single|and_chain|masked)((?: hmac-sha256:[0-9a-f]{64})+)")
_CLOCK_KEYS: Final = frozenset(
    {
        "first_seen",
        "last_observation_receipt_time",
        "last_seen",
        "last_successful_drain",
        "max_ts",
        "observed_at",
        "oldest_pending_receipt",
        "oldest_read_at",
        "oldest_receipt_time",
        "since",
        "ts",
    }
)
# Ages measured against the wall clock at read time: compared only as present or absent.
_AGE_KEYS: Final = frozenset({"oldest_pending_age_ms"})
_LATENCY_KEYS: Final = frozenset(
    {
        "bucket_counts",
        "last_ms",
        "max_ms",
        "mean_ms",
        "p50_ms_at_most",
        "p95_ms_at_most",
        "pass_timings",
        "recent_max_ms",
        "recent_p95_ms",
        # The serialized size of local state that holds the latency figures above, and its share
        # of the byte budget.
        "state_bytes",
        "store_lock_events",
        "sum_ms",
        "timings",
        "utilization_bps",
    }
)
# Observability-only diagnostics recorded when a pass's wall time exceeds its budget or a store
# lock was held for a second or more; they never change what the pass does
# (``observe_hooks._record_pass_timing``, ``observation_local`` lock ``long_hold``). Each is removed from
# ``hook_diagnostics.reasons`` with its counts taken out of the totals.
_LATENCY_REASONS: Final = frozenset({"hook_budget_exceeded", "store_lock_long_hold"})
_SERVICE_AUTHORS: Final = frozenset({"yoetz.engine", "yoetz:observation-coordinator"})
_CLOCK_MARGIN_SECONDS: Final = 120.0
_RELATIVE_CLOCK: Final = re.compile(r"\A[0-9]+(?:\.[0-9]+)?s ago\Z")
_CLOCK: Final = "<clock>"


def generated_tokens(text: str) -> set[str]:
    """Every value of a run-generated class that occurs in ``text`` (corpus inputs)."""

    found: set[str] = set()
    for match in _TOKEN.finditer(text):
        for group in _TOKEN_CLASS:
            if match.group(group) is not None:
                found.add(match.group(group))
    return found


def corpus_identity(corpus: Mapping[str, Any]) -> dict[str, Any]:
    """The corpus digest and its generated-class values, which every comparison keeps exact."""

    encoded = json.dumps(corpus, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return {
        "sha256": "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest(),
        "generated_tokens": sorted(generated_tokens(encoded)),
    }


def _parse_time(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


@dataclass(slots=True)
class _Window:
    start: datetime
    end: datetime

    def check_age(self, milliseconds: int, where: str, failures: list[str]) -> None:
        limit = (self.end - self.start).total_seconds() + _CLOCK_MARGIN_SECONDS
        if not 0 <= milliseconds <= limit * 1000:
            failures.append(f"age_outside_run:{where}")

    def check(self, value: Any, where: str, failures: list[str]) -> None:
        if value is None:
            return
        if type(value) is str and _RELATIVE_CLOCK.match(value):
            seconds = float(value.split("s", 1)[0])
            if seconds > (self.end - self.start).total_seconds() + _CLOCK_MARGIN_SECONDS:
                failures.append(f"clock_outside_run:{where}")
            return
        parsed = _parse_time(value) if type(value) is str else None
        margin = timedelta(seconds=_CLOCK_MARGIN_SECONDS)
        if parsed is None:
            failures.append(f"clock_unparsable:{where}")
        elif not self.start - margin <= parsed <= self.end + margin:
            failures.append(f"clock_outside_run:{where}")


def _canonical_tools() -> tuple[
    Callable[[Any], bytes], Callable[[Any], str], Callable[[bytes], Any]
]:
    from finishup.protocol.canonical import canonical_encode, entry_digest, strict_json_parse

    return (
        cast(Callable[[Any], bytes], canonical_encode),
        cast(Callable[[Any], str], entry_digest),
        cast(Callable[[bytes], Any], strict_json_parse),
    )


def chain_failures(task: Mapping[str, Any]) -> list[str]:
    """Recompute one exported task's hash chain and payload digests from its own bytes."""

    encode, digest_of, parse = _canonical_tools()
    failures: list[str] = []
    events = cast(list[dict[str, Any]], task.get("events") or [])
    if not events:
        return ["export_task_empty"]
    previous = "genesis"
    writers: dict[str, tuple[int, str]] = {}
    for sequence, event in enumerate(events, start=1):
        where = f"{task.get('task_id')}#{sequence}"
        try:
            raw = cast(str, event["canonical_entry"]).encode("utf-8")
            entry = cast(dict[str, Any], parse(raw))
            if encode(entry) != raw:
                failures.append(f"entry_noncanonical:{where}")
            preimage = {key: value for key, value in entry.items() if key != "entry_digest"}
            if digest_of(preimage) != entry["entry_digest"]:
                failures.append(f"entry_digest_mismatch:{where}")
            ledger = cast(dict[str, Any], entry["ledger"])
            if ledger["ingestion_sequence"] != str(sequence):
                failures.append(f"sequence_mismatch:{where}")
            if ledger["previous_entry_digest"] != previous:
                failures.append(f"ledger_chain_broken:{where}")
            if entry["task_id"] != task.get("task_id"):
                failures.append(f"task_mismatch:{where}")
            writer = cast(dict[str, Any], entry["writer"])
            seen, writer_previous = writers.get(writer["writer_id"], (0, "genesis"))
            if writer["sequence"] != str(seen + 1) or writer["previous_entry_digest"] != (
                writer_previous
            ):
                failures.append(f"writer_chain_broken:{where}")
            writers[writer["writer_id"]] = (seen + 1, entry["entry_digest"])
            payload = cast(str, event["payload"]).encode("utf-8")
            if "sha256:" + hashlib.sha256(payload).hexdigest() != event["payload_sha256"]:
                failures.append(f"payload_digest_mismatch:{where}")
            if len(payload) != entry["payload_ref"]["plaintext_size"]:
                failures.append(f"payload_size_mismatch:{where}")
            if encode(parse(payload)) != payload:
                failures.append(f"payload_noncanonical:{where}")
            previous = entry["entry_digest"]
        except (KeyError, TypeError, ValueError) as error:
            failures.append(f"entry_unreadable:{where}:{type(error).__name__}")
            break
    head = task.get("head")
    if head != {"head_digest": previous, "sequence": str(len(events))}:
        failures.append(f"export_head_mismatch:{task.get('task_id')}")
    return failures


def _entry(event: Mapping[str, Any]) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(cast(str, event["canonical_entry"])))


def bind_workspaces(run: Mapping[str, Any]) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Each mapped workspace's exported task, matched by its session id, plus binding failures."""

    failures: list[str] = []
    export = cast(dict[str, Any], run.get("export") or {})
    tasks = cast(list[dict[str, Any]], export.get("tasks") or [])
    bound: dict[str, dict[str, Any]] = {}
    claimed: set[str] = set()
    for key, ledger in sorted(cast(dict[str, dict[str, Any]], run.get("ledgers") or {}).items()):
        mapping = cast(dict[str, Any] | None, ledger.get("mapping"))
        if mapping is None:
            continue
        matches = [
            task
            for task in tasks
            if task.get("events")
            and _entry(task["events"][0])["session_id"] == mapping["session_id"]
        ]
        if len(matches) != 1:
            failures.append(f"export_task_unbound:{key}:{len(matches)}")
            continue
        bound[key] = matches[0]
        claimed.add(cast(str, matches[0]["task_id"]))
    for task in tasks:
        if task.get("task_id") not in claimed:
            failures.append(f"export_task_unclaimed:{task.get('task_id')}")
    return bound, failures


def run_failures(run: Mapping[str, Any]) -> list[str]:
    """Why a replay record cannot be compared: any failed, partial or inconsistent read."""

    failures: list[str] = []
    if not run.get("items"):
        failures.append("items_missing")
    for name in ("started_at", "finished_at"):
        if _parse_time(cast(str, run.get(name) or "")) is None:
            failures.append(f"run_window_missing:{name}")
    if stop_unclean(cast(dict[str, Any], run.get("service_stop") or {})):
        failures.append("service_stop_unclean")
    export = cast(dict[str, Any], run.get("export") or {})
    if export.get("ok") is not True or export.get("returncode") != 0:
        failures.append(f"export_failed:{export.get('error', 'missing')}")
    setup = cast(dict[str, dict[str, Any]], run.get("setup") or {})
    ledgers = cast(dict[str, dict[str, Any]], run.get("ledgers") or {})
    items = cast(list[dict[str, Any]], run.get("items") or [])
    workspaces = sorted({cast(str, item["workspace"]) for item in items} - {"cli"})
    last_label = {cast(str, item["workspace"]): cast(str, item["label"]) for item in items}
    for item in items:
        drain = cast(dict[str, Any] | None, item.get("drain"))
        if item["workspace"] != "cli" and (drain is None or drain.get("returncode") != 0):
            failures.append(f"drain_failed:{item['label']}")
    for key in workspaces:
        steps = cast(dict[str, dict[str, Any]] | None, setup.get(key))
        if (
            not steps
            or "grant" not in steps
            or any(step.get("returncode") != 0 for step in steps.values())
        ):
            failures.append(f"setup_failed:{key}")
        ledger = ledgers.get(key)
        if ledger is None:
            failures.append(f"ledger_missing:{key}")
            continue
        if ledger.get("mapped") is not True or not ledger.get("mapping"):
            failures.append(f"mapping_missing:{key}")
        if "history_error" in ledger or ledger.get("history_complete") is not True:
            failures.append(f"history_incomplete:{key}")
        if not ledger.get("history"):
            failures.append(f"history_empty:{key}")
        head = ledger.get("head_frontier")
        if not isinstance(head, dict):
            failures.append(f"head_frontier_missing:{key}")
        if ledger.get("observe_status_returncode") != 0:
            failures.append(f"observe_status_failed:{key}")
        if ledger.get("observe_status_read_after") != last_label.get(key):
            failures.append(f"observe_status_not_after_last_item:{key}")
        try:
            if not isinstance(json.loads(cast(str, ledger.get("observe_status") or "")), dict):
                failures.append(f"observe_status_not_object:{key}")
        except ValueError:
            failures.append(f"observe_status_unparsable:{key}")
    if failures:
        return failures
    bound, binding = bind_workspaces(run)
    failures += binding
    for key, task in sorted(bound.items()):
        failures += chain_failures(task)
        ledger = ledgers[key]
        events = {_entry(event)["event_id"]: _entry(event) for event in task["events"]}
        if ledger["head_frontier"] != task["head"]:
            failures.append(f"history_head_not_export_head:{key}")
        for row in cast(list[dict[str, Any]], ledger["history"]):
            entry = events.get(cast(str, row.get("event_id")))
            if entry is None or (
                row.get("ingestion_sequence"),
                row.get("schema_name"),
                row.get("schema_version"),
                row.get("accepted_at"),
                row.get("occurred_at"),
                row.get("publication_channel"),
                row.get("actor_id"),
            ) != (
                entry["ledger"]["ingestion_sequence"],
                entry["schema"]["name"],
                entry["schema"]["version"],
                entry["ledger"]["accepted_at"],
                entry["occurred_at"],
                entry["publication_channel"],
                entry["author"]["actor_id"],
            ):
                failures.append(f"history_row_not_in_export:{key}:{row.get('ingestion_sequence')}")
    return failures


# One compared part: a label and either raw text or a JSON tree already through its field policy.
type _Part = tuple[str, Any]


def _policy_entry(entry: dict[str, Any], window: _Window, failures: list[str]) -> dict[str, Any]:
    out = json.loads(json.dumps(entry))
    service = entry["author"]["actor_id"] in _SERVICE_AUTHORS
    window.check(entry["ledger"]["accepted_at"], "accepted_at", failures)
    out["ledger"]["accepted_at"] = _CLOCK
    if service:
        window.check(entry["occurred_at"], "occurred_at", failures)
        out["occurred_at"] = _CLOCK
    return out


def _policy_payload(
    entry: Mapping[str, Any], payload: dict[str, Any], window: _Window, failures: list[str]
) -> dict[str, Any]:
    out = dict(payload)
    if (
        entry["schema"]["name"] == "evidence_recorded"
        and entry["author"]["actor_id"] in _SERVICE_AUTHORS
        and "observed_at" in out
    ):
        window.check(out["observed_at"], "observed_at", failures)
        out["observed_at"] = _CLOCK
    return out


def _policy_status(value: Any, window: _Window, failures: list[str], path: str = "") -> Any:
    if isinstance(value, dict):
        source = cast(dict[str, Any], value)
        reasons = source.get("reasons")
        if isinstance(reasons, dict) and isinstance(source.get("count"), int):
            source = dict(source)
            kept = dict(cast(dict[str, Any], reasons))
            for reason in _LATENCY_REASONS & set(kept):
                entry = cast(dict[str, Any], kept.pop(reason))
                for total, part in (("count", "count"), ("recent_count", "recent")):
                    if isinstance(source.get(total), int) and isinstance(entry.get(part), int):
                        source[total] = source[total] - entry[part]
                if source.get("last_reason") == reason:
                    failures.append(f"latency_reason_is_last:{path}")
            source["reasons"] = kept
        out: dict[str, Any] = {}
        for key, item in source.items():
            if key in _LATENCY_KEYS:
                continue
            if key in _CLOCK_KEYS and (item is None or type(item) is str):
                window.check(item, f"{path}/{key}", failures)
                out[key] = None if item is None else _CLOCK
            elif key in _AGE_KEYS and type(item) is int:
                window.check_age(item, f"{path}/{key}", failures)
                out[key] = _CLOCK
            else:
                out[key] = _policy_status(item, window, failures, f"{path}/{key}")
        return out
    if isinstance(value, list):
        return [_policy_status(item, window, failures, path) for item in cast(list[Any], value)]
    return value


def _parts(run: Mapping[str, Any], failures: list[str]) -> dict[str, list[_Part]]:
    """Every compared part of every workspace, in replay order, through the field policies."""

    window = _Window(
        cast(datetime, _parse_time(cast(str, run["started_at"]))),
        cast(datetime, _parse_time(cast(str, run["finished_at"]))),
    )
    parts: dict[str, list[_Part]] = {}
    for key, steps in sorted(cast(dict[str, dict[str, Any]], run["setup"]).items()):
        bucket = parts.setdefault(key, [])
        for step, done in steps.items():
            bucket.append((f"{key} setup {step} stdout", cast(str, done["stdout"])))
            bucket.append((f"{key} setup {step} stderr", cast(str, done["stderr"])))
    for item in cast(list[dict[str, Any]], run["items"]):
        label = cast(str, item["label"])
        bucket = parts.setdefault(cast(str, item["workspace"]), [])
        bucket.append((f"{label} returncode", str(item["returncode"])))
        bucket.append((f"{label} stdout", cast(str, item["stdout"])))
        bucket.append((f"{label} stderr", cast(str, item["stderr"])))
        if "drain" in item:
            drain = cast(dict[str, Any], item["drain"])
            bucket.append((f"{label} drain", f"{drain['returncode']}\n{drain['stdout']}"))
            bucket.append((f"{label} drain stderr", cast(str, drain["stderr"])))
    bound, _ = bind_workspaces(run)
    for key, task in sorted(bound.items()):
        ledger = cast(dict[str, Any], run["ledgers"][key])
        bucket = parts.setdefault(key, [])
        status = json.loads(cast(str, ledger["observe_status"]))
        bucket.append((f"{key} observe status", _policy_status(status, window, failures)))
        bucket.append((f"{key} observe status stderr", cast(str, ledger["observe_status_stderr"])))
        entries = {_entry(event)["event_id"]: _entry(event) for event in task["events"]}
        for index, row in enumerate(cast(list[dict[str, Any]], ledger["history"])):
            policed = dict(row)
            policed["accepted_at"] = _CLOCK
            if entries[row["event_id"]]["author"]["actor_id"] in _SERVICE_AUTHORS:
                policed["occurred_at"] = _CLOCK
            bucket.append((f"{key} history[{index}]", policed))
        bucket.append((f"{key} history head", ledger["head_frontier"]))
        for index, event in enumerate(cast(list[dict[str, Any]], task["events"]), start=1):
            entry = _entry(event)
            bucket.append((f"{key} event[{index}] entry", _policy_entry(entry, window, failures)))
            payload = cast(dict[str, Any], json.loads(cast(str, event["payload"])))
            bucket.append(
                (f"{key} event[{index}] payload", _policy_payload(entry, payload, window, failures))
            )
        bucket.append((f"{key} export head", task["head"]))
    return parts


def _chain_names(run: Mapping[str, Any]) -> dict[str, str]:
    bound, _ = bind_workspaces(run)
    names: dict[str, str] = {}
    for key, task in sorted(bound.items()):
        for index, event in enumerate(cast(list[dict[str, Any]], task["events"]), start=1):
            names[_entry(event)["entry_digest"]] = f"<chain:{key}:{index}>"
    return names


@dataclass(slots=True)
class _Tokens:
    """A run's generated values, each with the slots it occupies, and the names they get."""

    exact: frozenset[str]
    chain: Mapping[str, str]
    slots: dict[str, list[tuple[Any, ...]]]
    kinds: dict[str, str]
    names: dict[str, str]

    def _scan(self, text: str) -> list[tuple[int, int, str, str | None]]:
        """``(start, end, value, class)`` spans; class ``None`` keeps the value exact."""

        grouped: list[tuple[int, int]] = [match.span(1) for match in _SEGMENT_GROUP.finditer(text)]
        spans: list[tuple[int, int, str, str | None]] = []
        for match in _TOKEN.finditer(text):
            for group, kind in (*_TOKEN_CLASS.items(), ("sha", "chain")):
                value = match.group(group)
                if value is None:
                    continue
                start, end = match.span(group)
                if kind == "chain":
                    spans.append((start, end, value, "chain" if value in self.chain else None))
                elif value in self.exact:
                    spans.append((start, end, value, None))
                else:
                    in_group = any(low <= start < high for low, high in grouped)
                    spans.append((start, end, value, f"{kind}:group" if in_group else kind))
                break
        return spans

    def collect(self, label: str, value: Any, path: str = "") -> None:
        if isinstance(value, dict):
            for key, item in cast(dict[str, Any], value).items():
                key_spans = [span for span in self._scan(key) if span[3] not in {None, "chain"}]
                for _start, _end, token, kind in key_spans:
                    self._note(token, cast(str, kind), (label, path, "key"))
                child = f"{path}/<key>" if key_spans else f"{path}/{key}"
                self.collect(label, item, child)
        elif isinstance(value, list):
            items = cast(list[Any], value)
            if self._is_set(items):
                for item in items:
                    self._note(item, self._whole_kind(item), (label, path, "set"))
            else:
                for index, item in enumerate(items):
                    self.collect(label, item, f"{path}[{index}]")
        elif isinstance(value, str):
            ordinal = 0
            for _start, _end, token, kind in self._scan(value):
                if kind is None or kind == "chain":
                    continue
                if kind.endswith(":group"):
                    self._note(token, kind.split(":")[0], (label, path, "group"))
                else:
                    self._note(token, kind, (label, path, ordinal))
                    ordinal += 1

    def _whole_kind(self, item: str) -> str:
        spans = self._scan(item)
        return cast(str, spans[0][3]).split(":")[0]

    def _is_set(self, items: list[Any]) -> bool:
        if not items or not all(isinstance(item, str) for item in items):
            return False
        for item in items:
            spans = self._scan(cast(str, item))
            if len(spans) != 1 or spans[0][:2] != (0, len(item)):
                return False
            if spans[0][3] not in {"id", "keyed", "source"}:
                return False
        return True

    def _note(self, token: str, kind: str, slot: tuple[Any, ...]) -> None:
        self.slots.setdefault(token, []).append(slot)
        self.kinds[token] = kind

    def signature(self, token: str) -> str:
        return json.dumps(sorted(self.slots[token], key=repr), separators=(",", ":"))

    def assign_names(self) -> None:
        # Named by a digest of the occurrence signature alone, so one differing value never
        # renames the others.
        for token, kind in self.kinds.items():
            digest = hashlib.sha256(self.signature(token).encode("utf-8")).hexdigest()[:12]
            self.names[token] = f"<{kind}@{digest}>"

    def render(self, value: Any) -> Any:
        if isinstance(value, dict):
            rendered = {
                self._render_text(key): self.render(item)
                for key, item in cast(dict[str, Any], value).items()
            }
            return dict(sorted(rendered.items()))
        if isinstance(value, list):
            items = cast(list[Any], value)
            if self._is_set(items):
                return sorted(self._render_text(cast(str, item)) for item in items)
            return [self.render(item) for item in items]
        if isinstance(value, str):
            return self._render_text(value)
        return value

    def _render_text(self, text: str) -> str:
        out: list[str] = []
        cursor = 0
        for start, end, token, kind in self._scan(text):
            if kind is None:
                continue
            out.append(text[cursor:start])
            out.append(self.chain[token] if kind == "chain" else self.names[token])
            cursor = end
        out.append(text[cursor:])
        rendered = "".join(out)
        # A keyed segment list is a set ordered by keyed value: compare it as a sorted set.
        return re.sub(
            r"\b(single|and_chain|masked)((?: <keyed@[0-9a-f]+>)+)",
            lambda m: m.group(1) + " " + " ".join(sorted(m.group(2).split())),
            rendered,
        )


def _render(tokens: _Tokens, value: Any) -> str:
    if isinstance(value, str):
        return tokens.render(value)
    return json.dumps(tokens.render(value), ensure_ascii=False, sort_keys=True)


def _first_difference(old: Any, new: Any, path: str = "") -> tuple[str, Any, Any]:
    """The first path at which two rendered JSON trees differ, with both values there."""

    if isinstance(old, dict) and isinstance(new, dict):
        old_map, new_map = cast(dict[str, Any], old), cast(dict[str, Any], new)
        for key in sorted(set(old_map) | set(new_map)):
            if old_map.get(key, ...) != new_map.get(key, ...):
                if key in old_map and key in new_map:
                    return _first_difference(old_map[key], new_map[key], f"{path}/{key}")
                return f"{path}/{key}", old_map.get(key, "<absent>"), new_map.get(key, "<absent>")
    if isinstance(old, list) and isinstance(new, list):
        old_list, new_list = cast(list[Any], old), cast(list[Any], new)
        if len(old_list) == len(new_list):
            for index, (a, b) in enumerate(zip(old_list, new_list, strict=True)):
                if a != b:
                    return _first_difference(a, b, f"{path}[{index}]")
    return path or "/", cast(Any, old), cast(Any, new)


def compare_runs(
    old: Mapping[str, Any], new: Mapping[str, Any], exact: frozenset[str] = frozenset()
) -> dict[str, Any]:
    """Compare two replays of one corpus; ``exact`` lists corpus values that are never renamed."""

    result: dict[str, Any] = {"identical": False, "workspaces": {}}
    old_labels = [item["label"] for item in cast(list[dict[str, Any]], old.get("items") or [])]
    new_labels = [item["label"] for item in cast(list[dict[str, Any]], new.get("items") or [])]
    result["labels_match"] = old_labels == new_labels and bool(old_labels)
    refused = {"old": run_failures(old), "new": run_failures(new)}
    if refused["old"] or refused["new"]:
        # A failed, partial or inconsistent read is never a comparable (let alone equal) run.
        result["refused"] = refused
        return result
    failures: dict[str, list[str]] = {"old": [], "new": []}
    parts = {"old": _parts(old, failures["old"]), "new": _parts(new, failures["new"])}
    if failures["old"] or failures["new"]:
        result["refused"] = failures
        return result
    tokens: dict[str, _Tokens] = {}
    for side, run in (("old", old), ("new", new)):
        collected = _Tokens(exact, _chain_names(run), {}, {}, {})
        for bucket in parts[side].values():
            for label, value in bucket:
                collected.collect(label, value)
        collected.assign_names()
        tokens[side] = collected
    keys = sorted(set(parts["old"]) | set(parts["new"]))
    for key in keys:
        old_parts, new_parts = parts["old"].get(key, []), parts["new"].get(key, [])
        mismatches: list[dict[str, str]] = []
        if [label for label, _ in old_parts] != [label for label, _ in new_parts]:
            mismatches.append(
                {"part": "structure", "path": "/", "old": "parts differ", "new": "parts differ"}
            )
        for (label, old_value), (_label, new_value) in zip(old_parts, new_parts, strict=False):
            a, b = _render(tokens["old"], old_value), _render(tokens["new"], new_value)
            if a != b:
                where, a_at, b_at = "/", a, b
                if not isinstance(old_value, str):
                    where, a_at, b_at = _first_difference(json.loads(a), json.loads(b))
                mismatches.append(
                    {
                        "part": label,
                        "path": where,
                        "old": str(a_at)[:4000],
                        "new": str(b_at)[:4000],
                    }
                )
        events = sum(1 for label, _ in old_parts if label.endswith(" entry"))
        result["workspaces"][key] = {
            "parts": len(old_parts),
            "events": events,
            "identical": not mismatches,
            "mismatches": mismatches,
        }
    result["bijection"] = _bijection(tokens["old"], tokens["new"])
    result["identical"] = (
        result["labels_match"]
        and result["bijection"]["consistent"]
        and all(entry["identical"] for entry in result["workspaces"].values())
    )
    return result


def _bijection(old: _Tokens, new: _Tokens) -> dict[str, Any]:
    """Whether the occurrence naming pairs the two runs' generated values one-to-one."""

    def groups(tokens: _Tokens) -> dict[str, set[str]]:
        out: dict[str, set[str]] = {}
        for token, name in tokens.names.items():
            out.setdefault(name, set()).add(token)
        return out

    old_groups, new_groups = groups(old), groups(new)
    unmatched = sorted(set(old_groups) ^ set(new_groups))
    uneven = sorted(
        name
        for name in set(old_groups) & set(new_groups)
        if len(old_groups[name]) != len(new_groups[name])
    )
    per_kind: dict[str, dict[str, int]] = {}
    for name, values in old_groups.items():
        kind = name[1:].split("@", 1)[0]
        stats = per_kind.setdefault(
            kind, {"values": 0, "identical_in_both": 0, "interchangeable": 0}
        )
        stats["values"] += len(values)
        stats["identical_in_both"] += len(values & new_groups.get(name, set()))
        if len(values) > 1:
            stats["interchangeable"] += len(values)
    only_old = sorted({old.signature(t) for t in old.kinds} - {new.signature(t) for t in new.kinds})
    only_new = sorted({new.signature(t) for t in new.kinds} - {old.signature(t) for t in old.kinds})
    return {
        "consistent": not unmatched and not uneven,
        "unmatched_names": unmatched[:20],
        "uneven_names": uneven[:20],
        "occurrences_only_old": only_old[:5],
        "occurrences_only_new": only_new[:5],
        "by_kind": per_kind,
    }


def _nearest_rank(values: Sequence[float], fraction: float) -> float:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(fraction * len(ordered)) - 1)]


def latency_table(old: Mapping[str, Any], new: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Per host and event: callback wall time medians and nearest-rank p90s, old against new."""

    groups: dict[tuple[str, str], tuple[list[float], list[float]]] = {}
    for run, slot in ((old, 0), (new, 1)):
        for item in cast(list[dict[str, Any]], run["items"]):
            if "/invalid/" in cast(str, item["label"]):
                continue
            keys = [(item["host"], item["event"]), (item["host"], "*")]
            if item["host"] in {"codex", "claude", "cursor"}:
                keys.append(("*", "*"))
            for key in keys:
                groups.setdefault(key, ([], []))[slot].append(cast(float, item["elapsed_ms"]))
    rows: list[dict[str, Any]] = []
    for (host, event), (a, b) in sorted(groups.items()):
        if not a or not b:
            continue
        rows.append(
            {
                "host": host,
                "event": event,
                "n": len(a),
                "old_median_ms": round(statistics.median(a), 1),
                "new_median_ms": round(statistics.median(b), 1),
                "old_p90_ms": round(_nearest_rank(a, 0.9), 1),
                "new_p90_ms": round(_nearest_rank(b, 0.9), 1),
                "median_saved_ms": round(statistics.median(a) - statistics.median(b), 1),
            }
        )
    return rows


def compare_records(old: Mapping[str, Any], new: Mapping[str, Any]) -> dict[str, Any]:
    """Compare two replay records mode by mode; any missing mode or other corpus is a failure."""

    summary: dict[str, Any] = {
        "old": old.get("build"),
        "new": new.get("build"),
        "modes": {},
        "failures": [],
    }
    old_corpus = cast(dict[str, Any], old.get("corpus") or {})
    new_corpus = cast(dict[str, Any], new.get("corpus") or {})
    if not old_corpus.get("sha256") or old_corpus.get("sha256") != new_corpus.get("sha256"):
        summary["failures"].append("corpus_mismatch_or_missing")
    old_modes = set(cast(dict[str, Any], old.get("runs") or {}))
    new_modes = set(cast(dict[str, Any], new.get("runs") or {}))
    if not old_modes or old_modes != new_modes:
        summary["failures"].append(f"modes_differ:{sorted(old_modes)}:{sorted(new_modes)}")
    exact = frozenset(
        cast(list[str], old_corpus.get("generated_tokens") or [])
        + cast(list[str], new_corpus.get("generated_tokens") or [])
    )
    for mode in sorted(old_modes & new_modes):
        old_run, new_run = old["runs"][mode], new["runs"][mode]
        summary["modes"][mode] = {
            "comparison": compare_runs(old_run, new_run, exact),
            "latency": latency_table(old_run, new_run),
        }
    summary["identical"] = not summary["failures"] and all(
        entry["comparison"]["identical"] for entry in summary["modes"].values()
    )
    return summary


def render_report(old: Mapping[str, Any], new: Mapping[str, Any]) -> tuple[str, dict[str, Any]]:
    summary = compare_records(old, new)
    old_ref = cast(dict[str, Any], old.get("build") or {}).get("source_ref")
    new_ref = cast(dict[str, Any], new.get("build") or {}).get("source_ref")
    lines = [f"# Hook replay: {old_ref} against {new_ref}", ""]
    for failure in summary["failures"]:
        lines.append(f"- record failure: `{failure}`")
    for mode, entry in summary["modes"].items():
        comparison = entry["comparison"]
        verdict = "identical" if comparison["identical"] else "DIFFERENT"
        lines.append(f"## Mode `{mode}`: {verdict}")
        lines.append("")
        if "refused" in comparison:
            lines.append("Refused: a read failed or was incomplete, so nothing was compared.")
            for side, reasons in comparison["refused"].items():
                for reason in reasons[:20]:
                    lines.append(f"- {side}: `{reason}`")
            lines.append("")
            continue
        lines.append("| Workspace | Compared parts | Ledger events (full payloads) | Result |")
        lines.append("|---|---:|---:|---|")
        for key, item in comparison["workspaces"].items():
            result = "identical" if item["identical"] else f"{len(item['mismatches'])} differ"
            lines.append(f"| {key} | {item['parts']} | {item['events']} | {result} |")
        lines.append("")
        bijection = comparison["bijection"]
        lines.append(f"Generated-value bijection consistent: {bijection['consistent']}.")
        lines.append("")
        lines.append("| Class | Values (old) | Identical in both | Interchangeable |")
        lines.append("|---|---:|---:|---:|")
        for kind, stats in sorted(bijection["by_kind"].items()):
            lines.append(
                f"| {kind} | {stats['values']} | {stats['identical_in_both']} | "
                f"{stats['interchangeable']} |"
            )
        lines.append("")
        lines.append("| Host | Event | n | Old median | New median | Old p90 | New p90 |")
        lines.append("|---|---|---:|---:|---:|---:|---:|")
        for row in entry["latency"]:
            lines.append(
                f"| {row['host']} | {row['event']} | {row['n']} | {row['old_median_ms']} ms | "
                f"{row['new_median_ms']} ms | {row['old_p90_ms']} ms | {row['new_p90_ms']} ms |"
            )
        lines.append("")
        for key, item in comparison["workspaces"].items():
            for mismatch in item["mismatches"][:5]:
                lines.append(f"### {mode} / {key} / {mismatch['part']} at `{mismatch['path']}`")
                lines.append("```text")
                lines.append("old: " + mismatch["old"][:1500])
                lines.append("new: " + mismatch["new"][:1500])
                lines.append("```")
    return "\n".join(lines) + "\n", summary


# ------------------------------------------------------------------------------------------- cli


def _cmd_corpus(args: argparse.Namespace) -> int:
    corpus = build_corpus([Path(path) for path in args.rollout], args.max_calls)
    Path(args.out).write_text(json.dumps(corpus, ensure_ascii=False), encoding="utf-8")
    counts: dict[str, int] = {}
    for item in corpus["items"]:
        counts[item["host"]] = counts.get(item["host"], 0) + 1
    print(json.dumps({"items": len(corpus["items"]), "by_host": counts}))
    return 0


def pinned_only_flag_error(args: argparse.Namespace) -> str | None:
    """Why the pinned-only experiment flags cannot be honored for these modes, or ``None``.

    Checked before any instance is provisioned, so a refused invocation leaves nothing behind.
    """

    if all(mode == "pinned" for mode in args.mode):
        return None
    for flag, value in (
        ("--admission-clock", args.admission_clock is not None),
        ("--fixed-observation-key", args.fixed_observation_key),
        ("--delay-ms", args.delay_ms != 0),
    ):
        if value:
            return f"{flag} applies to --mode pinned only"
    return None


def _cmd_replay(args: argparse.Namespace) -> int:
    refusal = pinned_only_flag_error(args)
    if refusal is not None:
        raise SystemExit(refusal)
    corpus = json.loads(Path(args.corpus).read_text(encoding="utf-8"))
    work_root = Path(args.work_root)
    work_root.mkdir(parents=True, exist_ok=True)
    log_path = work_root / f"replay-{args.tag}.log"

    def log(message: str) -> None:
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(message + "\n")

    record: dict[str, Any] = {
        "schema": "finishup.hook-replay-record/2",
        "pins": dict(PINNED_HOOK_BUDGETS),
        "corpus": corpus_identity(corpus),
        "runs": {},
        "instances": {},
    }
    # Each mode gets its own fresh instance: the corpus reuses recorded host session ids, and a
    # host session already bound in one workspace must not leak into the next mode's replay.
    for mode in args.mode:
        tag = f"{args.tag}{mode[0]}"
        instance = provision(
            Path(args.checkout), args.revision, Path(args.base).expanduser(), tag, args.python
        )
        log(f"provisioned {instance.provenance.get('source_ref')} at {instance.directory}")
        record["build"] = {
            key: instance.provenance.get(key)
            for key in ("source_ref", "source_state", "package_version", "package_digest")
        }
        replayer = Replayer(instance, work_root, log)
        replayer.delay_seconds = args.delay_ms / 1000.0
        replayer.admission_clock = args.admission_clock
        replayer.fixed_observation_key = args.fixed_observation_key
        entry: dict[str, Any] = {
            "tag": tag,
            "delay_ms": args.delay_ms,
            "admission_clock": args.admission_clock,
            "fixed_observation_key": args.fixed_observation_key,
        }
        record["instances"][mode] = entry
        try:
            started_at = datetime.now(UTC).isoformat()
            entry["setup"] = replayer.start(pause_background=mode == "pinned")
            run = replayer.replay(corpus, mode)
            run["started_at"] = started_at
            run["finished_at"] = datetime.now(UTC).isoformat()
            record["runs"][mode] = run
            # The service stops cleanly before its stores are exported; ``compare`` refuses a
            # run whose stop or export did not succeed.
            entry["stop"] = replayer.stop()
            run["service_stop"] = entry["stop"]
            run["export"] = replayer.export_ledgers()
            log(f"[{mode}] export ok={run['export'].get('ok')} {run['export'].get('error', '')}")
        finally:
            if replayer.service is not None:
                entry["stop"] = replayer.stop()
            entry["dispose"] = dispose(instance)
            Path(args.out).write_text(json.dumps(record, ensure_ascii=False), encoding="utf-8")
    return 0


def _cmd_latency(args: argparse.Namespace) -> int:
    """Both builds live at once, each callback run on one then the other (alternating order).

    Sequential replays of two builds see different machine load; interleaving each callback puts
    both builds under the same load at the same moment, so drift cancels out of the comparison.
    Latency only: the untouched launcher and service, nothing compared but wall time.
    """

    corpus = json.loads(Path(args.corpus).read_text(encoding="utf-8"))
    work_root = Path(args.work_root)
    work_root.mkdir(parents=True, exist_ok=True)
    log_path = work_root / f"latency-{args.tag}.log"

    def log(message: str) -> None:
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(message + "\n")

    record: dict[str, Any] = {
        "schema": "finishup.hook-replay-latency/1",
        "corpus": corpus_identity(corpus),
        "builds": {},
        "runs": {},
        "instances": {},
    }
    replayers: dict[str, Replayer] = {}
    base = Path(args.base).expanduser()
    try:
        for name, revision in (("old", args.old_revision), ("new", args.new_revision)):
            tag = f"{args.tag}{name[0]}"
            instance = provision(Path(args.checkout), revision, base, tag, args.python)
            record["builds"][name] = {
                key: instance.provenance.get(key)
                for key in ("source_ref", "source_state", "package_version", "package_digest")
            }
            replayers[name] = Replayer(instance, work_root / name, log)
            record["instances"][name] = {"tag": tag}
            record["instances"][name]["setup"] = replayers[name].start(pause_background=False)
        states = {name: replayer.begin(corpus, "shipped") for name, replayer in replayers.items()}
        for number, item in enumerate(cast(list[Item], corpus["items"]), start=1):
            for name in ("old", "new") if number % 2 else ("new", "old"):
                replayers[name].step(states[name], number, item)
        for name, state in states.items():
            record["runs"][name] = {"items": state.records}
    finally:
        for name, replayer in replayers.items():
            record["instances"][name]["stop"] = replayer.stop()
            record["instances"][name]["dispose"] = dispose(replayer.instance)
        Path(args.out).write_text(json.dumps(record, ensure_ascii=False), encoding="utf-8")
    rows = latency_table(record["runs"]["old"], record["runs"]["new"])
    print(json.dumps(rows, indent=1))
    return 0


def _cmd_compare(args: argparse.Namespace) -> int:
    old = json.loads(Path(args.old).read_text(encoding="utf-8"))
    new = json.loads(Path(args.new).read_text(encoding="utf-8"))
    report, summary = render_report(old, new)
    if args.report:
        Path(args.report).write_text(report, encoding="utf-8")
    if args.summary:
        Path(args.summary).write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(report)
    return 0 if summary["identical"] else 1


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    corpus = commands.add_parser("corpus", help="Build a replay corpus.")
    corpus.add_argument("--rollout", action="append", default=[], help="Codex rollout JSONL.")
    corpus.add_argument("--max-calls", type=int, default=24)
    corpus.add_argument("--out", required=True)
    corpus.set_defaults(handler=_cmd_corpus)
    replay = commands.add_parser("replay", help="Replay a corpus through one provisioned build.")
    replay.add_argument("--checkout", required=True)
    replay.add_argument("--revision", required=True)
    replay.add_argument("--tag", required=True)
    replay.add_argument("--base", default="~/.yz-instances")
    replay.add_argument("--python", default=sys.executable)
    replay.add_argument("--corpus", required=True)
    replay.add_argument("--work-root", required=True)
    replay.add_argument("--mode", action="append", choices=("pinned", "shipped"), required=True)
    replay.add_argument("--out", required=True)
    replay.add_argument(
        "--delay-ms",
        type=float,
        default=0.0,
        help="Pinned mode: hold each callback back this long before it starts (experiments).",
    )
    replay.add_argument(
        "--admission-clock",
        choices=sorted(ADMISSION_CLOCKS),
        help="Pinned mode: decide the admission buffer's flush without the wall clock (experiments).",
    )
    replay.add_argument(
        "--fixed-observation-key",
        action="store_true",
        help="Pinned mode: give every instance the same observation key (experiments).",
    )
    replay.set_defaults(handler=_cmd_replay)
    latency = commands.add_parser(
        "latency", help="Time two builds side by side, each callback interleaved."
    )
    latency.add_argument("--checkout", required=True)
    latency.add_argument("--old-revision", required=True)
    latency.add_argument("--new-revision", required=True)
    latency.add_argument("--tag", required=True)
    latency.add_argument("--base", default="~/.yz-instances")
    latency.add_argument("--python", default=sys.executable)
    latency.add_argument("--corpus", required=True)
    latency.add_argument("--work-root", required=True)
    latency.add_argument("--out", required=True)
    latency.set_defaults(handler=_cmd_latency)
    compare = commands.add_parser("compare", help="Compare two replay records.")
    compare.add_argument("old")
    compare.add_argument("new")
    compare.add_argument("--report")
    compare.add_argument("--summary")
    compare.set_defaults(handler=_cmd_compare)
    args = parser.parse_args(argv)
    return cast(Callable[[argparse.Namespace], int], args.handler)(args)


if __name__ == "__main__":
    raise SystemExit(main())
