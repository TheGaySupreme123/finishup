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
"""

from __future__ import annotations

import argparse
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
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
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
    "from finishup.cli import observe_hooks\n"
    "for name, value in json.loads(os.environ['HOOK_REPLAY_PINS']).items():\n"
    "    if not hasattr(observe_hooks, name):\n"
    "        raise SystemExit('hook_replay_pin_unknown:' + name)\n"
    "    setattr(observe_hooks, name, value)\n"
    "sys.argv = sys.argv[1:]\n"
    "from finishup.cli.entry import main\n"
    "main()\n"
)
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


class Replayer:
    """One provisioned build: its service, its ceremonies, and the replay through it."""

    def __init__(self, instance: Instance, work_root: Path, log: Callable[[str], None]) -> None:
        self.instance = instance
        self.work_root = work_root
        self.home = work_root / "home"
        self.log = log
        self.service: subprocess.Popen[bytes] | None = None
        self._ceremony = _load_by_path("hook_replay_ceremony", _HERE / "dogfood_ci" / "ceremony.py")
        self._lane = _load_by_path("hook_replay_lane", _HERE / "dogfood_ci" / "lane.py")

    def env(self, extra: Mapping[str, str] | None = None) -> dict[str, str]:
        return instance_env(self.home, extra)

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

    def start(self) -> dict[str, Any]:
        if self.home.exists():
            shutil.rmtree(self.home)
        (self.home / ".codex").mkdir(parents=True, mode=0o700)
        log_path = self.work_root / f"service-{self.instance.tag}.log"
        self.service = subprocess.Popen(  # noqa: S603 - fixed instance launcher argv
            [str(self.instance.launcher), "service", "run"],
            cwd=self.home,
            env=self.env(),
            stdin=subprocess.DEVNULL,
            stdout=log_path.open("wb"),
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        status = self._wait_status(lambda s: True)
        if status.get("vault_mode") != "uninitialized":
            raise SystemExit(f"vault not fresh: {status.get('vault_mode')}")
        passphrase = secrets.token_urlsafe(24)
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
        return {"service_status": ready, "privacy_answered": privacy.answered}

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
        try:
            outcome["exit_code"] = self.service.wait(timeout=60.0)
        except subprocess.TimeoutExpired:
            # Only the PID this replayer spawned is ever signalled.
            self.service.terminate()
            outcome["exit_code"] = self.service.wait(timeout=30.0)
            outcome["terminated"] = True
        self.service = None
        return outcome

    def replay(self, corpus: Mapping[str, Any], mode: str) -> dict[str, Any]:
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
            setup[key] = {"grant_returncode": grant.returncode}
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
                setup[key]["content_enable_returncode"] = enabled.returncode
        transcript_written = {name: 0 for name in transcripts}
        transcript_paths = {
            name: self.home / ".codex" / "sessions" / "2026" / "10" / "16" / spec["file"]
            for name, spec in transcripts.items()
        }
        claude_transcript = self.home / ".claude" / "projects" / "replay" / "session.jsonl"
        claude_transcript.parent.mkdir(parents=True, exist_ok=True)
        claude_transcript.touch()
        retained = self.instance.retained_python()
        records: list[dict[str, Any]] = []
        for number, item in enumerate(items, start=1):
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
                extra = {**host_env, "HOOK_REPLAY_PINS": json.dumps(dict(PINNED_HOOK_BUDGETS))}
            else:
                command = [str(self.instance.launcher), *argv]
                extra = host_env
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
            if item["workspace"] != "cli":
                drained = self.finishup(
                    ["observe", "drain", "--workspace", str(workspace), "--json"], cwd=workspace
                )
                record["drain"] = {
                    "returncode": drained.returncode,
                    "stdout": drained.stdout.decode("utf-8", errors="replace"),
                }
            records.append(record)
            self.log(
                f"[{mode}] {number}/{len(items)} {item['label']} rc={done.returncode} {elapsed_ms:.0f}ms"
            )
        ledgers = {
            key: self._ledger(mode_root / key, records, key) for key in workspaces if key != "cli"
        }
        return {"setup": setup, "items": records, "ledgers": ledgers}

    def _ledger(
        self, workspace: Path, records: Sequence[Mapping[str, Any]], key: str
    ) -> dict[str, Any]:
        mapping = None
        for record in records:
            if record["workspace"] != key:
                continue
            match = _MAPPED.search(cast(str, record["stdout"]) + "\n" + cast(str, record["stderr"]))
            if match:
                mapping = {"session_id": match.group(2), "writer_id": match.group(3)}
                break
        observed = self.finishup(["observe", "status", "--workspace", str(workspace), "--json"])
        result: dict[str, Any] = {
            "mapped": mapping is not None,
            "observe_status": observed.stdout.decode("utf-8", errors="replace"),
        }
        if mapping is None:
            return result
        history: list[Any] = []
        cursor: str | None = None
        for page in range(1, 200):
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
            try:
                status = cast(dict[str, Any], json.loads(done.stdout))
            except ValueError:
                result["history_error"] = done.stderr.decode("utf-8", errors="replace")[-2000:]
                break
            page_value = cast(dict[str, Any], status.get("page") or {})
            history.extend(cast(list[Any], page_value.get("items") or []))
            cursor = cast(str | None, page_value.get("next_cursor"))
            if cursor is None:
                result["head_frontier"] = status.get("head_frontier")
                break
        result["history"] = history
        return result


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

_TOKEN_PATTERNS: Final = (
    ("hmac", re.compile(r"hmac-sha256:[0-9a-f]{64}")),
    ("digest", re.compile(r"(?<!hmac-)sha256:[0-9a-f]{64}")),
    (
        "id",
        re.compile(r"\b[a-z]{2,5}_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"),
    ),
    (
        "uuid",
        re.compile(
            r"(?<![_0-9a-f-])[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"
        ),
    ),
    ("hex64", re.compile(r"(?<![:0-9a-f])[0-9a-f]{64}(?![0-9a-f])")),
    ("time", re.compile(r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})")),
)


def _tokens(text: str) -> Iterator[tuple[str, str]]:
    for kind, pattern in _TOKEN_PATTERNS:
        for match in pattern.finditer(text):
            yield kind, match.group(0)


@dataclass(slots=True)
class Renamer:
    """Renames the values only one run produced, consistently, in order of first appearance.

    A value present in both runs (a recorded host id, a digest of identical content) is kept
    verbatim and compared exactly; a value present in only one run was generated by that run
    (a fresh identifier, a wall-clock time, an installation-keyed commitment) and is replaced by
    ``<kind#n>``. Two runs that differ only in such values normalize to identical text.
    """

    run_only: frozenset[str]
    names: dict[str, str]
    counters: dict[str, int]
    renamed_kinds: dict[str, int]

    @classmethod
    def for_runs(cls, mine: str, theirs: str) -> Renamer:
        own = {value for _kind, value in _tokens(mine)}
        other = {value for _kind, value in _tokens(theirs)}
        return cls(frozenset(own - other), {}, {}, {})

    def apply(self, text: str) -> str:
        spans: list[tuple[int, int, str]] = []
        for kind, pattern in _TOKEN_PATTERNS:
            for match in pattern.finditer(text):
                value = match.group(0)
                if value not in self.run_only:
                    continue
                if any(start < match.end() and match.start() < end for start, end, _ in spans):
                    continue
                if value not in self.names:
                    self.counters[kind] = self.counters.get(kind, 0) + 1
                    self.names[value] = f"<{kind}#{self.counters[kind]}>"
                self.renamed_kinds[kind] = self.renamed_kinds.get(kind, 0) + 1
                spans.append((match.start(), match.end(), self.names[value]))
        out: list[str] = []
        cursor = 0
        for start, end, name in sorted(spans):
            out.append(text[cursor:start])
            out.append(name)
            cursor = end
        out.append(text[cursor:])
        return "".join(out)


def _stream(run: Mapping[str, Any], key: str) -> list[tuple[str, str]]:
    """Every compared byte of one workspace, as labelled text parts in replay order."""

    parts: list[tuple[str, str]] = []
    for item in cast(list[dict[str, Any]], run["items"]):
        if item["workspace"] != key:
            continue
        label = cast(str, item["label"])
        parts.append((f"{label} returncode", str(item["returncode"])))
        parts.append((f"{label} stdout", cast(str, item["stdout"])))
        parts.append((f"{label} stderr", cast(str, item["stderr"])))
        if "drain" in item:
            drain = cast(dict[str, Any], item["drain"])
            parts.append((f"{label} drain", f"{drain['returncode']}\n{drain['stdout']}"))
    ledger = cast(dict[str, Any] | None, run["ledgers"].get(key))
    if ledger is not None:
        parts.append(("ledger mapped", str(ledger.get("mapped"))))
        for index, event in enumerate(cast(list[Any], ledger.get("history") or [])):
            parts.append((f"ledger history[{index}]", json.dumps(event, sort_keys=True)))
        parts.append(("ledger head", json.dumps(ledger.get("head_frontier"), sort_keys=True)))
    return parts


def compare_runs(old: Mapping[str, Any], new: Mapping[str, Any]) -> dict[str, Any]:
    """Compare two replays of one corpus, workspace by workspace, after renaming run-only values."""

    workspaces = sorted({cast(str, item["workspace"]) for item in old["items"]})
    old_labels = [item["label"] for item in old["items"]]
    new_labels = [item["label"] for item in new["items"]]
    result: dict[str, Any] = {"labels_match": old_labels == new_labels, "workspaces": {}}
    for key in workspaces:
        old_parts, new_parts = _stream(old, key), _stream(new, key)
        old_text = "\n".join(text for _label, text in old_parts)
        new_text = "\n".join(text for _label, text in new_parts)
        old_renamer = Renamer.for_runs(old_text, new_text)
        new_renamer = Renamer.for_runs(new_text, old_text)
        mismatches: list[dict[str, str]] = []
        if [label for label, _ in old_parts] != [label for label, _ in new_parts]:
            mismatches.append({"part": "structure", "old": "parts differ", "new": "parts differ"})
        for (label, old_value), (_label, new_value) in zip(old_parts, new_parts, strict=False):
            a, b = old_renamer.apply(old_value), new_renamer.apply(new_value)
            if a != b:
                mismatches.append({"part": label, "old": a[:4000], "new": b[:4000]})
        ledger = cast(dict[str, Any], old["ledgers"].get(key) or {})
        result["workspaces"][key] = {
            "parts": len(old_parts),
            "history_events": len(cast(list[Any], ledger.get("history") or [])),
            "identical": not mismatches,
            "mismatches": mismatches,
            "renamed_old": dict(old_renamer.renamed_kinds),
            "renamed_new": dict(new_renamer.renamed_kinds),
        }
    result["identical"] = result["labels_match"] and all(
        entry["identical"] for entry in result["workspaces"].values()
    )
    return result


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


def render_report(old: Mapping[str, Any], new: Mapping[str, Any]) -> tuple[str, dict[str, Any]]:
    modes = sorted(set(old["runs"]) & set(new["runs"]))
    summary: dict[str, Any] = {"old": old["build"], "new": new["build"], "modes": {}}
    lines = [
        f"# Hook replay: {old['build']['source_ref']} against {new['build']['source_ref']}",
        "",
    ]
    for mode in modes:
        comparison = compare_runs(old["runs"][mode], new["runs"][mode])
        latency = latency_table(old["runs"][mode], new["runs"][mode])
        summary["modes"][mode] = {"comparison": comparison, "latency": latency}
        lines.append(f"## Mode `{mode}`: {'identical' if comparison['identical'] else 'DIFFERENT'}")
        lines.append("")
        lines.append(
            "| Workspace | Compared parts | Ledger events | Result | Renamed (old / new) |"
        )
        lines.append("|---|---:|---:|---|---|")
        for key, entry in comparison["workspaces"].items():
            lines.append(
                f"| {key} | {entry['parts']} | {entry['history_events']} | "
                f"{'identical' if entry['identical'] else f'{len(entry["mismatches"])} differ'} | "
                f"{entry['renamed_old']} / {entry['renamed_new']} |"
            )
        lines.append("")
        lines.append("| Host | Event | n | Old median | New median | Old p90 | New p90 |")
        lines.append("|---|---|---:|---:|---:|---:|---:|")
        for row in latency:
            lines.append(
                f"| {row['host']} | {row['event']} | {row['n']} | {row['old_median_ms']} ms | "
                f"{row['new_median_ms']} ms | {row['old_p90_ms']} ms | {row['new_p90_ms']} ms |"
            )
        lines.append("")
        for key, entry in comparison["workspaces"].items():
            for mismatch in entry["mismatches"][:5]:
                lines.append(f"### {mode} / {key} / {mismatch['part']}")
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


def _cmd_replay(args: argparse.Namespace) -> int:
    corpus = json.loads(Path(args.corpus).read_text(encoding="utf-8"))
    work_root = Path(args.work_root)
    work_root.mkdir(parents=True, exist_ok=True)
    log_path = work_root / f"replay-{args.tag}.log"

    def log(message: str) -> None:
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(message + "\n")

    record: dict[str, Any] = {
        "schema": "finishup.hook-replay-record/1",
        "pins": dict(PINNED_HOOK_BUDGETS),
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
        entry: dict[str, Any] = {"tag": tag}
        record["instances"][mode] = entry
        try:
            entry["setup"] = replayer.start()
            record["runs"][mode] = replayer.replay(corpus, mode)
        finally:
            entry["stop"] = replayer.stop()
            entry["dispose"] = dispose(instance)
            Path(args.out).write_text(json.dumps(record, ensure_ascii=False), encoding="utf-8")
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
    return 0 if all(m["comparison"]["identical"] for m in summary["modes"].values()) else 1


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
    replay.set_defaults(handler=_cmd_replay)
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
