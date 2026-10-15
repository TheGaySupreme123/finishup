"""Opt-in native startup tool control, separate from fail-open observation."""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
import time
from collections.abc import Callable, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO, Literal, cast

from finishup.adapters.integrations.startup_gate import GateScope, GateStore, accepted_publication
from finishup.adapters.workspace_binding import (
    canonical_workspace_locator,
    resolve_workspace_locator,
)
from finishup.cli.hook_io import (
    claude_context_output,
    cursor_context_output,
    read_cursor_hook_payload,
    stdout_json,
)
from finishup.domain.finishup_tools import (
    FINISHUP_SKILL_NAMES,
    FINISHUP_TOOL_SERVER_NAMES,
    finishup_scoped_tool_basename,
)
from finishup.legacy_names import GUIDANCE_SCHEME, LAUNCHER_NAMES, LEGACY_GUIDANCE_SCHEME
from finishup.ports.integrations import FINISHUP_WORKFLOW_TOOL_NAMES
from finishup.protocol.canonical import JsonValue
from finishup.protocol.errors import PublicErrorCode
from finishup.protocol.ids import IdKind, is_valid_id

_WORKFLOW = frozenset(FINISHUP_WORKFLOW_TOOL_NAMES)
# Cursor's ``mcp_server_name`` for the external and the plugin-bundled server, under the current
# and the legacy server name a 0.1-0.2.5 registration still carries (ADR-048).
_CURSOR_SERVER_KEYS = frozenset(
    key for server in FINISHUP_TOOL_SERVER_NAMES for key in (server, f"plugin-{server}-{server}")
)
# The bootstrap guidance documents, readable under either URI scheme: installed 0.1-0.2.5
# guidance and skills still name ``yoetz://`` (ADR-048).
_BOOTSTRAP_GUIDANCE_URIS = frozenset(
    f"{scheme}://guidance/{name}.md"
    for scheme in (GUIDANCE_SCHEME, LEGACY_GUIDANCE_SCHEME)
    for name in (
        "agent-instructions",
        "workflow",
        "publication-policy",
        "coverage-and-receipts",
        "request-templates",
    )
)
_SKILLS = frozenset(FINISHUP_SKILL_NAMES)
_DISCOVERY = frozenset({"ToolSearch", "AskUserQuestion", "AskQuestion", "ListMcpResources"})
_PRE = frozenset({"PreToolUse", "preToolUse", "beforeMCPExecution"})
_POST = frozenset({"PostToolUse", "PostToolUseFailure", "afterMCPExecution"})
_RESET = frozenset({"SessionStart", "sessionStart", "UserPromptSubmit", "beforeSubmitPrompt"})
_TRACKED_WRITES = frozenset({"start", "publish_work"})
_RETRYABLE_FAILURE_CODES = frozenset(
    {
        PublicErrorCode.OPERATION_PENDING.value,
        PublicErrorCode.INTERNAL_ERROR.value,
        PublicErrorCode.SERVICE_UNAVAILABLE.value,
    }
)
_PRESERVE_PENDING_CODES = _RETRYABLE_FAILURE_CODES | frozenset(
    {
        # A rejected replay can conflict with an operation that was already accepted or whose
        # outcome is still ambiguous. Keep the original ticket until an exact retry or status
        # recovery proves its outcome.
        PublicErrorCode.IDEMPOTENCY_CONFLICT.value,
        PublicErrorCode.REQUEST_IDENTITY_CONFLICT.value,
    }
)
_TERMINAL_FAILURE_CODES = frozenset(
    code.value for code in PublicErrorCode if code.value not in _PRESERVE_PENDING_CODES
)
_NOTICE = (
    "FinishUP required startup is active. Read finishup://guidance/workflow.md and load FinishUP tools. "
    "Start or attach this host session, then publish an accepted current-scope plan containing "
    "its obligations before investigation, edits, commands, or delegation. Each user turn and "
    "resume/compaction requires a fresh plan or plan revision. Keep the same task and recover "
    "pending operations with their original request ids. Text-only trivial answers need no "
    "bootstrap. The owner can replace this plugin with --startup-mode optional to disable the gate."
)
_RESET_FAILURE_NOTICE = (
    "FinishUP required startup could not safely advance this turn. Retry the exact prompt after "
    "the host's FinishUP state is writable; pending requests keep their original request ids. "
    "Substantive tool calls remain blocked until a fresh accepted plan is recorded."
)
_RESET_FAILURE_CONTEXT = (
    "FinishUP required startup could not safely advance this session boundary. The host's "
    "session-start hook cannot block the first prompt or tool; repair writable state and retry "
    "before substantive work. Pending requests keep their original request ids."
)


def _object(value: object) -> Mapping[str, JsonValue] | None:
    if isinstance(value, str):
        if len(value.encode()) > 262_144:
            return None
        try:
            value = json.loads(value)
        except ValueError:
            return None
    return cast(Mapping[str, JsonValue], value) if isinstance(value, dict) else None


def _result(value: object) -> Mapping[str, JsonValue] | None:
    obj = _object(value)
    if obj is None:
        return None
    result = obj
    if "structuredContent" in obj or "structured_content" in obj:
        result = _object(obj.get("structuredContent", obj.get("structured_content")))
    elif "content" in obj:
        blocks = obj.get("content")
        result = None
        if isinstance(blocks, list) and len(blocks) == 1 and isinstance(blocks[0], dict):
            result = _object(blocks[0].get("text"))
    if obj.get("isError") is True and (result is None or result.get("ok") is not False):
        return None
    return result


def workflow_tool(payload: Mapping[str, JsonValue], host: str, event: str) -> str | None:
    tool = payload.get("tool_name")
    if not isinstance(tool, str):
        return None
    server = payload.get("mcp_server_name")
    if host == "cursor" and event in {"beforeMCPExecution", "afterMCPExecution"}:
        return tool if server in _CURSOR_SERVER_KEYS and tool in _WORKFLOW else None
    return finishup_scoped_tool_basename(tool)


def bootstrap_tool(payload: Mapping[str, JsonValue], host: str, event: str) -> bool:
    tool = payload.get("tool_name")
    if not isinstance(tool, str):
        return False
    if workflow_tool(payload, host, event) is not None or tool in _DISCOVERY:
        return True
    if tool == "ReadMcpResource":
        arguments = _object(payload.get("tool_input"))
        return arguments is not None and arguments.get("uri") in _BOOTSTRAP_GUIDANCE_URIS
    if host == "cursor" and event == "preToolUse" and tool.startswith(("MCP:", "mcp__")):
        return True  # Deferred to the server-qualified beforeMCPExecution gate.
    if tool == "Skill":
        arguments = _object(payload.get("tool_input"))
        return arguments is not None and arguments.get("skill") in _SKILLS
    if tool in {"Bash", "Shell"}:
        arguments = _object(payload.get("tool_input"))
        command = None if arguments is None else arguments.get("command")
        if not isinstance(command, str) or any(char in command for char in ";|&<>`$\n\r"):
            return False
        try:
            argv = shlex.split(command)
        except ValueError:
            return False
        if len(argv) < 3:
            return False
        # This runtime's own launcher, or its deprecated legacy alias (ADR-048).
        launchers = {Path(sys.prefix) / "bin" / name for name in LAUNCHER_NAMES}
        selected = shutil.which(argv[0]) if argv[0] in LAUNCHER_NAMES else argv[0]
        if selected is None or Path(selected).absolute() not in launchers:
            return False
        # This only leaves the host's normal tool admission in force. It does
        # not authorize a named repair, consent decision, OS presence or unlock;
        # the existing runtime ceremony and current user instruction still do.
        return (argv[1], argv[2]) in {
            ("service", "status"),
            ("service", "diagnostics"),
            ("service", "restart"),
            ("consent", "catalog"),
            ("consent", "prepare"),
            ("consent", "status"),
            ("consent", "review"),
            ("consent", "authorize"),
            ("vault", "unlock"),
        }
    return False


def proposed_obligations(request: Mapping[str, JsonValue] | None) -> list[str]:
    if request is None:
        return []
    drafts = request.get("event_drafts")
    if not isinstance(drafts, list) or len(drafts) > 100:
        return []
    refs: set[str] = set()
    for draft in drafts:
        if not isinstance(draft, dict):
            continue
        schema, payload = draft.get("schema"), draft.get("payload")
        if (
            isinstance(schema, dict)
            and schema.get("name") == "obligation_published"
            and isinstance(payload, dict)
            # acknowledged_not_done (#1002) is not resolved: counted like open.
            and payload.get("status") in {"open", "acknowledged_not_done"}
        ):
            ref = payload.get("obligation_id")
            if isinstance(ref, str) and is_valid_id(IdKind.OBLIGATION, ref):
                refs.add(ref)
    return sorted(refs)


def clear_pending(scope: GateScope, rid: str) -> None:
    scope.pending.pop(rid, None)
    scope.pending_refs.pop(rid, None)
    scope.pending_generations.pop(rid, None)


def terminal_failure(result: Mapping[str, JsonValue]) -> bool:
    error = result.get("error")
    code = None if not isinstance(error, dict) else error.get("code")
    return result.get("ok") is False and type(code) is str and code in _TERMINAL_FAILURE_CODES


def recover_pending(scope: GateScope, result: Mapping[str, JsonValue]) -> None:
    if result.get("view") != "operation" or scope.route != (
        result.get("task_id"),
        result.get("session_id"),
        result.get("writer_id"),
    ):
        return
    page = result.get("page")
    if not isinstance(page, dict):
        return
    rid = page.get("operation_request_id")
    if not isinstance(rid, str) or rid not in scope.pending:
        return
    if page.get("state") == "complete":
        scope.required_refs = sorted(set(scope.required_refs) | set(scope.pending_refs[rid]))
        # The compact read cannot infer a lost plan payload; require a fresh
        # accepted restatement, without replaying a known complete write.
        scope.plan_generation = None
        clear_pending(scope, rid)
    elif page.get("state") == "absent":
        clear_pending(scope, rid)


def _invalidate_state(store: GateStore) -> None:
    """Persist an invalidation marker when a scope boundary cannot be persisted."""

    if not store.invalidate():
        raise OSError("startup_gate_reset_invalidation_failed")


@contextmanager
def _locked_for_event(store: GateStore, event: str):
    """Retry reset locks briefly, invalidating state when reset persistence fails."""

    if event not in _RESET:
        with store.locked():
            yield
        return
    for attempt in range(16):
        try:
            with store.locked():
                yield
                store.clear_invalidation()
            return
        except BlockingIOError:
            if attempt == 15:
                _invalidate_state(store)
                raise
            time.sleep(0.01)
        except Exception:
            _invalidate_state(store)
            raise


def _probe(scope: GateScope, workspace: str) -> bool:
    try:
        environment = dict(os.environ)
        environment.pop("PYTHONPATH", None)
        environment.pop("PYTHONSTARTUP", None)
        environment["PYTHONNOUSERSITE"] = "1"
        result = subprocess.run(
            [sys.executable, "-I", "-m", "finishup.cli.startup_gate_probe"],
            input=json.dumps(
                {
                    "route": scope.route,
                    "plan_id": scope.plan_id,
                    "obligation_count": len(scope.plan_refs),
                    "workspace": workspace,
                }
            ).encode(),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=1.25,
            check=False,
            cwd=os.path.sep,
            env=environment,
        )
        return result.returncode == 0 and result.stdout.strip() == b'{"ready": true}'
    except OSError, subprocess.TimeoutExpired:
        return False


def gate_output(host: str, event: str, admitted: bool, reason: str) -> dict[str, JsonValue]:
    if event not in _PRE:
        return {}
    if host == "claude":
        return (
            {}
            if admitted
            else {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": f"FinishUP required startup: {reason}. {_NOTICE}",
                }
            }
        )
    # beforeMCPExecution is an admission boundary. Never approve an MCP tool
    # here, including check: native user approval remains necessary (ADR-018).
    if admitted:
        return {"permission": "ask" if event == "beforeMCPExecution" else "allow"}
    return {
        "permission": "deny",
        "user_message": f"FinishUP startup: {reason}.",
        "agent_message": _NOTICE,
    }


def reset_failure_output(host: str, event: str) -> dict[str, JsonValue]:
    """Report a failed scope boundary using the host's supported control field.

    Claude's UserPromptSubmit and Cursor's beforeSubmitPrompt can block the
    current turn. Their session-start events are context-only, so they receive
    a bounded diagnostic and the following native pre-tool gate remains the
    enforcement boundary when durable invalidation succeeded.
    """

    if host == "claude" and event == "UserPromptSubmit":
        return {"decision": "block", "reason": _RESET_FAILURE_NOTICE}
    if host == "cursor" and event == "beforeSubmitPrompt":
        return {"continue": False, "user_message": _RESET_FAILURE_NOTICE}
    if host == "claude":
        return claude_context_output(event, _RESET_FAILURE_CONTEXT)
    return cursor_context_output(event, _RESET_FAILURE_CONTEXT)


def handle_startup_gate(
    *,
    host: Literal["claude", "cursor"],
    event: str,
    stdin_bytes: bytes | None = None,
    stdout: BinaryIO | None = None,
    _state: Path | None = None,
    probe: Callable[[GateScope, str], bool] = _probe,
) -> int:
    admitted, reason = False, "readiness_unavailable"
    output: dict[str, JsonValue] | None = None
    tool: str | None = None
    try:
        payload = read_cursor_hook_payload(stdin_bytes)
        # Bootstrap and same-request recovery remain available even if local
        # gate state cannot be read or the per-session lock is busy.
        # Resolve the workflow name before validating host identity or opening
        # the sidecar so tracked writes fail closed on every early error.
        tool = workflow_tool(payload, host, event)
        admitted = event in _PRE and bootstrap_tool(payload, host, event)
        session = payload.get("session_id") if host == "claude" else payload.get("conversation_id")
        if not isinstance(session, str) or not session:
            raise ValueError("startup_gate_identity_invalid")
        workspace = (
            canonical_workspace_locator(cast(str, payload.get("cwd")))
            if host == "claude" and isinstance(payload.get("cwd"), str)
            else resolve_workspace_locator(payload=payload)
        )
        if workspace is None:
            raise ValueError("startup_gate_workspace_invalid")
        request = _object(payload.get("tool_input"))
        store = GateStore(host, session, workspace, root=_state)
        with _locked_for_event(store, event):
            # A reset owns the lock and is the only operation allowed to
            # replace an invalidated sidecar. Preserve its route and pending
            # identities while GateScope.fresh clears the current readiness.
            scope = store.read_for_reset() if event in _RESET else store.read()
            if event in _RESET:
                keep = event in {"UserPromptSubmit", "beforeSubmitPrompt"} or payload.get(
                    "source"
                ) in {"resume", "compact"}
                old = scope
                scope = GateScope.fresh(scope)
                if not keep:
                    scope.needs_start = True
                    scope.plan_generation = None
                if old is None:
                    scope = GateScope.fresh()
                store.write(scope)
                output = (
                    claude_context_output(event, _NOTICE)
                    if host == "claude"
                    else {"continue": True}
                    if event == "beforeSubmitPrompt"
                    else cursor_context_output(event, _NOTICE)
                )
            elif event in {"SessionEnd", "sessionEnd"}:
                # A failed reset owns the invalidation marker. Do not let a
                # teardown hook replace the old sidecar with a fresh empty
                # scope while that marker is still present.
                if not store.is_invalidated():
                    store.write(GateScope.fresh(scope))
                output = {}
            elif event in _PRE:
                # An unqualified Cursor MCP name is checked by the separate
                # beforeMCPExecution hook, where server ownership is available.
                cursor_mcp = (
                    host == "cursor"
                    and event == "preToolUse"
                    and isinstance(payload.get("tool_name"), str)
                    and cast(str, payload["tool_name"]).startswith(("MCP:", "mcp__"))
                )
                if admitted:
                    admitted = True
                    if tool in _TRACKED_WRITES and not cursor_mcp:
                        try:
                            invalidated = store.is_invalidated()
                        except Exception:
                            invalidated = True
                        if invalidated:
                            # An invalidated sidecar is unreadable by design.
                            # Never replace it with an empty scope from a
                            # bootstrap write: that would discard ambiguous
                            # request identities before the next reset.
                            admitted = False
                            reason = "scope_reset_required"
                        else:
                            if scope is None:
                                scope = GateScope.fresh()
                            rid = None if request is None else request.get("request_id")
                            if isinstance(rid, str) and is_valid_id(IdKind.REQUEST, rid):
                                if len(scope.pending) >= 32 and rid not in scope.pending:
                                    # Preserve every ambiguous write identity. The
                                    # caller must retry one of those exact requests
                                    # before another pending ticket can be admitted.
                                    admitted = False
                                    reason = "pending_operation_capacity"
                                elif rid in scope.pending and scope.pending[rid] != tool:
                                    # A request id is bound to its original workflow operation;
                                    # do not let a mismatched replay replace its ticket metadata.
                                    admitted = False
                                    reason = "request_identity_conflict"
                                else:
                                    scope.pending.setdefault(rid, tool)
                                    scope.pending_generations.setdefault(rid, scope.generation)
                                    scope.pending_refs.setdefault(
                                        rid, proposed_obligations(request)
                                    )
                                    store.write(scope)
                elif scope is None or not scope.candidate:
                    reason = "current_plan_required"
                else:
                    # Release the private lock before the service probe. A
                    # concurrent scope mutation is fenced by the second read.
                    output = None
            elif (
                event in _POST and scope is not None and tool in {"start", "publish_work", "status"}
            ):
                result = _result(
                    payload.get("result_json") if host == "cursor" else payload.get("tool_response")
                )
                rid = None if request is None else request.get("request_id")
                # Cursor afterMCPExecution may omit tool_input. The service's
                # echoed request id still needs the exact pre-call ticket.
                if rid is None and result is not None:
                    rid = result.get("request_id")
                if tool == "status" and result is not None and result.get("ok") is True:
                    recover_pending(scope, result)
                    store.write(scope)
                if isinstance(rid, str) and scope.pending.get(rid) == tool:
                    if (
                        result is not None
                        and result.get("request_id") == rid
                        and result.get("ok") is True
                        and event != "PostToolUseFailure"
                    ):
                        if tool == "start":
                            values = (
                                result.get("task_id"),
                                result.get("session_id"),
                                result.get("writer_id"),
                            )
                            if all(
                                isinstance(value, str) and is_valid_id(kind, value)
                                for kind, value in zip(
                                    (IdKind.TASK, IdKind.SESSION, IdKind.WRITER),
                                    values,
                                    strict=True,
                                )
                            ):
                                route = cast(tuple[str, str, str], values)
                                if scope.route is not None and scope.route[0] != route[0]:
                                    scope.plan_refs, scope.required_refs = [], []
                                    scope.plan_version, scope.plan_id = 0, None
                                scope.route = route
                                scope.needs_start = False
                                scope.plan_generation = None
                        elif request is not None:
                            accepted_publication(scope, request, result)
                    if scope.pending_generations.get(rid) != scope.generation:
                        scope.plan_generation = None
                    # A failed/unknown write cannot silently release the gate.
                    # Retain its ticket until an exact successful replay proves
                    # the outcome; read-only operation recovery remains allowed.
                    if (
                        result is not None
                        and result.get("request_id") == rid
                        and (result.get("ok") is True or terminal_failure(result))
                    ):
                        clear_pending(scope, rid)
                    store.write(scope)
                output = {}
            else:
                output = {}
        if event in _PRE and not admitted and scope is not None and scope.candidate:
            if probe(scope, workspace):
                with store.locked():
                    current = store.read()
                    admitted = current is not None and current == scope and current.candidate
                reason = "scope_changed" if not admitted else "ready"
            else:
                reason = "live_plan_unverified"
        if output is None:
            output = gate_output(host, event, admitted, reason)
    except Exception:
        # A bootstrap write must be represented in the sidecar before the host
        # may run it. If lock acquisition or state persistence fails, never
        # return the bootstrap admission that was computed before the failure.
        if event in _PRE and tool in _TRACKED_WRITES:
            admitted = False
            reason = "startup_gate_state_unavailable"
        output = (
            reset_failure_output(host, event)
            if event in _RESET
            else gate_output(host, event, admitted, reason)
        )
    stdout_json(output, stdout)
    return 0
