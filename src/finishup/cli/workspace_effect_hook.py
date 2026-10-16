"""The hook's half of the workspace-effect fact (PR #1080 round 5, ADR-033 amendment).

``handle_observe`` calls ``workspace_fingerprint_pass`` once per live ``PreToolUse`` and
``PostToolUse`` hook pass, before it takes the observation store lock: the pre-call pass snapshots
the workspace while the host is still waiting to run the call, and the post-call pass compares and
returns the closed reading the envelope carries as ``workspace_effect``. Which calls are
fingerprinted, and when a call counts as ended, are decided here; the walk itself is
``adapters.workspace_fingerprint``.

Fingerprinted calls: every shell or exec tool, and every other tool that is not FinishUP's own
MCP tool, a host-native read (``Read``, ``Grep``, ``Glob``), an edit tool (already material by
itself), or one of a closed set of host tools that cannot touch files (planning, web search, a
Codex poll or sleep). A third-party MCP tool, a subagent, a process poll such as Codex's
``write_stdin`` and Claude Code's ``BashOutput`` are fingerprinted, so a write they make is seen.

A post-call reading is ``unavailable`` unless the host reported that the call ended: an explicit
process exit, a closed success or failure fact, or a denial. Codex reports a process still running
behind a session id with no exit, and Claude Code's ``run_in_background`` launch has no completion
fact; their later writes would fall outside the window, so FinishUP does not vouch for them.

Replays never fingerprint: the service's legacy-spool replay passes no workspace locator, and the
synchronous legacy Codex spool hook does not call this path at all. Those observations carry no
fact and stay material.
"""

from __future__ import annotations

import os
import re
import time
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Final, cast

from finishup.adapters.workspace_fingerprint import (
    SNAPSHOT_SECONDS,
    WorkspaceEffectReading,
    WorkspaceFingerprintStore,
    workspace_fingerprint_dir,
)
from finishup.domain.observation_selection import ROUTINE_READ_TOOLS, SHELL_TOOLS
from finishup.domain.values import JsonValue

__all__ = [
    "command_may_outlive_call",
    "fingerprinted_tool",
    "host_call_complete",
    "owned_relative_paths",
    "workspace_fingerprint_pass",
]

# Host tools that cannot touch the workspace: planning and task lists, web reads, questions to
# the user, and Codex's own poll and sleep controls. Leaving one out only costs a snapshot.
_INERT_TOOLS: Final = frozenset(
    {
        "askuserquestion",
        "clocksleep",
        "exitplanmode",
        "todowrite",
        "update_plan",
        "view_image",
        "wait",
        "web_search",
        "webfetch",
        "websearch",
    }
)
# The edit family as materialization names it (``observation_materialize._action_kind``): an edit
# is material by itself, so it needs no fingerprint.
_EDIT_TOOLS: Final = frozenset(
    {
        "apply_patch",
        "create_file",
        "edit",
        "file_change",
        "multi_edit",
        "str_replace",
        "write",
        "write_file",
    }
)
_COMMAND_HINTS: Final = ("shell", "exec", "terminal")


def _token(value: object) -> str | None:
    if type(value) is not str or not value or len(value) > 128:
        return None
    return value


def fingerprinted_tool(tool_name: object, *, finishup_owned: bool) -> bool:
    """Whether a call of *tool_name* gets a before/after workspace fingerprint."""

    token = _token(tool_name)
    if token is None or finishup_owned:
        return False
    lowered = token.casefold()
    if lowered in SHELL_TOOLS or any(hint in lowered for hint in _COMMAND_HINTS):
        return True
    if lowered in ROUTINE_READ_TOOLS or lowered in _INERT_TOOLS:
        return False
    return not (lowered in _EDIT_TOOLS or "edit" in lowered or "patch" in lowered)


# A shell background operator (a lone ``&``, not ``&&``, ``>&``, ``&>``, ``<&`` or ``|&``) or a
# detaching launcher. The text can only make a call *less* trusted here: a command that may leave
# a process writing after the post-call snapshot cannot be shown to have left the workspace
# unchanged. A quoted ``&`` is a false positive in the conservative direction.
_BACKGROUND_OPERATOR: Final = re.compile(r"(?<![&|<>])&(?![&>])")
_DETACHING_WORD: Final = re.compile(
    r"(?:^|[\s;|&(`])(?:nohup|setsid|disown|daemonize|start-stop-daemon)(?=$|[\s;|&)`])"
)


def _command_text(tool_input: Mapping[str, JsonValue]) -> str | None:
    for key in ("cmd", "command", "argv"):
        value = tool_input.get(key)
        if type(value) is str:
            return value
        if isinstance(value, list | tuple) and all(type(item) is str for item in value):
            return " ".join(cast(list[str], list(value)))
    return None


def command_may_outlive_call(payload: Mapping[str, JsonValue]) -> bool:
    """Whether the command text may leave a process running past the host's post-call event."""

    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, Mapping):
        return False
    text = _command_text(cast(Mapping[str, JsonValue], tool_input))
    return text is not None and (
        _BACKGROUND_OPERATOR.search(text) is not None or _DETACHING_WORD.search(text) is not None
    )


def host_call_complete(payload: Mapping[str, JsonValue]) -> bool:
    """Whether the host's own outcome facts say the call ended (never output text).

    *payload* carries the closed facts the host adapter already derived: an integer
    ``exit_status``, a boolean ``success`` or ``denied: true``. A Codex shell call still running
    behind a session id, and a Claude Code background launch, carry none of them. A command whose
    text backgrounds or detaches a process is never complete: it may write after the call ends.
    """

    tool_input = payload.get("tool_input")
    if isinstance(tool_input, Mapping) and tool_input.get("run_in_background") is True:
        return False
    if command_may_outlive_call(payload):
        return False
    return (
        type(payload.get("exit_status")) is int
        or type(payload.get("success")) is bool
        or payload.get("denied") is True
    )


def owned_relative_paths(workspace: str, roots: Iterable[str]) -> tuple[str, ...]:
    """FinishUP's own state or isolation roots that lie inside *workspace*, as relative paths."""

    relative: set[str] = set()
    for base in {os.path.normpath(workspace), os.path.realpath(workspace)}:
        for root in roots:
            if not root.startswith("/"):
                continue
            for normalized in {os.path.normpath(root), os.path.realpath(root)}:
                if normalized != base and normalized.startswith(base.rstrip("/") + "/"):
                    relative.add(normalized[len(base.rstrip("/")) + 1 :])
    return tuple(sorted(relative))


def workspace_fingerprint_pass(
    event: str,
    *,
    call_identity: str | None,
    workspace_locator: str,
    workspace_commitment: str,
    key_material: bytes,
    observation_root: Path,
    complete: bool,
    excluded: Iterable[str] = (),
    seconds: float = SNAPSHOT_SECONDS,
    host_deadline: float | None = None,
) -> WorkspaceEffectReading | None:
    """Run one hook's half of the fingerprint. Never raises.

    ``PreToolUse`` stores the snapshot and returns ``None`` (or an ``unavailable`` reading naming
    why no snapshot was stored, for diagnostics only). ``PostToolUse`` returns the reading the
    envelope carries. ``call_identity`` is the host session plus its tool-call identity; without
    one the two phases cannot be joined and the post reading is ``unavailable``.
    ``host_deadline`` (monotonic) is when the host may stop waiting for this pre-call pass and run
    the call anyway: a snapshot that completes after it may already include the call's writes, so
    it is withdrawn and the post reading becomes ``unavailable`` (``timeout``).
    """

    try:
        directory = workspace_fingerprint_dir(observation_root, workspace_commitment)
        if directory is None:
            return WorkspaceEffectReading("unavailable", "store_unusable")
        store = WorkspaceFingerprintStore(directory, key_material)
        deadline = time.monotonic() + max(0.0, seconds)
        if event == "PreToolUse":
            if call_identity is None:
                return WorkspaceEffectReading("unavailable", "no_pre_snapshot")
            backoff = store.recently_bounded()
            reason = store.capture_before(
                workspace_locator, call_identity, deadline=deadline, excluded=excluded
            )
            if reason is None and host_deadline is not None and time.monotonic() > host_deadline:
                store.invalidate(call_identity, "timeout")
                reason = "timeout"
            if reason is None:
                return None
            return WorkspaceEffectReading("unavailable", reason, fresh=backoff is None)
        if event == "PostToolUse":
            if call_identity is None:
                return WorkspaceEffectReading("unavailable", "no_pre_snapshot")
            return store.effect_after(
                workspace_locator,
                call_identity,
                deadline=deadline,
                call_complete=complete,
                excluded=excluded,
            )
    except Exception:
        return WorkspaceEffectReading("unavailable", "store_unusable")
    return None
