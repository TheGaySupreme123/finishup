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
process exit, a closed success or failure fact, a denial, or (Codex) the post event itself. Codex's
``Bash`` post is fired only after the process exited, so it is that call's completion fact, while it
states no exit (n7 RC1); a Codex process still running sends no post at all, and a response that
reads as Codex's own running-process header withholds completion. Claude Code's
``run_in_background`` launch and a command whose text backgrounds or detaches a process have no
completion fact (``background_launch``); their later writes would fall outside the window, so
FinishUP does not vouch for them. A reported completion is necessary, not sufficient: the adapter
also reads the process table and stays ``unavailable`` while a process begun during the call still
runs in the workspace (``process_lingering``, round 6).

Each post-call reading is also counted, by its closed effect and reason, in the workspace's
bounded local tally (``WorkspaceFingerprintStore.note_reading``) that ``observe status`` reports,
so a call that stayed material can be attributed to its reason without a wire change.

Replays never fingerprint: the service's legacy-spool replay passes no workspace locator, and the
synchronous legacy Codex spool hook does not call this path at all. Those observations carry no
fact and stay material.
"""

from __future__ import annotations

import contextlib
import os
import re
import time
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Final, Literal, cast

from finishup.adapters.workspace_fingerprint import (
    SNAPSHOT_SECONDS,
    WorkspaceEffectReading,
    WorkspaceFingerprintStore,
    workspace_fingerprint_dir,
)
from finishup.domain.command_segments import command_may_background
from finishup.domain.observation_selection import ROUTINE_READ_TOOLS, SHELL_TOOLS
from finishup.domain.values import JsonValue

__all__ = [
    "HOST_CALL_ENDED_KEY",
    "command_may_outlive_call",
    "fingerprinted_tool",
    "host_call_complete",
    "host_call_incomplete_reason",
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


# The conservative reading for text the shell grammar leaves undecided
# (``command_segments.command_may_background``): a shell background operator (a lone ``&``, not
# ``&&``, ``>&``, ``&>``, ``<&`` or ``|&``) or a detaching launcher anywhere. The grammar clears
# it only for a call made solely of programs known not to run an argument or stdin as code in the
# form given, each with no wrapper or assignment in front and no ANSI-C quoting in the text. A
# command that may leave a process writing after the post-call snapshot cannot be shown to have
# left the workspace unchanged, and the lingering-process probe sees only this user's processes
# (a ``sudo`` daemon is invisible to it).
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
    """Whether the command text may leave a process running past the host's post-call event.

    Shell grammar answers first (#1089): it says yes for a real background operator or detaching
    launcher, and no only when every program in the text, with no wrapper or assignment in front,
    is known not to run its arguments or stdin as code in the form given, so a quoted ``&`` there
    (``curl 'h?a=1&b=2'``) is data. Anything it leaves undecided keeps the conservative pattern.
    """

    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, Mapping):
        return False
    text = _command_text(cast(Mapping[str, JsonValue], tool_input))
    if text is None:
        return False
    verdict = command_may_background(text)
    if verdict is not None:
        return verdict
    return _BACKGROUND_OPERATOR.search(text) is not None or _DETACHING_WORD.search(text) is not None


# Set by a host adapter on its local copy of the outcome facts when the post event itself is the
# host's statement that the call ended (Codex ``Bash``); it never reaches an envelope.
HOST_CALL_ENDED_KEY: Final = "host_call_ended"

IncompleteReason = Literal["background_launch", "call_incomplete"]


def host_call_incomplete_reason(payload: Mapping[str, JsonValue]) -> IncompleteReason | None:
    """Why the host's facts do not say the call ended, or ``None`` when they do (never output text).

    *payload* carries the closed facts the host adapter already derived: an integer
    ``exit_status``, a boolean ``success``, ``denied: true``, or ``HOST_CALL_ENDED_KEY`` for a
    host whose post event is itself the completion fact. A Claude Code background launch and a
    command whose text backgrounds or detaches a process are never complete
    (``background_launch``): they may write after the call ends. Anything else without one of
    those facts is ``call_incomplete``.
    """

    tool_input = payload.get("tool_input")
    if isinstance(tool_input, Mapping) and tool_input.get("run_in_background") is True:
        return "background_launch"
    if command_may_outlive_call(payload):
        return "background_launch"
    if (
        type(payload.get("exit_status")) is int
        or type(payload.get("success")) is bool
        or payload.get("denied") is True
        or payload.get(HOST_CALL_ENDED_KEY) is True
    ):
        return None
    return "call_incomplete"


def host_call_complete(payload: Mapping[str, JsonValue]) -> bool:
    """Whether the host's own outcome facts say the call ended (``host_call_incomplete_reason``)."""

    return host_call_incomplete_reason(payload) is None


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
    incomplete_reason: IncompleteReason = "call_incomplete",
    call_token: str | None = None,
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
    it is never published and the post reading becomes ``unavailable`` (``timeout``).
    ``incomplete_reason`` names why an incomplete call is incomplete. ``call_token`` is the host's
    tool-call id, kept beside the post reading in the bounded local tally only when it is already
    a closed token.
    """

    store: WorkspaceFingerprintStore | None = None
    try:
        directory = workspace_fingerprint_dir(observation_root, workspace_commitment)
        if directory is None:
            # No store directory: nowhere to count this reading either.
            return WorkspaceEffectReading("unavailable", "store_unusable")
        store = WorkspaceFingerprintStore(directory, key_material)
        deadline = time.monotonic() + max(0.0, seconds)
        if event == "PreToolUse":
            if call_identity is None:
                return WorkspaceEffectReading("unavailable", "no_pre_snapshot")
            backoff = store.recently_bounded()
            # The host window is enforced inside the capture, before anything is published: a
            # late snapshot is never stored, so neither a concurrent post-call pass nor a pre-call
            # process killed at its timeout can leave one behind (PR #1080 round 6).
            reason = store.capture_before(
                workspace_locator,
                call_identity,
                deadline=deadline,
                host_deadline=host_deadline,
                excluded=excluded,
            )
            if reason is None:
                return None
            return WorkspaceEffectReading("unavailable", reason, fresh=backoff is None)
        if event == "PostToolUse":
            reading = (
                WorkspaceEffectReading("unavailable", "no_pre_snapshot")
                if call_identity is None
                else store.effect_after(
                    workspace_locator,
                    call_identity,
                    deadline=deadline,
                    call_complete=complete,
                    incomplete_reason=incomplete_reason,
                    excluded=excluded,
                )
            )
            # Local attribution only: a lost sample never changes the reading.
            with contextlib.suppress(Exception):
                store.note_reading(reading, call_token)
            return reading
    except Exception:
        failed = WorkspaceEffectReading("unavailable", "store_unusable")
        if event == "PostToolUse" and store is not None:
            # Counted best effort: a store too broken to compare may be too broken to count.
            with contextlib.suppress(Exception):
                store.note_reading(failed, call_token)
        return failed
    return None
