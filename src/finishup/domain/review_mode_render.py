"""Fixed wording for a task's review mode on every rendering (ADR-049).

One owner of the sentences the CLI, the terminal interface and the MCP summaries print for the
``review_mode`` a check ran in, the ``review_mode`` status reports, and the continuations that
say what to do when a task asked for AI-powered review and still runs local. Every input is a
closed token or a re-validated event id; no payload prose (a decision's statement or rationale)
ever reaches this text.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final, cast

from finishup.protocol.ids import IdKind, is_valid_id

__all__ = [
    "AI_REVIEW_SETUP_COMMAND",
    "CONVERSATION_SETTING_WORDS",
    "LOCAL_LABEL",
    "ROUTE_REREGISTER_COMMAND",
    "check_review_mode_line",
    "conversation_setting_line",
    "review_mode_continuation",
    "status_review_mode_line",
]

# The short label of the no-AI mode (owner naming decision): FinishUP's local checks.
LOCAL_LABEL: Final = "local (FinishUP)"
# The one-time owner setup that makes AI-powered review available to a repository: a reviewer
# and its key or login (``--set``; a ChatGPT subscription uses its own setup), then the
# repository's privacy policy (``--privacy``). ``provider status`` names what is still missing.
AI_REVIEW_SETUP_COMMAND: Final = (
    "`finishup --set` (or `finishup provider codex-subscription setup`), then `finishup "
    "--privacy`; `finishup provider status` shows what is missing"
)
# Re-registers a host connection on the policy route, through the usual reviewed preview.
ROUTE_REREGISTER_COMMAND: Final = "finishup setup run --route-profile policy"

CONVERSATION_SETTING_WORDS: Final[Mapping[str, str]] = {
    "local_only": "every task runs local checks only; agents may not turn on AI-powered review",
    "local_owner_approval": (
        "tasks start local; when an agent turns on AI-powered review, the owner approves each "
        "review"
    ),
    "local_agent_opt_in": (
        "tasks start local; an agent may turn on AI-powered review for a task when it helps"
    ),
    "ai_powered": "every task starts with AI-powered review",
}

_CONTINUATIONS: Final[Mapping[str, str]] = {
    "owner_local_only": (
        "The owner chose local checks only for this repository, so agents may not turn on "
        "AI-powered review; continue locally and do not ask again unless the user raises it."
    ),
    "route_local_only": (
        "This host connection is registered local-only (strict route), so it cannot request "
        "AI-powered review; continue locally. The owner can re-register it once on the policy "
        f"route: `{ROUTE_REREGISTER_COMMAND}`, then start a fresh agent session."
    ),
    "ai_review_not_set_up": (
        "AI-powered review is not set up for this repository, so this task stays local; "
        "continue locally. One-time owner setup in a local terminal: "
        f"{AI_REVIEW_SETUP_COMMAND}."
    ),
}

_LOCAL_REASON_TEXT: Final[Mapping[str, str]] = {
    "owner_local_only": "the owner chose local checks only for this repository",
    "route_local_only": "this host connection is registered local-only (strict route)",
    "ai_review_not_set_up": "AI-powered review is not set up for this repository",
}


def _mapping(value: object) -> Mapping[str, object] | None:
    if isinstance(value, Mapping):
        return cast(Mapping[str, object], value)
    return None


def _token(value: object, allowed: Mapping[str, object] | frozenset[str]) -> str | None:
    return value if type(value) is str and value in allowed else None


def _event(value: object) -> str | None:
    return cast(str, value) if is_valid_id(IdKind.EVENT, value) else None


def review_mode_continuation(local_reason: object) -> str:
    """What to do when a task asked for AI-powered review and runs local, or ``""``."""

    reason = _token(local_reason, _CONTINUATIONS)
    return "" if reason is None else _CONTINUATIONS[reason]


def check_review_mode_line(value: object) -> str:
    """One line naming the mode a check ran in and why, or ``""`` when none was recorded."""

    source = _mapping(value)
    if source is None:
        return ""
    mode = _token(source.get("mode"), frozenset({"local", "ai_powered"}))
    origin = _token(
        source.get("source"),
        frozenset({"conversation_default", "conversation_switch", "check_request"}),
    )
    if mode is None or origin is None:
        return ""
    reason = _token(source.get("local_reason"), _LOCAL_REASON_TEXT)
    switch = _event(source.get("switch_event_id"))
    switch_text = "" if switch is None else f" (switch {switch})"
    if mode == "ai_powered":
        why = {
            "conversation_default": "the owner's setting reviews every task",
            "conversation_switch": f"this task turned it on{switch_text}",
            "check_request": "this check asked for it",
        }[origin]
        return f"Review mode: AI-powered review; {why}."
    if reason is not None:
        asked = {
            "conversation_default": "AI-powered review was asked for",
            "conversation_switch": f"this task asked for AI-powered review{switch_text}",
            "check_request": "this check asked for AI-powered review",
        }[origin]
        return f"Review mode: {LOCAL_LABEL}; {asked}, but {_LOCAL_REASON_TEXT[reason]}."
    why = {
        "conversation_default": (
            "this task has not turned on AI-powered review (status shows whether it may)"
        ),
        "conversation_switch": f"this task switched back to local checks{switch_text}",
        "check_request": "this check asked for local checks only",
    }[origin]
    return f"Review mode: {LOCAL_LABEL}; {why}."


def status_review_mode_line(value: object) -> str:
    """One line for status: the mode the next check runs in, the owner's setting, the switch."""

    source = _mapping(value)
    if source is None:
        return ""
    mode = _token(source.get("mode"), frozenset({"local", "ai_powered"}))
    setting = _token(source.get("setting"), CONVERSATION_SETTING_WORDS)
    if mode is None or setting is None:
        return ""
    label = LOCAL_LABEL if mode == "local" else "AI-powered review"
    parts = [f"Review mode: {label}"]
    reason = _token(source.get("local_reason"), _LOCAL_REASON_TEXT)
    if mode == "local" and reason is not None:
        parts.append(f"this task asked for AI-powered review, but {_LOCAL_REASON_TEXT[reason]}")
    switch = _event(source.get("switch_event_id"))
    sequence = source.get("switch_sequence")
    if switch is not None:
        at = f" at sequence {sequence}" if type(sequence) is str and sequence.isdigit() else ""
        parts.append(f"latest switch {switch}{at}")
    parts.append(f"owner setting: {CONVERSATION_SETTING_WORDS[setting]}")
    return "; ".join(parts) + "."


def conversation_setting_line(setting: object) -> str:
    """The owner's conversation setting as one sentence, with the command that changes it."""

    token = _token(setting, CONVERSATION_SETTING_WORDS)
    if token is None:
        return ""
    return (
        f"Tasks: {CONVERSATION_SETTING_WORDS[token]} (change with "
        "'finishup privacy conversations')."
    )
