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
    "GRANT_MISSING_WORDS",
    "LOCAL_LABEL",
    "MIGRATION_PENDING_WORDS",
    "NOT_SET_UP_HERE",
    "RELEASED_LOCAL_ONLY_WORDS",
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
    "ai_powered": "every task runs with AI-powered review",
}

# A policy that predates the setting, with its inference channel off, reads as local only, but the
# owner never chose it: say what is true (nothing is set up), not that agents are forbidden.
RELEASED_LOCAL_ONLY_WORDS: Final = (
    "AI-powered review is not set up for this repository, so every task runs local checks only"
)
# Status beside any other setting when nothing can be reviewed here yet (no reviewer, credential
# or repository privacy grant).
NOT_SET_UP_HERE: Final = "AI-powered review is not set up for this repository yet"
# A repository without a privacy grant of its own reads the installation row, which is not its
# setting: say what is true there (review round 2).
# Where the installation's previously accepted permission is still to be carried forward to this
# repository (the released migration), say that rather than "not set up" (review round 3).
MIGRATION_PENDING_WORDS: Final = (
    "this repository has no privacy grant of its own yet; the installation's previously "
    "accepted permission is carried forward to it when a task first starts in this repository, "
    "without reapproval or broader disclosure"
)
GRANT_MISSING_WORDS: Final = (
    "AI-powered review is not set up for this repository: it has no privacy grant of its own "
    "yet, so no work is sent for AI-powered review. 'finishup --privacy' sets one up; with a "
    "reviewer bound it lists the AI-powered review options and asks how this repository's tasks "
    "use them"
)

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
    "review_disabled": (
        "AI-powered review is turned off in this installation's verification settings "
        "([verification] semantic is disabled), so checks that name no mode run local; continue "
        "locally."
    ),
    "ai_review_not_set_up": (
        "AI-powered review is not set up for this repository, so this task stays local; "
        "continue locally. One-time owner setup in a local terminal: "
        f"{AI_REVIEW_SETUP_COMMAND}."
    ),
}

# A local reason that already says why review cannot run here; the status line adds nothing.
_REASONS_THAT_SAY_WHY: Final = frozenset(
    {"ai_review_not_set_up", "review_disabled", "route_local_only"}
)

_LOCAL_REASON_TEXT: Final[Mapping[str, str]] = {
    "owner_local_only": "the owner chose local checks only for this repository",
    "route_local_only": "this host connection is registered local-only (strict route)",
    "review_disabled": "AI-powered review is turned off in the verification settings",
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
    requested = _token(source.get("requested"), frozenset({"local", "ai_powered"}))
    if mode == "local" and reason is not None:
        asked = (
            "the owner's setting asks for AI-powered review"
            if setting == "ai_powered"
            else "this task asked for AI-powered review"
        )
        parts.append(f"{asked}, but {_LOCAL_REASON_TEXT[reason]}")
    elif mode == "ai_powered" and requested == "local":
        parts.append("this task asked for local checks, but the owner's setting reviews every task")
    switch = _event(source.get("switch_event_id"))
    sequence = source.get("switch_sequence")
    if switch is not None:
        at = f" at sequence {sequence}" if type(sequence) is str and sequence.isdigit() else ""
        parts.append(f"latest switch {switch}{at}")
    explicit = source.get("setting_explicit")
    parts.append(f"owner setting: {_setting_words(setting, explicit)}")
    if (
        source.get("ai_review_available") is False
        and setting != "local_only"
        and reason not in _REASONS_THAT_SAY_WHY
    ):
        # No reviewer, credential or repository grant (review round 2): say so, beside the
        # setting the repository would follow once it is set up.
        parts.append(NOT_SET_UP_HERE)
    return "; ".join(parts) + "."


def _setting_words(setting: str, explicit: object) -> str:
    """The setting's words; a released ``local_only`` (``explicit`` false) says nothing is set up."""

    if setting == "local_only" and explicit is False:
        return RELEASED_LOCAL_ONLY_WORDS
    return CONVERSATION_SETTING_WORDS[setting]


def conversation_setting_line(
    setting: object,
    *,
    explicit: bool = True,
    grant_missing: bool = False,
    migration_pending: bool = False,
) -> str:
    """The owner's conversation setting as one sentence, with the command that changes it.

    ``explicit`` is whether the owner chose ``setting``: a policy that predates the setting and
    reads as local only says AI-powered review is not set up, with the one-time setup.
    ``grant_missing`` is a repository without a privacy grant of its own: it says AI-powered
    review is not set up there, unless the owner explicitly chose local only; where the
    installation's earlier permission is still to be carried forward (``migration_pending``) it
    says so instead.
    """

    token = _token(setting, CONVERSATION_SETTING_WORDS)
    if token is None:
        return ""
    if grant_missing and not (explicit and token == "local_only"):
        if migration_pending:
            return (
                f"Tasks: {MIGRATION_PENDING_WORDS}; once it is, "
                f"{CONVERSATION_SETTING_WORDS[token]} (change with "
                "'finishup privacy conversations')."
            )
        return f"Tasks: {GRANT_MISSING_WORDS}."
    if token == "local_only" and not explicit:
        return (
            f"Tasks: {RELEASED_LOCAL_ONLY_WORDS}. One-time owner setup in a local terminal: "
            f"{AI_REVIEW_SETUP_COMMAND}."
        )
    return (
        f"Tasks: {CONVERSATION_SETTING_WORDS[token]} (change with "
        "'finishup privacy conversations')."
    )
