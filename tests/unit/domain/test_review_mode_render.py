"""The shared review-mode wording on every rendering (ADR-049)."""

from __future__ import annotations

import json
import re
from typing import Any, Final, cast

import pytest
import typer
from tests.unit.protocol.test_models_and_schemas import (
    _check_result_wire,  # pyright: ignore[reportPrivateUsage]
)

from finishup.cli.render import render_human_check
from finishup.domain.review_mode_render import (
    AI_REVIEW_SETUP_COMMAND,
    ROUTE_REREGISTER_COMMAND,
    check_review_mode_line,
    conversation_setting_line,
    review_mode_continuation,
    status_review_mode_line,
)
from finishup.mcp.summaries import MAX_SUMMARY_BYTES, summary_for_check
from finishup.protocol.models import CheckResult, CheckSuccessModel

_SWITCH: Final = "evt_00000000-0000-4000-8000-000000000014"
_COMMAND: Final = re.compile(r"`finishup ([^`]+)`")


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (
            {"mode": "local", "source": "conversation_default"},
            "Review mode: local (FinishUP); this task has not turned on AI-powered review",
        ),
        (
            {"mode": "ai_powered", "source": "conversation_switch", "switch_event_id": _SWITCH},
            f"Review mode: AI-powered review; this task turned it on (switch {_SWITCH}).",
        ),
        (
            {"mode": "ai_powered", "source": "conversation_default"},
            "Review mode: AI-powered review; the owner's setting reviews every task.",
        ),
        (
            {"mode": "local", "source": "conversation_switch", "switch_event_id": _SWITCH},
            f"Review mode: local (FinishUP); this task switched back to local checks (switch "
            f"{_SWITCH}).",
        ),
        (
            {
                "mode": "local",
                "source": "conversation_switch",
                "switch_event_id": _SWITCH,
                "local_reason": "owner_local_only",
            },
            "but the owner chose local checks only for this repository.",
        ),
        (
            {"mode": "local", "source": "check_request", "local_reason": "ai_review_not_set_up"},
            "this check asked for AI-powered review, but AI-powered review is not set up",
        ),
        (
            {
                "mode": "local",
                "source": "conversation_switch",
                "switch_event_id": _SWITCH,
                "local_reason": "route_local_only",
            },
            "registered local-only (strict route)",
        ),
    ],
)
def test_the_check_line_names_the_mode_and_why(value: dict[str, str], expected: str) -> None:
    line = check_review_mode_line(value)
    assert expected in line
    assert "deterministic" not in line.lower()


def test_unknown_tokens_and_foreign_ids_render_nothing() -> None:
    assert check_review_mode_line(None) == ""
    assert check_review_mode_line({"mode": "maybe", "source": "conversation_default"}) == ""
    line = check_review_mode_line(
        {"mode": "ai_powered", "source": "conversation_switch", "switch_event_id": "<script>"}
    )
    assert "<script>" not in line
    assert review_mode_continuation("conversation_default") == ""
    assert review_mode_continuation("free text") == ""
    assert conversation_setting_line("sometimes") == ""


def test_each_requested_but_local_reason_has_an_exact_continuation() -> None:
    assert "The owner chose local checks only" in review_mode_continuation("owner_local_only")
    assert "do not ask again" in review_mode_continuation("owner_local_only")
    assert AI_REVIEW_SETUP_COMMAND in review_mode_continuation("ai_review_not_set_up")
    assert ROUTE_REREGISTER_COMMAND in review_mode_continuation("route_local_only")


def _resolve(words: list[str]) -> Any:
    from finishup.cli.app import app

    command: Any = typer.main.get_command(app)
    for word in words:
        subcommands = cast(dict[str, Any], getattr(command, "commands", None) or {})
        if word not in subcommands:
            return None
        command = subcommands[word]
    return command


def test_every_continuation_command_is_a_real_cli_command() -> None:
    from finishup.cli.app import app

    root_options = {
        option
        for param in typer.main.get_command(app).params
        for option in getattr(param, "opts", ())
    }
    commands = _COMMAND.findall(AI_REVIEW_SETUP_COMMAND) + [
        ROUTE_REREGISTER_COMMAND.removeprefix("finishup ")
    ]
    assert len(commands) == 5
    for command in commands:
        words = command.split()
        if words[0].startswith("--"):
            assert words[0] in root_options, command
            continue
        path = [word for word in words if not word.startswith("--") and word != "policy"]
        resolved = _resolve(path)
        assert resolved is not None, command
        options = {option for param in resolved.params for option in getattr(param, "opts", ())}
        for option in (word for word in words if word.startswith("--")):
            assert option in options, (command, option)


def test_status_line_names_the_setting_and_the_latest_switch() -> None:
    line = status_review_mode_line(
        {
            "mode": "ai_powered",
            "requested": "ai_powered",
            "setting": "local_agent_opt_in",
            "ai_review_available": True,
            "switch_event_id": _SWITCH,
            "switch_sequence": "7",
        }
    )
    assert line.startswith("Review mode: AI-powered review;")
    assert f"latest switch {_SWITCH} at sequence 7" in line
    assert "an agent may turn on AI-powered review for a task when it helps" in line


def test_a_released_local_only_says_review_is_not_set_up_not_that_agents_are_forbidden() -> None:
    """Review round 1 (P3): an unset policy with inference off is not the owner's choice."""

    released = {
        "mode": "local",
        "requested": "local",
        "setting": "local_only",
        "setting_explicit": False,
        "ai_review_available": False,
    }
    line = status_review_mode_line(released)
    assert "AI-powered review is not set up for this repository" in line
    assert "agents may not" not in line
    assert "agents may not" in status_review_mode_line({**released, "setting_explicit": True})
    text = conversation_setting_line("local_only", explicit=False)
    assert "not set up" in text and AI_REVIEW_SETUP_COMMAND in text
    assert "agents may not" not in text
    assert "agents may not" in conversation_setting_line("local_only")


def test_status_says_when_ai_review_is_not_set_up_here() -> None:
    """ADR-049 review round 2: a repository without its own grant cannot review yet."""

    line = status_review_mode_line(
        {
            "mode": "local",
            "requested": "local",
            "setting": "local_agent_opt_in",
            "setting_explicit": True,
            "ai_review_available": False,
            "local_reason": "conversation_default",
        }
    )
    assert line.endswith("AI-powered review is not set up for this repository yet.")
    # Not repeated where the reason or the owner's local-only choice already says it.
    opted = status_review_mode_line(
        {
            "mode": "local",
            "requested": "ai_powered",
            "setting": "local_agent_opt_in",
            "setting_explicit": True,
            "ai_review_available": False,
            "local_reason": "ai_review_not_set_up",
        }
    )
    assert opted.count("not set up") == 1
    chosen = status_review_mode_line(
        {
            "mode": "local",
            "requested": "local",
            "setting": "local_only",
            "setting_explicit": True,
            "ai_review_available": False,
        }
    )
    assert "not set up" not in chosen
    missing = conversation_setting_line("ai_powered", explicit=False, grant_missing=True)
    assert "AI-powered review is not set up for this repository" in missing
    assert "every task runs with AI-powered review" not in missing
    assert "agents may not" in conversation_setting_line(
        "local_only", explicit=True, grant_missing=True
    )


def test_status_says_when_the_owner_setting_overrides_a_switch_to_local() -> None:
    line = status_review_mode_line(
        {
            "mode": "ai_powered",
            "requested": "local",
            "setting": "ai_powered",
            "setting_explicit": True,
            "ai_review_available": True,
            "switch_event_id": _SWITCH,
            "switch_sequence": "4",
        }
    )
    assert "this task asked for local checks, but the owner's setting reviews every task" in line
    assert "every task runs with AI-powered review" in line


def test_review_turned_off_has_its_own_line_and_continuation() -> None:
    assert check_review_mode_line(
        {"mode": "local", "source": "conversation_default", "local_reason": "review_disabled"}
    ) == (
        "Review mode: local (FinishUP); AI-powered review was asked for, but AI-powered review "
        "is turned off in the verification settings."
    )
    assert "[verification] semantic is disabled" in review_mode_continuation("review_disabled")
    line = status_review_mode_line(
        {
            "mode": "local",
            "requested": "ai_powered",
            "setting": "ai_powered",
            "setting_explicit": True,
            "ai_review_available": True,
            "local_reason": "route_local_only",
        }
    )
    assert "the owner's setting asks for AI-powered review, but this host connection" in line


def test_check_renderings_carry_the_line_and_the_continuation_within_bounds() -> None:
    wire = cast(dict[str, Any], json.loads(json.dumps(_check_result_wire())))
    wire["review_mode"] = {
        "mode": "local",
        "source": "conversation_switch",
        "switch_event_id": _SWITCH,
        "local_reason": "ai_review_not_set_up",
    }
    result = CheckResult.model_validate(wire).root
    assert type(result) is CheckSuccessModel
    human = render_human_check(result)
    assert "Review mode: local (FinishUP); this task asked for AI-powered review" in human
    assert AI_REVIEW_SETUP_COMMAND in human
    summary = summary_for_check(wire)
    assert len(summary.encode("utf-8")) <= MAX_SUMMARY_BYTES
    assert "Review mode next: AI-powered review is not set up" in summary
    # A check without a recorded mode renders exactly as before.
    del wire["review_mode"]
    assert "Review mode" not in summary_for_check(wire)


@pytest.mark.parametrize("reason", ["review_disabled", "route_local_only"])
def test_a_reason_that_says_why_is_not_followed_by_not_set_up(reason: str) -> None:
    """Review round 3 (P3): the reason already explains it; nothing is added."""

    line = status_review_mode_line(
        {
            "mode": "local",
            "requested": "ai_powered",
            "setting": "local_agent_opt_in",
            "setting_explicit": True,
            "ai_review_available": False,
            "local_reason": reason,
        }
    )
    assert "not set up" not in line


def test_a_pending_carry_forward_says_the_earlier_permission_can_apply() -> None:
    """Review round 3 (P3): not "not set up" where the released migration is still pending."""

    line = conversation_setting_line(
        "ai_powered", explicit=False, grant_missing=True, migration_pending=True
    )
    assert "carried forward to it when a task first starts in this repository" in line
    assert "finishup --privacy" not in line
    assert "not set up" not in line
    assert "every task runs with AI-powered review" in line
