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
