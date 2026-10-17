"""The agent guidance that lets an agent decide when to turn on AI-powered review (ADR-049)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Final

from finishup.mcp.descriptors import descriptor_for

_REPO: Final = Path(__file__).resolve().parents[3]
_REVIEW: Final = _REPO / "guidance" / "review.md"
_CARD: Final = _REPO / "guidance" / "agent-instructions.md"
_HEADING: Final = "## Turn on AI-powered review for a task when local checks cannot judge it"


def _collapsed(path: Path) -> str:
    return " ".join(path.read_text(encoding="utf-8").split())


def _section() -> str:
    text = _REVIEW.read_text(encoding="utf-8")
    assert _HEADING in text
    return " ".join(text.partition(_HEADING)[2].split())


def test_the_section_is_trigger_first_with_steps_example_and_what_happens_next() -> None:
    section = _section()
    for label in (
        "**Turn it on when**",
        "**Stay local when**",
        "**How.**",
        "**What happens next.**",
        "**Worked example.**",
        "**About data.**",
    ):
        assert label in section, label
    # Each owner-named trigger and stay-local case is present.
    for trigger in (
        "spans several files or modules",
        "security-, privacy-, concurrency- or data-loss-sensitive",
        "tests and local checks cannot judge",
        "failed at the same problem more than once",
        "final independent review",
        "small or mechanical",
        "docs or formatting",
        "already cover what changed",
        "reading or exploring",
    ):
        assert trigger in section, trigger
    assert '`review_mode: "ai_powered"`' in section
    assert '`review_mode: "local"`' in section
    assert "`status` `review_mode`" in section


def test_the_data_statement_is_coverage_bounded() -> None:
    section = _section()
    assert "Do not hesitate over data." in section
    assert "standing permission" in section
    assert "the owner's policy governs and is enforced" in section
    lowered = section.lower()
    for claim in ("nothing leaves", "never leaves", "stays on this computer", "deterministic "):
        assert claim not in lowered, claim


def test_the_continuations_the_check_prints_are_explained() -> None:
    section = _section()
    for reason in (
        "owner_local_only",
        "ai_review_not_set_up",
        "route_local_only",
        "review_disabled",
        "conversation_default",
        "switched_to_local",
    ):
        assert f"`{reason}`" in section, reason


def test_the_switch_draft_is_never_reused_verbatim() -> None:
    """Review round 1 (P3): placeholders are named, and switching back is a new decision."""

    section = _section()
    assert "Use a fresh `event_id` and the real `occurred_at`" in section
    assert 'publish a new decision (fresh `event_id`) with `review_mode: "local"`' in section
    assert "a `final_review: true` check that omits `mode` runs that review" in section
    assert "mode: semantic_if_configured" not in section
    # Review round 3: switching back after the closing review makes it stale.
    assert "switch back to local before the closing review, not after it" in section


def test_a_supported_rebuttal_and_a_resolved_criterion_are_one_judgement() -> None:
    """Issue #1079: the agent page states the same reviewer duty the prompt states."""

    page = _collapsed(_REVIEW)
    assert (
        "A supported rebuttal is a `rejected` or `acknowledged` answer that cites evidence. "
        "The next review packet carries that answer. The reviewer must check that a recommended "
        "input or state is reachable under the interface the packet shows, and must judge a "
        "resolved obligation together with the result it cites, the latest observed verification, "
        "and any missing input. Do not treat a match as shown while one of those is missing."
        in page
    )
    for hint in ("numba", "llvmlite", "vigenere"):
        assert hint not in page, hint


def test_the_card_points_at_the_section_and_keeps_the_pinned_review_rule() -> None:
    card = _collapsed(_CARD)
    assert "Tasks may start local; `review.md`: when to turn on AI-powered review." in card
    assert (
        "Select `semantic_required` when the user, effective policy, or named acceptance "
        "criterion" in card
    )


def test_the_publish_and_check_descriptors_point_at_the_review_topic() -> None:
    for profile in ("policy", "strict"):
        publish = descriptor_for("publish_work", profile).description
        assert "decision_recorded 1.1.0 review_mode" in publish
        assert "finishup://guidance/review.md" in publish
        check = descriptor_for("check", profile).description
        assert "Omit mode to run in the task's review mode (status review_mode" in check
        assert "configured default" not in check
        check_request = descriptor_for("check", profile).input_schema
        assert "configured default" not in json.dumps(check_request, default=dict)
