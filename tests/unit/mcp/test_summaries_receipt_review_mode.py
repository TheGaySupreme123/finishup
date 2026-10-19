"""The MCP receipt summary points at the receipt's review-mode sentences (ADR-049, round 2)."""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import pytest

from finishup.mcp.summaries import _receipt_review_mode_clause
from finishup.protocol.canonical import JsonValue


def _receipt(body: str) -> dict[str, JsonValue]:
    return {
        "document": {
            "sections": [
                {
                    "key": "summary",
                    "body": "The applicable check ran local checks only (FinishUP).",
                },
                {"key": "limitations_and_coverage", "body": body},
            ]
        }
    }


@pytest.mark.parametrize(
    ("sentence", "pointer"),
    [
        (
            "Review mode switches recorded for this task: to AI-powered review at sequence 4 "
            "(event evt_x; recorded by harness:a (harness, self-asserted); declared authority "
            "harness:a). The applicable check ran with AI-powered review requested.",
            "review mode switched in this task (limitations section names each switch);",
        ),
        (
            "The applicable check ran local checks only (FinishUP); AI-powered review was not "
            "requested for this task.",
            "review mode: local (FinishUP); limitations section says how the check ran;",
        ),
        (
            "The applicable check ran local checks only (FinishUP), because AI-powered review is "
            "not set up for this repository.",
            "review mode: local (FinishUP); limitations section says how the check ran;",
        ),
        (
            "The applicable check ran with AI-powered review requested.",
            "review mode: AI-powered review; limitations section says how the check ran;",
        ),
    ],
)
def test_every_review_mode_sentence_gets_a_fixed_pointer(sentence: str, pointer: str) -> None:
    clause = _receipt_review_mode_clause(_receipt(f"Coverage is bounded. {sentence}"))
    assert clause == pointer
    # Closed wording only: no event id, actor or reason text reaches the summary.
    assert "evt_" not in clause and "harness" not in clause and "set up" not in clause


def test_a_receipt_whose_check_recorded_no_mode_gets_no_pointer() -> None:
    assert _receipt_review_mode_clause(_receipt("Coverage is bounded.")) == ""
