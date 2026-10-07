"""A rejected result outcome names the closed set and the blocker form (issue #977)."""

from __future__ import annotations

from yoetz.mcp.summaries import summary_for_public_error


def _error(field: str) -> dict[str, object]:
    return {
        "error": {
            "code": "INVALID_REQUEST",
            "retryable": False,
            "correlation_id": "err_2a3451f0-f46b-4599-b2e0-0ffa8a01c981",
            "safe_details": {"fields": [field], "reasons": ["invalid_type_or_value"]},
        }
    }


def test_rejected_outcome_names_the_closed_set_and_the_blocker_line() -> None:
    text = summary_for_public_error(_error("/event_drafts/1/payload/outcome"))
    assert "Rejected: invalid_type_or_value at /event_drafts/1/payload/outcome." in text
    assert "success|failure|partial|unknown (no blocked)" in text
    assert "yoetz-blocker:<kind>" in text
    # #984: repair first, a Yoetz limit is self-verified and never a blocker, and the blocker is
    # offered only for an open obligation genuinely blocked outside the agent's control.
    assert "then repair" in text
    assert "A Yoetz limit is never a blocker" in text
    assert "respond self_verified" in text
    assert "only for an open obligation genuinely blocked outside your control" in text
    assert len(text.encode("ascii")) <= 512


def test_other_rejections_carry_no_outcome_hint() -> None:
    text = summary_for_public_error(_error("/event_drafts/1/payload/action_kind"))
    assert "no blocked" not in text
