"""MCP check summaries lead with the AI-powered-review-not-requested limitation."""

from __future__ import annotations

from finishup.mcp.summaries import (
    MAX_SUMMARY_BYTES,
    summary_for_check,
    summary_for_receipt,
    summary_for_status,
)


def test_summary_for_deterministic_only_leads_with_semantic_not_requested() -> None:
    text = summary_for_check(
        {
            "verdict": "no_issue_detected",
            "findings": [],
            "suppressed_count": "0",
            "semantic_status": "not_requested",
            "semantic_reason": "deterministic_mode",
            "result_frontier": {"sequence": "3", "head_digest": "sha256:" + "a" * 64},
        }
    )
    assert text.startswith("No issue detected within local coverage;")
    assert "AI-powered review was not requested" in text


def test_capacity_summary_names_non_dispatch_and_bounded_next_step() -> None:
    text = summary_for_check(
        {
            "verdict": "incomplete_check",
            "findings": [],
            "suppressed_count": "0",
            "semantic_status": "failed",
            "semantic_reason": "case_capacity_exceeded",
            "result_frontier": {"sequence": "3", "head_digest": "sha256:" + "a" * 64},
        }
    )
    assert "Continuation: semantic_capacity_exceeded." in text
    assert "AI-powered review status/reason: failed/case_capacity_exceeded" in text
    assert "sha256:" + "a" * 64 in text
    assert "No provider attempt" not in text
    assert len(text.encode("ascii")) <= MAX_SUMMARY_BYTES


def test_check_summary_states_why_the_check_time_change_was_unavailable() -> None:
    text = summary_for_check(
        {
            "verdict": "no_issue_detected",
            "findings": [],
            "suppressed_count": "0",
            "semantic_status": "succeeded",
            "semantic_reason": "completed",
            "result_frontier": {"sequence": "3", "head_digest": "sha256:" + "a" * 64},
            "coverage": {
                "known_gaps": [
                    "check_time_change_unavailable",
                    "check_time_change_unavailable_changed_during_capture",
                ]
            },
        }
    )
    assert "The check-time change was unavailable: the working tree kept changing" in text
    assert len(text.encode("ascii")) <= MAX_SUMMARY_BYTES


def test_check_summary_names_opaque_withheld_item_and_closed_reason() -> None:
    text = summary_for_check(
        {
            "verdict": "incomplete_check",
            "findings": [],
            "suppressed_count": "0",
            "semantic_status": "succeeded",
            "semantic_reason": "completed",
            "semantic_withheld_items": [
                {"item_id": "excerpt-heuristic", "reason": "never_send_heuristic"}
            ],
            "result_frontier": {"sequence": "3", "head_digest": "sha256:" + "a" * 64},
        }
    )
    assert "excerpt-heuristic (never_send_heuristic)" in text
    assert len(text.encode("ascii")) <= MAX_SUMMARY_BYTES


def test_receipt_and_status_summaries_preserve_withheld_item_identity() -> None:
    receipt = summary_for_receipt(
        {
            "conclusion": "insufficient_coverage",
            "coverage": {"known_gaps": ["content_redacted"]},
            "suppressed_finding_count": "0",
            "result_frontier": {"sequence": "3", "head_digest": "sha256:" + "a" * 64},
            "document": {
                "semantic_withheld_items": [
                    {"item_id": "excerpt-heuristic", "reason": "never_send_heuristic"}
                ]
            },
        }
    )
    status = summary_for_status(
        {
            "view": "operation",
            "gaps": [],
            "closure_readiness": {},
            "coverage": {"ledger_freshness": "current"},
            "head_frontier": {"sequence": "3", "head_digest": "sha256:" + "a" * 64},
            "page": {
                "state": "complete",
                "operation_kind": "check",
                "semantic_withheld_items": [
                    {"item_id": "excerpt-heuristic", "reason": "never_send_heuristic"}
                ],
            },
        }
    )
    assert "excerpt-heuristic (never_send_heuristic)" in receipt
    assert "excerpt-heuristic (never_send_heuristic)" in status


_REDACTED_VALUES = [
    {
        "disposition": "value_replaced",
        "item_id": "excerpt-replaced",
        "lines": [2, 9],
        "source_ref": "evd_10000000-0000-4000-8000-000000000021",
    },
    {"disposition": "item_withheld", "item_id": "excerpt-withheld", "lines": [4]},
]


def test_check_summary_names_redacted_value_lines_and_the_fixed_agent_line() -> None:
    """PL2-1 (issue #982): refs and lines, never values, and the agent line exactly once."""

    from finishup.domain.receipts import (
        SEMANTIC_REDACTED_VALUES_AGENT_LINE,
        SEMANTIC_REDACTED_VALUES_AGENT_LINE_SHORT,
    )

    text = summary_for_check(
        {
            "verdict": "action_required",
            "findings": [],
            "suppressed_count": "0",
            "semantic_status": "succeeded",
            "semantic_reason": "completed",
            "semantic_redacted_values": _REDACTED_VALUES,
            "result_frontier": {"sequence": "3", "head_digest": "sha256:" + "a" * 64},
        }
    )
    # The frontier head digest is required, so the 512-byte summary carries the shorter fixed
    # form when the full line cannot fit beside it.
    assert (
        text.count(SEMANTIC_REDACTED_VALUES_AGENT_LINE)
        + text.count(SEMANTIC_REDACTED_VALUES_AGENT_LINE_SHORT)
        == 1
    )
    assert "head_digest: sha256:" in text
    assert len(text.encode("ascii")) <= MAX_SUMMARY_BYTES


def test_receipt_and_status_summaries_carry_the_fixed_agent_line() -> None:
    from finishup.domain.receipts import (
        SEMANTIC_REDACTED_VALUES_AGENT_LINE,
        SEMANTIC_REDACTED_VALUES_AGENT_LINE_SHORT,
    )

    receipt = summary_for_receipt(
        {
            "conclusion": "unresolved_findings_remain",
            "coverage": {"known_gaps": ["semantic_review_value_redacted"]},
            "suppressed_finding_count": "0",
            "result_frontier": {"sequence": "3", "head_digest": "sha256:" + "a" * 64},
            "document": {"semantic_redacted_values": _REDACTED_VALUES},
        }
    )
    status = summary_for_status(
        {
            "view": "operation",
            "gaps": [],
            "closure_readiness": {},
            "coverage": {"ledger_freshness": "current"},
            "head_frontier": {"sequence": "3", "head_digest": "sha256:" + "a" * 64},
            "page": {
                "state": "complete",
                "operation_kind": "check",
                "semantic_redacted_values": _REDACTED_VALUES,
            },
        }
    )
    assert receipt.count(SEMANTIC_REDACTED_VALUES_AGENT_LINE) == 1
    for text in (receipt, status):
        assert (
            text.count(SEMANTIC_REDACTED_VALUES_AGENT_LINE)
            + text.count(SEMANTIC_REDACTED_VALUES_AGENT_LINE_SHORT)
            == 1
        )
        assert len(text.encode("ascii")) <= MAX_SUMMARY_BYTES
    without = summary_for_receipt(
        {
            "conclusion": "unresolved_findings_remain",
            "coverage": {"known_gaps": []},
            "suppressed_finding_count": "0",
            "result_frontier": {"sequence": "3", "head_digest": "sha256:" + "a" * 64},
            "document": {},
        }
    )
    assert "[withheld-by-finishup:possible-credential]" not in without
    assert "[withheld-by-yoetz:possible-credential]" not in without
