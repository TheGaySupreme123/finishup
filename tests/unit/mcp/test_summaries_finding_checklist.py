"""The status findings summary counts only to-dos (issue #905 re-verification R1)."""

from __future__ import annotations

from yoetz.mcp.summaries import summary_for_check, summary_for_status


def _row(number: int, kind: str, state: str, rounds: str) -> dict[str, object]:
    return {
        "finding_id": f"fnd_59000000-0000-4000-8000-{number:012d}",
        "kind": kind,
        "todo_state": state,
        "review_rounds": rounds,
    }


def _summary(*rows: dict[str, object]) -> str:
    return summary_for_status(
        {
            "view": "findings",
            "head_frontier": {"sequence": "4", "head_digest": "sha256:" + "a" * 64},
            "page": {"items": list(rows), "next_cursor": None, "attempt_budget": "5"},
            "gaps": [],
        }
    )


def test_a_coverage_limitation_row_is_not_counted_as_a_to_do() -> None:
    text = _summary(_row(1, "ledger_stale_or_incomplete", "open", "7"))
    assert "to-do:" not in text
    assert "at budget" not in text


def test_actionable_rows_are_counted_and_unknown_kinds_are_ignored() -> None:
    text = _summary(
        _row(1, "completion_with_open_obligations", "open", "5"),
        _row(2, "ledger_stale_or_incomplete", "open", "9"),
        _row(3, "claim_without_admissible_evidence", "verified_resolved", "0"),
        _row(4, "not_a_kind", "open", "9"),
    )
    assert "to-do: open 1 (1 at budget 5), verified 1, not done 0, rejection accepted 0;" in text
    assert "not_a_kind" not in text
    assert len(text.encode()) <= 512


def _check_envelope(next_step: str) -> dict[str, object]:
    open_refs = [f"fnd_59000000-0000-4000-8000-{index:012d}" for index in range(1, 3)]
    return {
        "verdict": "action_required",
        "findings": [],
        "suppressed_count": "0",
        "semantic_status": "succeeded",
        "semantic_reason": "semantic_completed",
        "overall_next": {
            "action": "work_open_findings",
            "status": "action_required",
            "target_refs": open_refs,
        },
        "finding_checklist": {
            "attempt_budget": "2",
            "counts": {
                "acknowledged_not_done": "0",
                "open": "2",
                "open_at_budget": "1",
                "rejection_accepted": "0",
                "verified_resolved": "0",
            },
            "items": [],
            "next": next_step,
        },
        "result_frontier": {"sequence": "6", "head_digest": "sha256:" + "a" * 64},
    }


def test_the_at_budget_decision_survives_a_long_task_continuation() -> None:
    """Issue #905: the budget cue stays visible when the full to-do clause cannot fit."""

    text = summary_for_check(_check_envelope("decide_at_budget"))
    assert "overall next: work_open_findings" in text
    assert "finding checklist next: decide_at_budget (at budget 2);" in text
    assert len(text.encode("ascii")) <= 512


def test_no_compact_cue_is_invented_below_the_budget() -> None:
    text = summary_for_check(_check_envelope("work_open_findings"))
    assert "decide_at_budget" not in text
    assert "at budget" not in text


def test_linked_duplicates_are_named_only_when_present() -> None:
    """Issue #996: a holding link is counted from its structural id; its state is the earlier
    finding's, so the open count already reads as that finding allows."""

    linked = {
        **_row(2, "claim_without_admissible_evidence", "open", "0"),
        "duplicate_of_finding_id": "fnd_59000000-0000-4000-8000-000000000001",
    }
    text = _summary(_row(1, "completion_with_open_obligations", "open", "0"), linked)
    assert "to-do: open 2, verified 0, not done 0, rejection accepted 0, linked duplicates 1;" in (
        text
    )
    forged = {**linked, "duplicate_of_finding_id": "not an id"}
    assert "linked duplicates" not in _summary(forged)
