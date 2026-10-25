"""The draft receipt's wire rules and text (issue #975, ADR-046 amendment)."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from finishup.application.semantic_case import WITHHELD_OUTPUT_QUESTION, review_question_set
from finishup.protocol.models import StatusClosureReadinessModel
from finishup.protocol.readiness_text import (
    draft_receipt_criterion_lines,
    draft_receipt_variants,
)

_OBL = "obl_09750000-0000-4000-8000-000000000001"
_CLM = "clm_09750000-0000-4000-8000-000000000002"
_NOTE = "evt_09750000-0000-4000-8000-000000000003:1"


def _draft(**changes: Any) -> dict[str, Any]:
    draft: dict[str, Any] = {
        "label": "draft_records_not_correctness",
        "conclusion": "insufficient_coverage",
        "reasons": ["live_gap_bounds"],
        "criteria": [
            {
                "task_criterion_excerpt": "Every row must be sorted by id.",
                "source": "task_statement",
                "standing": "none",
                "refs": [],
            },
            {
                "obligation_criterion_excerpt": "The tool writes out.txt.",
                "source": "obligation",
                "standing": "agent_claim_only",
                "refs": [_CLM, _OBL],
            },
        ],
        "criteria_counts": {"linked_pass_current": "2", "agent_claim_only": "1", "none": "1"},
        "criteria_total": "4",
        "fix_or_decline_count": "0",
        "advice_unanswered": [_NOTE],
        "advice_unanswered_count": "1",
        "limitations": ["host_outcome_unavailable"],
        "limitation_count": "1",
    }
    draft.update(changes)
    return draft


def _readiness(draft: dict[str, Any] | None, **changes: Any) -> StatusClosureReadinessModel:
    body: dict[str, Any] = {
        "declared_obligation_count": "1",
        "no_obligations_reason": None,
        "open_obligation_count": "0",
        "unanswered_finding_count": "0",
        "receipt_blocking_finding_count": "0",
        "blocking_conditions": ["coverage_gaps_declared"],
        "state": "ready_with_limitations",
        "gap_classification_version": "9",
        "agent_actionable": [],
        "standing_limitations": ["host_outcome_unavailable"],
        "acknowledged_not_done": [],
        "acknowledged_not_done_count": "0",
        "blocked_obligations": [],
        "correctness_advisory_counts": {
            "total": "1",
            "no_recorded_response": "1",
            "withheld_may_answer": "0",
        },
        "predicted_receipt": {
            "conclusion": "insufficient_coverage",
            "reasons": [
                {"code": "live_gap_bounds", "rule": "R10", "count": "1", "refs": []},
            ],
            "reason_total": "1",
            "basis_frontier": "9",
            "provisional": False,
        },
        **({} if draft is None else {"draft_receipt": draft}),
    }
    body.update(changes)
    return StatusClosureReadinessModel.model_validate(body)


def test_a_draft_repeats_the_prediction_and_readiness_it_sits_beside() -> None:
    assert _readiness(_draft()).draft_receipt is not None
    for bad in (
        _draft(conclusion="no_unresolved_deterministic_findings"),
        _draft(reasons=["findings_disclosed"]),
        _draft(fix_or_decline_count="1"),
        _draft(advice_unanswered=[], advice_unanswered_count="0"),
        _draft(limitations=[], limitation_count="0"),
    ):
        with pytest.raises(ValidationError, match="draft_receipt"):
            _readiness(bad)
    # Only a ready readiness carries one.
    with pytest.raises(ValidationError, match="draft_receipt"):
        _readiness(
            _draft(),
            state="action_required",
            agent_actionable=["check_not_recorded"],
        )


def test_a_criterion_carries_exactly_its_own_excerpt_and_a_ref_unless_none() -> None:
    criterion: dict[str, Any] = {
        "task_criterion_excerpt": "Rows are sorted.",
        "source": "obligation",
        "standing": "none",
        "refs": [],
    }
    with pytest.raises(ValidationError, match="draft_receipt_criterion_excerpt_source"):
        _readiness(_draft(criteria=[criterion]))
    claim: dict[str, Any] = {
        "task_criterion_excerpt": "Rows are sorted.",
        "source": "task_statement",
        "standing": "agent_claim_only",
        "refs": [],
    }
    with pytest.raises(ValidationError, match="draft_receipt_criterion_refs_missing"):
        _readiness(_draft(criteria=[claim]))


def test_the_text_is_labelled_records_and_names_ids_counts_and_open_items() -> None:
    draft = _readiness(_draft()).draft_receipt
    (full, *_shorter) = draft_receipt_variants(draft)
    assert full.startswith("Draft receipt (records, not correctness): insufficient_coverage; ")
    assert f"2 linked passing current run, 1 agent claim only ({_CLM}, {_OBL}), 1 none" in full
    assert f"unanswered advice: 1 ({_NOTE})" in full
    assert "will disclose: host_outcome_unavailable" in full
    assert "keep working and check again; then request the final receipt" in full
    # Never a correctness word for a linked pass.
    assert "verified" not in full.lower()
    assert draft_receipt_criterion_lines(draft) == (
        '  none: "Every row must be sorted by id." (task statement)',
        f'  agent claim only: "The tool writes out.txt." (obligation) [{_CLM}, {_OBL}]',
    )
    assert draft_receipt_variants(None) == ()
    assert draft_receipt_variants({"conclusion": "clean"}) == ()


def test_a_withheld_excerpt_is_named_as_withheld_never_recovered() -> None:
    withheld: dict[str, Any] = {
        "task_criterion_excerpt": {
            "omitted": True,
            "category": "task_description",
            "reason": "category_not_allowed",
        },
        "source": "task_statement",
        "standing": "none",
        "refs": [],
    }
    lines = draft_receipt_criterion_lines({"criteria": [withheld]})
    assert lines == ("  none: (criterion text withheld by the privacy policy) (task statement)",)


def test_the_withheld_output_question_rides_only_a_closing_review_after_a_review() -> None:
    assert WITHHELD_OUTPUT_QUESTION not in review_question_set("final")
    assert WITHHELD_OUTPUT_QUESTION not in review_question_set("routine", prior_review=True)
    asked = review_question_set("final", prior_review=True, linked_verification=True)
    # Before the linked-check question, which stays last.
    assert asked[-2] == WITHHELD_OUTPUT_QUESTION
    assert "Counter-example" in asked[-1]
    # Bounded: it rides a packet whose read budget is pinned (#1173).
    assert len(WITHHELD_OUTPUT_QUESTION.encode()) < 240
