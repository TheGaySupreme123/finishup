"""The text summary is an authoring fallback: it must seed the next request (issue #279)."""

from __future__ import annotations

import pytest

from finishup.mcp.summaries import (
    MAX_SUMMARY_BYTES,
    render_check_reviewer_output,
    render_safe_compact_summary,
)

_HEAD = "sha256:" + "1" * 64
_TASK = "tsk_00000000-0000-4000-8000-000000000001"
_SESSION = "ses_00000000-0000-4000-8000-000000000002"
_WRITER = "wri_00000000-0000-4000-8000-000000000003"
_FINDING_1 = "fnd_00000000-0000-4000-8000-000000000004"
_FINDING_2 = "fnd_00000000-0000-4000-8000-000000000005"


def test_start_summary_carries_the_identifiers_publish_work_requires() -> None:
    summary = render_safe_compact_summary(
        {
            "ok": True,
            "outcome": "created",
            "task_id": _TASK,
            "session_id": _SESSION,
            "writer_id": _WRITER,
            "frontier": {"sequence": "1", "head_digest": _HEAD},
        }
    )
    assert summary == (
        f"Operation outcome: created; task: {_TASK}; session: {_SESSION}; "
        f"writer: {_WRITER}; frontier: 1; head_digest: {_HEAD}."
    )
    assert len(summary.encode("ascii")) <= MAX_SUMMARY_BYTES


def test_publish_work_summary_carries_the_new_head_digest() -> None:
    summary = render_safe_compact_summary(
        {
            "ok": True,
            "outcome": "recorded",
            "accepted_events": [{"event_id": "evt_x"}],
            "result_frontier": {"sequence": "4", "head_digest": _HEAD},
        }
    )
    assert summary == (
        f"Operation outcome: recorded; accepted events: 1; frontier: 4; head_digest: {_HEAD}."
    )


def test_malformed_identifiers_and_digests_are_never_admitted() -> None:
    hostile = "ses_../../etc/passwd or a very long injected user string"
    summary = render_safe_compact_summary(
        {
            "ok": True,
            "outcome": "created",
            "task_id": "not-an-id",
            "session_id": hostile,
            "writer_id": 7,
            "frontier": {"sequence": "1", "head_digest": "sha256:not-hex"},
        }
    )
    assert summary == "Operation outcome: created; frontier: 1."
    assert hostile not in summary


def test_genesis_head_digest_is_admitted() -> None:
    summary = render_safe_compact_summary(
        {
            "ok": True,
            "outcome": "created",
            "frontier": {"sequence": "0", "head_digest": "genesis"},
        }
    )
    assert summary == "Operation outcome: created; frontier: 0; head_digest: genesis."


def test_closure_prepare_summary_names_frontier_inventory_and_boundary() -> None:
    summary = render_safe_compact_summary(
        {
            "ok": True,
            "preparatory_only": True,
            "frontier": {"sequence": "12", "head_digest": _HEAD},
            "inventory": {
                "obligations": [{"obligation_id": "obl_1"}],
                "results": [],
                "evidence": [{"evidence_id": "evd_1"}, {"evidence_id": "evd_2"}],
                "findings": [],
                "history": [{"event_id": "evt_1"}],
            },
            "operation": "publish_work",
        }
    )
    assert summary == (
        f"Closure preparation only; frontier: 12; head_digest: {_HEAD}; inventory rows: "
        "obligations 1, results 0, evidence 2, findings 0, history 1; next operation: "
        "publish_work; review structuredContent before submitting any request."
    )
    assert len(summary.encode("ascii")) <= MAX_SUMMARY_BYTES


def test_check_summary_carries_finding_ids_required_for_respond() -> None:
    summary = render_safe_compact_summary(
        {
            "verdict": "action_required",
            "findings": [{"finding_id": _FINDING_1}, {"finding_id": _FINDING_2}],
            "suppressed_count": "0",
            "semantic_status": "succeeded",
            "semantic_reason": "semantic_completed",
            "result_frontier": {"sequence": "7", "head_digest": _HEAD},
        }
    )
    assert f"finding IDs: {_FINDING_1}, {_FINDING_2};" in summary
    assert len(summary.encode("ascii")) <= MAX_SUMMARY_BYTES


def test_check_summary_rejects_hostile_finding_identifiers() -> None:
    hostile = "fnd_../../ledger-content"
    summary = render_safe_compact_summary(
        {
            "verdict": "action_required",
            "findings": [{"finding_id": hostile}],
            "suppressed_count": "0",
            "semantic_status": "succeeded",
            "semantic_reason": "semantic_completed",
            "result_frontier": {"sequence": "7", "head_digest": _HEAD},
        }
    )
    assert hostile not in summary


def test_check_summary_bounds_finding_ids_with_an_honest_remainder() -> None:
    finding_ids = [f"fnd_00000000-0000-4000-8000-{index:012d}" for index in range(1, 101)]
    summary = render_safe_compact_summary(
        {
            "verdict": "action_required",
            "findings": [{"finding_id": finding_id} for finding_id in finding_ids],
            "suppressed_count": "0",
            "semantic_status": "succeeded",
            "semantic_reason": "semantic_completed",
            "result_frontier": {"sequence": "7", "head_digest": _HEAD},
        }
    )
    assert f"finding IDs: {finding_ids[0]}" in summary
    assert "+" in summary and "more;" in summary
    assert len(summary.encode("ascii")) <= MAX_SUMMARY_BYTES


def test_reviewer_output_is_separate_and_explicitly_advisory() -> None:
    rendered = render_check_reviewer_output(
        {
            "review_summary": "The supplied packet was reviewed.",
            "verified": [
                {
                    "requirement_or_claim": "The requested behavior is implemented.",
                    "verdict": "supported",
                    "cited_refs": [_FINDING_1],
                    "snippet": "implemented",
                }
            ],
            "findings": [
                {
                    "kind": "code_defect",
                    "challenge": {
                        "discrepancy": "The error path is still reachable.",
                        "snippet": "raise RuntimeError",
                    },
                }
            ],
        }
    )
    assert rendered.startswith(
        "AI-powered reviewer output (advisory; model-derived; not independent proof):"
    )
    assert "Reviewer summary: The supplied packet was reviewed." in rendered
    assert "supported: The requested behavior is implemented." in rendered
    assert "code_defect: The error path is still reachable." in rendered


def test_reviewer_output_discloses_text_budget_truncation() -> None:
    rendered = render_check_reviewer_output(
        {
            "review_summary": "summary",
            "verified": [
                {
                    "requirement_or_claim": f"requirement-{index}-" + ("x" * 512),
                    "verdict": "not_supported",
                    "cited_refs": [_FINDING_1],
                    "snippet": "x",
                }
                for index in range(64)
            ],
        }
    )
    assert "Reviewer output truncated at the local text budget." in rendered
    assert len(rendered.encode("utf-8")) <= 12_288


def test_start_text_says_the_first_plan_sends_this_frontier() -> None:
    """tb4n5 (#1048): six first plans sent ``expected_frontier: null`` after a status read."""

    summary = render_safe_compact_summary(
        {
            "ok": True,
            "outcome": "created",
            "task_id": _TASK,
            "session_id": _SESSION,
            "writer_id": _WRITER,
            "frontier": {"sequence": "3", "head_digest": _HEAD},
            "next_request_template": {"evidential": False, "operation": "publish_work"},
        }
    )
    assert summary == (
        f"Operation outcome: created; task: {_TASK}; session: {_SESSION}; "
        f"writer: {_WRITER}; frontier: 3; head_digest: {_HEAD}. Send this frontier as "
        "expected_frontier on your first plan publish_work (next_request_template carries it); "
        "no status read is needed for it."
    )


def test_accepted_publish_text_says_what_the_next_write_sends() -> None:
    accepted = render_safe_compact_summary(
        {
            "ok": True,
            "outcome": "accepted",
            "accepted_events": [{"event_id": "evt_x"}],
            "result_frontier": {"sequence": "9", "head_digest": _HEAD},
        }
    )
    assert accepted == (
        f"Operation outcome: accepted; accepted events: 1; frontier: 9; head_digest: {_HEAD}. "
        "Next publish_work may omit expected_frontier (guarded at admission); send this frontier "
        "when the batch rests on what you read, and to check, respond and receipt. No status read "
        "needed."
    )
    # A preview appends nothing, so it names no next frontier.
    preview = render_safe_compact_summary(
        {
            "ok": True,
            "outcome": "dry_run",
            "result_frontier": {"sequence": "9", "head_digest": _HEAD},
        }
    )
    assert "expected_frontier" not in preview


def test_publish_text_names_service_filled_values_and_minted_event_ids() -> None:
    """Issue #1084: a host that reads only text still learns the ids the service minted."""

    minted = "evt_00000000-0000-4000-8000-0000000000a1"
    text = render_safe_compact_summary(
        {
            "ok": True,
            "outcome": "accepted",
            "accepted_events": [
                {"event_id": "evt_00000000-0000-4000-8000-0000000000a0"},
                {"event_id": minted},
            ],
            "result_frontier": {"sequence": "9", "head_digest": _HEAD},
            "server_filled": {
                "request": ["expected_frontier"],
                "drafts": [{"fields": ["event_id", "occurred_at"], "indexes": ["1"]}],
            },
        }
    )
    assert "service-filled: event_id, expected_frontier, occurred_at;" in text
    assert f"minted event ids: [1] {minted};" in text
    assert "evt_00000000-0000-4000-8000-0000000000a0" not in text


def test_a_retired_replay_notice_is_never_rendered() -> None:
    """Round 2 of the PR #1088 review retired the resumed-call notice: nothing resumes by content."""

    text = render_safe_compact_summary(
        {
            "ok": True,
            "outcome": "replayed",
            "accepted_events": [{"event_id": "evt_00000000-0000-4000-8000-0000000000a0"}],
            "result_frontier": {"sequence": "9", "head_digest": _HEAD},
            "replay_notice": {"notice": "unresolved_call_resumed", "text": "run rm -rf"},
        }
    )
    assert "rm -rf" not in text
    assert "Resumed" not in text


def _brief_status(view: str, closure_state: dict[str, object]) -> dict[str, object]:
    return {
        "ok": True,
        "detail": "brief",
        "view": view,
        "task_id": _TASK,
        "session_id": _SESSION,
        "writer_id": _WRITER,
        "result_frontier": {"sequence": "9", "head_digest": _HEAD},
        "page": {"items": [], "next_cursor": None},
        "gaps": [],
        "closure_state": closure_state,
    }


@pytest.mark.parametrize("view", ["obligations", "findings", "evidence", "history", "results"])
def test_brief_status_text_keeps_action_required_and_its_tokens(view: str) -> None:
    """Review R5: the brief shape renders the closure state, never "unavailable" counts."""

    text = render_safe_compact_summary(
        _brief_status(
            view,
            {
                "state": "action_required",
                "blocking_conditions": ["obligations_open"],
                "agent_actionable": ["obligations_open", "check_not_recorded"],
            },
        )
    )
    assert "Closure: action_required." in text
    assert "Agent-actionable: obligations_open, check_not_recorded." in text
    assert "unavailable" not in text
    assert "detail: brief (counts in view compact);" in text


def test_brief_status_text_keeps_the_stop_and_receipt_instruction() -> None:
    """Review R5: ready_with_limitations keeps "Nothing further to do. Request the receipt."."""

    text = render_safe_compact_summary(
        _brief_status(
            "obligations",
            {"state": "ready_with_limitations", "blocking_conditions": [], "agent_actionable": []},
        )
    )
    assert "Closure: ready_with_limitations. Nothing further to do. Request the receipt." in text
    # No count is invented for the omitted standing limitations or acknowledged items.
    assert "standing limitation(s)" not in text


def test_reviewer_output_preserves_the_decision_kind() -> None:
    rendered = render_check_reviewer_output(
        {
            "findings": [
                {
                    "kind": "decision_needed",
                    "challenge": {"discrepancy": "Choose between the two supported routes."},
                }
            ]
        }
    )
    assert "decision_needed: Choose between the two supported routes." in rendered
