"""Transport-neutral summary weakening checks shared by CLI and MCP."""

from __future__ import annotations

from yoetz.mcp.summaries import MAX_SUMMARY_BYTES, render_safe_compact_summary
from yoetz.protocol.canonical import JsonValue


def test_human_summary_is_weaker_than_structured_output() -> None:
    secret = "raw-user-payload-must-not-appear"
    check = {
        "ok": True,
        "verdict": "incomplete_check",
        "findings": [{"summary": secret}],
        "suppressed_count": "3",
        "semantic_status": "not_configured",
        "semantic_reason": "provider_not_configured",
        "result_frontier": {"sequence": "7", "head_digest": "sha256:" + "0" * 64},
    }
    summary = render_safe_compact_summary(check)
    assert summary == (
        "Check verdict: incomplete_check; findings returned: 1; suppressed: 3; AI-powered review "
        "status/reason: not_configured/provider_not_configured; frontier: 7; "
        "head_digest: sha256:" + "0" * 64 + "."
    )
    assert secret not in summary
    assert len(summary.encode("ascii")) <= MAX_SUMMARY_BYTES

    status: dict[str, JsonValue] = {
        "ok": True,
        "view": "compact",
        "result_frontier": {"sequence": "9"},
        "page": {
            "items": [
                {
                    "freshness": "stale_after_material_change",
                    "open_obligation_count": "2",
                    "unanswered_finding_count": "4",
                    "receipt_blocking_finding_count": "3",
                    "latest_check_test_edits": {
                        "read_availability": "available",
                        "modified": "1",
                        "renamed": "0",
                        "deleted": "0",
                        "skipped": "0",
                        "unjustified": "0",
                        "unknown": "0",
                    },
                    "open_obligations": [
                        {
                            "obligation_id": "obl_00000000-0000-4000-8000-000000000001",
                            "description": secret,
                        }
                    ],
                    "task_title": secret,
                }
            ]
        },
        "gaps": ["redacted", "unknown"],
    }
    status_summary = render_safe_compact_summary(status)
    assert status_summary == (
        "Status view: compact; frontier: 9; freshness: stale_after_material_change; open "
        "obligations: 2; test edits available: 1 modified, 0 renamed, 0 deleted, 0 skipped, "
        "0 unjustified, 0 unknown; obligation IDs: obl_00000000-0000-4000-8000-000000000001; "
        "unanswered findings: 4; receipt-blocking findings: 3; "
        "reported gaps: 2."
    )
    assert secret not in status_summary

    # A real compact status carries closure_readiness beside the singleton. The readiness counters
    # win, but the summary must keep reporting the singleton's own (weaker) projection freshness
    # rather than the result envelope's newest-record coverage, which is routinely `current` at
    # exactly the frontier where the projection is already `partial`.
    status["coverage"] = {"ledger_freshness": "current"}
    status["closure_readiness"] = {
        "open_obligation_count": "2",
        "unanswered_finding_count": "0",
        "receipt_blocking_finding_count": "3",
    }
    assert render_safe_compact_summary(status) == (
        "Status view: compact; frontier: 9; freshness: stale_after_material_change; open "
        "obligations: 2; test edits available: 1 modified, 0 renamed, 0 deleted, 0 skipped, "
        "0 unjustified, 0 unknown; obligation IDs: obl_00000000-0000-4000-8000-000000000001; "
        "unanswered findings: 0; receipt-blocking findings: 3; "
        "reported gaps: 2."
    )

    status["view"] = "obligations"
    status["page"] = {
        "items": [
            {
                "obligation_id": "obl_00000000-0000-4000-8000-000000000002",
                "description": secret,
            },
            {"obligation_id": secret},
        ],
        "next_cursor": None,
    }
    assert render_safe_compact_summary(status) == (
        "Status view: obligations; frontier: 9; freshness: current; open obligations: 2; "
        "obligation IDs: obl_00000000-0000-4000-8000-000000000002; unanswered findings: 0; "
        "receipt-blocking findings: 3; reported gaps: 2."
    )
    assert secret not in render_safe_compact_summary(status)

    status["view"] = "findings"
    status["page"] = {"items": [], "next_cursor": None}
    status["coverage"] = {"ledger_freshness": "current"}
    status["closure_readiness"] = {
        "open_obligation_count": "0",
        "unanswered_finding_count": "0",
        "receipt_blocking_finding_count": "2",
    }
    assert render_safe_compact_summary(status) == (
        "Status view: findings; frontier: 9; freshness: current; open obligations: 0; "
        "unanswered findings: 0; receipt-blocking findings: 2; reported gaps: 2."
    )

    # An evidence row's `freshness` describes that evidence, not the ledger, so it must never be
    # promoted into the ledger-freshness slot of the summary.
    # Rows are counted per closed publication channel (#914); an unknown channel value is caller
    # text and is counted as a row without ever being rendered.
    status["view"] = "evidence"
    status["page"] = {
        "items": [
            {"freshness": "stale_after_material_change", "publication_channel": "hook_observed"},
            {"publication_channel": secret},
        ],
        "next_cursor": None,
    }
    evidence_summary = render_safe_compact_summary(status)
    assert evidence_summary == (
        "Status view: evidence; frontier: 9; freshness: current; open obligations: 0; "
        "evidence rows: 2 (hook_observed 1, unrecorded 1); "
        "unanswered findings: 0; receipt-blocking findings: 2; reported gaps: 2."
    )
    assert secret not in evidence_summary

    receipt = {
        "ok": True,
        "receipt_id": "rcp_00000000-0000-4000-8000-000000000001",
        "conclusion": "insufficient_coverage",
        "subject_frontier": {"sequence": "11"},
        "coverage": {"known_gaps": ["redacted_gap", "semantic_review_not_configured", secret]},
        "obligations": [
            {
                "obligation_id": "obl_00000000-0000-4000-8000-000000000002",
                "status": "open",
                "summary": secret,
            },
            {
                "obligation_id": "obl_00000000-0000-4000-8000-000000000003",
                "status": "resolved",
            },
        ],
        "suppressed_finding_count": 5,
        "human_text": secret,
    }
    receipt_summary = render_safe_compact_summary(receipt)
    assert receipt_summary == (
        "Receipt conclusion: insufficient_coverage; frontier: 11; coverage limitations: 3; "
        "open obligation IDs: obl_00000000-0000-4000-8000-000000000002; "
        "gap codes: redacted_gap, semantic_review_not_configured; "
        "suppressed findings: 5."
    )
    assert secret not in receipt_summary


def test_text_only_closure_lists_remain_bounded_and_keep_both_receipt_classes() -> None:
    # More ids than one list is allowed to take of the 4,096-byte text (1,024 characters per list).
    obligation_ids = [f"obl_00000000-0000-4000-8000-{index:012x}" for index in range(1, 61)]
    status: dict[str, JsonValue] = {
        "ok": True,
        "view": "obligations",
        "result_frontier": {"sequence": "12"},
        "page": {"items": [{"obligation_id": obligation_id} for obligation_id in obligation_ids]},
        "closure_readiness": {
            "open_obligation_count": "60",
            "unanswered_finding_count": "0",
            "receipt_blocking_finding_count": "0",
        },
        "coverage": {"ledger_freshness": "current"},
        "gaps": [],
    }
    status_summary = render_safe_compact_summary(status)
    assert "obligation IDs: obl_00000000-0000-4000-8000-000000000001" in status_summary
    assert "more" in status_summary
    assert len(status_summary.encode("ascii")) <= MAX_SUMMARY_BYTES

    receipt: dict[str, JsonValue] = {
        "ok": True,
        "receipt_id": "rcp_00000000-0000-4000-8000-000000000001",
        "conclusion": "insufficient_coverage",
        "subject_frontier": {"sequence": "13"},
        "coverage": {
            "known_gaps": [
                "check_not_recorded",
                "semantic_review_not_configured",
                "semantic_relevance_review_not_run",
            ]
        },
        "obligations": [
            {"obligation_id": obligation_id, "status": "open"} for obligation_id in obligation_ids
        ],
        "suppressed_finding_count": 0,
    }
    receipt_summary = render_safe_compact_summary(receipt)
    assert "open obligation IDs:" in receipt_summary
    assert "gap codes:" in receipt_summary
    assert "more" in receipt_summary
    assert len(receipt_summary.encode("ascii")) <= MAX_SUMMARY_BYTES
