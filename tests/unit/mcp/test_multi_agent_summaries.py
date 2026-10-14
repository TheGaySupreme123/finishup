"""Compact MCP text distinguishes lineage facts and advice without copying project content."""

from __future__ import annotations

from collections.abc import Mapping

from finishup.mcp.summaries import MAX_SUMMARY_BYTES, summary_for_check, summary_for_status
from finishup.protocol.canonical import JsonValue


def test_project_summary_carries_generation_and_counts_without_content() -> None:
    text = summary_for_status(
        {
            "view": "project",
            "head_frontier": {"sequence": "1", "head_digest": "sha256:" + "a" * 64},
            "page": {
                "project_id": "prj_59000000-0000-4000-8000-000000000001",
                "membership_generation": "3",
                "grant_state": "active",
                "title": "private project title",
                "description": "private project description",
                "members": [{"task_title": "private task"}],
                "lineage": {"children": [], "annotations": [{"origin": "host_observed"}]},
                "detections": [{"private_path": "/secret/file"}],
                "coverage": [{"task_id": "tsk_59000000-0000-4000-8000-000000000002"}],
                "receipts": [],
                "next_cursor": "private cursor",
            },
            "gaps": ["project_member_unavailable", "/private/raw/path"],
        }
    )
    assert "generation: 3; grant: active; members: 1" in text
    assert "detections: 1; receipts: 0; children: 0; host annotations: 1" in text
    assert "coverage: 1" in text
    assert "gap codes: project_member_unavailable;" in text
    assert "/private/raw/path" not in text
    assert "More pages available" in text
    assert "private" not in text and "/secret" not in text
    assert len(text.encode()) <= MAX_SUMMARY_BYTES


def test_hostile_project_grant_does_not_crash_or_leak() -> None:
    text = summary_for_status(
        {
            "view": "project",
            "page": {"grant_state": {"private": "secret"}},
        }
    )
    assert "grant: unavailable" in text
    assert "secret" not in text


def test_check_summary_prioritizes_actionable_input_over_finding_receipt() -> None:
    claim = "clm_59000000-0000-4000-8000-000000000011"
    text = summary_for_check(
        {
            "verdict": "insufficient_coverage",
            "findings": [],
            "suppressed_count": "0",
            "semantic_status": "succeeded",
            "semantic_reason": "semantic_completed",
            "finding_checklist": {
                "attempt_budget": "2",
                "counts": {
                    "acknowledged_not_done": "0",
                    "open": "0",
                    "open_at_budget": "0",
                    "rejection_accepted": "0",
                    "verified_resolved": "0",
                },
                "items": [],
                "next": "request_receipt",
            },
            "missing_for_assessment": [
                {
                    "kind": "verification_output",
                    "target_refs": [claim],
                    "availability": "agent_suppliable",
                }
            ],
            "overall_next": {
                "action": "supply_missing_input",
                "status": "action_required",
                "target_refs": [claim],
            },
            "result_frontier": {"sequence": "3", "head_digest": "sha256:" + "a" * 64},
        }
    )

    assert "overall next: supply_missing_input" in text
    assert "status: action_required" in text
    assert f"targets: {claim}" in text
    assert f"verification_output=agent_suppliable[{claim}]" in text
    assert len(text.encode("ascii")) <= MAX_SUMMARY_BYTES


def test_check_summary_keeps_structural_input_as_a_limitation() -> None:
    envelope: Mapping[str, JsonValue] = {
        "verdict": "insufficient_coverage",
        "findings": [],
        "suppressed_count": "0",
        "semantic_status": "succeeded",
        "semantic_reason": "semantic_completed",
        "missing_for_assessment": [
            {
                "kind": "command_identity",
                "target_refs": [],
                "availability": "structurally_unavailable_on_this_host",
            }
        ],
        "overall_next": {
            "action": "request_receipt",
            "status": "ready_with_limitations",
            "target_refs": [],
            "acknowledged_incomplete_endpoint": "receipt",
        },
        "result_frontier": {"sequence": "3", "head_digest": "sha256:" + "a" * 64},
    }
    text = summary_for_check(envelope)

    assert "overall next: supply_missing_input" not in text
    assert "overall next: request_receipt" in text
    assert "acknowledged incomplete endpoint: receipt" in text
    assert "disclose limitation at: receipt" in text
    assert "command_identity=structurally_unavailable_on_this_host" in text
    assert len(text.encode("ascii")) <= MAX_SUMMARY_BYTES


def test_check_summary_clips_many_overall_targets_without_dropping_action() -> None:
    refs: list[JsonValue] = [f"fnd_59000000-0000-4000-8000-{index:012x}" for index in range(64)]
    envelope: Mapping[str, JsonValue] = {
        "verdict": "action_required",
        "findings": [],
        "suppressed_count": "0",
        "semantic_status": "not_requested",
        "semantic_reason": "deterministic_mode",
        "overall_next": {
            "action": "review_recorded_work",
            "status": "action_required",
            "target_refs": refs,
        },
        "result_frontier": {"sequence": "3", "head_digest": "sha256:" + "a" * 64},
    }

    text = summary_for_check(envelope)

    assert "overall next: review_recorded_work; status: action_required" in text
    assert "...(+" in text
    assert len(text.encode("ascii")) <= MAX_SUMMARY_BYTES


def test_check_summary_keeps_global_supply_input_without_a_target_ref() -> None:
    envelope: Mapping[str, JsonValue] = {
        "verdict": "insufficient_coverage",
        "findings": [],
        "suppressed_count": "0",
        "semantic_status": "succeeded",
        "semantic_reason": "semantic_completed",
        "overall_next": {
            "action": "supply_missing_input",
            "status": "action_required",
            "target_refs": [],
        },
        "result_frontier": {"sequence": "3", "head_digest": "sha256:" + "a" * 64},
    }

    text = summary_for_check(envelope)

    assert "overall next: supply_missing_input; status: action_required" in text
    assert len(text.encode("ascii")) <= MAX_SUMMARY_BYTES


def test_check_summary_marks_preview_and_non_verdict_advice() -> None:
    text = summary_for_check(
        {
            "verdict": "no_issue_detected",
            "findings": [],
            "suppressed_count": "0",
            "semantic_status": "not_requested",
            "semantic_reason": "deterministic_mode",
            "children": {"label": "preview", "items": [{"acceptance": "pending"}]},
            "advisory_notes": [{"kind": "live_member_present"}],
        }
    )
    assert "No issue detected within deterministic coverage" in text
    assert "children (preview): 1" in text
    assert "project advice (non-verdict): 1" in text
    assert len(text.encode()) <= MAX_SUMMARY_BYTES
