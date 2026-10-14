"""Offline classification locks for the influence dogfood protocol (issue #133).

No live Codex, no network. Synthetic timeline dicts only. Validator is test-local
(``tests.unit.dogfood.influence_report``), not product runtime.
"""

from __future__ import annotations

from tests.unit.dogfood.influence_report import (
    AttributionRecord,
    InfluenceTimeline,
    classify_influence_report,
)


def test_healthy_zero_findings_honesty_only_not_demonstrated_influence() -> None:
    """Healthy service + zero findings + honesty-only wording + no revision → D not demonstrated."""

    timeline: InfluenceTimeline = {
        "activation": "session_ops",
        "experiment_profile": "strict",
        "semantic_status": "blocked_by_policy",
        "semantic_provenance_present": False,
        "ops_completed_honestly": True,
        "plan_before_first_source_edit": True,
        "obligation_before_first_source_edit": True,
        "valid_plan_ms": 100,
        "first_obligation_ms": 200,
        "first_source_edit_ms": 1000,
        "findings_deterministic": 0,
        "findings_semantic": 0,
        "attributions": [],
        "receipt_wording_changed_for_honesty": True,
        "seeded_defect_seeded": False,
        "final_prose": (
            "Service completed ops honestly; receipt conclusion matched weakest coverage. "
            "No material work revision occurred."
        ),
        "control_run": "not_run",
    }
    report = classify_influence_report(timeline)
    assert report["stream_a"] == "pass"
    assert report["stream_d"] == "not_demonstrated"
    assert report["work_product_influence"] == "not_demonstrated"
    assert report["honesty_influence"] == "yes"
    assert report["forbidden_summary_violation"] is False

    # Claiming improvement without demonstration violates the forbidden-summary rule.
    bad: InfluenceTimeline = {
        **timeline,
        "final_prose": "FinishUP improved the agent despite zero findings.",
    }
    bad_report = classify_influence_report(bad)
    assert bad_report["work_product_influence"] == "not_demonstrated"
    assert bad_report["forbidden_summary_violation"] is True


def test_registration_only_is_not_activation_or_influence() -> None:
    timeline: InfluenceTimeline = {
        "activation": "registered_only",
        "experiment_profile": "strict",
        "ops_completed_honestly": False,
        "attributions": [
            {
                "finishup_output_ref": "finding-should-not-count",
                "bounded_action_after": "source_revision",
                "recheck_result": "passed",
                "counterfactual": "uncertain",
            }
        ],
        "final_prose": "MCP registered; tools listed.",
    }
    report = classify_influence_report(timeline)
    assert report["is_activation"] is False
    assert report["activation"] == "registered_only"
    assert report["work_product_influence"] == "not_demonstrated"
    assert report["stream_d"] == "not_demonstrated"
    assert report["material_revisions_attributable_to_finishup"] == 0


def test_tools_list_only_is_not_activation() -> None:
    report = classify_influence_report(
        {
            "activation": "tools_listed",
            "experiment_profile": "policy",
            "final_prose": "tools/list returned six tools",
        }
    )
    assert report["is_activation"] is False
    assert report["stream_d"] == "not_demonstrated"
    assert report["stream_a"] == "not_demonstrated"


def test_strict_route_semantic_blocked_is_not_tested_not_fail() -> None:
    report = classify_influence_report(
        {
            "activation": "session_ops",
            "experiment_profile": "strict",
            "semantic_status": "blocked_by_policy",
            "semantic_provenance_present": False,
            "ops_completed_honestly": True,
            "findings_semantic": 0,
            "final_prose": "semantic_status=blocked_by_policy; usefulness not tested",
        }
    )
    assert report["stream_c"] == "not_tested"
    assert report["semantic_scoring_eligible"] is False
    assert report["stream_c"] != "fail"


def test_plan_after_first_edit_fails_early_publication_gate() -> None:
    report = classify_influence_report(
        {
            "activation": "session_ops",
            "experiment_profile": "strict",
            "ops_completed_honestly": True,
            "plan_before_first_source_edit": False,
            "obligation_before_first_source_edit": False,
            "first_source_edit_ms": 100,
            "valid_plan_ms": 500,
            "first_obligation_ms": 600,
            "final_prose": "plan published after first source edit",
        }
    )
    assert report["authoring_early_publication_gate"] == "failed"
    assert report["plan_and_obligation_before_first_source_edit"] is False
    assert report["stream_b"] == "fail"


def test_terminal_review_only_not_applicable_gate_is_not_tested_without_retry_thrash() -> None:
    """Terminal-review-only: gate N/A; Stream B stays not_tested when retries are low."""

    report = classify_influence_report(
        {
            "activation": "session_ops",
            "experiment_profile": "strict",
            "ops_completed_honestly": True,
            "terminal_review_only": True,
            "identical_structural_retries": 2,
            "final_prose": "terminal-review-only; early gate not applicable",
        }
    )
    assert report["authoring_early_publication_gate"] == "not_applicable"
    assert report["stream_b"] == "not_tested"


def test_terminal_review_only_not_applicable_gate_fails_on_identical_retry_thrash() -> None:
    """Terminal-review-only still fails Stream B when identical structural retries > 3."""

    report = classify_influence_report(
        {
            "activation": "session_ops",
            "experiment_profile": "strict",
            "ops_completed_honestly": True,
            "terminal_review_only": True,
            "identical_structural_retries": 4,
            "final_prose": "terminal-review-only but agent thrashed on structural rejects",
        }
    )
    assert report["authoring_early_publication_gate"] == "not_applicable"
    assert report["stream_b"] == "fail"


def test_finding_revision_recheck_demonstrates_influence() -> None:
    attribution: AttributionRecord = {
        "finishup_output_ref": "finding_det_1",
        "agent_decision_before": "no_revision_planned",
        "bounded_action_after": "source_revision",
        "new_evidence_ref": "sha256:" + ("a" * 64),
        "counterfactual": "uncertain",
        "recheck_result": "passed",
    }
    report = classify_influence_report(
        {
            "activation": "session_ops",
            "experiment_profile": "policy",
            "semantic_status": "succeeded",
            "semantic_provenance_present": True,
            "ops_completed_honestly": True,
            "plan_before_first_source_edit": True,
            "obligation_before_first_source_edit": True,
            "valid_plan_ms": 50,
            "first_obligation_ms": 80,
            "first_source_edit_ms": 200,
            "findings_deterministic": 1,
            "findings_accepted": 1,
            "attributions": [attribution],
            "seeded_defect_seeded": True,
            "seeded_defect_in_case": True,
            "seeded_defect_finding_present": True,
            "seeded_defect_agent_acted": True,
            "final_prose": "Agent revised source after finding_det_1; recheck passed.",
            "control_run": "run",
        }
    )
    assert report["work_product_influence"] == "demonstrated"
    assert report["stream_d"] == "pass"
    assert report["material_revisions_attributable_to_finishup"] == 1
    assert report["material_revisions_rechecked"] == 1
    assert report["seeded_defect_outcome"] == "remediated"
    assert report["seeded_defect_miss_class"] is None
    assert report["forbidden_summary_violation"] is False
    assert report["stream_c"] == "pass"
    assert report["semantic_scoring_eligible"] is True


def test_seeded_defect_absent_from_case_is_case_construction_miss() -> None:
    report = classify_influence_report(
        {
            "activation": "session_ops",
            "experiment_profile": "strict",
            "ops_completed_honestly": True,
            "seeded_defect_seeded": True,
            "seeded_defect_in_case": False,
            "seeded_defect_finding_present": False,
            "seeded_defect_agent_acted": False,
            "final_prose": "seeded defect never appeared in published case",
        }
    )
    assert report["seeded_defect_outcome"] == "missed"
    assert report["seeded_defect_miss_class"] == "case_construction_miss"


def test_defect_in_case_no_finding_is_checker_or_reviewer_miss() -> None:
    report = classify_influence_report(
        {
            "activation": "session_ops",
            "experiment_profile": "policy",
            "semantic_status": "succeeded",
            "semantic_provenance_present": True,
            "ops_completed_honestly": True,
            "seeded_defect_seeded": True,
            "seeded_defect_in_case": True,
            "seeded_defect_finding_present": False,
            "seeded_defect_agent_acted": False,
            "final_prose": "defect present; no finding",
        }
    )
    assert report["seeded_defect_outcome"] == "missed"
    assert report["seeded_defect_miss_class"] == "checker_or_reviewer_miss"


def test_finding_present_no_agent_action_is_agent_response_miss() -> None:
    report = classify_influence_report(
        {
            "activation": "session_ops",
            "experiment_profile": "strict",
            "ops_completed_honestly": True,
            "findings_deterministic": 1,
            "findings_ignored": 1,
            "seeded_defect_seeded": True,
            "seeded_defect_in_case": True,
            "seeded_defect_finding_present": True,
            "seeded_defect_agent_acted": False,
            "attributions": [],
            "final_prose": "valid finding; agent ignored it",
        }
    )
    assert report["seeded_defect_outcome"] == "missed"
    assert report["seeded_defect_miss_class"] == "agent_response_miss"
    assert report["work_product_influence"] == "not_demonstrated"
    assert report["stream_d"] == "not_demonstrated"


def test_receipt_wording_change_only_is_honesty_influence_not_stream_d() -> None:
    report = classify_influence_report(
        {
            "activation": "session_ops",
            "experiment_profile": "strict",
            "ops_completed_honestly": True,
            "plan_before_first_source_edit": True,
            "obligation_before_first_source_edit": True,
            "valid_plan_ms": 10,
            "first_obligation_ms": 20,
            "first_source_edit_ms": 100,
            "receipt_wording_changed_for_honesty": True,
            "attributions": [
                {
                    "finishup_output_ref": "receipt_1",
                    "agent_decision_before": "overclaimed_coverage",
                    "bounded_action_after": "receipt_wording_only",
                    "recheck_result": "not_applicable",
                    "counterfactual": "no",
                }
            ],
            "final_prose": "Receipt wording adjusted for honesty; work product unchanged.",
        }
    )
    assert report["honesty_influence"] == "yes"
    assert report["work_product_influence"] == "not_demonstrated"
    assert report["stream_d"] == "not_demonstrated"
    assert report["material_revisions_attributable_to_finishup"] == 0
    assert report["forbidden_summary_violation"] is False


def test_policy_failed_semantic_is_indeterminate_not_poor_quality() -> None:
    report = classify_influence_report(
        {
            "activation": "session_ops",
            "experiment_profile": "policy",
            "semantic_status": "failed",
            "semantic_provenance_present": True,
            "ops_completed_honestly": True,
            "final_prose": "AI-powered review attempt indeterminate",
        }
    )
    assert report["stream_c"] == "indeterminate"
    assert report["semantic_scoring_eligible"] is False
