"""One table of what each gap code does to a receipt (tb4n3 RC-3, issue #1026, ADR-046).

The 180 unchanged rows must keep today's behaviour under both routes; the 39 changed rows are
named here, each with its rule, so a reviewer reads exactly which codes the round re-labels.
tb4n4: ``deliverable_references_undeclared_file`` became agent work (#1044, changed);
``semantic_review_deferred_before_first_edit`` (issue #1046) follows the recorded route like the
``semantic_review_not_requested`` it rides with (disclosed where the route did not require review,
bounding where it did), so it is listed as changed; ``semantic_process_state_filtered`` (issue
#1042) is disclosed from the start, so it is listed as changed.
"""

from __future__ import annotations

import pytest

from finishup.kernel.closure_readiness import GAP_CLASSIFICATION, GapClass
from finishup.kernel.finding_resolution import DETERMINISTIC_PROOF_TOLERATED_GAPS
from finishup.kernel.gap_effect import (
    GAP_EFFECT_TABLE,
    GAP_EFFECT_WHY,
    PROOF_TOLERATED_GAPS,
    UNCLASSIFIED_GAP_PREFIX,
    GapContext,
    GapEffectKind,
    gap_base_code,
    gap_effect,
    judge_gaps,
)

# The gaps a clean deterministic conclusion could carry before the table (``CLEAN_COMPATIBLE_GAPS`` at
# 26e9cecf, plus the two standing task-fact disclosures tb4n3 LF added at 51169693d), frozen here so
# the table is checked against the behaviour it replaces, not against itself.
_CLEAN_COMPATIBLE_AT_BASE = frozenset(
    {
        "capture_handoff_retired",
        "captured_object_unavailable",
        "content_redacted",
        "content_unselected",
        "declared_output_content_moved",
        "declared_output_not_reviewable",
        "deliverable_references_undeclared_file",
        "host_outcome_unavailable",
        "install_into_private_env",
        "install_into_yoetz_runtime",
        "obligation_blocked_outside_agent_control",
        "obligation_evidence_stale_after_scope_edit",
        "plan_unrefined_before_first_edit",
        "planned_verification_agent_linked",
        "planned_verification_matched_by_prefix",
        "planned_verification_outcome_unknown",
        "planned_verification_unobservable",
        "preexisting_test_deleted",
        "preexisting_test_modified",
        "preexisting_test_renamed",
        "preexisting_test_skipped",
        "requested_output_ignored_by_repository",
        "requested_output_outside_workspace",
        "requested_output_unchanged",
        "requested_output_unverified",
        "unpaired_event",
        "verification_only_as_root",
        "write_outside_workspace",
    }
)
_GUARDED_AT_BASE = frozenset(
    {"captured_object_unavailable", "host_outcome_unavailable", "unpaired_event"}
)
# Readiness-only tokens synthesized by status, never recorded as coverage gaps.
_READINESS_ONLY = frozenset(
    {
        "assumption_disclosed",
        "verification_limit_disclosed",
        "finding_self_verified",
        "finding_disputed_after_rebuttal",
        "finding_premise_disputed",
        "finding_rejection_awaiting_ruling",
        "finding_limitation_disclosed",
        "finding_rejection_unreviewable",
    }
)
_CHANGED = frozenset(
    {
        "semantic_review_not_requested",
        "check_current_as_of_earlier_frontier",
        "compound_outcome_unavailable",
        "check_time_change_truncated",
        "check_time_change_unavailable_no_packet_room",
        "semantic_case_capacity_exceeded",
        "semantic_case_content_over_item_limit",
        "semantic_case_finding_refs_over_limit",
        "semantic_included_refs_not_recorded",
        "semantic_reference_scope_reduced",
        "semantic_review_refs_reduced",
        "advice_coverage_gaps_truncated",
        "advice_evidence_refs_truncated",
        "advice_ranked_findings_truncated",
        "advice_semantic_deferred",
        "advice_semantic_output_invalid",
        "advice_semantic_pending",
        # tb4n5 (#1019 r2): background advice skipped under a preview-required policy.
        "advice_semantic_preview_required",
        "advice_semantic_text_truncated",
        "advice_semantic_unavailable",
        "observation_qualified_partial",
        "details_truncated",
        "optional_observation_detail_omitted",
        "routine_read_detail_omitted",
        "routine_read_summary_invalid",
        "routine_summary_invalid",
        "semantic_prior_findings_over_limit",
        "semantic_prior_verdicts_unsupported",
        "semantic_restatements_suppressed",
        "semantic_process_state_filtered",
        "semantic_review_credential_heuristic_disabled",
        "semantic_review_value_redacted",
        "semantic_review_snippet_invalid",
        "optional_semantic_review_blocked_by_policy",
        "optional_semantic_review_registration_drift",
        "semantic_relevance_review_not_run",
        "semantic_review_not_configured",
        # tb4n4 (#1044): a disclosure that is now agent work (rule G0c).
        "deliverable_references_undeclared_file",
        # tb4n4 (#1046, review): FinishUP's own deferral is disclosed where review is not required.
        "semantic_review_deferred_before_first_edit",
        # tb4n5 (#1044 follow-up): a new disclosure, counted on the receipt, never agent work.
        "deliverable_references_ambiguous_name",
    }
)
_CARRIED = frozenset(_GUARDED_AT_BASE)


def test_the_classification_is_a_view_of_the_table_with_the_same_readiness_group() -> None:
    assert set(GAP_EFFECT_TABLE) == set(GAP_CLASSIFICATION)
    # The 218 recorded codes (#1040 follow-up added check_time_change_unavailable_git_version_
    # unsupported beside its G7 siblings; the #1044 follow-up added
    # deliverable_references_ambiguous_name; #1019 r2 added advice_semantic_preview_required)
    # + 3 readiness-only finding tokens.
    assert len(GAP_EFFECT_TABLE) == 221
    for code, group in GAP_CLASSIFICATION.items():
        assert GAP_EFFECT_TABLE[code].readiness is group, code
    assert {row.why for row in GAP_EFFECT_TABLE.values()} <= set(GAP_EFFECT_WHY)


def test_exactly_the_documented_rows_are_marked_changed() -> None:
    changed = {code for code, row in GAP_EFFECT_TABLE.items() if row.changed}
    assert changed == _CHANGED
    assert len(changed) == 40


@pytest.mark.parametrize("route_requires_review", [False, True])
def test_unchanged_rows_keep_the_behaviour_of_the_base_build(route_requires_review: bool) -> None:
    context = GapContext(route_requires_review=route_requires_review, check_carried=_CARRIED)
    drift: list[str] = []
    for code, row in GAP_EFFECT_TABLE.items():
        if row.changed or code in _READINESS_ONLY:
            continue
        bounded_at_base = code not in _CLEAN_COMPATIBLE_AT_BASE
        if gap_effect(code, context).kind.bounds != bounded_at_base:
            drift.append(code)
    assert drift == []


def test_proof_tolerance_is_one_set_not_a_third_table() -> None:
    assert PROOF_TOLERATED_GAPS == DETERMINISTIC_PROOF_TOLERATED_GAPS


def test_actionable_rows_are_exactly_the_agent_actionable_group() -> None:
    for code, row in GAP_EFFECT_TABLE.items():
        if row.readiness is GapClass.AGENT_ACTIONABLE:
            assert gap_effect(code).kind is GapEffectKind.ACTIONABLE, code
        elif row.readiness is GapClass.STANDING_LIMITATION:
            assert gap_effect(code).kind is not GapEffectKind.ACTIONABLE, code


def test_the_review_not_requested_gap_follows_the_recorded_route() -> None:
    code = "semantic_review_not_requested"
    assert gap_effect(code, GapContext(route_requires_review=False)).kind is (
        GapEffectKind.DISCLOSED
    )
    required = GapContext(route_requires_review=True, review_required=True)
    assert gap_effect(code, required).kind is GapEffectKind.ACTIONABLE
    current = GapContext(route_requires_review=True, review_required=True, review_current=True)
    assert gap_effect(code, current).kind is GapEffectKind.STANDING_BOUNDING
    # An absent recorded route (the default) keeps the missing review bounding.
    assert gap_effect(code).kind is GapEffectKind.STANDING_BOUNDING


def test_the_review_deferral_follows_the_recorded_route_like_the_missing_review() -> None:
    """Issue #1046 (review): a deferral never reads worse than ``deterministic_only`` would.

    Where the deferred check recorded that its route did not require review, the deferral is a
    disclosure exactly like the ``semantic_review_not_requested`` it rides with; where the route
    requires review (or the route is unknown) it bounds, and it is never agent work: the closing
    review, not a routine check, supplies the review.
    """

    code = "semantic_review_deferred_before_first_edit"
    optional = GapContext(route_requires_review=False)
    assert gap_effect(code, optional).kind is GapEffectKind.DISCLOSED
    assert gap_effect("semantic_review_not_requested", optional).kind is GapEffectKind.DISCLOSED
    for context in (
        GapContext(),
        GapContext(route_requires_review=True, review_required=True),
        GapContext(route_requires_review=True, review_required=True, review_current=True),
    ):
        assert gap_effect(code, context).kind is GapEffectKind.STANDING_BOUNDING
    assert GAP_EFFECT_TABLE[code].rule == "G7"


def test_the_earlier_frontier_gap_is_never_actionable() -> None:
    code = "check_current_as_of_earlier_frontier"
    assert gap_effect(code, GapContext(earlier_frontier_bounds=True)).kind is (
        GapEffectKind.STANDING_BOUNDING
    )
    assert gap_effect(code, GapContext(earlier_frontier_bounds=False)).kind is (
        GapEffectKind.DISCLOSED
    )


def test_host_observation_gaps_are_disclosed_only_while_the_check_carried_them() -> None:
    for code in ("host_outcome_unavailable", "unpaired_event", "compound_outcome_unavailable"):
        carried = GapContext(check_carried=frozenset({code}))
        assert gap_effect(code, carried).kind is GapEffectKind.DISCLOSED
        assert gap_effect(code, GapContext()).kind is GapEffectKind.STANDING_BOUNDING
        incomplete = GapContext(check_carried=frozenset({code}), commands_complete=False)
        assert gap_effect(code, incomplete).kind is GapEffectKind.STANDING_BOUNDING


def test_a_finishup_review_budget_bounds_only_when_the_reviewer_reported_it_could_not_assess() -> (
    None
):
    for code in ("check_time_change_truncated", "semantic_reference_scope_reduced"):
        clean = GapContext(route_requires_review=True, review_succeeded=True)
        assert gap_effect(code, clean).kind is GapEffectKind.DISCLOSED
        insufficient = GapContext(
            route_requires_review=True,
            review_succeeded=True,
            reviewer_reported_insufficiency=True,
        )
        assert gap_effect(code, insufficient).kind is GapEffectKind.STANDING_BOUNDING
        assert gap_effect(code, GapContext(route_requires_review=True)).kind is (
            GapEffectKind.STANDING_BOUNDING
        )
        assert gap_effect(code, GapContext(route_requires_review=False)).kind is (
            GapEffectKind.DISCLOSED
        )


def test_evidence_digest_only_stays_bounding_on_both_routes() -> None:
    for required in (False, True):
        context = GapContext(route_requires_review=required, review_succeeded=True)
        assert gap_effect("evidence_content_digest_only", context).kind is (
            GapEffectKind.STANDING_BOUNDING
        )


def test_a_cleared_historical_gap_never_bounds() -> None:
    context = GapContext(historical=frozenset({"truncated_payload"}))
    assert gap_effect("truncated_payload", context).kind is GapEffectKind.HISTORICAL
    assert not GapEffectKind.HISTORICAL.bounds


def test_unknown_codes_stay_visible_and_actionable() -> None:
    effect = gap_effect("code_from_a_newer_build")
    assert effect.kind is GapEffectKind.ACTIONABLE
    assert effect.code == UNCLASSIFIED_GAP_PREFIX + "code_from_a_newer_build"
    assert gap_effect("Not A Code!").code == UNCLASSIFIED_GAP_PREFIX + "unreadable_gap_code"


def test_wrapped_markers_classify_by_their_base_code() -> None:
    assert gap_base_code("check_coverage:content_unselected") == "content_unselected"
    assert gap_base_code("lineage:lineage_child_open:tsk_x:evt_y") == "lineage_child_open"
    assert gap_base_code("unknown_event:evt_1") == "unknown_event"
    assert gap_effect("retained_finding_coverage:content_unselected").kind is (
        GapEffectKind.DISCLOSED
    )


def test_judge_gaps_returns_one_sorted_entry_per_code() -> None:
    effects = judge_gaps(
        ["content_unselected", "check_coverage:content_unselected", "ledger_rejected"]
    )
    assert [effect.code for effect in effects] == ["content_unselected", "ledger_rejected"]
    assert [effect.kind for effect in effects] == [
        GapEffectKind.DISCLOSED,
        GapEffectKind.STANDING_BOUNDING,
    ]
