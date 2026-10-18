"""Human check rendering preserves preview and advisory boundaries."""

from __future__ import annotations

import pytest

from finishup.cli.render import render_human_check
from finishup.protocol.models import (
    CheckAdvisoryNoteModel,
    CheckChildrenPreviewModel,
    CheckMissingItemModel,
    CheckOverallNextModel,
    CheckSuccessModel,
    CoverageModel,
)


@pytest.mark.parametrize("label", ["recorded", "preview"])
def test_check_keeps_child_facts_and_project_advice_outside_findings(label: str) -> None:
    child = "tsk_59000000-0000-4000-8000-000000000002"
    project = "prj_59000000-0000-4000-8000-000000000001"
    # This pure renderer consumes an already projected result. Wire acceptance is exercised by
    # the public workflow and model suites; only the fields it reads are constructed here.
    result = CheckSuccessModel.model_construct(
        verdict="insufficient_coverage",
        semantic_status="not_requested",
        semantic_reason="deterministic_mode",
        findings=(),
        suppressed_count="0",
        coverage=CoverageModel.model_construct(known_gaps=()),
        children=CheckChildrenPreviewModel.model_validate(
            {
                "label": label,
                "tested_manifest_frontier": {"sequence": "7", "head_digest": "sha256:" + "a" * 64},
                "items": [
                    {
                        "child_task_id": child,
                        "origin": "self_registered",
                        "acceptance": "pending",
                        "work_state": "open",
                        "session_health": "contact_lost",
                        "rollup_state": "annotation",
                        "blocking_conditions": [],
                    }
                ],
            }
        ),
        advisory_notes=(
            CheckAdvisoryNoteModel.model_validate(
                {
                    "kind": "live_member_present",
                    "project_id": project,
                    "task_ids": [child],
                    "count": "1",
                }
            ),
        ),
    )

    rendered = render_human_check(result)
    assert rendered.startswith("Verdict: insufficient_coverage\n")
    assert "Findings: none\n" in rendered
    assert f"Child dependencies ({label}):" in rendered
    assert f"{child}: self_registered, pending; work open, session contact_lost" in rendered
    assert "Tested manifest frontier: 7" in rendered
    assert ("Preview facts do not change the recorded check." in rendered) == (label == "preview")
    assert "Project advice (does not affect the verdict):" in rendered
    assert f"live_member_present: 1; project {project}; tasks {child}" in rendered


def test_check_lists_named_missing_items_as_a_limitation_not_a_finding() -> None:
    """Issue #907: the CLI names what an unassessable review needed and who can supply it."""

    claim = "clm_59000000-0000-4000-8000-000000000001"
    result = CheckSuccessModel.model_construct(
        verdict="insufficient_coverage",
        semantic_status="succeeded",
        semantic_reason="semantic_completed",
        findings=(),
        suppressed_count="0",
        coverage=CoverageModel.model_construct(
            known_gaps=("semantic_missing_agent_suppliable", "semantic_packet_insufficient")
        ),
        children=None,
        advisory_notes=(),
        overall_next=CheckOverallNextModel.model_validate(
            {
                "action": "supply_missing_input",
                "status": "action_required",
                "target_refs": [claim],
            }
        ),
        missing_for_assessment=(
            CheckMissingItemModel.model_validate(
                {
                    "kind": "command_identity",
                    "target_refs": [],
                    "availability": "structurally_unavailable_on_this_host",
                }
            ),
            CheckMissingItemModel.model_validate(
                {
                    "kind": "verification_output",
                    "target_refs": [claim],
                    "availability": "agent_suppliable",
                }
            ),
        ),
    )
    rendered = render_human_check(result)
    assert "Findings: none\n" in rendered
    assert "Missing for assessment (the reviewer could not assess the packet):" in rendered
    assert f"- verification_output ({claim}): agent_suppliable" in rendered
    assert "- command_identity (no packet ref): structurally_unavailable_on_this_host" in rendered
    assert "publish exactly that item once, linked to its target, then `check` again" in rendered
    # W6: the instruction names the field that links the result to the target.
    assert "result_recorded whose action_id is the target's action and whose summary" in rendered
    assert (
        "Overall next [action_required]: If `missing_for_assessment` names an `agent_suppliable` "
        "item you can supply, publish exactly that item once, linked to its target, then `check` "
        f"again. If it is already supplied, or it is a packet, type or authority limit, go to the "
        f"receipt and state that specific limit. Never change your work to fit the reviewer "
        f"(targets: {claim})." in rendered
    )


def test_check_labels_finding_only_next_when_input_repair_is_required() -> None:
    """Issue #963: the findings checklist cannot outrank an actionable review-input gap."""

    claim = "clm_59000000-0000-4000-8000-000000000011"
    from finishup.protocol.models import CheckFindingChecklistModel

    checklist = CheckFindingChecklistModel.model_validate(
        {
            "attempt_budget": "2",
            "counts": {
                "acknowledged_not_done": "0",
                "open": "0",
                "open_at_budget": "0",
                "rejection_accepted": "0",
                "self_verified": "0",
                "verified_resolved": "0",
            },
            "next": "request_receipt",
            "items": [],
        }
    )
    result = CheckSuccessModel.model_construct(
        verdict="insufficient_coverage",
        semantic_status="succeeded",
        semantic_reason="semantic_completed",
        findings=(),
        suppressed_count="0",
        coverage=CoverageModel.model_construct(known_gaps=("semantic_missing_agent_suppliable",)),
        children=None,
        advisory_notes=(),
        finding_checklist=checklist,
        missing_for_assessment=(
            CheckMissingItemModel.model_validate(
                {
                    "kind": "verification_output",
                    "target_refs": [claim],
                    "availability": "agent_suppliable",
                }
            ),
        ),
    )

    rendered = render_human_check(result)
    assert (
        "Finding checklist next: No open findings remain on the list; request the receipt."
        in rendered
    )
    assert "publish exactly that item once, linked to its target, then `check` again" in rendered


def test_check_labels_structural_limitations_as_disclosure_at_receipt() -> None:
    """Issue #963: a standing limitation is disclosed, not presented as repair work."""

    result = CheckSuccessModel.model_construct(
        verdict="insufficient_coverage",
        semantic_status="succeeded",
        semantic_reason="semantic_completed",
        findings=(),
        suppressed_count="0",
        coverage=CoverageModel.model_construct(known_gaps=("unsupported_event",)),
        children=None,
        advisory_notes=(),
        overall_next=CheckOverallNextModel.model_validate(
            {
                "action": "request_receipt",
                "status": "ready_with_limitations",
                "target_refs": [],
                "acknowledged_incomplete_endpoint": "receipt",
            }
        ),
    )

    rendered = render_human_check(result)
    assert (
        "Overall next [ready_with_limitations]: Disclose the limitation at the receipt endpoint; "
        "acknowledged incomplete endpoint: receipt."
    ) in rendered


def test_check_renders_recorded_work_continuation_with_bounded_targets() -> None:
    obligation = "obl_59000000-0000-4000-8000-000000000001"
    result = CheckSuccessModel.model_construct(
        verdict="insufficient_coverage",
        semantic_status="not_requested",
        semantic_reason="deterministic_mode",
        findings=(),
        suppressed_count="0",
        coverage=CoverageModel.model_construct(known_gaps=()),
        children=None,
        advisory_notes=(),
        overall_next=CheckOverallNextModel.model_validate(
            {
                "action": "review_recorded_work",
                "status": "action_required",
                "target_refs": [obligation],
            }
        ),
    )

    rendered = render_human_check(result)

    assert (
        "Overall next [action_required]: Review the recorded work for open obligations or "
        f"undisclosed failures (targets: {obligation})."
    ) in rendered


def test_check_renders_the_finding_checklist_with_structural_tokens_only() -> None:
    """Issue #905: ``[ ] F-1 ... open (2/2)`` lines and one closed "Next:" sentence."""

    from finishup.protocol.models import CheckFindingChecklistModel

    checklist = CheckFindingChecklistModel.model_validate(
        {
            "attempt_budget": "2",
            "counts": {
                "acknowledged_not_done": "1",
                "open": "1",
                "open_at_budget": "1",
                "rejection_accepted": "0",
                "self_verified": "0",
                "verified_resolved": "1",
            },
            "next": "decide_at_budget",
            "items": [
                {
                    "finding_id": "fnd_59000000-0000-4000-8000-000000000001",
                    "todo_state": "open",
                    "review_rounds": "2",
                },
                {
                    "finding_id": "fnd_59000000-0000-4000-8000-000000000002",
                    "todo_state": "verified_resolved",
                    "review_rounds": "0",
                },
                {
                    "finding_id": "fnd_59000000-0000-4000-8000-000000000003",
                    "todo_state": "acknowledged_not_done",
                    "review_rounds": "1",
                },
            ],
        }
    )
    result = CheckSuccessModel.model_construct(
        verdict="no_issue_detected",
        semantic_status="not_requested",
        semantic_reason="deterministic_mode",
        findings=(),
        suppressed_count="0",
        coverage=CoverageModel.model_construct(known_gaps=()),
        children=None,
        advisory_notes=(),
        finding_checklist=checklist,
    )
    rendered = render_human_check(result)
    assert "To-do list (review-round budget 2):" in rendered
    assert "- [ ] F-1 fnd_59000000-0000-4000-8000-000000000001 open (2/2)" in rendered
    assert "- [x] F-2 fnd_59000000-0000-4000-8000-000000000002 verified_resolved" in rendered
    assert "- [~] F-3 fnd_59000000-0000-4000-8000-000000000003 acknowledged_not_done" in rendered
    assert "Next: An open finding reached the review-round budget" in rendered
    assert "Counts: open 1 (1 at budget), verified 1, not done 1, rejection accepted 0" in rendered
    assert "Not listed:" not in rendered


def test_check_checklist_says_how_many_items_the_list_leaves_out() -> None:
    from finishup.protocol.models import CheckFindingChecklistModel

    checklist = CheckFindingChecklistModel.model_validate(
        {
            "attempt_budget": "5",
            "counts": {
                "acknowledged_not_done": "0",
                "open": "1",
                "open_at_budget": "0",
                "rejection_accepted": "0",
                "self_verified": "0",
                "verified_resolved": "101",
            },
            "next": "work_open_findings",
            "items": [
                {
                    "finding_id": "fnd_59000000-0000-4000-8000-000000000101",
                    "todo_state": "open",
                    "review_rounds": "0",
                }
            ],
        }
    )
    result = CheckSuccessModel.model_construct(
        verdict="action_required",
        semantic_status="not_requested",
        semantic_reason="deterministic_mode",
        findings=(),
        suppressed_count="0",
        coverage=CoverageModel.model_construct(known_gaps=()),
        children=None,
        advisory_notes=(),
        finding_checklist=checklist,
    )
    rendered = render_human_check(result)
    assert "Counts: open 1, verified 101, not done 0, rejection accepted 0" in rendered
    assert "Not listed: 101" in rendered


def _limit_checklist(next_step: str, bases: tuple[tuple[str, str], ...]) -> object:
    from finishup.protocol.models import CheckFindingChecklistModel

    items = [
        {
            "finding_id": f"fnd_59000000-0000-4000-8000-{index:012d}",
            "todo_state": "open",
            "review_rounds": "0",
            "closure_class": "agent_work",
            "closure_basis": basis,
        }
        for index, (_name, basis) in enumerate(bases, start=1)
    ]
    to_disclose = sum(basis == "limitation_requested" for _name, basis in bases)
    return CheckFindingChecklistModel.model_validate(
        {
            "attempt_budget": "5",
            "counts": {
                "acknowledged_not_done": "0",
                "open": str(len(items)),
                "open_at_budget": "0",
                "rejection_accepted": "0",
                "self_verified": "0",
                "verified_resolved": "0",
                "to_do": str(len(items) - to_disclose),
                "awaiting_ruling": "0",
                "unmet": "0",
                "disclosed": "0",
                "to_disclose": str(to_disclose),
            },
            "next": next_step,
            "items": items,
        }
    )


def _limit_result(next_step: str, action: str, bases: tuple[tuple[str, str], ...]) -> object:
    checklist = _limit_checklist(next_step, bases)
    return CheckSuccessModel.model_construct(
        verdict="insufficient_coverage",
        semantic_status="succeeded",
        semantic_reason="semantic_completed",
        findings=(),
        suppressed_count="0",
        coverage=CoverageModel.model_construct(known_gaps=()),
        children=None,
        advisory_notes=(),
        finding_checklist=checklist,
        overall_next=CheckOverallNextModel.model_validate(
            {
                "action": action,
                "status": "action_required",
                "target_refs": [
                    f"fnd_59000000-0000-4000-8000-{index:012d}"
                    for index in range(1, len(bases) + 1)
                ],
            }
        ),
    )


def test_a_limitation_request_alone_is_worded_as_a_disclosure_on_both_continuations() -> None:
    """Owner decision 2026-10-12: ``disclose_limitations`` says how the answer decides its meaning."""

    rendered = render_human_check(
        _limit_result(
            "disclose_limitations",
            "disclose_limitations",
            (("a", "limitation_requested"),),
        )  # type: ignore[arg-type]
    )
    assert rendered.count("Disclose the named limitation requests") == 2
    assert "acknowledged_not_done only when you know it is not met" in rendered
    assert "Repair" not in rendered


def test_a_limitation_request_beside_real_work_names_both_in_the_work_continuation() -> None:
    rendered = render_human_check(
        _limit_result(
            "work_open_findings",
            "work_open_findings",
            (("a", "limitation_requested"), ("b", "open_unanswered")),
        )  # type: ignore[arg-type]
    )
    assert "Repair the open findings (or answer the reviewer's questions), then check again." in (
        rendered
    )
    assert "For a reviewer's request to state a limit, respond acknowledged with the reason" in (
        rendered
    )
    assert "Repair or answer the named open findings (a limitation request among them" in rendered
    assert "Disclose the named limitation requests" not in rendered
    # Without a limitation request the work continuation carries no such sentence.
    plain = render_human_check(
        _limit_result("work_open_findings", "work_open_findings", (("a", "open_unanswered"),))  # type: ignore[arg-type]
    )
    assert "state a limit" not in plain and "limitation request" not in plain


def test_the_agents_own_criterion_is_worded_as_fix_or_narrow_never_no_repair() -> None:
    """Review of #1043: an open ``agent_criterion_unmet`` reads ``limitation_requested`` but the
    check continues with ``work_open_findings``; both texts say fix it or narrow it, never that no
    repair is needed (the rows carry no kind, so the reviewer's request is named beside it)."""

    rendered = render_human_check(
        _limit_result(
            "work_open_findings",
            "work_open_findings",
            (("a", "limitation_requested"),),
        )  # type: ignore[arg-type]
    )
    assert rendered.count("fix it, or narrow it with acknowledged and a reason") == 2
    assert "agent_criterion_unmet is your own criterion" in rendered
    assert "no repair is needed" not in rendered.lower()
    assert "Disclose the named limitation requests" not in rendered
