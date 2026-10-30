"""#1245 (owner decision D22): obligation and claim rows survive packet narrowing.

In TB4 full-sol (atrx-vep-crispr a5) no obligation or claim text reached the closing reviewer,
while decisions did: the first capacity narrowing dropped goal, obligation and claim rows, and the
acknowledged-obligation question still named obligations the packet no longer carried. The
narrowing now drops the agent's goal and history first, then excerpt bytes, and drops obligation
and claim rows only when no plan that keeps them fits. The question names only carried rows.
"""

from __future__ import annotations

import re

from builders.policy_cases import (
    claim_record,
    clm,
    make_case,
    obl,
    obligation_record,
    plan_record,
)
from finishup.application.semantic_case import (
    ACKNOWLEDGED_REVIEW_INSTRUCTION,
    build_semantic_case,
    primary_material_selection,
    review_question_set,
    semantic_case_to_prepared_payload,
)
from finishup.domain.events import (
    ClaimKind,
    ClaimRecordedPayload,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
)
from finishup.domain.privacy import ReviewContextProfile, ReviewSelectionPolicy
from finishup.kernel.deterministic_checks import DeterministicCase
from finishup.ports.semantic import SemanticCase

_SELECTION = ReviewSelectionPolicy.for_profile(ReviewContextProfile.GOAL_AWARE)
_ID = re.compile(r"obl_[0-9a-f-]{36}")


def _case() -> DeterministicCase:
    acknowledged = (obl(1), obl(2))
    obligations = {
        number: obligation_record(
            ObligationPublishedPayload(
                number,
                "Write the variant report " * 3,
                "One row per qualifying variant",
                ObligationStatus.ACKNOWLEDGED_NOT_DONE
                if number in acknowledged
                else ObligationStatus.OPEN,
                acknowledged_not_done_reason=(
                    "Two supplied references disagree." if number in acknowledged else None
                ),
            ),
            10 + index,
        )
        for index, number in enumerate((obl(1), obl(2), obl(3)))
    }
    plan = PlanPublishedPayload(
        1, "Plan prose the reviewer can do without. " * 120, tuple(obligations)
    )
    claim = ClaimRecordedPayload(
        clm(1),
        ClaimKind.MATERIAL,
        "The report generator is written.",
        (),
        obligation_refs=(obl(3),),
    )
    return make_case(
        plans={1: plan_record(plan, 2)},
        obligations=obligations,
        claims={clm(1): claim_record(claim, 20)},
    )


def _build(
    case: DeterministicCase,
    selection: ReviewSelectionPolicy = _SELECTION,
    ceiling: int | None = None,
) -> SemanticCase:
    return build_semantic_case(
        case_id="cas_10000000-0000-4000-8000-000000000001",
        frozen_case=case,
        dependency_digest="sha256:" + "b" * 64,
        findings=(),
        review_context_profile=ReviewContextProfile.GOAL_AWARE,
        review_selection=selection,
        policy_id="pvy_10000000-0000-4000-8000-000000000001",
        policy_version="1",
        final_review=True,
        prepared_byte_ceiling=ceiling,
    )


def _size(case: SemanticCase) -> int:
    return len(semantic_case_to_prepared_payload(case, {item.item_id for item in case.items}))


def _cited(case: SemanticCase) -> set[str]:
    return {match for question in case.question_set for match in _ID.findall(question)}


def test_the_first_narrowing_keeps_obligation_and_claim_rows() -> None:
    narrowed = primary_material_selection(_SELECTION)
    assert {"obligations", "claims"} <= set(narrowed.sections)
    assert "goal" not in narrowed.sections and "timeline" not in narrowed.sections
    legacy = primary_material_selection(_SELECTION, keep_agent_account=False)
    assert not {"goal", "obligations", "claims"} & set(legacy.sections)


def test_a_narrowed_packet_carries_obligations_and_claims_and_drops_the_goal_first() -> None:
    case = _case()
    full = _build(case)
    assert full.packet.goal_item_ids and len(full.packet.obligation_item_ids) == 3
    # The planner keeps a 4 KiB reserve below the ceiling, so this narrows an over-plan case.
    narrowed = _build(case, ceiling=_size(full) + 4_096 - 1)
    assert narrowed.packet.goal_item_ids == ()
    assert narrowed.packet.obligation_item_ids == full.packet.obligation_item_ids
    assert narrowed.packet.claim_item_ids == full.packet.claim_item_ids
    question = narrowed.question_set[-1]
    assert "Obligations acknowledged as not done: " + ", ".join((str(obl(1)), str(obl(2)))) in (
        question
    )
    assert ACKNOWLEDGED_REVIEW_INSTRUCTION in question
    assert "not in this packet" not in question


def test_the_acknowledged_question_cites_only_obligations_the_packet_carries() -> None:
    case = _case()
    for selection in (_SELECTION, primary_material_selection(_SELECTION, keep_agent_account=False)):
        built = _build(case, selection)
        carried = {item.item_id for item in built.items}
        for ref in _cited(built):
            assert f"obligation-{ref}" in carried, ref
    # When the packet carries no obligation rows the question counts them and names none.
    bare = _build(case, primary_material_selection(_SELECTION, keep_agent_account=False))
    assert bare.packet.obligation_item_ids == () and _cited(bare) == set()
    assert bare.question_set[-1] == (
        "2 obligations acknowledged as not done are not in this packet: do not quote or judge "
        "them; state that limit in review_summary."
    )


def test_the_question_set_names_carried_rows_and_counts_the_rest() -> None:
    carried = str(obl(1))
    question = review_question_set("final", (), (carried,), acknowledged_not_carried=1)[-1]
    assert question.startswith(f"Obligations acknowledged as not done: {carried}. ")
    assert question.endswith(
        " 1 more acknowledged as not done is not in this packet: do not quote or judge it; state "
        "that limit in review_summary."
    )
    one = review_question_set("final", (), (), acknowledged_not_carried=1)[-1]
    assert one.startswith("1 obligation acknowledged as not done is not in this packet")
    # The routine phase still asks nothing about acknowledgements.
    assert review_question_set("routine", (), (), acknowledged_not_carried=1) == (
        review_question_set("routine")
    )


def test_the_service_planner_keeps_them_and_drops_them_only_as_a_last_resort() -> None:
    """The review composition plans the exact exchange through ``plan_under_channel_ceiling``."""

    from finishup.service.semantic_ceiling import (
        plan_under_channel_ceiling,
        with_ceiling_planning_gap,
    )

    case = _case()

    def build(selection: ReviewSelectionPolicy) -> SemanticCase:
        return build_semantic_case(
            case_id="cas_10000000-0000-4000-8000-000000000001",
            frozen_case=case,
            dependency_digest="sha256:" + "b" * 64,
            findings=(),
            review_context_profile=ReviewContextProfile.GOAL_AWARE,
            review_selection=selection,
            policy_id="pvy_10000000-0000-4000-8000-000000000001",
            policy_version="1",
            final_review=True,
            captured_content_gaps=with_ceiling_planning_gap(()),
        )

    full = build(_SELECTION)
    planned, selection, rounds = plan_under_channel_ceiling(
        full, _SELECTION, _size(full) - 1, build
    )
    assert rounds == 1 and {"obligations", "claims"} <= set(selection.sections)
    assert planned.packet.obligation_item_ids == full.packet.obligation_item_ids
    assert planned.packet.goal_item_ids == ()
    assert _size(planned) < _size(full)
    # Below what the obligation rows need, the last-resort round drops them, as before #1245.
    legacy = build(primary_material_selection(_SELECTION, keep_agent_account=False))
    planned, selection, rounds = plan_under_channel_ceiling(full, _SELECTION, _size(legacy), build)
    assert rounds == 2 and not {"goal", "obligations", "claims"} & set(selection.sections)
    assert planned.packet.obligation_item_ids == () and _size(planned) <= _size(legacy)
    carried = {item.item_id for item in planned.items}
    assert all(f"obligation-{ref}" in carried for ref in _cited(planned))
