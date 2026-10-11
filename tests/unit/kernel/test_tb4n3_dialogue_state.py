"""tb4n3 RC-1 and RC-7 (issues #1024, #1030): limitation lifecycle, standing position, reverse edges.

Each test is a shape a recorded tb4n3 run produced (ks S, vpp S, payments S, formal-crypto S,
pretrain S, cargo D) or a guard the owner named (G1 to G4), asserted on the pure kernel functions
every surface reads.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from builders.dialogue import (
    LIMITATION,
    answer,
    claim_row,
    limit_decision,
    local_finding,
    obligation_row,
    projection,
    reviewer_finding,
    ruling_check,
)
from builders.policy_cases import clm, evt, finding_record, fnd, obl, res
from yoetz.domain.events import ResponseRecordedPayload
from yoetz.domain.findings import (
    CheckVerdict,
    FindingKind,
    ResponseDisposition,
    finding_demands_work,
    is_limitation_request,
)
from yoetz.kernel.finding_resolution import (
    apply_check_resolution,
    apply_check_rulings,
    finding_is_resolved,
    next_standing_position,
    reopen_findings_resolved_by,
)
from yoetz.kernel.finding_todo import (
    ABSOLUTELY_FINAL_TODO_STATES,
    REOPENABLE_TODO_STATES,
    FindingTodoState,
    finding_blocks_receipt,
    finding_standing,
    finding_todo_state,
    premise_dispute_basis,
    ruling_since,
    standing_answer_frontier,
)
from yoetz.kernel.limitation import (
    DISCLOSED_BY_DECISION,
    DISCLOSED_BY_RESPONSE,
    LIMITATION_REQUESTED,
    limitation_disclosed_ids,
    limitation_requested_ids,
    limitation_standing,
)
from yoetz.kernel.projections import (
    ProjectionState,
    StandingPosition,
    projection_from_snapshot,
    projection_snapshot,
)
from yoetz.kernel.ranking import CheckCompleteness, RankingContext, rank_findings
from yoetz.protocol.coverage import Coverage

D = ResponseDisposition


# --- RC-1: the limitation lifecycle (owner decision Q4) -------------------------------------------


def _ks_state(*responses_for: tuple[int, ResponseDisposition, int]) -> ProjectionState:
    """ks S shape: one reviewer limitation request on the hidden-accuracy obligation."""

    findings = {fnd(1): finding_record(reviewer_finding(1, str(obl(1)), next_step=LIMITATION), 10)}
    responses = {fnd(n): answer(n, disposition, seq) for n, disposition, seq in responses_for}
    return projection(findings, responses, obligations={obl(1): obligation_row(1)})


def _limit_state(state: ProjectionState) -> str:
    standing = limitation_standing(state, fnd(1))
    assert standing is not None
    return standing.state


def test_a_limitation_request_is_a_to_disclose_item_until_one_acknowledgement() -> None:
    requested = _ks_state()
    standing = limitation_standing(requested, fnd(1))
    assert standing is not None
    assert (standing.state, standing.basis, standing.source_event_ids) == (
        LIMITATION_REQUESTED,
        None,
        (),
    )
    # Never repair work and never receipt-blocking work, yet it is still an open, unanswered item.
    payload = requested.findings[fnd(1)].payload
    assert payload is not None
    assert finding_demands_work(payload) is False
    assert finding_blocks_receipt(requested, fnd(1)) is False
    assert finding_todo_state(requested, fnd(1)) is FindingTodoState.OPEN
    assert limitation_requested_ids(requested) == (fnd(1),)
    assert limitation_disclosed_ids(requested) == ()


@pytest.mark.parametrize("disposition", [D.ACKNOWLEDGED, D.ACKNOWLEDGED_NOT_DONE])
def test_one_reasoned_acknowledgement_settles_it_as_a_disclosed_limitation(
    disposition: ResponseDisposition,
) -> None:
    """vpp S and payments S ended every such request ``acknowledged_not_done``: that is the
    disclosure now, not the end of a blocking item."""

    state = _ks_state((1, disposition, 12))
    standing = limitation_standing(state, fnd(1))
    assert standing is not None and standing.disclosed
    assert standing.basis == DISCLOSED_BY_RESPONSE
    assert standing.since_frontier == 12
    assert finding_blocks_receipt(state, fnd(1)) is False
    assert limitation_disclosed_ids(state) == (fnd(1),)


def test_a_rejection_a_bare_acknowledgement_and_a_reopen_do_not_disclose() -> None:
    assert _limit_state(_ks_state((1, D.REJECTED, 12))) == LIMITATION_REQUESTED
    bare = _ks_state()
    bare = replace(bare, responses={fnd(1): answer(1, D.ACKNOWLEDGED, 12, reason=None)})
    assert _limit_state(bare) == LIMITATION_REQUESTED
    # An acknowledged_not_done answer taken back with ``reopened`` is no longer a disclosure.
    reopened = _ks_state((1, D.REOPENED, 14))
    assert _limit_state(reopened) == LIMITATION_REQUESTED


def test_a_verification_limit_decision_on_the_obligation_discloses_it_but_an_assumption_does_not() -> (
    None
):
    base = _ks_state()
    disclosed = replace(base, decisions={evt(30): limit_decision(30, obl(1))})
    standing = limitation_standing(disclosed, fnd(1))
    assert standing is not None and standing.disclosed
    assert (standing.basis, standing.source_event_ids) == (DISCLOSED_BY_DECISION, (evt(30),))
    assumption = replace(
        base,
        decisions={evt(30): limit_decision(30, obl(1), kind="yoetz-assumption")},
    )
    assert _limit_state(assumption) == LIMITATION_REQUESTED
    other = replace(base, decisions={evt(30): limit_decision(30, obl(2))})
    assert _limit_state(other) == LIMITATION_REQUESTED
    superseded = replace(
        base,
        decisions={evt(30): replace(limit_decision(30, obl(1)), superseded_by_event_id=evt(31))},
    )
    assert _limit_state(superseded) == LIMITATION_REQUESTED


def test_g1_an_act_challenge_never_qualifies_even_beside_a_recorded_disclosure() -> None:
    """The reviewer sees an obtainable path, so the agent's own disclosure cannot turn it into a
    limitation (formal-crypto S: every challenge offered an ``act`` branch)."""

    findings = {fnd(1): finding_record(reviewer_finding(1, str(obl(1)), next_step="act"), 10)}
    state = projection(
        findings,
        {},
        obligations={obl(1): obligation_row(1)},
        decisions={evt(30): limit_decision(30, obl(1))},
    )
    payload = findings[fnd(1)].payload
    assert payload is not None
    assert is_limitation_request(payload) is False
    assert finding_demands_work(payload) is True
    assert limitation_standing(state, fnd(1)) is None
    assert finding_blocks_receipt(state, fnd(1)) is True


def test_g2_the_agents_own_could_not_find_it_never_qualifies_pretrain_s() -> None:
    """pretrain S: an ``act`` finding, the agent answered acknowledged_not_done "could not find
    it" and stopped. The acknowledgement re-check must still fire, so nothing may settle it."""

    finding = reviewer_finding(
        1, str(obl(1)), kind=FindingKind.TASK_REQUIREMENT_UNMET, next_step="act"
    )
    findings = {fnd(1): finding_record(finding, 10)}
    giving_up = answer(
        1, D.ACKNOWLEDGED_NOT_DONE, 12, reason="The original payloads or key cannot be found."
    )
    state = projection(findings, {fnd(1): giving_up}, obligations={obl(1): obligation_row(1)})
    assert limitation_standing(state, fnd(1)) is None
    assert finding_todo_state(state, fnd(1)) is FindingTodoState.ACKNOWLEDGED_NOT_DONE
    assert finding_blocks_receipt(state, fnd(1)) is True
    # The reviewer re-raised after the give-up: the standing premise dispute the Stop gate reads.
    reraised = replace(findings[fnd(1)], settled_reraise_count=1)
    disputed = projection({fnd(1): reraised}, {fnd(1): giving_up})
    assert premise_dispute_basis(disputed, fnd(1)) == "give_up_reraised"


def test_g3_a_disclosed_limitation_never_clears_the_emptied_deliverable_fact() -> None:
    """formal-crypto S: the working solver was emptied. A limitation on the same obligation, however
    it is disclosed, is independent of ``declared_output_emptied``, which stays agent-actionable on
    both routes and in the table every surface reads."""

    from yoetz.kernel.gap_effect import GapContext, GapEffectKind, gap_effect
    from yoetz.kernel.task_facts import DECLARED_OUTPUT_EMPTIED_GAP

    for route in (True, False):
        effect = gap_effect(DECLARED_OUTPUT_EMPTIED_GAP, GapContext(route_requires_review=route))
        assert effect.kind is GapEffectKind.ACTIONABLE
    state = _ks_state((1, D.ACKNOWLEDGED, 12))
    standing = limitation_standing(state, fnd(1))
    assert standing is not None and standing.disclosed
    # The class carries no deliverable state at all: it neither reads nor writes the delivered set.
    import inspect

    import yoetz.kernel.limitation as limitation_module

    assert "delivered_set" not in inspect.getsource(limitation_module)


def test_g4_a_limitation_only_check_is_never_clean_and_never_action_required() -> None:
    from builders.policy_cases import BASE_COVERAGE

    request = reviewer_finding(1, str(obl(1)), next_step=LIMITATION)
    coverage: Coverage = request.coverage
    context = RankingContext(coverage, CheckCompleteness.COMPLETE)
    ranked = rank_findings((), (request,), context, 5)
    assert ranked.verdict is CheckVerdict.INSUFFICIENT_COVERAGE
    work = reviewer_finding(2, str(obl(2)), next_step="act")
    mixed = rank_findings(
        (), (request, work), RankingContext(coverage, CheckCompleteness.COMPLETE), 5
    )
    assert mixed.verdict is CheckVerdict.ACTION_REQUIRED
    assert BASE_COVERAGE is not None


def test_a_limitation_request_a_later_check_proved_absent_is_history_not_a_limit() -> None:
    findings = {
        fnd(1): finding_record(
            reviewer_finding(1, str(obl(1)), next_step=LIMITATION),
            10,
            resolved_by_check_event_id=evt(20),
            resolution_frontier=20,
        )
    }
    state = projection(findings, {})
    assert limitation_standing(state, fnd(1)) is None
    assert finding_todo_state(state, fnd(1)) is FindingTodoState.VERIFIED_RESOLVED


# --- RC-7: the standing position (D-2) -------------------------------------------------------------


def _payload(
    disposition: ResponseDisposition, reason: str | None = "Because."
) -> ResponseRecordedPayload:
    return answer(1, disposition, 1, reason=reason).payload  # type: ignore[return-value]


def test_the_standing_position_is_the_earliest_reasoned_answer_and_reopened_retracts_it() -> None:
    position = next_standing_position(None, _payload(D.REJECTED), 6)
    assert position == StandingPosition("rejected", 6)
    # A later acknowledgement and a later give-up never erase or move the rebuttal.
    for later in (D.ACKNOWLEDGED, D.ACKNOWLEDGED_NOT_DONE):
        assert next_standing_position(position, _payload(later), 9) == position
    first_ack = next_standing_position(None, _payload(D.ACKNOWLEDGED), 5)
    assert first_ack == StandingPosition("acknowledged", 5)
    # A reasoned rejection in the run makes the kind ``rejected`` but keeps the earliest frontier.
    assert next_standing_position(first_ack, _payload(D.REJECTED), 9) == StandingPosition(
        "rejected", 5
    )
    # No reason, no position; duplicate_of and provenance_disputed are not positions.
    assert next_standing_position(None, _payload(D.ACKNOWLEDGED, reason=None), 5) is None
    assert next_standing_position(position, _payload(D.PROVENANCE_DISPUTED), 9) == position
    assert next_standing_position(position, _payload(D.REOPENED), 9) is None


def test_an_acknowledgement_after_a_rebuttal_does_not_erase_it_for_the_ruling_latches() -> None:
    """cargo S fnd_a752665d: rejected, then acknowledged, then self_verified. The reviewer's later
    ``withdrawn`` / unchanged repeat must still find the rebuttal standing (12 of 16 rejections
    were overwritten before the next review)."""

    finding = reviewer_finding(1, str(obl(1)), kind=FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS)
    standing = StandingPosition("rejected", 6)
    findings = {
        fnd(1): finding_record(finding, 5, standing_position=standing),
        fnd(2): finding_record(
            reviewer_finding(2, str(obl(2))),
            5,
            standing_position=StandingPosition("acknowledged", 6),
        ),
    }
    responses = {
        fnd(1): answer(1, D.ACKNOWLEDGED, 9),
        fnd(2): answer(2, D.ACKNOWLEDGED, 9),
    }
    mutable = dict(findings)
    apply_check_rulings(
        mutable,
        responses,
        ruling_check(rulings=((1, "withdrawn"), (2, "withdrawn"))),
        evt(30),
        check_frontier=30,
    )
    assert mutable[fnd(1)].rejection_accepted_by_check_event_id == evt(30)
    # An acknowledgement alone is not a rejection the reviewer can accept.
    assert mutable[fnd(2)].rejection_accepted_by_check_event_id is None
    state = projection(dict(mutable), responses)
    assert finding_todo_state(state, fnd(1)) is FindingTodoState.REJECTION_ACCEPTED
    assert finding_todo_state(state, fnd(2)) is FindingTodoState.OPEN


def test_a_repeat_over_a_reasoned_acknowledgement_latches_the_standing_disagreement() -> None:
    finding = reviewer_finding(1, str(obl(1)), kind=FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS)
    findings = {
        fnd(1): finding_record(finding, 5, standing_position=StandingPosition("acknowledged", 6))
    }
    responses = {fnd(1): answer(1, D.ACKNOWLEDGED, 6)}
    apply_check_rulings(
        findings,
        responses,
        ruling_check(rulings=((1, "disputed_after_rebuttal"),)),
        evt(30),
        check_frontier=30,
    )
    state = projection(dict(findings), responses)
    assert finding_todo_state(state, fnd(1)) is FindingTodoState.DISPUTED_AFTER_REBUTTAL
    assert finding_blocks_receipt(state, fnd(1)) is False
    assert findings[fnd(1)].review_rounds == 0
    assert ruling_since(state, fnd(1)) == 30


def test_the_standing_accessors_the_closure_classifier_reads() -> None:
    finding = reviewer_finding(1, str(obl(1)))
    findings = {
        fnd(1): finding_record(
            finding, 5, standing_position=StandingPosition("rejected", 6), last_ruling_frontier=8
        )
    }
    state = projection(findings, {fnd(1): answer(1, D.ACKNOWLEDGED, 9)})
    assert finding_standing(state, fnd(1)) == ("rejected", 6)
    assert standing_answer_frontier(state, fnd(1)) == 6
    assert ruling_since(state, fnd(1)) == 8  # a ruling followed the rejection: not awaiting one
    unanswered = projection({fnd(2): finding_record(reviewer_finding(2, str(obl(1))), 5)}, {})
    assert finding_standing(unanswered, fnd(2)) is None and ruling_since(unanswered, fnd(2)) is None
    # A hand-built projection without the reducer fact falls back to the latest reasoned answer.
    bare = projection({fnd(1): finding_record(finding, 5)}, {fnd(1): answer(1, D.REJECTED, 6)})
    assert finding_standing(bare, fnd(1)) == ("rejected", 6)


# --- RC-7: the reverse edges (owner decision 8) ----------------------------------------------------


@pytest.mark.parametrize("disposition", [D.ACKNOWLEDGED_NOT_DONE, D.SELF_VERIFIED])
def test_an_absence_proof_of_work_tested_after_the_answer_resolves_it(
    disposition: ResponseDisposition,
) -> None:
    """cargo D N3-5 and pretrain S: the agent repaired after giving up; the receipt stayed
    ``unresolved_findings_remain`` because the answer was a one-way door."""

    finding = local_finding(1)
    evidence = (res(1),) if disposition is D.SELF_VERIFIED else ()
    answered = {fnd(1): answer(1, disposition, 12, evidence=evidence)}
    before = {
        fnd(1): finding_record(finding, 5, resolved_by_check_event_id=evt(9), resolution_frontier=9)
    }
    after = {
        fnd(1): finding_record(
            finding, 5, resolved_by_check_event_id=evt(20), resolution_frontier=20
        )
    }
    # Proof of a state tested BEFORE the answer: the answer is still the last word.
    assert finding_is_resolved(projection(before, answered), fnd(1)) is False
    unresolved = finding_todo_state(projection(before, answered), fnd(1))
    assert unresolved in {FindingTodoState.ACKNOWLEDGED_NOT_DONE, FindingTodoState.SELF_VERIFIED}
    # Proof of a state tested AFTER it: the proof, not the agent, resolves the finding.
    state = projection(after, answered)
    assert finding_is_resolved(state, fnd(1)) is True
    assert finding_todo_state(state, fnd(1)) is FindingTodoState.VERIFIED_RESOLVED
    assert finding_blocks_receipt(state, fnd(1)) is False


def test_apply_check_resolution_records_the_tested_frontier_and_redaction_drops_it() -> None:
    findings = {fnd(1): finding_record(local_finding(1), 5)}
    clean = ruling_check(tested=21, qualifying=True)
    apply_check_resolution(findings, clean, evt(22))
    assert findings[fnd(1)].resolved_by_check_event_id == evt(22)
    assert findings[fnd(1)].resolution_frontier == 21
    reopen_findings_resolved_by(findings, frozenset({evt(22)}))
    assert findings[fnd(1)].resolved_by_check_event_id is None
    assert findings[fnd(1)].resolution_frontier is None


def test_reopened_takes_an_acknowledged_not_done_answer_back() -> None:
    finding = reviewer_finding(1, str(obl(1)))
    findings = {fnd(1): finding_record(finding, 5)}
    gave_up = projection(findings, {fnd(1): answer(1, D.ACKNOWLEDGED_NOT_DONE, 8)})
    assert finding_todo_state(gave_up, fnd(1)) in REOPENABLE_TODO_STATES
    reopened = projection(findings, {fnd(1): answer(1, D.REOPENED, 10)})
    assert finding_todo_state(reopened, fnd(1)) is FindingTodoState.OPEN
    assert finding_blocks_receipt(reopened, fnd(1)) is True  # an act finding is work again
    assert not REOPENABLE_TODO_STATES & ABSOLUTELY_FINAL_TODO_STATES


def test_the_new_projection_fields_round_trip_and_stay_absent_until_set() -> None:
    plain = finding_record(reviewer_finding(1, str(obl(1))), 5)
    rich = finding_record(
        reviewer_finding(2, str(obl(1))),
        6,
        resolved_by_check_event_id=evt(9),
        resolution_frontier=9,
        standing_position=StandingPosition("rejected", 7),
        last_ruling_frontier=8,
    )
    state = projection(
        {fnd(1): plain, fnd(2): rich},
        {},
        obligations={obl(1): replace(obligation_row(1, 4), introduced_frontier=2)},
    )
    snapshot = projection_snapshot(state)
    rows = snapshot["findings"]
    assert isinstance(rows, dict)
    for absent in ("standing_position", "last_ruling_frontier", "resolution_frontier"):
        assert absent not in rows[fnd(1)]  # type: ignore[operator]
    restored = projection_from_snapshot(snapshot)
    assert restored.findings[fnd(2)].standing_position == StandingPosition("rejected", 7)
    assert restored.findings[fnd(2)].last_ruling_frontier == 8
    assert restored.findings[fnd(2)].resolution_frontier == 9
    assert restored.findings[fnd(1)].standing_position is None
    assert restored.obligations[obl(1)].introduced_frontier == 2


def test_a_settled_reraise_widens_the_items_concern_by_what_it_cited() -> None:
    """formal-crypto S: the agent settled the item; a re-raise cited a second obligation, and a
    third review named only that one. The item remembers it (bounded, sorted, typed ids that
    are not subjects of work never join)."""

    finding = reviewer_finding(1, str(obl(1)))
    findings = {
        fnd(1): finding_record(
            finding,
            5,
            standing_position=StandingPosition("acknowledged_not_done", 6),
        )
    }
    responses = {fnd(1): answer(1, D.ACKNOWLEDGED_NOT_DONE, 6)}
    check = ruling_check(
        rulings=((1, "still_present"),),
        cited={1: (str(obl(2)), str(fnd(9)), str(res(3)))},
    )
    apply_check_rulings(findings, responses, check, evt(30), check_frontier=30)
    assert findings[fnd(1)].settled_reraise_count == 1
    assert findings[fnd(1)].absorbed_refs == (str(obl(2)),)
    # An absent absorbed set stays absent; a present one round-trips through the snapshot.
    snapshot = projection_snapshot(projection(dict(findings), responses))
    restored = projection_from_snapshot(snapshot)
    assert restored.findings[fnd(1)].absorbed_refs == (str(obl(2)),)
    plain = projection_snapshot(projection({fnd(1): finding_record(finding, 5)}, {}))
    rows = plain["findings"]
    assert isinstance(rows, dict)
    assert "absorbed_refs" not in rows[fnd(1)]  # type: ignore[operator]


def test_a_claim_covering_the_obligation_names_the_concern_when_no_obligation_is_cited() -> None:
    from yoetz.kernel.concern import concern_key

    state = projection(
        {},
        {},
        obligations={obl(1): obligation_row(1)},
        claims={clm(1): claim_row(1, 4, obl(1))},
    )
    assert concern_key(state, (str(clm(1)),)).obligations == frozenset({str(obl(1))})
    assert concern_key(state, (str(obl(1)),)).obligations == frozenset({str(obl(1))})
