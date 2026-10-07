"""Assumption and verification-limit disclosure lines (issue #995, ADR-033).

tb4n1: ks-solver, lake-temp-glm and vpp-loss-divergence (semantic arms) declared ``yoetz-blocker``
on finished work because a hidden verifier or a private trace was out of reach, and
cargo-flight-dispatch blocked four times "pending the task owner's cruise-altitude policy
decision" where a best-effort choice with a disclosed assumption was possible. A disclosure line
records that honestly without blocking anything.
"""

from __future__ import annotations

from builders.observed_runs import ObservedLedger
from yoetz.domain.events import (
    DecisionRecordedPayload,
    EventSchema,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
)
from yoetz.domain.values import EventId, actor_id, obligation_id
from yoetz.kernel.closure_readiness import (
    ASSUMPTION_DISCLOSED_GAP,
    GAP_CLASSIFICATION,
    VERIFICATION_LIMIT_DISCLOSED_GAP,
    GapClass,
    closure_readiness_facts,
    derive_closure_readiness,
)
from yoetz.kernel.reducers import replay
from yoetz.kernel.task_facts import (
    blocker_declarations,
    decision_batches,
    disclosure_declarations,
    disclosure_line_obligations,
    task_fact_signals,
)

_OBLIGATION = obligation_id("obl_00000000-0000-4000-8000-000000000001")
_OTHER = obligation_id("obl_00000000-0000-4000-8000-000000000002")
_UNKNOWN = obligation_id("obl_00000000-0000-4000-8000-0000000000ff")


def _ledger(status: ObligationStatus = ObligationStatus.OPEN) -> ObservedLedger:
    ledger = ObservedLedger()
    for obligation in (_OBLIGATION, _OTHER):
        ledger.append(
            EventSchema("obligation_published", "1.0.0"),
            ObligationPublishedPayload(
                obligation_id=obligation,
                description="Synthetic obligation",
                evidence_expectation="Observed run",
                status=status,
            ),
            observed=False,
        )
    ledger.append(
        EventSchema("plan_published", "1.0.0"),
        PlanPublishedPayload(1, "Plan", (_OBLIGATION, _OTHER)),
        observed=False,
    )
    return ledger


def _decide(
    ledger: ObservedLedger, statement: str, *, supersedes: EventId | None = None
) -> EventId:
    return ledger.append(
        EventSchema("decision_recorded", "1.0.0"),
        DecisionRecordedPayload(
            statement=statement,
            rationale="The verifier's private trace is not present in this workspace.",
            authority=actor_id("agt_codex"),
            supersedes_event_id=supersedes,
        ),
        observed=False,
    )


def test_only_exact_lines_with_a_well_formed_obligation_id_count() -> None:
    statement = "\n".join(
        (
            f"yoetz-assumption:{_OBLIGATION}",
            f"  yoetz-verification-limit:{_OBLIGATION}  ",
            f"yoetz-assumption:{_OBLIGATION}",
            f"yoetz-assumption: {_OTHER} because",
            "yoetz-assumption:obl_not-an-id",
            f"I assume yoetz-assumption:{_OTHER}",
            f"yoetz-verification-limit:{_OTHER}",
        )
    )
    assert disclosure_line_obligations(statement) == (
        ("assumption", _OBLIGATION),
        ("verification_limit", _OBLIGATION),
        ("verification_limit", _OTHER),
    )


def test_a_disclosure_is_standing_and_never_blocks_or_resolves() -> None:
    ledger = _ledger()
    before = ledger.prefix
    facts_before = closure_readiness_facts(replay(before), before)
    decision = _decide(
        ledger,
        "Chose the documented default altitude.\n"
        f"yoetz-assumption:{_OBLIGATION}\nyoetz-verification-limit:{_OTHER}",
    )
    prefix = ledger.prefix
    projection = replay(prefix)

    declared = disclosure_declarations(projection)
    assert [(item.obligation_id, item.kind, item.decision_event_id) for item in declared] == [
        (_OBLIGATION, "assumption", decision),
        (_OTHER, "verification_limit", decision),
    ]
    # Never a blocker, never a task fact, never a change to the obligations.
    assert dict(blocker_declarations(projection, decision_batches(prefix))) == {}
    assert task_fact_signals(projection, prefix) == task_fact_signals(replay(before), before)
    assert all(
        projection.obligations[item].payload.status is ObligationStatus.OPEN  # type: ignore[union-attr]
        for item in (_OBLIGATION, _OTHER)
    )
    facts = closure_readiness_facts(projection, prefix)
    assert facts.open_obligation_ids == facts_before.open_obligation_ids
    readiness = derive_closure_readiness(
        ("obligations_open",), (), facts, semantic_review_required=False
    )
    # The open obligations are still the agent's work; the disclosures only add standing codes.
    assert readiness.state == "action_required"
    assert "obligations_open" in readiness.agent_actionable
    assert {ASSUMPTION_DISCLOSED_GAP, VERIFICATION_LIMIT_DISCLOSED_GAP} <= set(
        readiness.standing_limitations
    )
    assert GAP_CLASSIFICATION[ASSUMPTION_DISCLOSED_GAP] is GapClass.STANDING_LIMITATION
    assert GAP_CLASSIFICATION[VERIFICATION_LIMIT_DISCLOSED_GAP] is GapClass.STANDING_LIMITATION


def test_finished_work_with_a_verification_limit_is_ready_with_limitations() -> None:
    """ks-solver sem: "hidden-verifier accuracy cannot be performed" on finished work."""

    ledger = _ledger(ObligationStatus.OPEN)
    _decide(ledger, f"yoetz-verification-limit:{_OBLIGATION}")
    prefix = ledger.prefix
    facts = closure_readiness_facts(replay(prefix), prefix)
    from dataclasses import replace

    facts = replace(facts, check_applicability="applicable")
    readiness = derive_closure_readiness((), (), facts, semantic_review_required=False)
    assert readiness.state == "ready_with_limitations"
    assert readiness.agent_actionable == ()
    assert readiness.standing_limitations == (VERIFICATION_LIMIT_DISCLOSED_GAP,)


def test_an_unknown_obligation_is_a_missing_ref_and_discloses_nothing() -> None:
    ledger = _ledger()
    decision = _decide(ledger, f"yoetz-assumption:{_UNKNOWN}")
    projection = replay(ledger.prefix)
    assert disclosure_declarations(projection) == ()
    assert f"missing_ref:{decision}:{_UNKNOWN}" in projection.coverage_gaps


def test_superseding_the_decision_withdraws_the_disclosure() -> None:
    ledger = _ledger()
    first = _decide(ledger, f"yoetz-assumption:{_OBLIGATION}")
    assert len(disclosure_declarations(replay(ledger.prefix))) == 1
    _decide(ledger, "The assumption no longer applies; the policy was found.", supersedes=first)
    prefix = ledger.prefix
    projection = replay(prefix)
    assert disclosure_declarations(projection) == ()
    readiness = derive_closure_readiness(
        (), (), closure_readiness_facts(projection, prefix), semantic_review_required=False
    )
    assert ASSUMPTION_DISCLOSED_GAP not in readiness.standing_limitations


def test_the_earliest_unsuperseded_decision_records_each_kind() -> None:
    ledger = _ledger()
    first = _decide(ledger, f"yoetz-assumption:{_OBLIGATION}")
    _decide(ledger, f"yoetz-assumption:{_OBLIGATION}")
    [row] = disclosure_declarations(replay(ledger.prefix))
    assert (row.obligation_id, row.decision_event_id) == (_OBLIGATION, first)
