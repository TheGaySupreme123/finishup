"""tb4n5 follow-up of #1042 through the check's reviewer fence: the local rule owns the relation.

In 3 of 9 S tasks (vigenere, live-db, medical) the reviewer raised "action has no linked result"
beside the local finding about the same agent-published action; the local twin resolved once the
agent linked the result while the AI twin latched ``disputed_after_rebuttal``. The AI copy of
``action_without_result`` or ``result_without_action`` is now counted and disclosed
(``local_rule_owned``), never minted; every other kind about the same action is still reviewed.
The #1046 follow-up (``fixed`` rulings citing ``evt_`` ids) is covered through the real ruling
admission in ``test_semantic_post_validation`` and end to end in
``integration/application/test_review_dialogue_workflow``.

The cases replay agent-published ledgers through the production case builder and the real check
fence (``validate_semantic_judgment``).
"""

from __future__ import annotations

from dataclasses import replace

from builders.observed_runs import ObservedLedger
from unit.application import test_tb4n4_review_frame as tb4n4
from yoetz.application.check import (
    SEMANTIC_REJECTED_LOCAL_RULE_OWNED,
    SemanticJudgmentReview,
    validate_semantic_judgment,
)
from yoetz.domain.events import (
    ActionKind,
    ActionRecordedPayload,
    ClaimKind,
    ClaimRecordedPayload,
    EventSchema,
    EvidenceKind,
    EvidenceRecordedPayload,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
    ResultOutcome,
    ResultRecordedPayload,
)
from yoetz.domain.findings import FindingKind
from yoetz.domain.receipts import SEMANTIC_PROCESS_STATE_FILTERED_GAP
from yoetz.domain.values import (
    EventId,
    action_id,
    claim_id,
    evidence_id,
    obligation_id,
    result_id,
    timestamp_from_string,
)
from yoetz.kernel.deterministic_checks import (
    CaseAvailabilityFacts,
    DeterministicCase,
    build_deterministic_case,
    run_deterministic_policies,
)
from yoetz.kernel.policies.work_integrity import WORK_INTEGRITY_POLICY_PACK
from yoetz.kernel.reducers import replay
from yoetz.ports.semantic import ReviewerChallenge, SemanticJudgment
from yoetz.protocol.coverage import EvidenceImmutability

_ENGINE = obligation_id("obl_00000000-0000-4000-8000-000000000501")
_SEED = obligation_id("obl_00000000-0000-4000-8000-000000000502")
_OTHER = obligation_id("obl_00000000-0000-4000-8000-000000000503")
_FIRST = "req_00000000-0000-4000-8000-000000000501"
_LATER = "req_00000000-0000-4000-8000-000000000502"


def _review(case: DeterministicCase, *challenges: ReviewerChallenge) -> SemanticJudgmentReview:
    return validate_semantic_judgment(
        case,
        (),
        SemanticJudgment("challenges_returned", challenges),
        tb4n4._provenance(),  # pyright: ignore[reportPrivateUsage]
        expected_frontier=case.frontier,
        review_phase="routine",
    )


def _awr(*refs: str, summary: str) -> ReviewerChallenge:
    return tb4n4._challenge(  # pyright: ignore[reportPrivateUsage]
        FindingKind.ACTION_WITHOUT_RESULT, *refs, summary=summary
    )


def _ledger() -> tuple[ObservedLedger, dict[str, EventId]]:
    """medical S L95 / vigenere S L88: an edit and a command published in one batch, with
    evidence but no result for the edit; unrelated work in a later batch."""

    ledger = ObservedLedger()
    for obligation in (_ENGINE, _SEED, _OTHER):
        ledger.append(
            EventSchema("obligation_published", "1.0.0"),
            ObligationPublishedPayload(
                obligation_id=obligation,
                description="Synthetic obligation",
                evidence_expectation="A recorded result",
                status=ObligationStatus.OPEN,
            ),
            observed=False,
            operation=_FIRST,
        )
    ledger.append(
        EventSchema("plan_published", "1.0.0"),
        PlanPublishedPayload(1, "Plan", (_ENGINE, _SEED, _OTHER)),
        observed=False,
        operation=_FIRST,
    )
    events: dict[str, EventId] = {}
    events["edit"] = ledger.append(
        EventSchema("action_recorded", "1.0.0"),
        ActionRecordedPayload(
            action_id("act_00000000-0000-4000-8000-000000000511"),
            ActionKind.EDIT,
            "Rewrote the triage scoring engine",
            obligation_refs=(_ENGINE,),
        ),
        observed=False,
        operation=_FIRST,
    )
    events["command"] = ledger.append(
        EventSchema("action_recorded", "1.0.0"),
        ActionRecordedPayload(
            action_id("act_00000000-0000-4000-8000-000000000512"),
            ActionKind.COMMAND,
            "Reinstalled and reseeded the database",
            command="python reseed.py",
            obligation_refs=(_SEED,),
        ),
        observed=False,
        operation=_FIRST,
    )
    events["evidence"] = ledger.append(
        EventSchema("evidence_recorded", "1.0.0"),
        EvidenceRecordedPayload(
            evidence_id=evidence_id("evd_00000000-0000-4000-8000-000000000513"),
            evidence_kind=EvidenceKind.COMMAND_OUTPUT,
            strength=EvidenceImmutability.METADATA_ONLY,
            observed_at=timestamp_from_string("2026-10-12T21:40:00.000Z"),
            description="The engine passes its scoring table",
        ),
        observed=False,
        operation=_FIRST,
    )
    events["later"] = ledger.append(
        EventSchema("action_recorded", "1.0.0"),
        ActionRecordedPayload(
            action_id("act_00000000-0000-4000-8000-000000000514"),
            ActionKind.RESEARCH,
            "Read the triage protocol notes",
            obligation_refs=(_OTHER,),
        ),
        observed=False,
        operation=_LATER,
    )
    return ledger, events


def _case(ledger: ObservedLedger) -> DeterministicCase:
    prefix = ledger.prefix
    return build_deterministic_case(replay(prefix), prefix, CaseAvailabilityFacts())


def _local_action_findings(case: DeterministicCase) -> list[tuple[str, ...]]:
    return [
        tuple(str(ref) for ref in item.candidate.subject_refs)
        for item in run_deterministic_policies(case, WORK_INTEGRITY_POLICY_PACK).assessments
        if item.candidate.kind is FindingKind.ACTION_WITHOUT_RESULT
    ]


def _fence_gaps(review: SemanticJudgmentReview) -> frozenset[str]:
    from yoetz.application.check import (
        _review_fence_gaps,  # pyright: ignore[reportPrivateUsage]
    )

    return _review_fence_gaps(review)


# --- #1042 follow-up: the local rule owns the action/result relation ---------------------------


def test_the_three_tb4n5_shapes_mint_no_ai_bookkeeping_finding() -> None:
    ledger, events = _ledger()
    case = _case(ledger)
    # The local rule keeps its own findings: both unpaired actions of the first batch, raised by the
    # later batch's unrelated work, never by each other.
    assert _local_action_findings(case) == [(str(events["edit"]),), (str(events["command"]),)]
    shapes = {
        # vigenere S fnd_e5e6fd62: the local subject plus an evidence event (a superset).
        "vigenere": _awr(
            str(events["edit"]), str(events["evidence"]), summary="The run has no linked result"
        ),
        # live-db S fnd_1c46b392: the identical subject.
        "live-db": _awr(str(events["edit"]), summary="The edit has no linked result"),
        # medical S fnd_97f805aa: "the engine edit has no linked result" citing the sibling command.
        "medical": _awr(str(events["command"]), summary="The engine edit has no linked result"),
    }
    for name, challenge in shapes.items():
        review = _review(case, challenge)
        assert review.candidates == (), name
        assert review.rejected_by_reason == ((SEMANTIC_REJECTED_LOCAL_RULE_OWNED, 1),), name
        # Disclosed, never bounding: the review saw everything it needed.
        assert _fence_gaps(review) == frozenset({SEMANTIC_PROCESS_STATE_FILTERED_GAP}), name
    # A result-without-action copy is the local rule's too.
    orphan = replace(shapes["live-db"], finding_kind=FindingKind.RESULT_WITHOUT_ACTION)
    assert _review(case, orphan).candidates == ()


def test_failed_or_unrun_verification_and_false_completion_claims_stay_reviewable() -> None:
    ledger, _events = _ledger()
    failed = ledger.append(
        EventSchema("result_recorded", "1.0.0"),
        ResultRecordedPayload(
            result_id("res_00000000-0000-4000-8000-000000000512"),
            action_id("act_00000000-0000-4000-8000-000000000512"),
            ResultOutcome.FAILURE,
            summary="The reseed failed",
        ),
        observed=False,
        operation=_LATER,
    )
    claim = ledger.append(
        EventSchema("claim_recorded", "1.0.0"),
        ClaimRecordedPayload(
            claim_id("clm_00000000-0000-4000-8000-000000000515"),
            ClaimKind.COMPLETION,
            "The engine is done and verified",
            (),
            obligation_refs=(_ENGINE, _SEED, _OTHER),
        ),
        observed=False,
        operation=_LATER,
    )
    case = _case(ledger)
    kept = (
        tb4n4._challenge(  # pyright: ignore[reportPrivateUsage]
            FindingKind.FAILED_WORK_OMITTED, str(failed), summary="The failed reseed is undisclosed"
        ),
        tb4n4._challenge(  # pyright: ignore[reportPrivateUsage]
            FindingKind.CLAIM_WITHOUT_ADMISSIBLE_EVIDENCE,
            str(claim),
            summary="The completion claim cites no verification",
        ),
        tb4n4._challenge(  # pyright: ignore[reportPrivateUsage]
            FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS,
            str(claim),
            str(_SEED),
            summary="Done is claimed while the reseed failed",
        ),
        # "action without result" naming no action or result says nothing the rule decides.
        _awr(str(_ENGINE), summary="The engine obligation's action has no outcome"),
    )
    for challenge in kept:
        review = _review(case, challenge)
        assert [candidate.kind for candidate in review.candidates] == [challenge.finding_kind]
        assert review.rejected_by_reason == ()
