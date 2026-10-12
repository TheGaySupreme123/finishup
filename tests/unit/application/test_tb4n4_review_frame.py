"""The check's reviewer fence for tb4n4 (issues #1042 and #1043).

* #1042: a routine review judges incomplete work only. Its correctness concern (``code_defect``)
  is recorded as an advisory, non-blocking note in the review summary; a challenge about Yoetz's
  own capture state, or a "never attempted" one during work in progress, is counted and disclosed
  (``semantic_process_state_filtered``), never minted, and never bounds the check.
* #1043: a ``task_requirement_unmet`` whose only cited work is the agent's own run beyond the
  task's declared verification is recorded as ``agent_criterion_unmet``: a limitation request the
  agent may fix or narrow with a reason.

The cases replay hook-observed ledgers through the production case builder; the reviewer's
judgment is scripted.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import replace

import pytest

from builders.observed_runs import INSTALLATION_KEY, ObservedLedger
from yoetz.application.check import (
    SEMANTIC_REJECTED_ROUTINE_COMPLETENESS,
    SEMANTIC_REJECTED_YOETZ_PROCESS_STATE,
    SemanticJudgmentReview,
    validate_semantic_judgment,
)
from yoetz.domain.events import (
    ActionKind,
    ActionRecordedPayload,
    EventSchema,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
    RequestedItem,
    RequestedItemKind,
)
from yoetz.domain.findings import (
    FindingKind,
    SamplingParams,
    SemanticDispatchKind,
    SemanticProvenance,
    is_limitation_request,
)
from yoetz.domain.receipts import (
    SEMANTIC_CHALLENGES_REJECTED_GAP,
    SEMANTIC_PROCESS_STATE_FILTERED_GAP,
)
from yoetz.domain.values import action_id, obligation_id
from yoetz.kernel.deterministic_checks import (
    CaseAvailabilityFacts,
    DeterministicCase,
    build_deterministic_case,
)
from yoetz.kernel.finding_resolution import (
    DETERMINISTIC_PROOF_TOLERATED_GAPS,
    SEMANTIC_ONLY_GAPS,
)
from yoetz.kernel.gap_effect import GapEffectKind, gap_effect
from yoetz.kernel.observed_failures import observed_action_description
from yoetz.kernel.reducers import replay
from yoetz.kernel.task_facts import register_command_identity_key
from yoetz.ports.semantic import ReviewerChallenge, SemanticJudgment
from yoetz.protocol.models import SemanticReason, SemanticStatus

_DIGEST = "sha256:" + "a" * 64
_OBLIGATION = obligation_id("obl_00000000-0000-4000-8000-000000000001")
_SAMPLE = "python3 solve.py --check sample_input.txt"
_STRESS = "python3 stress.py --streams 12 --seed-lengths 9-32"


@pytest.fixture(autouse=True)
def installation_key() -> Iterator[None]:
    register_command_identity_key(INSTALLATION_KEY)
    yield
    register_command_identity_key(None)


def _provenance() -> SemanticProvenance:
    return SemanticProvenance(
        provider="fake",
        endpoint_profile_id="fake",
        endpoint_profile_version="1.0.0",
        model="fake/model",
        sdk_version="1.0.0",
        prompt_digest=_DIGEST,
        schema_digest=_DIGEST,
        policy_digest=_DIGEST,
        privacy_policy_digest=_DIGEST,
        sampling_params=SamplingParams(128),
        latency_ms=1,
        semantic_attempt_id="att_20000000-0000-4000-8000-000000001042",
        dispatch_kind=SemanticDispatchKind.EXTERNAL,
        privacy_receipt_id="egr_20000000-0000-4000-8000-000000001042",
        status=SemanticStatus.SUCCEEDED,
        reason=SemanticReason.SEMANTIC_COMPLETED,
        provider_request_id="fake-1042",
        egress_authorization_id="aut_20000000-0000-4000-8000-000000001042",
        request_commitment="hmac-sha256:" + "b" * 64,
    )


def _challenge(
    kind: FindingKind, *refs: str, summary: str, next_step: str = "act"
) -> ReviewerChallenge:
    return ReviewerChallenge(
        kind,
        summary,
        tuple(sorted(refs)),
        "The discrepancy the reviewer saw.",
        "A plausible alternative reading.",
        f"Main agent: {summary.lower()}.",
        next_step,  # type: ignore[arg-type]
        "What the reviewer could not settle.",
    )


def _obligation(ledger: ObservedLedger, *, command: str | None = None) -> None:
    ledger.append(
        EventSchema("obligation_published", "1.0.0"),
        ObligationPublishedPayload(
            obligation_id=_OBLIGATION,
            description="Decrypt the interleaved streams",
            evidence_expectation="The sample decrypts",
            status=ObligationStatus.OPEN,
            requested_items=(
                () if command is None else (RequestedItem(RequestedItemKind.COMMAND, command),)
            ),
        ),
        observed=False,
    )
    ledger.append(
        EventSchema("plan_published", "1.0.0"),
        PlanPublishedPayload(1, "Plan", (_OBLIGATION,)),
        observed=False,
    )


def _case(ledger: ObservedLedger) -> DeterministicCase:
    prefix = ledger.prefix
    return build_deterministic_case(replay(prefix), prefix, CaseAvailabilityFacts())


def _review(
    case: DeterministicCase, *challenges: ReviewerChallenge, phase: str | None
) -> SemanticJudgmentReview:
    return validate_semantic_judgment(
        case,
        (),
        SemanticJudgment("challenges_returned", challenges),
        _provenance(),
        expected_frontier=case.frontier,
        review_phase=phase,  # type: ignore[arg-type]
    )


def _fence_gaps(review: SemanticJudgmentReview) -> frozenset[str]:
    from yoetz.application.check import (
        _review_fence_gaps,  # pyright: ignore[reportPrivateUsage]
    )

    return _review_fence_gaps(review)


# --- #1042 item 1: correctness concerns are advisory during work in progress -------------------


def test_a_routine_correctness_concern_is_an_advisory_note_not_a_finding() -> None:
    ledger = ObservedLedger()
    _obligation(ledger)
    edited = ledger.edit()
    case = _case(ledger)
    event = str(case.projection.results[edited].source_event_id)
    concern = _challenge(
        FindingKind.CODE_DEFECT, event, summary="The key schedule skips the last byte"
    )

    routine = _review(case, concern, phase="routine")
    assert routine.candidates == ()
    assert routine.advisory_notes == 1
    assert routine.rejected_by_reason == ()
    assert "Reviewer correctness notes (advisory and non-blocking" in routine.review_summary
    assert "The key schedule skips the last byte" in routine.review_summary
    # A note is not a dropped challenge: nothing bounds the check.
    assert _fence_gaps(routine) == frozenset()

    # The closing review judges completeness and correctness alike: the concern is a finding.
    final = _review(case, concern, phase="final")
    assert [candidate.kind for candidate in final.candidates] == [FindingKind.CODE_DEFECT]
    assert final.advisory_notes == 0
    # A caller that does not name the phase keeps the earlier behaviour.
    legacy = _review(case, concern, phase=None)
    assert [candidate.kind for candidate in legacy.candidates] == [FindingKind.CODE_DEFECT]


def test_an_incomplete_work_challenge_stays_a_finding_in_a_routine_review() -> None:
    """In-frame catches keep their kind and block exactly as before."""

    ledger = ObservedLedger()
    _obligation(ledger)
    failed = ledger.fail("pytest -q")
    case = _case(ledger)
    event = str(case.projection.results[failed].source_event_id)
    omitted = _challenge(
        FindingKind.FAILED_WORK_OMITTED, event, summary="The failing test run is not disclosed"
    )

    review = _review(case, omitted, phase="routine")
    assert [candidate.kind for candidate in review.candidates] == [FindingKind.FAILED_WORK_OMITTED]
    assert review.advisory_notes == 0


# --- #1042 item 2: Yoetz's own state and work not yet started are filtered and disclosed -------


def test_an_action_without_result_about_the_check_call_is_filtered_and_disclosed() -> None:
    ledger = ObservedLedger()
    _obligation(ledger)
    ledger.edit()
    check_call = action_id("act_00000000-0000-4000-8000-000000000101")
    ledger.append(
        EventSchema("action_recorded", "1.0.0"),
        ActionRecordedPayload(
            check_call,
            ActionKind.OTHER,
            observed_action_description("Observed other via Codex hook", "mcp__yoetz__check"),
        ),
        observed=True,
    )
    case = _case(ledger)
    event = str(case.projection.actions[check_call].source_event_id)
    challenge = _challenge(
        FindingKind.ACTION_WITHOUT_RESULT, event, summary="The check call has no result"
    )

    for phase in ("routine", "final"):
        review = _review(case, challenge, phase=phase)
        assert review.candidates == ()
        assert review.rejected_by_reason == ((SEMANTIC_REJECTED_YOETZ_PROCESS_STATE, 1),)
        assert _fence_gaps(review) == frozenset({SEMANTIC_PROCESS_STATE_FILTERED_GAP})


def test_never_attempted_is_dropped_only_while_work_is_in_progress() -> None:
    """ADR-040 section 5, now read from the phase the packet named (issue #1042): the closing review
    judges completeness, so a stop without a completion claim keeps "never attempted"."""

    ledger = ObservedLedger()
    _obligation(ledger)
    ledger.edit()
    case = _case(ledger)
    challenge = _challenge(
        FindingKind.REQUESTED_ITEM_NEVER_ATTEMPTED,
        str(_OBLIGATION),
        summary="The decoder was never attempted",
    )

    routine = _review(case, challenge, phase="routine")
    assert routine.candidates == ()
    assert routine.rejected_by_reason == ((SEMANTIC_REJECTED_ROUTINE_COMPLETENESS, 1),)
    assert _fence_gaps(routine) == frozenset({SEMANTIC_PROCESS_STATE_FILTERED_GAP})
    final = _review(case, challenge, phase="final")
    assert [candidate.kind for candidate in final.candidates] == [
        FindingKind.REQUESTED_ITEM_NEVER_ATTEMPTED
    ]
    # A caller that does not name the phase keeps section 5 as first written (no claim: dropped).
    assert _review(case, challenge, phase=None).candidates == ()
    # A requirement over an open obligation is not filtered: without the reviewer's words it
    # cannot be told from a real unmet requirement.
    unmet = replace(challenge, finding_kind=FindingKind.TASK_REQUIREMENT_UNMET)
    assert [c.kind for c in _review(case, unmet, phase="routine").candidates] == [
        FindingKind.TASK_REQUIREMENT_UNMET
    ]


def test_a_dropped_challenge_keeps_the_bounding_gap_beside_the_disclosure() -> None:
    ledger = ObservedLedger()
    _obligation(ledger)
    ledger.edit()
    case = _case(ledger)
    filtered = _challenge(
        FindingKind.REQUESTED_ITEM_NEVER_ATTEMPTED, str(_OBLIGATION), summary="Never attempted"
    )
    outside = _challenge(
        FindingKind.CODE_DEFECT,
        "clm_20000000-0000-4000-8000-000000000099",
        summary="Cites a claim outside the case",
    )

    review = _review(case, filtered, outside, phase="routine")
    assert _fence_gaps(review) == frozenset(
        {SEMANTIC_PROCESS_STATE_FILTERED_GAP, SEMANTIC_CHALLENGES_REJECTED_GAP}
    )


def test_the_disclosure_never_bounds_a_receipt_or_vetoes_an_absence_proof() -> None:
    code = SEMANTIC_PROCESS_STATE_FILTERED_GAP
    assert gap_effect(code).kind is GapEffectKind.DISCLOSED
    assert code in DETERMINISTIC_PROOF_TOLERATED_GAPS
    assert code not in SEMANTIC_ONLY_GAPS


# --- #1043 item 3: the agent's own probe is routed to its own criterion -------------------------


def _vigenere() -> tuple[DeterministicCase, str, str]:
    ledger = ObservedLedger()
    _obligation(ledger, command=_SAMPLE)
    ledger.edit()
    sample = ledger.passes(_SAMPLE)
    stress = ledger.fail(_STRESS)
    case = _case(ledger)
    results = case.projection.results
    return case, str(results[sample].source_event_id), str(results[stress].source_event_id)


def test_interleaved_vigenere_stress_failure_is_the_agents_own_criterion() -> None:
    """tb4n4 interleaved-vigenere S: failures on the agent's own 12-stream stress run became
    ``task_requirement_unmet`` and the agent spent forty minutes chasing them."""

    case, _sample, stress = _vigenere()
    challenge = _challenge(
        FindingKind.TASK_REQUIREMENT_UNMET,
        str(_OBLIGATION),
        stress,
        summary="The solver fails the twelve-stream configuration",
    )

    for phase in ("routine", "final"):
        review = _review(case, challenge, phase=phase)
        assert [candidate.kind for candidate in review.candidates] == [
            FindingKind.AGENT_CRITERION_UNMET
        ]
        assert review.agent_criteria == 1
        assert "requirement challenge(s) as your own criterion" in review.review_summary
        candidate = review.candidates[0]
        # The reviewer asked the agent to act; the criterion is still the agent's to narrow.
        assert candidate.challenge is not None
        assert candidate.challenge.requested_next_step == "act"


def test_a_requirement_citing_the_tasks_own_verification_stays_a_task_requirement() -> None:
    case, sample, stress = _vigenere()
    challenge = _challenge(
        FindingKind.TASK_REQUIREMENT_UNMET,
        sample,
        stress,
        summary="The sample output is wrong as well",
    )

    review = _review(case, challenge, phase="final")
    assert [candidate.kind for candidate in review.candidates] == [
        FindingKind.TASK_REQUIREMENT_UNMET
    ]
    assert review.agent_criteria == 0
    assert "as your own criterion" not in review.review_summary


def test_an_agent_criterion_finding_is_a_limitation_request_whatever_the_next_step() -> None:
    from builders.policy_cases import finding_record, fnd
    from yoetz.domain.findings import Finding, FindingChallenge, FindingOrigin
    from yoetz.kernel.closure_class import finding_closure

    case, _sample, stress = _vigenere()
    review = _review(
        case,
        _challenge(
            FindingKind.TASK_REQUIREMENT_UNMET,
            stress,
            summary="The solver fails the twelve-stream configuration",
        ),
        phase="final",
    )
    candidate = review.candidates[0]
    finding = Finding(
        finding_id=fnd(1),
        kind=candidate.kind,
        origin=FindingOrigin.SEMANTIC_MODEL_DERIVED,
        priority=candidate.priority,
        summary=candidate.summary,
        detail=candidate.detail,
        subject_refs=candidate.subject_refs,
        policy_id=candidate.policy_id,
        policy_version=candidate.policy_version,
        subject_frontier=candidate.subject_frontier,
        coverage=candidate.coverage,
        provenance=candidate.provenance,
        challenge=candidate.challenge,
    )
    assert is_limitation_request(finding)
    # The same challenge as a task requirement asking the agent to act is not one (guard G1).
    assert not is_limitation_request(
        replace(finding, kind=FindingKind.TASK_REQUIREMENT_UNMET, priority=1)
    )
    assert isinstance(finding.challenge, FindingChallenge)

    state = replace(
        case.projection, findings={fnd(1): finding_record(finding, case.frontier.sequence)}
    )
    closure = finding_closure(state, fnd(1))
    assert closure is not None
    assert closure.basis == "limitation_requested"
    assert closure.next_actions == ("acknowledge", "repair")
