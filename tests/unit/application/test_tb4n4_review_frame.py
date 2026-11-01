"""The check's reviewer fence for tb4n4 (issues #1042 and #1043).

* #1042: a routine review judges incomplete work only. Its correctness concern (``code_defect``)
  is recorded as an advisory, non-blocking note in the review summary; a challenge about FinishUP's
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
from finishup.application.check import (
    SEMANTIC_REJECTED_FINISHUP_PROCESS_STATE,
    SEMANTIC_REJECTED_ROUTINE_COMPLETENESS,
    SemanticJudgmentReview,
    validate_semantic_judgment,
)
from finishup.domain.events import (
    ActionKind,
    ActionRecordedPayload,
    EventSchema,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
    RequestedItem,
    RequestedItemKind,
)
from finishup.domain.findings import (
    FindingKind,
    SamplingParams,
    SemanticDispatchKind,
    SemanticProvenance,
    is_limitation_request,
)
from finishup.domain.receipts import (
    SEMANTIC_CHALLENGES_REJECTED_GAP,
    SEMANTIC_PROCESS_STATE_FILTERED_GAP,
)
from finishup.domain.values import EventId, JsonObject, action_id, obligation_id
from finishup.kernel.deterministic_checks import (
    CaseAvailabilityFacts,
    DeterministicCase,
    build_deterministic_case,
)
from finishup.kernel.finding_resolution import (
    DETERMINISTIC_PROOF_TOLERATED_GAPS,
    SEMANTIC_ONLY_GAPS,
)
from finishup.kernel.gap_effect import GapEffectKind, gap_effect
from finishup.kernel.observed_failures import observed_action_description
from finishup.kernel.reducers import replay
from finishup.kernel.task_facts import agent_linked_run_events, register_command_identity_key
from finishup.ports.semantic import ReviewerChallenge, SemanticJudgment
from finishup.protocol.models import SemanticReason, SemanticStatus

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
    case: DeterministicCase,
    *challenges: ReviewerChallenge,
    phase: str | None,
    linked: frozenset[EventId] | None = frozenset(),
) -> SemanticJudgmentReview:
    return validate_semantic_judgment(
        case,
        (),
        SemanticJudgment("challenges_returned", challenges),
        _provenance(),
        expected_frontier=case.frontier,
        review_phase=phase,  # type: ignore[arg-type]
        agent_linked_runs=linked,
    )


def _fence_gaps(review: SemanticJudgmentReview) -> frozenset[str]:
    from finishup.application.check import (
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
    assert len(routine.correctness_advisories) == 1
    assert routine.correctness_advisories[0]["summary"] == concern.summary
    assert routine.correctness_advisories[0]["detail"] == concern.message_to_main_agent
    assert routine.correctness_advisories[0]["subject_refs"] == concern.cited_refs
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


def test_routine_notes_citing_a_result_or_action_keep_the_rest_of_the_review() -> None:
    """#1162 review blocker: the fence accepts ``res_``/``act_`` citations and resolves them to
    their source event. The retained advisory row stores those resolved subjects; storing the raw
    citations failed the bounded row, rejected the whole review and dropped every challenge."""

    from finishup.domain.correctness_advisories import validate_advisories
    from finishup.domain.values import result_id

    ledger = ObservedLedger()
    _obligation(ledger)
    edited = ledger.edit()
    case = _case(ledger)
    action_event, result_event = ledger.events_of(edited)
    result_payload = case.projection.results[edited].payload
    assert result_payload is not None
    action_ref = str(getattr(result_payload, "action_id"))
    result_ref = str(result_id(str(edited)))
    assert action_ref.startswith("act_") and result_ref.startswith("res_")
    by_result = _challenge(
        FindingKind.CODE_DEFECT, result_ref, summary="Rotated frames are skipped"
    )
    by_action = _challenge(FindingKind.CODE_DEFECT, action_ref, summary="The footprint uses AABBs")
    unmet = _challenge(
        FindingKind.TASK_REQUIREMENT_UNMET, str(_OBLIGATION), summary="The decoder is unfinished"
    )

    review = _review(case, by_result, by_action, unmet, phase="routine")

    assert [candidate.kind for candidate in review.candidates] == [
        FindingKind.TASK_REQUIREMENT_UNMET
    ]
    assert review.advisory_notes == 2
    assert review.rejected_by_reason == ()
    assert [row["subject_refs"] for row in review.correctness_advisories] == [
        (str(result_event),),
        (str(action_event),),
    ]
    assert [row["summary"] for row in review.correctness_advisories] == [
        "Rotated frames are skipped",
        "The footprint uses AABBs",
    ]
    validate_advisories(review.correctness_advisories)
    assert "FinishUP note:" not in review.review_summary


def test_an_unretainable_advisory_row_degrades_to_the_summary_with_a_disclosure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#1162: an advisory-shape problem never discards an otherwise valid review.

    No reachable provider output fails the row once its subjects are fence-resolved (provider
    challenges are capped at three), so the row bound itself is narrowed here; the fence, the
    case and every other step are the production path.
    """

    import finishup.application.check as checks
    from finishup.domain.correctness_advisories import validate_advisories

    def refuse_second(rows: tuple[JsonObject, ...]) -> None:
        validate_advisories(rows)
        if any("second" in str(row["summary"]) for row in rows):
            raise ValueError("advisory_row_shape")

    monkeypatch.setattr(checks, "validate_advisories", refuse_second)
    ledger = ObservedLedger()
    _obligation(ledger)
    edited = ledger.edit()
    case = _case(ledger)
    event = str(case.projection.results[edited].source_event_id)
    first = _challenge(FindingKind.CODE_DEFECT, event, summary="The first concern")
    second = _challenge(FindingKind.CODE_DEFECT, event, summary="The second concern")
    unmet = _challenge(
        FindingKind.TASK_REQUIREMENT_UNMET, str(_OBLIGATION), summary="The decoder is unfinished"
    )

    review = _review(case, first, second, unmet, phase="routine")

    assert [candidate.kind for candidate in review.candidates] == [
        FindingKind.TASK_REQUIREMENT_UNMET
    ]
    assert review.advisory_notes == 2
    assert [row["summary"] for row in review.correctness_advisories] == ["The first concern"]
    assert "The second concern" in review.review_summary
    assert "FinishUP note: 1 reviewer correctness note(s) above are kept in this summary only" in (
        review.review_summary
    )


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


# --- #1042 item 2: FinishUP's own state and work not yet started are filtered and disclosed -------


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
            observed_action_description("Observed other via Codex hook", "mcp__finishup__check"),
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
        assert review.rejected_by_reason == ((SEMANTIC_REJECTED_FINISHUP_PROCESS_STATE, 1),)
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
    from finishup.domain.findings import Finding, FindingChallenge, FindingOrigin
    from finishup.kernel.closure_class import finding_closure

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


def test_a_run_the_agent_linked_to_the_declared_verification_is_never_its_own_probe() -> None:
    """Review of #1043 x #1049: a run the agent linked to a requested command (PL6-3) is the
    declared verification the task facts accept (``planned_verification_agent_linked``), not a
    run beyond it. A requirement challenge about that run stays the task's requirement; it never
    becomes the agent's own criterion."""

    planned = "make test"
    ledger = ObservedLedger()
    _obligation(ledger, command=planned)
    ledger.edit()
    linked_result = ledger.passes("./run_tests.sh --all")
    stress_result = ledger.fail(_STRESS)
    projection = replay(ledger.prefix)
    linked_payload = projection.results[linked_result].payload
    assert linked_payload is not None
    linked_action = projection.actions[linked_payload.action_id]
    ledger.append(
        EventSchema("action_recorded", "1.0.0"),
        ActionRecordedPayload(
            action_id("act_00000000-0000-4000-8000-00000000a001"),
            ActionKind.COMMAND,
            "Ran the test suite (the make test equivalent)",
            command=planned,
            attempted_items=(planned,),
        ),
        observed=False,
        causal_parents=(linked_action.source_event_id,),
    )
    case = _case(ledger)
    assert "planned_verification_agent_linked" in {gap.code for gap in case.gaps}
    links = agent_linked_run_events(case.projection, ledger.prefix)
    assert links == frozenset({linked_action.source_event_id})
    results = case.projection.results
    linked_event = str(results[linked_result].source_event_id)
    stress_event = str(results[stress_result].source_event_id)
    action_event = str(linked_action.source_event_id)

    for refs in (
        (linked_event,),
        (str(_OBLIGATION), action_event),
        (action_event, linked_event),
        (linked_event, stress_event),
    ):
        challenge = _challenge(
            FindingKind.TASK_REQUIREMENT_UNMET, *refs, summary="The required case was skipped"
        )
        review = _review(case, challenge, phase="final", linked=links)
        assert [candidate.kind for candidate in review.candidates] == [
            FindingKind.TASK_REQUIREMENT_UNMET
        ], refs
        assert review.agent_criteria == 0

    # The agent's own run beyond that verification is still its own criterion ...
    probe = _challenge(
        FindingKind.TASK_REQUIREMENT_UNMET, stress_event, summary="The stress run fails"
    )
    assert [c.kind for c in _review(case, probe, phase="final", linked=links).candidates] == [
        FindingKind.AGENT_CRITERION_UNMET
    ]
    # ... unless the links could not be read: then nothing is narrowed.
    assert [c.kind for c in _review(case, probe, phase="final", linked=None).candidates] == [
        FindingKind.TASK_REQUIREMENT_UNMET
    ]


def test_ai_staleness_is_a_non_blocking_rerun_question() -> None:
    ledger = ObservedLedger()
    ledger.plan("pytest -q")
    result = ledger.passes("pytest -q")
    run_event, _ = ledger.events_of(result)
    ledger.edit()
    case = _case(ledger)
    challenge = _challenge(
        FindingKind.STALE_EVIDENCE_FOR_CHANGED_STATE,
        str(run_event),
        summary="Verification predates an edit",
    )
    judgment = SemanticJudgment("challenges_returned", (challenge,))
    review = validate_semantic_judgment(
        case, (), judgment, _provenance(), expected_frontier=case.frontier, review_phase="final"
    )
    assert len(review.candidates) == 1
    assert review.candidates[0].kind is FindingKind.DECISION_NEEDED
    assert review.candidates[0].summary == "Is a verification rerun needed after these changes?"
    # The reviewer's own summary is kept as detail (PR #1167 review).
    assert review.candidates[0].detail == (
        "Reviewer observation: Verification predates an edit"
        " Main agent: verification predates an edit."
    )
    assert review.candidates[0].challenge is not None
    assert review.candidates[0].challenge.requested_next_step == "answer_question"


def test_a_stale_evidence_concern_not_about_a_verification_run_keeps_its_kind_and_text() -> None:
    """PR #1167 review: only a verification-rerun concern becomes the rerun question."""

    ledger = ObservedLedger()
    ledger.plan("pytest -q")
    ledger.passes("pytest -q")
    edited = ledger.edit()
    edit_event, _ = ledger.events_of(edited)
    case = _case(ledger)
    challenge = _challenge(
        FindingKind.STALE_EVIDENCE_FOR_CHANGED_STATE,
        str(edit_event),
        summary="The cited edit evidence describes an older file state",
    )
    review = validate_semantic_judgment(
        case,
        (),
        SemanticJudgment("challenges_returned", (challenge,)),
        _provenance(),
        expected_frontier=case.frontier,
        review_phase="final",
    )
    assert [candidate.kind for candidate in review.candidates] == [
        FindingKind.STALE_EVIDENCE_FOR_CHANGED_STATE
    ]
    assert review.candidates[0].summary == "The cited edit evidence describes an older file state"
    assert review.candidates[0].detail == (
        "Main agent: the cited edit evidence describes an older file state."
    )
