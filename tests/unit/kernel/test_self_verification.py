"""Which open findings the agent may close as ``self_verified`` (issue #984, ADR-034).

The reason sets below are the ones tb4n1 agents met at closure: deterministic findings left
unresolved by ``command_attempt_uncorroborated``, ``content_redacted`` and
``observation_input_loss``, and AI-powered findings left unresolved by
``semantic_packet_insufficient`` and ``semantic_reference_scope_reduced``. Every one was a FinishUP
limit the agent could not repair, and the agents filed false ``finishup-blocker`` claims instead.
"""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace
from typing import cast

import pytest

from builders.policy_cases import evd, evt, finding_record, fnd, obl, record
from finishup.domain.events import (
    CheckMode,
    CheckRecordedPayload,
    LedgerRecord,
    PolicyVersion,
    ResponseRecordedPayload,
)
from finishup.domain.findings import (
    FINDING_KIND_TRAITS,
    SELF_VERIFIED_GUIDANCE,
    CheckVerdict,
    Finding,
    FindingKind,
    FindingOrigin,
    ResponseDisposition,
)
from finishup.domain.values import Frontier
from finishup.kernel.closure_readiness import (
    FINDING_SELF_VERIFIED_GAP,
    GAP_CLASSIFICATION,
    ClosureReadinessFacts,
    GapClass,
    derive_closure_readiness,
)
from finishup.kernel.finding_resolution import (
    UNRESOLVED_FINDING_NEXT_STEPS,
    finding_resolution_explanation,
)
from finishup.kernel.finding_todo import (
    TERMINAL_TODO_STATES,
    FindingTodoState,
    finding_blocks_receipt,
    finding_todo_state,
    todo_counts,
)
from finishup.kernel.projections import ProjectionState, StandingPosition, empty_projection_state
from finishup.kernel.self_verification import (
    FINDING_NOT_PROOF_LIMITED,
    FINDING_NOT_RECHECKED,
    finding_proof_limited,
    reasons_proof_limited,
    self_verification_blocking_reasons,
    self_verification_evaluation,
    self_verification_refusal,
)
from finishup.protocol.coverage import (
    ArtifactObservation,
    AuthorshipAssurance,
    CheckType,
    Coverage,
    EvidenceImmutability,
    LedgerFreshness,
    PublicationChannel,
)
from finishup.protocol.models import (
    CheckPolicyExecutionModel,
    CheckScopeModel,
    SemanticReason,
    SemanticStatus,
)

_DIGEST = "sha256:" + "4" * 64
_DET = FindingOrigin.DETERMINISTIC
_SEM = FindingOrigin.SEMANTIC_MODEL_DERIVED


def _coverage(gaps: tuple[str, ...] = ()) -> Coverage:
    return Coverage(
        publication_channels=(PublicationChannel.ENGINE_DERIVED,),
        authorship_assurance=AuthorshipAssurance.SERVICE_AUTHENTICATED,
        artifact_observation=ArtifactObservation.PUBLISHED_ONLY,
        evidence_immutability=EvidenceImmutability.METADATA_ONLY,
        ledger_freshness=LedgerFreshness.PARTIAL if gaps else LedgerFreshness.CURRENT,
        check_types=(CheckType.DETERMINISTIC,),
        known_gaps=tuple(sorted(gaps, key=str.encode)),
    )


def _finding(
    number: int = 1, kind: FindingKind = FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS
) -> Finding:
    return Finding(
        finding_id=fnd(number),
        kind=kind,
        origin=FindingOrigin.DETERMINISTIC,
        priority=FINDING_KIND_TRAITS[kind][0],
        summary="A completion claim covers an open obligation.",
        detail="Resolve or revise the obligation before claiming completion.",
        subject_refs=(obl(1),),
        policy_id="work-integrity",
        policy_version="0.1.0",
        subject_frontier=Frontier(3, _DIGEST),
        coverage=_coverage(),
        provenance=None,
    )


def _check(
    *, tested: int = 8, returned: tuple[object, ...] = (), gaps: tuple[str, ...] = ()
) -> CheckRecordedPayload:
    return CheckRecordedPayload(
        mode=CheckMode.DETERMINISTIC_ONLY,
        policies=(PolicyVersion("work-integrity", "0.1.0"),),
        scope=CheckScopeModel(claim_ids=(), obligation_ids=()),
        policy_executions=(
            CheckPolicyExecutionModel(
                policy_id="work-integrity",
                policy_version="0.1.0",
                outcome="run",
                reason="completed",
            ),
        ),
        subject_frontier=Frontier(tested, _DIGEST),
        verdict=CheckVerdict.ACTION_REQUIRED if returned else CheckVerdict.NO_ISSUE_DETECTED,
        returned_finding_ids=returned,  # type: ignore[arg-type]
        suppressed_count=0,
        coverage=_coverage(("semantic_review_not_requested", *gaps)),
        semantic_status=SemanticStatus.NOT_REQUESTED,
        semantic_reason=SemanticReason.DETERMINISTIC_MODE,
        engine_version="0.1.0",
        projection_version="yoetz/0.1.0",
        semantic_provenance=None,
    )


def _row(sequence: int, check: CheckRecordedPayload) -> object:
    return SimpleNamespace(
        event_id=evt(sequence),
        schema=SimpleNamespace(name="check_recorded"),
        ledger=SimpleNamespace(ingestion_sequence=sequence),
        payload=check,
    )


def _state(*findings: Finding, response: ResponseDisposition | None = None) -> ProjectionState:
    responses = {}
    if response is not None:
        responses[fnd(1)] = record(
            ResponseRecordedPayload(
                fnd(1),
                Frontier(4, _DIGEST),
                response,
                "Ran the suite myself; output recorded as evidence.",
                evidence_refs=(evd(1),),
            ),
            9,
        )
    return replace(
        empty_projection_state(),
        frontier=20,
        head_digest=_DIGEST,
        findings={finding.finding_id: finding_record(finding, 4) for finding in findings},
        responses=responses,
    )


def _records(*rows: object) -> tuple[LedgerRecord, ...]:
    return cast(tuple[LedgerRecord, ...], rows)


# -- The pure reason rule -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("origin", "reasons"),
    [
        # tb4n1 deterministic closures: every remaining reason is a standing FinishUP limit.
        (_DET, ("coverage:command_attempt_uncorroborated",)),
        (_DET, ("coverage:content_redacted",)),
        (_DET, ("coverage:observation_input_loss",)),
        (
            _DET,
            (
                "command_relation_independence_unproven",
                "freshness_or_original_proof_unreadable",
                "coverage:command_attempt_uncorroborated",
                "coverage:content_redacted",
                "coverage:observation_input_loss",
            ),
        ),
        # tb4n1 AI-powered closures: the review packet bounded what the reviewer could see.
        (_SEM, ("semantic_packet_insufficient", "coverage:semantic_reference_scope_reduced")),
        (_SEM, ("finding_material_outside_reduced_review_scope",)),
        (_SEM, ("reviewer_verdict_unassessable", "coverage:content_redacted")),
        # A reviewer that re-raised it from a limited packet does not positively see it.
        (_SEM, ("issue_returned_again", "semantic_packet_insufficient")),
        (_SEM, ("reviewer_verdict_still_present", "coverage:content_redacted")),
        (_SEM, ("reviewer_verdict_answered_not_fixed", "reviewer_assessment_incomplete")),
    ],
)
def test_only_finishup_limits_are_self_verifiable(
    origin: FindingOrigin, reasons: tuple[str, ...]
) -> None:
    assert reasons_proof_limited(reasons, origin) is True


def test_a_review_that_cannot_complete_is_a_limit_only_when_durable() -> None:
    reasons = ("semantic_review_not_completed", "coverage:semantic_relevance_review_not_run")
    # A policy, privacy or configuration block no retry removes: a FinishUP limit.
    assert reasons_proof_limited(reasons, _SEM, review_undeliverable=True) is True
    # A timeout, rate limit or unavailable transport is transient: run check again.
    assert reasons_proof_limited(reasons, _SEM) is False


@pytest.mark.parametrize(
    ("origin", "reasons"),
    [
        (_DET, ()),  # resolved, or no recorded limit at all
        (_DET, ("issue_returned_again", "coverage:content_redacted")),  # the rule fired again
        (_DET, ("coverage:command_attempt_mismatch",)),  # agent-actionable gap
        (_DET, ("coverage:missing_ref",)),
        (_DET, ("coverage:gap_from_a_newer_build",)),  # unknown codes stay agent work
        (_DET, ("matching_policy_not_completed",)),
        (_DET, ("subject_outside_checked_scope", "coverage:content_redacted")),
        (_DET, ("finding_not_in_checked_frontier",)),
        (_DET, ("check_unreadable",)),
        (_DET, ("returned_findings_unreadable",)),
        (_SEM, ("coverage:semantic_review_not_requested",)),  # route-dependent: run the review
        (_SEM, ("issue_returned_again",)),
        (_SEM, ("reviewer_verdict_still_present",)),
        (_SEM, ("reviewer_verdict_answered_not_fixed",)),
        (_SEM, ("no_material_change_since_finding", "coverage:content_redacted")),
        # A reviewer that saw the repair and still sees the issue is not overridden by an
        # unrelated capture loss or by freshness alone (adversarial review of #984).
        (_SEM, ("reviewer_verdict_still_present", "coverage:observation_input_loss")),
        (_SEM, ("issue_returned_again", "freshness_unproven")),
        # The check's ranking cap withheld findings: whether it fired again is unknown.
        (_DET, ("findings_suppressed", "coverage:content_redacted")),
        (_SEM, ("findings_suppressed", "semantic_packet_insufficient")),
    ],
)
def test_finishup_still_seeing_it_or_agent_work_is_refused(
    origin: FindingOrigin, reasons: tuple[str, ...]
) -> None:
    assert reasons_proof_limited(reasons, origin) is False


def test_a_new_standing_code_becomes_self_verifiable_through_the_classification_table() -> None:
    standing = sorted(
        code for code, kind in GAP_CLASSIFICATION.items() if kind is GapClass.STANDING_LIMITATION
    )
    actionable = sorted(
        code for code, kind in GAP_CLASSIFICATION.items() if kind is GapClass.AGENT_ACTIONABLE
    )
    assert "observation_input_loss" in standing
    for code in standing:
        assert reasons_proof_limited(("coverage:" + code,), _DET), code
    for code in actionable:
        assert not reasons_proof_limited(("coverage:" + code,), _DET), code


# -- The replay-derived predicate -----------------------------------------------------------


def test_no_later_check_is_finding_not_rechecked() -> None:
    state = _state(_finding())
    assert self_verification_refusal(state, fnd(1), ()) == FINDING_NOT_RECHECKED
    # The check that raised it tested a frontier before the finding's record.
    raising = _records(_row(5, _check(tested=3, returned=(fnd(1),))))
    assert self_verification_refusal(state, fnd(1), raising) == FINDING_NOT_RECHECKED
    assert finding_proof_limited(state, fnd(1), raising) is False


@pytest.mark.parametrize(
    "gaps",
    [
        ("command_attempt_uncorroborated",),
        # L2 #982: capture-time ``content_redacted`` no longer vetoes a local absence proof, so it
        # alone leaves nothing unproven; it stays a limit beside the others below.
        # Lead request: case-wide observation loss is a standing FinishUP limit.
        ("observation_input_loss",),
        ("command_attempt_uncorroborated", "content_redacted", "observation_input_loss"),
    ],
)
def test_a_repair_only_a_finishup_limit_keeps_unproven_is_eligible(gaps: tuple[str, ...]) -> None:
    # tb4n1's typical leftover: a requested-item finding raised before work started.
    state = _state(_finding(kind=FindingKind.REQUESTED_ITEM_NEVER_ATTEMPTED))
    records = _records(_row(10, _check(gaps=gaps)))
    assert self_verification_refusal(state, fnd(1), records) is None
    assert finding_proof_limited(state, fnd(1), records) is True


def test_a_rule_that_fired_again_is_not_proof_limited() -> None:
    again = replace(_finding(2), summary="The same issue, raised again.")
    state = _state(_finding(), again)
    records = _records(_row(10, _check(returned=(fnd(2),), gaps=("content_redacted",))))
    assert self_verification_refusal(state, fnd(1), records) == FINDING_NOT_PROOF_LIMITED


def test_an_agent_actionable_gap_or_a_clean_check_is_not_proof_limited() -> None:
    state = _state(_finding())
    actionable = _records(_row(10, _check(gaps=("missing_ref",))))
    assert self_verification_refusal(state, fnd(1), actionable) == FINDING_NOT_PROOF_LIMITED
    clean = _records(_row(10, _check()))
    assert self_verification_refusal(state, fnd(1), clean) == FINDING_NOT_PROOF_LIMITED


# -- To-do state, readiness and the explanation ---------------------------------------------


def test_self_verified_is_terminal_disclosed_and_not_agent_work() -> None:
    state = _state(_finding(), response=ResponseDisposition.SELF_VERIFIED)
    assert finding_todo_state(state, fnd(1)) is FindingTodoState.SELF_VERIFIED
    assert FindingTodoState.SELF_VERIFIED in TERMINAL_TODO_STATES
    assert finding_blocks_receipt(state, fnd(1)) is False
    counts = todo_counts(state, (fnd(1),))
    assert (counts.self_verified, counts.open) == (1, 0)
    explanation = finding_resolution_explanation(state, fnd(1), ())
    assert explanation.startswith("Self-verified by the agent")
    assert "cannot read clean" in explanation
    assert "agent repaired this" not in explanation


def test_self_verified_rebuttal_describes_a_disproved_concern_without_claiming_a_repair() -> None:
    state = _state(_finding(), response=ResponseDisposition.SELF_VERIFIED)
    row = replace(state.findings[fnd(1)], standing_position=StandingPosition("rejected", 8))
    state = replace(state, findings={fnd(1): row})
    explanation = finding_resolution_explanation(state, fnd(1), ())
    assert "reports that it does not hold" in explanation
    assert "agent repaired this" not in explanation
    assert "cannot read clean" in explanation


def test_readiness_discloses_self_verified_findings_as_a_standing_limitation() -> None:
    facts = ClosureReadinessFacts(
        check_applicability="applicable",
        semantic_review_current=False,
        receipt_blocking_finding_ids=(),
        acknowledged_finding_ids=(),
        acknowledged_obligation_ids=(),
        self_verified_finding_ids=(fnd(1),),
    )
    split = derive_closure_readiness((), (), facts, semantic_review_required=False)
    assert split.state == "ready_with_limitations"
    assert split.agent_actionable == ()
    assert split.standing_limitations == (FINDING_SELF_VERIFIED_GAP,)
    assert GAP_CLASSIFICATION[FINDING_SELF_VERIFIED_GAP] is GapClass.STANDING_LIMITATION


def test_receipt_findings_unresolved_drops_when_every_blocking_item_is_settled() -> None:
    facts = ClosureReadinessFacts(
        check_applicability="applicable",
        semantic_review_current=False,
        receipt_blocking_finding_ids=(fnd(1), fnd(2)),
        acknowledged_finding_ids=(fnd(1),),
        acknowledged_obligation_ids=(),
        self_verified_finding_ids=(fnd(2),),
    )
    split = derive_closure_readiness(
        ("receipt_findings_unresolved",), (), facts, semantic_review_required=False
    )
    assert "receipt_findings_unresolved" not in split.agent_actionable
    assert split.state == "ready_with_limitations"
    open_one = replace(facts, self_verified_finding_ids=())
    split = derive_closure_readiness(
        ("receipt_findings_unresolved",), (), open_one, semantic_review_required=False
    )
    assert split.agent_actionable == ("receipt_findings_unresolved",)


def test_eligible_explanation_offers_self_verification_with_its_non_clean_meaning() -> None:
    state = _state(_finding())
    records = _records(_row(10, _check(gaps=("observation_input_loss",))))
    explanation = finding_resolution_explanation(state, fnd(1), records)
    assert "coverage:observation_input_loss" in explanation
    assert explanation.endswith(UNRESOLVED_FINDING_NEXT_STEPS)
    assert SELF_VERIFIED_GUIDANCE in explanation
    assert "Self-verification is available now" in explanation
    assert "repair it, then check" not in explanation
    assert "cannot read clean" in explanation
    assert "never a `finishup-blocker`" in explanation


@pytest.mark.parametrize(
    "gap",
    ["gap_from_a_newer_build", "missing_ref"],
)
def test_refused_explanation_names_the_same_current_conditions_as_respond(gap: str) -> None:
    state = _state(_finding())
    records = _records(_row(10, _check(gaps=(gap,))))
    refusal, blocking = self_verification_evaluation(state, fnd(1), records)
    assert refusal == self_verification_refusal(state, fnd(1), records)
    assert blocking == self_verification_blocking_reasons(state, fnd(1), records)
    assert "coverage:" + gap in blocking
    explanation = finding_resolution_explanation(state, fnd(1), records)
    assert "Self-verification is unavailable now: finding_not_proof_limited" in explanation
    assert all(reason in explanation for reason in blocking)
    assert SELF_VERIFIED_GUIDANCE not in explanation
    assert "repair it, then check" not in explanation
    assert "repeating the same repair" in explanation


def test_no_later_check_guidance_reports_actual_unavailability() -> None:
    explanation = finding_resolution_explanation(_state(_finding()), fnd(1), ())
    assert "Self-verification is unavailable now: finding_not_rechecked" in explanation
    assert SELF_VERIFIED_GUIDANCE not in explanation


@pytest.mark.parametrize("unreadable", ["check", "returned_findings"])
def test_unreadable_proof_guidance_reports_the_actual_refusal(unreadable: str) -> None:
    state = _state(_finding())
    check = _check(returned=(fnd(2),) if unreadable == "returned_findings" else ())
    if unreadable == "check":
        state = replace(state, coverage_gaps=(f"redacted_event:{evt(10)}",))
    records = _records(_row(10, check))
    refusal, blocking = self_verification_evaluation(state, fnd(1), records)
    assert refusal == FINDING_NOT_PROOF_LIMITED
    assert blocking == (unreadable + "_unreadable",)
    explanation = finding_resolution_explanation(state, fnd(1), records)
    assert "Self-verification is unavailable now" in explanation
    assert blocking[0] in explanation
    assert SELF_VERIFIED_GUIDANCE not in explanation


def test_guidance_display_bound_never_truncates_the_eligibility_calculation() -> None:
    state = _state(_finding())
    gaps = tuple(f"unknown_gap_{index:02}" for index in range(40))
    records = _records(_row(10, _check(gaps=gaps)))
    explanation = finding_resolution_explanation(state, fnd(1), records)
    assert "additional conditions omitted" in explanation
    assert self_verification_blocking_reasons(state, fnd(1), records) == tuple(
        "coverage:" + gap for gap in gaps
    )
    assert self_verification_refusal(state, fnd(1), records) == FINDING_NOT_PROOF_LIMITED


def test_terminal_self_verified_never_offers_another_response() -> None:
    state = _state(_finding(), response=ResponseDisposition.SELF_VERIFIED)
    records = _records(_row(10, _check(gaps=("observation_input_loss",))))
    explanation = finding_resolution_explanation(state, fnd(1), records)
    assert "The item is final" in explanation
    assert "Self-verification is available now" not in explanation
    assert SELF_VERIFIED_GUIDANCE not in explanation


# -- A later positive sighting is never hidden under the terminal row (adversarial review) ---


def test_a_rule_that_fires_again_after_self_verification_mints_a_new_finding() -> None:
    from finishup.application.check import prior_finding_ids

    finding = _finding()
    key = (finding.kind, finding.policy_id, finding.subject_refs)
    assert prior_finding_ids(_state(finding)) == {key: fnd(1)}
    # Self-verified: the re-derivation must not land silently on the terminal row; it takes a
    # fresh id the agent must answer.
    answered = _state(finding, response=ResponseDisposition.SELF_VERIFIED)
    assert prior_finding_ids(answered) == {}
    # Acknowledged-not-done keeps converging on its row: the agent said it will not do it.
    acknowledged = _state(finding, response=ResponseDisposition.ACKNOWLEDGED_NOT_DONE)
    assert prior_finding_ids(acknowledged) == {key: fnd(1)}
