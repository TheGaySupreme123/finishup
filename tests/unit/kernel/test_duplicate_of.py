"""``respond duplicate_of``: a re-raised finding linked to an earlier one (issue #996).

tb4n1 (D5, #980): reviewer concerns re-raised as new findings were answered again and again
(music-harmony semantic: 34 publishes and 50 status calls after the gate). ``restates`` links a
re-raise automatically when the reviewer cites the earlier finding; ``duplicate_of`` covers what
that misses. While the link holds the duplicate's to-do state is derived from the earlier finding,
the pair counts once, and a later check that raises the duplicate's issue again breaks the link.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from typing import cast

import pytest

from builders.policy_cases import evt, finding_record, fnd, obl, record
from yoetz.domain.events import (
    CheckMode,
    CheckRecordedPayload,
    EventSchema,
    PolicyVersion,
    ResponseRecordedPayload,
    decode_payload,
    encode_payload,
)
from yoetz.domain.findings import (
    FINDING_KIND_TRAITS,
    CheckVerdict,
    Finding,
    FindingKind,
    FindingOrigin,
    PriorFindingVerdictRecord,
    ResponseDisposition,
    SemanticDispatchKind,
    SemanticProvenance,
)
from yoetz.domain.values import FindingId, Frontier, evidence_id
from yoetz.kernel.closure_readiness import closure_readiness_facts
from yoetz.kernel.finding_resolution import (
    apply_check_rulings,
    finding_is_resolved,
    reopen_findings_resolved_by,
)
from yoetz.kernel.finding_todo import (
    FindingTodoState,
    duplicate_counting_id,
    duplicate_link_target,
    duplicate_root,
    finding_blocks_receipt,
    finding_todo_state,
)
from yoetz.kernel.projections import (
    FindingProjectionRecord,
    ProjectionRecord,
    ProjectionState,
    empty_projection_state,
    projection_from_snapshot,
    projection_snapshot,
    unanswered_finding_ids,
)
from yoetz.kernel.receipt_capacity import receipt_blocking_finding_count
from yoetz.ports.semantic import SamplingParams
from yoetz.protocol.canonical import canonical_encode
from yoetz.protocol.coverage import (
    ArtifactObservation,
    AuthorshipAssurance,
    CheckType,
    Coverage,
    EvidenceImmutability,
    LedgerFreshness,
    PublicationChannel,
)
from yoetz.protocol.errors import ProtocolValueError
from yoetz.protocol.models import (
    CheckPolicyExecutionModel,
    CheckScopeModel,
    SemanticReason,
    SemanticStatus,
)

_DIGEST = "sha256:" + "3" * 64


def _coverage() -> Coverage:
    return Coverage(
        publication_channels=(PublicationChannel.ENGINE_DERIVED,),
        authorship_assurance=AuthorshipAssurance.SERVICE_AUTHENTICATED,
        artifact_observation=ArtifactObservation.PUBLISHED_ONLY,
        evidence_immutability=EvidenceImmutability.METADATA_ONLY,
        ledger_freshness=LedgerFreshness.CURRENT,
        check_types=(CheckType.DETERMINISTIC,),
        known_gaps=(),
    )


def _finding(
    number: int,
    *,
    subject: int | None = None,
    origin: FindingOrigin = FindingOrigin.DETERMINISTIC,
) -> Finding:
    kind = FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS
    return Finding(
        finding_id=fnd(number),
        kind=kind,
        origin=origin,
        priority=FINDING_KIND_TRAITS[kind][0],
        summary="A completion claim covers an open obligation.",
        detail="Resolve or revise the obligation before claiming completion.",
        subject_refs=(obl(number if subject is None else subject),),
        policy_id="work-integrity",
        policy_version="0.1.0",
        subject_frontier=Frontier(3, _DIGEST),
        coverage=_coverage(),
        provenance=None,
    )


def _semantic(number: int, *, subject: int) -> Finding:
    provenance = SemanticProvenance(
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
        semantic_attempt_id="att_00000000-0000-4000-8000-000000000001",
        dispatch_kind=SemanticDispatchKind.EXTERNAL,
        privacy_receipt_id="egr_00000000-0000-4000-8000-000000000001",
        status=SemanticStatus.SUCCEEDED,
        reason=SemanticReason.SEMANTIC_COMPLETED,
        provider_request_id="fake-1",
        egress_authorization_id="aut_00000000-0000-4000-8000-000000000001",
        request_commitment="hmac-sha256:" + "b" * 64,
    )
    base = _finding(number, subject=subject)
    return replace(
        base,
        origin=FindingOrigin.SEMANTIC_MODEL_DERIVED,
        coverage=replace(
            _coverage(), check_types=(CheckType.DETERMINISTIC, CheckType.SEMANTIC_MODEL_DERIVED)
        ),
        provenance=provenance,
    )


def _check(
    *,
    returned: tuple[object, ...] = (),
    rulings: tuple[tuple[int, str], ...] = (),
) -> CheckRecordedPayload:
    # The fold reads only these fields, so skip semantic validation (as test_finding_todo does).
    payload = object.__new__(CheckRecordedPayload)
    for name, value in (
        ("mode", CheckMode.DETERMINISTIC_ONLY),
        ("policies", (PolicyVersion("work-integrity", "0.1.0"),)),
        ("scope", CheckScopeModel(claim_ids=(), obligation_ids=())),
        (
            "policy_executions",
            (
                CheckPolicyExecutionModel(
                    policy_id="work-integrity",
                    policy_version="0.1.0",
                    outcome="run",
                    reason="completed",
                ),
            ),
        ),
        ("subject_frontier", Frontier(8, _DIGEST)),
        ("verdict", CheckVerdict.ACTION_REQUIRED if returned else CheckVerdict.NO_ISSUE_DETECTED),
        ("returned_finding_ids", returned),
        ("suppressed_count", 1),
        ("coverage", _coverage()),
        ("semantic_status", SemanticStatus.NOT_REQUESTED),
        ("semantic_reason", SemanticReason.DETERMINISTIC_MODE),
        ("engine_version", "0.1.0"),
        ("projection_version", "yoetz/0.1.0"),
        ("semantic_provenance", None),
        ("semantic_conclusion", None),
        (
            "prior_finding_verdicts",
            tuple(
                PriorFindingVerdictRecord(fnd(number), verdict, ()) for number, verdict in rulings
            ),
        ),
    ):
        object.__setattr__(payload, name, value)
    return payload


def _answer(
    number: int, disposition: ResponseDisposition, *, at: int = 10
) -> ProjectionRecord[ResponseRecordedPayload]:
    reason = None if disposition is ResponseDisposition.ACKNOWLEDGED else "A recorded reason."
    evidence = (
        (evidence_id("evd_00000000-0000-4000-8000-000000000996"),)
        if disposition is ResponseDisposition.SELF_VERIFIED
        else ()
    )
    return record(
        ResponseRecordedPayload(
            fnd(number), Frontier(5, _DIGEST), disposition, reason, evidence_refs=evidence
        ),
        at,
    )


def _link(number: int, target: int, *, at: int = 11) -> ProjectionRecord[ResponseRecordedPayload]:
    return record(
        ResponseRecordedPayload(
            fnd(number),
            Frontier(5, _DIGEST),
            ResponseDisposition.DUPLICATE_OF,
            duplicate_of_finding_id=fnd(target),
        ),
        at,
    )


def _state(
    findings: Mapping[FindingId, FindingProjectionRecord],
    responses: Mapping[FindingId, ProjectionRecord[ResponseRecordedPayload]],
) -> ProjectionState:
    return replace(
        empty_projection_state(),
        frontier=20,
        head_digest=_DIGEST,
        findings=findings,
        responses=responses,
        freshness=LedgerFreshness.CURRENT,
    )


def _pair(
    target: FindingProjectionRecord | None = None,
    target_answer: ProjectionRecord[ResponseRecordedPayload] | None = None,
) -> ProjectionState:
    findings = {
        fnd(1): finding_record(_finding(1), 4) if target is None else target,
        fnd(2): finding_record(_finding(2), 6),
    }
    responses = {fnd(2): _link(2, 1)}
    if target_answer is not None:
        responses[fnd(1)] = target_answer
    return _state(findings, responses)


def test_the_payload_carries_the_target_only_for_duplicate_of_and_rides_1_1_0() -> None:
    linked = _link(2, 1).payload
    assert linked is not None
    encoded = encode_payload(linked)
    assert cast(Mapping[str, object], encoded)["duplicate_of_finding_id"] == fnd(1)
    assert decode_payload(EventSchema("response_recorded", "1.1.0"), encoded) == linked
    # duplicate_of without its target, and a finding named as its own duplicate.
    for bad in (None, fnd(2)):
        with pytest.raises(ProtocolValueError):
            ResponseRecordedPayload(
                fnd(2),
                Frontier(5, _DIGEST),
                ResponseDisposition.DUPLICATE_OF,
                duplicate_of_finding_id=bad,
            )
    with pytest.raises(ProtocolValueError):
        ResponseRecordedPayload(
            fnd(2),
            Frontier(5, _DIGEST),
            ResponseDisposition.REJECTED,
            "Not mine.",
            duplicate_of_finding_id=fnd(1),
        )


@pytest.mark.parametrize(
    ("target", "answer", "root_state", "duplicate_state"),
    (
        (None, None, FindingTodoState.OPEN, FindingTodoState.OPEN),
        # Resolution and an accepted rejection are never inherited (B1): a distinct finding must
        # not read clean through somebody else's proof.
        (
            finding_record(_finding(1), 4, resolved_by_check_event_id=evt(9)),
            None,
            FindingTodoState.VERIFIED_RESOLVED,
            FindingTodoState.OPEN,
        ),
        (
            replace(finding_record(_finding(1), 4), rejection_accepted_by_check_event_id=evt(9)),
            _answer(1, ResponseDisposition.REJECTED),
            FindingTodoState.REJECTION_ACCEPTED,
            FindingTodoState.OPEN,
        ),
        # The never-clean final answers are inherited.
        (
            None,
            _answer(1, ResponseDisposition.SELF_VERIFIED),
            FindingTodoState.SELF_VERIFIED,
            FindingTodoState.SELF_VERIFIED,
        ),
        (
            None,
            _answer(1, ResponseDisposition.ACKNOWLEDGED_NOT_DONE),
            FindingTodoState.ACKNOWLEDGED_NOT_DONE,
            FindingTodoState.ACKNOWLEDGED_NOT_DONE,
        ),
    ),
)
def test_a_linked_duplicate_inherits_only_never_clean_states(
    target: FindingProjectionRecord | None,
    answer: ProjectionRecord[ResponseRecordedPayload] | None,
    root_state: FindingTodoState,
    duplicate_state: FindingTodoState,
) -> None:
    state = _pair(target, answer)
    assert duplicate_link_target(state, fnd(2)) == fnd(1)
    assert finding_todo_state(state, fnd(1)) is root_state
    assert finding_todo_state(state, fnd(2)) is duplicate_state
    assert finding_is_resolved(state, fnd(2)) is False
    if root_state in {FindingTodoState.VERIFIED_RESOLVED, FindingTodoState.REJECTION_ACCEPTED}:
        # The open duplicate counts on its own, never hidden behind the settled earlier one.
        assert finding_blocks_receipt(state, fnd(2)) is True
        assert duplicate_counting_id(state, fnd(2)) == fnd(2)
        assert receipt_blocking_finding_count(state) == 1
        assert closure_readiness_facts(state, ()).receipt_blocking_finding_ids == (fnd(2),)


def test_a_link_to_a_different_kind_or_origin_never_holds() -> None:
    other_kind = replace(_finding(1), kind=FindingKind.CLAIM_WITHOUT_ADMISSIBLE_EVIDENCE)
    findings = {fnd(1): finding_record(other_kind, 4), fnd(2): finding_record(_finding(2), 6)}
    state = _state(findings, {fnd(2): _link(2, 1)})
    assert duplicate_link_target(state, fnd(2)) is None
    assert fnd(2) in unanswered_finding_ids(state, ())
    semantic = {
        fnd(1): finding_record(_semantic(1, subject=1), 4),
        fnd(2): finding_record(_finding(2), 6),
    }
    assert duplicate_link_target(_state(semantic, {fnd(2): _link(2, 1)}), fnd(2)) is None


def test_a_non_actionable_earlier_finding_never_names_an_actionable_duplicate() -> None:
    # Admission refuses a different kind; the counting rule still never hides an actionable
    # duplicate behind a non-actionable root.
    state = _pair()
    assert duplicate_counting_id(state, fnd(2)) == fnd(1)
    assert duplicate_counting_id(state, fnd(1)) == fnd(1)


def test_an_open_pair_counts_once_and_needs_one_answer() -> None:
    state = _pair()
    assert finding_todo_state(state, fnd(2)) is FindingTodoState.OPEN
    assert receipt_blocking_finding_count(state) == 1
    assert unanswered_finding_ids(state, ()) == frozenset({fnd(1)})
    facts = closure_readiness_facts(state, ())
    assert facts.receipt_blocking_finding_ids == (fnd(1),)
    # Answering the earlier finding answers both.
    answered = _pair(target_answer=_answer(1, ResponseDisposition.ACKNOWLEDGED_NOT_DONE))
    assert unanswered_finding_ids(answered, ()) == frozenset()
    facts = closure_readiness_facts(answered, ())
    assert facts.receipt_blocking_finding_ids == (fnd(1),)
    assert facts.acknowledged_finding_ids == (fnd(1),)


def test_the_duplicates_own_proof_still_counts_but_nothing_else_reads_cleaner() -> None:
    state = _pair()
    own = dict(state.findings)
    own[fnd(2)] = finding_record(_finding(2), 6, resolved_by_check_event_id=evt(9))
    proven = _state(own, dict(state.responses))
    assert finding_todo_state(proven, fnd(2)) is FindingTodoState.VERIFIED_RESOLVED
    assert finding_todo_state(proven, fnd(1)) is FindingTodoState.OPEN


def test_a_chain_formed_later_resolves_to_its_root_and_a_redacted_root_drops_the_link() -> None:
    findings = {
        fnd(1): finding_record(_finding(1), 4),
        fnd(2): finding_record(_finding(2), 6),
        fnd(3): finding_record(_finding(3), 7),
    }
    # 3 was linked to 2 first; 2 was linked to 1 afterwards.
    responses = {
        fnd(3): _link(3, 2, at=11),
        fnd(2): _link(2, 1, at=12),
        fnd(1): _answer(1, ResponseDisposition.ACKNOWLEDGED_NOT_DONE, at=13),
    }
    state = _state(findings, responses)
    assert duplicate_root(state, fnd(3)) == fnd(1)
    assert finding_todo_state(state, fnd(3)) is FindingTodoState.ACKNOWLEDGED_NOT_DONE
    assert receipt_blocking_finding_count(state) == 1
    redacted = dict(findings)
    redacted[fnd(1)] = FindingProjectionRecord(
        payload=None,
        payload_digest=findings[fnd(1)].payload_digest,
        redacted=True,
        source_event_id=evt(4),
        source_frontier=4,
    )
    unlinked = _state(redacted, responses)
    assert duplicate_link_target(unlinked, fnd(2)) is None
    assert finding_todo_state(unlinked, fnd(2)) is FindingTodoState.OPEN
    # A redacted root leaves the duplicate needing its own answer.
    assert fnd(2) in unanswered_finding_ids(unlinked, ())


def test_a_link_to_a_later_finding_never_holds() -> None:
    findings = {fnd(1): finding_record(_finding(1), 6), fnd(2): finding_record(_finding(2), 4)}
    state = _state(findings, {fnd(2): _link(2, 1)})
    assert duplicate_link_target(state, fnd(2)) is None


@pytest.mark.parametrize(
    ("check", "breaks"),
    (
        (_check(returned=(fnd(2),)), True),  # the check returned the duplicate again
        (_check(rulings=((2, "still_present"),)), True),
        (_check(rulings=((2, "answered_not_fixed"),)), True),
        (_check(rulings=((2, "fixed"),)), False),
        (_check(returned=(fnd(1),)), False),  # the earlier finding's own, distinct issue
        (_check(), False),
    ),
)
def test_a_later_check_that_raises_the_issue_again_breaks_the_link(
    check: CheckRecordedPayload, breaks: bool
) -> None:
    state = _pair()
    findings = dict(state.findings)
    apply_check_rulings(findings, state.responses, check, evt(15))
    assert (findings[fnd(2)].duplicate_link_broken_by_check_event_ids == (evt(15),)) is breaks
    after = _state(findings, dict(state.responses))
    assert (duplicate_link_target(after, fnd(2)) is None) is breaks
    if breaks:
        # The response no longer applies: the duplicate needs its own answer and counts alone.
        assert fnd(2) in unanswered_finding_ids(after, ())
        assert receipt_blocking_finding_count(after) == 2


def test_a_local_rule_firing_again_on_the_same_subject_breaks_the_link() -> None:
    findings = {
        fnd(1): finding_record(_finding(1), 4),
        fnd(2): finding_record(_finding(2, subject=1), 6),  # same issue key as fnd(1)
    }
    responses = {fnd(2): _link(2, 1)}
    apply_check_rulings(findings, responses, _check(returned=(fnd(1),)), evt(15))
    assert findings[fnd(2)].duplicate_link_broken_by_check_event_ids == (evt(15),)


def test_an_ai_powered_issue_key_alone_never_breaks_a_link() -> None:
    findings = {
        fnd(1): finding_record(_semantic(1, subject=1), 4),
        fnd(2): finding_record(_finding(2, subject=1), 6),
        fnd(3): finding_record(_semantic(3, subject=1), 7),
    }
    responses = {fnd(3): _link(3, 1)}
    apply_check_rulings(findings, responses, _check(returned=(fnd(1), fnd(2))), evt(15))
    assert findings[fnd(3)].duplicate_link_broken_by_check_event_ids == ()


def test_redacting_one_breaking_check_keeps_the_link_broken_while_another_remains() -> None:
    """S1: the break is recomputed from every remaining readable check, as a full replay is."""

    state = _pair()
    findings = dict(state.findings)
    apply_check_rulings(findings, state.responses, _check(returned=(fnd(2),)), evt(15))
    apply_check_rulings(findings, state.responses, _check(rulings=((2, "still_present"),)), evt(16))
    assert findings[fnd(2)].duplicate_link_broken_by_check_event_ids == (evt(15), evt(16))
    broken = _state(findings, dict(state.responses))
    snapshot = projection_snapshot(broken)
    rows = snapshot["findings"]
    assert isinstance(rows, dict)
    assert "duplicate_link_broken_by_check_event_ids" not in rows[fnd(1)]  # type: ignore[operator]
    decoded = projection_from_snapshot(snapshot)
    assert decoded == broken
    assert canonical_encode(projection_snapshot(decoded)) == canonical_encode(snapshot)
    reopen_findings_resolved_by(findings, frozenset({evt(15)}))
    assert findings[fnd(2)].duplicate_link_broken_by_check_event_ids == (evt(16),)
    assert duplicate_link_target(_state(findings, dict(state.responses)), fnd(2)) is None
    reopen_findings_resolved_by(findings, frozenset({evt(16)}))
    assert duplicate_link_target(_state(findings, dict(state.responses)), fnd(2)) == fnd(1)
