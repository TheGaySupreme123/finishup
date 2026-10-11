"""Findings as a converging to-do list: terminal states and review rounds (issue #905)."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace

import pytest

from builders.policy_cases import evt, finding_record, fnd, obl, record
from yoetz.domain.events import (
    CheckMode,
    CheckRecordedPayload,
    EventDraft,
    EventSchema,
    PolicyVersion,
    ResponseRecordedPayload,
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
from yoetz.domain.values import FindingId, Frontier, timestamp_from_string
from yoetz.kernel.finding_resolution import (
    apply_check_resolution,
    apply_check_rulings,
    finding_is_resolved,
    reopen_findings_resolved_by,
)
from yoetz.kernel.finding_todo import (
    ABSOLUTELY_FINAL_TODO_STATES,
    TERMINAL_TODO_STATES,
    TODO_TRANSITIONS,
    FindingTodoState,
    finding_blocks_receipt,
    finding_todo,
    finding_todo_state,
    todo_counts,
)
from yoetz.kernel.projections import (
    DecisionProjectionRecord,
    FindingProjectionRecord,
    ProjectionRecord,
    ProjectionState,
    empty_projection_state,
    projection_from_snapshot,
    projection_snapshot,
)
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


def _finding(number: int, origin: FindingOrigin = FindingOrigin.DETERMINISTIC) -> Finding:
    kind = FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS
    return Finding(
        finding_id=fnd(number),
        kind=kind,
        origin=origin,
        priority=FINDING_KIND_TRAITS[kind][0],
        summary="A completion claim covers an open obligation.",
        detail="Resolve or revise the obligation before claiming completion.",
        subject_refs=(obl(number),),
        policy_id="work-integrity",
        policy_version="0.1.0",
        subject_frontier=Frontier(3, _DIGEST),
        coverage=_coverage(),
        provenance=None,
    )


def _semantic(number: int) -> Finding:
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
    coverage = replace(
        _coverage(), check_types=(CheckType.DETERMINISTIC, CheckType.SEMANTIC_MODEL_DERIVED)
    )
    base = _finding(number)
    return Finding(
        finding_id=base.finding_id,
        kind=base.kind,
        origin=FindingOrigin.SEMANTIC_MODEL_DERIVED,
        priority=base.priority,
        summary=base.summary,
        detail=base.detail,
        subject_refs=base.subject_refs,
        policy_id=base.policy_id,
        policy_version=base.policy_version,
        subject_frontier=base.subject_frontier,
        coverage=coverage,
        provenance=provenance,
    )


def _check(
    *,
    tested: int = 8,
    returned: tuple[object, ...] = (),
    rulings: tuple[tuple[int, str], ...] = (),
) -> CheckRecordedPayload:
    # ``model_construct`` style: the fold reads only these fields, so skip semantic validation.
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
        ("subject_frontier", Frontier(tested, _DIGEST)),
        ("verdict", CheckVerdict.ACTION_REQUIRED if returned else CheckVerdict.NO_ISSUE_DETECTED),
        ("returned_finding_ids", returned),
        ("suppressed_count", 1),  # suppression keeps ``apply_check_resolution`` from proving
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


def _response(
    number: int, disposition: ResponseDisposition
) -> ProjectionRecord[ResponseRecordedPayload]:
    reason = None if disposition is ResponseDisposition.ACKNOWLEDGED else "A recorded reason."
    return record(
        ResponseRecordedPayload(fnd(number), Frontier(5, _DIGEST), disposition, reason), 6
    )


def _state(
    findings: Mapping[FindingId, FindingProjectionRecord],
    responses: Mapping[FindingId, ProjectionRecord[ResponseRecordedPayload]] | None = None,
) -> ProjectionState:
    return replace(
        empty_projection_state(),
        frontier=20,
        head_digest=_DIGEST,
        findings=findings,
        responses={} if responses is None else responses,
        freshness=LedgerFreshness.CURRENT,
    )


def test_the_transition_table_is_data_and_only_the_agents_never_clean_answers_have_an_exit() -> (
    None
):
    """tb4n3 RC-7 (#1030, owner decision 8): the table gained the reverse edges out of
    ``acknowledged_not_done`` and ``self_verified``; the three absolutely final states have none."""

    open_exits = {
        target for source, _cause, target in TODO_TRANSITIONS if source is FindingTodoState.OPEN
    }
    assert open_exits == set(TERMINAL_TODO_STATES)
    leaving_terminal = {
        (source, target)
        for source, _cause, target in TODO_TRANSITIONS
        if source is not FindingTodoState.OPEN
    }
    assert leaving_terminal == {
        (FindingTodoState.ACKNOWLEDGED_NOT_DONE, FindingTodoState.OPEN),
        (FindingTodoState.ACKNOWLEDGED_NOT_DONE, FindingTodoState.VERIFIED_RESOLVED),
        (FindingTodoState.SELF_VERIFIED, FindingTodoState.VERIFIED_RESOLVED),
    }
    assert {
        FindingTodoState.VERIFIED_RESOLVED,
        FindingTodoState.REJECTION_ACCEPTED,
        FindingTodoState.DISPUTED_AFTER_REBUTTAL,
    } == ABSOLUTELY_FINAL_TODO_STATES
    assert FindingTodoState.OPEN not in TERMINAL_TODO_STATES


def test_a_local_finding_returned_again_over_later_state_counts_one_round() -> None:
    findings = {fnd(1): finding_record(_finding(1), 4)}
    raising = _check(tested=3, returned=(fnd(1),))  # the check that raised it: same subject
    apply_check_rulings(findings, {}, raising, evt(9))
    assert findings[fnd(1)].review_rounds == 0
    for event in (10, 11):
        apply_check_rulings(findings, {}, _check(returned=(fnd(1),)), evt(event))
    assert findings[fnd(1)].review_rounds == 2
    todo = finding_todo(_state(dict(findings)), fnd(1), attempt_budget=2)
    assert todo.state is FindingTodoState.OPEN and todo.budget_reached


@pytest.mark.parametrize("verdict", ["still_present", "answered_not_fixed", "unassessable"])
def test_an_open_ruling_counts_a_round_and_never_closes(verdict: str) -> None:
    findings = {fnd(1): finding_record(_semantic(1), 4)}
    apply_check_rulings(findings, {}, _check(rulings=((1, verdict),)), evt(9))
    assert findings[fnd(1)].review_rounds == 1
    assert finding_todo_state(_state(dict(findings)), fnd(1)) is FindingTodoState.OPEN


def test_withdrawn_latches_only_after_a_readable_rejection() -> None:
    findings = {
        fnd(1): finding_record(_semantic(1), 4),
        fnd(2): finding_record(_semantic(2), 4),
    }
    responses = {
        fnd(1): _response(1, ResponseDisposition.REJECTED),
        fnd(2): _response(2, ResponseDisposition.ACKNOWLEDGED),
    }
    apply_check_rulings(
        findings, responses, _check(rulings=((1, "withdrawn"), (2, "withdrawn"))), evt(9)
    )
    assert findings[fnd(1)].rejection_accepted_by_check_event_id == evt(9)
    assert findings[fnd(2)].rejection_accepted_by_check_event_id is None
    state = _state(dict(findings), dict(responses))
    assert finding_todo_state(state, fnd(1)) is FindingTodoState.REJECTION_ACCEPTED
    assert finding_blocks_receipt(state, fnd(1)) is False
    assert finding_blocks_receipt(state, fnd(2)) is True
    assert todo_counts(state, (fnd(1), fnd(2))).rejection_accepted == 1


def test_an_explicit_withdrawn_outranks_the_same_checks_absence_proof() -> None:
    """PR #943 review P1: one check, two terminal outcomes; the reviewer's explicit ruling wins.

    ``apply_check_resolution`` runs first and may mark a rejected AI-powered finding resolved by
    the very check that rules it ``withdrawn``. The ruling fold then records the reasoned
    rejection as accepted and drops that same-check absence mark, so the item has exactly one
    final state. An item an *earlier* check already proved absent stays verified: done is done.
    """

    rejected = {
        fnd(1): _response(1, ResponseDisposition.REJECTED),
        fnd(2): _response(2, ResponseDisposition.REJECTED),
        fnd(3): _response(3, ResponseDisposition.ACKNOWLEDGED),
    }
    findings = {
        # As ``apply_check_resolution`` leaves them for check evt(9).
        fnd(1): finding_record(_semantic(1), 4, resolved_by_check_event_id=evt(9)),
        fnd(2): finding_record(_semantic(2), 4, resolved_by_check_event_id=evt(8)),
        fnd(3): finding_record(_semantic(3), 4, resolved_by_check_event_id=evt(9)),
    }
    check = _check(rulings=((1, "withdrawn"), (2, "withdrawn"), (3, "withdrawn")))
    apply_check_rulings(findings, rejected, check, evt(9))

    assert findings[fnd(1)].rejection_accepted_by_check_event_id == evt(9)
    assert findings[fnd(1)].resolved_by_check_event_id is None
    assert findings[fnd(1)].review_rounds == 0
    # Proven absent by an earlier check: final, the later ruling changes nothing.
    assert findings[fnd(2)].resolved_by_check_event_id == evt(8)
    assert findings[fnd(2)].rejection_accepted_by_check_event_id is None
    # No reasoned rejection to accept: the absence proof stands.
    assert findings[fnd(3)].resolved_by_check_event_id == evt(9)
    assert findings[fnd(3)].rejection_accepted_by_check_event_id is None

    state = _state(dict(findings), dict(rejected))
    assert finding_todo_state(state, fnd(1)) is FindingTodoState.REJECTION_ACCEPTED
    assert finding_is_resolved(state, fnd(1)) is False
    assert finding_blocks_receipt(state, fnd(1)) is False
    assert finding_todo_state(state, fnd(2)) is FindingTodoState.VERIFIED_RESOLVED
    assert finding_todo_state(state, fnd(3)) is FindingTodoState.VERIFIED_RESOLVED
    counts = todo_counts(state, (fnd(1), fnd(2), fnd(3)))
    assert (counts.rejection_accepted, counts.verified_resolved) == (1, 2)
    # Redacting the withdrawing check drops the latch and leaves the item open, never resolved.
    reopen_findings_resolved_by(findings, frozenset({evt(9)}))
    reopened = _state(dict(findings), dict(rejected))
    assert finding_todo_state(reopened, fnd(1)) is FindingTodoState.OPEN


def test_rejection_accepted_never_upgrades_and_redaction_drops_the_latch() -> None:
    latched = replace(finding_record(_finding(1), 4), rejection_accepted_by_check_event_id=evt(9))
    findings = {fnd(1): latched}
    clean = _check()
    object.__setattr__(clean, "suppressed_count", 0)
    control = {fnd(1): finding_record(_finding(1), 4)}
    apply_check_resolution(control, clean, evt(12))
    assert control[fnd(1)].resolved_by_check_event_id == evt(12), "the check does qualify"
    apply_check_resolution(findings, clean, evt(12))
    assert findings[fnd(1)].resolved_by_check_event_id is None, "no upgrade out of terminal"
    reopen_findings_resolved_by(findings, frozenset({evt(9)}))
    assert findings[fnd(1)].rejection_accepted_by_check_event_id is None


def test_acknowledged_not_done_is_never_resolved_and_always_blocks() -> None:
    proven = finding_record(_finding(1), 4, resolved_by_check_event_id=evt(9))
    state = _state(
        {fnd(1): proven}, {fnd(1): _response(1, ResponseDisposition.ACKNOWLEDGED_NOT_DONE)}
    )
    assert finding_is_resolved(state, fnd(1)) is False
    assert finding_todo_state(state, fnd(1)) is FindingTodoState.ACKNOWLEDGED_NOT_DONE
    assert finding_blocks_receipt(state, fnd(1)) is True


def test_todo_facts_round_trip_and_stay_absent_until_set() -> None:
    plain = finding_record(_finding(1), 4)
    counted = replace(
        finding_record(_semantic(2), 5),
        review_rounds=3,
        rejection_accepted_by_check_event_id=evt(9),
    )
    state = _state({fnd(1): plain, fnd(2): counted})
    snapshot = projection_snapshot(state)
    rows = snapshot["findings"]
    assert isinstance(rows, dict)
    assert "review_rounds" not in rows[fnd(1)]  # type: ignore[operator]
    assert "rejection_accepted_by_check_event_id" not in rows[fnd(1)]  # type: ignore[operator]
    decoded = projection_from_snapshot(snapshot)
    assert decoded == state
    assert canonical_encode(projection_snapshot(decoded)) == canonical_encode(snapshot)


def test_budget_is_bounded() -> None:
    state = _state({fnd(1): finding_record(_finding(1), 4)})
    for bad in (0, 51, True):
        with pytest.raises(ValueError, match="finding_attempt_budget_invalid"):
            finding_todo(state, fnd(1), attempt_budget=bad)  # type: ignore[arg-type]


def test_acknowledged_not_done_needs_a_reason_and_rides_only_response_recorded_1_1_0() -> None:
    with pytest.raises(ProtocolValueError):
        ResponseRecordedPayload(
            fnd(1), Frontier(5, _DIGEST), ResponseDisposition.ACKNOWLEDGED_NOT_DONE
        )
    payload = ResponseRecordedPayload(
        fnd(1), Frontier(5, _DIGEST), ResponseDisposition.ACKNOWLEDGED_NOT_DONE, "Out of scope."
    )
    at = timestamp_from_string("2026-09-30T12:00:00.000Z")
    EventDraft(evt(1), EventSchema("response_recorded", "1.1.0"), at, (evt(2),), payload, (), ())
    with pytest.raises(ProtocolValueError, match="invalid_event_schema"):
        EventDraft(
            evt(1), EventSchema("response_recorded", "1.0.0"), at, (evt(2),), payload, (), ()
        )
    rejected = ResponseRecordedPayload(
        fnd(1), Frontier(5, _DIGEST), ResponseDisposition.REJECTED, "Not applicable."
    )
    with pytest.raises(ProtocolValueError, match="invalid_event_schema"):
        EventDraft(
            evt(1), EventSchema("response_recorded", "1.1.0"), at, (evt(2),), rejected, (), ()
        )


def _kind_finding(number: int, kind: FindingKind) -> Finding:
    base = _finding(number)
    return Finding(
        finding_id=base.finding_id,
        kind=kind,
        origin=base.origin,
        priority=FINDING_KIND_TRAITS[kind][0],
        summary=base.summary,
        detail=base.detail,
        subject_refs=base.subject_refs,
        policy_id=base.policy_id,
        policy_version=base.policy_version,
        subject_frontier=base.subject_frontier,
        coverage=base.coverage,
        provenance=None,
    )


def test_a_coverage_limitation_never_drives_the_checklist_next_step() -> None:
    """D3(a): an open non-actionable row is not a to-do, even past the budget."""

    from yoetz.application.check import build_finding_checklist

    limitation = replace(
        finding_record(_kind_finding(1, FindingKind.LEDGER_STALE_OR_INCOMPLETE), 4),
        review_rounds=9,
    )
    checklist = build_finding_checklist(_state({fnd(1): limitation}), attempt_budget=2)
    assert checklist.items == ()
    assert checklist.next == "request_receipt"
    assert checklist.counts.open == 0


def test_the_checklist_counts_and_next_cover_items_past_the_listed_hundred() -> None:
    """D3(b): an open blocking item beyond the first 100 rows keeps ``next`` honest."""

    from yoetz.application.check import build_finding_checklist

    rows: dict[FindingId, FindingProjectionRecord] = {}
    for number in range(1, 101):
        rows[fnd(number)] = finding_record(_finding(number), 4, resolved_by_check_event_id=evt(9))
    late = _kind_finding(101, FindingKind.ACTION_WITHOUT_RESULT)  # priority 3: ranked last
    rows[fnd(101)] = finding_record(late, 4)
    checklist = build_finding_checklist(_state(rows), attempt_budget=5)
    assert len(checklist.items) == 100
    # R2: the open item ranked last is listed first; a closed row makes room for it.
    assert checklist.items[0].finding_id == fnd(101)
    assert checklist.items[0].todo_state == "open"
    assert (checklist.counts.open, checklist.counts.verified_resolved) == (1, 100)
    assert checklist.next == "work_open_findings"


def test_the_resolution_explanation_names_terminal_states() -> None:
    """D4: a final item explains itself as final, not as a disputed or unreadable response."""

    from yoetz.kernel.finding_resolution import finding_resolution_explanation

    not_done = _state(
        {fnd(1): finding_record(_semantic(1), 4)},
        {fnd(1): _response(1, ResponseDisposition.ACKNOWLEDGED_NOT_DONE)},
    )
    assert finding_resolution_explanation(not_done, fnd(1), ()).startswith(
        "Acknowledged, not done:"
    )
    accepted = _state(
        {
            fnd(1): replace(
                finding_record(_semantic(1), 4), rejection_accepted_by_check_event_id=evt(9)
            )
        },
        {fnd(1): _response(1, ResponseDisposition.REJECTED)},
    )
    explanation = finding_resolution_explanation(accepted, fnd(1), ())
    assert explanation.startswith("Rejection accepted:") and str(evt(9)) in explanation


def test_a_final_item_never_gains_review_rounds() -> None:
    """Greptile P2 on #943: an ``acknowledged_not_done`` item is final; a later check that returns
    it again, or a stray ruling on it, must not count a round."""

    local = finding_record(_finding(1), 4)
    ai = finding_record(_semantic(2), 4)
    findings = {fnd(1): local, fnd(2): ai}
    responses = {
        fnd(1): _response(1, ResponseDisposition.ACKNOWLEDGED_NOT_DONE),
        fnd(2): _response(2, ResponseDisposition.ACKNOWLEDGED_NOT_DONE),
    }
    check = _check(returned=(fnd(1),), rulings=((2, "still_present"),))
    apply_check_rulings(findings, responses, check, evt(9))
    assert findings[fnd(1)].review_rounds == 0
    assert findings[fnd(2)].review_rounds == 0
    # The same check still counts a round for an open item.
    open_findings = {fnd(1): finding_record(_finding(1), 4)}
    apply_check_rulings(open_findings, {}, check, evt(9))
    assert open_findings[fnd(1)].review_rounds == 1


def _premise(number: int, next_step: str = "act") -> Finding:
    from yoetz.domain.findings import FindingChallenge, finding_policy_identity

    kind = FindingKind.TASK_REQUIREMENT_UNMET
    policy_id, policy_version = finding_policy_identity(kind)
    return replace(
        _semantic(number),
        kind=kind,
        priority=FINDING_KIND_TRAITS[kind][0],
        policy_id=policy_id,
        policy_version=policy_version,
        summary="The required dispatchable single-tour plan is not delivered.",
        challenge=FindingChallenge(
            discrepancy="The task requires one dispatchable tour; none is delivered.",
            alternative_interpretation="A tour may be infeasible under the MTOW limit.",
            requested_next_step=next_step,
            uncertainty="Whether fuel planning can bring the tour under the limit.",
        ),
    )


def _blocker_decision(obligation: object) -> DecisionProjectionRecord:
    from yoetz.domain.events import DecisionRecordedPayload
    from yoetz.domain.values import actor_id

    payload = DecisionRecordedPayload(
        statement="The fixture service is unreachable.\nyoetz-blocker:dependency_unavailable",
        rationale="No network in the sandbox.",
        authority=actor_id("agent"),
        affected_obligation_ids=(obligation,),  # type: ignore[arg-type]
    )
    from yoetz.domain.events import encode_payload
    from yoetz.protocol.canonical import canonical_digest

    return DecisionProjectionRecord(
        payload=payload,
        payload_digest=canonical_digest(encode_payload(payload)),
        redacted=False,
        source_event_id=evt(3),
        source_frontier=3,
    )


def test_an_acknowledged_premise_challenge_is_a_dispute_only_with_a_recorded_anchor() -> None:
    """TB4 tb4n1 D7a (cargo): ``acknowledged_not_done`` must not silently end a premise challenge,
    but not every acknowledged requirement finding is one the reviewer still disputes.

    The rule is structural (no prose is read): the item is an acknowledged premise challenge and
    either cites a ``yoetz-blocker`` decision or the obligation it blocks (``blocker_cited``), or
    a review re-raised it after the acknowledgement (``give_up_reraised``). A disclosure-only
    request, a local finding, an open item, another kind and an unanchored acknowledgement are
    not premise disputes.
    """

    from yoetz.kernel.finding_todo import (
        PREMISE_DISPUTE_BLOCKER_CITED,
        PREMISE_DISPUTE_GIVE_UP_RERAISED,
        is_premise_challenge,
        premise_dispute_basis,
        standing_premise_disputes,
    )

    findings = {
        fnd(1): finding_record(_premise(1), 4),
        fnd(2): finding_record(_premise(2, "state_unresolved_limitation"), 4),
        fnd(3): finding_record(_premise(3), 4),
        fnd(4): finding_record(_semantic(4), 4),
        fnd(5): finding_record(_premise(5), 4),
        fnd(6): replace(finding_record(_premise(6), 4), settled_reraise_count=1),
    }
    responses = {
        fnd(number): _response(number, ResponseDisposition.ACKNOWLEDGED_NOT_DONE)
        for number in (1, 2, 4, 5, 6)
    }
    state = replace(
        _state(findings, responses),
        decisions={evt(3): _blocker_decision(obl(1))},
    )
    assert is_premise_challenge(_premise(1)) and not is_premise_challenge(_semantic(4))
    assert premise_dispute_basis(state, fnd(1)) == PREMISE_DISPUTE_BLOCKER_CITED
    assert premise_dispute_basis(state, fnd(6)) == PREMISE_DISPUTE_GIVE_UP_RERAISED
    # Acknowledged with no blocker cited and never re-raised: the reviewer never disputed it.
    assert premise_dispute_basis(state, fnd(5)) is None
    assert standing_premise_disputes(state) == (fnd(1), fnd(6))
    # Cross-lane (L4 D7a, #984): closure readiness binds this predicate and names the same ids,
    # which the Stop gate asks about once (``finding_premise_disputed``).
    from yoetz.kernel import closure_readiness

    assert closure_readiness._standing_premise_disputes is standing_premise_disputes  # pyright: ignore[reportPrivateUsage]
    assert closure_readiness.premise_disputed_finding_ids(state) == (fnd(1), fnd(6))
    todo = finding_todo(state, fnd(1))
    assert todo.state is FindingTodoState.ACKNOWLEDGED_NOT_DONE and todo.premise_disputed
    assert finding_todo(state, fnd(3)).premise_disputed is False  # still open: no dispute yet
    assert finding_todo(state, fnd(5)).premise_disputed is False
    assert finding_blocks_receipt(state, fnd(1)) is True
    # A superseded blocker decision is no anchor.
    superseded = replace(
        state,
        decisions={evt(3): replace(_blocker_decision(obl(1)), superseded_by_event_id=evt(7))},
    )
    assert standing_premise_disputes(superseded) == (fnd(6),)


def test_a_reraise_after_the_agent_settles_an_item_is_recorded_never_a_round() -> None:
    """Issue #980 / D7: the reviewer re-raising an acknowledged item records the dispute on it."""

    findings = {fnd(1): finding_record(_premise(1), 4), fnd(2): finding_record(_finding(2), 4)}
    responses = {
        fnd(1): _response(1, ResponseDisposition.ACKNOWLEDGED_NOT_DONE),
        fnd(2): _response(2, ResponseDisposition.ACKNOWLEDGED_NOT_DONE),
    }
    for event, verdict in ((9, "still_present"), (10, "answered_not_fixed"), (11, "unassessable")):
        apply_check_rulings(
            findings, responses, _check(rulings=((1, verdict), (2, verdict))), evt(event)
        )
    assert findings[fnd(1)].settled_reraise_count == 2
    assert findings[fnd(1)].review_rounds == 0
    assert findings[fnd(2)].settled_reraise_count == 0  # a local finding is never re-raised
    # A re-raise while the item is open is an ordinary round, not a settled re-raise.
    open_findings = {fnd(1): finding_record(_premise(1), 4)}
    apply_check_rulings(open_findings, {}, _check(rulings=((1, "still_present"),)), evt(9))
    assert (open_findings[fnd(1)].review_rounds, open_findings[fnd(1)].settled_reraise_count) == (
        1,
        0,
    )
    snapshot = projection_snapshot(_state(findings, responses))
    assert projection_from_snapshot(snapshot) == _state(findings, responses)


def test_a_self_verified_answer_counts_as_a_rebuttal() -> None:
    """D7b: the agent's ``self_verified`` answer (C1, issue #984) disputes the reviewer's standing
    claim like ``rejected`` does; matched by wire value so the fold reads either ledger."""

    from yoetz.kernel.reducers import (
        _REBUTTAL_DISPOSITION_VALUES,  # pyright: ignore[reportPrivateUsage]
    )

    assert _REBUTTAL_DISPOSITION_VALUES == {"rejected", "self_verified"}
    assert ResponseDisposition.ACKNOWLEDGED_NOT_DONE.value not in _REBUTTAL_DISPOSITION_VALUES


def test_rebuttals_and_the_last_reviewer_verdict_are_recorded_and_round_trip() -> None:
    """TB4 tb4n1 D7b: every rebuttal is counted and the reviewer's newest ruling is kept."""

    findings = {fnd(1): finding_record(_semantic(1), 4), fnd(2): finding_record(_finding(2), 4)}
    apply_check_rulings(
        findings, {}, _check(rulings=((1, "answered_not_fixed"), (2, "still_present"))), evt(9)
    )
    assert findings[fnd(1)].last_reviewer_verdict == "answered_not_fixed"
    assert findings[fnd(2)].last_reviewer_verdict is None  # a local finding is not ruled
    apply_check_rulings(findings, {}, _check(rulings=((1, "unassessable"),)), evt(10))
    assert findings[fnd(1)].last_reviewer_verdict == "unassessable"
    counted = replace(findings[fnd(1)], rebuttal_count=2)
    state = _state({fnd(1): counted, fnd(2): findings[fnd(2)]})
    snapshot = projection_snapshot(state)
    rows = snapshot["findings"]
    assert isinstance(rows, dict)
    assert "rebuttal_count" not in rows[fnd(2)]  # type: ignore[operator]
    assert "last_reviewer_verdict" not in rows[fnd(2)]  # type: ignore[operator]
    decoded = projection_from_snapshot(snapshot)
    assert decoded == state
    with pytest.raises(ValueError, match="invalid_projection_state"):
        replace(counted, last_reviewer_verdict="maybe")


# --- disputed_after_rebuttal (issue #1020, ADR-040, TB4 tb4n2 formal-crypto) --------------------


def test_disputed_after_rebuttal_latches_only_on_a_readable_rejection() -> None:
    findings = {
        fnd(1): finding_record(_semantic(1), 4),
        fnd(2): finding_record(_semantic(2), 4),
    }
    responses = {
        fnd(1): _response(1, ResponseDisposition.REJECTED),
        fnd(2): _response(2, ResponseDisposition.ACKNOWLEDGED),
    }
    check = _check(rulings=((1, "disputed_after_rebuttal"), (2, "disputed_after_rebuttal")))
    apply_check_rulings(findings, responses, check, evt(9))
    assert findings[fnd(1)].disputed_after_rebuttal_by_check_event_id == evt(9)
    assert findings[fnd(1)].review_rounds == 0  # a standing disagreement is not another round
    assert findings[fnd(2)].disputed_after_rebuttal_by_check_event_id is None
    state = _state(dict(findings), dict(responses))
    assert finding_todo_state(state, fnd(1)) is FindingTodoState.DISPUTED_AFTER_REBUTTAL
    assert FindingTodoState.DISPUTED_AFTER_REBUTTAL in TERMINAL_TODO_STATES
    assert finding_blocks_receipt(state, fnd(1)) is False
    assert finding_is_resolved(state, fnd(1)) is False
    assert todo_counts(state, (fnd(1), fnd(2))).disputed_after_rebuttal == 1
    # Further repeats of the dispute never count rounds or change the latch.
    apply_check_rulings(findings, responses, _check(rulings=((1, "still_present"),)), evt(10))
    assert findings[fnd(1)].review_rounds == 0
    assert findings[fnd(1)].disputed_after_rebuttal_by_check_event_id == evt(9)


def test_disputed_after_rebuttal_never_upgrades_and_redaction_drops_the_latch() -> None:
    latched = replace(
        finding_record(_semantic(1), 4), disputed_after_rebuttal_by_check_event_id=evt(9)
    )
    findings = {fnd(1): latched}
    clean = _check()
    object.__setattr__(clean, "suppressed_count", 0)
    apply_check_resolution(findings, clean, evt(12))
    assert findings[fnd(1)].resolved_by_check_event_id is None, "no upgrade out of terminal"
    reopen_findings_resolved_by(findings, frozenset({evt(9)}))
    assert findings[fnd(1)].disputed_after_rebuttal_by_check_event_id is None
    responses = {fnd(1): _response(1, ResponseDisposition.REJECTED)}
    assert finding_todo_state(_state(dict(findings), responses), fnd(1)) is FindingTodoState.OPEN


def test_disputed_after_rebuttal_round_trips_and_stays_absent_until_set() -> None:
    plain = finding_record(_semantic(1), 4)
    disputed = replace(
        finding_record(_semantic(2), 5), disputed_after_rebuttal_by_check_event_id=evt(9)
    )
    state = _state({fnd(1): plain, fnd(2): disputed})
    snapshot = projection_snapshot(state)
    rows = snapshot["findings"]
    assert isinstance(rows, dict)
    assert "disputed_after_rebuttal_by_check_event_id" not in rows[fnd(1)]  # type: ignore[operator]
    decoded = projection_from_snapshot(snapshot)
    assert decoded == state
    assert canonical_encode(projection_snapshot(decoded)) == canonical_encode(snapshot)
