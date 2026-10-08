"""Task facts scoped per finding for self-verification (tb4n2 P1-2, issue #1018, ADR-042)."""

from __future__ import annotations

from dataclasses import replace
from typing import cast

import pytest

from builders.policy_cases import (
    act,
    clm,
    evt,
    finding_record,
    fnd,
    obl,
    obligation_record,
    plan_record,
    record,
)
from yoetz.domain.events import (
    ActionKind,
    ActionRecordedPayload,
    ClaimKind,
    ClaimRecordedPayload,
    LedgerRecord,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
)
from yoetz.domain.findings import (
    FINDING_KIND_TRAITS,
    Finding,
    FindingKind,
    FindingOrigin,
    finding_policy_identity,
)
from yoetz.domain.values import EventId, Frontier
from yoetz.kernel import self_verification
from yoetz.kernel.finding_resolution import ResolutionAttempt
from yoetz.kernel.projections import ProjectionState, empty_projection_state
from yoetz.kernel.task_fact_scope import (
    finding_obligation_scope,
    scoped_resolution_reasons,
    task_fact_bears_on_finding,
)
from yoetz.protocol.coverage import (
    ArtifactObservation,
    AuthorshipAssurance,
    CheckType,
    Coverage,
    EvidenceImmutability,
    LedgerFreshness,
    PublicationChannel,
)

_DIGEST = "sha256:" + "e" * 64
_EALV = "coverage:edited_after_last_verification"


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


def _finding(kind: FindingKind, subjects: tuple[object, ...]) -> Finding:
    return Finding(
        finding_id=fnd(1),
        kind=kind,
        # The scope rule is origin-agnostic; a local origin keeps the fixture free of review
        # provenance.
        origin=FindingOrigin.DETERMINISTIC,
        priority=FINDING_KIND_TRAITS[kind][0],
        summary="The decoder still fails an independent benchmark.",
        detail="31 of 100 freshly generated keys failed.",
        subject_refs=subjects,  # type: ignore[arg-type]
        policy_id=finding_policy_identity(kind)[0],
        policy_version=finding_policy_identity(kind)[1],
        subject_frontier=Frontier(3, _DIGEST),
        coverage=_coverage(),
        provenance=None,
    )


def _obligation(number: int) -> ObligationPublishedPayload:
    return ObligationPublishedPayload(
        obligation_id=obl(number),
        description="Synthetic obligation",
        evidence_expectation="Typed evidence",
        status=ObligationStatus.OPEN,
    )


def _state(finding: Finding, **extra: object) -> ProjectionState:
    return replace(
        empty_projection_state(),
        frontier=20,
        head_digest=_DIGEST,
        findings={finding.finding_id: finding_record(finding, 4)},
        obligations={
            obl(1): obligation_record(_obligation(1), 1),
            obl(2): obligation_record(_obligation(2), 2),
        },
        plans={1: plan_record(PlanPublishedPayload(1, "Plan", (obl(1), obl(2))), 1)},
        **extra,  # type: ignore[arg-type]
    )


def test_finding_scope_follows_obligation_claim_and_action_subjects() -> None:
    claim = ClaimRecordedPayload(
        claim_id=clm(1),
        claim_kind=ClaimKind.MATERIAL,
        statement="Part one",
        supporting_refs=(),
        obligation_refs=(obl(2),),
    )
    action = ActionRecordedPayload(
        act(1), ActionKind.EDIT, "Edit", obligation_refs=(obl(1),), attempted_items=()
    )
    kind = FindingKind.CODE_DEFECT
    state = _state(
        _finding(kind, (obl(1),)),
        claims={clm(1): record(claim, 5)},
        actions={act(1): record(action, 6)},
    )
    assert finding_obligation_scope(state, fnd(1)) == {obl(1)}
    state = replace(state, findings={fnd(1): finding_record(_finding(kind, (clm(1),)), 4)})
    assert finding_obligation_scope(state, fnd(1)) == {obl(2)}
    state = replace(state, findings={fnd(1): finding_record(_finding(kind, (evt(6),)), 4)})
    assert finding_obligation_scope(state, fnd(1)) == {obl(1)}
    completion = replace(claim, claim_kind=ClaimKind.COMPLETION, obligation_refs=())
    state = replace(
        state,
        claims={clm(1): record(completion, 5)},
        findings={fnd(1): finding_record(_finding(kind, (clm(1),)), 4)},
    )
    assert finding_obligation_scope(state, fnd(1)) == {obl(1), obl(2)}


@pytest.mark.parametrize(
    ("kind", "bears"),
    [
        (FindingKind.CODE_DEFECT, False),
        (FindingKind.TASK_REQUIREMENT_UNMET, False),
        (FindingKind.CLAIM_WITHOUT_ADMISSIBLE_EVIDENCE, True),
        (FindingKind.EVIDENCE_DOES_NOT_SUPPORT_CLAIM, True),
        (FindingKind.STALE_EVIDENCE_FOR_CHANGED_STATE, True),
    ],
)
def test_edited_after_verification_bears_only_on_verification_findings(
    kind: FindingKind, bears: bool
) -> None:
    state = _state(_finding(kind, (obl(1),)))
    assert (
        task_fact_bears_on_finding(
            "edited_after_last_verification", state=state, finding_id=fnd(1), markers=None
        )
        is bears
    )


def test_obligation_scoped_facts_bear_only_on_their_obligation() -> None:
    state = _state(_finding(FindingKind.TASK_REQUIREMENT_UNMET, (obl(1),)))
    markers = (("planned_verification_stale", obl(2)),)
    assert not task_fact_bears_on_finding(
        "planned_verification_stale", state=state, finding_id=fnd(1), markers=markers
    )
    markers = (("planned_verification_stale", obl(1)),)
    assert task_fact_bears_on_finding(
        "planned_verification_stale", state=state, finding_id=fnd(1), markers=markers
    )
    # Unknown markers fail closed; a non-task-fact code always bears.
    assert task_fact_bears_on_finding(
        "planned_verification_stale", state=state, finding_id=fnd(1), markers=None
    )
    assert task_fact_bears_on_finding("missing_ref", state=state, finding_id=fnd(1), markers=())


def test_scoped_reasons_drop_unrelated_facts_but_never_empty_the_list() -> None:
    state = _state(_finding(FindingKind.CODE_DEFECT, (obl(1),)))
    reasons = ("reviewer_verdict_unassessable", _EALV, "coverage:semantic_review_refs_reduced")
    assert scoped_resolution_reasons(reasons, state=state, finding_id=fnd(1), records=()) == (
        "reviewer_verdict_unassessable",
        "coverage:semantic_review_refs_reduced",
    )
    # The only thing left between the finding and resolution: keep it, it is real agent work.
    assert scoped_resolution_reasons((_EALV,), state=state, finding_id=fnd(1), records=()) == (
        _EALV,
    )


def _attempt(reasons: tuple[str, ...]) -> ResolutionAttempt:
    return ResolutionAttempt(
        check_event_id=EventId(evt(10)),
        newest_check_event_id=EventId(evt(10)),
        could_resolve=False,
        subject_sequence=10,
        reasons=reasons,
    )


def test_interleaved_s_review_finding_is_self_verifiable_despite_unrelated_staleness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """tb4n2 interleaved S fnd_6fa89200: refused only for a task-wide unrelated fact."""

    reasons = ("reviewer_verdict_unassessable", _EALV, "coverage:semantic_review_refs_reduced")
    monkeypatch.setattr(
        self_verification,
        "finding_resolution_attempt",
        lambda *_args: _attempt(reasons),  # pyright: ignore[reportUnknownLambdaType,reportUnknownArgumentType]
    )
    records = cast(tuple[LedgerRecord, ...], ())
    defect = _state(_finding(FindingKind.CODE_DEFECT, (obl(1),)))
    assert self_verification.self_verification_refusal(defect, fnd(1), records) is None
    # A finding about verification is still refused while the work changed after the last run.
    stale = _state(_finding(FindingKind.CLAIM_WITHOUT_ADMISSIBLE_EVIDENCE, (obl(1),)))
    assert (
        self_verification.self_verification_refusal(stale, fnd(1), records)
        == self_verification.FINDING_NOT_PROOF_LIMITED
    )
