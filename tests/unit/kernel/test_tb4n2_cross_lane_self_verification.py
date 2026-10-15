"""Self-verification eligibility and its refusal reasons read the same scoped task facts (tb4n2).

Cross-lane lock: ``self_verification_refusal`` (closure) and ``self_verification_blocking_reasons``
(the ``finding_not_proof_limited`` refusal's ``safe_details.blocking_reasons``) both read the
per-finding scoped reasons of ``kernel.task_fact_scope`` (capture). The invariant: a refusal is
returned exactly when blocking reasons are non-empty, and blocking reasons never name a task fact
that does not bear on the finding, except through the documented fallback where an unrelated fact
is the only reason left.
"""

from __future__ import annotations

from dataclasses import replace
from typing import cast

import pytest

from builders.policy_cases import (
    evt,
    finding_record,
    fnd,
    obl,
    obligation_record,
    plan_record,
)
from finishup.domain.events import (
    LedgerRecord,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
)
from finishup.domain.findings import (
    FINDING_KIND_TRAITS,
    Finding,
    FindingKind,
    FindingOrigin,
    finding_policy_identity,
)
from finishup.domain.values import EventId, Frontier, ObligationId
from finishup.kernel import self_verification, task_fact_scope
from finishup.kernel.finding_resolution import ResolutionAttempt
from finishup.kernel.projections import ProjectionState, empty_projection_state
from finishup.kernel.task_fact_scope import scoped_resolution_reasons
from finishup.kernel.task_facts import TaskFactSignals
from finishup.protocol.coverage import (
    ArtifactObservation,
    AuthorshipAssurance,
    CheckType,
    Coverage,
    EvidenceImmutability,
    LedgerFreshness,
    PublicationChannel,
)

_DIGEST = "sha256:" + "c" * 64
_LIMIT = "coverage:content_redacted"  # a standing FinishUP limit: proof-limited on its own
_NOT_OBSERVED = "coverage:planned_verification_not_observed"
_STALE = "coverage:planned_verification_stale"
_EALV = "coverage:edited_after_last_verification"
_RECORDS = cast(tuple[LedgerRecord, ...], ())


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


def _finding(kind: FindingKind) -> Finding:
    return Finding(
        finding_id=fnd(1),
        kind=kind,
        origin=FindingOrigin.DETERMINISTIC,
        priority=FINDING_KIND_TRAITS[kind][0],
        summary="The parser still rejects a valid header.",
        detail="One of three header fixtures fails.",
        subject_refs=(obl(1),),
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


def _state(kind: FindingKind) -> ProjectionState:
    finding = _finding(kind)
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
    )


def _arrange(
    monkeypatch: pytest.MonkeyPatch,
    reasons: tuple[str, ...],
    markers: tuple[tuple[str, ObligationId | None], ...],
) -> None:
    attempt = ResolutionAttempt(
        check_event_id=EventId(evt(10)),
        newest_check_event_id=EventId(evt(10)),
        could_resolve=False,
        subject_sequence=10,
        reasons=reasons,
    )
    signals = TaskFactSignals(codes=(), markers=markers, acting_started=True)
    monkeypatch.setattr(self_verification, "finding_resolution_attempt", lambda *_a: attempt)  # pyright: ignore[reportUnknownLambdaType,reportUnknownArgumentType]
    monkeypatch.setattr(task_fact_scope, "task_fact_signals", lambda *_a: signals)  # pyright: ignore[reportUnknownLambdaType,reportUnknownArgumentType]


def _verdict(state: ProjectionState) -> tuple[str | None, tuple[str, ...]]:
    refusal = self_verification.self_verification_refusal(state, fnd(1), _RECORDS)
    blocking = self_verification.self_verification_blocking_reasons(state, fnd(1), _RECORDS)
    # The cross-lane invariant: a refusal exactly when blocking reasons are named.
    assert (refusal == self_verification.FINDING_NOT_PROOF_LIMITED) is bool(blocking)
    return refusal, blocking


@pytest.mark.parametrize(
    ("kind", "reasons", "markers"),
    [
        # An obligation-scoped fact about another obligation.
        (
            FindingKind.TASK_REQUIREMENT_UNMET,
            (_LIMIT, _NOT_OBSERVED),
            (("planned_verification_not_observed", obl(2)),),
        ),
        # Task-wide edited-after-verification on a finding that is not about verification.
        (FindingKind.CODE_DEFECT, (_EALV, _LIMIT), ()),
    ],
)
def test_unrelated_task_fact_neither_refuses_nor_is_named(
    monkeypatch: pytest.MonkeyPatch,
    kind: FindingKind,
    reasons: tuple[str, ...],
    markers: tuple[tuple[str, ObligationId | None], ...],
) -> None:
    _arrange(monkeypatch, reasons, markers)
    assert _verdict(_state(kind)) == (None, ())


def test_bearing_task_fact_refuses_and_is_the_only_fact_named(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    markers: tuple[tuple[str, ObligationId | None], ...] = (
        ("planned_verification_not_observed", obl(1)),
        ("planned_verification_stale", obl(2)),
    )
    # Related obligation fact, unrelated obligation fact, unrelated task-wide fact.
    _arrange(monkeypatch, (_LIMIT, _STALE, _NOT_OBSERVED, _EALV), markers)
    assert _verdict(_state(FindingKind.TASK_REQUIREMENT_UNMET)) == (
        self_verification.FINDING_NOT_PROOF_LIMITED,
        (_NOT_OBSERVED,),
    )


def test_bearing_edited_after_verification_refuses_a_verification_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    markers: tuple[tuple[str, ObligationId | None], ...] = (("planned_verification_stale", obl(2)),)
    _arrange(monkeypatch, (_EALV, _STALE, _LIMIT), markers)
    assert _verdict(_state(FindingKind.CLAIM_WITHOUT_ADMISSIBLE_EVIDENCE)) == (
        self_verification.FINDING_NOT_PROOF_LIMITED,
        (_EALV,),
    )


def test_unrelated_fact_alone_falls_back_and_still_agrees(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    markers: tuple[tuple[str, ObligationId | None], ...] = (
        ("planned_verification_not_observed", obl(2)),
    )
    _arrange(monkeypatch, (_NOT_OBSERVED,), markers)
    state = _state(FindingKind.TASK_REQUIREMENT_UNMET)
    # Documented fallback: every reason would be dropped, so the original reasons stand.
    assert scoped_resolution_reasons(
        (_NOT_OBSERVED,), state=state, finding_id=fnd(1), records=_RECORDS
    ) == (_NOT_OBSERVED,)
    assert _verdict(state) == (self_verification.FINDING_NOT_PROOF_LIMITED, (_NOT_OBSERVED,))
