"""Family B of tb4n3 (one concept, several computations), as regression tests (issue #1026).

Moved from the verification repros ``verify_n3/scratch_B_consistency/test_family_b.py`` (b1, b3, b4,
b5; b2 is the Stop gate and belongs to the gate lane). The repros asserted the CONSISTENT behaviour
and failed on the tb4n3 base 26e9cecf, each with the real attempts that reached it:

* b1 (ks S, vpp S, cargo D): readiness said "Nothing further to do" while the item still held the
  receipt at ``unresolved_findings_remain``.
* b3 (cargo D x2, ks S, lake D/S, cargo S): the check's next step called an acknowledged
  obligation open work while readiness and the checklist said "request the receipt".
* b4 (html / music / payments / vpp D): ``check_current_as_of_earlier_frontier`` was standing for
  readiness and bounding for the receipt, by two private rules.
* b5 (every D attempt, N3-2): the route was consulted by the receipt only; the full-check verdict
  never tolerated ``semantic_review_not_requested`` on a route that recorded it as not required.

They now read the one classifier, the one gap table and the one prediction.
"""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

from builders.observed_runs import INSTALLATION_KEY, ObservedLedger
from builders.policy_cases import finding_record, fnd, record
from yoetz.application.check import (
    build_finding_checklist,
    build_overall_next,
    full_check_gaps_clean,
    semantic_route_required,
)
from yoetz.domain.events import (
    OBLIGATION_SCHEMA_VERSION,
    EventSchema,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
    ResponseRecordedPayload,
)
from yoetz.domain.findings import (
    FINDING_KIND_TRAITS,
    Finding,
    FindingKind,
    FindingOrigin,
    ResponseDisposition,
    finding_policy_identity,
)
from yoetz.domain.values import Frontier, obligation_id
from yoetz.kernel.closure_class import ReceiptEffect, closure_counts, finding_closures
from yoetz.kernel.closure_readiness import closure_readiness_facts, derive_closure_readiness
from yoetz.kernel.gap_effect import GapContext, GapEffectKind, gap_effect
from yoetz.kernel.projections import ProjectionState
from yoetz.kernel.reducers import replay
from yoetz.kernel.task_facts import register_command_identity_key
from yoetz.protocol.coverage import (
    ArtifactObservation,
    AuthorshipAssurance,
    CheckType,
    Coverage,
    EvidenceImmutability,
    LedgerFreshness,
    PublicationChannel,
)
from yoetz.protocol.readiness_text import predicted_receipt_variants, readiness_directive

_DIGEST = "sha256:" + "3" * 64
_OBLIGATION = obligation_id("obl_da7fcee1-979b-4a5c-84cc-daf668869d31")
_REASON = "The cruise-altitude policy is the task owner's decision; reported in my answer."


@pytest.fixture(autouse=True)
def installation_key() -> object:
    register_command_identity_key(INSTALLATION_KEY)
    yield None
    register_command_identity_key(None)


def _acknowledged_obligation_ledger() -> ObservedLedger:
    ledger = ObservedLedger()
    ledger.append(
        EventSchema("obligation_published", OBLIGATION_SCHEMA_VERSION),
        ObligationPublishedPayload(
            obligation_id=_OBLIGATION,
            description="Synthetic obligation",
            evidence_expectation="Observed run",
            status=ObligationStatus.ACKNOWLEDGED_NOT_DONE,
            acknowledged_not_done_reason=_REASON,
        ),
        observed=False,
    )
    ledger.append(
        EventSchema("plan_published", "1.0.0"),
        PlanPublishedPayload(1, "Plan", (_OBLIGATION,)),
        observed=False,
    )
    return ledger


def _acknowledged_requirement_state() -> ProjectionState:
    """A reasoned ``acknowledged_not_done`` answer to an AI-powered requirement finding (ks S)."""

    finding = Finding(
        finding_id=fnd(1),
        kind=FindingKind.TASK_REQUIREMENT_UNMET,
        origin=FindingOrigin.DETERMINISTIC,
        priority=FINDING_KIND_TRAITS[FindingKind.TASK_REQUIREMENT_UNMET][0],
        summary="The accuracy requirement is not shown.",
        detail="Reach it or state the limit.",
        subject_refs=(_OBLIGATION,),
        policy_id=finding_policy_identity(FindingKind.TASK_REQUIREMENT_UNMET)[0],
        policy_version=finding_policy_identity(FindingKind.TASK_REQUIREMENT_UNMET)[1],
        subject_frontier=Frontier(2, _DIGEST),
        coverage=Coverage(
            publication_channels=(PublicationChannel.ENGINE_DERIVED,),
            authorship_assurance=AuthorshipAssurance.SERVICE_AUTHENTICATED,
            artifact_observation=ArtifactObservation.PUBLISHED_ONLY,
            evidence_immutability=EvidenceImmutability.METADATA_ONLY,
            ledger_freshness=LedgerFreshness.CURRENT,
            check_types=(CheckType.DETERMINISTIC,),
            known_gaps=(),
        ),
    )
    response = record(
        ResponseRecordedPayload(
            fnd(1), Frontier(2, _DIGEST), ResponseDisposition.ACKNOWLEDGED_NOT_DONE, _REASON
        ),
        4,
    )
    base = replay(_acknowledged_obligation_ledger().prefix)
    return replace(
        base,
        frontier=max(base.frontier, 4),
        findings={fnd(1): finding_record(finding, 3)},
        responses={fnd(1): response},
    )


def test_b1_readiness_done_never_hides_the_conclusion_the_receipt_will_carry() -> None:
    """An acknowledged requirement is final (nothing to do) and still holds the receipt unresolved.

    Readiness keeps ``ready_with_limitations`` (the agent has nothing left to do); the verdict says
    in the same breath what the receipt will read, with the counter that explains it.
    """

    state = _acknowledged_requirement_state()
    closures = finding_closures(state)
    counts = closure_counts(closures.values(), ())
    assert (counts.findings_to_do, counts.findings_unmet) == (0, 1)
    assert counts.receipt_blocking_findings == 1
    assert {item.receipt_effect for item in closures.values()} == {
        ReceiptEffect.UNRESOLVED_FINDINGS_REMAIN
    }
    # The finding came from a check, so the check applies; the hand-built state carries no check.
    facts = replace(closure_readiness_facts(state, ()), check_applicability="applicable")
    split = derive_closure_readiness(
        ("receipt_findings_unresolved",),
        (),
        facts,
        semantic_review_required=False,
    )
    assert split.state == "ready_with_limitations" and split.agent_actionable == ()
    directive = readiness_directive(split.state, standing=0, acknowledged=1)
    sentence = predicted_receipt_variants(
        {
            "conclusion": "unresolved_findings_remain",
            "reasons": [{"code": "findings_unmet", "count": "1", "refs": [str(fnd(1))]}],
        },
        state=split.state,
    )[0]
    assert "Nothing further to do" in directive
    assert "unresolved_findings_remain" in sentence and "acknowledged requirement" in sentence


def test_b3_the_checks_next_step_does_not_call_an_acknowledged_obligation_open_work() -> None:
    ledger = _acknowledged_obligation_ledger()
    projection = replay(ledger.prefix)
    checklist = build_finding_checklist(projection, attempt_budget=5)
    result = SimpleNamespace(
        missing_for_assessment=(),
        totals={"commands": {"live_failed": "0"}},
        coverage=SimpleNamespace(known_gaps=("content_unselected",)),
    )
    next_step = build_overall_next(result, checklist, projection)  # type: ignore[arg-type]
    assert next_step is not None
    assert (next_step.status, next_step.action) == ("ready_with_limitations", "request_receipt")
    assert next_step.target_refs == ()
    # ... and with nothing to disclose, the same check on an empty ledger reads ready.
    empty = replay(ObservedLedger().prefix)
    clean = build_overall_next(
        SimpleNamespace(
            missing_for_assessment=(),
            totals={"commands": {"live_failed": "0"}},
            coverage=SimpleNamespace(known_gaps=()),
        ),  # type: ignore[arg-type]
        build_finding_checklist(empty, attempt_budget=5),
        empty,
    )
    assert clean is not None and clean.status == "ready"


def test_b4_the_earlier_frontier_gap_has_one_class_and_one_bound() -> None:
    code = "check_current_as_of_earlier_frontier"
    # Readiness: never agent work (nothing recorded removes it).
    for bounds in (True, False):
        effect = gap_effect(code, GapContext(earlier_frontier_bounds=bounds))
        assert effect.readiness_group.value == "standing_limitation"
        assert effect.kind is (
            GapEffectKind.STANDING_BOUNDING if bounds else GapEffectKind.DISCLOSED
        )
    # The receipt: only an observation Yoetz cannot prove harmless bounds; answers to the
    # check's own findings (a responses-only suffix) are a disclosure, as ADR-040 section 7 says.
    assert gap_effect(code, GapContext(earlier_frontier_bounds=False)).kind is (
        GapEffectKind.DISCLOSED
    )


def test_b5_the_full_check_verdict_reads_the_recorded_route_like_the_receipt() -> None:
    gaps = ("content_unselected", "semantic_review_not_requested")
    totals = {"commands": {"unknown": "0", "live_failed": "0"}}
    route_required = semantic_route_required(
        "semantic_if_configured", "required", route_profile="strict"
    )
    assert route_required is False  # a strict route is the owner's deterministic-only choice
    assert full_check_gaps_clean(gaps, totals, route_requires_review=route_required)
    # A route that required review keeps the missing review bounding; so does an unknown route.
    assert not full_check_gaps_clean(gaps, totals, route_requires_review=True)
    assert not full_check_gaps_clean(gaps, totals)
    # The Yoetz packet budgets follow the same route: disclosed on a deterministic route.
    assert full_check_gaps_clean(
        ("check_time_change_truncated",), totals, route_requires_review=False
    )
    assert not full_check_gaps_clean(
        ("check_time_change_truncated",), totals, route_requires_review=True
    )
