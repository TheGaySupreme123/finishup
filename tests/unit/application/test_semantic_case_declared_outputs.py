"""Declared outputs outside the workspace reach the review packet (tb4n2 R7, P1-15, #1016).

cargo-flight-dispatch S: the task requires ``/output/flight_plan.json``. The check-time change
reads only the repository, and the hook capture the agent cited lost general excerpt room to
newer tool output, so the reviewer never saw the deliverable. Captures of a declared ``role:
output`` item outside the workspace are now reserved beside the current diff.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from builders.policy_cases import (
    act,
    clm,
    evd,
    evidence_record,
    make_case,
    obl,
    obligation_record,
    plan_record,
    record,
    res,
)
from yoetz.application.semantic_case import build_semantic_case, declared_output_capture_refs
from yoetz.domain.events import (
    ActionKind,
    ActionRecordedPayload,
    ClaimKind,
    ClaimRecordedPayload,
    EvidenceKind,
    EvidenceRecordedPayload,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
    RequestedItem,
    RequestedItemKind,
    RequestedItemRole,
    ResultOutcome,
    ResultRecordedPayload,
)
from yoetz.domain.privacy import ReviewContextProfile, ReviewSelectionPolicy
from yoetz.domain.values import EvidenceId, object_id, timestamp_from_string
from yoetz.kernel.deterministic_checks import DeterministicCase
from yoetz.kernel.projections import EvidenceProjectionRecord
from yoetz.protocol.coverage import EvidenceImmutability

_AT = timestamp_from_string("2026-10-08T00:00:00.000Z")
_OUTPUT = "/output/flight_plan.json"


def _evidence(
    number: int,
    frontier: int,
    *,
    reference: str | None = None,
    captured: bool = False,
    marker: str = "",
) -> EvidenceProjectionRecord:
    return evidence_record(
        EvidenceRecordedPayload(
            evd(number),
            EvidenceKind.ARTIFACT,
            EvidenceImmutability.METADATA_ONLY,
            _AT,
            reference=reference,
            captured_object_id=(
                object_id(f"obj_10000000-0000-4000-8000-{number:012x}") if captured else None
            ),
            description=marker or f"tool output {number}",
        ),
        frontier,
    )


def _case(
    *,
    role: RequestedItemRole | None = RequestedItemRole.OUTPUT,
    value: str = _OUTPUT,
    evidence: dict[EvidenceId, EvidenceProjectionRecord],
    claim_refs: tuple[EvidenceId, ...] = (),
    attempted: tuple[str, ...] = (),
) -> DeterministicCase:
    plan = plan_record(PlanPublishedPayload(1, "Dispatch the flight", (obl(1),)), 1)
    obligation = obligation_record(
        ObligationPublishedPayload(
            obl(1),
            "Write the flight plan",
            "The plan exists",
            ObligationStatus.OPEN,
            requested_items=(RequestedItem(RequestedItemKind.FILE, value, role),),
        ),
        2,
    )
    claims = (
        {
            clm(1): record(
                ClaimRecordedPayload(
                    clm(1),
                    ClaimKind.COMPLETION,
                    "The plan is written",
                    claim_refs,
                    obligation_refs=(obl(1),),
                ),
                90,
            )
        }
        if claim_refs
        else {}
    )
    actions = (
        {
            act(1): record(
                ActionRecordedPayload(
                    act(1), ActionKind.EDIT, "Wrote the plan", attempted_items=attempted
                ),
                3,
            )
        }
        if attempted
        else {}
    )
    results = (
        {
            res(1): record(
                ResultRecordedPayload(
                    res(1), act(1), ResultOutcome.SUCCESS, evidence_refs=(evd(9),)
                ),
                4,
            )
        }
        if attempted
        else {}
    )
    return make_case(
        plans={1: plan},
        obligations={obl(1): obligation},
        claims=claims,
        actions=actions,
        results=results,
        evidence=evidence,
        extra_refs=(obl(1), *evidence, *claims, *actions, *results),
    )


def _refs(case: DeterministicCase, root: str | None = "/app") -> frozenset[str]:
    allowed = frozenset(str(ref) for ref in case.allowed_ids)
    return declared_output_capture_refs(case.projection, allowed, root)


def test_evidence_naming_an_outside_output_is_selected() -> None:
    case = _case(
        evidence={
            evd(1): _evidence(1, 10, reference=_OUTPUT),
            evd(2): _evidence(2, 11, reference="/app/scratch.json"),
        }
    )

    assert _refs(case) == frozenset({str(evd(1))})


@pytest.mark.parametrize(
    ("role", "value", "root"),
    [
        (RequestedItemRole.INPUT, _OUTPUT, "/app"),
        (None, _OUTPUT, "/app"),
        (RequestedItemRole.OUTPUT, "/app/out.json", "/app"),
        (RequestedItemRole.OUTPUT, "out.json", "/app"),
        (RequestedItemRole.OUTPUT, _OUTPUT, None),
    ],
)
def test_inputs_inside_paths_and_unknown_roots_select_nothing(
    role: RequestedItemRole | None, value: str, root: str | None
) -> None:
    case = _case(
        role=role,
        value=value,
        evidence={evd(1): _evidence(1, 10, reference=value)},
    )

    assert _refs(case, root) == frozenset()


def test_claim_cited_captures_newest_two_and_attempted_items_are_selected() -> None:
    # The cargo shape: a hook capture (no agent reference) the corrected claim cites.
    evidence = {evd(n): _evidence(n, 10 + n, captured=n != 4) for n in (1, 2, 3, 4)} | {
        evd(9): _evidence(9, 30)
    }
    case = _case(
        evidence=evidence,
        claim_refs=(evd(1), evd(2), evd(3), evd(4)),
        attempted=(_OUTPUT,),
    )

    # evd(4) is the newest but carries no captured content; evd(9) is the attempted run's.
    assert _refs(case) == frozenset({str(evd(2)), str(evd(3)), str(evd(9))})
    redacted = replace(
        case.projection,
        evidence={
            **case.projection.evidence,
            evd(3): replace(evidence[evd(3)], payload=None, redacted=True),
        },
    )
    allowed = frozenset(str(ref) for ref in case.allowed_ids)
    assert str(evd(3)) not in declared_output_capture_refs(redacted, allowed, "/app")
    assert str(evd(3)) not in declared_output_capture_refs(
        case.projection, allowed - {str(evd(3))}, "/app"
    )


@pytest.mark.parametrize("profile", [ReviewContextProfile.ASSISTED, ReviewContextProfile.EXPANDED])
def test_outside_output_capture_wins_the_excerpt_cap(profile: ReviewContextProfile) -> None:
    evidence = {
        evd(1): _evidence(1, 10, reference=_OUTPUT, marker="PLAN_MARKER legs=3"),
        **{evd(n): _evidence(n, 10 + n, marker=f"NEWER_TOOL_OUTPUT {n}") for n in range(2, 8)},
    }
    case = _case(evidence=evidence)
    selection = replace(ReviewSelectionPolicy.for_profile(profile), max_excerpts=1)

    def build(root: str | None) -> bytes:
        semantic = build_semantic_case(
            case_id="cas_10000000-0000-4000-8000-000000001016",
            frozen_case=case,
            dependency_digest="sha256:" + "c" * 64,
            findings=(),
            review_context_profile=profile,
            review_selection=selection,
            policy_id="research-evidence",
            policy_version="0.1.0",
            workspace_root=root,
        )
        return b"".join(item.content for item in semantic.items if item.section == "excerpt")

    assert b"PLAN_MARKER" in build("/app")
    # Without the reservation the newest unrelated output takes the one slot.
    assert b"PLAN_MARKER" not in build(None)
