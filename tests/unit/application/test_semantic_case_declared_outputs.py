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


def test_a_cited_capture_with_the_same_bytes_as_an_older_one_keeps_its_reservation() -> None:
    """Codex review round 1: a later identical capture folds into the older excerpt, so the
    reservation of the cited (later) row must transfer to the kept one."""

    from typing import Any

    import tests.unit.application.test_semantic_case_selection as selection_tests

    from yoetz.application.semantic_case import CapturedContentScope, CapturedSemanticContent

    helpers: dict[str, Any] = {
        name: getattr(selection_tests, name)
        for name in (
            "_PHASE",
            "_PROFILE",
            "_SESSION",
            "_TASK",
            "_WORKSPACE_COMMITMENT",
            "_capture",
            "_captured_row",
            "_output_payload",
        )
    }
    phase, profile_of = helpers["_PHASE"], helpers["_PROFILE"]

    plan_text = '{"legs": 3, "PLAN_MARKER": true}\n'
    evidence: dict[EvidenceId, EvidenceProjectionRecord] = {}
    captured: list[CapturedSemanticContent] = []
    for number, text in [
        (10, plan_text),
        *((n, f"NEWER_TOOL_OUTPUT {n}\n") for n in range(11, 20)),
        (20, plan_text),
    ]:
        kind, content = helpers["_capture"](
            "codex", helpers["_output_payload"]("codex", text, number)
        )
        row, item = helpers["_captured_row"](
            number, evd(number), content, kind, profile_of["codex"]
        )
        evidence[evd(number)] = row
        captured.append(item)
    case = _case(evidence=evidence, claim_refs=(evd(20),))
    scope = CapturedContentScope(
        task_id=helpers["_TASK"],
        session_id=helpers["_SESSION"],
        workspace_commitment=helpers["_WORKSPACE_COMMITMENT"],
        authorized_profiles=(profile_of["codex"],),
        phase_bindings=tuple(
            sorted(((str(ref), phase) for ref in evidence), key=lambda pair: pair[0].encode())
        ),
    )
    profile = ReviewContextProfile.EXPANDED
    semantic = build_semantic_case(
        case_id="cas_10000000-0000-4000-8000-000000001017",
        frozen_case=case,
        dependency_digest="sha256:" + "c" * 64,
        findings=(),
        review_context_profile=profile,
        review_selection=replace(ReviewSelectionPolicy.for_profile(profile), max_excerpts=1),
        policy_id="research-evidence",
        policy_version="0.1.0",
        captured_content=tuple(captured),
        captured_content_scope=scope,
        workspace_root="/app",
    )

    excerpts = b"".join(item.content for item in semantic.items if item.section == "excerpt")
    assert b"PLAN_MARKER" in excerpts


def test_repeats_of_one_output_never_crowd_out_another() -> None:
    """Codex review round 2: nine newer rows for output A, one older row for output B."""

    plan = plan_record(PlanPublishedPayload(1, "Write both outputs", (obl(1),)), 1)
    obligation = obligation_record(
        ObligationPublishedPayload(
            obl(1),
            "Write both outputs",
            "Both exist",
            ObligationStatus.OPEN,
            requested_items=(
                RequestedItem(RequestedItemKind.FILE, "/output/a.json", RequestedItemRole.OUTPUT),
                RequestedItem(RequestedItemKind.FILE, "/output/b.json", RequestedItemRole.OUTPUT),
            ),
        ),
        2,
    )
    evidence = {evd(1): _evidence(1, 10, reference="/output/b.json")} | {
        evd(n): _evidence(n, 10 + n, reference="/output/a.json") for n in range(2, 11)
    }
    case = make_case(
        plans={1: plan},
        obligations={obl(1): obligation},
        evidence=evidence,
        extra_refs=(obl(1), *evidence),
    )

    refs = _refs(case)
    assert str(evd(1)) in refs
    assert refs == frozenset({str(evd(1)), str(evd(10)), str(evd(9)), str(evd(8))})
