"""AIP-3/AIP-4: reviewer oversized fixtures, entirely offline."""

from dataclasses import replace

import pytest

from builders.policy_cases import clm, evt, make_case, obl, obligation_record, record
from finishup.application import semantic_case as composer
from finishup.domain.events import (
    ClaimKind,
    ClaimRecordedPayload,
    MissingForAssessmentItem,
    ObligationPublishedPayload,
    ObligationStatus,
)
from finishup.domain.privacy import ReviewContextProfile, ReviewSelectionPolicy
from finishup.kernel.deterministic_checks import DeterministicCase
from finishup.kernel.projections import PendingMissingForAssessment
from finishup.ports.change_capture import TaskInputFile
from finishup.ports.semantic import SemanticCase
from finishup.service.semantic_ceiling import plan_under_channel_ceiling
from unit.application.test_semantic_case import (
    _captured_case_values,  # pyright: ignore[reportPrivateUsage]
)
from unit.application.test_semantic_case_packet_completeness import (
    _change,  # pyright: ignore[reportPrivateUsage]
    _react_case,  # pyright: ignore[reportPrivateUsage]
)

_SELECTION = ReviewSelectionPolicy.for_profile(ReviewContextProfile.EXPANDED)
_DIFF = (
    b"diff --git a/form.py b/form.py\n"
    + b"+return validate_input(value) # work under review\n" * 2200
)
_SPEC = b"SPEC HEAD\n" + b"Requirement line: do not accept bad input.\n" * 380 + b"SPEC TAIL\n"


def _rich_case(n: int, prose: int) -> DeterministicCase:
    base = _react_case()
    projection = base.projection
    obligations = dict(projection.obligations)
    claims = dict(projection.claims)
    sequences = iter(i for i in range(1, 100) if i not in {1, 2, 10, 11, 12, 20, 21, 22, 40, 50})
    for i in range(2, n + 2):
        obligations[obl(i)] = obligation_record(
            ObligationPublishedPayload(
                obl(i),
                f"Acceptance {i}: " + "scope detail " * (prose // 13),
                "The expected result is " + "requirement " * (prose // 12),
                ObligationStatus.OPEN,
            ),
            next(sequences),
        )
        claims[clm(i)] = record(
            ClaimRecordedPayload(
                clm(i),
                ClaimKind.COMPLETION,
                f"Claim {i}: " + "I implemented and checked this. " * (prose // 31),
                (),
                obligation_refs=(obl(i),),
            ),
            next(sequences),
        )
    rebuilt = make_case(
        plans=projection.plans,
        obligations=obligations,
        claims=claims,
        actions=projection.actions,
        results=projection.results,
        evidence=projection.evidence,
        extra_refs=tuple(base.allowed_ids),
    )
    return replace(rebuilt, task_statement=base.task_statement)


def _build(
    frozen: DeterministicCase,
    selection: ReviewSelectionPolicy = _SELECTION,
    ceiling: int | None = None,
    *,
    small: bool = False,
) -> SemanticCase:
    return composer.build_semantic_case(
        case_id="cas_10000000-0000-4000-8000-000000000001",
        frozen_case=frozen,
        dependency_digest="sha256:" + "b" * 64,
        findings=(),
        review_context_profile=ReviewContextProfile.CUSTOM,
        review_selection=selection,
        policy_id="pvy_10000000-0000-4000-8000-000000000001",
        policy_version="1",
        check_time_change=_change(
            b"diff --git a/form.py b/form.py\n+return value is not None\n" if small else _DIFF,
            inputs=(TaskInputFile("DESIGN.md", b"Reject None.\n", 13),)
            if small
            else (TaskInputFile("DESIGN.md", _SPEC, len(_SPEC)),),
        ),
        workspace_root="/app",
        captured_content_gaps=("content_unselected",) if selection != _SELECTION else (),
        prepared_byte_ceiling=ceiling,
    )


def _payload(case: SemanticCase) -> bytes:
    return composer.semantic_case_to_prepared_payload(case, {item.item_id for item in case.items})


@pytest.mark.parametrize("ceiling", [131_072])
@pytest.mark.parametrize("in_builder", [True, False])
def test_final_budget_protects_primary_material(ceiling: int, in_builder: bool) -> None:
    frozen = _rich_case(12, 2000)

    def rebuild(selection: ReviewSelectionPolicy) -> SemanticCase:
        return _build(frozen, selection, ceiling if in_builder else None)

    initial = rebuild(_SELECTION)
    case, _, _ = plan_under_channel_ceiling(initial, _SELECTION, ceiling, rebuild)
    assert len(_payload(case)) <= ceiling
    assert composer.check_time_change_bytes_carried(case) >= ceiling // 2 - 1024
    spec = next(item for item in case.items if item.item_id == "task-input-01")
    assert spec.content_bytes >= 2048
    assert b"SPEC HEAD" in spec.content and b"SPEC TAIL" in spec.content
    assert any(b"LATEST_NPM_TEST_RUN" in item.content for item in case.items)
    # Every removed narrative source is disclosed; counts survive the omission list's cap.
    carried = {item.source_ref for item in case.items if item.section in {"claim", "obligation"}}
    missing = {
        str(ref) for ref in (*frozen.projection.claims, *frozen.projection.obligations)
    } - carried
    omissions = {
        item.subject_ref for item in case.packet.omissions if item.reason == "not_selected"
    }
    assert missing and missing <= omissions
    assert "content_unselected" in case.packet.coverage.known_gaps
    assert case.packet.input_manifest is not None
    assert case.packet.input_manifest.omitted_item_total is not None
    assert case.packet.input_manifest.omitted_item_total >= len(omissions)
    again, _, _ = plan_under_channel_ceiling(rebuild(_SELECTION), _SELECTION, ceiling, rebuild)
    assert _payload(case) == _payload(again)


def test_aggregate_input_cut_builds_with_accounting() -> None:
    case = _build(_rich_case(24, 3000), ceiling=262_144)
    assert case.items
    assert "content_unselected" in case.packet.coverage.known_gaps
    assert all(
        item.subject_ref in case.frontier_refs | case.local_check_refs
        for item in case.packet.omissions
    )


def test_synthetic_task_input_omission_uses_linked_subjects() -> None:
    omissions: list[composer.ReviewOmission] = []
    composer._append_omission(  # pyright: ignore[reportPrivateUsage]
        omissions,
        "task-input",
        (str(obl(1)), "task-input"),
        composer.DataCategory.REPOSITORY_EXCERPT,
        "diff",
        "not_selected",
    )
    assert [item.subject_ref for item in omissions] == [str(obl(1))]


def test_small_packet_is_byte_identical_with_final_planning() -> None:
    frozen = _react_case()
    plain = _build(frozen, small=True)
    bounded = _build(frozen, ceiling=262_144, small=True)
    planned, selection, rounds = plan_under_channel_ceiling(
        bounded,
        _SELECTION,
        262_144,
        lambda selected: _build(frozen, selected, 262_144, small=True),
    )
    assert rounds == 0 and selection == _SELECTION
    assert bounded.case_digest == plain.case_digest == planned.case_digest
    assert _payload(bounded) == _payload(plain) == _payload(planned)


def test_observed_verification_survives_narrative_pressure() -> None:
    output = b"CHECK WITNESS: invalid input=None was rejected; assertion result=False\n" * 20
    observed, captured, scope = _captured_case_values(output)
    rich = _rich_case(12, 2000)
    projection = rich.projection
    frozen = make_case(
        plans=projection.plans,
        obligations=projection.obligations,
        claims=projection.claims,
        evidence=observed.projection.evidence,
        actions=projection.actions,
        results={
            ref: record(
                replace(row.payload, evidence_refs=tuple(observed.projection.evidence)),
                row.source_frontier,
            )
            for ref, row in projection.results.items()
            if row.payload is not None
        },
        extra_refs=tuple(rich.allowed_ids),
    )
    frozen = replace(frozen, task_statement=rich.task_statement)
    case = composer.build_semantic_case(
        case_id="cas_10000000-0000-4000-8000-000000000001",
        frozen_case=frozen,
        dependency_digest="sha256:" + "b" * 64,
        findings=(),
        review_context_profile=ReviewContextProfile.CUSTOM,
        review_selection=_SELECTION,
        policy_id="pvy_10000000-0000-4000-8000-000000000001",
        policy_version="1",
        check_time_change=_change(_DIFF, inputs=(TaskInputFile("DESIGN.md", _SPEC, len(_SPEC)),)),
        workspace_root="/app",
        prepared_byte_ceiling=131_072,
        captured_content=(captured,),
        captured_content_scope=scope,
    )
    assert len(_payload(case)) <= 131_072
    witness = next(item for item in case.items if b"CHECK WITNESS" in item.content)
    assert witness.content.startswith(b"[FinishUP: observed output captured by a host hook")
    assert witness.content_bytes >= len(output)
    assert composer.check_time_change_bytes_carried(case) >= 65_536 - 1024


def test_an_impossible_final_limit_cannot_lower_the_diff_floor() -> None:
    frozen = _rich_case(12, 2000)
    initial = _build(frozen)
    floor = composer.final_diff_floor(initial, _SELECTION, 4096)
    case, _, _ = plan_under_channel_ceiling(
        initial,
        _SELECTION,
        4096,
        lambda selection: _build(frozen, selection),
    )
    assert len(_payload(case)) > 4096  # Existing egress refusal; no falsely successful tiny diff.
    assert composer.check_time_change_bytes_carried(case) >= floor > 0


def test_pending_missing_input_context_survives_narrative_reduction() -> None:
    frozen = _rich_case(12, 2000)
    frozen = replace(
        frozen,
        projection=replace(
            frozen.projection,
            pending_missing_for_assessment=PendingMissingForAssessment(
                evt(1),
                1,
                (MissingForAssessmentItem("verification_output", (), "agent_suppliable"),),
            ),
        ),
    )
    case = _build(frozen, ceiling=131_072)
    assert "prior-missing-for-assessment" in case.packet.timeline_item_ids
    assert len(_payload(case)) <= 131_072
    assert composer.check_time_change_bytes_carried(case) >= 64_000
