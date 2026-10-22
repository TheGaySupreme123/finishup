"""Criterion coverage precedes the packet while retaining disclosure and capture fences."""

from __future__ import annotations

from dataclasses import replace

import pytest

from builders.policy_cases import (
    act,
    evt,
    make_case,
    obl,
    obligation_record,
    plan_record,
    record,
    res,
)
from finishup.application.semantic_case import (
    CheckTimeChange,
    _auto_supply_refusal,  # pyright: ignore[reportPrivateUsage]
    build_semantic_case,
    check_time_change_floor_bytes_carried,
    semantic_case_to_prepared_payload,
)
from finishup.domain.events import (
    ActionKind,
    ActionRecordedPayload,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
    ResultOutcome,
    ResultRecordedPayload,
    ResultVerification,
    VerificationDataSource,
    encode_payload,
)
from finishup.domain.privacy import ReviewContextProfile, ReviewSelectionPolicy
from finishup.domain.task_statement import RecordedTaskStatement
from finishup.kernel.deterministic_checks import DeterministicCase, FrozenHistoryEvent
from finishup.ports.semantic import SemanticCase
from finishup.protocol.canonical import canonical_digest
from finishup.protocol.models import DataCategory
from unit.application.test_semantic_case_check_change import (
    _change,  # pyright: ignore[reportPrivateUsage]
)


def _case(*, manifest: bool = True) -> DeterministicCase:
    criterion = "Every prediction must be within 20 mm."
    case = make_case(
        plans={1: plan_record(PlanPublishedPayload(1, "Deliver predictions", (obl(1),)), 1)},
        obligations={
            obl(1): obligation_record(
                ObligationPublishedPayload(
                    obl(1), "Prediction accuracy", criterion, ObligationStatus.OPEN
                ),
                2,
            )
        },
        actions={
            act(1): record(
                ActionRecordedPayload(
                    act(1), ActionKind.COMMAND, "Run the independent probe", "python stress.py"
                ),
                3,
            )
        },
        results={
            res(1): record(
                ResultRecordedPayload(
                    res(1),
                    act(1),
                    ResultOutcome.PARTIAL,
                    summary="6/100 failing; worst 105.61 mm; failure examples retained.",
                    verification=ResultVerification(
                        criterion, VerificationDataSource.OWN_GENERATED, 100, 6, worst="105.61 mm"
                    )
                    if manifest
                    else None,
                ),
                4,
            )
        },
        extra_refs=(obl(1), act(1), res(1), evt(1)),
    )
    return replace(
        case, task_statement=RecordedTaskStatement(criterion, evt(1), "plan_published", 1)
    )


def _build(
    selection: ReviewSelectionPolicy | None = None,
    *,
    frozen: DeterministicCase | None = None,
    change: CheckTimeChange | None = None,
) -> SemanticCase:
    return build_semantic_case(
        case_id="cas_10000000-0000-4000-8000-000000000001",
        frozen_case=frozen or _case(),
        dependency_digest="sha256:" + "b" * 64,
        findings=(),
        review_context_profile=ReviewContextProfile.CUSTOM
        if selection is not None
        else ReviewContextProfile.EXPANDED,
        review_selection=selection
        or ReviewSelectionPolicy.for_profile(ReviewContextProfile.EXPANDED),
        policy_id="pvy_10000000-0000-4000-8000-000000000001",
        policy_version="1",
        check_time_change=change,
    )


def test_packet_leads_with_agent_declared_failures_and_keeps_the_script_result() -> None:
    case = _build()
    first = case.items[0]
    assert first.section == "verification_coverage"
    assert case.packet.verification_coverage_item_ids == (first.item_id,)
    assert b'"label":"agent-declared"' in first.content
    assert b'"advisory":true' in first.content
    assert b'"failing":6' in first.content
    assert b'"own_or_tuned_only"' in first.content
    assert b'"criterion_span"' in first.content
    assert b"Every prediction" not in first.content
    assert any(b"failure examples retained" in item.content for item in case.items)
    prepared = semantic_case_to_prepared_payload(
        case, frozenset(item.item_id for item in case.items)
    )
    assert prepared.find(b'"verification_coverage"') < prepared.find(b'"task_statement"')


def test_only_a_manifest_bearing_review_asks_the_test_quality_question() -> None:
    question = _build().question_set[-1]
    assert question.startswith("When test manifests are present")
    for rule in (
        "an agent-declared manifest is not independent proof",
        "any expected value copied from the answer",
        "do not invent a test when no useful discriminator exists",
        "Do not request another unchanged run",
    ):
        assert rule in question
    plain = _build(frozen=_case(manifest=False)).question_set
    assert not any("test manifests" in text for text in plain)


def test_task_quote_and_manifest_stay_out_when_task_section_is_not_selected() -> None:
    selection = ReviewSelectionPolicy.for_profile(ReviewContextProfile.EXPANDED)
    case = _build(
        replace(
            selection,
            sections=tuple(
                section for section in selection.sections if section != "task_statement"
            ),
        )
    )
    assert case.packet.verification_coverage_item_ids == ()
    assert not any(item.section == "verification_coverage" for item in case.items)
    assert not any(b"criterion_quote" in item.content for item in case.items)


@pytest.mark.parametrize(
    ("profile", "carried"),
    [
        (ReviewContextProfile.STRUCTURAL, False),
        (ReviewContextProfile.GOAL_AWARE, False),
        (ReviewContextProfile.ASSISTED, True),
        (ReviewContextProfile.EXPANDED, True),
    ],
)
def test_only_profiles_selecting_task_text_and_test_excerpts_carry_the_index(
    profile: ReviewContextProfile, carried: bool
) -> None:
    case = _build(ReviewSelectionPolicy.for_profile(profile))
    assert bool(case.packet.verification_coverage_item_ids) is carried
    assert any(item.section == "verification_coverage" for item in case.items) is carried


def test_category_filtering_keeps_criterion_text_out_of_structural_and_evidence_items() -> None:
    frozen = _case()
    result = frozen.projection.results[res(1)].payload
    assert result is not None
    payload = encode_payload(result)
    digest = canonical_digest(payload)
    history = FrozenHistoryEvent(
        evt(4),
        "result_recorded",
        "1.1.0",
        4,
        "2026-10-21T00:00:00.000Z",
        None,
        None,
        digest,
        "available",
        payload,
    )
    for event in (history, replace(history, payload=None, content_visibility="not_selected")):
        case = _build(frozen=replace(frozen, history=(event,), history_availability="available"))
        selected = frozenset(
            item.item_id
            for item in case.items
            if item.category not in {DataCategory.TASK_DESCRIPTION, DataCategory.OBLIGATION_TEXT}
        )
        prepared = semantic_case_to_prepared_payload(case, selected)
        assert b"Every prediction must" not in prepared
        assert digest.encode() not in prepared
        assert b"criterion_span" in prepared


def test_coverage_does_not_take_the_reserved_current_diff_budget() -> None:
    selection = replace(
        ReviewSelectionPolicy.for_profile(ReviewContextProfile.EXPANDED),
        max_excerpts=4,
        max_excerpt_bytes=1024,
        max_total_excerpt_bytes=1024,
    )
    change = _change(b"diff --git a/code.py b/code.py\n" + b"+return value\n" * 300)
    case = _build(selection, change=change)
    assert case.packet.verification_coverage_item_ids
    assert check_time_change_floor_bytes_carried(case) >= selection.max_total_excerpt_bytes // 2
    assert (
        sum(item.content_bytes for item in case.packet.targeted_excerpts)
        <= selection.max_total_excerpt_bytes
    )


def test_declared_custom_output_still_requires_authenticated_context_and_safe_paths() -> None:
    identity = "omitted:hmac-sha256:" + "a" * 64

    def refusal(text: str | None = "python stress.py", *, declared: bool = False) -> str | None:
        return _auto_supply_refusal(
            identity,
            b"6/100 failed",
            workspace_root="/app",
            check_time_change=None,
            captured_command=text,
            captured_identity=identity,
            declared_verification=declared,
        )

    assert refusal() == "withheld_by_policy"
    assert refusal(declared=True) is None
    assert refusal(None, declared=True) == "withheld_by_policy"
    assert refusal("python stress.py ../private", declared=True) == "withheld_by_policy"
