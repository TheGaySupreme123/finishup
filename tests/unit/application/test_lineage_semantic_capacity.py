"""Lineage semantic input stays complete across the item bound (issue #826)."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import replace

import pytest

from builders.policy_cases import make_case, obl, plan_record
from finishup.application.semantic_case import (
    MAX_SEMANTIC_ITEM_BYTES,
    LineageSemanticCapacityExceeded,
    build_semantic_case,
)
from finishup.domain.coordination import LineageAcceptance, LineageOrigin, SessionHealth, WorkState
from finishup.domain.events import PlanPublishedPayload
from finishup.domain.findings import FINDING_KIND_TRAITS, FindingKind, FindingOrigin
from finishup.domain.privacy import ReviewContextProfile, ReviewSelectionPolicy
from finishup.domain.values import Frontier, event_id, finding_id, receipt_id, task_id
from finishup.kernel.lineage import (
    ChildDependencySnapshot,
    ChildFindingSnapshot,
    LineageEvaluation,
    LineageManifest,
    evaluate_lineage,
)
from finishup.ports.semantic import SemanticCase, SemanticCaseItem
from finishup.protocol.canonical import JsonValue, strict_json_parse
from finishup.protocol.coverage import PublicationChannel, coverage_for_channel
from finishup.protocol.models import DataCategory

_DIGEST = "sha256:" + "1" * 64
_FRONTIER = Frontier(3, _DIGEST)
_CHECK = event_id("evt_00000000-0000-4000-8000-000000000003")
_RECEIPT = receipt_id("rcp_00000000-0000-4000-8000-000000000001")
_MANIFEST = event_id("evt_00000000-0000-4000-8000-000000000001")


def _child(index: int) -> ChildDependencySnapshot:
    return ChildDependencySnapshot(
        child_task_id=task_id(f"tsk_00000000-0000-4000-8000-{index:012d}"),
        origin=LineageOrigin.PARENT_MINTED,
        acceptance=LineageAcceptance.ACCEPTED,
        work_state=WorkState.CLOSED,
        session_health=SessionHealth.ENDED,
        child_frontier=_FRONTIER,
        child_check_id=_CHECK,
        child_receipt_id=_RECEIPT,
        coverage=coverage_for_channel(PublicationChannel.ENGINE_DERIVED),
        findings=(),
        lineage_authority_revision="rev-1",
        read_gap_reasons=(),
        child_check_subject_frontier=_FRONTIER,
        manifest_event_id=_MANIFEST,
    )


def _evaluation(count: int, *, findings_per_child: int = 0) -> LineageEvaluation:
    kind = FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS
    children = tuple(
        replace(
            _child(index),
            findings=tuple(
                ChildFindingSnapshot(
                    finding_id(f"fnd_00000000-0000-4000-8000-{index * 100 + number:012d}"),
                    kind,
                    FindingOrigin.DETERMINISTIC,
                    FINDING_KIND_TRAITS[kind][0],
                    False,
                )
                for number in range(findings_per_child)
            ),
        )
        for index in range(1, count + 1)
    )
    return evaluate_lineage(LineageManifest(children))


def _case(count: int, *, findings_per_child: int = 0, parent_plan: bool = False) -> SemanticCase:
    profile = ReviewContextProfile.GOAL_AWARE if parent_plan else ReviewContextProfile.STRUCTURAL
    return build_semantic_case(
        case_id="cas_10000000-0000-4000-8000-000000000001",
        frozen_case=make_case(
            plans={1: plan_record(PlanPublishedPayload(1, "Parent work", (obl(1),)), 1)}
            if parent_plan
            else None
        ),
        dependency_digest="sha256:" + "b" * 64,
        findings=(),
        review_context_profile=profile,
        review_selection=ReviewSelectionPolicy.for_profile(profile),
        policy_id="pvy_10000000-0000-4000-8000-000000000001",
        policy_version="1",
        lineage_evaluation=_evaluation(count, findings_per_child=findings_per_child),
    )


def _lineage_items(case: SemanticCase) -> tuple[SemanticCaseItem, ...]:
    return tuple(item for item in case.items if item.source_ref == "lineage")


def _body(item: SemanticCaseItem) -> Mapping[str, JsonValue]:
    parsed = strict_json_parse(item.content)
    assert isinstance(parsed, dict)
    return parsed


def _child_ids(items: tuple[SemanticCaseItem, ...]) -> list[str]:
    found: list[str] = []
    for item in items:
        children = _body(item).get("children")
        assert isinstance(children, list)
        for row in children:
            assert isinstance(row, dict)
            child_id = row.get("child_task_id")
            assert isinstance(child_id, str)
            found.append(child_id)
    return found


def test_counts_around_the_item_bound_keep_every_child() -> None:
    observed: list[dict[str, object]] = []
    for count in (4, 8, 16, 22, 23, 24, 32, 64):
        case = _case(count)
        items = _lineage_items(case)
        ids = _child_ids(items)
        assert ids == sorted(set(ids), key=str.encode)
        assert len(ids) == count
        assert all(item.content_bytes <= MAX_SEMANTIC_ITEM_BYTES for item in items)
        assert all(item.item_id in case.packet.timeline_item_ids for item in items)
        schema = _body(items[0]).get("schema")
        observed.append(
            {
                "children": count,
                "parts": len(items),
                "bytes": [item.content_bytes for item in items],
                "schema": schema,
            }
        )
    assert observed[2]["parts"] == 1
    assert observed[2]["schema"] == "yoetz.lineage-semantic-input/1"
    assert observed[3]["children"] == 22
    assert observed[3]["bytes"] == [16196]
    assert observed[4]["parts"] == 2
    assert observed[4]["schema"] == "yoetz.lineage-semantic-input/2"
    assert observed[7]["children"] == 64
    fanout_parts = observed[7]["parts"]
    assert isinstance(fanout_parts, int)
    assert fanout_parts >= 2
    print(json.dumps(observed))


def test_partition_is_deterministic_and_commits_the_manifest() -> None:
    first = _lineage_items(_case(32))
    second = _lineage_items(_case(32))
    assert [item.content_digest for item in first] == [item.content_digest for item in second]
    digest = _body(first[0]).get("manifest_digest")
    assert isinstance(digest, str) and digest.startswith("sha256:")
    for index, item in enumerate(first):
        body = _body(item)
        assert body.get("schema") == "yoetz.lineage-semantic-input/2"
        assert body.get("manifest_digest") == digest
        assert body.get("part_index") == index
        assert body.get("part_count") == len(first)
        assert body.get("child_count") == 32
        assert item.item_id == f"lineage-{index:02d}"
    assert len(_child_ids(first)) == 32


def test_one_irreducible_child_is_a_capacity_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("finishup.application.semantic_case.MAX_SEMANTIC_ITEM_BYTES", 32)
    with pytest.raises(LineageSemanticCapacityExceeded, match="lineage_semantic_input_too_large"):
        _case(1)


def test_eight_children_are_complete_json_not_a_four_kib_cut() -> None:
    items = _lineage_items(_case(8))
    assert len(items) == 1
    assert items[0].item_id == "lineage"
    assert items[0].content_bytes == 5990
    assert len(_child_ids(items)) == 8
    assert _body(items[0]).get("schema") == "yoetz.lineage-semantic-input/1"


def test_finding_heavy_allowed_fanout_is_a_typed_total_capacity_error() -> None:
    # Each child admits 100 findings and each part fits 16 KiB, but the complete
    # set exceeds the independent 256 KiB case limit.
    with pytest.raises(LineageSemanticCapacityExceeded, match="lineage_semantic_case_too_large"):
        _case(32, findings_per_child=100)


def test_total_capacity_includes_retained_parent_content(monkeypatch: pytest.MonkeyPatch) -> None:
    child_only = _case(1)
    boundary = sum(item.content_bytes for item in child_only.items)
    monkeypatch.setattr("finishup.application.semantic_case.MAX_SEMANTIC_CASE_BYTES", boundary)
    assert _case(1) == child_only
    # n7 RC7 (d0781f890, ADR-006): at the case bound the agent's own narrative (here the parent
    # plan) is omitted before primary material, and independent lineage stays whole. The plan's
    # omission is disclosed, never silent.
    with_plan = _case(1, parent_plan=True)
    assert _lineage_items(with_plan) == _lineage_items(child_only)
    assert not any(item.section == "goal" for item in with_plan.items)
    assert "content_unselected" in with_plan.packet.coverage.known_gaps
    assert any(
        omission.category is DataCategory.TASK_DESCRIPTION and omission.reason == "not_selected"
        for omission in with_plan.packet.omissions
    )
    # Lineage alone over the bound is still refused, never cut.
    monkeypatch.setattr("finishup.application.semantic_case.MAX_SEMANTIC_CASE_BYTES", boundary - 1)
    with pytest.raises(LineageSemanticCapacityExceeded, match="lineage_semantic_case_too_large"):
        _case(1)
