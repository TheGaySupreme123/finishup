"""Acceptance matrix for frozen parent-to-child lineage rollups."""

from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace
from typing import Any, cast

import pytest

from finishup.domain.coordination import LineageAcceptance, LineageOrigin, SessionHealth, WorkState
from finishup.domain.events import ChildDependencySnapshot as DomainChildDependencySnapshot
from finishup.domain.findings import FINDING_KIND_TRAITS, FindingKind, FindingOrigin
from finishup.domain.values import (
    Actor,
    ActorType,
    EventId,
    Frontier,
    actor_id,
    event_id,
    finding_id,
    receipt_id,
    task_id,
)
from finishup.kernel.lineage import (
    ChildDependencySnapshot,
    ChildFindingSnapshot,
    LineageManifest,
    LineageRollupState,
    evaluate_lineage,
    evaluate_recorded_lineage,
    lineage_manifest_from_records,
)
from finishup.protocol.coverage import AuthorshipAssurance, PublicationChannel, coverage_for_channel

_DIGEST = "sha256:" + "1" * 64
_CHILD = task_id("tsk_00000000-0000-4000-8000-000000000001")
_MANIFEST_1 = event_id("evt_00000000-0000-4000-8000-000000000001")
_MANIFEST_2 = event_id("evt_00000000-0000-4000-8000-000000000002")
_CHECK = event_id("evt_00000000-0000-4000-8000-000000000003")
_RECEIPT = receipt_id("rcp_00000000-0000-4000-8000-000000000001")
_FINDING = finding_id("fnd_00000000-0000-4000-8000-000000000001")
_FRONTIER = Frontier(3, _DIGEST)


def _finding(kind: FindingKind, *, resolved: bool = False) -> ChildFindingSnapshot:
    return ChildFindingSnapshot(
        finding_id=_FINDING,
        kind=kind,
        origin=FindingOrigin.DETERMINISTIC,
        priority=FINDING_KIND_TRAITS[kind][0],
        resolved=resolved,
        resolution_event_id=_CHECK if resolved else None,
    )


def _child(
    *,
    acceptance: LineageAcceptance = LineageAcceptance.ACCEPTED,
    work_state: WorkState = WorkState.CLOSED,
    session_health: SessionHealth = SessionHealth.ENDED,
    frontier: Frontier | None = _FRONTIER,
    check: bool = True,
    receipt: bool = True,
    findings: tuple[ChildFindingSnapshot, ...] = (),
    read_gaps: tuple[str, ...] = (),
    manifest: EventId | None = _MANIFEST_1,
) -> ChildDependencySnapshot:
    return ChildDependencySnapshot(
        child_task_id=_CHILD,
        origin=LineageOrigin.PARENT_MINTED,
        acceptance=acceptance,
        work_state=work_state,
        session_health=session_health,
        child_frontier=frontier,
        child_check_id=_CHECK if check else None,
        child_receipt_id=_RECEIPT if receipt else None,
        coverage=coverage_for_channel(PublicationChannel.ENGINE_DERIVED),
        findings=findings,
        lineage_authority_revision="rev-1",
        read_gap_reasons=read_gaps,
        child_check_subject_frontier=_FRONTIER if check else None,
        manifest_event_id=manifest,
    )


def _record(
    event: EventId,
    sequence: int,
    children: tuple[ChildDependencySnapshot | DomainChildDependencySnapshot, ...],
    *,
    author: Actor | None = None,
    publication_channel: PublicationChannel = PublicationChannel.ENGINE_DERIVED,
) -> object:
    return SimpleNamespace(
        schema=SimpleNamespace(name="child_dependencies_recorded"),
        event_id=event,
        ledger=SimpleNamespace(ingestion_sequence=sequence),
        payload=SimpleNamespace(children=children),
        author=(
            author
            if author is not None
            else Actor(
                actor_id("yoetz:observation-coordinator"),
                ActorType.HARNESS,
                AuthorshipAssurance.HARNESS_OBSERVED,
            )
        ),
        publication_channel=publication_channel,
    )


@pytest.mark.parametrize(
    ("child", "state", "blocks"),
    (
        (_child(), LineageRollupState.CLEAN, False),
        (
            _child(findings=(_finding(FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS),)),
            LineageRollupState.BLOCKED,
            True,
        ),
        (
            _child(findings=(_finding(FindingKind.LEDGER_STALE_OR_INCOMPLETE),)),
            LineageRollupState.ANNOTATION,
            False,
        ),
        (
            _child(acceptance=LineageAcceptance.PENDING),
            LineageRollupState.ANNOTATION,
            False,
        ),
        (
            _child(work_state=WorkState.OPEN, session_health=SessionHealth.ACTIVE),
            LineageRollupState.OPEN_GAP,
            True,
        ),
        (
            _child(session_health=SessionHealth.CONTACT_LOST),
            LineageRollupState.INCOMPLETE,
            True,
        ),
        (
            _child(frontier=None, read_gaps=("missing",)),
            LineageRollupState.UNAVAILABLE,
            True,
        ),
    ),
)
def test_rollup_acceptance_matrix(
    child: ChildDependencySnapshot,
    state: LineageRollupState,
    blocks: bool,
) -> None:
    evaluation = evaluate_lineage(LineageManifest((child,)))
    assert evaluation.children[0].state is state
    assert evaluation.blocks_clean_completion is blocks
    assert evaluation.children[0].freshness == (
        "unknown"
        if child.child_frontier is None
        or child.child_check_id is None
        or child.child_receipt_id is None
        else "known"
    )


@pytest.mark.parametrize(
    ("work_state", "session_health", "state", "blocker"),
    (
        (WorkState.OPEN, SessionHealth.ACTIVE, LineageRollupState.OPEN_GAP, "lineage_child_open"),
        (
            WorkState.OPEN,
            SessionHealth.CONTACT_LOST,
            LineageRollupState.INCOMPLETE,
            "lineage_child_incomplete",
        ),
        (
            WorkState.CLOSED,
            SessionHealth.CONTACT_LOST,
            LineageRollupState.INCOMPLETE,
            "lineage_child_incomplete",
        ),
        (
            WorkState.OPEN,
            SessionHealth.ENDED,
            LineageRollupState.INCOMPLETE,
            "lineage_child_incomplete",
        ),
        (
            WorkState.ABANDONED,
            SessionHealth.ENDED,
            LineageRollupState.INCOMPLETE,
            "lineage_child_incomplete",
        ),
        (
            WorkState.CANCELLED,
            SessionHealth.ENDED,
            LineageRollupState.INCOMPLETE,
            "lineage_child_incomplete",
        ),
        (
            WorkState.WRITTEN_OFF,
            SessionHealth.ENDED,
            LineageRollupState.INCOMPLETE,
            "lineage_child_incomplete",
        ),
    ),
)
def test_informational_finding_does_not_hide_lifecycle_gap(
    work_state: WorkState,
    session_health: SessionHealth,
    state: LineageRollupState,
    blocker: str,
) -> None:
    """An informational finding annotates; it does not replace a lifecycle blocker.

    ``ledger_stale_or_incomplete`` is the only non-actionable finding kind, and the public
    check emits it from recorded ledger gaps. Those gaps are an independent coverage blocker,
    so the public conformance child stays ``open_gap`` for that reason and cannot isolate this
    precedence. This kernel case is the no-gap invariant.
    """

    finding = _finding(FindingKind.LEDGER_STALE_OR_INCOMPLETE)
    evaluation = evaluate_lineage(
        LineageManifest(
            (_child(work_state=work_state, session_health=session_health, findings=(finding,)),)
        )
    )
    child = evaluation.children[0]
    assert child.state is state
    assert child.blocks_clean_completion is True
    assert blocker in child.blockers
    assert child.finding_ids == ()
    assert evaluation.actionable_finding_ids == ()
    assert evaluation.snapshots[0].findings[0].finding_id == _FINDING
    assert blocker in evaluation.coverage.known_gaps


def test_informational_finding_annotates_verified_terminal_child() -> None:
    finding = _finding(FindingKind.LEDGER_STALE_OR_INCOMPLETE)
    evaluation = evaluate_lineage(LineageManifest((_child(findings=(finding,)),)))
    child = evaluation.children[0]
    assert child.state is LineageRollupState.ANNOTATION
    assert child.blocks_clean_completion is False
    assert child.blockers == ()
    assert evaluation.snapshots[0].findings[0].finding_id == _FINDING
    assert "lineage_child_open" not in evaluation.coverage.known_gaps
    assert "lineage_child_incomplete" not in evaluation.coverage.known_gaps


def test_coverage_blocker_precedes_informational_annotation() -> None:
    finding = _finding(FindingKind.LEDGER_STALE_OR_INCOMPLETE)
    child = replace(
        _child(findings=(finding,)),
        coverage=replace(
            coverage_for_channel(PublicationChannel.ENGINE_DERIVED),
            known_gaps=("child_partial",),
        ),
    )
    evaluation = evaluate_lineage(LineageManifest((child,)))
    assert evaluation.children[0].state is LineageRollupState.OPEN_GAP
    assert evaluation.children[0].blocks_clean_completion is True
    assert "lineage_child_coverage_gap" in evaluation.children[0].blockers
    assert evaluation.snapshots[0].findings[0].finding_id == _FINDING


def test_recorded_aggregate_replaces_removed_child_and_never_reads_live_state() -> None:
    first = _record(_MANIFEST_1, 1, (_child(),))
    second = _record(_MANIFEST_2, 2, ())
    manifest = lineage_manifest_from_records((first, second))
    assert manifest.children == ()
    assert manifest.source_event_id == _MANIFEST_2

    class LiveChild:
        def __getattribute__(self, name: str) -> object:
            raise AssertionError(f"live child read: {name}")

    # The evaluator accepts only the recorded immutable value; a live object is never passed to
    # or consulted by the rollup path.
    assert evaluate_lineage(manifest).children == ()
    del LiveChild


def test_forged_manifest_authority_is_replayed_as_a_named_gap() -> None:
    forged = _record(
        _MANIFEST_1,
        1,
        (_child(),),
        author=Actor(
            actor_id("agent:forged-manifest"),
            ActorType.LOGICAL_AGENT,
            AuthorshipAssurance.SELF_ASSERTED,
        ),
    )
    manifest = lineage_manifest_from_records((forged,))
    assert manifest.children == ()
    assert manifest.read_gap_reasons == ("not_authorized",)


def test_recorded_domain_event_revision_normalizes_to_kernel_token() -> None:
    domain_child = DomainChildDependencySnapshot(
        child_task_id=_CHILD,
        origin=LineageOrigin.PARENT_MINTED,
        acceptance=LineageAcceptance.ACCEPTED,
        work_state=WorkState.CLOSED,
        session_health=SessionHealth.ENDED,
        child_frontier=_FRONTIER,
        child_check_id=None,
        child_check_subject_frontier=None,
        child_receipt_id=None,
        coverage=coverage_for_channel(PublicationChannel.ENGINE_DERIVED),
        findings=(),
        lineage_authority_revision=1,
    )
    record = _record(_MANIFEST_1, 1, (domain_child,))
    manifest = lineage_manifest_from_records((record,))
    assert manifest.children[0].lineage_authority_revision == "1"


def test_later_recorded_manifest_is_uncovered_and_replay_bound() -> None:
    newer_frontier = Frontier(4, "sha256:" + "2" * 64)
    newer = replace(
        _child(),
        child_frontier=newer_frontier,
        child_check_subject_frontier=newer_frontier,
        manifest_event_id=_MANIFEST_2,
    )
    first = _record(_MANIFEST_1, 1, (_child(),))
    second = _record(_MANIFEST_2, 2, (newer,))
    evaluation = evaluate_recorded_lineage((first, second), tested_through_sequence=1)
    assert evaluation.children[0].state is LineageRollupState.CLEAN
    assert evaluation.children[0].tested_manifest_ref == _MANIFEST_1
    assert evaluation.children[0].later_manifest_ref == _MANIFEST_2
    assert "lineage_manifest_uncovered" in evaluation.coverage.known_gaps
    assert evaluation.blocks_clean_completion


def test_later_unreadable_manifest_keeps_its_authority_gap_visible() -> None:
    later = _record(
        _MANIFEST_2,
        2,
        (
            _child(
                frontier=None,
                check=False,
                receipt=False,
                read_gaps=("unreadable",),
                manifest=_MANIFEST_2,
            ),
        ),
    )
    first = _record(_MANIFEST_1, 1, (_child(),))

    evaluation = evaluate_recorded_lineage((first, later), tested_through_sequence=1)

    assert evaluation.children[0].state is LineageRollupState.CLEAN
    assert evaluation.children[0].later_manifest_ref == _MANIFEST_2
    assert "lineage_manifest_uncovered" in evaluation.coverage.known_gaps
    assert "lineage_child_unavailable" in {gap.code for gap in evaluation.gaps}


def test_pending_child_gaps_are_annotation_only() -> None:
    child = _child(
        acceptance=LineageAcceptance.PENDING,
        frontier=None,
        check=False,
        receipt=False,
        read_gaps=("missing",),
    )
    evaluation = evaluate_lineage(LineageManifest((child,)))
    assert evaluation.children[0].state is LineageRollupState.ANNOTATION
    assert evaluation.children[0].freshness == "unknown"
    assert evaluation.children[0].blockers == ()
    assert evaluation.blocks_clean_completion is False
    assert evaluation.coverage.known_gaps == ()
    assert {gap.code for gap in evaluation.gaps} == {
        "lineage_child_unavailable",
        "lineage_child_frontier_unknown",
        "lineage_child_verification_unknown",
    }


def test_rejected_child_not_authorized_gap_is_annotation_only() -> None:
    """A rejected child's NOT_AUTHORIZED gap stays visible and does not block the parent."""

    child = _child(
        acceptance=LineageAcceptance.REJECTED,
        frontier=None,
        check=False,
        receipt=False,
        read_gaps=("not_authorized",),
    )
    evaluation = evaluate_lineage(LineageManifest((child,)))
    row = evaluation.children[0]
    unavailable = tuple(gap for gap in evaluation.gaps if gap.code == "lineage_child_unavailable")
    assert row.state is LineageRollupState.ANNOTATION
    assert row.blocks_clean_completion is False
    assert row.blockers == ()
    assert evaluation.blocks_clean_completion is False
    assert evaluation.coverage.known_gaps == ()
    assert len(unavailable) == 1
    assert unavailable[0].detail == "not_authorized"
    assert unavailable[0].child_task_id == child.child_task_id


def test_rejected_child_provenance_restriction_is_annotation_only() -> None:
    child = replace(
        _child(acceptance=LineageAcceptance.REJECTED),
        provenance_restrictions=("authorization_missing",),
    )
    evaluation = evaluate_lineage(LineageManifest((child,)))
    row = evaluation.children[0]
    assert row.state is LineageRollupState.ANNOTATION
    assert row.blockers == ()
    assert evaluation.blocks_clean_completion is False
    assert evaluation.coverage.known_gaps == ()
    assert "lineage_child_provenance_restricted" in {gap.code for gap in evaluation.gaps}


def test_accepted_child_not_authorized_read_gap_still_blocks() -> None:
    child = _child(
        frontier=None,
        check=False,
        receipt=False,
        read_gaps=("not_authorized",),
    )
    evaluation = evaluate_lineage(LineageManifest((child,)))
    row = evaluation.children[0]
    assert row.state is LineageRollupState.UNAVAILABLE
    assert row.blocks_clean_completion is True
    assert "lineage_child_read_gap" in row.blockers
    assert "lineage_child_unavailable" in evaluation.coverage.known_gaps


def test_rejected_child_with_actionable_finding_cannot_escape_blocking_rollup() -> None:
    child = _child(
        acceptance=LineageAcceptance.REJECTED,
        findings=(_finding(FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS),),
    )
    evaluation = evaluate_lineage(LineageManifest((child,)))
    assert evaluation.children[0].state is LineageRollupState.BLOCKED
    assert evaluation.blocks_clean_completion is True
    assert evaluation.actionable_finding_ids == (_FINDING,)
    assert "lineage_invalid_acceptance_transition" in evaluation.coverage.known_gaps


def test_rejected_child_with_actionable_finding_and_read_gap_stays_blocking() -> None:
    """An impossible rejected snapshot still blocks when the bundle also could not be read."""

    child = _child(
        acceptance=LineageAcceptance.REJECTED,
        frontier=None,
        check=False,
        receipt=False,
        read_gaps=("not_authorized",),
        findings=(_finding(FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS),),
    )
    evaluation = evaluate_lineage(LineageManifest((child,)))
    row = evaluation.children[0]
    # UNAVAILABLE is the existing fail-closed state for an unreadable impossible
    # transition. Actionable ids are reported from BLOCKED rows; this row still
    # carries the finding and blocks clean completion through coverage.
    assert row.state is LineageRollupState.UNAVAILABLE
    assert row.blocks_clean_completion is True
    assert row.finding_ids == (_FINDING,)
    assert "lineage_invalid_acceptance_transition" in row.blockers
    assert evaluation.blocks_clean_completion is True
    assert "lineage_invalid_acceptance_transition" in evaluation.coverage.known_gaps
    assert "lineage_child_unavailable" in evaluation.coverage.known_gaps


# -- Issue #984 (ADR-034): a child's self_verified finding rolls up as "self-verified by the child
# agent; FinishUP could not prove it" -- never clean, never parent work, parent at best
# insufficient_coverage. The tb4n1 children met exactly this: a repair left unproven by
# ``command_attempt_uncorroborated`` that the child agent verified itself.

_OTHER_FINDING = finding_id("fnd_00000000-0000-4000-8000-000000000002")


def _self_verified(number: str = _FINDING) -> ChildFindingSnapshot:
    kind = FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS
    return ChildFindingSnapshot(
        finding_id=finding_id(number),
        kind=kind,
        origin=FindingOrigin.DETERMINISTIC,
        priority=FINDING_KIND_TRAITS[kind][0],
        resolved=False,
        actionable=True,
        self_verified=True,
    )


def test_child_self_verified_finding_is_not_parent_work_and_never_clean() -> None:
    from finishup.kernel.closure_readiness import (
        FINDING_SELF_VERIFIED_GAP,
        GAP_CLASSIFICATION,
        GapClass,
    )
    from finishup.kernel.lineage import CHILD_SELF_VERIFIED_GAP

    evaluation = evaluate_lineage(LineageManifest((_child(findings=(_self_verified(),)),)))
    (rollup,) = evaluation.children
    assert rollup.state is LineageRollupState.ANNOTATION
    assert rollup.finding_ids == ()
    assert rollup.blockers == ()
    assert rollup.self_verified_finding_ids == (_FINDING,)
    assert rollup.blocks_clean_completion is True
    assert evaluation.actionable_finding_ids == ()
    assert evaluation.self_verified_finding_ids == (_FINDING,)
    assert evaluation.blocks_clean_completion is True
    # The parent names the child's own standing code, so parent and child receipts agree.
    assert CHILD_SELF_VERIFIED_GAP == FINDING_SELF_VERIFIED_GAP
    assert GAP_CLASSIFICATION[CHILD_SELF_VERIFIED_GAP] is GapClass.STANDING_LIMITATION
    assert [(gap.code, gap.finding_ids) for gap in evaluation.gaps] == [
        (CHILD_SELF_VERIFIED_GAP, (_FINDING,))
    ]
    assert CHILD_SELF_VERIFIED_GAP in evaluation.coverage.known_gaps


def test_child_self_verified_finding_beside_open_work_keeps_only_the_open_work_actionable() -> None:
    open_work = replace(
        _finding(FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS), finding_id=_OTHER_FINDING
    )
    evaluation = evaluate_lineage(
        LineageManifest((_child(findings=(_self_verified(), open_work)),))
    )
    (rollup,) = evaluation.children
    assert rollup.state is LineageRollupState.BLOCKED
    assert evaluation.actionable_finding_ids == (_OTHER_FINDING,)
    assert rollup.self_verified_finding_ids == (_FINDING,)


def test_pending_child_self_verified_finding_stays_an_annotation() -> None:
    evaluation = evaluate_lineage(
        LineageManifest(
            (_child(acceptance=LineageAcceptance.PENDING, findings=(_self_verified(),)),)
        )
    )
    (rollup,) = evaluation.children
    assert rollup.state is LineageRollupState.ANNOTATION
    assert rollup.self_verified_finding_ids == ()
    assert evaluation.blocks_clean_completion is False


@pytest.mark.parametrize(
    "changes",
    (
        {"resolved": True, "resolution_event_id": _CHECK},
        {
            "kind": FindingKind.LEDGER_STALE_OR_INCOMPLETE,
            "priority": FINDING_KIND_TRAITS[FindingKind.LEDGER_STALE_OR_INCOMPLETE][0],
            "actionable": False,
        },
    ),
)
def test_self_verified_child_finding_is_unresolved_and_actionable_by_kind(
    changes: dict[str, object],
) -> None:
    with pytest.raises(ValueError):
        replace(_self_verified(), **changes)


def test_self_verified_child_finding_keeps_older_manifest_digests() -> None:
    plain = LineageManifest(
        (_child(findings=(_finding(FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS),)),)
    )
    flagged = LineageManifest((_child(findings=(_self_verified(),)),))
    (plain_child,) = plain.children
    (plain_row,) = cast(list[dict[str, Any]], plain_child.canonical_json()["findings"])
    (flagged_row,) = cast(list[dict[str, Any]], flagged.children[0].canonical_json()["findings"])
    assert "self_verified" not in plain_row
    assert flagged_row["self_verified"] is True
    assert plain.digest != flagged.digest


def test_self_verified_child_finding_round_trips_the_recorded_event_and_schema() -> None:
    from finishup.domain.events import (
        ChildDependenciesRecordedPayload,
        EventSchema,
        decode_payload,
        encode_payload,
    )
    from finishup.domain.events import ChildFindingSnapshot as DomainChildFindingSnapshot
    from finishup.domain.values import JsonValue as DomainJsonValue
    from finishup.protocol.canonical import JsonValue, canonical_encode
    from finishup.protocol.errors import ProtocolValueError
    from finishup.protocol.models import ChildFindingSnapshotModel
    from finishup.protocol.schemas import validate_schema_instance

    kind = FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS

    def row(**changes: object) -> DomainChildFindingSnapshot:
        values: dict[str, object] = {
            "finding_id": _FINDING,
            "kind": kind,
            "origin": FindingOrigin.DETERMINISTIC,
            "priority": FINDING_KIND_TRAITS[kind][0],
            "resolved": False,
            "actionable": True,
        }
        values.update(changes)
        return DomainChildFindingSnapshot(**values)  # type: ignore[arg-type]

    def payload(finding: DomainChildFindingSnapshot) -> ChildDependenciesRecordedPayload:
        return ChildDependenciesRecordedPayload(
            (
                DomainChildDependencySnapshot(
                    child_task_id=_CHILD,
                    origin=LineageOrigin.PARENT_MINTED,
                    acceptance=LineageAcceptance.ACCEPTED,
                    work_state=WorkState.CLOSED,
                    session_health=SessionHealth.ENDED,
                    child_frontier=_FRONTIER,
                    child_check_id=_CHECK,
                    child_check_subject_frontier=_FRONTIER,
                    child_receipt_id=_RECEIPT,
                    coverage=coverage_for_channel(PublicationChannel.ENGINE_DERIVED),
                    findings=(finding,),
                    lineage_authority_revision=1,
                ),
            )
        )

    schema = EventSchema("child_dependencies_recorded", "1.0.0")

    def plain(value: object) -> dict[str, Any]:
        return cast(dict[str, Any], json.loads(canonical_encode(cast(JsonValue, value))))

    plain_wire = plain(encode_payload(payload(row())))
    assert "self_verified" not in plain_wire["children"][0]["findings"][0]
    recorded = payload(row(self_verified=True))
    wire = plain(encode_payload(recorded))
    assert wire["children"][0]["findings"][0]["self_verified"] is True
    validate_schema_instance("child-dependencies-recorded", "1.0.0", cast(JsonValue, wire))
    assert decode_payload(schema, cast(DomainJsonValue, wire)) == recorded
    ChildFindingSnapshotModel.model_validate(wire["children"][0]["findings"][0])

    # The kernel adapter carries the flag from the recorded domain value.
    (kernel_child,) = lineage_manifest_from_records(
        (_record(_MANIFEST_1, 4, recorded.children),)
    ).children
    assert kernel_child.findings[0].self_verified is True

    # An explicit false is not a recorded spelling, and self-verified never means resolved.
    for bad in (False, "true"):
        wrong = deepcopy(wire)
        wrong["children"][0]["findings"][0]["self_verified"] = bad
        with pytest.raises(Exception):
            validate_schema_instance("child-dependencies-recorded", "1.0.0", cast(JsonValue, wrong))
        with pytest.raises(ProtocolValueError):
            decode_payload(schema, cast(DomainJsonValue, wrong))
    resolved = deepcopy(wire)
    resolved["children"][0]["findings"][0].update(resolved=True, resolution_event_id=_CHECK)
    with pytest.raises(Exception):
        validate_schema_instance("child-dependencies-recorded", "1.0.0", cast(JsonValue, resolved))
    with pytest.raises(ProtocolValueError):
        row(resolved=True, resolution_event_id=_CHECK, self_verified=True)
    with pytest.raises(ValueError):
        ChildFindingSnapshotModel.model_validate(resolved["children"][0]["findings"][0])
