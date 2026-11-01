"""Durability and idempotency checks for the project-coordination delivery store."""

from __future__ import annotations

import apsw
import pytest

from finishup.adapters.sqlite.project_coordination import SqliteCoordinationStore
from finishup.application.coordination import CoordinationAdvice, CoordinationParticipant
from finishup.domain.coordination import (
    CoordinationCoverage,
    CoordinationDetection,
    CoordinationError,
    CoordinationErrorCode,
    CoordinationGapCode,
    CoordinationObligationState,
    OverlapKind,
    coordination_detection_identity,
)
from finishup.domain.values import ObligationId
from finishup.protocol.canonical import canonical_digest
from finishup.protocol.ids import IdKind, new_id

pytestmark = pytest.mark.anyio


def _commitment(seed: str) -> str:
    return "hmac-sha256:" + seed * 64


def _schema(db: apsw.Connection) -> None:
    db.execute(
        """
        CREATE TABLE coordination_detections (
            detection_id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL,
            membership_generation INTEGER NOT NULL,
            left_task_id TEXT NOT NULL,
            right_task_id TEXT NOT NULL,
            overlap_kind TEXT NOT NULL,
            resource_identities_json TEXT NOT NULL,
            counterpart_task_id TEXT NOT NULL,
            advice_only INTEGER NOT NULL,
            obligation_declared INTEGER NOT NULL,
            addressed INTEGER NOT NULL,
            generation_valid INTEGER NOT NULL,
            detail_ref_json TEXT,
            resolved INTEGER NOT NULL
        )
        """
    )
    db.execute(
        """
        CREATE TABLE coordination_participants (
            detection_id TEXT NOT NULL,
            task_id TEXT NOT NULL,
            project_id TEXT NOT NULL,
            repository_commitment TEXT NOT NULL,
            workspace_commitment TEXT NOT NULL,
            route_generation INTEGER NOT NULL,
            source_has_attributable_paths INTEGER NOT NULL,
            PRIMARY KEY (detection_id, task_id)
        )
        """
    )
    db.execute(
        """
        CREATE TABLE coordination_deliveries (
            detection_id TEXT NOT NULL,
            target_task_id TEXT NOT NULL,
            outcome TEXT NOT NULL,
            expected_generation INTEGER NOT NULL,
            observed_generation INTEGER NOT NULL,
            reason_code TEXT,
            advice_json TEXT,
            PRIMARY KEY (detection_id, target_task_id)
        )
        """
    )
    db.execute(
        """
        CREATE TABLE coordination_obligations (
            detection_id TEXT NOT NULL,
            task_id TEXT NOT NULL,
            obligation_id TEXT,
            declared INTEGER NOT NULL,
            addressed INTEGER NOT NULL,
            resolved INTEGER NOT NULL,
            PRIMARY KEY (detection_id, task_id)
        )
        """
    )
    db.execute(
        """
        CREATE TABLE coordination_coverage (
            coverage_id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL,
            task_id TEXT NOT NULL,
            membership_generation INTEGER NOT NULL,
            coverage TEXT NOT NULL,
            gap_code TEXT NOT NULL,
            UNIQUE (project_id, task_id, membership_generation)
        )
        """
    )


def _detection() -> tuple[
    CoordinationDetection,
    tuple[CoordinationParticipant, CoordinationParticipant],
]:
    project = new_id(IdKind.PROJECT)
    left = new_id(IdKind.TASK)
    right = new_id(IdKind.TASK)
    repository = _commitment("a")
    resource = canonical_digest(
        {
            "case_sensitive": True,
            "path": "src/a.py",
            "repository_commitment": repository,
        }
    )
    detection_id = coordination_detection_identity(
        project_id_value=project,
        membership_generation=1,
        left_task_id=left,
        right_task_id=right,
        resource_identities=(resource,),
    )
    detection = CoordinationDetection(
        detection_id,
        project,
        1,
        left,
        right,
        OverlapKind.INTEGRATION,
        (resource,),
        right,
    )
    participants = (
        CoordinationParticipant(left, project, repository, _commitment("b"), 1),
        CoordinationParticipant(right, project, repository, _commitment("c"), 1),
    )
    return detection, participants


async def test_sqlite_store_round_trips_detection_participants_and_two_deliveries() -> None:
    db = apsw.Connection(":memory:")
    _schema(db)
    try:
        store = SqliteCoordinationStore(db)
        detection, participants = _detection()
        assert await store.put_detection(detection) == detection
        assert await store.put_detection(detection) == detection
        await store.put_participants(detection.detection_id, participants)
        stored_participants = await store.participants(detection.detection_id)
        assert stored_participants is not None
        assert {item.task_id for item in stored_participants} == {
            item.task_id for item in participants
        }

        first = CoordinationAdvice(
            detection.detection_id,
            participants[0].task_id,
            participants[1].task_id,
            detection.project_id,
            detection.membership_generation,
            detection.overlap_kind,
            detection.resource_identities,
            len(detection.resource_identities),
        )
        second = await store.put_advice(first)
        duplicate = await store.put_advice(first)
        assert second.outcome == "delivered"
        assert duplicate.outcome == "duplicate"
        assert await store.advice_for(detection.detection_id, participants[0].task_id) == first
        deliveries = await store.deliveries(detection.detection_id)
        assert len(deliveries) == 1
        assert deliveries[0].outcome == "delivered"
    finally:
        db.close(force=True)


async def test_sqlite_store_keeps_obligation_and_detection_transitions_forward_only() -> None:
    db = apsw.Connection(":memory:")
    _schema(db)
    try:
        store = SqliteCoordinationStore(db)
        detection, _participants = _detection()
        await store.put_detection(detection)
        obligation = new_id(IdKind.OBLIGATION)
        state = CoordinationObligationState(
            detection.detection_id,
            detection.left_task_id,
            True,
            obligation_id=ObligationId(obligation),
        )
        assert await store.set_obligation(state) == state
        addressed = CoordinationObligationState(
            detection.detection_id,
            detection.left_task_id,
            True,
            addressed=True,
            obligation_id=ObligationId(obligation),
        )
        assert await store.set_obligation(addressed) == addressed
        with pytest.raises(CoordinationError) as error:
            await store.set_obligation(state)
        assert error.value.code is CoordinationErrorCode.SELECTOR_CONFLICT

        updated = CoordinationDetection(
            detection.detection_id,
            detection.project_id,
            detection.membership_generation,
            detection.left_task_id,
            detection.right_task_id,
            detection.overlap_kind,
            detection.resource_identities,
            detection.counterpart_task_id,
            advice_only=False,
            obligation_declared=True,
            addressed=True,
        )
        assert await store.replace_detection(updated) == updated
        with pytest.raises(CoordinationError) as error:
            await store.replace_detection(
                CoordinationDetection(
                    detection.detection_id,
                    detection.project_id,
                    detection.membership_generation,
                    detection.left_task_id,
                    detection.right_task_id,
                    detection.overlap_kind,
                    (canonical_digest({"other": "resource"}),),
                    detection.counterpart_task_id,
                    advice_only=False,
                    obligation_declared=True,
                    addressed=True,
                )
            )
        assert error.value.code is CoordinationErrorCode.SELECTOR_CONFLICT
    finally:
        db.close(force=True)


async def test_sqlite_store_round_trips_generation_scoped_coverage() -> None:
    db = apsw.Connection(":memory:")
    _schema(db)
    try:
        store = SqliteCoordinationStore(db)
        project = new_id(IdKind.PROJECT)
        task = new_id(IdKind.TASK)
        coverage = CoordinationCoverage(
            new_id(IdKind.EVENT),
            project,
            task,
            7,
            "unobservable",
            CoordinationGapCode.NOT_OBSERVABLE,
        )
        assert await store.put_coverage(coverage) == coverage
        assert await store.put_coverage(coverage) == coverage
        assert await store.coverage_for(project, 7) == (coverage,)
        assert await store.coverage_for(project, 8) == ()

        conflicting = CoordinationCoverage(new_id(IdKind.EVENT), project, task, 7)
        with pytest.raises(CoordinationError) as error:
            await store.put_coverage(conflicting)
        assert error.value.code is CoordinationErrorCode.SELECTOR_CONFLICT
    finally:
        db.close(force=True)
