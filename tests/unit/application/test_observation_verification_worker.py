"""Durable generation-fenced observation verification repository behavior."""

from __future__ import annotations

import apsw

from finishup.adapters.approved_checks import (
    ApprovedCheckOutcome,
    ApprovedCheckResult,
    ApprovedCheckStatus,
)
from finishup.adapters.sqlite.migrations import initialize_bundle
from finishup.adapters.sqlite.observation_verification import (
    SqliteObservationVerificationRepository,
)

_WORKSPACE = "hmac-sha256:" + "a" * 64
_POLICY = "sha256:" + "b" * 64
_APPROVAL = "sha256:" + "c" * 64
_STATE_A = "sha256:" + "d" * 64
_STATE_B = "sha256:" + "e" * 64
_NOW = "2026-07-23T10:00:00.000Z"
_LATER = "2026-07-23T10:05:00.000Z"


def _repository() -> tuple[apsw.Connection, SqliteObservationVerificationRepository]:
    db = apsw.Connection(":memory:")
    initialize_bundle(db, {"task_id": "task_verification", "owner_generation": "1"})
    return db, SqliteObservationVerificationRepository(db)


def _result() -> ApprovedCheckResult:
    return ApprovedCheckResult(
        status=ApprovedCheckStatus.PASSED,
        outcome=ApprovedCheckOutcome.SUCCESS,
        exit_status=0,
        output_digest="sha256:" + "f" * 64,
        output_bytes=0,
        subject_state_digest=_STATE_B,
        approval_commitment=_APPROVAL,
        result_digest="sha256:" + "1" * 64,
        duration_ms=1,
    )


def test_rapid_changes_coalesce_and_identical_state_is_cached() -> None:
    db, repository = _repository()
    first = repository.enqueue_latest(
        workspace=_WORKSPACE,
        policy_digest=_POLICY,
        approvals=(_APPROVAL,),
        subject_state_digest=_STATE_A,
        enqueued_at=_NOW,
    )
    second = repository.enqueue_latest(
        workspace=_WORKSPACE,
        policy_digest=_POLICY,
        approvals=(_APPROVAL,),
        subject_state_digest=_STATE_B,
        enqueued_at=_LATER,
    )
    duplicate = repository.enqueue_latest(
        workspace=_WORKSPACE,
        policy_digest=_POLICY,
        approvals=(_APPROVAL,),
        subject_state_digest=_STATE_B,
        enqueued_at=_LATER,
    )
    assert len(first) == len(second) == 1
    assert duplicate == ()
    assert db.execute(
        "SELECT subject_state_digest,status FROM observation_verification_jobs ORDER BY state_token"
    ).fetchall() == [(_STATE_A, "stale"), (_STATE_B, "pending")]


def test_new_service_generation_recovers_abandoned_lease_and_result_is_immutable() -> None:
    db, repository = _repository()
    repository.enqueue_latest(
        workspace=_WORKSPACE,
        policy_digest=_POLICY,
        approvals=(_APPROVAL,),
        subject_state_digest=_STATE_B,
        enqueued_at=_NOW,
    )
    first = repository.claim_next(
        service_generation=1,
        lease_owner="service-one",
        lease_expires_at=_LATER,
        now=_NOW,
    )
    assert first is not None
    recovered = repository.claim_next(
        service_generation=2,
        lease_owner="service-two",
        lease_expires_at="2026-07-23T10:10:00.000Z",
        now="2026-07-23T10:01:00.000Z",
    )
    assert recovered == first
    assert recovered is not None
    repository.complete(
        job=recovered,
        service_generation=2,
        lease_owner="service-two",
        check_id="smoke",
        result=_result(),
        subject_state_after=_STATE_B,
        result_commitment=_result().result_digest,
        output_object_id=None,
        limitations_json=b"[]",
        is_current=True,
        recorded_at=_LATER,
    )
    assert db.execute(
        "SELECT status,is_current,result_commitment FROM observation_verification_results"
    ).fetchone() == ("passed", 1, _result().result_digest)
    assert (
        repository.claim_next(
            service_generation=2,
            lease_owner="service-two",
            lease_expires_at="2026-07-23T10:15:00.000Z",
            now=_LATER,
        )
        is None
    )
