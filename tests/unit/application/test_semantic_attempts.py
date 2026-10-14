"""Unit tests for durable AI-powered review attempt budget, retry matrix, and accounting."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Literal, cast

import pytest

from yoetz.application.semantic_attempts import (
    SemanticAttemptAccounting,
    attempt_accounting_from_rows,
    attempt_accounting_to_json,
    final_status_after_exhaustion,
    is_repairable_semantic_outcome,
    is_retriable_semantic_outcome,
    physical_attempt_budget,
    repair_retries_from_rows,
    run_durable_semantic_attempts,
    should_retry_after,
)
from yoetz.domain.findings import RuntimeTokenUsage, SemanticFailureClass
from yoetz.domain.values import Frontier
from yoetz.ports.ledger import (
    AttemptOutcome,
    CheckPhase,
    OperationLease,
    SemanticAttemptHandle,
    SemanticAttemptRecord,
    SemanticDisclosureWait,
    SemanticJobRecord,
)
from yoetz.ports.objects import ObjectKind, ObjectMetadata, ObjectRef
from yoetz.ports.semantic import Deadline
from yoetz.protocol.errors import PublicErrorCode, PublicOperationError
from yoetz.protocol.models import SemanticReason, SemanticStatus

_JOB = "job_40000000-0000-4000-8000-000000000001"
_ATT1 = "att_40000000-0000-4000-8000-000000000001"
_ATT2 = "att_40000000-0000-4000-8000-000000000002"
_ATT3 = "att_40000000-0000-4000-8000-000000000003"
_WRITER = "wri_40000000-0000-4000-8000-000000000001"
_OP = "req_40000000-0000-4000-8000-000000000001"
_SESSION = "ses_40000000-0000-4000-8000-000000000001"
_CASE = "sha256:" + "a" * 64
_DEP = "sha256:" + "b" * 64
_FRONTIER = Frontier(1, "sha256:" + "c" * 64)


def _case_ref() -> ObjectRef:
    return ObjectRef(
        "obj_40000000-0000-4000-8000-000000000001",
        2,
        "hmac-sha256:" + "d" * 64,
        "sha256:" + "e" * 64,
        "yoetz-object/1",
        "bmk-1",
        ObjectMetadata(
            ObjectKind.SEMANTIC_CASE,
            "application/json",
            "tsk_40000000-0000-4000-8000-000000000001",
            datetime(2026, 1, 1, tzinfo=UTC),
        ),
    )


def _response_ref() -> ObjectRef:
    return ObjectRef(
        "obj_40000000-0000-4000-8000-000000000002",
        2,
        "hmac-sha256:" + "f" * 64,
        "sha256:" + "1" * 64,
        "yoetz-object/1",
        "bmk-1",
        ObjectMetadata(
            ObjectKind.SEMANTIC_RESPONSE,
            "application/json",
            "tsk_40000000-0000-4000-8000-000000000001",
            datetime(2026, 1, 1, tzinfo=UTC),
        ),
    )


def _lease() -> OperationLease:
    return OperationLease(
        _WRITER,
        _OP,
        _SESSION,
        CheckPhase.SEMANTIC_WAIT,
        "owner-generation-1",
        "lease-owner-1",
        1,
        datetime(2030, 1, 1, tzinfo=UTC),
        _FRONTIER,
        _DEP,
    )


def test_physical_attempt_budget_caps_at_adr_006() -> None:
    assert physical_attempt_budget(0) == 1
    assert physical_attempt_budget(1) == 2
    assert physical_attempt_budget(2) == 3
    assert physical_attempt_budget(99) == 3


def test_retry_matrix_admits_only_approved_transient_classes() -> None:
    assert is_retriable_semantic_outcome(SemanticStatus.TIMEOUT, SemanticReason.PROVIDER_TIMEOUT)
    assert is_retriable_semantic_outcome(
        SemanticStatus.UNAVAILABLE, SemanticReason.TRANSPORT_UNAVAILABLE
    )
    assert is_retriable_semantic_outcome(
        SemanticStatus.UNAVAILABLE, SemanticReason.PROVIDER_RATE_LIMITED
    )
    assert not is_retriable_semantic_outcome(
        SemanticStatus.INVALID, SemanticReason.RESPONSE_SCHEMA_INVALID
    )
    assert not is_retriable_semantic_outcome(
        SemanticStatus.REFUSED, SemanticReason.PROVIDER_REFUSED
    )
    assert not is_retriable_semantic_outcome(
        SemanticStatus.BLOCKED_BY_POLICY, SemanticReason.NETWORK_EGRESS_DENIED
    )
    assert not is_retriable_semantic_outcome(
        SemanticStatus.HUMAN_DENIED, SemanticReason.HUMAN_DENIED
    )
    assert not is_retriable_semantic_outcome(
        SemanticStatus.UNAVAILABLE, SemanticReason.PROVIDER_QUOTA_EXHAUSTED
    )
    assert not is_retriable_semantic_outcome(SemanticStatus.STALE, SemanticReason.FRONTIER_CHANGED)
    assert not is_retriable_semantic_outcome(
        SemanticStatus.UNAVAILABLE,
        SemanticReason.TRANSPORT_UNAVAILABLE,
        failure_class=SemanticFailureClass.AUTHENTICATION,
    )
    assert not is_retriable_semantic_outcome(
        SemanticStatus.UNAVAILABLE,
        SemanticReason.TRANSPORT_UNAVAILABLE,
        failure_class=SemanticFailureClass.AUTHORIZATION,
    )
    assert is_retriable_semantic_outcome(
        SemanticStatus.UNAVAILABLE,
        SemanticReason.TRANSPORT_UNAVAILABLE,
        failure_class=SemanticFailureClass.TRANSPORT,
    )


def test_should_retry_respects_budget_and_deadline() -> None:
    assert should_retry_after(
        status=SemanticStatus.TIMEOUT,
        reason=SemanticReason.PROVIDER_TIMEOUT,
        attempts_completed=1,
        max_retries=2,
        deadline_expired=False,
    )
    assert not should_retry_after(
        status=SemanticStatus.TIMEOUT,
        reason=SemanticReason.PROVIDER_TIMEOUT,
        attempts_completed=1,
        max_retries=0,
        deadline_expired=False,
    )
    assert not should_retry_after(
        status=SemanticStatus.TIMEOUT,
        reason=SemanticReason.PROVIDER_TIMEOUT,
        attempts_completed=3,
        max_retries=2,
        deadline_expired=False,
    )
    assert not should_retry_after(
        status=SemanticStatus.TIMEOUT,
        reason=SemanticReason.PROVIDER_TIMEOUT,
        attempts_completed=1,
        max_retries=2,
        deadline_expired=True,
    )
    assert not should_retry_after(
        status=SemanticStatus.UNAVAILABLE,
        reason=SemanticReason.TRANSPORT_UNAVAILABLE,
        attempts_completed=1,
        max_retries=2,
        deadline_expired=False,
        failure_class=SemanticFailureClass.AUTHENTICATION,
    )


def test_final_status_after_exhaustion() -> None:
    status, reason = final_status_after_exhaustion(
        SemanticStatus.TIMEOUT,
        SemanticReason.PROVIDER_TIMEOUT,
        attempts_completed=1,
        max_retries=0,
    )
    assert (status, reason) == (SemanticStatus.TIMEOUT, SemanticReason.PROVIDER_TIMEOUT)

    status, reason = final_status_after_exhaustion(
        SemanticStatus.TIMEOUT,
        SemanticReason.PROVIDER_TIMEOUT,
        attempts_completed=3,
        max_retries=2,
    )
    assert (status, reason) == (
        SemanticStatus.UNAVAILABLE,
        SemanticReason.RETRY_BUDGET_EXHAUSTED,
    )


def test_attempt_accounting_from_rows_is_structural() -> None:
    job = SemanticJobRecord(
        _JOB,
        _WRITER,
        _OP,
        _CASE,
        _case_ref(),
        "failed",
        2,
        None,
        None,
        None,
        None,
        None,
        None,
        SemanticReason.RETRY_BUDGET_EXHAUSTED,
        datetime(2026, 1, 1, tzinfo=UTC),
    )
    attempts = (
        SemanticAttemptRecord(
            _JOB,
            _ATT1,
            1,
            "req_40000000-0000-4000-8000-0000000000aa",
            "expired",
            SemanticReason.PROVIDER_TIMEOUT,
            None,
        ),
        SemanticAttemptRecord(
            _JOB,
            _ATT2,
            2,
            "req_40000000-0000-4000-8000-0000000000bb",
            "failed",
            SemanticReason.RETRY_BUDGET_EXHAUSTED,
            None,
        ),
    )
    accounting = attempt_accounting_from_rows(job, attempts, max_retries=1)
    assert accounting.attempted_count == 2
    assert accounting.selected_attempt_id is None
    assert accounting.exhausted is True
    encoded = attempt_accounting_to_json(accounting)
    # No user-controlled content: only structural tokens and counts.
    assert encoded["attempted_count"] == 2
    assert encoded["exhausted"] is True
    raw = str(encoded)
    assert "timeout" in raw or "provider_timeout" in raw
    assert "secret" not in raw
    assert "prompt" not in raw


@dataclass(frozen=True, slots=True)
class _Eval:
    status: SemanticStatus
    reason: SemanticReason
    judgment: object | None = None
    provenance: object | None = None
    semantic_withheld_item_ids: tuple[str, ...] = ()


@dataclass
class _FakeLedger:
    job: SemanticJobRecord
    lease: OperationLease
    outcomes: list[tuple[str, AttemptOutcome, SemanticReason | None]] | None = None
    dispatches: list[str] | None = None
    mono: float = 0.0
    attempt_ids: list[str] | None = None
    provider_ids: list[str] | None = None
    selected: str | None = None
    attempts: dict[str, SemanticAttemptRecord] | None = None
    renew_count: int = 0
    claim_calls: int = 0
    disclosure_waits: list[tuple[str, str, datetime]] | None = None
    resolved_disclosure_waits: set[str] | None = None

    def __post_init__(self) -> None:
        self.disclosure_waits = []
        self.resolved_disclosure_waits = set()
        self.outcomes = []
        self.dispatches = []
        self.attempt_ids = []
        self.provider_ids = []
        self.attempts = {}
        self.renew_count = 0
        self.claim_calls = 0

    async def renew_leases(self, lease: OperationLease) -> OperationLease:
        assert lease.writer_id == self.lease.writer_id
        assert lease.operation_id == self.lease.operation_id
        self.renew_count += 1
        self.lease = replace(
            self.lease,
            lease_generation=self.lease.lease_generation + 1,
            lease_expires_at=datetime(2030, 1, 1, tzinfo=UTC),
        )
        return self.lease

    async def claim_semantic_job(self, lease: OperationLease, job_id: str) -> SemanticAttemptHandle:
        # After terminal recovery, claim must not be invoked.
        if self.job.state in {"succeeded", "failed", "quarantined"}:
            raise AssertionError("claim_semantic_job_on_terminal_job")
        assert lease == self.lease
        assert job_id == self.job.job_id
        self.claim_calls += 1
        assert self.attempts is not None
        assert self.disclosure_waits is not None
        assert self.resolved_disclosure_waits is not None
        if (
            self.job.state == "leased"
            and self.job.active_attempt_id is not None
            and self.disclosure_waits
            and self.job.job_id not in self.resolved_disclosure_waits
        ):
            current = self.attempts[self.job.active_attempt_id]
            return SemanticAttemptHandle(
                job_id,
                current.attempt_id,
                current.attempt_ordinal,
                current.provider_request_id,
                lease.writer_id,
                lease.operation_id,
                lease.owner_generation,
                lease.lease_owner_id,
                current.attempt_ordinal,
                lease.lease_expires_at,
                lease.frontier,
                lease.dependency_digest,
            )
        ordinal = self.job.attempt_count + 1
        att = f"att_40000000-0000-4000-8000-{ordinal:012x}"
        req = f"req_40000000-0000-4000-8000-{ordinal:012x}"
        handle = SemanticAttemptHandle(
            job_id,
            att,
            ordinal,
            req,
            lease.writer_id,
            lease.operation_id,
            lease.owner_generation,
            lease.lease_owner_id,
            ordinal,
            lease.lease_expires_at,
            lease.frontier,
            lease.dependency_digest,
        )
        self.job = replace(
            self.job,
            state="leased",
            attempt_count=ordinal,
            active_attempt_id=att,
            lease_owner_id=lease.lease_owner_id,
            lease_generation=ordinal,
            lease_expires_at=lease.lease_expires_at,
        )
        assert self.attempt_ids is not None
        assert self.provider_ids is not None
        self.attempt_ids.append(att)
        self.provider_ids.append(req)
        self.attempts[att] = SemanticAttemptRecord(job_id, att, ordinal, req, "started", None, None)
        return handle

    async def record_attempt_outcome(
        self,
        handle: SemanticAttemptHandle,
        outcome: AttemptOutcome,
        result_object_ref: ObjectRef | None = None,
        terminal_code: SemanticReason | None = None,
        token_usage: RuntimeTokenUsage | None = None,
    ) -> None:
        assert self.attempts is not None
        assert self.outcomes is not None
        self.outcomes.append((handle.attempt_id, outcome, terminal_code))
        state: Literal["started", "response_durable", "selected", "failed", "expired", "late"]
        if outcome is AttemptOutcome.RESPONSE_DURABLE:
            state = "response_durable"
        elif outcome is AttemptOutcome.EXPIRED:
            state = "expired"
        elif outcome is AttemptOutcome.FAILED:
            state = "failed"
        elif outcome is AttemptOutcome.LATE:
            state = "late"
        else:
            state = "selected"
        self.attempts[handle.attempt_id] = SemanticAttemptRecord(
            handle.job_id,
            handle.attempt_id,
            handle.attempt_ordinal,
            handle.provider_request_id,
            state,
            terminal_code,
            result_object_ref,
            None,
            token_usage,
        )
        if outcome is AttemptOutcome.EXPIRED:
            self.job = replace(
                self.job,
                state="queued",
                active_attempt_id=None,
                lease_owner_id=None,
                lease_generation=None,
                lease_expires_at=None,
            )
        elif outcome is AttemptOutcome.FAILED:
            self.job = replace(
                self.job,
                state="failed",
                active_attempt_id=None,
                lease_owner_id=None,
                lease_generation=None,
                lease_expires_at=None,
                terminal_code=terminal_code,
                terminal_at=datetime(2026, 1, 1, tzinfo=UTC),
            )

    async def fail_semantic_job(
        self,
        lease: OperationLease,
        job_id: str,
        terminal_code: SemanticReason,
    ) -> SemanticJobRecord:
        assert lease == self.lease
        assert job_id == self.job.job_id
        assert self.job.state == "queued"
        self.job = replace(
            self.job,
            state="failed",
            terminal_code=terminal_code,
            terminal_at=datetime(2026, 1, 1, tzinfo=UTC),
        )
        return self.job

    async def select_attempt(
        self,
        lease: OperationLease,
        handle: SemanticAttemptHandle,
        selected_result_object_ref: ObjectRef,
    ) -> object:
        self.selected = handle.attempt_id
        self.job = replace(
            self.job,
            state="succeeded",
            active_attempt_id=None,
            selected_attempt_id=handle.attempt_id,
            selected_result_object_ref=selected_result_object_ref,
            terminal_code=SemanticReason.SEMANTIC_COMPLETED,
            terminal_at=datetime(2026, 1, 1, tzinfo=UTC),
            lease_owner_id=None,
            lease_generation=None,
            lease_expires_at=None,
        )
        return object()

    async def load_semantic_job(
        self, writer_id: str, operation_id: str, case_digest: str | None = None
    ) -> SemanticJobRecord | None:
        assert (writer_id, operation_id) == (_WRITER, _OP)
        assert case_digest is None or self.job is None or case_digest == self.job.case_digest
        return self.job

    async def list_semantic_attempts(self, job_id: str) -> tuple[SemanticAttemptRecord, ...]:
        assert job_id == _JOB
        assert self.attempts is not None
        return tuple(sorted(self.attempts.values(), key=lambda item: item.attempt_ordinal))

    async def record_disclosure_wait(
        self,
        handle: SemanticAttemptHandle,
        pending_id: str,
        pending_expires_at: datetime,
    ) -> object:
        assert self.disclosure_waits is not None
        assert self.resolved_disclosure_waits is not None
        self.disclosure_waits.append((handle.attempt_id, pending_id, pending_expires_at))
        self.resolved_disclosure_waits.discard(handle.job_id)
        return None

    async def load_disclosure_wait(
        self, writer_id: str, operation_id: str
    ) -> SemanticDisclosureWait | None:
        assert (writer_id, operation_id) == (_WRITER, _OP)
        assert self.disclosure_waits is not None
        assert self.resolved_disclosure_waits is not None
        if not self.disclosure_waits:
            return None
        attempt_id, pending_id, pending_expires_at = self.disclosure_waits[-1]
        resolved = _JOB in self.resolved_disclosure_waits
        return SemanticDisclosureWait(
            _JOB,
            attempt_id,
            writer_id,
            operation_id,
            pending_id,
            pending_expires_at,
            "resolved" if resolved else "awaiting",
            datetime(2026, 1, 1, tzinfo=UTC) if resolved else None,
        )

    async def resolve_disclosure_wait(self, job_id: str) -> SemanticDisclosureWait:
        assert job_id == _JOB
        assert self.resolved_disclosure_waits is not None
        self.resolved_disclosure_waits.add(job_id)
        resolved = await self.load_disclosure_wait(_WRITER, _OP)
        assert resolved is not None
        return resolved


@pytest.mark.anyio
async def test_zero_retry_performs_exactly_one_attempt() -> None:
    lease = _lease()
    job = SemanticJobRecord(
        _JOB,
        _WRITER,
        _OP,
        _CASE,
        _case_ref(),
        "queued",
        0,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    ledger = _FakeLedger(job, lease)
    script = [
        _Eval(SemanticStatus.TIMEOUT, SemanticReason.PROVIDER_TIMEOUT),
    ]

    async def dispatch(handle: SemanticAttemptHandle, deadline: Deadline) -> _Eval:
        assert ledger.dispatches is not None
        ledger.dispatches.append(handle.attempt_id)
        assert not deadline.expired(0.0)
        return script.pop(0)

    async def publish(handle: SemanticAttemptHandle, evaluation: object) -> ObjectRef:
        raise AssertionError("publish_not_expected")

    finals: list[tuple[SemanticStatus, SemanticReason, int]] = []

    def build_final(
        status: SemanticStatus,
        reason: SemanticReason,
        evaluation: object | None,
        accounting: SemanticAttemptAccounting,
    ) -> object:
        finals.append((status, reason, accounting.attempted_count))
        return (status, reason, accounting)

    result = cast(
        tuple[SemanticStatus, SemanticReason, SemanticAttemptAccounting],
        await run_durable_semantic_attempts(
            ledger=ledger,
            lease=lease,
            job=job,
            deadline=Deadline(datetime(2030, 1, 1, tzinfo=UTC), 1000.0),
            max_retries=0,
            now_monotonic=lambda: 0.0,
            dispatch=dispatch,
            publish_success_response=publish,
            sleep=lambda _: _async_noop(),
            build_final=build_final,
        ),
    )
    assert ledger.dispatches is not None and len(ledger.dispatches) == 1
    assert ledger.outcomes is not None and ledger.outcomes[0][1] is AttemptOutcome.FAILED
    assert finals[0] == (SemanticStatus.TIMEOUT, SemanticReason.PROVIDER_TIMEOUT, 1)
    assert result[0] is SemanticStatus.TIMEOUT


async def _async_noop() -> None:
    return None


@pytest.mark.anyio
async def test_total_deadline_before_first_attempt_terminally_fails_job() -> None:
    lease = _lease()
    job = SemanticJobRecord(
        _JOB,
        _WRITER,
        _OP,
        _CASE,
        _case_ref(),
        "queued",
        0,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    ledger = _FakeLedger(job, lease)

    async def dispatch(handle: SemanticAttemptHandle, deadline: Deadline) -> _Eval:
        raise AssertionError("dispatch_not_expected_after_total_deadline")

    async def publish(handle: SemanticAttemptHandle, evaluation: object) -> ObjectRef:
        raise AssertionError("publish_not_expected")

    def build_final(
        status: SemanticStatus,
        reason: SemanticReason,
        evaluation: object | None,
        accounting: SemanticAttemptAccounting,
    ) -> object:
        return (status, reason, accounting)

    result = cast(
        tuple[SemanticStatus, SemanticReason, SemanticAttemptAccounting],
        await run_durable_semantic_attempts(
            ledger=ledger,
            lease=lease,
            job=job,
            deadline=Deadline(datetime(2026, 1, 1, tzinfo=UTC), 0.0),
            max_retries=2,
            now_monotonic=lambda: 1.0,
            dispatch=dispatch,
            publish_success_response=publish,
            build_final=build_final,
        ),
    )
    assert result[0] is SemanticStatus.TIMEOUT
    assert result[1] is SemanticReason.PROVIDER_TIMEOUT
    assert result[2].attempted_count == 0
    assert ledger.job.state == "failed"
    assert ledger.job.terminal_code is SemanticReason.PROVIDER_TIMEOUT


@pytest.mark.anyio
async def test_total_deadline_after_retriable_attempt_terminally_fails_queued_job() -> None:
    lease = _lease()
    job = SemanticJobRecord(
        _JOB,
        _WRITER,
        _OP,
        _CASE,
        _case_ref(),
        "queued",
        0,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    ledger = _FakeLedger(job, lease)
    monotonic_values = iter((0.0, 0.0, 0.0, 0.0, 1.0, 1.0))

    async def dispatch(handle: SemanticAttemptHandle, deadline: Deadline) -> _Eval:
        assert ledger.dispatches is not None
        ledger.dispatches.append(handle.attempt_id)
        return _Eval(SemanticStatus.TIMEOUT, SemanticReason.PROVIDER_TIMEOUT)

    async def publish(handle: SemanticAttemptHandle, evaluation: object) -> ObjectRef:
        raise AssertionError("publish_not_expected")

    def build_final(
        status: SemanticStatus,
        reason: SemanticReason,
        evaluation: object | None,
        accounting: SemanticAttemptAccounting,
    ) -> object:
        return (status, reason, accounting)

    result = cast(
        tuple[SemanticStatus, SemanticReason, SemanticAttemptAccounting],
        await run_durable_semantic_attempts(
            ledger=ledger,
            lease=lease,
            job=job,
            deadline=Deadline(datetime(2026, 1, 1, tzinfo=UTC), 0.5),
            max_retries=2,
            now_monotonic=lambda: next(monotonic_values),
            dispatch=dispatch,
            publish_success_response=publish,
            build_final=build_final,
        ),
    )
    assert result[0] is SemanticStatus.TIMEOUT
    assert result[1] is SemanticReason.PROVIDER_TIMEOUT
    assert result[2].attempted_count == 1
    assert ledger.outcomes == [(_ATT1, AttemptOutcome.EXPIRED, SemanticReason.PROVIDER_TIMEOUT)]
    assert ledger.job.state == "failed"
    assert ledger.job.terminal_code is SemanticReason.PROVIDER_TIMEOUT


@pytest.mark.anyio
async def test_two_retries_perform_at_most_three_physical_attempts() -> None:
    lease = _lease()
    job = SemanticJobRecord(
        _JOB,
        _WRITER,
        _OP,
        _CASE,
        _case_ref(),
        "queued",
        0,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    ledger = _FakeLedger(job, lease)
    script = [
        _Eval(SemanticStatus.TIMEOUT, SemanticReason.PROVIDER_TIMEOUT),
        _Eval(SemanticStatus.UNAVAILABLE, SemanticReason.PROVIDER_RATE_LIMITED),
        _Eval(SemanticStatus.UNAVAILABLE, SemanticReason.TRANSPORT_UNAVAILABLE),
        _Eval(SemanticStatus.TIMEOUT, SemanticReason.PROVIDER_TIMEOUT),  # must not run
    ]

    async def dispatch(handle: SemanticAttemptHandle, deadline: Deadline) -> _Eval:
        assert ledger.dispatches is not None
        ledger.dispatches.append(handle.provider_request_id)
        return script.pop(0)

    async def publish(handle: SemanticAttemptHandle, evaluation: object) -> ObjectRef:
        raise AssertionError("publish_not_expected")

    def build_final(
        status: SemanticStatus,
        reason: SemanticReason,
        evaluation: object | None,
        accounting: SemanticAttemptAccounting,
    ) -> object:
        return (status, reason, accounting)

    result = cast(
        tuple[SemanticStatus, SemanticReason, SemanticAttemptAccounting],
        await run_durable_semantic_attempts(
            ledger=ledger,
            lease=lease,
            job=job,
            deadline=Deadline(datetime(2030, 1, 1, tzinfo=UTC), 1000.0),
            max_retries=2,
            now_monotonic=lambda: 0.0,
            dispatch=dispatch,
            publish_success_response=publish,
            sleep=lambda _: _async_noop(),
            build_final=build_final,
        ),
    )
    assert ledger.dispatches is not None and len(ledger.dispatches) == 3
    assert len(set(ledger.dispatches)) == 3  # unique provider request ids
    assert ledger.attempt_ids is not None and len(set(ledger.attempt_ids)) == 3
    assert result[0] is SemanticStatus.UNAVAILABLE
    assert result[1] is SemanticReason.RETRY_BUDGET_EXHAUSTED
    assert result[2].attempted_count == 3
    assert result[2].exhausted is True
    # Intermediate retriable outcomes used EXPIRED; final FAILED.
    assert ledger.outcomes is not None
    assert [item[1] for item in ledger.outcomes] == [
        AttemptOutcome.EXPIRED,
        AttemptOutcome.EXPIRED,
        AttemptOutcome.FAILED,
    ]


@pytest.mark.anyio
async def test_success_selects_first_valid_and_stops() -> None:
    lease = _lease()
    job = SemanticJobRecord(
        _JOB,
        _WRITER,
        _OP,
        _CASE,
        _case_ref(),
        "queued",
        0,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    ledger = _FakeLedger(job, lease)
    script = [
        _Eval(SemanticStatus.TIMEOUT, SemanticReason.PROVIDER_TIMEOUT),
        _Eval(SemanticStatus.SUCCEEDED, SemanticReason.SEMANTIC_COMPLETED),
        _Eval(SemanticStatus.SUCCEEDED, SemanticReason.SEMANTIC_COMPLETED),
    ]

    async def dispatch(handle: SemanticAttemptHandle, deadline: Deadline) -> _Eval:
        assert ledger.dispatches is not None
        ledger.dispatches.append(handle.attempt_id)
        return script.pop(0)

    async def publish(handle: SemanticAttemptHandle, evaluation: object) -> ObjectRef:
        return _response_ref()

    def build_final(
        status: SemanticStatus,
        reason: SemanticReason,
        evaluation: object | None,
        accounting: SemanticAttemptAccounting,
    ) -> object:
        return (status, reason, accounting)

    result = cast(
        tuple[SemanticStatus, SemanticReason, SemanticAttemptAccounting],
        await run_durable_semantic_attempts(
            ledger=ledger,
            lease=lease,
            job=job,
            deadline=Deadline(datetime(2030, 1, 1, tzinfo=UTC), 1000.0),
            max_retries=2,
            now_monotonic=lambda: 0.0,
            dispatch=dispatch,
            publish_success_response=publish,
            sleep=lambda _: _async_noop(),
            build_final=build_final,
        ),
    )
    assert ledger.dispatches is not None
    assert len(ledger.dispatches) == 2
    assert ledger.selected is not None
    assert result[0] is SemanticStatus.SUCCEEDED
    assert result[2].selected_attempt_id == ledger.selected
    assert result[2].attempted_count == 2


@pytest.mark.anyio
async def test_policy_block_never_retries() -> None:
    lease = _lease()
    job = SemanticJobRecord(
        _JOB,
        _WRITER,
        _OP,
        _CASE,
        _case_ref(),
        "queued",
        0,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    ledger = _FakeLedger(job, lease)

    async def dispatch(handle: SemanticAttemptHandle, deadline: Deadline) -> _Eval:
        assert ledger.dispatches is not None
        ledger.dispatches.append(handle.attempt_id)
        return _Eval(SemanticStatus.BLOCKED_BY_POLICY, SemanticReason.NETWORK_EGRESS_DENIED)

    async def publish(handle: SemanticAttemptHandle, evaluation: object) -> ObjectRef:
        raise AssertionError("publish_not_expected")

    def build_final(
        status: SemanticStatus,
        reason: SemanticReason,
        evaluation: object | None,
        accounting: SemanticAttemptAccounting,
    ) -> object:
        return (status, reason, accounting)

    result = cast(
        tuple[SemanticStatus, SemanticReason, SemanticAttemptAccounting],
        await run_durable_semantic_attempts(
            ledger=ledger,
            lease=lease,
            job=job,
            deadline=Deadline(datetime(2030, 1, 1, tzinfo=UTC), 1000.0),
            max_retries=2,
            now_monotonic=lambda: 0.0,
            dispatch=dispatch,
            publish_success_response=publish,
            sleep=lambda _: _async_noop(),
            build_final=build_final,
        ),
    )
    assert ledger.dispatches is not None and len(ledger.dispatches) == 1
    assert result[0] is SemanticStatus.BLOCKED_BY_POLICY
    assert ledger.outcomes is not None and ledger.outcomes[0][1] is AttemptOutcome.FAILED


@pytest.mark.anyio
async def test_terminal_failed_job_recovers_without_claim() -> None:
    """Crash after final FAILED, before check commit: replay must not re-claim."""

    lease = _lease()
    job = SemanticJobRecord(
        _JOB,
        _WRITER,
        _OP,
        _CASE,
        _case_ref(),
        "failed",
        1,
        None,
        None,
        None,
        None,
        None,
        None,
        SemanticReason.PROVIDER_TIMEOUT,
        datetime(2026, 1, 1, tzinfo=UTC),
    )
    ledger = _FakeLedger(job, lease)
    ledger.attempts = {
        _ATT1: SemanticAttemptRecord(
            _JOB,
            _ATT1,
            1,
            "req_40000000-0000-4000-8000-0000000000aa",
            "failed",
            SemanticReason.PROVIDER_TIMEOUT,
            None,
        )
    }

    async def dispatch(handle: SemanticAttemptHandle, deadline: Deadline) -> _Eval:
        raise AssertionError("dispatch_not_expected_on_terminal_recovery")

    async def publish(handle: SemanticAttemptHandle, evaluation: object) -> ObjectRef:
        raise AssertionError("publish_not_expected")

    def build_final(
        status: SemanticStatus,
        reason: SemanticReason,
        evaluation: object | None,
        accounting: SemanticAttemptAccounting,
    ) -> object:
        return (status, reason, accounting)

    result = cast(
        tuple[SemanticStatus, SemanticReason, SemanticAttemptAccounting],
        await run_durable_semantic_attempts(
            ledger=ledger,
            lease=lease,
            job=job,
            deadline=Deadline(datetime(2030, 1, 1, tzinfo=UTC), 1000.0),
            max_retries=2,
            now_monotonic=lambda: 0.0,
            dispatch=dispatch,
            publish_success_response=publish,
            sleep=lambda _: _async_noop(),
            build_final=build_final,
        ),
    )
    assert ledger.claim_calls == 0
    assert result[0] is SemanticStatus.TIMEOUT
    assert result[1] is SemanticReason.PROVIDER_TIMEOUT
    assert result[2].attempted_count == 1
    assert ledger.renew_count >= 1


@pytest.mark.anyio
async def test_terminal_non_success_replays_withheld_item_ids_from_response_object() -> None:
    """A failed semantic job keeps omission identities available after terminal replay."""

    lease = _lease()
    job = SemanticJobRecord(
        _JOB,
        _WRITER,
        _OP,
        _CASE,
        _case_ref(),
        "queued",
        0,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    ledger = _FakeLedger(job, lease)
    evaluation = _Eval(
        SemanticStatus.BLOCKED_BY_POLICY,
        SemanticReason.NETWORK_EGRESS_DENIED,
        semantic_withheld_item_ids=("item_secret",),
    )
    published: list[tuple[str, tuple[str, ...]]] = []

    async def dispatch(handle: SemanticAttemptHandle, deadline: Deadline) -> _Eval:
        return evaluation

    async def publish(handle: SemanticAttemptHandle, value: object) -> ObjectRef:
        assert isinstance(value, _Eval)
        published.append((handle.attempt_id, value.semantic_withheld_item_ids))
        return _response_ref()

    def build_final(
        status: SemanticStatus,
        reason: SemanticReason,
        value: object | None,
        accounting: SemanticAttemptAccounting,
    ) -> object:
        return (status, reason, value, accounting)

    first = cast(
        tuple[SemanticStatus, SemanticReason, object | None, SemanticAttemptAccounting],
        await run_durable_semantic_attempts(
            ledger=ledger,
            lease=lease,
            job=job,
            deadline=Deadline(datetime(2030, 1, 1, tzinfo=UTC), 1000.0),
            max_retries=0,
            now_monotonic=lambda: 0.0,
            dispatch=dispatch,
            publish_success_response=publish,
            sleep=lambda _: _async_noop(),
            build_final=build_final,
        ),
    )
    assert first[0] is SemanticStatus.BLOCKED_BY_POLICY
    assert published == [(_ATT1, ("item_secret",))]
    assert ledger.attempts is not None
    assert ledger.attempts[_ATT1].result_object_ref == _response_ref()

    async def recover_response(ref: ObjectRef) -> _Eval | None:
        assert ref == _response_ref()
        return evaluation

    second = cast(
        tuple[SemanticStatus, SemanticReason, object | None, SemanticAttemptAccounting],
        await run_durable_semantic_attempts(
            ledger=ledger,
            lease=lease,
            job=ledger.job,
            deadline=Deadline(datetime(2030, 1, 1, tzinfo=UTC), 1000.0),
            max_retries=0,
            now_monotonic=lambda: 0.0,
            dispatch=dispatch,
            publish_success_response=publish,
            sleep=lambda _: _async_noop(),
            build_final=build_final,
            recover_response=recover_response,
        ),
    )
    assert second[0] is SemanticStatus.BLOCKED_BY_POLICY
    assert second[1] is SemanticReason.NETWORK_EGRESS_DENIED
    assert second[2] is evaluation
    assert isinstance(second[2], _Eval)
    assert second[2].semantic_withheld_item_ids == ("item_secret",)
    assert published == [(_ATT1, ("item_secret",))]
    assert ledger.claim_calls == 1


@pytest.mark.anyio
async def test_terminal_response_persistence_failure_is_unknown_without_replayable_evaluation() -> (
    None
):
    """A failed omission-object write cannot return ids that terminal replay cannot recover."""

    lease = _lease()
    job = _queued_job()
    ledger = _FakeLedger(job, lease)
    evaluation = _Eval(
        SemanticStatus.BLOCKED_BY_POLICY,
        SemanticReason.NETWORK_EGRESS_DENIED,
        semantic_withheld_item_ids=("item_secret",),
    )

    async def dispatch(handle: SemanticAttemptHandle, deadline: Deadline) -> _Eval:
        del handle, deadline
        return evaluation

    async def publish(handle: SemanticAttemptHandle, value: object) -> ObjectRef:
        del handle, value
        raise OSError("response_store_unavailable")

    def build_final(
        status: SemanticStatus,
        reason: SemanticReason,
        value: object | None,
        accounting: SemanticAttemptAccounting,
    ) -> object:
        return status, reason, value, accounting

    result = cast(
        tuple[SemanticStatus, SemanticReason, object | None, SemanticAttemptAccounting],
        await run_durable_semantic_attempts(
            ledger=ledger,
            lease=lease,
            job=job,
            deadline=Deadline(datetime(2030, 1, 1, tzinfo=UTC), 1000.0),
            max_retries=0,
            now_monotonic=lambda: 0.0,
            dispatch=dispatch,
            publish_success_response=publish,
            sleep=lambda _: _async_noop(),
            build_final=build_final,
        ),
    )

    assert result[:3] == (
        SemanticStatus.UNAVAILABLE,
        SemanticReason.RECEIPT_PERSISTENCE_UNKNOWN,
        None,
    )
    assert ledger.attempts is not None
    assert ledger.attempts[_ATT1].result_object_ref is None


@pytest.mark.anyio
async def test_retryable_withheld_evaluation_replays_after_deadline_terminalization() -> None:
    """An expired retry row keeps the same omission carrier for immediate and replayed results."""

    ledger = _FakeLedger(_queued_job(), _lease())
    evaluation = _Eval(
        SemanticStatus.TIMEOUT,
        SemanticReason.PROVIDER_TIMEOUT,
        semantic_withheld_item_ids=("item_secret",),
    )
    monotonic = [0.0]
    published: list[str] = []

    async def dispatch(handle: SemanticAttemptHandle, deadline: Deadline) -> _Eval:
        del deadline
        published.append(handle.attempt_id)
        monotonic[0] = 0.5
        return evaluation

    async def publish(handle: SemanticAttemptHandle, value: object) -> ObjectRef:
        assert isinstance(value, _Eval)
        assert value.semantic_withheld_item_ids == ("item_secret",)
        # The first attempt has already been classified as retryable when this callback runs.
        # Move the process clock past the frozen operation deadline before the loop can claim a
        # replacement, exercising deadline terminalization of the durable expired row.
        monotonic[0] = 1.1
        return _response_ref()

    async def sleep(_delay: float) -> None:
        raise AssertionError("deadline_should_close_before_backoff")

    def build_final(
        status: SemanticStatus,
        reason: SemanticReason,
        value: object | None,
        accounting: SemanticAttemptAccounting,
    ) -> object:
        return status, reason, value, accounting

    first = cast(
        tuple[SemanticStatus, SemanticReason, _Eval | None, SemanticAttemptAccounting],
        await run_durable_semantic_attempts(
            ledger=ledger,
            lease=ledger.lease,
            job=ledger.job,
            deadline=Deadline(datetime(2030, 1, 1, tzinfo=UTC), 1.0),
            max_retries=1,
            now_monotonic=lambda: monotonic[0],
            dispatch=dispatch,
            publish_success_response=publish,
            sleep=sleep,
            build_final=build_final,
        ),
    )
    assert first[2] is evaluation
    assert published == [_ATT1]
    assert ledger.attempts is not None
    assert ledger.attempts[_ATT1].result_object_ref == _response_ref()

    async def recover_response(ref: ObjectRef) -> _Eval | None:
        assert ref == _response_ref()
        return evaluation

    second = cast(
        tuple[SemanticStatus, SemanticReason, _Eval | None, SemanticAttemptAccounting],
        await run_durable_semantic_attempts(
            ledger=ledger,
            lease=ledger.lease,
            job=ledger.job,
            deadline=Deadline(datetime(2030, 1, 1, tzinfo=UTC), 1.0),
            max_retries=1,
            now_monotonic=lambda: 1.1,
            dispatch=dispatch,
            publish_success_response=publish,
            sleep=sleep,
            build_final=build_final,
            recover_response=recover_response,
        ),
    )
    assert second[0:2] == first[0:2]
    assert second[2] is evaluation
    assert first[2] is not None
    assert second[2] is not None
    assert second[2].semantic_withheld_item_ids == first[2].semantic_withheld_item_ids
    assert published == [_ATT1]


@pytest.mark.anyio
async def test_terminal_succeeded_job_recovers_via_selected_callback() -> None:
    """Crash after select_attempt: recover judgment/provenance without re-claim."""

    lease = _lease()
    job = SemanticJobRecord(
        _JOB,
        _WRITER,
        _OP,
        _CASE,
        _case_ref(),
        "succeeded",
        1,
        None,
        _ATT1,
        None,
        None,
        None,
        _response_ref(),
        SemanticReason.SEMANTIC_COMPLETED,
        datetime(2026, 1, 1, tzinfo=UTC),
    )
    ledger = _FakeLedger(job, lease)
    ledger.attempts = {
        _ATT1: SemanticAttemptRecord(
            _JOB,
            _ATT1,
            1,
            "req_40000000-0000-4000-8000-0000000000aa",
            "selected",
            SemanticReason.SEMANTIC_COMPLETED,
            _response_ref(),
        )
    }
    recovered = _Eval(SemanticStatus.SUCCEEDED, SemanticReason.SEMANTIC_COMPLETED, judgment="j")

    async def recover_selected(row: SemanticJobRecord) -> _Eval | None:
        assert row.state == "succeeded"
        return recovered

    async def dispatch(handle: SemanticAttemptHandle, deadline: Deadline) -> _Eval:
        raise AssertionError("dispatch_not_expected_on_terminal_recovery")

    async def publish(handle: SemanticAttemptHandle, evaluation: object) -> ObjectRef:
        raise AssertionError("publish_not_expected")

    def build_final(
        status: SemanticStatus,
        reason: SemanticReason,
        evaluation: object | None,
        accounting: SemanticAttemptAccounting,
    ) -> object:
        return (status, reason, evaluation, accounting)

    result = cast(
        tuple[SemanticStatus, SemanticReason, object | None, SemanticAttemptAccounting],
        await run_durable_semantic_attempts(
            ledger=ledger,
            lease=lease,
            job=job,
            deadline=Deadline(datetime(2030, 1, 1, tzinfo=UTC), 1000.0),
            max_retries=2,
            now_monotonic=lambda: 0.0,
            dispatch=dispatch,
            publish_success_response=publish,
            sleep=lambda _: _async_noop(),
            build_final=build_final,
            recover_selected=recover_selected,
        ),
    )
    assert ledger.claim_calls == 0
    assert result[0] is SemanticStatus.SUCCEEDED
    assert result[2] is recovered
    assert result[3].selected_attempt_id == _ATT1


@pytest.mark.anyio
async def test_attempt_loop_renews_operation_lease() -> None:
    """The attempt loop renews before claim and after dispatch/select mutations."""

    lease = _lease()
    job = SemanticJobRecord(
        _JOB,
        _WRITER,
        _OP,
        _CASE,
        _case_ref(),
        "queued",
        0,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    ledger = _FakeLedger(job, lease)
    renewed: list[OperationLease] = []

    async def dispatch(handle: SemanticAttemptHandle, deadline: Deadline) -> _Eval:
        return _Eval(SemanticStatus.SUCCEEDED, SemanticReason.SEMANTIC_COMPLETED)

    async def publish(handle: SemanticAttemptHandle, evaluation: object) -> ObjectRef:
        return _response_ref()

    def build_final(
        status: SemanticStatus,
        reason: SemanticReason,
        evaluation: object | None,
        accounting: SemanticAttemptAccounting,
    ) -> object:
        return (status, reason, accounting)

    def on_lease(renewed_lease: OperationLease) -> None:
        renewed.append(renewed_lease)

    await run_durable_semantic_attempts(
        ledger=ledger,
        lease=lease,
        job=job,
        deadline=Deadline(datetime(2030, 1, 1, tzinfo=UTC), 1000.0),
        max_retries=0,
        now_monotonic=lambda: 0.0,
        dispatch=dispatch,
        publish_success_response=publish,
        sleep=lambda _: _async_noop(),
        build_final=build_final,
        on_lease_renewed=on_lease,
    )
    # At least: initial renew + pre-claim renew + post-dispatch renew.
    assert ledger.renew_count >= 3
    assert len(renewed) >= 3
    assert renewed[-1].lease_generation > lease.lease_generation


@pytest.mark.anyio
async def test_raising_dispatch_terminalizes_attempt_and_job() -> None:
    """A dispatch that raises must not strand the durable state (dogfood run 2026-07-30).

    The production failure raised ``semantic_case_envelope_too_large`` while building the packet,
    after the attempt had already been claimed. Every terminalizing call sat on a normal-return
    path, so the exception unwound past all of them: the attempt stayed ``started``, the job
    stayed ``leased``, and because claim resumes the same attempt on replay, the check could
    never recover.
    """

    lease = _lease()
    job = SemanticJobRecord(
        _JOB,
        _WRITER,
        _OP,
        _CASE,
        _case_ref(),
        "queued",
        0,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    ledger = _FakeLedger(job, lease)

    async def dispatch(handle: SemanticAttemptHandle, deadline: Deadline) -> _Eval:
        raise ValueError("semantic_case_envelope_too_large")

    async def publish(handle: SemanticAttemptHandle, evaluation: object) -> ObjectRef:
        raise AssertionError("publish_must_not_run")

    def build_final(
        status: SemanticStatus,
        reason: SemanticReason,
        evaluation: object | None,
        accounting: SemanticAttemptAccounting,
    ) -> object:
        return (status, reason, accounting)

    result = await run_durable_semantic_attempts(
        ledger=ledger,
        lease=lease,
        job=job,
        deadline=Deadline(datetime(2030, 1, 1, tzinfo=UTC), 1000.0),
        max_retries=2,
        now_monotonic=lambda: 0.0,
        dispatch=dispatch,
        publish_success_response=publish,
        sleep=lambda _: _async_noop(),
        build_final=build_final,
    )

    status, reason, accounting = cast(
        tuple[SemanticStatus, SemanticReason, SemanticAttemptAccounting], result
    )
    assert status is SemanticStatus.FAILED
    assert reason is SemanticReason.COORDINATOR_FAILURE
    # The durable rows are terminal, not stranded.
    assert ledger.job.state == "failed"
    assert ledger.job.terminal_code is SemanticReason.COORDINATOR_FAILURE
    assert ledger.attempts is not None
    assert [row.state for row in ledger.attempts.values()] == ["failed"]
    # Accounting survives the failure, so the check can report what was attempted.
    assert accounting.attempted_count == 1
    # A deterministic build failure must not burn the whole retry budget re-raising.
    assert ledger.claim_calls == 1


@pytest.mark.anyio
async def test_raising_claim_terminalizes_job_without_an_attempt() -> None:
    """A raise before any attempt exists fails the job, never leaving it queued forever.

    ``record_attempt_outcome`` is not usable here — there is no claimed attempt — so this is the
    one case that belongs to ``fail_semantic_job``.
    """

    lease = _lease()
    job = SemanticJobRecord(
        _JOB,
        _WRITER,
        _OP,
        _CASE,
        _case_ref(),
        "queued",
        0,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )

    class _ClaimRaises(_FakeLedger):
        async def claim_semantic_job(
            self, lease: OperationLease, job_id: str
        ) -> SemanticAttemptHandle:
            raise RuntimeError("claim_exploded")

    ledger = _ClaimRaises(job, lease)

    async def dispatch(handle: SemanticAttemptHandle, deadline: Deadline) -> _Eval:
        raise AssertionError("dispatch_must_not_run")

    async def publish(handle: SemanticAttemptHandle, evaluation: object) -> ObjectRef:
        raise AssertionError("publish_must_not_run")

    def build_final(
        status: SemanticStatus,
        reason: SemanticReason,
        evaluation: object | None,
        accounting: SemanticAttemptAccounting,
    ) -> object:
        return (status, reason, accounting)

    result = await run_durable_semantic_attempts(
        ledger=ledger,
        lease=lease,
        job=job,
        deadline=Deadline(datetime(2030, 1, 1, tzinfo=UTC), 1000.0),
        max_retries=0,
        now_monotonic=lambda: 0.0,
        dispatch=dispatch,
        publish_success_response=publish,
        sleep=lambda _: _async_noop(),
        build_final=build_final,
    )

    status, reason, _ = cast(
        tuple[SemanticStatus, SemanticReason, SemanticAttemptAccounting], result
    )
    assert status is SemanticStatus.FAILED
    assert reason is SemanticReason.COORDINATOR_FAILURE
    assert ledger.job.state == "failed"
    assert ledger.attempts == {}


@pytest.mark.anyio
async def test_cancellation_terminalizes_before_propagating() -> None:
    """Cancellation must still release the durable state, then keep propagating."""

    lease = _lease()
    job = SemanticJobRecord(
        _JOB,
        _WRITER,
        _OP,
        _CASE,
        _case_ref(),
        "queued",
        0,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    ledger = _FakeLedger(job, lease)

    async def dispatch(handle: SemanticAttemptHandle, deadline: Deadline) -> _Eval:
        raise asyncio.CancelledError

    async def publish(handle: SemanticAttemptHandle, evaluation: object) -> ObjectRef:
        raise AssertionError("publish_must_not_run")

    def build_final(
        status: SemanticStatus,
        reason: SemanticReason,
        evaluation: object | None,
        accounting: SemanticAttemptAccounting,
    ) -> object:
        raise AssertionError("build_final_must_not_run_on_cancel")

    with pytest.raises(asyncio.CancelledError):
        await run_durable_semantic_attempts(
            ledger=ledger,
            lease=lease,
            job=job,
            deadline=Deadline(datetime(2030, 1, 1, tzinfo=UTC), 1000.0),
            max_retries=0,
            now_monotonic=lambda: 0.0,
            dispatch=dispatch,
            publish_success_response=publish,
            sleep=lambda _: _async_noop(),
            build_final=build_final,
        )

    assert ledger.job.state == "failed"
    assert ledger.attempts is not None
    assert [row.state for row in ledger.attempts.values()] == ["failed"]


@pytest.mark.anyio
async def test_repeated_cancellation_cannot_interrupt_terminal_writes() -> None:
    """A second task cancellation during a suspending ledger write waits for durability."""

    cleanup_started = asyncio.Event()
    allow_cleanup = asyncio.Event()

    class _SuspendingLedger(_FakeLedger):
        async def record_attempt_outcome(
            self,
            handle: SemanticAttemptHandle,
            outcome: AttemptOutcome,
            result_object_ref: ObjectRef | None = None,
            terminal_code: SemanticReason | None = None,
            token_usage: RuntimeTokenUsage | None = None,
        ) -> None:
            cleanup_started.set()
            await allow_cleanup.wait()
            await super().record_attempt_outcome(
                handle, outcome, result_object_ref, terminal_code, token_usage
            )

    lease = _lease()
    job = SemanticJobRecord(
        _JOB,
        _WRITER,
        _OP,
        _CASE,
        _case_ref(),
        "queued",
        0,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    ledger = _SuspendingLedger(job, lease)
    dispatch_started = asyncio.Event()

    async def dispatch(handle: SemanticAttemptHandle, deadline: Deadline) -> _Eval:
        dispatch_started.set()
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    async def publish(handle: SemanticAttemptHandle, evaluation: object) -> ObjectRef:
        raise AssertionError("publish_must_not_run")

    def build_final(
        status: SemanticStatus,
        reason: SemanticReason,
        evaluation: object | None,
        accounting: SemanticAttemptAccounting,
    ) -> object:
        raise AssertionError("build_final_must_not_run_on_cancel")

    task = asyncio.create_task(
        run_durable_semantic_attempts(
            ledger=ledger,
            lease=lease,
            job=job,
            deadline=Deadline(datetime(2030, 1, 1, tzinfo=UTC), 1000.0),
            max_retries=0,
            now_monotonic=lambda: 0.0,
            dispatch=dispatch,
            publish_success_response=publish,
            sleep=lambda _: _async_noop(),
            build_final=build_final,
        )
    )
    await dispatch_started.wait()
    task.cancel()
    await cleanup_started.wait()
    task.cancel()
    allow_cleanup.set()

    with pytest.raises(asyncio.CancelledError):
        await task
    assert ledger.job.state == "failed"
    assert ledger.attempts is not None
    assert [row.state for row in ledger.attempts.values()] == ["failed"]


@pytest.mark.anyio
async def test_retryable_claim_conflict_does_not_consume_an_attempt() -> None:
    """A live-owner claim conflict stays pending until the existing retry path can claim."""

    class _ConflictingLedger(_FakeLedger):
        conflict_count = 0

        async def claim_semantic_job(
            self, lease: OperationLease, job_id: str
        ) -> SemanticAttemptHandle:
            if self.conflict_count == 0:
                self.conflict_count += 1
                raise PublicOperationError(
                    PublicErrorCode.OPERATION_PENDING,
                    "operation pending",
                    True,
                )
            return await super().claim_semantic_job(lease, job_id)

    lease = _lease()
    job = SemanticJobRecord(
        _JOB,
        _WRITER,
        _OP,
        _CASE,
        _case_ref(),
        "queued",
        0,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    ledger = _ConflictingLedger(job, lease)

    async def dispatch(handle: SemanticAttemptHandle, deadline: Deadline) -> _Eval:
        return _Eval(SemanticStatus.SUCCEEDED, SemanticReason.SEMANTIC_COMPLETED)

    async def publish(handle: SemanticAttemptHandle, evaluation: object) -> ObjectRef:
        return _response_ref()

    result = await run_durable_semantic_attempts(
        ledger=ledger,
        lease=lease,
        job=job,
        deadline=Deadline(datetime(2030, 1, 1, tzinfo=UTC), 1000.0),
        max_retries=0,
        now_monotonic=lambda: 0.0,
        dispatch=dispatch,
        publish_success_response=publish,
        sleep=lambda _: _async_noop(),
        build_final=lambda status, reason, evaluation, accounting: (
            status,
            reason,
            accounting,
        ),
    )

    status, reason, accounting = cast(
        tuple[SemanticStatus, SemanticReason, SemanticAttemptAccounting], result
    )
    assert (status, reason) == (
        SemanticStatus.SUCCEEDED,
        SemanticReason.SEMANTIC_COMPLETED,
    )
    assert accounting.attempted_count == 1
    assert ledger.conflict_count == 1


# --- issue #348: one bounded repair retry after invalid / response_content_invalid ---------------


def _queued_job(attempt_count: int = 0) -> SemanticJobRecord:
    return SemanticJobRecord(
        _JOB,
        _WRITER,
        _OP,
        _CASE,
        _case_ref(),
        "queued",
        attempt_count,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )


def _build_tuple(
    status: SemanticStatus,
    reason: SemanticReason,
    evaluation: object | None,
    accounting: SemanticAttemptAccounting,
) -> object:
    return (status, reason, accounting)


async def _publish_response(handle: SemanticAttemptHandle, evaluation: object) -> ObjectRef:
    return _response_ref()


@dataclass(frozen=True, slots=True)
class _ExpiresAt:
    value: datetime

    def as_datetime(self) -> datetime:
        return self.value


@dataclass(frozen=True, slots=True)
class _Continuation:
    pending_id: str
    expires_at: _ExpiresAt


@dataclass(frozen=True, slots=True)
class _AwaitingEval:
    status: SemanticStatus
    reason: SemanticReason
    continuation: _Continuation
    judgment: object | None = None
    provenance: object | None = None


_Scripted = _Eval | _AwaitingEval


async def _run(
    ledger: _FakeLedger,
    script: list[_Scripted],
    *,
    max_retries: int,
    deadline: Deadline | None = None,
    now_monotonic: Callable[[], float] | None = None,
) -> tuple[SemanticStatus, SemanticReason, SemanticAttemptAccounting]:
    async def dispatch(handle: SemanticAttemptHandle, attempt_deadline: Deadline) -> _Scripted:
        assert ledger.dispatches is not None
        ledger.dispatches.append(handle.provider_request_id)
        assert script, "dispatch_past_budget"
        return script.pop(0)

    clock: Callable[[], float] = now_monotonic if now_monotonic is not None else (lambda: 0.0)
    return cast(
        tuple[SemanticStatus, SemanticReason, SemanticAttemptAccounting],
        await run_durable_semantic_attempts(
            ledger=ledger,
            lease=ledger.lease,
            job=ledger.job,
            deadline=deadline or Deadline(datetime(2030, 1, 1, tzinfo=UTC), 1000.0),
            max_retries=max_retries,
            now_monotonic=clock,
            dispatch=dispatch,
            publish_success_response=_publish_response,
            sleep=lambda _: _async_noop(),
            build_final=_build_tuple,
        ),
    )


_INVALID = _Eval(SemanticStatus.INVALID, SemanticReason.RESPONSE_CONTENT_INVALID)
_SUCCESS = _Eval(SemanticStatus.SUCCEEDED, SemanticReason.SEMANTIC_COMPLETED)


def test_repair_matrix_admits_only_response_content_invalid() -> None:
    assert is_repairable_semantic_outcome(
        SemanticStatus.INVALID, SemanticReason.RESPONSE_CONTENT_INVALID
    )
    # The repair class is not a transient class; it never enters the ADR-006 transient matrix.
    assert not is_retriable_semantic_outcome(
        SemanticStatus.INVALID, SemanticReason.RESPONSE_CONTENT_INVALID
    )
    for status, reason in (
        (SemanticStatus.INVALID, SemanticReason.RESPONSE_SCHEMA_INVALID),
        (SemanticStatus.INVALID, SemanticReason.SEMANTIC_JUDGMENT_REJECTED),
        (SemanticStatus.REFUSED, SemanticReason.PROVIDER_REFUSED),
        (SemanticStatus.HUMAN_DENIED, SemanticReason.HUMAN_DENIED),
        (SemanticStatus.BLOCKED_BY_POLICY, SemanticReason.NETWORK_EGRESS_DENIED),
        (SemanticStatus.BLOCKED_FORBIDDEN_DATA, SemanticReason.SECRET_DETECTED),
        (SemanticStatus.BLOCKED_FORBIDDEN_DATA, SemanticReason.NEVER_SEND_DETECTED),
        (SemanticStatus.STALE, SemanticReason.FRONTIER_CHANGED),
        (SemanticStatus.UNAVAILABLE, SemanticReason.PROVIDER_QUOTA_EXHAUSTED),
        (SemanticStatus.UNAVAILABLE, SemanticReason.CREDENTIAL_UNAVAILABLE),
        (SemanticStatus.TIMEOUT, SemanticReason.PROVIDER_TIMEOUT),
    ):
        assert not is_repairable_semantic_outcome(status, reason), reason


def test_should_retry_admits_exactly_one_repair_inside_budget_and_deadline() -> None:
    def repair(
        max_retries: int, *, deadline_expired: bool = False, repair_retries_used: int = 0
    ) -> bool:
        return should_retry_after(
            status=SemanticStatus.INVALID,
            reason=SemanticReason.RESPONSE_CONTENT_INVALID,
            attempts_completed=1,
            max_retries=max_retries,
            deadline_expired=deadline_expired,
            repair_retries_used=repair_retries_used,
        )

    assert repair(1)
    assert repair(2)
    # max_retries=0: no slot, unchanged single-attempt behavior.
    assert not repair(0)
    # The total deadline wins over the repair budget.
    assert not repair(2, deadline_expired=True)
    # One repair only, even when physical slots remain.
    assert not repair(2, repair_retries_used=1)
    # A transient class ignores the repair count.
    assert should_retry_after(
        status=SemanticStatus.TIMEOUT,
        reason=SemanticReason.PROVIDER_TIMEOUT,
        attempts_completed=2,
        max_retries=2,
        deadline_expired=False,
        repair_retries_used=1,
    )
    with pytest.raises(ValueError, match="repair_retries_used_invalid"):
        repair(1, repair_retries_used=-1)


def test_repair_retries_are_counted_from_durable_rows() -> None:
    rows = (
        SemanticAttemptRecord(
            _JOB, _ATT1, 1, "req_1", "expired", SemanticReason.PROVIDER_TIMEOUT, None
        ),
        SemanticAttemptRecord(
            _JOB, _ATT2, 2, "req_2", "expired", SemanticReason.RESPONSE_CONTENT_INVALID, None
        ),
        SemanticAttemptRecord(_JOB, _ATT3, 3, "req_3", "started", None, None),
    )
    assert repair_retries_from_rows(()) == 0
    assert repair_retries_from_rows(rows[:1]) == 0
    assert repair_retries_from_rows(rows) == 1


def test_final_status_keeps_the_honest_invalid_after_a_spent_repair() -> None:
    for attempts, retries in ((1, 0), (2, 1), (2, 2), (3, 2)):
        assert final_status_after_exhaustion(
            SemanticStatus.INVALID,
            SemanticReason.RESPONSE_CONTENT_INVALID,
            attempts_completed=attempts,
            max_retries=retries,
        ) == (SemanticStatus.INVALID, SemanticReason.RESPONSE_CONTENT_INVALID)
    # The transient exhaustion wording is untouched.
    assert final_status_after_exhaustion(
        SemanticStatus.TIMEOUT,
        SemanticReason.PROVIDER_TIMEOUT,
        attempts_completed=2,
        max_retries=1,
    ) == (SemanticStatus.UNAVAILABLE, SemanticReason.RETRY_BUDGET_EXHAUSTED)


@pytest.mark.anyio
async def test_zero_retry_invalid_is_terminal_after_exactly_one_attempt() -> None:
    ledger = _FakeLedger(_queued_job(), _lease())
    status, reason, accounting = await _run(ledger, [_INVALID, _SUCCESS], max_retries=0)
    assert ledger.dispatches is not None and len(ledger.dispatches) == 1
    assert (status, reason) == (SemanticStatus.INVALID, SemanticReason.RESPONSE_CONTENT_INVALID)
    assert accounting.attempted_count == 1
    assert accounting.selected_attempt_id is None
    assert ledger.outcomes == [
        (_ATT1, AttemptOutcome.FAILED, SemanticReason.RESPONSE_CONTENT_INVALID)
    ]
    assert ledger.job.state == "failed"


@pytest.mark.anyio
async def test_invalid_then_success_selects_the_repair_attempt() -> None:
    ledger = _FakeLedger(_queued_job(), _lease())
    status, reason, accounting = await _run(ledger, [_INVALID, _SUCCESS, _SUCCESS], max_retries=1)
    assert ledger.dispatches is not None and len(ledger.dispatches) == 2
    # Fresh physical identity for the repair: distinct attempt and provider request ids.
    assert len(set(ledger.dispatches)) == 2
    assert ledger.attempt_ids == [_ATT1, _ATT2]
    assert (status, reason) == (SemanticStatus.SUCCEEDED, SemanticReason.SEMANTIC_COMPLETED)
    assert ledger.selected == _ATT2
    assert accounting.selected_attempt_id == _ATT2
    assert accounting.attempted_count == 2
    assert accounting.exhausted is False
    # The repaired attempt stays visible in accounting next to the selected one.
    assert accounting.terminal_reason_counts == (("response_content_invalid", 1),)
    assert ledger.outcomes == [
        (_ATT1, AttemptOutcome.EXPIRED, SemanticReason.RESPONSE_CONTENT_INVALID),
        (_ATT2, AttemptOutcome.RESPONSE_DURABLE, None),
    ]
    assert ledger.job.state == "succeeded"


@pytest.mark.anyio
@pytest.mark.parametrize("max_retries", [1, 2])
async def test_invalid_then_invalid_stops_honestly_with_both_attempts(max_retries: int) -> None:
    ledger = _FakeLedger(_queued_job(), _lease())
    status, reason, accounting = await _run(
        ledger, [_INVALID, _INVALID, _SUCCESS], max_retries=max_retries
    )
    # A third dispatch never happens even when max_retries=2 leaves a physical slot.
    assert ledger.dispatches is not None and len(ledger.dispatches) == 2
    assert len(set(ledger.dispatches)) == 2
    assert (status, reason) == (SemanticStatus.INVALID, SemanticReason.RESPONSE_CONTENT_INVALID)
    assert accounting.attempted_count == 2
    assert accounting.selected_attempt_id is None
    assert accounting.terminal_reason_counts == (("response_content_invalid", 2),)
    # Physical exhaustion is reported only when the physical budget really was consumed.
    assert accounting.exhausted is (max_retries == 1)
    assert ledger.outcomes == [
        (_ATT1, AttemptOutcome.EXPIRED, SemanticReason.RESPONSE_CONTENT_INVALID),
        (_ATT2, AttemptOutcome.FAILED, SemanticReason.RESPONSE_CONTENT_INVALID),
    ]
    assert ledger.job.state == "failed"
    assert ledger.job.terminal_code is SemanticReason.RESPONSE_CONTENT_INVALID


@pytest.mark.anyio
async def test_expired_deadline_blocks_the_repair_without_losing_the_first_attempt() -> None:
    ledger = _FakeLedger(_queued_job(), _lease())
    clock = [0.0]
    deadline = Deadline(datetime(2030, 1, 1, tzinfo=UTC), 1000.0)

    async def dispatch(handle: SemanticAttemptHandle, attempt_deadline: Deadline) -> _Eval:
        assert ledger.dispatches is not None
        ledger.dispatches.append(handle.provider_request_id)
        clock[0] = 1000.0  # provider latency consumed the whole total deadline
        return _INVALID

    result = cast(
        tuple[SemanticStatus, SemanticReason, SemanticAttemptAccounting],
        await run_durable_semantic_attempts(
            ledger=ledger,
            lease=ledger.lease,
            job=ledger.job,
            deadline=deadline,
            max_retries=2,
            now_monotonic=lambda: clock[0],
            dispatch=dispatch,
            publish_success_response=_publish_response,
            sleep=lambda _: _async_noop(),
            build_final=_build_tuple,
        ),
    )
    assert ledger.dispatches is not None and len(ledger.dispatches) == 1
    assert (result[0], result[1]) == (
        SemanticStatus.INVALID,
        SemanticReason.RESPONSE_CONTENT_INVALID,
    )
    assert result[2].attempted_count == 1
    assert ledger.outcomes == [
        (_ATT1, AttemptOutcome.FAILED, SemanticReason.RESPONSE_CONTENT_INVALID)
    ]
    assert ledger.attempts is not None
    assert ledger.attempts[_ATT1].state == "failed"
    assert ledger.attempts[_ATT1].terminal_code is SemanticReason.RESPONSE_CONTENT_INVALID


@pytest.mark.anyio
async def test_repair_cap_survives_a_replay_with_fresh_coordinator_state() -> None:
    # Durable state after a crash or an awaiting_human replay: attempt 1 was already repaired
    # (expired / response_content_invalid) and the job is queued again. A fresh loop must read
    # that from the rows and refuse a second repair, whatever max_retries allows.
    ledger = _FakeLedger(_queued_job(attempt_count=1), _lease())
    assert ledger.attempts is not None
    ledger.attempts[_ATT1] = SemanticAttemptRecord(
        _JOB,
        _ATT1,
        1,
        "req_40000000-0000-4000-8000-000000000001",
        "expired",
        SemanticReason.RESPONSE_CONTENT_INVALID,
        None,
    )
    status, reason, accounting = await _run(ledger, [_INVALID, _SUCCESS], max_retries=2)
    assert ledger.dispatches is not None and len(ledger.dispatches) == 1
    assert (status, reason) == (SemanticStatus.INVALID, SemanticReason.RESPONSE_CONTENT_INVALID)
    assert accounting.attempted_count == 2
    assert accounting.terminal_reason_counts == (("response_content_invalid", 2),)
    assert ledger.outcomes == [
        (_ATT2, AttemptOutcome.FAILED, SemanticReason.RESPONSE_CONTENT_INVALID)
    ]


@pytest.mark.anyio
async def test_confirm_every_request_repair_waits_for_a_fresh_decision() -> None:
    # Under confirm_every_request the privacy gate answers every physical attempt with its own
    # proposal. The repair attempt therefore surfaces a second awaiting_human wait bound to the
    # new attempt; the first decision is never reused and nothing is dispatched on its authority.
    ledger = _FakeLedger(_queued_job(), _lease())
    first_wait = _AwaitingEval(
        SemanticStatus.AWAITING_HUMAN,
        SemanticReason.HUMAN_APPROVAL_REQUIRED,
        _Continuation(
            "ppr_40000000-0000-4000-8000-000000000003",
            _ExpiresAt(datetime(2030, 1, 1, tzinfo=UTC)),
        ),
    )
    second_wait = _AwaitingEval(
        SemanticStatus.AWAITING_HUMAN,
        SemanticReason.HUMAN_APPROVAL_REQUIRED,
        _Continuation(
            "ppr_40000000-0000-4000-8000-000000000004",
            _ExpiresAt(datetime(2030, 1, 1, tzinfo=UTC)),
        ),
    )
    first = await _run(ledger, [first_wait], max_retries=1)
    assert first[:2] == (
        SemanticStatus.AWAITING_HUMAN,
        SemanticReason.HUMAN_APPROVAL_REQUIRED,
    )
    status, reason, accounting = await _run(ledger, [_INVALID, second_wait], max_retries=1)
    assert ledger.dispatches is not None and len(ledger.dispatches) == 3
    assert len(set(ledger.dispatches)) == 2
    assert (status, reason) == (
        SemanticStatus.AWAITING_HUMAN,
        SemanticReason.HUMAN_APPROVAL_REQUIRED,
    )
    assert ledger.disclosure_waits == [
        (
            _ATT1,
            "ppr_40000000-0000-4000-8000-000000000003",
            datetime(2030, 1, 1, tzinfo=UTC),
        ),
        (
            _ATT2,
            "ppr_40000000-0000-4000-8000-000000000004",
            datetime(2030, 1, 1, tzinfo=UTC),
        ),
    ]
    # The repair attempt stays started and the job leased: an open wait, not a finished check.
    assert ledger.outcomes == [
        (_ATT1, AttemptOutcome.EXPIRED, SemanticReason.RESPONSE_CONTENT_INVALID)
    ]
    assert ledger.attempts is not None and ledger.attempts[_ATT2].state == "started"
    assert ledger.job.state == "leased"
    assert accounting.attempted_count == 2
    active_wait = await ledger.load_disclosure_wait(_WRITER, _OP)
    assert active_wait is not None
    assert active_wait.state == "awaiting"
    assert active_wait.attempt_id == _ATT2


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("terminal", "expected"),
    (
        (
            _Eval(SemanticStatus.HUMAN_DENIED, SemanticReason.HUMAN_DENIED),
            (SemanticStatus.HUMAN_DENIED, SemanticReason.HUMAN_DENIED),
        ),
        (
            _Eval(
                SemanticStatus.APPROVAL_EXPIRED,
                SemanticReason.HUMAN_APPROVAL_EXPIRED,
            ),
            (SemanticStatus.APPROVAL_EXPIRED, SemanticReason.HUMAN_APPROVAL_EXPIRED),
        ),
        (
            _Eval(
                SemanticStatus.BLOCKED_BY_POLICY,
                SemanticReason.POLICY_GENERATION_REVOKED,
            ),
            (SemanticStatus.BLOCKED_BY_POLICY, SemanticReason.POLICY_GENERATION_REVOKED),
        ),
    ),
)
async def test_wait_replay_terminalizes_the_same_attempt_and_resolves_one_use_state(
    terminal: _Eval,
    expected: tuple[SemanticStatus, SemanticReason],
) -> None:
    ledger = _FakeLedger(_queued_job(), _lease())
    waiting = _AwaitingEval(
        SemanticStatus.AWAITING_HUMAN,
        SemanticReason.HUMAN_APPROVAL_REQUIRED,
        _Continuation(
            "ppr_40000000-0000-4000-8000-000000000005",
            _ExpiresAt(datetime(2030, 1, 1, tzinfo=UTC)),
        ),
    )

    first = await _run(ledger, [waiting], max_retries=2)
    provider_request_id = ledger.provider_ids[0] if ledger.provider_ids is not None else None
    assert first[:2] == (
        SemanticStatus.AWAITING_HUMAN,
        SemanticReason.HUMAN_APPROVAL_REQUIRED,
    )

    second = await _run(ledger, [terminal], max_retries=2)

    assert second[:2] == expected
    assert ledger.provider_ids == [provider_request_id]
    assert ledger.attempt_ids == [_ATT1]
    assert ledger.outcomes == [(_ATT1, AttemptOutcome.FAILED, terminal.reason)]
    assert ledger.job.state == "failed"
    resolved = await ledger.load_disclosure_wait(_WRITER, _OP)
    assert resolved is not None and resolved.state == "resolved"


@pytest.mark.anyio
async def test_cancellation_after_wait_terminalizes_before_propagating_and_resolves_wait() -> None:
    ledger = _FakeLedger(_queued_job(), _lease())
    waiting = _AwaitingEval(
        SemanticStatus.AWAITING_HUMAN,
        SemanticReason.HUMAN_APPROVAL_REQUIRED,
        _Continuation(
            "ppr_40000000-0000-4000-8000-000000000006",
            _ExpiresAt(datetime(2030, 1, 1, tzinfo=UTC)),
        ),
    )
    await _run(ledger, [waiting], max_retries=0)

    async def cancel_dispatch(handle: SemanticAttemptHandle, attempt_deadline: Deadline) -> _Eval:
        del handle, attempt_deadline
        raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await run_durable_semantic_attempts(
            ledger=ledger,
            lease=ledger.lease,
            job=ledger.job,
            deadline=Deadline(datetime(2030, 1, 1, tzinfo=UTC), 1000.0),
            max_retries=0,
            now_monotonic=lambda: 0.0,
            dispatch=cancel_dispatch,
            publish_success_response=_publish_response,
            sleep=lambda _: _async_noop(),
            build_final=_build_tuple,
        )

    assert ledger.attempt_ids == [_ATT1]
    assert ledger.outcomes == [(_ATT1, AttemptOutcome.FAILED, SemanticReason.COORDINATOR_FAILURE)]
    assert ledger.job.state == "failed"
    resolved = await ledger.load_disclosure_wait(_WRITER, _OP)
    assert resolved is not None and resolved.state == "resolved"


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("status", "reason"),
    [
        (SemanticStatus.INVALID, SemanticReason.RESPONSE_SCHEMA_INVALID),
        (SemanticStatus.INVALID, SemanticReason.SEMANTIC_JUDGMENT_REJECTED),
        (SemanticStatus.REFUSED, SemanticReason.PROVIDER_REFUSED),
        (SemanticStatus.HUMAN_DENIED, SemanticReason.HUMAN_DENIED),
        (SemanticStatus.BLOCKED_BY_POLICY, SemanticReason.NETWORK_EGRESS_DENIED),
        (SemanticStatus.BLOCKED_FORBIDDEN_DATA, SemanticReason.SECRET_DETECTED),
        (SemanticStatus.STALE, SemanticReason.FRONTIER_CHANGED),
        (SemanticStatus.UNAVAILABLE, SemanticReason.PROVIDER_QUOTA_EXHAUSTED),
    ],
)
async def test_non_repairable_classes_never_consume_a_second_attempt(
    status: SemanticStatus, reason: SemanticReason
) -> None:
    ledger = _FakeLedger(_queued_job(), _lease())
    got_status, got_reason, accounting = await _run(
        ledger, [_Eval(status, reason), _SUCCESS], max_retries=2
    )
    assert ledger.dispatches is not None and len(ledger.dispatches) == 1
    assert (got_status, got_reason) == (status, reason)
    assert accounting.attempted_count == 1
    assert ledger.outcomes == [(_ATT1, AttemptOutcome.FAILED, reason)]


@pytest.mark.anyio
async def test_transient_then_invalid_reports_the_invalid_answer_not_exhaustion() -> None:
    ledger = _FakeLedger(_queued_job(), _lease())
    timeout = _Eval(SemanticStatus.TIMEOUT, SemanticReason.PROVIDER_TIMEOUT)
    status, reason, accounting = await _run(ledger, [timeout, _INVALID, _SUCCESS], max_retries=1)
    assert ledger.dispatches is not None and len(ledger.dispatches) == 2
    assert (status, reason) == (SemanticStatus.INVALID, SemanticReason.RESPONSE_CONTENT_INVALID)
    assert accounting.attempted_count == 2
    assert accounting.terminal_reason_counts == (
        ("provider_timeout", 1),
        ("response_content_invalid", 1),
    )


@pytest.mark.anyio
async def test_repair_shares_the_physical_budget_with_transient_retries() -> None:
    # invalid (repair) -> timeout (transient) -> success: three physical attempts, never four.
    ledger = _FakeLedger(_queued_job(), _lease())
    timeout = _Eval(SemanticStatus.TIMEOUT, SemanticReason.PROVIDER_TIMEOUT)
    status, reason, accounting = await _run(
        ledger, [_INVALID, timeout, _SUCCESS, _SUCCESS], max_retries=2
    )
    assert ledger.dispatches is not None and len(ledger.dispatches) == 3
    assert (status, reason) == (SemanticStatus.SUCCEEDED, SemanticReason.SEMANTIC_COMPLETED)
    assert accounting.selected_attempt_id == _ATT3
    assert accounting.attempted_count == 3


@pytest.mark.anyio
@pytest.mark.parametrize(
    "stage", ["claim", "dispatch_entered", "response_persistence", "result_commit"]
)
@pytest.mark.parametrize("cleanup_fails", [False, True])
async def test_exception_stage_survives_cleanup_and_is_request_joined(
    stage: str, cleanup_fails: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    from yoetz.observability.diagnostics import lookup_diagnostic_records

    lease = _lease()
    job = SemanticJobRecord(
        _JOB,
        _WRITER,
        _OP,
        _CASE,
        _case_ref(),
        "queued",
        0,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    ledger = _FakeLedger(job, lease)
    dispatch_count = 0

    async def fail(*args: object, **kwargs: object) -> object:
        raise RuntimeError("PRIVATE_SENTINEL_payload_must_never_be_logged")

    if stage == "claim":
        monkeypatch.setattr(ledger, "claim_semantic_job", fail)
    if stage == "result_commit":
        monkeypatch.setattr(ledger, "select_attempt", fail)
    if cleanup_fails:
        monkeypatch.setattr(ledger, "fail_semantic_job", fail)
        if stage == "dispatch_entered":
            monkeypatch.setattr(ledger, "record_attempt_outcome", fail)

    async def dispatch(handle: SemanticAttemptHandle, deadline: Deadline) -> _Eval:
        nonlocal dispatch_count
        dispatch_count += 1
        if stage == "dispatch_entered":
            raise ValueError("PRIVATE_SENTINEL_provider_outcome_uncertain")
        return _Eval(SemanticStatus.SUCCEEDED, SemanticReason.SEMANTIC_COMPLETED)

    async def publish(handle: SemanticAttemptHandle, evaluation: object) -> ObjectRef:
        if stage == "response_persistence":
            raise RuntimeError("PRIVATE_SENTINEL_response")
        return _response_ref()

    async def run() -> object:
        return await run_durable_semantic_attempts(
            ledger=ledger,
            lease=lease,
            job=job,
            deadline=Deadline(datetime(2030, 1, 1, tzinfo=UTC), 1000.0),
            max_retries=2,
            now_monotonic=lambda: 0.0,
            dispatch=dispatch,
            publish_success_response=publish,
            build_final=lambda status, reason, evaluation, accounting: (status, reason),
        )

    if stage == "result_commit":
        with pytest.raises(RuntimeError):
            await run()
    else:
        assert await run() == (SemanticStatus.FAILED, SemanticReason.COORDINATOR_FAILURE)
    records = lookup_diagnostic_records(request_id=_OP)
    assert any(row["operation"] == f"semantic_attempt_{stage}_failed" for row in records)
    assert all(row["request_id"] == _OP for row in records)
    assert "PRIVATE_SENTINEL" not in repr(records)
    assert dispatch_count == (0 if stage == "claim" else 1)
    if cleanup_fails and stage in {"claim", "dispatch_entered"}:
        assert len(records) >= 2


@pytest.mark.anyio
async def test_response_publication_failure_keeps_runtime_usage_on_failed_attempt() -> None:
    usage = RuntimeTokenUsage(120, 60, 10, 30, 8, 150)
    ledger = _FakeLedger(_queued_job(), _lease())

    async def dispatch(handle: SemanticAttemptHandle, deadline: Deadline) -> _Eval:
        del handle, deadline
        return _Eval(
            SemanticStatus.SUCCEEDED,
            SemanticReason.SEMANTIC_COMPLETED,
            provenance=SimpleNamespace(
                runtime_evidence=SimpleNamespace(token_usage=usage),
            ),
        )

    async def publish(handle: SemanticAttemptHandle, evaluation: object) -> ObjectRef:
        del handle, evaluation
        raise RuntimeError("response_publish_failed")

    result = await run_durable_semantic_attempts(
        ledger=ledger,
        lease=ledger.lease,
        job=ledger.job,
        deadline=Deadline(datetime(2030, 1, 1, tzinfo=UTC), 1000.0),
        max_retries=0,
        now_monotonic=lambda: 0.0,
        dispatch=dispatch,
        publish_success_response=publish,
        build_final=lambda status, reason, evaluation, accounting: (status, reason, accounting),
    )

    status, reason, accounting = cast(
        tuple[SemanticStatus, SemanticReason, SemanticAttemptAccounting], result
    )
    assert (status, reason) == (
        SemanticStatus.FAILED,
        SemanticReason.COORDINATOR_FAILURE,
    )
    assert accounting.attempt_usages[0].token_usage == usage
    assert ledger.attempts is not None
    assert ledger.attempts[_ATT1].token_usage == usage
