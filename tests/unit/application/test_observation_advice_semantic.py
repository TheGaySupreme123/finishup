"""Bounded asynchronous observation-advice AI-powered review (issue #619).

Every test drives the real SQLite repository over an in-memory bundle and the real advice
builder. No provider is ever called: the dispatch is a fake that records what it was handed.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import SimpleNamespace
from typing import cast

import apsw
import pytest

from yoetz.adapters.sqlite.migrations import initialize_bundle
from yoetz.adapters.sqlite.observation_advice_semantic import (
    SqliteObservationAdviceSemanticRepository,
)
from yoetz.application.observation_advice import (
    ADVICE_SEMANTIC_DEFERRED_GAP,
    ADVICE_SEMANTIC_PENDING_GAP,
    ADVICE_SEMANTIC_PREVIEW_REQUIRED_GAP,
    ADVICE_SEMANTIC_PREVIEW_REQUIRED_REASON,
    ADVICE_SEMANTIC_UNAVAILABLE_GAP,
    ObservationAdviceContextBuilder,
)
from yoetz.application.observation_advice_semantic import (
    ADVICE_SEMANTIC_FAILURE_REASONS,
    AdviceSemanticDrainHandle,
    ObservationAdviceSemanticAttempt,
    ObservationAdviceSemanticOutcome,
    ObservationAdviceSemanticScheduler,
    ObservationAdviceSemanticSupervisor,
    ObservationAdviceSemanticWorker,
    addon_from_attempt,
    advice_candidate_identity,
    advice_semantic_retry_delay_seconds,
)
from yoetz.application.observation_coordinator import ObservationCoordinator
from yoetz.domain.observation import (
    AdviceSnapshot,
    ObservationCursor,
    ObservationEnvelope,
    ObservationGapCode,
    ObservationLifecycle,
    ObservationSource,
    ObservationStatus,
    ObservationStatusQuery,
)
from yoetz.domain.values import JsonObject, Timestamp
from yoetz.ports.runtime import TaskRuntime
from yoetz.ports.semantic_budget import (
    current_semantic_background,
    current_semantic_budget_profile,
)
from yoetz.protocol.canonical import JsonValue, canonical_digest, strict_json_parse
from yoetz.protocol.coverage import CheckType

_COMMITMENT = "hmac-sha256:" + "a" * 64
_TIME = Timestamp("2026-09-08T21:00:00.000Z")
_SESSION = "ses_00000000-0000-4000-8000-000000000001"
_GAPS = (ObservationGapCode.SOURCE_LAG.value, ObservationGapCode.VERIFICATION_STALE.value)


def _envelope(identity: str, payload: dict[str, object], *, pos: int = 1) -> ObservationEnvelope:
    return ObservationEnvelope(
        session_commitment=_COMMITMENT,
        event_kind="PostToolUse",
        source_identity=identity,
        source=ObservationSource.CODEX_HOOK,
        cursor=ObservationCursor(
            source_generation=1,
            byte_position=pos * 8,
            event_position=pos,
            last_source_commitment=_COMMITMENT,
            mapping_version="codex-obs-hook/1.0.0",
        ),
        receipt_time=_TIME,
        structural_payload=JsonObject(payload),
        content_object_refs=(),
        gap_codes=(),
    )


def _repository() -> tuple[apsw.Connection, SqliteObservationAdviceSemanticRepository]:
    db = apsw.Connection(":memory:")
    initialize_bundle(db, {"task_id": "tsk_advice", "owner_generation": "1"})
    return db, SqliteObservationAdviceSemanticRepository(db)


@dataclass
class _Store:
    """The slice of the observation store the advice builder and scheduler touch."""

    repository: SqliteObservationAdviceSemanticRepository
    gaps: tuple[str, ...] = _GAPS
    failed_identity: str = "hook:fail"

    def list_envelopes(self, workspace: str) -> tuple[ObservationEnvelope, ...]:
        assert workspace == _COMMITMENT
        return (
            _envelope(
                self.failed_identity,
                {"tool_name": "shell", "exit_status": 1, "correlation_id": self.failed_identity},
            ),
        )

    async def status(self, query: ObservationStatusQuery) -> ObservationStatus:
        assert query.workspace_commitment == _COMMITMENT
        return ObservationStatus(
            ObservationLifecycle.ACTIVE, _COMMITMENT, {}, _TIME, 0, self.gaps, (), None
        )

    def load_advice_snapshot(self, workspace: str) -> None:
        assert workspace == _COMMITMENT
        return None

    def advice_semantic_repository(self) -> SqliteObservationAdviceSemanticRepository:
        return self.repository


def _clock() -> str:
    return "2026-09-08T21:00:00.000Z"


def _later() -> str:
    return "2026-09-08T21:02:00.000Z"


def _builder() -> ObservationAdviceContextBuilder:
    return ObservationAdviceContextBuilder(
        semantic_scheduler=ObservationAdviceSemanticScheduler(now=_clock)
    )


def _rows(
    db: apsw.Connection, repository: SqliteObservationAdviceSemanticRepository
) -> tuple[ObservationAdviceSemanticAttempt, ...]:
    """Every durable row in schedule order. The row is keyed by the pre-review evidence basis;
    the snapshot's own basis digest is recomputed after the AI-powered review gap is folded in."""

    keys = db.execute(
        "SELECT yoetz_session_id, basis_digest FROM observation_advice_semantic_attempts "
        "ORDER BY state_token"
    ).fetchall()
    rows: list[ObservationAdviceSemanticAttempt] = []
    for session, basis in keys:
        row = repository.lookup(yoetz_session_id=str(session), basis_digest=str(basis))
        assert row is not None
        rows.append(row)
    return tuple(rows)


def _packet(attempt: ObservationAdviceSemanticAttempt) -> Mapping[str, object]:
    parsed = strict_json_parse(attempt.packet_json)
    assert isinstance(parsed, Mapping)
    return parsed


def test_hook_path_build_enqueues_once_and_never_dispatches() -> None:
    """Two identical advice builds produce one durable row and a pending gap, no provider call.

    The scoped observation gaps reach the row and the packet byte-for-byte; the old inline
    callback dropped them and built the packet with an empty gap tuple.
    """

    db, repository = _repository()
    store = _Store(repository)
    builder = _builder()

    first = asyncio.run(builder.build(_COMMITMENT, store, yoetz_session_id=_SESSION))  # type: ignore[arg-type]
    second = asyncio.run(builder.build(_COMMITMENT, store, yoetz_session_id=_SESSION))  # type: ignore[arg-type]

    assert first is not None and second is not None
    assert first.evidence_basis_digest == second.evidence_basis_digest
    assert ADVICE_SEMANTIC_PENDING_GAP in first.confidence_coverage.known_gaps
    assert ADVICE_SEMANTIC_PENDING_GAP in second.confidence_coverage.known_gaps
    assert CheckType.SEMANTIC_MODEL_DERIVED not in first.confidence_coverage.check_types
    assert repository.list_pending_workspaces() == (_COMMITMENT,)
    (attempt,) = _rows(db, repository)
    assert attempt.status == "pending"
    assert attempt.attempt_count == 0
    assert attempt.yoetz_session_id == _SESSION
    assert attempt.coverage_gaps == tuple(sorted(_GAPS, key=str.encode))
    assert _packet(attempt)["coverage_gaps"] == list(sorted(_GAPS, key=str.encode))
    assert attempt.subject_digest == canonical_digest(cast(JsonValue, _packet(attempt)))


def test_stream_churn_reuses_condition_review_and_retains_the_prior_receipt() -> None:
    db, repository = _repository()
    store = _Store(repository)
    builder = _builder()
    first = asyncio.run(builder.build(_COMMITMENT, store, yoetz_session_id=_SESSION))  # type: ignore[arg-type]
    assert first is not None
    (first_row,) = _rows(db, repository)

    # Complete the first attempt through the worker so it holds a receipt.
    async def dispatch(
        attempt: ObservationAdviceSemanticAttempt,
    ) -> ObservationAdviceSemanticOutcome:
        assert current_semantic_budget_profile() == "routine"
        return ObservationAdviceSemanticOutcome(
            status="succeeded",
            attempt_receipt="egr_first",
            provider_identity="provider-a",
            evidence_digest=attempt.subject_digest,
        )

    worker = ObservationAdviceSemanticWorker(
        repository=repository,
        dispatch=dispatch,
        service_generation=1,
        lease_owner="svc-1",
        now=_clock,
        lease_expires_at=_later,
    )
    assert asyncio.run(worker.run_once()) is not None
    assert asyncio.run(worker.run_once()) is None

    # The reviewable rule summaries did not change, even though the stream digest did.
    store.failed_identity = "hook:fail-2"
    second = asyncio.run(builder.build(_COMMITMENT, store, yoetz_session_id=_SESSION))  # type: ignore[arg-type]
    assert second is not None
    assert second.evidence_basis_digest != first.evidence_basis_digest
    assert ADVICE_SEMANTIC_PENDING_GAP not in second.confidence_coverage.known_gaps
    (retained,) = _rows(db, repository)
    assert retained.basis_digest == first_row.basis_digest
    assert (retained.status, retained.attempt_receipt) == ("succeeded", "egr_first")
    assert asyncio.run(worker.run_once()) is None


def test_unattempted_pending_rows_are_superseded_by_a_newer_basis() -> None:
    """A pending row the provider never saw is cancelled when the basis moves on, so the worker
    never reviews evidence the advice no longer stands on; the cancellation stays visible."""

    _db, repository = _repository()
    first = repository.schedule(
        workspace=_COMMITMENT,
        yoetz_session_id=_SESSION,
        basis_digest="sha256:" + "1" * 64,
        subject_digest="sha256:" + "1" * 64,
        coverage_gaps=_GAPS,
        packet_json=b"{}",
        enqueued_at=_clock(),
        max_pending=16,
    )
    second = repository.schedule(
        workspace=_COMMITMENT,
        yoetz_session_id=_SESSION,
        basis_digest="sha256:" + "2" * 64,
        subject_digest="sha256:" + "2" * 64,
        coverage_gaps=_GAPS,
        packet_json=b"{}",
        enqueued_at=_clock(),
        max_pending=16,
    )
    assert isinstance(first, ObservationAdviceSemanticAttempt)
    assert isinstance(second, ObservationAdviceSemanticAttempt)
    assert second.status == "pending"
    superseded = repository.lookup(yoetz_session_id=_SESSION, basis_digest=first.basis_digest)
    assert superseded is not None
    assert (superseded.status, superseded.failure_reason) == ("cancelled", "superseded")
    addon = addon_from_attempt(superseded)
    assert addon is not None and addon.finding_ids == () and addon.failure_reason == "superseded"


def test_queue_bound_records_unavailable_without_an_attempt() -> None:
    _db, repository = _repository()
    for index in range(2):
        session = f"ses_00000000-0000-4000-8000-00000000000{index + 2}"
        row = repository.schedule(
            workspace=_COMMITMENT,
            yoetz_session_id=session,
            basis_digest="sha256:" + str(index) * 64,
            subject_digest="sha256:" + str(index) * 64,
            coverage_gaps=(),
            packet_json=b"{}",
            enqueued_at=_clock(),
            max_pending=2,
        )
        assert isinstance(row, ObservationAdviceSemanticAttempt)
        assert row.status == "pending"
    overflow = repository.schedule(
        workspace=_COMMITMENT,
        yoetz_session_id=_SESSION,
        basis_digest="sha256:" + "f" * 64,
        subject_digest="sha256:" + "f" * 64,
        coverage_gaps=(),
        packet_json=b"{}",
        enqueued_at=_clock(),
        max_pending=2,
    )
    assert isinstance(overflow, ObservationAdviceSemanticAttempt)
    assert (overflow.status, overflow.failure_reason) == ("unavailable", "queue_full")
    assert overflow.attempt_count == 0
    addon = addon_from_attempt(overflow)
    assert addon is not None
    assert addon.failure_reason == "queue_full" and addon.finding_ids == ()
    # The bounded row never becomes claimable work.
    claimed = repository.claim_next(
        service_generation=1, lease_owner="svc", lease_expires_at=_later(), now=_clock()
    )
    assert claimed is not None and claimed.yoetz_session_id != _SESSION


@pytest.mark.parametrize(
    ("outcome", "expected_reason"),
    [
        (
            ObservationAdviceSemanticOutcome(
                status="unavailable", failure_reason="authorization_missing"
            ),
            "authorization_missing",
        ),
        (
            ObservationAdviceSemanticOutcome(
                status="unavailable", failure_reason="provider_unavailable"
            ),
            "provider_unavailable",
        ),
        (
            ObservationAdviceSemanticOutcome(status="failed", failure_reason="provider_failed"),
            "provider_failed",
        ),
    ],
)
def test_non_success_outcomes_leave_a_truthful_gap_and_no_semantic_claim(
    outcome: ObservationAdviceSemanticOutcome, expected_reason: str
) -> None:
    db, repository = _repository()
    store = _Store(repository)
    builder = _builder()
    pending = asyncio.run(builder.build(_COMMITMENT, store, yoetz_session_id=_SESSION))  # type: ignore[arg-type]
    assert pending is not None

    async def dispatch(
        _attempt: ObservationAdviceSemanticAttempt,
    ) -> ObservationAdviceSemanticOutcome:
        return outcome

    worker = ObservationAdviceSemanticWorker(
        repository=repository,
        dispatch=dispatch,
        service_generation=1,
        lease_owner="svc-1",
        now=_clock,
        lease_expires_at=_later,
    )
    assert asyncio.run(worker.run_once()) is not None
    (row,) = _rows(db, repository)
    assert row.failure_reason == expected_reason and row.finding_ids == ()
    rebuilt = asyncio.run(builder.build(_COMMITMENT, store, yoetz_session_id=_SESSION))  # type: ignore[arg-type]
    assert rebuilt is not None
    assert ADVICE_SEMANTIC_UNAVAILABLE_GAP in rebuilt.confidence_coverage.known_gaps
    assert ADVICE_SEMANTIC_PENDING_GAP not in rebuilt.confidence_coverage.known_gaps
    assert CheckType.SEMANTIC_MODEL_DERIVED not in rebuilt.confidence_coverage.check_types


def test_dispatch_exception_and_cancellation_are_recorded_not_succeeded() -> None:
    _db, repository = _repository()
    for basis, exc in (("sha256:" + "a" * 64, RuntimeError("boom")), ("sha256:" + "b" * 64, None)):
        session = _SESSION if basis.endswith("a" * 64) else _SESSION[:-1] + "2"
        repository.schedule(
            workspace=_COMMITMENT,
            yoetz_session_id=session,
            basis_digest=basis,
            subject_digest=basis,
            coverage_gaps=(),
            packet_json=b"{}",
            enqueued_at=_clock(),
            max_pending=16,
        )

        async def dispatch(
            _attempt: ObservationAdviceSemanticAttempt,
        ) -> ObservationAdviceSemanticOutcome:
            if exc is not None:
                raise exc
            raise asyncio.CancelledError

        worker = ObservationAdviceSemanticWorker(
            repository=repository,
            dispatch=dispatch,
            service_generation=1,
            lease_owner="svc-1",
            now=_clock,
            lease_expires_at=_later,
        )
        if exc is None:
            with pytest.raises(asyncio.CancelledError):
                asyncio.run(worker.run_once())
        else:
            asyncio.run(worker.run_once())
        row = repository.lookup(yoetz_session_id=session, basis_digest=basis)
        assert row is not None
        assert row.status in {"failed", "cancelled"}
        assert row.failure_reason in ADVICE_SEMANTIC_FAILURE_REASONS
        assert row.finding_ids == ()


def test_cancellation_reconciliation_is_bounded_and_never_fabricates_provenance() -> None:
    """A cancelled row records reconciled egress provenance, or plain ``cancelled`` (#755).

    The reconciliation is shielded so cancellation cannot drop it, and bounded so a stuck or
    failing reconciler can never hold the foreground rebind open. Neither path may invent a
    success, a finding, or a second dispatch.
    """

    _db, repository = _repository()
    stuck = asyncio.Event()
    cases: tuple[tuple[str, str | None, str], ...] = (
        ("d", "egr_30000000-0000-4000-8000-0000000000d1", "reconciled"),
        ("e", None, "unconsumed"),
        ("f", None, "raises"),
        ("0", None, "stuck"),
    )
    for marker, receipt, mode in cases:
        basis = "sha256:" + marker * 64
        session = _SESSION[:-1] + marker
        repository.schedule(
            workspace=_COMMITMENT,
            yoetz_session_id=session,
            basis_digest=basis,
            subject_digest=basis,
            coverage_gaps=(),
            packet_json=b"{}",
            enqueued_at=_clock(),
            max_pending=16,
        )
        dispatches = 0

        async def dispatch(
            _attempt: ObservationAdviceSemanticAttempt,
        ) -> ObservationAdviceSemanticOutcome:
            nonlocal dispatches
            dispatches += 1
            raise asyncio.CancelledError

        async def reconcile(
            _attempt: ObservationAdviceSemanticAttempt,
            *,
            _receipt: str | None = receipt,
            _mode: str = mode,
        ) -> ObservationAdviceSemanticOutcome | None:
            if _mode == "raises":
                raise RuntimeError("audit unreadable")
            if _mode == "stuck":
                await stuck.wait()
            if _receipt is None:
                return None
            return ObservationAdviceSemanticOutcome(
                status="cancelled",
                failure_reason="cancelled",
                attempt_receipt=_receipt,
                provider_identity="provider-under-test",
            )

        worker = ObservationAdviceSemanticWorker(
            repository=repository,
            dispatch=dispatch,
            service_generation=1,
            lease_owner="svc-1",
            now=_clock,
            lease_expires_at=_later,
            reconcile_cancelled=reconcile,
            reconcile_timeout_seconds=0.05,
        )
        with pytest.raises(asyncio.CancelledError):
            asyncio.run(worker.run_once())

        row = repository.lookup(yoetz_session_id=session, basis_digest=basis)
        assert row is not None
        assert (row.status, row.failure_reason) == ("cancelled", "cancelled")
        assert row.finding_ids == ()
        assert row.attempt_receipt == receipt
        assert row.provider_identity == (None if receipt is None else "provider-under-test")
        assert dispatches == 1


def test_restart_reclaims_a_foreign_generation_lease_without_reporting_success() -> None:
    """A row left running by a previous service generation is re-attempted, never succeeded."""

    _db, repository = _repository()
    basis = "sha256:" + "c" * 64
    repository.schedule(
        workspace=_COMMITMENT,
        yoetz_session_id=_SESSION,
        basis_digest=basis,
        subject_digest=basis,
        coverage_gaps=_GAPS,
        packet_json=b"{}",
        enqueued_at=_clock(),
        max_pending=16,
    )
    stranded = repository.claim_next(
        service_generation=1, lease_owner="svc-old", lease_expires_at=_later(), now=_clock()
    )
    assert stranded is not None and stranded.status == "running"
    # While the old generation holds the lease, its own claim finds nothing more to do and the
    # row is still not a success.
    assert (
        repository.claim_next(
            service_generation=1, lease_owner="svc-old", lease_expires_at=_later(), now=_clock()
        )
        is None
    )
    addon = addon_from_attempt(repository.lookup(yoetz_session_id=_SESSION, basis_digest=basis))
    assert addon is not None and addon.failure_reason == "pending" and addon.finding_ids == ()

    # The next generation reclaims it and the attempt count reflects the interrupted try.
    reclaimed = repository.claim_next(
        service_generation=2, lease_owner="svc-new", lease_expires_at=_later(), now=_clock()
    )
    assert reclaimed is not None
    assert reclaimed.attempt_id == stranded.attempt_id
    assert reclaimed.attempt_count == 2
    # The stale holder can no longer complete it.
    with pytest.raises(Exception, match="stale"):
        repository.complete(
            attempt=stranded,
            service_generation=1,
            lease_owner="svc-old",
            outcome=ObservationAdviceSemanticOutcome(status="succeeded", attempt_receipt="x"),
            recorded_at=_clock(),
        )
    repository.complete(
        attempt=reclaimed,
        service_generation=2,
        lease_owner="svc-new",
        outcome=ObservationAdviceSemanticOutcome(status="succeeded", attempt_receipt="egr_new"),
        recorded_at=_clock(),
    )
    done = repository.lookup(yoetz_session_id=_SESSION, basis_digest=basis)
    assert done is not None and (done.status, done.attempt_receipt) == ("succeeded", "egr_new")


def test_repeatedly_interrupted_rows_terminate_as_interrupted() -> None:
    _db, repository = _repository()
    basis = "sha256:" + "d" * 64
    repository.schedule(
        workspace=_COMMITMENT,
        yoetz_session_id=_SESSION,
        basis_digest=basis,
        subject_digest=basis,
        coverage_gaps=(),
        packet_json=b"{}",
        enqueued_at=_clock(),
        max_pending=16,
    )
    for generation in (1, 2, 3):
        claimed = repository.claim_next(
            service_generation=generation,
            lease_owner=f"svc-{generation}",
            lease_expires_at=_later(),
            now=_clock(),
        )
        assert claimed is not None
    assert (
        repository.claim_next(
            service_generation=4, lease_owner="svc-4", lease_expires_at=_later(), now=_clock()
        )
        is None
    )
    row = repository.lookup(yoetz_session_id=_SESSION, basis_digest=basis)
    assert row is not None
    assert (row.status, row.failure_reason) == ("failed", "interrupted")


def test_supervisor_drains_registered_workers_and_reruns_advice_after_each_attempt() -> None:
    db, repository = _repository()
    store = _Store(repository)
    builder = _builder()
    pending = asyncio.run(builder.build(_COMMITMENT, store, yoetz_session_id=_SESSION))  # type: ignore[arg-type]
    assert pending is not None
    (row,) = _rows(db, repository)
    dispatched: list[str] = []
    reruns: list[str] = []
    idle: list[str] = []

    async def dispatch(
        attempt: ObservationAdviceSemanticAttempt,
    ) -> ObservationAdviceSemanticOutcome:
        dispatched.append(attempt.basis_digest)
        return ObservationAdviceSemanticOutcome(
            status="succeeded",
            attempt_receipt="egr_ok",
            provider_identity="provider-a",
            evidence_digest=attempt.subject_digest,
        )

    async def after() -> None:
        reruns.append("advice")

    async def on_idle() -> None:
        idle.append("released")

    async def scenario() -> None:
        supervisor = ObservationAdviceSemanticSupervisor(service_generation=1)
        worker = ObservationAdviceSemanticWorker(
            repository=repository,
            dispatch=dispatch,
            service_generation=1,
            lease_owner="svc-1",
            now=_clock,
            lease_expires_at=_later,
        )
        assert supervisor.register(
            AdviceSemanticDrainHandle(_COMMITMENT, worker, after_complete=after, on_idle=on_idle)
        )
        await supervisor.drain_once()
        assert not supervisor.has_handle(_COMMITMENT)
        await supervisor.stop()

    asyncio.run(scenario())
    assert dispatched == [row.basis_digest]
    assert reruns == ["advice"] and idle == ["released"]
    rebuilt = asyncio.run(builder.build(_COMMITMENT, store, yoetz_session_id=_SESSION))  # type: ignore[arg-type]
    assert rebuilt is not None
    assert ADVICE_SEMANTIC_PENDING_GAP not in rebuilt.confidence_coverage.known_gaps
    assert ADVICE_SEMANTIC_UNAVAILABLE_GAP not in rebuilt.confidence_coverage.known_gaps
    # A succeeded attempt without challenges is an honest receipt, not an additive finding.
    assert CheckType.SEMANTIC_MODEL_DERIVED not in rebuilt.confidence_coverage.check_types


def test_foreground_rebind_cancels_slow_provider_and_records_terminal_gap() -> None:
    """A foreground attach can yield the semantic runtime without redispatching its packet."""

    _db, repository = _repository()
    basis = "sha256:" + "e" * 64
    repository.schedule(
        workspace=_COMMITMENT,
        yoetz_session_id=_SESSION,
        basis_digest=basis,
        subject_digest=basis,
        coverage_gaps=_GAPS,
        packet_json=b"{}",
        enqueued_at=_clock(),
        max_pending=16,
    )
    started = asyncio.Event()
    idle: list[str] = []

    async def slow_dispatch(
        _attempt: ObservationAdviceSemanticAttempt,
    ) -> ObservationAdviceSemanticOutcome:
        started.set()
        # This represents a provider that could run past the five-second foreground rebind wait.
        # The worker's cooperative cancellation must settle the row without waiting for it.
        await asyncio.Event().wait()
        raise AssertionError("provider cancellation was not delivered")

    async def on_idle() -> None:
        idle.append("released")

    async def scenario() -> None:
        supervisor = ObservationAdviceSemanticSupervisor(service_generation=1)
        worker = ObservationAdviceSemanticWorker(
            repository=repository,
            dispatch=slow_dispatch,
            service_generation=1,
            lease_owner="svc-1",
            now=_clock,
            lease_expires_at=_later,
        )
        assert supervisor.register(AdviceSemanticDrainHandle(_COMMITMENT, worker, on_idle=on_idle))
        draining = asyncio.create_task(supervisor.drain_once())
        await asyncio.wait_for(started.wait(), 5)
        worker.request_rebind()
        await asyncio.wait_for(draining, 5)
        assert not supervisor.has_handle(_COMMITMENT)

    asyncio.run(scenario())
    row = repository.lookup(yoetz_session_id=_SESSION, basis_digest=basis)
    assert row is not None
    assert (row.status, row.failure_reason) == ("cancelled", "cancelled")
    assert repository.list_pending_workspaces() == ()
    assert idle == ["released"]


def test_foreground_rebind_also_releases_during_post_attempt_advice_rebuild() -> None:
    """A slow post-attempt rebuild cannot retain the semantic runtime past foreground priority."""

    _db, repository = _repository()
    basis = "sha256:" + "f" * 64
    repository.schedule(
        workspace=_COMMITMENT,
        yoetz_session_id=_SESSION,
        basis_digest=basis,
        subject_digest=basis,
        coverage_gaps=_GAPS,
        packet_json=b"{}",
        enqueued_at=_clock(),
        max_pending=16,
    )
    after_started = asyncio.Event()
    idle: list[str] = []

    async def dispatch(
        attempt: ObservationAdviceSemanticAttempt,
    ) -> ObservationAdviceSemanticOutcome:
        return ObservationAdviceSemanticOutcome(
            status="succeeded",
            attempt_receipt="egr_after",
            evidence_digest=attempt.subject_digest,
        )

    async def after_complete() -> None:
        after_started.set()
        await asyncio.Event().wait()

    async def on_idle() -> None:
        idle.append("released")

    async def scenario() -> None:
        supervisor = ObservationAdviceSemanticSupervisor(service_generation=1)
        worker = ObservationAdviceSemanticWorker(
            repository=repository,
            dispatch=dispatch,
            service_generation=1,
            lease_owner="svc-1",
            now=_clock,
            lease_expires_at=_later,
        )
        assert supervisor.register(
            AdviceSemanticDrainHandle(
                _COMMITMENT,
                worker,
                after_complete=after_complete,
                on_idle=on_idle,
            )
        )
        draining = asyncio.create_task(supervisor.drain_once())
        await asyncio.wait_for(after_started.wait(), 5)
        worker.request_rebind()
        await asyncio.wait_for(draining, 5)
        assert not supervisor.has_handle(_COMMITMENT)

    asyncio.run(scenario())
    row = repository.lookup(yoetz_session_id=_SESSION, basis_digest=basis)
    assert row is not None
    assert (row.status, row.attempt_receipt) == ("succeeded", "egr_after")
    assert idle == ["released"]


def test_rebind_retires_queued_workspace_while_another_provider_attempt_is_active() -> None:
    """A queued advisory lease yields immediately without parallelizing provider work."""

    _db_first, first_repository = _repository()
    _db_second, second_repository = _repository()
    second_session = _SESSION[:-1] + "2"
    first_repository.schedule(
        workspace=_COMMITMENT,
        yoetz_session_id=_SESSION,
        basis_digest="sha256:" + "1" * 64,
        subject_digest="sha256:" + "1" * 64,
        coverage_gaps=_GAPS,
        packet_json=b"{}",
        enqueued_at=_clock(),
        max_pending=16,
    )
    second_repository.schedule(
        workspace=_COMMITMENT,
        yoetz_session_id=second_session,
        basis_digest="sha256:" + "2" * 64,
        subject_digest="sha256:" + "2" * 64,
        coverage_gaps=_GAPS,
        packet_json=b"{}",
        enqueued_at=_clock(),
        max_pending=16,
    )
    first_started = asyncio.Event()
    release_first = asyncio.Event()
    second_idle = asyncio.Event()
    dispatched: list[str] = []

    async def dispatch(
        attempt: ObservationAdviceSemanticAttempt,
    ) -> ObservationAdviceSemanticOutcome:
        dispatched.append(attempt.yoetz_session_id)
        if attempt.yoetz_session_id == _SESSION:
            first_started.set()
            await release_first.wait()
        return ObservationAdviceSemanticOutcome(
            status="succeeded", attempt_receipt="egr_serialized"
        )

    async def on_second_idle() -> None:
        second_idle.set()

    async def scenario() -> None:
        supervisor = ObservationAdviceSemanticSupervisor(service_generation=1)
        first_worker = ObservationAdviceSemanticWorker(
            repository=first_repository,
            dispatch=dispatch,
            service_generation=1,
            lease_owner="svc-1",
            now=_clock,
            lease_expires_at=_later,
        )
        second_worker = ObservationAdviceSemanticWorker(
            repository=second_repository,
            dispatch=dispatch,
            service_generation=1,
            lease_owner="svc-1",
            now=_clock,
            lease_expires_at=_later,
        )
        assert supervisor.register(AdviceSemanticDrainHandle(_SESSION, first_worker))
        assert supervisor.register(
            AdviceSemanticDrainHandle(
                _COMMITMENT + "-second", second_worker, on_idle=on_second_idle
            )
        )
        draining = asyncio.create_task(supervisor.drain_once())
        await asyncio.wait_for(first_started.wait(), 5)
        supervisor.request_rebind(_COMMITMENT + "-second")
        await asyncio.wait_for(second_idle.wait(), 5)
        assert supervisor.has_handle(_SESSION)
        assert not supervisor.has_handle(_COMMITMENT + "-second")
        assert dispatched == [_SESSION]
        release_first.set()
        await asyncio.wait_for(draining, 5)
        await supervisor.stop()

    asyncio.run(scenario())
    first = first_repository.lookup(yoetz_session_id=_SESSION, basis_digest="sha256:" + "1" * 64)
    second = second_repository.lookup(
        yoetz_session_id=second_session, basis_digest="sha256:" + "2" * 64
    )
    assert first is not None and first.status == "succeeded"
    assert second is not None and second.status == "pending"


def test_outcome_shape_is_closed() -> None:
    with pytest.raises(ValueError, match="advice_semantic_outcome_invalid"):
        ObservationAdviceSemanticOutcome(status="failed", failure_reason="made_up")
    with pytest.raises(ValueError, match="advice_semantic_outcome_invalid"):
        ObservationAdviceSemanticOutcome(status="succeeded", failure_reason="provider_failed")
    with pytest.raises(ValueError, match="advice_semantic_outcome_invalid"):
        ObservationAdviceSemanticOutcome(
            status="failed", failure_reason="provider_failed", finding_ids=("fnd_x",)
        )


def test_repeated_rebind_preserves_consumed_attempt_provenance_and_releases_once() -> None:
    _db, repository = _repository()
    basis = "sha256:" + "b" * 64
    repository.schedule(
        workspace=_COMMITMENT,
        yoetz_session_id=_SESSION,
        basis_digest=basis,
        subject_digest=basis,
        coverage_gaps=_GAPS,
        packet_json=b"{}",
        enqueued_at=_clock(),
        max_pending=16,
    )
    entered = asyncio.Event()
    reconciling = asyncio.Event()
    finish_reconciliation = asyncio.Event()
    released: list[bool] = []

    async def dispatch(_: ObservationAdviceSemanticAttempt) -> ObservationAdviceSemanticOutcome:
        entered.set()
        await asyncio.Event().wait()
        raise AssertionError("expected cancellation")

    async def reconcile(_: ObservationAdviceSemanticAttempt) -> ObservationAdviceSemanticOutcome:
        reconciling.set()
        await finish_reconciliation.wait()
        return ObservationAdviceSemanticOutcome(
            status="cancelled",
            failure_reason="cancelled",
            attempt_receipt="egr_30000000-0000-4000-8000-0000000000d1",
            provider_identity="provider-under-test",
        )

    async def on_idle() -> None:
        released.append(True)

    async def scenario() -> None:
        supervisor = ObservationAdviceSemanticSupervisor(service_generation=1)
        worker = ObservationAdviceSemanticWorker(
            repository,
            dispatch,
            1,
            "svc-1",
            _clock,
            _later,
            reconcile,
        )
        assert supervisor.register(AdviceSemanticDrainHandle(_COMMITMENT, worker, on_idle=on_idle))
        draining = asyncio.create_task(supervisor.drain_once())
        await asyncio.wait_for(entered.wait(), 5)
        supervisor.request_rebind(_COMMITMENT)
        await asyncio.wait_for(reconciling.wait(), 5)
        # A second host arrives while the first cancellation is reconciling consumed authority.
        supervisor.request_rebind(_COMMITMENT)
        finish_reconciliation.set()
        await asyncio.wait_for(draining, 5)
        await supervisor.stop()
        assert not supervisor.has_handle(_COMMITMENT)

    asyncio.run(scenario())
    row = repository.lookup(yoetz_session_id=_SESSION, basis_digest=basis)
    assert row is not None
    assert row.status == "cancelled"
    assert row.attempt_receipt == "egr_30000000-0000-4000-8000-0000000000d1"
    assert row.provider_identity == "provider-under-test"
    assert released == [True]


def test_retirement_survives_cancelled_waiter_and_stop_joins_release() -> None:
    _, repository = _repository()
    entered = asyncio.Event()
    release_gate = asyncio.Event()
    released: list[bool] = []

    async def dispatch(_: ObservationAdviceSemanticAttempt) -> ObservationAdviceSemanticOutcome:
        raise AssertionError("an empty repository must not dispatch")

    async def on_idle() -> None:
        entered.set()
        await release_gate.wait()
        released.append(True)

    async def scenario() -> None:
        supervisor = ObservationAdviceSemanticSupervisor(service_generation=1)
        worker = ObservationAdviceSemanticWorker(repository, dispatch, 1, "svc-1", _clock, _later)
        assert supervisor.register(AdviceSemanticDrainHandle(_COMMITMENT, worker, on_idle=on_idle))
        draining = asyncio.create_task(supervisor.drain_once())
        await asyncio.wait_for(entered.wait(), 5)
        draining.cancel()
        stopping = asyncio.create_task(supervisor.stop())
        release_gate.set()
        await asyncio.wait_for(asyncio.gather(draining, stopping), 5)
        assert not supervisor.has_handle(_COMMITMENT)

    asyncio.run(scenario())
    assert released == [True]


def test_rebind_already_waiting_yields_newly_registered_advisory_handle() -> None:
    _, repository = _repository()
    released: list[object] = []
    supervisor = ObservationAdviceSemanticSupervisor(service_generation=1)
    owned = cast(
        TaskRuntime,
        SimpleNamespace(fence=SimpleNamespace(service_generation=1, service_instance_id="svc-1")),
    )

    async def dispatch(_: ObservationAdviceSemanticAttempt) -> ObservationAdviceSemanticOutcome:
        raise AssertionError("foreground yield must prevent provider dispatch")

    class Runtime:
        def register_rebind_callback(
            self, runtime: TaskRuntime, callback: Callable[[], None]
        ) -> bool:
            assert runtime is owned
            assert supervisor.has_handle(_COMMITMENT)
            callback()  # LocalBundleRuntime fires eagerly when a foreground start is waiting.
            return True

        def unregister_rebind_callback(
            self, runtime: TaskRuntime, callback: Callable[[], None]
        ) -> None:
            assert runtime is owned

        async def release(self, runtime: TaskRuntime) -> None:
            released.append(runtime)

    def store_for(_: object) -> SqliteObservationAdviceSemanticRepository:
        return repository

    coordinator = cast(
        ObservationCoordinator,
        SimpleNamespace(
            advice_semantic_supervisor=supervisor,
            advice_semantic_dispatch=dispatch,
            advice_semantic_cancellation_reconciler=None,
            runtime=Runtime(),
            _observation_store=store_for,
            _advice_semantic_repository=store_for,
        ),
    )

    async def scenario() -> None:
        registered = await ObservationCoordinator._register_advice_semantic_drain(  # pyright: ignore[reportPrivateUsage]
            coordinator, _COMMITMENT, owned, deferred_runtime=owned
        )
        assert registered
        await supervisor.stop()

    asyncio.run(scenario())
    assert released == [owned]


def _at(stamp: str) -> Callable[[], str]:
    return lambda: stamp


def _complete_next(
    repository: SqliteObservationAdviceSemanticRepository,
    outcome: ObservationAdviceSemanticOutcome,
    *,
    at: str,
) -> ObservationAdviceSemanticAttempt:
    async def dispatch(
        _attempt: ObservationAdviceSemanticAttempt,
    ) -> ObservationAdviceSemanticOutcome:
        assert current_semantic_budget_profile() == "routine"
        assert current_semantic_background() is True
        return outcome

    worker = ObservationAdviceSemanticWorker(
        repository=repository,
        dispatch=dispatch,
        service_generation=1,
        lease_owner="svc-1",
        now=_at(at),
        lease_expires_at=_at("2026-09-08T23:00:00.000Z"),
    )
    attempt = asyncio.run(worker.run_once())
    assert attempt is not None
    return attempt


def _scheduler_builder(
    stamp: str,
    revisits: list[tuple[str, str, float]] | None = None,
    *,
    route_ready: bool | None = None,
) -> ObservationAdviceContextBuilder:
    async def ready(_session: str) -> bool:
        assert route_ready is not None
        return route_ready

    return ObservationAdviceContextBuilder(
        semantic_scheduler=ObservationAdviceSemanticScheduler(
            now=_at(stamp),
            route_ready=None if route_ready is None else ready,
            revisit=None if revisits is None else lambda w, s, d: revisits.append((w, s, d)),
        )
    )


_SUCCEEDED = ObservationAdviceSemanticOutcome(status="succeeded", attempt_receipt="egr_ok")


def test_rate_limit_survives_repository_reopen_and_admits_changed_condition() -> None:
    db, repository = _repository()
    store = _Store(repository)
    first = asyncio.run(_builder().build(_COMMITMENT, store, yoetz_session_id=_SESSION))  # type: ignore[arg-type]
    assert first is not None
    _complete_next(repository, _SUCCEEDED, at="2026-09-08T21:00:00.000Z")
    (original,) = _rows(db, repository)
    # A genuinely different packet is rate limited; a fresh repository/scheduler cannot reset it.
    store.repository = SqliteObservationAdviceSemanticRepository(db)
    store.gaps = (ObservationGapCode.SOURCE_LAG.value,)
    revisits: list[tuple[str, str, float]] = []
    for _ in range(1, 180):
        deferred = asyncio.run(
            _scheduler_builder("2026-09-08T21:02:59.000Z", revisits).build(
                _COMMITMENT,
                store,
                yoetz_session_id=_SESSION,  # type: ignore[arg-type]
            )
        )
        assert deferred is not None
        assert ADVICE_SEMANTIC_DEFERRED_GAP in deferred.confidence_coverage.known_gaps
        assert ADVICE_SEMANTIC_PENDING_GAP not in deferred.confidence_coverage.known_gaps
        assert deferred.semantic_attempt_state == "unavailable"
    assert _rows(db, repository) == (original,)
    # Each refusal asks for a trailing-edge revisit when the interval elapses.
    assert revisits and all(item[:2] == (_COMMITMENT, _SESSION) for item in revisits)
    assert revisits[0][2] == pytest.approx(1.0)
    admitted_snapshot = asyncio.run(
        _scheduler_builder("2026-09-08T21:03:00.000Z").build(
            _COMMITMENT,
            store,
            yoetz_session_id=_SESSION,  # type: ignore[arg-type]
        )
    )
    assert admitted_snapshot is not None
    assert ADVICE_SEMANTIC_PENDING_GAP in admitted_snapshot.confidence_coverage.known_gaps
    prior, admitted = _rows(db, repository)
    assert prior == original
    assert admitted.basis_digest != prior.basis_digest
    assert admitted.status == "pending"


def test_unattempted_pending_row_does_not_consume_the_session_rate_limit() -> None:
    # A row the provider never saw is superseded by the newer identity, not rate limited.
    db, repository = _repository()
    store = _Store(repository)
    asyncio.run(_builder().build(_COMMITMENT, store, yoetz_session_id=_SESSION))  # type: ignore[arg-type]
    store.gaps = (ObservationGapCode.SOURCE_LAG.value,)
    asyncio.run(
        _scheduler_builder("2026-09-08T21:00:05.000Z").build(
            _COMMITMENT,
            store,
            yoetz_session_id=_SESSION,  # type: ignore[arg-type]
        )
    )
    first, second = _rows(db, repository)
    assert (first.status, first.failure_reason) == ("cancelled", "superseded")
    assert second.status == "pending"


def test_identity_ignores_evidence_counts_but_not_new_candidates() -> None:
    base: dict[str, object] = {
        "format": "yoetz.observation-advice-semantic/1",
        "policy": "p/1",
        "evidence_basis_digest": "sha256:" + "1" * 64,
        "coverage_gaps": ("source_lag",),
        "finding_summaries": ("failed_command",),
        "deterministic_rules": (
            {
                "kind": "k",
                "rule_code": "failed_command",
                "next_action": "resolve_failed_command",
                "evidence_ref_count": 1,
                "summary": "s",
            },
        ),
    }
    more_evidence = dict(base)
    more_evidence["evidence_basis_digest"] = "sha256:" + "2" * 64
    more_evidence["deterministic_rules"] = (
        {**base["deterministic_rules"][0], "evidence_ref_count": 7},  # type: ignore[index]
    )
    new_rule = dict(base)
    new_rule["deterministic_rules"] = (
        *base["deterministic_rules"],  # type: ignore[misc]
        {
            "kind": "k",
            "rule_code": "edit_without_verification",
            "next_action": "run_verification",
            "evidence_ref_count": 1,
            "summary": "t",
        },
    )
    new_action = dict(base)
    new_action["deterministic_rules"] = (
        {**base["deterministic_rules"][0], "next_action": "inspect"},  # type: ignore[index]
    )
    assert advice_candidate_identity(base) == advice_candidate_identity(more_evidence)
    assert advice_candidate_identity(base) != advice_candidate_identity(new_rule)
    assert advice_candidate_identity(base) != advice_candidate_identity(new_action)


def test_more_evidence_for_the_same_rule_reuses_the_reviewed_identity() -> None:
    db, repository = _repository()
    store = _Store(repository)
    asyncio.run(_builder().build(_COMMITMENT, store, yoetz_session_id=_SESSION))  # type: ignore[arg-type]
    _complete_next(repository, _SUCCEEDED, at=_clock())
    envelopes = (
        _envelope("hook:fail", {"tool_name": "shell", "exit_status": 1, "correlation_id": "a"}),
        _envelope(
            "hook:fail-2", {"tool_name": "shell", "exit_status": 1, "correlation_id": "b"}, pos=2
        ),
    )
    store.list_envelopes = lambda _workspace: envelopes  # type: ignore[method-assign]
    later = asyncio.run(
        _scheduler_builder("2026-09-08T22:00:00.000Z").build(
            _COMMITMENT,
            store,
            yoetz_session_id=_SESSION,  # type: ignore[arg-type]
        )
    )
    assert later is not None
    assert later.semantic_attempt_state == "ready"
    (only,) = _rows(db, repository)
    assert only.status == "succeeded"


def test_authorization_missing_backs_off_instead_of_retrying_on_every_build() -> None:
    """A non-success row is not sticky (#890), but never re-admitted hot (#923).

    ``authorization_missing`` now only arises when authority was lost between the route probe
    and the dispatch, so it waits the base backoff like any pre-provider failure; an
    unreachable route writes nothing at all.
    """

    db, repository = _repository()
    store = _Store(repository)
    asyncio.run(_builder().build(_COMMITMENT, store, yoetz_session_id=_SESSION))  # type: ignore[arg-type]
    _complete_next(
        repository,
        ObservationAdviceSemanticOutcome(
            status="unavailable", failure_reason="authorization_missing"
        ),
        at="2026-09-08T21:00:01.000Z",
    )
    # The route cannot reach a provider: no row, no revisit, disclosed as unavailable.
    revisits: list[tuple[str, str, float]] = []
    held = asyncio.run(
        _scheduler_builder("2026-09-08T21:01:00.000Z", revisits, route_ready=False).build(
            _COMMITMENT,
            store,
            yoetz_session_id=_SESSION,  # type: ignore[arg-type]
        )
    )
    assert held is not None
    assert ADVICE_SEMANTIC_UNAVAILABLE_GAP in held.confidence_coverage.known_gaps
    assert ADVICE_SEMANTIC_PENDING_GAP not in held.confidence_coverage.known_gaps
    assert len(_rows(db, repository)) == 1
    assert revisits == []
    # Reachable again, but inside the base backoff: still no new row; the revisit waits it out.
    backing_off = asyncio.run(
        _scheduler_builder("2026-09-08T21:01:30.000Z", revisits, route_ready=True).build(
            _COMMITMENT,
            store,
            yoetz_session_id=_SESSION,  # type: ignore[arg-type]
        )
    )
    assert backing_off is not None
    assert ADVICE_SEMANTIC_UNAVAILABLE_GAP in backing_off.confidence_coverage.known_gaps
    assert len(_rows(db, repository)) == 1
    assert revisits == [(_COMMITMENT, _SESSION, pytest.approx(91.0))]
    # The backoff elapsed: retried once. Pre-provider failures consume no rate limit.
    asyncio.run(
        _scheduler_builder("2026-09-08T21:03:01.000Z", route_ready=True).build(
            _COMMITMENT,
            store,
            yoetz_session_id=_SESSION,  # type: ignore[arg-type]
        )
    )
    first, retry = _rows(db, repository)
    assert first.failure_reason == "authorization_missing"
    assert retry.basis_digest == first.basis_digest + "#1"
    assert retry.status == "pending"
    retried = _complete_next(repository, _SUCCEEDED, at="2026-09-08T21:03:10.000Z")
    assert retried.attempt_id == retry.attempt_id
    ready = asyncio.run(
        _scheduler_builder("2026-09-08T21:30:00.000Z").build(
            _COMMITMENT,
            store,
            yoetz_session_id=_SESSION,  # type: ignore[arg-type]
        )
    )
    assert ready is not None and ready.semantic_attempt_state == "ready"
    assert len(_rows(db, repository)) == 2


def test_route_that_cannot_reach_a_provider_writes_no_row() -> None:
    """An inactive route, or one without a granted repository authority, enqueues nothing."""

    db, repository = _repository()
    store = _ManyFailuresStore(repository)
    revisits: list[tuple[str, str, float]] = []
    for failures in range(1, 6):
        store.failures = failures
        snapshot = asyncio.run(
            _scheduler_builder("2026-09-08T21:00:00.000Z", revisits, route_ready=False).build(
                _COMMITMENT,
                store,
                yoetz_session_id=_SESSION,  # type: ignore[arg-type]
            )
        )
        assert snapshot is not None
        gaps = snapshot.confidence_coverage.known_gaps
        assert gaps.count(ADVICE_SEMANTIC_UNAVAILABLE_GAP) == 1
        assert ADVICE_SEMANTIC_PENDING_GAP not in gaps
        assert snapshot.semantic_attempt_state == "disabled"
    assert _rows(db, repository) == ()
    assert revisits == []


def test_probe_and_dispatch_disagreeing_never_loops() -> None:
    """Authority lost after the probe: one row per backoff, never one per hook or drain."""

    db, repository = _repository()
    store = _Store(repository)
    revisits: list[tuple[str, str, float]] = []
    missing = ObservationAdviceSemanticOutcome(
        status="unavailable", failure_reason="authorization_missing"
    )
    snapshot = None
    for _ in range(12):
        # A hook build, then the drain and its post-attempt rebuild, all within one second.
        snapshot = asyncio.run(
            _scheduler_builder("2026-09-08T21:00:00.500Z", revisits, route_ready=True).build(
                _COMMITMENT,
                store,
                yoetz_session_id=_SESSION,  # type: ignore[arg-type]
            )
        )
        if repository.list_pending_workspaces():
            _complete_next(repository, missing, at="2026-09-08T21:00:00.000Z")
    assert snapshot is not None
    assert ADVICE_SEMANTIC_PENDING_GAP not in snapshot.confidence_coverage.known_gaps
    assert ADVICE_SEMANTIC_UNAVAILABLE_GAP in snapshot.confidence_coverage.known_gaps
    (only,) = _rows(db, repository)
    assert only.failure_reason == "authorization_missing"


def test_provider_failure_backs_off_exponentially_then_retries_without_a_new_hook() -> None:
    db, repository = _repository()
    store = _Store(repository)
    asyncio.run(_builder().build(_COMMITMENT, store, yoetz_session_id=_SESSION))  # type: ignore[arg-type]
    failed = ObservationAdviceSemanticOutcome(status="failed", failure_reason="provider_failed")
    _complete_next(repository, failed, at="2026-09-08T21:00:00.000Z")
    # Generation 1 backoff is the 180 s base; the rate limit is also 180 s.
    asyncio.run(
        _scheduler_builder("2026-09-08T21:02:59.000Z").build(
            _COMMITMENT,
            store,
            yoetz_session_id=_SESSION,  # type: ignore[arg-type]
        )
    )
    assert len(_rows(db, repository)) == 1
    asyncio.run(
        _scheduler_builder("2026-09-08T21:03:00.000Z").build(
            _COMMITMENT,
            store,
            yoetz_session_id=_SESSION,  # type: ignore[arg-type]
        )
    )
    assert len(_rows(db, repository)) == 2
    _complete_next(repository, failed, at="2026-09-08T21:03:00.000Z")
    # Generation 2 doubles to 360 s.
    revisits: list[tuple[str, str, float]] = []
    asyncio.run(
        _scheduler_builder("2026-09-08T21:08:59.000Z", revisits).build(
            _COMMITMENT,
            store,
            yoetz_session_id=_SESSION,  # type: ignore[arg-type]
        )
    )
    assert len(_rows(db, repository)) == 2
    assert revisits == [(_COMMITMENT, _SESSION, pytest.approx(1.0))]
    asyncio.run(
        _scheduler_builder("2026-09-08T21:09:00.000Z").build(
            _COMMITMENT,
            store,
            yoetz_session_id=_SESSION,  # type: ignore[arg-type]
        )
    )
    rows = _rows(db, repository)
    assert [row.basis_digest[-2:] for row in rows[1:]] == ["#1", "#2"]
    assert rows[-1].status == "pending"


def test_retry_delay_schedule_is_bounded() -> None:
    def row(reason: str) -> ObservationAdviceSemanticAttempt:
        return ObservationAdviceSemanticAttempt(
            attempt_id="a",
            workspace_commitment=_COMMITMENT,
            yoetz_session_id=_SESSION,
            basis_digest="b",
            subject_digest="sha256:" + "0" * 64,
            coverage_gaps=(),
            packet_json=b"{}",
            status="failed",
            state_token=1,
            failure_reason=reason,
        )

    delays = [
        advice_semantic_retry_delay_seconds(row("provider_failed"), generation=n, base_seconds=180)
        for n in range(1, 8)
    ]
    assert delays == [180, 360, 720, 1440, 2880, 2880, 2880]
    assert (
        advice_semantic_retry_delay_seconds(row("superseded"), generation=3, base_seconds=180) == 0
    )
    assert (
        advice_semantic_retry_delay_seconds(
            row("authorization_missing"), generation=5, base_seconds=180
        )
        == 180
    )


def test_supervisor_revisit_timer_rebuilds_once_per_session_and_stops_cleanly() -> None:
    async def scenario() -> list[tuple[str, str]]:
        supervisor = ObservationAdviceSemanticSupervisor(service_generation=1)
        calls: list[tuple[str, str]] = []

        async def handler(workspace: str, session: str) -> None:
            calls.append((workspace, session))

        supervisor.schedule_revisit(_COMMITMENT, _SESSION, 0.01)  # no handler: ignored
        assert supervisor.pending_revisits() == ()
        supervisor.set_revisit_handler(handler)
        supervisor.schedule_revisit(_COMMITMENT, _SESSION, 0.01)
        supervisor.schedule_revisit(_COMMITMENT, _SESSION, 0.01)
        assert supervisor.pending_revisits() == ((_COMMITMENT, _SESSION),)
        await asyncio.sleep(1.2)
        assert supervisor.pending_revisits() == ()
        supervisor.schedule_revisit(_COMMITMENT, _SESSION, 30.0)
        await supervisor.stop()
        assert supervisor.pending_revisits() == ()
        return calls

    assert asyncio.run(scenario()) == [(_COMMITMENT, _SESSION)]


def test_explicit_dispatch_outside_the_worker_is_not_background() -> None:
    # Explicit ``check`` dispatches never enter the background scope.
    assert current_semantic_background() is False


def test_disabled_scheduler_never_enqueues() -> None:
    db, repository = _repository()
    builder = ObservationAdviceContextBuilder(
        semantic_scheduler=ObservationAdviceSemanticScheduler(now=_clock, enabled=False)
    )
    snapshot = asyncio.run(
        builder.build(_COMMITMENT, _Store(repository), yoetz_session_id=_SESSION)
    )  # type: ignore[arg-type]
    assert snapshot is not None and snapshot.ranked_items
    assert _rows(db, repository) == ()


def test_disabled_dispatch_does_not_rediscover_pending_work() -> None:
    # Disabling in READY removes the dispatch callback. Recovery must not enter any runtime
    # or inspect pending work, even when the service supervisor exists.
    coordinator = ObservationCoordinator(
        runtime=object(),  # type: ignore[arg-type]
        local=object(),  # type: ignore[arg-type]
        clock=object(),  # type: ignore[arg-type]
        ids=object(),  # type: ignore[arg-type]
        advice_semantic_supervisor=ObservationAdviceSemanticSupervisor(service_generation=2),
        advice_semantic_dispatch=None,
    )
    asyncio.run(coordinator.rediscover_pending_advice_semantic())


# --- Provider readiness and cancelled-call usage (issue #923) ---------------------------------


@dataclass
class _ManyFailuresStore(_Store):
    """A session that keeps producing distinct advice candidates, one failed command each."""

    failures: int = 1

    def list_envelopes(self, workspace: str) -> tuple[ObservationEnvelope, ...]:
        assert workspace == _COMMITMENT
        return tuple(
            _envelope(
                f"hook:fail-{index}",
                {
                    "tool_name": "shell",
                    "exit_status": 1,
                    "correlation_id": f"hook:fail-{index}",
                },
                pos=index + 1,
            )
            for index in range(self.failures)
        )


class _Readiness:
    """A live provider-readiness fact that tests flip between builds."""

    def __init__(self, ready: bool) -> None:
        self.ready = ready
        self.probes = 0

    async def __call__(self) -> bool:
        self.probes += 1
        return self.ready


def _readiness_builder(
    readiness: Callable[[], object],
    revisits: list[tuple[str, str, float]] | None = None,
    *,
    stamp: str = "2026-09-08T21:00:00.000Z",
) -> ObservationAdviceContextBuilder:
    return ObservationAdviceContextBuilder(
        semantic_scheduler=ObservationAdviceSemanticScheduler(
            now=_at(stamp),
            revisit=None if revisits is None else lambda w, s, d: revisits.append((w, s, d)),
            provider_ready=readiness,  # type: ignore[arg-type]
        )
    )


def test_no_usable_provider_writes_no_row_and_reports_unavailable_once() -> None:
    """Arm B of #923: many candidates, no provider, no rows, and never a pending gap."""

    db, repository = _repository()
    store = _ManyFailuresStore(repository)
    readiness = _Readiness(False)
    revisits: list[tuple[str, str, float]] = []
    builder = _readiness_builder(readiness, revisits)

    snapshots: list[AdviceSnapshot] = []
    for failures in range(1, 9):
        # Every observation changes the candidate set, as a busy session would.
        store.failures = failures
        snapshot = asyncio.run(builder.build(_COMMITMENT, store, yoetz_session_id=_SESSION))  # type: ignore[arg-type]
        assert snapshot is not None and snapshot.ranked_items
        snapshots.append(snapshot)

    assert readiness.probes == 8
    assert _rows(db, repository) == ()
    assert repository.list_pending_workspaces() == ()
    assert revisits == []
    for snapshot in snapshots:
        gaps = snapshot.confidence_coverage.known_gaps
        assert gaps.count(ADVICE_SEMANTIC_UNAVAILABLE_GAP) == 1
        assert ADVICE_SEMANTIC_PENDING_GAP not in gaps
        assert ADVICE_SEMANTIC_DEFERRED_GAP not in gaps
        assert CheckType.SEMANTIC_MODEL_DERIVED not in snapshot.confidence_coverage.check_types
        # No attempt was requested, so none is reported as pending or failed.
        assert snapshot.semantic_attempt_state == "disabled"

    # The same evidence rebuilt is the same advice: nothing new to deliver.
    again = asyncio.run(builder.build(_COMMITMENT, store, yoetz_session_id=_SESSION))  # type: ignore[arg-type]
    assert again is not None
    assert again.suppression_identity == snapshots[-1].suppression_identity
    assert again.confidence_coverage == snapshots[-1].confidence_coverage
    assert _rows(db, repository) == ()


def test_provider_probe_failure_admits_nothing() -> None:
    db, repository = _repository()

    async def unreadable() -> bool:
        raise RuntimeError("vault locking race")

    snapshot = asyncio.run(
        _readiness_builder(unreadable).build(
            _COMMITMENT,
            _Store(repository),
            yoetz_session_id=_SESSION,  # type: ignore[arg-type]
        )
    )
    assert snapshot is not None
    assert ADVICE_SEMANTIC_UNAVAILABLE_GAP in snapshot.confidence_coverage.known_gaps
    assert ADVICE_SEMANTIC_PENDING_GAP not in snapshot.confidence_coverage.known_gaps
    assert _rows(db, repository) == ()


def test_binding_later_admits_advice_and_unbinding_stops_it_without_restart() -> None:
    """Readiness is read per build: bind admits the next condition, unbind admits nothing."""

    db, repository = _repository()
    store = _ManyFailuresStore(repository)
    readiness = _Readiness(False)
    builder = _readiness_builder(readiness)

    unbound = asyncio.run(builder.build(_COMMITMENT, store, yoetz_session_id=_SESSION))  # type: ignore[arg-type]
    assert unbound is not None
    assert ADVICE_SEMANTIC_UNAVAILABLE_GAP in unbound.confidence_coverage.known_gaps
    assert _rows(db, repository) == ()

    # The owner binds a provider and enables LLM inference: same scheduler, no restart.
    readiness.ready = True
    bound = asyncio.run(builder.build(_COMMITMENT, store, yoetz_session_id=_SESSION))  # type: ignore[arg-type]
    assert bound is not None
    assert ADVICE_SEMANTIC_PENDING_GAP in bound.confidence_coverage.known_gaps
    assert ADVICE_SEMANTIC_UNAVAILABLE_GAP not in bound.confidence_coverage.known_gaps
    (admitted,) = _rows(db, repository)
    assert admitted.status == "pending"

    # Removing the binding stops admission at once. The queued row is not reported as
    # pending work: the service dispatch drains it as ``provider_unavailable``.
    readiness.ready = False
    store.failures = 3
    unbound_again = asyncio.run(builder.build(_COMMITMENT, store, yoetz_session_id=_SESSION))  # type: ignore[arg-type]
    assert unbound_again is not None
    assert ADVICE_SEMANTIC_PENDING_GAP not in unbound_again.confidence_coverage.known_gaps
    assert ADVICE_SEMANTIC_UNAVAILABLE_GAP in unbound_again.confidence_coverage.known_gaps
    assert _rows(db, repository) == (admitted,)


def test_completed_review_stays_visible_after_the_provider_goes_away() -> None:
    db, repository = _repository()
    store = _Store(repository)
    readiness = _Readiness(True)
    builder = _readiness_builder(readiness)
    asyncio.run(builder.build(_COMMITMENT, store, yoetz_session_id=_SESSION))  # type: ignore[arg-type]
    _complete_next(repository, _SUCCEEDED, at="2026-09-08T21:00:01.000Z")
    (completed,) = _rows(db, repository)

    readiness.ready = False
    snapshot = asyncio.run(builder.build(_COMMITMENT, store, yoetz_session_id=_SESSION))  # type: ignore[arg-type]
    assert snapshot is not None
    assert snapshot.semantic_attempt_state == "ready"
    assert ADVICE_SEMANTIC_UNAVAILABLE_GAP not in snapshot.confidence_coverage.known_gaps
    assert ADVICE_SEMANTIC_PENDING_GAP not in snapshot.confidence_coverage.known_gaps
    assert _rows(db, repository) == (completed,)


def test_cancelled_request_reconciliation_marks_unknown_usage_unless_proven_unsent() -> None:
    """A cancelled advisory call names its provider whenever it may have started (#923)."""

    from yoetz.application.egress import SemanticEgressAttemptUnknown
    from yoetz.application.observation_advice_semantic import (
        ADVICE_SEMANTIC_CANCEL_RECOVERY_SECONDS,
        DEFAULT_ADVICE_SEMANTIC_RECONCILE_TIMEOUT_SECONDS,
        reconcile_cancelled_advice_request,
    )

    # The lookup's own bound sits inside the worker's, so it always finishes first.
    assert (
        ADVICE_SEMANTIC_CANCEL_RECOVERY_SECONDS < DEFAULT_ADVICE_SEMANTIC_RECONCILE_TIMEOUT_SECONDS
    )
    minted = ("req_00000000-0000-4000-8000-000000000923", "provider-under-test")
    stuck = asyncio.Event()

    async def consumed(_request: str) -> SemanticEgressAttemptUnknown | None:
        return SemanticEgressAttemptUnknown(
            _request, "ppr_00000000-0000-4000-8000-000000000923", "egr_consumed"
        )

    async def consumed_without_receipt(_request: str) -> SemanticEgressAttemptUnknown | None:
        return SemanticEgressAttemptUnknown(_request, "ppr_00000000-0000-4000-8000-000000000924")

    async def unconsumed(_request: str) -> SemanticEgressAttemptUnknown | None:
        return None

    async def unreadable(_request: str) -> SemanticEgressAttemptUnknown | None:
        raise RuntimeError("audit unreadable")

    async def blocked(_request: str) -> SemanticEgressAttemptUnknown | None:
        await stuck.wait()
        return None

    def run(
        request: tuple[str, str] | None, recover: object
    ) -> ObservationAdviceSemanticOutcome | None:
        return asyncio.run(
            reconcile_cancelled_advice_request(
                request,
                recover,  # type: ignore[arg-type]
                timeout_seconds=0.05,
            )
        )

    # Never minted, or authorization provably never consumed: nothing was sent.
    assert run(None, consumed) is None
    assert run(minted, unconsumed) is None
    # Consumed: the terminal receipt (else its proposal) and the provider.
    assert run(minted, consumed) == ObservationAdviceSemanticOutcome(
        status="cancelled",
        failure_reason="cancelled",
        attempt_receipt="egr_consumed",
        provider_identity="provider-under-test",
    )
    with_proposal = run(minted, consumed_without_receipt)
    assert with_proposal is not None
    assert with_proposal.attempt_receipt == "ppr_00000000-0000-4000-8000-000000000924"
    # Cannot establish either way: usage unknown, never a free call and never a success.
    unknown = ObservationAdviceSemanticOutcome(
        status="cancelled", failure_reason="cancelled", provider_identity="provider-under-test"
    )
    assert run(minted, unreadable) == unknown
    assert run(minted, blocked) == unknown
    assert run(minted, None) == unknown


def test_cancelled_call_row_records_usage_unknown_when_the_lookup_is_blocked() -> None:
    """The stored row keeps the provider identity even when the audit lock is held (#923)."""

    from yoetz.application.observation_advice_semantic import reconcile_cancelled_advice_request

    _db, repository = _repository()
    basis = "sha256:" + "9" * 64
    repository.schedule(
        workspace=_COMMITMENT,
        yoetz_session_id=_SESSION,
        basis_digest=basis,
        subject_digest=basis,
        coverage_gaps=(),
        packet_json=b"{}",
        enqueued_at=_clock(),
        max_pending=16,
    )
    minted: dict[str, tuple[str, str]] = {}
    held = asyncio.Event()

    async def dispatch(
        attempt: ObservationAdviceSemanticAttempt,
    ) -> ObservationAdviceSemanticOutcome:
        # The provider request was minted, then a foreground rebind cancelled the call.
        minted[attempt.attempt_id] = ("req_00000000-0000-4000-8000-000000000925", "codex")
        raise asyncio.CancelledError

    async def lookup_behind_foreground_check(_request: str) -> None:
        await held.wait()  # a foreground check holds the privacy admission lock

    async def reconcile(
        attempt: ObservationAdviceSemanticAttempt,
    ) -> ObservationAdviceSemanticOutcome | None:
        return await reconcile_cancelled_advice_request(
            minted.pop(attempt.attempt_id, None),
            lookup_behind_foreground_check,
            timeout_seconds=0.05,
        )

    worker = ObservationAdviceSemanticWorker(
        repository=repository,
        dispatch=dispatch,
        service_generation=1,
        lease_owner="svc-1",
        now=_clock,
        lease_expires_at=_later,
        reconcile_cancelled=reconcile,
        reconcile_timeout_seconds=1.0,
    )
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(worker.run_once())

    row = repository.lookup(yoetz_session_id=_SESSION, basis_digest=basis)
    assert row is not None
    assert (row.status, row.failure_reason) == ("cancelled", "cancelled")
    assert row.provider_identity == "codex"
    assert row.attempt_receipt is None
    assert row.finding_ids == ()


def _preview_builder(
    preview: bool | Exception, revisits: list[tuple[str, str, float]]
) -> ObservationAdviceContextBuilder:
    async def ready(*_args: str) -> bool:
        return True

    async def preview_required(_session: str) -> bool:
        if isinstance(preview, Exception):
            raise preview
        return preview

    return ObservationAdviceContextBuilder(
        semantic_scheduler=ObservationAdviceSemanticScheduler(
            now=_clock,
            provider_ready=ready,
            route_ready=ready,
            preview_required=preview_required,
            revisit=lambda w, s, d: revisits.append((w, s, d)),
        )
    )


def test_preview_required_policy_skips_background_advice_with_a_typed_reason() -> None:
    """A policy that needs the owner to preview each packet cannot run unattended (#1019)."""

    db, repository = _repository()
    revisits: list[tuple[str, str, float]] = []
    snapshot = asyncio.run(
        _preview_builder(True, revisits).build(
            _COMMITMENT,
            _Store(repository),  # type: ignore[arg-type]
            yoetz_session_id=_SESSION,
        )
    )
    assert snapshot is not None
    gaps = snapshot.confidence_coverage.known_gaps
    assert ADVICE_SEMANTIC_PREVIEW_REQUIRED_GAP in gaps
    assert ADVICE_SEMANTIC_UNAVAILABLE_GAP in gaps
    assert ADVICE_SEMANTIC_PENDING_GAP not in gaps
    assert snapshot.semantic_attempt_state == "disabled"
    # Skipped, not attempted: no row (so no provider identity or backoff) and no revisit.
    assert _rows(db, repository) == ()
    assert revisits == []
    # The preview reason is an admission-time condition, never a stored attempt outcome.
    assert ADVICE_SEMANTIC_PREVIEW_REQUIRED_REASON not in ADVICE_SEMANTIC_FAILURE_REASONS


def test_preview_probe_failure_fails_closed_as_unreachable() -> None:
    db, repository = _repository()
    snapshot = asyncio.run(
        _preview_builder(RuntimeError("policy store unreadable"), []).build(
            _COMMITMENT,
            _Store(repository),  # type: ignore[arg-type]
            yoetz_session_id=_SESSION,
        )
    )
    assert snapshot is not None
    gaps = snapshot.confidence_coverage.known_gaps
    assert ADVICE_SEMANTIC_UNAVAILABLE_GAP in gaps
    assert ADVICE_SEMANTIC_PREVIEW_REQUIRED_GAP not in gaps
    assert _rows(db, repository) == ()


def test_unattended_policy_still_admits_background_advice() -> None:
    db, repository = _repository()
    snapshot = asyncio.run(
        _preview_builder(False, []).build(
            _COMMITMENT,
            _Store(repository),  # type: ignore[arg-type]
            yoetz_session_id=_SESSION,
        )
    )
    assert snapshot is not None
    assert ADVICE_SEMANTIC_PENDING_GAP in snapshot.confidence_coverage.known_gaps
    assert ADVICE_SEMANTIC_PREVIEW_REQUIRED_GAP not in snapshot.confidence_coverage.known_gaps
    assert len(_rows(db, repository)) == 1
