"""Bounded durable-commit ordering and ambiguity resolution helpers."""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from dataclasses import dataclass
from typing import Any, Literal, overload

from finishup.ports.ledger import (
    AppendCommand,
    AppendResult,
    LedgerPort,
    OperationKind,
    OperationState,
)
from finishup.ports.objects import ObjectRef, ObjectStorePort, StagedObject
from finishup.ports.publish_response_catalog import (
    PublishResponseCatalogPort,
    StoredPublishResponse,
)
from finishup.ports.runtime import StartCompletionEvidence
from finishup.ports.start_catalog import (
    EncryptedResultRef,
    SafeReason,
    StartAllocation,
    StartCatalogPort,
    StartCommand,
    StartPhase,
)
from finishup.protocol.errors import PublicErrorCode, PublicOperationError

__all__ = [
    "CatalogLeaseYield",
    "CatalogCompletion",
    "CatalogPhaseAdvance",
    "CatalogQuarantine",
    "CommitResolution",
    "PreSubmissionCancelled",
    "PreparedMutation",
    "abandon_preappend_objects",
    "resolve_ambiguous_operation",
    "resolve_ambiguous_start",
    "run_catalog_transition",
    "run_prepared_append",
    "run_publish_response_commit",
]

type CommitOutcome = Literal["committed", "not_committed", "pending", "quarantined", "unknown"]

_STORAGE_RESOLUTION_CODES = frozenset(
    {
        PublicErrorCode.BUNDLE_BUSY,
        PublicErrorCode.STORAGE_UNSAFE,
        PublicErrorCode.STORAGE_CORRUPT,
        PublicErrorCode.MIGRATION_REQUIRED,
        PublicErrorCode.SERVICE_UNAVAILABLE,
    }
)
_SAFE_QUARANTINE_REASONS = frozenset(
    {
        "operation_event_range_mismatch",
        "operation_kind_state_contradiction",
        "operation_lease_shape_invalid",
        "operation_result_digest_mismatch",
        "operation_resume_object_invalid",
        "start_allocation_ambiguous",
        "start_bundle_invalid",
        "start_catalog_integrity",
        "start_lifecycle_contradiction",
        "start_result_object_missing",
        "start_route_contradiction",
    }
)


def _invalid() -> ValueError:
    return ValueError("invalid_unit_of_work_value")


@dataclass(frozen=True, slots=True)
class PreparedMutation:
    """A fully materialized append whose referenced objects are already durable."""

    writer_id: str
    operation_id: str
    request_digest: str
    expected_frontier: int | None
    finalized_object_refs: tuple[ObjectRef, ...]
    command: AppendCommand

    def __post_init__(self) -> None:
        if type(self.command) is not AppendCommand:
            raise _invalid()
        if (
            self.writer_id != self.command.writer_id
            or self.operation_id != self.command.operation_id
            or self.request_digest != self.command.request_digest
            or self.expected_frontier != self.command.expected_frontier
        ):
            raise _invalid()
        if type(self.finalized_object_refs) is not tuple or any(
            type(ref) is not ObjectRef for ref in self.finalized_object_refs
        ):
            raise _invalid()
        refs_by_id = {ref.object_id: ref for ref in self.finalized_object_refs}
        if len(refs_by_id) != len(self.finalized_object_refs):
            raise _invalid()
        if any(ref.metadata.task_id != self.command.task_id for ref in self.finalized_object_refs):
            raise _invalid()
        if any(
            refs_by_id.get(entry.payload_object.object_id) != entry.payload_object
            for entry in self.command.entries
        ):
            raise _invalid()
        if (
            self.command.result_object_ref is not None
            and refs_by_id.get(self.command.result_object_ref.object_id)
            != self.command.result_object_ref
        ):
            raise _invalid()


@dataclass(frozen=True, slots=True)
class CommitResolution:
    """A durable observation, with only the evidence applicable to that outcome."""

    outcome: CommitOutcome
    stored_result: bytes | None = None
    safe_reason: str | None = None
    failure: PublicOperationError | None = None

    def __post_init__(self) -> None:
        if type(self.outcome) is not str or self.outcome not in {
            "committed",
            "not_committed",
            "pending",
            "quarantined",
            "unknown",
        }:
            raise _invalid()
        if self.stored_result is not None and type(self.stored_result) is not bytes:
            raise _invalid()
        if self.safe_reason is not None and (
            type(self.safe_reason) is not str or self.safe_reason not in _SAFE_QUARANTINE_REASONS
        ):
            raise _invalid()
        if self.failure is not None and type(self.failure) is not PublicOperationError:
            raise _invalid()
        if self.failure is not None and self.failure.code not in _STORAGE_RESOLUTION_CODES:
            raise _invalid()
        shape = (
            self.stored_result is not None,
            self.safe_reason is not None,
            self.failure is not None,
        )
        expected = {
            "committed": (True, False, False),
            "not_committed": (False, False, False),
            "pending": (False, False, False),
            "quarantined": (False, True, False),
            "unknown": (False, False, True),
        }[self.outcome]
        if shape != expected:
            raise _invalid()


@dataclass(frozen=True, slots=True)
class CatalogLeaseYield:
    """Relinquish a definite failed start attempt without discarding its durable state."""

    allocation: StartAllocation

    def __post_init__(self) -> None:
        if type(self.allocation) is not StartAllocation:
            raise _invalid()


@dataclass(frozen=True, slots=True)
class CatalogPhaseAdvance:
    """A closed request for one start-catalog phase CAS."""

    allocation: StartAllocation
    phase: StartPhase
    result: EncryptedResultRef | None = None

    def __post_init__(self) -> None:
        if (
            type(self.allocation) is not StartAllocation
            or type(self.phase) is not StartPhase
            or (self.result is not None and type(self.result) is not EncryptedResultRef)
        ):
            raise _invalid()


@dataclass(frozen=True, slots=True)
class CatalogCompletion:
    """A closed request for the terminal start-catalog commit."""

    allocation: StartAllocation
    result: EncryptedResultRef
    evidence: StartCompletionEvidence

    def __post_init__(self) -> None:
        if (
            type(self.allocation) is not StartAllocation
            or type(self.result) is not EncryptedResultRef
            or type(self.evidence) is not StartCompletionEvidence
        ):
            raise _invalid()


@dataclass(frozen=True, slots=True)
class CatalogQuarantine:
    """A closed request for a durable start-catalog quarantine."""

    allocation: StartAllocation
    reason: SafeReason

    def __post_init__(self) -> None:
        if type(self.allocation) is not StartAllocation or type(self.reason) is not SafeReason:
            raise _invalid()


class PreSubmissionCancelled(asyncio.CancelledError):
    """Cancellation observed before any commit reached a port.

    Every raise site is provably ahead of submission: the port coroutine has either not been
    created or has been closed without being started, so no durable write can exist that could
    later reference the caller's finalized objects. A caller that finalized caller-owned objects
    for the refused mutation may therefore abandon them; a plain ``CancelledError`` carries no
    such guarantee and must be treated as an ambiguous commit.
    """


async def abandon_preappend_objects(
    objects: ObjectStorePort,
    staged_objects: tuple[StagedObject, ...],
    *,
    component: str,
    operation: str,
    request_id: str,
) -> None:
    """Finish best-effort cleanup for exact object stages never submitted to a ledger."""

    from finishup.observability.logging import record_classified_exception_without_raising

    async def abandon_all() -> None:
        for staged in reversed(staged_objects):
            try:
                await objects.abandon(staged)
            except Exception as exc:
                # Cleanup must not replace the caller's original failure. The exact object remains
                # eligible for delayed generation-fenced GC when abandon cannot remove it.
                record_classified_exception_without_raising(
                    exc,
                    component=component,
                    operation=operation,
                    request_id=request_id,
                )

    pending = abandon_all()
    try:
        cleanup = asyncio.create_task(pending)
    except RuntimeError as exc:
        # A closing loop cannot host the cleanup task. Close the un-started coroutine and retain
        # the original caller failure; delayed generation-fenced GC remains the fallback.
        pending.close()
        record_classified_exception_without_raising(
            exc,
            component=component,
            operation=operation,
            request_id=request_id,
        )
        return
    current = asyncio.current_task()
    cancellation: asyncio.CancelledError | None = None
    while True:
        try:
            await asyncio.shield(cleanup)
        except asyncio.CancelledError as exc:
            # Distinguish cancellation of this caller from cancellation inside the cleanup task.
            # The former is deferred until every exact stage has received an abandon attempt.
            if cancellation is None and current is not None and current.cancelling():
                cancellation = exc
        if cleanup.done():
            break
    try:
        cleanup.result()
    except BaseException as exc:
        # Retrieve every definite task outcome without replacing the original caller failure.
        record_classified_exception_without_raising(
            exc,
            component=component,
            operation=operation,
            request_id=request_id,
        )
    if cancellation is not None:
        raise cancellation


def _raise_if_cancelling() -> None:
    current = asyncio.current_task()
    if current is not None and current.cancelling():
        raise PreSubmissionCancelled


async def _await_definite[T](operation: Coroutine[Any, Any, T]) -> T:
    """Await one submitted commit to completion even after outer cancellation."""

    try:
        _raise_if_cancelling()
    except asyncio.CancelledError:
        operation.close()
        raise

    commit_task = asyncio.create_task(operation)
    cancellation: asyncio.CancelledError | None = None
    try:
        return await asyncio.shield(commit_task)
    except asyncio.CancelledError as exc:
        cancellation = exc

    while not commit_task.done():
        try:
            await asyncio.shield(commit_task)
        except asyncio.CancelledError:
            continue

    # Retrieve the definite port outcome so a failed task never becomes an unobserved exception.
    # Outer cancellation remains authoritative for the caller; same-ID retry resolves durability.
    try:
        commit_task.result()
    except BaseException:
        pass
    assert cancellation is not None
    raise cancellation


async def run_prepared_append(ledger: LedgerPort, prepared: PreparedMutation) -> AppendResult:
    """Submit exactly one prepared append and shield only that bounded port commit."""

    if type(prepared) is not PreparedMutation:
        raise _invalid()
    _raise_if_cancelling()
    return await _await_definite(ledger.append_batch(prepared.command))


async def run_publish_response_commit(
    catalog: PublishResponseCatalogPort, response: StoredPublishResponse
) -> StoredPublishResponse:
    """Put one validated response under the same cancellation-shielded commit boundary."""

    if type(response) is not StoredPublishResponse:
        raise _invalid()
    _raise_if_cancelling()
    return await _await_definite(catalog.put_if_absent(response))


def _idempotency_conflict() -> PublicOperationError:
    return PublicOperationError(
        PublicErrorCode.IDEMPOTENCY_CONFLICT,
        "The request ID was already used.",
        False,
    )


async def resolve_ambiguous_operation(
    ledger: LedgerPort,
    writer_id: str,
    operation_id: str,
    request_digest: str,
) -> CommitResolution:
    """Resolve a ledger operation solely from its durable operation record."""

    try:
        record = await ledger.lookup_operation(writer_id, operation_id)
    except PublicOperationError as exc:
        if exc.code not in _STORAGE_RESOLUTION_CODES:
            raise
        return CommitResolution("unknown", failure=exc)

    if record is None:
        return CommitResolution("not_committed")
    if record.request_digest != request_digest:
        raise _idempotency_conflict()
    if record.state is OperationState.COMPLETE:
        assert record.result_canonical is not None
        return CommitResolution("committed", stored_result=record.result_canonical)
    if record.state is OperationState.QUARANTINED:
        assert record.quarantine_code is not None
        return CommitResolution("quarantined", safe_reason=record.quarantine_code.value)
    if record.operation_kind is not OperationKind.CHECK:
        return CommitResolution(
            "quarantined",
            safe_reason="operation_kind_state_contradiction",
        )
    return CommitResolution("pending")


type CatalogTransition = (
    StartCommand | CatalogPhaseAdvance | CatalogCompletion | CatalogQuarantine | CatalogLeaseYield
)


@overload
async def run_catalog_transition(
    catalog: StartCatalogPort, transition: StartCommand | CatalogPhaseAdvance
) -> StartAllocation: ...


@overload
async def run_catalog_transition(
    catalog: StartCatalogPort, transition: CatalogCompletion | CatalogQuarantine | CatalogLeaseYield
) -> None: ...


async def run_catalog_transition(
    catalog: StartCatalogPort, transition: CatalogTransition
) -> StartAllocation | None:
    """Execute one closed start-catalog transition under the commit shield."""

    _raise_if_cancelling()
    if type(transition) is StartCommand:
        return await _await_definite(catalog.reserve_or_resume(transition))
    if type(transition) is CatalogPhaseAdvance:
        return await _await_definite(
            catalog.advance_phase(transition.allocation, transition.phase, transition.result)
        )
    if type(transition) is CatalogCompletion:
        await _await_definite(
            catalog.complete(transition.allocation, transition.result, transition.evidence)
        )
        return None
    if type(transition) is CatalogQuarantine:
        await _await_definite(catalog.quarantine(transition.allocation, transition.reason))
        return None
    if type(transition) is CatalogLeaseYield:
        await _await_definite(catalog.yield_lease(transition.allocation))
        return None
    raise _invalid()


async def resolve_ambiguous_start(
    catalog: StartCatalogPort, command: StartCommand
) -> CommitResolution:
    """Use the catalog's authoritative reserve/resume transition to resolve start."""

    try:
        allocation = await run_catalog_transition(catalog, command)
    except PublicOperationError as exc:
        if exc.code not in _STORAGE_RESOLUTION_CODES:
            raise
        return CommitResolution("unknown", failure=exc)
    if allocation.outcome == "replayed":
        assert allocation.replayed_result is not None
        return CommitResolution("committed", stored_result=allocation.replayed_result)
    return CommitResolution("pending")
