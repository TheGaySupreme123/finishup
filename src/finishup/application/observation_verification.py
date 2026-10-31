"""Compose workspace inspection and approved checks bound to subject-state digests."""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol, cast

from finishup.adapters.approved_checks import (
    ApprovedCheckApproval,
    ApprovedCheckCommand,
    ApprovedCheckResult,
    ApprovedCheckRunner,
    ApprovedCheckStatus,
)
from finishup.kernel.policies.observation_advice import ObservationCheckFact, ObservationInspectFact
from finishup.observability.logging import record_unexpected_exception_without_raising
from finishup.ports.subject_state import LocalWorkspaceHandle
from finishup.ports.workspace_inspect import (
    WorkspaceInspectCommand,
    WorkspaceInspectPort,
    WorkspaceInspectResult,
    WorkspaceInspectStatus,
)

__all__ = [
    "CompletedApprovedCheck",
    "InspectionOrchestrationResult",
    "ObservationVerificationJob",
    "ObservationVerificationRepository",
    "ObservationVerificationSupervisor",
    "ObservationVerificationWorker",
    "SubjectStateDigestFn",
    "VerificationDrainHandle",
    "orchestrate_changed_path_inspection",
    "run_bound_approved_check",
]

type SubjectStateDigestFn = Callable[[LocalWorkspaceHandle], str]
type ApprovedCheckMaterializer = Callable[["CompletedApprovedCheck"], Awaitable[None]]


@dataclass(frozen=True, slots=True)
class InspectionOrchestrationResult:
    inspect: WorkspaceInspectResult | None
    inspect_fact: ObservationInspectFact | None
    relative_paths: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ObservationVerificationJob:
    job_id: str
    workspace_commitment: str
    policy_digest: str
    approval_commitment: str
    subject_state_digest: str
    state_token: int


@dataclass(frozen=True, slots=True)
class CompletedApprovedCheck:
    job: ObservationVerificationJob
    approval_id: str
    result: ApprovedCheckResult
    subject_state_after: str | None
    output_object_id: str | None
    is_current: bool
    recorded_at: str
    # The runner replaced credential bytes in (or withheld) the output it handed over (#1015).
    output_redacted: bool = False


class ObservationVerificationRepository(Protocol):
    """Generation-fenced durable verification job/result repository."""

    def enqueue_latest(
        self,
        *,
        workspace: str,
        policy_digest: str,
        approvals: tuple[str, ...],
        subject_state_digest: str,
        enqueued_at: str,
    ) -> tuple[str, ...]: ...

    def claim_next(
        self,
        *,
        service_generation: int,
        lease_owner: str,
        lease_expires_at: str,
        now: str,
    ) -> ObservationVerificationJob | None: ...

    def list_pending_workspaces(self) -> tuple[str, ...]: ...

    def complete(
        self,
        *,
        job: ObservationVerificationJob,
        service_generation: int,
        lease_owner: str,
        check_id: str,
        result: ApprovedCheckResult,
        subject_state_after: str | None,
        result_commitment: str,
        output_object_id: str | None,
        limitations_json: bytes,
        is_current: bool,
        recorded_at: str,
    ) -> None: ...


WorkspaceProvider = Callable[[str], LocalWorkspaceHandle]
PolicyProvider = Callable[[str, str], tuple[ApprovedCheckApproval, ...]]
SubjectDigestProvider = Callable[[LocalWorkspaceHandle], str]
# ``(job, output, redacted)``: ``redacted`` is the runner's own redaction flag (#1015).
OutputPersister = Callable[[ObservationVerificationJob, bytes, bool], Awaitable[str | None]]
NowProvider = Callable[[], str]


@dataclass(frozen=True, slots=True)
class VerificationDrainHandle:
    """One task/workspace lane's durable worker plus optional post-drain hooks.

    A workspace can own more than one task once explicit sibling/child work is admitted.  The
    durable job repository is task-bundle local, so the supervisor must retain one handle per
    task lane rather than using the source workspace as a process-global singleton key.  The
    optional ``task_id`` keeps callers that predate multi-task routing source-compatible; those
    callers retain the historical one-handle-per-workspace behavior until they provide the task
    identity.
    """

    workspace_commitment: str
    worker: ObservationVerificationWorker
    after_complete: Callable[[], Awaitable[None]] | None = None
    on_idle: Callable[[], Awaitable[None]] | None = None
    task_id: str | None = None
    on_failure: Callable[[], Awaitable[None]] | None = None


@dataclass
class ObservationVerificationSupervisor:
    """Generation-fenced background verification owned by the ready lifecycle.

    Hook ingest only enqueues durable jobs and wakes this supervisor. Approved
    checks never execute inside the hook RPC budget. Startup discovers already-
    pending work via registered drain handles; expired leases are reclaimed by
    ``claim_next``. Shutdown waits for the loop to stop before vault/runtime close.
    """

    service_generation: int

    def __post_init__(self) -> None:
        self._handles: dict[str, VerificationDrainHandle] = {}
        self._wake = asyncio.Event()
        self._closed = False
        self._loop_task: asyncio.Task[None] | None = None
        self._lock = asyncio.Lock()

    @staticmethod
    def _handle_key(workspace_commitment: str, task_id: str | None = None) -> str:
        """Return an opaque in-process lane key.

        The workspace-only form deliberately remains the historical dictionary key for callers
        that do not yet provide a task identity.  The multi-task form is namespaced with a NUL
        separator; this value never crosses a public boundary, and all durable identity remains
        in the task repository and route fence.
        """

        return workspace_commitment if task_id is None else f"{workspace_commitment}\x00{task_id}"

    @classmethod
    def _key_for_handle(cls, handle: VerificationDrainHandle) -> str:
        return cls._handle_key(handle.workspace_commitment, handle.task_id)

    def register(self, handle: VerificationDrainHandle) -> bool:
        if self._closed:
            return False
        key = self._key_for_handle(handle)
        if key in self._handles:
            self._wake.set()
            return False
        self._handles[key] = handle
        self._wake.set()
        return True

    def has_handle(self, workspace_commitment: str, task_id: str | None = None) -> bool:
        """Return whether the requested lane is currently registered.

        ``task_id=None`` intentionally checks every lane for the workspace for compatibility with
        old callers.  Multi-task callers pass their task ID and therefore do not suppress an
        unrelated sibling sharing the same source workspace.
        """

        if task_id is not None:
            return self._handle_key(workspace_commitment, task_id) in self._handles
        legacy_key = self._handle_key(workspace_commitment)
        return legacy_key in self._handles or any(
            handle.workspace_commitment == workspace_commitment for handle in self._handles.values()
        )

    @property
    def closed(self) -> bool:
        return self._closed

    def unregister(self, workspace_commitment: str, task_id: str | None = None) -> None:
        self._handles.pop(self._handle_key(workspace_commitment, task_id), None)

    def notify(self, workspace_commitment: str | None = None) -> None:
        del workspace_commitment
        if not self._closed:
            self._wake.set()

    async def start(self) -> None:
        if self._loop_task is not None:
            return
        self._closed = False
        self._wake.set()
        self._loop_task = asyncio.create_task(self._run_loop(), name="observation-verification")

    async def rediscover(
        self,
        builders: Mapping[str, Callable[[], VerificationDrainHandle | None]],
    ) -> None:
        """Register drain handles for workspaces that still have durable pending jobs.

        ``builders`` maps workspace commitment → factory that rebuilds a worker/handle
        (or returns None when the workspace cannot be opened yet). Called once after
        ready-lifecycle start so restart reclaim can complete.
        """

        for _workspace, builder in sorted(builders.items(), key=lambda item: item[0].encode()):
            if self._closed:
                return
            handle = builder()
            if handle is None:
                continue
            self.register(handle)
        self.notify()

    async def stop(self) -> None:
        self._closed = True
        self._wake.set()
        task = self._loop_task
        self._loop_task = None
        if task is not None:
            with contextlib.suppress(asyncio.CancelledError):
                await task
        handles = tuple(self._handles.values())
        self._handles.clear()
        for handle in handles:
            if handle.on_idle is not None:
                await handle.on_idle()

    async def _run_loop(self) -> None:
        while not self._closed:
            # Consume the wake that started this pass before draining. A handle
            # registered by an on-idle handoff during the drain then leaves the
            # event set and starts the successor pass immediately.
            self._wake.clear()
            made_progress = await self._drain_once()
            if self._closed:
                break
            if made_progress:
                # One check per lane per round gives every task a fair turn while still draining a
                # busy lane without waiting for a timer.  Yield so a newly registered sibling can
                # join the next round before the current lane gets another turn.
                await asyncio.sleep(0)
                continue
            # Always park on the wake event so an empty handle set cannot busy-loop
            # and starve Application.close / supervisor.stop.
            try:
                await asyncio.wait_for(self._wake.wait(), timeout=2.0)
            except TimeoutError:
                pass

    async def _drain_handle_once(self, handle: VerificationDrainHandle) -> bool:
        """Run at most one job for one lane and release idle resources."""

        if self._closed or handle.worker.service_generation != self.service_generation:
            return False
        job = await handle.worker.run_once()
        if job is None:
            key = self._key_for_handle(handle)
            if self._handles.get(key) is handle:
                self.unregister(handle.workspace_commitment, handle.task_id)
                if handle.on_idle is not None:
                    await handle.on_idle()
            return False
        if handle.after_complete is not None:
            await handle.after_complete()
        return True

    async def _drain_once(self) -> bool:
        """Run one fair round across all registered task lanes.

        Previous code drained one workspace until empty before visiting the next.  Since the
        supervisor key was also only the workspace, a sibling task could be both hidden by
        registration and starved by a long queue.  Running one job per lane concurrently keeps
        independent task repositories independent while retaining one serialized worker per lane.
        """

        async with self._lock:
            handles = tuple(self._handles.values())
        if not handles:
            return False
        results = await asyncio.gather(
            *(self._drain_isolated_handle(handle) for handle in handles), return_exceptions=True
        )
        for result in results:
            if isinstance(result, BaseException):
                raise result
        return any(cast(bool, result) for result in results)

    async def _drain_isolated_handle(self, handle: VerificationDrainHandle) -> bool:
        """An ordinary lane failure must not terminate the shared service worker loop."""

        try:
            return await self._drain_handle_once(handle)
        except Exception as exc:
            record_unexpected_exception_without_raising(
                exc, component="application.observation_verification", operation="lane_failed"
            )
            if handle.on_failure is not None:
                try:
                    await handle.on_failure()
                except Exception as callback_error:
                    record_unexpected_exception_without_raising(
                        callback_error,
                        component="application.observation_verification",
                        operation="lane_failure_record_failed",
                    )
            return False


@dataclass
class ObservationVerificationWorker:
    """Run one serialized, generation-fenced durable verification lease at a time."""

    repository: ObservationVerificationRepository
    runner: ApprovedCheckRunner
    workspace_provider: WorkspaceProvider
    policy_provider: PolicyProvider
    capture_subject_state: SubjectDigestProvider
    persist_output: OutputPersister
    service_generation: int
    lease_owner: str
    now: NowProvider
    lease_expires_at: NowProvider
    materialize_result: ApprovedCheckMaterializer | None = None

    def enqueue_if_changed(
        self,
        *,
        workspace: str,
        policy_digest: str,
        approvals: tuple[ApprovedCheckApproval, ...],
        previous_subject_state_digest: str | None,
        subject_state_digest: str,
    ) -> tuple[str, ...]:
        if previous_subject_state_digest == subject_state_digest:
            return ()
        return self.repository.enqueue_latest(
            workspace=workspace,
            policy_digest=policy_digest,
            approvals=tuple(item.approval_commitment for item in approvals),
            subject_state_digest=subject_state_digest,
            enqueued_at=self.now(),
        )

    async def run_once(self) -> ObservationVerificationJob | None:
        job = self.repository.claim_next(
            service_generation=self.service_generation,
            lease_owner=self.lease_owner,
            lease_expires_at=self.lease_expires_at(),
            now=self.now(),
        )
        if job is None:
            return None
        workspace = self.workspace_provider(job.workspace_commitment)
        approvals = self.policy_provider(job.workspace_commitment, job.policy_digest)
        approval = next(
            (item for item in approvals if item.approval_commitment == job.approval_commitment),
            None,
        )
        if approval is None:
            raise RuntimeError("verification_policy_authority_missing")
        captured: list[tuple[bytes, bool]] = []

        def sink(output: bytes, redacted: bool) -> None:
            captured.append((output, redacted))

        original_sink = getattr(self.runner, "_output_sink", None)
        setattr(self.runner, "_output_sink", sink)
        try:
            result, _fact = await asyncio.to_thread(
                run_bound_approved_check,
                runner=self.runner,
                workspace=workspace,
                approval=approval,
                expected_subject_state_digest=job.subject_state_digest,
                capture_subject_state=self.capture_subject_state,
                cursor_event_position=job.state_token,
            )
        finally:
            setattr(self.runner, "_output_sink", original_sink)
        after = self.capture_subject_state(workspace)
        current = after == job.subject_state_digest
        output, output_redacted = captured[-1] if captured else (b"", False)
        output_object_id = (
            await self.persist_output(job, output, output_redacted) if output else None
        )
        recorded_at = self.now()
        if self.materialize_result is not None:
            await self.materialize_result(
                CompletedApprovedCheck(
                    job=job,
                    approval_id=approval.approval_id,
                    result=result,
                    subject_state_after=after,
                    output_object_id=output_object_id,
                    is_current=current,
                    recorded_at=recorded_at,
                    output_redacted=output_redacted,
                )
            )
        self.repository.complete(
            job=job,
            service_generation=self.service_generation,
            lease_owner=self.lease_owner,
            check_id=approval.approval_id,
            result=result,
            subject_state_after=after,
            result_commitment=result.result_digest,
            output_object_id=output_object_id,
            limitations_json=b"[]",
            is_current=current,
            recorded_at=recorded_at,
        )
        return job


def orchestrate_changed_path_inspection(
    *,
    workspace: LocalWorkspaceHandle,
    inspect_port: WorkspaceInspectPort,
    relative_paths: Sequence[str],
    changed_paths_digest: str | None = None,
) -> InspectionOrchestrationResult:
    """Inspect only consented, explicitly selected project-relative paths."""

    paths = tuple(relative_paths)
    if not paths:
        return InspectionOrchestrationResult(None, None, ())
    result = inspect_port.inspect(
        WorkspaceInspectCommand(workspace=workspace, relative_paths=paths)
    )
    if result.status is WorkspaceInspectStatus.REJECTED:
        return InspectionOrchestrationResult(result, None, paths)
    selection = result.selection_digest or "sha256:" + ("0" * 64)
    fact = ObservationInspectFact(
        selection_digest=selection,
        relative_paths=paths,
        changed_paths_digest=changed_paths_digest,
    )
    return InspectionOrchestrationResult(result, fact, paths)


def run_bound_approved_check(
    *,
    runner: ApprovedCheckRunner,
    workspace: LocalWorkspaceHandle,
    approval: ApprovedCheckApproval,
    expected_subject_state_digest: str,
    capture_subject_state: SubjectStateDigestFn,
    cursor_event_position: int,
) -> tuple[ApprovedCheckResult, ObservationCheckFact | None]:
    """Recompute subject state before/after; pre-mismatch is STALE without executing."""

    pre = capture_subject_state(workspace)
    result = runner.run(
        ApprovedCheckCommand(
            workspace=workspace,
            approval=approval,
            subject_state_digest=pre,
            expected_subject_state_digest=expected_subject_state_digest,
        )
    )
    if result.status is ApprovedCheckStatus.STALE:
        return result, None
    post = capture_subject_state(workspace)
    if result.status is ApprovedCheckStatus.PASSED and post != pre:
        # Record success but do not treat as current verification after state drift.
        fact = ObservationCheckFact(
            approval_commitment=approval.approval_commitment,
            subject_state_digest=pre,
            status="passed_not_current",
            cursor_event_position=cursor_event_position,
            is_current=False,
        )
        return result, fact
    if result.status is ApprovedCheckStatus.PASSED and post == pre:
        fact = ObservationCheckFact(
            approval_commitment=approval.approval_commitment,
            subject_state_digest=post,
            status="passed",
            cursor_event_position=cursor_event_position,
            is_current=True,
        )
        return result, fact
    fact = ObservationCheckFact(
        approval_commitment=approval.approval_commitment,
        subject_state_digest=post,
        status=result.status.value,
        cursor_event_position=cursor_event_position,
        is_current=False,
    )
    return result, fact


def check_facts_from_results(
    facts: Mapping[str, ObservationCheckFact],
) -> tuple[ObservationCheckFact, ...]:
    return tuple(facts[key] for key in sorted(facts, key=str.encode))
