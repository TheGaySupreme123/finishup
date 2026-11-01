"""Cross-task observation/check/receipt conformance for one source workspace.

This scenario exercises the production SQLite observation store, SQLite task ledger, approved
check worker, and ready-lifecycle verification supervisor together.  The two task bundles share a
repository commitment but retain independent session cursors, verification rows, advice inputs,
and receipt event graphs.  The check runners synchronize in a thread barrier so a workspace-keyed
supervisor regression fails instead of merely appearing fair in a sequential test.
"""

from __future__ import annotations

import asyncio
import shutil
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import apsw
import pytest

from builders.ledger_adapters import FixedClock, FixedIds, MemoryObjects, ownership_fence
from finishup.adapters.approved_checks import (
    ApprovedCheckApproval,
    ApprovedCheckCommand,
    ApprovedCheckResult,
    ApprovedCheckRunner,
    approval_commitment,
)
from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.adapters.sqlite.migrations import initialize_bundle
from finishup.adapters.sqlite.observation import SqliteObservationStore
from finishup.adapters.sqlite.repository import SqliteLedger
from finishup.adapters.workspace_inspect import open_inspect_workspace
from finishup.application.observation_advice import (
    ObservationAdviceBuildInput,
    build_observation_advice_snapshot,
)
from finishup.application.observation_coordinator import ObservationCoordinator
from finishup.application.observation_verification import (
    CompletedApprovedCheck,
    ObservationVerificationJob,
    ObservationVerificationSupervisor,
    ObservationVerificationWorker,
    VerificationDrainHandle,
)
from finishup.domain.observation import (
    ObservationCursor,
    ObservationEnvelope,
    ObservationGapCode,
    ObservationIngestDisposition,
    ObservationLifecycle,
    ObservationSource,
    ObservationStatusQuery,
)
from finishup.domain.values import JsonObject, Timestamp
from finishup.kernel.policies.observation_advice import (
    ObservationAdviceContext,
    observation_advice_findings,
)
from finishup.ports.check_sandbox import CheckSandboxLaunch, CheckSandboxStatus
from finishup.ports.diagnostics import RuntimeCapability
from finishup.ports.importer import ImporterPort
from finishup.ports.objects import ObjectStorePort
from finishup.ports.runtime import BundleRuntimePort, TaskRuntime
from finishup.protocol.canonical import canonical_digest
from finishup.protocol.ids import IdKind, new_id

pytestmark = pytest.mark.anyio

_WORKSPACE = "hmac-sha256:" + "a" * 64
_TIME = Timestamp("2026-09-05T12:00:00.000Z")
_TRUE = shutil.which("true") or "/usr/bin/true"


class _ConformanceSandbox:
    """Deterministic sandbox seam for the fixed no-network ``true`` command."""

    def prepare(
        self,
        *,
        argv: Sequence[str],
        cwd: Path,
        env: Mapping[str, str],
        deny_network: bool,
    ) -> CheckSandboxLaunch:
        assert deny_network is True
        return CheckSandboxLaunch(
            argv=tuple(argv),
            env=dict(env),
            cwd=cwd,
            status=CheckSandboxStatus.READY,
            network_isolated=True,
        )


class _BarrierRunner(ApprovedCheckRunner):
    """Run the real approved-check runner after both sibling lanes enter."""

    def __init__(
        self,
        approvals: dict[str, ApprovedCheckApproval],
        barrier: threading.Barrier,
        active: list[int],
        maximum: list[int],
        active_lock: threading.Lock,
    ) -> None:
        super().__init__(approvals, sandbox=_ConformanceSandbox())
        self._barrier = barrier
        self._active = active
        self._maximum = maximum
        self._active_lock = active_lock

    def run(self, command: ApprovedCheckCommand) -> ApprovedCheckResult:
        with self._active_lock:
            self._active[0] += 1
            self._maximum[0] = max(self._maximum[0], self._active[0])
        try:
            self._barrier.wait(timeout=2.0)
            return super().run(command)
        finally:
            with self._active_lock:
                self._active[0] -= 1


@dataclass
class _Lane:
    task_id: str
    session_id: str
    writer_id: str
    subject_digest: str
    db: apsw.Connection
    observation: SqliteObservationStore
    ledger: SqliteLedger
    runtime: TaskRuntime


def _lane(root: Path, index: int) -> _Lane:
    task_id = new_id(IdKind.TASK)
    session_id = new_id(IdKind.SESSION)
    writer_id = new_id(IdKind.WRITER)
    digest = "sha256:" + format(index + 1, "064x")
    db = apsw.Connection(str(root / f"task-{index}.sqlite3"))
    initialize_bundle(
        db,
        {
            "task_id": task_id,
            "owner_generation": "1",
            "owner_nonce": "ledger-test-nonce",
        },
    )
    observation = SqliteObservationStore(db)
    observation.grant_consent(_WORKSPACE, _TIME)
    session_commitment = "hmac-sha256:" + format(index + 1, "064x")
    observation.bind_session(_WORKSPACE, session_commitment)
    ids = FixedIds()
    objects = MemoryObjects(ids)
    ledger = SqliteLedger(
        db=db,
        task_id=task_id,
        ownership_fence=ownership_fence(),
        clock=FixedClock(),
        ids=ids,
        objects=objects,
    )
    runtime = TaskRuntime(
        task_id,
        session_id,
        writer_id,
        frozenset(
            {
                RuntimeCapability.STRUCTURAL_READ,
                RuntimeCapability.PAYLOAD_READ,
                RuntimeCapability.WRITE,
            }
        ),
        ledger,
        cast(ObjectStorePort, objects),
        cast(ImporterPort, object()),
        "0.1.0",
        "0.1.0",
        "0.1",
        "1.0.0",
        ownership_fence(),
        observation=observation,
    )
    return _Lane(task_id, session_id, writer_id, digest, db, observation, ledger, runtime)


def _envelope(index: int) -> ObservationEnvelope:
    session_commitment = "hmac-sha256:" + format(index + 1, "064x")
    return ObservationEnvelope(
        session_commitment=session_commitment,
        event_kind="PostToolUse",
        source_identity=f"multi-agent-hook-{index}",
        source=ObservationSource.CODEX_HOOK,
        cursor=ObservationCursor(
            source_generation=1,
            byte_position=index + 1,
            event_position=index + 1,
            last_source_commitment=_WORKSPACE,
            mapping_version="conformance/multi-agent/1",
        ),
        receipt_time=_TIME,
        structural_payload=JsonObject(
            {
                "tool_name": "shell",
                "exit_status": 1 if index == 0 else 0,
                "correlation_id": f"sibling-{index}",
                "event_ordinal": index + 1,
            }
        ),
        content_object_refs=(),
        gap_codes=(ObservationGapCode.UNPAIRED_EVENT.value,) if index == 0 else (),
    )


@pytest.mark.anyio
async def test_two_sibling_tasks_complete_isolated_observe_check_receipt_cycles(
    tmp_path: Path,
) -> None:
    """Two explicit sibling tasks sharing one repository never cross-contaminate evidence."""

    workspace_root = tmp_path / "workspace"
    workspace_root.mkdir()
    lanes = tuple(_lane(tmp_path, index) for index in range(2))
    supervisor = ObservationVerificationSupervisor(service_generation=1)
    done = asyncio.Event()
    completed: list[CompletedApprovedCheck] = []
    active = [0]
    maximum = [0]
    active_lock = threading.Lock()
    barrier = threading.Barrier(2)
    approval_id = "sibling-true"
    approval_digest = approval_commitment(approval_id, (_TRUE,), allow_network=False)
    approval = ApprovedCheckApproval(
        approval_id=approval_id,
        argv=(_TRUE,),
        allow_network=False,
        timeout_seconds=10.0,
        approval_commitment=approval_digest,
    )
    policy_digest = canonical_digest({"policy": "multi-agent-conformance"})

    try:
        ingests = await asyncio.gather(
            *(lane.observation.ingest(_envelope(index)) for index, lane in enumerate(lanes))
        )
        assert all(item.disposition is ObservationIngestDisposition.ACCEPTED for item in ingests)
        for lane in lanes:
            lane.observation.verification_repository().enqueue_latest(
                workspace=_WORKSPACE,
                policy_digest=policy_digest,
                approvals=(approval_digest,),
                subject_state_digest=lane.subject_digest,
                enqueued_at=_TIME.wire,
            )

        for index, lane in enumerate(lanes):
            handle = open_inspect_workspace(workspace_root)
            runner = _BarrierRunner(
                {approval_digest: approval}, barrier, active, maximum, active_lock
            )
            coordinator = ObservationCoordinator(
                runtime=cast(BundleRuntimePort, object()),
                local=LocalObservationStore(_state=tmp_path / f"local-{index}"),
                clock=FixedClock(),
                ids=FixedIds(),
                state_root=tmp_path / f"local-{index}",
            )

            async def _persist(
                _job: ObservationVerificationJob, _content: bytes, _redacted: bool
            ) -> str | None:
                return None

            async def _materialize(
                result: CompletedApprovedCheck,
                *,
                bound_coordinator: ObservationCoordinator = coordinator,
                bound_runtime: TaskRuntime = lane.runtime,
            ) -> None:
                await bound_coordinator._materialize_approved_check(  # pyright: ignore[reportPrivateUsage]
                    bound_runtime, result
                )
                completed.append(result)
                if len(completed) == len(lanes):
                    done.set()

            worker = ObservationVerificationWorker(
                repository=lane.observation.verification_repository(),
                runner=runner,
                workspace_provider=lambda _workspace, bound_handle=handle: bound_handle,
                policy_provider=lambda _workspace, _digest: (approval,),
                capture_subject_state=lambda _handle, digest=lane.subject_digest: digest,
                persist_output=_persist,
                service_generation=1,
                lease_owner=lane.runtime.fence.service_instance_id,
                now=lambda: _TIME.wire,
                lease_expires_at=lambda: "2026-09-05T12:02:00.000Z",
                materialize_result=_materialize,
            )
            assert supervisor.register(
                VerificationDrainHandle(
                    workspace_commitment=_WORKSPACE,
                    worker=worker,
                    task_id=lane.task_id,
                )
            )

        await supervisor.start()
        await asyncio.wait_for(done.wait(), timeout=10.0)
        assert maximum[0] == 2, "sibling checks were serialized by a workspace-only scheduler"
        assert len(completed) == 2

        for index, lane in enumerate(lanes):
            envelopes = tuple(lane.observation.list_envelopes(_WORKSPACE))
            assert len(envelopes) == 1
            assert envelopes[0].session_commitment == "hmac-sha256:" + format(index + 1, "064x")
            assert envelopes[0].gap_codes == (
                (ObservationGapCode.UNPAIRED_EVENT.value,) if index == 0 else ()
            )
            status = await lane.observation.status(ObservationStatusQuery(_WORKSPACE))
            assert status.source_coverage[ObservationSource.CODEX_HOOK] is True

            facts = lane.observation.load_check_facts(_WORKSPACE)
            assert len(facts) == 1
            assert facts[0].subject_state_digest == lane.subject_digest
            assert facts[0].status == "passed"
            assert facts[0].is_current is True
            assert lane.observation.verification_repository().list_pending_workspaces() == ()

            findings = observation_advice_findings(
                ObservationAdviceContext(
                    envelopes=envelopes,
                    lifecycle=ObservationLifecycle.ACTIVE,
                    gaps=envelopes[0].gap_codes,
                    check_facts=facts,
                )
            )
            rules = {item.rule_code for item in findings}
            if index == 0:
                assert "failed_command_unresolved" in rules
            else:
                assert "failed_command_unresolved" not in rules
            snapshot = build_observation_advice_snapshot(
                ObservationAdviceBuildInput(
                    envelopes=envelopes,
                    lifecycle=ObservationLifecycle.ACTIVE,
                    gaps=envelopes[0].gap_codes,
                    check_facts=facts,
                    has_real_observation=True,
                )
            )
            assert (snapshot is not None) is (index == 0)

            records = [record async for record in lane.ledger.load_events(lane.session_id)]
            assert [record.schema.name for record in records] == [
                "action_recorded",
                "evidence_recorded",
                "result_recorded",
            ]
            assert all(record.task_id == lane.task_id for record in records)
            assert all(record.session_id == lane.session_id for record in records)
    finally:
        await supervisor.stop()
        for lane in lanes:
            lane.db.close(force=True)
