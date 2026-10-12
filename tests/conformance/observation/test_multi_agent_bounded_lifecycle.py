"""Bounded multi-agent lifecycle, fairness, and fault-isolation scenarios.

These rows use the isolated READY composition and its encrypted task bundles.  They keep the
maintenance/recovery cycle separate from the scheduler's fair-round assertion so a passing
public task cycle cannot hide a workspace-only scheduling regression.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
from collections.abc import Mapping
from datetime import timedelta
from pathlib import Path
from typing import cast

import pytest

import yoetz.application.start as start_module
from builders.multi_agent import (  # pyright: ignore[reportPrivateUsage]
    MultiAgentService,
    _Paths,  # pyright: ignore[reportPrivateUsage]
    multi_agent_service,
)
from yoetz.adapters.keys.secret_memory import LocalSecretMemory
from yoetz.adapters.objects.encrypted_files import EncryptedFilesObjectStore
from yoetz.application.observation_verification import (
    ObservationVerificationSupervisor,
    ObservationVerificationWorker,
    VerificationDrainHandle,
)
from yoetz.application.publish_work import PublishWorkInternalResult
from yoetz.application.start import StartInternalResult
from yoetz.config.models import YoetzConfig
from yoetz.ports.control import RepositoryPrivacyContext
from yoetz.ports.diagnostics import RuntimeCapability, StartupCheckResult
from yoetz.ports.objects import ObjectKind, ObjectMetadata, ObjectRootSnapshot, ObjectSource
from yoetz.ports.runtime import RouteAccess, RouteCommand
from yoetz.ports.secret_memory import SecretPurpose
from yoetz.ports.start_catalog import TaskRouteState
from yoetz.protocol.errors import PublicErrorCode, PublicOperationError
from yoetz.protocol.ids import IdKind, new_id
from yoetz.protocol.models import (
    CheckRequest,
    PublishWorkRequest,
    ReceiptRequest,
    StartRequest,
    StatusRequest,
)
from yoetz.service.ready_composition import build_ready_application_factory

pytestmark = pytest.mark.anyio

_REPOSITORY = RepositoryPrivacyContext("hmac-sha256:" + "d" * 64, "git_common_root")
_SUPERVISOR_WORKSPACE = "hmac-sha256:" + "e" * 64
_PASSPHRASE = b"synthetic conformance vault only"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class _Diagnostics:
    def record(self, result: StartupCheckResult) -> None:
        assert isinstance(result, StartupCheckResult)


def _identity(actor: str = "harness:bounded-lifecycle") -> dict[str, object]:
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": new_id(IdKind.REQUEST),
        "actor": {"actor_id": actor, "actor_type": "harness"},
        "client": {
            "kind": "cooperative_agent",
            "version": "0.1.0",
            "integration": "cooperative_mcp",
        },
    }


def _workspace(root: Path) -> Path:
    root.mkdir()
    subprocess.run(["git", "init", "--quiet", str(root)], check=True, capture_output=True)
    return root.resolve()


def _frontier(value: object) -> Mapping[str, object]:
    as_wire = getattr(value, "as_wire", None)
    if callable(as_wire):
        return dict(cast(Mapping[str, object], as_wire()).items())
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        return cast(Mapping[str, object], model_dump(mode="json"))
    raise AssertionError("frontier is not serializable")


async def _status(service: MultiAgentService, task: StartInternalResult) -> object:
    return await service.app.status(
        StatusRequest.model_validate(
            {
                **_identity(),
                "session_id": task.session_id,
                "writer_id": task.writer_id,
                "view": "compact",
                "limit": "10",
            }
        ),
        repository_privacy_context=_REPOSITORY,
    )


async def _start_siblings(
    service: MultiAgentService, workspace: Path, count: int
) -> tuple[StartInternalResult, ...]:
    results: list[StartInternalResult] = []
    for index in range(count):
        result = await service.app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create",
                    "task_title": f"Bounded sibling {index}",
                    "workspace_ref": str(workspace),
                    "external_ref": f"bounded-sibling-{index}",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        assert isinstance(result, StartInternalResult)
        results.append(result)
    return tuple(results)


async def _publish_marker(service: MultiAgentService, task: StartInternalResult) -> object:
    current = await _status(service, task)
    result = await service.app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **_identity(),
                "session_id": task.session_id,
                "writer_id": task.writer_id,
                "expected_frontier": _frontier(getattr(current, "head_frontier")),
                "event_drafts": [
                    {
                        "event_id": new_id(IdKind.EVENT),
                        "schema": {"name": "action_recorded", "version": "1.0.0"},
                        "occurred_at": "2026-09-05T12:00:00.000Z",
                        "causal_parents": [],
                        "payload": {
                            "action_id": new_id(IdKind.ACTION),
                            "action_kind": "review",
                            "description": f"bounded-marker-{task.task_id}",
                        },
                        "artifact_refs": [],
                        "evidence_refs": [],
                    }
                ],
            }
        ),
        repository_privacy_context=_REPOSITORY,
    )
    assert isinstance(result, PublishWorkInternalResult)
    return result


async def _check(service: MultiAgentService, task: StartInternalResult) -> object:
    current = await _status(service, task)
    return await service.app.check(
        CheckRequest.model_validate(
            {
                **_identity(),
                "session_id": task.session_id,
                "writer_id": task.writer_id,
                "expected_frontier": _frontier(getattr(current, "head_frontier")),
                "mode": "deterministic_only",
                "max_findings": "10",
                "policy_packs": ["research-evidence/0.2.0", "work-integrity/0.3.0"],
            }
        ),
        repository_privacy_context=_REPOSITORY,
    )


async def _receipt(
    service: MultiAgentService,
    task: StartInternalResult,
    checked: object,
    *,
    request_id: str | None = None,
) -> object:
    identity = _identity()
    if request_id is not None:
        identity["request_id"] = request_id
    return await service.app.receipt(
        ReceiptRequest.model_validate(
            {
                **identity,
                "task_id": task.task_id,
                "session_id": task.session_id,
                "writer_id": task.writer_id,
                "expected_frontier": _frontier(getattr(checked, "result_frontier")),
                "format": "json",
                "include": "standard",
                "redaction_profile": "default_local_export",
            }
        ),
        repository_privacy_context=_REPOSITORY,
    )


async def _relock_and_reopen(service: MultiAgentService) -> LocalSecretMemory:
    """Close and recompose the real READY factory around the same encrypted installation."""

    await service.app.close()
    await service.vault.lock()
    memory = LocalSecretMemory()
    try:
        await service.vault.unlock(
            memory.capture(SecretPurpose.VAULT_UNLOCK, bytearray(_PASSPHRASE))
        )
        factory = build_ready_application_factory(
            lifecycle=service.lifecycle,
            vault=service.vault,
            config=YoetzConfig(),
            paths=_Paths(service.root),
            clock=service.clock,
            secret_memory=memory,
            diagnostics=_Diagnostics(),
        )
        service.app = await factory(1, service.vault.generation)
    except BaseException:
        memory.close()
        raise
    return memory


async def _create_unreferenced_object(service: MultiAgentService, task: StartInternalResult) -> str:
    """Create a real bundle object without a ledger reference for the GC seam."""

    runtime = await service.app.runtime.route(
        RouteCommand(
            session_id=task.session_id,
            writer_id=task.writer_id,
            access=RouteAccess.WRITE,
            required_capabilities=frozenset(
                {
                    RuntimeCapability.STRUCTURAL_READ,
                    RuntimeCapability.PAYLOAD_READ,
                    RuntimeCapability.WRITE,
                }
            ),
        )
    )
    try:
        metadata = ObjectMetadata(
            ObjectKind.CAPTURED_CONTENT,
            "application/octet-stream",
            task.task_id,
            service.clock.now_utc(),
        )
        staged = await runtime.objects.stage(ObjectSource(data=b"aged-gc-orphan"), metadata)
        reference = await runtime.objects.finalize(staged)
        # The production file-store sweep uses filesystem mtime as its retention clock.  Keep
        # this orphan deterministically older than the 24-hour retention window using the same
        # injected clock as the object metadata; waiting would make the lifecycle test flaky.
        store = cast(EncryptedFilesObjectStore, runtime.objects)
        aged_at = service.clock.now_utc() - timedelta(days=2)
        timestamp = aged_at.timestamp()
        os.utime(store._path_for(reference.object_id), (timestamp, timestamp))  # pyright: ignore[reportPrivateUsage]
        return reference.object_id
    finally:
        await service.app.runtime.release(runtime)


async def _sweep_unreferenced_object(
    service: MultiAgentService, task: StartInternalResult, expected_orphan_id: str
) -> int:
    """Run the production object-port sweep against the authenticated task root snapshot."""

    runtime = await service.app.runtime.route(
        RouteCommand(
            session_id=task.session_id,
            writer_id=task.writer_id,
            access=RouteAccess.WRITE,
            required_capabilities=frozenset(
                {
                    RuntimeCapability.STRUCTURAL_READ,
                    RuntimeCapability.PAYLOAD_READ,
                    RuntimeCapability.WRITE,
                }
            ),
        )
    )
    try:
        store = cast(EncryptedFilesObjectStore, runtime.objects)
        snapshot = await store._current_root_snapshot()  # pyright: ignore[reportPrivateUsage]
        assert isinstance(snapshot, ObjectRootSnapshot)
        assert expected_orphan_id not in snapshot.live_object_ids
        orphan_path = store._path_for(expected_orphan_id)  # pyright: ignore[reportPrivateUsage]
        removed = await runtime.objects.sweep_orphans(
            snapshot,
            service.clock.now_utc() + timedelta(days=4),
        )
        assert not orphan_path.exists()
        return removed
    finally:
        await service.app.runtime.release(runtime)


class _BoundedLane:
    def __init__(
        self,
        task_id: str,
        jobs: int,
        first_round: list[tuple[int, str]],
        finished: set[str],
        done: asyncio.Event,
    ) -> None:
        self.task_id = task_id
        self.jobs = jobs
        self.first_round = first_round
        self.finished = finished
        self.done = done
        self.service_generation = 1
        self.calls = 0
        self.expected_task_ids: frozenset[str] = frozenset()

    async def run_once(self) -> object | None:
        self.calls += 1
        if self.calls <= self.jobs:
            self.first_round.append((self.calls, self.task_id))
            return object()
        if self.calls == self.jobs + 1:
            self.finished.add(self.task_id)
            if len(self.finished) == len(self.expected_task_ids):
                self.done.set()
        return None


@pytest.mark.anyio
async def test_three_live_siblings_survive_maintenance_relock_and_gc(
    tmp_path: Path,
) -> None:
    """Three real task lanes retain independent state through maintenance and a vault relock."""

    workspace = _workspace(tmp_path / "workspace")
    async with multi_agent_service(tmp_path / "state") as service:
        siblings = await _start_siblings(service, workspace, 3)
        assert len({task.task_id for task in siblings}) == 3
        assert len({task.session_id for task in siblings}) == 3

        checks: dict[str, object] = {}
        receipt_request_ids: dict[str, str] = {}
        receipts: dict[str, object] = {}
        for task in siblings:
            await _publish_marker(service, task)
            checked = await _check(service, task)
            request_id = new_id(IdKind.REQUEST)
            receipt = await _receipt(service, task, checked, request_id=request_id)
            checks[task.task_id] = checked
            receipt_request_ids[task.task_id] = request_id
            receipts[task.task_id] = receipt
            assert getattr(checked, "task_id") == task.task_id
            assert getattr(receipt, "task_id") == task.task_id

        orphan_object_id = await _create_unreferenced_object(service, siblings[0])
        memory = await _relock_and_reopen(service)
        try:
            # These are the service-owned bounded maintenance paths.  They must iterate all
            # active routes while ignoring no task merely because a sibling shares its workspace.
            await service.app.recover_lineage()
            observation_sweep = service.app.observation_sweep
            assert observation_sweep is not None
            assert await observation_sweep() is not None
            coordination_sweep = service.app.coordination_sweep
            assert coordination_sweep is not None
            await coordination_sweep()

            # Advance the injected clock without crossing the short task-session lease.  Recovery
            # still replays all three route/object roots, which is the GC-root verification seam.
            service.clock.advance(seconds=5)
            (
                active_routes,
                _replayed_events,
                verified_objects,
            ) = await service.app.verify_recovery_candidate()
            assert active_routes == 3
            assert verified_objects >= 3
            # The object-port sweep is a real retention operation: the unreferenced aged object
            # is removed, while the receipt replay below proves rooted objects remain available.
            assert await _sweep_unreferenced_object(service, siblings[0], orphan_object_id) >= 1

            for task in siblings:
                status = await _status(service, task)
                assert getattr(status, "task_id") == task.task_id
                replayed = await _receipt(
                    service,
                    task,
                    checks[task.task_id],
                    request_id=receipt_request_ids[task.task_id],
                )
                assert getattr(replayed, "receipt_digest") == getattr(
                    receipts[task.task_id], "receipt_digest"
                )
        finally:
            memory.close()


@pytest.mark.anyio
async def test_quarantined_sibling_leaves_public_cycles_for_other_tasks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A real start-route quarantine does not poison the remaining sibling lanes."""

    workspace = _workspace(tmp_path / "workspace")
    async with multi_agent_service(tmp_path / "state") as service:
        healthy = await _start_siblings(service, workspace, 2)
        bad_request = StartRequest.model_validate(
            {
                **_identity(),
                "mode": "create",
                "task_title": "Injected quarantine sibling",
                "workspace_ref": str(workspace),
                "external_ref": "quarantine-sibling",
                "requested_view": "compact",
            }
        )
        quarantined_task_ids: list[str] = []

        async def fail_result_builder(*args: object, **kwargs: object) -> object:
            del kwargs
            allocation = args[2]
            quarantined_task_ids.append(cast(str, getattr(allocation, "task_id")))
            raise start_module._StartContradiction(  # pyright: ignore[reportPrivateUsage]
                "start_result_object_missing"
            )

        monkeypatch.setattr(start_module, "_build_result", fail_result_builder)
        with pytest.raises(PublicOperationError) as failure:
            await service.app.start(bad_request, repository_privacy_context=_REPOSITORY)
        assert failure.value.code is PublicErrorCode.STORAGE_CORRUPT
        assert failure.value.retryable is False
        assert failure.value.safe_details == {}
        assert len(quarantined_task_ids) == 1
        quarantined = await service.app.start_catalog.task_route(quarantined_task_ids[0])
        assert quarantined is not None
        assert quarantined.state is TaskRouteState.QUARANTINED

        # The same production recovery and observation sweeps walk around the quarantined route.
        await service.app.recover_lineage()
        observation_sweep = service.app.observation_sweep
        assert observation_sweep is not None
        assert await observation_sweep() is not None
        (
            active_routes,
            _replayed_events,
            verified_objects,
        ) = await service.app.verify_recovery_candidate()
        assert active_routes == 2
        assert verified_objects >= 2

        for task in healthy:
            await _publish_marker(service, task)
            checked = await _check(service, task)
            receipt = await _receipt(service, task, checked)
            assert getattr(checked, "task_id") == task.task_id
            assert getattr(receipt, "task_id") == task.task_id


@pytest.mark.anyio
async def test_ready_supervisor_fairness_has_bounded_work_per_live_task(
    tmp_path: Path,
) -> None:
    """Every live task receives one scheduler turn per round with a fixed probe bound."""

    workspace = _workspace(tmp_path / "workspace")
    async with multi_agent_service(tmp_path / "state") as service:
        tasks = await _start_siblings(service, workspace, 4)
        supervisor = service.app.verification_supervisor
        assert isinstance(supervisor, ObservationVerificationSupervisor)
        first_round: list[tuple[int, str]] = []
        finished: set[str] = set()
        done = asyncio.Event()
        lanes = tuple(
            _BoundedLane(
                task_id=task.task_id,
                jobs=3,
                first_round=first_round,
                finished=finished,
                done=done,
            )
            for task in tasks
        )
        task_ids = frozenset(task.task_id for task in tasks)
        for lane in lanes:
            lane.expected_task_ids = task_ids
            assert supervisor.register(
                VerificationDrainHandle(
                    workspace_commitment=_SUPERVISOR_WORKSPACE,
                    task_id=lane.task_id,
                    worker=cast(ObservationVerificationWorker, lane),
                )
            )
        supervisor.notify(_SUPERVISOR_WORKSPACE)
        await asyncio.wait_for(done.wait(), timeout=5.0)

        assert len(first_round) == len(tasks) * 3
        for round_number in range(1, 4):
            assert {
                task_id for observed_round, task_id in first_round if observed_round == round_number
            } == task_ids
        assert {lane.calls for lane in lanes} == {4}
        assert sum(lane.calls for lane in lanes) == len(tasks) * 4

        # The same four public routes remain usable after the bounded worker drain.
        for task in tasks:
            checked = await _check(service, task)
            receipt = await _receipt(service, task, checked)
            assert getattr(receipt, "task_id") == task.task_id
