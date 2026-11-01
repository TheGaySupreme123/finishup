"""Composed project-coordination recovery and reversal acceptance cases.

These tests deliberately exercise the READY application and durable coordination adapter.  The
unit detector tests cover identity math; this matrix keeps the ledger append, project generation,
delivery rows, and public check path in one isolated service.
"""

from __future__ import annotations

import subprocess
from collections.abc import AsyncGenerator, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import pytest

from builders.multi_agent import (
    MultiAgentService,
    ScenarioClock,
    multi_agent_service,
    private_service_root,
)
from finishup.adapters.keys.encrypted_vault import EncryptedVaultStore
from finishup.adapters.keys.secret_memory import LocalSecretMemory
from finishup.adapters.keys.vault_passphrase import VaultRootEnvelope
from finishup.adapters.repository_identity import resolve_repository_privacy_context
from finishup.application.coordination import (
    CoordinationAdvice,
    CoordinationContextWriter,
    CoordinationDetection,
    CoordinationParticipant,
    CoordinationRuntime,
)
from finishup.application.projects import (
    LinkProjectCommand,
    ProjectCommandError,
    ProjectDissolveCommand,
    ProjectRevokeCommand,
)
from finishup.application.publish_work import PublishWorkInternalResult
from finishup.application.service import Application
from finishup.application.start import StartInternalResult
from finishup.application.status import StatusInternalResult
from finishup.config.models import FinishUpConfig
from finishup.domain.coordination import CoordinationErrorCode, MemberKind
from finishup.domain.findings import FindingKind
from finishup.domain.values import JsonObject
from finishup.ports.control import RepositoryPrivacyContext, ServiceState, WorkspaceLocator
from finishup.ports.diagnostics import RuntimeCapability
from finishup.ports.keys import MacKeyPurpose
from finishup.ports.ledger import CheckCommitResult
from finishup.ports.runtime import RouteAccess, RouteCommand
from finishup.ports.secret_memory import SecretPurpose
from finishup.protocol.ids import IdKind, new_id
from finishup.protocol.models import (
    CheckRequest,
    PublishWorkRequest,
    ReceiptRequest,
    StartRequest,
    StatusProjectPageModel,
    StatusRequest,
)
from finishup.service.elevated_bootstrap import (
    load_pending,
    record_project_coordination_authorization,
)
from finishup.service.lifecycle import ServiceLifecycle
from finishup.service.ready_composition import build_ready_application_factory
from finishup.service.vault import VaultMode, VaultService

pytestmark = pytest.mark.anyio

_REPOSITORY = RepositoryPrivacyContext("hmac-sha256:" + "d" * 64, "git_common_root")
_PASSPHRASE = b"synthetic project recovery matrix vault"
_INSTALLATION_ID = "ins_69000000-0000-4000-8000-000000000001"
_INSTANCE_ID = "svc_69000000-0000-4000-8000-000000000002"


class _Generations:
    def __init__(self) -> None:
        self.current = 0

    def advance(self, instance_id: str) -> int:
        assert instance_id == _INSTANCE_ID
        self.current += 1
        return self.current


@dataclass(frozen=True)
class _Paths:
    bundle: Path

    @property
    def state(self) -> Path:
        return self.bundle / "state"


class _Diagnostics:
    def record(self, result: object) -> None:
        del result


@dataclass
class _Running:
    app: Application
    clock: ScenarioClock
    lifecycle: ServiceLifecycle
    vault: VaultService
    memory: LocalSecretMemory
    generation: int


class _RestartableReadyInstallation:
    """Small isolated READY composition that can be closed and reopened in one test."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.clock = ScenarioClock()
        self.generations = _Generations()
        self.running: _Running | None = None
        self._root_envelope: VaultRootEnvelope | None = None

    async def open(self) -> _Running:
        if self.running is not None:
            raise AssertionError("ready_installation_already_open")
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.root.chmod(0o700)
        memory = LocalSecretMemory()
        lifecycle = ServiceLifecycle(
            self.clock,
            generation_store=self.generations,
            process_start_identity_commitment="sha256:" + "a" * 64,
            instance_id=_INSTANCE_ID,
            singleton_lock_path=self.root / "service.lock",
        )
        await lifecycle.acquire_singleton()
        await lifecycle.transition(ServiceState.LOCKED)
        if self._root_envelope is None:
            vault = VaultService(
                installation_id=_INSTALLATION_ID,
                service_generation=1,
                mode=VaultMode.UNINITIALIZED,
                secret_memory=memory,
                clock=self.clock,
                vault_store_factory=lambda: EncryptedVaultStore(self.root / "vault"),
                pristine_state_digest="sha256:" + "b" * 64,
            )
            await vault.initialize_passphrase(
                memory.capture(SecretPurpose.VAULT_INITIALIZE, bytearray(_PASSPHRASE)),
                "sha256:" + "c" * 64,
            )
            self._root_envelope = cast(VaultRootEnvelope, getattr(vault, "_root_envelope"))
        else:
            vault = VaultService(
                installation_id=_INSTALLATION_ID,
                service_generation=lifecycle.instance.generation,
                mode=VaultMode.PASSPHRASE,
                secret_memory=memory,
                clock=self.clock,
                vault_store_factory=lambda: EncryptedVaultStore(self.root / "vault"),
                root_envelope=self._root_envelope,
            )
            await vault.unlock(memory.capture(SecretPurpose.VAULT_UNLOCK, bytearray(_PASSPHRASE)))
        generation = lifecycle.instance.generation
        factory = build_ready_application_factory(
            lifecycle=lifecycle,
            vault=vault,
            config=FinishUpConfig(),
            paths=_Paths(self.root),
            clock=self.clock,
            secret_memory=memory,
            diagnostics=_Diagnostics(),
        )
        app = await factory(generation, vault.generation)
        await lifecycle.transition(ServiceState.UNLOCKING)
        await lifecycle.transition(ServiceState.READY, vault_generation=vault.generation)
        self.running = _Running(app, self.clock, lifecycle, vault, memory, generation)
        return self.running

    async def close(self) -> None:
        current = self.running
        if current is None:
            return
        self._root_envelope = cast(VaultRootEnvelope, getattr(current.vault, "_root_envelope"))
        self.running = None
        await current.app.close()
        await current.vault.close()
        current.memory.close()
        await current.lifecycle.close()

    async def restart(self) -> _Running:
        await self.close()
        return await self.open()


@asynccontextmanager
async def _installation(root: Path) -> AsyncGenerator[_RestartableReadyInstallation]:
    del root  # pytest's basetemp is shared /tmp; the synthetic installation needs a private root.
    with private_service_root() as private_root:
        installation = _RestartableReadyInstallation(private_root)
        await installation.open()
        try:
            yield installation
        finally:
            await installation.close()


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _identity() -> dict[str, object]:
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": new_id(IdKind.REQUEST),
        "actor": {"actor_id": "harness:project-recovery-matrix", "actor_type": "harness"},
        "client": {
            "kind": "cooperative_agent",
            "version": "0.1.0",
            "integration": "cooperative_mcp",
        },
    }


def _event(name: str, payload: Mapping[str, object]) -> dict[str, object]:
    return {
        "event_id": new_id(IdKind.EVENT),
        "schema": {"name": name, "version": "1.0.0"},
        "occurred_at": "2026-09-06T12:00:00.000Z",
        "causal_parents": (),
        "payload": dict(payload),
        "artifact_refs": (),
        "evidence_refs": (),
    }


def _frontier(value: object) -> Mapping[str, object]:
    as_wire = getattr(value, "as_wire", None)
    if callable(as_wire):
        return dict(cast(Mapping[str, object], as_wire()).items())
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        return dict(cast(Mapping[str, object], model_dump(mode="json")).items())
    raise AssertionError("frontier_not_serializable")


async def _status(
    service: MultiAgentService,
    task: StartInternalResult,
    *,
    repository_privacy_context: RepositoryPrivacyContext = _REPOSITORY,
) -> StatusInternalResult:
    result = await service.app.status(
        StatusRequest.model_validate(
            {
                **_identity(),
                "session_id": task.session_id,
                "writer_id": task.writer_id,
                "view": "compact",
                "limit": "10",
            }
        ),
        repository_privacy_context=repository_privacy_context,
    )
    assert isinstance(result, StatusInternalResult)
    return result


async def _publish(
    service: MultiAgentService,
    task: StartInternalResult,
    drafts: Sequence[Mapping[str, object]],
    *,
    repository_privacy_context: RepositoryPrivacyContext = _REPOSITORY,
) -> PublishWorkInternalResult:
    status = await _status(service, task, repository_privacy_context=repository_privacy_context)
    result = await service.app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **_identity(),
                "session_id": task.session_id,
                "writer_id": task.writer_id,
                "expected_frontier": _frontier(status.head_frontier),
                "event_drafts": tuple(dict(item) for item in drafts),
            }
        ),
        repository_privacy_context=repository_privacy_context,
    )
    assert isinstance(result, PublishWorkInternalResult)
    return result


async def _check(service: MultiAgentService, task: StartInternalResult) -> CheckCommitResult:
    status = await _status(service, task)
    result = await service.app.check(
        CheckRequest.model_validate(
            {
                **_identity(),
                "session_id": task.session_id,
                "writer_id": task.writer_id,
                "expected_frontier": _frontier(status.head_frontier),
                "mode": "deterministic_only",
                "max_findings": "10",
            }
        ),
        repository_privacy_context=_REPOSITORY,
    )
    assert isinstance(result, CheckCommitResult)
    return result


async def _check_application(app: Application, task: StartInternalResult) -> CheckCommitResult:
    status = await _status_application(app, task)
    result = await app.check(
        CheckRequest.model_validate(
            {
                **_identity(),
                "session_id": task.session_id,
                "writer_id": task.writer_id,
                "expected_frontier": _frontier(status.head_frontier),
                "mode": "deterministic_only",
                "max_findings": "10",
            }
        ),
        repository_privacy_context=_REPOSITORY,
    )
    assert isinstance(result, CheckCommitResult)
    return result


async def _receipt_application(
    app: Application,
    task: StartInternalResult,
    checked: CheckCommitResult,
    *,
    request_id: str | None = None,
) -> object:
    identity = _identity()
    if request_id is not None:
        identity["request_id"] = request_id
    return await app.receipt(
        ReceiptRequest.model_validate(
            {
                **identity,
                "task_id": task.task_id,
                "session_id": task.session_id,
                "writer_id": task.writer_id,
                "expected_frontier": _frontier(checked.result_frontier),
                "format": "json",
                "include": "standard",
                "redaction_profile": "default_local_export",
            }
        ),
        repository_privacy_context=_REPOSITORY,
    )


async def _delegate_and_attach(
    app: Application, parent: StartInternalResult, title: str
) -> StartInternalResult:
    delegated = await app.start(
        StartRequest.model_validate(
            {
                **_identity(),
                "mode": "delegate",
                "task_title": title,
                "session_id": parent.session_id,
                "requested_view": "compact",
            }
        ),
        repository_privacy_context=_REPOSITORY,
    )
    handle = delegated.as_wire().get("attach_handle")
    assert isinstance(handle, Mapping)
    attached = await app.start(
        StartRequest.model_validate(
            {
                **_identity(),
                "mode": "attach",
                "task_title": title,
                "attach_handle": dict(handle),
                "requested_view": "compact",
            }
        ),
        repository_privacy_context=_REPOSITORY,
    )
    assert attached.task_id == delegated.task_id
    assert attached.parent_task_id == parent.task_id
    return attached


async def _start_pair_application(
    app: Application, workspace: Path
) -> tuple[StartInternalResult, ...]:
    tasks = tuple(
        [
            await app.start(
                StartRequest.model_validate(
                    {
                        **_identity(),
                        "mode": "create",
                        "task_title": f"Recovery matrix sibling {index}",
                        "workspace_ref": str(workspace),
                        "external_ref": f"recovery-matrix-{index}",
                        "requested_view": "compact",
                    }
                ),
                repository_privacy_context=_REPOSITORY,
            )
            for index in range(2)
        ]
    )
    return tasks


async def _start_pair(
    service: MultiAgentService, workspace: Path
) -> tuple[StartInternalResult, ...]:
    tasks = await _start_pair_application(service.app, workspace)
    observation = service.root / "state"
    from finishup.adapters.integrations.observation_local import LocalObservationStore

    store = LocalObservationStore(_state=observation)
    store.grant_consent(store.workspace_commitment(str(workspace)))
    return tasks


async def _status_application(app: Application, task: StartInternalResult) -> StatusInternalResult:
    result = await app.status(
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
    assert isinstance(result, StatusInternalResult)
    return result


async def _publish_application(
    app: Application,
    task: StartInternalResult,
    drafts: Sequence[Mapping[str, object]],
) -> PublishWorkInternalResult:
    status = await _status_application(app, task)
    result = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **_identity(),
                "session_id": task.session_id,
                "writer_id": task.writer_id,
                "expected_frontier": _frontier(status.head_frontier),
                "event_drafts": tuple(dict(item) for item in drafts),
            }
        ),
        repository_privacy_context=_REPOSITORY,
    )
    assert isinstance(result, PublishWorkInternalResult)
    return result


async def _coordination_context_count(app: Application, task: StartInternalResult) -> int:
    route = await app.start_catalog.task_route(task.task_id)
    assert route is not None
    runtime = await app.runtime.route(
        RouteCommand(
            route.session_id,
            None,
            RouteAccess.STRUCTURAL_READ,
            frozenset({RuntimeCapability.STRUCTURAL_READ}),
        )
    )
    try:
        names: list[str] = []
        async for record in runtime.ledger.load_events(runtime.session_id):
            names.append(record.schema.name)
        return names.count("coordination_context_recorded")
    finally:
        await app.runtime.release(runtime)


async def _grant_general_project(
    service: MultiAgentService, project_id: str, generation: int
) -> None:
    body = JsonObject(
        {
            "schema_version": "1.0.0",
            "operation": "grant",
            "request_id": new_id(IdKind.REQUEST),
            "project_id": project_id,
            "membership_generation": generation,
        }
    )
    try:
        await service.app.project(body, repository_privacy_context=_REPOSITORY)
    except Exception:
        pending = load_pending(_state=service.root / "state")
        assert pending is not None and pending.coordination_binding is not None
        audit = pending.coordination_binding["audit_record_id"]
        assert isinstance(audit, str)
        record_project_coordination_authorization(pending, _state=service.root / "state")
        # The durable operation owns the approved audit identity; retry the exact request.
    granted = await service.app.project(body, repository_privacy_context=_REPOSITORY)
    assert granted["state"] == "active"


async def _create_granted_general_project(
    service: MultiAgentService,
    tasks: tuple[StartInternalResult, ...],
) -> tuple[str, int]:
    created = await service.app.project(
        JsonObject(
            {
                "schema_version": "1.0.0",
                "operation": "create",
                "request_id": new_id(IdKind.REQUEST),
                "title": "Recovery matrix general project",
                "owner_task_id": tasks[0].task_id,
            }
        ),
        repository_privacy_context=_REPOSITORY,
    )
    project = created["project_id"]
    assert isinstance(project, str)
    await _grant_general_project(service, project, 1)
    for task in tasks:
        provenance = await service.app.start_catalog.task_source_provenance(task.task_id)
        assert provenance is not None and provenance.workspace_ref_commitment is not None
        linked = await service.app.project(
            JsonObject(
                {
                    "schema_version": "1.0.0",
                    "operation": "link",
                    "request_id": new_id(IdKind.REQUEST),
                    "project_id": project,
                    "member_kind": "task",
                    "member_commitment_or_id": task.task_id,
                    "source_workspace_commitment": provenance.workspace_ref_commitment,
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        assert linked["member_commitment_or_id"] == task.task_id
        state = await service.app.start_catalog.project_state(project)
        assert state is not None
        await _grant_general_project(service, project, state.membership_generation)
    state = await service.app.start_catalog.project_state(project)
    assert state is not None
    return project, state.membership_generation


async def test_public_structured_plan_overlap_declaration_disposition_and_recheck(
    tmp_path: Path,
) -> None:
    workspace = (tmp_path / "workspace").resolve()
    workspace.mkdir()
    subprocess.run(["git", "init", "--quiet", str(workspace)], check=True, capture_output=True)

    async with multi_agent_service(tmp_path / "state") as service:
        tasks = await _start_pair(service, workspace)
        obligation_ids = [new_id(IdKind.OBLIGATION) for _ in tasks]
        shared_plan_key = new_id(IdKind.OBLIGATION)
        for index, (task, obligation_id) in enumerate(zip(tasks, obligation_ids, strict=True)):
            await _publish(
                service,
                task,
                (
                    _event(
                        "plan_published",
                        {
                            "plan_version": 1,
                            "summary": "Coordinate the shared plan item.",
                            "obligation_refs": (shared_plan_key,),
                        },
                    ),
                    _event(
                        "obligation_published",
                        {
                            "obligation_id": obligation_id,
                            "description": "Record the coordination decision.",
                            "evidence_expectation": "A typed disposition is recorded.",
                            "status": "open",
                            "requested_items": (
                                {"item_kind": "file", "value": f"src/independent-{index}.py"},
                            ),
                        },
                    ),
                ),
            )

        project_ids = await service.app.start_catalog.list_task_project_ids(tasks[0].task_id)
        assert len(project_ids) == 1
        project = project_ids[0]
        project_application = service.app.project_application
        assert project_application is not None
        runtime = cast(CoordinationRuntime, getattr(project_application, "coordination_runtime"))
        detections = await runtime.detector.store.list_detections(project)
        assert len(detections) == 1
        detection = detections[0]
        assert detection.overlap_kind.value == "plan"
        assert detection.resource_identities

        await _publish(
            service,
            tasks[0],
            (
                _event(
                    "coordination_obligation_declared",
                    {
                        "detection_id": detection.detection_id,
                        "project_id": project,
                        "membership_generation": str(detection.membership_generation),
                        "recipient_task_id": tasks[0].task_id,
                        "obligation_id": obligation_ids[0],
                    },
                ),
            ),
        )
        finding_check = await _check(service, tasks[0])
        assert any(item.kind is FindingKind.COORDINATION_OVERLAP for item in finding_check.findings)

        evidence_id = new_id(IdKind.EVIDENCE)
        await _publish(
            service,
            tasks[0],
            (
                _event(
                    "evidence_recorded",
                    {
                        "evidence_id": evidence_id,
                        "evidence_kind": "test_result",
                        "strength": "content_digest",
                        "content_digest": "sha256:" + "a" * 64,
                        "observed_at": "2026-09-06T12:00:01.000Z",
                        "description": "The plan decision was recorded.",
                    },
                ),
            ),
        )
        await _publish(
            service,
            tasks[0],
            (
                _event(
                    "coordination_disposition_recorded",
                    {
                        "detection_id": detection.detection_id,
                        "project_id": project,
                        "membership_generation": str(detection.membership_generation),
                        "recipient_task_id": tasks[0].task_id,
                        "obligation_id": obligation_ids[0],
                        "disposition": "shared_work",
                        "evidence_refs": (evidence_id,),
                    },
                ),
            ),
        )
        resolved = await _check(service, tasks[0])
        assert not any(item.kind is FindingKind.COORDINATION_OVERLAP for item in resolved.findings)
        receipt = await service.app.receipt(
            ReceiptRequest.model_validate(
                {
                    **_identity(),
                    "task_id": tasks[0].task_id,
                    "session_id": tasks[0].session_id,
                    "writer_id": tasks[0].writer_id,
                    "expected_frontier": _frontier(resolved.result_frontier),
                    "format": "markdown",
                    "include": "standard",
                    "redaction_profile": "full_local",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        assert receipt.human_text is not None


async def test_public_queued_generation_revocation_records_refusal_without_advice(
    tmp_path: Path,
) -> None:
    """A revoke between durable queueing and delivery leaves two refused terminal rows."""

    workspace = (tmp_path / "workspace").resolve()
    workspace.mkdir()
    subprocess.run(["git", "init", "--quiet", str(workspace)], check=True, capture_output=True)

    async with multi_agent_service(tmp_path / "state") as service:
        tasks = await _start_pair(service, workspace)
        project, generation = await _create_granted_general_project(service, tasks)
        project_application = service.app.project_application
        assert project_application is not None
        runtime = cast(CoordinationRuntime, getattr(project_application, "coordination_runtime"))
        inputs = {
            task.task_id: await runtime.inputs.input_for(
                task.task_id, project, resources=("src/shared.py",)
            )
            for task in tasks
        }
        selected = {task_id: value for task_id, value in inputs.items() if value is not None}
        assert len(selected) == 2
        original_put_participants = runtime.detector.store.put_participants
        revoked = False

        async def revoke_after_queue(
            detection_id: str,
            participants: tuple[CoordinationParticipant, CoordinationParticipant],
        ) -> None:
            nonlocal revoked
            await original_put_participants(detection_id, participants)
            if not revoked:
                revoked = True
                await project_application.revoke(ProjectRevokeCommand(project, generation))

        runtime.detector.store.put_participants = revoke_after_queue  # type: ignore[method-assign]
        assert (
            await runtime.sweep(
                project_id_value=project,
                inputs=selected,
                expected_generation=generation,
            )
            == ()
        )
        deliveries = await runtime.detector.store.deliveries(
            (await runtime.detector.store.list_detections(project))[0].detection_id
        )
        assert len(deliveries) == 2
        assert {item.outcome for item in deliveries} == {"refused"}
        assert {item.reason_code for item in deliveries} == {"coordination_generation_revoked"}
        assert (
            await runtime.detector.store.advice_for(
                (await runtime.detector.store.list_detections(project))[0].detection_id,
                tasks[0].task_id,
            )
            is None
        )


async def test_public_crash_after_first_ledger_delivery_restarts_and_redelivers_exact_pair(
    tmp_path: Path,
) -> None:
    workspace = (tmp_path / "workspace").resolve()
    workspace.mkdir()
    subprocess.run(["git", "init", "--quiet", str(workspace)], check=True, capture_output=True)

    async with _installation(tmp_path / "installation") as installation:
        first = installation.running
        assert first is not None
        tasks = await _start_pair_application(first.app, workspace)
        from finishup.adapters.integrations.observation_local import LocalObservationStore

        observation = LocalObservationStore(_state=installation.root / "state")
        observation.grant_consent(observation.workspace_commitment(str(workspace)))
        project_ids = await first.app.start_catalog.list_task_project_ids(tasks[0].task_id)
        assert len(project_ids) == 1
        project = project_ids[0]
        project_application = first.app.project_application
        assert project_application is not None
        runtime = cast(CoordinationRuntime, getattr(project_application, "coordination_runtime"))
        writer = runtime.detector.context_writer
        assert writer is not None

        class _CrashAfterFirst:
            def __init__(self, delegate: CoordinationContextWriter) -> None:
                self.delegate = delegate
                self.calls = 0
                self.first_recipient: str | None = None

            async def record_context(
                self,
                detection: CoordinationDetection,
                recipient: CoordinationParticipant,
                source: CoordinationParticipant,
            ) -> str:
                result = await self.delegate.record_context(detection, recipient, source)
                self.calls += 1
                self.first_recipient = recipient.task_id
                if self.calls == 1:
                    raise RuntimeError("simulated_crash_after_first_coordination_ledger_delivery")
                return result

        crashing = _CrashAfterFirst(writer)
        runtime.detector.context_writer = crashing  # type: ignore[assignment]
        for index, task in enumerate(tasks):
            await _publish_application(
                first.app,
                task,
                (
                    _event(
                        "obligation_published",
                        {
                            "obligation_id": new_id(IdKind.OBLIGATION),
                            "description": "Coordinate one shared file.",
                            "evidence_expectation": "A coordination result is recorded.",
                            "status": "open",
                            "requested_items": ({"item_kind": "file", "value": "src/shared.py"},),
                        },
                    ),
                ),
            )
            if index == 0:
                assert await _coordination_context_count(first.app, task) == 0
        assert crashing.calls == 1
        assert crashing.first_recipient in {task.task_id for task in tasks}
        detections = await runtime.detector.store.list_detections(project)
        assert len(detections) == 1
        assert await runtime.detector.store.deliveries(detections[0].detection_id) == ()
        first_counts = [await _coordination_context_count(first.app, task) for task in tasks]
        assert sum(first_counts) == 1

        second = await installation.restart()
        recovered_application = second.app
        await recovered_application.recover_lineage()
        recovered_project_application = recovered_application.project_application
        assert recovered_project_application is not None
        recovered_runtime = cast(
            CoordinationRuntime, getattr(recovered_project_application, "coordination_runtime")
        )
        recovered_outputs = await recovered_runtime.sweep(project_id_value=project)
        assert len(recovered_outputs) == 2
        recovered_detections = await recovered_runtime.detector.store.list_detections(project)
        assert len(recovered_detections) == 1
        deliveries = await recovered_runtime.detector.store.deliveries(
            recovered_detections[0].detection_id
        )
        assert len(deliveries) == 2
        assert {item.outcome for item in deliveries} == {"delivered"}
        recovered_counts = [
            await _coordination_context_count(recovered_application, task) for task in tasks
        ]
        assert sum(recovered_counts) == 2
        advice_items: list[CoordinationAdvice | None] = []
        for task in tasks:
            advice_items.append(
                await recovered_runtime.detector.store.advice_for(
                    recovered_detections[0].detection_id, task.task_id
                )
            )
        advice = tuple(advice_items)
        assert all(item is not None for item in advice)
        assert all(item.target_task_id != item.counterpart_task_id for item in advice if item)


async def test_public_dissolve_preserves_parent_manifest_and_receipt_replay_digest(
    tmp_path: Path,
) -> None:
    workspace = (tmp_path / "workspace").resolve()
    workspace.mkdir()
    subprocess.run(["git", "init", "--quiet", str(workspace)], check=True, capture_output=True)

    async with multi_agent_service(tmp_path / "state") as service:
        parent, sibling = await _start_pair_application(service.app, workspace)
        from finishup.adapters.integrations.observation_local import LocalObservationStore

        observation = LocalObservationStore(_state=service.root / "state")
        observation.grant_consent(observation.workspace_commitment(str(workspace)))
        child = await _delegate_and_attach(service.app, parent, "Dissolve matrix child")
        await _publish(
            service,
            child,
            (_event("work_closed", {}),),
        )
        child_check = await _check(service, child)
        await _receipt_application(service.app, child, child_check)
        parent_check = await _check_application(service.app, parent)
        replay_request_id = new_id(IdKind.REQUEST)
        original = await _receipt_application(
            service.app,
            parent,
            parent_check,
            request_id=replay_request_id,
        )
        document = getattr(original, "document")
        assert isinstance(document, Mapping)
        assert "children" in document
        project, _ = await _create_granted_general_project(service, (parent, sibling))
        state = await service.app.start_catalog.project_state(project)
        assert state is not None
        dissolved = await service.app.project(
            JsonObject(
                {
                    "schema_version": "1.0.0",
                    "operation": "dissolve",
                    "request_id": new_id(IdKind.REQUEST),
                    "project_id": project,
                    "expected_generation": state.membership_generation,
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        assert dissolved["project_id"] == project
        assert dissolved["dissolved_at"] is not None
        reopened = await service.app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create",
                    "task_title": "Post-dissolve root",
                    "workspace_ref": str(workspace),
                    "external_ref": "recovery-matrix-post-dissolve",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        assert reopened.task_id != parent.task_id
        reopened_projects = await service.app.start_catalog.list_task_project_ids(reopened.task_id)
        assert project not in reopened_projects
        still_dissolved = await service.app.start_catalog.project_state(project)
        assert still_dissolved is not None and still_dissolved.dissolved_at is not None
        replayed = await _receipt_application(
            service.app,
            parent,
            parent_check,
            request_id=replay_request_id,
        )
        assert getattr(replayed, "receipt_digest") == getattr(original, "receipt_digest")
        assert getattr(replayed, "document") == document


async def test_public_implicit_dissolve_refuses_without_mutation_and_start_survives(
    tmp_path: Path,
) -> None:
    workspace = (tmp_path / "workspace").resolve()
    workspace.mkdir()
    subprocess.run(["git", "init", "--quiet", str(workspace)], check=True, capture_output=True)

    async with multi_agent_service(tmp_path / "state") as service:
        task = (await _start_pair_application(service.app, workspace))[0]
        project_ids = await service.app.start_catalog.list_task_project_ids(task.task_id)
        assert len(project_ids) == 1
        project = project_ids[0]
        state = await service.app.start_catalog.project_state(project)
        assert state is not None
        project_application = service.app.project_application
        assert project_application is not None
        with pytest.raises(ProjectCommandError) as refusal:
            await project_application.dissolve(
                ProjectDissolveCommand(project, state.membership_generation)
            )
        assert refusal.value.code is CoordinationErrorCode.IMPLICIT_PROJECT_REQUIRES_OPT_OUT
        unchanged = await service.app.start_catalog.project_state(project)
        assert unchanged is not None
        assert unchanged.dissolved_at is None
        assert unchanged.membership_generation == state.membership_generation

        reopened = await service.app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create",
                    "task_title": "Implicit project survivor",
                    "workspace_ref": str(workspace),
                    "external_ref": "recovery-matrix-implicit-survivor",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        assert reopened.task_id != task.task_id
        reopened_projects = await service.app.start_catalog.list_task_project_ids(reopened.task_id)
        assert project in reopened_projects
        still_active = await service.app.start_catalog.project_state(project)
        assert still_active is not None and still_active.dissolved_at is None


async def test_public_optout_preserves_accepted_delegation_and_rejects_second_general_link(
    tmp_path: Path,
) -> None:
    workspace = (tmp_path / "workspace").resolve()
    workspace.mkdir()
    subprocess.run(["git", "init", "--quiet", str(workspace)], check=True, capture_output=True)

    async with multi_agent_service(tmp_path / "state") as service:
        parent, sibling = await _start_pair_application(service.app, workspace)
        from finishup.adapters.integrations.observation_local import LocalObservationStore

        observation = LocalObservationStore(_state=service.root / "state")
        observation.grant_consent(observation.workspace_commitment(str(workspace)))
        child = await _delegate_and_attach(service.app, parent, "Optout matrix child")
        parent_provenance = await service.app.start_catalog.task_source_provenance(parent.task_id)
        child_provenance = await service.app.start_catalog.task_source_provenance(child.task_id)
        assert parent_provenance is not None
        assert child_provenance is not None
        if parent_provenance.workspace_ref_commitment is not None:
            observation.grant_consent(parent_provenance.workspace_ref_commitment)
        if child_provenance.workspace_ref_commitment is not None:
            observation.grant_consent(child_provenance.workspace_ref_commitment)
        repository_commitment = parent_provenance.repository_privacy_commitment
        assert repository_commitment is not None
        opted_out = await service.app.project(
            JsonObject(
                {
                    "schema_version": "1.0.0",
                    "operation": "opt_out",
                    "request_id": new_id(IdKind.REQUEST),
                    "repository_commitment": repository_commitment,
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        assert opted_out["auto_grouping"] is False
        lineage = await service.app.start_catalog.task_lineage(child.task_id)
        assert lineage is not None
        assert lineage.parent_task_id == parent.task_id
        assert lineage.acceptance is not None

        first_project, _ = await _create_granted_general_project(service, (parent, sibling))
        second_created = await service.app.project(
            JsonObject(
                {
                    "schema_version": "1.0.0",
                    "operation": "create",
                    "request_id": new_id(IdKind.REQUEST),
                    "title": "Recovery matrix second project",
                    "owner_task_id": parent.task_id,
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        second_project = second_created["project_id"]
        assert isinstance(second_project, str)
        await _grant_general_project(service, second_project, 1)
        assert first_project != second_project
        project_application = service.app.project_application
        assert project_application is not None
        sibling_provenance = await service.app.start_catalog.task_source_provenance(sibling.task_id)
        assert sibling_provenance is not None
        assert sibling_provenance.workspace_ref_commitment is not None
        with pytest.raises(ProjectCommandError) as refusal:
            await project_application.link(
                LinkProjectCommand(
                    second_project,
                    MemberKind.TASK,
                    sibling.task_id,
                    source_workspace_commitment=sibling_provenance.workspace_ref_commitment,
                )
            )
        assert refusal.value.code is CoordinationErrorCode.GENERAL_MEMBERSHIP_CONFLICT


async def test_public_ready_automatic_cross_repository_sweep_reports_coverage_without_overlap(
    tmp_path: Path,
) -> None:
    workspace_a = (tmp_path / "research-a").resolve()
    workspace_b = (tmp_path / "research-b").resolve()
    for workspace in (workspace_a, workspace_b):
        workspace.mkdir()
        subprocess.run(["git", "init", "--quiet", str(workspace)], check=True, capture_output=True)

    async with multi_agent_service(tmp_path / "state") as service:
        lookup = service.vault.installation_mac_handle(MacKeyPurpose.CATALOG_LOOKUP)
        repository_a = await resolve_repository_privacy_context(
            WorkspaceLocator(str(workspace_a)), lookup
        )
        repository_b = await resolve_repository_privacy_context(
            WorkspaceLocator(str(workspace_b)), lookup
        )
        assert repository_a.commitment != repository_b.commitment
        from finishup.adapters.integrations.observation_local import LocalObservationStore

        observation = LocalObservationStore(_state=service.root / "state")
        observation.grant_consent(observation.workspace_commitment(str(workspace_a)))
        observation.grant_consent(observation.workspace_commitment(str(workspace_b)))
        task_a = await service.app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create",
                    "task_title": "Research source A",
                    "workspace_ref": str(workspace_a),
                    "external_ref": "recovery-matrix-research-a",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=repository_a,
        )
        task_b = await service.app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create",
                    "task_title": "Research source B",
                    "workspace_ref": str(workspace_b),
                    "external_ref": "recovery-matrix-research-b",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=repository_b,
        )
        created = await service.app.project(
            JsonObject(
                {
                    "schema_version": "1.0.0",
                    "operation": "create",
                    "title": "Recovery matrix research project",
                    "request_id": new_id(IdKind.REQUEST),
                    "owner_task_id": task_a.task_id,
                }
            ),
            repository_privacy_context=repository_a,
        )
        project = created["project_id"]
        assert isinstance(project, str)
        await _grant_general_project(service, project, 1)
        await service.app.project(
            JsonObject(
                {
                    "schema_version": "1.0.0",
                    "operation": "link",
                    "request_id": new_id(IdKind.REQUEST),
                    "project_id": project,
                    "member_kind": "repository",
                    "member_commitment_or_id": repository_a.commitment,
                    "member_repository_commitment": repository_a.commitment,
                }
            ),
            repository_privacy_context=repository_a,
        )
        state = await service.app.start_catalog.project_state(project)
        assert state is not None
        await _grant_general_project(service, project, state.membership_generation)
        await service.app.project(
            JsonObject(
                {
                    "schema_version": "1.0.0",
                    "operation": "link",
                    "request_id": new_id(IdKind.REQUEST),
                    "project_id": project,
                    "member_kind": "repository",
                    "member_commitment_or_id": repository_b.commitment,
                    "member_repository_commitment": repository_b.commitment,
                }
            ),
            repository_privacy_context=repository_b,
        )
        state = await service.app.start_catalog.project_state(project)
        assert state is not None
        await _grant_general_project(service, project, state.membership_generation)

        for task, repository in ((task_a, repository_a), (task_b, repository_b)):
            await _publish(
                service,
                task,
                (
                    _event(
                        "obligation_published",
                        {
                            "obligation_id": new_id(IdKind.OBLIGATION),
                            "description": "Record the research source result.",
                            "evidence_expectation": "A source result is recorded.",
                            "status": "open",
                        },
                    ),
                ),
                repository_privacy_context=repository,
            )

        automatic = service.app.observation_sweep
        assert automatic is not None
        await automatic()
        project_application = service.app.project_application
        assert project_application is not None
        runtime = cast(CoordinationRuntime, getattr(project_application, "coordination_runtime"))
        state = await service.app.start_catalog.project_state(project)
        assert state is not None
        coverage = await runtime.detector.store.coverage_for(project, state.membership_generation)
        assert {row.task_id for row in coverage} == {task_a.task_id, task_b.task_id}
        project_status = await service.app.status(
            StatusRequest.model_validate(
                {
                    **_identity(),
                    "session_id": task_a.session_id,
                    "writer_id": task_a.writer_id,
                    "view": "project",
                    "limit": "100",
                    "project_id": project,
                }
            ),
            repository_privacy_context=repository_a,
        )
        assert isinstance(project_status.page, StatusProjectPageModel)
        assert {item.task_id for item in project_status.page.members} == {
            task_a.task_id,
            task_b.task_id,
        }
        assert {item.task_id for item in project_status.page.coverage} == {
            task_a.task_id,
            task_b.task_id,
        }

        for task, repository in ((task_a, repository_a), (task_b, repository_b)):
            await _publish(
                service,
                task,
                (
                    _event(
                        "obligation_published",
                        {
                            "obligation_id": new_id(IdKind.OBLIGATION),
                            "description": "Record the same relative research path.",
                            "evidence_expectation": "A source result is recorded.",
                            "status": "open",
                            "requested_items": ({"item_kind": "file", "value": "src/shared.py"},),
                        },
                    ),
                ),
                repository_privacy_context=repository,
            )
        await automatic()
        assert await runtime.detector.store.list_detections(project) == ()
