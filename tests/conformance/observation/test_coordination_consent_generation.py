"""Consent withdrawal fences project generations before coordination can be retried."""

from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest

from builders.multi_agent import multi_agent_service
from finishup.adapters.integrations.codex_lifecycle import (
    LifecycleMapping,
    load_mapping,
    store_mapping,
)
from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.application import start as start_module
from finishup.application.coordination import (
    CoordinationDetector,
    DeclaredCoordinationInput,
    InMemoryCoordinationStore,
)
from finishup.application.observation_coordinator import ObservationCoordinator
from finishup.application.projects import (
    InMemoryProjectCatalog,
    ProjectApplication,
    SourceConsentRevocationPlan,
)
from finishup.application.start import StartInternalResult
from finishup.domain.coordination import MemberKind
from finishup.domain.observation import ObservationRevokeCommand
from finishup.ports.control import ControlError, RepositoryPrivacyContext
from finishup.ports.start_catalog import TaskRouteState, TaskSourceProvenance
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.ids import IdKind, new_id
from finishup.protocol.models import StartRequest

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class _Ids:
    def new(self, kind: IdKind) -> str:
        return new_id(kind)


class _UnavailableRuntime:
    async def route(self, command: object) -> object:
        del command
        raise PublicOperationError(
            PublicErrorCode.SERVICE_UNAVAILABLE,
            "The task runtime is unavailable.",
            retryable=True,
        )


def _commitment(fill: str) -> str:
    return "hmac-sha256:" + fill * 64


def _identity() -> dict[str, object]:
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": new_id(IdKind.REQUEST),
        "actor": {"actor_id": "harness:consent-generation", "actor_type": "harness"},
        "client": {
            "kind": "cooperative_agent",
            "version": "0.1.0",
            "integration": "cooperative_mcp",
        },
    }


async def _composition(
    tmp_path: Path,
) -> tuple[LocalObservationStore, ProjectApplication, str, str, str, str]:
    local = LocalObservationStore(_state=tmp_path)
    workspace = local.workspace_commitment(str(tmp_path / "workspace"))
    local.grant_consent(workspace)

    task_id = new_id(IdKind.TASK)
    repository = _commitment("1")
    external = _commitment("2")
    route_digest = "sha256:" + "3" * 64
    catalog = InMemoryProjectCatalog()
    catalog.provenance[task_id] = TaskSourceProvenance(
        task_id,
        workspace,
        external,
        repository,
        1,
        route_digest,
    )
    repository_project = await catalog.ensure_repository_project(repository)
    general_project = await catalog.create_general_project(new_id(IdKind.PROJECT))
    await catalog.record_project_membership(
        general_project.project_id,
        member_kind=MemberKind.WORKSPACE,
        member_commitment_or_id=workspace,
    )
    app = ProjectApplication(catalog, ids=_Ids())

    codex_session_id = "consent-generation-session"
    local.bind_codex_session(workspace, codex_session_id)
    store_mapping(
        LifecycleMapping(
            mapping_version=1,
            codex_session_id=codex_session_id,
            finishup_task_id=task_id,
            finishup_session_id=new_id(IdKind.SESSION),
            finishup_writer_id=new_id(IdKind.WRITER),
            last_frontier=None,
        ),
        _state=tmp_path,
    )
    return (
        local,
        app,
        workspace,
        task_id,
        repository_project.project_id,
        general_project.project_id,
    )


def _coordinator(
    *,
    local: LocalObservationStore,
    app: ProjectApplication,
    state: Path,
    planner: object | None = None,
    applier: object | None = None,
) -> ObservationCoordinator:
    async def default_planner(
        task_ids: tuple[str, ...], _workspace_commitment: str, token: str
    ) -> SourceConsentRevocationPlan:
        return await app.plan_source_workspace_consent_invalidation(task_ids, token)

    return ObservationCoordinator(
        runtime=_UnavailableRuntime(),  # type: ignore[arg-type]
        local=local,
        clock=object(),  # type: ignore[arg-type]
        ids=_Ids(),
        state_root=state,
        mapping_loader=load_mapping,
        consent_invalidation_planner=default_planner if planner is None else planner,  # type: ignore[arg-type]
        consent_invalidation_applier=(
            app.apply_source_workspace_consent_invalidation if applier is None else applier  # type: ignore[arg-type]
        ),
    )


async def _generation(app: ProjectApplication, project_id: str) -> int:
    descriptor = await app.catalog.project_state(project_id)
    assert descriptor is not None
    return descriptor.membership_generation


async def test_revoke_retries_after_crash_before_plan_and_blocks_reconsent(
    tmp_path: Path,
) -> None:
    local, app, workspace, task_id, repository_project, general_project = await _composition(
        tmp_path
    )
    before = {
        project: await _generation(app, project)
        for project in (repository_project, general_project)
    }
    calls = 0

    async def fail_before_plan(
        task_ids: tuple[str, ...], _workspace: str, token: str
    ) -> SourceConsentRevocationPlan:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("injected_before_plan")
        return await app.plan_source_workspace_consent_invalidation(task_ids, token)

    coordinator = _coordinator(
        local=local,
        app=app,
        state=tmp_path,
        planner=fail_before_plan,
    )
    command = ObservationRevokeCommand(workspace)
    with pytest.raises(RuntimeError, match="injected_before_plan"):
        await coordinator.revoke(command)

    pending = local.pending_consent_revocation(workspace)
    assert pending is not None
    assert pending[1] is None
    with pytest.raises(PublicOperationError) as blocked:
        local.grant_consent(workspace)
    assert blocked.value.code is PublicErrorCode.SESSION_CONFLICT
    assert {project: await _generation(app, project) for project in before} == before

    await coordinator.revoke(command)
    assert local.pending_consent_revocation(workspace) is None
    assert {project: await _generation(app, project) for project in before} == {
        project: generation + 1 for project, generation in before.items()
    }

    # A repeated revoke in the same consent epoch is idempotent.  Re-consent is allowed only
    # after the durable project fence, and it does not restore the old generation.
    await coordinator.revoke(command)
    local.grant_consent(workspace)
    assert {project: await _generation(app, project) for project in before} == {
        project: generation + 1 for project, generation in before.items()
    }
    assert task_id


async def test_partial_generation_apply_replays_from_durable_plan_without_double_advance(
    tmp_path: Path,
) -> None:
    local, app, workspace, _task_id_value, repository_project, general_project = await _composition(
        tmp_path
    )
    projects = (repository_project, general_project)
    before = {project: await _generation(app, project) for project in projects}
    failed = True

    async def apply_one_then_fail(plan: SourceConsentRevocationPlan) -> object:
        nonlocal failed
        if failed:
            failed = False
            await app.apply_source_workspace_consent_invalidation(
                SourceConsentRevocationPlan(plan.revocation_token, plan.project_generations[:1])
            )
            raise RuntimeError("injected_partial_apply")
        return await app.apply_source_workspace_consent_invalidation(plan)

    coordinator = _coordinator(
        local=local,
        app=app,
        state=tmp_path,
        applier=apply_one_then_fail,
    )
    command = ObservationRevokeCommand(workspace)
    with pytest.raises(RuntimeError, match="injected_partial_apply"):
        await coordinator.revoke(command)

    pending = local.pending_consent_revocation(workspace)
    assert pending is not None
    assert pending[1] is not None
    assert len(pending[1]) == 2
    after_partial = {project: await _generation(app, project) for project in projects}
    assert sorted(after_partial.values()) == [before[projects[0]] + 1, before[projects[1]]]

    await coordinator.revoke(command)
    assert local.pending_consent_revocation(workspace) is None
    after_retry = {project: await _generation(app, project) for project in projects}
    assert after_retry == {project: generation + 1 for project, generation in before.items()}


async def test_empty_durable_plan_is_reused_after_apply_crash(tmp_path: Path) -> None:
    (
        local,
        app,
        workspace,
        _task_id_value,
        _repository_project,
        _general_project,
    ) = await _composition(tmp_path)
    planner_calls = 0
    applied_sizes: list[int] = []
    failed = True

    async def empty_planner(
        _task_ids: tuple[str, ...], _workspace: str, token: str
    ) -> SourceConsentRevocationPlan:
        nonlocal planner_calls
        planner_calls += 1
        return SourceConsentRevocationPlan(token, ())

    async def fail_after_empty_plan(plan: SourceConsentRevocationPlan) -> object:
        nonlocal failed
        applied_sizes.append(len(plan.project_generations))
        if failed:
            failed = False
            raise RuntimeError("injected_empty_plan_apply")
        return await app.apply_source_workspace_consent_invalidation(plan)

    coordinator = _coordinator(
        local=local,
        app=app,
        state=tmp_path,
        planner=empty_planner,
        applier=fail_after_empty_plan,
    )
    command = ObservationRevokeCommand(workspace)
    with pytest.raises(RuntimeError, match="injected_empty_plan_apply"):
        await coordinator.revoke(command)
    pending = local.pending_consent_revocation(workspace)
    assert pending is not None and pending[1] == ()

    await coordinator.revoke(command)
    assert planner_calls == 1
    assert applied_sizes == [0, 0]
    assert local.pending_consent_revocation(workspace) is None


@pytest.mark.parametrize(
    "failure_point",
    (
        None,
        "recovery_routes",
        "task_source_provenance",
        "missing_session_binding",
        "missing_task_source_provenance",
    ),
)
async def test_ready_revoke_fences_tasks_without_host_lifecycle_mappings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure_point: str | None
) -> None:
    """READY enumerates authenticated task routes when no hook mapping exists yet."""

    workspace = (tmp_path / "workspace").resolve()
    workspace.mkdir()
    repository = RepositoryPrivacyContext(_commitment("d"), "git_common_root")
    async with multi_agent_service(tmp_path / "ready-state") as service:
        tasks: list[StartInternalResult] = []
        for index in range(2):
            result = await service.app.start(
                StartRequest.model_validate(
                    {
                        **_identity(),
                        "mode": "create",
                        "task_title": f"Consent route {index}",
                        "workspace_ref": str(workspace),
                        "external_ref": f"consent-route-{index}",
                        "requested_view": "compact",
                    }
                ),
                repository_privacy_context=repository,
            )
            tasks.append(result)

        # A distinct active task without workspace identity cannot have contributed source
        # facts.  Its encrypted locator and catalog provenance must agree before it is skipped.
        await service.app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create",
                    "task_title": "Workspace-free task",
                    "requested_view": "compact",
                }
            )
        )

        assert tasks[0].task_id is not None
        project_ids = await service.app.start_catalog.list_task_project_ids(tasks[0].task_id)
        assert len(project_ids) == 1
        project = await service.app.start_catalog.project_state(project_ids[0])
        assert project is not None
        local = LocalObservationStore(_state=service.root / "state")
        local_workspace = local.workspace_commitment(str(workspace))
        local.grant_consent(local_workspace)

        if failure_point is not None:

            async def unavailable(*_args: object, **_kwargs: object) -> object:
                if failure_point.startswith("missing_"):
                    return None
                raise PublicOperationError(
                    PublicErrorCode.SERVICE_UNAVAILABLE,
                    "Injected source enumeration failure.",
                    retryable=True,
                )

            with monkeypatch.context() as patch:
                patch.setattr(
                    service.app.start_catalog,
                    failure_point.removeprefix("missing_"),
                    unavailable,
                )
                with pytest.raises(ControlError) as unavailable_result:
                    await service.app.observation_revoke(
                        {"workspace_commitment": local_workspace, "retain_evidence": True}
                    )
                assert unavailable_result.value.reason == "service_unavailable"
                assert unavailable_result.value.retryable is True
            pending = local.pending_consent_revocation(local_workspace)
            assert pending is not None and pending[1] is None
            with pytest.raises(PublicOperationError) as grant_blocked:
                local.grant_consent(local_workspace)
            assert grant_blocked.value.code is PublicErrorCode.SESSION_CONFLICT

        await service.app.observation_revoke(
            {
                "workspace_commitment": local_workspace,
                "retain_evidence": True,
            }
        )
        fenced = await service.app.start_catalog.project_state(project.project_id)
        assert fenced is not None
        assert fenced.membership_generation == project.membership_generation + 1
        assert local.pending_consent_revocation(local_workspace) is None

        # Re-consent is a new source epoch; it cannot restore the old project generation.
        local.grant_consent(local_workspace)
        current = await service.app.start_catalog.project_state(project.project_id)
        assert current is not None
        assert current.membership_generation == fenced.membership_generation


async def test_quarantined_route_keeps_structural_fence_association_private(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Terminal quarantines stay undisclosed while their durable association remains fenceable."""

    workspace = (tmp_path / "workspace").resolve()
    workspace.mkdir()
    repository = RepositoryPrivacyContext(_commitment("e"), "git_common_root")
    async with multi_agent_service(tmp_path / "quarantine-state") as service:
        request = StartRequest.model_validate(
            {
                **_identity(),
                "mode": "create",
                "task_title": "Consent quarantine",
                "workspace_ref": str(workspace),
                "external_ref": "consent-quarantine",
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
        with pytest.raises(PublicOperationError):
            await service.app.start(request, repository_privacy_context=repository)
        assert len(quarantined_task_ids) == 1
        route = await service.app.start_catalog.task_route(quarantined_task_ids[0])
        assert route is not None and route.state is TaskRouteState.QUARANTINED

        project = await service.app.start_catalog.create_general_project(new_id(IdKind.PROJECT))
        await service.app.start_catalog.record_project_membership(
            project.project_id,
            member_kind=MemberKind.TASK,
            member_commitment_or_id=quarantined_task_ids[0],
        )
        assert await service.app.start_catalog.list_task_project_ids(quarantined_task_ids[0]) == ()
        assert await service.app.start_catalog.list_task_project_ids_for_consent_invalidation(
            quarantined_task_ids[0]
        ) == (project.project_id,)


async def test_consent_refusal_irreversibly_invalidates_queued_detection() -> None:
    catalog = InMemoryProjectCatalog()
    repository = _commitment("a")
    workspace_one = _commitment("b")
    workspace_two = _commitment("c")
    task_one = new_id(IdKind.TASK)
    task_two = new_id(IdKind.TASK)
    catalog.provenance[task_one] = TaskSourceProvenance(
        task_one, workspace_one, _commitment("d"), repository, 1, "sha256:" + "1" * 64
    )
    catalog.provenance[task_two] = TaskSourceProvenance(
        task_two, workspace_two, _commitment("e"), repository, 1, "sha256:" + "2" * 64
    )
    project = await catalog.ensure_repository_project(repository)
    consent = True

    async def workspace_consent(_workspace: str) -> bool:
        return consent

    app = ProjectApplication(
        catalog,
        ids=_Ids(),
        workspace_consent=workspace_consent,
        coordination_source_authorizer=lambda _task, _workspace, _project: True,
    )
    store = InMemoryCoordinationStore()
    detector = CoordinationDetector(app, store)
    left = DeclaredCoordinationInput(
        task_one,
        project.project_id,
        repository,
        workspace_one,
        1,
        ("src/shared.py",),
    )
    right = DeclaredCoordinationInput(
        task_two,
        project.project_id,
        repository,
        workspace_two,
        1,
        ("src/shared.py",),
    )
    delivered = await detector.detect(left, right)
    assert len(delivered) == 2
    detection = await store.get_detection(delivered[0].detection_id)
    assert detection is not None and detection.generation_valid

    consent = False
    assert await detector.redeliver(detection.detection_id) == ()
    fenced = await store.get_detection(detection.detection_id)
    assert fenced is not None and not fenced.generation_valid

    # Re-consent does not reopen the old queued detection; a fresh generation/detection is
    # required before advice can be delivered again.
    consent = True
    assert await detector.redeliver(detection.detection_id) == ()
