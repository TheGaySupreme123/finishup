from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

from builders.multi_agent import INSTALLATION_ID, MultiAgentService, multi_agent_service
from finishup.adapters.privacy.catalog import encode_privacy_policy_json
from finishup.application.coordination import CoordinationParticipant
from finishup.application.projects import ProjectCommandError
from finishup.application.start import StartInternalResult
from finishup.domain.coordination import (
    CoordinationDetection,
    CoordinationErrorCode,
    OverlapKind,
    canonical_resource_identity,
)
from finishup.domain.privacy import (
    AuthorizationScope,
    AuthorizationScopeKind,
    DataCategory,
    DataClass,
)
from finishup.ports.control import RepositoryPrivacyContext
from finishup.ports.privacy import (
    HumanPolicyDecision,
    PolicyTransitionMember,
    PolicyTransitionProposal,
)
from finishup.protocol.canonical import canonical_digest
from finishup.protocol.ids import IdKind, new_id
from finishup.protocol.models import StartRequest

pytestmark = pytest.mark.anyio

_REPOSITORY = RepositoryPrivacyContext("hmac-sha256:" + "d" * 64, "git_common_root")


def _identity() -> dict[str, object]:
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": new_id(IdKind.REQUEST),
        "actor": {"actor_id": "harness:project-consent", "actor_type": "harness"},
        "client": {
            "kind": "cooperative_agent",
            "version": "0.1.0",
            "integration": "cooperative_mcp",
        },
    }


async def _persist_task_policy(
    service: MultiAgentService,
    task_id: str,
    workspace_commitment: str,
    *,
    categories: tuple[DataCategory, ...],
    data_classes: tuple[DataClass, ...],
    prior: object | None = None,
) -> object:
    """Commit one task-scope policy row through the real durable policy transition port."""

    app = getattr(service, "app")
    policy_app = app.privacy.policy_application
    assert policy_app is not None
    store = policy_app.policy_store
    scope = AuthorizationScope(
        AuthorizationScopeKind.TASK,
        INSTALLATION_ID,
        workspace_commitment,
        task_id,
    )
    if prior is None:
        base = await store.effective_policy(
            AuthorizationScope(AuthorizationScopeKind.MACHINE, INSTALLATION_ID)
        )
        source = base.policy
        action = "insert"
        expected_generation = None
        expected_digest = None
        version = 1
        supersedes = None
        proposal_expected_generation = base.generation
        proposal_expected_digest = base.effective_digest
    else:
        source = getattr(prior, "policy")
        action = "replace"
        expected_generation = getattr(prior, "generation")
        expected_digest = source.policy_digest
        version = source.version + 1
        supersedes = source.policy_digest
        proposal_expected_generation = expected_generation
        proposal_expected_digest = expected_digest
    placeholder = replace(
        source,
        policy_id=app.ids.new(IdKind.PRIVACY_POLICY),
        version=version,
        policy_digest="sha256:" + "0" * 64,
        effective_scope=scope,
        agent_context_categories=categories,
        agent_context_data_classes=data_classes,
        supersedes_policy_digest=supersedes,
        created_at=service.clock.now_utc(),
    )
    identity = encode_privacy_policy_json(placeholder)
    identity.pop("policy_digest")
    candidate = replace(placeholder, policy_digest=canonical_digest(identity))
    member = PolicyTransitionMember(
        action,
        scope,
        candidate,
        expected_generation,
        expected_digest,
    )
    now = service.clock.now_utc()
    proposal = PolicyTransitionProposal(
        scope,
        proposal_expected_generation,
        candidate,
        canonical_digest(
            {
                "scope_kind": scope.kind.value,
                "task_id": task_id,
                "candidate_policy_digest": candidate.policy_digest,
            }
        ),
        now,
        now + timedelta(minutes=5),
        app.ids.new(IdKind.PRIVACY_PROPOSAL),
        proposal_expected_digest,
        None,
        (member,),
    )
    prepared = await store.prepare_transition(proposal)
    return await store.commit_transition(
        prepared,
        HumanPolicyDecision(
            prepared.prepared_digest,
            True,
            now,
            "hmac-sha256:" + "e" * 64,
        ),
    )


async def test_ready_project_admission_maps_catalog_source_to_local_consent(
    tmp_path: Path,
) -> None:
    workspace_a = (tmp_path / "workspace-a").resolve()
    workspace_b = (tmp_path / "workspace-b").resolve()
    workspace_a.mkdir()
    workspace_b.mkdir()
    async with multi_agent_service(tmp_path / "state") as service:
        started: list[StartInternalResult] = []
        for index, workspace in enumerate((workspace_a, workspace_b)):
            started.append(
                await service.app.start(
                    StartRequest.model_validate(
                        {
                            **_identity(),
                            "mode": "create",
                            "task_title": f"Consent sibling {index}",
                            "workspace_ref": str(workspace),
                            "external_ref": f"consent-sibling-{index}",
                            "requested_view": "compact",
                        }
                    ),
                    repository_privacy_context=_REPOSITORY,
                )
            )
        first, second = started
        assert first.task_id is not None
        assert second.task_id is not None
        assert service.app.project_application is not None

        first_source = await service.app.start_catalog.task_source_provenance(first.task_id)
        second_source = await service.app.start_catalog.task_source_provenance(second.task_id)
        project = await service.app.start_catalog.repository_state(_REPOSITORY.commitment)
        assert first_source is not None and first_source.workspace_ref_commitment is not None
        assert second_source is not None and second_source.workspace_ref_commitment is not None
        assert project is not None

        from finishup.adapters.integrations.observation_local import LocalObservationStore

        local = LocalObservationStore(_state=service.root / "state")
        local.grant_consent(local.workspace_commitment(str(workspace_a)))

        admitted = await service.app.project_application.admit(
            source_task_id=first.task_id,
            source_workspace_commitment=first_source.workspace_ref_commitment,
            project=project.project_id,
        )
        assert admitted.source_task_id == first.task_id

        with pytest.raises(ProjectCommandError) as denied:
            await service.app.project_application.admit(
                source_task_id=second.task_id,
                source_workspace_commitment=second_source.workspace_ref_commitment,
                project=project.project_id,
            )
        assert denied.value.code is CoordinationErrorCode.CONSENT_REQUIRED


async def test_ready_coordination_uses_persisted_source_task_policy_and_reopens_after_widen(
    tmp_path: Path,
) -> None:
    workspace_a = (tmp_path / "workspace-a").resolve()
    workspace_b = (tmp_path / "workspace-b").resolve()
    workspace_a.mkdir()
    workspace_b.mkdir()
    async with multi_agent_service(tmp_path / "state") as service:
        from finishup.adapters.integrations.observation_local import LocalObservationStore

        local = LocalObservationStore(_state=service.root / "state")
        local.grant_consent(local.workspace_commitment(str(workspace_a)))
        local.grant_consent(local.workspace_commitment(str(workspace_b)))
        started: list[StartInternalResult] = []
        for index, workspace in enumerate((workspace_a, workspace_b)):
            started.append(
                await service.app.start(
                    StartRequest.model_validate(
                        {
                            **_identity(),
                            "request_id": new_id(IdKind.REQUEST),
                            "mode": "create",
                            "task_title": f"Policy sibling {index}",
                            "workspace_ref": str(workspace),
                            "external_ref": f"policy-sibling-{index}",
                            "requested_view": "compact",
                        }
                    ),
                    repository_privacy_context=_REPOSITORY,
                )
            )
        left, right = started
        assert left.task_id is not None and right.task_id is not None
        application = service.app.project_application
        assert application is not None
        left_source = await service.app.start_catalog.task_source_provenance(left.task_id)
        right_source = await service.app.start_catalog.task_source_provenance(right.task_id)
        project = await service.app.start_catalog.repository_state(_REPOSITORY.commitment)
        assert left_source is not None and left_source.workspace_ref_commitment is not None
        assert right_source is not None and right_source.workspace_ref_commitment is not None
        assert project is not None

        denied_policy = await _persist_task_policy(
            service,
            right.task_id,
            right_source.workspace_ref_commitment,
            categories=(),
            data_classes=(DataClass.PUBLIC_STRUCTURAL,),
        )
        with pytest.raises(ProjectCommandError) as denied:
            await application.admit(
                source_task_id=right.task_id,
                source_workspace_commitment=right_source.workspace_ref_commitment,
                project=project.project_id,
            )
        assert denied.value.code is CoordinationErrorCode.SOURCE_POLICY_DENIED

        detector = getattr(application, "coordination_detector")
        detection_id = new_id(IdKind.EVENT)
        resource = canonical_resource_identity(
            "src/shared.py", repository_commitment=_REPOSITORY.commitment
        )
        detection = CoordinationDetection(
            detection_id,
            project.project_id,
            project.membership_generation,
            left.task_id,
            right.task_id,
            OverlapKind.INTEGRATION,
            (resource,),
            right.task_id,
        )
        await detector.store.put_detection(detection)
        await detector.store.put_participants(
            detection_id,
            (
                CoordinationParticipant(
                    left.task_id,
                    project.project_id,
                    _REPOSITORY.commitment,
                    left_source.workspace_ref_commitment,
                    left_source.route_generation,
                ),
                CoordinationParticipant(
                    right.task_id,
                    project.project_id,
                    _REPOSITORY.commitment,
                    right_source.workspace_ref_commitment,
                    right_source.route_generation,
                ),
            ),
        )
        await detector._deliver(detection)  # pyright: ignore[reportPrivateUsage]
        deliveries = await detector.store.deliveries(detection_id)
        assert len(deliveries) == 2
        assert {item.outcome for item in deliveries} == {"refused"}
        assert all(
            item.reason_code == CoordinationErrorCode.SOURCE_POLICY_DENIED.value
            for item in deliveries
        )

        allowed_policy = await _persist_task_policy(
            service,
            right.task_id,
            right_source.workspace_ref_commitment,
            categories=(
                DataCategory.BOUNDED_STRUCTURAL_METADATA,
                DataCategory.FINDING_SUMMARY,
            ),
            data_classes=(DataClass.PUBLIC_STRUCTURAL,),
            prior=denied_policy,
        )
        assert getattr(allowed_policy, "policy").agent_context_categories == (
            DataCategory.BOUNDED_STRUCTURAL_METADATA,
            DataCategory.FINDING_SUMMARY,
        )
        admitted = await application.admit(
            source_task_id=right.task_id,
            source_workspace_commitment=right_source.workspace_ref_commitment,
            project=project.project_id,
        )
        assert admitted.allowed
