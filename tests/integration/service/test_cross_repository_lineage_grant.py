"""Composed cross-repository parent lineage admission through a project grant."""

from __future__ import annotations

from pathlib import Path

import pytest

from builders.multi_agent import MultiAgentService, multi_agent_service
from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.adapters.repository_identity import resolve_repository_privacy_context
from finishup.application.projects import (
    CreateProjectCommand,
    LinkProjectCommand,
    ProjectCommandError,
    ProjectGrantCommand,
    ProjectRevokeCommand,
)
from finishup.application.publish_work import PublishWorkInternalResult
from finishup.application.receipt import ReceiptInternalResult
from finishup.application.start import StartInternalResult
from finishup.domain.coordination import CoordinationErrorCode, MemberKind
from finishup.domain.events import (
    AcceptedEvent,
    ChildDependenciesRecordedPayload,
    ChildDependencySnapshot,
)
from finishup.ports.control import WorkspaceLocator
from finishup.ports.diagnostics import RuntimeCapability
from finishup.ports.keys import MacKeyPurpose
from finishup.ports.ledger import CheckCommitResult
from finishup.ports.runtime import RouteAccess, RouteCommand
from finishup.ports.start_catalog import StartIdentityInput
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.ids import IdKind, new_id
from finishup.protocol.models import CheckRequest, PublishWorkRequest, ReceiptRequest, StartRequest
from finishup.service.elevated_bootstrap import (
    load_pending,
    record_project_coordination_authorization,
)

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _start_request(
    *,
    workspace: Path,
    title: str,
    mode: str = "create",
    session_id: str | None = None,
    parent_session_id: str | None = None,
) -> StartRequest:
    body: dict[str, object] = {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": new_id(IdKind.REQUEST),
        "mode": mode,
        "task_title": title,
        "workspace_ref": str(workspace),
        "external_ref": title.lower().replace(" ", "-"),
        "actor": {"actor_id": "harness:cross-repo-lineage", "actor_type": "harness"},
        "client": {
            "kind": "cooperative_agent",
            "version": "0.3.0",
            "integration": "cooperative_mcp",
        },
        "requested_view": "compact",
    }
    if session_id is not None:
        body["session_id"] = session_id
    if parent_session_id is not None:
        body["parent_session_id"] = parent_session_id
    return StartRequest.model_validate(body)


async def _approve_and_grant(
    service: MultiAgentService, project_id: str, generation: int
) -> object:
    application = service.app.project_application
    assert application is not None
    with pytest.raises(ProjectCommandError) as pending_error:
        await application.grant(ProjectGrantCommand(project_id, generation))
    assert pending_error.value.code is CoordinationErrorCode.GRANT_REQUIRED
    state = service.root / "state"
    pending = load_pending(_state=state)
    assert pending is not None and pending.coordination_binding is not None
    audit_record_id = pending.coordination_binding["audit_record_id"]
    assert isinstance(audit_record_id, str)
    record_project_coordination_authorization(pending, _state=state)
    return await application.grant(ProjectGrantCommand(project_id, generation, audit_record_id))


async def test_ready_cross_repository_parent_lineage_requires_current_project_grant(
    tmp_path: Path,
) -> None:
    workspace_parent = (tmp_path / "parent").resolve()
    workspace_child = (tmp_path / "child").resolve()
    workspace_parent.mkdir()
    workspace_child.mkdir()
    async with multi_agent_service(tmp_path / "state") as service:
        lookup = service.vault.installation_mac_handle(MacKeyPurpose.CATALOG_LOOKUP)
        parent_repository = await resolve_repository_privacy_context(
            WorkspaceLocator(str(workspace_parent)), lookup
        )
        child_repository = await resolve_repository_privacy_context(
            WorkspaceLocator(str(workspace_child)), lookup
        )
        assert parent_repository.commitment != child_repository.commitment

        local = LocalObservationStore(_state=service.root / "state")
        local.grant_consent(local.workspace_commitment(str(workspace_parent)))
        local.grant_consent(local.workspace_commitment(str(workspace_child)))

        parent = await service.app.start(
            _start_request(workspace=workspace_parent, title="Parent task"),
            repository_privacy_context=parent_repository,
        )
        assert parent.task_id
        application = service.app.project_application
        assert application is not None
        route = await service.app.start_catalog.task_route(parent.task_id)
        assert route is not None

        project = await application.create(
            CreateProjectCommand(
                "Cross repository project",
                owner_task_id=parent.task_id,
                owner_route_generation=route.route_generation,
            )
        )
        await _approve_and_grant(service, project.project_id, 1)
        await application.link(
            LinkProjectCommand(
                project.project_id,
                MemberKind.REPOSITORY,
                parent_repository.commitment,
                member_repository_commitment=parent_repository.commitment,
            )
        )
        descriptor = await application.catalog.project_state(project.project_id)
        assert descriptor is not None and descriptor.membership_generation == 2
        await _approve_and_grant(service, project.project_id, 2)
        await application.link(
            LinkProjectCommand(
                project.project_id,
                MemberKind.REPOSITORY,
                child_repository.commitment,
                member_repository_commitment=child_repository.commitment,
            )
        )
        descriptor = await application.catalog.project_state(project.project_id)
        assert descriptor is not None and descriptor.membership_generation == 3
        await _approve_and_grant(service, project.project_id, 3)
        await application.revoke(ProjectRevokeCommand(project.project_id, 3))

        with pytest.raises(ProjectCommandError) as revoked_before_child:
            await application.admit_cross_repository_child(
                parent.task_id,
                child_repository.commitment,
            )
        assert revoked_before_child.value.code is CoordinationErrorCode.CROSS_REPOSITORY_LINEAGE

        denied = _start_request(
            workspace=workspace_child,
            title="Denied child",
            mode="delegate",
            session_id=parent.session_id,
        )
        with pytest.raises(PublicOperationError) as denied_error:
            await service.app.start(
                denied,
                repository_privacy_context=child_repository,
            )
        assert denied_error.value.code is PublicErrorCode.SESSION_CONFLICT

        await _approve_and_grant(service, project.project_id, 4)
        admitted = _start_request(
            workspace=workspace_child,
            title="Admitted child",
            mode="delegate",
            session_id=parent.session_id,
        )
        child = await service.app.start(
            admitted,
            repository_privacy_context=child_repository,
        )
        assert isinstance(child, StartInternalResult)
        assert child.task_id != parent.task_id
        child_provenance = await service.app.start_catalog.task_source_provenance(child.task_id)
        assert child_provenance is not None
        assert child_provenance.workspace_ref_commitment is not None
        assert child_provenance.repository_privacy_commitment == child_repository.commitment
        child_identity = await service.app.start_catalog.commit_identity(
            StartIdentityInput(
                "Admitted child",
                str(workspace_child),
                "admitted-child",
            )
        )
        assert child_provenance.workspace_ref_commitment == child_identity.workspace_ref_commitment
        child_local_consent = local.consent_for(local.workspace_commitment(str(workspace_child)))
        assert child_local_consent is not None and child_local_consent.active
        assert child.attach_handle is not None
        attach_body = _start_request(
            workspace=workspace_child,
            title="Admitted child",
            mode="attach",
        ).model_dump(mode="json", exclude_none=True)
        attach_body["attach_handle"] = {
            "handle": child.attach_handle.value,
            "child_task_id": child.attach_handle.task_id,
            "expires_at": child.attach_handle.expires_at.isoformat(timespec="milliseconds").replace(
                "+00:00", "Z"
            ),
        }
        attached = await service.app.start(
            StartRequest.model_validate(attach_body),
            repository_privacy_context=child_repository,
        )
        assert attached.outcome == "attached"
        assert attached.task_id == child.task_id
        child_admission = await application.admit(
            source_task_id=child.task_id,
            source_workspace_commitment=child_provenance.workspace_ref_commitment,
            project=project.project_id,
            expected_generation=4,
            cross_repository=True,
        )
        assert child_admission.source_task_id == child.task_id
        assert child_admission.membership_generation == 4
        child_authority = await application.admit_cross_repository_child(
            parent.task_id,
            child_repository.commitment,
        )
        assert child_authority.project_id == project.project_id
        assert child_authority.membership_generation == 4

        self_request_body = _start_request(
            workspace=workspace_child,
            title="Self registered child",
            mode="create",
        ).model_dump(mode="json", exclude_none=True)
        self_request_body["parent_session_id"] = parent.session_id
        self_child = await service.app.start(
            StartRequest.model_validate(self_request_body),
            repository_privacy_context=child_repository,
        )
        assert self_child.task_id != parent.task_id
        assert self_child.parent_task_id == parent.task_id
        assert self_child.origin is not None and self_child.origin.value == "self_registered"
        self_provenance = await service.app.start_catalog.task_source_provenance(self_child.task_id)
        assert self_provenance is not None
        assert self_provenance.repository_privacy_commitment == child_repository.commitment
        assert self_provenance.workspace_ref_commitment is not None
        self_admission = await application.admit(
            source_task_id=self_child.task_id,
            source_workspace_commitment=self_provenance.workspace_ref_commitment,
            project=project.project_id,
            expected_generation=4,
            cross_repository=True,
        )
        assert self_admission.membership_generation == 4

        obligation_id = new_id(IdKind.OBLIGATION)
        obligation_event_id = new_id(IdKind.EVENT)
        published = await service.app.publish_work(
            PublishWorkRequest.model_validate(
                {
                    "protocol_version": "0.1",
                    "schema_version": "1.0.0",
                    "request_id": new_id(IdKind.REQUEST),
                    "session_id": attached.session_id,
                    "writer_id": attached.writer_id,
                    "expected_frontier": attached.frontier.model_dump(mode="json"),
                    "event_drafts": [
                        {
                            "event_id": obligation_event_id,
                            "schema": {"name": "obligation_published", "version": "1.0.0"},
                            "occurred_at": "2026-09-05T12:00:00.000Z",
                            "causal_parents": [],
                            "payload": {
                                "obligation_id": obligation_id,
                                "description": "Publish the admitted child result.",
                                "acceptance_criteria": "A result is recorded in the child ledger.",
                                "evidence_expectation": "A linked immutable child result.",
                                "status": "open",
                            },
                            "artifact_refs": [],
                            "evidence_refs": [],
                        }
                    ],
                    "actor": {"actor_id": "harness:cross-repo-lineage", "actor_type": "harness"},
                    "client": {
                        "kind": "cooperative_agent",
                        "version": "0.3.0",
                        "integration": "cooperative_mcp",
                    },
                }
            ),
            repository_privacy_context=child_repository,
        )
        assert isinstance(published, PublishWorkInternalResult)
        checked = await service.app.check(
            CheckRequest.model_validate(
                {
                    "protocol_version": "0.1",
                    "schema_version": "1.0.0",
                    "request_id": new_id(IdKind.REQUEST),
                    "session_id": attached.session_id,
                    "writer_id": attached.writer_id,
                    "expected_frontier": dict(published.result_frontier.as_wire()),
                    "mode": "deterministic_only",
                    "max_findings": "3",
                    "actor": {"actor_id": "harness:cross-repo-lineage", "actor_type": "harness"},
                    "client": {
                        "kind": "cooperative_agent",
                        "version": "0.3.0",
                        "integration": "cooperative_mcp",
                    },
                }
            ),
            repository_privacy_context=child_repository,
        )
        assert isinstance(checked, CheckCommitResult)
        receipt = await service.app.receipt(
            ReceiptRequest.model_validate(
                {
                    "protocol_version": "0.1",
                    "schema_version": "1.0.0",
                    "request_id": new_id(IdKind.REQUEST),
                    "task_id": attached.task_id,
                    "session_id": attached.session_id,
                    "writer_id": attached.writer_id,
                    "expected_frontier": dict(checked.result_frontier.as_wire()),
                    "format": "json",
                    "include": "standard",
                    "redaction_profile": "full_local",
                    "actor": {"actor_id": "harness:cross-repo-lineage", "actor_type": "harness"},
                    "client": {
                        "kind": "cooperative_agent",
                        "version": "0.3.0",
                        "integration": "cooperative_mcp",
                    },
                }
            ),
            repository_privacy_context=child_repository,
        )
        assert isinstance(receipt, ReceiptInternalResult)
        assert receipt.task_id == child.task_id
        observation_sweep = service.app.observation_sweep
        assert observation_sweep is not None
        await observation_sweep()

        parent_runtime = await service.app.runtime.route(
            RouteCommand(
                parent.session_id,
                parent.writer_id,
                RouteAccess.PAYLOAD_READ,
                frozenset({RuntimeCapability.STRUCTURAL_READ, RuntimeCapability.PAYLOAD_READ}),
            )
        )
        try:
            manifests: list[ChildDependenciesRecordedPayload] = []
            async for record in parent_runtime.ledger.load_events(parent_runtime.session_id):
                if isinstance(record, AcceptedEvent) and isinstance(
                    record.payload, ChildDependenciesRecordedPayload
                ):
                    manifests.append(record.payload)
        finally:
            await service.app.runtime.release(parent_runtime)
        assert manifests
        child_snapshot: ChildDependencySnapshot | None = next(
            (
                item
                for manifest in manifests
                for item in manifest.children
                if str(item.child_task_id) == child.task_id
            ),
            None,
        )
        assert child_snapshot is not None
        assert child_snapshot.child_check_id is not None
        assert child_snapshot.child_receipt_id == receipt.receipt_id
        assert child_snapshot.membership_generation == 4
        assert child_snapshot.provenance_restrictions == ()
        assert child_snapshot.read_gap_reasons == ()

        await application.revoke(ProjectRevokeCommand(project.project_id, 4))
        with pytest.raises(ProjectCommandError) as revoked_after_child:
            await application.admit_cross_repository_child(
                parent.task_id,
                child_repository.commitment,
            )
        assert revoked_after_child.value.code is CoordinationErrorCode.CROSS_REPOSITORY_LINEAGE
        revoked = _start_request(
            workspace=workspace_child,
            title="Revoked child",
            mode="delegate",
            session_id=parent.session_id,
        )
        with pytest.raises(PublicOperationError) as revoked_error:
            await service.app.start(
                revoked,
                repository_privacy_context=child_repository,
            )
        assert revoked_error.value.code is PublicErrorCode.SESSION_CONFLICT
        revoked_self_body = _start_request(
            workspace=workspace_child,
            title="Revoked self child",
            mode="create",
        ).model_dump(mode="json", exclude_none=True)
        revoked_self_body["parent_session_id"] = parent.session_id
        with pytest.raises(PublicOperationError) as revoked_self_error:
            await service.app.start(
                StartRequest.model_validate(revoked_self_body),
                repository_privacy_context=child_repository,
            )
        assert revoked_self_error.value.code is PublicErrorCode.SESSION_CONFLICT
