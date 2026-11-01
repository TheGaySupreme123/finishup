"""Focused exact-consent tests for local project coordination grants."""

from __future__ import annotations

from pathlib import Path

import pytest

from builders.ledger_adapters import FixedIds
from finishup.application.projects import (
    InMemoryProjectCatalog,
    ProjectApplication,
    ProjectCommandError,
    ProjectGrantCommand,
)
from finishup.protocol.canonical import JsonValue
from finishup.protocol.ids import IdKind, new_id
from finishup.service.elevated_bootstrap import (
    ElevatedBootstrapError,
    PendingElevatedConsent,
    consume_project_coordination_authorization,
    load_pending,
    load_project_coordination_audit_record_id,
    load_project_coordination_authorization,
    prepare_pending,
    project_coordination_grant_binding,
    project_coordination_target_digest,
    record_project_coordination_authorization,
)
from finishup.service.project_coordination_authority import ProjectCoordinationGrantAuthority


def _binding() -> tuple[str, int, str, dict[str, JsonValue]]:
    project_id = new_id(IdKind.PROJECT)
    generation = 7
    audit_record_id = new_id(IdKind.EVENT)
    binding = project_coordination_grant_binding(
        project_id=project_id,
        membership_generation=generation,
        audit_record_id=audit_record_id,
    )
    return project_id, generation, audit_record_id, binding


def _prepare(state: Path) -> tuple[PendingElevatedConsent, str, int, str]:
    project_id, generation, audit_record_id, binding = _binding()
    digest = project_coordination_target_digest(binding)
    pending = prepare_pending(
        "project_coordination_grant",
        target_digest=digest,
        coordination_binding=binding,
        _state=state,
    )
    return pending, project_id, generation, audit_record_id


def test_project_grant_handoff_is_exact_and_one_use(tmp_path: Path) -> None:
    pending, project_id, generation, audit_record_id = _prepare(tmp_path / "state")
    authorization = record_project_coordination_authorization(pending, _state=tmp_path / "state")

    assert (
        load_project_coordination_authorization(
            project_id=project_id,
            membership_generation=generation,
            audit_record_id=audit_record_id,
            _state=tmp_path / "state",
        )
        == authorization
    )
    assert (
        load_project_coordination_authorization(
            project_id=project_id,
            membership_generation=generation + 1,
            audit_record_id=audit_record_id,
            _state=tmp_path / "state",
        )
        is None
    )

    consume_project_coordination_authorization(authorization, _state=tmp_path / "state")
    assert (
        load_project_coordination_authorization(
            project_id=project_id,
            membership_generation=generation,
            audit_record_id=audit_record_id,
            _state=tmp_path / "state",
        )
        is None
    )
    with pytest.raises(ElevatedBootstrapError, match="project_coordination_authorization_mismatch"):
        consume_project_coordination_authorization(authorization, _state=tmp_path / "state")


@pytest.mark.anyio
async def test_authority_prepares_then_accepts_only_approved_exact_binding(tmp_path: Path) -> None:
    state = tmp_path / "state"
    project_id, generation, audit_record_id, binding = _binding()
    authority = ProjectCoordinationGrantAuthority(state_path=state)

    # The first ordinary project command creates a pending request but does not authorize it.
    assert (await authority.authorize(project_id, generation, "grant", audit_record_id)) is False
    pending = load_pending(_state=state)
    assert pending is not None
    assert pending.operation == "project_coordination_grant"
    assert pending.coordination_binding == binding

    # No caller supplied label or nearby generation can use the pending request.
    assert (
        await authority.authorize(project_id, generation + 1, "grant", audit_record_id)
    ) is False
    assert (await authority.authorize(project_id, generation, "revoke", audit_record_id)) is False

    approved = record_project_coordination_authorization(pending, _state=state)
    assert await authority.authorize(project_id, generation, "grant", audit_record_id)

    # The application calls this only after its catalog commit.  Replaying cleanup is safe and
    # leaves no reusable authorization artifact.
    await authority.consume(project_id, generation, "grant", audit_record_id)
    assert (
        load_project_coordination_authorization(
            project_id=project_id,
            membership_generation=generation,
            audit_record_id=audit_record_id,
            _state=state,
        )
        is None
    )
    assert approved.target_digest == project_coordination_target_digest(binding)


@pytest.mark.anyio
async def test_project_application_commits_before_consuming_and_retries_idempotently(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    project_id = new_id(IdKind.PROJECT)
    catalog = InMemoryProjectCatalog()
    await catalog.create_general_project(project_id)
    authority = ProjectCoordinationGrantAuthority(state_path=state)
    application = ProjectApplication(
        catalog,
        ids=FixedIds(),
        grant_authorizer=authority,
    )
    command = ProjectGrantCommand(project_id, 1)

    with pytest.raises(ProjectCommandError, match="grant_required"):
        await application.grant(command)
    pending = load_pending(_state=state)
    assert pending is not None
    assert pending.coordination_binding is not None
    audit_record_id = pending.coordination_binding["audit_record_id"]
    assert type(audit_record_id) is str
    assert (
        load_project_coordination_audit_record_id(
            project_id=project_id,
            membership_generation=1,
            _state=state,
        )
        == audit_record_id
    )
    record_project_coordination_authorization(pending, _state=state)

    grant = await application.grant(command)
    assert grant.active
    assert (
        load_project_coordination_authorization(
            project_id=project_id,
            membership_generation=1,
            audit_record_id=audit_record_id,
            _state=state,
        )
        is None
    )
    # A response lost after the catalog commit must replay the durable grant without approval.
    assert await application.grant(command) == grant
