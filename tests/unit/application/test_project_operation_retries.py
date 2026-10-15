"""Crash/retry coverage for journaled project mutations.

Each case models a response being lost after the catalog effect commits.  The retry must use the
same request body and request id, recover the structural result, and avoid applying the effect a
second time.  The interleaving cases below also keep an old in-flight request from selecting a
newer membership or overwriting a newer text amendment.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field, replace
from typing import Any, Literal, cast

import pytest

from builders.ledger_adapters import FixedClock, FixedIds
from finishup.adapters.memory.project_operations import InMemoryProjectOperationJournal
from finishup.application.projects import (
    CreateProjectCommand,
    InMemoryProjectCatalog,
    LinkProjectCommand,
    ProjectAmendCommand,
    ProjectApplication,
    ProjectCommandError,
    ProjectDissolveCommand,
    ProjectGrantCommand,
    ProjectRevokeCommand,
)
from finishup.domain.coordination import (
    CoordinationErrorCode,
    MemberKind,
    ProjectDescriptor,
    ProjectMembership,
    ProjectTextRef,
)
from finishup.domain.privacy import LocalDisclosureSink
from finishup.domain.values import JsonValue
from finishup.ports.start_catalog import TaskSourceProvenance
from finishup.protocol.canonical import canonical_digest, canonical_encode
from finishup.protocol.ids import IdKind, new_id


def _operation_digest(value: JsonValue) -> str:
    return (
        "hmac-sha256:"
        + hmac.new(
            b"project-operation-test-key",
            canonical_encode(value),
            hashlib.sha256,
        ).hexdigest()
    )


def _commitment(seed: str) -> str:
    return "hmac-sha256:" + seed * 64


@dataclass(slots=True)
class _TextStore:
    ids: FixedIds
    writes: list[tuple[str, str, str]] = field(default_factory=lambda: list[tuple[str, str, str]]())

    async def put(
        self,
        project_id: str,
        field: str,
        plaintext: str,
        *,
        owner_task_id: str,
        route_generation: int,
        reserved_object_id: str | None = None,
    ) -> ProjectTextRef:
        self.writes.append((project_id, field, plaintext))
        return ProjectTextRef(
            reserved_object_id or self.ids.new(IdKind.OBJECT),
            canonical_digest({"project_id": project_id, "text": plaintext}),
            len(plaintext.encode("utf-8")),
            owner_task_id,
            route_generation,
            "sha256:" + "a" * 64,
        )

    async def read(self, reference: ProjectTextRef) -> str:
        del reference
        return "redacted"


class _Catalog(InMemoryProjectCatalog):
    def __init__(self, provenance: dict[str, TaskSourceProvenance]) -> None:
        super().__init__()
        self.provenance = provenance

    async def task_source_provenance(self, task_id: str) -> TaskSourceProvenance | None:
        return self.provenance.get(task_id)


@dataclass(slots=True)
class _GrantApproval:
    authorize_calls: int = 0
    consume_calls: int = 0

    async def authorize(
        self,
        project_id: str,
        membership_generation: int,
        action: str,
        audit_record_id: str,
    ) -> bool:
        del project_id, membership_generation, action, audit_record_id
        self.authorize_calls += 1
        return True

    async def consume(
        self,
        project_id: str,
        membership_generation: int,
        action: str,
        audit_record_id: str,
    ) -> None:
        del project_id, membership_generation, action, audit_record_id
        self.consume_calls += 1


class _CompleteFailsOnce(InMemoryProjectOperationJournal):
    """Leave the operation pending after its effect, as a lost response would."""

    def __init__(self) -> None:
        super().__init__()
        self.complete_calls = 0

    async def complete(self, request_id: str, request_digest: str, result_canonical: bytes):
        self.complete_calls += 1
        if self.complete_calls == 1:
            raise RuntimeError("simulated_lost_response")
        return await super().complete(request_id, request_digest, result_canonical)


def _provenance(task_id: str, workspace: str, repository: str) -> TaskSourceProvenance:
    return TaskSourceProvenance(
        task_id,
        workspace,
        _commitment("e"),
        repository,
        1,
        "sha256:" + "b" * 64,
    )


def _allow_text_disclosure(
    owner_task_id: str,
    owner_workspace_commitment: str,
    field: Literal["title", "description"],
    sink: LocalDisclosureSink,
    purpose: str,
) -> bool:
    del owner_task_id, owner_workspace_commitment, field, sink, purpose
    return True


def _allow_coordination_source(
    source_task_id: str,
    source_workspace_commitment: str,
    project_id: str,
) -> bool:
    del source_task_id, source_workspace_commitment, project_id
    return True


def _app_context(
    *,
    journal: InMemoryProjectOperationJournal,
    catalog: _Catalog | None = None,
    owner: str | None = None,
    workspace: str | None = None,
    repository: str | None = None,
) -> tuple[
    ProjectApplication,
    _Catalog,
    _TextStore,
    str,
    str,
    str,
]:
    ids = FixedIds()
    selected_owner = owner or new_id(IdKind.TASK)
    selected_workspace = workspace or _commitment("1")
    selected_repository = repository or _commitment("2")
    default_provenance = _provenance(selected_owner, selected_workspace, selected_repository)
    selected_catalog = catalog or _Catalog({selected_owner: default_provenance})
    text_store = _TextStore(ids)
    approval = _GrantApproval()
    app = ProjectApplication(
        selected_catalog,
        ids=ids,
        clock=FixedClock(),
        text_store=text_store,
        workspace_consent=lambda _workspace: True,
        grant_authorizer=approval,
        text_disclosure_authorizer=_allow_text_disclosure,
        coordination_source_authorizer=_allow_coordination_source,
        operation_journal=journal,
        operation_digest=_operation_digest,
    )
    return (
        app,
        selected_catalog,
        text_store,
        selected_owner,
        selected_workspace,
        selected_repository,
    )


async def _base_project(
    app: ProjectApplication,
    *,
    owner: str,
    workspace: str,
    with_owner_membership: bool = False,
) -> ProjectDescriptor:
    project = await app.create(title="base", owner_task_id=owner)
    if with_owner_membership:
        await app.grant(ProjectGrantCommand(project.project_id, 1, new_id(IdKind.EVENT)))
        await app.link(
            LinkProjectCommand(
                project.project_id,
                MemberKind.TASK,
                owner,
                source_workspace_commitment=workspace,
            )
        )
        await app.grant(ProjectGrantCommand(project.project_id, 2, new_id(IdKind.EVENT)))
    return project


@pytest.mark.anyio
@pytest.mark.parametrize(
    "operation",
    ("amend", "link", "dissolve", "opt_out", "opt_in", "grant", "revoke"),
)
async def test_project_operations_replay_after_effect_before_response(
    operation: str,
) -> None:
    journal = _CompleteFailsOnce()
    app, catalog, text_store, owner, workspace, repository = _app_context(journal=journal)
    request = new_id(IdKind.REQUEST)

    if operation == "amend":
        project = await _base_project(
            app, owner=owner, workspace=workspace, with_owner_membership=True
        )
        command = ProjectAmendCommand(
            project.project_id,
            title="amended",
            owner_task_id=owner,
            owner_route_generation=1,
        )

        async def invoke() -> object:
            return await app.amend(command, request_id=request)

    elif operation == "link":
        project = await _base_project(app, owner=owner, workspace=workspace)
        await app.grant(ProjectGrantCommand(project.project_id, 1, new_id(IdKind.EVENT)))
        command = LinkProjectCommand(
            project.project_id,
            MemberKind.TASK,
            owner,
            source_workspace_commitment=workspace,
        )

        async def invoke() -> object:
            return await app.link(command, request_id=request)

    elif operation == "dissolve":
        project = await _base_project(app, owner=owner, workspace=workspace)
        command = ProjectDissolveCommand(project.project_id, expected_generation=1)

        async def invoke() -> object:
            return await app.dissolve(command, request_id=request)

    elif operation in {"opt_out", "opt_in"}:
        project = await catalog.ensure_repository_project(repository)
        if operation == "opt_in":
            await catalog.set_project_auto_grouping(repository, enabled=False)

        async def invoke() -> object:
            return await app.set_auto_grouping(
                repository, operation == "opt_in", request_id=request
            )

    elif operation == "grant":
        project = await _base_project(app, owner=owner, workspace=workspace)
        command = ProjectGrantCommand(project.project_id, 1, new_id(IdKind.EVENT))

        async def invoke() -> object:
            return await app.grant(command, request_id=request)

    else:
        project = await _base_project(app, owner=owner, workspace=workspace)
        await app.grant(ProjectGrantCommand(project.project_id, 1, new_id(IdKind.EVENT)))
        command = ProjectRevokeCommand(project.project_id, 1, new_id(IdKind.EVENT))

        async def invoke() -> object:
            return await app.revoke(command, request_id=request)

    with pytest.raises(RuntimeError, match="simulated_lost_response"):
        await invoke()

    record = journal.records[request]
    assert not record.completed
    request_digest = record.request_digest
    replay = await invoke()
    assert journal.records[request].completed
    assert journal.records[request].request_digest == request_digest
    assert journal.complete_calls == 2
    assert await invoke() == replay
    assert journal.complete_calls == 2

    if operation == "amend":
        assert replay == await catalog.project_state(project.project_id)
        assert len(text_store.writes) == 2
    elif operation == "link":
        members = await catalog.project_memberships(project.project_id)
        replay_membership = cast(ProjectMembership, replay)
        assert replay_membership in members
        assert sum(item.active for item in members) == 1
        assert replay_membership.membership_generation == 2
    elif operation == "dissolve":
        assert replay == await catalog.project_state(project.project_id)
        state = await catalog.project_state(project.project_id)
        assert state is not None and state.dissolved_at is not None
        assert state.membership_generation == 2
    elif operation in {"opt_out", "opt_in"}:
        assert replay == await catalog.repository_state(repository)
        state = await catalog.repository_state(repository)
        assert state is not None and state.auto_grouping is (operation == "opt_in")
        assert state.membership_generation == (3 if operation == "opt_in" else 2)
    else:
        assert replay == await catalog.coordination_grant(project.project_id, 1)
        grant = await catalog.coordination_grant(project.project_id, 1)
        assert grant is not None
        if operation == "grant":
            assert grant.active
            assert len(catalog.projects[project.project_id].grants) == 1
        else:
            assert not grant.active
            state = await catalog.project_state(project.project_id)
            assert state is not None and state.membership_generation == 2
            assert len(catalog.projects[project.project_id].grants) == 2


@pytest.mark.anyio
async def test_link_retry_does_not_replay_a_later_relink_membership() -> None:
    journal = _CompleteFailsOnce()
    app, catalog, _text_store, owner, workspace, _repository = _app_context(journal=journal)
    project = await _base_project(app, owner=owner, workspace=workspace)
    await app.grant(ProjectGrantCommand(project.project_id, 1, new_id(IdKind.EVENT)))
    command = LinkProjectCommand(
        project.project_id,
        MemberKind.TASK,
        owner,
        source_workspace_commitment=workspace,
    )
    request = new_id(IdKind.REQUEST)

    with pytest.raises(RuntimeError, match="simulated_lost_response"):
        await app.link(command, request_id=request)
    first = next(
        item
        for item in await catalog.project_memberships(project.project_id)
        if item.active and item.member_commitment_or_id == owner
    )
    assert journal.records[request].effect_generation == first.membership_generation

    await app.unlink(
        project_id=project.project_id,
        member_kind=MemberKind.TASK,
        member_commitment_or_id=owner,
    )
    await app.grant(ProjectGrantCommand(project.project_id, 3, new_id(IdKind.EVENT)))
    later = await app.link(command)
    assert later.membership_generation == 4

    replay = await app.link(command, request_id=request)
    assert replay.membership_generation == first.membership_generation
    assert replay.member_commitment_or_id == first.member_commitment_or_id
    assert replay != later
    active = [
        item
        for item in await catalog.project_memberships(project.project_id)
        if item.active and item.member_commitment_or_id == owner
    ]
    assert active == [later]
    assert journal.records[request].completed
    assert journal.complete_calls == 2


@pytest.mark.anyio
async def test_older_amend_retry_cannot_overwrite_a_newer_amend() -> None:
    journal = _CompleteFailsOnce()
    app, catalog, _text_store, owner, workspace, _repository = _app_context(journal=journal)
    project = await _base_project(app, owner=owner, workspace=workspace, with_owner_membership=True)
    old = ProjectAmendCommand(
        project.project_id,
        title="old",
        owner_task_id=owner,
        owner_route_generation=1,
    )
    old_request = new_id(IdKind.REQUEST)
    with pytest.raises(RuntimeError, match="simulated_lost_response"):
        await app.amend(old, request_id=old_request)

    newer = ProjectAmendCommand(
        project.project_id,
        title="new",
        owner_task_id=owner,
        owner_route_generation=1,
    )
    newer_request = new_id(IdKind.REQUEST)
    current = await app.amend(newer, request_id=newer_request)
    assert current.title_ref is not None

    with pytest.raises(ProjectCommandError) as error:
        await app.amend(old, request_id=old_request)
    assert error.value.code is CoordinationErrorCode.SELECTOR_CONFLICT
    assert await catalog.project_state(project.project_id) == current
    assert journal.records[old_request].phase == "effect_pending"


class _RotatingCatalog(_Catalog):
    def __init__(self, provenance: dict[str, TaskSourceProvenance]) -> None:
        super().__init__(provenance)
        self.route_generation = 1

    async def task_route_generation(self, task_id: str) -> int:
        del task_id
        return self.route_generation

    async def task_source_provenance(self, task_id: str) -> TaskSourceProvenance | None:
        provenance = self.provenance.get(task_id)
        return (
            None
            if provenance is None
            else replace(provenance, route_generation=self.route_generation)
        )


class _FailTextReadyOnceJournal(InMemoryProjectOperationJournal):
    """Leave a reserved row after object finalization, as a crash before text_ready would."""

    def __init__(self) -> None:
        super().__init__()
        self.text_ready_attempts = 0

    async def advance(
        self,
        request_id: str,
        request_digest: str,
        *,
        phase: Literal["text_ready", "effect_pending"],
        **kwargs: object,
    ):
        if phase == "text_ready":
            self.text_ready_attempts += 1
            if self.text_ready_attempts == 1:
                raise RuntimeError("simulated_crash_before_text_ready")
        return await super().advance(
            request_id,
            request_digest,
            phase=phase,
            **cast(Any, kwargs),
        )


class _RotateAfterTextReadyJournal(InMemoryProjectOperationJournal):
    def __init__(self, catalog: _RotatingCatalog) -> None:
        super().__init__()
        self.catalog = catalog
        self.complete_calls = 0

    async def advance(
        self,
        request_id: str,
        request_digest: str,
        *,
        phase: Literal["text_ready", "effect_pending"],
        **kwargs: object,
    ):
        result = await super().advance(request_id, request_digest, phase=phase, **cast(Any, kwargs))
        if phase == "text_ready":
            self.catalog.route_generation = 2
        return result

    async def complete(self, request_id: str, request_digest: str, result_canonical: bytes):
        self.complete_calls += 1
        return await super().complete(request_id, request_digest, result_canonical)


@pytest.mark.anyio
async def test_amend_rejects_route_rotation_after_text_ready() -> None:
    owner = new_id(IdKind.TASK)
    workspace = _commitment("1")
    repository = _commitment("2")
    catalog = _RotatingCatalog({owner: _provenance(owner, workspace, repository)})
    journal = _RotateAfterTextReadyJournal(catalog)
    app, _catalog, text_store, _owner, _workspace, _repository = _app_context(
        journal=journal,
        catalog=catalog,
        owner=owner,
        workspace=workspace,
        repository=repository,
    )
    project = await _base_project(app, owner=owner, workspace=workspace, with_owner_membership=True)
    before = await catalog.project_state(project.project_id)
    assert before is not None
    request = new_id(IdKind.REQUEST)
    command = ProjectAmendCommand(
        project.project_id,
        title="stale route",
        owner_task_id=owner,
        owner_route_generation=1,
    )

    with pytest.raises(ProjectCommandError) as error:
        await app.amend(command, request_id=request)
    assert error.value.code is CoordinationErrorCode.GENERATION_MISMATCH
    after = await catalog.project_state(project.project_id)
    assert after == before
    assert len(text_store.writes) == 2
    assert not journal.records[request].completed


@pytest.mark.anyio
@pytest.mark.parametrize("operation", ("create", "amend"))
async def test_reserved_text_retry_refuses_route_rotation_before_rewrite(
    operation: str,
) -> None:
    """A finalized reserved object must not be rewritten under a rotated route."""

    owner = new_id(IdKind.TASK)
    workspace = _commitment("1")
    repository = _commitment("2")
    catalog = _RotatingCatalog({owner: _provenance(owner, workspace, repository)})
    journal = _FailTextReadyOnceJournal()
    app, _catalog, text_store, _owner, _workspace, _repository = _app_context(
        journal=journal,
        catalog=catalog,
        owner=owner,
        workspace=workspace,
        repository=repository,
    )

    if operation == "create":
        command: CreateProjectCommand | ProjectAmendCommand = CreateProjectCommand(
            "reserved create",
            owner_task_id=owner,
        )

        async def invoke() -> object:
            return await app.create(command, request_id=request)

        expected_writes_after_first_attempt = 1
    else:
        project = await _base_project(
            app,
            owner=owner,
            workspace=workspace,
            with_owner_membership=True,
        )
        command = ProjectAmendCommand(
            project.project_id,
            title="reserved amend",
            owner_task_id=owner,
        )

        async def invoke() -> object:
            return await app.amend(command, request_id=request)

        expected_writes_after_first_attempt = 2

    request = new_id(IdKind.REQUEST)
    with pytest.raises(RuntimeError, match="simulated_crash_before_text_ready"):
        await invoke()
    record = journal.records[request]
    assert record.phase == "reserved"
    assert record.title_ref is None
    assert record.owner_task_id == owner
    assert record.owner_route_generation == 1
    assert len(text_store.writes) == expected_writes_after_first_attempt

    # The live provenance has rotated too, so current-route admission accepts generation 2.  The
    # retry must still use the reservation-time generation and fail before calling ``put`` again.
    catalog.route_generation = 2
    with pytest.raises(ProjectCommandError) as error:
        await invoke()
    assert error.value.code is CoordinationErrorCode.GENERATION_MISMATCH
    assert journal.records[request].phase == "reserved"
    assert journal.records[request].title_ref is None
    assert len(text_store.writes) == expected_writes_after_first_attempt
