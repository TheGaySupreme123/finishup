"""Automatic admission preserves selectors, dormant work, and grouping preferences."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from builders.multi_agent import multi_agent_service
from finishup.domain.coordination import SessionHealth, WorkState
from finishup.ports.control import RepositoryPrivacyContext
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.ids import IdKind, new_id
from finishup.protocol.models import StartRequest

pytestmark = pytest.mark.anyio
_REPOSITORY = RepositoryPrivacyContext("hmac-sha256:" + "f" * 64, "git_common_root")


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _request(workspace: Path, external: str, **selectors: object) -> StartRequest:
    return StartRequest.model_validate(
        {
            "protocol_version": "0.1",
            "schema_version": "1.0.0",
            "request_id": new_id(IdKind.REQUEST),
            "actor": {"actor_id": "harness:admission", "actor_type": "harness"},
            "client": {
                "kind": "cooperative_agent",
                "version": "0.1.0",
                "integration": "cooperative_mcp",
            },
            "mode": "create_or_attach",
            "task_title": "Admission matrix",
            "workspace_ref": str(workspace),
            "external_ref": external,
            "requested_view": "compact",
            **selectors,
        }
    )


async def test_dormant_unbound_task_does_not_select_or_group_new_work(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    async with multi_agent_service(tmp_path / "state") as service:
        first = await service.app.start(
            _request(workspace, "dormant"), repository_privacy_context=_REPOSITORY
        )
        await service.app.start_catalog.record_session_state(
            first.task_id,
            first.session_id,
            health=SessionHealth.ENDED,
            changed_at=service.clock.now_utc(),
        )
        second = await service.app.start(
            _request(workspace, "new-work"), repository_privacy_context=_REPOSITORY
        )
        assert second.task_id != first.task_id
        assert await service.app.start_catalog.task_work_state(first.task_id) is WorkState.OPEN
        assert await service.app.start_catalog.list_task_project_ids(first.task_id) == ()
        assert await service.app.start_catalog.list_task_project_ids(second.task_id) == ()
        assert await service.app.start_catalog.repository_state(_REPOSITORY.commitment) is None
        assert (await service.app.start_catalog.resolve_route(first.session_id)) is not None


async def test_auto_grouping_off_admits_second_live_task_without_project(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    async with multi_agent_service(tmp_path / "state") as service:
        projects = service.app.project_application
        assert projects is not None
        await projects.opt_out(_REPOSITORY.commitment)
        first = await service.app.start(
            _request(workspace, "host-one"), repository_privacy_context=_REPOSITORY
        )
        second = await service.app.start(
            _request(workspace, "host-two"), repository_privacy_context=_REPOSITORY
        )
        assert first.task_id != second.task_id
        for task in (first, second):
            sessions = await service.app.start_catalog.task_session_states(task.task_id)
            assert any(item.health is SessionHealth.ACTIVE for item in sessions)
            assert await service.app.start_catalog.list_task_project_ids(task.task_id) == ()
        assert await service.app.start_catalog.repository_state(_REPOSITORY.commitment) is None


async def test_explicit_create_collision_is_distinct_from_automatic_pair_resume(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    async with multi_agent_service(tmp_path / "state") as service:
        first = await service.app.start(
            _request(workspace, "same-pair"), repository_privacy_context=_REPOSITORY
        )
        with pytest.raises(PublicOperationError) as refused:
            await service.app.start(
                _request(workspace, "same-pair", mode="create"),
                repository_privacy_context=_REPOSITORY,
            )
        assert refused.value.code is PublicErrorCode.SESSION_CONFLICT
        assert refused.value.safe_details == {"reason_code": "workspace_task_exists"}
        resumed = await service.app.start(
            _request(workspace, "same-pair"), repository_privacy_context=_REPOSITORY
        )
        assert resumed.task_id == first.task_id
        assert resumed.session_id != first.session_id
        assert await service.app.start_catalog.list_repository_task_ids(_REPOSITORY.commitment) == (
            first.task_id,
        )


@pytest.mark.parametrize(
    "conflict", ("handle_session", "handle_pair", "session_pair", "parent_session")
)
async def test_disagreeing_public_selectors_refuse_before_child_mutation(
    tmp_path: Path, conflict: str
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    async with multi_agent_service(tmp_path / "state") as service:
        parent = await service.app.start(
            _request(workspace, "parent"), repository_privacy_context=_REPOSITORY
        )
        other = await service.app.start(
            _request(workspace, "other"), repository_privacy_context=_REPOSITORY
        )
        delegated = await service.app.start(
            _request(workspace, "child", mode="delegate", session_id=parent.session_id),
            repository_privacy_context=_REPOSITORY,
        )
        assert delegated.attach_handle is not None
        before = await service.app.start_catalog.list_child_task_ids(parent.task_id)
        handle = delegated.as_wire()["attach_handle"]
        with pytest.raises(ValidationError, match="selector_conflict"):
            _request(
                workspace,
                "child",
                mode="attach",
                attach_handle=handle,
                parent_session_id=parent.session_id,
            )
        if conflict == "handle_session":
            request = _request(
                workspace, "child", mode="attach", attach_handle=handle, session_id=other.session_id
            )
        elif conflict == "handle_pair":
            request = _request(workspace, "other", mode="attach", attach_handle=handle)
        elif conflict == "session_pair":
            request = _request(workspace, "other", mode="attach", session_id=parent.session_id)
        else:
            request = _request(
                workspace,
                "self-child",
                parent_session_id=parent.session_id,
                session_id=other.session_id,
            )
        with pytest.raises(PublicOperationError) as refused:
            await service.app.start(request, repository_privacy_context=_REPOSITORY)
        assert refused.value.code is PublicErrorCode.SESSION_CONFLICT
        assert refused.value.safe_details == {
            "reason_code": "selector_conflict",
            "continuation": "lineage_state_refresh",
        }
        assert await service.app.start_catalog.list_child_task_ids(parent.task_id) == before
        child_route = await service.app.start_catalog.task_route(delegated.attach_handle.task_id)
        assert child_route is not None
        attached = await service.app.start(
            _request(
                workspace,
                "child",
                mode="attach",
                attach_handle=handle,
                session_id=child_route.session_id,
            ),
            repository_privacy_context=_REPOSITORY,
        )
        assert attached.task_id == delegated.attach_handle.task_id
        assert attached.task_id not in (parent.task_id, other.task_id)
