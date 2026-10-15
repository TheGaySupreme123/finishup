"""Issue #509: actual Git worktrees compose identity, liveness, and consent."""

from __future__ import annotations

import hashlib
import hmac
import subprocess
from pathlib import Path

import pytest

from builders.multi_agent import multi_agent_service
from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.adapters.repository_identity import resolve_repository_privacy_context
from finishup.domain.coordination import SessionHealth
from finishup.ports.control import WorkspaceLocator
from finishup.protocol.ids import IdKind, new_id
from finishup.protocol.models import StartRequest

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class _SyntheticIdentityKey:
    def mac(self, domain: bytes, message: bytes) -> str:
        return (
            "hmac-sha256:"
            + hmac.new(
                b"synthetic-worktree-conformance-key", domain + message, hashlib.sha256
            ).hexdigest()
        )


def _git(*args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=FinishUP Test", "-c", "user.email=test@finishup.invalid", *args],
        check=True,
        capture_output=True,
    )


def _start(workspace: Path) -> StartRequest:
    return StartRequest.model_validate(
        {
            "protocol_version": "0.1",
            "schema_version": "1.0.0",
            "request_id": new_id(IdKind.REQUEST),
            "actor": {"actor_id": "harness:worktree-conformance", "actor_type": "harness"},
            "client": {
                "kind": "test_client",
                "version": "0.1.0",
                "integration": "cooperative_mcp",
            },
            "mode": "create_or_attach",
            "task_title": "Synthetic worktree participant",
            "workspace_ref": str(workspace.resolve()),
            "external_ref": "worktree-509",
            "requested_view": "compact",
        }
    )


async def test_worktrees_share_live_project_but_require_independent_source_consent(
    tmp_path: Path,
) -> None:
    primary, linked = tmp_path / "primary", tmp_path / "linked"
    _git("init", "--quiet", str(primary))
    _git("-C", str(primary), "commit", "--quiet", "--allow-empty", "-m", "synthetic base")
    _git("-C", str(primary), "worktree", "add", "--quiet", "-b", "linked", str(linked))
    assert (primary / ".git").is_dir()
    assert (linked / ".git").is_file()
    identity = _SyntheticIdentityKey()
    contexts = tuple(
        [
            await resolve_repository_privacy_context(WorkspaceLocator(str(path)), identity)
            for path in (primary, linked)
        ]
    )
    assert contexts[0] == contexts[1]
    assert contexts[0].identity_kind == "git_common_root"

    async with multi_agent_service(tmp_path / "state") as service:
        app = service.app
        first = await app.start(_start(primary), repository_privacy_context=contexts[0])
        await app.start_catalog.record_session_state(
            first.task_id,
            first.session_id,
            health=SessionHealth.ENDED,
            changed_at=service.clock.now_utc(),
        )
        second = await app.start(_start(linked), repository_privacy_context=contexts[1])
        assert first.task_id != second.task_id
        assert await app.start_catalog.repository_state(contexts[0].commitment) is None

        resumed = await app.start(_start(primary), repository_privacy_context=contexts[0])
        assert resumed.task_id == first.task_id
        project = await app.start_catalog.repository_state(contexts[0].commitment)
        assert project is not None
        assert await app.start_catalog.list_task_project_ids(first.task_id) == (project.project_id,)
        assert await app.start_catalog.list_task_project_ids(second.task_id) == (
            project.project_id,
        )

        local = LocalObservationStore(_state=service.root / "state")
        first_workspace = local.workspace_commitment(str(primary.resolve()))
        second_workspace = local.workspace_commitment(str(linked.resolve()))
        assert first_workspace != second_workspace
        local.grant_consent(first_workspace)
        projects = app.project_application
        assert projects is not None
        assert (
            await projects.live_admitted_member_task_ids(first.task_id, project=project.project_id)
            == ()
        )

        local.grant_consent(second_workspace)
        assert await projects.live_admitted_member_task_ids(
            first.task_id, project=project.project_id
        ) == (second.task_id,)
        assert await projects.live_admitted_member_task_ids(
            second.task_id, project=project.project_id
        ) == (first.task_id,)

        await app.start_catalog.record_session_state(
            second.task_id,
            second.session_id,
            health=SessionHealth.ENDED,
            changed_at=service.clock.now_utc(),
        )
        assert (
            await projects.live_admitted_member_task_ids(first.task_id, project=project.project_id)
            == ()
        )
