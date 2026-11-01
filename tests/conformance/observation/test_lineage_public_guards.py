"""Public admission guards for service-stamped lineage lifecycle families."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from builders.multi_agent import multi_agent_service
from finishup.ports.control import RepositoryPrivacyContext
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.ids import IdKind, new_id
from finishup.protocol.models import PublishWorkRequest, StartRequest

pytestmark = pytest.mark.anyio

_REPOSITORY = RepositoryPrivacyContext("hmac-sha256:" + "e" * 64, "git_common_root")


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _workspace(root: Path) -> Path:
    root.mkdir()
    subprocess.run(["git", "init", "--quiet", str(root)], check=True, capture_output=True)
    return root.resolve()


def _identity() -> dict[str, object]:
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": new_id(IdKind.REQUEST),
        # A service-looking actor must not bypass the ordinary public writer boundary.
        "actor": {"actor_id": "yoetz:lineage-service", "actor_type": "yoetz_engine"},
        "client": {
            "kind": "cooperative_agent",
            "version": "0.1.0",
            "integration": "cooperative_mcp",
        },
    }


@pytest.mark.parametrize(
    ("event_name", "payload"),
    [
        (
            "delegation_declared",
            {
                "child_task_id": "tsk_00000000-0000-4000-8000-000000000901",
                "handle_digest": "sha256:" + "a" * 64,
                "depth": 1,
            },
        ),
        ("child_dependencies_recorded", {"children": []}),
        ("work_abandoned", {"service_stamped": True, "reason_code": "contact_lost"}),
    ],
)
async def test_public_publish_rejects_service_stamped_lineage_families(
    tmp_path: Path,
    event_name: str,
    payload: dict[str, object],
) -> None:
    workspace = _workspace(tmp_path / "workspace")
    async with multi_agent_service(tmp_path / "state") as service:
        app = service.app
        started = await app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create",
                    "task_title": "Service-only guard",
                    "workspace_ref": str(workspace),
                    "external_ref": "service-only-guard",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        request = PublishWorkRequest.model_validate(
            {
                **_identity(),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": started.frontier.model_dump(mode="json"),
                "event_drafts": [
                    {
                        "event_id": new_id(IdKind.EVENT),
                        "schema": {"name": event_name, "version": "1.0.0"},
                        "occurred_at": "2026-09-05T12:00:00.000Z",
                        "causal_parents": [],
                        "payload": payload,
                        "artifact_refs": [],
                        "evidence_refs": [],
                    }
                ],
            }
        )
        with pytest.raises(PublicOperationError) as caught:
            await app.publish_work(request, repository_privacy_context=_REPOSITORY)
        assert caught.value.code is PublicErrorCode.INVALID_REQUEST
        assert caught.value.safe_details["reason_code"] == "event_family_not_admitted"
        assert await app.start_catalog.task_route(started.task_id) is not None
