"""Synthetic public-workflow qualification for self-registration, separate from native proof."""

from __future__ import annotations

import subprocess
from collections.abc import Mapping
from pathlib import Path

import pytest

from builders.multi_agent import multi_agent_service
from yoetz.application.publish_work import PublishWorkInternalResult
from yoetz.application.start import StartInternalResult
from yoetz.ports.control import RepositoryPrivacyContext
from yoetz.ports.ledger import CheckCommitResult
from yoetz.protocol.errors import PublicErrorCode, PublicOperationError
from yoetz.protocol.ids import IdKind, new_id
from yoetz.protocol.models import (
    CheckRequest,
    PublishWorkRequest,
    ReceiptRequest,
    StartRequest,
    StatusLineagePageModel,
    StatusRequest,
)

pytestmark = pytest.mark.anyio

_REPOSITORY = RepositoryPrivacyContext("hmac-sha256:" + "f" * 64, "git_common_root")


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
        "actor": {"actor_id": "harness:self-registration", "actor_type": "harness"},
        "client": {
            "kind": "cooperative_agent",
            "version": "0.1.0",
            "integration": "cooperative_mcp",
        },
    }


async def test_self_registration_pending_acceptance_closure_and_receipt_rollup(
    tmp_path: Path,
) -> None:
    workspace = _workspace(tmp_path / "workspace")
    async with multi_agent_service(tmp_path / "state") as service:
        parent = await service.app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create",
                    "task_title": "Self-registration parent",
                    "workspace_ref": str(workspace),
                    "external_ref": "self-registration-parent",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        request = StartRequest.model_validate(
            {
                **_identity(),
                "mode": "create",
                "task_title": "Self-registered pending child",
                "workspace_ref": str(workspace),
                "external_ref": "self-registration-child",
                "parent_session_id": parent.session_id,
                "requested_view": "compact",
            }
        )
        child = await service.app.start(
            request,
            repository_privacy_context=_REPOSITORY,
        )
        replay = await service.app.start(request, repository_privacy_context=_REPOSITORY)
        assert replay.task_id == child.task_id
        assert replay.session_id == child.session_id
        assert replay.acceptance == "pending"
        assert child.acceptance == "pending"
        lineage = await service.app.start_catalog.task_lineage(child.task_id)
        assert lineage is not None
        assert lineage.parent_task_id == parent.task_id
        assert lineage.origin is not None and lineage.origin.value == "self_registered"
        assert lineage.acceptance is not None and lineage.acceptance.value == "pending"

        async def status(task: StartInternalResult, view: str = "compact"):
            return await service.app.status(
                StatusRequest.model_validate(
                    {
                        **_identity(),
                        "session_id": task.session_id,
                        "writer_id": task.writer_id,
                        "view": view,
                        "limit": "10",
                    }
                ),
                repository_privacy_context=_REPOSITORY,
            )

        async def publish(task: StartInternalResult, name: str, payload: Mapping[str, object]):
            current = await status(task)
            result = await service.app.publish_work(
                PublishWorkRequest.model_validate(
                    {
                        **_identity(),
                        "session_id": task.session_id,
                        "writer_id": task.writer_id,
                        "expected_frontier": dict(current.head_frontier.as_wire().items()),
                        "event_drafts": [
                            {
                                "event_id": new_id(IdKind.EVENT),
                                "schema": {"name": name, "version": "1.0.0"},
                                "occurred_at": "2026-09-05T12:00:00.000Z",
                                "causal_parents": [],
                                "payload": dict(payload),
                                "artifact_refs": [],
                                "evidence_refs": [],
                            }
                        ],
                    }
                ),
                repository_privacy_context=_REPOSITORY,
            )
            assert isinstance(result, PublishWorkInternalResult)
            assert result.task_id == task.task_id

        async def check(task: StartInternalResult):
            current = await status(task)
            result = await service.app.check(
                CheckRequest.model_validate(
                    {
                        **_identity(),
                        "session_id": task.session_id,
                        "writer_id": task.writer_id,
                        "expected_frontier": dict(current.head_frontier.as_wire().items()),
                        "mode": "deterministic_only",
                        "max_findings": "10",
                        "policy_packs": ["work-integrity/0.3.0"],
                    }
                ),
                repository_privacy_context=_REPOSITORY,
            )
            assert isinstance(result, CheckCommitResult)
            return result

        async def receipt(task: StartInternalResult):
            current = await status(task)
            return await service.app.receipt(
                ReceiptRequest.model_validate(
                    {
                        **_identity(),
                        "task_id": task.task_id,
                        "session_id": task.session_id,
                        "writer_id": task.writer_id,
                        "expected_frontier": dict(current.head_frontier.as_wire().items()),
                        "format": "json",
                        "include": "standard",
                        "redaction_profile": "default_local_export",
                    }
                ),
                repository_privacy_context=_REPOSITORY,
            )

        async def child_row():
            result = await status(parent, "lineage")
            assert isinstance(result.page, StatusLineagePageModel)
            (row,) = result.page.children
            assert row.task_id == child.task_id
            assert row.origin == "self_registered"
            return row

        assert child.task_id != parent.task_id
        assert child.session_id != parent.session_id
        assert child.writer_id != parent.writer_id
        pending = await child_row()
        assert pending.acceptance == "pending"
        assert pending.rollup_state == "annotation"

        # Pending self-registration is visible, but is not yet a parent dependency.
        sweep = service.app.observation_sweep
        assert sweep is not None
        await sweep()
        pending_check = await check(parent)
        assert pending_check.children is not None
        (pending_preview,) = pending_check.children.items
        assert pending_preview.acceptance.value == "pending"
        assert pending_preview.rollup_state.value == "annotation"
        assert pending_preview.blocking_conditions == ()

        await publish(parent, "child_accepted", {"child_task_id": child.task_id})
        accepted = await child_row()
        assert accepted.acceptance == "accepted"
        assert accepted.work_state == "open"
        assert accepted.rollup_state != "clean"

        await publish(
            child,
            "plan_published",
            {
                "plan_version": 1,
                "summary": "Bounded child review with no material change",
                "obligation_refs": [],
                "no_obligations_reason": "no_material_change",
            },
        )
        await check(child)
        open_receipt = await receipt(child)
        assert open_receipt.task_id == child.task_id
        assert (await child_row()).work_state == "open"  # A receipt cannot close work.

        await publish(child, "work_closed", {})
        await check(child)
        closed_receipt = await receipt(child)
        assert closed_receipt.receipt_digest != open_receipt.receipt_digest
        closed = await child_row()
        assert closed.acceptance == "accepted"
        assert closed.work_state == "closed"

        # A service-owned manifest and a new parent check incorporate the child result.
        await sweep()
        parent_check = await check(parent)
        assert parent_check.children is not None
        (preview,) = parent_check.children.items
        assert preview.child_task_id == child.task_id
        assert preview.origin.value == "self_registered"
        assert preview.acceptance.value == "accepted"
        assert preview.work_state.value == "closed"
        parent_receipt = await receipt(parent)
        assert isinstance(parent_receipt.document, Mapping)
        children = parent_receipt.document["children"]
        assert isinstance(children, Mapping)
        rows = children["children"]
        assert isinstance(rows, list)
        (row,) = rows
        assert isinstance(row, Mapping)
        assert row["child_task_id"] == child.task_id
        assert row["tested_manifest_ref"] is not None
        assert row["outcome"] != "clean"  # Local-only review remains coverage-bounded.
        assert parent_receipt.conclusion != "no_unresolved_deterministic_findings"


async def test_real_sqlite_rejects_historical_and_closed_parent_admission(
    tmp_path: Path,
) -> None:
    workspace = _workspace(tmp_path / "workspace")
    async with multi_agent_service(tmp_path / "state") as service:
        parent = await service.app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create",
                    "task_title": "Historical parent",
                    "workspace_ref": str(workspace),
                    "external_ref": "historical-parent",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        rotated = await service.app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create_or_attach",
                    "task_title": "Historical parent resumed",
                    "workspace_ref": str(workspace),
                    "external_ref": "historical-parent",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        assert rotated.task_id == parent.task_id
        assert rotated.session_id != parent.session_id

        for mode in ("delegate", "create"):
            request_body: dict[str, object] = {
                **_identity(),
                "mode": mode,
                "task_title": f"Historical child {mode}",
                "requested_view": "compact",
            }
            if mode == "delegate":
                request_body["session_id"] = parent.session_id
            else:
                request_body["parent_session_id"] = parent.session_id
                request_body["workspace_ref"] = str(workspace)
                request_body["external_ref"] = "historical-self-registration"
            with pytest.raises(PublicOperationError) as caught:
                await service.app.start(
                    StartRequest.model_validate(request_body),
                    repository_privacy_context=_REPOSITORY,
                )
            # A delegated selector is rejected by the start catalog before the lineage
            # coordinator can inspect the retired route.  Self-registration reaches the
            # coordinator and receives its typed active-session refusal.
            expected = (
                PublicErrorCode.SESSION_NOT_FOUND
                if mode == "delegate"
                else PublicErrorCode.SESSION_CONFLICT
            )
            assert caught.value.code is expected, mode

        closed = await service.app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create",
                    "task_title": "Closed parent",
                    "workspace_ref": str(workspace),
                    "external_ref": "closed-parent",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        close_request = PublishWorkRequest.model_validate(
            {
                **_identity(),
                "session_id": closed.session_id,
                "writer_id": closed.writer_id,
                "expected_frontier": closed.frontier.model_dump(mode="json"),
                "event_drafts": [
                    {
                        "event_id": new_id(IdKind.EVENT),
                        "schema": {"name": "work_closed", "version": "1.0.0"},
                        "occurred_at": "2026-09-05T12:00:00.000Z",
                        "causal_parents": [],
                        "payload": {},
                        "artifact_refs": [],
                        "evidence_refs": [],
                    }
                ],
            }
        )
        await service.app.publish_work(close_request, repository_privacy_context=_REPOSITORY)

        for mode in ("delegate", "create"):
            request_body = {
                **_identity(),
                "mode": mode,
                "task_title": f"Closed child {mode}",
                "requested_view": "compact",
            }
            if mode == "delegate":
                request_body["session_id"] = closed.session_id
            else:
                request_body["parent_session_id"] = closed.session_id
                request_body["workspace_ref"] = str(workspace)
                request_body["external_ref"] = "closed-self-registration"
            with pytest.raises(PublicOperationError) as caught:
                await service.app.start(
                    StartRequest.model_validate(request_body),
                    repository_privacy_context=_REPOSITORY,
                )
            assert caught.value.code is PublicErrorCode.SESSION_CONFLICT
