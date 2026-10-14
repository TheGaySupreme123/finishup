"""Host correlation cannot strand an otherwise valid child attach capability."""

from __future__ import annotations

import subprocess
from collections.abc import Mapping
from pathlib import Path

import pytest

from builders.multi_agent import multi_agent_service
from finishup.domain.host_lineage import host_lineage_from_payload
from finishup.domain.observation import ObservationSource
from finishup.domain.values import JsonValue
from finishup.ports.control import RepositoryPrivacyContext
from finishup.ports.host_lineage import HostLineageRegistryError, HostLineageRegistryReason
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.ids import IdKind, new_id
from finishup.protocol.models import StartRequest

pytestmark = pytest.mark.anyio
_REPOSITORY = RepositoryPrivacyContext("hmac-sha256:" + "d" * 64, "git_common_root")


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _request(**values: object) -> StartRequest:
    return StartRequest.model_validate(
        {
            "protocol_version": "0.1",
            "schema_version": "1.0.0",
            "request_id": new_id(IdKind.REQUEST),
            "actor": {"actor_id": "harness:attach-correlation", "actor_type": "harness"},
            "client": {
                "kind": "cooperative_agent",
                "version": "0.3.0",
                "integration": "cooperative_mcp",
            },
            "task_title": "correlated child",
            "requested_view": "compact",
            **values,
        }
    )


async def test_conflicting_annotation_is_refused_before_handle_consumption(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    subprocess.run(["git", "init", "--quiet", str(workspace)], check=True, capture_output=True)
    async with multi_agent_service(tmp_path / "state") as service:
        app = service.app
        parent = await app.start(
            _request(mode="create", workspace_ref=str(workspace.resolve()), external_ref="parent"),
            repository_privacy_context=_REPOSITORY,
        )
        delegated = await app.start(
            _request(mode="delegate", session_id=parent.session_id),
            repository_privacy_context=_REPOSITORY,
        )
        registry = app.host_lineage_registry
        lineage = app.lineage
        assert registry is not None and lineage is not None
        observation = host_lineage_from_payload(
            "codex", "SubagentStart", {"subagent_id": "worker", "parent_tool_call_id": "call-a"}
        )
        assert observation is not None
        annotation = await registry.record_host_lineage_observation(
            parent.task_id,
            observation,
            observed_session_commitment="hmac-sha256:" + "a" * 64,
            source=ObservationSource.CODEX_HOOK,
        )
        before = await app.start_catalog.resolve_route(delegated.session_id)
        with pytest.raises(PublicOperationError) as caught:
            await app.start(
                _request(
                    mode="attach",
                    attach_handle=delegated.as_wire()["attach_handle"],
                    correlation_id=annotation.correlation_id,
                    subagent_id="worker",
                    parent_tool_call_id="call-b",
                ),
                repository_privacy_context=_REPOSITORY,
            )
        assert caught.value.code is PublicErrorCode.SESSION_CONFLICT
        assert caught.value.safe_details["reason_code"] == "host_lineage_annotation_invalid"
        assert delegated.attach_handle is not None
        handle = await lineage.store.get_handle(delegated.attach_handle.digest)
        assert handle is not None and handle.consumed_session_id is None
        assert await app.start_catalog.resolve_route(delegated.session_id) == before
        assert await registry.list_provisional_annotations(parent.task_id) == (annotation,)

        attached = await app.start(
            _request(
                mode="attach",
                attach_handle=delegated.as_wire()["attach_handle"],
                correlation_id=annotation.correlation_id,
                subagent_id="worker",
                parent_tool_call_id="call-a",
            ),
            repository_privacy_context=_REPOSITORY,
        )
        assert attached.task_id == delegated.task_id
        assert await registry.list_provisional_annotations(parent.task_id) == ()


async def test_post_attach_registry_failure_replays_same_session_after_handle_expiry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    subprocess.run(["git", "init", "--quiet", str(workspace)], check=True, capture_output=True)
    async with multi_agent_service(tmp_path / "state") as service:
        app = service.app
        parent = await app.start(
            _request(mode="create", workspace_ref=str(workspace.resolve()), external_ref="parent"),
            repository_privacy_context=_REPOSITORY,
        )
        delegated = await app.start(
            _request(mode="delegate", session_id=parent.session_id),
            repository_privacy_context=_REPOSITORY,
        )
        lineage = app.lineage
        assert lineage is not None and delegated.attach_handle is not None
        original = lineage._host_annotation_merger  # pyright: ignore[reportPrivateUsage]
        assert original is not None
        fail_once = True

        async def flaky_merge(values: Mapping[str, JsonValue]) -> None:
            nonlocal fail_once
            if values.get("validate_only") is not True and fail_once:
                fail_once = False
                raise HostLineageRegistryError(
                    HostLineageRegistryReason.STORAGE_BUSY, retryable=True
                )
            await original(values)

        monkeypatch.setattr(lineage, "_host_annotation_merger", flaky_merge)
        request = _request(
            mode="attach",
            attach_handle=delegated.as_wire()["attach_handle"],
            subagent_id="worker",
        )
        with pytest.raises(PublicOperationError) as caught:
            await app.start(request, repository_privacy_context=_REPOSITORY)
        assert caught.value.code is PublicErrorCode.BUNDLE_BUSY and caught.value.retryable
        handle = await lineage.store.get_handle(delegated.attach_handle.digest)
        assert handle is not None and handle.consumed_session_id is not None
        consumed_session = handle.consumed_session_id
        service.clock.advance(seconds=301)
        replay = await app.start(request, repository_privacy_context=_REPOSITORY)
        assert replay.task_id == delegated.task_id
        assert replay.session_id == consumed_session
        children = await lineage.store.list_children(parent.task_id)
        assert len(children) == 1
        assert children[0].active_session_id == consumed_session
