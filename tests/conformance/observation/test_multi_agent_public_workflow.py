"""Named #509 scenarios through the production service and encrypted task bundles.

These rows supplement the observation worker concurrency scenario: a worker's check result is
not a public task check or a task receipt. Each row below invokes the actual public operations.
"""

from __future__ import annotations

import asyncio
import io
import json
import subprocess
from collections.abc import Mapping
from pathlib import Path

import pytest

from builders.multi_agent import multi_agent_service, relock_and_reopen_multi_agent_service
from yoetz.adapters.integrations.codex_lifecycle import load_mapping, scoped_child_session_id
from yoetz.adapters.integrations.observation_local import LocalObservationStore
from yoetz.application.publish_work import PublishWorkInternalResult
from yoetz.application.start import StartInternalResult
from yoetz.cli.hooks import bind_start_mapping_outcome
from yoetz.cli.observe_hooks import handle_observe
from yoetz.config.models import LineageSettings, YoetzConfig
from yoetz.domain.coordination import WorkState
from yoetz.domain.observation import (
    AdviceSnapshot,
    ObservationIngestRequest,
    observation_ingest_request_to_json,
    observation_ingest_result_from_json,
)
from yoetz.domain.values import finding_id
from yoetz.ports.control import RepositoryPrivacyContext
from yoetz.ports.ledger import CheckCommitResult
from yoetz.ports.start_catalog import TaskRouteState
from yoetz.protocol.coverage import (
    ArtifactObservation,
    AuthorshipAssurance,
    CheckType,
    Coverage,
    EvidenceImmutability,
    LedgerFreshness,
    PublicationChannel,
)
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

# This is the trusted control boundary's resolved Git-common-root identity. The public
# workspace_ref remains only a task selector and is never used as disclosure authority.
_REPOSITORY = RepositoryPrivacyContext("hmac-sha256:" + "d" * 64, "git_common_root")


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _identity() -> dict[str, object]:
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": new_id(IdKind.REQUEST),
        "actor": {"actor_id": "harness:conformance", "actor_type": "harness"},
        "client": {
            "kind": "cooperative_agent",
            "version": "0.1.0",
            "integration": "cooperative_mcp",
        },
    }


def _workspace(root: Path) -> Path:
    root.mkdir()
    subprocess.run(["git", "init", "--quiet", str(root)], check=True, capture_output=True)
    return root.resolve()


async def test_multi_agent_teardown_attempts_every_close_after_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed close cannot strand a later service resource or its writer."""

    calls: list[str] = []

    with pytest.raises(RuntimeError, match="injected app close failure"):
        async with multi_agent_service(tmp_path / "state") as service:
            original_app_close = service.app.close
            original_vault_close = service.vault.close
            original_memory_close = service.memory.close
            original_lifecycle_close = service.lifecycle.close

            async def fail_app_close(_app: object) -> None:
                calls.append("app")
                await original_app_close()
                raise RuntimeError("injected app close failure")

            async def close_vault(_vault: object) -> None:
                calls.append("vault")
                await original_vault_close()

            def close_memory(_memory: object) -> None:
                calls.append("memory")
                original_memory_close()

            async def close_lifecycle(_lifecycle: object) -> None:
                calls.append("lifecycle")
                await original_lifecycle_close()

            monkeypatch.setattr(type(service.app), "close", fail_app_close)
            monkeypatch.setattr(type(service.vault), "close", close_vault)
            monkeypatch.setattr(type(service.memory), "close", close_memory)
            monkeypatch.setattr(type(service.lifecycle), "close", close_lifecycle)

    assert calls == ["app", "vault", "memory", "lifecycle"]


async def test_explicit_siblings_have_independent_public_checks_receipts_and_work_state(
    tmp_path: Path,
) -> None:
    """#509 independent-root control: workspace proximity never grants child ownership."""

    workspace = _workspace(tmp_path / "workspace")
    async with multi_agent_service(tmp_path / "state") as service:
        app = service.app
        tasks: list[StartInternalResult] = []
        for index in range(2):
            tasks.append(
                await app.start(
                    StartRequest.model_validate(
                        {
                            **_identity(),
                            "mode": "create",
                            "task_title": f"Sibling {index}",
                            "workspace_ref": str(workspace),
                            "external_ref": f"sibling-{index}",
                            "requested_view": "compact",
                        }
                    ),
                    repository_privacy_context=_REPOSITORY,
                )
            )
        first, second = tasks
        assert first.task_id != second.task_id
        assert first.session_id != second.session_id
        assert first.writer_id != second.writer_id

        receipt_ids: set[str] = set()
        for task in tasks:
            checked = await app.check(
                CheckRequest.model_validate(
                    {
                        **_identity(),
                        "session_id": task.session_id,
                        "writer_id": task.writer_id,
                        "expected_frontier": task.frontier.model_dump(mode="json"),
                        "mode": "deterministic_only",
                        "max_findings": "10",
                        "policy_packs": ["work-integrity/0.3.0"],
                    }
                ),
                repository_privacy_context=_REPOSITORY,
            )
            assert isinstance(checked, CheckCommitResult)
            assert checked.task_id == task.task_id
            assert checked.outcome == "committed"
            receipt_request = ReceiptRequest.model_validate(
                {
                    **_identity(),
                    "task_id": task.task_id,
                    "session_id": task.session_id,
                    "writer_id": task.writer_id,
                    "expected_frontier": dict(checked.result_frontier.as_wire().items()),
                    "format": "json",
                    "include": "standard",
                    "redaction_profile": "default_local_export",
                }
            )
            receipt = await app.receipt(receipt_request, repository_privacy_context=_REPOSITORY)
            receipt_ids.add(receipt.receipt_id)
            assert receipt.task_id == task.task_id
            assert receipt.document is not None
            assert isinstance(receipt.document, Mapping)
            children_section = receipt.document["children"]
            assert isinstance(children_section, Mapping)
            assert children_section["children"] == []
            assert (
                await app.receipt(receipt_request, repository_privacy_context=_REPOSITORY)
            ).receipt_digest == receipt.receipt_digest
            lineage = await app.start_catalog.task_lineage(task.task_id)
            assert lineage is not None and lineage.work_state is WorkState.OPEN
            status = await app.status(
                StatusRequest.model_validate(
                    {
                        **_identity(),
                        "session_id": task.session_id,
                        "writer_id": task.writer_id,
                        "view": "lineage",
                        "limit": "10",
                    }
                ),
                repository_privacy_context=_REPOSITORY,
            )
            assert status.task_id == task.task_id
            assert isinstance(status.page, StatusLineagePageModel)
            assert status.page.parent_task_id is None
            assert status.page.children == ()
            assert status.page.annotations == ()
        assert len(receipt_ids) == 2


@pytest.mark.parametrize("same_pair", [True, False])
async def test_concurrent_create_or_attach_pairs_are_resolved_atomically(
    tmp_path: Path,
    same_pair: bool,
) -> None:
    workspace = _workspace(tmp_path / "workspace")
    async with multi_agent_service(tmp_path / "state") as service:
        requests = tuple(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create_or_attach",
                    "task_title": f"Concurrent {index}",
                    "workspace_ref": str(workspace),
                    "external_ref": "shared-pair" if same_pair else f"independent-{index}",
                    "requested_view": "compact",
                }
            )
            for index in range(2)
        )
        results = await asyncio.gather(
            *(
                service.app.start(request, repository_privacy_context=_REPOSITORY)
                for request in requests
            )
        )
        assert len({result.task_id for result in results}) == (1 if same_pair else 2)
        projects = tuple(
            [
                await service.app.start_catalog.list_task_project_ids(result.task_id)
                for result in results
            ]
        )
        if same_pair:
            assert projects == ((), ()), "two sessions on one task cannot create a project"
        else:
            assert len(projects[0]) == 1
            assert projects[0] == projects[1]
            assert set(await service.app.start_catalog.list_project_task_ids(projects[0][0])) == {
                result.task_id for result in results
            }
        for request, original in zip(requests, results, strict=True):
            replay = await service.app.start(request, repository_privacy_context=_REPOSITORY)
            assert (replay.task_id, replay.session_id, replay.writer_id) == (
                original.task_id,
                original.session_id,
                original.writer_id,
            )


async def test_real_delegation_attach_publication_and_child_receipt_preserve_parent_lane(
    tmp_path: Path,
) -> None:
    """#509 delegated attach: distinct identity, accepted lineage, receipt, explicit closure."""

    workspace = _workspace(tmp_path / "workspace")
    async with multi_agent_service(tmp_path / "state") as service:
        app = service.app
        parent = await app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create",
                    "task_title": "Parent",
                    "workspace_ref": str(workspace),
                    "external_ref": "parent",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        parent_host_session = "native-parent-session"
        lifecycle_state = service.root / "state"
        assert (
            bind_start_mapping_outcome(
                {
                    "session_id": parent_host_session,
                    "tool_name": "mcp__yoetz__start",
                    "tool_response": {"structuredContent": parent.as_wire()},
                },
                _state=lifecycle_state,
            )
            == "bound"
        )
        parent_mapping = load_mapping(parent_host_session, _state=lifecycle_state)
        assert parent_mapping is not None
        assert (
            parent_mapping.yoetz_task_id,
            parent_mapping.yoetz_session_id,
            parent_mapping.yoetz_writer_id,
            parent_mapping.last_frontier,
        ) == (
            parent.task_id,
            parent.session_id,
            parent.writer_id,
            f"{parent.frontier.sequence}:{parent.frontier.head_digest}",
        )
        parent_binding = await app.start_catalog.session_binding(parent.session_id)
        delegate_request = StartRequest.model_validate(
            {
                **_identity(),
                "mode": "delegate",
                "task_title": "Child",
                "session_id": parent.session_id,
                "requested_view": "compact",
            }
        )
        delegated = await app.start(delegate_request, repository_privacy_context=_REPOSITORY)
        assert delegated.attach_handle is not None
        assert (
            bind_start_mapping_outcome(
                {
                    "session_id": parent_host_session,
                    "tool_name": "mcp__yoetz__start",
                    "tool_response": {"structuredContent": delegated.as_wire()},
                },
                _state=lifecycle_state,
            )
            == "bound"
        )
        delegated_parent_mapping = load_mapping(parent_host_session, _state=lifecycle_state)
        assert delegated_parent_mapping is not None
        assert (
            delegated_parent_mapping.yoetz_task_id,
            delegated_parent_mapping.yoetz_session_id,
            delegated_parent_mapping.yoetz_writer_id,
            delegated_parent_mapping.last_frontier,
        ) == (
            parent.task_id,
            parent.session_id,
            parent.writer_id,
            f"{delegated.frontier.sequence}:{delegated.frontier.head_digest}",
        )
        child_route = await app.start_catalog.task_route(delegated.task_id)
        assert child_route is not None
        assert child_route.state is TaskRouteState.INITIALIZING
        replayed = await app.start(delegate_request, repository_privacy_context=_REPOSITORY)
        assert replayed.task_id == delegated.task_id
        assert replayed.attach_handle == delegated.attach_handle
        after_delegation = await app.start_catalog.session_binding(parent.session_id)
        assert parent_binding is not None and after_delegation is not None
        assert (
            after_delegation.task_id,
            after_delegation.session_id,
            after_delegation.writer_id,
        ) == (
            parent_binding.task_id,
            parent_binding.session_id,
            parent_binding.writer_id,
        )
        attached = await app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "attach",
                    "task_title": "Child",
                    "attach_handle": delegated.as_wire()["attach_handle"],
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        assert attached.task_id == delegated.task_id
        assert attached.task_id != parent.task_id
        assert attached.session_id != parent.session_id
        assert attached.writer_id != parent.writer_id
        assert attached.origin == "parent_minted"
        assert attached.acceptance == "accepted"
        child_host_session = "native-child-session"
        assert child_host_session != parent_host_session
        assert (
            bind_start_mapping_outcome(
                {
                    "session_id": child_host_session,
                    "tool_name": "mcp__yoetz__start",
                    "tool_response": {"structuredContent": attached.as_wire()},
                },
                _state=lifecycle_state,
            )
            == "bound"
        )
        child_mapping = load_mapping(child_host_session, _state=lifecycle_state)
        assert child_mapping is not None
        assert (
            child_mapping.yoetz_task_id,
            child_mapping.yoetz_session_id,
            child_mapping.yoetz_writer_id,
            child_mapping.last_frontier,
        ) == (
            attached.task_id,
            attached.session_id,
            attached.writer_id,
            f"{attached.frontier.sequence}:{attached.frontier.head_digest}",
        )
        assert load_mapping(parent_host_session, _state=lifecycle_state) == delegated_parent_mapping
        publication = await app.publish_work(
            PublishWorkRequest.model_validate(
                {
                    **_identity(),
                    "session_id": attached.session_id,
                    "writer_id": attached.writer_id,
                    "expected_frontier": attached.frontier.model_dump(mode="json"),
                    "event_drafts": [
                        {
                            "event_id": new_id(IdKind.EVENT),
                            "schema": {"name": "action_recorded", "version": "1.0.0"},
                            "occurred_at": "2026-09-05T12:00:00.000Z",
                            "causal_parents": [],
                            "payload": {
                                "action_id": new_id(IdKind.ACTION),
                                "action_kind": "review",
                                "description": "Child-only marker review",
                            },
                            "artifact_refs": [],
                            "evidence_refs": [],
                        }
                    ],
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        assert isinstance(publication, PublishWorkInternalResult)
        assert publication.task_id == attached.task_id
        checked = await app.check(
            CheckRequest.model_validate(
                {
                    **_identity(),
                    "session_id": attached.session_id,
                    "writer_id": attached.writer_id,
                    "expected_frontier": dict(publication.result_frontier.as_wire().items()),
                    "mode": "deterministic_only",
                    "max_findings": "10",
                    "policy_packs": ["work-integrity/0.3.0"],
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        assert isinstance(checked, CheckCommitResult)
        receipt = await app.receipt(
            ReceiptRequest.model_validate(
                {
                    **_identity(),
                    "task_id": attached.task_id,
                    "session_id": attached.session_id,
                    "writer_id": attached.writer_id,
                    "expected_frontier": dict(checked.result_frontier.as_wire().items()),
                    "format": "json",
                    "include": "standard",
                    "redaction_profile": "default_local_export",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        assert receipt.task_id == attached.task_id
        assert isinstance(receipt.document, Mapping)
        assert receipt.document["task_id"] == attached.task_id
        lineage = await app.status(
            StatusRequest.model_validate(
                {
                    **_identity(),
                    "session_id": parent.session_id,
                    "writer_id": parent.writer_id,
                    "view": "lineage",
                    "limit": "10",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        assert isinstance(lineage.page, StatusLineagePageModel)
        (child,) = lineage.page.children
        assert child.task_id == attached.task_id
        assert child.origin == "parent_minted"
        assert child.acceptance == "accepted"
        assert child.work_state == "open"
        assert child.rollup_state != "clean"

        # A receipt is not work closure. Only the child's explicit lifecycle publication
        # closes this dependency, without closing the parent or upgrading its limited check.
        child_status = await app.status(
            StatusRequest.model_validate(
                {
                    **_identity(),
                    "session_id": attached.session_id,
                    "writer_id": attached.writer_id,
                    "view": "compact",
                    "limit": "1",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        closed = await app.publish_work(
            PublishWorkRequest.model_validate(
                {
                    **_identity(),
                    "session_id": attached.session_id,
                    "writer_id": attached.writer_id,
                    "expected_frontier": dict(child_status.head_frontier.as_wire().items()),
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
            ),
            repository_privacy_context=_REPOSITORY,
        )
        assert isinstance(closed, PublishWorkInternalResult)
        assert closed.task_id == attached.task_id
        after_close = await app.status(
            StatusRequest.model_validate(
                {
                    **_identity(),
                    "session_id": parent.session_id,
                    "writer_id": parent.writer_id,
                    "view": "lineage",
                    "limit": "10",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        assert isinstance(after_close.page, StatusLineagePageModel)
        (closed_child,) = after_close.page.children
        assert closed_child.task_id == attached.task_id
        assert closed_child.origin == "parent_minted"
        assert closed_child.acceptance == "accepted"
        assert closed_child.work_state == "closed"
        assert closed_child.rollup_state != "clean"
        parent_lineage = await app.start_catalog.task_lineage(parent.task_id)
        assert parent_lineage is not None and parent_lineage.work_state is WorkState.OPEN
        assert load_mapping(parent_host_session, _state=lifecycle_state) == delegated_parent_mapping


async def test_generic_recovery_cannot_select_child_beside_root_siblings(
    tmp_path: Path,
) -> None:
    """Root-session recovery may rotate a root while a child stays handle-selected only."""

    workspace = _workspace(tmp_path / "workspace")
    async with multi_agent_service(tmp_path / "state") as service:
        app = service.app
        parent = await app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create",
                    "task_title": "Recovery parent",
                    "workspace_ref": str(workspace),
                    "external_ref": "recovery-parent",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        sibling = await app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create",
                    "task_title": "Recovery sibling",
                    "workspace_ref": str(workspace),
                    "external_ref": "recovery-sibling",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        delegated = await app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "delegate",
                    "task_title": "Recovery child",
                    "session_id": parent.session_id,
                    "workspace_ref": str(workspace),
                    "external_ref": "recovery-child",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        assert delegated.attach_handle is not None
        attached = await app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "attach",
                    "task_title": "Recovery child",
                    "workspace_ref": str(workspace),
                    "external_ref": "recovery-child",
                    "attach_handle": delegated.as_wire()["attach_handle"],
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        child_route = await app.start_catalog.task_route(attached.task_id)
        assert child_route is not None
        assert child_route.parent_task_id == parent.task_id
        assert attached.task_id not in {parent.task_id, sibling.task_id}

        parent_recovered = await app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "attach",
                    "task_title": "Recovery parent",
                    "session_id": parent.session_id,
                    "workspace_ref": str(workspace),
                    "external_ref": "recovery-parent-next",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        assert parent_recovered.task_id == parent.task_id
        assert parent_recovered.session_id != parent.session_id

        with pytest.raises(PublicOperationError) as child_recovery:
            await app.start(
                StartRequest.model_validate(
                    {
                        **_identity(),
                        "mode": "attach",
                        "task_title": "Recovery child",
                        "session_id": attached.session_id,
                        "workspace_ref": str(workspace),
                        "external_ref": "recovery-child-next",
                        "requested_view": "compact",
                    }
                ),
                repository_privacy_context=_REPOSITORY,
            )
        assert child_recovery.value.code is PublicErrorCode.SESSION_CONFLICT
        assert child_recovery.value.safe_details["reason_code"] == "selector_conflict"
        assert await app.start_catalog.resolve_route(sibling.session_id) is not None


async def test_codex_shared_host_child_alias_routes_observation_to_attached_child(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A Codex child callback keeps the parent lane and advice independent."""

    workspace = _workspace(tmp_path / "workspace")
    async with multi_agent_service(tmp_path / "state") as service:
        app = service.app
        # The builder keeps its service state in a private owner-only root.  Production
        # observation ingest resolves lifecycle mappings through the isolated-root contract,
        # so point that contract at this same test installation before exercising the public
        # ingest path.
        monkeypatch.setenv("YOETZ_ISOLATED_ROOT", str(service.root))
        parent = await app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create",
                    "task_title": "Shared host parent",
                    "workspace_ref": str(workspace),
                    "external_ref": "shared-host-parent",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        parent_host_session = "codex-shared-parent-session"
        lifecycle_state = service.root / "state"
        assert (
            bind_start_mapping_outcome(
                {
                    "session_id": parent_host_session,
                    "tool_name": "mcp__yoetz__start",
                    "tool_response": {"structuredContent": parent.as_wire()},
                },
                _state=lifecycle_state,
            )
            == "bound"
        )

        delegated = await app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "delegate",
                    "task_title": "Shared host child",
                    "session_id": parent.session_id,
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        assert delegated.attach_handle is not None
        assert (
            bind_start_mapping_outcome(
                {
                    "session_id": parent_host_session,
                    "tool_name": "mcp__yoetz__start",
                    "tool_response": {"structuredContent": delegated.as_wire()},
                },
                _state=lifecycle_state,
            )
            == "bound"
        )
        parent_mapping = load_mapping(parent_host_session, _state=lifecycle_state)
        assert parent_mapping is not None
        assert parent_mapping.yoetz_task_id == parent.task_id

        attached = await app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "attach",
                    "task_title": "Shared host child",
                    "attach_handle": delegated.as_wire()["attach_handle"],
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        child_agent_id = "codex-native-child-agent"
        assert (
            bind_start_mapping_outcome(
                {
                    # Codex sends the child attach result through the parent's host session.
                    "session_id": parent_host_session,
                    "agent_id": child_agent_id,
                    "tool_name": "mcp__yoetz__start",
                    "tool_response": {"structuredContent": attached.as_wire()},
                },
                _state=lifecycle_state,
            )
            == "bound"
        )
        child_host_lane = scoped_child_session_id(
            parent_host_session,
            host="codex",
            identity=child_agent_id,
            identity_kind="host",
        )
        child_mapping = load_mapping(child_host_lane, _state=lifecycle_state)
        assert child_mapping is not None
        assert (
            child_mapping.yoetz_task_id,
            child_mapping.yoetz_session_id,
            child_mapping.yoetz_writer_id,
            child_mapping.last_frontier,
        ) == (
            attached.task_id,
            attached.session_id,
            attached.writer_id,
            f"{attached.frontier.sequence}:{attached.frontier.head_digest}",
        )
        assert load_mapping(parent_host_session, _state=lifecycle_state) == parent_mapping

        observation_store = LocalObservationStore(_state=lifecycle_state)
        workspace_commitment = observation_store.workspace_commitment(str(workspace))
        observation_store.grant_consent(workspace_commitment)
        observation_store.set_session_advice_snapshot(
            workspace_commitment,
            yoetz_session_id=parent.session_id,
            snapshot=AdviceSnapshot(
                ranked_finding_ids=(finding_id("fnd_00000000-0000-4000-8000-000000000001"),),
                evidence_basis_digest="sha256:" + "a" * 64,
                confidence_coverage=Coverage(
                    publication_channels=(PublicationChannel.HOOK_OBSERVED,),
                    authorship_assurance=AuthorshipAssurance.HARNESS_OBSERVED,
                    artifact_observation=ArtifactObservation.HOOK_OBSERVED,
                    evidence_immutability=EvidenceImmutability.CONTENT_DIGEST,
                    ledger_freshness=LedgerFreshness.CURRENT,
                    check_types=(CheckType.DETERMINISTIC,),
                    known_gaps=(),
                ),
                recommended_next_action="call_status",
                freshness_frontier="frontier-1",
                suppression_identity="suppress-shared-host-parent",
            ),
        )
        parent_advice_before = observation_store.peek_advice_for_delivery(
            workspace_commitment,
            yoetz_session_id=parent.session_id,
            allow_standing=False,
            session_commitment=observation_store.session_commitment(parent_host_session),
        )
        assert parent_advice_before is not None

        for event_name in ("PreToolUse", "PostToolUse"):
            output = io.BytesIO()
            payload: dict[str, object] = {
                "hook_event_name": event_name,
                "session_id": parent_host_session,
                "agent_id": child_agent_id,
                "tool_name": "shell",
                "tool_call_id": "codex-child-call",
                "exit_status": 0,
            }
            assert (
                handle_observe(
                    event_name=None,
                    stdin_bytes=json.dumps(payload).encode(),
                    stdout=output,
                    workspace=str(workspace),
                    _state=lifecycle_state,
                    skip_service=True,
                )
                == 0
            )
            assert json.loads(output.getvalue().decode()) == {}

        pending_rows = observation_store.list_pending_outbox_rows(workspace_commitment)
        assert len(pending_rows) == 2
        assert {row.codex_session_id for row in pending_rows} == {child_host_lane}
        for row in pending_rows:
            result = observation_ingest_result_from_json(
                await app.observation_ingest(
                    observation_ingest_request_to_json(
                        ObservationIngestRequest(
                            codex_session_id=row.codex_session_id,
                            envelope=row.envelope,
                        )
                    )
                )
            )
            assert result.disposition.value == "accepted"
            assert observation_store.acknowledge_outbox_row(workspace_commitment, row)

        child_status = await app.status(
            StatusRequest.model_validate(
                {
                    **_identity(),
                    "session_id": attached.session_id,
                    "writer_id": attached.writer_id,
                    "view": "compact",
                    "limit": "10",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        assert child_status.task_id == attached.task_id
        assert int(child_status.result_frontier.sequence) > int(attached.frontier.sequence)

        parent_status = await app.status(
            StatusRequest.model_validate(
                {
                    **_identity(),
                    "session_id": parent.session_id,
                    "writer_id": parent.writer_id,
                    "view": "compact",
                    "limit": "10",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        assert parent_status.task_id == parent.task_id
        assert parent_status.result_frontier == parent_status.subject_frontier
        parent_advice_after = observation_store.peek_advice_for_delivery(
            workspace_commitment,
            yoetz_session_id=parent.session_id,
            allow_standing=False,
            session_commitment=observation_store.session_commitment(parent_host_session),
        )
        assert parent_advice_after is not None
        assert parent_advice_after.delivery_identity == parent_advice_before.delivery_identity


async def test_late_subagent_stop_after_parent_reattach_keeps_registry_annotation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#509 unregistered-helper control retains advice without cooperative child ownership."""

    workspace = _workspace(tmp_path / "workspace")
    async with multi_agent_service(tmp_path / "state") as service:
        app = service.app
        monkeypatch.setenv("YOETZ_ISOLATED_ROOT", str(service.root))
        parent = await app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create",
                    "task_title": "Observed parent",
                    "workspace_ref": str(workspace),
                    "external_ref": "observed-parent",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        parent_host_session = "observed-parent-host-session"
        lifecycle_state = service.root / "state"
        assert (
            bind_start_mapping_outcome(
                {
                    "session_id": parent_host_session,
                    "tool_name": "mcp__yoetz__start",
                    "tool_response": {"structuredContent": parent.as_wire()},
                },
                _state=lifecycle_state,
            )
            == "bound"
        )

        observation_store = LocalObservationStore(_state=lifecycle_state)
        workspace_commitment = observation_store.workspace_commitment(str(workspace))
        observation_store.grant_consent(workspace_commitment)
        output = io.BytesIO()
        assert (
            handle_observe(
                event_name=None,
                stdin_bytes=json.dumps(
                    {
                        "hook_event_name": "SubagentStart",
                        "session_id": parent_host_session,
                        "subagent_id": "observed-child",
                    }
                ).encode(),
                stdout=output,
                workspace=str(workspace),
                _state=lifecycle_state,
                skip_service=True,
            )
            == 0
        )
        rows = observation_store.list_pending_outbox_rows(workspace_commitment)
        assert len(rows) == 1
        row = rows[0]
        result = observation_ingest_result_from_json(
            await app.observation_ingest(
                observation_ingest_request_to_json(
                    ObservationIngestRequest(
                        codex_session_id=parent_host_session,
                        envelope=row.envelope,
                    )
                )
            )
        )
        assert result.disposition.value == "accepted"
        assert observation_store.acknowledge_outbox_row(workspace_commitment, row)

        registry = app.host_lineage_registry
        assert registry is not None
        annotations = await registry.list_provisional_annotations(parent.task_id)
        assert len(annotations) == 1
        initial_annotation = annotations[0]

        # Reattach the same parent task through the same host session.  The service rotates its
        # Yoetz session/writer while retaining the host mapping and registry correlation.
        resumed = await app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create_or_attach",
                    "task_title": "Observed parent resumed",
                    "workspace_ref": str(workspace),
                    "external_ref": "observed-parent",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        assert resumed.task_id == parent.task_id
        assert (resumed.session_id, resumed.writer_id) != (
            parent.session_id,
            parent.writer_id,
        )
        assert (
            bind_start_mapping_outcome(
                {
                    "session_id": parent_host_session,
                    "tool_name": "mcp__yoetz__start",
                    "tool_response": {"structuredContent": resumed.as_wire()},
                },
                _state=lifecycle_state,
            )
            == "bound"
        )
        rotated_mapping = load_mapping(parent_host_session, _state=lifecycle_state)
        assert rotated_mapping is not None
        assert (rotated_mapping.yoetz_session_id, rotated_mapping.yoetz_writer_id) == (
            resumed.session_id,
            resumed.writer_id,
        )

        # The late stop arrives on the rotated route and must complete the original annotation.
        output = io.BytesIO()
        assert (
            handle_observe(
                event_name=None,
                stdin_bytes=json.dumps(
                    {
                        "hook_event_name": "SubagentStop",
                        "session_id": parent_host_session,
                        "subagent_id": "observed-child",
                        "result_status": "finding",
                        "success": False,
                    }
                ).encode(),
                stdout=output,
                workspace=str(workspace),
                _state=lifecycle_state,
                skip_service=True,
            )
            == 0
        )
        late_rows = observation_store.list_pending_outbox_rows(workspace_commitment)
        assert len(late_rows) == 1
        late_row = late_rows[0]
        late_result = observation_ingest_result_from_json(
            await app.observation_ingest(
                observation_ingest_request_to_json(
                    ObservationIngestRequest(
                        codex_session_id=parent_host_session,
                        envelope=late_row.envelope,
                    )
                )
            )
        )
        assert late_result.disposition.value == "accepted"
        assert observation_store.acknowledge_outbox_row(workspace_commitment, late_row)

        annotations = await registry.list_provisional_annotations(parent.task_id)
        assert len(annotations) == 1
        annotation = annotations[0]
        assert annotation.correlation_id == initial_annotation.correlation_id
        assert annotation.observed_phases == ("start", "stop")
        snapshot = observation_store.advice_snapshot_for(workspace_commitment)
        assert snapshot is not None
        finding = next(
            item
            for item in snapshot.ranked_items
            if item.rule_code == "subagent_finding_unaddressed"
        )
        assert finding.evidence_refs[0] == annotation.correlation_id

        lineage_status = await app.status(
            StatusRequest.model_validate(
                {
                    **_identity(),
                    "session_id": resumed.session_id,
                    "writer_id": resumed.writer_id,
                    "view": "lineage",
                    "limit": "10",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        assert isinstance(lineage_status.page, StatusLineagePageModel)
        # A native start/stop is observation, not a child registration, acceptance, check or
        # receipt. The helper's missing cooperative lineage must remain explicit even though
        # its finding can be delivered as advice using the registry's correlation identity.
        assert lineage_status.page.children == ()
        assert len(lineage_status.page.annotations) == 1
        assert lineage_status.page.annotations[0].origin == "host_observed"
        assert lineage_status.page.annotations[0].acceptance == "pending"
        assert any(
            item.correlation_id == annotation.correlation_id
            for item in lineage_status.page.annotations
        )
        delivery = observation_store.peek_advice_for_delivery(
            workspace_commitment,
            yoetz_session_id=resumed.session_id,
            allow_standing=False,
            session_commitment=observation_store.session_commitment(parent_host_session),
        )
        assert delivery is not None
        assert delivery.item is not None
        assert delivery.item.rule_code == "subagent_finding_unaddressed"
        assert delivery.item.evidence_refs[0] == annotation.correlation_id

        # A later parent lifecycle event forces another advice build.  The service must resolve
        # the retained stop through the read-only registry lookup rather than dropping back to the
        # opaque hook identity.
        output = io.BytesIO()
        assert (
            handle_observe(
                event_name="Stop",
                stdin_bytes=json.dumps({"session_id": parent_host_session}).encode(),
                stdout=output,
                workspace=str(workspace),
                _state=lifecycle_state,
                skip_service=True,
            )
            == 0
        )
        refresh_rows = observation_store.list_pending_outbox_rows(workspace_commitment)
        assert len(refresh_rows) == 1
        refresh_row = refresh_rows[0]
        refreshed = observation_ingest_result_from_json(
            await app.observation_ingest(
                observation_ingest_request_to_json(
                    ObservationIngestRequest(
                        codex_session_id=parent_host_session,
                        envelope=refresh_row.envelope,
                    )
                )
            )
        )
        assert refreshed.disposition.value == "accepted"
        assert observation_store.acknowledge_outbox_row(workspace_commitment, refresh_row)
        refreshed_snapshot = observation_store.advice_snapshot_for(workspace_commitment)
        assert refreshed_snapshot is not None
        refreshed_finding = next(
            item
            for item in refreshed_snapshot.ranked_items
            if item.rule_code == "subagent_finding_unaddressed"
        )
        assert refreshed_finding.evidence_refs[0] == annotation.correlation_id

        # Reopen the READY composition around the same encrypted catalog and task bundles.  The
        # registry row, its clocks, and the scoped host mapping must survive that service restart.
        await relock_and_reopen_multi_agent_service(service)
        app = service.app
        reopened_registry = app.host_lineage_registry
        assert reopened_registry is not None
        reopened_annotations = await reopened_registry.list_provisional_annotations(parent.task_id)
        assert len(reopened_annotations) == 1
        reopened_annotation = reopened_annotations[0]
        assert reopened_annotation.correlation_id == annotation.correlation_id
        assert reopened_annotation.first_observed_at == annotation.first_observed_at
        assert reopened_annotation.last_observed_at == annotation.last_observed_at

        # A normal parent Stop after restart rebuilds advice from retained envelopes and must
        # still resolve the original annotation instead of dropping to the hook identity.
        output = io.BytesIO()
        assert (
            handle_observe(
                event_name="Stop",
                stdin_bytes=json.dumps({"session_id": parent_host_session}).encode(),
                stdout=output,
                workspace=str(workspace),
                _state=lifecycle_state,
                skip_service=True,
            )
            == 0
        )
        post_restart_rows = observation_store.list_pending_outbox_rows(workspace_commitment)
        assert len(post_restart_rows) == 1
        post_restart_row = post_restart_rows[0]
        post_restart_result = observation_ingest_result_from_json(
            await app.observation_ingest(
                observation_ingest_request_to_json(
                    ObservationIngestRequest(
                        codex_session_id=parent_host_session,
                        envelope=post_restart_row.envelope,
                    )
                )
            )
        )
        assert post_restart_result.disposition.value == "accepted"
        assert observation_store.acknowledge_outbox_row(workspace_commitment, post_restart_row)
        final_snapshot = observation_store.advice_snapshot_for(workspace_commitment)
        assert final_snapshot is not None
        final_finding = next(
            item
            for item in final_snapshot.ranked_items
            if item.rule_code == "subagent_finding_unaddressed"
        )
        assert final_finding.evidence_refs[0] == reopened_annotation.correlation_id
        assert await reopened_registry.list_provisional_annotations(parent.task_id) == (
            reopened_annotation,
        )

        # A parent receipt cannot turn that host-only handoff into checked child work.
        current = await app.status(
            StatusRequest.model_validate(
                {
                    **_identity(),
                    "session_id": resumed.session_id,
                    "writer_id": resumed.writer_id,
                    "view": "compact",
                    "limit": "1",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        checked = await app.check(
            CheckRequest.model_validate(
                {
                    **_identity(),
                    "session_id": resumed.session_id,
                    "writer_id": resumed.writer_id,
                    "expected_frontier": dict(current.head_frontier.as_wire().items()),
                    "mode": "deterministic_only",
                    "max_findings": "10",
                    "policy_packs": ["work-integrity/0.3.0"],
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        assert isinstance(checked, CheckCommitResult)
        receipt = await app.receipt(
            ReceiptRequest.model_validate(
                {
                    **_identity(),
                    "task_id": resumed.task_id,
                    "session_id": resumed.session_id,
                    "writer_id": resumed.writer_id,
                    "expected_frontier": dict(checked.result_frontier.as_wire().items()),
                    "format": "json",
                    "include": "standard",
                    "redaction_profile": "default_local_export",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        assert receipt.document is not None
        assert isinstance(receipt.document, Mapping)
        children_section = receipt.document["children"]
        assert isinstance(children_section, Mapping)
        assert children_section["children"] == []
        assert receipt.conclusion != "no_unresolved_deterministic_findings"


async def test_delegated_child_does_not_consume_parent_selector(
    tmp_path: Path,
) -> None:
    """Child source commitments stay visible to lineage without becoming start selectors."""

    workspace = _workspace(tmp_path / "workspace")
    async with multi_agent_service(tmp_path / "state") as service:
        app = service.app
        parent = await app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create",
                    "task_title": "Selector parent",
                    "workspace_ref": str(workspace),
                    "external_ref": "selector-parent",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        delegated = await app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "delegate",
                    "task_title": "Selector child",
                    "session_id": parent.session_id,
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        resumed = await app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create_or_attach",
                    "task_title": "Selector parent resumed",
                    "workspace_ref": str(workspace),
                    "external_ref": "selector-parent",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        assert resumed.task_id == parent.task_id
        assert delegated.task_id != resumed.task_id


async def test_ready_config_enforces_depth_and_fanout_bounds(
    tmp_path: Path,
) -> None:
    workspace = _workspace(tmp_path / "workspace")
    depth_config = YoetzConfig(lineage=LineageSettings(max_depth=0))
    async with multi_agent_service(tmp_path / "depth-state", config=depth_config) as service:
        parent = await service.app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create",
                    "task_title": "Depth parent",
                    "workspace_ref": str(workspace),
                    "external_ref": "depth-parent",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        with pytest.raises(PublicOperationError) as depth_error:
            await service.app.start(
                StartRequest.model_validate(
                    {
                        **_identity(),
                        "mode": "delegate",
                        "task_title": "Depth child",
                        "session_id": parent.session_id,
                        "requested_view": "compact",
                    }
                ),
                repository_privacy_context=_REPOSITORY,
            )
        assert depth_error.value.code is PublicErrorCode.LIMIT_EXCEEDED

    fanout_config = YoetzConfig(lineage=LineageSettings(max_fanout=1))
    async with multi_agent_service(tmp_path / "fanout-state", config=fanout_config) as service:
        parent = await service.app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create",
                    "task_title": "Fanout parent",
                    "workspace_ref": str(workspace),
                    "external_ref": "fanout-parent",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        for title in ("Fanout child one", "Fanout child two"):
            request = StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "delegate",
                    "task_title": title,
                    "session_id": parent.session_id,
                    "requested_view": "compact",
                }
            )
            if title.endswith("one"):
                await service.app.start(request, repository_privacy_context=_REPOSITORY)
                continue
            with pytest.raises(PublicOperationError) as fanout_error:
                await service.app.start(request, repository_privacy_context=_REPOSITORY)
            assert fanout_error.value.code is PublicErrorCode.LIMIT_EXCEEDED


async def test_attached_child_can_continue_after_parent_work_closes(
    tmp_path: Path,
) -> None:
    """Parent completion does not revoke an already attached child's independent route."""

    workspace = _workspace(tmp_path / "workspace")
    async with multi_agent_service(tmp_path / "state") as service:
        app = service.app
        parent = await app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create",
                    "task_title": "Detached parent",
                    "workspace_ref": str(workspace),
                    "external_ref": "detached-parent",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        delegate_request = StartRequest.model_validate(
            {
                **_identity(),
                "mode": "delegate",
                "task_title": "Detached child",
                "session_id": parent.session_id,
                "requested_view": "compact",
            }
        )
        delegated = await app.start(delegate_request, repository_privacy_context=_REPOSITORY)
        attached = await app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "attach",
                    "task_title": "Detached child",
                    "attach_handle": delegated.as_wire()["attach_handle"],
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        current_parent = await app.start(delegate_request, repository_privacy_context=_REPOSITORY)
        await app.publish_work(
            PublishWorkRequest.model_validate(
                {
                    **_identity(),
                    "session_id": parent.session_id,
                    "writer_id": parent.writer_id,
                    "expected_frontier": current_parent.frontier.model_dump(mode="json"),
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
            ),
            repository_privacy_context=_REPOSITORY,
        )
        child_action = await app.publish_work(
            PublishWorkRequest.model_validate(
                {
                    **_identity(),
                    "session_id": attached.session_id,
                    "writer_id": attached.writer_id,
                    "expected_frontier": attached.frontier.model_dump(mode="json"),
                    "event_drafts": [
                        {
                            "event_id": new_id(IdKind.EVENT),
                            "schema": {"name": "action_recorded", "version": "1.0.0"},
                            "occurred_at": "2026-09-05T12:00:00.000Z",
                            "causal_parents": [],
                            "payload": {
                                "action_id": new_id(IdKind.ACTION),
                                "action_kind": "review",
                                "description": "Detached child continues",
                            },
                            "artifact_refs": [],
                            "evidence_refs": [],
                        }
                    ],
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        assert isinstance(child_action, PublishWorkInternalResult)
        assert child_action.task_id == attached.task_id


@pytest.mark.parametrize("observed_first", [False, True])
async def test_native_handle_attach_correlates_without_declared_host_ids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, observed_first: bool
) -> None:
    """The blessed handle-only flow merges its native callback in either arrival order."""

    workspace = _workspace(tmp_path / "workspace")
    async with multi_agent_service(tmp_path / "state") as service:
        app = service.app
        monkeypatch.setenv("YOETZ_ISOLATED_ROOT", str(service.root))
        parent = await app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create",
                    "task_title": "Bridge parent",
                    "workspace_ref": str(workspace),
                    "external_ref": "bridge-parent",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        host_session = "native-shared-bridge-session"
        state = service.root / "state"
        assert (
            bind_start_mapping_outcome(
                {
                    "session_id": host_session,
                    "tool_name": "mcp__yoetz__start",
                    "tool_response": {"structuredContent": parent.as_wire()},
                },
                _state=state,
            )
            == "bound"
        )
        local = LocalObservationStore(_state=state)
        workspace_commitment = local.workspace_commitment(str(workspace))
        local.grant_consent(workspace_commitment)
        from yoetz.domain.values import timestamp_from_datetime

        monkeypatch.setattr(
            "yoetz.cli.observe_hooks._now", lambda: timestamp_from_datetime(service.clock.now_utc())
        )

        async def ingest_hook(payload: Mapping[str, object]) -> ObservationIngestRequest:
            assert (
                handle_observe(
                    event_name=None,
                    stdin_bytes=json.dumps(payload).encode(),
                    stdout=io.BytesIO(),
                    workspace=str(workspace),
                    _state=state,
                    skip_service=True,
                )
                == 0
            )
            rows = local.list_pending_outbox_rows(workspace_commitment)
            assert len(rows) == 1
            row = rows[0]
            result = observation_ingest_result_from_json(
                await app.observation_ingest(
                    observation_ingest_request_to_json(
                        ObservationIngestRequest(
                            codex_session_id=row.codex_session_id,
                            envelope=row.envelope,
                        )
                    )
                )
            )
            assert result.disposition.value == "accepted", result
            assert local.acknowledge_outbox_row(workspace_commitment, row)
            return ObservationIngestRequest(
                codex_session_id=row.codex_session_id, envelope=row.envelope
            )

        observed = {
            "hook_event_name": "SubagentStart",
            "session_id": host_session,
            "subagent_id": "native-worker",
            "parent_tool_call_id": "spawn-call",
        }
        if observed_first:
            await ingest_hook(observed)
        delegated = await app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "delegate",
                    "task_title": "Bridge child",
                    "session_id": parent.session_id,
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        attached = await app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "attach",
                    "task_title": "Bridge child",
                    "attach_handle": delegated.as_wire()["attach_handle"],
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        callback = {
            "hook_event_name": "PostToolUse",
            "session_id": host_session,
            "subagent_id": "native-worker",
            "parent_tool_call_id": "spawn-call",
            "tool_use_id": "attach-call",
            "tool_name": "mcp__yoetz__start",
            "tool_response": {"structuredContent": attached.as_wire()},
        }
        assert bind_start_mapping_outcome(callback, _state=state) == "bound"
        before_activity = await app.start_catalog.task_session_state(attached.session_id)
        assert before_activity is not None
        service.clock.advance(seconds=30)
        callback_request = await ingest_hook(callback)
        after_activity = await app.start_catalog.task_session_state(attached.session_id)
        assert after_activity is not None
        assert after_activity.lease_expires_at is not None
        assert before_activity.lease_expires_at is not None
        assert after_activity.lease_expires_at > before_activity.lease_expires_at
        service.clock.advance(seconds=10)
        replay = observation_ingest_result_from_json(
            await app.observation_ingest(observation_ingest_request_to_json(callback_request))
        )
        assert replay.disposition.value == "duplicate"
        after_replay = await app.start_catalog.task_session_state(attached.session_id)
        assert after_replay is not None
        assert after_replay.lease_expires_at == after_activity.lease_expires_at
        parent_mapping = load_mapping(host_session, _state=state)
        assert parent_mapping is not None and parent_mapping.yoetz_task_id == parent.task_id
        if not observed_first:
            await ingest_hook(observed)
        await ingest_hook({**observed, "hook_event_name": "SubagentStop"})
        registry = app.host_lineage_registry
        assert registry is not None
        assert await registry.list_provisional_annotations(parent.task_id) == ()
        from yoetz.domain.host_lineage import host_lineage_from_payload

        signal = host_lineage_from_payload("codex", "SubagentStop", observed)
        assert signal is not None
        annotation = await registry.find_host_lineage_observation(parent.task_id, signal)
        assert annotation is not None and annotation.bound_child_task_id == attached.task_id
        assert annotation.observed_phases == ("start", "stop")
        assert await app.start_catalog.list_child_task_ids(parent.task_id) == (attached.task_id,)
