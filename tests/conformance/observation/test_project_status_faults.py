"""Project status after real member receipts, and typed classification of status faults (#840).

The native dogfood reproduced as two concurrent roots in one repository that each publish an open
obligation for the same typed file, check, and record a receipt. Every later ``status
view=project`` from either root returned ``INVALID_REQUEST`` because the member receipt row could
not be projected, and the diagnostic retained only the public code. These cases run the production
READY composition and inject a fault at each status stage boundary to prove the public
classification and the joined, content-free diagnostic.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

import yoetz.application.status as status_module
import yoetz.application.task_views as task_views_module
import yoetz.observability.diagnostics as diagnostics
from builders.multi_agent import MultiAgentService, multi_agent_service
from yoetz.adapters.integrations.observation_local import LocalObservationStore
from yoetz.application.projects import ProjectApplication, ProjectStatus
from yoetz.application.publish_work import PublishWorkInternalResult
from yoetz.application.receipt import ReceiptInternalResult
from yoetz.application.start import StartInternalResult
from yoetz.application.status import StatusInternalResult
from yoetz.domain.coordination import CoordinationError, CoordinationErrorCode
from yoetz.domain.values import JsonObject
from yoetz.ports.control import RepositoryPrivacyContext
from yoetz.ports.diagnostics import RuntimeCapability
from yoetz.ports.host_lineage import HostLineageRegistryError, HostLineageRegistryReason
from yoetz.ports.ledger import CheckCommitResult
from yoetz.ports.runtime import RouteAccess, RouteCommand
from yoetz.protocol.errors import PublicErrorCode, PublicOperationError
from yoetz.protocol.ids import IdKind, new_id
from yoetz.protocol.models import (
    CheckRequest,
    OmittedContentModel,
    PublishWorkRequest,
    ReceiptRequest,
    StartRequest,
    StatusAdvicePageModel,
    StatusLineagePageModel,
    StatusProjectPageModel,
    StatusProjectReceiptModel,
    StatusRequest,
)

pytestmark = pytest.mark.anyio

_REPOSITORY = RepositoryPrivacyContext("hmac-sha256:" + "d" * 64, "git_common_root")
# Injected faults carry this marker in their message; no diagnostic may ever contain it.
_CANARY = "canary-840-must-not-leak"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@dataclass(frozen=True)
class _Root:
    task: StartInternalResult
    receipt: ReceiptInternalResult
    checked: CheckCommitResult


def _identity(request_id: str | None = None) -> dict[str, object]:
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": new_id(IdKind.REQUEST) if request_id is None else request_id,
        "actor": {"actor_id": "harness:project-status-faults", "actor_type": "harness"},
        "client": {
            "kind": "cooperative_agent",
            "version": "0.3.0",
            "integration": "cooperative_mcp",
        },
    }


def _frontier(frontier: object) -> dict[str, object]:
    as_wire = getattr(frontier, "as_wire", None)
    if callable(as_wire):
        return dict(cast(Mapping[str, object], as_wire()).items())
    model_dump = getattr(frontier, "model_dump", None)
    if callable(model_dump):
        return cast(dict[str, object], model_dump(mode="json"))
    raise AssertionError("frontier is not serializable")


async def _status(
    service: MultiAgentService,
    task: StartInternalResult,
    *,
    view: str = "compact",
    limit: str = "1",
    request_id: str | None = None,
    selectors: Mapping[str, str] | None = None,
) -> StatusInternalResult:
    body: dict[str, object] = {
        **_identity(request_id),
        "session_id": task.session_id,
        "writer_id": task.writer_id,
        "view": view,
        "limit": limit,
        **(selectors or {}),
    }
    result = await service.app.status(
        StatusRequest.model_validate(body), repository_privacy_context=_REPOSITORY
    )
    assert isinstance(result, StatusInternalResult)
    return result


async def _publish(
    service: MultiAgentService, task: StartInternalResult, drafts: Sequence[Mapping[str, object]]
) -> None:
    status = await _status(service, task)
    result = await service.app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **_identity(),
                "session_id": task.session_id,
                "writer_id": task.writer_id,
                "expected_frontier": _frontier(status.head_frontier),
                "event_drafts": tuple(dict(item) for item in drafts),
            }
        ),
        repository_privacy_context=_REPOSITORY,
    )
    assert isinstance(result, PublishWorkInternalResult)


async def _check_and_receipt(service: MultiAgentService, task: StartInternalResult) -> _Root:
    status = await _status(service, task)
    checked = await service.app.check(
        CheckRequest.model_validate(
            {
                **_identity(),
                "session_id": task.session_id,
                "writer_id": task.writer_id,
                "expected_frontier": _frontier(status.head_frontier),
                "mode": "deterministic_only",
                "max_findings": "10",
            }
        ),
        repository_privacy_context=_REPOSITORY,
    )
    assert isinstance(checked, CheckCommitResult)
    receipt = await service.app.receipt(
        ReceiptRequest.model_validate(
            {
                **_identity(),
                "task_id": task.task_id,
                "session_id": task.session_id,
                "writer_id": task.writer_id,
                "expected_frontier": _frontier(checked.result_frontier),
                "format": "json",
                "include": "standard",
                "redaction_profile": "default_local_export",
            }
        ),
        repository_privacy_context=_REPOSITORY,
    )
    return _Root(task, receipt, checked)


async def _two_roots_with_receipts(
    service: MultiAgentService, workspace: Path
) -> tuple[_Root, _Root, str]:
    """Reproduce the native shape: same repository, same typed file, each root receipted."""

    tasks = [
        await service.app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create",
                    "task_title": f"Concurrent root {index}",
                    "workspace_ref": str(workspace),
                    "external_ref": f"concurrent-root-{index}",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        for index in range(2)
    ]
    store = LocalObservationStore(_state=service.root / "state")
    store.grant_consent(store.workspace_commitment(str(workspace)))
    for index, task in enumerate(tasks):
        await _publish(
            service,
            task,
            (
                {
                    "event_id": new_id(IdKind.EVENT),
                    "schema": {"name": "obligation_published", "version": "1.0.0"},
                    "occurred_at": "2026-09-25T10:00:00.000Z",
                    "causal_parents": (),
                    "payload": {
                        "obligation_id": new_id(IdKind.OBLIGATION),
                        "description": f"Review the shared resource {index}.",
                        "evidence_expectation": "A recorded review decision.",
                        "status": "open",
                        "requested_items": ({"item_kind": "file", "value": "src/shared.py"},),
                    },
                    "artifact_refs": (),
                    "evidence_refs": (),
                },
            ),
        )
    project_ids = await service.app.start_catalog.list_task_project_ids(tasks[0].task_id)
    assert len(project_ids) == 1
    first = await _check_and_receipt(service, tasks[0])
    second = await _check_and_receipt(service, tasks[1])
    return first, second, project_ids[0]


def _workspace(tmp_path: Path) -> Path:
    workspace = (tmp_path / "workspace").resolve()
    workspace.mkdir()
    subprocess.run(["git", "init", "--quiet", str(workspace)], check=True, capture_output=True)
    return workspace


def _records(
    *, correlation_id: str | None = None, request_id: str | None = None
) -> tuple[Mapping[str, object], ...]:
    return diagnostics.lookup_diagnostic_records(correlation_id, request_id=request_id)


def _assert_ring_is_content_free() -> None:
    path = diagnostics.diagnostic_log_path()
    raw = path.read_text(encoding="ascii") if path.is_file() else ""
    assert _CANARY not in raw
    assert "traceback" not in raw.lower()
    assert "src/shared.py" not in raw


def _assert_joined(
    error: PublicOperationError,
    *,
    code: PublicErrorCode,
    operation: str,
    phase: str,
    reason: str,
    origin_module: str,
    request_id: str,
) -> None:
    """The public id resolves to exactly one bounded record naming the class and origin."""

    assert error.code is code
    assert error.retryable is False
    assert error.correlation_id is not None
    assert error.safe_details == {"phase": phase}
    assert _CANARY not in error.message
    records = _records(correlation_id=error.correlation_id)
    assert len(records) == 1
    record = records[0]
    assert record["component"] == "application.status"
    assert record["operation"] == operation
    assert record["reason"] == reason
    assert record["request_id"] == request_id
    origin = record["origin"]
    assert type(origin) is str and origin.startswith(origin_module + ":")
    # A classified status fault is never recorded as an invalid caller request.
    assert all(item.get("reason") != "invalid_request" for item in _records(request_id=request_id))
    _assert_ring_is_content_free()


async def test_project_view_survives_member_receipts_from_both_roots(tmp_path: Path) -> None:
    """The native #840 shape: both roots read project membership, resources, and receipts."""

    async with multi_agent_service(tmp_path / "state") as service:
        first, second, project_id = await _two_roots_with_receipts(service, _workspace(tmp_path))
        roots = {root.task.task_id: root for root in (first, second)}
        for root in (first, second):
            # Selector-free (the frozen schema's intended form) and the source-supported own-task
            # selector must both answer without guessing a project id.
            for selectors in ({}, {"task_id": root.task.task_id}):
                result = await _status(
                    service, root.task, view="project", limit="100", selectors=selectors
                )
                page = result.page
                assert isinstance(page, StatusProjectPageModel)
                assert page.project_id == project_id
                assert {item.task_id for item in page.members} == set(roots)
                assert len(page.detections) == 1
                detection = page.detections[0]
                assert set(detection.task_ids) == set(roots)
                assert detection.resource_count == "1"
                assert isinstance(detection.resource_paths, OmittedContentModel)
                # Every member's recorded receipt is visible with its exact subject frontier.
                assert {item.task_id for item in page.receipts} == set(roots)
                for item in page.receipts:
                    expected = roots[item.task_id]
                    assert expected.receipt.receipt_id == item.receipt_id
                    assert item.frontier.model_dump(mode="json") == _frontier(
                        expected.checked.result_frontier
                    )
                    assert item.conclusion == expected.receipt.conclusion
                assert "project_member_unavailable" not in result.gaps
            advice = await _status(service, root.task, view="advice", limit="10")
            assert isinstance(advice.page, StatusAdvicePageModel)


async def test_member_receipt_projection_fault_degrades_only_that_member(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One member's unprojectable row is a disclosed gap and a joined record, not a lost view."""

    async with multi_agent_service(tmp_path / "state") as service:
        first, second, _project_id = await _two_roots_with_receipts(service, _workspace(tmp_path))
        real = StatusProjectReceiptModel

        class _FaultyReceiptModel:
            @staticmethod
            def model_validate(value: Mapping[str, object]) -> StatusProjectReceiptModel:
                if value["task_id"] == second.task.task_id:
                    raise ValueError(_CANARY)
                return real.model_validate(value)

        monkeypatch.setattr(task_views_module, "StatusProjectReceiptModel", _FaultyReceiptModel)
        request_id = new_id(IdKind.REQUEST)
        result = await _status(
            service, first.task, view="project", limit="100", request_id=request_id
        )
        page = result.page
        assert isinstance(page, StatusProjectPageModel)
        assert {item.task_id for item in page.members} == {
            first.task.task_id,
            second.task.task_id,
        }
        assert tuple(item.task_id for item in page.receipts) == (first.task.task_id,)
        assert "project_member_unavailable" in result.gaps
        records = [
            item
            for item in _records(request_id=request_id)
            if item["component"] == "application.status"
        ]
        assert len(records) == 1
        assert records[0]["operation"] == "status_project_model_failed"
        assert records[0]["reason"] == "exception_value_error"
        origin = records[0]["origin"]
        assert type(origin) is str and origin.startswith("yoetz.application.task_views:")
        _assert_ring_is_content_free()


async def test_member_replay_fault_degrades_only_that_member(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async with multi_agent_service(tmp_path / "state") as service:
        first, second, _project_id = await _two_roots_with_receipts(service, _workspace(tmp_path))
        real = task_views_module.lineage_manifest_from_records

        def faulty(records: Sequence[object]) -> object:
            if any(getattr(item, "task_id", None) == second.task.task_id for item in records):
                raise ValueError(_CANARY)
            return real(records)

        monkeypatch.setattr(task_views_module, "lineage_manifest_from_records", faulty)
        request_id = new_id(IdKind.REQUEST)
        result = await _status(
            service, first.task, view="project", limit="100", request_id=request_id
        )
        assert isinstance(result.page, StatusProjectPageModel)
        assert tuple(item.task_id for item in result.page.receipts) == (first.task.task_id,)
        assert "project_member_unavailable" in result.gaps
        (record,) = (
            item
            for item in _records(request_id=request_id)
            if item["component"] == "application.status"
        )
        assert record["operation"] == "status_project_replay_failed"
        assert record["reason"] == "exception_value_error"
        _assert_ring_is_content_free()


async def test_member_catalog_route_fault_degrades_only_that_member(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A corrupt catalog route is contained to its member before bundle routing begins."""

    async with multi_agent_service(tmp_path / "state") as service:
        first, second, _project_id = await _two_roots_with_receipts(service, _workspace(tmp_path))
        project_application = service.app.project_application
        assert project_application is not None
        admitted_view = await project_application.project_view_for(first.task.task_id)
        assert isinstance(admitted_view, ProjectStatus)
        compact = await _status(service, first.task, view="compact", limit="1")
        runtime = await service.app.runtime.route(
            RouteCommand(
                first.task.session_id,
                first.task.writer_id,
                RouteAccess.PAYLOAD_READ,
                frozenset({RuntimeCapability.STRUCTURAL_READ, RuntimeCapability.PAYLOAD_READ}),
            )
        )
        catalog_type = type(service.app.start_catalog)
        real_task_route = catalog_type.task_route

        async def corrupt_route(self: object, task_id: str) -> object:
            if task_id == second.task.task_id:
                raise PublicOperationError(
                    PublicErrorCode.STORAGE_CORRUPT,
                    "The stored project route is inconsistent.",
                    False,
                )
            return await real_task_route(self, task_id)  # type: ignore[arg-type]

        monkeypatch.setattr(catalog_type, "task_route", corrupt_route)
        request_id = new_id(IdKind.REQUEST)

        async def admitted(*_args: object, **_kwargs: object) -> ProjectStatus:
            return admitted_view

        try:
            snapshot = await task_views_module.project_status_snapshot(
                cast(ProjectApplication, SimpleNamespace(project_view_for=admitted)),
                service.app.start_catalog,
                service.app.runtime,
                runtime,
                compact.head_frontier,
                selected_task_id=None,
                project_id=None,
                request_id=request_id,
            )
            assert isinstance(snapshot, task_views_module.ProjectStatusSnapshot)
            assert first.task.task_id in {item.task_id for item in snapshot.members}
            assert tuple(item.task_id for item in snapshot.receipts) == (first.task.task_id,)
            assert "project_member_unavailable" in snapshot.gaps
            (record,) = tuple(
                item
                for item in _records(request_id=request_id)
                if item["component"] == "application.status"
            )
            assert record["operation"] == "status_project_member_unavailable"
            assert record["reason"] == "storage_corrupt"
            _assert_ring_is_content_free()
        finally:
            await service.app.runtime.release(runtime)


async def test_host_lineage_storage_fault_is_classified_at_status_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async with multi_agent_service(tmp_path / "state") as service:
        first, _second, _project_id = await _two_roots_with_receipts(service, _workspace(tmp_path))
        registry = service.app.host_lineage_registry
        assert registry is not None
        registry_type = type(registry)

        async def corrupt_annotations(self: object, *_args: object, **_kwargs: object) -> object:
            del self
            raise HostLineageRegistryError(HostLineageRegistryReason.STORAGE_CORRUPT)

        monkeypatch.setattr(registry_type, "list_provisional_annotations", corrupt_annotations)
        request_id = new_id(IdKind.REQUEST)
        with pytest.raises(PublicOperationError) as caught:
            await _status(service, first.task, view="lineage", limit="10", request_id=request_id)
        _assert_joined(
            caught.value,
            code=PublicErrorCode.STORAGE_CORRUPT,
            operation="status_lineage_replay_failed",
            phase="replay",
            reason="exception_host_lineage_registry_error",
            origin_module="yoetz.application.task_views",
            request_id=request_id,
        )


async def test_candidate_frontier_fault_is_classified_at_status_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async with multi_agent_service(tmp_path / "state") as service:
        first, _second, _project_id = await _two_roots_with_receipts(service, _workspace(tmp_path))
        real_projection = status_module.projection_for_records

        async def inconsistent_projection(*args: object) -> object:
            projection = await real_projection(*args)  # type: ignore[arg-type]
            return replace(projection, frontier=projection.frontier + 1)

        monkeypatch.setattr(status_module, "projection_for_records", inconsistent_projection)
        request_id = new_id(IdKind.REQUEST)
        with pytest.raises(PublicOperationError) as caught:
            await _status(
                service,
                first.task,
                view="candidate_findings",
                limit="10",
                request_id=request_id,
            )
        _assert_joined(
            caught.value,
            code=PublicErrorCode.STORAGE_CORRUPT,
            operation="status_candidate_findings_replay_failed",
            phase="replay",
            reason="exception_value_error",
            origin_module="yoetz.application.status",
            request_id=request_id,
        )


async def test_requester_lineage_replay_fault_is_storage_corrupt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async with multi_agent_service(tmp_path / "state") as service:
        first, _second, _project_id = await _two_roots_with_receipts(service, _workspace(tmp_path))

        def faulty(records: Sequence[object]) -> object:
            del records
            raise ValueError(_CANARY)

        monkeypatch.setattr(task_views_module, "lineage_manifest_from_records", faulty)
        request_id = new_id(IdKind.REQUEST)
        with pytest.raises(PublicOperationError) as caught:
            await _status(service, first.task, view="lineage", limit="10", request_id=request_id)
        _assert_joined(
            caught.value,
            code=PublicErrorCode.STORAGE_CORRUPT,
            operation="status_lineage_replay_failed",
            phase="replay",
            reason="exception_value_error",
            origin_module="yoetz.application.task_views",
            request_id=request_id,
        )


async def test_project_row_model_fault_is_internal_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A project-level row that fails its closed wire model is the service's own defect."""

    async with multi_agent_service(tmp_path / "state") as service:
        first, _second, _project_id = await _two_roots_with_receipts(service, _workspace(tmp_path))
        real = ProjectApplication.project_view_for

        async def invalid_detection(self: ProjectApplication, *args: object, **kwargs: object):
            view = await real(self, *args, **kwargs)  # type: ignore[arg-type]
            if not isinstance(view, ProjectStatus):
                return view
            row = dict(view.detections[0].items())
            row["task_ids"] = (first.task.task_id,)  # one task cannot form an overlap
            return replace(view, detections=(JsonObject(row),))

        monkeypatch.setattr(ProjectApplication, "project_view_for", invalid_detection)
        request_id = new_id(IdKind.REQUEST)
        with pytest.raises(PublicOperationError) as caught:
            await _status(service, first.task, view="project", limit="100", request_id=request_id)
        _assert_joined(
            caught.value,
            code=PublicErrorCode.INTERNAL_ERROR,
            operation="status_project_model_failed",
            phase="model",
            reason="exception_validation_error",
            origin_module="yoetz.application.task_views",
            request_id=request_id,
        )


async def test_project_snapshot_digest_fault_is_internal_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async with multi_agent_service(tmp_path / "state") as service:
        first, _second, _project_id = await _two_roots_with_receipts(service, _workspace(tmp_path))

        def faulty_digest(value: object) -> str:
            del value
            raise ValueError(_CANARY)

        monkeypatch.setattr(status_module, "canonical_digest", faulty_digest)
        request_id = new_id(IdKind.REQUEST)
        with pytest.raises(PublicOperationError) as caught:
            await _status(service, first.task, view="project", limit="100", request_id=request_id)
        _assert_joined(
            caught.value,
            code=PublicErrorCode.INTERNAL_ERROR,
            operation="status_project_digest_failed",
            phase="digest",
            reason="exception_value_error",
            origin_module="yoetz.application.status",
            request_id=request_id,
        )


async def test_unclassified_project_projection_fault_is_internal_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A coordination ValueError is not caller input, even though it subclasses ValueError."""

    async with multi_agent_service(tmp_path / "state") as service:
        first, _second, _project_id = await _two_roots_with_receipts(service, _workspace(tmp_path))

        async def broken(self: ProjectApplication, *args: object, **kwargs: object) -> object:
            del self, args, kwargs
            raise CoordinationError(CoordinationErrorCode.INVALID)

        monkeypatch.setattr(ProjectApplication, "project_view_for", broken)
        request_id = new_id(IdKind.REQUEST)
        with pytest.raises(PublicOperationError) as caught:
            await _status(service, first.task, view="project", limit="100", request_id=request_id)
        _assert_joined(
            caught.value,
            code=PublicErrorCode.INTERNAL_ERROR,
            operation="status_project_projection_failed",
            phase="projection",
            reason="exception_coordination_error",
            origin_module="yoetz.application.task_views",
            request_id=request_id,
        )


async def test_caller_query_shape_remains_invalid_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only the caller's own view/filter/cursor translation still maps to INVALID_REQUEST."""

    async with multi_agent_service(tmp_path / "state") as service:
        first, _second, _project_id = await _two_roots_with_receipts(service, _workspace(tmp_path))

        def rejected(value: object) -> object:
            del value
            raise ValueError("status_filter_invalid")

        monkeypatch.setattr(status_module, "_port_filter", rejected)
        request_id = new_id(IdKind.REQUEST)
        with pytest.raises(PublicOperationError) as caught:
            await _status(
                service, first.task, view="obligations", limit="10", request_id=request_id
            )
        assert caught.value.code is PublicErrorCode.INVALID_REQUEST
        assert caught.value.message == "The status request is invalid."
        assert not [
            item
            for item in _records(request_id=request_id)
            if item["component"] == "application.status"
        ]


async def test_lineage_and_project_views_still_answer_without_faults(tmp_path: Path) -> None:
    """Guard the fixture itself: the injected cases above start from a healthy project."""

    async with multi_agent_service(tmp_path / "state") as service:
        first, _second, _project_id = await _two_roots_with_receipts(service, _workspace(tmp_path))
        lineage = await _status(service, first.task, view="lineage", limit="10")
        assert isinstance(lineage.page, StatusLineagePageModel)
        path = diagnostics.diagnostic_log_path()
        if path.is_file():
            for line in path.read_text(encoding="ascii").splitlines():
                assert json.loads(line).get("component") != "application.status"
