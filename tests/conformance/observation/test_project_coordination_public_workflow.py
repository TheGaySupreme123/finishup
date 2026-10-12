"""Public-service proof for the durable project coordination flow.

The scenario exercises the production READY composition from typed work publication through
recipient-ledger context append, default coordination checking, and a typed disposition.  It keeps
the generic response acknowledgement in the middle to prove that acknowledgement alone does not
address an overlap.
"""

from __future__ import annotations

import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast

import pytest

from builders.multi_agent import MultiAgentService, multi_agent_service
from yoetz.adapters.integrations.observation_local import LocalObservationStore
from yoetz.application.coordination import CoordinationRuntime
from yoetz.application.publish_work import PublishWorkInternalResult
from yoetz.application.start import StartInternalResult
from yoetz.application.status import StatusInternalResult
from yoetz.domain.findings import FindingKind
from yoetz.domain.observation import ObservationRevokeCommand
from yoetz.ports.control import RepositoryPrivacyContext
from yoetz.ports.diagnostics import RuntimeCapability
from yoetz.ports.ledger import CheckCommitResult
from yoetz.ports.runtime import RouteAccess, RouteCommand
from yoetz.protocol.ids import IdKind, new_id
from yoetz.protocol.models import (
    CheckRequest,
    PublishWorkRequest,
    ReceiptRequest,
    RespondRequest,
    StartRequest,
    StatusProjectPageModel,
    StatusRequest,
)

pytestmark = pytest.mark.anyio

_REPOSITORY = RepositoryPrivacyContext("hmac-sha256:" + "d" * 64, "git_common_root")


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _identity() -> dict[str, object]:
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": new_id(IdKind.REQUEST),
        "actor": {"actor_id": "harness:project-coordination", "actor_type": "harness"},
        "client": {
            "kind": "cooperative_agent",
            "version": "0.1.0",
            "integration": "cooperative_mcp",
        },
    }


def _frontier(frontier: object) -> Mapping[str, object]:
    as_wire = getattr(frontier, "as_wire", None)
    if callable(as_wire):
        wire = cast(Mapping[str, object], as_wire())
        return dict(wire.items())
    model_dump = getattr(frontier, "model_dump", None)
    if callable(model_dump):
        return cast(Mapping[str, object], model_dump(mode="json"))
    raise AssertionError("frontier is not serializable")


def _event(
    name: str,
    payload: Mapping[str, object],
    *,
    evidence_refs: Sequence[str] = (),
) -> dict[str, object]:
    return {
        "event_id": new_id(IdKind.EVENT),
        "schema": {"name": name, "version": "1.0.0"},
        "occurred_at": "2026-09-05T12:00:00.000Z",
        "causal_parents": (),
        "payload": dict(payload),
        "artifact_refs": (),
        "evidence_refs": tuple(evidence_refs),
    }


async def _status(
    service: MultiAgentService,
    task: StartInternalResult,
    *,
    view: str = "compact",
    project_id: str | None = None,
    limit: str = "1",
) -> StatusInternalResult:
    body: dict[str, object] = {
        **_identity(),
        "session_id": task.session_id,
        "writer_id": task.writer_id,
        "view": view,
        "limit": limit,
    }
    if project_id is not None:
        body["project_id"] = project_id
    result = await service.app.status(
        StatusRequest.model_validate(body),
        repository_privacy_context=_REPOSITORY,
    )
    assert isinstance(result, StatusInternalResult)
    return result


async def _publish(
    service: MultiAgentService,
    task: StartInternalResult,
    drafts: Sequence[Mapping[str, object]],
) -> PublishWorkInternalResult:
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
    return result


async def _check(service: MultiAgentService, task: StartInternalResult) -> CheckCommitResult:
    status = await _status(service, task)
    result = await service.app.check(
        CheckRequest.model_validate(
            {
                **_identity(),
                "session_id": task.session_id,
                "writer_id": task.writer_id,
                "expected_frontier": _frontier(status.head_frontier),
                "mode": "deterministic_only",
                "max_findings": "10",
                # Deliberately omitted: production default selection must include coordination.
            }
        ),
        repository_privacy_context=_REPOSITORY,
    )
    assert isinstance(result, CheckCommitResult)
    return result


async def _ledger_schema_names(
    service: MultiAgentService, task: StartInternalResult
) -> tuple[str, ...]:
    route = await service.app.start_catalog.task_route(task.task_id)
    assert route is not None
    runtime = await service.app.runtime.route(
        RouteCommand(
            route.session_id,
            task.writer_id,
            RouteAccess.STRUCTURAL_READ,
            frozenset({RuntimeCapability.STRUCTURAL_READ}),
        )
    )
    try:
        names: list[str] = []
        async for record in runtime.ledger.load_events(runtime.session_id):
            names.append(record.schema.name)
        return tuple(names)
    finally:
        await service.app.runtime.release(runtime)


async def test_public_coordination_context_finding_disposition_and_recheck(
    tmp_path: Path,
) -> None:
    workspace = (tmp_path / "workspace").resolve()
    workspace.mkdir()
    subprocess.run(["git", "init", "--quiet", str(workspace)], check=True, capture_output=True)

    async with multi_agent_service(tmp_path / "state") as service:
        tasks = [
            await service.app.start(
                StartRequest.model_validate(
                    {
                        **_identity(),
                        "mode": "create",
                        "task_title": f"Coordination sibling {index}",
                        "workspace_ref": str(workspace),
                        "external_ref": f"coordination-sibling-{index}",
                        "requested_view": "compact",
                    }
                ),
                repository_privacy_context=_REPOSITORY,
            )
            for index in range(2)
        ]
        observation_store = LocalObservationStore(_state=service.root / "state")
        workspace_commitment = observation_store.workspace_commitment(str(workspace))
        observation_store.grant_consent(workspace_commitment)

        obligation_ids: list[str] = []
        for index, task in enumerate(tasks):
            obligation = new_id(IdKind.OBLIGATION)
            obligation_ids.append(obligation)
            await _publish(
                service,
                task,
                (
                    _event(
                        "obligation_published",
                        {
                            "obligation_id": obligation,
                            "description": f"Coordinate shared file work {index}.",
                            "evidence_expectation": "A recorded coordination decision.",
                            "status": "open",
                            "requested_items": ({"item_kind": "file", "value": "src/shared.py"},),
                        },
                    ),
                ),
            )

        project_ids = await service.app.start_catalog.list_task_project_ids(tasks[0].task_id)
        assert len(project_ids) == 1
        project_application = service.app.project_application
        assert project_application is not None
        coordination = cast(
            CoordinationRuntime, getattr(project_application, "coordination_runtime")
        )
        detections = await coordination.detector.store.list_detections(project_ids[0])
        assert len(detections) == 1
        detection = detections[0]
        deliveries = await coordination.detector.store.deliveries(detection.detection_id)
        assert len(deliveries) == 2
        assert {row.outcome for row in deliveries} == {"delivered"}
        ledger_names = [await _ledger_schema_names(service, task) for task in tasks]
        assert all("coordination_context_recorded" in names for names in ledger_names)

        # Ordinary FILE/SOURCE obligations create advice and frozen context only.  They do not
        # authorize a coordination finding until one participant explicitly binds its open
        # obligation to this exact detection.
        advice_only = await _check(service, tasks[0])
        assert len(advice_only.advisory_notes) == 1
        advice_note = advice_only.advisory_notes[0]
        assert advice_note.kind == "live_member_present"
        assert advice_note.project_id == project_ids[0]
        assert advice_note.task_ids == (tasks[1].task_id,)
        assert advice_note.count == 1
        assert not any(
            item.kind is FindingKind.COORDINATION_OVERLAP for item in advice_only.findings
        )
        await _publish(
            service,
            tasks[0],
            (
                _event(
                    "coordination_obligation_declared",
                    {
                        "detection_id": detection.detection_id,
                        "project_id": project_ids[0],
                        "membership_generation": "1",
                        "recipient_task_id": tasks[0].task_id,
                        "obligation_id": obligation_ids[0],
                    },
                ),
            ),
        )
        declared_names = await _ledger_schema_names(service, tasks[0])
        assert "coordination_obligation_declared" in declared_names
        declared_input = await coordination.inputs.input_for(
            tasks[0].task_id,
            project_ids[0],
        )
        assert declared_input is not None
        assert tuple(item.detection_id for item in declared_input.coordination_declarations) == (
            detection.detection_id,
        )

        checked = await _check(service, tasks[0])
        assert len(checked.findings) == 1
        finding = checked.findings[0]
        assert finding.kind is FindingKind.COORDINATION_OVERLAP
        assert finding.policy_id == "coordination"
        assert checked.versions.policy_packs == (
            "coordination/0.1.0",
            "research-evidence/0.2.0",
            "work-integrity/0.3.0",
        )

        acknowledged = await service.app.respond(
            RespondRequest.model_validate(
                {
                    **_identity(),
                    "session_id": tasks[0].session_id,
                    "writer_id": tasks[0].writer_id,
                    "expected_frontier": _frontier(checked.result_frontier),
                    "finding_id": finding.finding_id,
                    "finding_frontier": _frontier(checked.result_frontier),
                    "disposition": "acknowledged",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        assert acknowledged.response.disposition == "acknowledged"
        still_open = await _check(service, tasks[0])
        assert any(item.kind is FindingKind.COORDINATION_OVERLAP for item in still_open.findings)

        evidence_id = new_id(IdKind.EVIDENCE)
        await _publish(
            service,
            tasks[0],
            (
                _event(
                    "evidence_recorded",
                    {
                        "evidence_id": evidence_id,
                        "evidence_kind": "test_result",
                        "strength": "content_digest",
                        "content_digest": "sha256:" + "e" * 64,
                        "observed_at": "2026-09-05T12:00:03.000Z",
                        "description": "The shared-work disposition was recorded.",
                    },
                ),
            ),
        )
        await _publish(
            service,
            tasks[0],
            (
                _event(
                    "coordination_disposition_recorded",
                    {
                        "detection_id": detection.detection_id,
                        "project_id": project_ids[0],
                        "membership_generation": "1",
                        "recipient_task_id": tasks[0].task_id,
                        "obligation_id": obligation_ids[0],
                        "disposition": "shared_work",
                        "evidence_refs": (evidence_id,),
                    },
                    evidence_refs=(evidence_id,),
                ),
            ),
        )
        resolved = await _check(service, tasks[0])
        assert not any(item.kind is FindingKind.COORDINATION_OVERLAP for item in resolved.findings)
        # The physical overlap and its pair delivery remain durable; only the qualifying recipient
        # check changed the finding state.
        assert detection.overlap_kind.value == "physical"
        assert len(await coordination.detector.store.deliveries(detection.detection_id)) == 2

        receipt = await service.app.receipt(
            ReceiptRequest.model_validate(
                {
                    **_identity(),
                    "task_id": tasks[0].task_id,
                    "session_id": tasks[0].session_id,
                    "writer_id": tasks[0].writer_id,
                    "expected_frontier": _frontier(resolved.result_frontier),
                    "format": "json",
                    "include": "standard",
                    "redaction_profile": "full_local",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        assert receipt.document is not None
        assert receipt.human_text is None
        rendered = cast(Mapping[str, object], receipt.document)
        assert rendered.get("conclusion") == receipt.conclusion

        text_receipt = await service.app.receipt(
            ReceiptRequest.model_validate(
                {
                    **_identity(),
                    "task_id": tasks[0].task_id,
                    "session_id": tasks[0].session_id,
                    "writer_id": tasks[0].writer_id,
                    "expected_frontier": _frontier(receipt.result_frontier),
                    "format": "text",
                    "include": "standard",
                    "redaction_profile": "full_local",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        assert text_receipt.document is None
        assert text_receipt.human_text is not None

        markdown_receipt = await service.app.receipt(
            ReceiptRequest.model_validate(
                {
                    **_identity(),
                    "task_id": tasks[0].task_id,
                    "session_id": tasks[0].session_id,
                    "writer_id": tasks[0].writer_id,
                    "expected_frontier": _frontier(text_receipt.result_frontier),
                    "format": "markdown",
                    "include": "standard",
                    "redaction_profile": "full_local",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        assert markdown_receipt.document is None
        assert markdown_receipt.human_text is not None
        assert "resolved" in markdown_receipt.human_text.lower()


async def test_check_project_presence_advice_without_overlap_preserves_verdict(
    tmp_path: Path,
) -> None:
    """A live admitted member is advisory even when no overlap detection exists."""

    workspace = (tmp_path / "workspace").resolve()
    workspace.mkdir()
    subprocess.run(["git", "init", "--quiet", str(workspace)], check=True, capture_output=True)

    async with multi_agent_service(tmp_path / "state") as service:
        first = await service.app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create",
                    "task_title": "Presence requester",
                    "workspace_ref": str(workspace),
                    "external_ref": "presence-requester",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        LocalObservationStore(_state=service.root / "state").grant_consent(
            LocalObservationStore(_state=service.root / "state").workspace_commitment(
                str(workspace)
            )
        )
        before = await _check(service, first)
        assert before.advisory_notes == ()

        second = await service.app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create",
                    "task_title": "Presence sibling",
                    "workspace_ref": str(workspace),
                    "external_ref": "presence-sibling",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        await _publish(
            service,
            second,
            (
                _event(
                    "obligation_published",
                    {
                        "obligation_id": new_id(IdKind.OBLIGATION),
                        "description": "A distinct sibling scope.",
                        "evidence_expectation": "A recorded result.",
                        "status": "open",
                        "requested_items": ({"item_kind": "file", "value": "src/other.py"},),
                    },
                ),
            ),
        )
        project_ids = await service.app.start_catalog.list_task_project_ids(first.task_id)
        assert len(project_ids) == 1
        coordination = cast(
            CoordinationRuntime, getattr(service.app.project_application, "coordination_runtime")
        )
        assert await coordination.detector.store.list_detections(project_ids[0]) == ()
        after = await _check(service, first)
        assert after.verdict == before.verdict
        assert tuple((item.kind, item.subject_refs) for item in after.findings) == tuple(
            (item.kind, item.subject_refs) for item in before.findings
        )
        assert len(after.advisory_notes) == 1
        note = after.advisory_notes[0]
        assert note.kind == "live_member_present"
        assert note.task_ids == (second.task_id,)
        assert note.count == 1


async def test_check_duplicate_finding_advice_is_separate_from_findings(
    tmp_path: Path,
) -> None:
    """Matching typed finding/resource identities produce a non-verdict duplicate note."""

    workspace = (tmp_path / "workspace").resolve()
    workspace.mkdir()
    subprocess.run(["git", "init", "--quiet", str(workspace)], check=True, capture_output=True)

    async with multi_agent_service(tmp_path / "state") as service:
        tasks = [
            await service.app.start(
                StartRequest.model_validate(
                    {
                        **_identity(),
                        "mode": "create",
                        "task_title": f"Duplicate sibling {index}",
                        "workspace_ref": str(workspace),
                        "external_ref": f"duplicate-sibling-{index}",
                        "requested_view": "compact",
                    }
                ),
                repository_privacy_context=_REPOSITORY,
            )
            for index in range(2)
        ]
        LocalObservationStore(_state=service.root / "state").grant_consent(
            LocalObservationStore(_state=service.root / "state").workspace_commitment(
                str(workspace)
            )
        )

        for task in tasks:
            obligation = new_id(IdKind.OBLIGATION)
            await _publish(
                service,
                task,
                (
                    _event(
                        "obligation_published",
                        {
                            "obligation_id": obligation,
                            "description": "Same typed shared scope.",
                            "evidence_expectation": "A recorded result.",
                            "status": "open",
                            "requested_items": ({"item_kind": "file", "value": "src/shared.py"},),
                        },
                    ),
                    _event(
                        "claim_recorded",
                        {
                            "claim_id": new_id(IdKind.CLAIM),
                            "claim_kind": "completion",
                            "statement": "The work is complete.",
                            "supporting_refs": (obligation,),
                            "obligation_refs": (obligation,),
                        },
                    ),
                ),
            )

        sibling_checked = await _check(service, tasks[1])
        assert sibling_checked.findings
        requester_checked = await _check(service, tasks[0])
        notes_by_kind = {note.kind: note for note in requester_checked.advisory_notes}
        assert notes_by_kind["live_member_present"].task_ids == (tasks[1].task_id,)
        duplicate = notes_by_kind["duplicate_finding"]
        assert duplicate.task_ids == tuple(sorted((tasks[0].task_id, tasks[1].task_id)))
        assert duplicate.count == 2
        assert requester_checked.verdict == "action_required"
        assert all(note.kind != "coordination_overlap" for note in requester_checked.advisory_notes)


async def test_public_coordination_unobservable_coverage_has_no_fake_pair(
    tmp_path: Path,
) -> None:
    workspace = (tmp_path / "workspace").resolve()
    workspace.mkdir()
    subprocess.run(["git", "init", "--quiet", str(workspace)], check=True, capture_output=True)

    async with multi_agent_service(tmp_path / "state") as service:
        tasks = [
            await service.app.start(
                StartRequest.model_validate(
                    {
                        **_identity(),
                        "mode": "create",
                        "task_title": f"Unobservable sibling {index}",
                        "workspace_ref": str(workspace),
                        "external_ref": f"unobservable-sibling-{index}",
                        "requested_view": "compact",
                    }
                ),
                repository_privacy_context=_REPOSITORY,
            )
            for index in range(2)
        ]
        observation_store = LocalObservationStore(_state=service.root / "state")
        workspace_commitment = observation_store.workspace_commitment(str(workspace))
        observation_store.grant_consent(workspace_commitment)
        evidence_id = new_id(IdKind.EVIDENCE)
        await _publish(
            service,
            tasks[0],
            (
                _event(
                    "evidence_recorded",
                    {
                        "evidence_id": evidence_id,
                        "evidence_kind": "test_result",
                        "strength": "content_digest",
                        "content_digest": "sha256:" + "f" * 64,
                        "observed_at": "2026-09-05T12:01:00.000Z",
                        "description": "No attributable path was published.",
                    },
                ),
            ),
        )
        project_ids = await service.app.start_catalog.list_task_project_ids(tasks[0].task_id)
        assert len(project_ids) == 1
        project = await service.app.start_catalog.project_state(project_ids[0])
        assert project is not None
        project_application = service.app.project_application
        assert project_application is not None
        coordination = cast(
            CoordinationRuntime, getattr(project_application, "coordination_runtime")
        )
        rows = await coordination.detector.store.coverage_for(
            project_ids[0], project.membership_generation
        )
        assert {row.task_id for row in rows} == {task.task_id for task in tasks}
        assert all(row.coverage == "unobservable" for row in rows)
        assert all(row.gap_code.value == "not_observable" for row in rows)
        assert all("resource" not in row.as_wire() for row in rows)
        assert await coordination.detector.store.list_detections(project_ids[0]) == ()
        status = await _status(
            service,
            tasks[0],
            view="project",
            project_id=project_ids[0],
            limit="100",
        )
        assert isinstance(status.page, StatusProjectPageModel)
        assert {(item.task_id, item.coverage, item.gap_code) for item in status.page.coverage} == {
            (row.task_id, row.coverage, row.gap_code.value) for row in rows
        }

        public_rows = await project_application.coordination_coverage_for(
            tasks[0].task_id,
            project=project_ids[0],
            expected_generation=project.membership_generation,
        )
        assert public_rows == rows
        observation_store.revoke(ObservationRevokeCommand(workspace_commitment))
        assert (
            await project_application.coordination_coverage_for(
                tasks[0].task_id,
                project=project_ids[0],
                expected_generation=project.membership_generation,
            )
            == ()
        )
