"""Superseded project generations close stranded coordination findings (issue #842).

A membership-generation change fences coordination authority immediately.  Before #842, a context
and declaration already recorded in a recipient ledger kept deriving an actionable
``coordination_overlap`` finding that its typed disposition could no longer address, because the
disposition must be admitted at that exact old generation.  These scenarios drive every
generation-advancing path through the production READY composition: disposition refusal, the
next check, and the receipt, plus successor-detection isolation.
"""

from __future__ import annotations

import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast

import pytest

from builders.multi_agent import (
    MultiAgentService,
    multi_agent_service,
    relock_and_reopen_multi_agent_service,
)
from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.application.coordination import CoordinationRuntime
from finishup.application.projects import ProjectRevokeCommand
from finishup.application.publish_work import PublishWorkInternalResult
from finishup.application.start import StartInternalResult
from finishup.application.status import StatusInternalResult
from finishup.domain.coordination import CoordinationDetection, CoordinationGapCode
from finishup.domain.events import AcceptedEvent, CoordinationContextRecordedPayload
from finishup.domain.findings import Finding, FindingKind
from finishup.domain.values import JsonObject
from finishup.ports.control import RepositoryPrivacyContext
from finishup.ports.diagnostics import RuntimeCapability
from finishup.ports.ledger import CheckCommitResult
from finishup.ports.runtime import RouteAccess, RouteCommand
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.ids import IdKind, new_id
from finishup.protocol.models import (
    CheckRequest,
    PublishWorkRequest,
    ReceiptRequest,
    StartRequest,
    StatusFindingsPageModel,
    StatusRequest,
)
from finishup.protocol.recovery import RECOVERY_DIRECTIVES
from finishup.service.elevated_bootstrap import (
    load_pending,
    record_project_coordination_authorization,
)

pytestmark = pytest.mark.anyio

_REPOSITORY = RepositoryPrivacyContext("hmac-sha256:" + "d" * 64, "git_common_root")
_SUPERSEDED_REASON = "coordination_generation_superseded"
_SUPERSEDED_CONTINUATION = "coordination_superseded_recheck"

_REPOSITORY_CHANGES = ("opt_out_opt_in", "opt_out", "consent_revoke", "consent_revoke_reconsent")
_GENERAL_CHANGES = (
    "grant_revoke_regrant",
    "link_third_task",
    "unlink_recipient",
    "unlink_counterpart",
    "dissolve",
)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _identity() -> dict[str, object]:
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": new_id(IdKind.REQUEST),
        "actor": {"actor_id": "harness:coordination-superseded", "actor_type": "harness"},
        "client": {
            "kind": "cooperative_agent",
            "version": "0.1.0",
            "integration": "cooperative_mcp",
        },
    }


def _event(
    name: str,
    payload: Mapping[str, object],
    *,
    evidence_refs: Sequence[str] = (),
) -> dict[str, object]:
    return {
        "event_id": new_id(IdKind.EVENT),
        "schema": {"name": name, "version": "1.0.0"},
        "occurred_at": "2026-09-25T12:00:00.000Z",
        "causal_parents": (),
        "payload": dict(payload),
        "artifact_refs": (),
        "evidence_refs": tuple(evidence_refs),
    }


def _frontier(value: object) -> Mapping[str, object]:
    as_wire = getattr(value, "as_wire", None)
    if callable(as_wire):
        return dict(cast(Mapping[str, object], as_wire()).items())
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        return dict(cast(Mapping[str, object], model_dump(mode="json")).items())
    raise AssertionError("frontier_not_serializable")


async def _status(
    service: MultiAgentService,
    task: StartInternalResult,
    *,
    view: str = "compact",
    limit: str = "10",
) -> StatusInternalResult:
    result = await service.app.status(
        StatusRequest.model_validate(
            {
                **_identity(),
                "session_id": task.session_id,
                "writer_id": task.writer_id,
                "view": view,
                "limit": limit,
            }
        ),
        repository_privacy_context=_REPOSITORY,
    )
    assert isinstance(result, StatusInternalResult)
    return result


def _publish_request(
    task: StartInternalResult, status: StatusInternalResult, drafts: Sequence[Mapping[str, object]]
) -> PublishWorkRequest:
    return PublishWorkRequest.model_validate(
        {
            **_identity(),
            "session_id": task.session_id,
            "writer_id": task.writer_id,
            "expected_frontier": _frontier(status.head_frontier),
            "event_drafts": tuple(dict(item) for item in drafts),
        }
    )


async def _publish(
    service: MultiAgentService,
    task: StartInternalResult,
    drafts: Sequence[Mapping[str, object]],
) -> PublishWorkInternalResult:
    status = await _status(service, task)
    result = await service.app.publish_work(
        _publish_request(task, status, drafts),
        repository_privacy_context=_REPOSITORY,
    )
    assert isinstance(result, PublishWorkInternalResult)
    return result


async def _publish_refused(
    service: MultiAgentService,
    task: StartInternalResult,
    drafts: Sequence[Mapping[str, object]],
) -> PublicOperationError:
    status = await _status(service, task)
    with pytest.raises(PublicOperationError) as refused:
        await service.app.publish_work(
            _publish_request(task, status, drafts),
            repository_privacy_context=_REPOSITORY,
        )
    after = await _status(service, task)
    # A refused publication appends nothing, not even a service-stamped closure.
    assert after.head_frontier == status.head_frontier
    return refused.value


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
            }
        ),
        repository_privacy_context=_REPOSITORY,
    )
    assert isinstance(result, CheckCommitResult)
    return result


async def _receipt(
    service: MultiAgentService,
    task: StartInternalResult,
    checked: CheckCommitResult,
    *,
    output: str,
) -> object:
    return await service.app.receipt(
        ReceiptRequest.model_validate(
            {
                **_identity(),
                "task_id": task.task_id,
                "session_id": task.session_id,
                "writer_id": task.writer_id,
                "expected_frontier": _frontier(checked.result_frontier),
                "format": output,
                "include": "standard",
                "redaction_profile": "full_local",
            }
        ),
        repository_privacy_context=_REPOSITORY,
    )


async def _ledger_contexts(
    service: MultiAgentService, task: StartInternalResult
) -> tuple[tuple[str, CoordinationContextRecordedPayload], ...]:
    route = await service.app.start_catalog.task_route(task.task_id)
    assert route is not None
    # A payload read opens a task that no route has touched since a service restart.
    runtime = await service.app.runtime.route(
        RouteCommand(
            route.session_id,
            None,
            RouteAccess.PAYLOAD_READ,
            frozenset({RuntimeCapability.STRUCTURAL_READ, RuntimeCapability.PAYLOAD_READ}),
        )
    )
    try:
        contexts: list[tuple[str, CoordinationContextRecordedPayload]] = []
        async for record in runtime.ledger.load_events(runtime.session_id):
            if type(record) is AcceptedEvent and isinstance(
                record.payload, CoordinationContextRecordedPayload
            ):
                contexts.append((record.event_id, record.payload))
        return tuple(contexts)
    finally:
        await service.app.runtime.release(runtime)


def _coordination(service: MultiAgentService) -> CoordinationRuntime:
    project_application = service.app.project_application
    assert project_application is not None
    return cast(CoordinationRuntime, getattr(project_application, "coordination_runtime"))


async def _start_pair(
    service: MultiAgentService, workspace: Path
) -> tuple[StartInternalResult, StartInternalResult]:
    tasks = [
        await service.app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create",
                    "task_title": f"Superseded coordination sibling {index}",
                    "workspace_ref": str(workspace),
                    "external_ref": f"superseded-coordination-{index}",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        for index in range(2)
    ]
    observation = LocalObservationStore(_state=service.root / "state")
    observation.grant_consent(observation.workspace_commitment(str(workspace)))
    return tasks[0], tasks[1]


async def _project_operation(service: MultiAgentService, body: Mapping[str, object]) -> JsonObject:
    return await service.app.project(
        JsonObject({"schema_version": "1.0.0", "request_id": new_id(IdKind.REQUEST), **body}),
        repository_privacy_context=_REPOSITORY,
    )


async def _grant_general_project(service: MultiAgentService, project: str, generation: int) -> None:
    body = {"operation": "grant", "project_id": project, "membership_generation": generation}
    request_id = new_id(IdKind.REQUEST)
    request = JsonObject({"schema_version": "1.0.0", "request_id": request_id, **body})
    try:
        await service.app.project(request, repository_privacy_context=_REPOSITORY)
    except Exception:
        pending = load_pending(_state=service.root / "state")
        assert pending is not None and pending.coordination_binding is not None
        record_project_coordination_authorization(pending, _state=service.root / "state")
    granted = await service.app.project(request, repository_privacy_context=_REPOSITORY)
    assert granted["state"] == "active"


async def _repository_commitment(service: MultiAgentService, task: StartInternalResult) -> str:
    provenance = await service.app.start_catalog.task_source_provenance(task.task_id)
    assert provenance is not None
    assert provenance.repository_privacy_commitment is not None
    return provenance.repository_privacy_commitment


async def _general_project(
    service: MultiAgentService, tasks: tuple[StartInternalResult, StartInternalResult]
) -> str:
    """Opt the repository out, then group both tasks in one granted general project."""

    await _project_operation(
        service,
        {
            "operation": "opt_out",
            "repository_commitment": await _repository_commitment(service, tasks[0]),
        },
    )
    created = await _project_operation(
        service,
        {
            "operation": "create",
            "title": "Superseded coordination general project",
            "owner_task_id": tasks[0].task_id,
        },
    )
    project = created["project_id"]
    assert isinstance(project, str)
    await _grant_general_project(service, project, 1)
    for task in tasks:
        provenance = await service.app.start_catalog.task_source_provenance(task.task_id)
        assert provenance is not None and provenance.workspace_ref_commitment is not None
        await _project_operation(
            service,
            {
                "operation": "link",
                "project_id": project,
                "member_kind": "task",
                "member_commitment_or_id": task.task_id,
                "source_workspace_commitment": provenance.workspace_ref_commitment,
            },
        )
        state = await service.app.start_catalog.project_state(project)
        assert state is not None
        await _grant_general_project(service, project, state.membership_generation)
    return project


async def _declared_overlap(
    service: MultiAgentService,
    tasks: tuple[StartInternalResult, StartInternalResult],
    project: str | None,
    *,
    overlap: str = "physical",
) -> tuple[CoordinationDetection, str, Finding]:
    """Publish one overlapping obligation per task and bind task 0's to the detection.

    ``physical`` shares one typed file resource.  ``plan`` shares only a structured plan item,
    whose context the check evaluates without attributable paths.
    """

    obligations = [new_id(IdKind.OBLIGATION) for _ in tasks]
    for index, (task, obligation) in enumerate(zip(tasks, obligations, strict=True)):
        resource = "src/shared.py" if overlap == "physical" else f"src/independent-{index}.py"
        drafts: list[dict[str, object]] = [
            _event(
                "obligation_published",
                {
                    "obligation_id": obligation,
                    "description": f"Coordinate the overlapping work {index}.",
                    "evidence_expectation": "A recorded coordination decision.",
                    "status": "open",
                    "requested_items": ({"item_kind": "file", "value": resource},),
                },
            )
        ]
        if overlap == "plan":
            # Both plans name the recipient's own obligation, so the recipient ledger has no
            # dangling reference that would itself block finding resolution.
            drafts.append(
                _event(
                    "plan_published",
                    {
                        "plan_version": 1,
                        "summary": "Coordinate the shared plan item.",
                        "obligation_refs": (obligations[0],),
                    },
                )
            )
        await _publish(service, task, drafts)
    if project is None:
        project_ids = await service.app.start_catalog.list_task_project_ids(tasks[0].task_id)
        assert len(project_ids) == 1
        project = project_ids[0]
    detections = await _coordination(service).detector.store.list_detections(project)
    assert len(detections) == 1
    detection = detections[0]
    assert detection.overlap_kind.value == overlap
    await _publish(
        service,
        tasks[0],
        (
            _event(
                "coordination_obligation_declared",
                {
                    "detection_id": detection.detection_id,
                    "project_id": project,
                    "membership_generation": str(detection.membership_generation),
                    "recipient_task_id": tasks[0].task_id,
                    "obligation_id": obligations[0],
                },
            ),
        ),
    )
    checked = await _check(service, tasks[0])
    overlaps = [item for item in checked.findings if item.kind is FindingKind.COORDINATION_OVERLAP]
    assert len(overlaps) == 1
    # While the generation is current, nothing is closed early.
    assert not any(
        CoordinationGapCode.REVOKED in payload.gap_codes
        for _, payload in await _ledger_contexts(service, tasks[0])
    )
    return detection, obligations[0], overlaps[0]


async def _supersede(
    service: MultiAgentService,
    change: str,
    tasks: tuple[StartInternalResult, StartInternalResult],
    project: str,
    workspace: Path,
) -> None:
    before = await service.app.start_catalog.project_state(project)
    assert before is not None
    if change in {"opt_out_opt_in", "opt_out"}:
        repository = await _repository_commitment(service, tasks[0])
        await _project_operation(
            service, {"operation": "opt_out", "repository_commitment": repository}
        )
        if change == "opt_out_opt_in":
            await _project_operation(
                service, {"operation": "opt_in", "repository_commitment": repository}
            )
    elif change in {"consent_revoke", "consent_revoke_reconsent"}:
        observation = LocalObservationStore(_state=service.root / "state")
        commitment = observation.workspace_commitment(str(workspace))
        await service.app.observation_revoke(
            {"workspace_commitment": commitment, "retain_evidence": True}
        )
        if change == "consent_revoke_reconsent":
            observation.grant_consent(commitment)
    elif change == "grant_revoke_regrant":
        project_application = service.app.project_application
        assert project_application is not None
        await project_application.revoke(
            ProjectRevokeCommand(project, before.membership_generation)
        )
        revoked = await service.app.start_catalog.project_state(project)
        assert revoked is not None
        await _grant_general_project(service, project, revoked.membership_generation)
    elif change == "link_third_task":
        third = await service.app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create",
                    "task_title": "Superseded coordination late member",
                    "workspace_ref": str(workspace),
                    "external_ref": "superseded-coordination-late-member",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        provenance = await service.app.start_catalog.task_source_provenance(third.task_id)
        assert provenance is not None and provenance.workspace_ref_commitment is not None
        await _project_operation(
            service,
            {
                "operation": "link",
                "project_id": project,
                "member_kind": "task",
                "member_commitment_or_id": third.task_id,
                "source_workspace_commitment": provenance.workspace_ref_commitment,
            },
        )
        linked = await service.app.start_catalog.project_state(project)
        assert linked is not None
        await _grant_general_project(service, project, linked.membership_generation)
    elif change in {"unlink_recipient", "unlink_counterpart"}:
        member = tasks[0] if change == "unlink_recipient" else tasks[1]
        await _project_operation(
            service,
            {
                "operation": "unlink",
                "project_id": project,
                "member_kind": "task",
                "member_commitment_or_id": member.task_id,
            },
        )
    elif change == "dissolve":
        await _project_operation(service, {"operation": "dissolve", "project_id": project})
    else:
        raise AssertionError(change)
    after = await service.app.start_catalog.project_state(project)
    assert after is not None
    assert after.membership_generation > before.membership_generation
    assert (after.dissolved_at is not None) is (change == "dissolve")


async def _assert_superseded_closure(
    service: MultiAgentService,
    tasks: tuple[StartInternalResult, StartInternalResult],
    detection: CoordinationDetection,
    obligation: str,
    stranded: Finding,
) -> None:
    recipient = tasks[0]
    generation = str(detection.membership_generation)
    evidence = new_id(IdKind.EVIDENCE)
    await _publish(
        service,
        recipient,
        (
            _event(
                "evidence_recorded",
                {
                    "evidence_id": evidence,
                    "evidence_kind": "test_result",
                    "strength": "content_digest",
                    "content_digest": "sha256:" + "e" * 64,
                    "observed_at": "2026-09-25T12:00:03.000Z",
                    "description": "The coordination decision was recorded.",
                },
            ),
        ),
    )

    # The typed disposition for the old generation stays refused (no authority is revived), but
    # the refusal names the superseded generation and an available action instead of asking the
    # caller to reauthorize a generation that can never be current again.
    refused = await _publish_refused(
        service,
        recipient,
        (
            _event(
                "coordination_disposition_recorded",
                {
                    "detection_id": detection.detection_id,
                    "project_id": detection.project_id,
                    "membership_generation": generation,
                    "recipient_task_id": recipient.task_id,
                    "obligation_id": obligation,
                    "disposition": "shared_work",
                    "evidence_refs": (evidence,),
                },
                evidence_refs=(evidence,),
            ),
        ),
    )
    assert refused.code is PublicErrorCode.INVALID_REQUEST
    assert refused.safe_details["reason_code"] == _SUPERSEDED_REASON
    assert refused.safe_details["continuation"] == _SUPERSEDED_CONTINUATION
    directive = RECOVERY_DIRECTIVES[_SUPERSEDED_CONTINUATION].directive
    assert "Run check" in directive and "cannot be reauthorized" in directive

    # A fresh declaration cannot rebind the old generation either.
    redeclared = await _publish_refused(
        service,
        recipient,
        (
            _event(
                "coordination_obligation_declared",
                {
                    "detection_id": detection.detection_id,
                    "project_id": detection.project_id,
                    "membership_generation": generation,
                    "recipient_task_id": recipient.task_id,
                    "obligation_id": obligation,
                },
            ),
        ),
    )
    assert redeclared.safe_details["reason_code"] == _SUPERSEDED_REASON

    # The next check records the durable closure in the recipient's own ledger, derives no
    # current coordination finding from the historical context, and resolves the stranded one.
    checked = await _check(service, recipient)
    assert not any(item.kind is FindingKind.COORDINATION_OVERLAP for item in checked.findings)
    contexts = await _ledger_contexts(service, recipient)
    delivered = [
        (event_id, payload)
        for event_id, payload in contexts
        if payload.detection_id == detection.detection_id
        and CoordinationGapCode.REVOKED not in payload.gap_codes
    ]
    closures = [
        payload
        for _, payload in contexts
        if payload.detection_id == detection.detection_id
        and CoordinationGapCode.REVOKED in payload.gap_codes
    ]
    assert len(delivered) == 1
    assert stranded.subject_refs == (delivered[0][0],)
    assert len(closures) == 1
    closure = closures[0]
    original = delivered[0][1]
    assert closure.gap_codes == (CoordinationGapCode.REVOKED,)
    assert closure.recipient_task_id == recipient.task_id
    assert closure.counterpart_task_id == original.counterpart_task_id
    assert closure.membership_generation == original.membership_generation
    assert closure.resource_identities == ()
    assert closure.resource_count == 0
    assert closure.detail_ref is None
    assert closure.source_attributable_paths is False
    # Only the recipient's own ledger is touched; the counterpart holds no closure.
    assert not any(
        CoordinationGapCode.REVOKED in payload.gap_codes
        for _, payload in await _ledger_contexts(service, tasks[1])
    )
    # The old detector row can no longer be redelivered.
    coordination = _coordination(service)
    stored = await coordination.detector.store.get_detection(detection.detection_id)
    assert stored is not None and stored.generation_valid is False
    assert await coordination.detector.redeliver(detection.detection_id) == ()

    findings_view = await _status(service, recipient, view="findings", limit="50")
    assert isinstance(findings_view.page, StatusFindingsPageModel)
    rows = {item.finding_id: item for item in findings_view.page.items}
    assert rows[stranded.finding_id].resolved is True
    detail = rows[stranded.finding_id].detail
    assert isinstance(detail, str)
    assert f"project coordination generation {generation} was superseded" in detail
    assert "not as a current coordination obligation" in detail

    # Rechecking is idempotent: the closure is recorded once.
    rechecked = await _check(service, recipient)
    assert not any(item.kind is FindingKind.COORDINATION_OVERLAP for item in rechecked.findings)
    assert (
        sum(
            1
            for _, payload in await _ledger_contexts(service, recipient)
            if CoordinationGapCode.REVOKED in payload.gap_codes
        )
        == 1
    )

    # Receipts carry the same distinction: the stranded finding is resolved history whose
    # explanation names the superseded generation, never a current unresolved obligation.
    json_receipt = await _receipt(service, recipient, rechecked, output="json")
    document = getattr(json_receipt, "document", None)
    assert isinstance(document, Mapping)
    sections = {
        cast(str, section["key"]): section
        for section in cast(Sequence[Mapping[str, object]], document["sections"])
    }
    assert stranded.finding_id in cast(Sequence[str], sections["summary"]["items"])
    findings_section = sections["findings_and_dispositions"]
    assert stranded.finding_id not in cast(Sequence[str], findings_section["items"])
    explanation = (
        f"{stranded.finding_id}: Resolved by qualifying check "
        if isinstance(findings_section["body"], str)
        else None
    )
    assert explanation is not None and explanation in cast(str, findings_section["body"])
    assert f"project coordination generation {generation} was superseded" in cast(
        str, findings_section["body"]
    )
    for output in ("markdown", "text"):
        rendered = await _receipt(service, recipient, rechecked, output=output)
        human_text = getattr(rendered, "human_text", None)
        assert isinstance(human_text, str)
        assert f"project coordination generation {generation} was superseded" in human_text


@pytest.mark.parametrize("change", _REPOSITORY_CHANGES)
async def test_repository_generation_change_closes_stranded_coordination_finding(
    tmp_path: Path, change: str
) -> None:
    workspace = (tmp_path / "workspace").resolve()
    workspace.mkdir()
    subprocess.run(["git", "init", "--quiet", str(workspace)], check=True, capture_output=True)

    async with multi_agent_service(tmp_path / "state") as service:
        tasks = await _start_pair(service, workspace)
        detection, obligation, stranded = await _declared_overlap(service, tasks, None)
        await _supersede(service, change, tasks, detection.project_id, workspace)
        await _assert_superseded_closure(service, tasks, detection, obligation, stranded)


@pytest.mark.parametrize("change", _GENERAL_CHANGES)
async def test_general_generation_change_closes_stranded_coordination_finding(
    tmp_path: Path, change: str
) -> None:
    workspace = (tmp_path / "workspace").resolve()
    workspace.mkdir()
    subprocess.run(["git", "init", "--quiet", str(workspace)], check=True, capture_output=True)

    async with multi_agent_service(tmp_path / "state") as service:
        tasks = await _start_pair(service, workspace)
        project = await _general_project(service, tasks)
        detection, obligation, stranded = await _declared_overlap(service, tasks, project)
        assert detection.project_id == project
        await _supersede(service, change, tasks, project, workspace)
        await _assert_superseded_closure(service, tasks, detection, obligation, stranded)


@pytest.mark.parametrize("change", ("opt_out", "consent_revoke_reconsent"))
async def test_plan_overlap_generation_change_closes_stranded_coordination_finding(
    tmp_path: Path, change: str
) -> None:
    """A plan overlap has no attributable paths, so only the closure itself can retire it."""

    workspace = (tmp_path / "workspace").resolve()
    workspace.mkdir()
    subprocess.run(["git", "init", "--quiet", str(workspace)], check=True, capture_output=True)

    async with multi_agent_service(tmp_path / "state") as service:
        tasks = await _start_pair(service, workspace)
        detection, obligation, stranded = await _declared_overlap(
            service, tasks, None, overlap="plan"
        )
        await _supersede(service, change, tasks, detection.project_id, workspace)
        await _assert_superseded_closure(service, tasks, detection, obligation, stranded)


async def test_successor_detection_is_not_hidden_or_addressed_by_the_old_generation(
    tmp_path: Path,
) -> None:
    """The closure is exact: it neither suppresses nor answers the current successor detection."""

    workspace = (tmp_path / "workspace").resolve()
    workspace.mkdir()
    subprocess.run(["git", "init", "--quiet", str(workspace)], check=True, capture_output=True)

    async with multi_agent_service(tmp_path / "state") as service:
        tasks = await _start_pair(service, workspace)
        detection, obligation, stranded = await _declared_overlap(service, tasks, None)
        project = detection.project_id
        await _supersede(service, "opt_out_opt_in", tasks, project, workspace)
        current = await service.app.start_catalog.project_state(project)
        assert current is not None and current.membership_generation == 3

        # A publication sweeps the regrouped project and delivers a successor detection.
        evidence = new_id(IdKind.EVIDENCE)
        await _publish(
            service,
            tasks[0],
            (
                _event(
                    "evidence_recorded",
                    {
                        "evidence_id": evidence,
                        "evidence_kind": "test_result",
                        "strength": "content_digest",
                        "content_digest": "sha256:" + "c" * 64,
                        "observed_at": "2026-09-25T12:00:05.000Z",
                        "description": "The shared file decision was recorded.",
                    },
                ),
            ),
        )
        coordination = _coordination(service)
        detections = {
            item.detection_id: item
            for item in await coordination.detector.store.list_detections(project)
        }
        successors = [
            item
            for item in detections.values()
            if item.membership_generation == current.membership_generation
        ]
        assert len(successors) == 1
        successor = successors[0]
        assert successor.detection_id != detection.detection_id

        closed = await _check(service, tasks[0])
        assert not any(item.kind is FindingKind.COORDINATION_OVERLAP for item in closed.findings)

        # The old-generation disposition cannot be spent on the successor ...
        refused = await _publish_refused(
            service,
            tasks[0],
            (
                _event(
                    "coordination_disposition_recorded",
                    {
                        "detection_id": detection.detection_id,
                        "project_id": project,
                        "membership_generation": str(detection.membership_generation),
                        "recipient_task_id": tasks[0].task_id,
                        "obligation_id": obligation,
                        "disposition": "sequencing",
                        "evidence_refs": (evidence,),
                    },
                    evidence_refs=(evidence,),
                ),
            ),
        )
        assert refused.safe_details["reason_code"] == _SUPERSEDED_REASON

        # ... and the old closure does not hide a current declaration on the successor.
        await _publish(
            service,
            tasks[0],
            (
                _event(
                    "coordination_obligation_declared",
                    {
                        "detection_id": successor.detection_id,
                        "project_id": project,
                        "membership_generation": str(successor.membership_generation),
                        "recipient_task_id": tasks[0].task_id,
                        "obligation_id": obligation,
                    },
                ),
            ),
        )
        current_check = await _check(service, tasks[0])
        overlaps = [
            item for item in current_check.findings if item.kind is FindingKind.COORDINATION_OVERLAP
        ]
        assert len(overlaps) == 1
        assert overlaps[0].finding_id != stranded.finding_id
        assert overlaps[0].subject_refs != stranded.subject_refs

        # The current successor is addressed through the ordinary typed disposition.
        await _publish(
            service,
            tasks[0],
            (
                _event(
                    "coordination_disposition_recorded",
                    {
                        "detection_id": successor.detection_id,
                        "project_id": project,
                        "membership_generation": str(successor.membership_generation),
                        "recipient_task_id": tasks[0].task_id,
                        "obligation_id": obligation,
                        "disposition": "shared_work",
                        "evidence_refs": (evidence,),
                    },
                    evidence_refs=(evidence,),
                ),
            ),
        )
        resolved = await _check(service, tasks[0])
        assert not any(item.kind is FindingKind.COORDINATION_OVERLAP for item in resolved.findings)
        findings_view = await _status(service, tasks[0], view="findings", limit="50")
        assert isinstance(findings_view.page, StatusFindingsPageModel)
        rows = {item.finding_id: item for item in findings_view.page.items}
        assert rows[stranded.finding_id].resolved is True
        assert rows[overlaps[0].finding_id].resolved is True
        successor_detail = rows[overlaps[0].finding_id].detail
        assert isinstance(successor_detail, str)
        # The successor was addressed, not superseded, and its explanation says so.
        assert "was superseded" not in successor_detail


async def test_closure_is_derived_from_durable_state_across_service_restarts(
    tmp_path: Path,
) -> None:
    """A supersession recorded before a restart still closes once, and only once, afterwards."""

    workspace = (tmp_path / "workspace").resolve()
    workspace.mkdir()
    subprocess.run(["git", "init", "--quiet", str(workspace)], check=True, capture_output=True)

    async with multi_agent_service(tmp_path / "state") as service:
        tasks = await _start_pair(service, workspace)
        detection, obligation, stranded = await _declared_overlap(service, tasks, None)
        await _supersede(service, "opt_out", tasks, detection.project_id, workspace)

        # The generation advance is durable catalog state; nothing in memory carries it over.
        await relock_and_reopen_multi_agent_service(service)
        await _assert_superseded_closure(service, tasks, detection, obligation, stranded)

        await relock_and_reopen_multi_agent_service(service)
        rechecked = await _check(service, tasks[0])
        assert not any(item.kind is FindingKind.COORDINATION_OVERLAP for item in rechecked.findings)
        closures = [
            payload
            for _, payload in await _ledger_contexts(service, tasks[0])
            if CoordinationGapCode.REVOKED in payload.gap_codes
        ]
        assert len(closures) == 1
        findings_view = await _status(service, tasks[0], view="findings", limit="50")
        assert isinstance(findings_view.page, StatusFindingsPageModel)
        rows = {item.finding_id: item for item in findings_view.page.items}
        assert rows[stranded.finding_id].resolved is True


async def test_direct_reconciliation_is_idempotent_and_leaves_current_generations_alone(
    tmp_path: Path,
) -> None:
    """The reconciler also runs outside a check; it closes once and never closes current work."""

    workspace = (tmp_path / "workspace").resolve()
    workspace.mkdir()
    subprocess.run(["git", "init", "--quiet", str(workspace)], check=True, capture_output=True)

    async with multi_agent_service(tmp_path / "state") as service:
        tasks = await _start_pair(service, workspace)
        detection, _obligation, stranded = await _declared_overlap(service, tasks, None)
        coordination = _coordination(service)

        # A current generation is never closed.
        assert await coordination.retire_superseded_contexts(tasks[0].task_id) == ()
        assert await coordination.retire_superseded_contexts(tasks[1].task_id) == ()

        await _supersede(service, "opt_out", tasks, detection.project_id, workspace)
        closed = await coordination.retire_superseded_contexts(tasks[0].task_id)
        assert len(closed) == 1
        assert await coordination.retire_superseded_contexts(tasks[0].task_id) == ()
        # The counterpart declared nothing, so it has nothing to close.
        assert await coordination.retire_superseded_contexts(tasks[1].task_id) == ()

        checked = await _check(service, tasks[0])
        assert not any(item.kind is FindingKind.COORDINATION_OVERLAP for item in checked.findings)
        closures = [
            event_id
            for event_id, payload in await _ledger_contexts(service, tasks[0])
            if CoordinationGapCode.REVOKED in payload.gap_codes
        ]
        assert closures == list(closed)
        findings_view = await _status(service, tasks[0], view="findings", limit="50")
        assert isinstance(findings_view.page, StatusFindingsPageModel)
        rows = {item.finding_id: item for item in findings_view.page.items}
        assert rows[stranded.finding_id].resolved is True


@pytest.mark.parametrize("failure_stage", ("get_detection", "replace_detection"))
async def test_committed_closure_retries_detector_invalidation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure_stage: str
) -> None:
    """A committed recipient marker is not proof the detector update also committed."""

    workspace = (tmp_path / "workspace").resolve()
    workspace.mkdir()
    subprocess.run(["git", "init", "--quiet", str(workspace)], check=True, capture_output=True)
    async with multi_agent_service(tmp_path / "state") as service:
        tasks = await _start_pair(service, workspace)
        detection, _obligation, _finding = await _declared_overlap(service, tasks, None)
        coordination = _coordination(service)
        store = coordination.detector.store
        await _supersede(service, "opt_out", tasks, detection.project_id, workspace)
        original = getattr(store, failure_stage)

        async def fail_after_marker(*_args: object, **_kwargs: object) -> object:
            raise OSError("synthetic detector persistence failure")

        monkeypatch.setattr(store, failure_stage, fail_after_marker)
        with pytest.raises(OSError, match="synthetic detector persistence failure"):
            await coordination.retire_superseded_contexts(tasks[0].task_id)
        monkeypatch.setattr(store, failure_stage, original)
        closures = [
            event_id
            for event_id, payload in await _ledger_contexts(service, tasks[0])
            if CoordinationGapCode.REVOKED in payload.gap_codes
        ]
        assert len(closures) == 1
        stored = await store.get_detection(detection.detection_id)
        assert stored is not None and stored.generation_valid

        # Retry the missing store transition without appending another closure.
        assert await coordination.retire_superseded_contexts(tasks[0].task_id) == ()
        stored = await store.get_detection(detection.detection_id)
        assert stored is not None and not stored.generation_valid
        assert [
            event_id
            for event_id, payload in await _ledger_contexts(service, tasks[0])
            if CoordinationGapCode.REVOKED in payload.gap_codes
        ] == closures
