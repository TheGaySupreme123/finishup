"""Integration coverage for ``status view=operation`` recovery (run-4 residual plan 06 / #61).

The five cases the recovery surface must be total over: completed publish_work, completed check
(the run-4 failure), unknown request_id, a prior writer on the same task, and a pending in-flight
operation. Plus compact-projection lag and cursor rejection so no path raises unbounded.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest

from builders.ledger_adapters import (
    FixedClock,
    MemoryObjects,
    append_command,
    memory_adapter,
    ownership_fence,
)
from builders.start_application import (
    MemoryStartRuntime,
    protocol_id,
    start_composition,
    start_request,
)
from yoetz.adapters.memory.ledger import MemoryLedgerAdapter
from yoetz.application.egress import PrivacyCoordinator
from yoetz.application.publish_work import Application as PublishApplication
from yoetz.application.publish_work import execute_publish_work
from yoetz.application.service import Application, ControlProjectionBinding, VerificationPolicy
from yoetz.application.status import Application as StatusApplication
from yoetz.application.status import execute_status
from yoetz.domain.events import RuntimeProfile
from yoetz.domain.privacy import (
    AuthorizationScope,
    AuthorizationScopeKind,
    CandidateContext,
    ConsentSource,
    LocalDisclosureApproved,
    LocalDisclosureReceipt,
    PrivacyOutcome,
    ReceiptCounts,
    ReceiptPolicyBinding,
    ReceiptSecretScan,
    ReceiptTransformations,
)
from yoetz.domain.receipts import PolicyVersionEntry, ReceiptVersionSlice, SchemaVersionEntry
from yoetz.domain.values import Frontier, session_id
from yoetz.ports.diagnostics import RuntimeCapability
from yoetz.ports.importer import ImporterPort, ImportStatusSnapshot
from yoetz.ports.ledger import (
    AppendCommand,
    CheckPhase,
    CheckSuspensionKind,
    OperationKind,
    OperationRecord,
    OperationState,
    SemanticDisclosureWait,
)
from yoetz.ports.objects import ObjectKind, ObjectMetadata, ObjectRef, ObjectStorePort
from yoetz.ports.publish_response_catalog import PublishResponseCatalogPort
from yoetz.ports.runtime import BundleRuntimePort, RouteCommand, TaskRuntime
from yoetz.protocol.canonical import JsonValue, canonical_encode
from yoetz.protocol.errors import PublicErrorCode, PublicOperationError
from yoetz.protocol.models import (
    CheckRequest,
    FrontierModel,
    PublishWorkRequest,
    PublishWorkRequestModel,
    StatusOperationPageModel,
    StatusRequest,
)

pytestmark = pytest.mark.anyio

_DIGEST = "sha256:" + "7" * 64
_WORKSPACE = "hmac-sha256:" + "8" * 64


class _IdleImporter:
    async def status(self, session: str) -> ImportStatusSnapshot:
        return ImportStatusSnapshot(session_id(session), 0, 0, (), ())


class _PublishRuntime:
    def __init__(self, task: TaskRuntime) -> None:
        self.task = task

    async def route(self, command: RouteCommand) -> TaskRuntime:
        del command
        return self.task

    async def release(self, runtime: TaskRuntime) -> None:
        assert runtime is self.task


class _PublishApp:
    def __init__(self, runtime: _PublishRuntime) -> None:
        self.runtime = runtime
        self.clock = FixedClock()
        self.status_cursor_key = b"status-operation-view-cursor-key!!!"

    def authorizes_import_publication(self, request: PublishWorkRequestModel) -> bool:
        del request
        return False


class _WorkflowRuntime(MemoryStartRuntime):
    async def route(self, command: RouteCommand) -> TaskRuntime:
        assert command.writer_id is not None
        task_id, resources = next(iter(self.resources.items()))
        ledger, objects = resources
        assert (command.session_id, command.writer_id) in self.owners
        return TaskRuntime(
            task_id,
            command.session_id,
            command.writer_id,
            frozenset(
                {
                    RuntimeCapability.WRITE,
                    RuntimeCapability.STRUCTURAL_READ,
                    RuntimeCapability.PAYLOAD_READ,
                }
            ),
            ledger,
            objects,
            cast(ImporterPort, _IdleImporter()),
            "0.1.0",
            "0.1.0",
            "0.1",
            "1.0.0",
            ownership_fence(),
        )


class _ProjectionSpy:
    async def prepare_local_disclosure(
        self, candidate: CandidateContext
    ) -> LocalDisclosureApproved:
        sink = candidate.local_sink
        assert sink is not None
        proposal_id = protocol_id("ppr_", 801)
        policy = ReceiptPolicyBinding(protocol_id("pvy_", 802), 1, _DIGEST, _DIGEST)
        receipt = LocalDisclosureReceipt(
            "1.0.0",
            protocol_id("egr_", 803),
            candidate.request_id,
            proposal_id,
            sink,
            PrivacyOutcome.COMPLETED,
            datetime(2026, 7, 19, 12, 0, tzinfo=UTC),
            candidate.scope,
            candidate.purpose,
            policy,
            ConsentSource.BASELINE_POLICY,
            (),
            (),
            ReceiptCounts(0, 0, 0, 0, 0, 0, 0),
            ReceiptTransformations(0, 0, 0),
            ReceiptSecretScan("1.0.0", _DIGEST, 0, True),
            None,
            1,
        )
        return LocalDisclosureApproved(
            proposal_id,
            candidate.request_id,
            sink,
            candidate.purpose,
            candidate.scope,
            _DIGEST,
            _WORKSPACE,
            (),
            (),
            receipt,
        )

    async def close(self) -> None:
        return None


def _versions() -> ReceiptVersionSlice:
    return ReceiptVersionSlice(
        package_name="yoetz",
        package_version="0.1.0",
        protocol_version="0.1",
        engine_version="0.1.0",
        projection_version="0.1.0",
        object_format_version="yoetz-object/1",
        catalog_schema_version="1",
        bundle_schema_version="1",
        policy_versions=(
            PolicyVersionEntry("research-evidence", "0.1.0"),
            PolicyVersionEntry("work-integrity", "0.1.0"),
        ),
        schema_versions=(SchemaVersionEntry("receipts/receipt-document", "1.0.0"),),
        resource_manifest_digest=_DIGEST,
    )


def _scope(_: ControlProjectionBinding, source: Mapping[str, JsonValue]) -> AuthorizationScope:
    return AuthorizationScope(
        AuthorizationScopeKind.TASK,
        protocol_id("ins_", 804),
        _WORKSPACE,
        cast(str, source["task_id"]),
    )


async def _semantic_disabled(
    frozen: object,
    findings: object,
    runtime: object | None = None,
    lineage_evaluation: object | None = None,
    require_complete_specification: bool = False,
) -> object:
    del frozen, findings, runtime, lineage_evaluation
    raise AssertionError("semantic_evaluator_called_in_deterministic_mode")


def _request_base(request_id: str) -> dict[str, object]:
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": request_id,
        "actor": {"actor_id": "harness:test", "actor_type": "harness"},
        "client": {"kind": "test_client", "version": "0.1.0", "integration": "local_cli"},
    }


def _frontier(value: Frontier | FrontierModel) -> dict[str, object]:
    if isinstance(value, Frontier):
        return dict(value.as_wire().items())
    return cast(dict[str, object], value.model_dump(mode="json"))


def _publish_composition() -> tuple[_PublishApp, MemoryObjects, AppendCommand, MemoryLedgerAdapter]:
    seed = append_command()
    ledger = memory_adapter(seed)
    objects = cast(MemoryObjects, ledger._objects)  # pyright: ignore[reportPrivateUsage]
    task = TaskRuntime(
        seed.task_id,
        seed.session_id,
        seed.writer_id,
        frozenset(
            {
                RuntimeCapability.WRITE,
                RuntimeCapability.STRUCTURAL_READ,
                RuntimeCapability.PAYLOAD_READ,
            }
        ),
        ledger,
        cast(ObjectStorePort, objects),
        cast(ImporterPort, _IdleImporter()),
        "0.1.0",
        "0.1.0",
        "0.1",
        "1.0.0",
        ownership_fence(),
    )
    return _PublishApp(_PublishRuntime(task)), objects, seed, ledger


def _status_operation_request(
    *,
    session_id: str,
    writer_id: str,
    operation_request_id: str,
    request_tail: int,
    cursor: str | None = None,
) -> StatusRequest:
    body: dict[str, object] = {
        **_request_base(f"req_00000000-0000-4000-8000-{request_tail:012d}"),
        "session_id": session_id,
        "writer_id": writer_id,
        "view": "operation",
        "limit": "1",
        "filter": {"operation_request_id": operation_request_id},
    }
    if cursor is not None:
        body["cursor"] = cursor
    return StatusRequest.model_validate(body)


async def _workflow_app() -> tuple[Application, _WorkflowRuntime, object]:
    start_app, start_runtime, clock, catalog = start_composition()
    ids = start_runtime.ids
    runtime = _WorkflowRuntime(clock, ids)
    app = Application(
        start_catalog=catalog.delegate,
        publish_responses=cast(PublishResponseCatalogPort, catalog.delegate),
        runtime=cast(BundleRuntimePort, runtime),
        clock=clock,
        ids=ids,
        verification_policy=VerificationPolicy(semantic="disabled", max_findings=3),
        privacy=cast(PrivacyCoordinator, _ProjectionSpy()),
        status_cursor_key=b"status-operation-view-workflow-key!",
        waiver_policy_digest=_DIGEST,
        semantic_evaluator=_semantic_disabled,
        disclosure_scope_for=_scope,
        receipt_version_resolver=lambda _: _versions(),
        waiver_authorizer=lambda _: False,
        import_publication_authorizer=lambda _: False,
        profile=RuntimeProfile.TEST_FAKE,
        policy_packs=("research-evidence/0.2.0", "work-integrity/0.3.0"),
        version_manifest=start_app.version_manifest,
        enforce_repository_identity=False,
    )
    return app, runtime, catalog


async def test_status_view_operation_returns_completed_check_page() -> None:
    """Run-4 sequence: a completed check looked up by request_id returns a bounded page."""

    app, runtime, _catalog = await _workflow_app()
    started = await app.start(start_request(810, title="Operation view check recovery"))
    obligation_id = protocol_id("obl_", 811)
    published = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 812)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(started.frontier),
                "event_drafts": (
                    {
                        "event_id": protocol_id("evt_", 813),
                        "schema": {"name": "obligation_published", "version": "1.0.0"},
                        "occurred_at": "2026-07-19T12:00:00.000Z",
                        "causal_parents": (),
                        "payload": {
                            "obligation_id": obligation_id,
                            "description": "Publish a result for the operation-view check.",
                            "acceptance_criteria": "A result is recorded in the task ledger.",
                            "evidence_expectation": "A linked immutable result record.",
                            "requested_items": (
                                {"item_kind": "change", "value": "operation-view-result"},
                            ),
                            "status": "open",
                        },
                        "artifact_refs": (),
                        "evidence_refs": (),
                    },
                ),
            }
        )
    )
    check_req_id = protocol_id("req_", 814)
    await app.check(
        CheckRequest.model_validate(
            {
                **_request_base(check_req_id),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(published.result_frontier),
                "mode": "deterministic_only",
                "max_findings": "3",
            }
        )
    )
    ledger, _objects = runtime.resources[started.task_id]
    durable = await ledger.lookup_operation(started.writer_id, check_req_id)
    assert durable is not None
    assert durable.operation_kind is OperationKind.CHECK
    assert durable.state is OperationState.COMPLETE

    status = await app.status(
        _status_operation_request(
            session_id=started.session_id,
            writer_id=started.writer_id,
            operation_request_id=check_req_id,
            request_tail=901,
        )
    )
    page = status.page
    assert type(page) is StatusOperationPageModel
    assert page.found is True
    assert page.state == "complete"
    assert page.operation_kind == "check"
    assert page.outcome is None
    assert page.accepted_events == ()
    assert page.subject_frontier is None
    assert page.result_frontier is None


async def test_status_view_operation_returns_stored_publish_work_detail() -> None:
    app, _objects, seed, _ledger = _publish_composition()
    request = PublishWorkRequestModel.model_validate(
        {
            "protocol_version": "0.1",
            "schema_version": "1.0.0",
            "request_id": "req_00000000-0000-4000-8000-000000000501",
            "session_id": seed.session_id,
            "writer_id": seed.writer_id,
            "expected_frontier": None,
            "event_drafts": (
                {
                    "event_id": "evt_00000000-0000-4000-8000-000000000502",
                    "schema": {"name": "action_recorded", "version": "1.0.0"},
                    "occurred_at": "2026-07-19T12:00:00.000Z",
                    "causal_parents": (),
                    "payload": {
                        "action_id": "act_00000000-0000-4000-8000-000000000503",
                        "action_kind": "other",
                        "description": "Materialized one coherent slice",
                    },
                    "artifact_refs": (),
                    "evidence_refs": (),
                },
            ),
            "actor": {"actor_id": "harness:test", "actor_type": "harness"},
            "client": {
                "kind": "test_client",
                "version": "0.1.0",
                "integration": "local_cli",
            },
        }
    )
    first = await execute_publish_work(cast(PublishApplication, app), request)

    status = await execute_status(
        cast(StatusApplication, app),
        _status_operation_request(
            session_id=seed.session_id,
            writer_id=seed.writer_id,
            operation_request_id=request.request_id,
            request_tail=510,
        ),
    )
    page = status.page
    assert type(page) is StatusOperationPageModel
    assert page.found is True
    assert page.state == "complete"
    assert page.operation_kind == "publish_work"
    assert page.outcome == "accepted"
    assert page.result_frontier is not None
    assert page.result_frontier.sequence == str(first.result_frontier.sequence)
    assert tuple(item.event_id for item in page.accepted_events) == tuple(
        item.event_id for item in first.accepted_events
    )


async def test_status_view_operation_absent_for_unknown_request_id() -> None:
    app, _objects, seed, _ledger = _publish_composition()
    status = await execute_status(
        cast(StatusApplication, app),
        _status_operation_request(
            session_id=seed.session_id,
            writer_id=seed.writer_id,
            operation_request_id="req_00000000-0000-4000-8000-000000000599",
            request_tail=522,
        ),
    )
    page = cast(StatusOperationPageModel, status.page)
    assert page.found is False
    assert page.state == "absent"
    assert page.operation_kind is None
    assert page.accepted_events == ()


async def test_status_view_operation_finds_prior_writer_request_id_on_same_task() -> None:
    """Writer-scoped lookup stays private; task-scoped recovery finds the same-task request (#438)."""

    app, _objects, seed, ledger = _publish_composition()
    request = PublishWorkRequestModel.model_validate(
        {
            "protocol_version": "0.1",
            "schema_version": "1.0.0",
            "request_id": "req_00000000-0000-4000-8000-000000000521",
            "session_id": seed.session_id,
            "writer_id": seed.writer_id,
            "expected_frontier": None,
            "event_drafts": (
                {
                    "event_id": "evt_00000000-0000-4000-8000-000000000522",
                    "schema": {"name": "action_recorded", "version": "1.0.0"},
                    "occurred_at": "2026-07-19T12:00:00.000Z",
                    "causal_parents": (),
                    "payload": {
                        "action_id": "act_00000000-0000-4000-8000-000000000523",
                        "action_kind": "other",
                        "description": "Owned by the original writer only.",
                    },
                    "artifact_refs": (),
                    "evidence_refs": (),
                },
            ),
            "actor": {"actor_id": "harness:test", "actor_type": "harness"},
            "client": {
                "kind": "test_client",
                "version": "0.1.0",
                "integration": "local_cli",
            },
        }
    )
    await execute_publish_work(cast(PublishApplication, app), request)
    foreign_writer = "wri_00000000-0000-4000-8000-000000000599"
    assert foreign_writer != seed.writer_id
    assert (await ledger.lookup_operation(foreign_writer, request.request_id)) is None
    assert (await ledger.lookup_operation(seed.writer_id, request.request_id)) is not None
    found = await ledger.lookup_task_operation(foreign_writer, request.request_id)
    assert found is not None
    assert found.writer_id == seed.writer_id

    # Route with the successor writer_id on the same ledger, matching attach-after-start.
    base = app.runtime.task

    class _ForeignRuntime:
        async def route(self, command: RouteCommand) -> TaskRuntime:
            assert command.writer_id == foreign_writer
            return TaskRuntime(
                base.task_id,
                command.session_id,
                command.writer_id,
                base.capabilities,
                base.ledger,
                base.objects,
                base.importer,
                base.projection_version,
                base.engine_version,
                base.protocol_version,
                base.bundle_schema_version,
                base.fence,
            )

        async def release(self, runtime: TaskRuntime) -> None:
            del runtime

    foreign_app = _PublishApp(cast(_PublishRuntime, _ForeignRuntime()))
    status = await execute_status(
        cast(StatusApplication, foreign_app),
        _status_operation_request(
            session_id=seed.session_id,
            writer_id=foreign_writer,
            operation_request_id=request.request_id,
            request_tail=524,
        ),
    )
    page = cast(StatusOperationPageModel, status.page)
    assert page.found is True
    assert page.state == "complete"
    assert page.operation_kind == "publish_work"

    original = await ledger.lookup_operation(seed.writer_id, request.request_id)
    assert original is not None
    ledger._state.operations[(foreign_writer, request.request_id)] = (  # pyright: ignore[reportPrivateUsage]
        replace(original, writer_id=foreign_writer),
        None,
    )
    preferred = await ledger.lookup_task_operation(foreign_writer, request.request_id)
    assert preferred is not None
    assert preferred.writer_id == foreign_writer
    assert (
        await ledger.lookup_task_operation(
            "wri_00000000-0000-4000-8000-000000000598", request.request_id
        )
        is None
    )


async def test_status_view_operation_reports_pending_for_in_flight_check() -> None:
    app, _objects, seed, ledger = _publish_composition()
    op_id = "req_00000000-0000-4000-8000-000000000701"
    resume = ObjectRef(
        "obj_00000000-0000-4000-8000-00000000aaaa",
        1,
        "hmac-sha256:" + "a" * 64,
        "sha256:" + "b" * 64,
        "yoetz-object/1",
        "bmk-1",
        ObjectMetadata(
            ObjectKind.CHECK_RESUME,
            "application/vnd.yoetz.check-resume+json",
            seed.task_id,
            datetime(2026, 1, 1, tzinfo=UTC),
        ),
    )
    pending = OperationRecord(
        seed.writer_id,
        op_id,
        OperationKind.CHECK,
        "sha256:" + "c" * 64,
        OperationState.PENDING,
        CheckPhase.RESERVED,
        "owner-generation-1",
        "lease-owner-1",
        1,
        datetime(2030, 1, 1, tzinfo=UTC),
        resume,
        None,
        None,
        None,
        None,
        None,
    )
    ledger._state.operations[(seed.writer_id, op_id)] = (  # pyright: ignore[reportPrivateUsage]
        pending,
        None,
    )
    status = await execute_status(
        cast(StatusApplication, app),
        _status_operation_request(
            session_id=seed.session_id,
            writer_id=seed.writer_id,
            operation_request_id=op_id,
            request_tail=702,
        ),
    )
    page = cast(StatusOperationPageModel, status.page)
    assert page.found is True
    assert page.state == "pending"
    assert page.operation_kind == "check"
    assert page.accepted_events == ()


async def test_status_view_operation_recovers_missing_repository_grant_for_same_request() -> None:
    base, _objects, seed, ledger = _publish_composition()
    app = _PublishApp(base.runtime)
    op_id = "req_00000000-0000-4000-8000-000000000703"
    resume = ObjectRef(
        "obj_00000000-0000-4000-8000-00000000aaac",
        1,
        "hmac-sha256:" + "a" * 64,
        "sha256:" + "b" * 64,
        "yoetz-object/1",
        "bmk-1",
        ObjectMetadata(
            ObjectKind.DETERMINISTIC_RESULT,
            "application/vnd.yoetz.deterministic-result+json",
            seed.task_id,
            datetime(2026, 1, 1, tzinfo=UTC),
        ),
    )
    pending = OperationRecord(
        seed.writer_id,
        op_id,
        OperationKind.CHECK,
        "sha256:" + "c" * 64,
        OperationState.PENDING,
        CheckPhase.SEMANTIC_WAIT,
        "owner-generation-1",
        "lease-owner-1",
        1,
        datetime(2030, 1, 1, tzinfo=UTC),
        resume,
        None,
        None,
        None,
        None,
        None,
        CheckSuspensionKind.REPOSITORY_GRANT,
    )
    ledger._state.operations[(seed.writer_id, op_id)] = (  # pyright: ignore[reportPrivateUsage]
        pending,
        None,
    )
    stale_job_id = protocol_id("job_", 705)
    ledger._state.disclosure_waits[stale_job_id] = (  # pyright: ignore[reportPrivateUsage]
        SemanticDisclosureWait(
            stale_job_id,
            protocol_id("att_", 706),
            seed.writer_id,
            op_id,
            protocol_id("ppr_", 707),
            datetime(2030, 1, 1, tzinfo=UTC),
            "awaiting",
            None,
        )
    )

    status = await execute_status(
        cast(StatusApplication, app),
        _status_operation_request(
            session_id=seed.session_id,
            writer_id=seed.writer_id,
            operation_request_id=op_id,
            request_tail=704,
        ),
    )

    page = cast(StatusOperationPageModel, status.page)
    assert page.continuation is not None
    assert page.continuation.kind == "repository_privacy_setup"
    assert page.continuation.command == ("yoetz", "--privacy")
    assert page.continuation.replay_request_id == op_id
    continuation_wire = page.continuation.model_dump(mode="json", exclude_none=True)
    assert "pending_id" not in continuation_wire
    assert "expires_at" not in continuation_wire


async def test_status_view_operation_recovers_disclosure_wait_after_writer_rotation() -> None:
    """The successor session recovers the old writer's one-use continuation (#438)."""

    base, _objects, seed, ledger = _publish_composition()
    operation_id = "req_00000000-0000-4000-8000-000000000708"
    resume = ObjectRef(
        "obj_00000000-0000-4000-8000-00000000aaad",
        1,
        "hmac-sha256:" + "a" * 64,
        "sha256:" + "b" * 64,
        "yoetz-object/1",
        "bmk-1",
        ObjectMetadata(
            ObjectKind.DETERMINISTIC_RESULT,
            "application/vnd.yoetz.deterministic-result+json",
            seed.task_id,
            datetime(2026, 1, 1, tzinfo=UTC),
        ),
    )
    pending = OperationRecord(
        seed.writer_id,
        operation_id,
        OperationKind.CHECK,
        "sha256:" + "c" * 64,
        OperationState.PENDING,
        CheckPhase.SEMANTIC_WAIT,
        "owner-generation-1",
        "lease-owner-1",
        1,
        datetime(2030, 1, 1, tzinfo=UTC),
        resume,
        None,
        None,
        None,
        None,
        None,
    )
    ledger._state.operations[(seed.writer_id, operation_id)] = (  # pyright: ignore[reportPrivateUsage]
        pending,
        None,
    )
    pending_id = protocol_id("ppr_", 711)
    wait = SemanticDisclosureWait(
        protocol_id("job_", 709),
        protocol_id("att_", 710),
        seed.writer_id,
        operation_id,
        pending_id,
        datetime(2030, 1, 1, tzinfo=UTC),
        "awaiting",
        None,
    )
    ledger._state.disclosure_waits[wait.job_id] = wait  # pyright: ignore[reportPrivateUsage]

    successor_writer = "wri_00000000-0000-4000-8000-000000000712"
    successor_session = "ses_00000000-0000-4000-8000-000000000713"
    successor = replace(
        base.runtime.task,
        session_id=successor_session,
        writer_id=successor_writer,
    )
    app = _PublishApp(_PublishRuntime(successor))
    assert await ledger.load_disclosure_wait(successor_writer, operation_id) is None
    assert await ledger.load_disclosure_wait(seed.writer_id, operation_id) == wait

    status = await execute_status(
        cast(StatusApplication, app),
        _status_operation_request(
            session_id=successor_session,
            writer_id=successor_writer,
            operation_request_id=operation_id,
            request_tail=714,
        ),
    )

    page = cast(StatusOperationPageModel, status.page)
    assert page.found is True
    assert page.state == "pending"
    assert page.continuation is not None
    assert page.continuation.kind == "privacy_disclosure_decision"
    assert page.continuation.pending_id == pending_id
    assert page.continuation.command == (
        "yoetz",
        "privacy",
        "decide-disclosure",
        pending_id,
    )
    assert page.continuation.replay_request_id == operation_id


def _complete_check_record(writer_id: str, operation_id: str) -> OperationRecord:
    """A terminal, non-publish operation seeded directly, without paying for a real check."""

    canonical = canonical_encode(
        {
            "finding_ids": (),
            "request_id": operation_id,
            "result_frontier": Frontier.genesis().as_wire(),
            "subject_frontier": Frontier.genesis().as_wire(),
            "verdict": "clean",
        }
    )
    return OperationRecord(
        writer_id,
        operation_id,
        OperationKind.CHECK,
        "sha256:" + "d" * 64,
        OperationState.COMPLETE,
        CheckPhase.TERMINAL,
        None,
        None,
        None,
        None,
        None,
        canonical,
        f"sha256:{hashlib.sha256(canonical).hexdigest()}",
        None,
        None,
        datetime(2026, 1, 1, tzinfo=UTC),
    )


async def test_status_view_operation_survives_compact_projection_lag() -> None:
    """Compact enrichment must not fail recovery when the projection is temporarily unreadable."""

    app, runtime, _catalog = await _workflow_app()
    started = await app.start(start_request(830, title="Compact lag recovery"))
    check_req_id = protocol_id("req_", 831)
    # Seed a complete non-publish operation without going through check (ledger inject).
    ledger, _objects = runtime.resources[started.task_id]
    ledger._state.operations[(started.writer_id, check_req_id)] = (  # pyright: ignore[reportPrivateUsage]
        _complete_check_record(started.writer_id, check_req_id),
        None,
    )

    async def boom(*_args: object, **_kwargs: object) -> object:
        raise PublicOperationError(PublicErrorCode.SERVICE_UNAVAILABLE, "projection lagging", True)

    ledger.query_projection = boom  # type: ignore[method-assign]

    status = await app.status(
        _status_operation_request(
            session_id=started.session_id,
            writer_id=started.writer_id,
            operation_request_id=check_req_id,
            request_tail=832,
        )
    )
    page = cast(StatusOperationPageModel, status.page)
    assert page.found is True
    assert page.state == "complete"
    assert page.operation_kind == "check"
    assert status.rebuild_state == "rebuild_required"


async def test_status_view_operation_records_invalid_compact_enrichment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A compact page of the wrong shape degrades recovery, but never silently.

    Enrichment is secondary, so the operation page still resolves on structural defaults. The
    discarded ``AttributeError`` is the only evidence that the projection returned something it
    should not, so it must leave a bounded, resolvable record rather than vanish.
    """

    import yoetz.observability.diagnostics as diagnostics

    monkeypatch.setattr(diagnostics, "log_dir", lambda: tmp_path)
    app, runtime, _catalog = await _workflow_app()
    started = await app.start(start_request(870, title="Compact enrichment invalid"))
    check_req_id = protocol_id("req_", 871)
    ledger, _objects = runtime.resources[started.task_id]
    ledger._state.operations[(started.writer_id, check_req_id)] = (  # pyright: ignore[reportPrivateUsage]
        _complete_check_record(started.writer_id, check_req_id),
        None,
    )

    class _ShapelessPage:
        """A page missing every enrichment attribute the branch reads."""

    async def shapeless(*_args: object, **_kwargs: object) -> object:
        return _ShapelessPage()

    ledger.query_projection = shapeless  # type: ignore[method-assign]

    status = await app.status(
        _status_operation_request(
            session_id=started.session_id,
            writer_id=started.writer_id,
            operation_request_id=check_req_id,
            request_tail=872,
        )
    )

    page = cast(StatusOperationPageModel, status.page)
    assert page.found is True
    assert page.state == "complete"
    assert page.operation_kind == "check"
    assert status.rebuild_state == "rebuild_required"

    raw = diagnostics.diagnostic_log_path(root=tmp_path).read_text(encoding="ascii")
    records = tuple(
        cast(Mapping[str, object], json.loads(line)) for line in raw.splitlines() if line
    )
    # Both enrichments read the same bad page: the operation branch's own coverage/frontier
    # reads, and closure readiness, which runs on every view. Each degrades and each records.
    assert [item["operation"] for item in records] == [
        "status_operation_compact_enrichment_invalid",
        "status_closure_readiness_page_invalid",
    ]
    for item in records:
        assert item == {
            "timestamp": item["timestamp"],
            "correlation_id": item["correlation_id"],
            "component": "application.status",
            "operation": item["operation"],
            "reason": "exception_attribute_error",
            # Bounded source location: the exception class alone cannot distinguish which guarded
            # site degraded, which is what made the production AttributeError undiagnosable.
            "origin": item["origin"],
            "request_id": "req_00000000-0000-4000-8000-000000000872",
        }
        origin = item["origin"]
        assert type(origin) is str
        assert origin.startswith("yoetz.application.status:")
    assert "traceback" not in raw
    assert "_ShapelessPage" not in raw
    assert str(tmp_path) not in raw


async def test_status_view_operation_rejects_cursor_with_bounded_error() -> None:
    """Cursor-bearing operation views are invalid input, never an unbounded exception."""

    app, _objects, seed, _ledger = _publish_composition()
    with pytest.raises(PublicOperationError) as caught:
        await execute_status(
            cast(StatusApplication, app),
            _status_operation_request(
                session_id=seed.session_id,
                writer_id=seed.writer_id,
                operation_request_id="req_00000000-0000-4000-8000-000000000599",
                request_tail=840,
                # Shape is irrelevant: the operation branch rejects any cursor before decode use.
                cursor="not-a-valid-cursor-but-present",
            ),
        )
    assert caught.value.code is PublicErrorCode.INVALID_REQUEST
    assert caught.value.retryable is False


async def test_status_view_operation_page_from_corrupt_record_is_storage_corrupt() -> None:
    """A complete record whose stored bytes are not the expected shape stays bounded."""

    app, _objects, seed, ledger = _publish_composition()
    op_id = "req_00000000-0000-4000-8000-000000000850"
    corrupt_bytes = b'{"not":"append-result"}'
    corrupt = OperationRecord(
        seed.writer_id,
        op_id,
        OperationKind.PUBLISH_WORK,
        "sha256:" + "e" * 64,
        OperationState.COMPLETE,
        CheckPhase.TERMINAL,
        None,
        None,
        None,
        None,
        None,
        corrupt_bytes,
        f"sha256:{hashlib.sha256(corrupt_bytes).hexdigest()}",
        None,
        None,
        datetime(2026, 1, 1, tzinfo=UTC),
    )
    ledger._state.operations[(seed.writer_id, op_id)] = (  # pyright: ignore[reportPrivateUsage]
        corrupt,
        None,
    )
    with pytest.raises(PublicOperationError) as caught:
        await execute_status(
            cast(StatusApplication, app),
            _status_operation_request(
                session_id=seed.session_id,
                writer_id=seed.writer_id,
                operation_request_id=op_id,
                request_tail=851,
            ),
        )
    assert caught.value.code is PublicErrorCode.STORAGE_CORRUPT


async def test_status_view_operation_survives_a_stranded_semantic_wait_check() -> None:
    """Recovery must work for the shape that actually failed in production.

    The 2026-07-30 dogfood run left a check pending in ``SEMANTIC_WAIT`` with a leased AI-powered review
    job and an attempt still ``started``, and every ``status(view=operation)`` against it failed
    with an AttributeError recorded as ``read_projection_failed``. The existing pending-operation
    test seeds ``CheckPhase.RESERVED`` with no AI-powered review job at all, which is why it never caught
    this: the failing state is specifically a check parked mid-dispatch.
    """

    app, _objects, seed, ledger = _publish_composition()
    op_id = "req_00000000-0000-4000-8000-000000000801"
    resume = ObjectRef(
        "obj_00000000-0000-4000-8000-00000000bbbb",
        1,
        "hmac-sha256:" + "a" * 64,
        "sha256:" + "b" * 64,
        "yoetz-object/1",
        "bmk-1",
        ObjectMetadata(
            # A check parked in SEMANTIC_WAIT has already produced its local result.
            ObjectKind.DETERMINISTIC_RESULT,
            "application/vnd.yoetz.deterministic-result+json",
            seed.task_id,
            datetime(2026, 1, 1, tzinfo=UTC),
        ),
    )
    pending = OperationRecord(
        seed.writer_id,
        op_id,
        OperationKind.CHECK,
        "sha256:" + "c" * 64,
        OperationState.PENDING,
        CheckPhase.SEMANTIC_WAIT,
        "owner-generation-1",
        "lease-owner-1",
        1,
        datetime(2030, 1, 1, tzinfo=UTC),
        resume,
        None,
        None,
        None,
        None,
        None,
    )
    ledger._state.operations[(seed.writer_id, op_id)] = (  # pyright: ignore[reportPrivateUsage]
        pending,
        None,
    )

    status = await execute_status(
        cast(StatusApplication, app),
        _status_operation_request(
            session_id=seed.session_id,
            writer_id=seed.writer_id,
            operation_request_id=op_id,
            request_tail=802,
        ),
    )
    page = cast(StatusOperationPageModel, status.page)
    assert page.found is True
    assert page.state == "pending"
    assert page.operation_kind == "check"
