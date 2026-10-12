"""Provider-free integration of the ready application workflow and projection boundary."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import cast

import pytest

from builders.ledger_adapters import ownership_fence
from builders.start_application import (
    MemoryStartRuntime,
    protocol_id,
    start_composition,
    start_request,
)
from yoetz.application.egress import PrivacyCoordinator
from yoetz.application.service import (
    Application,
    ClientProjectionContext,
    ControlProjectionBinding,
    ProjectionRenderMode,
    VerificationPolicy,
)
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
from yoetz.domain.receipts import (
    PolicyVersionEntry,
    ReceiptVersionSlice,
    SchemaVersionEntry,
)
from yoetz.domain.values import Frontier, session_id
from yoetz.ports.control import ControlClientKind, ControlMethod
from yoetz.ports.diagnostics import RuntimeCapability
from yoetz.ports.importer import ImporterPort, ImportStatusSnapshot
from yoetz.ports.ledger import (
    CheckCommitResult,
    CheckPhase,
    OperationLease,
    OperationState,
)
from yoetz.ports.objects import ObjectKind, ObjectRef
from yoetz.ports.publish_response_catalog import PublishResponseCatalogPort
from yoetz.ports.runtime import BundleRuntimePort, RouteCommand, TaskRuntime
from yoetz.protocol.canonical import JsonValue, canonical_encode
from yoetz.protocol.errors import PublicErrorCode, PublicOperationError
from yoetz.protocol.models import (
    CheckRequest,
    FrontierModel,
    PublishWorkRequest,
    ReceiptRequest,
    ReceiptResultModel,
    RespondRequest,
    StatusRequest,
    StatusVersionsPageModel,
)
from yoetz.version import build_status_version_slice_facts

pytestmark = pytest.mark.anyio

_DIGEST = "sha256:" + "7" * 64
_WORKSPACE = "hmac-sha256:" + "8" * 64


class _IdleImporter:
    async def status(self, session: str) -> ImportStatusSnapshot:
        return ImportStatusSnapshot(session_id(session), 0, 0, (), ())


class _WorkflowRuntime(MemoryStartRuntime):
    """Extend the START memory composition with ready writer routing."""

    async def route(self, command: RouteCommand) -> TaskRuntime:
        assert command.writer_id is not None
        assert command.required_capabilities <= frozenset(
            {
                RuntimeCapability.WRITE,
                RuntimeCapability.STRUCTURAL_READ,
                RuntimeCapability.PAYLOAD_READ,
            }
        )
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
    def __init__(self) -> None:
        self.candidates: list[CandidateContext] = []

    async def prepare_local_disclosure(
        self, candidate: CandidateContext
    ) -> LocalDisclosureApproved:
        self.candidates.append(candidate)
        sink = candidate.local_sink
        assert sink is not None
        proposal_id = protocol_id("ppr_", 801)
        policy = ReceiptPolicyBinding(
            protocol_id("pvy_", 802),
            1,
            _DIGEST,
            _DIGEST,
        )
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
        # Keep this workflow on the current receipt artifact so the latest catalog schema's
        # required additive children section is present in the projected document.
        schema_versions=(SchemaVersionEntry("receipts/receipt-document", "1.3.0"),),
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


def _request_base(request_id: str) -> dict[str, JsonValue]:
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": request_id,
        "actor": {"actor_id": "harness:test", "actor_type": "harness"},
        "client": {"kind": "test_client", "version": "0.1.0", "integration": "local_cli"},
    }


def _frontier(value: Frontier | FrontierModel) -> JsonValue:
    if isinstance(value, Frontier):
        return cast(JsonValue, dict(value.as_wire().items()))
    return cast(JsonValue, value.model_dump(mode="json"))


async def test_full_workflow_uses_one_final_client_projection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    start_app, start_runtime, clock, catalog = start_composition()
    projection = _ProjectionSpy()
    ids = start_runtime.ids
    runtime = _WorkflowRuntime(clock, ids)
    app = Application(
        start_catalog=catalog.delegate,
        publish_responses=cast(PublishResponseCatalogPort, catalog.delegate),
        runtime=cast(BundleRuntimePort, runtime),
        clock=clock,
        ids=ids,
        verification_policy=VerificationPolicy(semantic="disabled", max_findings=3),
        privacy=cast(PrivacyCoordinator, projection),
        status_cursor_key=b"workflow-status-cursor-key",
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

    started = await app.start(start_request(810, title="Offline full workflow"))
    obligation_id = protocol_id("obl_", 811)
    obligation_event_id = protocol_id("evt_", 813)
    publish_wire = {
        **_request_base(protocol_id("req_", 812)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(started.frontier),
        "event_drafts": (
            {
                "event_id": obligation_event_id,
                "schema": {"name": "obligation_published", "version": "1.0.0"},
                "occurred_at": "2026-07-19T12:00:00.000Z",
                "causal_parents": (),
                "payload": {
                    "obligation_id": obligation_id,
                    "description": "Publish a result for the full-workflow exercise.",
                    "acceptance_criteria": "A result is recorded in the task ledger.",
                    "evidence_expectation": "A linked immutable result record.",
                    "requested_items": ({"item_kind": "change", "value": "workflow-result"},),
                    "status": "open",
                },
                "artifact_refs": (),
                "evidence_refs": (),
            },
            {
                "event_id": protocol_id("evt_", 818),
                "schema": {"name": "claim_recorded", "version": "1.0.0"},
                "occurred_at": "2026-07-19T12:00:01.000Z",
                "causal_parents": (obligation_event_id,),
                "payload": {
                    "claim_id": protocol_id("clm_", 819),
                    "claim_kind": "completion",
                    "statement": "The workflow is complete.",
                    "supporting_refs": (obligation_id,),
                    "obligation_refs": (obligation_id,),
                },
                "artifact_refs": (),
                "evidence_refs": (),
            },
        ),
    }
    published = await app.publish_work(PublishWorkRequest.model_validate(publish_wire))

    first_check_wire = {
        **_request_base(protocol_id("req_", 814)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(published.result_frontier),
        "mode": "deterministic_only",
        "max_findings": "3",
    }
    check_request = CheckRequest.model_validate(first_check_wire)
    ledger, objects = runtime.resources[started.task_id]
    advance = ledger.advance_check_phase
    crash_pending = True

    async def crash_after_deterministic_result(
        lease: OperationLease,
        expected_phase: CheckPhase,
        next_phase: CheckPhase,
        durable_object_ref: ObjectRef | None = None,
    ) -> OperationLease:
        nonlocal crash_pending
        if crash_pending and expected_phase is CheckPhase.RESERVED:
            crash_pending = False
            raise RuntimeError("simulated_post_deterministic_publish_crash")
        return await advance(lease, expected_phase, next_phase, durable_object_ref)

    monkeypatch.setattr(ledger, "advance_check_phase", crash_after_deterministic_result)
    with pytest.raises(PublicOperationError) as first_failure:
        await app.check(check_request)
    assert first_failure.value.code is PublicErrorCode.INTERNAL_ERROR
    failed_operation = await ledger.lookup_operation(started.writer_id, check_request.request_id)
    assert failed_operation is not None
    assert failed_operation.state is OperationState.COMPLETE
    assert failed_operation.phase is CheckPhase.TERMINAL
    with pytest.raises(PublicOperationError) as exact_replay:
        await app.check(check_request)
    assert exact_replay.value.code is PublicErrorCode.INTERNAL_ERROR

    recovery_wire = {
        **first_check_wire,
        "request_id": protocol_id("req_", 822),
    }
    recovery_request = CheckRequest.model_validate(recovery_wire)

    crash_after_local_ready = True

    async def crash_before_finalization(
        lease: OperationLease,
        expected_phase: CheckPhase,
        next_phase: CheckPhase,
        durable_object_ref: ObjectRef | None = None,
    ) -> OperationLease:
        nonlocal crash_after_local_ready
        replacement = await advance(lease, expected_phase, next_phase, durable_object_ref)
        if crash_after_local_ready and next_phase is CheckPhase.LOCAL_READY:
            crash_after_local_ready = False
            raise RuntimeError("simulated_post_local_ready_crash")
        return replacement

    monkeypatch.setattr(ledger, "advance_check_phase", crash_before_finalization)
    with pytest.raises(PublicOperationError) as second_failure:
        await app.check(recovery_request)
    assert second_failure.value.code is PublicErrorCode.INTERNAL_ERROR
    deterministic_refs = objects.refs_for_kind(ObjectKind.DETERMINISTIC_RESULT)
    assert len(deterministic_refs) == 2
    durable_operation = await ledger.lookup_operation(
        started.writer_id, recovery_request.request_id
    )
    assert durable_operation is not None
    assert durable_operation.phase is CheckPhase.LOCAL_READY
    assert durable_operation.resume_object_ref == deterministic_refs[-1]

    clock.advance(61)
    monkeypatch.setattr(ledger, "advance_check_phase", advance)

    checked = await app.check(recovery_request)
    assert type(checked) is CheckCommitResult, f"unexpected nonterminal check: {type(checked)}"
    assert checked.findings
    assert len(objects.refs_for_kind(ObjectKind.DETERMINISTIC_RESULT)) == 2
    finding = checked.findings[0]

    respond_wire = {
        **_request_base(protocol_id("req_", 815)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(checked.result_frontier),
        "finding_id": finding.finding_id,
        "finding_frontier": _frontier(checked.result_frontier),
        "disposition": "acknowledged",
        "reason": "The missing result remains explicit until follow-up work is published.",
    }
    responded = await app.respond(RespondRequest.model_validate(respond_wire))

    second_check_wire = {
        **_request_base(protocol_id("req_", 816)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(responded.result_frontier),
        "mode": "deterministic_only",
        "max_findings": "3",
    }
    rechecked = await app.check(CheckRequest.model_validate(second_check_wire))
    assert type(rechecked) is CheckCommitResult, f"unexpected nonterminal check: {type(rechecked)}"

    status = await app.status(
        StatusRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 820)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "view": "versions",
                "limit": "10",
                "at_frontier": str(rechecked.result_frontier.sequence),
            }
        ),
        route_profile="strict",
    )
    assert status.subject_frontier == rechecked.result_frontier
    assert status.view == "versions"
    assert type(status.page) is StatusVersionsPageModel
    assert status.page.items[0].route_profile == "strict"
    versions = status.page.items[0]
    facts = build_status_version_slice_facts()
    assert versions.apsw_version == facts.apsw_version
    assert versions.sqlite_version == facts.sqlite_version
    assert versions.sqlite_source_id == facts.sqlite_source_id
    assert versions.projection_version == facts.projection_version
    assert versions.apsw_version != "3.51.0.0"
    assert versions.sqlite_version != "3.51.0"
    assert versions.sqlite_source_id != "runtime-verified-by-connection-gate"

    receipt_wire = {
        **_request_base(protocol_id("req_", 817)),
        "task_id": started.task_id,
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(rechecked.result_frontier),
        "format": "json",
        "include": "standard",
        "redaction_profile": "full_local",
    }
    receipt_request = ReceiptRequest.model_validate(receipt_wire)
    receipt = await app.receipt(receipt_request)

    assert projection.candidates == []
    facts = await app.projection_binding_facts(
        ControlMethod.RECEIPT,
        receipt_request,
        receipt,
    )
    rpc_id = protocol_id("rpc_", 820)
    service_instance_id = protocol_id("svc_", 821)
    binding = ControlProjectionBinding(
        rpc_id,
        ControlMethod.RECEIPT,
        service_instance_id,
        1,
        facts.original_request_id,
        facts.route_identity_digest,
        canonical_encode(
            {
                "rpc_id": rpc_id,
                "method": "receipt",
                "service_instance_id": service_instance_id,
                "service_generation": "1",
            }
        ),
    )
    projected = await app.project_result_for_client(
        ClientProjectionContext(
            ControlClientKind.CLI,
            ProjectionRenderMode.HUMAN_READABLE,
            True,
        ),
        binding,
        receipt,
    )

    assert isinstance(projected, ReceiptResultModel)
    assert projected.root.ok is True
    assert projected.root.receipt_id == receipt.receipt_id
    assert projected.root.privacy_projection.sink == "local_human_view"
    assert len(projection.candidates) == 1
    assert _frontier(published.subject_frontier) == _frontier(started.frontier)
    assert checked.subject_frontier == published.result_frontier
    assert responded.subject_frontier == checked.result_frontier
    assert rechecked.subject_frontier == responded.result_frontier
    assert receipt.subject_frontier == rechecked.result_frontier
    assert runtime.release_count == 10
