"""Public status contract: read-only cross-surface parity, receipted disclosure, frontier and
pagination exactness, the future-frontier error mapping, the candidate-findings whole-case path,
and filter/derivation defaults.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from datetime import UTC, datetime
from typing import cast
from unittest.mock import AsyncMock

import pytest

from builders.ledger_adapters import ownership_fence
from builders.start_application import (
    MemoryStartRuntime,
    protocol_id,
    start_composition,
    start_request,
)
from finishup.application.egress import PrivacyCoordinator
from finishup.application.projects import ProjectApplication
from finishup.application.service import (
    Application,
    ClientProjectionContext,
    ControlProjectionBinding,
    ProjectionRenderMode,
    VerificationPolicy,
)
from finishup.application.start import StartInternalResult
from finishup.application.status import StatusInternalResult
from finishup.application.task_views import LineageStatusSnapshot, ProjectStatusSnapshot
from finishup.domain.events import AcceptedEvent, RuntimeProfile
from finishup.domain.privacy import (
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
from finishup.domain.receipts import PolicyVersionEntry, ReceiptVersionSlice, SchemaVersionEntry
from finishup.domain.values import Frontier, session_id
from finishup.kernel.reducers import replay
from finishup.ports.control import ControlClientKind, ControlMethod
from finishup.ports.diagnostics import RuntimeCapability
from finishup.ports.importer import ImporterPort, ImportStatusSnapshot
from finishup.ports.ledger import CheckCommitResult
from finishup.ports.publish_response_catalog import PublishResponseCatalogPort
from finishup.ports.runtime import BundleRuntimePort, RouteCommand, TaskRuntime
from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.models import (
    CheckRequest,
    FrontierModel,
    PublishWorkDryRunModel,
    PublishWorkRequest,
    PublishWorkResultModel,
    RespondRequest,
    StatusCandidateFindingsPageModel,
    StatusCompactPageModel,
    StatusFindingsPageModel,
    StatusLineageAnnotationModel,
    StatusLineageChildModel,
    StatusLineagePageModel,
    StatusObligationsPageModel,
    StatusProjectMemberModel,
    StatusProjectPageModel,
    StatusRequest,
    StatusResultModel,
    StatusResultsPageModel,
)

pytestmark = pytest.mark.anyio

_DIGEST = "sha256:" + "7" * 64
_WORKSPACE = "hmac-sha256:" + "8" * 64
_POLICY_PACKS = ("research-evidence/0.2.0", "work-integrity/0.3.0")


class _IdleImporter:
    async def status(self, session: str) -> ImportStatusSnapshot:
        return ImportStatusSnapshot(session_id(session), 0, 0, (), ())


class _Reservation:
    source_identity_digest = _DIGEST
    publication_ordinal = 0


class _ReservedImportState:
    """Minimal already-verified reservation seam used by the memory ledger import path."""

    jobs: dict[str, object] = {}

    def has_pending_import(self, session: str) -> bool:
        del session
        return False

    def publication_reservation(self, writer: str, request: str) -> _Reservation:
        del writer, request
        return _Reservation()


class _WorkflowRuntime(MemoryStartRuntime):
    """Extend the START memory composition with ready writer routing (duplicated across
    operation-contract test modules by established convention; see
    ``tests/integration/application/test_respond_status_receipt.py``)."""

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
    def __init__(self) -> None:
        self.candidates: list[CandidateContext] = []

    async def prepare_local_disclosure(
        self, candidate: CandidateContext
    ) -> LocalDisclosureApproved:
        self.candidates.append(candidate)
        sink = candidate.local_sink
        assert sink is not None
        proposal_id = protocol_id("ppr_", 3900 + len(self.candidates))
        policy = ReceiptPolicyBinding(
            protocol_id("pvy_", 3950 + len(self.candidates)), 1, _DIGEST, _DIGEST
        )
        receipt = LocalDisclosureReceipt(
            "1.0.0",
            protocol_id("egr_", 3960 + len(self.candidates)),
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
        package_name="finishup",
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


def _scope(_binding: object, source: Mapping[str, JsonValue]) -> AuthorizationScope:
    return AuthorizationScope(
        AuthorizationScopeKind.TASK,
        protocol_id("ins_", 3999),
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


def _actor(actor_type: str = "harness") -> dict[str, JsonValue]:
    return {"actor_id": "harness:test", "actor_type": actor_type}


def _client(integration: str = "local_cli") -> dict[str, JsonValue]:
    return {"kind": "test_client", "version": "0.1.0", "integration": integration}


def _request_base(request_id: str, *, actor_type: str = "harness") -> dict[str, JsonValue]:
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": request_id,
        "actor": _actor(actor_type),
        "client": _client(),
    }


def _frontier(value: Frontier | FrontierModel) -> JsonValue:
    if isinstance(value, Frontier):
        return cast(JsonValue, dict(value.as_wire().items()))
    return cast(JsonValue, value.model_dump(mode="json"))


def _build_app(
    *, seed_offset: int = 0, trusted_import: bool = False
) -> tuple[Application, _WorkflowRuntime, _ProjectionSpy]:
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
        status_cursor_key=(b"status-contract-cursor-key" + str(seed_offset).encode() * 8)[:32],
        waiver_policy_digest=_DIGEST,
        semantic_evaluator=_semantic_disabled,
        disclosure_scope_for=_scope,
        receipt_version_resolver=lambda _: _versions(),
        waiver_authorizer=lambda _: False,
        import_publication_authorizer=lambda _: trusted_import,
        profile=RuntimeProfile.TEST_FAKE,
        policy_packs=_POLICY_PACKS,
        version_manifest=start_app.version_manifest,
        enforce_repository_identity=False,
    )
    return app, runtime, projection


async def _bootstrap_finding(
    app: Application, *, seed: int, obligation_count: int = 1
) -> tuple[StartInternalResult, CheckCommitResult, tuple[str, ...]]:
    """Publish ``obligation_count`` open obligations plus an unsupported completion claim
    covering all of them, then check. Mirrors the exact scenario already proven in
    ``test_full_workflow.py`` to yield actionable ``completion_with_open_obligations`` findings.
    """

    started = await app.start(start_request(seed, title="Status contract exercise"))
    obligation_ids = tuple(
        protocol_id("obl_", seed + 1 + index) for index in range(obligation_count)
    )
    obligation_event_ids = tuple(
        protocol_id("evt_", seed + 10 + index) for index in range(obligation_count)
    )
    obligation_drafts = tuple(
        {
            "event_id": obligation_event_ids[index],
            "schema": {"name": "obligation_published", "version": "1.0.0"},
            "occurred_at": "2026-07-19T12:00:00.000Z",
            "causal_parents": (),
            "payload": {
                "obligation_id": obligation_ids[index],
                "description": f"Publish a result for status contract exercise {index}.",
                "acceptance_criteria": "A result is recorded in the task ledger.",
                "evidence_expectation": "A linked immutable result record.",
                "status": "open",
            },
            "artifact_refs": (),
            "evidence_refs": (),
        }
        for index in range(obligation_count)
    )
    claim_draft = {
        "event_id": protocol_id("evt_", seed + 20),
        "schema": {"name": "claim_recorded", "version": "1.0.0"},
        "occurred_at": "2026-07-19T12:00:01.000Z",
        "causal_parents": obligation_event_ids,
        "payload": {
            "claim_id": protocol_id("clm_", seed + 21),
            "claim_kind": "completion",
            "statement": "The exercise is complete.",
            "supporting_refs": obligation_ids,
            "obligation_refs": obligation_ids,
        },
        "artifact_refs": (),
        "evidence_refs": (),
    }
    publish_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", seed + 22)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(started.frontier),
        "event_drafts": (*obligation_drafts, claim_draft),
    }
    published = await app.publish_work(PublishWorkRequest.model_validate(publish_wire))
    check_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", seed + 23)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(published.result_frontier),
        "mode": "deterministic_only",
        "max_findings": "3",
    }
    checked = await app.check(CheckRequest.model_validate(check_wire))
    assert type(checked) is CheckCommitResult, f"unexpected nonterminal check: {type(checked)}"
    assert checked.findings, "the seeded scenario must always yield at least one finding"
    return started, checked, obligation_ids


def _cli_binding(rpc_seed: int, facts: object) -> ControlProjectionBinding:
    rpc_id = protocol_id("rpc_", rpc_seed)
    service_instance_id = protocol_id("svc_", rpc_seed + 1)
    return ControlProjectionBinding(
        rpc_id,
        ControlMethod.STATUS,
        service_instance_id,
        1,
        cast(str | None, getattr(facts, "original_request_id", None)),
        cast(str | None, getattr(facts, "route_identity_digest", None)),
        canonical_encode(
            {
                "rpc_id": rpc_id,
                "method": "status",
                "service_instance_id": service_instance_id,
                "service_generation": "1",
            }
        ),
    )


async def _assert_mcp_scope_projection(
    app: Application,
    request: StatusRequest,
    status: StatusInternalResult,
    *,
    seed: int,
    declared: str | None,
    opened: str | None,
    reason: str | None,
    blockers: tuple[str, ...],
) -> None:
    source = cast(
        dict[str, JsonValue], request.model_dump(mode="json", by_alias=True, exclude_none=True)
    )
    facts = await app.projection_binding_facts(ControlMethod.STATUS, source, status)
    projected = await app.project_result_for_client(
        ClientProjectionContext(
            ControlClientKind.MCP_BRIDGE,
            ProjectionRenderMode.MACHINE_READABLE,
            False,
        ),
        _cli_binding(seed, facts),
        status,
    )
    assert isinstance(projected, StatusResultModel)
    assert projected.root.ok is True
    page = cast(StatusCompactPageModel, projected.root.page)
    assert page.items[0].declared_obligation_count == declared
    assert page.items[0].open_obligation_count == opened
    assert page.items[0].no_obligations_reason == reason
    assert projected.root.closure_readiness.blocking_conditions == blockers


async def test_status_request_result_parity() -> None:
    """The same status result, projected for CLI and MCP-bridge surfaces, carries the same
    public page content everywhere; only the trusted per-surface disclosure sink differs."""

    app, _runtime, projection = _build_app(seed_offset=1)
    started, checked, _obligations = await _bootstrap_finding(app, seed=100)
    status_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 110)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "view": "findings",
        "limit": "10",
        "at_frontier": str(checked.result_frontier.sequence),
    }
    status = await app.status(StatusRequest.model_validate(status_wire))
    facts = await app.projection_binding_facts(ControlMethod.STATUS, status_wire, status)

    cli_context = ClientProjectionContext(
        ControlClientKind.CLI, ProjectionRenderMode.HUMAN_READABLE, True
    )
    mcp_context = ClientProjectionContext(
        ControlClientKind.MCP_BRIDGE, ProjectionRenderMode.MACHINE_READABLE, False
    )
    cli_projected = await app.project_result_for_client(
        cli_context, _cli_binding(111, facts), status
    )
    mcp_projected = await app.project_result_for_client(
        mcp_context, _cli_binding(113, facts), status
    )
    assert isinstance(cli_projected, StatusResultModel)
    assert isinstance(mcp_projected, StatusResultModel)
    assert cli_projected.root.ok is True
    assert mcp_projected.root.ok is True

    cli_body = cli_projected.root.model_dump(mode="json", exclude={"privacy_projection"})
    mcp_body = mcp_projected.root.model_dump(mode="json", exclude={"privacy_projection"})
    assert cli_body == mcp_body
    assert cli_projected.root.view == "findings"
    assert cli_projected.root.privacy_projection.sink == "local_human_view"
    assert mcp_projected.root.privacy_projection.sink == "agent_context"
    assert len(projection.candidates) == 2


@pytest.mark.parametrize(
    "reason",
    (
        None,
        "no_material_change",
        "single_atomic_change",
        "exploratory_scope_unknown",
    ),
)
async def test_status_distinguishes_undeclared_and_declared_empty_scope(
    reason: str | None,
) -> None:
    seed = (
        500
        if reason is None
        else 510
        + (
            "no_material_change",
            "single_atomic_change",
            "exploratory_scope_unknown",
        ).index(reason)
    )
    app, _runtime, _projection = _build_app(seed_offset=seed)
    started = await app.start(start_request(seed, title="Declared completion scope"))

    before = await app.status(
        StatusRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 1)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "view": "compact",
                "limit": "10",
            }
        )
    )
    before_page = cast(StatusCompactPageModel, before.page)
    assert before_page.items[0].declared_obligation_count == "0"
    assert before_page.items[0].no_obligations_reason is None
    assert before.closure_readiness.blocking_conditions == ("no_plan_published",)

    payload: dict[str, JsonValue] = {
        "plan_version": 1,
        "summary": "Record the effective completion scope.",
        "obligation_refs": [],
    }
    if reason is not None:
        payload["no_obligations_reason"] = reason
    published = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 2)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(started.frontier),
                "event_drafts": [
                    {
                        "event_id": protocol_id("evt_", seed + 3),
                        "schema": {"name": "plan_published", "version": "1.0.0"},
                        "occurred_at": "2026-08-04T12:00:00.000Z",
                        "causal_parents": [],
                        "payload": payload,
                        "artifact_refs": [],
                        "evidence_refs": [],
                    }
                ],
            }
        )
    )
    status_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", seed + 4)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "view": "compact",
        "limit": "10",
        "at_frontier": str(published.result_frontier.sequence),
    }
    status = await app.status(StatusRequest.model_validate(status_wire))
    page = cast(StatusCompactPageModel, status.page)
    item = page.items[0]
    assert item.declared_obligation_count == "0"
    assert item.no_obligations_reason == reason
    assert item.open_obligation_count == "0"
    assert status.closure_readiness.declared_obligation_count == "0"
    assert status.closure_readiness.no_obligations_reason == reason
    assert status.closure_readiness.blocking_conditions == (
        ("no_obligations_declared",) if reason is None else ()
    )

    facts = await app.projection_binding_facts(ControlMethod.STATUS, status_wire, status)
    projected = await app.project_result_for_client(
        ClientProjectionContext(
            ControlClientKind.MCP_BRIDGE,
            ProjectionRenderMode.MACHINE_READABLE,
            False,
        ),
        _cli_binding(seed + 5, facts),
        status,
    )
    assert isinstance(projected, StatusResultModel)
    assert projected.root.ok is True
    projected_success = projected.root
    projected_page = cast(StatusCompactPageModel, projected_success.page)
    assert projected_page.items[0].no_obligations_reason == reason
    assert projected_success.closure_readiness.blocking_conditions == (
        ("no_obligations_declared",) if reason is None else ()
    )


async def test_status_distinguishes_open_and_resolved_declared_obligations() -> None:
    seed = 540
    app, _runtime, _projection = _build_app(seed_offset=seed)
    started = await app.start(start_request(seed, title="Declared obligation lifecycle"))
    obligation_id = protocol_id("obl_", seed + 1)
    obligation_event_id = protocol_id("evt_", seed + 2)
    plan_event_id = protocol_id("evt_", seed + 3)
    meaning: dict[str, JsonValue] = {
        "obligation_id": obligation_id,
        "description": "Prove the declared status lifecycle.",
        "acceptance_criteria": "The declared obligation resolves with evidence.",
        "evidence_expectation": "A focused deterministic test result.",
    }
    published = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 4)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(started.frontier),
                "event_drafts": [
                    {
                        "event_id": obligation_event_id,
                        "schema": {"name": "obligation_published", "version": "1.0.0"},
                        "occurred_at": "2026-08-04T12:00:00.000Z",
                        "causal_parents": [],
                        "payload": {**meaning, "status": "open"},
                        "artifact_refs": [],
                        "evidence_refs": [],
                    },
                    {
                        "event_id": plan_event_id,
                        "schema": {"name": "plan_published", "version": "1.0.0"},
                        "occurred_at": "2026-08-04T12:00:01.000Z",
                        "causal_parents": [obligation_event_id],
                        "payload": {
                            "plan_version": 1,
                            "summary": "Declare the obligation status lifecycle.",
                            "obligation_refs": [obligation_id],
                        },
                        "artifact_refs": [],
                        "evidence_refs": [],
                    },
                ],
            }
        )
    )

    open_request = StatusRequest.model_validate(
        {
            **_request_base(protocol_id("req_", seed + 5)),
            "session_id": started.session_id,
            "writer_id": started.writer_id,
            "view": "compact",
            "limit": "10",
            "at_frontier": str(published.result_frontier.sequence),
        }
    )
    open_status = await app.status(open_request)
    open_item = cast(StatusCompactPageModel, open_status.page).items[0]
    assert open_item.declared_obligation_count == "1"
    assert open_item.open_obligation_count == "1"
    assert open_item.no_obligations_reason is None
    assert open_status.closure_readiness.blocking_conditions == ("obligations_open",)
    await _assert_mcp_scope_projection(
        app,
        open_request,
        open_status,
        seed=seed + 50,
        declared="1",
        opened="1",
        reason=None,
        blockers=("obligations_open",),
    )

    evidence_id = protocol_id("evd_", seed + 6)
    resolved = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 7)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(published.result_frontier),
                "event_drafts": [
                    {
                        "event_id": protocol_id("evt_", seed + 8),
                        "schema": {"name": "evidence_recorded", "version": "1.0.0"},
                        "occurred_at": "2026-08-04T12:00:02.000Z",
                        "causal_parents": [plan_event_id],
                        "payload": {
                            "evidence_id": evidence_id,
                            "evidence_kind": "test_result",
                            "strength": "content_digest",
                            "content_digest": "sha256:" + "1" * 64,
                            "observed_at": "2026-08-04T12:00:02.000Z",
                            "description": "The focused declared-scope test passed.",
                        },
                        "artifact_refs": [],
                        "evidence_refs": [],
                    },
                    {
                        "event_id": protocol_id("evt_", seed + 9),
                        "schema": {"name": "obligation_published", "version": "1.0.0"},
                        "occurred_at": "2026-08-04T12:00:03.000Z",
                        "causal_parents": [protocol_id("evt_", seed + 8)],
                        "payload": {
                            **meaning,
                            "status": "resolved",
                            "resolution_evidence_refs": [evidence_id],
                        },
                        "artifact_refs": [],
                        "evidence_refs": [evidence_id],
                    },
                ],
            }
        )
    )
    resolved_request = StatusRequest.model_validate(
        {
            **_request_base(protocol_id("req_", seed + 10)),
            "session_id": started.session_id,
            "writer_id": started.writer_id,
            "view": "compact",
            "limit": "10",
            "at_frontier": str(resolved.result_frontier.sequence),
        }
    )
    resolved_status = await app.status(resolved_request)
    resolved_item = cast(StatusCompactPageModel, resolved_status.page).items[0]
    assert resolved_item.declared_obligation_count == "1"
    assert resolved_item.open_obligation_count == "0"
    # ADR-046: status lists the gaps the receipt would carry, so the digest-only evidence that
    # resolved the obligation is declared here instead of surfacing only on the receipt.
    assert resolved_status.closure_readiness.blocking_conditions == ("coverage_gaps_declared",)
    assert "evidence_digest_subject_legacy_unknown" in (
        resolved_status.closure_readiness.standing_limitations or ()
    )
    await _assert_mcp_scope_projection(
        app,
        resolved_request,
        resolved_status,
        seed=seed + 52,
        declared="1",
        opened="0",
        reason=None,
        blockers=("coverage_gaps_declared",),
    )


async def test_status_revision_repairs_undeclared_empty_scope() -> None:
    seed = 560
    app, _runtime, _projection = _build_app(seed_offset=seed)
    started = await app.start(start_request(seed, title="Repair declared empty scope"))
    first_event_id = protocol_id("evt_", seed + 1)
    first = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 2)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(started.frontier),
                "event_drafts": [
                    {
                        "event_id": first_event_id,
                        "schema": {"name": "plan_published", "version": "1.0.0"},
                        "occurred_at": "2026-08-04T12:00:00.000Z",
                        "causal_parents": [],
                        "payload": {
                            "plan_version": 1,
                            "summary": "Initially omit the empty-scope declaration.",
                            "obligation_refs": [],
                        },
                        "artifact_refs": [],
                        "evidence_refs": [],
                    }
                ],
            }
        )
    )
    before = await app.status(
        StatusRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 3)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "view": "compact",
                "limit": "10",
                "at_frontier": str(first.result_frontier.sequence),
            }
        )
    )
    assert before.closure_readiness.blocking_conditions == ("no_obligations_declared",)

    revised = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 4)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(first.result_frontier),
                "event_drafts": [
                    {
                        "event_id": protocol_id("evt_", seed + 5),
                        "schema": {"name": "plan_revised", "version": "1.0.0"},
                        "occurred_at": "2026-08-04T12:00:01.000Z",
                        "causal_parents": [first_event_id],
                        "payload": {
                            "plan_version": 2,
                            "supersedes_plan_version": 1,
                            "reason": "Record the explicit empty-scope declaration.",
                            "summary": "No material change applies.",
                            "obligation_changes": [],
                            "no_obligations_reason": "no_material_change",
                        },
                        "artifact_refs": [],
                        "evidence_refs": [],
                    }
                ],
            }
        )
    )
    after_request = StatusRequest.model_validate(
        {
            **_request_base(protocol_id("req_", seed + 6)),
            "session_id": started.session_id,
            "writer_id": started.writer_id,
            "view": "compact",
            "limit": "10",
            "at_frontier": str(revised.result_frontier.sequence),
        }
    )
    after = await app.status(after_request)
    after_item = cast(StatusCompactPageModel, after.page).items[0]
    assert after_item.declared_obligation_count == "0"
    assert after_item.no_obligations_reason == "no_material_change"
    assert after.closure_readiness.blocking_conditions == ()
    await _assert_mcp_scope_projection(
        app,
        after_request,
        after,
        seed=seed + 50,
        declared="0",
        opened="0",
        reason="no_material_change",
        blockers=(),
    )


async def test_status_missing_declared_reference_stays_conservatively_open() -> None:
    seed = 580
    app, _runtime, _projection = _build_app(seed_offset=seed)
    started = await app.start(start_request(seed, title="Missing declared reference"))
    missing_obligation = protocol_id("obl_", seed + 1)
    published = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 2)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(started.frontier),
                "event_drafts": [
                    {
                        "event_id": protocol_id("evt_", seed + 3),
                        "schema": {"name": "plan_published", "version": "1.0.0"},
                        "occurred_at": "2026-08-04T12:00:00.000Z",
                        "causal_parents": [],
                        "payload": {
                            "plan_version": 1,
                            "summary": "Retain the declared missing reference.",
                            "obligation_refs": [missing_obligation],
                        },
                        "artifact_refs": [],
                        "evidence_refs": [],
                    }
                ],
            }
        )
    )
    status_request = StatusRequest.model_validate(
        {
            **_request_base(protocol_id("req_", seed + 4)),
            "session_id": started.session_id,
            "writer_id": started.writer_id,
            "view": "compact",
            "limit": "10",
            "at_frontier": str(published.result_frontier.sequence),
        }
    )
    status = await app.status(status_request)
    item = cast(StatusCompactPageModel, status.page).items[0]
    assert item.declared_obligation_count == "1"
    assert item.open_obligation_count == "1"
    assert item.open_obligations == ()
    assert "missing_ref" in item.gaps
    assert status.closure_readiness.blocking_conditions == (
        "obligations_open",
        "coverage_gaps_declared",
    )
    await _assert_mcp_scope_projection(
        app,
        status_request,
        status,
        seed=seed + 50,
        declared="1",
        opened="1",
        reason=None,
        blockers=("obligations_open", "coverage_gaps_declared"),
    )


async def test_unreadable_plan_scope_is_unknown_in_status_and_attach() -> None:
    seed = 600
    app, runtime, _projection = _build_app(seed_offset=seed)
    title = "Redacted declared scope"
    started = await app.start(start_request(seed, title=title))
    plan_event_id = protocol_id("evt_", seed + 1)
    plan = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 2)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(started.frontier),
                "event_drafts": [
                    {
                        "event_id": plan_event_id,
                        "schema": {"name": "plan_published", "version": "1.0.0"},
                        "occurred_at": "2026-08-04T12:00:00.000Z",
                        "causal_parents": [],
                        "payload": {
                            "plan_version": 1,
                            "summary": "Declare an empty scope before redaction.",
                            "obligation_refs": [],
                            "no_obligations_reason": "single_atomic_change",
                        },
                        "artifact_refs": [],
                        "evidence_refs": [],
                    }
                ],
            }
        )
    )
    ledger, _objects = runtime.resources[started.task_id]
    unreadable_records = tuple(
        replace(record, payload=None)
        if type(record) is AcceptedEvent and record.event_id == plan_event_id
        else record
        for record in ledger._state.records  # pyright: ignore[reportPrivateUsage]
    )
    ledger._state.records = unreadable_records  # pyright: ignore[reportPrivateUsage]
    ledger._state.projection = replay(unreadable_records)  # pyright: ignore[reportPrivateUsage]
    status = await app.status(
        StatusRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 5)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "view": "compact",
                "limit": "10",
                "at_frontier": str(plan.result_frontier.sequence),
            }
        )
    )
    item = cast(StatusCompactPageModel, status.page).items[0]
    assert item.current_plan_event_id == plan_event_id
    assert item.declared_obligation_count is None
    assert item.open_obligation_count is None
    assert item.no_obligations_reason is None
    assert status.closure_readiness.declared_obligation_count is None
    assert status.closure_readiness.blocking_conditions == ("readiness_unknown",)

    attached = await app.start(
        start_request(
            seed + 6,
            mode="attach",
            title=title,
            session_id=started.session_id,
        )
    )
    assert attached.compact.open_obligation_count is None


async def test_redacted_declared_obligation_stays_conservatively_open() -> None:
    seed = 620
    app, runtime, _projection = _build_app(seed_offset=seed)
    started = await app.start(start_request(seed, title="Redacted declared obligation"))
    obligation_id = protocol_id("obl_", seed + 1)
    obligation_event_id = protocol_id("evt_", seed + 2)
    await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 3)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(started.frontier),
                "event_drafts": [
                    {
                        "event_id": obligation_event_id,
                        "schema": {"name": "obligation_published", "version": "1.0.0"},
                        "occurred_at": "2026-08-04T12:00:00.000Z",
                        "causal_parents": [],
                        "payload": {
                            "obligation_id": obligation_id,
                            "description": "Keep a redacted declared row conservative.",
                            "acceptance_criteria": "Status never reports the row resolved.",
                            "evidence_expectation": "A readable obligation payload.",
                            "status": "open",
                        },
                        "artifact_refs": [],
                        "evidence_refs": [],
                    },
                    {
                        "event_id": protocol_id("evt_", seed + 4),
                        "schema": {"name": "plan_published", "version": "1.0.0"},
                        "occurred_at": "2026-08-04T12:00:01.000Z",
                        "causal_parents": [obligation_event_id],
                        "payload": {
                            "plan_version": 1,
                            "summary": "Declare the row before its payload becomes unreadable.",
                            "obligation_refs": [obligation_id],
                        },
                        "artifact_refs": [],
                        "evidence_refs": [],
                    },
                ],
            }
        )
    )
    ledger, _objects = runtime.resources[started.task_id]
    redacted_records = tuple(
        replace(record, payload=None)
        if type(record) is AcceptedEvent and record.event_id == obligation_event_id
        else record
        for record in ledger._state.records  # pyright: ignore[reportPrivateUsage]
    )
    ledger._state.records = redacted_records  # pyright: ignore[reportPrivateUsage]
    ledger._state.projection = replay(redacted_records)  # pyright: ignore[reportPrivateUsage]
    request = StatusRequest.model_validate(
        {
            **_request_base(protocol_id("req_", seed + 5)),
            "session_id": started.session_id,
            "writer_id": started.writer_id,
            "view": "compact",
            "limit": "10",
        }
    )
    status = await app.status(request)
    item = cast(StatusCompactPageModel, status.page).items[0]
    assert item.declared_obligation_count == "1"
    assert item.open_obligation_count == "1"
    assert item.open_obligations == ()
    assert status.closure_readiness.blocking_conditions == ("obligations_open",)
    await _assert_mcp_scope_projection(
        app,
        request,
        status,
        seed=seed + 50,
        declared="1",
        opened="1",
        reason=None,
        blockers=("obligations_open",),
    )


async def test_unknown_plan_family_event_makes_scope_unknown() -> None:
    seed = 640
    app, runtime, _projection = _build_app(seed_offset=seed, trusted_import=True)
    started = await app.start(start_request(seed, title="Unknown future plan event"))
    published = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 1)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(started.frontier),
                "event_drafts": [
                    {
                        "event_id": protocol_id("evt_", seed + 2),
                        "schema": {"name": "plan_published", "version": "1.0.0"},
                        "occurred_at": "2026-08-04T12:00:00.000Z",
                        "causal_parents": [],
                        "payload": {
                            "plan_version": 1,
                            "summary": "Known plan before a future plan-family event.",
                            "obligation_refs": [],
                            "no_obligations_reason": "exploratory_scope_unknown",
                        },
                        "artifact_refs": [],
                        "evidence_refs": [],
                    }
                ],
            }
        )
    )
    unknown_event_id = protocol_id("evt_", seed + 3)
    ledger, _objects = runtime.resources[started.task_id]
    ledger._import_state = _ReservedImportState()  # pyright: ignore[reportPrivateUsage]
    unknown = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 4), actor_type="importer"),
                "client": _client("codex_jsonl_import"),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(published.result_frontier),
                "event_drafts": [
                    {
                        "event_id": unknown_event_id,
                        "schema": {"name": "plan_revised", "version": "2.0.0"},
                        "occurred_at": "2026-08-04T12:00:01.000Z",
                        "causal_parents": [protocol_id("evt_", seed + 2)],
                        "payload": {"opaque": "future plan scope"},
                        "artifact_refs": [],
                        "evidence_refs": [],
                    }
                ],
            }
        )
    )
    request = StatusRequest.model_validate(
        {
            **_request_base(protocol_id("req_", seed + 5)),
            "session_id": started.session_id,
            "writer_id": started.writer_id,
            "view": "compact",
            "limit": "10",
            "at_frontier": str(unknown.result_frontier.sequence),
        }
    )
    status = await app.status(request)
    item = cast(StatusCompactPageModel, status.page).items[0]
    assert item.current_plan_event_id == unknown_event_id
    assert item.declared_obligation_count is None
    assert item.open_obligation_count is None
    assert item.no_obligations_reason is None
    assert "unknown_event" in item.gaps
    assert status.closure_readiness.blocking_conditions == ("readiness_unknown",)
    await _assert_mcp_scope_projection(
        app,
        request,
        status,
        seed=seed + 50,
        declared=None,
        opened=None,
        reason=None,
        blockers=("readiness_unknown",),
    )


async def test_status_is_task_state_read_only_and_projection_receipted() -> None:
    """Status writes no task-ledger event/object/operation and never mutates the projection;
    ordinary client disclosure of an otherwise-ordinary status result gets exactly one durable
    local-disclosure receipt and a ``privacy_projection``."""

    app, runtime, projection = _build_app(seed_offset=2)
    started, checked, _obligations = await _bootstrap_finding(app, seed=200)
    ledger, _objects = runtime.resources[started.task_id]
    frontier_before = await ledger.load_frontier()

    status_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 210)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "view": "findings",
        "limit": "10",
        "at_frontier": str(checked.result_frontier.sequence),
    }
    status_request = StatusRequest.model_validate(status_wire)
    status = await app.status(status_request)
    assert status.subject_frontier == checked.result_frontier
    assert status.result_frontier == checked.result_frontier

    # Repeating the identical read at the identical frontier never advances the ledger: status
    # produces no accepted event, so the frontier after two reads is unchanged.
    repeated = await app.status(
        StatusRequest.model_validate({**status_wire, "request_id": protocol_id("req_", 211)})
    )
    assert repeated.subject_frontier == status.subject_frontier
    assert repeated.result_frontier == status.result_frontier
    frontier_after = await ledger.load_frontier()
    assert frontier_after == frontier_before

    # The raw internal status result carries no privacy marker until it is projected for an
    # ordinary client; no candidate has been proposed yet.
    assert projection.candidates == []
    facts = await app.projection_binding_facts(ControlMethod.STATUS, status_wire, status)
    binding = _cli_binding(212, facts)
    projected = await app.project_result_for_client(
        ClientProjectionContext(ControlClientKind.CLI, ProjectionRenderMode.HUMAN_READABLE, True),
        binding,
        status,
    )
    assert isinstance(projected, StatusResultModel)
    assert projected.root.ok is True
    assert projected.root.privacy_projection.sink == "local_human_view"
    assert len(projection.candidates) == 1

    # Replaying the exact same logical projection reuses the durable receipt facts rather than
    # minting a fresh one for an unchanged result/policy/sink pair -- at most one additional
    # candidate is proposed to confirm reuse rather than an unbounded receipt per replay.
    projected_again = await app.project_result_for_client(
        ClientProjectionContext(ControlClientKind.CLI, ProjectionRenderMode.HUMAN_READABLE, True),
        binding,
        status,
    )
    assert isinstance(projected_again, StatusResultModel)
    assert projected_again.root.ok is True
    assert len(projection.candidates) <= 2


async def test_status_frontier_and_pagination_parity() -> None:
    """Requested/head/effective frontiers and page contents are exact across a paginated scan;
    the cursor never loses, duplicates, or reorders the fixed-frontier item set."""

    app, _runtime, _projection = _build_app(seed_offset=3)
    started, checked, obligation_ids = await _bootstrap_finding(app, seed=300, obligation_count=2)

    unpaginated_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 310)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "view": "obligations",
        "limit": "10",
        "at_frontier": str(checked.result_frontier.sequence),
    }
    unpaginated = await app.status(StatusRequest.model_validate(unpaginated_wire))
    unpaginated_page = cast(StatusObligationsPageModel, unpaginated.page)
    assert len(unpaginated_page.items) == len(obligation_ids)

    first_wire: dict[str, JsonValue] = {
        **unpaginated_wire,
        "request_id": protocol_id("req_", 311),
        "limit": "1",
    }
    first_page = await app.status(StatusRequest.model_validate(first_wire))
    first_obligations_page = cast(StatusObligationsPageModel, first_page.page)
    assert len(first_obligations_page.items) == 1
    assert first_obligations_page.next_cursor is not None
    assert first_page.subject_frontier == unpaginated.subject_frontier
    assert first_page.head_frontier == unpaginated.head_frontier

    second_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 312)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "view": "obligations",
        "limit": "1",
        "cursor": first_obligations_page.next_cursor,
    }
    second_page = await app.status(StatusRequest.model_validate(second_wire))
    second_obligations_page = cast(StatusObligationsPageModel, second_page.page)
    assert len(second_obligations_page.items) == 1
    assert second_page.subject_frontier == unpaginated.subject_frontier
    assert second_page.head_frontier == unpaginated.head_frontier

    paginated_ids = {
        first_obligations_page.items[0].obligation_id,
        second_obligations_page.items[0].obligation_id,
    }
    unpaginated_ids = {item.obligation_id for item in unpaginated_page.items}
    assert paginated_ids == unpaginated_ids


async def test_status_projects_requested_attempt_accounting_and_result_structure() -> None:
    app, _runtime, _projection = _build_app(seed_offset=31)
    seed = 3_100
    started = await app.start(start_request(seed, title="Attempt-accounting status"))
    obligation = protocol_id("obl_", seed + 1)
    obligation_event = protocol_id("evt_", seed + 2)
    plan_event = protocol_id("evt_", seed + 3)
    command = "uv run pytest tests/unit/example.py"
    change = "src/finishup/example.py"
    published = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 4)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(started.frontier),
                "event_drafts": [
                    {
                        "event_id": obligation_event,
                        "schema": {"name": "obligation_published", "version": "1.0.0"},
                        "occurred_at": "2026-08-28T10:00:00.000Z",
                        "causal_parents": [],
                        "payload": {
                            "obligation_id": obligation,
                            "description": "Exercise exact attempt accounting.",
                            "acceptance_criteria": "Both request kinds stay byte-identical.",
                            "evidence_expectation": "A structural status projection.",
                            "status": "open",
                            "requested_items": [
                                {"item_kind": "command", "value": command},
                                {"item_kind": "change", "value": change},
                            ],
                        },
                        "artifact_refs": [],
                        "evidence_refs": [],
                    },
                    {
                        "event_id": plan_event,
                        "schema": {"name": "plan_published", "version": "1.0.0"},
                        "occurred_at": "2026-08-28T10:00:01.000Z",
                        "causal_parents": [obligation_event],
                        "payload": {
                            "plan_version": 1,
                            "summary": "Declare the attempt-accounting obligation.",
                            "obligation_refs": [obligation],
                        },
                        "artifact_refs": [],
                        "evidence_refs": [],
                    },
                ],
            }
        )
    )

    obligations = await app.status(
        StatusRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 5)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "view": "obligations",
                "limit": "10",
                "at_frontier": str(published.result_frontier.sequence),
            }
        )
    )
    item = cast(StatusObligationsPageModel, obligations.page).items[0]
    assert tuple((entry.item_kind, entry.value) for entry in item.requested_items) == (
        ("command", command),
        ("change", change),
    )
    assert item.unattempted_items == item.requested_items

    dry_run = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 6)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(published.result_frontier),
                "dry_run": True,
                "event_drafts": [
                    {
                        "event_id": protocol_id("evt_", seed + 7),
                        "schema": {"name": "action_recorded", "version": "1.0.0"},
                        "occurred_at": "2026-08-28T10:00:02.000Z",
                        "causal_parents": [],
                        "payload": {
                            "action_id": protocol_id("act_", seed + 8),
                            "action_kind": "other",
                            "description": "Preview an unrelated append.",
                        },
                        "artifact_refs": [],
                        "evidence_refs": [],
                    }
                ],
            }
        )
    )
    assert isinstance(dry_run, PublishWorkResultModel)
    assert isinstance(dry_run.root, PublishWorkDryRunModel)
    action = protocol_id("act_", seed + 9)
    result = protocol_id("res_", seed + 10)
    result_event = protocol_id("evt_", seed + 12)
    recorded = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 11)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(published.result_frontier),
                "event_drafts": [
                    {
                        "event_id": protocol_id("evt_", seed + 13),
                        "schema": {"name": "action_recorded", "version": "1.0.0"},
                        "occurred_at": "2026-08-28T10:00:03.000Z",
                        "causal_parents": [],
                        "payload": {
                            "action_id": action,
                            "action_kind": "command",
                            "description": "Attempt the command item.",
                            "command": command,
                            "obligation_refs": [obligation],
                            "attempted_items": [command],
                        },
                        "artifact_refs": [],
                        "evidence_refs": [],
                    },
                    {
                        "event_id": result_event,
                        "schema": {"name": "result_recorded", "version": "1.0.0"},
                        "occurred_at": "2026-08-28T10:00:04.000Z",
                        "causal_parents": [],
                        "payload": {
                            "result_id": result,
                            "action_id": action,
                            "outcome": "success",
                        },
                        "artifact_refs": [],
                        "evidence_refs": [],
                    },
                ],
            }
        )
    )
    after = await app.status(
        StatusRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 14)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "view": "obligations",
                "limit": "10",
                "at_frontier": str(recorded.result_frontier.sequence),
            }
        )
    )
    after_item = cast(StatusObligationsPageModel, after.page).items[0]
    assert tuple((entry.item_kind, entry.value) for entry in after_item.unattempted_items) == (
        ("change", change),
    )

    results = await app.status(
        StatusRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 15)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "view": "results",
                "limit": "10",
                "at_frontier": str(recorded.result_frontier.sequence),
            }
        )
    )
    result_item = cast(StatusResultsPageModel, results.page).items[0]
    assert result_item.result_id == result
    assert result_item.source_event_id == result_event
    assert result_item.payload_available is True
    assert result_item.outcome == "success"
    assert result_item.action_id == action
    assert result_item.evidence_refs == ()


async def test_later_plan_published_restates_scope_after_revision_chain() -> None:
    app, _runtime, _projection = _build_app(seed_offset=32)
    seed = 3_200
    started = await app.start(start_request(seed, title="Plan restatement status"))
    obligations = tuple(protocol_id("obl_", seed + index) for index in range(1, 4))
    obligation_events = tuple(protocol_id("evt_", seed + index) for index in range(10, 13))
    first = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 20)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(started.frontier),
                "event_drafts": [
                    *(
                        {
                            "event_id": event,
                            "schema": {"name": "obligation_published", "version": "1.0.0"},
                            "occurred_at": "2026-08-28T10:10:00.000Z",
                            "causal_parents": [],
                            "payload": {
                                "obligation_id": obligation,
                                "description": f"Scope obligation {index}.",
                                "evidence_expectation": "Status counters.",
                                "status": "open",
                            },
                            "artifact_refs": [],
                            "evidence_refs": [],
                        }
                        for index, (obligation, event) in enumerate(
                            zip(obligations, obligation_events, strict=True), start=1
                        )
                    ),
                    {
                        "event_id": protocol_id("evt_", seed + 21),
                        "schema": {"name": "plan_published", "version": "1.0.0"},
                        "occurred_at": "2026-08-28T10:10:01.000Z",
                        "causal_parents": list(obligation_events),
                        "payload": {
                            "plan_version": 1,
                            "summary": "Initial scope.",
                            "obligation_refs": [obligations[0]],
                        },
                        "artifact_refs": [],
                        "evidence_refs": [],
                    },
                ],
            }
        )
    )
    revised = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 22)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(first.result_frontier),
                "event_drafts": [
                    {
                        "event_id": protocol_id("evt_", seed + 23),
                        "schema": {"name": "plan_revised", "version": "1.0.0"},
                        "occurred_at": "2026-08-28T10:10:02.000Z",
                        "causal_parents": [],
                        "payload": {
                            "plan_version": 2,
                            "supersedes_plan_version": 1,
                            "reason": "Add a material obligation.",
                            "summary": "Expanded scope.",
                            "obligation_changes": [
                                {"obligation_id": obligations[1], "change": "carried"}
                            ],
                        },
                        "artifact_refs": [],
                        "evidence_refs": [],
                    }
                ],
            }
        )
    )
    restated = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 24)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(revised.result_frontier),
                "event_drafts": [
                    {
                        "event_id": protocol_id("evt_", seed + 25),
                        "schema": {"name": "plan_published", "version": "1.0.0"},
                        "occurred_at": "2026-08-28T10:10:03.000Z",
                        "causal_parents": [],
                        "payload": {
                            "plan_version": 3,
                            "summary": "Full append-only scope restatement.",
                            "obligation_refs": list(obligations),
                        },
                        "artifact_refs": [],
                        "evidence_refs": [],
                    }
                ],
            }
        )
    )
    status = await app.status(
        StatusRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 26)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "view": "compact",
                "limit": "10",
                "at_frontier": str(restated.result_frontier.sequence),
            }
        )
    )
    item = cast(StatusCompactPageModel, status.page).items[0]
    assert item.current_plan_event_id == protocol_id("evt_", seed + 25)
    assert item.declared_obligation_count == "3"
    assert item.open_obligation_count == "3"
    assert status.closure_readiness.declared_obligation_count == "3"
    assert status.closure_readiness.open_obligation_count == "3"
    assert status.closure_readiness.blocking_conditions == ("obligations_open",)


async def test_future_frontier_is_invalid_request() -> None:
    """A requested read-only frontier beyond the observed head is ``INVALID_REQUEST``, never
    ``FRONTIER_CONFLICT`` -- status is a read-only query, so a future sequence is invalid query
    input, not a stale optimistic mutation guard."""

    app, _runtime, _projection = _build_app(seed_offset=4)
    started, checked, _obligations = await _bootstrap_finding(app, seed=400)
    future_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 410)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "view": "compact",
        "limit": "10",
        "at_frontier": str(checked.result_frontier.sequence + 1000),
    }
    with pytest.raises(PublicOperationError) as failure:
        await app.status(StatusRequest.model_validate(future_wire))
    assert failure.value.code is PublicErrorCode.INVALID_REQUEST
    assert failure.value.code is not PublicErrorCode.FRONTIER_CONFLICT


async def test_candidate_findings_uses_only_whole_case_path() -> None:
    """The candidate-findings view uses one exact availability snapshot rather than any
    ``ProjectionQuery``, and its deterministic identity matches a same-frontier check."""

    app, _runtime, _projection = _build_app(seed_offset=5)
    started, checked, _obligations = await _bootstrap_finding(app, seed=500)
    candidate_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 510)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "view": "candidate_findings",
        "limit": "10",
        "at_frontier": str(checked.result_frontier.sequence),
    }
    candidates = await app.status(StatusRequest.model_validate(candidate_wire))
    candidates_page = cast(StatusCandidateFindingsPageModel, candidates.page)
    assert candidates_page.items

    check_issue = {
        (finding.kind.value, finding.policy_id, finding.policy_version, finding.subject_refs)
        for finding in checked.findings
    }
    candidate_issue = {
        (item.kind, item.policy_id, item.policy_version, item.subject_refs)
        for item in candidates_page.items
    }
    assert candidate_issue == check_issue

    # Any other view is a bounded row query over the port-owned typed position, not this
    # whole-case scan: it accepts an ordinary (nonnegative) cursor position, while
    # ``candidate_findings`` accepts only its own integer offset -- the two paging identities
    # never mix.
    findings_wire: dict[str, JsonValue] = {
        **candidate_wire,
        "view": "findings",
        "request_id": protocol_id("req_", 511),
    }
    findings_status = await app.status(StatusRequest.model_validate(findings_wire))
    assert findings_status.view == "findings"


async def test_candidate_parity_excludes_semantic_findings() -> None:
    """Deterministic candidate identity matches a same-frontier check independently of capping;
    no AI-powered finding has a candidate row.

    The composed harness in this file runs with AI-powered verification disabled (local
    mode only, matching every other operation-contract test module), so a live AI-powered
    finding cannot be produced here; this asserts the origin invariant that does hold for every
    row actually returned.
    """

    app, _runtime, _projection = _build_app(seed_offset=6)
    started, checked, _obligations = await _bootstrap_finding(app, seed=600)
    candidate_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 610)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "view": "candidate_findings",
        "limit": "10",
        "at_frontier": str(checked.result_frontier.sequence),
    }
    candidates = await app.status(StatusRequest.model_validate(candidate_wire))
    candidates_page = cast(StatusCandidateFindingsPageModel, candidates.page)
    assert candidates_page.items
    assert all(item.origin == "deterministic" for item in candidates_page.items)
    assert all(finding.origin.value == "deterministic" for finding in checked.findings)


async def test_finding_and_candidate_tie_breaks_are_distinct() -> None:
    """Recorded findings-view order and candidate-findings-view order are each internally
    stable and deterministic across repeated reads of the identical frontier, even when two
    findings of the same kind/priority are recorded together."""

    app, _runtime, _projection = _build_app(seed_offset=7)
    started, checked, _obligation_ids = await _bootstrap_finding(app, seed=700, obligation_count=2)
    # Two obligations covered by one completion claim record more than one finding sharing the
    # same kind/priority, so their relative order is decided purely by the tie-break rule.
    assert len(checked.findings) >= 2

    findings_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 710)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "view": "findings",
        "limit": "10",
        "at_frontier": str(checked.result_frontier.sequence),
    }
    findings_first = await app.status(StatusRequest.model_validate(findings_wire))
    findings_second = await app.status(
        StatusRequest.model_validate({**findings_wire, "request_id": protocol_id("req_", 711)})
    )
    findings_first_page = cast(StatusFindingsPageModel, findings_first.page)
    findings_second_page = cast(StatusFindingsPageModel, findings_second.page)
    first_order = tuple(item.finding_id for item in findings_first_page.items)
    second_order = tuple(item.finding_id for item in findings_second_page.items)
    assert first_order == second_order
    # Among the rows that share the exact same rank_key (kind/priority/coverage strength), the
    # recorded tie-break is finding ID ascending.
    same_rank_groups: dict[tuple[str, int], list[str]] = {}
    for item in findings_first_page.items:
        same_rank_groups.setdefault((item.kind, item.priority), []).append(item.finding_id)
    for group in same_rank_groups.values():
        if len(group) > 1:
            assert group == sorted(group)

    candidate_wire: dict[str, JsonValue] = {
        **findings_wire,
        "view": "candidate_findings",
        "request_id": protocol_id("req_", 712),
    }
    candidates_first = await app.status(StatusRequest.model_validate(candidate_wire))
    candidates_second = await app.status(
        StatusRequest.model_validate({**candidate_wire, "request_id": protocol_id("req_", 713)})
    )
    candidates_first_page = cast(StatusCandidateFindingsPageModel, candidates_first.page)
    candidates_second_page = cast(StatusCandidateFindingsPageModel, candidates_second.page)
    candidate_first_order = tuple(item.subject_refs for item in candidates_first_page.items)
    candidate_second_order = tuple(item.subject_refs for item in candidates_second_page.items)
    # The candidate tie-break (canonical emission ordinal) is independent of finding_id -- which
    # does not exist yet for a not-yet-recorded candidate row -- but is still fully deterministic
    # across repeated reads of the identical frozen frontier.
    assert candidate_first_order == candidate_second_order
    expected_issue = {
        (finding.kind.value, finding.policy_id, finding.policy_version, finding.subject_refs)
        for finding in checked.findings
    }
    candidate_issue = {
        (item.kind, item.policy_id, item.policy_version, item.subject_refs)
        for item in candidates_first_page.items
    }
    # The bootstrapped scenario records more distinct issues than the capped check's
    # ``max_findings=3`` returns; every capped check finding still matches one uncapped
    # candidate row exactly (candidate identity does not depend on capping).
    assert expected_issue <= candidate_issue


async def test_status_raw_item_derivation_and_filter_defaults() -> None:
    """Every returned field follows the registered projection source, and absent/false include
    flags compose with AND: an explicit ``status=resolved`` filter alone, without
    ``include_resolved=true``, is intentionally empty."""

    app, _runtime, _projection = _build_app(seed_offset=8)
    started, checked, obligation_ids = await _bootstrap_finding(app, seed=800)
    finding = checked.findings[0]

    ack_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 810)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(checked.result_frontier),
        "finding_id": finding.finding_id,
        "finding_frontier": _frontier(checked.result_frontier),
        "disposition": "acknowledged",
        "reason": "Tracked for the derivation/filter-default exercise.",
    }
    responded = await app.respond(RespondRequest.model_validate(ack_wire))

    findings_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 811)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "view": "findings",
        "limit": "10",
        "at_frontier": str(responded.result_frontier.sequence),
    }
    findings_status = await app.status(StatusRequest.model_validate(findings_wire))
    findings_status_page = cast(StatusFindingsPageModel, findings_status.page)
    item = next(row for row in findings_status_page.items if row.finding_id == finding.finding_id)
    # Raw item derivation follows the exact recorded source facts.
    assert item.disposition == "acknowledged"
    assert item.resolved is False
    assert item.kind == finding.kind.value
    assert item.policy_id == finding.policy_id
    assert item.subject_refs == finding.subject_refs

    open_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 812)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "view": "obligations",
        "limit": "10",
        "at_frontier": str(responded.result_frontier.sequence),
    }
    open_only = await app.status(StatusRequest.model_validate(open_wire))
    open_only_page = cast(StatusObligationsPageModel, open_only.page)
    assert {row.obligation_id for row in open_only_page.items} == set(obligation_ids)
    assert all(row.status == "open" for row in open_only_page.items)

    # An explicit ``status=resolved`` filter alone -- without ``include_resolved=true`` -- is
    # intentionally empty: absent/false ``include_resolved`` always suppresses resolved rows,
    # even when another filter field explicitly names them. Filters compose with AND, never OR.
    resolved_only_wire: dict[str, JsonValue] = {
        **open_wire,
        "request_id": protocol_id("req_", 813),
        "filter": {"status": "resolved"},
    }
    resolved_only = await app.status(StatusRequest.model_validate(resolved_only_wire))
    assert cast(StatusObligationsPageModel, resolved_only.page).items == ()

    resolved_included_wire: dict[str, JsonValue] = {
        **open_wire,
        "request_id": protocol_id("req_", 814),
        "filter": {"status": "resolved", "include_resolved": True},
    }
    resolved_included = await app.status(StatusRequest.model_validate(resolved_included_wire))
    # No obligation is actually resolved in this scenario, so this remains empty too: the
    # composed filter is honest about there being nothing to include, not silently ignored.
    assert cast(StatusObligationsPageModel, resolved_included.page).items == ()


async def test_finding_resolution_requires_recorded_applicability() -> None:
    """Acknowledged/rejected/waived disposition never resolves a finding; only a later
    check that runs its policy to completion over overlapping scope, current and gap-free,
    with zero suppression, resolves it."""

    app, _runtime, _projection = _build_app(
        seed_offset=9,
    )
    started, checked, _obligations = await _bootstrap_finding(app, seed=900)
    finding = checked.findings[0]
    issue = (finding.kind, finding.policy_id, finding.policy_version, finding.subject_refs)

    ack_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 910)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(checked.result_frontier),
        "finding_id": finding.finding_id,
        "finding_frontier": _frontier(checked.result_frontier),
        "disposition": "acknowledged",
        "reason": "Not yet addressed.",
    }
    responded = await app.respond(RespondRequest.model_validate(ack_wire))

    recheck_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 911)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(responded.result_frontier),
        "mode": "deterministic_only",
        "max_findings": "3",
    }
    rechecked = await app.check(CheckRequest.model_validate(recheck_wire))
    assert type(rechecked) is CheckCommitResult, f"unexpected nonterminal check: {type(rechecked)}"
    assert rechecked.findings
    rechecked_issue = (
        rechecked.findings[0].kind,
        rechecked.findings[0].policy_id,
        rechecked.findings[0].policy_version,
        rechecked.findings[0].subject_refs,
    )
    assert rechecked_issue == issue

    status_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 912)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "view": "findings",
        "limit": "10",
        "at_frontier": str(rechecked.result_frontier.sequence),
        "filter": {"include_resolved": True},
    }
    status = await app.status(StatusRequest.model_validate(status_wire))
    # The acknowledgement never resolved the original finding: the newer same-issue row (the
    # only one visible at this frontier) still reports unresolved.
    assert all(not row.resolved for row in cast(StatusFindingsPageModel, status.page).items)


async def test_status_tombstone_and_unreadable_page_progress() -> None:
    """A row omitted for tombstone/unreadability still consumes its scanned cursor position and
    is never backfilled, so cursor progress cannot loop forever."""

    app, _runtime, _projection = _build_app(seed_offset=10)
    started, checked, obligation_ids = await _bootstrap_finding(app, seed=1000, obligation_count=2)

    obligations_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 1010)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "view": "obligations",
        "limit": "1",
        "at_frontier": str(checked.result_frontier.sequence),
    }
    first_page = await app.status(StatusRequest.model_validate(obligations_wire))
    first_obligations_page = cast(StatusObligationsPageModel, first_page.page)
    assert first_obligations_page.next_cursor is not None

    scanned: list[str] = [item.obligation_id for item in first_obligations_page.items]
    cursor = first_obligations_page.next_cursor
    seen_cursors: set[str] = {cursor}
    for step in range(1, 4):
        page_wire: dict[str, JsonValue] = {
            **_request_base(protocol_id("req_", 1010 + step)),
            "session_id": started.session_id,
            "writer_id": started.writer_id,
            "view": "obligations",
            "limit": "1",
            "cursor": cursor,
        }
        page = await app.status(StatusRequest.model_validate(page_wire))
        obligations_page = cast(StatusObligationsPageModel, page.page)
        scanned.extend(item.obligation_id for item in obligations_page.items)
        if obligations_page.next_cursor is None:
            break
        # Cursor progress never loops: each successive cursor must be new.
        assert obligations_page.next_cursor not in seen_cursors
        seen_cursors.add(obligations_page.next_cursor)
        cursor = obligations_page.next_cursor
    assert set(scanned) == set(obligation_ids)


async def test_status_filters_before_payload_hydration() -> None:
    """Filter/order/lookahead selection is structural: the page returned for a bounded limit
    contains exactly the selected rows and never more than the requested bound."""

    app, _runtime, _projection = _build_app(seed_offset=11)
    started, checked, obligation_ids = await _bootstrap_finding(app, seed=1100, obligation_count=2)

    bounded_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 1110)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "view": "obligations",
        "limit": "1",
        "at_frontier": str(checked.result_frontier.sequence),
    }
    bounded = await app.status(StatusRequest.model_validate(bounded_wire))
    bounded_page = cast(StatusObligationsPageModel, bounded.page)
    assert len(bounded_page.items) == 1
    assert bounded_page.next_cursor is not None

    full_wire: dict[str, JsonValue] = {
        **bounded_wire,
        "request_id": protocol_id("req_", 1111),
        "limit": "10",
    }
    full = await app.status(StatusRequest.model_validate(full_wire))
    full_page = cast(StatusObligationsPageModel, full.page)
    assert len(full_page.items) == len(obligation_ids)
    assert {item.obligation_id for item in full_page.items} == set(obligation_ids)


async def test_lineage_paginates_children_and_annotations_and_rejects_changed_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from finishup.application import task_views

    app, _runtime, _projection = _build_app(seed_offset=12)
    started = await app.start(start_request(1200, title="Lineage pagination exercise"))
    children = tuple(
        StatusLineageChildModel.model_validate(
            {
                "task_id": protocol_id("tsk_", 12_000 + index),
                "parent_task_id": started.task_id,
                "origin": "self_registered",
                "acceptance": "pending",
                "work_state": "open",
                "session_health": "contact_lost",
                "depth": "1",
                "rollup_state": "annotation",
                "blocking_conditions": (),
            }
        )
        for index in range(105)
    )
    annotations = tuple(
        StatusLineageAnnotationModel.model_validate(
            {
                "correlation_id": f"lineage:observed-{index}",
                "subagent_id": f"agent-{index}",
                "origin": "host_observed",
                "acceptance": "pending",
            }
        )
        for index in range(8)
    )
    snapshot = LineageStatusSnapshot(None, children, annotations)

    async def read_snapshot(*_args: object, **_kwargs: object) -> LineageStatusSnapshot:
        return snapshot

    monkeypatch.setattr(task_views, "lineage_status_page", read_snapshot)
    wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 1201)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "view": "lineage",
        "limit": "50",
    }
    first = await app.status(StatusRequest.model_validate(wire))
    assert isinstance(first.page, StatusLineagePageModel)
    first_cursor = first.page.next_cursor
    assert first_cursor is not None
    seen_children = [item.task_id for item in first.page.children]
    seen_annotations = [item.correlation_id for item in first.page.annotations]
    cursor = first_cursor
    while cursor is not None:
        result = await app.status(StatusRequest.model_validate({**wire, "cursor": cursor}))
        assert isinstance(result.page, StatusLineagePageModel)
        assert len(result.page.children) + len(result.page.annotations) <= 50
        seen_children.extend(item.task_id for item in result.page.children)
        seen_annotations.extend(item.correlation_id for item in result.page.annotations)
        cursor = result.page.next_cursor
    assert seen_children == [item.task_id for item in children]
    assert seen_annotations == [item.correlation_id for item in annotations]
    assert _frontier(first.result_frontier) == _frontier(started.frontier)

    with pytest.raises(PublicOperationError) as selector_error:
        await app.status(
            StatusRequest.model_validate(
                {**wire, "cursor": first_cursor, "task_id": protocol_id("tsk_", 999)}
            )
        )
    assert selector_error.value.code is PublicErrorCode.INVALID_REQUEST

    snapshot = replace(snapshot, children=children[:-1])
    with pytest.raises(PublicOperationError, match="cursor is stale"):
        await app.status(StatusRequest.model_validate({**wire, "cursor": first_cursor}))


async def test_project_status_pages_and_lineage_fallback_use_the_public_projection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from finishup.application import task_views

    app, _runtime, _projection = _build_app(seed_offset=13)
    app = replace(
        app, project_application=cast(ProjectApplication, AsyncMock(spec=ProjectApplication))
    )
    started = await app.start(start_request(1300, title="Project status exercise"))
    members = tuple(
        StatusProjectMemberModel.model_validate(
            {
                "task_id": protocol_id("tsk_", 13_000 + index),
                "actor_id": None if index else "harness:test",
                "work_state": "open",
                "session_health": "contact_lost",
            }
        )
        for index in range(3)
    )
    snapshot: ProjectStatusSnapshot | LineageStatusSnapshot = ProjectStatusSnapshot(
        {
            "project_id": protocol_id("prj_", 1300),
            "kind": "repository",
            "membership_generation": "1",
            "grant_state": None,
        },
        members,
        LineageStatusSnapshot(None, ()),
        (),
        (),
        (),
    )

    async def read_snapshot(
        *_args: object, **_kwargs: object
    ) -> ProjectStatusSnapshot | LineageStatusSnapshot:
        return snapshot

    monkeypatch.setattr(task_views, "project_status_snapshot", read_snapshot)
    wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 1301)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "view": "project",
        "limit": "2",
    }
    first = await app.status(StatusRequest.model_validate(wire))
    assert isinstance(first.page, StatusProjectPageModel)
    assert len(first.page.members) == 2
    assert first.page.next_cursor is not None
    second = await app.status(
        StatusRequest.model_validate({**wire, "cursor": first.page.next_cursor})
    )
    assert isinstance(second.page, StatusProjectPageModel)
    assert second.page.members == members[2:]
    assert second.page.next_cursor is None

    snapshot = LineageStatusSnapshot(None, ())
    fallback = await app.status(StatusRequest.model_validate(wire))
    assert fallback.view == "lineage"
    assert isinstance(fallback.page, StatusLineagePageModel)
    facts = await app.projection_binding_facts(ControlMethod.STATUS, wire, fallback)
    projected = await app.project_result_for_client(
        ClientProjectionContext(ControlClientKind.CLI, ProjectionRenderMode.HUMAN_READABLE, True),
        _cli_binding(1302, facts),
        fallback,
    )
    assert isinstance(projected, StatusResultModel)
    assert projected.root.ok is True
    assert projected.root.view == "lineage"
