"""Public respond contract: cross-surface result parity, waiver scope/expiry preservation, and
consistent error mapping.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
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
from yoetz.application.start import StartInternalResult
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
from yoetz.ports.control import ControlClientKind, ControlMethod
from yoetz.ports.diagnostics import RuntimeCapability
from yoetz.ports.importer import ImporterPort, ImportStatusSnapshot
from yoetz.ports.ledger import CheckCommitResult
from yoetz.ports.publish_response_catalog import PublishResponseCatalogPort
from yoetz.ports.runtime import BundleRuntimePort, RouteCommand, TaskRuntime
from yoetz.protocol.canonical import JsonValue, canonical_encode
from yoetz.protocol.errors import PublicErrorCode, PublicOperationError
from yoetz.protocol.models import (
    CheckRequest,
    FrontierModel,
    PublishWorkRequest,
    RespondRequest,
    RespondResultModel,
)

pytestmark = pytest.mark.anyio

_DIGEST = "sha256:" + "7" * 64
_WORKSPACE = "hmac-sha256:" + "8" * 64
_POLICY_PACKS = ("research-evidence/0.2.0", "work-integrity/0.3.0")


class _IdleImporter:
    async def status(self, session: str) -> ImportStatusSnapshot:
        return ImportStatusSnapshot(session_id(session), 0, 0, (), ())


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
        proposal_id = protocol_id("ppr_", 2900 + len(self.candidates))
        policy = ReceiptPolicyBinding(
            protocol_id("pvy_", 2950 + len(self.candidates)), 1, _DIGEST, _DIGEST
        )
        receipt = LocalDisclosureReceipt(
            "1.0.0",
            protocol_id("egr_", 2960 + len(self.candidates)),
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


def _scope(_binding: object, source: Mapping[str, JsonValue]) -> AuthorizationScope:
    return AuthorizationScope(
        AuthorizationScopeKind.TASK,
        protocol_id("ins_", 2999),
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


def _request_base(
    request_id: str, *, actor_type: str = "harness", integration: str = "local_cli"
) -> dict[str, JsonValue]:
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": request_id,
        "actor": _actor(actor_type),
        "client": _client(integration),
    }


def _frontier(value: Frontier | FrontierModel) -> JsonValue:
    if isinstance(value, Frontier):
        return cast(JsonValue, dict(value.as_wire().items()))
    return cast(JsonValue, value.model_dump(mode="json"))


def _build_app(
    *, seed_offset: int = 0, waiver_authorizer: Callable[[RespondRequest], bool] | None = None
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
        status_cursor_key=(b"respond-contract-cursor-key-" + str(seed_offset).encode() * 4)[:32],
        waiver_policy_digest=_DIGEST,
        semantic_evaluator=_semantic_disabled,
        disclosure_scope_for=_scope,
        receipt_version_resolver=lambda _: _versions(),
        waiver_authorizer=(lambda _: True) if waiver_authorizer is None else waiver_authorizer,
        import_publication_authorizer=lambda _: False,
        profile=RuntimeProfile.TEST_FAKE,
        policy_packs=_POLICY_PACKS,
        version_manifest=start_app.version_manifest,
        enforce_repository_identity=False,
    )
    return app, runtime, projection


async def _bootstrap_finding(
    app: Application, *, seed: int
) -> tuple[StartInternalResult, CheckCommitResult, str]:
    """Publish one open obligation plus an unsupported completion claim, then check.

    Mirrors the exact scenario already proven in ``test_full_workflow.py`` to yield one
    actionable ``completion_with_open_obligations`` finding.
    """

    started = await app.start(start_request(seed, title="Respond contract exercise"))
    obligation_id = protocol_id("obl_", seed + 1)
    obligation_event_id = protocol_id("evt_", seed + 2)
    publish_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", seed + 3)),
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
                    "description": "Publish a result for the respond contract exercise.",
                    "acceptance_criteria": "A result is recorded in the task ledger.",
                    "evidence_expectation": "A linked immutable result record.",
                    "status": "open",
                },
                "artifact_refs": (),
                "evidence_refs": (),
            },
            {
                "event_id": protocol_id("evt_", seed + 4),
                "schema": {"name": "claim_recorded", "version": "1.0.0"},
                "occurred_at": "2026-07-19T12:00:01.000Z",
                "causal_parents": (obligation_event_id,),
                "payload": {
                    "claim_id": protocol_id("clm_", seed + 5),
                    "claim_kind": "completion",
                    "statement": "The exercise is complete.",
                    "supporting_refs": (obligation_id,),
                    "obligation_refs": (obligation_id,),
                },
                "artifact_refs": (),
                "evidence_refs": (),
            },
        ),
    }
    published = await app.publish_work(PublishWorkRequest.model_validate(publish_wire))
    check_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", seed + 6)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(published.result_frontier),
        "mode": "deterministic_only",
        "max_findings": "3",
    }
    checked = await app.check(CheckRequest.model_validate(check_wire))
    assert type(checked) is CheckCommitResult, f"unexpected nonterminal check: {type(checked)}"
    assert checked.findings, "the seeded scenario must always yield one actionable finding"
    return started, checked, obligation_id


def _cli_binding(rpc_seed: int, facts: object) -> ControlProjectionBinding:
    rpc_id = protocol_id("rpc_", rpc_seed)
    service_instance_id = protocol_id("svc_", rpc_seed + 1)
    return ControlProjectionBinding(
        rpc_id,
        ControlMethod.RESPOND,
        service_instance_id,
        1,
        cast(str | None, getattr(facts, "original_request_id", None)),
        cast(str | None, getattr(facts, "route_identity_digest", None)),
        canonical_encode(
            {
                "rpc_id": rpc_id,
                "method": "respond",
                "service_instance_id": service_instance_id,
                "service_generation": "1",
            }
        ),
    )


@pytest.mark.parametrize("disposition", ("acknowledged", "provenance_disputed"))
async def test_respond_request_result_parity(disposition: str) -> None:
    """The same finding response, projected for CLI and MCP-bridge surfaces, carries the same
    public response fields everywhere; only the trusted per-surface disclosure sink differs."""

    app, _runtime, projection = _build_app(seed_offset=1)
    started, checked, _obligation = await _bootstrap_finding(app, seed=100)
    finding = checked.findings[0]
    response_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 110)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(checked.result_frontier),
        "finding_id": finding.finding_id,
        "finding_frontier": _frontier(checked.result_frontier),
        "disposition": disposition,
        "reason": "Addressed by follow-up work already tracked elsewhere.",
    }
    responded = await app.respond(RespondRequest.model_validate(response_wire))
    facts = await app.projection_binding_facts(ControlMethod.RESPOND, response_wire, responded)

    cli_context = ClientProjectionContext(
        ControlClientKind.CLI, ProjectionRenderMode.HUMAN_READABLE, True
    )
    mcp_context = ClientProjectionContext(
        ControlClientKind.MCP_BRIDGE, ProjectionRenderMode.MACHINE_READABLE, False
    )
    cli_projected = await app.project_result_for_client(
        cli_context, _cli_binding(111, facts), responded
    )
    mcp_projected = await app.project_result_for_client(
        mcp_context, _cli_binding(113, facts), responded
    )
    assert isinstance(cli_projected, RespondResultModel)
    assert isinstance(mcp_projected, RespondResultModel)
    assert cli_projected.root.ok is True
    assert mcp_projected.root.ok is True

    cli_body = cli_projected.root.model_dump(mode="json", exclude={"privacy_projection"})
    mcp_body = mcp_projected.root.model_dump(mode="json", exclude={"privacy_projection"})
    assert cli_body == mcp_body
    assert cli_projected.root.response.disposition == disposition
    assert cli_projected.root.privacy_projection.sink == "local_human_view"
    assert mcp_projected.root.privacy_projection.sink == "agent_context"
    assert len(projection.candidates) == 2


async def test_waiver_scope_and_expiry_parity() -> None:
    """Waiver scope and expiry are preserved exactly and identically across CLI and MCP-bridge
    surface projections of the same response."""

    app, _runtime, _projection = _build_app(seed_offset=2, waiver_authorizer=lambda _: True)
    started, checked, _obligation = await _bootstrap_finding(app, seed=200)
    finding = checked.findings[0]
    waive_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 210), actor_type="human"),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(checked.result_frontier),
        "finding_id": finding.finding_id,
        "finding_frontier": _frontier(checked.result_frontier),
        "disposition": "waived",
        "reason": "Waived pending an unrelated release freeze.",
        "waiver_scope": "finding_only",
        "waiver_expiry": "2030-01-01T00:00:00.000Z",
    }
    waived = await app.respond(RespondRequest.model_validate(waive_wire))
    assert waived.response.waiver_scope == "finding_only"
    assert waived.response.waiver_expiry == "2030-01-01T00:00:00.000Z"

    facts = await app.projection_binding_facts(ControlMethod.RESPOND, waive_wire, waived)
    cli_context = ClientProjectionContext(
        ControlClientKind.CLI, ProjectionRenderMode.HUMAN_READABLE, True
    )
    mcp_context = ClientProjectionContext(
        ControlClientKind.MCP_BRIDGE, ProjectionRenderMode.MACHINE_READABLE, False
    )
    cli_projected = await app.project_result_for_client(
        cli_context, _cli_binding(220, facts), waived
    )
    mcp_projected = await app.project_result_for_client(
        mcp_context, _cli_binding(222, facts), waived
    )
    assert isinstance(cli_projected, RespondResultModel)
    assert isinstance(mcp_projected, RespondResultModel)
    assert cli_projected.root.ok is True
    assert mcp_projected.root.ok is True

    assert cli_projected.root.response.waiver_scope == "finding_only"
    assert mcp_projected.root.response.waiver_scope == "finding_only"
    assert cli_projected.root.response.waiver_expiry == "2030-01-01T00:00:00.000Z"
    assert mcp_projected.root.response.waiver_expiry == "2030-01-01T00:00:00.000Z"
    # No surface may narrow or broaden the recorded waiver: scope is the sole v0.1 vocabulary
    # member (``finding_only``) and expiry is the exact supplied timestamp on both surfaces.
    assert cli_projected.root.response.waiver_scope == mcp_projected.root.response.waiver_scope
    assert cli_projected.root.response.waiver_expiry == mcp_projected.root.response.waiver_expiry


async def test_response_error_parity() -> None:
    """Invalid or stale responses fail identically no matter which surface's request tag
    (``client.integration``) submitted them."""

    # An unauthorized waiver fails as INVALID_REQUEST from every non-human/non-local_cli surface
    # tag, and identically from a local_cli surface with waiver authorization explicitly denied.
    denied_app, _denied_runtime, _p1 = _build_app(seed_offset=3, waiver_authorizer=lambda _: False)
    started, checked, _obligation = await _bootstrap_finding(denied_app, seed=300)
    finding = checked.findings[0]

    codes: list[PublicErrorCode] = []
    for integration, actor_type in (
        ("local_cli", "logical_agent"),
        ("cooperative_mcp", "human"),
    ):
        wire: dict[str, JsonValue] = {
            **_request_base(
                protocol_id("req_", 310 + len(codes)),
                actor_type=actor_type,
                integration=integration,
            ),
            "session_id": started.session_id,
            "writer_id": started.writer_id,
            "expected_frontier": _frontier(checked.result_frontier),
            "finding_id": finding.finding_id,
            "finding_frontier": _frontier(checked.result_frontier),
            "disposition": "waived",
            "reason": "An unauthorized surface attempts to waive.",
            "waiver_scope": "finding_only",
        }
        with pytest.raises(PublicOperationError) as failure:
            await denied_app.respond(RespondRequest.model_validate(wire))
        codes.append(failure.value.code)
    assert codes == [PublicErrorCode.INVALID_REQUEST, PublicErrorCode.INVALID_REQUEST]

    # A response naming a finding that is unavailable at the supplied finding_frontier fails
    # identically as INVALID_REQUEST regardless of which surface tag submitted it.
    stale_codes: list[PublicErrorCode] = []
    for integration in ("local_cli", "cooperative_mcp"):
        stale_wire: dict[str, JsonValue] = {
            **_request_base(protocol_id("req_", 320 + len(stale_codes)), integration=integration),
            "session_id": started.session_id,
            "writer_id": started.writer_id,
            "expected_frontier": _frontier(checked.result_frontier),
            "finding_id": "fnd_00000000-0000-4000-8000-0000000000ff",
            "finding_frontier": _frontier(checked.result_frontier),
            "disposition": "acknowledged",
        }
        with pytest.raises(PublicOperationError) as stale_failure:
            await denied_app.respond(RespondRequest.model_validate(stale_wire))
        stale_codes.append(stale_failure.value.code)
    assert stale_codes == [PublicErrorCode.INVALID_REQUEST, PublicErrorCode.INVALID_REQUEST]
