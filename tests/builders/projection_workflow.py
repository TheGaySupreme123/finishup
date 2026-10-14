"""One realistic workflow that yields an internal result for every public control method.

Result-model projection defects have now escaped three times in a row — a phantom null on every
accepted event (PR #50), then nested findings the strict closed models could not accept at all.
Each fix landed against one operation while the class stayed alive in the others, because nothing
walked the whole public surface at once.

This builder is that missing seam. It runs a single provider-free workflow through the real ready
composition — real vault objects, the real privacy coordinator seeded with the shipped default
policy, the real closed-model validation the daemon runs for an MCP bridge client — and hands back
the internal result of ``start``, ``publish_work``, ``check``, ``respond``, ``status`` (every view)
and ``receipt``, each paired with the request body its projection binding is derived from.

Callers assert whatever property they are sweeping for; the builder only guarantees that the
material is realistic and that every nested collection the public models declare is actually
populated. Add a new operation or a new view here and every sweep built on it picks it up.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, cast

import yoetz.service.ready_composition as ready_composition
from builders.ledger_adapters import MemoryObjects, ownership_fence
from builders.review_manifests import provider_bound_manifest
from builders.start_application import (
    MemoryStartRuntime,
    StartTestLookup,
    protocol_id,
    start_composition,
    start_request,
)
from yoetz.adapters.memory.privacy import (
    MemoryPrivacyAudit,
    MemoryPrivacyCatalogState,
    MemoryPrivacyPolicyStore,
)
from yoetz.application.check import FinalSemanticEvaluation
from yoetz.application.egress import PrivacyCoordinator
from yoetz.application.publish_work import PublishWorkInternalResult
from yoetz.application.service import (
    Application,
    ClientProjectionContext,
    ControlProjectionBinding,
    ProjectionRenderMode,
    UnprojectedControlBody,
    VerificationPolicy,
)
from yoetz.domain.events import RuntimeProfile
from yoetz.domain.findings import SemanticDispatchKind, SemanticProvenance
from yoetz.domain.privacy import (
    AuthorizationScope,
    AuthorizationScopeKind,
    PrivacyPolicy,
)
from yoetz.domain.receipts import (
    PolicyVersionEntry,
    ReceiptVersionSlice,
    SchemaVersionEntry,
)
from yoetz.domain.values import Frontier
from yoetz.ports.control import ControlClientKind, ControlMethod
from yoetz.ports.diagnostics import RuntimeCapability
from yoetz.ports.importer import ImporterPort, ImportStatusSnapshot
from yoetz.ports.ledger import CheckCommitResult
from yoetz.ports.objects import ObjectStorePort
from yoetz.ports.publish_response_catalog import PublishResponseCatalogPort
from yoetz.ports.runtime import BundleRuntimePort, RouteCommand, TaskRuntime
from yoetz.ports.semantic import SamplingParams, SemanticJudgment
from yoetz.protocol.canonical import JsonValue, canonical_encode
from yoetz.protocol.models import (
    CheckRequest,
    FrontierModel,
    PublishWorkRequest,
    ReceiptRequest,
    RespondRequest,
    SemanticReason,
    SemanticStatus,
    StatusRequest,
    public_model_to_wire,
)

__all__ = [
    "PROJECTION_DIGEST",
    "STATUS_VIEWS",
    "ProjectionCase",
    "ProjectionWorkflow",
    "build_projection_application",
    "frontier_json",
    "project_case",
    "request_base",
    "run_projection_workflow",
]

PROJECTION_DIGEST = "sha256:" + "7" * 64
_WORKSPACE = "hmac-sha256:" + "8" * 64
_INSTALLATION = protocol_id("ins_", 1404)
_NOW = datetime(2026, 7, 28, 12, 0, tzinfo=UTC)

# The exact ten-view vocabulary ``StatusSuccessModel.view`` declares. Kept as a tuple so a sweep
# that iterates it fails loudly the day a view is added without a case here.
STATUS_VIEWS: tuple[str, ...] = (
    "advice",
    "assignment",
    "candidate_findings",
    "compact",
    "evidence",
    "findings",
    "history",
    "obligations",
    "operation",
    "versions",
)

_CAPABILITIES = frozenset(
    {
        RuntimeCapability.WRITE,
        RuntimeCapability.STRUCTURAL_READ,
        RuntimeCapability.PAYLOAD_READ,
        RuntimeCapability.SEMANTIC,
    }
)

# Reaching for the private builder on purpose: a projection regression only means something if the
# policy under test is identical in disposition to the one the daemon seeds, including the
# ``finding_summary`` inclusion for the agent context.
_denied_policy = cast(
    "Callable[..., PrivacyPolicy]",
    getattr(ready_composition, "_denied_policy"),
)


class _IdleImporter:
    """Provide a stable idle importer status for projection tests."""

    async def status(self, session: str) -> ImportStatusSnapshot:
        """Return an empty importer snapshot for the requested session."""

        from yoetz.domain.values import session_id

        return ImportStatusSnapshot(session_id(session), 0, 0, (), ())


class _ProjectionRuntime(MemoryStartRuntime):
    """Extend the START memory composition with ready writer routing."""

    async def route(self, command: RouteCommand) -> TaskRuntime:
        """Resolve the sole seeded task when the requested writer owns it."""

        assert command.writer_id is not None
        assert command.required_capabilities <= _CAPABILITIES
        task_id, resources = next(iter(self.resources.items()))
        ledger, objects = resources
        assert (command.session_id, command.writer_id) in self.owners
        return TaskRuntime(
            task_id,
            command.session_id,
            command.writer_id,
            _CAPABILITIES,
            ledger,
            objects,
            cast(ImporterPort, _IdleImporter()),
            "0.1.0",
            "0.1.0",
            "0.1",
            "1.0.0",
            ownership_fence(),
        )


class _Gateway:
    """Stand in for an unused outbound gateway."""

    async def close(self) -> None:
        """Close the no-op gateway."""

        return None


def _versions() -> ReceiptVersionSlice:
    """Return a stable version slice for local disclosure receipts."""

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
        # The current receipt writer emits the additive child section.  Its inner document
        # schema_version remains 1.0.0; the artifact selected by the version slice is 1.2.0.
        schema_versions=(SchemaVersionEntry("receipts/receipt-document", "1.3.0"),),
        resource_manifest_digest=PROJECTION_DIGEST,
    )


def _scope(_: ControlProjectionBinding, source: Mapping[str, JsonValue]) -> AuthorizationScope:
    """Bind disclosure to the projected result's task identity."""

    return AuthorizationScope(
        AuthorizationScopeKind.TASK,
        _INSTALLATION,
        _WORKSPACE,
        cast(str, source["task_id"]),
    )


async def _semantic_never(
    frozen: object,
    findings: object,
    runtime: object | None = None,
    lineage_evaluation: object | None = None,
    require_complete_specification: bool = False,
) -> object:
    """Fail if a local-only composition reaches AI-powered evaluation."""

    del frozen, findings, runtime, lineage_evaluation
    raise AssertionError("semantic_evaluator_called_in_deterministic_mode")


async def _semantic_succeeds(
    frozen: object,
    findings: object,
    runtime: object | None = None,
    lineage_evaluation: object | None = None,
    require_complete_specification: bool = False,
) -> object:
    """Return a succeeded AI-powered review outcome that raises no challenge of its own.

    AI-powered review *delivery* is a separate subject; these sweeps only need the review to reach
    ``succeeded`` so that the local findings travel the AI-powered review modes too.
    """

    del frozen, findings, runtime, lineage_evaluation
    return FinalSemanticEvaluation(
        SemanticStatus.SUCCEEDED,
        SemanticReason.SEMANTIC_COMPLETED,
        judgment=SemanticJudgment("no_material_discrepancy", ()),
        provenance=SemanticProvenance(
            provider="fake",
            endpoint_profile_id="fake",
            endpoint_profile_version="1.0.0",
            model="fake/model",
            sdk_version="1.0.0",
            prompt_digest=PROJECTION_DIGEST,
            schema_digest=PROJECTION_DIGEST,
            policy_digest=PROJECTION_DIGEST,
            privacy_policy_digest=PROJECTION_DIGEST,
            sampling_params=SamplingParams(128),
            latency_ms=1,
            semantic_attempt_id=protocol_id("att_", 1490),
            dispatch_kind=SemanticDispatchKind.EXTERNAL,
            privacy_receipt_id=protocol_id("egr_", 1491),
            status=SemanticStatus.SUCCEEDED,
            reason=SemanticReason.SEMANTIC_COMPLETED,
            provider_request_id="fake-1",
            egress_authorization_id=protocol_id("aut_", 1492),
            request_commitment="hmac-sha256:" + "b" * 64,
        ),
        provider_input_manifest=provider_bound_manifest(),
    )


def request_base(request_id: str) -> dict[str, JsonValue]:
    """Build the common MCP request envelope a cooperative agent sends."""

    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": request_id,
        "actor": {
            "actor_id": "projection-sweep",
            "actor_type": "logical_agent",
            "display_name": "Codex",
        },
        "client": {
            "kind": "cooperative_agent",
            "version": "1.0",
            "integration": "cooperative_mcp",
        },
    }


def frontier_json(value: Frontier | FrontierModel) -> JsonValue:
    """Normalize domain and wire frontiers to JSON."""

    if isinstance(value, Frontier):
        return cast(JsonValue, dict(value.as_wire().items()))
    return cast(JsonValue, value.model_dump(mode="json"))


async def build_projection_application(
    semantic: Literal["disabled", "optional"] = "disabled",
    *,
    seed: int = 1400,
    max_findings: int = 3,
) -> tuple[Application, PrivacyPolicy]:
    """A ready application whose disclosure boundary is the real coordinator and default policy."""

    start_app, start_runtime, clock, catalog = start_composition()
    ids = start_runtime.ids
    privacy_state = MemoryPrivacyCatalogState()
    policies = MemoryPrivacyPolicyStore(privacy_state, clock)
    policy = _denied_policy(
        installation_id=_INSTALLATION,
        policy_id=protocol_id("pvy_", seed),
        policy_digest=PROJECTION_DIGEST,
        created_at=_NOW,
    )
    await policies.seed_if_absent(policy)
    audit = MemoryPrivacyAudit(
        privacy_state, cast(ObjectStorePort, MemoryObjects(ids)), StartTestLookup(), clock
    )
    coordinator = PrivacyCoordinator(
        policies,
        # The enforcer the daemon composes, including its trusted provenance resolver (#914).
        ready_composition.build_local_privacy_enforcer(),
        audit,
        _Gateway(),  # type: ignore[arg-type]
        clock,
        ids,
    )
    runtime = _ProjectionRuntime(clock, ids)
    app = Application(
        start_catalog=catalog.delegate,
        publish_responses=cast(PublishResponseCatalogPort, catalog.delegate),
        runtime=cast(BundleRuntimePort, runtime),
        clock=clock,
        ids=ids,
        verification_policy=VerificationPolicy(semantic=semantic, max_findings=max_findings),
        privacy=coordinator,
        status_cursor_key=b"projection-workflow-status-cursor-key",
        waiver_policy_digest=PROJECTION_DIGEST,
        semantic_evaluator=_semantic_never if semantic == "disabled" else _semantic_succeeds,
        disclosure_scope_for=_scope,
        receipt_version_resolver=lambda _: _versions(),
        waiver_authorizer=lambda _: False,
        import_publication_authorizer=lambda _: False,
        profile=RuntimeProfile.TEST_FAKE,
        policy_packs=("research-evidence/0.2.0", "work-integrity/0.3.0"),
        version_manifest=start_app.version_manifest,
        enforce_repository_identity=False,
        connected_provider_ids=() if semantic == "disabled" else ("fake",),
        provider_credential_connected=semantic != "disabled",
        semantic_ready=semantic != "disabled",
    )
    return app, policy


@dataclass(frozen=True, slots=True)
class ProjectionCase:
    """One internal result and the request body its projection binding derives from.

    ``label`` distinguishes cases that share a method — the ten status views all carry
    ``ControlMethod.STATUS`` — and is what a failing sweep names.
    """

    label: str
    method: ControlMethod
    request_body: Mapping[str, JsonValue]
    internal: UnprojectedControlBody


@dataclass(frozen=True, slots=True)
class ProjectionWorkflow:
    """The application that ran the workflow, plus one case per public result model."""

    app: Application
    policy: PrivacyPolicy
    cases: tuple[ProjectionCase, ...]

    def case(self, label: str) -> ProjectionCase:
        """Return the single case carrying *label*."""

        for item in self.cases:
            if item.label == label:
                return item
        raise KeyError(label)


async def project_case(
    app: Application, case: ProjectionCase, seed: int
) -> Mapping[str, JsonValue]:
    """Run the daemon's exact post-commit projection for an MCP bridge client."""

    facts = await app.projection_binding_facts(case.method, case.request_body, case.internal)
    rpc_id = protocol_id("rpc_", seed)
    service_instance_id = protocol_id("svc_", seed + 1)
    binding = ControlProjectionBinding(
        rpc_id,
        case.method,
        service_instance_id,
        1,
        facts.original_request_id,
        facts.route_identity_digest,
        canonical_encode(
            {
                "rpc_id": rpc_id,
                "method": case.method.value,
                "service_instance_id": service_instance_id,
                "service_generation": "1",
            }
        ),
    )
    projected = await app.project_result_for_client(
        ClientProjectionContext(
            ControlClientKind.MCP_BRIDGE, ProjectionRenderMode.MACHINE_READABLE, False
        ),
        binding,
        case.internal,
    )
    return public_model_to_wire(projected)


def _event_drafts(seed: int, obligation_event_id: str, obligation_id: str) -> list[JsonValue]:
    """A batch that populates every nested status collection the sweep walks.

    An obligation with an unmet requested item, an assignment that owns it, and an
    action/result/evidence/claim chain whose claim rests on the obligation alone — so the
    local policies have real material and ``check`` produces real findings.
    """

    action_id = protocol_id("act_", seed + 10)
    result_id = protocol_id("res_", seed + 11)
    evidence_id = protocol_id("evd_", seed + 12)
    action_event_id = protocol_id("evt_", seed + 13)
    result_event_id = protocol_id("evt_", seed + 14)
    evidence_event_id = protocol_id("evt_", seed + 15)
    plan_event_id = protocol_id("evt_", seed + 19)
    return [
        {
            "event_id": plan_event_id,
            "schema": {"name": "plan_published", "version": "1.0.0"},
            "occurred_at": "2026-07-28T11:59:59.000Z",
            "causal_parents": [],
            "payload": {
                "plan_version": 1,
                "summary": "Exercise every public result projection.",
                "obligation_refs": [obligation_id],
            },
            "artifact_refs": [],
            "evidence_refs": [],
        },
        {
            "event_id": obligation_event_id,
            "schema": {"name": "obligation_published", "version": "1.0.0"},
            "occurred_at": "2026-07-28T12:00:00.000Z",
            "causal_parents": [plan_event_id],
            "payload": {
                "obligation_id": obligation_id,
                "description": "Publish a result for the projection sweep.",
                "acceptance_criteria": "A result is recorded in the task ledger.",
                "evidence_expectation": "A linked immutable result record.",
                "requested_items": [
                    {"item_kind": "change", "value": "sweep-result"},
                    {"item_kind": "change", "value": "sweep-unattempted"},
                ],
                "status": "open",
            },
            "artifact_refs": [],
            "evidence_refs": [],
        },
        {
            "event_id": protocol_id("evt_", seed + 16),
            "schema": {"name": "assignment_recorded", "version": "1.0.0"},
            "occurred_at": "2026-07-28T12:00:01.000Z",
            "causal_parents": [obligation_event_id],
            "payload": {
                "assignee_actor_id": "projection-sweep",
                "obligation_ids": [obligation_id],
                "scope_description": "Owns the projection sweep obligation.",
            },
            "artifact_refs": [],
            "evidence_refs": [],
        },
        {
            "event_id": action_event_id,
            "schema": {"name": "action_recorded", "version": "1.0.0"},
            "occurred_at": "2026-07-28T12:00:02.000Z",
            "causal_parents": [obligation_event_id],
            "payload": {
                "action_id": action_id,
                "action_kind": "edit",
                "description": "Edited the projection sweep fixture.",
            },
            "artifact_refs": [],
            "evidence_refs": [],
        },
        {
            "event_id": result_event_id,
            "schema": {"name": "result_recorded", "version": "1.0.0"},
            "occurred_at": "2026-07-28T12:00:03.000Z",
            "causal_parents": [action_event_id],
            "payload": {
                "result_id": result_id,
                "action_id": action_id,
                "outcome": "success",
                "summary": "The projection sweep fixture was edited.",
            },
            "artifact_refs": [],
            "evidence_refs": [],
        },
        {
            "event_id": evidence_event_id,
            "schema": {"name": "evidence_recorded", "version": "1.0.0"},
            "occurred_at": "2026-07-28T12:00:04.000Z",
            "causal_parents": [result_event_id],
            "payload": {
                "evidence_id": evidence_id,
                "evidence_kind": "test_result",
                "strength": "metadata_only",
                "observed_at": "2026-07-28T12:00:04.000Z",
                "reference": "the projection sweep fixture",
            },
            "artifact_refs": [],
            "evidence_refs": [],
        },
        {
            "event_id": protocol_id("evt_", seed + 17),
            "schema": {"name": "claim_recorded", "version": "1.0.0"},
            "occurred_at": "2026-07-28T12:00:05.000Z",
            "causal_parents": [evidence_event_id],
            "payload": {
                "claim_id": protocol_id("clm_", seed + 18),
                "claim_kind": "completion",
                "statement": "The projection sweep work is complete.",
                "supporting_refs": [obligation_id],
                "obligation_refs": [obligation_id],
            },
            "artifact_refs": [],
            "evidence_refs": [],
        },
    ]


async def run_projection_workflow(
    semantic: Literal["disabled", "optional"] = "disabled",
    *,
    seed: int = 1400,
    max_findings: int = 3,
) -> ProjectionWorkflow:
    """Run one workflow and collect a case for every public result model and status view."""

    app, policy = await build_projection_application(semantic, seed=seed, max_findings=max_findings)
    cases: list[ProjectionCase] = []

    start_body = start_request(seed + 1, title="Projection sweep")
    started = await app.start(start_body)
    cases.append(
        ProjectionCase("start", ControlMethod.START, start_body.model_dump(mode="json"), started)
    )

    obligation_id = protocol_id("obl_", seed + 2)
    obligation_event_id = protocol_id("evt_", seed + 3)
    publish_body: dict[str, JsonValue] = {
        **request_base(protocol_id("req_", seed + 4)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": frontier_json(started.frontier),
        "event_drafts": _event_drafts(seed, obligation_event_id, obligation_id),
    }
    published = await app.publish_work(PublishWorkRequest.model_validate(publish_body))
    # A first, non-replayed publish always yields the internal result; the replay branch returns a
    # stored public result instead, and the sweep needs the unprojected body.
    assert type(published) is PublishWorkInternalResult
    cases.append(
        ProjectionCase("publish_work", ControlMethod.PUBLISH_WORK, publish_body, published)
    )

    check_body: dict[str, JsonValue] = {
        **request_base(protocol_id("req_", seed + 5)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": frontier_json(published.result_frontier),
        "mode": "deterministic_only" if semantic == "disabled" else "semantic_required",
        "max_findings": str(max_findings),
    }
    checked = await app.check(CheckRequest.model_validate(check_body))
    # This sweep drives a terminal check; a suspension here is a fixture bug, not a branch to
    # handle, so narrow once rather than at every attribute read below.
    assert type(checked) is CheckCommitResult, f"unexpected nonterminal check: {type(checked)}"
    assert checked.findings, "the sweep workflow must produce at least one finding"
    cases.append(ProjectionCase("check", ControlMethod.CHECK, check_body, checked))

    respond_body: dict[str, JsonValue] = {
        **request_base(protocol_id("req_", seed + 6)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": frontier_json(checked.result_frontier),
        "finding_id": checked.findings[0].finding_id,
        "finding_frontier": frontier_json(checked.result_frontier),
        "disposition": "acknowledged",
        "reason": "The gap stays explicit until follow-up work is published.",
        "evidence_refs": [protocol_id("evd_", seed + 12)],
    }
    responded = await app.respond(RespondRequest.model_validate(respond_body))
    cases.append(ProjectionCase("respond", ControlMethod.RESPOND, respond_body, responded))

    for offset, view in enumerate(STATUS_VIEWS):
        status_body: dict[str, JsonValue] = {
            **request_base(protocol_id("req_", seed + 20 + offset)),
            "session_id": started.session_id,
            "writer_id": started.writer_id,
            "view": view,
            "limit": "10",
            "at_frontier": str(responded.result_frontier.sequence),
        }
        if view == "operation":
            # The only view whose filter the frozen request schema makes mandatory. Point it at
            # the publish, the one operation kind whose recovery page carries a nested
            # ``accepted_events`` collection rather than an empty one.
            status_body["filter"] = {"operation_request_id": cast(str, publish_body["request_id"])}
        status = await app.status(StatusRequest.model_validate(status_body))
        cases.append(ProjectionCase(f"status/{view}", ControlMethod.STATUS, status_body, status))

    receipt_body: dict[str, JsonValue] = {
        **request_base(protocol_id("req_", seed + 40)),
        "task_id": started.task_id,
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": frontier_json(responded.result_frontier),
        "format": "json",
        "include": "standard",
        "redaction_profile": "full_local",
    }
    receipt = await app.receipt(ReceiptRequest.model_validate(receipt_body))
    cases.append(ProjectionCase("receipt", ControlMethod.RECEIPT, receipt_body, receipt))

    return ProjectionWorkflow(app, policy, tuple(cases))
