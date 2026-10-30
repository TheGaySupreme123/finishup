"""Integration coverage for the response, status, and receipt operations composing over one
frozen frontier, all driven through the real ``Application`` facade and the memory ledger oracle.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any, Literal, cast

import apsw
import pydantic
import pytest

from builders.ledger_adapters import FixedIds, MemoryObjects, ownership_fence
from builders.review_manifests import provider_bound_manifest
from builders.start_application import (
    MemoryStartRuntime,
    StartTestClock,
    protocol_id,
    start_composition,
    start_request,
)
from finishup.adapters.sqlite.migrations import initialize_bundle
from finishup.adapters.sqlite.repository import SqliteLedger
from finishup.application.check import FinalSemanticEvaluation
from finishup.application.egress import PrivacyCoordinator
from finishup.application.observation_advice import stable_advice_finding_id
from finishup.application.observation_materialize import (
    materialize_observation_envelope,
    observation_author,
)
from finishup.application.publish_work import PublishWorkInternalResult
from finishup.application.receipt import ReceiptInternalResult
from finishup.application.semantic_case import (
    ReviewPacketDisclosure,
    build_semantic_case,
    review_packet_disclosure,
    semantic_case_to_candidate_context,
    semantic_case_to_prepared_payload,
    sent_ledger_refs,
)
from finishup.application.service import Application, VerificationPolicy
from finishup.application.start import StartInternalResult
from finishup.domain.events import (
    EVIDENCE_SCHEMA_VERSION,
    ActionKind,
    ActionRecordedPayload,
    CheckRecordedPayload,
    DecisionRecordedPayload,
    EventDraft,
    EventSchema,
    EvidenceKind,
    EvidenceRecordedPayload,
    LedgerRecord,
    ResultOutcome,
    ResultRecordedPayload,
    RuntimeProfile,
    encode_payload,
    media_type_for,
)
from finishup.domain.findings import (
    FINDING_KIND_TRAITS,
    Finding,
    FindingKind,
    FindingOrigin,
    SemanticDispatchKind,
    SemanticProvenance,
)
from finishup.domain.observation import (
    ObservationContentKind,
    ObservationContentManifest,
    ObservationCursor,
    ObservationEnvelope,
    ObservationSource,
)
from finishup.domain.privacy import (
    AuthorizationScope,
    AuthorizationScopeKind,
    CandidateContext,
    ConsentSource,
    LocalDisclosureApproved,
    LocalDisclosureReceipt,
    PrivacyOutcome,
    ProviderBinding,
    ReceiptCounts,
    ReceiptPolicyBinding,
    ReceiptSecretScan,
    ReceiptTransformations,
    ReviewContextProfile,
    ReviewSelectionPolicy,
)
from finishup.domain.receipts import PolicyVersionEntry, ReceiptVersionSlice, SchemaVersionEntry
from finishup.domain.values import (
    Frontier,
    Timestamp,
    action_id,
    event_id,
    evidence_id,
    finding_id,
    object_id,
    result_id,
    session_id,
    timestamp_from_datetime,
)
from finishup.domain.values import JsonObject as DomainJsonObject
from finishup.kernel.finding_resolution import finding_is_resolved
from finishup.kernel.policies.observation_advice import (
    OBSERVATION_ADVICE_POLICY_ID,
    ObservationAdviceCandidate,
)
from finishup.kernel.projections import projection_from_snapshot, projection_snapshot
from finishup.kernel.receipt_capacity import receipt_gap_codes
from finishup.kernel.reducers import replay
from finishup.mcp.summaries import summary_for_status
from finishup.ports.diagnostics import RuntimeCapability
from finishup.ports.importer import ImporterPort, ImportStatusSnapshot
from finishup.ports.ledger import (
    AppendCommand,
    AppendEntry,
    CheckCommitResult,
    FrozenCase,
    LedgerPort,
    OperationKind,
    ProjectionView,
    StoredProjection,
)
from finishup.ports.objects import (
    ObjectKind,
    ObjectMetadata,
    ObjectRef,
    ObjectRootSnapshot,
    ObjectSource,
    StagedObject,
)
from finishup.ports.publish_response_catalog import PublishResponseCatalogPort
from finishup.ports.runtime import (
    BundleProvisionCommand,
    BundleRuntimePort,
    RouteCommand,
    TaskRuntime,
)
from finishup.ports.semantic import (
    ReviewerChallenge,
    ReviewerNextStep,
    SamplingParams,
    SemanticCase,
    SemanticJudgment,
    VerifiedReviewItem,
)
from finishup.protocol.canonical import JsonValue, canonical_digest, canonical_encode
from finishup.protocol.coverage import (
    ArtifactObservation,
    AuthorshipAssurance,
    CheckType,
    Coverage,
    EvidenceImmutability,
    LedgerFreshness,
    PublicationChannel,
    coverage_for_channel,
)
from finishup.protocol.errors import ProtocolValueError, PublicErrorCode, PublicOperationError
from finishup.protocol.models import (
    CheckRequest,
    FrontierModel,
    PublishWorkDryRunModel,
    PublishWorkRequest,
    PublishWorkResult,
    ReceiptRequest,
    RespondRequest,
    SemanticReason,
    SemanticStatus,
    StartRequest,
    StatusCandidateFindingsPageModel,
    StatusCompactItemModel,
    StatusCompactPageModel,
    StatusEvidencePageModel,
    StatusFindingItemModel,
    StatusFindingsPageModel,
    StatusObligationsPageModel,
    StatusOperationPageModel,
    StatusRequest,
)
from finishup.protocol.recovery import REASON_REMEDIES
from fixture_loader import load_fixture_json

pytestmark = pytest.mark.anyio

_DIGEST = "sha256:" + "7" * 64
_WORKSPACE = "hmac-sha256:" + "8" * 64
_POLICY_PACKS = ("research-evidence/0.2.0", "work-integrity/0.3.0")


class _IdleImporter:
    async def status(self, session: str) -> ImportStatusSnapshot:
        return ImportStatusSnapshot(session_id(session), 0, 0, (), ())


class _FailSecondPersistObjects(MemoryObjects):
    """Fault wrapper that keeps the shared backing store visible to the ledger and retry."""

    def __init__(
        self,
        delegate: MemoryObjects,
        fault_at: Literal["stage", "finalize", "cancel_after_finalize"],
    ) -> None:
        self._delegate = delegate
        self._fault_at = fault_at
        self.stage_calls = 0
        self.finalize_calls = 0
        self.abandoned_ids: list[str] = []
        self._failed = False

    def refs_for_kind(self, kind: ObjectKind) -> tuple[ObjectRef, ...]:
        return self._delegate.refs_for_kind(kind)

    async def commitment_for(self, data: bytes, kind: ObjectKind) -> str:
        return await self._delegate.commitment_for(data, kind)

    async def stage(
        self, source: ObjectSource, metadata: ObjectMetadata, *, object_id: str | None = None
    ) -> StagedObject:
        self.stage_calls += 1
        if self._fault_at == "stage" and self.stage_calls == 2 and not self._failed:
            self._failed = True
            raise OSError("simulated_second_stage_failure")
        return await self._delegate.stage(source, metadata, object_id=object_id)

    async def finalize(self, staged: StagedObject) -> ObjectRef:
        self.finalize_calls += 1
        if self._fault_at == "finalize" and self.finalize_calls == 2 and not self._failed:
            self._failed = True
            raise OSError("simulated_second_finalize_failure")
        result = await self._delegate.finalize(staged)
        if (
            self._fault_at == "cancel_after_finalize"
            and self.finalize_calls == 2
            and not self._failed
        ):
            # Both exact objects are now finalized and nothing has been submitted. Requesting
            # cancellation here reaches the commit boundary through the synchronous append/mutation
            # construction, with no suspension point in between.
            self._failed = True
            current = asyncio.current_task()
            assert current is not None
            current.cancel()
        return result

    async def abandon(self, staged: StagedObject) -> None:
        self.abandoned_ids.append(staged.object_id)
        await self._delegate.abandon(staged)

    async def resolve_verified(self, object_id: str, envelope_digest: str) -> ObjectRef:
        return await self._delegate.resolve_verified(object_id, envelope_digest)

    def open_verified(self, ref: ObjectRef) -> AsyncIterator[bytes]:
        return self._delegate.open_verified(ref)

    async def sweep_orphans(self, root_snapshot: ObjectRootSnapshot, now: datetime) -> int:
        return await self._delegate.sweep_orphans(root_snapshot, now)


class _WorkflowRuntime(MemoryStartRuntime):
    """Extend the START memory composition with ready writer routing (mirrors the full-workflow
    integration harness; duplicated here rather than imported since test modules are not a shared
    library and this file may not modify that sibling)."""

    def __init__(
        self,
        clock: StartTestClock,
        ids: FixedIds,
        *,
        ledger_backend: Literal["memory", "sqlite"] = "memory",
    ) -> None:
        super().__init__(clock, ids)
        self.ledger_backend = ledger_backend
        self.sqlite_connections: list[apsw.Connection] = []
        self.owner_tasks: dict[tuple[str, str], str] = {}

    async def provision_start(self, command: BundleProvisionCommand) -> TaskRuntime:
        if self.ledger_backend == "memory":
            runtime = await super().provision_start(command)
            self.owner_tasks[(command.session_id, command.writer_id)] = command.task_id
            return runtime
        resources = self.resources.get(command.task_id)
        if resources is None:
            objects = MemoryObjects(self.ids)
            db = apsw.Connection(":memory:")
            initialize_bundle(
                db,
                {
                    "task_id": command.task_id,
                    "owner_generation": str(command.owner_generation),
                    "owner_nonce": "ledger-test-nonce",
                },
            )
            ledger = SqliteLedger(
                db=db,
                task_id=command.task_id,
                ownership_fence=ownership_fence(generation=command.owner_generation),
                clock=self.clock,
                ids=self.ids,
                objects=objects,
            )
            resources = (ledger, objects)  # type: ignore[assignment]
            self.resources[command.task_id] = resources  # type: ignore[assignment]
            self.sqlite_connections.append(db)
        ledger, objects = resources
        self.owners[(command.session_id, command.writer_id)] = command.owner_generation
        self.owner_tasks[(command.session_id, command.writer_id)] = command.task_id
        return TaskRuntime(
            command.task_id,
            command.session_id,
            command.writer_id,
            frozenset(),
            ledger,
            objects,
            cast(ImporterPort, object()),
            command.projection_version,
            command.engine_version,
            command.protocol_version,
            command.bundle_schema_version,
            ownership_fence(generation=command.owner_generation),
        )

    async def route(self, command: RouteCommand) -> TaskRuntime:
        assert command.writer_id is not None
        task_id = self.owner_tasks.get((command.session_id, command.writer_id))
        assert task_id is not None
        resources = self.resources[task_id]
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
                    # Granted unconditionally: a local-only check never reaches the
                    # capability gate, so this only opens the AI-powered review path for the app built
                    # with ``semantic="optional"``.
                    RuntimeCapability.SEMANTIC,
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
    """A scripted local-disclosure coordinator: every candidate is approved in full, and every
    approval is a fresh durable receipt, so the test can assert exactly one receipt per client
    projection without depending on the real privacy/egress subsystem under test elsewhere."""

    def __init__(self) -> None:
        self.candidates: list[CandidateContext] = []

    async def prepare_local_disclosure(
        self, candidate: CandidateContext
    ) -> LocalDisclosureApproved:
        self.candidates.append(candidate)
        sink = candidate.local_sink
        assert sink is not None
        proposal_id = protocol_id("ppr_", 900 + len(self.candidates))
        policy = ReceiptPolicyBinding(
            protocol_id("pvy_", 950 + len(self.candidates)), 1, _DIGEST, _DIGEST
        )
        receipt = LocalDisclosureReceipt(
            "1.0.0",
            protocol_id("egr_", 960 + len(self.candidates)),
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
        protocol_id("ins_", 999),
        _WORKSPACE,
        cast(str, source["task_id"]),
    )


async def _semantic_disabled(
    frozen: object,
    findings: object,
    runtime: object | None = None,
    lineage_evaluation: object | None = None,
) -> object:
    del frozen, findings, runtime, lineage_evaluation
    raise AssertionError("semantic_evaluator_called_in_deterministic_mode")


async def _semantic_succeeds(
    frozen: object,
    findings: object,
    runtime: object | None = None,
    lineage_evaluation: object | None = None,
) -> object:
    """Reach ``succeeded`` without raising an AI-powered review challenge of its own.

    AI-powered review delivery is exercised elsewhere; here the only thing that matters is that the check
    earns ``semantic_model_derived`` coverage, so the receipt has something to lose.
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
            prompt_digest=_DIGEST,
            schema_digest=_DIGEST,
            policy_digest=_DIGEST,
            privacy_policy_digest=_DIGEST,
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
    *,
    waiver_authorizer: Callable[[RespondRequest], bool] | None = None,
    seed_offset: int = 0,
    semantic: Literal["disabled", "optional", "required"] = "disabled",
    ledger_backend: Literal["memory", "sqlite"] = "memory",
    semantic_evaluator: Callable[..., Awaitable[object]] | None = None,
) -> tuple[Application, _WorkflowRuntime, _ProjectionSpy]:
    start_app, start_runtime, clock, catalog = start_composition()
    projection = _ProjectionSpy()
    ids = start_runtime.ids
    runtime = _WorkflowRuntime(clock, ids, ledger_backend=ledger_backend)
    app = Application(
        start_catalog=catalog.delegate,
        publish_responses=cast(PublishResponseCatalogPort, catalog.delegate),
        runtime=cast(BundleRuntimePort, runtime),
        clock=clock,
        ids=ids,
        verification_policy=VerificationPolicy(semantic=semantic, max_findings=3),
        privacy=cast(PrivacyCoordinator, projection),
        status_cursor_key=(b"respond-status-receipt-cursor-key-" + str(seed_offset).encode() * 4)[
            :32
        ],
        waiver_policy_digest=_DIGEST,
        semantic_evaluator=(
            semantic_evaluator
            if semantic_evaluator is not None
            else _semantic_disabled
            if semantic == "disabled"
            else _semantic_succeeds
        ),
        disclosure_scope_for=_scope,
        receipt_version_resolver=lambda _: _versions(),
        waiver_authorizer=(lambda _: False) if waiver_authorizer is None else waiver_authorizer,
        import_publication_authorizer=lambda _: False,
        profile=RuntimeProfile.TEST_FAKE,
        policy_packs=_POLICY_PACKS,
        version_manifest=start_app.version_manifest,
        enforce_repository_identity=False,
        connected_provider_ids=() if semantic == "disabled" else ("fake",),
        provider_credential_connected=semantic != "disabled",
        semantic_ready=semantic != "disabled",
    )
    return app, runtime, projection


async def _bootstrap_finding(
    app: Application,
    *,
    seed: int,
    mode: str = "deterministic_only",
    refs: bool = False,
    max_findings: str = "3",
    task_statement: str | None = None,
    requested_items: tuple[dict[str, JsonValue], ...] = (),
) -> tuple[StartInternalResult, CheckCommitResult, str]:
    """Publish one open obligation plus an unsupported completion claim about it, then check.

    This reuses the exact scenario already proven (in ``test_full_workflow.py``) to yield one
    actionable ``completion_with_open_obligations`` finding, so the finding-triggering mechanics
    themselves are not re-derived here. ``task_statement`` records one through a reattaching
    ``start`` before anything is published (issue #908).
    """

    started = await app.start(
        start_request(seed, title="Respond/status/receipt exercise", refs=refs)
    )
    first_frontier = started.frontier
    if task_statement is not None:
        attached = await app.start(
            StartRequest.model_validate(
                {
                    **_request_base(protocol_id("req_", seed + 25)),
                    "mode": "attach",
                    "session_id": started.session_id,
                    "task_title": "Respond/status/receipt exercise",
                    "requested_view": "compact",
                    "task_statement": task_statement,
                }
            )
        )
        first_frontier = attached.frontier
    obligation_id = protocol_id("obl_", seed + 1)
    obligation_event_id = protocol_id("evt_", seed + 2)
    publish_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", seed + 3)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(first_frontier),
        "event_drafts": (
            {
                "event_id": obligation_event_id,
                "schema": {"name": "obligation_published", "version": "1.0.0"},
                "occurred_at": "2026-07-19T12:00:00.000Z",
                "causal_parents": (),
                "payload": {
                    "obligation_id": obligation_id,
                    "description": "Publish a result for the respond/status/receipt exercise.",
                    "acceptance_criteria": "A result is recorded in the task ledger.",
                    "evidence_expectation": "A linked immutable result record.",
                    **({"requested_items": requested_items} if requested_items else {}),
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
        "mode": mode,
        "max_findings": max_findings,
    }
    checked = await app.check(CheckRequest.model_validate(check_wire))
    assert type(checked) is CheckCommitResult, f"unexpected nonterminal check: {type(checked)}"
    assert checked.findings, "the seeded scenario must always yield one actionable finding"
    return started, checked, obligation_id


async def test_response_disposition_and_waiver_scope() -> None:
    # Acknowledged: reason optional, no waiver fields recorded.
    ack_app, _ack_runtime, _ = _build_app()
    started, checked, _obligation = await _bootstrap_finding(ack_app, seed=100)
    finding = checked.findings[0]
    ack_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 110)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(checked.result_frontier),
        "finding_id": finding.finding_id,
        "finding_frontier": _frontier(checked.result_frontier),
        "disposition": "acknowledged",
    }
    acked = await ack_app.respond(RespondRequest.model_validate(ack_wire))
    assert acked.response.disposition == "acknowledged"
    assert acked.response.reason is None
    assert acked.response.waiver_scope is None
    assert acked.response.waiver_expiry is None

    # Rejected: reason is required and recorded exactly.
    reject_app, _reject_runtime, _ = _build_app()
    started2, checked2, _obligation2 = await _bootstrap_finding(reject_app, seed=200)
    finding2 = checked2.findings[0]
    reject_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 210)),
        "session_id": started2.session_id,
        "writer_id": started2.writer_id,
        "expected_frontier": _frontier(checked2.result_frontier),
        "finding_id": finding2.finding_id,
        "finding_frontier": _frontier(checked2.result_frontier),
        "disposition": "rejected",
        "reason": "The obligation is intentionally deferred to a later milestone.",
    }
    rejected = await reject_app.respond(RespondRequest.model_validate(reject_wire))
    assert rejected.response.disposition == "rejected"
    assert (
        rejected.response.reason == "The obligation is intentionally deferred to a later milestone."
    )
    assert rejected.response.waiver_scope is None

    # ``reason`` is required for ``rejected``/``waived``; this is a frozen contract rule enforced
    # before the request even reaches the application (the same closed vocabulary the unit-level
    # request-shape tests lock), so it is a schema validation failure here, not a public error.
    with pytest.raises(pydantic.ValidationError):
        RespondRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 211)),
                "session_id": started2.session_id,
                "writer_id": started2.writer_id,
                "expected_frontier": _frontier(rejected.result_frontier),
                "finding_id": finding2.finding_id,
                "finding_frontier": _frontier(checked2.result_frontier),
                "disposition": "rejected",
            }
        )

    # Waived: requires an interactive human local_cli actor explicitly authorized, exactly the
    # single v0.1 ``finding_only`` scope, and may further narrow with an expiry.
    waive_app, _waive_runtime, _ = _build_app(waiver_authorizer=lambda _: True)
    started3, checked3, _obligation3 = await _bootstrap_finding(waive_app, seed=300)
    finding3 = checked3.findings[0]
    waive_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 310), actor_type="human"),
        "session_id": started3.session_id,
        "writer_id": started3.writer_id,
        "expected_frontier": _frontier(checked3.result_frontier),
        "finding_id": finding3.finding_id,
        "finding_frontier": _frontier(checked3.result_frontier),
        "disposition": "waived",
        "reason": "Waived pending an unrelated release freeze.",
        "waiver_scope": "finding_only",
        "waiver_expiry": "2030-01-01T00:00:00.000Z",
    }
    waived = await waive_app.respond(RespondRequest.model_validate(waive_wire))
    assert waived.response.disposition == "waived"
    assert waived.response.waiver_scope == "finding_only"
    assert waived.response.waiver_expiry == "2030-01-01T00:00:00.000Z"
    assert waived.warning_codes == ()

    # A non-human/non-local_cli actor, or an unauthorized one, may never waive.
    with pytest.raises(PublicOperationError) as unauthorized:
        await ack_app.respond(
            RespondRequest.model_validate(
                {
                    **_request_base(protocol_id("req_", 111)),
                    "session_id": started.session_id,
                    "writer_id": started.writer_id,
                    "expected_frontier": _frontier(acked.result_frontier),
                    "finding_id": finding.finding_id,
                    "finding_frontier": _frontier(checked.result_frontier),
                    "disposition": "waived",
                    "reason": "An agent may not waive.",
                    "waiver_scope": "finding_only",
                }
            )
        )
    assert unauthorized.value.code is PublicErrorCode.INVALID_REQUEST


async def test_status_is_task_read_only_paginated_and_projection_receipted() -> None:
    from finishup.application.service import (
        ClientProjectionContext,
        ControlProjectionBinding,
        ProjectionRenderMode,
    )
    from finishup.ports.control import ControlClientKind, ControlMethod
    from finishup.protocol.canonical import canonical_encode
    from finishup.protocol.models import StatusResultModel

    app, runtime, projection = _build_app(seed_offset=1)
    started, checked, _obligation = await _bootstrap_finding(app, seed=400)

    status_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 410)),
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
    page = cast(StatusFindingsPageModel, status.page)
    assert page.items
    item = page.items[0]
    assert item.disposition == "none"
    assert item.resolved is False

    # Status never writes task state: repeating it (and a fresh receipt at the same frontier)
    # observes the identical frontier every time.
    repeated = await app.status(
        StatusRequest.model_validate({**status_wire, "request_id": protocol_id("req_", 411)})
    )
    assert repeated.subject_frontier == status.subject_frontier
    assert repeated.result_frontier == status.result_frontier

    receipt_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 412)),
        "task_id": started.task_id,
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(checked.result_frontier),
        "format": "json",
        "include": "standard",
        "redaction_profile": "full_local",
    }
    receipt_after_status = await app.receipt(ReceiptRequest.model_validate(receipt_wire))
    assert receipt_after_status.subject_frontier == checked.result_frontier

    # Ordinary client disclosure of an otherwise-ordinary status result is durably receipted;
    # the raw internal result itself carries no such marker until it is projected.
    assert projection.candidates == []
    facts = await app.projection_binding_facts(ControlMethod.STATUS, status_request, status)
    rpc_id = protocol_id("rpc_", 413)
    service_instance_id = protocol_id("svc_", 414)
    binding = ControlProjectionBinding(
        rpc_id,
        ControlMethod.STATUS,
        service_instance_id,
        1,
        facts.original_request_id,
        facts.route_identity_digest,
        canonical_encode(
            {
                "rpc_id": rpc_id,
                "method": "status",
                "service_instance_id": service_instance_id,
                "service_generation": "1",
            }
        ),
    )
    projected = await app.project_result_for_client(
        ClientProjectionContext(
            ControlClientKind.CLI, ProjectionRenderMode.HUMAN_READABLE, True, owner_view=True
        ),
        binding,
        status,
    )
    assert isinstance(projected, StatusResultModel)
    assert projected.root.ok is True
    from finishup.protocol.models import StatusSuccessModel

    assert isinstance(projected.root, StatusSuccessModel)
    assert projected.root.privacy_projection.sink == "local_human_view"
    assert len(projection.candidates) == 1

    # Replaying the exact same logical projection reuses the same durable receipt rather than
    # minting a second one for an unchanged result/policy/sink.
    projected_again = await app.project_result_for_client(
        ClientProjectionContext(
            ControlClientKind.CLI, ProjectionRenderMode.HUMAN_READABLE, True, owner_view=True
        ),
        binding,
        status,
    )
    assert isinstance(projected_again, StatusResultModel)
    assert projected_again.root.ok is True
    assert isinstance(projected_again.root, StatusSuccessModel)
    assert (
        projected_again.root.privacy_projection.local_disclosure_receipt_id
        != projected.root.privacy_projection.local_disclosure_receipt_id
    ) or len(projection.candidates) == 2
    _ = runtime


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
async def test_receipt_matches_check_and_response_state(
    backend: Literal["memory", "sqlite"], monkeypatch: pytest.MonkeyPatch
) -> None:
    app, _runtime, _ = _build_app(seed_offset=2, ledger_backend=backend)
    started, checked, _obligation = await _bootstrap_finding(app, seed=500)

    def forbidden_replay(*_args: object) -> object:
        pytest.fail("respond/receipt must reuse the authenticated current projection")

    monkeypatch.setattr(
        "finishup.application.ledger_snapshot._replay_until_cancelled", forbidden_replay
    )
    monkeypatch.setattr("finishup.kernel.deterministic_checks.replay", forbidden_replay)
    finding = checked.findings[0]

    respond_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 510)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(checked.result_frontier),
        "finding_id": finding.finding_id,
        "finding_frontier": _frontier(checked.result_frontier),
        "disposition": "acknowledged",
    }
    responded = await app.respond(RespondRequest.model_validate(respond_wire))

    receipt_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 511)),
        "task_id": started.task_id,
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(responded.result_frontier),
        "format": "json",
        "include": "standard",
        "redaction_profile": "full_local",
    }
    receipt_request = ReceiptRequest.model_validate(receipt_wire)
    receipt = await app.receipt(receipt_request)

    assert receipt.subject_frontier == responded.result_frontier
    # An acknowledgement never resolves the finding, so the receipt still reports it unresolved.
    assert receipt.conclusion == "unresolved_findings_remain"
    assert receipt.suppressed_finding_count == 0
    assert receipt.versions == _versions()

    # Idempotent return: the identical logical request replays the same durable receipt facts.
    replayed = await app.receipt(ReceiptRequest.model_validate(receipt_wire))
    assert replayed.receipt_id == receipt.receipt_id
    assert replayed.receipt_digest == receipt.receipt_digest
    assert replayed.conclusion == receipt.conclusion
    assert replayed.result_frontier == receipt.result_frontier


@pytest.mark.parametrize(
    ("fault_at", "expected_abandoned"),
    (("stage", 1), ("finalize", 2)),
)
async def test_second_object_failure_abandons_stages_then_same_request_retries(
    fault_at: Literal["stage", "finalize"], expected_abandoned: int
) -> None:
    """Issue #339: a pre-append payload failure leaves no finalized receipt per retry."""

    app, runtime, _ = _build_app(seed_offset=33)
    started, checked, _obligation = await _bootstrap_finding(app, seed=5100)
    ledger, backing_objects = runtime.resources[started.task_id]
    faulting_objects = _FailSecondPersistObjects(backing_objects, fault_at)
    runtime.resources[started.task_id] = (ledger, faulting_objects)
    receipt_refs_before = backing_objects.refs_for_kind(ObjectKind.RECEIPT)
    payload_refs_before = backing_objects.refs_for_kind(ObjectKind.EVENT_PAYLOAD)
    receipt_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 5110)),
        "task_id": started.task_id,
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(checked.result_frontier),
        "format": "json",
        "include": "standard",
        "redaction_profile": "full_local",
    }
    request = ReceiptRequest.model_validate(receipt_wire)

    with pytest.raises(PublicOperationError) as caught:
        await app.receipt(request)
    assert caught.value.code is PublicErrorCode.STORAGE_UNSAFE
    assert caught.value.retryable is True
    assert len(faulting_objects.abandoned_ids) == expected_abandoned
    assert len(set(faulting_objects.abandoned_ids)) == expected_abandoned
    assert backing_objects.refs_for_kind(ObjectKind.RECEIPT) == receipt_refs_before
    assert backing_objects.refs_for_kind(ObjectKind.EVENT_PAYLOAD) == payload_refs_before
    assert await ledger.lookup_operation(started.writer_id, request.request_id) is None

    retried = await app.receipt(request)
    assert len(backing_objects.refs_for_kind(ObjectKind.RECEIPT)) == len(receipt_refs_before) + 1
    assert (
        len(backing_objects.refs_for_kind(ObjectKind.EVENT_PAYLOAD)) == len(payload_refs_before) + 1
    )
    replayed = await app.receipt(request)
    assert replayed.receipt_id == retried.receipt_id
    assert replayed.receipt_object_id == retried.receipt_object_id
    assert replayed.result_frontier == retried.result_frontier


async def test_cancellation_refused_at_the_commit_boundary_abandons_both_stages() -> None:
    """Issue #339: pre-submission cancellation must not leave two finalized orphans."""

    app, runtime, _ = _build_app(seed_offset=41)
    started, checked, _obligation = await _bootstrap_finding(app, seed=5300)
    ledger, backing_objects = runtime.resources[started.task_id]
    faulting_objects = _FailSecondPersistObjects(backing_objects, "cancel_after_finalize")
    runtime.resources[started.task_id] = (ledger, faulting_objects)
    receipt_refs_before = backing_objects.refs_for_kind(ObjectKind.RECEIPT)
    payload_refs_before = backing_objects.refs_for_kind(ObjectKind.EVENT_PAYLOAD)
    receipt_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 5310)),
        "task_id": started.task_id,
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(checked.result_frontier),
        "format": "json",
        "include": "standard",
        "redaction_profile": "full_local",
    }
    request = ReceiptRequest.model_validate(receipt_wire)

    # The cancellation is requested from inside the receipt task, so the test task stays live.
    receipt_task = asyncio.create_task(app.receipt(request))
    with pytest.raises(asyncio.CancelledError):
        await receipt_task

    assert faulting_objects.finalize_calls == 2
    assert len(faulting_objects.abandoned_ids) == 2
    assert len(set(faulting_objects.abandoned_ids)) == 2
    assert backing_objects.refs_for_kind(ObjectKind.RECEIPT) == receipt_refs_before
    assert backing_objects.refs_for_kind(ObjectKind.EVENT_PAYLOAD) == payload_refs_before
    assert await ledger.lookup_operation(started.writer_id, request.request_id) is None

    retried = await app.receipt(request)
    assert len(backing_objects.refs_for_kind(ObjectKind.RECEIPT)) == len(receipt_refs_before) + 1
    assert (
        len(backing_objects.refs_for_kind(ObjectKind.EVENT_PAYLOAD)) == len(payload_refs_before) + 1
    )
    replayed = await app.receipt(request)
    assert replayed.receipt_object_id == retried.receipt_object_id


async def test_reviewer_challenge_response_paths_use_existing_protocol() -> None:
    """Evidence attached to a response reuses the ordinary evidence/response surfaces; no
    reviewer-challenge-specific reply type exists."""

    app, _runtime, _ = _build_app(seed_offset=3)
    started, checked, _obligation = await _bootstrap_finding(app, seed=600)
    finding = checked.findings[0]

    evidence_event_id = protocol_id("evt_", 610)
    evidence_id = protocol_id("evd_", 611)
    publish_evidence_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 612)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(checked.result_frontier),
        "event_drafts": (
            {
                "event_id": evidence_event_id,
                "schema": {"name": "evidence_recorded", "version": "1.0.0"},
                "occurred_at": "2026-07-19T12:00:02.000Z",
                "causal_parents": (),
                "payload": {
                    "evidence_id": evidence_id,
                    "evidence_kind": "artifact",
                    "strength": "mutable_reference",
                    "observed_at": "2026-07-19T12:00:02.000Z",
                    "reference": "workflow-evidence-A",
                },
                "artifact_refs": (),
                "evidence_refs": (),
            },
        ),
    }
    published = await app.publish_work(PublishWorkRequest.model_validate(publish_evidence_wire))

    respond_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 613)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(published.result_frontier),
        "finding_id": finding.finding_id,
        "finding_frontier": _frontier(checked.result_frontier),
        "disposition": "acknowledged",
        "reason": "Addressed with newly published evidence rather than a bespoke reply.",
        "evidence_refs": (evidence_id,),
    }
    responded = await app.respond(RespondRequest.model_validate(respond_wire))

    assert responded.response.disposition == "acknowledged"
    assert tuple(item.reference_id for item in responded.response.evidence) == (evidence_id,)
    assert all(item.description is None for item in responded.response.evidence)

    # The published evidence is attributable ordinary ledger history, discoverable through the
    # existing read-only status surface rather than any reviewer-specific channel.
    evidence_status_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 6135)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "view": "evidence",
        "limit": "10",
        "at_frontier": str(responded.result_frontier.sequence),
    }
    evidence_status = await app.status(StatusRequest.model_validate(evidence_status_wire))
    evidence_page = cast(StatusEvidencePageModel, evidence_status.page)
    assert any(item.evidence_id == evidence_id for item in evidence_page.items)

    # The same frontier can still be rechecked with the ordinary check operation; no separate
    # "resolve challenge" operation exists.
    recheck_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 614)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(responded.result_frontier),
        "mode": "deterministic_only",
        "max_findings": "3",
    }
    rechecked = await app.check(CheckRequest.model_validate(recheck_wire))
    assert type(rechecked) is CheckCommitResult, f"unexpected nonterminal check: {type(rechecked)}"
    assert rechecked.subject_frontier == responded.result_frontier


async def test_response_and_waiver_never_resolve_finding() -> None:
    app, _runtime, _ = _build_app(seed_offset=4, waiver_authorizer=lambda _: True)
    started, checked, _obligation = await _bootstrap_finding(app, seed=700)
    finding = checked.findings[0]
    issue = (finding.kind, finding.policy_id, finding.policy_version, finding.subject_refs)

    waive_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 710), actor_type="human"),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(checked.result_frontier),
        "finding_id": finding.finding_id,
        "finding_frontier": _frontier(checked.result_frontier),
        "disposition": "waived",
        "reason": "Temporarily waived while triage continues.",
        "waiver_scope": "finding_only",
        # Already-expired relative to the fixed application clock (2026-07-19).
        "waiver_expiry": "2020-01-01T00:00:00.000Z",
    }
    waived = await app.respond(RespondRequest.model_validate(waive_wire))
    assert waived.response.disposition == "waived"
    assert waived.warning_codes == ("waiver_expired_at_recording",)

    recheck_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 711)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(waived.result_frontier),
        "mode": "deterministic_only",
        "max_findings": "3",
    }
    rechecked = await app.check(CheckRequest.model_validate(recheck_wire))
    assert type(rechecked) is CheckCommitResult, f"unexpected nonterminal check: {type(rechecked)}"

    # Neither the disposition nor an already-expired waiver resolved the issue: the very same
    # issue (kind/policy/subject) is still reported, under the finding_id already answered rather
    # than a fresh duplicate.
    assert rechecked.findings
    rechecked_issue = (
        rechecked.findings[0].kind,
        rechecked.findings[0].policy_id,
        rechecked.findings[0].policy_version,
        rechecked.findings[0].subject_refs,
    )
    assert rechecked_issue == issue
    assert rechecked.findings[0].finding_id == finding.finding_id


async def test_scoped_check_applicability_is_durable() -> None:
    app, _runtime, _ = _build_app(seed_offset=5)
    started, checked, _obligation = await _bootstrap_finding(app, seed=800)
    finding = checked.findings[0]
    issue = (finding.kind, finding.policy_id, finding.policy_version, finding.subject_refs)

    ack_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 810)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(checked.result_frontier),
        "finding_id": finding.finding_id,
        "finding_frontier": _frontier(checked.result_frontier),
        "disposition": "acknowledged",
    }
    acked = await app.respond(RespondRequest.model_validate(ack_wire))

    # Two consecutive rechecks at the current frontier with no new coverage repeat the exact same
    # durable issue identity: applicability is a stable structural fact, not a per-call guess.
    first_recheck_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 811)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(acked.result_frontier),
        "mode": "deterministic_only",
        "max_findings": "3",
    }
    first_recheck = await app.check(CheckRequest.model_validate(first_recheck_wire))
    assert type(first_recheck) is CheckCommitResult, (
        f"unexpected nonterminal check: {type(first_recheck)}"
    )
    second_recheck_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 812)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(first_recheck.result_frontier),
        "mode": "deterministic_only",
        "max_findings": "3",
    }
    second_recheck = await app.check(CheckRequest.model_validate(second_recheck_wire))
    assert type(second_recheck) is CheckCommitResult, (
        f"unexpected nonterminal check: {type(second_recheck)}"
    )

    for outcome in (first_recheck, second_recheck):
        assert outcome.findings
        outcome_issue = (
            outcome.findings[0].kind,
            outcome.findings[0].policy_id,
            outcome.findings[0].policy_version,
            outcome.findings[0].subject_refs,
        )
        assert outcome_issue == issue

    # A receipt built at the latest frontier reflects the same durable, still-unresolved issue.
    receipt_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 813)),
        "task_id": started.task_id,
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(second_recheck.result_frontier),
        "format": "json",
        "include": "standard",
        "redaction_profile": "full_local",
    }
    receipt = await app.receipt(ReceiptRequest.model_validate(receipt_wire))
    assert receipt.conclusion == "unresolved_findings_remain"


async def test_receipt_build_context_is_complete() -> None:
    app, _runtime, _ = _build_app(seed_offset=6)
    started, checked, _obligation = await _bootstrap_finding(app, seed=900)
    finding = checked.findings[0]

    respond_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 910)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(checked.result_frontier),
        "finding_id": finding.finding_id,
        "finding_frontier": _frontier(checked.result_frontier),
        "disposition": "acknowledged",
    }
    responded = await app.respond(RespondRequest.model_validate(respond_wire))

    receipt_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 911)),
        "task_id": started.task_id,
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(responded.result_frontier),
        "format": "json",
        "include": "standard",
        "redaction_profile": "full_local",
    }
    receipt = await app.receipt(ReceiptRequest.model_validate(receipt_wire))

    assert receipt.document is not None
    document = cast(Mapping[str, JsonValue], receipt.document)
    # The application-normalized build context is complete: current issue rows, coverage/gaps,
    # and the exact version slice are all present in the one built document, not assembled later.
    for key in (
        "receipt_id",
        "subject_frontier",
        "conclusion",
        "coverage",
        "findings",
        "obligations",
        "responses",
        "gaps",
        "versions",
    ):
        assert key in document, key
    findings = cast(tuple[Mapping[str, JsonValue], ...], document["findings"])
    assert any(cast(str, item["finding_id"]) == finding.finding_id for item in findings)
    versions = cast(Mapping[str, JsonValue], document["versions"])
    assert versions["package_version"] == "0.1.0"
    assert versions["resource_manifest_digest"] == _DIGEST
    # The response answers a finding this very check returned, so it reports on the check rather
    # than publishing untested work: the check stays attributed and its coverage folds in. The
    # receipt still declares the earlier-frontier gap, so nothing reads as re-checked here.
    assert "check_not_applicable" not in receipt.coverage.known_gaps
    assert "check_current_as_of_earlier_frontier" in receipt.coverage.known_gaps
    assert CheckType.DETERMINISTIC in receipt.coverage.check_types
    gaps = cast(tuple[Mapping[str, JsonValue], ...], document["gaps"])
    assert any(cast(str, gap["code"]) == "check_current_as_of_earlier_frontier" for gap in gaps)

    # The bare code is honest but not interpretable: the 2026-07-27 dogfood saw
    # `check_not_applicable` immediately after a check that succeeded with external provenance and
    # could not tell which of four readings was meant. The limitations section must say which.
    sections = cast(tuple[Mapping[str, JsonValue], ...], document["sections"])
    limitations = next(
        cast(str, section["body"])
        for section in sections
        if cast(str, section["key"]) == "limitations_and_coverage"
    )
    tested = checked.subject_frontier.sequence
    assert f"A check is recorded at subject frontier {tested} and still contributes here" in (
        limitations
    )
    assert "only responses to the findings it returned were published after it" in limitations
    assert f"Its verdict is current as of subject frontier {tested}" in limitations
    assert f"not frontier {receipt.subject_frontier.sequence}" in limitations
    assert "Re-run check to evaluate the later material" in limitations

    text_wire: dict[str, JsonValue] = {
        **receipt_wire,
        "request_id": protocol_id("req_", 912),
        "expected_frontier": _frontier(receipt.result_frontier),
        "format": "markdown",
    }
    text_receipt = await app.receipt(ReceiptRequest.model_validate(text_wire))
    assert text_receipt.document is None
    assert text_receipt.human_text is not None
    # Markdown/text project the canonical sections (#437), including the limitations body
    # that distinguishes check coverage from a compact finding count (#429).
    assert "Limitations" in text_receipt.human_text
    assert "unresolved" in text_receipt.human_text.lower()
    assert text_receipt.conclusion == receipt.conclusion


@pytest.mark.parametrize("resolved", (False, True), ids=("current", "resolved"))
async def test_receipt_folds_retained_observation_finding_coverage_after_recovery(
    resolved: bool,
) -> None:
    """Regression for #259, narrowed by #912.

    Observation advice records its own finding coverage inside the finding payload while the
    accepted engine-derived envelope remains current. A later healthy check can therefore have
    stronger current coverage without erasing the historical ``cursor_stale`` limitation carried
    by a retained finding that is still current: receipt construction must weaken to that history,
    not classify the valid state as ``STORAGE_CORRUPT``. Once a later qualifying check resolves the
    retained row, it stays in the document as history but its coverage no longer lowers the
    receipt, and no ``retained_finding_coverage`` gap is minted for it (issue #912).
    """

    # The current row keeps the exact 64-code receipt boundary: its retained 63 codes plus the
    # missing review of a local-only check on a route that requires one. A local-only check on a
    # route that does not records no review gap (#1041).
    app, runtime, _ = _build_app(seed_offset=16, semantic="disabled" if resolved else "required")
    started = await app.start(start_request(2500, title="Recovered observation coverage"))
    start_frontier = Frontier(int(started.frontier.sequence), started.frontier.head_digest)
    ledger, objects = next(iter(runtime.resources.values()))
    records = tuple(
        [
            record
            async for record in ledger.load_events(
                started.session_id, through=start_frontier.sequence
            )
        ]
    )
    assert records

    retained_gap_codes = tuple(
        sorted(
            {"cursor_stale", *(f"retained_capacity_{index:03d}" for index in range(62))},
            key=str.encode,
        )
    )
    assert len(retained_gap_codes) == 63
    retained_coverage = Coverage(
        publication_channels=(PublicationChannel.ENGINE_DERIVED,),
        authorship_assurance=AuthorshipAssurance.HARNESS_OBSERVED,
        artifact_observation=ArtifactObservation.HOOK_OBSERVED,
        evidence_immutability=EvidenceImmutability.METADATA_ONLY,
        ledger_freshness=LedgerFreshness.PARTIAL,
        check_types=(CheckType.DETERMINISTIC,),
        known_gaps=retained_gap_codes,
    )
    kind = FindingKind.LEDGER_STALE_OR_INCOMPLETE
    retained = Finding(
        finding_id(protocol_id("fnd_", 2501)),
        kind,
        FindingOrigin.DETERMINISTIC,
        FINDING_KIND_TRAITS[kind][0],
        "Observation delivery was stale.",
        "Observation delivery later recovered; retain this historical limitation.",
        (records[0].event_id,),
        "work-integrity",
        "0.1.0",
        start_frontier,
        retained_coverage,
        None,
    )
    payload = canonical_encode(encode_payload(retained))
    now = app.clock.now_utc()
    metadata = ObjectMetadata(
        ObjectKind.EVENT_PAYLOAD,
        media_type_for("finding_recorded"),
        started.task_id,
        now,
    )
    staged = await objects.stage(ObjectSource(data=payload, declared_size=len(payload)), metadata)
    payload_ref = await objects.finalize(staged)
    appended = await ledger.append_batch(
        AppendCommand(
            started.task_id,
            started.session_id,
            started.writer_id,
            protocol_id("req_", 2502),
            OperationKind.PUBLISH_WORK,
            _DIGEST,
            start_frontier.sequence,
            (
                AppendEntry(
                    EventDraft(
                        event_id(protocol_id("evt_", 2503)),
                        EventSchema("finding_recorded", "1.0.0"),
                        timestamp_from_datetime(now),
                        (),
                        retained,
                        (),
                        (),
                    ),
                    observation_author(),
                    payload_ref,
                    payload_ref.commitment,
                    metadata.media_type,
                    payload_ref.plaintext_size,
                    PublicationChannel.ENGINE_DERIVED,
                    coverage_for_channel(PublicationChannel.ENGINE_DERIVED),
                    "projected",
                ),
            ),
        )
    )

    check_frontier = appended.result_frontier
    if not resolved:
        # A provenance dispute pins the retained row current: the released status wire keeps it
        # ``resolved=false`` even after a qualifying check, so its history still folds.
        disputed = await app.respond(
            RespondRequest.model_validate(
                {
                    **_request_base(protocol_id("req_", 2506)),
                    "session_id": started.session_id,
                    "writer_id": started.writer_id,
                    "expected_frontier": _frontier(appended.result_frontier),
                    "finding_id": retained.finding_id,
                    "finding_frontier": _frontier(appended.result_frontier),
                    "disposition": "provenance_disputed",
                    "reason": "The retained observation row is disputed for this regression.",
                }
            )
        )
        check_frontier = disputed.result_frontier
    checked = await app.check(
        CheckRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 2504)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(check_frontier),
                "mode": "deterministic_only",
                "max_findings": "3",
            }
        )
    )
    assert type(checked) is CheckCommitResult
    assert checked.findings == ()
    assert "cursor_stale" not in checked.coverage.known_gaps

    receipt = await app.receipt(
        ReceiptRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 2505)),
                "task_id": started.task_id,
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(checked.result_frontier),
                "format": "json",
                "include": "standard",
                "redaction_profile": "full_local",
            }
        )
    )

    assert FINDING_KIND_TRAITS[kind][1] is False
    # Issue #986 (E2), #1041: with the retained row resolved, a local-only check on a route that
    # did not require AI-powered review leaves no gap at all; the disputed row's retained coverage
    # still bounds the conclusion.
    assert receipt.conclusion == (
        "no_unresolved_deterministic_findings" if resolved else "insufficient_coverage"
    )
    assert receipt.coverage.ledger_freshness is (
        LedgerFreshness.CURRENT if resolved else LedgerFreshness.PARTIAL
    )
    document = cast(Mapping[str, JsonValue], receipt.document)
    findings = cast(tuple[Mapping[str, JsonValue], ...], document["findings"])
    assert any(item["finding_id"] == retained.finding_id for item in findings)
    gaps = cast(tuple[Mapping[str, JsonValue], ...], document["gaps"])
    sections = {
        cast(Mapping[str, JsonValue], section)["key"]: cast(Mapping[str, JsonValue], section)
        for section in cast(list[JsonValue], document["sections"])
    }
    all_records = tuple([record async for record in ledger.load_events(started.session_id)])
    capacity = receipt_gap_codes(replay(all_records), all_records)
    if resolved:
        # History, not a limitation: listed as resolved and absent from the coverage fold.
        assert sections["summary"]["items"] == [retained.finding_id]
        assert receipt.coverage.known_gaps == ()
        assert not any(item["code"] == "cursor_stale" for item in gaps)
        assert "cursor_stale" not in capacity
        return
    assert sections["summary"]["items"] == []
    # The retained 63-code set plus semantic_review_not_requested exercises the exact public
    # boundary through real receipt construction and JSON projection, not only admission math.
    assert len(receipt.coverage.known_gaps) == 64
    assert "cursor_stale" in receipt.coverage.known_gaps
    assert sum(item["code"] == "cursor_stale" for item in gaps) == 1
    assert "cursor_stale" in capacity


async def test_legacy_receipt_coverage_overflow_is_not_invalid_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An internal 65-code fold is capacity exhaustion, not caller-malformed input."""

    app, _runtime, _ = _build_app(seed_offset=26)
    started = await app.start(start_request(2600, title="Legacy receipt coverage overflow"))

    def overflow(*_args: object, **_kwargs: object) -> object:
        raise ProtocolValueError("invalid_known_gap")

    monkeypatch.setattr("finishup.application.receipt._context", overflow)
    with pytest.raises(PublicOperationError) as caught:
        await app.receipt(
            ReceiptRequest.model_validate(
                {
                    **_request_base(protocol_id("req_", 2601)),
                    "task_id": started.task_id,
                    "session_id": started.session_id,
                    "writer_id": started.writer_id,
                    "expected_frontier": _frontier(started.frontier),
                    "format": "json",
                    "include": "standard",
                    "redaction_profile": "full_local",
                }
            )
        )
    assert caught.value.code is PublicErrorCode.LIMIT_EXCEEDED
    assert caught.value.retryable is False
    assert "capacity" in caught.value.message.lower()


async def test_successful_check_contributes_to_receipt_at_resulting_head() -> None:
    """2026-07-27 run-2 regression: a check at subject frontier N appends its own events
    (``check_recorded`` plus one ``finding_recorded`` per returned finding), landing past N.
    A receipt taken at that head must still count the check: applicability follows the material
    state, never frontier equality, which could never hold."""

    app, _runtime, _ = _build_app(seed_offset=7)
    started, checked, _obligation = await _bootstrap_finding(app, seed=1000)
    # The check's own events (one check_recorded plus one finding_recorded per returned finding)
    # advance the frontier past the tested subject, so strict frontier equality could never hold.
    assert checked.findings
    assert checked.result_frontier.sequence > checked.subject_frontier.sequence

    receipt_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 1010)),
        "task_id": started.task_id,
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(checked.result_frontier),
        "format": "json",
        "include": "standard",
        "redaction_profile": "full_local",
    }
    receipt = await app.receipt(ReceiptRequest.model_validate(receipt_wire))

    assert "check_not_applicable" not in receipt.coverage.known_gaps
    # The applicable check's coverage folds into the receipt, so its check types carry through.
    assert CheckType.DETERMINISTIC in receipt.coverage.check_types
    # The bootstrap finding is unresolved, so the conclusion still cannot be strong; what
    # changes is that the check now contributes instead of being dropped by frontier arithmetic.
    assert receipt.conclusion == "unresolved_findings_remain"
    assert receipt.suppressed_finding_count == 0

    # An immaterial advance never revokes the check: a receipt taken after the first receipt's
    # own ``receipt_recorded`` event still applies the same check.
    later_wire: dict[str, JsonValue] = {
        **receipt_wire,
        "request_id": protocol_id("req_", 1011),
        "expected_frontier": _frontier(receipt.result_frontier),
    }
    later = await app.receipt(ReceiptRequest.model_validate(later_wire))
    assert "check_not_applicable" not in later.coverage.known_gaps
    assert CheckType.DETERMINISTIC in later.coverage.check_types

    # Compact status reports the applicable check's coverage, not the newest envelope baseline:
    # the head record is the receipt's own engine-derived event (check_types=(none,)), yet the
    # check still shows through. This was the run-2 symptom (`check_types=["none"]` at head).
    status = await app.status(
        StatusRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 1012)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "view": "compact",
                "limit": "10",
            }
        )
    )
    compact = cast(StatusCompactPageModel, status.page)
    assert CheckType.DETERMINISTIC in compact.items[0].coverage.check_types


async def test_material_work_after_check_produces_check_not_applicable() -> None:
    """The gap still fires when it should: material work published after the check supersedes
    its verdict, and the limitations wording says exactly that."""

    app, _runtime, _ = _build_app(seed_offset=8)
    started, checked, _obligation = await _bootstrap_finding(app, seed=1100)

    publish_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 1110)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(checked.result_frontier),
        "event_drafts": (
            {
                "event_id": protocol_id("evt_", 1111),
                "schema": {"name": "claim_recorded", "version": "1.0.0"},
                "occurred_at": "2026-07-19T12:00:02.000Z",
                "causal_parents": (),
                "payload": {
                    "claim_id": protocol_id("clm_", 1112),
                    "claim_kind": "material",
                    "statement": "New material work landed after the check.",
                    "supporting_refs": (),
                    "obligation_refs": (),
                },
                "artifact_refs": (),
                "evidence_refs": (),
            },
        ),
    }
    published = await app.publish_work(PublishWorkRequest.model_validate(publish_wire))

    receipt = await app.receipt(
        ReceiptRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 1113)),
                "task_id": started.task_id,
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(published.result_frontier),
                "format": "json",
                "include": "standard",
                "redaction_profile": "full_local",
            }
        )
    )

    assert "check_not_applicable" in receipt.coverage.known_gaps
    assert receipt.document is not None
    document = cast(Mapping[str, JsonValue], receipt.document)
    sections = cast(tuple[Mapping[str, JsonValue], ...], document["sections"])
    limitations = next(
        cast(str, section["body"])
        for section in sections
        if cast(str, section["key"]) == "limitations_and_coverage"
    )
    assert "material work was published after it" in limitations
    assert "Re-run check at this frontier to restore coverage." in limitations


async def test_receipt_after_respond_keeps_semantic_check_coverage() -> None:
    """Issue #172: the guidance-mandated check -> respond -> receipt sequence used to drop the
    AI-powered review half of a successful check's coverage, leaving the receipt claiming only the
    ``deterministic`` baseline it would have carried with no check at all."""

    app, _runtime, _ = _build_app(seed_offset=9, semantic="optional")
    started, checked, _obligation = await _bootstrap_finding(
        app, seed=1200, mode="semantic_if_configured"
    )
    assert CheckType.SEMANTIC_MODEL_DERIVED in checked.coverage.check_types
    assert checked.findings

    frontier = checked.result_frontier
    for offset, finding in enumerate(checked.findings):
        responded = await app.respond(
            RespondRequest.model_validate(
                {
                    **_request_base(protocol_id("req_", 1210 + offset)),
                    "session_id": started.session_id,
                    "writer_id": started.writer_id,
                    "expected_frontier": _frontier(frontier),
                    "finding_id": finding.finding_id,
                    "finding_frontier": _frontier(checked.result_frontier),
                    "disposition": "acknowledged",
                }
            )
        )
        frontier = responded.result_frontier

    receipt = await app.receipt(
        ReceiptRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 1220)),
                "task_id": started.task_id,
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(frontier),
                "format": "json",
                "include": "standard",
                "redaction_profile": "full_local",
            }
        )
    )

    assert CheckType.SEMANTIC_MODEL_DERIVED in receipt.coverage.check_types
    assert CheckType.DETERMINISTIC in receipt.coverage.check_types
    assert "check_not_applicable" not in receipt.coverage.known_gaps
    assert "check_current_as_of_earlier_frontier" in receipt.coverage.known_gaps

    # Status reads the same ledger through the same predicate, so it cannot disagree.
    status = await app.status(
        StatusRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 1221)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "view": "compact",
                "limit": "10",
            }
        )
    )
    compact = cast(StatusCompactPageModel, status.page)
    assert CheckType.SEMANTIC_MODEL_DERIVED in compact.items[0].coverage.check_types


async def test_response_to_unreturned_finding_produces_check_not_applicable() -> None:
    """Only responses to the applicable check's own findings preserve it. A response to some
    other finding is untested work as far as that check is concerned, so the gap still fires."""

    app, _runtime, _ = _build_app(seed_offset=10)
    started, checked, obligation = await _bootstrap_finding(app, seed=1300)
    stale_finding = checked.findings[0]

    # Resolving the obligation retires the first check's issue, so the recheck no longer returns
    # that finding: the first check's finding is one the applicable (second) check never returned.
    evidence_id = protocol_id("evd_", 1314)
    resolve_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 1313)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(checked.result_frontier),
        "event_drafts": (
            {
                "event_id": protocol_id("evt_", 1315),
                "schema": {"name": "evidence_recorded", "version": "1.0.0"},
                "occurred_at": "2026-07-19T12:00:02.000Z",
                "causal_parents": (),
                "payload": {
                    "evidence_id": evidence_id,
                    "evidence_kind": "artifact",
                    "strength": "mutable_reference",
                    "observed_at": "2026-07-19T12:00:02.000Z",
                    "reference": "respond-exercise-result",
                },
                "artifact_refs": (),
                "evidence_refs": (),
            },
            {
                "event_id": protocol_id("evt_", 1316),
                "schema": {"name": "obligation_published", "version": "1.0.0"},
                "occurred_at": "2026-07-19T12:00:03.000Z",
                "causal_parents": (),
                "payload": {
                    "obligation_id": obligation,
                    "description": "Publish a result for the respond/status/receipt exercise.",
                    "acceptance_criteria": "A result is recorded in the task ledger.",
                    "evidence_expectation": "A linked immutable result record.",
                    "status": "resolved",
                    "resolution_evidence_refs": (evidence_id,),
                },
                "artifact_refs": (),
                "evidence_refs": (),
            },
        ),
    }
    resolved = await app.publish_work(PublishWorkRequest.model_validate(resolve_wire))

    rechecked = await app.check(
        CheckRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 1310)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(resolved.result_frontier),
                "mode": "deterministic_only",
                "max_findings": "3",
            }
        )
    )
    assert type(rechecked) is CheckCommitResult, f"unexpected nonterminal check: {type(rechecked)}"
    assert stale_finding.finding_id not in tuple(item.finding_id for item in rechecked.findings)

    # The recheck proved that finding absent, so it is verified_resolved and final (issue #905):
    # a response to it records nothing, and so cannot make the applicable check inapplicable.
    with pytest.raises(PublicOperationError) as terminal:
        await app.respond(
            RespondRequest.model_validate(
                {
                    **_request_base(protocol_id("req_", 1311)),
                    "session_id": started.session_id,
                    "writer_id": started.writer_id,
                    "expected_frontier": _frontier(rechecked.result_frontier),
                    "finding_id": stale_finding.finding_id,
                    "finding_frontier": _frontier(checked.result_frontier),
                    "disposition": "acknowledged",
                }
            )
        )
    assert terminal.value.safe_details is not None
    assert terminal.value.safe_details["reason_code"] == "finding_terminal"

    receipt = await app.receipt(
        ReceiptRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 1312)),
                "task_id": started.task_id,
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(rechecked.result_frontier),
                "format": "json",
                "include": "standard",
                "redaction_profile": "full_local",
            }
        )
    )

    assert "check_not_applicable" not in receipt.coverage.known_gaps
    assert "check_current_as_of_earlier_frontier" not in receipt.coverage.known_gaps


async def test_check_respond_recheck_reaches_a_fixed_point() -> None:
    """The documented cadence has a fixed point: acknowledging a finding and rechecking with no
    other new events converges on the already-answered record instead of minting a duplicate,
    flagging its own bookkeeping as staleness, and demanding yet another check."""

    app, _runtime, _ = _build_app(seed_offset=11)
    started, checked, _obligation = await _bootstrap_finding(app, seed=1400)

    frontier = checked.result_frontier
    for offset, finding in enumerate(checked.findings):
        acked = await app.respond(
            RespondRequest.model_validate(
                {
                    **_request_base(protocol_id("req_", 1410 + offset)),
                    "session_id": started.session_id,
                    "writer_id": started.writer_id,
                    "expected_frontier": _frontier(frontier),
                    "finding_id": finding.finding_id,
                    "finding_frontier": _frontier(checked.result_frontier),
                    "disposition": "acknowledged",
                }
            )
        )
        frontier = acked.result_frontier

    rechecked = await app.check(
        CheckRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 1420)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(frontier),
                "mode": "deterministic_only",
                "max_findings": "3",
            }
        )
    )
    assert type(rechecked) is CheckCommitResult, f"unexpected nonterminal check: {type(rechecked)}"

    # The unanswered issues are still reported, under the ids already acknowledged.
    assert tuple(item.finding_id for item in rechecked.findings) == tuple(
        item.finding_id for item in checked.findings
    )

    status = await app.status(
        StatusRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 1412)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "view": "compact",
                "limit": "10",
            }
        )
    )
    compact = cast(StatusCompactPageModel, status.page)
    item = compact.items[0]
    # The acknowledged finding is answered on the record and the recheck's own bookkeeping is not
    # material change, so nothing demands another cycle.
    assert item.unanswered_finding_count == "0"
    assert int(item.receipt_blocking_finding_count) > 0
    # A local-only check asked for on a route that requires no review declares no gap (#1041).
    assert status.closure_readiness.blocking_conditions == (
        "receipt_findings_unresolved",
        "no_plan_published",
    )
    assert item.freshness != "stale_after_material_change"

    # The MCP text fallback stands in for this exact result when a host drops structured content,
    # so it must report the singleton's own counters and freshness.
    summary = summary_for_status(status.as_json())
    assert f"freshness: {item.freshness}" in summary
    assert status.coverage.ledger_freshness.value == item.freshness
    assert "semantic_review_not_requested" not in status.coverage.known_gaps
    assert "check_not_applicable" not in status.coverage.known_gaps
    assert "unanswered findings: 0" in summary
    # ADR-046: the phrase is gone; the counters sentence carries the same number (to do + unmet).
    assert "receipt-blocking" not in summary


async def test_status_freshness_scalar_survives_immaterial_events() -> None:
    """Issue #307: a check that declared coverage gaps recorded ``partial`` freshness. The
    projection scalar reported that only on the event that recorded the check and reverted to
    ``current`` on the next event of any family, while the item's own
    ``coverage.ledger_freshness`` kept the gaps. One item then carried two disagreeing freshness
    fields, and an agent reading the summary line was told the ledger was clean.

    A receipt and a re-attach change nothing but the frontier and the session id, so the retained
    check still governs and its recorded freshness must still be what the item reports.
    """

    # A policy that requires review makes the local-only check's missing review a declared gap
    # (#1041: on a route that requires none it declares nothing).
    app, _runtime, _ = _build_app(seed_offset=27, semantic="required")
    started, checked, _obligation = await _bootstrap_finding(app, seed=1900)

    # `deterministic_only` declines the AI-powered review, which is a declared coverage gap, so the
    # check downgraded its own freshness. This is the precondition the bug needs.
    assert checked.coverage.ledger_freshness is LedgerFreshness.PARTIAL
    assert "semantic_review_not_requested" in checked.coverage.known_gaps

    def status_wire(seed: int) -> dict[str, JsonValue]:
        return {
            **_request_base(protocol_id("req_", seed)),
            "session_id": started.session_id,
            "writer_id": started.writer_id,
            "view": "compact",
            "limit": "10",
        }

    status = await app.status(StatusRequest.model_validate(status_wire(1910)))
    item = cast(StatusCompactPageModel, status.page).items[0]
    # Immediately after the check both fields already agreed; the bug was never visible here.
    assert item.freshness == "partial"
    assert item.coverage.ledger_freshness is LedgerFreshness.PARTIAL

    # A receipt appends one engine-derived `receipt_recorded`. It is not a material family, so it
    # cannot supersede the check, and nothing in the ledger changed except the frontier.
    receipt = await app.receipt(
        ReceiptRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 1911)),
                "task_id": started.task_id,
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(checked.result_frontier),
                "format": "json",
                "include": "standard",
                "redaction_profile": "full_local",
            }
        )
    )
    assert "check_not_applicable" not in receipt.coverage.known_gaps

    after_receipt = await app.status(StatusRequest.model_validate(status_wire(1912)))
    item_after = cast(StatusCompactPageModel, after_receipt.page).items[0]
    # The retained check still carries the gaps, so the scalar still has to report them.
    assert item_after.coverage.ledger_freshness is LedgerFreshness.PARTIAL
    assert "semantic_review_not_requested" in item_after.coverage.known_gaps
    assert item_after.freshness == "partial"
    assert item_after.freshness == item_after.coverage.ledger_freshness.value

    # The summary line an agent reads is derived from the scalar, so it must not read clean while
    # the structured coverage beside it records the gaps.
    summary = summary_for_status(after_receipt.as_json())
    assert "freshness: partial" in summary
    assert "freshness: current" not in summary


def _receipt_wire(
    request_seed: int,
    *,
    task_id: str,
    session: str,
    writer: str,
    frontier: Frontier | FrontierModel,
) -> dict[str, JsonValue]:
    return {
        **_request_base(protocol_id("req_", request_seed)),
        "task_id": task_id,
        "session_id": session,
        "writer_id": writer,
        "expected_frontier": _frontier(frontier),
        "format": "json",
        "include": "standard",
        "redaction_profile": "full_local",
    }


async def test_receipt_survives_reattach_through_create_or_attach() -> None:
    """Regression for issue #200.

    ``start mode=create_or_attach`` mints a fresh session for an existing task and appends one
    ordinary ``session_resumed`` event to the task-global ingestion/digest chain. Reading the
    ledger back through the attached session must therefore still yield the whole task chain: a
    session-filtered slice would start mid-chain and replay, which is genesis-anchored, would
    reject it as a corrupt projection.
    """

    app, _runtime, _ = _build_app(seed_offset=12)
    started, checked, obligation = await _bootstrap_finding(app, seed=1900, refs=True)

    before = await app.receipt(
        ReceiptRequest.model_validate(
            _receipt_wire(
                1910,
                task_id=started.task_id,
                session=started.session_id,
                writer=started.writer_id,
                frontier=checked.result_frontier,
            )
        )
    )
    assert before.subject_frontier == checked.result_frontier
    assert before.conclusion == "unresolved_findings_remain"

    attached = await app.start(
        start_request(1920, title="Respond/status/receipt exercise", refs=True)
    )
    assert attached.outcome == "attached"
    assert attached.task_id == started.task_id
    assert attached.session_id != started.session_id
    assert attached.writer_id != started.writer_id

    after = await app.receipt(
        ReceiptRequest.model_validate(
            _receipt_wire(
                1930,
                task_id=attached.task_id,
                session=attached.session_id,
                writer=attached.writer_id,
                frontier=attached.frontier,
            )
        )
    )

    # The receipt covers the whole task ledger, not the suffix this session authored: its subject
    # frontier is the attached head, which is strictly beyond the pre-resume receipt's.
    assert _frontier(after.subject_frontier) == _frontier(attached.frontier)
    assert after.subject_frontier.sequence > before.subject_frontier.sequence
    assert after.receipt_id != before.receipt_id

    # It also still reports the work published before the resume: the same unresolved conclusion,
    # from the same pre-resume check, over the same obligation.
    assert after.conclusion == before.conclusion
    assert after.suppressed_finding_count == before.suppressed_finding_count
    assert after.versions == before.versions
    document = cast(Mapping[str, JsonValue], after.document)
    assert obligation in canonical_encode(document).decode()

    # ``status view=candidate_findings`` reads the ledger the same way and was equally broken.
    candidates = await app.status(
        StatusRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 1940)),
                "session_id": attached.session_id,
                "writer_id": attached.writer_id,
                "view": "candidate_findings",
                "limit": "10",
                "at_frontier": str(after.result_frontier.sequence),
            }
        )
    )
    candidate_page = cast(StatusCandidateFindingsPageModel, candidates.page)
    assert candidate_page.items
    assert any(obligation in item.subject_refs for item in candidate_page.items)

    # The ordinary findings view is task-wide from the attached session too: the finding the
    # pre-resume check returned is still the finding on the record.
    findings = await app.status(
        StatusRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 1950)),
                "session_id": attached.session_id,
                "writer_id": attached.writer_id,
                "view": "findings",
                "limit": "10",
                "at_frontier": str(after.result_frontier.sequence),
            }
        )
    )
    findings_page = cast(StatusFindingsPageModel, findings.page)
    assert tuple(item.finding_id for item in findings_page.items) == tuple(
        item.finding_id for item in checked.findings
    )


async def test_dry_run_publish_survives_reattach_through_create_or_attach() -> None:
    """The dry-run preflight replays the task ledger too (issue #200).

    ``publish_work dry_run=true`` proves a batch would reduce by replaying the existing records
    with the provisional ones appended, and it converts any replay ``ValueError`` into
    ``EVENT_INVALID``. Reading a session-filtered slice therefore turned every dry run on a
    resumed task into an invalid batch, and made a draft citing a pre-resume event look like a
    missing causal parent rather than the valid reference it is.
    """

    app, _runtime, _ = _build_app(seed_offset=14)
    started, _checked, _obligation = await _bootstrap_finding(app, seed=2100, refs=True)
    # The obligation event ``_bootstrap_finding`` publishes, named the same way it names it.
    obligation_event_id = protocol_id("evt_", 2102)

    attached = await app.start(
        start_request(2120, title="Respond/status/receipt exercise", refs=True)
    )
    assert attached.outcome == "attached"
    assert attached.task_id == started.task_id
    assert attached.session_id != started.session_id

    action_event_id = protocol_id("evt_", 2131)
    preview = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 2130)),
                "session_id": attached.session_id,
                "writer_id": attached.writer_id,
                "expected_frontier": _frontier(attached.frontier),
                "dry_run": True,
                "event_drafts": (
                    {
                        "event_id": action_event_id,
                        "schema": {"name": "action_recorded", "version": "1.0.0"},
                        "occurred_at": "2026-07-19T12:00:02.000Z",
                        # Published before the resume, so the attached session can only cite it if
                        # the preflight reads the whole task chain.
                        "causal_parents": (obligation_event_id,),
                        "payload": {
                            "action_id": protocol_id("act_", 2132),
                            "action_kind": "other",
                            "description": "Continue the exercise from the attached session.",
                        },
                        "artifact_refs": (),
                        "evidence_refs": (),
                    },
                ),
            }
        )
    )

    assert type(preview) is PublishWorkResult, f"unexpected publish result: {type(preview)}"
    assert preview.ok is True
    assert preview.outcome == "dry_run"
    assert preview.subject_frontier.sequence == attached.frontier.sequence
    assert preview.result_frontier == preview.subject_frontier
    root = cast(PublishWorkDryRunModel, preview.root)
    assert root.evidential is False
    assert len(root.would_accept) == 1
    assert root.would_accept[0].event_id == action_event_id
    assert root.would_accept[0].causal_parents == (obligation_event_id,)

    # Duplicate detection stays task-wide as well: re-drafting a pre-resume event id is still an
    # invalid batch, so widening the read did not turn the preflight into a false positive.
    with pytest.raises(PublicOperationError) as caught:
        await app.publish_work(
            PublishWorkRequest.model_validate(
                {
                    **_request_base(protocol_id("req_", 2140)),
                    "session_id": attached.session_id,
                    "writer_id": attached.writer_id,
                    "expected_frontier": _frontier(attached.frontier),
                    "dry_run": True,
                    "event_drafts": (
                        {
                            "event_id": obligation_event_id,
                            "schema": {"name": "action_recorded", "version": "1.0.0"},
                            "occurred_at": "2026-07-19T12:00:03.000Z",
                            "causal_parents": (),
                            "payload": {
                                "action_id": protocol_id("act_", 2141),
                                "action_kind": "other",
                                "description": "Reuse an event id already on the task ledger.",
                            },
                            "artifact_refs": (),
                            "evidence_refs": (),
                        },
                    ),
                }
            )
        )
    assert caught.value.code is PublicErrorCode.EVENT_INVALID


async def test_reattach_detaches_the_prior_session_from_the_task_route() -> None:
    """The prior session stops being routable when a new one attaches (issue #200).

    Membership in the ledger is what ``load_events`` checks; *authority* to act on the task is a
    route question, and that is what a resumed START moves. This locks the contract that the fix
    for #200 must not weaken: widening the ledger read does not keep a superseded session
    routable.
    """

    app, _runtime, _ = _build_app(seed_offset=13)
    started, _checked, _obligation = await _bootstrap_finding(app, seed=2000, refs=True)

    assert await app.start_catalog.resolve_route(started.session_id) is not None

    attached = await app.start(
        start_request(2020, title="Respond/status/receipt exercise", refs=True)
    )
    assert attached.outcome == "attached"

    # Bounded, not an internal error: the superseded session no longer resolves to a route, which
    # both application routing and the real bundle runtime turn into SESSION_NOT_FOUND before any
    # ledger read.
    assert await app.start_catalog.resolve_route(started.session_id) is None
    resumed_route = await app.start_catalog.resolve_route(attached.session_id)
    assert resumed_route is not None
    assert resumed_route.task_id == attached.task_id

    # A session that never touched this task reads nothing from its ledger.
    ledger, _objects = _runtime.resources[attached.task_id]
    stranger = protocol_id("ses_", 2099)
    assert [record async for record in ledger.load_events(stranger)] == []


async def test_status_operation_after_reattach_recovers_prior_session_request() -> None:
    """Issue #438: view=operation from the successor session finds the prior request_id."""

    app, _runtime, _ = _build_app(seed_offset=14)
    started, checked, _obligation = await _bootstrap_finding(app, seed=2100, refs=True)

    attached = await app.start(
        start_request(2120, title="Respond/status/receipt exercise", refs=True)
    )
    assert attached.session_id != started.session_id
    recovered = await app.status(
        StatusRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 2130)),
                "session_id": attached.session_id,
                "writer_id": attached.writer_id,
                "view": "operation",
                "filter": {"operation_request_id": checked.request_id},
                "limit": "100",
            }
        )
    )
    page = recovered.page
    assert type(page) is StatusOperationPageModel
    assert page.found is True
    assert page.state == "complete"
    assert page.operation_kind == "check"

    assert await app.start_catalog.resolve_route(started.session_id) is None
    binding = await app.start_catalog.session_binding(started.session_id)
    assert binding is not None
    assert binding.session_id == attached.session_id
    assert binding.writer_id == attached.writer_id


async def test_explicit_sibling_handoff_preserves_predecessor_state_and_fresh_scope() -> None:
    """A bounded sibling keeps the predecessor receipt/findings/obligations as separate history."""

    app, _runtime, _ = _build_app(seed_offset=15)
    started, checked, predecessor_obligation = await _bootstrap_finding(app, seed=2300, refs=True)

    predecessor_findings_status = await app.status(
        StatusRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 2310)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "view": "findings",
                "limit": "10",
                "at_frontier": str(checked.result_frontier.sequence),
            }
        )
    )
    predecessor_findings = cast(StatusFindingsPageModel, predecessor_findings_status.page)
    predecessor_finding_ids = tuple(item.finding_id for item in predecessor_findings.items)
    assert predecessor_finding_ids

    predecessor_obligations_status = await app.status(
        StatusRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 2311)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "view": "obligations",
                "limit": "10",
                "at_frontier": str(checked.result_frontier.sequence),
            }
        )
    )
    predecessor_obligations = cast(StatusObligationsPageModel, predecessor_obligations_status.page)
    assert tuple(item.obligation_id for item in predecessor_obligations.items) == (
        predecessor_obligation,
    )

    predecessor_receipt = await app.receipt(
        ReceiptRequest.model_validate(
            _receipt_wire(
                2312,
                task_id=started.task_id,
                session=started.session_id,
                writer=started.writer_id,
                frontier=checked.result_frontier,
            )
        )
    )
    assert predecessor_receipt.conclusion == "unresolved_findings_remain"

    sibling_wire = start_request(2320, title="Bounded repaired verification", refs=True).model_dump(
        mode="json", exclude_none=True
    )
    sibling_wire["mode"] = "create"
    sibling_wire["external_ref"] = "issue-613-recovery-v1"
    sibling = await app.start(StartRequest.model_validate(sibling_wire))
    assert sibling.task_id != started.task_id
    assert sibling.session_id != started.session_id
    assert sibling.writer_id != started.writer_id

    sibling_obligation = protocol_id("obl_", 2321)
    sibling_evidence = protocol_id("evd_", 2322)
    sibling_published = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 2323)),
                "session_id": sibling.session_id,
                "writer_id": sibling.writer_id,
                "expected_frontier": _frontier(sibling.frontier),
                "event_drafts": (
                    {
                        "event_id": protocol_id("evt_", 2324),
                        "schema": {"name": "plan_published", "version": "1.0.0"},
                        "occurred_at": "2026-07-19T12:00:02.000Z",
                        "causal_parents": (),
                        "payload": {
                            "plan_version": 1,
                            "summary": "Run the bounded repaired verification scope.",
                            "obligation_refs": (sibling_obligation,),
                        },
                        "artifact_refs": (),
                        "evidence_refs": (),
                    },
                    {
                        "event_id": protocol_id("evt_", 2325),
                        "schema": {"name": "obligation_published", "version": "1.0.0"},
                        "occurred_at": "2026-07-19T12:00:03.000Z",
                        "causal_parents": (),
                        "payload": {
                            "obligation_id": sibling_obligation,
                            "description": "Complete the repaired verification scope.",
                            "acceptance_criteria": "A new check covers the repaired scope.",
                            "evidence_expectation": "A caller-published test result commitment.",
                            "status": "open",
                        },
                        "artifact_refs": (),
                        "evidence_refs": (),
                    },
                    {
                        "event_id": protocol_id("evt_", 2326),
                        "schema": {"name": "evidence_recorded", "version": "1.0.0"},
                        "occurred_at": "2026-07-19T12:00:04.000Z",
                        "causal_parents": (),
                        "payload": {
                            "evidence_id": sibling_evidence,
                            "evidence_kind": "test_result",
                            "strength": "content_digest",
                            "content_digest": "sha256:" + "b" * 64,
                            "observed_at": "2026-07-19T12:00:04.000Z",
                            "description": "A caller-published repaired-scope test result commitment.",
                        },
                        "artifact_refs": (),
                        "evidence_refs": (),
                    },
                ),
            }
        )
    )
    assert type(sibling_published) is PublishWorkInternalResult

    sibling_checked = await app.check(
        CheckRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 2327)),
                "session_id": sibling.session_id,
                "writer_id": sibling.writer_id,
                "expected_frontier": _frontier(sibling_published.result_frontier),
                "mode": "deterministic_only",
                "max_findings": "3",
            }
        )
    )
    assert type(sibling_checked) is CheckCommitResult

    sibling_evidence_status = await app.status(
        StatusRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 2328)),
                "session_id": sibling.session_id,
                "writer_id": sibling.writer_id,
                "view": "evidence",
                "limit": "10",
                "at_frontier": str(sibling_checked.result_frontier.sequence),
            }
        )
    )
    sibling_evidence_page = cast(StatusEvidencePageModel, sibling_evidence_status.page)
    assert any(item.evidence_id == sibling_evidence for item in sibling_evidence_page.items)

    sibling_receipt = await app.receipt(
        ReceiptRequest.model_validate(
            _receipt_wire(
                2329,
                task_id=sibling.task_id,
                session=sibling.session_id,
                writer=sibling.writer_id,
                frontier=sibling_checked.result_frontier,
            )
        )
    )
    sibling_document = cast(Mapping[str, JsonValue], sibling_receipt.document)
    sibling_document_bytes = canonical_encode(sibling_document)
    assert sibling_obligation.encode() in sibling_document_bytes
    assert predecessor_obligation.encode() not in sibling_document_bytes
    assert predecessor_finding_ids[0].encode() not in sibling_document_bytes

    # The predecessor was never mutated by the sibling's plan, evidence, check, or receipt.
    predecessor_findings_after_status = await app.status(
        StatusRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 2330)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "view": "findings",
                "limit": "10",
            }
        )
    )
    predecessor_findings_after = cast(
        StatusFindingsPageModel, predecessor_findings_after_status.page
    )
    assert predecessor_findings_after_status.subject_frontier == predecessor_receipt.result_frontier
    assert predecessor_findings_after_status.result_frontier == predecessor_receipt.result_frontier
    assert tuple(
        item.model_dump(mode="json") for item in predecessor_findings_after.items
    ) == tuple(item.model_dump(mode="json") for item in predecessor_findings.items)

    predecessor_obligations_after_status = await app.status(
        StatusRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 2331)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "view": "obligations",
                "limit": "10",
            }
        )
    )
    predecessor_obligations_after = cast(
        StatusObligationsPageModel, predecessor_obligations_after_status.page
    )
    assert (
        predecessor_obligations_after_status.subject_frontier == predecessor_receipt.result_frontier
    )
    assert (
        predecessor_obligations_after_status.result_frontier == predecessor_receipt.result_frontier
    )
    assert tuple(
        item.model_dump(mode="json") for item in predecessor_obligations_after.items
    ) == tuple(item.model_dump(mode="json") for item in predecessor_obligations.items)

    # Re-read the original receipt through its idempotent request, without creating a new one.
    predecessor_receipt_after = await app.receipt(
        ReceiptRequest.model_validate(
            _receipt_wire(
                2312,
                task_id=started.task_id,
                session=started.session_id,
                writer=started.writer_id,
                frontier=checked.result_frontier,
            )
        )
    )
    assert predecessor_receipt_after.subject_frontier == predecessor_receipt.subject_frontier
    assert predecessor_receipt_after.conclusion == predecessor_receipt.conclusion
    assert predecessor_receipt_after.coverage == predecessor_receipt.coverage
    assert predecessor_receipt_after.receipt_id == predecessor_receipt.receipt_id
    assert predecessor_receipt_after.receipt_digest == predecessor_receipt.receipt_digest
    predecessor_document = cast(Mapping[str, JsonValue], predecessor_receipt_after.document)
    assert predecessor_obligation.encode() in canonical_encode(predecessor_document)


async def _drain_observation_record(
    app: Application,
    runtime: _WorkflowRuntime,
    started: StartInternalResult,
    *,
    seed: int,
    expected_frontier: int,
    finding: Finding | None = None,
    operation_kind: OperationKind = OperationKind.PUBLISH_WORK,
):
    """Append one observation-authored record straight to the ledger, standing in for the hook
    drain that keeps moving the head between an agent's calls (issue #320)."""

    ledger, objects = next(iter(runtime.resources.values()))
    now = app.clock.now_utc()
    if finding is None:
        schema_name = "evidence_recorded"
        schema = EventSchema("evidence_recorded", EVIDENCE_SCHEMA_VERSION)
        channel = PublicationChannel.HOOK_OBSERVED
        payload: Finding | EvidenceRecordedPayload = EvidenceRecordedPayload(
            evidence_id(protocol_id("evd_", seed)),
            EvidenceKind.ARTIFACT,
            EvidenceImmutability.MUTABLE_REFERENCE,
            timestamp_from_datetime(now),
            reference="hook-observation-note",
        )
    else:
        schema_name = "finding_recorded"
        schema = EventSchema("finding_recorded", "1.0.0")
        channel = PublicationChannel.ENGINE_DERIVED
        payload = finding
    encoded = canonical_encode(encode_payload(payload))
    metadata = ObjectMetadata(
        ObjectKind.EVENT_PAYLOAD, media_type_for(schema_name), started.task_id, now
    )
    staged = await objects.stage(ObjectSource(data=encoded, declared_size=len(encoded)), metadata)
    payload_ref = await objects.finalize(staged)
    result_object_ref = None
    if operation_kind is OperationKind.RECEIPT:
        receipt_metadata = ObjectMetadata(
            ObjectKind.RECEIPT,
            "application/vnd.yoetz.receipt+json",
            started.task_id,
            now,
        )
        receipt_staged = await objects.stage(
            ObjectSource(data=b"{}", declared_size=2), receipt_metadata
        )
        result_object_ref = await objects.finalize(receipt_staged)
    return await ledger.append_batch(
        AppendCommand(
            started.task_id,
            started.session_id,
            started.writer_id,
            protocol_id("req_", seed + 1),
            operation_kind,
            _DIGEST,
            expected_frontier,
            (
                AppendEntry(
                    EventDraft(
                        event_id(protocol_id("evt_", seed + 2)),
                        schema,
                        timestamp_from_datetime(now),
                        (),
                        payload,
                        (),
                        (),
                    ),
                    observation_author(),
                    payload_ref,
                    payload_ref.commitment,
                    metadata.media_type,
                    payload_ref.plaintext_size,
                    channel,
                    coverage_for_channel(channel),
                    "projected",
                ),
            ),
            result_object_ref,
        )
    )


async def _drain_observation_work_sequence(
    app: Application,
    runtime: _WorkflowRuntime,
    started: StartInternalResult,
    *,
    seed: int,
    expected_frontier: int,
):
    """Append a non-empty hook-observed action/result/decision suffix like issue #361."""

    ledger, objects = next(iter(runtime.resources.values()))
    now = app.clock.now_utc()
    observed_action_id = action_id(protocol_id("act_", seed))
    payloads: tuple[
        tuple[str, ActionRecordedPayload | ResultRecordedPayload | DecisionRecordedPayload], ...
    ] = (
        (
            "action_recorded",
            ActionRecordedPayload(
                observed_action_id,
                ActionKind.OTHER,
                "Hook observed a completed tool action.",
            ),
        ),
        (
            "result_recorded",
            ResultRecordedPayload(
                result_id(protocol_id("res_", seed + 1)),
                observed_action_id,
                ResultOutcome.SUCCESS,
                summary="The observed tool action completed.",
            ),
        ),
        (
            "decision_recorded",
            DecisionRecordedPayload(
                "Observation delivery completed.",
                "The hook grouped the observed action and result.",
                observation_author().actor_id,
            ),
        ),
    )
    entries: list[AppendEntry] = []
    for offset, (schema_name, payload) in enumerate(payloads):
        encoded = canonical_encode(encode_payload(payload))
        metadata = ObjectMetadata(
            ObjectKind.EVENT_PAYLOAD, media_type_for(schema_name), started.task_id, now
        )
        staged = await objects.stage(
            ObjectSource(data=encoded, declared_size=len(encoded)), metadata
        )
        payload_ref = await objects.finalize(staged)
        entries.append(
            AppendEntry(
                EventDraft(
                    event_id(protocol_id("evt_", seed + 10 + offset)),
                    EventSchema(schema_name, "1.0.0"),
                    timestamp_from_datetime(now),
                    (),
                    payload,
                    (),
                    (),
                ),
                observation_author(),
                payload_ref,
                payload_ref.commitment,
                metadata.media_type,
                payload_ref.plaintext_size,
                PublicationChannel.HOOK_OBSERVED,
                coverage_for_channel(PublicationChannel.HOOK_OBSERVED),
                "projected",
            )
        )
    return await ledger.append_batch(
        AppendCommand(
            started.task_id,
            started.session_id,
            started.writer_id,
            protocol_id("req_", seed + 20),
            OperationKind.PUBLISH_WORK,
            _DIGEST,
            expected_frontier,
            tuple(entries),
            None,
        )
    )


async def _drain_host_observation_gaps(
    app: Application,
    runtime: _WorkflowRuntime,
    started: StartInternalResult,
    *,
    seed: int,
    expected_frontier: int,
    known_gaps: tuple[str, ...] = (
        "content_unselected",
        "host_outcome_unavailable",
        "unpaired_event",
    ),
):
    """Append an observation whose structured event is readable but captured bytes are absent."""

    ledger, objects = next(iter(runtime.resources.values()))
    now = app.clock.now_utc()
    captured_object_id = object_id(protocol_id("obj_", seed + 2))
    payload = EvidenceRecordedPayload(
        evidence_id(protocol_id("evd_", seed + 3)),
        EvidenceKind.ARTIFACT,
        EvidenceImmutability.IMMUTABLE_SNAPSHOT,
        timestamp_from_datetime(now),
        captured_object_id=captured_object_id,
        content_digest="sha256:" + "9" * 64,
        description="The host captured content but the frozen bytes are unavailable.",
    )
    encoded = canonical_encode(encode_payload(payload))
    metadata = ObjectMetadata(
        ObjectKind.EVENT_PAYLOAD, media_type_for("evidence_recorded"), started.task_id, now
    )
    staged = await objects.stage(ObjectSource(data=encoded, declared_size=len(encoded)), metadata)
    payload_ref = await objects.finalize(staged)
    coverage = replace(
        coverage_for_channel(PublicationChannel.HOOK_OBSERVED),
        ledger_freshness=LedgerFreshness.REDACTED_GAP,
        known_gaps=known_gaps,
    )
    return await ledger.append_batch(
        AppendCommand(
            started.task_id,
            started.session_id,
            started.writer_id,
            protocol_id("req_", seed),
            OperationKind.PUBLISH_WORK,
            _DIGEST,
            expected_frontier,
            (
                AppendEntry(
                    EventDraft(
                        event_id(protocol_id("evt_", seed + 1)),
                        EventSchema("evidence_recorded", "1.0.0"),
                        timestamp_from_datetime(now),
                        (),
                        payload,
                        (captured_object_id,),
                        (),
                    ),
                    observation_author(),
                    payload_ref,
                    payload_ref.commitment,
                    metadata.media_type,
                    payload_ref.plaintext_size,
                    PublicationChannel.HOOK_OBSERVED,
                    coverage,
                    "projected",
                ),
            ),
        )
    )


def _drained_finding(subject_event_id: str, frontier: Frontier, seed: int) -> Finding:
    kind = FindingKind.LEDGER_STALE_OR_INCOMPLETE
    return Finding(
        finding_id(protocol_id("fnd_", seed)),
        kind,
        FindingOrigin.DETERMINISTIC,
        FINDING_KIND_TRAITS[kind][0],
        "Observation advice materialized a finding mid-drain.",
        "Re-run the check at the current head to cover it.",
        (event_id(subject_event_id),),
        "work-integrity",
        "0.1.0",
        frontier,
        Coverage(
            publication_channels=(PublicationChannel.ENGINE_DERIVED,),
            authorship_assurance=AuthorshipAssurance.HARNESS_OBSERVED,
            artifact_observation=ArtifactObservation.HOOK_OBSERVED,
            evidence_immutability=EvidenceImmutability.METADATA_ONLY,
            ledger_freshness=LedgerFreshness.PARTIAL,
            check_types=(CheckType.DETERMINISTIC,),
            known_gaps=("cursor_stale",),
        ),
        None,
    )


async def test_check_freeze_tolerates_observation_only_drain() -> None:
    """Regression for #320 (check side).

    A check whose expected frontier went stale to observation-only motion must not conflict:
    freeze acquisition accepts the held frontier and freezes at the real head, so the case covers
    the drained records instead of racing them.
    """

    app, runtime, _ = _build_app(seed_offset=20)
    started, checked, _obligation = await _bootstrap_finding(app, seed=3100)
    drained = await _drain_observation_record(
        app, runtime, started, seed=3110, expected_frontier=checked.result_frontier.sequence
    )

    recheck_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 3120)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        # Stale on purpose: the drain moved the head after this frontier was read.
        "expected_frontier": _frontier(checked.result_frontier),
        "mode": "deterministic_only",
        "max_findings": "3",
    }
    rechecked = await app.check(CheckRequest.model_validate(recheck_wire))
    assert type(rechecked) is CheckCommitResult, f"unexpected nonterminal check: {type(rechecked)}"
    assert rechecked.subject_frontier == drained.result_frontier


async def test_receipt_tolerates_observation_only_drain() -> None:
    """Regression for #320 (receipt side, the session 01a013c1 livelock).

    A receipt whose expected frontier went stale to observation-only, finding-free motion pins to
    that frontier: the case replays the genesis prefix and the locator event appends past the
    drained head, instead of the retry loop racing the drain forever.
    """

    app, runtime, _ = _build_app(seed_offset=21)
    started, checked, _obligation = await _bootstrap_finding(app, seed=3200)
    finding = checked.findings[0]
    respond_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 3210)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(checked.result_frontier),
        "finding_id": finding.finding_id,
        "finding_frontier": _frontier(checked.result_frontier),
        "disposition": "acknowledged",
    }
    responded = await app.respond(RespondRequest.model_validate(respond_wire))

    first = await _drain_observation_record(
        app, runtime, started, seed=3220, expected_frontier=responded.result_frontier.sequence
    )
    second = await _drain_observation_record(
        app, runtime, started, seed=3230, expected_frontier=first.result_frontier.sequence
    )

    receipt_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 3240)),
        "task_id": started.task_id,
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        # Stale on purpose: two observation records landed after the respond result was read.
        "expected_frontier": _frontier(responded.result_frontier),
        "format": "json",
        "include": "standard",
        "redaction_profile": "full_local",
    }
    receipt = await app.receipt(ReceiptRequest.model_validate(receipt_wire))

    assert receipt.subject_frontier == responded.result_frontier
    assert receipt.result_frontier.sequence == second.result_frontier.sequence + 1
    # The pinned case is the same truth an undrained receipt would have documented.
    assert receipt.conclusion == "unresolved_findings_remain"


def _forbid_genesis_replay(monkeypatch: pytest.MonkeyPatch, why: str) -> None:
    def forbidden(*_args: object) -> object:
        pytest.fail(why)

    monkeypatch.setattr("finishup.application.ledger_snapshot._replay_until_cancelled", forbidden)
    monkeypatch.setattr("finishup.kernel.deterministic_checks.replay", forbidden)
    monkeypatch.setattr("finishup.adapters.memory.ledger.replay", forbidden)
    monkeypatch.setattr("finishup.adapters.memory.ledger.replay_with_index", forbidden)


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
async def test_stale_frontier_respond_and_receipt_never_replay_from_genesis(
    backend: Literal["memory", "sqlite"], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Issue #886: the normal live case is one or more observation drains behind the head.

    Respond reads its finding at the older check frontier and receipt pins to a frontier the
    hook drain already moved past. Both must reuse adapter-owned projections (live head or a
    retained exact frontier) instead of re-reducing the whole ledger, and still produce the same
    facts as the undrained path.
    """

    app, runtime, _ = _build_app(seed_offset=86, ledger_backend=backend)
    started, checked, _obligation = await _bootstrap_finding(app, seed=8600)
    finding = checked.findings[0]
    head = checked.result_frontier
    for offset in range(3):
        drained = await _drain_observation_record(
            app, runtime, started, seed=8610 + offset * 10, expected_frontier=head.sequence
        )
        head = drained.result_frontier
    ledger, _objects = next(iter(runtime.resources.values()))
    records = tuple([row async for row in ledger.load_events(started.session_id)])
    # The retained projection at the stale check frontier is exactly the genesis replay.
    retained = await ledger.load_trusted_projection(started.session_id, checked.result_frontier)
    assert retained is not None
    assert retained == replay(records[: checked.result_frontier.sequence])

    _forbid_genesis_replay(monkeypatch, "stale-frontier respond/receipt must not replay")
    responded = await app.respond(
        RespondRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 8650)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(head),
                "finding_id": finding.finding_id,
                "finding_frontier": _frontier(checked.result_frontier),
                "disposition": "acknowledged",
            }
        )
    )
    assert responded.result_frontier.sequence == head.sequence + 1

    after_respond = await _drain_observation_record(
        app,
        runtime,
        started,
        seed=8660,
        expected_frontier=responded.result_frontier.sequence,
    )
    receipt = await app.receipt(
        ReceiptRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 8670)),
                "task_id": started.task_id,
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                # One observation drain behind the live head.
                "expected_frontier": _frontier(responded.result_frontier),
                "format": "json",
                "include": "standard",
                "redaction_profile": "full_local",
            }
        )
    )
    assert receipt.subject_frontier == responded.result_frontier
    assert receipt.result_frontier.sequence == after_respond.result_frontier.sequence + 1
    assert receipt.conclusion == "unresolved_findings_remain"
    monkeypatch.undo()
    # The incrementally extended live projection is the genesis replay of the final chain.
    final = tuple([row async for row in ledger.load_events(started.session_id)])
    stored = await ledger.load_projection(started.session_id, ProjectionView.CANDIDATE_FINDINGS)
    assert stored is not None and stored.state == replay(final)


async def test_stale_finding_frontier_outside_the_current_chain_is_still_rejected() -> None:
    app, runtime, _ = _build_app(seed_offset=87)
    started, checked, _obligation = await _bootstrap_finding(app, seed=8700)
    drained = await _drain_observation_record(
        app, runtime, started, seed=8710, expected_frontier=checked.result_frontier.sequence
    )
    forged = {
        "sequence": str(checked.result_frontier.sequence),
        "head_digest": "sha256:" + "0" * 64,
    }
    with pytest.raises(PublicOperationError) as raised:
        await app.respond(
            RespondRequest.model_validate(
                {
                    **_request_base(protocol_id("req_", 8750)),
                    "session_id": started.session_id,
                    "writer_id": started.writer_id,
                    "expected_frontier": _frontier(drained.result_frontier),
                    "finding_id": checked.findings[0].finding_id,
                    "finding_frontier": forged,
                    "disposition": "acknowledged",
                }
            )
        )
    assert raised.value.code in {
        PublicErrorCode.FRONTIER_CONFLICT,
        PublicErrorCode.INVALID_REQUEST,
    }


@pytest.mark.parametrize("ledger_backend", ("memory", "sqlite"))
async def test_finding_free_observation_work_keeps_check_applicable(
    ledger_backend: Literal["memory", "sqlite"],
) -> None:
    """Issue #361: delivered hook work is observation, not untested cooperative work.

    Exercise both public receipt construction and append-time capacity over the memory oracle and
    durable SQLite implementation. The suffix deliberately has more than one record and uses the
    action/result/decision families from the live occurrence.
    """

    app, runtime, _ = _build_app(seed_offset=28, ledger_backend=ledger_backend)
    started, checked, _obligation = await _bootstrap_finding(app, seed=3700)
    finding = checked.findings[0]
    responded = await app.respond(
        RespondRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 3710)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(checked.result_frontier),
                "finding_id": finding.finding_id,
                "finding_frontier": _frontier(checked.result_frontier),
                "disposition": "acknowledged",
            }
        )
    )
    observed = await _drain_observation_work_sequence(
        app,
        runtime,
        started,
        seed=3720,
        expected_frontier=responded.result_frontier.sequence,
    )

    ledger, _objects = next(iter(runtime.resources.values()))
    records = tuple([record async for record in ledger.load_events(started.session_id)])
    projection = replay(records)
    capacity_gaps = receipt_gap_codes(projection, records)
    assert "check_not_applicable" not in capacity_gaps
    assert "check_current_as_of_earlier_frontier" in capacity_gaps

    status = await app.status(
        StatusRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 3740)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "view": "compact",
                "limit": "10",
            }
        )
    )
    compact = cast(StatusCompactPageModel, status.page)
    assert CheckType.DETERMINISTIC in compact.items[0].coverage.check_types
    assert compact.items[0].freshness != LedgerFreshness.STALE_AFTER_MATERIAL_CHANGE.value
    # Status and the receipt must expose the same earlier-frontier qualification. The suffix is
    # attributable observation work, so the check remains useful, but compact status must not
    # silently report the current ledger as fully covered.
    assert "check_current_as_of_earlier_frontier" in compact.items[0].coverage.known_gaps
    assert "check_current_as_of_earlier_frontier" in compact.items[0].gaps
    assert "check_current_as_of_earlier_frontier" in status.coverage.known_gaps
    assert "coverage_gaps_declared" in status.closure_readiness.blocking_conditions

    receipt = await app.receipt(
        ReceiptRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 3750)),
                "task_id": started.task_id,
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(observed.result_frontier),
                "format": "json",
                "include": "standard",
                "redaction_profile": "full_local",
            }
        )
    )
    assert "check_not_applicable" not in receipt.coverage.known_gaps
    assert "check_current_as_of_earlier_frontier" in receipt.coverage.known_gaps
    assert CheckType.DETERMINISTIC in receipt.coverage.check_types
    # Issue #657: the suffix here is a check-answering response followed by finding-free host
    # observations, so the explanation must disclose the mixture rather than claim responses only.
    assert receipt.document is not None
    limitations = _limitations_body(receipt.document)
    assert "responses to the findings it returned and finding-free host observations" in (
        limitations
    )
    assert "only responses to the findings it returned" not in limitations
    assert f"not frontier {receipt.subject_frontier.sequence}" in limitations


def _limitations_body(document: object) -> str:
    sections = cast(
        tuple[Mapping[str, JsonValue], ...],
        cast(Mapping[str, JsonValue], document)["sections"],
    )
    return next(
        cast(str, section["body"])
        for section in sections
        if cast(str, section["key"]) == "limitations_and_coverage"
    )


@pytest.mark.parametrize("ledger_backend", ("memory", "sqlite"))
async def test_observation_only_suffix_is_named_as_observations(
    ledger_backend: Literal["memory", "sqlite"],
) -> None:
    """Issue #657: a check followed only by finding-free host observations stays attributable,
    and the receipt must say observations were retained but not evaluated. It must not claim
    that finding responses were published, and it must keep the tested boundary explicit."""

    app, runtime, _ = _build_app(seed_offset=29, ledger_backend=ledger_backend)
    started, checked, _obligation = await _bootstrap_finding(app, seed=3800)
    observed = await _drain_observation_work_sequence(
        app,
        runtime,
        started,
        seed=3820,
        expected_frontier=checked.result_frontier.sequence,
    )

    receipt = await app.receipt(
        ReceiptRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 3850)),
                "task_id": started.task_id,
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(observed.result_frontier),
                "format": "json",
                "include": "standard",
                "redaction_profile": "full_local",
            }
        )
    )
    assert "check_not_applicable" not in receipt.coverage.known_gaps
    assert "check_current_as_of_earlier_frontier" in receipt.coverage.known_gaps
    assert CheckType.DETERMINISTIC in receipt.coverage.check_types
    assert receipt.document is not None
    limitations = _limitations_body(receipt.document)
    tested = checked.subject_frontier.sequence
    assert f"A check is recorded at subject frontier {tested} and still contributes here" in (
        limitations
    )
    assert "finding-free host observations" in limitations
    assert "not evaluated by that check" in limitations
    assert "responses to the findings it returned" not in limitations
    assert f"Its verdict is current as of subject frontier {tested}" in limitations
    assert f"not frontier {receipt.subject_frontier.sequence}" in limitations
    assert "Re-run check to evaluate the later material" in limitations

    # The same sentence reaches every delivery rendering (markdown/text project the sections).
    text_receipt = await app.receipt(
        ReceiptRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 3851)),
                "task_id": started.task_id,
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(receipt.result_frontier),
                "format": "text",
                "include": "standard",
                "redaction_profile": "full_local",
            }
        )
    )
    assert text_receipt.human_text is not None
    assert "finding-free host observations" in text_receipt.human_text
    assert "responses to the findings it returned" not in text_receipt.human_text


@pytest.mark.parametrize("ledger_backend", ("memory", "sqlite"))
async def test_observation_finding_still_invalidates_check(
    ledger_backend: Literal["memory", "sqlite"],
) -> None:
    """Issue #361 positive control: a hook-observed finding remains uncovered new truth."""

    app, runtime, _ = _build_app(seed_offset=29, ledger_backend=ledger_backend)
    started, checked, _obligation = await _bootstrap_finding(app, seed=3800)
    drained = await _drain_observation_record(
        app,
        runtime,
        started,
        seed=3810,
        expected_frontier=checked.result_frontier.sequence,
        finding=_drained_finding(
            protocol_id("evt_", 3802),
            Frontier(int(checked.result_frontier.sequence), checked.result_frontier.head_digest),
            3815,
        ),
    )
    ledger, _objects = next(iter(runtime.resources.values()))
    records = tuple([record async for record in ledger.load_events(started.session_id)])
    assert "check_not_applicable" in receipt_gap_codes(replay(records), records)

    receipt = await app.receipt(
        ReceiptRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 3820)),
                "task_id": started.task_id,
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(drained.result_frontier),
                "format": "json",
                "include": "standard",
                "redaction_profile": "full_local",
            }
        )
    )
    assert "check_not_applicable" in receipt.coverage.known_gaps


async def test_receipt_conflict_on_drained_finding_carries_repair_facts_and_converges() -> None:
    """The receipt tolerance is bounded by material truth (#320).

    A finding materialized past the pinned frontier would be silently uncovered, so that drain
    stays a conflict — but one honoring the shared retry contract: retryable, head in
    safe_details, and the retry at that head documents the drained finding.
    """

    app, runtime, _ = _build_app(seed_offset=22)
    started, checked, _obligation = await _bootstrap_finding(app, seed=3300)
    finding = checked.findings[0]
    respond_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 3310)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(checked.result_frontier),
        "finding_id": finding.finding_id,
        "finding_frontier": _frontier(checked.result_frontier),
        "disposition": "acknowledged",
    }
    responded = await app.respond(RespondRequest.model_validate(respond_wire))

    obligation_event_id = protocol_id("evt_", 3302)
    drained = await _drain_observation_record(
        app,
        runtime,
        started,
        seed=3320,
        expected_frontier=responded.result_frontier.sequence,
        finding=_drained_finding(
            obligation_event_id,
            Frontier(
                int(responded.result_frontier.sequence), responded.result_frontier.head_digest
            ),
            3325,
        ),
    )

    receipt_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 3330)),
        "task_id": started.task_id,
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(responded.result_frontier),
        "format": "json",
        "include": "standard",
        "redaction_profile": "full_local",
    }
    with pytest.raises(PublicOperationError) as caught:
        await app.receipt(ReceiptRequest.model_validate(receipt_wire))
    assert caught.value.code is PublicErrorCode.FRONTIER_CONFLICT
    assert caught.value.retryable is True
    assert caught.value.safe_details["sequence"] == drained.result_frontier.sequence
    assert caught.value.safe_details["head_digest"] == drained.result_frontier.head_digest

    retried_wire: dict[str, JsonValue] = {
        **receipt_wire,
        "request_id": protocol_id("req_", 3340),
        "expected_frontier": {
            "sequence": str(caught.value.safe_details["sequence"]),
            "head_digest": str(caught.value.safe_details["head_digest"]),
        },
    }
    retried = await app.receipt(ReceiptRequest.model_validate(retried_wire))
    assert retried.subject_frontier == drained.result_frontier
    document = cast(Mapping[str, JsonValue], retried.document)
    findings = cast(tuple[Mapping[str, JsonValue], ...], document["findings"])
    assert any(item["finding_id"] == protocol_id("fnd_", 3325) for item in findings)


async def test_receipt_agent_motion_still_conflicts_with_repair_facts() -> None:
    """Material (agent-authored) motion past the receipt frontier stays a real conflict, with
    the shared retry contract intact."""

    app, _runtime, _ = _build_app(seed_offset=23)
    started, checked, _obligation = await _bootstrap_finding(app, seed=3400)
    finding = checked.findings[0]
    respond_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 3410)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(checked.result_frontier),
        "finding_id": finding.finding_id,
        "finding_frontier": _frontier(checked.result_frontier),
        "disposition": "acknowledged",
    }
    responded = await app.respond(RespondRequest.model_validate(respond_wire))

    publish_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 3420)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(responded.result_frontier),
        "event_drafts": (
            {
                "event_id": protocol_id("evt_", 3421),
                "schema": {"name": "evidence_recorded", "version": "1.0.0"},
                "occurred_at": "2026-07-19T12:00:02.000Z",
                "causal_parents": (),
                "payload": {
                    "evidence_id": protocol_id("evd_", 3422),
                    "evidence_kind": "artifact",
                    "strength": "mutable_reference",
                    "observed_at": "2026-07-19T12:00:02.000Z",
                    "reference": "agent-authored-motion",
                },
                "artifact_refs": (),
                "evidence_refs": (),
            },
        ),
    }
    published = await app.publish_work(PublishWorkRequest.model_validate(publish_wire))

    receipt_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 3430)),
        "task_id": started.task_id,
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(responded.result_frontier),
        "format": "json",
        "include": "standard",
        "redaction_profile": "full_local",
    }
    with pytest.raises(PublicOperationError) as caught:
        await app.receipt(ReceiptRequest.model_validate(receipt_wire))
    assert caught.value.code is PublicErrorCode.FRONTIER_CONFLICT
    assert caught.value.retryable is True
    assert caught.value.safe_details["sequence"] == published.result_frontier.sequence


async def test_receipt_prefix_replay_conflict_is_retryable_with_repair_facts() -> None:
    """Regression for #326.

    The receipt's own prefix-replay conflict must honor the same retry contract as every
    ledger-minted frontier conflict on the same request: retryable, with the replayed head as
    the repair fact — not a dead-end ``retryable: false`` with no details.
    """

    app, _runtime, _ = _build_app(seed_offset=24)
    started, checked, _obligation = await _bootstrap_finding(app, seed=3500)
    head = checked.result_frontier

    beyond_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 3510)),
        "task_id": started.task_id,
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        # A frontier past the live head: copied from another writer's in-flight result.
        "expected_frontier": {
            "sequence": str(int(head.sequence) + 5),
            "head_digest": head.head_digest,
        },
        "format": "json",
        "include": "standard",
        "redaction_profile": "full_local",
    }
    with pytest.raises(PublicOperationError) as caught:
        await app.receipt(ReceiptRequest.model_validate(beyond_wire))
    assert caught.value.code is PublicErrorCode.FRONTIER_CONFLICT
    assert caught.value.retryable is True
    assert dict(caught.value.safe_details) == {
        "continuation": "frontier_refresh_required",
        "head_digest": head.head_digest,
        "reason_code": "frontier_changed",
        "sequence": int(head.sequence),
    }

    stale_digest_wire: dict[str, JsonValue] = {
        **beyond_wire,
        "request_id": protocol_id("req_", 3520),
        "expected_frontier": {
            "sequence": str(head.sequence),
            "head_digest": "sha256:" + "e" * 64,
        },
    }
    with pytest.raises(PublicOperationError) as stale_caught:
        await app.receipt(ReceiptRequest.model_validate(stale_digest_wire))
    assert stale_caught.value.code is PublicErrorCode.FRONTIER_CONFLICT
    assert stale_caught.value.retryable is True
    assert stale_caught.value.safe_details["head_digest"] == head.head_digest

    repaired_wire: dict[str, JsonValue] = {
        **beyond_wire,
        "request_id": protocol_id("req_", 3530),
        "expected_frontier": {
            "sequence": str(caught.value.safe_details["sequence"]),
            "head_digest": str(caught.value.safe_details["head_digest"]),
        },
    }
    repaired = await app.receipt(ReceiptRequest.model_validate(repaired_wire))
    assert repaired.subject_frontier == head


async def test_receipt_append_stage_rejects_observation_finding_suffix() -> None:
    """The append-stage twin of the availability guard (#320).

    A finding drained between a receipt's availability snapshot and its locator append would be
    silently uncovered by the pinned case, so a RECEIPT-kind append refuses a finding-bearing
    observation suffix that the same append tolerates for every other operation kind.
    """

    app, runtime, _ = _build_app(seed_offset=25)
    started, checked, _obligation = await _bootstrap_finding(app, seed=3600)
    drained = await _drain_observation_record(
        app,
        runtime,
        started,
        seed=3610,
        expected_frontier=checked.result_frontier.sequence,
        finding=_drained_finding(
            protocol_id("evt_", 3602),
            Frontier(int(checked.result_frontier.sequence), checked.result_frontier.head_digest),
            3615,
        ),
    )

    with pytest.raises(PublicOperationError) as caught:
        await _drain_observation_record(
            app,
            runtime,
            started,
            seed=3620,
            expected_frontier=checked.result_frontier.sequence,
            operation_kind=OperationKind.RECEIPT,
        )
    assert caught.value.code is PublicErrorCode.FRONTIER_CONFLICT
    assert caught.value.retryable is True
    assert caught.value.safe_details["sequence"] == drained.result_frontier.sequence

    accepted = await _drain_observation_record(
        app,
        runtime,
        started,
        seed=3630,
        expected_frontier=checked.result_frontier.sequence,
    )
    assert accepted.result_frontier.sequence == drained.result_frontier.sequence + 1


async def _repair_open_obligation(
    app: Application,
    started: StartInternalResult,
    obligation_id: str,
    frontier: Frontier,
    *,
    seed: int,
) -> PublishWorkInternalResult:
    """Resolve the seeded obligation the exact way the publication policy admits.

    The meaning fields repeat the open row byte-for-byte; only ``status`` and
    ``resolution_evidence_refs`` change, and the resolving evidence lands in the same batch.
    """

    evidence = protocol_id("evd_", seed)
    wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", seed)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(frontier),
        "event_drafts": (
            {
                "event_id": protocol_id("evt_", seed + 1),
                "schema": {"name": "evidence_recorded", "version": EVIDENCE_SCHEMA_VERSION},
                "occurred_at": "2026-07-19T12:01:00.000Z",
                "causal_parents": (),
                "payload": {
                    "evidence_id": evidence,
                    "evidence_kind": "test_result",
                    "strength": "content_digest",
                    "content_digest": "sha256:" + "3" * 64,
                    "observed_at": "2026-07-19T12:01:00.000Z",
                    "description": "The exercise's result was recorded.",
                    # Digest-bound so the recheck carries no legacy-evidence gap: a repair must
                    # leave a state a check can actually prove clean.
                    "digest_binding": {
                        "subject": "test_report",
                        "content_availability": "digest_only",
                        "byte_count": 128,
                        "provenance": "caller_asserted",
                    },
                },
                "artifact_refs": (),
                "evidence_refs": (),
            },
            {
                "event_id": protocol_id("evt_", seed + 2),
                "schema": {"name": "obligation_published", "version": "1.0.0"},
                "occurred_at": "2026-07-19T12:01:01.000Z",
                "causal_parents": (protocol_id("evt_", seed + 1),),
                "payload": {
                    "obligation_id": obligation_id,
                    "description": "Publish a result for the respond/status/receipt exercise.",
                    "acceptance_criteria": "A result is recorded in the task ledger.",
                    "evidence_expectation": "A linked immutable result record.",
                    "status": "resolved",
                    "resolution_evidence_refs": (evidence,),
                },
                "artifact_refs": (),
                "evidence_refs": (evidence,),
            },
        ),
    }
    result = await app.publish_work(PublishWorkRequest.model_validate(wire))
    assert type(result) is PublishWorkInternalResult, f"unexpected publish outcome: {type(result)}"
    return result


async def _findings_view(
    app: Application, started: StartInternalResult, seed: int, *, include_resolved: bool
) -> StatusFindingsPageModel:
    status = await app.status(
        StatusRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "view": "findings",
                "limit": "10",
                "filter": {"include_resolved": include_resolved},
            }
        )
    )
    return cast(StatusFindingsPageModel, status.page)


@pytest.mark.parametrize("ledger_backend", ("memory", "sqlite"))
async def test_host_observation_gaps_do_not_keep_repaired_action_finding_current(
    ledger_backend: Literal["memory", "sqlite"],
) -> None:
    """Issue #538: unrelated host gaps limit coverage, not local-finding resolution."""

    app, runtime, _ = _build_app(seed_offset=29, ledger_backend=ledger_backend)
    started = await app.start(start_request(5000, title="Host-gap finding resolution"))
    obligation_a = protocol_id("obl_", 5001)
    obligation_b = protocol_id("obl_", 5002)
    action_a = protocol_id("act_", 5003)
    action_b = protocol_id("act_", 5004)
    publish_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 5005)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(started.frontier),
        "event_drafts": (
            {
                "event_id": protocol_id("evt_", 5006),
                "schema": {"name": "plan_published", "version": "1.0.0"},
                "occurred_at": "2026-07-19T12:00:00.000Z",
                "causal_parents": (),
                "payload": {
                    "plan_version": 1,
                    "summary": "Exercise action/result integrity under host coverage gaps.",
                    "obligation_refs": (obligation_a, obligation_b),
                },
                "artifact_refs": (),
                "evidence_refs": (),
            },
            *(
                {
                    "event_id": protocol_id("evt_", 5007 + offset),
                    "schema": {"name": "obligation_published", "version": "1.0.0"},
                    "occurred_at": "2026-07-19T12:00:00.000Z",
                    "causal_parents": (),
                    "payload": {
                        "obligation_id": obligation,
                        "description": f"Record result {offset + 1}.",
                        "acceptance_criteria": "A linked result is recorded.",
                        "evidence_expectation": "A result event.",
                        "status": "open",
                    },
                    "artifact_refs": (),
                    "evidence_refs": (),
                }
                for offset, obligation in enumerate((obligation_a, obligation_b))
            ),
            {
                "event_id": protocol_id("evt_", 5009),
                "schema": {"name": "action_recorded", "version": "1.0.0"},
                "occurred_at": "2026-07-19T12:00:01.000Z",
                "causal_parents": (),
                "payload": {
                    "action_id": action_a,
                    "action_kind": "other",
                    "description": "Attempt result 1.",
                    "obligation_refs": (obligation_a,),
                },
                "artifact_refs": (),
                "evidence_refs": (),
            },
        ),
    }
    first_batch = await app.publish_work(PublishWorkRequest.model_validate(publish_wire))
    # The unrelated later work arrives in its own batch: a sibling in the same batch is never
    # subsequent work (tb4n5 follow-up).
    published = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 5090)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(first_batch.result_frontier),
                "event_drafts": (
                    {
                        "event_id": protocol_id("evt_", 5010),
                        "schema": {"name": "action_recorded", "version": "1.0.0"},
                        "occurred_at": "2026-07-19T12:00:01.000Z",
                        "causal_parents": (),
                        "payload": {
                            "action_id": action_b,
                            "action_kind": "other",
                            "description": "Attempt result 2.",
                            "obligation_refs": (obligation_b,),
                        },
                        "artifact_refs": (),
                        "evidence_refs": (),
                    },
                ),
            }
        )
    )
    first_check = await app.check(
        CheckRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 5011)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(published.result_frontier),
                "mode": "deterministic_only",
                "max_findings": "3",
            }
        )
    )
    assert type(first_check) is CheckCommitResult
    action_finding = next(
        item for item in first_check.findings if item.kind is FindingKind.ACTION_WITHOUT_RESULT
    )
    assert action_finding.coverage.ledger_freshness is LedgerFreshness.CURRENT
    assert action_finding.coverage.known_gaps == ()

    repaired = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 5012)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(first_check.result_frontier),
                "event_drafts": (
                    {
                        "event_id": protocol_id("evt_", 5013),
                        "schema": {"name": "result_recorded", "version": "1.0.0"},
                        "occurred_at": "2026-07-19T12:00:02.000Z",
                        "causal_parents": (),
                        "payload": {
                            "result_id": protocol_id("res_", 5014),
                            "action_id": action_a,
                            "outcome": "success",
                            "summary": "The first action now has its result.",
                        },
                        "artifact_refs": (),
                        "evidence_refs": (),
                    },
                ),
            }
        )
    )
    observed = await _drain_host_observation_gaps(
        app,
        runtime,
        started,
        seed=5015,
        expected_frontier=int(repaired.result_frontier.sequence),
    )
    rechecked = await app.check(
        CheckRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 5017)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(observed.result_frontier),
                "mode": "deterministic_only",
                "max_findings": "3",
            }
        )
    )
    assert type(rechecked) is CheckCommitResult
    assert action_finding.finding_id not in {item.finding_id for item in rechecked.findings}
    assert rechecked.coverage.ledger_freshness is LedgerFreshness.REDACTED_GAP
    assert {
        "captured_object_unavailable",
        "content_unselected",
        "host_outcome_unavailable",
        "unpaired_event",
    } <= set(rechecked.coverage.known_gaps)

    history = await _findings_view(app, started, 5018, include_resolved=True)
    by_id = {item.finding_id: item for item in history.items}
    assert by_id[action_finding.finding_id].resolved is True
    status = await app.status(
        StatusRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 5019)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "view": "compact",
                "limit": "10",
            }
        )
    )
    compact = cast(StatusCompactPageModel, status.page).items[0]
    assert compact.receipt_blocking_finding_count == "0"
    assert "receipt_findings_unresolved" not in status.closure_readiness.blocking_conditions

    receipt = await app.receipt(
        ReceiptRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 5020)),
                "task_id": started.task_id,
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(rechecked.result_frontier),
                "format": "json",
                "include": "standard",
                "redaction_profile": "full_local",
            }
        )
    )
    assert receipt.conclusion != "unresolved_findings_remain"
    assert receipt.coverage.ledger_freshness is LedgerFreshness.REDACTED_GAP
    assert {
        "captured_object_unavailable",
        "content_unselected",
        "host_outcome_unavailable",
        "unpaired_event",
    } <= set(receipt.coverage.known_gaps)
    document = cast(dict[str, JsonValue], receipt.document)
    assert action_finding.finding_id in {
        cast(str, cast(dict[str, JsonValue], row)["finding_id"])
        for row in cast(list[JsonValue], document["findings"])
    }
    sections = {
        cast(dict[str, JsonValue], section)["key"]: cast(dict[str, JsonValue], section)
        for section in cast(list[JsonValue], document["sections"])
    }
    assert action_finding.finding_id in cast(list[str], sections["summary"]["items"])
    projected_frontier = receipt.result_frontier
    for index, projected in enumerate(("markdown", "text")):
        rendered = await app.receipt(
            ReceiptRequest.model_validate(
                {
                    **_request_base(protocol_id("req_", 5021 + index)),
                    "task_id": started.task_id,
                    "session_id": started.session_id,
                    "writer_id": started.writer_id,
                    "expected_frontier": _frontier(projected_frontier),
                    "format": projected,
                    "include": "standard",
                    "redaction_profile": "full_local",
                }
            )
        )
        projected_frontier = rendered.result_frontier
        assert rendered.document is None
        human_text = rendered.human_text
        assert human_text is not None
        # The admitted host gaps stay visible as receipt limitations in every rendering (#538).
        for gap in (
            "captured_object_unavailable",
            "content_unselected",
            "host_outcome_unavailable",
            "unpaired_event",
        ):
            assert gap in human_text
        assert rendered.conclusion == receipt.conclusion


@pytest.mark.parametrize("ledger_backend", ("memory", "sqlite"))
async def test_repair_plus_later_qualifying_check_resolves_the_finding(
    ledger_backend: Literal["memory", "sqlite"],
) -> None:
    """Issue #458: the record is repaired, a later whole-case local check finds the
    same issue absent, and the finding stops blocking the receipt while staying visible.

    The response alone changes nothing (locked separately); the proof is the check.
    """

    app, _runtime, _ = _build_app(seed_offset=20, ledger_backend=ledger_backend)
    started, checked, obligation_id = await _bootstrap_finding(app, seed=2000)
    finding = checked.findings[0]
    assert finding.kind is FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS

    acked = await app.respond(
        RespondRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 2010)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(checked.result_frontier),
                "finding_id": finding.finding_id,
                "finding_frontier": _frontier(checked.result_frontier),
                "disposition": "acknowledged",
            }
        )
    )
    seeded_ids = {item.finding_id for item in checked.findings}
    before = await _findings_view(app, started, 2011, include_resolved=True)
    assert {item.finding_id: item.resolved for item in before.items} == dict.fromkeys(
        seeded_ids, False
    )

    repaired = await _repair_open_obligation(
        app, started, obligation_id, acked.result_frontier, seed=2020
    )
    rechecked = await app.check(
        CheckRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 2030)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(repaired.result_frontier),
                "mode": "deterministic_only",
                "max_findings": "3",
            }
        )
    )
    assert type(rechecked) is CheckCommitResult, f"unexpected nonterminal check: {type(rechecked)}"
    assert not seeded_ids & {item.finding_id for item in rechecked.findings}, (
        "the repaired state must not re-fire the seeded issues"
    )
    assert all(not FINDING_KIND_TRAITS[item.kind][1] for item in rechecked.findings), (
        "only advisory rows (digest-only evidence) may remain"
    )
    assert rechecked.suppressed_count == 0
    advisory_ids = {item.finding_id for item in rechecked.findings}

    # Status: the seeded rows are history now — visible only on request, no longer
    # receipt-blocking — while the recheck's own advisory row is current and unanswered.
    default_view = await _findings_view(app, started, 2040, include_resolved=False)
    assert {item.finding_id for item in default_view.items} == advisory_ids
    history = await _findings_view(app, started, 2041, include_resolved=True)
    by_id = {item.finding_id: item for item in history.items}
    assert set(by_id) == seeded_ids | advisory_ids
    assert all(by_id[item].resolved for item in seeded_ids)
    assert by_id[finding.finding_id].disposition == "acknowledged"
    assert all(not by_id[item].resolved for item in advisory_ids)
    status = await app.status(
        StatusRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 2042)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "view": "compact",
                "limit": "10",
            }
        )
    )
    compact = cast(StatusCompactPageModel, status.page).items[0]
    # A seeded row the recheck resolved without a response is verified_resolved, a final state
    # ``respond`` refuses, so it is no longer response work (pilot blocker); any advisory row the
    # recheck returned is unanswered and current. None of them blocks.
    assert compact.unanswered_finding_count == str(len(advisory_ids))
    assert compact.receipt_blocking_finding_count == "0"
    assert "receipt_findings_unresolved" not in status.closure_readiness.blocking_conditions

    # Receipt: no longer ``unresolved_findings_remain``; the resolved row stays in the document
    # as history and the wording separates it from current findings and coverage gaps.
    receipt = await app.receipt(
        ReceiptRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 2050)),
                "task_id": started.task_id,
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(rechecked.result_frontier),
                "format": "json",
                "include": "standard",
                "redaction_profile": "full_local",
            }
        )
    )
    assert receipt.conclusion != "unresolved_findings_remain"
    document = cast(dict[str, JsonValue], receipt.document)
    assert {
        cast(str, cast(dict[str, JsonValue], row)["finding_id"])
        for row in cast(list[JsonValue], document["findings"])
    } == seeded_ids | advisory_ids
    sections = {
        cast(dict[str, JsonValue], section)["key"]: cast(dict[str, JsonValue], section)
        for section in cast(list[JsonValue], document["sections"])
    }
    assert sections["summary"]["items"] == sorted(seeded_ids)
    assert "resolved by a later qualifying check" in cast(str, sections["summary"]["body"])
    assert "remain visible as history" in cast(str, sections["summary"]["body"])
    assert sections["findings_and_dispositions"]["items"] == []
    assert "remains unresolved" not in cast(str, sections["findings_and_dispositions"]["body"])
    text = await app.receipt(
        ReceiptRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 2051)),
                "task_id": started.task_id,
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(receipt.result_frontier),
                "format": "text",
                "include": "standard",
                "redaction_profile": "full_local",
            }
        )
    )
    assert text.human_text is not None
    assert "resolved by a later qualifying check" in text.human_text
    assert "remain unresolved" not in text.human_text


async def test_refired_issue_after_resolution_is_a_blocking_successor() -> None:
    """Resolution is not a waiver: reopening the obligation re-fires the issue as a fresh row
    that blocks again, while the resolved row keeps its proof as history."""

    app, _runtime, _ = _build_app(seed_offset=21)
    started, checked, obligation_id = await _bootstrap_finding(app, seed=2100)
    finding = checked.findings[0]
    repaired = await _repair_open_obligation(
        app, started, obligation_id, checked.result_frontier, seed=2120
    )
    clean = await app.check(
        CheckRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 2130)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(repaired.result_frontier),
                "mode": "deterministic_only",
                "max_findings": "3",
            }
        )
    )
    assert type(clean) is CheckCommitResult
    assert not any(FINDING_KIND_TRAITS[item.kind][1] for item in clean.findings)

    # A brand-new completion claim over a brand-new open obligation is the same issue kind but a
    # different subject, so it is a different issue; the resolved row must stay resolved and the
    # new one must block.
    reopened = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 2140)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(clean.result_frontier),
                "event_drafts": (
                    {
                        "event_id": protocol_id("evt_", 2141),
                        "schema": {"name": "obligation_published", "version": "1.0.0"},
                        "occurred_at": "2026-07-19T12:02:00.000Z",
                        "causal_parents": (),
                        "payload": {
                            "obligation_id": protocol_id("obl_", 2142),
                            "description": "Publish a second result.",
                            "acceptance_criteria": "A second result is recorded.",
                            "evidence_expectation": "A linked immutable result record.",
                            "status": "open",
                        },
                        "artifact_refs": (),
                        "evidence_refs": (),
                    },
                    {
                        "event_id": protocol_id("evt_", 2143),
                        "schema": {"name": "claim_recorded", "version": "1.0.0"},
                        "occurred_at": "2026-07-19T12:02:01.000Z",
                        "causal_parents": (protocol_id("evt_", 2141),),
                        "payload": {
                            "claim_id": protocol_id("clm_", 2144),
                            "claim_kind": "completion",
                            "statement": "The second exercise is complete.",
                            "supporting_refs": (protocol_id("obl_", 2142),),
                            "obligation_refs": (protocol_id("obl_", 2142),),
                        },
                        "artifact_refs": (),
                        "evidence_refs": (),
                    },
                ),
            }
        )
    )
    refired = await app.check(
        CheckRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 2150)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(reopened.result_frontier),
                "mode": "deterministic_only",
                "max_findings": "3",
            }
        )
    )
    assert type(refired) is CheckCommitResult
    assert refired.findings, "the new open obligation under a completion claim must fire"
    assert all(item.finding_id != finding.finding_id for item in refired.findings)

    history = await _findings_view(app, started, 2160, include_resolved=True)
    by_id = {item.finding_id: item.resolved for item in history.items}
    assert by_id[finding.finding_id] is True
    assert all(by_id[item.finding_id] is False for item in refired.findings)
    receipt = await app.receipt(
        ReceiptRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 2170)),
                "task_id": started.task_id,
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(refired.result_frontier),
                "format": "json",
                "include": "standard",
                "redaction_profile": "full_local",
            }
        )
    )
    assert receipt.conclusion == "unresolved_findings_remain"


async def test_scoped_check_that_excludes_the_subject_resolves_nothing() -> None:
    """A recheck scoped to a different subject never saw the repaired obligation's issue, so the
    finding stays current even though the repair itself is on the ledger."""

    app, _runtime, _ = _build_app(seed_offset=22)
    started, checked, obligation_id = await _bootstrap_finding(app, seed=2200)
    finding = checked.findings[0]
    repaired = await _repair_open_obligation(
        app, started, obligation_id, checked.result_frontier, seed=2220
    )
    other = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 2230)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(repaired.result_frontier),
                "event_drafts": (
                    {
                        "event_id": protocol_id("evt_", 2231),
                        "schema": {"name": "obligation_published", "version": "1.0.0"},
                        "occurred_at": "2026-07-19T12:03:00.000Z",
                        "causal_parents": (),
                        "payload": {
                            "obligation_id": protocol_id("obl_", 2232),
                            "description": "An unrelated open obligation.",
                            "acceptance_criteria": "Unrelated work is recorded.",
                            "evidence_expectation": "A linked immutable result record.",
                            "status": "open",
                        },
                        "artifact_refs": (),
                        "evidence_refs": (),
                    },
                ),
            }
        )
    )
    scoped = await app.check(
        CheckRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 2240)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(other.result_frontier),
                "mode": "deterministic_only",
                "max_findings": "3",
                "scope": {"claim_ids": (), "obligation_ids": (protocol_id("obl_", 2232),)},
            }
        )
    )
    assert type(scoped) is CheckCommitResult
    history = await _findings_view(app, started, 2250, include_resolved=True)
    assert {item.finding_id: item.resolved for item in history.items}[finding.finding_id] is False
    status = await app.status(
        StatusRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 2251)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "view": "compact",
                "limit": "10",
            }
        )
    )
    assert "receipt_findings_unresolved" in status.closure_readiness.blocking_conditions


@pytest.mark.parametrize("ledger_backend", ("memory", "sqlite"))
@pytest.mark.parametrize("repair", ("carried", "restated", "narrowed"))
async def test_completion_scope_difference_is_visible_and_repairable(
    ledger_backend: Literal["memory", "sqlite"], repair: str
) -> None:
    """679: preview, append, status, replay, check and receipt share the same scope."""
    app, runtime, _ = _build_app(ledger_backend=ledger_backend)
    started = await app.start(start_request(61000, title="Scope consistency"))
    a, b = protocol_id("obl_", 61001), protocol_id("obl_", 61002)
    evidence = protocol_id("evd_", 61003)
    old_claim = protocol_id("clm_", 61004)
    serial = 61100
    frontier = started.frontier
    requests: list[PublishWorkRequest] = []

    def draft(name: str, payload: dict[str, JsonValue]) -> dict[str, JsonValue]:
        nonlocal serial
        serial += 1
        return {
            "event_id": protocol_id("evt_", serial),
            "schema": {"name": name, "version": "1.1.0" if name == "claim_recorded" else "1.0.0"},
            "occurred_at": "2026-07-19T12:00:00.000Z",
            "causal_parents": [],
            "artifact_refs": [],
            "evidence_refs": [],
            "payload": payload,
        }

    async def publish(drafts: list[dict[str, JsonValue]], *, preview: bool = False) -> object:
        nonlocal serial, frontier
        serial += 1
        request = PublishWorkRequest.model_validate(
            {
                **_request_base(protocol_id("req_", serial)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(frontier),
                "event_drafts": drafts,
                "dry_run": preview,
            }
        )
        requests.append(request)
        result = await app.publish_work(request)
        if type(result) is PublishWorkInternalResult:
            frontier = result.result_frontier
        return result

    obligations: list[dict[str, JsonValue]] = [
        {
            "obligation_id": key,
            "description": "Synthetic work",
            "evidence_expectation": "Evidence",
            "status": "open",
        }
        for key in (a, b)
    ]
    await publish(
        [
            draft(
                "plan_published", {"plan_version": 1, "summary": "Plan A", "obligation_refs": [a]}
            ),
            *(draft("obligation_published", value) for value in obligations),
            draft(
                "evidence_recorded",
                {
                    "evidence_id": evidence,
                    "evidence_kind": "other",
                    "strength": "metadata_only",
                    "description": "Synthetic evidence",
                    "observed_at": "2026-07-19T12:00:00.000Z",
                },
            ),
            *(
                draft(
                    "obligation_published",
                    {**value, "status": "resolved", "resolution_evidence_refs": [evidence]},
                )
                for value in obligations
            ),
        ]
    )
    claimed = [
        draft(
            "claim_recorded",
            {
                "claim_id": old_claim,
                "claim_kind": "completion",
                "statement": "A and B complete",
                "obligation_refs": [a, b],
                "supporting_refs": [evidence],
                "limitation_refs": [],
                "supersedes_claim_refs": [],
            },
        )
    ]
    preview = await publish(claimed, preview=True)
    assert isinstance(preview, PublishWorkResult)
    assert "completion_claim_outside_plan" in preview.root.gaps  # type: ignore[union-attr]
    committed = await publish(claimed)
    assert isinstance(committed, PublishWorkInternalResult)
    assert "completion_claim_outside_plan" in committed.gaps
    claim_request = requests[-1]

    async def inspect() -> tuple[CheckCommitResult, object]:
        nonlocal serial, frontier
        serial += 1
        status = await app.status(
            StatusRequest.model_validate(
                {
                    **_request_base(protocol_id("req_", serial)),
                    "session_id": started.session_id,
                    "writer_id": started.writer_id,
                    "view": "compact",
                    "limit": "10",
                }
            )
        )
        serial += 1
        check = await app.check(
            CheckRequest.model_validate(
                {
                    **_request_base(protocol_id("req_", serial)),
                    "session_id": started.session_id,
                    "writer_id": started.writer_id,
                    "expected_frontier": _frontier(frontier),
                    "mode": "deterministic_only",
                    "max_findings": "10",
                }
            )
        )
        assert type(check) is CheckCommitResult
        frontier = check.result_frontier
        return check, status

    checked, status = await inspect()
    assert "completion_claim_outside_plan" in checked.coverage.known_gaps
    assert getattr(status, "closure_readiness").declared_obligation_count == "1"
    assert "coverage_gaps_declared" in getattr(status, "closure_readiness").blocking_conditions
    for fmt in ("json", "markdown", "text"):
        serial += 1
        receipt = await app.receipt(
            ReceiptRequest.model_validate(
                {
                    **_request_base(protocol_id("req_", serial)),
                    "task_id": started.task_id,
                    "session_id": started.session_id,
                    "writer_id": started.writer_id,
                    "expected_frontier": _frontier(frontier),
                    "format": fmt,
                    "include": "standard",
                    "redaction_profile": "full_local",
                }
            )
        )
        frontier = receipt.result_frontier
        assert receipt.conclusion == "insufficient_coverage"
        assert "completion_claim_outside_plan" in receipt.coverage.known_gaps
        assert "plan_revised" in str(receipt.document if fmt == "json" else receipt.human_text)

    if repair == "carried":
        fixed = draft(
            "plan_revised",
            {
                "plan_version": 2,
                "supersedes_plan_version": 1,
                "summary": "Include B",
                "reason": "New work",
                "obligation_changes": [{"obligation_id": b, "change": "carried"}],
            },
        )
    elif repair == "restated":
        fixed = draft(
            "plan_published", {"plan_version": 2, "summary": "Include B", "obligation_refs": [a, b]}
        )
    else:
        fixed = draft(
            "claim_recorded",
            {
                "claim_id": protocol_id("clm_", 61999),
                "claim_kind": "completion",
                "statement": "Only A",
                "obligation_refs": [a],
                "supporting_refs": [evidence],
                "limitation_refs": [],
                "supersedes_claim_refs": [old_claim],
            },
        )
    await publish([fixed])
    checked, _ = await inspect()
    assert "completion_claim_outside_plan" not in checked.coverage.known_gaps
    assert "completion_plan_not_claimed" not in checked.coverage.known_gaps
    ledger, _ = next(iter(runtime.resources.values()))
    records = tuple([row async for row in ledger.load_events(started.session_id)])
    from finishup.kernel.completion_scope import completion_scope_codes

    assert completion_scope_codes(replay(records)) == ()

    retried = await app.publish_work(claim_request)
    assert isinstance(retried, PublishWorkInternalResult)
    assert retried.result_frontier == committed.result_frontier
    assert retried.gaps == committed.gaps
    if repair != "narrowed":
        await publish(
            [
                draft(
                    "claim_recorded",
                    {
                        "claim_id": protocol_id("clm_", 61998),
                        "claim_kind": "completion",
                        "statement": "Partial A",
                        "obligation_refs": [a],
                        "supporting_refs": [evidence],
                        "limitation_refs": [],
                        "supersedes_claim_refs": [old_claim],
                    },
                )
            ]
        )
        partial, partial_status = await inspect()
        assert "completion_plan_not_claimed" in partial.coverage.known_gaps
        assert getattr(partial_status, "closure_readiness").open_obligation_count == "0"
        serial += 1
        receipt = await app.receipt(
            ReceiptRequest.model_validate(
                {
                    **_request_base(protocol_id("req_", serial)),
                    "task_id": started.task_id,
                    "session_id": started.session_id,
                    "writer_id": started.writer_id,
                    "expected_frontier": _frontier(frontier),
                    "format": "text",
                    "include": "standard",
                    "redaction_profile": "full_local",
                }
            )
        )
        assert "outside a completion claim" in str(receipt.human_text)
        assert receipt.conclusion == "insufficient_coverage"


@pytest.mark.parametrize("ledger_backend", ("memory", "sqlite"))
async def test_publish_reuses_validated_projection_and_falls_back_for_stale_metadata(
    ledger_backend: Literal["memory", "sqlite"], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Normal appends use the stored projection; invalid metadata keeps historical replay safe."""

    app, workflow_runtime, _ = _build_app(ledger_backend=ledger_backend)
    started, checked, _ = await _bootstrap_finding(app, seed=7000)
    ledger, _objects = workflow_runtime.resources[started.task_id]
    ledger_port = cast(LedgerPort, ledger)
    original_load_events = ledger_port.load_events
    event_loads: list[tuple[int, int | None]] = []

    def observed_load_events(
        loaded_session_id: str, *, after: int = 0, through: int | None = None
    ) -> AsyncIterator[LedgerRecord]:
        event_loads.append((after, through))
        return original_load_events(loaded_session_id, after=after, through=through)

    monkeypatch.setattr(ledger_port, "load_events", observed_load_events)
    frontier = checked.result_frontier

    async def publish_action(
        request_tail: int, event_tail: int, action_tail: int
    ) -> PublishWorkInternalResult:
        nonlocal frontier
        published = await app.publish_work(
            PublishWorkRequest.model_validate(
                {
                    **_request_base(protocol_id("req_", request_tail)),
                    "session_id": started.session_id,
                    "writer_id": started.writer_id,
                    "expected_frontier": _frontier(frontier),
                    "event_drafts": (
                        {
                            "event_id": protocol_id("evt_", event_tail),
                            "schema": {"name": "action_recorded", "version": "1.0.0"},
                            "occurred_at": "2026-07-19T12:00:00.000Z",
                            "causal_parents": (),
                            "payload": {
                                "action_id": protocol_id("act_", action_tail),
                                "action_kind": "other",
                                "description": "Exercise cached projection publication.",
                            },
                            "artifact_refs": (),
                            "evidence_refs": (),
                        },
                    ),
                }
            )
        )
        assert type(published) is PublishWorkInternalResult
        frontier = published.result_frontier
        return published

    await publish_action(7100, 7101, 7102)
    assert event_loads
    assert all(after > 0 for after, _through in event_loads)

    original_load_projection = ledger_port.load_projection

    async def stale_projection(
        loaded_session_id: str, view: ProjectionView
    ) -> StoredProjection | None:
        stored = await original_load_projection(loaded_session_id, view)
        if stored is not None and view is ProjectionView.CANDIDATE_FINDINGS:
            return replace(stored, lag=1)
        return stored

    event_loads.clear()
    monkeypatch.setattr(ledger_port, "load_projection", stale_projection)
    await publish_action(7103, 7104, 7105)
    assert any(after == 0 for after, _through in event_loads)


@pytest.mark.parametrize("ledger_backend", ("memory", "sqlite"))
@pytest.mark.parametrize("overlap", (False, True))
@pytest.mark.parametrize("scope_mismatch", (False, True))
async def test_command_gap_partition_preserves_receipt_coverage(
    ledger_backend: Literal["memory", "sqlite"], overlap: bool, scope_mismatch: bool
) -> None:
    """682: real append, repair, recheck and receipts keep independent proof separate."""
    app, runtime, _ = _build_app(ledger_backend=ledger_backend)
    started = await app.start(start_request(62000, title="Command gap resolution"))
    a, b = protocol_id("obl_", 62001), protocol_id("obl_", 62002)
    aa, ab = protocol_id("act_", 62003), protocol_id("act_", 62004)
    ra, rb = protocol_id("res_", 62005), protocol_id("res_", 62006)
    serial = 62100
    frontier = started.frontier

    def base() -> dict[str, JsonValue]:
        nonlocal serial
        serial += 1
        return {
            **_request_base(protocol_id("req_", serial)),
            "session_id": started.session_id,
            "writer_id": started.writer_id,
        }

    def draft(name: str, payload: dict[str, JsonValue]) -> dict[str, JsonValue]:
        nonlocal serial
        serial += 1
        return {
            "event_id": protocol_id("evt_", serial),
            "schema": {"name": name, "version": "1.0.0"},
            "occurred_at": "2026-07-19T12:00:00.000Z",
            "causal_parents": [],
            "artifact_refs": [],
            "evidence_refs": [],
            "payload": payload,
        }

    async def publish(drafts: list[dict[str, JsonValue]]) -> None:
        nonlocal frontier
        result = await app.publish_work(
            PublishWorkRequest.model_validate(
                {**base(), "expected_frontier": _frontier(frontier), "event_drafts": drafts}
            )
        )
        assert type(result) is PublishWorkInternalResult
        frontier = result.result_frontier

    async def check() -> CheckCommitResult:
        nonlocal frontier
        result = await app.check(
            CheckRequest.model_validate(
                {
                    **base(),
                    "expected_frontier": _frontier(frontier),
                    "mode": "deterministic_only",
                    "max_findings": "10",
                }
            )
        )
        assert type(result) is CheckCommitResult
        frontier = result.result_frontier
        return result

    oa: dict[str, JsonValue] = {
        "obligation_id": a,
        "description": "Edit A",
        "evidence_expectation": "Result",
        "status": "open",
    }
    ob: dict[str, JsonValue] = {
        "obligation_id": b,
        "description": "Work B",
        "evidence_expectation": "Result",
        "status": "open",
    }
    (oa if overlap else ob)["requested_items"] = [
        {"item_kind": "command", "value": "pytest exact.py"}
    ]
    action_a: dict[str, JsonValue] = {
        "action_id": aa,
        "action_kind": "edit",
        "description": "Edit",
        "obligation_refs": [a],
    }
    action_b: dict[str, JsonValue] = {
        "action_id": ab,
        "action_kind": "review",
        "description": "Other work",
        "obligation_refs": [b],
    }
    (action_a if overlap else action_b)["attempted_items"] = ["pytest exact.py"]
    await publish(
        [
            draft(
                "plan_published", {"plan_version": 1, "summary": "Plan", "obligation_refs": [a, b]}
            ),
            draft("obligation_published", oa),
            draft("obligation_published", ob),
            draft("action_recorded", action_a),
        ]
    )
    # B is later, unrelated work in its own batch (a same-batch sibling never is, tb4n5).
    await publish(
        [
            draft("action_recorded", action_b),
            draft("result_recorded", {"result_id": rb, "action_id": ab, "outcome": "success"}),
            draft(
                "obligation_published",
                {**ob, "status": "resolved", "resolution_evidence_refs": [rb]},
            ),
        ]
    )
    first = await check()
    target = next(f for f in first.findings if f.kind is FindingKind.ACTION_WITHOUT_RESULT)
    assert target.coverage.known_gaps == ()
    await publish(
        [
            draft("result_recorded", {"result_id": ra, "action_id": aa, "outcome": "success"}),
            draft(
                "obligation_published",
                {**oa, "status": "resolved", "resolution_evidence_refs": [ra]},
            ),
        ]
    )
    if scope_mismatch:
        await publish(
            [
                draft(
                    "claim_recorded",
                    {
                        "claim_id": protocol_id("clm_", 62007),
                        "claim_kind": "completion",
                        "statement": "Only A is covered by this claim",
                        "obligation_refs": [a],
                        "supporting_refs": [ra],
                    },
                )
            ]
        )
    should_resolve = not overlap and not scope_mismatch
    second = await check()
    if scope_mismatch:
        assert "completion_plan_not_claimed" in second.coverage.known_gaps
    assert not any(f.kind is FindingKind.ACTION_WITHOUT_RESULT for f in second.findings)
    assert "command_attempt_uncorroborated" in second.coverage.known_gaps
    status = await app.status(
        StatusRequest.model_validate(
            {**base(), "view": "findings", "limit": "100", "filter": {"include_resolved": True}}
        )
    )
    assert isinstance(status.page, StatusFindingsPageModel)
    current = next(row for row in status.page.items if row.finding_id == target.finding_id)
    assert current.resolved is should_resolve, current.detail
    if overlap:
        assert "command_relation_overlaps_obligation:" + a in str(current.detail)
    ledger, _ = next(iter(runtime.resources.values()))
    records = tuple([row async for row in ledger.load_events(started.session_id)])
    from finishup.kernel.finding_resolution import finding_is_resolved
    from finishup.kernel.projections import projection_from_snapshot, projection_snapshot

    rebuilt = replay(records)
    assert finding_is_resolved(rebuilt, target.finding_id) is should_resolve
    assert (
        finding_is_resolved(
            projection_from_snapshot(projection_snapshot(rebuilt)), target.finding_id
        )
        is should_resolve
    )
    for fmt in ("json", "markdown", "text"):
        receipt = await app.receipt(
            ReceiptRequest.model_validate(
                {
                    **base(),
                    "task_id": started.task_id,
                    "expected_frontier": _frontier(frontier),
                    "format": fmt,
                    "include": "standard",
                    "redaction_profile": "full_local",
                }
            )
        )
        frontier = receipt.result_frontier
        assert "command_attempt_uncorroborated" in receipt.coverage.known_gaps
        if scope_mismatch:
            assert "completion_plan_not_claimed" in receipt.coverage.known_gaps
        assert receipt.conclusion == (
            "insufficient_coverage" if should_resolve else "unresolved_findings_remain"
        )
        if fmt != "json":
            assert receipt.human_text is not None
            assert "command_attempt_uncorroborated" in receipt.human_text
    respond_request = RespondRequest.model_validate(
        {
            **base(),
            "expected_frontier": _frontier(frontier),
            "finding_id": target.finding_id,
            "finding_frontier": _frontier(first.result_frontier),
            "disposition": "acknowledged",
            "reason": "Historical finding remains in the record.",
        }
    )
    if should_resolve:
        # A verified_resolved finding is final (issue #905): the response records nothing.
        with pytest.raises(PublicOperationError) as terminal:
            await app.respond(respond_request)
        assert terminal.value.safe_details is not None
        assert terminal.value.safe_details["reason_code"] == "finding_terminal"
        return
    response = await app.respond(respond_request)
    frontier = response.result_frontier
    receipt = await app.receipt(
        ReceiptRequest.model_validate(
            {
                **base(),
                "task_id": started.task_id,
                "expected_frontier": _frontier(frontier),
                "format": "json",
                "include": "standard",
                "redaction_profile": "full_local",
            }
        )
    )
    frontier = receipt.result_frontier
    assert "check_not_applicable" in receipt.coverage.known_gaps
    status = await app.status(
        StatusRequest.model_validate(
            {
                **base(),
                "view": "findings",
                "limit": "100",
                "filter": {"include_resolved": True},
            }
        )
    )
    assert isinstance(status.page, StatusFindingsPageModel)
    final = next(row for row in status.page.items if row.finding_id == target.finding_id)
    assert final.resolved is should_resolve


@pytest.mark.parametrize("ledger_backend", ("memory", "sqlite"))
async def test_empty_claim_repair_converges_across_views_and_receipts(
    ledger_backend: Literal["memory", "sqlite"], monkeypatch: pytest.MonkeyPatch
) -> None:
    """#859: historical C0 + scoped C1 become C2 without rewriting accepted bytes."""
    import finishup.application.publish_work as publication
    from finishup.kernel.claims import effective_claim_ids
    from finishup.kernel.completion_scope import completion_scope_codes

    app, runtime, _ = _build_app(ledger_backend=ledger_backend)
    started = await app.start(start_request(85900, title="Empty claim repair"))
    obligation = protocol_id("obl_", 85901)
    evidence = protocol_id("evd_", 85902)
    c0, c1, c2 = (protocol_id("clm_", n) for n in (85903, 85904, 85905))
    serial = 86000
    frontier = started.frontier

    def draft(name: str, payload: dict[str, JsonValue]) -> dict[str, JsonValue]:
        nonlocal serial
        serial += 1
        return {
            "event_id": protocol_id("evt_", serial),
            "schema": {"name": name, "version": "1.1.0" if name == "claim_recorded" else "1.0.0"},
            "occurred_at": "2026-07-19T12:00:00.000Z",
            "causal_parents": [],
            "artifact_refs": [],
            "evidence_refs": [],
            "payload": payload,
        }

    def request_base() -> dict[str, object]:
        nonlocal serial
        serial += 1
        return {
            **_request_base(protocol_id("req_", serial)),
            "session_id": started.session_id,
            "writer_id": started.writer_id,
        }

    async def publish(drafts: list[dict[str, JsonValue]]) -> PublishWorkRequest:
        nonlocal frontier
        req = PublishWorkRequest.model_validate(
            {**request_base(), "expected_frontier": _frontier(frontier), "event_drafts": drafts}
        )
        preview = await app.publish_work(req.model_copy(update={"dry_run": True}))
        assert isinstance(preview, PublishWorkResult)
        result = await app.publish_work(req)
        assert isinstance(result, PublishWorkInternalResult)
        frontier = result.result_frontier
        return req

    meaning: dict[str, JsonValue] = {
        "obligation_id": obligation,
        "description": "Synthetic bounded repair",
        "evidence_expectation": "Evidence",
        "status": "open",
    }
    await publish(
        [
            draft(
                "plan_published",
                {"plan_version": 1, "summary": "Repair", "obligation_refs": [obligation]},
            ),
            draft("obligation_published", meaning),
            draft(
                "evidence_recorded",
                {
                    "evidence_id": evidence,
                    "evidence_kind": "other",
                    "strength": "metadata_only",
                    "description": "Synthetic evidence",
                    "observed_at": "2026-07-19T12:00:00.000Z",
                },
            ),
            draft(
                "obligation_published",
                {**meaning, "status": "resolved", "resolution_evidence_refs": [evidence]},
            ),
        ]
    )
    initial: dict[str, JsonValue] = {
        "claim_id": c0,
        "claim_kind": "completion",
        "statement": "Original missing scope",
        "supporting_refs": [obligation],
        "limitation_refs": [],
        "supersedes_claim_refs": [],
    }

    # Seed the exact historically accepted v1.1 authoring shape through the ordinary durable
    # append path with only the new admission guard disabled, as on the pre-fix runtime.
    def prior_admission(*_args: object) -> None:
        pass

    with monkeypatch.context() as old_runtime:
        old_runtime.setattr(publication, "_validate_new_completion_scope", prior_admission)
        historical_request = await publish([draft("claim_recorded", initial)])
    await publish(
        [
            draft(
                "claim_recorded",
                {
                    **initial,
                    "claim_id": c1,
                    "statement": "Scoped completion",
                    "obligation_refs": [obligation],
                    "supporting_refs": [evidence],
                },
            )
        ]
    )
    ledger, _ = runtime.resources[started.task_id]
    before = tuple([row async for row in ledger.load_events(started.session_id)])
    assert completion_scope_codes(replay(before)) == ("completion_plan_not_claimed",)
    for view in ("compact", "candidate_findings"):
        status = await app.status(
            StatusRequest.model_validate({**request_base(), "view": view, "limit": "100"})
        )
        assert "completion_plan_not_claimed" in str(status)
    await publish(
        [
            draft(
                "claim_recorded",
                {
                    **initial,
                    "claim_id": c2,
                    "statement": "Corrected bounded completion",
                    "obligation_refs": [obligation],
                    "supporting_refs": [evidence],
                    "supersedes_claim_refs": [c0, c1],
                },
            )
        ]
    )
    records = tuple([row async for row in ledger.load_events(started.session_id)])
    assert records[: len(before)] == before
    state = replay(records)
    assert effective_claim_ids(state) == frozenset({c2})
    assert completion_scope_codes(state) == ()
    for view in ("compact", "candidate_findings", "history"):
        status = await app.status(
            StatusRequest.model_validate({**request_base(), "view": view, "limit": "100"})
        )
        assert "completion_plan_not_claimed" not in str(status)
    # A pre-upgrade operation remains replayable even though its authoring shape is now refused.
    recovered = await app.publish_work(historical_request)
    assert isinstance(recovered, PublishWorkInternalResult)
    assert recovered.outcome == "replayed"
    check = await app.check(
        CheckRequest.model_validate(
            {
                **request_base(),
                "expected_frontier": _frontier(frontier),
                "mode": "deterministic_only",
                "max_findings": "10",
            }
        )
    )
    assert isinstance(check, CheckCommitResult)
    frontier = check.result_frontier
    assert "completion_plan_not_claimed" not in check.coverage.known_gaps
    for fmt in ("json", "markdown", "text"):
        receipt = await app.receipt(
            ReceiptRequest.model_validate(
                {
                    **request_base(),
                    "task_id": started.task_id,
                    "expected_frontier": _frontier(frontier),
                    "format": fmt,
                    "include": "standard",
                    "redaction_profile": "full_local",
                }
            )
        )
        frontier = receipt.result_frontier
        assert "completion_plan_not_claimed" not in receipt.coverage.known_gaps
        rendered = str(receipt.document if fmt == "json" else receipt.human_text)
        # A local-only check asked for on a route that requires no review is not a disclosed
        # missing review on any rendering (#1041).
        assert "semantic_review_not_requested" not in receipt.coverage.known_gaps
        assert "semantic_review_not_requested" not in rendered
        assert "AI-powered review was not requested" not in rendered
        if fmt == "json":
            assert c2 in rendered
        assert "Original missing scope" not in rendered
        assert receipt.conclusion != "no_issue_detected"


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
async def test_succeeded_review_records_assessable_conclusion_durably(
    backend: Literal["memory", "sqlite"],
) -> None:
    app, runtime, _ = _build_app(seed_offset=40, semantic="optional", ledger_backend=backend)
    started, checked, _ = await _bootstrap_finding(app, seed=8000, mode="semantic_if_configured")
    ledger, _ = runtime.resources[started.task_id]
    records = tuple([row async for row in ledger.load_events(started.session_id)])
    row = next(row for row in reversed(records) if type(row.payload) is CheckRecordedPayload)
    # Every completed check now carries frozen-work totals, so the conclusion rides on 1.4.0.
    assert row.schema.version == "1.4.0"
    assert type(row.payload) is CheckRecordedPayload
    assert row.payload.semantic_conclusion == "no_material_discrepancy"
    assert row.payload.totals is not None
    rebuilt = replay(records)
    assert Frontier(rebuilt.frontier, rebuilt.head_digest) == checked.result_frontier


def _semantic_challenge_evaluator(
    claim_ref: str,
    *,
    subjects: tuple[str, ...] = (),
    next_step: ReviewerNextStep = "provide_evidence",
) -> Callable[..., Awaitable[object]]:
    """Raise one AI-powered challenge about *claim_ref*, also citing any further *subjects*.

    The default asks the agent to record the result that supports the claim (``provide_evidence``),
    which is what its message says; a ``state_unresolved_limitation`` request is a disclosure the
    agent acknowledges once (tb4n3 RC-1), so it has its own tests.
    """

    cited = tuple(sorted({claim_ref, *subjects}, key=str.encode))

    async def evaluate(
        frozen: object,
        findings: object,
        runtime: object | None = None,
        lineage_evaluation: object | None = None,
    ) -> object:
        succeeded = cast(FinalSemanticEvaluation, await _semantic_succeeds(frozen, findings))
        challenge = ReviewerChallenge(
            FindingKind.CLAIM_WITHOUT_ADMISSIBLE_EVIDENCE,
            "The completion claim has no readable support.",
            cited,
            "The claim cites only an open obligation.",
            "The work may be done but unrecorded.",
            "Record the result that supports the claim.",
            next_step,
            "No result content is in the packet.",
        )
        return replace(succeeded, judgment=SemanticJudgment("challenges_returned", (challenge,)))

    return evaluate


async def test_acknowledging_a_limitation_request_needs_no_resolution_attempt() -> None:
    """tb4n3 RC-1 (owner decision Q4): the reviewer asked the agent to state a limit, so one
    reasoned acknowledgement settles it; the repair-attempt rule above is for repair demands."""

    seed = 5350
    app, _runtime, _ = _build_app(
        seed_offset=54,
        semantic="optional",
        semantic_evaluator=_semantic_challenge_evaluator(
            protocol_id("clm_", seed + 5), next_step="state_unresolved_limitation"
        ),
    )
    started, checked, _obligation = await _bootstrap_finding(
        app, seed=seed, mode="semantic_if_configured"
    )
    finding = next(
        item for item in checked.findings if item.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED
    )
    # The request is a disclosure to acknowledge, not work (other findings of the bootstrap may
    # still make the check action_required).
    assert finding.challenge is not None
    assert finding.challenge.requested_next_step == "state_unresolved_limitation"
    recorded = await app.respond(
        RespondRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 10)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(checked.result_frontier),
                "finding_id": finding.finding_id,
                "finding_frontier": _frontier(checked.result_frontier),
                "disposition": "acknowledged",
                "reason": "The result content is withheld by the task design; stated as a limit.",
            }
        )
    )
    assert recorded.response.disposition == "acknowledged"
    assert recorded.closure_after is not None
    assert recorded.closure_after.limitation == "limitation_disclosed"


async def test_accepting_a_semantic_finding_requires_a_recorded_resolution_attempt() -> None:
    """Issue #885: accepting a repair demand is not an answer until one concrete attempt is recorded.

    A reviewer's limitation request is the exception (tb4n3 RC-1, owner decision Q4): it asks for a
    disclosure, so one reasoned acknowledgement settles it (``test_acknowledging_a_limitation...``).
    """

    seed = 5300
    app, _runtime, _ = _build_app(
        seed_offset=53,
        semantic="optional",
        semantic_evaluator=_semantic_challenge_evaluator(protocol_id("clm_", seed + 5)),
    )
    started, checked, _obligation = await _bootstrap_finding(
        app, seed=seed, mode="semantic_if_configured"
    )
    finding = next(
        item for item in checked.findings if item.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED
    )

    def respond_wire(
        request_seed: int,
        frontier: Frontier | FrontierModel,
        disposition: str,
        refs: tuple[str, ...] = (),
    ) -> RespondRequest:
        wire: dict[str, JsonValue] = {
            **_request_base(protocol_id("req_", request_seed)),
            "session_id": started.session_id,
            "writer_id": started.writer_id,
            "expected_frontier": _frontier(frontier),
            "finding_id": finding.finding_id,
            "finding_frontier": _frontier(checked.result_frontier),
            "disposition": disposition,
            "reason": "The evidence-provenance limitation is accepted.",
        }
        if refs:
            wire["evidence_refs"] = refs
        return RespondRequest.model_validate(wire)

    with pytest.raises(PublicOperationError) as refused:
        await app.respond(respond_wire(seed + 10, checked.result_frontier, "acknowledged"))
    assert refused.value.code is PublicErrorCode.INVALID_REQUEST, refused.value.message
    assert dict(refused.value.safe_details) == {
        "continuation": "input_correction_new_identity",
        "field": "/evidence_refs",
        "reason_code": "resolution_attempt_required",
    }

    # A dispute is not an acceptance and keeps its own contract.
    disputed = await app.respond(respond_wire(seed + 11, checked.result_frontier, "rejected"))
    assert disputed.response.disposition == "rejected"

    evidence_ref = protocol_id("evd_", seed + 12)
    published = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 13)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(disputed.result_frontier),
                "event_drafts": (
                    {
                        "event_id": protocol_id("evt_", seed + 14),
                        "schema": {"name": "evidence_recorded", "version": "1.0.0"},
                        "occurred_at": "2026-07-19T12:00:02.000Z",
                        "causal_parents": (),
                        "payload": {
                            "evidence_id": evidence_ref,
                            "evidence_kind": "artifact",
                            "strength": "mutable_reference",
                            "observed_at": "2026-07-19T12:00:02.000Z",
                            "reference": "attempted-verification",
                        },
                        "artifact_refs": (),
                        "evidence_refs": (),
                    },
                ),
            }
        )
    )
    accepted = await app.respond(
        respond_wire(seed + 15, published.result_frontier, "acknowledged", (evidence_ref,))
    )
    assert accepted.response.disposition == "acknowledged"
    assert tuple(item.reference_id for item in accepted.response.evidence) == (evidence_ref,)


def _scripted_reviewer(
    rounds: list[Callable[[FrozenCase], tuple[ReviewerChallenge, ...]]],
) -> Callable[..., Awaitable[object]]:
    """Answer each check with the next scripted round of reviewer challenges."""

    async def evaluate(
        frozen: object,
        findings: object,
        runtime: object | None = None,
        lineage_evaluation: object | None = None,
    ) -> object:
        succeeded = cast(FinalSemanticEvaluation, await _semantic_succeeds(frozen, findings))
        challenges = rounds.pop(0)(cast(FrozenCase, frozen))
        return replace(succeeded, judgment=SemanticJudgment("challenges_returned", challenges))

    return evaluate


async def test_process_finding_is_answered_by_the_completed_review_but_work_findings_are_not() -> (
    None
):
    """Issue #906 scripted replay of the kea/dateutil shapes through check and respond.

    Check 1 (kea check 1): the reviewer reports two distinct problems in one round, an open work
    obligation under a completion claim and a code defect; both land as findings. The agent rejects
    the defect. Check 2: a record-state finding cites only an earlier ``check_recorded`` row (FinishUP
    process state). ``acknowledged`` on it needs no filler publish, because the completed review
    recorded after it is its resolution. The work-obligation finding, a finding that mixes a process
    row with the claim, and a work-kind finding that cites only the check row while challenging what
    it established keep the ``resolution_attempt_required`` gate. Checks 3 and 4: restatements are
    about what they restate, and a finding about the agent's own response keeps the gate.
    """

    seed = 5600
    obligation_ref = protocol_id("obl_", seed + 1)
    claim_ref = protocol_id("clm_", seed + 5)

    def two_distinct_problems(_frozen: FrozenCase) -> tuple[ReviewerChallenge, ...]:
        return (
            ReviewerChallenge(
                FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS,
                "Completion is claimed while the result obligation is open.",
                (obligation_ref,),
                "The obligation to publish a result is still open under the completion claim.",
                "The result may exist but was not recorded against the obligation.",
                "Publish the result and resolve the obligation, or narrow the claim.",
                "act",
                "The packet carries no result for the obligation.",
            ),
            ReviewerChallenge(
                FindingKind.DIFF_DOES_NOT_MATCH_ACCOUNT,
                "Map dependency paths collide for distinct keys with the same string form.",
                (claim_ref,),
                "The change keys dependencies by String(key), so distinct keys collide.",
                "Keys may never share a string form in practice.",
                "Key dependency paths by identity and add a collision test.",
                "act",
                "No test exercises two keys with one string form.",
            ),
        )

    def process_rows(frozen: FrozenCase) -> tuple[ReviewerChallenge, ...]:
        prior_check = next(
            str(item.event_id)
            for item in frozen.case.history
            if item.schema_name == "check_recorded"
        )
        return (
            ReviewerChallenge(
                FindingKind.LEDGER_STALE_OR_INCOMPLETE,
                "The earlier check left its findings unsettled.",
                (prior_check,),
                "The earlier check still carries open findings.",
                "Those findings may simply await this review.",
                "Record the outcome of the earlier check.",
                "provide_evidence",
                "The packet does not show the earlier findings resolved.",
            ),
            ReviewerChallenge(
                FindingKind.EVIDENCE_DOES_NOT_SUPPORT_CLAIM,
                "The completion claim rests on the earlier check.",
                (prior_check, claim_ref),
                "The claim cites the earlier check rather than a recorded result.",
                "The earlier check may have covered the result.",
                "Record the result that supports the claim.",
                "provide_evidence",
                "No result content is in the packet.",
            ),
            # Cites only the earlier check row, but challenges what that check established about
            # the work: a work kind keeps the gate even with a process-only subject set.
            ReviewerChallenge(
                FindingKind.STALE_EVIDENCE_FOR_CHANGED_STATE,
                "The earlier check verified code the collision change has since replaced.",
                (prior_check,),
                "The earlier check ran before the dependency-key change it is cited for.",
                "The change may not affect what the earlier check exercised.",
                "Re-verify the dependency-key change and record the result.",
                "act",
                "No verification after the dependency-key change is in the packet.",
            ),
        )

    rounds = [two_distinct_problems, process_rows]
    app, _runtime, _ = _build_app(
        seed_offset=56, semantic="optional", semantic_evaluator=_scripted_reviewer(rounds)
    )
    started, checked, _obligation = await _bootstrap_finding(
        app, seed=seed, mode="semantic_if_configured", max_findings="8"
    )
    assert checked.suppressed_count == 0
    first_round = [
        item for item in checked.findings if item.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED
    ]
    # Every distinct problem the reviewer returned in one round is recorded; nothing drops the
    # open work obligation as "process state".
    assert {item.kind for item in first_round} == {
        FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS,
        FindingKind.DIFF_DOES_NOT_MATCH_ACCOUNT,
    }
    work_finding = next(
        item for item in first_round if item.kind is FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS
    )
    defect_finding = next(
        item for item in first_round if item.kind is FindingKind.DIFF_DOES_NOT_MATCH_ACCOUNT
    )
    answered = await app.respond(
        RespondRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 15)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(checked.result_frontier),
                "finding_id": defect_finding.finding_id,
                "finding_frontier": _frontier(checked.result_frontier),
                "disposition": "rejected",
                "reason": "Keys never share a string form in this store.",
            }
        )
    )

    rechecked = await app.check(
        CheckRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 20)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(answered.result_frontier),
                "mode": "semantic_if_configured",
                "max_findings": "8",
            }
        )
    )
    assert type(rechecked) is CheckCommitResult
    assert rounds == []
    second_round = {
        item.kind: item
        for item in rechecked.findings
        if item.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED
    }
    assert rechecked.suppressed_count == 0
    process_finding = second_round[FindingKind.LEDGER_STALE_OR_INCOMPLETE]
    mixed_finding = second_round[FindingKind.EVIDENCE_DOES_NOT_SUPPORT_CLAIM]
    check_cited_work_finding = second_round[FindingKind.STALE_EVIDENCE_FOR_CHANGED_STATE]

    def acknowledge(
        request_seed: int,
        finding: Finding,
        finding_frontier: Frontier | FrontierModel,
        expected: Frontier | FrontierModel,
    ) -> RespondRequest:
        return RespondRequest.model_validate(
            {
                **_request_base(protocol_id("req_", request_seed)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(expected),
                "finding_id": finding.finding_id,
                "finding_frontier": _frontier(finding_frontier),
                "disposition": "acknowledged",
                "reason": "The completed review recorded after this finding answers it.",
            }
        )

    accepted = await app.respond(
        acknowledge(
            seed + 30, process_finding, rechecked.result_frontier, rechecked.result_frontier
        )
    )
    assert accepted.response.disposition == "acknowledged"
    assert accepted.response.evidence == ()

    for request_seed, finding, finding_frontier in (
        (seed + 31, mixed_finding, rechecked.result_frontier),
        (seed + 33, work_finding, checked.result_frontier),
        (seed + 34, check_cited_work_finding, rechecked.result_frontier),
    ):
        with pytest.raises(PublicOperationError) as refused:
            await app.respond(
                acknowledge(request_seed, finding, finding_frontier, accepted.result_frontier)
            )
        assert refused.value.code is PublicErrorCode.INVALID_REQUEST, refused.value.message
        assert refused.value.safe_details["reason_code"] == "resolution_attempt_required"

    # Check 3: the reviewer restates earlier findings by citing only their finding_recorded rows.
    # A restatement is about whatever the restated finding was about: restating the code defect
    # keeps the gate, while restating the process finding stays a process finding. A finding about
    # the agent's own response keeps the gate too.
    restated = {
        "defect": defect_finding.finding_id,
        "process": process_finding.finding_id,
        "check_cited_work": check_cited_work_finding.finding_id,
    }

    def restatements(frozen: FrozenCase) -> tuple[ReviewerChallenge, ...]:
        def source(key: str) -> str:
            record = frozen.case.projection.findings[finding_id(restated[key])]
            return str(record.source_event_id)

        return (
            ReviewerChallenge(
                FindingKind.DIFF_DOES_NOT_MATCH_ACCOUNT,
                "The earlier collision defect still stands.",
                (source("defect"),),
                "The recorded collision finding is not repaired by any later change.",
                "The rejection may rest on facts the packet does not carry.",
                "Key dependency paths by identity and add a collision test.",
                "act",
                "The packet carries no later change to the dependency keys.",
            ),
            ReviewerChallenge(
                FindingKind.LEDGER_STALE_OR_INCOMPLETE,
                "The earlier finding about the prior check is still open.",
                (source("process"),),
                "The finding about the earlier check has no recorded outcome.",
                "It may simply await this review.",
                "Record the outcome of the earlier check.",
                "provide_evidence",
                "The packet does not show that finding resolved.",
            ),
            # An agent's answer is the agent's own content, never process state.
            ReviewerChallenge(
                FindingKind.WEAK_OR_STALE_RESPONSE,
                "The rejection of the collision finding gives no grounds.",
                (agent_answer(frozen),),
                "The response rejects the finding without citing a test or the change.",
                "The agent may hold unrecorded grounds for the rejection.",
                "Cite the test or change that shows distinct keys cannot collide.",
                "dispute_with_evidence",
                "The packet carries no evidence for the rejection.",
            ),
        )

    def agent_answer(frozen: FrozenCase) -> str:
        return next(
            str(item.event_id)
            for item in frozen.case.history
            if item.schema_name == "response_recorded"
        )

    def work_restatement(frozen: FrozenCase) -> tuple[ReviewerChallenge, ...]:
        record = frozen.case.projection.findings[finding_id(restated["check_cited_work"])]
        # A record-state restatement of a work finding is still about the work.
        return (
            ReviewerChallenge(
                FindingKind.LEDGER_STALE_OR_INCOMPLETE,
                "The stale-verification finding has no recorded outcome.",
                (str(record.source_event_id),),
                "The finding about verification of the replaced code is still open.",
                "It may simply await this review.",
                "Record the outcome of that finding.",
                "provide_evidence",
                "The packet does not show that finding resolved.",
            ),
        )

    rounds.extend((restatements, work_restatement))
    third = await app.check(
        CheckRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 40)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(accepted.result_frontier),
                "mode": "semantic_if_configured",
                "max_findings": "8",
            }
        )
    )
    assert type(third) is CheckCommitResult
    assert third.suppressed_count == 0
    third_round = {
        item.summary: item
        for item in third.findings
        if item.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED
    }
    restated_defect = third_round["The earlier collision defect still stands."]
    restated_process = third_round["The earlier finding about the prior check is still open."]
    response_finding = third_round["The rejection of the collision finding gives no grounds."]
    for request_seed, finding in ((seed + 41, restated_defect), (seed + 43, response_finding)):
        with pytest.raises(PublicOperationError) as refused:
            await app.respond(
                acknowledge(request_seed, finding, third.result_frontier, third.result_frontier)
            )
        assert refused.value.safe_details["reason_code"] == "resolution_attempt_required"
    process_again = await app.respond(
        acknowledge(seed + 42, restated_process, third.result_frontier, third.result_frontier)
    )
    assert process_again.response.disposition == "acknowledged"
    assert process_again.response.evidence == ()

    # Check 4: a record-state restatement of the check-citing work finding keeps the gate.
    fourth = await app.check(
        CheckRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 50)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(process_again.result_frontier),
                "mode": "semantic_if_configured",
                "max_findings": "8",
            }
        )
    )
    assert type(fourth) is CheckCommitResult
    assert fourth.suppressed_count == 0
    assert rounds == []
    restated_work = next(
        item
        for item in fourth.findings
        if item.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED
        and item.summary == "The stale-verification finding has no recorded outcome."
    )
    with pytest.raises(PublicOperationError) as refused:
        await app.respond(
            acknowledge(seed + 51, restated_work, fourth.result_frontier, fourth.result_frontier)
        )
    assert refused.value.safe_details["reason_code"] == "resolution_attempt_required"


def _scripted_semantic_evaluator(
    claim_ref: str,
    conclusions: list[str],
    *,
    case_gaps: tuple[str, ...],
    over_item_limit: bool,
    scope_reduced: list[bool] | None = None,
    omitted_refs: list[tuple[str, ...]] | None = None,
    subjects: tuple[str, ...] = (),
) -> Callable[..., Awaitable[object]]:
    """Answer each check with the next scripted conclusion under the same capture limits.

    ``scope_reduced`` scripts, per check, whether the review packet carried a reduced reference
    scope; omitted, no packet is reduced. ``omitted_refs`` scripts, per reduced check, which
    frozen references its sent packet carried no content item for; every other one is reported as
    sent. Omitted, a reduced review reports nothing about what it sent.
    """

    async def evaluate(
        frozen: object,
        findings: object,
        runtime: object | None = None,
        lineage_evaluation: object | None = None,
    ) -> object:
        raised = cast(
            FinalSemanticEvaluation,
            await _semantic_challenge_evaluator(claim_ref, subjects=subjects)(frozen, findings),
        )
        conclusion = conclusions.pop(0)
        judgment = (
            raised.judgment
            if conclusion == "challenges_returned"
            else SemanticJudgment("no_material_discrepancy", ())
        )
        reduced = bool(scope_reduced and scope_reduced.pop(0))
        included: frozenset[str] | None = None
        if reduced and omitted_refs:
            allowed = cast(FrozenCase, frozen).case.allowed_ids
            included = frozenset(str(ref) for ref in allowed) - set(omitted_refs.pop(0))
        return replace(
            raised,
            judgment=judgment,
            case_content_gaps=case_gaps,
            case_content_over_item_limit=over_item_limit,
            case_reference_scope_reduced=reduced,
            case_included_refs=included,
        )

    return evaluate


@pytest.mark.parametrize(
    ("case_gaps", "over_item_limit"),
    [
        (("content_capture_unavailable",), False),
        (("content_unselected",), False),
        (("captured_object_unavailable", "content_capture_unavailable"), False),
        ((), True),
        # A review without the task statement (issue #908) is an unchanged recorded limit.
        (("task_statement_not_authorized", "task_statement_unavailable"), False),
        (("task_statement_not_supplied",), False),
    ],
)
async def test_semantic_finding_resolves_within_its_recorded_capture_baseline(
    case_gaps: tuple[str, ...], over_item_limit: bool
) -> None:
    """Issue #884 through the real check, replay, status and receipt path.

    The finding records the capture limits its review ran under. An unchanged re-run proves
    nothing; after material work, a completed review under the same recorded limits resolves it,
    while every limit stays on the receipt and the conclusion is never clean.
    """

    seed = 5400
    expected_gaps: set[str] = set(case_gaps)
    if over_item_limit:
        expected_gaps.add("semantic_case_content_over_item_limit")
    conclusions = ["challenges_returned", "no_material_discrepancy", "no_material_discrepancy"]
    app, _runtime, _ = _build_app(
        seed_offset=54,
        semantic="optional",
        semantic_evaluator=_scripted_semantic_evaluator(
            protocol_id("clm_", seed + 5),
            conclusions,
            case_gaps=case_gaps,
            over_item_limit=over_item_limit,
        ),
    )
    started, checked, _obligation = await _bootstrap_finding(
        app, seed=seed, mode="semantic_if_configured"
    )
    finding = next(
        item for item in checked.findings if item.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED
    )
    # P0: the capture baseline is durable finding coverage, not only check coverage.
    assert expected_gaps <= set(finding.coverage.known_gaps)
    assert expected_gaps <= set(checked.coverage.known_gaps)

    async def recheck(request_seed: int, frontier: Frontier | FrontierModel) -> CheckCommitResult:
        result = await app.check(
            CheckRequest.model_validate(
                {
                    **_request_base(protocol_id("req_", request_seed)),
                    "session_id": started.session_id,
                    "writer_id": started.writer_id,
                    "expected_frontier": _frontier(frontier),
                    "mode": "semantic_if_configured",
                    "max_findings": "8",
                }
            )
        )
        assert type(result) is CheckCommitResult
        return result

    async def resolved(request_seed: int) -> bool:
        view = await _findings_view(app, started, request_seed, include_resolved=True)
        return next(item for item in view.items if item.finding_id == finding.finding_id).resolved

    # A re-run over unchanged state that merely does not repeat the issue is not proof.
    rerolled = await recheck(seed + 20, checked.result_frontier)
    assert finding.finding_id not in {item.finding_id for item in rerolled.findings}
    assert await resolved(seed + 21) is False

    evidence_ref = protocol_id("evd_", seed + 30)
    published = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 31)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(rerolled.result_frontier),
                "event_drafts": (
                    {
                        "event_id": protocol_id("evt_", seed + 32),
                        "schema": {"name": "evidence_recorded", "version": "1.0.0"},
                        "occurred_at": "2026-07-19T12:00:03.000Z",
                        "causal_parents": (),
                        "payload": {
                            "evidence_id": evidence_ref,
                            "evidence_kind": "artifact",
                            "strength": "mutable_reference",
                            "observed_at": "2026-07-19T12:00:03.000Z",
                            "reference": "repair-evidence",
                        },
                        "artifact_refs": (),
                        "evidence_refs": (),
                    },
                ),
            }
        )
    )
    repaired = await recheck(seed + 40, published.result_frontier)
    assert expected_gaps <= set(repaired.coverage.known_gaps)
    assert await resolved(seed + 41) is True
    assert conclusions == []

    receipt = await app.receipt(
        ReceiptRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 50)),
                "task_id": started.task_id,
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(repaired.result_frontier),
                "format": "json",
                "include": "standard",
                "redaction_profile": "full_local",
            }
        )
    )
    # Resolution never removes the recorded capture limits, and no clean receipt results.
    assert expected_gaps <= set(receipt.coverage.known_gaps)
    assert receipt.conclusion != "no_issue_detected"


async def test_a_defect_the_review_still_finds_after_repair_stays_current() -> None:
    """Material work does not close a finding the later completed review returns again."""

    seed = 5500
    conclusions = ["challenges_returned", "challenges_returned"]
    app, _runtime, _ = _build_app(
        seed_offset=55,
        semantic="optional",
        semantic_evaluator=_scripted_semantic_evaluator(
            protocol_id("clm_", seed + 5),
            conclusions,
            case_gaps=("content_capture_unavailable",),
            over_item_limit=False,
        ),
    )
    started, checked, _obligation = await _bootstrap_finding(
        app, seed=seed, mode="semantic_if_configured"
    )
    finding = next(
        item for item in checked.findings if item.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED
    )
    published = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 31)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(checked.result_frontier),
                "event_drafts": (
                    {
                        "event_id": protocol_id("evt_", seed + 32),
                        "schema": {"name": "evidence_recorded", "version": "1.0.0"},
                        "occurred_at": "2026-07-19T12:00:03.000Z",
                        "causal_parents": (),
                        "payload": {
                            "evidence_id": protocol_id("evd_", seed + 30),
                            "evidence_kind": "artifact",
                            "strength": "mutable_reference",
                            "observed_at": "2026-07-19T12:00:03.000Z",
                            "reference": "unrelated-evidence",
                        },
                        "artifact_refs": (),
                        "evidence_refs": (),
                    },
                ),
            }
        )
    )
    rechecked = await app.check(
        CheckRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 40)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(published.result_frontier),
                "mode": "semantic_if_configured",
                "max_findings": "8",
            }
        )
    )
    assert type(rechecked) is CheckCommitResult
    view = await _findings_view(app, started, seed + 41, include_resolved=True)
    by_id = {item.finding_id: item for item in view.items}
    assert by_id[finding.finding_id].resolved is False
    # Issue #905: the unchanged restatement is seen again and suppressed rather than minted as a
    # second row, and it is recorded on the open item as ``still_present`` so the later review
    # still speaks for it: suppression never reads as absence.
    refired = [
        item
        for item in rechecked.findings
        if item.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED and item.kind is finding.kind
    ]
    assert refired == []
    assert "semantic_restatements_suppressed" in rechecked.coverage.known_gaps
    assert by_id[finding.finding_id].todo_state == "open"
    assert by_id[finding.finding_id].review_rounds == "1"


# Issue #912: the publication recipe's caller digests are a disclosed provenance label, never an
# unclearable finding. The drafts below follow `publication-policy.md` "Making a change reviewable"
# verbatim: the hunk travels in ``description`` and its SHA-256 as a ``caller_asserted``
# ``digest_only`` binding, exactly the shape the DeepSWE v2 agents published.
_ISSUE_912_HUNKS: tuple[str, ...] = (
    "@@ -41,6 +41,9 @@ export function serializeError(error: Error) {\n"
    "   const result = { name: error.name, message: error.message };\n"
    "+  if (error.stack !== undefined) {\n"
    "+    result.stack = error.stack;\n"
    "+  }\n"
    "   return result;\n",
    "@@ -88,4 +91,5 @@ export function deserializeError(value: SerializedError) {\n"
    "   const error = new Error(value.message);\n"
    "+  error.stack = value.stack;\n"
    "   return error;\n",
    "@@ -12,3 +12,8 @@ describe('error stack', () => {\n"
    "+  it('round-trips the stack', () => {\n"
    "+    const copy = deserialize(serialize(new Error('x')));\n"
    "+    expect(copy.stack).toContain('Error: x');\n"
    "+  });\n",
    "@@ -3,2 +3,3 @@ import { registerCustom } from './registry';\n"
    "+import { serializeError, deserializeError } from './error';\n",
    "PASS  test/error-stack.test.ts\n  error stack\n    ✓ round-trips the stack (3 ms)\n",
)
_ISSUE_912_OPEN_OBLIGATION: dict[str, JsonValue] = {
    "description": "Serialize and restore Error stack traces.",
    "acceptance_criteria": "A deserialized error keeps the original stack text.",
    "evidence_expectation": "The source change and a passing round-trip test.",
    "status": "open",
}


def _caller_digest_excerpt_draft(
    seed: int,
    hunk: str,
    *,
    subject: str,
    availability: Literal["digest_only", "withheld"] = "digest_only",
) -> dict[str, JsonValue]:
    data = hunk.encode("utf-8")
    return {
        "event_id": protocol_id("evt_", seed),
        "schema": {"name": "evidence_recorded", "version": "1.1.0"},
        "occurred_at": "2026-09-28T10:00:00.000Z",
        "causal_parents": (),
        "payload": {
            "evidence_id": protocol_id("evd_", seed + 1),
            "evidence_kind": "artifact",
            "strength": "content_digest",
            "content_digest": "sha256:" + hashlib.sha256(data).hexdigest(),
            "observed_at": "2026-09-28T10:00:00.000Z",
            "description": hunk,
            "digest_binding": {
                "subject": subject,
                "content_availability": availability,
                "byte_count": len(data),
                "provenance": "caller_asserted",
            },
        },
        "artifact_refs": (),
        "evidence_refs": (),
    }


def _obligation_draft_912(
    seed: int, obligation_id: str, *, resolved_by: tuple[str, ...] = ()
) -> dict[str, JsonValue]:
    payload: dict[str, JsonValue] = dict(_ISSUE_912_OPEN_OBLIGATION)
    if resolved_by:
        payload["status"] = "resolved"
        payload["resolution_evidence_refs"] = tuple(sorted(resolved_by))
    return {
        "event_id": protocol_id("evt_", seed),
        "schema": {"name": "obligation_published", "version": "1.0.0"},
        "occurred_at": "2026-09-28T10:00:01.000Z",
        "causal_parents": (),
        "payload": {"obligation_id": obligation_id, **payload},
        "artifact_refs": (),
        "evidence_refs": tuple(sorted(resolved_by)),
    }


def _completion_claim_draft_912(
    seed: int,
    claim_id: str,
    obligation_id: str,
    supporting_refs: tuple[str, ...],
    *,
    supersedes: tuple[str, ...] = (),
) -> dict[str, JsonValue]:
    return {
        "event_id": protocol_id("evt_", seed),
        "schema": {"name": "claim_recorded", "version": "1.1.0"},
        "occurred_at": "2026-09-28T10:00:02.000Z",
        "causal_parents": (),
        "payload": {
            "claim_id": claim_id,
            "claim_kind": "completion",
            "statement": "Error stacks now survive serialization; the round-trip test passes.",
            "supporting_refs": tuple(sorted((*supporting_refs, obligation_id))),
            "obligation_refs": (obligation_id,),
            "limitation_refs": (),
            "supersedes_claim_refs": tuple(sorted(supersedes)),
        },
        "artifact_refs": (),
        "evidence_refs": (),
    }


async def _publish_912(
    app: Application,
    started: StartInternalResult,
    frontier: Frontier | FrontierModel,
    seed: int,
    drafts: tuple[dict[str, JsonValue], ...],
) -> PublishWorkInternalResult:
    result = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(frontier),
                "event_drafts": drafts,
            }
        )
    )
    assert type(result) is PublishWorkInternalResult, f"unexpected publish outcome: {type(result)}"
    return result


async def _check_912(
    app: Application, started: StartInternalResult, frontier: Frontier | FrontierModel, seed: int
) -> CheckCommitResult:
    checked = await app.check(
        CheckRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(frontier),
                "mode": "deterministic_only",
                "max_findings": "8",
            }
        )
    )
    assert type(checked) is CheckCommitResult, f"unexpected nonterminal check: {type(checked)}"
    return checked


def _provenance_findings(findings: tuple[Finding, ...]) -> tuple[Finding, ...]:
    """Findings that report, or send the agent after, a caller digest's provenance."""

    return tuple(
        finding
        for finding in findings
        if finding.kind is FindingKind.LEDGER_STALE_OR_INCOMPLETE
        or "evidence_content_digest_only" in finding.detail
        or "content-bearing" in finding.detail
    )


async def _receipt_912(
    app: Application,
    started: StartInternalResult,
    frontier: Frontier | FrontierModel,
    seed: int,
    receipt_format: Literal["json", "markdown", "text"],
):
    return await app.receipt(
        ReceiptRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed)),
                "task_id": started.task_id,
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(frontier),
                "format": receipt_format,
                "include": "standard",
                "redaction_profile": "full_local",
            }
        )
    )


async def _compact_912(app: Application, started: StartInternalResult, seed: int):
    status = await app.status(
        StatusRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "view": "compact",
                "limit": "10",
            }
        )
    )
    return cast(StatusCompactPageModel, status.page).items[0], status.closure_readiness


@pytest.mark.parametrize("ledger_backend", ("memory", "sqlite"))
async def test_growing_caller_digest_excerpts_mint_no_finding_and_one_receipt_label(
    ledger_backend: Literal["memory", "sqlite"],
) -> None:
    """Issue #912, superjson C replay: five checks, five subject-set sizes, zero finding ids.

    The agent resolves its obligation with a digest-only diff excerpt (the "permanent from birth"
    shape: 28/32 attempts), then keeps publishing further bounded excerpts and a corrected claim
    citing all of them, checking after each round. Before the fix every round minted a new
    ``ledger_stale_or_incomplete`` id whose text asked for "content-bearing evidence". Now none is
    raised, nothing is left to answer, and the receipt still discloses once, with the exact count,
    that FinishUP did not verify those caller digests.
    """

    app, _runtime, _ = _build_app(seed_offset=40, ledger_backend=ledger_backend)
    started = await app.start(start_request(9120, title="Digest-only evidence replay"))
    obligation_id = protocol_id("obl_", 9121)
    opened = await _publish_912(
        app, started, started.frontier, 9122, (_obligation_draft_912(9123, obligation_id),)
    )

    first = _caller_digest_excerpt_draft(9130, _ISSUE_912_HUNKS[0], subject="source_diff")
    evidence_refs = [cast(str, cast(dict[str, JsonValue], first["payload"])["evidence_id"])]
    claim_id = protocol_id("clm_", 9133)
    published = await _publish_912(
        app,
        started,
        opened.result_frontier,
        9134,
        (
            first,
            _obligation_draft_912(9135, obligation_id, resolved_by=tuple(evidence_refs)),
            _completion_claim_draft_912(9136, claim_id, obligation_id, tuple(evidence_refs)),
        ),
    )
    checked = await _check_912(app, started, published.result_frontier, 9137)
    returned: list[tuple[str, ...]] = [tuple(item.finding_id for item in checked.findings)]
    assert _provenance_findings(checked.findings) == ()
    assert "evidence_content_digest_only" in checked.coverage.known_gaps

    for round_index, hunk in enumerate(_ISSUE_912_HUNKS[1:], start=1):
        base = 9140 + round_index * 10
        excerpt = _caller_digest_excerpt_draft(base, hunk, subject="bounded_excerpt")
        evidence_refs.append(
            cast(str, cast(dict[str, JsonValue], excerpt["payload"])["evidence_id"])
        )
        replacement = protocol_id("clm_", base + 2)
        published = await _publish_912(
            app,
            started,
            checked.result_frontier,
            base + 3,
            (
                excerpt,
                _completion_claim_draft_912(
                    base + 4,
                    replacement,
                    obligation_id,
                    tuple(evidence_refs),
                    supersedes=(claim_id,),
                ),
            ),
        )
        claim_id = replacement
        checked = await _check_912(app, started, published.result_frontier, base + 5)
        assert _provenance_findings(checked.findings) == (), round_index
        assert "evidence_content_digest_only" in checked.coverage.known_gaps
        returned.append(tuple(item.finding_id for item in checked.findings))

    # Following the recipe verbatim leaves nothing to clear: no finding in any of the five checks,
    # where the unfixed service minted a fresh id each time the subject set grew.
    assert returned == [()] * len(_ISSUE_912_HUNKS), returned
    history = await _findings_view(app, started, 9200, include_resolved=True)
    assert all(item.kind != FindingKind.LEDGER_STALE_OR_INCOMPLETE.value for item in history.items)
    compact, readiness = await _compact_912(app, started, 9201)
    assert compact.unanswered_finding_count == "0"
    assert "findings_unanswered" not in readiness.blocking_conditions

    receipt = await _receipt_912(app, started, checked.result_frontier, 9202, "json")
    assert receipt.conclusion != "unresolved_findings_remain"
    assert "evidence_content_digest_only" in receipt.coverage.known_gaps
    body = _limitations_body(receipt.document)
    assert body.count("caller-asserted digest") == 1
    assert (
        f"{len(_ISSUE_912_HUNKS)} cited evidence items carry caller-asserted digests that FinishUP "
        "did not verify: the digest was recorded but the bytes were not retained."
    ) in body
    assert "withheld" not in body
    document = cast(dict[str, JsonValue], receipt.document)
    assert not any(
        str(cast(dict[str, JsonValue], gap)["code"]).startswith("retained_finding_coverage")
        for gap in cast(list[JsonValue], document["gaps"])
    )
    text = await _receipt_912(app, started, receipt.result_frontier, 9203, "text")
    assert text.human_text is not None
    assert "cited evidence items carry caller-asserted digests" in text.human_text
    assert "content-bearing" not in text.human_text


@pytest.mark.parametrize("ledger_backend", ("memory", "sqlite"))
async def test_receipt_label_keeps_digest_only_and_withheld_retention_apart(
    ledger_backend: Literal["memory", "sqlite"],
) -> None:
    """Review finding PR925-F3: the count-bearing label must not merge two retention facts.

    A ``digest_only`` item kept its digest but the bytes were never retained; a ``withheld`` item
    records that the publisher withheld the bytes. One cited item of each kind yields one label
    with a total and a per-kind breakdown, identically in the JSON, markdown and text receipts.
    """

    app, _runtime, _ = _build_app(seed_offset=41, ledger_backend=ledger_backend)
    started = await app.start(start_request(9700, title="Mixed caller-digest retention"))
    obligation_id = protocol_id("obl_", 9701)
    opened = await _publish_912(
        app, started, started.frontier, 9702, (_obligation_draft_912(9703, obligation_id),)
    )
    digest_only = _caller_digest_excerpt_draft(9710, _ISSUE_912_HUNKS[0], subject="source_diff")
    withheld = _caller_digest_excerpt_draft(
        9720, _ISSUE_912_HUNKS[1], subject="bounded_excerpt", availability="withheld"
    )
    refs = tuple(
        cast(str, cast(dict[str, JsonValue], draft["payload"])["evidence_id"])
        for draft in (digest_only, withheld)
    )
    published = await _publish_912(
        app,
        started,
        opened.result_frontier,
        9730,
        (
            digest_only,
            withheld,
            _obligation_draft_912(9731, obligation_id, resolved_by=refs),
            _completion_claim_draft_912(9732, protocol_id("clm_", 9733), obligation_id, refs),
        ),
    )
    checked = await _check_912(app, started, published.result_frontier, 9734)
    assert _provenance_findings(checked.findings) == ()
    assert {"evidence_content_digest_only", "evidence_content_withheld"} <= set(
        checked.coverage.known_gaps
    )

    expected = (
        "2 cited evidence items carry caller-asserted digests that FinishUP did not verify: "
        "1 is digest-only (the digest was recorded but the bytes were not retained) and "
        "1 is withheld (the publisher recorded the bytes as withheld)."
    )
    receipt = await _receipt_912(app, started, checked.result_frontier, 9740, "json")
    body = _limitations_body(receipt.document)
    assert body.count("caller-asserted digest") == 1
    assert expected in body
    frontier = receipt.result_frontier
    human_formats: tuple[tuple[int, Literal["markdown", "text"]], ...] = (
        (9741, "markdown"),
        (9742, "text"),
    )
    for seed, receipt_format in human_formats:
        rendered = await _receipt_912(app, started, frontier, seed, receipt_format)
        assert rendered.human_text is not None
        assert rendered.human_text.count("caller-asserted digest") == 1
        assert expected in rendered.human_text
        frontier = rendered.result_frontier


async def _append_native_tool_output_capture(
    app: Application,
    runtime: _WorkflowRuntime,
    started: StartInternalResult,
    *,
    seed: int,
    expected_frontier: int,
):
    """Append the production materialization of one captured Codex tool output (OBS-001).

    The envelope and manifest are the canonical fixture's recorded Codex ``PostToolUse`` shell
    output; only the narrative message part is left out, so the capture adds no unrelated gap.
    The captured bytes are stored, so the evidence is native ``observation_captured`` content.
    """

    fixture = cast(
        dict[str, JsonValue], load_fixture_json("canonical/OBS-001-captured-evidence.case.json")
    )
    source = cast(dict[str, JsonValue], fixture["input"])
    raw = cast(dict[str, JsonValue], source["envelope"])
    cursor = cast(dict[str, JsonValue], raw["cursor"])
    manifest = next(
        cast(dict[str, JsonValue], item)
        for item in cast(list[JsonValue], source["manifests"])
        if cast(dict[str, JsonValue], item)["content_kind"] == "tool_output"
    )
    captured_id = cast(str, manifest["object_id"])
    envelope = ObservationEnvelope(
        session_commitment=cast(str, raw["session_commitment"]),
        event_kind=cast(str, raw["event_kind"]),
        source_identity=cast(str, raw["source_identity"]),
        source=ObservationSource(cast(str, raw["source"])),
        cursor=ObservationCursor(
            cast(int, cursor["hook_seq"]),
            cast(int, cursor["session_stream_pos"]),
            cast(int, cursor["source_ordinal"]),
            cast(str, cursor["last_commitment"]),
            cast(str, cursor["mapping_version"]),
        ),
        receipt_time=Timestamp(cast(str, raw["receipt_time"])),
        structural_payload=DomainJsonObject(cast(dict[str, JsonValue], raw["structural_payload"])),
        content_object_refs=(captured_id,),
        gap_codes=(),
    )
    batch = materialize_observation_envelope(
        envelope,
        task_id=started.task_id,
        captured_content=(
            ObservationContentManifest(
                object_id=captured_id,
                envelope_digest=cast(str, manifest["envelope_digest"]),
                content_kind=ObservationContentKind(cast(str, manifest["content_kind"])),
                part_index=cast(int, manifest["part_index"]),
                part_count=cast(int, manifest["part_count"]),
                redacted=cast(bool, manifest["redacted"]),
                content_digest=cast(str, manifest["content_digest"]),
                content_bytes=cast(int, manifest["content_bytes"]),
            ),
        ),
    )
    assert batch.skip_reason is None and batch.coverage.known_gaps == ()
    ledger, objects = next(iter(runtime.resources.values()))
    now = app.clock.now_utc()
    output = b"3 passed, 0 failed\n\n"
    captured = await objects.finalize(
        await objects.stage(
            ObjectSource(data=output, declared_size=len(output)),
            ObjectMetadata(ObjectKind.CAPTURED_CONTENT, "text/plain", started.task_id, now),
            object_id=captured_id,
        )
    )
    entries: list[AppendEntry] = []
    for item in batch.drafts:
        metadata = ObjectMetadata(
            ObjectKind.EVENT_PAYLOAD,
            media_type_for(item.draft.schema.name),
            started.task_id,
            now,
        )
        payload_ref = await objects.finalize(
            await objects.stage(
                ObjectSource(data=item.payload_bytes, declared_size=len(item.payload_bytes)),
                metadata,
            )
        )
        entries.append(
            AppendEntry(
                item.draft,
                observation_author(),
                payload_ref,
                payload_ref.commitment,
                metadata.media_type,
                payload_ref.plaintext_size,
                batch.channel,
                batch.coverage,
                item.projection_status,
            )
        )
    appended = await ledger.append_batch(
        AppendCommand(
            started.task_id,
            started.session_id,
            started.writer_id,
            protocol_id("req_", seed),
            OperationKind.PUBLISH_WORK,
            _DIGEST,
            expected_frontier,
            tuple(entries),
            None,
            (captured,),
        )
    )
    evidence = next(
        cast(EvidenceRecordedPayload, item.draft.payload)
        for item in batch.drafts
        if item.draft.schema.name == "evidence_recorded"
    )
    assert evidence.digest_binding is not None
    assert evidence.strength is EvidenceImmutability.IMMUTABLE_SNAPSHOT
    return appended, str(evidence.evidence_id)


async def test_resolved_obligation_digest_is_one_disclosed_label_beside_native_support() -> None:
    """Issue #912, expr C replay: no permanence trap and no impossible instruction.

    A digest-only diff excerpt is locked into a resolved obligation's resolution refs, which stay
    in scope forever. The agent then switches to native captured evidence and corrects its claim
    to cite only that. Before the fix the resolved obligation kept a finding alive that told the
    agent to "record content-bearing evidence"; now no finding is raised, the native snapshot adds
    no provenance gap, and the receipt carries exactly one disclosed label counting that one item.
    """

    app, runtime, _ = _build_app(seed_offset=41)
    started = await app.start(start_request(9300, title="Resolved-obligation digest replay"))
    obligation_id = protocol_id("obl_", 9301)
    opened = await _publish_912(
        app, started, started.frontier, 9302, (_obligation_draft_912(9303, obligation_id),)
    )
    excerpt = _caller_digest_excerpt_draft(9310, _ISSUE_912_HUNKS[0], subject="source_diff")
    digest_ref = cast(str, cast(dict[str, JsonValue], excerpt["payload"])["evidence_id"])
    first_claim = protocol_id("clm_", 9312)
    published = await _publish_912(
        app,
        started,
        opened.result_frontier,
        9313,
        (
            excerpt,
            _obligation_draft_912(9314, obligation_id, resolved_by=(digest_ref,)),
            _completion_claim_draft_912(9315, first_claim, obligation_id, (digest_ref,)),
        ),
    )
    checked = await _check_912(app, started, published.result_frontier, 9316)
    assert _provenance_findings(checked.findings) == ()

    captured, native_ref = await _append_native_tool_output_capture(
        app,
        runtime,
        started,
        seed=9320,
        expected_frontier=checked.result_frontier.sequence,
    )
    corrected = await _publish_912(
        app,
        started,
        captured.result_frontier,
        9330,
        (
            _completion_claim_draft_912(
                9331,
                protocol_id("clm_", 9332),
                obligation_id,
                (native_ref,),
                supersedes=(first_claim,),
            ),
        ),
    )
    rechecked = await _check_912(app, started, corrected.result_frontier, 9333)
    assert _provenance_findings(rechecked.findings) == ()
    assert "evidence_content_digest_only" in rechecked.coverage.known_gaps
    assert "evidence_digest_subject_legacy_unknown" not in rechecked.coverage.known_gaps

    receipt = await _receipt_912(app, started, rechecked.result_frontier, 9340, "json")
    assert receipt.conclusion != "unresolved_findings_remain"
    body = _limitations_body(receipt.document)
    assert body.count("caller-asserted digest") == 1
    assert (
        "One cited evidence item carries a caller-asserted digest that FinishUP did not verify"
        in (body)
    )
    assert "content-bearing" not in body
    document = cast(dict[str, JsonValue], receipt.document)
    digest_gaps = [
        cast(dict[str, JsonValue], gap)
        for gap in cast(list[JsonValue], document["gaps"])
        if cast(dict[str, JsonValue], gap)["code"] == "evidence_content_digest_only"
    ]
    # The only unverified caller digest is the one the resolved obligation still cites.
    assert [gap["subject_refs"] for gap in digest_gaps] == [[protocol_id("evt_", 9310)]]


async def test_pre_upgrade_digest_finding_resolves_as_history_without_a_replacement() -> None:
    """Issue #912 lifecycle, geo C and koota-pair B replays on a ledger written before the fix.

    The pre-upgrade service recorded a digest-only ``ledger_stale_or_incomplete`` finding and the
    agent answered it. The first check after the upgrade neither returns it nor raises a
    replacement id; it proves the issue absent, so the old row becomes resolved history. A further
    identical recheck is a fixed point with nothing to answer, and the resolved row's coverage no
    longer lowers the receipt, which names the caller digest once as a label.
    """

    app, runtime, _ = _build_app(seed_offset=42)
    started = await app.start(start_request(9400, title="Pre-upgrade digest finding replay"))
    obligation_id = protocol_id("obl_", 9401)
    opened = await _publish_912(
        app, started, started.frontier, 9402, (_obligation_draft_912(9403, obligation_id),)
    )
    excerpt = _caller_digest_excerpt_draft(9410, _ISSUE_912_HUNKS[1], subject="bounded_excerpt")
    digest_ref = cast(str, cast(dict[str, JsonValue], excerpt["payload"])["evidence_id"])
    published = await _publish_912(
        app,
        started,
        opened.result_frontier,
        9412,
        (
            excerpt,
            _obligation_draft_912(9413, obligation_id, resolved_by=(digest_ref,)),
            _completion_claim_draft_912(
                9414, protocol_id("clm_", 9415), obligation_id, (digest_ref,)
            ),
        ),
    )
    frontier = Frontier(
        int(published.result_frontier.sequence), published.result_frontier.head_digest
    )
    kind = FindingKind.LEDGER_STALE_OR_INCOMPLETE
    old_coverage = replace(
        coverage_for_channel(PublicationChannel.ENGINE_DERIVED),
        check_types=(CheckType.DETERMINISTIC,),
        ledger_freshness=LedgerFreshness.PARTIAL,
        known_gaps=("evidence_content_digest_only", "semantic_review_not_requested"),
    )
    old = Finding(
        finding_id(protocol_id("fnd_", 9420)),
        kind,
        FindingOrigin.DETERMINISTIC,
        FINDING_KIND_TRAITS[kind][0],
        "The ledger is too incomplete for a current conclusion.",
        (
            f"Subjects: {protocol_id('evt_', 9410)}. Gaps: evidence_content_digest_only. Main "
            "agent: Treat the conclusion as coverage-limited. An evidence-provenance gap is not "
            "resolved by a finding response: record content-bearing evidence or accept the gap "
            "in the receipt."
        ),
        (event_id(protocol_id("evt_", 9410)),),
        "work-integrity",
        "0.1.0",
        frontier,
        old_coverage,
        None,
    )
    recorded = await _drain_observation_record(
        app,
        runtime,
        started,
        seed=9421,
        expected_frontier=frontier.sequence,
        finding=old,
    )
    answered = await app.respond(
        RespondRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 9430)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(recorded.result_frontier),
                "finding_id": old.finding_id,
                "finding_frontier": _frontier(recorded.result_frontier),
                "disposition": "acknowledged",
                "reason": "Caller-published excerpts remain digest-only provenance.",
            }
        )
    )
    checked = await _check_912(app, started, answered.result_frontier, 9431)
    assert _provenance_findings(checked.findings) == ()
    assert old.finding_id not in {item.finding_id for item in checked.findings}
    history = await _findings_view(app, started, 9432, include_resolved=True)
    by_id = {item.finding_id: item for item in history.items}
    assert by_id[old.finding_id].resolved is True
    assert [item.finding_id for item in history.items if item.kind == kind.value] == [
        old.finding_id
    ]

    again = await _check_912(app, started, checked.result_frontier, 9433)
    assert tuple(item.finding_id for item in again.findings) == tuple(
        item.finding_id for item in checked.findings
    )
    assert again.verdict == checked.verdict
    compact, readiness = await _compact_912(app, started, 9434)
    assert compact.unanswered_finding_count == "0"
    assert compact.receipt_blocking_finding_count == "0"
    assert "findings_unanswered" not in readiness.blocking_conditions

    receipt = await _receipt_912(app, started, again.result_frontier, 9435, "json")
    document = cast(dict[str, JsonValue], receipt.document)
    sections = {
        cast(dict[str, JsonValue], section)["key"]: cast(dict[str, JsonValue], section)
        for section in cast(list[JsonValue], document["sections"])
    }
    assert old.finding_id in cast(list[JsonValue], sections["summary"]["items"])
    assert not any(
        str(cast(dict[str, JsonValue], gap)["code"]).startswith("retained_finding_coverage")
        for gap in cast(list[JsonValue], document["gaps"])
    )
    body = _limitations_body(receipt.document)
    assert body.count("caller-asserted digest") == 1
    assert "One cited evidence item carries a caller-asserted digest" in body


# Issue #911: the observation advisory "Observation coverage is incomplete or stale" landed in
# every Codex session of the 2026-09 DeepSWE run as the same ledger finding. These cases replay
# that exported ledger shape: the observation coordinator's service-stamped `finding_recorded`
# carrying the exact dda53ae2 payload (its id is derived by the production advice functions, not
# special-cased anywhere), recorded long before the agent's check.
_LEGACY_ADVISORY_ID = "fnd_8a9389b5-1e7c-49c5-b078-31ad9aeced8e"


def _legacy_observation_advisory(subject_event_id: str, frontier: Frontier) -> Finding:
    candidate = ObservationAdviceCandidate(
        FindingKind.LEDGER_STALE_OR_INCOMPLETE,
        "observation_gap_or_stale",
        "refresh_observation",
        ("hook:930755a9",),
        FINDING_KIND_TRAITS[FindingKind.LEDGER_STALE_OR_INCOMPLETE][0],
        "observation-gap",
    )
    # The exported ledger was written under observation-advice policy 0.1.5 (dda53ae2). Issue #909
    # later moved the policy to 0.1.6, which gives a new condition a new id but never rewrites a
    # recorded one, so derive the legacy id with the production digest shape at that version.
    legacy_digest = canonical_digest(
        {
            "policy": f"{OBSERVATION_ADVICE_POLICY_ID}/0.1.5",
            "kind": candidate.kind.value,
            "rule_code": candidate.rule_code,
            "detail_token": candidate.detail_token,
        }
    )
    advisory_id = stable_advice_finding_id(
        candidate.rule_code, candidate.detail_token, legacy_digest
    )
    assert advisory_id == _LEGACY_ADVISORY_ID
    return Finding(
        advisory_id,
        FindingKind.LEDGER_STALE_OR_INCOMPLETE,
        FindingOrigin.DETERMINISTIC,
        3,
        "Observation coverage is incomplete or stale",
        "Source lag, mapping, or drain gaps prevent complete observation",
        (event_id(subject_event_id),),
        "work-integrity",
        "0.1.0",
        frontier,
        Coverage(
            publication_channels=(
                PublicationChannel.ENGINE_DERIVED,
                PublicationChannel.HOOK_OBSERVED,
            ),
            authorship_assurance=AuthorshipAssurance.HARNESS_OBSERVED,
            artifact_observation=ArtifactObservation.HOOK_OBSERVED,
            evidence_immutability=EvidenceImmutability.CONTENT_DIGEST,
            ledger_freshness=LedgerFreshness.PARTIAL,
            check_types=(CheckType.DETERMINISTIC,),
            known_gaps=(
                "advice_semantic_pending",
                "observation_qualified_partial",
                "unpaired_event",
            ),
        ),
        None,
    )


async def _kombu_shape(
    app: Application, runtime: _WorkflowRuntime, *, seed: int
) -> tuple[StartInternalResult, Finding, CheckCommitResult]:
    """Start, let observation record the legacy advisory, publish work, and check it."""

    started = await app.start(start_request(seed, title="Observation advisory closure"))
    ledger, _objects = next(iter(runtime.resources.values()))
    opened = [record async for record in ledger.load_events(started.session_id)][0]
    advisory = _legacy_observation_advisory(
        opened.event_id,
        Frontier(int(started.frontier.sequence), started.frontier.head_digest),
    )
    drained = await _drain_observation_record(
        app,
        runtime,
        started,
        seed=seed + 1,
        expected_frontier=int(started.frontier.sequence),
        finding=advisory,
    )
    # The Codex profile's standing host gaps ride on ordinary hook observation, so the check's
    # own coverage carries them too; that is what left every exported row unresolvable.
    drained = await _drain_host_observation_gaps(
        app,
        runtime,
        started,
        seed=seed + 5,
        expected_frontier=int(drained.result_frontier.sequence),
    )
    obligation = protocol_id("obl_", seed + 10)
    obligation_event = protocol_id("evt_", seed + 11)
    published = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 12)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(drained.result_frontier),
                "event_drafts": (
                    {
                        "event_id": obligation_event,
                        "schema": {"name": "obligation_published", "version": "1.0.0"},
                        "occurred_at": "2026-09-29T08:20:00.000Z",
                        "causal_parents": (),
                        "payload": {
                            "obligation_id": obligation,
                            "description": "Route rejected messages to the dead-letter queue.",
                            "acceptance_criteria": "The dead-letter path is implemented.",
                            "evidence_expectation": "A linked immutable result record.",
                            "status": "open",
                        },
                        "artifact_refs": (),
                        "evidence_refs": (),
                    },
                    {
                        "event_id": protocol_id("evt_", seed + 13),
                        "schema": {"name": "claim_recorded", "version": "1.0.0"},
                        "occurred_at": "2026-09-29T08:21:00.000Z",
                        "causal_parents": (obligation_event,),
                        "payload": {
                            "claim_id": protocol_id("clm_", seed + 14),
                            "claim_kind": "completion",
                            "statement": "Dead-lettering is implemented.",
                            "supporting_refs": (obligation,),
                            "obligation_refs": (obligation,),
                        },
                        "artifact_refs": (),
                        "evidence_refs": (),
                    },
                ),
            }
        )
    )
    checked = await app.check(
        CheckRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 15)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(published.result_frontier),
                "mode": "deterministic_only",
                "max_findings": "3",
            }
        )
    )
    assert type(checked) is CheckCommitResult, f"unexpected nonterminal check: {type(checked)}"
    # The check judged the record but never returns observation advice.
    assert _LEGACY_ADVISORY_ID not in {item.finding_id for item in checked.findings}
    return started, advisory, checked


async def _compact(app: Application, started: StartInternalResult, seed: int):
    return await app.status(
        StatusRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "view": "compact",
                "limit": "10",
            }
        )
    )


def _assert_durable_mirror(runtime: _WorkflowRuntime, item: StatusCompactItemModel) -> None:
    """The SQLite ``p1_projection_state`` mirror counts exactly what compact status counts."""

    for db in runtime.sqlite_connections:
        row = db.execute(
            "SELECT unresolved_finding_count, freshness FROM p1_projection_state "
            "WHERE projection_name='work'"
        ).fetchone()
        assert row is not None
        assert (str(row[0]), row[1]) == (item.unanswered_finding_count, item.freshness)


@pytest.mark.parametrize("ledger_backend", ("memory", "sqlite"))
async def test_legacy_observation_advisory_is_a_disclosed_limitation_not_response_work(
    ledger_backend: Literal["memory", "sqlite"],
) -> None:
    """Issue #911: the old advisory row renders as disclosed history, never as unanswered work.

    It stays visible in view=findings and on the receipt, keeps its unmet resolution requirements
    (it does not become resolvable), and leaves the unanswered counter, the compact preview, and
    closure_readiness's findings_unanswered, on every backend and on the MCP text fallback.
    """

    seed = 9110
    app, runtime, _ = _build_app(seed_offset=91, ledger_backend=ledger_backend)
    started, _advisory, checked = await _kombu_shape(app, runtime, seed=seed)
    returned_ids = {item.finding_id for item in checked.findings}

    status = await _compact(app, started, seed + 30)
    item = cast(StatusCompactPageModel, status.page).items[0]
    assert item.unanswered_finding_count == str(len(returned_ids))
    assert {row.finding_id for row in item.unanswered_findings} == returned_ids
    assert status.closure_readiness.unanswered_finding_count == str(len(returned_ids))
    _assert_durable_mirror(runtime, item)

    # Answer the check's own findings at its result frontier (koota-pair shape): not material.
    frontier = checked.result_frontier
    for offset, returned in enumerate(checked.findings):
        answered = await app.respond(
            RespondRequest.model_validate(
                {
                    **_request_base(protocol_id("req_", seed + 40 + offset)),
                    "session_id": started.session_id,
                    "writer_id": started.writer_id,
                    "expected_frontier": _frontier(frontier),
                    "finding_id": returned.finding_id,
                    "finding_frontier": _frontier(checked.result_frontier),
                    "disposition": "acknowledged",
                    "reason": "Accepted; the dead-letter path is tracked separately.",
                }
            )
        )
        frontier = answered.result_frontier

    status = await _compact(app, started, seed + 50)
    item = cast(StatusCompactPageModel, status.page).items[0]
    assert item.unanswered_finding_count == "0"
    assert item.unanswered_findings == ()
    assert "findings_unanswered" not in status.closure_readiness.blocking_conditions
    assert status.closure_readiness.unanswered_finding_count == "0"
    assert item.freshness != LedgerFreshness.STALE_AFTER_MATERIAL_CHANGE.value
    assert "unanswered findings: 0" in summary_for_status(status.as_json())
    _assert_durable_mirror(runtime, item)

    page = await _findings_view(app, started, seed + 51, include_resolved=True)
    legacy = next(row for row in page.items if row.finding_id == _LEGACY_ADVISORY_ID)
    assert legacy.disposition == "none"
    assert legacy.resolved is False
    assert legacy.priority == 3
    assert isinstance(legacy.detail, str)
    assert "Observation-authored coverage limitation: it needs no response" in legacy.detail
    # Rendering and counting change; proof does not: its unmet requirements stay unmet.
    assert "Resolution requirements not met" in legacy.detail, legacy.detail
    assert "freshness_or_original_proof_unreadable" in legacy.detail, legacy.detail
    assert "unpaired_event" in legacy.coverage.known_gaps

    receipt = await app.receipt(
        ReceiptRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 60)),
                "task_id": started.task_id,
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(frontier),
                "format": "text",
                "include": "full",
                "redaction_profile": "full_local",
            }
        )
    )
    assert "check_not_applicable" not in receipt.coverage.known_gaps
    assert "unpaired_event" in receipt.coverage.known_gaps
    assert receipt.human_text is not None
    assert "recorded coverage-limitation finding" in receipt.human_text


@pytest.mark.parametrize("ledger_backend", ("memory", "sqlite"))
async def test_acknowledging_the_observation_advisory_after_the_check_needs_no_recheck(
    ledger_backend: Literal["memory", "sqlite"],
) -> None:
    """Issue #911 kombu B replay: check, then acknowledge the observation advisory, then status.

    The acknowledgement uses only the current status frontier (no historical frontier search)
    and leaves the check attributable: status carries check_current_as_of_earlier_frontier at
    most, never stale_after_material_change, and the receipt still folds the check.
    """

    seed = 9210
    app, runtime, _ = _build_app(seed_offset=92, ledger_backend=ledger_backend)
    started, advisory, checked = await _kombu_shape(app, runtime, seed=seed)

    before = await _compact(app, started, seed + 30)
    assert cast(StatusCompactPageModel, before.page).items[0].freshness != (
        LedgerFreshness.STALE_AFTER_MATERIAL_CHANGE.value
    )

    # The finding's subject_frontier precedes its record and stays rejected, with a message that
    # names the frontier to use instead of "the check that returned it" (this one never was).
    with pytest.raises(PublicOperationError) as refused:
        await app.respond(
            RespondRequest.model_validate(
                {
                    **_request_base(protocol_id("req_", seed + 31)),
                    "session_id": started.session_id,
                    "writer_id": started.writer_id,
                    "expected_frontier": _frontier(before.subject_frontier),
                    "finding_id": advisory.finding_id,
                    "finding_frontier": _frontier(advisory.subject_frontier),
                    "disposition": "acknowledged",
                }
            )
        )
    assert refused.value.code is PublicErrorCode.INVALID_REQUEST
    assert "at or after the finding's own record" in refused.value.message
    assert "current status frontier" in refused.value.message
    assert "No historical frontier search is needed" in refused.value.message
    assert "the check that returned it" not in refused.value.message

    head = before.subject_frontier
    assert int(head.sequence) > int(advisory.subject_frontier.sequence) + 1
    responded = await app.respond(
        RespondRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 32)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(head),
                "finding_id": advisory.finding_id,
                "finding_frontier": _frontier(head),
                "disposition": "acknowledged",
                "reason": "Observation coverage limitation, not evidence against the change.",
            }
        )
    )
    assert responded.response.disposition == "acknowledged"

    ledger, _objects = next(iter(runtime.resources.values()))
    records = tuple([record async for record in ledger.load_events(started.session_id)])
    projection = replay(records)
    assert projection.freshness is not LedgerFreshness.STALE_AFTER_MATERIAL_CHANGE
    capacity_gaps = receipt_gap_codes(projection, records)
    assert "check_not_applicable" not in capacity_gaps
    assert "check_current_as_of_earlier_frontier" in capacity_gaps

    after = await _compact(app, started, seed + 40)
    item = cast(StatusCompactPageModel, after.page).items[0]
    assert item.freshness != LedgerFreshness.STALE_AFTER_MATERIAL_CHANGE.value
    assert "check_current_as_of_earlier_frontier" in item.coverage.known_gaps
    assert CheckType.DETERMINISTIC in item.coverage.check_types
    assert item.unanswered_finding_count == str(len(checked.findings))

    page = await _findings_view(app, started, seed + 41, include_resolved=True)
    legacy = next(row for row in page.items if row.finding_id == _LEGACY_ADVISORY_ID)
    assert legacy.disposition == "acknowledged"
    # Acknowledged is done, not resolved: the limitation stays disclosed.
    assert legacy.resolved is False

    receipt = await app.receipt(
        ReceiptRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 50)),
                "task_id": started.task_id,
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(responded.result_frontier),
                "format": "json",
                "include": "standard",
                "redaction_profile": "full_local",
            }
        )
    )
    assert "check_not_applicable" not in receipt.coverage.known_gaps
    assert "check_current_as_of_earlier_frontier" in receipt.coverage.known_gaps
    assert CheckType.DETERMINISTIC in receipt.coverage.check_types
    assert "unpaired_event" in receipt.coverage.known_gaps
    assert receipt.document is not None
    limitations = _limitations_body(receipt.document)
    assert (
        "only responses to the findings it returned or to observation-authored coverage "
        "limitations were published after it"
    ) in limitations
    document = cast(Mapping[str, JsonValue], receipt.document)
    responses = cast(tuple[Mapping[str, JsonValue], ...], document["responses"])
    assert any(
        row["finding_id"] == _LEGACY_ADVISORY_ID and row["disposition"] == "acknowledged"
        for row in responses
    )


async def test_rejecting_the_observation_advisory_after_the_check_stays_material() -> None:
    """Issue #911 keeps productive rechecks: only an unscored acknowledgement is exempt.

    A rejection can raise a later weak-response or questionable-rejection finding, so it still
    supersedes the check exactly like any other response to a finding the check did not return.
    The recheck it requires is productive: it scores the unsupported rejection, which the stale
    check could not have reported (ADR-022, observation-authored limitation findings, item 2).
    """

    seed = 9310
    app, runtime, _ = _build_app(seed_offset=93)
    started, advisory, checked = await _kombu_shape(app, runtime, seed=seed)
    head = (await _compact(app, started, seed + 30)).subject_frontier
    rejected = await app.respond(
        RespondRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 31)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(head),
                "finding_id": advisory.finding_id,
                "finding_frontier": _frontier(head),
                "disposition": "rejected",
                "reason": "Observation is healthy.",
            }
        )
    )
    after = await _compact(app, started, seed + 40)
    item = cast(StatusCompactPageModel, after.page).items[0]
    assert item.freshness == LedgerFreshness.STALE_AFTER_MATERIAL_CHANGE.value
    ledger, _objects = next(iter(runtime.resources.values()))
    records = tuple([record async for record in ledger.load_events(started.session_id)])
    assert "check_not_applicable" in receipt_gap_codes(replay(records), records)

    rechecked = await app.check(
        CheckRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 50)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(rejected.result_frontier),
                "mode": "deterministic_only",
                "max_findings": "10",
            }
        )
    )
    assert type(rechecked) is CheckCommitResult, f"unexpected nonterminal check: {type(rechecked)}"
    scored = FindingKind.QUESTIONABLE_FINDING_REJECTION
    assert scored not in {item.kind for item in checked.findings}
    assert scored in {item.kind for item in rechecked.findings}


async def test_acknowledging_a_semantic_finding_at_the_current_frontier_counts_later_evidence() -> (
    None
):
    """Issue #911: any in-chain frontier at or after the record names the finding.

    Issue #885's attempt rule measures "after the finding" from the finding's own record, so
    naming the finding by the current status frontier (the frontier status hands the agent) does
    not hide the repair evidence recorded between the finding and that frontier, and evidence
    recorded before the finding still does not count.
    """

    seed = 9410
    app, _runtime, _ = _build_app(
        seed_offset=94,
        semantic="optional",
        semantic_evaluator=_semantic_challenge_evaluator(protocol_id("clm_", seed + 5)),
    )
    started, checked, _obligation = await _bootstrap_finding(
        app, seed=seed, mode="semantic_if_configured"
    )
    finding = next(
        item for item in checked.findings if item.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED
    )
    evidence_ref = protocol_id("evd_", seed + 12)
    published = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 13)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(checked.result_frontier),
                "event_drafts": (
                    {
                        "event_id": protocol_id("evt_", seed + 14),
                        "schema": {"name": "evidence_recorded", "version": "1.0.0"},
                        "occurred_at": "2026-09-29T12:00:02.000Z",
                        "causal_parents": (),
                        "payload": {
                            "evidence_id": evidence_ref,
                            "evidence_kind": "artifact",
                            "strength": "mutable_reference",
                            "observed_at": "2026-09-29T12:00:02.000Z",
                            "reference": "attempted-verification",
                        },
                        "artifact_refs": (),
                        "evidence_refs": (),
                    },
                ),
            }
        )
    )
    head = published.result_frontier
    accepted = await app.respond(
        RespondRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 15)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(head),
                "finding_id": finding.finding_id,
                "finding_frontier": _frontier(head),
                "disposition": "acknowledged",
                "reason": "The limitation is accepted after the recorded attempt.",
                "evidence_refs": (evidence_ref,),
            }
        )
    )
    assert accepted.response.disposition == "acknowledged"


async def test_evidence_recorded_before_a_semantic_finding_never_counts_as_its_attempt() -> None:
    """Issue #911 keeps #885 honest: evidence recorded before the finding is never its attempt.

    Naming the finding by a later in-chain frontier (the current status frontier) or by the
    check result frontier must not let pre-finding evidence satisfy the attempt requirement.
    """

    seed = 9510
    app, _runtime, _ = _build_app(
        seed_offset=95,
        semantic="optional",
        semantic_evaluator=_semantic_challenge_evaluator(protocol_id("clm_", seed + 5)),
    )
    started = await app.start(start_request(seed, title="Pre-finding evidence"))
    obligation = protocol_id("obl_", seed + 1)
    obligation_event = protocol_id("evt_", seed + 2)
    early_evidence = protocol_id("evd_", seed + 7)
    published = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 3)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(started.frontier),
                "event_drafts": (
                    {
                        "event_id": obligation_event,
                        "schema": {"name": "obligation_published", "version": "1.0.0"},
                        "occurred_at": "2026-09-29T12:00:00.000Z",
                        "causal_parents": (),
                        "payload": {
                            "obligation_id": obligation,
                            "description": "Publish a result for the exercise.",
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
                        "occurred_at": "2026-09-29T12:00:01.000Z",
                        "causal_parents": (obligation_event,),
                        "payload": {
                            "claim_id": protocol_id("clm_", seed + 5),
                            "claim_kind": "completion",
                            "statement": "The exercise is complete.",
                            "supporting_refs": (obligation,),
                            "obligation_refs": (obligation,),
                        },
                        "artifact_refs": (),
                        "evidence_refs": (),
                    },
                    {
                        "event_id": protocol_id("evt_", seed + 6),
                        "schema": {"name": "evidence_recorded", "version": "1.0.0"},
                        "occurred_at": "2026-09-29T12:00:01.500Z",
                        "causal_parents": (),
                        "payload": {
                            "evidence_id": early_evidence,
                            "evidence_kind": "artifact",
                            "strength": "mutable_reference",
                            "observed_at": "2026-09-29T12:00:01.500Z",
                            "reference": "pre-finding-verification",
                        },
                        "artifact_refs": (),
                        "evidence_refs": (),
                    },
                ),
            }
        )
    )
    checked = await app.check(
        CheckRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 8)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(published.result_frontier),
                "mode": "semantic_if_configured",
                "max_findings": "3",
            }
        )
    )
    assert type(checked) is CheckCommitResult
    finding = next(
        item for item in checked.findings if item.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED
    )
    later = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 11)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(checked.result_frontier),
                "event_drafts": (
                    {
                        "event_id": protocol_id("evt_", seed + 12),
                        "schema": {"name": "evidence_recorded", "version": "1.0.0"},
                        "occurred_at": "2026-09-29T12:00:03.000Z",
                        "causal_parents": (),
                        "payload": {
                            "evidence_id": protocol_id("evd_", seed + 13),
                            "evidence_kind": "artifact",
                            "strength": "mutable_reference",
                            "observed_at": "2026-09-29T12:00:03.000Z",
                            "reference": "unrelated-later-note",
                        },
                        "artifact_refs": (),
                        "evidence_refs": (),
                    },
                ),
            }
        )
    )
    head = later.result_frontier
    assert int(head.sequence) > int(checked.result_frontier.sequence)
    for request_seed, finding_frontier in ((seed + 9, head), (seed + 10, checked.result_frontier)):
        with pytest.raises(PublicOperationError) as refused:
            await app.respond(
                RespondRequest.model_validate(
                    {
                        **_request_base(protocol_id("req_", request_seed)),
                        "session_id": started.session_id,
                        "writer_id": started.writer_id,
                        "expected_frontier": _frontier(head),
                        "finding_id": finding.finding_id,
                        "finding_frontier": _frontier(finding_frontier),
                        "disposition": "acknowledged",
                        "reason": "Limitation accepted.",
                        "evidence_refs": (early_evidence,),
                    }
                )
            )
        assert refused.value.code is PublicErrorCode.INVALID_REQUEST
        assert refused.value.safe_details["reason_code"] == "resolution_attempt_required"


def _unassessed_recheck_evaluator(
    claim_ref: str, source: Literal["unshown", "dropped", "complete"]
) -> Callable[..., Awaitable[object]]:
    """Raise one AI-powered finding, then recheck with a review that did not assess it.

    ``unshown``: the prior-findings section left it out (section limit or envelope trimming).
    ``dropped``: the reviewer's ruling was malformed and the normalizer dropped it.
    ``complete``: the control, a complete review that is silent about it.
    """

    calls: list[int] = []

    async def evaluate(
        frozen: object,
        findings: object,
        runtime: object | None = None,
        lineage_evaluation: object | None = None,
    ) -> object:
        raised = cast(
            FinalSemanticEvaluation,
            await _semantic_challenge_evaluator(claim_ref)(frozen, findings),
        )
        calls.append(1)
        if len(calls) == 1:
            return replace(raised, case_content_gaps=())
        return replace(
            raised,
            judgment=SemanticJudgment(
                "no_material_discrepancy",
                (),
                prior_finding_verdicts_dropped=1 if source == "dropped" else 0,
            ),
            case_content_gaps=(
                ("semantic_prior_findings_over_limit",) if source == "unshown" else ()
            ),
        )

    return evaluate


@pytest.mark.parametrize("ledger_backend", ("memory", "sqlite"))
@pytest.mark.parametrize("source", ("unshown", "dropped", "complete"))
async def test_an_ai_finding_the_recheck_did_not_assess_never_resolves_by_silence(
    ledger_backend: Literal["memory", "sqlite"],
    source: Literal["unshown", "dropped", "complete"],
) -> None:
    """Greptile P1 on #905 through the real check, replay and status path, on both ledgers.

    After material work, a completed recheck that never showed the finding to the reviewer, or
    dropped the reviewer's ruling on it, must not resolve it: the finding was not assessed. The
    packet gap stays disclosed. A complete review that is merely silent keeps the ordinary rule.
    """

    seed = 5600 + {"unshown": 0, "dropped": 100, "complete": 200}[source]
    app, runtime, _ = _build_app(
        seed_offset=56,
        semantic="optional",
        ledger_backend=ledger_backend,
        semantic_evaluator=_unassessed_recheck_evaluator(protocol_id("clm_", seed + 5), source),
    )
    started, checked, _obligation = await _bootstrap_finding(
        app, seed=seed, mode="semantic_if_configured"
    )
    finding = next(
        item for item in checked.findings if item.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED
    )
    published = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 31)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(checked.result_frontier),
                "event_drafts": (
                    {
                        "event_id": protocol_id("evt_", seed + 32),
                        "schema": {"name": "evidence_recorded", "version": "1.0.0"},
                        "occurred_at": "2026-07-19T12:00:03.000Z",
                        "causal_parents": (),
                        "payload": {
                            "evidence_id": protocol_id("evd_", seed + 30),
                            "evidence_kind": "artifact",
                            "strength": "mutable_reference",
                            "observed_at": "2026-07-19T12:00:03.000Z",
                            "reference": "unrelated-evidence",
                        },
                        "artifact_refs": (),
                        "evidence_refs": (),
                    },
                ),
            }
        )
    )
    rechecked = await app.check(
        CheckRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 40)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(published.result_frontier),
                "mode": "semantic_if_configured",
                "max_findings": "8",
            }
        )
    )
    assert type(rechecked) is CheckCommitResult
    assert finding.finding_id not in {item.finding_id for item in rechecked.findings}
    disclosed = {
        "unshown": "semantic_prior_findings_over_limit",
        "dropped": "semantic_prior_verdicts_unsupported",
    }.get(source)
    if disclosed is not None:
        assert disclosed in rechecked.coverage.known_gaps

    view = await _findings_view(app, started, seed + 41, include_resolved=True)
    row = next(item for item in view.items if item.finding_id == finding.finding_id)
    assert row.resolved is (source == "complete")
    if source != "complete":
        assert "reviewer_assessment_incomplete" in _projected_detail(row.detail)

    # Replay from the recorded events reaches the same answer on this ledger backend.
    ledger, _ = next(iter(runtime.resources.values()))
    records = tuple([item async for item in ledger.load_events(started.session_id)])
    from finishup.kernel.finding_resolution import finding_is_resolved

    assert finding_is_resolved(replay(records), finding.finding_id) is (source == "complete")


def _projected_detail(detail: object) -> str:
    return detail if type(detail) is str else ""


@pytest.mark.parametrize("ledger_backend", ("memory", "sqlite"))
async def test_the_check_carries_the_finding_checklist_on_both_ledgers(
    ledger_backend: Literal["memory", "sqlite"],
) -> None:
    """Issue #905: the list is read from the adapter-owned projection, never a status page."""

    app, _runtime, _ = _build_app(seed_offset=57, ledger_backend=ledger_backend)
    _started, checked, _obligation = await _bootstrap_finding(app, seed=5700)
    checklist = checked.finding_checklist
    assert checklist is not None
    from finishup.domain.findings import FINDING_KIND_TRAITS

    blocking = {item.finding_id for item in checked.findings if FINDING_KIND_TRAITS[item.kind][1]}
    assert blocking <= {item.finding_id for item in checklist.items}
    assert checklist.counts.open == len(checklist.items)
    assert checklist.next == "work_open_findings"


@pytest.mark.parametrize("ledger_backend", ("memory", "sqlite"))
async def test_a_final_local_finding_returned_again_gains_no_review_round(
    ledger_backend: Literal["memory", "sqlite"],
) -> None:
    """Greptile P2 on #943 through the real respond, check, status and replay path.

    A local finding answered ``acknowledged_not_done`` is final. The next check returns it again
    over a later subject; its review rounds stay 0 in the adapter's projection and in a replay.
    """

    app, runtime, _ = _build_app(seed_offset=58, ledger_backend=ledger_backend)
    started, checked, _obligation = await _bootstrap_finding(app, seed=5800)
    finding = checked.findings[0]
    responded = await app.respond(
        RespondRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 5810)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(checked.result_frontier),
                "finding_id": finding.finding_id,
                "finding_frontier": _frontier(checked.result_frontier),
                "disposition": "acknowledged_not_done",
                "reason": "The obligation is deferred to a later milestone by the owner.",
            }
        )
    )
    rechecked = await app.check(
        CheckRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 5811)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(responded.result_frontier),
                "mode": "deterministic_only",
                "max_findings": "3",
            }
        )
    )
    assert type(rechecked) is CheckCommitResult
    assert finding.finding_id in {item.finding_id for item in rechecked.findings}

    view = await _findings_view(app, started, 5812, include_resolved=True)
    row = next(item for item in view.items if item.finding_id == finding.finding_id)
    assert (row.todo_state, row.review_rounds) == ("acknowledged_not_done", "0")
    ledger, _ = next(iter(runtime.resources.values()))
    records = tuple([item async for item in ledger.load_events(started.session_id)])
    assert replay(records).findings[finding.finding_id].review_rounds == 0


@pytest.mark.parametrize("statement", ["never", "after_finding", "before_finding"])
async def test_a_finding_raised_before_the_task_statement_is_not_trapped_by_its_gaps(
    statement: str,
) -> None:
    """Issue #908: an AI-powered finding recorded before any review could carry a statement.

    Its own coverage names no task-statement code (the raising review predates the feature), and
    every later review under a pre-section approval carries ``task_statement_unavailable`` and
    ``task_statement_not_authorized``. After material work, a completed later review that does not
    return the issue resolves it, the codes stay on the receipt, and the conclusion stays bounded.
    A finding raised after a statement-capable event gets no such tolerance and stays open.
    """

    seed = 5600
    conclusions = ["challenges_returned", "no_material_discrepancy"]
    gaps_by_call = [(), ("task_statement_not_authorized", "task_statement_unavailable")]
    raised = _scripted_semantic_evaluator(
        protocol_id("clm_", seed + 5), conclusions, case_gaps=(), over_item_limit=False
    )

    async def evaluate(
        frozen: object,
        findings: object,
        runtime: object | None = None,
        lineage_evaluation: object | None = None,
    ) -> object:
        result = cast(FinalSemanticEvaluation, await raised(frozen, findings))
        return replace(result, case_content_gaps=gaps_by_call.pop(0))

    app, _runtime, _ = _build_app(seed_offset=56, semantic="optional", semantic_evaluator=evaluate)
    started, checked, _obligation = await _bootstrap_finding(
        app,
        seed=seed,
        mode="semantic_if_configured",
        task_statement="The user's request, verbatim." if statement == "before_finding" else None,
    )
    finding = next(
        item for item in checked.findings if item.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED
    )
    assert not {gap for gap in finding.coverage.known_gaps if gap.startswith("task_statement")}
    frontier: object = checked.result_frontier
    if statement == "after_finding":
        attached = await app.start(
            StartRequest.model_validate(
                {
                    **_request_base(protocol_id("req_", seed + 25)),
                    "mode": "attach",
                    "session_id": started.session_id,
                    "task_title": "Respond/status/receipt exercise",
                    "requested_view": "compact",
                    "task_statement": "The user's request, verbatim.",
                }
            )
        )
        frontier = attached.frontier
    drafts: list[dict[str, object]] = [
        {
            "event_id": protocol_id("evt_", seed + 32),
            "schema": {"name": "evidence_recorded", "version": "1.0.0"},
            "occurred_at": "2026-07-19T12:00:03.000Z",
            "causal_parents": (),
            "payload": {
                "evidence_id": protocol_id("evd_", seed + 30),
                "evidence_kind": "artifact",
                "strength": "mutable_reference",
                "observed_at": "2026-07-19T12:00:03.000Z",
                "reference": "repair-evidence",
            },
            "artifact_refs": (),
            "evidence_refs": (),
        }
    ]
    if statement == "after_finding":
        # The statement now recorded beside a completion claim on no plan raises the
        # undecomposed-request finding (pilot blocker D3), whose open gap would bound this
        # AI-powered proof too. This fixture edits nothing, so its documented answer, the
        # no-material-work decision, keeps the test on the task-statement gaps it is about.
        from finishup.domain.task_statement import current_task_statement

        ledger, _objects = _runtime.resources[started.task_id]
        recorded = current_task_statement(
            tuple([row async for row in ledger.load_events(started.session_id)])
        )
        assert recorded is not None
        drafts.append(
            {
                "event_id": protocol_id("evt_", seed + 33),
                "schema": {"name": "decision_recorded", "version": "1.0.0"},
                "occurred_at": "2026-07-19T12:00:03.000Z",
                "causal_parents": (),
                "payload": {
                    "statement": f"finishup-no-material-work:{recorded.source_event_id}",
                    "rationale": "The fixture asks for no file change.",
                    "authority": "harness:test",
                },
                "artifact_refs": (),
                "evidence_refs": (),
            }
        )
    published = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 31)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(cast(Frontier, frontier)),
                "event_drafts": tuple(drafts),
            }
        )
    )
    repaired = await app.check(
        CheckRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 40)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(published.result_frontier),
                "mode": "semantic_if_configured",
                "max_findings": "8",
            }
        )
    )
    assert type(repaired) is CheckCommitResult
    assert {"task_statement_not_authorized", "task_statement_unavailable"} <= set(
        repaired.coverage.known_gaps
    )
    view = await _findings_view(app, started, seed + 41, include_resolved=True)
    resolved = next(item for item in view.items if item.finding_id == finding.finding_id).resolved
    # Raised after a statement-capable event, the finding had its chance at the statement, so a
    # later review that lacks it proves nothing new and the issue stays open.
    assert resolved is (statement != "before_finding")
    assert conclusions == [] and gaps_by_call == []


async def test_status_finding_frontier_answers_every_origin_on_the_first_attempt() -> None:
    """Issue #917: ``status view=findings`` names the frontier ``respond`` accepts as-is.

    One deterministic, one AI-powered review and one observation-origin finding are each
    answered with the ``finding_frontier`` their status item carries, without a frontier
    hunt. The item's ``subject_frontier`` precedes its own record and stays distinct.
    """

    seed = 9170
    app, runtime, _ = _build_app(
        seed_offset=91,
        semantic="optional",
        semantic_evaluator=_semantic_challenge_evaluator(protocol_id("clm_", seed + 5)),
    )
    started, checked, _obligation = await _bootstrap_finding(
        app, seed=seed, mode="semantic_if_configured"
    )
    drained = await _drain_observation_record(
        app,
        runtime,
        started,
        seed=seed + 40,
        expected_frontier=checked.result_frontier.sequence,
        finding=_drained_finding(
            protocol_id("evt_", seed + 2),
            Frontier(int(checked.result_frontier.sequence), checked.result_frontier.head_digest),
            seed + 45,
        ),
    )
    head = Frontier(drained.accepted[-1].ingestion_sequence, drained.accepted[-1].entry_digest)
    status = await app.status(
        StatusRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 50)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "view": "findings",
                "limit": "10",
                "at_frontier": str(head.sequence),
            }
        )
    )
    items = cast(StatusFindingsPageModel, status.page).items
    origins = {item.origin for item in items}
    assert origins == {"deterministic", "semantic_model_derived"}
    assert any(item.finding_id == protocol_id("fnd_", seed + 45) for item in items)
    assert all(item.finding_frontier is not None for item in items)
    assert all(item.finding_frontier != item.subject_frontier for item in items)

    current: Frontier | FrontierModel = head
    for index, item in enumerate(items):
        responded = await app.respond(
            RespondRequest.model_validate(
                {
                    **_request_base(protocol_id("req_", seed + 60 + index)),
                    "session_id": started.session_id,
                    "writer_id": started.writer_id,
                    "expected_frontier": _frontier(current),
                    "finding_id": item.finding_id,
                    "finding_frontier": _frontier(cast(FrontierModel, item.finding_frontier)),
                    "disposition": "rejected",
                    "reason": "Recorded as out of scope for this exercise.",
                }
            )
        )
        assert responded.response.disposition == "rejected"
        current = responded.result_frontier


_SCOPE_REDUCED = "semantic_reference_scope_reduced"


async def _semantic_recheck(
    app: Application,
    started: StartInternalResult,
    seed: int,
    frontier: Frontier | FrontierModel,
) -> CheckCommitResult:
    result = await app.check(
        CheckRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(frontier),
                "mode": "semantic_if_configured",
                "max_findings": "8",
            }
        )
    )
    assert type(result) is CheckCommitResult
    return result


async def _publish_repair_evidence(
    app: Application,
    started: StartInternalResult,
    seed: int,
    frontier: Frontier | FrontierModel,
) -> PublishWorkInternalResult:
    published = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 1)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(frontier),
                "event_drafts": (
                    {
                        "event_id": protocol_id("evt_", seed + 2),
                        "schema": {"name": "evidence_recorded", "version": "1.0.0"},
                        "occurred_at": "2026-07-19T12:00:03.000Z",
                        "causal_parents": (),
                        "payload": {
                            "evidence_id": protocol_id("evd_", seed),
                            "evidence_kind": "artifact",
                            "strength": "mutable_reference",
                            "observed_at": "2026-07-19T12:00:03.000Z",
                            "reference": "repair-evidence",
                        },
                        "artifact_refs": (),
                        "evidence_refs": (),
                    },
                ),
            }
        )
    )
    assert type(published) is PublishWorkInternalResult
    return published


async def _assert_reduced_scope_disclosed(
    app: Application,
    started: StartInternalResult,
    seed: int,
    frontier: Frontier | FrontierModel,
    *,
    blockers: tuple[str, ...] = (),
) -> None:
    """Status and every receipt rendering still say the review saw a bounded scope.

    Each of *blockers* must also appear in the JSON document and in the markdown and text
    renderings, where the receipt explains why a finding stays current.
    """

    status = await app.status(
        StatusRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "view": "compact",
                "limit": "10",
            }
        )
    )
    compact = cast(StatusCompactPageModel, status.page).items[0]
    assert _SCOPE_REDUCED in compact.coverage.known_gaps
    for offset, fmt in enumerate(("json", "markdown", "text"), start=1):
        receipt = await app.receipt(
            ReceiptRequest.model_validate(
                {
                    **_request_base(protocol_id("req_", seed + offset)),
                    "task_id": started.task_id,
                    "session_id": started.session_id,
                    "writer_id": started.writer_id,
                    "expected_frontier": _frontier(frontier),
                    "format": fmt,
                    "include": "standard",
                    "redaction_profile": "full_local",
                }
            )
        )
        frontier = receipt.result_frontier
        assert _SCOPE_REDUCED in receipt.coverage.known_gaps
        assert receipt.coverage.ledger_freshness is not LedgerFreshness.CURRENT
        assert receipt.conclusion != "no_issue_detected"
        if fmt != "json":
            assert receipt.human_text is not None
            assert _SCOPE_REDUCED in receipt.human_text
            rendered = receipt.human_text
        else:
            assert receipt.document is not None
            rendered = canonical_encode(receipt.document).decode("utf-8")
        for blocker in blockers:
            assert blocker in rendered, (fmt, blocker)


@pytest.mark.parametrize("ledger_backend", ("memory", "sqlite"))
async def test_semantic_finding_resolves_under_its_recorded_reduced_reference_scope(
    ledger_backend: Literal["memory", "sqlite"],
) -> None:
    """Issue #904 through the real check, replay, status and receipt path.

    Every review of a long session runs over a reduced reference scope. The finding records the
    one its review ran under, so a completed review under the same bound resolves it after a
    repair, while check, status and receipts keep disclosing the bounded scope.
    """

    seed = 5600
    conclusions = ["challenges_returned", "no_material_discrepancy", "no_material_discrepancy"]
    app, runtime, _ = _build_app(
        seed_offset=56,
        semantic="optional",
        ledger_backend=ledger_backend,
        semantic_evaluator=_scripted_semantic_evaluator(
            protocol_id("clm_", seed + 5),
            conclusions,
            case_gaps=("content_unselected",),
            over_item_limit=False,
            scope_reduced=[True, True, True],
            # Each packet leaves out the unrelated obligation event and carries everything else.
            omitted_refs=[(protocol_id("evt_", seed + 2),)] * 3,
        ),
    )
    started, checked, _obligation = await _bootstrap_finding(
        app, seed=seed, mode="semantic_if_configured"
    )
    finding = next(
        item for item in checked.findings if item.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED
    )
    # The raise-time stamp: durable finding coverage, beside the check's own disclosure.
    assert _SCOPE_REDUCED in finding.coverage.known_gaps
    assert _SCOPE_REDUCED in checked.coverage.known_gaps

    rerolled = await _semantic_recheck(app, started, seed + 20, checked.result_frontier)
    assert finding.finding_id not in {item.finding_id for item in rerolled.findings}
    view = await _findings_view(app, started, seed + 21, include_resolved=True)
    row = next(item for item in view.items if item.finding_id == finding.finding_id)
    assert row.resolved is False
    # Only the missing repair is named; the unchanged scope is not a blocker.
    assert "no_material_change_since_finding" in str(row.detail)
    assert "coverage:" + _SCOPE_REDUCED not in str(row.detail)

    published = await _publish_repair_evidence(app, started, seed + 30, rerolled.result_frontier)
    repaired = await _semantic_recheck(app, started, seed + 40, published.result_frontier)
    assert _SCOPE_REDUCED in repaired.coverage.known_gaps
    view = await _findings_view(app, started, seed + 41, include_resolved=True)
    assert next(item for item in view.items if item.finding_id == finding.finding_id).resolved
    assert conclusions == []

    ledger, _objects = next(iter(runtime.resources.values()))
    records = tuple([row async for row in ledger.load_events(started.session_id)])
    rebuilt = replay(records)
    assert finding_is_resolved(rebuilt, finding.finding_id)
    stored = await ledger.load_projection(started.session_id, ProjectionView.CANDIDATE_FINDINGS)
    assert stored is not None and stored.state == rebuilt

    await _assert_reduced_scope_disclosed(app, started, seed + 50, repaired.result_frontier)


@pytest.mark.parametrize("ledger_backend", ("memory", "sqlite"))
async def test_a_reduced_review_that_omitted_the_repair_leaves_the_semantic_finding_open(
    ledger_backend: Literal["memory", "sqlite"],
) -> None:
    """PR930-F1 through the real check, replay, status and receipt path.

    The finding was raised under a reduced reference scope, the agent published repair evidence
    and answered the finding with it, and a later completed review under the same bound did not
    return the issue. That review's sent packet carried no content for the repair evidence, so it
    proves nothing about the repair: the finding stays current, and status and every receipt
    rendering name why while disclosing the bounded scope. A review whose sent content was not
    recorded proves nothing either and carries ``semantic_included_refs_not_recorded``. The next
    review whose packet carried the repair resolves it.
    """

    seed = 5900
    repair_evidence = protocol_id("evd_", seed + 30)
    repair_event = protocol_id("evt_", seed + 32)
    conclusions = [
        "challenges_returned",
        "no_material_discrepancy",
        "no_material_discrepancy",
        "no_material_discrepancy",
    ]
    omitted = [
        (protocol_id("evt_", seed + 2),),
        (repair_evidence, repair_event),
        (protocol_id("evt_", seed + 2),),
    ]
    reduced = [True, True, True, True]
    app, runtime, _ = _build_app(
        seed_offset=59,
        semantic="optional",
        ledger_backend=ledger_backend,
        semantic_evaluator=_scripted_semantic_evaluator(
            protocol_id("clm_", seed + 5),
            conclusions,
            case_gaps=("content_unselected",),
            over_item_limit=False,
            scope_reduced=reduced,
            omitted_refs=omitted,
        ),
    )
    started, checked, _obligation = await _bootstrap_finding(
        app, seed=seed, mode="semantic_if_configured"
    )
    finding = next(
        item for item in checked.findings if item.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED
    )
    assert _SCOPE_REDUCED in finding.coverage.known_gaps

    published = await _publish_repair_evidence(app, started, seed + 30, checked.result_frontier)
    answered = await app.respond(
        RespondRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 35)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(published.result_frontier),
                "finding_id": finding.finding_id,
                "finding_frontier": _frontier(checked.result_frontier),
                "disposition": "acknowledged",
                "reason": "Recorded the result that supports the claim.",
                "evidence_refs": (repair_evidence,),
            }
        )
    )
    frontier: Frontier | FrontierModel = answered.result_frontier

    async def recheck_leaves_open(request_seed: int, reason: str) -> CheckCommitResult:
        repaired = await _semantic_recheck(app, started, request_seed, frontier)
        assert finding.finding_id not in {item.finding_id for item in repaired.findings}
        assert _SCOPE_REDUCED in repaired.coverage.known_gaps
        view = await _findings_view(app, started, request_seed + 1, include_resolved=True)
        row = next(item for item in view.items if item.finding_id == finding.finding_id)
        assert row.resolved is False
        assert reason in str(row.detail)
        assert "coverage:" + _SCOPE_REDUCED in str(row.detail)
        return repaired

    omitted_repair = await recheck_leaves_open(
        seed + 40, "finding_material_outside_reduced_review_scope"
    )
    frontier = omitted_repair.result_frontier
    # A reduced review that records no included references is no proof either.
    omitted.clear()
    unrecorded = await recheck_leaves_open(
        seed + 44, "finding_material_outside_reduced_review_scope"
    )
    # A completed reduced review whose sent content was not recorded says so on its coverage.
    assert "semantic_included_refs_not_recorded" in unrecorded.coverage.known_gaps
    assert "semantic_included_refs_not_recorded" not in omitted_repair.coverage.known_gaps
    await _assert_reduced_scope_disclosed(
        app,
        started,
        seed + 50,
        unrecorded.result_frontier,
        blockers=(
            "finding_material_outside_reduced_review_scope",
            "coverage:" + _SCOPE_REDUCED,
            "semantic_included_refs_not_recorded",
        ),
    )

    ledger, _objects = next(iter(runtime.resources.values()))
    records = tuple([item async for item in ledger.load_events(started.session_id)])
    rebuilt = replay(records)
    assert not finding_is_resolved(rebuilt, finding.finding_id)
    stored = await ledger.load_projection(started.session_id, ProjectionView.CANDIDATE_FINDINGS)
    assert stored is not None and stored.state == rebuilt
    included = [
        row.payload.semantic_included_refs
        for row in records
        if isinstance(row.payload, CheckRecordedPayload)
    ]
    assert included[0] is not None and repair_evidence not in included[0]
    assert included[1] is not None and repair_evidence not in included[1]
    assert included[2] is None

    # The next review whose packet carried the repair evidence resolves the finding.
    omitted.append((protocol_id("evt_", seed + 2),))
    status = await app.status(
        StatusRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 60)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "view": "compact",
                "limit": "10",
            }
        )
    )
    in_view = await _semantic_recheck(app, started, seed + 61, status.result_frontier)
    assert finding.finding_id not in {item.finding_id for item in in_view.findings}
    view = await _findings_view(app, started, seed + 62, include_resolved=True)
    assert next(item for item in view.items if item.finding_id == finding.finding_id).resolved
    assert conclusions == [] and reduced == []


async def _resolve_pre_upgrade_finding(
    monkeypatch: pytest.MonkeyPatch,
    *,
    seed: int,
    ledger_backend: Literal["memory", "sqlite"] = "memory",
) -> tuple[
    Application,
    _WorkflowRuntime,
    StartInternalResult,
    CheckCommitResult,
    Finding,
    CheckCommitResult,
]:
    """Raise a finding without the scope stamp, as a pre-upgrade service did, then resolve it.

    The raising check records the reduced scope the finding does not carry. The upgraded service
    reads that check's recorded coverage, so a repair and a completed review under the same bound
    resolve the finding.
    """

    import finishup.application.check as check_module

    stamp = check_module.semantic_capture_baseline_gaps

    def pre_upgrade_stamp(result: FinalSemanticEvaluation) -> frozenset[str]:
        return stamp(result) - {_SCOPE_REDUCED}

    conclusions = ["challenges_returned", "no_material_discrepancy"]
    app, runtime, _ = _build_app(
        seed_offset=seed // 100,
        semantic="optional",
        ledger_backend=ledger_backend,
        semantic_evaluator=_scripted_semantic_evaluator(
            protocol_id("clm_", seed + 5),
            conclusions,
            case_gaps=("content_unselected",),
            over_item_limit=False,
            scope_reduced=[True, True],
            omitted_refs=[(protocol_id("evt_", seed + 2),)] * 2,
        ),
    )
    monkeypatch.setattr(check_module, "semantic_capture_baseline_gaps", pre_upgrade_stamp)
    started, checked, _obligation = await _bootstrap_finding(
        app, seed=seed, mode="semantic_if_configured"
    )
    monkeypatch.undo()
    finding = next(
        item for item in checked.findings if item.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED
    )
    assert "content_unselected" in finding.coverage.known_gaps
    assert _SCOPE_REDUCED not in finding.coverage.known_gaps
    assert _SCOPE_REDUCED in checked.coverage.known_gaps

    published = await _publish_repair_evidence(app, started, seed + 30, checked.result_frontier)
    repaired = await _semantic_recheck(app, started, seed + 40, published.result_frontier)
    assert finding.finding_id not in {item.finding_id for item in repaired.findings}
    view = await _findings_view(app, started, seed + 41, include_resolved=True)
    row = next(item for item in view.items if item.finding_id == finding.finding_id)
    assert row.resolved is True, row.detail
    assert conclusions == []
    return app, runtime, started, checked, finding, repaired


async def test_pre_upgrade_semantic_finding_resolves_through_its_raising_checks_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Lifecycle fallback: a finding raised before the stamp is never rewritten, and resolves.

    A projection rebuild over the same ledger gives the same answer.
    """

    seed = 5700
    app, runtime, started, _checked, finding, repaired = await _resolve_pre_upgrade_finding(
        monkeypatch, seed=seed
    )
    ledger, _objects = next(iter(runtime.resources.values()))
    records = tuple([row async for row in ledger.load_events(started.session_id)])
    rebuilt = replay(records)
    record = rebuilt.findings[finding.finding_id]
    assert finding_is_resolved(rebuilt, finding.finding_id)
    # Never retro-stamped: the recorded finding keeps the coverage it was raised with.
    assert record.payload is not None
    assert _SCOPE_REDUCED not in record.payload.coverage.known_gaps
    assert record.reduced_scope_raising_check_event_id is not None
    assert finding_is_resolved(
        projection_from_snapshot(projection_snapshot(rebuilt)), finding.finding_id
    )
    await _assert_reduced_scope_disclosed(app, started, seed + 50, repaired.result_frontier)


async def _append_local_redaction(
    app: Application,
    runtime: _WorkflowRuntime,
    started: StartInternalResult,
    *,
    seed: int,
    expected_frontier: int,
    target: str,
) -> None:
    """Append a local human's logical redaction of *target*, shaped like the recorded fixture."""

    from finishup.domain.events import (
        RedactionMethod,
        RedactionReasonCategory,
        RedactionRecordedPayload,
    )
    from finishup.domain.values import Actor, ActorType, actor_id

    ledger, objects = next(iter(runtime.resources.values()))
    now = app.clock.now_utc()
    payload = RedactionRecordedPayload(
        (event_id(target),),
        (),
        RedactionMethod.LOGICAL_REDACTION,
        RedactionReasonCategory.OTHER,
        actor_id("human.test.local"),
        "The raising check is redacted.",
    )
    encoded = canonical_encode(encode_payload(payload))
    metadata = ObjectMetadata(
        ObjectKind.EVENT_PAYLOAD, media_type_for("redaction_recorded"), started.task_id, now
    )
    staged = await objects.stage(ObjectSource(data=encoded, declared_size=len(encoded)), metadata)
    payload_ref = await objects.finalize(staged)
    channel = PublicationChannel.LOCAL_CLI
    await ledger.append_batch(
        AppendCommand(
            started.task_id,
            started.session_id,
            started.writer_id,
            protocol_id("req_", seed),
            OperationKind.PUBLISH_WORK,
            _DIGEST,
            expected_frontier,
            (
                AppendEntry(
                    EventDraft(
                        event_id(protocol_id("evt_", seed + 1)),
                        EventSchema("redaction_recorded", "1.0.0"),
                        timestamp_from_datetime(now),
                        (),
                        payload,
                        (),
                        (),
                    ),
                    Actor(
                        actor_id("human.test.local"),
                        ActorType.HUMAN,
                        AuthorshipAssurance.LOCALLY_AUTHENTICATED,
                    ),
                    payload_ref,
                    payload_ref.commitment,
                    metadata.media_type,
                    payload_ref.plaintext_size,
                    channel,
                    coverage_for_channel(channel),
                    "projected",
                ),
            ),
            None,
        )
    )


async def _resolved_in_json_receipt(
    app: Application,
    started: StartInternalResult,
    seed: int,
    frontier: Frontier | FrontierModel,
) -> tuple[frozenset[str], ReceiptInternalResult]:
    receipt = await app.receipt(
        ReceiptRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed)),
                "task_id": started.task_id,
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(frontier),
                "format": "json",
                "include": "standard",
                "redaction_profile": "full_local",
            }
        )
    )
    document = cast(Mapping[str, JsonValue], receipt.document)
    sections = cast(tuple[Mapping[str, JsonValue], ...], document["sections"])
    summary = next(section for section in sections if section["key"] == "summary")
    items = cast(tuple[str, ...], summary["items"])
    return frozenset(item for item in items if item.startswith("fnd_")), receipt


@pytest.mark.parametrize("ledger_backend", ("memory", "sqlite"))
async def test_redacting_the_raising_check_reopens_a_resolution_that_read_it(
    monkeypatch: pytest.MonkeyPatch, ledger_backend: Literal["memory", "sqlite"]
) -> None:
    """Unreadable proof is no proof (#904 review): the fallback's source check is proof input.

    A pre-upgrade finding resolved only through its raising check's recorded reduced scope. Once
    that check is redacted, status and receipts report it current again, and a projection rebuild
    over the same ledger agrees.
    """

    seed = 5900
    app, runtime, started, checked, finding, repaired = await _resolve_pre_upgrade_finding(
        monkeypatch, seed=seed, ledger_backend=ledger_backend
    )
    resolved_ids, receipt = await _resolved_in_json_receipt(
        app, started, seed + 50, repaired.result_frontier
    )
    assert finding.finding_id in resolved_ids

    ledger, _objects = next(iter(runtime.resources.values()))
    records = tuple([row async for row in ledger.load_events(started.session_id)])
    raising = next(
        row
        for row in records
        if isinstance(row.payload, CheckRecordedPayload)
        and finding.finding_id in row.payload.returned_finding_ids
        and row.payload.subject_frontier.sequence == checked.subject_frontier.sequence
    )
    record = replay(records).findings[finding.finding_id]
    assert record.resolution_raising_check_event_id == raising.event_id

    await _append_local_redaction(
        app,
        runtime,
        started,
        seed=seed + 60,
        expected_frontier=receipt.result_frontier.sequence,
        target=raising.event_id,
    )
    view = await _findings_view(app, started, seed + 62, include_resolved=True)
    row = next(item for item in view.items if item.finding_id == finding.finding_id)
    assert row.resolved is False
    head = await ledger.load_projection(started.session_id, ProjectionView.CANDIDATE_FINDINGS)
    assert head is not None
    resolved_ids, _receipt = await _resolved_in_json_receipt(app, started, seed + 63, head.frontier)
    assert finding.finding_id not in resolved_ids

    records = tuple([row async for row in ledger.load_events(started.session_id)])
    rebuilt = replay(records)
    assert not finding_is_resolved(rebuilt, finding.finding_id)
    assert rebuilt.findings[finding.finding_id].reduced_scope_raising_check_event_id is None
    stored = await ledger.load_projection(started.session_id, ProjectionView.CANDIDATE_FINDINGS)
    assert stored is not None and stored.state == rebuilt
    assert (
        finding_is_resolved(
            projection_from_snapshot(projection_snapshot(rebuilt)), finding.finding_id
        )
        is False
    )


async def test_a_newly_reduced_reference_scope_still_blocks_semantic_resolution() -> None:
    """A finding raised by a review that saw the whole ledger is not cleared by a bounded one."""

    seed = 5800
    conclusions = ["challenges_returned", "no_material_discrepancy"]
    app, _runtime, _ = _build_app(
        seed_offset=58,
        semantic="optional",
        semantic_evaluator=_scripted_semantic_evaluator(
            protocol_id("clm_", seed + 5),
            conclusions,
            case_gaps=("content_unselected",),
            over_item_limit=False,
            scope_reduced=[False, True],
        ),
    )
    started, checked, _obligation = await _bootstrap_finding(
        app, seed=seed, mode="semantic_if_configured"
    )
    finding = next(
        item for item in checked.findings if item.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED
    )
    assert _SCOPE_REDUCED not in finding.coverage.known_gaps
    assert _SCOPE_REDUCED not in checked.coverage.known_gaps

    published = await _publish_repair_evidence(app, started, seed + 30, checked.result_frontier)
    repaired = await _semantic_recheck(app, started, seed + 40, published.result_frontier)
    assert _SCOPE_REDUCED in repaired.coverage.known_gaps
    view = await _findings_view(app, started, seed + 41, include_resolved=True)
    row = next(item for item in view.items if item.finding_id == finding.finding_id)
    assert row.resolved is False
    assert "coverage:" + _SCOPE_REDUCED in str(row.detail)


_REVIEW_SCOPE = AuthorizationScope(
    AuthorizationScopeKind.TASK,
    "ins_10000000-0000-4000-8000-000000000001",
    "hmac-sha256:" + "a" * 64,
    "tsk_10000000-0000-4000-8000-000000000001",
)


def _sent_packet_evaluator(
    claim_ref: str,
    conclusions: list[str],
    sent: list[tuple[SemanticCase, ReviewPacketDisclosure]],
    *,
    withhold_excerpts_of: frozenset[str] = frozenset(),
    subjects: tuple[str, ...] = (),
) -> Callable[..., Awaitable[object]]:
    """A reduced review whose record is what the real sent packet carried (#904).

    It builds the real review case from the production-frozen case (recorded history available),
    approves every offered item except the excerpts of *withhold_excerpts_of* (a per-item privacy
    drop), assembles the exact provider document, reads it, and names the ledger records it
    carried the way the composition does.
    """

    async def evaluate(
        frozen: object,
        findings: object,
        runtime: object | None = None,
        lineage_evaluation: object | None = None,
    ) -> object:
        raised = cast(
            FinalSemanticEvaluation,
            await _scripted_semantic_evaluator(
                claim_ref,
                conclusions,
                case_gaps=("content_unselected",),
                over_item_limit=False,
                scope_reduced=[True],
                subjects=subjects,
            )(frozen, findings),
        )
        case = cast(FrozenCase, frozen).case
        assert case.history_availability == "available", "production freezes recorded history"
        profile = ReviewContextProfile.EXPANDED
        semantic = build_semantic_case(
            case_id=protocol_id("cas_", 9040 + len(sent)),
            frozen_case=case,
            dependency_digest=_DIGEST,
            findings=cast(tuple[Finding, ...], findings),
            review_context_profile=profile,
            review_selection=ReviewSelectionPolicy.for_profile(profile),
            policy_id=protocol_id("pvy_", 9040),
            policy_version="1",
        )
        candidate = semantic_case_to_candidate_context(
            semantic,
            request_id=protocol_id("req_", 9040 + len(sent)),
            scope=_REVIEW_SCOPE,
            provider_binding=ProviderBinding(
                "fireworks", "test-model", "chat-completions", "1", "external"
            ),
        )
        withheld = {
            item.item_id
            for item in semantic.items
            if item.section == "excerpt" and item.source_ref in withhold_excerpts_of
        }
        prepared = semantic_case_to_prepared_payload(
            semantic, {item.item_id for item in candidate.items} - withheld
        )
        disclosure = review_packet_disclosure(prepared)
        assert disclosure is not None
        sent.append((semantic, disclosure))
        return replace(raised, case_included_refs=sent_ledger_refs(disclosure, case.projection))

    return evaluate


async def _publish_drafts(
    app: Application,
    started: StartInternalResult,
    seed: int,
    frontier: Frontier | FrontierModel,
    drafts: tuple[dict[str, JsonValue], ...],
) -> PublishWorkInternalResult:
    published = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(frontier),
                "event_drafts": drafts,
            }
        )
    )
    assert type(published) is PublishWorkInternalResult
    return published


def _draft(event: str, name: str, payload: dict[str, JsonValue]) -> dict[str, JsonValue]:
    return {
        "event_id": event,
        "schema": {"name": name, "version": "1.0.0"},
        "occurred_at": "2026-07-19T12:00:03.000Z",
        "causal_parents": (),
        "payload": payload,
        "artifact_refs": (),
        "evidence_refs": (),
    }


_REPAIRS = (
    "result_without_evidence",
    "described_evidence",
    "reference_only_evidence",
    "digest_only_evidence",
)


@pytest.mark.parametrize("repair", _REPAIRS)
async def test_a_reduced_review_credits_a_repair_carried_by_its_recording_event(
    repair: str,
) -> None:
    """Liveness on the production case shape, where recorded history is available (#904).

    Results and evidence then travel as history items keyed by the event that recorded them; a
    logical ``res_`` or ``evd_`` is a content ``source_ref`` only for a failure or evidence excerpt.
    A repair the sent packet carried under its recording event must still resolve the finding.
    """

    seed = 6100 + 100 * _REPAIRS.index(repair)
    conclusions = ["challenges_returned", "no_material_discrepancy"]
    sent: list[tuple[SemanticCase, ReviewPacketDisclosure]] = []
    app, runtime, _ = _build_app(
        seed_offset=seed // 100,
        semantic="optional",
        semantic_evaluator=_sent_packet_evaluator(protocol_id("clm_", seed + 5), conclusions, sent),
    )
    started, checked, _obligation = await _bootstrap_finding(
        app, seed=seed, mode="semantic_if_configured"
    )
    finding = next(
        item for item in checked.findings if item.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED
    )
    assert _SCOPE_REDUCED in finding.coverage.known_gaps

    action, result, evidence = (
        protocol_id("act_", seed + 30),
        protocol_id("res_", seed + 31),
        protocol_id("evd_", seed + 32),
    )
    recording_event = protocol_id("evt_", seed + 42)
    if repair == "result_without_evidence":
        cited = result
        drafts = (
            _draft(
                protocol_id("evt_", seed + 41),
                "action_recorded",
                {"action_id": action, "action_kind": "edit", "description": "Validate offsets"},
            ),
            _draft(
                recording_event,
                "result_recorded",
                {"result_id": result, "action_id": action, "outcome": "success", "exit_status": 0},
            ),
        )
    else:
        cited = evidence
        described = repair == "described_evidence"
        drafts = (
            _draft(
                recording_event,
                "evidence_recorded",
                {
                    "evidence_id": evidence,
                    "evidence_kind": "test_result" if described else "artifact",
                    "strength": "mutable_reference",
                    "observed_at": "2026-07-19T12:00:03.000Z",
                    **(
                        {
                            "description": "12 passed; negative offsets rejected",
                            "reference": "ci-run-6200",
                        }
                        if described
                        else {"reference": "ci-run-6300"}
                        if repair == "reference_only_evidence"
                        else {"reference": "ci-run-6400", "content_digest": "sha256:" + "7" * 64}
                    ),
                },
            ),
        )
    published = await _publish_drafts(app, started, seed + 40, checked.result_frontier, drafts)
    answered = await app.respond(
        RespondRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 50)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(published.result_frontier),
                "finding_id": finding.finding_id,
                "finding_frontier": _frontier(checked.result_frontier),
                "disposition": "acknowledged",
                "reason": "Validated offsets and recorded the run.",
                "evidence_refs": (cited,),
            }
        )
    )
    repaired = await _semantic_recheck(app, started, seed + 60, answered.result_frontier)
    assert conclusions == []
    assert _SCOPE_REDUCED in repaired.coverage.known_gaps
    assert "semantic_included_refs_not_recorded" not in repaired.coverage.known_gaps

    _semantic, disclosure = sent[-1]
    if repair == "result_without_evidence":
        # The successful result is carried only as its recording event's history item.
        assert result not in disclosure.carried
        assert recording_event in disclosure.payload_events
    view = await _findings_view(app, started, seed + 61, include_resolved=True)
    row = next(item for item in view.items if item.finding_id == finding.finding_id)
    assert row.resolved is True, row.detail

    ledger, _objects = next(iter(runtime.resources.values()))
    records = tuple([item async for item in ledger.load_events(started.session_id)])
    [check] = [
        row.payload
        for row in records
        if isinstance(row.payload, CheckRecordedPayload)
        and row.payload.subject_frontier.sequence == repaired.subject_frontier.sequence
    ]
    assert check.semantic_included_refs is not None and cited in check.semantic_included_refs
    assert finding_is_resolved(replay(records), finding.finding_id)


async def test_a_reduced_review_does_not_credit_a_record_it_withheld() -> None:
    """The recording event was sent, but privacy withheld the record's own excerpt: still open.

    Only a ``not_recorded`` omission (the payload is all the ledger holds) lets a recording event
    stand in for its record; a ``not_selected`` or policy-withheld record is not credited.
    """

    seed = 6600
    evidence = protocol_id("evd_", seed + 32)
    recording_event = protocol_id("evt_", seed + 42)
    conclusions = ["challenges_returned", "no_material_discrepancy"]
    sent: list[tuple[SemanticCase, ReviewPacketDisclosure]] = []
    app, _runtime, _ = _build_app(
        seed_offset=66,
        semantic="optional",
        semantic_evaluator=_sent_packet_evaluator(
            protocol_id("clm_", seed + 5),
            conclusions,
            sent,
            withhold_excerpts_of=frozenset({evidence}),
        ),
    )
    started, checked, _obligation = await _bootstrap_finding(
        app, seed=seed, mode="semantic_if_configured"
    )
    finding = next(
        item for item in checked.findings if item.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED
    )
    published = await _publish_drafts(
        app,
        started,
        seed + 40,
        checked.result_frontier,
        (
            _draft(
                recording_event,
                "evidence_recorded",
                {
                    "evidence_id": evidence,
                    "evidence_kind": "test_result",
                    "strength": "mutable_reference",
                    "observed_at": "2026-07-19T12:00:03.000Z",
                    "description": "12 passed; negative offsets rejected",
                    "reference": "ci-run-6400",
                },
            ),
        ),
    )
    answered = await app.respond(
        RespondRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 50)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(published.result_frontier),
                "finding_id": finding.finding_id,
                "finding_frontier": _frontier(checked.result_frontier),
                "disposition": "acknowledged",
                "reason": "Validated offsets and recorded the run.",
                "evidence_refs": (evidence,),
            }
        )
    )
    repaired = await _semantic_recheck(app, started, seed + 60, answered.result_frontier)
    _semantic, disclosure = sent[-1]
    assert recording_event in disclosure.payload_events
    assert evidence in disclosure.withheld and evidence not in disclosure.carried
    assert _SCOPE_REDUCED in repaired.coverage.known_gaps
    view = await _findings_view(app, started, seed + 61, include_resolved=True)
    row = next(item for item in view.items if item.finding_id == finding.finding_id)
    assert row.resolved is False
    assert "finding_material_outside_reduced_review_scope" in str(row.detail)


def _claim_correction(
    event: str, claim: str, supersedes: str, support: str, obligation: str
) -> dict[str, JsonValue]:
    draft = _draft(
        event,
        "claim_recorded",
        {
            "claim_id": claim,
            "claim_kind": "completion",
            "statement": "The exercise is complete; the repair run is recorded.",
            "supporting_refs": (support,),
            "limitation_refs": (),
            "supersedes_claim_refs": (supersedes,),
            "obligation_refs": (obligation,),
        },
    )
    return {**draft, "schema": {"name": "claim_recorded", "version": "1.1.0"}}


@pytest.mark.parametrize("ledger_backend", ("memory", "sqlite"))
async def test_a_long_session_repair_that_evicted_the_subjects_resolves_the_finding(
    ledger_backend: Literal["memory", "sqlite"],
) -> None:
    """Issue #947, the goreleaser shape, through the real packet, check, replay and receipts.

    The reviewer cites an early action event, an early evidence event and the completion claim.
    The agent then works on (well over 64 more recorded events), corrects the claim as asked, and
    answers with the repair evidence. The third review's real packet no longer carries the early
    events in its history window, nor the superseded claim, yet it carried the finding's own row,
    the corrected claim, the repair evidence and later changes: the finding resolves, while status
    and every receipt rendering keep disclosing the reduced reference scope. Replay equals live.
    """

    seed = 6700
    obligation, obligation_event = protocol_id("obl_", seed + 1), protocol_id("evt_", seed + 2)
    old_claim, old_claim_event = protocol_id("clm_", seed + 5), protocol_id("evt_", seed + 4)
    old_action, old_action_event = protocol_id("act_", seed + 6), protocol_id("evt_", seed + 7)
    old_evidence, old_evidence_event = protocol_id("evd_", seed + 8), protocol_id("evt_", seed + 9)
    conclusions = ["challenges_returned", "no_material_discrepancy", "no_material_discrepancy"]
    sent: list[tuple[SemanticCase, ReviewPacketDisclosure]] = []
    app, runtime, _ = _build_app(
        seed_offset=67,
        semantic="optional",
        ledger_backend=ledger_backend,
        semantic_evaluator=_sent_packet_evaluator(
            old_claim, conclusions, sent, subjects=(old_action_event, old_evidence_event)
        ),
    )
    started = await app.start(start_request(seed, title="Long-session repair"))
    first = await _publish_drafts(
        app,
        started,
        seed + 10,
        started.frontier,
        (
            _draft(
                obligation_event,
                "obligation_published",
                {
                    "obligation_id": obligation,
                    "description": "Release archives carry the checksum file.",
                    "acceptance_criteria": "The release test passes.",
                    "evidence_expectation": "A recorded test run.",
                    "status": "open",
                },
            ),
            _draft(
                old_action_event,
                "action_recorded",
                {"action_id": old_action, "action_kind": "edit", "description": "First attempt"},
            ),
            _draft(
                old_evidence_event,
                "evidence_recorded",
                {
                    "evidence_id": old_evidence,
                    "evidence_kind": "test_result",
                    "strength": "mutable_reference",
                    "observed_at": "2026-07-19T12:00:03.000Z",
                    "description": "release test: 3 passed",
                    "reference": "ci-run-6701",
                },
            ),
            _draft(
                old_claim_event,
                "claim_recorded",
                {
                    "claim_id": old_claim,
                    "claim_kind": "completion",
                    "statement": "The exercise is complete.",
                    "supporting_refs": (old_evidence,),
                    "obligation_refs": (obligation,),
                },
            ),
        ),
    )
    raised = await _semantic_recheck(app, started, seed + 20, first.result_frontier)
    finding = next(
        item for item in raised.findings if item.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED
    )
    assert {old_claim, old_action_event, old_evidence_event} <= set(finding.subject_refs)
    assert _SCOPE_REDUCED in finding.coverage.known_gaps

    # An unchanged recheck proves nothing.
    unchanged = await _semantic_recheck(app, started, seed + 21, raised.result_frontier)
    view = await _findings_view(app, started, seed + 22, include_resolved=True)
    row = next(item for item in view.items if item.finding_id == finding.finding_id)
    assert row.resolved is False
    assert "no_material_change_since_finding" in str(row.detail)

    # Long work: far more recorded events than the 64-row history window holds.
    frontier: Frontier | FrontierModel = unchanged.result_frontier
    for batch in range(2):
        drafts = tuple(
            _draft(
                protocol_id("evt_", seed + 1000 + 100 * batch + number),
                "action_recorded",
                {
                    "action_id": protocol_id("act_", seed + 1000 + 100 * batch + number),
                    "action_kind": "edit",
                    "description": f"Work step {batch}-{number}",
                },
            )
            for number in range(60)
        )
        frontier = (
            await _publish_drafts(app, started, seed + 30 + batch, frontier, drafts)
        ).result_frontier

    repair_evidence = protocol_id("evd_", seed + 40)
    corrected_claim = protocol_id("clm_", seed + 41)
    repaired = await _publish_drafts(
        app,
        started,
        seed + 42,
        frontier,
        (
            _draft(
                protocol_id("evt_", seed + 43),
                "evidence_recorded",
                {
                    "evidence_id": repair_evidence,
                    "evidence_kind": "test_result",
                    "strength": "mutable_reference",
                    "observed_at": "2026-07-19T12:00:03.000Z",
                    "description": "release test: 4 passed; checksum file present",
                    "reference": "ci-run-6744",
                },
            ),
            _claim_correction(
                protocol_id("evt_", seed + 44),
                corrected_claim,
                old_claim,
                repair_evidence,
                obligation,
            ),
        ),
    )
    answered = await app.respond(
        RespondRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 50)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(repaired.result_frontier),
                "finding_id": finding.finding_id,
                "finding_frontier": _frontier(raised.result_frontier),
                "disposition": "acknowledged",
                "reason": "Added the checksum file and corrected the completion claim.",
                "evidence_refs": (repair_evidence,),
            }
        )
    )
    third = await _semantic_recheck(app, started, seed + 60, answered.result_frontier)
    assert conclusions == []
    assert finding.finding_id not in {item.finding_id for item in third.findings}
    assert _SCOPE_REDUCED in third.coverage.known_gaps

    ledger, _objects = next(iter(runtime.resources.values()))
    records = tuple([item async for item in ledger.load_events(started.session_id)])
    [check] = [
        item.payload
        for item in records
        if isinstance(item.payload, CheckRecordedPayload)
        and item.payload.subject_frontier.sequence == third.subject_frontier.sequence
    ]
    included = set(check.semantic_included_refs or ())
    # None of the cited material was re-sent: the window evicted the early events and the claim
    # was superseded. The finding's own row, the correction and the repair were.
    assert not {old_claim, old_claim_event, old_action_event, old_evidence_event} & included
    assert {finding.finding_id, corrected_claim, repair_evidence} <= included

    view = await _findings_view(app, started, seed + 61, include_resolved=True)
    row = next(item for item in view.items if item.finding_id == finding.finding_id)
    assert row.resolved is True, row.detail
    rebuilt = replay(records)
    assert finding_is_resolved(rebuilt, finding.finding_id)
    stored = await ledger.load_projection(started.session_id, ProjectionView.CANDIDATE_FINDINGS)
    assert stored is not None and stored.state == rebuilt
    await _assert_reduced_scope_disclosed(app, started, seed + 70, third.result_frontier)


async def test_reattach_with_an_unchanged_statement_keeps_the_statement_event() -> None:
    """Pilot blocker D2: repeating the unchanged statement on re-attach is not an amendment.

    The resume still records the statement it was given (the ledger keeps the history), but
    the earlier event stays the current statement event, so the finding subject and every
    obligation citing it stay put; both events count as equivalent. An amended statement moves it.
    """

    from finishup.domain.events import SessionResumedPayload
    from finishup.domain.task_statement import current_task_statement

    seed = 9800
    statement = "The user's request, verbatim."
    app, runtime, _ = _build_app(seed_offset=98)

    def attach(offset: int, text: str) -> StartRequest:
        return StartRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + offset)),
                "mode": "create_or_attach",
                "workspace_ref": "workspace-A",
                "external_ref": "external-A",
                "task_title": "Respond/status/receipt exercise",
                "requested_view": "compact",
                "task_statement": text,
            }
        )

    started = await app.start(attach(1, statement))
    assert started.outcome == "created"
    ledger, _objects = runtime.resources[started.task_id]

    async def records() -> tuple[LedgerRecord, ...]:
        return tuple([row async for row in ledger.load_events(started.session_id)])

    opened = current_task_statement(await records())
    assert opened is not None and opened.source_family == "session_opened"

    same = await app.start(attach(2, statement))
    assert same.outcome == "attached"
    after_same = await records()
    resumed = [row for row in after_same if type(row.payload) is SessionResumedPayload]
    assert len(resumed) == 1
    assert cast(SessionResumedPayload, resumed[0].payload).task_statement == statement
    current = current_task_statement(after_same)
    assert current is not None and current.source_event_id == opened.source_event_id
    assert set(current.equivalent_event_ids) == {opened.source_event_id, resumed[0].event_id}

    amended = await app.start(attach(3, "A different request."))
    assert amended.outcome == "attached"
    current = current_task_statement(await records())
    assert current is not None
    assert current.source_family == "session_resumed"
    assert current.text == "A different request."
    assert current.equivalent_event_ids == (current.source_event_id,)


def _question_evaluator(claim_ref: str) -> Callable[..., Awaitable[object]]:
    """Ask the agent one question about *claim_ref* (issue #976)."""

    async def evaluate(
        frozen: object,
        findings: object,
        runtime: object | None = None,
        lineage_evaluation: object | None = None,
    ) -> object:
        succeeded = cast(FinalSemanticEvaluation, await _semantic_succeeds(frozen, findings))
        question = ReviewerChallenge(
            FindingKind.CLAIM_WITHOUT_ADMISSIBLE_EVIDENCE,
            "Which interpretation of the output format did you choose?",
            (claim_ref,),
            "Question: does the claim use the separator the task statement shows?",
            "The chosen separator may match the statement exactly.",
            "Answer which separator you used and why.",
            "answer_question",
            "The packet does not show the written output.",
        )
        return replace(succeeded, judgment=SemanticJudgment("challenges_returned", (question,)))

    return evaluate


async def test_reviewer_question_is_answered_by_a_reason_and_bare_acknowledgement_refused() -> None:
    """TB4 tb4f1 (issue #976): a reviewer finding needs an answer the next review can read."""

    seed = 5400
    app, _runtime, _ = _build_app(
        seed_offset=54,
        semantic="optional",
        semantic_evaluator=_question_evaluator(protocol_id("clm_", seed + 5)),
    )
    started, checked, _obligation = await _bootstrap_finding(
        app, seed=seed, mode="semantic_if_configured"
    )
    question = next(
        item for item in checked.findings if item.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED
    )
    assert question.challenge is not None
    assert question.challenge.requested_next_step == "answer_question"

    def wire(request_seed: int, reason: str | None) -> RespondRequest:
        body: dict[str, JsonValue] = {
            **_request_base(protocol_id("req_", request_seed)),
            "session_id": started.session_id,
            "writer_id": started.writer_id,
            "expected_frontier": _frontier(checked.result_frontier),
            "finding_id": question.finding_id,
            "finding_frontier": _frontier(checked.result_frontier),
            "disposition": "acknowledged",
        }
        if reason is not None:
            body["reason"] = reason
        return RespondRequest.model_validate(body)

    with pytest.raises(PublicOperationError) as refused:
        await app.respond(wire(seed + 10, None))
    assert refused.value.code is PublicErrorCode.INVALID_REQUEST
    assert refused.value.safe_details["reason_code"] == "response_fields_invalid"
    assert refused.value.safe_details["field"] == "/reason"

    # The answer is the reason; a question needs no separate resolution attempt.
    answered = await app.respond(wire(seed + 11, "I used '; ' exactly as output_format.txt shows."))
    assert answered.response.disposition == "acknowledged"


async def test_closing_review_request_reaches_the_evaluator() -> None:
    """Issue #976: ``final_review`` travels from the check request to the evaluator seam."""

    seen: list[bool] = []

    async def evaluate(
        frozen: object,
        findings: object,
        runtime: object | None = None,
        lineage_evaluation: object | None = None,
        require_complete_specification: bool = False,
        final_review: bool = False,
    ) -> object:
        del require_complete_specification
        seen.append(final_review)
        return await _semantic_succeeds(frozen, findings)

    seed = 5500
    app, _runtime, _ = _build_app(seed_offset=55, semantic="optional", semantic_evaluator=evaluate)
    started, checked, _obligation = await _bootstrap_finding(
        app, seed=seed, mode="semantic_if_configured"
    )
    closing = await app.check(
        CheckRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 30)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(checked.result_frontier),
                "mode": "semantic_if_configured",
                "final_review": True,
            }
        )
    )
    assert type(closing) is CheckCommitResult
    assert seen == [False, True]


async def test_requested_output_facts_reach_the_evaluator_as_task_fact_gaps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Issue #977: check-time requested-file facts travel to the AI-powered review seam.

    The workspace read is replaced (it needs a real Git checkout); everything from the closed
    gap codes onward runs through the real check and ``Application.evaluate_semantic_check``.
    """

    from finishup.application import check_change
    from finishup.kernel.deterministic_checks import REQUESTED_OUTPUT_ABSENT_FACT
    from finishup.kernel.task_facts import REQUESTED_OUTPUT_GIT_IGNORED_GAP, RequestedOutputState

    seed = 5600
    obligation = protocol_id("obl_", seed + 1)

    async def states(**_kwargs: object) -> dict[tuple[object, int], RequestedOutputState]:
        return {
            (obligation, 0): RequestedOutputState("inside", exists=False),
            (obligation, 1): RequestedOutputState(
                "inside", exists=True, ignored=True, ignored_by_task=True
            ),
        }

    monkeypatch.setattr(check_change, "requested_output_states", states)
    seen: list[tuple[str, ...]] = []

    async def evaluate(
        frozen: object,
        findings: object,
        runtime: object | None = None,
        lineage_evaluation: object | None = None,
        require_complete_specification: bool = False,
        task_fact_gaps: tuple[str, ...] = (),
    ) -> object:
        del require_complete_specification
        seen.append(task_fact_gaps)
        return await _semantic_succeeds(frozen, findings, runtime, lineage_evaluation)

    app, _runtime, _ = _build_app(seed_offset=56, semantic="optional", semantic_evaluator=evaluate)
    await _bootstrap_finding(
        app,
        seed=seed,
        mode="semantic_if_configured",
        requested_items=(
            {"item_kind": "file", "value": "out/missing.txt"},
            {"item_kind": "file", "value": "out/ignored.txt"},
        ),
    )

    assert seen == [(REQUESTED_OUTPUT_ABSENT_FACT, REQUESTED_OUTPUT_GIT_IGNORED_GAP)]


async def _compact_readiness(app: Application, started: StartInternalResult, seed: int) -> Any:
    status = await app.status(
        StatusRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "view": "compact",
                "limit": "1",
            }
        )
    )
    return status.closure_readiness


async def test_self_verified_answers_a_local_finding_only_observation_loss_keeps_unproven() -> None:
    """Issue #984, tb4n1 B3/C1: one lost hook input marked later observations
    ``observation_input_loss``; the repaired local finding could never be proven absent and the
    agent filed a false ``finishup-blocker``. It now verifies the repair itself and says so."""

    app, runtime, _ = _build_app(seed_offset=41)
    started, checked, obligation = await _bootstrap_finding(app, seed=9800)
    finding = checked.findings[0]
    repaired = await _repair_open_obligation(
        app, started, obligation, checked.result_frontier, seed=9820
    )
    evidence = protocol_id("evd_", 9820)
    drained = await _drain_host_observation_gaps(
        app,
        runtime,
        started,
        seed=9840,
        expected_frontier=repaired.result_frontier.sequence,
        known_gaps=("observation_input_loss",),
    )
    rechecked = await app.check(
        CheckRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 9850)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(drained.result_frontier),
                "mode": "deterministic_only",
                "max_findings": "3",
            }
        )
    )
    assert type(rechecked) is CheckCommitResult
    assert "observation_input_loss" in rechecked.coverage.known_gaps
    page = await _findings_view(app, started, 9855, include_resolved=True)
    row = next(item for item in page.items if item.finding_id == finding.finding_id)
    assert row.resolved is False
    assert "coverage:observation_input_loss" in cast(str, row.detail)
    assert "respond `self_verified`" in cast(str, row.detail)
    blocking_before = int(
        cast(str, (await _compact_readiness(app, started, 9857)).receipt_blocking_finding_count)
    )

    answered = await app.respond(
        RespondRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 9860)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(rechecked.result_frontier),
                "finding_id": finding.finding_id,
                "finding_frontier": _frontier(rechecked.result_frontier),
                "disposition": "self_verified",
                "reason": "The obligation's result is recorded; I re-read the ledger row myself.",
                "evidence_refs": (evidence,),
            }
        )
    )
    assert answered.response.disposition == "self_verified"
    page = await _findings_view(app, started, 9865, include_resolved=True)
    row = next(item for item in page.items if item.finding_id == finding.finding_id)
    assert (row.todo_state, row.resolved) == ("self_verified", False)
    readiness = await _compact_readiness(app, started, 9870)
    # The self-verified item stops counting as agent work; the other findings still do.
    assert int(cast(str, readiness.receipt_blocking_finding_count)) == blocking_before - 1
    assert "finding_self_verified" in (readiness.standing_limitations or ())
    receipt = await app.receipt(
        ReceiptRequest.model_validate(
            _receipt_wire(
                9880,
                task_id=started.task_id,
                session=started.session_id,
                writer=started.writer_id,
                frontier=answered.result_frontier,
            )
        )
    )
    assert receipt.conclusion != "no_unresolved_deterministic_findings"


async def _restate_claim(
    app: Application,
    started: StartInternalResult,
    obligation_id: str,
    frontier: Frontier | FrontierModel,
    *,
    seed: int,
) -> PublishWorkInternalResult:
    """Repeat the unsupported completion claim (tb4n1: the agent claimed done again)."""

    result = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(frontier),
                "event_drafts": (
                    {
                        "event_id": protocol_id("evt_", seed + 1),
                        "schema": {"name": "claim_recorded", "version": "1.0.0"},
                        "occurred_at": "2026-07-19T12:02:00.000Z",
                        "causal_parents": (),
                        "payload": {
                            "claim_id": protocol_id("clm_", seed + 2),
                            "claim_kind": "completion",
                            "statement": "The exercise is complete, really.",
                            "supporting_refs": (obligation_id,),
                            "obligation_refs": (obligation_id,),
                        },
                        "artifact_refs": (),
                        "evidence_refs": (),
                    },
                ),
            }
        )
    )
    assert type(result) is PublishWorkInternalResult
    return result


async def _check_again(
    app: Application,
    started: StartInternalResult,
    frontier: Frontier | FrontierModel,
    seed: int,
    *,
    max_findings: str = "3",
) -> CheckCommitResult:
    checked = await app.check(
        CheckRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(frontier),
                "mode": "deterministic_only",
                "max_findings": max_findings,
            }
        )
    )
    assert type(checked) is CheckCommitResult
    return checked


def _duplicate_wire(
    started: StartInternalResult,
    frontier: Frontier | FrontierModel,
    finding: str,
    target: str,
    seed: int,
) -> dict[str, JsonValue]:
    return {
        **_request_base(protocol_id("req_", seed)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(frontier),
        "finding_id": finding,
        "finding_frontier": _frontier(frontier),
        "disposition": "duplicate_of",
        "duplicate_of_finding_id": target,
    }


async def _refused_duplicate(
    app: Application,
    started: StartInternalResult,
    frontier: Frontier | FrontierModel,
    finding: str,
    target: str,
    seed: int,
) -> str:
    with pytest.raises(PublicOperationError) as refused:
        await app.respond(
            RespondRequest.model_validate(_duplicate_wire(started, frontier, finding, target, seed))
        )
    return cast(str, refused.value.safe_details["reason_code"])


def _row(page: StatusFindingsPageModel, finding: str) -> StatusFindingItemModel:
    return next(item for item in page.items if item.finding_id == finding)


async def _restated_completion_findings(
    app: Application, *, restatements: int, seed_offset: int
) -> tuple[StartInternalResult, CheckCommitResult, list[str], list[str]]:
    """tb4n1: the agent claimed completion again over the same open obligation, so the same rule
    raised the same kind of finding again under a new id each time."""

    started, checked, obligation = await _bootstrap_finding(app, seed=9960, max_findings="10")
    frontier: Frontier | FrontierModel = checked.result_frontier
    for index in range(restatements):
        published = await _restate_claim(
            app, started, obligation, frontier, seed=10400 + 20 * index
        )
        frontier = published.result_frontier
    rechecked = await _check_again(app, started, frontier, 10490, max_findings="10")
    page = await _findings_view(app, started, seed_offset, include_resolved=True)
    ordered = sorted(
        page.items,
        key=lambda item: int(item.finding_frontier.sequence) if item.finding_frontier else 0,
    )
    completion = [
        item.finding_id for item in ordered if item.kind == "completion_with_open_obligations"
    ]
    other = [item.finding_id for item in ordered if item.kind != "completion_with_open_obligations"]
    return started, rechecked, completion, other


async def test_duplicate_of_admission_refuses_other_issues_and_chains() -> None:
    """Issue #996: a link is admitted only for a genuine restatement: an earlier, readable
    finding of the same origin and kind that is not itself linked, from a finding nothing links
    to. Field rules are enforced by the request schema."""

    app, _runtime, _ = _build_app(seed_offset=61)
    started, checked, completion, other = await _restated_completion_findings(
        app, restatements=3, seed_offset=10100
    )
    first, second, third, fourth = completion[:4]
    at = checked.result_frontier

    assert await _refused_duplicate(app, started, at, second, second, 10101) == (
        "duplicate_target_same_finding"
    )
    unknown = protocol_id("fnd_", 10102)
    assert await _refused_duplicate(app, started, at, second, unknown, 10103) == (
        "duplicate_target_unknown"
    )
    assert await _refused_duplicate(app, started, at, first, second, 10104) == (
        "duplicate_target_not_earlier"
    )
    # A different kind is a different issue, even on the same claim and obligation.
    later_other = other[-1]
    assert await _refused_duplicate(app, started, at, later_other, first, 10105) == (
        "duplicate_target_different_issue"
    )
    missing = _duplicate_wire(started, at, second, first, 10106)
    del missing["duplicate_of_finding_id"]
    with pytest.raises(pydantic.ValidationError):
        RespondRequest.model_validate(missing)
    stray = {**_duplicate_wire(started, at, second, first, 10107), "disposition": "rejected"}
    stray["reason"] = "Not a duplicate."
    with pytest.raises(pydantic.ValidationError):
        RespondRequest.model_validate(stray)

    linked = await app.respond(
        RespondRequest.model_validate(_duplicate_wire(started, at, fourth, third, 10108))
    )
    assert linked.response.disposition == "duplicate_of"
    assert linked.response.duplicate_of_finding_id == third
    frontier = linked.result_frontier
    # Something links to the third finding, so it cannot become a duplicate itself.
    assert await _refused_duplicate(app, started, frontier, third, first, 10109) == (
        "duplicate_has_duplicates"
    )
    # A linked target is refused rather than silently re-pointed.
    again = await app.respond(
        RespondRequest.model_validate(_duplicate_wire(started, frontier, second, first, 10110))
    )
    assert await _refused_duplicate(app, started, again.result_frontier, fourth, second, 10111) == (
        "duplicate_target_is_duplicate"
    )


@pytest.mark.parametrize("ledger_backend", ("memory", "sqlite"))
async def test_duplicate_of_counts_once_inherits_state_and_breaks_on_re_raise(
    ledger_backend: Literal["memory", "sqlite"],
) -> None:
    """Issue #996 (tb4n1 D5/#980): a re-raised concern minted as a new finding is answered by
    linking it to the earlier finding. The pair counts once in readiness, the duplicate inherits
    only the earlier finding's never-clean answer, and a later check that returns it again
    breaks the link so it needs its own answer."""

    app, _runtime, _ = _build_app(seed_offset=62, ledger_backend=ledger_backend)
    started, checked, completion, _other = await _restated_completion_findings(
        app, restatements=1, seed_offset=10200
    )
    earliest, middle = completion[:2]
    before = await _compact_readiness(app, started, 10201)
    unanswered = int(cast(str, before.unanswered_finding_count))
    blocking = int(cast(str, before.receipt_blocking_finding_count))

    linked = await app.respond(
        RespondRequest.model_validate(
            _duplicate_wire(started, checked.result_frontier, middle, earliest, 10202)
        )
    )
    page = await _findings_view(app, started, 10203, include_resolved=True)
    row = _row(page, middle)
    assert row.disposition == "duplicate_of"
    assert row.duplicate_of_finding_id == earliest
    assert row.todo_state == "open"
    assert row.resolved is False
    linked_readiness = await _compact_readiness(app, started, 10204)
    # The duplicate is answered and, while both are open, the pair counts once.
    assert linked_readiness.unanswered_finding_count == str(unanswered - 1)
    assert linked_readiness.receipt_blocking_finding_count == str(blocking - 1)
    assert "receipt_findings_unresolved" in linked_readiness.blocking_conditions

    # The earlier finding's never-clean final answer is inherited.
    ended = await app.respond(
        RespondRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 10205)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(linked.result_frontier),
                "finding_id": earliest,
                "finding_frontier": _frontier(linked.result_frontier),
                "disposition": "acknowledged_not_done",
                "reason": "The exercise result is out of scope for this run.",
            }
        )
    )
    page = await _findings_view(app, started, 10206, include_resolved=True)
    assert _row(page, middle).todo_state == "acknowledged_not_done"
    assert _row(page, earliest).todo_state == "acknowledged_not_done"
    readiness = await _compact_readiness(app, started, 10207)
    assert readiness.acknowledged_not_done is not None
    assert earliest in readiness.acknowledged_not_done
    assert middle not in readiness.acknowledged_not_done
    with pytest.raises(PublicOperationError) as terminal:
        await app.respond(
            RespondRequest.model_validate(
                _duplicate_wire(started, ended.result_frontier, middle, earliest, 10208)
            )
        )
    assert terminal.value.safe_details["reason_code"] == "finding_terminal"

    # The receipt carries the duplicate's answer and never reads cleaner than the earlier
    # finding allows (the link section itself is on the 1.3.0 artifact; see test_receipts).
    receipt = await _receipt_912(app, started, ended.result_frontier, 10310, "json")
    document = cast(dict[str, JsonValue], receipt.document)
    dispositions = {
        cast(dict[str, JsonValue], item)["finding_id"]: cast(dict[str, JsonValue], item)[
            "disposition"
        ]
        for item in cast(list[JsonValue], document["responses"])
    }
    assert dispositions[middle] == "duplicate_of"
    assert receipt.conclusion == "unresolved_findings_remain"
    frontier = receipt.result_frontier
    for seed, receipt_format in ((10311, "markdown"), (10312, "text")):
        rendered = await _receipt_912(
            app, started, frontier, seed, cast(Literal["markdown", "text"], receipt_format)
        )
        assert rendered.human_text is not None
        assert rendered.conclusion == "unresolved_findings_remain"
        frontier = rendered.result_frontier

    # A later check returns the duplicate's issue again: the link breaks for good.
    again = await _check_again(app, started, frontier, 10212, max_findings="10")
    assert middle in {item.finding_id for item in again.findings}
    page = await _findings_view(app, started, 10213, include_resolved=True)
    row = _row(page, middle)
    assert row.disposition == "duplicate_of"
    assert row.duplicate_of_finding_id is None
    assert row.todo_state == "open"
    broken = await _compact_readiness(app, started, 10214)
    # Its duplicate_of answer no longer applies: it needs its own answer again.
    assert broken.unanswered_finding_count == str(unanswered - 1)
    assert await _refused_duplicate(
        app, started, again.result_frontier, middle, earliest, 10215
    ) == ("duplicate_link_broken")


# --- tb4n3 RC-5 (issue #1028, ADR-045): one emptied deliverable, every surface ---------------------


async def test_an_emptied_deliverable_tells_the_same_story_on_every_surface(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """formal-crypto S, end to end through the real check, status, gate and receipt.

    A delivered ``/app/solve.sage`` (15,975 bytes) is emptied, the solver obligation is
    republished ``acknowledged_not_done`` (which cleared the old fact), and the next check still
    reports it. The check result, status readiness, the Stop-gate text and the receipt (json,
    markdown, text) carry the same ``Why:`` sentence from the same recorded history.
    """

    from builders.observed_runs import INSTALLATION_KEY
    from finishup.application import check_change
    from finishup.application.check import check_internal_json
    from finishup.cli.closure_gate import closure_gate_from_readiness
    from finishup.cli.render import render_closure_readiness_lines
    from finishup.kernel.fact_lineage import lineage_from_wire, lineage_text
    from finishup.kernel.task_facts import (
        DECLARED_OUTPUT_EMPTIED_GAP,
        RequestedOutputState,
        register_command_identity_key,
    )

    seed = 7700
    obligation = protocol_id("obl_", seed + 1)
    box: dict[str, RequestedOutputState] = {
        "state": RequestedOutputState(
            "inside",
            exists=True,
            changed=True,
            size_bytes=15_975,
            lines=310,
            relative="solve.sage",
        )
    }

    async def states(**_kwargs: object) -> dict[tuple[object, int], RequestedOutputState]:
        return {(obligation, 0): box["state"]}

    monkeypatch.setattr(check_change, "requested_output_states", states)
    register_command_identity_key(INSTALLATION_KEY)
    try:
        app, _runtime, _ = _build_app(seed_offset=77)
        started = await app.start(start_request(seed, title="Emptied deliverable", refs=False))
        item = {"item_kind": "file", "value": "/app/solve.sage", "role": "output"}

        def obligation_draft(number: int, status: str, reason: str | None) -> dict[str, JsonValue]:
            return {
                "event_id": protocol_id("evt_", seed + number),
                "schema": {"name": "obligation_published", "version": "1.1.0"},
                "occurred_at": "2026-10-11T12:00:00.000Z",
                "causal_parents": (),
                "payload": {
                    "obligation_id": obligation,
                    "description": "Deliver the standalone solver at /app/solve.sage.",
                    "acceptance_criteria": "The solver reconstructs the target.",
                    "evidence_expectation": "Timed runs.",
                    "requested_items": (item,),
                    "status": status,
                    **({"acknowledged_not_done_reason": reason} if reason else {}),
                },
                "artifact_refs": (),
                "evidence_refs": (),
            }

        async def publish(drafts: tuple[dict[str, JsonValue], ...], frontier: Any, n: int) -> Any:
            return await app.publish_work(
                PublishWorkRequest.model_validate(
                    {
                        **_request_base(protocol_id("req_", seed + n)),
                        "session_id": started.session_id,
                        "writer_id": started.writer_id,
                        "expected_frontier": _frontier(frontier),
                        "event_drafts": drafts,
                    }
                )
            )

        async def check(frontier: Any, n: int) -> CheckCommitResult:
            result = await app.check(
                CheckRequest.model_validate(
                    {
                        **_request_base(protocol_id("req_", seed + n)),
                        "session_id": started.session_id,
                        "writer_id": started.writer_id,
                        "expected_frontier": _frontier(frontier),
                        "mode": "deterministic_only",
                        "max_findings": "3",
                    }
                )
            )
            assert type(result) is CheckCommitResult
            return result

        published = await publish(
            (
                obligation_draft(2, "open", None),
                {
                    "event_id": protocol_id("evt_", seed + 3),
                    "schema": {"name": "plan_published", "version": "1.0.0"},
                    "occurred_at": "2026-10-11T12:00:01.000Z",
                    "causal_parents": (),
                    "payload": {
                        "plan_version": 1,
                        "summary": "Deliver the solver.",
                        "obligation_refs": (obligation,),
                    },
                    "artifact_refs": (),
                    "evidence_refs": (),
                },
                {
                    "event_id": protocol_id("evt_", seed + 4),
                    "schema": {"name": "claim_recorded", "version": "1.0.0"},
                    "occurred_at": "2026-10-11T12:00:02.000Z",
                    "causal_parents": (),
                    "payload": {
                        "claim_id": protocol_id("clm_", seed + 5),
                        "claim_kind": "completion",
                        "statement": "The solver is delivered.",
                        "supporting_refs": (obligation,),
                        "obligation_refs": (obligation,),
                    },
                    "artifact_refs": (),
                    "evidence_refs": (),
                },
            ),
            started.frontier,
            10,
        )
        first = await check(published.result_frontier, 11)
        assert DECLARED_OUTPUT_EMPTIED_GAP not in first.coverage.known_gaps
        assert [(s.size_bytes, s.lines, s.basis) for s in first.deliverable_states] == [
            (15_975, 310, "delivered")
        ]

        # The agent empties the solver and republishes its obligation as not done.
        box["state"] = RequestedOutputState(
            "inside", exists=True, changed=True, size_bytes=0, lines=0, relative="solve.sage"
        )
        acknowledged = await publish(
            (obligation_draft(12, "acknowledged_not_done", "Not solved for every input."),),
            first.result_frontier,
            13,
        )
        checked = await check(acknowledged.result_frontier, 14)

        # 1. The check result.
        assert DECLARED_OUTPUT_EMPTIED_GAP in checked.coverage.known_gaps
        (fact,) = [x for x in checked.fact_lineage if x.code == DECLARED_OUTPUT_EMPTIED_GAP]
        assert (fact.state, fact.proof, fact.basis) == ("emptied", "earlier_check", "delivered")
        assert (fact.prior_size_bytes, fact.prior_lines, fact.now_size_bytes) == (15_975, 310, 0)
        why = lineage_text(fact)
        assert "15975 bytes / 310 lines" in why and obligation in why
        wire = check_internal_json(checked)
        assert wire["fact_lineage"] and DECLARED_OUTPUT_EMPTIED_GAP in cast(
            list[str], cast(dict[str, Any], wire["coverage"])["known_gaps"]
        )
        # A same-request retry answers with the same story (the first answer is frozen).
        replayed = await check(acknowledged.result_frontier, 14)
        assert replayed.fact_lineage == checked.fact_lineage
        assert check_internal_json(replayed)["fact_lineage"] == wire["fact_lineage"]

        # 2. Status readiness: the same code and the same lineage.
        status = await app.status(
            StatusRequest.model_validate(
                {
                    **_request_base(protocol_id("req_", seed + 15)),
                    "session_id": started.session_id,
                    "writer_id": started.writer_id,
                    "view": "compact",
                    "limit": "1",
                }
            )
        )
        readiness = status.closure_readiness
        assert DECLARED_OUTPUT_EMPTIED_GAP in cast(tuple[str, ...], readiness.agent_actionable)
        assert readiness.fact_lineage is not None
        status_fact = next(
            lineage_from_wire(x) for x in readiness.fact_lineage if x.code == fact.code
        )
        assert lineage_text(status_fact) == why
        assert why in render_closure_readiness_lines(readiness)

        # 3. The Stop-gate text names the token and says why.
        gate = closure_gate_from_readiness(
            readiness,
            frontier_sequence=str(status.head_frontier.sequence),
            frontier_digest=status.head_frontier.head_digest,
            observation_pending=False,
        )
        assert gate is not None and DECLARED_OUTPUT_EMPTIED_GAP in gate.items
        # The provenance sentence is the lowest-priority optional sentence (RC-5/RC-8): beside
        # other items it yields to the host bound, but the token always says why it fired - the
        # withdrawn-deliverable sentence names the rule and the obligation from the same lineage.
        assert why in gate.text or (f"rule {fact.rule}" in gate.text and obligation in gate.text)
        assert "Acknowledging or republishing the obligation does not clear this" in gate.text

        # 4. The receipt, in every format.
        frontier = status.head_frontier
        rendered: dict[str, Any] = {}
        for number, form in enumerate(("json", "markdown", "text")):
            receipt = await _receipt_912(
                app, started, frontier, seed + 20 + number, cast(Literal["json"], form)
            )
            rendered[form] = receipt
            frontier = receipt.result_frontier
        document = cast(dict[str, Any], rendered["json"].document)
        (gap,) = [x for x in document["gaps"] if x["code"] == DECLARED_OUTPUT_EMPTIED_GAP]
        assert why in gap["detail"]
        assert why in rendered["markdown"].human_text
        assert why in rendered["text"].human_text
    finally:
        register_command_identity_key(None)


# --- n7 RC3b (issue #1103): respond evidence_refs is a reference set -----------------------------


async def _finding_with_two_evidence(
    app: Application, *, seed: int
) -> tuple[StartInternalResult, CheckCommitResult, PublishWorkInternalResult, str, str]:
    """One finding plus two evidence records published after it (the n7 respond shape)."""

    started, checked, _obligation = await _bootstrap_finding(app, seed=seed)
    low, high = protocol_id("evd_", seed + 41), protocol_id("evd_", seed + 42)
    drafts: list[dict[str, JsonValue]] = [
        {
            "schema": {"name": "evidence_recorded", "version": "1.0.0"},
            "payload": {
                "evidence_id": evidence,
                "evidence_kind": "test_result",
                "strength": "metadata_only",
                "description": "12 passed",
                "observed_at": "2026-07-19T12:00:05.000Z",
            },
        }
        for evidence in (low, high)
    ]
    published = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 40)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "event_drafts": drafts,
            }
        )
    )
    assert isinstance(published, PublishWorkInternalResult)
    return started, checked, published, low, high


def _rejection_wire(
    started: StartInternalResult,
    checked: CheckCommitResult,
    published: PublishWorkInternalResult,
    request_id: str,
    evidence_refs: list[str],
) -> dict[str, JsonValue]:
    return {
        **_request_base(request_id),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(published.result_frontier),
        "finding_id": checked.findings[0].finding_id,
        "finding_frontier": _frontier(checked.result_frontier),
        "disposition": "rejected",
        "reason": "The finding names work outside this task.",
        "evidence_refs": cast(JsonValue, evidence_refs),
    }


async def _response_events(runtime: _WorkflowRuntime, session_id: str) -> tuple[Any, ...]:
    ledger, _objects = next(iter(runtime.resources.values()))
    return tuple(
        [
            row
            async for row in ledger.load_events(session_id)
            if row.schema.name == "response_recorded"
        ]
    )


async def test_unsorted_evidence_refs_are_accepted_and_recorded_sorted() -> None:
    """n7: 53 answers listing evidence out of order were refused with a reason-free error."""

    app, runtime, _ = _build_app(seed_offset=103)
    started, checked, published, low, high = await _finding_with_two_evidence(app, seed=10300)
    wire = _rejection_wire(
        started, checked, published, protocol_id("req_", 10350), [high, low, high]
    )
    request = RespondRequest.model_validate(wire)
    assert request.evidence_refs == (low, high)
    answered = await app.respond(request)
    assert answered.response.disposition == "rejected"
    assert tuple(item.reference_id for item in answered.response.evidence) == (low, high)
    (event,) = await _response_events(runtime, started.session_id)
    assert event.payload.evidence_refs == (low, high)
    assert event.evidence_refs == (low, high)


async def test_unsorted_and_sorted_answers_are_one_request() -> None:
    app, runtime, _ = _build_app(seed_offset=104)
    started, checked, published, low, high = await _finding_with_two_evidence(app, seed=10400)
    request_id = protocol_id("req_", 10450)
    first = await app.respond(
        RespondRequest.model_validate(
            _rejection_wire(started, checked, published, request_id, [low, high])
        )
    )
    # The same answer listed in another order, with a repeat, under the same request_id is the
    # same request: it replays the committed answer instead of conflicting or appending again.
    replayed = await app.respond(
        RespondRequest.model_validate(
            _rejection_wire(started, checked, published, request_id, [high, low, low])
        )
    )
    assert replayed.accepted_event == first.accepted_event
    assert replayed.result_frontier == first.result_frontier
    assert len(await _response_events(runtime, started.session_id)) == 1


@pytest.mark.parametrize(
    ("reason_code", "field", "details"),
    [
        (
            "unsorted_set_field",
            "evidence_refs",
            # The reason's own directive is kept; the pointer is the request field.
            {
                "continuation": "sorted_set_required",
                "field": "/evidence_refs",
                "reason_code": "unsorted_set_field",
            },
        ),
        (
            "response_fields_invalid",
            None,
            {
                "continuation": "input_correction_new_identity",
                "reason_code": "response_fields_invalid",
            },
        ),
        (
            # A field outside the frozen pointer table is never echoed.
            "set_member_not_ascii",
            "finding_frontier",
            {
                "continuation": "input_correction_new_identity",
                "reason_code": "set_member_not_ascii",
            },
        ),
    ],
)
async def test_a_payload_refusal_names_its_reason_and_field(
    monkeypatch: pytest.MonkeyPatch,
    reason_code: str,
    field: str | None,
    details: dict[str, str],
) -> None:
    import finishup.application.respond as respond_module
    from finishup.mcp.errors import tool_error_envelope
    from finishup.mcp.server import result_from_public_model
    from finishup.protocol.models import RespondResult

    app, runtime, _ = _build_app(seed_offset=105)
    started, checked, published, low, _high = await _finding_with_two_evidence(app, seed=10500)

    def refuse(*_args: object, **_kwargs: object) -> object:
        raise ProtocolValueError(reason_code, field=field)

    monkeypatch.setattr(respond_module, "ResponseRecordedPayload", refuse)
    with pytest.raises(PublicOperationError) as caught:
        await app.respond(
            RespondRequest.model_validate(
                _rejection_wire(started, checked, published, protocol_id("req_", 10550), [low])
            )
        )
    error = caught.value
    assert error.code is PublicErrorCode.INVALID_REQUEST
    assert error.retryable is False
    assert dict(error.safe_details or {}) == details
    assert error.message.startswith(
        "The response is invalid: safe_details.reason_code names the rule it breaks"
    )
    assert "Nothing was recorded." in error.message
    # Nothing was appended for the refused answer.
    assert await _response_events(runtime, started.session_id) == ()

    # Codex reads the structured body, Claude Code the text: both carry the reason (W6/#579).
    bound = error.bind_correlation_id("err_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
    envelope = tool_error_envelope(bound, request_id=protocol_id("req_", 10550))
    hint = respond_module._RESPONSE_PAYLOAD_HINTS.get(reason_code)  # pyright: ignore[reportPrivateUsage]
    if hint is not None:
        assert error.message.endswith(hint)
    for host in ("codex", "claude"):
        rendered = result_from_public_model(
            RespondResult.model_validate(envelope), host_profile=host
        )
        assert rendered.isError is True
        structured = cast(dict[str, Any], rendered.structuredContent)
        assert structured["error"]["safe_details"] == details
        assert structured["error"]["message"] == error.message
        text = cast(Any, rendered.content[0]).text
        pointer = details.get("field")
        expected = f"{reason_code} at {pointer}" if pointer is not None else reason_code
        assert f"Reason: {expected}" in text
        assert "The finding names work outside this task." not in text
        if reason_code == "response_fields_invalid":
            # The text summary never renders the message, so the field rule rides as a remedy.
            assert f"Remedy: {REASON_REMEDIES[reason_code]}" in text
    # Cursor's text channel is the canonical JSON copy of the body, message included.
    cursor = result_from_public_model(RespondResult.model_validate(envelope), host_profile="cursor")
    cursor_body = json.loads(cast(Any, cursor.content[0]).text)
    assert cursor_body["error"]["message"] == error.message
    assert cursor_body["error"]["safe_details"] == details


def _claude_text(error: PublicOperationError, request_id: str) -> str:
    from finishup.mcp.errors import tool_error_envelope
    from finishup.mcp.server import result_from_public_model
    from finishup.protocol.models import RespondResult

    bound = error.bind_correlation_id("err_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
    envelope = tool_error_envelope(bound, request_id=request_id)
    rendered = result_from_public_model(
        RespondResult.model_validate(envelope), host_profile="claude"
    )
    return cast(Any, rendered.content[0]).text


async def test_application_field_refusals_get_a_remedy_that_holds_for_them() -> None:
    """The ``response_fields_invalid`` remedy is keyed by the token alone (n7 RC3b, #1103).

    Claude Code reads only the bounded text, which never renders a message, so for the checks
    respond makes itself (an unrecorded reference, nothing to reopen) the remedy is the only
    guidance it gets. It has to state the rule each of them broke, never contradict it.
    """

    app, _runtime, _ = _build_app(seed_offset=109)
    started, checked, published, low, _high = await _finding_with_two_evidence(app, seed=10900)
    remedy = f"Remedy: {REASON_REMEDIES['response_fields_invalid']}"

    unknown = protocol_id("req_", 10950)
    with pytest.raises(PublicOperationError) as unrecorded:
        await app.respond(
            RespondRequest.model_validate(
                _rejection_wire(
                    started, checked, published, unknown, [low, protocol_id("evd_", 10999)]
                )
            )
        )
    assert unrecorded.value.message == "A response reference is invalid."
    text = _claude_text(unrecorded.value, unknown)
    assert "Reason: response_fields_invalid at /evidence_refs." in text
    assert remedy in text
    assert "evidence_refs ids must be recorded" in text

    reopen = protocol_id("req_", 10951)
    wire = _rejection_wire(started, checked, published, reopen, [low])
    wire["disposition"] = "reopened"
    with pytest.raises(PublicOperationError) as nothing:
        await app.respond(RespondRequest.model_validate(wire))
    assert (nothing.value.safe_details or {}).get("field") == "/disposition"
    text = _claude_text(nothing.value, reopen)
    assert "Reason: response_fields_invalid at /disposition." in text
    assert remedy in text
    # The answer carried a reason, so the remedy must name the state rule, not only the reason.
    assert "reopened only undoes acknowledged_not_done" in text


async def test_an_ai_finding_acknowledgement_refusal_remedy_names_its_rule() -> None:
    """Issue #976's refusal: the remedy must not imply plain acknowledged needs no reason."""

    seed = 11000
    app, _runtime, _ = _build_app(
        seed_offset=110,
        semantic="optional",
        semantic_evaluator=_question_evaluator(protocol_id("clm_", seed + 5)),
    )
    started, checked, _obligation = await _bootstrap_finding(
        app, seed=seed, mode="semantic_if_configured"
    )
    question = next(
        item for item in checked.findings if item.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED
    )
    request_id = protocol_id("req_", seed + 10)
    with pytest.raises(PublicOperationError) as refused:
        await app.respond(
            RespondRequest.model_validate(
                {
                    **_request_base(request_id),
                    "session_id": started.session_id,
                    "writer_id": started.writer_id,
                    "expected_frontier": _frontier(checked.result_frontier),
                    "finding_id": question.finding_id,
                    "finding_frontier": _frontier(checked.result_frontier),
                    "disposition": "acknowledged",
                }
            )
        )
    assert refused.value.message.startswith("Acknowledging an AI-powered review finding")
    text = _claude_text(refused.value, request_id)
    assert "Reason: response_fields_invalid at /reason." in text
    assert f"Remedy: {REASON_REMEDIES['response_fields_invalid']}" in text
    assert "acknowledged on an AI-powered finding need a reason" in text


def test_the_field_rule_remedy_names_every_disposition_the_payload_needs_a_reason_for() -> None:
    remedy = REASON_REMEDIES["response_fields_invalid"]
    needs_reason = remedy.split(" need a reason;", 1)[0]
    for disposition in (
        "acknowledged_not_done",
        "provenance_disputed",
        "rejected",
        "reopened",
        "self_verified",
        "waived",
        "acknowledged on an AI-powered finding",
    ):
        assert disposition in needs_reason
    for rule in (
        "self_verified: one after the finding",
        "go only with waived",
        "duplicate_of_finding_id only, and always, with duplicate_of",
    ):
        assert rule in remedy


async def test_an_unsorted_set_refusal_carries_its_corrective_hint() -> None:
    app, _runtime, _ = _build_app(seed_offset=106)
    started, checked, published, low, high = await _finding_with_two_evidence(app, seed=10600)
    # A request copied without validation reaches the domain unsorted: the refusal still says why.
    request = RespondRequest.model_validate(
        _rejection_wire(started, checked, published, protocol_id("req_", 10650), [low, high])
    ).model_copy(update={"evidence_refs": (high, low)})
    with pytest.raises(PublicOperationError) as caught:
        await app.respond(request)
    assert dict(caught.value.safe_details or {}) == {
        "continuation": "sorted_set_required",
        "field": "/evidence_refs",
        "reason_code": "unsorted_set_field",
    }
    assert caught.value.message.endswith(" List evidence_refs in ascending order.")


async def test_the_catch_all_keeps_its_message_and_names_the_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import finishup.application.respond as respond_module

    app, _runtime, _ = _build_app(seed_offset=107)
    started, checked, published, low, _high = await _finding_with_two_evidence(app, seed=10700)

    async def broken(*_args: object, **_kwargs: object) -> object:
        raise ProtocolValueError("stored_result_shape_invalid")

    # Shaping the result runs after the append, so this refusal may not claim nothing was recorded.
    monkeypatch.setattr(respond_module, "_public_result", broken)
    with pytest.raises(PublicOperationError) as caught:
        await app.respond(
            RespondRequest.model_validate(
                _rejection_wire(started, checked, published, protocol_id("req_", 10750), [low])
            )
        )
    assert caught.value.code is PublicErrorCode.INVALID_REQUEST
    assert caught.value.message == "The response request is invalid."
    assert (caught.value.safe_details or {}).get("reason_code") == "stored_result_shape_invalid"


async def test_the_receipt_catch_all_keeps_its_message_and_names_the_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import finishup.application.receipt as receipt_module

    app, _runtime, _ = _build_app(seed_offset=108)
    started, checked, _obligation = await _bootstrap_finding(app, seed=10800)

    def broken(*_args: object, **_kwargs: object) -> object:
        raise ProtocolValueError("stored_result_shape_invalid")

    # Shaping the result runs after the append, so the catch-all keeps its plain message and
    # names only the frozen reason token, never the exception text.
    monkeypatch.setattr(receipt_module, "_internal_result", broken)
    with pytest.raises(PublicOperationError) as caught:
        await app.receipt(
            ReceiptRequest.model_validate(
                _receipt_wire(
                    10850,
                    task_id=started.task_id,
                    session=started.session_id,
                    writer=started.writer_id,
                    frontier=checked.result_frontier,
                )
            )
        )
    assert caught.value.code is PublicErrorCode.INVALID_REQUEST
    assert caught.value.retryable is False
    assert caught.value.message == "The receipt request is invalid."
    # The reason's own continuation is derived from the token, as for every other refusal.
    assert dict(caught.value.safe_details or {}) == {
        "continuation": "lineage_integrity_review",
        "reason_code": "stored_result_shape_invalid",
    }


def _routine_note(summary: str, cited: str) -> ReviewerChallenge:
    return ReviewerChallenge(
        FindingKind.CODE_DEFECT,
        summary,
        (cited,),
        "The edit computes the footprint in world coordinates.",
        "The receptacle may never be rotated in practice.",
        "Transform the object origin into the receptacle frame; test a rotated receptacle.",
        "act",
        "No rotated-receptacle case is in the packet.",
    )


async def _routine_advisory_task(
    app: Application, *, seed: int
) -> tuple[StartInternalResult, CheckCommitResult, dict[str, str]]:
    """Start, publish an open obligation and an edit with its result, then run a routine check.

    No completion claim is recorded, so the review is routine and a ``code_defect`` stays an
    advisory note. The reviewer is the app's scripted evaluator; the fence is production's.
    """

    refs = {
        "obligation": protocol_id("obl_", seed + 1),
        "action_event": protocol_id("evt_", seed + 2),
        "action": protocol_id("act_", seed + 3),
        "result_event": protocol_id("evt_", seed + 4),
        "result": protocol_id("res_", seed + 5),
    }
    started = await app.start(start_request(seed, title="Advisory exercise", refs=True))
    published = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 6)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(started.frontier),
                "event_drafts": [
                    {
                        "event_id": protocol_id("evt_", seed + 7),
                        "schema": {"name": "obligation_published", "version": "1.0.0"},
                        "occurred_at": "2026-07-19T12:00:00.000Z",
                        "causal_parents": [],
                        "payload": {
                            "obligation_id": refs["obligation"],
                            "description": "Place objects inside rotated receptacles.",
                            "evidence_expectation": "A linked immutable result record.",
                            "status": "open",
                        },
                        "artifact_refs": [],
                        "evidence_refs": [],
                    },
                    {
                        "event_id": refs["action_event"],
                        "schema": {"name": "action_recorded", "version": "1.0.0"},
                        "occurred_at": "2026-07-19T12:00:01.000Z",
                        "causal_parents": [],
                        "payload": {
                            "action_id": refs["action"],
                            "action_kind": "edit",
                            "description": "Edit the placement geometry.",
                        },
                        "artifact_refs": [],
                        "evidence_refs": [],
                    },
                    {
                        "event_id": refs["result_event"],
                        "schema": {"name": "result_recorded", "version": "1.0.0"},
                        "occurred_at": "2026-07-19T12:00:02.000Z",
                        "causal_parents": [refs["action_event"]],
                        "payload": {
                            "result_id": refs["result"],
                            "action_id": refs["action"],
                            "outcome": "success",
                            "summary": "The placement geometry was edited.",
                        },
                        "artifact_refs": [],
                        "evidence_refs": [],
                    },
                ],
            }
        )
    )
    checked = await app.check(
        CheckRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 8)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(published.result_frontier),
                "mode": "semantic_required",
            }
        )
    )
    assert isinstance(checked, CheckCommitResult)
    return started, checked, refs


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
async def test_routine_notes_citing_a_result_and_an_action_reach_closing_with_the_review(
    backend: Literal["memory", "sqlite"],
) -> None:
    """#1162 review blocker: ``res_``/``act_`` citations are legal for the fence; the stored note
    keeps their resolved source events, and the review's other challenge is still committed."""

    from finishup.kernel.correctness_advisories import correctness_advisories

    seed = 216300

    def round_one(_frozen: FrozenCase) -> tuple[ReviewerChallenge, ...]:
        return (
            _routine_note("Geometry uses world AABBs.", protocol_id("res_", seed + 5)),
            _routine_note("Rotated receptacles are untested.", protocol_id("act_", seed + 3)),
            ReviewerChallenge(
                FindingKind.TASK_REQUIREMENT_UNMET,
                "Placement inside rotated receptacles is not done.",
                (protocol_id("obl_", seed + 1),),
                "The obligation is open and no result covers rotated receptacles.",
                "The work may be planned for later.",
                "Implement rotated-receptacle placement and record the result.",
                "act",
                "The packet has no rotated-receptacle result.",
            ),
        )

    app, runtime, _ = _build_app(
        semantic="required",
        ledger_backend=backend,
        semantic_evaluator=_scripted_reviewer([round_one]),
    )
    started, checked, refs = await _routine_advisory_task(app, seed=seed)
    # The review was admitted, not recorded as a rejected judgment.
    assert checked.semantic_status is SemanticStatus.SUCCEEDED
    assert [
        item.kind
        for item in checked.findings
        if item.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED
    ] == [FindingKind.TASK_REQUIREMENT_UNMET]
    ledger, _objects = runtime.resources[started.task_id]
    records = tuple([r async for r in ledger.load_events(started.session_id)])
    notes = correctness_advisories(records)
    assert [note.concern["subject_refs"] for note in notes] == [
        (refs["result_event"],),
        (refs["action_event"],),
    ]
    assert notes[0].check.schema.version == "1.6.0"
    receipt = await app.receipt(
        ReceiptRequest.model_validate(
            {
                **_receipt_wire(
                    request_seed=seed + 20,
                    task_id=started.task_id,
                    session=started.session_id,
                    writer=started.writer_id,
                    frontier=checked.result_frontier,
                ),
                "format": "text",
                "include": "summary",
            }
        )
    )
    assert "Earlier correctness advisories: 2; no recorded response: 2" in str(receipt.as_json())


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
async def test_history_never_shows_another_sessions_advisory_check(
    backend: Literal["memory", "sqlite"],
) -> None:
    """#1162 review: history stays session-scoped; the receipt keeps the task-wide count."""

    from finishup.protocol.models import StatusHistoryPageModel

    seed = 216400

    def round_one(_frozen: FrozenCase) -> tuple[ReviewerChallenge, ...]:
        return (_routine_note("Geometry uses world AABBs.", protocol_id("res_", seed + 5)),)

    app, _runtime, _ = _build_app(
        semantic="required",
        ledger_backend=backend,
        semantic_evaluator=_scripted_reviewer([round_one]),
    )
    started, _checked, _refs = await _routine_advisory_task(app, seed=seed)
    other = await app.start(start_request(seed + 30, title="Advisory exercise", refs=True))
    assert other.task_id == started.task_id and other.session_id != started.session_id

    async def history(session: str, writer: str, request_seed: int) -> StatusHistoryPageModel:
        result = await app.status(
            StatusRequest.model_validate(
                {
                    **_request_base(protocol_id("req_", request_seed)),
                    "session_id": session,
                    "writer_id": writer,
                    "view": "history",
                    "limit": "50",
                }
            )
        )
        assert isinstance(result.page, StatusHistoryPageModel)
        return result.page

    own = await history(started.session_id, started.writer_id, seed + 40)
    noted = [item for item in own.items if getattr(item, "correctness_advisories", None)]
    assert [item.schema_name for item in noted] == ["check_recorded"]
    assert "world AABBs" in json.dumps([item.model_dump(mode="json") for item in noted])
    foreign = await history(other.session_id, other.writer_id, seed + 41)
    assert all(item.schema_name != "check_recorded" for item in foreign.items)
    assert all(getattr(item, "correctness_advisories", None) is None for item in foreign.items)
    assert all(getattr(item, "review_input_manifest", None) is None for item in foreign.items)
    assert "world AABBs" not in json.dumps([item.model_dump(mode="json") for item in foreign.items])
    # The receipt is task-wide and still counts the note for the other session.
    receipt = await app.receipt(
        ReceiptRequest.model_validate(
            {
                **_receipt_wire(
                    request_seed=seed + 42,
                    task_id=other.task_id,
                    session=other.session_id,
                    writer=other.writer_id,
                    frontier=other.frontier,
                ),
                "format": "json",
                "include": "summary",
            }
        )
    )
    assert "Earlier correctness advisories: 1; no recorded response: 1" in str(receipt.as_json())


_ADVISORY_LABELS = {
    None: "no recorded response",
    "declined": "declined with reason",
    "addressed": "addressed (agent-reported, linked evidence)",
    # #1240 D3: checked, kept my choice.
    "kept_choice": "checked, kept my choice (agent-reported, with reason)",
}


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
@pytest.mark.parametrize("disposition", [None, "declined", "addressed", "kept_choice"])
async def test_correctness_advisory_survives_check_response_and_receipt(
    backend: Literal["memory", "sqlite"], disposition: str | None
) -> None:
    """TAMP-like: a note survives later clean review output; silence never reports repair.

    The note comes from a scripted reviewer through the production fence (no patched validator).
    """
    from finishup.kernel.correctness_advisories import correctness_advisories
    from finishup.protocol.models import StatusHistoryPageModel

    def round_one(_frozen: FrozenCase) -> tuple[ReviewerChallenge, ...]:
        return (
            _routine_note(
                "Geometry uses world AABBs instead of receptacle-frame footprints.",
                protocol_id("res_", 216205),
            ),
        )

    def clean_round(_frozen: FrozenCase) -> tuple[ReviewerChallenge, ...]:
        return ()

    app, runtime, _ = _build_app(
        semantic="required",
        ledger_backend=backend,
        semantic_evaluator=_scripted_reviewer([round_one, clean_round]),
    )

    def advisory_versions(_runtime: object) -> ReceiptVersionSlice:
        return replace(
            _versions(), schema_versions=(SchemaVersionEntry("receipts/receipt-document", "1.3.0"),)
        )

    app = replace(app, receipt_version_resolver=advisory_versions)
    started, checked, task_refs = await _routine_advisory_task(app, seed=216200)
    ledger, _objects = runtime.resources[started.task_id]
    records = tuple([r async for r in ledger.load_events(started.session_id)])
    notes = correctness_advisories(records)
    assert len(notes) == 1 and notes[0].response is None
    assert notes[0].concern["subject_refs"] == (task_refs["result_event"],)
    assert notes[0].check.schema.version == "1.6.0"
    assert notes[0].check.payload.semantic_provenance is not None  # type: ignore[union-attr]
    frontier = checked.result_frontier
    # A second check returns no such note. Its silence cannot answer the earlier note.
    later = await app.check(
        CheckRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 216210)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(frontier),
                "mode": "semantic_required",
            }
        )
    )
    assert isinstance(later, CheckCommitResult)
    frontier = later.result_frontier
    if disposition is not None:
        # The linked result is an assertion's evidence, not independent proof of a repair.
        refs: tuple[str, ...] = ()
        if disposition == "addressed":
            published = await app.publish_work(
                PublishWorkRequest.model_validate(
                    {
                        **_request_base(protocol_id("req_", 216211)),
                        "session_id": started.session_id,
                        "writer_id": started.writer_id,
                        "expected_frontier": _frontier(frontier),
                        "event_drafts": [
                            {
                                "event_id": protocol_id("evt_", 216212),
                                "schema": {"name": "action_recorded", "version": "1.0.0"},
                                "occurred_at": "2026-07-19T12:00:02.000Z",
                                "causal_parents": [],
                                "payload": {
                                    "action_id": protocol_id("act_", 216213),
                                    "action_kind": "review",
                                    "description": "Run the rotated-receptacle verification.",
                                },
                                "artifact_refs": [],
                                "evidence_refs": [],
                            },
                            {
                                "event_id": protocol_id("evt_", 216214),
                                "schema": {"name": "result_recorded", "version": "1.0.0"},
                                "occurred_at": "2026-07-19T12:00:03.000Z",
                                "causal_parents": [protocol_id("evt_", 216212)],
                                "payload": {
                                    "result_id": protocol_id("res_", 216215),
                                    "action_id": protocol_id("act_", 216213),
                                    "outcome": "success",
                                    "summary": "Local footprint test passed (agent-reported).",
                                },
                                "artifact_refs": [],
                                "evidence_refs": [],
                            },
                        ],
                    }
                )
            )
            frontier = published.result_frontier
            refs = (protocol_id("res_", 216215),)
        body = {
            **_request_base(protocol_id("req_", 216216)),
            "session_id": started.session_id,
            "writer_id": started.writer_id,
            "expected_frontier": _frontier(frontier),
            "finding_id": notes[0].advisory_id,
            "finding_frontier": _frontier(checked.result_frontier),
            "disposition": disposition,
            "reason": "Kept the existing geometry with its limitation."
            if disposition in {"declined", "kept_choice"}
            else "Changed to the local frame and checked the linked result.",
            "evidence_refs": refs,
        }
        answered = await app.respond(RespondRequest.model_validate(body))
        replayed = await app.respond(RespondRequest.model_validate(body))
        assert answered.result_frontier == replayed.result_frontier
        assert answered.response.disposition == disposition
        frontier = answered.result_frontier
    status = await app.status(
        StatusRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 216220)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "view": "history",
                "limit": "1",
                "filter": {"schema_name": "check_recorded"},
            }
        )
    )
    assert isinstance(status.page, StatusHistoryPageModel)
    row = status.page.items[0]
    advisory = getattr(row, "correctness_advisories")[0]
    assert advisory.disposition == (disposition or "no_recorded_response")
    assert "world AABBs" in str(advisory.summary)
    assert advisory.subject_refs == (task_refs["result_event"],)
    assert (advisory.response_event_id is None) is (disposition is None)
    assert getattr(row, "advisory_provenance") is not None
    from builders.status_wire import compact_status
    from finishup.cli.render import render_human_status
    from finishup.protocol.models import StatusSuccessModel

    history_text = render_human_status(
        StatusSuccessModel.model_validate(
            {
                **status.as_json(),
                "privacy_projection": cast(
                    StatusSuccessModel, compact_status().result.root
                ).privacy_projection.model_dump(mode="json"),
            }
        )
    )
    assert "world AABBs" in history_text and "AI-powered source:" in history_text
    assert _ADVISORY_LABELS[disposition] in history_text
    assert status.page.next_cursor is not None
    # Following the cursor keeps the same bound frontier and omits the older check's note.
    second = await app.status(
        StatusRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 216221)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "view": "history",
                "limit": "1",
                "filter": {"schema_name": "check_recorded"},
                "cursor": status.page.next_cursor,
            }
        )
    )
    assert second.subject_frontier == status.subject_frontier
    assert isinstance(second.page, StatusHistoryPageModel)
    assert getattr(second.page.items[0], "correctness_advisories", None) is None
    # Readiness names what is still open: the summary stays while the note has no recorded
    # response and leaves once it has one (the receipt below still lists the note).
    assert (status.closure_readiness.correctness_advisory_summary is None) is (
        disposition is not None
    )
    for offset, format_value in enumerate(("json", "markdown", "text")):
        receipt = await app.receipt(
            ReceiptRequest.model_validate(
                {
                    **_receipt_wire(
                        request_seed=216230 + offset,
                        task_id=started.task_id,
                        session=started.session_id,
                        writer=started.writer_id,
                        frontier=frontier,
                    ),
                    "format": format_value,
                    "include": "summary",
                }
            )
        )
        text = str(receipt.as_json())
        assert "Earlier correctness advisories: 1" in text
        assert "world AABBs" in text
        # History is session-scoped, so the receipt names the session that recorded the check.
        assert f"in session {started.session_id}" in text
        assert f"with session_id {started.session_id}" in text
        assert _ADVISORY_LABELS[disposition] in text

    if backend == "sqlite":
        cold = SqliteLedger(
            db=runtime.sqlite_connections[0],
            task_id=started.task_id,
            ownership_fence=ownership_fence(
                generation=runtime.owners[(started.session_id, started.writer_id)]
            ),
            clock=runtime.clock,
            ids=runtime.ids,
            objects=_objects,
        )
        cold_records = tuple([record async for record in cold.load_events(started.session_id)])
        retained = correctness_advisories(cold_records)
        assert len(retained) == 1
        assert retained[0].disposition == (disposition or "no recorded response")


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
async def test_an_advisory_response_needs_respond_and_evidence_recorded_after_the_note(
    backend: Literal["memory", "sqlite"],
) -> None:
    """#1162 review: publish_work cannot record an advisory response around respond's checks,
    and addressed cannot cite only work the reviewer already had when it raised the note."""

    from finishup.domain.correctness_advisories import ADVISORY_RESPONSE_STATEMENT
    from finishup.kernel.correctness_advisories import correctness_advisories

    def round_one(_frozen: FrozenCase) -> tuple[ReviewerChallenge, ...]:
        return (
            _routine_note(
                "Geometry uses world AABBs instead of receptacle-frame footprints.",
                protocol_id("res_", 216405),
            ),
        )

    app, runtime, _ = _build_app(
        semantic="required",
        ledger_backend=backend,
        semantic_evaluator=_scripted_reviewer([round_one]),
    )
    started, checked, task_refs = await _routine_advisory_task(app, seed=216400)
    ledger, _objects = runtime.resources[started.task_id]
    records = tuple([r async for r in ledger.load_events(started.session_id)])
    (note,) = correctness_advisories(records)
    with pytest.raises(PublicOperationError) as published:
        await app.publish_work(
            PublishWorkRequest.model_validate(
                {
                    **_request_base(protocol_id("req_", 216410)),
                    "session_id": started.session_id,
                    "writer_id": started.writer_id,
                    "expected_frontier": _frontier(checked.result_frontier),
                    "event_drafts": [
                        {
                            "event_id": protocol_id("evt_", 216411),
                            "schema": {"name": "decision_recorded", "version": "1.1.0"},
                            "occurred_at": "2026-07-19T12:00:05.000Z",
                            "causal_parents": [str(note.check.event_id)],
                            "payload": {
                                "statement": ADVISORY_RESPONSE_STATEMENT,
                                "rationale": "Published around respond.",
                                "authority": "harness:test",
                                "advisory_response": {
                                    "advisory_id": note.advisory_id,
                                    "disposition": "addressed",
                                    "evidence_refs": [task_refs["result"]],
                                },
                            },
                            "artifact_refs": [],
                            "evidence_refs": [task_refs["result"]],
                        }
                    ],
                }
            )
        )
    assert published.value.safe_details is not None
    assert published.value.safe_details["reason_code"] == "event_family_not_admitted"
    assert published.value.safe_details["field"] == "/event_drafts/0/payload/advisory_response"
    assert "only through respond" in str(published.value)
    with pytest.raises(PublicOperationError) as early:
        await app.respond(
            RespondRequest.model_validate(
                {
                    **_request_base(protocol_id("req_", 216412)),
                    "session_id": started.session_id,
                    "writer_id": started.writer_id,
                    "expected_frontier": _frontier(checked.result_frontier),
                    "finding_id": note.advisory_id,
                    "finding_frontier": _frontier(checked.result_frontier),
                    "disposition": "addressed",
                    "reason": "Cites only the edit the reviewer already read.",
                    # The edit's own result, recorded before the check that raised the note.
                    "evidence_refs": [task_refs["result"]],
                }
            )
        )
    assert early.value.safe_details is not None
    assert early.value.safe_details["reason_code"] == "response_fields_invalid"
    assert early.value.safe_details["field"] == "/evidence_refs"
    # The history row's only frontier is the check's subject frontier, which precedes the check
    # record (the #917 trap): the refusal names the frontier that works, with a reason code.
    subject = cast(CheckRecordedPayload, note.check.payload).subject_frontier
    with pytest.raises(PublicOperationError) as before_check:
        await app.respond(
            RespondRequest.model_validate(
                {
                    **_request_base(protocol_id("req_", 216413)),
                    "session_id": started.session_id,
                    "writer_id": started.writer_id,
                    "expected_frontier": _frontier(checked.result_frontier),
                    "finding_id": note.advisory_id,
                    "finding_frontier": {
                        "sequence": str(subject.sequence),
                        "head_digest": subject.head_digest,
                    },
                    "disposition": "declined",
                    "reason": "Kept the existing geometry.",
                }
            )
        )
    assert before_check.value.safe_details is not None
    assert before_check.value.safe_details["reason_code"] == "invalid_frontier"
    assert before_check.value.safe_details["field"] == "/finding_frontier"
    message = str(before_check.value)
    assert f"sequence {note.check.ledger.ingestion_sequence}" in message
    assert "current status frontier" in message and "advisory_subject_frontier" in message
    after = tuple([r async for r in ledger.load_events(started.session_id)])
    assert len(after) == len(records)
    assert correctness_advisories(after)[0].response is None


# --- #1162 tracked reviewer advice ----------------------------------------------------------------


def _tracked_reviewer(
    rounds: list[Callable[[FrozenCase], SemanticJudgment]],
    text_by_ref: Mapping[str, tuple[str, ...]],
) -> Callable[..., Awaitable[object]]:
    """Answer each check with the next scripted whole judgment, over a provider-bound text index."""

    async def evaluate(
        frozen: object,
        findings: object,
        runtime: object | None = None,
        lineage_evaluation: object | None = None,
    ) -> object:
        succeeded = cast(FinalSemanticEvaluation, await _semantic_succeeds(frozen, findings))
        return replace(
            succeeded,
            judgment=rounds.pop(0)(cast(FrozenCase, frozen)),
            provider_input_text_by_ref=text_by_ref,
        )

    return evaluate


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
async def test_tracked_reviewer_advice_is_answered_once_and_not_raised_again(
    backend: Literal["memory", "sqlite"],
) -> None:
    """#1162 tracked advice end to end, through the production fence, respond and receipt.

    A verified row marked not_supported that cites the obligation gets an advisory identity on
    the check's structured result and text; a not_assessable row citing only an event stays plain.
    Readiness counts it, the receipt lists it unanswered, ``respond declined`` with a reason
    closes it and the receipt shows the reason, and a later review that repeats it with no newer
    material folds onto the same identity instead of raising it again.
    """

    from finishup.application.check import check_internal_json
    from finishup.kernel.correctness_advisories import correctness_advisories
    from finishup.mcp.summaries import render_check_reviewer_output

    seed = 216600
    obligation = protocol_id("obl_", seed + 1)
    action_event = protocol_id("evt_", seed + 2)
    statement = "Place objects inside rotated receptacles"

    def not_supported(_frozen: FrozenCase) -> SemanticJudgment:
        return SemanticJudgment(
            "no_material_discrepancy",
            (),
            review_summary="Placement traced for axis-aligned receptacles only.",
            verified=(
                VerifiedReviewItem(
                    "Rotated receptacles are handled", "not_supported", (obligation,), statement
                ),
                VerifiedReviewItem("The edit is complete", "not_assessable", (action_event,)),
            ),
        )

    new_result = protocol_id("res_", seed + 53)

    def with_new_material(_frozen: FrozenCase) -> SemanticJudgment:
        return SemanticJudgment(
            "no_material_discrepancy",
            (),
            verified=(
                VerifiedReviewItem(
                    "Rotated receptacles are handled",
                    "not_supported",
                    (new_result, obligation),
                    statement,
                ),
            ),
        )

    app, runtime, _ = _build_app(
        semantic="required",
        ledger_backend=backend,
        semantic_evaluator=_tracked_reviewer(
            [not_supported, not_supported, with_new_material],
            {
                obligation: (statement + ".",),
                action_event: ("Edit the placement geometry.",),
                new_result: ("Rotated placement probe failed.",),
            },
        ),
    )
    started, checked, _refs = await _routine_advisory_task(app, seed=seed)
    assert checked.semantic_status is SemanticStatus.SUCCEEDED
    ledger, _objects = runtime.resources[started.task_id]
    records = tuple([r async for r in ledger.load_events(started.session_id)])
    notes = correctness_advisories(records)
    assert [note.concern.get("origin") for note in notes] == ["verified_not_supported"]
    advisory_id = notes[0].advisory_id
    # The check's structured result carries the identity, its origin and subjects.
    wire = check_internal_json(checked)
    assert wire["correctness_advisories"] == (
        {
            "advisory_id": advisory_id,
            "origin": "verified_not_supported",
            "subject_refs": (obligation,),
            "summary": "Rotated receptacles are handled",
        },
    )
    text = render_check_reviewer_output(wire)
    assert "Tracked reviewer advice" in text
    assert f"- {advisory_id} (reviewer row not_supported; {obligation})" in text
    # A lost check response is recovered with its advisory identities (PR #1214 review).
    operation = await app.status(
        StatusRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 15)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "view": "operation",
                "filter": {"operation_request_id": checked.request_id},
                "limit": "100",
            }
        )
    )
    assert type(operation.page) is StatusOperationPageModel
    outcome = operation.page.check_outcome
    assert outcome is not None
    assert [row.model_dump(mode="json") for row in outcome.correctness_advisories] == [
        {
            "advisory_id": advisory_id,
            "origin": "verified_not_supported",
            "subject_refs": [obligation],
        }
    ]
    readiness = cast(Mapping[str, Any], checked.closure_readiness)
    assert readiness["correctness_advisory_counts"] == {
        "total": "1",
        "no_recorded_response": "1",
        "withheld_may_answer": "0",
    }
    assert advisory_id in readiness["correctness_advisory_summary"]
    # #1139: the counted ledger line, early on the result and the same as readiness's copy.
    line = cast(str, wire["agent_status_line"])
    assert line == readiness["evidence_basis_summary"]
    assert line.startswith("Ledger (records, not correctness): ")
    assert "advice unanswered: 1" in line and "Rotated" not in line
    for view, detail in (("compact", "brief"), ("findings", "brief"), ("compact", "full")):
        status = await app.status(
            StatusRequest.model_validate(
                {
                    **_request_base(protocol_id("req_", seed + 10 + len(view) + len(detail))),
                    "session_id": started.session_id,
                    "writer_id": started.writer_id,
                    "view": view,
                    "detail": detail,
                    "at_frontier": str(checked.result_frontier.sequence),
                }
            )
        )
        body = status.as_json()
        assert body["agent_status_line"] == line
        assert list(body).index("agent_status_line") < list(body).index("page")

    async def receipt_text(
        request_seed: int, frontier: Frontier | FrontierModel
    ) -> tuple[str, Frontier]:
        receipt = await app.receipt(
            ReceiptRequest.model_validate(
                {
                    **_receipt_wire(
                        request_seed=request_seed,
                        task_id=started.task_id,
                        session=started.session_id,
                        writer=started.writer_id,
                        frontier=frontier,
                    ),
                    "format": "text",
                    "include": "summary",
                }
            )
        )
        return str(receipt.as_json()), receipt.result_frontier

    unanswered, head = await receipt_text(seed + 20, checked.result_frontier)
    assert "Earlier correctness advisories: 1; no recorded response: 1" in unanswered
    assert f"Correctness advisory {advisory_id} (reviewer row not_supported): no recorded" in (
        unanswered
    )
    answered = await app.respond(
        RespondRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 30)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(head),
                "finding_id": advisory_id,
                "finding_frontier": _frontier(checked.result_frontier),
                "disposition": "declined",
                "reason": "Rotation is outside the task's stated receptacle set.",
                "evidence_refs": [],
            }
        )
    )
    closed, head = await receipt_text(seed + 31, answered.result_frontier)
    assert "Earlier correctness advisories: 1; no recorded response: 0" in closed
    assert "declined with reason" in closed
    assert "Rotation is outside the task's stated receptacle set." in closed
    # A later review repeats the row with no newer material: folded, never a second identity.
    later = await app.check(
        CheckRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 40)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(head),
                "mode": "semantic_required",
            }
        )
    )
    assert isinstance(later, CheckCommitResult)
    assert later.correctness_advisories == ()
    assert f"not raised again: {advisory_id}." in str(later.review_summary)
    after = correctness_advisories(tuple([r async for r in ledger.load_events(started.session_id)]))
    assert [note.advisory_id for note in after] == [advisory_id]
    assert after[0].disposition == "declined"
    later_readiness = cast(Mapping[str, Any], later.closure_readiness)
    assert later_readiness["correctness_advisory_counts"]["no_recorded_response"] == "0"
    assert "correctness_advisory_summary" not in later_readiness
    assert "advice unanswered" not in later_readiness["evidence_basis_summary"]
    # New concern material (a result linked to the obligation, recorded after the answer) that
    # the next review cites makes the repeat new advice with its own identity.
    published = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 50)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(later.result_frontier),
                "event_drafts": [
                    {
                        "event_id": protocol_id("evt_", seed + 51),
                        "schema": {"name": "action_recorded", "version": "1.0.0"},
                        "occurred_at": "2026-07-19T12:00:05.000Z",
                        "causal_parents": [],
                        "payload": {
                            "action_id": protocol_id("act_", seed + 52),
                            "action_kind": "edit",
                            "description": "Probe rotated placement.",
                            "obligation_refs": [obligation],
                        },
                        "artifact_refs": [],
                        "evidence_refs": [],
                    },
                    {
                        "event_id": protocol_id("evt_", seed + 54),
                        "schema": {"name": "result_recorded", "version": "1.0.0"},
                        "occurred_at": "2026-07-19T12:00:06.000Z",
                        "causal_parents": [protocol_id("evt_", seed + 51)],
                        "payload": {
                            "result_id": new_result,
                            "action_id": protocol_id("act_", seed + 52),
                            "outcome": "failure",
                            "summary": "Rotated placement probe failed.",
                        },
                        "artifact_refs": [],
                        "evidence_refs": [],
                    },
                ],
            }
        )
    )
    reopened = await app.check(
        CheckRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 60)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(published.result_frontier),
                "mode": "semantic_required",
            }
        )
    )
    assert isinstance(reopened, CheckCommitResult)
    assert [row["origin"] for row in reopened.correctness_advisories] == ["verified_not_supported"]
    assert reopened.correctness_advisories[0]["advisory_id"] != advisory_id


async def test_a_self_verified_rerun_question_gets_the_receipt_status_predicted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """D8 (#1243), the TB4 session-window-debug reproducer, end to end.

    A test run, an edit, and a check that asks the rerun question (``ledger_stale_or_incomplete``),
    which the agent answers ``self_verified`` with a reason and evidence. Status predicted clean
    and both receipt calls failed ``invalid_receipt_conclusion``. The answered process note now
    neither caps nor refuses the receipt, and status and the receipt in every format read one
    conclusion.

    In the run a later check could not prove the question gone, which admitted the answer. These
    synthetic hook runs carry no command identity, so a rerun here never retires the question;
    the test admits the answer at the eligibility predicate alone (its rules are locked in
    ``tests/unit/kernel/test_self_verification.py``) and drives everything after it for real.
    """

    from finishup.application import respond as respond_module
    from integration.application import test_tb4n3_own_calls_cross_surface as observed

    original = _versions
    monkeypatch.setattr(
        __import__(__name__, fromlist=["_versions"]),
        "_versions",
        lambda: replace(
            original(),
            schema_versions=(SchemaVersionEntry("receipts/receipt-document", "1.3.0"),),
        ),
    )
    app, runtime, _ = _build_app(seed_offset=83, semantic="required")
    started = await app.start(start_request(5900, title="self-verified rerun question"))
    appended = await observed._append_observed(  # pyright: ignore[reportPrivateUsage]
        app,
        runtime,
        started,
        (
            observed._action(5920, ActionKind.COMMAND, "Bash", "test"),  # pyright: ignore[reportPrivateUsage]
            observed._result(5921, 5920),  # pyright: ignore[reportPrivateUsage]
            observed._action(5922, ActionKind.EDIT, "apply_patch", "compound"),  # pyright: ignore[reportPrivateUsage]
            observed._result(5923, 5922),  # pyright: ignore[reportPrivateUsage]
        ),
        seed=5930,
        expected_frontier=int(started.frontier.sequence),
    )
    checked = await app.check(
        CheckRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 5940)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(appended.result_frontier),
                "mode": "semantic_if_configured",
                "max_findings": "5",
            }
        )
    )
    assert type(checked) is CheckCommitResult
    question = next(
        item
        for item in checked.findings
        if item.kind is FindingKind.LEDGER_STALE_OR_INCOMPLETE
        and item.summary == "Is a verification rerun needed after the recorded changes?"
    )
    eligible = respond_module.self_verification_refusal

    def admitted(projection: Any, finding: Any, records: Any) -> str | None:
        return None if finding == question.finding_id else eligible(projection, finding, records)

    monkeypatch.setattr(respond_module, "self_verification_refusal", admitted)
    # The agent's own verification, recorded after the question.
    rerun = await observed._append_observed(  # pyright: ignore[reportPrivateUsage]
        app,
        runtime,
        started,
        (
            observed._action(5924, ActionKind.COMMAND, "Bash", "test"),  # pyright: ignore[reportPrivateUsage]
            observed._result(5925, 5924),  # pyright: ignore[reportPrivateUsage]
        ),
        seed=5935,
        expected_frontier=int(checked.result_frontier.sequence),
    )
    answered = await app.respond(
        RespondRequest.model_validate(
            {
                **_request_base(protocol_id("req_", 5950)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(rerun.result_frontier),
                "finding_id": question.finding_id,
                "finding_frontier": _frontier(checked.result_frontier),
                "disposition": "self_verified",
                "reason": "I reran the tests after the edit by hand; they still pass.",
                "evidence_refs": (protocol_id("res_", 5925),),
            }
        )
    )
    assert answered.response.disposition == "self_verified"
    readiness = await _compact_readiness(app, started, 5960)
    assert readiness.predicted_receipt is not None
    assert "finding_self_verified" not in (readiness.standing_limitations or ())
    for offset, fmt in enumerate(("json", "markdown", "text")):
        receipt = await app.receipt(
            ReceiptRequest.model_validate(
                {
                    **_receipt_wire(
                        5970 + offset,
                        task_id=started.task_id,
                        session=started.session_id,
                        writer=started.writer_id,
                        frontier=answered.result_frontier,
                    ),
                    "format": fmt,
                }
            )
        )
        assert receipt.conclusion == readiness.predicted_receipt.conclusion, fmt
        if receipt.document is not None:
            listed = cast(dict[str, Any], receipt.document).get("self_verified_finding_ids", [])
            assert question.finding_id not in listed
