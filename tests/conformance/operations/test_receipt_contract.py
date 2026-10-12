"""Public receipt contract: canonical document/compact parity, wording weakness, reviewed
fixture byte-matching, the profile/include matrix, and the shared availability snapshot.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest

from builders.ledger_adapters import ownership_fence
from builders.start_application import (
    MemoryStartRuntime,
    protocol_id,
    start_composition,
    start_request,
)
from yoetz.application.egress import PrivacyCoordinator
from yoetz.application.receipt import ReceiptInternalResult
from yoetz.application.service import (
    Application,
    ClientProjectionContext,
    ControlProjectionBinding,
    ProjectionRenderMode,
    VerificationPolicy,
)
from yoetz.application.start import StartInternalResult
from yoetz.domain.events import ReceiptRecordedPayload, RuntimeProfile
from yoetz.domain.privacy import (
    AuthorizationScope,
    AuthorizationScopeKind,
    CandidateContext,
    ConsentSource,
    DataCategory,
    LocalDisclosureApproved,
    LocalDisclosureBlocked,
    LocalDisclosureOmission,
    LocalDisclosureReceipt,
    PrivacyOutcome,
    ReceiptCounts,
    ReceiptPolicyBinding,
    ReceiptSecretScan,
    ReceiptTransformations,
)
from yoetz.domain.receipts import (
    PolicyVersionEntry,
    ReceiptConclusion,
    ReceiptVersionSlice,
    SchemaVersionEntry,
    receipt_document_from_json,
    receipt_document_to_json,
    render_receipt_compact,
)
from yoetz.domain.values import Frontier, session_id
from yoetz.ports.control import ControlClientKind, ControlError, ControlMethod
from yoetz.ports.diagnostics import RuntimeCapability
from yoetz.ports.importer import ImporterPort, ImportStatusSnapshot
from yoetz.ports.ledger import CheckCommitResult
from yoetz.ports.publish_response_catalog import PublishResponseCatalogPort
from yoetz.ports.runtime import BundleRuntimePort, RouteCommand, TaskRuntime
from yoetz.protocol.canonical import JsonValue, canonical_digest, canonical_encode
from yoetz.protocol.coverage import coverage_to_json
from yoetz.protocol.errors import PublicErrorCode, PublicOperationError
from yoetz.protocol.models import (
    CheckRequest,
    FrontierModel,
    PublishWorkRequest,
    ReceiptRedactionProfile,
    ReceiptRequest,
    ReceiptResultModel,
    RespondRequest,
    StatusFindingsPageModel,
    StatusRequest,
)

pytestmark = pytest.mark.anyio

_DIGEST = "sha256:" + "7" * 64
_WORKSPACE = "hmac-sha256:" + "8" * 64
_POLICY_PACKS = ("research-evidence/0.2.0", "work-integrity/0.3.0")
_FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "receipts"


class _IdleImporter:
    async def status(self, session: str) -> ImportStatusSnapshot:
        return ImportStatusSnapshot(session_id(session), 0, 0, (), ())


class _WorkflowRuntime(MemoryStartRuntime):
    """Extend the START memory composition with ready writer routing (duplicated from
    ``tests/integration/application/test_respond_status_receipt.py`` rather than imported,
    since test modules are not a shared library)."""

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
    """Approve every candidate with a fresh durable receipt, matching the sibling harness."""

    def __init__(self) -> None:
        self.candidates: list[CandidateContext] = []

    async def prepare_local_disclosure(
        self, candidate: CandidateContext
    ) -> LocalDisclosureApproved:
        self.candidates.append(candidate)
        sink = candidate.local_sink
        assert sink is not None
        proposal_id = protocol_id("ppr_", 1900 + len(self.candidates))
        policy = ReceiptPolicyBinding(
            protocol_id("pvy_", 1950 + len(self.candidates)), 1, _DIGEST, _DIGEST
        )
        receipt = LocalDisclosureReceipt(
            "1.0.0",
            protocol_id("egr_", 1960 + len(self.candidates)),
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


class _BlockingDocumentProjectionSpy:
    """Approve nothing under ``/document`` so JSON receipt projection must fail closed."""

    def __init__(self) -> None:
        self.candidates: list[CandidateContext] = []

    async def prepare_local_disclosure(self, candidate: CandidateContext) -> LocalDisclosureBlocked:
        self.candidates.append(candidate)
        sink = candidate.local_sink
        assert sink is not None
        omissions = tuple(
            sorted(
                (
                    LocalDisclosureOmission(
                        item.origin_ref,
                        item.category,
                        "local_disclosure_not_authorized",
                    )
                    for item in candidate.items
                    if item.origin_ref == "/document" or item.origin_ref.startswith("/document/")
                ),
                key=lambda item: item.json_pointer.encode(),
            )
        )
        assert omissions, "seeded JSON receipt must expose at least one document content leaf"
        proposal_id = protocol_id("ppr_", 1900 + len(self.candidates))
        policy = ReceiptPolicyBinding(
            protocol_id("pvy_", 1950 + len(self.candidates)), 1, _DIGEST, _DIGEST
        )
        receipt = LocalDisclosureReceipt(
            "1.0.0",
            protocol_id("egr_", 1960 + len(self.candidates)),
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
            (DataCategory.FINDING_SUMMARY,),
            ReceiptCounts(0, 0, 0, 0, 0, 0, 0),
            ReceiptTransformations(0, 0, 0),
            ReceiptSecretScan("1.0.0", _DIGEST, 0, True),
            None,
            1,
        )
        return LocalDisclosureBlocked(
            proposal_id,
            candidate.request_id,
            sink,
            candidate.purpose,
            candidate.scope,
            _DIGEST,
            _WORKSPACE,
            omissions,
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
        # The current application writer emits the additive 1.3.0 artifact, whose inner
        # ``schema_version`` remains 1.0.0.  Golden documents above still exercise legacy
        # 1.0/1.1 artifact decoding separately.
        schema_versions=(SchemaVersionEntry("receipts/receipt-document", "1.3.0"),),
        resource_manifest_digest=_DIGEST,
    )


def _scope(_binding: object, source: Mapping[str, JsonValue]) -> AuthorizationScope:
    return AuthorizationScope(
        AuthorizationScopeKind.TASK,
        protocol_id("ins_", 1999),
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
    *,
    seed_offset: int = 0,
    projection: _ProjectionSpy | _BlockingDocumentProjectionSpy | None = None,
) -> tuple[Application, _WorkflowRuntime, _ProjectionSpy | _BlockingDocumentProjectionSpy]:
    start_app, start_runtime, clock, catalog = start_composition()
    projection = _ProjectionSpy() if projection is None else projection
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
        status_cursor_key=(b"receipt-contract-cursor-key-" + str(seed_offset).encode() * 4)[:32],
        waiver_policy_digest=_DIGEST,
        semantic_evaluator=_semantic_disabled,
        disclosure_scope_for=_scope,
        receipt_version_resolver=lambda _: _versions(),
        waiver_authorizer=lambda _: False,
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

    started = await app.start(start_request(seed, title="Receipt contract exercise"))
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
                    "description": "Publish a result for the receipt contract exercise.",
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


async def _receipt(app: Application, wire: dict[str, JsonValue]) -> ReceiptInternalResult:
    return await app.receipt(ReceiptRequest.model_validate(wire))


async def test_receipt_request_result_parity() -> None:
    """The same receipt result, projected for CLI and MCP-bridge surfaces, carries the same
    public content everywhere; only the trusted per-surface disclosure sink differs."""

    app, _runtime, projection = _build_app(seed_offset=1)
    started, checked, _obligation = await _bootstrap_finding(app, seed=100)
    receipt_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 110)),
        "task_id": started.task_id,
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(checked.result_frontier),
        "format": "json",
        "include": "standard",
        "redaction_profile": "full_local",
    }
    receipt = await _receipt(app, receipt_wire)
    facts = await app.projection_binding_facts(ControlMethod.RECEIPT, receipt_wire, receipt)

    cli_context = ClientProjectionContext(
        ControlClientKind.CLI, ProjectionRenderMode.HUMAN_READABLE, True
    )
    mcp_context = ClientProjectionContext(
        ControlClientKind.MCP_BRIDGE, ProjectionRenderMode.MACHINE_READABLE, False
    )
    cli_binding = ControlProjectionBinding(
        protocol_id("rpc_", 111),
        ControlMethod.RECEIPT,
        protocol_id("svc_", 112),
        1,
        facts.original_request_id,
        facts.route_identity_digest,
        canonical_encode(
            {
                "rpc_id": protocol_id("rpc_", 111),
                "method": "receipt",
                "service_instance_id": protocol_id("svc_", 112),
                "service_generation": "1",
            }
        ),
    )
    mcp_binding = ControlProjectionBinding(
        protocol_id("rpc_", 113),
        ControlMethod.RECEIPT,
        protocol_id("svc_", 114),
        1,
        facts.original_request_id,
        facts.route_identity_digest,
        canonical_encode(
            {
                "rpc_id": protocol_id("rpc_", 113),
                "method": "receipt",
                "service_instance_id": protocol_id("svc_", 114),
                "service_generation": "1",
            }
        ),
    )
    cli_projected = await app.project_result_for_client(cli_context, cli_binding, receipt)
    mcp_projected = await app.project_result_for_client(mcp_context, mcp_binding, receipt)
    assert isinstance(cli_projected, ReceiptResultModel)
    assert isinstance(mcp_projected, ReceiptResultModel)
    assert cli_projected.root.ok is True
    assert mcp_projected.root.ok is True

    cli_body = cli_projected.root.model_dump(mode="json", exclude={"privacy_projection"})
    mcp_body = mcp_projected.root.model_dump(mode="json", exclude={"privacy_projection"})
    assert cli_body == mcp_body
    assert cli_projected.root.receipt_id == receipt.receipt_id
    assert cli_projected.root.privacy_projection.sink == "local_human_view"
    assert mcp_projected.root.privacy_projection.sink == "agent_context"
    assert mcp_projected.root.privacy_projection.omitted_pointers == ()
    assert mcp_projected.root.document is not None
    assert len(projection.candidates) == 2


async def test_json_receipt_projection_fails_closed_when_document_leaves_blocked() -> None:
    """Digest-bound JSON receipts must not emit partly rewritten documents under omission."""

    app, _runtime, projection = _build_app(
        seed_offset=11, projection=_BlockingDocumentProjectionSpy()
    )
    started, checked, _obligation = await _bootstrap_finding(app, seed=1100)
    receipt_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 1110)),
        "task_id": started.task_id,
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(checked.result_frontier),
        "format": "json",
        "include": "standard",
        "redaction_profile": "full_local",
    }
    receipt = await _receipt(app, receipt_wire)
    facts = await app.projection_binding_facts(ControlMethod.RECEIPT, receipt_wire, receipt)
    binding = ControlProjectionBinding(
        protocol_id("rpc_", 1111),
        ControlMethod.RECEIPT,
        protocol_id("svc_", 1112),
        1,
        facts.original_request_id,
        facts.route_identity_digest,
        canonical_encode(
            {
                "rpc_id": protocol_id("rpc_", 1111),
                "method": "receipt",
                "service_instance_id": protocol_id("svc_", 1112),
                "service_generation": "1",
            }
        ),
    )
    with pytest.raises(ControlError, match="privacy_projection_blocked"):
        await app.project_result_for_client(
            ClientProjectionContext(
                ControlClientKind.MCP_BRIDGE, ProjectionRenderMode.MACHINE_READABLE, False
            ),
            binding,
            receipt,
        )
    assert len(projection.candidates) == 1


async def test_frontier_and_own_event_exclusion_parity() -> None:
    """A receipt's own ``receipt_recorded`` event advances the result frontier by exactly one
    step past the subject frontier, and is never itself part of the subject it describes."""

    app, _runtime, _projection = _build_app(seed_offset=2)
    started, checked, _obligation = await _bootstrap_finding(app, seed=200)
    receipt_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 210)),
        "task_id": started.task_id,
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(checked.result_frontier),
        "format": "json",
        "include": "standard",
        "redaction_profile": "full_local",
    }
    receipt = await _receipt(app, receipt_wire)

    assert receipt.subject_frontier == checked.result_frontier
    assert receipt.result_frontier.sequence == checked.result_frontier.sequence + 1
    assert receipt.result_frontier != receipt.subject_frontier

    # An exact idempotent replay of the same logical request reproduces the same subject
    # frontier and receipt identity: the receipt's own event never contaminates its own subject.
    replayed = await _receipt(app, receipt_wire)
    assert replayed.receipt_id == receipt.receipt_id
    assert replayed.receipt_digest == receipt.receipt_digest
    assert replayed.subject_frontier == receipt.subject_frontier
    assert replayed.result_frontier == receipt.result_frontier

    # A later receipt built after the first one's own event is appended still reports the
    # unchanged case truth at its own new (later) subject frontier, not retroactively including
    # the prior receipt event as case material.
    later_wire: dict[str, JsonValue] = {
        **receipt_wire,
        "request_id": protocol_id("req_", 211),
        "expected_frontier": _frontier(receipt.result_frontier),
    }
    later = await _receipt(app, later_wire)
    assert later.subject_frontier == receipt.result_frontier
    assert later.conclusion == receipt.conclusion
    assert later.suppressed_finding_count == receipt.suppressed_finding_count


async def test_receipt_wording_is_weaker_than_document() -> None:
    """Markdown/text wording never claims more than the canonical JSON document."""

    app, _runtime, _projection = _build_app(seed_offset=3)
    started, checked, _obligation = await _bootstrap_finding(app, seed=300)
    json_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 310)),
        "task_id": started.task_id,
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(checked.result_frontier),
        "format": "json",
        "include": "full",
        "redaction_profile": "full_local",
    }
    json_receipt = await _receipt(app, json_wire)
    assert json_receipt.conclusion == "unresolved_findings_remain"
    assert json_receipt.document is not None

    text_wire: dict[str, JsonValue] = {
        **json_wire,
        "request_id": protocol_id("req_", 311),
        "expected_frontier": _frontier(json_receipt.result_frontier),
        "format": "markdown",
    }
    text_receipt = await _receipt(app, text_wire)
    assert text_receipt.document is None
    assert text_receipt.human_text is not None
    assert text_receipt.conclusion == json_receipt.conclusion

    forbidden = ("fully verified", "all work is complete", "proof of correctness", "passed")
    lowered = text_receipt.human_text.lower()
    for phrase in forbidden:
        assert phrase not in lowered
    # The wording never claims a stronger conclusion than the canonical document: an
    # ``unresolved_findings_remain`` receipt must say so, not "clear" or "resolved".
    assert "unresolved" in lowered


def _fixture_variants() -> tuple[tuple[str, str, dict[str, Any], str, str], ...]:
    result: list[tuple[str, str, dict[str, Any], str, str]] = []
    for path in sorted(_FIXTURES.glob("*.case.json")):
        case = cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))
        variants = cast(dict[str, dict[str, Any]], case["expected"]["variants"])
        for name, expected in sorted(variants.items()):
            if "receipt_document" not in expected:
                continue
            result.append(
                (
                    path.name,
                    name,
                    cast(dict[str, Any], expected["receipt_document"]),
                    cast(str, expected["compact_markdown"]),
                    cast(str, expected["canonical_receipt_digest"]),
                )
            )
    return tuple(result)


_VARIANTS = _fixture_variants()


def _variant(file_name: str, variant_name: str) -> dict[str, Any]:
    from copy import deepcopy

    for candidate_file, candidate_name, document, _, _ in _VARIANTS:
        if candidate_file == file_name and candidate_name == variant_name:
            return deepcopy(document)
    raise AssertionError(f"unknown fixture variant: {file_name}/{variant_name}")


@pytest.mark.parametrize(
    ("file_name", "variant_name", "wire", "expected_compact", "expected_digest"),
    _VARIANTS,
    ids=[f"{file_name}:{variant_name}" for file_name, variant_name, *_ in _VARIANTS],
)
def test_reviewed_receipt_vectors_match_exact_document_and_compact_bytes(
    file_name: str,
    variant_name: str,
    wire: dict[str, Any],
    expected_compact: str,
    expected_digest: str,
) -> None:
    """Every reviewed fixture round-trips through production decode/encode/render code to the
    exact reviewed bytes, without the test recomputing the expected vector itself (the
    independence requirement: the expected bytes are loaded verbatim from the frozen fixture
    file, never regenerated by test code)."""

    del file_name, variant_name
    document = receipt_document_from_json(wire)
    encoded = receipt_document_to_json(document)
    assert canonical_encode(cast(JsonValue, encoded)) == canonical_encode(cast(JsonValue, wire))
    assert canonical_digest(cast(JsonValue, encoded)) == expected_digest
    compact = render_receipt_compact(document)
    assert compact == expected_compact


def test_wrapper_that_upgrades_receipt_conclusion_fails() -> None:
    """A wrapper that mutates the decoded conclusion to a stronger vocabulary member before
    compact rendering must never reproduce the reviewed weaker wording."""

    from dataclasses import replace

    from yoetz.domain.receipts import ReceiptConclusion

    wire = _variant("unresolved-findings.case.json", "mixed_open_responses")
    document = receipt_document_from_json(wire)
    assert document.conclusion is ReceiptConclusion.UNRESOLVED_FINDINGS_REMAIN
    original = render_receipt_compact(document)

    upgraded = replace(document, conclusion=ReceiptConclusion.NO_UNRESOLVED_DETERMINISTIC_FINDINGS)
    assert render_receipt_compact(upgraded) != original
    assert "no unresolved local findings" in render_receipt_compact(upgraded)


async def test_profile_include_matrix_changes_canonical_document() -> None:
    """All nine ``redaction_profile`` x ``include`` combinations select exact field/section
    material before hashing, while conclusion/frontier/suppression/coverage/gap truth never
    strengthens or disappears across the matrix."""

    app, _runtime, _projection = _build_app(seed_offset=4)
    started, checked, _obligation = await _bootstrap_finding(app, seed=400)
    finding = checked.findings[0]
    reject_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 410)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(checked.result_frontier),
        "finding_id": finding.finding_id,
        "finding_frontier": _frontier(checked.result_frontier),
        "disposition": "rejected",
        "reason": "A protected rejection reason that redaction must remove.",
    }
    responded = await app.respond(RespondRequest.model_validate(reject_wire))

    profiles = ("full_local", "default_local_export", "redacted_share")
    includes = ("summary", "standard", "full")
    frontier = _frontier(responded.result_frontier)
    seed = 420
    documents: dict[tuple[str, str], ReceiptInternalResult] = {}
    for profile in profiles:
        for include in includes:
            wire: dict[str, JsonValue] = {
                **_request_base(protocol_id("req_", seed)),
                "task_id": started.task_id,
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": frontier,
                "format": "json",
                "include": include,
                "redaction_profile": profile,
            }
            receipt = await _receipt(app, wire)
            documents[(profile, include)] = receipt
            frontier = _frontier(receipt.result_frontier)
            seed += 1

    assert len(documents) == 9
    baseline = documents[("full_local", "full")]
    for receipt in documents.values():
        # Truth-bearing facts never strengthen, weaken inconsistently, or disappear anywhere in
        # the matrix: the underlying case did not change between these calls, only rendering.
        assert receipt.conclusion == baseline.conclusion
        assert receipt.suppressed_finding_count == baseline.suppressed_finding_count
        assert receipt.coverage.known_gaps == baseline.coverage.known_gaps

    full_local_full = documents[("full_local", "full")]
    redacted_share_full = documents[("redacted_share", "full")]
    assert full_local_full.receipt_digest != redacted_share_full.receipt_digest
    full_local_document = cast(dict[str, Any], full_local_full.document)
    redacted_document = cast(dict[str, Any], redacted_share_full.document)
    assert full_local_document["responses"]
    # ``rejected`` rows are omitted entirely under ``redacted_share`` because their required
    # reason cannot be blanked without losing the disposition's meaning.
    assert redacted_document["responses"] == []
    assert redacted_document["redactions"]

    summary_full_local = documents[("full_local", "summary")]
    full_full_local = documents[("full_local", "full")]
    assert summary_full_local.receipt_digest != full_full_local.receipt_digest
    assert summary_full_local.conclusion == full_full_local.conclusion


async def test_receipt_context_uses_same_availability_snapshot() -> None:
    """Receipt gaps/coverage are derived from the exact same explicit case facts as check,
    never independently re-guessed from the projection alone."""

    app, _runtime, _projection = _build_app(seed_offset=5)
    started, checked, _obligation = await _bootstrap_finding(app, seed=500)
    finding = checked.findings[0]

    receipt_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 510)),
        "task_id": started.task_id,
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(checked.result_frontier),
        "format": "json",
        "include": "full",
        "redaction_profile": "full_local",
    }
    receipt = await _receipt(app, receipt_wire)
    document = cast(dict[str, Any], receipt.document)
    document_findings = cast(list[dict[str, Any]], document["findings"])
    receipt_finding = next(
        item for item in document_findings if item["finding_id"] == finding.finding_id
    )

    # The exact same coverage snapshot the check reported for this finding is what the receipt
    # reports for it too -- never a fresh, projection-only recomputation.
    assert canonical_encode(cast(JsonValue, receipt_finding["coverage"])) == canonical_encode(
        cast(JsonValue, coverage_to_json(finding.coverage))
    )

    # The same is true for the whole-document weakest coverage against the check's own coverage:
    # a status read at the identical frontier observes no different availability facts either.
    status_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 511)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "view": "findings",
        "limit": "10",
        "at_frontier": str(checked.result_frontier.sequence),
    }
    status = await app.status(StatusRequest.model_validate(status_wire))
    status_page = cast(StatusFindingsPageModel, status.page)
    status_item = next(item for item in status_page.items if item.finding_id == finding.finding_id)
    assert canonical_encode(
        cast(JsonValue, status_item.coverage.model_dump(mode="json"))
    ) == canonical_encode(cast(JsonValue, receipt_finding["coverage"]))


async def test_receipt_replay_object_verification_failure_is_storage_corrupt() -> None:
    app, runtime, _projection = _build_app(seed_offset=22)
    started, checked, _obligation = await _bootstrap_finding(app, seed=2200)
    receipt_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 2210)),
        "task_id": started.task_id,
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(checked.result_frontier),
        "format": "json",
        "include": "standard",
        "redaction_profile": "full_local",
    }
    first = await _receipt(app, receipt_wire)
    assert first.ok is True

    _task_id, resources = next(iter(runtime.resources.items()))
    _ledger, objects = resources

    def _failing_open(_ref: object) -> object:
        raise ValueError("object_verification_failed")

    objects.open_verified = _failing_open  # pyright: ignore[reportAttributeAccessIssue]

    with pytest.raises(PublicOperationError) as caught:
        await _receipt(app, receipt_wire)
    assert caught.value.code is PublicErrorCode.STORAGE_CORRUPT
    assert caught.value.message == "The stored receipt is invalid."
    assert caught.value.retryable is False


async def test_receipt_replay_object_oserror_is_retryable_storage_unsafe() -> None:
    app, runtime, _projection = _build_app(seed_offset=24)
    started, checked, _obligation = await _bootstrap_finding(app, seed=2400)
    receipt_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 2410)),
        "task_id": started.task_id,
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(checked.result_frontier),
        "format": "json",
        "include": "standard",
        "redaction_profile": "full_local",
    }
    first = await _receipt(app, receipt_wire)
    assert first.ok is True

    _task_id, resources = next(iter(runtime.resources.items()))
    _ledger, objects = resources

    def _failing_open(_ref: object) -> object:
        raise OSError(5, "Input/output error")

    objects.open_verified = _failing_open  # pyright: ignore[reportAttributeAccessIssue]

    with pytest.raises(PublicOperationError) as caught:
        await _receipt(app, receipt_wire)
    assert caught.value.code is PublicErrorCode.STORAGE_UNSAFE
    assert caught.value.message == "Receipt object storage is unavailable."
    assert caught.value.retryable is True
    assert caught.value.correlation_id is not None
    assert caught.value.correlation_id.startswith("err_")
    assert "Input/output error" not in caught.value.message


@pytest.mark.parametrize(
    ("field", "replacement", "reason"),
    (
        ("receipt_digest", "sha256:" + "9" * 64, "receipt_digest_mismatch"),
        ("receipt_id", protocol_id("egr_", 2420), "receipt_id_mismatch"),
        ("subject_frontier", Frontier(0, "genesis"), "receipt_frontier_mismatch"),
        (
            "conclusion_code",
            ReceiptConclusion.NO_UNRESOLVED_DETERMINISTIC_FINDINGS,
            "receipt_conclusion_mismatch",
        ),
        (
            "redaction_profile",
            ReceiptRedactionProfile.REDACTED_SHARE,
            "receipt_redaction_profile_mismatch",
        ),
    ),
)
async def test_receipt_replay_integrity_mismatch_is_classified_at_application_site(
    field: str,
    replacement: object,
    reason: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Each bounded replay-binding mismatch retains an application-site diagnostic identity."""

    import yoetz.observability.diagnostics as diagnostics
    from yoetz.observability.diagnostics import lookup_diagnostic_records

    monkeypatch.setattr(diagnostics, "log_dir", lambda: tmp_path)
    app, runtime, _projection = _build_app(seed_offset=25)
    started, checked, _obligation = await _bootstrap_finding(app, seed=2500)
    receipt_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 2510)),
        "task_id": started.task_id,
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(checked.result_frontier),
        "format": "json",
        "include": "standard",
        "redaction_profile": "full_local",
    }
    first = await _receipt(app, receipt_wire)
    assert first.ok is True

    _task_id, resources = next(iter(runtime.resources.items()))
    ledger, _objects = resources
    record = next(
        record
        for record in ledger._state.records  # pyright: ignore[reportPrivateUsage]
        if record.schema.name == "receipt_recorded"
    )
    payload = cast(ReceiptRecordedPayload, record.payload)
    object.__setattr__(payload, field, replacement)

    with pytest.raises(PublicOperationError) as caught:
        await _receipt(app, receipt_wire)
    assert caught.value.code is PublicErrorCode.STORAGE_CORRUPT
    assert caught.value.message == "The stored receipt is invalid."
    assert caught.value.retryable is False
    assert caught.value.correlation_id is not None
    found = lookup_diagnostic_records(caught.value.correlation_id, root=tmp_path)
    assert len(found) == 1
    assert found[0]["component"] == "application.receipt"
    assert found[0]["operation"] == "receipt_object_read"
    assert found[0]["reason"] == reason
    recorded_operation = found[0]["operation"]
    assert type(recorded_operation) is str
    assert "internal_error" not in recorded_operation


async def test_receipt_stage_oserror_is_retryable_storage_unsafe() -> None:
    app, runtime, _projection = _build_app(seed_offset=23)
    started, checked, _obligation = await _bootstrap_finding(app, seed=2300)
    receipt_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 2310)),
        "task_id": started.task_id,
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(checked.result_frontier),
        "format": "json",
        "include": "standard",
        "redaction_profile": "full_local",
    }

    _task_id, resources = next(iter(runtime.resources.items()))
    _ledger, objects = resources

    async def _failing_stage(_source: object, _metadata: object) -> object:
        raise OSError("No space left on device")

    objects.stage = _failing_stage  # pyright: ignore[reportAttributeAccessIssue]

    with pytest.raises(PublicOperationError) as caught:
        await _receipt(app, receipt_wire)
    assert caught.value.code is PublicErrorCode.STORAGE_UNSAFE
    assert caught.value.message == "Receipt object storage is unavailable."
    assert caught.value.retryable is True
    assert "No space left on device" not in caught.value.message
