"""Codex interrupt/resume/reattach capability evidence.

Non-live cells prove trigger hooks are absent while harness profiles are unfrozen and that the
local application layer replays an identical publish request without duplicating effects. Live
Codex interrupt/resume cells require ``YOETZ_LIVE_CODEX=1``.
"""

from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest

from builders.ledger_adapters import ownership_fence
from builders.start_application import (
    MemoryStartRuntime,
    protocol_id,
    start_composition,
    start_request,
)
from capability.evidence import (
    CapabilityCase,
    EvidenceOutcome,
    Observation,
    bytes_digest,
    codex_profiles_frozen,
    live_codex_authorized,
    record_and_write,
    runtime_capability_context,
)
from yoetz.adapters.integrations.codex_skill import CODEX_HARNESS_PROFILE
from yoetz.application.egress import PrivacyCoordinator
from yoetz.application.service import Application, VerificationPolicy
from yoetz.domain.events import RuntimeProfile
from yoetz.domain.privacy import CandidateContext
from yoetz.domain.receipts import PolicyVersionEntry, ReceiptVersionSlice, SchemaVersionEntry
from yoetz.domain.values import Frontier
from yoetz.ports.diagnostics import RuntimeCapability
from yoetz.ports.importer import ImporterPort, ImportStatusSnapshot
from yoetz.ports.publish_response_catalog import PublishResponseCatalogPort
from yoetz.ports.runtime import BundleRuntimePort, RouteCommand, TaskRuntime
from yoetz.protocol.canonical import JsonValue, canonical_digest
from yoetz.protocol.models import FrontierModel, PublishWorkRequest

_TEST_REVISION = bytes_digest(Path(__file__).read_bytes())
_VERSION = "0.139.0"
_DIGEST = "sha256:" + "7" * 64


class _IdleImporter:
    async def status(self, session: str) -> ImportStatusSnapshot:
        from yoetz.domain.values import session_id

        return ImportStatusSnapshot(session_id(session), 0, 0, (), ())


class _StrictLocalRuntime(MemoryStartRuntime):
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


class _NoDisclosurePrivacy:
    async def prepare_local_disclosure(self, candidate: CandidateContext) -> object:
        raise AssertionError("resume capability cell must stay local")

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


async def _semantic_forbidden(
    frozen: object,
    findings: object,
    runtime: object | None = None,
    lineage_evaluation: object | None = None,
    require_complete_specification: bool = False,
) -> object:
    del frozen, findings, runtime, lineage_evaluation
    raise AssertionError("resume capability cell must never invoke the AI-powered evaluator")


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def test_trigger_hooks_absent_while_unprofiled(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir(mode=0o700)
    assert dict(CODEX_HARNESS_PROFILE.hooks_by_capability_profile) == {}
    context = runtime_capability_context(
        fixture_digest=bytes_digest(b"resume-hooks-absent"),
        test_revision=_TEST_REVISION,
        config_profile_digest=canonical_digest({"cell": "hooks_absent"}),
        external_tool="codex",
        external_version=_VERSION,
        integration_channel="codex_mcp_stdio",
    )
    if codex_profiles_frozen():
        pytest.skip("frozen profiles move trigger-hook cells into the live matrix")
    evidence = record_and_write(
        CapabilityCase(
            case_id="RSM-001",
            requirement_id="ADR-010.trigger-hooks",
            claim_id="E-013.resume-hooks",
            capability_family="codex_resume_reattach",
            required_observation_codes=frozenset({"hooks_map_empty", "profiles_frozen"}),
            allowed_observation_codes=frozenset({"hooks_map_empty", "profiles_frozen"}),
        ),
        context,
        (
            Observation("hooks_map_empty", boolean_value=True),
            Observation("profiles_frozen", boolean_value=False),
        ),
        EvidenceOutcome.UNSUPPORTED,
        ("trigger_hook_unprofiled",),
        output_root=evidence_root,
    )
    assert evidence.outcome is EvidenceOutcome.UNSUPPORTED


@pytest.mark.anyio
async def test_idempotent_reattach_does_not_duplicate_local_effect(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir(mode=0o700)
    start_app, start_runtime, clock, catalog = start_composition()
    runtime = _StrictLocalRuntime(clock, start_runtime.ids)
    app = Application(
        start_catalog=catalog.delegate,
        publish_responses=cast(PublishResponseCatalogPort, catalog.delegate),
        runtime=cast(BundleRuntimePort, runtime),
        clock=clock,
        ids=start_runtime.ids,
        verification_policy=VerificationPolicy(semantic="disabled", max_findings=3),
        privacy=cast(PrivacyCoordinator, _NoDisclosurePrivacy()),
        status_cursor_key=b"resume-capability-cursor-key",
        waiver_policy_digest=_DIGEST,
        semantic_evaluator=_semantic_forbidden,
        disclosure_scope_for=lambda binding, source: (_ for _ in ()).throw(
            AssertionError("no disclosure")
        ),
        receipt_version_resolver=lambda _: _versions(),
        waiver_authorizer=lambda _: False,
        import_publication_authorizer=lambda _: False,
        profile=RuntimeProfile.STRICT_LOCAL,
        policy_packs=("research-evidence/0.2.0", "work-integrity/0.3.0"),
        version_manifest=start_app.version_manifest,
        enforce_repository_identity=False,
    )
    started = await app.start(start_request(501, title="Resume reattach local oracle"))
    obligation_id = protocol_id("obl_", 502)
    event_id = protocol_id("evt_", 503)
    request_id = protocol_id("req_", 504)
    publish_wire = {
        **_request_base(request_id),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(started.frontier),
        "event_drafts": (
            {
                "event_id": event_id,
                "schema": {"name": "obligation_published", "version": "1.0.0"},
                "occurred_at": "2026-07-19T12:00:00.000Z",
                "causal_parents": (),
                "payload": {
                    "obligation_id": obligation_id,
                    "description": "Local resume oracle obligation.",
                    "acceptance_criteria": "One durable publication.",
                    "evidence_expectation": "Immutable obligation record.",
                    "requested_items": ({"item_kind": "change", "value": "resume-oracle"},),
                    "status": "open",
                },
                "artifact_refs": (),
                "evidence_refs": (),
            },
        ),
    }
    first = await app.publish_work(PublishWorkRequest.model_validate(publish_wire))
    second = await app.publish_work(PublishWorkRequest.model_validate(publish_wire))
    assert first.result_frontier == second.result_frontier
    assert first.accepted_events == second.accepted_events
    assert second.outcome == "replayed"

    context = runtime_capability_context(
        fixture_digest=bytes_digest(b"local-idempotent-reattach"),
        test_revision=_TEST_REVISION,
        config_profile_digest=canonical_digest({"cell": "idempotent_reattach"}),
        external_tool="codex",
        external_version=_VERSION,
        integration_channel="local_cli",
    )
    evidence = record_and_write(
        CapabilityCase(
            case_id="RSM-002",
            requirement_id="ADR-002.idempotency",
            claim_id="E-002.resume-reattach",
            capability_family="codex_resume_reattach",
            required_observation_codes=frozenset(
                {"duplicate_effect", "frontier_stable", "session_stable"}
            ),
            allowed_observation_codes=frozenset(
                {"duplicate_effect", "frontier_stable", "session_stable"}
            ),
        ),
        context,
        (
            Observation("duplicate_effect", boolean_value=False),
            Observation("frontier_stable", boolean_value=True),
            Observation("session_stable", boolean_value=True),
        ),
        EvidenceOutcome.PASS,
        output_root=evidence_root,
    )
    assert evidence.outcome is EvidenceOutcome.PASS


@pytest.mark.live
def test_live_codex_interrupt_and_resume(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir(mode=0o700)
    context = runtime_capability_context(
        fixture_digest=bytes_digest(b"live-resume"),
        test_revision=_TEST_REVISION,
        config_profile_digest=canonical_digest({"cell": "live_resume"}),
        external_tool="codex",
        external_version=_VERSION,
        integration_channel="codex_mcp_stdio",
    )
    if not live_codex_authorized():
        evidence = record_and_write(
            CapabilityCase(
                case_id="RSM-LIVE-001",
                requirement_id="ADR-005.resume",
                claim_id="E-002.resume-live",
                capability_family="codex_resume_reattach",
                required_observation_codes=frozenset({"live_authorized"}),
                allowed_observation_codes=frozenset({"live_authorized"}),
            ),
            context,
            (Observation("live_authorized", boolean_value=False),),
            EvidenceOutcome.UNSUPPORTED,
            ("live_codex_not_authorized",),
            output_root=evidence_root,
        )
        assert evidence.outcome is EvidenceOutcome.UNSUPPORTED
        return
    pytest.fail("live Codex resume authorized; observe interrupt/compact/reopen before pass")
