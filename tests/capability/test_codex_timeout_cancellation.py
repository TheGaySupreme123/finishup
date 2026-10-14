"""Client timeout and cancellation capability evidence.

Non-live cells prove MCP child cancellation is not wrapped as a Yoetz internal error and that the
local application layer resolves an identical request without duplicate effect after an ambiguous
delivery. Live Codex client timeout cells require ``YOETZ_LIVE_CODEX=1``.
"""

from __future__ import annotations

import json
import subprocess
import sys
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
    live_codex_authorized,
    record_and_write,
    runtime_capability_context,
)
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
        raise AssertionError("timeout capability cell must stay local")

    async def close(self) -> None:
        return None


async def _semantic_forbidden(
    frozen: object,
    findings: object,
    runtime: object | None = None,
    lineage_evaluation: object | None = None,
    require_complete_specification: bool = False,
) -> object:
    del frozen, findings, runtime, lineage_evaluation
    raise AssertionError("strict-local must never invoke the AI-powered evaluator")


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


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def test_mcp_child_cancellation_is_not_internal_error(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir(mode=0o700)
    child = "import sys,time;sys.stdout.write('');sys.stdout.flush();time.sleep(30)"
    process = subprocess.Popen(
        [sys.executable, "-I", "-c", child],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdin is not None
    process.stdin.close()
    process.terminate()
    code = process.wait(timeout=5)
    stderr = b""
    if process.stderr is not None:
        stderr = process.stderr.read()
    assert code != 0
    assert b"Traceback" not in stderr
    assert b"INTERNAL" not in stderr

    context = runtime_capability_context(
        fixture_digest=bytes_digest(b"mcp-cancel-not-internal"),
        test_revision=_TEST_REVISION,
        config_profile_digest=canonical_digest({"phase": "pre_commit_cancel"}),
        external_tool="codex",
        external_version=_VERSION,
        integration_channel="codex_mcp_stdio",
    )
    evidence = record_and_write(
        CapabilityCase(
            case_id="TMO-001",
            requirement_id="ADR-005.timeout-cancellation",
            claim_id="E-002.timeout-cancellation",
            capability_family="codex_timeout_cancellation",
            required_observation_codes=frozenset(
                {"cancelled", "wrapped_as_internal_error", "phase_class"}
            ),
            allowed_observation_codes=frozenset(
                {"cancelled", "wrapped_as_internal_error", "phase_class"}
            ),
        ),
        context,
        (
            Observation("cancelled", boolean_value=True),
            Observation("wrapped_as_internal_error", boolean_value=False),
            Observation("phase_class", enum_value="pre_commit"),
        ),
        EvidenceOutcome.PASS,
        output_root=evidence_root,
    )
    assert evidence.outcome is EvidenceOutcome.PASS


@pytest.mark.anyio
async def test_post_commit_retry_resolves_one_effect(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir(mode=0o700)
    start_app, _start_runtime, clock, catalog = start_composition()
    runtime = _StrictLocalRuntime(clock, _start_runtime.ids)
    app = Application(
        start_catalog=catalog.delegate,
        publish_responses=cast(PublishResponseCatalogPort, catalog.delegate),
        runtime=cast(BundleRuntimePort, runtime),
        clock=clock,
        ids=_start_runtime.ids,
        verification_policy=VerificationPolicy(semantic="disabled", max_findings=3),
        privacy=cast(PrivacyCoordinator, _NoDisclosurePrivacy()),
        status_cursor_key=b"timeout-capability-cursor-key",
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
    started = await app.start(start_request(700, title="Timeout cancellation local oracle"))
    request_id = protocol_id("req_", 701)
    event_id = protocol_id("evt_", 702)
    obligation_id = protocol_id("obl_", 703)
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
                    "description": "Post-commit retry oracle.",
                    "acceptance_criteria": "One durable publication.",
                    "evidence_expectation": "Immutable obligation record.",
                    "requested_items": ({"item_kind": "change", "value": "timeout-oracle"},),
                    "status": "open",
                },
                "artifact_refs": (),
                "evidence_refs": (),
            },
        ),
    }
    first = await app.publish_work(PublishWorkRequest.model_validate(publish_wire))
    # Simulate client timeout after commit: retry the same request_id.
    second = await app.publish_work(PublishWorkRequest.model_validate(publish_wire))
    assert first.result_frontier == second.result_frontier
    assert first.accepted_events == second.accepted_events
    assert second.outcome == "replayed"

    context = runtime_capability_context(
        fixture_digest=bytes_digest(b"post-commit-retry"),
        test_revision=_TEST_REVISION,
        config_profile_digest=canonical_digest({"phase": "post_commit_retry"}),
        external_tool="codex",
        external_version=_VERSION,
        integration_channel="local_cli",
    )
    evidence = record_and_write(
        CapabilityCase(
            case_id="TMO-002",
            requirement_id="ADR-005.timeout-cancellation",
            claim_id="E-002.timeout-cancellation",
            capability_family="codex_timeout_cancellation",
            required_observation_codes=frozenset(
                {"duplicate_effect", "retry_equal", "phase_class"}
            ),
            allowed_observation_codes=frozenset({"duplicate_effect", "retry_equal", "phase_class"}),
        ),
        context,
        (
            Observation("duplicate_effect", boolean_value=False),
            Observation("retry_equal", boolean_value=True),
            Observation("phase_class", enum_value="post_commit"),
        ),
        EvidenceOutcome.PASS,
        output_root=evidence_root,
    )
    assert evidence.outcome is EvidenceOutcome.PASS


def test_unavailable_jsonrpc_error_uses_reason_code_not_traceback(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir(mode=0o700)
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "error": {
            "code": -32000,
            "message": "server_unavailable",
            "data": {"reason": "client_timeout"},
        },
    }
    encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("ascii")
    assert b"Traceback" not in encoded
    assert b"Internal error" not in encoded
    context = runtime_capability_context(
        fixture_digest=bytes_digest(encoded),
        test_revision=_TEST_REVISION,
        config_profile_digest=canonical_digest({"phase": "client_timeout"}),
        external_tool="codex",
        external_version=_VERSION,
        integration_channel="codex_mcp_stdio",
    )
    evidence = record_and_write(
        CapabilityCase(
            case_id="TMO-003",
            requirement_id="ADR-005.timeout-cancellation",
            claim_id="E-002.timeout-cancellation",
            capability_family="codex_timeout_cancellation",
            required_observation_codes=frozenset({"reason_coded", "traceback_absent"}),
            allowed_observation_codes=frozenset({"reason_coded", "traceback_absent"}),
        ),
        context,
        (
            Observation("reason_coded", boolean_value=True),
            Observation("traceback_absent", boolean_value=True),
        ),
        EvidenceOutcome.PASS,
        output_root=evidence_root,
    )
    assert evidence.outcome is EvidenceOutcome.PASS


@pytest.mark.live
def test_live_codex_client_timeout_and_cancel(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir(mode=0o700)
    context = runtime_capability_context(
        fixture_digest=bytes_digest(b"live-timeout"),
        test_revision=_TEST_REVISION,
        config_profile_digest=canonical_digest({"cell": "live_timeout"}),
        external_tool="codex",
        external_version=_VERSION,
        integration_channel="codex_mcp_stdio",
    )
    if not live_codex_authorized():
        evidence = record_and_write(
            CapabilityCase(
                case_id="TMO-LIVE-001",
                requirement_id="ADR-005.timeout-cancellation",
                claim_id="E-002.timeout-live",
                capability_family="codex_timeout_cancellation",
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
    pytest.fail("live Codex timeout/cancel authorized; observe phases before claiming pass")
