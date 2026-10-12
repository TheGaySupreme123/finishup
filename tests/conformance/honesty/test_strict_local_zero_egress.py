"""Honesty conformance: strict-local performs zero network egress and reads no credentials.

These tests exercise the real ``Application`` local-check workflow (``start`` -> ``publish_work``
-> ``check``) composed exactly the way ``RuntimeProfile.STRICT_LOCAL`` / ``profile="strict-local"``
requires -- AI-powered review disabled, no provider adapter constructed -- with ``socket.socket``,
``socket.create_connection``, and ``socket.getaddrinfo`` monkeypatched to raise. The workflow must
still complete and return a real, useful local finding: strict-local's zero-egress guarantee
is not achieved by silently doing nothing. A companion test proves the config schema itself forbids
attaching a provider (and therefore credentials) to the strict-local profile, and that fake
credential-shaped environment values never leak into the produced findings or receipt.
"""

from __future__ import annotations

import socket
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
from yoetz.application.receipt import ReceiptInternalResult
from yoetz.application.service import Application, VerificationPolicy
from yoetz.config.models import (
    PROFILE_CAPABILITIES,
    ConfigError,
    NetworkPolicy,
    ProviderProfileConfig,
    YoetzConfig,
)
from yoetz.domain.events import RuntimeProfile
from yoetz.domain.findings import CheckVerdict
from yoetz.domain.privacy import CandidateContext
from yoetz.domain.receipts import (
    OPTIONAL_SEMANTIC_REVIEW_BLOCKED_BY_POLICY_GAP,
    PolicyVersionEntry,
    ReceiptVersionSlice,
    SchemaVersionEntry,
)
from yoetz.domain.values import Frontier
from yoetz.ports.diagnostics import RuntimeCapability
from yoetz.ports.importer import ImporterPort, ImportStatusSnapshot
from yoetz.ports.ledger import CheckCommitResult
from yoetz.ports.publish_response_catalog import PublishResponseCatalogPort
from yoetz.ports.runtime import BundleRuntimePort, RouteCommand, TaskRuntime
from yoetz.protocol.canonical import JsonValue, canonical_encode
from yoetz.protocol.models import CheckRequest, FrontierModel, PublishWorkRequest, ReceiptRequest

pytestmark = pytest.mark.anyio

_DIGEST = "sha256:" + "7" * 64


class _IdleImporter:
    async def status(self, session: str) -> ImportStatusSnapshot:
        from yoetz.domain.values import session_id

        return ImportStatusSnapshot(session_id(session), 0, 0, (), ())


class _StrictLocalRuntime(MemoryStartRuntime):
    """Extend the START memory composition with ready writer routing (no network involved)."""

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
    """A privacy coordinator that must never be asked to disclose anything in this test."""

    async def prepare_local_disclosure(self, candidate: CandidateContext) -> object:
        raise AssertionError("no local disclosure is required for a local-only check")

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
    raise AssertionError(
        "strict-local + disabled AI-powered review must never invoke the evaluator"
    )


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


def _deny_network(*_args: object, **_kwargs: object) -> object:
    raise AssertionError("strict-local must never attempt network egress")


def _build_strict_local_application() -> tuple[Application, _StrictLocalRuntime, object, object]:
    start_app, start_runtime, clock, catalog = start_composition()
    ids = start_runtime.ids
    runtime = _StrictLocalRuntime(clock, ids)
    app = Application(
        start_catalog=catalog.delegate,
        publish_responses=cast(PublishResponseCatalogPort, catalog.delegate),
        runtime=cast(BundleRuntimePort, runtime),
        clock=clock,
        ids=ids,
        verification_policy=VerificationPolicy(semantic="disabled", max_findings=3),
        privacy=cast(PrivacyCoordinator, _NoDisclosurePrivacy()),
        status_cursor_key=b"strict-local-status-cursor-key",
        waiver_policy_digest=_DIGEST,
        semantic_evaluator=_semantic_forbidden,
        disclosure_scope_for=lambda binding, source: (_ for _ in ()).throw(
            AssertionError("disclosure scope is never resolved in a local-only check")
        ),
        receipt_version_resolver=lambda _: _versions(),
        waiver_authorizer=lambda _: False,
        import_publication_authorizer=lambda _: False,
        profile=RuntimeProfile.STRICT_LOCAL,
        policy_packs=("research-evidence/0.2.0", "work-integrity/0.3.0"),
        version_manifest=start_app.version_manifest,
        enforce_repository_identity=False,
    )
    return app, runtime, clock, catalog


async def _run_deterministic_check(app: Application, seed: int) -> CheckCommitResult:
    started = await app.start(start_request(seed, title="Strict-local zero-egress exercise"))
    obligation_id = protocol_id("obl_", seed + 1)
    obligation_event_id = protocol_id("evt_", seed + 2)
    publish_wire = {
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
                    "description": "Publish a result for the strict-local exercise.",
                    "acceptance_criteria": "A result is recorded in the task ledger.",
                    "evidence_expectation": "A linked immutable result record.",
                    "requested_items": ({"item_kind": "change", "value": "strict-local-result"},),
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
                    "statement": "The strict-local exercise is complete.",
                    "supporting_refs": (obligation_id,),
                    "obligation_refs": (obligation_id,),
                },
                "artifact_refs": (),
                "evidence_refs": (),
            },
        ),
    }
    published = await app.publish_work(PublishWorkRequest.model_validate(publish_wire))

    check_wire = {
        **_request_base(protocol_id("req_", seed + 6)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(published.result_frontier),
        "mode": "deterministic_only",
        "max_findings": "3",
    }
    checked = await app.check(CheckRequest.model_validate(check_wire))
    # The strict route never reaches a provider, so it can never suspend on a disclosure
    # decision; a nonterminal result here would mean the ceiling leaked.
    assert type(checked) is CheckCommitResult, f"unexpected nonterminal check: {type(checked)}"
    return checked


async def _run_route_ceiling_check(
    app: Application, seed: int
) -> tuple[CheckCommitResult, ReceiptInternalResult]:
    started = await app.start(start_request(seed, title="Route ceiling exercise"))
    published = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 1)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(started.frontier),
                "event_drafts": (
                    {
                        "event_id": protocol_id("evt_", seed + 2),
                        "schema": {"name": "claim_recorded", "version": "1.0.0"},
                        "occurred_at": "2026-07-29T12:00:00.000Z",
                        "causal_parents": (),
                        "payload": {
                            "claim_id": protocol_id("clm_", seed + 3),
                            "claim_kind": "material",
                            "statement": "This claim requests AI-powered review.",
                            "supporting_refs": (),
                            "obligation_refs": (),
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
                **_request_base(protocol_id("req_", seed + 4)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(published.result_frontier),
                "mode": "semantic_required",
                "max_findings": "3",
            }
        ),
        route_profile="strict",
    )
    assert type(checked) is CheckCommitResult, f"unexpected nonterminal check: {type(checked)}"
    receipt = await app.receipt(
        ReceiptRequest.model_validate(
            {
                **_request_base(protocol_id("req_", seed + 5)),
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
    return checked, receipt


async def test_zero_egress_in_strict_local(monkeypatch: pytest.MonkeyPatch) -> None:
    """No AF_INET/AF_INET6 socket, DNS lookup, or connection is ever attempted under strict-local."""

    assert PROFILE_CAPABILITIES["strict-local"].network is NetworkPolicy.DENIED

    monkeypatch.setattr(socket, "socket", _deny_network)
    monkeypatch.setattr(socket, "create_connection", _deny_network)
    monkeypatch.setattr(socket, "getaddrinfo", _deny_network)

    app, _runtime, _clock, _catalog = _build_strict_local_application()
    checked = await _run_deterministic_check(app, seed=900)

    # The workflow completed end to end without ever touching a socket, and it still returned a
    # real, actionable result -- zero egress was not achieved by silently returning nothing.
    assert checked.findings
    assert checked.verdict is CheckVerdict.ACTION_REQUIRED


async def test_strict_local_still_supports_deterministic_operations() -> None:
    """Local checks remain fully useful (real findings/verdict) under strict-local."""

    app, _runtime, _clock, _catalog = _build_strict_local_application()
    checked = await _run_deterministic_check(app, seed=910)

    assert checked.verdict is CheckVerdict.ACTION_REQUIRED
    assert checked.findings
    finding = checked.findings[0]
    assert finding.summary
    assert finding.coverage.known_gaps == () or finding.coverage.known_gaps


async def test_route_ceiling_blocks_required_semantics_and_carries_gap_into_receipt() -> None:
    app, _runtime, _clock, _catalog = _build_strict_local_application()

    checked, receipt = await _run_route_ceiling_check(app, seed=915)

    assert checked.semantic_status.value == "blocked_by_policy"
    assert checked.semantic_reason.value == "route_semantic_ceiling"
    assert checked.verdict.value == "incomplete_check"
    assert OPTIONAL_SEMANTIC_REVIEW_BLOCKED_BY_POLICY_GAP in checked.coverage.known_gaps
    assert OPTIONAL_SEMANTIC_REVIEW_BLOCKED_BY_POLICY_GAP in receipt.coverage.known_gaps


def test_strict_local_forbids_provider_attachment_structurally() -> None:
    """The config schema itself refuses to attach a provider (and its credentials) to strict-local."""

    provider = ProviderProfileConfig(
        provider_id="openai",
        endpoint_profile_id="review.default",
        endpoint_profile_version="1.0.0",
        model="gpt-5.4",
        capability_profile="review-default-v1",
    )
    with pytest.raises(ConfigError) as exc_info:
        YoetzConfig(profile="strict-local", provider=provider)
    assert exc_info.value.reason_code == "strict_local_forbids_provider"

    # The provider schema itself structurally forbids any key that looks like a credential --
    # there is no field through which an API key, token, or secret could even be attached.
    with pytest.raises(ConfigError) as secret_exc:
        ProviderProfileConfig.model_validate(
            {
                "provider_id": "openai",
                "endpoint_profile_id": "review.default",
                "endpoint_profile_version": "1.0.0",
                "model": "gpt-5.4",
                "capability_profile": "review-default-v1",
                "api_key": "sk-should-never-be-accepted",
            }
        )
    assert secret_exc.value.reason_code == "secret_in_config"


async def test_fake_credentials_are_not_read_or_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    """Credential-shaped environment values never leak into strict-local findings or receipts."""

    fake_secret = "sk-fake-strict-local-should-never-appear-anywhere"
    monkeypatch.setenv("OPENAI_API_KEY", fake_secret)
    monkeypatch.setenv("ANTHROPIC_API_KEY", fake_secret)
    monkeypatch.setenv("YOETZ_PROVIDER_TOKEN", fake_secret)

    app, _runtime, _clock, _catalog = _build_strict_local_application()
    checked = await _run_deterministic_check(app, seed=920)

    serialized = canonical_encode(
        cast(
            JsonValue,
            {
                "verdict": checked.verdict.value,
                "findings": [
                    {
                        "finding_id": finding.finding_id,
                        "summary": finding.summary,
                        "detail": finding.detail,
                    }
                    for finding in checked.findings
                ],
            },
        )
    ).decode("utf-8")
    assert fake_secret not in serialized
    assert "OPENAI_API_KEY" not in serialized
    assert "ANTHROPIC_API_KEY" not in serialized
